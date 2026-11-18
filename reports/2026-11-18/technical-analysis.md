# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-18

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 652 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 652 |
| Unique family labels | 8 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 65 |
| unknown | 17 |
| XWorm | 6 |
| Formbook | 5 |
| Prometei | 4 |
| STRRAT | 1 |
| Panchan | 1 |
| AsyncRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 82 |
| exe | 13 |
| py | 2 |
| js | 1 |
| jar | 1 |
| sh | 1 |

## Per-Sample Analysis

### Sample 1: `032313b66f60099b`

| Field | Value |
|---|---|
| SHA-256 | `032313b66f60099b71c4713bf43b27fcab23cfcf098b13b5bd554524a58de98f` |
| Family label | `unknown` |
| File name | `vcruntime` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `346a41b1b08ed58ea6520e6bdf61933a` |
| SHA-1 | `eab65766d7568cc21409fb16a1377c234e5264b8` |
| SHA-256 | `032313b66f60099b71c4713bf43b27fcab23cfcf098b13b5bd554524a58de98f` |
| SHA3-384 | `441e2e9c93f61bf1e551af6e09d06fd49b7cd2a2137c79194a32f5c501a727147c3a9d0e306751b4a2386d9cbaa5eaf0` |
| TLSH | `T109D37C8BBA069CA6D8910BF94FD79B8D2FA360608F67C7D67D0D16740E55ECE5C0A380` |
| TELFHASH | `t1cb315166fd35952d7aa11924ec5c8bb19114a723a7581e31af3dc0dc1c3f082b42ad6f` |
| SSDEEP | `3072:oNeBbaym45QdzUoUzp/VzNfL4/O6PLE27/lgoqLrnmHiG:oNUuymEQdIoUzp/Vzn6TEg/q3mHiG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_032313b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "032313b66f60099b71c4713bf43b27fcab23cfcf098b13b5bd554524a58de98f"
    family = "unknown"
    file_name = "vcruntime"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:35"
  condition:
    hash.sha256(0, filesize) == "032313b66f60099b71c4713bf43b27fcab23cfcf098b13b5bd554524a58de98f"
}
```

### Sample 2: `219886558ffc16d1`

| Field | Value |
|---|---|
| SHA-256 | `219886558ffc16d1580f79f619be773508bfd8feb26023c1b50d9c6f6d0996f0` |
| Family label | `unknown` |
| File name | `libstd` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff30268e3e0a4691f954df6d36ccbdf6` |
| SHA-1 | `9a415f1eb4c7121efa96d111d45b48d23890b86b` |
| SHA-256 | `219886558ffc16d1580f79f619be773508bfd8feb26023c1b50d9c6f6d0996f0` |
| SHA3-384 | `9762ceaf7e1bc2b371d97c849c269ed2843fbbb2ea5782f129a7070941defa4b3ec5a6192570029fff3492acf9165b40` |
| TLSH | `T14C730B0679818E53C1C11BBAB69F43693721B798D7DB3303DA187FB43F8669D0E2A250` |
| TELFHASH | `t1b11135b5bd30a12d6d4505248d8c49b06614b313b3195e32ff38c5ec1d350d1b20fd6e` |
| SSDEEP | `1536:fqZscsdwnlxlmOIBdBAsTIgEReO5ZtYsrEapntNv8F:qnlxlfkdBA8cUOntYsrLEF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_21988655
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "219886558ffc16d1580f79f619be773508bfd8feb26023c1b50d9c6f6d0996f0"
    family = "unknown"
    file_name = "libstd"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:32"
  condition:
    hash.sha256(0, filesize) == "219886558ffc16d1580f79f619be773508bfd8feb26023c1b50d9c6f6d0996f0"
}
```

### Sample 3: `bb0a547115aafd58`

| Field | Value |
|---|---|
| SHA-256 | `bb0a547115aafd586aab949ffd15bdfdff0f740b43dfa68eed9ef679318e507b` |
| Family label | `unknown` |
| File name | `libgcc` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:29` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98a3bd6123992e8030acb6686b0afa05` |
| SHA-1 | `0f95301810d4c7fce0a44b5959e1c60ecf6e32ec` |
| SHA-256 | `bb0a547115aafd586aab949ffd15bdfdff0f740b43dfa68eed9ef679318e507b` |
| SHA3-384 | `93ae3d5b563b112414afdc1e6985ed695af306866acecc3d6e235c05fa92513891cae183b8090852beaa68346454d74c` |
| TLSH | `T1C9730A0679818E53C5C11BBAB69F43693721B798D7DB3303DA187FB43F8669D0E2A250` |
| TELFHASH | `t1b11135b5bd30a12d6d4505248d8c49b06614b313b3195e32ff38c5ec1d350d1b20fd6e` |
| SSDEEP | `1536:FqZscsdwnlxlmOIBdBAsTIgEReOQZtYsrEapnKNv8F:onlxlfkdBA8cUO+tYsrQEF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_bb0a5471
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb0a547115aafd586aab949ffd15bdfdff0f740b43dfa68eed9ef679318e507b"
    family = "unknown"
    file_name = "libgcc"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:29"
  condition:
    hash.sha256(0, filesize) == "bb0a547115aafd586aab949ffd15bdfdff0f740b43dfa68eed9ef679318e507b"
}
```

### Sample 4: `caa94ba39d489d02`

| Field | Value |
|---|---|
| SHA-256 | `caa94ba39d489d025d98b1c79b8beab28d1dcfb3c5837cf67d74fa7fe5f63e2b` |
| Family label | `unknown` |
| File name | `d3d10` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:27` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f31af3f46213773d03ebc40a844ef0bb` |
| SHA-1 | `4b09f8090b359288a90cfaf53d0383238d8ce5a6` |
| SHA-256 | `caa94ba39d489d025d98b1c79b8beab28d1dcfb3c5837cf67d74fa7fe5f63e2b` |
| SHA3-384 | `c306b91933efd11d33172613e572c6c4fa82e4aa89b50a096e7c16e9b4acf92afceeabcff067638816fd263485a6e651` |
| TLSH | `T171533A82A923EAB3C84327B517A79B704A31F8754B366D06F32CBEF45E526C8710535D` |
| TELFHASH | `t1d91163a5bd30a53ead5555208d8c89b06614f323b3194e32ff38c4ec6d3a091b21bdae` |
| SSDEEP | `1536:J0YBGS8BTAjODLhLU2HsdVk1JCF2cigWJttQCMSNK:JhGfJI2cVkLC0NttQKK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_caa94ba3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caa94ba39d489d025d98b1c79b8beab28d1dcfb3c5837cf67d74fa7fe5f63e2b"
    family = "unknown"
    file_name = "d3d10"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:27"
  condition:
    hash.sha256(0, filesize) == "caa94ba39d489d025d98b1c79b8beab28d1dcfb3c5837cf67d74fa7fe5f63e2b"
}
```

### Sample 5: `4245341327823028`

| Field | Value |
|---|---|
| SHA-256 | `4245341327823028091aba8cb11aa297394ed4c277d67ebdf34801ef49c7320b` |
| Family label | `unknown` |
| File name | `msvcp` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:24` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38ee42c7d54ca22f07354ed22f52be3e` |
| SHA-1 | `0ceb234e162fe5f6f95295138ed843866bc62b2a` |
| SHA-256 | `4245341327823028091aba8cb11aa297394ed4c277d67ebdf34801ef49c7320b` |
| SHA3-384 | `64ece5158378fb66985525498561ef19f42182b0dd118ec74666947a90a0415f9bb8b0729af215c2a2f5a7ea0d44ce71` |
| TLSH | `T1CE432903BDA55F67D48A6BB462F34B388B43F8254F531B99A228ECF44643ECC7919364` |
| TELFHASH | `t1fa1135b5bd30a12d6d4505208d8c49b06214b313b3191e32ff38c5ec1d350d1b10fd6e` |
| SSDEEP | `1536:06U+31IKqRXY7YXME7i6R3C4hQ9TnnAFXq:0/KqNY0Jm6R3E9Qq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_42453413
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4245341327823028091aba8cb11aa297394ed4c277d67ebdf34801ef49c7320b"
    family = "unknown"
    file_name = "msvcp"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:24"
  condition:
    hash.sha256(0, filesize) == "4245341327823028091aba8cb11aa297394ed4c277d67ebdf34801ef49c7320b"
}
```

### Sample 6: `12f0546d011e41e4`

| Field | Value |
|---|---|
| SHA-256 | `12f0546d011e41e495c0ad35587689c62c4ba1f912ada9a9858ad5d5851e8021` |
| Family label | `unknown` |
| File name | `xinput` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5f65329fa1da5e5345670718e764110` |
| SHA-1 | `655cb561af766a21517d3278d66d13f0fbccfb81` |
| SHA-256 | `12f0546d011e41e495c0ad35587689c62c4ba1f912ada9a9858ad5d5851e8021` |
| SHA3-384 | `0f7e551ace6662de0b60914228c3e65348be03b5a3b3bc6c6065ff49d0e329072ff6474f3adbd620ff1b966c41e9cf25` |
| TLSH | `T1E293A50B7F218EF7D49BCD7709BA8702208EB0172194776A7974E96CBA1754F09E3CA4` |
| TELFHASH | `t1b11135b5bd30a12d6d4505248d8c49b06614b313b3195e32ff38c5ec1d350d1b20fd6e` |
| SSDEEP | `1536:i5hRjYL/3r5867bZnr4TBZVre0NQlS7A83:i5hRjPxTBOW3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_12f0546d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12f0546d011e41e495c0ad35587689c62c4ba1f912ada9a9858ad5d5851e8021"
    family = "unknown"
    file_name = "xinput"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:22"
  condition:
    hash.sha256(0, filesize) == "12f0546d011e41e495c0ad35587689c62c4ba1f912ada9a9858ad5d5851e8021"
}
```

### Sample 7: `2849af577a06f739`

| Field | Value |
|---|---|
| SHA-256 | `2849af577a06f7399e7312666ffbe6021ef0759be43d21a976ccfb336baeb137` |
| Family label | `unknown` |
| File name | `dxgi` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:19` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b84dfa7de2c830d1bb0d5f94d3dfdb3` |
| SHA-1 | `2ca0b525e4c958bb8b325d18805072dd154c97bc` |
| SHA-256 | `2849af577a06f7399e7312666ffbe6021ef0759be43d21a976ccfb336baeb137` |
| SHA3-384 | `03922bfbf10ed0ae1d623eacd64ad5c6fb23534198d3f97624ee7d96f4cfb76cc634eafd5456b431832c146c3095bc5c` |
| TLSH | `T14893B71A3E619FFFF66C827487F78A3046C572562ED08745E16CFA491E3064E681F3A8` |
| TELFHASH | `t1b11135b5bd30a12d6d4505248d8c49b06614b313b3195e32ff38c5ec1d350d1b20fd6e` |
| SSDEEP | `1536:a/F3J2KfuUiEMLjaM6w6cXr6qWsKscWNCEWKIOBFPioqgmD1dhKmnbChTJTn8A83:aGRJ76qWsKscWNCEWKIOBFPima1jbbKi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_2849af57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2849af577a06f7399e7312666ffbe6021ef0759be43d21a976ccfb336baeb137"
    family = "unknown"
    file_name = "dxgi"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:19"
  condition:
    hash.sha256(0, filesize) == "2849af577a06f7399e7312666ffbe6021ef0759be43d21a976ccfb336baeb137"
}
```

### Sample 8: `f087ec5d003ae07d`

| Field | Value |
|---|---|
| SHA-256 | `f087ec5d003ae07d505382345f7c24c0322247e856e1374751ee3b3e781fe6a7` |
| Family label | `unknown` |
| File name | `openal` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:16` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f8ed49ce5996d7c8eda91c1a1a5176f` |
| SHA-1 | `7a8eff18ff9135e2cfdc8a9ad6270280e0fb3d1d` |
| SHA-256 | `f087ec5d003ae07d505382345f7c24c0322247e856e1374751ee3b3e781fe6a7` |
| SHA3-384 | `4345e61448911ca9e10c903994f41b7248b8a3a8b8cc478d07d6c8587d3d229970ca3879bd3ee21b969a9615dba03920` |
| TLSH | `T184533A42372C4B13C1672AF015F717F183A7FD912B639244A61EBE894673FB16906FA8` |
| TELFHASH | `t1b11135b5bd30a12d6d4505248d8c49b06614b313b3195e32ff38c5ec1d350d1b20fd6e` |
| SSDEEP | `768:9doLC7VurZzUISS+bGoygKYVq7NLfyFOhI++Z0drphGXj2Np53+o9Mc11TZHmfR:kMudQ1S+bdqxIOhIF0hphI+wmdGfR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_f087ec5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f087ec5d003ae07d505382345f7c24c0322247e856e1374751ee3b3e781fe6a7"
    family = "unknown"
    file_name = "openal"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:16"
  condition:
    hash.sha256(0, filesize) == "f087ec5d003ae07d505382345f7c24c0322247e856e1374751ee3b3e781fe6a7"
}
```

### Sample 9: `3ec16b971cd15e1e`

| Field | Value |
|---|---|
| SHA-256 | `3ec16b971cd15e1e2e07f870ab66daa2ad1967e12da9a7036cb34a9d1fd012a9` |
| Family label | `unknown` |
| File name | `ddraw` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:14` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3094355bcd555704ad200950bcb0d8d3` |
| SHA-1 | `2dbd349d7fcf50864ef3bcac76525f0f2bc25c46` |
| SHA-256 | `3ec16b971cd15e1e2e07f870ab66daa2ad1967e12da9a7036cb34a9d1fd012a9` |
| SHA3-384 | `d69dcf4a9e0b700204869fb728fd73c6dbfa2fcf9c929380d9c01e60346cd417af37d2fa35973128b6b45aae8808f2d1` |
| TLSH | `T1496329917505EE7FEC4BF37689D30724F530B91A5A630662B266BDA34A722C47839F02` |
| TELFHASH | `t19f11f0b5a930a12d6d4909248d8c89b06614b313a3195e32be39c5ec2d354a1b21fe6e` |
| SSDEEP | `1536:XORoa3h0ubR45zBC2J8J4zoyFcRLwOVd/WZrkHl8HG3n:sbMzBdnvsw8dEAHl5n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_3ec16b97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ec16b971cd15e1e2e07f870ab66daa2ad1967e12da9a7036cb34a9d1fd012a9"
    family = "unknown"
    file_name = "ddraw"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:14"
  condition:
    hash.sha256(0, filesize) == "3ec16b971cd15e1e2e07f870ab66daa2ad1967e12da9a7036cb34a9d1fd012a9"
}
```

### Sample 10: `c58aa5775db17153`

| Field | Value |
|---|---|
| SHA-256 | `c58aa5775db17153220f5c676b1d03d0c3ab0464550a30da047c6af8695d0b61` |
| Family label | `unknown` |
| File name | `vulkan` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:11` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ce23da0d1b1ae10795a7cd293da8991` |
| SHA-1 | `2cdf176a54cc408eed07e1f80fb7066fdb5b014e` |
| SHA-256 | `c58aa5775db17153220f5c676b1d03d0c3ab0464550a30da047c6af8695d0b61` |
| SHA3-384 | `8b17967b4bf33234786a92a49b916607d4cef407c564e2f98d05384e3d0864cb1ffc0543ac6927959cfd7f2761a035cc` |
| TLSH | `T18E734B327A755E17C4C8A17A41E74331B7F1AA1A58B7961EBD316EC8BB107C03A2B374` |
| TELFHASH | `t13a1112b5b930a12d6d490a248d8d49b06614b313b3195e32ff38c5ec1d364d1b20fd6e` |
| SSDEEP | `768:6jJdr77Qa5A0XHzmR0IJ2PDrA7GashflO+l+BW6MbpEhZ4Ck3d1dLXmm09:6jfr77fHz40uEnOwhfll+NypEYCWDh09` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_c58aa577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c58aa5775db17153220f5c676b1d03d0c3ab0464550a30da047c6af8695d0b61"
    family = "unknown"
    file_name = "vulkan"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:11"
  condition:
    hash.sha256(0, filesize) == "c58aa5775db17153220f5c676b1d03d0c3ab0464550a30da047c6af8695d0b61"
}
```

### Sample 11: `ade786a1912b30d2`

| Field | Value |
|---|---|
| SHA-256 | `ade786a1912b30d20290c2426bf889255d9e50bde8d7f72e31db97e8814e9312` |
| Family label | `unknown` |
| File name | `libEGL` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:08` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `470ed371e811e6a6c845216746889f6d` |
| SHA-1 | `4dc7adf283c9cec39a9a0da6b4a983fd27b3dc57` |
| SHA-256 | `ade786a1912b30d20290c2426bf889255d9e50bde8d7f72e31db97e8814e9312` |
| SHA3-384 | `6c2dbe8290cb3edd2219a4d3185435384f97320c0e5272798db153b7b7a0e6ca5262e425d1992614273b6ca19b447ceb` |
| TLSH | `T1D0932A06B5918A53C0C617797A9F966937237BA8C7DF33039A186FB42F4279E0E3E111` |
| TELFHASH | `t1fd213566b934a52dbe650924dd9c86f15210a72373080e31bf39c5ec1d3a092f52bd5f` |
| SSDEEP | `1536:1Ynbe1Sb3Su1Y4dWrN4XuCmQ6MXhidJPk9Zk+ytAQa6zoTciO/re2r:tSbG4Mp4XtKJPk9Ztytha6wyKi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_ade786a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ade786a1912b30d20290c2426bf889255d9e50bde8d7f72e31db97e8814e9312"
    family = "unknown"
    file_name = "libEGL"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:08"
  condition:
    hash.sha256(0, filesize) == "ade786a1912b30d20290c2426bf889255d9e50bde8d7f72e31db97e8814e9312"
}
```

### Sample 12: `8c2ff62d55d632fe`

| Field | Value |
|---|---|
| SHA-256 | `8c2ff62d55d632fed8e3a828a1b89f2e623e7f2a0014f032d1fe04a6a6254150` |
| Family label | `unknown` |
| File name | `d3d9` |
| File type | `elf` |
| First seen | `2026-11-18 07:39:05` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7bb8aef1405cc014355c31ec725ec2fa` |
| SHA-1 | `c1a28936548afe6f184e24c23abb5b91aa6b4b10` |
| SHA-256 | `8c2ff62d55d632fed8e3a828a1b89f2e623e7f2a0014f032d1fe04a6a6254150` |
| SHA3-384 | `6cec03b58524b61801a4c547d472c6ae89a21f725db8e848e6406b19ef58cc4467881a252e77d8e0662a340650d9c890` |
| TLSH | `T1EA533B85A923DAB3D4436BB51BE38B204931F83A0B36AD46F72D7EF45E526C8701935C` |
| TELFHASH | `t1d91163a5bd30a53ead5555208d8c89b06614f323b3194e32ff38c4ec6d3a091b21bdae` |
| SSDEEP | `1536:xIfoAPRarJuHWfhygvRGMeIpx1V39orf8/xPzx5uSNK:xIX9gJGI71V+kPzBK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_8c2ff62d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c2ff62d55d632fed8e3a828a1b89f2e623e7f2a0014f032d1fe04a6a6254150"
    family = "unknown"
    file_name = "d3d9"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:05"
  condition:
    hash.sha256(0, filesize) == "8c2ff62d55d632fed8e3a828a1b89f2e623e7f2a0014f032d1fe04a6a6254150"
}
```

### Sample 13: `e45d7773ee91b55d`

| Field | Value |
|---|---|
| SHA-256 | `e45d7773ee91b55d98d77c7792f3930d0b2adf89bf3f82a01ec1a85eadee1f20` |
| Family label | `STRRAT` |
| File name | `Tax Returns of R38,765.js` |
| File type | `js` |
| First seen | `2026-11-18 07:35:06` |
| Reporter | `abuse_ch` |
| Tags | `js, STRRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d88d5c6428e7848d5336365cb42cc4f5` |
| SHA-1 | `17f8d89deb1d93aa9b5eb812e6e37d2764d0a0a8` |
| SHA-256 | `e45d7773ee91b55d98d77c7792f3930d0b2adf89bf3f82a01ec1a85eadee1f20` |
| SHA3-384 | `4a003bfb61d833a59a7c06fa2e8722821cecd576dd0db5cec85629a19c1333aa9e3d810adbd2f9f0f85ce1d3b820bfb0` |
| TLSH | `T1C8050F55B3AA098B1B0B9F34341A1D6377B80B60EFCC49C49657EE998C5EFC70259E0B` |
| SSDEEP | `3072:OJErxpJI1qxg1PYGWecfH954PSRSBrM3XzaGZCkXY7qx2DWuO9UaBbVgOzmoeraZ:N` |

#### Technical Assessment

- The sample is tracked as `STRRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_STRRAT_013_e45d7773
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e45d7773ee91b55d98d77c7792f3930d0b2adf89bf3f82a01ec1a85eadee1f20"
    family = "STRRAT"
    file_name = "Tax Returns of R38,765.js"
    file_type = "js"
    first_seen = "2026-11-18 07:35:06"
  condition:
    hash.sha256(0, filesize) == "e45d7773ee91b55d98d77c7792f3930d0b2adf89bf3f82a01ec1a85eadee1f20"
}
```

### Sample 14: `fd17b84f0abdbcb6`

| Field | Value |
|---|---|
| SHA-256 | `fd17b84f0abdbcb6c734727a3fb9346d8dd2a2b5c87b088bef5b7e7e163adc98` |
| Family label | `unknown` |
| File name | `Loader_v2.exe` |
| File type | `exe` |
| First seen | `2026-11-18 07:35:06` |
| Reporter | `smica83` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3798c4fdb62dee9ddec007e7c3d1c299` |
| SHA-1 | `f6eabdf668c894e288c6033fb4a6fe096b176258` |
| SHA-256 | `fd17b84f0abdbcb6c734727a3fb9346d8dd2a2b5c87b088bef5b7e7e163adc98` |
| SHA3-384 | `ef2121065d379593731d7dc91ef573c0bf858ba2e8b225f6128ff6d54dc69996a16c16638f758197db39228e79dbcb83` |
| IMPHASH | `f0d05c1dd5ba1ed096c85a04a8275fec` |
| TLSH | `T1143733E0696151FBD8E69630D8F9E92BD723B8C78B3085E7039049379E934D81E397E1` |
| SSDEEP | `393216:EjEv8L8TlNIZ37UJ32eivEoxa8g3mlyjPZE34Ja90nGmIFFXEfdtN2azCkOxOWBn:EjEvFbS4ce2IVmM+O29v5azBOEwuJuz` |
| ICON-DHASH | `aebc385c4ce0e8f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_fd17b84f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd17b84f0abdbcb6c734727a3fb9346d8dd2a2b5c87b088bef5b7e7e163adc98"
    family = "unknown"
    file_name = "Loader_v2.exe"
    file_type = "exe"
    first_seen = "2026-11-18 07:35:06"
  condition:
    hash.sha256(0, filesize) == "fd17b84f0abdbcb6c734727a3fb9346d8dd2a2b5c87b088bef5b7e7e163adc98"
}
```

### Sample 15: `91e5263f8146a978`

| Field | Value |
|---|---|
| SHA-256 | `91e5263f8146a978a86dcee7e6a9e818cf2156d4383b91d02c30f55d12b193f4` |
| Family label | `unknown` |
| File name | `WindowsUpdate.jar` |
| File type | `jar` |
| First seen | `2026-11-18 07:31:45` |
| Reporter | `smica83` |
| Tags | `jar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8072b07f339c33e4b6ef8334f64ead48` |
| SHA-1 | `7f5ba77f1abf8d58237df7c1bd83bd8810a04201` |
| SHA-256 | `91e5263f8146a978a86dcee7e6a9e818cf2156d4383b91d02c30f55d12b193f4` |
| SHA3-384 | `44622919795560b9a4bf5ef2f2d73e4d103a2e84902eefb9777420fec893d831312ed430ec256a16bb56e2387475c93c` |
| TLSH | `T160A533CF2B9B1BF5C81E2F7C9B7263C0DA5173D09D9482515FD4582EC51BA832CB22A6` |
| SSDEEP | `49152:GMiIC5h3yTnCEslUEfh/vnx4FPPThd2/mz+W4/oL:OpusqEp/vnx2DOLd6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_91e5263f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91e5263f8146a978a86dcee7e6a9e818cf2156d4383b91d02c30f55d12b193f4"
    family = "unknown"
    file_name = "WindowsUpdate.jar"
    file_type = "jar"
    first_seen = "2026-11-18 07:31:45"
  condition:
    hash.sha256(0, filesize) == "91e5263f8146a978a86dcee7e6a9e818cf2156d4383b91d02c30f55d12b193f4"
}
```

### Sample 16: `30bad4cfd09e6381`

| Field | Value |
|---|---|
| SHA-256 | `30bad4cfd09e6381328b78411f7254478d50f26d0f0e7682cd4562b3405186a9` |
| Family label | `unknown` |
| File name | `wp.py` |
| File type | `py` |
| First seen | `2026-11-18 07:27:15` |
| Reporter | `real_kaeptnbalu` |
| Tags | `persistence, py, watchdog` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c44e71990225562ad36b54a916ef3283` |
| SHA-1 | `7af847888261bae05caab4655788918ce37b00d6` |
| SHA-256 | `30bad4cfd09e6381328b78411f7254478d50f26d0f0e7682cd4562b3405186a9` |
| SHA3-384 | `60c8d183bed4f6e2576932ba78a8cd6090c3c4beb4339097d0131e3b7ba55eefd5a5ff7dbf8243f610ec816c5c40124d` |
| TLSH | `T145314ED2FE6CA421D663C6191522C0806A9B69A3E74B9878BCCCE5107F470B0D2BA85E` |
| SSDEEP | `24:5NtihZkVcAYgvpYpKAgbvvrlKOKCEtwvg/iKSbSj/H9IvTv4OVXafSmf+29h:H0Zy3CKLbvv5KO/EH+OKvTwmXUzD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `py`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_30bad4cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30bad4cfd09e6381328b78411f7254478d50f26d0f0e7682cd4562b3405186a9"
    family = "unknown"
    file_name = "wp.py"
    file_type = "py"
    first_seen = "2026-11-18 07:27:15"
  condition:
    hash.sha256(0, filesize) == "30bad4cfd09e6381328b78411f7254478d50f26d0f0e7682cd4562b3405186a9"
}
```

### Sample 17: `c30c8e937d48dae4`

| Field | Value |
|---|---|
| SHA-256 | `c30c8e937d48dae48c5c6a65952a409ef78f259075f64fbf27b250d5c9b394f2` |
| Family label | `unknown` |
| File name | `xinj.py` |
| File type | `py` |
| First seen | `2026-11-18 07:27:11` |
| Reporter | `real_kaeptnbalu` |
| Tags | `injector, py, shellcode` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `444af5dd0e118e23c8dbd3de24a8cbed` |
| SHA-1 | `bfb4c4af3c94a81beaf5f8292f338ffc39066143` |
| SHA-256 | `c30c8e937d48dae48c5c6a65952a409ef78f259075f64fbf27b250d5c9b394f2` |
| SHA3-384 | `25b8d205de217484f5f843116cdefe0baeabc96fdfb57b8d43f0413c41e889f19fcfd48e0c40b90ff62248de7700a334` |
| TLSH | `T1A072C601494E9576C38394489622CCC23F66A50766346E3CBFEEC372AF8D57E82747B9` |
| SSDEEP | `192:J25BNqLcNHn4zH9alGD4C0kJnFhpZ0Pd7/yRz9h2EThYyABrwiXk3q5efguzXj1C:J25niHyC0kJHmdUh2sYyR1NeZZNzEzs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `py`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_c30c8e93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c30c8e937d48dae48c5c6a65952a409ef78f259075f64fbf27b250d5c9b394f2"
    family = "unknown"
    file_name = "xinj.py"
    file_type = "py"
    first_seen = "2026-11-18 07:27:11"
  condition:
    hash.sha256(0, filesize) == "c30c8e937d48dae48c5c6a65952a409ef78f259075f64fbf27b250d5c9b394f2"
}
```

### Sample 18: `8848e83cc2c61974`

| Field | Value |
|---|---|
| SHA-256 | `8848e83cc2c619748d0900da2b4867b7dd01f5f104200ee3a8e2f7a6d7143c0f` |
| Family label | `Mirai` |
| File name | `mentality-cloud.x86_64` |
| File type | `elf` |
| First seen | `2026-11-18 07:11:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11fc6ae28524147e6f5996f8f6e1a6c8` |
| SHA-1 | `a6c3a8f8f783624d02ea43a333c85b80c327d771` |
| SHA-256 | `8848e83cc2c619748d0900da2b4867b7dd01f5f104200ee3a8e2f7a6d7143c0f` |
| SHA3-384 | `8eec54648d5af4d303d42052d3c63bcd19cff3dbd9e1bc31d1a6a1436f679086a65f437e3d752a89920f63a5b55be0ba` |
| TLSH | `T196734B47798081FDC5AAC43943BFB236C463B0BE1239B29B53D9FE262D4AE601F1D855` |
| TELFHASH | `t1572125a679950c74e0fbe076f35af8652c721e9024e03af5ce3ba5f29b283d50c61817` |
| SSDEEP | `1536:ZkXZ6kG/wnd4ER6qPFZ7E2ztgeyBlsPUVjxfq/kxen:OZlG/wnd4iLPFZHztGBls4xfq//n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_8848e83c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8848e83cc2c619748d0900da2b4867b7dd01f5f104200ee3a8e2f7a6d7143c0f"
    family = "Mirai"
    file_name = "mentality-cloud.x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 07:11:23"
  condition:
    hash.sha256(0, filesize) == "8848e83cc2c619748d0900da2b4867b7dd01f5f104200ee3a8e2f7a6d7143c0f"
}
```

### Sample 19: `027b645b8b20614d`

| Field | Value |
|---|---|
| SHA-256 | `027b645b8b20614d77d0648ed2c1765641fae5e6358ddacde2463c75cb2ce18f` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.arm7` |
| File type | `elf` |
| First seen | `2026-11-18 07:11:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0f9c409352916a84c4eb46624647f30` |
| SHA-1 | `bda365ac85e0930436fca1c8add1f0113eeef0e6` |
| SHA-256 | `027b645b8b20614d77d0648ed2c1765641fae5e6358ddacde2463c75cb2ce18f` |
| SHA3-384 | `d36b5f0e02894e17ee5a285f25b05ba308f830241c2e9af74c07d578a54a81c4152291ebc2f20fb4cb011322aa347035` |
| TLSH | `T1DDE34C46FA414F13C0D61779BAEF424933239B9593DB73069928AFB43F8275E0E63A05` |
| TELFHASH | `t1932120b1173652195961eeac89ed67710a2cc3021341ff33ef22c4ac640504eea2ac0f` |
| SSDEEP | `3072:2XFXMIMN6vwVRaXgfIOG2kJNrfY0cGSII4M/9x37I:2XFXMIMKCRaXgfIOGFDZcGSIjM/9x37I` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_027b645b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "027b645b8b20614d77d0648ed2c1765641fae5e6358ddacde2463c75cb2ce18f"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm7"
    file_type = "elf"
    first_seen = "2026-11-18 07:11:18"
  condition:
    hash.sha256(0, filesize) == "027b645b8b20614d77d0648ed2c1765641fae5e6358ddacde2463c75cb2ce18f"
}
```

### Sample 20: `89795adac8f814af`

| Field | Value |
|---|---|
| SHA-256 | `89795adac8f814af28ac6def74c8c21a07f2b227596810088ffccb7fbe2205d5` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.ppc` |
| File type | `elf` |
| First seen | `2026-11-18 07:11:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6171fb36547d2b81cd6bdde6ec512a04` |
| SHA-1 | `e17cc9f7d23daeb9ad3aae7b6992d0c70c6f605e` |
| SHA-256 | `89795adac8f814af28ac6def74c8c21a07f2b227596810088ffccb7fbe2205d5` |
| SHA3-384 | `3f3f3b1cfa9dd7f2e05bff5f9ef63a5275aec9c269fba17d7709aa50f34dc5c2b69613f2aa93940c48ae0f8974a4001c` |
| TLSH | `T16B534A02B31C0A43C1A71970293F2BD19BFBFAD122E4F689251F9B969671E335485FC9` |
| SSDEEP | `1536:8Mp9lKxanh3KS5jc0ujthwtvlIWhaJ3Akl:VhVRKS5jcRjAlIWaBAa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_89795ada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89795adac8f814af28ac6def74c8c21a07f2b227596810088ffccb7fbe2205d5"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.ppc"
    file_type = "elf"
    first_seen = "2026-11-18 07:11:13"
  condition:
    hash.sha256(0, filesize) == "89795adac8f814af28ac6def74c8c21a07f2b227596810088ffccb7fbe2205d5"
}
```

### Sample 21: `771463af999817e8`

| Field | Value |
|---|---|
| SHA-256 | `771463af999817e8f76240ddc983fd554de5de011ff81fa7947d25016d165054` |
| Family label | `Mirai` |
| File name | `mentality-cloud.x86` |
| File type | `elf` |
| First seen | `2026-11-18 07:11:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54edd455438b5131868659d3e7c84535` |
| SHA-1 | `d07ae7e2387ae4313d18e6ee8a15a6d92a3dce6e` |
| SHA-256 | `771463af999817e8f76240ddc983fd554de5de011ff81fa7947d25016d165054` |
| SHA3-384 | `67256bdfb02e9e62b2a4da56abcae6853a8945f43c64a558bf6a23b35ebf4c18c6b14608e7753125b2046bd4e12531bf` |
| TLSH | `T1E0737CC5FA83D4F5E81205352277AB379AB3E53E2168DF83C379A672DC03542E91629C` |
| TELFHASH | `t1c531f7fb0abe0ceca7d0a940c32b5e51295ee77b14a037b605639934236bdc3507ac79` |
| SSDEEP | `1536:/S8t9cXSZERVMnvi6qKIUPX2D2CYVNhXdCo0ZV:/vt95Z9nvi6qnUuDLMddo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_771463af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "771463af999817e8f76240ddc983fd554de5de011ff81fa7947d25016d165054"
    family = "Mirai"
    file_name = "mentality-cloud.x86"
    file_type = "elf"
    first_seen = "2026-11-18 07:11:08"
  condition:
    hash.sha256(0, filesize) == "771463af999817e8f76240ddc983fd554de5de011ff81fa7947d25016d165054"
}
```

### Sample 22: `766387fa0582545e`

| Field | Value |
|---|---|
| SHA-256 | `766387fa0582545e6f23237d0ac63862084d6d4f8eec86cdaf24a3fcddc125ee` |
| Family label | `Mirai` |
| File name | `mentality-cloud.i686` |
| File type | `elf` |
| First seen | `2026-11-18 07:11:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c41939715e24ca0c7148177c6e0b53e` |
| SHA-1 | `d07f8e37fee7e5dadc637f00bd73b5633bf29b4e` |
| SHA-256 | `766387fa0582545e6f23237d0ac63862084d6d4f8eec86cdaf24a3fcddc125ee` |
| SHA3-384 | `ef3258cc4afa74c124a5a6305efd1a172d7f1c6af481a8b3ec539e6a49d3548cba70eae96376591a960f79bd9ba68f2b` |
| TLSH | `T1E58339C1FA8BC1F6E91B88344076F23FCA32E96940B2C75DDF5AAF36DA335415212259` |
| TELFHASH | `t1b3313cf9097d08e4a7d4ac80c24f6f71390ae77b24e072b146b358353267e0250b9c7b` |
| SSDEEP | `1536:s8Yw0s4oyfpPJvNYhpa90dJyU3WM83JOJoLEAQk/sA3O:GTsCtJVYddJs93JOJYE83O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_766387fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "766387fa0582545e6f23237d0ac63862084d6d4f8eec86cdaf24a3fcddc125ee"
    family = "Mirai"
    file_name = "mentality-cloud.i686"
    file_type = "elf"
    first_seen = "2026-11-18 07:11:02"
  condition:
    hash.sha256(0, filesize) == "766387fa0582545e6f23237d0ac63862084d6d4f8eec86cdaf24a3fcddc125ee"
}
```

### Sample 23: `3dd5927cdeda55f7`

| Field | Value |
|---|---|
| SHA-256 | `3dd5927cdeda55f7bc1d8aabc534568d163be2d570c4818b83e438d988a64340` |
| Family label | `Mirai` |
| File name | `mentality-cloud.mips` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ceb685592b3140c391ac36c32735b517` |
| SHA-1 | `d3b9464c8c1f936ec4d534c2c807261d75c7c2eb` |
| SHA-256 | `3dd5927cdeda55f7bc1d8aabc534568d163be2d570c4818b83e438d988a64340` |
| SHA3-384 | `36a006678cd5d85ebc357081e7534d3ad78af1b3d4e5c203209491ea29c0d46c2f0c6de608486d37d9266b9d5c049843` |
| TLSH | `T1EAB3D64E7F329F7CFBA8C23447B35A21A65923D227E1DA85D19CD6011E7024E681FBB4` |
| TELFHASH | `t17811581c8d3863e0d7751caa6becff76e15130eb0a256e378e10e99d9a6dd429e01c1c` |
| SSDEEP | `1536:9kUl7xt8Fyhmf/tOhsEeK/6eq7BuMTEXSiy7APk2PK6e/BdHZLBZ:bl7xRwnzEeKieq7Bu+EXSiy7OkAKBZLH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_3dd5927c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dd5927cdeda55f7bc1d8aabc534568d163be2d570c4818b83e438d988a64340"
    family = "Mirai"
    file_name = "mentality-cloud.mips"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:58"
  condition:
    hash.sha256(0, filesize) == "3dd5927cdeda55f7bc1d8aabc534568d163be2d570c4818b83e438d988a64340"
}
```

### Sample 24: `964018bdf5064e24`

| Field | Value |
|---|---|
| SHA-256 | `964018bdf5064e241d4def33333bca60358e7f474217f4544dbb88c46da0f75b` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.i686` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5225abc24c7e74c6b9ddb5ca5b36b0ee` |
| SHA-1 | `09e10174e67e2e732b5f97bce223bb1395d1abfb` |
| SHA-256 | `964018bdf5064e241d4def33333bca60358e7f474217f4544dbb88c46da0f75b` |
| SHA3-384 | `83b8a5ae115efc0e30229515e7000651cda9b83316e654a8b94aa0aa7839df5a7d8e22d56fdb8824d38d7540172b88d7` |
| TLSH | `T18C532982F48B80F2D84B493050A7F63FDF30D9EA5170DA5EEFA99F75EA275428111A4C` |
| TELFHASH | `t18f21d1ff0afe18e8e3d8a840c35e2ee1586ae63b106132f54132d8581393dd285a9c79` |
| SSDEEP | `1536:Ur09IO9eOLTUl/MUeuY2WXyQsaHXYzwHTUdcpos:k0iO9eOLTUl/xeuyiFcXYzYTIwo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_964018bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "964018bdf5064e241d4def33333bca60358e7f474217f4544dbb88c46da0f75b"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.i686"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:54"
  condition:
    hash.sha256(0, filesize) == "964018bdf5064e241d4def33333bca60358e7f474217f4544dbb88c46da0f75b"
}
```

### Sample 25: `9fff203b78906ab9`

| Field | Value |
|---|---|
| SHA-256 | `9fff203b78906ab9dd944d3811c9d005fc1dcd5970993afa028c185227aca173` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.arm` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a81ff9494a757538690d7eed7f068936` |
| SHA-1 | `68dd6ec5fef907599a3471767de50d562215f149` |
| SHA-256 | `9fff203b78906ab9dd944d3811c9d005fc1dcd5970993afa028c185227aca173` |
| SHA3-384 | `7654182cb1a77814c0ab92729c4f950afa4591aac6ec998596aded022ba8116e6c34bb885e7032f2671b92c10576a858` |
| TLSH | `T1AE633B91FC819A13C5C5037AFAAE42CD3B2613E8E2DA7217CE255F2137C651B0C6BE65` |
| TELFHASH | `t1bc4113f781688adc3be48340469b162bcead34781746359aee1d379fc193ce0722a437` |
| SSDEEP | `1536:FlLaq6tjm6X2qN+UfKGLYSJWwm1b5BY69Gvts:FlODf9JTm3iLts` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_9fff203b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fff203b78906ab9dd944d3811c9d005fc1dcd5970993afa028c185227aca173"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:50"
  condition:
    hash.sha256(0, filesize) == "9fff203b78906ab9dd944d3811c9d005fc1dcd5970993afa028c185227aca173"
}
```

### Sample 26: `4d5f0068493838dc`

| Field | Value |
|---|---|
| SHA-256 | `4d5f0068493838dcdc4404f52af4d6134775fa525eacd81e0dd114e4bb429f11` |
| Family label | `Mirai` |
| File name | `mentality-cloud.arm5` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2c8cc4f51c40a958f6d2fad62d7cf63` |
| SHA-1 | `ac2b2b79214d9ea506b7b4c2c2095054fe2efd23` |
| SHA-256 | `4d5f0068493838dcdc4404f52af4d6134775fa525eacd81e0dd114e4bb429f11` |
| SHA3-384 | `adf79679a4b12beb232b185c42a7eb8ffbb2a909e88519affd8b0ec8259b7de075750549d4e8407c1d590565712c3f70` |
| TLSH | `T1B8331A81FCD2996EC6C0237AA73E618F3311B3A4D1CF3617CD182B2276C661F4DA6A41` |
| TELFHASH | `t10fe06140fe764b1884e75a34ecdd47b495116217a1664710cf54daf0883f15ca71cd5e` |
| SSDEEP | `768:5ZypRmLbTn1YUc3FVfc8+ArQ5fwMC0ydAvjJ1fLWottBfXLSLBNLnHKmz:5smXTWJ1ufwMC0V1fLXfXLS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_4d5f0068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d5f0068493838dcdc4404f52af4d6134775fa525eacd81e0dd114e4bb429f11"
    family = "Mirai"
    file_name = "mentality-cloud.arm5"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:46"
  condition:
    hash.sha256(0, filesize) == "4d5f0068493838dcdc4404f52af4d6134775fa525eacd81e0dd114e4bb429f11"
}
```

### Sample 27: `2f454e85e3707fc3`

| Field | Value |
|---|---|
| SHA-256 | `2f454e85e3707fc36bc3f365263324c309b05556a3b13e10b545029db74442f7` |
| Family label | `Mirai` |
| File name | `mentality-cloud.arm7` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82ab8564219f153f78a2536629009df3` |
| SHA-1 | `d4a5a69d9c54c1aaf356587c7e97fa7cc84a168e` |
| SHA-256 | `2f454e85e3707fc36bc3f365263324c309b05556a3b13e10b545029db74442f7` |
| SHA3-384 | `60582edd4ba081421b3de2a1971343cb0655a52dbfd6458414000d27802c78ade20abcc70ab42934c20e19382b30d10e` |
| TLSH | `T178F33B46EA418A13C0D62779BB9F424633239764D3EB33069928BFF43F8679E0E67505` |
| TELFHASH | `t14421ed31573151196ab1d964ecec97b2152987132389ee33df3ac8dc181a09be93ec0f` |
| SSDEEP | `3072:wNhUhCsANaACirxFxgj6g1IPCbKv0jmyct0M/9TdNi4:wNnXNaACirxFaWgcCGvImycyM/9q4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_2f454e85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f454e85e3707fc36bc3f365263324c309b05556a3b13e10b545029db74442f7"
    family = "Mirai"
    file_name = "mentality-cloud.arm7"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:42"
  condition:
    hash.sha256(0, filesize) == "2f454e85e3707fc36bc3f365263324c309b05556a3b13e10b545029db74442f7"
}
```

### Sample 28: `ebbc9f8ff016d262`

| Field | Value |
|---|---|
| SHA-256 | `ebbc9f8ff016d2628cf44ad55998c1f8e8b86e6076fd6b38bc140157dd7ed20e` |
| Family label | `Mirai` |
| File name | `mentality-cloud.ppc` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abe96b14ddc99718486f3dcd82ddbc6c` |
| SHA-1 | `c59334224ce05ee95b54449ef422e91e9abad786` |
| SHA-256 | `ebbc9f8ff016d2628cf44ad55998c1f8e8b86e6076fd6b38bc140157dd7ed20e` |
| SHA3-384 | `f464b2ce09562e4842da4892572c1bfa2d90bde83b79fbefc767a02c8e44368b47dd62790f33a975c9e79edca3fde688` |
| TLSH | `T178834A02734C0D47D1675EF42A3F27E583AFE99121E4FA89650FDB4681B2E33154AEC8` |
| SSDEEP | `1536:m6SrhsZbpUKISos7S9Y+wuFqKTu0uKYaT:m6SrhsZaoU9uueqT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_ebbc9f8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebbc9f8ff016d2628cf44ad55998c1f8e8b86e6076fd6b38bc140157dd7ed20e"
    family = "Mirai"
    file_name = "mentality-cloud.ppc"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:38"
  condition:
    hash.sha256(0, filesize) == "ebbc9f8ff016d2628cf44ad55998c1f8e8b86e6076fd6b38bc140157dd7ed20e"
}
```

### Sample 29: `13df1c87c1cdbf8f`

| Field | Value |
|---|---|
| SHA-256 | `13df1c87c1cdbf8f64f0c6d2011bbae1ae0f5adfa1df3f55a8aa915e216abb5b` |
| Family label | `Mirai` |
| File name | `mentality-cloud.mpsl` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bea4dec9d311bc09aec7957a352c7f08` |
| SHA-1 | `623bb29887f935a87abab5471ff99088a8be99b1` |
| SHA-256 | `13df1c87c1cdbf8f64f0c6d2011bbae1ae0f5adfa1df3f55a8aa915e216abb5b` |
| SHA3-384 | `fa790875d1ab200e1d473db438d15ed540743ea30eadbe3ea41aef37ad77e5893711d6c5667b82bc0a8bf77082ec85e6` |
| TLSH | `T1E3B3D709BFA10EF7E86FCC3709E91B0128CD692621B87B75B574D518F24A64F1AE3874` |
| SSDEEP | `1536:slHGj1ufd3fCAbgwKSjJwMtdljkm9oRlcdCZpWAwQerFbpclOWNgw1V:slSed3fCAb0S7ElcdCKjr0D1V` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_13df1c87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13df1c87c1cdbf8f64f0c6d2011bbae1ae0f5adfa1df3f55a8aa915e216abb5b"
    family = "Mirai"
    file_name = "mentality-cloud.mpsl"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:34"
  condition:
    hash.sha256(0, filesize) == "13df1c87c1cdbf8f64f0c6d2011bbae1ae0f5adfa1df3f55a8aa915e216abb5b"
}
```

### Sample 30: `bc02e875442bea02`

| Field | Value |
|---|---|
| SHA-256 | `bc02e875442bea0299bf413e1403c81d0f76e185edc85da5e79169b06c364274` |
| Family label | `Mirai` |
| File name | `mentality-cloud.arm` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae4ca3f84dddb229d9964549b6e75c6e` |
| SHA-1 | `b9c5c7cfa5033d49d7b69f5dd78983b5b95044ef` |
| SHA-256 | `bc02e875442bea0299bf413e1403c81d0f76e185edc85da5e79169b06c364274` |
| SHA3-384 | `9816985390e0fb41a19cb09d435aa469c235064a2f86c8053b7f871282064b5402b124ee8dc608e966a45409e564dcd8` |
| TLSH | `T184834C85FC819A12C6C5277BFB2E028E37262394E2DE3207DE259F2237C651B0D7B555` |
| TELFHASH | `t1f251ceb79b981fdd9be9c200468d21159afd31bd1b1425638e1c6b8b85839c2f22f81b` |
| SSDEEP | `1536:C6HrI1SwOle8I4t76nF8jkk4Q3+gKm3pB2IOkZvHe:C6HM1KleEWFxBQ3OUtHe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_bc02e875
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc02e875442bea0299bf413e1403c81d0f76e185edc85da5e79169b06c364274"
    family = "Mirai"
    file_name = "mentality-cloud.arm"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:30"
  condition:
    hash.sha256(0, filesize) == "bc02e875442bea0299bf413e1403c81d0f76e185edc85da5e79169b06c364274"
}
```

### Sample 31: `115234e37a7198a3`

| Field | Value |
|---|---|
| SHA-256 | `115234e37a7198a3057f3d86d93a14de96e7251ed4ebfa7ff8dab98893e275d3` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.x86_64` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc5770326bbce1c3b15e967bd91b3288` |
| SHA-1 | `014aac0b0cc117d21732fd9d63560867f4cea8cd` |
| SHA-256 | `115234e37a7198a3057f3d86d93a14de96e7251ed4ebfa7ff8dab98893e275d3` |
| SHA3-384 | `cc01138adfd84d033bdbbf3326f99933071e8d9f36e3403faa3249b3c70139d22f322d293121580dab653d52abee6fc3` |
| TLSH | `T14053090BB84280FDC096C134577EBA3AE93670FE1278B2A777E8BF262956D610D0DD44` |
| TELFHASH | `t143110467385a04c0e0fbf572734bf0985d3a1e6414e038e2e432a1b6e7197428a79c37` |
| SSDEEP | `1536:Rx43P9P1q5DCf784ZvPABluKok7JZ2YjBSh4:D4319q5WDvPAB/ok7WYjBSh4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_115234e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "115234e37a7198a3057f3d86d93a14de96e7251ed4ebfa7ff8dab98893e275d3"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:26"
  condition:
    hash.sha256(0, filesize) == "115234e37a7198a3057f3d86d93a14de96e7251ed4ebfa7ff8dab98893e275d3"
}
```

### Sample 32: `1291219ad7b29688`

| Field | Value |
|---|---|
| SHA-256 | `1291219ad7b296887c8bbdb14d4d7ed6207855d8641f193fa65a331890ddf3c5` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.mpsl` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4de86328ce19bb3975db5cb40c70fdde` |
| SHA-1 | `90d7191d7569bad120656bb4c0aadf31d1deebc1` |
| SHA-256 | `1291219ad7b296887c8bbdb14d4d7ed6207855d8641f193fa65a331890ddf3c5` |
| SHA3-384 | `1d0c0f650a245f6577b73830e294bcda89715bd8966f665d5ed590dc1ca1c2e86bf7bd05ab26ad0eda57063050f20347` |
| TLSH | `T1FF93B509BF904FB7DCABCC370AA91B0129CC555722A97F36B534D828B55B20B6AD3C74` |
| SSDEEP | `1536:Mp4/FL9VOjR6fmMhuCQ9Jqq5DLE+2CZYssIa13bT:Mp4/F5VOjRIuCGDLE5CYBbT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_1291219a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1291219ad7b296887c8bbdb14d4d7ed6207855d8641f193fa65a331890ddf3c5"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.mpsl"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:21"
  condition:
    hash.sha256(0, filesize) == "1291219ad7b296887c8bbdb14d4d7ed6207855d8641f193fa65a331890ddf3c5"
}
```

### Sample 33: `b475f90544354232`

| Field | Value |
|---|---|
| SHA-256 | `b475f90544354232758432ba2ae7efb64ce7d2a64c3d11bd2da97f51c22d7b6a` |
| Family label | `Mirai` |
| File name | `mentality-cloud.m68k` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19f38ce39bb1e85f5735fe100603e465` |
| SHA-1 | `1f28db8ce193a15fed40a342ccb433746050f08a` |
| SHA-256 | `b475f90544354232758432ba2ae7efb64ce7d2a64c3d11bd2da97f51c22d7b6a` |
| SHA3-384 | `6b080db3e071df3267442bea62f9f13984d7005c441362d639bc0c1f4d728a486509bcdf2f46a933e928b1393e859ce9` |
| TLSH | `T1AE9329C6B400DD7DF41FDABB4463490AB930A3625A931F277767BD63AC321A44867E82` |
| SSDEEP | `1536:wtoloJ7TK7ijQsYS//OtgpoMDg7w2AggBuzLiHa8Y6UrB5PM8IQX2CrzEWM035v+:wTQtSOurgK68hUrBB9GTWn3N6l47kHeQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_b475f905
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b475f90544354232758432ba2ae7efb64ce7d2a64c3d11bd2da97f51c22d7b6a"
    family = "Mirai"
    file_name = "mentality-cloud.m68k"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:13"
  condition:
    hash.sha256(0, filesize) == "b475f90544354232758432ba2ae7efb64ce7d2a64c3d11bd2da97f51c22d7b6a"
}
```

### Sample 34: `5590f9ab82bea661`

| Field | Value |
|---|---|
| SHA-256 | `5590f9ab82bea6615a272158a255d5c82ef21878c06783c7b195b9f5440b010f` |
| Family label | `Mirai` |
| File name | `mentality-cloud.spc` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5be4e4d39c11a0bea2b1097426241dde` |
| SHA-1 | `367a086e61314a241bc2ce7baf1930056a53a461` |
| SHA-256 | `5590f9ab82bea6615a272158a255d5c82ef21878c06783c7b195b9f5440b010f` |
| SHA3-384 | `4624b752ae3c69942a8fee2e87a15545b141f225671a253f62dcb6609f4a2ec36a86f3f1b5089c555ef7c7ae429f49b7` |
| TLSH | `T1BA836C21B8391E2BC4E4A47B22F34336F1F6438E24A89B1E7D710E8DBF2159036576B5` |
| SSDEEP | `1536:YsKLwgD3bFGaemX5XYE4ZoZ1UtS+dYm5swZsw0XtVp:5+bIsJAM6YOso8p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_5590f9ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5590f9ab82bea6615a272158a255d5c82ef21878c06783c7b195b9f5440b010f"
    family = "Mirai"
    file_name = "mentality-cloud.spc"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:10"
  condition:
    hash.sha256(0, filesize) == "5590f9ab82bea6615a272158a255d5c82ef21878c06783c7b195b9f5440b010f"
}
```

### Sample 35: `c7aed76b8795268f`

| Field | Value |
|---|---|
| SHA-256 | `c7aed76b8795268f151cf85f36d778d55a9be3e785ed41b03d90c44ebd203e9b` |
| Family label | `Mirai` |
| File name | `mentality-cloud.x86_64` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfc98194d3cddcd5c7ec9ddf6292d33e` |
| SHA-1 | `8d56df8cac47b352591e2db781fb088c1e0284f0` |
| SHA-256 | `c7aed76b8795268f151cf85f36d778d55a9be3e785ed41b03d90c44ebd203e9b` |
| SHA3-384 | `28fdeff263bc3f28bd7bd7837f889bb07270b512d8cd8a4c0398d941c86cdbb6683b94c612c487162c9bb8b09d22f05e` |
| TLSH | `T1A103F1FB25BF9AFCD4EC31F1099D3BE6F578705108952B690A1E51FC4C62A362A21B70` |
| SSDEEP | `768:bVvFysIRIoYVpn2FM6h+DacgvUcSI0x7TxNFkpBqHx0Yo:p0ROAFM6h+DMvUME5NFIoxo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_c7aed76b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7aed76b8795268f151cf85f36d778d55a9be3e785ed41b03d90c44ebd203e9b"
    family = "Mirai"
    file_name = "mentality-cloud.x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:06"
  condition:
    hash.sha256(0, filesize) == "c7aed76b8795268f151cf85f36d778d55a9be3e785ed41b03d90c44ebd203e9b"
}
```

### Sample 36: `2b84598489b7338b`

| Field | Value |
|---|---|
| SHA-256 | `2b84598489b7338b867a6fbb4638bd41c857c738ac9906f10ebabf1afbbfe8d2` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.arc` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3860d11499bc26a0c86457a70e77565d` |
| SHA-1 | `a1a0d8f1aefbaf5a1688ad50cadfc84d6014e4a5` |
| SHA-256 | `2b84598489b7338b867a6fbb4638bd41c857c738ac9906f10ebabf1afbbfe8d2` |
| SHA3-384 | `f0d42ed275dd5807c9d7ae9c5fe0d3a8b6c597d020f5ba3c25be17f9fb2da90be50c0d608359392aa264e0e30d05f569` |
| TLSH | `T113B39DDBF2871161C89246F007CB4BAE3E2323C15F178AE73C69667969751DF8902F92` |
| SSDEEP | `1536:QhmlPOHh1bhawTY+jSprkfxmW1toNK04gG5O/LWh:amlGHQwTY+jyMxhoNK04gG5Oq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_2b845984
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b84598489b7338b867a6fbb4638bd41c857c738ac9906f10ebabf1afbbfe8d2"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arc"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:03"
  condition:
    hash.sha256(0, filesize) == "2b84598489b7338b867a6fbb4638bd41c857c738ac9906f10ebabf1afbbfe8d2"
}
```

### Sample 37: `20eff41f1d2be20f`

| Field | Value |
|---|---|
| SHA-256 | `20eff41f1d2be20f8f92205497962c7d10c4a5bf1d109e0ce34ac2c661214550` |
| Family label | `Mirai` |
| File name | `mentality-cloud.sh4` |
| File type | `elf` |
| First seen | `2026-11-18 07:10:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `004e4a7d39e5f77b8d06fad2f0931402` |
| SHA-1 | `d22bbc7989a165e0ad6300f2748ed5ecf5487002` |
| SHA-256 | `20eff41f1d2be20f8f92205497962c7d10c4a5bf1d109e0ce34ac2c661214550` |
| SHA3-384 | `0a519ce7244c3601ef737a3352a9f650c6f364f774926da0c9d09cdaa94b2426462493712c2a79d9d0b0a83cb508a958` |
| TLSH | `T1CC739E63C8691D98C65C82B879B49E391333D850A5971FF616EACA36D047EDCF4093F8` |
| SSDEEP | `1536:8/YLYVOdd7dl/+GvXmKbuaD7K5SnyC7uJwEuk:8gLYgTD/+cZbN2SnyfSTk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_20eff41f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20eff41f1d2be20f8f92205497962c7d10c4a5bf1d109e0ce34ac2c661214550"
    family = "Mirai"
    file_name = "mentality-cloud.sh4"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:00"
  condition:
    hash.sha256(0, filesize) == "20eff41f1d2be20f8f92205497962c7d10c4a5bf1d109e0ce34ac2c661214550"
}
```

### Sample 38: `f9f663749098bbee`

| Field | Value |
|---|---|
| SHA-256 | `f9f663749098bbee31fa7da817e2cee6aa63d7248da1d9c5471f5c8d5c286730` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.arm7` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6497afe9d089954e8c5f982e451c9b92` |
| SHA-1 | `4fc5b897b06bebd8a3b02dd8fa3967d9b2b2ba60` |
| SHA-256 | `f9f663749098bbee31fa7da817e2cee6aa63d7248da1d9c5471f5c8d5c286730` |
| SHA3-384 | `2805a632f5158cc91d04c17dd9c29fe487dad1dfdd827738e5555c71ccd39ec540821ff0a253518b806544e75c098475` |
| TLSH | `T15B43F117E2365EB7E3402C7658AC5156BF11CEFAB4B9203B13180A1E7B80806EF562CA` |
| SSDEEP | `768:7oY/HEtFo3q6QsaGOOWPNRV3w4B2qYP/ZHx0bX9q3UELeHbBXw7I0xQAZCkrdBrR:7oMn3twOQ5gemLGNX/iZCEBryYjR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_f9f66374
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9f663749098bbee31fa7da817e2cee6aa63d7248da1d9c5471f5c8d5c286730"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm7"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:58"
  condition:
    hash.sha256(0, filesize) == "f9f663749098bbee31fa7da817e2cee6aa63d7248da1d9c5471f5c8d5c286730"
}
```

### Sample 39: `806bd8770459788f`

| Field | Value |
|---|---|
| SHA-256 | `806bd8770459788f99d6ffcd149b5e9daa0f49ee03b78d93791aa331e5023178` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.ppc` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `110a9554ed7675483e7302bb528483bd` |
| SHA-1 | `23fcf66699be406add6cff227d52133356fdf6de` |
| SHA-256 | `806bd8770459788f99d6ffcd149b5e9daa0f49ee03b78d93791aa331e5023178` |
| SHA3-384 | `7482c4fb713514eb661004917c5b38bf8336894fa212ac1bc20c831d0e4f06fc953f6aff13c2e74c0602b89009f66212` |
| TLSH | `T126C2F138E84239CFDB53B8F01C92DAD663B21F9F2A614DD2E752AB70525B51352C07C8` |
| SSDEEP | `768:i7ZgG5QPFUwzAc1hI+wc8yzbUQIpG4uVcqgw0906D:+ZvucIhff8yzAQIpG4u+qgw090C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_806bd877
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "806bd8770459788f99d6ffcd149b5e9daa0f49ee03b78d93791aa331e5023178"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.ppc"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:55"
  condition:
    hash.sha256(0, filesize) == "806bd8770459788f99d6ffcd149b5e9daa0f49ee03b78d93791aa331e5023178"
}
```

### Sample 40: `9b7143308b280d7c`

| Field | Value |
|---|---|
| SHA-256 | `9b7143308b280d7c5784ff339f7f990a7ebc2e561b898651798f23a1c413cbcd` |
| Family label | `Mirai` |
| File name | `mentality-cloud.x86` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e30e6238d75bfc3a542d6a03fab4ca71` |
| SHA-1 | `a27aca77d64564e9e1d7a387025d5c75dee54434` |
| SHA-256 | `9b7143308b280d7c5784ff339f7f990a7ebc2e561b898651798f23a1c413cbcd` |
| SHA3-384 | `05d4dae49b5ee29d97618adae8bb336b93af3b95bf52c7f35859339e100ff0fc8bc7b5095e4be5ff35f78a0a72665bd4` |
| TLSH | `T12C03F1579947E74BD17A44357C86B03F2A888685608F475BFA88502D0A61F7A2F3C7B8` |
| SSDEEP | `768:NRTysS5vrzogxo9a3SLo+yqXhG1UjFVB2EPc/LIjxv85nknbcuyD7UHQRjFb:XTys8vrzqa3tq01UjJOTIdU5nknouy8W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_9b714330
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b7143308b280d7c5784ff339f7f990a7ebc2e561b898651798f23a1c413cbcd"
    family = "Mirai"
    file_name = "mentality-cloud.x86"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:52"
  condition:
    hash.sha256(0, filesize) == "9b7143308b280d7c5784ff339f7f990a7ebc2e561b898651798f23a1c413cbcd"
}
```

### Sample 41: `6e0a9b65891ec826`

| Field | Value |
|---|---|
| SHA-256 | `6e0a9b65891ec8269e636aeee0b0210148a2e4c91932e90f3a61da527487c825` |
| Family label | `Mirai` |
| File name | `mentality-cloud.i686` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8cb2f37defde8347e3ad3985f361219a` |
| SHA-1 | `c0e20d815efe08b565030203229d46149010186f` |
| SHA-256 | `6e0a9b65891ec8269e636aeee0b0210148a2e4c91932e90f3a61da527487c825` |
| SHA3-384 | `864e7518b94b8d92c93ca3c7f033b9419245923aed3c46f573b572bd4f4146f181405cafc42728e7726f178a3c7f18f5` |
| TLSH | `T10403E1378C7A6D1EE86E14B07CFAFA0E1025DCDA70854DF9EAC061B76AF5729491C2C4` |
| SSDEEP | `768:dUgyoBu/IhKeSIg+VXWTUUGn9UmKVf2g1r3W/d3WOcAhZ1WeWXnbcuyD7UHQRjn:dUg66geGon9UhVf11rG/oOcAhZ1NWXnO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_6e0a9b65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e0a9b65891ec8269e636aeee0b0210148a2e4c91932e90f3a61da527487c825"
    family = "Mirai"
    file_name = "mentality-cloud.i686"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:50"
  condition:
    hash.sha256(0, filesize) == "6e0a9b65891ec8269e636aeee0b0210148a2e4c91932e90f3a61da527487c825"
}
```

### Sample 42: `3967a8fbd4bffd90`

| Field | Value |
|---|---|
| SHA-256 | `3967a8fbd4bffd90e51dd478f964d18f03dd41eb28d750118820c400c5b0e17d` |
| Family label | `Mirai` |
| File name | `mentality-cloud.mips` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `164cb429838e913a1c0427a8da5dd3cb` |
| SHA-1 | `4fbe6b512bc43b32203e00d1354211ff22f4d7a9` |
| SHA-256 | `3967a8fbd4bffd90e51dd478f964d18f03dd41eb28d750118820c400c5b0e17d` |
| SHA3-384 | `ef5f16e69ab2a9b4e40d0a0c9f754fb5b19ad6265a76bcddb566cfd603763d7e3ab3cc0e8c059aee2712712752d7b107` |
| TLSH | `T16F03F14C3B5649DACC47D8365BC18FD82E9967F7BCC34A53AA35A12789C21447C6B3C8` |
| SSDEEP | `768:KFsmm9Rs3gJzrGrVV5OgcbbV/WNFtCCM2mtC+yQyJ/dBEUlJgGlzDpbuR1JVQ:KFs303gJ2rtOfbVONFt02p9lBRfVJus` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_3967a8fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3967a8fbd4bffd90e51dd478f964d18f03dd41eb28d750118820c400c5b0e17d"
    family = "Mirai"
    file_name = "mentality-cloud.mips"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:47"
  condition:
    hash.sha256(0, filesize) == "3967a8fbd4bffd90e51dd478f964d18f03dd41eb28d750118820c400c5b0e17d"
}
```

### Sample 43: `7a9f8a2d271b96c0`

| Field | Value |
|---|---|
| SHA-256 | `7a9f8a2d271b96c06d839ff8978d3581aa7771cea568f8d966324c14ba5e1f1e` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.i686` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d51897213ccaec2deec537253c2f9f8a` |
| SHA-1 | `db6d36c86cf7fa8f175efa13d5d26edf797d3c93` |
| SHA-256 | `7a9f8a2d271b96c06d839ff8978d3581aa7771cea568f8d966324c14ba5e1f1e` |
| SHA3-384 | `cde66ba032444183eefdcc0563ff09a534bd45fae30f7cf8702b8f39492dfafcd1dc43d358ee6ca8b322e1d1bc971daa` |
| TLSH | `T1D4D2E1D492C0574FC47F4B3E425D08FF40715ACC778DC6CAA9DEA282A4AB254E5BC95C` |
| SSDEEP | `768:znZvT1iw5z24QOSeVHa9meWA4sYGZb+f3Afq:zZbYuKyFHubWFHGZKkq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_7a9f8a2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a9f8a2d271b96c06d839ff8978d3581aa7771cea568f8d966324c14ba5e1f1e"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.i686"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:44"
  condition:
    hash.sha256(0, filesize) == "7a9f8a2d271b96c06d839ff8978d3581aa7771cea568f8d966324c14ba5e1f1e"
}
```

### Sample 44: `d6d8021e2e5dbce1`

| Field | Value |
|---|---|
| SHA-256 | `d6d8021e2e5dbce11c0ec9d5ef433485cb0834fc3bd4164a72f61993e017f5ec` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.arm` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46dcc95741d09dc4fd2149d73da56cc1` |
| SHA-1 | `70285b3059bf224529ad4683e2b0352cc7e25774` |
| SHA-256 | `d6d8021e2e5dbce11c0ec9d5ef433485cb0834fc3bd4164a72f61993e017f5ec` |
| SHA3-384 | `eeba224de9838043b38f3913ff77d5aae7a12ffdb2a436c896304836c0ee58838e82038eef7118538ad8432432cfb729` |
| TLSH | `T1C4D2D17CB4148580EAE508362439D2D77A571AF9D2D937772060676C39C791E0AF8B89` |
| SSDEEP | `768:S0beLCMhEsL8aAuqRVCB38PRKXkBgfsis3Uoz6:S0iv85PumZwGgfez6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_d6d8021e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6d8021e2e5dbce11c0ec9d5ef433485cb0834fc3bd4164a72f61993e017f5ec"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:42"
  condition:
    hash.sha256(0, filesize) == "d6d8021e2e5dbce11c0ec9d5ef433485cb0834fc3bd4164a72f61993e017f5ec"
}
```

### Sample 45: `f7a590cd7ebcfe9f`

| Field | Value |
|---|---|
| SHA-256 | `f7a590cd7ebcfe9f20b633ad2535cd4b303ada673c20db45ab2b1daa0886eeef` |
| Family label | `Mirai` |
| File name | `mentality-cloud.arm5` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53bb6a11975ac7284b4a020bc6f557f7` |
| SHA-1 | `82eac419589669b71609b9f4375767b9d56e4e63` |
| SHA-256 | `f7a590cd7ebcfe9f20b633ad2535cd4b303ada673c20db45ab2b1daa0886eeef` |
| SHA3-384 | `3bf999217b935dca5fe9f6ea4222db041c77c06885849dc3db7ab3da6719eb17a01ef0e6e85513771202422d0433c7aa` |
| TLSH | `T1D5B2D030A0A7357297741E3158F8CAC1FF57827AD04A30310D6495EAEE9BC1E676CB83` |
| SSDEEP | `384:ysFg+xJ1OkzrG15x1T6LItk6xX+Vd4+wB3PxqhgB60qU3Cbn8hymdGUop5hH4:/LJ1trG15x1TEItk4XCZQ/s0qUyb8s3Q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_f7a590cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7a590cd7ebcfe9f20b633ad2535cd4b303ada673c20db45ab2b1daa0886eeef"
    family = "Mirai"
    file_name = "mentality-cloud.arm5"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:39"
  condition:
    hash.sha256(0, filesize) == "f7a590cd7ebcfe9f20b633ad2535cd4b303ada673c20db45ab2b1daa0886eeef"
}
```

### Sample 46: `f7bc67915ebcc38c`

| Field | Value |
|---|---|
| SHA-256 | `f7bc67915ebcc38cc4b4ff2e7006f2e0918baf689dbf3e366371b6eb77afcd03` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.sh4` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af322e24f3fdad02dcdd4b6c2a884066` |
| SHA-1 | `92a5ed5b09ccba1c4614384f23872accc9d5d70d` |
| SHA-256 | `f7bc67915ebcc38cc4b4ff2e7006f2e0918baf689dbf3e366371b6eb77afcd03` |
| SHA3-384 | `50446cb4b59d675236f50d178a95e63807433e838f788cb3b44e7746187b9c8867aa8ccae003609993e196f1f2dfa63b` |
| TLSH | `T19F438D3AD4296D54C0964574B4AC8F351F23E0C883536EFB2AA983B96453DADFA01FF4` |
| SSDEEP | `768:QakzqAuHqHXSt7qQLrTfpXkb99Z7XdsCs07PK8OHIavoWlknSTC6blJIfmNhSwsI:QaC2yCF/9W7XdsF0K8OHTAW5TC6hNJs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_f7bc6791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7bc67915ebcc38cc4b4ff2e7006f2e0918baf689dbf3e366371b6eb77afcd03"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.sh4"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:36"
  condition:
    hash.sha256(0, filesize) == "f7bc67915ebcc38cc4b4ff2e7006f2e0918baf689dbf3e366371b6eb77afcd03"
}
```

### Sample 47: `b4a2d9cca8891c0a`

| Field | Value |
|---|---|
| SHA-256 | `b4a2d9cca8891c0ae3d7a314ef8e4c3742e77b7cbee8ed8a692da22ddb02f3ba` |
| Family label | `Mirai` |
| File name | `mentality-cloud.arm7` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99628fc4cdb42062768421b220cfb513` |
| SHA-1 | `d535cf7cb7895ffa160b2f48887d4e330dcbcc8a` |
| SHA-256 | `b4a2d9cca8891c0ae3d7a314ef8e4c3742e77b7cbee8ed8a692da22ddb02f3ba` |
| SHA3-384 | `4edf8c7a937e418e33519340c0d813c598339ec35bdb1505256e2c714bdd3c91ba3e9ac44b5dc53b613b6dc50123af85` |
| TLSH | `T105530219FF1620F5BF60F8F9AFEB6581BA1B87BDE34C211F20444555B89205CB3E8496` |
| SSDEEP | `1536:Ck+JSfCDyoWIGLCR944Od5EOEPjLgaZSk94rbXtC:CkXxOqEG4Od53OjLgafa3tC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_b4a2d9cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4a2d9cca8891c0ae3d7a314ef8e4c3742e77b7cbee8ed8a692da22ddb02f3ba"
    family = "Mirai"
    file_name = "mentality-cloud.arm7"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:34"
  condition:
    hash.sha256(0, filesize) == "b4a2d9cca8891c0ae3d7a314ef8e4c3742e77b7cbee8ed8a692da22ddb02f3ba"
}
```

### Sample 48: `b4ae5c8cfe802522`

| Field | Value |
|---|---|
| SHA-256 | `b4ae5c8cfe80252221ac27fb14c13aafb56f272de222e8a06e671b22bb14b12d` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.m68k` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74032c3ff4d646157ccd4c4d97b9a6c4` |
| SHA-1 | `fbce38fa4daddb74a2992d78e4351f021c48fc5b` |
| SHA-256 | `b4ae5c8cfe80252221ac27fb14c13aafb56f272de222e8a06e671b22bb14b12d` |
| SHA3-384 | `d8657e4f4a3582035357f37f4b4381c123e9a3f42f2126020881c4390dbc53f260feac5ea399708f57b1cd8c56e7ae6f` |
| TLSH | `T1E6632ADAF801DD7DF80FE6BA4417090AB931A3D142830B3767A7FDA3BC721A55912E85` |
| SSDEEP | `1536:52AymkBuxq8ZoBsaIBmq2sY5SieciIJqO:5AmYux64m/sM9JqO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_b4ae5c8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4ae5c8cfe80252221ac27fb14c13aafb56f272de222e8a06e671b22bb14b12d"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.m68k"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:31"
  condition:
    hash.sha256(0, filesize) == "b4ae5c8cfe80252221ac27fb14c13aafb56f272de222e8a06e671b22bb14b12d"
}
```

### Sample 49: `3fcb447f7e76d8f7`

| Field | Value |
|---|---|
| SHA-256 | `3fcb447f7e76d8f7753e5935975f66a09380393c33f42626242cf120e3d29cd0` |
| Family label | `Mirai` |
| File name | `mentality-cloud.ppc` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3977641e9d35d29709a453efcbe8ba51` |
| SHA-1 | `0a660d16534a2ebc9bd93f9ebf23f052d4d12dd5` |
| SHA-256 | `3fcb447f7e76d8f7753e5935975f66a09380393c33f42626242cf120e3d29cd0` |
| SHA3-384 | `a75614b55104ed5310b71a9587ed5f7ea30f331b20dea1ee63d7fea78e528bbcff1f4c56190645094853b457c74e2613` |
| TLSH | `T1B603E1E6D2085E1BFB7998A14C5AA2C32B810F4DF6F1CD49C0AE9911D2C132F6655FEC` |
| SSDEEP | `768:JM1+vwULWbo0Xv8LMGJwP4NkZcGS4y5Lzgi2bOgSCJKTpl24uVcqgw09H:JW6Qoz1QcXLzAbOtCJKTS4u+qgw09H` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_3fcb447f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fcb447f7e76d8f7753e5935975f66a09380393c33f42626242cf120e3d29cd0"
    family = "Mirai"
    file_name = "mentality-cloud.ppc"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:28"
  condition:
    hash.sha256(0, filesize) == "3fcb447f7e76d8f7753e5935975f66a09380393c33f42626242cf120e3d29cd0"
}
```

### Sample 50: `eea08dc35c05f43c`

| Field | Value |
|---|---|
| SHA-256 | `eea08dc35c05f43c65aad780a0a5ea74e3754ed389f6a8f9dd447245e728e8a8` |
| Family label | `Mirai` |
| File name | `mentality-cloud.mpsl` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8158841d0369a9c63ba284ec6b9f814a` |
| SHA-1 | `33496999ce8a76911dc7353555d7a8503d44aaa0` |
| SHA-256 | `eea08dc35c05f43c65aad780a0a5ea74e3754ed389f6a8f9dd447245e728e8a8` |
| SHA3-384 | `a263e642c561c3688d0b33c0a030792ec5772cef7b505c9f6f2e058495eafc0b74476d06334091ea97758c4721cb9694` |
| TLSH | `T11813E11D95A91896CE8C5DB2184E44C48E88F1D4769E35C87310CCA1EDEC98EEED89EF` |
| SSDEEP | `768:jK4PkOw7q8dOnCmQLUMRiHh5Y0Rcba/6m8BDFeXgCXSUjj3b7gTVWe:bw7qfnCVxQlRlWFeQXUv3bEV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_eea08dc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eea08dc35c05f43c65aad780a0a5ea74e3754ed389f6a8f9dd447245e728e8a8"
    family = "Mirai"
    file_name = "mentality-cloud.mpsl"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:25"
  condition:
    hash.sha256(0, filesize) == "eea08dc35c05f43c65aad780a0a5ea74e3754ed389f6a8f9dd447245e728e8a8"
}
```

### Sample 51: `61767e616dc37556`

| Field | Value |
|---|---|
| SHA-256 | `61767e616dc37556066837dd0dafddbce022fdd1494019d6fca6d92ef8f588d2` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.arm5` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a6bb0c94825c7f32a06eed79a065993` |
| SHA-1 | `bd7b9f4cf13847fdbb5f25ca94db4e74541b813b` |
| SHA-256 | `61767e616dc37556066837dd0dafddbce022fdd1494019d6fca6d92ef8f588d2` |
| SHA3-384 | `b1a3b19900ce69bcf0c0a73da5ee26fd316e5c42f4876392e5f1ecf8b426f30f207affeb18714321b2a726267bd81410` |
| TLSH | `T19E13F791F8815A2BC6D0137AFAAF5A8D3321B3E8E2CB7217CD514B117AD561F0C6AF50` |
| TELFHASH | `t1dae02600fc759a1d6ac76a74eccc46b4a601726751664b00cf14dbe4c83f450a70ca4a` |
| SSDEEP | `768:2tyym5M/Bx/dRhFmE+m9phf8ZZQmItrPWxHbMbqN4tQapdPh1mA2EDEy0eYjW9TX:Wm5GFmPmphUv/IpPNbqNOQafOPLpTZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_61767e61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61767e616dc37556066837dd0dafddbce022fdd1494019d6fca6d92ef8f588d2"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm5"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:24"
  condition:
    hash.sha256(0, filesize) == "61767e616dc37556066837dd0dafddbce022fdd1494019d6fca6d92ef8f588d2"
}
```

### Sample 52: `9f4c9d9665c70ff9`

| Field | Value |
|---|---|
| SHA-256 | `9f4c9d9665c70ff9a6e214329e8d3ce4556500ba20e038eb80450328ffe2380d` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.spc` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b272d52db197ff4cf0abf103f41af14b` |
| SHA-1 | `0325228f1c43d9952919926090c9be2f55d9f82d` |
| SHA-256 | `9f4c9d9665c70ff9a6e214329e8d3ce4556500ba20e038eb80450328ffe2380d` |
| SHA3-384 | `7e462064adab5c7c5de697deae29564789e06a2e69a746ae50cf186fed81cb6f7e8702f90e0e1e584fd52e9ca8e133c8` |
| TLSH | `T10B632B21BA351E17C0D4647A21FB5B19B2F196DE62A8C61E3D710E4FFF21A406943EF8` |
| SSDEEP | `1536:3aRh4MjrNUzgXXvcxbmTK3FVjDC4UinR75SYvtt+nvvZ:KtNWFbnRVjH+J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_9f4c9d96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f4c9d9665c70ff9a6e214329e8d3ce4556500ba20e038eb80450328ffe2380d"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.spc"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:23"
  condition:
    hash.sha256(0, filesize) == "9f4c9d9665c70ff9a6e214329e8d3ce4556500ba20e038eb80450328ffe2380d"
}
```

### Sample 53: `96e694c33484c087`

| Field | Value |
|---|---|
| SHA-256 | `96e694c33484c0876b3827884295d457f03e0cc3dc607bf0ed2719b26a04fdc9` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.mips` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `142d259d52f3032c5af47690fc176d8d` |
| SHA-1 | `681d06423a2f7e1a717a2d797a078c6d6e3173da` |
| SHA-256 | `96e694c33484c0876b3827884295d457f03e0cc3dc607bf0ed2719b26a04fdc9` |
| SHA3-384 | `db3204aff14f4efa7a0f1af2e80eb80ca0d47636b62e5fc44749a5d5de46fe32bc92d4db9d0ef06aa283773f3e3318c7` |
| TLSH | `T10683D81E7E218FBDFAE9863447B78E16A65833CA37E1D585D16CD6002E6024E341FFA4` |
| TELFHASH | `t1a1014c488d3892f457361dca676def77f55530df06125d378e00b96daa6e9429e01c0c` |
| SSDEEP | `1536:lv1ZlKmxtBidTspK83i2HSOUWiaVeAxrFQ:5Jxthp1i2yOUWiazrFQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_96e694c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96e694c33484c0876b3827884295d457f03e0cc3dc607bf0ed2719b26a04fdc9"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.mips"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:20"
  condition:
    hash.sha256(0, filesize) == "96e694c33484c0876b3827884295d457f03e0cc3dc607bf0ed2719b26a04fdc9"
}
```

### Sample 54: `1345a7c5746070ee`

| Field | Value |
|---|---|
| SHA-256 | `1345a7c5746070ee4d3457c1dd990c9ee74201a8cd9829d79d974097b832c015` |
| Family label | `Mirai` |
| File name | `mentality-cloud.arm` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68a686b27332f8154f70209716d7ab9c` |
| SHA-1 | `812c22c402bcee2a1da8aff1fdf1b6c67fec461f` |
| SHA-256 | `1345a7c5746070ee4d3457c1dd990c9ee74201a8cd9829d79d974097b832c015` |
| SHA3-384 | `708eee16e9bd7eda80e0a1e9be5e9db1bb940e8f7fcc676622f48f59dd16bba6b5db8e0872e1adf76900a847d5097644` |
| TLSH | `T13803F1715BAC6D30C31414BE9C1DEEDD17B315BEC36A64520825272BEE9D3817C7289E` |
| SSDEEP | `768:WlvaF3CbBVcD6s6/fDM2m147XaU9O+taI/iSXlzAVLuw0h6s5fJVs3UozT:LF3Cbe6/847qUfVVXtxw0h7yzT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_1345a7c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1345a7c5746070ee4d3457c1dd990c9ee74201a8cd9829d79d974097b832c015"
    family = "Mirai"
    file_name = "mentality-cloud.arm"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:20"
  condition:
    hash.sha256(0, filesize) == "1345a7c5746070ee4d3457c1dd990c9ee74201a8cd9829d79d974097b832c015"
}
```

### Sample 55: `f5d29434e7a5b62b`

| Field | Value |
|---|---|
| SHA-256 | `f5d29434e7a5b62bbb5cf3c87579cb8c762c484c44f20b576e64cabd5c4accf6` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.x86_64` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c68c29557b0b7a6d5ecdb4b109958ba` |
| SHA-1 | `f0f48f0df6a38be94a8e59f850b489a924f65113` |
| SHA-256 | `f5d29434e7a5b62bbb5cf3c87579cb8c762c484c44f20b576e64cabd5c4accf6` |
| SHA3-384 | `f78fa04ac2bac4c8349119c16f811f9bc7f2d9ce985e597de539606649e8a5ac5cbfbc235730f37f52dd526fc2669303` |
| TLSH | `T189D2D086207AF3EDD17281BA51D3E56B5ED73851AED853CD180FB0AA42D0A66E170FE0` |
| SSDEEP | `768:eaajh00oaZnvH2dbJCnUPVsBqlop/1eJ6K406JzfGsh:3G60oaRvUd9lop/hKKLh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_f5d29434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5d29434e7a5b62bbb5cf3c87579cb8c762c484c44f20b576e64cabd5c4accf6"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:17"
  condition:
    hash.sha256(0, filesize) == "f5d29434e7a5b62bbb5cf3c87579cb8c762c484c44f20b576e64cabd5c4accf6"
}
```

### Sample 56: `593efa380d1616ad`

| Field | Value |
|---|---|
| SHA-256 | `593efa380d1616adfa06b9dde008f76e8f24b2069fc1e1523fc3aab74685586f` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.arm6` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7145d1a37cadcb9a956fc7135d934cb` |
| SHA-1 | `3edf367eccc62c455ad960eec43dddad0d5cf477` |
| SHA-256 | `593efa380d1616adfa06b9dde008f76e8f24b2069fc1e1523fc3aab74685586f` |
| SHA3-384 | `812cb461a8f9b6861f84aeedf3e74962ac8f8fca0dfb30beccc178258c4364030ef53f057d464ed69fcf28750c5b3057` |
| TLSH | `T15973F956B8814F21D5D5027AFA2E118E331317B9E3DE72229D209F343BC662B0E7BD55` |
| TELFHASH | `t1ed11a358254816fcf3e0c520c1de35bf595234a9b2022c84c70e5faf06a7ac1b17883f` |
| SSDEEP | `1536:/ln0TtPAkKSC6zFBK9hA7Clz4cannTcBIcixMK97gGHM5zYoNC:ItAbS7P/cafMK97gGHMZRNC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_593efa38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "593efa380d1616adfa06b9dde008f76e8f24b2069fc1e1523fc3aab74685586f"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm6"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:16"
  condition:
    hash.sha256(0, filesize) == "593efa380d1616adfa06b9dde008f76e8f24b2069fc1e1523fc3aab74685586f"
}
```

### Sample 57: `3da5b80c5739af62`

| Field | Value |
|---|---|
| SHA-256 | `3da5b80c5739af62401d588cc32d91f8351399c0f9c0045e25650015657ed345` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.mpsl` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f103be89ac1d0badb722448b691b2a3a` |
| SHA-1 | `b392718524ba13605e8016199216a2cdfb66f1df` |
| SHA-256 | `3da5b80c5739af62401d588cc32d91f8351399c0f9c0045e25650015657ed345` |
| SHA3-384 | `d1dca5ece4a9de25497038d397585c8b554b78ef14f187493ff0a0bd0551e1f80dbd3072fcd4ec7faca5467bf392ab02` |
| TLSH | `T12DE2D05FF87DF906C9AE8535518D0365CE84B4C5327F97085320ECCC7A1DE66BAAC468` |
| SSDEEP | `768:3J1P1TBwNMennf+L7MveSiqGE00l6Bti9fg6Wr:3DhBwNMofk70TiqGCYri9fgD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_3da5b80c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3da5b80c5739af62401d588cc32d91f8351399c0f9c0045e25650015657ed345"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.mpsl"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:15"
  condition:
    hash.sha256(0, filesize) == "3da5b80c5739af62401d588cc32d91f8351399c0f9c0045e25650015657ed345"
}
```

### Sample 58: `a1795f396b86bbf1`

| Field | Value |
|---|---|
| SHA-256 | `a1795f396b86bbf1c8afcafee7b3bea660626d714cbb926bc2f65de06ca45011` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.arm5` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbcb9f1da340216d026b7003072c4c5a` |
| SHA-1 | `1cea15d0222868ae0c9827e28d029f4f20aae408` |
| SHA-256 | `a1795f396b86bbf1c8afcafee7b3bea660626d714cbb926bc2f65de06ca45011` |
| SHA3-384 | `213efa60f456bf7bfd1c0cd77eef1b774f299d85ad8be78529cc1ae911b33611bcde07d4554c6441e8fb7426ef91c9ae` |
| TLSH | `T12282BF101656BD62D5348133DAACC9C767AF5DB8C6FA33E131400238E6268A395FDBE7` |
| SSDEEP | `384:NjFEcxjeFOQi9bc8mXG0mjTqqUOb35GefPfKfhymdGUop5h72G:4i9Y8mXGxjTVUOTfPks3Uoz92G` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_a1795f39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1795f396b86bbf1c8afcafee7b3bea660626d714cbb926bc2f65de06ca45011"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm5"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:11"
  condition:
    hash.sha256(0, filesize) == "a1795f396b86bbf1c8afcafee7b3bea660626d714cbb926bc2f65de06ca45011"
}
```

### Sample 59: `67252552e4efcfd5`

| Field | Value |
|---|---|
| SHA-256 | `67252552e4efcfd53929e5cc860e14d95226222cdaa80455fae5a5ad934c3366` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.mips` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cabf370cf42b40871f3e7b2bdb367e3d` |
| SHA-1 | `6dacfd46a8a51f2a56f125116d6348f85b840a4e` |
| SHA-256 | `67252552e4efcfd53929e5cc860e14d95226222cdaa80455fae5a5ad934c3366` |
| SHA3-384 | `a75f470b0af6c5a3c72c8a056ddeee5c320bbb244f8c46770d3886ad9787724f8049f63c181e997155b7bd57e5cb1a88` |
| TLSH | `T111D2D1FC4356178DD6C4C076A3E813982BF10739E0AB9C8D3961D647EC885BA5D877D4` |
| SSDEEP | `768:gACm3crFuJ0BNUXE+J1W4/b8hqd20/ZmQTJgGlzDpbuR1Jy:3d3V0G38W/jVJuM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_67252552
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67252552e4efcfd53929e5cc860e14d95226222cdaa80455fae5a5ad934c3366"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.mips"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:08"
  condition:
    hash.sha256(0, filesize) == "67252552e4efcfd53929e5cc860e14d95226222cdaa80455fae5a5ad934c3366"
}
```

### Sample 60: `a470b3a5cf980b04`

| Field | Value |
|---|---|
| SHA-256 | `a470b3a5cf980b040842ee1d2c5224d10c73869bb59f3c76dc31b366d99d567a` |
| Family label | `Mirai` |
| File name | `FGx8SNCa4txePA.arm6` |
| File type | `elf` |
| First seen | `2026-11-18 07:09:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1af61cf438dc1f36d33cdeafbf8aca9b` |
| SHA-1 | `e7439103451c644e531149b50122bb0b02f8e21a` |
| SHA-256 | `a470b3a5cf980b040842ee1d2c5224d10c73869bb59f3c76dc31b366d99d567a` |
| SHA3-384 | `efcb066b32121589b96d8f9fc951ff4de5b68a23f6ef5f541d58d0f11bdbce05738b4f09a94cd04563a910b830c5f950` |
| TLSH | `T1E3F2F23AFA4356C2CE31083EFBAF86CD974717B0C85E38365455D7391A71602A924F9D` |
| SSDEEP | `768:nEWuV9QrPjpnzsoK2poMTfM+U9l1HZ4FFFSO5aoTYvU9q3UELT1:mw13KkTX6DHZ4JXElLp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_a470b3a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a470b3a5cf980b040842ee1d2c5224d10c73869bb59f3c76dc31b366d99d567a"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm6"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:06"
  condition:
    hash.sha256(0, filesize) == "a470b3a5cf980b040842ee1d2c5224d10c73869bb59f3c76dc31b366d99d567a"
}
```

### Sample 61: `e5a522b2b9d8e922`

| Field | Value |
|---|---|
| SHA-256 | `e5a522b2b9d8e9220e0d4cf43e1587c1d1ccf444812607229f63fabe1ef65830` |
| Family label | `Panchan` |
| File name | `e5a522b2b9d8e9220e0d4cf43e1587c1d1ccf444812607229f63fabe1ef65830` |
| File type | `elf` |
| First seen | `2026-11-18 06:52:18` |
| Reporter | `hett` |
| Tags | `elf, honeypot, Panchan, shardlure` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b01598f670108e18557702d94242af63` |
| SHA-1 | `28b296267a3e8727afac43666c234c905a55b616` |
| SHA-256 | `e5a522b2b9d8e9220e0d4cf43e1587c1d1ccf444812607229f63fabe1ef65830` |
| SHA3-384 | `30c6929bc268f0050e1672af3be8d6f90f582dde2f721facd2b229aff97ddde3a6ce5aaddbc06d880c9158ee07c04049` |
| TLSH | `T126665B73905614D8D1ADC974D5152213BEA8388B673873DBBBC076F11BBABE49A78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQS:cqYUQuVDt0TZEB` |

#### Technical Assessment

- The sample is tracked as `Panchan` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Panchan_061_e5a522b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5a522b2b9d8e9220e0d4cf43e1587c1d1ccf444812607229f63fabe1ef65830"
    family = "Panchan"
    file_name = "e5a522b2b9d8e9220e0d4cf43e1587c1d1ccf444812607229f63fabe1ef65830"
    file_type = "elf"
    first_seen = "2026-11-18 06:52:18"
  condition:
    hash.sha256(0, filesize) == "e5a522b2b9d8e9220e0d4cf43e1587c1d1ccf444812607229f63fabe1ef65830"
}
```

### Sample 62: `8b515b6ece08aaea`

| Field | Value |
|---|---|
| SHA-256 | `8b515b6ece08aaea6f84d5a094394acbababe209b10cccd945d0b46fd6acc6a0` |
| Family label | `XWorm` |
| File name | `_00068` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:40` |
| Reporter | `ni_fi_70` |
| Tags | `exe, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec423b82461d6c5fd5e4ac553af7949a` |
| SHA-1 | `e1e653012332bab8aea54aa6cc5b0c4b5dbba3dd` |
| SHA-256 | `8b515b6ece08aaea6f84d5a094394acbababe209b10cccd945d0b46fd6acc6a0` |
| SHA3-384 | `0afd93e89a384984e0370cda79a8293e1dafa93b5ebc2f915ca4a4757f2c58740b97e16f28104a34aa92b08203dcd567` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T146C4E05426A9DB06CAB6A3F42971E1B813B57DAE7821E3058FD9BDEF7432F040D04A53` |
| SSDEEP | `12288:6bELUirFZ+5O+2q16TZ4FhD+oZIGdNXo/HRFGa+:MENFI5B16TCX+gI+2Gd` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_062_8b515b6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b515b6ece08aaea6f84d5a094394acbababe209b10cccd945d0b46fd6acc6a0"
    family = "XWorm"
    file_name = "_00068"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:40"
  condition:
    hash.sha256(0, filesize) == "8b515b6ece08aaea6f84d5a094394acbababe209b10cccd945d0b46fd6acc6a0"
}
```

### Sample 63: `c4c84f595ae9260f`

| Field | Value |
|---|---|
| SHA-256 | `c4c84f595ae9260f703dadae2379d47591dd92d1b85802105798ab5de2aa1bf4` |
| Family label | `XWorm` |
| File name | `a92816d7b9df41859ae6cba47f1f10b6.MSG` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:36` |
| Reporter | `ni_fi_70` |
| Tags | `exe, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0cc2616b97756ed461236da3e812f47` |
| SHA-1 | `ed188c2b78bbbb4a08e08b725c4442038d451570` |
| SHA-256 | `c4c84f595ae9260f703dadae2379d47591dd92d1b85802105798ab5de2aa1bf4` |
| SHA3-384 | `d25a41bf22bc5a85d85771dd046b33f7de57d9978bb5e56fa8f2033b2ce1c26b8476f039e0289c07bd3bd1c4499d801f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F1C4E0543269DB0AC97257F41A71F2B813F96DAE2862E3068FC5ACDF3976F084E04653` |
| SSDEEP | `12288:tbELUiLYsqCHaR/HfCVGK2TZdJXF9UFQyefg+5O+2q:VE1YsqC6RnCVkdJXLUuy6v5B` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_063_c4c84f59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4c84f595ae9260f703dadae2379d47591dd92d1b85802105798ab5de2aa1bf4"
    family = "XWorm"
    file_name = "a92816d7b9df41859ae6cba47f1f10b6.MSG"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:36"
  condition:
    hash.sha256(0, filesize) == "c4c84f595ae9260f703dadae2379d47591dd92d1b85802105798ab5de2aa1bf4"
}
```

### Sample 64: `8f92be363039893c`

| Field | Value |
|---|---|
| SHA-256 | `8f92be363039893c07a578bf0be3cffd5b22f6cc402c18269ba6e650db81a93f` |
| Family label | `Formbook` |
| File name | `8f92be363039893c07a578bf0be3cffd5b22f6cc402c18269ba6e650db81a93f` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:33` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aed6ea818e989a532d71f06dfa540658` |
| SHA-1 | `028122e283391939e31666c18e00ed144c6c8074` |
| SHA-256 | `8f92be363039893c07a578bf0be3cffd5b22f6cc402c18269ba6e650db81a93f` |
| SHA3-384 | `94a59fa49650d0ff99932cf13bdc33311da7ff8bd01e1ab9d660b795eab028bc1abdbf07e5772f2d5e2ffe8ce66e1721` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E605F14422A8EB19D9BA67F016B2F1B413F97D6EA421D3194FC1ADEBB471F008D09763` |
| SSDEEP | `24576:825BirMfK3QKkYrLePQLVHKxqG2I2jCSi8:EHbk4iQRqxqm2i` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_064_8f92be36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f92be363039893c07a578bf0be3cffd5b22f6cc402c18269ba6e650db81a93f"
    family = "Formbook"
    file_name = "8f92be363039893c07a578bf0be3cffd5b22f6cc402c18269ba6e650db81a93f"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:33"
  condition:
    hash.sha256(0, filesize) == "8f92be363039893c07a578bf0be3cffd5b22f6cc402c18269ba6e650db81a93f"
}
```

### Sample 65: `0c88759246530f18`

| Field | Value |
|---|---|
| SHA-256 | `0c88759246530f189e87fa23a593084b7cc29a389b7a8df08f1413dc731f4ad0` |
| Family label | `XWorm` |
| File name | `entity-kNE9qHNQ` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:30` |
| Reporter | `ni_fi_70` |
| Tags | `exe, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84088a22dabaa7822192979b5cc075dc` |
| SHA-1 | `01538778c3a0ea9369aa3809e048711b21ce1d86` |
| SHA-256 | `0c88759246530f189e87fa23a593084b7cc29a389b7a8df08f1413dc731f4ad0` |
| SHA3-384 | `5c85dbce7388a470eb683ba16dcad9df6bcb4ea21fe1e953b9d1082dd42833e79aef3e7f6f3fac88f7842db7be1fc142` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T190D49C24AAA5E705C56963F0D861E1F583BD6D9AE422C20F8EC57DDB3CF2B027D24643` |
| SSDEEP | `12288:9Azfk3Lv8GXLenU8qif7W0RFs8TH+5O+2q:SLk3IGXKa0RFsd5B` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_065_0c887592
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c88759246530f189e87fa23a593084b7cc29a389b7a8df08f1413dc731f4ad0"
    family = "XWorm"
    file_name = "entity-kNE9qHNQ"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:30"
  condition:
    hash.sha256(0, filesize) == "0c88759246530f189e87fa23a593084b7cc29a389b7a8df08f1413dc731f4ad0"
}
```

### Sample 66: `99e03781b4c52c5c`

| Field | Value |
|---|---|
| SHA-256 | `99e03781b4c52c5c5440082e54fff18857e59fe8161bf92184649ebcac7a6000` |
| Family label | `Formbook` |
| File name | `md5001000000020.tmp` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:27` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76bdba4bb9b80fd5e7d51950e5373bc4` |
| SHA-1 | `14b49ca70c341923d4f079c27c7485266f1a7633` |
| SHA-256 | `99e03781b4c52c5c5440082e54fff18857e59fe8161bf92184649ebcac7a6000` |
| SHA3-384 | `edefc7ec01922f9d625832692a01020b94676071d5876fcee3f851a43c638e4f62999cbecce00855c3f6bb7a13b5678a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15D05015432A8DB06D87AA3F449B1E17503B5AE6B6821E3468FC57DCF79B2F044E08793` |
| SSDEEP | `12288:tbELUiNY1j+5O+2qYtB9j8HgNhChNmomN8L5zz0SHHBfisQDGjZmnfWFOnJ4a0Wn:VEDY1C5B2jzChNmoIBSHDIGZmn+FAn` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_066_99e03781
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99e03781b4c52c5c5440082e54fff18857e59fe8161bf92184649ebcac7a6000"
    family = "Formbook"
    file_name = "md5001000000020.tmp"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:27"
  condition:
    hash.sha256(0, filesize) == "99e03781b4c52c5c5440082e54fff18857e59fe8161bf92184649ebcac7a6000"
}
```

### Sample 67: `c50ced1116cae745`

| Field | Value |
|---|---|
| SHA-256 | `c50ced1116cae74556951a395ce9bb2f958a519105093b38025009b7046a9f07` |
| Family label | `Formbook` |
| File name | `_00015` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:24` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63db93c47580b0066c4554fbfd453d16` |
| SHA-1 | `e0b7b989cbb4cd9d875de88556e06f677fe77fa7` |
| SHA-256 | `c50ced1116cae74556951a395ce9bb2f958a519105093b38025009b7046a9f07` |
| SHA3-384 | `0db810ee9c0ddcfe7369ae523ad6ad8a288a9d76f5d8cbffe164ea0955dd30c5e7a6698d30e0a0e7aafda11e6b7e6b62` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1FE05F14427A9AB0AD9BA67F41AB5F27803B47D5DA032D3158FC56CDFB422F049E08763` |
| SSDEEP | `12288:kAF9LvPBAV08zka7Jt9+5O+2qD6YWRdg6SovWxr9ZnASkondmM+65eC+leBCQlzm:kk5BDCgjoo9ZnASXdmfVlekMz` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_067_c50ced11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c50ced1116cae74556951a395ce9bb2f958a519105093b38025009b7046a9f07"
    family = "Formbook"
    file_name = "_00015"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:24"
  condition:
    hash.sha256(0, filesize) == "c50ced1116cae74556951a395ce9bb2f958a519105093b38025009b7046a9f07"
}
```

### Sample 68: `8fef53474f80898c`

| Field | Value |
|---|---|
| SHA-256 | `8fef53474f80898c6f6aefa627af7d7241484cfac19e8ae80c5a6c939b0a727e` |
| Family label | `XWorm` |
| File name | `_00093` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:21` |
| Reporter | `ni_fi_70` |
| Tags | `exe, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32245e93897d2dffe35d1a487192bda3` |
| SHA-1 | `f6a4d0e73e2b449157157ff1b7348decfdb7b3fe` |
| SHA-256 | `8fef53474f80898c6f6aefa627af7d7241484cfac19e8ae80c5a6c939b0a727e` |
| SHA3-384 | `dd68eb6bee6660af9d0d333d1d5a5bafe643f94b989c4df1cccf73b93031a41922d73d6e9a90c425f7b14924217dea5a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T168C4D05432A9EB1AD9BA57F41A76F2B803F47E9EA421D2164FC5ADDF3462F008D08353` |
| SSDEEP | `12288:iAF9LvPBAV08zkaleam+5O+2qwmbzWQbxA7LUz98JXQfwRr9WA3L:o15BzvW+Ai8JXQfMjL` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_068_8fef5347
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fef53474f80898c6f6aefa627af7d7241484cfac19e8ae80c5a6c939b0a727e"
    family = "XWorm"
    file_name = "_00093"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:21"
  condition:
    hash.sha256(0, filesize) == "8fef53474f80898c6f6aefa627af7d7241484cfac19e8ae80c5a6c939b0a727e"
}
```

### Sample 69: `20370532a621f261`

| Field | Value |
|---|---|
| SHA-256 | `20370532a621f2611b51ad0369fb1f48c5208f49a971b56b44f1e2d321c41cb0` |
| Family label | `Formbook` |
| File name | `_00006` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:18` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `283a7a00cfc8ae313e2637cff09f8fc0` |
| SHA-1 | `f1d71098c4cb7be839dbea22235a7aea93284254` |
| SHA-256 | `20370532a621f2611b51ad0369fb1f48c5208f49a971b56b44f1e2d321c41cb0` |
| SHA3-384 | `f130ed70268c816b7a86559664c4b94a0a0099d4d38cd47ab0759a88b6e2e427d6bee99c7a48e613261c4c408e6bcdb1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B205F1043369AB09D97A57F529B2E13813F5BEAEA910E3055FD97CDBB471B044E00BA3` |
| SSDEEP | `12288:DGT+5O+2qRVllkvxlD2yEIGhFLxHT2ZTxbJaEnM9yBgFeIgdnwLySnuuFXKh:DH5BRrlk6ykhFLxT2xbDM9wg5ry9uFX` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_069_20370532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20370532a621f2611b51ad0369fb1f48c5208f49a971b56b44f1e2d321c41cb0"
    family = "Formbook"
    file_name = "_00006"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:18"
  condition:
    hash.sha256(0, filesize) == "20370532a621f2611b51ad0369fb1f48c5208f49a971b56b44f1e2d321c41cb0"
}
```

### Sample 70: `e6ff71e8dcd5b810`

| Field | Value |
|---|---|
| SHA-256 | `e6ff71e8dcd5b81016287a4e601a6bed569e256e179c17e32182e08f4ce234d0` |
| Family label | `XWorm` |
| File name | `md5001000070613.tmp` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:15` |
| Reporter | `ni_fi_70` |
| Tags | `exe, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f0e7d7767c19247fe18c5c164e6d48f` |
| SHA-1 | `d31376b38cf002be76af54c3f03a0185513139f9` |
| SHA-256 | `e6ff71e8dcd5b81016287a4e601a6bed569e256e179c17e32182e08f4ce234d0` |
| SHA3-384 | `a6a113277226f0c6a8cfa5d37535e26ca1ad0a74d275d8231dd458b6dd409ce4be5a03fca14bf26109a1849460e6de88` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T184C4E0142268DB0AC97667F51DB1E27903B97E9E6821E3028FC5BCEF79B6F044E04653` |
| SSDEEP | `12288:JbELUi4RT+5O+2qgPcSdrkvXWku0sY415ZZ14seV0oF+DtHQOv7QL:hEWRy5B4Lov1u+4JZ1peV0s+pHD` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_070_e6ff71e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6ff71e8dcd5b81016287a4e601a6bed569e256e179c17e32182e08f4ce234d0"
    family = "XWorm"
    file_name = "md5001000070613.tmp"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:15"
  condition:
    hash.sha256(0, filesize) == "e6ff71e8dcd5b81016287a4e601a6bed569e256e179c17e32182e08f4ce234d0"
}
```

### Sample 71: `6b6d1feb22b89f7c`

| Field | Value |
|---|---|
| SHA-256 | `6b6d1feb22b89f7c188f7ec7fed0b3fb48299119228b516379b6f4bbc3fec336` |
| Family label | `XWorm` |
| File name | `_00032` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:12` |
| Reporter | `ni_fi_70` |
| Tags | `exe, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d8c69d30f0abebb9f67f9cd6f03118f` |
| SHA-1 | `aace49cc1dfa3d4a11c988d5dcd6d60e89376ab0` |
| SHA-256 | `6b6d1feb22b89f7c188f7ec7fed0b3fb48299119228b516379b6f4bbc3fec336` |
| SHA3-384 | `bb77f987401143713c941be4a6783bc7984de6776ba3b6b21044dc961125b9185f14ffefd13cdbc0b659661c43346306` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T130D49C64AA65EB05C52967F4D861E1F587BC6D9AE822C10F8EC47DDB3CF2B027D24243` |
| SSDEEP | `12288:g6zfT+5O+2qSncOzy4t7yDQj3mnILmvLY+XC8y:7ry5BWpdvLgE+XQ` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_071_6b6d1feb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b6d1feb22b89f7c188f7ec7fed0b3fb48299119228b516379b6f4bbc3fec336"
    family = "XWorm"
    file_name = "_00032"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:12"
  condition:
    hash.sha256(0, filesize) == "6b6d1feb22b89f7c188f7ec7fed0b3fb48299119228b516379b6f4bbc3fec336"
}
```

### Sample 72: `9921c957833c07bf`

| Field | Value |
|---|---|
| SHA-256 | `9921c957833c07bf45c7f67f3a9f3d15555ad4da2be2b44021d6d211c1a8be67` |
| Family label | `AsyncRAT` |
| File name | `b8f773f382aa4c3296c9d501ac9d2932.MSG` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:09` |
| Reporter | `ni_fi_70` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0767c7a4c0518e80dfc50148c82929f4` |
| SHA-1 | `976e43f4cf66509ce676bf14c6f5cfe396835fcc` |
| SHA-256 | `9921c957833c07bf45c7f67f3a9f3d15555ad4da2be2b44021d6d211c1a8be67` |
| SHA3-384 | `34983245dc3f306cc50d8e8d538d60ea5a1791f6e9745c4e729a73840a199ca54b149793d4d704dbd17ff2ebef1f2057` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E8C4E0083269DB06CA7597F51971F17803F9AE9E6821E3028FC6BDDF7966F044E08663` |
| SSDEEP | `12288:LbELUiY8Y+5O+2qJ3LEDN9fQCGSba1ZBDWJ5z/fL6DLx6UBz:fEC8H5B5sNdBGSAa/uLR` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_072_9921c957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9921c957833c07bf45c7f67f3a9f3d15555ad4da2be2b44021d6d211c1a8be67"
    family = "AsyncRAT"
    file_name = "b8f773f382aa4c3296c9d501ac9d2932.MSG"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:09"
  condition:
    hash.sha256(0, filesize) == "9921c957833c07bf45c7f67f3a9f3d15555ad4da2be2b44021d6d211c1a8be67"
}
```

### Sample 73: `0692bcfd2eb11a5e`

| Field | Value |
|---|---|
| SHA-256 | `0692bcfd2eb11a5ec2f5b1076e6cc4cd4c911adbc8ac34b7350c9797a25e432d` |
| Family label | `Formbook` |
| File name | `6704b98266b949fbad6f0c153627d944.MSG` |
| File type | `exe` |
| First seen | `2026-11-18 05:50:06` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0466db73c8168afbb4329cf17cc4075f` |
| SHA-1 | `ee9ef63711d8d1e4ce7b39e70d1251b59114ef78` |
| SHA-256 | `0692bcfd2eb11a5ec2f5b1076e6cc4cd4c911adbc8ac34b7350c9797a25e432d` |
| SHA3-384 | `78b37f5f2443badd58d198ada6a867e4bd40f4a4bc554b3506ed9a234771f2d49cc25e1055da6cb660c98449176c7c52` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14605CE60BA65EB05C52963F4D861E1F583AD6DAAE412D20F8EC97DDB3CF27027C24253` |
| SSDEEP | `24576:3ac5BeU4lGIH7xifMz8Zgq1Afn2PzhiCjIl47/:sUwG4cPqZubg5O7` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_073_0692bcfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0692bcfd2eb11a5ec2f5b1076e6cc4cd4c911adbc8ac34b7350c9797a25e432d"
    family = "Formbook"
    file_name = "6704b98266b949fbad6f0c153627d944.MSG"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:06"
  condition:
    hash.sha256(0, filesize) == "0692bcfd2eb11a5ec2f5b1076e6cc4cd4c911adbc8ac34b7350c9797a25e432d"
}
```

### Sample 74: `c813b812f9383c18`

| Field | Value |
|---|---|
| SHA-256 | `c813b812f9383c189a840e0cffd8868ccd1989b3db0b56fc0f337495417ffee1` |
| Family label | `unknown` |
| File name | `c813b812f9383c189a840e0cffd8868ccd1989b3db0b56fc0f337495417ffee1` |
| File type | `sh` |
| First seen | `2026-11-18 05:48:30` |
| Reporter | `hett` |
| Tags | `bash, honeypot, script, sh, shardlure` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6903162dba69795292cafa2d4d4e460d` |
| SHA-1 | `c53266d54f97890fbfad5d8bcf13ae74a43ba151` |
| SHA-256 | `c813b812f9383c189a840e0cffd8868ccd1989b3db0b56fc0f337495417ffee1` |
| SHA3-384 | `de7827b11a7bec8207c47ac0437fb99ccbcc2bf5f05bb047bc15f092171498342fe474cb6d8ec784e3d80e1ea077108b` |
| TLSH | `T18C81B0916CA18832A175906EE7E9516167CF4A23442C7C04FA4EBD18BF3C2A4F1B0B5E` |
| SSDEEP | `96:/n8xq7c39UCSObrgvKyH+gRJ7E2FxGoLzoCr5Jia5+2leVHYCGnDrW1zkpuD:P8xqnargvKyH+gRRE2FxGoLzoCr58M+p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_c813b812
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c813b812f9383c189a840e0cffd8868ccd1989b3db0b56fc0f337495417ffee1"
    family = "unknown"
    file_name = "c813b812f9383c189a840e0cffd8868ccd1989b3db0b56fc0f337495417ffee1"
    file_type = "sh"
    first_seen = "2026-11-18 05:48:30"
  condition:
    hash.sha256(0, filesize) == "c813b812f9383c189a840e0cffd8868ccd1989b3db0b56fc0f337495417ffee1"
}
```

### Sample 75: `e8e26860ce49a7df`

| Field | Value |
|---|---|
| SHA-256 | `e8e26860ce49a7df66f9b41e5d66412e5a230d03bc2fcfeb3b9b1c0f2c34e9a2` |
| Family label | `Mirai` |
| File name | `e8e26860ce49a7df66f9b41e5d66412e5a230d03bc2fcfeb3b9b1c0f2c34e9a2` |
| File type | `elf` |
| First seen | `2026-11-18 05:47:56` |
| Reporter | `vlasovmichael` |
| Tags | `elf, honeypot, Mirai, Torii, trojan.mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c90c3273beba0ad11ec99b2d049109e7` |
| SHA-1 | `5cf18bb819dcd5b2639c5d6cd2e663de598b4136` |
| SHA-256 | `e8e26860ce49a7df66f9b41e5d66412e5a230d03bc2fcfeb3b9b1c0f2c34e9a2` |
| SHA3-384 | `f0755ebb427c736897b755d286066d4748d2e7d782090454a390450a7584c15907079e37b289fa23f68e2bebeddf4d0e` |
| TLSH | `T19EB3AEDBF7472091C86286F007C74BDE2E6322119F6BE9E76C0E2A3B15794DB5917382` |
| SSDEEP | `1536:CA+h8DpCXw2yIS3Mrm3wCampWqQL2eoJ8wm2AHusiwxZJTGEgl/LWq:V+h8tp2FSym3wCBtI2fiOsi0Jglq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_e8e26860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8e26860ce49a7df66f9b41e5d66412e5a230d03bc2fcfeb3b9b1c0f2c34e9a2"
    family = "Mirai"
    file_name = "e8e26860ce49a7df66f9b41e5d66412e5a230d03bc2fcfeb3b9b1c0f2c34e9a2"
    file_type = "elf"
    first_seen = "2026-11-18 05:47:56"
  condition:
    hash.sha256(0, filesize) == "e8e26860ce49a7df66f9b41e5d66412e5a230d03bc2fcfeb3b9b1c0f2c34e9a2"
}
```

### Sample 76: `48e7c1e1e23d0b36`

| Field | Value |
|---|---|
| SHA-256 | `48e7c1e1e23d0b36a9fa57383d8bc391891e5069c6965485266d63ce65b1fbdb` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-11-18 05:44:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05e90b2d89293439eacdecb1c5fed93c` |
| SHA-1 | `d6160a679afffc056b1f327df8182534c45977bd` |
| SHA-256 | `48e7c1e1e23d0b36a9fa57383d8bc391891e5069c6965485266d63ce65b1fbdb` |
| SHA3-384 | `0fd8498e857b8ad9b82e73bcf337fc408b7dd0b84c94f8d9aca1a7b003d9189adc20806301d29ae59efaa14c8f6f4af9` |
| TLSH | `T15F735C42B30C0A43D1AB9DB03E3F2BD593EFBB9121F4A645691E9B859175E331182ECD` |
| SSDEEP | `1536:rDNbgToiYPrTuXTolGTEN/BGL10ilhZ7fKbjyWgiOE9l:t6oF+4GTEdO10uhZD60Il` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_48e7c1e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48e7c1e1e23d0b36a9fa57383d8bc391891e5069c6965485266d63ce65b1fbdb"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-18 05:44:17"
  condition:
    hash.sha256(0, filesize) == "48e7c1e1e23d0b36a9fa57383d8bc391891e5069c6965485266d63ce65b1fbdb"
}
```

### Sample 77: `1734d82391a4771b`

| Field | Value |
|---|---|
| SHA-256 | `1734d82391a4771b63e5da431048526567ca8743397b2fab24abf44c27e8703a` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-18 05:44:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e7eea76548e7d032b5ea48052542910` |
| SHA-1 | `31be8508062c75871b8fcd64a3f855d2bbbb6ed8` |
| SHA-256 | `1734d82391a4771b63e5da431048526567ca8743397b2fab24abf44c27e8703a` |
| SHA3-384 | `3cfc814a85809938a3f036ad15dedc84dd1e577da0669957e2708857d7c022f35eef2197b25bb2ebfdeedef86d4f7a40` |
| TLSH | `T152556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSD:SDjxB4m5n8XlaPWi+d+a4TjxQP4V` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_077_1734d823
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1734d82391a4771b63e5da431048526567ca8743397b2fab24abf44c27e8703a"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-18 05:44:11"
  condition:
    hash.sha256(0, filesize) == "1734d82391a4771b63e5da431048526567ca8743397b2fab24abf44c27e8703a"
}
```

### Sample 78: `e631b02a4e79c964`

| Field | Value |
|---|---|
| SHA-256 | `e631b02a4e79c964e4e49ddacdb5f61a08819c7a64b6ccad81b7f465e4a05184` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-11-18 05:44:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bbc1c14ef98c0ebf5cc777b340a0210` |
| SHA-1 | `5488582c944cdcd6956acfba811c55f86980c1d6` |
| SHA-256 | `e631b02a4e79c964e4e49ddacdb5f61a08819c7a64b6ccad81b7f465e4a05184` |
| SHA3-384 | `f24721d7a0e9b4f6ee6d702cccacb25f9f35f4cfe505efae32a4454cf1375abe3b138337d120bea88e164825c09a415d` |
| TLSH | `T1EC734B95FD419A13C5C1257AFB2F8289775B13B8D2EB3303AA259F30238B9670E3B545` |
| SSDEEP | `1536:Vb2BYWSZ1MXSePoJXsWkKSvF9lOmtqOVKs2tKVET2z:Vb2iwCeP2XsWkKIStt0EO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_e631b02a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e631b02a4e79c964e4e49ddacdb5f61a08819c7a64b6ccad81b7f465e4a05184"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-18 05:44:08"
  condition:
    hash.sha256(0, filesize) == "e631b02a4e79c964e4e49ddacdb5f61a08819c7a64b6ccad81b7f465e4a05184"
}
```

### Sample 79: `82078f6e2f6d5f76`

| Field | Value |
|---|---|
| SHA-256 | `82078f6e2f6d5f76556c0ea24fe0964b4678b4559442703dd637d191b7c7a44b` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-11-18 05:44:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a267900be8a5840da92a85c2c4bcfc17` |
| SHA-1 | `16dfbdab4bfe90e68d9026158c0255eb898cf7e6` |
| SHA-256 | `82078f6e2f6d5f76556c0ea24fe0964b4678b4559442703dd637d191b7c7a44b` |
| SHA3-384 | `9f77a8f1f599eb2ed71551751a7a67500449ab78fb35acdf92abb0c1a85288c6c0051f640aa5e7c7995697c798ae3c9a` |
| TLSH | `T13703F15DC06699C2FB997058CD1EABB333840B8B7760CDE113484A804B59A33FB52EDD` |
| SSDEEP | `768:N0UI+WghZK67hmn51SWRrf3iXyl9K453IFKimbvmymzXC4uVcqgw0XJJkmW6:yRVjLSyfys54A5LmzS4u+qgw0f7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_82078f6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82078f6e2f6d5f76556c0ea24fe0964b4678b4559442703dd637d191b7c7a44b"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-18 05:44:06"
  condition:
    hash.sha256(0, filesize) == "82078f6e2f6d5f76556c0ea24fe0964b4678b4559442703dd637d191b7c7a44b"
}
```

### Sample 80: `de4a8c66fb63a9ce`

| Field | Value |
|---|---|
| SHA-256 | `de4a8c66fb63a9ce5de27eecdf99d5da3196642715388f4adaca44b1f4faff98` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-18 05:36:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84345bb45b0677eb76b6a985e7672d62` |
| SHA-1 | `72dcb0f6f7c24eb4158962235255697861b632e2` |
| SHA-256 | `de4a8c66fb63a9ce5de27eecdf99d5da3196642715388f4adaca44b1f4faff98` |
| SHA3-384 | `e300045d3c659c1889eae093b42e28c53837edf924ec6ef0a9f3d8dbb0750dda7711656ea2a1325f07656be8d5bf36f3` |
| TLSH | `T1D593C84E6E31CFADF268C63047F75B20A75973D623E1C685E2ACD1041E6034E695FBA8` |
| TELFHASH | `t1cd11635c4e7423a467365d99156eefbbe1a130df27252c378e11a8a8abbdd415e04c0c` |
| SSDEEP | `1536:CKd/JemTr+IDUTyI0AaP/MG1CnLmpF8YksUHf3PnDn9vx5KivdTeZZTQ3lY+B3y:7Tem2IOd0r1Ch9JPvdL3lY+Bi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_de4a8c66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de4a8c66fb63a9ce5de27eecdf99d5da3196642715388f4adaca44b1f4faff98"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-18 05:36:25"
  condition:
    hash.sha256(0, filesize) == "de4a8c66fb63a9ce5de27eecdf99d5da3196642715388f4adaca44b1f4faff98"
}
```

### Sample 81: `b14a51949b7ca2c9`

| Field | Value |
|---|---|
| SHA-256 | `b14a51949b7ca2c9305c8c921589b16ae1885fa6e8ec53570d4161ba312b43ed` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-11-18 05:36:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd42e74608343de9c67065a5e0cbad2e` |
| SHA-1 | `2061d0059c09f4a74ec3599fdaa441b84ddf96da` |
| SHA-256 | `b14a51949b7ca2c9305c8c921589b16ae1885fa6e8ec53570d4161ba312b43ed` |
| SHA3-384 | `0dd1b0d5e15a2348b23de36f63035400c2c4efbbb98614420d998d76017de075863d60bfef32530c057663d3c0efbec5` |
| TLSH | `T1E9835B37FE714D27C8D8697A61F74325F5F6478A20FC8A0A3DA10D8DAF696803117BA4` |
| SSDEEP | `768:a7t6GsKChUbaAc3l+vdqc4KRl4k3O+cb5VKlAlwlct0iTEXdIF/VX+LteQIBIg:a7YKCSbaf8VqcLMwQ5ectwdI5V+telz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_b14a5194
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b14a51949b7ca2c9305c8c921589b16ae1885fa6e8ec53570d4161ba312b43ed"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-11-18 05:36:09"
  condition:
    hash.sha256(0, filesize) == "b14a51949b7ca2c9305c8c921589b16ae1885fa6e8ec53570d4161ba312b43ed"
}
```

### Sample 82: `fbb4ee3698ec25fe`

| Field | Value |
|---|---|
| SHA-256 | `fbb4ee3698ec25fec7a78f17ed744f55e0d70b64346ff9e9b39c5291714f303f` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-18 05:36:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eaaeff81b415c1d1c8326c664260a767` |
| SHA-1 | `fa8acaed0ea5b88469b917817d393e0ecb01708f` |
| SHA-256 | `fbb4ee3698ec25fec7a78f17ed744f55e0d70b64346ff9e9b39c5291714f303f` |
| SHA3-384 | `27a1fa78f302c05cfa154ee5ec06492b8dba3afd835a2ca7a6725a1af086ab8bc7521b1443bd165381649d068b7198b3` |
| TLSH | `T14913F11A1B0A0967F5E784F919991B8351764FE27C3BF84A4CC962F3C40A3B8F56B2D1` |
| SSDEEP | `768:NE1jATa3OYLhVmD6ZOKC0QgPHyMPp70fHHbaAqiDjWuJKB37R/NXv1YYmbYJgGlg:NEEOLjmAqlMp0f+EDjWuYX+YmbYVEWS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_fbb4ee36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbb4ee3698ec25fec7a78f17ed744f55e0d70b64346ff9e9b39c5291714f303f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-18 05:36:06"
  condition:
    hash.sha256(0, filesize) == "fbb4ee3698ec25fec7a78f17ed744f55e0d70b64346ff9e9b39c5291714f303f"
}
```

### Sample 83: `d2d2e002714c37f8`

| Field | Value |
|---|---|
| SHA-256 | `d2d2e002714c37f8e8947931f04b7998885bc24680b14beee47d9b596823d241` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-18 05:33:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbed06821a8b1beeb536d07c49a7ddaa` |
| SHA-1 | `5042ea971480e9e91087e2ce56eda4fef75b6818` |
| SHA-256 | `d2d2e002714c37f8e8947931f04b7998885bc24680b14beee47d9b596823d241` |
| SHA3-384 | `beea27eccebd9d35f152dc43117bca1c27b97de91255e14da48be5049288f6b2691f05a37bddc5e5272e8a5d822ee5a1` |
| TLSH | `T1FB556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSm:SDjxB4m5n8XlaPWi+d+a4TjxQP4w` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_083_d2d2e002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2d2e002714c37f8e8947931f04b7998885bc24680b14beee47d9b596823d241"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-18 05:33:07"
  condition:
    hash.sha256(0, filesize) == "d2d2e002714c37f8e8947931f04b7998885bc24680b14beee47d9b596823d241"
}
```

### Sample 84: `71e86c3b8c125215`

| Field | Value |
|---|---|
| SHA-256 | `71e86c3b8c12521551dd3d47aebde6c0c63c9818f0f70afac40692d9eef85165` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-11-18 05:32:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95457307bbfb4caa2fd5a087991306e2` |
| SHA-1 | `9a0eb48237c9472305a8d4975473d6c73f6c838f` |
| SHA-256 | `71e86c3b8c12521551dd3d47aebde6c0c63c9818f0f70afac40692d9eef85165` |
| SHA3-384 | `e3e5b8afd1a06891ab6f9402ce7346944e5e00d694d5a746487948dfad81a17a469eb5c98bba7c9c5aa2d88d64542abc` |
| TLSH | `T1C0638EE7C8262E14E16996B170B2CF784B63B51156CB2FB9166BC3799083DDDF2013B8` |
| SSDEEP | `1536:W25y/kf8uFwil3jox90nDKhvDE73U0lCW5rJPCTr:W25Ekf8Ewh0nmhgY0lbtwr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_71e86c3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71e86c3b8c12521551dd3d47aebde6c0c63c9818f0f70afac40692d9eef85165"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-18 05:32:05"
  condition:
    hash.sha256(0, filesize) == "71e86c3b8c12521551dd3d47aebde6c0c63c9818f0f70afac40692d9eef85165"
}
```

### Sample 85: `a01ca0b5167a4211`

| Field | Value |
|---|---|
| SHA-256 | `a01ca0b5167a4211b115d27579f0552484a1f48d78805debabdc40c9f21f3ed3` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-11-18 05:29:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3abe14794f3594c5ca34342d43349f9b` |
| SHA-1 | `2e38de98aa460dcb9909e4cb6650eb93b59c2ceb` |
| SHA-256 | `a01ca0b5167a4211b115d27579f0552484a1f48d78805debabdc40c9f21f3ed3` |
| SHA3-384 | `be1a3d029c12d8566040cf9f85ab05f376cd3fe1191726c9f2fd3ffb7edd721d1e449f3ffae21e6fe17e0a0ceb80fb88` |
| TLSH | `T1EB637DC1F183D0F5DC6B44B5806AB32E9731EA292034DA15EF759F6ADD33A01B61B329` |
| TELFHASH | `t1053138f60e6b48e877d0a840c71f6bd2595ef633192036e445b29dd037ead95447cc39` |
| SSDEEP | `1536:k/iJkcwKNvGZ+R/PWpsNwliVNH1i6pysYbm:kKJkcwaqmWyNwliVNVDcm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_a01ca0b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a01ca0b5167a4211b115d27579f0552484a1f48d78805debabdc40c9f21f3ed3"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-11-18 05:29:18"
  condition:
    hash.sha256(0, filesize) == "a01ca0b5167a4211b115d27579f0552484a1f48d78805debabdc40c9f21f3ed3"
}
```

### Sample 86: `6e86d289c8b34588`

| Field | Value |
|---|---|
| SHA-256 | `6e86d289c8b345888d1b6bd16de687ebf4fcafc0173c79f1255ec0fd9df7541d` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-11-18 05:29:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79fc128724bb75f448857dacb0ca32f9` |
| SHA-1 | `b5ccaba9c79c8926ce8f6dd80b6a820ae0a9e47a` |
| SHA-256 | `6e86d289c8b345888d1b6bd16de687ebf4fcafc0173c79f1255ec0fd9df7541d` |
| SHA3-384 | `3126fa61a9f8fb304b37abd460668435c168de7702cea27cc07f6890686871215ef5e8ded0813e61b5cc6808489ff120` |
| TLSH | `T12BF2F279A6E8990DCBBF92BF01AD7CC51010972CF496A4632F5CDC3A14A3E14BF39585` |
| SSDEEP | `768:18p1kSi7uzuHyySY072gTi5OH20vdApA1d2plj+R2/XB1UrqYc1HnbcuyD7UFO:2+S6ShY0bTsOHldASSlj+R2J1yJUHnod` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_6e86d289
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e86d289c8b345888d1b6bd16de687ebf4fcafc0173c79f1255ec0fd9df7541d"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-11-18 05:29:07"
  condition:
    hash.sha256(0, filesize) == "6e86d289c8b345888d1b6bd16de687ebf4fcafc0173c79f1255ec0fd9df7541d"
}
```

### Sample 87: `074c291732db50ec`

| Field | Value |
|---|---|
| SHA-256 | `074c291732db50ec45a5dd819d1f2ba224087eaabc14fa8a3b70ba744508d5c3` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-11-18 05:28:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a7fb350a4bff1bc02b8a0c643284195` |
| SHA-1 | `a23f26af0354da1cb3af0409cdbc1c9fca3f4be3` |
| SHA-256 | `074c291732db50ec45a5dd819d1f2ba224087eaabc14fa8a3b70ba744508d5c3` |
| SHA3-384 | `64905326cfec18c7624dabdba044b2e6c6f33868ffe7d2f6e51155351d3a1855e2e988abaee80a0fa79032d2177bc731` |
| TLSH | `T149636CC5F683E0F2E89600B91137A7665732E93910BDFF46EB21553BEC22501E75A3AC` |
| TELFHASH | `t10031dcf61ebb48ecb3d09841c71b2ad72929ea3719a0b2f44172a85533f6d4180b8d39` |
| SSDEEP | `1536:sNHP5eMUCnRVvpnMSgBIK8TX3q0lY39QB/p/KmBD:UP5e9HBoTX37lQ8syD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_074c2917
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "074c291732db50ec45a5dd819d1f2ba224087eaabc14fa8a3b70ba744508d5c3"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-18 05:28:18"
  condition:
    hash.sha256(0, filesize) == "074c291732db50ec45a5dd819d1f2ba224087eaabc14fa8a3b70ba744508d5c3"
}
```

### Sample 88: `1cc698edeb3593bb`

| Field | Value |
|---|---|
| SHA-256 | `1cc698edeb3593bbb5512cfcbe5207af8d167df7e2977f46284af8d389e51277` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-11-18 05:28:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a5421448a634f4da3c3045cb0c41f98` |
| SHA-1 | `91f4172dd40669b563dad218d4d2d3382ab40d8e` |
| SHA-256 | `1cc698edeb3593bbb5512cfcbe5207af8d167df7e2977f46284af8d389e51277` |
| SHA3-384 | `267e3335d9234ecd8273800ca02681983fee464e550c49c7bb8e4e9611e5af08f3f4f6b9674fda84813b9e0a6cb44101` |
| TLSH | `T12FF2F148A6FD5B80CA0BD27421CFFC87086DED1ADD1420E72B09231BD472E9F6A5D683` |
| SSDEEP | `768:aM40kG8SrFMDZxld4y9zq3lr7HvX1fnbcuyD7Uep:aM4098W6FxldhS9fnouy8q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_1cc698ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cc698edeb3593bbb5512cfcbe5207af8d167df7e2977f46284af8d389e51277"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-18 05:28:10"
  condition:
    hash.sha256(0, filesize) == "1cc698edeb3593bbb5512cfcbe5207af8d167df7e2977f46284af8d389e51277"
}
```

### Sample 89: `8f586ecff2b419b1`

| Field | Value |
|---|---|
| SHA-256 | `8f586ecff2b419b1a3cce134640c26b825e308bcacfb22ae4f5ce80cbf1d4d67` |
| Family label | `Mirai` |
| File name | `iranbot-ultimate.i586` |
| File type | `elf` |
| First seen | `2026-11-18 05:28:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e5aaf2736ed982021c1833fccfc924d` |
| SHA-1 | `7bf76145f367d911e5651b17448b0ab626f2642e` |
| SHA-256 | `8f586ecff2b419b1a3cce134640c26b825e308bcacfb22ae4f5ce80cbf1d4d67` |
| SHA3-384 | `734518353b72c6ff07b14b35c71fa2fc47fae3062eae1cb5c626ebbdaeb279f03ccb2e49d06fcd9445371481a5bb0876` |
| TLSH | `T159C35B85E7D3D0F1E8174DB2103A633B9B32A93E8035DB47EFB46931AD52A41D62E61C` |
| TELFHASH | `t178516dfafa750de96bd05c02e68e5731bd0eab77282436b705f32965326214051fbc38` |
| SSDEEP | `3072:SLz2b2+Ys4gNDUM/hLbSJ4b/lhb3+6kwYnlg:02l40DUM/hXh3+BwUu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_8f586ecf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f586ecff2b419b1a3cce134640c26b825e308bcacfb22ae4f5ce80cbf1d4d67"
    family = "Mirai"
    file_name = "iranbot-ultimate.i586"
    file_type = "elf"
    first_seen = "2026-11-18 05:28:07"
  condition:
    hash.sha256(0, filesize) == "8f586ecff2b419b1a3cce134640c26b825e308bcacfb22ae4f5ce80cbf1d4d67"
}
```

### Sample 90: `b4b7b586c1dc7776`

| Field | Value |
|---|---|
| SHA-256 | `b4b7b586c1dc77761dcae2cbe280e3aed238986011c98c174c89cc2908693325` |
| Family label | `Mirai` |
| File name | `i486.new` |
| File type | `elf` |
| First seen | `2026-11-18 05:27:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73ede6ad3c87ba3cbd63dd268987d154` |
| SHA-1 | `eba4726131c97fc771206bf8dc0d7ab70d592f7d` |
| SHA-256 | `b4b7b586c1dc77761dcae2cbe280e3aed238986011c98c174c89cc2908693325` |
| SHA3-384 | `8c78e2d62b611b2a6a1392450a67a8dd396f7928f86b72bd0fdb814e90c0bf1925a94f061b5b0012b95f4e6e2f17eecd` |
| TLSH | `T14824180772B4EB90D9F58470709987798914D4B613B7A98EDF86DDB0FE08140BA2D3AF` |
| TELFHASH | `t1d141243004bb34f4d2575a6213b16924493e5de467717db28fd109acde90f820ce5d2e` |
| SSDEEP | `3072:d5LP+ORGNemOs32ZLtDVF/i/2Bq0S8RX3r/7jza4D/UatFs:d5SmJtDVAuQ0SMX3LzaMMo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_b4b7b586
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4b7b586c1dc77761dcae2cbe280e3aed238986011c98c174c89cc2908693325"
    family = "Mirai"
    file_name = "i486.new"
    file_type = "elf"
    first_seen = "2026-11-18 05:27:07"
  condition:
    hash.sha256(0, filesize) == "b4b7b586c1dc77761dcae2cbe280e3aed238986011c98c174c89cc2908693325"
}
```

### Sample 91: `f297afd79f2d365e`

| Field | Value |
|---|---|
| SHA-256 | `f297afd79f2d365eeff2bdac3582af421a75d25a57a6aae32cb3049f54e12069` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-11-18 05:26:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f99b574b232e4aa300e18124483a15cc` |
| SHA-1 | `cadf6290b3c844a01bcbfb67338603282d6e62ea` |
| SHA-256 | `f297afd79f2d365eeff2bdac3582af421a75d25a57a6aae32cb3049f54e12069` |
| SHA3-384 | `3689927a97af93c752914e8e2fdeeffbbf301516aca392b7e819cab582741cd2031d08be6e2efd91666f8f5885ae2564` |
| TLSH | `T12A835B96FD419A23C5C1157BFF6F83883B1B43B8D3EA32079A259F2123879260E3B555` |
| SSDEEP | `1536:qrf0oR5hqaZijN/5u2HlGJdYlZxm9fOKET2dbo+vkJj9Q2SSv8KNJ:qrfp3HM/59lGJdYlywTqbY/8E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_f297afd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f297afd79f2d365eeff2bdac3582af421a75d25a57a6aae32cb3049f54e12069"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-11-18 05:26:07"
  condition:
    hash.sha256(0, filesize) == "f297afd79f2d365eeff2bdac3582af421a75d25a57a6aae32cb3049f54e12069"
}
```

### Sample 92: `b4c92111ba57cf6b`

| Field | Value |
|---|---|
| SHA-256 | `b4c92111ba57cf6b67141d5b81d68e802de7036e8be047ae16878984a54288c6` |
| Family label | `Mirai` |
| File name | `armv6l.new` |
| File type | `elf` |
| First seen | `2026-11-18 05:25:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `486c8a019c146a213f7bf207866e05f7` |
| SHA-1 | `06841749ac045d47bbb98d3872ad974f33ff8581` |
| SHA-256 | `b4c92111ba57cf6b67141d5b81d68e802de7036e8be047ae16878984a54288c6` |
| SHA3-384 | `395726dfd208a17aac8193725e6d7addcd207e856018af49f4fa83f4565da1a9dc235d11c07b0d52021faa953c0c64e3` |
| TLSH | `T15C240A9B75B6A490C9E4887DB26942FC734793EA83FAB50DCE158E60F48E504693D3C3` |
| TELFHASH | `t17ef09e70043b20f6e285b858a766d13eab3d09c5c72d20e288c38a1c5ca244480e2d73` |
| SSDEEP | `3072:BRGNemOu514I5fL5tI2eoY7Eek15EIA8wsgdws:65XfLvILUekvAGgdZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_b4c92111
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4c92111ba57cf6b67141d5b81d68e802de7036e8be047ae16878984a54288c6"
    family = "Mirai"
    file_name = "armv6l.new"
    file_type = "elf"
    first_seen = "2026-11-18 05:25:06"
  condition:
    hash.sha256(0, filesize) == "b4c92111ba57cf6b67141d5b81d68e802de7036e8be047ae16878984a54288c6"
}
```

### Sample 93: `8bdafb667fdb611e`

| Field | Value |
|---|---|
| SHA-256 | `8bdafb667fdb611e0158fe026c5492a8d91c0196ca7b46b6e3e6c6e66199fd83` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-18 05:22:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb3734d275167a8a649e13c4866b08ef` |
| SHA-1 | `bb04b84c0a64fdc3eddabbc6851654e446f45537` |
| SHA-256 | `8bdafb667fdb611e0158fe026c5492a8d91c0196ca7b46b6e3e6c6e66199fd83` |
| SHA3-384 | `579b6da6b1080dd0bd5d200503b3c0f47e33cd60ce97bf493adba9746fa39f292cd2d73749067b8f4fe8ac729da04836` |
| TLSH | `T187637D1775C1E0FCCC8DC178469EB636E9B3B47A02B4B91977D0EE1A2E58E112F6E640` |
| TELFHASH | `t11d2124b57c9a0850d1fbf131e757d1602d601a2414fa38f9dab2b8f98e22b800e76823` |
| SSDEEP | `1536:XEwCVj75pUr8zSFuO1al2sflAlhKTVcMv:XEwUPq8zzO1al5flAlhsqM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_8bdafb66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bdafb667fdb611e0158fe026c5492a8d91c0196ca7b46b6e3e6c6e66199fd83"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 05:22:16"
  condition:
    hash.sha256(0, filesize) == "8bdafb667fdb611e0158fe026c5492a8d91c0196ca7b46b6e3e6c6e66199fd83"
}
```

### Sample 94: `41ad835dd6fb6680`

| Field | Value |
|---|---|
| SHA-256 | `41ad835dd6fb668047c0764aced6c4fb36b936a0989525a201dc2aa91313fada` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-18 05:22:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac1d08b61d9b23186b9332e787e5bf26` |
| SHA-1 | `050e9913ac41f44e35f9ff282d61d83de73348a7` |
| SHA-256 | `41ad835dd6fb668047c0764aced6c4fb36b936a0989525a201dc2aa91313fada` |
| SHA3-384 | `3d6275768828fc326817c455bcf4c43a4ae7a6efd01ab09d94bd8b0df060455ed779da0b8553019daaefbfd6be4cbb69` |
| TLSH | `T11B03E1BBA11ADCF8DCABF1FD371832D8F315AC0750058B5B989929FB44E59D13A2460A` |
| SSDEEP | `768:E0i+NO9yr/GRlf0Q269TA8Nv+gMuj8NHvMXFM0p7i7c4N:FG9y8f0/6TtYuj8NPsDQn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_41ad835d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41ad835dd6fb668047c0764aced6c4fb36b936a0989525a201dc2aa91313fada"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 05:22:05"
  condition:
    hash.sha256(0, filesize) == "41ad835dd6fb668047c0764aced6c4fb36b936a0989525a201dc2aa91313fada"
}
```

### Sample 95: `2d3a03c745245cb1`

| Field | Value |
|---|---|
| SHA-256 | `2d3a03c745245cb1788f77766340d1c5904e9ea5de56e792c70dc304acc162e6` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-11-18 05:20:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5bb4e46e271ead9ed7e02e95a92586b` |
| SHA-1 | `d7ca1c1e5d1800506cf0808d059255b39a8a5bde` |
| SHA-256 | `2d3a03c745245cb1788f77766340d1c5904e9ea5de56e792c70dc304acc162e6` |
| SHA3-384 | `1a5844fd930890c452358bdb3786eaeaf7dbadc2d7be12e2aed20e8afd44879e559793885b15f4f98ff10973b5b637a4` |
| TLSH | `T17C834CDBF800D9BAF80DE77B8453050AB630F7710A821B76739B7527ED361A54926F82` |
| SSDEEP | `1536:NMAr2sfLA+yW5pMo5M8noQyZ1+w9Y5m9mg2pXg7HriFeINyxJc3N+QB2:2Gs2Mo53yZ1+X5kmg2pXiKNyxJ9Q8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_2d3a03c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d3a03c745245cb1788f77766340d1c5904e9ea5de56e792c70dc304acc162e6"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-18 05:20:09"
  condition:
    hash.sha256(0, filesize) == "2d3a03c745245cb1788f77766340d1c5904e9ea5de56e792c70dc304acc162e6"
}
```

### Sample 96: `779a80758cbf72a3`

| Field | Value |
|---|---|
| SHA-256 | `779a80758cbf72a3db9699c44ec1ac4e231a8d27919c39d7124380cd1149bd7e` |
| Family label | `Mirai` |
| File name | `iranbot-ultimate.i686` |
| File type | `elf` |
| First seen | `2026-11-18 05:20:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abe92751ae9718cedb6baa6dab7cd095` |
| SHA-1 | `3b77b694aa61de312c81874493bb11866f05b5c2` |
| SHA-256 | `779a80758cbf72a3db9699c44ec1ac4e231a8d27919c39d7124380cd1149bd7e` |
| SHA3-384 | `57f259a5a7e60552b7dbed29f33f7b636d946405f85a8b9ab789ef35aa0a67cd5b08c14c8b3046d698bb19827834c8d7` |
| TLSH | `T12BC35B40FBC3C1F1D8074E71902A733FDB31AA1E8035CA1BEFE16E25DA57E419A16299` |
| TELFHASH | `t1975148f9ad7608e867d09d02f28e4b31ed0dab6b286471b705f31a7032b254197bac35` |
| SSDEEP | `3072:djzYQzch5sg2BzDDV+kiG7H5u8/9npNhBTS:RYQzCsg2BXDkgpbBTS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_779a8075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "779a80758cbf72a3db9699c44ec1ac4e231a8d27919c39d7124380cd1149bd7e"
    family = "Mirai"
    file_name = "iranbot-ultimate.i686"
    file_type = "elf"
    first_seen = "2026-11-18 05:20:06"
  condition:
    hash.sha256(0, filesize) == "779a80758cbf72a3db9699c44ec1ac4e231a8d27919c39d7124380cd1149bd7e"
}
```

### Sample 97: `54725148d719c34e`

| Field | Value |
|---|---|
| SHA-256 | `54725148d719c34e077eb1b18f0337072699c410953b23115b8b32e30440b9df` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-18 05:19:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efac871f21f5fed6c87164a4fb39eae4` |
| SHA-1 | `38b9cce34b85049d0854061dc239169b092aa795` |
| SHA-256 | `54725148d719c34e077eb1b18f0337072699c410953b23115b8b32e30440b9df` |
| SHA3-384 | `9ea070d582ffbb718fcea61e944244da281d8631e5105d268a5d3c5d6540a03da0f4e7765aeafec1bb8e71eb56a15018` |
| TLSH | `T1C2556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSK:SDjxB4m5n8XlaPWi+d+a4TjxQP4M` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_097_54725148
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54725148d719c34e077eb1b18f0337072699c410953b23115b8b32e30440b9df"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-18 05:19:06"
  condition:
    hash.sha256(0, filesize) == "54725148d719c34e077eb1b18f0337072699c410953b23115b8b32e30440b9df"
}
```

### Sample 98: `41b86bf3fa8d5c9c`

| Field | Value |
|---|---|
| SHA-256 | `41b86bf3fa8d5c9c1aee20af8b0963d3bb91a602408bab3d2665b3d41536fa61` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-11-18 05:18:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a191dac5124aed014047d484959b588` |
| SHA-1 | `51ce624975a1e1bfde04b5e5a8fbf291575c1a0b` |
| SHA-256 | `41b86bf3fa8d5c9c1aee20af8b0963d3bb91a602408bab3d2665b3d41536fa61` |
| SHA3-384 | `17c5c441419d055776c5f7578f3cf264ed31dcfa5efba97bc1cf5ed4189ffdbdeddf58a1d3c513e84a7238c3ee1580aa` |
| TLSH | `T157834A5AF8819B12D9D114BAFE2E528D3313177CD3EF72269E20AF3423875670E3A915` |
| SSDEEP | `1536:8AnE0l1T3AG4LYnbehSNaealSd13+9vq/p1iXag5hW/94a147lS5oY6:Dl1MG4LObehMHalfaMhW/94a14JS6d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_41b86bf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41b86bf3fa8d5c9c1aee20af8b0963d3bb91a602408bab3d2665b3d41536fa61"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-18 05:18:22"
  condition:
    hash.sha256(0, filesize) == "41b86bf3fa8d5c9c1aee20af8b0963d3bb91a602408bab3d2665b3d41536fa61"
}
```

### Sample 99: `3e99d60bd4b556e1`

| Field | Value |
|---|---|
| SHA-256 | `3e99d60bd4b556e14fa952be8e66762d14cb82ef845113b852fd161b7b3a5d95` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-11-18 05:18:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d43457c7ed3f9748b35e420a3a01d652` |
| SHA-1 | `0837cfa4a261b1c2ac7345294bf6687d9cc015c9` |
| SHA-256 | `3e99d60bd4b556e14fa952be8e66762d14cb82ef845113b852fd161b7b3a5d95` |
| SHA3-384 | `e3874a7bcbbcf2264c811a434639faf0eda361396c8c8d804a126603241ebfe939031a5e5f6771caae4c057c550a71aa` |
| TLSH | `T1A413F14123A4AC26D2A51D76466D6243EF4726F54BD9F4F13B80CA682CD342F66F238F` |
| SSDEEP | `768:3SJkbESbUeBg51km3cLGYQgm9LEhEFOXscFwu2+RhNEsMUYPHVD1T55yGkq3UirW:CJkg2gInGfukUYPl1T55yN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_3e99d60b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e99d60bd4b556e14fa952be8e66762d14cb82ef845113b852fd161b7b3a5d95"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-18 05:18:06"
  condition:
    hash.sha256(0, filesize) == "3e99d60bd4b556e14fa952be8e66762d14cb82ef845113b852fd161b7b3a5d95"
}
```

### Sample 100: `3b43362bf668b610`

| Field | Value |
|---|---|
| SHA-256 | `3b43362bf668b610e5d543bcf8d98665298b547c239cf998f7ecd167a48ffbe4` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-18 05:16:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `238cbda03a53c2802ae859cdc65a69a8` |
| SHA-1 | `c4dc906133bfbb6afd966cdb7243ec55b0850135` |
| SHA-256 | `3b43362bf668b610e5d543bcf8d98665298b547c239cf998f7ecd167a48ffbe4` |
| SHA3-384 | `0590e80770266759c783ef07ef6400755a40ed23ec2d4ae44a9e93f21e9cdceaa631507c22ef29661243e2a916b55daf` |
| TLSH | `T169556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSZ:SDjxB4m5n8XlaPWi+d+a4TjxQP4T` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_100_3b43362b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b43362bf668b610e5d543bcf8d98665298b547c239cf998f7ecd167a48ffbe4"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-18 05:16:06"
  condition:
    hash.sha256(0, filesize) == "3b43362bf668b610e5d543bcf8d98665298b547c239cf998f7ecd167a48ffbe4"
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
 * Generated: 2026-11-18T07:40:58.531088+00:00
 */

rule MalwareBazaar_unknown_001_032313b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "032313b66f60099b71c4713bf43b27fcab23cfcf098b13b5bd554524a58de98f"
    family = "unknown"
    file_name = "vcruntime"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:35"
  condition:
    hash.sha256(0, filesize) == "032313b66f60099b71c4713bf43b27fcab23cfcf098b13b5bd554524a58de98f"
}

rule MalwareBazaar_unknown_002_21988655
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "219886558ffc16d1580f79f619be773508bfd8feb26023c1b50d9c6f6d0996f0"
    family = "unknown"
    file_name = "libstd"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:32"
  condition:
    hash.sha256(0, filesize) == "219886558ffc16d1580f79f619be773508bfd8feb26023c1b50d9c6f6d0996f0"
}

rule MalwareBazaar_unknown_003_bb0a5471
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb0a547115aafd586aab949ffd15bdfdff0f740b43dfa68eed9ef679318e507b"
    family = "unknown"
    file_name = "libgcc"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:29"
  condition:
    hash.sha256(0, filesize) == "bb0a547115aafd586aab949ffd15bdfdff0f740b43dfa68eed9ef679318e507b"
}

rule MalwareBazaar_unknown_004_caa94ba3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caa94ba39d489d025d98b1c79b8beab28d1dcfb3c5837cf67d74fa7fe5f63e2b"
    family = "unknown"
    file_name = "d3d10"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:27"
  condition:
    hash.sha256(0, filesize) == "caa94ba39d489d025d98b1c79b8beab28d1dcfb3c5837cf67d74fa7fe5f63e2b"
}

rule MalwareBazaar_unknown_005_42453413
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4245341327823028091aba8cb11aa297394ed4c277d67ebdf34801ef49c7320b"
    family = "unknown"
    file_name = "msvcp"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:24"
  condition:
    hash.sha256(0, filesize) == "4245341327823028091aba8cb11aa297394ed4c277d67ebdf34801ef49c7320b"
}

rule MalwareBazaar_unknown_006_12f0546d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12f0546d011e41e495c0ad35587689c62c4ba1f912ada9a9858ad5d5851e8021"
    family = "unknown"
    file_name = "xinput"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:22"
  condition:
    hash.sha256(0, filesize) == "12f0546d011e41e495c0ad35587689c62c4ba1f912ada9a9858ad5d5851e8021"
}

rule MalwareBazaar_unknown_007_2849af57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2849af577a06f7399e7312666ffbe6021ef0759be43d21a976ccfb336baeb137"
    family = "unknown"
    file_name = "dxgi"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:19"
  condition:
    hash.sha256(0, filesize) == "2849af577a06f7399e7312666ffbe6021ef0759be43d21a976ccfb336baeb137"
}

rule MalwareBazaar_unknown_008_f087ec5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f087ec5d003ae07d505382345f7c24c0322247e856e1374751ee3b3e781fe6a7"
    family = "unknown"
    file_name = "openal"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:16"
  condition:
    hash.sha256(0, filesize) == "f087ec5d003ae07d505382345f7c24c0322247e856e1374751ee3b3e781fe6a7"
}

rule MalwareBazaar_unknown_009_3ec16b97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ec16b971cd15e1e2e07f870ab66daa2ad1967e12da9a7036cb34a9d1fd012a9"
    family = "unknown"
    file_name = "ddraw"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:14"
  condition:
    hash.sha256(0, filesize) == "3ec16b971cd15e1e2e07f870ab66daa2ad1967e12da9a7036cb34a9d1fd012a9"
}

rule MalwareBazaar_unknown_010_c58aa577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c58aa5775db17153220f5c676b1d03d0c3ab0464550a30da047c6af8695d0b61"
    family = "unknown"
    file_name = "vulkan"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:11"
  condition:
    hash.sha256(0, filesize) == "c58aa5775db17153220f5c676b1d03d0c3ab0464550a30da047c6af8695d0b61"
}

rule MalwareBazaar_unknown_011_ade786a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ade786a1912b30d20290c2426bf889255d9e50bde8d7f72e31db97e8814e9312"
    family = "unknown"
    file_name = "libEGL"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:08"
  condition:
    hash.sha256(0, filesize) == "ade786a1912b30d20290c2426bf889255d9e50bde8d7f72e31db97e8814e9312"
}

rule MalwareBazaar_unknown_012_8c2ff62d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c2ff62d55d632fed8e3a828a1b89f2e623e7f2a0014f032d1fe04a6a6254150"
    family = "unknown"
    file_name = "d3d9"
    file_type = "elf"
    first_seen = "2026-11-18 07:39:05"
  condition:
    hash.sha256(0, filesize) == "8c2ff62d55d632fed8e3a828a1b89f2e623e7f2a0014f032d1fe04a6a6254150"
}

rule MalwareBazaar_STRRAT_013_e45d7773
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e45d7773ee91b55d98d77c7792f3930d0b2adf89bf3f82a01ec1a85eadee1f20"
    family = "STRRAT"
    file_name = "Tax Returns of R38,765.js"
    file_type = "js"
    first_seen = "2026-11-18 07:35:06"
  condition:
    hash.sha256(0, filesize) == "e45d7773ee91b55d98d77c7792f3930d0b2adf89bf3f82a01ec1a85eadee1f20"
}

rule MalwareBazaar_unknown_014_fd17b84f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd17b84f0abdbcb6c734727a3fb9346d8dd2a2b5c87b088bef5b7e7e163adc98"
    family = "unknown"
    file_name = "Loader_v2.exe"
    file_type = "exe"
    first_seen = "2026-11-18 07:35:06"
  condition:
    hash.sha256(0, filesize) == "fd17b84f0abdbcb6c734727a3fb9346d8dd2a2b5c87b088bef5b7e7e163adc98"
}

rule MalwareBazaar_unknown_015_91e5263f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91e5263f8146a978a86dcee7e6a9e818cf2156d4383b91d02c30f55d12b193f4"
    family = "unknown"
    file_name = "WindowsUpdate.jar"
    file_type = "jar"
    first_seen = "2026-11-18 07:31:45"
  condition:
    hash.sha256(0, filesize) == "91e5263f8146a978a86dcee7e6a9e818cf2156d4383b91d02c30f55d12b193f4"
}

rule MalwareBazaar_unknown_016_30bad4cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30bad4cfd09e6381328b78411f7254478d50f26d0f0e7682cd4562b3405186a9"
    family = "unknown"
    file_name = "wp.py"
    file_type = "py"
    first_seen = "2026-11-18 07:27:15"
  condition:
    hash.sha256(0, filesize) == "30bad4cfd09e6381328b78411f7254478d50f26d0f0e7682cd4562b3405186a9"
}

rule MalwareBazaar_unknown_017_c30c8e93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c30c8e937d48dae48c5c6a65952a409ef78f259075f64fbf27b250d5c9b394f2"
    family = "unknown"
    file_name = "xinj.py"
    file_type = "py"
    first_seen = "2026-11-18 07:27:11"
  condition:
    hash.sha256(0, filesize) == "c30c8e937d48dae48c5c6a65952a409ef78f259075f64fbf27b250d5c9b394f2"
}

rule MalwareBazaar_Mirai_018_8848e83c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8848e83cc2c619748d0900da2b4867b7dd01f5f104200ee3a8e2f7a6d7143c0f"
    family = "Mirai"
    file_name = "mentality-cloud.x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 07:11:23"
  condition:
    hash.sha256(0, filesize) == "8848e83cc2c619748d0900da2b4867b7dd01f5f104200ee3a8e2f7a6d7143c0f"
}

rule MalwareBazaar_Mirai_019_027b645b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "027b645b8b20614d77d0648ed2c1765641fae5e6358ddacde2463c75cb2ce18f"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm7"
    file_type = "elf"
    first_seen = "2026-11-18 07:11:18"
  condition:
    hash.sha256(0, filesize) == "027b645b8b20614d77d0648ed2c1765641fae5e6358ddacde2463c75cb2ce18f"
}

rule MalwareBazaar_Mirai_020_89795ada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89795adac8f814af28ac6def74c8c21a07f2b227596810088ffccb7fbe2205d5"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.ppc"
    file_type = "elf"
    first_seen = "2026-11-18 07:11:13"
  condition:
    hash.sha256(0, filesize) == "89795adac8f814af28ac6def74c8c21a07f2b227596810088ffccb7fbe2205d5"
}

rule MalwareBazaar_Mirai_021_771463af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "771463af999817e8f76240ddc983fd554de5de011ff81fa7947d25016d165054"
    family = "Mirai"
    file_name = "mentality-cloud.x86"
    file_type = "elf"
    first_seen = "2026-11-18 07:11:08"
  condition:
    hash.sha256(0, filesize) == "771463af999817e8f76240ddc983fd554de5de011ff81fa7947d25016d165054"
}

rule MalwareBazaar_Mirai_022_766387fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "766387fa0582545e6f23237d0ac63862084d6d4f8eec86cdaf24a3fcddc125ee"
    family = "Mirai"
    file_name = "mentality-cloud.i686"
    file_type = "elf"
    first_seen = "2026-11-18 07:11:02"
  condition:
    hash.sha256(0, filesize) == "766387fa0582545e6f23237d0ac63862084d6d4f8eec86cdaf24a3fcddc125ee"
}

rule MalwareBazaar_Mirai_023_3dd5927c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dd5927cdeda55f7bc1d8aabc534568d163be2d570c4818b83e438d988a64340"
    family = "Mirai"
    file_name = "mentality-cloud.mips"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:58"
  condition:
    hash.sha256(0, filesize) == "3dd5927cdeda55f7bc1d8aabc534568d163be2d570c4818b83e438d988a64340"
}

rule MalwareBazaar_Mirai_024_964018bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "964018bdf5064e241d4def33333bca60358e7f474217f4544dbb88c46da0f75b"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.i686"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:54"
  condition:
    hash.sha256(0, filesize) == "964018bdf5064e241d4def33333bca60358e7f474217f4544dbb88c46da0f75b"
}

rule MalwareBazaar_Mirai_025_9fff203b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fff203b78906ab9dd944d3811c9d005fc1dcd5970993afa028c185227aca173"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:50"
  condition:
    hash.sha256(0, filesize) == "9fff203b78906ab9dd944d3811c9d005fc1dcd5970993afa028c185227aca173"
}

rule MalwareBazaar_Mirai_026_4d5f0068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d5f0068493838dcdc4404f52af4d6134775fa525eacd81e0dd114e4bb429f11"
    family = "Mirai"
    file_name = "mentality-cloud.arm5"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:46"
  condition:
    hash.sha256(0, filesize) == "4d5f0068493838dcdc4404f52af4d6134775fa525eacd81e0dd114e4bb429f11"
}

rule MalwareBazaar_Mirai_027_2f454e85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f454e85e3707fc36bc3f365263324c309b05556a3b13e10b545029db74442f7"
    family = "Mirai"
    file_name = "mentality-cloud.arm7"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:42"
  condition:
    hash.sha256(0, filesize) == "2f454e85e3707fc36bc3f365263324c309b05556a3b13e10b545029db74442f7"
}

rule MalwareBazaar_Mirai_028_ebbc9f8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebbc9f8ff016d2628cf44ad55998c1f8e8b86e6076fd6b38bc140157dd7ed20e"
    family = "Mirai"
    file_name = "mentality-cloud.ppc"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:38"
  condition:
    hash.sha256(0, filesize) == "ebbc9f8ff016d2628cf44ad55998c1f8e8b86e6076fd6b38bc140157dd7ed20e"
}

rule MalwareBazaar_Mirai_029_13df1c87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13df1c87c1cdbf8f64f0c6d2011bbae1ae0f5adfa1df3f55a8aa915e216abb5b"
    family = "Mirai"
    file_name = "mentality-cloud.mpsl"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:34"
  condition:
    hash.sha256(0, filesize) == "13df1c87c1cdbf8f64f0c6d2011bbae1ae0f5adfa1df3f55a8aa915e216abb5b"
}

rule MalwareBazaar_Mirai_030_bc02e875
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc02e875442bea0299bf413e1403c81d0f76e185edc85da5e79169b06c364274"
    family = "Mirai"
    file_name = "mentality-cloud.arm"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:30"
  condition:
    hash.sha256(0, filesize) == "bc02e875442bea0299bf413e1403c81d0f76e185edc85da5e79169b06c364274"
}

rule MalwareBazaar_Mirai_031_115234e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "115234e37a7198a3057f3d86d93a14de96e7251ed4ebfa7ff8dab98893e275d3"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:26"
  condition:
    hash.sha256(0, filesize) == "115234e37a7198a3057f3d86d93a14de96e7251ed4ebfa7ff8dab98893e275d3"
}

rule MalwareBazaar_Mirai_032_1291219a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1291219ad7b296887c8bbdb14d4d7ed6207855d8641f193fa65a331890ddf3c5"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.mpsl"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:21"
  condition:
    hash.sha256(0, filesize) == "1291219ad7b296887c8bbdb14d4d7ed6207855d8641f193fa65a331890ddf3c5"
}

rule MalwareBazaar_Mirai_033_b475f905
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b475f90544354232758432ba2ae7efb64ce7d2a64c3d11bd2da97f51c22d7b6a"
    family = "Mirai"
    file_name = "mentality-cloud.m68k"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:13"
  condition:
    hash.sha256(0, filesize) == "b475f90544354232758432ba2ae7efb64ce7d2a64c3d11bd2da97f51c22d7b6a"
}

rule MalwareBazaar_Mirai_034_5590f9ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5590f9ab82bea6615a272158a255d5c82ef21878c06783c7b195b9f5440b010f"
    family = "Mirai"
    file_name = "mentality-cloud.spc"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:10"
  condition:
    hash.sha256(0, filesize) == "5590f9ab82bea6615a272158a255d5c82ef21878c06783c7b195b9f5440b010f"
}

rule MalwareBazaar_Mirai_035_c7aed76b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7aed76b8795268f151cf85f36d778d55a9be3e785ed41b03d90c44ebd203e9b"
    family = "Mirai"
    file_name = "mentality-cloud.x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:06"
  condition:
    hash.sha256(0, filesize) == "c7aed76b8795268f151cf85f36d778d55a9be3e785ed41b03d90c44ebd203e9b"
}

rule MalwareBazaar_Mirai_036_2b845984
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b84598489b7338b867a6fbb4638bd41c857c738ac9906f10ebabf1afbbfe8d2"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arc"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:03"
  condition:
    hash.sha256(0, filesize) == "2b84598489b7338b867a6fbb4638bd41c857c738ac9906f10ebabf1afbbfe8d2"
}

rule MalwareBazaar_Mirai_037_20eff41f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20eff41f1d2be20f8f92205497962c7d10c4a5bf1d109e0ce34ac2c661214550"
    family = "Mirai"
    file_name = "mentality-cloud.sh4"
    file_type = "elf"
    first_seen = "2026-11-18 07:10:00"
  condition:
    hash.sha256(0, filesize) == "20eff41f1d2be20f8f92205497962c7d10c4a5bf1d109e0ce34ac2c661214550"
}

rule MalwareBazaar_Mirai_038_f9f66374
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9f663749098bbee31fa7da817e2cee6aa63d7248da1d9c5471f5c8d5c286730"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm7"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:58"
  condition:
    hash.sha256(0, filesize) == "f9f663749098bbee31fa7da817e2cee6aa63d7248da1d9c5471f5c8d5c286730"
}

rule MalwareBazaar_Mirai_039_806bd877
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "806bd8770459788f99d6ffcd149b5e9daa0f49ee03b78d93791aa331e5023178"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.ppc"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:55"
  condition:
    hash.sha256(0, filesize) == "806bd8770459788f99d6ffcd149b5e9daa0f49ee03b78d93791aa331e5023178"
}

rule MalwareBazaar_Mirai_040_9b714330
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b7143308b280d7c5784ff339f7f990a7ebc2e561b898651798f23a1c413cbcd"
    family = "Mirai"
    file_name = "mentality-cloud.x86"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:52"
  condition:
    hash.sha256(0, filesize) == "9b7143308b280d7c5784ff339f7f990a7ebc2e561b898651798f23a1c413cbcd"
}

rule MalwareBazaar_Mirai_041_6e0a9b65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e0a9b65891ec8269e636aeee0b0210148a2e4c91932e90f3a61da527487c825"
    family = "Mirai"
    file_name = "mentality-cloud.i686"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:50"
  condition:
    hash.sha256(0, filesize) == "6e0a9b65891ec8269e636aeee0b0210148a2e4c91932e90f3a61da527487c825"
}

rule MalwareBazaar_Mirai_042_3967a8fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3967a8fbd4bffd90e51dd478f964d18f03dd41eb28d750118820c400c5b0e17d"
    family = "Mirai"
    file_name = "mentality-cloud.mips"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:47"
  condition:
    hash.sha256(0, filesize) == "3967a8fbd4bffd90e51dd478f964d18f03dd41eb28d750118820c400c5b0e17d"
}

rule MalwareBazaar_Mirai_043_7a9f8a2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a9f8a2d271b96c06d839ff8978d3581aa7771cea568f8d966324c14ba5e1f1e"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.i686"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:44"
  condition:
    hash.sha256(0, filesize) == "7a9f8a2d271b96c06d839ff8978d3581aa7771cea568f8d966324c14ba5e1f1e"
}

rule MalwareBazaar_Mirai_044_d6d8021e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6d8021e2e5dbce11c0ec9d5ef433485cb0834fc3bd4164a72f61993e017f5ec"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:42"
  condition:
    hash.sha256(0, filesize) == "d6d8021e2e5dbce11c0ec9d5ef433485cb0834fc3bd4164a72f61993e017f5ec"
}

rule MalwareBazaar_Mirai_045_f7a590cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7a590cd7ebcfe9f20b633ad2535cd4b303ada673c20db45ab2b1daa0886eeef"
    family = "Mirai"
    file_name = "mentality-cloud.arm5"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:39"
  condition:
    hash.sha256(0, filesize) == "f7a590cd7ebcfe9f20b633ad2535cd4b303ada673c20db45ab2b1daa0886eeef"
}

rule MalwareBazaar_Mirai_046_f7bc6791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7bc67915ebcc38cc4b4ff2e7006f2e0918baf689dbf3e366371b6eb77afcd03"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.sh4"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:36"
  condition:
    hash.sha256(0, filesize) == "f7bc67915ebcc38cc4b4ff2e7006f2e0918baf689dbf3e366371b6eb77afcd03"
}

rule MalwareBazaar_Mirai_047_b4a2d9cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4a2d9cca8891c0ae3d7a314ef8e4c3742e77b7cbee8ed8a692da22ddb02f3ba"
    family = "Mirai"
    file_name = "mentality-cloud.arm7"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:34"
  condition:
    hash.sha256(0, filesize) == "b4a2d9cca8891c0ae3d7a314ef8e4c3742e77b7cbee8ed8a692da22ddb02f3ba"
}

rule MalwareBazaar_Mirai_048_b4ae5c8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4ae5c8cfe80252221ac27fb14c13aafb56f272de222e8a06e671b22bb14b12d"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.m68k"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:31"
  condition:
    hash.sha256(0, filesize) == "b4ae5c8cfe80252221ac27fb14c13aafb56f272de222e8a06e671b22bb14b12d"
}

rule MalwareBazaar_Mirai_049_3fcb447f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fcb447f7e76d8f7753e5935975f66a09380393c33f42626242cf120e3d29cd0"
    family = "Mirai"
    file_name = "mentality-cloud.ppc"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:28"
  condition:
    hash.sha256(0, filesize) == "3fcb447f7e76d8f7753e5935975f66a09380393c33f42626242cf120e3d29cd0"
}

rule MalwareBazaar_Mirai_050_eea08dc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eea08dc35c05f43c65aad780a0a5ea74e3754ed389f6a8f9dd447245e728e8a8"
    family = "Mirai"
    file_name = "mentality-cloud.mpsl"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:25"
  condition:
    hash.sha256(0, filesize) == "eea08dc35c05f43c65aad780a0a5ea74e3754ed389f6a8f9dd447245e728e8a8"
}

rule MalwareBazaar_Mirai_051_61767e61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61767e616dc37556066837dd0dafddbce022fdd1494019d6fca6d92ef8f588d2"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm5"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:24"
  condition:
    hash.sha256(0, filesize) == "61767e616dc37556066837dd0dafddbce022fdd1494019d6fca6d92ef8f588d2"
}

rule MalwareBazaar_Mirai_052_9f4c9d96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f4c9d9665c70ff9a6e214329e8d3ce4556500ba20e038eb80450328ffe2380d"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.spc"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:23"
  condition:
    hash.sha256(0, filesize) == "9f4c9d9665c70ff9a6e214329e8d3ce4556500ba20e038eb80450328ffe2380d"
}

rule MalwareBazaar_Mirai_053_96e694c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96e694c33484c0876b3827884295d457f03e0cc3dc607bf0ed2719b26a04fdc9"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.mips"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:20"
  condition:
    hash.sha256(0, filesize) == "96e694c33484c0876b3827884295d457f03e0cc3dc607bf0ed2719b26a04fdc9"
}

rule MalwareBazaar_Mirai_054_1345a7c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1345a7c5746070ee4d3457c1dd990c9ee74201a8cd9829d79d974097b832c015"
    family = "Mirai"
    file_name = "mentality-cloud.arm"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:20"
  condition:
    hash.sha256(0, filesize) == "1345a7c5746070ee4d3457c1dd990c9ee74201a8cd9829d79d974097b832c015"
}

rule MalwareBazaar_Mirai_055_f5d29434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5d29434e7a5b62bbb5cf3c87579cb8c762c484c44f20b576e64cabd5c4accf6"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:17"
  condition:
    hash.sha256(0, filesize) == "f5d29434e7a5b62bbb5cf3c87579cb8c762c484c44f20b576e64cabd5c4accf6"
}

rule MalwareBazaar_Mirai_056_593efa38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "593efa380d1616adfa06b9dde008f76e8f24b2069fc1e1523fc3aab74685586f"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm6"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:16"
  condition:
    hash.sha256(0, filesize) == "593efa380d1616adfa06b9dde008f76e8f24b2069fc1e1523fc3aab74685586f"
}

rule MalwareBazaar_Mirai_057_3da5b80c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3da5b80c5739af62401d588cc32d91f8351399c0f9c0045e25650015657ed345"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.mpsl"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:15"
  condition:
    hash.sha256(0, filesize) == "3da5b80c5739af62401d588cc32d91f8351399c0f9c0045e25650015657ed345"
}

rule MalwareBazaar_Mirai_058_a1795f39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1795f396b86bbf1c8afcafee7b3bea660626d714cbb926bc2f65de06ca45011"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm5"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:11"
  condition:
    hash.sha256(0, filesize) == "a1795f396b86bbf1c8afcafee7b3bea660626d714cbb926bc2f65de06ca45011"
}

rule MalwareBazaar_Mirai_059_67252552
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67252552e4efcfd53929e5cc860e14d95226222cdaa80455fae5a5ad934c3366"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.mips"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:08"
  condition:
    hash.sha256(0, filesize) == "67252552e4efcfd53929e5cc860e14d95226222cdaa80455fae5a5ad934c3366"
}

rule MalwareBazaar_Mirai_060_a470b3a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a470b3a5cf980b040842ee1d2c5224d10c73869bb59f3c76dc31b366d99d567a"
    family = "Mirai"
    file_name = "FGx8SNCa4txePA.arm6"
    file_type = "elf"
    first_seen = "2026-11-18 07:09:06"
  condition:
    hash.sha256(0, filesize) == "a470b3a5cf980b040842ee1d2c5224d10c73869bb59f3c76dc31b366d99d567a"
}

rule MalwareBazaar_Panchan_061_e5a522b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5a522b2b9d8e9220e0d4cf43e1587c1d1ccf444812607229f63fabe1ef65830"
    family = "Panchan"
    file_name = "e5a522b2b9d8e9220e0d4cf43e1587c1d1ccf444812607229f63fabe1ef65830"
    file_type = "elf"
    first_seen = "2026-11-18 06:52:18"
  condition:
    hash.sha256(0, filesize) == "e5a522b2b9d8e9220e0d4cf43e1587c1d1ccf444812607229f63fabe1ef65830"
}

rule MalwareBazaar_XWorm_062_8b515b6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b515b6ece08aaea6f84d5a094394acbababe209b10cccd945d0b46fd6acc6a0"
    family = "XWorm"
    file_name = "_00068"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:40"
  condition:
    hash.sha256(0, filesize) == "8b515b6ece08aaea6f84d5a094394acbababe209b10cccd945d0b46fd6acc6a0"
}

rule MalwareBazaar_XWorm_063_c4c84f59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4c84f595ae9260f703dadae2379d47591dd92d1b85802105798ab5de2aa1bf4"
    family = "XWorm"
    file_name = "a92816d7b9df41859ae6cba47f1f10b6.MSG"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:36"
  condition:
    hash.sha256(0, filesize) == "c4c84f595ae9260f703dadae2379d47591dd92d1b85802105798ab5de2aa1bf4"
}

rule MalwareBazaar_Formbook_064_8f92be36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f92be363039893c07a578bf0be3cffd5b22f6cc402c18269ba6e650db81a93f"
    family = "Formbook"
    file_name = "8f92be363039893c07a578bf0be3cffd5b22f6cc402c18269ba6e650db81a93f"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:33"
  condition:
    hash.sha256(0, filesize) == "8f92be363039893c07a578bf0be3cffd5b22f6cc402c18269ba6e650db81a93f"
}

rule MalwareBazaar_XWorm_065_0c887592
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c88759246530f189e87fa23a593084b7cc29a389b7a8df08f1413dc731f4ad0"
    family = "XWorm"
    file_name = "entity-kNE9qHNQ"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:30"
  condition:
    hash.sha256(0, filesize) == "0c88759246530f189e87fa23a593084b7cc29a389b7a8df08f1413dc731f4ad0"
}

rule MalwareBazaar_Formbook_066_99e03781
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99e03781b4c52c5c5440082e54fff18857e59fe8161bf92184649ebcac7a6000"
    family = "Formbook"
    file_name = "md5001000000020.tmp"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:27"
  condition:
    hash.sha256(0, filesize) == "99e03781b4c52c5c5440082e54fff18857e59fe8161bf92184649ebcac7a6000"
}

rule MalwareBazaar_Formbook_067_c50ced11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c50ced1116cae74556951a395ce9bb2f958a519105093b38025009b7046a9f07"
    family = "Formbook"
    file_name = "_00015"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:24"
  condition:
    hash.sha256(0, filesize) == "c50ced1116cae74556951a395ce9bb2f958a519105093b38025009b7046a9f07"
}

rule MalwareBazaar_XWorm_068_8fef5347
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fef53474f80898c6f6aefa627af7d7241484cfac19e8ae80c5a6c939b0a727e"
    family = "XWorm"
    file_name = "_00093"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:21"
  condition:
    hash.sha256(0, filesize) == "8fef53474f80898c6f6aefa627af7d7241484cfac19e8ae80c5a6c939b0a727e"
}

rule MalwareBazaar_Formbook_069_20370532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20370532a621f2611b51ad0369fb1f48c5208f49a971b56b44f1e2d321c41cb0"
    family = "Formbook"
    file_name = "_00006"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:18"
  condition:
    hash.sha256(0, filesize) == "20370532a621f2611b51ad0369fb1f48c5208f49a971b56b44f1e2d321c41cb0"
}

rule MalwareBazaar_XWorm_070_e6ff71e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6ff71e8dcd5b81016287a4e601a6bed569e256e179c17e32182e08f4ce234d0"
    family = "XWorm"
    file_name = "md5001000070613.tmp"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:15"
  condition:
    hash.sha256(0, filesize) == "e6ff71e8dcd5b81016287a4e601a6bed569e256e179c17e32182e08f4ce234d0"
}

rule MalwareBazaar_XWorm_071_6b6d1feb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b6d1feb22b89f7c188f7ec7fed0b3fb48299119228b516379b6f4bbc3fec336"
    family = "XWorm"
    file_name = "_00032"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:12"
  condition:
    hash.sha256(0, filesize) == "6b6d1feb22b89f7c188f7ec7fed0b3fb48299119228b516379b6f4bbc3fec336"
}

rule MalwareBazaar_AsyncRAT_072_9921c957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9921c957833c07bf45c7f67f3a9f3d15555ad4da2be2b44021d6d211c1a8be67"
    family = "AsyncRAT"
    file_name = "b8f773f382aa4c3296c9d501ac9d2932.MSG"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:09"
  condition:
    hash.sha256(0, filesize) == "9921c957833c07bf45c7f67f3a9f3d15555ad4da2be2b44021d6d211c1a8be67"
}

rule MalwareBazaar_Formbook_073_0692bcfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0692bcfd2eb11a5ec2f5b1076e6cc4cd4c911adbc8ac34b7350c9797a25e432d"
    family = "Formbook"
    file_name = "6704b98266b949fbad6f0c153627d944.MSG"
    file_type = "exe"
    first_seen = "2026-11-18 05:50:06"
  condition:
    hash.sha256(0, filesize) == "0692bcfd2eb11a5ec2f5b1076e6cc4cd4c911adbc8ac34b7350c9797a25e432d"
}

rule MalwareBazaar_unknown_074_c813b812
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c813b812f9383c189a840e0cffd8868ccd1989b3db0b56fc0f337495417ffee1"
    family = "unknown"
    file_name = "c813b812f9383c189a840e0cffd8868ccd1989b3db0b56fc0f337495417ffee1"
    file_type = "sh"
    first_seen = "2026-11-18 05:48:30"
  condition:
    hash.sha256(0, filesize) == "c813b812f9383c189a840e0cffd8868ccd1989b3db0b56fc0f337495417ffee1"
}

rule MalwareBazaar_Mirai_075_e8e26860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8e26860ce49a7df66f9b41e5d66412e5a230d03bc2fcfeb3b9b1c0f2c34e9a2"
    family = "Mirai"
    file_name = "e8e26860ce49a7df66f9b41e5d66412e5a230d03bc2fcfeb3b9b1c0f2c34e9a2"
    file_type = "elf"
    first_seen = "2026-11-18 05:47:56"
  condition:
    hash.sha256(0, filesize) == "e8e26860ce49a7df66f9b41e5d66412e5a230d03bc2fcfeb3b9b1c0f2c34e9a2"
}

rule MalwareBazaar_Mirai_076_48e7c1e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48e7c1e1e23d0b36a9fa57383d8bc391891e5069c6965485266d63ce65b1fbdb"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-18 05:44:17"
  condition:
    hash.sha256(0, filesize) == "48e7c1e1e23d0b36a9fa57383d8bc391891e5069c6965485266d63ce65b1fbdb"
}

rule MalwareBazaar_Prometei_077_1734d823
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1734d82391a4771b63e5da431048526567ca8743397b2fab24abf44c27e8703a"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-18 05:44:11"
  condition:
    hash.sha256(0, filesize) == "1734d82391a4771b63e5da431048526567ca8743397b2fab24abf44c27e8703a"
}

rule MalwareBazaar_Mirai_078_e631b02a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e631b02a4e79c964e4e49ddacdb5f61a08819c7a64b6ccad81b7f465e4a05184"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-18 05:44:08"
  condition:
    hash.sha256(0, filesize) == "e631b02a4e79c964e4e49ddacdb5f61a08819c7a64b6ccad81b7f465e4a05184"
}

rule MalwareBazaar_Mirai_079_82078f6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82078f6e2f6d5f76556c0ea24fe0964b4678b4559442703dd637d191b7c7a44b"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-18 05:44:06"
  condition:
    hash.sha256(0, filesize) == "82078f6e2f6d5f76556c0ea24fe0964b4678b4559442703dd637d191b7c7a44b"
}

rule MalwareBazaar_Mirai_080_de4a8c66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de4a8c66fb63a9ce5de27eecdf99d5da3196642715388f4adaca44b1f4faff98"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-18 05:36:25"
  condition:
    hash.sha256(0, filesize) == "de4a8c66fb63a9ce5de27eecdf99d5da3196642715388f4adaca44b1f4faff98"
}

rule MalwareBazaar_Mirai_081_b14a5194
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b14a51949b7ca2c9305c8c921589b16ae1885fa6e8ec53570d4161ba312b43ed"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-11-18 05:36:09"
  condition:
    hash.sha256(0, filesize) == "b14a51949b7ca2c9305c8c921589b16ae1885fa6e8ec53570d4161ba312b43ed"
}

rule MalwareBazaar_Mirai_082_fbb4ee36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbb4ee3698ec25fec7a78f17ed744f55e0d70b64346ff9e9b39c5291714f303f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-18 05:36:06"
  condition:
    hash.sha256(0, filesize) == "fbb4ee3698ec25fec7a78f17ed744f55e0d70b64346ff9e9b39c5291714f303f"
}

rule MalwareBazaar_Prometei_083_d2d2e002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2d2e002714c37f8e8947931f04b7998885bc24680b14beee47d9b596823d241"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-18 05:33:07"
  condition:
    hash.sha256(0, filesize) == "d2d2e002714c37f8e8947931f04b7998885bc24680b14beee47d9b596823d241"
}

rule MalwareBazaar_Mirai_084_71e86c3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71e86c3b8c12521551dd3d47aebde6c0c63c9818f0f70afac40692d9eef85165"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-18 05:32:05"
  condition:
    hash.sha256(0, filesize) == "71e86c3b8c12521551dd3d47aebde6c0c63c9818f0f70afac40692d9eef85165"
}

rule MalwareBazaar_Mirai_085_a01ca0b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a01ca0b5167a4211b115d27579f0552484a1f48d78805debabdc40c9f21f3ed3"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-11-18 05:29:18"
  condition:
    hash.sha256(0, filesize) == "a01ca0b5167a4211b115d27579f0552484a1f48d78805debabdc40c9f21f3ed3"
}

rule MalwareBazaar_Mirai_086_6e86d289
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e86d289c8b345888d1b6bd16de687ebf4fcafc0173c79f1255ec0fd9df7541d"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-11-18 05:29:07"
  condition:
    hash.sha256(0, filesize) == "6e86d289c8b345888d1b6bd16de687ebf4fcafc0173c79f1255ec0fd9df7541d"
}

rule MalwareBazaar_Mirai_087_074c2917
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "074c291732db50ec45a5dd819d1f2ba224087eaabc14fa8a3b70ba744508d5c3"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-18 05:28:18"
  condition:
    hash.sha256(0, filesize) == "074c291732db50ec45a5dd819d1f2ba224087eaabc14fa8a3b70ba744508d5c3"
}

rule MalwareBazaar_Mirai_088_1cc698ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cc698edeb3593bbb5512cfcbe5207af8d167df7e2977f46284af8d389e51277"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-18 05:28:10"
  condition:
    hash.sha256(0, filesize) == "1cc698edeb3593bbb5512cfcbe5207af8d167df7e2977f46284af8d389e51277"
}

rule MalwareBazaar_Mirai_089_8f586ecf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f586ecff2b419b1a3cce134640c26b825e308bcacfb22ae4f5ce80cbf1d4d67"
    family = "Mirai"
    file_name = "iranbot-ultimate.i586"
    file_type = "elf"
    first_seen = "2026-11-18 05:28:07"
  condition:
    hash.sha256(0, filesize) == "8f586ecff2b419b1a3cce134640c26b825e308bcacfb22ae4f5ce80cbf1d4d67"
}

rule MalwareBazaar_Mirai_090_b4b7b586
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4b7b586c1dc77761dcae2cbe280e3aed238986011c98c174c89cc2908693325"
    family = "Mirai"
    file_name = "i486.new"
    file_type = "elf"
    first_seen = "2026-11-18 05:27:07"
  condition:
    hash.sha256(0, filesize) == "b4b7b586c1dc77761dcae2cbe280e3aed238986011c98c174c89cc2908693325"
}

rule MalwareBazaar_Mirai_091_f297afd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f297afd79f2d365eeff2bdac3582af421a75d25a57a6aae32cb3049f54e12069"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-11-18 05:26:07"
  condition:
    hash.sha256(0, filesize) == "f297afd79f2d365eeff2bdac3582af421a75d25a57a6aae32cb3049f54e12069"
}

rule MalwareBazaar_Mirai_092_b4c92111
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4c92111ba57cf6b67141d5b81d68e802de7036e8be047ae16878984a54288c6"
    family = "Mirai"
    file_name = "armv6l.new"
    file_type = "elf"
    first_seen = "2026-11-18 05:25:06"
  condition:
    hash.sha256(0, filesize) == "b4c92111ba57cf6b67141d5b81d68e802de7036e8be047ae16878984a54288c6"
}

rule MalwareBazaar_Mirai_093_8bdafb66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bdafb667fdb611e0158fe026c5492a8d91c0196ca7b46b6e3e6c6e66199fd83"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 05:22:16"
  condition:
    hash.sha256(0, filesize) == "8bdafb667fdb611e0158fe026c5492a8d91c0196ca7b46b6e3e6c6e66199fd83"
}

rule MalwareBazaar_Mirai_094_41ad835d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41ad835dd6fb668047c0764aced6c4fb36b936a0989525a201dc2aa91313fada"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-18 05:22:05"
  condition:
    hash.sha256(0, filesize) == "41ad835dd6fb668047c0764aced6c4fb36b936a0989525a201dc2aa91313fada"
}

rule MalwareBazaar_Mirai_095_2d3a03c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d3a03c745245cb1788f77766340d1c5904e9ea5de56e792c70dc304acc162e6"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-18 05:20:09"
  condition:
    hash.sha256(0, filesize) == "2d3a03c745245cb1788f77766340d1c5904e9ea5de56e792c70dc304acc162e6"
}

rule MalwareBazaar_Mirai_096_779a8075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "779a80758cbf72a3db9699c44ec1ac4e231a8d27919c39d7124380cd1149bd7e"
    family = "Mirai"
    file_name = "iranbot-ultimate.i686"
    file_type = "elf"
    first_seen = "2026-11-18 05:20:06"
  condition:
    hash.sha256(0, filesize) == "779a80758cbf72a3db9699c44ec1ac4e231a8d27919c39d7124380cd1149bd7e"
}

rule MalwareBazaar_Prometei_097_54725148
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54725148d719c34e077eb1b18f0337072699c410953b23115b8b32e30440b9df"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-18 05:19:06"
  condition:
    hash.sha256(0, filesize) == "54725148d719c34e077eb1b18f0337072699c410953b23115b8b32e30440b9df"
}

rule MalwareBazaar_Mirai_098_41b86bf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41b86bf3fa8d5c9c1aee20af8b0963d3bb91a602408bab3d2665b3d41536fa61"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-18 05:18:22"
  condition:
    hash.sha256(0, filesize) == "41b86bf3fa8d5c9c1aee20af8b0963d3bb91a602408bab3d2665b3d41536fa61"
}

rule MalwareBazaar_Mirai_099_3e99d60b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e99d60bd4b556e14fa952be8e66762d14cb82ef845113b852fd161b7b3a5d95"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-18 05:18:06"
  condition:
    hash.sha256(0, filesize) == "3e99d60bd4b556e14fa952be8e66762d14cb82ef845113b852fd161b7b3a5d95"
}

rule MalwareBazaar_Prometei_100_3b43362b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b43362bf668b610e5d543bcf8d98665298b547c239cf998f7ecd167a48ffbe4"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-18 05:16:06"
  condition:
    hash.sha256(0, filesize) == "3b43362bf668b610e5d543bcf8d98665298b547c239cf998f7ecd167a48ffbe4"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

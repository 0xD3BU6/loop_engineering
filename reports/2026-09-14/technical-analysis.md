# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-14

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 594 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 594 |
| Unique family labels | 9 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 41 |
| VShell | 30 |
| Mirai | 14 |
| Snowlight | 9 |
| RemusStealer | 2 |
| RemcosRAT | 1 |
| ValleyRAT | 1 |
| njrat | 1 |
| Vidar | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 40 |
| elf | 27 |
| unknown | 17 |
| sh | 8 |
| zip | 3 |
| js | 2 |
| macho | 1 |
| vbs | 1 |
| ps1 | 1 |

## Per-Sample Analysis

### Sample 1: `a13860e9645e1493`

| Field | Value |
|---|---|
| SHA-256 | `a13860e9645e1493d0dbe32f05ea675e907eff8444f255de0b7eb1b61506a97b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-14 05:05:03` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX8.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10a9779b40d1e8ebf958275ad25d3091` |
| SHA-1 | `a45529e1c80488f8bfe4e0326ae68cb9acedfa32` |
| SHA-256 | `a13860e9645e1493d0dbe32f05ea675e907eff8444f255de0b7eb1b61506a97b` |
| SHA3-384 | `6fc49bd4e18679e1b663283f6b994351a19f335783f1c239aa1ef6b9e5f14ef949b3dcc33023ac1ddee03098c4503f69` |
| IMPHASH | `2335fd0614148766d7ec181f0aaad422` |
| TLSH | `T11FB633ABFE055565E939C237A971D133C20F29FB06B24D35B429BD3077824280B9A7DB` |
| SSDEEP | `196608:dNSkGBwBzXm2xtrxrDsfZ+ltVW2o07BR63s4G8n/ClZl9hSIJ9YUrsdNix2937:dRGBwBTm+NxrDsfZ+l7D7BCG86blPJqT` |
| ICON-DHASH | `30b2b2f069f0d48a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_a13860e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a13860e9645e1493d0dbe32f05ea675e907eff8444f255de0b7eb1b61506a97b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-14 05:05:03"
  condition:
    hash.sha256(0, filesize) == "a13860e9645e1493d0dbe32f05ea675e907eff8444f255de0b7eb1b61506a97b"
}
```

### Sample 2: `8749dc2d450640cf`

| Field | Value |
|---|---|
| SHA-256 | `8749dc2d450640cfa6a935458073fef0d4a81d9b0abb29cd1638bdf1544f2c48` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-14 05:02:30` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b33bb22552479afe51eed7c80d9da03a` |
| SHA-1 | `14a98cc20230f63121d599c930abc3e04d02a882` |
| SHA-256 | `8749dc2d450640cfa6a935458073fef0d4a81d9b0abb29cd1638bdf1544f2c48` |
| SHA3-384 | `f9e37094b3cd1a49ee97b6262c3ae3318f51b951fc20d8ae9e3bf535ae6cdd91000ca93b9a0eb976599e4271a69fd42d` |
| TLSH | `T197236D651A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5A69DD10972D` |
| SSDEEP | `768:GXRWNGxVS9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ilxtcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_8749dc2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8749dc2d450640cfa6a935458073fef0d4a81d9b0abb29cd1638bdf1544f2c48"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-14 05:02:30"
  condition:
    hash.sha256(0, filesize) == "8749dc2d450640cfa6a935458073fef0d4a81d9b0abb29cd1638bdf1544f2c48"
}
```

### Sample 3: `3cb1feed97e63a55`

| Field | Value |
|---|---|
| SHA-256 | `3cb1feed97e63a55c639dad81b2e9051892420b4966fb661da24b0b6ad0bfdd3` |
| Family label | `unknown` |
| File name | `3cb1feed97e63a55c639dad81b2e9051892420b4966fb661da24b0b6ad0bfdd3.bin` |
| File type | `zip` |
| First seen | `2026-09-14 05:00:57` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1552d3d0c80e6038599ead02b55d638` |
| SHA-1 | `bb3fa28a2bd961ba485effbd4c88d27c54f0d1f5` |
| SHA-256 | `3cb1feed97e63a55c639dad81b2e9051892420b4966fb661da24b0b6ad0bfdd3` |
| SHA3-384 | `0cc646d80deead0ba321577a212f02ef32bbc9c6d7246cd30143aedafcca4e997e3fe4dd2deae0961c3e4637202809be` |
| TLSH | `T12B653365BF8CAB9BE545FF33286E536D27566EC6A0506DE91F83A4B0C24F7A10EC0143` |
| SSDEEP | `24576:QtKbItvIs16ZixuBWPAXz1fajz64g/pMDOcuaJw8YUZIHNTtWpEhULgZoYp:QtKbItwVHRSjzZCMKKJaO03WpEKEVp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_3cb1feed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cb1feed97e63a55c639dad81b2e9051892420b4966fb661da24b0b6ad0bfdd3"
    family = "unknown"
    file_name = "3cb1feed97e63a55c639dad81b2e9051892420b4966fb661da24b0b6ad0bfdd3.bin"
    file_type = "zip"
    first_seen = "2026-09-14 05:00:57"
  condition:
    hash.sha256(0, filesize) == "3cb1feed97e63a55c639dad81b2e9051892420b4966fb661da24b0b6ad0bfdd3"
}
```

### Sample 4: `1d5ecdcfec8f414b`

| Field | Value |
|---|---|
| SHA-256 | `1d5ecdcfec8f414b6d7ec5038a154baa88c3c3584949bf0fd3cef69022687859` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-14 04:54:05` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee831e2692b49ce5e1e4e436fba348b5` |
| SHA-256 | `1d5ecdcfec8f414b6d7ec5038a154baa88c3c3584949bf0fd3cef69022687859` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_1d5ecdcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d5ecdcfec8f414b6d7ec5038a154baa88c3c3584949bf0fd3cef69022687859"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-14 04:54:05"
  condition:
    hash.sha256(0, filesize) == "1d5ecdcfec8f414b6d7ec5038a154baa88c3c3584949bf0fd3cef69022687859"
}
```

### Sample 5: `c2c46e82c334da5c`

| Field | Value |
|---|---|
| SHA-256 | `c2c46e82c334da5c665ea02d5840dd70f138279d3a17572623b55f7430196ca4` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-14 04:44:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6aa749394fb2f8d0ff82228118944a5` |
| SHA-1 | `147c6c795ca4ef61d095e6e5d100d3cb045b4c7d` |
| SHA-256 | `c2c46e82c334da5c665ea02d5840dd70f138279d3a17572623b55f7430196ca4` |
| SHA3-384 | `13b3ee8d595af8884e7e5b45aaa3482d7b3d4cb68c36fbaae96d6f963c54cd4bff3979273635e4c223edf7438fef7812` |
| TLSH | `T152236C651A857C149E99C4371D7E2F0CB9AD43E6320452EE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:qVEJVIhtMG9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:QEJ2Mjcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_c2c46e82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2c46e82c334da5c665ea02d5840dd70f138279d3a17572623b55f7430196ca4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-14 04:44:56"
  condition:
    hash.sha256(0, filesize) == "c2c46e82c334da5c665ea02d5840dd70f138279d3a17572623b55f7430196ca4"
}
```

### Sample 6: `adba27615403539d`

| Field | Value |
|---|---|
| SHA-256 | `adba27615403539d9bde6f67a578237441e48076ea62d4e895f038a6c836d2d7` |
| Family label | `unknown` |
| File name | `stage1_script.txt` |
| File type | `unknown` |
| First seen | `2026-09-14 04:38:09` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, dropper, Foxveil, macOS, zsh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50c1ebba0f53b5db8da6170f665a37a6` |
| SHA-256 | `adba27615403539d9bde6f67a578237441e48076ea62d4e895f038a6c836d2d7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_adba2761
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adba27615403539d9bde6f67a578237441e48076ea62d4e895f038a6c836d2d7"
    family = "unknown"
    file_name = "stage1_script.txt"
    file_type = "unknown"
    first_seen = "2026-09-14 04:38:09"
  condition:
    hash.sha256(0, filesize) == "adba27615403539d9bde6f67a578237441e48076ea62d4e895f038a6c836d2d7"
}
```

### Sample 7: `204b5d236e4384b2`

| Field | Value |
|---|---|
| SHA-256 | `204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc` |
| Family label | `unknown` |
| File name | `macho_204b5d236e43.bin` |
| File type | `macho` |
| First seen | `2026-09-14 04:38:06` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f89411fe64c83e60a78a96a0d569bab` |
| SHA-256 | `204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_204b5d23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc"
    family = "unknown"
    file_name = "macho_204b5d236e43.bin"
    file_type = "macho"
    first_seen = "2026-09-14 04:38:06"
  condition:
    hash.sha256(0, filesize) == "204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc"
}
```

### Sample 8: `e71180c84e4b5fd0`

| Field | Value |
|---|---|
| SHA-256 | `e71180c84e4b5fd0f49090facc0ed59a9e76c1e1f79d6e880d0f1cfb44e40366` |
| Family label | `VShell` |
| File name | `e71180c84e4b5fd0f49090facc0ed59a9e76c1e1f79d6e880d0f1cfb44e40366.exe` |
| File type | `exe` |
| First seen | `2026-09-14 04:31:26` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59ffb55e1c0d995e1044de1e8e56fe62` |
| SHA-1 | `194d297176ccf34b43dbfaf43e084dd87d373b55` |
| SHA-256 | `e71180c84e4b5fd0f49090facc0ed59a9e76c1e1f79d6e880d0f1cfb44e40366` |
| SHA3-384 | `05d659a8289dd2e09763e6ea37446cc44858728921533946825e3bd936955260285eeaa7a21d5cb061e78fa1d5005c20` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1C0716188F3176EF5E43C8BF940D3A664D059ABB8C250BF4D5E60381D3C210BA255AF96` |
| SSDEEP | `48:6Icwm0Lt2WuJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4j2tcSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_008_e71180c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e71180c84e4b5fd0f49090facc0ed59a9e76c1e1f79d6e880d0f1cfb44e40366"
    family = "VShell"
    file_name = "e71180c84e4b5fd0f49090facc0ed59a9e76c1e1f79d6e880d0f1cfb44e40366.exe"
    file_type = "exe"
    first_seen = "2026-09-14 04:31:26"
  condition:
    hash.sha256(0, filesize) == "e71180c84e4b5fd0f49090facc0ed59a9e76c1e1f79d6e880d0f1cfb44e40366"
}
```

### Sample 9: `1e25bb36f94f904f`

| Field | Value |
|---|---|
| SHA-256 | `1e25bb36f94f904fd7c4a2d88752fa57c127a533276d0259b6f245386bbe3bd8` |
| Family label | `VShell` |
| File name | `1e25bb36f94f904fd7c4a2d88752fa57c127a533276d0259b6f245386bbe3bd8.exe` |
| File type | `exe` |
| First seen | `2026-09-14 04:31:23` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1b7bc886c6ecb8018aca9257edb9af8` |
| SHA-1 | `ff3ff8ddce01fd1877d4a65dc122dba036c2c59c` |
| SHA-256 | `1e25bb36f94f904fd7c4a2d88752fa57c127a533276d0259b6f245386bbe3bd8` |
| SHA3-384 | `444b4a35ef998ef002d5225dd24a6807e2d07bd859f14770140af0104ac04643acd1635811cda6d6f0341410ef93d386` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T14891A5C5F75BE6B6EC1C07F600A379A8C4A82E14927C9B574FE16F0C3C111AA3D2DA52` |
| SSDEEP | `48:6I7lwe7oB5M08SvJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1uO09xq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_009_1e25bb36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e25bb36f94f904fd7c4a2d88752fa57c127a533276d0259b6f245386bbe3bd8"
    family = "VShell"
    file_name = "1e25bb36f94f904fd7c4a2d88752fa57c127a533276d0259b6f245386bbe3bd8.exe"
    file_type = "exe"
    first_seen = "2026-09-14 04:31:23"
  condition:
    hash.sha256(0, filesize) == "1e25bb36f94f904fd7c4a2d88752fa57c127a533276d0259b6f245386bbe3bd8"
}
```

### Sample 10: `d42dd98e3d93614a`

| Field | Value |
|---|---|
| SHA-256 | `d42dd98e3d93614afd3343c080e890a4e59da42e10ab04d1eef0150d3bfba54b` |
| Family label | `Snowlight` |
| File name | `d42dd98e3d93614afd3343c080e890a4e59da42e10ab04d1eef0150d3bfba54b.elf` |
| File type | `elf` |
| First seen | `2026-09-14 04:31:20` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57c06ab4f96029f1ac6adcfa02e42ff5` |
| SHA-1 | `a6a82cb699012338569abf128a51c4a64871e44d` |
| SHA-256 | `d42dd98e3d93614afd3343c080e890a4e59da42e10ab04d1eef0150d3bfba54b` |
| SHA3-384 | `b20ca5ee90bda0c5b5a46c6f2bac288cb47541bd4b12483b8c84225b6741e3751f83ba9244eed3429de4e7ae4ac33946` |
| TLSH | `T151E17217E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3PJheuhi05Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcb/JhAaZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_010_d42dd98e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d42dd98e3d93614afd3343c080e890a4e59da42e10ab04d1eef0150d3bfba54b"
    family = "Snowlight"
    file_name = "d42dd98e3d93614afd3343c080e890a4e59da42e10ab04d1eef0150d3bfba54b.elf"
    file_type = "elf"
    first_seen = "2026-09-14 04:31:20"
  condition:
    hash.sha256(0, filesize) == "d42dd98e3d93614afd3343c080e890a4e59da42e10ab04d1eef0150d3bfba54b"
}
```

### Sample 11: `01ade49da5924459`

| Field | Value |
|---|---|
| SHA-256 | `01ade49da5924459befd34e293fa56b455eebc896374d259e744adc022acc5c2` |
| Family label | `VShell` |
| File name | `01ade49da5924459befd34e293fa56b455eebc896374d259e744adc022acc5c2.exe` |
| File type | `exe` |
| First seen | `2026-09-14 04:31:17` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5512a27aea25338e3f61128d8e35916` |
| SHA-1 | `b4dbf9a47138e97fc6c951ab06229b368775f48e` |
| SHA-256 | `01ade49da5924459befd34e293fa56b455eebc896374d259e744adc022acc5c2` |
| SHA3-384 | `f709b357554d6a749e643ef843f4dbe8cc3f44a38d031eed63feeb6b12d69fb79b084c9e1866a272cd4927865bc878f3` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T13571B54160541AF2D94CA3BF8487B895FD4EB248A2C80B0B0398D81A2F7507BB0D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DH8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DHG++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_011_01ade49d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01ade49da5924459befd34e293fa56b455eebc896374d259e744adc022acc5c2"
    family = "VShell"
    file_name = "01ade49da5924459befd34e293fa56b455eebc896374d259e744adc022acc5c2.exe"
    file_type = "exe"
    first_seen = "2026-09-14 04:31:17"
  condition:
    hash.sha256(0, filesize) == "01ade49da5924459befd34e293fa56b455eebc896374d259e744adc022acc5c2"
}
```

### Sample 12: `576c3b0717fdd274`

| Field | Value |
|---|---|
| SHA-256 | `576c3b0717fdd274e9edf38aa97d0ae40ddde8455c89782d79d4d4ebb67ecec7` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-14 04:07:06` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76c65be76596468d2511d44510cfebbf` |
| SHA-256 | `576c3b0717fdd274e9edf38aa97d0ae40ddde8455c89782d79d4d4ebb67ecec7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_576c3b07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "576c3b0717fdd274e9edf38aa97d0ae40ddde8455c89782d79d4d4ebb67ecec7"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-14 04:07:06"
  condition:
    hash.sha256(0, filesize) == "576c3b0717fdd274e9edf38aa97d0ae40ddde8455c89782d79d4d4ebb67ecec7"
}
```

### Sample 13: `933115a4ffd43027`

| Field | Value |
|---|---|
| SHA-256 | `933115a4ffd430275f259515fbeb6a5a7096fc5bf4906ee1b1bd44407c19a4af` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-14 04:04:19` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c56e80762df63fa1f79d83a9016988f5` |
| SHA-1 | `972b232ad0ed363ad6101ebfed9378497021c12b` |
| SHA-256 | `933115a4ffd430275f259515fbeb6a5a7096fc5bf4906ee1b1bd44407c19a4af` |
| SHA3-384 | `5aa06bfe029cf268450e7ca57694478b84cb69245574168227af4164c87c518cc60e4ef68b6b9efb5fb3a19b72499145` |
| TLSH | `T1CFC28D966A867C44BEC94A3E4CBD2B0D6DF5C3D1324D42AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:Zf8vCB+25j6es8RE9FYpMSUpi+20qUpi+20YQX:Zf8l25Jid2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_933115a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "933115a4ffd430275f259515fbeb6a5a7096fc5bf4906ee1b1bd44407c19a4af"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-14 04:04:19"
  condition:
    hash.sha256(0, filesize) == "933115a4ffd430275f259515fbeb6a5a7096fc5bf4906ee1b1bd44407c19a4af"
}
```

### Sample 14: `21a9c0f4749b6f33`

| Field | Value |
|---|---|
| SHA-256 | `21a9c0f4749b6f3338c32d321c3fcc7234782a855f1af9d4cc272aff1a5a1112` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-14 03:54:53` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8123734f08c12a79753504b5e15d56ad` |
| SHA-256 | `21a9c0f4749b6f3338c32d321c3fcc7234782a855f1af9d4cc272aff1a5a1112` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_21a9c0f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21a9c0f4749b6f3338c32d321c3fcc7234782a855f1af9d4cc272aff1a5a1112"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-14 03:54:53"
  condition:
    hash.sha256(0, filesize) == "21a9c0f4749b6f3338c32d321c3fcc7234782a855f1af9d4cc272aff1a5a1112"
}
```

### Sample 15: `bd2c0f97b36cb7de`

| Field | Value |
|---|---|
| SHA-256 | `bd2c0f97b36cb7deecd7039bef3ce34302355d0cc8ef57422d5ac5f81b739b36` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-14 03:53:52` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c56c7a09161a18b00c88205f7ccce106` |
| SHA-256 | `bd2c0f97b36cb7deecd7039bef3ce34302355d0cc8ef57422d5ac5f81b739b36` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_bd2c0f97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd2c0f97b36cb7deecd7039bef3ce34302355d0cc8ef57422d5ac5f81b739b36"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-14 03:53:52"
  condition:
    hash.sha256(0, filesize) == "bd2c0f97b36cb7deecd7039bef3ce34302355d0cc8ef57422d5ac5f81b739b36"
}
```

### Sample 16: `81591d89a7283bb1`

| Field | Value |
|---|---|
| SHA-256 | `81591d89a7283bb11e05ce80e00256bea9218acbfcec5542cd9ffda9bd18db8a` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-14 03:47:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5411fa5970b362c4f8de9d337ad0e0c2` |
| SHA-1 | `55d1c660585e53c3dff552ed6aea123f0ee9332c` |
| SHA-256 | `81591d89a7283bb11e05ce80e00256bea9218acbfcec5542cd9ffda9bd18db8a` |
| SHA3-384 | `e76d172e98968ca6cb100951e11e81758048031cb5bdd6c080601066d1b4a394d9dc128e9a091e731d9978da475c569a` |
| TLSH | `T1A5C28E966A867C44BEC98B3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11F9CD618B1A` |
| SSDEEP | `768:X8vCB+25j6es8RGcH9FYpMSUpi+20qUpi+20YQX:X8l25JPhd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_81591d89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81591d89a7283bb11e05ce80e00256bea9218acbfcec5542cd9ffda9bd18db8a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-14 03:47:38"
  condition:
    hash.sha256(0, filesize) == "81591d89a7283bb11e05ce80e00256bea9218acbfcec5542cd9ffda9bd18db8a"
}
```

### Sample 17: `3f4545a5f15fe892`

| Field | Value |
|---|---|
| SHA-256 | `3f4545a5f15fe892f21df9ee911af2ed27a8e0fff9084c6b32b5056d9d18c187` |
| Family label | `RemusStealer` |
| File name | `C2C63147E280ABE9FDE6EFA535C13CE5.exe` |
| File type | `exe` |
| First seen | `2026-09-14 03:20:15` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2c63147e280abe9fde6efa535c13ce5` |
| SHA-1 | `48afa75dc0e75d72c086714b7cbde68076a09325` |
| SHA-256 | `3f4545a5f15fe892f21df9ee911af2ed27a8e0fff9084c6b32b5056d9d18c187` |
| SHA3-384 | `3b7af796511a8183900f3e1afa5e7c6d7d00dfe77dbe75760be0b9da9b971dc028c2ec6f0e516dcb1183c142484aa450` |
| IMPHASH | `96ab939b3b55d317ed1968d099ccc72c` |
| TLSH | `T175152209DB4758FAEE7299309AABF37F952C5C419CAA6E47DF4007339C23532C026B59` |
| SSDEEP | `12288:d0pbmpaFAf5PgnhYrFvtyxndd2X1kcHFdr7viV5xeq5q7C5/jI3Cgl7hLQI94Z9u:gqpyAeeFFyIquTL85wq5WC0CWhLoRZlk` |
| ICON-DHASH | `000288c366bc5922` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_017_3f4545a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f4545a5f15fe892f21df9ee911af2ed27a8e0fff9084c6b32b5056d9d18c187"
    family = "RemusStealer"
    file_name = "C2C63147E280ABE9FDE6EFA535C13CE5.exe"
    file_type = "exe"
    first_seen = "2026-09-14 03:20:15"
  condition:
    hash.sha256(0, filesize) == "3f4545a5f15fe892f21df9ee911af2ed27a8e0fff9084c6b32b5056d9d18c187"
}
```

### Sample 18: `e51ee5140bead9c9`

| Field | Value |
|---|---|
| SHA-256 | `e51ee5140bead9c974f22988b80899cc2d10ab9efe6301853f2babe552c330f3` |
| Family label | `RemcosRAT` |
| File name | `Phyllosoma.vbs` |
| File type | `vbs` |
| First seen | `2026-09-14 03:11:48` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3d781b345281e22a0b20a614e324f6e` |
| SHA-1 | `95d8bab53721ed6f46f6bb1615e6262e6783889a` |
| SHA-256 | `e51ee5140bead9c974f22988b80899cc2d10ab9efe6301853f2babe552c330f3` |
| SHA3-384 | `6f1eac43948e6a0184462a1a1413755afae1612f442d919a18edb84ee2e7a97110e9f8b557324416538a23cfa44b9890` |
| TLSH | `T1F5535C25DE941B160F8B27ABFC451A62C9BC8515452304F4FEEC734D610FAACB3BD22A` |
| SSDEEP | `1536:ToscEILBtFSUkV2ThTklHU5hWa4BnUan3pY9:ToscJvkAhTwHDa4JDn5+` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_018_e51ee514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e51ee5140bead9c974f22988b80899cc2d10ab9efe6301853f2babe552c330f3"
    family = "RemcosRAT"
    file_name = "Phyllosoma.vbs"
    file_type = "vbs"
    first_seen = "2026-09-14 03:11:48"
  condition:
    hash.sha256(0, filesize) == "e51ee5140bead9c974f22988b80899cc2d10ab9efe6301853f2babe552c330f3"
}
```

### Sample 19: `a2718a829cf311f7`

| Field | Value |
|---|---|
| SHA-256 | `a2718a829cf311f77dc8d9fdbd50246921b7783c8192827e79e007acf96ea6ca` |
| Family label | `unknown` |
| File name | `a2718a829cf311f77dc8d9fdbd50246921b7783c8192827e79e007acf96ea6ca` |
| File type | `elf` |
| First seen | `2026-09-14 03:08:18` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f063a9d3c6c29935c10ee62824c0c7bf` |
| SHA-1 | `e830f44ee4c9bae6544829beffdb5dd37bb8542a` |
| SHA-256 | `a2718a829cf311f77dc8d9fdbd50246921b7783c8192827e79e007acf96ea6ca` |
| SHA3-384 | `6bc65c587a723c5d5a79402e1b12205f0d8a5ec7f53b24c5219a8298f0493da4f71ab3ba012a9b4956ccefd9653db730` |
| TLSH | `T12967CF7792067CE9E9B94DB4C41015816DA87C874778A3C7BAC8B1E666FB2D08D3E730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQe:cqYUQuVDt0TZEAoB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_a2718a82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2718a829cf311f77dc8d9fdbd50246921b7783c8192827e79e007acf96ea6ca"
    family = "unknown"
    file_name = "a2718a829cf311f77dc8d9fdbd50246921b7783c8192827e79e007acf96ea6ca"
    file_type = "elf"
    first_seen = "2026-09-14 03:08:18"
  condition:
    hash.sha256(0, filesize) == "a2718a829cf311f77dc8d9fdbd50246921b7783c8192827e79e007acf96ea6ca"
}
```

### Sample 20: `604495eeedb9f412`

| Field | Value |
|---|---|
| SHA-256 | `604495eeedb9f4124706a35b0907213716f43af17e7662e15e8c15eb41c13c46` |
| Family label | `unknown` |
| File name | `FedEx_AWB_456789.js` |
| File type | `js` |
| First seen | `2026-09-14 02:57:08` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `002df6d51a82df7b95da78c2f732b9cc` |
| SHA-1 | `de43627973542f85f423cd10fdda4c466187d8a9` |
| SHA-256 | `604495eeedb9f4124706a35b0907213716f43af17e7662e15e8c15eb41c13c46` |
| SHA3-384 | `bb415181a5fa1df4f918c7d9606faed43f55bc87db95484104c6587e75226939df2ece5191c8d8e335e9fa489a65b2b7` |
| TLSH | `T150276CC94137F709D80E28F4AB753D8E6F8FD8BD597494E252B4DC2B1F2585AA386308` |
| SSDEEP | `3072:62KcXON25Ll5lt/ENPzlLG1mX/dc73fOa2t212N2+Y+Q2MQyeyn1vfWg0giFj6X+:0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_604495ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "604495eeedb9f4124706a35b0907213716f43af17e7662e15e8c15eb41c13c46"
    family = "unknown"
    file_name = "FedEx_AWB_456789.js"
    file_type = "js"
    first_seen = "2026-09-14 02:57:08"
  condition:
    hash.sha256(0, filesize) == "604495eeedb9f4124706a35b0907213716f43af17e7662e15e8c15eb41c13c46"
}
```

### Sample 21: `07a7afd2a891cbd8`

| Field | Value |
|---|---|
| SHA-256 | `07a7afd2a891cbd8b1600d0327a6832d596b655011b9fc79265c7e068bc8fc85` |
| Family label | `VShell` |
| File name | `07a7afd2a891cbd8b1600d0327a6832d596b655011b9fc79265c7e068bc8fc85.exe` |
| File type | `exe` |
| First seen | `2026-09-14 02:47:20` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba345a7feefcb0de8776f41d0aa7f4fd` |
| SHA-1 | `0a811f358968d6e038222453c9398e1d9e44cd32` |
| SHA-256 | `07a7afd2a891cbd8b1600d0327a6832d596b655011b9fc79265c7e068bc8fc85` |
| SHA3-384 | `7d7c5bacf38204f67b8d01ef85ab17fa840ad63006907671067ea51c7885ee569290424f2244b2ef19ffe02ecda4f7fe` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1759194C5F75BE6B2EC1C07F500A379A4C4682E18826C9B464FA16F1C3C111AA3D6DA52` |
| SSDEEP | `48:6I7lwe7ADwf08SEJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1L092q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_021_07a7afd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07a7afd2a891cbd8b1600d0327a6832d596b655011b9fc79265c7e068bc8fc85"
    family = "VShell"
    file_name = "07a7afd2a891cbd8b1600d0327a6832d596b655011b9fc79265c7e068bc8fc85.exe"
    file_type = "exe"
    first_seen = "2026-09-14 02:47:20"
  condition:
    hash.sha256(0, filesize) == "07a7afd2a891cbd8b1600d0327a6832d596b655011b9fc79265c7e068bc8fc85"
}
```

### Sample 22: `2921c54b7d2c0a8a`

| Field | Value |
|---|---|
| SHA-256 | `2921c54b7d2c0a8a9dd0789cce72cdc55e58366d1fa064d44c059a2cb87d5657` |
| Family label | `VShell` |
| File name | `2921c54b7d2c0a8a9dd0789cce72cdc55e58366d1fa064d44c059a2cb87d5657.exe` |
| File type | `exe` |
| First seen | `2026-09-14 02:47:16` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8f92e3d3e2e5285aa93b1ccaf9f4788` |
| SHA-1 | `f0f39896309354b60e94b1aaf424bc81e45eb06d` |
| SHA-256 | `2921c54b7d2c0a8a9dd0789cce72cdc55e58366d1fa064d44c059a2cb87d5657` |
| SHA3-384 | `cf12c73fb7b5d85d3c36bb004caf339e6fd420a729b900cfc3bd5b8524471e9353357c6917e65905537038f6f4830f1f` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1A191E74170B989E7E85D81BB4C0FB8A0B919740A41C483A70378A5953F39A7FF0BCB0E` |
| SSDEEP | `48:6IIF9BlQaexogZH7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMJM0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_022_2921c54b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2921c54b7d2c0a8a9dd0789cce72cdc55e58366d1fa064d44c059a2cb87d5657"
    family = "VShell"
    file_name = "2921c54b7d2c0a8a9dd0789cce72cdc55e58366d1fa064d44c059a2cb87d5657.exe"
    file_type = "exe"
    first_seen = "2026-09-14 02:47:16"
  condition:
    hash.sha256(0, filesize) == "2921c54b7d2c0a8a9dd0789cce72cdc55e58366d1fa064d44c059a2cb87d5657"
}
```

### Sample 23: `86b9ddeb528f6f64`

| Field | Value |
|---|---|
| SHA-256 | `86b9ddeb528f6f6452d5b6eb209055f6c0378b5a2c2217e257209395e1d3a09a` |
| Family label | `Snowlight` |
| File name | `86b9ddeb528f6f6452d5b6eb209055f6c0378b5a2c2217e257209395e1d3a09a.elf` |
| File type | `elf` |
| First seen | `2026-09-14 02:44:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8959ece56fb657fe76c8060a287d483e` |
| SHA-1 | `3db6a639ffaf72a70d2c2f46356709682dcd80af` |
| SHA-256 | `86b9ddeb528f6f6452d5b6eb209055f6c0378b5a2c2217e257209395e1d3a09a` |
| SHA3-384 | `b84cdb972886bb88bc9c6a9a1df212d703fbc06dc8e3ee9ca84c74c95e8131d62f9d89cb1a92b4d9ad9bb62d1a993880` |
| TLSH | `T194E17117E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw38Jheuhi/5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbMJhARZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_023_86b9ddeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86b9ddeb528f6f6452d5b6eb209055f6c0378b5a2c2217e257209395e1d3a09a"
    family = "Snowlight"
    file_name = "86b9ddeb528f6f6452d5b6eb209055f6c0378b5a2c2217e257209395e1d3a09a.elf"
    file_type = "elf"
    first_seen = "2026-09-14 02:44:04"
  condition:
    hash.sha256(0, filesize) == "86b9ddeb528f6f6452d5b6eb209055f6c0378b5a2c2217e257209395e1d3a09a"
}
```

### Sample 24: `9924976d221c0003`

| Field | Value |
|---|---|
| SHA-256 | `9924976d221c0003bee515bf23bdfdd003fdc3be04d827588b2bcdac5c034ead` |
| Family label | `Snowlight` |
| File name | `9924976d221c0003bee515bf23bdfdd003fdc3be04d827588b2bcdac5c034ead.elf` |
| File type | `elf` |
| First seen | `2026-09-14 02:44:01` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b67d2d139b757bb034d118aed17a7e1` |
| SHA-1 | `60a1250fbae994816bca9960de274fea3efcda7d` |
| SHA-256 | `9924976d221c0003bee515bf23bdfdd003fdc3be04d827588b2bcdac5c034ead` |
| SHA3-384 | `b51c898072ca2008b53a4b0bf2be5015290307ca451bd9cc7796a49fa206ec4f7b5d316200f238e58988d1cda491bbc9` |
| TLSH | `T1C4123047A2D0CE3FC8D953384467122472B794BEDF629713064925B53F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6dH5ML09V1J9G8Ymt+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHaZMWT1YmAhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_024_9924976d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9924976d221c0003bee515bf23bdfdd003fdc3be04d827588b2bcdac5c034ead"
    family = "Snowlight"
    file_name = "9924976d221c0003bee515bf23bdfdd003fdc3be04d827588b2bcdac5c034ead.elf"
    file_type = "elf"
    first_seen = "2026-09-14 02:44:01"
  condition:
    hash.sha256(0, filesize) == "9924976d221c0003bee515bf23bdfdd003fdc3be04d827588b2bcdac5c034ead"
}
```

### Sample 25: `8bff2ade47175af1`

| Field | Value |
|---|---|
| SHA-256 | `8bff2ade47175af18f41e33559a6bb4f46295e3e780f4c92b2a765da5604e7a5` |
| Family label | `VShell` |
| File name | `8bff2ade47175af18f41e33559a6bb4f46295e3e780f4c92b2a765da5604e7a5.exe` |
| File type | `exe` |
| First seen | `2026-09-14 02:43:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fded524b169474de18e6614c05e5b435` |
| SHA-1 | `2c04860697186f2da3d64fdd946a3831b2e88cf2` |
| SHA-256 | `8bff2ade47175af18f41e33559a6bb4f46295e3e780f4c92b2a765da5604e7a5` |
| SHA3-384 | `1e01eb98c63191e1d103e9e948ce8cc1a060748521581a663109737b24e046d1f4e58050c0b7a4983bda2d976edc6cf9` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T161716188F3135EF5E43C8BF900D3A614D4199BB8C250BF8D5E60381D3C214BA269AF97` |
| SSDEEP | `48:6Icwm0ht2WVJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jQtnSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_025_8bff2ade
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bff2ade47175af18f41e33559a6bb4f46295e3e780f4c92b2a765da5604e7a5"
    family = "VShell"
    file_name = "8bff2ade47175af18f41e33559a6bb4f46295e3e780f4c92b2a765da5604e7a5.exe"
    file_type = "exe"
    first_seen = "2026-09-14 02:43:58"
  condition:
    hash.sha256(0, filesize) == "8bff2ade47175af18f41e33559a6bb4f46295e3e780f4c92b2a765da5604e7a5"
}
```

### Sample 26: `bb66063453efe9e9`

| Field | Value |
|---|---|
| SHA-256 | `bb66063453efe9e93235121be7bbdbf8b38cbeae66c6163b8e2c101e9689e843` |
| Family label | `Mirai` |
| File name | `bb66063453efe9e93235121be7bbdbf8b38cbeae66c6163b8e2c101e9689e843.elf` |
| File type | `elf` |
| First seen | `2026-09-14 02:43:56` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3488e71fcaaf830f678e1ddb6978954` |
| SHA-1 | `0ea690ca5eda04b49cf69a4ccc26b5cba91671bf` |
| SHA-256 | `bb66063453efe9e93235121be7bbdbf8b38cbeae66c6163b8e2c101e9689e843` |
| SHA3-384 | `c9555a341ad329f260d6498916b675e6800c9004e23ed6cb646c1c1eb602c34d832ea003c514b3edc597fc09d92fb955` |
| TLSH | `T1C7E15207E2D5CE72D8CD133846935749213AC86EAB83EF03650C5999EE43BDC7A63752` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccF9146Gwz7cSym4S2ofahbpZiQ:fsue7c8JxFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_bb660634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb66063453efe9e93235121be7bbdbf8b38cbeae66c6163b8e2c101e9689e843"
    family = "Mirai"
    file_name = "bb66063453efe9e93235121be7bbdbf8b38cbeae66c6163b8e2c101e9689e843.elf"
    file_type = "elf"
    first_seen = "2026-09-14 02:43:56"
  condition:
    hash.sha256(0, filesize) == "bb66063453efe9e93235121be7bbdbf8b38cbeae66c6163b8e2c101e9689e843"
}
```

### Sample 27: `a0be1c01913ee53e`

| Field | Value |
|---|---|
| SHA-256 | `a0be1c01913ee53e6ea5fe2af57aec9024c5a02573e78b87ee10a8222f464b3f` |
| Family label | `Mirai` |
| File name | `a0be1c01913ee53e6ea5fe2af57aec9024c5a02573e78b87ee10a8222f464b3f.elf` |
| File type | `elf` |
| First seen | `2026-09-14 02:43:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a02db9970b1ad68467573f11fc514ee` |
| SHA-1 | `914e9a2b1e409a2222d0373c01d6f71619a6ba79` |
| SHA-256 | `a0be1c01913ee53e6ea5fe2af57aec9024c5a02573e78b87ee10a8222f464b3f` |
| SHA3-384 | `d82cbdedeeda11e8adab87c758a26cc84462e548e8490d20d2f4c58a38f50025a0edb8155a3a2ba3c46844a5b1fe7b2d` |
| TLSH | `T1FF124047A2D1CE7BC8EC13384467122472BBD47ADFA29713050C65B66E923D81E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5jlTTej6TNJ9ViNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTjTTfTpVOdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_a0be1c01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0be1c01913ee53e6ea5fe2af57aec9024c5a02573e78b87ee10a8222f464b3f"
    family = "Mirai"
    file_name = "a0be1c01913ee53e6ea5fe2af57aec9024c5a02573e78b87ee10a8222f464b3f.elf"
    file_type = "elf"
    first_seen = "2026-09-14 02:43:08"
  condition:
    hash.sha256(0, filesize) == "a0be1c01913ee53e6ea5fe2af57aec9024c5a02573e78b87ee10a8222f464b3f"
}
```

### Sample 28: `08f2c963906b126c`

| Field | Value |
|---|---|
| SHA-256 | `08f2c963906b126c0a10b47aa28eccebf8e209f3885c54489f771e948dc89b1a` |
| Family label | `ValleyRAT` |
| File name | `2df08b445585f5db43736868b4bc8428.exe` |
| File type | `exe` |
| First seen | `2026-09-14 02:15:12` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2df08b445585f5db43736868b4bc8428` |
| SHA-1 | `053f9c64a94448d467f0ca20e0ee5346c2f7a308` |
| SHA-256 | `08f2c963906b126c0a10b47aa28eccebf8e209f3885c54489f771e948dc89b1a` |
| SHA3-384 | `6f7686f663fa9ff695c83f52f2ab073ddd4ad6591635b4ca1a148545179c7c4d8d2afbfe1c21a37a40eeae89f363243a` |
| IMPHASH | `1fdaeb54e1a420b9565bb2d23869778b` |
| TLSH | `T1E655123136D0C0B3D147227884F1CBB29EAABCB2076549DB67D02B7B1F745D29B7825A` |
| SSDEEP | `12288:/QKreuMBX0bLaL0DudXezE09Si/ckGHt6pshsPSGkYl2XIQCb+Lk1TWbPXQnAN5L:/hQULZgXe4i7ojhsP5Lgrk1TWb4AN5` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_028_08f2c963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08f2c963906b126c0a10b47aa28eccebf8e209f3885c54489f771e948dc89b1a"
    family = "ValleyRAT"
    file_name = "2df08b445585f5db43736868b4bc8428.exe"
    file_type = "exe"
    first_seen = "2026-09-14 02:15:12"
  condition:
    hash.sha256(0, filesize) == "08f2c963906b126c0a10b47aa28eccebf8e209f3885c54489f771e948dc89b1a"
}
```

### Sample 29: `5ca5ff4d4e479a7e`

| Field | Value |
|---|---|
| SHA-256 | `5ca5ff4d4e479a7e6069b77df839af9d5d4fc2bbd26fcddb99dd27307f045f3e` |
| Family label | `Mirai` |
| File name | `5ca5ff4d4e479a7e6069b77df839af9d5d4fc2bbd26fcddb99dd27307f045f3e` |
| File type | `elf` |
| First seen | `2026-09-14 02:09:26` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfa99128b0e7c7fd7fda58db532f7079` |
| SHA-1 | `01d62480b47de60f43455ef5ad050c47a453a64a` |
| SHA-256 | `5ca5ff4d4e479a7e6069b77df839af9d5d4fc2bbd26fcddb99dd27307f045f3e` |
| SHA3-384 | `5671b415990fd509fc29b8c70bb90ad26f84ee31e711495f057cad9f6b20ef60bab2ad8532a3392580266359d9fc461a` |
| TLSH | `T196D37C07B5C264BDC482C8300B5F9513EA36746D8733676B6B80A6753D93F681F3DAA2` |
| TELFHASH | `t1b6f08404bc7d9b5a0ae25974ac5e1792a083a53610229f28ff20ebd4583f048e208d4e` |
| SSDEEP | `3072:W35f3/2GAMoDI1PNcnY14C5nLKPklEsMvb0s56qZWAW9R:WJvloCIsLVTMz5suWA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_5ca5ff4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ca5ff4d4e479a7e6069b77df839af9d5d4fc2bbd26fcddb99dd27307f045f3e"
    family = "Mirai"
    file_name = "5ca5ff4d4e479a7e6069b77df839af9d5d4fc2bbd26fcddb99dd27307f045f3e"
    file_type = "elf"
    first_seen = "2026-09-14 02:09:26"
  condition:
    hash.sha256(0, filesize) == "5ca5ff4d4e479a7e6069b77df839af9d5d4fc2bbd26fcddb99dd27307f045f3e"
}
```

### Sample 30: `3f4cf59841168607`

| Field | Value |
|---|---|
| SHA-256 | `3f4cf598411686071c8d89cbc0e20aab908543887207ac2e8ace4664d0da78fb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-14 02:06:12` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `452c133b1daee499382e42a9cc7d9231` |
| SHA-256 | `3f4cf598411686071c8d89cbc0e20aab908543887207ac2e8ace4664d0da78fb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_3f4cf598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f4cf598411686071c8d89cbc0e20aab908543887207ac2e8ace4664d0da78fb"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-14 02:06:12"
  condition:
    hash.sha256(0, filesize) == "3f4cf598411686071c8d89cbc0e20aab908543887207ac2e8ace4664d0da78fb"
}
```

### Sample 31: `d7d42055585aaf60`

| Field | Value |
|---|---|
| SHA-256 | `d7d42055585aaf602b8a00d8d62afe4150da70b6063d6b1e671cd39845d0b5ab` |
| Family label | `njrat` |
| File name | `284ad6b6c0c24e56c56b681f4492a1e3.exe` |
| File type | `exe` |
| First seen | `2026-09-14 00:50:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `284ad6b6c0c24e56c56b681f4492a1e3` |
| SHA-1 | `34d8054a787dea343e82e3794d8e1c95bbf66190` |
| SHA-256 | `d7d42055585aaf602b8a00d8d62afe4150da70b6063d6b1e671cd39845d0b5ab` |
| SHA3-384 | `508613f1816e737c74645779209b93f441a917a2e18f3c6f571b69119449935c25b5806cfcccba30b42267ee540c8e20` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T166E2F94A7EA58851C87C06B08B7596D403B0E187C41EDF2B8CC561DB6BF3AF91D48AF9` |
| SSDEEP | `384:f8aZYC9twBNdcvFaly2H0dbJo6HghcASEJqc/ZmRvR6JZlbw8hqIusZzZpKTyFL1:TY+sNKqNHnSdRpcnurTyFR` |
| ICON-DHASH | `01cccc969696d400` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_031_d7d42055
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7d42055585aaf602b8a00d8d62afe4150da70b6063d6b1e671cd39845d0b5ab"
    family = "njrat"
    file_name = "284ad6b6c0c24e56c56b681f4492a1e3.exe"
    file_type = "exe"
    first_seen = "2026-09-14 00:50:07"
  condition:
    hash.sha256(0, filesize) == "d7d42055585aaf602b8a00d8d62afe4150da70b6063d6b1e671cd39845d0b5ab"
}
```

### Sample 32: `ae372be0ba4977a6`

| Field | Value |
|---|---|
| SHA-256 | `ae372be0ba4977a6b72832e32a79663196ab90a1d0398c804502b4cd9e32109a` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-14 00:29:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b17a4b16ce5f983562114afe7a8194cc` |
| SHA-1 | `646ec1c98396f191f950d03f4737b24db02cd2e2` |
| SHA-256 | `ae372be0ba4977a6b72832e32a79663196ab90a1d0398c804502b4cd9e32109a` |
| SHA3-384 | `9ffda5092609cfb02a4ad815ca9a8b3026a1d4ddd8ca51a1de2fe1cbf00bc05c09bfef68cc8671bfdd5b64bdfab3169d` |
| TLSH | `T16223174AFD805F00D9E525BAFE1E524933934B7CE3FE7111AE215B2523C6A2B0F76912` |
| TELFHASH | `t18cf09e104a856cedf3d2190ad38e76439912aaea3f746c8633ebbc075337f82053029d` |
| SSDEEP | `1536:pVnsySSbuDyyyyyyyyoPo6/8GmdUiH2lXEi7g1CFnih:nS8h/8GmdYxg1CFi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_ae372be0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae372be0ba4977a6b72832e32a79663196ab90a1d0398c804502b4cd9e32109a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-14 00:29:18"
  condition:
    hash.sha256(0, filesize) == "ae372be0ba4977a6b72832e32a79663196ab90a1d0398c804502b4cd9e32109a"
}
```

### Sample 33: `0a7daa19d18fd62c`

| Field | Value |
|---|---|
| SHA-256 | `0a7daa19d18fd62cabf0529e84f7eb126f8b1060313cbe11279e19087705ad20` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-14 00:28:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0619ea92183c0295e38c50812013d42d` |
| SHA-1 | `f4c65cf758cfe5e833fbe3d02e38a4d1ac8f7e56` |
| SHA-256 | `0a7daa19d18fd62cabf0529e84f7eb126f8b1060313cbe11279e19087705ad20` |
| SHA3-384 | `e01acbe1f907bee4a37cab9f4eed55c26691a4465d54dba5d7575109c9177a8b6b1dc4e9ee6ea3a1fba876e9bbaed8c1` |
| TLSH | `T17BB2D062E7853CD2C6F1257AECEC0D43BB175BF8D0AE71602685AB1525E61432AFE903` |
| SSDEEP | `768:RUGq2dCZcop8f41VQ4FQhsQOwWIVAZaUD/3Uf/:bdCZcn41NKhsFGVLr/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_0a7daa19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a7daa19d18fd62cabf0529e84f7eb126f8b1060313cbe11279e19087705ad20"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-14 00:28:57"
  condition:
    hash.sha256(0, filesize) == "0a7daa19d18fd62cabf0529e84f7eb126f8b1060313cbe11279e19087705ad20"
}
```

### Sample 34: `4ba17752a7fa6fb2`

| Field | Value |
|---|---|
| SHA-256 | `4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-09-14 00:28:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `905ca98775cb833bc54c4c69e9313ca4` |
| SHA-1 | `849176c24e9c9ed95150412a80b7fd18f7f1e24a` |
| SHA-256 | `4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718` |
| SHA3-384 | `0fd45c0a0ffc82e6644776cbc46c8978a44802e753be086ebf2b878a71b4c6a73fc05908449d2e1506b2b33639dcd340` |
| TLSH | `T154B21B84E547E0F1F41B46B880A6E73EDB30E52A6554D91BFF70977EEA13E11830B20A` |
| TELFHASH | `t1b2f0c2e1be7604f5fbcafd5ca71e2a03eb366da20b2164b980f623117ed3201c072015` |
| SSDEEP | `384:fCaiJsgpQn9ITTIDvqx2aeOkUYs883SlGlwDryUhpeLza0pqq7ukzAE:CY9Iyvw2HwYsHvGD2UhpQa0pqqKOAE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_4ba17752
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-14 00:28:23"
  condition:
    hash.sha256(0, filesize) == "4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718"
}
```

### Sample 35: `9cce9b23ed561bb6`

| Field | Value |
|---|---|
| SHA-256 | `9cce9b23ed561bb603f4be736d7d280b0f0660c7aacca33281dd105b4c3bc166` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-14 00:27:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c60c4e3b440722e963303121ad6a1ab` |
| SHA-1 | `ae0b3d7e75dee2c3ab199fcf2f5d11d7e4e21a63` |
| SHA-256 | `9cce9b23ed561bb603f4be736d7d280b0f0660c7aacca33281dd105b4c3bc166` |
| SHA3-384 | `7a8b1a83c27ad31ba62c782f5e1b7a21818d587e68fb2b84f1c563a78b825f27485faeb43d00aee4844b28702130439d` |
| TLSH | `T1BBE31985FC509F26C6D225BBFB5E428D772A1768D3FE720399255F20378A85B0E37242` |
| TELFHASH | `t128e06841db5c06ec26d80894d4ac4966b1fd795d2f100467aa9c7cdf63a06b1fc3c85b` |
| SSDEEP | `3072:isvdrzSCTFf2Fx2Apj6NNbZgAsLhxrppOG:5vdrHeH2Ap2NNbZBsLhxNpOG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_9cce9b23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cce9b23ed561bb603f4be736d7d280b0f0660c7aacca33281dd105b4c3bc166"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-14 00:27:58"
  condition:
    hash.sha256(0, filesize) == "9cce9b23ed561bb603f4be736d7d280b0f0660c7aacca33281dd105b4c3bc166"
}
```

### Sample 36: `5e89cb6636cce0d5`

| Field | Value |
|---|---|
| SHA-256 | `5e89cb6636cce0d51af8ad82990ab860652459312c0456684346b7004dda38ef` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-09-14 00:27:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c6b8057dd1fdfea17bb3803074df160` |
| SHA-1 | `7443a54804fea6432bbfbc552ddef812ea4210dd` |
| SHA-256 | `5e89cb6636cce0d51af8ad82990ab860652459312c0456684346b7004dda38ef` |
| SHA3-384 | `913124701727c0ec58345c127cc3ac4f707d2d04a504cbf4821ea185992d84f85368a6be1b4b0201b5ca502a3aa84ff8` |
| TLSH | `T160A37E47F3854F63C225A1744EE34A2DBEE92AC346E68493E3796E1013B65E07C1DEC9` |
| TELFHASH | `t141110e309b29a1145d82dea8c8ed5b65652ec9521615ef33dd31c18c641a0eee31fc8f` |
| SSDEEP | `3072:dQzkxpduIqC8YFt/8rUJ5MRw1qgAU9iF2Mw+UjJ6:i4xLJqChCUJqwunW+a` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_5e89cb66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e89cb6636cce0d51af8ad82990ab860652459312c0456684346b7004dda38ef"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-09-14 00:27:57"
  condition:
    hash.sha256(0, filesize) == "5e89cb6636cce0d51af8ad82990ab860652459312c0456684346b7004dda38ef"
}
```

### Sample 37: `6df8cea94aa168c7`

| Field | Value |
|---|---|
| SHA-256 | `6df8cea94aa168c770b87e09590a1ddc9736bf25f6f8f13287d6581a3088fb58` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-09-14 00:27:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcc4438ba59845701fd330588c7a8e5a` |
| SHA-1 | `fce32e938cec8ee4da4fcbde28a98bc07f619b76` |
| SHA-256 | `6df8cea94aa168c770b87e09590a1ddc9736bf25f6f8f13287d6581a3088fb58` |
| SHA3-384 | `159dddbc33593b1c0e46d847710d16fc7513c0d80acd24159f24738a9998751e0982e7acbb9e2771277a635bbb2f63f9` |
| TLSH | `T15D72CF92C0AB1E59C1BE5131757E3E9A1C99921C778AC19BB6C038329512F683DFCFC2` |
| SSDEEP | `384:MNQyj4nscax9eF4YMn5z+BmxOMuANaNJawcudoD7UqkX0qWT+ImN:yQy0BagIz+PnbcuyD7UB8o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_6df8cea9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6df8cea94aa168c770b87e09590a1ddc9736bf25f6f8f13287d6581a3088fb58"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-14 00:27:56"
  condition:
    hash.sha256(0, filesize) == "6df8cea94aa168c770b87e09590a1ddc9736bf25f6f8f13287d6581a3088fb58"
}
```

### Sample 38: `1be5de7ba4ca6634`

| Field | Value |
|---|---|
| SHA-256 | `1be5de7ba4ca6634b97708a6aeaff3879cbba37a706a2e9618ae97332556e834` |
| Family label | `unknown` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-09-14 00:27:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d2cda8d6b822eafda1929feacde6292` |
| SHA-1 | `e5f85c4fd05ea99bb407be3d9011691523b485d0` |
| SHA-256 | `1be5de7ba4ca6634b97708a6aeaff3879cbba37a706a2e9618ae97332556e834` |
| SHA3-384 | `90967b9cd451cecc3a1b5ac37bc9bbde64c6d9a80e8eb9fd21a357f2f7e7cc2de77844dff1b0a716c3e7f5aee4accb83` |
| TLSH | `T1D0D21B3AEAB24913C4D459B855F3832DB9FA425FA4794B193C6B0EC4EF91B806113FE4` |
| SSDEEP | `384:+wc6EyZ69i0JYqOxoUv6D07hYvjMX6YtFU+pphcZ6Qay:Dc6ECn4OxoizcOTO+KZ6Jy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_1be5de7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1be5de7ba4ca6634b97708a6aeaff3879cbba37a706a2e9618ae97332556e834"
    family = "unknown"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-14 00:27:54"
  condition:
    hash.sha256(0, filesize) == "1be5de7ba4ca6634b97708a6aeaff3879cbba37a706a2e9618ae97332556e834"
}
```

### Sample 39: `e78d873a275cb56a`

| Field | Value |
|---|---|
| SHA-256 | `e78d873a275cb56ace7042e6bb1c734d84545a08baf4f789712fba37280267e3` |
| Family label | `unknown` |
| File name | `MV CHRYSANTHI S_VESSEL_DESCRIPTION.js` |
| File type | `js` |
| First seen | `2026-09-14 00:17:41` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16c1fd7f1586fd61c657e51d34102bca` |
| SHA-1 | `e3678a0bff956cab30061b02f8760608ebccb5b7` |
| SHA-256 | `e78d873a275cb56ace7042e6bb1c734d84545a08baf4f789712fba37280267e3` |
| SHA3-384 | `9af192654bfc4c3b907cb6fcda899a29bb1d1c3909bdfcb12b1b22fbe00c3b42bd644b4bef911984f60e651db9c3185d` |
| TLSH | `T155E52BB373C7B94DA89523ECEDCC15081B4FD4194F9235E4A0EB0BC45A4BD5A1AA4CAF` |
| SSDEEP | `12288:9jx5kAYypUmxi4Zf0yrkGRgA5BBbf96/AOWcfjJ55ziokUG:f5kAYypUmxi4Zf0yrkQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_e78d873a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e78d873a275cb56ace7042e6bb1c734d84545a08baf4f789712fba37280267e3"
    family = "unknown"
    file_name = "MV CHRYSANTHI S_VESSEL_DESCRIPTION.js"
    file_type = "js"
    first_seen = "2026-09-14 00:17:41"
  condition:
    hash.sha256(0, filesize) == "e78d873a275cb56ace7042e6bb1c734d84545a08baf4f789712fba37280267e3"
}
```

### Sample 40: `d89ba5767848eb55`

| Field | Value |
|---|---|
| SHA-256 | `d89ba5767848eb5597d03a1d0ae30cc451050859fbc3b9fd3095a9474dd7d86b` |
| Family label | `unknown` |
| File name | `Update.zip` |
| File type | `zip` |
| First seen | `2026-09-13 23:54:56` |
| Reporter | `ave9858` |
| Tags | `fakemas, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a243fe8d6d02416e33d62248c25f40f` |
| SHA-1 | `ffeeb2530a4c9f498cb96d5494e0ab2480a63a13` |
| SHA-256 | `d89ba5767848eb5597d03a1d0ae30cc451050859fbc3b9fd3095a9474dd7d86b` |
| SHA3-384 | `c06d761c19d25b0221144199e2955d5637069108abbfad08f1b9c3f84d47f53efcb174c996c8e9fca9e1dd597467122f` |
| TLSH | `T13FC633508E3C5EFFD94BF33B20E9859B692D8B023443766F3D2E61939C472D16B09A19` |
| SSDEEP | `196608:v8vC7ouppwWscp1H+Fg0eMldZUsqoZVtPz6E+DMl0SkULeCclszL5:v8yokwWsc7HCSsRXDtPz6TDa0HULenly` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_d89ba576
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d89ba5767848eb5597d03a1d0ae30cc451050859fbc3b9fd3095a9474dd7d86b"
    family = "unknown"
    file_name = "Update.zip"
    file_type = "zip"
    first_seen = "2026-09-13 23:54:56"
  condition:
    hash.sha256(0, filesize) == "d89ba5767848eb5597d03a1d0ae30cc451050859fbc3b9fd3095a9474dd7d86b"
}
```

### Sample 41: `b2bdb2a4e93fb7d4`

| Field | Value |
|---|---|
| SHA-256 | `b2bdb2a4e93fb7d4e2d6f87fc27e8016f64b31a53d373bf34c1ceeec02875041` |
| Family label | `unknown` |
| File name | `fakemas.ps1` |
| File type | `ps1` |
| First seen | `2026-09-13 23:34:01` |
| Reporter | `ave9858` |
| Tags | `fakemas, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `388636d04a2e5f85c93f67db34fd7722` |
| SHA-1 | `18347b54073f7d63bd85553d29e3751918c61ea3` |
| SHA-256 | `b2bdb2a4e93fb7d4e2d6f87fc27e8016f64b31a53d373bf34c1ceeec02875041` |
| SHA3-384 | `539c854df2f0280e5d64dc47b5a016b4f02b19fc2f9e58da6fcbba125080874b288019bcbd3bb80521353997ff921f8d` |
| TLSH | `T1C461A85AB7D0E2B18AB31919CCC5A795643B407221135610B2BD87547F9CD9FC7A33CA` |
| SSDEEP | `96:U3im6NnztX94QjCZ548e36xih4AE+b1Hf:U3ibNztN4Q+Z548eqxihIuHf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_b2bdb2a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2bdb2a4e93fb7d4e2d6f87fc27e8016f64b31a53d373bf34c1ceeec02875041"
    family = "unknown"
    file_name = "fakemas.ps1"
    file_type = "ps1"
    first_seen = "2026-09-13 23:34:01"
  condition:
    hash.sha256(0, filesize) == "b2bdb2a4e93fb7d4e2d6f87fc27e8016f64b31a53d373bf34c1ceeec02875041"
}
```

### Sample 42: `67d2cf32ba9cd000`

| Field | Value |
|---|---|
| SHA-256 | `67d2cf32ba9cd0005efd57c1224360875c8c4ce69b8dec37af85c690c16c568e` |
| Family label | `unknown` |
| File name | `meteor-rejects-addon-1.21.11-meteorrejects.net.jar.q` |
| File type | `zip` |
| First seen | `2026-09-13 23:07:16` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ace9833c0e88c6a7470fdd06a5b68d9` |
| SHA-1 | `cf448ec13ffe57b95e6822f14c8c27647fabcd11` |
| SHA-256 | `67d2cf32ba9cd0005efd57c1224360875c8c4ce69b8dec37af85c690c16c568e` |
| SHA3-384 | `a89f760853a0f279a309dc4bd1d1d548a30299accc807ae383d8818d2990fee9b0b610652421aa9794ad91a8306fda8a` |
| TLSH | `T1FDE51227E9D8C07FD867B33291025AA1B94D0AF3D00560FF16FC0ABAC5859DB27617E6` |
| SSDEEP | `49152:yCBm2R3UT4+7hCLYILY757B2S6zJjnB/p2HR3MSMCbT1tZv9BV+5q:6XVYsAFlbBUx3MJWjBsM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_67d2cf32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67d2cf32ba9cd0005efd57c1224360875c8c4ce69b8dec37af85c690c16c568e"
    family = "unknown"
    file_name = "meteor-rejects-addon-1.21.11-meteorrejects.net.jar.q"
    file_type = "zip"
    first_seen = "2026-09-13 23:07:16"
  condition:
    hash.sha256(0, filesize) == "67d2cf32ba9cd0005efd57c1224360875c8c4ce69b8dec37af85c690c16c568e"
}
```

### Sample 43: `a383685ca5382767`

| Field | Value |
|---|---|
| SHA-256 | `a383685ca53827674ae3c34d1f51e33a7973126199f1743936eda7b8d0f22785` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 23:00:31` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, worker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46d7925d69f2204358772d2c216f8965` |
| SHA-256 | `a383685ca53827674ae3c34d1f51e33a7973126199f1743936eda7b8d0f22785` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_a383685c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a383685ca53827674ae3c34d1f51e33a7973126199f1743936eda7b8d0f22785"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 23:00:31"
  condition:
    hash.sha256(0, filesize) == "a383685ca53827674ae3c34d1f51e33a7973126199f1743936eda7b8d0f22785"
}
```

### Sample 44: `8312133009b0f805`

| Field | Value |
|---|---|
| SHA-256 | `8312133009b0f8051bd53a403a561a898c55f714d6ea16af63b6e5f54d6010f1` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-13 22:48:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `255790d927a0f6e078497a30558842b9` |
| SHA-1 | `b956d7246da2c330686fee1a91763e5eec06cbc0` |
| SHA-256 | `8312133009b0f8051bd53a403a561a898c55f714d6ea16af63b6e5f54d6010f1` |
| SHA3-384 | `5388153dfbbded6ef644b94fe2a7ade590e2e2f77ef63d595514ea1bfbbb89efef5365a53195efaff413cfe64a7d2629` |
| TLSH | `T1A4C28E956A857C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:H8vCB+25j6es8RCWg9FYpMSUpi+20qUpi+20YQX:H8l25JCWmd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_83121330
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8312133009b0f8051bd53a403a561a898c55f714d6ea16af63b6e5f54d6010f1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-13 22:48:53"
  condition:
    hash.sha256(0, filesize) == "8312133009b0f8051bd53a403a561a898c55f714d6ea16af63b6e5f54d6010f1"
}
```

### Sample 45: `fd5a365ce5ad86c6`

| Field | Value |
|---|---|
| SHA-256 | `fd5a365ce5ad86c6e0bf6356237f11c2c6ae8f0a350bf2a4c209f99e1d527f5e` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-13 22:44:54` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eab950b418810a1ad8c313ea5da1cbfd` |
| SHA-256 | `fd5a365ce5ad86c6e0bf6356237f11c2c6ae8f0a350bf2a4c209f99e1d527f5e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_fd5a365c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd5a365ce5ad86c6e0bf6356237f11c2c6ae8f0a350bf2a4c209f99e1d527f5e"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 22:44:54"
  condition:
    hash.sha256(0, filesize) == "fd5a365ce5ad86c6e0bf6356237f11c2c6ae8f0a350bf2a4c209f99e1d527f5e"
}
```

### Sample 46: `07a7511ea03bea00`

| Field | Value |
|---|---|
| SHA-256 | `07a7511ea03bea008d1b3f92db12e3bf654c6c2fd8383ab607bd3704230823b9` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-13 22:38:59` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b30edac65ecd6a8d500598bd91f233f` |
| SHA-256 | `07a7511ea03bea008d1b3f92db12e3bf654c6c2fd8383ab607bd3704230823b9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_07a7511e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07a7511ea03bea008d1b3f92db12e3bf654c6c2fd8383ab607bd3704230823b9"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 22:38:59"
  condition:
    hash.sha256(0, filesize) == "07a7511ea03bea008d1b3f92db12e3bf654c6c2fd8383ab607bd3704230823b9"
}
```

### Sample 47: `a7246d705df5e6b3`

| Field | Value |
|---|---|
| SHA-256 | `a7246d705df5e6b324d167f9caf965f2ff52696bb5e5a60ad65cccc6a2ac14de` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-13 22:38:58` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8aa9ffd94d818a7f4f6fe5d6180c385f` |
| SHA-256 | `a7246d705df5e6b324d167f9caf965f2ff52696bb5e5a60ad65cccc6a2ac14de` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_a7246d70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7246d705df5e6b324d167f9caf965f2ff52696bb5e5a60ad65cccc6a2ac14de"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 22:38:58"
  condition:
    hash.sha256(0, filesize) == "a7246d705df5e6b324d167f9caf965f2ff52696bb5e5a60ad65cccc6a2ac14de"
}
```

### Sample 48: `213a0320b76bf702`

| Field | Value |
|---|---|
| SHA-256 | `213a0320b76bf702583ffd25754609124847c67527b3855b2321b1f8fd3b12e2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-13 22:11:32` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f643c6723e6e989724c39ec3457e18d` |
| SHA-1 | `73dc3547cb3ce3444da85d45916ba36cd4fb8e57` |
| SHA-256 | `213a0320b76bf702583ffd25754609124847c67527b3855b2321b1f8fd3b12e2` |
| SHA3-384 | `23e5792dc0e43ab26e6ec34574af488a87ab6d18124f400ffadca35764b026a9f488d49846d37b83bf9160f0dcc8b576` |
| IMPHASH | `11ec7c7af64a7771b7e7b1e6a54181b2` |
| TLSH | `T18C82D809B74290EADAE7D374D5FF8BB6F861BD410674A23F8310D63E2C30A82956D603` |
| SSDEEP | `384:K4SAIl+tYHuwZugtexyFqy4eFPWDjeJy:K42+iHL4xy8kFPWmJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_213a0320
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "213a0320b76bf702583ffd25754609124847c67527b3855b2321b1f8fd3b12e2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-13 22:11:32"
  condition:
    hash.sha256(0, filesize) == "213a0320b76bf702583ffd25754609124847c67527b3855b2321b1f8fd3b12e2"
}
```

### Sample 49: `37a3d7f47dfaff63`

| Field | Value |
|---|---|
| SHA-256 | `37a3d7f47dfaff63354658895d972008f6f5020c4b0936b49d76afdf1f2ad3c8` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-13 22:11:11` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX3.file, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `582d0bf303a87b4b1c0c06b9af1c0fb3` |
| SHA-1 | `3863141aa1c44842140479d68f09e99d15cb42df` |
| SHA-256 | `37a3d7f47dfaff63354658895d972008f6f5020c4b0936b49d76afdf1f2ad3c8` |
| SHA3-384 | `f14ac641b5b5460c1995092c99d0c88f5375c6b160438c46cc0fa48ebadc96eb86cbaa6d5fa5cd0d6d46a721e7f17676` |
| IMPHASH | `7de1855770fd82990edb8ef5c6146b38` |
| TLSH | `T1C6255C5773E930F9E037863C85A24645E776B8351B61ABEF07A0426A1F276D08D3AF31` |
| SSDEEP | `3072:q4ipihh6w9GJFpMYhi0+vCffhWFmXAa+nP/q+VCzjq:q479GJFWYhqvC+mXrKSj` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_049_37a3d7f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37a3d7f47dfaff63354658895d972008f6f5020c4b0936b49d76afdf1f2ad3c8"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-13 22:11:11"
  condition:
    hash.sha256(0, filesize) == "37a3d7f47dfaff63354658895d972008f6f5020c4b0936b49d76afdf1f2ad3c8"
}
```

### Sample 50: `4fd414da4fbb5095`

| Field | Value |
|---|---|
| SHA-256 | `4fd414da4fbb509545a7cc2322ceef048b345b1dea3fa3ec2d49c4abaad3430d` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-13 22:06:56` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c84c69a22fd6021eb59dad72cfb593a1` |
| SHA-256 | `4fd414da4fbb509545a7cc2322ceef048b345b1dea3fa3ec2d49c4abaad3430d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_4fd414da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fd414da4fbb509545a7cc2322ceef048b345b1dea3fa3ec2d49c4abaad3430d"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 22:06:56"
  condition:
    hash.sha256(0, filesize) == "4fd414da4fbb509545a7cc2322ceef048b345b1dea3fa3ec2d49c4abaad3430d"
}
```

### Sample 51: `8066d7da3ea04391`

| Field | Value |
|---|---|
| SHA-256 | `8066d7da3ea0439109de27acd56c86f6300a280d2126883ade57ae78070d3ab3` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-13 22:05:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d4df1e836f58ff7b1c3d0ce203f44cd` |
| SHA-1 | `495c51f115fbe6568ba0a002ce24916579de18d0` |
| SHA-256 | `8066d7da3ea0439109de27acd56c86f6300a280d2126883ade57ae78070d3ab3` |
| SHA3-384 | `560cb2215bdf4f71639034d1e93ae69ebba5375ba3fd015a7e7422d5830a1d28969281456fde64087094b03863536f60` |
| TLSH | `T158236C6516857C14AE99C4375D7E2F0CBDAD43E6314492EE7FCE3CF28C4AAAC920861D` |
| SSDEEP | `768:Kr9NyXsZztCb9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:0HusZBcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_8066d7da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8066d7da3ea0439109de27acd56c86f6300a280d2126883ade57ae78070d3ab3"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-13 22:05:58"
  condition:
    hash.sha256(0, filesize) == "8066d7da3ea0439109de27acd56c86f6300a280d2126883ade57ae78070d3ab3"
}
```

### Sample 52: `0d32c25410242c6c`

| Field | Value |
|---|---|
| SHA-256 | `0d32c25410242c6c30a4714e9366c29a4e1496e4862a00b02fd1267bf5c24fea` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 22:02:45` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdf5ca897321346c56d5e18c69fe64eb` |
| SHA-256 | `0d32c25410242c6c30a4714e9366c29a4e1496e4862a00b02fd1267bf5c24fea` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_0d32c254
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d32c25410242c6c30a4714e9366c29a4e1496e4862a00b02fd1267bf5c24fea"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 22:02:45"
  condition:
    hash.sha256(0, filesize) == "0d32c25410242c6c30a4714e9366c29a4e1496e4862a00b02fd1267bf5c24fea"
}
```

### Sample 53: `cb7f90012d79865f`

| Field | Value |
|---|---|
| SHA-256 | `cb7f90012d79865f44643eee1a44f458f4ce3ac1dcd722f288b8b211a21b227c` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-13 21:58:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6288a50cdc13a38003eb28e1ebf81c6` |
| SHA-1 | `fb7ed5a51894f98bcd6fd41c5422a05c3979220e` |
| SHA-256 | `cb7f90012d79865f44643eee1a44f458f4ce3ac1dcd722f288b8b211a21b227c` |
| SHA3-384 | `74551d5d84c4dfed71810f7b99b7e1fd4910cad1e78834bef83fcb21aa0719a62f5e169ff2aed7f5a1de2b6a0ce0c23b` |
| TLSH | `T196236C6616857C24AA99C4371D7E2F0CBDAD43E6320492EE7FCA3CF28C5A69DD10871D` |
| SSDEEP | `768:eXRWNGxVIj9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:alxrcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_cb7f9001
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb7f90012d79865f44643eee1a44f458f4ce3ac1dcd722f288b8b211a21b227c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-13 21:58:56"
  condition:
    hash.sha256(0, filesize) == "cb7f90012d79865f44643eee1a44f458f4ce3ac1dcd722f288b8b211a21b227c"
}
```

### Sample 54: `d7289acbe0802584`

| Field | Value |
|---|---|
| SHA-256 | `d7289acbe0802584dcc549dc3be603f628502ad0f97be943c45d46ee6a63ed59` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-13 21:49:53` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acb5f196ab3ebc87125ede7396ab9579` |
| SHA-256 | `d7289acbe0802584dcc549dc3be603f628502ad0f97be943c45d46ee6a63ed59` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_d7289acb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7289acbe0802584dcc549dc3be603f628502ad0f97be943c45d46ee6a63ed59"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 21:49:53"
  condition:
    hash.sha256(0, filesize) == "d7289acbe0802584dcc549dc3be603f628502ad0f97be943c45d46ee6a63ed59"
}
```

### Sample 55: `50e90fe8ef4ebc41`

| Field | Value |
|---|---|
| SHA-256 | `50e90fe8ef4ebc412e361a409a043eae382c087adce8aaaf38ec8d1c03ba65ec` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-13 21:47:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4253c06a84fc8b932c0307cdb8d4e280` |
| SHA-1 | `faf4d4143522f5a9e57950b98a05de1b61224ca4` |
| SHA-256 | `50e90fe8ef4ebc412e361a409a043eae382c087adce8aaaf38ec8d1c03ba65ec` |
| SHA3-384 | `ef6bf11e09314308511a99c319937642551aa42f22e8b02dadb3e342d7a9ff7924055ad98a46fbb02ae8a495e49a8d9e` |
| TLSH | `T10BC27D956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:28vCB+25j6es8R4h9FYpMSUpi+20qUpi+20YQX:28l25JMd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_50e90fe8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50e90fe8ef4ebc412e361a409a043eae382c087adce8aaaf38ec8d1c03ba65ec"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-13 21:47:53"
  condition:
    hash.sha256(0, filesize) == "50e90fe8ef4ebc412e361a409a043eae382c087adce8aaaf38ec8d1c03ba65ec"
}
```

### Sample 56: `c057475b4c991df8`

| Field | Value |
|---|---|
| SHA-256 | `c057475b4c991df80b524e27f264bf8982f2fe6f6925c2cdcbe99eb9978fc28b` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-13 21:41:56` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3740260ab372434a4ffaabf975081de` |
| SHA-256 | `c057475b4c991df80b524e27f264bf8982f2fe6f6925c2cdcbe99eb9978fc28b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_c057475b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c057475b4c991df80b524e27f264bf8982f2fe6f6925c2cdcbe99eb9978fc28b"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 21:41:56"
  condition:
    hash.sha256(0, filesize) == "c057475b4c991df80b524e27f264bf8982f2fe6f6925c2cdcbe99eb9978fc28b"
}
```

### Sample 57: `6fbe2a1d1229aad5`

| Field | Value |
|---|---|
| SHA-256 | `6fbe2a1d1229aad5b33ee951d7cfdb4a4870e8ee342464742812d2e0c2b3c082` |
| Family label | `VShell` |
| File name | `6fbe2a1d1229aad5b33ee951d7cfdb4a4870e8ee342464742812d2e0c2b3c082.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:36:23` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4bd8e16e2c9b4d5257705d6cf547121` |
| SHA-1 | `12ea3b79b9c67a63c1f3acf96c2eeaf738301a0d` |
| SHA-256 | `6fbe2a1d1229aad5b33ee951d7cfdb4a4870e8ee342464742812d2e0c2b3c082` |
| SHA3-384 | `8936538e158b73decb0f00abfe18ac3ab7318b53f467ea08e12a873e5718184ba67668f4d32804537ed8311153369549` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T10171B581605456F2D94DA37FC487B895FD4FB24CA2C80B0F43A89C1A2F7107BB1D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6Dzyvjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6Dzy7++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_057_6fbe2a1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fbe2a1d1229aad5b33ee951d7cfdb4a4870e8ee342464742812d2e0c2b3c082"
    family = "VShell"
    file_name = "6fbe2a1d1229aad5b33ee951d7cfdb4a4870e8ee342464742812d2e0c2b3c082.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:36:23"
  condition:
    hash.sha256(0, filesize) == "6fbe2a1d1229aad5b33ee951d7cfdb4a4870e8ee342464742812d2e0c2b3c082"
}
```

### Sample 58: `56377c8e1746c4f3`

| Field | Value |
|---|---|
| SHA-256 | `56377c8e1746c4f368fc1408cfa1f18557ec0fb281de3c9236b280aba346be51` |
| Family label | `VShell` |
| File name | `56377c8e1746c4f368fc1408cfa1f18557ec0fb281de3c9236b280aba346be51.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:31:30` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6d73a5e5de76c744285516d9e9b7e02` |
| SHA-1 | `b96941ee78323e0b07acecfc3bd6137b2d331d79` |
| SHA-256 | `56377c8e1746c4f368fc1408cfa1f18557ec0fb281de3c9236b280aba346be51` |
| SHA3-384 | `42b871ef8778659bc0a98e24e2deb506794401a504494bba7f4340d93746c215c09fb0ea1dad77716d7faf709cfb783c` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T17791A5C5F75BE6B6EC1C17F500A379A4C4682E18927C9B464FE16F0C3C111AA3D2DA52` |
| SSDEEP | `48:6I7lwe7Gh08SB8JdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1w09BOq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_058_56377c8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56377c8e1746c4f368fc1408cfa1f18557ec0fb281de3c9236b280aba346be51"
    family = "VShell"
    file_name = "56377c8e1746c4f368fc1408cfa1f18557ec0fb281de3c9236b280aba346be51.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:31:30"
  condition:
    hash.sha256(0, filesize) == "56377c8e1746c4f368fc1408cfa1f18557ec0fb281de3c9236b280aba346be51"
}
```

### Sample 59: `9d24316bd0f8af89`

| Field | Value |
|---|---|
| SHA-256 | `9d24316bd0f8af89c590f6c37070f905cb60a15745fbe748b525e67d2a05b640` |
| Family label | `VShell` |
| File name | `9d24316bd0f8af89c590f6c37070f905cb60a15745fbe748b525e67d2a05b640.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:31:28` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c874b7cc3c552bfb1c3a11d10b84513` |
| SHA-1 | `29aad0322992dc31986d54a2b1e23d4d57f128ff` |
| SHA-256 | `9d24316bd0f8af89c590f6c37070f905cb60a15745fbe748b525e67d2a05b640` |
| SHA3-384 | `bb37d1fe8faf986a5d45021974e2c9e06d8b30d34a8cf51751dbce2dfa79ba847a1ca097d5584f02c25494909b2c90f5` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1FF91D74170B989E7EC5C81BB4D0FB8A0B91D780A41C483A70378A5953E3A57BF57CB0D` |
| SSDEEP | `48:6IIF9BlQaexdgZh7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMoW0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_059_9d24316b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d24316bd0f8af89c590f6c37070f905cb60a15745fbe748b525e67d2a05b640"
    family = "VShell"
    file_name = "9d24316bd0f8af89c590f6c37070f905cb60a15745fbe748b525e67d2a05b640.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:31:28"
  condition:
    hash.sha256(0, filesize) == "9d24316bd0f8af89c590f6c37070f905cb60a15745fbe748b525e67d2a05b640"
}
```

### Sample 60: `7ff2e43032d97935`

| Field | Value |
|---|---|
| SHA-256 | `7ff2e43032d97935091c5f5a9e3a83446cc4971e3451bdb78fc3ce25faaa52b5` |
| Family label | `Mirai` |
| File name | `7ff2e43032d97935091c5f5a9e3a83446cc4971e3451bdb78fc3ce25faaa52b5.elf` |
| File type | `elf` |
| First seen | `2026-09-13 21:31:25` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65422e418eaa185f9e3666285c7a19fb` |
| SHA-1 | `eb3592dae4f5801e969622e9216f37c9cee5b7c5` |
| SHA-256 | `7ff2e43032d97935091c5f5a9e3a83446cc4971e3451bdb78fc3ce25faaa52b5` |
| SHA3-384 | `4d36689c92b0407eab8bf22c726547b61ec407cfc506d6dd5bde4be1c700393034358a2cd93ddc8a3f4c4c5d7ade7802` |
| TLSH | `T1B8E16207E2D5CE72D8CD133847931749213AC86EAB83AF03650C1999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFjd146zwz7cSym4S2ofahbpZiQ:fsue7cIJMFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_7ff2e430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ff2e43032d97935091c5f5a9e3a83446cc4971e3451bdb78fc3ce25faaa52b5"
    family = "Mirai"
    file_name = "7ff2e43032d97935091c5f5a9e3a83446cc4971e3451bdb78fc3ce25faaa52b5.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:31:25"
  condition:
    hash.sha256(0, filesize) == "7ff2e43032d97935091c5f5a9e3a83446cc4971e3451bdb78fc3ce25faaa52b5"
}
```

### Sample 61: `015b2f5ff28e4d6c`

| Field | Value |
|---|---|
| SHA-256 | `015b2f5ff28e4d6c8e242cc909f381544f5e0687df65700e65180045bc088ea0` |
| Family label | `Mirai` |
| File name | `015b2f5ff28e4d6c8e242cc909f381544f5e0687df65700e65180045bc088ea0.elf` |
| File type | `elf` |
| First seen | `2026-09-13 21:31:22` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c652ac58a7c263d2221d114400ae6cea` |
| SHA-1 | `36b7e89a9f9acbadb12e17d32f951dcf26539028` |
| SHA-256 | `015b2f5ff28e4d6c8e242cc909f381544f5e0687df65700e65180045bc088ea0` |
| SHA3-384 | `ce7112f735928f37391983d3509a1de0177d5d2e9d801ca7a53b6ef5af93751a3a1e32eea16cbe9e50e4c6e07fd41ea3` |
| TLSH | `T145E16207E2D5CE72D8CD133846931749213AD86EAB83AF03650C1999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFS146Cwz7cSym4S2ofahbpZiQ:fsue7c9JtFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_015b2f5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "015b2f5ff28e4d6c8e242cc909f381544f5e0687df65700e65180045bc088ea0"
    family = "Mirai"
    file_name = "015b2f5ff28e4d6c8e242cc909f381544f5e0687df65700e65180045bc088ea0.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:31:22"
  condition:
    hash.sha256(0, filesize) == "015b2f5ff28e4d6c8e242cc909f381544f5e0687df65700e65180045bc088ea0"
}
```

### Sample 62: `81f570ea4d714e3b`

| Field | Value |
|---|---|
| SHA-256 | `81f570ea4d714e3b7a01981c311a83b5a60684ab21c3b3352c8905543f42519f` |
| Family label | `VShell` |
| File name | `81f570ea4d714e3b7a01981c311a83b5a60684ab21c3b3352c8905543f42519f.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:31:19` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6bf21922104deed719c09ca0ad4fa0f` |
| SHA-1 | `6839be33f23c5aeef333fbfb7dced21f07ef23b4` |
| SHA-256 | `81f570ea4d714e3b7a01981c311a83b5a60684ab21c3b3352c8905543f42519f` |
| SHA3-384 | `95118d672f40e9a5c80e27a725fda25e0394aa484e882976c5498decdcd3fea4fd64ffc05545d45085847c83809d807b` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T13C715088F3135AF1E42C86F840D3A654C0599BB8C250BF4D5E60281D3C220BA265EF96` |
| SSDEEP | `48:6Icwm0zqst2WPJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jWzt1SNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_062_81f570ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81f570ea4d714e3b7a01981c311a83b5a60684ab21c3b3352c8905543f42519f"
    family = "VShell"
    file_name = "81f570ea4d714e3b7a01981c311a83b5a60684ab21c3b3352c8905543f42519f.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:31:19"
  condition:
    hash.sha256(0, filesize) == "81f570ea4d714e3b7a01981c311a83b5a60684ab21c3b3352c8905543f42519f"
}
```

### Sample 63: `31b05e1365291fe2`

| Field | Value |
|---|---|
| SHA-256 | `31b05e1365291fe2486c3fa4e68e17ce11a07b4d97e419604f0fbbb2b137f49e` |
| Family label | `Vidar` |
| File name | `p?t=e604e2f7dc0d11e53fee29481106a781_3a723106a8cd40dce6893cabb402f98cbe38086e` |
| File type | `exe` |
| First seen | `2026-09-13 21:27:39` |
| Reporter | `anonymous` |
| Tags | `ClickFix, exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2135f5ae38032c8e2c05b2837a4294df` |
| SHA-1 | `6e0d67c1c8aab68e5f9720cb9c5b107265cb7e96` |
| SHA-256 | `31b05e1365291fe2486c3fa4e68e17ce11a07b4d97e419604f0fbbb2b137f49e` |
| SHA3-384 | `1187a61eea256aab71d5f83a39a254f3fa20eef0bf5a5402e04b4e79e86bc46467c1fe3a2a5e8cd6d64fcf2608ed3a83` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T145D59D0BBCA118E6C4AEA2714D7351817B31BC451F3263D72A90B7782FB6BE05EB4758` |
| SSDEEP | `49152:SqvHQH8kt9AK2cSl6bSmiYYYYYYYYYYYM3RtgvV+SS:Sq4cs03RtKV+S` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_063_31b05e13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31b05e1365291fe2486c3fa4e68e17ce11a07b4d97e419604f0fbbb2b137f49e"
    family = "Vidar"
    file_name = "p?t=e604e2f7dc0d11e53fee29481106a781_3a723106a8cd40dce6893cabb402f98cbe38086e"
    file_type = "exe"
    first_seen = "2026-09-13 21:27:39"
  condition:
    hash.sha256(0, filesize) == "31b05e1365291fe2486c3fa4e68e17ce11a07b4d97e419604f0fbbb2b137f49e"
}
```

### Sample 64: `2595487dc6b82f6a`

| Field | Value |
|---|---|
| SHA-256 | `2595487dc6b82f6a9a7ef88dcb826fefcdca5a32323b840f7248796dd2461220` |
| Family label | `unknown` |
| File name | `b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:21:21` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ae04c09372bb6d53d08b847205b9f74` |
| SHA-1 | `9f0c3090bf82c68c02b64e961eedfd61054683af` |
| SHA-256 | `2595487dc6b82f6a9a7ef88dcb826fefcdca5a32323b840f7248796dd2461220` |
| SHA3-384 | `2ab6f06022f37b7bf9c16fdb444e663759d32af8353af8cf6baa27d7501a14026382cac4435c9993f3c94b7e519ff2c0` |
| IMPHASH | `af40a2c8db5784e92faf37e71b4836b9` |
| TLSH | `T135750223F3A094A1D10C52BB66F2073E2EF0D3615C7A0927EFE08DFE9D61A61865754E` |
| SSDEEP | `24576:5AjDDZzywRoadtPNqCyv5PUQh3JtXzqZqDvPGW3IRCdGd0Fx1+bCCYa11jqQJDXk:5KU2RRCcd031+bv1hlrxqPk4UvsD5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_2595487d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2595487dc6b82f6a9a7ef88dcb826fefcdca5a32323b840f7248796dd2461220"
    family = "unknown"
    file_name = "b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:21:21"
  condition:
    hash.sha256(0, filesize) == "2595487dc6b82f6a9a7ef88dcb826fefcdca5a32323b840f7248796dd2461220"
}
```

### Sample 65: `b1bb369c12b3c957`

| Field | Value |
|---|---|
| SHA-256 | `b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e` |
| Family label | `unknown` |
| File name | `b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:20:29` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb7a1925f00c98509a6ab98f71ac7f69` |
| SHA-1 | `57edf339cf31ac467fb521b5ffaec104343666b6` |
| SHA-256 | `b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e` |
| SHA3-384 | `cfbfbe0c5cf6638aed6d3f3d540ba8d13db652d6de417a2795579f0bcb91bdd1a20e4deb9204609df041f5bcb8a4149e` |
| IMPHASH | `dc51245cba233f909267df3c87d0bdfa` |
| TLSH | `T13855330992EA6874F43D4936CC3D6B37DAE84B485886585E4727D8F588FE33C8E190DD` |
| SSDEEP | `24576:Al+U6kZeOqR2ItJ4spQD3q/0biYTHnlRwYl5icBskk163sIi/2:A4sDqR2mfq+/0biClBmc9A63K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_b1bb369c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e"
    family = "unknown"
    file_name = "b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:20:29"
  condition:
    hash.sha256(0, filesize) == "b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e"
}
```

### Sample 66: `77f879691310d233`

| Field | Value |
|---|---|
| SHA-256 | `77f879691310d233621ec53a68290d28e4aa83334e36a2069e91074cbe3dcfeb` |
| Family label | `VShell` |
| File name | `77f879691310d233621ec53a68290d28e4aa83334e36a2069e91074cbe3dcfeb.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:11:56` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf317fe017ab368277408580de80a48b` |
| SHA-1 | `f8104c4f8da9b497efd7c3c8329eeaae273bdb8c` |
| SHA-256 | `77f879691310d233621ec53a68290d28e4aa83334e36a2069e91074cbe3dcfeb` |
| SHA3-384 | `69ac06a316854cd2971f5941e64ce0f1e6a932704e0b314d333223d6bd170747043eef8385a8027007486b145b6c25e4` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1DD715088F3175EF1E42C46F90093A654D4599BB8C250BF4D5F60281D3C210BA295AF97` |
| SSDEEP | `48:6Icwm0h1t2WVJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jQ1tnSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_066_77f87969
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77f879691310d233621ec53a68290d28e4aa83334e36a2069e91074cbe3dcfeb"
    family = "VShell"
    file_name = "77f879691310d233621ec53a68290d28e4aa83334e36a2069e91074cbe3dcfeb.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:11:56"
  condition:
    hash.sha256(0, filesize) == "77f879691310d233621ec53a68290d28e4aa83334e36a2069e91074cbe3dcfeb"
}
```

### Sample 67: `46c75a86d2493710`

| Field | Value |
|---|---|
| SHA-256 | `46c75a86d2493710bd827e4ff84f7d6412d53ba9d8c4fc8e844de8af338c88ee` |
| Family label | `VShell` |
| File name | `46c75a86d2493710bd827e4ff84f7d6412d53ba9d8c4fc8e844de8af338c88ee.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:11:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63ce92a29a9b5ac973d914acdba26162` |
| SHA-1 | `0e28c76cda45b70443ef25b87e2cc3019fc8a58e` |
| SHA-256 | `46c75a86d2493710bd827e4ff84f7d6412d53ba9d8c4fc8e844de8af338c88ee` |
| SHA3-384 | `d954ae529ea2b3aec566f4873b4f0f449ac8b2e3fdf535a7f7a10127e47bedd180bf058a28e478ab6b9c29f52e342067` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1E591C64170B989E7E85D41BB4D0FB8A0B91D740A41C483A74378A5993E3A57BF57CB0E` |
| SSDEEP | `48:6IIF9BlQaexIjCLegZL7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMIjCno0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_067_46c75a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46c75a86d2493710bd827e4ff84f7d6412d53ba9d8c4fc8e844de8af338c88ee"
    family = "VShell"
    file_name = "46c75a86d2493710bd827e4ff84f7d6412d53ba9d8c4fc8e844de8af338c88ee.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:11:54"
  condition:
    hash.sha256(0, filesize) == "46c75a86d2493710bd827e4ff84f7d6412d53ba9d8c4fc8e844de8af338c88ee"
}
```

### Sample 68: `804111c64e49ef40`

| Field | Value |
|---|---|
| SHA-256 | `804111c64e49ef400093f53e16f65a8607de9489e1d052c2e6bdda2cfa7fcf77` |
| Family label | `VShell` |
| File name | `804111c64e49ef400093f53e16f65a8607de9489e1d052c2e6bdda2cfa7fcf77.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:11:05` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `056681587b8a1879c23808f71f11132f` |
| SHA-1 | `25a7fe25159852775bcbfb6edcf7a8e88ac75ea5` |
| SHA-256 | `804111c64e49ef400093f53e16f65a8607de9489e1d052c2e6bdda2cfa7fcf77` |
| SHA3-384 | `d6af2e7fdc5244790d631879cc764a4201151ab67a39060682b31ee83a90e98f234870f28a2b0febd5f8f19078fb303c` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T19471B54160541AF2D94CE3BF8487B8A6FD4EB248A2C80B0B0398981A2F7147BB0D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DiVjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DiF++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_068_804111c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "804111c64e49ef400093f53e16f65a8607de9489e1d052c2e6bdda2cfa7fcf77"
    family = "VShell"
    file_name = "804111c64e49ef400093f53e16f65a8607de9489e1d052c2e6bdda2cfa7fcf77.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:11:05"
  condition:
    hash.sha256(0, filesize) == "804111c64e49ef400093f53e16f65a8607de9489e1d052c2e6bdda2cfa7fcf77"
}
```

### Sample 69: `25f946d5bebb3501`

| Field | Value |
|---|---|
| SHA-256 | `25f946d5bebb35015546c90f6256716e4283f8540aaf31773d06098fbf645801` |
| Family label | `VShell` |
| File name | `25f946d5bebb35015546c90f6256716e4283f8540aaf31773d06098fbf645801.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:11:02` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c4843c4e0f83601f80071fb76996cfe` |
| SHA-1 | `9fe258b44b260a89e727189e7be4c6047b375d6f` |
| SHA-256 | `25f946d5bebb35015546c90f6256716e4283f8540aaf31773d06098fbf645801` |
| SHA3-384 | `51dd35e8bf3871a37e7b4ddaa12c64f0b69d1aeb21d007a00263813afa5fc179041d909af11899f8819a54508ad70b8e` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1F391A5C5F757E6B2EC1C07F500A379A4C8682E14927D9B574FA16F1C3C111AA3D3DA52` |
| SSDEEP | `48:6I7lwe7WW08SEJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1z092q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_069_25f946d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25f946d5bebb35015546c90f6256716e4283f8540aaf31773d06098fbf645801"
    family = "VShell"
    file_name = "25f946d5bebb35015546c90f6256716e4283f8540aaf31773d06098fbf645801.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:11:02"
  condition:
    hash.sha256(0, filesize) == "25f946d5bebb35015546c90f6256716e4283f8540aaf31773d06098fbf645801"
}
```

### Sample 70: `46f4cd435ca39c8f`

| Field | Value |
|---|---|
| SHA-256 | `46f4cd435ca39c8fc2f1814fd9740a7ee9716207f5351d21008672ab466149eb` |
| Family label | `VShell` |
| File name | `46f4cd435ca39c8fc2f1814fd9740a7ee9716207f5351d21008672ab466149eb.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:11:00` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75617aa59603c611d94bc21202da0de7` |
| SHA-1 | `bde85c41c52b5bdb269b943e6d4978d4ddead23f` |
| SHA-256 | `46f4cd435ca39c8fc2f1814fd9740a7ee9716207f5351d21008672ab466149eb` |
| SHA3-384 | `01a424ef2d473919d66dfd4b4c9d92c6c134aa71c0336edddb644d4ee1de5d595100c3231615a9d4405baaab74962de4` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1F191D64170B988E7E85C41BB4C0FB8A0B91D740A41C483A70378A5993E3A57BF07CB0E` |
| SSDEEP | `48:6IIF9BlQaexIjCLegZH7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMIjCnM0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_070_46f4cd43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46f4cd435ca39c8fc2f1814fd9740a7ee9716207f5351d21008672ab466149eb"
    family = "VShell"
    file_name = "46f4cd435ca39c8fc2f1814fd9740a7ee9716207f5351d21008672ab466149eb.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:11:00"
  condition:
    hash.sha256(0, filesize) == "46f4cd435ca39c8fc2f1814fd9740a7ee9716207f5351d21008672ab466149eb"
}
```

### Sample 71: `e4955c3c33a13634`

| Field | Value |
|---|---|
| SHA-256 | `e4955c3c33a1363472dffa0cbac8505fc443d4d4228a6dd5ab569fd194f9d918` |
| Family label | `VShell` |
| File name | `e4955c3c33a1363472dffa0cbac8505fc443d4d4228a6dd5ab569fd194f9d918.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:10:56` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b6ae9c4a76297dd054cf709746f2d7b` |
| SHA-1 | `53b08db86ac2f36212d48d87965bca1a6bd0c0fc` |
| SHA-256 | `e4955c3c33a1363472dffa0cbac8505fc443d4d4228a6dd5ab569fd194f9d918` |
| SHA3-384 | `0d588b959360df6c3b2ef245c3379eacf01ea4edf6a0b2dbbbe5711ec0f99e4239f26e40f71ec311f15f2652e9df159c` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1B5715088F3176EF5E42C46F80093A654D4599BB8C250BE4D5F60281D3C220BA255AF97` |
| SSDEEP | `48:6Icwm0h1t2WecJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jQ1tzSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_071_e4955c3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4955c3c33a1363472dffa0cbac8505fc443d4d4228a6dd5ab569fd194f9d918"
    family = "VShell"
    file_name = "e4955c3c33a1363472dffa0cbac8505fc443d4d4228a6dd5ab569fd194f9d918.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:10:56"
  condition:
    hash.sha256(0, filesize) == "e4955c3c33a1363472dffa0cbac8505fc443d4d4228a6dd5ab569fd194f9d918"
}
```

### Sample 72: `ab42877d03155a4b`

| Field | Value |
|---|---|
| SHA-256 | `ab42877d03155a4b5a5cc662e1d86df4c00201281b357fae9d2463827bf0de61` |
| Family label | `VShell` |
| File name | `ab42877d03155a4b5a5cc662e1d86df4c00201281b357fae9d2463827bf0de61.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:10:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `484aac99b11953b6dc9d01d01ddc3e06` |
| SHA-1 | `b6f4a57cd921932cb41872e9c2fcde2a29d7d710` |
| SHA-256 | `ab42877d03155a4b5a5cc662e1d86df4c00201281b357fae9d2463827bf0de61` |
| SHA3-384 | `453f7a6b377559f4cc42aff105f15c10764b00453bee8d614f121f6b2ba7a3062f07040a4282b4b85c4cb6b5dbb12493` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T17D91C5C5F357E6B6EC1C07F500A379A4C8682E14927C9B474FA12F0C3C111AA3C3DA12` |
| SSDEEP | `48:6I7lwe7WW08SYfJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1z09+q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_072_ab42877d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab42877d03155a4b5a5cc662e1d86df4c00201281b357fae9d2463827bf0de61"
    family = "VShell"
    file_name = "ab42877d03155a4b5a5cc662e1d86df4c00201281b357fae9d2463827bf0de61.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:10:54"
  condition:
    hash.sha256(0, filesize) == "ab42877d03155a4b5a5cc662e1d86df4c00201281b357fae9d2463827bf0de61"
}
```

### Sample 73: `ad7829bf9fbc4713`

| Field | Value |
|---|---|
| SHA-256 | `ad7829bf9fbc471369b48b47703ba4e7dbc58769a4f38285404c5c7ec6bdce16` |
| Family label | `VShell` |
| File name | `ad7829bf9fbc471369b48b47703ba4e7dbc58769a4f38285404c5c7ec6bdce16.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:10:51` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f37fcb39c7eb4a45ef02d1065a481347` |
| SHA-1 | `371e94fb75ddc19ba493ef18dbd7ff06e3abaacc` |
| SHA-256 | `ad7829bf9fbc471369b48b47703ba4e7dbc58769a4f38285404c5c7ec6bdce16` |
| SHA3-384 | `36d5ede605d9ebef025ab9ce1f5222986eed8e093cfd3200073a2a520273f08a873d91e429b1ad96c079506b05b0a0e0` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1F371B54160541AF2D94CE3BF8487B896FD4EB248A2C80B0B0398981A2F7507BB0D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6Dixjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DiJ++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_073_ad7829bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad7829bf9fbc471369b48b47703ba4e7dbc58769a4f38285404c5c7ec6bdce16"
    family = "VShell"
    file_name = "ad7829bf9fbc471369b48b47703ba4e7dbc58769a4f38285404c5c7ec6bdce16.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:10:51"
  condition:
    hash.sha256(0, filesize) == "ad7829bf9fbc471369b48b47703ba4e7dbc58769a4f38285404c5c7ec6bdce16"
}
```

### Sample 74: `83c3b0789133e767`

| Field | Value |
|---|---|
| SHA-256 | `83c3b0789133e767350a3fbb1010851546473a0726bf876cd70e9d40f7f4bcf6` |
| Family label | `Snowlight` |
| File name | `83c3b0789133e767350a3fbb1010851546473a0726bf876cd70e9d40f7f4bcf6.elf` |
| File type | `elf` |
| First seen | `2026-09-13 21:05:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02c01ee13f002aff0e967e42f034a712` |
| SHA-1 | `a91515ff07f616fba2990ed302399ee59178e7c9` |
| SHA-256 | `83c3b0789133e767350a3fbb1010851546473a0726bf876cd70e9d40f7f4bcf6` |
| SHA3-384 | `eff521875c2c1b280dde9a38a86ec031e02d6eac7f306f0959462bf0d248167efd67dedc4c4e2cb2ea7cd4e1c7bb406c` |
| TLSH | `T120E17217E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3DOJheuhiG5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbKJhAwZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_074_83c3b078
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83c3b0789133e767350a3fbb1010851546473a0726bf876cd70e9d40f7f4bcf6"
    family = "Snowlight"
    file_name = "83c3b0789133e767350a3fbb1010851546473a0726bf876cd70e9d40f7f4bcf6.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:05:14"
  condition:
    hash.sha256(0, filesize) == "83c3b0789133e767350a3fbb1010851546473a0726bf876cd70e9d40f7f4bcf6"
}
```

### Sample 75: `46dcb2cbab575cb8`

| Field | Value |
|---|---|
| SHA-256 | `46dcb2cbab575cb8a4a8d608c70c6acdc34b18e7ffbf0c479e177a48c6822a08` |
| Family label | `VShell` |
| File name | `46dcb2cbab575cb8a4a8d608c70c6acdc34b18e7ffbf0c479e177a48c6822a08.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:05:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6348eba3fd21ce57c3dc080e793cd1e` |
| SHA-1 | `005b912b60647db2d25de00b92e04adc49f6e24d` |
| SHA-256 | `46dcb2cbab575cb8a4a8d608c70c6acdc34b18e7ffbf0c479e177a48c6822a08` |
| SHA3-384 | `f9bfe55a09892a6b9763f82d6fe51ba4dc85b7b0ac15f12466505f8d3ebf6870f45e1b92b575c7b1c84503a60320ecf6` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1AC71B54160545AF2D94CE3BF8587B895FD4FB248A2C80B0B0798981A2F7107BB4D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DQpjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DQR++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_075_46dcb2cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46dcb2cbab575cb8a4a8d608c70c6acdc34b18e7ffbf0c479e177a48c6822a08"
    family = "VShell"
    file_name = "46dcb2cbab575cb8a4a8d608c70c6acdc34b18e7ffbf0c479e177a48c6822a08.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:05:11"
  condition:
    hash.sha256(0, filesize) == "46dcb2cbab575cb8a4a8d608c70c6acdc34b18e7ffbf0c479e177a48c6822a08"
}
```

### Sample 76: `94eb3e7e60a01066`

| Field | Value |
|---|---|
| SHA-256 | `94eb3e7e60a010665022d1d8cd9fd38a3c9e4d08a535f4384b63b95441de2630` |
| Family label | `Snowlight` |
| File name | `94eb3e7e60a010665022d1d8cd9fd38a3c9e4d08a535f4384b63b95441de2630.elf` |
| File type | `elf` |
| First seen | `2026-09-13 21:05:09` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb90ca6f855fcfd82e3fed4d65fa1e19` |
| SHA-1 | `976962ad0b7e2fb360dd7a387b89ced728e47944` |
| SHA-256 | `94eb3e7e60a010665022d1d8cd9fd38a3c9e4d08a535f4384b63b95441de2630` |
| SHA3-384 | `3de385f4fac938fcf1c29a3b9d60109183b6f94a8da2dce471ec6751cad584885535796127701815c5c085dcbaf99e1b` |
| TLSH | `T184124047A2D0CE3FC8E953384467122472B794BEDF629713064815B63F427E81E2EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS67H5ML09V1J9G8YmS+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHsZMWT1YmfhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_076_94eb3e7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94eb3e7e60a010665022d1d8cd9fd38a3c9e4d08a535f4384b63b95441de2630"
    family = "Snowlight"
    file_name = "94eb3e7e60a010665022d1d8cd9fd38a3c9e4d08a535f4384b63b95441de2630.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:05:09"
  condition:
    hash.sha256(0, filesize) == "94eb3e7e60a010665022d1d8cd9fd38a3c9e4d08a535f4384b63b95441de2630"
}
```

### Sample 77: `5b48a3bf7827e461`

| Field | Value |
|---|---|
| SHA-256 | `5b48a3bf7827e461849c3b29b96775dc7e5e38766f51d0562ed73d352d082e41` |
| Family label | `unknown` |
| File name | `5b48a3bf7827e461849c3b29b96775dc7e5e38766f51d0562ed73d352d082e41.exe` |
| File type | `exe` |
| First seen | `2026-09-13 21:01:40` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c173936dfee19dd117c155fcaa07d040` |
| SHA-1 | `50b06c50d3b03037f8c26163704a9e8e5eeeef4a` |
| SHA-256 | `5b48a3bf7827e461849c3b29b96775dc7e5e38766f51d0562ed73d352d082e41` |
| SHA3-384 | `f173465230a23b6f6fd26337cdfe2873c147ea3fe9b9a4e383a96f2c48e01dd21d9d2be72070e38c5719dd37fc771a89` |
| IMPHASH | `48d13170eda7ae88733253b960667262` |
| TLSH | `T17FD4E149B96903FCC15950BA899E25D6B2E1B4874FB06BEF079808462F2F6DC5F3CB11` |
| SSDEEP | `12288:Y6AfsZuKp6430SkPMVhanBjnQyOd2Dq5vrCyXjJACsaOr1:vOsA7BMVhEBjnpnOaaOx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_5b48a3bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b48a3bf7827e461849c3b29b96775dc7e5e38766f51d0562ed73d352d082e41"
    family = "unknown"
    file_name = "5b48a3bf7827e461849c3b29b96775dc7e5e38766f51d0562ed73d352d082e41.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:01:40"
  condition:
    hash.sha256(0, filesize) == "5b48a3bf7827e461849c3b29b96775dc7e5e38766f51d0562ed73d352d082e41"
}
```

### Sample 78: `b36d30ad0a646eee`

| Field | Value |
|---|---|
| SHA-256 | `b36d30ad0a646eeed5f02b48ac6b02f2cd2c125df298252dc1070aeff80de3e3` |
| Family label | `Snowlight` |
| File name | `b36d30ad0a646eeed5f02b48ac6b02f2cd2c125df298252dc1070aeff80de3e3.elf` |
| File type | `elf` |
| First seen | `2026-09-13 21:00:43` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3af80ce717bdb1789839e3e8a8c7bde` |
| SHA-1 | `66176032451623864252b740a0ff464fc618c17c` |
| SHA-256 | `b36d30ad0a646eeed5f02b48ac6b02f2cd2c125df298252dc1070aeff80de3e3` |
| SHA3-384 | `4ce15ad9bb12bb21a14e67c25fb050297abd1894bfdb791d50cce63f60c0c4976425a92a58548e0981128e6d3b86b692` |
| TLSH | `T191122F47A2D0CE3FC8D9533844A7122472B794BADF629723064915B53F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6WH5ML09V1J9G8Ymf+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHJZMWT1Ym2hrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_078_b36d30ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b36d30ad0a646eeed5f02b48ac6b02f2cd2c125df298252dc1070aeff80de3e3"
    family = "Snowlight"
    file_name = "b36d30ad0a646eeed5f02b48ac6b02f2cd2c125df298252dc1070aeff80de3e3.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:00:43"
  condition:
    hash.sha256(0, filesize) == "b36d30ad0a646eeed5f02b48ac6b02f2cd2c125df298252dc1070aeff80de3e3"
}
```

### Sample 79: `666c4c426bb64bdc`

| Field | Value |
|---|---|
| SHA-256 | `666c4c426bb64bdc5ecbd03826b3d8cd495b452d23985bdae13e35f187ac56ab` |
| Family label | `Mirai` |
| File name | `666c4c426bb64bdc5ecbd03826b3d8cd495b452d23985bdae13e35f187ac56ab.elf` |
| File type | `elf` |
| First seen | `2026-09-13 21:00:40` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72206f3447aceba7ae1a1bc553523b83` |
| SHA-1 | `d3130fb662064620db8b8aee6bbf28fc3dd95ee5` |
| SHA-256 | `666c4c426bb64bdc5ecbd03826b3d8cd495b452d23985bdae13e35f187ac56ab` |
| SHA3-384 | `545078f93430f3e520f6b88afee4e115cda353261fe079654264c335e79c1ff7508ba7f4ac9d1a9bf6a09662ef892c8f` |
| TLSH | `T162E17207E2D5CE72D8CD133846931749213AC86EAB83AF03650C1A99EE43BDC7A63752` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFS146Awz7cSym4S2ofahbpZiQ:fsue7c9JrFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_666c4c42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "666c4c426bb64bdc5ecbd03826b3d8cd495b452d23985bdae13e35f187ac56ab"
    family = "Mirai"
    file_name = "666c4c426bb64bdc5ecbd03826b3d8cd495b452d23985bdae13e35f187ac56ab.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:00:40"
  condition:
    hash.sha256(0, filesize) == "666c4c426bb64bdc5ecbd03826b3d8cd495b452d23985bdae13e35f187ac56ab"
}
```

### Sample 80: `33808f4224a82607`

| Field | Value |
|---|---|
| SHA-256 | `33808f4224a8260786123b1a662fbf6fef738031e03c6b47128c64f125e68f8b` |
| Family label | `VShell` |
| File name | `33808f4224a8260786123b1a662fbf6fef738031e03c6b47128c64f125e68f8b.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:56:24` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c642d0778e65f7def72a724dbddae63e` |
| SHA-1 | `52ae4479c6bd8b670ba65ef55395990463fb6c7a` |
| SHA-256 | `33808f4224a8260786123b1a662fbf6fef738031e03c6b47128c64f125e68f8b` |
| SHA3-384 | `dd295f0758ab4935272c3eb9311c0c88163dac080b221c3a674fe18bde5780ae711ba838f369a32b2794d2e8d2687b21` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T13E91A5C5F757E6B2EC1C17F500A379A4C4682E14927C9B464FA16F0C3C111AA3C2DA52` |
| SSDEEP | `48:6I7lwe7F/bi08SEJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl19m092q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_080_33808f42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33808f4224a8260786123b1a662fbf6fef738031e03c6b47128c64f125e68f8b"
    family = "VShell"
    file_name = "33808f4224a8260786123b1a662fbf6fef738031e03c6b47128c64f125e68f8b.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:56:24"
  condition:
    hash.sha256(0, filesize) == "33808f4224a8260786123b1a662fbf6fef738031e03c6b47128c64f125e68f8b"
}
```

### Sample 81: `7386686dd98bb774`

| Field | Value |
|---|---|
| SHA-256 | `7386686dd98bb774d352990a5f84fa210aff26ac6ecd5858857d2f54d8a04c07` |
| Family label | `Snowlight` |
| File name | `7386686dd98bb774d352990a5f84fa210aff26ac6ecd5858857d2f54d8a04c07.elf` |
| File type | `elf` |
| First seen | `2026-09-13 20:55:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d6b669825e4acf7f396811107e2c912` |
| SHA-1 | `a53075996b781d854851322069a74c6ae111cfb4` |
| SHA-256 | `7386686dd98bb774d352990a5f84fa210aff26ac6ecd5858857d2f54d8a04c07` |
| SHA3-384 | `0e15bac37136af6181c0989ce5f255d66d65ff884e6e6fab69a4bead4112d785d54efcd4f91efe733d06fa078a1e3835` |
| TLSH | `T114E17217E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw39Jheuhi35Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbtJhAJZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_081_7386686d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7386686dd98bb774d352990a5f84fa210aff26ac6ecd5858857d2f54d8a04c07"
    family = "Snowlight"
    file_name = "7386686dd98bb774d352990a5f84fa210aff26ac6ecd5858857d2f54d8a04c07.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:55:07"
  condition:
    hash.sha256(0, filesize) == "7386686dd98bb774d352990a5f84fa210aff26ac6ecd5858857d2f54d8a04c07"
}
```

### Sample 82: `2d5f05106b2cd88b`

| Field | Value |
|---|---|
| SHA-256 | `2d5f05106b2cd88b2d6eabc7813f30a60c95823af166548c804be3e128028bf1` |
| Family label | `VShell` |
| File name | `2d5f05106b2cd88b2d6eabc7813f30a60c95823af166548c804be3e128028bf1.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:55:04` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0296131ff41eb0893cedd4a2f810df0e` |
| SHA-1 | `d2d662c171fc4698391b5f4ab81d0b796cd58d34` |
| SHA-256 | `2d5f05106b2cd88b2d6eabc7813f30a60c95823af166548c804be3e128028bf1` |
| SHA3-384 | `e71d56c6a1317f2f4afd0b93801163ab29610981c9afc23c4d5f99dc56151a1a24b4523ca58846173b8720389e5a0fe3` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1F791A5C5F757E6B6EC1C17F500A379A4C4682E14927C9B568FE16F1C3C111AA3C3DA52` |
| SSDEEP | `48:6I7lwe7e508SLJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1Y091q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_082_2d5f0510
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d5f05106b2cd88b2d6eabc7813f30a60c95823af166548c804be3e128028bf1"
    family = "VShell"
    file_name = "2d5f05106b2cd88b2d6eabc7813f30a60c95823af166548c804be3e128028bf1.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:55:04"
  condition:
    hash.sha256(0, filesize) == "2d5f05106b2cd88b2d6eabc7813f30a60c95823af166548c804be3e128028bf1"
}
```

### Sample 83: `9991d9987da7f9be`

| Field | Value |
|---|---|
| SHA-256 | `9991d9987da7f9be952fba8199baa69237c42d10a66eb60a52bf77143145111e` |
| Family label | `Mirai` |
| File name | `9991d9987da7f9be952fba8199baa69237c42d10a66eb60a52bf77143145111e.elf` |
| File type | `elf` |
| First seen | `2026-09-13 20:55:01` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b1d7ab7018baaf8b65a3b7dda8a636d` |
| SHA-1 | `f3a547ea30e174d30c5e2ca09f9a9437c25637d2` |
| SHA-256 | `9991d9987da7f9be952fba8199baa69237c42d10a66eb60a52bf77143145111e` |
| SHA3-384 | `6fc2a67c99b5efcc32e7dfd1c9e0d90c2a0809f527394ac1b94ad1028175916c2763067dcac6212c3e0f86d8ffad8777` |
| TLSH | `T138E16207E2D5CE72D8CD133846935749213AC86EAB83AF03650C5999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFFk146Dwz7cSym4S2ofahbpZiQ:fsue7cSwJ8Fym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_9991d998
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9991d9987da7f9be952fba8199baa69237c42d10a66eb60a52bf77143145111e"
    family = "Mirai"
    file_name = "9991d9987da7f9be952fba8199baa69237c42d10a66eb60a52bf77143145111e.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:55:01"
  condition:
    hash.sha256(0, filesize) == "9991d9987da7f9be952fba8199baa69237c42d10a66eb60a52bf77143145111e"
}
```

### Sample 84: `e5c7b3d6dec0c897`

| Field | Value |
|---|---|
| SHA-256 | `e5c7b3d6dec0c89701fa8c94cdc5d1353770a04edd5eeaf987c45630647e74d8` |
| Family label | `VShell` |
| File name | `e5c7b3d6dec0c89701fa8c94cdc5d1353770a04edd5eeaf987c45630647e74d8.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:51:15` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7af911f1df0aa7d4d4571362738448b5` |
| SHA-1 | `b97d4976984f696ba3a39a01c6e7bff7b1dbac35` |
| SHA-256 | `e5c7b3d6dec0c89701fa8c94cdc5d1353770a04edd5eeaf987c45630647e74d8` |
| SHA3-384 | `a910f1f494b2cdfc437c8ed121b924d196d0f27400781d98bc36ec45e31d364f6fc70ad355de00d0b90df005713f0c09` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T159716088F3276AF5E43C87F840D3A624D019ABB8C250BF4D5E60381D3C220BA255AF97` |
| SSDEEP | `48:6Icwm07/t2WSJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4j+tQSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_084_e5c7b3d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5c7b3d6dec0c89701fa8c94cdc5d1353770a04edd5eeaf987c45630647e74d8"
    family = "VShell"
    file_name = "e5c7b3d6dec0c89701fa8c94cdc5d1353770a04edd5eeaf987c45630647e74d8.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:51:15"
  condition:
    hash.sha256(0, filesize) == "e5c7b3d6dec0c89701fa8c94cdc5d1353770a04edd5eeaf987c45630647e74d8"
}
```

### Sample 85: `a2a067ca282f9034`

| Field | Value |
|---|---|
| SHA-256 | `a2a067ca282f9034391e2cf1b4d2fe681cbe0326588d507b3cff5b2fab70bc7e` |
| Family label | `VShell` |
| File name | `a2a067ca282f9034391e2cf1b4d2fe681cbe0326588d507b3cff5b2fab70bc7e.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:51:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba390cbf46c5122029cef0fb3856ad06` |
| SHA-1 | `40d0cad445286da173870bf4e69c932193a1fcaa` |
| SHA-256 | `a2a067ca282f9034391e2cf1b4d2fe681cbe0326588d507b3cff5b2fab70bc7e` |
| SHA3-384 | `b856350f87e4b10778238101f2ee7891d12fcb5aaec3ad48c91ad1c3e7824bf04ace4bfe507dfed9b098edbdbed04bc1` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T11971B741605416F2D98DE37FC587B895FD4FB248A2C84B0B0398981A3F7547BB0D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DX+8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DOG++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_085_a2a067ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2a067ca282f9034391e2cf1b4d2fe681cbe0326588d507b3cff5b2fab70bc7e"
    family = "VShell"
    file_name = "a2a067ca282f9034391e2cf1b4d2fe681cbe0326588d507b3cff5b2fab70bc7e.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:51:13"
  condition:
    hash.sha256(0, filesize) == "a2a067ca282f9034391e2cf1b4d2fe681cbe0326588d507b3cff5b2fab70bc7e"
}
```

### Sample 86: `994b914dc77a84a9`

| Field | Value |
|---|---|
| SHA-256 | `994b914dc77a84a9adbe5ba1c49cd6bab320924c4d0938134d5c47ce9cedee8b` |
| Family label | `VShell` |
| File name | `994b914dc77a84a9adbe5ba1c49cd6bab320924c4d0938134d5c47ce9cedee8b.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:51:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b70e8b70be76d2449980147e9cb8584` |
| SHA-1 | `d819bcd00f21ba4eadd248c0715d4d6fabdb0f38` |
| SHA-256 | `994b914dc77a84a9adbe5ba1c49cd6bab320924c4d0938134d5c47ce9cedee8b` |
| SHA3-384 | `874359a1666b53b461d966c2184e90190aea1bf5bbdda1370bbaa79ed93d27b6ea417342ed6ad308d8b902972e11a5ed` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T17D71B54160641AF2D98CA37F8587B899FD4EB248A2C84B0B4398981A3F7547BB0D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DXR8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DhG++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_086_994b914d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "994b914dc77a84a9adbe5ba1c49cd6bab320924c4d0938134d5c47ce9cedee8b"
    family = "VShell"
    file_name = "994b914dc77a84a9adbe5ba1c49cd6bab320924c4d0938134d5c47ce9cedee8b.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:51:10"
  condition:
    hash.sha256(0, filesize) == "994b914dc77a84a9adbe5ba1c49cd6bab320924c4d0938134d5c47ce9cedee8b"
}
```

### Sample 87: `c66e9d85ddd7bb98`

| Field | Value |
|---|---|
| SHA-256 | `c66e9d85ddd7bb98a60b1823e1cc7cb27035da727744c03735317f2106da80e8` |
| Family label | `VShell` |
| File name | `c66e9d85ddd7bb98a60b1823e1cc7cb27035da727744c03735317f2106da80e8.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:46:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74aafcae56a21581c61978458f7d39e2` |
| SHA-1 | `e2e0763120c39e4c10e05a2b21a805e6288d0683` |
| SHA-256 | `c66e9d85ddd7bb98a60b1823e1cc7cb27035da727744c03735317f2106da80e8` |
| SHA3-384 | `00656e506831dab0451005988c34d4f62404b852c451b2614b0ad01496143c5cb76322ecbc5c085f92cfbc1d5cc348fb` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1BB71B54160505AF2D94CE37F8487B895FD4EB248A2C84B0F0398D81A2F7507BB1D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DB8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DBG++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_087_c66e9d85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c66e9d85ddd7bb98a60b1823e1cc7cb27035da727744c03735317f2106da80e8"
    family = "VShell"
    file_name = "c66e9d85ddd7bb98a60b1823e1cc7cb27035da727744c03735317f2106da80e8.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:46:09"
  condition:
    hash.sha256(0, filesize) == "c66e9d85ddd7bb98a60b1823e1cc7cb27035da727744c03735317f2106da80e8"
}
```

### Sample 88: `f50d920a6bd6b6c1`

| Field | Value |
|---|---|
| SHA-256 | `f50d920a6bd6b6c12fd4f6ffb828b5528a14c6f371c08ac43b213291bf2937a7` |
| Family label | `Mirai` |
| File name | `f50d920a6bd6b6c12fd4f6ffb828b5528a14c6f371c08ac43b213291bf2937a7.elf` |
| File type | `elf` |
| First seen | `2026-09-13 20:45:06` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `766f1a35753cd48d1372eca3a14a43ea` |
| SHA-1 | `03e4df61f8a3ceffd4308b586728b42c18b6b268` |
| SHA-256 | `f50d920a6bd6b6c12fd4f6ffb828b5528a14c6f371c08ac43b213291bf2937a7` |
| SHA3-384 | `81ff37ee22954a5235adf496be47a172eead12116f0c836f07ba8f325afc057588b278879a756391444be18a65987b42` |
| TLSH | `T1B5125147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5AlTTej6TNJ9V9Nddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTcTTfTpVtdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_f50d920a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f50d920a6bd6b6c12fd4f6ffb828b5528a14c6f371c08ac43b213291bf2937a7"
    family = "Mirai"
    file_name = "f50d920a6bd6b6c12fd4f6ffb828b5528a14c6f371c08ac43b213291bf2937a7.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:45:06"
  condition:
    hash.sha256(0, filesize) == "f50d920a6bd6b6c12fd4f6ffb828b5528a14c6f371c08ac43b213291bf2937a7"
}
```

### Sample 89: `2155ee0755c0daa5`

| Field | Value |
|---|---|
| SHA-256 | `2155ee0755c0daa58c70d6532db297aa06c473a3779617e56bc154da2974524e` |
| Family label | `VShell` |
| File name | `2155ee0755c0daa58c70d6532db297aa06c473a3779617e56bc154da2974524e.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:41:04` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `853694dba542b9b75fe7d4466c45e28e` |
| SHA-1 | `c346b49400f52e9a396a1f4de1720ed770bbf4fb` |
| SHA-256 | `2155ee0755c0daa58c70d6532db297aa06c473a3779617e56bc154da2974524e` |
| SHA3-384 | `415f2144cc950ec674aa2359ae2774086bd437bdb8e4decd0aff9f6b86116703e219cfa0fef2fd53c37a669fef6e1983` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T11191A5C5F75BE6B6EC1C07F500A379A4C4682E18927C9B468FE16F0C3C111AA3D2DA52` |
| SSDEEP | `48:6I7lwe7zF08SLJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl19091q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_089_2155ee07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2155ee0755c0daa58c70d6532db297aa06c473a3779617e56bc154da2974524e"
    family = "VShell"
    file_name = "2155ee0755c0daa58c70d6532db297aa06c473a3779617e56bc154da2974524e.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:41:04"
  condition:
    hash.sha256(0, filesize) == "2155ee0755c0daa58c70d6532db297aa06c473a3779617e56bc154da2974524e"
}
```

### Sample 90: `fc04b7b1134f7c2f`

| Field | Value |
|---|---|
| SHA-256 | `fc04b7b1134f7c2f1d7e9fb71294d9c623e4c5455284ceb562af3b22b06fb0d0` |
| Family label | `VShell` |
| File name | `fc04b7b1134f7c2f1d7e9fb71294d9c623e4c5455284ceb562af3b22b06fb0d0.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:41:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7feadd4cc0844a7f69205e2d86a37dc1` |
| SHA-1 | `9b186757e35ad517c1e8654c97cb7809723794f4` |
| SHA-256 | `fc04b7b1134f7c2f1d7e9fb71294d9c623e4c5455284ceb562af3b22b06fb0d0` |
| SHA3-384 | `25a2ba9d14ad64a87dd2274ca9a72eacfdf68940640d6202d88a961fb7087c21cf87fd9488b7cf252b1272acde558a9b` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1BB715088F3136AF5E43C87F84093A514D059ABB8C250AE4D5E60281E3C210BA265AF96` |
| SSDEEP | `48:6Icwm03t2WSJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jmtQSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_090_fc04b7b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc04b7b1134f7c2f1d7e9fb71294d9c623e4c5455284ceb562af3b22b06fb0d0"
    family = "VShell"
    file_name = "fc04b7b1134f7c2f1d7e9fb71294d9c623e4c5455284ceb562af3b22b06fb0d0.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:41:01"
  condition:
    hash.sha256(0, filesize) == "fc04b7b1134f7c2f1d7e9fb71294d9c623e4c5455284ceb562af3b22b06fb0d0"
}
```

### Sample 91: `b680dd93e62b2b59`

| Field | Value |
|---|---|
| SHA-256 | `b680dd93e62b2b59831e0bd17721693f40af3697ca01054fba1d2318329a7dd6` |
| Family label | `Mirai` |
| File name | `b680dd93e62b2b59831e0bd17721693f40af3697ca01054fba1d2318329a7dd6.elf` |
| File type | `elf` |
| First seen | `2026-09-13 20:26:29` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6cef2b07579654b2b52221f43d467cb` |
| SHA-1 | `2013e6cf5c34e00c228e73dff5c5bb3213473ee2` |
| SHA-256 | `b680dd93e62b2b59831e0bd17721693f40af3697ca01054fba1d2318329a7dd6` |
| SHA3-384 | `576a1c6e2fb0635aaa05b7b1b418f3f5d89881574e5f9284c1baa33ca5285afc39d1405d2d02ed819b9fd4d3875ccc96` |
| TLSH | `T1E3125147A2D1CE7FC8E813384457122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5ilTTej6TNJ9VHNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTyTTfTpVTdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_b680dd93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b680dd93e62b2b59831e0bd17721693f40af3697ca01054fba1d2318329a7dd6"
    family = "Mirai"
    file_name = "b680dd93e62b2b59831e0bd17721693f40af3697ca01054fba1d2318329a7dd6.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:26:29"
  condition:
    hash.sha256(0, filesize) == "b680dd93e62b2b59831e0bd17721693f40af3697ca01054fba1d2318329a7dd6"
}
```

### Sample 92: `c1fed7ca6574f470`

| Field | Value |
|---|---|
| SHA-256 | `c1fed7ca6574f4705efddac6d028554da5b0b0c905d61fc9083f60b577ce6a80` |
| Family label | `VShell` |
| File name | `c1fed7ca6574f4705efddac6d028554da5b0b0c905d61fc9083f60b577ce6a80.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:25:07` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15d5b98040322e38a63a37618f149a59` |
| SHA-1 | `b493f79bcf1811891cdac18dbd73b7976ea9ecef` |
| SHA-256 | `c1fed7ca6574f4705efddac6d028554da5b0b0c905d61fc9083f60b577ce6a80` |
| SHA3-384 | `f5b1b5930c1c2d75f5631979508ef6f66b6fc8b4798b947c20d54c05ce0491ba7c8e40f13a98cda8edfc9f4ff8aff697` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T15B71B54160505AF2D94DA37F8587B8A5FD4EB248A2C80B0F079C981A3F7507BB0DD613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DsPtjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DKt++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_092_c1fed7ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1fed7ca6574f4705efddac6d028554da5b0b0c905d61fc9083f60b577ce6a80"
    family = "VShell"
    file_name = "c1fed7ca6574f4705efddac6d028554da5b0b0c905d61fc9083f60b577ce6a80.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:25:07"
  condition:
    hash.sha256(0, filesize) == "c1fed7ca6574f4705efddac6d028554da5b0b0c905d61fc9083f60b577ce6a80"
}
```

### Sample 93: `27bcc30e9cb698c2`

| Field | Value |
|---|---|
| SHA-256 | `27bcc30e9cb698c20bed734237dc3d929c34c70415ab79b90610ac698d768bf0` |
| Family label | `VShell` |
| File name | `27bcc30e9cb698c20bed734237dc3d929c34c70415ab79b90610ac698d768bf0.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:15:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8321ee3ed60ccf7c4fa84d1c8e95be0c` |
| SHA-1 | `31d7fd38bc07bc5160e0a4f57b82123f4e7b9ae8` |
| SHA-256 | `27bcc30e9cb698c20bed734237dc3d929c34c70415ab79b90610ac698d768bf0` |
| SHA3-384 | `19ab95a2fbaf75bc43c8f94ae5d15798c69314868834ebbd59c018ff9d2cbc479745a13e06fb16c48ce59eca950f4319` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T16B71B54160941AF2D94CA37F8487B899FD5EB248A2C84B0F0398D81A2F7547BB0DA613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DN8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DNG++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_093_27bcc30e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27bcc30e9cb698c20bed734237dc3d929c34c70415ab79b90610ac698d768bf0"
    family = "VShell"
    file_name = "27bcc30e9cb698c20bed734237dc3d929c34c70415ab79b90610ac698d768bf0.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:15:11"
  condition:
    hash.sha256(0, filesize) == "27bcc30e9cb698c20bed734237dc3d929c34c70415ab79b90610ac698d768bf0"
}
```

### Sample 94: `76dc6cd13100f369`

| Field | Value |
|---|---|
| SHA-256 | `76dc6cd13100f369d4926d28ffb9cb1a0771d211bb36a9ab02b93fa857452149` |
| Family label | `Mirai` |
| File name | `76dc6cd13100f369d4926d28ffb9cb1a0771d211bb36a9ab02b93fa857452149.elf` |
| File type | `elf` |
| First seen | `2026-09-13 20:15:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c05c484663630a36cf29e6015e40bf1` |
| SHA-1 | `8e101a7ed4b6de0928d5bbb2d3df6e853fb45a4f` |
| SHA-256 | `76dc6cd13100f369d4926d28ffb9cb1a0771d211bb36a9ab02b93fa857452149` |
| SHA3-384 | `f3ee2c531641ab7efc5f2f409bf64919d1afda4c1f693cb956bc5e427e421a0c359621441a978a18144720ffbadb323b` |
| TLSH | `T1F5E16207E2D5CD72D8CD133847931749213AC86EAB83EF03650C1999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFS146jwz7cSym4S2ofahbpZiQ:fsue7c9JcFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_76dc6cd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76dc6cd13100f369d4926d28ffb9cb1a0771d211bb36a9ab02b93fa857452149"
    family = "Mirai"
    file_name = "76dc6cd13100f369d4926d28ffb9cb1a0771d211bb36a9ab02b93fa857452149.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:15:08"
  condition:
    hash.sha256(0, filesize) == "76dc6cd13100f369d4926d28ffb9cb1a0771d211bb36a9ab02b93fa857452149"
}
```

### Sample 95: `1dfa69826e4ac3ec`

| Field | Value |
|---|---|
| SHA-256 | `1dfa69826e4ac3ec19da8e653ea207232e2814029d7ed6699ee3aeb28998216a` |
| Family label | `Snowlight` |
| File name | `1dfa69826e4ac3ec19da8e653ea207232e2814029d7ed6699ee3aeb28998216a.elf` |
| File type | `elf` |
| First seen | `2026-09-13 20:10:22` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a07fc0fb701129e93bebd00a230ed6a` |
| SHA-1 | `ccfc795cb54569ed0dbb64d7ac5ccf3245bb99c4` |
| SHA-256 | `1dfa69826e4ac3ec19da8e653ea207232e2814029d7ed6699ee3aeb28998216a` |
| SHA3-384 | `65685fe0451bfa744c2c9e6bdf8423d00226ea709edad35b279d26db4cd9cd5ae8f38af7425cf7dd62c03002bfa94960` |
| TLSH | `T1A9E16017E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw39Jheuhih5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbNJhA/Zz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_095_1dfa6982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dfa69826e4ac3ec19da8e653ea207232e2814029d7ed6699ee3aeb28998216a"
    family = "Snowlight"
    file_name = "1dfa69826e4ac3ec19da8e653ea207232e2814029d7ed6699ee3aeb28998216a.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:10:22"
  condition:
    hash.sha256(0, filesize) == "1dfa69826e4ac3ec19da8e653ea207232e2814029d7ed6699ee3aeb28998216a"
}
```

### Sample 96: `813407349f7cdce8`

| Field | Value |
|---|---|
| SHA-256 | `813407349f7cdce84985a19a38f8f138c1ff8ab8d2dbde71392873beb9881685` |
| Family label | `Snowlight` |
| File name | `813407349f7cdce84985a19a38f8f138c1ff8ab8d2dbde71392873beb9881685.elf` |
| File type | `elf` |
| First seen | `2026-09-13 20:10:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e1365060f2d61d3683ca44b9694c07b` |
| SHA-1 | `60ae6959e0cf50ddf840eb898a8da98018143bbd` |
| SHA-256 | `813407349f7cdce84985a19a38f8f138c1ff8ab8d2dbde71392873beb9881685` |
| SHA3-384 | `303946958cc1b1dda40663658fb9a821263778e8ba227d7e23e2306b96e9f38a9c43d38bd0a020ebdaa48e04568617c6` |
| TLSH | `T13B123F47A2D0CE3FC8D9533844A7122472B794BEDF629713064815B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6kH5ML09V1J9G8Ymf+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWH3ZMWT1Ym2hrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_096_81340734
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "813407349f7cdce84985a19a38f8f138c1ff8ab8d2dbde71392873beb9881685"
    family = "Snowlight"
    file_name = "813407349f7cdce84985a19a38f8f138c1ff8ab8d2dbde71392873beb9881685.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:10:07"
  condition:
    hash.sha256(0, filesize) == "813407349f7cdce84985a19a38f8f138c1ff8ab8d2dbde71392873beb9881685"
}
```

### Sample 97: `54e27f31669d1d0c`

| Field | Value |
|---|---|
| SHA-256 | `54e27f31669d1d0c56514ceb76cf62bfa5c606ad3ec24cfef430837d2a01f071` |
| Family label | `VShell` |
| File name | `54e27f31669d1d0c56514ceb76cf62bfa5c606ad3ec24cfef430837d2a01f071.exe` |
| File type | `exe` |
| First seen | `2026-09-13 20:05:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `569eee59870595f82727f28e7e217298` |
| SHA-1 | `7071a9bcdf0af8428b5fa585148177912c68d6c1` |
| SHA-256 | `54e27f31669d1d0c56514ceb76cf62bfa5c606ad3ec24cfef430837d2a01f071` |
| SHA3-384 | `3fba89f8de11a307212a382cb55e066d152ee3e7c559ae8f92690bfd3e79bee40d49a5f81b63113c2894d4f67dd6d5ae` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1F991A5C6F757E6B2EC1C07F500A379A4C4682E14827C9B574FA16F0C3C111AA3C7DA12` |
| SSDEEP | `48:6I7lwe7AF08SFbJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1q09Flq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_097_54e27f31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54e27f31669d1d0c56514ceb76cf62bfa5c606ad3ec24cfef430837d2a01f071"
    family = "VShell"
    file_name = "54e27f31669d1d0c56514ceb76cf62bfa5c606ad3ec24cfef430837d2a01f071.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:05:49"
  condition:
    hash.sha256(0, filesize) == "54e27f31669d1d0c56514ceb76cf62bfa5c606ad3ec24cfef430837d2a01f071"
}
```

### Sample 98: `637f57ed440b7e9e`

| Field | Value |
|---|---|
| SHA-256 | `637f57ed440b7e9e080cbe29776764e7403ee67f200bf133b393bab181ed6e6b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 20:01:23` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9874138960d507fd71ba8fa59f1250c0` |
| SHA-256 | `637f57ed440b7e9e080cbe29776764e7403ee67f200bf133b393bab181ed6e6b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_637f57ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "637f57ed440b7e9e080cbe29776764e7403ee67f200bf133b393bab181ed6e6b"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 20:01:23"
  condition:
    hash.sha256(0, filesize) == "637f57ed440b7e9e080cbe29776764e7403ee67f200bf133b393bab181ed6e6b"
}
```

### Sample 99: `02298b94b0729f26`

| Field | Value |
|---|---|
| SHA-256 | `02298b94b0729f263f3dfa55d5692cdc88ffa3a41727ca09c2a3ee22318a0aa9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 20:01:18` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c78c6e50bc4e464f7efcaa03a1dc2a6f` |
| SHA-256 | `02298b94b0729f263f3dfa55d5692cdc88ffa3a41727ca09c2a3ee22318a0aa9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_02298b94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02298b94b0729f263f3dfa55d5692cdc88ffa3a41727ca09c2a3ee22318a0aa9"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 20:01:18"
  condition:
    hash.sha256(0, filesize) == "02298b94b0729f263f3dfa55d5692cdc88ffa3a41727ca09c2a3ee22318a0aa9"
}
```

### Sample 100: `4ed90b3becfb26ff`

| Field | Value |
|---|---|
| SHA-256 | `4ed90b3becfb26ff25459808b80390aff3380445534b3aa8e3bb01998aea9347` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 20:01:14` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b53c45d1527067539acd08a5ca08b973` |
| SHA-256 | `4ed90b3becfb26ff25459808b80390aff3380445534b3aa8e3bb01998aea9347` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_4ed90b3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ed90b3becfb26ff25459808b80390aff3380445534b3aa8e3bb01998aea9347"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 20:01:14"
  condition:
    hash.sha256(0, filesize) == "4ed90b3becfb26ff25459808b80390aff3380445534b3aa8e3bb01998aea9347"
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
 * Generated: 2026-09-14T05:05:30.972891+00:00
 */

rule MalwareBazaar_unknown_001_a13860e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a13860e9645e1493d0dbe32f05ea675e907eff8444f255de0b7eb1b61506a97b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-14 05:05:03"
  condition:
    hash.sha256(0, filesize) == "a13860e9645e1493d0dbe32f05ea675e907eff8444f255de0b7eb1b61506a97b"
}

rule MalwareBazaar_unknown_002_8749dc2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8749dc2d450640cfa6a935458073fef0d4a81d9b0abb29cd1638bdf1544f2c48"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-14 05:02:30"
  condition:
    hash.sha256(0, filesize) == "8749dc2d450640cfa6a935458073fef0d4a81d9b0abb29cd1638bdf1544f2c48"
}

rule MalwareBazaar_unknown_003_3cb1feed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cb1feed97e63a55c639dad81b2e9051892420b4966fb661da24b0b6ad0bfdd3"
    family = "unknown"
    file_name = "3cb1feed97e63a55c639dad81b2e9051892420b4966fb661da24b0b6ad0bfdd3.bin"
    file_type = "zip"
    first_seen = "2026-09-14 05:00:57"
  condition:
    hash.sha256(0, filesize) == "3cb1feed97e63a55c639dad81b2e9051892420b4966fb661da24b0b6ad0bfdd3"
}

rule MalwareBazaar_unknown_004_1d5ecdcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d5ecdcfec8f414b6d7ec5038a154baa88c3c3584949bf0fd3cef69022687859"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-14 04:54:05"
  condition:
    hash.sha256(0, filesize) == "1d5ecdcfec8f414b6d7ec5038a154baa88c3c3584949bf0fd3cef69022687859"
}

rule MalwareBazaar_unknown_005_c2c46e82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2c46e82c334da5c665ea02d5840dd70f138279d3a17572623b55f7430196ca4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-14 04:44:56"
  condition:
    hash.sha256(0, filesize) == "c2c46e82c334da5c665ea02d5840dd70f138279d3a17572623b55f7430196ca4"
}

rule MalwareBazaar_unknown_006_adba2761
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adba27615403539d9bde6f67a578237441e48076ea62d4e895f038a6c836d2d7"
    family = "unknown"
    file_name = "stage1_script.txt"
    file_type = "unknown"
    first_seen = "2026-09-14 04:38:09"
  condition:
    hash.sha256(0, filesize) == "adba27615403539d9bde6f67a578237441e48076ea62d4e895f038a6c836d2d7"
}

rule MalwareBazaar_unknown_007_204b5d23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc"
    family = "unknown"
    file_name = "macho_204b5d236e43.bin"
    file_type = "macho"
    first_seen = "2026-09-14 04:38:06"
  condition:
    hash.sha256(0, filesize) == "204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc"
}

rule MalwareBazaar_VShell_008_e71180c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e71180c84e4b5fd0f49090facc0ed59a9e76c1e1f79d6e880d0f1cfb44e40366"
    family = "VShell"
    file_name = "e71180c84e4b5fd0f49090facc0ed59a9e76c1e1f79d6e880d0f1cfb44e40366.exe"
    file_type = "exe"
    first_seen = "2026-09-14 04:31:26"
  condition:
    hash.sha256(0, filesize) == "e71180c84e4b5fd0f49090facc0ed59a9e76c1e1f79d6e880d0f1cfb44e40366"
}

rule MalwareBazaar_VShell_009_1e25bb36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e25bb36f94f904fd7c4a2d88752fa57c127a533276d0259b6f245386bbe3bd8"
    family = "VShell"
    file_name = "1e25bb36f94f904fd7c4a2d88752fa57c127a533276d0259b6f245386bbe3bd8.exe"
    file_type = "exe"
    first_seen = "2026-09-14 04:31:23"
  condition:
    hash.sha256(0, filesize) == "1e25bb36f94f904fd7c4a2d88752fa57c127a533276d0259b6f245386bbe3bd8"
}

rule MalwareBazaar_Snowlight_010_d42dd98e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d42dd98e3d93614afd3343c080e890a4e59da42e10ab04d1eef0150d3bfba54b"
    family = "Snowlight"
    file_name = "d42dd98e3d93614afd3343c080e890a4e59da42e10ab04d1eef0150d3bfba54b.elf"
    file_type = "elf"
    first_seen = "2026-09-14 04:31:20"
  condition:
    hash.sha256(0, filesize) == "d42dd98e3d93614afd3343c080e890a4e59da42e10ab04d1eef0150d3bfba54b"
}

rule MalwareBazaar_VShell_011_01ade49d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01ade49da5924459befd34e293fa56b455eebc896374d259e744adc022acc5c2"
    family = "VShell"
    file_name = "01ade49da5924459befd34e293fa56b455eebc896374d259e744adc022acc5c2.exe"
    file_type = "exe"
    first_seen = "2026-09-14 04:31:17"
  condition:
    hash.sha256(0, filesize) == "01ade49da5924459befd34e293fa56b455eebc896374d259e744adc022acc5c2"
}

rule MalwareBazaar_unknown_012_576c3b07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "576c3b0717fdd274e9edf38aa97d0ae40ddde8455c89782d79d4d4ebb67ecec7"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-14 04:07:06"
  condition:
    hash.sha256(0, filesize) == "576c3b0717fdd274e9edf38aa97d0ae40ddde8455c89782d79d4d4ebb67ecec7"
}

rule MalwareBazaar_unknown_013_933115a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "933115a4ffd430275f259515fbeb6a5a7096fc5bf4906ee1b1bd44407c19a4af"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-14 04:04:19"
  condition:
    hash.sha256(0, filesize) == "933115a4ffd430275f259515fbeb6a5a7096fc5bf4906ee1b1bd44407c19a4af"
}

rule MalwareBazaar_unknown_014_21a9c0f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21a9c0f4749b6f3338c32d321c3fcc7234782a855f1af9d4cc272aff1a5a1112"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-14 03:54:53"
  condition:
    hash.sha256(0, filesize) == "21a9c0f4749b6f3338c32d321c3fcc7234782a855f1af9d4cc272aff1a5a1112"
}

rule MalwareBazaar_unknown_015_bd2c0f97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd2c0f97b36cb7deecd7039bef3ce34302355d0cc8ef57422d5ac5f81b739b36"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-14 03:53:52"
  condition:
    hash.sha256(0, filesize) == "bd2c0f97b36cb7deecd7039bef3ce34302355d0cc8ef57422d5ac5f81b739b36"
}

rule MalwareBazaar_unknown_016_81591d89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81591d89a7283bb11e05ce80e00256bea9218acbfcec5542cd9ffda9bd18db8a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-14 03:47:38"
  condition:
    hash.sha256(0, filesize) == "81591d89a7283bb11e05ce80e00256bea9218acbfcec5542cd9ffda9bd18db8a"
}

rule MalwareBazaar_RemusStealer_017_3f4545a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f4545a5f15fe892f21df9ee911af2ed27a8e0fff9084c6b32b5056d9d18c187"
    family = "RemusStealer"
    file_name = "C2C63147E280ABE9FDE6EFA535C13CE5.exe"
    file_type = "exe"
    first_seen = "2026-09-14 03:20:15"
  condition:
    hash.sha256(0, filesize) == "3f4545a5f15fe892f21df9ee911af2ed27a8e0fff9084c6b32b5056d9d18c187"
}

rule MalwareBazaar_RemcosRAT_018_e51ee514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e51ee5140bead9c974f22988b80899cc2d10ab9efe6301853f2babe552c330f3"
    family = "RemcosRAT"
    file_name = "Phyllosoma.vbs"
    file_type = "vbs"
    first_seen = "2026-09-14 03:11:48"
  condition:
    hash.sha256(0, filesize) == "e51ee5140bead9c974f22988b80899cc2d10ab9efe6301853f2babe552c330f3"
}

rule MalwareBazaar_unknown_019_a2718a82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2718a829cf311f77dc8d9fdbd50246921b7783c8192827e79e007acf96ea6ca"
    family = "unknown"
    file_name = "a2718a829cf311f77dc8d9fdbd50246921b7783c8192827e79e007acf96ea6ca"
    file_type = "elf"
    first_seen = "2026-09-14 03:08:18"
  condition:
    hash.sha256(0, filesize) == "a2718a829cf311f77dc8d9fdbd50246921b7783c8192827e79e007acf96ea6ca"
}

rule MalwareBazaar_unknown_020_604495ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "604495eeedb9f4124706a35b0907213716f43af17e7662e15e8c15eb41c13c46"
    family = "unknown"
    file_name = "FedEx_AWB_456789.js"
    file_type = "js"
    first_seen = "2026-09-14 02:57:08"
  condition:
    hash.sha256(0, filesize) == "604495eeedb9f4124706a35b0907213716f43af17e7662e15e8c15eb41c13c46"
}

rule MalwareBazaar_VShell_021_07a7afd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07a7afd2a891cbd8b1600d0327a6832d596b655011b9fc79265c7e068bc8fc85"
    family = "VShell"
    file_name = "07a7afd2a891cbd8b1600d0327a6832d596b655011b9fc79265c7e068bc8fc85.exe"
    file_type = "exe"
    first_seen = "2026-09-14 02:47:20"
  condition:
    hash.sha256(0, filesize) == "07a7afd2a891cbd8b1600d0327a6832d596b655011b9fc79265c7e068bc8fc85"
}

rule MalwareBazaar_VShell_022_2921c54b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2921c54b7d2c0a8a9dd0789cce72cdc55e58366d1fa064d44c059a2cb87d5657"
    family = "VShell"
    file_name = "2921c54b7d2c0a8a9dd0789cce72cdc55e58366d1fa064d44c059a2cb87d5657.exe"
    file_type = "exe"
    first_seen = "2026-09-14 02:47:16"
  condition:
    hash.sha256(0, filesize) == "2921c54b7d2c0a8a9dd0789cce72cdc55e58366d1fa064d44c059a2cb87d5657"
}

rule MalwareBazaar_Snowlight_023_86b9ddeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86b9ddeb528f6f6452d5b6eb209055f6c0378b5a2c2217e257209395e1d3a09a"
    family = "Snowlight"
    file_name = "86b9ddeb528f6f6452d5b6eb209055f6c0378b5a2c2217e257209395e1d3a09a.elf"
    file_type = "elf"
    first_seen = "2026-09-14 02:44:04"
  condition:
    hash.sha256(0, filesize) == "86b9ddeb528f6f6452d5b6eb209055f6c0378b5a2c2217e257209395e1d3a09a"
}

rule MalwareBazaar_Snowlight_024_9924976d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9924976d221c0003bee515bf23bdfdd003fdc3be04d827588b2bcdac5c034ead"
    family = "Snowlight"
    file_name = "9924976d221c0003bee515bf23bdfdd003fdc3be04d827588b2bcdac5c034ead.elf"
    file_type = "elf"
    first_seen = "2026-09-14 02:44:01"
  condition:
    hash.sha256(0, filesize) == "9924976d221c0003bee515bf23bdfdd003fdc3be04d827588b2bcdac5c034ead"
}

rule MalwareBazaar_VShell_025_8bff2ade
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bff2ade47175af18f41e33559a6bb4f46295e3e780f4c92b2a765da5604e7a5"
    family = "VShell"
    file_name = "8bff2ade47175af18f41e33559a6bb4f46295e3e780f4c92b2a765da5604e7a5.exe"
    file_type = "exe"
    first_seen = "2026-09-14 02:43:58"
  condition:
    hash.sha256(0, filesize) == "8bff2ade47175af18f41e33559a6bb4f46295e3e780f4c92b2a765da5604e7a5"
}

rule MalwareBazaar_Mirai_026_bb660634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb66063453efe9e93235121be7bbdbf8b38cbeae66c6163b8e2c101e9689e843"
    family = "Mirai"
    file_name = "bb66063453efe9e93235121be7bbdbf8b38cbeae66c6163b8e2c101e9689e843.elf"
    file_type = "elf"
    first_seen = "2026-09-14 02:43:56"
  condition:
    hash.sha256(0, filesize) == "bb66063453efe9e93235121be7bbdbf8b38cbeae66c6163b8e2c101e9689e843"
}

rule MalwareBazaar_Mirai_027_a0be1c01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0be1c01913ee53e6ea5fe2af57aec9024c5a02573e78b87ee10a8222f464b3f"
    family = "Mirai"
    file_name = "a0be1c01913ee53e6ea5fe2af57aec9024c5a02573e78b87ee10a8222f464b3f.elf"
    file_type = "elf"
    first_seen = "2026-09-14 02:43:08"
  condition:
    hash.sha256(0, filesize) == "a0be1c01913ee53e6ea5fe2af57aec9024c5a02573e78b87ee10a8222f464b3f"
}

rule MalwareBazaar_ValleyRAT_028_08f2c963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08f2c963906b126c0a10b47aa28eccebf8e209f3885c54489f771e948dc89b1a"
    family = "ValleyRAT"
    file_name = "2df08b445585f5db43736868b4bc8428.exe"
    file_type = "exe"
    first_seen = "2026-09-14 02:15:12"
  condition:
    hash.sha256(0, filesize) == "08f2c963906b126c0a10b47aa28eccebf8e209f3885c54489f771e948dc89b1a"
}

rule MalwareBazaar_Mirai_029_5ca5ff4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ca5ff4d4e479a7e6069b77df839af9d5d4fc2bbd26fcddb99dd27307f045f3e"
    family = "Mirai"
    file_name = "5ca5ff4d4e479a7e6069b77df839af9d5d4fc2bbd26fcddb99dd27307f045f3e"
    file_type = "elf"
    first_seen = "2026-09-14 02:09:26"
  condition:
    hash.sha256(0, filesize) == "5ca5ff4d4e479a7e6069b77df839af9d5d4fc2bbd26fcddb99dd27307f045f3e"
}

rule MalwareBazaar_unknown_030_3f4cf598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f4cf598411686071c8d89cbc0e20aab908543887207ac2e8ace4664d0da78fb"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-14 02:06:12"
  condition:
    hash.sha256(0, filesize) == "3f4cf598411686071c8d89cbc0e20aab908543887207ac2e8ace4664d0da78fb"
}

rule MalwareBazaar_njrat_031_d7d42055
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7d42055585aaf602b8a00d8d62afe4150da70b6063d6b1e671cd39845d0b5ab"
    family = "njrat"
    file_name = "284ad6b6c0c24e56c56b681f4492a1e3.exe"
    file_type = "exe"
    first_seen = "2026-09-14 00:50:07"
  condition:
    hash.sha256(0, filesize) == "d7d42055585aaf602b8a00d8d62afe4150da70b6063d6b1e671cd39845d0b5ab"
}

rule MalwareBazaar_Mirai_032_ae372be0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae372be0ba4977a6b72832e32a79663196ab90a1d0398c804502b4cd9e32109a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-14 00:29:18"
  condition:
    hash.sha256(0, filesize) == "ae372be0ba4977a6b72832e32a79663196ab90a1d0398c804502b4cd9e32109a"
}

rule MalwareBazaar_Mirai_033_0a7daa19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a7daa19d18fd62cabf0529e84f7eb126f8b1060313cbe11279e19087705ad20"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-14 00:28:57"
  condition:
    hash.sha256(0, filesize) == "0a7daa19d18fd62cabf0529e84f7eb126f8b1060313cbe11279e19087705ad20"
}

rule MalwareBazaar_unknown_034_4ba17752
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-14 00:28:23"
  condition:
    hash.sha256(0, filesize) == "4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718"
}

rule MalwareBazaar_Mirai_035_9cce9b23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cce9b23ed561bb603f4be736d7d280b0f0660c7aacca33281dd105b4c3bc166"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-14 00:27:58"
  condition:
    hash.sha256(0, filesize) == "9cce9b23ed561bb603f4be736d7d280b0f0660c7aacca33281dd105b4c3bc166"
}

rule MalwareBazaar_Mirai_036_5e89cb66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e89cb6636cce0d51af8ad82990ab860652459312c0456684346b7004dda38ef"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-09-14 00:27:57"
  condition:
    hash.sha256(0, filesize) == "5e89cb6636cce0d51af8ad82990ab860652459312c0456684346b7004dda38ef"
}

rule MalwareBazaar_unknown_037_6df8cea9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6df8cea94aa168c770b87e09590a1ddc9736bf25f6f8f13287d6581a3088fb58"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-14 00:27:56"
  condition:
    hash.sha256(0, filesize) == "6df8cea94aa168c770b87e09590a1ddc9736bf25f6f8f13287d6581a3088fb58"
}

rule MalwareBazaar_unknown_038_1be5de7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1be5de7ba4ca6634b97708a6aeaff3879cbba37a706a2e9618ae97332556e834"
    family = "unknown"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-14 00:27:54"
  condition:
    hash.sha256(0, filesize) == "1be5de7ba4ca6634b97708a6aeaff3879cbba37a706a2e9618ae97332556e834"
}

rule MalwareBazaar_unknown_039_e78d873a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e78d873a275cb56ace7042e6bb1c734d84545a08baf4f789712fba37280267e3"
    family = "unknown"
    file_name = "MV CHRYSANTHI S_VESSEL_DESCRIPTION.js"
    file_type = "js"
    first_seen = "2026-09-14 00:17:41"
  condition:
    hash.sha256(0, filesize) == "e78d873a275cb56ace7042e6bb1c734d84545a08baf4f789712fba37280267e3"
}

rule MalwareBazaar_unknown_040_d89ba576
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d89ba5767848eb5597d03a1d0ae30cc451050859fbc3b9fd3095a9474dd7d86b"
    family = "unknown"
    file_name = "Update.zip"
    file_type = "zip"
    first_seen = "2026-09-13 23:54:56"
  condition:
    hash.sha256(0, filesize) == "d89ba5767848eb5597d03a1d0ae30cc451050859fbc3b9fd3095a9474dd7d86b"
}

rule MalwareBazaar_unknown_041_b2bdb2a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2bdb2a4e93fb7d4e2d6f87fc27e8016f64b31a53d373bf34c1ceeec02875041"
    family = "unknown"
    file_name = "fakemas.ps1"
    file_type = "ps1"
    first_seen = "2026-09-13 23:34:01"
  condition:
    hash.sha256(0, filesize) == "b2bdb2a4e93fb7d4e2d6f87fc27e8016f64b31a53d373bf34c1ceeec02875041"
}

rule MalwareBazaar_unknown_042_67d2cf32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67d2cf32ba9cd0005efd57c1224360875c8c4ce69b8dec37af85c690c16c568e"
    family = "unknown"
    file_name = "meteor-rejects-addon-1.21.11-meteorrejects.net.jar.q"
    file_type = "zip"
    first_seen = "2026-09-13 23:07:16"
  condition:
    hash.sha256(0, filesize) == "67d2cf32ba9cd0005efd57c1224360875c8c4ce69b8dec37af85c690c16c568e"
}

rule MalwareBazaar_unknown_043_a383685c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a383685ca53827674ae3c34d1f51e33a7973126199f1743936eda7b8d0f22785"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 23:00:31"
  condition:
    hash.sha256(0, filesize) == "a383685ca53827674ae3c34d1f51e33a7973126199f1743936eda7b8d0f22785"
}

rule MalwareBazaar_unknown_044_83121330
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8312133009b0f8051bd53a403a561a898c55f714d6ea16af63b6e5f54d6010f1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-13 22:48:53"
  condition:
    hash.sha256(0, filesize) == "8312133009b0f8051bd53a403a561a898c55f714d6ea16af63b6e5f54d6010f1"
}

rule MalwareBazaar_unknown_045_fd5a365c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd5a365ce5ad86c6e0bf6356237f11c2c6ae8f0a350bf2a4c209f99e1d527f5e"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 22:44:54"
  condition:
    hash.sha256(0, filesize) == "fd5a365ce5ad86c6e0bf6356237f11c2c6ae8f0a350bf2a4c209f99e1d527f5e"
}

rule MalwareBazaar_unknown_046_07a7511e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07a7511ea03bea008d1b3f92db12e3bf654c6c2fd8383ab607bd3704230823b9"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 22:38:59"
  condition:
    hash.sha256(0, filesize) == "07a7511ea03bea008d1b3f92db12e3bf654c6c2fd8383ab607bd3704230823b9"
}

rule MalwareBazaar_unknown_047_a7246d70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7246d705df5e6b324d167f9caf965f2ff52696bb5e5a60ad65cccc6a2ac14de"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 22:38:58"
  condition:
    hash.sha256(0, filesize) == "a7246d705df5e6b324d167f9caf965f2ff52696bb5e5a60ad65cccc6a2ac14de"
}

rule MalwareBazaar_unknown_048_213a0320
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "213a0320b76bf702583ffd25754609124847c67527b3855b2321b1f8fd3b12e2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-13 22:11:32"
  condition:
    hash.sha256(0, filesize) == "213a0320b76bf702583ffd25754609124847c67527b3855b2321b1f8fd3b12e2"
}

rule MalwareBazaar_RemusStealer_049_37a3d7f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37a3d7f47dfaff63354658895d972008f6f5020c4b0936b49d76afdf1f2ad3c8"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-13 22:11:11"
  condition:
    hash.sha256(0, filesize) == "37a3d7f47dfaff63354658895d972008f6f5020c4b0936b49d76afdf1f2ad3c8"
}

rule MalwareBazaar_unknown_050_4fd414da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fd414da4fbb509545a7cc2322ceef048b345b1dea3fa3ec2d49c4abaad3430d"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 22:06:56"
  condition:
    hash.sha256(0, filesize) == "4fd414da4fbb509545a7cc2322ceef048b345b1dea3fa3ec2d49c4abaad3430d"
}

rule MalwareBazaar_unknown_051_8066d7da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8066d7da3ea0439109de27acd56c86f6300a280d2126883ade57ae78070d3ab3"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-13 22:05:58"
  condition:
    hash.sha256(0, filesize) == "8066d7da3ea0439109de27acd56c86f6300a280d2126883ade57ae78070d3ab3"
}

rule MalwareBazaar_unknown_052_0d32c254
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d32c25410242c6c30a4714e9366c29a4e1496e4862a00b02fd1267bf5c24fea"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 22:02:45"
  condition:
    hash.sha256(0, filesize) == "0d32c25410242c6c30a4714e9366c29a4e1496e4862a00b02fd1267bf5c24fea"
}

rule MalwareBazaar_unknown_053_cb7f9001
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb7f90012d79865f44643eee1a44f458f4ce3ac1dcd722f288b8b211a21b227c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-13 21:58:56"
  condition:
    hash.sha256(0, filesize) == "cb7f90012d79865f44643eee1a44f458f4ce3ac1dcd722f288b8b211a21b227c"
}

rule MalwareBazaar_unknown_054_d7289acb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7289acbe0802584dcc549dc3be603f628502ad0f97be943c45d46ee6a63ed59"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 21:49:53"
  condition:
    hash.sha256(0, filesize) == "d7289acbe0802584dcc549dc3be603f628502ad0f97be943c45d46ee6a63ed59"
}

rule MalwareBazaar_unknown_055_50e90fe8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50e90fe8ef4ebc412e361a409a043eae382c087adce8aaaf38ec8d1c03ba65ec"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-13 21:47:53"
  condition:
    hash.sha256(0, filesize) == "50e90fe8ef4ebc412e361a409a043eae382c087adce8aaaf38ec8d1c03ba65ec"
}

rule MalwareBazaar_unknown_056_c057475b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c057475b4c991df80b524e27f264bf8982f2fe6f6925c2cdcbe99eb9978fc28b"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 21:41:56"
  condition:
    hash.sha256(0, filesize) == "c057475b4c991df80b524e27f264bf8982f2fe6f6925c2cdcbe99eb9978fc28b"
}

rule MalwareBazaar_VShell_057_6fbe2a1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fbe2a1d1229aad5b33ee951d7cfdb4a4870e8ee342464742812d2e0c2b3c082"
    family = "VShell"
    file_name = "6fbe2a1d1229aad5b33ee951d7cfdb4a4870e8ee342464742812d2e0c2b3c082.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:36:23"
  condition:
    hash.sha256(0, filesize) == "6fbe2a1d1229aad5b33ee951d7cfdb4a4870e8ee342464742812d2e0c2b3c082"
}

rule MalwareBazaar_VShell_058_56377c8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56377c8e1746c4f368fc1408cfa1f18557ec0fb281de3c9236b280aba346be51"
    family = "VShell"
    file_name = "56377c8e1746c4f368fc1408cfa1f18557ec0fb281de3c9236b280aba346be51.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:31:30"
  condition:
    hash.sha256(0, filesize) == "56377c8e1746c4f368fc1408cfa1f18557ec0fb281de3c9236b280aba346be51"
}

rule MalwareBazaar_VShell_059_9d24316b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d24316bd0f8af89c590f6c37070f905cb60a15745fbe748b525e67d2a05b640"
    family = "VShell"
    file_name = "9d24316bd0f8af89c590f6c37070f905cb60a15745fbe748b525e67d2a05b640.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:31:28"
  condition:
    hash.sha256(0, filesize) == "9d24316bd0f8af89c590f6c37070f905cb60a15745fbe748b525e67d2a05b640"
}

rule MalwareBazaar_Mirai_060_7ff2e430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ff2e43032d97935091c5f5a9e3a83446cc4971e3451bdb78fc3ce25faaa52b5"
    family = "Mirai"
    file_name = "7ff2e43032d97935091c5f5a9e3a83446cc4971e3451bdb78fc3ce25faaa52b5.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:31:25"
  condition:
    hash.sha256(0, filesize) == "7ff2e43032d97935091c5f5a9e3a83446cc4971e3451bdb78fc3ce25faaa52b5"
}

rule MalwareBazaar_Mirai_061_015b2f5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "015b2f5ff28e4d6c8e242cc909f381544f5e0687df65700e65180045bc088ea0"
    family = "Mirai"
    file_name = "015b2f5ff28e4d6c8e242cc909f381544f5e0687df65700e65180045bc088ea0.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:31:22"
  condition:
    hash.sha256(0, filesize) == "015b2f5ff28e4d6c8e242cc909f381544f5e0687df65700e65180045bc088ea0"
}

rule MalwareBazaar_VShell_062_81f570ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81f570ea4d714e3b7a01981c311a83b5a60684ab21c3b3352c8905543f42519f"
    family = "VShell"
    file_name = "81f570ea4d714e3b7a01981c311a83b5a60684ab21c3b3352c8905543f42519f.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:31:19"
  condition:
    hash.sha256(0, filesize) == "81f570ea4d714e3b7a01981c311a83b5a60684ab21c3b3352c8905543f42519f"
}

rule MalwareBazaar_Vidar_063_31b05e13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31b05e1365291fe2486c3fa4e68e17ce11a07b4d97e419604f0fbbb2b137f49e"
    family = "Vidar"
    file_name = "p?t=e604e2f7dc0d11e53fee29481106a781_3a723106a8cd40dce6893cabb402f98cbe38086e"
    file_type = "exe"
    first_seen = "2026-09-13 21:27:39"
  condition:
    hash.sha256(0, filesize) == "31b05e1365291fe2486c3fa4e68e17ce11a07b4d97e419604f0fbbb2b137f49e"
}

rule MalwareBazaar_unknown_064_2595487d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2595487dc6b82f6a9a7ef88dcb826fefcdca5a32323b840f7248796dd2461220"
    family = "unknown"
    file_name = "b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:21:21"
  condition:
    hash.sha256(0, filesize) == "2595487dc6b82f6a9a7ef88dcb826fefcdca5a32323b840f7248796dd2461220"
}

rule MalwareBazaar_unknown_065_b1bb369c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e"
    family = "unknown"
    file_name = "b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:20:29"
  condition:
    hash.sha256(0, filesize) == "b1bb369c12b3c9576d2178f448cfc174387aad27a90b34f678574b6b6c41471e"
}

rule MalwareBazaar_VShell_066_77f87969
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77f879691310d233621ec53a68290d28e4aa83334e36a2069e91074cbe3dcfeb"
    family = "VShell"
    file_name = "77f879691310d233621ec53a68290d28e4aa83334e36a2069e91074cbe3dcfeb.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:11:56"
  condition:
    hash.sha256(0, filesize) == "77f879691310d233621ec53a68290d28e4aa83334e36a2069e91074cbe3dcfeb"
}

rule MalwareBazaar_VShell_067_46c75a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46c75a86d2493710bd827e4ff84f7d6412d53ba9d8c4fc8e844de8af338c88ee"
    family = "VShell"
    file_name = "46c75a86d2493710bd827e4ff84f7d6412d53ba9d8c4fc8e844de8af338c88ee.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:11:54"
  condition:
    hash.sha256(0, filesize) == "46c75a86d2493710bd827e4ff84f7d6412d53ba9d8c4fc8e844de8af338c88ee"
}

rule MalwareBazaar_VShell_068_804111c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "804111c64e49ef400093f53e16f65a8607de9489e1d052c2e6bdda2cfa7fcf77"
    family = "VShell"
    file_name = "804111c64e49ef400093f53e16f65a8607de9489e1d052c2e6bdda2cfa7fcf77.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:11:05"
  condition:
    hash.sha256(0, filesize) == "804111c64e49ef400093f53e16f65a8607de9489e1d052c2e6bdda2cfa7fcf77"
}

rule MalwareBazaar_VShell_069_25f946d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25f946d5bebb35015546c90f6256716e4283f8540aaf31773d06098fbf645801"
    family = "VShell"
    file_name = "25f946d5bebb35015546c90f6256716e4283f8540aaf31773d06098fbf645801.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:11:02"
  condition:
    hash.sha256(0, filesize) == "25f946d5bebb35015546c90f6256716e4283f8540aaf31773d06098fbf645801"
}

rule MalwareBazaar_VShell_070_46f4cd43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46f4cd435ca39c8fc2f1814fd9740a7ee9716207f5351d21008672ab466149eb"
    family = "VShell"
    file_name = "46f4cd435ca39c8fc2f1814fd9740a7ee9716207f5351d21008672ab466149eb.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:11:00"
  condition:
    hash.sha256(0, filesize) == "46f4cd435ca39c8fc2f1814fd9740a7ee9716207f5351d21008672ab466149eb"
}

rule MalwareBazaar_VShell_071_e4955c3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4955c3c33a1363472dffa0cbac8505fc443d4d4228a6dd5ab569fd194f9d918"
    family = "VShell"
    file_name = "e4955c3c33a1363472dffa0cbac8505fc443d4d4228a6dd5ab569fd194f9d918.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:10:56"
  condition:
    hash.sha256(0, filesize) == "e4955c3c33a1363472dffa0cbac8505fc443d4d4228a6dd5ab569fd194f9d918"
}

rule MalwareBazaar_VShell_072_ab42877d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab42877d03155a4b5a5cc662e1d86df4c00201281b357fae9d2463827bf0de61"
    family = "VShell"
    file_name = "ab42877d03155a4b5a5cc662e1d86df4c00201281b357fae9d2463827bf0de61.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:10:54"
  condition:
    hash.sha256(0, filesize) == "ab42877d03155a4b5a5cc662e1d86df4c00201281b357fae9d2463827bf0de61"
}

rule MalwareBazaar_VShell_073_ad7829bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad7829bf9fbc471369b48b47703ba4e7dbc58769a4f38285404c5c7ec6bdce16"
    family = "VShell"
    file_name = "ad7829bf9fbc471369b48b47703ba4e7dbc58769a4f38285404c5c7ec6bdce16.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:10:51"
  condition:
    hash.sha256(0, filesize) == "ad7829bf9fbc471369b48b47703ba4e7dbc58769a4f38285404c5c7ec6bdce16"
}

rule MalwareBazaar_Snowlight_074_83c3b078
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83c3b0789133e767350a3fbb1010851546473a0726bf876cd70e9d40f7f4bcf6"
    family = "Snowlight"
    file_name = "83c3b0789133e767350a3fbb1010851546473a0726bf876cd70e9d40f7f4bcf6.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:05:14"
  condition:
    hash.sha256(0, filesize) == "83c3b0789133e767350a3fbb1010851546473a0726bf876cd70e9d40f7f4bcf6"
}

rule MalwareBazaar_VShell_075_46dcb2cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46dcb2cbab575cb8a4a8d608c70c6acdc34b18e7ffbf0c479e177a48c6822a08"
    family = "VShell"
    file_name = "46dcb2cbab575cb8a4a8d608c70c6acdc34b18e7ffbf0c479e177a48c6822a08.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:05:11"
  condition:
    hash.sha256(0, filesize) == "46dcb2cbab575cb8a4a8d608c70c6acdc34b18e7ffbf0c479e177a48c6822a08"
}

rule MalwareBazaar_Snowlight_076_94eb3e7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94eb3e7e60a010665022d1d8cd9fd38a3c9e4d08a535f4384b63b95441de2630"
    family = "Snowlight"
    file_name = "94eb3e7e60a010665022d1d8cd9fd38a3c9e4d08a535f4384b63b95441de2630.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:05:09"
  condition:
    hash.sha256(0, filesize) == "94eb3e7e60a010665022d1d8cd9fd38a3c9e4d08a535f4384b63b95441de2630"
}

rule MalwareBazaar_unknown_077_5b48a3bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b48a3bf7827e461849c3b29b96775dc7e5e38766f51d0562ed73d352d082e41"
    family = "unknown"
    file_name = "5b48a3bf7827e461849c3b29b96775dc7e5e38766f51d0562ed73d352d082e41.exe"
    file_type = "exe"
    first_seen = "2026-09-13 21:01:40"
  condition:
    hash.sha256(0, filesize) == "5b48a3bf7827e461849c3b29b96775dc7e5e38766f51d0562ed73d352d082e41"
}

rule MalwareBazaar_Snowlight_078_b36d30ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b36d30ad0a646eeed5f02b48ac6b02f2cd2c125df298252dc1070aeff80de3e3"
    family = "Snowlight"
    file_name = "b36d30ad0a646eeed5f02b48ac6b02f2cd2c125df298252dc1070aeff80de3e3.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:00:43"
  condition:
    hash.sha256(0, filesize) == "b36d30ad0a646eeed5f02b48ac6b02f2cd2c125df298252dc1070aeff80de3e3"
}

rule MalwareBazaar_Mirai_079_666c4c42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "666c4c426bb64bdc5ecbd03826b3d8cd495b452d23985bdae13e35f187ac56ab"
    family = "Mirai"
    file_name = "666c4c426bb64bdc5ecbd03826b3d8cd495b452d23985bdae13e35f187ac56ab.elf"
    file_type = "elf"
    first_seen = "2026-09-13 21:00:40"
  condition:
    hash.sha256(0, filesize) == "666c4c426bb64bdc5ecbd03826b3d8cd495b452d23985bdae13e35f187ac56ab"
}

rule MalwareBazaar_VShell_080_33808f42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33808f4224a8260786123b1a662fbf6fef738031e03c6b47128c64f125e68f8b"
    family = "VShell"
    file_name = "33808f4224a8260786123b1a662fbf6fef738031e03c6b47128c64f125e68f8b.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:56:24"
  condition:
    hash.sha256(0, filesize) == "33808f4224a8260786123b1a662fbf6fef738031e03c6b47128c64f125e68f8b"
}

rule MalwareBazaar_Snowlight_081_7386686d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7386686dd98bb774d352990a5f84fa210aff26ac6ecd5858857d2f54d8a04c07"
    family = "Snowlight"
    file_name = "7386686dd98bb774d352990a5f84fa210aff26ac6ecd5858857d2f54d8a04c07.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:55:07"
  condition:
    hash.sha256(0, filesize) == "7386686dd98bb774d352990a5f84fa210aff26ac6ecd5858857d2f54d8a04c07"
}

rule MalwareBazaar_VShell_082_2d5f0510
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d5f05106b2cd88b2d6eabc7813f30a60c95823af166548c804be3e128028bf1"
    family = "VShell"
    file_name = "2d5f05106b2cd88b2d6eabc7813f30a60c95823af166548c804be3e128028bf1.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:55:04"
  condition:
    hash.sha256(0, filesize) == "2d5f05106b2cd88b2d6eabc7813f30a60c95823af166548c804be3e128028bf1"
}

rule MalwareBazaar_Mirai_083_9991d998
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9991d9987da7f9be952fba8199baa69237c42d10a66eb60a52bf77143145111e"
    family = "Mirai"
    file_name = "9991d9987da7f9be952fba8199baa69237c42d10a66eb60a52bf77143145111e.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:55:01"
  condition:
    hash.sha256(0, filesize) == "9991d9987da7f9be952fba8199baa69237c42d10a66eb60a52bf77143145111e"
}

rule MalwareBazaar_VShell_084_e5c7b3d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5c7b3d6dec0c89701fa8c94cdc5d1353770a04edd5eeaf987c45630647e74d8"
    family = "VShell"
    file_name = "e5c7b3d6dec0c89701fa8c94cdc5d1353770a04edd5eeaf987c45630647e74d8.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:51:15"
  condition:
    hash.sha256(0, filesize) == "e5c7b3d6dec0c89701fa8c94cdc5d1353770a04edd5eeaf987c45630647e74d8"
}

rule MalwareBazaar_VShell_085_a2a067ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2a067ca282f9034391e2cf1b4d2fe681cbe0326588d507b3cff5b2fab70bc7e"
    family = "VShell"
    file_name = "a2a067ca282f9034391e2cf1b4d2fe681cbe0326588d507b3cff5b2fab70bc7e.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:51:13"
  condition:
    hash.sha256(0, filesize) == "a2a067ca282f9034391e2cf1b4d2fe681cbe0326588d507b3cff5b2fab70bc7e"
}

rule MalwareBazaar_VShell_086_994b914d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "994b914dc77a84a9adbe5ba1c49cd6bab320924c4d0938134d5c47ce9cedee8b"
    family = "VShell"
    file_name = "994b914dc77a84a9adbe5ba1c49cd6bab320924c4d0938134d5c47ce9cedee8b.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:51:10"
  condition:
    hash.sha256(0, filesize) == "994b914dc77a84a9adbe5ba1c49cd6bab320924c4d0938134d5c47ce9cedee8b"
}

rule MalwareBazaar_VShell_087_c66e9d85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c66e9d85ddd7bb98a60b1823e1cc7cb27035da727744c03735317f2106da80e8"
    family = "VShell"
    file_name = "c66e9d85ddd7bb98a60b1823e1cc7cb27035da727744c03735317f2106da80e8.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:46:09"
  condition:
    hash.sha256(0, filesize) == "c66e9d85ddd7bb98a60b1823e1cc7cb27035da727744c03735317f2106da80e8"
}

rule MalwareBazaar_Mirai_088_f50d920a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f50d920a6bd6b6c12fd4f6ffb828b5528a14c6f371c08ac43b213291bf2937a7"
    family = "Mirai"
    file_name = "f50d920a6bd6b6c12fd4f6ffb828b5528a14c6f371c08ac43b213291bf2937a7.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:45:06"
  condition:
    hash.sha256(0, filesize) == "f50d920a6bd6b6c12fd4f6ffb828b5528a14c6f371c08ac43b213291bf2937a7"
}

rule MalwareBazaar_VShell_089_2155ee07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2155ee0755c0daa58c70d6532db297aa06c473a3779617e56bc154da2974524e"
    family = "VShell"
    file_name = "2155ee0755c0daa58c70d6532db297aa06c473a3779617e56bc154da2974524e.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:41:04"
  condition:
    hash.sha256(0, filesize) == "2155ee0755c0daa58c70d6532db297aa06c473a3779617e56bc154da2974524e"
}

rule MalwareBazaar_VShell_090_fc04b7b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc04b7b1134f7c2f1d7e9fb71294d9c623e4c5455284ceb562af3b22b06fb0d0"
    family = "VShell"
    file_name = "fc04b7b1134f7c2f1d7e9fb71294d9c623e4c5455284ceb562af3b22b06fb0d0.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:41:01"
  condition:
    hash.sha256(0, filesize) == "fc04b7b1134f7c2f1d7e9fb71294d9c623e4c5455284ceb562af3b22b06fb0d0"
}

rule MalwareBazaar_Mirai_091_b680dd93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b680dd93e62b2b59831e0bd17721693f40af3697ca01054fba1d2318329a7dd6"
    family = "Mirai"
    file_name = "b680dd93e62b2b59831e0bd17721693f40af3697ca01054fba1d2318329a7dd6.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:26:29"
  condition:
    hash.sha256(0, filesize) == "b680dd93e62b2b59831e0bd17721693f40af3697ca01054fba1d2318329a7dd6"
}

rule MalwareBazaar_VShell_092_c1fed7ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1fed7ca6574f4705efddac6d028554da5b0b0c905d61fc9083f60b577ce6a80"
    family = "VShell"
    file_name = "c1fed7ca6574f4705efddac6d028554da5b0b0c905d61fc9083f60b577ce6a80.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:25:07"
  condition:
    hash.sha256(0, filesize) == "c1fed7ca6574f4705efddac6d028554da5b0b0c905d61fc9083f60b577ce6a80"
}

rule MalwareBazaar_VShell_093_27bcc30e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27bcc30e9cb698c20bed734237dc3d929c34c70415ab79b90610ac698d768bf0"
    family = "VShell"
    file_name = "27bcc30e9cb698c20bed734237dc3d929c34c70415ab79b90610ac698d768bf0.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:15:11"
  condition:
    hash.sha256(0, filesize) == "27bcc30e9cb698c20bed734237dc3d929c34c70415ab79b90610ac698d768bf0"
}

rule MalwareBazaar_Mirai_094_76dc6cd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76dc6cd13100f369d4926d28ffb9cb1a0771d211bb36a9ab02b93fa857452149"
    family = "Mirai"
    file_name = "76dc6cd13100f369d4926d28ffb9cb1a0771d211bb36a9ab02b93fa857452149.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:15:08"
  condition:
    hash.sha256(0, filesize) == "76dc6cd13100f369d4926d28ffb9cb1a0771d211bb36a9ab02b93fa857452149"
}

rule MalwareBazaar_Snowlight_095_1dfa6982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dfa69826e4ac3ec19da8e653ea207232e2814029d7ed6699ee3aeb28998216a"
    family = "Snowlight"
    file_name = "1dfa69826e4ac3ec19da8e653ea207232e2814029d7ed6699ee3aeb28998216a.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:10:22"
  condition:
    hash.sha256(0, filesize) == "1dfa69826e4ac3ec19da8e653ea207232e2814029d7ed6699ee3aeb28998216a"
}

rule MalwareBazaar_Snowlight_096_81340734
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "813407349f7cdce84985a19a38f8f138c1ff8ab8d2dbde71392873beb9881685"
    family = "Snowlight"
    file_name = "813407349f7cdce84985a19a38f8f138c1ff8ab8d2dbde71392873beb9881685.elf"
    file_type = "elf"
    first_seen = "2026-09-13 20:10:07"
  condition:
    hash.sha256(0, filesize) == "813407349f7cdce84985a19a38f8f138c1ff8ab8d2dbde71392873beb9881685"
}

rule MalwareBazaar_VShell_097_54e27f31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54e27f31669d1d0c56514ceb76cf62bfa5c606ad3ec24cfef430837d2a01f071"
    family = "VShell"
    file_name = "54e27f31669d1d0c56514ceb76cf62bfa5c606ad3ec24cfef430837d2a01f071.exe"
    file_type = "exe"
    first_seen = "2026-09-13 20:05:49"
  condition:
    hash.sha256(0, filesize) == "54e27f31669d1d0c56514ceb76cf62bfa5c606ad3ec24cfef430837d2a01f071"
}

rule MalwareBazaar_unknown_098_637f57ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "637f57ed440b7e9e080cbe29776764e7403ee67f200bf133b393bab181ed6e6b"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 20:01:23"
  condition:
    hash.sha256(0, filesize) == "637f57ed440b7e9e080cbe29776764e7403ee67f200bf133b393bab181ed6e6b"
}

rule MalwareBazaar_unknown_099_02298b94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02298b94b0729f263f3dfa55d5692cdc88ffa3a41727ca09c2a3ee22318a0aa9"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 20:01:18"
  condition:
    hash.sha256(0, filesize) == "02298b94b0729f263f3dfa55d5692cdc88ffa3a41727ca09c2a3ee22318a0aa9"
}

rule MalwareBazaar_unknown_100_4ed90b3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ed90b3becfb26ff25459808b80390aff3380445534b3aa8e3bb01998aea9347"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 20:01:14"
  condition:
    hash.sha256(0, filesize) == "4ed90b3becfb26ff25459808b80390aff3380445534b3aa8e3bb01998aea9347"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

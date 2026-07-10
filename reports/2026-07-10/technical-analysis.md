# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-10

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 622 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 622 |
| Unique family labels | 15 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 65 |
| Mirai | 10 |
| RemcosRAT | 5 |
| Vidar | 4 |
| SalatStealer | 3 |
| Cobalt Strike | 2 |
| WannaCry | 2 |
| Efimer | 2 |
| RatonRAT | 1 |
| ValleyRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 43 |
| elf | 19 |
| unknown | 11 |
| sh | 8 |
| zip | 6 |
| dll | 5 |
| vbs | 3 |
| js | 3 |
| gz | 1 |
| 7z | 1 |

## Per-Sample Analysis

### Sample 1: `6953e6d2e8facd1a`

| Field | Value |
|---|---|
| SHA-256 | `6953e6d2e8facd1ad7eaef3d95e3aae39f660a539329df240582dfab4501b49b` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 03:52:00` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `914f0b43128f5ede1083809ab35b144c` |
| SHA-1 | `daa33e089ca3b9adbbf5bf3b12153c6323cd01d2` |
| SHA-256 | `6953e6d2e8facd1ad7eaef3d95e3aae39f660a539329df240582dfab4501b49b` |
| SHA3-384 | `b8f36779f0237cb0e6bbab0e61a9f6e39204bfe0637ce6ea17ff7bbae07753a9ac91a65e3de5ca0c5283095ff089d53d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T16CE6332878D000EAEAB3413CEED191A9E869B8A50736DC9F97D4D2B57D531D04E3A723` |
| SSDEEP | `393216:Vmqgf2Ssw+WfafHFBJcpzDFCaQuZy4XMCHWUjX7cuI3/PGTAI:VPJS+VNHcWaQu84XMb8X4H/O7` |
| ICON-DHASH | `d470f0e8e8e1f130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_6953e6d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6953e6d2e8facd1ad7eaef3d95e3aae39f660a539329df240582dfab4501b49b"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 03:52:00"
  condition:
    hash.sha256(0, filesize) == "6953e6d2e8facd1ad7eaef3d95e3aae39f660a539329df240582dfab4501b49b"
}
```

### Sample 2: `3563a0dd216236d5`

| Field | Value |
|---|---|
| SHA-256 | `3563a0dd216236d5f6f8bc871afe1f98f5bff78afe2d95f80276906dcdf278e2` |
| Family label | `RemcosRAT` |
| File name | `RFQGoodsLogisticsLandedCost20260710Returnurge.vbs` |
| File type | `vbs` |
| First seen | `2026-07-10 03:45:09` |
| Reporter | `abuse_ch` |
| Tags | `RAT, RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `093be3d92f4fcba7045f5e7616bd1337` |
| SHA-1 | `2d07a981108feef3cff710b5fc4aa88f3785a080` |
| SHA-256 | `3563a0dd216236d5f6f8bc871afe1f98f5bff78afe2d95f80276906dcdf278e2` |
| SHA3-384 | `b0d419cf5b64ae3be2e1cbf112b8cad1432d8184d4a8736c0e9369cb4f9858c008b3de5690f49788cb85cb0f33bba863` |
| TLSH | `T1CBA2F9F5CC4106958D035BF69C08BA20D0B54BE3E53044B5AD7EF3E8590AA68BE789DE` |
| SSDEEP | `384:s+p2IwI3TSbUBZldecpMLNvb6u0IEzisyt81+X1kz8wKDt3qw:suwbODd1py57Tt8oOYP` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_002_3563a0dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3563a0dd216236d5f6f8bc871afe1f98f5bff78afe2d95f80276906dcdf278e2"
    family = "RemcosRAT"
    file_name = "RFQGoodsLogisticsLandedCost20260710Returnurge.vbs"
    file_type = "vbs"
    first_seen = "2026-07-10 03:45:09"
  condition:
    hash.sha256(0, filesize) == "3563a0dd216236d5f6f8bc871afe1f98f5bff78afe2d95f80276906dcdf278e2"
}
```

### Sample 3: `1f08b33c61a20cb9`

| Field | Value |
|---|---|
| SHA-256 | `1f08b33c61a20cb9327b1a529df79f2072ba72646631619e622eb0c1e6a6e8f7` |
| Family label | `RemcosRAT` |
| File name | `Laminaterne.vbs` |
| File type | `vbs` |
| First seen | `2026-07-10 03:44:07` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6efcf29493c6363a552407059ab80c7c` |
| SHA-1 | `afcd03023b10a951bb4a612a30602938389b761b` |
| SHA-256 | `1f08b33c61a20cb9327b1a529df79f2072ba72646631619e622eb0c1e6a6e8f7` |
| SHA3-384 | `83cdef3e1dfbcad1b6b5727efa25b6e0b1ee4f06553b775f0577b58c3e7ac0e30ee8e8f3907613f009e9ed6dfdc586a0` |
| TLSH | `T1AEA24C76C94296445D070BB64C4EE62AD2954371E13100ED3E7CF36E2816A286FBDDDF` |
| SSDEEP | `384:s+p2IwI3TSbFkKEeeMtNuCNItZMnYiZzuUulO07j7vva8BLM:suwb5dEhQLN3YvlNueM` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_003_1f08b33c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f08b33c61a20cb9327b1a529df79f2072ba72646631619e622eb0c1e6a6e8f7"
    family = "RemcosRAT"
    file_name = "Laminaterne.vbs"
    file_type = "vbs"
    first_seen = "2026-07-10 03:44:07"
  condition:
    hash.sha256(0, filesize) == "1f08b33c61a20cb9327b1a529df79f2072ba72646631619e622eb0c1e6a6e8f7"
}
```

### Sample 4: `ff2fb9db58c022b5`

| Field | Value |
|---|---|
| SHA-256 | `ff2fb9db58c022b54bc0a49ec5b8c22c96bd6f8010ff28e8ef9988f68d298dbc` |
| Family label | `unknown` |
| File name | `ff2fb9db58c022b54bc0a49ec5b8c22c96bd6f8010ff28e8ef9988f68d298dbc` |
| File type | `sh` |
| First seen | `2026-07-10 03:22:10` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31736557521a8f943747472dafa86020` |
| SHA-1 | `0a8e31ca19a5fd304d9b9a298a9ca1adadf86793` |
| SHA-256 | `ff2fb9db58c022b54bc0a49ec5b8c22c96bd6f8010ff28e8ef9988f68d298dbc` |
| SHA3-384 | `738b96b4e008963a24af334550370679538a8ae82dbaca4d656f61916c4e5282d0bee50878c3ec232c439c3f893ae777` |
| TLSH | `T18A9131C6F8E491323302407DBDCAA0602797255B895BEC68B4AEEA113F1931C63E5F77` |
| SSDEEP | `96:HL7lYLbH87wIbzrxBFIoenuMDJh34wpQKlzGnbMZhb8T:HVYfH8E+zXeohKlCnb+1k` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_ff2fb9db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff2fb9db58c022b54bc0a49ec5b8c22c96bd6f8010ff28e8ef9988f68d298dbc"
    family = "unknown"
    file_name = "ff2fb9db58c022b54bc0a49ec5b8c22c96bd6f8010ff28e8ef9988f68d298dbc"
    file_type = "sh"
    first_seen = "2026-07-10 03:22:10"
  condition:
    hash.sha256(0, filesize) == "ff2fb9db58c022b54bc0a49ec5b8c22c96bd6f8010ff28e8ef9988f68d298dbc"
}
```

### Sample 5: `4919efb3417bed43`

| Field | Value |
|---|---|
| SHA-256 | `4919efb3417bed43e3b985f0c980f197cb59f4d7a4d2894834eb33347edc6831` |
| Family label | `unknown` |
| File name | `loader.decoded.txt` |
| File type | `unknown` |
| First seen | `2026-07-10 03:20:58` |
| Reporter | `anonymous` |
| Tags | `BeaverTail, ContagiousInterview, deobfuscated, strings` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25fdcb3f36536f5d3d67d1da669ec8d2` |
| SHA-256 | `4919efb3417bed43e3b985f0c980f197cb59f4d7a4d2894834eb33347edc6831` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_4919efb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4919efb3417bed43e3b985f0c980f197cb59f4d7a4d2894834eb33347edc6831"
    family = "unknown"
    file_name = "loader.decoded.txt"
    file_type = "unknown"
    first_seen = "2026-07-10 03:20:58"
  condition:
    hash.sha256(0, filesize) == "4919efb3417bed43e3b985f0c980f197cb59f4d7a4d2894834eb33347edc6831"
}
```

### Sample 6: `aa42289f45060a82`

| Field | Value |
|---|---|
| SHA-256 | `aa42289f45060a82c21197da722374d97d1c4cb91d315617c9b1f9ae88691fba` |
| Family label | `unknown` |
| File name | `parser.decoded.txt` |
| File type | `unknown` |
| First seen | `2026-07-10 03:20:56` |
| Reporter | `anonymous` |
| Tags | `BeaverTail, ContagiousInterview, deobfuscated, strings` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0987d67e729caeba9b56be1539632205` |
| SHA-256 | `aa42289f45060a82c21197da722374d97d1c4cb91d315617c9b1f9ae88691fba` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_aa42289f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa42289f45060a82c21197da722374d97d1c4cb91d315617c9b1f9ae88691fba"
    family = "unknown"
    file_name = "parser.decoded.txt"
    file_type = "unknown"
    first_seen = "2026-07-10 03:20:56"
  condition:
    hash.sha256(0, filesize) == "aa42289f45060a82c21197da722374d97d1c4cb91d315617c9b1f9ae88691fba"
}
```

### Sample 7: `e8573e97c75bec4b`

| Field | Value |
|---|---|
| SHA-256 | `e8573e97c75bec4b9645f40c94a1f961971aa28444e3726564f4dda1312aac25` |
| Family label | `RatonRAT` |
| File name | `ratonClient.exe` |
| File type | `exe` |
| First seen | `2026-07-10 03:10:30` |
| Reporter | `abuse_ch` |
| Tags | `exe, RatonRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a1983ef9feea7bdb06c17d5957db7aa` |
| SHA-1 | `3ef07367be035c6524b96fd552a57f309710b34b` |
| SHA-256 | `e8573e97c75bec4b9645f40c94a1f961971aa28444e3726564f4dda1312aac25` |
| SHA3-384 | `b47c326d7da7ba563f1367ce09466746ef5c4d90599e7ddfccf46c8eecd37c68a37dfe46428bbc9c4b20801a43347579` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18906CF407BD4CE1BE19F87B6B4F2021057B5EC15A796E70B2E90BAAC1CB37445E1839B` |
| SSDEEP | `49152:5mu4tq0WgVUlsHjkmiGWU5+5WeLGpMZ7iKPNgo9sk:Cq0WgVUuHjkDGjYQeqpgmltk` |

#### Technical Assessment

- The sample is tracked as `RatonRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RatonRAT_007_e8573e97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8573e97c75bec4b9645f40c94a1f961971aa28444e3726564f4dda1312aac25"
    family = "RatonRAT"
    file_name = "ratonClient.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:30"
  condition:
    hash.sha256(0, filesize) == "e8573e97c75bec4b9645f40c94a1f961971aa28444e3726564f4dda1312aac25"
}
```

### Sample 8: `539abaeb1d337bd7`

| Field | Value |
|---|---|
| SHA-256 | `539abaeb1d337bd77d51589b1debe5339e87f2e07f62235d9b1ada5a11d6d056` |
| Family label | `ValleyRAT` |
| File name | `1967745B78718A571407FCE13485412B.dll` |
| File type | `dll` |
| First seen | `2026-07-10 03:10:26` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1967745b78718a571407fce13485412b` |
| SHA-1 | `08998ae5a8c8634c098e9fd80a59fdf085d04c7a` |
| SHA-256 | `539abaeb1d337bd77d51589b1debe5339e87f2e07f62235d9b1ada5a11d6d056` |
| SHA3-384 | `fee60befad4baffb16f087958b445bae798b5834789ecd3f9ab4cb2e02b788de26ea8facb0bc5a2f86104cd64b7bc121` |
| IMPHASH | `51854b55cb5d96f3c48379e874452e51` |
| TLSH | `T156147D217280D236C1DB1638A9BB9FB31D7D6971076A85CBB3948E790E703D1BA3471E` |
| SSDEEP | `3072:WyNd6vSgEBrE5STBVOyyqGBoTPoEuEahUOl7vztHSd2GXxHJW8:WyNZBrxlxyqGGTpuEahUOl7LU1pW` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_008_539abaeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "539abaeb1d337bd77d51589b1debe5339e87f2e07f62235d9b1ada5a11d6d056"
    family = "ValleyRAT"
    file_name = "1967745B78718A571407FCE13485412B.dll"
    file_type = "dll"
    first_seen = "2026-07-10 03:10:26"
  condition:
    hash.sha256(0, filesize) == "539abaeb1d337bd77d51589b1debe5339e87f2e07f62235d9b1ada5a11d6d056"
}
```

### Sample 9: `c35055499d7bf391`

| Field | Value |
|---|---|
| SHA-256 | `c35055499d7bf39198746a21bac07fb902e6307818898d6f961f3fdddaff5bde` |
| Family label | `Cobalt Strike` |
| File name | `c35055499d7bf39198746a21bac07fb902e6307818898.exe` |
| File type | `exe` |
| First seen | `2026-07-10 03:10:23` |
| Reporter | `abuse_ch` |
| Tags | `Cobalt Strike, CobaltStrike, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd9284cedf382def729cf6450aec8e54` |
| SHA-1 | `9ad4cd770ff008c6368b50661c59a2e436877b52` |
| SHA-256 | `c35055499d7bf39198746a21bac07fb902e6307818898d6f961f3fdddaff5bde` |
| SHA3-384 | `8a9eb8b41f66a3210627abfa8a14f9c4f74ba1a223abf1c3f84cfc8c17b9b3a6e670d7ced589a8d14af9672e1329bc60` |
| IMPHASH | `ca85b6618b1e1cad2f59872f180b38c6` |
| TLSH | `T1BFD33BC7AFA5DD97DD15473844E78319133AF3904B864B132D20AA351E23BE0BF9768A` |
| SSDEEP | `1536:DFKkSAps4rasU4yamaCXRvW4eW3LNFNvtO1WUvMFMQiNsR8QHKH4RQ27:xK12PLivVLNFNvtOwdRPHKH0D7` |

#### Technical Assessment

- The sample is tracked as `Cobalt Strike` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Cobalt_Strike_009_c3505549
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c35055499d7bf39198746a21bac07fb902e6307818898d6f961f3fdddaff5bde"
    family = "Cobalt Strike"
    file_name = "c35055499d7bf39198746a21bac07fb902e6307818898.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:23"
  condition:
    hash.sha256(0, filesize) == "c35055499d7bf39198746a21bac07fb902e6307818898d6f961f3fdddaff5bde"
}
```

### Sample 10: `c0762bd8b3b098c6`

| Field | Value |
|---|---|
| SHA-256 | `c0762bd8b3b098c6d5300256f9e8bc67d45709dc244db37cc55c5e2b0312e907` |
| Family label | `RemcosRAT` |
| File name | `c0762bd8b3b098c6d5300256f9e8bc67d45709dc244db.exe` |
| File type | `exe` |
| First seen | `2026-07-10 03:10:20` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `983cca37c0534eb53f981fb4eb89a7f8` |
| SHA-1 | `b818f746e14dc148f6572c8ab264a62dbe6bc760` |
| SHA-256 | `c0762bd8b3b098c6d5300256f9e8bc67d45709dc244db37cc55c5e2b0312e907` |
| SHA3-384 | `47bbcdb05850a83f8223722ba6472ee903607d5d5a487ca434fcd128ac0fcdf116f9f1443ea96e2c3f1aaf854181f62a` |
| IMPHASH | `e77512f955eaf60ccff45e02d69234de` |
| TLSH | `T1BDA4BF01BAD2C072D57654300C3AE775DEBDBD212839897BB3D61D97FD30190A63AAB2` |
| SSDEEP | `12288:/13ak/mBXTG4/1v08KI7ZnMEF76JqmsvZQCS:tak/mBXTV/R0nEF76gFZh` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_010_c0762bd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0762bd8b3b098c6d5300256f9e8bc67d45709dc244db37cc55c5e2b0312e907"
    family = "RemcosRAT"
    file_name = "c0762bd8b3b098c6d5300256f9e8bc67d45709dc244db.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:20"
  condition:
    hash.sha256(0, filesize) == "c0762bd8b3b098c6d5300256f9e8bc67d45709dc244db37cc55c5e2b0312e907"
}
```

### Sample 11: `f35b6cb6af991bfa`

| Field | Value |
|---|---|
| SHA-256 | `f35b6cb6af991bfa735e039f6bc0e49c69759c015a2074b87eed8f20e4200135` |
| Family label | `RemcosRAT` |
| File name | `f35b6cb6af991bfa735e039f6bc0e49c69759c015a207.exe` |
| File type | `exe` |
| First seen | `2026-07-10 03:10:16` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `654607f31a256d943a2de9b63b30929c` |
| SHA-1 | `679fb2dbfe81808a883729d15cd03b99eda8d1ba` |
| SHA-256 | `f35b6cb6af991bfa735e039f6bc0e49c69759c015a2074b87eed8f20e4200135` |
| SHA3-384 | `2497caed94e21301f97044afeae2bde78c418c683c38105d98dee68f8108d6775c0c3856094ed0e2ab103b7a361ede99` |
| IMPHASH | `e77512f955eaf60ccff45e02d69234de` |
| TLSH | `T194A4BF01BAD2C072D57654300C3AE775DEBDBD212839897BB3D61D97FD30190A63AAB2` |
| SSDEEP | `12288:/13ak/mBXTG4/1v08KI7ZnMEF76JqmsvZQmS:tak/mBXTV/R0nEF76gFZZ` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_011_f35b6cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f35b6cb6af991bfa735e039f6bc0e49c69759c015a2074b87eed8f20e4200135"
    family = "RemcosRAT"
    file_name = "f35b6cb6af991bfa735e039f6bc0e49c69759c015a207.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:16"
  condition:
    hash.sha256(0, filesize) == "f35b6cb6af991bfa735e039f6bc0e49c69759c015a2074b87eed8f20e4200135"
}
```

### Sample 12: `34da1d049c923131`

| Field | Value |
|---|---|
| SHA-256 | `34da1d049c92313152f28cdf5bad644bff93cc6beca25e139453e20ed7a1a85f` |
| Family label | `RemcosRAT` |
| File name | `PO.bat.exe` |
| File type | `exe` |
| First seen | `2026-07-10 03:10:13` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13ed2a77b08df2b52e3420205e763a41` |
| SHA-1 | `6d8433dceb879d60c4fbcaf3c1fa66832d8ed101` |
| SHA-256 | `34da1d049c92313152f28cdf5bad644bff93cc6beca25e139453e20ed7a1a85f` |
| SHA3-384 | `541c09597efdf72f70f779f520b12a6b70fde857e31e0ebd1c18d08a1e9c919db93e5ab8f954417f5681eb64789ca8c1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F8551298330ADD12CA925FF00EB1D7B405680D98F811D343DEFABEEBB57E6856D09291` |
| SSDEEP | `24576:ImR6pFjWonBrNmUeBofK3O8GS6gSGtixOgWfdI8lf6vMwQEvPbof7jOd9EOae:IaixWIroUBSS8igVf6vMDwiOdt` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_012_34da1d04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34da1d049c92313152f28cdf5bad644bff93cc6beca25e139453e20ed7a1a85f"
    family = "RemcosRAT"
    file_name = "PO.bat.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:13"
  condition:
    hash.sha256(0, filesize) == "34da1d049c92313152f28cdf5bad644bff93cc6beca25e139453e20ed7a1a85f"
}
```

### Sample 13: `df4e36252bf8a2b1`

| Field | Value |
|---|---|
| SHA-256 | `df4e36252bf8a2b1dee291bcaf9e0505246cacc1d1ea9db3494f30c8506ba0cb` |
| Family label | `njrat` |
| File name | `1b622c451fcc9d83aad8bf45b1c42b5f.exe` |
| File type | `exe` |
| First seen | `2026-07-10 03:10:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b622c451fcc9d83aad8bf45b1c42b5f` |
| SHA-1 | `2e70ac7f1bdfc2f9912448ee2b6c2c478bef3aab` |
| SHA-256 | `df4e36252bf8a2b1dee291bcaf9e0505246cacc1d1ea9db3494f30c8506ba0cb` |
| SHA3-384 | `c29bf1f74db5618fd90a43d88b7b4c3db1797476cc16eac97b4aa7bbc005226e61e6f292d4516c056f15e59e6de72fc7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19993E94977E52524E0BF56F75471F2014E34B48B1612E39D98F219AA0B33AC44F8AFEB` |
| SSDEEP | `1536:UUNJD/HBZbszKu9AZp77r1jEwzGi1dD8DlgS:UUUzK4AZtHCi1dyy` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_013_df4e3625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df4e36252bf8a2b1dee291bcaf9e0505246cacc1d1ea9db3494f30c8506ba0cb"
    family = "njrat"
    file_name = "1b622c451fcc9d83aad8bf45b1c42b5f.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:09"
  condition:
    hash.sha256(0, filesize) == "df4e36252bf8a2b1dee291bcaf9e0505246cacc1d1ea9db3494f30c8506ba0cb"
}
```

### Sample 14: `ac255036bfc86ebf`

| Field | Value |
|---|---|
| SHA-256 | `ac255036bfc86ebfedcc638e79fb2cf98ac70942c325a52e45fa33c2eea0f063` |
| Family label | `unknown` |
| File name | `ORDER-27098-07PDF.vbs` |
| File type | `unknown` |
| First seen | `2026-07-10 03:10:06` |
| Reporter | `abuse_ch` |
| Tags | `RAT, vbs, WSHRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cfa26870f809a4d0a02cc23b7d4e648` |
| SHA-256 | `ac255036bfc86ebfedcc638e79fb2cf98ac70942c325a52e45fa33c2eea0f063` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_ac255036
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac255036bfc86ebfedcc638e79fb2cf98ac70942c325a52e45fa33c2eea0f063"
    family = "unknown"
    file_name = "ORDER-27098-07PDF.vbs"
    file_type = "unknown"
    first_seen = "2026-07-10 03:10:06"
  condition:
    hash.sha256(0, filesize) == "ac255036bfc86ebfedcc638e79fb2cf98ac70942c325a52e45fa33c2eea0f063"
}
```

### Sample 15: `b8165568c11eabc5`

| Field | Value |
|---|---|
| SHA-256 | `b8165568c11eabc56eb6f059fc02c64a7ae6e1ac6ab723abe76f99badc1ce293` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 03:09:40` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb2c1ff3b9fc5ac2e422ff889d2e5ad8` |
| SHA-1 | `5b1c8db8da4cdecbf22bd3d1e669e758bb4ea7e4` |
| SHA-256 | `b8165568c11eabc56eb6f059fc02c64a7ae6e1ac6ab723abe76f99badc1ce293` |
| SHA3-384 | `275e438287aae3c77aa7b0f37953900debde0ac33355f648261d9ef841b1c2e42f4229b30e51571664990ace5bbe74f3` |
| IMPHASH | `5a08440e22a99b9fda864d620400de65` |
| TLSH | `T1E295128FEA6907F5C93991BC44215312EAA8BC024F10EEEB29A53D765C57AFD1F39700` |
| SSDEEP | `49152:5trVb1mWmnvHO4ZP6bRXgCleFFvnWSuRJiQ6wN2quEaKlqU/:+1GQC0jWSkJiQ6wUqu0F` |
| ICON-DHASH | `f0f89a9a9adcf830` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_b8165568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8165568c11eabc56eb6f059fc02c64a7ae6e1ac6ab723abe76f99badc1ce293"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 03:09:40"
  condition:
    hash.sha256(0, filesize) == "b8165568c11eabc56eb6f059fc02c64a7ae6e1ac6ab723abe76f99badc1ce293"
}
```

### Sample 16: `c25a08d59a215dce`

| Field | Value |
|---|---|
| SHA-256 | `c25a08d59a215dce54ce9aed5636d5958eb6b87daee3b40ae666f92951be37f6` |
| Family label | `unknown` |
| File name | `dsetup.dll` |
| File type | `dll` |
| First seen | `2026-07-10 02:57:29` |
| Reporter | `iamaachum` |
| Tags | `ConnectWise, dll, micro-vpn-expres-top` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ef0113bc0e9e2d0efe9021c0b3421e8` |
| SHA-1 | `bbf57300b43c53857d6fb25f46b9f15b76fbf382` |
| SHA-256 | `c25a08d59a215dce54ce9aed5636d5958eb6b87daee3b40ae666f92951be37f6` |
| SHA3-384 | `f06570bb5e6d1c4e2da7ae6efebe8896517bdd86896f901993fc064b99f7245ae5eb4ac4ac89bb7fe7e3aac2ef11b642` |
| IMPHASH | `f1783104dc04202edb1280448f79953f` |
| TLSH | `T12A083312B2C8E53EE0B71A35687FE211593B7A147A22CD0F27A0095C5FF7A406E29F57` |
| SSDEEP | `1572864:s/2rwnAPGuRuAKEFx3hWt+dVGsmFi9lL8YycbwcnzCm2fSngYfian7MiefV3Qd6O:saKA+AnFx3hWt+ndZ8Yycbjnun2vxPt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_c25a08d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c25a08d59a215dce54ce9aed5636d5958eb6b87daee3b40ae666f92951be37f6"
    family = "unknown"
    file_name = "dsetup.dll"
    file_type = "dll"
    first_seen = "2026-07-10 02:57:29"
  condition:
    hash.sha256(0, filesize) == "c25a08d59a215dce54ce9aed5636d5958eb6b87daee3b40ae666f92951be37f6"
}
```

### Sample 17: `f101a45d8085c6fc`

| Field | Value |
|---|---|
| SHA-256 | `f101a45d8085c6fc1fa111aa9219abe2adcc16705f3ebeb91626fbd085ba9d13` |
| Family label | `unknown` |
| File name | `ryujinx.zip` |
| File type | `zip` |
| First seen | `2026-07-10 02:56:41` |
| Reporter | `iamaachum` |
| Tags | `ConnectWise, micro-vpn-expres-top, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11724fce9f766a838d7dc18e4b2132d6` |
| SHA-1 | `4b54fdc4845245edb8b64a8adf5156a43f3a1827` |
| SHA-256 | `f101a45d8085c6fc1fa111aa9219abe2adcc16705f3ebeb91626fbd085ba9d13` |
| SHA3-384 | `3694721d9f93e76339910f1e8d9297adc5a6bd7b0814ff6e12606f849730c753f9f2a675d6a52a9e7890cd7f5ffded2c` |
| TLSH | `T17C0833406C98FE7D3D0668B624EDA11F25263A0443B10777FBF9227E628B751DEA4B13` |
| SSDEEP | `1572864:L92refS7gojGaqKR3Nporg118m0Fml3ldyUyIWgQcmx9HjfjO2EjP7ueL9YJYu+v:LsISuaxR3Nporgff1pdWgQrxViPr9K+v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_f101a45d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f101a45d8085c6fc1fa111aa9219abe2adcc16705f3ebeb91626fbd085ba9d13"
    family = "unknown"
    file_name = "ryujinx.zip"
    file_type = "zip"
    first_seen = "2026-07-10 02:56:41"
  condition:
    hash.sha256(0, filesize) == "f101a45d8085c6fc1fa111aa9219abe2adcc16705f3ebeb91626fbd085ba9d13"
}
```

### Sample 18: `c6a712524646dd27`

| Field | Value |
|---|---|
| SHA-256 | `c6a712524646dd2775b996884b15277439de1962b27a450530fdbd0de460cffa` |
| Family label | `unknown` |
| File name | `dsetup.dll` |
| File type | `dll` |
| First seen | `2026-07-10 02:55:27` |
| Reporter | `iamaachum` |
| Tags | `ConnectWise, dll, micro-vpn-expres-top` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `191618ab8994285c12d07a34e5a8de93` |
| SHA-1 | `91c4fc43e22a2478b3170c576fc016141183bc8c` |
| SHA-256 | `c6a712524646dd2775b996884b15277439de1962b27a450530fdbd0de460cffa` |
| SHA3-384 | `b2cb46ef67be20ba086702d54a43e45e5584b931b0e51f930451633e81cc9f0c8960975358ec7d915909cf0f31231e2b` |
| IMPHASH | `f1783104dc04202edb1280448f79953f` |
| TLSH | `T19F08332176E1C472E2B32630257AE675857A7E609B3482DF73443A1D5AF36C0A938F73` |
| SSDEEP | `1572864:pVH+LN90Idp9z8UC/lImB3m2wo2DT27bFd6j905UDLIAnJy:zH+LXVfz8UCNZB3xwF22j9R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_c6a71252
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6a712524646dd2775b996884b15277439de1962b27a450530fdbd0de460cffa"
    family = "unknown"
    file_name = "dsetup.dll"
    file_type = "dll"
    first_seen = "2026-07-10 02:55:27"
  condition:
    hash.sha256(0, filesize) == "c6a712524646dd2775b996884b15277439de1962b27a450530fdbd0de460cffa"
}
```

### Sample 19: `5c01b3af2ca6b789`

| Field | Value |
|---|---|
| SHA-256 | `5c01b3af2ca6b789a8006d902f738f81bb99c1696b352c1e6444fdd78b37cdcf` |
| Family label | `unknown` |
| File name | `letsview_setup.zip` |
| File type | `zip` |
| First seen | `2026-07-10 02:54:28` |
| Reporter | `iamaachum` |
| Tags | `ConnectWise, micro-vpn-expres-top, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa8a532dbd86570df852f5992d3b297d` |
| SHA-1 | `608aebc6b8a73526d4f9f0cd9d736b185e64210b` |
| SHA-256 | `5c01b3af2ca6b789a8006d902f738f81bb99c1696b352c1e6444fdd78b37cdcf` |
| SHA3-384 | `72bae1234819a556e0870c6284fad9d831fa66cf52ba0365fc784f67f4e262e4391be410b65f3816bc5202b47b33cdec` |
| TLSH | `T168083331A1E25AD0B69872E950620C7C817BCB29DFC887FF734B5987E48B2D67854C63` |
| SSDEEP | `1572864:iN3ctthkiHPf/Ye0/7Y2VHY6sm0Xx+XnX1ijfydorV0oXvt7:I3ctvfn/Ye0jnVHZsh+Ujfr17` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_5c01b3af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c01b3af2ca6b789a8006d902f738f81bb99c1696b352c1e6444fdd78b37cdcf"
    family = "unknown"
    file_name = "letsview_setup.zip"
    file_type = "zip"
    first_seen = "2026-07-10 02:54:28"
  condition:
    hash.sha256(0, filesize) == "5c01b3af2ca6b789a8006d902f738f81bb99c1696b352c1e6444fdd78b37cdcf"
}
```

### Sample 20: `b4d0f84e44a782b5`

| Field | Value |
|---|---|
| SHA-256 | `b4d0f84e44a782b5c98c48a34a5442bde600f59e451a067f5ea28d3cbe528966` |
| Family label | `unknown` |
| File name | `dsetup.dll` |
| File type | `dll` |
| First seen | `2026-07-10 02:53:00` |
| Reporter | `iamaachum` |
| Tags | `ConnectWise, dll, micro.vpn-expres.top` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a8a4e95d3d586b050d51e9fed7f1315` |
| SHA-1 | `aa2dd7567fc5df4ccde7fee6efc7669920451031` |
| SHA-256 | `b4d0f84e44a782b5c98c48a34a5442bde600f59e451a067f5ea28d3cbe528966` |
| SHA3-384 | `4b07f41b458b252bfc4bfaf8ddc64621b3ac2bef3b55b21bf910924a7a77f5ec3b367244a55813fbbc8fa3f0c3a9055d` |
| IMPHASH | `f1783104dc04202edb1280448f79953f` |
| TLSH | `T17AD7334232E8C075F1B20EB47A79D2E25D773E5126BCD14E2A21776D1AF3780A438F66` |
| SSDEEP | `1572864:0nphedyp6W3/22dI1DdnBynqT9cFx1O0w0DMuuceTJGtdsIe:0XYyp6W3+2S1ZUqExA0w2MukJGt8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_b4d0f84e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4d0f84e44a782b5c98c48a34a5442bde600f59e451a067f5ea28d3cbe528966"
    family = "unknown"
    file_name = "dsetup.dll"
    file_type = "dll"
    first_seen = "2026-07-10 02:53:00"
  condition:
    hash.sha256(0, filesize) == "b4d0f84e44a782b5c98c48a34a5442bde600f59e451a067f5ea28d3cbe528966"
}
```

### Sample 21: `36bd5ca4aaedc3d7`

| Field | Value |
|---|---|
| SHA-256 | `36bd5ca4aaedc3d7f377de097ba915eaf4774fb07cb080aec7e5359c7128c1a6` |
| Family label | `unknown` |
| File name | `ivcam.zip` |
| File type | `zip` |
| First seen | `2026-07-10 02:52:19` |
| Reporter | `iamaachum` |
| Tags | `ConnectWise, micro-vpn-expres-top, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `660630762cf338cf269b41c3b9335c5d` |
| SHA-1 | `d42090aca71e2381227f71e6361f7deb29c27835` |
| SHA-256 | `36bd5ca4aaedc3d7f377de097ba915eaf4774fb07cb080aec7e5359c7128c1a6` |
| SHA3-384 | `7dc8ebb3237d629f42ab28dd02a158508bd40ff80cddd93e867cb66c74fe5f0876c7d6f1af8b9bdc6b5e925d07215381` |
| TLSH | `T1E9D73322745C52D92DAC0564E6079FEB66379B2703BCF11B3EDA1789FD875A38232E04` |
| SSDEEP | `1572864:oxNJGVoP05MiR29l33xQdsDvRLh3+OIa5gyGeolzeZAFOMehv:GPcoP05M199WGNhOOIugyKzeZAChv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_36bd5ca4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36bd5ca4aaedc3d7f377de097ba915eaf4774fb07cb080aec7e5359c7128c1a6"
    family = "unknown"
    file_name = "ivcam.zip"
    file_type = "zip"
    first_seen = "2026-07-10 02:52:19"
  condition:
    hash.sha256(0, filesize) == "36bd5ca4aaedc3d7f377de097ba915eaf4774fb07cb080aec7e5359c7128c1a6"
}
```

### Sample 22: `81438ec974a24527`

| Field | Value |
|---|---|
| SHA-256 | `81438ec974a24527a4218f451214e4abeda74c6d112c2b2366571d1ba8eb700e` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 02:52:01` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46a7d8d9303db9b9c5301b6d080088cc` |
| SHA-1 | `27312667da1771cefb8880a0364d41ed056b59f0` |
| SHA-256 | `81438ec974a24527a4218f451214e4abeda74c6d112c2b2366571d1ba8eb700e` |
| SHA3-384 | `a8666417b697dfe9bc11120e583dc556b5139ee1706a6b6374b58d2af7a5912b200ed3d43a023a7da3cb844cab5056c5` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T120E63354B5E020FDE9B7423CFEE1818AE4D570224F75CA9B47688AF4AF131E06D3DA16` |
| SSDEEP | `393216:4Xp7kyys4TMx9h4BdKDXMCHWUjXMcuI3/PGTAI:GhuTMJ4Bd2XMb8XZH/O7` |
| ICON-DHASH | `5471d4d8c8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_81438ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81438ec974a24527a4218f451214e4abeda74c6d112c2b2366571d1ba8eb700e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 02:52:01"
  condition:
    hash.sha256(0, filesize) == "81438ec974a24527a4218f451214e4abeda74c6d112c2b2366571d1ba8eb700e"
}
```

### Sample 23: `53f0f718847c209a`

| Field | Value |
|---|---|
| SHA-256 | `53f0f718847c209a482f3fa3f52a5ce5245af57da1aa03ecb84d9c3133750955` |
| Family label | `unknown` |
| File name | `dsetup.dll` |
| File type | `dll` |
| First seen | `2026-07-10 02:37:04` |
| Reporter | `iamaachum` |
| Tags | `ConnectWise, dll, micro-vpn-expres-top` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cabbe67c383da28e50dc3d48e1aecc3` |
| SHA-1 | `ebfa946e7c15049e439ca507349c5ff4b92458e0` |
| SHA-256 | `53f0f718847c209a482f3fa3f52a5ce5245af57da1aa03ecb84d9c3133750955` |
| SHA3-384 | `5804f9e5e2604a7638863c6f86151d7e623023b319a7d74d452c057e12bfa02c7887c7ad9162494dc5f8562ca6cffe9a` |
| IMPHASH | `f1783104dc04202edb1280448f79953f` |
| TLSH | `T1A208335172E6D02AF0BB1B322AF6E25088FB7E41A931D90E2691555D4FF3A406D3CF27` |
| SSDEEP | `1572864:BdnnKkFZmw7lq97FqK0+/PM6c/8PpqnZcbjmXijmEYZ0bNpUdJdYv:BBnK87lq97gCpcigZcbTjmVEzkvY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_53f0f718
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53f0f718847c209a482f3fa3f52a5ce5245af57da1aa03ecb84d9c3133750955"
    family = "unknown"
    file_name = "dsetup.dll"
    file_type = "dll"
    first_seen = "2026-07-10 02:37:04"
  condition:
    hash.sha256(0, filesize) == "53f0f718847c209a482f3fa3f52a5ce5245af57da1aa03ecb84d9c3133750955"
}
```

### Sample 24: `122bf0050365d7b9`

| Field | Value |
|---|---|
| SHA-256 | `122bf0050365d7b9ceec62e7359d03d6285db98f3c7bb898ef3cdc22e6d70f24` |
| Family label | `unknown` |
| File name | `winscp_setup.zip` |
| File type | `zip` |
| First seen | `2026-07-10 02:35:12` |
| Reporter | `iamaachum` |
| Tags | `ConnectWise, micro-vpn-expres-top, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14993201fb686ee32a4d46aaa77efb25` |
| SHA-1 | `778a4f1db0d26016142b6dc1b7efd68d6ce5e9bf` |
| SHA-256 | `122bf0050365d7b9ceec62e7359d03d6285db98f3c7bb898ef3cdc22e6d70f24` |
| SHA3-384 | `9f3cfc5a5eb4938deca232f832301b5415d7f49ea5d087f1650448986e8591553ce66adb22f19251395558115c2b4bc4` |
| TLSH | `T1A208335CEE93E2CFB005B9432FC2C741C648B4CBD6525989485B775B7EC9EC38AAC819` |
| SSDEEP | `1572864:jd1/QC7/U0XT2vnBsMi49/GU0RY716Nb+r7ynetEyAlI4TVFMlZHax8:jP/QiXT2vnCkR0Yc5+rltEJ/34Fa+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_122bf005
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "122bf0050365d7b9ceec62e7359d03d6285db98f3c7bb898ef3cdc22e6d70f24"
    family = "unknown"
    file_name = "winscp_setup.zip"
    file_type = "zip"
    first_seen = "2026-07-10 02:35:12"
  condition:
    hash.sha256(0, filesize) == "122bf0050365d7b9ceec62e7359d03d6285db98f3c7bb898ef3cdc22e6d70f24"
}
```

### Sample 25: `a6b325e695644dda`

| Field | Value |
|---|---|
| SHA-256 | `a6b325e695644ddaaf6edf0c41604179fd53d1e515afa52e5d526426a4644d76` |
| Family label | `SalatStealer` |
| File name | `setup-Happ.x64.exe` |
| File type | `exe` |
| First seen | `2026-07-10 02:32:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f77dafb7f7cf6d7c3318f8ff01fa5e6d` |
| SHA-1 | `cf236e17e176cacaa951e086637bf62c04635080` |
| SHA-256 | `a6b325e695644ddaaf6edf0c41604179fd53d1e515afa52e5d526426a4644d76` |
| SHA3-384 | `ded9ad679b49d47aa899b8206ef85b6f1409b0c476c38205e2a75880bbb32481dd9cdfe8c8c59d2e17f4ff32114f8030` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1BBC66B11FADB95F5E903583101ABB37F23315D048B28CB9BEB547B2AF87B6A11C66305` |
| SSDEEP | `98304:QyK5IeG7XBCrevMqG0arl+4HR4SG2Z1OENf:gInYekkarlvx/l9` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_025_a6b325e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6b325e695644ddaaf6edf0c41604179fd53d1e515afa52e5d526426a4644d76"
    family = "SalatStealer"
    file_name = "setup-Happ.x64.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:32:38"
  condition:
    hash.sha256(0, filesize) == "a6b325e695644ddaaf6edf0c41604179fd53d1e515afa52e5d526426a4644d76"
}
```

### Sample 26: `d632a7428a5a8a6c`

| Field | Value |
|---|---|
| SHA-256 | `d632a7428a5a8a6c4642ba4ddecfbbe96e28ed030a204156c5018527ba4a6b46` |
| Family label | `SalatStealer` |
| File name | `setup-Happ.x64.exe` |
| File type | `exe` |
| First seen | `2026-07-10 02:31:35` |
| Reporter | `iamaachum` |
| Tags | `exe, RUS, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d653ada71dcf3f24d2d6dd5ef22a169b` |
| SHA-1 | `ec84b042161c8037b5e6d556dc7795c10788f24c` |
| SHA-256 | `d632a7428a5a8a6c4642ba4ddecfbbe96e28ed030a204156c5018527ba4a6b46` |
| SHA3-384 | `b5ff3dcfad92c3a6d7b6dafda5149555c8a2557a1cdbca7f93d22d275a84036ee59441d59d1d42a0697b6572bb9dc80f` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T16DF53326F7A073C2C8E5137581D3DC0FA259B766FD26931610BCEDBA21A355BCD82872` |
| SSDEEP | `98304:XYNbHVjVmxjak/4JqxdLQJHLiyPRHlP5cJlD:oNbHJVd2dLkf7RYl` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_026_d632a742
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d632a7428a5a8a6c4642ba4ddecfbbe96e28ed030a204156c5018527ba4a6b46"
    family = "SalatStealer"
    file_name = "setup-Happ.x64.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:31:35"
  condition:
    hash.sha256(0, filesize) == "d632a7428a5a8a6c4642ba4ddecfbbe96e28ed030a204156c5018527ba4a6b46"
}
```

### Sample 27: `59eb2fad261dc13a`

| Field | Value |
|---|---|
| SHA-256 | `59eb2fad261dc13a1e9bfab3a57cd51a4841f82787130202ff348bbaf2c6409d` |
| Family label | `unknown` |
| File name | `nvd_driver_dll.exe` |
| File type | `exe` |
| First seen | `2026-07-10 02:12:22` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-RemusStealer, exe, kkc-vogueatelier-cc, ZigClipper` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44faf223cbf8b4bd1d4221476322fab4` |
| SHA-1 | `a11f2aeabbb8ebfa0e66c457ecdc06d232b4ca51` |
| SHA-256 | `59eb2fad261dc13a1e9bfab3a57cd51a4841f82787130202ff348bbaf2c6409d` |
| SHA3-384 | `ca1f44a62acba4bf1b8ca3e46a44c10ab89690de366829bcee8e832f9d667dd7a634982366a5e3d3b1c3962a3588ebe6` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T18EF54A06BCA149FAC86AA23189B351927B75BC085F3233D72E90B7782F727D05D39B54` |
| SSDEEP | `24576:GY5HURZGU5LmtS1JbmfVzDaf0lGwhAR7wYv3iwjPZ2Bele5IK2J8yFKJ9yrbwARs:GYxw0iCcbmdfKAh8X71CZ` |
| ICON-DHASH | `7476def8f8a858b8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_59eb2fad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59eb2fad261dc13a1e9bfab3a57cd51a4841f82787130202ff348bbaf2c6409d"
    family = "unknown"
    file_name = "nvd_driver_dll.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:12:22"
  condition:
    hash.sha256(0, filesize) == "59eb2fad261dc13a1e9bfab3a57cd51a4841f82787130202ff348bbaf2c6409d"
}
```

### Sample 28: `1fc2634ee7f9bddd`

| Field | Value |
|---|---|
| SHA-256 | `1fc2634ee7f9bdddc44bdb2424e898e71d844b8935c2d9c6bb208a6a5befba9e` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-10 02:11:32` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4f11447afc4928a9ce8843fc81cb25c` |
| SHA-1 | `ac0ba770904dedc4cd0f713b89359048325993ef` |
| SHA-256 | `1fc2634ee7f9bdddc44bdb2424e898e71d844b8935c2d9c6bb208a6a5befba9e` |
| SHA3-384 | `016707095b554393fb8b089a62488b1d7e372c4070aca33fa9194f9aaf2e674a6f219e2ed0886e92d3e3639afaf622a2` |
| IMPHASH | `20f35ed688f00eacb2c7ea603d9f248e` |
| TLSH | `T12324196BD25375FCD652C07852667232B732BA3847209FFB0393C7359E21AC06E79A24` |
| SSDEEP | `3072:n4lZxQqBgVY/9x82TLnGa3uTRWjIqdygeioPpXYHYyawyB7aQ1hp2YyR1:6ZxQwggL/uEIqdygetRxj77nU1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_1fc2634e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fc2634ee7f9bdddc44bdb2424e898e71d844b8935c2d9c6bb208a6a5befba9e"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:11:32"
  condition:
    hash.sha256(0, filesize) == "1fc2634ee7f9bdddc44bdb2424e898e71d844b8935c2d9c6bb208a6a5befba9e"
}
```

### Sample 29: `8b218bfe6b176c32`

| Field | Value |
|---|---|
| SHA-256 | `8b218bfe6b176c32b971029e4c038f33f4619689c69246fc7e4567386c9ed8dc` |
| Family label | `unknown` |
| File name | `Dqgz6WdgM7ak.exe` |
| File type | `exe` |
| First seen | `2026-07-10 02:08:16` |
| Reporter | `iamaachum` |
| Tags | `51-222-31-217, exe, RUS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `989a6991c5d8bb99e53fcbbed13aad11` |
| SHA-1 | `78a7a577d665274711dc68db54ed06adf3d9bdb0` |
| SHA-256 | `8b218bfe6b176c32b971029e4c038f33f4619689c69246fc7e4567386c9ed8dc` |
| SHA3-384 | `4b900d4731c8dc0e1322d5fb8342ed79d8873b69d78e1d841c40739aac7cb8eda633f46237f62dfe378dc280a4192378` |
| IMPHASH | `d9cb5cd51fb2795f802053b19b55331a` |
| TLSH | `T1643733EA0C52743BEC8812772EFE245F2AB52BCE2D59DAF5357E82E2800574A4F405D7` |
| SSDEEP | `393216:r54eSQOXZMnGADf/GMF0MIM37euQYHvO7dg42T0i3ei:9pOSnhD3GAXreuXOJZ2T0iui` |
| ICON-DHASH | `7071f4e8d896a64d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_8b218bfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b218bfe6b176c32b971029e4c038f33f4619689c69246fc7e4567386c9ed8dc"
    family = "unknown"
    file_name = "Dqgz6WdgM7ak.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:08:16"
  condition:
    hash.sha256(0, filesize) == "8b218bfe6b176c32b971029e4c038f33f4619689c69246fc7e4567386c9ed8dc"
}
```

### Sample 30: `7ee796a8fef94d38`

| Field | Value |
|---|---|
| SHA-256 | `7ee796a8fef94d38a6ef3d906fe3d37052b5b6c2435420dcc75e459fbc501a68` |
| Family label | `unknown` |
| File name | `Nix.exe` |
| File type | `exe` |
| First seen | `2026-07-10 02:06:02` |
| Reporter | `iamaachum` |
| Tags | `exe, RUS, SKYF1132-62070-portmap-host, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e66f889923ccb7dc34641a4d7ddc234` |
| SHA-1 | `c4785f0696cae4e8630d28e545bbee207544e7e3` |
| SHA-256 | `7ee796a8fef94d38a6ef3d906fe3d37052b5b6c2435420dcc75e459fbc501a68` |
| SHA3-384 | `33ccacb8679090e0fafa952cc2d227f36219459455737d60eafc2d9c6c6f5076a2c36e7e29e355b9472a6665aa1e0daa` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16337336624BF9E13F588E17D00AC099E518753DE68D358C29BF847E7CC4B61A2F2E583` |
| SSDEEP | `393216:P9VgKASQW/v5LfypcrHshaoiM7C2Vj6CzKM1THaIas9Jp8SgdcMhm:1VgY9KpTaoikPNvT9zLzgdcMU` |
| ICON-DHASH | `7071f4e8d896a64d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_7ee796a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ee796a8fef94d38a6ef3d906fe3d37052b5b6c2435420dcc75e459fbc501a68"
    family = "unknown"
    file_name = "Nix.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:06:02"
  condition:
    hash.sha256(0, filesize) == "7ee796a8fef94d38a6ef3d906fe3d37052b5b6c2435420dcc75e459fbc501a68"
}
```

### Sample 31: `1b582f8604311337`

| Field | Value |
|---|---|
| SHA-256 | `1b582f86043113376d91e7e699e0c7b9b62dce358a77a1ae0c7cd6f0d219a7d2` |
| Family label | `unknown` |
| File name | `rSRL405120008.exe` |
| File type | `exe` |
| First seen | `2026-07-10 02:02:17` |
| Reporter | `fabiodemartin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `850aaae69590cd576a589cef35768fce` |
| SHA-1 | `bc370d703a16fff1f376c2dd972bd7aa91f287b5` |
| SHA-256 | `1b582f86043113376d91e7e699e0c7b9b62dce358a77a1ae0c7cd6f0d219a7d2` |
| SHA3-384 | `93ddee13f88fc24214d4fc96f08fbb34da5f11db8b0c99ccdfb18c3ee137b64e86e27e01bd72434d7917a40d13855735` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C9B59832E6025FC2E72F57345D756F80D7CE26E7D43006AB921E773AE9E81A4881319E` |
| SSDEEP | `24576:kKi8lKKKKKKKKKKKKKKK2TnXEif/8stHVf/8stHvvMM8bVc8CKkVwU2yAXscvVo6:Hi8lKKKKKKKKKKKKKKKP` |
| ICON-DHASH | `02e1c0cc9e969668` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_1b582f86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b582f86043113376d91e7e699e0c7b9b62dce358a77a1ae0c7cd6f0d219a7d2"
    family = "unknown"
    file_name = "rSRL405120008.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:02:17"
  condition:
    hash.sha256(0, filesize) == "1b582f86043113376d91e7e699e0c7b9b62dce358a77a1ae0c7cd6f0d219a7d2"
}
```

### Sample 32: `e08ba6b6bd164546`

| Field | Value |
|---|---|
| SHA-256 | `e08ba6b6bd164546cc8f8819ab67d22f7a410d6fe9bbb2e350dbe24786e93d55` |
| Family label | `unknown` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-07-10 01:55:55` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `968b49795eddd02848759e0f1cf7c838` |
| SHA-1 | `0cb3f9f77acf2075a6074b05b56ab1b54125226d` |
| SHA-256 | `e08ba6b6bd164546cc8f8819ab67d22f7a410d6fe9bbb2e350dbe24786e93d55` |
| SHA3-384 | `ce8fce626d8e6bce5e7879a0d3cd960b24b0392204c9880a6cb632967dddc59a0ee9927dc7a58ab5564de32d60a11ee4` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1FFC65B51FA8B54F6E9071831405BB23F63305E048B28DBDBFB547B6EFC7B681186A249` |
| SSDEEP | `49152:DwlReXmtDIXDYPXrgMTGy+1xE2EEYaujUSoWUi/XUNJN/DBd2v2KDrBnafZVO0RE:UqXus8r7wtxrZpupDgvNueHE61U` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_e08ba6b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e08ba6b6bd164546cc8f8819ab67d22f7a410d6fe9bbb2e350dbe24786e93d55"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-07-10 01:55:55"
  condition:
    hash.sha256(0, filesize) == "e08ba6b6bd164546cc8f8819ab67d22f7a410d6fe9bbb2e350dbe24786e93d55"
}
```

### Sample 33: `d9e8f073c050b9f7`

| Field | Value |
|---|---|
| SHA-256 | `d9e8f073c050b9f75f78003c05cc77bc0b60fb5bbdfb980fe6216fa0fd8ace6a` |
| Family label | `SalatStealer` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-07-10 01:55:39` |
| Reporter | `iamaachum` |
| Tags | `exe, RUS, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3c1ef1092965bc58c12d579a889f296` |
| SHA-1 | `3e5560670aeaf9ae87844f896264751efc1446cd` |
| SHA-256 | `d9e8f073c050b9f75f78003c05cc77bc0b60fb5bbdfb980fe6216fa0fd8ace6a` |
| SHA3-384 | `3415ed10f2a8cec1399bf1c2ac641ab9c0c4309b358706c7c6f7cc718698414ba710e9efb86f958e3eeaa13bc8be6492` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T127E533F137B7A422F77F58F17A9823DC30C8AE294F099E85785CB83C94B67255A12B05` |
| SSDEEP | `98304:nAFSrC6fBiLdno8fH8V8A7a1tm4tKEGTG+:2SrC6fBiLdno8kyA+tm4tKEkG+` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_033_d9e8f073
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9e8f073c050b9f75f78003c05cc77bc0b60fb5bbdfb980fe6216fa0fd8ace6a"
    family = "SalatStealer"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-07-10 01:55:39"
  condition:
    hash.sha256(0, filesize) == "d9e8f073c050b9f75f78003c05cc77bc0b60fb5bbdfb980fe6216fa0fd8ace6a"
}
```

### Sample 34: `f101fda6093f1275`

| Field | Value |
|---|---|
| SHA-256 | `f101fda6093f12758efae630bc265d6bad71479249685b7503c05e707424a276` |
| Family label | `unknown` |
| File name | `windows.body` |
| File type | `unknown` |
| First seen | `2026-07-10 01:53:55` |
| Reporter | `anonymous` |
| Tags | `backdoor, BeaverTail, ContagiousInterview, FamousChollima, js, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d912cb3f95aaba276186445c4702d85` |
| SHA-256 | `f101fda6093f12758efae630bc265d6bad71479249685b7503c05e707424a276` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_f101fda6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f101fda6093f12758efae630bc265d6bad71479249685b7503c05e707424a276"
    family = "unknown"
    file_name = "windows.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:53:55"
  condition:
    hash.sha256(0, filesize) == "f101fda6093f12758efae630bc265d6bad71479249685b7503c05e707424a276"
}
```

### Sample 35: `f0d032c835744156`

| Field | Value |
|---|---|
| SHA-256 | `f0d032c835744156d134ff521c8bc2996f0d7922c7c0c8c31f12fb27d7dddc99` |
| Family label | `unknown` |
| File name | `macos.body` |
| File type | `unknown` |
| First seen | `2026-07-10 01:53:53` |
| Reporter | `anonymous` |
| Tags | `backdoor, BeaverTail, ContagiousInterview, FamousChollima, js, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3dd013aee8409b61b871907628ef0e59` |
| SHA-256 | `f0d032c835744156d134ff521c8bc2996f0d7922c7c0c8c31f12fb27d7dddc99` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_f0d032c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0d032c835744156d134ff521c8bc2996f0d7922c7c0c8c31f12fb27d7dddc99"
    family = "unknown"
    file_name = "macos.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:53:53"
  condition:
    hash.sha256(0, filesize) == "f0d032c835744156d134ff521c8bc2996f0d7922c7c0c8c31f12fb27d7dddc99"
}
```

### Sample 36: `2d8d12f404151317`

| Field | Value |
|---|---|
| SHA-256 | `2d8d12f404151317ff562585b5d2e5ba728b7e8aba60d950835a1a80e6462c3f` |
| Family label | `unknown` |
| File name | `linux.body` |
| File type | `unknown` |
| First seen | `2026-07-10 01:53:50` |
| Reporter | `anonymous` |
| Tags | `backdoor, BeaverTail, ContagiousInterview, FamousChollima, js, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `941573863e08a3efcba296e14a51b397` |
| SHA-256 | `2d8d12f404151317ff562585b5d2e5ba728b7e8aba60d950835a1a80e6462c3f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_2d8d12f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d8d12f404151317ff562585b5d2e5ba728b7e8aba60d950835a1a80e6462c3f"
    family = "unknown"
    file_name = "linux.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:53:50"
  condition:
    hash.sha256(0, filesize) == "2d8d12f404151317ff562585b5d2e5ba728b7e8aba60d950835a1a80e6462c3f"
}
```

### Sample 37: `7135a3a223914550`

| Field | Value |
|---|---|
| SHA-256 | `7135a3a2239145504e6fdc81bcdef7bcbd69a06727b638a59ba1f3e76130eb1d` |
| Family label | `unknown` |
| File name | `w.body` |
| File type | `unknown` |
| First seen | `2026-07-10 01:53:48` |
| Reporter | `anonymous` |
| Tags | `backdoor, BeaverTail, ContagiousInterview, FamousChollima, js, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5481c71576080900fa6e2be030d3fad0` |
| SHA-256 | `7135a3a2239145504e6fdc81bcdef7bcbd69a06727b638a59ba1f3e76130eb1d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_7135a3a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7135a3a2239145504e6fdc81bcdef7bcbd69a06727b638a59ba1f3e76130eb1d"
    family = "unknown"
    file_name = "w.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:53:48"
  condition:
    hash.sha256(0, filesize) == "7135a3a2239145504e6fdc81bcdef7bcbd69a06727b638a59ba1f3e76130eb1d"
}
```

### Sample 38: `9580aefa4e99bac7`

| Field | Value |
|---|---|
| SHA-256 | `9580aefa4e99bac7914a988a79688ef6173ee0e0175b993cdfcfea72cc40703b` |
| Family label | `unknown` |
| File name | `l.body` |
| File type | `unknown` |
| First seen | `2026-07-10 01:53:45` |
| Reporter | `anonymous` |
| Tags | `backdoor, BeaverTail, ContagiousInterview, FamousChollima, js, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9162f702cd17b716157f6edc51b94375` |
| SHA-256 | `9580aefa4e99bac7914a988a79688ef6173ee0e0175b993cdfcfea72cc40703b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_9580aefa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9580aefa4e99bac7914a988a79688ef6173ee0e0175b993cdfcfea72cc40703b"
    family = "unknown"
    file_name = "l.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:53:45"
  condition:
    hash.sha256(0, filesize) == "9580aefa4e99bac7914a988a79688ef6173ee0e0175b993cdfcfea72cc40703b"
}
```

### Sample 39: `281d4d60fc99cf7f`

| Field | Value |
|---|---|
| SHA-256 | `281d4d60fc99cf7f54819defb1c7c14b9202d46890936c4c6b9ebe3ddc75dd2f` |
| Family label | `unknown` |
| File name | `parser.js` |
| File type | `js` |
| First seen | `2026-07-10 01:53:41` |
| Reporter | `anonymous` |
| Tags | `backdoor, BeaverTail, ContagiousInterview, FamousChollima, js, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f4f2baabfab879d27720387a9378bf6` |
| SHA-256 | `281d4d60fc99cf7f54819defb1c7c14b9202d46890936c4c6b9ebe3ddc75dd2f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_281d4d60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "281d4d60fc99cf7f54819defb1c7c14b9202d46890936c4c6b9ebe3ddc75dd2f"
    family = "unknown"
    file_name = "parser.js"
    file_type = "js"
    first_seen = "2026-07-10 01:53:41"
  condition:
    hash.sha256(0, filesize) == "281d4d60fc99cf7f54819defb1c7c14b9202d46890936c4c6b9ebe3ddc75dd2f"
}
```

### Sample 40: `56ca405fa5c12838`

| Field | Value |
|---|---|
| SHA-256 | `56ca405fa5c12838051af41d5b515a3dc6064531eaabe635242d13e0e72de848` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 01:52:03` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1d1d914cd05bb1cbced378d002a44f9` |
| SHA-1 | `e4ef197da5354c0a2948f6a2f14104c587a9b385` |
| SHA-256 | `56ca405fa5c12838051af41d5b515a3dc6064531eaabe635242d13e0e72de848` |
| SHA3-384 | `47291c8295721c3cad2e10064e689313f642a7c81a3664974d46e2b8645903bc7a51397d0032be2cb54596f1d568b996` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T138E6330569E461EAE6A3017CFDF1A5D6E1F9B4A44372CECB0F5483627D431E08D3C66A` |
| SSDEEP | `393216:dC6Ca0xirCidCmJwb3be815XMCHWUjX1cuI3/PGTAI:dokWiVwXeS5XMb8XCH/O7` |
| ICON-DHASH | `71f8d0f0f0e8f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_56ca405f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56ca405fa5c12838051af41d5b515a3dc6064531eaabe635242d13e0e72de848"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 01:52:03"
  condition:
    hash.sha256(0, filesize) == "56ca405fa5c12838051af41d5b515a3dc6064531eaabe635242d13e0e72de848"
}
```

### Sample 41: `3167c1f795dceb06`

| Field | Value |
|---|---|
| SHA-256 | `3167c1f795dceb0642b2a446b30f137d4187b2a908990b2ce630036d45b67087` |
| Family label | `unknown` |
| File name | `m.body` |
| File type | `unknown` |
| First seen | `2026-07-10 01:51:32` |
| Reporter | `anonymous` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f05576d8348af4f03f6a633b138f2d55` |
| SHA-256 | `3167c1f795dceb0642b2a446b30f137d4187b2a908990b2ce630036d45b67087` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_3167c1f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3167c1f795dceb0642b2a446b30f137d4187b2a908990b2ce630036d45b67087"
    family = "unknown"
    file_name = "m.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:51:32"
  condition:
    hash.sha256(0, filesize) == "3167c1f795dceb0642b2a446b30f137d4187b2a908990b2ce630036d45b67087"
}
```

### Sample 42: `5af50126946695fd`

| Field | Value |
|---|---|
| SHA-256 | `5af50126946695fdd63c761bad06b5644f686a3b7ab3e3ac39d2c9ac870bf032` |
| Family label | `unknown` |
| File name | `preplan.tar.gz` |
| File type | `gz` |
| First seen | `2026-07-10 01:48:09` |
| Reporter | `anonymous` |
| Tags | `BeaverTail, gz` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdd760bb12371103fba3760bf4c71ba0` |
| SHA-1 | `35d0d812f96d2efd38b3f0cedb632f2214643e6a` |
| SHA-256 | `5af50126946695fdd63c761bad06b5644f686a3b7ab3e3ac39d2c9ac870bf032` |
| SHA3-384 | `0974586d028463cd0a3418d499b5dade1b61b103018b076f04a44a41f1d823387b5d3d51cd976cf3be7b1b82d69ac8f7` |
| TLSH | `T122D633F6B02DA036B6B82087986322467CB89E402D3CE9D23FDF4711DE9534F1556AB7` |
| SSDEEP | `393216:U8kzpQVLUqJ8sifNoF+0j2cRyJJgN02bLNncXUuHPwUMi0:AzpQV9J8sYNoXqDJJgN02bJcXUGPwUMH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_5af50126
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5af50126946695fdd63c761bad06b5644f686a3b7ab3e3ac39d2c9ac870bf032"
    family = "unknown"
    file_name = "preplan.tar.gz"
    file_type = "gz"
    first_seen = "2026-07-10 01:48:09"
  condition:
    hash.sha256(0, filesize) == "5af50126946695fdd63c761bad06b5644f686a3b7ab3e3ac39d2c9ac870bf032"
}
```

### Sample 43: `6db4c3d2ab56227d`

| Field | Value |
|---|---|
| SHA-256 | `6db4c3d2ab56227d36eff59d1dc9e13eadf9959996fab1e0b04591cc5e637d04` |
| Family label | `unknown` |
| File name | `loader.js` |
| File type | `js` |
| First seen | `2026-07-10 01:48:06` |
| Reporter | `anonymous` |
| Tags | `BeaverTail, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef9bb7c80e2726a5870f42e1ea0d1898` |
| SHA-256 | `6db4c3d2ab56227d36eff59d1dc9e13eadf9959996fab1e0b04591cc5e637d04` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_6db4c3d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6db4c3d2ab56227d36eff59d1dc9e13eadf9959996fab1e0b04591cc5e637d04"
    family = "unknown"
    file_name = "loader.js"
    file_type = "js"
    first_seen = "2026-07-10 01:48:06"
  condition:
    hash.sha256(0, filesize) == "6db4c3d2ab56227d36eff59d1dc9e13eadf9959996fab1e0b04591cc5e637d04"
}
```

### Sample 44: `dacc3d21d8d1e49f`

| Field | Value |
|---|---|
| SHA-256 | `dacc3d21d8d1e49fd7728f3500943b9eddd80589264d939fbe1fd880fe03938d` |
| Family label | `NanoCore` |
| File name | `xoilacbongda-wc2026a.tv.exe` |
| File type | `exe` |
| First seen | `2026-07-10 01:45:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f85edfbd3b5d8c22774f4239c920727e` |
| SHA-1 | `fb85963c2e68338d4f33bdef2ee4020d7f698317` |
| SHA-256 | `dacc3d21d8d1e49fd7728f3500943b9eddd80589264d939fbe1fd880fe03938d` |
| SHA3-384 | `07203240a5265bfa8554cee76ef9fb10d8f490a2c8ef592beec1f8af92fa67a086e1afe44a33c099edd17266331f52fc` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13514CF657BA88A3FE2CE8679601201538378C2E3D9C3F3DE58D854B68B663E54B071D7` |
| SSDEEP | `3072:szEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HI0DE9teJPqnXjTA9LWTbg9/K:sLV6Bta6dtJmakIM59ETe5qnXjct2EQ` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_044_dacc3d21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dacc3d21d8d1e49fd7728f3500943b9eddd80589264d939fbe1fd880fe03938d"
    family = "NanoCore"
    file_name = "xoilacbongda-wc2026a.tv.exe"
    file_type = "exe"
    first_seen = "2026-07-10 01:45:05"
  condition:
    hash.sha256(0, filesize) == "dacc3d21d8d1e49fd7728f3500943b9eddd80589264d939fbe1fd880fe03938d"
}
```

### Sample 45: `3085170853d70615`

| Field | Value |
|---|---|
| SHA-256 | `3085170853d70615dff57549f0e44e6c3f86c35f36d658aeed03bf728061f2db` |
| Family label | `unknown` |
| File name | `Gigantiske.vbs` |
| File type | `vbs` |
| First seen | `2026-07-10 01:33:59` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0482c163b41a34dfa013b7371eb86f46` |
| SHA-1 | `7cc4c5d9e9eb4aba8db82d4dc9aad12562fdeb6a` |
| SHA-256 | `3085170853d70615dff57549f0e44e6c3f86c35f36d658aeed03bf728061f2db` |
| SHA3-384 | `1faae1e239c73f317e4792a6651ff294b3288010527bb51a6238f251abbcdce07c11d5f3dc845ce7d487c1bc61c572c0` |
| TLSH | `T1A7A21B56CC450E849E8B2BF5580DB83195980771603245A4BE6EF3B7340EFA82E79F9F` |
| SSDEEP | `384:s+p2IwI3TSbTgFdeNMVNl+hZKGAsKWzlsY8vTHCxYE5R3:suwbHAdc4qKAKWT8rm33` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_30851708
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3085170853d70615dff57549f0e44e6c3f86c35f36d658aeed03bf728061f2db"
    family = "unknown"
    file_name = "Gigantiske.vbs"
    file_type = "vbs"
    first_seen = "2026-07-10 01:33:59"
  condition:
    hash.sha256(0, filesize) == "3085170853d70615dff57549f0e44e6c3f86c35f36d658aeed03bf728061f2db"
}
```

### Sample 46: `9a42d843c5c0dd75`

| Field | Value |
|---|---|
| SHA-256 | `9a42d843c5c0dd751898a0bec5a68d0fc097364788f99cdba6533b2f125b4a5f` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 00:52:05` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b4bfd9422eb241b2d324cb69d65900b` |
| SHA-1 | `ad76e4103136992aef4bba1d6f5518fec9255c51` |
| SHA-256 | `9a42d843c5c0dd751898a0bec5a68d0fc097364788f99cdba6533b2f125b4a5f` |
| SHA3-384 | `8ae820ac7a4fc1ce2240752960e7a24f723cb351960dc49dc91c97b87452eaee2cdb032db3adad2f99925aa888d047db` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1B7E63358BBE495EEF273603DA9F24611F766B0710771C8EF43D892A52E430E14E3E25A` |
| SSDEEP | `393216:INpEmJzJY05JK4wGUfYt6XHlXMCHWUjX+cuI3/PGTAI:IDJfD50fYsXFXMb8XzH/O7` |
| ICON-DHASH | `71f8d0f0f0e8f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_9a42d843
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a42d843c5c0dd751898a0bec5a68d0fc097364788f99cdba6533b2f125b4a5f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 00:52:05"
  condition:
    hash.sha256(0, filesize) == "9a42d843c5c0dd751898a0bec5a68d0fc097364788f99cdba6533b2f125b4a5f"
}
```

### Sample 47: `41bfb4bb51823fd9`

| Field | Value |
|---|---|
| SHA-256 | `41bfb4bb51823fd994d0f34504be227ea6367c9506bb99ca0f1bef6968fd7fba` |
| Family label | `Cobalt Strike` |
| File name | `javaw64_xor.exe` |
| File type | `exe` |
| First seen | `2026-07-10 00:29:53` |
| Reporter | `CNGaoLing` |
| Tags | `Cobalt Strike, CobaltStrike, exe, ShellCode` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d183531f684f78bfa407ee9b49709ae` |
| SHA-1 | `17f23766491eb4fc2624dd99b84f7d82d58d7751` |
| SHA-256 | `41bfb4bb51823fd994d0f34504be227ea6367c9506bb99ca0f1bef6968fd7fba` |
| SHA3-384 | `c772cf0a807d299f00e877c16788718b76dd2efaba81a137cba3ea52baaa029e61d8cdd70c64d2139843174d438ff971` |
| IMPHASH | `7a1164872bc8cc127a4e2bc0d7a665cf` |
| TLSH | `T186C1730633B94C9EF1E76B7498AB4672713DBC306D36DB2E4680522F28726044D0A732` |
| SSDEEP | `48:6kzj1JySISBDxoZ0rZx4DbQStOSZDpSbeEF09Ju:OSI30rZxhSXGbF0` |

#### Technical Assessment

- The sample is tracked as `Cobalt Strike` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Cobalt_Strike_047_41bfb4bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41bfb4bb51823fd994d0f34504be227ea6367c9506bb99ca0f1bef6968fd7fba"
    family = "Cobalt Strike"
    file_name = "javaw64_xor.exe"
    file_type = "exe"
    first_seen = "2026-07-10 00:29:53"
  condition:
    hash.sha256(0, filesize) == "41bfb4bb51823fd994d0f34504be227ea6367c9506bb99ca0f1bef6968fd7fba"
}
```

### Sample 48: `5ac0761c29fc5487`

| Field | Value |
|---|---|
| SHA-256 | `5ac0761c29fc5487ce913ce7457117844a269cd1058e96ac0ce3b8b6ca017caf` |
| Family label | `unknown` |
| File name | `package` |
| File type | `zip` |
| First seen | `2026-07-10 00:10:15` |
| Reporter | `monitorsg` |
| Tags | `KongTuke, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75fdea7fe58c169665fe42493e26b708` |
| SHA-1 | `a6a060db7d8754fd4b67071b8debd7ce8a7aeccd` |
| SHA-256 | `5ac0761c29fc5487ce913ce7457117844a269cd1058e96ac0ce3b8b6ca017caf` |
| SHA3-384 | `94582baa6b78b9a66a3546853cc85f1cc812e5acf0aea2c3343197f49354ddd452771f5de6bf0344e2a55659f22eaf9c` |
| TLSH | `T19E6633D959A5B53DCFAFBF3901C410629390FBCB1EC930A26C20E922954DC5A7E719E3` |
| SSDEEP | `196608:07UekvKjIiptC5nYv/UxKcZDv5euSQ/8Li2:07UekSjI6mnmAhZteu3Y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_5ac0761c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ac0761c29fc5487ce913ce7457117844a269cd1058e96ac0ce3b8b6ca017caf"
    family = "unknown"
    file_name = "package"
    file_type = "zip"
    first_seen = "2026-07-10 00:10:15"
  condition:
    hash.sha256(0, filesize) == "5ac0761c29fc5487ce913ce7457117844a269cd1058e96ac0ce3b8b6ca017caf"
}
```

### Sample 49: `158380ebd870255f`

| Field | Value |
|---|---|
| SHA-256 | `158380ebd870255fbf0ecc986480b6ec4601a5074db9bb2ff41cdb626dbee2be` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 00:00:48` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25a24d759937813e28d65d08f342c3d3` |
| SHA-1 | `965a6e624f0a24d09223fd0a3c41e0a7d92844c0` |
| SHA-256 | `158380ebd870255fbf0ecc986480b6ec4601a5074db9bb2ff41cdb626dbee2be` |
| SHA3-384 | `623869d883f6a7bfecd081f598fbecd84c06df0d54c6e18aebba5ecc5f14c43bf80c622c00e59a0ea6ad007e0a2e2e63` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T1F932B31E2E4B0321DE5009B4E575424A517D2EE37387EBDBE633D6CB4AD6E4580C0AAF` |
| SSDEEP | `192:QIo2WBS5BQcxSHO8+59DtPFJxTEZmFhquc:ro/csuDfDtPFwZ` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_049_158380eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "158380ebd870255fbf0ecc986480b6ec4601a5074db9bb2ff41cdb626dbee2be"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 00:00:48"
  condition:
    hash.sha256(0, filesize) == "158380ebd870255fbf0ecc986480b6ec4601a5074db9bb2ff41cdb626dbee2be"
}
```

### Sample 50: `ed74b54adeea87f6`

| Field | Value |
|---|---|
| SHA-256 | `ed74b54adeea87f6c2b55e5d4344011a3f4cc660af29493c87ffa1804d1d0c82` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-09 23:52:04` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3443909d7c6697a9f2cf26ad234d4230` |
| SHA-1 | `cd955bf6546b1910de417b789d5b6073b6b715cf` |
| SHA-256 | `ed74b54adeea87f6c2b55e5d4344011a3f4cc660af29493c87ffa1804d1d0c82` |
| SHA3-384 | `099823208ad27acfffe310900d8f385517816f6b880d569b0f2e2bb502416d349a3997d4b0dc31bf43523830c4420641` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T13BE63308B7E106EEF9B35138E4E16785F168346A1B71C99F57A4C3B29E672F00D3A643` |
| SSDEEP | `393216:0/SfgpX4mHMq0HKZjhlgiXuOumXMCHWUjXFcuI3/PGTAI:0jp4mM5cjhlgiXLumXMb8XyH/O7` |
| ICON-DHASH | `5471f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_ed74b54a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed74b54adeea87f6c2b55e5d4344011a3f4cc660af29493c87ffa1804d1d0c82"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 23:52:04"
  condition:
    hash.sha256(0, filesize) == "ed74b54adeea87f6c2b55e5d4344011a3f4cc660af29493c87ffa1804d1d0c82"
}
```

### Sample 51: `d245a4abe50cde64`

| Field | Value |
|---|---|
| SHA-256 | `d245a4abe50cde648ca38cf0c05b95f5c25ffb83683fe6413621c2e3634afacb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-09 23:30:29` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f6d8065c716f1e967be9febd38742b9` |
| SHA-1 | `2518f699a30120562f51c4f27ee352b110e3a621` |
| SHA-256 | `d245a4abe50cde648ca38cf0c05b95f5c25ffb83683fe6413621c2e3634afacb` |
| SHA3-384 | `a51935141aa7fad9266274a6219ad6e24a9cb39d513d82e8de32208dbbae60eccf6f1395a64c76c9ef8bb507a2c27109` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T138D61233B28AE53EE46A0A3555B2F110543B6E6C6D028D4A96E4F45CCF357B03E3EB46` |
| SSDEEP | `98304:roJJqcV0LYXa4WLHB82wNViRY1Q9xy7u+0QRM2M9yR/uGhM/Mi6NVFZx/2y6NELe:ep0LYUbGV3YT+NRNRRNVbxwNELNC` |
| ICON-DHASH | `241b387070d8d924` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_d245a4ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d245a4abe50cde648ca38cf0c05b95f5c25ffb83683fe6413621c2e3634afacb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-09 23:30:29"
  condition:
    hash.sha256(0, filesize) == "d245a4abe50cde648ca38cf0c05b95f5c25ffb83683fe6413621c2e3634afacb"
}
```

### Sample 52: `cfd7ad5fd929fbde`

| Field | Value |
|---|---|
| SHA-256 | `cfd7ad5fd929fbdef0af698ee1f7f1624ed46109a50125f7ab39b14bd84dfcac` |
| Family label | `unknown` |
| File name | `cfd7ad5fd929fbdef0af698ee1f7f1624ed46109a50125f7ab39b14bd84dfcac` |
| File type | `elf` |
| First seen | `2026-07-09 23:16:30` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e4fa7e3af59b35f528dd0ab9a1fd0fc` |
| SHA-1 | `c41e8017ca6a593915e75b9c1c50b7b7ec7bb055` |
| SHA-256 | `cfd7ad5fd929fbdef0af698ee1f7f1624ed46109a50125f7ab39b14bd84dfcac` |
| SHA3-384 | `af74fb377980ae5c6230e934213d78879020fae9e69f0be9b66684b2da4dafd8becf9a6fdc6a2fb190ae624015dd0f1d` |
| TLSH | `T17E55E657E89580F4C0EFE174C726A213B9A13489473437E76FA18AF11B26FE866BD314` |
| SSDEEP | `24576:ci3nHRD3wC7g9rb/TBvO90dL3BmAFd4A64nsfJ7FOQzjFyaWPli9+Q:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64I` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_cfd7ad5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfd7ad5fd929fbdef0af698ee1f7f1624ed46109a50125f7ab39b14bd84dfcac"
    family = "unknown"
    file_name = "cfd7ad5fd929fbdef0af698ee1f7f1624ed46109a50125f7ab39b14bd84dfcac"
    file_type = "elf"
    first_seen = "2026-07-09 23:16:30"
  condition:
    hash.sha256(0, filesize) == "cfd7ad5fd929fbdef0af698ee1f7f1624ed46109a50125f7ab39b14bd84dfcac"
}
```

### Sample 53: `d8c36edf382ffb8b`

| Field | Value |
|---|---|
| SHA-256 | `d8c36edf382ffb8ba83d05881e9b31bfa1d33a787b945685cf512b80ab00fc2c` |
| Family label | `WannaCry` |
| File name | `d8c36edf382ffb8ba83d05881e9b31bfa1d33a787b945685cf512b80ab00fc2c` |
| File type | `exe` |
| First seen | `2026-07-09 23:15:39` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11109d7f245bdafb213cc57cd0f749ea` |
| SHA-1 | `cb77a673cc27c5eb683d8f4c90a59728d910af60` |
| SHA-256 | `d8c36edf382ffb8ba83d05881e9b31bfa1d33a787b945685cf512b80ab00fc2c` |
| SHA3-384 | `9104941ef9805bdef4e8f88d5dee610a40725225b3991ce09e2384e5b18b9ab74dd3cfec0e678b36674ab8549f84c24d` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T16536335462A855BCE0520AB444B3CE16F3B73C55ABBA8B0F4780426F0D63F9BAFD4B15` |
| SSDEEP | `98304:DXDqPoBhz1aRxcSUZk36SAEdhvxWa9P5uR8yAVp2H:DXDqPe1Cxc7k3ZAEUadgR8yc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_053_d8c36edf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8c36edf382ffb8ba83d05881e9b31bfa1d33a787b945685cf512b80ab00fc2c"
    family = "WannaCry"
    file_name = "d8c36edf382ffb8ba83d05881e9b31bfa1d33a787b945685cf512b80ab00fc2c"
    file_type = "exe"
    first_seen = "2026-07-09 23:15:39"
  condition:
    hash.sha256(0, filesize) == "d8c36edf382ffb8ba83d05881e9b31bfa1d33a787b945685cf512b80ab00fc2c"
}
```

### Sample 54: `29f1016661c51389`

| Field | Value |
|---|---|
| SHA-256 | `29f1016661c51389d799e1c6e5afa5e9c2fc142c7f5382f60f3f08ed223adfbb` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-09 23:04:23` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb604ea7ec75ee47ebb50c85a3edd605` |
| SHA-1 | `50de1cdbe7a94b57a2d07f8324989a55472df6a4` |
| SHA-256 | `29f1016661c51389d799e1c6e5afa5e9c2fc142c7f5382f60f3f08ed223adfbb` |
| SHA3-384 | `47cfcb54012a740e4919ed4f651bcfce60de72f929fc9bdb6c7a34dd68cccc9b157ed85ac359b5f09f14a923f3bfe0fe` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11396C007AC9189F6C4BE9236897262A2B761BC180F3623C76F50B3782F727C45DB5791` |
| SSDEEP | `196608:FPz9d0BwvhtXWTO77/x7xfpPC7XRyQsGK9A2l:FPH0ByhtXWTUdpPDRGW1l` |
| ICON-DHASH | `71ccaaaa96b0d469` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_054_29f10166
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29f1016661c51389d799e1c6e5afa5e9c2fc142c7f5382f60f3f08ed223adfbb"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-09 23:04:23"
  condition:
    hash.sha256(0, filesize) == "29f1016661c51389d799e1c6e5afa5e9c2fc142c7f5382f60f3f08ed223adfbb"
}
```

### Sample 55: `aeed7c42c5a0de19`

| Field | Value |
|---|---|
| SHA-256 | `aeed7c42c5a0de1913b826911ce5926f1b05807170d7ac34f2e511b9458593a8` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-09 22:52:05` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9e6f3aa6525d4c613d31a1a1fe9b67b` |
| SHA-1 | `2b438f14bd802a2c046138172e90430c0c81f8bc` |
| SHA-256 | `aeed7c42c5a0de1913b826911ce5926f1b05807170d7ac34f2e511b9458593a8` |
| SHA3-384 | `8cfae32677946c5d22f99d1cc3caf4f980b187f233065a156a52087ecb94835783fd6f7813c9af9b75059b3cdab83b14` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1B6E6331896C111FEE463503DDCE279A6E06A78770B72CADF276487A5BE572A00F39313` |
| SSDEEP | `393216:pEulgTGmSMOAsJEwnQhHbcL12TMPtYU3uXMCHWUjXccuI3/PGTAI:pELG0O1dcs12TiYeuXMb8XJH/O7` |
| ICON-DHASH | `5479fcbccce4f0b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_aeed7c42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aeed7c42c5a0de1913b826911ce5926f1b05807170d7ac34f2e511b9458593a8"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 22:52:05"
  condition:
    hash.sha256(0, filesize) == "aeed7c42c5a0de1913b826911ce5926f1b05807170d7ac34f2e511b9458593a8"
}
```

### Sample 56: `92bab327f0800fe6`

| Field | Value |
|---|---|
| SHA-256 | `92bab327f0800fe67fdd049fc76f9acfcbd5c5b79794187192f48c6cae0e0724` |
| Family label | `unknown` |
| File name | `file.js` |
| File type | `js` |
| First seen | `2026-07-09 22:35:00` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, js, Kongtuke` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26231c038d7733d7e2761215b81f38ad` |
| SHA-1 | `9b0b4569d684f363eb38c574f380ce26f5c96e7d` |
| SHA-256 | `92bab327f0800fe67fdd049fc76f9acfcbd5c5b79794187192f48c6cae0e0724` |
| SHA3-384 | `d8653ee5104f046ef55c3ccc9549bddb8519dfaff66413a0a9dccc262bffbab182c10d784f272c8cc138953064273ebf` |
| TLSH | `T15702C91B732512F7D5AA1CE70B1F01461075F12B2C01E0A2CAA1F9563DBDF8269767B8` |
| SSDEEP | `96:uvRvYdlW8UVbbBiOVgQ5mTwPTEx/CQdBCpjMzrXrr8wgN+2kpxiTsFGSJDI7Y4rJ:U5Y3VUVbb8oRnPT2zB02frO+2kp7NI7f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_92bab327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92bab327f0800fe67fdd049fc76f9acfcbd5c5b79794187192f48c6cae0e0724"
    family = "unknown"
    file_name = "file.js"
    file_type = "js"
    first_seen = "2026-07-09 22:35:00"
  condition:
    hash.sha256(0, filesize) == "92bab327f0800fe67fdd049fc76f9acfcbd5c5b79794187192f48c6cae0e0724"
}
```

### Sample 57: `2186a1d4bafc5196`

| Field | Value |
|---|---|
| SHA-256 | `2186a1d4bafc51969dc84c97aafea7231cbbbb55566fca72a5df983060099f5a` |
| Family label | `unknown` |
| File name | `update-mixed-22001166.zip` |
| File type | `zip` |
| First seen | `2026-07-09 22:32:34` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, KongTuke, Mintsloader, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa6fabae0e2fc9476bf3f24809da2d77` |
| SHA-1 | `5739c8e8744ea87c75bd462c541b926a9cb277d8` |
| SHA-256 | `2186a1d4bafc51969dc84c97aafea7231cbbbb55566fca72a5df983060099f5a` |
| SHA3-384 | `2c5b45359b0691f649e8b3d4303c269fe1b1a74049cfa760a600b0485368c0c3ac8e25e318ea042e47d6a1880f8ec40a` |
| TLSH | `T15D6633DD06E9652CEF8BBF3E14C430B29340DACA1AC831A05535F532D98D95ABEA0DD7` |
| SSDEEP | `196608:9FeQaKjIJptC5nHq52c8U44UxkdTcZDv5euSQ/8Lix:9FeQRjITmnH42c8vkqZteu3b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_2186a1d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2186a1d4bafc51969dc84c97aafea7231cbbbb55566fca72a5df983060099f5a"
    family = "unknown"
    file_name = "update-mixed-22001166.zip"
    file_type = "zip"
    first_seen = "2026-07-09 22:32:34"
  condition:
    hash.sha256(0, filesize) == "2186a1d4bafc51969dc84c97aafea7231cbbbb55566fca72a5df983060099f5a"
}
```

### Sample 58: `8602b5a93f61ef26`

| Field | Value |
|---|---|
| SHA-256 | `8602b5a93f61ef26519762e545df3a252ac765cd2e8062837722d049bf1ab34d` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-09 21:52:07` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a90a801f776cab1cf0d5faedacf0cc5a` |
| SHA-1 | `a8a1a600a199fd5c16d16aeef7312cfacad5aa1c` |
| SHA-256 | `8602b5a93f61ef26519762e545df3a252ac765cd2e8062837722d049bf1ab34d` |
| SHA3-384 | `9b98bba556fe5a04614a966c15b8873470b9823a361750008fed1a52ce490a375dc22e4501f542f5b20da3813bd0046a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1B1E6335826F026FEF9739038E8E24D90E4A9B4A55735CACF07EC82923D572D4C93D693` |
| SSDEEP | `393216:bNx0hGL5+xLMu/Plif+j5qyxgLXMCHWUjX8cuI3/PGTAI:bNah65+tL10+jQ0gLXMb8XpH/O7` |
| ICON-DHASH | `30f8fcdccce4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_8602b5a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8602b5a93f61ef26519762e545df3a252ac765cd2e8062837722d049bf1ab34d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 21:52:07"
  condition:
    hash.sha256(0, filesize) == "8602b5a93f61ef26519762e545df3a252ac765cd2e8062837722d049bf1ab34d"
}
```

### Sample 59: `3a9d703ba7f75643`

| Field | Value |
|---|---|
| SHA-256 | `3a9d703ba7f7564399365db7ab8b04238806ef7a53df0b6822f32b80bf0f5a80` |
| Family label | `unknown` |
| File name | `dev.golove.velto` |
| File type | `unknown` |
| First seen | `2026-07-09 21:21:41` |
| Reporter | `smica83` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed33a3c8d9e861515623a73b27ea4913` |
| SHA-256 | `3a9d703ba7f7564399365db7ab8b04238806ef7a53df0b6822f32b80bf0f5a80` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_3a9d703b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a9d703ba7f7564399365db7ab8b04238806ef7a53df0b6822f32b80bf0f5a80"
    family = "unknown"
    file_name = "dev.golove.velto"
    file_type = "unknown"
    first_seen = "2026-07-09 21:21:41"
  condition:
    hash.sha256(0, filesize) == "3a9d703ba7f7564399365db7ab8b04238806ef7a53df0b6822f32b80bf0f5a80"
}
```

### Sample 60: `41a35436cb79c950`

| Field | Value |
|---|---|
| SHA-256 | `41a35436cb79c95001b2fdb7076e26c996bc9a913d64c7f54db9507882773120` |
| Family label | `WannaCry` |
| File name | `41a35436cb79c95001b2fdb7076e26c996bc9a913d64c7f54db9507882773120` |
| File type | `exe` |
| First seen | `2026-07-09 21:15:17` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17bbc98ffde5371d4f1eb96d290a0ba9` |
| SHA-1 | `818d8b3263c3e7673134c9c6a075b932e287a11d` |
| SHA-256 | `41a35436cb79c95001b2fdb7076e26c996bc9a913d64c7f54db9507882773120` |
| SHA3-384 | `a26721b204e21c3b18945e806e769c149841e17c8e8c276a31ce693714e900d35d0beb0e72e7ff21838c876cf2bbfac7` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T14C36234A32AC90FCD40A6374D4B78E16E2B37C9A22BD970F9B4487660D13791FB68753` |
| SSDEEP | `24576:jbLgBbLgurgQhfdmMSirYbcMNgef0QeQjG/D8kIqA+:jnsnsQqMSPbcBVQej/U+` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_060_41a35436
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41a35436cb79c95001b2fdb7076e26c996bc9a913d64c7f54db9507882773120"
    family = "WannaCry"
    file_name = "41a35436cb79c95001b2fdb7076e26c996bc9a913d64c7f54db9507882773120"
    file_type = "exe"
    first_seen = "2026-07-09 21:15:17"
  condition:
    hash.sha256(0, filesize) == "41a35436cb79c95001b2fdb7076e26c996bc9a913d64c7f54db9507882773120"
}
```

### Sample 61: `725c24ec04fba51d`

| Field | Value |
|---|---|
| SHA-256 | `725c24ec04fba51daa1f30f2b463759c9443ddc284261a58d96979e9a97eb436` |
| Family label | `unknown` |
| File name | `725c24ec04fba51daa1f30f2b463759c9443ddc284261a58d96979e9a97eb436` |
| File type | `sh` |
| First seen | `2026-07-09 21:12:15` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80f62cc49808653c913920cb6efdbd2b` |
| SHA-1 | `7d23fef1e54081e332cd0f51149ad8932271112d` |
| SHA-256 | `725c24ec04fba51daa1f30f2b463759c9443ddc284261a58d96979e9a97eb436` |
| SHA3-384 | `0094161a12ad4600f4e27ce931535d2d160b9360f8e85e554dc5bb9b2d2db39aa89079d72fae8c6dbc07724c31d0b042` |
| TLSH | `T15651FED3E4A59136731680BD6F9AE0602B67112B5F93ED3C74BEEA004F2902471E6B32` |
| SSDEEP | `48:ELun1ut1xXxFIDczWJf2qJ4HsJ9ION7fvWl3g71fZUH0r7Dm4EAXNk/GAx:ELk1GxBFIoknuMDJh34wpLDmVM0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_725c24ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "725c24ec04fba51daa1f30f2b463759c9443ddc284261a58d96979e9a97eb436"
    family = "unknown"
    file_name = "725c24ec04fba51daa1f30f2b463759c9443ddc284261a58d96979e9a97eb436"
    file_type = "sh"
    first_seen = "2026-07-09 21:12:15"
  condition:
    hash.sha256(0, filesize) == "725c24ec04fba51daa1f30f2b463759c9443ddc284261a58d96979e9a97eb436"
}
```

### Sample 62: `e81c8b5bc8b6be98`

| Field | Value |
|---|---|
| SHA-256 | `e81c8b5bc8b6be982906ef0b4932074225f5b46757d898dedf480c0cf8011861` |
| Family label | `unknown` |
| File name | `e81c8b5bc8b6be982906ef0b4932074225f5b46757d898dedf480c0cf8011861` |
| File type | `sh` |
| First seen | `2026-07-09 21:00:47` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b531bb1601d67efed2dd031d42b93f93` |
| SHA-1 | `702ac10ed08e52916211c4b27f5ef307dec77c3d` |
| SHA-256 | `e81c8b5bc8b6be982906ef0b4932074225f5b46757d898dedf480c0cf8011861` |
| SHA3-384 | `922f41bf15ac902e202fdb16f764fe0dea949ff22bc6361796502f519450e59d1ee4219ed538d19a3f07223876e3c88d` |
| TLSH | `T1794112D7E4E59232B316807D6F9BE0603763202B5E63EC7C74BEE9014F1912071E6A32` |
| SSDEEP | `48:ELul1ut1xXxFIDczpf2qJ4HsJ9ION7fvWl3g7186q2K30rjlcm4EAXNk/GAx:ELW1GxBFIodnuMDJh34wpQQOmVM0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_e81c8b5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e81c8b5bc8b6be982906ef0b4932074225f5b46757d898dedf480c0cf8011861"
    family = "unknown"
    file_name = "e81c8b5bc8b6be982906ef0b4932074225f5b46757d898dedf480c0cf8011861"
    file_type = "sh"
    first_seen = "2026-07-09 21:00:47"
  condition:
    hash.sha256(0, filesize) == "e81c8b5bc8b6be982906ef0b4932074225f5b46757d898dedf480c0cf8011861"
}
```

### Sample 63: `8451b01ca5c10591`

| Field | Value |
|---|---|
| SHA-256 | `8451b01ca5c1059121cc0ea724c2e2d98bc761a3aa00618f514babfff74d337a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-09 20:52:05` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f9fec92dd249217734aa93045cd95a4` |
| SHA-1 | `9dacf1c2af9ba652d6039812e80a2345f9a4d9d9` |
| SHA-256 | `8451b01ca5c1059121cc0ea724c2e2d98bc761a3aa00618f514babfff74d337a` |
| SHA3-384 | `8f6ff4a3261791b23890f8e21e60ad48dc21e63726e706c8e9f3cf35b19a48839d2102a255971f57bf63d8fff0ad6024` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T112E6335C69C012FDE663813DDAE21281E57A787A4B70CADF1BA407617E671E08D3CB63` |
| SSDEEP | `393216:PekgstRKto/TJQvrVaunOJgWWXMCHWUjXecuI3/PGTAI:PebJWJKVGKzXMb8XTH/O7` |
| ICON-DHASH | `1870e0e0f8f8f060` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_8451b01c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8451b01ca5c1059121cc0ea724c2e2d98bc761a3aa00618f514babfff74d337a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 20:52:05"
  condition:
    hash.sha256(0, filesize) == "8451b01ca5c1059121cc0ea724c2e2d98bc761a3aa00618f514babfff74d337a"
}
```

### Sample 64: `3066874504f49274`

| Field | Value |
|---|---|
| SHA-256 | `3066874504f49274ec261de95cf94797158d0a169a61d9e546eb2df731b1b74b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-09 20:40:47` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX8.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9975b63feb6669b9b0e948eeaa4c3dc` |
| SHA-1 | `ec2562fb7c4d6c28a056a97cb6112fa16103f103` |
| SHA-256 | `3066874504f49274ec261de95cf94797158d0a169a61d9e546eb2df731b1b74b` |
| SHA3-384 | `f6e484902346f21a199a706a918b059deb27d70d18631ff8000d1cfce88b0b73375dc6032139b6ddec66506b48f524ce` |
| IMPHASH | `86f1f56935451fab526b19f6de359407` |
| TLSH | `T1E2848E1AF69404F9E167D17CC9624906FA727C4E07606ACF23A44AA71F376E49E3FB10` |
| SSDEEP | `6144:MDBIlbxWi7yte1VZOXgjECWQKjTajQ4jbemK3/eq6l19tgkzjyDrJ:xWDSfjE7jM7/e7xCLgkzGDr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_30668745
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3066874504f49274ec261de95cf94797158d0a169a61d9e546eb2df731b1b74b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-09 20:40:47"
  condition:
    hash.sha256(0, filesize) == "3066874504f49274ec261de95cf94797158d0a169a61d9e546eb2df731b1b74b"
}
```

### Sample 65: `d07766429ea14ac3`

| Field | Value |
|---|---|
| SHA-256 | `d07766429ea14ac3c403bde5a9498a9fe161a059eea212b3baf3f520b078f709` |
| Family label | `unknown` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-09 20:33:06` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89d00270b9546603c772b8ccb01c8739` |
| SHA-1 | `945c926496e5238430677b5181114edaab0037d0` |
| SHA-256 | `d07766429ea14ac3c403bde5a9498a9fe161a059eea212b3baf3f520b078f709` |
| SHA3-384 | `b1663e24916bfed25feb678c4da1089212fb8a2b3f752d7f028f1bcb313f82aad5245b9075afe8132f539176a4053c31` |
| TLSH | `T115A312D9D6ADCC24DF56B06D4C019BC1BF50F3EB1BA2F64128419FE46E82C29F92C606` |
| SSDEEP | `3072:ntweSPGgofNsT9/7/7kH6pjStvoS9Bib4u+qgw2u6:ntxvVfN8R/oapjmQSu/6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_d0776642
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d07766429ea14ac3c403bde5a9498a9fe161a059eea212b3baf3f520b078f709"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-09 20:33:06"
  condition:
    hash.sha256(0, filesize) == "d07766429ea14ac3c403bde5a9498a9fe161a059eea212b3baf3f520b078f709"
}
```

### Sample 66: `92d93285e39e3775`

| Field | Value |
|---|---|
| SHA-256 | `92d93285e39e37750ba59f7127807f3c9d4de18fb8efe386042587e204604108` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-09 20:29:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2dbfea3ae9860e01ffd305f97d22160f` |
| SHA-1 | `a181475519c6bf7c07f424aef1a65aab018c6fbd` |
| SHA-256 | `92d93285e39e37750ba59f7127807f3c9d4de18fb8efe386042587e204604108` |
| SHA3-384 | `3c05a7a0d3f91cf2963a5112c87244dd49f4a2b8bbe92d7f3a1a6a12b5e0191fa91c81adda017eec8f28c5fd8b19f3e0` |
| TLSH | `T1EC337D5516817C149A99D8371D7F2F0CB9AD43E6320492ED7FCF3CF28C4AA9DA118719` |
| SSDEEP | `768:fXOGVv69GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnB:fLXcK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_92d93285
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92d93285e39e37750ba59f7127807f3c9d4de18fb8efe386042587e204604108"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-09 20:29:27"
  condition:
    hash.sha256(0, filesize) == "92d93285e39e37750ba59f7127807f3c9d4de18fb8efe386042587e204604108"
}
```

### Sample 67: `3ba2080a5a4791a7`

| Field | Value |
|---|---|
| SHA-256 | `3ba2080a5a4791a7a8c5ea42ac40826bfca758f3abea4da90d3f22fbc50c2d60` |
| Family label | `unknown` |
| File name | `推特提号器q.exe` |
| File type | `exe` |
| First seen | `2026-07-09 20:25:23` |
| Reporter | `CNGaoLing` |
| Tags | `AsyncRAT, Backdoor, exe, SilverFox, ValleyRAT, XRed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `206ae1cd4e8b116a646d5bb96de88c57` |
| SHA-1 | `f611b859613a55145eb44ee36829a7d87bbb84ad` |
| SHA-256 | `3ba2080a5a4791a7a8c5ea42ac40826bfca758f3abea4da90d3f22fbc50c2d60` |
| SHA3-384 | `71c9eee66284781959944bd2ea82178fe4da04ec59d2da455e97f2736b80abdf3dd6bf7171d3eb6e3c3287d512bc048d` |
| IMPHASH | `332f7ce65ead0adfb3d35147033aabe9` |
| TLSH | `T1C906E023B2C7553BE0764A394D67E265583BBA616D229C5BABF40C4CCF291C12D3F287` |
| SSDEEP | `98304:Qnsmtk2aM5fgQ+y04MdN35LIi7Ky5PCtgb3s7DP:uLPb+y04C3hm3` |
| ICON-DHASH | `7178f666b079b9b9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_3ba2080a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ba2080a5a4791a7a8c5ea42ac40826bfca758f3abea4da90d3f22fbc50c2d60"
    family = "unknown"
    file_name = "推特提号器q.exe"
    file_type = "exe"
    first_seen = "2026-07-09 20:25:23"
  condition:
    hash.sha256(0, filesize) == "3ba2080a5a4791a7a8c5ea42ac40826bfca758f3abea4da90d3f22fbc50c2d60"
}
```

### Sample 68: `b689762ccfcd2350`

| Field | Value |
|---|---|
| SHA-256 | `b689762ccfcd2350f30e36203e89847fe1a3e8e60b74e91b082ae4e4a5d5353d` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-09 20:25:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3db3f7969f4bf22b4a9f27c93fd712a7` |
| SHA-1 | `ccf74a710a7d1fa0fdeb44f5daebd33f57984f24` |
| SHA-256 | `b689762ccfcd2350f30e36203e89847fe1a3e8e60b74e91b082ae4e4a5d5353d` |
| SHA3-384 | `d8b3acf713c6a14618e358ddd610a80756cbe0fe1c961ec9697996df132c7308248e73af89e1c8678a2692e8a778a2dc` |
| TLSH | `T16A748FA2646059CFCE5099BAB36C8F3427912C71C21B1FBD1D568118A2CF8DBF1D6BE4` |
| SSDEEP | `6144:3MdzYFsaOGDZTDO/2NvwQglJ8C49N5sz7eBNL:8dzYFsmDZTjw3lJV4L5geBV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_b689762c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b689762ccfcd2350f30e36203e89847fe1a3e8e60b74e91b082ae4e4a5d5353d"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-09 20:25:13"
  condition:
    hash.sha256(0, filesize) == "b689762ccfcd2350f30e36203e89847fe1a3e8e60b74e91b082ae4e4a5d5353d"
}
```

### Sample 69: `a98d50beff9c89aa`

| Field | Value |
|---|---|
| SHA-256 | `a98d50beff9c89aa88280e3f6112c2cfaa150385b40656440c2a023b03e5662b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-09 20:23:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `daee935324c91d32e0e9ca78d56a4882` |
| SHA-1 | `59aaa1c20e4a750cf289ef58049a8d03f3286a8a` |
| SHA-256 | `a98d50beff9c89aa88280e3f6112c2cfaa150385b40656440c2a023b03e5662b` |
| SHA3-384 | `e0e1387c2e75837f9acff22d18b997fbfa1a60e8216e6b0da90321570eff86e7b259ae5670e032340f88afb380893712` |
| TLSH | `T107337D6516857C14AA99C8365D7F2F0CBCAD43E6314491EE7FCE3CF28C4AA9CA21971C` |
| SSDEEP | `768:Br9NyXsZztCz9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnB:5HusZtcK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_a98d50be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a98d50beff9c89aa88280e3f6112c2cfaa150385b40656440c2a023b03e5662b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-09 20:23:32"
  condition:
    hash.sha256(0, filesize) == "a98d50beff9c89aa88280e3f6112c2cfaa150385b40656440c2a023b03e5662b"
}
```

### Sample 70: `3b6fa85634e3aa55`

| Field | Value |
|---|---|
| SHA-256 | `3b6fa85634e3aa554424e53bd0a9b7317aeca0f25a5d6903b83dc9f42e71ad4b` |
| Family label | `unknown` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-07-09 20:15:04` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c2c05de906d7e682b570fa3a537c431` |
| SHA-1 | `d31f91ec061679fbb0537fa2e7cb33b0d005bb0f` |
| SHA-256 | `3b6fa85634e3aa554424e53bd0a9b7317aeca0f25a5d6903b83dc9f42e71ad4b` |
| SHA3-384 | `a0c49336fed0606d829298e1ab4f2b2ab94f7cb0b6aaaf4b8f8afe3ae8a3520540bc9d7104d1ff61ee44bd26b7643a27` |
| TLSH | `T19B649D537B878F96E225B5714AF3C178AAE9360706F7C46BC33A5B0213994D0BC19EC9` |
| TELFHASH | `t196111448683ec45a7de30664cc3c5a95d70fcd3538514720df08c7c4897e4059219f5f` |
| SSDEEP | `6144:vhetYU2Mh8NOmfOYYQjEBQ6Q0IyQcju75stykwXOQ:vhetYh9O5YLEB3QAu6tykw+Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_3b6fa856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b6fa85634e3aa554424e53bd0a9b7317aeca0f25a5d6903b83dc9f42e71ad4b"
    family = "unknown"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-07-09 20:15:04"
  condition:
    hash.sha256(0, filesize) == "3b6fa85634e3aa554424e53bd0a9b7317aeca0f25a5d6903b83dc9f42e71ad4b"
}
```

### Sample 71: `aa77c3256a16b91d`

| Field | Value |
|---|---|
| SHA-256 | `aa77c3256a16b91d2621d797cb8cf16f0254bd587a511d4e75f54de51c304c0f` |
| Family label | `Mirai` |
| File name | `void.mpsl` |
| File type | `elf` |
| First seen | `2026-07-09 20:13:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90609d7050621a1e68f98067065c3d50` |
| SHA-1 | `828149b865906f1512459ed6595cf1741845c159` |
| SHA-256 | `aa77c3256a16b91d2621d797cb8cf16f0254bd587a511d4e75f54de51c304c0f` |
| SHA3-384 | `d89b16f5525fb683e4bdd3fdf812bed4eceda755f2b2e956f31f0ca843824d3c47524920c219812981ea986710116282` |
| TLSH | `T1A114E819ABA10FFBDCAFCD3702E90B0128CCA55722A43B757674D528F64A50B5AE3C74` |
| SSDEEP | `3072:sEnWmNPmIZqzkTNwhGtvJXxaA1hnU1zQ1On/:sEWwPmJkihGhJXAinUdeO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_aa77c325
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa77c3256a16b91d2621d797cb8cf16f0254bd587a511d4e75f54de51c304c0f"
    family = "Mirai"
    file_name = "void.mpsl"
    file_type = "elf"
    first_seen = "2026-07-09 20:13:32"
  condition:
    hash.sha256(0, filesize) == "aa77c3256a16b91d2621d797cb8cf16f0254bd587a511d4e75f54de51c304c0f"
}
```

### Sample 72: `7ff7ad40017d89d4`

| Field | Value |
|---|---|
| SHA-256 | `7ff7ad40017d89d4e399c70bb79f1db6bdb57aea05939748cdfe3b9f1527c21f` |
| Family label | `Mirai` |
| File name | `void.sh4` |
| File type | `elf` |
| First seen | `2026-07-09 20:12:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32d7142648b9be0c46add0cd341214a2` |
| SHA-1 | `f0e60f4240a3ce257c13fcdfc6a5c8a91b8d4bf8` |
| SHA-256 | `7ff7ad40017d89d4e399c70bb79f1db6bdb57aea05939748cdfe3b9f1527c21f` |
| SHA3-384 | `823d6adc4bc662db56603c455196d9d74bc2f259b8fa55b16087966135c3413de7dbb6836316faa11b335789e5f40dd5` |
| TLSH | `T1EED36A33D8266F58D195C174B064DF782B63A6A482875FBA29A7C3B44047ECDF904BF8` |
| SSDEEP | `3072:5+I0uz/RUKcVyXh3ffHLEXZ+cqWOMPYrDyz:5+6/uKzXRfcT3OAYr+z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_7ff7ad40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ff7ad40017d89d4e399c70bb79f1db6bdb57aea05939748cdfe3b9f1527c21f"
    family = "Mirai"
    file_name = "void.sh4"
    file_type = "elf"
    first_seen = "2026-07-09 20:12:28"
  condition:
    hash.sha256(0, filesize) == "7ff7ad40017d89d4e399c70bb79f1db6bdb57aea05939748cdfe3b9f1527c21f"
}
```

### Sample 73: `2f0ba36eb00eedff`

| Field | Value |
|---|---|
| SHA-256 | `2f0ba36eb00eedff7a6c8eabbd2436998dc5756dc57219476553fca52b203a5e` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-09 20:07:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c983f19e84771eb59293f30d57e02665` |
| SHA-1 | `82664190ee70a95a157080deef41e84b08ff452d` |
| SHA-256 | `2f0ba36eb00eedff7a6c8eabbd2436998dc5756dc57219476553fca52b203a5e` |
| SHA3-384 | `8e9c820efd6f8c412c75fd76bb9f914e960531352765c4eb255c713d52a5ade247c9be7286a46e2167f4a4e21db70b76` |
| TLSH | `T156B312D7AA366F7CEA2826738FC50850F77348225462DA4506DCC33B6C2E7D87562A63` |
| SSDEEP | `3072:TV4G6zonVIY8GCIdG8x3xeDiiMDc/Brb7g9a:TV4G6zyFdRUDvFN5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_2f0ba36e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f0ba36eb00eedff7a6c8eabbd2436998dc5756dc57219476553fca52b203a5e"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-09 20:07:22"
  condition:
    hash.sha256(0, filesize) == "2f0ba36eb00eedff7a6c8eabbd2436998dc5756dc57219476553fca52b203a5e"
}
```

### Sample 74: `72b2bb12dedd3cc8`

| Field | Value |
|---|---|
| SHA-256 | `72b2bb12dedd3cc8b5d9a977adb6f8b68b3ce3a26bc20c277fa49f1b59048f9a` |
| Family label | `AveMariaRAT` |
| File name | `rTransferencia.exe` |
| File type | `exe` |
| First seen | `2026-07-09 20:00:07` |
| Reporter | `fabiodemartin` |
| Tags | `AveMariaRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80fd8473ec9edd85e977b302e4761b41` |
| SHA-1 | `bd69c4b1825aa9b4c6f7646e7969e4bd73a8a567` |
| SHA-256 | `72b2bb12dedd3cc8b5d9a977adb6f8b68b3ce3a26bc20c277fa49f1b59048f9a` |
| SHA3-384 | `0b10abebb4ffc5d96313ddfb6b5bbbf78ada342e87cf5d4b769b3ab0da89670c8d7bc5218c20fa575a8bec6c94f75234` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17B94CFCAA6D08D30C94A9D34C0301D6402378F597E96F346ED68BC7337B7ADA2CA5997` |
| SSDEEP | `6144:6+MDCWfks6/Qjl9gm1zzehRYYnqLqgd9FGPgzDj6RmpJurCTmSHCX3YhoII:LOZcsvh9gmZzeczwaDj12MmSHCMI` |
| ICON-DHASH | `70c0db4eea7ab0fc` |

#### Technical Assessment

- The sample is tracked as `AveMariaRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AveMariaRAT_074_72b2bb12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72b2bb12dedd3cc8b5d9a977adb6f8b68b3ce3a26bc20c277fa49f1b59048f9a"
    family = "AveMariaRAT"
    file_name = "rTransferencia.exe"
    file_type = "exe"
    first_seen = "2026-07-09 20:00:07"
  condition:
    hash.sha256(0, filesize) == "72b2bb12dedd3cc8b5d9a977adb6f8b68b3ce3a26bc20c277fa49f1b59048f9a"
}
```

### Sample 75: `5caf5e70726c56bc`

| Field | Value |
|---|---|
| SHA-256 | `5caf5e70726c56bc484171aa8a2f7f322d1629135574500c33eb74d3860c9bce` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-07-09 19:58:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e0370d99fbbd943eafb6f5968926383` |
| SHA-1 | `f6260637b45a2c36f1d2b15d6ac2083e167b960d` |
| SHA-256 | `5caf5e70726c56bc484171aa8a2f7f322d1629135574500c33eb74d3860c9bce` |
| SHA3-384 | `b0ac7e26858feff60b735e1861d8fae1d41fbd6fde17f39e9a023e2d323d5159a0624b0561ef6f5ba3926004efbca6cd` |
| TLSH | `T1E5B3121E69095F0B04E110FAF73C801BE30C8BB9A54E695FEA2F5D6C35044A9BFD6B16` |
| SSDEEP | `3072:Jp65gFfphiUIPStacDrAcIfbrorEVzXJ9E:Jp650pqPyFYpfHu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_5caf5e70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5caf5e70726c56bc484171aa8a2f7f322d1629135574500c33eb74d3860c9bce"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-09 19:58:14"
  condition:
    hash.sha256(0, filesize) == "5caf5e70726c56bc484171aa8a2f7f322d1629135574500c33eb74d3860c9bce"
}
```

### Sample 76: `8848d6f5e76195a4`

| Field | Value |
|---|---|
| SHA-256 | `8848d6f5e76195a4a4190deb3b5766ce67615ef6347837d893349e719eed0b47` |
| Family label | `unknown` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-07-09 19:55:07` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4a4ab31dcc19d0621b6d7b3c4ec2dbf` |
| SHA-1 | `4f4b5966ad30c2aaa4e604975246057e7508048e` |
| SHA-256 | `8848d6f5e76195a4a4190deb3b5766ce67615ef6347837d893349e719eed0b47` |
| SHA3-384 | `c148159dd4dbd647705395aa0192a5e8bdfbab77c804133fd50038ba33a1d10cc15edec7bc103d6812f596dc09386dce` |
| TLSH | `T172A312BA92659321693082F8FE8421096B54342CD5B379FD131409B277FE8A8EEF4953` |
| SSDEEP | `3072:YgcqGmC4IPgrcxp4IrCyLPPdV4iJeRcfcecD69/:Y+GXpoEpdLHd5eekeWM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_8848d6f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8848d6f5e76195a4a4190deb3b5766ce67615ef6347837d893349e719eed0b47"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-09 19:55:07"
  condition:
    hash.sha256(0, filesize) == "8848d6f5e76195a4a4190deb3b5766ce67615ef6347837d893349e719eed0b47"
}
```

### Sample 77: `719f09877c07bf12`

| Field | Value |
|---|---|
| SHA-256 | `719f09877c07bf12dca4f9196d4c2eb5af5cb36fc6c55a644a762997cc4e470e` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-09 19:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da26235919a193e09af86f56b1eecc2a` |
| SHA-1 | `a24b38e7fb55ba567c7656c42ba7f81fbe961ec4` |
| SHA-256 | `719f09877c07bf12dca4f9196d4c2eb5af5cb36fc6c55a644a762997cc4e470e` |
| SHA3-384 | `c3c16cdbeaaf8ee768a42cab9fb563e62e5311539bb683a058e0a7c7fb86fb9499ad495835c5b2545ce10771eb0449d2` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D0E63398A6E065DEF5E3813CDED195C2E5A4B4669739CC8F0FA843623E170A44C3E71B` |
| SSDEEP | `393216:GUPmB298d7qh5SCBlZlUpgEdPKXMCHWUjXdcuI3/PGTAI:GoH28QgEIXMb8XqH/O7` |
| ICON-DHASH | `7071e4d6e6e47130` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_077_719f0987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "719f09877c07bf12dca4f9196d4c2eb5af5cb36fc6c55a644a762997cc4e470e"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 19:52:08"
  condition:
    hash.sha256(0, filesize) == "719f09877c07bf12dca4f9196d4c2eb5af5cb36fc6c55a644a762997cc4e470e"
}
```

### Sample 78: `ba826be9b66bc82c`

| Field | Value |
|---|---|
| SHA-256 | `ba826be9b66bc82c62d13d33c5c90edc6994d21948e854203d60ded683e45c9f` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-09 19:51:33` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4c40240b8bf6547d9170cc483b2e439` |
| SHA-1 | `ddf2e9cfeb5fb0d3dd94b8f0dbb08639f6939cdf` |
| SHA-256 | `ba826be9b66bc82c62d13d33c5c90edc6994d21948e854203d60ded683e45c9f` |
| SHA3-384 | `726032a5acca838b94568f3941d06abaf2a9f8d52f61edc3a761f9926d8456c3cacf93f46a19501ea9c866d2f89fb367` |
| TLSH | `T170B312B7D6F63865EBF520338457F9B29384F9C42BF9874059785312C844B8ACA607BD` |
| SSDEEP | `1536:DubDMbeZ4e9ndGW/du0P+yHQznCPLnvwDfTe5izSnVpDFP+jnO/TppI4aXeQRU+k:ibDldx/4SQznCFYunVpFyO/EVXPRlM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_ba826be9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba826be9b66bc82c62d13d33c5c90edc6994d21948e854203d60ded683e45c9f"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-09 19:51:33"
  condition:
    hash.sha256(0, filesize) == "ba826be9b66bc82c62d13d33c5c90edc6994d21948e854203d60ded683e45c9f"
}
```

### Sample 79: `eb82a907d60ef93a`

| Field | Value |
|---|---|
| SHA-256 | `eb82a907d60ef93a1adfb5f5881a54d9b5f626cfce3206aa8a21aa9e7d76f765` |
| Family label | `unknown` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-07-09 19:42:12` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5997db454378c55f8b52706313dce600` |
| SHA-1 | `5290ae46e83c9d8eaa31da871dc94c93022ae59f` |
| SHA-256 | `eb82a907d60ef93a1adfb5f5881a54d9b5f626cfce3206aa8a21aa9e7d76f765` |
| SHA3-384 | `f2e99887c7493d32aac243adddbf8301a09856deaa379dd97d038ab478aa9087c51bdca593c715c209f02c9c47dc620c` |
| TLSH | `T1C2A31234C02980EBDF59E932A60D96D066C8667EF6F02A974D3052B47FE7A11F2F4907` |
| SSDEEP | `3072:KuI+4JDTU5TRPQX75HQYD00SCd+kUmxhhlx:KJ+kTUhRPQXSC0ehlx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_eb82a907
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb82a907d60ef93a1adfb5f5881a54d9b5f626cfce3206aa8a21aa9e7d76f765"
    family = "unknown"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-07-09 19:42:12"
  condition:
    hash.sha256(0, filesize) == "eb82a907d60ef93a1adfb5f5881a54d9b5f626cfce3206aa8a21aa9e7d76f765"
}
```

### Sample 80: `9ebc81fcb58ca55f`

| Field | Value |
|---|---|
| SHA-256 | `9ebc81fcb58ca55f4b7368a9b80ac4521144b7c9e55788b054d3bf8bcea7a533` |
| Family label | `unknown` |
| File name | `Netorase.exe` |
| File type | `exe` |
| First seen | `2026-07-09 19:38:46` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dab6069b2fa6925e7e6d6a3586ebaea7` |
| SHA-1 | `b8e06083c98b04ae5d055fda323e720933134a52` |
| SHA-256 | `9ebc81fcb58ca55f4b7368a9b80ac4521144b7c9e55788b054d3bf8bcea7a533` |
| SHA3-384 | `ab1e192c24cd0c73f0a6b9856113adfb7cea672c8b86dd0309a5a20d4b405711d8432d25166e6f0e1ef91dddbfed86e8` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T1B308334E086DC4C3C57F9AFA7E6330AAD244DD271DB4E42D6B0D07E8B5A1D6210B993B` |
| SSDEEP | `1572864:wt9IKPtfUw6yRWYIJImKljUoEkB9dNDsMLXgiMZrIuEtxbZSJ7:wUKRUw6yRWhImKljUvOhLXMxIufJ7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_9ebc81fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ebc81fcb58ca55f4b7368a9b80ac4521144b7c9e55788b054d3bf8bcea7a533"
    family = "unknown"
    file_name = "Netorase.exe"
    file_type = "exe"
    first_seen = "2026-07-09 19:38:46"
  condition:
    hash.sha256(0, filesize) == "9ebc81fcb58ca55f4b7368a9b80ac4521144b7c9e55788b054d3bf8bcea7a533"
}
```

### Sample 81: `db3d4d4ae5f9acf1`

| Field | Value |
|---|---|
| SHA-256 | `db3d4d4ae5f9acf1a3922e229fba045046d62c2c765cdc7821347e5b7357275d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-09 19:34:23` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de9c5ff3ea3994fc541f7b6677415beb` |
| SHA-1 | `a1d502729ccd437dd6ae67160daf8633e1eacffd` |
| SHA-256 | `db3d4d4ae5f9acf1a3922e229fba045046d62c2c765cdc7821347e5b7357275d` |
| SHA3-384 | `071a80439990e0c4bebdd1c6dd84e464d8bcbd3f834e68c36567c80f420e2c19b22a50ce24d560957718b206180c0c58` |
| IMPHASH | `59667224ee0313970348dd1811a42053` |
| TLSH | `T11E043B395682BDE9F4D62A3EBB55BB28EE4EFD1003AAE45F06D4506F00935385F37A40` |
| SSDEEP | `3072:5t68L20+bxuOgVfnST6nNvfNn1UuldI598ZK5u1FIApvhX:/gbxWfSutXUuldIP8ZK56FBv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_db3d4d4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db3d4d4ae5f9acf1a3922e229fba045046d62c2c765cdc7821347e5b7357275d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-09 19:34:23"
  condition:
    hash.sha256(0, filesize) == "db3d4d4ae5f9acf1a3922e229fba045046d62c2c765cdc7821347e5b7357275d"
}
```

### Sample 82: `6880110bb6b5caf0`

| Field | Value |
|---|---|
| SHA-256 | `6880110bb6b5caf0b41af519e5463fed007fa8101f2a37a543654322dada345d` |
| Family label | `Vidar` |
| File name | `KungFu.exe` |
| File type | `exe` |
| First seen | `2026-07-09 19:32:53` |
| Reporter | `abuse_ch` |
| Tags | `de-pumped, exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `420fd444d624d3c701378822a35cbe88` |
| SHA-1 | `f4857428876dd9f5f49e2a226a7f43c6002d6bec` |
| SHA-256 | `6880110bb6b5caf0b41af519e5463fed007fa8101f2a37a543654322dada345d` |
| SHA3-384 | `32113397cd1db092e2228030333559dc0a0497737abb367e0375ad8c922b05c204b7d6a32d6dc5a79d354faf80f4d808` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1CAA533CD0BD5287AF1B087B096B980E2C135BCE35B2A15AF52D145BD8B63BC8E538753` |
| SSDEEP | `49152:eu8vkIOghbU9adZxdQhgnohDOPZag30Dap1kIB3pL8EndrQkRcwrWRh89Z:+vAghbia7xY0PbGukIxpYEZcf8` |
| ICON-DHASH | `b4bb9abc3c0b1304` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_082_6880110b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6880110bb6b5caf0b41af519e5463fed007fa8101f2a37a543654322dada345d"
    family = "Vidar"
    file_name = "KungFu.exe"
    file_type = "exe"
    first_seen = "2026-07-09 19:32:53"
  condition:
    hash.sha256(0, filesize) == "6880110bb6b5caf0b41af519e5463fed007fa8101f2a37a543654322dada345d"
}
```

### Sample 83: `e951ad2d9c9e5e49`

| Field | Value |
|---|---|
| SHA-256 | `e951ad2d9c9e5e499c7f8b3ca795a58f4c935873a20f51cb1882b11474038ce0` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-09 19:32:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b40ce4f596ad7ab0eb14391cb0d85657` |
| SHA-1 | `983943be5ed951e3e84fce4c075d9987c12f9117` |
| SHA-256 | `e951ad2d9c9e5e499c7f8b3ca795a58f4c935873a20f51cb1882b11474038ce0` |
| SHA3-384 | `62dd0f491f547e18e7c16412d2f9d50753867c9cf0b9bc7a124575f7a40176f0cdd84ab5f5373fa8228238c621f0aeb3` |
| TLSH | `T1CAC3121A00127ACEF4C4BCFA17EA217363F2E940F15E2B5963F16A6E019F53673A6011` |
| SSDEEP | `3072:xRZeSTbsgzp8TVdh5TyNetS5tbmUG8U9Ip:DJTfiTVdhANeMTbDU9Ip` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_e951ad2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e951ad2d9c9e5e499c7f8b3ca795a58f4c935873a20f51cb1882b11474038ce0"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-09 19:32:08"
  condition:
    hash.sha256(0, filesize) == "e951ad2d9c9e5e499c7f8b3ca795a58f4c935873a20f51cb1882b11474038ce0"
}
```

### Sample 84: `93222e8d11c89738`

| Field | Value |
|---|---|
| SHA-256 | `93222e8d11c8973821f86ccf658aba2ed6d3ac044ad56bac58a70bad2f6d1482` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-09 19:28:28` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54b22a18aba117dce4fed835ab6e2e53` |
| SHA-1 | `265fb1e2fd804a2e25f140b55b83804bda1731a2` |
| SHA-256 | `93222e8d11c8973821f86ccf658aba2ed6d3ac044ad56bac58a70bad2f6d1482` |
| SHA3-384 | `a2b5c4bc563b5fd36aa98353b68578161b459bf51230c637bd310c569e12752ebac2d57030c80212357ac7dec233e788` |
| TLSH | `T159C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:Mq8vCB+25j6es8Rk9FYpMSUpi+20qUpi+20YQX:98l25JCd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_93222e8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93222e8d11c8973821f86ccf658aba2ed6d3ac044ad56bac58a70bad2f6d1482"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-09 19:28:28"
  condition:
    hash.sha256(0, filesize) == "93222e8d11c8973821f86ccf658aba2ed6d3ac044ad56bac58a70bad2f6d1482"
}
```

### Sample 85: `f57d00c4b273dcd3`

| Field | Value |
|---|---|
| SHA-256 | `f57d00c4b273dcd3b8d5fa73c63d26a861dba2d4d240c555c8e78c928a24f4a2` |
| Family label | `unknown` |
| File name | `PR# 122883 _ YMFOS.exe` |
| File type | `exe` |
| First seen | `2026-07-09 19:25:27` |
| Reporter | `threatcat_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7740f8a2a0353a6973eb98d883f426d4` |
| SHA-1 | `37a33fc1463b4568bc7783d629a64d02bb2d40ba` |
| SHA-256 | `f57d00c4b273dcd3b8d5fa73c63d26a861dba2d4d240c555c8e78c928a24f4a2` |
| SHA3-384 | `f1f25891ecd303dcdde3cf3418fca84e281a3bcc72f4b488f63bb3bfdd68c6a3cc78d3d73007e0f8844055d3bd2435df` |
| IMPHASH | `52fc4cd1f0148f6789c566674a94e859` |
| TLSH | `T17A066C70D351B065D1A7C430CED60EF464A1703B52366D1F1BC5E82A25FBEA1ABAD3A3` |
| SSDEEP | `49152:vi+RGR+18/UhF1BBFWE5XHkob6SNwRDe2Ij+DJ1vknJADm3VJmc/py9QW5iKG11k:BB35jLKm3VI9Q0jhv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_f57d00c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f57d00c4b273dcd3b8d5fa73c63d26a861dba2d4d240c555c8e78c928a24f4a2"
    family = "unknown"
    file_name = "PR# 122883 _ YMFOS.exe"
    file_type = "exe"
    first_seen = "2026-07-09 19:25:27"
  condition:
    hash.sha256(0, filesize) == "f57d00c4b273dcd3b8d5fa73c63d26a861dba2d4d240c555c8e78c928a24f4a2"
}
```

### Sample 86: `595e3d46169a51dc`

| Field | Value |
|---|---|
| SHA-256 | `595e3d46169a51dcf93d15690d34508726729c6f6cdfec88b5e366070934537d` |
| Family label | `LegionLoader` |
| File name | `a.exe` |
| File type | `exe` |
| First seen | `2026-07-09 19:17:46` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, exe, LegionLoader, littleforlot-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4d88df61bbfac0f164269705ac55b7d` |
| SHA-1 | `2b98695668d8398e9c6b0e224bc6b1b6991f6365` |
| SHA-256 | `595e3d46169a51dcf93d15690d34508726729c6f6cdfec88b5e366070934537d` |
| SHA3-384 | `2f5bae8bfb92f689df6d63c3d9bdf797235ad951a2dcb8466a0202c820a74f6a6504a4910913520459aab0aec023af8b` |
| IMPHASH | `a7eeec345d41d6cffa9ccd06218cdd65` |
| TLSH | `T1C5D4023D4CD327EED575863C92D2B379B599B7F12B010AE39741569D3A32FC82AB1A00` |
| SSDEEP | `12288:2AbFeDF3/aQEdXrGzphnRE/f0yNdpH9wqE3TyXF8ILmJ2xWq8Nrb:2AJn9rGzxMf0kdwqgTyTCJ2o` |
| ICON-DHASH | `0b0787e270ac8603` |

#### Technical Assessment

- The sample is tracked as `LegionLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LegionLoader_086_595e3d46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "595e3d46169a51dcf93d15690d34508726729c6f6cdfec88b5e366070934537d"
    family = "LegionLoader"
    file_name = "a.exe"
    file_type = "exe"
    first_seen = "2026-07-09 19:17:46"
  condition:
    hash.sha256(0, filesize) == "595e3d46169a51dcf93d15690d34508726729c6f6cdfec88b5e366070934537d"
}
```

### Sample 87: `d8def83bb0ebac9c`

| Field | Value |
|---|---|
| SHA-256 | `d8def83bb0ebac9cc0554f6cc9ab0394d992d0e53d0e896b849d1d553a84eecc` |
| Family label | `unknown` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-07-09 19:15:06` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `798992656087625844562ea365db525f` |
| SHA-1 | `bd3bd1ed55b3a525661111704ad81f568ce53bad` |
| SHA-256 | `d8def83bb0ebac9cc0554f6cc9ab0394d992d0e53d0e896b849d1d553a84eecc` |
| SHA3-384 | `5f0305cdb0a8fbd249b91934dcb728b5cc95da938060515b61353c9e3fa0a5cc81d0ac38c7d591442eb0088108c5a89c` |
| TLSH | `T1C9A31224E4ECFC12DB50DEF24D0A04C2716B4838F1D1F5B1534898FA624B66992FE9AB` |
| SSDEEP | `3072:CDfTC4Jat9Hou72qHrLGwZoV6Ej/70NcIVD+sGsg:C7L+9H5x9ZM6qMhg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_d8def83b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8def83bb0ebac9cc0554f6cc9ab0394d992d0e53d0e896b849d1d553a84eecc"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-09 19:15:06"
  condition:
    hash.sha256(0, filesize) == "d8def83bb0ebac9cc0554f6cc9ab0394d992d0e53d0e896b849d1d553a84eecc"
}
```

### Sample 88: `7d2ae2a214a78507`

| Field | Value |
|---|---|
| SHA-256 | `7d2ae2a214a78507141ac7dff3e0757e392db7b626e30b925e555ccbc13ebe6f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-09 19:15:05` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d9f2fef98eaac514aa6b6b617fcc438` |
| SHA-1 | `c70080975deec8d3b1b08174ae8e2252613b20a1` |
| SHA-256 | `7d2ae2a214a78507141ac7dff3e0757e392db7b626e30b925e555ccbc13ebe6f` |
| SHA3-384 | `51afb0a5656d51ead80773c5d35005b489ad79dbaa966fa697f1f650013ba7e7d4503391ac82e605bf0a4c68e17b7dfc` |
| TLSH | `T160C27E956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:x8vCB+25j6es8RA8K9FYpMSUpi+20qUpi+20YQX:x8l25JV8d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_7d2ae2a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d2ae2a214a78507141ac7dff3e0757e392db7b626e30b925e555ccbc13ebe6f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-09 19:15:05"
  condition:
    hash.sha256(0, filesize) == "7d2ae2a214a78507141ac7dff3e0757e392db7b626e30b925e555ccbc13ebe6f"
}
```

### Sample 89: `243b8f76eb849109`

| Field | Value |
|---|---|
| SHA-256 | `243b8f76eb8491091fcce90f7ccdbf081958a4b371e739ecdbb2ec1738aababe` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-09 19:13:58` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87520cbe320f2afe862db0fcdfa17a22` |
| SHA-1 | `1ed11c118eb4373213cce3ebc204ad56e307cd16` |
| SHA-256 | `243b8f76eb8491091fcce90f7ccdbf081958a4b371e739ecdbb2ec1738aababe` |
| SHA3-384 | `9a27ce2c78b71f8723a3649430baec0a5054a0e0a4eb029bfc0495ccbe9fbfe03f835a1af8b969c06ac06c1129d8e00f` |
| IMPHASH | `ddae556bf00b750d860560e7e27d467e` |
| TLSH | `T19AE3C691F2DA0CCBE66491BC52E6E222353DB8E003139B67063565774FDEB933AE0587` |
| SSDEEP | `3072:06Lxq/tnH2no5yLWUy0xmrMMSvFSv4RCy6ENcmV:06LxqtVivgv6V7V` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_243b8f76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "243b8f76eb8491091fcce90f7ccdbf081958a4b371e739ecdbb2ec1738aababe"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-09 19:13:58"
  condition:
    hash.sha256(0, filesize) == "243b8f76eb8491091fcce90f7ccdbf081958a4b371e739ecdbb2ec1738aababe"
}
```

### Sample 90: `1878af2ede36c2bd`

| Field | Value |
|---|---|
| SHA-256 | `1878af2ede36c2bda6735f859c306a9bda538933193d8f46de8fcf4573ae5c88` |
| Family label | `unknown` |
| File name | `1878af2ede36c2bda6735f859c306a9bda538933193d8f46de8fcf4573ae5c88` |
| File type | `unknown` |
| First seen | `2026-07-09 19:13:11` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e53735d43e1abffcb0820849ce8ebd8c` |
| SHA-256 | `1878af2ede36c2bda6735f859c306a9bda538933193d8f46de8fcf4573ae5c88` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_1878af2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1878af2ede36c2bda6735f859c306a9bda538933193d8f46de8fcf4573ae5c88"
    family = "unknown"
    file_name = "1878af2ede36c2bda6735f859c306a9bda538933193d8f46de8fcf4573ae5c88"
    file_type = "unknown"
    first_seen = "2026-07-09 19:13:11"
  condition:
    hash.sha256(0, filesize) == "1878af2ede36c2bda6735f859c306a9bda538933193d8f46de8fcf4573ae5c88"
}
```

### Sample 91: `32f368c31812bb7a`

| Field | Value |
|---|---|
| SHA-256 | `32f368c31812bb7a9704c0e250ba8e90845ce06d107f36360117de30818c2da2` |
| Family label | `unknown` |
| File name | `32f368c31812bb7a9704c0e250ba8e90845ce06d107f36360117de30818c2da2` |
| File type | `sh` |
| First seen | `2026-07-09 19:13:09` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c80ef5a759201528feef0b4dbbe53974` |
| SHA-1 | `966d0ef3aaa67faeebd5033a3255d5d44f60bef0` |
| SHA-256 | `32f368c31812bb7a9704c0e250ba8e90845ce06d107f36360117de30818c2da2` |
| SHA3-384 | `c2586fbed0cac8646fab25ace448f8953a82d3a96049d6e328caf5404442099852f5d2728bf9b57b56747e387e18a905` |
| TLSH | `T1594150C3E4D94432F316807D0E96F0906B13112B0E57EF38B8ADE5419F6963062D2B72` |
| SSDEEP | `48:ELuV1ut1xXxFIDMzdO+xXxZI9MefOqJ4HsJON7f1872K9ylM46:EL61GxBFIY1xBZI2e/uMAh9wlyeB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_32f368c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f368c31812bb7a9704c0e250ba8e90845ce06d107f36360117de30818c2da2"
    family = "unknown"
    file_name = "32f368c31812bb7a9704c0e250ba8e90845ce06d107f36360117de30818c2da2"
    file_type = "sh"
    first_seen = "2026-07-09 19:13:09"
  condition:
    hash.sha256(0, filesize) == "32f368c31812bb7a9704c0e250ba8e90845ce06d107f36360117de30818c2da2"
}
```

### Sample 92: `4cca32f774fe33f9`

| Field | Value |
|---|---|
| SHA-256 | `4cca32f774fe33f96b8cca18dc5b24bf93abe684516f2722331f49f66d2b940e` |
| Family label | `Vidar` |
| File name | `KungFu_patched.exe` |
| File type | `exe` |
| First seen | `2026-07-09 19:11:28` |
| Reporter | `iamaachum` |
| Tags | `AsgardProtector, de-pumped, exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b65213cc6c7631f409b0c3fb370aab58` |
| SHA-1 | `1f02d29086ff5e1d96ea9079b3ed9820759417ac` |
| SHA-256 | `4cca32f774fe33f96b8cca18dc5b24bf93abe684516f2722331f49f66d2b940e` |
| SHA3-384 | `6e183a6fda6ed16820aae50d49a7999631747ae4a7473232d135d9c4bc0d5426aa55fc6bcf4cd25baec3784b789cd695` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1F92633CD0BD5287AF1B087B096B980E2C135BCE35B2A15AF52D145BD8B63BC8E538753` |
| SSDEEP | `49152:eu8vkIOghbU9adZxdQhgnohDOPZag30Dap1kIB3pL8EndrQkRcwrWRh89Z:+vAghbia7xY0PbGukIxpYEZcf8` |
| ICON-DHASH | `b4bb9abc3c0b1304` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_092_4cca32f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cca32f774fe33f96b8cca18dc5b24bf93abe684516f2722331f49f66d2b940e"
    family = "Vidar"
    file_name = "KungFu_patched.exe"
    file_type = "exe"
    first_seen = "2026-07-09 19:11:28"
  condition:
    hash.sha256(0, filesize) == "4cca32f774fe33f96b8cca18dc5b24bf93abe684516f2722331f49f66d2b940e"
}
```

### Sample 93: `96da185331e1daaa`

| Field | Value |
|---|---|
| SHA-256 | `96da185331e1daaac8bf43071c290ebc03cae73e968930d25ec7b63df7b5f27d` |
| Family label | `Vidar` |
| File name | `KungFu.7z` |
| File type | `7z` |
| First seen | `2026-07-09 19:10:29` |
| Reporter | `iamaachum` |
| Tags | `7z, AsgardProtector, ClickFix, file-pumped, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9a712c8f31d4f56260ca0c726f27bab` |
| SHA-1 | `c8c5bbe664c564405c6d6abc2dfec9aa410d6dc4` |
| SHA-256 | `96da185331e1daaac8bf43071c290ebc03cae73e968930d25ec7b63df7b5f27d` |
| SHA3-384 | `734a8cb51a42a4a80304ec7b8f09bfc0a28f2a6187f1f0dbd912fbbc81215f7143f6e46ca2e09d21303d93b8497ab0ee` |
| TLSH | `T1E5A53394A98B931D7D6A60FFF18BFADE2039633C1FDCF04589A97C2263A1CD06995071` |
| SSDEEP | `49152:vJZsX2BTkIXp35wpvfZ0iOoTYWdOp5tHLzac7Y4d4Dj3tgW1Kdvpa:BZsX2VkIXp3qIz5J7Y4dkV4c` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_093_96da1853
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96da185331e1daaac8bf43071c290ebc03cae73e968930d25ec7b63df7b5f27d"
    family = "Vidar"
    file_name = "KungFu.7z"
    file_type = "7z"
    first_seen = "2026-07-09 19:10:29"
  condition:
    hash.sha256(0, filesize) == "96da185331e1daaac8bf43071c290ebc03cae73e968930d25ec7b63df7b5f27d"
}
```

### Sample 94: `73bcca5b454619b3`

| Field | Value |
|---|---|
| SHA-256 | `73bcca5b454619b329fd696ba5049fb404b38857702dd65e2f093851076fda38` |
| Family label | `Mirai` |
| File name | `kaizen.arm7sf_srv` |
| File type | `elf` |
| First seen | `2026-07-09 19:09:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8be48f95cbc2df9479731537a031ba2` |
| SHA-1 | `a20671157de5023f976bc16e6cc7b5869618f76d` |
| SHA-256 | `73bcca5b454619b329fd696ba5049fb404b38857702dd65e2f093851076fda38` |
| SHA3-384 | `78ca0662717ee62cda2dfa4de8d427cacbc54c23d046db64f100484abea22f707bd6a2576dcab90ea70cf60a084b2774` |
| TLSH | `T1EBD3198DF8908FA2C5D136BABA5D118C33A267F5C2E9B102DE146F3027DF95E067B542` |
| SSDEEP | `3072:rqmW+8XKpeb14XzVqg8RB1sGd1bTzHKKkAxkDXEsg8tH:rnpemM11bTIDw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_73bcca5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73bcca5b454619b329fd696ba5049fb404b38857702dd65e2f093851076fda38"
    family = "Mirai"
    file_name = "kaizen.arm7sf_srv"
    file_type = "elf"
    first_seen = "2026-07-09 19:09:18"
  condition:
    hash.sha256(0, filesize) == "73bcca5b454619b329fd696ba5049fb404b38857702dd65e2f093851076fda38"
}
```

### Sample 95: `0489461205b62afa`

| Field | Value |
|---|---|
| SHA-256 | `0489461205b62afa1bd96de91a2afb92c0da0b0d03c6b64f9619b983dd219502` |
| Family label | `Mirai` |
| File name | `kaizen.x86_64_srv` |
| File type | `elf` |
| First seen | `2026-07-09 19:08:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bf1a80d54a6ce508d1b32dc6907bf64` |
| SHA-1 | `8861fed126dd4bc5a1e81b7e75b7448d521bc6fb` |
| SHA-256 | `0489461205b62afa1bd96de91a2afb92c0da0b0d03c6b64f9619b983dd219502` |
| SHA3-384 | `f98044c1ad5d2d05f0913304e20c252a32fd6f91f8757c0c848e70082eb82a61edaed58d4a866d7c9c5f12181ed18f9f` |
| TLSH | `T18CD35B46A15564FCC81BC178977F9833F631BC6E4234BAAB27C47B311C2ADA06B19787` |
| SSDEEP | `1536:RVWtT3VwGJPnc+SpO7fYQjRO044TpwoIzup8/jQ11cj2wXGYC1RPGvyXc2h3M1QB:a3Vr34ODYYR4gpwvzupGQ1mSwESq1M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_04894612
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0489461205b62afa1bd96de91a2afb92c0da0b0d03c6b64f9619b983dd219502"
    family = "Mirai"
    file_name = "kaizen.x86_64_srv"
    file_type = "elf"
    first_seen = "2026-07-09 19:08:45"
  condition:
    hash.sha256(0, filesize) == "0489461205b62afa1bd96de91a2afb92c0da0b0d03c6b64f9619b983dd219502"
}
```

### Sample 96: `0e9d63c1a463dd47`

| Field | Value |
|---|---|
| SHA-256 | `0e9d63c1a463dd4736d486a3cc014f0bfc376c56e01d39b2bc05c10ec4b132fc` |
| Family label | `Mirai` |
| File name | `kaizen.x86_64_srv` |
| File type | `elf` |
| First seen | `2026-07-09 19:08:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `154c501910e8ffadf84f38aef3d112f2` |
| SHA-1 | `66ed2a66c7ffb098c68aca37268e7823f05e922b` |
| SHA-256 | `0e9d63c1a463dd4736d486a3cc014f0bfc376c56e01d39b2bc05c10ec4b132fc` |
| SHA3-384 | `cb77fdbdf316178361a80fee271c66c58ee99b86eeba5b809b4a0fc6302891e09d26187d253aaf597ed9d19040318068` |
| TLSH | `T1573302F63494A017D974C2FB1794469E9D2ED307102DA81F5C28BCB330D9A19D378AEA` |
| SSDEEP | `768:ZeASfjvjK3df94ZHujH5MqRvOcin3EMVUQ6QJ4ZqdQD3iF8j1RQ+Wu9eqD+XdNi:sASfjvj8dV4ZHujEEMm9vunu9eqyXvi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_0e9d63c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e9d63c1a463dd4736d486a3cc014f0bfc376c56e01d39b2bc05c10ec4b132fc"
    family = "Mirai"
    file_name = "kaizen.x86_64_srv"
    file_type = "elf"
    first_seen = "2026-07-09 19:08:12"
  condition:
    hash.sha256(0, filesize) == "0e9d63c1a463dd4736d486a3cc014f0bfc376c56e01d39b2bc05c10ec4b132fc"
}
```

### Sample 97: `0f53ffd52bacfb58`

| Field | Value |
|---|---|
| SHA-256 | `0f53ffd52bacfb588af6425033e5f391147aaf47002b813dee2aabad1768403d` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-09 19:04:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da26b2d1e5b60481510ada419cb0e6e9` |
| SHA-1 | `7a9b3335d3bd44eb2919670a40ce95a94cd4d694` |
| SHA-256 | `0f53ffd52bacfb588af6425033e5f391147aaf47002b813dee2aabad1768403d` |
| SHA3-384 | `d2451e4e1b54b7ba06670c4f93618155c6159a914f6e1b2717de7c56257ab501fa720ae7a365c021d9988b92418a67b6` |
| TLSH | `T19E646CE3FC01EDBFF85FD732CC134A04B134E32164921A3A61A37B77AA2A1555963D86` |
| SSDEEP | `6144:fUM3eHhSUWmV4ThRvBoFzihiFsJtZwryKCCPa8x70DaLCggG:8SU3ivBoFzihiFsJwxoggG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_0f53ffd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f53ffd52bacfb588af6425033e5f391147aaf47002b813dee2aabad1768403d"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-09 19:04:12"
  condition:
    hash.sha256(0, filesize) == "0f53ffd52bacfb588af6425033e5f391147aaf47002b813dee2aabad1768403d"
}
```

### Sample 98: `991721e0913df206`

| Field | Value |
|---|---|
| SHA-256 | `991721e0913df2064a98d27cc143094f1fb57caa934cff46da74d068f466ee12` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-09 19:04:11` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2626e0b8c3768c9d15fad48ada091ae` |
| SHA-1 | `80c1346f946cecc2a485c3598ecc8db08b09a825` |
| SHA-256 | `991721e0913df2064a98d27cc143094f1fb57caa934cff46da74d068f466ee12` |
| SHA3-384 | `596c4cfca92f8744a08be03ba46aae1d77112cf9009703b852f875a8d0ad5e8c53d94657d79afaa125e27b1e2dcf3abc` |
| TLSH | `T1B2A302C91BFF82F9CC3CC0351D5927E87601CA15FB60905D8A9C31AA5D1ABA0EDEE385` |
| SSDEEP | `3072:c4UA41QBtEH1CWTXLsdMBPnHiaN0NWbxeQUBitz/outq:c4UJ1EuXLsdqSgxrXtzoSq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_991721e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "991721e0913df2064a98d27cc143094f1fb57caa934cff46da74d068f466ee12"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-09 19:04:11"
  condition:
    hash.sha256(0, filesize) == "991721e0913df2064a98d27cc143094f1fb57caa934cff46da74d068f466ee12"
}
```

### Sample 99: `df6feb0ac8a10f63`

| Field | Value |
|---|---|
| SHA-256 | `df6feb0ac8a10f63e2058894dd831280080f7c40ce065270d5b7ea5d9a326217` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-09 19:02:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31f527554e999049a3858cefc95a5123` |
| SHA-1 | `012ffc67bf8080d2f5ca6dd984cd831a7d50ec8a` |
| SHA-256 | `df6feb0ac8a10f63e2058894dd831280080f7c40ce065270d5b7ea5d9a326217` |
| SHA3-384 | `ece67d35f4adc46bf17574b1e32b06d6835dea7bf33a06cd2b20483988738c722d5ebdbeeec2f700ccb4ece1ad097cab` |
| TLSH | `T1B7B3026D57041068D8287A7C04D28F5D1F2A5EA7F511A38264E065BF948FEFE1B8EFE0` |
| SSDEEP | `1536:2u4ZjgH1p9dWYSth2EkgvZXFShuWHAfRC8TNrj/oVLInOniwHRzEKiNbCf/tgFTL:2u41gH/42uv24WgQ8h4NTiYRzca/tYVt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_df6feb0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df6feb0ac8a10f63e2058894dd831280080f7c40ce065270d5b7ea5d9a326217"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-09 19:02:41"
  condition:
    hash.sha256(0, filesize) == "df6feb0ac8a10f63e2058894dd831280080f7c40ce065270d5b7ea5d9a326217"
}
```

### Sample 100: `85db7625a733ec1c`

| Field | Value |
|---|---|
| SHA-256 | `85db7625a733ec1cd1fb244ba15b78c4a2485c2a119836e87257e7ccc05c5145` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-09 18:52:07` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35e3ffe7f932dff7ec62f30f0b98bec0` |
| SHA-1 | `01649a1173f1c9d059e14ae17147e4dc620e4e34` |
| SHA-256 | `85db7625a733ec1cd1fb244ba15b78c4a2485c2a119836e87257e7ccc05c5145` |
| SHA3-384 | `974c9596b35cfe7d769f8cb38ac40927e59d4e574703cf521917dbe4ee71bf3f35ddf2b43fb3dcfaff65a4be880b8f41` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F7E6331CA7D043FEDAB3103EEAE18A91E05470761B72CA8B0BD453929E976D04D3E367` |
| SSDEEP | `393216:QLnHGAlY5EBpUEaDrYI16e+4XMCHWUjXTcuI3/PGTAI:QLnmrzEaDV1l+4XMb8XQH/O7` |
| ICON-DHASH | `40b960c0dc797218` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_100_85db7625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85db7625a733ec1cd1fb244ba15b78c4a2485c2a119836e87257e7ccc05c5145"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 18:52:07"
  condition:
    hash.sha256(0, filesize) == "85db7625a733ec1cd1fb244ba15b78c4a2485c2a119836e87257e7ccc05c5145"
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
 * Generated: 2026-07-10T04:27:30.347593+00:00
 */

rule MalwareBazaar_unknown_001_6953e6d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6953e6d2e8facd1ad7eaef3d95e3aae39f660a539329df240582dfab4501b49b"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 03:52:00"
  condition:
    hash.sha256(0, filesize) == "6953e6d2e8facd1ad7eaef3d95e3aae39f660a539329df240582dfab4501b49b"
}

rule MalwareBazaar_RemcosRAT_002_3563a0dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3563a0dd216236d5f6f8bc871afe1f98f5bff78afe2d95f80276906dcdf278e2"
    family = "RemcosRAT"
    file_name = "RFQGoodsLogisticsLandedCost20260710Returnurge.vbs"
    file_type = "vbs"
    first_seen = "2026-07-10 03:45:09"
  condition:
    hash.sha256(0, filesize) == "3563a0dd216236d5f6f8bc871afe1f98f5bff78afe2d95f80276906dcdf278e2"
}

rule MalwareBazaar_RemcosRAT_003_1f08b33c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f08b33c61a20cb9327b1a529df79f2072ba72646631619e622eb0c1e6a6e8f7"
    family = "RemcosRAT"
    file_name = "Laminaterne.vbs"
    file_type = "vbs"
    first_seen = "2026-07-10 03:44:07"
  condition:
    hash.sha256(0, filesize) == "1f08b33c61a20cb9327b1a529df79f2072ba72646631619e622eb0c1e6a6e8f7"
}

rule MalwareBazaar_unknown_004_ff2fb9db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff2fb9db58c022b54bc0a49ec5b8c22c96bd6f8010ff28e8ef9988f68d298dbc"
    family = "unknown"
    file_name = "ff2fb9db58c022b54bc0a49ec5b8c22c96bd6f8010ff28e8ef9988f68d298dbc"
    file_type = "sh"
    first_seen = "2026-07-10 03:22:10"
  condition:
    hash.sha256(0, filesize) == "ff2fb9db58c022b54bc0a49ec5b8c22c96bd6f8010ff28e8ef9988f68d298dbc"
}

rule MalwareBazaar_unknown_005_4919efb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4919efb3417bed43e3b985f0c980f197cb59f4d7a4d2894834eb33347edc6831"
    family = "unknown"
    file_name = "loader.decoded.txt"
    file_type = "unknown"
    first_seen = "2026-07-10 03:20:58"
  condition:
    hash.sha256(0, filesize) == "4919efb3417bed43e3b985f0c980f197cb59f4d7a4d2894834eb33347edc6831"
}

rule MalwareBazaar_unknown_006_aa42289f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa42289f45060a82c21197da722374d97d1c4cb91d315617c9b1f9ae88691fba"
    family = "unknown"
    file_name = "parser.decoded.txt"
    file_type = "unknown"
    first_seen = "2026-07-10 03:20:56"
  condition:
    hash.sha256(0, filesize) == "aa42289f45060a82c21197da722374d97d1c4cb91d315617c9b1f9ae88691fba"
}

rule MalwareBazaar_RatonRAT_007_e8573e97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8573e97c75bec4b9645f40c94a1f961971aa28444e3726564f4dda1312aac25"
    family = "RatonRAT"
    file_name = "ratonClient.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:30"
  condition:
    hash.sha256(0, filesize) == "e8573e97c75bec4b9645f40c94a1f961971aa28444e3726564f4dda1312aac25"
}

rule MalwareBazaar_ValleyRAT_008_539abaeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "539abaeb1d337bd77d51589b1debe5339e87f2e07f62235d9b1ada5a11d6d056"
    family = "ValleyRAT"
    file_name = "1967745B78718A571407FCE13485412B.dll"
    file_type = "dll"
    first_seen = "2026-07-10 03:10:26"
  condition:
    hash.sha256(0, filesize) == "539abaeb1d337bd77d51589b1debe5339e87f2e07f62235d9b1ada5a11d6d056"
}

rule MalwareBazaar_Cobalt_Strike_009_c3505549
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c35055499d7bf39198746a21bac07fb902e6307818898d6f961f3fdddaff5bde"
    family = "Cobalt Strike"
    file_name = "c35055499d7bf39198746a21bac07fb902e6307818898.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:23"
  condition:
    hash.sha256(0, filesize) == "c35055499d7bf39198746a21bac07fb902e6307818898d6f961f3fdddaff5bde"
}

rule MalwareBazaar_RemcosRAT_010_c0762bd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0762bd8b3b098c6d5300256f9e8bc67d45709dc244db37cc55c5e2b0312e907"
    family = "RemcosRAT"
    file_name = "c0762bd8b3b098c6d5300256f9e8bc67d45709dc244db.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:20"
  condition:
    hash.sha256(0, filesize) == "c0762bd8b3b098c6d5300256f9e8bc67d45709dc244db37cc55c5e2b0312e907"
}

rule MalwareBazaar_RemcosRAT_011_f35b6cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f35b6cb6af991bfa735e039f6bc0e49c69759c015a2074b87eed8f20e4200135"
    family = "RemcosRAT"
    file_name = "f35b6cb6af991bfa735e039f6bc0e49c69759c015a207.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:16"
  condition:
    hash.sha256(0, filesize) == "f35b6cb6af991bfa735e039f6bc0e49c69759c015a2074b87eed8f20e4200135"
}

rule MalwareBazaar_RemcosRAT_012_34da1d04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34da1d049c92313152f28cdf5bad644bff93cc6beca25e139453e20ed7a1a85f"
    family = "RemcosRAT"
    file_name = "PO.bat.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:13"
  condition:
    hash.sha256(0, filesize) == "34da1d049c92313152f28cdf5bad644bff93cc6beca25e139453e20ed7a1a85f"
}

rule MalwareBazaar_njrat_013_df4e3625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df4e36252bf8a2b1dee291bcaf9e0505246cacc1d1ea9db3494f30c8506ba0cb"
    family = "njrat"
    file_name = "1b622c451fcc9d83aad8bf45b1c42b5f.exe"
    file_type = "exe"
    first_seen = "2026-07-10 03:10:09"
  condition:
    hash.sha256(0, filesize) == "df4e36252bf8a2b1dee291bcaf9e0505246cacc1d1ea9db3494f30c8506ba0cb"
}

rule MalwareBazaar_unknown_014_ac255036
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac255036bfc86ebfedcc638e79fb2cf98ac70942c325a52e45fa33c2eea0f063"
    family = "unknown"
    file_name = "ORDER-27098-07PDF.vbs"
    file_type = "unknown"
    first_seen = "2026-07-10 03:10:06"
  condition:
    hash.sha256(0, filesize) == "ac255036bfc86ebfedcc638e79fb2cf98ac70942c325a52e45fa33c2eea0f063"
}

rule MalwareBazaar_unknown_015_b8165568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8165568c11eabc56eb6f059fc02c64a7ae6e1ac6ab723abe76f99badc1ce293"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 03:09:40"
  condition:
    hash.sha256(0, filesize) == "b8165568c11eabc56eb6f059fc02c64a7ae6e1ac6ab723abe76f99badc1ce293"
}

rule MalwareBazaar_unknown_016_c25a08d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c25a08d59a215dce54ce9aed5636d5958eb6b87daee3b40ae666f92951be37f6"
    family = "unknown"
    file_name = "dsetup.dll"
    file_type = "dll"
    first_seen = "2026-07-10 02:57:29"
  condition:
    hash.sha256(0, filesize) == "c25a08d59a215dce54ce9aed5636d5958eb6b87daee3b40ae666f92951be37f6"
}

rule MalwareBazaar_unknown_017_f101a45d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f101a45d8085c6fc1fa111aa9219abe2adcc16705f3ebeb91626fbd085ba9d13"
    family = "unknown"
    file_name = "ryujinx.zip"
    file_type = "zip"
    first_seen = "2026-07-10 02:56:41"
  condition:
    hash.sha256(0, filesize) == "f101a45d8085c6fc1fa111aa9219abe2adcc16705f3ebeb91626fbd085ba9d13"
}

rule MalwareBazaar_unknown_018_c6a71252
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6a712524646dd2775b996884b15277439de1962b27a450530fdbd0de460cffa"
    family = "unknown"
    file_name = "dsetup.dll"
    file_type = "dll"
    first_seen = "2026-07-10 02:55:27"
  condition:
    hash.sha256(0, filesize) == "c6a712524646dd2775b996884b15277439de1962b27a450530fdbd0de460cffa"
}

rule MalwareBazaar_unknown_019_5c01b3af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c01b3af2ca6b789a8006d902f738f81bb99c1696b352c1e6444fdd78b37cdcf"
    family = "unknown"
    file_name = "letsview_setup.zip"
    file_type = "zip"
    first_seen = "2026-07-10 02:54:28"
  condition:
    hash.sha256(0, filesize) == "5c01b3af2ca6b789a8006d902f738f81bb99c1696b352c1e6444fdd78b37cdcf"
}

rule MalwareBazaar_unknown_020_b4d0f84e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4d0f84e44a782b5c98c48a34a5442bde600f59e451a067f5ea28d3cbe528966"
    family = "unknown"
    file_name = "dsetup.dll"
    file_type = "dll"
    first_seen = "2026-07-10 02:53:00"
  condition:
    hash.sha256(0, filesize) == "b4d0f84e44a782b5c98c48a34a5442bde600f59e451a067f5ea28d3cbe528966"
}

rule MalwareBazaar_unknown_021_36bd5ca4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36bd5ca4aaedc3d7f377de097ba915eaf4774fb07cb080aec7e5359c7128c1a6"
    family = "unknown"
    file_name = "ivcam.zip"
    file_type = "zip"
    first_seen = "2026-07-10 02:52:19"
  condition:
    hash.sha256(0, filesize) == "36bd5ca4aaedc3d7f377de097ba915eaf4774fb07cb080aec7e5359c7128c1a6"
}

rule MalwareBazaar_unknown_022_81438ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81438ec974a24527a4218f451214e4abeda74c6d112c2b2366571d1ba8eb700e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 02:52:01"
  condition:
    hash.sha256(0, filesize) == "81438ec974a24527a4218f451214e4abeda74c6d112c2b2366571d1ba8eb700e"
}

rule MalwareBazaar_unknown_023_53f0f718
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53f0f718847c209a482f3fa3f52a5ce5245af57da1aa03ecb84d9c3133750955"
    family = "unknown"
    file_name = "dsetup.dll"
    file_type = "dll"
    first_seen = "2026-07-10 02:37:04"
  condition:
    hash.sha256(0, filesize) == "53f0f718847c209a482f3fa3f52a5ce5245af57da1aa03ecb84d9c3133750955"
}

rule MalwareBazaar_unknown_024_122bf005
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "122bf0050365d7b9ceec62e7359d03d6285db98f3c7bb898ef3cdc22e6d70f24"
    family = "unknown"
    file_name = "winscp_setup.zip"
    file_type = "zip"
    first_seen = "2026-07-10 02:35:12"
  condition:
    hash.sha256(0, filesize) == "122bf0050365d7b9ceec62e7359d03d6285db98f3c7bb898ef3cdc22e6d70f24"
}

rule MalwareBazaar_SalatStealer_025_a6b325e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6b325e695644ddaaf6edf0c41604179fd53d1e515afa52e5d526426a4644d76"
    family = "SalatStealer"
    file_name = "setup-Happ.x64.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:32:38"
  condition:
    hash.sha256(0, filesize) == "a6b325e695644ddaaf6edf0c41604179fd53d1e515afa52e5d526426a4644d76"
}

rule MalwareBazaar_SalatStealer_026_d632a742
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d632a7428a5a8a6c4642ba4ddecfbbe96e28ed030a204156c5018527ba4a6b46"
    family = "SalatStealer"
    file_name = "setup-Happ.x64.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:31:35"
  condition:
    hash.sha256(0, filesize) == "d632a7428a5a8a6c4642ba4ddecfbbe96e28ed030a204156c5018527ba4a6b46"
}

rule MalwareBazaar_unknown_027_59eb2fad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59eb2fad261dc13a1e9bfab3a57cd51a4841f82787130202ff348bbaf2c6409d"
    family = "unknown"
    file_name = "nvd_driver_dll.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:12:22"
  condition:
    hash.sha256(0, filesize) == "59eb2fad261dc13a1e9bfab3a57cd51a4841f82787130202ff348bbaf2c6409d"
}

rule MalwareBazaar_unknown_028_1fc2634e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fc2634ee7f9bdddc44bdb2424e898e71d844b8935c2d9c6bb208a6a5befba9e"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:11:32"
  condition:
    hash.sha256(0, filesize) == "1fc2634ee7f9bdddc44bdb2424e898e71d844b8935c2d9c6bb208a6a5befba9e"
}

rule MalwareBazaar_unknown_029_8b218bfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b218bfe6b176c32b971029e4c038f33f4619689c69246fc7e4567386c9ed8dc"
    family = "unknown"
    file_name = "Dqgz6WdgM7ak.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:08:16"
  condition:
    hash.sha256(0, filesize) == "8b218bfe6b176c32b971029e4c038f33f4619689c69246fc7e4567386c9ed8dc"
}

rule MalwareBazaar_unknown_030_7ee796a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ee796a8fef94d38a6ef3d906fe3d37052b5b6c2435420dcc75e459fbc501a68"
    family = "unknown"
    file_name = "Nix.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:06:02"
  condition:
    hash.sha256(0, filesize) == "7ee796a8fef94d38a6ef3d906fe3d37052b5b6c2435420dcc75e459fbc501a68"
}

rule MalwareBazaar_unknown_031_1b582f86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b582f86043113376d91e7e699e0c7b9b62dce358a77a1ae0c7cd6f0d219a7d2"
    family = "unknown"
    file_name = "rSRL405120008.exe"
    file_type = "exe"
    first_seen = "2026-07-10 02:02:17"
  condition:
    hash.sha256(0, filesize) == "1b582f86043113376d91e7e699e0c7b9b62dce358a77a1ae0c7cd6f0d219a7d2"
}

rule MalwareBazaar_unknown_032_e08ba6b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e08ba6b6bd164546cc8f8819ab67d22f7a410d6fe9bbb2e350dbe24786e93d55"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-07-10 01:55:55"
  condition:
    hash.sha256(0, filesize) == "e08ba6b6bd164546cc8f8819ab67d22f7a410d6fe9bbb2e350dbe24786e93d55"
}

rule MalwareBazaar_SalatStealer_033_d9e8f073
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9e8f073c050b9f75f78003c05cc77bc0b60fb5bbdfb980fe6216fa0fd8ace6a"
    family = "SalatStealer"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-07-10 01:55:39"
  condition:
    hash.sha256(0, filesize) == "d9e8f073c050b9f75f78003c05cc77bc0b60fb5bbdfb980fe6216fa0fd8ace6a"
}

rule MalwareBazaar_unknown_034_f101fda6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f101fda6093f12758efae630bc265d6bad71479249685b7503c05e707424a276"
    family = "unknown"
    file_name = "windows.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:53:55"
  condition:
    hash.sha256(0, filesize) == "f101fda6093f12758efae630bc265d6bad71479249685b7503c05e707424a276"
}

rule MalwareBazaar_unknown_035_f0d032c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0d032c835744156d134ff521c8bc2996f0d7922c7c0c8c31f12fb27d7dddc99"
    family = "unknown"
    file_name = "macos.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:53:53"
  condition:
    hash.sha256(0, filesize) == "f0d032c835744156d134ff521c8bc2996f0d7922c7c0c8c31f12fb27d7dddc99"
}

rule MalwareBazaar_unknown_036_2d8d12f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d8d12f404151317ff562585b5d2e5ba728b7e8aba60d950835a1a80e6462c3f"
    family = "unknown"
    file_name = "linux.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:53:50"
  condition:
    hash.sha256(0, filesize) == "2d8d12f404151317ff562585b5d2e5ba728b7e8aba60d950835a1a80e6462c3f"
}

rule MalwareBazaar_unknown_037_7135a3a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7135a3a2239145504e6fdc81bcdef7bcbd69a06727b638a59ba1f3e76130eb1d"
    family = "unknown"
    file_name = "w.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:53:48"
  condition:
    hash.sha256(0, filesize) == "7135a3a2239145504e6fdc81bcdef7bcbd69a06727b638a59ba1f3e76130eb1d"
}

rule MalwareBazaar_unknown_038_9580aefa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9580aefa4e99bac7914a988a79688ef6173ee0e0175b993cdfcfea72cc40703b"
    family = "unknown"
    file_name = "l.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:53:45"
  condition:
    hash.sha256(0, filesize) == "9580aefa4e99bac7914a988a79688ef6173ee0e0175b993cdfcfea72cc40703b"
}

rule MalwareBazaar_unknown_039_281d4d60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "281d4d60fc99cf7f54819defb1c7c14b9202d46890936c4c6b9ebe3ddc75dd2f"
    family = "unknown"
    file_name = "parser.js"
    file_type = "js"
    first_seen = "2026-07-10 01:53:41"
  condition:
    hash.sha256(0, filesize) == "281d4d60fc99cf7f54819defb1c7c14b9202d46890936c4c6b9ebe3ddc75dd2f"
}

rule MalwareBazaar_unknown_040_56ca405f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56ca405fa5c12838051af41d5b515a3dc6064531eaabe635242d13e0e72de848"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 01:52:03"
  condition:
    hash.sha256(0, filesize) == "56ca405fa5c12838051af41d5b515a3dc6064531eaabe635242d13e0e72de848"
}

rule MalwareBazaar_unknown_041_3167c1f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3167c1f795dceb0642b2a446b30f137d4187b2a908990b2ce630036d45b67087"
    family = "unknown"
    file_name = "m.body"
    file_type = "unknown"
    first_seen = "2026-07-10 01:51:32"
  condition:
    hash.sha256(0, filesize) == "3167c1f795dceb0642b2a446b30f137d4187b2a908990b2ce630036d45b67087"
}

rule MalwareBazaar_unknown_042_5af50126
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5af50126946695fdd63c761bad06b5644f686a3b7ab3e3ac39d2c9ac870bf032"
    family = "unknown"
    file_name = "preplan.tar.gz"
    file_type = "gz"
    first_seen = "2026-07-10 01:48:09"
  condition:
    hash.sha256(0, filesize) == "5af50126946695fdd63c761bad06b5644f686a3b7ab3e3ac39d2c9ac870bf032"
}

rule MalwareBazaar_unknown_043_6db4c3d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6db4c3d2ab56227d36eff59d1dc9e13eadf9959996fab1e0b04591cc5e637d04"
    family = "unknown"
    file_name = "loader.js"
    file_type = "js"
    first_seen = "2026-07-10 01:48:06"
  condition:
    hash.sha256(0, filesize) == "6db4c3d2ab56227d36eff59d1dc9e13eadf9959996fab1e0b04591cc5e637d04"
}

rule MalwareBazaar_NanoCore_044_dacc3d21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dacc3d21d8d1e49fd7728f3500943b9eddd80589264d939fbe1fd880fe03938d"
    family = "NanoCore"
    file_name = "xoilacbongda-wc2026a.tv.exe"
    file_type = "exe"
    first_seen = "2026-07-10 01:45:05"
  condition:
    hash.sha256(0, filesize) == "dacc3d21d8d1e49fd7728f3500943b9eddd80589264d939fbe1fd880fe03938d"
}

rule MalwareBazaar_unknown_045_30851708
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3085170853d70615dff57549f0e44e6c3f86c35f36d658aeed03bf728061f2db"
    family = "unknown"
    file_name = "Gigantiske.vbs"
    file_type = "vbs"
    first_seen = "2026-07-10 01:33:59"
  condition:
    hash.sha256(0, filesize) == "3085170853d70615dff57549f0e44e6c3f86c35f36d658aeed03bf728061f2db"
}

rule MalwareBazaar_unknown_046_9a42d843
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a42d843c5c0dd751898a0bec5a68d0fc097364788f99cdba6533b2f125b4a5f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 00:52:05"
  condition:
    hash.sha256(0, filesize) == "9a42d843c5c0dd751898a0bec5a68d0fc097364788f99cdba6533b2f125b4a5f"
}

rule MalwareBazaar_Cobalt_Strike_047_41bfb4bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41bfb4bb51823fd994d0f34504be227ea6367c9506bb99ca0f1bef6968fd7fba"
    family = "Cobalt Strike"
    file_name = "javaw64_xor.exe"
    file_type = "exe"
    first_seen = "2026-07-10 00:29:53"
  condition:
    hash.sha256(0, filesize) == "41bfb4bb51823fd994d0f34504be227ea6367c9506bb99ca0f1bef6968fd7fba"
}

rule MalwareBazaar_unknown_048_5ac0761c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ac0761c29fc5487ce913ce7457117844a269cd1058e96ac0ce3b8b6ca017caf"
    family = "unknown"
    file_name = "package"
    file_type = "zip"
    first_seen = "2026-07-10 00:10:15"
  condition:
    hash.sha256(0, filesize) == "5ac0761c29fc5487ce913ce7457117844a269cd1058e96ac0ce3b8b6ca017caf"
}

rule MalwareBazaar_CoinMiner_049_158380eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "158380ebd870255fbf0ecc986480b6ec4601a5074db9bb2ff41cdb626dbee2be"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 00:00:48"
  condition:
    hash.sha256(0, filesize) == "158380ebd870255fbf0ecc986480b6ec4601a5074db9bb2ff41cdb626dbee2be"
}

rule MalwareBazaar_unknown_050_ed74b54a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed74b54adeea87f6c2b55e5d4344011a3f4cc660af29493c87ffa1804d1d0c82"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 23:52:04"
  condition:
    hash.sha256(0, filesize) == "ed74b54adeea87f6c2b55e5d4344011a3f4cc660af29493c87ffa1804d1d0c82"
}

rule MalwareBazaar_unknown_051_d245a4ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d245a4abe50cde648ca38cf0c05b95f5c25ffb83683fe6413621c2e3634afacb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-09 23:30:29"
  condition:
    hash.sha256(0, filesize) == "d245a4abe50cde648ca38cf0c05b95f5c25ffb83683fe6413621c2e3634afacb"
}

rule MalwareBazaar_unknown_052_cfd7ad5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfd7ad5fd929fbdef0af698ee1f7f1624ed46109a50125f7ab39b14bd84dfcac"
    family = "unknown"
    file_name = "cfd7ad5fd929fbdef0af698ee1f7f1624ed46109a50125f7ab39b14bd84dfcac"
    file_type = "elf"
    first_seen = "2026-07-09 23:16:30"
  condition:
    hash.sha256(0, filesize) == "cfd7ad5fd929fbdef0af698ee1f7f1624ed46109a50125f7ab39b14bd84dfcac"
}

rule MalwareBazaar_WannaCry_053_d8c36edf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8c36edf382ffb8ba83d05881e9b31bfa1d33a787b945685cf512b80ab00fc2c"
    family = "WannaCry"
    file_name = "d8c36edf382ffb8ba83d05881e9b31bfa1d33a787b945685cf512b80ab00fc2c"
    file_type = "exe"
    first_seen = "2026-07-09 23:15:39"
  condition:
    hash.sha256(0, filesize) == "d8c36edf382ffb8ba83d05881e9b31bfa1d33a787b945685cf512b80ab00fc2c"
}

rule MalwareBazaar_Vidar_054_29f10166
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29f1016661c51389d799e1c6e5afa5e9c2fc142c7f5382f60f3f08ed223adfbb"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-09 23:04:23"
  condition:
    hash.sha256(0, filesize) == "29f1016661c51389d799e1c6e5afa5e9c2fc142c7f5382f60f3f08ed223adfbb"
}

rule MalwareBazaar_unknown_055_aeed7c42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aeed7c42c5a0de1913b826911ce5926f1b05807170d7ac34f2e511b9458593a8"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 22:52:05"
  condition:
    hash.sha256(0, filesize) == "aeed7c42c5a0de1913b826911ce5926f1b05807170d7ac34f2e511b9458593a8"
}

rule MalwareBazaar_unknown_056_92bab327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92bab327f0800fe67fdd049fc76f9acfcbd5c5b79794187192f48c6cae0e0724"
    family = "unknown"
    file_name = "file.js"
    file_type = "js"
    first_seen = "2026-07-09 22:35:00"
  condition:
    hash.sha256(0, filesize) == "92bab327f0800fe67fdd049fc76f9acfcbd5c5b79794187192f48c6cae0e0724"
}

rule MalwareBazaar_unknown_057_2186a1d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2186a1d4bafc51969dc84c97aafea7231cbbbb55566fca72a5df983060099f5a"
    family = "unknown"
    file_name = "update-mixed-22001166.zip"
    file_type = "zip"
    first_seen = "2026-07-09 22:32:34"
  condition:
    hash.sha256(0, filesize) == "2186a1d4bafc51969dc84c97aafea7231cbbbb55566fca72a5df983060099f5a"
}

rule MalwareBazaar_unknown_058_8602b5a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8602b5a93f61ef26519762e545df3a252ac765cd2e8062837722d049bf1ab34d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 21:52:07"
  condition:
    hash.sha256(0, filesize) == "8602b5a93f61ef26519762e545df3a252ac765cd2e8062837722d049bf1ab34d"
}

rule MalwareBazaar_unknown_059_3a9d703b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a9d703ba7f7564399365db7ab8b04238806ef7a53df0b6822f32b80bf0f5a80"
    family = "unknown"
    file_name = "dev.golove.velto"
    file_type = "unknown"
    first_seen = "2026-07-09 21:21:41"
  condition:
    hash.sha256(0, filesize) == "3a9d703ba7f7564399365db7ab8b04238806ef7a53df0b6822f32b80bf0f5a80"
}

rule MalwareBazaar_WannaCry_060_41a35436
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41a35436cb79c95001b2fdb7076e26c996bc9a913d64c7f54db9507882773120"
    family = "WannaCry"
    file_name = "41a35436cb79c95001b2fdb7076e26c996bc9a913d64c7f54db9507882773120"
    file_type = "exe"
    first_seen = "2026-07-09 21:15:17"
  condition:
    hash.sha256(0, filesize) == "41a35436cb79c95001b2fdb7076e26c996bc9a913d64c7f54db9507882773120"
}

rule MalwareBazaar_unknown_061_725c24ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "725c24ec04fba51daa1f30f2b463759c9443ddc284261a58d96979e9a97eb436"
    family = "unknown"
    file_name = "725c24ec04fba51daa1f30f2b463759c9443ddc284261a58d96979e9a97eb436"
    file_type = "sh"
    first_seen = "2026-07-09 21:12:15"
  condition:
    hash.sha256(0, filesize) == "725c24ec04fba51daa1f30f2b463759c9443ddc284261a58d96979e9a97eb436"
}

rule MalwareBazaar_unknown_062_e81c8b5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e81c8b5bc8b6be982906ef0b4932074225f5b46757d898dedf480c0cf8011861"
    family = "unknown"
    file_name = "e81c8b5bc8b6be982906ef0b4932074225f5b46757d898dedf480c0cf8011861"
    file_type = "sh"
    first_seen = "2026-07-09 21:00:47"
  condition:
    hash.sha256(0, filesize) == "e81c8b5bc8b6be982906ef0b4932074225f5b46757d898dedf480c0cf8011861"
}

rule MalwareBazaar_unknown_063_8451b01c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8451b01ca5c1059121cc0ea724c2e2d98bc761a3aa00618f514babfff74d337a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 20:52:05"
  condition:
    hash.sha256(0, filesize) == "8451b01ca5c1059121cc0ea724c2e2d98bc761a3aa00618f514babfff74d337a"
}

rule MalwareBazaar_unknown_064_30668745
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3066874504f49274ec261de95cf94797158d0a169a61d9e546eb2df731b1b74b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-09 20:40:47"
  condition:
    hash.sha256(0, filesize) == "3066874504f49274ec261de95cf94797158d0a169a61d9e546eb2df731b1b74b"
}

rule MalwareBazaar_unknown_065_d0776642
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d07766429ea14ac3c403bde5a9498a9fe161a059eea212b3baf3f520b078f709"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-09 20:33:06"
  condition:
    hash.sha256(0, filesize) == "d07766429ea14ac3c403bde5a9498a9fe161a059eea212b3baf3f520b078f709"
}

rule MalwareBazaar_unknown_066_92d93285
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92d93285e39e37750ba59f7127807f3c9d4de18fb8efe386042587e204604108"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-09 20:29:27"
  condition:
    hash.sha256(0, filesize) == "92d93285e39e37750ba59f7127807f3c9d4de18fb8efe386042587e204604108"
}

rule MalwareBazaar_unknown_067_3ba2080a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ba2080a5a4791a7a8c5ea42ac40826bfca758f3abea4da90d3f22fbc50c2d60"
    family = "unknown"
    file_name = "推特提号器q.exe"
    file_type = "exe"
    first_seen = "2026-07-09 20:25:23"
  condition:
    hash.sha256(0, filesize) == "3ba2080a5a4791a7a8c5ea42ac40826bfca758f3abea4da90d3f22fbc50c2d60"
}

rule MalwareBazaar_Mirai_068_b689762c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b689762ccfcd2350f30e36203e89847fe1a3e8e60b74e91b082ae4e4a5d5353d"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-09 20:25:13"
  condition:
    hash.sha256(0, filesize) == "b689762ccfcd2350f30e36203e89847fe1a3e8e60b74e91b082ae4e4a5d5353d"
}

rule MalwareBazaar_unknown_069_a98d50be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a98d50beff9c89aa88280e3f6112c2cfaa150385b40656440c2a023b03e5662b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-09 20:23:32"
  condition:
    hash.sha256(0, filesize) == "a98d50beff9c89aa88280e3f6112c2cfaa150385b40656440c2a023b03e5662b"
}

rule MalwareBazaar_unknown_070_3b6fa856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b6fa85634e3aa554424e53bd0a9b7317aeca0f25a5d6903b83dc9f42e71ad4b"
    family = "unknown"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-07-09 20:15:04"
  condition:
    hash.sha256(0, filesize) == "3b6fa85634e3aa554424e53bd0a9b7317aeca0f25a5d6903b83dc9f42e71ad4b"
}

rule MalwareBazaar_Mirai_071_aa77c325
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa77c3256a16b91d2621d797cb8cf16f0254bd587a511d4e75f54de51c304c0f"
    family = "Mirai"
    file_name = "void.mpsl"
    file_type = "elf"
    first_seen = "2026-07-09 20:13:32"
  condition:
    hash.sha256(0, filesize) == "aa77c3256a16b91d2621d797cb8cf16f0254bd587a511d4e75f54de51c304c0f"
}

rule MalwareBazaar_Mirai_072_7ff7ad40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ff7ad40017d89d4e399c70bb79f1db6bdb57aea05939748cdfe3b9f1527c21f"
    family = "Mirai"
    file_name = "void.sh4"
    file_type = "elf"
    first_seen = "2026-07-09 20:12:28"
  condition:
    hash.sha256(0, filesize) == "7ff7ad40017d89d4e399c70bb79f1db6bdb57aea05939748cdfe3b9f1527c21f"
}

rule MalwareBazaar_unknown_073_2f0ba36e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f0ba36eb00eedff7a6c8eabbd2436998dc5756dc57219476553fca52b203a5e"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-09 20:07:22"
  condition:
    hash.sha256(0, filesize) == "2f0ba36eb00eedff7a6c8eabbd2436998dc5756dc57219476553fca52b203a5e"
}

rule MalwareBazaar_AveMariaRAT_074_72b2bb12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72b2bb12dedd3cc8b5d9a977adb6f8b68b3ce3a26bc20c277fa49f1b59048f9a"
    family = "AveMariaRAT"
    file_name = "rTransferencia.exe"
    file_type = "exe"
    first_seen = "2026-07-09 20:00:07"
  condition:
    hash.sha256(0, filesize) == "72b2bb12dedd3cc8b5d9a977adb6f8b68b3ce3a26bc20c277fa49f1b59048f9a"
}

rule MalwareBazaar_Mirai_075_5caf5e70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5caf5e70726c56bc484171aa8a2f7f322d1629135574500c33eb74d3860c9bce"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-09 19:58:14"
  condition:
    hash.sha256(0, filesize) == "5caf5e70726c56bc484171aa8a2f7f322d1629135574500c33eb74d3860c9bce"
}

rule MalwareBazaar_unknown_076_8848d6f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8848d6f5e76195a4a4190deb3b5766ce67615ef6347837d893349e719eed0b47"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-09 19:55:07"
  condition:
    hash.sha256(0, filesize) == "8848d6f5e76195a4a4190deb3b5766ce67615ef6347837d893349e719eed0b47"
}

rule MalwareBazaar_Efimer_077_719f0987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "719f09877c07bf12dca4f9196d4c2eb5af5cb36fc6c55a644a762997cc4e470e"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 19:52:08"
  condition:
    hash.sha256(0, filesize) == "719f09877c07bf12dca4f9196d4c2eb5af5cb36fc6c55a644a762997cc4e470e"
}

rule MalwareBazaar_unknown_078_ba826be9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba826be9b66bc82c62d13d33c5c90edc6994d21948e854203d60ded683e45c9f"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-09 19:51:33"
  condition:
    hash.sha256(0, filesize) == "ba826be9b66bc82c62d13d33c5c90edc6994d21948e854203d60ded683e45c9f"
}

rule MalwareBazaar_unknown_079_eb82a907
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb82a907d60ef93a1adfb5f5881a54d9b5f626cfce3206aa8a21aa9e7d76f765"
    family = "unknown"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-07-09 19:42:12"
  condition:
    hash.sha256(0, filesize) == "eb82a907d60ef93a1adfb5f5881a54d9b5f626cfce3206aa8a21aa9e7d76f765"
}

rule MalwareBazaar_unknown_080_9ebc81fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ebc81fcb58ca55f4b7368a9b80ac4521144b7c9e55788b054d3bf8bcea7a533"
    family = "unknown"
    file_name = "Netorase.exe"
    file_type = "exe"
    first_seen = "2026-07-09 19:38:46"
  condition:
    hash.sha256(0, filesize) == "9ebc81fcb58ca55f4b7368a9b80ac4521144b7c9e55788b054d3bf8bcea7a533"
}

rule MalwareBazaar_unknown_081_db3d4d4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db3d4d4ae5f9acf1a3922e229fba045046d62c2c765cdc7821347e5b7357275d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-09 19:34:23"
  condition:
    hash.sha256(0, filesize) == "db3d4d4ae5f9acf1a3922e229fba045046d62c2c765cdc7821347e5b7357275d"
}

rule MalwareBazaar_Vidar_082_6880110b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6880110bb6b5caf0b41af519e5463fed007fa8101f2a37a543654322dada345d"
    family = "Vidar"
    file_name = "KungFu.exe"
    file_type = "exe"
    first_seen = "2026-07-09 19:32:53"
  condition:
    hash.sha256(0, filesize) == "6880110bb6b5caf0b41af519e5463fed007fa8101f2a37a543654322dada345d"
}

rule MalwareBazaar_Mirai_083_e951ad2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e951ad2d9c9e5e499c7f8b3ca795a58f4c935873a20f51cb1882b11474038ce0"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-09 19:32:08"
  condition:
    hash.sha256(0, filesize) == "e951ad2d9c9e5e499c7f8b3ca795a58f4c935873a20f51cb1882b11474038ce0"
}

rule MalwareBazaar_unknown_084_93222e8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93222e8d11c8973821f86ccf658aba2ed6d3ac044ad56bac58a70bad2f6d1482"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-09 19:28:28"
  condition:
    hash.sha256(0, filesize) == "93222e8d11c8973821f86ccf658aba2ed6d3ac044ad56bac58a70bad2f6d1482"
}

rule MalwareBazaar_unknown_085_f57d00c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f57d00c4b273dcd3b8d5fa73c63d26a861dba2d4d240c555c8e78c928a24f4a2"
    family = "unknown"
    file_name = "PR# 122883 _ YMFOS.exe"
    file_type = "exe"
    first_seen = "2026-07-09 19:25:27"
  condition:
    hash.sha256(0, filesize) == "f57d00c4b273dcd3b8d5fa73c63d26a861dba2d4d240c555c8e78c928a24f4a2"
}

rule MalwareBazaar_LegionLoader_086_595e3d46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "595e3d46169a51dcf93d15690d34508726729c6f6cdfec88b5e366070934537d"
    family = "LegionLoader"
    file_name = "a.exe"
    file_type = "exe"
    first_seen = "2026-07-09 19:17:46"
  condition:
    hash.sha256(0, filesize) == "595e3d46169a51dcf93d15690d34508726729c6f6cdfec88b5e366070934537d"
}

rule MalwareBazaar_unknown_087_d8def83b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8def83bb0ebac9cc0554f6cc9ab0394d992d0e53d0e896b849d1d553a84eecc"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-09 19:15:06"
  condition:
    hash.sha256(0, filesize) == "d8def83bb0ebac9cc0554f6cc9ab0394d992d0e53d0e896b849d1d553a84eecc"
}

rule MalwareBazaar_unknown_088_7d2ae2a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d2ae2a214a78507141ac7dff3e0757e392db7b626e30b925e555ccbc13ebe6f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-09 19:15:05"
  condition:
    hash.sha256(0, filesize) == "7d2ae2a214a78507141ac7dff3e0757e392db7b626e30b925e555ccbc13ebe6f"
}

rule MalwareBazaar_unknown_089_243b8f76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "243b8f76eb8491091fcce90f7ccdbf081958a4b371e739ecdbb2ec1738aababe"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-09 19:13:58"
  condition:
    hash.sha256(0, filesize) == "243b8f76eb8491091fcce90f7ccdbf081958a4b371e739ecdbb2ec1738aababe"
}

rule MalwareBazaar_unknown_090_1878af2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1878af2ede36c2bda6735f859c306a9bda538933193d8f46de8fcf4573ae5c88"
    family = "unknown"
    file_name = "1878af2ede36c2bda6735f859c306a9bda538933193d8f46de8fcf4573ae5c88"
    file_type = "unknown"
    first_seen = "2026-07-09 19:13:11"
  condition:
    hash.sha256(0, filesize) == "1878af2ede36c2bda6735f859c306a9bda538933193d8f46de8fcf4573ae5c88"
}

rule MalwareBazaar_unknown_091_32f368c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f368c31812bb7a9704c0e250ba8e90845ce06d107f36360117de30818c2da2"
    family = "unknown"
    file_name = "32f368c31812bb7a9704c0e250ba8e90845ce06d107f36360117de30818c2da2"
    file_type = "sh"
    first_seen = "2026-07-09 19:13:09"
  condition:
    hash.sha256(0, filesize) == "32f368c31812bb7a9704c0e250ba8e90845ce06d107f36360117de30818c2da2"
}

rule MalwareBazaar_Vidar_092_4cca32f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cca32f774fe33f96b8cca18dc5b24bf93abe684516f2722331f49f66d2b940e"
    family = "Vidar"
    file_name = "KungFu_patched.exe"
    file_type = "exe"
    first_seen = "2026-07-09 19:11:28"
  condition:
    hash.sha256(0, filesize) == "4cca32f774fe33f96b8cca18dc5b24bf93abe684516f2722331f49f66d2b940e"
}

rule MalwareBazaar_Vidar_093_96da1853
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96da185331e1daaac8bf43071c290ebc03cae73e968930d25ec7b63df7b5f27d"
    family = "Vidar"
    file_name = "KungFu.7z"
    file_type = "7z"
    first_seen = "2026-07-09 19:10:29"
  condition:
    hash.sha256(0, filesize) == "96da185331e1daaac8bf43071c290ebc03cae73e968930d25ec7b63df7b5f27d"
}

rule MalwareBazaar_Mirai_094_73bcca5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73bcca5b454619b329fd696ba5049fb404b38857702dd65e2f093851076fda38"
    family = "Mirai"
    file_name = "kaizen.arm7sf_srv"
    file_type = "elf"
    first_seen = "2026-07-09 19:09:18"
  condition:
    hash.sha256(0, filesize) == "73bcca5b454619b329fd696ba5049fb404b38857702dd65e2f093851076fda38"
}

rule MalwareBazaar_Mirai_095_04894612
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0489461205b62afa1bd96de91a2afb92c0da0b0d03c6b64f9619b983dd219502"
    family = "Mirai"
    file_name = "kaizen.x86_64_srv"
    file_type = "elf"
    first_seen = "2026-07-09 19:08:45"
  condition:
    hash.sha256(0, filesize) == "0489461205b62afa1bd96de91a2afb92c0da0b0d03c6b64f9619b983dd219502"
}

rule MalwareBazaar_Mirai_096_0e9d63c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e9d63c1a463dd4736d486a3cc014f0bfc376c56e01d39b2bc05c10ec4b132fc"
    family = "Mirai"
    file_name = "kaizen.x86_64_srv"
    file_type = "elf"
    first_seen = "2026-07-09 19:08:12"
  condition:
    hash.sha256(0, filesize) == "0e9d63c1a463dd4736d486a3cc014f0bfc376c56e01d39b2bc05c10ec4b132fc"
}

rule MalwareBazaar_Mirai_097_0f53ffd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f53ffd52bacfb588af6425033e5f391147aaf47002b813dee2aabad1768403d"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-09 19:04:12"
  condition:
    hash.sha256(0, filesize) == "0f53ffd52bacfb588af6425033e5f391147aaf47002b813dee2aabad1768403d"
}

rule MalwareBazaar_unknown_098_991721e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "991721e0913df2064a98d27cc143094f1fb57caa934cff46da74d068f466ee12"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-09 19:04:11"
  condition:
    hash.sha256(0, filesize) == "991721e0913df2064a98d27cc143094f1fb57caa934cff46da74d068f466ee12"
}

rule MalwareBazaar_Mirai_099_df6feb0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df6feb0ac8a10f63e2058894dd831280080f7c40ce065270d5b7ea5d9a326217"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-09 19:02:41"
  condition:
    hash.sha256(0, filesize) == "df6feb0ac8a10f63e2058894dd831280080f7c40ce065270d5b7ea5d9a326217"
}

rule MalwareBazaar_Efimer_100_85db7625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85db7625a733ec1cd1fb244ba15b78c4a2485c2a119836e87257e7ccc05c5145"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-09 18:52:07"
  condition:
    hash.sha256(0, filesize) == "85db7625a733ec1cd1fb244ba15b78c4a2485c2a119836e87257e7ccc05c5145"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

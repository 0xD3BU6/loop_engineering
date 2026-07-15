# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-15

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 674 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 674 |
| Unique family labels | 16 |
| Unique file types | 13 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 40 |
| Mirai | 22 |
| ConnectWise | 17 |
| Efimer | 6 |
| WannaCry | 3 |
| ArkeiStealer | 2 |
| Vidar | 1 |
| GCleaner | 1 |
| PureLogsStealer | 1 |
| CoinMiner | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 47 |
| elf | 23 |
| sh | 15 |
| ps1 | 3 |
| js | 3 |
| vbs | 2 |
| bat | 1 |
| docx | 1 |
| applescript | 1 |
| xlsx | 1 |

## Per-Sample Analysis

### Sample 1: `406c33efa357e5b7`

| Field | Value |
|---|---|
| SHA-256 | `406c33efa357e5b7f95257b7e34855ab44cfc3c7d93272d50d1e78a68a40fe11` |
| Family label | `ConnectWise` |
| File name | `Adobe_Acrobat.bat` |
| File type | `bat` |
| First seen | `2026-07-15 03:10:49` |
| Reporter | `nat` |
| Tags | `bat, ConnectWise` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8544dc256d3f898f2ac7fa9d941b8ef4` |
| SHA-1 | `91deba90def8ea5dd96a5eadc4955d41c4c2c594` |
| SHA-256 | `406c33efa357e5b7f95257b7e34855ab44cfc3c7d93272d50d1e78a68a40fe11` |
| SHA3-384 | `72b15f17600a3f7fe8bbe5b8704985dc5aefde80f8bd4695172a84aab07721db3c926a2653858775eacef57729c6f51a` |
| TLSH | `T11A22FE3E361435A617DA4A1A8A2F11413E7A584B03017DC971EE907EDB76EE07BBE1C3` |
| SSDEEP | `192:Kc8v9bFqI1Lf1NVYBvK2xuXY+y3AoFpp5R792VqIdDid9ZXI:Kck9B1rtlo+pOF2VonY` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_001_406c33ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "406c33efa357e5b7f95257b7e34855ab44cfc3c7d93272d50d1e78a68a40fe11"
    family = "ConnectWise"
    file_name = "Adobe_Acrobat.bat"
    file_type = "bat"
    first_seen = "2026-07-15 03:10:49"
  condition:
    hash.sha256(0, filesize) == "406c33efa357e5b7f95257b7e34855ab44cfc3c7d93272d50d1e78a68a40fe11"
}
```

### Sample 2: `84ade85f5b49b00b`

| Field | Value |
|---|---|
| SHA-256 | `84ade85f5b49b00b37df593a973170eb31c3fd771b40f4c753fe9dc1560f5cd8` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-15 02:55:56` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX5.file, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `194fc7dd9b9d09ced1dbf65f6c504c19` |
| SHA-1 | `61588a233d41e6f3c5dc837d8eb76eb42c37dff6` |
| SHA-256 | `84ade85f5b49b00b37df593a973170eb31c3fd771b40f4c753fe9dc1560f5cd8` |
| SHA3-384 | `1ca107ff72fcbeb191c106336860552a9055c914a5486c736c3f570a44c0a2cde48315806ddcb7d6647d48469ec84978` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F075280BBCD009F6D4AA9232896761517B72BC490F3127D73AA0B27C2F727E49E75748` |
| SSDEEP | `24576:HJy81JhKMVSJXDSZhsBYzym3/QBele5yKD9e++vRbui:HJZDhKKSxSEBYzV2KvRbr` |
| ICON-DHASH | `84b4e0e870fce470` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_002_84ade85f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84ade85f5b49b00b37df593a973170eb31c3fd771b40f4c753fe9dc1560f5cd8"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 02:55:56"
  condition:
    hash.sha256(0, filesize) == "84ade85f5b49b00b37df593a973170eb31c3fd771b40f4c753fe9dc1560f5cd8"
}
```

### Sample 3: `4fc8b0280d5b02ff`

| Field | Value |
|---|---|
| SHA-256 | `4fc8b0280d5b02ffdf185530f3366f976f215d147e7d01b1910121330a6dd274` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-15 02:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc9cc1ff3671f2294d440fdf1723c84b` |
| SHA-1 | `abf07d1adecb57194744c7d19fd486b96b1d8f79` |
| SHA-256 | `4fc8b0280d5b02ffdf185530f3366f976f215d147e7d01b1910121330a6dd274` |
| SHA3-384 | `ad075440c574fa0c4c90f2fabaa7f280176d689316dd2cfed485317c074a76b5947ecfa308eb3363631b162c31bde1ea` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1A1E6331427D162EDEE23413CEAE26598F46678B04735C9CF53B847A27E532E48C3DA36` |
| SSDEEP | `393216:pYrUdpD447xgYLNnxRdVyQOrQXMCHWUjXPcuI3/PGTAI:pYkDg2xRdtHXMb8XEH/O7` |
| ICON-DHASH | `e8e865e0d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_4fc8b028
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fc8b0280d5b02ffdf185530f3366f976f215d147e7d01b1910121330a6dd274"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 02:52:10"
  condition:
    hash.sha256(0, filesize) == "4fc8b0280d5b02ffdf185530f3366f976f215d147e7d01b1910121330a6dd274"
}
```

### Sample 4: `91217219b771a295`

| Field | Value |
|---|---|
| SHA-256 | `91217219b771a295b5c51c12308ed49c22c844a035b2b4f309ad6f4a37cadf0b` |
| Family label | `GCleaner` |
| File name | `setup_euone.bin` |
| File type | `exe` |
| First seen | `2026-07-15 02:52:06` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, GCleaner` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a64b250856e49e2752c5e70ebd4d02ce` |
| SHA-1 | `46da5dfac54c272e55f5f3d724ede953e2f9b73f` |
| SHA-256 | `91217219b771a295b5c51c12308ed49c22c844a035b2b4f309ad6f4a37cadf0b` |
| SHA3-384 | `f4cf5c3806d0fb518b3fd693e89513461f74d3a888b18ae3a42f8e7905f3749b4f5c8bb9fdfc08c540568d3e68b7b97c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15BC533586094F903C60677362B28F1FC736EAE6DAD21C5236FDCECDFB460954AC88592` |
| SSDEEP | `49152:HDYl4ghPETWofP4A6YAZ1OKq+fw76iaN5YFEFzgMTA/n17Qtnd9UD:HEl4sPiD6YAZgAY6iI5YwzgEAN6` |

#### Technical Assessment

- The sample is tracked as `GCleaner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GCleaner_004_91217219
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91217219b771a295b5c51c12308ed49c22c844a035b2b4f309ad6f4a37cadf0b"
    family = "GCleaner"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-07-15 02:52:06"
  condition:
    hash.sha256(0, filesize) == "91217219b771a295b5c51c12308ed49c22c844a035b2b4f309ad6f4a37cadf0b"
}
```

### Sample 5: `4d1a0237c82bddae`

| Field | Value |
|---|---|
| SHA-256 | `4d1a0237c82bddae9cd21a434b2e2cb65563d0af942a8b67ae70785fb5f1bf76` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-15 02:22:20` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `def7c0055909f72dd20f2d0a5f79f5c3` |
| SHA-1 | `f3c4990ac6ce249363bbdec35110ce79d9a4f523` |
| SHA-256 | `4d1a0237c82bddae9cd21a434b2e2cb65563d0af942a8b67ae70785fb5f1bf76` |
| SHA3-384 | `06709f354a0edda40297fc5fb912e7a4e7485185f101e96d60a2c28f284179bafa56c00e9f82bc111e268a478f66ca3d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16ED67D037D9108E9D0A6D73289B65552BB74BC4C8B3237E72E60BA782F363D19D39B50` |
| SSDEEP | `49152:DdVn6JetT4FMLY79ug1W+j4aC1h352yZ9MsPMMp124uyyK7CK9GvtTGHOKSCIOH1:DdNQY/syhWZvl8OOvd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_4d1a0237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d1a0237c82bddae9cd21a434b2e2cb65563d0af942a8b67ae70785fb5f1bf76"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 02:22:20"
  condition:
    hash.sha256(0, filesize) == "4d1a0237c82bddae9cd21a434b2e2cb65563d0af942a8b67ae70785fb5f1bf76"
}
```

### Sample 6: `7ca0ba91ec68940e`

| Field | Value |
|---|---|
| SHA-256 | `7ca0ba91ec68940ed9964d0f912901b654ddd338864fc214419cf40b0b4b29f7` |
| Family label | `unknown` |
| File name | `Ekspeditionssekretrens.vbs` |
| File type | `vbs` |
| First seen | `2026-07-15 01:52:53` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d3ed0b71f904139702f31712872d228` |
| SHA-1 | `85897e5b8f9e3a9a471217831e36b8fc7c0c8d11` |
| SHA-256 | `7ca0ba91ec68940ed9964d0f912901b654ddd338864fc214419cf40b0b4b29f7` |
| SHA3-384 | `9753273d7210d63bbec9dc5abaa9be33c25161ac5d90942338bff044c3f54767da1cef52e9f80c176e49be70a91dc916` |
| TLSH | `T160F208A0DAD217781D074FFD9C152520E0FC435A513584DCAE6E732A281E7B86E3AEF9` |
| SSDEEP | `768:LmA/nDcohtDj/Ro/YUVEKzPV6s3M1iQopbwhqJn9jit:qA/DcwJR8JVEmd2k3Yq9i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_7ca0ba91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ca0ba91ec68940ed9964d0f912901b654ddd338864fc214419cf40b0b4b29f7"
    family = "unknown"
    file_name = "Ekspeditionssekretrens.vbs"
    file_type = "vbs"
    first_seen = "2026-07-15 01:52:53"
  condition:
    hash.sha256(0, filesize) == "7ca0ba91ec68940ed9964d0f912901b654ddd338864fc214419cf40b0b4b29f7"
}
```

### Sample 7: `5be612361cea707a`

| Field | Value |
|---|---|
| SHA-256 | `5be612361cea707ae16d6516efc630c1c4d6d3b2b234c504287b43a41361d891` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-15 01:52:07` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03649e79a9282617187c49b48c595e08` |
| SHA-1 | `0bc2ace54d5d7d7341e5536c726d8ba946f61afc` |
| SHA-256 | `5be612361cea707ae16d6516efc630c1c4d6d3b2b234c504287b43a41361d891` |
| SHA3-384 | `e1d7bf8c11bfe138ec58d9467d49e654c54d556e4b723977c1e2ab29d44d58e595213c2e2f4419910856dbb5f821400a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T155E63304A7D066FDDAB3803EEEE3B891DAA874251F37C9CF076486B26D575E0053C626` |
| SSDEEP | `393216:DwPPs4ypyLdCpew0G7ZKAHV0ZNQD1XMCHWUjXhcuI3/PGTAI:DCLQIAyZNs1XMb8X2H/O7` |
| ICON-DHASH | `30f8fcdccce4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_5be61236
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5be612361cea707ae16d6516efc630c1c4d6d3b2b234c504287b43a41361d891"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 01:52:07"
  condition:
    hash.sha256(0, filesize) == "5be612361cea707ae16d6516efc630c1c4d6d3b2b234c504287b43a41361d891"
}
```

### Sample 8: `05cc3f0982581b13`

| Field | Value |
|---|---|
| SHA-256 | `05cc3f0982581b13437c6e5736adae2ba1e5aa45cf1f0509b554e2538a9105e8` |
| Family label | `Mirai` |
| File name | `tarm6` |
| File type | `elf` |
| First seen | `2026-07-15 01:28:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d13433da4fe43056634e77313f5f254b` |
| SHA-1 | `55dc5df7ab8fb6e623cae72de35706f302f71425` |
| SHA-256 | `05cc3f0982581b13437c6e5736adae2ba1e5aa45cf1f0509b554e2538a9105e8` |
| SHA3-384 | `1fa3de4135d0e7b6a0115cc282689a93205c331f1335b307bcb77eed9b1528288b19b95ccca05f759737b723fed98521` |
| TLSH | `T14CA31A8AB891A720C2C216BBFE1F018E33174BF8D2DE73529D145F64778B95B0E3A615` |
| TELFHASH | `t118e0d89fae25014956e11059c2ae901b55eeb2922f0728d696acff4e8742781f03693b` |
| SSDEEP | `3072:ADbd92tuvgvdki0pblkbOq/ypr8MJ1aoULbLjf7nLcwr:AHHuvdX0pblkbyFt1aJLbnT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_05cc3f09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05cc3f0982581b13437c6e5736adae2ba1e5aa45cf1f0509b554e2538a9105e8"
    family = "Mirai"
    file_name = "tarm6"
    file_type = "elf"
    first_seen = "2026-07-15 01:28:24"
  condition:
    hash.sha256(0, filesize) == "05cc3f0982581b13437c6e5736adae2ba1e5aa45cf1f0509b554e2538a9105e8"
}
```

### Sample 9: `922b537567f77e67`

| Field | Value |
|---|---|
| SHA-256 | `922b537567f77e67b83d4aac7eb3069a75a176991caf7c70e5f5529ca3041734` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-15 01:26:45` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `adbdcb5e87bc73f30b5c1ae1721d1a11` |
| SHA-1 | `b20f66739881eb85ae759e22839aa78831679b53` |
| SHA-256 | `922b537567f77e67b83d4aac7eb3069a75a176991caf7c70e5f5529ca3041734` |
| SHA3-384 | `36d03cb579e42badf6ba1443f698c3d847869bc9ce3984617033a01fae2ccfb256994754ab0cea644f15e221ea4a8c58` |
| TLSH | `T12601AFCE86105D4040A9C55D36D75555F820C3CF26968FB9BF6C5E2DEB85904B036FC9` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaYoXuh18yjSvF0dwX:e9Qp+Ms/6e/vKdwX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_922b5375
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "922b537567f77e67b83d4aac7eb3069a75a176991caf7c70e5f5529ca3041734"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-15 01:26:45"
  condition:
    hash.sha256(0, filesize) == "922b537567f77e67b83d4aac7eb3069a75a176991caf7c70e5f5529ca3041734"
}
```

### Sample 10: `4b7f8c067e894fe9`

| Field | Value |
|---|---|
| SHA-256 | `4b7f8c067e894fe9af8def6d3a421438f9dcee40012bd877a963d76e48f96a28` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-15 01:25:23` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b539bbef1dfd0459f2380a1f4d668c5` |
| SHA-1 | `5b3136593c471f52c16c5c2e1e3e9271080cdfd7` |
| SHA-256 | `4b7f8c067e894fe9af8def6d3a421438f9dcee40012bd877a963d76e48f96a28` |
| SHA3-384 | `8dd59a8053b5fcae65f8eaa63bef69acb47d76a1b99b51e7937652f0263a7344857702c5d1754aa1d2602e7582b46886` |
| TLSH | `T1E5C27D966A867C44BDC98A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:98vCB+25j6es8RA+J9FYpMSUpi+20qUpi+20YQX:98l25Jld2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_4b7f8c06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b7f8c067e894fe9af8def6d3a421438f9dcee40012bd877a963d76e48f96a28"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-15 01:25:23"
  condition:
    hash.sha256(0, filesize) == "4b7f8c067e894fe9af8def6d3a421438f9dcee40012bd877a963d76e48f96a28"
}
```

### Sample 11: `bac70764a37e48ba`

| Field | Value |
|---|---|
| SHA-256 | `bac70764a37e48ba063b0e80d21db47138bc5116411aa577f91e97e4ddbe6c22` |
| Family label | `Mirai` |
| File name | `tarm7` |
| File type | `elf` |
| First seen | `2026-07-15 01:11:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0967e8091962546250dab35ee8fdb7ad` |
| SHA-1 | `b4b23f0f98e5b42a71bb340f62d9a941b6ba553a` |
| SHA-256 | `bac70764a37e48ba063b0e80d21db47138bc5116411aa577f91e97e4ddbe6c22` |
| SHA3-384 | `6e5a9911ca6958ebf502e8bcefb61e93259a974c04d244ae72219aa1b6791775e806e2585e30dddc0282df7b24a524a8` |
| TLSH | `T1FBB31A89F841AB20D2D226BBFE5F018E33534BB8D3EA72129D145F6477CA95B0E37605` |
| TELFHASH | `t125e0d892ea21509817ed411301de90275bfe72953b11642592dd6bc55151c56b82ec17` |
| SSDEEP | `3072:GNquKp1vMJT9N+tvp3bOAZ5aAfJA22a/ZmCQl7mLLL5nEYwy:GAzcN+tvp3b5aUV2a/ZmCQlaL5d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_bac70764
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bac70764a37e48ba063b0e80d21db47138bc5116411aa577f91e97e4ddbe6c22"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-15 01:11:49"
  condition:
    hash.sha256(0, filesize) == "bac70764a37e48ba063b0e80d21db47138bc5116411aa577f91e97e4ddbe6c22"
}
```

### Sample 12: `108b78de37eae804`

| Field | Value |
|---|---|
| SHA-256 | `108b78de37eae804aeca049393898209699770d567a1e61a46e894613c77a31f` |
| Family label | `Mirai` |
| File name | `tarm7` |
| File type | `elf` |
| First seen | `2026-07-15 01:10:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a30a294e8d207389adf1268124046371` |
| SHA-1 | `a1257fcd3969408150d3158bed171b46eb78cb59` |
| SHA-256 | `108b78de37eae804aeca049393898209699770d567a1e61a46e894613c77a31f` |
| SHA3-384 | `2a4b30a898b0c0caa6ad7a575f51c503e22fad492e47aee71c2f6b303dae06afa3fe21bf0842d2f979b7e447ec18b4de` |
| TLSH | `T143B30A89F8816B20D2D226BBFE5F018E33534BB8D3EE72129D145F6477CA95B0E36605` |
| TELFHASH | `t101e06881ff8151d8a7e8005340dd90237beeb0ac3b101494026d6bcbe246a41b43ec1b` |
| SSDEEP | `3072:Hrc3Q20KS3F2PqEKbOAGC9XSJy1jaOpdCBJywgTkq+E/wm:Hr0s3F2PqEKUC9WgjaOpdCBJjg6y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_108b78de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "108b78de37eae804aeca049393898209699770d567a1e61a46e894613c77a31f"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-15 01:10:24"
  condition:
    hash.sha256(0, filesize) == "108b78de37eae804aeca049393898209699770d567a1e61a46e894613c77a31f"
}
```

### Sample 13: `b0b11df70f79a606`

| Field | Value |
|---|---|
| SHA-256 | `b0b11df70f79a6062064b3e26847ee7ab322a3347073dbf851b019469d4c78b2` |
| Family label | `Mirai` |
| File name | `tmips` |
| File type | `elf` |
| First seen | `2026-07-15 01:10:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eafcdc972b792ae6c7911515c6065760` |
| SHA-1 | `04e96d23fd0eb109e5f84d64e801ede500af8b48` |
| SHA-256 | `b0b11df70f79a6062064b3e26847ee7ab322a3347073dbf851b019469d4c78b2` |
| SHA3-384 | `f4a198026bdb5e47f1c73d4edcf9a18ead5abf2a2ea19ca565cf158fb7a2234f070b44abfac62ca929339aebb75944ba` |
| TLSH | `T183B3B61A3E219F7EF3ACC2384BF74E25935823D626E0D6C5E15CD9011E6438DA45FBA8` |
| TELFHASH | `t1b5115b588d3812f59b721edd6aecfe76e45170df4a215e3b8c00fdad9a2d9428e00c2c` |
| SSDEEP | `3072:XCaSO9Xqt5P05wGVmYb9jHavjIvU9uYnXKWS3wnLJ:XCaSO9XqRGVmYb9mIvU9uQ6ELJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_b0b11df7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0b11df70f79a6062064b3e26847ee7ab322a3347073dbf851b019469d4c78b2"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-07-15 01:10:23"
  condition:
    hash.sha256(0, filesize) == "b0b11df70f79a6062064b3e26847ee7ab322a3347073dbf851b019469d4c78b2"
}
```

### Sample 14: `98e8f9526424151f`

| Field | Value |
|---|---|
| SHA-256 | `98e8f9526424151fd88386ff52251ae00bd938b79887011daec54590f23b6ab0` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-15 00:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14f7471840349e30817c7bbcbc3d0a5c` |
| SHA-1 | `b39ca11fc1b08bebb1405f4ffca5fa3f11db391b` |
| SHA-256 | `98e8f9526424151fd88386ff52251ae00bd938b79887011daec54590f23b6ab0` |
| SHA3-384 | `c3884068834e64d62947859b2e4d5c65f32cda46f6d10b95fd01834e4a8c70285668f02ee1313226ff7f1ea1022d7d80` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T16EE63358B5F512F9D6B3503CEEE2A5A5A66474760BB2C5EF43984B92AE072D0CD3C303` |
| SSDEEP | `196608:KbqucGyCeg7DevT7ulLBzH1OensZFMN+P9XMCHGLLc54i1wN+MCsPIcu9KYK39sm:Kb+e7qb7uAq2XMCHWUjXTcuI3/PGTAI` |
| ICON-DHASH | `40b960c0dc797204` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_98e8f952
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98e8f9526424151fd88386ff52251ae00bd938b79887011daec54590f23b6ab0"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 00:52:08"
  condition:
    hash.sha256(0, filesize) == "98e8f9526424151fd88386ff52251ae00bd938b79887011daec54590f23b6ab0"
}
```

### Sample 15: `8d411425c9eb6077`

| Field | Value |
|---|---|
| SHA-256 | `8d411425c9eb60772d3bca4af3aca93415a1d3495bf5e2d9eb6ade8341f24451` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-15 00:44:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60b0d54f7b3279b6b2814e86eb24d7c5` |
| SHA-1 | `f07549fe184849255ddc4d4092a41f0ca1509a1d` |
| SHA-256 | `8d411425c9eb60772d3bca4af3aca93415a1d3495bf5e2d9eb6ade8341f24451` |
| SHA3-384 | `8638325624311a1d12544fb6df82965e5d9afc681e922dd49117d96a1aface41892f6b7942c9579ec9502de3c8501e38` |
| TLSH | `T146136D6526913C28AE9998371D7E1F0CBDAA83E2310491DDBFCB3CF18C59A9CD21871D` |
| SSDEEP | `768:/XRWNGxVS9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnp:5lxVcy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_8d411425
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d411425c9eb60772d3bca4af3aca93415a1d3495bf5e2d9eb6ade8341f24451"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-15 00:44:51"
  condition:
    hash.sha256(0, filesize) == "8d411425c9eb60772d3bca4af3aca93415a1d3495bf5e2d9eb6ade8341f24451"
}
```

### Sample 16: `5b92b9f938117b49`

| Field | Value |
|---|---|
| SHA-256 | `5b92b9f938117b49f280cd0d85bdaf26f83ea8a93002c61f5386e972fb49d9e4` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-15 00:32:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90ac2af53d585881fa737d1944640c6c` |
| SHA-1 | `1d039dc0fa8c64fef5110cdfd62b4889a183fcd6` |
| SHA-256 | `5b92b9f938117b49f280cd0d85bdaf26f83ea8a93002c61f5386e972fb49d9e4` |
| SHA3-384 | `252895d5799b3780fe7ef51295b5b8da5aec297470abef6f32d84acdf96a20c83330c714e16b9f5f6ece4dccf10cd281` |
| TLSH | `T1E5C28D95AA967C44BEC94A3E4CBD2B1D6DF4C3D1324942AC3D8B3C719C15FACC618B1A` |
| SSDEEP | `768:68vCB+25j6es8RMz9FYpMSUpi+20qUpi+20YQX:68l25JYd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_5b92b9f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b92b9f938117b49f280cd0d85bdaf26f83ea8a93002c61f5386e972fb49d9e4"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-15 00:32:54"
  condition:
    hash.sha256(0, filesize) == "5b92b9f938117b49f280cd0d85bdaf26f83ea8a93002c61f5386e972fb49d9e4"
}
```

### Sample 17: `2499d91e3183ea9e`

| Field | Value |
|---|---|
| SHA-256 | `2499d91e3183ea9e426ea138c4d94eddb7da4ccb49e936bf464037345f0f9c31` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-15 00:16:27` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `239320bcd300f03a6fbe0a976ae3af6c` |
| SHA-1 | `24f8d824acdb56063face1a52007e25c21aea8ac` |
| SHA-256 | `2499d91e3183ea9e426ea138c4d94eddb7da4ccb49e936bf464037345f0f9c31` |
| SHA3-384 | `ee89cadc9aa71949a641694eedbbb6d0829edb7e303c98b74d2aa300e0e85687b4649dd482e6bed9c15e5a5ec7a7c159` |
| TLSH | `T153D3024E99400165D49ED73149CFC0FB5CF1F44AAB3470252BCDA4BA4E1BBD6A601E6B` |
| TELFHASH | `t1f6b00121eb906524a6b1da0a6a533e48b46a31e5b0756164299f6101b61c64526d3004` |
| SSDEEP | `3072:62RGjp1in+cpPeNiOpUJJCiU3S5d6Z4vkJsO:6IGzdcmidTi3S5tvO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_2499d91e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2499d91e3183ea9e426ea138c4d94eddb7da4ccb49e936bf464037345f0f9c31"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-15 00:16:27"
  condition:
    hash.sha256(0, filesize) == "2499d91e3183ea9e426ea138c4d94eddb7da4ccb49e936bf464037345f0f9c31"
}
```

### Sample 18: `f910373ecf094f2e`

| Field | Value |
|---|---|
| SHA-256 | `f910373ecf094f2ebb9db0b6b0e6808c4e9cb98b0cac0841c35a40f0396cec72` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-15 00:14:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bb13184000280ddc56528de6c8646a6` |
| SHA-1 | `725b1621115588f9d9494603a8ccccfbe5a1fbe7` |
| SHA-256 | `f910373ecf094f2ebb9db0b6b0e6808c4e9cb98b0cac0841c35a40f0396cec72` |
| SHA3-384 | `2bb512e601a04cb1a7e4e40201200a509df4b17152d90c4fc8363dfc0cbc271bffe8acdd51812ec4d1eaf60e47aff92d` |
| TLSH | `T1F4018CCA46106D404059CA5966D75690F420C3CF569A4FB87F9C5E2DEB89504B036FC9` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaYoXu/8ydSvFa3M7:e9Qp+Ms/37vo3M7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_f910373e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f910373ecf094f2ebb9db0b6b0e6808c4e9cb98b0cac0841c35a40f0396cec72"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-15 00:14:50"
  condition:
    hash.sha256(0, filesize) == "f910373ecf094f2ebb9db0b6b0e6808c4e9cb98b0cac0841c35a40f0396cec72"
}
```

### Sample 19: `a6b3947c7ad28018`

| Field | Value |
|---|---|
| SHA-256 | `a6b3947c7ad280189c1ea1eb16876759c230aa67daa843b001991ba745cf6054` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 23:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `816713f696a7dd4ab40ad08c76d16591` |
| SHA-1 | `80b4aaa0b3a5f6b29e600e9e147b2564d432b405` |
| SHA-256 | `a6b3947c7ad280189c1ea1eb16876759c230aa67daa843b001991ba745cf6054` |
| SHA3-384 | `09817f5e6feaf2adf5acd2d8bc0b51832d02dbb66e31de7be6672d29cc1deaed6916cce3a9aa0f2bd28d8950b4787e63` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1A4E6330465E443D6CBB3803D99E224A5E16878760772CDC7DAA843F1AE573E08D3DB9B` |
| SSDEEP | `393216:IEZMZRh//Yf0eDeRYFkr5n0uXMCHWUjX4cuI3/PGTAI:ItZR1QhDjFA5n0uXMb8XNH/O7` |
| ICON-DHASH | `5071f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_a6b3947c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6b3947c7ad280189c1ea1eb16876759c230aa67daa843b001991ba745cf6054"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 23:52:08"
  condition:
    hash.sha256(0, filesize) == "a6b3947c7ad280189c1ea1eb16876759c230aa67daa843b001991ba745cf6054"
}
```

### Sample 20: `78f623acdbf85412`

| Field | Value |
|---|---|
| SHA-256 | `78f623acdbf8541288cfc969fe4c39ca194939bfb30e921dc2d6d9bc4012b4ff` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Mardom.IN.10.59186461` |
| File type | `exe` |
| First seen | `2026-07-14 23:43:59` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5bee4bbdab0a5b20748f266772d4189` |
| SHA-1 | `5d31db1e638af76a103e288f08f39d67728d92db` |
| SHA-256 | `78f623acdbf8541288cfc969fe4c39ca194939bfb30e921dc2d6d9bc4012b4ff` |
| SHA3-384 | `6a7ac676976d062768ea3ddfb270d619219a5e853ca9e5a3f1baa2b1e3ad5a046e2ac8e7c53e44ed07b62eb4921c265d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14305AE2A32958F21C28A5372C1D7890097A6D647B6ABEB0B31C413D61D473FEDA4B3D7` |
| SSDEEP | `12288:EVYGxhn+LlyotBhEUd2rGNWCjJgbjekdJxXthWwZribw:E6inaBJXJgff75iw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_78f623ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78f623acdbf8541288cfc969fe4c39ca194939bfb30e921dc2d6d9bc4012b4ff"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Mardom.IN.10.59186461"
    file_type = "exe"
    first_seen = "2026-07-14 23:43:59"
  condition:
    hash.sha256(0, filesize) == "78f623acdbf8541288cfc969fe4c39ca194939bfb30e921dc2d6d9bc4012b4ff"
}
```

### Sample 21: `dc6790cdf758ba93`

| Field | Value |
|---|---|
| SHA-256 | `dc6790cdf758ba93696edf19d490d1fbb59a4312d456c77a498ccf3b955e1572` |
| Family label | `PureLogsStealer` |
| File name | `SecuriteInfo.com.Heur.MSIL.Benin.5.59112575` |
| File type | `exe` |
| First seen | `2026-07-14 23:43:58` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8241127f4521046c5b38a78b7f5c94ab` |
| SHA-1 | `8cd75c44d701bf536b73f2156fadcf843e8a101d` |
| SHA-256 | `dc6790cdf758ba93696edf19d490d1fbb59a4312d456c77a498ccf3b955e1572` |
| SHA3-384 | `0a257a766f515a5bace3df3b52223cb703c03ecd0e5afcaf9f3ca861e9c5cdc88f067a35bc8813cf40ae760f310e3b2f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15B059E3A72914E12C24A13B3C1D74A0093A6D65777ABFB0F31C913DB19463EEEE06697` |
| SSDEEP | `12288:U6r5wwNCBjbP8QkZBobbF6Cmu3YTHKu9IjiPJbw18HWKXx0mz:WlpsBot6Q3Y2u9mkJfH5xZ` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_021_dc6790cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc6790cdf758ba93696edf19d490d1fbb59a4312d456c77a498ccf3b955e1572"
    family = "PureLogsStealer"
    file_name = "SecuriteInfo.com.Heur.MSIL.Benin.5.59112575"
    file_type = "exe"
    first_seen = "2026-07-14 23:43:58"
  condition:
    hash.sha256(0, filesize) == "dc6790cdf758ba93696edf19d490d1fbb59a4312d456c77a498ccf3b955e1572"
}
```

### Sample 22: `0cba96220bd33958`

| Field | Value |
|---|---|
| SHA-256 | `0cba96220bd33958a47a7f09d656594ce73c83b79801a873a3ba397ba747c925` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-14 23:35:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0db115d00cf971f4126aea2d07d8d042` |
| SHA-1 | `156e8aed3e76be1d9d9bb9475f1de648dd9f4d49` |
| SHA-256 | `0cba96220bd33958a47a7f09d656594ce73c83b79801a873a3ba397ba747c925` |
| SHA3-384 | `8f8bf103759f8a984f24a9417d3ccee946f374bbe0beca0d78fd2e59ed39e361ddbdadf6252a29694bf269cbf5b37f62` |
| TLSH | `T10D137D695A953C249E8989371D7E2F0CB9AA83E5300851DDBFCB3CF68C45ADCE21871D` |
| SSDEEP | `768:w+VEJVIhtMt9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnp:wcEJ2Mucy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_0cba9622
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cba96220bd33958a47a7f09d656594ce73c83b79801a873a3ba397ba747c925"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-14 23:35:57"
  condition:
    hash.sha256(0, filesize) == "0cba96220bd33958a47a7f09d656594ce73c83b79801a873a3ba397ba747c925"
}
```

### Sample 23: `aa251d0e0ce55abd`

| Field | Value |
|---|---|
| SHA-256 | `aa251d0e0ce55abd93ecda85cebafd82ea119f406cb63d9556fdeec1f4a27d1e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-14 23:34:30` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d6001e6b85de38a6e390f7adc47acea` |
| SHA-1 | `492bc465439a735ae106697474162364167c572b` |
| SHA-256 | `aa251d0e0ce55abd93ecda85cebafd82ea119f406cb63d9556fdeec1f4a27d1e` |
| SHA3-384 | `72b56ccdf5d45ca518757835215610d232c408c70117ea9e2b79cbf061b8f670fcb37318cf73566834b9afe6a5a1748e` |
| TLSH | `T1D5C27D956A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C12FACD618B1A` |
| SSDEEP | `768:c8vCB+25j6es8RU9FYpMSUpi+20qUpi+20YQX:c8l25Jyd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_aa251d0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa251d0e0ce55abd93ecda85cebafd82ea119f406cb63d9556fdeec1f4a27d1e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-14 23:34:30"
  condition:
    hash.sha256(0, filesize) == "aa251d0e0ce55abd93ecda85cebafd82ea119f406cb63d9556fdeec1f4a27d1e"
}
```

### Sample 24: `69a2951532eb07ac`

| Field | Value |
|---|---|
| SHA-256 | `69a2951532eb07aca5543f9e726cc9c1bb0ce7f5551c6eff336f508c7a0e7a38` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 22:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a79ab903483c62586664b52b32923e37` |
| SHA-1 | `6e46132425df7b18c2c6192a9711516f1b6d626e` |
| SHA-256 | `69a2951532eb07aca5543f9e726cc9c1bb0ce7f5551c6eff336f508c7a0e7a38` |
| SHA3-384 | `f821bb5f4d1e46f7fd6a20e8552bc6dbc6809b20d3883039fcd0168a73dd1bed0a3902a230349b5df09844b47ae9f04e` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T117E6331C79D101FEEEB3013DEEE21669E4A470A04732C99F539487A25E172E28D3B767` |
| SSDEEP | `393216:UJ+SbiLpd08zB1Sb38aVXMCHWUjX8cuI3/PGTAI:UJ+TddZzBQr8aVXMb8XpH/O7` |
| ICON-DHASH | `99dcf8f8dcf8e144` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_69a29515
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69a2951532eb07aca5543f9e726cc9c1bb0ce7f5551c6eff336f508c7a0e7a38"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 22:52:08"
  condition:
    hash.sha256(0, filesize) == "69a2951532eb07aca5543f9e726cc9c1bb0ce7f5551c6eff336f508c7a0e7a38"
}
```

### Sample 25: `a6ea67372e5b31bf`

| Field | Value |
|---|---|
| SHA-256 | `a6ea67372e5b31bfd633d9745541577e9f3edb39f0eea75cf9679b632ca04908` |
| Family label | `Mirai` |
| File name | `a6ea67372e5b31bfd633d9745541577e9f3edb39f0eea75cf9679b632ca04908` |
| File type | `elf` |
| First seen | `2026-07-14 22:41:46` |
| Reporter | `c2hunter` |
| Tags | `elf, Gafgyt, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f02d8836b9916257432ca366aa5507c7` |
| SHA-1 | `f3292e04938ea87ee4b33b6b905a1af7847e2425` |
| SHA-256 | `a6ea67372e5b31bfd633d9745541577e9f3edb39f0eea75cf9679b632ca04908` |
| SHA3-384 | `76081360ee893dcaec6ce00390432c2c9dad04828ebc4beb6c8d0992f6aadb97522a04e2c3ab76ef4e692131687cc390` |
| TLSH | `T15CB3AF87B2907ABEF0A45E3FC4135E26A6259F705583273D71FDF9906E3A3503292E42` |
| SSDEEP | `1536:tdNSXAeuUGWnKYUqwaJ1Xq/3A5hcB57laZeCNjHWBOdiyWT15Ov6fHzD8rSR:t3SrlGWnKTU83AQB5A5Liy36fPUSR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_a6ea6737
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6ea67372e5b31bfd633d9745541577e9f3edb39f0eea75cf9679b632ca04908"
    family = "Mirai"
    file_name = "a6ea67372e5b31bfd633d9745541577e9f3edb39f0eea75cf9679b632ca04908"
    file_type = "elf"
    first_seen = "2026-07-14 22:41:46"
  condition:
    hash.sha256(0, filesize) == "a6ea67372e5b31bfd633d9745541577e9f3edb39f0eea75cf9679b632ca04908"
}
```

### Sample 26: `5850b6e589ea496b`

| Field | Value |
|---|---|
| SHA-256 | `5850b6e589ea496b093b3c162dab126789ea118276bc3c23ff4cf75c6c19c8d5` |
| Family label | `Mirai` |
| File name | `5850b6e589ea496b093b3c162dab126789ea118276bc3c23ff4cf75c6c19c8d5` |
| File type | `elf` |
| First seen | `2026-07-14 22:41:43` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82b84e74215809b1ac155be27a531ef1` |
| SHA-1 | `4dcc04911ac4fb393a5f90b1fdc79f25b4201dbf` |
| SHA-256 | `5850b6e589ea496b093b3c162dab126789ea118276bc3c23ff4cf75c6c19c8d5` |
| SHA3-384 | `538369879c0fb3bae8626042697b37a85f8f511ec260ea3248587e05a8e90c24d333de9f5f8aede5ed31d4f34d20c398` |
| TLSH | `T16F146C2BB3C39CE6C51063308C316362776FD7081958EAFFDA1B3794A9977225A246C7` |
| SSDEEP | `6144:1R9Om5159ZA0mzoWcz4Mm4ztkES7IKTtF:BZAyFzQSdS7II` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_5850b6e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5850b6e589ea496b093b3c162dab126789ea118276bc3c23ff4cf75c6c19c8d5"
    family = "Mirai"
    file_name = "5850b6e589ea496b093b3c162dab126789ea118276bc3c23ff4cf75c6c19c8d5"
    file_type = "elf"
    first_seen = "2026-07-14 22:41:43"
  condition:
    hash.sha256(0, filesize) == "5850b6e589ea496b093b3c162dab126789ea118276bc3c23ff4cf75c6c19c8d5"
}
```

### Sample 27: `1b9d1966ec3bfc3d`

| Field | Value |
|---|---|
| SHA-256 | `1b9d1966ec3bfc3d78ee8bd6715f11a2a3a7d22f1b5d3eb19ae3ebd8879bdc35` |
| Family label | `WannaCry` |
| File name | `1b9d1966ec3bfc3d78ee8bd6715f11a2a3a7d22f1b5d3eb19ae3ebd8879bdc35` |
| File type | `exe` |
| First seen | `2026-07-14 22:15:11` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5667a191efb1c5f4a2797c3c8aa86350` |
| SHA-1 | `df5c60a549fb5a13ef35f7cab4888a98ab6028da` |
| SHA-256 | `1b9d1966ec3bfc3d78ee8bd6715f11a2a3a7d22f1b5d3eb19ae3ebd8879bdc35` |
| SHA3-384 | `56e3feac2ad1150d11e4a8464f6a61dde095e479e93db0562f2e09a0108c6f508549b99259920c98d7612b0a1de418d3` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1F536126972D86ABAF7B32BF121758B6457B6BD01AE1A461F1260054E0C73F48DCC3F29` |
| SSDEEP | `98304:DI8qPoBhz1aRxcSUDk36SAEdhvxWa9ocpis2xgzBJriN:DI8qPe1Cxcxk3ZAEUa+cpis2xgzBJriN` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_027_1b9d1966
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b9d1966ec3bfc3d78ee8bd6715f11a2a3a7d22f1b5d3eb19ae3ebd8879bdc35"
    family = "WannaCry"
    file_name = "1b9d1966ec3bfc3d78ee8bd6715f11a2a3a7d22f1b5d3eb19ae3ebd8879bdc35"
    file_type = "exe"
    first_seen = "2026-07-14 22:15:11"
  condition:
    hash.sha256(0, filesize) == "1b9d1966ec3bfc3d78ee8bd6715f11a2a3a7d22f1b5d3eb19ae3ebd8879bdc35"
}
```

### Sample 28: `2892f77e6c5389ba`

| Field | Value |
|---|---|
| SHA-256 | `2892f77e6c5389ba707efd4e12024e309fc4d9994a0747cb80f0cd0cea507c0b` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 21:52:06` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `265b041576785229f47cb65c8c292dc5` |
| SHA-1 | `634d94966d4ab324a8c1b54d76f04696f4e39cb5` |
| SHA-256 | `2892f77e6c5389ba707efd4e12024e309fc4d9994a0747cb80f0cd0cea507c0b` |
| SHA3-384 | `7c0cf9c842d4b960f7e24088378ce9ace1bba4839d00d39333cc849c61424de86d1c6efc62cf3f22c1f922f2be5e2dfc` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T11EE6331897D006FFD573903CEAD35665E09838A24F31CBCB4F6883A99D6B3E0553A693` |
| SSDEEP | `393216:MbgKd8zciqvD11WwCSQnXMCHWUjXVcuI3/PGTAI:MEz4isD11unXMb8XiH/O7` |
| ICON-DHASH | `70f0f0e8e8f0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_2892f77e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2892f77e6c5389ba707efd4e12024e309fc4d9994a0747cb80f0cd0cea507c0b"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 21:52:06"
  condition:
    hash.sha256(0, filesize) == "2892f77e6c5389ba707efd4e12024e309fc4d9994a0747cb80f0cd0cea507c0b"
}
```

### Sample 29: `ca631ce69ac6e03a`

| Field | Value |
|---|---|
| SHA-256 | `ca631ce69ac6e03a639fd2bacb55087bb6e1fb1a29556cda9fbc1dd022e54228` |
| Family label | `unknown` |
| File name | `ca631ce69ac6e03a639fd2bacb55087bb6e1fb1a29556cda9fbc1dd022e54228` |
| File type | `sh` |
| First seen | `2026-07-14 21:30:18` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2233235be785152e63b1f7972a3532a3` |
| SHA-1 | `e2a784c3c9bf2c80196f6b51c350c022b899ec22` |
| SHA-256 | `ca631ce69ac6e03a639fd2bacb55087bb6e1fb1a29556cda9fbc1dd022e54228` |
| SHA3-384 | `e44d8c6908cb6e745b4adefb8eab8e597eb7137cd407b0c2fe289a35fd370c44026c43ca1b81c592750c73334dbe46d4` |
| TLSH | `T19211E7DC5AA19ACE5A438649BB704188D99E82D2ED438F19E5B1056A20BC269377EB80` |
| SSDEEP | `24:HBGlUb8LAGyauHW40LO3pgRs89AI+22MtKvgCro9LGC6:styauHW40LO3pgRs89AI+2ztOkdGn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_ca631ce6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca631ce69ac6e03a639fd2bacb55087bb6e1fb1a29556cda9fbc1dd022e54228"
    family = "unknown"
    file_name = "ca631ce69ac6e03a639fd2bacb55087bb6e1fb1a29556cda9fbc1dd022e54228"
    file_type = "sh"
    first_seen = "2026-07-14 21:30:18"
  condition:
    hash.sha256(0, filesize) == "ca631ce69ac6e03a639fd2bacb55087bb6e1fb1a29556cda9fbc1dd022e54228"
}
```

### Sample 30: `0a638387a0937be2`

| Field | Value |
|---|---|
| SHA-256 | `0a638387a0937be2017e2fe3aca11ad3483c182a96d337de7b83bf927f75c148` |
| Family label | `unknown` |
| File name | `0a638387a0937be2017e2fe3aca11ad3483c182a96d337de7b83bf927f75c148` |
| File type | `sh` |
| First seen | `2026-07-14 21:30:12` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e63dd4b969b76bb499cbdfd300de19e6` |
| SHA-1 | `61a6ef7b18ba39e90bd481967acf824f277e0809` |
| SHA-256 | `0a638387a0937be2017e2fe3aca11ad3483c182a96d337de7b83bf927f75c148` |
| SHA3-384 | `e4e5b14368fd0a986b0ead42dca6b53f137b5bb758008bb2bc2b0e2cfe2b8e20cd80ddbc130381d73c4a2ff5a1ca77d6` |
| TLSH | `T16B213BD846608BED5AC38649BB7042CCD59E42C3FC43AF49E49505AB31BC2A8776FB84` |
| SSDEEP | `24:H2/lUb8L1I/aupW40LYZpgRG89Ay+22MnKvgsro90C6:W/ncaupW40LYZpgRG89Ay+2znYkSn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_0a638387
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a638387a0937be2017e2fe3aca11ad3483c182a96d337de7b83bf927f75c148"
    family = "unknown"
    file_name = "0a638387a0937be2017e2fe3aca11ad3483c182a96d337de7b83bf927f75c148"
    file_type = "sh"
    first_seen = "2026-07-14 21:30:12"
  condition:
    hash.sha256(0, filesize) == "0a638387a0937be2017e2fe3aca11ad3483c182a96d337de7b83bf927f75c148"
}
```

### Sample 31: `20226b2b49c6d721`

| Field | Value |
|---|---|
| SHA-256 | `20226b2b49c6d721bd5458710c111510a0f501616d5a2859943b4dc2d8f74736` |
| Family label | `unknown` |
| File name | `gc.key` |
| File type | `exe` |
| First seen | `2026-07-14 21:09:48` |
| Reporter | `monitorsg` |
| Tags | `ClearFake, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1197411c01a27f66455d004cb2013cf3` |
| SHA-1 | `a12add941b37c26aaeca8d2f43c17ff00a20709c` |
| SHA-256 | `20226b2b49c6d721bd5458710c111510a0f501616d5a2859943b4dc2d8f74736` |
| SHA3-384 | `ac6f59c6bf2883767344a9f2f1c9cdc06df979f604a5c6012ecf27137bcced9f6e2103f5da5fc919c983eb70d2714bca` |
| IMPHASH | `17959180aa6d2c96074ff57e33017f1c` |
| TLSH | `T127868D2BEDF445DEE49FB53C81137211BE223D0017126B173AE8B3391D367646A69B2E` |
| SSDEEP | `49152:WcbyJq/u6aikMSiJuhJIvtnceXxcHYOVGHS3enuNikeeNwhc+eVER4xHbdkYrR9f:8Wv9cqcHY/yejg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_20226b2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20226b2b49c6d721bd5458710c111510a0f501616d5a2859943b4dc2d8f74736"
    family = "unknown"
    file_name = "gc.key"
    file_type = "exe"
    first_seen = "2026-07-14 21:09:48"
  condition:
    hash.sha256(0, filesize) == "20226b2b49c6d721bd5458710c111510a0f501616d5a2859943b4dc2d8f74736"
}
```

### Sample 32: `2a19ad3ce75c78d5`

| Field | Value |
|---|---|
| SHA-256 | `2a19ad3ce75c78d58025e0f4612f3d950f45afb4d8c11d7470642e554459a453` |
| Family label | `ArkeiStealer` |
| File name | `Order-269916_71038.exe` |
| File type | `exe` |
| First seen | `2026-07-14 21:07:11` |
| Reporter | `Exodia6542` |
| Tags | `ArkeiStealer, exe, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `988676498cc49e5b9e8d4c741dd38bb2` |
| SHA-1 | `57e458baa3567d75981318582882d48065067a03` |
| SHA-256 | `2a19ad3ce75c78d58025e0f4612f3d950f45afb4d8c11d7470642e554459a453` |
| SHA3-384 | `eb37156b11321d2d008d6c46decfd9c06e5cd93d3a340a6361eed234d7c0518e01eff14dbbc67c25a8aebc30704f5db1` |
| TLSH | `T1B8B5418ED68207B5F3DAE777522AD62A5DF6314580728A31CF463D354F0BE206029EED` |
| SSDEEP | `12288:0judCuw8n1Ed4CG7qPGXMASMfcD9V0krO:0co1d13d7Sky` |

#### Technical Assessment

- The sample is tracked as `ArkeiStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ArkeiStealer_032_2a19ad3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a19ad3ce75c78d58025e0f4612f3d950f45afb4d8c11d7470642e554459a453"
    family = "ArkeiStealer"
    file_name = "Order-269916_71038.exe"
    file_type = "exe"
    first_seen = "2026-07-14 21:07:11"
  condition:
    hash.sha256(0, filesize) == "2a19ad3ce75c78d58025e0f4612f3d950f45afb4d8c11d7470642e554459a453"
}
```

### Sample 33: `e1d2d45b8f5c4fb4`

| Field | Value |
|---|---|
| SHA-256 | `e1d2d45b8f5c4fb4eb7ea1ca4833696e8fd87a706fbb8a89f614bd53d314cffa` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnaarch64xnxn` |
| File type | `elf` |
| First seen | `2026-07-14 20:53:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8294f9361c29a8913bfe938bd967773` |
| SHA-1 | `a4d986d2b87c96a541d03b2e52aea50767efda6b` |
| SHA-256 | `e1d2d45b8f5c4fb4eb7ea1ca4833696e8fd87a706fbb8a89f614bd53d314cffa` |
| SHA3-384 | `01cbae0ebe7b2e6cddb2d6173ce652a1733fd6818bc164fa117519c2eab7a1c1f3b95a83157e6b30db20f1e2851a727c` |
| TLSH | `T189148D68FE4F68D2D2C7E37DAE4A0FA2302779749565C0B51A00A29FD5EAFD488D0613` |
| SSDEEP | `3072:badBpAIWIfbEdOcdY3rZiigZ2eNRzPxp:bOVfbEdxm4iubD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_e1d2d45b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1d2d45b8f5c4fb4eb7ea1ca4833696e8fd87a706fbb8a89f614bd53d314cffa"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnaarch64xnxn"
    file_type = "elf"
    first_seen = "2026-07-14 20:53:56"
  condition:
    hash.sha256(0, filesize) == "e1d2d45b8f5c4fb4eb7ea1ca4833696e8fd87a706fbb8a89f614bd53d314cffa"
}
```

### Sample 34: `52829b64caa9ef53`

| Field | Value |
|---|---|
| SHA-256 | `52829b64caa9ef53e8f600b1e286bd06d24ab70eeb284d8289f41b73d58f28dd` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxni386xnxn` |
| File type | `elf` |
| First seen | `2026-07-14 20:53:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06c1decd0701baba3c3b11a4c98b4106` |
| SHA-1 | `4f9168d28b58ecdeeb6df90436ebcd25bcb2809d` |
| SHA-256 | `52829b64caa9ef53e8f600b1e286bd06d24ab70eeb284d8289f41b73d58f28dd` |
| SHA3-384 | `d2fee5e896b9d9fe42ce1ca8c75962a350aac6a88db237d90eda73a575291750e7a91e47a22171fa8d86b9084a655ad3` |
| TLSH | `T179C35B82E6A2D0F1E68701B00557F3E68935EA305416CEC6EFA93D71EC717829D9BB1C` |
| TELFHASH | `t1dd4107fa5ea60ce873d49c05d35e1730b909da3b687036aa40f31e7536fad9212b5c35` |
| SSDEEP | `3072:3atpsoRNjmj1VGCr75MoS9SrPwVrx5tiymw:VoRNjmj1VGFVrRiyh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_52829b64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52829b64caa9ef53e8f600b1e286bd06d24ab70eeb284d8289f41b73d58f28dd"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-07-14 20:53:53"
  condition:
    hash.sha256(0, filesize) == "52829b64caa9ef53e8f600b1e286bd06d24ab70eeb284d8289f41b73d58f28dd"
}
```

### Sample 35: `5b7b9a6449dcf0b7`

| Field | Value |
|---|---|
| SHA-256 | `5b7b9a6449dcf0b779dd72210926d4567453aa40f16b473343a3aa4372798884` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnaarch64xnxn` |
| File type | `elf` |
| First seen | `2026-07-14 20:52:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96009412ff151e92cfd2ab186eac3988` |
| SHA-1 | `6bf184a41eebcb8b344be3d25d458716dfd2a884` |
| SHA-256 | `5b7b9a6449dcf0b779dd72210926d4567453aa40f16b473343a3aa4372798884` |
| SHA3-384 | `21634f5944e94eb8dd3b0b8d40397078e2125a5a842a01c8e1a3044eea6195f6dbd592557b64dadb5fe04be5001edf88` |
| TLSH | `T1776302CF6E702B66C18CE1B1743815DACC3A9C8AE353C69D87E1AB96073853654C8B1B` |
| SSDEEP | `1536:1axZLmYKVDNSl2y08yumeJyGYVmIMGjKWhtNk:1axZLmYKX+t08jmeJhYTG6tNk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_5b7b9a64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b7b9a6449dcf0b779dd72210926d4567453aa40f16b473343a3aa4372798884"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnaarch64xnxn"
    file_type = "elf"
    first_seen = "2026-07-14 20:52:43"
  condition:
    hash.sha256(0, filesize) == "5b7b9a6449dcf0b779dd72210926d4567453aa40f16b473343a3aa4372798884"
}
```

### Sample 36: `f9a1915d056acc36`

| Field | Value |
|---|---|
| SHA-256 | `f9a1915d056acc36d5405d81c80d0065078b1e47d8003d41fcb823e9b2e27835` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxni386xnxn` |
| File type | `elf` |
| First seen | `2026-07-14 20:52:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0600d3fb991100376191f7627019e878` |
| SHA-1 | `5f0f0e107d6d3304f3d5462eb222dc48be2d6579` |
| SHA-256 | `f9a1915d056acc36d5405d81c80d0065078b1e47d8003d41fcb823e9b2e27835` |
| SHA3-384 | `b67061a05941f3f79243e4e45ec40c0703462913a80b7f82a20d021a839c23146c52906df2c319e8931a1430c2719977` |
| TLSH | `T1C65302F6A0E4BDCDC2596334021F1A073E8663B86096A53AB6C4F65907F0344DFD9BD1` |
| TELFHASH | `t1a0b01122cc8a8e020200882e0a0a022fe280feb82c0bf303a0b80c28e0b2c8e0000083` |
| SSDEEP | `1536:C1/S5aOdeB51F+yuXkoPgvFbFX6hTZ0f8ASAH1Lkg4azHg:CM5az1Fy0oPgdZX6hTo8R+1LGazHg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_f9a1915d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9a1915d056acc36d5405d81c80d0065078b1e47d8003d41fcb823e9b2e27835"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-07-14 20:52:41"
  condition:
    hash.sha256(0, filesize) == "f9a1915d056acc36d5405d81c80d0065078b1e47d8003d41fcb823e9b2e27835"
}
```

### Sample 37: `8026e59c5c481b82`

| Field | Value |
|---|---|
| SHA-256 | `8026e59c5c481b8280404ab39e850bb4f412ae43cdd9cfbc8a1dbaa69302903e` |
| Family label | `Mirai` |
| File name | `run.sh` |
| File type | `sh` |
| First seen | `2026-07-14 20:52:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28bed84beb9b71b60995f3739e6242ff` |
| SHA-1 | `c3d0200c509b7f4ac68ece241e415759ef3785da` |
| SHA-256 | `8026e59c5c481b8280404ab39e850bb4f412ae43cdd9cfbc8a1dbaa69302903e` |
| SHA3-384 | `abb0fac296e391afa220cc38d1e17710fbfd12d198f68d136ecc47f538d3a7d8edfb440628fee6ceefab860f3a3e197a` |
| TLSH | `T1C5515EDB030C5B32961989CEB7F731B4714AE18266DFD705FA44082D4FCAE4C7696E61` |
| SSDEEP | `24:7oHDnD2JMJgDgbiBFMQMuZ9fESfEnE2EhE8gui9Q9bwcbnt3iDiJUfFOL+n+hM3I:6D2JMu0biB+RuZJJcvyK4bwd+hM3I` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_8026e59c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8026e59c5c481b8280404ab39e850bb4f412ae43cdd9cfbc8a1dbaa69302903e"
    family = "Mirai"
    file_name = "run.sh"
    file_type = "sh"
    first_seen = "2026-07-14 20:52:40"
  condition:
    hash.sha256(0, filesize) == "8026e59c5c481b8280404ab39e850bb4f412ae43cdd9cfbc8a1dbaa69302903e"
}
```

### Sample 38: `b36510313521bd52`

| Field | Value |
|---|---|
| SHA-256 | `b36510313521bd52a5eca4b3c7c3a829383883537472361d936c74ef2f42f1a0` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 20:52:07` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65e8d25b6125d17596b8c53c4563cd6c` |
| SHA-1 | `18107d8159254a1668bb06ef5f0faccdafe27f62` |
| SHA-256 | `b36510313521bd52a5eca4b3c7c3a829383883537472361d936c74ef2f42f1a0` |
| SHA3-384 | `c927675644be4e3920f4533b4bedb9740a4da3995db592af86691eec66de4745a07ae7f7338e207260717340b8d5b8ee` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T17EE6331D3BE402EDEAA7913CDB919656F565B03A4731C0CF027893A67FAB1E08D3D246` |
| SSDEEP | `393216:5NknB89bvRDqeXMCHWUjXacuI3/PGTAI:5+BGjRDqeXMb8XXH/O7` |
| ICON-DHASH | `f0d89ca692c6f4f0` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_038_b3651031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b36510313521bd52a5eca4b3c7c3a829383883537472361d936c74ef2f42f1a0"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 20:52:07"
  condition:
    hash.sha256(0, filesize) == "b36510313521bd52a5eca4b3c7c3a829383883537472361d936c74ef2f42f1a0"
}
```

### Sample 39: `1be1cf9f734a326d`

| Field | Value |
|---|---|
| SHA-256 | `1be1cf9f734a326dab0e909204f981c305923ccb2ea476e8b804f3317a8dffcb` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win64.MalwareX-gen.98861688` |
| File type | `exe` |
| First seen | `2026-07-14 20:33:45` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74bb7fa4541d236106940bd78ab50382` |
| SHA-1 | `c0e75e1e4cdb802934f5fe6d24a1344c779aa8dd` |
| SHA-256 | `1be1cf9f734a326dab0e909204f981c305923ccb2ea476e8b804f3317a8dffcb` |
| SHA3-384 | `dc75268d1d3baadb9ddf88b9601c36aef95612ce2d8ec6d49ad4e2eb9ca1216a6995c376b3b7f132fce490df6743108a` |
| IMPHASH | `92576cbf961890053b0276abaa28bb78` |
| TLSH | `T169D46C19F7A410FEE16BC578C9524916FBB27C4747A0AACF13904A961F2B6E04F3E712` |
| SSDEEP | `12288:FNH+AxETh1IpJWIf9KvvGQJClDeSF6XPj:FkAqTXCJDWgI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_1be1cf9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1be1cf9f734a326dab0e909204f981c305923ccb2ea476e8b804f3317a8dffcb"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.MalwareX-gen.98861688"
    file_type = "exe"
    first_seen = "2026-07-14 20:33:45"
  condition:
    hash.sha256(0, filesize) == "1be1cf9f734a326dab0e909204f981c305923ccb2ea476e8b804f3317a8dffcb"
}
```

### Sample 40: `246dca0b1a6195c4`

| Field | Value |
|---|---|
| SHA-256 | `246dca0b1a6195c4c6fb26bcb9b31aef79f1af5f8e506007715d53c794051d08` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-14 20:31:19` |
| Reporter | `Bitsight` |
| Tags | `54e64e, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4027e98c618c01beb38ae402cc15b6b` |
| SHA-1 | `75d6e27fc673f8d776fb8d0682a5cc96e1414ef8` |
| SHA-256 | `246dca0b1a6195c4c6fb26bcb9b31aef79f1af5f8e506007715d53c794051d08` |
| SHA3-384 | `064a53c518a713790e24d06f4a01e3a136f819b4d6058b91b800aa84efae0d23650637f88a4bd1cc5fa3a4e53a3b3681` |
| IMPHASH | `de41d4e0545d977de6ca665131bb479a` |
| TLSH | `T1CAC533E5B0801BEDC351587BDA88DE396B5B74EA176270C3BF93531580642E0B378A9F` |
| SSDEEP | `49152:qtYsSZ/XS3k1qG1K4T4u+HaG76gsRSh6QwGmd5S:qtY5Z/iRG1K41+HaGWlSKGm7S` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_040_246dca0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "246dca0b1a6195c4c6fb26bcb9b31aef79f1af5f8e506007715d53c794051d08"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-14 20:31:19"
  condition:
    hash.sha256(0, filesize) == "246dca0b1a6195c4c6fb26bcb9b31aef79f1af5f8e506007715d53c794051d08"
}
```

### Sample 41: `31d6f080dee4e86a`

| Field | Value |
|---|---|
| SHA-256 | `31d6f080dee4e86aa08a9ef73c216044c9e046724310b97dbae15cd95d138b15` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-14 20:25:59` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e7448263a0543c408a5f3595ee750b9` |
| SHA-1 | `24679b128550bfbafe65dcf6097a695b8b33bd24` |
| SHA-256 | `31d6f080dee4e86aa08a9ef73c216044c9e046724310b97dbae15cd95d138b15` |
| SHA3-384 | `1f91ad111d9b6cced78afb88fec1d6fd6595c5231af64ff0e705e1fe77577eb05c05f4b8be22e6aa58e1a3a678b13f42` |
| IMPHASH | `94efea64d0bfcd91bc8ed25c735f834b` |
| TLSH | `T1A8157F29A66801FDD1B6C1B8CA564902F771748703319ACF03E09AA77F2B6F45E7EB11` |
| SSDEEP | `12288:frIDaM5mgM2v5BIY+ZltPPBRXI3q6VsZ2cH6/9D0IhVvvTN64E:FuYBVI3ZVsZ2caF4Ihpw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_31d6f080
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31d6f080dee4e86aa08a9ef73c216044c9e046724310b97dbae15cd95d138b15"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-14 20:25:59"
  condition:
    hash.sha256(0, filesize) == "31d6f080dee4e86aa08a9ef73c216044c9e046724310b97dbae15cd95d138b15"
}
```

### Sample 42: `ed107d285623a1b8`

| Field | Value |
|---|---|
| SHA-256 | `ed107d285623a1b880b4f063d5cd8a2c2a2423e594c2f1da8903ca823bd49a4e` |
| Family label | `KongTuke` |
| File name | `f` |
| File type | `ps1` |
| First seen | `2026-07-14 20:11:14` |
| Reporter | `monitorsg` |
| Tags | `KongTuke, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9bccc0467b04fe9753b111a004210f2` |
| SHA-1 | `d2e86c2a6db3bab7d23327fda1c1437e85eb9dc2` |
| SHA-256 | `ed107d285623a1b880b4f063d5cd8a2c2a2423e594c2f1da8903ca823bd49a4e` |
| SHA3-384 | `f5f14a95ae5acfa1610017f4334be856b23b7e63845267b1b52dba50b018ed58f669fd589d2a07c8fff2b8302ff77595` |
| TLSH | `T1E9D16D75339528B99ACB5E412F1394115EB30B0F692044C079AEE0F70F9F3A6E75A7D2` |
| SSDEEP | `192:9dnF9HPM7isQnVlqgHs3LEb4WaiVJqWCF:jXPki9nVI7Ekxsg` |

#### Technical Assessment

- The sample is tracked as `KongTuke` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_KongTuke_042_ed107d28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed107d285623a1b880b4f063d5cd8a2c2a2423e594c2f1da8903ca823bd49a4e"
    family = "KongTuke"
    file_name = "f"
    file_type = "ps1"
    first_seen = "2026-07-14 20:11:14"
  condition:
    hash.sha256(0, filesize) == "ed107d285623a1b880b4f063d5cd8a2c2a2423e594c2f1da8903ca823bd49a4e"
}
```

### Sample 43: `6589805ec9895c73`

| Field | Value |
|---|---|
| SHA-256 | `6589805ec9895c732a4a42ab270862fd9495a6bfcb5270e087ccb20e5dffab58` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 19:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9733360ab9f50521b202b203e938e042` |
| SHA-1 | `ea8723d17e26e977eed71cfa5148b85023060363` |
| SHA-256 | `6589805ec9895c732a4a42ab270862fd9495a6bfcb5270e087ccb20e5dffab58` |
| SHA3-384 | `074b7329950d9c855171c62fd3e450125a22a741e251bfeefe9c285e5cb7a73ee25284542ce5b7644ca78b9f3d650773` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T110E633287BE441FEE163803CECF790F2D669786A17B2C6CF4B909661AE571F04839617` |
| SSDEEP | `393216:iUkp1Bhv+hYhzUDMQmyOXMCHWUjXGcuI3/PGTAI:id1BhuYhzKpqXMb8X7H/O7` |
| ICON-DHASH | `5471f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_043_6589805e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6589805ec9895c732a4a42ab270862fd9495a6bfcb5270e087ccb20e5dffab58"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 19:52:08"
  condition:
    hash.sha256(0, filesize) == "6589805ec9895c732a4a42ab270862fd9495a6bfcb5270e087ccb20e5dffab58"
}
```

### Sample 44: `2172f09302778dbe`

| Field | Value |
|---|---|
| SHA-256 | `2172f09302778dbe9ac1970784517b318ab9d6a0891f40713ae21b2e982808c5` |
| Family label | `unknown` |
| File name | `macuifang_only_criminal_regulatory_request_HIM_AUT_ZhuhaiYuheng.docx` |
| File type | `docx` |
| First seen | `2026-07-14 19:48:34` |
| Reporter | `smica83` |
| Tags | `docx, HUN` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab8a67365535555becd7fbcac05adb5d` |
| SHA-1 | `64bbef24b52ec1dc2db886715beb24c104eb9e0f` |
| SHA-256 | `2172f09302778dbe9ac1970784517b318ab9d6a0891f40713ae21b2e982808c5` |
| SHA3-384 | `25cf633487ec486728a1f7f3385bf62e2b2bf3978a7987b58d7307630cc6fb7023fb135f9e25b292bc59614c0e613ba5` |
| TLSH | `T157C52223E1309817D7BE0230A9D34B40863658EE86FE99369AD336A0B7DEFEC315454D` |
| SSDEEP | `49152:cvSxSAlVP7+eTkzaWLzP9BftNBXwc0GeBnzRL7bHAbmnc:cv/4BtkzTLzP9Ffuc0GMnzRrASc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `docx`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_2172f093
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2172f09302778dbe9ac1970784517b318ab9d6a0891f40713ae21b2e982808c5"
    family = "unknown"
    file_name = "macuifang_only_criminal_regulatory_request_HIM_AUT_ZhuhaiYuheng.docx"
    file_type = "docx"
    first_seen = "2026-07-14 19:48:34"
  condition:
    hash.sha256(0, filesize) == "2172f09302778dbe9ac1970784517b318ab9d6a0891f40713ae21b2e982808c5"
}
```

### Sample 45: `f62519453afb691d`

| Field | Value |
|---|---|
| SHA-256 | `f62519453afb691de16b4674927332cc8b28b4325c4e19892d31813b691652d0` |
| Family label | `unknown` |
| File name | `LADING_LOGISTICS_COMPANY_CARRIER_AGREEMENT.vbs` |
| File type | `vbs` |
| First seen | `2026-07-14 19:32:43` |
| Reporter | `smica83` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b99e3ac29a8eaf4ae21aa0338b6bc209` |
| SHA-1 | `28df4f6678645ae10d203bdea9a671ff47a713da` |
| SHA-256 | `f62519453afb691de16b4674927332cc8b28b4325c4e19892d31813b691652d0` |
| SHA3-384 | `980c7e6c18e65e18d296e074a3e4e4c508a72a00329b2cda0b662914f3b1d6716e33bf76506a8e7dbc78ae12aa643412` |
| TLSH | `T128E02652001E869A0DA727E555D6484D8011A2E46E74A161BF40C8DD642D2ACA3B928E` |
| SSDEEP | `6:jw+7y0Px+yBpauBhNFvo0AgB8GFPuEs4oJXcviUhtpG9J9P9:dOp4BvNB8XE/oVcqwkP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_f6251945
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f62519453afb691de16b4674927332cc8b28b4325c4e19892d31813b691652d0"
    family = "unknown"
    file_name = "LADING_LOGISTICS_COMPANY_CARRIER_AGREEMENT.vbs"
    file_type = "vbs"
    first_seen = "2026-07-14 19:32:43"
  condition:
    hash.sha256(0, filesize) == "f62519453afb691de16b4674927332cc8b28b4325c4e19892d31813b691652d0"
}
```

### Sample 46: `c283269a23aef350`

| Field | Value |
|---|---|
| SHA-256 | `c283269a23aef3509594c76e0819fcd45771e092408dd6392dffc730939fa9c7` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-14 19:23:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e47e0ec8d199b47c1bd4bcbd9d35d4a4` |
| SHA-1 | `42aa49c51493732b5b5ade455457e9c25fefa622` |
| SHA-256 | `c283269a23aef3509594c76e0819fcd45771e092408dd6392dffc730939fa9c7` |
| SHA3-384 | `d6fb309d0d173d4fba5e33b877b8c8db56298a436b3cee05a69c7adc9484d9a23c09b09fb951918cd4691fb124f2cddc` |
| TLSH | `T175137D6566853C28AE9988371D7E1F0CBDAA83E2310491DDBFCB3CF18C59A9CD21871D` |
| SSDEEP | `768:tXRWNGxVp9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnp:Xlxocy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_c283269a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c283269a23aef3509594c76e0819fcd45771e092408dd6392dffc730939fa9c7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-14 19:23:42"
  condition:
    hash.sha256(0, filesize) == "c283269a23aef3509594c76e0819fcd45771e092408dd6392dffc730939fa9c7"
}
```

### Sample 47: `641b5af758b9636a`

| Field | Value |
|---|---|
| SHA-256 | `641b5af758b9636aaab679f428033b44961a96516b8287b8b3ea828a42e8e028` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-14 19:11:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c00be06ef63935446cc2ec5b865d6ef5` |
| SHA-1 | `eeea1e4098adebda09ba1e32ad411e546bebb103` |
| SHA-256 | `641b5af758b9636aaab679f428033b44961a96516b8287b8b3ea828a42e8e028` |
| SHA3-384 | `319eb33d8137d210bbfe574cb93333c381ed4bc5466aa5b64412e9adf5e6e3f57ee0a09ceaac7883c471a22d1a348a1d` |
| TLSH | `T18DC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1224D42AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:P8vCB+25j6es8Rm9FYpMSUpi+20qUpi+20YQX:P8l25JQd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_641b5af7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "641b5af758b9636aaab679f428033b44961a96516b8287b8b3ea828a42e8e028"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-14 19:11:40"
  condition:
    hash.sha256(0, filesize) == "641b5af758b9636aaab679f428033b44961a96516b8287b8b3ea828a42e8e028"
}
```

### Sample 48: `abc81d4d4b22d838`

| Field | Value |
|---|---|
| SHA-256 | `abc81d4d4b22d8388e829f3fedeb35cb3d3a7e50a108ba1ac779161b21a5bad3` |
| Family label | `RemusStealer` |
| File name | `gc.key` |
| File type | `exe` |
| First seen | `2026-07-14 19:08:19` |
| Reporter | `monitorsg` |
| Tags | `ClearFake, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65b3365e8f4250c573db411546d878ad` |
| SHA-1 | `58d9a67598361da6ecd4815ced630fd59d6998e3` |
| SHA-256 | `abc81d4d4b22d8388e829f3fedeb35cb3d3a7e50a108ba1ac779161b21a5bad3` |
| SHA3-384 | `7ac96e66ca56f7417927d186594c57ff9f0fc9b1cb6a15735c17959623f7f9385d352532271bb18e45d550c65875440d` |
| IMPHASH | `a3e81ef42267088b67ef184fb27eec81` |
| TLSH | `T14D665C0BFDB50ADBC0BAF13444637216BE613D0086226F675AD4F7741F337616A9AB28` |
| SSDEEP | `49152:hfKgQhEHqNuTwGtzenlakWtfmrEQSJtqK1RTVp1bD9vMJgFU+a08CVbxWEhtUO9n:SMqQ0EzlbBvGo8kLLeffs43a` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_048_abc81d4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abc81d4d4b22d8388e829f3fedeb35cb3d3a7e50a108ba1ac779161b21a5bad3"
    family = "RemusStealer"
    file_name = "gc.key"
    file_type = "exe"
    first_seen = "2026-07-14 19:08:19"
  condition:
    hash.sha256(0, filesize) == "abc81d4d4b22d8388e829f3fedeb35cb3d3a7e50a108ba1ac779161b21a5bad3"
}
```

### Sample 49: `b96e72fc8af7ac85`

| Field | Value |
|---|---|
| SHA-256 | `b96e72fc8af7ac854ea39bf288b45e0675dc588b1925b151548d1843c80ad000` |
| Family label | `ArkeiStealer` |
| File name | `order_37335536.exe` |
| File type | `exe` |
| First seen | `2026-07-14 18:59:20` |
| Reporter | `Exodia6542` |
| Tags | `ArkeiStealer, exe, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `188ca35330b8df8e91d287e51e8da85f` |
| SHA-1 | `1b6600825d9d3779f6f21b7a2ac5916700caf7d2` |
| SHA-256 | `b96e72fc8af7ac854ea39bf288b45e0675dc588b1925b151548d1843c80ad000` |
| SHA3-384 | `a23a74137543865fe7769c9deafb267b7c1a639cd61449300b4c6af171b3833ef806ed3c02252ee31fd5b16ac7c77a80` |
| IMPHASH | `67139503bd6a6e2010992d4f6e08368f` |
| TLSH | `T16EB5418ED68207B5F3DAE7775229D62A5DF6314580728A31CF463D354F0BE20A029EED` |
| SSDEEP | `12288:njudCuw8n1Ed4CG7qPGXMASMfcD9V0krZYo:nco1d13d7SklYo` |
| ICON-DHASH | `372f172717170723` |

#### Technical Assessment

- The sample is tracked as `ArkeiStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ArkeiStealer_049_b96e72fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b96e72fc8af7ac854ea39bf288b45e0675dc588b1925b151548d1843c80ad000"
    family = "ArkeiStealer"
    file_name = "order_37335536.exe"
    file_type = "exe"
    first_seen = "2026-07-14 18:59:20"
  condition:
    hash.sha256(0, filesize) == "b96e72fc8af7ac854ea39bf288b45e0675dc588b1925b151548d1843c80ad000"
}
```

### Sample 50: `593c2d77f1bf98f5`

| Field | Value |
|---|---|
| SHA-256 | `593c2d77f1bf98f5beff03fc094b950e4e4d1c8a306397a7db1f18bda9b5c695` |
| Family label | `MacSync` |
| File name | `macsync.applescript` |
| File type | `applescript` |
| First seen | `2026-07-14 18:56:09` |
| Reporter | `petergs` |
| Tags | `AmosStealer, applescript, MacSync, MacSyncStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f10ac306b4c2c12e69c7c778cca6592e` |
| SHA-1 | `057802730116d65724c1c40522a63224fcde0693` |
| SHA-256 | `593c2d77f1bf98f5beff03fc094b950e4e4d1c8a306397a7db1f18bda9b5c695` |
| SHA3-384 | `56aaf42872eb64b608d5212e76d3ff745e0df77cb2fced398f85e9199eeb24d4c0a39665ddb1cd4564513dafd22f845a` |
| TLSH | `T15D139307695502AE93F4C976A15182B5830FC34F4293E429B2ECC37E2F1ABD5A1F26F1` |
| SSDEEP | `384:ZrXlXhRcpxrSFy7o9DITnw/uzlF60sLHMNo+uMiPSrXVO:Blq+Fy7o9DFdKXVO` |

#### Technical Assessment

- The sample is tracked as `MacSync` by MalwareBazaar metadata.
- The observed artifact type is `applescript`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MacSync_050_593c2d77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "593c2d77f1bf98f5beff03fc094b950e4e4d1c8a306397a7db1f18bda9b5c695"
    family = "MacSync"
    file_name = "macsync.applescript"
    file_type = "applescript"
    first_seen = "2026-07-14 18:56:09"
  condition:
    hash.sha256(0, filesize) == "593c2d77f1bf98f5beff03fc094b950e4e4d1c8a306397a7db1f18bda9b5c695"
}
```

### Sample 51: `b7a973918dc83e4f`

| Field | Value |
|---|---|
| SHA-256 | `b7a973918dc83e4fda18643592e3c660b0bc64add0ce9d7ffd6e7e04ccba0967` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-14 18:53:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed7c6573aed306cbf4c3fddc77e5c400` |
| SHA-1 | `265e00bf1681402c0f6fa2a07fb02d7b6d3c9527` |
| SHA-256 | `b7a973918dc83e4fda18643592e3c660b0bc64add0ce9d7ffd6e7e04ccba0967` |
| SHA3-384 | `3d038fe316b2d4e8635c299a84cba84da274e0b72e635d73f7061d99886f0ec2e94b465f8c3f19b2f21ca13b102e7e11` |
| TLSH | `T166E3E60E6E358F6DF379C336C7F74A259B98738216D1C649D26CF9122E2024D241FBA9` |
| TELFHASH | `t1b121c15c497823e067711c9d2aeeef73e19130df1b362d338e11e9a9a6bc9824e00c1c` |
| SSDEEP | `3072:xbo+kGIP6HvsRwsGk4d4ySi8PoqDdRNAVRwdNP+ZBmu8BOjUF0Qv1C8iucFa1NJu:xbo+kGIP69oHdpAX5g8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_b7a97391
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7a973918dc83e4fda18643592e3c660b0bc64add0ce9d7ffd6e7e04ccba0967"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-14 18:53:37"
  condition:
    hash.sha256(0, filesize) == "b7a973918dc83e4fda18643592e3c660b0bc64add0ce9d7ffd6e7e04ccba0967"
}
```

### Sample 52: `dcb9772a15cc16d9`

| Field | Value |
|---|---|
| SHA-256 | `dcb9772a15cc16d9bed50c4be2724b30629f6c2437239a99327445840dda4185` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 18:52:06` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8095389bbb2b28ed85516e43ad2c9636` |
| SHA-1 | `5228a14d784ee65cfbf0753adaf7729bf906cfbf` |
| SHA-256 | `dcb9772a15cc16d9bed50c4be2724b30629f6c2437239a99327445840dda4185` |
| SHA3-384 | `f30d494677efad590fe232fe88fd7302b112d8be4f3ff25045e050698f7ada39f9810bb1ccfa1015d43fe2a9d19b390f` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1EAE6334DAAE021FEC6774239FEC21315F86478750B76CBCB4AB4A3596E131C9493DA23` |
| SSDEEP | `393216:agyswpdnQE1SghMi4783wXMCHWUjXHcuI3/PGTAI:ag6aC2B7+wXMb8X8H/O7` |
| ICON-DHASH | `99dcf8f8dcf8e144` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_052_dcb9772a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcb9772a15cc16d9bed50c4be2724b30629f6c2437239a99327445840dda4185"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 18:52:06"
  condition:
    hash.sha256(0, filesize) == "dcb9772a15cc16d9bed50c4be2724b30629f6c2437239a99327445840dda4185"
}
```

### Sample 53: `8dcbddb7a3b55ed6`

| Field | Value |
|---|---|
| SHA-256 | `8dcbddb7a3b55ed63e56eb6d166879071683b6bbc6eeb03740dad94fed880ed0` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-14 18:49:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccde69e5939f79a9e003f62a147cb53d` |
| SHA-1 | `977faadac7f50ba12d328d3d5ba25695bba9fc15` |
| SHA-256 | `8dcbddb7a3b55ed63e56eb6d166879071683b6bbc6eeb03740dad94fed880ed0` |
| SHA3-384 | `fc788049eec996722c77f4eea0d73b23cb13c2f35883707e4a8f6623ae826f278c55c84b2a28bde4c22a38b59eede853` |
| TLSH | `T19BA34A89EA13D4F1F8526D700C37A3368BB6D4365136FA81FB513B716C2B712A907A9C` |
| TELFHASH | `t1a2410af66e660ce8bb80a806e34e5b72bd0d57bb157066f604f3287136d76418277c39` |
| SSDEEP | `1536:+j8xhqZx3kF5r6gCnQfxPZUKRdMDRRBBQaE1h6n7vOk8w27qNt2eIuRrnk9l9yJ:88aNW2gCn2BZBR6QN+7vn2m72+kA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_8dcbddb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8dcbddb7a3b55ed63e56eb6d166879071683b6bbc6eeb03740dad94fed880ed0"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-14 18:49:46"
  condition:
    hash.sha256(0, filesize) == "8dcbddb7a3b55ed63e56eb6d166879071683b6bbc6eeb03740dad94fed880ed0"
}
```

### Sample 54: `a56d15cde8dae382`

| Field | Value |
|---|---|
| SHA-256 | `a56d15cde8dae3826dada7044ba5e8bac63cc473fe1de9efc0faee7099967114` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-14 18:47:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df47360d432c296430b91f529a2ee196` |
| SHA-1 | `85bef37dc93f36689036a8517a3e849be94f0f39` |
| SHA-256 | `a56d15cde8dae3826dada7044ba5e8bac63cc473fe1de9efc0faee7099967114` |
| SHA3-384 | `d53ee95946bc1a9df90b455b3bda172fe84c3ae60f5656ee16f6838b3d3d782c16feb71de1446d2cac99982f349eaf54` |
| TLSH | `T1B7930845FD829F01D9C916BBFE1E018D335367A8E3EE71129D206F2177CA61B0A7B451` |
| TELFHASH | `t153d02ea0a2c882c47bc1470a8686133b8e8079a07a081044ebe0bf9b8426e8030b2833` |
| SSDEEP | `1536:WFnfLrTz4qSMMVeENtvjAtQnHF2JoTaDTRakMFASkpdX9l0WiGM3nTH6Y7BlTHwq:mLrf4qSMMVeiUtQ4J1DtakMFASkYuM3T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_a56d15cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a56d15cde8dae3826dada7044ba5e8bac63cc473fe1de9efc0faee7099967114"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-14 18:47:38"
  condition:
    hash.sha256(0, filesize) == "a56d15cde8dae3826dada7044ba5e8bac63cc473fe1de9efc0faee7099967114"
}
```

### Sample 55: `cb60c05a179fc2f1`

| Field | Value |
|---|---|
| SHA-256 | `cb60c05a179fc2f196486101d1c49be82cb4f6f1771212b02f21b97cfaa0331c` |
| Family label | `unknown` |
| File name | `cb60c05a179fc2f196486101d1c49be82cb4f6f1771212b02f21b97cfaa0331c` |
| File type | `xlsx` |
| First seen | `2026-07-14 18:44:02` |
| Reporter | `anonymous` |
| Tags | `xlsx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `758afea95b818063536b6fd7a5a15a92` |
| SHA-1 | `227e61eca20d832241a1e152920c42bf049f2e69` |
| SHA-256 | `cb60c05a179fc2f196486101d1c49be82cb4f6f1771212b02f21b97cfaa0331c` |
| SHA3-384 | `77cefba3b9f7a5acac16ec849f579c10289a09ee260d17e3dfc7a099ee8d214b6c5fc180d49337b448e72d0325563809` |
| TLSH | `T108F46C11FD56C838CA62653ADCC106F23A707C024E0AED8B3518733E7FB79775A6A616` |
| SSDEEP | `12288:K17aw2vxK1HBY3EfIfRLWOK6U0x9CFbrD2iKmYhKmiOg:/TAhgCIU0uFfD2iKo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xlsx`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_cb60c05a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb60c05a179fc2f196486101d1c49be82cb4f6f1771212b02f21b97cfaa0331c"
    family = "unknown"
    file_name = "cb60c05a179fc2f196486101d1c49be82cb4f6f1771212b02f21b97cfaa0331c"
    file_type = "xlsx"
    first_seen = "2026-07-14 18:44:02"
  condition:
    hash.sha256(0, filesize) == "cb60c05a179fc2f196486101d1c49be82cb4f6f1771212b02f21b97cfaa0331c"
}
```

### Sample 56: `81ef05cc4d07cd22`

| Field | Value |
|---|---|
| SHA-256 | `81ef05cc4d07cd22cd7cd7099f278dd9b9a3ae8ad4770b3d387892e1c6cfb7d7` |
| Family label | `unknown` |
| File name | `81ef05cc4d07cd22cd7cd7099f278dd9b9a3ae8ad4770b3d387892e1c6cfb7d7` |
| File type | `macho` |
| First seen | `2026-07-14 18:35:22` |
| Reporter | `anonymous` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `588ebbe16593cdd13a0b9f4e77a9b513` |
| SHA-1 | `d230794982325afae687aef0a5245e50c7530539` |
| SHA-256 | `81ef05cc4d07cd22cd7cd7099f278dd9b9a3ae8ad4770b3d387892e1c6cfb7d7` |
| SHA3-384 | `f7a89a8460a0a3812420a301651ea6c2b4a3fb7027e31947cb48972ea0a8a24232e07bdd7ddcd7f74eea83bc65df7c8e` |
| TLSH | `T161E54C99890E0814C2F191BCECA30B7B05529554876CB68CBEA1D86DDFBB7F310A76F1` |
| SSDEEP | `49152:2Y1dit9qTRlEltsd3srvRg5rMqQlyt0NtYc35iCORVTJ:nTEI8ltsdcFg5rMqQlyaN6c35iCORVT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_81ef05cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81ef05cc4d07cd22cd7cd7099f278dd9b9a3ae8ad4770b3d387892e1c6cfb7d7"
    family = "unknown"
    file_name = "81ef05cc4d07cd22cd7cd7099f278dd9b9a3ae8ad4770b3d387892e1c6cfb7d7"
    file_type = "macho"
    first_seen = "2026-07-14 18:35:22"
  condition:
    hash.sha256(0, filesize) == "81ef05cc4d07cd22cd7cd7099f278dd9b9a3ae8ad4770b3d387892e1c6cfb7d7"
}
```

### Sample 57: `eefd5fe077a3033d`

| Field | Value |
|---|---|
| SHA-256 | `eefd5fe077a3033d4c16c887c6894a92fdcffbb050aa97da5196702a424e2835` |
| Family label | `Mirai` |
| File name | `bot_x86_64` |
| File type | `elf` |
| First seen | `2026-07-14 18:12:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `673f2295a76361b85432f5e1dc7bc8b7` |
| SHA-1 | `6ad0cdb02aedb95d7630f85954c6a76d524c0226` |
| SHA-256 | `eefd5fe077a3033d4c16c887c6894a92fdcffbb050aa97da5196702a424e2835` |
| SHA3-384 | `eb9c8cc7bc29a69fe677736f8857018a675971008e0f3c3822853cfec8d8b9389b9a865ecf28a937e72043e918e04223` |
| TLSH | `T1CC457C57B2F364FDC053C430879BD6A2A931B42542226E7F66C4CB302FA6E641B5DB63` |
| TELFHASH | `t1ac2141e7543da4a04adeac80e59b2724e10ff19458b10a23fca0c65c72fe61f49674eb` |
| SSDEEP | `24576:+wrjO4kbULQIQzVLaJjM7ayOdk3A2rKk2ub9qvF/eA:+w/O4kbUu57KAA2OE9qoA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_eefd5fe0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eefd5fe077a3033d4c16c887c6894a92fdcffbb050aa97da5196702a424e2835"
    family = "Mirai"
    file_name = "bot_x86_64"
    file_type = "elf"
    first_seen = "2026-07-14 18:12:44"
  condition:
    hash.sha256(0, filesize) == "eefd5fe077a3033d4c16c887c6894a92fdcffbb050aa97da5196702a424e2835"
}
```

### Sample 58: `0a5118fea6cffe6f`

| Field | Value |
|---|---|
| SHA-256 | `0a5118fea6cffe6fd7d694ca014fd728763922ecd675c949e5c9218dc1540386` |
| Family label | `unknown` |
| File name | `PURCHASE RDER_NOPWQ2026.JS` |
| File type | `js` |
| First seen | `2026-07-14 18:05:51` |
| Reporter | `James_inthe_box` |
| Tags | `exe, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea291379e3ebab0fafa234bb0a05374e` |
| SHA-1 | `a9f2a96fe2c7ac4f4f20b411bcfe78f7d77cb4fe` |
| SHA-256 | `0a5118fea6cffe6fd7d694ca014fd728763922ecd675c949e5c9218dc1540386` |
| SHA3-384 | `72ce85029ffe7350f173b34be49dcc3ec07eb463b4b549204aeb61dc9d197d779f3c4559a5335bad2b1dd05a0a44e6c5` |
| TLSH | `T18FE53B40831894B1A96EDB2DE437AE784A4DF00321CDDF1D38BD0664BB56E47A74DAE3` |
| SSDEEP | `98304:RD6M5YE1vgJN3t7uavTqu6DyGtkUq3kJ1dIIwpn/GDRUs4Ky:R2G1oJHHL2vt6qjIzF/GDR3c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_0a5118fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a5118fea6cffe6fd7d694ca014fd728763922ecd675c949e5c9218dc1540386"
    family = "unknown"
    file_name = "PURCHASE RDER_NOPWQ2026.JS"
    file_type = "js"
    first_seen = "2026-07-14 18:05:51"
  condition:
    hash.sha256(0, filesize) == "0a5118fea6cffe6fd7d694ca014fd728763922ecd675c949e5c9218dc1540386"
}
```

### Sample 59: `1bd9e446a11bf2dc`

| Field | Value |
|---|---|
| SHA-256 | `1bd9e446a11bf2dca961562ed807476067ea4ade0fa068c97b58173e651060f3` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-14 17:58:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ea2b67370560692e43d23a3e9dce1eb` |
| SHA-1 | `9ba9b4c24f1913a8644969a271f62b828e79f4c7` |
| SHA-256 | `1bd9e446a11bf2dca961562ed807476067ea4ade0fa068c97b58173e651060f3` |
| SHA3-384 | `375c0333b0c0e6761e3a7ba893a4959d20ca90ecc8479c64819ee4d75bbea554b7d7fb54580b56c22edf2fc665c8e126` |
| TLSH | `T165D3068AF8819F21D4D612BEFA4F518D332367E8E3EE7112DD245B2477CA51B0A7B211` |
| TELFHASH | `t135d0a72ff66149d42785401140dfb2019b9d54aa2741701538903f03cd43e83b436883` |
| SSDEEP | `3072:8mH2rHQ6qvC2Hup47aL4u0fpgREkjujkaDKaMnersXuGobKy44NVnbWt:8mH2DveVHN7aMuggpCIaDKaMneYXGKB1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_1bd9e446
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bd9e446a11bf2dca961562ed807476067ea4ade0fa068c97b58173e651060f3"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-14 17:58:47"
  condition:
    hash.sha256(0, filesize) == "1bd9e446a11bf2dca961562ed807476067ea4ade0fa068c97b58173e651060f3"
}
```

### Sample 60: `31fa1cdc0530f810`

| Field | Value |
|---|---|
| SHA-256 | `31fa1cdc0530f8105b7f69e2b408fc5971dcdff3815ee6ab7bfbb7f756e0002e` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-14 17:58:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06c82847168f3fe581fb77ab835d0915` |
| SHA-1 | `7de1b26c0e21944d7c05f5707ca8b6e31966fdc4` |
| SHA-256 | `31fa1cdc0530f8105b7f69e2b408fc5971dcdff3815ee6ab7bfbb7f756e0002e` |
| SHA3-384 | `3a2e37a02cd088930f0e1dafb2a906b979286a07305eb67d069983cec606d2e20a359f734ed6670570644fe31a899857` |
| TLSH | `T150F3E816EF602EF7D8EBCC3791B98B0A34DC555A22A42BB57534E424B64B44F46D3CB0` |
| SSDEEP | `3072:vaQNOV4EO8b/V7LRazX+wSjWAZYG1UeiTFbBnbfx:iv4Eb/V7a+wSjPYG1UZfx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_31fa1cdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31fa1cdc0530f8105b7f69e2b408fc5971dcdff3815ee6ab7bfbb7f756e0002e"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-14 17:58:45"
  condition:
    hash.sha256(0, filesize) == "31fa1cdc0530f8105b7f69e2b408fc5971dcdff3815ee6ab7bfbb7f756e0002e"
}
```

### Sample 61: `5df3574a5aacfd5e`

| Field | Value |
|---|---|
| SHA-256 | `5df3574a5aacfd5eb8cabbef5a9153d7dffc854289639acffd1ed0f21bbf887a` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-14 17:58:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8dd5cc2b63c8a3cd42ba2826a0602851` |
| SHA-1 | `4bcb76e8aeedb972f7b4784bf13a4e1aebf948e9` |
| SHA-256 | `5df3574a5aacfd5eb8cabbef5a9153d7dffc854289639acffd1ed0f21bbf887a` |
| SHA3-384 | `5cda89a4536879682ebb13642c1bb77e7014edc9699d0d251521ea5e6d8096387d36f1d1d7ad4342abf86ddb2f8a0deb` |
| TLSH | `T14AC32889B8929A62C6D716BFFA4F42CD773663E4E3DF7107DD185B21328641B0E6B201` |
| TELFHASH | `t19ad097b3bf3a09e0afc10080404db31222d870728b2220823aff1e0f1403f82b80dc42` |
| SSDEEP | `3072:0U7FYPZ7NIe0QdciU5I1aK5y4S6FlYBnb2:V5Ys4dcioIlU4SqE2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_5df3574a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5df3574a5aacfd5eb8cabbef5a9153d7dffc854289639acffd1ed0f21bbf887a"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-14 17:58:44"
  condition:
    hash.sha256(0, filesize) == "5df3574a5aacfd5eb8cabbef5a9153d7dffc854289639acffd1ed0f21bbf887a"
}
```

### Sample 62: `a3861ca7da0494b1`

| Field | Value |
|---|---|
| SHA-256 | `a3861ca7da0494b1ffa4dfb0d940d1c27a34a38481f861a55ec1cd4cd97ef9b2` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-14 17:58:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `468d27c8ee230cd63d8c89763d8f3e47` |
| SHA-1 | `2d3243de54ec17d0c6677a7fc89d99b9a8045fd6` |
| SHA-256 | `a3861ca7da0494b1ffa4dfb0d940d1c27a34a38481f861a55ec1cd4cd97ef9b2` |
| SHA3-384 | `f6823fdcf084dfee75aa42b769438494a9396b9fc68e9d877a4df5e72e485015e8129dd9b467d4d7aa47fc313d66651d` |
| TLSH | `T144C28D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:lu8vCB+25j6es8Raj9FYpMSUpi+20qUpi+20YQX:08l25Jcd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_a3861ca7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3861ca7da0494b1ffa4dfb0d940d1c27a34a38481f861a55ec1cd4cd97ef9b2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-14 17:58:43"
  condition:
    hash.sha256(0, filesize) == "a3861ca7da0494b1ffa4dfb0d940d1c27a34a38481f861a55ec1cd4cd97ef9b2"
}
```

### Sample 63: `55aac3a0ab90b917`

| Field | Value |
|---|---|
| SHA-256 | `55aac3a0ab90b91703fa5b60f8b60f25c94993c8d1ab380298ebf6e1db2dff44` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 17:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bd2afd623eec679db9a9f9a1aed7fa5` |
| SHA-1 | `4ef4f1dbc809dfa6029b9c4919e6b49c5be263a8` |
| SHA-256 | `55aac3a0ab90b91703fa5b60f8b60f25c94993c8d1ab380298ebf6e1db2dff44` |
| SHA3-384 | `b8223f12417fc47c760711abae870c3c71ac370fb49f68ff743dba721c1b46d893ab272bfceb5c2e002dd248b2c167a2` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D3E633885AD012EEE8B38238EEC15596F525F4B637B2C6DF0B6453A16C531D04E3EB1B` |
| SSDEEP | `393216:vcj+UDM4arXuncJUW63HeXMCHWUjXScuI3/PGTAI:v+jDM4arXu6XMb8XvH/O7` |
| ICON-DHASH | `78fcf8f8fcf8e048` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_063_55aac3a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55aac3a0ab90b91703fa5b60f8b60f25c94993c8d1ab380298ebf6e1db2dff44"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 17:52:08"
  condition:
    hash.sha256(0, filesize) == "55aac3a0ab90b91703fa5b60f8b60f25c94993c8d1ab380298ebf6e1db2dff44"
}
```

### Sample 64: `12d5387555e9e985`

| Field | Value |
|---|---|
| SHA-256 | `12d5387555e9e98571857a89b40cc370dbba56094c317ee6cf4f2e450153a4b5` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-14 17:42:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90533ccffae94164e20a832a6fed4328` |
| SHA-1 | `16e4b8e6217d877dc8e228ec594c4dd1bd198e97` |
| SHA-256 | `12d5387555e9e98571857a89b40cc370dbba56094c317ee6cf4f2e450153a4b5` |
| SHA3-384 | `cae3fa0ce87853097a244aedda0412334b3d4b1edcf40d50a3452077419cf18f4d132be1240a1c35fb42b5d9c14c5738` |
| TLSH | `T11BD38F5C9D1E7DC2C2C2F2FEAD450F66312675744A64C3F6290062CEEB9EED698B1432` |
| SSDEEP | `3072:DRqDBIEXmV0nStB/NPdzUT2oBXdBYjz8bDCKhR2JP:DsqC457dzUTnB3Ycb2K2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_12d53875
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12d5387555e9e98571857a89b40cc370dbba56094c317ee6cf4f2e450153a4b5"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-14 17:42:45"
  condition:
    hash.sha256(0, filesize) == "12d5387555e9e98571857a89b40cc370dbba56094c317ee6cf4f2e450153a4b5"
}
```

### Sample 65: `dd131beed1da6cce`

| Field | Value |
|---|---|
| SHA-256 | `dd131beed1da6ccee24174b28153ff11d65f69be9c7dd92eb2efe683b017ff3e` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-14 17:40:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f0d9b5c234423981bf8a825af8e6738` |
| SHA-1 | `c00852244687d1b9d6f1882026966994251edcd5` |
| SHA-256 | `dd131beed1da6ccee24174b28153ff11d65f69be9c7dd92eb2efe683b017ff3e` |
| SHA3-384 | `5adc2b265b129255b26e6e76a26a6a8cbc05cd6e12ecad7f2e2f8f858262a9920c9a413d7e23a7492d5b9e79101b2b59` |
| TLSH | `T1C3136C652A953C25AE9988371C7E2F0CBDA983E1310851DDBFCA3CF18C49A9CE71971D` |
| SSDEEP | `768:Hcsr0a1ldy9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnp:3hXcy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_dd131bee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd131beed1da6ccee24174b28153ff11d65f69be9c7dd92eb2efe683b017ff3e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-14 17:40:42"
  condition:
    hash.sha256(0, filesize) == "dd131beed1da6ccee24174b28153ff11d65f69be9c7dd92eb2efe683b017ff3e"
}
```

### Sample 66: `e9c85fed4f8cd175`

| Field | Value |
|---|---|
| SHA-256 | `e9c85fed4f8cd17535a62b2cd2832c3ca0e652df1c4914e96fb00f0eb1af710b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-14 17:36:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a7f4e8113bea2b3f3523226ff33663e` |
| SHA-1 | `35b5b0cbcabbe7d08472ad4363a1ab2bdb630e4c` |
| SHA-256 | `e9c85fed4f8cd17535a62b2cd2832c3ca0e652df1c4914e96fb00f0eb1af710b` |
| SHA3-384 | `ea663e45f053599e4cf8545c04bff2a2879cbf89d37c8d3d3b6577083bb746d3916c9f5dbc11c1f2c44e09a89961da81` |
| TLSH | `T18E137D6926953C25AE9988371C7E2F0CBDA983E1310851DDBFCA3CF18C49A9CE71971D` |
| SSDEEP | `768:bcsr0a1ldo9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnp:zh1cy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_e9c85fed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9c85fed4f8cd17535a62b2cd2832c3ca0e652df1c4914e96fb00f0eb1af710b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-14 17:36:46"
  condition:
    hash.sha256(0, filesize) == "e9c85fed4f8cd17535a62b2cd2832c3ca0e652df1c4914e96fb00f0eb1af710b"
}
```

### Sample 67: `8db515e787086c63`

| Field | Value |
|---|---|
| SHA-256 | `8db515e787086c6338598c862601d6643c898af8407452679009ab51960eb299` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.FileRepMalware.63522757` |
| File type | `exe` |
| First seen | `2026-07-14 17:30:55` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa2e1369013a7ce09b2a435fe66a1c33` |
| SHA-1 | `d54b0ff7aeba501554ab1c2cead2838632e8b452` |
| SHA-256 | `8db515e787086c6338598c862601d6643c898af8407452679009ab51960eb299` |
| SHA3-384 | `fa9d49055910b9e82933b9aadd0bcbc96c612ae0f4f061c0fbeab6372ed154813a9d73b6daffc028915bf9e4aaab1593` |
| IMPHASH | `92576cbf961890053b0276abaa28bb78` |
| TLSH | `T129D46C19F7A410FEE16BC578C9524916FBB27C4747A0AACF13904A961F2B6E04F3E712` |
| SSDEEP | `12288:8NH+AxETh1IpJWIf9KvvGQJClDeSF6X+j:8kAqTXCJDWgx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_8db515e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8db515e787086c6338598c862601d6643c898af8407452679009ab51960eb299"
    family = "unknown"
    file_name = "SecuriteInfo.com.FileRepMalware.63522757"
    file_type = "exe"
    first_seen = "2026-07-14 17:30:55"
  condition:
    hash.sha256(0, filesize) == "8db515e787086c6338598c862601d6643c898af8407452679009ab51960eb299"
}
```

### Sample 68: `3846e513d6a32765`

| Field | Value |
|---|---|
| SHA-256 | `3846e513d6a32765431ef270ccf8ad44f7627d278a2dd1e70855b21aaa6b632a` |
| Family label | `WannaCry` |
| File name | `3846e513d6a32765431ef270ccf8ad44f7627d278a2dd1e70855b21aaa6b632a` |
| File type | `exe` |
| First seen | `2026-07-14 17:15:19` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0976a8537c8b28b66c65416ec72c5ffc` |
| SHA-1 | `985bc107b5dd3026a46f88b33f8c084001a7c5f0` |
| SHA-256 | `3846e513d6a32765431ef270ccf8ad44f7627d278a2dd1e70855b21aaa6b632a` |
| SHA3-384 | `5762b5fe394458d0346f07ff85469843d4ebee469068b7d35f3a3e9b3758f1a0d5fa4b9f4bc244eefc4cb9b394d9ff6c` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1B9362359366C81FDD11B927490F38E21E6B37C862279870F4BD08B671E63790BE78B16` |
| SSDEEP | `24576:jbLgvbLgddQhfdmMSirYbcMNgef0EgXe4i7ojhsP5Lgrk1TWb4AN5:jnmnAQqMSPbcBVre30jaNf1TWbdz` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_068_3846e513
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3846e513d6a32765431ef270ccf8ad44f7627d278a2dd1e70855b21aaa6b632a"
    family = "WannaCry"
    file_name = "3846e513d6a32765431ef270ccf8ad44f7627d278a2dd1e70855b21aaa6b632a"
    file_type = "exe"
    first_seen = "2026-07-14 17:15:19"
  condition:
    hash.sha256(0, filesize) == "3846e513d6a32765431ef270ccf8ad44f7627d278a2dd1e70855b21aaa6b632a"
}
```

### Sample 69: `7d2b009f6ec2a028`

| Field | Value |
|---|---|
| SHA-256 | `7d2b009f6ec2a02836b984cadf294569a5d7095d9ee496118d408da37f0a269c` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 16:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0302228512abfe6bbc426e762c90e25` |
| SHA-1 | `6472914eeda58894b0033eeeaeca797a23fa1c4a` |
| SHA-256 | `7d2b009f6ec2a02836b984cadf294569a5d7095d9ee496118d408da37f0a269c` |
| SHA3-384 | `0adfa8a6e80f624519fed48b5a8b7d04fdd84cc1d6fe6ac996317a9c89644aa73ca9a46d0669ba1d224beda1bbb1f59d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T14DE6331DA6D021FBEB77003EEEE06A95E644B4BA4B71C28B07B482E6BE171D05C35753` |
| SSDEEP | `393216:a9tRlEQYvnh0hXMCHWUjX/cuI3/PGTAI:a9tjEQYPhmXMb8XUH/O7` |
| ICON-DHASH | `70f0f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_069_7d2b009f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d2b009f6ec2a02836b984cadf294569a5d7095d9ee496118d408da37f0a269c"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 16:52:08"
  condition:
    hash.sha256(0, filesize) == "7d2b009f6ec2a02836b984cadf294569a5d7095d9ee496118d408da37f0a269c"
}
```

### Sample 70: `086446ea42d2dddc`

| Field | Value |
|---|---|
| SHA-256 | `086446ea42d2dddc6548112b88aa59fcea0eab0849340ee101902e4fbf55f718` |
| Family label | `Mirai` |
| File name | `bot.x86` |
| File type | `elf` |
| First seen | `2026-07-14 16:47:26` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3242810577f07def7dedb10ea0090be` |
| SHA-1 | `502c40aaec4fa1fbaf40af694a002235f2c7dbe0` |
| SHA-256 | `086446ea42d2dddc6548112b88aa59fcea0eab0849340ee101902e4fbf55f718` |
| SHA3-384 | `28ce026c248b67274c31da124f90f60603c45a1148d293bc2776a3f7c96c3e7506fce6b4e52cb8d2ae2e798225a04979` |
| TLSH | `T18F156C1BB2B3B4FCC167C43047ABD962A931B46511226E7F65C4DA303E27D701B2EB66` |
| TELFHASH | `t11cc19f740ff970b4a6d7c611f322f4b59e73289672e535b026266d88dfc5f800d62863` |
| SSDEEP | `24576:zcfuwy4kDRHqItrK3URnW4hv+Vx00JJJJJJJJJlJJHJJJJJJJFJJJARJ:zcfuwy4k4ItrkURW4h2D` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_086446ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "086446ea42d2dddc6548112b88aa59fcea0eab0849340ee101902e4fbf55f718"
    family = "Mirai"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-07-14 16:47:26"
  condition:
    hash.sha256(0, filesize) == "086446ea42d2dddc6548112b88aa59fcea0eab0849340ee101902e4fbf55f718"
}
```

### Sample 71: `c0111291f4dfeba0`

| Field | Value |
|---|---|
| SHA-256 | `c0111291f4dfeba09099cfcbd07930830cb13360365404152b18fc85d77e1ac7` |
| Family label | `Gafgyt` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-14 16:47:00` |
| Reporter | `BlinkzSec` |
| Tags | `Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44ac76fd5a463c06a2c19303a1c08a4a` |
| SHA-1 | `3543512e50821eee49aa0df6bfcfbca6ebf17bb8` |
| SHA-256 | `c0111291f4dfeba09099cfcbd07930830cb13360365404152b18fc85d77e1ac7` |
| SHA3-384 | `9aae94922d153426e29bb6dab4917da842b7564edf0bca1e5d6c4fd42467198e6f906c2aa43a7d09b47253ad71641106` |
| TLSH | `T14C733A96F8809B12D6D1157AFF1E528E3313077CE3DE32129E24AB2477879A70E7B905` |
| TELFHASH | `t1eff07d208e8c5cacf7d0583dc1df7b563a2aa26ee51234544e5f1d619a326c19d92826` |
| SSDEEP | `1536:6InBLgdjV+aPOfQTMaYiL0t3lavG9dk5W2OHYSr:fgdJ+aG0x0t3lavG8/oN` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_071_c0111291
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0111291f4dfeba09099cfcbd07930830cb13360365404152b18fc85d77e1ac7"
    family = "Gafgyt"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-14 16:47:00"
  condition:
    hash.sha256(0, filesize) == "c0111291f4dfeba09099cfcbd07930830cb13360365404152b18fc85d77e1ac7"
}
```

### Sample 72: `e5ce25903af43830`

| Field | Value |
|---|---|
| SHA-256 | `e5ce25903af4383079e1378ab0a1b07275631aedcfe4e41df96c2431d598aebb` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:43:07` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ecc5edc858de3a14cbefeef7f790877` |
| SHA-1 | `2b28d2475238d31c8f7c55ea5a521a6117bd803e` |
| SHA-256 | `e5ce25903af4383079e1378ab0a1b07275631aedcfe4e41df96c2431d598aebb` |
| SHA3-384 | `cadd7bfd8fda30bf4bbe53bcd75b73e3569babb9cb057901997b2e9521e6d99f982b5647b7e62fa776cf4037f65c6d26` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1DA46E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:4zIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:4hfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_072_e5ce2590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5ce25903af4383079e1378ab0a1b07275631aedcfe4e41df96c2431d598aebb"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:43:07"
  condition:
    hash.sha256(0, filesize) == "e5ce25903af4383079e1378ab0a1b07275631aedcfe4e41df96c2431d598aebb"
}
```

### Sample 73: `cf3dced525f0a3dd`

| Field | Value |
|---|---|
| SHA-256 | `cf3dced525f0a3dd0e4047ef0669837671e655614441ed582084de9a03fd2615` |
| Family label | `unknown` |
| File name | `dab.ps1` |
| File type | `ps1` |
| First seen | `2026-07-14 16:36:02` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a26cdb421f012a5617ee9e7df2254fb4` |
| SHA-1 | `af28c720598ddc90eebd82e12f987d51f1a6fa25` |
| SHA-256 | `cf3dced525f0a3dd0e4047ef0669837671e655614441ed582084de9a03fd2615` |
| SHA3-384 | `4552e48dec69f3d42fe06b97b430458c2eec35652f4064bdcc3a6ab1d87de3ee056b3b71427ba9c0412d3ec3856c598b` |
| TLSH | `T104B13F91E947455681F746AB7F12A104F0C2013FCA0A6C06F2AC66963FB835EC6F2F5A` |
| SSDEEP | `96:Mh9rxdxtxTxkhQeLyDbSGxPv54HGT5uuPCk0Y2jYUzzr7V956/4S:8Tj9N7bSGxPB4mT5tPCk0Y25zDV/6t` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_cf3dced5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf3dced525f0a3dd0e4047ef0669837671e655614441ed582084de9a03fd2615"
    family = "unknown"
    file_name = "dab.ps1"
    file_type = "ps1"
    first_seen = "2026-07-14 16:36:02"
  condition:
    hash.sha256(0, filesize) == "cf3dced525f0a3dd0e4047ef0669837671e655614441ed582084de9a03fd2615"
}
```

### Sample 74: `5607a94195a263ef`

| Field | Value |
|---|---|
| SHA-256 | `5607a94195a263ef620cebbc3c4e64930d631f0582d0452131c694556e623e50` |
| Family label | `unknown` |
| File name | `dab.ps1` |
| File type | `ps1` |
| First seen | `2026-07-14 16:35:58` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdee3f3e4c5c5792121f2513dcd324c7` |
| SHA-1 | `5b4b2dab62f12a1ccff231b532131482a9332b62` |
| SHA-256 | `5607a94195a263ef620cebbc3c4e64930d631f0582d0452131c694556e623e50` |
| SHA3-384 | `a5b5ddd949e25b76466a61a937eb17d1b3fc08183f17c8e05d3f27bf1c39b0b9428cd94aaf6ff3e86f261f340124974d` |
| TLSH | `T142B13F91E947455681F746AB7F12A104F0C1013FCA0A6C06F2EC66963FB835E86F2F5A` |
| SSDEEP | `96:Mh9rxdxtxTxkhqMLeLyDbSGxPv54HGT5uuPCk0Y2jYUzzr7V956/4S:8Tj9+L7bSGxPB4mT5tPCk0Y25zDV/6t` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_5607a941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5607a94195a263ef620cebbc3c4e64930d631f0582d0452131c694556e623e50"
    family = "unknown"
    file_name = "dab.ps1"
    file_type = "ps1"
    first_seen = "2026-07-14 16:35:58"
  condition:
    hash.sha256(0, filesize) == "5607a94195a263ef620cebbc3c4e64930d631f0582d0452131c694556e623e50"
}
```

### Sample 75: `732dfed9c6d0fbdf`

| Field | Value |
|---|---|
| SHA-256 | `732dfed9c6d0fbdfd29addfb4d3981dd4f50bbb1417bd397ad42787a21b7558a` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:57` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b7c8886fecd8f44cd53fd423caa3d68` |
| SHA-1 | `fc414f6d56efac6c248b597ef62dc956ff8bedd8` |
| SHA-256 | `732dfed9c6d0fbdfd29addfb4d3981dd4f50bbb1417bd397ad42787a21b7558a` |
| SHA3-384 | `a5a836fef47fa2e6f4a6f1a7db5ba190dedef99edee6bba80c14b9e5fda24b9c0462f49f7505d922baf08797a1ed1bc9` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T138646C11B9C48432C673383147B8E2B28DBDB8301D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:9mlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFti9c:41iw7gryNkSV1hy1Z1u2JLI9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_075_732dfed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "732dfed9c6d0fbdfd29addfb4d3981dd4f50bbb1417bd397ad42787a21b7558a"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:57"
  condition:
    hash.sha256(0, filesize) == "732dfed9c6d0fbdfd29addfb4d3981dd4f50bbb1417bd397ad42787a21b7558a"
}
```

### Sample 76: `eb4ca3c1757eb36f`

| Field | Value |
|---|---|
| SHA-256 | `eb4ca3c1757eb36faa00200c5ce0345a396724c195b33f36563d452d4abcddd7` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:57` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb61a8f8fb611ec5f78343e139593ea8` |
| SHA-1 | `33dfbfc68d3fcec6c99a994f85979ef765009caf` |
| SHA-256 | `eb4ca3c1757eb36faa00200c5ce0345a396724c195b33f36563d452d4abcddd7` |
| SHA3-384 | `27d5887a28417324d4549212cd9e694c6c919227da3f636785b2c77d3878ce67c923f58afef596821a9cb357a6063b24` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T17C46F141B3D695B5D0BF0638D87A42A65634BC108712CBFF57A4BD296D32BC08E7237A` |
| SSDEEP | `49152:yfRBDtJkGYYpT0+TFiH7efP3nrGLq7FVsLBe+1GVxrKlsuwGenGwfZVkVjOi8if0:+qs6efP3rn/TYGVxz3GBwRVkGuyXOM` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_076_eb4ca3c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb4ca3c1757eb36faa00200c5ce0345a396724c195b33f36563d452d4abcddd7"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:57"
  condition:
    hash.sha256(0, filesize) == "eb4ca3c1757eb36faa00200c5ce0345a396724c195b33f36563d452d4abcddd7"
}
```

### Sample 77: `c361c144166d6855`

| Field | Value |
|---|---|
| SHA-256 | `c361c144166d68555ebee186ba47d4421e6ab4c3330739e1ca3e57f38a438832` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:44` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f191045009ed1d703132acbf3d5d9f1` |
| SHA-1 | `efd6981731b666e5b3931931f7cdc3e0072f74d4` |
| SHA-256 | `c361c144166d68555ebee186ba47d4421e6ab4c3330739e1ca3e57f38a438832` |
| SHA3-384 | `5173af4d686c30ea38e9775b33cfac5926f9528789eaa73a520663edf39d4a6b50613701fab7a2ca535795145cd1f123` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T18546E101B3D695B6D1BF1638D87A52656734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:LzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:LhfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_077_c361c144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c361c144166d68555ebee186ba47d4421e6ab4c3330739e1ca3e57f38a438832"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:44"
  condition:
    hash.sha256(0, filesize) == "c361c144166d68555ebee186ba47d4421e6ab4c3330739e1ca3e57f38a438832"
}
```

### Sample 78: `97219eed1eda6a12`

| Field | Value |
|---|---|
| SHA-256 | `97219eed1eda6a12d672138da9c9c540e95be415d227fd81c6933eb1b81f7160` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:42` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abffa933bba9273c4dc2096c0e125ff9` |
| SHA-1 | `e3bc15a2d2a89e5a384e1d323f7a7d8e6ba5d0a6` |
| SHA-256 | `97219eed1eda6a12d672138da9c9c540e95be415d227fd81c6933eb1b81f7160` |
| SHA3-384 | `9f3b384f28f15296a8fb2d62f68b97d1fc0d3e9b190d641c312d341f09a65e1952fbd2b5ae9cc9d95c551e0a28547d1c` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1B2647C11B9C48432C673383147B8E2B28DBDB8301D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:ymlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9O:R1iw7gryNkSV1hy1Z1u2JLu9O` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_078_97219eed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97219eed1eda6a12d672138da9c9c540e95be415d227fd81c6933eb1b81f7160"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:42"
  condition:
    hash.sha256(0, filesize) == "97219eed1eda6a12d672138da9c9c540e95be415d227fd81c6933eb1b81f7160"
}
```

### Sample 79: `d92594e95e83004a`

| Field | Value |
|---|---|
| SHA-256 | `d92594e95e83004ab04ac3eb9fa30d1f9079d13b9df210714d24c82c398e31d2` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:41` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff7b13f301311cb21ee7592ff1f09947` |
| SHA-1 | `da3c5e0554f51f93f1c229c13fa26e914e60f236` |
| SHA-256 | `d92594e95e83004ab04ac3eb9fa30d1f9079d13b9df210714d24c82c398e31d2` |
| SHA3-384 | `b028044b51c09a4daf4232040017b8e5a3894fbf706fe4a0339ec128ae66dd78207ed494095d7663f7c134b6a27fbe94` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T12446E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:yzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:yhfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_079_d92594e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d92594e95e83004ab04ac3eb9fa30d1f9079d13b9df210714d24c82c398e31d2"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:41"
  condition:
    hash.sha256(0, filesize) == "d92594e95e83004ab04ac3eb9fa30d1f9079d13b9df210714d24c82c398e31d2"
}
```

### Sample 80: `1c581a5bcc6a4fb4`

| Field | Value |
|---|---|
| SHA-256 | `1c581a5bcc6a4fb4ecb9d6151c9c88adfe678d3771fdd1accf9820152064f0c2` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:38` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd609d2c607c6bb70cbf4d5c7c21a891` |
| SHA-1 | `9e6fef572d60322135fe2a2312880006d39675d8` |
| SHA-256 | `1c581a5bcc6a4fb4ecb9d6151c9c88adfe678d3771fdd1accf9820152064f0c2` |
| SHA3-384 | `f1c862d460704bd6c207e059f78c3eeedff49780505aa1b6824024a235c5f62135635b158d00f2313a0930c7c367ff40` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1AD46E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:6zIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:6hfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_080_1c581a5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c581a5bcc6a4fb4ecb9d6151c9c88adfe678d3771fdd1accf9820152064f0c2"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:38"
  condition:
    hash.sha256(0, filesize) == "1c581a5bcc6a4fb4ecb9d6151c9c88adfe678d3771fdd1accf9820152064f0c2"
}
```

### Sample 81: `44b6d6bbd97152d4`

| Field | Value |
|---|---|
| SHA-256 | `44b6d6bbd97152d4e7cd25ed49bde0f8a1c5d30c241d99c4a34f66cec3f28e2f` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:37` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa5eaae30652c27a23f084070f12e897` |
| SHA-1 | `7a26456e44190c848ec4af15a57be6e836db01fa` |
| SHA-256 | `44b6d6bbd97152d4e7cd25ed49bde0f8a1c5d30c241d99c4a34f66cec3f28e2f` |
| SHA3-384 | `d0dda105fe92fdb135c371974f7684a76447a518f80b3fc0eb2688cebc404fe81aa09dc1691e83af128ad08e3897a4a3` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1B7646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:amlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9:p1iw7gryNkSV1hy1Z1u2JLu9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_081_44b6d6bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44b6d6bbd97152d4e7cd25ed49bde0f8a1c5d30c241d99c4a34f66cec3f28e2f"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:37"
  condition:
    hash.sha256(0, filesize) == "44b6d6bbd97152d4e7cd25ed49bde0f8a1c5d30c241d99c4a34f66cec3f28e2f"
}
```

### Sample 82: `783d41b84f4de36b`

| Field | Value |
|---|---|
| SHA-256 | `783d41b84f4de36b14e48e2c3f18f5ede44e97348e03cfc9396f77f42fdf0689` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:35` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fc15ab0c75c547f66c9cd8ad85c136b` |
| SHA-1 | `fb9664a2dc8d3b88f5e17312677dcfcd29bd23ad` |
| SHA-256 | `783d41b84f4de36b14e48e2c3f18f5ede44e97348e03cfc9396f77f42fdf0689` |
| SHA3-384 | `1204e25e19aeaab80f66e0e17b47463952cb2969d4028e89717ada30f2720260f79a61d4ba53f4fb76f2dead558861eb` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T19646E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:azIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:ahfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_082_783d41b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "783d41b84f4de36b14e48e2c3f18f5ede44e97348e03cfc9396f77f42fdf0689"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:35"
  condition:
    hash.sha256(0, filesize) == "783d41b84f4de36b14e48e2c3f18f5ede44e97348e03cfc9396f77f42fdf0689"
}
```

### Sample 83: `6f2139d68bc0222b`

| Field | Value |
|---|---|
| SHA-256 | `6f2139d68bc0222b441fadeb6f484650ee7192aceea86c5399749b279898abd0` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:34` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e29f64a18e8b2a5f4e8ef07d5ff70d84` |
| SHA-1 | `6a77c9d084298edb321ac95c28a94eb2eb8a0c9f` |
| SHA-256 | `6f2139d68bc0222b441fadeb6f484650ee7192aceea86c5399749b279898abd0` |
| SHA3-384 | `f38b74800e24a2789bca2c81a6bd65f8238348ce1b83523638e69c1438ff4c92161dd8a468de792c1adac883239875ef` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T180646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:KmlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9+:51iw7gryNkSV1hy1Z1u2JLu9+` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_083_6f2139d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f2139d68bc0222b441fadeb6f484650ee7192aceea86c5399749b279898abd0"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:34"
  condition:
    hash.sha256(0, filesize) == "6f2139d68bc0222b441fadeb6f484650ee7192aceea86c5399749b279898abd0"
}
```

### Sample 84: `2b5f7211a6c98dc9`

| Field | Value |
|---|---|
| SHA-256 | `2b5f7211a6c98dc9302023024cf7e11e5360314160a6b291f74350eeb46c072d` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:32` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1002b1cb400c7198c2c72b2dd6dfb029` |
| SHA-1 | `fe327af001f6ffb002f053c3a03e15cca1384a1e` |
| SHA-256 | `2b5f7211a6c98dc9302023024cf7e11e5360314160a6b291f74350eeb46c072d` |
| SHA3-384 | `f4455c492aac31a3eaf0b03677c56fe3573b3662e8a0b94e6b7b8a93cf4bb61937c1f7c981832f9d45a3d27c2c7729ee` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1D0646D11B9C48432C673383147B8E2B28DBDB8301D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:CmlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji90:B1iw7gryNkSV1hy1Z1u2JLu90` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_084_2b5f7211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b5f7211a6c98dc9302023024cf7e11e5360314160a6b291f74350eeb46c072d"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:32"
  condition:
    hash.sha256(0, filesize) == "2b5f7211a6c98dc9302023024cf7e11e5360314160a6b291f74350eeb46c072d"
}
```

### Sample 85: `0b3a0e6bf514f9ba`

| Field | Value |
|---|---|
| SHA-256 | `0b3a0e6bf514f9baecd9f26cdbeb74afc455666d0d41db4b8673f7a98cd855cf` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:30` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f12bb455c44905d39301d85baae785ef` |
| SHA-1 | `dcab0b70a530de49ade1fa12c5f91e22bb69bb3b` |
| SHA-256 | `0b3a0e6bf514f9baecd9f26cdbeb74afc455666d0d41db4b8673f7a98cd855cf` |
| SHA3-384 | `85429be92c694c790066a12c32245cc630aba7e6cdadd929ff0b6fcdbdfef66f4768a99dfee4d5f5dbf9309738c321e6` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1AE646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:imlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9:h1iw7gryNkSV1hy1Z1u2JLu9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_085_0b3a0e6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b3a0e6bf514f9baecd9f26cdbeb74afc455666d0d41db4b8673f7a98cd855cf"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:30"
  condition:
    hash.sha256(0, filesize) == "0b3a0e6bf514f9baecd9f26cdbeb74afc455666d0d41db4b8673f7a98cd855cf"
}
```

### Sample 86: `cd68d01fe8e57890`

| Field | Value |
|---|---|
| SHA-256 | `cd68d01fe8e57890fcbbe66833a8416981feda4d79148a661692fa364db66738` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:30` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `765c50d86c02177d5479ae31794e8447` |
| SHA-1 | `af959c3a23704bc5712f71031b848e0f2b286ae7` |
| SHA-256 | `cd68d01fe8e57890fcbbe66833a8416981feda4d79148a661692fa364db66738` |
| SHA3-384 | `4b12f17693607e9d779d15d8358945ce6967faeb224d00102f1a658d18b2a6507fbc12ea5662618072ce2cf4857954dc` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T10946E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:/zIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:/hfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_086_cd68d01f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd68d01fe8e57890fcbbe66833a8416981feda4d79148a661692fa364db66738"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:30"
  condition:
    hash.sha256(0, filesize) == "cd68d01fe8e57890fcbbe66833a8416981feda4d79148a661692fa364db66738"
}
```

### Sample 87: `24cf9f32c1e3ebec`

| Field | Value |
|---|---|
| SHA-256 | `24cf9f32c1e3ebec5e810a865ad4acdcd28669d4b548929c8e4a962d77e44b1b` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:29:25` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b6b7be273f8c409f44fd94655b3e6cb` |
| SHA-1 | `24e62aa365df0031addf76831f231468b7b8bef2` |
| SHA-256 | `24cf9f32c1e3ebec5e810a865ad4acdcd28669d4b548929c8e4a962d77e44b1b` |
| SHA3-384 | `1e281aa395d8567d23b1ed583db7f2187e15f2a4ab4c175ebab513280c905f6745fce1834e361b48887b36a1a9c150fd` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1FC646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:ymlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9:R1iw7gryNkSV1hy1Z1u2JLu9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_087_24cf9f32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24cf9f32c1e3ebec5e810a865ad4acdcd28669d4b548929c8e4a962d77e44b1b"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:25"
  condition:
    hash.sha256(0, filesize) == "24cf9f32c1e3ebec5e810a865ad4acdcd28669d4b548929c8e4a962d77e44b1b"
}
```

### Sample 88: `4a3d1b9df22e50a9`

| Field | Value |
|---|---|
| SHA-256 | `4a3d1b9df22e50a9556d7161dc36800eb37833eca26057036d34e5be27f4df6d` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.FileRepMalware.11498445` |
| File type | `exe` |
| First seen | `2026-07-14 16:25:51` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e42871b165d20d0ec5f391d9d49be60` |
| SHA-1 | `eb6bdb5f668bf5e848d27f278e9b5558a716cd90` |
| SHA-256 | `4a3d1b9df22e50a9556d7161dc36800eb37833eca26057036d34e5be27f4df6d` |
| SHA3-384 | `24b89eb6b63c1fb40248b92c434b7e82d03c25b875e5d658c03f26c1f2bac6f0c52b02b4baca951fffd62c143eb4dcb8` |
| IMPHASH | `92576cbf961890053b0276abaa28bb78` |
| TLSH | `T102D46C19F7A410FEE16BC578C9524916FBB27C4747A0AACF13904A961F2B6E04F3E712` |
| SSDEEP | `12288:yNH+AxETh1IpJWIf9KvvGQJClDeSF6X0j:ykAqTXCJDWg3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_4a3d1b9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a3d1b9df22e50a9556d7161dc36800eb37833eca26057036d34e5be27f4df6d"
    family = "unknown"
    file_name = "SecuriteInfo.com.FileRepMalware.11498445"
    file_type = "exe"
    first_seen = "2026-07-14 16:25:51"
  condition:
    hash.sha256(0, filesize) == "4a3d1b9df22e50a9556d7161dc36800eb37833eca26057036d34e5be27f4df6d"
}
```

### Sample 89: `8e6d648dd5b03d2d`

| Field | Value |
|---|---|
| SHA-256 | `8e6d648dd5b03d2d56ccc1a08908ecdfdd1dbbfac5c9d8d399d9a0e5d9227579` |
| Family label | `unknown` |
| File name | `Demanda_Civil_Reparacion_Da±o_Patrimonial_NUM80005.js` |
| File type | `js` |
| First seen | `2026-07-14 16:16:07` |
| Reporter | `NatrXN1O1` |
| Tags | `js, Remcos` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b095acf446b47b7c1f123f4e81d2d646` |
| SHA-1 | `f3cff9f39b1241467569ddead45741a14b4c71a2` |
| SHA-256 | `8e6d648dd5b03d2d56ccc1a08908ecdfdd1dbbfac5c9d8d399d9a0e5d9227579` |
| SHA3-384 | `ba4701baae27160b294c748f288c63bc90e437624d1664986de16656ca133064a0024c3732bed63de2cd532d5947ab20` |
| TLSH | `T1B322C70832A0712EA12C13A3489F233558FE55B53ED9C7F8993FCA953E41A867C56DEC` |
| SSDEEP | `192:P3AQe48IHr9YnS98l9k34quFWiPR7S0xj43tsPrc8LY5SoH1B:P3z/JYS9OkIquFWbw4iPI8Lmh1B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_8e6d648d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e6d648dd5b03d2d56ccc1a08908ecdfdd1dbbfac5c9d8d399d9a0e5d9227579"
    family = "unknown"
    file_name = "Demanda_Civil_Reparacion_Da±o_Patrimonial_NUM80005.js"
    file_type = "js"
    first_seen = "2026-07-14 16:16:07"
  condition:
    hash.sha256(0, filesize) == "8e6d648dd5b03d2d56ccc1a08908ecdfdd1dbbfac5c9d8d399d9a0e5d9227579"
}
```

### Sample 90: `28f28077680c530e`

| Field | Value |
|---|---|
| SHA-256 | `28f28077680c530e9d4278cecf0d8a9ac0682ed63bf9ee1d6a90cd18b88e67fa` |
| Family label | `WannaCry` |
| File name | `28f28077680c530e9d4278cecf0d8a9ac0682ed63bf9ee1d6a90cd18b88e67fa` |
| File type | `exe` |
| First seen | `2026-07-14 16:15:15` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6e76ba53c968b6c967b618fe1788b0d` |
| SHA-1 | `a62e579ffd189f9a7c4e962b7a517dec7561a10f` |
| SHA-256 | `28f28077680c530e9d4278cecf0d8a9ac0682ed63bf9ee1d6a90cd18b88e67fa` |
| SHA3-384 | `69abd6408f50435f7bceaca7e169d988224a30efafd49efb5074a943b6e7c23c0ec6e0333955bc2d696506837cfb5b40` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T15E36129932AC80FCD4165274D4B34E25F6B3BC9E12B9870F97948B6A0E13391BB34B57` |
| SSDEEP | `12288:jbLgD1bLgmluCtgQhMbaIMu7L5NVErCA4z2g6rTcbckPU82900Ve7zw+K+D:jbLgBbLgurgQhfdmMSirYbcMNgef0` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_090_28f28077
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28f28077680c530e9d4278cecf0d8a9ac0682ed63bf9ee1d6a90cd18b88e67fa"
    family = "WannaCry"
    file_name = "28f28077680c530e9d4278cecf0d8a9ac0682ed63bf9ee1d6a90cd18b88e67fa"
    file_type = "exe"
    first_seen = "2026-07-14 16:15:15"
  condition:
    hash.sha256(0, filesize) == "28f28077680c530e9d4278cecf0d8a9ac0682ed63bf9ee1d6a90cd18b88e67fa"
}
```

### Sample 91: `4ec5a94f92dea1d8`

| Field | Value |
|---|---|
| SHA-256 | `4ec5a94f92dea1d81599c4792c902075ffc2e2afe94e80bb48f40094080c34e2` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-14 16:12:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `708a18776922f9f955fc81c0fa4d438c` |
| SHA-1 | `7b502ebd503b3480b62c215157cfac0c280eacea` |
| SHA-256 | `4ec5a94f92dea1d81599c4792c902075ffc2e2afe94e80bb48f40094080c34e2` |
| SHA3-384 | `c2d42d2fca15014d4e0f2ccfd354b8b4fb565eab6472fd27b7e3e0b2476109cc5a7d75cb500562a3f1cc0326b4aaad31` |
| TLSH | `T16CB31889B8D29A62C6D316BFFA4F428D773663E4E3DF7107DD185B21328651A0E6B201` |
| TELFHASH | `t19ad097b3bf3a09e0afc10080404db31222d870728b2220823aff1e0f1403f82b80dc42` |
| SSDEEP | `3072:OLSGJF7sNvZLuNciU5I1a2UmCK7l3C1y6Bnb7:OmG4hscioIJU5K7Iyq7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_4ec5a94f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ec5a94f92dea1d81599c4792c902075ffc2e2afe94e80bb48f40094080c34e2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-14 16:12:43"
  condition:
    hash.sha256(0, filesize) == "4ec5a94f92dea1d81599c4792c902075ffc2e2afe94e80bb48f40094080c34e2"
}
```

### Sample 92: `9959cf5abc2b9244`

| Field | Value |
|---|---|
| SHA-256 | `9959cf5abc2b92440926e0acc7365125ddd143e30b0c855ae006fd83d01e395b` |
| Family label | `unknown` |
| File name | `East Coast Signs  Graphics PROJECT.pdf` |
| File type | `pdf` |
| First seen | `2026-07-14 16:03:20` |
| Reporter | `jsmithatpcrx` |
| Tags | `pdf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee203c457911da9ed5211f87797100e2` |
| SHA-256 | `9959cf5abc2b92440926e0acc7365125ddd143e30b0c855ae006fd83d01e395b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `pdf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_9959cf5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9959cf5abc2b92440926e0acc7365125ddd143e30b0c855ae006fd83d01e395b"
    family = "unknown"
    file_name = "East Coast Signs  Graphics PROJECT.pdf"
    file_type = "pdf"
    first_seen = "2026-07-14 16:03:20"
  condition:
    hash.sha256(0, filesize) == "9959cf5abc2b92440926e0acc7365125ddd143e30b0c855ae006fd83d01e395b"
}
```

### Sample 93: `3700e44be4e67447`

| Field | Value |
|---|---|
| SHA-256 | `3700e44be4e674477ca36b3dc4012608afcebf7917ca68eeff6b8782694fd768` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-14 16:02:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b041b74cddc05a51c44292104c6cef69` |
| SHA-1 | `7da837500b402731d48d554b1fefc791f39a50b4` |
| SHA-256 | `3700e44be4e674477ca36b3dc4012608afcebf7917ca68eeff6b8782694fd768` |
| SHA3-384 | `02657215f0dd437f6431fdbf0cd69ce04493b932e1de9d00697ae33d1b02576cf4b08197d64db72cacab6d17fae0e56e` |
| TLSH | `T1A7631A45BD82AA06CAD90377FA1E42CD331173D8E2ED3227DD256F11B7CA52B0E6B161` |
| TELFHASH | `t1cdd05e238e5c2bc872d6431608692b4d96dd34de2629c828baad3fa99f12cc5749a570` |
| SSDEEP | `1536:+6j0x+EXI18HoBsXMcdGj/JLfRwuq6T3OxgITHwbZnU:70EEXuKo4MN/FRw8TOZwbZnU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_3700e44b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3700e44be4e674477ca36b3dc4012608afcebf7917ca68eeff6b8782694fd768"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-14 16:02:49"
  condition:
    hash.sha256(0, filesize) == "3700e44be4e674477ca36b3dc4012608afcebf7917ca68eeff6b8782694fd768"
}
```

### Sample 94: `daca7dff705d30c7`

| Field | Value |
|---|---|
| SHA-256 | `daca7dff705d30c7f81ae424b54ee528e5559d7d4160eed7ffd357e294bf411e` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:02:35` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27a888a3dbaa952dbb432ef33815fbec` |
| SHA-1 | `083ea9ca81bc01c51d55a276aeb1fed9b3717ad0` |
| SHA-256 | `daca7dff705d30c7f81ae424b54ee528e5559d7d4160eed7ffd357e294bf411e` |
| SHA3-384 | `4ab277caa4c4c2391098f2255e850cc6e72707f594fd6dfdf00f948ed1fa9671f136089449d4d7b10f947eaebe93d345` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1DB46E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:izIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:ihfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_094_daca7dff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daca7dff705d30c7f81ae424b54ee528e5559d7d4160eed7ffd357e294bf411e"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:02:35"
  condition:
    hash.sha256(0, filesize) == "daca7dff705d30c7f81ae424b54ee528e5559d7d4160eed7ffd357e294bf411e"
}
```

### Sample 95: `8fe09be2bb21339f`

| Field | Value |
|---|---|
| SHA-256 | `8fe09be2bb21339f8b9ab4f3f30a9bcb4f6e167410ef3449f9659b3fb6f1cd10` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:02:31` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7046e88eb63b1d5271901092ce6e3838` |
| SHA-1 | `cc8caab23e20032831b1dc6e45a781925b6ee938` |
| SHA-256 | `8fe09be2bb21339f8b9ab4f3f30a9bcb4f6e167410ef3449f9659b3fb6f1cd10` |
| SHA3-384 | `cdc2512a4b0cef68c11e80102c252e1400ee95e9b3ae7cd7534d3a72698f34ee602a4fb5a8d86b17a1890bcf9d8fd3f6` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1B5646D11B9C48432C673383147B8E2B28DBDB8301D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:qmlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9L:Z1iw7gryNkSV1hy1Z1u2JLu9L` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_095_8fe09be2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fe09be2bb21339f8b9ab4f3f30a9bcb4f6e167410ef3449f9659b3fb6f1cd10"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:02:31"
  condition:
    hash.sha256(0, filesize) == "8fe09be2bb21339f8b9ab4f3f30a9bcb4f6e167410ef3449f9659b3fb6f1cd10"
}
```

### Sample 96: `393e5aed4cef3842`

| Field | Value |
|---|---|
| SHA-256 | `393e5aed4cef384221a6f662b7ee9910e2dc299add5d38bb315fa2748f1d7387` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-14 16:01:10` |
| Reporter | `iamaachum` |
| Tags | `exe, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ba651a87513795f28b41c62c326814b` |
| SHA-1 | `b18a7b65b51ca73bee9cf4e749e87f92959783c0` |
| SHA-256 | `393e5aed4cef384221a6f662b7ee9910e2dc299add5d38bb315fa2748f1d7387` |
| SHA3-384 | `023fca6f6f73f42d92dbaf62c8c7f3e1ce9acd5d16332a9e0005ab070155b91863cb5bc5e80127d2084cf759d4e42def` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T121B6334FB1424E9BD58411B098A58BB1223DD404EEE332B2DA99476FFFC71704789EA7` |
| SSDEEP | `196608:X9Y5QKtwekD43Go2d2qxgwfGEAroDl6X1OWa/e:t5CKDtDd3xLP/e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_393e5aed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "393e5aed4cef384221a6f662b7ee9910e2dc299add5d38bb315fa2748f1d7387"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:01:10"
  condition:
    hash.sha256(0, filesize) == "393e5aed4cef384221a6f662b7ee9910e2dc299add5d38bb315fa2748f1d7387"
}
```

### Sample 97: `d44dafd48ec502e2`

| Field | Value |
|---|---|
| SHA-256 | `d44dafd48ec502e2512076ad1d66209059511292413123f87965011d5d96262e` |
| Family label | `unknown` |
| File name | `interface.scpt` |
| File type | `scpt` |
| First seen | `2026-07-14 15:57:20` |
| Reporter | `smica83` |
| Tags | `scpt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `445ca07cd8910bf03f64b58c97efbad7` |
| SHA-1 | `12afe62e0cdf124b734a57eb0c9aeb50ed841f16` |
| SHA-256 | `d44dafd48ec502e2512076ad1d66209059511292413123f87965011d5d96262e` |
| SHA3-384 | `c6d4b2dd8926f777c575290a1a7e40b82a7d31deb1b85d77867f41e587d201a499ced48634d1bf0b13ed6bf774bb9e64` |
| TLSH | `T111F23B46F3D90AA2FEF33BB02AB15349C5397D59C93BCF6C4458216B02826C89527773` |
| SSDEEP | `768:gyecW4c/fxYe5fxynqwVyRaVcty1MRjCLuwyP1yFXspwbyd25UDT:+GeEqSjMRjCLYwbyNT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `scpt`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_d44dafd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d44dafd48ec502e2512076ad1d66209059511292413123f87965011d5d96262e"
    family = "unknown"
    file_name = "interface.scpt"
    file_type = "scpt"
    first_seen = "2026-07-14 15:57:20"
  condition:
    hash.sha256(0, filesize) == "d44dafd48ec502e2512076ad1d66209059511292413123f87965011d5d96262e"
}
```

### Sample 98: `6e7516a816c34eb1`

| Field | Value |
|---|---|
| SHA-256 | `6e7516a816c34eb1f9e2b1399ead4ed9a64e2132ecbb9c5e86bd249ae9fe304a` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 15:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0478fbc916f64dd814a4ff330eaccb66` |
| SHA-1 | `e3de68dd96f13ff80c1c309d3ae620fd6521239b` |
| SHA-256 | `6e7516a816c34eb1f9e2b1399ead4ed9a64e2132ecbb9c5e86bd249ae9fe304a` |
| SHA3-384 | `7b2d6fdd01291e029c1c5a5a4815234fe6c4f935f6aa271123aa3ec6b32cee219e60f0940fd310aca3037f825c4c70d9` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F5E63318A9C601EEF9F3513DEDE06684CAE9B4A50779DADF03A883A16D171D0DC3E607` |
| SSDEEP | `393216:xg8xCGGtmtSuUaCseeqD5XMCHWUjX+cuI3/PGTAI:xgGCG6mt/UaY5XMb8XzH/O7` |
| ICON-DHASH | `71f0d8d8f8e8f070` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_098_6e7516a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e7516a816c34eb1f9e2b1399ead4ed9a64e2132ecbb9c5e86bd249ae9fe304a"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 15:52:09"
  condition:
    hash.sha256(0, filesize) == "6e7516a816c34eb1f9e2b1399ead4ed9a64e2132ecbb9c5e86bd249ae9fe304a"
}
```

### Sample 99: `94b21f488f5fecc9`

| Field | Value |
|---|---|
| SHA-256 | `94b21f488f5fecc9aa5ec4a4188e7d14049d0b9e0d3d64027a450640bfbd706d` |
| Family label | `NWHStealer` |
| File name | `app.exe` |
| File type | `exe` |
| First seen | `2026-07-14 15:48:08` |
| Reporter | `iamaachum` |
| Tags | `exe, NWHStealer, unauth-amper-cc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c80c3d0c0430e22dc4287879b00328d2` |
| SHA-1 | `5ac5a982835602e627361e29a0a621436279760c` |
| SHA-256 | `94b21f488f5fecc9aa5ec4a4188e7d14049d0b9e0d3d64027a450640bfbd706d` |
| SHA3-384 | `ef1ca564ff97d24e091f85d266f0d0918c6ec29473b91f4ee954eac3df085eea23755dff5221255449ae8646beb64b6e` |
| IMPHASH | `fd6f6d07cc33ee9a2b65bda58a07bb94` |
| TLSH | `T1A0286C43A2E751D8F0BBD17497E65323E932BC490B3469EF12944B312F72AE0A779B11` |
| SSDEEP | `1572864:vZa7hmguP2nG0/Vyv7UhgxIabc/x7Awby:vZa7hmguP2nUOnAwby` |
| ICON-DHASH | `9170cc9296cc7001` |

#### Technical Assessment

- The sample is tracked as `NWHStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NWHStealer_099_94b21f48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94b21f488f5fecc9aa5ec4a4188e7d14049d0b9e0d3d64027a450640bfbd706d"
    family = "NWHStealer"
    file_name = "app.exe"
    file_type = "exe"
    first_seen = "2026-07-14 15:48:08"
  condition:
    hash.sha256(0, filesize) == "94b21f488f5fecc9aa5ec4a4188e7d14049d0b9e0d3d64027a450640bfbd706d"
}
```

### Sample 100: `0bef1f58295a8d70`

| Field | Value |
|---|---|
| SHA-256 | `0bef1f58295a8d704c4f0ab7d3f8a3c6b9af49ed2cb28066327754080e202b26` |
| Family label | `LxBaseRAT` |
| File name | `Quotation Request – Purchase Order.Malaysia-Airports..js` |
| File type | `js` |
| First seen | `2026-07-14 15:41:31` |
| Reporter | `threatcat_ch` |
| Tags | `js, LxBaseRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7691e1cd95a852916c652efc0f002f71` |
| SHA-1 | `c29318b16a85f33bef3d50c6a0a0dab39279ba64` |
| SHA-256 | `0bef1f58295a8d704c4f0ab7d3f8a3c6b9af49ed2cb28066327754080e202b26` |
| SHA3-384 | `9e32c49cb3da1a82448ef2fe8524cd728f0cad2002918c34d9475ef526762467a1dac1cfc694448cc0e3cd6fbbae10bd` |
| TLSH | `T19C457C50089F6035B7EC9D03CBCBFFFD83FA83A462992ED5086813915B6D944F256C6A` |
| SSDEEP | `24576:7zAetY3HkGdqqZ8J+/Rye1TJIVgbM6HiYFXPAcUUWdb9t2cKz7bqyV8o8:7ntY3BHZ4+5ye1TO+bMJUocUUWdptby0` |

#### Technical Assessment

- The sample is tracked as `LxBaseRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LxBaseRAT_100_0bef1f58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bef1f58295a8d704c4f0ab7d3f8a3c6b9af49ed2cb28066327754080e202b26"
    family = "LxBaseRAT"
    file_name = "Quotation Request – Purchase Order.Malaysia-Airports..js"
    file_type = "js"
    first_seen = "2026-07-14 15:41:31"
  condition:
    hash.sha256(0, filesize) == "0bef1f58295a8d704c4f0ab7d3f8a3c6b9af49ed2cb28066327754080e202b26"
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
 * Generated: 2026-07-15T03:40:31.915848+00:00
 */

rule MalwareBazaar_ConnectWise_001_406c33ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "406c33efa357e5b7f95257b7e34855ab44cfc3c7d93272d50d1e78a68a40fe11"
    family = "ConnectWise"
    file_name = "Adobe_Acrobat.bat"
    file_type = "bat"
    first_seen = "2026-07-15 03:10:49"
  condition:
    hash.sha256(0, filesize) == "406c33efa357e5b7f95257b7e34855ab44cfc3c7d93272d50d1e78a68a40fe11"
}

rule MalwareBazaar_Vidar_002_84ade85f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84ade85f5b49b00b37df593a973170eb31c3fd771b40f4c753fe9dc1560f5cd8"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 02:55:56"
  condition:
    hash.sha256(0, filesize) == "84ade85f5b49b00b37df593a973170eb31c3fd771b40f4c753fe9dc1560f5cd8"
}

rule MalwareBazaar_unknown_003_4fc8b028
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fc8b0280d5b02ffdf185530f3366f976f215d147e7d01b1910121330a6dd274"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 02:52:10"
  condition:
    hash.sha256(0, filesize) == "4fc8b0280d5b02ffdf185530f3366f976f215d147e7d01b1910121330a6dd274"
}

rule MalwareBazaar_GCleaner_004_91217219
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91217219b771a295b5c51c12308ed49c22c844a035b2b4f309ad6f4a37cadf0b"
    family = "GCleaner"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-07-15 02:52:06"
  condition:
    hash.sha256(0, filesize) == "91217219b771a295b5c51c12308ed49c22c844a035b2b4f309ad6f4a37cadf0b"
}

rule MalwareBazaar_unknown_005_4d1a0237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d1a0237c82bddae9cd21a434b2e2cb65563d0af942a8b67ae70785fb5f1bf76"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 02:22:20"
  condition:
    hash.sha256(0, filesize) == "4d1a0237c82bddae9cd21a434b2e2cb65563d0af942a8b67ae70785fb5f1bf76"
}

rule MalwareBazaar_unknown_006_7ca0ba91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ca0ba91ec68940ed9964d0f912901b654ddd338864fc214419cf40b0b4b29f7"
    family = "unknown"
    file_name = "Ekspeditionssekretrens.vbs"
    file_type = "vbs"
    first_seen = "2026-07-15 01:52:53"
  condition:
    hash.sha256(0, filesize) == "7ca0ba91ec68940ed9964d0f912901b654ddd338864fc214419cf40b0b4b29f7"
}

rule MalwareBazaar_unknown_007_5be61236
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5be612361cea707ae16d6516efc630c1c4d6d3b2b234c504287b43a41361d891"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 01:52:07"
  condition:
    hash.sha256(0, filesize) == "5be612361cea707ae16d6516efc630c1c4d6d3b2b234c504287b43a41361d891"
}

rule MalwareBazaar_Mirai_008_05cc3f09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05cc3f0982581b13437c6e5736adae2ba1e5aa45cf1f0509b554e2538a9105e8"
    family = "Mirai"
    file_name = "tarm6"
    file_type = "elf"
    first_seen = "2026-07-15 01:28:24"
  condition:
    hash.sha256(0, filesize) == "05cc3f0982581b13437c6e5736adae2ba1e5aa45cf1f0509b554e2538a9105e8"
}

rule MalwareBazaar_unknown_009_922b5375
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "922b537567f77e67b83d4aac7eb3069a75a176991caf7c70e5f5529ca3041734"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-15 01:26:45"
  condition:
    hash.sha256(0, filesize) == "922b537567f77e67b83d4aac7eb3069a75a176991caf7c70e5f5529ca3041734"
}

rule MalwareBazaar_unknown_010_4b7f8c06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b7f8c067e894fe9af8def6d3a421438f9dcee40012bd877a963d76e48f96a28"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-15 01:25:23"
  condition:
    hash.sha256(0, filesize) == "4b7f8c067e894fe9af8def6d3a421438f9dcee40012bd877a963d76e48f96a28"
}

rule MalwareBazaar_Mirai_011_bac70764
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bac70764a37e48ba063b0e80d21db47138bc5116411aa577f91e97e4ddbe6c22"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-15 01:11:49"
  condition:
    hash.sha256(0, filesize) == "bac70764a37e48ba063b0e80d21db47138bc5116411aa577f91e97e4ddbe6c22"
}

rule MalwareBazaar_Mirai_012_108b78de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "108b78de37eae804aeca049393898209699770d567a1e61a46e894613c77a31f"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-15 01:10:24"
  condition:
    hash.sha256(0, filesize) == "108b78de37eae804aeca049393898209699770d567a1e61a46e894613c77a31f"
}

rule MalwareBazaar_Mirai_013_b0b11df7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0b11df70f79a6062064b3e26847ee7ab322a3347073dbf851b019469d4c78b2"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-07-15 01:10:23"
  condition:
    hash.sha256(0, filesize) == "b0b11df70f79a6062064b3e26847ee7ab322a3347073dbf851b019469d4c78b2"
}

rule MalwareBazaar_unknown_014_98e8f952
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98e8f9526424151fd88386ff52251ae00bd938b79887011daec54590f23b6ab0"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 00:52:08"
  condition:
    hash.sha256(0, filesize) == "98e8f9526424151fd88386ff52251ae00bd938b79887011daec54590f23b6ab0"
}

rule MalwareBazaar_unknown_015_8d411425
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d411425c9eb60772d3bca4af3aca93415a1d3495bf5e2d9eb6ade8341f24451"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-15 00:44:51"
  condition:
    hash.sha256(0, filesize) == "8d411425c9eb60772d3bca4af3aca93415a1d3495bf5e2d9eb6ade8341f24451"
}

rule MalwareBazaar_unknown_016_5b92b9f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b92b9f938117b49f280cd0d85bdaf26f83ea8a93002c61f5386e972fb49d9e4"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-15 00:32:54"
  condition:
    hash.sha256(0, filesize) == "5b92b9f938117b49f280cd0d85bdaf26f83ea8a93002c61f5386e972fb49d9e4"
}

rule MalwareBazaar_unknown_017_2499d91e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2499d91e3183ea9e426ea138c4d94eddb7da4ccb49e936bf464037345f0f9c31"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-15 00:16:27"
  condition:
    hash.sha256(0, filesize) == "2499d91e3183ea9e426ea138c4d94eddb7da4ccb49e936bf464037345f0f9c31"
}

rule MalwareBazaar_unknown_018_f910373e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f910373ecf094f2ebb9db0b6b0e6808c4e9cb98b0cac0841c35a40f0396cec72"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-15 00:14:50"
  condition:
    hash.sha256(0, filesize) == "f910373ecf094f2ebb9db0b6b0e6808c4e9cb98b0cac0841c35a40f0396cec72"
}

rule MalwareBazaar_unknown_019_a6b3947c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6b3947c7ad280189c1ea1eb16876759c230aa67daa843b001991ba745cf6054"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 23:52:08"
  condition:
    hash.sha256(0, filesize) == "a6b3947c7ad280189c1ea1eb16876759c230aa67daa843b001991ba745cf6054"
}

rule MalwareBazaar_unknown_020_78f623ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78f623acdbf8541288cfc969fe4c39ca194939bfb30e921dc2d6d9bc4012b4ff"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Mardom.IN.10.59186461"
    file_type = "exe"
    first_seen = "2026-07-14 23:43:59"
  condition:
    hash.sha256(0, filesize) == "78f623acdbf8541288cfc969fe4c39ca194939bfb30e921dc2d6d9bc4012b4ff"
}

rule MalwareBazaar_PureLogsStealer_021_dc6790cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc6790cdf758ba93696edf19d490d1fbb59a4312d456c77a498ccf3b955e1572"
    family = "PureLogsStealer"
    file_name = "SecuriteInfo.com.Heur.MSIL.Benin.5.59112575"
    file_type = "exe"
    first_seen = "2026-07-14 23:43:58"
  condition:
    hash.sha256(0, filesize) == "dc6790cdf758ba93696edf19d490d1fbb59a4312d456c77a498ccf3b955e1572"
}

rule MalwareBazaar_unknown_022_0cba9622
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cba96220bd33958a47a7f09d656594ce73c83b79801a873a3ba397ba747c925"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-14 23:35:57"
  condition:
    hash.sha256(0, filesize) == "0cba96220bd33958a47a7f09d656594ce73c83b79801a873a3ba397ba747c925"
}

rule MalwareBazaar_unknown_023_aa251d0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa251d0e0ce55abd93ecda85cebafd82ea119f406cb63d9556fdeec1f4a27d1e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-14 23:34:30"
  condition:
    hash.sha256(0, filesize) == "aa251d0e0ce55abd93ecda85cebafd82ea119f406cb63d9556fdeec1f4a27d1e"
}

rule MalwareBazaar_unknown_024_69a29515
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69a2951532eb07aca5543f9e726cc9c1bb0ce7f5551c6eff336f508c7a0e7a38"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 22:52:08"
  condition:
    hash.sha256(0, filesize) == "69a2951532eb07aca5543f9e726cc9c1bb0ce7f5551c6eff336f508c7a0e7a38"
}

rule MalwareBazaar_Mirai_025_a6ea6737
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6ea67372e5b31bfd633d9745541577e9f3edb39f0eea75cf9679b632ca04908"
    family = "Mirai"
    file_name = "a6ea67372e5b31bfd633d9745541577e9f3edb39f0eea75cf9679b632ca04908"
    file_type = "elf"
    first_seen = "2026-07-14 22:41:46"
  condition:
    hash.sha256(0, filesize) == "a6ea67372e5b31bfd633d9745541577e9f3edb39f0eea75cf9679b632ca04908"
}

rule MalwareBazaar_Mirai_026_5850b6e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5850b6e589ea496b093b3c162dab126789ea118276bc3c23ff4cf75c6c19c8d5"
    family = "Mirai"
    file_name = "5850b6e589ea496b093b3c162dab126789ea118276bc3c23ff4cf75c6c19c8d5"
    file_type = "elf"
    first_seen = "2026-07-14 22:41:43"
  condition:
    hash.sha256(0, filesize) == "5850b6e589ea496b093b3c162dab126789ea118276bc3c23ff4cf75c6c19c8d5"
}

rule MalwareBazaar_WannaCry_027_1b9d1966
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b9d1966ec3bfc3d78ee8bd6715f11a2a3a7d22f1b5d3eb19ae3ebd8879bdc35"
    family = "WannaCry"
    file_name = "1b9d1966ec3bfc3d78ee8bd6715f11a2a3a7d22f1b5d3eb19ae3ebd8879bdc35"
    file_type = "exe"
    first_seen = "2026-07-14 22:15:11"
  condition:
    hash.sha256(0, filesize) == "1b9d1966ec3bfc3d78ee8bd6715f11a2a3a7d22f1b5d3eb19ae3ebd8879bdc35"
}

rule MalwareBazaar_unknown_028_2892f77e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2892f77e6c5389ba707efd4e12024e309fc4d9994a0747cb80f0cd0cea507c0b"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 21:52:06"
  condition:
    hash.sha256(0, filesize) == "2892f77e6c5389ba707efd4e12024e309fc4d9994a0747cb80f0cd0cea507c0b"
}

rule MalwareBazaar_unknown_029_ca631ce6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca631ce69ac6e03a639fd2bacb55087bb6e1fb1a29556cda9fbc1dd022e54228"
    family = "unknown"
    file_name = "ca631ce69ac6e03a639fd2bacb55087bb6e1fb1a29556cda9fbc1dd022e54228"
    file_type = "sh"
    first_seen = "2026-07-14 21:30:18"
  condition:
    hash.sha256(0, filesize) == "ca631ce69ac6e03a639fd2bacb55087bb6e1fb1a29556cda9fbc1dd022e54228"
}

rule MalwareBazaar_unknown_030_0a638387
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a638387a0937be2017e2fe3aca11ad3483c182a96d337de7b83bf927f75c148"
    family = "unknown"
    file_name = "0a638387a0937be2017e2fe3aca11ad3483c182a96d337de7b83bf927f75c148"
    file_type = "sh"
    first_seen = "2026-07-14 21:30:12"
  condition:
    hash.sha256(0, filesize) == "0a638387a0937be2017e2fe3aca11ad3483c182a96d337de7b83bf927f75c148"
}

rule MalwareBazaar_unknown_031_20226b2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20226b2b49c6d721bd5458710c111510a0f501616d5a2859943b4dc2d8f74736"
    family = "unknown"
    file_name = "gc.key"
    file_type = "exe"
    first_seen = "2026-07-14 21:09:48"
  condition:
    hash.sha256(0, filesize) == "20226b2b49c6d721bd5458710c111510a0f501616d5a2859943b4dc2d8f74736"
}

rule MalwareBazaar_ArkeiStealer_032_2a19ad3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a19ad3ce75c78d58025e0f4612f3d950f45afb4d8c11d7470642e554459a453"
    family = "ArkeiStealer"
    file_name = "Order-269916_71038.exe"
    file_type = "exe"
    first_seen = "2026-07-14 21:07:11"
  condition:
    hash.sha256(0, filesize) == "2a19ad3ce75c78d58025e0f4612f3d950f45afb4d8c11d7470642e554459a453"
}

rule MalwareBazaar_Mirai_033_e1d2d45b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1d2d45b8f5c4fb4eb7ea1ca4833696e8fd87a706fbb8a89f614bd53d314cffa"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnaarch64xnxn"
    file_type = "elf"
    first_seen = "2026-07-14 20:53:56"
  condition:
    hash.sha256(0, filesize) == "e1d2d45b8f5c4fb4eb7ea1ca4833696e8fd87a706fbb8a89f614bd53d314cffa"
}

rule MalwareBazaar_Mirai_034_52829b64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52829b64caa9ef53e8f600b1e286bd06d24ab70eeb284d8289f41b73d58f28dd"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-07-14 20:53:53"
  condition:
    hash.sha256(0, filesize) == "52829b64caa9ef53e8f600b1e286bd06d24ab70eeb284d8289f41b73d58f28dd"
}

rule MalwareBazaar_Mirai_035_5b7b9a64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b7b9a6449dcf0b779dd72210926d4567453aa40f16b473343a3aa4372798884"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnaarch64xnxn"
    file_type = "elf"
    first_seen = "2026-07-14 20:52:43"
  condition:
    hash.sha256(0, filesize) == "5b7b9a6449dcf0b779dd72210926d4567453aa40f16b473343a3aa4372798884"
}

rule MalwareBazaar_Mirai_036_f9a1915d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9a1915d056acc36d5405d81c80d0065078b1e47d8003d41fcb823e9b2e27835"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-07-14 20:52:41"
  condition:
    hash.sha256(0, filesize) == "f9a1915d056acc36d5405d81c80d0065078b1e47d8003d41fcb823e9b2e27835"
}

rule MalwareBazaar_Mirai_037_8026e59c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8026e59c5c481b8280404ab39e850bb4f412ae43cdd9cfbc8a1dbaa69302903e"
    family = "Mirai"
    file_name = "run.sh"
    file_type = "sh"
    first_seen = "2026-07-14 20:52:40"
  condition:
    hash.sha256(0, filesize) == "8026e59c5c481b8280404ab39e850bb4f412ae43cdd9cfbc8a1dbaa69302903e"
}

rule MalwareBazaar_Efimer_038_b3651031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b36510313521bd52a5eca4b3c7c3a829383883537472361d936c74ef2f42f1a0"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 20:52:07"
  condition:
    hash.sha256(0, filesize) == "b36510313521bd52a5eca4b3c7c3a829383883537472361d936c74ef2f42f1a0"
}

rule MalwareBazaar_unknown_039_1be1cf9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1be1cf9f734a326dab0e909204f981c305923ccb2ea476e8b804f3317a8dffcb"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.MalwareX-gen.98861688"
    file_type = "exe"
    first_seen = "2026-07-14 20:33:45"
  condition:
    hash.sha256(0, filesize) == "1be1cf9f734a326dab0e909204f981c305923ccb2ea476e8b804f3317a8dffcb"
}

rule MalwareBazaar_CoinMiner_040_246dca0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "246dca0b1a6195c4c6fb26bcb9b31aef79f1af5f8e506007715d53c794051d08"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-14 20:31:19"
  condition:
    hash.sha256(0, filesize) == "246dca0b1a6195c4c6fb26bcb9b31aef79f1af5f8e506007715d53c794051d08"
}

rule MalwareBazaar_unknown_041_31d6f080
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31d6f080dee4e86aa08a9ef73c216044c9e046724310b97dbae15cd95d138b15"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-14 20:25:59"
  condition:
    hash.sha256(0, filesize) == "31d6f080dee4e86aa08a9ef73c216044c9e046724310b97dbae15cd95d138b15"
}

rule MalwareBazaar_KongTuke_042_ed107d28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed107d285623a1b880b4f063d5cd8a2c2a2423e594c2f1da8903ca823bd49a4e"
    family = "KongTuke"
    file_name = "f"
    file_type = "ps1"
    first_seen = "2026-07-14 20:11:14"
  condition:
    hash.sha256(0, filesize) == "ed107d285623a1b880b4f063d5cd8a2c2a2423e594c2f1da8903ca823bd49a4e"
}

rule MalwareBazaar_Efimer_043_6589805e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6589805ec9895c732a4a42ab270862fd9495a6bfcb5270e087ccb20e5dffab58"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 19:52:08"
  condition:
    hash.sha256(0, filesize) == "6589805ec9895c732a4a42ab270862fd9495a6bfcb5270e087ccb20e5dffab58"
}

rule MalwareBazaar_unknown_044_2172f093
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2172f09302778dbe9ac1970784517b318ab9d6a0891f40713ae21b2e982808c5"
    family = "unknown"
    file_name = "macuifang_only_criminal_regulatory_request_HIM_AUT_ZhuhaiYuheng.docx"
    file_type = "docx"
    first_seen = "2026-07-14 19:48:34"
  condition:
    hash.sha256(0, filesize) == "2172f09302778dbe9ac1970784517b318ab9d6a0891f40713ae21b2e982808c5"
}

rule MalwareBazaar_unknown_045_f6251945
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f62519453afb691de16b4674927332cc8b28b4325c4e19892d31813b691652d0"
    family = "unknown"
    file_name = "LADING_LOGISTICS_COMPANY_CARRIER_AGREEMENT.vbs"
    file_type = "vbs"
    first_seen = "2026-07-14 19:32:43"
  condition:
    hash.sha256(0, filesize) == "f62519453afb691de16b4674927332cc8b28b4325c4e19892d31813b691652d0"
}

rule MalwareBazaar_unknown_046_c283269a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c283269a23aef3509594c76e0819fcd45771e092408dd6392dffc730939fa9c7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-14 19:23:42"
  condition:
    hash.sha256(0, filesize) == "c283269a23aef3509594c76e0819fcd45771e092408dd6392dffc730939fa9c7"
}

rule MalwareBazaar_unknown_047_641b5af7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "641b5af758b9636aaab679f428033b44961a96516b8287b8b3ea828a42e8e028"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-14 19:11:40"
  condition:
    hash.sha256(0, filesize) == "641b5af758b9636aaab679f428033b44961a96516b8287b8b3ea828a42e8e028"
}

rule MalwareBazaar_RemusStealer_048_abc81d4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abc81d4d4b22d8388e829f3fedeb35cb3d3a7e50a108ba1ac779161b21a5bad3"
    family = "RemusStealer"
    file_name = "gc.key"
    file_type = "exe"
    first_seen = "2026-07-14 19:08:19"
  condition:
    hash.sha256(0, filesize) == "abc81d4d4b22d8388e829f3fedeb35cb3d3a7e50a108ba1ac779161b21a5bad3"
}

rule MalwareBazaar_ArkeiStealer_049_b96e72fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b96e72fc8af7ac854ea39bf288b45e0675dc588b1925b151548d1843c80ad000"
    family = "ArkeiStealer"
    file_name = "order_37335536.exe"
    file_type = "exe"
    first_seen = "2026-07-14 18:59:20"
  condition:
    hash.sha256(0, filesize) == "b96e72fc8af7ac854ea39bf288b45e0675dc588b1925b151548d1843c80ad000"
}

rule MalwareBazaar_MacSync_050_593c2d77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "593c2d77f1bf98f5beff03fc094b950e4e4d1c8a306397a7db1f18bda9b5c695"
    family = "MacSync"
    file_name = "macsync.applescript"
    file_type = "applescript"
    first_seen = "2026-07-14 18:56:09"
  condition:
    hash.sha256(0, filesize) == "593c2d77f1bf98f5beff03fc094b950e4e4d1c8a306397a7db1f18bda9b5c695"
}

rule MalwareBazaar_Mirai_051_b7a97391
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7a973918dc83e4fda18643592e3c660b0bc64add0ce9d7ffd6e7e04ccba0967"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-14 18:53:37"
  condition:
    hash.sha256(0, filesize) == "b7a973918dc83e4fda18643592e3c660b0bc64add0ce9d7ffd6e7e04ccba0967"
}

rule MalwareBazaar_Efimer_052_dcb9772a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcb9772a15cc16d9bed50c4be2724b30629f6c2437239a99327445840dda4185"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 18:52:06"
  condition:
    hash.sha256(0, filesize) == "dcb9772a15cc16d9bed50c4be2724b30629f6c2437239a99327445840dda4185"
}

rule MalwareBazaar_Mirai_053_8dcbddb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8dcbddb7a3b55ed63e56eb6d166879071683b6bbc6eeb03740dad94fed880ed0"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-14 18:49:46"
  condition:
    hash.sha256(0, filesize) == "8dcbddb7a3b55ed63e56eb6d166879071683b6bbc6eeb03740dad94fed880ed0"
}

rule MalwareBazaar_Mirai_054_a56d15cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a56d15cde8dae3826dada7044ba5e8bac63cc473fe1de9efc0faee7099967114"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-14 18:47:38"
  condition:
    hash.sha256(0, filesize) == "a56d15cde8dae3826dada7044ba5e8bac63cc473fe1de9efc0faee7099967114"
}

rule MalwareBazaar_unknown_055_cb60c05a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb60c05a179fc2f196486101d1c49be82cb4f6f1771212b02f21b97cfaa0331c"
    family = "unknown"
    file_name = "cb60c05a179fc2f196486101d1c49be82cb4f6f1771212b02f21b97cfaa0331c"
    file_type = "xlsx"
    first_seen = "2026-07-14 18:44:02"
  condition:
    hash.sha256(0, filesize) == "cb60c05a179fc2f196486101d1c49be82cb4f6f1771212b02f21b97cfaa0331c"
}

rule MalwareBazaar_unknown_056_81ef05cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81ef05cc4d07cd22cd7cd7099f278dd9b9a3ae8ad4770b3d387892e1c6cfb7d7"
    family = "unknown"
    file_name = "81ef05cc4d07cd22cd7cd7099f278dd9b9a3ae8ad4770b3d387892e1c6cfb7d7"
    file_type = "macho"
    first_seen = "2026-07-14 18:35:22"
  condition:
    hash.sha256(0, filesize) == "81ef05cc4d07cd22cd7cd7099f278dd9b9a3ae8ad4770b3d387892e1c6cfb7d7"
}

rule MalwareBazaar_Mirai_057_eefd5fe0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eefd5fe077a3033d4c16c887c6894a92fdcffbb050aa97da5196702a424e2835"
    family = "Mirai"
    file_name = "bot_x86_64"
    file_type = "elf"
    first_seen = "2026-07-14 18:12:44"
  condition:
    hash.sha256(0, filesize) == "eefd5fe077a3033d4c16c887c6894a92fdcffbb050aa97da5196702a424e2835"
}

rule MalwareBazaar_unknown_058_0a5118fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a5118fea6cffe6fd7d694ca014fd728763922ecd675c949e5c9218dc1540386"
    family = "unknown"
    file_name = "PURCHASE RDER_NOPWQ2026.JS"
    file_type = "js"
    first_seen = "2026-07-14 18:05:51"
  condition:
    hash.sha256(0, filesize) == "0a5118fea6cffe6fd7d694ca014fd728763922ecd675c949e5c9218dc1540386"
}

rule MalwareBazaar_Mirai_059_1bd9e446
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bd9e446a11bf2dca961562ed807476067ea4ade0fa068c97b58173e651060f3"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-14 17:58:47"
  condition:
    hash.sha256(0, filesize) == "1bd9e446a11bf2dca961562ed807476067ea4ade0fa068c97b58173e651060f3"
}

rule MalwareBazaar_Mirai_060_31fa1cdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31fa1cdc0530f8105b7f69e2b408fc5971dcdff3815ee6ab7bfbb7f756e0002e"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-14 17:58:45"
  condition:
    hash.sha256(0, filesize) == "31fa1cdc0530f8105b7f69e2b408fc5971dcdff3815ee6ab7bfbb7f756e0002e"
}

rule MalwareBazaar_Mirai_061_5df3574a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5df3574a5aacfd5eb8cabbef5a9153d7dffc854289639acffd1ed0f21bbf887a"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-14 17:58:44"
  condition:
    hash.sha256(0, filesize) == "5df3574a5aacfd5eb8cabbef5a9153d7dffc854289639acffd1ed0f21bbf887a"
}

rule MalwareBazaar_unknown_062_a3861ca7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3861ca7da0494b1ffa4dfb0d940d1c27a34a38481f861a55ec1cd4cd97ef9b2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-14 17:58:43"
  condition:
    hash.sha256(0, filesize) == "a3861ca7da0494b1ffa4dfb0d940d1c27a34a38481f861a55ec1cd4cd97ef9b2"
}

rule MalwareBazaar_Efimer_063_55aac3a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55aac3a0ab90b91703fa5b60f8b60f25c94993c8d1ab380298ebf6e1db2dff44"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 17:52:08"
  condition:
    hash.sha256(0, filesize) == "55aac3a0ab90b91703fa5b60f8b60f25c94993c8d1ab380298ebf6e1db2dff44"
}

rule MalwareBazaar_Mirai_064_12d53875
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12d5387555e9e98571857a89b40cc370dbba56094c317ee6cf4f2e450153a4b5"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-14 17:42:45"
  condition:
    hash.sha256(0, filesize) == "12d5387555e9e98571857a89b40cc370dbba56094c317ee6cf4f2e450153a4b5"
}

rule MalwareBazaar_unknown_065_dd131bee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd131beed1da6ccee24174b28153ff11d65f69be9c7dd92eb2efe683b017ff3e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-14 17:40:42"
  condition:
    hash.sha256(0, filesize) == "dd131beed1da6ccee24174b28153ff11d65f69be9c7dd92eb2efe683b017ff3e"
}

rule MalwareBazaar_unknown_066_e9c85fed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9c85fed4f8cd17535a62b2cd2832c3ca0e652df1c4914e96fb00f0eb1af710b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-14 17:36:46"
  condition:
    hash.sha256(0, filesize) == "e9c85fed4f8cd17535a62b2cd2832c3ca0e652df1c4914e96fb00f0eb1af710b"
}

rule MalwareBazaar_unknown_067_8db515e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8db515e787086c6338598c862601d6643c898af8407452679009ab51960eb299"
    family = "unknown"
    file_name = "SecuriteInfo.com.FileRepMalware.63522757"
    file_type = "exe"
    first_seen = "2026-07-14 17:30:55"
  condition:
    hash.sha256(0, filesize) == "8db515e787086c6338598c862601d6643c898af8407452679009ab51960eb299"
}

rule MalwareBazaar_WannaCry_068_3846e513
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3846e513d6a32765431ef270ccf8ad44f7627d278a2dd1e70855b21aaa6b632a"
    family = "WannaCry"
    file_name = "3846e513d6a32765431ef270ccf8ad44f7627d278a2dd1e70855b21aaa6b632a"
    file_type = "exe"
    first_seen = "2026-07-14 17:15:19"
  condition:
    hash.sha256(0, filesize) == "3846e513d6a32765431ef270ccf8ad44f7627d278a2dd1e70855b21aaa6b632a"
}

rule MalwareBazaar_Efimer_069_7d2b009f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d2b009f6ec2a02836b984cadf294569a5d7095d9ee496118d408da37f0a269c"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 16:52:08"
  condition:
    hash.sha256(0, filesize) == "7d2b009f6ec2a02836b984cadf294569a5d7095d9ee496118d408da37f0a269c"
}

rule MalwareBazaar_Mirai_070_086446ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "086446ea42d2dddc6548112b88aa59fcea0eab0849340ee101902e4fbf55f718"
    family = "Mirai"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-07-14 16:47:26"
  condition:
    hash.sha256(0, filesize) == "086446ea42d2dddc6548112b88aa59fcea0eab0849340ee101902e4fbf55f718"
}

rule MalwareBazaar_Gafgyt_071_c0111291
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0111291f4dfeba09099cfcbd07930830cb13360365404152b18fc85d77e1ac7"
    family = "Gafgyt"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-14 16:47:00"
  condition:
    hash.sha256(0, filesize) == "c0111291f4dfeba09099cfcbd07930830cb13360365404152b18fc85d77e1ac7"
}

rule MalwareBazaar_ConnectWise_072_e5ce2590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5ce25903af4383079e1378ab0a1b07275631aedcfe4e41df96c2431d598aebb"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:43:07"
  condition:
    hash.sha256(0, filesize) == "e5ce25903af4383079e1378ab0a1b07275631aedcfe4e41df96c2431d598aebb"
}

rule MalwareBazaar_unknown_073_cf3dced5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf3dced525f0a3dd0e4047ef0669837671e655614441ed582084de9a03fd2615"
    family = "unknown"
    file_name = "dab.ps1"
    file_type = "ps1"
    first_seen = "2026-07-14 16:36:02"
  condition:
    hash.sha256(0, filesize) == "cf3dced525f0a3dd0e4047ef0669837671e655614441ed582084de9a03fd2615"
}

rule MalwareBazaar_unknown_074_5607a941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5607a94195a263ef620cebbc3c4e64930d631f0582d0452131c694556e623e50"
    family = "unknown"
    file_name = "dab.ps1"
    file_type = "ps1"
    first_seen = "2026-07-14 16:35:58"
  condition:
    hash.sha256(0, filesize) == "5607a94195a263ef620cebbc3c4e64930d631f0582d0452131c694556e623e50"
}

rule MalwareBazaar_ConnectWise_075_732dfed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "732dfed9c6d0fbdfd29addfb4d3981dd4f50bbb1417bd397ad42787a21b7558a"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:57"
  condition:
    hash.sha256(0, filesize) == "732dfed9c6d0fbdfd29addfb4d3981dd4f50bbb1417bd397ad42787a21b7558a"
}

rule MalwareBazaar_ConnectWise_076_eb4ca3c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb4ca3c1757eb36faa00200c5ce0345a396724c195b33f36563d452d4abcddd7"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:57"
  condition:
    hash.sha256(0, filesize) == "eb4ca3c1757eb36faa00200c5ce0345a396724c195b33f36563d452d4abcddd7"
}

rule MalwareBazaar_ConnectWise_077_c361c144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c361c144166d68555ebee186ba47d4421e6ab4c3330739e1ca3e57f38a438832"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:44"
  condition:
    hash.sha256(0, filesize) == "c361c144166d68555ebee186ba47d4421e6ab4c3330739e1ca3e57f38a438832"
}

rule MalwareBazaar_ConnectWise_078_97219eed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97219eed1eda6a12d672138da9c9c540e95be415d227fd81c6933eb1b81f7160"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:42"
  condition:
    hash.sha256(0, filesize) == "97219eed1eda6a12d672138da9c9c540e95be415d227fd81c6933eb1b81f7160"
}

rule MalwareBazaar_ConnectWise_079_d92594e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d92594e95e83004ab04ac3eb9fa30d1f9079d13b9df210714d24c82c398e31d2"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:41"
  condition:
    hash.sha256(0, filesize) == "d92594e95e83004ab04ac3eb9fa30d1f9079d13b9df210714d24c82c398e31d2"
}

rule MalwareBazaar_ConnectWise_080_1c581a5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c581a5bcc6a4fb4ecb9d6151c9c88adfe678d3771fdd1accf9820152064f0c2"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:38"
  condition:
    hash.sha256(0, filesize) == "1c581a5bcc6a4fb4ecb9d6151c9c88adfe678d3771fdd1accf9820152064f0c2"
}

rule MalwareBazaar_ConnectWise_081_44b6d6bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44b6d6bbd97152d4e7cd25ed49bde0f8a1c5d30c241d99c4a34f66cec3f28e2f"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:37"
  condition:
    hash.sha256(0, filesize) == "44b6d6bbd97152d4e7cd25ed49bde0f8a1c5d30c241d99c4a34f66cec3f28e2f"
}

rule MalwareBazaar_ConnectWise_082_783d41b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "783d41b84f4de36b14e48e2c3f18f5ede44e97348e03cfc9396f77f42fdf0689"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:35"
  condition:
    hash.sha256(0, filesize) == "783d41b84f4de36b14e48e2c3f18f5ede44e97348e03cfc9396f77f42fdf0689"
}

rule MalwareBazaar_ConnectWise_083_6f2139d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f2139d68bc0222b441fadeb6f484650ee7192aceea86c5399749b279898abd0"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:34"
  condition:
    hash.sha256(0, filesize) == "6f2139d68bc0222b441fadeb6f484650ee7192aceea86c5399749b279898abd0"
}

rule MalwareBazaar_ConnectWise_084_2b5f7211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b5f7211a6c98dc9302023024cf7e11e5360314160a6b291f74350eeb46c072d"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:32"
  condition:
    hash.sha256(0, filesize) == "2b5f7211a6c98dc9302023024cf7e11e5360314160a6b291f74350eeb46c072d"
}

rule MalwareBazaar_ConnectWise_085_0b3a0e6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b3a0e6bf514f9baecd9f26cdbeb74afc455666d0d41db4b8673f7a98cd855cf"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:30"
  condition:
    hash.sha256(0, filesize) == "0b3a0e6bf514f9baecd9f26cdbeb74afc455666d0d41db4b8673f7a98cd855cf"
}

rule MalwareBazaar_ConnectWise_086_cd68d01f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd68d01fe8e57890fcbbe66833a8416981feda4d79148a661692fa364db66738"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:30"
  condition:
    hash.sha256(0, filesize) == "cd68d01fe8e57890fcbbe66833a8416981feda4d79148a661692fa364db66738"
}

rule MalwareBazaar_ConnectWise_087_24cf9f32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24cf9f32c1e3ebec5e810a865ad4acdcd28669d4b548929c8e4a962d77e44b1b"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:29:25"
  condition:
    hash.sha256(0, filesize) == "24cf9f32c1e3ebec5e810a865ad4acdcd28669d4b548929c8e4a962d77e44b1b"
}

rule MalwareBazaar_unknown_088_4a3d1b9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a3d1b9df22e50a9556d7161dc36800eb37833eca26057036d34e5be27f4df6d"
    family = "unknown"
    file_name = "SecuriteInfo.com.FileRepMalware.11498445"
    file_type = "exe"
    first_seen = "2026-07-14 16:25:51"
  condition:
    hash.sha256(0, filesize) == "4a3d1b9df22e50a9556d7161dc36800eb37833eca26057036d34e5be27f4df6d"
}

rule MalwareBazaar_unknown_089_8e6d648d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e6d648dd5b03d2d56ccc1a08908ecdfdd1dbbfac5c9d8d399d9a0e5d9227579"
    family = "unknown"
    file_name = "Demanda_Civil_Reparacion_Da±o_Patrimonial_NUM80005.js"
    file_type = "js"
    first_seen = "2026-07-14 16:16:07"
  condition:
    hash.sha256(0, filesize) == "8e6d648dd5b03d2d56ccc1a08908ecdfdd1dbbfac5c9d8d399d9a0e5d9227579"
}

rule MalwareBazaar_WannaCry_090_28f28077
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28f28077680c530e9d4278cecf0d8a9ac0682ed63bf9ee1d6a90cd18b88e67fa"
    family = "WannaCry"
    file_name = "28f28077680c530e9d4278cecf0d8a9ac0682ed63bf9ee1d6a90cd18b88e67fa"
    file_type = "exe"
    first_seen = "2026-07-14 16:15:15"
  condition:
    hash.sha256(0, filesize) == "28f28077680c530e9d4278cecf0d8a9ac0682ed63bf9ee1d6a90cd18b88e67fa"
}

rule MalwareBazaar_Mirai_091_4ec5a94f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ec5a94f92dea1d81599c4792c902075ffc2e2afe94e80bb48f40094080c34e2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-14 16:12:43"
  condition:
    hash.sha256(0, filesize) == "4ec5a94f92dea1d81599c4792c902075ffc2e2afe94e80bb48f40094080c34e2"
}

rule MalwareBazaar_unknown_092_9959cf5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9959cf5abc2b92440926e0acc7365125ddd143e30b0c855ae006fd83d01e395b"
    family = "unknown"
    file_name = "East Coast Signs  Graphics PROJECT.pdf"
    file_type = "pdf"
    first_seen = "2026-07-14 16:03:20"
  condition:
    hash.sha256(0, filesize) == "9959cf5abc2b92440926e0acc7365125ddd143e30b0c855ae006fd83d01e395b"
}

rule MalwareBazaar_Mirai_093_3700e44b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3700e44be4e674477ca36b3dc4012608afcebf7917ca68eeff6b8782694fd768"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-14 16:02:49"
  condition:
    hash.sha256(0, filesize) == "3700e44be4e674477ca36b3dc4012608afcebf7917ca68eeff6b8782694fd768"
}

rule MalwareBazaar_ConnectWise_094_daca7dff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daca7dff705d30c7f81ae424b54ee528e5559d7d4160eed7ffd357e294bf411e"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:02:35"
  condition:
    hash.sha256(0, filesize) == "daca7dff705d30c7f81ae424b54ee528e5559d7d4160eed7ffd357e294bf411e"
}

rule MalwareBazaar_ConnectWise_095_8fe09be2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fe09be2bb21339f8b9ab4f3f30a9bcb4f6e167410ef3449f9659b3fb6f1cd10"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:02:31"
  condition:
    hash.sha256(0, filesize) == "8fe09be2bb21339f8b9ab4f3f30a9bcb4f6e167410ef3449f9659b3fb6f1cd10"
}

rule MalwareBazaar_unknown_096_393e5aed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "393e5aed4cef384221a6f662b7ee9910e2dc299add5d38bb315fa2748f1d7387"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-14 16:01:10"
  condition:
    hash.sha256(0, filesize) == "393e5aed4cef384221a6f662b7ee9910e2dc299add5d38bb315fa2748f1d7387"
}

rule MalwareBazaar_unknown_097_d44dafd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d44dafd48ec502e2512076ad1d66209059511292413123f87965011d5d96262e"
    family = "unknown"
    file_name = "interface.scpt"
    file_type = "scpt"
    first_seen = "2026-07-14 15:57:20"
  condition:
    hash.sha256(0, filesize) == "d44dafd48ec502e2512076ad1d66209059511292413123f87965011d5d96262e"
}

rule MalwareBazaar_Efimer_098_6e7516a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e7516a816c34eb1f9e2b1399ead4ed9a64e2132ecbb9c5e86bd249ae9fe304a"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 15:52:09"
  condition:
    hash.sha256(0, filesize) == "6e7516a816c34eb1f9e2b1399ead4ed9a64e2132ecbb9c5e86bd249ae9fe304a"
}

rule MalwareBazaar_NWHStealer_099_94b21f48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94b21f488f5fecc9aa5ec4a4188e7d14049d0b9e0d3d64027a450640bfbd706d"
    family = "NWHStealer"
    file_name = "app.exe"
    file_type = "exe"
    first_seen = "2026-07-14 15:48:08"
  condition:
    hash.sha256(0, filesize) == "94b21f488f5fecc9aa5ec4a4188e7d14049d0b9e0d3d64027a450640bfbd706d"
}

rule MalwareBazaar_LxBaseRAT_100_0bef1f58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bef1f58295a8d704c4f0ab7d3f8a3c6b9af49ed2cb28066327754080e202b26"
    family = "LxBaseRAT"
    file_name = "Quotation Request – Purchase Order.Malaysia-Airports..js"
    file_type = "js"
    first_seen = "2026-07-14 15:41:31"
  condition:
    hash.sha256(0, filesize) == "0bef1f58295a8d704c4f0ab7d3f8a3c6b9af49ed2cb28066327754080e202b26"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

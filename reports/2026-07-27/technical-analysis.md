# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-27

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 672 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 672 |
| Unique family labels | 8 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 52 |
| RemusStealer | 30 |
| Mirai | 10 |
| LummaStealer | 4 |
| AsyncRAT | 1 |
| RemcosRAT | 1 |
| Stealc | 1 |
| ValleyRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 65 |
| sh | 13 |
| elf | 12 |
| unknown | 3 |
| zip | 2 |
| vbs | 1 |
| py | 1 |
| js | 1 |
| dmg | 1 |
| rar | 1 |

## Per-Sample Analysis

### Sample 1: `8230ecb782d68b44`

| Field | Value |
|---|---|
| SHA-256 | `8230ecb782d68b44a91d1dab3b65f98324e653efc0c8529c4e81cb762cc8e179` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-27 03:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b40c04705635d82de166087f3ff19874` |
| SHA-1 | `99bb423901e51d8e4a36a45d6a798a232eab7838` |
| SHA-256 | `8230ecb782d68b44a91d1dab3b65f98324e653efc0c8529c4e81cb762cc8e179` |
| SHA3-384 | `1562f51e08ee1ea5fb6e7a0aea718054611b34623b0c9e59176b52e98fa33b9b1aecce1941d2402ec9995715ddc80eee` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T14BE63364B9C012BDD5A3C13CEAE153D6D8A5B4B64B72C98B477883F16D2B1901C3EE27` |
| SSDEEP | `393216:YEUlVtrifHCSUSG/azvJx+KrasoXMCHWUjX9cuI3/PGTAI:YPmUFyzvT+KroXMb8XKH/O7` |
| ICON-DHASH | `71f0d8d8e8e8f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_8230ecb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8230ecb782d68b44a91d1dab3b65f98324e653efc0c8529c4e81cb762cc8e179"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 03:52:32"
  condition:
    hash.sha256(0, filesize) == "8230ecb782d68b44a91d1dab3b65f98324e653efc0c8529c4e81cb762cc8e179"
}
```

### Sample 2: `b9605d53a902f608`

| Field | Value |
|---|---|
| SHA-256 | `b9605d53a902f60867aca67f42ac7a53222edd2463c3936c5c3c9e75a457a7dc` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-27 03:49:55` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48a25b304eb3713989cb9dc976618cad` |
| SHA-1 | `9d86e201c18c09c36a208c4f1a35ed98a66760c5` |
| SHA-256 | `b9605d53a902f60867aca67f42ac7a53222edd2463c3936c5c3c9e75a457a7dc` |
| SHA3-384 | `9b58dfe76de15c95c6b40b6aef9e856f1401efb0fc11332e11e3f4365cf499b6602c1addaf1e7b6ba3543513418be9d4` |
| TLSH | `T1D6C28D966A967C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACC618B1A` |
| SSDEEP | `768:d8vCB+25j6es8RY9FYpMSUpi+20qUpi+20YQX:d8l25Jud2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_b9605d53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9605d53a902f60867aca67f42ac7a53222edd2463c3936c5c3c9e75a457a7dc"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-27 03:49:55"
  condition:
    hash.sha256(0, filesize) == "b9605d53a902f60867aca67f42ac7a53222edd2463c3936c5c3c9e75a457a7dc"
}
```

### Sample 3: `85a229fa75bcf5ef`

| Field | Value |
|---|---|
| SHA-256 | `85a229fa75bcf5ef41066bb0618ade943cba3b72c377fee22bc2ff94dfaf4160` |
| Family label | `AsyncRAT` |
| File name | `F8BETAPP.exe` |
| File type | `exe` |
| First seen | `2026-07-27 03:18:58` |
| Reporter | `anonymous` |
| Tags | `AsyncRAT, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9b9e94e807a98caa367cf2b4b995eeb` |
| SHA-1 | `ac38d4936c5bdf74c2ecdd3d6da8adc35db12b6b` |
| SHA-256 | `85a229fa75bcf5ef41066bb0618ade943cba3b72c377fee22bc2ff94dfaf4160` |
| SHA3-384 | `83fbc9febcf2f1bc1cb71d3d80644d9269572200ee09adbe8190968054006971b2e331f7f6b0785961390e31ff8d93a3` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D1C22A0833E4C671D2FD4ABA8C33D5009B75E95B9913D75A6FC890AD29237CD8A14FE4` |
| SSDEEP | `384:5Tdv2D9YfxWcvHtZARPn9j/H9qbuUsMbQxnCJfJBndnjJXKyl:1dvhDt+LIbIBiBnGS` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_003_85a229fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85a229fa75bcf5ef41066bb0618ade943cba3b72c377fee22bc2ff94dfaf4160"
    family = "AsyncRAT"
    file_name = "F8BETAPP.exe"
    file_type = "exe"
    first_seen = "2026-07-27 03:18:58"
  condition:
    hash.sha256(0, filesize) == "85a229fa75bcf5ef41066bb0618ade943cba3b72c377fee22bc2ff94dfaf4160"
}
```

### Sample 4: `00ec97c78c9c4fc2`

| Field | Value |
|---|---|
| SHA-256 | `00ec97c78c9c4fc27f8beda4ffe27d4f4cb98b0208e13b7a1652d6c1e120cd76` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-27 02:52:33` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b25fd6814be7f03c56bfb669d8587844` |
| SHA-1 | `27f9857ee08246eacb56c194989071ec5213c704` |
| SHA-256 | `00ec97c78c9c4fc27f8beda4ffe27d4f4cb98b0208e13b7a1652d6c1e120cd76` |
| SHA3-384 | `d4ae0e9fceb1b7654c0b015f18325f85091ffb36a8bae7fa47b51917139544e470acae348932a4a02cf3d565201f86c1` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T18BE63318A2D012EEE5F34239DD51B9D6A591B8361B7BC98B4BB443A25F831E0CD3D336` |
| SSDEEP | `393216:flsqU3uO/jL2yKlthvC1n1mgXMCHWUjXycuI3/PGTAI:flsb9z8tZcnYgXMb8XPH/O7` |
| ICON-DHASH | `71f0e4d4e6e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_00ec97c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00ec97c78c9c4fc27f8beda4ffe27d4f4cb98b0208e13b7a1652d6c1e120cd76"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 02:52:33"
  condition:
    hash.sha256(0, filesize) == "00ec97c78c9c4fc27f8beda4ffe27d4f4cb98b0208e13b7a1652d6c1e120cd76"
}
```

### Sample 5: `e594838ef765312d`

| Field | Value |
|---|---|
| SHA-256 | `e594838ef765312d60475677ec54bf23a4fad659aad928f4564d49890ee9c23b` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-27 01:52:34` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e63172525926f847841634253c9534ac` |
| SHA-1 | `e34584001e81b6d185beac42b2b48726d8790207` |
| SHA-256 | `e594838ef765312d60475677ec54bf23a4fad659aad928f4564d49890ee9c23b` |
| SHA3-384 | `208dfbce37a18149b37bef1606f01f74e46e8d3d18d54b918982a18cebceadfa45e6a8401b3c6f45adbbfa9413a95976` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T12FE6330CA1C502EDEA73423DFAD115A1D1E9B4714736CADB47A8A7E12E332A1893DF53` |
| SSDEEP | `393216:THWnvb0GsvF8qwjw+gXMCHWUjXccuI3/PGTAI:TU0LClpgXMb8XJH/O7` |
| ICON-DHASH | `e8e865e0d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_e594838e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e594838ef765312d60475677ec54bf23a4fad659aad928f4564d49890ee9c23b"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 01:52:34"
  condition:
    hash.sha256(0, filesize) == "e594838ef765312d60475677ec54bf23a4fad659aad928f4564d49890ee9c23b"
}
```

### Sample 6: `56f8e042eeb5e755`

| Field | Value |
|---|---|
| SHA-256 | `56f8e042eeb5e75508be62a8add15ea8552b08fde09a112cc7acfc67d49fe7c3` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-27 01:41:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0df3e348d3cdbe261bad3914aab84797` |
| SHA-1 | `93381ddfd28c8ee0f38fd3a363999b38a589b790` |
| SHA-256 | `56f8e042eeb5e75508be62a8add15ea8552b08fde09a112cc7acfc67d49fe7c3` |
| SHA3-384 | `0d30ab3cc0c06bb0fefc9261c9ad52e5eef82c01f8717f547ef07b2dc686abe1b7551eb81bee3340e6ecdfb4fd030fce` |
| TLSH | `T1DE236C661A857C14AA98C4371D7E2F0CBDAD43E6320492DE7FCB3CF28C5AA9D910971D` |
| SSDEEP | `768:4XRWNGxVQ9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:slxfcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_56f8e042
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56f8e042eeb5e75508be62a8add15ea8552b08fde09a112cc7acfc67d49fe7c3"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-27 01:41:54"
  condition:
    hash.sha256(0, filesize) == "56f8e042eeb5e75508be62a8add15ea8552b08fde09a112cc7acfc67d49fe7c3"
}
```

### Sample 7: `c67e82aed910bc47`

| Field | Value |
|---|---|
| SHA-256 | `c67e82aed910bc4706a7da1675284bfa90f5c9371d596f541a575fdcc02e36f7` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-27 01:39:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56ff9604be4436c616b152b068f95983` |
| SHA-1 | `b93bbfdfea4f556420b999c242b09e2ec83b494a` |
| SHA-256 | `c67e82aed910bc4706a7da1675284bfa90f5c9371d596f541a575fdcc02e36f7` |
| SHA3-384 | `2da1ba9a6d05566f8114c0254f098c7c382b9871a0d0bc394343978c6cdb3d16ad5037be7dd62cdd750ae43c2133cef9` |
| TLSH | `T138235C6516857C24AA98C4361C7E2F0CB9AD43E6324452EE7FCF3CF68C4A69D910971D` |
| SSDEEP | `768:+i+j9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:5+kcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_c67e82ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c67e82aed910bc4706a7da1675284bfa90f5c9371d596f541a575fdcc02e36f7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-27 01:39:54"
  condition:
    hash.sha256(0, filesize) == "c67e82aed910bc4706a7da1675284bfa90f5c9371d596f541a575fdcc02e36f7"
}
```

### Sample 8: `268b8fdf9834f2c6`

| Field | Value |
|---|---|
| SHA-256 | `268b8fdf9834f2c6ad8149b2aa56fad90403c91964ed813609a92b7454ecf34f` |
| Family label | `RemcosRAT` |
| File name | `QU20262707.vbs` |
| File type | `vbs` |
| First seen | `2026-07-27 01:26:02` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b5a4db33036eaaa61bef098f0ef0541` |
| SHA-1 | `efe58ef1e0e9dc744a701b51a70199b156dfbd12` |
| SHA-256 | `268b8fdf9834f2c6ad8149b2aa56fad90403c91964ed813609a92b7454ecf34f` |
| SHA3-384 | `d293bec46c4687db7c3da1bbd3717768bb402a0da786fbc7dea27bac07144f614319b681b7158df5fe0a3fc1d4c9bf96` |
| TLSH | `T1AD442820DCD40B3A0E57079DFF514A65C9FDC529863790ECEA9E072E50125ACEBBF268` |
| SSDEEP | `6144:Fuptv2hXayOPIW5S0WvNpX52hWD/pLhkRmCKYRTd:i7yOPIWwh1p8SwYYr` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_008_268b8fdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "268b8fdf9834f2c6ad8149b2aa56fad90403c91964ed813609a92b7454ecf34f"
    family = "RemcosRAT"
    file_name = "QU20262707.vbs"
    file_type = "vbs"
    first_seen = "2026-07-27 01:26:02"
  condition:
    hash.sha256(0, filesize) == "268b8fdf9834f2c6ad8149b2aa56fad90403c91964ed813609a92b7454ecf34f"
}
```

### Sample 9: `f29c23e3ce0a393d`

| Field | Value |
|---|---|
| SHA-256 | `f29c23e3ce0a393d9cd5927b4873e8b9a4a8800e4a1270abfd8f279ae4041729` |
| Family label | `unknown` |
| File name | `nz.sh` |
| File type | `sh` |
| First seen | `2026-07-27 01:09:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f824e050493f0ada9253977d59769ec` |
| SHA-1 | `cce6d8b57236e0ea6f3dc047f28b63e666f07ca6` |
| SHA-256 | `f29c23e3ce0a393d9cd5927b4873e8b9a4a8800e4a1270abfd8f279ae4041729` |
| SHA3-384 | `44efc4d2379acd94c0a335254d75703fee1102805912d548b659aebd1f5e6735894f26d8af0b81fe060f70d5e5d573a4` |
| TLSH | `T1F61104C6100243341FD2E923FABA8C1930AAA5D654D79F1965D9B8F188CDD0D3955AC7` |
| SSDEEP | `12:JCkp0F5AM7AtX0F5AZPx7AZPIhOf0F5AB7ADVZX0F5A97AtNX0F5AzQ8i7AzQ8GY:ItGPtsGd6dIhOEGKDPsG2sGzTRzTGFC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_f29c23e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f29c23e3ce0a393d9cd5927b4873e8b9a4a8800e4a1270abfd8f279ae4041729"
    family = "unknown"
    file_name = "nz.sh"
    file_type = "sh"
    first_seen = "2026-07-27 01:09:54"
  condition:
    hash.sha256(0, filesize) == "f29c23e3ce0a393d9cd5927b4873e8b9a4a8800e4a1270abfd8f279ae4041729"
}
```

### Sample 10: `51403e760e00cb8a`

| Field | Value |
|---|---|
| SHA-256 | `51403e760e00cb8ad725cc3404154a324c604204f061e285c513d03011f1ac2e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-27 01:07:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d81cf06defd1e349fbe3ae41e8b2dc60` |
| SHA-1 | `b7229367139c5e40080f3e71a687b82c7fbdabe8` |
| SHA-256 | `51403e760e00cb8ad725cc3404154a324c604204f061e285c513d03011f1ac2e` |
| SHA3-384 | `33dafe0686bd7f68843df16b8ea8e3d739f3e956e46e6c01d5f1ad505158ceed2ae5d98cdead441d7f51686aaff8f667` |
| TLSH | `T19BC26C966A867C44BDC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:g8vCB+25j6es8Rf9FYpMSUpi+20qUpi+20YQX:g8l25Jpd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_51403e76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51403e760e00cb8ad725cc3404154a324c604204f061e285c513d03011f1ac2e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-27 01:07:58"
  condition:
    hash.sha256(0, filesize) == "51403e760e00cb8ad725cc3404154a324c604204f061e285c513d03011f1ac2e"
}
```

### Sample 11: `c29fb2bdcaefee96`

| Field | Value |
|---|---|
| SHA-256 | `c29fb2bdcaefee9681b1b7ab1f85e610c9218918a11591bb63f553ccd6f5077a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-27 00:52:28` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b229cd58d97751c907b89d5d5612b18` |
| SHA-1 | `914b3d26eda8d3de8c302f2479973ad87e7f6760` |
| SHA-256 | `c29fb2bdcaefee9681b1b7ab1f85e610c9218918a11591bb63f553ccd6f5077a` |
| SHA3-384 | `cf9e36629e0c28cb74368ef1427a58027a0b7b5af58bd6ec564b423c851b9be74523b747cd5426cc66a4b1feab9506a1` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1E4E6331834D012EEE493023DE9E1566AE4F974731733CE9F0BA457617E872918E3EA27` |
| SSDEEP | `393216:kf48iQvA8w5VopGfa80CBkZkRxXMCHWUjXzcuI3/PGTAI:kfzvgopGf3xXMb8XwH/O7` |
| ICON-DHASH | `b270e8cccce8f1b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_c29fb2bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c29fb2bdcaefee9681b1b7ab1f85e610c9218918a11591bb63f553ccd6f5077a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 00:52:28"
  condition:
    hash.sha256(0, filesize) == "c29fb2bdcaefee9681b1b7ab1f85e610c9218918a11591bb63f553ccd6f5077a"
}
```

### Sample 12: `84742f0748a01c59`

| Field | Value |
|---|---|
| SHA-256 | `84742f0748a01c59931925dd2e1da61624c78fd115aad38a6acd1b48ee9d0fd1` |
| Family label | `unknown` |
| File name | `HeartProblemsFanGame.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:50:20` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca97388c5734eb30b7ebcb0804da0577` |
| SHA-1 | `e9b0f1c855686f04ed6ce216a246d9e5af2d9642` |
| SHA-256 | `84742f0748a01c59931925dd2e1da61624c78fd115aad38a6acd1b48ee9d0fd1` |
| SHA3-384 | `20cc2e5af8a9685c49f3ef4105157c92875bffaa77a4e4916700817d5154aed0b91f795030922fb8b5ef24b5f2150664` |
| TLSH | `T11B28CF02A3E88599C0BFD139D57B550BE7F2BC695331D7CB1180597A2E73BE04A3A362` |
| SSDEEP | `1572864:z2Jzwbt/z+l1zAxJorsgdnen9qPsniUd:KJzwbtal1z0ysge9qUiUd` |
| ICON-DHASH | `39e8ccd4f0f8d4cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_84742f07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84742f0748a01c59931925dd2e1da61624c78fd115aad38a6acd1b48ee9d0fd1"
    family = "unknown"
    file_name = "HeartProblemsFanGame.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:50:20"
  condition:
    hash.sha256(0, filesize) == "84742f0748a01c59931925dd2e1da61624c78fd115aad38a6acd1b48ee9d0fd1"
}
```

### Sample 13: `7b092a35e70113f5`

| Field | Value |
|---|---|
| SHA-256 | `7b092a35e70113f5165a653135cb3a7ca29312ceb0b4a874c160473d30830a60` |
| Family label | `RemusStealer` |
| File name | `R2.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:40:55` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa928a93d7521a60e5ced8454d0120fd` |
| SHA-1 | `40d9de85f33decc66b4b9df6cbfea867c82887fc` |
| SHA-256 | `7b092a35e70113f5165a653135cb3a7ca29312ceb0b4a874c160473d30830a60` |
| SHA3-384 | `10bcb9ac5ac6a8e80f2a02e65a91a9f3b33ff87bde3b545ae4c7a7e143e3b7730701f2b4c9a5a8e8f6eccb0268ebaaa2` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T167B55A07BCE009E9C4AA937289B656917B71BC084F3263D72E90B7783F72AD09D35794` |
| SSDEEP | `24576:ZN2WgDCQqMQ6jeCHytr8j41mJo4AJU2Ba20LqJBele5r926CSo5ibJt:ZNtg6MfeLtrNgJorJU202PJgK` |
| ICON-DHASH | `d43379f0f07933d4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_013_7b092a35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b092a35e70113f5165a653135cb3a7ca29312ceb0b4a874c160473d30830a60"
    family = "RemusStealer"
    file_name = "R2.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:40:55"
  condition:
    hash.sha256(0, filesize) == "7b092a35e70113f5165a653135cb3a7ca29312ceb0b4a874c160473d30830a60"
}
```

### Sample 14: `bcd7660ccc0b839d`

| Field | Value |
|---|---|
| SHA-256 | `bcd7660ccc0b839dd001bce86a2ba33a6777e644be12fae5ddc3df87a767e76e` |
| Family label | `unknown` |
| File name | `pty10` |
| File type | `elf` |
| First seen | `2026-07-27 00:39:57` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2a1ba08d246a39483f9cde2c94c9efb` |
| SHA-1 | `06449f2bda9c2cc2c24cad58c09ae2a4a7094ca0` |
| SHA-256 | `bcd7660ccc0b839dd001bce86a2ba33a6777e644be12fae5ddc3df87a767e76e` |
| SHA3-384 | `18a72411087da4e3ebeb89f7443bfbdb35803adffa43a551b456d53d0a736b59b586f0d9cb5edbad996e29f1ef09e6e1` |
| TLSH | `T1A10533995BFF79828EA61C9D41E7DA0B07D62F9504FBCD0058E7028953D9133CA22FE5` |
| SSDEEP | `24576:VoG13EsScEPHXMWvDa1kt78govVlkTun78MzULIhn:Voe3EUEvNv7g/vVlwwJZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_bcd7660c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcd7660ccc0b839dd001bce86a2ba33a6777e644be12fae5ddc3df87a767e76e"
    family = "unknown"
    file_name = "pty10"
    file_type = "elf"
    first_seen = "2026-07-27 00:39:57"
  condition:
    hash.sha256(0, filesize) == "bcd7660ccc0b839dd001bce86a2ba33a6777e644be12fae5ddc3df87a767e76e"
}
```

### Sample 15: `14acb457792a4857`

| Field | Value |
|---|---|
| SHA-256 | `14acb457792a4857aa226eb7cc24bdbe8642adf896e3905a79d09e4dd9e9e511` |
| Family label | `unknown` |
| File name | `c.sh` |
| File type | `sh` |
| First seen | `2026-07-27 00:39:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64dd490fe20b776addc29f3e7eeb7ea7` |
| SHA-1 | `021ed91215b705aa2151e073ef78dbd6c2d6c04a` |
| SHA-256 | `14acb457792a4857aa226eb7cc24bdbe8642adf896e3905a79d09e4dd9e9e511` |
| SHA3-384 | `ba80b12ce7e2cb8ed2a534e54b00ae3543bc0f011bee36aaa71650bc27e16fda697132651d95d96b71d4d96468c606ed` |
| TLSH | `T15FE026CB001AB3404B889E04FC5A883E78AB82D130329618B202F4F4C9CD109383AFDF` |
| SSDEEP | `6:VSLA3JP8khELVBQLA3DQ8ksWQELLcBQLA3cxh9yLcMBQLA3dxhbQxIMBUA:VSLAZPfhE3QLAzQ8ksxgwQLAyhgLcAQJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_14acb457
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14acb457792a4857aa226eb7cc24bdbe8642adf896e3905a79d09e4dd9e9e511"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-27 00:39:56"
  condition:
    hash.sha256(0, filesize) == "14acb457792a4857aa226eb7cc24bdbe8642adf896e3905a79d09e4dd9e9e511"
}
```

### Sample 16: `35392a9849d7e9df`

| Field | Value |
|---|---|
| SHA-256 | `35392a9849d7e9dfb4ee700a16700a94883fde859d57fdd891631bdbc6a75db0` |
| Family label | `unknown` |
| File name | `crazy.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:38:17` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea2b5a00e49d3a09f38eadfda23df277` |
| SHA-1 | `b61cf8e65e87dc9b3aeb4087d26696a107230f8e` |
| SHA-256 | `35392a9849d7e9dfb4ee700a16700a94883fde859d57fdd891631bdbc6a75db0` |
| SHA3-384 | `c6945a8a47a105169988fe01ab7ad6adbcd394aa420037a3af9e8a7faa50f952ea231d2cc2b192de325dbc021cf7056d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C9B55A07BCE10DE9C4AA933289A655917B71BC084F3227D72E90B3782F72BD19D35B94` |
| SSDEEP | `24576:N4CW/BQLpamgRxdE0fQ5KtxK1oe1MMHUW7YkjLqJBele5r926CS75icYk:N4Z/+LjgRo04It81MM0wYJjZ` |
| ICON-DHASH | `d43379f0f07933d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_35392a98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35392a9849d7e9dfb4ee700a16700a94883fde859d57fdd891631bdbc6a75db0"
    family = "unknown"
    file_name = "crazy.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:38:17"
  condition:
    hash.sha256(0, filesize) == "35392a9849d7e9dfb4ee700a16700a94883fde859d57fdd891631bdbc6a75db0"
}
```

### Sample 17: `c431caed57d9d769`

| Field | Value |
|---|---|
| SHA-256 | `c431caed57d9d7699aa519790582595c96224c0f00bee914f8c4ee2252495e23` |
| Family label | `RemusStealer` |
| File name | `beb.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:37:38` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cf591c9fd2aed0286ffb519f12da683` |
| SHA-1 | `0ce231dba3b1911ca64b31ca8bce79fd1dc4c1b1` |
| SHA-256 | `c431caed57d9d7699aa519790582595c96224c0f00bee914f8c4ee2252495e23` |
| SHA3-384 | `51095550a6f94d05104f1228f3e85b5f15297330ca5a61f85cb3bc6fc3cd7d8b5146383df4c34cb4ffa923b2abe9e915` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T155B55A07BCE109E9C4AA937289A655917B71BC084F3223D72E90B7783F76BD08D35B94` |
| SSDEEP | `24576:acxN90g5jzFAijN9XqLa9KDFu1CEY6aWyPnSXfTLqJBele5r926CSckiM1:acv902jKijnqLaMD44EmPgIJp` |
| ICON-DHASH | `d43379f0f07933d4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_017_c431caed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c431caed57d9d7699aa519790582595c96224c0f00bee914f8c4ee2252495e23"
    family = "RemusStealer"
    file_name = "beb.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:37:38"
  condition:
    hash.sha256(0, filesize) == "c431caed57d9d7699aa519790582595c96224c0f00bee914f8c4ee2252495e23"
}
```

### Sample 18: `1bd26a5f04837e6b`

| Field | Value |
|---|---|
| SHA-256 | `1bd26a5f04837e6b58262c5cef3a2de052928414bc5bcc1106861c3792ab595c` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-27 00:21:55` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45fd1e3e792acf04754e6a8acd10a943` |
| SHA-1 | `fb3d80ffe54aeca1e6c44a3987416b3b87627179` |
| SHA-256 | `1bd26a5f04837e6b58262c5cef3a2de052928414bc5bcc1106861c3792ab595c` |
| SHA3-384 | `dd8f968c3a57999297f701f0408ac0f70e7515a3cdafe990a357dad2e9016c8ac8219bec3994f28ce68fe522ed27e0b4` |
| TLSH | `T1D8C27D966A867C44BDC94A3E4CBE2B1D6DF5C3D1324942AC3D8A3C719C11F9CD618B1A` |
| SSDEEP | `768:58vCB+25j6es8Rb9FYpMSUpi+20qUpi+20YQX:58l25Jtd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_1bd26a5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bd26a5f04837e6b58262c5cef3a2de052928414bc5bcc1106861c3792ab595c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-27 00:21:55"
  condition:
    hash.sha256(0, filesize) == "1bd26a5f04837e6b58262c5cef3a2de052928414bc5bcc1106861c3792ab595c"
}
```

### Sample 19: `4b7ff0262fe7d98c`

| Field | Value |
|---|---|
| SHA-256 | `4b7ff0262fe7d98cfd1c3ec38cb17d1aa7b66524be8fa2de0ce7a30a3d81fa38` |
| Family label | `unknown` |
| File name | `wp-static-cache-fa39743a.php` |
| File type | `unknown` |
| First seen | `2026-07-27 00:19:05` |
| Reporter | `iamaachum` |
| Tags | `backdoor, CVE-2026-60137, CVE-2026-63030, webshell, wordpress, wp2shell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2579f2830672b13fcabaff7564806f9` |
| SHA-256 | `4b7ff0262fe7d98cfd1c3ec38cb17d1aa7b66524be8fa2de0ce7a30a3d81fa38` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_4b7ff026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b7ff0262fe7d98cfd1c3ec38cb17d1aa7b66524be8fa2de0ce7a30a3d81fa38"
    family = "unknown"
    file_name = "wp-static-cache-fa39743a.php"
    file_type = "unknown"
    first_seen = "2026-07-27 00:19:05"
  condition:
    hash.sha256(0, filesize) == "4b7ff0262fe7d98cfd1c3ec38cb17d1aa7b66524be8fa2de0ce7a30a3d81fa38"
}
```

### Sample 20: `c4ea01549f1fe365`

| Field | Value |
|---|---|
| SHA-256 | `c4ea01549f1fe365652d0c9d839f54d8d8f42bf4182ad5389839908e8f2a5653` |
| Family label | `unknown` |
| File name | `wp-static-cache-c1adaafb.php` |
| File type | `unknown` |
| First seen | `2026-07-27 00:18:28` |
| Reporter | `iamaachum` |
| Tags | `backdoor, CVE-2026-60137, CVE-2026-63030, php, webshell, wordpress, wp2shell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85a36e73daf264f1a5542ac916a4c76e` |
| SHA-256 | `c4ea01549f1fe365652d0c9d839f54d8d8f42bf4182ad5389839908e8f2a5653` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_c4ea0154
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4ea01549f1fe365652d0c9d839f54d8d8f42bf4182ad5389839908e8f2a5653"
    family = "unknown"
    file_name = "wp-static-cache-c1adaafb.php"
    file_type = "unknown"
    first_seen = "2026-07-27 00:18:28"
  condition:
    hash.sha256(0, filesize) == "c4ea01549f1fe365652d0c9d839f54d8d8f42bf4182ad5389839908e8f2a5653"
}
```

### Sample 21: `de9efd031aef9cae`

| Field | Value |
|---|---|
| SHA-256 | `de9efd031aef9caed59021a2c79356d875648426a921151e18db33ce75aeacff` |
| Family label | `unknown` |
| File name | `wp-static-cache-7c197308.php` |
| File type | `unknown` |
| First seen | `2026-07-27 00:17:50` |
| Reporter | `iamaachum` |
| Tags | `backdoor, CVE-2026-60137, CVE-2026-63030, webshell, wordpress` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77619e60fa9c3a1e9d52b5e43003c523` |
| SHA-256 | `de9efd031aef9caed59021a2c79356d875648426a921151e18db33ce75aeacff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_de9efd03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de9efd031aef9caed59021a2c79356d875648426a921151e18db33ce75aeacff"
    family = "unknown"
    file_name = "wp-static-cache-7c197308.php"
    file_type = "unknown"
    first_seen = "2026-07-27 00:17:50"
  condition:
    hash.sha256(0, filesize) == "de9efd031aef9caed59021a2c79356d875648426a921151e18db33ce75aeacff"
}
```

### Sample 22: `9626a88c8395f0bd`

| Field | Value |
|---|---|
| SHA-256 | `9626a88c8395f0bd5c34b1c09ba8571d56004945c8569d954841fceafc498ef6` |
| Family label | `unknown` |
| File name | `browser.py` |
| File type | `py` |
| First seen | `2026-07-27 00:14:18` |
| Reporter | `anonymous` |
| Tags | `AminOgluStealer, py` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d8d8f65a8a862d245622d202c311d86` |
| SHA-1 | `b5b57d4c1e5960687f2dd5f5dcd5c8039c90bbe6` |
| SHA-256 | `9626a88c8395f0bd5c34b1c09ba8571d56004945c8569d954841fceafc498ef6` |
| SHA3-384 | `71a21fa3fb8dc87fa38218a0536cc46324216c947a6599d25ac81f048ab3f51916a4b2f010b5a1790d42b6bb4cac79a2` |
| TLSH | `T1ACA302B3FE169ED6057CF689D564AA68EF01670B1612998F3461A7CE0F372134AD0C8F` |
| SSDEEP | `3072:XpnLayM6o4HPDJlaKED+AQlyHbbeypSgzB+OLLXu:5Lf97JoKEK0PZnzBVLq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `py`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_9626a88c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9626a88c8395f0bd5c34b1c09ba8571d56004945c8569d954841fceafc498ef6"
    family = "unknown"
    file_name = "browser.py"
    file_type = "py"
    first_seen = "2026-07-27 00:14:18"
  condition:
    hash.sha256(0, filesize) == "9626a88c8395f0bd5c34b1c09ba8571d56004945c8569d954841fceafc498ef6"
}
```

### Sample 23: `2489a7c56d832faf`

| Field | Value |
|---|---|
| SHA-256 | `2489a7c56d832faf097303f8f495f5d459e62c83eeff43b39ab3a3e6a66b8c5b` |
| Family label | `unknown` |
| File name | `crypted.js` |
| File type | `js` |
| First seen | `2026-07-27 00:14:16` |
| Reporter | `anonymous` |
| Tags | `AminOgluStealer, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39193161cbd1c22346210a6683dfb6e1` |
| SHA-1 | `ba47f0247bd6c9ed15f24aa8b23abcbc5d8c6f06` |
| SHA-256 | `2489a7c56d832faf097303f8f495f5d459e62c83eeff43b39ab3a3e6a66b8c5b` |
| SHA3-384 | `8857ce9f0c0a890482abe889e4014c319ed2760c6f00796f22b1eb774500486832020abdcd614a58bda5a79ba37acd16` |
| TLSH | `T114D512872EF51CF62293D76E465BEB7BD6012FB14572748F30C20BC3934AA0A5B96907` |
| SSDEEP | `49152:aZodoF2Fa+YTtwP5VUI2LIWVSDQmIPuuA:h` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_2489a7c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2489a7c56d832faf097303f8f495f5d459e62c83eeff43b39ab3a3e6a66b8c5b"
    family = "unknown"
    file_name = "crypted.js"
    file_type = "js"
    first_seen = "2026-07-27 00:14:16"
  condition:
    hash.sha256(0, filesize) == "2489a7c56d832faf097303f8f495f5d459e62c83eeff43b39ab3a3e6a66b8c5b"
}
```

### Sample 24: `4e40ac262149dde5`

| Field | Value |
|---|---|
| SHA-256 | `4e40ac262149dde5d453c18cf700c384c846aa51dfcc5dcb9d57eac720b06d3f` |
| Family label | `unknown` |
| File name | `BlossCraft-Launcher.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:14:13` |
| Reporter | `anonymous` |
| Tags | `AminOgluStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `357b903fbfc7c4bc6590a92f3e07aaf4` |
| SHA-1 | `6db44b1c145e570f446118d63afd66055190a3a8` |
| SHA-256 | `4e40ac262149dde5d453c18cf700c384c846aa51dfcc5dcb9d57eac720b06d3f` |
| SHA3-384 | `af4a81478bd6c9f54fb7b013c16eae78936d3481d94bb0c2b4ff3d61c74b752e37b45922c2ba677100ce162efd2f28af` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T118083383DEA5A5B3D4A59E7F1405029E1A5EF243CAB53118ABEC213FD3E7D8946F00D8` |
| SSDEEP | `1572864:2r2u7dc2CNOuxPgaIz3XfDayhjhJTxWqqxZBHdX9vrKDeeQcz5bivwKOv:2rTJJuxPeznbaShJF1qxtteDRQ83` |
| ICON-DHASH | `4ae6a29670aaf010` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_4e40ac26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e40ac262149dde5d453c18cf700c384c846aa51dfcc5dcb9d57eac720b06d3f"
    family = "unknown"
    file_name = "BlossCraft-Launcher.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:14:13"
  condition:
    hash.sha256(0, filesize) == "4e40ac262149dde5d453c18cf700c384c846aa51dfcc5dcb9d57eac720b06d3f"
}
```

### Sample 25: `d3e984f5e189ae6c`

| Field | Value |
|---|---|
| SHA-256 | `d3e984f5e189ae6cd49bafa6298418583acab68292390bb63f21deec50740310` |
| Family label | `unknown` |
| File name | `xqAAE.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:08:07` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, aethersyncmatrix5-lol, exe, id-exhumepacifier-cc, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81729e5e6c1936b27f016a20897d30f1` |
| SHA-1 | `4c2da29463731ead232871e15e781ffd5f710a9c` |
| SHA-256 | `d3e984f5e189ae6cd49bafa6298418583acab68292390bb63f21deec50740310` |
| SHA3-384 | `cbf13fb071a9324a638644347b72cc2ff25b6cebbf88c1fdc2cd0da03c0e3a7d6e3a8c601db689f54e868e5218ac3b2f` |
| TLSH | `T181C48D56E6D2C1F1DD4349F1331FB32BBB7A5E2A8925C5F6E3E229499872361190F082` |
| SSDEEP | `12288:q8hW8fk0oD1RJ3/zk8XpKBB2iqSCbUdcw0E6/h0EZ1wDdM6GeQSMuVQ/:q8hW8fk0g1RJ3/zNZriqLbyGE6/h0dDL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_d3e984f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3e984f5e189ae6cd49bafa6298418583acab68292390bb63f21deec50740310"
    family = "unknown"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:08:07"
  condition:
    hash.sha256(0, filesize) == "d3e984f5e189ae6cd49bafa6298418583acab68292390bb63f21deec50740310"
}
```

### Sample 26: `205fc66381b8e254`

| Field | Value |
|---|---|
| SHA-256 | `205fc66381b8e254508d40c693a1314c9fc2b94b8023b29483803c8b0e449c4d` |
| Family label | `RemusStealer` |
| File name | `R5.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:07:14` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1b109827296c243ffc9e4583b9fd738` |
| SHA-1 | `c9ac15d711deeb63b01f8c49738bbdd7d70f4011` |
| SHA-256 | `205fc66381b8e254508d40c693a1314c9fc2b94b8023b29483803c8b0e449c4d` |
| SHA3-384 | `8b15f7432d0fe3276f342360392d0eade49ee138461e1af92e635ea77611e2d98f4785f9e6848b3e6bb8865d383d6221` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T1E424096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLF7l19CGiics:Qj5WUEBx+Q7PEfFnQU+tV` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_026_205fc663
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "205fc66381b8e254508d40c693a1314c9fc2b94b8023b29483803c8b0e449c4d"
    family = "RemusStealer"
    file_name = "R5.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:07:14"
  condition:
    hash.sha256(0, filesize) == "205fc66381b8e254508d40c693a1314c9fc2b94b8023b29483803c8b0e449c4d"
}
```

### Sample 27: `9e7fc86ad3c5efb2`

| Field | Value |
|---|---|
| SHA-256 | `9e7fc86ad3c5efb2e6746ab61dc43187eeb685c1fd9719bcb9553c173530f899` |
| Family label | `RemusStealer` |
| File name | `R2.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:06:40` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7ae17502be4db7ddac2dedaf98404d5` |
| SHA-1 | `3b773ede23c77347e7ea0c24dce8adb966082a89` |
| SHA-256 | `9e7fc86ad3c5efb2e6746ab61dc43187eeb685c1fd9719bcb9553c173530f899` |
| SHA3-384 | `13c70e0c828f5ab80a71408273a0d84ff22cc13efa79fa73e7ef11ec2435f06bbeb3fbf91e24414e371ea0d73a25bcee` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T1F024096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFF11CGiics:Qj5WUEBx+Q7PEfFnQU+tB` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_027_9e7fc86a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e7fc86ad3c5efb2e6746ab61dc43187eeb685c1fd9719bcb9553c173530f899"
    family = "RemusStealer"
    file_name = "R2.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:06:40"
  condition:
    hash.sha256(0, filesize) == "9e7fc86ad3c5efb2e6746ab61dc43187eeb685c1fd9719bcb9553c173530f899"
}
```

### Sample 28: `ece6e9395edb8935`

| Field | Value |
|---|---|
| SHA-256 | `ece6e9395edb8935c993a2945ac196a614149d65f10212e912e4654981646e37` |
| Family label | `RemusStealer` |
| File name | `ojujn.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:06:07` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ac8576f45bb73244f12a00976fefbae` |
| SHA-1 | `c57e06f49f785ae408d42e4b2fb139c0e7c0b4f1` |
| SHA-256 | `ece6e9395edb8935c993a2945ac196a614149d65f10212e912e4654981646e37` |
| SHA3-384 | `bb0aee53ef8cc9b184f978dc4891b6e321b6c887c45afc005afb3ad286ddbb6977b51865c6be6589999f50b470de61e5` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T16B24096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC45E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFC18CGiics:Qj5WUEBx+Q7PEfFnQU+tI` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_028_ece6e939
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ece6e9395edb8935c993a2945ac196a614149d65f10212e912e4654981646e37"
    family = "RemusStealer"
    file_name = "ojujn.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:06:07"
  condition:
    hash.sha256(0, filesize) == "ece6e9395edb8935c993a2945ac196a614149d65f10212e912e4654981646e37"
}
```

### Sample 29: `b0fb0119b9cce5b7`

| Field | Value |
|---|---|
| SHA-256 | `b0fb0119b9cce5b7aeef7f3499f5a71c5642c89f130daabc60822413cc2f5cd5` |
| Family label | `RemusStealer` |
| File name | `KLLNMF.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:05:36` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d618238e35254bcad69d184ef94a8e9` |
| SHA-1 | `ee749699843b1de9b2e711540cf16ebb9104ba26` |
| SHA-256 | `b0fb0119b9cce5b7aeef7f3499f5a71c5642c89f130daabc60822413cc2f5cd5` |
| SHA3-384 | `2835c5a80b75eea44dba59984da37ba34a745208a78aa2544ffc120aa74bb5f4b5ee872b1be8fe5d00e7188209c02b9a` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T1F824096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLF61gCGiics:Qj5WUEBx+Q7PEfFnQU+t8` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_029_b0fb0119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0fb0119b9cce5b7aeef7f3499f5a71c5642c89f130daabc60822413cc2f5cd5"
    family = "RemusStealer"
    file_name = "KLLNMF.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:05:36"
  condition:
    hash.sha256(0, filesize) == "b0fb0119b9cce5b7aeef7f3499f5a71c5642c89f130daabc60822413cc2f5cd5"
}
```

### Sample 30: `0e13be378b2ddf71`

| Field | Value |
|---|---|
| SHA-256 | `0e13be378b2ddf71bb66fbe2f90e4eeb241fe9fa92ef8e382320c86685f21d6f` |
| Family label | `RemusStealer` |
| File name | `kliulij.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:05:04` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87873d4cb6d2c05ffdacb2da3400a033` |
| SHA-1 | `166e44b9008405f89ac2031f62ee5e65e8b3d611` |
| SHA-256 | `0e13be378b2ddf71bb66fbe2f90e4eeb241fe9fa92ef8e382320c86685f21d6f` |
| SHA3-384 | `fdb18633b4e2e8307daa42fc97d2c32faaef23b4e4bdd8a8507d13999ab63a2843b6fc6449d77b4a637ff3b7af435b02` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T1CD24096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFy1gCGiics:Qj5WUEBx+Q7PEfFnQU+t4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_030_0e13be37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e13be378b2ddf71bb66fbe2f90e4eeb241fe9fa92ef8e382320c86685f21d6f"
    family = "RemusStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:05:04"
  condition:
    hash.sha256(0, filesize) == "0e13be378b2ddf71bb66fbe2f90e4eeb241fe9fa92ef8e382320c86685f21d6f"
}
```

### Sample 31: `f50688b538fecc5e`

| Field | Value |
|---|---|
| SHA-256 | `f50688b538fecc5ef7c893e148ddbb3cc1919fcb7c6462033fb72cb469242461` |
| Family label | `unknown` |
| File name | `KLHdfs.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:04:28` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, aethersyncmatrix5-lol, app-api-metricsengine-cc, exe, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cc9617281fc4505af569a4915e42a08` |
| SHA-1 | `c3e2dbb3515bf9e9c2202c9b489df627b512abd1` |
| SHA-256 | `f50688b538fecc5ef7c893e148ddbb3cc1919fcb7c6462033fb72cb469242461` |
| SHA3-384 | `c4ad8b91dc39f5407adcd926b271b92f17f6353898f486c5101c662055ac69442666da3da1222fe11187cb232b124460` |
| TLSH | `T1D1C46C49E5D2C1F0DE4385B2336FF22B6B311D0A8975CAFADBA16D959C233746A0F481` |
| SSDEEP | `12288:4lwOsm0kanafpalMx2aL4W9tkB1T96fOi+qoQ4ERZJ3b8TJBKUtz:dOn5QafpJ2akXJklxZJMXKU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_f50688b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f50688b538fecc5ef7c893e148ddbb3cc1919fcb7c6462033fb72cb469242461"
    family = "unknown"
    file_name = "KLHdfs.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:04:28"
  condition:
    hash.sha256(0, filesize) == "f50688b538fecc5ef7c893e148ddbb3cc1919fcb7c6462033fb72cb469242461"
}
```

### Sample 32: `8fb184c2d0b42adc`

| Field | Value |
|---|---|
| SHA-256 | `8fb184c2d0b42adc0695d6dab31d7905490028c77d9a472d18c06975e19bf24a` |
| Family label | `RemusStealer` |
| File name | `kJHGFDs.exe` |
| File type | `exe` |
| First seen | `2026-07-27 00:03:36` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eafb10f6fb3732229b64d5cddfc7540f` |
| SHA-1 | `cb8e1f5df3bc9f7a3211698ccfd69b38956f0eb2` |
| SHA-256 | `8fb184c2d0b42adc0695d6dab31d7905490028c77d9a472d18c06975e19bf24a` |
| SHA3-384 | `f06f4531c5e30d7af2c998ecd3a179f164a14e0b8212f59b63ca3a2ff8785051ad7cc6da76baf56776d68e3c3924a412` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T19424096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFh1NCGiics:Qj5WUEBx+Q7PEfFnQU+th` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_032_8fb184c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fb184c2d0b42adc0695d6dab31d7905490028c77d9a472d18c06975e19bf24a"
    family = "RemusStealer"
    file_name = "kJHGFDs.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:03:36"
  condition:
    hash.sha256(0, filesize) == "8fb184c2d0b42adc0695d6dab31d7905490028c77d9a472d18c06975e19bf24a"
}
```

### Sample 33: `9ed7214d1a093fe7`

| Field | Value |
|---|---|
| SHA-256 | `9ed7214d1a093fe7d3819b3143a17ce2a572662d55deebc6938a098cf8b0509d` |
| Family label | `unknown` |
| File name | `9ed7214d1a093fe7d3819b3143a17ce2a572662d55deebc6938a098cf8b0509d` |
| File type | `sh` |
| First seen | `2026-07-27 00:00:39` |
| Reporter | `anonymous` |
| Tags | `cowrie, hermes-noc, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ffce0f74261da11c21206b81203b061` |
| SHA-1 | `88290cc37b0d09fe406dc6c55e3d6397066e2b99` |
| SHA-256 | `9ed7214d1a093fe7d3819b3143a17ce2a572662d55deebc6938a098cf8b0509d` |
| SHA3-384 | `3ff43c65758d820a45e5e0f5b73746e204f42e36e7b5f386cd02c21bffed896d3c64c582023dc39590864eabd9b585ce` |
| TLSH | `T15C3154EF45309A391213CDDEB3727248B41C81F7294BDBE49D584EE982495CCB266FC6` |
| SSDEEP | `12:Ui6ODTxDxx6xHA/0PxJ3a63l2hf5Dox6oAwJY+xDk62A4tRI6lVEllvD6hZ+M6+U:lDd6p32sZA0YW4lVUK0WJ4C1Pxy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_9ed7214d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ed7214d1a093fe7d3819b3143a17ce2a572662d55deebc6938a098cf8b0509d"
    family = "unknown"
    file_name = "9ed7214d1a093fe7d3819b3143a17ce2a572662d55deebc6938a098cf8b0509d"
    file_type = "sh"
    first_seen = "2026-07-27 00:00:39"
  condition:
    hash.sha256(0, filesize) == "9ed7214d1a093fe7d3819b3143a17ce2a572662d55deebc6938a098cf8b0509d"
}
```

### Sample 34: `c51cdb75acfe918b`

| Field | Value |
|---|---|
| SHA-256 | `c51cdb75acfe918b90165cbeb4b1acc466b3514b9adaac055556987c61939821` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-26 23:53:05` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a26e56e773729e2927dab324996948cf` |
| SHA-1 | `d25c56f391d1a390ea7b3b33d569676252c59852` |
| SHA-256 | `c51cdb75acfe918b90165cbeb4b1acc466b3514b9adaac055556987c61939821` |
| SHA3-384 | `38d2ba3428196fd9250ac1f4cb61612e6211152803765425fba43de02e6dffaef3acb502e5e2f1a15290418aeb6d8f21` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T178E63345EAD02AFEE537403CEAE21186F159BC665B31CAAF075883652E772D04D3DB23` |
| SSDEEP | `393216:yB6hkkHXET0RscOjRH5fTXMCHWUjXscuI3/PGTAI:y0hkk3RBOVZbXMb8X5H/O7` |
| ICON-DHASH | `f0d89ea292c6f4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_c51cdb75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c51cdb75acfe918b90165cbeb4b1acc466b3514b9adaac055556987c61939821"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 23:53:05"
  condition:
    hash.sha256(0, filesize) == "c51cdb75acfe918b90165cbeb4b1acc466b3514b9adaac055556987c61939821"
}
```

### Sample 35: `e440f3fbbd33d569`

| Field | Value |
|---|---|
| SHA-256 | `e440f3fbbd33d569432ddbc45ee7de8a19b1648de898c01329d5f3a404bde96d` |
| Family label | `RemusStealer` |
| File name | `jhgkuyyg.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:55:18` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `faa1ec6c4f2ee779a599ab56481a1a47` |
| SHA-1 | `c0633997b9f28fbfee5a5d7aa0ebbbe6620d9b0d` |
| SHA-256 | `e440f3fbbd33d569432ddbc45ee7de8a19b1648de898c01329d5f3a404bde96d` |
| SHA3-384 | `00802d7a3e3047c0de8b40cb70297af1a8414e6e1c3939098e7c5f5b0ffe7b2aaa596da2be1a55e4b87fb5b3201dc94e` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T15724096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFo1kCGiics:Qj5WUEBx+Q7PEfFnQU+tC` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_035_e440f3fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e440f3fbbd33d569432ddbc45ee7de8a19b1648de898c01329d5f3a404bde96d"
    family = "RemusStealer"
    file_name = "jhgkuyyg.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:55:18"
  condition:
    hash.sha256(0, filesize) == "e440f3fbbd33d569432ddbc45ee7de8a19b1648de898c01329d5f3a404bde96d"
}
```

### Sample 36: `f43b33aacb1d9f73`

| Field | Value |
|---|---|
| SHA-256 | `f43b33aacb1d9f73ec3d687285c0e22ab6bafd6e5797106b711778aef073a9ca` |
| Family label | `RemusStealer` |
| File name | `hnmh.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:54:43` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4d4e4242b6344f5e54b36fa8e882f36` |
| SHA-1 | `453f7fe1bee981cf41006f07e8b5ad6e736ad22a` |
| SHA-256 | `f43b33aacb1d9f73ec3d687285c0e22ab6bafd6e5797106b711778aef073a9ca` |
| SHA3-384 | `b6c0e255c6670ed2ac9d42c5b7887fcb0b7a0f5069ee001f167204ec2d9bd678866299ed3454ad89206ac11164750915` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T1F624096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFc1nCGiics:Qj5WUEBx+Q7PEfFnQU+tS` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_036_f43b33aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f43b33aacb1d9f73ec3d687285c0e22ab6bafd6e5797106b711778aef073a9ca"
    family = "RemusStealer"
    file_name = "hnmh.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:54:43"
  condition:
    hash.sha256(0, filesize) == "f43b33aacb1d9f73ec3d687285c0e22ab6bafd6e5797106b711778aef073a9ca"
}
```

### Sample 37: `51bfb2f390653647`

| Field | Value |
|---|---|
| SHA-256 | `51bfb2f390653647b087d789ef1559c3fdf220c565a909f1eee4d593893420dd` |
| Family label | `RemusStealer` |
| File name | `hjbk.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:54:03` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e684ae1e3bf3994c4f68e84faa73f806` |
| SHA-1 | `3102f42f7ea5346f0dd9e05ba35dcb4260b1c524` |
| SHA-256 | `51bfb2f390653647b087d789ef1559c3fdf220c565a909f1eee4d593893420dd` |
| SHA3-384 | `774dd3a804900d1b4c21d66890c7d08bcfeb66858a9e149757dda10bcb83c207c7241d43398ba4e01bb87c89f5d76f63` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T1E724086BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFn11CGiics:Qj5WUEBx+Q7PEfFnQU+tj` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_037_51bfb2f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51bfb2f390653647b087d789ef1559c3fdf220c565a909f1eee4d593893420dd"
    family = "RemusStealer"
    file_name = "hjbk.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:54:03"
  condition:
    hash.sha256(0, filesize) == "51bfb2f390653647b087d789ef1559c3fdf220c565a909f1eee4d593893420dd"
}
```

### Sample 38: `7805b06ffc78058b`

| Field | Value |
|---|---|
| SHA-256 | `7805b06ffc78058b2dd8f41155c9fc353c1267629aeaf3ee8f8e587fd11f013e` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-26 22:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e70e3254dbab0a39f52dd81cb82123d3` |
| SHA-1 | `0555b030cc6625fa3a3840dde59150f337af4d82` |
| SHA-256 | `7805b06ffc78058b2dd8f41155c9fc353c1267629aeaf3ee8f8e587fd11f013e` |
| SHA3-384 | `49daf61ccf638fcedfcdc788c8d11b8ef98adc10c34adea44fcabd7dba6608266e2bbe64d64af8df0858b4d133cc96b6` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D6E63304B9E017EEDFA3013DEE810995D1B6B81A1B3AC5DF1BA887903E571D0AC3D766` |
| SSDEEP | `393216:2MRwI/ro+wGJfDaNpojXYmgUNoXMCHWUjXYcuI3/PGTAI:2MpccJ7gpkYmZoXMb8XtH/O7` |
| ICON-DHASH | `e8e86560d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_7805b06f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7805b06ffc78058b2dd8f41155c9fc353c1267629aeaf3ee8f8e587fd11f013e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 22:52:30"
  condition:
    hash.sha256(0, filesize) == "7805b06ffc78058b2dd8f41155c9fc353c1267629aeaf3ee8f8e587fd11f013e"
}
```

### Sample 39: `f52809d57d816cf9`

| Field | Value |
|---|---|
| SHA-256 | `f52809d57d816cf9ea7e95de64df46fcc1cf62d3da972c167497935b5eca74d7` |
| Family label | `unknown` |
| File name | `crazy.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:52:12` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9979541d2af1afa4339b737f42f5b8a` |
| SHA-1 | `2bf70a77e73578f09f44d7a0c5701ef048170408` |
| SHA-256 | `f52809d57d816cf9ea7e95de64df46fcc1cf62d3da972c167497935b5eca74d7` |
| SHA3-384 | `3d4b50dd2715ac4ae92ef7050f4c931aa2e318d5ac16fad3530f376455cbb9d72f1bf7a7e8a1b44e57f1bb13364b3742` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T12D24096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLF51RCGiics:Qj5WUEBx+Q7PEfFnQU+tR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_f52809d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f52809d57d816cf9ea7e95de64df46fcc1cf62d3da972c167497935b5eca74d7"
    family = "unknown"
    file_name = "crazy.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:52:12"
  condition:
    hash.sha256(0, filesize) == "f52809d57d816cf9ea7e95de64df46fcc1cf62d3da972c167497935b5eca74d7"
}
```

### Sample 40: `53afc0671b022a58`

| Field | Value |
|---|---|
| SHA-256 | `53afc0671b022a589954ba2a6755e1fb56a23552b7fb96740035d8c6fb59a780` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.9816.16164.28322` |
| File type | `elf` |
| First seen | `2026-07-26 22:51:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `457a6831ec751129b320de3c63ddea7a` |
| SHA-1 | `a172f30ac9a5d0ddba29218b6f6171454a31a166` |
| SHA-256 | `53afc0671b022a589954ba2a6755e1fb56a23552b7fb96740035d8c6fb59a780` |
| SHA3-384 | `23fcb4c904bcfa39e46ea434a67f263291b5026093eebd9a4b8159eaabd9cabd37f89274ff11bd5a8db821f28ab47197` |
| TLSH | `T153A32946F8814A21C5D512BEFA1E318E331357BCE2DE73129E14AF2173865EB0E7B615` |
| TELFHASH | `t1f9f0aca0865616ec27f4e50cc1af202c6a3d79a6372a1575448d0b8a87a71c2f50983b` |
| SSDEEP | `1536:wAnTSlO27kf5J7ZLBpqpp8GBgcQxEE3k7uaRrtOXrD0Rilp2x/F0v7Xh5GYWF6:ilRbpp8nuik7uaRgp2x/F8ThULF6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_53afc067
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53afc0671b022a589954ba2a6755e1fb56a23552b7fb96740035d8c6fb59a780"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.16164.28322"
    file_type = "elf"
    first_seen = "2026-07-26 22:51:46"
  condition:
    hash.sha256(0, filesize) == "53afc0671b022a589954ba2a6755e1fb56a23552b7fb96740035d8c6fb59a780"
}
```

### Sample 41: `4f58256a0e3199a3`

| Field | Value |
|---|---|
| SHA-256 | `4f58256a0e3199a31f42cfd1a9c2637625c8c3386b290ad4a95d5534af58c74d` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.9816.6013.2947` |
| File type | `elf` |
| First seen | `2026-07-26 22:51:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57645793382fc0f1ba98660977ba977e` |
| SHA-1 | `fe3a3b8c3d3e56ac8c7dd0a51e3eda5711bf4415` |
| SHA-256 | `4f58256a0e3199a31f42cfd1a9c2637625c8c3386b290ad4a95d5534af58c74d` |
| SHA3-384 | `efd534b7828b3f2d33109bdd17573d4dd680672f546bd7e1d0afd5e44f4d719111665bd18abdc9136a951c7a2288b3e0` |
| TLSH | `T1D1B3E84E6F318F7DFBA8C23447B39A21975923D227E2C685D19CDA011E7028E645FBB4` |
| TELFHASH | `t143118b184a3823e097751d9d6bedffb2e59170db4a255d338c00e9ae9b6dd418d01c1c` |
| SSDEEP | `1536:SEkWiTLiZECcpHOWWJDmmn5Pd1Oe4uPrs9j4ZWn+E7+TeVedVPneQBZN01X6n:gni50poFLP49j4+7+Te0dVPZ01X6n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_4f58256a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f58256a0e3199a31f42cfd1a9c2637625c8c3386b290ad4a95d5534af58c74d"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.6013.2947"
    file_type = "elf"
    first_seen = "2026-07-26 22:51:43"
  condition:
    hash.sha256(0, filesize) == "4f58256a0e3199a31f42cfd1a9c2637625c8c3386b290ad4a95d5534af58c74d"
}
```

### Sample 42: `b29391ba505af508`

| Field | Value |
|---|---|
| SHA-256 | `b29391ba505af508f2110f54f73b203e2710b8b6c8a8717005e5c7a4050630e1` |
| Family label | `RemusStealer` |
| File name | `bjbh.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:51:36` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23a9a402c5192b3c687cc59c40049929` |
| SHA-1 | `fe81c9d838854fa3ec23f010b4c1c74c808fd199` |
| SHA-256 | `b29391ba505af508f2110f54f73b203e2710b8b6c8a8717005e5c7a4050630e1` |
| SHA3-384 | `5ea1d4d579c4e051d7a6189f2c1db2fa49aeb96bc86108fe8e0b0d0fc003af7f04ece960f5054d1012a0edec621abef0` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T1BC24086BD25370FCD652C07852666232B732BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFC1XCGiics:Qj5WUEBx+Q7PEfFnQU+tc` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_042_b29391ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b29391ba505af508f2110f54f73b203e2710b8b6c8a8717005e5c7a4050630e1"
    family = "RemusStealer"
    file_name = "bjbh.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:51:36"
  condition:
    hash.sha256(0, filesize) == "b29391ba505af508f2110f54f73b203e2710b8b6c8a8717005e5c7a4050630e1"
}
```

### Sample 43: `602afb3c05b22b36`

| Field | Value |
|---|---|
| SHA-256 | `602afb3c05b22b36d643010ec3e804728971d327537310301ce3890ae97a6aed` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.9816.16164.28322` |
| File type | `elf` |
| First seen | `2026-07-26 22:51:06` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03da3c371915a830ffb4b13f6934eff6` |
| SHA-1 | `683d206615bc50df8923310ecd500d15ce002ec5` |
| SHA-256 | `602afb3c05b22b36d643010ec3e804728971d327537310301ce3890ae97a6aed` |
| SHA3-384 | `fa7a82cfaf0c51ea6adb0c8b6a9c99444540a5f1c33f1efe44652ad9406c6357f6a3cd288d20ee505f34e83057c69fd9` |
| TLSH | `T12213F1C848A66AE6832049B6EE90D3C683ADCA7CD5F658230E055F94E5E7C073BF91D1` |
| SSDEEP | `768:zrzD+GX7QWruIIOkByjnKkYEyEol8HKmJ77ZB7pCLabcQ+mys1DXIVIF9q3UEL8i:zvDZJuInJY8qmtD7pCLaj+myEDIOYLd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_602afb3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "602afb3c05b22b36d643010ec3e804728971d327537310301ce3890ae97a6aed"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.16164.28322"
    file_type = "elf"
    first_seen = "2026-07-26 22:51:06"
  condition:
    hash.sha256(0, filesize) == "602afb3c05b22b36d643010ec3e804728971d327537310301ce3890ae97a6aed"
}
```

### Sample 44: `527cb72afb7644af`

| Field | Value |
|---|---|
| SHA-256 | `527cb72afb7644af363fa08aec91c3c1ab0f19535eb4d6b23fe57dfcb3a291e8` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.9816.6013.2947` |
| File type | `elf` |
| First seen | `2026-07-26 22:51:05` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e93e48729747f6894213778149e00f7` |
| SHA-1 | `46d668eabe4274437643acbf0535ddf6ffd43a6d` |
| SHA-256 | `527cb72afb7644af363fa08aec91c3c1ab0f19535eb4d6b23fe57dfcb3a291e8` |
| SHA3-384 | `96e708b31001db6319194aaaf937d5473892823cfb9d1e062408bba4dcb4589e778cd74475326a535390524d8c3002cf` |
| TLSH | `T13613F168E70109D2E182413B21B80FD23BD31FF7BD86D86D651CA641C6DB6F03563EA8` |
| SSDEEP | `768:kVSrYS3JuIk8or7wskgzNl2/wkRY7aYUeG4pU8T3BomHAdH5p9KhbekJgGlzDpb8:k8DY8oXws/f2/wkmuYUeGh8TG+EYlecY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_527cb72a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "527cb72afb7644af363fa08aec91c3c1ab0f19535eb4d6b23fe57dfcb3a291e8"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.6013.2947"
    file_type = "elf"
    first_seen = "2026-07-26 22:51:05"
  condition:
    hash.sha256(0, filesize) == "527cb72afb7644af363fa08aec91c3c1ab0f19535eb4d6b23fe57dfcb3a291e8"
}
```

### Sample 45: `da7935affcec91c3`

| Field | Value |
|---|---|
| SHA-256 | `da7935affcec91c317acf98b52eca551f2501b29ad502749e4c084492142c6eb` |
| Family label | `RemusStealer` |
| File name | `beb.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:51:01` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31cf950bc1322291ecb5a3a13c3b96b8` |
| SHA-1 | `e99c5339ab851962a09acd833bbc5138a04d75f6` |
| SHA-256 | `da7935affcec91c317acf98b52eca551f2501b29ad502749e4c084492142c6eb` |
| SHA3-384 | `858caa89866be7275de8ca2f0dd24815dfdf40a277a6243d2a895b1f64eb7a7b565910396c9f751b670f7ee4a344bcc3` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T19F24096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFyi1/CGiics:Qj5WUEBx+Q7PEfFnQU+tUW` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_045_da7935af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da7935affcec91c317acf98b52eca551f2501b29ad502749e4c084492142c6eb"
    family = "RemusStealer"
    file_name = "beb.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:51:01"
  condition:
    hash.sha256(0, filesize) == "da7935affcec91c317acf98b52eca551f2501b29ad502749e4c084492142c6eb"
}
```

### Sample 46: `43e89a578fcb9e1c`

| Field | Value |
|---|---|
| SHA-256 | `43e89a578fcb9e1cea02e64c24829936b9b47ef6f2acb4e033436f8d5d446168` |
| Family label | `RemusStealer` |
| File name | `arFtU.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:50:28` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, Uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e269369facd09a383f21d3e599091b1` |
| SHA-1 | `486098d78773574d0b60566991304aab175d3aaa` |
| SHA-256 | `43e89a578fcb9e1cea02e64c24829936b9b47ef6f2acb4e033436f8d5d446168` |
| SHA3-384 | `9c2d5d4d0ad35bf38642a9a80908ae5d1d7832ec740e77ca9a719333b0b1bf117c7d6a71cedffb66617ddf469f18e44a` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T1E024096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFT1oCGiics:Qj5WUEBx+Q7PEfFnQU+tn` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_046_43e89a57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43e89a578fcb9e1cea02e64c24829936b9b47ef6f2acb4e033436f8d5d446168"
    family = "RemusStealer"
    file_name = "arFtU.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:50:28"
  condition:
    hash.sha256(0, filesize) == "43e89a578fcb9e1cea02e64c24829936b9b47ef6f2acb4e033436f8d5d446168"
}
```

### Sample 47: `33bd75f49eee1a5f`

| Field | Value |
|---|---|
| SHA-256 | `33bd75f49eee1a5f86bf7f673573a28c14c45b8f8d1b91694b214a1ec3d6c333` |
| Family label | `RemusStealer` |
| File name | `ARbeb.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:49:53` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58ef78c52ac325ae64968eadc5496250` |
| SHA-1 | `95d047527125fc03a0a6147415671d6689b884aa` |
| SHA-256 | `33bd75f49eee1a5f86bf7f673573a28c14c45b8f8d1b91694b214a1ec3d6c333` |
| SHA3-384 | `3037bbec6c1965d49e400e37c5c63b82ab39f0a069f17e92eba6a46edcf1ba43409e658d220e6fd4323219bfcf2d2374` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T1FA24096BD25370FCD652C07852666232B733BA3C47359EF702A3C3359D21AC46E7A929` |
| SSDEEP | `6144:FejlHWFiEBx+QncAE0EfFnyVUjYcapLFx1OCGiics:Qj5WUEBx+Q7PEfFnQU+tR` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_047_33bd75f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33bd75f49eee1a5f86bf7f673573a28c14c45b8f8d1b91694b214a1ec3d6c333"
    family = "RemusStealer"
    file_name = "ARbeb.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:49:53"
  condition:
    hash.sha256(0, filesize) == "33bd75f49eee1a5f86bf7f673573a28c14c45b8f8d1b91694b214a1ec3d6c333"
}
```

### Sample 48: `e15d8d51a52da2c3`

| Field | Value |
|---|---|
| SHA-256 | `e15d8d51a52da2c39d11d0409764821d2bc94794eea7ae3c8846b8ac078f4a0a` |
| Family label | `unknown` |
| File name | `acr.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:49:09` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, aethersyncmatrix5-lol, exe, monitor-monitorportal-cc, uncrypted` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `636a4a206e84c88baeba66425e33ee16` |
| SHA-1 | `e52de16302130b89ea1e51892b9107b875c59169` |
| SHA-256 | `e15d8d51a52da2c39d11d0409764821d2bc94794eea7ae3c8846b8ac078f4a0a` |
| SHA3-384 | `bd89de99b92605228fa6ccb1971bb37cc39eb3f72010efd3d6b00dbf1b71dcb04e95be35830c29ce34bede7bf1cbfacb` |
| TLSH | `T149F4AE16DAD2C1F2DE03D5B222EEF32F5A762E278839CEEAD7A05CB56813344250F155` |
| SSDEEP | `12288:7JpvL9GT6Lx1dVHIFFNdlUHBFfAfL3mYdRTAaZUDjopTMuK3xTl/2Lig1C:7/UTEFH+FNdShFfAfL3mYdRTAaZUDjoA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_e15d8d51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e15d8d51a52da2c39d11d0409764821d2bc94794eea7ae3c8846b8ac078f4a0a"
    family = "unknown"
    file_name = "acr.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:49:09"
  condition:
    hash.sha256(0, filesize) == "e15d8d51a52da2c39d11d0409764821d2bc94794eea7ae3c8846b8ac078f4a0a"
}
```

### Sample 49: `a1101793f851eb22`

| Field | Value |
|---|---|
| SHA-256 | `a1101793f851eb22dcffb2533be05bfd016e73b35e1ad2e35fc0d71d5099b52b` |
| Family label | `LummaStealer` |
| File name | `xqAAE.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:25:26` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, aethersyncmatrix5-lol, exe, id-exhumepacifier-cc, not-LummaStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3464135169dd3733163a502f959014ad` |
| SHA-1 | `d560a3f7c5cc9ae8073e9e326fa8f85fbb60555e` |
| SHA-256 | `a1101793f851eb22dcffb2533be05bfd016e73b35e1ad2e35fc0d71d5099b52b` |
| SHA3-384 | `e43ecfb2e0584f94a46d326d75e85a989a407b4c9dd4f3cab9f6cf1e02a4b77e57a44baf04e36010b432240816dbc752` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T15CD55A41FEC744F6E502163154A762AF2339AD065F35AB97FB443A7DEA372D6083320A` |
| SSDEEP | `49152:7sPlpnJ3IdsH/cIE+7XiR/ljQS735AbQh6:4NpnpgsfTa/eS7Rh` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_049_a1101793
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1101793f851eb22dcffb2533be05bfd016e73b35e1ad2e35fc0d71d5099b52b"
    family = "LummaStealer"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:25:26"
  condition:
    hash.sha256(0, filesize) == "a1101793f851eb22dcffb2533be05bfd016e73b35e1ad2e35fc0d71d5099b52b"
}
```

### Sample 50: `5820e30bc1d4bf9d`

| Field | Value |
|---|---|
| SHA-256 | `5820e30bc1d4bf9db0b6eca0249754c99b514cfa52b78990487cbf98f7b55569` |
| Family label | `RemusStealer` |
| File name | `R5.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:23:19` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14fce87cf261a710c1cebcc8a4f4e9da` |
| SHA-1 | `f5a24b79ce6654e125a712eb6084c5245e6dd8e9` |
| SHA-256 | `5820e30bc1d4bf9db0b6eca0249754c99b514cfa52b78990487cbf98f7b55569` |
| SHA3-384 | `af292983b4056ecbd2b9fc66823020a6ee32cebc84dc7b38c4a4d7ad3323e415d82ca8867af9607b2732485ec2c8dfb9` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T12CC55A03BDA109E6C0ADA33189B256527B71BC085B3633E72E90B7782F727D16D39B54` |
| SSDEEP | `24576:cXVInyeA2i7GUECfDejWiE86LG6rXeUbkraPzk7nG9OT+dGGbp0Q+PZoBele5I9s:cXVYC2SEeejWk/kbFEG9p0QeCcn2` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_050_5820e30b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5820e30bc1d4bf9db0b6eca0249754c99b514cfa52b78990487cbf98f7b55569"
    family = "RemusStealer"
    file_name = "R5.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:23:19"
  condition:
    hash.sha256(0, filesize) == "5820e30bc1d4bf9db0b6eca0249754c99b514cfa52b78990487cbf98f7b55569"
}
```

### Sample 51: `5cab5c362ded4c77`

| Field | Value |
|---|---|
| SHA-256 | `5cab5c362ded4c7795a68b94af56ff9922e15b4d343c7796bdc1c8338ac34887` |
| Family label | `RemusStealer` |
| File name | `R2.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:22:42` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6054e9828a4aa09e7469c589afc6fce` |
| SHA-1 | `4339591ef72328dbbbaacb8119ece8d18a708cb0` |
| SHA-256 | `5cab5c362ded4c7795a68b94af56ff9922e15b4d343c7796bdc1c8338ac34887` |
| SHA3-384 | `4ce5ee561a0dc28aa89275de68f76fa71028eb251cc27a3435d86748e4c9885096ad4af425d73852607d65ed05b52bf7` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T199C55A03BDA108E6C0AAA33289B356527B71BC085B3633D72E90B7782F727D16D75B54` |
| SSDEEP | `24576:BjCpLi4UiTSqhO3LgmpHSpGlKSqPl/NCOLOMO1OpDvFeLTFYXDPPZoBele5I9DUY:BjCNkiRh+LgiSgI9XpDvILBYTCAG6` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_051_5cab5c36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cab5c362ded4c7795a68b94af56ff9922e15b4d343c7796bdc1c8338ac34887"
    family = "RemusStealer"
    file_name = "R2.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:22:42"
  condition:
    hash.sha256(0, filesize) == "5cab5c362ded4c7795a68b94af56ff9922e15b4d343c7796bdc1c8338ac34887"
}
```

### Sample 52: `239fa9a692f16c74`

| Field | Value |
|---|---|
| SHA-256 | `239fa9a692f16c74b8faa90e48099978b0aadeb90fb5b8aae1c4b3161d516190` |
| Family label | `RemusStealer` |
| File name | `ojujn.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:22:02` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af584b28ceda51c7d4ea86910078646a` |
| SHA-1 | `fd21771360238bd0e8850400c232eab1f3c35475` |
| SHA-256 | `239fa9a692f16c74b8faa90e48099978b0aadeb90fb5b8aae1c4b3161d516190` |
| SHA3-384 | `2f1f9cdc095a46c7e05874675777b739eaf584ac8443b15bf8c40f453ce9b534278942e037c03a04669eee2a9f04a6cd` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T114C55907BCE149E6C0AEA33189B266527B71BC085B3227E72E90B7382F727D15D35B54` |
| SSDEEP | `24576:bWrF4N8YJvjYQOumWugdZhduN9QU2WgDzxqi0FC8cPZoBele5I9DUAKdKGKDE2D:bWrKiY1EQjmW97hQExqiV8wCYQE` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_052_239fa9a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "239fa9a692f16c74b8faa90e48099978b0aadeb90fb5b8aae1c4b3161d516190"
    family = "RemusStealer"
    file_name = "ojujn.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:22:02"
  condition:
    hash.sha256(0, filesize) == "239fa9a692f16c74b8faa90e48099978b0aadeb90fb5b8aae1c4b3161d516190"
}
```

### Sample 53: `7c8d18cc4785264f`

| Field | Value |
|---|---|
| SHA-256 | `7c8d18cc4785264f3a7d3423ebaeae8bf95d1ed9916dc4e6aab4f1f523747bdc` |
| Family label | `RemusStealer` |
| File name | `KLLNMF.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:21:31` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19e84ca8fa5f649584b7baebd8d01f1d` |
| SHA-1 | `94932c0d201345ceb252ca61d81df0dec1187ae7` |
| SHA-256 | `7c8d18cc4785264f3a7d3423ebaeae8bf95d1ed9916dc4e6aab4f1f523747bdc` |
| SHA3-384 | `4cc7f94813055ac76f48e7cf89cc20b69d762d7293e80572cb47abc2f286aac1ae23eb8c7edeb9eaaad78c9a7e107642` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D8C55907BCA149E6C0A9A33189B352527B71BC085B3633DB2E90B7782F727D15D39B58` |
| SSDEEP | `24576:YA6VTL/rj0G9iyGYQVSHT52Sxxbq3fkdqKYOhMSrnPZoBele5I9DUAKyKGatEVL:YA6xL/lMydQVc5HpQx3QvCNeB` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_053_7c8d18cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c8d18cc4785264f3a7d3423ebaeae8bf95d1ed9916dc4e6aab4f1f523747bdc"
    family = "RemusStealer"
    file_name = "KLLNMF.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:21:31"
  condition:
    hash.sha256(0, filesize) == "7c8d18cc4785264f3a7d3423ebaeae8bf95d1ed9916dc4e6aab4f1f523747bdc"
}
```

### Sample 54: `d84d9eb1e140f0f3`

| Field | Value |
|---|---|
| SHA-256 | `d84d9eb1e140f0f320976cc8219a6fc31136a2a1d5b89a55f8fe6217b170ae74` |
| Family label | `RemusStealer` |
| File name | `kliulij.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:21:01` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ef7a8539ffd93b31ac86add92a3df0e` |
| SHA-1 | `575188273fc0030ebb146b7ac8e1c9d40e4656c8` |
| SHA-256 | `d84d9eb1e140f0f320976cc8219a6fc31136a2a1d5b89a55f8fe6217b170ae74` |
| SHA3-384 | `4113f7d73712959be22070b56bf9703a8c5f87865dc2905712be621c4ff32ea6952535fb7c455b3e56cc4aa60beaf9f4` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T164C55907BCE149F6C0A9A33189B256527B71BC085B3223DB2E90B7382F727D19D79B54` |
| SSDEEP | `49152:I5HaEYwqHtBFgEp7Ewk1zWwG7jfJbCxRn:I56NrEs7DtGp` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_054_d84d9eb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d84d9eb1e140f0f320976cc8219a6fc31136a2a1d5b89a55f8fe6217b170ae74"
    family = "RemusStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:21:01"
  condition:
    hash.sha256(0, filesize) == "d84d9eb1e140f0f320976cc8219a6fc31136a2a1d5b89a55f8fe6217b170ae74"
}
```

### Sample 55: `bfe2c25627eec336`

| Field | Value |
|---|---|
| SHA-256 | `bfe2c25627eec3369b94ec60c1592e9cb38868f83f812a4ec506947d59ac8891` |
| Family label | `LummaStealer` |
| File name | `KLHdfs.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:20:27` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, aethersyncmatrix5-lol, app-api-metricsengine-cc, exe, not-LummaStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb3416ca351652997b09bc64c62e5531` |
| SHA-1 | `fec23a611159c06ff8ad5df619497ab71a756cf6` |
| SHA-256 | `bfe2c25627eec3369b94ec60c1592e9cb38868f83f812a4ec506947d59ac8891` |
| SHA3-384 | `fcb95f0066446c3a8fee12e24ef057b0d086d5d23480d6b7a402237db08fdc81289ce6a2a481fd06c3d06aadd972b101` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C9D56B01FEC744F6E602163654A722AF2335AD065F35DB97EB543A79FA332D6083720A` |
| SSDEEP | `24576:c/PK76HjLg/L/uoe0dHMTFUH6YBoLCb5yA2RJXEMRpcWzf8QVO9gco7XpqrUDNPD:cXKR1dHi1b3i0XorKu49AgbQh+T` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_055_bfe2c256
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfe2c25627eec3369b94ec60c1592e9cb38868f83f812a4ec506947d59ac8891"
    family = "LummaStealer"
    file_name = "KLHdfs.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:20:27"
  condition:
    hash.sha256(0, filesize) == "bfe2c25627eec3369b94ec60c1592e9cb38868f83f812a4ec506947d59ac8891"
}
```

### Sample 56: `55fa2ac196000639`

| Field | Value |
|---|---|
| SHA-256 | `55fa2ac196000639174619c5ff366119c874393cc4d3575533639cd409af1758` |
| Family label | `RemusStealer` |
| File name | `kJHGFDs.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:19:27` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eff12246e40f22f87be90b4d27b2daa5` |
| SHA-1 | `43563fe1d748cac51e21738045f579747eb22d93` |
| SHA-256 | `55fa2ac196000639174619c5ff366119c874393cc4d3575533639cd409af1758` |
| SHA3-384 | `bf9f54ee959cc8aa591bdfb962ec1f5ad8c42f4814b15f4f65de35286ee8325e4bd54a3d69f6409d81b2393fde12b01e` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T10EC55907BCE109E6C0ADA33189B256527B71BC085B3223DB2E90B7782F727D19D79B54` |
| SSDEEP | `24576:Tr/pYG6ho+c65IlGKxz3ZoZUZ0uCKOBkEGg1GpUb/EaNSPZoBele5I9DUAKsKGKk:Tr/yThoZOIFxz3ZDZmqE/EaICrpm` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_056_55fa2ac1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55fa2ac196000639174619c5ff366119c874393cc4d3575533639cd409af1758"
    family = "RemusStealer"
    file_name = "kJHGFDs.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:19:27"
  condition:
    hash.sha256(0, filesize) == "55fa2ac196000639174619c5ff366119c874393cc4d3575533639cd409af1758"
}
```

### Sample 57: `0eaf541c66a2384f`

| Field | Value |
|---|---|
| SHA-256 | `0eaf541c66a2384ff77265a9e3e2bf11300d0c47642b1d953b52843e6365d659` |
| Family label | `RemusStealer` |
| File name | `jhgkuyyg.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:18:39` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a0a275f424bd2dd34701768c384e900` |
| SHA-1 | `8ccfe59dfee26f101164bb91a139acfdbd54ff47` |
| SHA-256 | `0eaf541c66a2384ff77265a9e3e2bf11300d0c47642b1d953b52843e6365d659` |
| SHA3-384 | `eb76d8ca38a1c9994777a63e62329cd29d612005c8079f9805bc27a7ccb5b3cf78ba5ef0551eb4b78e6ef2a3e602e9c3` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T121C55907BCA109F6C0A9A33189B25252BB71BC085B3633DB2E90B7782F727D19D75B54` |
| SSDEEP | `24576:PMjTQI/qldwKckLXWCxaZo2eZQzsH3n8luoHR6wRA0nQB5/s64/PZoBele5I9DUQ:PMjjilGzkLmCxaZKZ7sZQBiCqF9` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_057_0eaf541c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eaf541c66a2384ff77265a9e3e2bf11300d0c47642b1d953b52843e6365d659"
    family = "RemusStealer"
    file_name = "jhgkuyyg.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:18:39"
  condition:
    hash.sha256(0, filesize) == "0eaf541c66a2384ff77265a9e3e2bf11300d0c47642b1d953b52843e6365d659"
}
```

### Sample 58: `24cabe973a480c2a`

| Field | Value |
|---|---|
| SHA-256 | `24cabe973a480c2a5a489500c2615c2cbe0399cd0087b04ba56d0e725043a6ca` |
| Family label | `RemusStealer` |
| File name | `hnmh.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:17:17` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b49afca85545ff5db04d08360274b5ed` |
| SHA-1 | `925bd1946991f834571b089c463b2ace0306c9d8` |
| SHA-256 | `24cabe973a480c2a5a489500c2615c2cbe0399cd0087b04ba56d0e725043a6ca` |
| SHA3-384 | `c4874ff50a76ad31fa0ac6f5390bc63001c55e2b8ee924f44449d6e273fed52a744ebc6b0d21c8be057008ea374c5f98` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T12EC55907BCA149E6C0ADA33189B262527B71BC085B3633E72E90B7782F727D15D39B54` |
| SSDEEP | `24576:EUGU3W6r7JSpqnIpyyWrMTaemymlofeoWpDUZ6ya9V3PZoBele5I9DUAKDKGK0EO:EUGMzrznayyWeoyUDUVa9FCKjIn` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_058_24cabe97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24cabe973a480c2a5a489500c2615c2cbe0399cd0087b04ba56d0e725043a6ca"
    family = "RemusStealer"
    file_name = "hnmh.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:17:17"
  condition:
    hash.sha256(0, filesize) == "24cabe973a480c2a5a489500c2615c2cbe0399cd0087b04ba56d0e725043a6ca"
}
```

### Sample 59: `6cd26345cc89c28c`

| Field | Value |
|---|---|
| SHA-256 | `6cd26345cc89c28c8ea226eb8ffa96be4f48af5fa369a403cdfb6fc46ff3ebef` |
| Family label | `RemusStealer` |
| File name | `hjbk.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:12:34` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a21b839850fda4b533d973af7b230c14` |
| SHA-1 | `25741d77150d950bde43a0424ebd59f659aaf9fa` |
| SHA-256 | `6cd26345cc89c28c8ea226eb8ffa96be4f48af5fa369a403cdfb6fc46ff3ebef` |
| SHA3-384 | `3d69ee1d6b500b8b38b26f6ef012bc34d14be584bed49459c93e0998ab8e6b6dc1e557fdb9b724d5577a09f80d978cca` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T196C55A07BDE109E6C0ADA33189B26652BB71BC085B3623D72E90B7382F727D16D35B54` |
| SSDEEP | `24576:KZjxY9ZnVVXRiz0yqBb2B7Us1iM39nFdmBUHrM4YWSKPZoBele5I9DUAK/KGK+EZ:KZjmvnxinqBb2OslABouCCmBZ` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_059_6cd26345
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cd26345cc89c28c8ea226eb8ffa96be4f48af5fa369a403cdfb6fc46ff3ebef"
    family = "RemusStealer"
    file_name = "hjbk.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:12:34"
  condition:
    hash.sha256(0, filesize) == "6cd26345cc89c28c8ea226eb8ffa96be4f48af5fa369a403cdfb6fc46ff3ebef"
}
```

### Sample 60: `85287c739d9703b2`

| Field | Value |
|---|---|
| SHA-256 | `85287c739d9703b2909c65478ee803897192d43144d27a3ef3eb7c2dd7b3e393` |
| Family label | `unknown` |
| File name | `crazy.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:11:50` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b60ddaa02a5fec2ec3151f6f84dc5c8` |
| SHA-1 | `7ac1f357f35b350994d83ff83008d75c4b6f16af` |
| SHA-256 | `85287c739d9703b2909c65478ee803897192d43144d27a3ef3eb7c2dd7b3e393` |
| SHA3-384 | `c91c9679a57954ac6d397b8c629d7c12e2c07e865ba498102b0674f79bb5669b4e2f92369e2a35971bd2739d3674cd8a` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T105C55A07BCA109E6C0ADA33189B252527B71BC085B3633D72E90B7782F727D1AD79B54` |
| SSDEEP | `24576:GGVlWSWvYM2s+9Xb0B27AQKJzAbg2XM7iogiOaP7kDSXc2qXEPZoBele5I9DUAKi:GGVYTvb+2B2BcyIzkDSXc4CVDps` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_85287c73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85287c739d9703b2909c65478ee803897192d43144d27a3ef3eb7c2dd7b3e393"
    family = "unknown"
    file_name = "crazy.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:11:50"
  condition:
    hash.sha256(0, filesize) == "85287c739d9703b2909c65478ee803897192d43144d27a3ef3eb7c2dd7b3e393"
}
```

### Sample 61: `3541431ce10c1833`

| Field | Value |
|---|---|
| SHA-256 | `3541431ce10c1833122df54cb4478ebc1631c89ca373a5747c322350a60d6385` |
| Family label | `RemusStealer` |
| File name | `bjbh.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:11:15` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, dropped-by-Adware.DownloadAssistant, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2626817c354412174fc4937efd1ad539` |
| SHA-1 | `0cd8542cd41d178747559b3b0b056e456f1d1fdb` |
| SHA-256 | `3541431ce10c1833122df54cb4478ebc1631c89ca373a5747c322350a60d6385` |
| SHA3-384 | `529af529331f9a7866bd9cf91e34da583b57278342763a31976cfa72ff7a4c7fe2f65056bcdb3648ff325b92839455f9` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T14EC55A07BCE109E6C0A9A33189B26152BB71BC085B3637E72E90B7782F727D19D35B54` |
| SSDEEP | `24576:xo/r3hVsKAwmrtRjV9VoPaZyxBFFsld51E/ZCVnyzTzH9c/JSPZoBele5I9DUAKR:xo/1KKzMtRR9VnZWFFaguQ9kJaCU+9` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_061_3541431c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3541431ce10c1833122df54cb4478ebc1631c89ca373a5747c322350a60d6385"
    family = "RemusStealer"
    file_name = "bjbh.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:11:15"
  condition:
    hash.sha256(0, filesize) == "3541431ce10c1833122df54cb4478ebc1631c89ca373a5747c322350a60d6385"
}
```

### Sample 62: `1a1bdfcbeec8791e`

| Field | Value |
|---|---|
| SHA-256 | `1a1bdfcbeec8791e79f8745a700a42a75dae7afd665a038da2b0d7812a0c0370` |
| Family label | `RemusStealer` |
| File name | `beb.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:10:30` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c4ad644cc7c5715a31e1b5aff752672` |
| SHA-1 | `191958630ec8522c0f29a824e81f2d939611ff0f` |
| SHA-256 | `1a1bdfcbeec8791e79f8745a700a42a75dae7afd665a038da2b0d7812a0c0370` |
| SHA3-384 | `0698a563a7646a57f53488f12bd39b29f6b570291321890fff7f8ac1eb6ae7c761c2c15573d9b80be181217697fbb5fd` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E8C55907BDA109F6C0A9A33189B326527B71BC085B3623D72E90B7382F727D16D79B54` |
| SSDEEP | `24576:KSsccVFOwSLQilPCphKg3ek/psK3dtWi0cDuhCOLOMO193MnlPPZoBele5I9DUAO:KSs3ywGlMKgbGikyuCmnCAW7` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_062_1a1bdfcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a1bdfcbeec8791e79f8745a700a42a75dae7afd665a038da2b0d7812a0c0370"
    family = "RemusStealer"
    file_name = "beb.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:10:30"
  condition:
    hash.sha256(0, filesize) == "1a1bdfcbeec8791e79f8745a700a42a75dae7afd665a038da2b0d7812a0c0370"
}
```

### Sample 63: `a3e15e1e942f76b3`

| Field | Value |
|---|---|
| SHA-256 | `a3e15e1e942f76b3d30cddd9f6cef8c91206b1a179871ce751613bf6efa2be5c` |
| Family label | `RemusStealer` |
| File name | `arFtU.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:09:46` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42264ef4d8637bc58d406e5e96622c8f` |
| SHA-1 | `6c3b7823087376206785d4d0a00465831b6d2894` |
| SHA-256 | `a3e15e1e942f76b3d30cddd9f6cef8c91206b1a179871ce751613bf6efa2be5c` |
| SHA3-384 | `a705c13938586a4dc1b2fe4234c73e611ddb067eef46321b2ecebd89ca283281781a0549e818822584cfd58f31857a3f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1BDC55907BDA108E6C0AAA33189B352527B71BC085B3633E72E90B7782F727D16D75B54` |
| SSDEEP | `24576:ejHS+SZdr6H54MSdVnW+Von5gNqwXiQrG4eHphobjFnc/GfTM6PZoBele5I9DUA1:ejHLOrHMYVnWZn6kwbSIjpc/gTFC9+7` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_063_a3e15e1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3e15e1e942f76b3d30cddd9f6cef8c91206b1a179871ce751613bf6efa2be5c"
    family = "RemusStealer"
    file_name = "arFtU.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:09:46"
  condition:
    hash.sha256(0, filesize) == "a3e15e1e942f76b3d30cddd9f6cef8c91206b1a179871ce751613bf6efa2be5c"
}
```

### Sample 64: `f30ce99a34cfc611`

| Field | Value |
|---|---|
| SHA-256 | `f30ce99a34cfc61168a99aff2ad0463cf0dac2902f86b1e73d060a28499bcf7f` |
| Family label | `RemusStealer` |
| File name | `ARbeb.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:08:41` |
| Reporter | `iamaachum` |
| Tags | `aethersyncmatrix5-lol, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a8a5fdf5feb574213c53bca1cb9688a` |
| SHA-1 | `22e8454bee44e98d9be147e9f397bc1a554342f5` |
| SHA-256 | `f30ce99a34cfc61168a99aff2ad0463cf0dac2902f86b1e73d060a28499bcf7f` |
| SHA3-384 | `a1f53156677c4fbf3a944884c738b474a72cdb53b0bdc5b6bc47dd45b0fb6826995a9c734713b12045dc40eeae503314` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11DC55907BCA149F6C0AAA33189B252527B71BC085B3633D72E90B7382F727D15D79B58` |
| SSDEEP | `24576:ZIYvYEzAZJ8SxwQ7gPZHHn7rYfcISSmCJCOLOMO1ME9zeZVaPZoBele5I9DUAKRE:ZIYQ8ArxT7gFb1/qECMBb` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_064_f30ce99a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f30ce99a34cfc61168a99aff2ad0463cf0dac2902f86b1e73d060a28499bcf7f"
    family = "RemusStealer"
    file_name = "ARbeb.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:08:41"
  condition:
    hash.sha256(0, filesize) == "f30ce99a34cfc61168a99aff2ad0463cf0dac2902f86b1e73d060a28499bcf7f"
}
```

### Sample 65: `f3761ae2ffb508e1`

| Field | Value |
|---|---|
| SHA-256 | `f3761ae2ffb508e1df76e974692226ac38b368b213349e2969d72fc49f51ea7a` |
| Family label | `LummaStealer` |
| File name | `acr.exe` |
| File type | `exe` |
| First seen | `2026-07-26 22:07:49` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, aethersyncmatrix5-lol, exe, monitor-monitorportal-cc, not-LummaStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5254b68ad505660d433d8eed93c371f` |
| SHA-1 | `c41da0cd9d017f4ff38bdfbd19e8f7ac6d9e2a0b` |
| SHA-256 | `f3761ae2ffb508e1df76e974692226ac38b368b213349e2969d72fc49f51ea7a` |
| SHA3-384 | `b4943750309e4a11338c7784f0008c2a1f89c69cb481e1b4bfbf1ad9ab092a8568bd24d27b0df425589a115a8ba77ce7` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F1D56A01FEC755F2E503163154A762AF273AAD065F35DB97EA807B7AEA332D10832709` |
| SSDEEP | `49152:/LDANbVYqBDXfQnjI78Va/DwMRYXebQhfBz:jcNbSafqSR/DwMRg1h5z` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_065_f3761ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3761ae2ffb508e1df76e974692226ac38b368b213349e2969d72fc49f51ea7a"
    family = "LummaStealer"
    file_name = "acr.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:07:49"
  condition:
    hash.sha256(0, filesize) == "f3761ae2ffb508e1df76e974692226ac38b368b213349e2969d72fc49f51ea7a"
}
```

### Sample 66: `7f9e2dc8918ea3f9`

| Field | Value |
|---|---|
| SHA-256 | `7f9e2dc8918ea3f90d35ff18dd92963b81e331651d234d6373e269e036606762` |
| Family label | `Stealc` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-07-26 21:52:43` |
| Reporter | `iamaachum` |
| Tags | `160-20-109-33, AsgardProtector, dropped-by-OffLoader, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bfcbc6d80962f4d6313d9102e4ff3d3` |
| SHA-1 | `3a3d3f293e52d151062c51b62fd39e543c9e6a85` |
| SHA-256 | `7f9e2dc8918ea3f90d35ff18dd92963b81e331651d234d6373e269e036606762` |
| SHA3-384 | `79241d09d93569d9b6230588d2ad51aac8a4716e39abf9bd5c11d58646aa29bea8b60fd8f2ad9232e2bf3bd3d62fe088` |
| IMPHASH | `013c74198fc6e42dcf33737d6c40c012` |
| TLSH | `T108E501D39241C7D4F4382935F06E690E02323D7F858CA05EE559B5126BB3D86EEE3A1B` |
| SSDEEP | `98304:NFGyooooogNfENTEHnVaQuQM7HNiJV6Hv7dHBt:jnNfEWVaLtrEV6Hv5b` |
| ICON-DHASH | `36969e9e6c3eb03a` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_066_7f9e2dc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f9e2dc8918ea3f90d35ff18dd92963b81e331651d234d6373e269e036606762"
    family = "Stealc"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:52:43"
  condition:
    hash.sha256(0, filesize) == "7f9e2dc8918ea3f90d35ff18dd92963b81e331651d234d6373e269e036606762"
}
```

### Sample 67: `43095747bec46e0b`

| Field | Value |
|---|---|
| SHA-256 | `43095747bec46e0b016fe04caa8b447216e47eb788ad40e57f83fd2cd3b1d63a` |
| Family label | `unknown` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-07-26 21:52:36` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddb831195cd126a623071a57cb419a7f` |
| SHA-1 | `2f5245c3857f5eb9477571c971e2d8ec365cf4ed` |
| SHA-256 | `43095747bec46e0b016fe04caa8b447216e47eb788ad40e57f83fd2cd3b1d63a` |
| SHA3-384 | `ad3acb60d385698e3c94e4b7a851c485f9b37720e59af6791867c9636104246c5314db68f66d1474b58e42a4217a5954` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T15DC55A03BDE108E6C0A9A33189B25252BB71BC085B3637D72E90B7782F727D1AD75B54` |
| SSDEEP | `24576:BONBMhGXvkmLi/YU7cw2KUmW0GLwpnumImjmmyOUrOaapBpOJ8debEyPZoBele5K:BON2gXRi9gw2Kak7yiaapBISgCTVk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_43095747
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43095747bec46e0b016fe04caa8b447216e47eb788ad40e57f83fd2cd3b1d63a"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:52:36"
  condition:
    hash.sha256(0, filesize) == "43095747bec46e0b016fe04caa8b447216e47eb788ad40e57f83fd2cd3b1d63a"
}
```

### Sample 68: `aa8e03cadb21e393`

| Field | Value |
|---|---|
| SHA-256 | `aa8e03cadb21e3939196e2658707563e7d6f1259b9d69f973b22ba494d1e49b4` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-26 21:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b990a1f4505ebf24ca3161556ee81f8f` |
| SHA-1 | `b899a4973c99eac9189e5cd7e209ea789183ba24` |
| SHA-256 | `aa8e03cadb21e3939196e2658707563e7d6f1259b9d69f973b22ba494d1e49b4` |
| SHA3-384 | `ee03b8c0ac9f275b12b640723e50e95f41afdaa143c4c9b7b23905b673c9ccdbebf50d69d991c269ddc6821bdb30162e` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T142E6334862D056FEE9B3A23DEEC351D4F16874722771C4DB1BA44BF1BE17290893EA12` |
| SSDEEP | `393216:e8DaFXMgsSJ2GTn1XMCHWUjXucuI3/PGTAI:e8eFXmGb1XMb8XDH/O7` |
| ICON-DHASH | `d4f87cbc8cc47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_aa8e03ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa8e03cadb21e3939196e2658707563e7d6f1259b9d69f973b22ba494d1e49b4"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 21:52:30"
  condition:
    hash.sha256(0, filesize) == "aa8e03cadb21e3939196e2658707563e7d6f1259b9d69f973b22ba494d1e49b4"
}
```

### Sample 69: `1e925e77624c2db8`

| Field | Value |
|---|---|
| SHA-256 | `1e925e77624c2db848d076f43d92f1acfdf832ff7ef48063f38088dd81e4c298` |
| Family label | `unknown` |
| File name | `dollar.exe` |
| File type | `exe` |
| First seen | `2026-07-26 21:43:35` |
| Reporter | `iamaachum` |
| Tags | `132-243-212-126, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff23372bf45cd719bfba8ab5b507a099` |
| SHA-1 | `d61c2cbd1c96fefc370ccda8e0e818d56ab0e9f1` |
| SHA-256 | `1e925e77624c2db848d076f43d92f1acfdf832ff7ef48063f38088dd81e4c298` |
| SHA3-384 | `621ee164a362b9714389ef76877ed51e1cf4fb3f684ce5a80ca8db5158f533fc87ffda0bf790868da6b3b017b627a17b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T158F54B03AD9149FAC499A331C9B761527B74BC0C5B3633DB2E50BAB82E727C05D39B94` |
| SSDEEP | `49152:pzf9ikvO0UZnei5Mxaj9aTHi8PCDU6RbXCXPULZLq6H4vGwp4zTfCwZ:pz1NQ/BH4vLp4vZZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_1e925e77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e925e77624c2db848d076f43d92f1acfdf832ff7ef48063f38088dd81e4c298"
    family = "unknown"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:43:35"
  condition:
    hash.sha256(0, filesize) == "1e925e77624c2db848d076f43d92f1acfdf832ff7ef48063f38088dd81e4c298"
}
```

### Sample 70: `0a0b01867e41bbd7`

| Field | Value |
|---|---|
| SHA-256 | `0a0b01867e41bbd7e9863cbf839efb3a2f0963c2ccedd06c22c22beda6aafa19` |
| Family label | `unknown` |
| File name | `MegaBasterd.exe` |
| File type | `exe` |
| First seen | `2026-07-26 21:23:55` |
| Reporter | `iamaachum` |
| Tags | `exe, megabasterd-com, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce67f463c3459693c3934737bdcce0f7` |
| SHA-1 | `d95e0e95aaa5bd035ad7cd1b24b5de03cb9d735d` |
| SHA-256 | `0a0b01867e41bbd7e9863cbf839efb3a2f0963c2ccedd06c22c22beda6aafa19` |
| SHA3-384 | `0765479ec6c6095b79a38e032de9dcbff0efad42de72f68d7d4e1041a845dfb911e6460ff2894526daecc37604ffa06c` |
| IMPHASH | `51a80ea29674dca0d37bdf9bcafa7a0d` |
| TLSH | `T1FF335B4EB2C314FCC52FC0B985D68B76AA71B8211124AF3E769CDA301F10D646F3AE56` |
| SSDEEP | `768:CHHrET4k408zFbUn/8byR9X+pXFHxHUgRqVqnZB5CQmZKZCoqHy6+HOr:CHHrlpbWAyR9EFHx0gsVqZGZeGy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_0a0b0186
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a0b01867e41bbd7e9863cbf839efb3a2f0963c2ccedd06c22c22beda6aafa19"
    family = "unknown"
    file_name = "MegaBasterd.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:23:55"
  condition:
    hash.sha256(0, filesize) == "0a0b01867e41bbd7e9863cbf839efb3a2f0963c2ccedd06c22c22beda6aafa19"
}
```

### Sample 71: `12f1e8ea44fae73b`

| Field | Value |
|---|---|
| SHA-256 | `12f1e8ea44fae73b7636824985c04866d44dce4c76c203fe4c547d781416b900` |
| Family label | `unknown` |
| File name | `Launcher.dmg` |
| File type | `dmg` |
| First seen | `2026-07-26 21:22:40` |
| Reporter | `iamaachum` |
| Tags | `dmg, MacSync, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73fd97bc9afc00c3614ed21b1985c900` |
| SHA-1 | `469464b0c4c77e5d204c5510ff87eea9cdde1e4b` |
| SHA-256 | `12f1e8ea44fae73b7636824985c04866d44dce4c76c203fe4c547d781416b900` |
| SHA3-384 | `9c50ec28e8fa7f8f1e923b35fb383d5eb68a81546a035a020cf18f307b5fd50092bbbe4c1047b49593fc92b3cb0962f5` |
| TLSH | `T1BDB3AC78DB0928B3FE1515B0766920171CAA1EBB3821DC2AA6D7384F2387F317D74E56` |
| SSDEEP | `3072:H0dusU9ShDX6cohyYprqzN/S2eRtfmOeQSzgI:HEU9ShDXFyyPh/zA5mMSzgI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dmg`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_12f1e8ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12f1e8ea44fae73b7636824985c04866d44dce4c76c203fe4c547d781416b900"
    family = "unknown"
    file_name = "Launcher.dmg"
    file_type = "dmg"
    first_seen = "2026-07-26 21:22:40"
  condition:
    hash.sha256(0, filesize) == "12f1e8ea44fae73b7636824985c04866d44dce4c76c203fe4c547d781416b900"
}
```

### Sample 72: `e6016e68b528ea80`

| Field | Value |
|---|---|
| SHA-256 | `e6016e68b528ea80caa37afb5a283e88a78659ffea48d8fc297fad7676072324` |
| Family label | `unknown` |
| File name | `Up4pc_Compressed_File_Download.exe` |
| File type | `exe` |
| First seen | `2026-07-26 21:20:31` |
| Reporter | `iamaachum` |
| Tags | `exe, up4pc-com, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba47ab37b1b099e3df4d38ecf868e55f` |
| SHA-1 | `32c8fad6904ff4fc95e64b1a82e56f8f13aad770` |
| SHA-256 | `e6016e68b528ea80caa37afb5a283e88a78659ffea48d8fc297fad7676072324` |
| SHA3-384 | `b696d24e299ac473750632b5fe80b845ca8cad2d5409a143dbb239552c229f0a2368dcc0f3c9eefd05e90355dfb4ccdd` |
| IMPHASH | `5b5b24d18f42c274c0880244c9d97c2e` |
| TLSH | `T1A0E32A57E29370FCC557C17845966772FA30B8324324AE7E7BACDA312F10E60BE29A15` |
| SSDEEP | `3072:K1B1+D7PsRD419nxwqeqbyq/9GbJ5dUWPPw1h6Z:K1AoD41gQyY7WHvZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_e6016e68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6016e68b528ea80caa37afb5a283e88a78659ffea48d8fc297fad7676072324"
    family = "unknown"
    file_name = "Up4pc_Compressed_File_Download.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:20:31"
  condition:
    hash.sha256(0, filesize) == "e6016e68b528ea80caa37afb5a283e88a78659ffea48d8fc297fad7676072324"
}
```

### Sample 73: `e964b3d18222d68e`

| Field | Value |
|---|---|
| SHA-256 | `e964b3d18222d68e19230c089fc7599f1d9fd6dc205fca13705c535feebe0627` |
| Family label | `LummaStealer` |
| File name | `Build.exe` |
| File type | `exe` |
| First seen | `2026-07-26 21:19:29` |
| Reporter | `iamaachum` |
| Tags | `exe, LummaStealer, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b7b5a050a3c834448c925de7e33633b` |
| SHA-1 | `c4748eac0048e91b1a95f94b5f4fd835a5200f90` |
| SHA-256 | `e964b3d18222d68e19230c089fc7599f1d9fd6dc205fca13705c535feebe0627` |
| SHA3-384 | `83cfac37f40c2a05d58cd2472e1f6388104a3b6d58c3affac571944348c6394a8a9e4b06c5abd9a27d137814238c54c2` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1D3A55B40FDD359F6E002163295A772AB2335AC050B3BDB97EB84BA79F9772D50837209` |
| SSDEEP | `24576:joWN5h3U4Lg/LFlsYyZ61U+BRqATkMdzMrioyMaZzqZwnv0o4zW/ItJEzb3gqswW:j/NrRr61z1s2v0o4zW/IjEzbQqshbgGh` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_073_e964b3d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e964b3d18222d68e19230c089fc7599f1d9fd6dc205fca13705c535feebe0627"
    family = "LummaStealer"
    file_name = "Build.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:19:29"
  condition:
    hash.sha256(0, filesize) == "e964b3d18222d68e19230c089fc7599f1d9fd6dc205fca13705c535feebe0627"
}
```

### Sample 74: `ed401886b7711526`

| Field | Value |
|---|---|
| SHA-256 | `ed401886b771152687f6fc844e8c2c296705456e810a1ec5886c7065735f2951` |
| Family label | `unknown` |
| File name | `encryptor.exe` |
| File type | `exe` |
| First seen | `2026-07-26 21:18:41` |
| Reporter | `iamaachum` |
| Tags | `exe, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e679b35fc6e23403d369fc1e93ef2b9` |
| SHA-1 | `0935ee0928ed100fb28fcfaa3f7dee6f4403e93b` |
| SHA-256 | `ed401886b771152687f6fc844e8c2c296705456e810a1ec5886c7065735f2951` |
| SHA3-384 | `d008e9a037e708d006a98aa060e086b1773f06da9eebe8898566b9c76c4fc2fe9c9cbd3a4c4224341397503233e15832` |
| IMPHASH | `fe133f5557cac3cd3d72d3e03c96c29f` |
| TLSH | `T1AF448C59B7B51CF9EDA7853DC9424A06EB72BC0647A0E68F03E00A975F236E05E3E711` |
| SSDEEP | `3072:50+nnW7foMeTUN4MySOswQdiOylAzLyH4EvMu8smzrI9d8CqdnJ7sn4c95N+ppKR:508dUl3ZdiOam8DbL8tKsp+sw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_ed401886
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed401886b771152687f6fc844e8c2c296705456e810a1ec5886c7065735f2951"
    family = "unknown"
    file_name = "encryptor.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:18:41"
  condition:
    hash.sha256(0, filesize) == "ed401886b771152687f6fc844e8c2c296705456e810a1ec5886c7065735f2951"
}
```

### Sample 75: `53ba5fd24bbf81d3`

| Field | Value |
|---|---|
| SHA-256 | `53ba5fd24bbf81d3a2fc53af19884b8ebb6344281891bdb78adb924a1f65b40b` |
| Family label | `unknown` |
| File name | `chromelevator_arm64.exe` |
| File type | `exe` |
| First seen | `2026-07-26 21:17:56` |
| Reporter | `iamaachum` |
| Tags | `arm64, ChromElevator, exe, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24909335a110650fbd9b5633b3855534` |
| SHA-1 | `75b2c0de956c99ba5df53567faab45d878a5ee3b` |
| SHA-256 | `53ba5fd24bbf81d3a2fc53af19884b8ebb6344281891bdb78adb924a1f65b40b` |
| SHA3-384 | `bd75355772b55298634df9e4b739a7fd5050aab266fd8727e8b235ecd0d3b8b76072181250b041ccbfc21760569ca73a` |
| IMPHASH | `32858949e18d8b6ed83e72cb40c63c49` |
| TLSH | `T1DC65F1926B8D58E5D7C6D33CCC604E54602FF6788834C98F705B060EDDAEAC4DEA59A3` |
| SSDEEP | `24576:by2WPmGW/kwU7GeCvYhT5UROd6e7DtwhslezLdb64If0+x9g:G9mN8wU7ao1UAguDtwpu4If` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_53ba5fd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53ba5fd24bbf81d3a2fc53af19884b8ebb6344281891bdb78adb924a1f65b40b"
    family = "unknown"
    file_name = "chromelevator_arm64.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:17:56"
  condition:
    hash.sha256(0, filesize) == "53ba5fd24bbf81d3a2fc53af19884b8ebb6344281891bdb78adb924a1f65b40b"
}
```

### Sample 76: `2d9346aa5de94f20`

| Field | Value |
|---|---|
| SHA-256 | `2d9346aa5de94f207e93db952eeed52861b4b31a2c98899147c5fa59b2deee55` |
| Family label | `unknown` |
| File name | `chromelevator_x64.exe` |
| File type | `exe` |
| First seen | `2026-07-26 21:16:22` |
| Reporter | `iamaachum` |
| Tags | `ChromElevator, exe, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `205d7d91b72d06246a647c3290403280` |
| SHA-1 | `83979e73d7e00548bdf4fba960fdcce5bacbf146` |
| SHA-256 | `2d9346aa5de94f207e93db952eeed52861b4b31a2c98899147c5fa59b2deee55` |
| SHA3-384 | `84318f1a6cdbe71f1461a33904772d0419036f8e4e54cec249b3b9d996e1d2d884c1c44f14cf0e0b051fbd70872fe97d` |
| IMPHASH | `c137ae5983c45e257bede56695037c40` |
| TLSH | `T1B1650216A6A900F9D2A3C578CC565D0ADB72F8025F74EADF03A81A960F237E49D3F711` |
| SSDEEP | `24576:ovwaUdlN+P6WLIcA9UJCO2GoxdV0fwoYFcCaBC87oNf6hr3qFt:ovwGP6X9A0dVjoYOFFIyhz4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_2d9346aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d9346aa5de94f207e93db952eeed52861b4b31a2c98899147c5fa59b2deee55"
    family = "unknown"
    file_name = "chromelevator_x64.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:16:22"
  condition:
    hash.sha256(0, filesize) == "2d9346aa5de94f207e93db952eeed52861b4b31a2c98899147c5fa59b2deee55"
}
```

### Sample 77: `555e5544368694f5`

| Field | Value |
|---|---|
| SHA-256 | `555e5544368694f5726c77cf1a12e3f2d6d57479a00c462476ec552312a753a4` |
| Family label | `unknown` |
| File name | `Megabasterd.exe` |
| File type | `exe` |
| First seen | `2026-07-26 21:14:13` |
| Reporter | `iamaachum` |
| Tags | `exe, megabasterd-com, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f577fe3546869bd9ea1f185c6646544` |
| SHA-1 | `95f00f95c96284adab1d7852e67fdcbb6445bba3` |
| SHA-256 | `555e5544368694f5726c77cf1a12e3f2d6d57479a00c462476ec552312a753a4` |
| SHA3-384 | `e85a672315299d795029c4b779cf533a8c162ade9d6f1dbe9813a097e325b7ee2c303ab8ed82eba0a50d1e832117a878` |
| IMPHASH | `dcef13196d9946b892f62428821e6df6` |
| TLSH | `T1F7E32913E29370FCC117C1B8459A5772FA31B8254324AE7EB7ACDA712F11E607E29B25` |
| SSDEEP | `3072:30/zFkHuTJyJDwh9rxOvsq9ow7LAsqMsdUWPPhhSGc:3mJwDwh65oAAsRNWHhbc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_555e5544
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "555e5544368694f5726c77cf1a12e3f2d6d57479a00c462476ec552312a753a4"
    family = "unknown"
    file_name = "Megabasterd.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:14:13"
  condition:
    hash.sha256(0, filesize) == "555e5544368694f5726c77cf1a12e3f2d6d57479a00c462476ec552312a753a4"
}
```

### Sample 78: `afaea86058dc0a84`

| Field | Value |
|---|---|
| SHA-256 | `afaea86058dc0a8475b6a07a7404e37624cf8a70aa9fb9f3a2038ec61862eb4c` |
| Family label | `unknown` |
| File name | `c.sh` |
| File type | `sh` |
| First seen | `2026-07-26 21:11:55` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10c1d25dfd571af943ee6193731c56fb` |
| SHA-1 | `eaea1966505cca62e2f950acb02abe79aba35cf2` |
| SHA-256 | `afaea86058dc0a8475b6a07a7404e37624cf8a70aa9fb9f3a2038ec61862eb4c` |
| SHA3-384 | `a44fbef00aaa562d94fb7c9be84559e4dee60c400635e43fd07b8f13d8f98d138302e52e72c74f9d42b7ce6623ebc5a5` |
| TLSH | `T15A11B2DA4118A3461B488D14FC5B8C3D796B96E67136E514B286F8F48DCC2052D39FEF` |
| SSDEEP | `24:3J30C9GHjsFJNIxKVXKn0ydfh6zTks20hp3AtZEsGyhOfThlHA:fQDCXJeqTkxiAZTjhGhlg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_afaea860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afaea86058dc0a8475b6a07a7404e37624cf8a70aa9fb9f3a2038ec61862eb4c"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-26 21:11:55"
  condition:
    hash.sha256(0, filesize) == "afaea86058dc0a8475b6a07a7404e37624cf8a70aa9fb9f3a2038ec61862eb4c"
}
```

### Sample 79: `5a6f57b0f7404d70`

| Field | Value |
|---|---|
| SHA-256 | `5a6f57b0f7404d70c29e5c39b3bdd95064df4c4885f0fbbdcee41e438ff8444c` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-26 20:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3b3d37c7861b4d63bc2b1b966efdedb` |
| SHA-1 | `b6d1264bc8df859f931f78369c3552bcb6dbc256` |
| SHA-256 | `5a6f57b0f7404d70c29e5c39b3bdd95064df4c4885f0fbbdcee41e438ff8444c` |
| SHA3-384 | `037da70f5d151106749d77208bcc448ba90524b9cccd480573a8e09354d3c93105be7e6dc37685e872a929aefad7f0fa` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T14DE633489FE001FEEAF3907DEEE19194D52474261776D2DF876967A83E432E08D3434A` |
| SSDEEP | `393216:fFhNn1DV2Gn5chuOQQtqkT24wXMCHWUjXgcuI3/PGTAI:frN1V5eunkYXMb8X1H/O7` |
| ICON-DHASH | `f0f0f0e8e8f0f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_5a6f57b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a6f57b0f7404d70c29e5c39b3bdd95064df4c4885f0fbbdcee41e438ff8444c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 20:52:30"
  condition:
    hash.sha256(0, filesize) == "5a6f57b0f7404d70c29e5c39b3bdd95064df4c4885f0fbbdcee41e438ff8444c"
}
```

### Sample 80: `54117f39ec10e191`

| Field | Value |
|---|---|
| SHA-256 | `54117f39ec10e191bd8d2513998c926cbd70e65f1aea9063f54801db1f046e11` |
| Family label | `unknown` |
| File name | `jquery.min1.js` |
| File type | `zip` |
| First seen | `2026-07-26 20:23:30` |
| Reporter | `iamaachum` |
| Tags | `45-140-14-113, 46-225-113-75, Arechclient2, dropped-by-ACRStealer, SectopRAT, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f569ebb4d2fa3ea9cf7fd56a223ecda2` |
| SHA-1 | `9b61bf2fa69ea708678739ac35dd665c6ad146b4` |
| SHA-256 | `54117f39ec10e191bd8d2513998c926cbd70e65f1aea9063f54801db1f046e11` |
| SHA3-384 | `bfc404f2332bdf55778501c33cd1ef4f11c866812f845e56b167f367c4e1e86a1b5c4bfc209801a35afa35dc5bcf7a8a` |
| TLSH | `T15B66CF52B3C816E9D066D63896059233D2B2BC224772D2CB06E6E75A1F7BBD14B3F701` |
| SSDEEP | `196608:KojyTlmSIiyqGDM7CdiIu3PSUN2v70wKS5W66D7AqltNq8CdRF:ZWTnIwGIbIsSUNSfCyqlq82F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_54117f39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54117f39ec10e191bd8d2513998c926cbd70e65f1aea9063f54801db1f046e11"
    family = "unknown"
    file_name = "jquery.min1.js"
    file_type = "zip"
    first_seen = "2026-07-26 20:23:30"
  condition:
    hash.sha256(0, filesize) == "54117f39ec10e191bd8d2513998c926cbd70e65f1aea9063f54801db1f046e11"
}
```

### Sample 81: `279d04c0cfd700c8`

| Field | Value |
|---|---|
| SHA-256 | `279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92` |
| Family label | `unknown` |
| File name | `jquery.min.js` |
| File type | `zip` |
| First seen | `2026-07-26 20:22:05` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, lb-propertyfind-cc, ZigClipper, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56241fae7b30fae69410925b91107df5` |
| SHA-1 | `95e291766bde87901fe6e253f71c84bd9c8af4a8` |
| SHA-256 | `279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92` |
| SHA3-384 | `67528b54ca5d9a83b7f73951150fee7938349962f540824d5377c0f1719a5fc0c85f10a930f243f260e27f2494f7c40b` |
| TLSH | `T19896AE13B29802F5D0AAC27897569232E671BC161731A2CF2699F2191F7BFE04B7F711` |
| SSDEEP | `196608:Ojw00mNBT0WAC/5lTIW98M7YzVdj+8CdRK:OEwIy5lTF50Vdj+82K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_279d04c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92"
    family = "unknown"
    file_name = "jquery.min.js"
    file_type = "zip"
    first_seen = "2026-07-26 20:22:05"
  condition:
    hash.sha256(0, filesize) == "279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92"
}
```

### Sample 82: `64c25e91637c23fa`

| Field | Value |
|---|---|
| SHA-256 | `64c25e91637c23fa8d29fcbe425b9649e8a2a917316892b855fdd279df82c081` |
| Family label | `unknown` |
| File name | `Srv.exe` |
| File type | `exe` |
| First seen | `2026-07-26 19:58:19` |
| Reporter | `smica83` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0292d32f18e43ce3faef61d7386ea738` |
| SHA-1 | `570a1217458b37db1341d864ddc6e9d38af41fc2` |
| SHA-256 | `64c25e91637c23fa8d29fcbe425b9649e8a2a917316892b855fdd279df82c081` |
| SHA3-384 | `3d818ecc87745cc6a6dba9e4b34b11bf24dcff30f9d9e86f40993044dcff9106186b70b93e0202e45613737416b0ba24` |
| IMPHASH | `d254662db81cb875fef4e3dae1658b1e` |
| TLSH | `T1CAB6CF42FB594232EEA70175889B732D612A7B910350FBC7BBEC750657A02D0B33767A` |
| SSDEEP | `196608:bJjfYbpEJsv6tWKFdu9CedRz+V7BpLJw6PcBT:bJkiJsv6tWKFdu9CejgdpK06T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_64c25e91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64c25e91637c23fa8d29fcbe425b9649e8a2a917316892b855fdd279df82c081"
    family = "unknown"
    file_name = "Srv.exe"
    file_type = "exe"
    first_seen = "2026-07-26 19:58:19"
  condition:
    hash.sha256(0, filesize) == "64c25e91637c23fa8d29fcbe425b9649e8a2a917316892b855fdd279df82c081"
}
```

### Sample 83: `41986e5a10e7d708`

| Field | Value |
|---|---|
| SHA-256 | `41986e5a10e7d708d74a8758a0dfc543fcaae48fe238a4b82194da0292338c14` |
| Family label | `unknown` |
| File name | `Lobby+X.rar` |
| File type | `rar` |
| First seen | `2026-07-26 19:53:34` |
| Reporter | `smica83` |
| Tags | `CVE-2025-8088, rar, UKR` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a3173e20eb1508b5ae29dabfda043c9` |
| SHA-1 | `a11d24b6b07aeadc4ed293358f541b448c24f884` |
| SHA-256 | `41986e5a10e7d708d74a8758a0dfc543fcaae48fe238a4b82194da0292338c14` |
| SHA3-384 | `7ba22ff800a471ccce06023c650d0f7646014d30bb70e0d0f2d6ea80302130b7a98306aeaa9e79655910ac460351414d` |
| TLSH | `T1C9B3F129EC884A99D7C0B6B4E9D370372B1106E29E742317D3C1DB883AEA95D658F8C5` |
| SSDEEP | `3072:GjUvx7Gn1QNN7MU5oUUKkdYU8Zzb/wE/ehkgwwRx51v:GepK1c7MU5WYU8Zzb/wh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_41986e5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41986e5a10e7d708d74a8758a0dfc543fcaae48fe238a4b82194da0292338c14"
    family = "unknown"
    file_name = "Lobby+X.rar"
    file_type = "rar"
    first_seen = "2026-07-26 19:53:34"
  condition:
    hash.sha256(0, filesize) == "41986e5a10e7d708d74a8758a0dfc543fcaae48fe238a4b82194da0292338c14"
}
```

### Sample 84: `732b8cf362f486b7`

| Field | Value |
|---|---|
| SHA-256 | `732b8cf362f486b7569eaa85d9e39f71fe1438ba68214300a9b33c204c447264` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-26 19:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9cca1ed778b5b2450d7010cb1a024535` |
| SHA-1 | `00b0292f6e85a6e31efb3c223626dbff9d42612b` |
| SHA-256 | `732b8cf362f486b7569eaa85d9e39f71fe1438ba68214300a9b33c204c447264` |
| SHA3-384 | `c1c5389cbaaea2fee47de5b13cfa04170a019ef09ba1561a5a50226952984acdbf5071b698168f6e822f674bcf597b1a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D2E63348B5E021EAD2B3513CEDA11595E872F1725772C5DB07E847B86C2B1E08E3DB2B` |
| SSDEEP | `393216:8qbk6dy0JDwNo87jH3w3SFQTsXMCHWUjX1cuI3/PGTAI:8R6E0Dg5bKAXMb8XCH/O7` |
| ICON-DHASH | `a078e0e0d8f8f03a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_732b8cf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "732b8cf362f486b7569eaa85d9e39f71fe1438ba68214300a9b33c204c447264"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 19:52:30"
  condition:
    hash.sha256(0, filesize) == "732b8cf362f486b7569eaa85d9e39f71fe1438ba68214300a9b33c204c447264"
}
```

### Sample 85: `6e795be8d4f34f79`

| Field | Value |
|---|---|
| SHA-256 | `6e795be8d4f34f798012d46530c62843dbb74c7cc64fd3a2db37ff68c85f52b8` |
| Family label | `ValleyRAT` |
| File name | `6399E481BEE00F73CF825B0DCE1FC30B.exe` |
| File type | `exe` |
| First seen | `2026-07-26 19:45:08` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6399e481bee00f73cf825b0dce1fc30b` |
| SHA-1 | `ff77c50195d619514562aee94de25a4a9323d0c7` |
| SHA-256 | `6e795be8d4f34f798012d46530c62843dbb74c7cc64fd3a2db37ff68c85f52b8` |
| SHA3-384 | `7d99abc485beb02ba9257ae1b67b2446e98ab3dfe5d54aa36c96fa8ccadc7a2ce3cf24f398be843a5ad2bf2a4a9a9da1` |
| IMPHASH | `2e526d5d63c1e746ac85952051c8bc45` |
| TLSH | `T172E38C20B5C1C473C8B6283149E4EA75963DF8725F2059DB63881BFD9E302D1AB3DA67` |
| SSDEEP | `3072:Bz3EDHbOGYzbn0rtsMpxDC0XNXPgOc4rnHBFpGzIEIJOV85u0VMNYM:Bry7OGYX05sIY0XNPgd4HBFYz1qRM` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_085_6e795be8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e795be8d4f34f798012d46530c62843dbb74c7cc64fd3a2db37ff68c85f52b8"
    family = "ValleyRAT"
    file_name = "6399E481BEE00F73CF825B0DCE1FC30B.exe"
    file_type = "exe"
    first_seen = "2026-07-26 19:45:08"
  condition:
    hash.sha256(0, filesize) == "6e795be8d4f34f798012d46530c62843dbb74c7cc64fd3a2db37ff68c85f52b8"
}
```

### Sample 86: `90233ccbb540fad9`

| Field | Value |
|---|---|
| SHA-256 | `90233ccbb540fad9ec81ca3ae88266ed2df968f559a64bcc133ea5875ac7e2c0` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-07-26 19:42:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4ab5bdc2dcb031b43ad0a41df487ce5` |
| SHA-1 | `aa323314cb7224410bb1b68fbdb9d327a5c8e558` |
| SHA-256 | `90233ccbb540fad9ec81ca3ae88266ed2df968f559a64bcc133ea5875ac7e2c0` |
| SHA3-384 | `9dbafe6eb9e7ffa41c48d4f84e05e54cd1d9eee70bb6d0089d14e384f430660cbf8f37bdd25a90ae14041a0bd1efa58d` |
| TLSH | `T119730A91BD82566FC6D0637FFA5F528D332563E8C2DE3223D9258B11338A51F0977AA0` |
| TELFHASH | `t181f08b04fe768e1948f29a71ccbd17a0d507522761a21720ef56cae08c3e458f30891d` |
| SSDEEP | `1536:EjqHGilvIQ92VEAl/sywGoQvmGtPzygfPS2mWffIydIy:xGwb2VEAl/bwCvGUKePX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_90233ccb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90233ccbb540fad9ec81ca3ae88266ed2df968f559a64bcc133ea5875ac7e2c0"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-07-26 19:42:53"
  condition:
    hash.sha256(0, filesize) == "90233ccbb540fad9ec81ca3ae88266ed2df968f559a64bcc133ea5875ac7e2c0"
}
```

### Sample 87: `158089dcc6e71e5f`

| Field | Value |
|---|---|
| SHA-256 | `158089dcc6e71e5f6dd212dfdb7657414f3eb540aefed1d82c6b9b56195956f4` |
| Family label | `unknown` |
| File name | `payload.sh` |
| File type | `sh` |
| First seen | `2026-07-26 19:40:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f79d2e1d04a85fa522d1d0252e671a26` |
| SHA-1 | `29d5a93ebd81bbcbf84f442be87d875062a6ab4a` |
| SHA-256 | `158089dcc6e71e5f6dd212dfdb7657414f3eb540aefed1d82c6b9b56195956f4` |
| SHA3-384 | `2980dcfe83840bae56a131ba59e1b835d24aef9ab67d0c94f9c1ab2a0754eba511deb22d63459c7637eb908b02844ba7` |
| TLSH | `T14631449F405814099E478D01F075EBBF722BEFBD93B57709DA8A26739288B6030716DD` |
| SSDEEP | `48:aOc4LgshXAbxBp9C+C/CRyDqHTCDW1sVkF8:aOc4LgshXAbxv9T0ayDSTCDW1sVkF8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_158089dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "158089dcc6e71e5f6dd212dfdb7657414f3eb540aefed1d82c6b9b56195956f4"
    family = "unknown"
    file_name = "payload.sh"
    file_type = "sh"
    first_seen = "2026-07-26 19:40:52"
  condition:
    hash.sha256(0, filesize) == "158089dcc6e71e5f6dd212dfdb7657414f3eb540aefed1d82c6b9b56195956f4"
}
```

### Sample 88: `a1603956bbcef1b3`

| Field | Value |
|---|---|
| SHA-256 | `a1603956bbcef1b38c55082a22754f04203fae16b24b7ad868413184ba68a08b` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-07-26 19:28:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b4921807b9cff4d7c6ff7ac6f338d90` |
| SHA-1 | `83cf27b425d8b826968f7ce51eda4c9096b082ca` |
| SHA-256 | `a1603956bbcef1b38c55082a22754f04203fae16b24b7ad868413184ba68a08b` |
| SHA3-384 | `2f07d3d36dc34a742dddeba9a7df9502af8dd389c03a7f290446a18bc7be64ffc567f3661723af542e44e0e7d63f0875` |
| TLSH | `T1A2144AC3F900DDBDF80AE33744134916B130B7A214925B37B297797BE93A19A0577E8A` |
| SSDEEP | `3072:IYvBkWzBnJcKu7Lpn90LyQQraqpWlIgOeLD3dVpjbidL0EfrPy9fkhKTD:dBkWdJcKJDQraMW82D3AL0oy9hTD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_a1603956
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1603956bbcef1b38c55082a22754f04203fae16b24b7ad868413184ba68a08b"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-07-26 19:28:55"
  condition:
    hash.sha256(0, filesize) == "a1603956bbcef1b38c55082a22754f04203fae16b24b7ad868413184ba68a08b"
}
```

### Sample 89: `9346840245721eca`

| Field | Value |
|---|---|
| SHA-256 | `9346840245721ecabe3bbf50b9c55882b7bb99e978d30329c1f9be9a19f6e61f` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-07-26 19:26:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `980a95174e1b4b381c764ce52e80d8d6` |
| SHA-1 | `4064c69afa49c8bbb822b6e07999678d7b985f93` |
| SHA-256 | `9346840245721ecabe3bbf50b9c55882b7bb99e978d30329c1f9be9a19f6e61f` |
| SHA3-384 | `7ff83cc1ead63435dbc5584ada591bf1e4dd0a19251e93a6591baa44455a76ba8d4a9d4373c1b0977ed5648a673521b0` |
| TLSH | `T14FD39FC1E743D0F5E85605F01037A7219B7AD43A983AFB52DB692E31AC72A819F1B35C` |
| TELFHASH | `t1455125f92aba0cec6b809c46a24a5b117e0a577f386033b718735435337be45867bc39` |
| SSDEEP | `3072:sOmi2V/36JDFK3fBbsn01d2qB4GAs8iE:sOm5/KOvBtB1H4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_93468402
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9346840245721ecabe3bbf50b9c55882b7bb99e978d30329c1f9be9a19f6e61f"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-07-26 19:26:55"
  condition:
    hash.sha256(0, filesize) == "9346840245721ecabe3bbf50b9c55882b7bb99e978d30329c1f9be9a19f6e61f"
}
```

### Sample 90: `79c7de724b8d91a5`

| Field | Value |
|---|---|
| SHA-256 | `79c7de724b8d91a50fd7cf1d4bb572fedba37d33f9e705ce37957af43c0e8b9c` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-26 19:22:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8488bddda51e1c92d0977499a348ccb` |
| SHA-1 | `9d33aedff877aff887020cdfe756ee1fb3407b13` |
| SHA-256 | `79c7de724b8d91a50fd7cf1d4bb572fedba37d33f9e705ce37957af43c0e8b9c` |
| SHA3-384 | `e8eac4d0e216b6ccbc5f79198f4397a6f3083fb092b11eadd0ea021055fdc2d6f658905d915914dad3feb3daa746c393` |
| TLSH | `T1CBC28D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:88vCB+25j6es8Ru9FYpMSUpi+20qUpi+20YQX:88l25JId2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_79c7de72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79c7de724b8d91a50fd7cf1d4bb572fedba37d33f9e705ce37957af43c0e8b9c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-26 19:22:53"
  condition:
    hash.sha256(0, filesize) == "79c7de724b8d91a50fd7cf1d4bb572fedba37d33f9e705ce37957af43c0e8b9c"
}
```

### Sample 91: `ee1e2234a51bbba1`

| Field | Value |
|---|---|
| SHA-256 | `ee1e2234a51bbba1bfdf4726fc06c351b2dbc3a952215e608e9e4a5874e380f2` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-07-26 19:20:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `450d55b930f11faed9ad2a2fd8e38948` |
| SHA-1 | `fd7ab4a722faeec3e948910b70fb8e1c1db00647` |
| SHA-256 | `ee1e2234a51bbba1bfdf4726fc06c351b2dbc3a952215e608e9e4a5874e380f2` |
| SHA3-384 | `852819c8b8a5d36dc5d5b768c33b5e91c5b023145298b2057ae55c5da79e244281450d7dc2850a5cfd34c4e21586b39c` |
| TLSH | `T139F38C67D8356E6CD224E4B0F4319F7D2B53D66180931FAAA9A7C6748047DCCF6093B8` |
| SSDEEP | `3072:Ldbbj+N1D9ffVuY14vn/j8It7YWLh6aFiiz:Ldu93AY14vn7hBLxFP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_ee1e2234
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee1e2234a51bbba1bfdf4726fc06c351b2dbc3a952215e608e9e4a5874e380f2"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-07-26 19:20:54"
  condition:
    hash.sha256(0, filesize) == "ee1e2234a51bbba1bfdf4726fc06c351b2dbc3a952215e608e9e4a5874e380f2"
}
```

### Sample 92: `b29b34738355449c`

| Field | Value |
|---|---|
| SHA-256 | `b29b34738355449cfc0609602966074d6dbeac2c6335a3c16f31124b72c34eb1` |
| Family label | `unknown` |
| File name | `x` |
| File type | `sh` |
| First seen | `2026-07-26 19:20:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac0e671bc3520c6dfb2597ed3a8c67b1` |
| SHA-1 | `bbcc5ca472940d57ef0438c553dfeddd0035d771` |
| SHA-256 | `b29b34738355449cfc0609602966074d6dbeac2c6335a3c16f31124b72c34eb1` |
| SHA3-384 | `aadeb6e05e92b6a9b65d6a4465689dd9902272b175647c21150753fbc0b0a517977841f6c39ed9f454c75a49a306748c` |
| TLSH | `T1A77273F0F92C983637CD6538F25D990899C35C3E1AAB3630502BEE54051DB5A732DB7A` |
| SSDEEP | `192:i+1gso1gjix8Sj1VAEBUADGP/6B0i1gh4BuWKTT5GqkgA:BTiWqA4UADAZdhQuW5r` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_b29b3473
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b29b34738355449cfc0609602966074d6dbeac2c6335a3c16f31124b72c34eb1"
    family = "unknown"
    file_name = "x"
    file_type = "sh"
    first_seen = "2026-07-26 19:20:53"
  condition:
    hash.sha256(0, filesize) == "b29b34738355449cfc0609602966074d6dbeac2c6335a3c16f31124b72c34eb1"
}
```

### Sample 93: `83554baeeb700815`

| Field | Value |
|---|---|
| SHA-256 | `83554baeeb700815f9b6492584a1b1a40c64f752d1ff1a67cde079ad524b008f` |
| Family label | `RemusStealer` |
| File name | `dd_Pkg_09_yrxp12x2.exe` |
| File type | `exe` |
| First seen | `2026-07-26 19:18:08` |
| Reporter | `CNGaoLing` |
| Tags | `exe, RAT, RemusStealer, XAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ae6397d898c18b1356dedcbe225e639` |
| SHA-1 | `8ddc91dd3c92113e654815c91c9accde8170dde1` |
| SHA-256 | `83554baeeb700815f9b6492584a1b1a40c64f752d1ff1a67cde079ad524b008f` |
| SHA3-384 | `29c5f9089416ce6d1fda77214b7a7fc36034eff5a59b9599e3bc6ca16ef767b0b6e8313c117e0878ee18565cbc20c157` |
| IMPHASH | `573bb7b41bc641bd95c0f5eec13c233b` |
| TLSH | `T1692733289FEDE638C19647B6C7945A34CDA908C911DC7277934D2F13EEC3A2A507B1B8` |
| SSDEEP | `393216:WBuh88jMY2LToqSLIGug8C+U1C39YGOFEEV6DnyPQTKH1OZVozeXo80BkpiQv8v:WSwYOOvu/CmY1FE1jWQTY5C0mRvE` |
| ICON-DHASH | `686c74f4c2e8e4e0` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_093_83554bae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83554baeeb700815f9b6492584a1b1a40c64f752d1ff1a67cde079ad524b008f"
    family = "RemusStealer"
    file_name = "dd_Pkg_09_yrxp12x2.exe"
    file_type = "exe"
    first_seen = "2026-07-26 19:18:08"
  condition:
    hash.sha256(0, filesize) == "83554baeeb700815f9b6492584a1b1a40c64f752d1ff1a67cde079ad524b008f"
}
```

### Sample 94: `0ce97c6a160fab6d`

| Field | Value |
|---|---|
| SHA-256 | `0ce97c6a160fab6db1246fd2f4fc0a932b2ada179e42a2d66005e2dbb3a6a8ae` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-07-26 19:12:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7772434e4d86715756c3b5844ec46f9` |
| SHA-1 | `bb2ca764d73257c4c78277e7b99cd27eff4c9904` |
| SHA-256 | `0ce97c6a160fab6db1246fd2f4fc0a932b2ada179e42a2d66005e2dbb3a6a8ae` |
| SHA3-384 | `c8c61489b65e4f3d8f400a5b0536d24546847285f0751e7c6c59981bfe0d1cbd7097915e860d661c199e79ed9bda49ef` |
| TLSH | `T18D042A45F8808A17C6D652BBFB4E428D372A67A8D3EE7107DD215F21378B96B0E37241` |
| TELFHASH | `t10ba00215cb441dc775449159eae5d0b90c6217411690140696295ccf2ed764000b1593` |
| SSDEEP | `3072:UzBy+V95RRwNROuUw8hsXej8CD44ZU3csF6NnAfADBgR:C/RU0rIG44Z6csFZoDE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_0ce97c6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ce97c6a160fab6db1246fd2f4fc0a932b2ada179e42a2d66005e2dbb3a6a8ae"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-07-26 19:12:57"
  condition:
    hash.sha256(0, filesize) == "0ce97c6a160fab6db1246fd2f4fc0a932b2ada179e42a2d66005e2dbb3a6a8ae"
}
```

### Sample 95: `83b8de55cd477c75`

| Field | Value |
|---|---|
| SHA-256 | `83b8de55cd477c75eac4280e38ab0c4184f0b43de7467729d4acd6d1830ecc95` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-07-26 19:03:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5427516930974c7f43189c4cd94522a5` |
| SHA-1 | `6ae9a5e0de8424cf88133470314dce66fa71c7b4` |
| SHA-256 | `83b8de55cd477c75eac4280e38ab0c4184f0b43de7467729d4acd6d1830ecc95` |
| SHA3-384 | `6e003881adbf64cf7b7e2c412660e6cef5f7126aa6dc3d27e3a171856deb4bf46eab2795c33924d8e601843ce7833b40` |
| TLSH | `T1CD442946FA404A13C4D617B9FA9F42453333E768D3EB73069928AFB43BC775A0E62605` |
| TELFHASH | `t168410b718b2415266a61dc14caee93a2241edb075344fe33df22c48c280944fe62bc4f` |
| SSDEEP | `6144:NiW98sKU6NdkCZILad8guAUc6YfdkxvtEHxdjEV/GCemx2cLis:NiW98E6ICZILad8guAUc6kdmVwk/hemX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_83b8de55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83b8de55cd477c75eac4280e38ab0c4184f0b43de7467729d4acd6d1830ecc95"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-07-26 19:03:02"
  condition:
    hash.sha256(0, filesize) == "83b8de55cd477c75eac4280e38ab0c4184f0b43de7467729d4acd6d1830ecc95"
}
```

### Sample 96: `59a9721c8214ef99`

| Field | Value |
|---|---|
| SHA-256 | `59a9721c8214ef997096498c44dcf5f122e1c604b6f248456e8dc430e7512fdb` |
| Family label | `unknown` |
| File name | `59a9721c8214ef997096498c44dcf5f122e1c604b6f248456e8dc430e7512fdb` |
| File type | `elf` |
| First seen | `2026-07-26 19:00:26` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e91defa2add4b9bec7259f7b75049843` |
| SHA-1 | `f8488b88ecbe9d0dbe6263dda369a9325c194467` |
| SHA-256 | `59a9721c8214ef997096498c44dcf5f122e1c604b6f248456e8dc430e7512fdb` |
| SHA3-384 | `aa8e82e9c2ed1a7b03df84be3cd118c1426aff823d58abeb32d065505803abb51c3e969b3e422c537af224cf05d3f4a4` |
| TLSH | `T1E7D68C77914238E9E5A98CB4D11025426DBC388B5738A3C7BAC471F667BA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQQ:cqYUQuVDt0TZE7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_59a9721c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59a9721c8214ef997096498c44dcf5f122e1c604b6f248456e8dc430e7512fdb"
    family = "unknown"
    file_name = "59a9721c8214ef997096498c44dcf5f122e1c604b6f248456e8dc430e7512fdb"
    file_type = "elf"
    first_seen = "2026-07-26 19:00:26"
  condition:
    hash.sha256(0, filesize) == "59a9721c8214ef997096498c44dcf5f122e1c604b6f248456e8dc430e7512fdb"
}
```

### Sample 97: `f02758770d616fc8`

| Field | Value |
|---|---|
| SHA-256 | `f02758770d616fc8ff7ddbe5caf069d4bbd2bae5422a32a95cfa8c7f6a0a9b8d` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-26 18:52:28` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbe604a519a46c1d97c48853b7666886` |
| SHA-1 | `288671a4f0294228030d12bc8d7b2add26d24a37` |
| SHA-256 | `f02758770d616fc8ff7ddbe5caf069d4bbd2bae5422a32a95cfa8c7f6a0a9b8d` |
| SHA3-384 | `78aa11b7653f9c1a1f2a158caa6b052ba3e4087937f99e474643292449ce194b58190b1f501673d14c4113c5897f947d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1BBE6330CABF901FEEA734279CDB185A5E864B4735B72D18B0B9843A21D272E14D3D717` |
| SSDEEP | `393216:XmRnr5q552TiIWV3LaPGuBmrhNOXMCHWUjXOcuI3/PGTAI:XmNU5gTijVu8GXMb8XjH/O7` |
| ICON-DHASH | `e8e864e0d8e8e848` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_f0275877
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f02758770d616fc8ff7ddbe5caf069d4bbd2bae5422a32a95cfa8c7f6a0a9b8d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 18:52:28"
  condition:
    hash.sha256(0, filesize) == "f02758770d616fc8ff7ddbe5caf069d4bbd2bae5422a32a95cfa8c7f6a0a9b8d"
}
```

### Sample 98: `6d9bd1e24e5f6bbd`

| Field | Value |
|---|---|
| SHA-256 | `6d9bd1e24e5f6bbdb0ae30a6a8de25043b658865f2ad2a84da382966689cdbee` |
| Family label | `RemusStealer` |
| File name | `?????.exe` |
| File type | `exe` |
| First seen | `2026-07-26 18:50:58` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfe122e52e61f9f83c32cd079e60e3a4` |
| SHA-1 | `b2ed0f05bd388e35f48601b37a4586b7bf1d6cd2` |
| SHA-256 | `6d9bd1e24e5f6bbdb0ae30a6a8de25043b658865f2ad2a84da382966689cdbee` |
| SHA3-384 | `ec2c22de1c3555e823c829491920cc536560b715e41fe286f9249aa96cefc6bdfebe9ba5e4fa8ec96d6dfcefa88127fd` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T152B55A07BCE149E9C4AA933289B656917B71BC084F3223D72E90B7782F72BD09D35B54` |
| SSDEEP | `24576:Anj8OfE75DXP/bm3zJwU8XQg+WLTFVgu34Y4AzwKSkfMsNTll78LLqJBele5r92O:AnjHfgD3b+JwbnzLTFVteqwRkrNjYwJ3` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_098_6d9bd1e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d9bd1e24e5f6bbdb0ae30a6a8de25043b658865f2ad2a84da382966689cdbee"
    family = "RemusStealer"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-07-26 18:50:58"
  condition:
    hash.sha256(0, filesize) == "6d9bd1e24e5f6bbdb0ae30a6a8de25043b658865f2ad2a84da382966689cdbee"
}
```

### Sample 99: `23fee915a2ede0fa`

| Field | Value |
|---|---|
| SHA-256 | `23fee915a2ede0fa0ca36b1590ef0319703f58fbeaca1d5cfdef77ebf470582d` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-26 18:49:45` |
| Reporter | `iamaachum` |
| Tags | `exe, up4pc-com, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6d3bf3ffcb43ecf26ac0a5319aa75b7` |
| SHA-1 | `162779abe15588612cdde42f43ff1aa0d2a9ec76` |
| SHA-256 | `23fee915a2ede0fa0ca36b1590ef0319703f58fbeaca1d5cfdef77ebf470582d` |
| SHA3-384 | `53e4f2dddd6dedcdc1edda675d351e647768e4f66da76d285fe405be73eb51f33f264632192b185d095f6247267d2b80` |
| IMPHASH | `dcef13196d9946b892f62428821e6df6` |
| TLSH | `T1CBE32913E29370FCC117C1B8459A5772FA31B8254324AE7EB7ACDA712F11E607E29B25` |
| SSDEEP | `3072:j0/zFkHuTJyJDwh9rxOvsq9ow7LAQqEsdUWPPhhSGc:jmJwDwh65oAAQZNWHhbc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_23fee915
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23fee915a2ede0fa0ca36b1590ef0319703f58fbeaca1d5cfdef77ebf470582d"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-26 18:49:45"
  condition:
    hash.sha256(0, filesize) == "23fee915a2ede0fa0ca36b1590ef0319703f58fbeaca1d5cfdef77ebf470582d"
}
```

### Sample 100: `94e381ba36dcbf27`

| Field | Value |
|---|---|
| SHA-256 | `94e381ba36dcbf27e4907f9049eff1a8694dfafd4af899be0bed6b781f13b5ac` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-26 18:48:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1005d9b43af652c2dd5b8942ac78972` |
| SHA-1 | `40433f49ac6459c4340ca78265ba19fa79ac36ac` |
| SHA-256 | `94e381ba36dcbf27e4907f9049eff1a8694dfafd4af899be0bed6b781f13b5ac` |
| SHA3-384 | `acce39409bcbac61f836e62d9d429fc8be561b5054fa5027d36b52d7eb2a1887747891e2b130c82a49c3f421dbde0714` |
| TLSH | `T102C27CA56A867C44BEC94A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C15FACD618B1A` |
| SSDEEP | `768:R8vCB+25j6es8RL9FYpMSUpi+20qUpi+20YQX:R8l25Jdd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_94e381ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94e381ba36dcbf27e4907f9049eff1a8694dfafd4af899be0bed6b781f13b5ac"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-26 18:48:58"
  condition:
    hash.sha256(0, filesize) == "94e381ba36dcbf27e4907f9049eff1a8694dfafd4af899be0bed6b781f13b5ac"
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
 * Generated: 2026-07-27T04:07:40.676294+00:00
 */

rule MalwareBazaar_unknown_001_8230ecb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8230ecb782d68b44a91d1dab3b65f98324e653efc0c8529c4e81cb762cc8e179"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 03:52:32"
  condition:
    hash.sha256(0, filesize) == "8230ecb782d68b44a91d1dab3b65f98324e653efc0c8529c4e81cb762cc8e179"
}

rule MalwareBazaar_unknown_002_b9605d53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9605d53a902f60867aca67f42ac7a53222edd2463c3936c5c3c9e75a457a7dc"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-27 03:49:55"
  condition:
    hash.sha256(0, filesize) == "b9605d53a902f60867aca67f42ac7a53222edd2463c3936c5c3c9e75a457a7dc"
}

rule MalwareBazaar_AsyncRAT_003_85a229fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85a229fa75bcf5ef41066bb0618ade943cba3b72c377fee22bc2ff94dfaf4160"
    family = "AsyncRAT"
    file_name = "F8BETAPP.exe"
    file_type = "exe"
    first_seen = "2026-07-27 03:18:58"
  condition:
    hash.sha256(0, filesize) == "85a229fa75bcf5ef41066bb0618ade943cba3b72c377fee22bc2ff94dfaf4160"
}

rule MalwareBazaar_unknown_004_00ec97c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00ec97c78c9c4fc27f8beda4ffe27d4f4cb98b0208e13b7a1652d6c1e120cd76"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 02:52:33"
  condition:
    hash.sha256(0, filesize) == "00ec97c78c9c4fc27f8beda4ffe27d4f4cb98b0208e13b7a1652d6c1e120cd76"
}

rule MalwareBazaar_unknown_005_e594838e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e594838ef765312d60475677ec54bf23a4fad659aad928f4564d49890ee9c23b"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 01:52:34"
  condition:
    hash.sha256(0, filesize) == "e594838ef765312d60475677ec54bf23a4fad659aad928f4564d49890ee9c23b"
}

rule MalwareBazaar_unknown_006_56f8e042
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56f8e042eeb5e75508be62a8add15ea8552b08fde09a112cc7acfc67d49fe7c3"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-27 01:41:54"
  condition:
    hash.sha256(0, filesize) == "56f8e042eeb5e75508be62a8add15ea8552b08fde09a112cc7acfc67d49fe7c3"
}

rule MalwareBazaar_unknown_007_c67e82ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c67e82aed910bc4706a7da1675284bfa90f5c9371d596f541a575fdcc02e36f7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-27 01:39:54"
  condition:
    hash.sha256(0, filesize) == "c67e82aed910bc4706a7da1675284bfa90f5c9371d596f541a575fdcc02e36f7"
}

rule MalwareBazaar_RemcosRAT_008_268b8fdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "268b8fdf9834f2c6ad8149b2aa56fad90403c91964ed813609a92b7454ecf34f"
    family = "RemcosRAT"
    file_name = "QU20262707.vbs"
    file_type = "vbs"
    first_seen = "2026-07-27 01:26:02"
  condition:
    hash.sha256(0, filesize) == "268b8fdf9834f2c6ad8149b2aa56fad90403c91964ed813609a92b7454ecf34f"
}

rule MalwareBazaar_unknown_009_f29c23e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f29c23e3ce0a393d9cd5927b4873e8b9a4a8800e4a1270abfd8f279ae4041729"
    family = "unknown"
    file_name = "nz.sh"
    file_type = "sh"
    first_seen = "2026-07-27 01:09:54"
  condition:
    hash.sha256(0, filesize) == "f29c23e3ce0a393d9cd5927b4873e8b9a4a8800e4a1270abfd8f279ae4041729"
}

rule MalwareBazaar_unknown_010_51403e76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51403e760e00cb8ad725cc3404154a324c604204f061e285c513d03011f1ac2e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-27 01:07:58"
  condition:
    hash.sha256(0, filesize) == "51403e760e00cb8ad725cc3404154a324c604204f061e285c513d03011f1ac2e"
}

rule MalwareBazaar_unknown_011_c29fb2bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c29fb2bdcaefee9681b1b7ab1f85e610c9218918a11591bb63f553ccd6f5077a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 00:52:28"
  condition:
    hash.sha256(0, filesize) == "c29fb2bdcaefee9681b1b7ab1f85e610c9218918a11591bb63f553ccd6f5077a"
}

rule MalwareBazaar_unknown_012_84742f07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84742f0748a01c59931925dd2e1da61624c78fd115aad38a6acd1b48ee9d0fd1"
    family = "unknown"
    file_name = "HeartProblemsFanGame.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:50:20"
  condition:
    hash.sha256(0, filesize) == "84742f0748a01c59931925dd2e1da61624c78fd115aad38a6acd1b48ee9d0fd1"
}

rule MalwareBazaar_RemusStealer_013_7b092a35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b092a35e70113f5165a653135cb3a7ca29312ceb0b4a874c160473d30830a60"
    family = "RemusStealer"
    file_name = "R2.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:40:55"
  condition:
    hash.sha256(0, filesize) == "7b092a35e70113f5165a653135cb3a7ca29312ceb0b4a874c160473d30830a60"
}

rule MalwareBazaar_unknown_014_bcd7660c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcd7660ccc0b839dd001bce86a2ba33a6777e644be12fae5ddc3df87a767e76e"
    family = "unknown"
    file_name = "pty10"
    file_type = "elf"
    first_seen = "2026-07-27 00:39:57"
  condition:
    hash.sha256(0, filesize) == "bcd7660ccc0b839dd001bce86a2ba33a6777e644be12fae5ddc3df87a767e76e"
}

rule MalwareBazaar_unknown_015_14acb457
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14acb457792a4857aa226eb7cc24bdbe8642adf896e3905a79d09e4dd9e9e511"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-27 00:39:56"
  condition:
    hash.sha256(0, filesize) == "14acb457792a4857aa226eb7cc24bdbe8642adf896e3905a79d09e4dd9e9e511"
}

rule MalwareBazaar_unknown_016_35392a98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35392a9849d7e9dfb4ee700a16700a94883fde859d57fdd891631bdbc6a75db0"
    family = "unknown"
    file_name = "crazy.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:38:17"
  condition:
    hash.sha256(0, filesize) == "35392a9849d7e9dfb4ee700a16700a94883fde859d57fdd891631bdbc6a75db0"
}

rule MalwareBazaar_RemusStealer_017_c431caed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c431caed57d9d7699aa519790582595c96224c0f00bee914f8c4ee2252495e23"
    family = "RemusStealer"
    file_name = "beb.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:37:38"
  condition:
    hash.sha256(0, filesize) == "c431caed57d9d7699aa519790582595c96224c0f00bee914f8c4ee2252495e23"
}

rule MalwareBazaar_unknown_018_1bd26a5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bd26a5f04837e6b58262c5cef3a2de052928414bc5bcc1106861c3792ab595c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-27 00:21:55"
  condition:
    hash.sha256(0, filesize) == "1bd26a5f04837e6b58262c5cef3a2de052928414bc5bcc1106861c3792ab595c"
}

rule MalwareBazaar_unknown_019_4b7ff026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b7ff0262fe7d98cfd1c3ec38cb17d1aa7b66524be8fa2de0ce7a30a3d81fa38"
    family = "unknown"
    file_name = "wp-static-cache-fa39743a.php"
    file_type = "unknown"
    first_seen = "2026-07-27 00:19:05"
  condition:
    hash.sha256(0, filesize) == "4b7ff0262fe7d98cfd1c3ec38cb17d1aa7b66524be8fa2de0ce7a30a3d81fa38"
}

rule MalwareBazaar_unknown_020_c4ea0154
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4ea01549f1fe365652d0c9d839f54d8d8f42bf4182ad5389839908e8f2a5653"
    family = "unknown"
    file_name = "wp-static-cache-c1adaafb.php"
    file_type = "unknown"
    first_seen = "2026-07-27 00:18:28"
  condition:
    hash.sha256(0, filesize) == "c4ea01549f1fe365652d0c9d839f54d8d8f42bf4182ad5389839908e8f2a5653"
}

rule MalwareBazaar_unknown_021_de9efd03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de9efd031aef9caed59021a2c79356d875648426a921151e18db33ce75aeacff"
    family = "unknown"
    file_name = "wp-static-cache-7c197308.php"
    file_type = "unknown"
    first_seen = "2026-07-27 00:17:50"
  condition:
    hash.sha256(0, filesize) == "de9efd031aef9caed59021a2c79356d875648426a921151e18db33ce75aeacff"
}

rule MalwareBazaar_unknown_022_9626a88c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9626a88c8395f0bd5c34b1c09ba8571d56004945c8569d954841fceafc498ef6"
    family = "unknown"
    file_name = "browser.py"
    file_type = "py"
    first_seen = "2026-07-27 00:14:18"
  condition:
    hash.sha256(0, filesize) == "9626a88c8395f0bd5c34b1c09ba8571d56004945c8569d954841fceafc498ef6"
}

rule MalwareBazaar_unknown_023_2489a7c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2489a7c56d832faf097303f8f495f5d459e62c83eeff43b39ab3a3e6a66b8c5b"
    family = "unknown"
    file_name = "crypted.js"
    file_type = "js"
    first_seen = "2026-07-27 00:14:16"
  condition:
    hash.sha256(0, filesize) == "2489a7c56d832faf097303f8f495f5d459e62c83eeff43b39ab3a3e6a66b8c5b"
}

rule MalwareBazaar_unknown_024_4e40ac26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e40ac262149dde5d453c18cf700c384c846aa51dfcc5dcb9d57eac720b06d3f"
    family = "unknown"
    file_name = "BlossCraft-Launcher.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:14:13"
  condition:
    hash.sha256(0, filesize) == "4e40ac262149dde5d453c18cf700c384c846aa51dfcc5dcb9d57eac720b06d3f"
}

rule MalwareBazaar_unknown_025_d3e984f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3e984f5e189ae6cd49bafa6298418583acab68292390bb63f21deec50740310"
    family = "unknown"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:08:07"
  condition:
    hash.sha256(0, filesize) == "d3e984f5e189ae6cd49bafa6298418583acab68292390bb63f21deec50740310"
}

rule MalwareBazaar_RemusStealer_026_205fc663
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "205fc66381b8e254508d40c693a1314c9fc2b94b8023b29483803c8b0e449c4d"
    family = "RemusStealer"
    file_name = "R5.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:07:14"
  condition:
    hash.sha256(0, filesize) == "205fc66381b8e254508d40c693a1314c9fc2b94b8023b29483803c8b0e449c4d"
}

rule MalwareBazaar_RemusStealer_027_9e7fc86a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e7fc86ad3c5efb2e6746ab61dc43187eeb685c1fd9719bcb9553c173530f899"
    family = "RemusStealer"
    file_name = "R2.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:06:40"
  condition:
    hash.sha256(0, filesize) == "9e7fc86ad3c5efb2e6746ab61dc43187eeb685c1fd9719bcb9553c173530f899"
}

rule MalwareBazaar_RemusStealer_028_ece6e939
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ece6e9395edb8935c993a2945ac196a614149d65f10212e912e4654981646e37"
    family = "RemusStealer"
    file_name = "ojujn.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:06:07"
  condition:
    hash.sha256(0, filesize) == "ece6e9395edb8935c993a2945ac196a614149d65f10212e912e4654981646e37"
}

rule MalwareBazaar_RemusStealer_029_b0fb0119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0fb0119b9cce5b7aeef7f3499f5a71c5642c89f130daabc60822413cc2f5cd5"
    family = "RemusStealer"
    file_name = "KLLNMF.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:05:36"
  condition:
    hash.sha256(0, filesize) == "b0fb0119b9cce5b7aeef7f3499f5a71c5642c89f130daabc60822413cc2f5cd5"
}

rule MalwareBazaar_RemusStealer_030_0e13be37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e13be378b2ddf71bb66fbe2f90e4eeb241fe9fa92ef8e382320c86685f21d6f"
    family = "RemusStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:05:04"
  condition:
    hash.sha256(0, filesize) == "0e13be378b2ddf71bb66fbe2f90e4eeb241fe9fa92ef8e382320c86685f21d6f"
}

rule MalwareBazaar_unknown_031_f50688b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f50688b538fecc5ef7c893e148ddbb3cc1919fcb7c6462033fb72cb469242461"
    family = "unknown"
    file_name = "KLHdfs.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:04:28"
  condition:
    hash.sha256(0, filesize) == "f50688b538fecc5ef7c893e148ddbb3cc1919fcb7c6462033fb72cb469242461"
}

rule MalwareBazaar_RemusStealer_032_8fb184c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fb184c2d0b42adc0695d6dab31d7905490028c77d9a472d18c06975e19bf24a"
    family = "RemusStealer"
    file_name = "kJHGFDs.exe"
    file_type = "exe"
    first_seen = "2026-07-27 00:03:36"
  condition:
    hash.sha256(0, filesize) == "8fb184c2d0b42adc0695d6dab31d7905490028c77d9a472d18c06975e19bf24a"
}

rule MalwareBazaar_unknown_033_9ed7214d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ed7214d1a093fe7d3819b3143a17ce2a572662d55deebc6938a098cf8b0509d"
    family = "unknown"
    file_name = "9ed7214d1a093fe7d3819b3143a17ce2a572662d55deebc6938a098cf8b0509d"
    file_type = "sh"
    first_seen = "2026-07-27 00:00:39"
  condition:
    hash.sha256(0, filesize) == "9ed7214d1a093fe7d3819b3143a17ce2a572662d55deebc6938a098cf8b0509d"
}

rule MalwareBazaar_unknown_034_c51cdb75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c51cdb75acfe918b90165cbeb4b1acc466b3514b9adaac055556987c61939821"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 23:53:05"
  condition:
    hash.sha256(0, filesize) == "c51cdb75acfe918b90165cbeb4b1acc466b3514b9adaac055556987c61939821"
}

rule MalwareBazaar_RemusStealer_035_e440f3fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e440f3fbbd33d569432ddbc45ee7de8a19b1648de898c01329d5f3a404bde96d"
    family = "RemusStealer"
    file_name = "jhgkuyyg.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:55:18"
  condition:
    hash.sha256(0, filesize) == "e440f3fbbd33d569432ddbc45ee7de8a19b1648de898c01329d5f3a404bde96d"
}

rule MalwareBazaar_RemusStealer_036_f43b33aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f43b33aacb1d9f73ec3d687285c0e22ab6bafd6e5797106b711778aef073a9ca"
    family = "RemusStealer"
    file_name = "hnmh.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:54:43"
  condition:
    hash.sha256(0, filesize) == "f43b33aacb1d9f73ec3d687285c0e22ab6bafd6e5797106b711778aef073a9ca"
}

rule MalwareBazaar_RemusStealer_037_51bfb2f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51bfb2f390653647b087d789ef1559c3fdf220c565a909f1eee4d593893420dd"
    family = "RemusStealer"
    file_name = "hjbk.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:54:03"
  condition:
    hash.sha256(0, filesize) == "51bfb2f390653647b087d789ef1559c3fdf220c565a909f1eee4d593893420dd"
}

rule MalwareBazaar_unknown_038_7805b06f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7805b06ffc78058b2dd8f41155c9fc353c1267629aeaf3ee8f8e587fd11f013e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 22:52:30"
  condition:
    hash.sha256(0, filesize) == "7805b06ffc78058b2dd8f41155c9fc353c1267629aeaf3ee8f8e587fd11f013e"
}

rule MalwareBazaar_unknown_039_f52809d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f52809d57d816cf9ea7e95de64df46fcc1cf62d3da972c167497935b5eca74d7"
    family = "unknown"
    file_name = "crazy.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:52:12"
  condition:
    hash.sha256(0, filesize) == "f52809d57d816cf9ea7e95de64df46fcc1cf62d3da972c167497935b5eca74d7"
}

rule MalwareBazaar_Mirai_040_53afc067
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53afc0671b022a589954ba2a6755e1fb56a23552b7fb96740035d8c6fb59a780"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.16164.28322"
    file_type = "elf"
    first_seen = "2026-07-26 22:51:46"
  condition:
    hash.sha256(0, filesize) == "53afc0671b022a589954ba2a6755e1fb56a23552b7fb96740035d8c6fb59a780"
}

rule MalwareBazaar_Mirai_041_4f58256a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f58256a0e3199a31f42cfd1a9c2637625c8c3386b290ad4a95d5534af58c74d"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.6013.2947"
    file_type = "elf"
    first_seen = "2026-07-26 22:51:43"
  condition:
    hash.sha256(0, filesize) == "4f58256a0e3199a31f42cfd1a9c2637625c8c3386b290ad4a95d5534af58c74d"
}

rule MalwareBazaar_RemusStealer_042_b29391ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b29391ba505af508f2110f54f73b203e2710b8b6c8a8717005e5c7a4050630e1"
    family = "RemusStealer"
    file_name = "bjbh.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:51:36"
  condition:
    hash.sha256(0, filesize) == "b29391ba505af508f2110f54f73b203e2710b8b6c8a8717005e5c7a4050630e1"
}

rule MalwareBazaar_Mirai_043_602afb3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "602afb3c05b22b36d643010ec3e804728971d327537310301ce3890ae97a6aed"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.16164.28322"
    file_type = "elf"
    first_seen = "2026-07-26 22:51:06"
  condition:
    hash.sha256(0, filesize) == "602afb3c05b22b36d643010ec3e804728971d327537310301ce3890ae97a6aed"
}

rule MalwareBazaar_Mirai_044_527cb72a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "527cb72afb7644af363fa08aec91c3c1ab0f19535eb4d6b23fe57dfcb3a291e8"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.6013.2947"
    file_type = "elf"
    first_seen = "2026-07-26 22:51:05"
  condition:
    hash.sha256(0, filesize) == "527cb72afb7644af363fa08aec91c3c1ab0f19535eb4d6b23fe57dfcb3a291e8"
}

rule MalwareBazaar_RemusStealer_045_da7935af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da7935affcec91c317acf98b52eca551f2501b29ad502749e4c084492142c6eb"
    family = "RemusStealer"
    file_name = "beb.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:51:01"
  condition:
    hash.sha256(0, filesize) == "da7935affcec91c317acf98b52eca551f2501b29ad502749e4c084492142c6eb"
}

rule MalwareBazaar_RemusStealer_046_43e89a57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43e89a578fcb9e1cea02e64c24829936b9b47ef6f2acb4e033436f8d5d446168"
    family = "RemusStealer"
    file_name = "arFtU.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:50:28"
  condition:
    hash.sha256(0, filesize) == "43e89a578fcb9e1cea02e64c24829936b9b47ef6f2acb4e033436f8d5d446168"
}

rule MalwareBazaar_RemusStealer_047_33bd75f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33bd75f49eee1a5f86bf7f673573a28c14c45b8f8d1b91694b214a1ec3d6c333"
    family = "RemusStealer"
    file_name = "ARbeb.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:49:53"
  condition:
    hash.sha256(0, filesize) == "33bd75f49eee1a5f86bf7f673573a28c14c45b8f8d1b91694b214a1ec3d6c333"
}

rule MalwareBazaar_unknown_048_e15d8d51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e15d8d51a52da2c39d11d0409764821d2bc94794eea7ae3c8846b8ac078f4a0a"
    family = "unknown"
    file_name = "acr.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:49:09"
  condition:
    hash.sha256(0, filesize) == "e15d8d51a52da2c39d11d0409764821d2bc94794eea7ae3c8846b8ac078f4a0a"
}

rule MalwareBazaar_LummaStealer_049_a1101793
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1101793f851eb22dcffb2533be05bfd016e73b35e1ad2e35fc0d71d5099b52b"
    family = "LummaStealer"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:25:26"
  condition:
    hash.sha256(0, filesize) == "a1101793f851eb22dcffb2533be05bfd016e73b35e1ad2e35fc0d71d5099b52b"
}

rule MalwareBazaar_RemusStealer_050_5820e30b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5820e30bc1d4bf9db0b6eca0249754c99b514cfa52b78990487cbf98f7b55569"
    family = "RemusStealer"
    file_name = "R5.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:23:19"
  condition:
    hash.sha256(0, filesize) == "5820e30bc1d4bf9db0b6eca0249754c99b514cfa52b78990487cbf98f7b55569"
}

rule MalwareBazaar_RemusStealer_051_5cab5c36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cab5c362ded4c7795a68b94af56ff9922e15b4d343c7796bdc1c8338ac34887"
    family = "RemusStealer"
    file_name = "R2.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:22:42"
  condition:
    hash.sha256(0, filesize) == "5cab5c362ded4c7795a68b94af56ff9922e15b4d343c7796bdc1c8338ac34887"
}

rule MalwareBazaar_RemusStealer_052_239fa9a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "239fa9a692f16c74b8faa90e48099978b0aadeb90fb5b8aae1c4b3161d516190"
    family = "RemusStealer"
    file_name = "ojujn.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:22:02"
  condition:
    hash.sha256(0, filesize) == "239fa9a692f16c74b8faa90e48099978b0aadeb90fb5b8aae1c4b3161d516190"
}

rule MalwareBazaar_RemusStealer_053_7c8d18cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c8d18cc4785264f3a7d3423ebaeae8bf95d1ed9916dc4e6aab4f1f523747bdc"
    family = "RemusStealer"
    file_name = "KLLNMF.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:21:31"
  condition:
    hash.sha256(0, filesize) == "7c8d18cc4785264f3a7d3423ebaeae8bf95d1ed9916dc4e6aab4f1f523747bdc"
}

rule MalwareBazaar_RemusStealer_054_d84d9eb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d84d9eb1e140f0f320976cc8219a6fc31136a2a1d5b89a55f8fe6217b170ae74"
    family = "RemusStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:21:01"
  condition:
    hash.sha256(0, filesize) == "d84d9eb1e140f0f320976cc8219a6fc31136a2a1d5b89a55f8fe6217b170ae74"
}

rule MalwareBazaar_LummaStealer_055_bfe2c256
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfe2c25627eec3369b94ec60c1592e9cb38868f83f812a4ec506947d59ac8891"
    family = "LummaStealer"
    file_name = "KLHdfs.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:20:27"
  condition:
    hash.sha256(0, filesize) == "bfe2c25627eec3369b94ec60c1592e9cb38868f83f812a4ec506947d59ac8891"
}

rule MalwareBazaar_RemusStealer_056_55fa2ac1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55fa2ac196000639174619c5ff366119c874393cc4d3575533639cd409af1758"
    family = "RemusStealer"
    file_name = "kJHGFDs.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:19:27"
  condition:
    hash.sha256(0, filesize) == "55fa2ac196000639174619c5ff366119c874393cc4d3575533639cd409af1758"
}

rule MalwareBazaar_RemusStealer_057_0eaf541c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eaf541c66a2384ff77265a9e3e2bf11300d0c47642b1d953b52843e6365d659"
    family = "RemusStealer"
    file_name = "jhgkuyyg.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:18:39"
  condition:
    hash.sha256(0, filesize) == "0eaf541c66a2384ff77265a9e3e2bf11300d0c47642b1d953b52843e6365d659"
}

rule MalwareBazaar_RemusStealer_058_24cabe97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24cabe973a480c2a5a489500c2615c2cbe0399cd0087b04ba56d0e725043a6ca"
    family = "RemusStealer"
    file_name = "hnmh.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:17:17"
  condition:
    hash.sha256(0, filesize) == "24cabe973a480c2a5a489500c2615c2cbe0399cd0087b04ba56d0e725043a6ca"
}

rule MalwareBazaar_RemusStealer_059_6cd26345
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cd26345cc89c28c8ea226eb8ffa96be4f48af5fa369a403cdfb6fc46ff3ebef"
    family = "RemusStealer"
    file_name = "hjbk.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:12:34"
  condition:
    hash.sha256(0, filesize) == "6cd26345cc89c28c8ea226eb8ffa96be4f48af5fa369a403cdfb6fc46ff3ebef"
}

rule MalwareBazaar_unknown_060_85287c73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85287c739d9703b2909c65478ee803897192d43144d27a3ef3eb7c2dd7b3e393"
    family = "unknown"
    file_name = "crazy.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:11:50"
  condition:
    hash.sha256(0, filesize) == "85287c739d9703b2909c65478ee803897192d43144d27a3ef3eb7c2dd7b3e393"
}

rule MalwareBazaar_RemusStealer_061_3541431c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3541431ce10c1833122df54cb4478ebc1631c89ca373a5747c322350a60d6385"
    family = "RemusStealer"
    file_name = "bjbh.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:11:15"
  condition:
    hash.sha256(0, filesize) == "3541431ce10c1833122df54cb4478ebc1631c89ca373a5747c322350a60d6385"
}

rule MalwareBazaar_RemusStealer_062_1a1bdfcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a1bdfcbeec8791e79f8745a700a42a75dae7afd665a038da2b0d7812a0c0370"
    family = "RemusStealer"
    file_name = "beb.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:10:30"
  condition:
    hash.sha256(0, filesize) == "1a1bdfcbeec8791e79f8745a700a42a75dae7afd665a038da2b0d7812a0c0370"
}

rule MalwareBazaar_RemusStealer_063_a3e15e1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3e15e1e942f76b3d30cddd9f6cef8c91206b1a179871ce751613bf6efa2be5c"
    family = "RemusStealer"
    file_name = "arFtU.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:09:46"
  condition:
    hash.sha256(0, filesize) == "a3e15e1e942f76b3d30cddd9f6cef8c91206b1a179871ce751613bf6efa2be5c"
}

rule MalwareBazaar_RemusStealer_064_f30ce99a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f30ce99a34cfc61168a99aff2ad0463cf0dac2902f86b1e73d060a28499bcf7f"
    family = "RemusStealer"
    file_name = "ARbeb.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:08:41"
  condition:
    hash.sha256(0, filesize) == "f30ce99a34cfc61168a99aff2ad0463cf0dac2902f86b1e73d060a28499bcf7f"
}

rule MalwareBazaar_LummaStealer_065_f3761ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3761ae2ffb508e1df76e974692226ac38b368b213349e2969d72fc49f51ea7a"
    family = "LummaStealer"
    file_name = "acr.exe"
    file_type = "exe"
    first_seen = "2026-07-26 22:07:49"
  condition:
    hash.sha256(0, filesize) == "f3761ae2ffb508e1df76e974692226ac38b368b213349e2969d72fc49f51ea7a"
}

rule MalwareBazaar_Stealc_066_7f9e2dc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f9e2dc8918ea3f90d35ff18dd92963b81e331651d234d6373e269e036606762"
    family = "Stealc"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:52:43"
  condition:
    hash.sha256(0, filesize) == "7f9e2dc8918ea3f90d35ff18dd92963b81e331651d234d6373e269e036606762"
}

rule MalwareBazaar_unknown_067_43095747
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43095747bec46e0b016fe04caa8b447216e47eb788ad40e57f83fd2cd3b1d63a"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:52:36"
  condition:
    hash.sha256(0, filesize) == "43095747bec46e0b016fe04caa8b447216e47eb788ad40e57f83fd2cd3b1d63a"
}

rule MalwareBazaar_unknown_068_aa8e03ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa8e03cadb21e3939196e2658707563e7d6f1259b9d69f973b22ba494d1e49b4"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 21:52:30"
  condition:
    hash.sha256(0, filesize) == "aa8e03cadb21e3939196e2658707563e7d6f1259b9d69f973b22ba494d1e49b4"
}

rule MalwareBazaar_unknown_069_1e925e77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e925e77624c2db848d076f43d92f1acfdf832ff7ef48063f38088dd81e4c298"
    family = "unknown"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:43:35"
  condition:
    hash.sha256(0, filesize) == "1e925e77624c2db848d076f43d92f1acfdf832ff7ef48063f38088dd81e4c298"
}

rule MalwareBazaar_unknown_070_0a0b0186
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a0b01867e41bbd7e9863cbf839efb3a2f0963c2ccedd06c22c22beda6aafa19"
    family = "unknown"
    file_name = "MegaBasterd.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:23:55"
  condition:
    hash.sha256(0, filesize) == "0a0b01867e41bbd7e9863cbf839efb3a2f0963c2ccedd06c22c22beda6aafa19"
}

rule MalwareBazaar_unknown_071_12f1e8ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12f1e8ea44fae73b7636824985c04866d44dce4c76c203fe4c547d781416b900"
    family = "unknown"
    file_name = "Launcher.dmg"
    file_type = "dmg"
    first_seen = "2026-07-26 21:22:40"
  condition:
    hash.sha256(0, filesize) == "12f1e8ea44fae73b7636824985c04866d44dce4c76c203fe4c547d781416b900"
}

rule MalwareBazaar_unknown_072_e6016e68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6016e68b528ea80caa37afb5a283e88a78659ffea48d8fc297fad7676072324"
    family = "unknown"
    file_name = "Up4pc_Compressed_File_Download.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:20:31"
  condition:
    hash.sha256(0, filesize) == "e6016e68b528ea80caa37afb5a283e88a78659ffea48d8fc297fad7676072324"
}

rule MalwareBazaar_LummaStealer_073_e964b3d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e964b3d18222d68e19230c089fc7599f1d9fd6dc205fca13705c535feebe0627"
    family = "LummaStealer"
    file_name = "Build.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:19:29"
  condition:
    hash.sha256(0, filesize) == "e964b3d18222d68e19230c089fc7599f1d9fd6dc205fca13705c535feebe0627"
}

rule MalwareBazaar_unknown_074_ed401886
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed401886b771152687f6fc844e8c2c296705456e810a1ec5886c7065735f2951"
    family = "unknown"
    file_name = "encryptor.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:18:41"
  condition:
    hash.sha256(0, filesize) == "ed401886b771152687f6fc844e8c2c296705456e810a1ec5886c7065735f2951"
}

rule MalwareBazaar_unknown_075_53ba5fd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53ba5fd24bbf81d3a2fc53af19884b8ebb6344281891bdb78adb924a1f65b40b"
    family = "unknown"
    file_name = "chromelevator_arm64.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:17:56"
  condition:
    hash.sha256(0, filesize) == "53ba5fd24bbf81d3a2fc53af19884b8ebb6344281891bdb78adb924a1f65b40b"
}

rule MalwareBazaar_unknown_076_2d9346aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d9346aa5de94f207e93db952eeed52861b4b31a2c98899147c5fa59b2deee55"
    family = "unknown"
    file_name = "chromelevator_x64.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:16:22"
  condition:
    hash.sha256(0, filesize) == "2d9346aa5de94f207e93db952eeed52861b4b31a2c98899147c5fa59b2deee55"
}

rule MalwareBazaar_unknown_077_555e5544
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "555e5544368694f5726c77cf1a12e3f2d6d57479a00c462476ec552312a753a4"
    family = "unknown"
    file_name = "Megabasterd.exe"
    file_type = "exe"
    first_seen = "2026-07-26 21:14:13"
  condition:
    hash.sha256(0, filesize) == "555e5544368694f5726c77cf1a12e3f2d6d57479a00c462476ec552312a753a4"
}

rule MalwareBazaar_unknown_078_afaea860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afaea86058dc0a8475b6a07a7404e37624cf8a70aa9fb9f3a2038ec61862eb4c"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-26 21:11:55"
  condition:
    hash.sha256(0, filesize) == "afaea86058dc0a8475b6a07a7404e37624cf8a70aa9fb9f3a2038ec61862eb4c"
}

rule MalwareBazaar_unknown_079_5a6f57b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a6f57b0f7404d70c29e5c39b3bdd95064df4c4885f0fbbdcee41e438ff8444c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 20:52:30"
  condition:
    hash.sha256(0, filesize) == "5a6f57b0f7404d70c29e5c39b3bdd95064df4c4885f0fbbdcee41e438ff8444c"
}

rule MalwareBazaar_unknown_080_54117f39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54117f39ec10e191bd8d2513998c926cbd70e65f1aea9063f54801db1f046e11"
    family = "unknown"
    file_name = "jquery.min1.js"
    file_type = "zip"
    first_seen = "2026-07-26 20:23:30"
  condition:
    hash.sha256(0, filesize) == "54117f39ec10e191bd8d2513998c926cbd70e65f1aea9063f54801db1f046e11"
}

rule MalwareBazaar_unknown_081_279d04c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92"
    family = "unknown"
    file_name = "jquery.min.js"
    file_type = "zip"
    first_seen = "2026-07-26 20:22:05"
  condition:
    hash.sha256(0, filesize) == "279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92"
}

rule MalwareBazaar_unknown_082_64c25e91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64c25e91637c23fa8d29fcbe425b9649e8a2a917316892b855fdd279df82c081"
    family = "unknown"
    file_name = "Srv.exe"
    file_type = "exe"
    first_seen = "2026-07-26 19:58:19"
  condition:
    hash.sha256(0, filesize) == "64c25e91637c23fa8d29fcbe425b9649e8a2a917316892b855fdd279df82c081"
}

rule MalwareBazaar_unknown_083_41986e5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41986e5a10e7d708d74a8758a0dfc543fcaae48fe238a4b82194da0292338c14"
    family = "unknown"
    file_name = "Lobby+X.rar"
    file_type = "rar"
    first_seen = "2026-07-26 19:53:34"
  condition:
    hash.sha256(0, filesize) == "41986e5a10e7d708d74a8758a0dfc543fcaae48fe238a4b82194da0292338c14"
}

rule MalwareBazaar_unknown_084_732b8cf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "732b8cf362f486b7569eaa85d9e39f71fe1438ba68214300a9b33c204c447264"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 19:52:30"
  condition:
    hash.sha256(0, filesize) == "732b8cf362f486b7569eaa85d9e39f71fe1438ba68214300a9b33c204c447264"
}

rule MalwareBazaar_ValleyRAT_085_6e795be8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e795be8d4f34f798012d46530c62843dbb74c7cc64fd3a2db37ff68c85f52b8"
    family = "ValleyRAT"
    file_name = "6399E481BEE00F73CF825B0DCE1FC30B.exe"
    file_type = "exe"
    first_seen = "2026-07-26 19:45:08"
  condition:
    hash.sha256(0, filesize) == "6e795be8d4f34f798012d46530c62843dbb74c7cc64fd3a2db37ff68c85f52b8"
}

rule MalwareBazaar_Mirai_086_90233ccb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90233ccbb540fad9ec81ca3ae88266ed2df968f559a64bcc133ea5875ac7e2c0"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-07-26 19:42:53"
  condition:
    hash.sha256(0, filesize) == "90233ccbb540fad9ec81ca3ae88266ed2df968f559a64bcc133ea5875ac7e2c0"
}

rule MalwareBazaar_unknown_087_158089dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "158089dcc6e71e5f6dd212dfdb7657414f3eb540aefed1d82c6b9b56195956f4"
    family = "unknown"
    file_name = "payload.sh"
    file_type = "sh"
    first_seen = "2026-07-26 19:40:52"
  condition:
    hash.sha256(0, filesize) == "158089dcc6e71e5f6dd212dfdb7657414f3eb540aefed1d82c6b9b56195956f4"
}

rule MalwareBazaar_Mirai_088_a1603956
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1603956bbcef1b38c55082a22754f04203fae16b24b7ad868413184ba68a08b"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-07-26 19:28:55"
  condition:
    hash.sha256(0, filesize) == "a1603956bbcef1b38c55082a22754f04203fae16b24b7ad868413184ba68a08b"
}

rule MalwareBazaar_Mirai_089_93468402
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9346840245721ecabe3bbf50b9c55882b7bb99e978d30329c1f9be9a19f6e61f"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-07-26 19:26:55"
  condition:
    hash.sha256(0, filesize) == "9346840245721ecabe3bbf50b9c55882b7bb99e978d30329c1f9be9a19f6e61f"
}

rule MalwareBazaar_unknown_090_79c7de72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79c7de724b8d91a50fd7cf1d4bb572fedba37d33f9e705ce37957af43c0e8b9c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-26 19:22:53"
  condition:
    hash.sha256(0, filesize) == "79c7de724b8d91a50fd7cf1d4bb572fedba37d33f9e705ce37957af43c0e8b9c"
}

rule MalwareBazaar_Mirai_091_ee1e2234
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee1e2234a51bbba1bfdf4726fc06c351b2dbc3a952215e608e9e4a5874e380f2"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-07-26 19:20:54"
  condition:
    hash.sha256(0, filesize) == "ee1e2234a51bbba1bfdf4726fc06c351b2dbc3a952215e608e9e4a5874e380f2"
}

rule MalwareBazaar_unknown_092_b29b3473
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b29b34738355449cfc0609602966074d6dbeac2c6335a3c16f31124b72c34eb1"
    family = "unknown"
    file_name = "x"
    file_type = "sh"
    first_seen = "2026-07-26 19:20:53"
  condition:
    hash.sha256(0, filesize) == "b29b34738355449cfc0609602966074d6dbeac2c6335a3c16f31124b72c34eb1"
}

rule MalwareBazaar_RemusStealer_093_83554bae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83554baeeb700815f9b6492584a1b1a40c64f752d1ff1a67cde079ad524b008f"
    family = "RemusStealer"
    file_name = "dd_Pkg_09_yrxp12x2.exe"
    file_type = "exe"
    first_seen = "2026-07-26 19:18:08"
  condition:
    hash.sha256(0, filesize) == "83554baeeb700815f9b6492584a1b1a40c64f752d1ff1a67cde079ad524b008f"
}

rule MalwareBazaar_Mirai_094_0ce97c6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ce97c6a160fab6db1246fd2f4fc0a932b2ada179e42a2d66005e2dbb3a6a8ae"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-07-26 19:12:57"
  condition:
    hash.sha256(0, filesize) == "0ce97c6a160fab6db1246fd2f4fc0a932b2ada179e42a2d66005e2dbb3a6a8ae"
}

rule MalwareBazaar_Mirai_095_83b8de55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83b8de55cd477c75eac4280e38ab0c4184f0b43de7467729d4acd6d1830ecc95"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-07-26 19:03:02"
  condition:
    hash.sha256(0, filesize) == "83b8de55cd477c75eac4280e38ab0c4184f0b43de7467729d4acd6d1830ecc95"
}

rule MalwareBazaar_unknown_096_59a9721c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59a9721c8214ef997096498c44dcf5f122e1c604b6f248456e8dc430e7512fdb"
    family = "unknown"
    file_name = "59a9721c8214ef997096498c44dcf5f122e1c604b6f248456e8dc430e7512fdb"
    file_type = "elf"
    first_seen = "2026-07-26 19:00:26"
  condition:
    hash.sha256(0, filesize) == "59a9721c8214ef997096498c44dcf5f122e1c604b6f248456e8dc430e7512fdb"
}

rule MalwareBazaar_unknown_097_f0275877
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f02758770d616fc8ff7ddbe5caf069d4bbd2bae5422a32a95cfa8c7f6a0a9b8d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 18:52:28"
  condition:
    hash.sha256(0, filesize) == "f02758770d616fc8ff7ddbe5caf069d4bbd2bae5422a32a95cfa8c7f6a0a9b8d"
}

rule MalwareBazaar_RemusStealer_098_6d9bd1e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d9bd1e24e5f6bbdb0ae30a6a8de25043b658865f2ad2a84da382966689cdbee"
    family = "RemusStealer"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-07-26 18:50:58"
  condition:
    hash.sha256(0, filesize) == "6d9bd1e24e5f6bbdb0ae30a6a8de25043b658865f2ad2a84da382966689cdbee"
}

rule MalwareBazaar_unknown_099_23fee915
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23fee915a2ede0fa0ca36b1590ef0319703f58fbeaca1d5cfdef77ebf470582d"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-26 18:49:45"
  condition:
    hash.sha256(0, filesize) == "23fee915a2ede0fa0ca36b1590ef0319703f58fbeaca1d5cfdef77ebf470582d"
}

rule MalwareBazaar_unknown_100_94e381ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94e381ba36dcbf27e4907f9049eff1a8694dfafd4af899be0bed6b781f13b5ac"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-26 18:48:58"
  condition:
    hash.sha256(0, filesize) == "94e381ba36dcbf27e4907f9049eff1a8694dfafd4af899be0bed6b781f13b5ac"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

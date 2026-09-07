# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-07

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
| Unique family labels | 16 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 55 |
| AsyncRAT | 12 |
| Mirai | 8 |
| Gafgyt | 4 |
| Vidar | 3 |
| Amadey | 3 |
| CoinMiner | 2 |
| RemcosRAT | 2 |
| GuLoader | 2 |
| BlankGrabber | 2 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 48 |
| elf | 19 |
| sh | 14 |
| unknown | 6 |
| zip | 4 |
| js | 3 |
| vbs | 3 |
| jar | 2 |
| hta | 1 |

## Per-Sample Analysis

### Sample 1: `84f77fe2a8b1468e`

| Field | Value |
|---|---|
| SHA-256 | `84f77fe2a8b1468efa0c4efba816501cc6b7f6a99a826ee2344ab5ef7f362abb` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-07 04:38:47` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fbcc89ef6af6311893a40005829073ca` |
| SHA-256 | `84f77fe2a8b1468efa0c4efba816501cc6b7f6a99a826ee2344ab5ef7f362abb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_84f77fe2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84f77fe2a8b1468efa0c4efba816501cc6b7f6a99a826ee2344ab5ef7f362abb"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-07 04:38:47"
  condition:
    hash.sha256(0, filesize) == "84f77fe2a8b1468efa0c4efba816501cc6b7f6a99a826ee2344ab5ef7f362abb"
}
```

### Sample 2: `5b555500eac93184`

| Field | Value |
|---|---|
| SHA-256 | `5b555500eac931841f3c4b8223c6d88f46ea9093a1d63ac10872f6b46b8ae7c4` |
| Family label | `unknown` |
| File name | `5b555500eac931841f3c4b8223c6d88f46ea9093a1d63ac10872f6b46b8ae7c4.exe` |
| File type | `exe` |
| First seen | `2026-09-07 04:19:00` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87c3c64200af61316282e1f616b8855f` |
| SHA-1 | `ce53fa76785e8d9fccc32b11571efcc6f8e36f25` |
| SHA-256 | `5b555500eac931841f3c4b8223c6d88f46ea9093a1d63ac10872f6b46b8ae7c4` |
| SHA3-384 | `9c4ae58cc20e21c8720fc5fae463a0a2ceae06dc1bb069e48e213fe8497529d1b688bbbca9bdd2fab6942e0d62601237` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T1B8D5234EFEF21871E875C7B28E83E07EB1193B8146658C93778C67001E225696CB57BE` |
| SSDEEP | `49152:qbOqelGv5J7PBckd1RfdAy/zsOPqLwAB10jy3ChzsBUEAPcKLBf4jikYJa:7lw/ckd1RxoOYwAB1+WChzpBPxfGt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_5b555500
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b555500eac931841f3c4b8223c6d88f46ea9093a1d63ac10872f6b46b8ae7c4"
    family = "unknown"
    file_name = "5b555500eac931841f3c4b8223c6d88f46ea9093a1d63ac10872f6b46b8ae7c4.exe"
    file_type = "exe"
    first_seen = "2026-09-07 04:19:00"
  condition:
    hash.sha256(0, filesize) == "5b555500eac931841f3c4b8223c6d88f46ea9093a1d63ac10872f6b46b8ae7c4"
}
```

### Sample 3: `cd4b5390890f18df`

| Field | Value |
|---|---|
| SHA-256 | `cd4b5390890f18df23345caa1dba8621efc1aff60f376e49e17c4fe67a181845` |
| Family label | `Gafgyt` |
| File name | `cd4b5390890f18df23345caa1dba8621efc1aff60f376e49e17c4fe67a181845` |
| File type | `elf` |
| First seen | `2026-09-07 04:06:37` |
| Reporter | `c2hunter` |
| Tags | `elf, Gafgyt, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79b2ccbc7e567c91aa7dcb5ed50f4d75` |
| SHA-1 | `d87329e15f4810aa3a9da516b33c8520c2897c79` |
| SHA-256 | `cd4b5390890f18df23345caa1dba8621efc1aff60f376e49e17c4fe67a181845` |
| SHA3-384 | `5878c725f8286440b3628a2ff78d25d2958fcb824ece944720e59e4966dc41eedfe003d53dfe7bd2f629ef81aca9aa15` |
| TLSH | `T199833B47E9A19FB7C0866A7565AB5E300B13E9912B4F1A4A303CA7F8434F4CD790EF64` |
| TELFHASH | `t1b511dc4270ba891d2bb299249cbc42b5265536236382be75bf0ec5c49537002ba79e8b` |
| SSDEEP | `1536:ClN9YyOXmMSr4k9dgGwKGg0CfjGJCudojMyTRLmkxVqOEeofzee:g7OXmMSr4krG3JdBQLmkxVqODofzee` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_003_cd4b5390
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd4b5390890f18df23345caa1dba8621efc1aff60f376e49e17c4fe67a181845"
    family = "Gafgyt"
    file_name = "cd4b5390890f18df23345caa1dba8621efc1aff60f376e49e17c4fe67a181845"
    file_type = "elf"
    first_seen = "2026-09-07 04:06:37"
  condition:
    hash.sha256(0, filesize) == "cd4b5390890f18df23345caa1dba8621efc1aff60f376e49e17c4fe67a181845"
}
```

### Sample 4: `5991ed79238ab8bd`

| Field | Value |
|---|---|
| SHA-256 | `5991ed79238ab8bd0f4c4983e3e6fbc73784396daf7d585349eae37d5907c60b` |
| Family label | `Gafgyt` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-09-07 03:58:08` |
| Reporter | `abuserobot66609` |
| Tags | `Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b015a03784a64f9f76c3aadce8ef0902` |
| SHA-1 | `4df07aec0c435596f6403b3fd293dfbc0695cbe6` |
| SHA-256 | `5991ed79238ab8bd0f4c4983e3e6fbc73784396daf7d585349eae37d5907c60b` |
| SHA3-384 | `e83a72edc5c957cd8a68881bd1fd54240f2bed6b04d2911cdd783778bab29935815a114427c24195c627abb85a130fc3` |
| TLSH | `T103935D27B552C6BBC08752B42BDFEA615833B4BC0B32720B33D47DA52B259D91E6DB01` |
| TELFHASH | `t1d211020260b689282bb259205cbc42f1165526233341be75bf0ec5c4993b002aa78e8b` |
| SSDEEP | `1536:W7uJtxNeVE8zV7aDlvhE1hmkJ0S36W6bWjK3UyPXfH0mA+KWOXFseaZYxe:4SsVEeVMlpmXJ0O6WpjKkifUm/KWOXFE` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_004_5991ed79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5991ed79238ab8bd0f4c4983e3e6fbc73784396daf7d585349eae37d5907c60b"
    family = "Gafgyt"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-09-07 03:58:08"
  condition:
    hash.sha256(0, filesize) == "5991ed79238ab8bd0f4c4983e3e6fbc73784396daf7d585349eae37d5907c60b"
}
```

### Sample 5: `e96e86dd43cbd957`

| Field | Value |
|---|---|
| SHA-256 | `e96e86dd43cbd957848d1d482a5efed9c5557e3d48cf5e67abee6f207504b3ed` |
| Family label | `Gafgyt` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-09-07 03:58:06` |
| Reporter | `abuserobot66609` |
| Tags | `Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c09f077d6dc27175cb7951ea063ad73` |
| SHA-1 | `4a9c78e097e2f1b97149529aaffaa3ff19018e62` |
| SHA-256 | `e96e86dd43cbd957848d1d482a5efed9c5557e3d48cf5e67abee6f207504b3ed` |
| SHA3-384 | `81c7c4ebe4f9e40a15e7b3e9eb0befd5794ac77a68267cd0bc1e5fcea20e28ff6d559ea90ac3ff954c8ae1d0d32d4ef6` |
| TLSH | `T166C39517BB618FB7D81FDE33059A8902108DE58A12D96F6BB2B4C92CE74B94F08D3D54` |
| TELFHASH | `t1fe11104270b6891c2bb259245cbc42b0165532232381be74bf0ec5c05937002ba79e8b` |
| SSDEEP | `1536:/UHeTxCAms/Y8Zm3lKYA43gMJwSkJ8EpI+DzUh8rmW+IFB1Df11hR/:/UyLqAmgMJM8EO+Dw8rmW+IFB1Dt1hR/` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_005_e96e86dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e96e86dd43cbd957848d1d482a5efed9c5557e3d48cf5e67abee6f207504b3ed"
    family = "Gafgyt"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-09-07 03:58:06"
  condition:
    hash.sha256(0, filesize) == "e96e86dd43cbd957848d1d482a5efed9c5557e3d48cf5e67abee6f207504b3ed"
}
```

### Sample 6: `d75b9a8289eda8d4`

| Field | Value |
|---|---|
| SHA-256 | `d75b9a8289eda8d48ff22e483f6df819d6a3e2d3fe638f6cb986d74358fe6e8e` |
| Family label | `Mirai` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-09-07 03:58:05` |
| Reporter | `abuserobot66609` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a4738141a0711d7f5ca5f81ddb4660f` |
| SHA-1 | `d4a02fa0832d7d3b2fe1e9eaadcf22a36b65ec17` |
| SHA-256 | `d75b9a8289eda8d48ff22e483f6df819d6a3e2d3fe638f6cb986d74358fe6e8e` |
| SHA3-384 | `978315b46c5399ecc4bd36e74403f81eb8b6aa27056c7b9f4e41964ffb4168e9a644c4461e18c15a2fc9bb84f4341bf1` |
| TLSH | `T1AAC3842E7E12BFBEE668863107F35F70879521D227A19382F26CD6181E7128D1C5FB64` |
| TELFHASH | `t1fe11104270b6891c2bb259245cbc42b0165532232381be74bf0ec5c05937002ba79e8b` |
| SSDEEP | `1536:M7je1TMGq+f+AQ2rK7zeXeReXe8V2rK7Ie+u60GAzQj1l72HBevEdWfRZrmW+IFj:Ted0W0MZQHTd6RZrmW+IFB1Dt1hR/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_d75b9a82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d75b9a8289eda8d48ff22e483f6df819d6a3e2d3fe638f6cb986d74358fe6e8e"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-09-07 03:58:05"
  condition:
    hash.sha256(0, filesize) == "d75b9a8289eda8d48ff22e483f6df819d6a3e2d3fe638f6cb986d74358fe6e8e"
}
```

### Sample 7: `6a7e1676d52a8590`

| Field | Value |
|---|---|
| SHA-256 | `6a7e1676d52a85906d43a543bdb35f8b3282447a5ce8c98dfad33e04afe79dc6` |
| Family label | `Gafgyt` |
| File name | `sample` |
| File type | `sh` |
| First seen | `2026-09-07 03:58:04` |
| Reporter | `abuserobot66609` |
| Tags | `Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c99f1314ea1b13dcaef2e2bc74a808b9` |
| SHA-1 | `db15c5ad189e8f1bf664e01c5cfaac846ce5aa5c` |
| SHA-256 | `6a7e1676d52a85906d43a543bdb35f8b3282447a5ce8c98dfad33e04afe79dc6` |
| SHA3-384 | `73f2dba9ebf6cb4dd917015e72a2583152a94f88e882d511bb3d61fff7d9a3de62e52b624747d6d5fc3ec1e394ffd035` |
| TLSH | `T1624149D721950FF32C90D93B32798490F5D1A19A95C75F4669DC3CE448BEEECA844682` |
| SSDEEP | `48:vEd8j9RttQdM8FYJRH70T6GCSIBL1b5NSI5xQT:vEd8jLttQdMCYJRH70T6GCSIBBb5NSIo` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_007_6a7e1676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a7e1676d52a85906d43a543bdb35f8b3282447a5ce8c98dfad33e04afe79dc6"
    family = "Gafgyt"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-09-07 03:58:04"
  condition:
    hash.sha256(0, filesize) == "6a7e1676d52a85906d43a543bdb35f8b3282447a5ce8c98dfad33e04afe79dc6"
}
```

### Sample 8: `fd20a97a9623afec`

| Field | Value |
|---|---|
| SHA-256 | `fd20a97a9623afecfe3d2a50f8ef75930c7522ba7e6589a03db62979509f50ea` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-07 03:50:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `109ea7d4f43ab2311308deb6911b645c` |
| SHA-1 | `f4eceba69046454dfb2f2d51616503797504fc58` |
| SHA-256 | `fd20a97a9623afecfe3d2a50f8ef75930c7522ba7e6589a03db62979509f50ea` |
| SHA3-384 | `36753c3991b5b63822df2113595e0ecf65c139dfa103c103f53c4b82a911d173e24c738cfbbd8daa5bab9ba182d896d5` |
| TLSH | `T157C27D956A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:X8vCB+25j6es8RL9FYpMSUpi+20qUpi+20YQX:X8l25Jdd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_fd20a97a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd20a97a9623afecfe3d2a50f8ef75930c7522ba7e6589a03db62979509f50ea"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-07 03:50:48"
  condition:
    hash.sha256(0, filesize) == "fd20a97a9623afecfe3d2a50f8ef75930c7522ba7e6589a03db62979509f50ea"
}
```

### Sample 9: `3c1aa8627871e0c1`

| Field | Value |
|---|---|
| SHA-256 | `3c1aa8627871e0c1d698e0854d482f5f6e7323b6c65e2488efa264fc5436c0d5` |
| Family label | `ValleyRAT` |
| File name | `A8B50F1767FFE24416B671820377036B.exe` |
| File type | `exe` |
| First seen | `2026-09-07 03:50:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8b50f1767ffe24416b671820377036b` |
| SHA-1 | `55d6ac8ea97ccfc0d0bea16bf3c4f6a0609f46b8` |
| SHA-256 | `3c1aa8627871e0c1d698e0854d482f5f6e7323b6c65e2488efa264fc5436c0d5` |
| SHA3-384 | `3febb2f0697d8ecc8fb13c8eefc1b0bcbe8864298890b71ddde81a57064d8f737cbc9a087dd24ece0f64e62d8e40696f` |
| IMPHASH | `836688c7d21e39394af41ce9a8c2d728` |
| TLSH | `T1B8567C30764AC52BDA7E01B0292CDA9F556D7E720B7154D7B3DC2E6E1AB48C20732E27` |
| SSDEEP | `98304:9hDq6qXCP7yKPNmxecLushvf7UQIYWuxmKeAK12QzwdTgvV/RQebJF:TDq6UE7ovRQzK86e/` |
| ICON-DHASH | `6ded69c7b130b2c0` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_009_3c1aa862
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c1aa8627871e0c1d698e0854d482f5f6e7323b6c65e2488efa264fc5436c0d5"
    family = "ValleyRAT"
    file_name = "A8B50F1767FFE24416B671820377036B.exe"
    file_type = "exe"
    first_seen = "2026-09-07 03:50:07"
  condition:
    hash.sha256(0, filesize) == "3c1aa8627871e0c1d698e0854d482f5f6e7323b6c65e2488efa264fc5436c0d5"
}
```

### Sample 10: `d867286843c77fb1`

| Field | Value |
|---|---|
| SHA-256 | `d867286843c77fb12979de0c70dcf2c23c75a8baca25ca97ef77df9531807888` |
| Family label | `unknown` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-09-07 03:48:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `850011a2fe8cd783f86f8f8a9b2e8357` |
| SHA-1 | `7774c62a84645584a5cd63adbadc4646633c8bd8` |
| SHA-256 | `d867286843c77fb12979de0c70dcf2c23c75a8baca25ca97ef77df9531807888` |
| SHA3-384 | `d3fbc8626ddd39299823228f81134c058b072001b18b3a7442a6ec6ec9b57cbdfdbff3b84232b73fa86da155497161b3` |
| TLSH | `T145C312B34B0D309D67A12C369F4781F1B06A23DAC95FFA42A70A5CE4E569CB9878F441` |
| SSDEEP | `3072:QylvpjYO93HYQS1cijOppIHqGf54hRewsCpWcvT:B/EO9rS5jOppIHqn7Ps0pT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_d8672868
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d867286843c77fb12979de0c70dcf2c23c75a8baca25ca97ef77df9531807888"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-09-07 03:48:46"
  condition:
    hash.sha256(0, filesize) == "d867286843c77fb12979de0c70dcf2c23c75a8baca25ca97ef77df9531807888"
}
```

### Sample 11: `32995ee3a0858c8c`

| Field | Value |
|---|---|
| SHA-256 | `32995ee3a0858c8c7f5594aa1bb4d38de616d66d60b920c5ffefe9bb41fccf38` |
| Family label | `Mirai` |
| File name | `w.sh` |
| File type | `sh` |
| First seen | `2026-09-07 03:46:49` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e51a9fa1407971b95657e6b355aed84` |
| SHA-1 | `da615b44c37fb15116e20246905753f06990e720` |
| SHA-256 | `32995ee3a0858c8c7f5594aa1bb4d38de616d66d60b920c5ffefe9bb41fccf38` |
| SHA3-384 | `b325957bf723b6dc699be132eb225ec42f6243da75550ef463c5339ba81cd510c960d47d5248ba11664d18999295f7c9` |
| TLSH | `T1CF1170CF16D4A053C89CCD48746FC818A64487D374961F5EEC8CA8FAA9C5B1CF166F49` |
| SSDEEP | `24:8Ilc0acoEcHcbDc1Ric3c65cTKgczNI75c17c/oR:8IlcBcvcHc/c1Ric3cccTLcy5c17c/0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_32995ee3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32995ee3a0858c8c7f5594aa1bb4d38de616d66d60b920c5ffefe9bb41fccf38"
    family = "Mirai"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-09-07 03:46:49"
  condition:
    hash.sha256(0, filesize) == "32995ee3a0858c8c7f5594aa1bb4d38de616d66d60b920c5ffefe9bb41fccf38"
}
```

### Sample 12: `6fef8d31119d09fe`

| Field | Value |
|---|---|
| SHA-256 | `6fef8d31119d09fe251811cd15d883b73b84f2e45340b8717998299b6bffa9ce` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-07 03:42:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8e386adfb6ea658f87d062787bf1be5` |
| SHA-1 | `6dcb24ba3da97f92d26d52bd35d11f92c3e812d8` |
| SHA-256 | `6fef8d31119d09fe251811cd15d883b73b84f2e45340b8717998299b6bffa9ce` |
| SHA3-384 | `3c631a7bd856fcbb53980531b042b8f2cc55d60e7f1289ff436e55d2a51f79a1896d8f18f68a79ae7ec8dc22a27508ce` |
| TLSH | `T123236C661A857C14AA98D4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5A69D910872D` |
| SSDEEP | `768:VXRWNGxV39GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:/lxacr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_6fef8d31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fef8d31119d09fe251811cd15d883b73b84f2e45340b8717998299b6bffa9ce"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-07 03:42:38"
  condition:
    hash.sha256(0, filesize) == "6fef8d31119d09fe251811cd15d883b73b84f2e45340b8717998299b6bffa9ce"
}
```

### Sample 13: `51727678607bdc67`

| Field | Value |
|---|---|
| SHA-256 | `51727678607bdc67055453bc60d89c7ca8fd3840b7d0a59a29ec254ea843e681` |
| Family label | `unknown` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-09-07 03:36:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61039f541595cdbeb0e1de80406246ef` |
| SHA-1 | `8c725d23427142f6cbbe2c6ae053a068fdb4aef6` |
| SHA-256 | `51727678607bdc67055453bc60d89c7ca8fd3840b7d0a59a29ec254ea843e681` |
| SHA3-384 | `f45a9ea0b0ff00c4aad1e798239d98b103afc9985e6c0660f40cdacbea5b23ab6df3fb8fbeec603f6ec55f1c9dba7491` |
| TLSH | `T119C3127CB320EC51C3F01EBBE70D8A0D215D57B07126139643D49E29A3B2C5B6A7A775` |
| SSDEEP | `1536:3/JzufPIrcD7t93zjaWes+zGcK4QUkyT5VHiOQPlYo4FMRMNu8QQpivslgukmQC6:PJEPWcpeGcIK5w1PlY0f8DDLxQC1rQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_51727678
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51727678607bdc67055453bc60d89c7ca8fd3840b7d0a59a29ec254ea843e681"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-07 03:36:49"
  condition:
    hash.sha256(0, filesize) == "51727678607bdc67055453bc60d89c7ca8fd3840b7d0a59a29ec254ea843e681"
}
```

### Sample 14: `fb3931cd32e154f3`

| Field | Value |
|---|---|
| SHA-256 | `fb3931cd32e154f3856ab8eaf8c45d5aedbb697068f5bd3f8e8684be181bbee4` |
| Family label | `unknown` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-09-07 03:30:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5a269cf3cafb76b7bbcd0118d519339` |
| SHA-1 | `bcf7f425aa3f2b2e78637745b44e36319337de07` |
| SHA-256 | `fb3931cd32e154f3856ab8eaf8c45d5aedbb697068f5bd3f8e8684be181bbee4` |
| SHA3-384 | `be5bec8eb33e2cc76972f5164ef93b19b99bdbfb78d4a485a2ab67f23019809829fcb8ad14a443cfdd3bc7f962a138c6` |
| TLSH | `T1B5C30221455AD9F4C584DEB2CD62A18EBF7208F1726773C273240F48E981C5B93E6B9B` |
| SSDEEP | `3072:3zv9d5saQMOhxlnWNHDMH8h3Lz9rq0tMO6:3z5FIlWFDMHY3/JTtMO6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_fb3931cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb3931cd32e154f3856ab8eaf8c45d5aedbb697068f5bd3f8e8684be181bbee4"
    family = "unknown"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-09-07 03:30:39"
  condition:
    hash.sha256(0, filesize) == "fb3931cd32e154f3856ab8eaf8c45d5aedbb697068f5bd3f8e8684be181bbee4"
}
```

### Sample 15: `c0fdf9d2bccc7365`

| Field | Value |
|---|---|
| SHA-256 | `c0fdf9d2bccc736513e0a8b62dd671fc8563db87bd7cd9c7e063250a2a3da655` |
| Family label | `unknown` |
| File name | `MV_GREEN_GEM_APPOINTMENT_LETTER.js` |
| File type | `js` |
| First seen | `2026-09-07 03:25:39` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b4362928ae4003afb3e9c7ed01e8f95` |
| SHA-1 | `72780fa89c028e9ef100ae0249e9e0bc5c0fce7e` |
| SHA-256 | `c0fdf9d2bccc736513e0a8b62dd671fc8563db87bd7cd9c7e063250a2a3da655` |
| SHA3-384 | `1c5d7a102bcdc018a6b7119ca6c20152266a6f3ce5427c42dadbf25c1f35d26b5bc9666be17191541269d16fc0e910af` |
| TLSH | `T1DCE5D6F377F9B1875E0463BE948DA4888F89C4581BCBB5C4A0DB48D9658F8C63AC4C5B` |
| SSDEEP | `12288:BS68PhH1nM7HkldZDK0E7FW88UGwxS6phFXPfnb4cRCPLvrXZ0x6Dsrgvy0FWIgv:B/YhHe78zDKZv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_c0fdf9d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0fdf9d2bccc736513e0a8b62dd671fc8563db87bd7cd9c7e063250a2a3da655"
    family = "unknown"
    file_name = "MV_GREEN_GEM_APPOINTMENT_LETTER.js"
    file_type = "js"
    first_seen = "2026-09-07 03:25:39"
  condition:
    hash.sha256(0, filesize) == "c0fdf9d2bccc736513e0a8b62dd671fc8563db87bd7cd9c7e063250a2a3da655"
}
```

### Sample 16: `388031645b254281`

| Field | Value |
|---|---|
| SHA-256 | `388031645b2542819fd927cebae961b51ec67b257032d3b613917955382bdcee` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-07 03:22:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26faef7073ec074b940ef7410b562088` |
| SHA-1 | `b576f6fee3619953506c47e5aae32a71b55c0f41` |
| SHA-256 | `388031645b2542819fd927cebae961b51ec67b257032d3b613917955382bdcee` |
| SHA3-384 | `85b29dfcf7e8019d0680392bc26ca85312abdf20734ef93430d1a0b2e54806eaa5c766e9560c5ea0ce8a6c5bafab8976` |
| TLSH | `T15DC28D95AA867C44BDC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:L8vCB+25j6es8RL9FYpMSUpi+20qUpi+20YQX:L8l25Jdd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_38803164
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "388031645b2542819fd927cebae961b51ec67b257032d3b613917955382bdcee"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-07 03:22:39"
  condition:
    hash.sha256(0, filesize) == "388031645b2542819fd927cebae961b51ec67b257032d3b613917955382bdcee"
}
```

### Sample 17: `7bcfc5863f119c89`

| Field | Value |
|---|---|
| SHA-256 | `7bcfc5863f119c8904ba0a5ade201e3dc3c17981a51d81ff13ef90d08edd4101` |
| Family label | `Vidar` |
| File name | `7bcfc5863f119c8904ba0a5ade201e3dc3c17981a51d81ff13ef90d08edd4101.bin` |
| File type | `exe` |
| First seen | `2026-09-07 03:20:23` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d83f3488e6729304b7e6b875b210fb22` |
| SHA-1 | `3b985940dc4be5a8eb42d1713d5b50ab587737f1` |
| SHA-256 | `7bcfc5863f119c8904ba0a5ade201e3dc3c17981a51d81ff13ef90d08edd4101` |
| SHA3-384 | `b999739e91544fd00142df0e9afa85cfd9ce4ad6ece795215c79145ef0c1eda37ee0392cd46ebd3b92e6cfc42e493275` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T162266B13BC9488E9C06AD73AC56A8262FAB1BC084F3173E77E51B6782E377E05539714` |
| SSDEEP | `49152:S87NQjnAT/LKUH3KOMLPGDEAt3tW1x+p2AxruQTJc0Mj3dCct:Sa61xAdsrtZ` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_017_7bcfc586
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bcfc5863f119c8904ba0a5ade201e3dc3c17981a51d81ff13ef90d08edd4101"
    family = "Vidar"
    file_name = "7bcfc5863f119c8904ba0a5ade201e3dc3c17981a51d81ff13ef90d08edd4101.bin"
    file_type = "exe"
    first_seen = "2026-09-07 03:20:23"
  condition:
    hash.sha256(0, filesize) == "7bcfc5863f119c8904ba0a5ade201e3dc3c17981a51d81ff13ef90d08edd4101"
}
```

### Sample 18: `0e96f03ffdc6a7f0`

| Field | Value |
|---|---|
| SHA-256 | `0e96f03ffdc6a7f0b60591ef68f098e5684f59deafd6fb051a58d85f777bce7c` |
| Family label | `Vidar` |
| File name | `0e96f03ffdc6a7f0b60591ef68f098e5684f59deafd6fb051a58d85f777bce7c.bin` |
| File type | `exe` |
| First seen | `2026-09-07 03:20:19` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41bb9deb5df15c23e54b1945bc6e4976` |
| SHA-1 | `a0338611eb552eb707052bff2baa2d367a53d4f7` |
| SHA-256 | `0e96f03ffdc6a7f0b60591ef68f098e5684f59deafd6fb051a58d85f777bce7c` |
| SHA3-384 | `f814a719ba132433d31e7ee290cc264e4f405bff2125bf2521b20ec28e46204331929b52213213f69ee44002acec0f01` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T120067C07BC8148A6C4AAA335C8A25641B77DBC891F3263D32A547BBB2F737D09D39750` |
| SSDEEP | `49152:wvy9++/0wBg7kdpzuRglwBJRRzu5GhuMjaHlFWjCwUVd:w/KT9wbqNMeCjT+d` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_018_0e96f03f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e96f03ffdc6a7f0b60591ef68f098e5684f59deafd6fb051a58d85f777bce7c"
    family = "Vidar"
    file_name = "0e96f03ffdc6a7f0b60591ef68f098e5684f59deafd6fb051a58d85f777bce7c.bin"
    file_type = "exe"
    first_seen = "2026-09-07 03:20:19"
  condition:
    hash.sha256(0, filesize) == "0e96f03ffdc6a7f0b60591ef68f098e5684f59deafd6fb051a58d85f777bce7c"
}
```

### Sample 19: `4806edb12512156d`

| Field | Value |
|---|---|
| SHA-256 | `4806edb12512156dec5a3ef9d7632a74bb8d0fbf05e64ec7bc4e164da517ee89` |
| Family label | `unknown` |
| File name | `4806edb12512156dec5a3ef9d7632a74bb8d0fbf05e64ec7bc4e164da517ee89.elf` |
| File type | `elf` |
| First seen | `2026-09-07 03:18:18` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d44abedf336ddc912b3b659219493a0` |
| SHA-1 | `d0e665b46cf01692e399c291483867e80444ad55` |
| SHA-256 | `4806edb12512156dec5a3ef9d7632a74bb8d0fbf05e64ec7bc4e164da517ee89` |
| SHA3-384 | `4c1781666e351d1f8384966bbc20b9eed1f92cf7f5043014246650197f1892a780bf7dbaf29d7f5d63d838da5ed4cfd9` |
| TLSH | `T1CDC31311C1BDE5F8E69DE4B99D28950DBF79A8E928152106299C0F3703D2A1B3FBC847` |
| SSDEEP | `3072:EpzUSo1PKGmv6m3HmL+RYqZiSm4ksM24sDaFNo1ZLnbxdDA9L8Y/Z:woSofmv63L+O34ksKgavALUl8GZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_4806edb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4806edb12512156dec5a3ef9d7632a74bb8d0fbf05e64ec7bc4e164da517ee89"
    family = "unknown"
    file_name = "4806edb12512156dec5a3ef9d7632a74bb8d0fbf05e64ec7bc4e164da517ee89.elf"
    file_type = "elf"
    first_seen = "2026-09-07 03:18:18"
  condition:
    hash.sha256(0, filesize) == "4806edb12512156dec5a3ef9d7632a74bb8d0fbf05e64ec7bc4e164da517ee89"
}
```

### Sample 20: `44d4e73e3ec5d260`

| Field | Value |
|---|---|
| SHA-256 | `44d4e73e3ec5d260f2e943fd53dbd373dee12451a784b782001a5050aadc5739` |
| Family label | `unknown` |
| File name | `44d4e73e3ec5d260f2e943fd53dbd373dee12451a784b782001a5050aadc5739.elf` |
| File type | `elf` |
| First seen | `2026-09-07 03:18:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ab31c9323708a0451a795d10311de42` |
| SHA-1 | `503117ac00239b4e05d2ec8a04ac1125045d0338` |
| SHA-256 | `44d4e73e3ec5d260f2e943fd53dbd373dee12451a784b782001a5050aadc5739` |
| SHA3-384 | `89d174ddbbcf56b974824cbb51d8281e1ae13944c5dc5ad5e16df53ee790bd4361f8b122c02fc74d4d21233be9facbfe` |
| TLSH | `T134C312F642436A7AC6DF2FB1E8E2974341A74E6584B718F3004347A255E37CBA4F9609` |
| SSDEEP | `3072:DIq262ZKWaQebRXR9hXcq64EdG1QKSu9FLaVPRuqv7w+vI:DTF2hObt75J6KSuWDj1vI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_44d4e73e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44d4e73e3ec5d260f2e943fd53dbd373dee12451a784b782001a5050aadc5739"
    family = "unknown"
    file_name = "44d4e73e3ec5d260f2e943fd53dbd373dee12451a784b782001a5050aadc5739.elf"
    file_type = "elf"
    first_seen = "2026-09-07 03:18:14"
  condition:
    hash.sha256(0, filesize) == "44d4e73e3ec5d260f2e943fd53dbd373dee12451a784b782001a5050aadc5739"
}
```

### Sample 21: `5d7004c89597bbdb`

| Field | Value |
|---|---|
| SHA-256 | `5d7004c89597bbdbca578f3f441c2a61ffe89a6afdaf9c953fac8163890379a6` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-07 03:17:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0b8ee7ccf6673e14e0e5446b4f59c8a` |
| SHA-1 | `3073f255422254713ecb0381e981421376842ad3` |
| SHA-256 | `5d7004c89597bbdbca578f3f441c2a61ffe89a6afdaf9c953fac8163890379a6` |
| SHA3-384 | `957d67b76743c5b7551153d900e4b28321212d36e1b961c25d7701b7161c8b90dfda3186f39bc6b97ced5114d306b700` |
| TLSH | `T11EE2E815EF504EBBD8A7CD3344B84B4230CD6C2723F52B2B2D71E929B11A54A9BD39E4` |
| SSDEEP | `768:LXnUWeCvISc5UBHlwef7eNusXOXiq6OeXEJ:LkagDyBCu70W6OW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_5d7004c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d7004c89597bbdbca578f3f441c2a61ffe89a6afdaf9c953fac8163890379a6"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-07 03:17:29"
  condition:
    hash.sha256(0, filesize) == "5d7004c89597bbdbca578f3f441c2a61ffe89a6afdaf9c953fac8163890379a6"
}
```

### Sample 22: `5ed7ca74c12e3b05`

| Field | Value |
|---|---|
| SHA-256 | `5ed7ca74c12e3b05eda94baa5992276b8491a305b620a6938b618447f7ffb007` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-09-07 03:16:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `922247e86037c18bd9a6b25466cedf0a` |
| SHA-1 | `39439f49610bab97dcdd581bcc87a8b19d5527a2` |
| SHA-256 | `5ed7ca74c12e3b05eda94baa5992276b8491a305b620a6938b618447f7ffb007` |
| SHA3-384 | `5409d6c6455ebec04918b546f609085f275e88ca950ea6a7858114e59e5fa52bd934838855829575cbcfb4e8644a09a5` |
| TLSH | `T1CDC312632527B9C10131A536FE7822C87A57079514EE7102B074E5DAFDE3C6AEBE6133` |
| SSDEEP | `1536:F7tUxVMNz4eyLA7iRwDfG9qX77ioQL3lVVSWfe2eL7ccmpfq1Ysksg5HYRpwqd:F7toqzo+iSSYXHrQzJSceccmpq1JJ6m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_5ed7ca74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ed7ca74c12e3b05eda94baa5992276b8491a305b620a6938b618447f7ffb007"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-09-07 03:16:46"
  condition:
    hash.sha256(0, filesize) == "5ed7ca74c12e3b05eda94baa5992276b8491a305b620a6938b618447f7ffb007"
}
```

### Sample 23: `91d6e3988b09fc0a`

| Field | Value |
|---|---|
| SHA-256 | `91d6e3988b09fc0a749eb4149a2b177ff4dbfe7cef6b7c6c230eb899ed237bc7` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-07 03:16:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4def37ac453eccbe02c18ec26f33081` |
| SHA-1 | `0fce6ab9379aaa51edc8168f54497726ca0bab4c` |
| SHA-256 | `91d6e3988b09fc0a749eb4149a2b177ff4dbfe7cef6b7c6c230eb899ed237bc7` |
| SHA3-384 | `910955ed847e3b12dcc064d50d16adde21ca5a2ea8a7842243a6385b3003229937b94bb7595653c8d5dd22995eba0d11` |
| TLSH | `T1E072AF8DD5B47ACBCFEE2E3C55A833B06E81B090666D4F5CA315CCC5E369506788E079` |
| SSDEEP | `384:EIxjFfh7KRhyAYjiJiwSKT5Yye6eoxyI5RWGVCzrqHAEiulf:EIxjFp2Ixji0wSo5eY0cW+HAER` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_91d6e398
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91d6e3988b09fc0a749eb4149a2b177ff4dbfe7cef6b7c6c230eb899ed237bc7"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-07 03:16:44"
  condition:
    hash.sha256(0, filesize) == "91d6e3988b09fc0a749eb4149a2b177ff4dbfe7cef6b7c6c230eb899ed237bc7"
}
```

### Sample 24: `ece669beecd14a53`

| Field | Value |
|---|---|
| SHA-256 | `ece669beecd14a53805d61e520f426740d32201acf0d355132cc5122f2b6cb07` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-07 03:14:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `065900a67ab6e742983a10f773490472` |
| SHA-1 | `f69726fa85812a90994e679e73440e3ef73ca8f6` |
| SHA-256 | `ece669beecd14a53805d61e520f426740d32201acf0d355132cc5122f2b6cb07` |
| SHA3-384 | `c4bcbb5f3e9563961bc890386d73da556196cb823ef6827bf5b886663f8cd67b38a01948b9984d2f972be1a2bc66d917` |
| TLSH | `T1E03132DE41109E361103CE8977A635C86A8EA1EF289FC7D4DC5C0ED9528878CF161B99` |
| SSDEEP | `24:PEs6kz8G1a3gdFaEkAski/PIzy1qI5CkX6cs2:cAz8IFaEkdkgzX6c5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_ece669be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ece669beecd14a53805d61e520f426740d32201acf0d355132cc5122f2b6cb07"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-07 03:14:46"
  condition:
    hash.sha256(0, filesize) == "ece669beecd14a53805d61e520f426740d32201acf0d355132cc5122f2b6cb07"
}
```

### Sample 25: `602ffa86ce02a12e`

| Field | Value |
|---|---|
| SHA-256 | `602ffa86ce02a12e74860c15f5dc8bc77c8e213439a54b433b05a4a0ce80af96` |
| Family label | `unknown` |
| File name | `602ffa86ce02a12e74860c15f5dc8bc77c8e213439a54b433b05a4a0ce80af96.elf` |
| File type | `elf` |
| First seen | `2026-09-07 03:13:48` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2c7d939397982187340731e56cf89c9` |
| SHA-1 | `b0bf012c06a9557efd73d8da40d99d6d15efd6c4` |
| SHA-256 | `602ffa86ce02a12e74860c15f5dc8bc77c8e213439a54b433b05a4a0ce80af96` |
| SHA3-384 | `0856d48c5e600c72a3c6b1cbb3e8a18d0a1204b078fe4ba6bbad8a0f176baa5c9b3acb34752e2a914b38dee03c240904` |
| TLSH | `T10EC3022B38791B51FBB049F180FB310B72525BB4CDF3695A0614877AFEEC09D667A881` |
| SSDEEP | `3072:1zaIDkpeaiJ0iVibykCnBWfhIKh3o5W3z3UFi9xMGaMWt:vI8tJ3i9CnBqmKhY52LMGw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_602ffa86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "602ffa86ce02a12e74860c15f5dc8bc77c8e213439a54b433b05a4a0ce80af96"
    family = "unknown"
    file_name = "602ffa86ce02a12e74860c15f5dc8bc77c8e213439a54b433b05a4a0ce80af96.elf"
    file_type = "elf"
    first_seen = "2026-09-07 03:13:48"
  condition:
    hash.sha256(0, filesize) == "602ffa86ce02a12e74860c15f5dc8bc77c8e213439a54b433b05a4a0ce80af96"
}
```

### Sample 26: `a41c8459e992f986`

| Field | Value |
|---|---|
| SHA-256 | `a41c8459e992f9869734343bb01ce16022e6a6721247702abdb05e510734ac5e` |
| Family label | `unknown` |
| File name | `daemonx` |
| File type | `elf` |
| First seen | `2026-09-07 03:12:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e092a99f21a0548dd299fb3381389e9c` |
| SHA-1 | `085f2ae2fdfbbab96f9c59de2ecaca4f657d9403` |
| SHA-256 | `a41c8459e992f9869734343bb01ce16022e6a6721247702abdb05e510734ac5e` |
| SHA3-384 | `bf80d318b2bb33dce6d43e0cbb1f9957f43328d56dc4df456202b5f584a8f2b7478d407eef7cd9955ff27d4bb4397bb5` |
| TLSH | `T17DD64A03EDA585E8C0A991348A769253BB71BC484B3523D72F60F7343F76BD06ABA354` |
| TELFHASH | `t1bb628c754dbd34b5a69ac911f3a3b4b4657328b566f438f00027ac85ffc1e814cea86b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:B7xZJFYbVxYzTSTlbpY58+h44a7TaVECUJn6VTl+nK6cZsRQgBB43EQ:BpYV+zTUSa7TaVECAn6DLNCCGNQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_a41c8459
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a41c8459e992f9869734343bb01ce16022e6a6721247702abdb05e510734ac5e"
    family = "unknown"
    file_name = "daemonx"
    file_type = "elf"
    first_seen = "2026-09-07 03:12:37"
  condition:
    hash.sha256(0, filesize) == "a41c8459e992f9869734343bb01ce16022e6a6721247702abdb05e510734ac5e"
}
```

### Sample 27: `71829e7265a93a61`

| Field | Value |
|---|---|
| SHA-256 | `71829e7265a93a611ecdbcc0bae4404f7fa281ea2e3202f2b4b75c0c67e3f504` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-07 03:12:35` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7adf67576ee9ec51f695898131f076e3` |
| SHA-256 | `71829e7265a93a611ecdbcc0bae4404f7fa281ea2e3202f2b4b75c0c67e3f504` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_71829e72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71829e7265a93a611ecdbcc0bae4404f7fa281ea2e3202f2b4b75c0c67e3f504"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-07 03:12:35"
  condition:
    hash.sha256(0, filesize) == "71829e7265a93a611ecdbcc0bae4404f7fa281ea2e3202f2b4b75c0c67e3f504"
}
```

### Sample 28: `0d373e1f9dfeaa5a`

| Field | Value |
|---|---|
| SHA-256 | `0d373e1f9dfeaa5a1c2bffa6116ce78bc2af1174a503c8cba5944664fae60500` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-09-07 03:12:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa1b084324ccfbb29fc3fe6d0aae0619` |
| SHA-1 | `1c790040f4de558bd16c94ea0ef2dc446c231f19` |
| SHA-256 | `0d373e1f9dfeaa5a1c2bffa6116ce78bc2af1174a503c8cba5944664fae60500` |
| SHA3-384 | `78f61b705ddae3ba7ae350490809b14c4049752883cdfcafd523b4f0a733a51257518c2a44cc4d7aa7507ca9700862f6` |
| TLSH | `T116C313DBCE5A328481ED9973B56AB404D5344B78CCFB54A61A1C9CB8B4E3881467C36F` |
| SSDEEP | `3072:Xgbfz2jJhjjqvYLdz7mnhxXm9ITP8g1mP76:XOfCjTiYLN7ksITP8g1z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_0d373e1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d373e1f9dfeaa5a1c2bffa6116ce78bc2af1174a503c8cba5944664fae60500"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-09-07 03:12:34"
  condition:
    hash.sha256(0, filesize) == "0d373e1f9dfeaa5a1c2bffa6116ce78bc2af1174a503c8cba5944664fae60500"
}
```

### Sample 29: `28f968b7bd17a853`

| Field | Value |
|---|---|
| SHA-256 | `28f968b7bd17a853cb98c7ac89e20e616fb9b20f0c434b540da5fd2dd5850a67` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-07 03:12:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c31eba292565ea12c096a40f0da0ffb` |
| SHA-1 | `8752979180c6059fe2064e9bf90384e1de83ce6c` |
| SHA-256 | `28f968b7bd17a853cb98c7ac89e20e616fb9b20f0c434b540da5fd2dd5850a67` |
| SHA3-384 | `37698f5046f36ee7c30b0752f59a28b0e1d21cca6a3d6ad8bec893db8c7a98254d0ff224f45d469434055ffac89e74b3` |
| TLSH | `T187236C6516857C14AE98C8365C7F2F0CB9AD43E6314492EE7FCA3CF28C4A6AD920871D` |
| SSDEEP | `768:499NyXsZztCK9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:wHusZ6cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_28f968b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28f968b7bd17a853cb98c7ac89e20e616fb9b20f0c434b540da5fd2dd5850a67"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-07 03:12:32"
  condition:
    hash.sha256(0, filesize) == "28f968b7bd17a853cb98c7ac89e20e616fb9b20f0c434b540da5fd2dd5850a67"
}
```

### Sample 30: `0005921df4484d8e`

| Field | Value |
|---|---|
| SHA-256 | `0005921df4484d8e1d4319b40efc52389e75b8e8e1653afc7cd47379a2d65979` |
| Family label | `CoinMiner` |
| File name | `0005921df4484d8e1d4319b40efc52389e75b8e8e1653afc7cd47379a2d65979.exe` |
| File type | `exe` |
| First seen | `2026-09-07 03:08:24` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38399f68cb5177f14823b296761ed3f1` |
| SHA-1 | `2eca807766846dbb55e41c3ddf7f4e721c641a13` |
| SHA-256 | `0005921df4484d8e1d4319b40efc52389e75b8e8e1653afc7cd47379a2d65979` |
| SHA3-384 | `25383de694aa144fb3f1678ba843c698393ef928133695b1833a73f3cc445e538fba41d18a40b8a0895555f27e1b5118` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T17536338939C6D574D5A3C3B84563707EB37E37258960BCAE7EC9AD104E9BE00583E386` |
| SSDEEP | `98304:tLiEOkFsAz/vjGE94otcStV+4g5u+bwORDwi2YI8QQkcLhk8jw3:tLiwsADyE94oySvhg59vDwiHLhkUw` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_030_0005921d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0005921df4484d8e1d4319b40efc52389e75b8e8e1653afc7cd47379a2d65979"
    family = "CoinMiner"
    file_name = "0005921df4484d8e1d4319b40efc52389e75b8e8e1653afc7cd47379a2d65979.exe"
    file_type = "exe"
    first_seen = "2026-09-07 03:08:24"
  condition:
    hash.sha256(0, filesize) == "0005921df4484d8e1d4319b40efc52389e75b8e8e1653afc7cd47379a2d65979"
}
```

### Sample 31: `0930835df15e2511`

| Field | Value |
|---|---|
| SHA-256 | `0930835df15e25115815eb540c839b62dde02dadc7149040ca5c7474457ee106` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-07 03:03:40` |
| Reporter | `Bitsight` |
| Tags | `54e64e, 9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26dea20b0915b3c469ed70c053b3e5fb` |
| SHA-1 | `922349777fddc85bad44e68a586c478036037cd5` |
| SHA-256 | `0930835df15e25115815eb540c839b62dde02dadc7149040ca5c7474457ee106` |
| SHA3-384 | `e4d05ea689cded7f2b6973d3950fb3ded8bd54f1acb4f30dfdee53095c3c12da28e056f4380973b08c493a914ea315b1` |
| IMPHASH | `a604b4697f94922aff3add61321029b3` |
| TLSH | `T1EE08AE15E3D84B16D67FC27CC2638512E7B1B8421362D7CF0495EA992F63BC1AB36263` |
| SSDEEP | `786432:FbiI1rI7FsKUXTjdJyFV1OH0n5fj5P14Sn7V:FzcFsLGFVHZHZ7V` |
| ICON-DHASH | `a2193c3a2cd62ba6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_0930835d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0930835df15e25115815eb540c839b62dde02dadc7149040ca5c7474457ee106"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-07 03:03:40"
  condition:
    hash.sha256(0, filesize) == "0930835df15e25115815eb540c839b62dde02dadc7149040ca5c7474457ee106"
}
```

### Sample 32: `82bdf2586c0f7b37`

| Field | Value |
|---|---|
| SHA-256 | `82bdf2586c0f7b37448e40c854af2b48fdb5d27dbf43d3f6d18f772e02ccc1c1` |
| Family label | `RemcosRAT` |
| File name | `SOAStatement-WEBBEDSTVLEETBooking #0001255399.js` |
| File type | `js` |
| First seen | `2026-09-07 02:25:05` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af00ac12d1ac92fc0a2f2172df07c572` |
| SHA-1 | `7c023cdf7d64dc1efc15b637882bd6cda94898df` |
| SHA-256 | `82bdf2586c0f7b37448e40c854af2b48fdb5d27dbf43d3f6d18f772e02ccc1c1` |
| SHA3-384 | `1e3525fc1040b187fb6fffca251438a47ab122f01104d53973ecb6502412b0bb7eded48922a685c39b63235b3180e0a0` |
| TLSH | `T10C4660E15361DA32B32957CC52368AA49509728305E1DB1D31BCD626BB2FCC77378EE2` |
| SSDEEP | `98304:JybLFytyNeFszKEOElwp3M9xAY8DPpV/EbGwAV8IjhWRJ2kc1EIGJdTQiN1TyxlK:JybLFYyNIgKEOWG33bH/E6xU2bVwV9NX` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_032_82bdf258
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82bdf2586c0f7b37448e40c854af2b48fdb5d27dbf43d3f6d18f772e02ccc1c1"
    family = "RemcosRAT"
    file_name = "SOAStatement-WEBBEDSTVLEETBooking #0001255399.js"
    file_type = "js"
    first_seen = "2026-09-07 02:25:05"
  condition:
    hash.sha256(0, filesize) == "82bdf2586c0f7b37448e40c854af2b48fdb5d27dbf43d3f6d18f772e02ccc1c1"
}
```

### Sample 33: `f79139304d7e7197`

| Field | Value |
|---|---|
| SHA-256 | `f79139304d7e7197ffe1bab0441eccdfaaa2bd0d745f4c4ea810ec7c92cb2e76` |
| Family label | `GuLoader` |
| File name | `Chlorites.vbs` |
| File type | `vbs` |
| First seen | `2026-09-07 01:33:44` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed85049025cfc4b64d2fe8edbb0d138c` |
| SHA-1 | `91c9f305bdead634287833286ae00c6cbc0d2308` |
| SHA-256 | `f79139304d7e7197ffe1bab0441eccdfaaa2bd0d745f4c4ea810ec7c92cb2e76` |
| SHA3-384 | `18bc9d85867d7305b09d5a294f18352dc96003cc14fe7658411e277c55d98caf7d8ec4a7578e093bdc2c19ed44859882` |
| TLSH | `T155536D20EE6401190E5B27A9DC147E52C5FEA2DA561714E1FFEAB30C440B59CB3BE22E` |
| SSDEEP | `1536:W7KGo9Kji81ob4ZymuN86Y3L6Au1qkhI4wwD2QxP:AI9s/oMy/SN3L3u1qkGRwDtxP` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_033_f7913930
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f79139304d7e7197ffe1bab0441eccdfaaa2bd0d745f4c4ea810ec7c92cb2e76"
    family = "GuLoader"
    file_name = "Chlorites.vbs"
    file_type = "vbs"
    first_seen = "2026-09-07 01:33:44"
  condition:
    hash.sha256(0, filesize) == "f79139304d7e7197ffe1bab0441eccdfaaa2bd0d745f4c4ea810ec7c92cb2e76"
}
```

### Sample 34: `eeb6b304c33fd3ed`

| Field | Value |
|---|---|
| SHA-256 | `eeb6b304c33fd3ed46d2438040507905faed7f20ec73c90cd5a645bad239833d` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-07 00:56:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b70ce6d7461fc6992f97772be169a255` |
| SHA-1 | `fe99384bb7309123d1840fcdf0c90da78364174b` |
| SHA-256 | `eeb6b304c33fd3ed46d2438040507905faed7f20ec73c90cd5a645bad239833d` |
| SHA3-384 | `3078fe963b72ed98f14f3a1da1d2a5e9803f087753af37e8efa862f109c48123fefc323083d7a8f5a51c42a09deffff3` |
| TLSH | `T1ED236C651A857C149A99C4371D7E2F0CB9AD43E6320452EE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:AVEJVIhtM89GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:+EJ2Mxcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_eeb6b304
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeb6b304c33fd3ed46d2438040507905faed7f20ec73c90cd5a645bad239833d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-07 00:56:34"
  condition:
    hash.sha256(0, filesize) == "eeb6b304c33fd3ed46d2438040507905faed7f20ec73c90cd5a645bad239833d"
}
```

### Sample 35: `3a194fa1bf6a0bbf`

| Field | Value |
|---|---|
| SHA-256 | `3a194fa1bf6a0bbf7b9f164b5a81d6d4f8258c5aec5943db0b35977849950ad2` |
| Family label | `unknown` |
| File name | `3a194fa1bf6a0bbf7b9f164b5a81d6d4f8258c5aec5943db0b35977849950ad2.exe` |
| File type | `exe` |
| First seen | `2026-09-07 00:38:46` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f723b0c3564c6c452474b2ec939c8dc` |
| SHA-1 | `14f92afa36fb720357d1ce252559bb82bee5e643` |
| SHA-256 | `3a194fa1bf6a0bbf7b9f164b5a81d6d4f8258c5aec5943db0b35977849950ad2` |
| SHA3-384 | `93a71556834e41265c8da08e164dfc508bb6213d840c70da7d4e28144fdf44d3e2125a5a34d7866b74f5e26f0f5fe0de` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T10DD523D8BED21571E033C3B756C354BEB16A7B4186604D8BB6C96B007E22A2DAC37375` |
| SSDEEP | `49152:6AmH548yUi1Tt3V42Soh2wEdWtgYZnv8zUOC2vLV4a0/X52w1+v77S:6r548yUUTt3baWtTv8zfJ54H/F1YS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_3a194fa1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a194fa1bf6a0bbf7b9f164b5a81d6d4f8258c5aec5943db0b35977849950ad2"
    family = "unknown"
    file_name = "3a194fa1bf6a0bbf7b9f164b5a81d6d4f8258c5aec5943db0b35977849950ad2.exe"
    file_type = "exe"
    first_seen = "2026-09-07 00:38:46"
  condition:
    hash.sha256(0, filesize) == "3a194fa1bf6a0bbf7b9f164b5a81d6d4f8258c5aec5943db0b35977849950ad2"
}
```

### Sample 36: `01b14dd94b830351`

| Field | Value |
|---|---|
| SHA-256 | `01b14dd94b830351164ba0ca558b5534e0741b1631b6603d20096776dea34841` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-07 00:08:30` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd05666b505478f5f96a7495dfaf0446` |
| SHA-1 | `96b32b849d98f3af6205571f70bd6836118f3954` |
| SHA-256 | `01b14dd94b830351164ba0ca558b5534e0741b1631b6603d20096776dea34841` |
| SHA3-384 | `ce8523c8104621eba914cc86030178d8de9aa093f2e5ef4825c0890b30e370242d97565cc06843463e7c30cf30aeac64` |
| IMPHASH | `20dd26497880c05caed9305b3c8b9109` |
| TLSH | `T147463357A3E31079E441BFBB84A594401D2278BC1AE5B4013DB5E30C2EBDFE685B6B63` |
| SSDEEP | `98304:Y7Q9D3VHU/OH7FKpqJ3T+CSVAmS2LSmySrT6oBwUzr1S1M4d:YCFKpu3TAVAr2gSrRxf1Cvd` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_01b14dd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01b14dd94b830351164ba0ca558b5534e0741b1631b6603d20096776dea34841"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-07 00:08:30"
  condition:
    hash.sha256(0, filesize) == "01b14dd94b830351164ba0ca558b5534e0741b1631b6603d20096776dea34841"
}
```

### Sample 37: `0e52dc105f018542`

| Field | Value |
|---|---|
| SHA-256 | `0e52dc105f01854254ee865a31af4b79f701c9437ca7591d979e60ade6d6cf2f` |
| Family label | `unknown` |
| File name | `PrmUx.js` |
| File type | `js` |
| First seen | `2026-09-06 23:39:05` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b91d6c726fa93a3ad6e7bbd75452245` |
| SHA-1 | `70ce994b8d1519c9a6e9f96b012d82a583050b74` |
| SHA-256 | `0e52dc105f01854254ee865a31af4b79f701c9437ca7591d979e60ade6d6cf2f` |
| SHA3-384 | `8d4aec7c8f06f5e19501e3d04d58ce75fed32ae29007226536941389334dcebad7c436bdef85695db8e2a435074b07da` |
| TLSH | `TNULL` |
| SSDEEP | `3:UtRwgyKwajZg/4kn:SRwgKQZgr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_0e52dc10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e52dc105f01854254ee865a31af4b79f701c9437ca7591d979e60ade6d6cf2f"
    family = "unknown"
    file_name = "PrmUx.js"
    file_type = "js"
    first_seen = "2026-09-06 23:39:05"
  condition:
    hash.sha256(0, filesize) == "0e52dc105f01854254ee865a31af4b79f701c9437ca7591d979e60ade6d6cf2f"
}
```

### Sample 38: `926054d5f2882959`

| Field | Value |
|---|---|
| SHA-256 | `926054d5f2882959f4747a04ed67d899c9983a8788660fbfe9a887164b411fdc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-06 23:33:35` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2375a2379f2d8305069831aadc72eeba` |
| SHA-1 | `82d87ee37e674a8152647d899f20fd9a6d123ce6` |
| SHA-256 | `926054d5f2882959f4747a04ed67d899c9983a8788660fbfe9a887164b411fdc` |
| SHA3-384 | `27c80716d78b053edb093e38c8dfe476950122951e7521eaac9855a690966530b2c39588ca5d434359473c5a5015527d` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T17C963381BAE1447DE1BC6F78C6F38101CC34BC988BB1960F3599F99E89B23D25678716` |
| SSDEEP | `196608:UGpyS4/cNzwbTBS0DZxdS+rcBI5/qApRuh97so6bT6:UG8TUVwBXDxS+g2qAp476bG` |
| ICON-DHASH | `b46269d8e8215000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_926054d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "926054d5f2882959f4747a04ed67d899c9983a8788660fbfe9a887164b411fdc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-06 23:33:35"
  condition:
    hash.sha256(0, filesize) == "926054d5f2882959f4747a04ed67d899c9983a8788660fbfe9a887164b411fdc"
}
```

### Sample 39: `846f390faea2a33d`

| Field | Value |
|---|---|
| SHA-256 | `846f390faea2a33d5ca0c1876292853c55439bd1c26c8206a62afcd4c7333593` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-06 23:32:14` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX2.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e87ce4b1b9398c6290557d0852e7fbd2` |
| SHA-1 | `4eee87669038ff0c974af1a447931b8eb22f2a85` |
| SHA-256 | `846f390faea2a33d5ca0c1876292853c55439bd1c26c8206a62afcd4c7333593` |
| SHA3-384 | `aa39c34605bb8364d77b0c11148d83fea7ee2843e544ab2e2c25850c18c7bbcc5b5251f42b6cbca474b34929ecac33b3` |
| IMPHASH | `5f5fa424e9b15e23e31be560376f47b5` |
| TLSH | `T1A6F523A4E4C728B4D85BF7B6869B737DF16E3BA20560DC473ACC6F000E72215653AB91` |
| SSDEEP | `98304:QNnZtvLXVvr3vZ8OJvNNK9Unrcq1kLpvgXPCDH:QDtvLRjvZlJvN0KCVmPCDH` |
| ICON-DHASH | `9271f8f0f0f0f0ec` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_846f390f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "846f390faea2a33d5ca0c1876292853c55439bd1c26c8206a62afcd4c7333593"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-06 23:32:14"
  condition:
    hash.sha256(0, filesize) == "846f390faea2a33d5ca0c1876292853c55439bd1c26c8206a62afcd4c7333593"
}
```

### Sample 40: `e801f57192dae98f`

| Field | Value |
|---|---|
| SHA-256 | `e801f57192dae98fac7cefc90bc5da6332bc668a5a2d9addbf135427ccd0c8d0` |
| Family label | `GuLoader` |
| File name | `Unstintingly.vbs` |
| File type | `vbs` |
| First seen | `2026-09-06 23:13:15` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f750668658c89814794b813a788ada5` |
| SHA-1 | `c8918d4cbc3f080db337d5efde2b8a75c493a208` |
| SHA-256 | `e801f57192dae98fac7cefc90bc5da6332bc668a5a2d9addbf135427ccd0c8d0` |
| SHA3-384 | `d409b2b5d42a4e1a91b6ebb40d3451da57c0e9a8d1b91ecf7795ff75a42e6a6007d0bceb8e872351423ade6204f4bc3f` |
| TLSH | `T159535B34FA6D023B4D4B2EBDECC61E55C5BE9211112350F1BEE4630C5446EACA3BE6AD` |
| SSDEEP | `1536:WQL2t2KHZw4v1JmkIVKz3e6AuPUaht4wwDVWo:jK2cu4vTIVs3e3uPUaTRwDVh` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_040_e801f571
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e801f57192dae98fac7cefc90bc5da6332bc668a5a2d9addbf135427ccd0c8d0"
    family = "GuLoader"
    file_name = "Unstintingly.vbs"
    file_type = "vbs"
    first_seen = "2026-09-06 23:13:15"
  condition:
    hash.sha256(0, filesize) == "e801f57192dae98fac7cefc90bc5da6332bc668a5a2d9addbf135427ccd0c8d0"
}
```

### Sample 41: `46dc1914bfd36e66`

| Field | Value |
|---|---|
| SHA-256 | `46dc1914bfd36e66de65da421aba7581711cf761705a0cc8c9affc9f674c710e` |
| Family label | `Vidar` |
| File name | `46dc1914bfd36e66de65da421aba7581711cf761705a0cc8c9affc9f674c710e.bin` |
| File type | `exe` |
| First seen | `2026-09-06 23:12:34` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `735de4014969c6106fe08998e9529322` |
| SHA-1 | `4fdd7a6c6cf28775e40f6760fc7a31774edb97bb` |
| SHA-256 | `46dc1914bfd36e66de65da421aba7581711cf761705a0cc8c9affc9f674c710e` |
| SHA3-384 | `331057ba8547e6a7198e292f3d9ccd4187a8164921b1bfee7e462bdfce7c52af3b04e035025a39de3b7a679e5965f2f8` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E3867D0BF96001B5C89A9730C9BB12537B79B8489B3273E36D1076746F7A7E0B9B6704` |
| SSDEEP | `49152:1DxwUYSBf2JmsDnCsTgklVrgz0LzyJb0zxvbPAY1BR2YsnE2h+NVjewQGJ+/gWEj:1dsCgl5satT1yZqJ` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_041_46dc1914
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46dc1914bfd36e66de65da421aba7581711cf761705a0cc8c9affc9f674c710e"
    family = "Vidar"
    file_name = "46dc1914bfd36e66de65da421aba7581711cf761705a0cc8c9affc9f674c710e.bin"
    file_type = "exe"
    first_seen = "2026-09-06 23:12:34"
  condition:
    hash.sha256(0, filesize) == "46dc1914bfd36e66de65da421aba7581711cf761705a0cc8c9affc9f674c710e"
}
```

### Sample 42: `67e8ef0325a8725e`

| Field | Value |
|---|---|
| SHA-256 | `67e8ef0325a8725e9884c0b19ac014f0c3ea497eee1f905187b8d77b25221689` |
| Family label | `unknown` |
| File name | `67e8ef0325a8725e9884c0b19ac014f0c3ea497eee1f905187b8d77b25221689.bin` |
| File type | `exe` |
| First seen | `2026-09-06 23:12:31` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3148634c8654854e404f555d2bd2b96` |
| SHA-1 | `3692cd56bedffa423bbec11f824a3c0fbdb0de83` |
| SHA-256 | `67e8ef0325a8725e9884c0b19ac014f0c3ea497eee1f905187b8d77b25221689` |
| SHA3-384 | `7180463d8edaaa044ea69bd8a014ec4ff3783e949272f12860902be74c058532bf4dc920501658e9397130bbcddcad35` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T136D66B03B9A861F4D45D9A34C57F12A3AB25BC8CC73563971E406A302F6BBC17EB6358` |
| SSDEEP | `98304:c5nu8M9wv8tC+8XEIWnHFNn1MmURPE9NuDdAyiZ:ckuvd+RIUnUoYiZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_67e8ef03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67e8ef0325a8725e9884c0b19ac014f0c3ea497eee1f905187b8d77b25221689"
    family = "unknown"
    file_name = "67e8ef0325a8725e9884c0b19ac014f0c3ea497eee1f905187b8d77b25221689.bin"
    file_type = "exe"
    first_seen = "2026-09-06 23:12:31"
  condition:
    hash.sha256(0, filesize) == "67e8ef0325a8725e9884c0b19ac014f0c3ea497eee1f905187b8d77b25221689"
}
```

### Sample 43: `74a28581cdc96b69`

| Field | Value |
|---|---|
| SHA-256 | `74a28581cdc96b69d58c1b2f640c2f3c6932d11eb4b53fb5bf9cf2e89ac30dd4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-06 23:08:20` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c78b60ce5342bf9df1a81e4165c433cc` |
| SHA-1 | `12cf71c80316f19513163cab9c8c73944ac75a87` |
| SHA-256 | `74a28581cdc96b69d58c1b2f640c2f3c6932d11eb4b53fb5bf9cf2e89ac30dd4` |
| SHA3-384 | `ecd44c0170a2fef8836931554eb664a1534b73c1332df5c40c632c2dd811603764bb91e25d8da4aa948e07cf4d2948fc` |
| IMPHASH | `fd0cdb4a8a6540edb41d120205cd9d07` |
| TLSH | `T178B4F15BF78817F8D12AE67889654A45A6B2B4913B527AEF07A001E35F737C04D3FB20` |
| SSDEEP | `12288:r7558r/GPc1rwpBdITX8GsEilnfT4Z8N:3kGU1rwfly+k2N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_74a28581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74a28581cdc96b69d58c1b2f640c2f3c6932d11eb4b53fb5bf9cf2e89ac30dd4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-06 23:08:20"
  condition:
    hash.sha256(0, filesize) == "74a28581cdc96b69d58c1b2f640c2f3c6932d11eb4b53fb5bf9cf2e89ac30dd4"
}
```

### Sample 44: `d53bfb43671e23ef`

| Field | Value |
|---|---|
| SHA-256 | `d53bfb43671e23ef1f925166938a2f4fb28ad163f88e92a26505aa2d56cf8977` |
| Family label | `AsyncRAT` |
| File name | `d53bfb43671e23ef1f925166938a2f4fb28ad163f88e92a26505aa2d56cf8977.bin` |
| File type | `zip` |
| First seen | `2026-09-06 22:59:40` |
| Reporter | `Tuxxin` |
| Tags | `AsyncRAT, exe, whack.sh, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4293df021391096798350408310c5787` |
| SHA-1 | `144d9363edbd6e354d14ed17ef2f04b60aa6f23a` |
| SHA-256 | `d53bfb43671e23ef1f925166938a2f4fb28ad163f88e92a26505aa2d56cf8977` |
| SHA3-384 | `fd8c0c88e8a23d4a1477560d0757e7189974281bb1072c706de2dfbbf4ec4b1dbff49cc45c6ad8523e9bb287082bb819` |
| TLSH | `T104E2F1AFD70A872BA2F2917CC061335D332F248ED2F725016A284787B8C655F656CDC9` |
| SSDEEP | `768:J4bfo5SafnBsbLufB8f0G+CLD+R5CAOs6E2jZycASFcwfc/:J95SequfB8fICyZ2jAcAoc/` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_044_d53bfb43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d53bfb43671e23ef1f925166938a2f4fb28ad163f88e92a26505aa2d56cf8977"
    family = "AsyncRAT"
    file_name = "d53bfb43671e23ef1f925166938a2f4fb28ad163f88e92a26505aa2d56cf8977.bin"
    file_type = "zip"
    first_seen = "2026-09-06 22:59:40"
  condition:
    hash.sha256(0, filesize) == "d53bfb43671e23ef1f925166938a2f4fb28ad163f88e92a26505aa2d56cf8977"
}
```

### Sample 45: `052f0caff530a67f`

| Field | Value |
|---|---|
| SHA-256 | `052f0caff530a67f9a17df5795806d9b01a551f309e434cd4eb92fba8e024051` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-06 22:59:21` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba6e6307f89fa58ee8decc698d40062a` |
| SHA-1 | `d1edd21ab466c2d1ae4f0dc67432d1e839261a87` |
| SHA-256 | `052f0caff530a67f9a17df5795806d9b01a551f309e434cd4eb92fba8e024051` |
| SHA3-384 | `afe84a3e7d88658ca524eefb32b4adff5c7a518748f6050f8aaf8fb273a64c95b6aba93d336bbd40e7b89ed79783d951` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T12E65F196FBD7EE61E38E0E3881732D4787E6D4251173E30A488B7AE44C9B72D5812397` |
| SSDEEP | `24576:Xa+ZW0rXdUTT1y4eljhTIAqKfySMfk5/uWVKEzyC/1WoNJhvk:X/WMXdUxGvMkcE3/EoR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_052f0caf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "052f0caff530a67f9a17df5795806d9b01a551f309e434cd4eb92fba8e024051"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-06 22:59:21"
  condition:
    hash.sha256(0, filesize) == "052f0caff530a67f9a17df5795806d9b01a551f309e434cd4eb92fba8e024051"
}
```

### Sample 46: `00e4094ed954d05c`

| Field | Value |
|---|---|
| SHA-256 | `00e4094ed954d05c9089582e75716ef8edaca197e0b2d29ab8c7357d8e1651e8` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-06 22:36:43` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `070ac2e30af41005961f8a82dbf41b71` |
| SHA-256 | `00e4094ed954d05c9089582e75716ef8edaca197e0b2d29ab8c7357d8e1651e8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_00e4094e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00e4094ed954d05c9089582e75716ef8edaca197e0b2d29ab8c7357d8e1651e8"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-06 22:36:43"
  condition:
    hash.sha256(0, filesize) == "00e4094ed954d05c9089582e75716ef8edaca197e0b2d29ab8c7357d8e1651e8"
}
```

### Sample 47: `764e5f51e92dd166`

| Field | Value |
|---|---|
| SHA-256 | `764e5f51e92dd166ff27cf105a7e1de4ab8689db0aaf6aa404839db6dc549b39` |
| Family label | `Mirai` |
| File name | `kworker` |
| File type | `elf` |
| First seen | `2026-09-06 22:28:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b18b349465b1caea55f4236f91ef32b` |
| SHA-1 | `5d003d4a1c3c6709e668510137e37cf96d0fb410` |
| SHA-256 | `764e5f51e92dd166ff27cf105a7e1de4ab8689db0aaf6aa404839db6dc549b39` |
| SHA3-384 | `181a9661d6880fe5fe7a0f89949b2f8a28e933a4100529cf0a25a375d4c84a5f479c43c297fdb91cfefabf2ed0f70504` |
| TLSH | `T168D32A00F990C767C2D2177AF79E429D33332B68979B33255A34ABB42FC17992E39521` |
| TELFHASH | `t1cc213e5262fe8b286bf34924ec7c03f115912a2372853e70bf1ec6c4453b046b866e9f` |
| SSDEEP | `3072:81Hfa6gzyrlJLQ3navxWIFkqHPVwkqf706CjzmsQTi7aHgp:4JLmnavkwP2kqajzmsQTi+Hgp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_764e5f51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "764e5f51e92dd166ff27cf105a7e1de4ab8689db0aaf6aa404839db6dc549b39"
    family = "Mirai"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-09-06 22:28:41"
  condition:
    hash.sha256(0, filesize) == "764e5f51e92dd166ff27cf105a7e1de4ab8689db0aaf6aa404839db6dc549b39"
}
```

### Sample 48: `aaaf5da70c09896a`

| Field | Value |
|---|---|
| SHA-256 | `aaaf5da70c09896a1527b7b32a2f9ec22184b8bdb2cca248accd48492e8a1cef` |
| Family label | `unknown` |
| File name | `installer_r2.0.18.exe` |
| File type | `exe` |
| First seen | `2026-09-06 22:26:40` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8cbfe7bfce42787ef7810aaffd1fdd8` |
| SHA-1 | `5119e15cc4e00eaece12898300bfcc239d88d46c` |
| SHA-256 | `aaaf5da70c09896a1527b7b32a2f9ec22184b8bdb2cca248accd48492e8a1cef` |
| SHA3-384 | `b91a4ce9a9ab6c2e0cc62273a66c37d01b40d2adba6142d3acbaff7a2ef0afb39ee460a270c6d7efcbfa49c7e38e6bf8` |
| IMPHASH | `c329cfdce996b315359260e710fbdc76` |
| TLSH | `T1EE67EA46B605C98AE0265274D8878FF4A722ECB1C6B1976733A93F1D7FFA30C4E92454` |
| SSDEEP | `98304:7ClvSImXQ9EkE6uzJdQ2Orf8wsGF4tVjibVpOMOaci583EGsGFCJNlvj:GlvSIkQu5TcT4PILhAxTCxvj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_aaaf5da7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aaaf5da70c09896a1527b7b32a2f9ec22184b8bdb2cca248accd48492e8a1cef"
    family = "unknown"
    file_name = "installer_r2.0.18.exe"
    file_type = "exe"
    first_seen = "2026-09-06 22:26:40"
  condition:
    hash.sha256(0, filesize) == "aaaf5da70c09896a1527b7b32a2f9ec22184b8bdb2cca248accd48492e8a1cef"
}
```

### Sample 49: `cb348c4b94101839`

| Field | Value |
|---|---|
| SHA-256 | `cb348c4b941018399a9e1e3172bf43872849d511927bd42f81008b2a53c344ca` |
| Family label | `unknown` |
| File name | `installer_r2.0.03.exe` |
| File type | `exe` |
| First seen | `2026-09-06 22:25:41` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a333f4fa28043d3461d1ce1f813960c3` |
| SHA-1 | `46817aebd934617a30347195e2eee257e9d3b57a` |
| SHA-256 | `cb348c4b941018399a9e1e3172bf43872849d511927bd42f81008b2a53c344ca` |
| SHA3-384 | `e3f3721b72b1c563b304b2c1ac77df84fa1c1868077b05d83e62f212adcba36b24c73fc31470b075398937d0980ca6aa` |
| IMPHASH | `c329cfdce996b315359260e710fbdc76` |
| TLSH | `T1B767EA46B605C98AE0265274D8878FF4A722ECB1C6B1976733A93F1D7FFA30C4E92454` |
| SSDEEP | `98304:kClvSImXQ9EkE6uzJdQ2Orf8wsGF4tVjibVpOMOaci583EGsGFCJNlvm:plvSIkQu5TcT4PILhAxTCxvm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_cb348c4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb348c4b941018399a9e1e3172bf43872849d511927bd42f81008b2a53c344ca"
    family = "unknown"
    file_name = "installer_r2.0.03.exe"
    file_type = "exe"
    first_seen = "2026-09-06 22:25:41"
  condition:
    hash.sha256(0, filesize) == "cb348c4b941018399a9e1e3172bf43872849d511927bd42f81008b2a53c344ca"
}
```

### Sample 50: `394db160badc3198`

| Field | Value |
|---|---|
| SHA-256 | `394db160badc3198c94aa6c7fea01e68d6908864e1b35084538079b4f19e3a6f` |
| Family label | `unknown` |
| File name | `installer_r2.0.02.exe` |
| File type | `exe` |
| First seen | `2026-09-06 22:24:22` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae195298087be617ee0f265c3e611e92` |
| SHA-1 | `5323a026789b632726541bf2ed49e1550062804f` |
| SHA-256 | `394db160badc3198c94aa6c7fea01e68d6908864e1b35084538079b4f19e3a6f` |
| SHA3-384 | `733e6d3098b470c9c91f6b3699888f9cfde80f3ed62d7d743e0b2ef57fb58518cfa93704bf11d00e52b9173c2363a8fd` |
| IMPHASH | `c329cfdce996b315359260e710fbdc76` |
| TLSH | `T10C67EA46B605C98AE0265274D8878FF4A722ECB1C6B1976733A93F1D7FFA30C4E92454` |
| SSDEEP | `98304:9ClvSImXQ9EkE6uzJdQ2Orf8wsGF4tVjibVpOMOaci583EGsGFCJNlvj:MlvSIkQu5TcT4PILhAxTCxvj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_394db160
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "394db160badc3198c94aa6c7fea01e68d6908864e1b35084538079b4f19e3a6f"
    family = "unknown"
    file_name = "installer_r2.0.02.exe"
    file_type = "exe"
    first_seen = "2026-09-06 22:24:22"
  condition:
    hash.sha256(0, filesize) == "394db160badc3198c94aa6c7fea01e68d6908864e1b35084538079b4f19e3a6f"
}
```

### Sample 51: `daff0b9de30438bb`

| Field | Value |
|---|---|
| SHA-256 | `daff0b9de30438bb1578bb35e6c4388187ea6e7c9cc4a14ee3a0b9eb45a22c46` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-06 22:20:47` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb8e2842a2cb9ab155be0fb726f169c2` |
| SHA-1 | `d0d7aa5c4ed883f445108c906278e5393024c1cc` |
| SHA-256 | `daff0b9de30438bb1578bb35e6c4388187ea6e7c9cc4a14ee3a0b9eb45a22c46` |
| SHA3-384 | `fc03ae3059a86a321a7e517a2da238a3fc89764cac593bc77b718509ccf63dd62a5eef7ce720b8eb7cdb3bbf1252cd14` |
| TLSH | `T1EA236D6516857C24AA98C4371D7E2F0CBDAD43E6320492EE7FCB3CF28C5A69D910971D` |
| SSDEEP | `768:NXRWNGxV49GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:3lx7cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_daff0b9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daff0b9de30438bb1578bb35e6c4388187ea6e7c9cc4a14ee3a0b9eb45a22c46"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-06 22:20:47"
  condition:
    hash.sha256(0, filesize) == "daff0b9de30438bb1578bb35e6c4388187ea6e7c9cc4a14ee3a0b9eb45a22c46"
}
```

### Sample 52: `363576a90042aa9b`

| Field | Value |
|---|---|
| SHA-256 | `363576a90042aa9b9bd6c8fef815f38b75bbf25dc251e8219820dff96f54c645` |
| Family label | `unknown` |
| File name | `363576a90042aa9b9bd6c8fef815f38b75bbf25dc251e8219820dff96f54c645.exe` |
| File type | `exe` |
| First seen | `2026-09-06 22:13:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `707ad262d7981698b302502559ea7c7e` |
| SHA-1 | `7caf4affcef597144ef3f8853bab7bcb703d30c6` |
| SHA-256 | `363576a90042aa9b9bd6c8fef815f38b75bbf25dc251e8219820dff96f54c645` |
| SHA3-384 | `5614ba567675aeb5779be7b25f60665077ede9963e60d8e8fee67ae15b23c44e9003fabd00eae0066f78f98996c956aa` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T193D522DAB8FA2A74D477C3B68F42F4BDB06A77814B348E87369D2A100D536446D39339` |
| SSDEEP | `49152:fn2+tBF92dag6HeB4DEagS0jEOoWgXVcbwR33CDZ/yVgSG/YUVdTSvj:f2+fFvgVYEFUWgFcbQ36aLMD4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_363576a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "363576a90042aa9b9bd6c8fef815f38b75bbf25dc251e8219820dff96f54c645"
    family = "unknown"
    file_name = "363576a90042aa9b9bd6c8fef815f38b75bbf25dc251e8219820dff96f54c645.exe"
    file_type = "exe"
    first_seen = "2026-09-06 22:13:18"
  condition:
    hash.sha256(0, filesize) == "363576a90042aa9b9bd6c8fef815f38b75bbf25dc251e8219820dff96f54c645"
}
```

### Sample 53: `25f6dbcaefccc99c`

| Field | Value |
|---|---|
| SHA-256 | `25f6dbcaefccc99c7878ade79fd66e8714760133f74cb282b19170f67b07cab6` |
| Family label | `unknown` |
| File name | `launch.sh` |
| File type | `sh` |
| First seen | `2026-09-06 22:12:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31260b1a40034638ae06f9faf6b88554` |
| SHA-1 | `ac60535cbcc50f3aa004a41b68bd2066326172ea` |
| SHA-256 | `25f6dbcaefccc99c7878ade79fd66e8714760133f74cb282b19170f67b07cab6` |
| SHA3-384 | `855c3683311848ef5e4503f286b8330fc31d14002837d92ef092a5baa3864ef69e455c30bf7744423f5aa9de15defc61` |
| TLSH | `T195F09E052BE184F7C21436E84F1FD06B441653AF31E35F901A06266F4D9A0EF7161461` |
| SSDEEP | `12:JaCBZooEFcQ0Do1LKBesx5IjFc1H5N1opebsJEXAMJEXna8nFFH+J:JaCfooEFcQ0cpRjFkH31opebsJEXAMJN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_25f6dbca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25f6dbcaefccc99c7878ade79fd66e8714760133f74cb282b19170f67b07cab6"
    family = "unknown"
    file_name = "launch.sh"
    file_type = "sh"
    first_seen = "2026-09-06 22:12:40"
  condition:
    hash.sha256(0, filesize) == "25f6dbcaefccc99c7878ade79fd66e8714760133f74cb282b19170f67b07cab6"
}
```

### Sample 54: `a037767ff9f8496c`

| Field | Value |
|---|---|
| SHA-256 | `a037767ff9f8496c3ff65c4d34b38d52e4f52ab6de075b03f0bd43408502087d` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-06 22:10:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae7f6c84267e38c08ea8776fd0d62de2` |
| SHA-1 | `9a3cdd1e80920dab81aa46f2a0b4f14e6f28fa49` |
| SHA-256 | `a037767ff9f8496c3ff65c4d34b38d52e4f52ab6de075b03f0bd43408502087d` |
| SHA3-384 | `c4a5ea4d3d4c2b4e906a108076d7a53636dbb549e4bc8a75227bb20f5118e3c8a0a5fa3b66843b1c37411bc2a207d6ef` |
| TLSH | `T18C236C651A857C149A99C4371D7F2F0CB9AD43E6320452DE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:jVEJVIhtMo9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:5EJ2M1cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_a037767f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a037767ff9f8496c3ff65c4d34b38d52e4f52ab6de075b03f0bd43408502087d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-06 22:10:46"
  condition:
    hash.sha256(0, filesize) == "a037767ff9f8496c3ff65c4d34b38d52e4f52ab6de075b03f0bd43408502087d"
}
```

### Sample 55: `f9203fd939323924`

| Field | Value |
|---|---|
| SHA-256 | `f9203fd93932392404872c6cfdc90b6328d494ec8d607a87fe5ceef71d211c79` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-06 22:06:01` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c83e6e3921ea8f9461db86bf0ff18ea3` |
| SHA-1 | `35f837a5bc1ffdcd41149a45335a6f8f50ab842c` |
| SHA-256 | `f9203fd93932392404872c6cfdc90b6328d494ec8d607a87fe5ceef71d211c79` |
| SHA3-384 | `0f12023e94c54021e2746aa93529db6e5a445b220c09750c156441591a67da0ef2c6a8aa5ca68d2a11aa71a2fddbb41b` |
| TLSH | `T18DC28D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:08vCB+25j6es8RSW9FYpMSUpi+20qUpi+20YQX:08l25JLd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_f9203fd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9203fd93932392404872c6cfdc90b6328d494ec8d607a87fe5ceef71d211c79"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-06 22:06:01"
  condition:
    hash.sha256(0, filesize) == "f9203fd93932392404872c6cfdc90b6328d494ec8d607a87fe5ceef71d211c79"
}
```

### Sample 56: `7856c46f70d3cf10`

| Field | Value |
|---|---|
| SHA-256 | `7856c46f70d3cf105ee1a4b89a56e66270ef07e364436d33748455e7871a8db8` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-06 21:37:47` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9793d48461d9c2ea834c1e9bc9e60587` |
| SHA-1 | `570ae0979537faa4920abb4956d0e581cc91949f` |
| SHA-256 | `7856c46f70d3cf105ee1a4b89a56e66270ef07e364436d33748455e7871a8db8` |
| SHA3-384 | `94cfe58f82803bc5ac594d81d73151a839377c657ec297c8d3948bea0e1aa4133149802fad682c9dfbda230509e93e3b` |
| TLSH | `T1323164DE01141A315002CE8E73A33249A19EEAF7689FD7D4DD685EF991883CCF263B59` |
| SSDEEP | `24:zq/4v3we5rX218MdLCaF1Nljadk9fqIMZMF:zq/EbiNLfNleYxMZMF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_7856c46f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7856c46f70d3cf105ee1a4b89a56e66270ef07e364436d33748455e7871a8db8"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-06 21:37:47"
  condition:
    hash.sha256(0, filesize) == "7856c46f70d3cf105ee1a4b89a56e66270ef07e364436d33748455e7871a8db8"
}
```

### Sample 57: `3f64b47077def396`

| Field | Value |
|---|---|
| SHA-256 | `3f64b47077def39688ca9d675d05f99449c6e11184227123a03da4e542e7a809` |
| Family label | `unknown` |
| File name | `goodthingsforbestpersonforme.hta` |
| File type | `hta` |
| First seen | `2026-09-06 21:23:51` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb5b172efbc8eca92ef9ffacad53c7a6` |
| SHA-1 | `6b16124c4a6852db15ac5d9468be067b61ce049b` |
| SHA-256 | `3f64b47077def39688ca9d675d05f99449c6e11184227123a03da4e542e7a809` |
| SHA3-384 | `e94a11dd4dd12e383dbdd515af51a147d2c1fb4697bc87507870c48e8e2e97d42d9d8fb59e0629fdb42e952367cd8572` |
| TLSH | `T1CBF05C4298A08D29523016146EC0FA055E9AEA479749BD4C76AAA0BD1FC47C1CDCF87C` |
| SSDEEP | `6:qTIuJzhqIwGiY63fAbplilAl3t11/+SR0AqIbR2AWHwlcXCILV4LKTjawlauF0N9:qTp0JYyg9193R5qsPWDXXLVeuqAEd2QL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_3f64b470
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f64b47077def39688ca9d675d05f99449c6e11184227123a03da4e542e7a809"
    family = "unknown"
    file_name = "goodthingsforbestpersonforme.hta"
    file_type = "hta"
    first_seen = "2026-09-06 21:23:51"
  condition:
    hash.sha256(0, filesize) == "3f64b47077def39688ca9d675d05f99449c6e11184227123a03da4e542e7a809"
}
```

### Sample 58: `5b6daf199b4f6a64`

| Field | Value |
|---|---|
| SHA-256 | `5b6daf199b4f6a649690ee385b49dfc4f04a37cb9d20e9e2825321af780bd86c` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-06 21:17:46` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cce3c62f7108dfe534f4d99679282e2d` |
| SHA-256 | `5b6daf199b4f6a649690ee385b49dfc4f04a37cb9d20e9e2825321af780bd86c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_5b6daf19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b6daf199b4f6a649690ee385b49dfc4f04a37cb9d20e9e2825321af780bd86c"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-06 21:17:46"
  condition:
    hash.sha256(0, filesize) == "5b6daf199b4f6a649690ee385b49dfc4f04a37cb9d20e9e2825321af780bd86c"
}
```

### Sample 59: `aec8af25da16b467`

| Field | Value |
|---|---|
| SHA-256 | `aec8af25da16b46753cafb08e8311e21adc072c2b442b7c56f7ddb91197f6c39` |
| Family label | `Mirai` |
| File name | `riscv32` |
| File type | `elf` |
| First seen | `2026-09-06 21:17:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc3cbd4dda5db4a985585232050f0829` |
| SHA-1 | `ddebb09311760b856b0709d92f0d734858b91083` |
| SHA-256 | `aec8af25da16b46753cafb08e8311e21adc072c2b442b7c56f7ddb91197f6c39` |
| SHA3-384 | `04397ff5e63457416f02a16f3a4a82b3b50ef6565d50f8718f64ff26b3a0a577e9c68c967d2c73c6771df4b5cf454883` |
| TLSH | `T114742A8CA2F1E3CEE158EE745321BC1A5D72463B3093728A619EB97313BB19449F9D70` |
| SSDEEP | `6144:qyv340X2YpbcbwajL4LgUNmv1kPLoOqqa90u:R5miwUYXUNw1kTTa90u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_aec8af25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aec8af25da16b46753cafb08e8311e21adc072c2b442b7c56f7ddb91197f6c39"
    family = "Mirai"
    file_name = "riscv32"
    file_type = "elf"
    first_seen = "2026-09-06 21:17:45"
  condition:
    hash.sha256(0, filesize) == "aec8af25da16b46753cafb08e8311e21adc072c2b442b7c56f7ddb91197f6c39"
}
```

### Sample 60: `1b11ac41a6d5dfb8`

| Field | Value |
|---|---|
| SHA-256 | `1b11ac41a6d5dfb86512055953983daf30e4762adb61576cf55e47c02440dcf3` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-06 21:11:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33c424cfdedef3ea528b28c5c01fb32d` |
| SHA-1 | `49f91fc47c8e07f02316816232b48ede6ba3b38c` |
| SHA-256 | `1b11ac41a6d5dfb86512055953983daf30e4762adb61576cf55e47c02440dcf3` |
| SHA3-384 | `f6d69add0b030eb80417f7e1d640a70b309697cf6b84c78734da32be9bdca7ddf98b701263d41823c332a44fcbbb507f` |
| TLSH | `T158C27D956A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C12FACD618B1A` |
| SSDEEP | `768:B8vCB+25j6es8RN9FYpMSUpi+20qUpi+20YQX:B8l25J7d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_1b11ac41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b11ac41a6d5dfb86512055953983daf30e4762adb61576cf55e47c02440dcf3"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-06 21:11:53"
  condition:
    hash.sha256(0, filesize) == "1b11ac41a6d5dfb86512055953983daf30e4762adb61576cf55e47c02440dcf3"
}
```

### Sample 61: `06a5de44a3305caf`

| Field | Value |
|---|---|
| SHA-256 | `06a5de44a3305cafcc0ae4a51e051fa6f64de8a5c11b580ae18bb0a88f1dfaee` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-06 21:09:44` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32ab563be5c7183712a2194e4d5d1701` |
| SHA-256 | `06a5de44a3305cafcc0ae4a51e051fa6f64de8a5c11b580ae18bb0a88f1dfaee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_06a5de44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06a5de44a3305cafcc0ae4a51e051fa6f64de8a5c11b580ae18bb0a88f1dfaee"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-06 21:09:44"
  condition:
    hash.sha256(0, filesize) == "06a5de44a3305cafcc0ae4a51e051fa6f64de8a5c11b580ae18bb0a88f1dfaee"
}
```

### Sample 62: `5aa0cd0fb49efc53`

| Field | Value |
|---|---|
| SHA-256 | `5aa0cd0fb49efc5368952f1449686a63f61f33748892a08afe2c8e458dce70ae` |
| Family label | `Mirai` |
| File name | `5aa0cd0fb49efc5368952f1449686a63f61f33748892a08afe2c8e458dce70ae.elf` |
| File type | `elf` |
| First seen | `2026-09-06 21:08:46` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `914d3d8c1833038d4752ff5ff01939f0` |
| SHA-1 | `99d9055405b27f20277ed3810062054b7737d88b` |
| SHA-256 | `5aa0cd0fb49efc5368952f1449686a63f61f33748892a08afe2c8e458dce70ae` |
| SHA3-384 | `eb7cfc5197ef6a23f880a6418ca56090a8d8828a1964cce9019e2dc62e29952fda8f8e323ef9eb9bc30be8d397ca30e8` |
| TLSH | `T123B32B40FD548767C3C227FAF78E439D3B356B6857DB33116A346EB42B85B982E29120` |
| TELFHASH | `t11d21448262fe8a282bf30938ec7c03b01591261322857f70bf1ec5c40437006b965e8f` |
| SSDEEP | `3072:jWT/ykVEhYlkVdEfclo346N2gaFNYLcvAIutpLYJOYV0mIerJnTuXm6ciQH3MhEZ:N6wqHtHu0mIWIm6ciQH36E5r6A` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_5aa0cd0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5aa0cd0fb49efc5368952f1449686a63f61f33748892a08afe2c8e458dce70ae"
    family = "Mirai"
    file_name = "5aa0cd0fb49efc5368952f1449686a63f61f33748892a08afe2c8e458dce70ae.elf"
    file_type = "elf"
    first_seen = "2026-09-06 21:08:46"
  condition:
    hash.sha256(0, filesize) == "5aa0cd0fb49efc5368952f1449686a63f61f33748892a08afe2c8e458dce70ae"
}
```

### Sample 63: `9831a1b023f28b6c`

| Field | Value |
|---|---|
| SHA-256 | `9831a1b023f28b6cfd4c7c83099270aa48e43bf7bd8842e8858993abce86dc24` |
| Family label | `CoinMiner` |
| File name | `9831a1b023f28b6cfd4c7c83099270aa48e43bf7bd8842e8858993abce86dc24.exe` |
| File type | `exe` |
| First seen | `2026-09-06 21:03:19` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7148799ea07b90d6e2a187d3f1bc0538` |
| SHA-1 | `382969cbcbdf57754c256daf99acdcfa676d7280` |
| SHA-256 | `9831a1b023f28b6cfd4c7c83099270aa48e43bf7bd8842e8858993abce86dc24` |
| SHA3-384 | `4683ed54bccbf32c62620588802a37a872ebed6aae4a22c54fd35b4eb89dccc3faf891873745c6ed19d420cb9cff26a2` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T1E73633C57ECEA478C417C3B85653607E726DBB818934BDA336C9BE008D67D19687B388` |
| SSDEEP | `98304:1H0YLgGVOWd85SyjBLtCcPp8xe1NbmdFHxxJPqOe6Q41gZ99iexTx:1Hd0GIBFjBpHp8gGF9PW6QggZHt` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_063_9831a1b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9831a1b023f28b6cfd4c7c83099270aa48e43bf7bd8842e8858993abce86dc24"
    family = "CoinMiner"
    file_name = "9831a1b023f28b6cfd4c7c83099270aa48e43bf7bd8842e8858993abce86dc24.exe"
    file_type = "exe"
    first_seen = "2026-09-06 21:03:19"
  condition:
    hash.sha256(0, filesize) == "9831a1b023f28b6cfd4c7c83099270aa48e43bf7bd8842e8858993abce86dc24"
}
```

### Sample 64: `194f9a024339c321`

| Field | Value |
|---|---|
| SHA-256 | `194f9a024339c321343fe1f96d91335308b7fe4f41bb3bd875cdfc3e8fc149ff` |
| Family label | `Mirai` |
| File name | `194f9a024339c321343fe1f96d91335308b7fe4f41bb3bd875cdfc3e8fc149ff.elf` |
| File type | `elf` |
| First seen | `2026-09-06 20:58:21` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `227610692ac10207de5963b17c9bbf3b` |
| SHA-1 | `4b0e17ad2b2d234610790d9aa2c38d0dee82dbb4` |
| SHA-256 | `194f9a024339c321343fe1f96d91335308b7fe4f41bb3bd875cdfc3e8fc149ff` |
| SHA3-384 | `c1e5b67aff607203b2a84ab64f092ed8dfd897b96c1950673d2f6c6ead49e5fbff9f7f62983343f5a587625288864240` |
| TLSH | `T1E0C31B40FD548767C3D227B6F78E439D3B365A64A7DB331169247EB42F81B982E39220` |
| TELFHASH | `t11d21448262fe8a282bf30938ec7c03b01591261322857f70bf1ec5c40437006b965e8f` |
| SSDEEP | `3072:BGTfykVEhYlknuxEVc14z4+h2gVAN4L8cKz1wnwE+dRVL6Ndm/rOn+vEmZ9TQ3dN:W+WbhbdXL6dmKVmZ9TQ3dxj5B6A` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_194f9a02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "194f9a024339c321343fe1f96d91335308b7fe4f41bb3bd875cdfc3e8fc149ff"
    family = "Mirai"
    file_name = "194f9a024339c321343fe1f96d91335308b7fe4f41bb3bd875cdfc3e8fc149ff.elf"
    file_type = "elf"
    first_seen = "2026-09-06 20:58:21"
  condition:
    hash.sha256(0, filesize) == "194f9a024339c321343fe1f96d91335308b7fe4f41bb3bd875cdfc3e8fc149ff"
}
```

### Sample 65: `e8bdbd96cb33b0e9`

| Field | Value |
|---|---|
| SHA-256 | `e8bdbd96cb33b0e92cd7bae8f64e6599627dc3df656fc0a31435cd2bc06bd9a4` |
| Family label | `unknown` |
| File name | `0d736040f6fcab61ef390639d0f9deb1270c8b3492dd7abd9cdc8ec43a100364.zip` |
| File type | `zip` |
| First seen | `2026-09-06 20:09:22` |
| Reporter | `rifteyy` |
| Tags | `ultravnc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0017fdb8b5d6e5ef908cad3412eef910` |
| SHA-1 | `a2bcb0e1d872dd0f4db64c02133d00f7ae2680ce` |
| SHA-256 | `e8bdbd96cb33b0e92cd7bae8f64e6599627dc3df656fc0a31435cd2bc06bd9a4` |
| SHA3-384 | `bf116d1b342b48a51240cad2501f24ed3ad80020e59c4cc919dd7d254380f679d1e72832f607c2f369c34fb635fc0fff` |
| TLSH | `T12244232435D8B730E838995FDF541C3DEF64492B9748FAC7644828BB125B751838B8AF` |
| SSDEEP | `6144:GiN6DXyBxVhxC9QuqV42xUlihOm9Qf9o+skjOa:GiN6DCLVhxCeG2xUlicmGf6+H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_e8bdbd96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8bdbd96cb33b0e92cd7bae8f64e6599627dc3df656fc0a31435cd2bc06bd9a4"
    family = "unknown"
    file_name = "0d736040f6fcab61ef390639d0f9deb1270c8b3492dd7abd9cdc8ec43a100364.zip"
    file_type = "zip"
    first_seen = "2026-09-06 20:09:22"
  condition:
    hash.sha256(0, filesize) == "e8bdbd96cb33b0e92cd7bae8f64e6599627dc3df656fc0a31435cd2bc06bd9a4"
}
```

### Sample 66: `c6a2648e2fb73c59`

| Field | Value |
|---|---|
| SHA-256 | `c6a2648e2fb73c593025ad77df99644d0404997bf01d65466f6b2e38411ebf1e` |
| Family label | `SilentNet` |
| File name | `index_all_french_db.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:09:14` |
| Reporter | `rifteyy` |
| Tags | `exe, loader, silentnet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0ea64b46e5d2a3e10893116b6d20e0a` |
| SHA-1 | `f8aa772130e1bdad51e3fd52c4f776c46ce36784` |
| SHA-256 | `c6a2648e2fb73c593025ad77df99644d0404997bf01d65466f6b2e38411ebf1e` |
| SHA3-384 | `c91f30e08eee2f8b484a5df2e6416d5202b1cccbb0fa668034c7ec0546915adc9e987a1ae39454b05a9dea3e90d19e30` |
| IMPHASH | `73f461c771aef77ec43d53a0c54f0c8d` |
| TLSH | `T1BC357C83E7A385D8C116C9B5534BF137F9627C8E4B157197ABC41E633A67BA4E22CB00` |
| SSDEEP | `12288:Dbs/m0E54jwaFXGc8lEBBBHGBKq2IZwDlCvfqItNqdg:DbOVE5ifGPRZwhCvf3fd` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_066_c6a2648e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6a2648e2fb73c593025ad77df99644d0404997bf01d65466f6b2e38411ebf1e"
    family = "SilentNet"
    file_name = "index_all_french_db.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:09:14"
  condition:
    hash.sha256(0, filesize) == "c6a2648e2fb73c593025ad77df99644d0404997bf01d65466f6b2e38411ebf1e"
}
```

### Sample 67: `9536bb0a76bf37fd`

| Field | Value |
|---|---|
| SHA-256 | `9536bb0a76bf37fdc27861c3f6948a10f5a2c9a7ff1d26c3eb51b5770045d670` |
| Family label | `unknown` |
| File name | `WinSystemHost.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:08:53` |
| Reporter | `rifteyy` |
| Tags | `DonutLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `447313e14f08e285c0f3e407b62a4972` |
| SHA-1 | `45b2a56b1fccde7c5c7e3e5314decf3bb8c9b640` |
| SHA-256 | `9536bb0a76bf37fdc27861c3f6948a10f5a2c9a7ff1d26c3eb51b5770045d670` |
| SHA3-384 | `6ff2244e39cf8e50f48e1bad14b009346b2c977c44f026d1613b9ce779b9bf718bdcf19500079c87f58004d3752648a3` |
| IMPHASH | `06ac4d4c38fdb478d2cae1f0eea00634` |
| TLSH | `T16BB58E1BB7A900ECD0A7C179CE064617E7B174091370AAEF16D08AA61F27FE15E7E712` |
| SSDEEP | `49152:PHsa8sSkULl/VZveXzuq/VbN5A6K3fALG4qC3:PgcGAb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_9536bb0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9536bb0a76bf37fdc27861c3f6948a10f5a2c9a7ff1d26c3eb51b5770045d670"
    family = "unknown"
    file_name = "WinSystemHost.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:08:53"
  condition:
    hash.sha256(0, filesize) == "9536bb0a76bf37fdc27861c3f6948a10f5a2c9a7ff1d26c3eb51b5770045d670"
}
```

### Sample 68: `9c8969b2fc30c395`

| Field | Value |
|---|---|
| SHA-256 | `9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456` |
| Family label | `VenomRAT` |
| File name | `privateemu.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:08:45` |
| Reporter | `rifteyy` |
| Tags | `AsyncRAT, exe, rat, VenomRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75f0d7ca7e0a6348202bf6533ea26f53` |
| SHA-1 | `230ca7bbf9859c65cd1d0112f7091fce4bf46bcf` |
| SHA-256 | `9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456` |
| SHA3-384 | `7ea47b207f6c354f990d997ce79598c0991224131ccb5eeaf552b3ab0e5eb568a050f8e38d97d222a5d49f0185ccba53` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T100735B0137D88926F2AE47B9ADF251074EF8D5576112CE5E7CC800CD6AA7BC58A037EA` |
| SSDEEP | `1536:tUk0cxVGlCBiPMVIsOBe+lIRH1bW/UNpQzc7QVclN:tURcxVMWiPMVzObqH1bWcvQ+KY` |

#### Technical Assessment

- The sample is tracked as `VenomRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VenomRAT_068_9c8969b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456"
    family = "VenomRAT"
    file_name = "privateemu.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:08:45"
  condition:
    hash.sha256(0, filesize) == "9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456"
}
```

### Sample 69: `fa3523b9e59def35`

| Field | Value |
|---|---|
| SHA-256 | `fa3523b9e59def3558f6e9e97563dfd1e511391c290bc642a05962aeccef4afe` |
| Family label | `BlankGrabber` |
| File name | `Delta_cracked.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:08:44` |
| Reporter | `rifteyy` |
| Tags | `BlankGrabber, exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b958353109ac8ecf07fccb1530e84af0` |
| SHA-1 | `410dbde6c5078fc7ea8dae0c9d3364fb1e5b2430` |
| SHA-256 | `fa3523b9e59def3558f6e9e97563dfd1e511391c290bc642a05962aeccef4afe` |
| SHA3-384 | `a0d598a3e789241ce013b54f3c5a0e9b4519436b0155606d95bdc9dfd7bf11d610da8cdc9e327ffa41c360e2c2488a32` |
| IMPHASH | `ed71b47f404234b025eb1f9c0778046c` |
| TLSH | `T197A63359629508F7FBD2453DDA65C966EB71B4324B70CECF07A882201E332E1987E732` |
| SSDEEP | `196608:MqfkzmFUP7C4JG4+NVlTjat7tPGB/ihrAyCk7VPfF8bfTfQ3LZapK4Dfrtw3D:M36FU+4kjjatZ+/yNCk7VPfF8bfTvHmz` |

#### Technical Assessment

- The sample is tracked as `BlankGrabber` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BlankGrabber_069_fa3523b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa3523b9e59def3558f6e9e97563dfd1e511391c290bc642a05962aeccef4afe"
    family = "BlankGrabber"
    file_name = "Delta_cracked.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:08:44"
  condition:
    hash.sha256(0, filesize) == "fa3523b9e59def3558f6e9e97563dfd1e511391c290bc642a05962aeccef4afe"
}
```

### Sample 70: `3a297d846199ddff`

| Field | Value |
|---|---|
| SHA-256 | `3a297d846199ddff323b30eadb510daedbbd08a9e76949c06df09e1592dd0f02` |
| Family label | `unknown` |
| File name | `OpenBulletCE_1.3.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:08:31` |
| Reporter | `rifteyy` |
| Tags | `exe, Stealc, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc8ae43dccc23d134bbaac1096f0d21a` |
| SHA-1 | `642aecb0b5a7257782dac0e86a082280902add5b` |
| SHA-256 | `3a297d846199ddff323b30eadb510daedbbd08a9e76949c06df09e1592dd0f02` |
| SHA3-384 | `56a9f06148799b9117d183cc25be29685fcb9e733a2ae3c199f89392ff7751bd14ca6e7c0a293b9b2848169109205a03` |
| IMPHASH | `6b46d14e506e96f6104eaca4ffd6f8c4` |
| TLSH | `T194C633E2552232B8F5B08B3A41C3D5779B34B5A4DC283AB640C8D8A79FDA4394E1CFD5` |
| SSDEEP | `196608:CWU4iZvzOg1EOD2A/6JmpTmc/4iZvzOg1EODHA/6JmpT1JXrxwNc+Hvk3iJFcwA0:VixbEY/6JmpTmFixbEH/6JmpT1d1wNcn` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_3a297d84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a297d846199ddff323b30eadb510daedbbd08a9e76949c06df09e1592dd0f02"
    family = "unknown"
    file_name = "OpenBulletCE_1.3.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:08:31"
  condition:
    hash.sha256(0, filesize) == "3a297d846199ddff323b30eadb510daedbbd08a9e76949c06df09e1592dd0f02"
}
```

### Sample 71: `1ae6cb0cdcf57b0e`

| Field | Value |
|---|---|
| SHA-256 | `1ae6cb0cdcf57b0ea68a04c7b83892c00ed6f73594d8f0b5c5742a5fcbf9b009` |
| Family label | `unknown` |
| File name | `WinSystemHost.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:07:46` |
| Reporter | `rifteyy` |
| Tags | `DonutLoader, exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9352bb40822133d79c2622c1101b060d` |
| SHA-1 | `7fd0d983b5fdfb21592c621fb34d8fc127cac998` |
| SHA-256 | `1ae6cb0cdcf57b0ea68a04c7b83892c00ed6f73594d8f0b5c5742a5fcbf9b009` |
| SHA3-384 | `aac30956de0535768ea2f4ceffad81866c099fccd49e77303f5d2efafec6ed1344d60eb57fe7960c33c4cbb4b643bd7b` |
| IMPHASH | `77fbfc5b6c1c876f8a1eba43f6966392` |
| TLSH | `T11CB59F1BA6A900FCD0A7C179CE074A17E77174091371AAEF06D08AAA1F27BE15F7E711` |
| SSDEEP | `49152:8Ja5bpuBl6ew2T57cHQ9LYVCd0uXh9do5HipI:r8Xhw5HU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_1ae6cb0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae6cb0cdcf57b0ea68a04c7b83892c00ed6f73594d8f0b5c5742a5fcbf9b009"
    family = "unknown"
    file_name = "WinSystemHost.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:07:46"
  condition:
    hash.sha256(0, filesize) == "1ae6cb0cdcf57b0ea68a04c7b83892c00ed6f73594d8f0b5c5742a5fcbf9b009"
}
```

### Sample 72: `d38f4c8fe3deb633`

| Field | Value |
|---|---|
| SHA-256 | `d38f4c8fe3deb6338c561bebe8e7751c97e926907515128a4e579cccebee5ff5` |
| Family label | `Amadey` |
| File name | `taskmanager.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:07:24` |
| Reporter | `abuse_ch` |
| Tags | `Amadey, exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0521b02f1494d62f04e78eb4435443eb` |
| SHA-1 | `93e5f586ae99c7da4731b29f845af42294a04a87` |
| SHA-256 | `d38f4c8fe3deb6338c561bebe8e7751c97e926907515128a4e579cccebee5ff5` |
| SHA3-384 | `45a932f0afe5c4bf40e8085de47e386f7c615ebb889fc22f9e4c3f3ca90278860ef93d899cd2836c452b334887297233` |
| IMPHASH | `9de6be7a4c44b3d12f5f66ec980c3dfa` |
| TLSH | `T1AB944C213817C032D56091715E7AFFF685AD6D258B7149EBBBC40E375E202D2AA31F3A` |
| SSDEEP | `6144:RJfjr/kDxy8zp5VBzrxa9+aTgQLQjB+a7d0fmkmZKasmGWzqFE5BUgAOU/vK5S4:RJfjr/kDx3z09xiga7d97hwgh5S4` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_072_d38f4c8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d38f4c8fe3deb6338c561bebe8e7751c97e926907515128a4e579cccebee5ff5"
    family = "Amadey"
    file_name = "taskmanager.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:07:24"
  condition:
    hash.sha256(0, filesize) == "d38f4c8fe3deb6338c561bebe8e7751c97e926907515128a4e579cccebee5ff5"
}
```

### Sample 73: `7024c376d00fbb19`

| Field | Value |
|---|---|
| SHA-256 | `7024c376d00fbb19ea15f7e06d19d16de65c5b02283e072ae6c16f30dcebb3db` |
| Family label | `unknown` |
| File name | `7024c376d00fbb19ea15f7e06d19d16de65c5b02283e072ae6c16f30dcebb3db.exe` |
| File type | `unknown` |
| First seen | `2026-09-06 20:06:54` |
| Reporter | `rifteyy` |
| Tags | `rat, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23eed88647016a3e5a1a4203ce1ea038` |
| SHA-256 | `7024c376d00fbb19ea15f7e06d19d16de65c5b02283e072ae6c16f30dcebb3db` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_7024c376
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7024c376d00fbb19ea15f7e06d19d16de65c5b02283e072ae6c16f30dcebb3db"
    family = "unknown"
    file_name = "7024c376d00fbb19ea15f7e06d19d16de65c5b02283e072ae6c16f30dcebb3db.exe"
    file_type = "unknown"
    first_seen = "2026-09-06 20:06:54"
  condition:
    hash.sha256(0, filesize) == "7024c376d00fbb19ea15f7e06d19d16de65c5b02283e072ae6c16f30dcebb3db"
}
```

### Sample 74: `28e985edba591272`

| Field | Value |
|---|---|
| SHA-256 | `28e985edba59127261da83fe963b0a3674d9007840acd8db505fec6ac455c987` |
| Family label | `Amadey` |
| File name | `taskmanager.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:06:40` |
| Reporter | `rifteyy` |
| Tags | `amadey, exe, loader, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f05dada33b1b43b4281c2ea748b9c1ae` |
| SHA-1 | `40b4764b8c799fc0bc859fc912233e4cd10c20e6` |
| SHA-256 | `28e985edba59127261da83fe963b0a3674d9007840acd8db505fec6ac455c987` |
| SHA3-384 | `b3000632e35aae5590cf0a70db0e546b1a15c785cf2e66163f364299ee013b82fcc38724ee565a0946e1b55d9bd8040c` |
| IMPHASH | `381b40dd6bff24580b4c540462e4f76e` |
| TLSH | `T1DAF31286907D923CE17868B5A1EEDE02F974FFD0ECBD8489F196714904B96B8C6F7110` |
| SSDEEP | `3072:O+aL26Ogi52ztMX/kipPTq/jLfuDX+gUy1i4woUDQut/T0j8z4OFOtc80w5o8Y8Z:O+arOgi5Q6X/u/nfuDX+Uo4woUDQut/4` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_074_28e985ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28e985edba59127261da83fe963b0a3674d9007840acd8db505fec6ac455c987"
    family = "Amadey"
    file_name = "taskmanager.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:06:40"
  condition:
    hash.sha256(0, filesize) == "28e985edba59127261da83fe963b0a3674d9007840acd8db505fec6ac455c987"
}
```

### Sample 75: `409ccd057be80760`

| Field | Value |
|---|---|
| SHA-256 | `409ccd057be807603e155a2a8579dfd9c7b67c0984db27b5e259fe438ef3fa8c` |
| Family label | `BlankGrabber` |
| File name | `builder.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:06:33` |
| Reporter | `rifteyy` |
| Tags | `blankgrabber, exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17cc76da66e27f9a43ddbcea070918f7` |
| SHA-1 | `2b76e116e1aa0774fd0675572077541585e13318` |
| SHA-256 | `409ccd057be807603e155a2a8579dfd9c7b67c0984db27b5e259fe438ef3fa8c` |
| SHA3-384 | `6a8c0a96bd79a21acdf86ca9793f86f01ce6b70763b1bce826bed6babb8904ba3ec0e4079a7741b81b6e256696babb77` |
| IMPHASH | `1af6c885af093afc55142c2f1761dbe8` |
| TLSH | `T129763325B3F01DF2F9A7297AD882C519D6B1FC550B24CA8B435906BA0F27A604D3FF58` |
| SSDEEP | `98304:wRHDjWM8JEE1rAEamaHl3Ne4i3Tf2PkOpfW9hZMMoVmkzhxIdfXeROYKJJcGhEI6:wF0QleNTfm/pf+xk4dWROtrbWOjgdj` |

#### Technical Assessment

- The sample is tracked as `BlankGrabber` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BlankGrabber_075_409ccd05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "409ccd057be807603e155a2a8579dfd9c7b67c0984db27b5e259fe438ef3fa8c"
    family = "BlankGrabber"
    file_name = "builder.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:06:33"
  condition:
    hash.sha256(0, filesize) == "409ccd057be807603e155a2a8579dfd9c7b67c0984db27b5e259fe438ef3fa8c"
}
```

### Sample 76: `8211468fff3cd6cf`

| Field | Value |
|---|---|
| SHA-256 | `8211468fff3cd6cf858f652b53db995782d573a092d00dac648b863d1b237efd` |
| Family label | `RedLineStealer` |
| File name | `8211468fff3cd6cf858f652b53db995782d573a092d00dac648b863d1b237efd` |
| File type | `exe` |
| First seen | `2026-09-06 20:06:08` |
| Reporter | `rifteyy` |
| Tags | `amadey, exe, lumma, RedLineStealer, stealc, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1130fe776458c3e4f3779a8f037eaa0b` |
| SHA-1 | `ff8b0cc9c8554eec5e5c65cc1990418ec812b8f2` |
| SHA-256 | `8211468fff3cd6cf858f652b53db995782d573a092d00dac648b863d1b237efd` |
| SHA3-384 | `b79e94a06943ece638fc2e016c696ddd4bba4a907c944d2afd3989cbb03ea3831b73f6e89beb2a08eb338240de9b2b16` |
| IMPHASH | `646167cce332c1c252cdcb1839e0cf48` |
| TLSH | `T11176335BF2C6206FFCF9473309F961930725EE710F24959F9A40ACAC29706266EB5372` |
| SSDEEP | `196608:TuKsZTLojKaHaPSN1I0F0ekhDd7phctNO/Ecudbv:eBa6KjICLkhDdfIAEcuZ` |
| ICON-DHASH | `f8f0f4c8c8c8d8f0` |

#### Technical Assessment

- The sample is tracked as `RedLineStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RedLineStealer_076_8211468f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8211468fff3cd6cf858f652b53db995782d573a092d00dac648b863d1b237efd"
    family = "RedLineStealer"
    file_name = "8211468fff3cd6cf858f652b53db995782d573a092d00dac648b863d1b237efd"
    file_type = "exe"
    first_seen = "2026-09-06 20:06:08"
  condition:
    hash.sha256(0, filesize) == "8211468fff3cd6cf858f652b53db995782d573a092d00dac648b863d1b237efd"
}
```

### Sample 77: `4ae3908e2daf0d4d`

| Field | Value |
|---|---|
| SHA-256 | `4ae3908e2daf0d4ddf63935ef64b29d1707d217354168bad94bbdfec85e045f5` |
| Family label | `unknown` |
| File name | `client.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:04:39` |
| Reporter | `rifteyy` |
| Tags | `DonutLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b59b6b5a88cdd64ebaf37c743ea965f8` |
| SHA-1 | `8e4ca7ec59983d1d26c554a832b89a9ef3358a04` |
| SHA-256 | `4ae3908e2daf0d4ddf63935ef64b29d1707d217354168bad94bbdfec85e045f5` |
| SHA3-384 | `5e1eb363b2d71190372f03525ebe043ce6d624b853af762b01007a4c1bb8b4479735bed00f658007c572a60fbbd91e40` |
| IMPHASH | `77fbfc5b6c1c876f8a1eba43f6966392` |
| TLSH | `T14BB59F1BA7A900ECD0A7C179CE074A17E77174091371AADF16E08AAA1F27BE14F7E711` |
| SSDEEP | `49152:LU6jcBrnlbM6PmqZI5qoBVdD/SVhBFzcYPHO:nCnvcMO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_4ae3908e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ae3908e2daf0d4ddf63935ef64b29d1707d217354168bad94bbdfec85e045f5"
    family = "unknown"
    file_name = "client.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:04:39"
  condition:
    hash.sha256(0, filesize) == "4ae3908e2daf0d4ddf63935ef64b29d1707d217354168bad94bbdfec85e045f5"
}
```

### Sample 78: `83a3a48e8998fe74`

| Field | Value |
|---|---|
| SHA-256 | `83a3a48e8998fe74853161d31476c613d6eaf05f618446dd9d9b1016ada44822` |
| Family label | `unknown` |
| File name | `client.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:04:28` |
| Reporter | `rifteyy` |
| Tags | `DonutLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1a1fc9d59c0a43b55732cc1b07c2bf9` |
| SHA-1 | `6f86ecc5cb4008d7276d3cf69004a90caa4f7417` |
| SHA-256 | `83a3a48e8998fe74853161d31476c613d6eaf05f618446dd9d9b1016ada44822` |
| SHA3-384 | `f6ecc07e834db4cf8a2948b412c424844931c8874182fa652639ff27f9a6ca7a46c562b7b8ccb7ead267ced13103eec1` |
| IMPHASH | `77fbfc5b6c1c876f8a1eba43f6966392` |
| TLSH | `T195B59E1BA7A900ECD0A7C179CE474A17E7B174091370AAEF06D08A9A1F27BE15F7E711` |
| SSDEEP | `49152:GS9n8GzolfC6unBixZyt8lv6O+FI5VE/h3QMN:VE5VW3/N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_83a3a48e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83a3a48e8998fe74853161d31476c613d6eaf05f618446dd9d9b1016ada44822"
    family = "unknown"
    file_name = "client.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:04:28"
  condition:
    hash.sha256(0, filesize) == "83a3a48e8998fe74853161d31476c613d6eaf05f618446dd9d9b1016ada44822"
}
```

### Sample 79: `da074ef5707b4d68`

| Field | Value |
|---|---|
| SHA-256 | `da074ef5707b4d685734dea298bf5ced3bcc0dbf38f7242f7e50ab4585b61d55` |
| Family label | `unknown` |
| File name | `656b90c4553ec077f0ff60bf35edee765dffa4d63d4e2148221f9ef1171bb437.zip` |
| File type | `zip` |
| First seen | `2026-09-06 20:04:23` |
| Reporter | `rifteyy` |
| Tags | `uacbypass, vulnerable-driver, XMRig, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15e582e08ab23708f6bd790335ef050f` |
| SHA-1 | `886a790c5845f349e719fa1ac7b38d5be7dc1a76` |
| SHA-256 | `da074ef5707b4d685734dea298bf5ced3bcc0dbf38f7242f7e50ab4585b61d55` |
| SHA3-384 | `6540f52473279c70a9f3402b85e64e48f9f92217d5b5104ceb4f916b4201259e18de800a4f8727c475961bf3aac3cf0d` |
| TLSH | `T18C36338BF14F25AB0F8F4D412994899728B1626DF396F8AFB6C00F874B54D19342B4F6` |
| SSDEEP | `98304:JZIC3yxsnjMyxQLyP/oWEX9QtyEZQl271ysdl1Z6boYghC1ZdFj2:JZZixQjMyeyP/ZA9QLZQk7pdmoZhC1o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_da074ef5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da074ef5707b4d685734dea298bf5ced3bcc0dbf38f7242f7e50ab4585b61d55"
    family = "unknown"
    file_name = "656b90c4553ec077f0ff60bf35edee765dffa4d63d4e2148221f9ef1171bb437.zip"
    file_type = "zip"
    first_seen = "2026-09-06 20:04:23"
  condition:
    hash.sha256(0, filesize) == "da074ef5707b4d685734dea298bf5ced3bcc0dbf38f7242f7e50ab4585b61d55"
}
```

### Sample 80: `eb0e2b6424e5ec1e`

| Field | Value |
|---|---|
| SHA-256 | `eb0e2b6424e5ec1eb95d183a0f7022ab8044bf610972105289b8113ece084826` |
| Family label | `unknown` |
| File name | `test.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:03:23` |
| Reporter | `rifteyy` |
| Tags | `exe, exploit, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f336178aad13fded5af40cc3bb5da30` |
| SHA-1 | `b99f3b8aaf00ce8e1e971336cec9313d835bc33b` |
| SHA-256 | `eb0e2b6424e5ec1eb95d183a0f7022ab8044bf610972105289b8113ece084826` |
| SHA3-384 | `9c192548c0ac03cd5d7efd821594b3cae240b7c186c4bf8ff6be3fedb390bc7452942f5eee275f7e109480ca0ee83f6b` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T161763907ECA554E9C0AEC13189639562BF717C485B3123D32B50F6386F76BE0AEBA750` |
| SSDEEP | `98304:zktiYkwt4pdBWYfr3CeaFOumvBh8huTAE:zbdwt4pjnD3CFE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_eb0e2b64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb0e2b6424e5ec1eb95d183a0f7022ab8044bf610972105289b8113ece084826"
    family = "unknown"
    file_name = "test.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:03:23"
  condition:
    hash.sha256(0, filesize) == "eb0e2b6424e5ec1eb95d183a0f7022ab8044bf610972105289b8113ece084826"
}
```

### Sample 81: `15dc0305186d2c1f`

| Field | Value |
|---|---|
| SHA-256 | `15dc0305186d2c1f9f63a147d7a462faaf090878b7b719fb612f6a99ceccf6dd` |
| Family label | `unknown` |
| File name | `qt_test_s8yhb.exe.upload.zip` |
| File type | `zip` |
| First seen | `2026-09-06 20:03:04` |
| Reporter | `skocherhan` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0fd6da8fff9769e0e8157e9c786e6f7` |
| SHA-1 | `4c13c69e9ed38cbf7eb3a09efa96af2e861964b8` |
| SHA-256 | `15dc0305186d2c1f9f63a147d7a462faaf090878b7b719fb612f6a99ceccf6dd` |
| SHA3-384 | `0830645e821b3da33178b6588ab034e42b91eac1a786b814170cd1ead2018c8c802822c52541a60e967578553a27ca80` |
| TLSH | `T1E1E6331753D873AB640F63AAA47BB744516FC643CAC30699B9E3A3172D1EF049F38618` |
| SSDEEP | `393216:rw3fCijcZ7AZ72249UP9JFb1znyYFDvyb3fIIhRB:rw3fCijcSZnP9j1jyAKfIIh7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_15dc0305
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15dc0305186d2c1f9f63a147d7a462faaf090878b7b719fb612f6a99ceccf6dd"
    family = "unknown"
    file_name = "qt_test_s8yhb.exe.upload.zip"
    file_type = "zip"
    first_seen = "2026-09-06 20:03:04"
  condition:
    hash.sha256(0, filesize) == "15dc0305186d2c1f9f63a147d7a462faaf090878b7b719fb612f6a99ceccf6dd"
}
```

### Sample 82: `5e84fd9106777b85`

| Field | Value |
|---|---|
| SHA-256 | `5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761` |
| Family label | `AsyncRAT` |
| File name | `Beta-Cheat_protected.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:02:02` |
| Reporter | `rifteyy` |
| Tags | `AsyncRAT, exe, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36aa1dc60ecca0a2dfb562e0feda2080` |
| SHA-1 | `f2e3bbb09dc3b30aa39af0794cd5fec2a2d052e8` |
| SHA-256 | `5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761` |
| SHA3-384 | `41c84a3a79b471d3932f1360c1b00f5bf3747234900225e6d77d7a703045f3fad49b8db74719af49a4511aa5f0823b49` |
| IMPHASH | `4328f7206db519cd4e82283211d98e83` |
| TLSH | `T15806232F6D423C3AE77595BF0410B1CDA8686D1187E9B2123A2FFB2CDD3CE57A906941` |
| SSDEEP | `49152:ezrqO7iP7RKy5h3lEKqd7n5D5dapQ2wMENKZhkqrweA0QvQcAtjySLveE9:4Wh3lEH951gCKZhfrwP/vYtjtrf9` |
| ICON-DHASH | `f0cca6aaaaa6ccf0` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_082_5e84fd91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761"
    family = "AsyncRAT"
    file_name = "Beta-Cheat_protected.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:02:02"
  condition:
    hash.sha256(0, filesize) == "5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761"
}
```

### Sample 83: `0862cc6ab1a0bd82`

| Field | Value |
|---|---|
| SHA-256 | `0862cc6ab1a0bd821b1b00fda8002d56d91f2979613505a88e142133240f8d27` |
| Family label | `AsyncRAT` |
| File name | `SteelSeries.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:01:43` |
| Reporter | `rifteyy` |
| Tags | `AsyncRat, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81e3fdbe1f9a1a72a5cda8223cee03ce` |
| SHA-1 | `ba6fd61f8796fcaa8df95dcb0e6ecef144ca3ff1` |
| SHA-256 | `0862cc6ab1a0bd821b1b00fda8002d56d91f2979613505a88e142133240f8d27` |
| SHA3-384 | `19ed5247ac8f18306e6d86e19f70991a79a2b428c8147ca2b4436a12c5a11c542bd30179af2c22ae793cb4f9edea57b0` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T112232C003BE9822BF2BE5B789CF251458676F1A33603D64D1CC451DB5623FC69A42AFE` |
| SSDEEP | `768:mu/dRTUo0HQbWUnmjSmo2qMmdSPvYiPIMzjbigX3cbSNA6H6qx6JuGBDZyx:mu/dRTUPE2idygrM3bFXsuNA6H6d9dyx` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_083_0862cc6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0862cc6ab1a0bd821b1b00fda8002d56d91f2979613505a88e142133240f8d27"
    family = "AsyncRAT"
    file_name = "SteelSeries.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:01:43"
  condition:
    hash.sha256(0, filesize) == "0862cc6ab1a0bd821b1b00fda8002d56d91f2979613505a88e142133240f8d27"
}
```

### Sample 84: `4d10c9b2408ba1f4`

| Field | Value |
|---|---|
| SHA-256 | `4d10c9b2408ba1f4cd2d3a776808a35528164e2963f497c4c06725ac840ea611` |
| Family label | `Amadey` |
| File name | `1l74V2.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:01:35` |
| Reporter | `rifteyy` |
| Tags | `Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `045a3a09458a21a8b3b2d3011d1e02d4` |
| SHA-1 | `00642e3d2a067cd64089279e8a4e7db9dcd9f8b6` |
| SHA-256 | `4d10c9b2408ba1f4cd2d3a776808a35528164e2963f497c4c06725ac840ea611` |
| SHA3-384 | `1db0f1ef2ff7ef51d05485cb94a0c83c94164703eaf3603ab26347d4adcac42605a18a797e764b79cc5ba2826ae246ac` |
| IMPHASH | `2eabe9054cad5152567f0699947a2c5b` |
| TLSH | `T19A8533575B9335DBD63A1536E7452AC82B74331B301E35FBBE08A82A91C337DCE284A5` |
| SSDEEP | `24576:LfuAgZXWbHZptuQiY0ZjPz/WdYAN1HXLv66J+KdHCf6ILND/KGgJ1sfp1e2hiyM:LfuVXiu00Pz9AHD66JnIL9KyM` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_084_4d10c9b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d10c9b2408ba1f4cd2d3a776808a35528164e2963f497c4c06725ac840ea611"
    family = "Amadey"
    file_name = "1l74V2.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:01:35"
  condition:
    hash.sha256(0, filesize) == "4d10c9b2408ba1f4cd2d3a776808a35528164e2963f497c4c06725ac840ea611"
}
```

### Sample 85: `e17581ec73d1c5a0`

| Field | Value |
|---|---|
| SHA-256 | `e17581ec73d1c5a0d2849b6ba44dc59117f41b0d490860bfbe556271635775d2` |
| Family label | `AsyncRAT` |
| File name | `GoogleInstaller.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:00:35` |
| Reporter | `rifteyy` |
| Tags | `AsyncRat, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `118becc8a86008e134a5dacfa038768d` |
| SHA-1 | `fa4be7026002c36bc71c9b8e1fffa83dc5437180` |
| SHA-256 | `e17581ec73d1c5a0d2849b6ba44dc59117f41b0d490860bfbe556271635775d2` |
| SHA3-384 | `d603a287792f0e765975636d0a696ef999527a814a2ccb5ba81dababd58b99af212cd4e3859411061ea85caa28627395` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14A232A003BE9C22BF2BE4FB8ACF26145467AF6736603D54E1CC451961613FC69A42AFD` |
| SSDEEP | `768:JuFfATEszatAWUqJaYmmo2q95+UOfSScWTzjbngXCiHDkxr9F4t4HPXaGcDZif+:JuFfATEd62K+llHT3bgXrgxZFmwXKdim` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_085_e17581ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e17581ec73d1c5a0d2849b6ba44dc59117f41b0d490860bfbe556271635775d2"
    family = "AsyncRAT"
    file_name = "GoogleInstaller.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:00:35"
  condition:
    hash.sha256(0, filesize) == "e17581ec73d1c5a0d2849b6ba44dc59117f41b0d490860bfbe556271635775d2"
}
```

### Sample 86: `6f201afc797370ac`

| Field | Value |
|---|---|
| SHA-256 | `6f201afc797370ac6e33fafec41a794a2eb44c1bfd7d9079e3633ebe7bbb41e1` |
| Family label | `njrat` |
| File name | `hostr.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:00:30` |
| Reporter | `rifteyy` |
| Tags | `backdoor, exe, NjRat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a559b6d223c79f3736dc52794636cfd` |
| SHA-1 | `5c4676b37fcd49990d21960a2df57af72ceef29a` |
| SHA-256 | `6f201afc797370ac6e33fafec41a794a2eb44c1bfd7d9079e3633ebe7bbb41e1` |
| SHA3-384 | `752856d3804b15f1ad18cdc35baeb6b7bd3f648506da607387c150119773272368d49163b3c09d8fd2111cf01952e8ba` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T154B32C4F2BDD901ECDE0B374E68EA7C9009199D596F118826BEF0078019F36BE778D96` |
| SSDEEP | `1536:aDYEasJqkUssXOcfaAJzYU4r/1CbSYlIePDVFkhgIJZH:aasJjUfFOderYRH` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_086_6f201afc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f201afc797370ac6e33fafec41a794a2eb44c1bfd7d9079e3633ebe7bbb41e1"
    family = "njrat"
    file_name = "hostr.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:00:30"
  condition:
    hash.sha256(0, filesize) == "6f201afc797370ac6e33fafec41a794a2eb44c1bfd7d9079e3633ebe7bbb41e1"
}
```

### Sample 87: `cdb73efc68080265`

| Field | Value |
|---|---|
| SHA-256 | `cdb73efc6808026585e0268ee4396c6ffc1d4d0288abff967c23c94057fc2ab0` |
| Family label | `AsyncRAT` |
| File name | `ChromeSetup.exe` |
| File type | `exe` |
| First seen | `2026-09-06 20:00:08` |
| Reporter | `rifteyy` |
| Tags | `AsyncRat, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac45ee03c99ed2769e9aa75c2bf95a18` |
| SHA-1 | `ec66c3675d27dba0324d7b6f4ad1499059f0c593` |
| SHA-256 | `cdb73efc6808026585e0268ee4396c6ffc1d4d0288abff967c23c94057fc2ab0` |
| SHA3-384 | `e584e744e361f84db84a86fbcfe6eedf27c13ab5d29cf14bf2ae2d26ee0d199ddac0bcde40135432e19d2e4e06b44a7a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T10C231A003BE9822BF2BE4FB89DF26145867AF5636603D64E1CC441D71613FC69642AFE` |
| SSDEEP | `768:/u63N5T7w8vSWUkDuzmo2qQ9Aq7rhFysWvzjbFgXCiWh04+w5zOMdcDZLz+:/u63N5T7Pg2tA2tFy3v3bCXrG+w9OdLC` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_087_cdb73efc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdb73efc6808026585e0268ee4396c6ffc1d4d0288abff967c23c94057fc2ab0"
    family = "AsyncRAT"
    file_name = "ChromeSetup.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:00:08"
  condition:
    hash.sha256(0, filesize) == "cdb73efc6808026585e0268ee4396c6ffc1d4d0288abff967c23c94057fc2ab0"
}
```

### Sample 88: `9ba76ceb13a62e63`

| Field | Value |
|---|---|
| SHA-256 | `9ba76ceb13a62e632b94324fc772d7921c461c6fd5e70844aadca97dcc15cb7a` |
| Family label | `AsyncRAT` |
| File name | `AU88APP.exe` |
| File type | `exe` |
| First seen | `2026-09-06 19:59:28` |
| Reporter | `rifteyy` |
| Tags | `asyncrat, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdbde70e7dd779cebec7d5afb272da96` |
| SHA-1 | `3b930db64e5478fa38d42d5c20e9efa75dbe7489` |
| SHA-256 | `9ba76ceb13a62e632b94324fc772d7921c461c6fd5e70844aadca97dcc15cb7a` |
| SHA3-384 | `a3889c383eaa11faff83f4d82f3657fd773bcbf4adda8528721ea7a64f5dabce497fe9f0cbad85552e3c10184f10a3de` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T196C24D0873E8C572D1FE06BA883385009775D95B9913D76A6FC890AE2E237CD8A14FE4` |
| SSDEEP | `384:zQpwoOiZTWqSOsVa/KFHbx0yH9qbuUscCbQxnCJfJBndnjJeKWjT+:zQpVg1VDHV0wIb1BBiBnPWjT+` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_088_9ba76ceb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ba76ceb13a62e632b94324fc772d7921c461c6fd5e70844aadca97dcc15cb7a"
    family = "AsyncRAT"
    file_name = "AU88APP.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:59:28"
  condition:
    hash.sha256(0, filesize) == "9ba76ceb13a62e632b94324fc772d7921c461c6fd5e70844aadca97dcc15cb7a"
}
```

### Sample 89: `43316503acbbc524`

| Field | Value |
|---|---|
| SHA-256 | `43316503acbbc5245e96113bd6df3403d770467910feb7d91622c62ae6f02317` |
| Family label | `AsyncRAT` |
| File name | `from_okvip_with_love.exe` |
| File type | `exe` |
| First seen | `2026-09-06 19:59:26` |
| Reporter | `rifteyy` |
| Tags | `asyncrat, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50798da6b70328ed81624d7a9a4dd1db` |
| SHA-1 | `a7d6b8bb5025a77eead516c9f9c8667a4b147e05` |
| SHA-256 | `43316503acbbc5245e96113bd6df3403d770467910feb7d91622c62ae6f02317` |
| SHA3-384 | `e20d34f7b848f5dd6d22e9e130801abc0ea0f33b5781ac4f72e6a92c342b3c8386b0c1691e23e93e6227b418f1cfceb9` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CA938D007BD8852AF5BEDB38A8B3534507B4AD572802DA9D0DD435AF0A737C49D463BE` |
| SSDEEP | `1536:vfxBqtmkAaLF2clJVG/NEbxsJf4HbTfr+8x3wDu3Y6Uk9jg+rr6GbOsKpeQiQKWs:v3q4s6NEbx2f4ADud7r6GiX8QiQ/1S` |
| ICON-DHASH | `e09a676060678ee0` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_089_43316503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43316503acbbc5245e96113bd6df3403d770467910feb7d91622c62ae6f02317"
    family = "AsyncRAT"
    file_name = "from_okvip_with_love.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:59:26"
  condition:
    hash.sha256(0, filesize) == "43316503acbbc5245e96113bd6df3403d770467910feb7d91622c62ae6f02317"
}
```

### Sample 90: `b6f9fc16a92bb2e4`

| Field | Value |
|---|---|
| SHA-256 | `b6f9fc16a92bb2e422f20db1a4c32018e070a20d50adde6742cd066b0c9aa870` |
| Family label | `AsyncRAT` |
| File name | `from_kiwi_okvip_with_love.exe` |
| File type | `exe` |
| First seen | `2026-09-06 19:59:09` |
| Reporter | `rifteyy` |
| Tags | `asyncrat, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57566bc0003ee4be731e2d585755a489` |
| SHA-1 | `8547fb670fb27b98b25a20e8a4c2ae5bae563bd2` |
| SHA-256 | `b6f9fc16a92bb2e422f20db1a4c32018e070a20d50adde6742cd066b0c9aa870` |
| SHA3-384 | `b9568b679a05521dba0ade73f436aef4f7bea15a4b86da99c02c0ed2d65239f30f36c2f714a78fb0de6cb06bfb56035b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C4937D007BD88529F6BEDB38A8B2434507B5BD576802DA9D0DD439AF0A737C099067FE` |
| SSDEEP | `1536:uffVRqlAkAqN4z/klApuDv1EbDsB+r4qthvddR8V3wDu3Y6Uk9jg+rr6GbOsKpeN:uXjqW89NDNEbDW+UqtpnPDud7r6GiX8N` |
| ICON-DHASH | `e09a676060678ee0` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_090_b6f9fc16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6f9fc16a92bb2e422f20db1a4c32018e070a20d50adde6742cd066b0c9aa870"
    family = "AsyncRAT"
    file_name = "from_kiwi_okvip_with_love.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:59:09"
  condition:
    hash.sha256(0, filesize) == "b6f9fc16a92bb2e422f20db1a4c32018e070a20d50adde6742cd066b0c9aa870"
}
```

### Sample 91: `cccce5d5491d76a7`

| Field | Value |
|---|---|
| SHA-256 | `cccce5d5491d76a7aef09599c91b10bd109c03b307095be10ed85a95ce54ad8e` |
| Family label | `AsyncRAT` |
| File name | `from_kiwi_okvip_with_love_hehe.exe` |
| File type | `exe` |
| First seen | `2026-09-06 19:59:00` |
| Reporter | `rifteyy` |
| Tags | `AsyncRat, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41b60b889c0a403674131e69880e8f9c` |
| SHA-1 | `c88e2b991983883e668dd8fbfb1d99d3a73d322e` |
| SHA-256 | `cccce5d5491d76a7aef09599c91b10bd109c03b307095be10ed85a95ce54ad8e` |
| SHA3-384 | `e9a9ee154dbec9f29fe1ab21a0b0b00b305c554d95ec56c0df3f0267de5ea5e2645395bb5d345a1954319b3d19d67d9e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BD937D007BD88529F6BEDB38A8B2434507B4BD572812D68D0DD439AF1A73BC099427BF` |
| SSDEEP | `1536:ef4RqLgUAGnKnIhtMhjbysJJfj2bvwb8l3wDu3Y6Uk9jg+rr6GbOsKpeQiQKW1S:ecqcgnshjby2JW6Dud7r6GiX8QiQ/1S` |
| ICON-DHASH | `e09a676060678ee0` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_091_cccce5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cccce5d5491d76a7aef09599c91b10bd109c03b307095be10ed85a95ce54ad8e"
    family = "AsyncRAT"
    file_name = "from_kiwi_okvip_with_love_hehe.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:59:00"
  condition:
    hash.sha256(0, filesize) == "cccce5d5491d76a7aef09599c91b10bd109c03b307095be10ed85a95ce54ad8e"
}
```

### Sample 92: `cdaf86deee504274`

| Field | Value |
|---|---|
| SHA-256 | `cdaf86deee5042744424ed5990b91db92e964ff3d139ec6bf4c07b42ca659952` |
| Family label | `AsyncRAT` |
| File name | `SHBETAPP.exe` |
| File type | `exe` |
| First seen | `2026-09-06 19:58:51` |
| Reporter | `rifteyy` |
| Tags | `asyncrat, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7656295a11fb1016e9eddb71cfb4f24e` |
| SHA-1 | `a2001f8ccc298375a90f468b650fd6cbd788b2cb` |
| SHA-256 | `cdaf86deee5042744424ed5990b91db92e964ff3d139ec6bf4c07b42ca659952` |
| SHA3-384 | `6542ea1f67d5420838c1c61e1a9087705ded43abcdb351bc44d9f63092697484d3f2e9f0633045d1f0f3c62f01f3a5f3` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A1C23B0833F4C571E2FD4ABA9833D6008B75E55B9913D76A6FC890AD2E2378D8A14FD4` |
| SSDEEP | `384:/N3SaTSXW9bVWw7HtZARPn9jeH9qbuUszbQxnCJfJBndnjJ2Kh/+:/N3SaT5Lt+QIb3BiBn3h/+` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_092_cdaf86de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdaf86deee5042744424ed5990b91db92e964ff3d139ec6bf4c07b42ca659952"
    family = "AsyncRAT"
    file_name = "SHBETAPP.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:58:51"
  condition:
    hash.sha256(0, filesize) == "cdaf86deee5042744424ed5990b91db92e964ff3d139ec6bf4c07b42ca659952"
}
```

### Sample 93: `2070e2483590dd3b`

| Field | Value |
|---|---|
| SHA-256 | `2070e2483590dd3b6ccbe4339d29c095edbbc4cadd6b57dac3ec006ff76c7bbc` |
| Family label | `SalatStealer` |
| File name | `RknNObhod.exe` |
| File type | `exe` |
| First seen | `2026-09-06 19:58:29` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6291601663c7a8d748b1119985dd3aa` |
| SHA-1 | `4856b8991ee233bbbb68b87d664f9d89a2a3727f` |
| SHA-256 | `2070e2483590dd3b6ccbe4339d29c095edbbc4cadd6b57dac3ec006ff76c7bbc` |
| SHA3-384 | `e26b5039ceb99df1b5b7426319a0bf66c10eaf8abfbccd76003e0f6ea0a89cc7ecac74f713648124429b0e0feb31e27e` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1B5C65C11FACB54F6F9036831416BB27F23315D048B28DB9BEB583B6BF877691186A305` |
| SSDEEP | `98304:sGsqTIVri2C3jGdD4/Lobr4i3HVd7EqO/:hTx3jUDsirTeqO/` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_093_2070e248
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2070e2483590dd3b6ccbe4339d29c095edbbc4cadd6b57dac3ec006ff76c7bbc"
    family = "SalatStealer"
    file_name = "RknNObhod.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:58:29"
  condition:
    hash.sha256(0, filesize) == "2070e2483590dd3b6ccbe4339d29c095edbbc4cadd6b57dac3ec006ff76c7bbc"
}
```

### Sample 94: `ebd9d6ef8b792ba8`

| Field | Value |
|---|---|
| SHA-256 | `ebd9d6ef8b792ba88aa5edbd9bc093ec8739729fecc8507c8d3b158c02f09024` |
| Family label | `AsyncRAT` |
| File name | `CM88APP.exe` |
| File type | `exe` |
| First seen | `2026-09-06 19:58:09` |
| Reporter | `rifteyy` |
| Tags | `asyncrat, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16a2b7f149c3196299232a6d30d414aa` |
| SHA-1 | `9ee6f8b5afcdef110f24835004979b899dee94ed` |
| SHA-256 | `ebd9d6ef8b792ba88aa5edbd9bc093ec8739729fecc8507c8d3b158c02f09024` |
| SHA3-384 | `8da8cfe0161de25e94bb65c10c799264753d149a2984a311c0b4cb5da5872dfcd3fcf90b87a0386f813b0b9874ef5584` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E5C22C0873E8C572D2FE4ABA883385009775D55B9913D76A6FC890AE2E237CD8B14FD4` |
| SSDEEP | `384:ATdv2D9YfxWceOsVa/KFHbxFH9qbuUsDbQxnCJfJBndnjJ3KxB+:edvhi1VDHVFIbdBiBnOxB+` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_094_ebd9d6ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebd9d6ef8b792ba88aa5edbd9bc093ec8739729fecc8507c8d3b158c02f09024"
    family = "AsyncRAT"
    file_name = "CM88APP.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:58:09"
  condition:
    hash.sha256(0, filesize) == "ebd9d6ef8b792ba88aa5edbd9bc093ec8739729fecc8507c8d3b158c02f09024"
}
```

### Sample 95: `579e244c821b1556`

| Field | Value |
|---|---|
| SHA-256 | `579e244c821b155684cec762f68b7ce76d806da76f5367a4798b97c9246500c7` |
| Family label | `AsyncRAT` |
| File name | `from_au88_with_love.exe` |
| File type | `exe` |
| First seen | `2026-09-06 19:58:02` |
| Reporter | `rifteyy` |
| Tags | `AsyncRat, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51e64c2ff5c48a36454b023e75ca146f` |
| SHA-1 | `350079a36c0e81911cc3cda143047b2514c27e5a` |
| SHA-256 | `579e244c821b155684cec762f68b7ce76d806da76f5367a4798b97c9246500c7` |
| SHA3-384 | `73ef3748625daecb9f0c7ba1b7d6788646823fea98dafd3841e3f1951c73045613171d97f9e5937d3a7c28cbb868d015` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1EE936D007BD88529F67E8B38A8B3438507B4AD576802DA9D0DD439AF1A737C59D063BF` |
| SSDEEP | `1536:cfQhqlSvUAth+Mqf7/SBEbxsBuMxDKwzqH853wDu3Y6Uk9jg+rr6GbOsKpeQiQKV:cEqEfxBEbxWuM4rDud7r6GiX8QiQ/1S` |
| ICON-DHASH | `e09a676060678ee0` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_095_579e244c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "579e244c821b155684cec762f68b7ce76d806da76f5367a4798b97c9246500c7"
    family = "AsyncRAT"
    file_name = "from_au88_with_love.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:58:02"
  condition:
    hash.sha256(0, filesize) == "579e244c821b155684cec762f68b7ce76d806da76f5367a4798b97c9246500c7"
}
```

### Sample 96: `0210f19ad6b72c88`

| Field | Value |
|---|---|
| SHA-256 | `0210f19ad6b72c8860d9e88b31c546a39a47939ded2bf91c65738b7ffdcf913c` |
| Family label | `SalatStealer` |
| File name | `RknNObhod.exe` |
| File type | `exe` |
| First seen | `2026-09-06 19:57:45` |
| Reporter | `Alex_sev` |
| Tags | `exe, salat, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fffc6bffec393271a37de759561ffde` |
| SHA-1 | `21aecffb290c94bcd919081bcf34b0a9b869d505` |
| SHA-256 | `0210f19ad6b72c8860d9e88b31c546a39a47939ded2bf91c65738b7ffdcf913c` |
| SHA3-384 | `fd2e75bdd5caefc5cb1644f535c5b488e18812f1376ad35b7c6f1d38722d59e46e8f66b273b51cfa89d8521c6ef8c516` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T150F53360A06B4307E7E4263657BE9675B2A937C7A0E0205E1945C3B8336B7BE13F81D7` |
| SSDEEP | `49152:sYSlpS9paP7+atEGPSIPDLCTHs4CHOwS/lJ6DxYq2t8nrmcAUe+34mP6XhJbpnKv:s7pUQeIwpC8l+Yp0rmcViX3MCAbUK9` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_096_0210f19a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0210f19ad6b72c8860d9e88b31c546a39a47939ded2bf91c65738b7ffdcf913c"
    family = "SalatStealer"
    file_name = "RknNObhod.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:57:45"
  condition:
    hash.sha256(0, filesize) == "0210f19ad6b72c8860d9e88b31c546a39a47939ded2bf91c65738b7ffdcf913c"
}
```

### Sample 97: `2fb694cdfaad46ea`

| Field | Value |
|---|---|
| SHA-256 | `2fb694cdfaad46ea8d5937291a33b33eae0083921151afb6362a252cec512837` |
| Family label | `RemcosRAT` |
| File name | `hello_khoe_khong.exe` |
| File type | `exe` |
| First seen | `2026-09-06 19:47:27` |
| Reporter | `rifteyy` |
| Tags | `exe, rat, Remcos, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a85ef8c4e6fd94970ba9de9a96d71367` |
| SHA-1 | `711831c780034f3d6f3e05c60d7d8d797a5b98e8` |
| SHA-256 | `2fb694cdfaad46ea8d5937291a33b33eae0083921151afb6362a252cec512837` |
| SHA3-384 | `42d8d8c2e3e50da5a19bcd7bb75bfc1ff66dfc8dff81288e5fb4683a47d66ff09235bc8f35960cd5ae0c0a4d9b0747fa` |
| IMPHASH | `91e69cff27767212388496ea08379c84` |
| TLSH | `T11DE46D59A39402F8D0B7C135C982953BE7B2BC065571472F03D70E9B2F276A16F3AB26` |
| SSDEEP | `12288:NIfxS5XkH4nOqwitNfuquCwgs69gy3V5v+BNyo3PoL5aDz:C5GXkH4nnwitNfuq9wgs3y3V5vgNyo3E` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_097_2fb694cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fb694cdfaad46ea8d5937291a33b33eae0083921151afb6362a252cec512837"
    family = "RemcosRAT"
    file_name = "hello_khoe_khong.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:47:27"
  condition:
    hash.sha256(0, filesize) == "2fb694cdfaad46ea8d5937291a33b33eae0083921151afb6362a252cec512837"
}
```

### Sample 98: `bd5976c72f95a7cc`

| Field | Value |
|---|---|
| SHA-256 | `bd5976c72f95a7cc2ff2f54ac1376cf608305a097561c1fa9ecd06ab89047a1f` |
| Family label | `unknown` |
| File name | `script.vbs` |
| File type | `vbs` |
| First seen | `2026-09-06 19:45:34` |
| Reporter | `ShadowOpCode` |
| Tags | `neonstriker99, NeonVanguard, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `388b9fdaed3877ff39ee9a24622b3f9b` |
| SHA-1 | `fb03c005df2719dcc4c803913a28e9428be6274c` |
| SHA-256 | `bd5976c72f95a7cc2ff2f54ac1376cf608305a097561c1fa9ecd06ab89047a1f` |
| SHA3-384 | `c13cc4cda90d48364b6a9a48d67659e1da07182d5b861d2d39645a93c3253db1dc3bafc12161309a35e5619266c3e72f` |
| TLSH | `T17081446FFFBCD3330453408361B6E93AA4162B97295078868A5C87A91A707B3E5E1589` |
| SSDEEP | `96:E+eDXYvNcxsrhdPFzV/x8HsrEzwzsC8rakuCSgO0cUmomIL/LL1cLXSW7Nk5ULP9:/cxsrhdPFJ/x8MIsMrakAgO0cPbI7LhY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_bd5976c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd5976c72f95a7cc2ff2f54ac1376cf608305a097561c1fa9ecd06ab89047a1f"
    family = "unknown"
    file_name = "script.vbs"
    file_type = "vbs"
    first_seen = "2026-09-06 19:45:34"
  condition:
    hash.sha256(0, filesize) == "bd5976c72f95a7cc2ff2f54ac1376cf608305a097561c1fa9ecd06ab89047a1f"
}
```

### Sample 99: `4078e5813147c155`

| Field | Value |
|---|---|
| SHA-256 | `4078e5813147c155c6c4c58e42b34796733f39c68d4188e3b9595dfb0e3e13b9` |
| Family label | `unknown` |
| File name | `payload.jar` |
| File type | `jar` |
| First seen | `2026-09-06 19:45:26` |
| Reporter | `ShadowOpCode` |
| Tags | `jar, neonstriker99, NeonVanguard` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81071d8237b879cb867e3ae8c9a9c1a7` |
| SHA-1 | `14d842d44a008654283e69fe1757860a4cabca55` |
| SHA-256 | `4078e5813147c155c6c4c58e42b34796733f39c68d4188e3b9595dfb0e3e13b9` |
| SHA3-384 | `5238f911cb73941da3484a4b7ebb3695d04977e10a2fac773e9176fe93a9bec54a436ce045c4fe49c6072837371732b2` |
| TLSH | `T101E7010BBD989C2DC587803310628296E721E28DC959DB4F0AB9554ADCE0E6B1F53FDF` |
| SSDEEP | `1572864:b/QhMmpsmKuMEDOUVUg2FfBBJkkWrbHcKZhrj5YXtepcVvaRkBB:bYhMzmKqOUCNrJkkWrrcKZLuApcVvae` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_4078e581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4078e5813147c155c6c4c58e42b34796733f39c68d4188e3b9595dfb0e3e13b9"
    family = "unknown"
    file_name = "payload.jar"
    file_type = "jar"
    first_seen = "2026-09-06 19:45:26"
  condition:
    hash.sha256(0, filesize) == "4078e5813147c155c6c4c58e42b34796733f39c68d4188e3b9595dfb0e3e13b9"
}
```

### Sample 100: `65f1c072e9cf73d4`

| Field | Value |
|---|---|
| SHA-256 | `65f1c072e9cf73d46829d6cab343d606d3430d8d090ee8cc32b6a0d4ebe43f74` |
| Family label | `unknown` |
| File name | `OneDriveSync.jar` |
| File type | `jar` |
| First seen | `2026-09-06 19:45:10` |
| Reporter | `ShadowOpCode` |
| Tags | `jar, neonstriker99, NeonVanguard` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2582d9e455fa6cd3d314d6767c1f1ff` |
| SHA-1 | `961de4df64916880dba75e4932c9969d5893805e` |
| SHA-256 | `65f1c072e9cf73d46829d6cab343d606d3430d8d090ee8cc32b6a0d4ebe43f74` |
| SHA3-384 | `fef798b534e1d55f0b17d68d0710a8e75b081fcfaf1536e7fb42546546a6e114c62574e6cad478462ac5db2151c10d71` |
| TLSH | `T108E5F1CF7DD5B16DDE2B993B04208082D51D20A8C08AD46F09A5498DE936F6D2736FFE` |
| SSDEEP | `49152:AobhOmIcP747i6luFFJwIFqw0IRTCUtExSRp5dLIMXzjbywePuihQBAvjn1W0iwk:AAoOP747WFpaIRTCTkXHbePuihMcRWl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_65f1c072
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65f1c072e9cf73d46829d6cab343d606d3430d8d090ee8cc32b6a0d4ebe43f74"
    family = "unknown"
    file_name = "OneDriveSync.jar"
    file_type = "jar"
    first_seen = "2026-09-06 19:45:10"
  condition:
    hash.sha256(0, filesize) == "65f1c072e9cf73d46829d6cab343d606d3430d8d090ee8cc32b6a0d4ebe43f74"
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
 * Generated: 2026-09-07T04:52:30.997160+00:00
 */

rule MalwareBazaar_unknown_001_84f77fe2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84f77fe2a8b1468efa0c4efba816501cc6b7f6a99a826ee2344ab5ef7f362abb"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-07 04:38:47"
  condition:
    hash.sha256(0, filesize) == "84f77fe2a8b1468efa0c4efba816501cc6b7f6a99a826ee2344ab5ef7f362abb"
}

rule MalwareBazaar_unknown_002_5b555500
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b555500eac931841f3c4b8223c6d88f46ea9093a1d63ac10872f6b46b8ae7c4"
    family = "unknown"
    file_name = "5b555500eac931841f3c4b8223c6d88f46ea9093a1d63ac10872f6b46b8ae7c4.exe"
    file_type = "exe"
    first_seen = "2026-09-07 04:19:00"
  condition:
    hash.sha256(0, filesize) == "5b555500eac931841f3c4b8223c6d88f46ea9093a1d63ac10872f6b46b8ae7c4"
}

rule MalwareBazaar_Gafgyt_003_cd4b5390
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd4b5390890f18df23345caa1dba8621efc1aff60f376e49e17c4fe67a181845"
    family = "Gafgyt"
    file_name = "cd4b5390890f18df23345caa1dba8621efc1aff60f376e49e17c4fe67a181845"
    file_type = "elf"
    first_seen = "2026-09-07 04:06:37"
  condition:
    hash.sha256(0, filesize) == "cd4b5390890f18df23345caa1dba8621efc1aff60f376e49e17c4fe67a181845"
}

rule MalwareBazaar_Gafgyt_004_5991ed79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5991ed79238ab8bd0f4c4983e3e6fbc73784396daf7d585349eae37d5907c60b"
    family = "Gafgyt"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-09-07 03:58:08"
  condition:
    hash.sha256(0, filesize) == "5991ed79238ab8bd0f4c4983e3e6fbc73784396daf7d585349eae37d5907c60b"
}

rule MalwareBazaar_Gafgyt_005_e96e86dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e96e86dd43cbd957848d1d482a5efed9c5557e3d48cf5e67abee6f207504b3ed"
    family = "Gafgyt"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-09-07 03:58:06"
  condition:
    hash.sha256(0, filesize) == "e96e86dd43cbd957848d1d482a5efed9c5557e3d48cf5e67abee6f207504b3ed"
}

rule MalwareBazaar_Mirai_006_d75b9a82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d75b9a8289eda8d48ff22e483f6df819d6a3e2d3fe638f6cb986d74358fe6e8e"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-09-07 03:58:05"
  condition:
    hash.sha256(0, filesize) == "d75b9a8289eda8d48ff22e483f6df819d6a3e2d3fe638f6cb986d74358fe6e8e"
}

rule MalwareBazaar_Gafgyt_007_6a7e1676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a7e1676d52a85906d43a543bdb35f8b3282447a5ce8c98dfad33e04afe79dc6"
    family = "Gafgyt"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-09-07 03:58:04"
  condition:
    hash.sha256(0, filesize) == "6a7e1676d52a85906d43a543bdb35f8b3282447a5ce8c98dfad33e04afe79dc6"
}

rule MalwareBazaar_unknown_008_fd20a97a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd20a97a9623afecfe3d2a50f8ef75930c7522ba7e6589a03db62979509f50ea"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-07 03:50:48"
  condition:
    hash.sha256(0, filesize) == "fd20a97a9623afecfe3d2a50f8ef75930c7522ba7e6589a03db62979509f50ea"
}

rule MalwareBazaar_ValleyRAT_009_3c1aa862
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c1aa8627871e0c1d698e0854d482f5f6e7323b6c65e2488efa264fc5436c0d5"
    family = "ValleyRAT"
    file_name = "A8B50F1767FFE24416B671820377036B.exe"
    file_type = "exe"
    first_seen = "2026-09-07 03:50:07"
  condition:
    hash.sha256(0, filesize) == "3c1aa8627871e0c1d698e0854d482f5f6e7323b6c65e2488efa264fc5436c0d5"
}

rule MalwareBazaar_unknown_010_d8672868
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d867286843c77fb12979de0c70dcf2c23c75a8baca25ca97ef77df9531807888"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-09-07 03:48:46"
  condition:
    hash.sha256(0, filesize) == "d867286843c77fb12979de0c70dcf2c23c75a8baca25ca97ef77df9531807888"
}

rule MalwareBazaar_Mirai_011_32995ee3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32995ee3a0858c8c7f5594aa1bb4d38de616d66d60b920c5ffefe9bb41fccf38"
    family = "Mirai"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-09-07 03:46:49"
  condition:
    hash.sha256(0, filesize) == "32995ee3a0858c8c7f5594aa1bb4d38de616d66d60b920c5ffefe9bb41fccf38"
}

rule MalwareBazaar_unknown_012_6fef8d31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fef8d31119d09fe251811cd15d883b73b84f2e45340b8717998299b6bffa9ce"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-07 03:42:38"
  condition:
    hash.sha256(0, filesize) == "6fef8d31119d09fe251811cd15d883b73b84f2e45340b8717998299b6bffa9ce"
}

rule MalwareBazaar_unknown_013_51727678
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51727678607bdc67055453bc60d89c7ca8fd3840b7d0a59a29ec254ea843e681"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-07 03:36:49"
  condition:
    hash.sha256(0, filesize) == "51727678607bdc67055453bc60d89c7ca8fd3840b7d0a59a29ec254ea843e681"
}

rule MalwareBazaar_unknown_014_fb3931cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb3931cd32e154f3856ab8eaf8c45d5aedbb697068f5bd3f8e8684be181bbee4"
    family = "unknown"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-09-07 03:30:39"
  condition:
    hash.sha256(0, filesize) == "fb3931cd32e154f3856ab8eaf8c45d5aedbb697068f5bd3f8e8684be181bbee4"
}

rule MalwareBazaar_unknown_015_c0fdf9d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0fdf9d2bccc736513e0a8b62dd671fc8563db87bd7cd9c7e063250a2a3da655"
    family = "unknown"
    file_name = "MV_GREEN_GEM_APPOINTMENT_LETTER.js"
    file_type = "js"
    first_seen = "2026-09-07 03:25:39"
  condition:
    hash.sha256(0, filesize) == "c0fdf9d2bccc736513e0a8b62dd671fc8563db87bd7cd9c7e063250a2a3da655"
}

rule MalwareBazaar_unknown_016_38803164
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "388031645b2542819fd927cebae961b51ec67b257032d3b613917955382bdcee"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-07 03:22:39"
  condition:
    hash.sha256(0, filesize) == "388031645b2542819fd927cebae961b51ec67b257032d3b613917955382bdcee"
}

rule MalwareBazaar_Vidar_017_7bcfc586
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bcfc5863f119c8904ba0a5ade201e3dc3c17981a51d81ff13ef90d08edd4101"
    family = "Vidar"
    file_name = "7bcfc5863f119c8904ba0a5ade201e3dc3c17981a51d81ff13ef90d08edd4101.bin"
    file_type = "exe"
    first_seen = "2026-09-07 03:20:23"
  condition:
    hash.sha256(0, filesize) == "7bcfc5863f119c8904ba0a5ade201e3dc3c17981a51d81ff13ef90d08edd4101"
}

rule MalwareBazaar_Vidar_018_0e96f03f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e96f03ffdc6a7f0b60591ef68f098e5684f59deafd6fb051a58d85f777bce7c"
    family = "Vidar"
    file_name = "0e96f03ffdc6a7f0b60591ef68f098e5684f59deafd6fb051a58d85f777bce7c.bin"
    file_type = "exe"
    first_seen = "2026-09-07 03:20:19"
  condition:
    hash.sha256(0, filesize) == "0e96f03ffdc6a7f0b60591ef68f098e5684f59deafd6fb051a58d85f777bce7c"
}

rule MalwareBazaar_unknown_019_4806edb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4806edb12512156dec5a3ef9d7632a74bb8d0fbf05e64ec7bc4e164da517ee89"
    family = "unknown"
    file_name = "4806edb12512156dec5a3ef9d7632a74bb8d0fbf05e64ec7bc4e164da517ee89.elf"
    file_type = "elf"
    first_seen = "2026-09-07 03:18:18"
  condition:
    hash.sha256(0, filesize) == "4806edb12512156dec5a3ef9d7632a74bb8d0fbf05e64ec7bc4e164da517ee89"
}

rule MalwareBazaar_unknown_020_44d4e73e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44d4e73e3ec5d260f2e943fd53dbd373dee12451a784b782001a5050aadc5739"
    family = "unknown"
    file_name = "44d4e73e3ec5d260f2e943fd53dbd373dee12451a784b782001a5050aadc5739.elf"
    file_type = "elf"
    first_seen = "2026-09-07 03:18:14"
  condition:
    hash.sha256(0, filesize) == "44d4e73e3ec5d260f2e943fd53dbd373dee12451a784b782001a5050aadc5739"
}

rule MalwareBazaar_unknown_021_5d7004c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d7004c89597bbdbca578f3f441c2a61ffe89a6afdaf9c953fac8163890379a6"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-07 03:17:29"
  condition:
    hash.sha256(0, filesize) == "5d7004c89597bbdbca578f3f441c2a61ffe89a6afdaf9c953fac8163890379a6"
}

rule MalwareBazaar_Mirai_022_5ed7ca74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ed7ca74c12e3b05eda94baa5992276b8491a305b620a6938b618447f7ffb007"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-09-07 03:16:46"
  condition:
    hash.sha256(0, filesize) == "5ed7ca74c12e3b05eda94baa5992276b8491a305b620a6938b618447f7ffb007"
}

rule MalwareBazaar_unknown_023_91d6e398
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91d6e3988b09fc0a749eb4149a2b177ff4dbfe7cef6b7c6c230eb899ed237bc7"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-07 03:16:44"
  condition:
    hash.sha256(0, filesize) == "91d6e3988b09fc0a749eb4149a2b177ff4dbfe7cef6b7c6c230eb899ed237bc7"
}

rule MalwareBazaar_unknown_024_ece669be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ece669beecd14a53805d61e520f426740d32201acf0d355132cc5122f2b6cb07"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-07 03:14:46"
  condition:
    hash.sha256(0, filesize) == "ece669beecd14a53805d61e520f426740d32201acf0d355132cc5122f2b6cb07"
}

rule MalwareBazaar_unknown_025_602ffa86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "602ffa86ce02a12e74860c15f5dc8bc77c8e213439a54b433b05a4a0ce80af96"
    family = "unknown"
    file_name = "602ffa86ce02a12e74860c15f5dc8bc77c8e213439a54b433b05a4a0ce80af96.elf"
    file_type = "elf"
    first_seen = "2026-09-07 03:13:48"
  condition:
    hash.sha256(0, filesize) == "602ffa86ce02a12e74860c15f5dc8bc77c8e213439a54b433b05a4a0ce80af96"
}

rule MalwareBazaar_unknown_026_a41c8459
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a41c8459e992f9869734343bb01ce16022e6a6721247702abdb05e510734ac5e"
    family = "unknown"
    file_name = "daemonx"
    file_type = "elf"
    first_seen = "2026-09-07 03:12:37"
  condition:
    hash.sha256(0, filesize) == "a41c8459e992f9869734343bb01ce16022e6a6721247702abdb05e510734ac5e"
}

rule MalwareBazaar_unknown_027_71829e72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71829e7265a93a611ecdbcc0bae4404f7fa281ea2e3202f2b4b75c0c67e3f504"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-07 03:12:35"
  condition:
    hash.sha256(0, filesize) == "71829e7265a93a611ecdbcc0bae4404f7fa281ea2e3202f2b4b75c0c67e3f504"
}

rule MalwareBazaar_Mirai_028_0d373e1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d373e1f9dfeaa5a1c2bffa6116ce78bc2af1174a503c8cba5944664fae60500"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-09-07 03:12:34"
  condition:
    hash.sha256(0, filesize) == "0d373e1f9dfeaa5a1c2bffa6116ce78bc2af1174a503c8cba5944664fae60500"
}

rule MalwareBazaar_unknown_029_28f968b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28f968b7bd17a853cb98c7ac89e20e616fb9b20f0c434b540da5fd2dd5850a67"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-07 03:12:32"
  condition:
    hash.sha256(0, filesize) == "28f968b7bd17a853cb98c7ac89e20e616fb9b20f0c434b540da5fd2dd5850a67"
}

rule MalwareBazaar_CoinMiner_030_0005921d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0005921df4484d8e1d4319b40efc52389e75b8e8e1653afc7cd47379a2d65979"
    family = "CoinMiner"
    file_name = "0005921df4484d8e1d4319b40efc52389e75b8e8e1653afc7cd47379a2d65979.exe"
    file_type = "exe"
    first_seen = "2026-09-07 03:08:24"
  condition:
    hash.sha256(0, filesize) == "0005921df4484d8e1d4319b40efc52389e75b8e8e1653afc7cd47379a2d65979"
}

rule MalwareBazaar_unknown_031_0930835d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0930835df15e25115815eb540c839b62dde02dadc7149040ca5c7474457ee106"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-07 03:03:40"
  condition:
    hash.sha256(0, filesize) == "0930835df15e25115815eb540c839b62dde02dadc7149040ca5c7474457ee106"
}

rule MalwareBazaar_RemcosRAT_032_82bdf258
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82bdf2586c0f7b37448e40c854af2b48fdb5d27dbf43d3f6d18f772e02ccc1c1"
    family = "RemcosRAT"
    file_name = "SOAStatement-WEBBEDSTVLEETBooking #0001255399.js"
    file_type = "js"
    first_seen = "2026-09-07 02:25:05"
  condition:
    hash.sha256(0, filesize) == "82bdf2586c0f7b37448e40c854af2b48fdb5d27dbf43d3f6d18f772e02ccc1c1"
}

rule MalwareBazaar_GuLoader_033_f7913930
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f79139304d7e7197ffe1bab0441eccdfaaa2bd0d745f4c4ea810ec7c92cb2e76"
    family = "GuLoader"
    file_name = "Chlorites.vbs"
    file_type = "vbs"
    first_seen = "2026-09-07 01:33:44"
  condition:
    hash.sha256(0, filesize) == "f79139304d7e7197ffe1bab0441eccdfaaa2bd0d745f4c4ea810ec7c92cb2e76"
}

rule MalwareBazaar_unknown_034_eeb6b304
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeb6b304c33fd3ed46d2438040507905faed7f20ec73c90cd5a645bad239833d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-07 00:56:34"
  condition:
    hash.sha256(0, filesize) == "eeb6b304c33fd3ed46d2438040507905faed7f20ec73c90cd5a645bad239833d"
}

rule MalwareBazaar_unknown_035_3a194fa1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a194fa1bf6a0bbf7b9f164b5a81d6d4f8258c5aec5943db0b35977849950ad2"
    family = "unknown"
    file_name = "3a194fa1bf6a0bbf7b9f164b5a81d6d4f8258c5aec5943db0b35977849950ad2.exe"
    file_type = "exe"
    first_seen = "2026-09-07 00:38:46"
  condition:
    hash.sha256(0, filesize) == "3a194fa1bf6a0bbf7b9f164b5a81d6d4f8258c5aec5943db0b35977849950ad2"
}

rule MalwareBazaar_unknown_036_01b14dd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01b14dd94b830351164ba0ca558b5534e0741b1631b6603d20096776dea34841"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-07 00:08:30"
  condition:
    hash.sha256(0, filesize) == "01b14dd94b830351164ba0ca558b5534e0741b1631b6603d20096776dea34841"
}

rule MalwareBazaar_unknown_037_0e52dc10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e52dc105f01854254ee865a31af4b79f701c9437ca7591d979e60ade6d6cf2f"
    family = "unknown"
    file_name = "PrmUx.js"
    file_type = "js"
    first_seen = "2026-09-06 23:39:05"
  condition:
    hash.sha256(0, filesize) == "0e52dc105f01854254ee865a31af4b79f701c9437ca7591d979e60ade6d6cf2f"
}

rule MalwareBazaar_unknown_038_926054d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "926054d5f2882959f4747a04ed67d899c9983a8788660fbfe9a887164b411fdc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-06 23:33:35"
  condition:
    hash.sha256(0, filesize) == "926054d5f2882959f4747a04ed67d899c9983a8788660fbfe9a887164b411fdc"
}

rule MalwareBazaar_unknown_039_846f390f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "846f390faea2a33d5ca0c1876292853c55439bd1c26c8206a62afcd4c7333593"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-06 23:32:14"
  condition:
    hash.sha256(0, filesize) == "846f390faea2a33d5ca0c1876292853c55439bd1c26c8206a62afcd4c7333593"
}

rule MalwareBazaar_GuLoader_040_e801f571
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e801f57192dae98fac7cefc90bc5da6332bc668a5a2d9addbf135427ccd0c8d0"
    family = "GuLoader"
    file_name = "Unstintingly.vbs"
    file_type = "vbs"
    first_seen = "2026-09-06 23:13:15"
  condition:
    hash.sha256(0, filesize) == "e801f57192dae98fac7cefc90bc5da6332bc668a5a2d9addbf135427ccd0c8d0"
}

rule MalwareBazaar_Vidar_041_46dc1914
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46dc1914bfd36e66de65da421aba7581711cf761705a0cc8c9affc9f674c710e"
    family = "Vidar"
    file_name = "46dc1914bfd36e66de65da421aba7581711cf761705a0cc8c9affc9f674c710e.bin"
    file_type = "exe"
    first_seen = "2026-09-06 23:12:34"
  condition:
    hash.sha256(0, filesize) == "46dc1914bfd36e66de65da421aba7581711cf761705a0cc8c9affc9f674c710e"
}

rule MalwareBazaar_unknown_042_67e8ef03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67e8ef0325a8725e9884c0b19ac014f0c3ea497eee1f905187b8d77b25221689"
    family = "unknown"
    file_name = "67e8ef0325a8725e9884c0b19ac014f0c3ea497eee1f905187b8d77b25221689.bin"
    file_type = "exe"
    first_seen = "2026-09-06 23:12:31"
  condition:
    hash.sha256(0, filesize) == "67e8ef0325a8725e9884c0b19ac014f0c3ea497eee1f905187b8d77b25221689"
}

rule MalwareBazaar_unknown_043_74a28581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74a28581cdc96b69d58c1b2f640c2f3c6932d11eb4b53fb5bf9cf2e89ac30dd4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-06 23:08:20"
  condition:
    hash.sha256(0, filesize) == "74a28581cdc96b69d58c1b2f640c2f3c6932d11eb4b53fb5bf9cf2e89ac30dd4"
}

rule MalwareBazaar_AsyncRAT_044_d53bfb43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d53bfb43671e23ef1f925166938a2f4fb28ad163f88e92a26505aa2d56cf8977"
    family = "AsyncRAT"
    file_name = "d53bfb43671e23ef1f925166938a2f4fb28ad163f88e92a26505aa2d56cf8977.bin"
    file_type = "zip"
    first_seen = "2026-09-06 22:59:40"
  condition:
    hash.sha256(0, filesize) == "d53bfb43671e23ef1f925166938a2f4fb28ad163f88e92a26505aa2d56cf8977"
}

rule MalwareBazaar_unknown_045_052f0caf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "052f0caff530a67f9a17df5795806d9b01a551f309e434cd4eb92fba8e024051"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-06 22:59:21"
  condition:
    hash.sha256(0, filesize) == "052f0caff530a67f9a17df5795806d9b01a551f309e434cd4eb92fba8e024051"
}

rule MalwareBazaar_unknown_046_00e4094e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00e4094ed954d05c9089582e75716ef8edaca197e0b2d29ab8c7357d8e1651e8"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-06 22:36:43"
  condition:
    hash.sha256(0, filesize) == "00e4094ed954d05c9089582e75716ef8edaca197e0b2d29ab8c7357d8e1651e8"
}

rule MalwareBazaar_Mirai_047_764e5f51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "764e5f51e92dd166ff27cf105a7e1de4ab8689db0aaf6aa404839db6dc549b39"
    family = "Mirai"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-09-06 22:28:41"
  condition:
    hash.sha256(0, filesize) == "764e5f51e92dd166ff27cf105a7e1de4ab8689db0aaf6aa404839db6dc549b39"
}

rule MalwareBazaar_unknown_048_aaaf5da7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aaaf5da70c09896a1527b7b32a2f9ec22184b8bdb2cca248accd48492e8a1cef"
    family = "unknown"
    file_name = "installer_r2.0.18.exe"
    file_type = "exe"
    first_seen = "2026-09-06 22:26:40"
  condition:
    hash.sha256(0, filesize) == "aaaf5da70c09896a1527b7b32a2f9ec22184b8bdb2cca248accd48492e8a1cef"
}

rule MalwareBazaar_unknown_049_cb348c4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb348c4b941018399a9e1e3172bf43872849d511927bd42f81008b2a53c344ca"
    family = "unknown"
    file_name = "installer_r2.0.03.exe"
    file_type = "exe"
    first_seen = "2026-09-06 22:25:41"
  condition:
    hash.sha256(0, filesize) == "cb348c4b941018399a9e1e3172bf43872849d511927bd42f81008b2a53c344ca"
}

rule MalwareBazaar_unknown_050_394db160
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "394db160badc3198c94aa6c7fea01e68d6908864e1b35084538079b4f19e3a6f"
    family = "unknown"
    file_name = "installer_r2.0.02.exe"
    file_type = "exe"
    first_seen = "2026-09-06 22:24:22"
  condition:
    hash.sha256(0, filesize) == "394db160badc3198c94aa6c7fea01e68d6908864e1b35084538079b4f19e3a6f"
}

rule MalwareBazaar_unknown_051_daff0b9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daff0b9de30438bb1578bb35e6c4388187ea6e7c9cc4a14ee3a0b9eb45a22c46"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-06 22:20:47"
  condition:
    hash.sha256(0, filesize) == "daff0b9de30438bb1578bb35e6c4388187ea6e7c9cc4a14ee3a0b9eb45a22c46"
}

rule MalwareBazaar_unknown_052_363576a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "363576a90042aa9b9bd6c8fef815f38b75bbf25dc251e8219820dff96f54c645"
    family = "unknown"
    file_name = "363576a90042aa9b9bd6c8fef815f38b75bbf25dc251e8219820dff96f54c645.exe"
    file_type = "exe"
    first_seen = "2026-09-06 22:13:18"
  condition:
    hash.sha256(0, filesize) == "363576a90042aa9b9bd6c8fef815f38b75bbf25dc251e8219820dff96f54c645"
}

rule MalwareBazaar_unknown_053_25f6dbca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25f6dbcaefccc99c7878ade79fd66e8714760133f74cb282b19170f67b07cab6"
    family = "unknown"
    file_name = "launch.sh"
    file_type = "sh"
    first_seen = "2026-09-06 22:12:40"
  condition:
    hash.sha256(0, filesize) == "25f6dbcaefccc99c7878ade79fd66e8714760133f74cb282b19170f67b07cab6"
}

rule MalwareBazaar_unknown_054_a037767f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a037767ff9f8496c3ff65c4d34b38d52e4f52ab6de075b03f0bd43408502087d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-06 22:10:46"
  condition:
    hash.sha256(0, filesize) == "a037767ff9f8496c3ff65c4d34b38d52e4f52ab6de075b03f0bd43408502087d"
}

rule MalwareBazaar_unknown_055_f9203fd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9203fd93932392404872c6cfdc90b6328d494ec8d607a87fe5ceef71d211c79"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-06 22:06:01"
  condition:
    hash.sha256(0, filesize) == "f9203fd93932392404872c6cfdc90b6328d494ec8d607a87fe5ceef71d211c79"
}

rule MalwareBazaar_unknown_056_7856c46f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7856c46f70d3cf105ee1a4b89a56e66270ef07e364436d33748455e7871a8db8"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-06 21:37:47"
  condition:
    hash.sha256(0, filesize) == "7856c46f70d3cf105ee1a4b89a56e66270ef07e364436d33748455e7871a8db8"
}

rule MalwareBazaar_unknown_057_3f64b470
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f64b47077def39688ca9d675d05f99449c6e11184227123a03da4e542e7a809"
    family = "unknown"
    file_name = "goodthingsforbestpersonforme.hta"
    file_type = "hta"
    first_seen = "2026-09-06 21:23:51"
  condition:
    hash.sha256(0, filesize) == "3f64b47077def39688ca9d675d05f99449c6e11184227123a03da4e542e7a809"
}

rule MalwareBazaar_unknown_058_5b6daf19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b6daf199b4f6a649690ee385b49dfc4f04a37cb9d20e9e2825321af780bd86c"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-06 21:17:46"
  condition:
    hash.sha256(0, filesize) == "5b6daf199b4f6a649690ee385b49dfc4f04a37cb9d20e9e2825321af780bd86c"
}

rule MalwareBazaar_Mirai_059_aec8af25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aec8af25da16b46753cafb08e8311e21adc072c2b442b7c56f7ddb91197f6c39"
    family = "Mirai"
    file_name = "riscv32"
    file_type = "elf"
    first_seen = "2026-09-06 21:17:45"
  condition:
    hash.sha256(0, filesize) == "aec8af25da16b46753cafb08e8311e21adc072c2b442b7c56f7ddb91197f6c39"
}

rule MalwareBazaar_unknown_060_1b11ac41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b11ac41a6d5dfb86512055953983daf30e4762adb61576cf55e47c02440dcf3"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-06 21:11:53"
  condition:
    hash.sha256(0, filesize) == "1b11ac41a6d5dfb86512055953983daf30e4762adb61576cf55e47c02440dcf3"
}

rule MalwareBazaar_unknown_061_06a5de44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06a5de44a3305cafcc0ae4a51e051fa6f64de8a5c11b580ae18bb0a88f1dfaee"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-06 21:09:44"
  condition:
    hash.sha256(0, filesize) == "06a5de44a3305cafcc0ae4a51e051fa6f64de8a5c11b580ae18bb0a88f1dfaee"
}

rule MalwareBazaar_Mirai_062_5aa0cd0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5aa0cd0fb49efc5368952f1449686a63f61f33748892a08afe2c8e458dce70ae"
    family = "Mirai"
    file_name = "5aa0cd0fb49efc5368952f1449686a63f61f33748892a08afe2c8e458dce70ae.elf"
    file_type = "elf"
    first_seen = "2026-09-06 21:08:46"
  condition:
    hash.sha256(0, filesize) == "5aa0cd0fb49efc5368952f1449686a63f61f33748892a08afe2c8e458dce70ae"
}

rule MalwareBazaar_CoinMiner_063_9831a1b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9831a1b023f28b6cfd4c7c83099270aa48e43bf7bd8842e8858993abce86dc24"
    family = "CoinMiner"
    file_name = "9831a1b023f28b6cfd4c7c83099270aa48e43bf7bd8842e8858993abce86dc24.exe"
    file_type = "exe"
    first_seen = "2026-09-06 21:03:19"
  condition:
    hash.sha256(0, filesize) == "9831a1b023f28b6cfd4c7c83099270aa48e43bf7bd8842e8858993abce86dc24"
}

rule MalwareBazaar_Mirai_064_194f9a02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "194f9a024339c321343fe1f96d91335308b7fe4f41bb3bd875cdfc3e8fc149ff"
    family = "Mirai"
    file_name = "194f9a024339c321343fe1f96d91335308b7fe4f41bb3bd875cdfc3e8fc149ff.elf"
    file_type = "elf"
    first_seen = "2026-09-06 20:58:21"
  condition:
    hash.sha256(0, filesize) == "194f9a024339c321343fe1f96d91335308b7fe4f41bb3bd875cdfc3e8fc149ff"
}

rule MalwareBazaar_unknown_065_e8bdbd96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8bdbd96cb33b0e92cd7bae8f64e6599627dc3df656fc0a31435cd2bc06bd9a4"
    family = "unknown"
    file_name = "0d736040f6fcab61ef390639d0f9deb1270c8b3492dd7abd9cdc8ec43a100364.zip"
    file_type = "zip"
    first_seen = "2026-09-06 20:09:22"
  condition:
    hash.sha256(0, filesize) == "e8bdbd96cb33b0e92cd7bae8f64e6599627dc3df656fc0a31435cd2bc06bd9a4"
}

rule MalwareBazaar_SilentNet_066_c6a2648e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6a2648e2fb73c593025ad77df99644d0404997bf01d65466f6b2e38411ebf1e"
    family = "SilentNet"
    file_name = "index_all_french_db.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:09:14"
  condition:
    hash.sha256(0, filesize) == "c6a2648e2fb73c593025ad77df99644d0404997bf01d65466f6b2e38411ebf1e"
}

rule MalwareBazaar_unknown_067_9536bb0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9536bb0a76bf37fdc27861c3f6948a10f5a2c9a7ff1d26c3eb51b5770045d670"
    family = "unknown"
    file_name = "WinSystemHost.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:08:53"
  condition:
    hash.sha256(0, filesize) == "9536bb0a76bf37fdc27861c3f6948a10f5a2c9a7ff1d26c3eb51b5770045d670"
}

rule MalwareBazaar_VenomRAT_068_9c8969b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456"
    family = "VenomRAT"
    file_name = "privateemu.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:08:45"
  condition:
    hash.sha256(0, filesize) == "9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456"
}

rule MalwareBazaar_BlankGrabber_069_fa3523b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa3523b9e59def3558f6e9e97563dfd1e511391c290bc642a05962aeccef4afe"
    family = "BlankGrabber"
    file_name = "Delta_cracked.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:08:44"
  condition:
    hash.sha256(0, filesize) == "fa3523b9e59def3558f6e9e97563dfd1e511391c290bc642a05962aeccef4afe"
}

rule MalwareBazaar_unknown_070_3a297d84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a297d846199ddff323b30eadb510daedbbd08a9e76949c06df09e1592dd0f02"
    family = "unknown"
    file_name = "OpenBulletCE_1.3.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:08:31"
  condition:
    hash.sha256(0, filesize) == "3a297d846199ddff323b30eadb510daedbbd08a9e76949c06df09e1592dd0f02"
}

rule MalwareBazaar_unknown_071_1ae6cb0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae6cb0cdcf57b0ea68a04c7b83892c00ed6f73594d8f0b5c5742a5fcbf9b009"
    family = "unknown"
    file_name = "WinSystemHost.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:07:46"
  condition:
    hash.sha256(0, filesize) == "1ae6cb0cdcf57b0ea68a04c7b83892c00ed6f73594d8f0b5c5742a5fcbf9b009"
}

rule MalwareBazaar_Amadey_072_d38f4c8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d38f4c8fe3deb6338c561bebe8e7751c97e926907515128a4e579cccebee5ff5"
    family = "Amadey"
    file_name = "taskmanager.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:07:24"
  condition:
    hash.sha256(0, filesize) == "d38f4c8fe3deb6338c561bebe8e7751c97e926907515128a4e579cccebee5ff5"
}

rule MalwareBazaar_unknown_073_7024c376
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7024c376d00fbb19ea15f7e06d19d16de65c5b02283e072ae6c16f30dcebb3db"
    family = "unknown"
    file_name = "7024c376d00fbb19ea15f7e06d19d16de65c5b02283e072ae6c16f30dcebb3db.exe"
    file_type = "unknown"
    first_seen = "2026-09-06 20:06:54"
  condition:
    hash.sha256(0, filesize) == "7024c376d00fbb19ea15f7e06d19d16de65c5b02283e072ae6c16f30dcebb3db"
}

rule MalwareBazaar_Amadey_074_28e985ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28e985edba59127261da83fe963b0a3674d9007840acd8db505fec6ac455c987"
    family = "Amadey"
    file_name = "taskmanager.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:06:40"
  condition:
    hash.sha256(0, filesize) == "28e985edba59127261da83fe963b0a3674d9007840acd8db505fec6ac455c987"
}

rule MalwareBazaar_BlankGrabber_075_409ccd05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "409ccd057be807603e155a2a8579dfd9c7b67c0984db27b5e259fe438ef3fa8c"
    family = "BlankGrabber"
    file_name = "builder.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:06:33"
  condition:
    hash.sha256(0, filesize) == "409ccd057be807603e155a2a8579dfd9c7b67c0984db27b5e259fe438ef3fa8c"
}

rule MalwareBazaar_RedLineStealer_076_8211468f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8211468fff3cd6cf858f652b53db995782d573a092d00dac648b863d1b237efd"
    family = "RedLineStealer"
    file_name = "8211468fff3cd6cf858f652b53db995782d573a092d00dac648b863d1b237efd"
    file_type = "exe"
    first_seen = "2026-09-06 20:06:08"
  condition:
    hash.sha256(0, filesize) == "8211468fff3cd6cf858f652b53db995782d573a092d00dac648b863d1b237efd"
}

rule MalwareBazaar_unknown_077_4ae3908e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ae3908e2daf0d4ddf63935ef64b29d1707d217354168bad94bbdfec85e045f5"
    family = "unknown"
    file_name = "client.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:04:39"
  condition:
    hash.sha256(0, filesize) == "4ae3908e2daf0d4ddf63935ef64b29d1707d217354168bad94bbdfec85e045f5"
}

rule MalwareBazaar_unknown_078_83a3a48e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83a3a48e8998fe74853161d31476c613d6eaf05f618446dd9d9b1016ada44822"
    family = "unknown"
    file_name = "client.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:04:28"
  condition:
    hash.sha256(0, filesize) == "83a3a48e8998fe74853161d31476c613d6eaf05f618446dd9d9b1016ada44822"
}

rule MalwareBazaar_unknown_079_da074ef5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da074ef5707b4d685734dea298bf5ced3bcc0dbf38f7242f7e50ab4585b61d55"
    family = "unknown"
    file_name = "656b90c4553ec077f0ff60bf35edee765dffa4d63d4e2148221f9ef1171bb437.zip"
    file_type = "zip"
    first_seen = "2026-09-06 20:04:23"
  condition:
    hash.sha256(0, filesize) == "da074ef5707b4d685734dea298bf5ced3bcc0dbf38f7242f7e50ab4585b61d55"
}

rule MalwareBazaar_unknown_080_eb0e2b64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb0e2b6424e5ec1eb95d183a0f7022ab8044bf610972105289b8113ece084826"
    family = "unknown"
    file_name = "test.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:03:23"
  condition:
    hash.sha256(0, filesize) == "eb0e2b6424e5ec1eb95d183a0f7022ab8044bf610972105289b8113ece084826"
}

rule MalwareBazaar_unknown_081_15dc0305
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15dc0305186d2c1f9f63a147d7a462faaf090878b7b719fb612f6a99ceccf6dd"
    family = "unknown"
    file_name = "qt_test_s8yhb.exe.upload.zip"
    file_type = "zip"
    first_seen = "2026-09-06 20:03:04"
  condition:
    hash.sha256(0, filesize) == "15dc0305186d2c1f9f63a147d7a462faaf090878b7b719fb612f6a99ceccf6dd"
}

rule MalwareBazaar_AsyncRAT_082_5e84fd91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761"
    family = "AsyncRAT"
    file_name = "Beta-Cheat_protected.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:02:02"
  condition:
    hash.sha256(0, filesize) == "5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761"
}

rule MalwareBazaar_AsyncRAT_083_0862cc6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0862cc6ab1a0bd821b1b00fda8002d56d91f2979613505a88e142133240f8d27"
    family = "AsyncRAT"
    file_name = "SteelSeries.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:01:43"
  condition:
    hash.sha256(0, filesize) == "0862cc6ab1a0bd821b1b00fda8002d56d91f2979613505a88e142133240f8d27"
}

rule MalwareBazaar_Amadey_084_4d10c9b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d10c9b2408ba1f4cd2d3a776808a35528164e2963f497c4c06725ac840ea611"
    family = "Amadey"
    file_name = "1l74V2.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:01:35"
  condition:
    hash.sha256(0, filesize) == "4d10c9b2408ba1f4cd2d3a776808a35528164e2963f497c4c06725ac840ea611"
}

rule MalwareBazaar_AsyncRAT_085_e17581ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e17581ec73d1c5a0d2849b6ba44dc59117f41b0d490860bfbe556271635775d2"
    family = "AsyncRAT"
    file_name = "GoogleInstaller.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:00:35"
  condition:
    hash.sha256(0, filesize) == "e17581ec73d1c5a0d2849b6ba44dc59117f41b0d490860bfbe556271635775d2"
}

rule MalwareBazaar_njrat_086_6f201afc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f201afc797370ac6e33fafec41a794a2eb44c1bfd7d9079e3633ebe7bbb41e1"
    family = "njrat"
    file_name = "hostr.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:00:30"
  condition:
    hash.sha256(0, filesize) == "6f201afc797370ac6e33fafec41a794a2eb44c1bfd7d9079e3633ebe7bbb41e1"
}

rule MalwareBazaar_AsyncRAT_087_cdb73efc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdb73efc6808026585e0268ee4396c6ffc1d4d0288abff967c23c94057fc2ab0"
    family = "AsyncRAT"
    file_name = "ChromeSetup.exe"
    file_type = "exe"
    first_seen = "2026-09-06 20:00:08"
  condition:
    hash.sha256(0, filesize) == "cdb73efc6808026585e0268ee4396c6ffc1d4d0288abff967c23c94057fc2ab0"
}

rule MalwareBazaar_AsyncRAT_088_9ba76ceb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ba76ceb13a62e632b94324fc772d7921c461c6fd5e70844aadca97dcc15cb7a"
    family = "AsyncRAT"
    file_name = "AU88APP.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:59:28"
  condition:
    hash.sha256(0, filesize) == "9ba76ceb13a62e632b94324fc772d7921c461c6fd5e70844aadca97dcc15cb7a"
}

rule MalwareBazaar_AsyncRAT_089_43316503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43316503acbbc5245e96113bd6df3403d770467910feb7d91622c62ae6f02317"
    family = "AsyncRAT"
    file_name = "from_okvip_with_love.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:59:26"
  condition:
    hash.sha256(0, filesize) == "43316503acbbc5245e96113bd6df3403d770467910feb7d91622c62ae6f02317"
}

rule MalwareBazaar_AsyncRAT_090_b6f9fc16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6f9fc16a92bb2e422f20db1a4c32018e070a20d50adde6742cd066b0c9aa870"
    family = "AsyncRAT"
    file_name = "from_kiwi_okvip_with_love.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:59:09"
  condition:
    hash.sha256(0, filesize) == "b6f9fc16a92bb2e422f20db1a4c32018e070a20d50adde6742cd066b0c9aa870"
}

rule MalwareBazaar_AsyncRAT_091_cccce5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cccce5d5491d76a7aef09599c91b10bd109c03b307095be10ed85a95ce54ad8e"
    family = "AsyncRAT"
    file_name = "from_kiwi_okvip_with_love_hehe.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:59:00"
  condition:
    hash.sha256(0, filesize) == "cccce5d5491d76a7aef09599c91b10bd109c03b307095be10ed85a95ce54ad8e"
}

rule MalwareBazaar_AsyncRAT_092_cdaf86de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdaf86deee5042744424ed5990b91db92e964ff3d139ec6bf4c07b42ca659952"
    family = "AsyncRAT"
    file_name = "SHBETAPP.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:58:51"
  condition:
    hash.sha256(0, filesize) == "cdaf86deee5042744424ed5990b91db92e964ff3d139ec6bf4c07b42ca659952"
}

rule MalwareBazaar_SalatStealer_093_2070e248
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2070e2483590dd3b6ccbe4339d29c095edbbc4cadd6b57dac3ec006ff76c7bbc"
    family = "SalatStealer"
    file_name = "RknNObhod.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:58:29"
  condition:
    hash.sha256(0, filesize) == "2070e2483590dd3b6ccbe4339d29c095edbbc4cadd6b57dac3ec006ff76c7bbc"
}

rule MalwareBazaar_AsyncRAT_094_ebd9d6ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebd9d6ef8b792ba88aa5edbd9bc093ec8739729fecc8507c8d3b158c02f09024"
    family = "AsyncRAT"
    file_name = "CM88APP.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:58:09"
  condition:
    hash.sha256(0, filesize) == "ebd9d6ef8b792ba88aa5edbd9bc093ec8739729fecc8507c8d3b158c02f09024"
}

rule MalwareBazaar_AsyncRAT_095_579e244c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "579e244c821b155684cec762f68b7ce76d806da76f5367a4798b97c9246500c7"
    family = "AsyncRAT"
    file_name = "from_au88_with_love.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:58:02"
  condition:
    hash.sha256(0, filesize) == "579e244c821b155684cec762f68b7ce76d806da76f5367a4798b97c9246500c7"
}

rule MalwareBazaar_SalatStealer_096_0210f19a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0210f19ad6b72c8860d9e88b31c546a39a47939ded2bf91c65738b7ffdcf913c"
    family = "SalatStealer"
    file_name = "RknNObhod.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:57:45"
  condition:
    hash.sha256(0, filesize) == "0210f19ad6b72c8860d9e88b31c546a39a47939ded2bf91c65738b7ffdcf913c"
}

rule MalwareBazaar_RemcosRAT_097_2fb694cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fb694cdfaad46ea8d5937291a33b33eae0083921151afb6362a252cec512837"
    family = "RemcosRAT"
    file_name = "hello_khoe_khong.exe"
    file_type = "exe"
    first_seen = "2026-09-06 19:47:27"
  condition:
    hash.sha256(0, filesize) == "2fb694cdfaad46ea8d5937291a33b33eae0083921151afb6362a252cec512837"
}

rule MalwareBazaar_unknown_098_bd5976c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd5976c72f95a7cc2ff2f54ac1376cf608305a097561c1fa9ecd06ab89047a1f"
    family = "unknown"
    file_name = "script.vbs"
    file_type = "vbs"
    first_seen = "2026-09-06 19:45:34"
  condition:
    hash.sha256(0, filesize) == "bd5976c72f95a7cc2ff2f54ac1376cf608305a097561c1fa9ecd06ab89047a1f"
}

rule MalwareBazaar_unknown_099_4078e581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4078e5813147c155c6c4c58e42b34796733f39c68d4188e3b9595dfb0e3e13b9"
    family = "unknown"
    file_name = "payload.jar"
    file_type = "jar"
    first_seen = "2026-09-06 19:45:26"
  condition:
    hash.sha256(0, filesize) == "4078e5813147c155c6c4c58e42b34796733f39c68d4188e3b9595dfb0e3e13b9"
}

rule MalwareBazaar_unknown_100_65f1c072
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65f1c072e9cf73d46829d6cab343d606d3430d8d090ee8cc32b6a0d4ebe43f74"
    family = "unknown"
    file_name = "OneDriveSync.jar"
    file_type = "jar"
    first_seen = "2026-09-06 19:45:10"
  condition:
    hash.sha256(0, filesize) == "65f1c072e9cf73d46829d6cab343d606d3430d8d090ee8cc32b6a0d4ebe43f74"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-13

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 637 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 637 |
| Unique family labels | 8 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 48 |
| unknown | 39 |
| Vidar | 6 |
| CoinMiner | 3 |
| DCRat | 1 |
| WannaCry | 1 |
| Havoc | 1 |
| AsyncRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 49 |
| exe | 33 |
| unknown | 7 |
| sh | 7 |
| iso | 1 |
| ps1 | 1 |
| doc | 1 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `501f1e4ea746839e`

| Field | Value |
|---|---|
| SHA-256 | `501f1e4ea746839e90ced6f4a76422c3ae0001b45f9c2c4ed78910d4d0a1180c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-13 03:01:33` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0813c020f6270a0eaecfd6041e1998bf` |
| SHA-256 | `501f1e4ea746839e90ced6f4a76422c3ae0001b45f9c2c4ed78910d4d0a1180c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_501f1e4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "501f1e4ea746839e90ced6f4a76422c3ae0001b45f9c2c4ed78910d4d0a1180c"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-13 03:01:33"
  condition:
    hash.sha256(0, filesize) == "501f1e4ea746839e90ced6f4a76422c3ae0001b45f9c2c4ed78910d4d0a1180c"
}
```

### Sample 2: `4a51300720f6f810`

| Field | Value |
|---|---|
| SHA-256 | `4a51300720f6f81002920991029e8f68306a362c826078e9f19ccac4b153511d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-13 03:01:26` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b53465e94d05f5a988e581f2abfe2388` |
| SHA-256 | `4a51300720f6f81002920991029e8f68306a362c826078e9f19ccac4b153511d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_4a513007
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a51300720f6f81002920991029e8f68306a362c826078e9f19ccac4b153511d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-13 03:01:26"
  condition:
    hash.sha256(0, filesize) == "4a51300720f6f81002920991029e8f68306a362c826078e9f19ccac4b153511d"
}
```

### Sample 3: `0e0d4a2643d7590b`

| Field | Value |
|---|---|
| SHA-256 | `0e0d4a2643d7590b59f8dd9259f9989bffac862087e0d9a0f95e69dea95f38be` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-13 02:51:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ae5176d4f1100e1ffee625ba6d75cdc` |
| SHA-1 | `7485397727f07323a8f494a4aab0366757b1e788` |
| SHA-256 | `0e0d4a2643d7590b59f8dd9259f9989bffac862087e0d9a0f95e69dea95f38be` |
| SHA3-384 | `fad4568710c3804b3e9bea5895f861deddedb1a991a30741a5a4ba90e6219eedd84075b36a23795912807380fb497d8d` |
| TLSH | `T17F142B05E6404B53C0D327BAF7CB434A73239B54A7EB73059628ABB43BC679E5F22506` |
| TELFHASH | `t1df3142a9a23c81654db15c08ddad17b6444bd32217d0bb26ff1ac8cc582a80ee535d1f` |
| SSDEEP | `3072:enBrwO2vLsNGwJ3eTaEy+CC3KpWTF2E7IO5uFxGHrM/RW6KQejQZGRuM:Kw1okwJuTaEy+CC6cf5ujgrM/RrKoGgM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_0e0d4a26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e0d4a2643d7590b59f8dd9259f9989bffac862087e0d9a0f95e69dea95f38be"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-13 02:51:58"
  condition:
    hash.sha256(0, filesize) == "0e0d4a2643d7590b59f8dd9259f9989bffac862087e0d9a0f95e69dea95f38be"
}
```

### Sample 4: `3f67aaa79b36b33d`

| Field | Value |
|---|---|
| SHA-256 | `3f67aaa79b36b33d0b6bf22fc842f3eada9ebff6670fc3aae51308c5d0292e24` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-13 02:50:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ea35c891f2704dd9745dbb41fc645af` |
| SHA-1 | `383d72e22c4e956090a44a9545cdea5c45ac41a6` |
| SHA-256 | `3f67aaa79b36b33d0b6bf22fc842f3eada9ebff6670fc3aae51308c5d0292e24` |
| SHA3-384 | `950302e366a89fb562e983005faf5b1d706c98251d85d07ef36a4b11395adf6a4ec0e19cf64ec60b70a1b12742a6b75d` |
| TLSH | `T151F36B26B4C1D4FDC8D9C1B84BEEE236E972F0595134B11F17C4AE262E9DF206B6D620` |
| TELFHASH | `t18651eb702c6979a421fbdb66b34af068e871092008e170e5eff76ef9de923840d71027` |
| SSDEEP | `3072:hY9w/G9y7C8bCZmhHKbH1ZAloKtFbfpljwz4nPzTM/Vj5E:XnnHkVqrV5nY5E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_3f67aaa7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f67aaa79b36b33d0b6bf22fc842f3eada9ebff6670fc3aae51308c5d0292e24"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 02:50:55"
  condition:
    hash.sha256(0, filesize) == "3f67aaa79b36b33d0b6bf22fc842f3eada9ebff6670fc3aae51308c5d0292e24"
}
```

### Sample 5: `2926f6b7f7b75ad4`

| Field | Value |
|---|---|
| SHA-256 | `2926f6b7f7b75ad404d564961f5061af5335c6a96838793d9f1c92a4fb0cbd49` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-13 02:49:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d0a74ffc0fa183dc856024411298c8d` |
| SHA-1 | `415b208c9ee43d6c2d66a5ec400dc0722e9038d5` |
| SHA-256 | `2926f6b7f7b75ad404d564961f5061af5335c6a96838793d9f1c92a4fb0cbd49` |
| SHA3-384 | `fa93b3d369d427a9b0f16fbbffd732883d6b4fea2673640e32137c6f51237c93cf0596573ca9651ef1f2401f6e47e534` |
| TLSH | `T1F05302C963E278D4C72F4F7606EEC48CB3E59C13A1415F2729E620F584697A0DE417E2` |
| SSDEEP | `1536:4FUuUIUSAZ/Pblyd+QJDJHMasDZ7UM/IydycFL0:iRUSY/T07D5psDaudK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_2926f6b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2926f6b7f7b75ad404d564961f5061af5335c6a96838793d9f1c92a4fb0cbd49"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 02:49:55"
  condition:
    hash.sha256(0, filesize) == "2926f6b7f7b75ad404d564961f5061af5335c6a96838793d9f1c92a4fb0cbd49"
}
```

### Sample 6: `c9bf9fc13119182e`

| Field | Value |
|---|---|
| SHA-256 | `c9bf9fc13119182ec3f44875b2ac5b3235605f8f5e6198ca7e9dd8ca3ad3b9ec` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-13 02:46:04` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20d97b5f88e4a0910dd2ee3b3c40c7b9` |
| SHA-1 | `829a55b439fb383004253d38a82f777ac0c581b2` |
| SHA-256 | `c9bf9fc13119182ec3f44875b2ac5b3235605f8f5e6198ca7e9dd8ca3ad3b9ec` |
| SHA3-384 | `90442617fbbcbc7c68a87a1e11b6ad7958e4e139ff83d0a566c658f26bae39dae759d808a27308a6d11a1a40265e911b` |
| TLSH | `T174235C6516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF68C4A6ADD109B1D` |
| SSDEEP | `768:c+K9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:c+fcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_c9bf9fc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9bf9fc13119182ec3f44875b2ac5b3235605f8f5e6198ca7e9dd8ca3ad3b9ec"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-13 02:46:04"
  condition:
    hash.sha256(0, filesize) == "c9bf9fc13119182ec3f44875b2ac5b3235605f8f5e6198ca7e9dd8ca3ad3b9ec"
}
```

### Sample 7: `beec9de861a22593`

| Field | Value |
|---|---|
| SHA-256 | `beec9de861a22593ebec152e204e7daa92c819bb809226ea87c530a4b644b044` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-08-13 02:44:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70909e0beca399b281c369c4c2abcdf2` |
| SHA-1 | `1d533a601fd76ee8f2a432c5c8df67cc37a44d04` |
| SHA-256 | `beec9de861a22593ebec152e204e7daa92c819bb809226ea87c530a4b644b044` |
| SHA3-384 | `fe54db61171f764428e974da2898e105e1cf4aa27df7c1d53df110c0c5d1544c4d49295fab68bed66856d50b8c255c4d` |
| TLSH | `T1B4E30755FD958F22C6C265BBFB8E428C772B1758D3FE720399256F20378B85A0E3A141` |
| TELFHASH | `t1ac212241cfc40bdc53e45114609fb06556f479fe2e2638436b6daf1f95138d3703942a` |
| SSDEEP | `3072:VJlyPVPKvI8HJ8+hWa79tz93wGTAL1/xdeGFLFBSrHQ:VJlyPVPKvI0U+Xz93wwAZ/DjBFBSE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_beec9de8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "beec9de861a22593ebec152e204e7daa92c819bb809226ea87c530a4b644b044"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-13 02:44:00"
  condition:
    hash.sha256(0, filesize) == "beec9de861a22593ebec152e204e7daa92c819bb809226ea87c530a4b644b044"
}
```

### Sample 8: `f3137c3cfcd9c8e7`

| Field | Value |
|---|---|
| SHA-256 | `f3137c3cfcd9c8e705bbc5c4b08d16af556f97a12a2b7b4f65492de77788f885` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-08-13 02:41:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea09c45c49abd2d090ba0b79f283a08a` |
| SHA-1 | `a442eb84d4a535bd90282f22388ffa082983d8c3` |
| SHA-256 | `f3137c3cfcd9c8e705bbc5c4b08d16af556f97a12a2b7b4f65492de77788f885` |
| SHA3-384 | `ebaae38ad54c181259ceb95795429d1b67fd39a74f1dfccdd3c9307267fba51bca409953880ff3256fc414dc67a35111` |
| TLSH | `T13BE3F759FD41AF00D5D635FAFA4E028973931B6CE3FE7102AE245B2123CAA6B0F76505` |
| TELFHASH | `t18321eb53fe540fece3c941bd904e311a16fcbaea7a22241a508d8b0f8661dc2753a817` |
| SSDEEP | `3072:8UBzUsT4Pb5l/yVvhCK6LRy43REaIq3aXrbpMaph44ZgVdU/MlTsHK:8UBzUssPb/SwKAcKEaI+aXrbpJp/ZEyM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_f3137c3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3137c3cfcd9c8e705bbc5c4b08d16af556f97a12a2b7b4f65492de77788f885"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-08-13 02:41:55"
  condition:
    hash.sha256(0, filesize) == "f3137c3cfcd9c8e705bbc5c4b08d16af556f97a12a2b7b4f65492de77788f885"
}
```

### Sample 9: `534d42bacaf13a9a`

| Field | Value |
|---|---|
| SHA-256 | `534d42bacaf13a9a2b0246ac604882d17cc740d16a750686c73780ee2ac4aaa2` |
| Family label | `unknown` |
| File name | `USD $50,000.00.exe` |
| File type | `exe` |
| First seen | `2026-08-13 02:34:53` |
| Reporter | `threatcat_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e2b658505c35a55a71186c2c618f491` |
| SHA-1 | `77f783cdb4a873fa1a34c33b726d085d46b5979b` |
| SHA-256 | `534d42bacaf13a9a2b0246ac604882d17cc740d16a750686c73780ee2ac4aaa2` |
| SHA3-384 | `5239c80652d11aea4c84b21b928352b41e64f30e0be32d6a4e1da90e596ae99e338b1173e13d83e07efce9982e720856` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F105BE226F4A3F51C62E1639C0A6182083F6DC065FF7D3EA3FE85DE66962790DD36502` |
| SSDEEP | `12288:OE85Qj+B2mbllj9G47cb9o4f7wlWDw37n5AbU0rYM3GuxUwK:ORxQmbL77e7wl9nOU0rYsdK` |
| ICON-DHASH | `4db292f2d88cb40b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_534d42ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "534d42bacaf13a9a2b0246ac604882d17cc740d16a750686c73780ee2ac4aaa2"
    family = "unknown"
    file_name = "USD $50,000.00.exe"
    file_type = "exe"
    first_seen = "2026-08-13 02:34:53"
  condition:
    hash.sha256(0, filesize) == "534d42bacaf13a9a2b0246ac604882d17cc740d16a750686c73780ee2ac4aaa2"
}
```

### Sample 10: `4a8cc17f0df2448a`

| Field | Value |
|---|---|
| SHA-256 | `4a8cc17f0df2448ac7fb7306477c759786348ec01bdfb28e3077b7254a740965` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-08-13 02:26:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8e378343044a8bd21830d200a34a2f3` |
| SHA-1 | `914c86e973482b9cfdd016244123403f97a6ac3e` |
| SHA-256 | `4a8cc17f0df2448ac7fb7306477c759786348ec01bdfb28e3077b7254a740965` |
| SHA3-384 | `9370c530c4708cb5a2d0c134ca9c3dbbf634d8dc1f73868e32ff60fa69ff0e1e9c9eb579c494a3396f9d9c5246880c9b` |
| TLSH | `T163F31956F9819B11D5C255BAFE0E128E73131B38E3EE72129D246B74778B8BF0E3A405` |
| TELFHASH | `t146213516df6006ac6be4417850dd543757bc3ae52f16240a9a0fbe0ad2364c3762c42f` |
| SSDEEP | `3072:W1x4nsusW+KeTQHwgaxtLGbn1x1aYHMVvqGDizVh7Qq3/9eL2PHGR:W1x4ns3BBcwFtqn1HaYMtqGaVh7QW9e/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_4a8cc17f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a8cc17f0df2448ac7fb7306477c759786348ec01bdfb28e3077b7254a740965"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-13 02:26:02"
  condition:
    hash.sha256(0, filesize) == "4a8cc17f0df2448ac7fb7306477c759786348ec01bdfb28e3077b7254a740965"
}
```

### Sample 11: `a927d84600015018`

| Field | Value |
|---|---|
| SHA-256 | `a927d846000150182ceb79dc90494dff0d36acffd5aa78f793c110eae5694c2f` |
| Family label | `unknown` |
| File name | `bbc` |
| File type | `sh` |
| First seen | `2026-08-13 02:26:01` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd4badb66fc97b03d4fd9cbb7563a937` |
| SHA-1 | `9894c275621f94ecb023f90275e1da7e6c719618` |
| SHA-256 | `a927d846000150182ceb79dc90494dff0d36acffd5aa78f793c110eae5694c2f` |
| SHA3-384 | `6727fd379b6b80218e0858749c9be0bde3aaac64917fd3bbee2b6318da52b880fead9d115fce38a0de2428c35e761265` |
| TLSH | `T10DF08C03A48BF036808439A8EB76F75AFC24BC476262CE4CB840BA50EED74247861240` |
| SSDEEP | `12:lSjhh1OL9ephRjk4Y4bou7Co1VOq2xddNizdI/HXu81lmXx:lk1gYpTr8i3fOq2bf8IGMAh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_a927d846
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a927d846000150182ceb79dc90494dff0d36acffd5aa78f793c110eae5694c2f"
    family = "unknown"
    file_name = "bbc"
    file_type = "sh"
    first_seen = "2026-08-13 02:26:01"
  condition:
    hash.sha256(0, filesize) == "a927d846000150182ceb79dc90494dff0d36acffd5aa78f793c110eae5694c2f"
}
```

### Sample 12: `f858d116faf99236`

| Field | Value |
|---|---|
| SHA-256 | `f858d116faf992366be063f8681a5b5d153a5e69944577761470b063d403f88c` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-08-13 02:20:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `482f73e280bd05edcaaa58c35b981ee1` |
| SHA-1 | `054fc4192debe158c721742cf1ac8d60b520271a` |
| SHA-256 | `f858d116faf992366be063f8681a5b5d153a5e69944577761470b063d403f88c` |
| SHA3-384 | `52cf358998eaf4d9d383072a855493e54c8c40cb3d94339d15433edd8d0326e7c6cdbbf56937235543d1e3414d0eadcf` |
| TLSH | `T122930995BC828B12D9C412BAFA1E118D3313177CE2EE73129D206F2577CB96B0E7B516` |
| TELFHASH | `t18831309a6e8c0f9ca3f6400d8a4f936b5de430fc0b113a859f8d368f86569e0b065436` |
| SSDEEP | `1536:e8MnlMqPfs9MyzsJi3y5RfVBfi2iPFa1VqiDQhFMD1iv7FWjT7xi5IYUc:eCYfTyzyXP62iPFa1JW7FWjTFi+o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_f858d116
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f858d116faf992366be063f8681a5b5d153a5e69944577761470b063d403f88c"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-13 02:20:51"
  condition:
    hash.sha256(0, filesize) == "f858d116faf992366be063f8681a5b5d153a5e69944577761470b063d403f88c"
}
```

### Sample 13: `ae0c56bd6b7122ad`

| Field | Value |
|---|---|
| SHA-256 | `ae0c56bd6b7122adb67c3fb2804f02464798a16f015f8147c3d2d621ad87c9ca` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-08-13 02:20:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be1979703d4ce84fbc7c585f472accf9` |
| SHA-1 | `03c88b656eb6119c5b18d71fef6cd248a2292c95` |
| SHA-256 | `ae0c56bd6b7122adb67c3fb2804f02464798a16f015f8147c3d2d621ad87c9ca` |
| SHA3-384 | `927c3296b25c73e420d5d768c3fafb59411f0a6b548c940af45d2233dd2b8d7f3d29604ba214e48c3fa3d61dd834d153` |
| TLSH | `T17E731991FC819613C6D4127BFB6E428D372653A8D2EE73039D266F20779B82B0E77641` |
| TELFHASH | `t18f5132bb9f640f8c9be4c25882ce616a19ec34bd1b043597ce5d378b91e3682b50d437` |
| SSDEEP | `1536:XaP69Sc3K1fFbwXu4WxFqSc6fTaZzwVrOfSl7GRwFY:XaP6DYbw+pPqSraZzwY6lS3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_ae0c56bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0c56bd6b7122adb67c3fb2804f02464798a16f015f8147c3d2d621ad87c9ca"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-08-13 02:20:48"
  condition:
    hash.sha256(0, filesize) == "ae0c56bd6b7122adb67c3fb2804f02464798a16f015f8147c3d2d621ad87c9ca"
}
```

### Sample 14: `3fa6280b8fb6e208`

| Field | Value |
|---|---|
| SHA-256 | `3fa6280b8fb6e208c0e67fae05e4c94cb3ea41c83f9a497f9b6664d00d78fdf2` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-08-13 02:19:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b23ebf422c885d38363589a08c1b6ed9` |
| SHA-1 | `1bdccf4c58f4c1cb23e69f7d2be0da5770876699` |
| SHA-256 | `3fa6280b8fb6e208c0e67fae05e4c94cb3ea41c83f9a497f9b6664d00d78fdf2` |
| SHA3-384 | `b64f11cd361e2f3d4e285db49de5f006fc3a5ed1695817c70530e0b3c3671c94c9b78a928dd5578549aef1a267cf2212` |
| TLSH | `T13603E2D2913300B0D9F1CEB59C3C85929755BAACD4D6312B2DB6C728AF8DD611BF44D2` |
| SSDEEP | `768:aCaiy2henK9oHNR4qpS1KmutA4dJWjCBdSdqQBCU8PoqUq9q3UELn4:aCaiNeKo/0KZdJTpQMUcoZfL4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_3fa6280b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa6280b8fb6e208c0e67fae05e4c94cb3ea41c83f9a497f9b6664d00d78fdf2"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-13 02:19:58"
  condition:
    hash.sha256(0, filesize) == "3fa6280b8fb6e208c0e67fae05e4c94cb3ea41c83f9a497f9b6664d00d78fdf2"
}
```

### Sample 15: `a20f7aad7c1baeb9`

| Field | Value |
|---|---|
| SHA-256 | `a20f7aad7c1baeb96fa1f8404cc1ef9056636225979824d7a5297d3bc8f0609b` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-13 02:19:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1a45d456b6c6b1446c920d30b999985` |
| SHA-1 | `6cc0263ae95a1bb06e8d141cfa6332ee2b36cd87` |
| SHA-256 | `a20f7aad7c1baeb96fa1f8404cc1ef9056636225979824d7a5297d3bc8f0609b` |
| SHA3-384 | `6a7cce2b967532ad82232e39269e9852954fa5e554d4f4a7d0011b7ddc11fd5ced721472828f01d5c53c9d734de603a5` |
| TLSH | `T183C27D956A867C44BDC98B3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11FACD618B2A` |
| SSDEEP | `768:kK8vCB+25j6es8R5k79FYpMSUpi+20qUpi+20YQX:kK8l25J5kNd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_a20f7aad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a20f7aad7c1baeb96fa1f8404cc1ef9056636225979824d7a5297d3bc8f0609b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-13 02:19:57"
  condition:
    hash.sha256(0, filesize) == "a20f7aad7c1baeb96fa1f8404cc1ef9056636225979824d7a5297d3bc8f0609b"
}
```

### Sample 16: `6b9726c40810214f`

| Field | Value |
|---|---|
| SHA-256 | `6b9726c40810214f4c9991fd472060ee540ed6fc6df98c1bcc47048802240bed` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-08-13 02:19:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d0dddcf60d2ee823f82a807cd66c956` |
| SHA-1 | `55a7b2cbc5c9bec01ca17d82ff625b304d3fd252` |
| SHA-256 | `6b9726c40810214f4c9991fd472060ee540ed6fc6df98c1bcc47048802240bed` |
| SHA3-384 | `2d4c65b344db85fdb850a6a886c4564e5fc125839106e2a118b718da85a902878595ef38c02d4d7947d3f30ac4c6939f` |
| TLSH | `T142F2E1715F52EAF2D2F08179F939108297613DA9F0BC3226BCD88568B8C9ADB20B1517` |
| SSDEEP | `768:4yPTQbwpEDGIFQxlob+6cy01E+oYGes3Uoz1W:4yPAdaIuxi+Ly29Uz1W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_6b9726c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b9726c40810214f4c9991fd472060ee540ed6fc6df98c1bcc47048802240bed"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-08-13 02:19:56"
  condition:
    hash.sha256(0, filesize) == "6b9726c40810214f4c9991fd472060ee540ed6fc6df98c1bcc47048802240bed"
}
```

### Sample 17: `3b498192384e9468`

| Field | Value |
|---|---|
| SHA-256 | `3b498192384e946885d868bf3afd1d38b7713974623e30e4bd9f1e98673e5d08` |
| Family label | `Mirai` |
| File name | `data_mipsel` |
| File type | `elf` |
| First seen | `2026-08-13 02:17:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28829770c61473ef46c920596b34d30c` |
| SHA-1 | `6cc9a6846fa303c881db633a78e8e105efd190a4` |
| SHA-256 | `3b498192384e946885d868bf3afd1d38b7713974623e30e4bd9f1e98673e5d08` |
| SHA3-384 | `544fca8f8ee4438a933cc637b0cf56320eb9de9e95015032ad660bd22f3cbe6bff5663e53d4c1fa886eb5d29d3a1f3d0` |
| TLSH | `T1D304F60ABF610FB7D8ABDD7702E90B0129CCA91B25B43B757534E818B54B58B49E3C78` |
| SSDEEP | `1536:LyX+wYT6HAIzpT8T0Ym/QPreostS07nRzDGBqdCCuc3sPlQ08M0/cqirZWhEyrwh:OOw/8rpsgK1t1M0GrCEQASWs78` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_3b498192
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b498192384e946885d868bf3afd1d38b7713974623e30e4bd9f1e98673e5d08"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-08-13 02:17:55"
  condition:
    hash.sha256(0, filesize) == "3b498192384e946885d868bf3afd1d38b7713974623e30e4bd9f1e98673e5d08"
}
```

### Sample 18: `368160899f8e7811`

| Field | Value |
|---|---|
| SHA-256 | `368160899f8e7811a45bfabc8dd7464d79575e9d0bb0ded1ac585c40ecbaeb93` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-13 02:15:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3803b552e6d0bdd4809dc6d8251839c` |
| SHA-1 | `19634c4c147809216264378bd9b419444100b4a5` |
| SHA-256 | `368160899f8e7811a45bfabc8dd7464d79575e9d0bb0ded1ac585c40ecbaeb93` |
| SHA3-384 | `1a614fc3a43af5823c4168bff53cd3a6236b70813a657771b53f75eae5210eeea587b725af927cb04f5002ce4255ade8` |
| TLSH | `T1D3D35B63CC796F58C128D5B0B1318F795BA3A960914B6FBE58B7C2748087C8DF6463B8` |
| SSDEEP | `3072:vSLwRmgn5a4y3fLel+4MczqWV3W8l/49Hu:6s1n5Dy3fcp3V3P/48` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_36816089
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "368160899f8e7811a45bfabc8dd7464d79575e9d0bb0ded1ac585c40ecbaeb93"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-13 02:15:59"
  condition:
    hash.sha256(0, filesize) == "368160899f8e7811a45bfabc8dd7464d79575e9d0bb0ded1ac585c40ecbaeb93"
}
```

### Sample 19: `91bbb53706f8b4d4`

| Field | Value |
|---|---|
| SHA-256 | `91bbb53706f8b4d4142e22e1ca06b8ee2078e9409d1ba23c89a5baa738150019` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-13 02:12:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52d8c11310e8fd903def90f4dabc31d8` |
| SHA-1 | `03dabe922753ee2acb0ae532ddd52a997aff1876` |
| SHA-256 | `91bbb53706f8b4d4142e22e1ca06b8ee2078e9409d1ba23c89a5baa738150019` |
| SHA3-384 | `b87d28b7e790cb967b6c537d4a73830a654cf3b7dfee7bb1997574884c83094afc95d13cba058d733b68fa4c6577abed` |
| TLSH | `T1EA24965E6E328F7EF2A8C73447B74B20A75D23D626E1D684D2ACC1141E6035E641FFA8` |
| TELFHASH | `t12541af180db817f0b3656c5d489dff26d6a331eb7e262c238e51e86aa769f834d10c0c` |
| SSDEEP | `3072:o4urEayZw1PN+nQAbFmdxeAAY78LM41VCrY7h6pBTXZoNkG44aNsB3DHZlWH:o4OEayZw1yfbFmwoEBqkNGJo2PdNsB1G` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_91bbb537
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91bbb53706f8b4d4142e22e1ca06b8ee2078e9409d1ba23c89a5baa738150019"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-13 02:12:02"
  condition:
    hash.sha256(0, filesize) == "91bbb53706f8b4d4142e22e1ca06b8ee2078e9409d1ba23c89a5baa738150019"
}
```

### Sample 20: `d5fd3c15f9514e18`

| Field | Value |
|---|---|
| SHA-256 | `d5fd3c15f9514e187adf6756e85b5b7ce377a8639a327e60bdeedf0fb19f3258` |
| Family label | `Mirai` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-08-13 02:08:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d60bbf3973597220f7f1d64faebd5a05` |
| SHA-1 | `c7e8bfe4941e81e707cdd1176c2e099bd76d6747` |
| SHA-256 | `d5fd3c15f9514e187adf6756e85b5b7ce377a8639a327e60bdeedf0fb19f3258` |
| SHA3-384 | `58f65f7c8553c92bcc05462a477a972a14f6d1b887f8b3012df6798f6075eecc0c00d65f55e9c0605184c3ee888f31f8` |
| TLSH | `T16D434B22C9FD9D46CAD0B97A02E703E3D2C75B1483E4DA4EED941F698F0A3205D67798` |
| TELFHASH | `t13cf0ac48e93d8f2d46e36d30cc7d8b52a1a3893352a1c325df58cac0593e115f219e0e` |
| SSDEEP | `1536:rxkUF1r9n4naWT3r9n4nM9a2A2UOtq4XVi95u2BOcA0XXMlcitw3tu:rxkUF1r94a63r94t12UO044ghw30` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_d5fd3c15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5fd3c15f9514e187adf6756e85b5b7ce377a8639a327e60bdeedf0fb19f3258"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-08-13 02:08:10"
  condition:
    hash.sha256(0, filesize) == "d5fd3c15f9514e187adf6756e85b5b7ce377a8639a327e60bdeedf0fb19f3258"
}
```

### Sample 21: `79cb0240cf8f0767`

| Field | Value |
|---|---|
| SHA-256 | `79cb0240cf8f0767b94923cfd8007e71628ae7bfd9af38ed67b6d34c422a7c62` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-13 02:06:14` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da4dd08cebacef41fde1487a31a9372a` |
| SHA-1 | `96a4fb7b883dc3340eeacdd32ecbeb80d4196759` |
| SHA-256 | `79cb0240cf8f0767b94923cfd8007e71628ae7bfd9af38ed67b6d34c422a7c62` |
| SHA3-384 | `3785685acd142495fe829e372991cdf7160c7ee4ad9f3a187295fc95bccc8a6cee2869477428f98d9e26cfc3df436bd8` |
| TLSH | `T1D3C27C966A867C44BEC98A3E4CBD2B1D6DF4C3D1324942AC3D8A3C71DC15F9CD618B1A` |
| SSDEEP | `768:Ia8vCB+25j6es8Rb9FYpMSUpi+20qUpi+20YQX:Ia8l25Jtd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_79cb0240
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79cb0240cf8f0767b94923cfd8007e71628ae7bfd9af38ed67b6d34c422a7c62"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-13 02:06:14"
  condition:
    hash.sha256(0, filesize) == "79cb0240cf8f0767b94923cfd8007e71628ae7bfd9af38ed67b6d34c422a7c62"
}
```

### Sample 22: `fd0e0269eee45e68`

| Field | Value |
|---|---|
| SHA-256 | `fd0e0269eee45e681eca36c4ea6a1bfa41a4d7421167da23270afc35e5eaed01` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-13 02:01:12` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `132293040dacd4e3f4550e0285c5c465` |
| SHA-256 | `fd0e0269eee45e681eca36c4ea6a1bfa41a4d7421167da23270afc35e5eaed01` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_fd0e0269
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd0e0269eee45e681eca36c4ea6a1bfa41a4d7421167da23270afc35e5eaed01"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-13 02:01:12"
  condition:
    hash.sha256(0, filesize) == "fd0e0269eee45e681eca36c4ea6a1bfa41a4d7421167da23270afc35e5eaed01"
}
```

### Sample 23: `80db791509c34212`

| Field | Value |
|---|---|
| SHA-256 | `80db791509c3421260a19aa13397072d6aa7c6981822ee03333950a3444e74f0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-13 02:01:05` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1125a90571e81f6b48baeda6d2f64b5f` |
| SHA-256 | `80db791509c3421260a19aa13397072d6aa7c6981822ee03333950a3444e74f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_80db7915
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80db791509c3421260a19aa13397072d6aa7c6981822ee03333950a3444e74f0"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-13 02:01:05"
  condition:
    hash.sha256(0, filesize) == "80db791509c3421260a19aa13397072d6aa7c6981822ee03333950a3444e74f0"
}
```

### Sample 24: `47a24d074131c35a`

| Field | Value |
|---|---|
| SHA-256 | `47a24d074131c35a8abccb79a958316165a5827b96d446c5d31f1f7b0efa4c4d` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-08-13 01:59:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f131f0cc29b8f2481a6681093d53f164` |
| SHA-1 | `161b969d92ed9bd7aa81ffc95e598cae03766b6e` |
| SHA-256 | `47a24d074131c35a8abccb79a958316165a5827b96d446c5d31f1f7b0efa4c4d` |
| SHA3-384 | `2512466780a426df383fb783976d14aa7aa3b039a87bae2f70e93e02825d4b476790e413c8bb2b4f7e006b80578439ef` |
| TLSH | `T19AB35DC9FB83E0F4D9460AB0115BE77E8B35DE225024DE5AD7E4FE75AC32602A11A71C` |
| TELFHASH | `t1e4514bb65ef20cdc77d15445d10a53a39e1de27f29103ab682f3695033baf42817ad39` |
| SSDEEP | `1536:61hRX7krhfcccjrUa6vhOH44zQ5JlxU031s54oqPl5jyLWAiPkIRVFCGVS+r:613LKfA/6vhq44zQP+XqNzAinFVSW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_47a24d07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47a24d074131c35a8abccb79a958316165a5827b96d446c5d31f1f7b0efa4c4d"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-13 01:59:55"
  condition:
    hash.sha256(0, filesize) == "47a24d074131c35a8abccb79a958316165a5827b96d446c5d31f1f7b0efa4c4d"
}
```

### Sample 25: `a4e82a110c505c1f`

| Field | Value |
|---|---|
| SHA-256 | `a4e82a110c505c1fa42956ad1f7c105d745677148a93f64d5c0a23c6b63e219f` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-13 01:55:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3302fa48501d642d935696129bf53b6` |
| SHA-1 | `46deca297c14ded0bc38583d4d8f85a3e7177e24` |
| SHA-256 | `a4e82a110c505c1fa42956ad1f7c105d745677148a93f64d5c0a23c6b63e219f` |
| SHA3-384 | `383f557c803eeacebac6a2e4dc37dadb1af58e4657be48bed2ce530f83635dbb4984b349457f685db98e6cca0b044842` |
| TLSH | `T11024D80AAF510FFBD8AFDD3306E90B4625CC651722A83B393674D524F64A94B49E3C78` |
| SSDEEP | `3072:F5F9DqS+8pAOAQ6M4dvEUNMKddnCPMpeHRlIH55I:3F9mS+8pfdgEUO2p4ru5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_a4e82a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4e82a110c505c1fa42956ad1f7c105d745677148a93f64d5c0a23c6b63e219f"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-13 01:55:58"
  condition:
    hash.sha256(0, filesize) == "a4e82a110c505c1fa42956ad1f7c105d745677148a93f64d5c0a23c6b63e219f"
}
```

### Sample 26: `391bdcb9558ee696`

| Field | Value |
|---|---|
| SHA-256 | `391bdcb9558ee696f7ed9f8b45ee25c831ecd103340ca998b68716711e6c429c` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-13 01:50:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a485f013761995b33cc9db9a47409941` |
| SHA-1 | `c5fe15d0b39c6e0a9d19d1d4f4340fb690d58c6f` |
| SHA-256 | `391bdcb9558ee696f7ed9f8b45ee25c831ecd103340ca998b68716711e6c429c` |
| SHA3-384 | `f216b3cf1cdcb988561051392807c37d0cd5ac70f56be5bc796b1d728e1d25ed68ecf9346c200bd810d841768d628bfa` |
| TLSH | `T155635AC1A643D4F9FC6605785077FB338B72F4361029DA8BD369E973AC62501EA463AC` |
| TELFHASH | `t11031c0f62d6e0ae9b7e1ac48c35e5ed13a7dd63b25a072a044a3583022e3d9540b9c39` |
| SSDEEP | `1536:dV+J2AQTtzE3I59TLEF8M1OV/Xh3NYZfLxABmpQSq7:dVujQTtz4gpG1OVXBNoTxu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_391bdcb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "391bdcb9558ee696f7ed9f8b45ee25c831ecd103340ca998b68716711e6c429c"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 01:50:44"
  condition:
    hash.sha256(0, filesize) == "391bdcb9558ee696f7ed9f8b45ee25c831ecd103340ca998b68716711e6c429c"
}
```

### Sample 27: `9f7ef60eca04d7f3`

| Field | Value |
|---|---|
| SHA-256 | `9f7ef60eca04d7f3153e9226a20ce34c0cb798c0f31dbceb91a58c724445469a` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-13 01:49:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33d50e8565e727233dfb52c6f501349b` |
| SHA-1 | `53f4ce70942af3ffdd28c94ab950e39010edabef` |
| SHA-256 | `9f7ef60eca04d7f3153e9226a20ce34c0cb798c0f31dbceb91a58c724445469a` |
| SHA3-384 | `e1bdaeec0ba2439585cc55424e6826d025f8096b79e319a68832ad176e3fbe18b3809f2c3ffb19c27a3c3846be700351` |
| TLSH | `T151F2E121F9A5C1DFC53C20B2A19E526A7911B10EC589E68837CE743B6921F343726ECE` |
| SSDEEP | `768:1OH/tfxlyxWYazeuOmvo5VscH0zm6ZilNs7QZ+nbcuyD7UHQRjI:1Of0izeuOkGVM5ZuGm+nouy8HyM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_9f7ef60e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f7ef60eca04d7f3153e9226a20ce34c0cb798c0f31dbceb91a58c724445469a"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 01:49:54"
  condition:
    hash.sha256(0, filesize) == "9f7ef60eca04d7f3153e9226a20ce34c0cb798c0f31dbceb91a58c724445469a"
}
```

### Sample 28: `ae0049d554db8034`

| Field | Value |
|---|---|
| SHA-256 | `ae0049d554db803483b5677a2bf7995c6d2aecb8e036978e6e6169afa88d44ab` |
| Family label | `Mirai` |
| File name | `data_arm4` |
| File type | `elf` |
| First seen | `2026-08-13 01:49:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b08c1b8aa6067e4f08afd6b16db5bd3f` |
| SHA-1 | `81f74208ac2f2455efa6c3061b8daf9af4718c9d` |
| SHA-256 | `ae0049d554db803483b5677a2bf7995c6d2aecb8e036978e6e6169afa88d44ab` |
| SHA3-384 | `1173fc89b2f67e47a720a2967b4b9d95adfae0c97ce1cea4e1ec4a6cbf5352ef0ed452617f4f72d10be7ec0a0704c4b2` |
| TLSH | `T1EFD31A527D429F13C5C321F6FBAE46583B136BBCD7EA3102E924BF61274B8DA0E26511` |
| TELFHASH | `t14a31fe75dfb404d86be99188a19ab4362bec32de37143951a2ae7a5f4e03cc1b43d90d` |
| SSDEEP | `3072:BYFIEyd4oA26yzXGuh02omr/S/zP7VOPkFiB7z:BYFInzXNh0N6izP70iiB7z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_ae0049d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0049d554db803483b5677a2bf7995c6d2aecb8e036978e6e6169afa88d44ab"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-08-13 01:49:53"
  condition:
    hash.sha256(0, filesize) == "ae0049d554db803483b5677a2bf7995c6d2aecb8e036978e6e6169afa88d44ab"
}
```

### Sample 29: `68a5be8895dd1130`

| Field | Value |
|---|---|
| SHA-256 | `68a5be8895dd1130e6beb6f0bc508c9d022b51ef0ed8279cf46db2cfab729247` |
| Family label | `unknown` |
| File name | `68a5be8895dd1130e6beb6f0bc508c9d022b51ef0ed8279cf46db2cfab729247.bin` |
| File type | `unknown` |
| First seen | `2026-08-13 01:43:53` |
| Reporter | `Tuxxin` |
| Tags | `jpg, stego, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `446e0f6180871eb59d26dfc6512f5bd6` |
| SHA-256 | `68a5be8895dd1130e6beb6f0bc508c9d022b51ef0ed8279cf46db2cfab729247` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_68a5be88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68a5be8895dd1130e6beb6f0bc508c9d022b51ef0ed8279cf46db2cfab729247"
    family = "unknown"
    file_name = "68a5be8895dd1130e6beb6f0bc508c9d022b51ef0ed8279cf46db2cfab729247.bin"
    file_type = "unknown"
    first_seen = "2026-08-13 01:43:53"
  condition:
    hash.sha256(0, filesize) == "68a5be8895dd1130e6beb6f0bc508c9d022b51ef0ed8279cf46db2cfab729247"
}
```

### Sample 30: `0ade487718f7253e`

| Field | Value |
|---|---|
| SHA-256 | `0ade487718f7253ecd1e325ad9adeb09701289999a05412e94a3a01c02e701b8` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-08-13 01:34:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9df68a27153fb6f1d937bc5a23cdc83a` |
| SHA-1 | `e259daeab5501a8e995ca501a345b9d8d161069a` |
| SHA-256 | `0ade487718f7253ecd1e325ad9adeb09701289999a05412e94a3a01c02e701b8` |
| SHA3-384 | `0eebf702226d14c7eed5c484895980c61aeec7c5f8362ffa53aed11ee3196b3346926f800be0584226fd11bbf4f8c301` |
| TLSH | `T186A3B81E6E219FADF768833047B78F31A75833D626E1D645E2ACD6101E6034E641FFA8` |
| TELFHASH | `t1f821a94c4a7423e497751c992aaeff77e1a030cf4a256e378e10e9ada6bd9825d00c1c` |
| SSDEEP | `1536:w1KMlrYXa1y4eSqPV1jP1NKyB5j6sbDGMv2UeZI971G7kB:UblrYXgy4O1j3KyB5j6sbKMv2+1OkB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_0ade4877
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ade487718f7253ecd1e325ad9adeb09701289999a05412e94a3a01c02e701b8"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-13 01:34:38"
  condition:
    hash.sha256(0, filesize) == "0ade487718f7253ecd1e325ad9adeb09701289999a05412e94a3a01c02e701b8"
}
```

### Sample 31: `8cfb9a33dd9e40f1`

| Field | Value |
|---|---|
| SHA-256 | `8cfb9a33dd9e40f1912c9332b91c3308e4a59883824dcfd900bc90c86ee7df9c` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-08-13 01:33:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `799364fc7130bdff64cff395ee5862dd` |
| SHA-1 | `0e565f3978e1a641db9ce3899017badff0d43542` |
| SHA-256 | `8cfb9a33dd9e40f1912c9332b91c3308e4a59883824dcfd900bc90c86ee7df9c` |
| SHA3-384 | `c8977dab15a03c92b7af7bb0b22ddce81b9bffabbe3febdec94c3a46079425e3ba3be732848909d2cbbc83baffba9315` |
| TLSH | `T1DE03E168410455DAD89ED3B91A9033F3682236676562DB063B43E3B1ACDB6C538D3FE0` |
| SSDEEP | `768:G3RmOA0oSbe3sZah9czhDf7Fb71c6CEPdaWsrGEoJgGlzDpbuR1Jw0:G3IO83ZYzhz7d7jcdGvVJuq0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_8cfb9a33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cfb9a33dd9e40f1912c9332b91c3308e4a59883824dcfd900bc90c86ee7df9c"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-13 01:33:56"
  condition:
    hash.sha256(0, filesize) == "8cfb9a33dd9e40f1912c9332b91c3308e4a59883824dcfd900bc90c86ee7df9c"
}
```

### Sample 32: `677613b506d73c2b`

| Field | Value |
|---|---|
| SHA-256 | `677613b506d73c2be470e60eda9ec4aece981468d382b23f2ed0f671656a84a6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-13 01:33:00` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28593603046302147d9e05011665ebd0` |
| SHA-1 | `cc08b84a18590d954a88aaf0844bdf44bde060f2` |
| SHA-256 | `677613b506d73c2be470e60eda9ec4aece981468d382b23f2ed0f671656a84a6` |
| SHA3-384 | `08217ac602c95773d174ce20e851d918d09f34601658e57f48148b084110b6b630ce73c82d0429dd571df42b8c3ec995` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1374407147CFE413EB063BFA27FD8A9EBDA9FE976664AA417104503078A00F90DF06579` |
| SSDEEP | `1536:foEKfhWHMKVE+uibpOXDmoXnkZnwYG5L9iEKfhWHMKVE+uibpOXDmoXnkZnwYG5K:f7vivfvivS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_677613b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "677613b506d73c2be470e60eda9ec4aece981468d382b23f2ed0f671656a84a6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-13 01:33:00"
  condition:
    hash.sha256(0, filesize) == "677613b506d73c2be470e60eda9ec4aece981468d382b23f2ed0f671656a84a6"
}
```

### Sample 33: `fffc7c1ca08e6cd9`

| Field | Value |
|---|---|
| SHA-256 | `fffc7c1ca08e6cd9b373e2ecb1b278caa6c4c1489bfa92577c53bcfa173b847a` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-08-13 01:32:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28ca801fb01550dadfd7bb0f5a08cc89` |
| SHA-1 | `86e00c0d68d21384187a7d3c8e38b4ff467ed1bf` |
| SHA-256 | `fffc7c1ca08e6cd9b373e2ecb1b278caa6c4c1489bfa92577c53bcfa173b847a` |
| SHA3-384 | `3358b077ea998ab6babb8ec6569f040656aa986948b60a92baf3094fa4d248a5a2acbce7ce431cc47adef0354ce723be` |
| TLSH | `T119F3AE97F70F20A0C82206F41BCB579D2A2361018F6B97E76C6E763E26765DF68063D1` |
| SSDEEP | `3072:HizgeqJAi9DvORuLsJgKAbo9ci9+6DPgyCRql19nzHXeq:Cz4JgusgPc9PkirCRql1leq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_fffc7c1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fffc7c1ca08e6cd9b373e2ecb1b278caa6c4c1489bfa92577c53bcfa173b847a"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-13 01:32:00"
  condition:
    hash.sha256(0, filesize) == "fffc7c1ca08e6cd9b373e2ecb1b278caa6c4c1489bfa92577c53bcfa173b847a"
}
```

### Sample 34: `4ffb7afc5a85fe8d`

| Field | Value |
|---|---|
| SHA-256 | `4ffb7afc5a85fe8d342ed584cce1579240124c74f11808ebb178d33da8c79779` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-13 01:29:54` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a64c683e7d79e9f81ae388cd0ba05173` |
| SHA-1 | `0304613134a48199b7e21153a05309c2e9fa896e` |
| SHA-256 | `4ffb7afc5a85fe8d342ed584cce1579240124c74f11808ebb178d33da8c79779` |
| SHA3-384 | `c0717c49bc64412d272bcce2881624a597fc3869ceea3a7c0b33fdfebbb5fd713239293a04cfc9aa93ee68c70d3b0f74` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T109B6339573A80499F07D5BF609730AE7AE31FCDB258A27CFD71982181EE32968131367` |
| SSDEEP | `196608:rcjsBvvKYTIw1+8cMKDhJUJw2srwxxio7oCLcRXuxzAH0hCOlZlPojVSD7GEJ:rfB6/wAMihgOrmiGov1W42COlMQD` |
| ICON-DHASH | `f8f0f0d4ccf07076` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_4ffb7afc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ffb7afc5a85fe8d342ed584cce1579240124c74f11808ebb178d33da8c79779"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-13 01:29:54"
  condition:
    hash.sha256(0, filesize) == "4ffb7afc5a85fe8d342ed584cce1579240124c74f11808ebb178d33da8c79779"
}
```

### Sample 35: `b571ac0a13a864f2`

| Field | Value |
|---|---|
| SHA-256 | `b571ac0a13a864f246d66f55ba310b9df8d0a71caf3c773d8e45e237305d0e6a` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-13 01:27:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fae4999a45200182fd615b31ed8956da` |
| SHA-1 | `5912f200cba4a2a2136b80e52e379ee2011b3ecf` |
| SHA-256 | `b571ac0a13a864f246d66f55ba310b9df8d0a71caf3c773d8e45e237305d0e6a` |
| SHA3-384 | `f78131744a263e1c96a56ba88e17de0ae0509415ea52fa4828ad6ccbb9e9254a0dfd547885de99664262167525d8f0da` |
| TLSH | `T11A0429C7FD00E9BAF80AE7374813041AB130B7A604825A377257357FED7A199157BE8A` |
| SSDEEP | `3072:hkLBevOaCih1i7uapFyTSRRyhhoJ4rNvJXgZubUV9jbibL/bBJ6lpVIeQ:hX/v6PyTKRyhho+rHGubJLFJ6GeQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_b571ac0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b571ac0a13a864f246d66f55ba310b9df8d0a71caf3c773d8e45e237305d0e6a"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-13 01:27:58"
  condition:
    hash.sha256(0, filesize) == "b571ac0a13a864f246d66f55ba310b9df8d0a71caf3c773d8e45e237305d0e6a"
}
```

### Sample 36: `1b3099234082a828`

| Field | Value |
|---|---|
| SHA-256 | `1b3099234082a8287e83b74e649826d495bf1d9e8ceea1c6766198e8f9376330` |
| Family label | `Mirai` |
| File name | `data_x86_64` |
| File type | `elf` |
| First seen | `2026-08-13 01:25:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe45f4a8d872ebf8316d161faeab5c48` |
| SHA-1 | `2e78d663364ebaf05e7d4b7a4a933c3a65306fe9` |
| SHA-256 | `1b3099234082a8287e83b74e649826d495bf1d9e8ceea1c6766198e8f9376330` |
| SHA3-384 | `aacfc3db4bf8cef523306a4f741b336de7442aab33cc8101558b22da0613575743575c2345ba2e772080db9513ff9b0e` |
| TLSH | `T1EC944A53F6A228FDD956C930825D6213F638744943126AFB27C8EB353E16AD06F3EB50` |
| TELFHASH | `t1e4b145b1418565b8e452e5e5ceb1e771d6b647e9c35039358a3cfcb1ef42fa8aa20c03` |
| SSDEEP | `6144:hRVvQvK/bAMnDtGGwoVUve/dXEpYJhY66cFAW5G+5GfPi64D3Nz8LOfBteTM2BBh:hrYiUGO21C6PawTv6ECLOfBwY4Q9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_1b309923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b3099234082a8287e83b74e649826d495bf1d9e8ceea1c6766198e8f9376330"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 01:25:59"
  condition:
    hash.sha256(0, filesize) == "1b3099234082a8287e83b74e649826d495bf1d9e8ceea1c6766198e8f9376330"
}
```

### Sample 37: `0b83f7746bdd2f76`

| Field | Value |
|---|---|
| SHA-256 | `0b83f7746bdd2f7633fdadc707fda9931d70915155ac1e4ba8300a311e5be6ba` |
| Family label | `unknown` |
| File name | `0b83f7746bdd2f7633fdadc707fda9931d70915155ac1e4ba8300a311e5be6ba.bin` |
| File type | `exe` |
| First seen | `2026-08-13 01:02:14` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `353e68846a55a9d49adaa2cdf4856ae7` |
| SHA-1 | `280bdbc983cdf9d36a5b4498c9d436c4dd7e6eaa` |
| SHA-256 | `0b83f7746bdd2f7633fdadc707fda9931d70915155ac1e4ba8300a311e5be6ba` |
| SHA3-384 | `4956d16c97b08bbc0e0cd472c3038e4b9deabe263209d8d991ebdcf2429a1fbb572bbeb5e11cc40a175f994f42abd958` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T149366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaN:uc3XND1aJrCOkN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_0b83f774
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b83f7746bdd2f7633fdadc707fda9931d70915155ac1e4ba8300a311e5be6ba"
    family = "unknown"
    file_name = "0b83f7746bdd2f7633fdadc707fda9931d70915155ac1e4ba8300a311e5be6ba.bin"
    file_type = "exe"
    first_seen = "2026-08-13 01:02:14"
  condition:
    hash.sha256(0, filesize) == "0b83f7746bdd2f7633fdadc707fda9931d70915155ac1e4ba8300a311e5be6ba"
}
```

### Sample 38: `ef09996dfdf27682`

| Field | Value |
|---|---|
| SHA-256 | `ef09996dfdf2768242a6aa4659a6c6262148cd98bd0882cdbfcc6c9e8a248764` |
| Family label | `unknown` |
| File name | `ef09996dfdf2768242a6aa4659a6c6262148cd98bd0882cdbfcc6c9e8a248764.bin` |
| File type | `exe` |
| First seen | `2026-08-13 01:02:12` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b73c1f3e91415b41389bac8939647f2` |
| SHA-1 | `502a0ba30ee590dd814e4f677daef1630c9a1138` |
| SHA-256 | `ef09996dfdf2768242a6aa4659a6c6262148cd98bd0882cdbfcc6c9e8a248764` |
| SHA3-384 | `9c1a45b911213beb31eb30443955221b4d365f5467ccd6d5b6990820b62942ce3bda7d2c485dc24ed0e05cf18409d591` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T196366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaq:uc3XND1aJrCOkq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_ef09996d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef09996dfdf2768242a6aa4659a6c6262148cd98bd0882cdbfcc6c9e8a248764"
    family = "unknown"
    file_name = "ef09996dfdf2768242a6aa4659a6c6262148cd98bd0882cdbfcc6c9e8a248764.bin"
    file_type = "exe"
    first_seen = "2026-08-13 01:02:12"
  condition:
    hash.sha256(0, filesize) == "ef09996dfdf2768242a6aa4659a6c6262148cd98bd0882cdbfcc6c9e8a248764"
}
```

### Sample 39: `4b12e723bb5cb1cb`

| Field | Value |
|---|---|
| SHA-256 | `4b12e723bb5cb1cb175aace0197386d417522fb467ae8e9fc53e980c8a0a13f8` |
| Family label | `unknown` |
| File name | `4b12e723bb5cb1cb175aace0197386d417522fb467ae8e9fc53e980c8a0a13f8.bin` |
| File type | `exe` |
| First seen | `2026-08-13 01:02:10` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9eac66030ec1bcc323f079213977cf2` |
| SHA-1 | `631fe08c4a42abb4a5555de9b371320fadf99c8c` |
| SHA-256 | `4b12e723bb5cb1cb175aace0197386d417522fb467ae8e9fc53e980c8a0a13f8` |
| SHA3-384 | `e5fc6318465aa05612afefd171869bee4f463f811e4c46995baefa61e51a9790bb098d26f282548e88468fe9db8acabf` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T180366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaai:uc3XND1aJrCOki` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_4b12e723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b12e723bb5cb1cb175aace0197386d417522fb467ae8e9fc53e980c8a0a13f8"
    family = "unknown"
    file_name = "4b12e723bb5cb1cb175aace0197386d417522fb467ae8e9fc53e980c8a0a13f8.bin"
    file_type = "exe"
    first_seen = "2026-08-13 01:02:10"
  condition:
    hash.sha256(0, filesize) == "4b12e723bb5cb1cb175aace0197386d417522fb467ae8e9fc53e980c8a0a13f8"
}
```

### Sample 40: `965fca6f4ab47b54`

| Field | Value |
|---|---|
| SHA-256 | `965fca6f4ab47b5479a701cfca3d1e8cc3bd1f1e00040105c16015e7e92144c7` |
| Family label | `unknown` |
| File name | `965fca6f4ab47b5479a701cfca3d1e8cc3bd1f1e00040105c16015e7e92144c7.bin` |
| File type | `exe` |
| First seen | `2026-08-13 01:02:08` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `233ffdbc23cff56464310919d02f39ad` |
| SHA-1 | `cb6a5d3fadca86e01b55fc828e513dc95e860a80` |
| SHA-256 | `965fca6f4ab47b5479a701cfca3d1e8cc3bd1f1e00040105c16015e7e92144c7` |
| SHA3-384 | `da689594856dace9fce4aed755d693c0f26b1e085dabeb3e9052575ff1c0b5ead48a3ce0d24845cbc0d4542245563f8b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B6366A03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaZ:uc3XND1aJrCOkZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_965fca6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "965fca6f4ab47b5479a701cfca3d1e8cc3bd1f1e00040105c16015e7e92144c7"
    family = "unknown"
    file_name = "965fca6f4ab47b5479a701cfca3d1e8cc3bd1f1e00040105c16015e7e92144c7.bin"
    file_type = "exe"
    first_seen = "2026-08-13 01:02:08"
  condition:
    hash.sha256(0, filesize) == "965fca6f4ab47b5479a701cfca3d1e8cc3bd1f1e00040105c16015e7e92144c7"
}
```

### Sample 41: `04168e3872a815ac`

| Field | Value |
|---|---|
| SHA-256 | `04168e3872a815ace4f4c59a787ef0d10782df4b2111d46d899b10eade942f80` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-13 01:00:51` |
| Reporter | `Bitsight` |
| Tags | `babki, CoinMiner, dropped-by-StealC, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f5d8c60ecc89e5caa14e45ae0c0e7dd` |
| SHA-1 | `f811f3cc27f9a18ba8e042ea725f41f6b8976baa` |
| SHA-256 | `04168e3872a815ace4f4c59a787ef0d10782df4b2111d46d899b10eade942f80` |
| SHA3-384 | `7e61332865c400d838025a21d210aa91a08838aa8d96fe8207b8a23f17be44a6dc7c65e5efe95dca704a156d0019c128` |
| IMPHASH | `3eaf5807ffab1e2f73dcc6c476f60324` |
| TLSH | `T1FE422A06AED98131E7F10DB105BA824B86BD3CB23F91EC9FA710F5462A757A0C471A7D` |
| SSDEEP | `192:PWeTbgOeHRikMIjleg7zK1FyJxTZ3lk9nAthB3NOk:OITGGIj0A+jyZK9nABsk` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_041_04168e38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04168e3872a815ace4f4c59a787ef0d10782df4b2111d46d899b10eade942f80"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-13 01:00:51"
  condition:
    hash.sha256(0, filesize) == "04168e3872a815ace4f4c59a787ef0d10782df4b2111d46d899b10eade942f80"
}
```

### Sample 42: `beb7b0d778dee883`

| Field | Value |
|---|---|
| SHA-256 | `beb7b0d778dee883735af6fcc0c11ea38d1f5f334f5a22f1b1047f244ba4de2b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-13 01:00:41` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01ab2877b3bc153f99bb2aa8e4fa6534` |
| SHA-1 | `e9341ec94be82638b5ac8513769215e0278b8970` |
| SHA-256 | `beb7b0d778dee883735af6fcc0c11ea38d1f5f334f5a22f1b1047f244ba4de2b` |
| SHA3-384 | `48b0ff7f7d9cb014db77b0b3d8cb5da6791d7a7adf74007bd5f2d233e0821c50008d623607862d8bc5f54692743bb782` |
| IMPHASH | `e6946be461c41a1fc69c37572d0c5975` |
| TLSH | `T10507C0BADB07169AC986827CC2C37524D735255163FD32CA8B909E750FA73999C3EEC0` |
| SSDEEP | `196608:hn9jDO23gNDcI3JHnHKx1ofrQRqImy3hEiW8mTo4IqhyP26oq:h9jDO23iAQJHHKqi1tqhyP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_beb7b0d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "beb7b0d778dee883735af6fcc0c11ea38d1f5f334f5a22f1b1047f244ba4de2b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-13 01:00:41"
  condition:
    hash.sha256(0, filesize) == "beb7b0d778dee883735af6fcc0c11ea38d1f5f334f5a22f1b1047f244ba4de2b"
}
```

### Sample 43: `158dcc5fd88c94f8`

| Field | Value |
|---|---|
| SHA-256 | `158dcc5fd88c94f8386ba99f0f77866200fc593f4b35755d357a33ec87fec298` |
| Family label | `DCRat` |
| File name | `05700e9fe7caa7ffbb63fccc4cff6179.exe` |
| File type | `exe` |
| First seen | `2026-08-13 00:50:07` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05700e9fe7caa7ffbb63fccc4cff6179` |
| SHA-1 | `f65f1c971886160a7ab7f706265c9326024f0157` |
| SHA-256 | `158dcc5fd88c94f8386ba99f0f77866200fc593f4b35755d357a33ec87fec298` |
| SHA3-384 | `f1e3984912676673f18b5066765ac1eadb16f5e0a64a897eb0313f64664a0700b53d56cf280ea38410cdb185764c7bdf` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15C05F9017E44CE91F0191673C1EF820847B4A9516AE6E72BBDAE337E55123A73C0E9DB` |
| SSDEEP | `12288:GLygb83qk14WSI5SUMEEokHmKcBhORXdv20hhGXPIrTHQmN84zx:Gv83zjSpUMEEokHm7+Jc0LG/zmN84t` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_043_158dcc5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "158dcc5fd88c94f8386ba99f0f77866200fc593f4b35755d357a33ec87fec298"
    family = "DCRat"
    file_name = "05700e9fe7caa7ffbb63fccc4cff6179.exe"
    file_type = "exe"
    first_seen = "2026-08-13 00:50:07"
  condition:
    hash.sha256(0, filesize) == "158dcc5fd88c94f8386ba99f0f77866200fc593f4b35755d357a33ec87fec298"
}
```

### Sample 44: `b5755fb03eae1c73`

| Field | Value |
|---|---|
| SHA-256 | `b5755fb03eae1c73b4ad2f417c1ca7d0ff09e27344cc7d5dbdfd4903d5d7429a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-13 00:47:42` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec3e697e43f35bc69ca8f677cc70e1d1` |
| SHA-256 | `b5755fb03eae1c73b4ad2f417c1ca7d0ff09e27344cc7d5dbdfd4903d5d7429a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_b5755fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5755fb03eae1c73b4ad2f417c1ca7d0ff09e27344cc7d5dbdfd4903d5d7429a"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-13 00:47:42"
  condition:
    hash.sha256(0, filesize) == "b5755fb03eae1c73b4ad2f417c1ca7d0ff09e27344cc7d5dbdfd4903d5d7429a"
}
```

### Sample 45: `967fceb5b057003c`

| Field | Value |
|---|---|
| SHA-256 | `967fceb5b057003cb398afc50a071ff55dd004e0b1088c80daf8146ef2caed78` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-12 23:52:35` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d39394efe3e231253b5730d4d6c5fb74` |
| SHA-1 | `aff63d875ed62ce9300ec2ccd236fddb34e4f99d` |
| SHA-256 | `967fceb5b057003cb398afc50a071ff55dd004e0b1088c80daf8146ef2caed78` |
| SHA3-384 | `d239e878c3759be4fe70a514fbdda3b02c6e63381febfb9c6587feb5ee077a975dc05d4179e7d667c5a1bbf5ff42e489` |
| IMPHASH | `976d2ad389e8b21847d44dfb70916b1f` |
| TLSH | `T1FFE6330E95D2339DE6B0623CFFA062E4F44879F65B32A2F75B68D2605CA31D06C3915B` |
| SSDEEP | `393216:evCERZ8MNtmWuREobXMCHWUj0cuI3/PGTAI:evTM8mNRbbXMb8hH/O7` |
| ICON-DHASH | `70f0e4c4c4e0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_967fceb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "967fceb5b057003cb398afc50a071ff55dd004e0b1088c80daf8146ef2caed78"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-12 23:52:35"
  condition:
    hash.sha256(0, filesize) == "967fceb5b057003cb398afc50a071ff55dd004e0b1088c80daf8146ef2caed78"
}
```

### Sample 46: `6c37df31d27e6bd1`

| Field | Value |
|---|---|
| SHA-256 | `6c37df31d27e6bd1baeb985ecaa4b9b3767b70076c9c7aa403b5c4f0e68fe0fd` |
| Family label | `unknown` |
| File name | `reportsaccs.exe` |
| File type | `exe` |
| First seen | `2026-08-12 23:28:08` |
| Reporter | `JaffaCakes118` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `427a8774a668af50e0023b34c244d979` |
| SHA-1 | `aa0e5a047e6e5b6937dc96d0fe5ef5d2f249c0ed` |
| SHA-256 | `6c37df31d27e6bd1baeb985ecaa4b9b3767b70076c9c7aa403b5c4f0e68fe0fd` |
| SHA3-384 | `7d74b65476200cf8efeb6cd4d196d62216be2f0b5c4cbd3ad853912f4e6bc57ebb2a70a4830e59ef32acae4790eb53e8` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T189173376A3E548F2F8E397314A03859477777C981730E8DB43A09AA52C771E83A359B3` |
| SSDEEP | `393216:h85vzd2aoEeJ0LohVEHCYFqAONLuC9hHTodRGkXMkVtbmvq2AAvd6:W5vzd21nbhVEHCYFqfSCX0LhXMiyvFv` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_6c37df31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c37df31d27e6bd1baeb985ecaa4b9b3767b70076c9c7aa403b5c4f0e68fe0fd"
    family = "unknown"
    file_name = "reportsaccs.exe"
    file_type = "exe"
    first_seen = "2026-08-12 23:28:08"
  condition:
    hash.sha256(0, filesize) == "6c37df31d27e6bd1baeb985ecaa4b9b3767b70076c9c7aa403b5c4f0e68fe0fd"
}
```

### Sample 47: `ed2a78cca6457504`

| Field | Value |
|---|---|
| SHA-256 | `ed2a78cca645750490acdd56cf1a819967d669bf1a2f13bbef44b9d7ce1db61f` |
| Family label | `WannaCry` |
| File name | `ed2a78cca645750490acdd56cf1a819967d669bf1a2f13bbef44b9d7ce1db61f` |
| File type | `exe` |
| First seen | `2026-08-12 23:15:57` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `469f0e42341e9d6caeed17669c8bfed2` |
| SHA-1 | `ac3aea578e9af171fb80ffb6b7421b72d2bda308` |
| SHA-256 | `ed2a78cca645750490acdd56cf1a819967d669bf1a2f13bbef44b9d7ce1db61f` |
| SHA3-384 | `239eca8d87f870bcfdfe6f2e877c2788223a2eb7e7f755b2400f8e847203eef718bf456190f5662e8966d170b9edc6f5` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T15536BF01D9E41B54D6B28BB6A97B8710537A7E848D57970E0358A02A1C33F1CDEE2FED` |
| SSDEEP | `49152:jnXnAQqMSPbcBVQej/1INGx+TSqTdX1HkQo6SAA:DXDqPoBhz1aGxcSUDk36SA` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_047_ed2a78cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed2a78cca645750490acdd56cf1a819967d669bf1a2f13bbef44b9d7ce1db61f"
    family = "WannaCry"
    file_name = "ed2a78cca645750490acdd56cf1a819967d669bf1a2f13bbef44b9d7ce1db61f"
    file_type = "exe"
    first_seen = "2026-08-12 23:15:57"
  condition:
    hash.sha256(0, filesize) == "ed2a78cca645750490acdd56cf1a819967d669bf1a2f13bbef44b9d7ce1db61f"
}
```

### Sample 48: `edc2b90996347cf8`

| Field | Value |
|---|---|
| SHA-256 | `edc2b90996347cf8ebffb8befe24b96a2a3a6e489b9e02768315f8f7a3c07cbe` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-12 22:51:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff57b6dcabb6bd7521a97b39e56a7e2d` |
| SHA-1 | `d8019f00461aab6406144476fc1684c6babee7ba` |
| SHA-256 | `edc2b90996347cf8ebffb8befe24b96a2a3a6e489b9e02768315f8f7a3c07cbe` |
| SHA3-384 | `7205f234bb8e17b822f5b14e63ce07b1159469495e9549114ffe194823e1690b9608fff650da66e5b5e376f00e787eca` |
| TLSH | `T14A94B54A6E228F7DF67887348BF70A30D76D23D613E1D584E1ACD1151E2424EA91FBAC` |
| TELFHASH | `t1d891afe7387917a4aa984c8d46dced208c931cef2aa61c27df91d48ed717b836f11c18` |
| SSDEEP | `6144:gvZBbY6i/JCNVGly8wzgFpdZZWxpe1bqhYFgp8TzMRw5RJLm+BX6:6ud3diRaX6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_edc2b909
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edc2b90996347cf8ebffb8befe24b96a2a3a6e489b9e02768315f8f7a3c07cbe"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-12 22:51:06"
  condition:
    hash.sha256(0, filesize) == "edc2b90996347cf8ebffb8befe24b96a2a3a6e489b9e02768315f8f7a3c07cbe"
}
```

### Sample 49: `7fc40677a79d0cbc`

| Field | Value |
|---|---|
| SHA-256 | `7fc40677a79d0cbc675d8c0042d6cfbc87ca1a9982f5046008feb7bd4fe799b9` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-12 22:51:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60612f788bb18bb1bc13ee569181fe0a` |
| SHA-1 | `b70fd63661d766420d24e48b6cb1eb7d72f403bf` |
| SHA-256 | `7fc40677a79d0cbc675d8c0042d6cfbc87ca1a9982f5046008feb7bd4fe799b9` |
| SHA3-384 | `9a35b0d8038757b0350ac7466e76972510bd9bbc32767a2abd8c30643d10c7d09f470180b303bedcec0ba7bab0406977` |
| TLSH | `T1CD542966BD819B95D5D12ABFFF5E824933172BBCE2EE3102DD145F2137CA84A0E7A101` |
| SSDEEP | `6144:FNpw17tZpsC0PKhnz/Fnd7Kc1r+Ewhoe0aGnD7U6tOLyPBumfJO+7:FstZpsC0ChnzJd5yhhoe0a+D7U6tVZl/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_7fc40677
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fc40677a79d0cbc675d8c0042d6cfbc87ca1a9982f5046008feb7bd4fe799b9"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-12 22:51:05"
  condition:
    hash.sha256(0, filesize) == "7fc40677a79d0cbc675d8c0042d6cfbc87ca1a9982f5046008feb7bd4fe799b9"
}
```

### Sample 50: `01c70849ed30aa1c`

| Field | Value |
|---|---|
| SHA-256 | `01c70849ed30aa1cc4e08cb7529b62c2e3a9044ad0ab000ad84a343444a8dd5a` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-12 22:51:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ffac7731469e5a5269cdae564208b3e` |
| SHA-1 | `20919124a409125dd6093ab6a8b866886d5af98a` |
| SHA-256 | `01c70849ed30aa1cc4e08cb7529b62c2e3a9044ad0ab000ad84a343444a8dd5a` |
| SHA3-384 | `9dc1d1b52bb753045e90ef28ff46d6beee64acf62b5504a385ab1c72a361fffa46746e286b35db950b89626ecc116ad3` |
| TLSH | `T1CE640765BD418BA6C6C15ABBFF5E838C732B17ADD2EE3103DD155F21379A84A0E3A101` |
| SSDEEP | `6144:aZHYotUWejARUS73O7pttpaJyiziVQI+Iy/2JrQA/fTMJ4/MOcqCCFp1R3X:aZHYotUWejAP7UpttEJ1iVQI+ILQJ4EO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_01c70849
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01c70849ed30aa1cc4e08cb7529b62c2e3a9044ad0ab000ad84a343444a8dd5a"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-12 22:51:03"
  condition:
    hash.sha256(0, filesize) == "01c70849ed30aa1cc4e08cb7529b62c2e3a9044ad0ab000ad84a343444a8dd5a"
}
```

### Sample 51: `b595ef9ca4756a07`

| Field | Value |
|---|---|
| SHA-256 | `b595ef9ca4756a07bc83027a943009cb947d03c4c261a3e4cc3bec467b43c203` |
| Family label | `Mirai` |
| File name | `2778ce` |
| File type | `elf` |
| First seen | `2026-08-12 22:49:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4dd7c86ed52e9af1f0ecc8fcd27f100` |
| SHA-1 | `d6f0f4430e73254482e8057f60b4649f040c3ff0` |
| SHA-256 | `b595ef9ca4756a07bc83027a943009cb947d03c4c261a3e4cc3bec467b43c203` |
| SHA3-384 | `f7e3b5a85aa60473bb8d77e1eb62b4a07ef5d01094dcf90091d9491262f00946f0defeed59524afbacb132fbd347ca29` |
| TLSH | `T11C13F881BC929A26C6E4237AFA6E52CD336177A8C2DF3617CC215F407B8951F0D7BA41` |
| TELFHASH | `t1abe02644ad728a2c88d39ab4ed8803e49513631a550b4b20df60d6e0d43f408e218e0a` |
| SSDEEP | `768:FCsBGLm5TEDXJJRVYPCVUQkhBZtbg3XIlwquk0hLpMq6TUCpm3e+4r8ov+W5PNp:cVm5oTEYU4FqubUB6e+COWt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_b595ef9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b595ef9ca4756a07bc83027a943009cb947d03c4c261a3e4cc3bec467b43c203"
    family = "Mirai"
    file_name = "2778ce"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:09"
  condition:
    hash.sha256(0, filesize) == "b595ef9ca4756a07bc83027a943009cb947d03c4c261a3e4cc3bec467b43c203"
}
```

### Sample 52: `5c502903694591a2`

| Field | Value |
|---|---|
| SHA-256 | `5c502903694591a219ca263247c4c159967c5838c9a85641f3fb908b983d1e32` |
| Family label | `Mirai` |
| File name | `341d04` |
| File type | `elf` |
| First seen | `2026-08-12 22:49:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f3f383f55b374c22904e4fe5e1a218d` |
| SHA-1 | `c65ebb643e64d641a61cb3b5b9cd5781c965a544` |
| SHA-256 | `5c502903694591a219ca263247c4c159967c5838c9a85641f3fb908b983d1e32` |
| SHA3-384 | `8c249c55ee48aaaf190ac2bae4692c9d4c66b1b5f0025c4d49ea6f9daa94de35c99976cf434923e610632d07d4f277ae` |
| TLSH | `T11963A60A3E628FFCFB6D873447B79E319698339226E1D545E15CEA011E7030E645FBA8` |
| TELFHASH | `t169014918453813f093814dde6becff35e4b145efaa216e338e40e99aab215468d00c2c` |
| SSDEEP | `1536:rXXpOKyD100rKDrRpRbYrsQVGwal5KhxiK:9OjDO5rBbqVGvuhYK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_5c502903
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c502903694591a219ca263247c4c159967c5838c9a85641f3fb908b983d1e32"
    family = "Mirai"
    file_name = "341d04"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:08"
  condition:
    hash.sha256(0, filesize) == "5c502903694591a219ca263247c4c159967c5838c9a85641f3fb908b983d1e32"
}
```

### Sample 53: `a75a98641037e42a`

| Field | Value |
|---|---|
| SHA-256 | `a75a98641037e42abb4c543d90e81dafdae3b27e90972b705a2e9242a5bee123` |
| Family label | `Mirai` |
| File name | `085175` |
| File type | `elf` |
| First seen | `2026-08-12 22:49:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a4ff1180c94cb3fdb654dffe8e0a8f3` |
| SHA-1 | `0b9d90367fac224fa9ad29ef1f35cb8e22e776a4` |
| SHA-256 | `a75a98641037e42abb4c543d90e81dafdae3b27e90972b705a2e9242a5bee123` |
| SHA3-384 | `8151a20a2634bf7ac8835a70f37019bcfb3f0389ba2471270f15f7ed7f42d9a1e37922b629691e02681b44aa515787af` |
| TLSH | `T1C163830ABF210FB7EC6BCC3749E51B46359C640B21A93B3A7934D818F60B65B59F3864` |
| SSDEEP | `768:ijdCpewyFRfBrqH7HDXzFtIxCxseI5mVeqe32eCg4lDx0h00Xiqkr25/q0N:4dCpewORCPhMHXK7u2Zwud25iU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_a75a9864
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a75a98641037e42abb4c543d90e81dafdae3b27e90972b705a2e9242a5bee123"
    family = "Mirai"
    file_name = "085175"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:06"
  condition:
    hash.sha256(0, filesize) == "a75a98641037e42abb4c543d90e81dafdae3b27e90972b705a2e9242a5bee123"
}
```

### Sample 54: `41ac975aa0638b87`

| Field | Value |
|---|---|
| SHA-256 | `41ac975aa0638b879bade9f672fbcdacb303bc6ceb5e92083b85af9cd440cd04` |
| Family label | `Mirai` |
| File name | `f971dc` |
| File type | `elf` |
| First seen | `2026-08-12 22:49:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29d7b20380beabca5148b32f28d00610` |
| SHA-1 | `1cd405c9d057a51cc5bb21a5f79a3cbc288bd9df` |
| SHA-256 | `41ac975aa0638b879bade9f672fbcdacb303bc6ceb5e92083b85af9cd440cd04` |
| SHA3-384 | `ae0af880a83cc522627164fa1c697a56fb4ea158089ddf11f081bb105076dc67362c1e1f6837e17d55ba143490c67814` |
| TLSH | `T1BE237D7AC82D6EC4C55C96786829CABC0B53E104C5A31FF647D6C9A644C3EACFA193F4` |
| SSDEEP | `768:clelZlh+PwtBBRN9eCUCyGekpSplC1l2jWqxxGwCnoO1uCh:cISPwtB39p4plCSWUxT3OuCh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_41ac975a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41ac975aa0638b879bade9f672fbcdacb303bc6ceb5e92083b85af9cd440cd04"
    family = "Mirai"
    file_name = "f971dc"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:05"
  condition:
    hash.sha256(0, filesize) == "41ac975aa0638b879bade9f672fbcdacb303bc6ceb5e92083b85af9cd440cd04"
}
```

### Sample 55: `383819dd8c7df607`

| Field | Value |
|---|---|
| SHA-256 | `383819dd8c7df6077d193ace66715d7b3e5d82e0de0ad87ef8a783965786d606` |
| Family label | `Mirai` |
| File name | `bfde3b` |
| File type | `elf` |
| First seen | `2026-08-12 22:49:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01f089f522d2df28bc08f62a7f124503` |
| SHA-1 | `03123a6d9159b9ce4a3bbd64dc250f891ef18e8f` |
| SHA-256 | `383819dd8c7df6077d193ace66715d7b3e5d82e0de0ad87ef8a783965786d606` |
| SHA3-384 | `e0a419633d210610d8473845a4728455d506e57c5c5e106f8c6e81e7e2ffde8a820cec0769f7aee38904b9092c080157` |
| TLSH | `T1B4C32A46EB818B13C4D5177ABAAF42493323E764D3DB730699185FB43F86B9E0E63502` |
| TELFHASH | `t127217cf1472a55245659cfdc9ed9a3aa022dc2161387df33ee11c4aca01a09de535d4f` |
| SSDEEP | `3072:LiIF6cHuKUq4hezpywr6pyYxO9z8IsIM/9D:LJF6cHRUq4wzpywr+yrzPhM/9D` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_383819dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "383819dd8c7df6077d193ace66715d7b3e5d82e0de0ad87ef8a783965786d606"
    family = "Mirai"
    file_name = "bfde3b"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:03"
  condition:
    hash.sha256(0, filesize) == "383819dd8c7df6077d193ace66715d7b3e5d82e0de0ad87ef8a783965786d606"
}
```

### Sample 56: `bf0aabf517685756`

| Field | Value |
|---|---|
| SHA-256 | `bf0aabf517685756f16b22f4b1907113a1cd160fa7b5ee384cb554b42b311841` |
| Family label | `Mirai` |
| File name | `068f87` |
| File type | `elf` |
| First seen | `2026-08-12 22:49:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db2e8aa26d8d625d934d2011e492a938` |
| SHA-1 | `87a7b0368697ba112498f54ef0d413449181d7e6` |
| SHA-256 | `bf0aabf517685756f16b22f4b1907113a1cd160fa7b5ee384cb554b42b311841` |
| SHA3-384 | `0db916e635ec99643b1b571d9a7d63fc7a68426c4446ede78101d54c35559ab063e0c6f79958fab267167db5b1168442` |
| TLSH | `T132330713B98180FCC08AC2740B7FB53AD43775BE0239B2A97FD8FA166A86E211E1D545` |
| TELFHASH | `t104114579b59f08c4b1fbf622b39ae0624d600bb021d039e3c4316dbdda62782097503a` |
| SSDEEP | `768:FP7iHSUqwdNtcBLl/I5wlmNZHqvYtWFMEA5gQjDwIcUjdWZP:J2qwdjcBLlQ5wlmnHqeWFUCYkka` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_bf0aabf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf0aabf517685756f16b22f4b1907113a1cd160fa7b5ee384cb554b42b311841"
    family = "Mirai"
    file_name = "068f87"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:02"
  condition:
    hash.sha256(0, filesize) == "bf0aabf517685756f16b22f4b1907113a1cd160fa7b5ee384cb554b42b311841"
}
```

### Sample 57: `3b2f2f02077aee3e`

| Field | Value |
|---|---|
| SHA-256 | `3b2f2f02077aee3efe6dcca1bb84afc59af14fff78d1b6dd18aed0c24e08a313` |
| Family label | `Mirai` |
| File name | `5b5f1c` |
| File type | `elf` |
| First seen | `2026-08-12 22:49:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f1b2dcf7e6f4f2d5b9ef723b3fd402b` |
| SHA-1 | `799df7d1265c2a2098f20a3919f4c267d2c6669d` |
| SHA-256 | `3b2f2f02077aee3efe6dcca1bb84afc59af14fff78d1b6dd18aed0c24e08a313` |
| SHA3-384 | `f2bf1e636423ae801ff7996d99ed5213bd97cba988d526bbbcffdee09d49b84f398afb733ec6112a9abfad744c57b2d0` |
| TLSH | `T10353F856BC818A15C5D413BAFE2E118D33236778E2EF7212DE105F25778A96F0E7B902` |
| TELFHASH | `t1f3f0dc21ce8c4f8c83a148a9621a8112178a30f016253a868f7a2f8f0a49da9f07a432` |
| SSDEEP | `1536:gVnYeZUNim04yCN1sA1XyyEgWqUQVdDi1TxdEuwms:eucR4tPsiXyZg8TxdEnj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_3b2f2f02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b2f2f02077aee3efe6dcca1bb84afc59af14fff78d1b6dd18aed0c24e08a313"
    family = "Mirai"
    file_name = "5b5f1c"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:01"
  condition:
    hash.sha256(0, filesize) == "3b2f2f02077aee3efe6dcca1bb84afc59af14fff78d1b6dd18aed0c24e08a313"
}
```

### Sample 58: `8bdbe21eafc7223a`

| Field | Value |
|---|---|
| SHA-256 | `8bdbe21eafc7223a75ea9d075237d389e0c39f6370721f1ea36214989e5bab63` |
| Family label | `Mirai` |
| File name | `ec54e5` |
| File type | `elf` |
| First seen | `2026-08-12 22:49:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `295f3d71940f224699357163405d9553` |
| SHA-1 | `73445dcaff640d213ca811cb07c6062ffed5696c` |
| SHA-256 | `8bdbe21eafc7223a75ea9d075237d389e0c39f6370721f1ea36214989e5bab63` |
| SHA3-384 | `93b504ade060e94b338f1fce898b6b8fb04019431eaa5afbec3261e07f12a63389d19d8ed7a8b03fc2a573904780614f` |
| TLSH | `T14033F881BC929612C5E423B7FA6E42CD332563A4D2EF3213DD222F11779A92F0D7B651` |
| TELFHASH | `t1de31cc929e5c0b8c7fe0834567ca62a5dadc31f89300672e9e2d975b02839a0b31b437` |
| SSDEEP | `768:nciTxwAAo7758yVIoEavixJYrrxVglC/qWgpCmAAUS3L+adZnLWM4ZQoNkaPNOPG:ciTxOYsaRgpFjHLWMk8I` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_8bdbe21e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bdbe21eafc7223a75ea9d075237d389e0c39f6370721f1ea36214989e5bab63"
    family = "Mirai"
    file_name = "ec54e5"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:00"
  condition:
    hash.sha256(0, filesize) == "8bdbe21eafc7223a75ea9d075237d389e0c39f6370721f1ea36214989e5bab63"
}
```

### Sample 59: `abda6887930f4e2e`

| Field | Value |
|---|---|
| SHA-256 | `abda6887930f4e2e1047b39adf23bbf8bdee9e15c7e2101245bb690be7d80488` |
| Family label | `Mirai` |
| File name | `126678` |
| File type | `elf` |
| First seen | `2026-08-12 22:48:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94616e9e1bcfe15409d598b2f03cec63` |
| SHA-1 | `8079652d1192a3029c4333dcfb907cf647f00b13` |
| SHA-256 | `abda6887930f4e2e1047b39adf23bbf8bdee9e15c7e2101245bb690be7d80488` |
| SHA3-384 | `3c2aea2222b4e210e2abf764d71e68d68faba6376024b1e02cda583def64e44cfead94ea5e87bb72834ead8a2332d981` |
| TLSH | `T1DD333A2179392A17C4D0B87A61F74768B2F5474F25A8CB1E7E730E4EFF20690A117AB4` |
| SSDEEP | `1536:K17qMS5ZuIYB8lB7u25aqUvqAy3Qh0tYy:533wsRW0yy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_abda6887
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abda6887930f4e2e1047b39adf23bbf8bdee9e15c7e2101245bb690be7d80488"
    family = "Mirai"
    file_name = "126678"
    file_type = "elf"
    first_seen = "2026-08-12 22:48:58"
  condition:
    hash.sha256(0, filesize) == "abda6887930f4e2e1047b39adf23bbf8bdee9e15c7e2101245bb690be7d80488"
}
```

### Sample 60: `9c719ba3b1cd4a8c`

| Field | Value |
|---|---|
| SHA-256 | `9c719ba3b1cd4a8cf820c5eaea04aae7d0188da53e75f18f9c04c1fbbd3cc97e` |
| Family label | `Mirai` |
| File name | `b59af2` |
| File type | `elf` |
| First seen | `2026-08-12 22:48:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e93dcf769aa814e7eda82b271e731d88` |
| SHA-1 | `700dbdb75e2f401432d777eb65705ca35a7a7c32` |
| SHA-256 | `9c719ba3b1cd4a8cf820c5eaea04aae7d0188da53e75f18f9c04c1fbbd3cc97e` |
| SHA3-384 | `7861e56eb76e4c0ccf528cf3be7b30e081f05d5750c2c6dd2e224a594a9c2f78b21435b600c6ff2e576dc21808a92a96` |
| TLSH | `T11A234AC4A947EDF8EC1607B5213BF7365BF6F037212CDD8BC39899239953A02960629D` |
| TELFHASH | `t1e51191bf1eb60ef8f7d4a440c31916e2187ac52b0aa466e905721c9476e1dd09579c3a` |
| SSDEEP | `768:DnrKxZUimqDS4mtQEE5PTrvC0BmIDKSOjO+xEmi6Xa+/xliMezd2Xc:zufVDpmtQH5PTrvC0BmIDuzxEmpayx8b` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_9c719ba3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c719ba3b1cd4a8cf820c5eaea04aae7d0188da53e75f18f9c04c1fbbd3cc97e"
    family = "Mirai"
    file_name = "b59af2"
    file_type = "elf"
    first_seen = "2026-08-12 22:48:57"
  condition:
    hash.sha256(0, filesize) == "9c719ba3b1cd4a8cf820c5eaea04aae7d0188da53e75f18f9c04c1fbbd3cc97e"
}
```

### Sample 61: `9d44d4d051f6aa3f`

| Field | Value |
|---|---|
| SHA-256 | `9d44d4d051f6aa3fbc95fab0aae818347a602d655fa7f1fba6267e728d7ff2d3` |
| Family label | `Mirai` |
| File name | `659716` |
| File type | `elf` |
| First seen | `2026-08-12 22:48:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `530413ffda3e9ff04a66d5af3e4f8ecf` |
| SHA-1 | `2d61924572d0b2b283d61faaa25b8461d8ccfd85` |
| SHA-256 | `9d44d4d051f6aa3fbc95fab0aae818347a602d655fa7f1fba6267e728d7ff2d3` |
| SHA3-384 | `fe0a4d77f273ae6c9772ff49a81184bb3920772cd32a99d932e7ad52918d70982122b09835aeddab8016ee7779070fc7` |
| TLSH | `T15A233D42361C0947D1A62AF0393F67E0D3FFA9A020F4B588291F9B5A8579E771186FCD` |
| SSDEEP | `768:71uHSE37Msvla/1q0LvozQY1bfRXo1+Uottl+heWQR18kXQ8h:71uyCM/1q0LveBLFrrWQj8kAq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_9d44d4d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d44d4d051f6aa3fbc95fab0aae818347a602d655fa7f1fba6267e728d7ff2d3"
    family = "Mirai"
    file_name = "659716"
    file_type = "elf"
    first_seen = "2026-08-12 22:48:56"
  condition:
    hash.sha256(0, filesize) == "9d44d4d051f6aa3fbc95fab0aae818347a602d655fa7f1fba6267e728d7ff2d3"
}
```

### Sample 62: `3366350561c41f5d`

| Field | Value |
|---|---|
| SHA-256 | `3366350561c41f5d15994244bfd7358ca256d16a1e954d7a986bd4d2d50c895e` |
| Family label | `Mirai` |
| File name | `3f9c7b` |
| File type | `elf` |
| First seen | `2026-08-12 22:48:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55e59bfde3760e798bc3ccba0f814ee5` |
| SHA-1 | `f3d7f35f862912437c6eed21791d468e6fb54d45` |
| SHA-256 | `3366350561c41f5d15994244bfd7358ca256d16a1e954d7a986bd4d2d50c895e` |
| SHA3-384 | `f6f9e0057c695ce8f81504ba66533cb3722c9ca39c5278a2d2fa36a5e674dfb8e795f7a5fc6a25489f1bcfba3942c902` |
| TLSH | `T1FC332ADAB8019D7CF80FEBBE84534909F525775554830F2767ABFCA3AC722548E22D82` |
| SSDEEP | `768:do/6VviAP+dsOD3aewluHNw3G78Twi1n2jwahfTF7PSB8rHE:doCVq86pnwKNk28TN1EwahLF7PG8rk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_33663505
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3366350561c41f5d15994244bfd7358ca256d16a1e954d7a986bd4d2d50c895e"
    family = "Mirai"
    file_name = "3f9c7b"
    file_type = "elf"
    first_seen = "2026-08-12 22:48:55"
  condition:
    hash.sha256(0, filesize) == "3366350561c41f5d15994244bfd7358ca256d16a1e954d7a986bd4d2d50c895e"
}
```

### Sample 63: `1ec25086be7fa291`

| Field | Value |
|---|---|
| SHA-256 | `1ec25086be7fa2918db0f591bff7417190bec288ec668b8dce53950134c886a4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-12 22:45:38` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02cb1b2082c1b208ac67d96cd235b495` |
| SHA-1 | `0a2f4f54f396c74cf01bb57f45a2133ea94bb754` |
| SHA-256 | `1ec25086be7fa2918db0f591bff7417190bec288ec668b8dce53950134c886a4` |
| SHA3-384 | `b6175eee9039e25ef50a9e62c91bc9e10e81ec6f25329d32d8ace679c0f20a4dc0c0d216223d4f6f49a34d6865807eab` |
| IMPHASH | `91a6a6f60534f1893d8b6695452d5b75` |
| TLSH | `T13BD522033F04A955C45A2A71D9B1C7BC6731FD59AE96939B34D2BE0BFECAAC21C491C0` |
| SSDEEP | `49152:JHGKzG1Jjn9dmbQrf4y1I+r87N+VhodAoObsjiALX2c4GIN94A3mZjwuCC:p/zG1JzbmAI+g7N+VhoWY2ST+9tm9Rh` |
| ICON-DHASH | `54b279e8c8696900` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_1ec25086
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ec25086be7fa2918db0f591bff7417190bec288ec668b8dce53950134c886a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-12 22:45:38"
  condition:
    hash.sha256(0, filesize) == "1ec25086be7fa2918db0f591bff7417190bec288ec668b8dce53950134c886a4"
}
```

### Sample 64: `afc9662bbe72c217`

| Field | Value |
|---|---|
| SHA-256 | `afc9662bbe72c2171342431d5f13ea9ce5cd3b61006524061061399628b5970d` |
| Family label | `Vidar` |
| File name | `afc9662bbe72c2171342431d5f13ea9ce5cd3b61006524061061399628b5970d.bin` |
| File type | `exe` |
| First seen | `2026-08-12 22:30:59` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dc7769dd69352fcc6f47d640cf78c7a` |
| SHA-1 | `d7daf7212610cff6e413e018c12355cc109dc5c0` |
| SHA-256 | `afc9662bbe72c2171342431d5f13ea9ce5cd3b61006524061061399628b5970d` |
| SHA3-384 | `149134317d9420390ee3242f8d203bc2d194aea09cb00a760dfc9d01d16f4521f2bd9fa10c594b7a379f403193064a7f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C1267B07BEA108F9C1AAE33589AB4212BB74BC4D4B3233D32E50AA782F727D15D75754` |
| SSDEEP | `49152:yoHVmHat/2n9oeLgDkF+9tRoH0NM18wlX2NhAbcsqZTUaP6jc:yGf489+18wlX2/ocsqZP` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_064_afc9662b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afc9662bbe72c2171342431d5f13ea9ce5cd3b61006524061061399628b5970d"
    family = "Vidar"
    file_name = "afc9662bbe72c2171342431d5f13ea9ce5cd3b61006524061061399628b5970d.bin"
    file_type = "exe"
    first_seen = "2026-08-12 22:30:59"
  condition:
    hash.sha256(0, filesize) == "afc9662bbe72c2171342431d5f13ea9ce5cd3b61006524061061399628b5970d"
}
```

### Sample 65: `2f0c7deae88b0985`

| Field | Value |
|---|---|
| SHA-256 | `2f0c7deae88b098583f9c6333a32d54b846fb684f5013bd7f93cac53642b71df` |
| Family label | `unknown` |
| File name | `2f0c7deae88b098583f9c6333a32d54b846fb684f5013bd7f93cac53642b71df.bin` |
| File type | `exe` |
| First seen | `2026-08-12 22:30:57` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52231938f6bf4d6db6f788b4c5abb44d` |
| SHA-1 | `1a6ee8fd48c85140dffaaf0dae95943a4fe67c98` |
| SHA-256 | `2f0c7deae88b098583f9c6333a32d54b846fb684f5013bd7f93cac53642b71df` |
| SHA3-384 | `3a11b10e4665cd3225e8a65bfad68498e6fc3f97e7ceb800aa1bc53be2cdaec04a949112d226d2ee6a6f670a6aa28409` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A4568C03EC9158EAC1DAA23189A79213BB71BC495B3223D72FA0B7782F727D05D79714` |
| SSDEEP | `49152:l3THB/zHQ3prolxyDqwusovdQIIQWio3etaLehe2ooX5GZlUqUZSOpfBeZKcK9K1:lTZyuvdtINMK2oo4lUq7EfXEn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_2f0c7dea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f0c7deae88b098583f9c6333a32d54b846fb684f5013bd7f93cac53642b71df"
    family = "unknown"
    file_name = "2f0c7deae88b098583f9c6333a32d54b846fb684f5013bd7f93cac53642b71df.bin"
    file_type = "exe"
    first_seen = "2026-08-12 22:30:57"
  condition:
    hash.sha256(0, filesize) == "2f0c7deae88b098583f9c6333a32d54b846fb684f5013bd7f93cac53642b71df"
}
```

### Sample 66: `d2a74301bdf3c50d`

| Field | Value |
|---|---|
| SHA-256 | `d2a74301bdf3c50d57a5a08aacf69b26fdf32fe9a8a4dd299a3d73125ce4f73f` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-12 22:28:43` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef4c9e9473853e02e7056c338d535388` |
| SHA-1 | `279a06088b51a4c42009c0ae09720ceb96e2387a` |
| SHA-256 | `d2a74301bdf3c50d57a5a08aacf69b26fdf32fe9a8a4dd299a3d73125ce4f73f` |
| SHA3-384 | `af1514ff8a7b40764188645633e44546f87623281adcaceb3c6a06cad2380d503cd9d03634bb900773a88217cc6fec95` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T19006BE07BCA009F6D0AAA33688B366617B71BC044B3627D72EA1B7382F367D05C75725` |
| SSDEEP | `49152:Ry8G7L5ss+nkxGe3ocsPLHOab1ARcNTZp1/6yr7N+qaS2CCZWTT:RyP7ww3pa5hlZiyrI9S` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_d2a74301
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2a74301bdf3c50d57a5a08aacf69b26fdf32fe9a8a4dd299a3d73125ce4f73f"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-12 22:28:43"
  condition:
    hash.sha256(0, filesize) == "d2a74301bdf3c50d57a5a08aacf69b26fdf32fe9a8a4dd299a3d73125ce4f73f"
}
```

### Sample 67: `71613db242e2659d`

| Field | Value |
|---|---|
| SHA-256 | `71613db242e2659dec7a3ce13b56367dfde705758f66a140baf24907bcc8ade7` |
| Family label | `Mirai` |
| File name | `data_arm7` |
| File type | `elf` |
| First seen | `2026-08-12 22:26:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9b88d387e82c59a331368298f96cdf6` |
| SHA-1 | `24f354b866e48b7220a0bed1f233b896a64bc982` |
| SHA-256 | `71613db242e2659dec7a3ce13b56367dfde705758f66a140baf24907bcc8ade7` |
| SHA3-384 | `9bb3bdb3077ba8d95f26cc9df28ee08fe25820d4059bf8831844301e114fbfa75e634ad5be5ea8098d3258439b68b28f` |
| TLSH | `T176F31856BA519F12D5C321FAFB9E814933136FB8E3F971029D206F60278B89B0F76502` |
| TELFHASH | `t1723120605f551dfd7be4c051c1eda529f7a030d93b143c52c9be9b1e5e538d2302840a` |
| SSDEEP | `3072:cCnNFd0HNN4Oeb1JiDtpRMtLJcyRhaHqCKy+oI1mHpzZ1BtFWbogfm/:cUNFeHNNfCJiDxWJhhaHqCKy+oIkHpXR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_71613db2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71613db242e2659dec7a3ce13b56367dfde705758f66a140baf24907bcc8ade7"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-08-12 22:26:57"
  condition:
    hash.sha256(0, filesize) == "71613db242e2659dec7a3ce13b56367dfde705758f66a140baf24907bcc8ade7"
}
```

### Sample 68: `8e57f52d19952b76`

| Field | Value |
|---|---|
| SHA-256 | `8e57f52d19952b761b82a28b528705df1e3d607b4d317bc3d96f1a27f8242d72` |
| Family label | `unknown` |
| File name | `8e57f52d19952b761b82a28b528705df1e3d607b4d317bc3d96f1a27f8242d72.exe` |
| File type | `exe` |
| First seen | `2026-08-12 22:24:03` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `256a2c7e8913d763a6510f561dbed7a1` |
| SHA-1 | `c52a152e2a5b150936c6ac7d723f2883f043c5b2` |
| SHA-256 | `8e57f52d19952b761b82a28b528705df1e3d607b4d317bc3d96f1a27f8242d72` |
| SHA3-384 | `fdbd9f9a05db13c6a114f57465fb6efb8a6eb4657225b8b8ecfec4c023d167f84635630237e1405ce841aad3684b980f` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T157D5239A7CF358B4D07AC3318FD3E8AD71693B8587614E9B36CC5D409D228889C7A778` |
| SSDEEP | `49152:TFWXPM677rPksxo+2Dw7POzuhSlu8s8gk7ZJeSA6Qr2/FE9aIHuBDw9dfLZY:TOPX77nxo+TPOzuauz8gk7ZJM2/FEOmo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_8e57f52d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e57f52d19952b761b82a28b528705df1e3d607b4d317bc3d96f1a27f8242d72"
    family = "unknown"
    file_name = "8e57f52d19952b761b82a28b528705df1e3d607b4d317bc3d96f1a27f8242d72.exe"
    file_type = "exe"
    first_seen = "2026-08-12 22:24:03"
  condition:
    hash.sha256(0, filesize) == "8e57f52d19952b761b82a28b528705df1e3d607b4d317bc3d96f1a27f8242d72"
}
```

### Sample 69: `d0294a7caf27f11e`

| Field | Value |
|---|---|
| SHA-256 | `d0294a7caf27f11e40af507cafa5627b65b5096b5cf9926a31d5cba0993fc1da` |
| Family label | `CoinMiner` |
| File name | `d0294a7caf27f11e40af507cafa5627b65b5096b5cf9926a31d5cba0993fc1da.exe` |
| File type | `exe` |
| First seen | `2026-08-12 22:23:57` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8ae197268f46a6e5b443532aef82c52` |
| SHA-1 | `31ab8fe40bb4f1d8f069ae2494b6c8050f954037` |
| SHA-256 | `d0294a7caf27f11e40af507cafa5627b65b5096b5cf9926a31d5cba0993fc1da` |
| SHA3-384 | `5c7c339212b623f30297001baa7de5567cb94134d674ab0a42b671ba6bc6519fecb4e50e48253f7652594ae034f9a289` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1073633D62DD241B6C49AC7F8825326FDF13B3F4449617E5FBACC2A044AA6A08853D7C7` |
| SSDEEP | `98304:jgwqmLds22oRmNglYOIUz+yLx2SyxLvaYNb8drpISrwWDsz:j6022NqW9B+yLxXyx1Nb8FlD` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_069_d0294a7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0294a7caf27f11e40af507cafa5627b65b5096b5cf9926a31d5cba0993fc1da"
    family = "CoinMiner"
    file_name = "d0294a7caf27f11e40af507cafa5627b65b5096b5cf9926a31d5cba0993fc1da.exe"
    file_type = "exe"
    first_seen = "2026-08-12 22:23:57"
  condition:
    hash.sha256(0, filesize) == "d0294a7caf27f11e40af507cafa5627b65b5096b5cf9926a31d5cba0993fc1da"
}
```

### Sample 70: `4339a4bf8be2b5e3`

| Field | Value |
|---|---|
| SHA-256 | `4339a4bf8be2b5e32f6ed2c644b9bf1181ac25b336e0ed5198c808098279d27e` |
| Family label | `Vidar` |
| File name | `4339a4bf8be2b5e32f6ed2c644b9bf1181ac25b336e0ed5198c808098279d27e.bin` |
| File type | `exe` |
| First seen | `2026-08-12 22:00:42` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44826cadb848eddd3550c0269fa2ad4d` |
| SHA-1 | `4468fa2b9975b4b7570f947f36829ae549edabee` |
| SHA-256 | `4339a4bf8be2b5e32f6ed2c644b9bf1181ac25b336e0ed5198c808098279d27e` |
| SHA3-384 | `91b8611950dc01e9bdf77bb395d2589ea2d2a8ac4b1d7f12e7b0fc1a59ff7bbdab6ca800697ff433808d6c778e41d89c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T176567B13EC9119EAC19AA331C8A79252BB757C885B3223D36FA0B7782F727D06D74750` |
| SSDEEP | `98304:2vbvfbyXEZ/BdymAzGZyJ8/LRYq/dSfUEM:2SXEZ5dKQRDSFM` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_070_4339a4bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4339a4bf8be2b5e32f6ed2c644b9bf1181ac25b336e0ed5198c808098279d27e"
    family = "Vidar"
    file_name = "4339a4bf8be2b5e32f6ed2c644b9bf1181ac25b336e0ed5198c808098279d27e.bin"
    file_type = "exe"
    first_seen = "2026-08-12 22:00:42"
  condition:
    hash.sha256(0, filesize) == "4339a4bf8be2b5e32f6ed2c644b9bf1181ac25b336e0ed5198c808098279d27e"
}
```

### Sample 71: `af60ac5b44bd1e03`

| Field | Value |
|---|---|
| SHA-256 | `af60ac5b44bd1e03ee564d33c1da963db85b4f73b05f6820a8f2a57c4e73efd4` |
| Family label | `unknown` |
| File name | `af60ac5b44bd1e03ee564d33c1da963db85b4f73b05f6820a8f2a57c4e73efd4.bin` |
| File type | `exe` |
| First seen | `2026-08-12 22:00:39` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `380bd9d291ceddb3592d5afaf72f425b` |
| SHA-1 | `9fee2ddadc31cd71ca887f0caf1a15e9eabb45d6` |
| SHA-256 | `af60ac5b44bd1e03ee564d33c1da963db85b4f73b05f6820a8f2a57c4e73efd4` |
| SHA3-384 | `95cd18dd6705cc00466459e08a4b8634e7930da3ed0a55ba6690d7d23fbb371cdfde3fdef4330e4af322755b5aa949d7` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T14D568B13EC9109E5C19AE23189A79252BB74BC495B3223D32FA0B7783F727C0AE75754` |
| SSDEEP | `49152:X5IFiliFwzHYi7GD5X3yiJ78BWm5UTGEa9xyAdWvLTLC2JQEUBe8KcK9KlESxEaW:XGEsXiiN8sbjaOcWvLTLCUyJEd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_af60ac5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af60ac5b44bd1e03ee564d33c1da963db85b4f73b05f6820a8f2a57c4e73efd4"
    family = "unknown"
    file_name = "af60ac5b44bd1e03ee564d33c1da963db85b4f73b05f6820a8f2a57c4e73efd4.bin"
    file_type = "exe"
    first_seen = "2026-08-12 22:00:39"
  condition:
    hash.sha256(0, filesize) == "af60ac5b44bd1e03ee564d33c1da963db85b4f73b05f6820a8f2a57c4e73efd4"
}
```

### Sample 72: `9cc1484aaeefb46f`

| Field | Value |
|---|---|
| SHA-256 | `9cc1484aaeefb46feb49edf79bd0c0f2a82eadbe630a7c1937bf7c4b0bd87e35` |
| Family label | `unknown` |
| File name | `9cc1484aaeefb46feb49edf79bd0c0f2a82eadbe630a7c1937bf7c4b0bd87e35.bin` |
| File type | `exe` |
| First seen | `2026-08-12 22:00:37` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbf4167c8684449858268bf36d2049a3` |
| SHA-1 | `fd044a41ba47c934bcfba111b61f1a18ca1b4d78` |
| SHA-256 | `9cc1484aaeefb46feb49edf79bd0c0f2a82eadbe630a7c1937bf7c4b0bd87e35` |
| SHA3-384 | `ecbbc0d95571bb664e6b74c5e6f474eb857be590075d4d85ba7e90be656af3b988265fb9a3c64760e9f266a8475d8a51` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D9267B07BEA108F9C1AAE33589AB4212BB74BC4D4B3233D32E50AA782F727D15D75754` |
| SSDEEP | `49152:yoHVmHat/2n9oeLgDkF+9tRoH0NM18wlX2NhAbcsqZTUaP6jc:yGf489+18wlX2/ocsqZP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_9cc1484a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cc1484aaeefb46feb49edf79bd0c0f2a82eadbe630a7c1937bf7c4b0bd87e35"
    family = "unknown"
    file_name = "9cc1484aaeefb46feb49edf79bd0c0f2a82eadbe630a7c1937bf7c4b0bd87e35.bin"
    file_type = "exe"
    first_seen = "2026-08-12 22:00:37"
  condition:
    hash.sha256(0, filesize) == "9cc1484aaeefb46feb49edf79bd0c0f2a82eadbe630a7c1937bf7c4b0bd87e35"
}
```

### Sample 73: `fcde17b95346c7a4`

| Field | Value |
|---|---|
| SHA-256 | `fcde17b95346c7a44de2de0ce663e5e9a4dc9af982e11b10538385892428748b` |
| Family label | `unknown` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-08-12 21:52:31` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f91c88dcd2def8e468162054063034e` |
| SHA-1 | `01bf757daa6ffff30366ff4c8dfe3cd0f64e33bc` |
| SHA-256 | `fcde17b95346c7a44de2de0ce663e5e9a4dc9af982e11b10538385892428748b` |
| SHA3-384 | `c82e3f6c850e5875236159ab394542bed940ce4a7f4bd064d3a28ce38827bd0e239e1b47d2acd6879d1e6cc9e286248d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B0F59E07BCA149F6D09AA33289B35651BB70BC484B3527D72E90BB382F727C05D7AB15` |
| SSDEEP | `49152:iudlwuSAECqSSkbYCK0dcsPLHBF/zU9X4mkCxWXy:iun83IxUX4mhP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_fcde17b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcde17b95346c7a44de2de0ce663e5e9a4dc9af982e11b10538385892428748b"
    family = "unknown"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-12 21:52:31"
  condition:
    hash.sha256(0, filesize) == "fcde17b95346c7a44de2de0ce663e5e9a4dc9af982e11b10538385892428748b"
}
```

### Sample 74: `b38fda4a414a530a`

| Field | Value |
|---|---|
| SHA-256 | `b38fda4a414a530a9ffeb9ecf6b1ef05453cd1d62033efc8f89b1d307af3552b` |
| Family label | `unknown` |
| File name | `Schet_Akt_1842_v2.iso` |
| File type | `iso` |
| First seen | `2026-08-12 21:50:47` |
| Reporter | `skocherhan` |
| Tags | `93-152-223-39, iso, opendir` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cf5eb2f3d384f27394889efee17ddd8` |
| SHA-1 | `3af37cece00250ebb06456a5b6050bb0cf386adf` |
| SHA-256 | `b38fda4a414a530a9ffeb9ecf6b1ef05453cd1d62033efc8f89b1d307af3552b` |
| SHA3-384 | `66ee22bd616e28e7081ad18e84e59f7bf2570f2d496632cbd97435963032bd85ec02292e719a1e567e0cc4137056e726` |
| TLSH | `T1176321041FD11229D7F2CB3A6CF6B62196B3F440E6B18F6E319E50680F93A01A965F7D` |
| SSDEEP | `48:5OMvBGCecjqpuf4c0yNK5UTbWJePjWgI3aQ:5gCecu8fDY5/JiWg0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_b38fda4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b38fda4a414a530a9ffeb9ecf6b1ef05453cd1d62033efc8f89b1d307af3552b"
    family = "unknown"
    file_name = "Schet_Akt_1842_v2.iso"
    file_type = "iso"
    first_seen = "2026-08-12 21:50:47"
  condition:
    hash.sha256(0, filesize) == "b38fda4a414a530a9ffeb9ecf6b1ef05453cd1d62033efc8f89b1d307af3552b"
}
```

### Sample 75: `1b151dd1b1ca6365`

| Field | Value |
|---|---|
| SHA-256 | `1b151dd1b1ca636550029602ee88eae182a4143fef630a608647f4b027051a9a` |
| Family label | `Havoc` |
| File name | `view.ps1` |
| File type | `ps1` |
| First seen | `2026-08-12 21:48:57` |
| Reporter | `skocherhan` |
| Tags | `93-152-223-39, Havoc, opendir, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aab85d7018c9401dca0b45a0cc8e30e1` |
| SHA-1 | `bd17b9e101a0a7b813cd068f08b0a1a422de36b7` |
| SHA-256 | `1b151dd1b1ca636550029602ee88eae182a4143fef630a608647f4b027051a9a` |
| SHA3-384 | `b41cd769b3870ebdaf1216b0b77959c8475a2704a7e69c060a41a73b7420f294c7c10fa4f4bede07c47b4b7d5aebeb86` |
| TLSH | `T1D921D72333088E6803168191717C38E3DEB4C2FAB8B00814A5D179C825BEFE2305C78B` |
| SSDEEP | `24:PSmb7FFj1K2cYEHp2Owxs4H3WdyuSp2p8xs4H3vV3E0suep2nSC+Gh6/xCMpXR0X:P7r1KHHlmIPSG6SwvkNpheX` |

#### Technical Assessment

- The sample is tracked as `Havoc` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Havoc_075_1b151dd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b151dd1b1ca636550029602ee88eae182a4143fef630a608647f4b027051a9a"
    family = "Havoc"
    file_name = "view.ps1"
    file_type = "ps1"
    first_seen = "2026-08-12 21:48:57"
  condition:
    hash.sha256(0, filesize) == "1b151dd1b1ca636550029602ee88eae182a4143fef630a608647f4b027051a9a"
}
```

### Sample 76: `f8b0b7e53c36cf41`

| Field | Value |
|---|---|
| SHA-256 | `f8b0b7e53c36cf4147526f692eca5bf98aa7206f13990c02b9270e04c341e5c0` |
| Family label | `unknown` |
| File name | `pisos.bin` |
| File type | `unknown` |
| First seen | `2026-08-12 21:48:09` |
| Reporter | `skocherhan` |
| Tags | `93-152-223-39, opendir` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `984441faad02c83c2e89af88de800ce8` |
| SHA-256 | `f8b0b7e53c36cf4147526f692eca5bf98aa7206f13990c02b9270e04c341e5c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_f8b0b7e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b0b7e53c36cf4147526f692eca5bf98aa7206f13990c02b9270e04c341e5c0"
    family = "unknown"
    file_name = "pisos.bin"
    file_type = "unknown"
    first_seen = "2026-08-12 21:48:09"
  condition:
    hash.sha256(0, filesize) == "f8b0b7e53c36cf4147526f692eca5bf98aa7206f13990c02b9270e04c341e5c0"
}
```

### Sample 77: `e3fbe466054844db`

| Field | Value |
|---|---|
| SHA-256 | `e3fbe466054844db78527a099d11a4e9d12c40a4bd9add4bef9faea10a902eae` |
| Family label | `unknown` |
| File name | `Schet_Akt_1842.docx` |
| File type | `doc` |
| First seen | `2026-08-12 21:46:51` |
| Reporter | `skocherhan` |
| Tags | `93-152-223-39, doc, opendir` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce9ce3395ca1e410b7949d9160b8905c` |
| SHA-1 | `214f8a07827b6c51e1922f1a94735ea0633c6c53` |
| SHA-256 | `e3fbe466054844db78527a099d11a4e9d12c40a4bd9add4bef9faea10a902eae` |
| SHA3-384 | `4fa50e686615633f0f7180cf83a9a9b595ac879a20453d05fb6ce0f5ffdee3cc7a8ba126a19b4c300682b75053fd56ce` |
| TLSH | `T10003E025CD275071E0B7BA32EE1E4D90F2594B54C1D17B7B382F829990B3B4EED5B205` |
| SSDEEP | `768:ZAWFnm7rdW8Rhej2aCRWrY/CGD5uLiNTKUU2vqYfoZ4C:Lm7rZHIwr/CGD5uLmdU2iB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `doc`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_e3fbe466
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3fbe466054844db78527a099d11a4e9d12c40a4bd9add4bef9faea10a902eae"
    family = "unknown"
    file_name = "Schet_Akt_1842.docx"
    file_type = "doc"
    first_seen = "2026-08-12 21:46:51"
  condition:
    hash.sha256(0, filesize) == "e3fbe466054844db78527a099d11a4e9d12c40a4bd9add4bef9faea10a902eae"
}
```

### Sample 78: `524266500e8341c5`

| Field | Value |
|---|---|
| SHA-256 | `524266500e8341c5c20a548d1f96c55b3696422e761a9c22044f60254d777a8b` |
| Family label | `unknown` |
| File name | `Advanced_IP_Scanner_2.5.4594.3.exe` |
| File type | `exe` |
| First seen | `2026-08-12 21:34:22` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01530f5d652b62efc9e1191dfc117c9a` |
| SHA-1 | `e92aa2866df95cca5e40748611f90a8aaf0c2591` |
| SHA-256 | `524266500e8341c5c20a548d1f96c55b3696422e761a9c22044f60254d777a8b` |
| SHA3-384 | `e99a3781a459a09871a9e6a39e1f14900f4e2689c03a29db415e3c603bfbfa0b8cdbf723bf577abef381d92951e9041a` |
| IMPHASH | `4b9cdada3652e5e29db9b5b5ac8e325a` |
| TLSH | `T14C872369A6BD00E6E86A8178C2865227D730BD5517F017CB5E64B6FA0F73BD02E7E340` |
| SSDEEP | `786432:r9uwkhCHvFpmSpkIES+y7Th9mT97S7CzNwWCJK05IRTX+F3:r9uwkhCHXXkIESHR987S+pwW+NF3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_52426650
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "524266500e8341c5c20a548d1f96c55b3696422e761a9c22044f60254d777a8b"
    family = "unknown"
    file_name = "Advanced_IP_Scanner_2.5.4594.3.exe"
    file_type = "exe"
    first_seen = "2026-08-12 21:34:22"
  condition:
    hash.sha256(0, filesize) == "524266500e8341c5c20a548d1f96c55b3696422e761a9c22044f60254d777a8b"
}
```

### Sample 79: `752816328ef0c903`

| Field | Value |
|---|---|
| SHA-256 | `752816328ef0c903baea78bc49a1aa8047f248758d91d4c903bad82546706d97` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-12 21:30:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `127c16645484d777a5794866aae0777e` |
| SHA-1 | `d1eb5eab9f8e345103f95665d6a336ec9028cd03` |
| SHA-256 | `752816328ef0c903baea78bc49a1aa8047f248758d91d4c903bad82546706d97` |
| SHA3-384 | `acf61d97c58487a0a57946f418356be0bfbc97d6451ea7d2fc22b99a419465d253d1954373700d8688e31f943dd9fa44` |
| TLSH | `T15C14961E6E329F7EF268C73447B74A34976D23D623E1D684D2ACC1101E6035E685FBA8` |
| TELFHASH | `t1ec41b2180db813b0a6395d5d05ddfb27d6a331df7e262c238e11e85aab69b439d10c0c` |
| SSDEEP | `3072:soaRqWNvWjNUy8yAFJ0qcqEwwZSEkXXNpEVZQq9xvUimhJEhUzHlIS:soaRqWNed8yAsEtG/xXYJEuRR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_75281632
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "752816328ef0c903baea78bc49a1aa8047f248758d91d4c903bad82546706d97"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-12 21:30:59"
  condition:
    hash.sha256(0, filesize) == "752816328ef0c903baea78bc49a1aa8047f248758d91d4c903bad82546706d97"
}
```

### Sample 80: `91b2d597575f7400`

| Field | Value |
|---|---|
| SHA-256 | `91b2d597575f74009b8502c77279761cea8635606e7ca1fd146fb1a4a3127785` |
| Family label | `Vidar` |
| File name | `91b2d597575f74009b8502c77279761cea8635606e7ca1fd146fb1a4a3127785.bin` |
| File type | `exe` |
| First seen | `2026-08-12 21:30:22` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9c064c8839561510fd48495aaba5e6c` |
| SHA-1 | `a887ca3f33c97a52abd352b8266c9559f0de7885` |
| SHA-256 | `91b2d597575f74009b8502c77279761cea8635606e7ca1fd146fb1a4a3127785` |
| SHA3-384 | `ad89f09d2752bd2823da291ce4f9a04193a1f0fe7a5844b4cd18bb52eeb4c7db3c3abc44d1fe03d1503be1b33792168c` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1A3765B0BA9515CB5C09AF63184BA4247FB707CBD573263D72E90BA782F763C16A38316` |
| SSDEEP | `49152:qYOcEhGogLzwpw4GXr4k8dvGNjB1UPOhNElfw9V+Ea5ELwPm82Xf3INVG3YPTV+E:q868XN8BGelfw9UEMPm82kXr/tvF` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_080_91b2d597
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91b2d597575f74009b8502c77279761cea8635606e7ca1fd146fb1a4a3127785"
    family = "Vidar"
    file_name = "91b2d597575f74009b8502c77279761cea8635606e7ca1fd146fb1a4a3127785.bin"
    file_type = "exe"
    first_seen = "2026-08-12 21:30:22"
  condition:
    hash.sha256(0, filesize) == "91b2d597575f74009b8502c77279761cea8635606e7ca1fd146fb1a4a3127785"
}
```

### Sample 81: `68ef1df7c303a460`

| Field | Value |
|---|---|
| SHA-256 | `68ef1df7c303a4600df13103cbb093cd11e59775b39f5dbe391a28394191b45f` |
| Family label | `unknown` |
| File name | `68ef1df7c303a4600df13103cbb093cd11e59775b39f5dbe391a28394191b45f.bin` |
| File type | `exe` |
| First seen | `2026-08-12 21:30:20` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c617b419fb4f659ceebf1d102e382d37` |
| SHA-1 | `41d684a76082e5c22c759e5c370be512d5f44a1b` |
| SHA-256 | `68ef1df7c303a4600df13103cbb093cd11e59775b39f5dbe391a28394191b45f` |
| SHA3-384 | `a83d4b41ed5901387a120070a19e9a5ef6838b4ecbf367906fc580d56952c2614bfdff76daf3743608a43113112cc922` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T10C368C03DA6646A1C15B9B3145B642117AB9FC98873437F73EB0B7312F6A7E11ABCB04` |
| SSDEEP | `98304:fSAIHV9EyqZZfcyd/0NSH+9uFX+6nkKqd:fS1kZZhtBaG6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_68ef1df7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68ef1df7c303a4600df13103cbb093cd11e59775b39f5dbe391a28394191b45f"
    family = "unknown"
    file_name = "68ef1df7c303a4600df13103cbb093cd11e59775b39f5dbe391a28394191b45f.bin"
    file_type = "exe"
    first_seen = "2026-08-12 21:30:20"
  condition:
    hash.sha256(0, filesize) == "68ef1df7c303a4600df13103cbb093cd11e59775b39f5dbe391a28394191b45f"
}
```

### Sample 82: `b218bc6125777b17`

| Field | Value |
|---|---|
| SHA-256 | `b218bc6125777b170bbefe4f0e761c94232d8ca6ae4ce9cb7b40124a72ba2cb4` |
| Family label | `Vidar` |
| File name | `b218bc6125777b170bbefe4f0e761c94232d8ca6ae4ce9cb7b40124a72ba2cb4.bin` |
| File type | `exe` |
| First seen | `2026-08-12 21:30:17` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1e6fe5bfba717dd0423048c79f83cc5` |
| SHA-1 | `73ce4ca45d072aaf298d1668c407dee63249d06a` |
| SHA-256 | `b218bc6125777b170bbefe4f0e761c94232d8ca6ae4ce9cb7b40124a72ba2cb4` |
| SHA3-384 | `03cd2866bb8c069f2fac8351f6568192d0501454355c66637eb92a15b472a5d642aae04f66e335d4626098dca8159a9c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T15C567C13EC9219E9C1DAA63189678253BB71BC884B3223D72FA0B7782F727D06D75750` |
| SSDEEP | `49152:88vBAeiWm9NggDOjt1s9LqEPc2Unj98Q2smsj/GOrVEiWi3kBeVKcK9Ke4UEa5Er:8SAPuU9+Ek2Ej9usV/GQVudlEr` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_082_b218bc61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b218bc6125777b170bbefe4f0e761c94232d8ca6ae4ce9cb7b40124a72ba2cb4"
    family = "Vidar"
    file_name = "b218bc6125777b170bbefe4f0e761c94232d8ca6ae4ce9cb7b40124a72ba2cb4.bin"
    file_type = "exe"
    first_seen = "2026-08-12 21:30:17"
  condition:
    hash.sha256(0, filesize) == "b218bc6125777b170bbefe4f0e761c94232d8ca6ae4ce9cb7b40124a72ba2cb4"
}
```

### Sample 83: `db16dd04af5c8c11`

| Field | Value |
|---|---|
| SHA-256 | `db16dd04af5c8c11941a314ddf0810a153e4f95e95477dadc9f6f35acf34c629` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-08-12 21:20:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aba834f454985151bf015d673fcdd056` |
| SHA-1 | `9811782a93ef4d70472562ddc751536e05c4bc3a` |
| SHA-256 | `db16dd04af5c8c11941a314ddf0810a153e4f95e95477dadc9f6f35acf34c629` |
| SHA3-384 | `763731bdae96e7652113d8b0c93dd807f738183a051b87f8ff21eae42a0c7c75bf697543eb72cce7664ac2bb1164d498` |
| TLSH | `T149E31945FD458F17C6C326BBFB4E428C7B261768D3EE710389256F60379B96A0E3A142` |
| TELFHASH | `t17c210e82df580bacf7c4074480dd3102eaa83aca3977ac55db49eb9a0153cd0b02a017` |
| SSDEEP | `3072:nRe39nzVoceUWEEGuJQwfIwnnoi+2O4IdZllDZchCKUSMVPHy:Re39nzVNwLKwfIwnJ+/4MdqhCKUSAa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_db16dd04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db16dd04af5c8c11941a314ddf0810a153e4f95e95477dadc9f6f35acf34c629"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-12 21:20:57"
  condition:
    hash.sha256(0, filesize) == "db16dd04af5c8c11941a314ddf0810a153e4f95e95477dadc9f6f35acf34c629"
}
```

### Sample 84: `6fd1c8e3daedfe0f`

| Field | Value |
|---|---|
| SHA-256 | `6fd1c8e3daedfe0ff0c6ec7e4f0bf4d085cdb17b0230f13b6d33496785a9c9cb` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-12 21:14:55` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5fb6ab87d9d2e0fd02008f29597cf4b` |
| SHA-1 | `e1af6b59a3661aee0bb8087a59a283da39a23119` |
| SHA-256 | `6fd1c8e3daedfe0ff0c6ec7e4f0bf4d085cdb17b0230f13b6d33496785a9c9cb` |
| SHA3-384 | `4fd1bb5964dbf60d2cdc567aca89ff9cdf6f4c0a34f61d240fa5ecfe50f26a4873279b0933361350edf8e0167c485392` |
| TLSH | `T11DC26D956A867C44BEC94A3E4CBE2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:t8vCB+25j6es8Ri9FYpMSUpi+20qUpi+20YQX:t8l25JEd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_6fd1c8e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fd1c8e3daedfe0ff0c6ec7e4f0bf4d085cdb17b0230f13b6d33496785a9c9cb"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-12 21:14:55"
  condition:
    hash.sha256(0, filesize) == "6fd1c8e3daedfe0ff0c6ec7e4f0bf4d085cdb17b0230f13b6d33496785a9c9cb"
}
```

### Sample 85: `cb68c082c22d3f27`

| Field | Value |
|---|---|
| SHA-256 | `cb68c082c22d3f2751ded48b1fa24d079ef1378bb7352353634b2ccb6985c44e` |
| Family label | `unknown` |
| File name | `cb68c082c22d3f2751ded48b1fa24d079ef1378bb7352353634b2ccb6985c44e.bin` |
| File type | `exe` |
| First seen | `2026-08-12 20:59:58` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ef82d7bb436b700b32fb0cb0e3b64df` |
| SHA-1 | `9e3fcc975bf699ab362838794c21211b4c6129de` |
| SHA-256 | `cb68c082c22d3f2751ded48b1fa24d079ef1378bb7352353634b2ccb6985c44e` |
| SHA3-384 | `9ebc3685fac4e47b6a6c7d162ed4d37fed2db0e90d409381ae9ca4caa2c047fad9799e7025b4f86d5c3a3712b38d2ce8` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1FE866B07EA529DB6C4A6E63185A64247AB74BC3C873263D31EB1B2783F767E05E34314` |
| SSDEEP | `196608:CKLyXZS7gvPKLjpqQ7mNuaQWDzc1rO7M8+mkOUpEE9IBrdAL+NFv5EAoHr:CKLZ7gvPKLjpqQ7mNuaQAzc1rO7M8+mq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_cb68c082
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb68c082c22d3f2751ded48b1fa24d079ef1378bb7352353634b2ccb6985c44e"
    family = "unknown"
    file_name = "cb68c082c22d3f2751ded48b1fa24d079ef1378bb7352353634b2ccb6985c44e.bin"
    file_type = "exe"
    first_seen = "2026-08-12 20:59:58"
  condition:
    hash.sha256(0, filesize) == "cb68c082c22d3f2751ded48b1fa24d079ef1378bb7352353634b2ccb6985c44e"
}
```

### Sample 86: `2e7dc6d8f996729e`

| Field | Value |
|---|---|
| SHA-256 | `2e7dc6d8f996729e1091bc4886d5baaf3a7a36f8f45617e1ef9101fb5ec778e5` |
| Family label | `unknown` |
| File name | `2e7dc6d8f996729e1091bc4886d5baaf3a7a36f8f45617e1ef9101fb5ec778e5.bin` |
| File type | `exe` |
| First seen | `2026-08-12 20:59:56` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89a8e4baede7381f4da5441d0ba25cd7` |
| SHA-1 | `06b382f0e785ff4e38b39672f26423e24a53e3a2` |
| SHA-256 | `2e7dc6d8f996729e1091bc4886d5baaf3a7a36f8f45617e1ef9101fb5ec778e5` |
| SHA3-384 | `74c24e98092cce772e59cfa13b48fdddde92bb74dbe8560537a900ef9125e66a69fb39e11d4499042eaf0f0689af9e0b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B5567C07FC9159E5C09AB23189A79212BB75BC480B3227D72FA0B7782F727D06E79750` |
| SSDEEP | `49152:25gZbLbbN6pX8VWwzP/WAakctg1TMMOAU1ZNNmizCJrhQ47XPdT+1L4ulW0BeJKi:2yRTW/tQYpzzoy4TPdT+yoW0YEe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_2e7dc6d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e7dc6d8f996729e1091bc4886d5baaf3a7a36f8f45617e1ef9101fb5ec778e5"
    family = "unknown"
    file_name = "2e7dc6d8f996729e1091bc4886d5baaf3a7a36f8f45617e1ef9101fb5ec778e5.bin"
    file_type = "exe"
    first_seen = "2026-08-12 20:59:56"
  condition:
    hash.sha256(0, filesize) == "2e7dc6d8f996729e1091bc4886d5baaf3a7a36f8f45617e1ef9101fb5ec778e5"
}
```

### Sample 87: `124c9272f0721515`

| Field | Value |
|---|---|
| SHA-256 | `124c9272f072151529a74124a04fb27b1890a37c2149242eeab006d6244d61bf` |
| Family label | `Vidar` |
| File name | `124c9272f072151529a74124a04fb27b1890a37c2149242eeab006d6244d61bf.bin` |
| File type | `exe` |
| First seen | `2026-08-12 20:59:54` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e24641b93f8f73a01bf6946c0b44448` |
| SHA-1 | `3f518413fd15acccf819a9f19888d4ec898315bf` |
| SHA-256 | `124c9272f072151529a74124a04fb27b1890a37c2149242eeab006d6244d61bf` |
| SHA3-384 | `22b4d38db19de10909502f824bdb383ab38769eb8526a657b8f8b032843c3afe252b5f52f09f0d6709032f7a43d625e6` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T14B56590BBB610578C495EB74C8B682557A787C8C873173E31D90AA782F663E19D3EB07` |
| SSDEEP | `49152:AaA1keR1q9yw+LShQsdaqt9ln6NR0/bsZ2pH0UquQxzoXd30ab5QoT/s0iWSfZxQ:AqBhOBe02rkvBNqtocIPG` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_087_124c9272
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "124c9272f072151529a74124a04fb27b1890a37c2149242eeab006d6244d61bf"
    family = "Vidar"
    file_name = "124c9272f072151529a74124a04fb27b1890a37c2149242eeab006d6244d61bf.bin"
    file_type = "exe"
    first_seen = "2026-08-12 20:59:54"
  condition:
    hash.sha256(0, filesize) == "124c9272f072151529a74124a04fb27b1890a37c2149242eeab006d6244d61bf"
}
```

### Sample 88: `71883121b2f9a24a`

| Field | Value |
|---|---|
| SHA-256 | `71883121b2f9a24a74c37974317962160b3af5bd1146d8ae8307c3d28c75a2e8` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-12 20:52:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdaa5df2fc0926b1f0f20b9217631147` |
| SHA-1 | `0b3197b593fe439f67ea525388d4c37cd0130391` |
| SHA-256 | `71883121b2f9a24a74c37974317962160b3af5bd1146d8ae8307c3d28c75a2e8` |
| SHA3-384 | `b11b8bf285183a9f024f728a6bd498d9c6916b51a1a4f53264aaf8652643bff12470d8328d30bdd528420292a42432fa` |
| TLSH | `T1F43183DA04151E322103CA9D7362359CB18EE2EB695FC7D4DD494EE9418838CF1A5B5D` |
| SSDEEP | `12:U066xlf6RU8AL6ApIWxKWblY6KOOl9DDi76Wzt6eCNWGi6NWGa4zaVL6V0uL2vmV:ZShhscl9Dy6qe0Rzj3EWx54wAqi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_71883121
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71883121b2f9a24a74c37974317962160b3af5bd1146d8ae8307c3d28c75a2e8"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-12 20:52:11"
  condition:
    hash.sha256(0, filesize) == "71883121b2f9a24a74c37974317962160b3af5bd1146d8ae8307c3d28c75a2e8"
}
```

### Sample 89: `0ef3bf87332779d4`

| Field | Value |
|---|---|
| SHA-256 | `0ef3bf87332779d4b37885eaa23e12fe0e7bf597da7356718eed8691377eb999` |
| Family label | `AsyncRAT` |
| File name | `QH88APP.exe` |
| File type | `exe` |
| First seen | `2026-08-12 20:50:26` |
| Reporter | `anonymous` |
| Tags | `AsyncRAT, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd179f38399080ca33cb55fa0342afaf` |
| SHA-1 | `7de9de3ae394116af7915b9f8d5ffa3d8bbcc7e4` |
| SHA-256 | `0ef3bf87332779d4b37885eaa23e12fe0e7bf597da7356718eed8691377eb999` |
| SHA3-384 | `d0507a6ae3c0dba5f7048ca5ff6a9f1900322e3bd68bfbb746cfe53d4c9676c513c5964ff523d841bb6a60843df68693` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T106C23C0833E4C676D1FE4ABAC83385009779D55B9923D75A5FC490AE2933BCD8A18FE4` |
| SSDEEP | `384:tjG3urUZ2egznZWEGOsVa/KFHbZaH9qbuUsibQxnCJfJBndnjJEKj:tjG3XZ2/i1VDHdIIboBiBntj` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_089_0ef3bf87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ef3bf87332779d4b37885eaa23e12fe0e7bf597da7356718eed8691377eb999"
    family = "AsyncRAT"
    file_name = "QH88APP.exe"
    file_type = "exe"
    first_seen = "2026-08-12 20:50:26"
  condition:
    hash.sha256(0, filesize) == "0ef3bf87332779d4b37885eaa23e12fe0e7bf597da7356718eed8691377eb999"
}
```

### Sample 90: `0352a0814d2244b9`

| Field | Value |
|---|---|
| SHA-256 | `0352a0814d2244b9568cf2b051222f2034760cf228618529371fa7d3b86050da` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-08-12 20:45:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac028e0c0fa55813fe39d41511eeeeb1` |
| SHA-1 | `a3e5749a618cd52084dc5a7de48ac5b990631a18` |
| SHA-256 | `0352a0814d2244b9568cf2b051222f2034760cf228618529371fa7d3b86050da` |
| SHA3-384 | `bc3d1cac959d843edd14df3cbeef31b000aa8f538e5f7c1e578cb494ebb955c978cbb72d562ed98e839c61d6b115cc93` |
| TLSH | `T108E33A05B30D0A47D2672EF03F3B27E1D3DF9A8124E4F684291FAA899271D325586EDD` |
| SSDEEP | `1536:VOUknEYbTExHBYxozRilSOWeoGKrIkSFFuMSRz4fodPBiZOgsU0q3vAXtxetjj+M:gUAE3BYxgAhI8uPMZXmXVoGBH2ac` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_0352a081
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0352a0814d2244b9568cf2b051222f2034760cf228618529371fa7d3b86050da"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-12 20:45:40"
  condition:
    hash.sha256(0, filesize) == "0352a0814d2244b9568cf2b051222f2034760cf228618529371fa7d3b86050da"
}
```

### Sample 91: `b3a39b3cc853d625`

| Field | Value |
|---|---|
| SHA-256 | `b3a39b3cc853d62505eaf57f5d9480f8396dc7a3888846a09fb277e797551182` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-08-12 20:39:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d199d140244c616d5059887c10dc8d5` |
| SHA-1 | `cf8e711e5ad0e5d1a93ea7eb106a644b3e9a7788` |
| SHA-256 | `b3a39b3cc853d62505eaf57f5d9480f8396dc7a3888846a09fb277e797551182` |
| SHA3-384 | `60ccb6e8c242c00a85e3e1fd7dd99f70dfbed0df01ead4f241cb0e6a768d6af45faa7b3118e8c7855db98d30a0c8ba65` |
| TLSH | `T1D3A35CC9F783E0F0ED4609B1116BB77E8634DE226124DE5ADB94FD769C32602A21E71C` |
| TELFHASH | `t1344119fa6de518ecb7d09404934f67221d6de63b15403bb247f3181823fbe82916ac35` |
| SSDEEP | `1536:Ywt5W/aaSFg7LyghBP/atLvh3mUs31sgmo9mIv7N9doyqzFtNV/Er:Y8T6LZhZ/atLO+c97Jq1V/s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_b3a39b3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3a39b3cc853d62505eaf57f5d9480f8396dc7a3888846a09fb277e797551182"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-12 20:39:18"
  condition:
    hash.sha256(0, filesize) == "b3a39b3cc853d62505eaf57f5d9480f8396dc7a3888846a09fb277e797551182"
}
```

### Sample 92: `88174718adac0d95`

| Field | Value |
|---|---|
| SHA-256 | `88174718adac0d95c5c2d87eab47b63d8b135dcec6c77b5962d9cc2c1433204e` |
| Family label | `unknown` |
| File name | `Invoice_Adobe_installer.msi` |
| File type | `msi` |
| First seen | `2026-08-12 20:34:20` |
| Reporter | `James_inthe_box` |
| Tags | `exe, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5aa904eb96c13f55b43a11ee0f2e4432` |
| SHA-1 | `731808b77c7ddd0a1ba649a804684cdd18bc4828` |
| SHA-256 | `88174718adac0d95c5c2d87eab47b63d8b135dcec6c77b5962d9cc2c1433204e` |
| SHA3-384 | `38f639f0cfb0f5ea3a0355a92ad1427eff187c37b0ae7f5eecebd6a06b5eca0d4976ef7dacd6a95051e4488b062815a5` |
| TLSH | `T15AF4CF117640C436C2B70A365669C6641A7EFC306E618A9B73C43F7EEE317C1AA24B77` |
| SSDEEP | `12288:sRsNW7ehwj4lkauPx5Ki7BvmZGRiTll0UlKLElxOqAXuiieFkgRuvxUSHwi7BvmC:syNW7nvUAW1lKwPOvfcvUnGJJulXvU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_88174718
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88174718adac0d95c5c2d87eab47b63d8b135dcec6c77b5962d9cc2c1433204e"
    family = "unknown"
    file_name = "Invoice_Adobe_installer.msi"
    file_type = "msi"
    first_seen = "2026-08-12 20:34:20"
  condition:
    hash.sha256(0, filesize) == "88174718adac0d95c5c2d87eab47b63d8b135dcec6c77b5962d9cc2c1433204e"
}
```

### Sample 93: `e8e3cbd3e99636bb`

| Field | Value |
|---|---|
| SHA-256 | `e8e3cbd3e99636bbd54efb8e62b07f8c53a79c23a968a6252317d5c2db8e3248` |
| Family label | `Vidar` |
| File name | `e8e3cbd3e99636bbd54efb8e62b07f8c53a79c23a968a6252317d5c2db8e3248.bin` |
| File type | `exe` |
| First seen | `2026-08-12 20:29:39` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6db50acb272807b33c5cb41eceef3b1f` |
| SHA-1 | `a5a7efe523bddd7f8f09c32e434e6928e8d6387b` |
| SHA-256 | `e8e3cbd3e99636bbd54efb8e62b07f8c53a79c23a968a6252317d5c2db8e3248` |
| SHA3-384 | `2fe15bcf93963c1cc39cac867089a9ecc59591e2702cd69c01565874204ba30424dc7e566c45e2d91b844f8c3a0739ef` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1DC164A177A9409F9C4A9E736C8B75261BA70BC4C8B3133D32E50AA782F723D19D79B44` |
| SSDEEP | `49152:dbZvI1zk935SUWFjXt1OdG5J+RW/13mUZ7TgojA5exA7FA:dVIGWd3GGVRTgP5e5` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_093_e8e3cbd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8e3cbd3e99636bbd54efb8e62b07f8c53a79c23a968a6252317d5c2db8e3248"
    family = "Vidar"
    file_name = "e8e3cbd3e99636bbd54efb8e62b07f8c53a79c23a968a6252317d5c2db8e3248.bin"
    file_type = "exe"
    first_seen = "2026-08-12 20:29:39"
  condition:
    hash.sha256(0, filesize) == "e8e3cbd3e99636bbd54efb8e62b07f8c53a79c23a968a6252317d5c2db8e3248"
}
```

### Sample 94: `6acdd71730d33689`

| Field | Value |
|---|---|
| SHA-256 | `6acdd71730d33689acaad80591691c6cbd3d653656c628fcc0ff8400ac75324c` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-12 20:20:46` |
| Reporter | `Bitsight` |
| Tags | `54e64e, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13beeac1ef1955b907b4e878fd24e904` |
| SHA-1 | `b2b315b0b2f1ba03f18f5a48dc3ae97088b22821` |
| SHA-256 | `6acdd71730d33689acaad80591691c6cbd3d653656c628fcc0ff8400ac75324c` |
| SHA3-384 | `1061f485bc5627250697f9f20f2cc75d492f896a073f5bba9db6bc70f2df091a9cce41da857c873189673376ac07810e` |
| IMPHASH | `160c101dd73adb2f729e5b922904fc20` |
| TLSH | `T1A9068D03F69580F9C05DC079874B9632FA32B8890635B2EF6BD45B213E66F906F1E719` |
| SSDEEP | `49152:jFzjDLG7Q7B4FGgLRqZ1lMYgInYo2VKzSVvwGtulnWjiRnSJgLw15UlO4TsEFq7D:4W3lQ6rSuA2SJ+w1MTg7N+Y` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_094_6acdd717
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6acdd71730d33689acaad80591691c6cbd3d653656c628fcc0ff8400ac75324c"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-12 20:20:46"
  condition:
    hash.sha256(0, filesize) == "6acdd71730d33689acaad80591691c6cbd3d653656c628fcc0ff8400ac75324c"
}
```

### Sample 95: `1814a5238c648088`

| Field | Value |
|---|---|
| SHA-256 | `1814a5238c648088ddb3a7d82c2408bd815be81ecafbff11f43c84fe5be5f4eb` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-12 20:18:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f07dfcd88dc8b9ba8e2b30ae96787888` |
| SHA-1 | `9a3f0a79e8573701dac83063900d84b0e8ba5950` |
| SHA-256 | `1814a5238c648088ddb3a7d82c2408bd815be81ecafbff11f43c84fe5be5f4eb` |
| SHA3-384 | `5a41116b1bf2248cd348897ac2943c19cb00b7849ce6abbecadb1ec8be7f2619f3aabb7ede3338b9ed3dbaf3f708e54e` |
| TLSH | `T15FE36B17B5C0D8FDC8DAC1B84BAEE226D972F4195174B25F23C4AF262E4DF206B6D610` |
| TELFHASH | `t16251ba743d593a98a1f7fb62730bd958dc790a1018e172e59e777deacb123400cb20a2` |
| SSDEEP | `3072:oZxYuwH0i5vqKX+LTbr1Mv4l71/eGDcSQfO9Inoy4UdYVZR8:s9JVMSeGgNwJR8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_1814a523
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1814a5238c648088ddb3a7d82c2408bd815be81ecafbff11f43c84fe5be5f4eb"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-12 20:18:42"
  condition:
    hash.sha256(0, filesize) == "1814a5238c648088ddb3a7d82c2408bd815be81ecafbff11f43c84fe5be5f4eb"
}
```

### Sample 96: `0ee582d0460ecb40`

| Field | Value |
|---|---|
| SHA-256 | `0ee582d0460ecb4088c37d41e4c3c3743c5a842aaef2f8adf1f036b74005b2ca` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-12 20:18:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf6b2cf59c312f6251bbec40cf52d769` |
| SHA-1 | `81a91a86c29052f93fec8f1740dbf81fdc5bdf76` |
| SHA-256 | `0ee582d0460ecb4088c37d41e4c3c3743c5a842aaef2f8adf1f036b74005b2ca` |
| SHA3-384 | `ba8c19d966f0613b5ff2ba99ac3619070546d9d61505d59cab7d7c7599b12bfeb95e828971b150171de52e09b4016250` |
| TLSH | `T13753F1A362B78A68C4225B7C4C3941E4EAA3B9603313DE6E04C890FDD4777859F34F99` |
| SSDEEP | `1536:rJruMQ2vycSu4Dbau3zVZOO7NOa+YzeJ7LgIR/EA:9MOSue3zV7NOrYza5R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_0ee582d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ee582d0460ecb4088c37d41e4c3c3743c5a842aaef2f8adf1f036b74005b2ca"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-12 20:18:01"
  condition:
    hash.sha256(0, filesize) == "0ee582d0460ecb4088c37d41e4c3c3743c5a842aaef2f8adf1f036b74005b2ca"
}
```

### Sample 97: `cd69aa2c38616f4f`

| Field | Value |
|---|---|
| SHA-256 | `cd69aa2c38616f4f759476e47d98a5d1d0d761d193d73360e309d255fd327985` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-08-12 20:13:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `adfbf87ad3f04374eba549a79abb1698` |
| SHA-1 | `e71df12b525e3b556562c310c87d144c0c6b1149` |
| SHA-256 | `cd69aa2c38616f4f759476e47d98a5d1d0d761d193d73360e309d255fd327985` |
| SHA3-384 | `087228f26873e0626d2d53d618c87738d371b6d33d8d0af90f38d6de41d205b1072258a770a71368b8520d30ed1f3e98` |
| TLSH | `T15E145BA5BA0F6C42F1C2D3F9DE8C83F17E1735E3C67689B1781213ADCAA39D95990502` |
| SSDEEP | `3072:n7OOQhHies3QaARCFk0RSfwGXH7zWsdNfJ2EMTa3Fnoq:n7QhH5s3QaARCa0RhGX7zx52Ednoq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_cd69aa2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd69aa2c38616f4f759476e47d98a5d1d0d761d193d73360e309d255fd327985"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-12 20:13:27"
  condition:
    hash.sha256(0, filesize) == "cd69aa2c38616f4f759476e47d98a5d1d0d761d193d73360e309d255fd327985"
}
```

### Sample 98: `86853a0c9272afe1`

| Field | Value |
|---|---|
| SHA-256 | `86853a0c9272afe15734577c5a7a14a5f98632b89aa986945e3bed3aa0c39b72` |
| Family label | `unknown` |
| File name | `86853a0c9272afe15734577c5a7a14a5f98632b89aa986945e3bed3aa0c39b72` |
| File type | `elf` |
| First seen | `2026-08-12 20:08:29` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8628c297e1e6613f18c19184b75ac504` |
| SHA-1 | `fba53867f5eb1c6f0a62e45db164794b7bba0f0c` |
| SHA-256 | `86853a0c9272afe15734577c5a7a14a5f98632b89aa986945e3bed3aa0c39b72` |
| SHA3-384 | `e9b3a58455d6cc4dc0b060098e4ea65ce075beaaf6f153d9763b452698cfcab8a2eebef7f159b83a6424d3d3a2fcc284` |
| TLSH | `T105E69D77914338E9E5A98CB4D11025426DAC388B5738A3C7BAC471F667BA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQH:cqYUQuVDt0TZEc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_86853a0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86853a0c9272afe15734577c5a7a14a5f98632b89aa986945e3bed3aa0c39b72"
    family = "unknown"
    file_name = "86853a0c9272afe15734577c5a7a14a5f98632b89aa986945e3bed3aa0c39b72"
    file_type = "elf"
    first_seen = "2026-08-12 20:08:29"
  condition:
    hash.sha256(0, filesize) == "86853a0c9272afe15734577c5a7a14a5f98632b89aa986945e3bed3aa0c39b72"
}
```

### Sample 99: `ac5b3f3e20bf74fb`

| Field | Value |
|---|---|
| SHA-256 | `ac5b3f3e20bf74fb25ed3caa8856deb61f8e44d691b955402421621a50801c7b` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-12 20:05:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `896d6a1b70f8e321657274858717dd5f` |
| SHA-1 | `b1c099645c67945ef65595aad96c963f983aabbb` |
| SHA-256 | `ac5b3f3e20bf74fb25ed3caa8856deb61f8e44d691b955402421621a50801c7b` |
| SHA3-384 | `d5062c93f3e6f76847b0d580a7395749be74b405665ce1804db78fe152182786092e6c47855f5fd3fab25c7e232668e7` |
| TLSH | `T1D2D34A63CC796E58D624D5B1B0358BB86B93A524918B1FFE14B7C2748043ECEF6493B8` |
| SSDEEP | `3072:KkyQgSgr55IBZ8FrQTdHp1lx2Wj2VTK88JHYjYY:U5Xr5uB2FrkXjj2888KjYY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_ac5b3f3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac5b3f3e20bf74fb25ed3caa8856deb61f8e44d691b955402421621a50801c7b"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-12 20:05:16"
  condition:
    hash.sha256(0, filesize) == "ac5b3f3e20bf74fb25ed3caa8856deb61f8e44d691b955402421621a50801c7b"
}
```

### Sample 100: `8eaa8e6cc4ddc443`

| Field | Value |
|---|---|
| SHA-256 | `8eaa8e6cc4ddc443d7a8b81dcaf07d86531995c34b83b5f91b77817bf2c5182b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-12 20:02:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d71f22e7f371fd8cebdfcab4f513e58a` |
| SHA-1 | `ee66a8ecb39623a4215c02dc3e4cd94ef1a5ba7e` |
| SHA-256 | `8eaa8e6cc4ddc443d7a8b81dcaf07d86531995c34b83b5f91b77817bf2c5182b` |
| SHA3-384 | `1af431bea46e3d8f7f46aa79d1cb6c8929df15be84c4ad7205ecd1cb977ce40de534db4cd3580136160486bf9d20e151` |
| TLSH | `T1DA235C6516857C24AE98C4361C7E2F0CB9AD83E6324452EE7FCB3CF68C4A69DD10971D` |
| SSDEEP | `768:2Z+19GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:e+mcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_8eaa8e6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8eaa8e6cc4ddc443d7a8b81dcaf07d86531995c34b83b5f91b77817bf2c5182b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-12 20:02:31"
  condition:
    hash.sha256(0, filesize) == "8eaa8e6cc4ddc443d7a8b81dcaf07d86531995c34b83b5f91b77817bf2c5182b"
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
 * Generated: 2026-08-13T03:02:27.826573+00:00
 */

rule MalwareBazaar_unknown_001_501f1e4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "501f1e4ea746839e90ced6f4a76422c3ae0001b45f9c2c4ed78910d4d0a1180c"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-13 03:01:33"
  condition:
    hash.sha256(0, filesize) == "501f1e4ea746839e90ced6f4a76422c3ae0001b45f9c2c4ed78910d4d0a1180c"
}

rule MalwareBazaar_unknown_002_4a513007
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a51300720f6f81002920991029e8f68306a362c826078e9f19ccac4b153511d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-13 03:01:26"
  condition:
    hash.sha256(0, filesize) == "4a51300720f6f81002920991029e8f68306a362c826078e9f19ccac4b153511d"
}

rule MalwareBazaar_Mirai_003_0e0d4a26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e0d4a2643d7590b59f8dd9259f9989bffac862087e0d9a0f95e69dea95f38be"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-13 02:51:58"
  condition:
    hash.sha256(0, filesize) == "0e0d4a2643d7590b59f8dd9259f9989bffac862087e0d9a0f95e69dea95f38be"
}

rule MalwareBazaar_Mirai_004_3f67aaa7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f67aaa79b36b33d0b6bf22fc842f3eada9ebff6670fc3aae51308c5d0292e24"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 02:50:55"
  condition:
    hash.sha256(0, filesize) == "3f67aaa79b36b33d0b6bf22fc842f3eada9ebff6670fc3aae51308c5d0292e24"
}

rule MalwareBazaar_Mirai_005_2926f6b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2926f6b7f7b75ad404d564961f5061af5335c6a96838793d9f1c92a4fb0cbd49"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 02:49:55"
  condition:
    hash.sha256(0, filesize) == "2926f6b7f7b75ad404d564961f5061af5335c6a96838793d9f1c92a4fb0cbd49"
}

rule MalwareBazaar_unknown_006_c9bf9fc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9bf9fc13119182ec3f44875b2ac5b3235605f8f5e6198ca7e9dd8ca3ad3b9ec"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-13 02:46:04"
  condition:
    hash.sha256(0, filesize) == "c9bf9fc13119182ec3f44875b2ac5b3235605f8f5e6198ca7e9dd8ca3ad3b9ec"
}

rule MalwareBazaar_Mirai_007_beec9de8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "beec9de861a22593ebec152e204e7daa92c819bb809226ea87c530a4b644b044"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-13 02:44:00"
  condition:
    hash.sha256(0, filesize) == "beec9de861a22593ebec152e204e7daa92c819bb809226ea87c530a4b644b044"
}

rule MalwareBazaar_Mirai_008_f3137c3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3137c3cfcd9c8e705bbc5c4b08d16af556f97a12a2b7b4f65492de77788f885"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-08-13 02:41:55"
  condition:
    hash.sha256(0, filesize) == "f3137c3cfcd9c8e705bbc5c4b08d16af556f97a12a2b7b4f65492de77788f885"
}

rule MalwareBazaar_unknown_009_534d42ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "534d42bacaf13a9a2b0246ac604882d17cc740d16a750686c73780ee2ac4aaa2"
    family = "unknown"
    file_name = "USD $50,000.00.exe"
    file_type = "exe"
    first_seen = "2026-08-13 02:34:53"
  condition:
    hash.sha256(0, filesize) == "534d42bacaf13a9a2b0246ac604882d17cc740d16a750686c73780ee2ac4aaa2"
}

rule MalwareBazaar_Mirai_010_4a8cc17f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a8cc17f0df2448ac7fb7306477c759786348ec01bdfb28e3077b7254a740965"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-13 02:26:02"
  condition:
    hash.sha256(0, filesize) == "4a8cc17f0df2448ac7fb7306477c759786348ec01bdfb28e3077b7254a740965"
}

rule MalwareBazaar_unknown_011_a927d846
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a927d846000150182ceb79dc90494dff0d36acffd5aa78f793c110eae5694c2f"
    family = "unknown"
    file_name = "bbc"
    file_type = "sh"
    first_seen = "2026-08-13 02:26:01"
  condition:
    hash.sha256(0, filesize) == "a927d846000150182ceb79dc90494dff0d36acffd5aa78f793c110eae5694c2f"
}

rule MalwareBazaar_Mirai_012_f858d116
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f858d116faf992366be063f8681a5b5d153a5e69944577761470b063d403f88c"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-13 02:20:51"
  condition:
    hash.sha256(0, filesize) == "f858d116faf992366be063f8681a5b5d153a5e69944577761470b063d403f88c"
}

rule MalwareBazaar_Mirai_013_ae0c56bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0c56bd6b7122adb67c3fb2804f02464798a16f015f8147c3d2d621ad87c9ca"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-08-13 02:20:48"
  condition:
    hash.sha256(0, filesize) == "ae0c56bd6b7122adb67c3fb2804f02464798a16f015f8147c3d2d621ad87c9ca"
}

rule MalwareBazaar_Mirai_014_3fa6280b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa6280b8fb6e208c0e67fae05e4c94cb3ea41c83f9a497f9b6664d00d78fdf2"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-13 02:19:58"
  condition:
    hash.sha256(0, filesize) == "3fa6280b8fb6e208c0e67fae05e4c94cb3ea41c83f9a497f9b6664d00d78fdf2"
}

rule MalwareBazaar_unknown_015_a20f7aad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a20f7aad7c1baeb96fa1f8404cc1ef9056636225979824d7a5297d3bc8f0609b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-13 02:19:57"
  condition:
    hash.sha256(0, filesize) == "a20f7aad7c1baeb96fa1f8404cc1ef9056636225979824d7a5297d3bc8f0609b"
}

rule MalwareBazaar_Mirai_016_6b9726c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b9726c40810214f4c9991fd472060ee540ed6fc6df98c1bcc47048802240bed"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-08-13 02:19:56"
  condition:
    hash.sha256(0, filesize) == "6b9726c40810214f4c9991fd472060ee540ed6fc6df98c1bcc47048802240bed"
}

rule MalwareBazaar_Mirai_017_3b498192
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b498192384e946885d868bf3afd1d38b7713974623e30e4bd9f1e98673e5d08"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-08-13 02:17:55"
  condition:
    hash.sha256(0, filesize) == "3b498192384e946885d868bf3afd1d38b7713974623e30e4bd9f1e98673e5d08"
}

rule MalwareBazaar_Mirai_018_36816089
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "368160899f8e7811a45bfabc8dd7464d79575e9d0bb0ded1ac585c40ecbaeb93"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-13 02:15:59"
  condition:
    hash.sha256(0, filesize) == "368160899f8e7811a45bfabc8dd7464d79575e9d0bb0ded1ac585c40ecbaeb93"
}

rule MalwareBazaar_Mirai_019_91bbb537
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91bbb53706f8b4d4142e22e1ca06b8ee2078e9409d1ba23c89a5baa738150019"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-13 02:12:02"
  condition:
    hash.sha256(0, filesize) == "91bbb53706f8b4d4142e22e1ca06b8ee2078e9409d1ba23c89a5baa738150019"
}

rule MalwareBazaar_Mirai_020_d5fd3c15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5fd3c15f9514e187adf6756e85b5b7ce377a8639a327e60bdeedf0fb19f3258"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-08-13 02:08:10"
  condition:
    hash.sha256(0, filesize) == "d5fd3c15f9514e187adf6756e85b5b7ce377a8639a327e60bdeedf0fb19f3258"
}

rule MalwareBazaar_unknown_021_79cb0240
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79cb0240cf8f0767b94923cfd8007e71628ae7bfd9af38ed67b6d34c422a7c62"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-13 02:06:14"
  condition:
    hash.sha256(0, filesize) == "79cb0240cf8f0767b94923cfd8007e71628ae7bfd9af38ed67b6d34c422a7c62"
}

rule MalwareBazaar_unknown_022_fd0e0269
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd0e0269eee45e681eca36c4ea6a1bfa41a4d7421167da23270afc35e5eaed01"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-13 02:01:12"
  condition:
    hash.sha256(0, filesize) == "fd0e0269eee45e681eca36c4ea6a1bfa41a4d7421167da23270afc35e5eaed01"
}

rule MalwareBazaar_unknown_023_80db7915
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80db791509c3421260a19aa13397072d6aa7c6981822ee03333950a3444e74f0"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-13 02:01:05"
  condition:
    hash.sha256(0, filesize) == "80db791509c3421260a19aa13397072d6aa7c6981822ee03333950a3444e74f0"
}

rule MalwareBazaar_Mirai_024_47a24d07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47a24d074131c35a8abccb79a958316165a5827b96d446c5d31f1f7b0efa4c4d"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-13 01:59:55"
  condition:
    hash.sha256(0, filesize) == "47a24d074131c35a8abccb79a958316165a5827b96d446c5d31f1f7b0efa4c4d"
}

rule MalwareBazaar_Mirai_025_a4e82a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4e82a110c505c1fa42956ad1f7c105d745677148a93f64d5c0a23c6b63e219f"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-13 01:55:58"
  condition:
    hash.sha256(0, filesize) == "a4e82a110c505c1fa42956ad1f7c105d745677148a93f64d5c0a23c6b63e219f"
}

rule MalwareBazaar_Mirai_026_391bdcb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "391bdcb9558ee696f7ed9f8b45ee25c831ecd103340ca998b68716711e6c429c"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 01:50:44"
  condition:
    hash.sha256(0, filesize) == "391bdcb9558ee696f7ed9f8b45ee25c831ecd103340ca998b68716711e6c429c"
}

rule MalwareBazaar_Mirai_027_9f7ef60e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f7ef60eca04d7f3153e9226a20ce34c0cb798c0f31dbceb91a58c724445469a"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 01:49:54"
  condition:
    hash.sha256(0, filesize) == "9f7ef60eca04d7f3153e9226a20ce34c0cb798c0f31dbceb91a58c724445469a"
}

rule MalwareBazaar_Mirai_028_ae0049d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0049d554db803483b5677a2bf7995c6d2aecb8e036978e6e6169afa88d44ab"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-08-13 01:49:53"
  condition:
    hash.sha256(0, filesize) == "ae0049d554db803483b5677a2bf7995c6d2aecb8e036978e6e6169afa88d44ab"
}

rule MalwareBazaar_unknown_029_68a5be88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68a5be8895dd1130e6beb6f0bc508c9d022b51ef0ed8279cf46db2cfab729247"
    family = "unknown"
    file_name = "68a5be8895dd1130e6beb6f0bc508c9d022b51ef0ed8279cf46db2cfab729247.bin"
    file_type = "unknown"
    first_seen = "2026-08-13 01:43:53"
  condition:
    hash.sha256(0, filesize) == "68a5be8895dd1130e6beb6f0bc508c9d022b51ef0ed8279cf46db2cfab729247"
}

rule MalwareBazaar_Mirai_030_0ade4877
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ade487718f7253ecd1e325ad9adeb09701289999a05412e94a3a01c02e701b8"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-13 01:34:38"
  condition:
    hash.sha256(0, filesize) == "0ade487718f7253ecd1e325ad9adeb09701289999a05412e94a3a01c02e701b8"
}

rule MalwareBazaar_Mirai_031_8cfb9a33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cfb9a33dd9e40f1912c9332b91c3308e4a59883824dcfd900bc90c86ee7df9c"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-13 01:33:56"
  condition:
    hash.sha256(0, filesize) == "8cfb9a33dd9e40f1912c9332b91c3308e4a59883824dcfd900bc90c86ee7df9c"
}

rule MalwareBazaar_unknown_032_677613b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "677613b506d73c2be470e60eda9ec4aece981468d382b23f2ed0f671656a84a6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-13 01:33:00"
  condition:
    hash.sha256(0, filesize) == "677613b506d73c2be470e60eda9ec4aece981468d382b23f2ed0f671656a84a6"
}

rule MalwareBazaar_Mirai_033_fffc7c1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fffc7c1ca08e6cd9b373e2ecb1b278caa6c4c1489bfa92577c53bcfa173b847a"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-13 01:32:00"
  condition:
    hash.sha256(0, filesize) == "fffc7c1ca08e6cd9b373e2ecb1b278caa6c4c1489bfa92577c53bcfa173b847a"
}

rule MalwareBazaar_unknown_034_4ffb7afc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ffb7afc5a85fe8d342ed584cce1579240124c74f11808ebb178d33da8c79779"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-13 01:29:54"
  condition:
    hash.sha256(0, filesize) == "4ffb7afc5a85fe8d342ed584cce1579240124c74f11808ebb178d33da8c79779"
}

rule MalwareBazaar_Mirai_035_b571ac0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b571ac0a13a864f246d66f55ba310b9df8d0a71caf3c773d8e45e237305d0e6a"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-13 01:27:58"
  condition:
    hash.sha256(0, filesize) == "b571ac0a13a864f246d66f55ba310b9df8d0a71caf3c773d8e45e237305d0e6a"
}

rule MalwareBazaar_Mirai_036_1b309923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b3099234082a8287e83b74e649826d495bf1d9e8ceea1c6766198e8f9376330"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 01:25:59"
  condition:
    hash.sha256(0, filesize) == "1b3099234082a8287e83b74e649826d495bf1d9e8ceea1c6766198e8f9376330"
}

rule MalwareBazaar_unknown_037_0b83f774
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b83f7746bdd2f7633fdadc707fda9931d70915155ac1e4ba8300a311e5be6ba"
    family = "unknown"
    file_name = "0b83f7746bdd2f7633fdadc707fda9931d70915155ac1e4ba8300a311e5be6ba.bin"
    file_type = "exe"
    first_seen = "2026-08-13 01:02:14"
  condition:
    hash.sha256(0, filesize) == "0b83f7746bdd2f7633fdadc707fda9931d70915155ac1e4ba8300a311e5be6ba"
}

rule MalwareBazaar_unknown_038_ef09996d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef09996dfdf2768242a6aa4659a6c6262148cd98bd0882cdbfcc6c9e8a248764"
    family = "unknown"
    file_name = "ef09996dfdf2768242a6aa4659a6c6262148cd98bd0882cdbfcc6c9e8a248764.bin"
    file_type = "exe"
    first_seen = "2026-08-13 01:02:12"
  condition:
    hash.sha256(0, filesize) == "ef09996dfdf2768242a6aa4659a6c6262148cd98bd0882cdbfcc6c9e8a248764"
}

rule MalwareBazaar_unknown_039_4b12e723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b12e723bb5cb1cb175aace0197386d417522fb467ae8e9fc53e980c8a0a13f8"
    family = "unknown"
    file_name = "4b12e723bb5cb1cb175aace0197386d417522fb467ae8e9fc53e980c8a0a13f8.bin"
    file_type = "exe"
    first_seen = "2026-08-13 01:02:10"
  condition:
    hash.sha256(0, filesize) == "4b12e723bb5cb1cb175aace0197386d417522fb467ae8e9fc53e980c8a0a13f8"
}

rule MalwareBazaar_unknown_040_965fca6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "965fca6f4ab47b5479a701cfca3d1e8cc3bd1f1e00040105c16015e7e92144c7"
    family = "unknown"
    file_name = "965fca6f4ab47b5479a701cfca3d1e8cc3bd1f1e00040105c16015e7e92144c7.bin"
    file_type = "exe"
    first_seen = "2026-08-13 01:02:08"
  condition:
    hash.sha256(0, filesize) == "965fca6f4ab47b5479a701cfca3d1e8cc3bd1f1e00040105c16015e7e92144c7"
}

rule MalwareBazaar_CoinMiner_041_04168e38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04168e3872a815ace4f4c59a787ef0d10782df4b2111d46d899b10eade942f80"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-13 01:00:51"
  condition:
    hash.sha256(0, filesize) == "04168e3872a815ace4f4c59a787ef0d10782df4b2111d46d899b10eade942f80"
}

rule MalwareBazaar_unknown_042_beb7b0d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "beb7b0d778dee883735af6fcc0c11ea38d1f5f334f5a22f1b1047f244ba4de2b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-13 01:00:41"
  condition:
    hash.sha256(0, filesize) == "beb7b0d778dee883735af6fcc0c11ea38d1f5f334f5a22f1b1047f244ba4de2b"
}

rule MalwareBazaar_DCRat_043_158dcc5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "158dcc5fd88c94f8386ba99f0f77866200fc593f4b35755d357a33ec87fec298"
    family = "DCRat"
    file_name = "05700e9fe7caa7ffbb63fccc4cff6179.exe"
    file_type = "exe"
    first_seen = "2026-08-13 00:50:07"
  condition:
    hash.sha256(0, filesize) == "158dcc5fd88c94f8386ba99f0f77866200fc593f4b35755d357a33ec87fec298"
}

rule MalwareBazaar_unknown_044_b5755fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5755fb03eae1c73b4ad2f417c1ca7d0ff09e27344cc7d5dbdfd4903d5d7429a"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-13 00:47:42"
  condition:
    hash.sha256(0, filesize) == "b5755fb03eae1c73b4ad2f417c1ca7d0ff09e27344cc7d5dbdfd4903d5d7429a"
}

rule MalwareBazaar_unknown_045_967fceb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "967fceb5b057003cb398afc50a071ff55dd004e0b1088c80daf8146ef2caed78"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-12 23:52:35"
  condition:
    hash.sha256(0, filesize) == "967fceb5b057003cb398afc50a071ff55dd004e0b1088c80daf8146ef2caed78"
}

rule MalwareBazaar_unknown_046_6c37df31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c37df31d27e6bd1baeb985ecaa4b9b3767b70076c9c7aa403b5c4f0e68fe0fd"
    family = "unknown"
    file_name = "reportsaccs.exe"
    file_type = "exe"
    first_seen = "2026-08-12 23:28:08"
  condition:
    hash.sha256(0, filesize) == "6c37df31d27e6bd1baeb985ecaa4b9b3767b70076c9c7aa403b5c4f0e68fe0fd"
}

rule MalwareBazaar_WannaCry_047_ed2a78cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed2a78cca645750490acdd56cf1a819967d669bf1a2f13bbef44b9d7ce1db61f"
    family = "WannaCry"
    file_name = "ed2a78cca645750490acdd56cf1a819967d669bf1a2f13bbef44b9d7ce1db61f"
    file_type = "exe"
    first_seen = "2026-08-12 23:15:57"
  condition:
    hash.sha256(0, filesize) == "ed2a78cca645750490acdd56cf1a819967d669bf1a2f13bbef44b9d7ce1db61f"
}

rule MalwareBazaar_Mirai_048_edc2b909
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edc2b90996347cf8ebffb8befe24b96a2a3a6e489b9e02768315f8f7a3c07cbe"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-12 22:51:06"
  condition:
    hash.sha256(0, filesize) == "edc2b90996347cf8ebffb8befe24b96a2a3a6e489b9e02768315f8f7a3c07cbe"
}

rule MalwareBazaar_Mirai_049_7fc40677
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fc40677a79d0cbc675d8c0042d6cfbc87ca1a9982f5046008feb7bd4fe799b9"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-12 22:51:05"
  condition:
    hash.sha256(0, filesize) == "7fc40677a79d0cbc675d8c0042d6cfbc87ca1a9982f5046008feb7bd4fe799b9"
}

rule MalwareBazaar_Mirai_050_01c70849
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01c70849ed30aa1cc4e08cb7529b62c2e3a9044ad0ab000ad84a343444a8dd5a"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-12 22:51:03"
  condition:
    hash.sha256(0, filesize) == "01c70849ed30aa1cc4e08cb7529b62c2e3a9044ad0ab000ad84a343444a8dd5a"
}

rule MalwareBazaar_Mirai_051_b595ef9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b595ef9ca4756a07bc83027a943009cb947d03c4c261a3e4cc3bec467b43c203"
    family = "Mirai"
    file_name = "2778ce"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:09"
  condition:
    hash.sha256(0, filesize) == "b595ef9ca4756a07bc83027a943009cb947d03c4c261a3e4cc3bec467b43c203"
}

rule MalwareBazaar_Mirai_052_5c502903
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c502903694591a219ca263247c4c159967c5838c9a85641f3fb908b983d1e32"
    family = "Mirai"
    file_name = "341d04"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:08"
  condition:
    hash.sha256(0, filesize) == "5c502903694591a219ca263247c4c159967c5838c9a85641f3fb908b983d1e32"
}

rule MalwareBazaar_Mirai_053_a75a9864
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a75a98641037e42abb4c543d90e81dafdae3b27e90972b705a2e9242a5bee123"
    family = "Mirai"
    file_name = "085175"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:06"
  condition:
    hash.sha256(0, filesize) == "a75a98641037e42abb4c543d90e81dafdae3b27e90972b705a2e9242a5bee123"
}

rule MalwareBazaar_Mirai_054_41ac975a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41ac975aa0638b879bade9f672fbcdacb303bc6ceb5e92083b85af9cd440cd04"
    family = "Mirai"
    file_name = "f971dc"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:05"
  condition:
    hash.sha256(0, filesize) == "41ac975aa0638b879bade9f672fbcdacb303bc6ceb5e92083b85af9cd440cd04"
}

rule MalwareBazaar_Mirai_055_383819dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "383819dd8c7df6077d193ace66715d7b3e5d82e0de0ad87ef8a783965786d606"
    family = "Mirai"
    file_name = "bfde3b"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:03"
  condition:
    hash.sha256(0, filesize) == "383819dd8c7df6077d193ace66715d7b3e5d82e0de0ad87ef8a783965786d606"
}

rule MalwareBazaar_Mirai_056_bf0aabf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf0aabf517685756f16b22f4b1907113a1cd160fa7b5ee384cb554b42b311841"
    family = "Mirai"
    file_name = "068f87"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:02"
  condition:
    hash.sha256(0, filesize) == "bf0aabf517685756f16b22f4b1907113a1cd160fa7b5ee384cb554b42b311841"
}

rule MalwareBazaar_Mirai_057_3b2f2f02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b2f2f02077aee3efe6dcca1bb84afc59af14fff78d1b6dd18aed0c24e08a313"
    family = "Mirai"
    file_name = "5b5f1c"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:01"
  condition:
    hash.sha256(0, filesize) == "3b2f2f02077aee3efe6dcca1bb84afc59af14fff78d1b6dd18aed0c24e08a313"
}

rule MalwareBazaar_Mirai_058_8bdbe21e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bdbe21eafc7223a75ea9d075237d389e0c39f6370721f1ea36214989e5bab63"
    family = "Mirai"
    file_name = "ec54e5"
    file_type = "elf"
    first_seen = "2026-08-12 22:49:00"
  condition:
    hash.sha256(0, filesize) == "8bdbe21eafc7223a75ea9d075237d389e0c39f6370721f1ea36214989e5bab63"
}

rule MalwareBazaar_Mirai_059_abda6887
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abda6887930f4e2e1047b39adf23bbf8bdee9e15c7e2101245bb690be7d80488"
    family = "Mirai"
    file_name = "126678"
    file_type = "elf"
    first_seen = "2026-08-12 22:48:58"
  condition:
    hash.sha256(0, filesize) == "abda6887930f4e2e1047b39adf23bbf8bdee9e15c7e2101245bb690be7d80488"
}

rule MalwareBazaar_Mirai_060_9c719ba3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c719ba3b1cd4a8cf820c5eaea04aae7d0188da53e75f18f9c04c1fbbd3cc97e"
    family = "Mirai"
    file_name = "b59af2"
    file_type = "elf"
    first_seen = "2026-08-12 22:48:57"
  condition:
    hash.sha256(0, filesize) == "9c719ba3b1cd4a8cf820c5eaea04aae7d0188da53e75f18f9c04c1fbbd3cc97e"
}

rule MalwareBazaar_Mirai_061_9d44d4d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d44d4d051f6aa3fbc95fab0aae818347a602d655fa7f1fba6267e728d7ff2d3"
    family = "Mirai"
    file_name = "659716"
    file_type = "elf"
    first_seen = "2026-08-12 22:48:56"
  condition:
    hash.sha256(0, filesize) == "9d44d4d051f6aa3fbc95fab0aae818347a602d655fa7f1fba6267e728d7ff2d3"
}

rule MalwareBazaar_Mirai_062_33663505
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3366350561c41f5d15994244bfd7358ca256d16a1e954d7a986bd4d2d50c895e"
    family = "Mirai"
    file_name = "3f9c7b"
    file_type = "elf"
    first_seen = "2026-08-12 22:48:55"
  condition:
    hash.sha256(0, filesize) == "3366350561c41f5d15994244bfd7358ca256d16a1e954d7a986bd4d2d50c895e"
}

rule MalwareBazaar_unknown_063_1ec25086
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ec25086be7fa2918db0f591bff7417190bec288ec668b8dce53950134c886a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-12 22:45:38"
  condition:
    hash.sha256(0, filesize) == "1ec25086be7fa2918db0f591bff7417190bec288ec668b8dce53950134c886a4"
}

rule MalwareBazaar_Vidar_064_afc9662b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afc9662bbe72c2171342431d5f13ea9ce5cd3b61006524061061399628b5970d"
    family = "Vidar"
    file_name = "afc9662bbe72c2171342431d5f13ea9ce5cd3b61006524061061399628b5970d.bin"
    file_type = "exe"
    first_seen = "2026-08-12 22:30:59"
  condition:
    hash.sha256(0, filesize) == "afc9662bbe72c2171342431d5f13ea9ce5cd3b61006524061061399628b5970d"
}

rule MalwareBazaar_unknown_065_2f0c7dea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f0c7deae88b098583f9c6333a32d54b846fb684f5013bd7f93cac53642b71df"
    family = "unknown"
    file_name = "2f0c7deae88b098583f9c6333a32d54b846fb684f5013bd7f93cac53642b71df.bin"
    file_type = "exe"
    first_seen = "2026-08-12 22:30:57"
  condition:
    hash.sha256(0, filesize) == "2f0c7deae88b098583f9c6333a32d54b846fb684f5013bd7f93cac53642b71df"
}

rule MalwareBazaar_unknown_066_d2a74301
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2a74301bdf3c50d57a5a08aacf69b26fdf32fe9a8a4dd299a3d73125ce4f73f"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-12 22:28:43"
  condition:
    hash.sha256(0, filesize) == "d2a74301bdf3c50d57a5a08aacf69b26fdf32fe9a8a4dd299a3d73125ce4f73f"
}

rule MalwareBazaar_Mirai_067_71613db2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71613db242e2659dec7a3ce13b56367dfde705758f66a140baf24907bcc8ade7"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-08-12 22:26:57"
  condition:
    hash.sha256(0, filesize) == "71613db242e2659dec7a3ce13b56367dfde705758f66a140baf24907bcc8ade7"
}

rule MalwareBazaar_unknown_068_8e57f52d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e57f52d19952b761b82a28b528705df1e3d607b4d317bc3d96f1a27f8242d72"
    family = "unknown"
    file_name = "8e57f52d19952b761b82a28b528705df1e3d607b4d317bc3d96f1a27f8242d72.exe"
    file_type = "exe"
    first_seen = "2026-08-12 22:24:03"
  condition:
    hash.sha256(0, filesize) == "8e57f52d19952b761b82a28b528705df1e3d607b4d317bc3d96f1a27f8242d72"
}

rule MalwareBazaar_CoinMiner_069_d0294a7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0294a7caf27f11e40af507cafa5627b65b5096b5cf9926a31d5cba0993fc1da"
    family = "CoinMiner"
    file_name = "d0294a7caf27f11e40af507cafa5627b65b5096b5cf9926a31d5cba0993fc1da.exe"
    file_type = "exe"
    first_seen = "2026-08-12 22:23:57"
  condition:
    hash.sha256(0, filesize) == "d0294a7caf27f11e40af507cafa5627b65b5096b5cf9926a31d5cba0993fc1da"
}

rule MalwareBazaar_Vidar_070_4339a4bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4339a4bf8be2b5e32f6ed2c644b9bf1181ac25b336e0ed5198c808098279d27e"
    family = "Vidar"
    file_name = "4339a4bf8be2b5e32f6ed2c644b9bf1181ac25b336e0ed5198c808098279d27e.bin"
    file_type = "exe"
    first_seen = "2026-08-12 22:00:42"
  condition:
    hash.sha256(0, filesize) == "4339a4bf8be2b5e32f6ed2c644b9bf1181ac25b336e0ed5198c808098279d27e"
}

rule MalwareBazaar_unknown_071_af60ac5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af60ac5b44bd1e03ee564d33c1da963db85b4f73b05f6820a8f2a57c4e73efd4"
    family = "unknown"
    file_name = "af60ac5b44bd1e03ee564d33c1da963db85b4f73b05f6820a8f2a57c4e73efd4.bin"
    file_type = "exe"
    first_seen = "2026-08-12 22:00:39"
  condition:
    hash.sha256(0, filesize) == "af60ac5b44bd1e03ee564d33c1da963db85b4f73b05f6820a8f2a57c4e73efd4"
}

rule MalwareBazaar_unknown_072_9cc1484a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cc1484aaeefb46feb49edf79bd0c0f2a82eadbe630a7c1937bf7c4b0bd87e35"
    family = "unknown"
    file_name = "9cc1484aaeefb46feb49edf79bd0c0f2a82eadbe630a7c1937bf7c4b0bd87e35.bin"
    file_type = "exe"
    first_seen = "2026-08-12 22:00:37"
  condition:
    hash.sha256(0, filesize) == "9cc1484aaeefb46feb49edf79bd0c0f2a82eadbe630a7c1937bf7c4b0bd87e35"
}

rule MalwareBazaar_unknown_073_fcde17b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcde17b95346c7a44de2de0ce663e5e9a4dc9af982e11b10538385892428748b"
    family = "unknown"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-12 21:52:31"
  condition:
    hash.sha256(0, filesize) == "fcde17b95346c7a44de2de0ce663e5e9a4dc9af982e11b10538385892428748b"
}

rule MalwareBazaar_unknown_074_b38fda4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b38fda4a414a530a9ffeb9ecf6b1ef05453cd1d62033efc8f89b1d307af3552b"
    family = "unknown"
    file_name = "Schet_Akt_1842_v2.iso"
    file_type = "iso"
    first_seen = "2026-08-12 21:50:47"
  condition:
    hash.sha256(0, filesize) == "b38fda4a414a530a9ffeb9ecf6b1ef05453cd1d62033efc8f89b1d307af3552b"
}

rule MalwareBazaar_Havoc_075_1b151dd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b151dd1b1ca636550029602ee88eae182a4143fef630a608647f4b027051a9a"
    family = "Havoc"
    file_name = "view.ps1"
    file_type = "ps1"
    first_seen = "2026-08-12 21:48:57"
  condition:
    hash.sha256(0, filesize) == "1b151dd1b1ca636550029602ee88eae182a4143fef630a608647f4b027051a9a"
}

rule MalwareBazaar_unknown_076_f8b0b7e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b0b7e53c36cf4147526f692eca5bf98aa7206f13990c02b9270e04c341e5c0"
    family = "unknown"
    file_name = "pisos.bin"
    file_type = "unknown"
    first_seen = "2026-08-12 21:48:09"
  condition:
    hash.sha256(0, filesize) == "f8b0b7e53c36cf4147526f692eca5bf98aa7206f13990c02b9270e04c341e5c0"
}

rule MalwareBazaar_unknown_077_e3fbe466
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3fbe466054844db78527a099d11a4e9d12c40a4bd9add4bef9faea10a902eae"
    family = "unknown"
    file_name = "Schet_Akt_1842.docx"
    file_type = "doc"
    first_seen = "2026-08-12 21:46:51"
  condition:
    hash.sha256(0, filesize) == "e3fbe466054844db78527a099d11a4e9d12c40a4bd9add4bef9faea10a902eae"
}

rule MalwareBazaar_unknown_078_52426650
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "524266500e8341c5c20a548d1f96c55b3696422e761a9c22044f60254d777a8b"
    family = "unknown"
    file_name = "Advanced_IP_Scanner_2.5.4594.3.exe"
    file_type = "exe"
    first_seen = "2026-08-12 21:34:22"
  condition:
    hash.sha256(0, filesize) == "524266500e8341c5c20a548d1f96c55b3696422e761a9c22044f60254d777a8b"
}

rule MalwareBazaar_Mirai_079_75281632
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "752816328ef0c903baea78bc49a1aa8047f248758d91d4c903bad82546706d97"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-12 21:30:59"
  condition:
    hash.sha256(0, filesize) == "752816328ef0c903baea78bc49a1aa8047f248758d91d4c903bad82546706d97"
}

rule MalwareBazaar_Vidar_080_91b2d597
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91b2d597575f74009b8502c77279761cea8635606e7ca1fd146fb1a4a3127785"
    family = "Vidar"
    file_name = "91b2d597575f74009b8502c77279761cea8635606e7ca1fd146fb1a4a3127785.bin"
    file_type = "exe"
    first_seen = "2026-08-12 21:30:22"
  condition:
    hash.sha256(0, filesize) == "91b2d597575f74009b8502c77279761cea8635606e7ca1fd146fb1a4a3127785"
}

rule MalwareBazaar_unknown_081_68ef1df7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68ef1df7c303a4600df13103cbb093cd11e59775b39f5dbe391a28394191b45f"
    family = "unknown"
    file_name = "68ef1df7c303a4600df13103cbb093cd11e59775b39f5dbe391a28394191b45f.bin"
    file_type = "exe"
    first_seen = "2026-08-12 21:30:20"
  condition:
    hash.sha256(0, filesize) == "68ef1df7c303a4600df13103cbb093cd11e59775b39f5dbe391a28394191b45f"
}

rule MalwareBazaar_Vidar_082_b218bc61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b218bc6125777b170bbefe4f0e761c94232d8ca6ae4ce9cb7b40124a72ba2cb4"
    family = "Vidar"
    file_name = "b218bc6125777b170bbefe4f0e761c94232d8ca6ae4ce9cb7b40124a72ba2cb4.bin"
    file_type = "exe"
    first_seen = "2026-08-12 21:30:17"
  condition:
    hash.sha256(0, filesize) == "b218bc6125777b170bbefe4f0e761c94232d8ca6ae4ce9cb7b40124a72ba2cb4"
}

rule MalwareBazaar_Mirai_083_db16dd04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db16dd04af5c8c11941a314ddf0810a153e4f95e95477dadc9f6f35acf34c629"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-12 21:20:57"
  condition:
    hash.sha256(0, filesize) == "db16dd04af5c8c11941a314ddf0810a153e4f95e95477dadc9f6f35acf34c629"
}

rule MalwareBazaar_unknown_084_6fd1c8e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fd1c8e3daedfe0ff0c6ec7e4f0bf4d085cdb17b0230f13b6d33496785a9c9cb"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-12 21:14:55"
  condition:
    hash.sha256(0, filesize) == "6fd1c8e3daedfe0ff0c6ec7e4f0bf4d085cdb17b0230f13b6d33496785a9c9cb"
}

rule MalwareBazaar_unknown_085_cb68c082
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb68c082c22d3f2751ded48b1fa24d079ef1378bb7352353634b2ccb6985c44e"
    family = "unknown"
    file_name = "cb68c082c22d3f2751ded48b1fa24d079ef1378bb7352353634b2ccb6985c44e.bin"
    file_type = "exe"
    first_seen = "2026-08-12 20:59:58"
  condition:
    hash.sha256(0, filesize) == "cb68c082c22d3f2751ded48b1fa24d079ef1378bb7352353634b2ccb6985c44e"
}

rule MalwareBazaar_unknown_086_2e7dc6d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e7dc6d8f996729e1091bc4886d5baaf3a7a36f8f45617e1ef9101fb5ec778e5"
    family = "unknown"
    file_name = "2e7dc6d8f996729e1091bc4886d5baaf3a7a36f8f45617e1ef9101fb5ec778e5.bin"
    file_type = "exe"
    first_seen = "2026-08-12 20:59:56"
  condition:
    hash.sha256(0, filesize) == "2e7dc6d8f996729e1091bc4886d5baaf3a7a36f8f45617e1ef9101fb5ec778e5"
}

rule MalwareBazaar_Vidar_087_124c9272
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "124c9272f072151529a74124a04fb27b1890a37c2149242eeab006d6244d61bf"
    family = "Vidar"
    file_name = "124c9272f072151529a74124a04fb27b1890a37c2149242eeab006d6244d61bf.bin"
    file_type = "exe"
    first_seen = "2026-08-12 20:59:54"
  condition:
    hash.sha256(0, filesize) == "124c9272f072151529a74124a04fb27b1890a37c2149242eeab006d6244d61bf"
}

rule MalwareBazaar_unknown_088_71883121
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71883121b2f9a24a74c37974317962160b3af5bd1146d8ae8307c3d28c75a2e8"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-12 20:52:11"
  condition:
    hash.sha256(0, filesize) == "71883121b2f9a24a74c37974317962160b3af5bd1146d8ae8307c3d28c75a2e8"
}

rule MalwareBazaar_AsyncRAT_089_0ef3bf87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ef3bf87332779d4b37885eaa23e12fe0e7bf597da7356718eed8691377eb999"
    family = "AsyncRAT"
    file_name = "QH88APP.exe"
    file_type = "exe"
    first_seen = "2026-08-12 20:50:26"
  condition:
    hash.sha256(0, filesize) == "0ef3bf87332779d4b37885eaa23e12fe0e7bf597da7356718eed8691377eb999"
}

rule MalwareBazaar_Mirai_090_0352a081
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0352a0814d2244b9568cf2b051222f2034760cf228618529371fa7d3b86050da"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-12 20:45:40"
  condition:
    hash.sha256(0, filesize) == "0352a0814d2244b9568cf2b051222f2034760cf228618529371fa7d3b86050da"
}

rule MalwareBazaar_Mirai_091_b3a39b3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3a39b3cc853d62505eaf57f5d9480f8396dc7a3888846a09fb277e797551182"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-12 20:39:18"
  condition:
    hash.sha256(0, filesize) == "b3a39b3cc853d62505eaf57f5d9480f8396dc7a3888846a09fb277e797551182"
}

rule MalwareBazaar_unknown_092_88174718
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88174718adac0d95c5c2d87eab47b63d8b135dcec6c77b5962d9cc2c1433204e"
    family = "unknown"
    file_name = "Invoice_Adobe_installer.msi"
    file_type = "msi"
    first_seen = "2026-08-12 20:34:20"
  condition:
    hash.sha256(0, filesize) == "88174718adac0d95c5c2d87eab47b63d8b135dcec6c77b5962d9cc2c1433204e"
}

rule MalwareBazaar_Vidar_093_e8e3cbd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8e3cbd3e99636bbd54efb8e62b07f8c53a79c23a968a6252317d5c2db8e3248"
    family = "Vidar"
    file_name = "e8e3cbd3e99636bbd54efb8e62b07f8c53a79c23a968a6252317d5c2db8e3248.bin"
    file_type = "exe"
    first_seen = "2026-08-12 20:29:39"
  condition:
    hash.sha256(0, filesize) == "e8e3cbd3e99636bbd54efb8e62b07f8c53a79c23a968a6252317d5c2db8e3248"
}

rule MalwareBazaar_CoinMiner_094_6acdd717
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6acdd71730d33689acaad80591691c6cbd3d653656c628fcc0ff8400ac75324c"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-12 20:20:46"
  condition:
    hash.sha256(0, filesize) == "6acdd71730d33689acaad80591691c6cbd3d653656c628fcc0ff8400ac75324c"
}

rule MalwareBazaar_Mirai_095_1814a523
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1814a5238c648088ddb3a7d82c2408bd815be81ecafbff11f43c84fe5be5f4eb"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-12 20:18:42"
  condition:
    hash.sha256(0, filesize) == "1814a5238c648088ddb3a7d82c2408bd815be81ecafbff11f43c84fe5be5f4eb"
}

rule MalwareBazaar_Mirai_096_0ee582d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ee582d0460ecb4088c37d41e4c3c3743c5a842aaef2f8adf1f036b74005b2ca"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-12 20:18:01"
  condition:
    hash.sha256(0, filesize) == "0ee582d0460ecb4088c37d41e4c3c3743c5a842aaef2f8adf1f036b74005b2ca"
}

rule MalwareBazaar_Mirai_097_cd69aa2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd69aa2c38616f4f759476e47d98a5d1d0d761d193d73360e309d255fd327985"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-12 20:13:27"
  condition:
    hash.sha256(0, filesize) == "cd69aa2c38616f4f759476e47d98a5d1d0d761d193d73360e309d255fd327985"
}

rule MalwareBazaar_unknown_098_86853a0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86853a0c9272afe15734577c5a7a14a5f98632b89aa986945e3bed3aa0c39b72"
    family = "unknown"
    file_name = "86853a0c9272afe15734577c5a7a14a5f98632b89aa986945e3bed3aa0c39b72"
    file_type = "elf"
    first_seen = "2026-08-12 20:08:29"
  condition:
    hash.sha256(0, filesize) == "86853a0c9272afe15734577c5a7a14a5f98632b89aa986945e3bed3aa0c39b72"
}

rule MalwareBazaar_Mirai_099_ac5b3f3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac5b3f3e20bf74fb25ed3caa8856deb61f8e44d691b955402421621a50801c7b"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-12 20:05:16"
  condition:
    hash.sha256(0, filesize) == "ac5b3f3e20bf74fb25ed3caa8856deb61f8e44d691b955402421621a50801c7b"
}

rule MalwareBazaar_unknown_100_8eaa8e6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8eaa8e6cc4ddc443d7a8b81dcaf07d86531995c34b83b5f91b77817bf2c5182b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-12 20:02:31"
  condition:
    hash.sha256(0, filesize) == "8eaa8e6cc4ddc443d7a8b81dcaf07d86531995c34b83b5f91b77817bf2c5182b"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-01

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 684 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 684 |
| Unique family labels | 11 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 63 |
| Mirai | 23 |
| CoinMiner | 4 |
| ValleyRAT | 2 |
| RustyStealer | 2 |
| NanoCore | 1 |
| RaspberryRobin | 1 |
| Tofsee | 1 |
| AokigaharaStealer | 1 |
| WannaCry | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 42 |
| elf | 28 |
| macho | 7 |
| zip | 6 |
| hta | 5 |
| msi | 3 |
| sh | 2 |
| dll | 2 |
| ps1 | 2 |
| iso | 1 |

## Per-Sample Analysis

### Sample 1: `981ff25c886308d5`

| Field | Value |
|---|---|
| SHA-256 | `981ff25c886308d5350b4446184f14406be6cc01186bb19ebf0de8cf843e392f` |
| Family label | `unknown` |
| File name | `macho_981ff25c8863.bin` |
| File type | `macho` |
| First seen | `2026-11-01 05:57:47` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa90dc518e8abb2a4a7815701f80150e` |
| SHA-1 | `76419eb299841dead28771d2c0e57090ba10bd3a` |
| SHA-256 | `981ff25c886308d5350b4446184f14406be6cc01186bb19ebf0de8cf843e392f` |
| SHA3-384 | `5a4bee5bd710ae7cc37537e753730dcd2d168a4416a701002f9c521132cbe6c9ca625d2a0fd87f0dccb14ff02fb4a3d3` |
| TLSH | `T17D8502009B3755E6E4B770729F288F1554E0AE809A5B6BF8612DF31F2D36753B263223` |
| SSDEEP | `24576:xHSpP3BpNqjokqXwjYna2F0W/bHm2jb9+cDDVKQQWS/MfEtKIk6j6Z8/UurwWXLR:uBpNq4P39+cDDVfY/3jH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_981ff25c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "981ff25c886308d5350b4446184f14406be6cc01186bb19ebf0de8cf843e392f"
    family = "unknown"
    file_name = "macho_981ff25c8863.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:57:47"
  condition:
    hash.sha256(0, filesize) == "981ff25c886308d5350b4446184f14406be6cc01186bb19ebf0de8cf843e392f"
}
```

### Sample 2: `8aa9c73475a64d9d`

| Field | Value |
|---|---|
| SHA-256 | `8aa9c73475a64d9d5ef62124ff91f6de00eac4ccf9258152bd795a808a17eecb` |
| Family label | `unknown` |
| File name | `macho_8aa9c73475a6.bin` |
| File type | `macho` |
| First seen | `2026-11-01 05:49:34` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0676e18f2e4c1cd44458abba96a4eef6` |
| SHA-1 | `3f253f4bc1afa1c9416951ba48cd01d68a75ed1f` |
| SHA-256 | `8aa9c73475a64d9d5ef62124ff91f6de00eac4ccf9258152bd795a808a17eecb` |
| SHA3-384 | `acecabe30dda94aa7e9eb1fbd841fc34b25e95a48d8e6883f810b005a08a34aaa5dcbf8067e79b632c19828de2cd8828` |
| TLSH | `T1ACA5E1408E6A5187C59A2073AC8B8F59857431A1CF84CEE96341A3DACE3A7D377931F7` |
| SSDEEP | `49152:tP0mkYPTBKiiBE1rNR91+/K+an2B3OgzY+zhgpmhx6QewZiBHTSQNKnFuSmjgzko:qSBETHro2mZY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_8aa9c734
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8aa9c73475a64d9d5ef62124ff91f6de00eac4ccf9258152bd795a808a17eecb"
    family = "unknown"
    file_name = "macho_8aa9c73475a6.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:49:34"
  condition:
    hash.sha256(0, filesize) == "8aa9c73475a64d9d5ef62124ff91f6de00eac4ccf9258152bd795a808a17eecb"
}
```

### Sample 3: `ff19f83f177ee4ea`

| Field | Value |
|---|---|
| SHA-256 | `ff19f83f177ee4eac22c9fa447e932e56f5a91032c130a8bd30b69e0f7eed3d5` |
| Family label | `unknown` |
| File name | `macho_ff19f83f177e.bin` |
| File type | `macho` |
| First seen | `2026-11-01 05:44:20` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d684b2d2eb3bb9295994c9262fdbfcfe` |
| SHA-1 | `e73243e8ae84151d511839f644444f23bce50521` |
| SHA-256 | `ff19f83f177ee4eac22c9fa447e932e56f5a91032c130a8bd30b69e0f7eed3d5` |
| SHA3-384 | `aa69c92cdd5deabfc3781e00c2dc12bae9eb4aa7f9f29df5ba32776903710e63d3885ed3412a50cda6bbbed34ecf9684` |
| TLSH | `T1FFA5E0108D1F619BD40621339C9A0F5942F068D0CD0DEEE95391B7A6EE3B397BB522B7` |
| SSDEEP | `49152:n0HCSXcZU9MVcDWc9LWBJmaKfidKkxSZUVetp:0HMZmow` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_ff19f83f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff19f83f177ee4eac22c9fa447e932e56f5a91032c130a8bd30b69e0f7eed3d5"
    family = "unknown"
    file_name = "macho_ff19f83f177e.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:44:20"
  condition:
    hash.sha256(0, filesize) == "ff19f83f177ee4eac22c9fa447e932e56f5a91032c130a8bd30b69e0f7eed3d5"
}
```

### Sample 4: `42949634a09db058`

| Field | Value |
|---|---|
| SHA-256 | `42949634a09db058449c1c51a80ebfbad074ea1a6b6f14a583604a138a9f561b` |
| Family label | `unknown` |
| File name | `macho_42949634a09d.bin` |
| File type | `macho` |
| First seen | `2026-11-01 05:32:48` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b25a646b14ccac14e6d76aeb10746d7d` |
| SHA-1 | `3d3af45188bd6516c2038b895cf77b37c5244186` |
| SHA-256 | `42949634a09db058449c1c51a80ebfbad074ea1a6b6f14a583604a138a9f561b` |
| SHA3-384 | `e3d1ff4703e57a1871bbf01d2af4703e01d577c6a21cd7c86460ba4060fbd772f52c33a078f68589b6fe7e39ab1097b7` |
| TLSH | `T17AA5F1141636622AF1423133A91E0FC925A03AF5785CB9F66B25D72A7D37AD3B463333` |
| SSDEEP | `24576:nemaGunUip6I25YFDQfW3H0tx/iyKPHsJ76YHLAD0AeeB+xfoohnXVFRUDFzQxgF:ecin+jtxBKkXHLOd7BSnhzuDuz95ZSiy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_42949634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42949634a09db058449c1c51a80ebfbad074ea1a6b6f14a583604a138a9f561b"
    family = "unknown"
    file_name = "macho_42949634a09d.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:32:48"
  condition:
    hash.sha256(0, filesize) == "42949634a09db058449c1c51a80ebfbad074ea1a6b6f14a583604a138a9f561b"
}
```

### Sample 5: `1ec9297709a225f9`

| Field | Value |
|---|---|
| SHA-256 | `1ec9297709a225f912fc7145f43654bc1a6b61e56c9684bf22c6aaf0fad98289` |
| Family label | `unknown` |
| File name | `macho_1ec9297709a2.bin` |
| File type | `macho` |
| First seen | `2026-11-01 05:31:11` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e41f974d4a1044a8d773581058e5709` |
| SHA-1 | `6e5f9285e81d37819cf539b7d3dc308d1a5c0633` |
| SHA-256 | `1ec9297709a225f912fc7145f43654bc1a6b61e56c9684bf22c6aaf0fad98289` |
| SHA3-384 | `f9bf627688ec58fd62b04c6394856babaeda721d7ddacb7f1a17ea055e919a9c493b98858be12796a681651872c36a3b` |
| TLSH | `T11285F2240276A239E3021531AD304BD95894AFB1A97DF9F76F64DB623F31583A4623F3` |
| SSDEEP | `24576:QHQWcfIy2uaL2gM8Az6j3yE63Qz90iMqxR9/NshK4z2OAMmxm3BSOmPu9Xc0P:QWs2gM8Az6nX+m8K4z2GYmB9DP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_1ec92977
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ec9297709a225f912fc7145f43654bc1a6b61e56c9684bf22c6aaf0fad98289"
    family = "unknown"
    file_name = "macho_1ec9297709a2.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:31:11"
  condition:
    hash.sha256(0, filesize) == "1ec9297709a225f912fc7145f43654bc1a6b61e56c9684bf22c6aaf0fad98289"
}
```

### Sample 6: `95b3a52bad5da046`

| Field | Value |
|---|---|
| SHA-256 | `95b3a52bad5da0468d6af8a8c56e0ca7e307c2c0151f2531903e27c49458d308` |
| Family label | `unknown` |
| File name | `macho_95b3a52bad5d.bin` |
| File type | `macho` |
| First seen | `2026-11-01 05:29:33` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0434c3a935d370719a6afe99c9789ddc` |
| SHA-1 | `7de6fef624099635ed2980d0ac18eab72e4e4e57` |
| SHA-256 | `95b3a52bad5da0468d6af8a8c56e0ca7e307c2c0151f2531903e27c49458d308` |
| SHA3-384 | `604f4abbb7c782480e349356402073952ce378ed4014c9af3533a5419f9050c56dfff100a3fa22fd126a04d56e523098` |
| TLSH | `T1C995F1404E9EA216D48D01739DC68B1844B871E0CE49CDEA6342A39ADE3D3D777672FB` |
| SSDEEP | `24576:MLCipMl9aXjJ5qroccj5vcBXTEal0JwcV4KxlCR8DRMqepnJfaL7HP0X6MSx5XgB:MwnazJj5OSbw8DRMqeXan1xx+S4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_95b3a52b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95b3a52bad5da0468d6af8a8c56e0ca7e307c2c0151f2531903e27c49458d308"
    family = "unknown"
    file_name = "macho_95b3a52bad5d.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:29:33"
  condition:
    hash.sha256(0, filesize) == "95b3a52bad5da0468d6af8a8c56e0ca7e307c2c0151f2531903e27c49458d308"
}
```

### Sample 7: `faf25e8e778647de`

| Field | Value |
|---|---|
| SHA-256 | `faf25e8e778647deb0d0b30927eeaae9bc2d860cc317bb2d76ab48e84e82a001` |
| Family label | `Mirai` |
| File name | `nyx_bot_linux_amd64` |
| File type | `elf` |
| First seen | `2026-11-01 05:29:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ca299ae111de0fd8e8e1aa66c631622` |
| SHA-1 | `12192204563ce845391d12d3809b6e86ca0dd551` |
| SHA-256 | `faf25e8e778647deb0d0b30927eeaae9bc2d860cc317bb2d76ab48e84e82a001` |
| SHA3-384 | `f6bd64ea8c601ef26fe759a73d46703d88623f90b53b3a70b081714c1297fc619a33cfb58da67268a140d7b8729d17e1` |
| TLSH | `T120564B13EC9555E9C2AEE2308A629162BA717C496B3123D33F50F7782F73BD06A79740` |
| TELFHASH | `t132226a745dbc75b4b696da10b3a3b5b4967718a166f838b11023ad80ffc1e801ce6c7b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:UyOFD/aByTvnRsRgmNlNpUw//wwb2ZImET:UyE/iyTKlT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_faf25e8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faf25e8e778647deb0d0b30927eeaae9bc2d860cc317bb2d76ab48e84e82a001"
    family = "Mirai"
    file_name = "nyx_bot_linux_amd64"
    file_type = "elf"
    first_seen = "2026-11-01 05:29:20"
  condition:
    hash.sha256(0, filesize) == "faf25e8e778647deb0d0b30927eeaae9bc2d860cc317bb2d76ab48e84e82a001"
}
```

### Sample 8: `6ee52429a22ee09c`

| Field | Value |
|---|---|
| SHA-256 | `6ee52429a22ee09c723794eaa590cd4f08a4109d5e3bd9bb7e71f94de3e3851a` |
| Family label | `unknown` |
| File name | `macho_6ee52429a22e.bin` |
| File type | `macho` |
| First seen | `2026-11-01 05:28:56` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f6efbda20e31b987715892d44fb5ac8` |
| SHA-1 | `392881ee7f69674abb59e4eda54d33edd3fa9807` |
| SHA-256 | `6ee52429a22ee09c723794eaa590cd4f08a4109d5e3bd9bb7e71f94de3e3851a` |
| SHA3-384 | `ca768291a2c3636bd79f2c4549d4555b5bf7195a70c6082d9cd1c046d5573ef606cb6a1df84251efc241511e8a94ae34` |
| TLSH | `T13B8501241F3A4256EC876033EC144F9756A0BF889B8CE6F96225C7237E35613F6A7325` |
| SSDEEP | `24576:ddiHPuw8PkmdsrMV6ejmQU5kxTgNIzbhw5xCvYMUaIfMlRjVRQ2+NArTgNIe:i4n7eAbhw5AvYMUVCZFeP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_6ee52429
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee52429a22ee09c723794eaa590cd4f08a4109d5e3bd9bb7e71f94de3e3851a"
    family = "unknown"
    file_name = "macho_6ee52429a22e.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:28:56"
  condition:
    hash.sha256(0, filesize) == "6ee52429a22ee09c723794eaa590cd4f08a4109d5e3bd9bb7e71f94de3e3851a"
}
```

### Sample 9: `f9b3091f6fd32546`

| Field | Value |
|---|---|
| SHA-256 | `f9b3091f6fd32546606eb05dec4cbccf331df02c15da8d2f5bc760ee06197a4f` |
| Family label | `Mirai` |
| File name | `f9b3091f6fd32546606eb05dec4cbccf331df02c15da8d2f5bc760ee06197a4f.elf` |
| File type | `elf` |
| First seen | `2026-11-01 05:20:09` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f27b51b9e7487e382c53ea66ecc244f5` |
| SHA-1 | `5d218872c610b7e7097c6b20be2ccec6479090f5` |
| SHA-256 | `f9b3091f6fd32546606eb05dec4cbccf331df02c15da8d2f5bc760ee06197a4f` |
| SHA3-384 | `0ba8c3525f440852b2f2fc31ebe40ba376389891c6a980c4b9b531213f42fcdb9e72cb43d975d1b3a9562d697c89c4e2` |
| TLSH | `T146B36CC5F743E4F5ED5742B1513AE7728B73E83A002DEA43C768A936E85A500DA0B35E` |
| TELFHASH | `t1f15128fb2a7a4de897d49801c30e9b616e1de77b146037b24633d825335ad8242bbc79` |
| SSDEEP | `1536:j5BVDvE37+mRmipxWaTY764+CcPgkfNoC0zQCqFJlmBPIO11JSB8Vwb72:HVDU7+mRmipxhy64+LdCzHGJgBhAr72` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_f9b3091f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9b3091f6fd32546606eb05dec4cbccf331df02c15da8d2f5bc760ee06197a4f"
    family = "Mirai"
    file_name = "f9b3091f6fd32546606eb05dec4cbccf331df02c15da8d2f5bc760ee06197a4f.elf"
    file_type = "elf"
    first_seen = "2026-11-01 05:20:09"
  condition:
    hash.sha256(0, filesize) == "f9b3091f6fd32546606eb05dec4cbccf331df02c15da8d2f5bc760ee06197a4f"
}
```

### Sample 10: `cca729f2af3ca462`

| Field | Value |
|---|---|
| SHA-256 | `cca729f2af3ca4622d1e23f2c149ae2ea7d50b52f4ed729cf3eba33b4fd605c1` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-01 04:37:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b0368fe7be980caaa99a5a67af9de52` |
| SHA-1 | `df02cd27b7151b53a517a82daa3bbb03b7622841` |
| SHA-256 | `cca729f2af3ca4622d1e23f2c149ae2ea7d50b52f4ed729cf3eba33b4fd605c1` |
| SHA3-384 | `2e83a4f7d3c3ebdbb129998b20e98f6f48f305028a8b0fe3dc6d6e7822dbf41be0f9fa74045bc91b690dd9b95e266af6` |
| TLSH | `T12F556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSZ:SDjxB4m5n8XlaPWi+d+a4TjxQP4f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_cca729f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cca729f2af3ca4622d1e23f2c149ae2ea7d50b52f4ed729cf3eba33b4fd605c1"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-01 04:37:53"
  condition:
    hash.sha256(0, filesize) == "cca729f2af3ca4622d1e23f2c149ae2ea7d50b52f4ed729cf3eba33b4fd605c1"
}
```

### Sample 11: `cfa2bac42af30c73`

| Field | Value |
|---|---|
| SHA-256 | `cfa2bac42af30c732cda9939159c3f41996cf074c2f7f3e3b21d38d944ff3e0e` |
| Family label | `unknown` |
| File name | `cfa2bac42af30c732cda9939159c3f41996cf074c2f7f3e3b21d38d944ff3e0e.sh` |
| File type | `sh` |
| First seen | `2026-11-01 04:09:26` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea9cfaab1508cc7c8a2174e46c4bcb83` |
| SHA-1 | `9c0906737b3aeaa0e2b6f4373f4ec0bddb7a13ce` |
| SHA-256 | `cfa2bac42af30c732cda9939159c3f41996cf074c2f7f3e3b21d38d944ff3e0e` |
| SHA3-384 | `028d33c8f2a076e7d0b7e3fabdd393153b7499cefdc64d39939f1e8c6605a057cd719d3b73eb02ea128f43c93c939e7f` |
| TLSH | `T10702113B11F08B72D7C421C9526656A54E72A70B992A14F8F4BF573A9F2DA0330E7B30` |
| SSDEEP | `96:cCuwKB657sht+O+v1fsn+h4+tIicqbA/GsGsioVbeez4b:cCuwu65C4hvZ5mzjBk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_cfa2bac4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfa2bac42af30c732cda9939159c3f41996cf074c2f7f3e3b21d38d944ff3e0e"
    family = "unknown"
    file_name = "cfa2bac42af30c732cda9939159c3f41996cf074c2f7f3e3b21d38d944ff3e0e.sh"
    file_type = "sh"
    first_seen = "2026-11-01 04:09:26"
  condition:
    hash.sha256(0, filesize) == "cfa2bac42af30c732cda9939159c3f41996cf074c2f7f3e3b21d38d944ff3e0e"
}
```

### Sample 12: `ae278113941181d7`

| Field | Value |
|---|---|
| SHA-256 | `ae278113941181d7e1bcac838910e29667527f6388bfab8b543fcb46827df3b6` |
| Family label | `unknown` |
| File name | `install.1.2.04.exe` |
| File type | `exe` |
| First seen | `2026-11-01 03:50:03` |
| Reporter | `CNGaoLing` |
| Tags | `exe, PatchedHostLoader, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3e66b983ee18aff63a9c1eee05ad73a` |
| SHA-1 | `c9ac73e97de2f1add078d692bec63206f2f3755a` |
| SHA-256 | `ae278113941181d7e1bcac838910e29667527f6388bfab8b543fcb46827df3b6` |
| SHA3-384 | `09f656046a4a061e61640ed24018cbe4ff000c298d1a44030f281b015507d5b7c4ee66f2a48b60d91f538df57c6acccc` |
| IMPHASH | `20abbe0f6ab059ea4a375bcb6b8a717b` |
| TLSH | `T113770646FA414DD2F85846F588ABB7A023FEBD7582D1C30721D87325AFAF29C0E93195` |
| SSDEEP | `196608:AqEfM3r4vGOgAVAiZfFK0SBqtiEPFNPTN:g6qpx` |
| ICON-DHASH | `009269ecd4d42900` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_ae278113
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae278113941181d7e1bcac838910e29667527f6388bfab8b543fcb46827df3b6"
    family = "unknown"
    file_name = "install.1.2.04.exe"
    file_type = "exe"
    first_seen = "2026-11-01 03:50:03"
  condition:
    hash.sha256(0, filesize) == "ae278113941181d7e1bcac838910e29667527f6388bfab8b543fcb46827df3b6"
}
```

### Sample 13: `36f6f9331b5efe71`

| Field | Value |
|---|---|
| SHA-256 | `36f6f9331b5efe7124f043b8a3b922a6c4df5cb3cf37cb14827baab47aa70c7c` |
| Family label | `unknown` |
| File name | `install.1.2.03.exe` |
| File type | `exe` |
| First seen | `2026-11-01 03:49:12` |
| Reporter | `CNGaoLing` |
| Tags | `exe, PatchedHostLoader, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28082ae3d4df7758dbf0a6a27d8d0fb5` |
| SHA-1 | `bc869e74bc2db6a25d6a798210a5bcfbeef1e333` |
| SHA-256 | `36f6f9331b5efe7124f043b8a3b922a6c4df5cb3cf37cb14827baab47aa70c7c` |
| SHA3-384 | `2ae3db85e41837f2f8779060045e6cc752d401363d17c9b00b6b1cabd1cfdae01b99c25933d33e25710636ef42a502de` |
| IMPHASH | `20abbe0f6ab059ea4a375bcb6b8a717b` |
| TLSH | `T16C770646FA414DD2F85846F588ABB7A023FEBD7582D1C30721D87325AFAF29C0E93195` |
| SSDEEP | `196608:PqEfM3r4vGOgAVAiZfFK0SBqtiEPFNPTP:n6qpr` |
| ICON-DHASH | `009269ecd4d42900` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_36f6f933
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36f6f9331b5efe7124f043b8a3b922a6c4df5cb3cf37cb14827baab47aa70c7c"
    family = "unknown"
    file_name = "install.1.2.03.exe"
    file_type = "exe"
    first_seen = "2026-11-01 03:49:12"
  condition:
    hash.sha256(0, filesize) == "36f6f9331b5efe7124f043b8a3b922a6c4df5cb3cf37cb14827baab47aa70c7c"
}
```

### Sample 14: `eaa1e4a9281a7711`

| Field | Value |
|---|---|
| SHA-256 | `eaa1e4a9281a77116892f2ca249ac07f123a96a148afe2dbf1a9d3080fc834d6` |
| Family label | `Mirai` |
| File name | `main_arm6` |
| File type | `elf` |
| First seen | `2026-11-01 03:24:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3b6fa4a9f1d15c2a7184fdbdf7f1252` |
| SHA-1 | `086767aeb1d224164683084adfb916b726a05048` |
| SHA-256 | `eaa1e4a9281a77116892f2ca249ac07f123a96a148afe2dbf1a9d3080fc834d6` |
| SHA3-384 | `a9abfcd925677fdbb8a61f389ffb43a27315b62caa0ef579cd184e21319185020e8880f880237ae00195722a39bc228a` |
| TLSH | `T170F31956B8819B11D5D112BEFE1E028E33231B7CE3DE72069E246F24778A97B0E3B515` |
| TELFHASH | `t129d09762f3c0163cebf42828e04023207fb83a5a032530870aee3e638d86000f41020b` |
| SSDEEP | `3072:9DIofxMlC0HEnBKo4kmU9jbwWXsEbpGKaD/cvJRiXN8R70wUe8/473:yAMlPknBKo47WoWX9bp5aYBYN8SwUe84` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_eaa1e4a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaa1e4a9281a77116892f2ca249ac07f123a96a148afe2dbf1a9d3080fc834d6"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-11-01 03:24:11"
  condition:
    hash.sha256(0, filesize) == "eaa1e4a9281a77116892f2ca249ac07f123a96a148afe2dbf1a9d3080fc834d6"
}
```

### Sample 15: `c363b0179cbd5428`

| Field | Value |
|---|---|
| SHA-256 | `c363b0179cbd542865af005d2cc861525e5a5fdb2cd955eeb45741e99690be45` |
| Family label | `unknown` |
| File name | `c363b0179cbd542865af005d2cc861525e5a5fdb2cd955eeb45741e99690be45` |
| File type | `sh` |
| First seen | `2026-11-01 03:08:47` |
| Reporter | `spydisec` |
| Tags | `cowrie, dropper, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7ed22228f576467125ee6310fb4ad3b` |
| SHA-1 | `9b1816a90f27ca74ab4a109b08057bdf3020c6a6` |
| SHA-256 | `c363b0179cbd542865af005d2cc861525e5a5fdb2cd955eeb45741e99690be45` |
| SHA3-384 | `49f1735a021fa40be7096c368e6c0c556d912d46503eb85309d5659ed89c100b5727b0d07f798f6577d3e00ecc6b7d6d` |
| TLSH | `T19F5100F5B8A0ED317805583C6BDBA264A946083B08283C52F4DFAC347F2C8947174BBA` |
| SSDEEP | `48:z72b17U7ZC9up+xCmv8jrQWJysOQc5cnNoGOb3U7UzCUMzCUICUWTJAJR8lVJD8I:WmO4rdQWJyO6bJyUiJVUo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_c363b017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c363b0179cbd542865af005d2cc861525e5a5fdb2cd955eeb45741e99690be45"
    family = "unknown"
    file_name = "c363b0179cbd542865af005d2cc861525e5a5fdb2cd955eeb45741e99690be45"
    file_type = "sh"
    first_seen = "2026-11-01 03:08:47"
  condition:
    hash.sha256(0, filesize) == "c363b0179cbd542865af005d2cc861525e5a5fdb2cd955eeb45741e99690be45"
}
```

### Sample 16: `fcb12e0ae3f50e17`

| Field | Value |
|---|---|
| SHA-256 | `fcb12e0ae3f50e171a814269e3c8174c613204b40d64bfb855d93668517104ba` |
| Family label | `Mirai` |
| File name | `fcb12e0ae3f50e17.bin` |
| File type | `elf` |
| First seen | `2026-11-01 02:23:57` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad41a1b90c3599466c69a900be7e97e8` |
| SHA-1 | `fdf2e2a9e828652683b64aa8b0b5d5b84ea485d3` |
| SHA-256 | `fcb12e0ae3f50e171a814269e3c8174c613204b40d64bfb855d93668517104ba` |
| SHA3-384 | `36f5f1008dc756f40b0cbde421a34268e2371baffbcbfd686e011a07760c5c1f93a0e563b916a1dff0488de872e12c49` |
| TLSH | `T1FC966B97B9925957C5E43677ACBE80C433634EBA8BC753566D05FA3C3ABE1980E38304` |
| TELFHASH | `t1442453a3cc66bf5b4fc403229cf5d5c49397d04708926b986fb08336d4eb48da5ba35a` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:rzaKI2c6Ha1d+n3qcE+rSEm1a9HcfvRBsnUE53Zz4GmHIHfOt:PaKI76Ha+qcHr/V2RmUE6IHfc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_fcb12e0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcb12e0ae3f50e171a814269e3c8174c613204b40d64bfb855d93668517104ba"
    family = "Mirai"
    file_name = "fcb12e0ae3f50e17.bin"
    file_type = "elf"
    first_seen = "2026-11-01 02:23:57"
  condition:
    hash.sha256(0, filesize) == "fcb12e0ae3f50e171a814269e3c8174c613204b40d64bfb855d93668517104ba"
}
```

### Sample 17: `95cca0c53fb872f2`

| Field | Value |
|---|---|
| SHA-256 | `95cca0c53fb872f2133364e7590d816a39983bf7aacab30768472cd45845ddfb` |
| Family label | `NanoCore` |
| File name | `B923F381A98DEAFF472A4BD021172712.exe` |
| File type | `exe` |
| First seen | `2026-11-01 02:20:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b923f381a98deaff472a4bd021172712` |
| SHA-1 | `28a02d39b6441caf1d54b4e16941cced822a397e` |
| SHA-256 | `95cca0c53fb872f2133364e7590d816a39983bf7aacab30768472cd45845ddfb` |
| SHA3-384 | `dda6d611c97606eb2fa4b70b1af3255070731a37413e52d3154151c03aceb028e514d965fce309fb75778549e96dcbdf` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18B14CF1A77A94A2FE2DE8AB9611212579379C2E3D8C3F3EF28D454B34B163E506071D3` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5FMluAJDAxGJg09osM:MLV6Btpmk2RAioJgzr` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_017_95cca0c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95cca0c53fb872f2133364e7590d816a39983bf7aacab30768472cd45845ddfb"
    family = "NanoCore"
    file_name = "B923F381A98DEAFF472A4BD021172712.exe"
    file_type = "exe"
    first_seen = "2026-11-01 02:20:07"
  condition:
    hash.sha256(0, filesize) == "95cca0c53fb872f2133364e7590d816a39983bf7aacab30768472cd45845ddfb"
}
```

### Sample 18: `b37413c715212c65`

| Field | Value |
|---|---|
| SHA-256 | `b37413c715212c655c328e99657f9a50bdcaf7366f74935fe232663a5d156698` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-11-01 02:15:17` |
| Reporter | `josie` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74258b8aaf517905f3435bc463a509db` |
| SHA-1 | `3da364aa03414851fbd5f08be8ebac6bae10e0d6` |
| SHA-256 | `b37413c715212c655c328e99657f9a50bdcaf7366f74935fe232663a5d156698` |
| SHA3-384 | `69b7e6ea8923ff815b23067e06c05265c20ea5ddbc970e939bd04443fa3a7868b082d76e95d1e8f808ce9b3e7fa9b6be` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1DE466D07FDA155AAC4AAA634C4A752027BB47C8C6B3173D32F40F6382E767D05EB9B05` |
| SSDEEP | `49152:1qXCj/r+coZmubGiihg2JaEnNVxOTQPPY7+qTIiv9NCtfb+q9XuCs1f7FPOVY6:11nO6QNTvjWfyCgT+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_b37413c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b37413c715212c655c328e99657f9a50bdcaf7366f74935fe232663a5d156698"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-01 02:15:17"
  condition:
    hash.sha256(0, filesize) == "b37413c715212c655c328e99657f9a50bdcaf7366f74935fe232663a5d156698"
}
```

### Sample 19: `077cae04215aca2c`

| Field | Value |
|---|---|
| SHA-256 | `077cae04215aca2c742ceaf837fd8293671c9b0fa9b58de0e8bb106072796482` |
| Family label | `unknown` |
| File name | `077cae04215aca2c742ceaf837fd8293671c9b0fa9b58de0e8bb106072796482.exe` |
| File type | `exe` |
| First seen | `2026-11-01 01:49:00` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0bafbe71a1349214e838f6ff93cd2b2` |
| SHA-1 | `1788cf1464f107db9bc4c113ac53810b665c300f` |
| SHA-256 | `077cae04215aca2c742ceaf837fd8293671c9b0fa9b58de0e8bb106072796482` |
| SHA3-384 | `bce71bac3b3d2c7814180c3427f6591d2f874ac58e90b90976ee11d97b5b1284869c64ae118558651f9695f5be35c24d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11622E70577F45725E6FF8B742DF253101B75FAAA8920CB8D3D94228D4CB2B808956FB2` |
| SSDEEP | `192:dNu1izb68Hq8bujsWDPtva4IWoHBnesfB0uXA9lCTO:G1i/3qShWDPtva48HBely` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_077cae04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "077cae04215aca2c742ceaf837fd8293671c9b0fa9b58de0e8bb106072796482"
    family = "unknown"
    file_name = "077cae04215aca2c742ceaf837fd8293671c9b0fa9b58de0e8bb106072796482.exe"
    file_type = "exe"
    first_seen = "2026-11-01 01:49:00"
  condition:
    hash.sha256(0, filesize) == "077cae04215aca2c742ceaf837fd8293671c9b0fa9b58de0e8bb106072796482"
}
```

### Sample 20: `7ec8a37604d91190`

| Field | Value |
|---|---|
| SHA-256 | `7ec8a37604d9119055090f201a07f54619c29ccbdf14f65cf6198e529345ca07` |
| Family label | `unknown` |
| File name | `slod.msi` |
| File type | `msi` |
| First seen | `2026-11-01 01:05:49` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, msi, PavinLoader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2313837f1ac6059e8a0c82f9fd33dbfb` |
| SHA-1 | `5937146ad4da87d90899da6d8981e9273f994d89` |
| SHA-256 | `7ec8a37604d9119055090f201a07f54619c29ccbdf14f65cf6198e529345ca07` |
| SHA3-384 | `d9aa98c39aa011ff35c99bb3a063d8f1801cc5ddeeb044f64af85bbdc6dcc8c3fbe57bd8629edbfc44f6551672eb877b` |
| TLSH | `T1DC7633F63C6103D4EC7A377461F68349935BEFB6130762E2136AB26939B111138FB986` |
| SSDEEP | `196608:spiFmy5lfC7B5+T7xEqKPnD0erbk18C1siUjiGbEry/J:spimV7GT7xY7Uhsfbxx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_7ec8a376
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ec8a37604d9119055090f201a07f54619c29ccbdf14f65cf6198e529345ca07"
    family = "unknown"
    file_name = "slod.msi"
    file_type = "msi"
    first_seen = "2026-11-01 01:05:49"
  condition:
    hash.sha256(0, filesize) == "7ec8a37604d9119055090f201a07f54619c29ccbdf14f65cf6198e529345ca07"
}
```

### Sample 21: `fd133e64799ab52e`

| Field | Value |
|---|---|
| SHA-256 | `fd133e64799ab52e50eb290d44e446c426a9f91096f8ac7b5293ce81b7bf58e2` |
| Family label | `unknown` |
| File name | `cler.msi` |
| File type | `msi` |
| First seen | `2026-11-01 01:05:13` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, msi, PavinLoader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `396f1b3ec53070261ed205db297dfdc8` |
| SHA-1 | `b0008ec229ebb9979df117b945d7637f5b92168f` |
| SHA-256 | `fd133e64799ab52e50eb290d44e446c426a9f91096f8ac7b5293ce81b7bf58e2` |
| SHA3-384 | `1a1d594881535f313789e9b4a2fdc12a869e0b4507034d3a7f3668c6c10dfd2a8620ce3512d45d6ac963f7f001005db7` |
| TLSH | `T1A68633E37C9AC1EFC58173B2C89B4697C2924E620225F5973953360DAAF7E01A5F630D` |
| SSDEEP | `196608:M/qI+Ljub77sNfxEo33IJtJhsYHHWnBPc27x47:S16jeSEJJhpnWB0e4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_fd133e64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd133e64799ab52e50eb290d44e446c426a9f91096f8ac7b5293ce81b7bf58e2"
    family = "unknown"
    file_name = "cler.msi"
    file_type = "msi"
    first_seen = "2026-11-01 01:05:13"
  condition:
    hash.sha256(0, filesize) == "fd133e64799ab52e50eb290d44e446c426a9f91096f8ac7b5293ce81b7bf58e2"
}
```

### Sample 22: `c3925c81ab10d012`

| Field | Value |
|---|---|
| SHA-256 | `c3925c81ab10d0121609552738cdff4bf8b621c8392522435d46d0c9a9d39d89` |
| Family label | `Mirai` |
| File name | `main_arm` |
| File type | `elf` |
| First seen | `2026-11-01 00:49:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b16d869d1084365024c901ccf5ce338a` |
| SHA-1 | `817e47cbe4f1be13e58fcd9bd4c814c096ff19f4` |
| SHA-256 | `c3925c81ab10d0121609552738cdff4bf8b621c8392522435d46d0c9a9d39d89` |
| SHA3-384 | `625f93659412c88c91ef45e42ade345694ff2d10dde3faea250dda84193fefde643c6b329b267aec3c71bb0b14bccd9e` |
| TLSH | `T1F5E31A46FC509E13C6D512BBFF5E428D372A17A8D3EE72039D256F21378696B0E7A102` |
| TELFHASH | `t11e213515ef5c1fac73e04455815c78191ef932e93b001a57df0a3b9f4911e66f83e822` |
| SSDEEP | `3072:POZCVB14x4zXTm0GKBzGtYNoZ2vGMpJ4QmRpn/CV+YIV146ZU:PO0Q4zXSsf4QA/CVLa46u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_c3925c81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3925c81ab10d0121609552738cdff4bf8b621c8392522435d46d0c9a9d39d89"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-11-01 00:49:13"
  condition:
    hash.sha256(0, filesize) == "c3925c81ab10d0121609552738cdff4bf8b621c8392522435d46d0c9a9d39d89"
}
```

### Sample 23: `c54c3592e1c1bc94`

| Field | Value |
|---|---|
| SHA-256 | `c54c3592e1c1bc94f81646ac0051fbac4109811b21a3831f91b3a77b0d8def11` |
| Family label | `Mirai` |
| File name | `c54c3592e1c1bc94.bin` |
| File type | `elf` |
| First seen | `2026-11-01 00:25:54` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea749b9205d16d43034f337f430f6159` |
| SHA-1 | `e6f2c62f0eeee6324dc476047b5375e396c8d90e` |
| SHA-256 | `c54c3592e1c1bc94f81646ac0051fbac4109811b21a3831f91b3a77b0d8def11` |
| SHA3-384 | `e18d9a2a82732785f29dc3d3b93ebcefee267b4f1bc1332a9611c00c7ea2c14c1cb0400018ef69ecba2b00f53fc782f4` |
| TLSH | `T1CF967C12FECB54F6E983093004ABE26F63315C054F24DB97EB54BF2AF97B6951832219` |
| TELFHASH | `t1132453a3cc66bf5b4fc403229cf5d5c49397d04708926b986fb08336d4eb48da5ba35a` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:vRJvlDlluCtXA2aaZcT3L3bEtQBeT+w19Z5Fz6l/uQz8W9eFZ9:7lb7XA2aTTb3Itqeq8Fzanz8Get` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_c54c3592
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c54c3592e1c1bc94f81646ac0051fbac4109811b21a3831f91b3a77b0d8def11"
    family = "Mirai"
    file_name = "c54c3592e1c1bc94.bin"
    file_type = "elf"
    first_seen = "2026-11-01 00:25:54"
  condition:
    hash.sha256(0, filesize) == "c54c3592e1c1bc94f81646ac0051fbac4109811b21a3831f91b3a77b0d8def11"
}
```

### Sample 24: `a0432d0a7ca04b53`

| Field | Value |
|---|---|
| SHA-256 | `a0432d0a7ca04b53e130a54710338385de639fe9a9cc0b858bd1649d539630e5` |
| Family label | `Mirai` |
| File name | `a0432d0a7ca04b53.bin` |
| File type | `elf` |
| First seen | `2026-11-01 00:25:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b9e6bd4a06986632ad2366051fc6131` |
| SHA-1 | `9518c7a2a463ab6ef5cdfa9fd4bd9247b5b8bd74` |
| SHA-256 | `a0432d0a7ca04b53e130a54710338385de639fe9a9cc0b858bd1649d539630e5` |
| SHA3-384 | `790121624e73511d4a387cdf41cda5db993aed507fa16cb4bbac8ae09acce01acdb560b7d4e4405c6fafd778c503b384` |
| TLSH | `T1FD840A88A1F1E7DED2D4EA75B319780D3B230736B1DB3146A51DAA3333EB1450AF9921` |
| TELFHASH | `t1dbf05015dc6a363cc3df952d82db803a0cce22950b6325da574a236cde43ec0e2e1c32` |
| SSDEEP | `6144:Z/g3d5jrYK4jLxcaW/TAomkshTDfwGyeSwx8ZPZa9BG:EjrY3PbvkeSO87a9BG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_a0432d0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0432d0a7ca04b53e130a54710338385de639fe9a9cc0b858bd1649d539630e5"
    family = "Mirai"
    file_name = "a0432d0a7ca04b53.bin"
    file_type = "elf"
    first_seen = "2026-11-01 00:25:47"
  condition:
    hash.sha256(0, filesize) == "a0432d0a7ca04b53e130a54710338385de639fe9a9cc0b858bd1649d539630e5"
}
```

### Sample 25: `931195a7237f8213`

| Field | Value |
|---|---|
| SHA-256 | `931195a7237f8213f80a0a76c76a9663061793e5b74ece9975d489c0eb971e2b` |
| Family label | `unknown` |
| File name | `931195a7237f8213.bin` |
| File type | `exe` |
| First seen | `2026-11-01 00:25:41` |
| Reporter | `Tuxxin` |
| Tags | `exe, hijackloader, rugmi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2afbca1414aebab2dcc5cd50085449c0` |
| SHA-1 | `5e4eda33025a9e885dfb7bcda51dea049573c2a2` |
| SHA-256 | `931195a7237f8213f80a0a76c76a9663061793e5b74ece9975d489c0eb971e2b` |
| SHA3-384 | `f3a2523375d284e7d9412cb59c43348e7a67db1d6d258c81194b64b41babcf7374b61b8f8650007e8b21c4d51e9faab0` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T1EAF6334173C06AF2C7ADDCB29F09EB9591B1FA5593954E852F58AE062C93C23210B3FD` |
| SSDEEP | `393216:+pZwkoanZjd7S2iE0YsNadx6KyfEqVUxzKoZ5Yl8:eZAIj7n0mdEKyxKr7YG` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_931195a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "931195a7237f8213f80a0a76c76a9663061793e5b74ece9975d489c0eb971e2b"
    family = "unknown"
    file_name = "931195a7237f8213.bin"
    file_type = "exe"
    first_seen = "2026-11-01 00:25:41"
  condition:
    hash.sha256(0, filesize) == "931195a7237f8213f80a0a76c76a9663061793e5b74ece9975d489c0eb971e2b"
}
```

### Sample 26: `586cddc7b67e1c20`

| Field | Value |
|---|---|
| SHA-256 | `586cddc7b67e1c2072b39cc6d0669b3031ab66c0075e91f8a81b8bd92b2e5c8e` |
| Family label | `Mirai` |
| File name | `586cddc7b67e1c20.bin` |
| File type | `elf` |
| First seen | `2026-11-01 00:25:30` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b58c469228405b117cdad45491c1abba` |
| SHA-1 | `9d2df1b1e73869a1abf247ffe56bdf7da768fced` |
| SHA-256 | `586cddc7b67e1c2072b39cc6d0669b3031ab66c0075e91f8a81b8bd92b2e5c8e` |
| SHA3-384 | `15867d66a14357b61104d1fdd22b6a63f9a20eec212b7e57d5b595a91dd4db6b66bd324e59a62565a7e6ddc16f3d6bca` |
| TLSH | `T17614961E6E228F7DF368C73447B78A25975D33D626E1D684E1ACC2141F6028E641FFA8` |
| TELFHASH | `t1a841a1280eb817e0a7656c5d099dff26d6a330de7e162c378e11e86aeb69b435d14c0c` |
| SSDEEP | `6144:bYYibp96JfIrtVA4G1GBa5kGpNwnNNNNNNNNNNNNElXdHrU:Evbp96sgkV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_586cddc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "586cddc7b67e1c2072b39cc6d0669b3031ab66c0075e91f8a81b8bd92b2e5c8e"
    family = "Mirai"
    file_name = "586cddc7b67e1c20.bin"
    file_type = "elf"
    first_seen = "2026-11-01 00:25:30"
  condition:
    hash.sha256(0, filesize) == "586cddc7b67e1c2072b39cc6d0669b3031ab66c0075e91f8a81b8bd92b2e5c8e"
}
```

### Sample 27: `d51568526eb146d6`

| Field | Value |
|---|---|
| SHA-256 | `d51568526eb146d673f4864629f21b40d70b35f5e25b88074a8bc63719cd67a8` |
| Family label | `Mirai` |
| File name | `d51568526eb146d6.bin` |
| File type | `elf` |
| First seen | `2026-11-01 00:25:23` |
| Reporter | `Tuxxin` |
| Tags | `elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb02e94e177bcbc36c9b8a431693f0fb` |
| SHA-1 | `aa90369da0f2435edd25160f47f9872f92ec9f72` |
| SHA-256 | `d51568526eb146d673f4864629f21b40d70b35f5e25b88074a8bc63719cd67a8` |
| SHA3-384 | `0395cffbb0a20340a62fbc2137143af49a10267007965e81ec596a71feb1fa4f7205c32ca61923a3a1a090b05adf3fcf` |
| TLSH | `T100841988D2F2E2FDF154E9716305BD1B5C324A363083B187F39E7A7352B618486E9A35` |
| TELFHASH | `t1c991baf2296f49ee73e0a942930a6f01ed0bc6a7486032b405f376d572b3e635375875` |
| SSDEEP | `6144:N/UUxjs0FGate672sZkUAXtS3nniPjBzOnBu2Wu2R+L7PMa9q/:N3xjs0FGate672sZkUAXtSXs82R+LbMB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_d5156852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51568526eb146d673f4864629f21b40d70b35f5e25b88074a8bc63719cd67a8"
    family = "Mirai"
    file_name = "d51568526eb146d6.bin"
    file_type = "elf"
    first_seen = "2026-11-01 00:25:23"
  condition:
    hash.sha256(0, filesize) == "d51568526eb146d673f4864629f21b40d70b35f5e25b88074a8bc63719cd67a8"
}
```

### Sample 28: `bc7615f394446ebe`

| Field | Value |
|---|---|
| SHA-256 | `bc7615f394446ebec2ee732636de22153f38756f63277359ca2f78eadb07f42a` |
| Family label | `unknown` |
| File name | `FACEITInstaller_64.exe` |
| File type | `exe` |
| First seen | `2026-11-01 00:23:24` |
| Reporter | `Parper` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33934bba3a04e6dbbf47d63cc598bb4c` |
| SHA-1 | `e517d54e082141dc2b9884aa659f2e0f02c201b2` |
| SHA-256 | `bc7615f394446ebec2ee732636de22153f38756f63277359ca2f78eadb07f42a` |
| SHA3-384 | `8a97cccd0a8d7776563588c8bd5dcc108cf204ace91acc26306c0afbc9b728d2e2bc84db8b15da5ce13f233a953db5a8` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1B3683362B6E7AAACE6056B3ECC8D8119E730F8C50DD18BDFD7114D69BE4998187243C3` |
| SSDEEP | `3145728:ESabllLMDEPEkjLHs1MR3nBMoPM6CosBbdKXO3LWeEmu2iMnooXQ+:ESQ/0EPE0HsyWoP4osBuSqea23oW` |
| ICON-DHASH | `30a88ea2b6cc6970` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_bc7615f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc7615f394446ebec2ee732636de22153f38756f63277359ca2f78eadb07f42a"
    family = "unknown"
    file_name = "FACEITInstaller_64.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:23:24"
  condition:
    hash.sha256(0, filesize) == "bc7615f394446ebec2ee732636de22153f38756f63277359ca2f78eadb07f42a"
}
```

### Sample 29: `f860fc8792473bae`

| Field | Value |
|---|---|
| SHA-256 | `f860fc8792473baefb1cbeb5f6d59c0107ce1ee53c43742a124ee6316f08d9cb` |
| Family label | `unknown` |
| File name | `payload_decrypted.zip` |
| File type | `zip` |
| First seen | `2026-11-01 00:23:04` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-RenPyLoader, PavinLoader, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98834504e81d6b57497a7de1e105c5d4` |
| SHA-1 | `0a053b37c32b259889647a160b134bcdc729f73a` |
| SHA-256 | `f860fc8792473baefb1cbeb5f6d59c0107ce1ee53c43742a124ee6316f08d9cb` |
| SHA3-384 | `b267e1567c5992621a379ca51afadbd0b649024ec9fe05cf9df2bfcf9081535b6a8dfd49067138843871876054c51d23` |
| TLSH | `T13BA7D4D013F89BD9B98C1B4B452C3FBD966512BB184762CCBA61EED12D27A744C18CCE` |
| SSDEEP | `24576:TbgoOC0jcTu3xOa+nuEmtG4lSvpXapePmfwOYhCwwdxQEQCzV15xwjD0zb30yFVB:C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_f860fc87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f860fc8792473baefb1cbeb5f6d59c0107ce1ee53c43742a124ee6316f08d9cb"
    family = "unknown"
    file_name = "payload_decrypted.zip"
    file_type = "zip"
    first_seen = "2026-11-01 00:23:04"
  condition:
    hash.sha256(0, filesize) == "f860fc8792473baefb1cbeb5f6d59c0107ce1ee53c43742a124ee6316f08d9cb"
}
```

### Sample 30: `30e6f65380198bd4`

| Field | Value |
|---|---|
| SHA-256 | `30e6f65380198bd4d49227d780f19a01d297aa8ed7ae643167e490f5e7b8fca5` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-11-01 00:12:19` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, data-wickenhollow-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dfc29fcbae3f85a932141966378f274` |
| SHA-1 | `ba3b01c90d517eaa3b59c8ca730d94290ddefd4f` |
| SHA-256 | `30e6f65380198bd4d49227d780f19a01d297aa8ed7ae643167e490f5e7b8fca5` |
| SHA3-384 | `546aa298a08958a7753fd43cea73be3283e86283885e4e2a66877d4ef4c9893735e2f81616d8e51ad607b35984ccf94e` |
| TLSH | `T15C47236CB8B5B84AF5D0537BC6C52CBAEB2CE541D7E93C9B8E2440467D8310E4F6AC61` |
| SSDEEP | `786432:qotJpzs4vIBOmJPj1j/FVs4vbRos4vzRJ:qo9nvsxRVnvbGnvzRJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_30e6f653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30e6f65380198bd4d49227d780f19a01d297aa8ed7ae643167e490f5e7b8fca5"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-01 00:12:19"
  condition:
    hash.sha256(0, filesize) == "30e6f65380198bd4d49227d780f19a01d297aa8ed7ae643167e490f5e7b8fca5"
}
```

### Sample 31: `d9fead88582068c1`

| Field | Value |
|---|---|
| SHA-256 | `d9fead88582068c1d9642a109ab73669f168e7f7a45554cda6069819baf0dde0` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-11-01 00:11:11` |
| Reporter | `iamaachum` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3274663a19e59e52490023f359f680e4` |
| SHA-1 | `4e358a56bda84d78655c000a6d90d7018a9f2a0f` |
| SHA-256 | `d9fead88582068c1d9642a109ab73669f168e7f7a45554cda6069819baf0dde0` |
| SHA3-384 | `6104f1ce60fe7c9bc24effb07f6fc4a8ebd89bd6ad488ac819de4615a8267c29428f0eeba3182716338fa8f638f82989` |
| IMPHASH | `118137e447e61ecf0a8b40fbe9dd057d` |
| TLSH | `T10335E182B7937DF9F426C07875021A62A5667C450BE0A6EB578C3B1B0E2E6D5CBFD310` |
| SSDEEP | `12288:42memsLavY5NmkK2I9vUgCLafQmOqT0y1s4ZNpcje+67a6y/Cu4e0qWhIVqFW8Iq:4kmGfoUgCL0UE0yB4jeIVKR0VSW8I` |
| ICON-DHASH | `08341272b1125a24` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_d9fead88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9fead88582068c1d9642a109ab73669f168e7f7a45554cda6069819baf0dde0"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:11:11"
  condition:
    hash.sha256(0, filesize) == "d9fead88582068c1d9642a109ab73669f168e7f7a45554cda6069819baf0dde0"
}
```

### Sample 32: `b292553214c1eb0e`

| Field | Value |
|---|---|
| SHA-256 | `b292553214c1eb0e0aa485a4835f213547856bb3580171f2c2bcb97ab0a40b0e` |
| Family label | `ValleyRAT` |
| File name | `A283C881A189A50B3C861A8BB37C5CB9.dll` |
| File type | `dll` |
| First seen | `2026-11-01 00:10:10` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a283c881a189a50b3c861a8bb37c5cb9` |
| SHA-1 | `0d6a0b55256070ef38ebf51504d8b419fb6c352c` |
| SHA-256 | `b292553214c1eb0e0aa485a4835f213547856bb3580171f2c2bcb97ab0a40b0e` |
| SHA3-384 | `ebd08caea6daf22123796f72e90ed8f4414e2b6bb561bf618d16288577c1b732f9381f9e85029cbd79914004c5b66772` |
| IMPHASH | `ed719d06b435e943e2137e8d090ae910` |
| TLSH | `T15B848D41B985C132E5AE0570B935EFA65D7DBD710BE0A4CFA3C40DAE9D207C1AB3871A` |
| SSDEEP | `6144:b7xWm+5wnTb6MS2TUoMpQ4CcPyEeScCcplGYF95p8FABQu9e:bI5pR2TUoMpQ4CbfPF3C4W` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_032_b2925532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b292553214c1eb0e0aa485a4835f213547856bb3580171f2c2bcb97ab0a40b0e"
    family = "ValleyRAT"
    file_name = "A283C881A189A50B3C861A8BB37C5CB9.dll"
    file_type = "dll"
    first_seen = "2026-11-01 00:10:10"
  condition:
    hash.sha256(0, filesize) == "b292553214c1eb0e0aa485a4835f213547856bb3580171f2c2bcb97ab0a40b0e"
}
```

### Sample 33: `19520eea568e1e80`

| Field | Value |
|---|---|
| SHA-256 | `19520eea568e1e804292e3a60765dedea5462561d75b0ba49eaf7ef8ef13602b` |
| Family label | `unknown` |
| File name | `Installer41805x64.exe` |
| File type | `exe` |
| First seen | `2026-11-01 00:09:54` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49ea4f827580c8ac3b39c3e524b9abb8` |
| SHA-1 | `b1e770aff79365ed65e40e1106699bec701fe22d` |
| SHA-256 | `19520eea568e1e804292e3a60765dedea5462561d75b0ba49eaf7ef8ef13602b` |
| SHA3-384 | `1abab01853cf7fa5213fb808182d6b78d176fc8548aa7f5e54c54452d974e7899e7fd4dfe3631f727efeb22cfa46bfa1` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T101E633D1C743FF22D5201B38FF6E446AED994AA47F21C7A6D91C23BD18F6229344325A` |
| SSDEEP | `393216:x4eV2GkUX03mD7j2Zryg6w+9pkW3vuSUa3IB1EzB:xTV2GGmOryldfkgvVw+z` |
| ICON-DHASH | `71e0ccccb28ee870` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_19520eea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19520eea568e1e804292e3a60765dedea5462561d75b0ba49eaf7ef8ef13602b"
    family = "unknown"
    file_name = "Installer41805x64.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:09:54"
  condition:
    hash.sha256(0, filesize) == "19520eea568e1e804292e3a60765dedea5462561d75b0ba49eaf7ef8ef13602b"
}
```

### Sample 34: `c51e37c1622bff8c`

| Field | Value |
|---|---|
| SHA-256 | `c51e37c1622bff8c874a6452c30f70f0aef59ca9f2c09cf98e8e7c406535e4f3` |
| Family label | `unknown` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-11-01 00:09:27` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `503c2b3c6c80dbbb075da6582f8906e9` |
| SHA-1 | `964ed2f8beb2e974c3d4d159e4c7bcb13e519f3a` |
| SHA-256 | `c51e37c1622bff8c874a6452c30f70f0aef59ca9f2c09cf98e8e7c406535e4f3` |
| SHA3-384 | `87ed8c1a493880c20e806ffa532b03c5f36f242c7291ff702bde1389fb4b848a2f7464f9546e9f48c66be66864c160c6` |
| TLSH | `T1E9E633D1C743FF12D5201B38FF5E446AED9A4AA47F21C7A6E91C23BD18F7229344225A` |
| SSDEEP | `393216:c4eV2GkUX03mD7j2Zryg6w+9pkW3vuSUa3IB1EzB:cTV2GGmOryldfkgvVw+z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_c51e37c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c51e37c1622bff8c874a6452c30f70f0aef59ca9f2c09cf98e8e7c406535e4f3"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-11-01 00:09:27"
  condition:
    hash.sha256(0, filesize) == "c51e37c1622bff8c874a6452c30f70f0aef59ca9f2c09cf98e8e7c406535e4f3"
}
```

### Sample 35: `a6284a9e3cd2414a`

| Field | Value |
|---|---|
| SHA-256 | `a6284a9e3cd2414a72d5a183353fc76fd994510af1eb2921e8d2c9ccf84c9517` |
| Family label | `unknown` |
| File name | `Installer_L_X64_x86_2024.zip` |
| File type | `zip` |
| First seen | `2026-11-01 00:08:19` |
| Reporter | `iamaachum` |
| Tags | `HijackLoader, IDATLoader, WARDENStealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c93b632efbe12fe9744352571dddb19` |
| SHA-1 | `dcdfa20be0b369b9de10adaabc7ef9472da5aa56` |
| SHA-256 | `a6284a9e3cd2414a72d5a183353fc76fd994510af1eb2921e8d2c9ccf84c9517` |
| SHA3-384 | `e0c023b71c3bb0eee90aa6b450aaa54a5175781d3efd17cb2dc08e59e0b642d517e00b7923b4251230f216b6358f7bc6` |
| TLSH | `T1EEE73358DB5D609DE3BAEABAE4CA75EEA5B2C4050BA0FF2F295810811CD33F51F06417` |
| SSDEEP | `1572864:EQljv08wS+4dKjkbg+DNGvQGc4IrG1c49uHLI1byM1JdiUNqbjrUAK:EQljW4bg5cTGu7WyMJNq6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_a6284a9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6284a9e3cd2414a72d5a183353fc76fd994510af1eb2921e8d2c9ccf84c9517"
    family = "unknown"
    file_name = "Installer_L_X64_x86_2024.zip"
    file_type = "zip"
    first_seen = "2026-11-01 00:08:19"
  condition:
    hash.sha256(0, filesize) == "a6284a9e3cd2414a72d5a183353fc76fd994510af1eb2921e8d2c9ccf84c9517"
}
```

### Sample 36: `0b4e389ea5d262b3`

| Field | Value |
|---|---|
| SHA-256 | `0b4e389ea5d262b3e6689847d53900a3c508572c7165e7d6b0fba384fd86a1ca` |
| Family label | `unknown` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-11-01 00:07:08` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, wooocommerce-shopping` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `423a7ad5d76d0dbb933e735b043bc1e0` |
| SHA-1 | `d9a6ab838a17865f06df20fcecf6385df024db1e` |
| SHA-256 | `0b4e389ea5d262b3e6689847d53900a3c508572c7165e7d6b0fba384fd86a1ca` |
| SHA3-384 | `7c05b699bf6f90ceb5bc09dfb2ed093c634abb0da6d3e3072131ecb83ba05e589bc39faf233e3d754fea03167be62dff` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1035639137F5448B8D096EB38C57B82623631BC898B3533E72E51BA386F367D1A979704` |
| SSDEEP | `24576:w+wtWi0UCrrTcg/HeU/AETNgHlOeXy3Vr3JqJ2cpKDTVq5aUVIX0Afvh2UwQq/vB:wPMnUUcc+lkrnqC0evhUvFB0OuQDLh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_0b4e389e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b4e389ea5d262b3e6689847d53900a3c508572c7165e7d6b0fba384fd86a1ca"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:07:08"
  condition:
    hash.sha256(0, filesize) == "0b4e389ea5d262b3e6689847d53900a3c508572c7165e7d6b0fba384fd86a1ca"
}
```

### Sample 37: `43db1c8b806fcecd`

| Field | Value |
|---|---|
| SHA-256 | `43db1c8b806fcecdd4b752e8d093ff9c16c7ed7ee6333ff76807f2fe6c4c3ed4` |
| Family label | `unknown` |
| File name | `Setup_latest.exe` |
| File type | `exe` |
| First seen | `2026-11-01 00:05:57` |
| Reporter | `iamaachum` |
| Tags | `exe, SpaxMedia, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9848d4ff3bc7bc943a3917bdf1fe2064` |
| SHA-1 | `5c603f43bc2efe5f4a73641a35a4887bbb6d6513` |
| SHA-256 | `43db1c8b806fcecdd4b752e8d093ff9c16c7ed7ee6333ff76807f2fe6c4c3ed4` |
| SHA3-384 | `2d68db80f650c73776fefa2bd3cf5d8ae6df62a1c39fc59e450cf909d167a8060f6cf92dcdbc086e64304140e60b8b43` |
| IMPHASH | `2a1db37dca0a6e37aef2f40583f94a67` |
| TLSH | `T1E90733C87B0A6DFDED9D9D79C0865000C0622EAA57C861768F8D3B258B336CA79F5F50` |
| SSDEEP | `393216:g/mf21cRxn2YD/c/ZUCFsafj2wWpraBUfmM2CZsg1N9Y34Ji:e421An2YLc/5FSvNayeM2CZssRJi` |
| ICON-DHASH | `ffffdbf3f3dbffff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_43db1c8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43db1c8b806fcecdd4b752e8d093ff9c16c7ed7ee6333ff76807f2fe6c4c3ed4"
    family = "unknown"
    file_name = "Setup_latest.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:05:57"
  condition:
    hash.sha256(0, filesize) == "43db1c8b806fcecdd4b752e8d093ff9c16c7ed7ee6333ff76807f2fe6c4c3ed4"
}
```

### Sample 38: `0d071eaede91a8c3`

| Field | Value |
|---|---|
| SHA-256 | `0d071eaede91a8c31dfe5fa25859e944e62e967d6a1a1316b9845778b5fe38af` |
| Family label | `unknown` |
| File name | `application_patched.exe` |
| File type | `exe` |
| First seen | `2026-11-01 00:04:15` |
| Reporter | `iamaachum` |
| Tags | `de-pumped, exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2e73a64aea662418eda2e7a6aef0934` |
| SHA-1 | `08f744c8888214c1a39545f9352aa00e4561bec6` |
| SHA-256 | `0d071eaede91a8c31dfe5fa25859e944e62e967d6a1a1316b9845778b5fe38af` |
| SHA3-384 | `9a570fe66954ad25a8d07e4516f0f77bfac76a647cddbb492d83e4e74291132b18b2a8659202515ff8125262f0258346` |
| IMPHASH | `8b98e4c440ad72f1e7a323e85897fd47` |
| TLSH | `T11C77BE01B7D84471E2FB2634257AA7365A7EBD301FA082CB275467AE2C717C19E3076B` |
| SSDEEP | `393216:YAr+eOX4iIJ3VY4HiFxxm16GiCuN+U+lIkksFh/GZ:YAr+eOX4iIJFGF616F9+lI7mheZ` |
| ICON-DHASH | `d4aeeee8cccce0d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_0d071eae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d071eaede91a8c31dfe5fa25859e944e62e967d6a1a1316b9845778b5fe38af"
    family = "unknown"
    file_name = "application_patched.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:04:15"
  condition:
    hash.sha256(0, filesize) == "0d071eaede91a8c31dfe5fa25859e944e62e967d6a1a1316b9845778b5fe38af"
}
```

### Sample 39: `14dc82bc5ee7c606`

| Field | Value |
|---|---|
| SHA-256 | `14dc82bc5ee7c606e862a702666cc1b314179545f3a56fa68fc76b29d5900576` |
| Family label | `unknown` |
| File name | `application.7z` |
| File type | `7z` |
| First seen | `2026-11-01 00:03:42` |
| Reporter | `iamaachum` |
| Tags | `7z, file-pumped, pw-1650, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f2b58f4c0908f46a9d119be4e376740` |
| SHA-1 | `498876a32a1864ed043f26e851e5f380c74dcbf9` |
| SHA-256 | `14dc82bc5ee7c606e862a702666cc1b314179545f3a56fa68fc76b29d5900576` |
| SHA3-384 | `2268682043c37c375568bce28cc4b06e50efa7ab959ce23caea35d01f223982f3f06a086be0c879580223113f7a2d37a` |
| TLSH | `T109F633FB09EC6C7409E6AF720DE6D9C42B85D279CFE1CACD77471F1E052A89416A0E18` |
| SSDEEP | `393216:o0LS6X9RNZFPYVR0PMeIEQ7Z4qeD8A9BkyTgLb:9z97ZpGYMeIEq4nPky8n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_14dc82bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14dc82bc5ee7c606e862a702666cc1b314179545f3a56fa68fc76b29d5900576"
    family = "unknown"
    file_name = "application.7z"
    file_type = "7z"
    first_seen = "2026-11-01 00:03:42"
  condition:
    hash.sha256(0, filesize) == "14dc82bc5ee7c606e862a702666cc1b314179545f3a56fa68fc76b29d5900576"
}
```

### Sample 40: `a722772daefdf8c9`

| Field | Value |
|---|---|
| SHA-256 | `a722772daefdf8c9630c00ec51a176f3b53cdf35a9133b91abd0121517f66f34` |
| Family label | `unknown` |
| File name | `client2.google.com.cup2key.zip` |
| File type | `zip` |
| First seen | `2026-11-01 00:02:27` |
| Reporter | `iamaachum` |
| Tags | `data-nomadhive-cc, dropped-by-ACRStealer, ZigClipper, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5930a8ddf866f391219a449d7a97973` |
| SHA-1 | `82e00fbaaff1a2d42d5aaf314d7496896fe6bf3d` |
| SHA-256 | `a722772daefdf8c9630c00ec51a176f3b53cdf35a9133b91abd0121517f66f34` |
| SHA3-384 | `9dcf0d9be84958929ec98ad0ca43d1a7443c8af58ed53b0304da97698f99c5d18671a171cb988875e420619ccf585b27` |
| TLSH | `T19B4533A3F6728AED9651243CD1365AA20079077F5C067EB63E33B4722D4A3647CEF281` |
| SSDEEP | `24576:RGD0hall+nP3r5fyjOc7T7EZ2w4xPnXm1EWkIYEkZ0/2/bcfLpMF7txJv:Rs0ha+P3dfQTT7g2tpWkIY9S/SwOF7Td` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_a722772d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a722772daefdf8c9630c00ec51a176f3b53cdf35a9133b91abd0121517f66f34"
    family = "unknown"
    file_name = "client2.google.com.cup2key.zip"
    file_type = "zip"
    first_seen = "2026-11-01 00:02:27"
  condition:
    hash.sha256(0, filesize) == "a722772daefdf8c9630c00ec51a176f3b53cdf35a9133b91abd0121517f66f34"
}
```

### Sample 41: `3e64a72d9226a356`

| Field | Value |
|---|---|
| SHA-256 | `3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb` |
| Family label | `unknown` |
| File name | `3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb` |
| File type | `exe` |
| First seen | `2026-11-01 00:02:20` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, exe, pe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b6348d0ae58888a496851ac9e9cce5d` |
| SHA-1 | `203df8202cc07f080ff2f3ba78c2490e2a895a73` |
| SHA-256 | `3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb` |
| SHA3-384 | `50000503523a424607949f2c1e49c0b9fe4bc7925442017b85dbb9e81d8d0c776f3d42f349b6017d7c1784e2fed7fe9a` |
| IMPHASH | `d9293932c5a9235a32ddf5e9f562cfe1` |
| TLSH | `T115946C02B79588B8E05BC07487578A73AA3778860B21F9EF03D496353E6AFE1673D714` |
| SSDEEP | `6144:lcf9u5TUWM6VJB77lc/WKUMRQTNsp9F2cS77LQaEp+TmebX4t+nIs:KfQ5P772QxAS77SASWF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_3e64a72d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb"
    family = "unknown"
    file_name = "3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb"
    file_type = "exe"
    first_seen = "2026-11-01 00:02:20"
  condition:
    hash.sha256(0, filesize) == "3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb"
}
```

### Sample 42: `7d33d7780e4de1b5`

| Field | Value |
|---|---|
| SHA-256 | `7d33d7780e4de1b568c1a99eaadb4895e16fc0ae7a72a25e5cc115b6b218e381` |
| Family label | `unknown` |
| File name | `eda1686d-c620-49a0-ab53-6b6659f6cad1.ps1` |
| File type | `ps1` |
| First seen | `2026-11-01 00:01:42` |
| Reporter | `iamaachum` |
| Tags | `data-nomadhive-cc, dropped-by-ACRStealer, ps1, ZigClipper` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35f2df5549dc1062da565be36ec33c4e` |
| SHA-1 | `9f146aa1f5f87972e05ef8d34d12fff5709ae44a` |
| SHA-256 | `7d33d7780e4de1b568c1a99eaadb4895e16fc0ae7a72a25e5cc115b6b218e381` |
| SHA3-384 | `07bb3b52876bb69ecf6e615ce024f976eaad66527e17f4bffd9e9406b75c585003872786c4e124f914e68bff2d12f981` |
| TLSH | `T187A43F613380B862914EDFB96D110C0BE3DDA069EFCFAC4D9BC9F6844B87568469DCB1` |
| SSDEEP | `6144:SV5hTFeCPXCW6lQbt/IpuufCNJq3Hc88BTrrPERE1R6RxRJbt47LqLvpZ1tblrXU:YDFeCPXC08X8Btht3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_7d33d778
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d33d7780e4de1b568c1a99eaadb4895e16fc0ae7a72a25e5cc115b6b218e381"
    family = "unknown"
    file_name = "eda1686d-c620-49a0-ab53-6b6659f6cad1.ps1"
    file_type = "ps1"
    first_seen = "2026-11-01 00:01:42"
  condition:
    hash.sha256(0, filesize) == "7d33d7780e4de1b568c1a99eaadb4895e16fc0ae7a72a25e5cc115b6b218e381"
}
```

### Sample 43: `60f4f3fd202f77f1`

| Field | Value |
|---|---|
| SHA-256 | `60f4f3fd202f77f14d1eda4829c48b5c5fcd170951c914a0a73428c332df9844` |
| Family label | `unknown` |
| File name | `bbd224f8-8296-404b-ab7c-c93301380271.ps1` |
| File type | `ps1` |
| First seen | `2026-10-31 23:59:25` |
| Reporter | `iamaachum` |
| Tags | `62-238-87-60, Arechclient2, AsgardProtector, dropped-by-ACRStealer, ps1, SectopRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e6ae85fd49a0814ca052edad1a0e366` |
| SHA-1 | `22cb830907176b5bd73f62928d98238063a1d590` |
| SHA-256 | `60f4f3fd202f77f14d1eda4829c48b5c5fcd170951c914a0a73428c332df9844` |
| SHA3-384 | `a5cf80ce707d52d556b9c3257d58696618e7ec986547ed9c6b8ea31919e27123c0c8b837b4f90ba2a8d383d4786954d3` |
| TLSH | `T1E2A4316137C0B866914EDFB96C010C0B93DD607ADFCFA85EABC9E6844B87578468DCB1` |
| SSDEEP | `6144:zEC+uojeBdWOTNiywGdlYoA6auYauu+U4G46YHY7pdQpdepdVpdfzm2mXXJ/C88Z:I8ig888Sc5m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_60f4f3fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60f4f3fd202f77f14d1eda4829c48b5c5fcd170951c914a0a73428c332df9844"
    family = "unknown"
    file_name = "bbd224f8-8296-404b-ab7c-c93301380271.ps1"
    file_type = "ps1"
    first_seen = "2026-10-31 23:59:25"
  condition:
    hash.sha256(0, filesize) == "60f4f3fd202f77f14d1eda4829c48b5c5fcd170951c914a0a73428c332df9844"
}
```

### Sample 44: `5d4ccb77b6ae228c`

| Field | Value |
|---|---|
| SHA-256 | `5d4ccb77b6ae228cfd09641816d538f8336084ef0e93c90453b60e1b04be99bb` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-10-31 23:57:03` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, img-tallowfetch-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd47493ba4591ade13c08db5e577a10c` |
| SHA-1 | `4f7cf97962e530075ac40abe78a2d1a7b97ff119` |
| SHA-256 | `5d4ccb77b6ae228cfd09641816d538f8336084ef0e93c90453b60e1b04be99bb` |
| SHA3-384 | `b15a6df11e29472bde7389a23f54b4df54f7a6c59fed13f75afd585a4a122b737dc9d6fc59013731064128a361ab669b` |
| TLSH | `T1D147334264EB4F81C86D903DC0EF4F03EA01AB49905B935F53A9E35B7EF37B49A5580A` |
| SSDEEP | `786432:nvlQNexo4dxUXfiWEyfb7rUsL3O9lYYOTYUsZAM3/jkmgt9:nvJxndGdE27N742YO4N7kl9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_5d4ccb77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d4ccb77b6ae228cfd09641816d538f8336084ef0e93c90453b60e1b04be99bb"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-10-31 23:57:03"
  condition:
    hash.sha256(0, filesize) == "5d4ccb77b6ae228cfd09641816d538f8336084ef0e93c90453b60e1b04be99bb"
}
```

### Sample 45: `ae79a18faa326d85`

| Field | Value |
|---|---|
| SHA-256 | `ae79a18faa326d8522701a36850a9d511cdf0450f59ee5cf678b5ddf1bd441cb` |
| Family label | `unknown` |
| File name | `task_360.exe` |
| File type | `exe` |
| First seen | `2026-10-31 23:45:15` |
| Reporter | `iamaachum` |
| Tags | `AvisLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be6a6fee9eea10e88a40335604d945fe` |
| SHA-1 | `263b60b3005e2a63b8c74c55439311aa10a8da66` |
| SHA-256 | `ae79a18faa326d8522701a36850a9d511cdf0450f59ee5cf678b5ddf1bd441cb` |
| SHA3-384 | `4bb6fe029ee0ba3fe4fca2dc1747d9923173434bf084c3e136eae3adc099c736aca1f14dc6b077635cbac0273ed68ab3` |
| IMPHASH | `fd4b87bc1963adb80825da86225ffbd4` |
| TLSH | `T19A853B2AE2A350FCC56BD170835B9272F971B42951347D7F1F94CB301F22E605A6EBA8` |
| SSDEEP | `24576:kazuG3g8nPRJOxv3eYtxVKtnTh2qEnyf0K/w6GFe2V3TiODZ:kaz5gGpJQvtxchh2qEnyBnO3T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_ae79a18f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae79a18faa326d8522701a36850a9d511cdf0450f59ee5cf678b5ddf1bd441cb"
    family = "unknown"
    file_name = "task_360.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:45:15"
  condition:
    hash.sha256(0, filesize) == "ae79a18faa326d8522701a36850a9d511cdf0450f59ee5cf678b5ddf1bd441cb"
}
```

### Sample 46: `d0897e93090efa7e`

| Field | Value |
|---|---|
| SHA-256 | `d0897e93090efa7e0ca7b2a0913f45d908c436dc4b9def8a60f82e435247a26d` |
| Family label | `RaspberryRobin` |
| File name | `task_354.exe` |
| File type | `exe` |
| First seen | `2026-10-31 23:44:13` |
| Reporter | `iamaachum` |
| Tags | `13-143-132-84, 91-92-43-45, 93-152-213-215, exe, RaspberryRobin` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72efd05c4a0117643365c18ac8de7aff` |
| SHA-1 | `b67d01ef6dce5d2b36175b82a98c8431879bd151` |
| SHA-256 | `d0897e93090efa7e0ca7b2a0913f45d908c436dc4b9def8a60f82e435247a26d` |
| SHA3-384 | `18e7a31d6351d1b2d55114feb7410299b19a2985856578417834fe03f35764b69c85f8926cf322d5cc284f97589d6e7e` |
| IMPHASH | `e2b0240584d94019fcdab28910b42b16` |
| TLSH | `T102B5F17EDF89939AC19411FA8C78E758F44D8DC08E0961C5CFE049E2C1AE308B569BDB` |
| SSDEEP | `49152:xOSGeRfUXpRP9IT6z+YocKhqPeGiZ4/CHdd1IKxD6:wRP9I6DocKQPLiKKHzCKh` |

#### Technical Assessment

- The sample is tracked as `RaspberryRobin` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RaspberryRobin_046_d0897e93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0897e93090efa7e0ca7b2a0913f45d908c436dc4b9def8a60f82e435247a26d"
    family = "RaspberryRobin"
    file_name = "task_354.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:44:13"
  condition:
    hash.sha256(0, filesize) == "d0897e93090efa7e0ca7b2a0913f45d908c436dc4b9def8a60f82e435247a26d"
}
```

### Sample 47: `9d248e41c44dc042`

| Field | Value |
|---|---|
| SHA-256 | `9d248e41c44dc04235c3fa71f09bbc620e1e4cd4a488436effdfa0de47a092b7` |
| Family label | `Mirai` |
| File name | `bot-linux-amd64` |
| File type | `elf` |
| First seen | `2026-10-31 23:44:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edd2c9fd34134cad6a1f34e97c4ef72c` |
| SHA-1 | `e024db6450f11aae49fec858c6a28a84a09ad68a` |
| SHA-256 | `9d248e41c44dc04235c3fa71f09bbc620e1e4cd4a488436effdfa0de47a092b7` |
| SHA3-384 | `5a9c2106e4249e120752e1a6a72a3978a9fcd414ac1a0b2e52637beae854be199164470255a7c3e660c761688c359945` |
| TLSH | `T16DA68C43FCA929E9C1EEA131897391527B727C594B3263C32F90F6282E73BD46979740` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:sixnzn3xqX2wimUk29lPEi8Y/KV5iTW0uEsHYyqWNAydLwNNONpUh:sG3sGkUkli8M0AuEsHY4Ay5tg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_9d248e41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d248e41c44dc04235c3fa71f09bbc620e1e4cd4a488436effdfa0de47a092b7"
    family = "Mirai"
    file_name = "bot-linux-amd64"
    file_type = "elf"
    first_seen = "2026-10-31 23:44:12"
  condition:
    hash.sha256(0, filesize) == "9d248e41c44dc04235c3fa71f09bbc620e1e4cd4a488436effdfa0de47a092b7"
}
```

### Sample 48: `30438ad34a3f3a4c`

| Field | Value |
|---|---|
| SHA-256 | `30438ad34a3f3a4c0d8ca14cee517eee0f2465a027c2f806c91d262283a2bff9` |
| Family label | `Tofsee` |
| File name | `𝐏𝐑𝐎 𝐒𝐄𝐓𝐔𝐏.exe` |
| File type | `exe` |
| First seen | `2026-10-31 23:41:50` |
| Reporter | `iamaachum` |
| Tags | `DonutLoader, exe, signed, Tofsee` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09ec9fe45f87c25427bd2044bba0cf32` |
| SHA-1 | `926c3d717cd73ef5e123a5324ad69bedaaf09b63` |
| SHA-256 | `30438ad34a3f3a4c0d8ca14cee517eee0f2465a027c2f806c91d262283a2bff9` |
| SHA3-384 | `0eac7f705529b729153d83bf224d03956d0288063fcc3fa0fe7644321c41854000badf2e0ad7f2eb0ed2d4ff163484c9` |
| IMPHASH | `222ccc60e23286b562114c421f606312` |
| TLSH | `T1816633218F759CBAC53C933970BF5F2A6BF15EC4885DF1EB4391A483166AB42091F82D` |
| SSDEEP | `49152:WccCPB0rLHurdjAq6xW2e+JtaEWksoIYi0QZszw10qf8HHHuTXcPguvoiebmaU9k:v` |
| ICON-DHASH | `d48eb26969b28fd4` |

#### Technical Assessment

- The sample is tracked as `Tofsee` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Tofsee_048_30438ad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30438ad34a3f3a4c0d8ca14cee517eee0f2465a027c2f806c91d262283a2bff9"
    family = "Tofsee"
    file_name = "𝐏𝐑𝐎 𝐒𝐄𝐓𝐔𝐏.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:41:50"
  condition:
    hash.sha256(0, filesize) == "30438ad34a3f3a4c0d8ca14cee517eee0f2465a027c2f806c91d262283a2bff9"
}
```

### Sample 49: `2c868a4a61dfc58f`

| Field | Value |
|---|---|
| SHA-256 | `2c868a4a61dfc58fa73b87a9e68c7876f836c608c539558053d829ea462064cb` |
| Family label | `unknown` |
| File name | `Setup-2.exe` |
| File type | `exe` |
| First seen | `2026-10-31 23:24:58` |
| Reporter | `iamaachum` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `599816bd76c6a15327270eed67b6d856` |
| SHA-1 | `0f8cdc5ecff01b04fc33d047a3c0679d7cc68160` |
| SHA-256 | `2c868a4a61dfc58fa73b87a9e68c7876f836c608c539558053d829ea462064cb` |
| SHA3-384 | `fbb3d741899d8709aa81f2ee2ecd934fe547d3ca36b6683e1f82b3ea9bde12ce36cbf37b36c511bbd4d627f97a2432b1` |
| IMPHASH | `b99293e16ae88a5c25c53925e445249b` |
| TLSH | `T15B45ACB1B7550CB9F8E5CD7581862D16C12478232AE048A643AC3F4B3E215DB5AFFB1E` |
| SSDEEP | `24576:vrky3zrN7AFYF4NhHLG7aXhxIWS5P+faWhyR:vrt3vdKNNG1WS5P+x` |
| ICON-DHASH | `9671e0d4d4e07196` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_2c868a4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c868a4a61dfc58fa73b87a9e68c7876f836c608c539558053d829ea462064cb"
    family = "unknown"
    file_name = "Setup-2.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:24:58"
  condition:
    hash.sha256(0, filesize) == "2c868a4a61dfc58fa73b87a9e68c7876f836c608c539558053d829ea462064cb"
}
```

### Sample 50: `0cffe2b753674df3`

| Field | Value |
|---|---|
| SHA-256 | `0cffe2b753674df357aa2980e349765dc763602149f1a61de87cf817506857eb` |
| Family label | `unknown` |
| File name | `Setup-1.exe` |
| File type | `exe` |
| First seen | `2026-10-31 23:23:28` |
| Reporter | `iamaachum` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d806c5a233e3a296952527a4e180eb32` |
| SHA-1 | `465ee90e168d6d7c4b7543cfa81158706140026e` |
| SHA-256 | `0cffe2b753674df357aa2980e349765dc763602149f1a61de87cf817506857eb` |
| SHA3-384 | `430dc686f140c46caa6006877cfebf3736a0025df29298791cffa4c843ea2bf099c64ffc264e5d7799be2801c4abe6b5` |
| IMPHASH | `b3341ab58e3f414ed3c99efcc3b6303f` |
| TLSH | `T178352B385B961CFBF9F5E3B2B3414429E460D53241F08ACEA93F8E678614248DDEA51F` |
| SSDEEP | `12288:abKkqrJEi1TAOY5ldu0pFxf8qe1AJZR98l+bxrcqPYjY9EatW4e4Jj6RiRZbRHCs:QKkaqz/dNxbemWQFC0EatWGp6obVC1` |
| ICON-DHASH | `08341272b1125a04` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_0cffe2b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cffe2b753674df357aa2980e349765dc763602149f1a61de87cf817506857eb"
    family = "unknown"
    file_name = "Setup-1.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:23:28"
  condition:
    hash.sha256(0, filesize) == "0cffe2b753674df357aa2980e349765dc763602149f1a61de87cf817506857eb"
}
```

### Sample 51: `73c6c7a8ee2b6503`

| Field | Value |
|---|---|
| SHA-256 | `73c6c7a8ee2b650316b8723b9b581b200678329fac21f4bb73e11f6adf81bf01` |
| Family label | `unknown` |
| File name | `gitlосitу64-v.5.502.exe` |
| File type | `exe` |
| First seen | `2026-10-31 23:05:53` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed, stealer, Vidar, vidarstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f124dfb1d48b8217bff20cdaad06bd1c` |
| SHA-1 | `1bbd9d65cea6604b08bd6b594e13696d485515b4` |
| SHA-256 | `73c6c7a8ee2b650316b8723b9b581b200678329fac21f4bb73e11f6adf81bf01` |
| SHA3-384 | `11e5d3fd4ab028b46fd517fbf1155db8a6b819dfd733796ef9fc13394459d7d08898064f7e3b0d5453a7f912e0c245fd` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1DD467D13FDA154AAC4AAA234C4A752427BB47C8D6B3173D32F40F6382E767D05EB9B05` |
| SSDEEP | `49152:oAlC0A15gJGCFViRaz34/1ZlJoylwI5hXtdBod9XaY2B0pEPLQ:oMgxx5PEd9qY2BQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_73c6c7a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73c6c7a8ee2b650316b8723b9b581b200678329fac21f4bb73e11f6adf81bf01"
    family = "unknown"
    file_name = "gitlосitу64-v.5.502.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:05:53"
  condition:
    hash.sha256(0, filesize) == "73c6c7a8ee2b650316b8723b9b581b200678329fac21f4bb73e11f6adf81bf01"
}
```

### Sample 52: `3cbaae896e2ac678`

| Field | Value |
|---|---|
| SHA-256 | `3cbaae896e2ac678aa0a43622ab6025d3cd3f9b5bf3970feccd2662b12b15dea` |
| Family label | `Mirai` |
| File name | `main_arm5` |
| File type | `elf` |
| First seen | `2026-10-31 23:01:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b34d5a2a89d7f92189ef170ee4ff5d0` |
| SHA-1 | `0de682a10c3236909d6e0b7d7a68c051b6546709` |
| SHA-256 | `3cbaae896e2ac678aa0a43622ab6025d3cd3f9b5bf3970feccd2662b12b15dea` |
| SHA3-384 | `556d1ccbb5ed13de270870af6a7f06ebf6f46105d66bd4c8f04c0d87a8c70364c6982b681f9ac58afdbfb539e1bf9fb2` |
| TLSH | `T12AE31A45FC509A12C6D622BBFF5E428D372A17A8D3EE72079D156F20378796B0E3B502` |
| TELFHASH | `t10621fd26cf6c0fdcb7f482955169720a0fea35b8372039da5f563e9f5403591b41e032` |
| SSDEEP | `3072:tC8EZ9vyGA+NWPRyudkpN473USd+YpQIs84m7ro:tCf1AQ+qpN47kSd+sshm3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_3cbaae89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cbaae896e2ac678aa0a43622ab6025d3cd3f9b5bf3970feccd2662b12b15dea"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-10-31 23:01:35"
  condition:
    hash.sha256(0, filesize) == "3cbaae896e2ac678aa0a43622ab6025d3cd3f9b5bf3970feccd2662b12b15dea"
}
```

### Sample 53: `5b6f9a43cbd0e760`

| Field | Value |
|---|---|
| SHA-256 | `5b6f9a43cbd0e7608ff4b6bdae43a66dd5d435caa1c078f39955dae1bb703965` |
| Family label | `unknown` |
| File name | `export.php` |
| File type | `exe` |
| First seen | `2026-10-31 22:52:29` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00f63ebe109a55d488071f45b9c36953` |
| SHA-1 | `b2b80c0217c6ff8f7acf210ceb44c34779570151` |
| SHA-256 | `5b6f9a43cbd0e7608ff4b6bdae43a66dd5d435caa1c078f39955dae1bb703965` |
| SHA3-384 | `19810f3d7737f03324940c6fa9079fa47b531cb918d48ba275d7ad0cbdaa0f111a371adb6070eabefcd0fbc7b1ae6a81` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19725F11BBAE0FEAFC4166DF79F90A9128200C11D1D03E2365B9732BDD26C89F69157C6` |
| SSDEEP | `24576:2omMUkowOFvGo5Ce9DBYqFyPecr/Lw97JOQ4SXshNWt:2omRt3DDCqF4ecr/M5iN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_5b6f9a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b6f9a43cbd0e7608ff4b6bdae43a66dd5d435caa1c078f39955dae1bb703965"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-10-31 22:52:29"
  condition:
    hash.sha256(0, filesize) == "5b6f9a43cbd0e7608ff4b6bdae43a66dd5d435caa1c078f39955dae1bb703965"
}
```

### Sample 54: `7b026f26374a7aea`

| Field | Value |
|---|---|
| SHA-256 | `7b026f26374a7aea28f4c4e483fe9aad004ee3a7e33d308aa3a8de0bd5dfb303` |
| Family label | `Mirai` |
| File name | `bot-linux-mips` |
| File type | `elf` |
| First seen | `2026-10-31 22:51:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `704fe05da19f0906baa1b4a4b409f1f7` |
| SHA-1 | `7feaf3d341c31d4840f4ca39af8858523b189552` |
| SHA-256 | `7b026f26374a7aea28f4c4e483fe9aad004ee3a7e33d308aa3a8de0bd5dfb303` |
| SHA3-384 | `83caf6ff5d1e4afced3170bbdae08d425147861c4de6651904c629178e0bba112f42ae8c009c7e5f9248672dbfda793b` |
| TLSH | `T1CFA66B17BB2CEB4EE21822305DF2CA856B2A5C9541D7A417A341F718E8F317C5A6EDF0` |
| TELFHASH | `t1583453a3cc26bf5b4fc403229cf6c5c4535bd04608927b996fb09336d4eb48da5ba35a` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:pZzBnM0KoVNUg0n4jEtcvCecU+juubyg4h85eJmqQV9K:vzBnpCg0njtICR5AQnK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_7b026f26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b026f26374a7aea28f4c4e483fe9aad004ee3a7e33d308aa3a8de0bd5dfb303"
    family = "Mirai"
    file_name = "bot-linux-mips"
    file_type = "elf"
    first_seen = "2026-10-31 22:51:45"
  condition:
    hash.sha256(0, filesize) == "7b026f26374a7aea28f4c4e483fe9aad004ee3a7e33d308aa3a8de0bd5dfb303"
}
```

### Sample 55: `d35eea4fca7cf1b3`

| Field | Value |
|---|---|
| SHA-256 | `d35eea4fca7cf1b35418f3fe62f5fc442b2af9a73e8b665961f915611895d12b` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-31 22:51:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89611f03df79d5ba70e59a222f298bed` |
| SHA-1 | `5a57ac146f1849fac7088dbb43e5897c9494dcdb` |
| SHA-256 | `d35eea4fca7cf1b35418f3fe62f5fc442b2af9a73e8b665961f915611895d12b` |
| SHA3-384 | `c97404b49a404ffffae683cf2220135e93fb70864b6e2a6b289a56c16009614b6925eaa455c9836198f6f9a747ef6dde` |
| TLSH | `T12B556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS7:SDjxB4m5n8XlaPWi+d+a4TjxQP4d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_d35eea4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d35eea4fca7cf1b35418f3fe62f5fc442b2af9a73e8b665961f915611895d12b"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-31 22:51:42"
  condition:
    hash.sha256(0, filesize) == "d35eea4fca7cf1b35418f3fe62f5fc442b2af9a73e8b665961f915611895d12b"
}
```

### Sample 56: `a84568d291f3ab3e`

| Field | Value |
|---|---|
| SHA-256 | `a84568d291f3ab3e2862c875d57657236258fa591ae251f379c23263885ead4b` |
| Family label | `CoinMiner` |
| File name | `CenterMSI_drive11.164.10.exe` |
| File type | `exe` |
| First seen | `2026-10-31 22:43:13` |
| Reporter | `iamaachum` |
| Tags | `191-217-210-95, CoinMiner, CorvusMiner, dropped-by-WARDENStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bd7ed167b3d1910bc90a1e2cb317f85` |
| SHA-1 | `58c7c1513d1a28d1797d9cd6d0df0cf4659a3e8c` |
| SHA-256 | `a84568d291f3ab3e2862c875d57657236258fa591ae251f379c23263885ead4b` |
| SHA3-384 | `cb27031ea08f4095785008b5abc9949ae32c515d7b6914ffcf45e8db036d6b82750d36dd4b0509d81fa107d3ef1b456a` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T18DC6011BFCA418E9C4AEA231897299527B717C481F3123D72B50B6B83F72BD0AD79705` |
| SSDEEP | `196608:cXModv5eEv40KNs4p0qjafehOgD/TnVUlMB7Ss/G9JP1Th:c9dv3mNb0ykehOgXnF5SvvP1` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_056_a84568d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a84568d291f3ab3e2862c875d57657236258fa591ae251f379c23263885ead4b"
    family = "CoinMiner"
    file_name = "CenterMSI_drive11.164.10.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:43:13"
  condition:
    hash.sha256(0, filesize) == "a84568d291f3ab3e2862c875d57657236258fa591ae251f379c23263885ead4b"
}
```

### Sample 57: `9c3a760765258f5e`

| Field | Value |
|---|---|
| SHA-256 | `9c3a760765258f5e7802e828af6d5b88d69eee4bfc497e741d1bc4d80738242b` |
| Family label | `CoinMiner` |
| File name | `CenterMSI_drive11.164.10.exe` |
| File type | `exe` |
| First seen | `2026-10-31 22:42:06` |
| Reporter | `iamaachum` |
| Tags | `191-217-210-94, CoinMiner, CorvusMiner, dropped-by-WARDENStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c237a67ff109f651507303052881e1c` |
| SHA-1 | `555a4ffd105f202439f652919422dd55c307bcab` |
| SHA-256 | `9c3a760765258f5e7802e828af6d5b88d69eee4bfc497e741d1bc4d80738242b` |
| SHA3-384 | `707af525f568121ca12ad0c0fee88936ef75ee993b01d33d602546ce2354c68d3aab1c03b1645480e79806202221cf42` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T116C6F10BEC5198F9C0BA927149329952BF397C491B3193D72B94B6B82E73BE0DE75700` |
| SSDEEP | `196608:OMEa+jUIP9z1lAS2eEb2FyQ0RKba0wwlZUBT0dEjl7JVhivmJz:Oxa+jUI5PQHK4QXb9wlFjFoI` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_057_9c3a7607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c3a760765258f5e7802e828af6d5b88d69eee4bfc497e741d1bc4d80738242b"
    family = "CoinMiner"
    file_name = "CenterMSI_drive11.164.10.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:42:06"
  condition:
    hash.sha256(0, filesize) == "9c3a760765258f5e7802e828af6d5b88d69eee4bfc497e741d1bc4d80738242b"
}
```

### Sample 58: `ba4ee6ce0b34b33d`

| Field | Value |
|---|---|
| SHA-256 | `ba4ee6ce0b34b33d2b9494f45ef059e7360dcf783240674ca06a61e352667908` |
| Family label | `unknown` |
| File name | `pyservice64.exe` |
| File type | `exe` |
| First seen | `2026-10-31 22:40:50` |
| Reporter | `iamaachum` |
| Tags | `cloudflare-gd, CoinMiner, corvusminer, dropped-by-WARDENStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0974330985ad4a64254435ce269d8d78` |
| SHA-1 | `9685778fd1e7aa09118af06f4ad8153aa3787de7` |
| SHA-256 | `ba4ee6ce0b34b33d2b9494f45ef059e7360dcf783240674ca06a61e352667908` |
| SHA3-384 | `29904043a008e6b561469e45f3962749e6af2a3984981f4932539a960f0ab0511bc58937fd202ab31bc57542fa2acfc1` |
| IMPHASH | `0399b4182ddfc6730283cd2dbbd3b686` |
| TLSH | `T11DB73307FCA518F6C4AAE235893795127B71BC880F3123DB1E50BAA82F727D05D7A764` |
| SSDEEP | `786432:OV4SSuXY5b7sKQDSffNXwUNUrhqKn1liECtH1n6LONQpvJ0rrznKep7HdIAoJ:cK5vgGXFUrhqAiECtVniOtrzn9g` |
| ICON-DHASH | `dcdcdcdcfcfcd4d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_ba4ee6ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba4ee6ce0b34b33d2b9494f45ef059e7360dcf783240674ca06a61e352667908"
    family = "unknown"
    file_name = "pyservice64.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:40:50"
  condition:
    hash.sha256(0, filesize) == "ba4ee6ce0b34b33d2b9494f45ef059e7360dcf783240674ca06a61e352667908"
}
```

### Sample 59: `5795fe674d0f9759`

| Field | Value |
|---|---|
| SHA-256 | `5795fe674d0f9759cdfc26217924dcbdcf37f23a78131bce6d92b3398f608d0d` |
| Family label | `unknown` |
| File name | `vcomp140.exe` |
| File type | `exe` |
| First seen | `2026-10-31 22:39:49` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-Stealc, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eef03b5360332abe50f232349e1d8cd1` |
| SHA-1 | `c2669f6b55443a159258da1bc317b9d38f22a045` |
| SHA-256 | `5795fe674d0f9759cdfc26217924dcbdcf37f23a78131bce6d92b3398f608d0d` |
| SHA3-384 | `3b45d0456bc3726a5567a627dade00927d04f93ee7ec3683a24d92cbb594ee5b1122d3f1157ab2e9ae0eada62d23f7ad` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1AD56D007FCA109E6C0AAA23189B395867F71BC491F2563C72EA0B7782F72BE05D74754` |
| SSDEEP | `98304:WR1zEEd/ngl/tsYasjca7tsMIvQFz5VnCPl9+pyayHltn:WRphBc/tsYastsHaVnW2yaYn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_5795fe67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5795fe674d0f9759cdfc26217924dcbdcf37f23a78131bce6d92b3398f608d0d"
    family = "unknown"
    file_name = "vcomp140.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:39:49"
  condition:
    hash.sha256(0, filesize) == "5795fe674d0f9759cdfc26217924dcbdcf37f23a78131bce6d92b3398f608d0d"
}
```

### Sample 60: `806351b3460f58bd`

| Field | Value |
|---|---|
| SHA-256 | `806351b3460f58bd7a3a4f939ab78f8faa076fffa38628fb516b9716394e62f6` |
| Family label | `CoinMiner` |
| File name | `IntelRMS_service112.90.988.exe` |
| File type | `exe` |
| First seen | `2026-10-31 22:39:20` |
| Reporter | `iamaachum` |
| Tags | `191-217-210-95, CoinMiner, CorvusMiner, dropped-by-WARDENStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9c460283d8c40910e598b14a008fda1` |
| SHA-1 | `457c265bdcee3f1dd2fd7b3b7e0292f637b018d7` |
| SHA-256 | `806351b3460f58bd7a3a4f939ab78f8faa076fffa38628fb516b9716394e62f6` |
| SHA3-384 | `ac5bf289d3db0f1622101e32e6ae46ed93b9dd0a4b49800cd19219368b8afbe33a607cfe3ead24426e0e42d2db5cc78d` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T13EC6020BFCA158E5C4AE9232897299527B31BC481F3127D72B40B6B82FB3BD06D79715` |
| SSDEEP | `196608:lW1Jvdc0fDuIYYG3aD1EOB3Lpg7rru4XtySrw24sOpIDP:lWc0b/GKGOBlg7rq4Xfrw2nOpIb` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_060_806351b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "806351b3460f58bd7a3a4f939ab78f8faa076fffa38628fb516b9716394e62f6"
    family = "CoinMiner"
    file_name = "IntelRMS_service112.90.988.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:39:20"
  condition:
    hash.sha256(0, filesize) == "806351b3460f58bd7a3a4f939ab78f8faa076fffa38628fb516b9716394e62f6"
}
```

### Sample 61: `6c9c45fbe531f5a8`

| Field | Value |
|---|---|
| SHA-256 | `6c9c45fbe531f5a89190a1b6ddf674edb4aa2d1b53e215e237b78ab7cd7bfb8b` |
| Family label | `CoinMiner` |
| File name | `IntelRMS_service112.90.988.exe` |
| File type | `exe` |
| First seen | `2026-10-31 22:36:21` |
| Reporter | `iamaachum` |
| Tags | `191-217-210-95, CoinMiner, CorvusMiner, dropped-by-WARDENStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5041bf073e849bcd751f85c48c0c5c7c` |
| SHA-1 | `562e43ec1ee8bb7eca70db3ee62734efe77be289` |
| SHA-256 | `6c9c45fbe531f5a89190a1b6ddf674edb4aa2d1b53e215e237b78ab7cd7bfb8b` |
| SHA3-384 | `1a74d90712e286a62b6692809ba4c19758087421547a2e7567d4961cbd322de52bca24b73dafb1e9f61a288f5da96a21` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T134C60107FCA518F5C0AE963189729562BB21BC441F2123DB2B50F6B82FB3BD0AD79754` |
| SSDEEP | `196608:BsC79yZT6JhN/GqAeGGC08LK6uq5Is6TZ5Tpf5rS+LuGW:B77klQLGqDvZ8NCTs+qGW` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_061_6c9c45fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c9c45fbe531f5a89190a1b6ddf674edb4aa2d1b53e215e237b78ab7cd7bfb8b"
    family = "CoinMiner"
    file_name = "IntelRMS_service112.90.988.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:36:21"
  condition:
    hash.sha256(0, filesize) == "6c9c45fbe531f5a89190a1b6ddf674edb4aa2d1b53e215e237b78ab7cd7bfb8b"
}
```

### Sample 62: `ab1cee0ca786d407`

| Field | Value |
|---|---|
| SHA-256 | `ab1cee0ca786d407e2d0ef724056d6ec47092587b71ec23e41fc9bd495c8cd3e` |
| Family label | `unknown` |
| File name | `ab1cee0ca786d407e2d0ef724056d6ec47092587b71ec23e41fc9bd495c8cd3e.dll` |
| File type | `exe` |
| First seen | `2026-10-31 22:21:35` |
| Reporter | `Kejult` |
| Tags | `defendertamper, dll, exe, killDefender` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ab770be0917963d7492574c5d8626b3` |
| SHA-1 | `c95fbabd1c53d8ff7374b82bfb266484a3ac4954` |
| SHA-256 | `ab1cee0ca786d407e2d0ef724056d6ec47092587b71ec23e41fc9bd495c8cd3e` |
| SHA3-384 | `5904df99de11cf3ee6cdef294b47319b376faeae374b4ba75e47b75f82b90039309bc01eb799432517970e6804e301f7` |
| IMPHASH | `5b05610e8d423db235d424b1c9876342` |
| TLSH | `T17EE6C99B0016D746AC394B7B8CB70172A3FF1289F83E95B235D9B9705D216AB18603DF` |
| SSDEEP | `49152:XBxp6ZZra576DHr6GSpsFkZqGnnx0ZPghLVbrMvu1x9BQYn0jYl/5Khmuog6:j/q6vhjVbyuz/lhKhk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_ab1cee0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab1cee0ca786d407e2d0ef724056d6ec47092587b71ec23e41fc9bd495c8cd3e"
    family = "unknown"
    file_name = "ab1cee0ca786d407e2d0ef724056d6ec47092587b71ec23e41fc9bd495c8cd3e.dll"
    file_type = "exe"
    first_seen = "2026-10-31 22:21:35"
  condition:
    hash.sha256(0, filesize) == "ab1cee0ca786d407e2d0ef724056d6ec47092587b71ec23e41fc9bd495c8cd3e"
}
```

### Sample 63: `1e48eb751699f706`

| Field | Value |
|---|---|
| SHA-256 | `1e48eb751699f706278e798d3d8f679fefe3f4fc1347d68f3d875d8a366e4075` |
| Family label | `RustyStealer` |
| File name | `1e48eb751699f706278e798d3d8f679fefe3f4fc1347d68f3d875d8a366e4075.dll` |
| File type | `exe` |
| First seen | `2026-10-31 22:20:52` |
| Reporter | `Kejult` |
| Tags | `dll, exe, nwh, nwhstealer, RustyStealer, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36bb9d5df97c6dbd7ebb3f8a10ebf3cc` |
| SHA-1 | `3e68883675b6aa4e5ccd48f61f7fc6f16af714fa` |
| SHA-256 | `1e48eb751699f706278e798d3d8f679fefe3f4fc1347d68f3d875d8a366e4075` |
| SHA3-384 | `9d4ae5b8e62f186a7284d8220c60b754e223c03ce9ff43c0de25dd408f1dac930820cb04e6d6c2e3e5c27dada09fbe8a` |
| IMPHASH | `e58b1de1b0892e8f36424fddb102489d` |
| TLSH | `T1CA46685EBB8B3ABCC71B0539452B473A3819E6450A69CCBF85D6D3B0FD306421616EF2` |
| SSDEEP | `98304:lcsCj1BHmb/OcaNp6m7Swl0W9OCmwiZy/eCsxvhzzAkfXPi:lcF1xmbGr2mVe0PAyTcvhYM/i` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_063_1e48eb75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e48eb751699f706278e798d3d8f679fefe3f4fc1347d68f3d875d8a366e4075"
    family = "RustyStealer"
    file_name = "1e48eb751699f706278e798d3d8f679fefe3f4fc1347d68f3d875d8a366e4075.dll"
    file_type = "exe"
    first_seen = "2026-10-31 22:20:52"
  condition:
    hash.sha256(0, filesize) == "1e48eb751699f706278e798d3d8f679fefe3f4fc1347d68f3d875d8a366e4075"
}
```

### Sample 64: `4f64901c53e90330`

| Field | Value |
|---|---|
| SHA-256 | `4f64901c53e903309136e13892c4c8a5c4c57550b08acd1ae53757ca43c7d8e5` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-10-31 22:16:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0178491f83696a471c33406e4f85b349` |
| SHA-1 | `a0008fc33ea910da3fb33e432d3c3bb30026d0ae` |
| SHA-256 | `4f64901c53e903309136e13892c4c8a5c4c57550b08acd1ae53757ca43c7d8e5` |
| SHA3-384 | `711d8c1bbb8bf2b8b5eef3a8ca6d8aa65b214b9de5251e1608a12cf42dc765d5dc2403d285c94972865622317752d1d2` |
| TLSH | `T15014C60AAB510FFBDCAFCD3706E90B0638CD651722A47B3A7674D528F54A50B49E3C68` |
| SSDEEP | `3072:bRoKcX+vZTxWYesGBmn87pgiBHbzi/WYvV/a2E:bRYuvZTusGCSgiBHaZc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_4f64901c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f64901c53e903309136e13892c4c8a5c4c57550b08acd1ae53757ca43c7d8e5"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-10-31 22:16:43"
  condition:
    hash.sha256(0, filesize) == "4f64901c53e903309136e13892c4c8a5c4c57550b08acd1ae53757ca43c7d8e5"
}
```

### Sample 65: `d912ad7735ac150a`

| Field | Value |
|---|---|
| SHA-256 | `d912ad7735ac150a5b289f5c7f4ed61971288433786c5212d329e33037a9bf5a` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-31 22:14:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `484f0b6fa3cdd6dfe4ac76ef06ab8e4d` |
| SHA-1 | `4176c23841348a5e7363732faa5e69f4e6dbfa60` |
| SHA-256 | `d912ad7735ac150a5b289f5c7f4ed61971288433786c5212d329e33037a9bf5a` |
| SHA3-384 | `2ab19757ccc63b0a67c7533b7ad190fd854c32b97b7865c14e6e5ec47999a44807a95f832c68266fd970af947571d7dc` |
| TLSH | `T1CD556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSy:SDjxB4m5n8XlaPWi+d+a4TjxQP4U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_d912ad77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d912ad7735ac150a5b289f5c7f4ed61971288433786c5212d329e33037a9bf5a"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-31 22:14:15"
  condition:
    hash.sha256(0, filesize) == "d912ad7735ac150a5b289f5c7f4ed61971288433786c5212d329e33037a9bf5a"
}
```

### Sample 66: `d8c97a23c53348a4`

| Field | Value |
|---|---|
| SHA-256 | `d8c97a23c53348a4070186283e3ac0aabce26e33e8f5bd64731408eb768dd40d` |
| Family label | `unknown` |
| File name | `Dhcud0.hta` |
| File type | `hta` |
| First seen | `2026-10-31 21:55:40` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dad3fb75db159672c2e0527f1d6e377c` |
| SHA-1 | `c408635be227962bbffdc67a6e19d346096872a4` |
| SHA-256 | `d8c97a23c53348a4070186283e3ac0aabce26e33e8f5bd64731408eb768dd40d` |
| SHA3-384 | `26fc17f7798e009112d6160f7e255445fa0e3ef9184504e907f30c87bef6eaa5e03a193039fc35f4f156d3f8717a0329` |
| TLSH | `T1BE42185CAED161B0EB1707DEA3AF25690228A0C7240DC484F94CDEE87F467DC4A57B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzjbqFtCESfRUM:sXX+/DV7k/3iFtaRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_d8c97a23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8c97a23c53348a4070186283e3ac0aabce26e33e8f5bd64731408eb768dd40d"
    family = "unknown"
    file_name = "Dhcud0.hta"
    file_type = "hta"
    first_seen = "2026-10-31 21:55:40"
  condition:
    hash.sha256(0, filesize) == "d8c97a23c53348a4070186283e3ac0aabce26e33e8f5bd64731408eb768dd40d"
}
```

### Sample 67: `323c3cff3088cebc`

| Field | Value |
|---|---|
| SHA-256 | `323c3cff3088cebcb9d637896828aa4f29a3a5e726b7b0cf1a6ecf6fe8d8883e` |
| Family label | `Mirai` |
| File name | `main_x86_64` |
| File type | `elf` |
| First seen | `2026-10-31 21:55:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc80a81eea9f0b5b219760da61fb4b33` |
| SHA-1 | `0c8359513d6845e69de52ee92583cb71fb879760` |
| SHA-256 | `323c3cff3088cebcb9d637896828aa4f29a3a5e726b7b0cf1a6ecf6fe8d8883e` |
| SHA3-384 | `67a05132d3786efc765300beb4ac994caafc0bf894c7021ae90ad918e51cc2025e5bbe47bc90172e27671872a355b3f0` |
| TLSH | `T1B0F34A03B5C094FDC8D9C2788BAFB13ADD72F51D1138B16F2784AA271E9DE206B2D651` |
| TELFHASH | `t19551ad303caa2d6861ebe2b9734ed859e8720a1019e174e4de276df5df027850da1036` |
| SSDEEP | `3072:k14itvt9WCa7h3SxPqHlZIUHeYULPLZQnijepbcA6u7F:G4itvt9WCadiwlE6ItAR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_323c3cff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "323c3cff3088cebcb9d637896828aa4f29a3a5e726b7b0cf1a6ecf6fe8d8883e"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-10-31 21:55:36"
  condition:
    hash.sha256(0, filesize) == "323c3cff3088cebcb9d637896828aa4f29a3a5e726b7b0cf1a6ecf6fe8d8883e"
}
```

### Sample 68: `c5906f3997ae2a42`

| Field | Value |
|---|---|
| SHA-256 | `c5906f3997ae2a42761bcf036e9da971a7f372dbd8013884fd8934b6e48b28db` |
| Family label | `unknown` |
| File name | `export.php` |
| File type | `exe` |
| First seen | `2026-10-31 21:52:26` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d27855b01a9200728682a69c423a8e45` |
| SHA-1 | `a59e273fa649257e1f7943b7a7c2e077d2ed0fb0` |
| SHA-256 | `c5906f3997ae2a42761bcf036e9da971a7f372dbd8013884fd8934b6e48b28db` |
| SHA3-384 | `3609988d008562ebb197fb578dbf6ec9dc8ff97969b13e8170fe5872c557bf831a0c2f1917a5c72b3963d363b27b6369` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19425F1FFB98C348EC94BC97AD86C185BF2D45A534E029602623BD9CAC1D8F85CF42593` |
| SSDEEP | `24576:OVXGlcuB2FjE7CFN+VVznO2raYZaWKv7TQg:3y7kCFAMYZaj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_c5906f39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5906f3997ae2a42761bcf036e9da971a7f372dbd8013884fd8934b6e48b28db"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-10-31 21:52:26"
  condition:
    hash.sha256(0, filesize) == "c5906f3997ae2a42761bcf036e9da971a7f372dbd8013884fd8934b6e48b28db"
}
```

### Sample 69: `b054dff887f2fde9`

| Field | Value |
|---|---|
| SHA-256 | `b054dff887f2fde959f25b42dc49d6dc0dd504f863d0a896a143fc01b21a2de6` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-31 21:48:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de75fb6d0b988b9f9aa1fce4b998a826` |
| SHA-1 | `05f1b6ce02e71958b7c9e4f5d6eb8e9b486527df` |
| SHA-256 | `b054dff887f2fde959f25b42dc49d6dc0dd504f863d0a896a143fc01b21a2de6` |
| SHA3-384 | `e1f7720ecb27ff657ea3030fbfe052f4c5e57882d56171d55540fcefe11247c31f2531a93f1253ed80dddd30552c2351` |
| TLSH | `T192741A88A1F1E7DED2D4EA75B319780D3A230736B1DB3146A51DAA3333EB1450AFD921` |
| TELFHASH | `t1e3f0c623ec709dcc6bd79075d6abd0568074355813c560c7abf8599d4d27e1146f4471` |
| SSDEEP | `6144:QYCUy6aDr4oMiwSXeFKQomGnIwi6i4w4PZdxMzija9Mrc:2vdMiwaeQmgThZTMya9Mrc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_b054dff8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b054dff887f2fde959f25b42dc49d6dc0dd504f863d0a896a143fc01b21a2de6"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-31 21:48:13"
  condition:
    hash.sha256(0, filesize) == "b054dff887f2fde959f25b42dc49d6dc0dd504f863d0a896a143fc01b21a2de6"
}
```

### Sample 70: `d7006d308ee13d9b`

| Field | Value |
|---|---|
| SHA-256 | `d7006d308ee13d9b4324a2fbd91549ef9604c3313486ce991f7eb3ceedb55140` |
| Family label | `unknown` |
| File name | `interview_jibril_rajoub.hta` |
| File type | `hta` |
| First seen | `2026-10-31 21:33:55` |
| Reporter | `smica83` |
| Tags | `APT-C-23, AridViper, hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76a3f0b55803e376a3cdd31d73b9e803` |
| SHA-1 | `d2bb947b22bfa4e04a540dd8ce455fbf67cbfa46` |
| SHA-256 | `d7006d308ee13d9b4324a2fbd91549ef9604c3313486ce991f7eb3ceedb55140` |
| SHA3-384 | `7097014d00d214e931ff4f6d61b1294efae2ec9746fe43194e764e328732fd3ed74c7b23330bd9862a094851fb02828d` |
| TLSH | `T18E2171A11A2FC7ECCABA13A8490DC654C5D7601C6709A753716CC40639617938FDCB9E` |
| SSDEEP | `24:NJ2ZSvzdjrsD7KrEjoivCwelYAztdOuVXLQernOHDk3OnHnVt5PllOWTMC6:7pvz47JEivCweqUtsuJSjpnVrOC6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_d7006d30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7006d308ee13d9b4324a2fbd91549ef9604c3313486ce991f7eb3ceedb55140"
    family = "unknown"
    file_name = "interview_jibril_rajoub.hta"
    file_type = "hta"
    first_seen = "2026-10-31 21:33:55"
  condition:
    hash.sha256(0, filesize) == "d7006d308ee13d9b4324a2fbd91549ef9604c3313486ce991f7eb3ceedb55140"
}
```

### Sample 71: `2cf2922d0df1857f`

| Field | Value |
|---|---|
| SHA-256 | `2cf2922d0df1857f9fe38b3ab7666f85f791e68ee648e3790630c7ac4136a978` |
| Family label | `unknown` |
| File name | `CV_israa_Jerusalem.hta` |
| File type | `hta` |
| First seen | `2026-10-31 21:29:25` |
| Reporter | `smica83` |
| Tags | `APT-C-23, AridViper, hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0b04e318e2e152ffc1bf482facf5c05` |
| SHA-1 | `4244b0cb3769be5f948cbcaf29fbd77dba414512` |
| SHA-256 | `2cf2922d0df1857f9fe38b3ab7666f85f791e68ee648e3790630c7ac4136a978` |
| SHA3-384 | `81024aae8a297ae562947fe48407d3d905b3d039ae7d4790757cd03fa7054982d8c10a91023b317e8dd728a00f426e52` |
| TLSH | `T1BF2186601E8E83ACC6EE137C5A48C260C4D7540C6315AB93719CC9423DA1696CFDD79C` |
| SSDEEP | `24:NJ2ZSvzdjrsDsKrxoivvFwelYAztdOJVpoYB3OHDkw/IHnVt5PllyiDWTMC6:7pvz4sZivdweqUtsJT4jp/WnVrrC6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_2cf2922d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cf2922d0df1857f9fe38b3ab7666f85f791e68ee648e3790630c7ac4136a978"
    family = "unknown"
    file_name = "CV_israa_Jerusalem.hta"
    file_type = "hta"
    first_seen = "2026-10-31 21:29:25"
  condition:
    hash.sha256(0, filesize) == "2cf2922d0df1857f9fe38b3ab7666f85f791e68ee648e3790630c7ac4136a978"
}
```

### Sample 72: `2dc9ea3c14cb2af3`

| Field | Value |
|---|---|
| SHA-256 | `2dc9ea3c14cb2af3a4eb4cd4688a3540cae434b4e5394ea09b4b64eb6d4a81cc` |
| Family label | `unknown` |
| File name | `CV_israa_Jerusalem.docm` |
| File type | `docm` |
| First seen | `2026-10-31 21:28:37` |
| Reporter | `smica83` |
| Tags | `APT-C-23, AridViper, docm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0fab6619f0456203263ab3bc289cb40` |
| SHA-1 | `8a4730f451fe5b0ecdcd23e2facb963524798603` |
| SHA-256 | `2dc9ea3c14cb2af3a4eb4cd4688a3540cae434b4e5394ea09b4b64eb6d4a81cc` |
| SHA3-384 | `73b30f4c60f592bcc7e1ff7b72597ea9da0e882c7f335819bd57a2b1aa67ae0f15f1daddc0a77dd42b1d84a7f878f08b` |
| TLSH | `T14E82BF7DD181307FF5AAA47E94100BB0E1580911E970F87F5904F6AE8991E5B170FFDA` |
| SSDEEP | `384:/igsQtyybNgWwPvsu/SfgW6CaLrN6qINRU9fo:/bpyyWWQEySfn6PLKy2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `docm`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_2dc9ea3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dc9ea3c14cb2af3a4eb4cd4688a3540cae434b4e5394ea09b4b64eb6d4a81cc"
    family = "unknown"
    file_name = "CV_israa_Jerusalem.docm"
    file_type = "docm"
    first_seen = "2026-10-31 21:28:37"
  condition:
    hash.sha256(0, filesize) == "2dc9ea3c14cb2af3a4eb4cd4688a3540cae434b4e5394ea09b4b64eb6d4a81cc"
}
```

### Sample 73: `e34efe9b7001f45c`

| Field | Value |
|---|---|
| SHA-256 | `e34efe9b7001f45cbf03764eb9658c3c3e4889b1c81454758df799fa7dc40e9e` |
| Family label | `unknown` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-10-31 21:01:00` |
| Reporter | `AmadeyHunter` |
| Tags | `DIVINEX, exe, stealer, Warden, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18e98d2c16ee08ff0aa47f20151a8a49` |
| SHA-1 | `a59b4230af319460137f56800952113f11640280` |
| SHA-256 | `e34efe9b7001f45cbf03764eb9658c3c3e4889b1c81454758df799fa7dc40e9e` |
| SHA3-384 | `f70589e7a6eda04c8b63b471295fe5eec731d05e0290a39f359144ee76c26f1bea9d8c69274b8fd560af2f75469632ad` |
| IMPHASH | `40c62f9a65df089070bf68c57211cc64` |
| TLSH | `T182E40142BAE582ADE824C578C9575506F666FC400760A9FB63C4A73E2F37BC8573AF10` |
| SSDEEP | `12288:Spa3LhG/LHfE9SdKTXmRbX742RKKfMwByLgMp9kGfwFI0dr2:Ma3SHdKsw2UCPBI1p90ddr2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_e34efe9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e34efe9b7001f45cbf03764eb9658c3c3e4889b1c81454758df799fa7dc40e9e"
    family = "unknown"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-10-31 21:01:00"
  condition:
    hash.sha256(0, filesize) == "e34efe9b7001f45cbf03764eb9658c3c3e4889b1c81454758df799fa7dc40e9e"
}
```

### Sample 74: `42b9001bc3cba345`

| Field | Value |
|---|---|
| SHA-256 | `42b9001bc3cba3459607da359512d20adf4453f74d7ed793d39d77be465ee9c2` |
| Family label | `unknown` |
| File name | `OurNew.exe` |
| File type | `exe` |
| First seen | `2026-10-31 20:52:37` |
| Reporter | `iamaachum` |
| Tags | `151-243-28-105, dropped-by-OffLoader, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b84a5e42e8ca3c0bc1b8b6ed1474d5c4` |
| SHA-1 | `d95949733d3b3766f1611522b6c7e4e5fabb012d` |
| SHA-256 | `42b9001bc3cba3459607da359512d20adf4453f74d7ed793d39d77be465ee9c2` |
| SHA3-384 | `db656464573abdf8ff91e89f836b3bb6571e2f08b39a946d2df6223b074bad8b9ca9e06b42cc0d59538d7d7b5ee0597e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18736EFA85CAB6602D5BBC3F65F9ED4A7C6461C133905DE2922FF4BB8961B9C09043D3C` |
| SSDEEP | `98304:gTjfnQTqVLik+6MNV/6rTGt0P7J+JEQ4evoRmpSFdW3m8Z6inPr:K/SqNi+MNArCQ7gJtNYmpeW3D04Pr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_42b9001b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42b9001bc3cba3459607da359512d20adf4453f74d7ed793d39d77be465ee9c2"
    family = "unknown"
    file_name = "OurNew.exe"
    file_type = "exe"
    first_seen = "2026-10-31 20:52:37"
  condition:
    hash.sha256(0, filesize) == "42b9001bc3cba3459607da359512d20adf4453f74d7ed793d39d77be465ee9c2"
}
```

### Sample 75: `e3b3d631cba7f3ff`

| Field | Value |
|---|---|
| SHA-256 | `e3b3d631cba7f3ff41d6dcc207a52bc84e096facec79953684849564d85d40e3` |
| Family label | `unknown` |
| File name | `newisbest.exe` |
| File type | `exe` |
| First seen | `2026-10-31 20:52:31` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66172a54c3aeb2b7cd53656a07c5e0ae` |
| SHA-1 | `653c72e5a7687f54ebd7189c60034b0fbdf2d9b8` |
| SHA-256 | `e3b3d631cba7f3ff41d6dcc207a52bc84e096facec79953684849564d85d40e3` |
| SHA3-384 | `a5c46a151b11b3d9cf2fbc68476cd886f5b50458146490183a55a1b8e5626f3cde0558201a1d74d3461f094631baa1b0` |
| IMPHASH | `fba8030d9f17b9d5534e27fa1491df97` |
| TLSH | `T1C3353C583BCF0DF9F0575E753C842A4092A7256B41C8AEF18C4C05BB5C269CA1EFE97A` |
| SSDEEP | `12288:qGrDG2CzfVJjVi2FHdbvNsoFqCE+pnNuMXFXIKzAAJc/Ppv:qGfGj42FHdeihJpNXVXIgAAGXpv` |
| ICON-DHASH | `000c327171320c00` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_e3b3d631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3b3d631cba7f3ff41d6dcc207a52bc84e096facec79953684849564d85d40e3"
    family = "unknown"
    file_name = "newisbest.exe"
    file_type = "exe"
    first_seen = "2026-10-31 20:52:31"
  condition:
    hash.sha256(0, filesize) == "e3b3d631cba7f3ff41d6dcc207a52bc84e096facec79953684849564d85d40e3"
}
```

### Sample 76: `449162c0118749eb`

| Field | Value |
|---|---|
| SHA-256 | `449162c0118749eb2c836d1c8af26976f010a1842e04743694d6d5479a7542d9` |
| Family label | `Mirai` |
| File name | `main_sh4` |
| File type | `elf` |
| First seen | `2026-10-31 20:27:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6f7d36d6e0455bb47843a6ad9f4e434` |
| SHA-1 | `1691fe52b1393cd27983852e5e12850f17a8b33a` |
| SHA-256 | `449162c0118749eb2c836d1c8af26976f010a1842e04743694d6d5479a7542d9` |
| SHA3-384 | `884d14a2c44d9d859167f4885f1957adc9a806bdecdfcd019c187d7f761ee6ae993164c9c752ac490cc41c88d380b3f1` |
| TLSH | `T1B9D35AB3CC296F58E668D5B0F0308FBC2B63A51181871FBA56A7C6788047D8DF6457B8` |
| SSDEEP | `1536:WGd5tqZJ3EOAtZdQxYOzODguyR2C4MKb9D77uB4s+j9kCe32W0Y7LYbCg43a5:WGYXMZGO8RR2hbVNs+jBc2Wz7LYmRa5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_449162c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "449162c0118749eb2c836d1c8af26976f010a1842e04743694d6d5479a7542d9"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-10-31 20:27:40"
  condition:
    hash.sha256(0, filesize) == "449162c0118749eb2c836d1c8af26976f010a1842e04743694d6d5479a7542d9"
}
```

### Sample 77: `b25a752117a9f707`

| Field | Value |
|---|---|
| SHA-256 | `b25a752117a9f7072929b88771a281fc7a412a2955b087ef6b3741e8a2434343` |
| Family label | `unknown` |
| File name | `rvtools-4.8.1.msi` |
| File type | `msi` |
| First seen | `2026-10-31 19:29:06` |
| Reporter | `SquiblydooBlog` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1aa082ed170a8409552bef1fa790cdc` |
| SHA-1 | `aeb708466f02255ddec4688d4cffb90adfac0f39` |
| SHA-256 | `b25a752117a9f7072929b88771a281fc7a412a2955b087ef6b3741e8a2434343` |
| SHA3-384 | `2730edc3dd8360c6366d4dc3af125d3ab3d5eb7e4a7b3b67a17d104a00b15b67a6d37447e4d1d5f1ca0a8af8c9bebf26` |
| TLSH | `T1DA2733F899D52C2FFBC2207F05FB5D2E467039967007216ED372FD1B52AAAD028B4196` |
| SSDEEP | `393216:PVljnzesf/Q7wQSnNQlJ8l7lm6lZEqvSwobfq/I2TpTzkQH:PVpnzes36wQAelJ8l7VKqvLIyz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_b25a7521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b25a752117a9f7072929b88771a281fc7a412a2955b087ef6b3741e8a2434343"
    family = "unknown"
    file_name = "rvtools-4.8.1.msi"
    file_type = "msi"
    first_seen = "2026-10-31 19:29:06"
  condition:
    hash.sha256(0, filesize) == "b25a752117a9f7072929b88771a281fc7a412a2955b087ef6b3741e8a2434343"
}
```

### Sample 78: `4757f0ad27bc4a13`

| Field | Value |
|---|---|
| SHA-256 | `4757f0ad27bc4a13d3c9c50645359a19e6658962f864c4c580323e32824d33c6` |
| Family label | `unknown` |
| File name | `4757f0ad27bc4a13d3c9c50645359a19e6658962f864c4c580323e32824d33c6` |
| File type | `elf` |
| First seen | `2026-10-31 19:00:14` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8473a43c100ce40ef2fe313c86075fb3` |
| SHA-1 | `51a29fcd62d865911cdf6fa6e12aa29b1eaa3b81` |
| SHA-256 | `4757f0ad27bc4a13d3c9c50645359a19e6658962f864c4c580323e32824d33c6` |
| SHA3-384 | `164d0ca966da04d49e9c59ae56c41c552eaafd6a44dfffbd83bf4c8702ed74e0dc09556029c8a1bd348a073c7bf630b6` |
| TLSH | `T14F362973A49154E4D2EED574C6256213BEE0389B273423CB7BD076E11B7ABE49A78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQw:cqYUQuVDt0TZEP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_4757f0ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4757f0ad27bc4a13d3c9c50645359a19e6658962f864c4c580323e32824d33c6"
    family = "unknown"
    file_name = "4757f0ad27bc4a13d3c9c50645359a19e6658962f864c4c580323e32824d33c6"
    file_type = "elf"
    first_seen = "2026-10-31 19:00:14"
  condition:
    hash.sha256(0, filesize) == "4757f0ad27bc4a13d3c9c50645359a19e6658962f864c4c580323e32824d33c6"
}
```

### Sample 79: `3102a25b1ff3c134`

| Field | Value |
|---|---|
| SHA-256 | `3102a25b1ff3c13468769f7fe38ebaf50cf6660e7a533e2bde723bc17b8f6e39` |
| Family label | `unknown` |
| File name | `3102a25b1ff3c13468769f7fe38ebaf50cf6660e7a533e2bde723bc17b8f6e39` |
| File type | `elf` |
| First seen | `2026-10-31 18:53:39` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a07154f7aa818a97bfe23f73ffca314` |
| SHA-1 | `9a9a9ea4b45a3cfeea1f33593e79c19962079201` |
| SHA-256 | `3102a25b1ff3c13468769f7fe38ebaf50cf6660e7a533e2bde723bc17b8f6e39` |
| SHA3-384 | `12637e48e50885c4597a56b220523a42e99cfc0f504997f538b99c808b5f5d18ac9fce49c9211917af5b18b5d3ccc01f` |
| TLSH | `T1D7A5BE1BB59250FDC1D7C030879B9633AA32B49952347E7F62C4AF312E26F20675EB61` |
| SSDEEP | `49152:MOpFRF8oFPvnl50p+0eVlvviccJ1TbXLP9TIy2o162i0:FprnVnq+Zvqz1vL9TWo16X0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_3102a25b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3102a25b1ff3c13468769f7fe38ebaf50cf6660e7a533e2bde723bc17b8f6e39"
    family = "unknown"
    file_name = "3102a25b1ff3c13468769f7fe38ebaf50cf6660e7a533e2bde723bc17b8f6e39"
    file_type = "elf"
    first_seen = "2026-10-31 18:53:39"
  condition:
    hash.sha256(0, filesize) == "3102a25b1ff3c13468769f7fe38ebaf50cf6660e7a533e2bde723bc17b8f6e39"
}
```

### Sample 80: `7cd4c78e13625706`

| Field | Value |
|---|---|
| SHA-256 | `7cd4c78e13625706f3012bb236b48afcab8f4ef1ec4e9b7fc4c13a87a3cced02` |
| Family label | `unknown` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-10-31 18:49:22` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, Novrixs, stealer, Warden, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcc1c17fca2d1187843d1f4f762c5da7` |
| SHA-1 | `762480d14be6c2ddc1825f45c1e26a138206f44a` |
| SHA-256 | `7cd4c78e13625706f3012bb236b48afcab8f4ef1ec4e9b7fc4c13a87a3cced02` |
| SHA3-384 | `3bfbdee16102af6d269a6bb9798d3e9c810dd251acc9cb8420aecc9c38a024217108316e3ff9a7102aac7c4a1da9bb48` |
| IMPHASH | `2e4a0079ea7f26da5d79f05d8d4c3b45` |
| TLSH | `T166E40156F69942A9C429D53C8623690AA6B1BC450720ABFF13C1A33E1F77BE4C73DB50` |
| SSDEEP | `12288:JeVXMCeiYmbmXcmv/kmxMALs9h2cWsx4xE1jD8qJXa2sY8vbsrxf3i:JC74cy/ZMA8h2cWs+21jAOEvb6R3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_7cd4c78e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cd4c78e13625706f3012bb236b48afcab8f4ef1ec4e9b7fc4c13a87a3cced02"
    family = "unknown"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-10-31 18:49:22"
  condition:
    hash.sha256(0, filesize) == "7cd4c78e13625706f3012bb236b48afcab8f4ef1ec4e9b7fc4c13a87a3cced02"
}
```

### Sample 81: `4a0b3f9aaf8214e7`

| Field | Value |
|---|---|
| SHA-256 | `4a0b3f9aaf8214e7b3a4ea6784fb9960ac0aeca67ff1c35d418d0bcced56697c` |
| Family label | `unknown` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-10-31 18:48:01` |
| Reporter | `AmadeyHunter` |
| Tags | `DIVINEX, exe, stealer, Warden, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfc8d40259466774cb69b6d03f5e6894` |
| SHA-1 | `fc9d89fdbcc6a00ea36b61b858789600d56c8bbf` |
| SHA-256 | `4a0b3f9aaf8214e7b3a4ea6784fb9960ac0aeca67ff1c35d418d0bcced56697c` |
| SHA3-384 | `0a8eee11bf2b50e52f88e19212a7a373e1362270b15e31debadf2d4c0ab58a363d798870d399649b3cfb1ddb257fd7f3` |
| IMPHASH | `25573ef7ad9ff9996180c60a45082ca1` |
| TLSH | `T1A6F41251FA9685E9D422D23848230A55F6B53C510750EAFB43E8933F2FA7BE90B39B50` |
| SSDEEP | `12288:dTMq7UghNXeUIj+/6Lmpn4bdhejfXTrumg0SOOmtN1jwjtAbbwDAoaX5E5:dgq7UeK+iLOn4bdhejfXTamuORtN1jwR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_4a0b3f9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a0b3f9aaf8214e7b3a4ea6784fb9960ac0aeca67ff1c35d418d0bcced56697c"
    family = "unknown"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-10-31 18:48:01"
  condition:
    hash.sha256(0, filesize) == "4a0b3f9aaf8214e7b3a4ea6784fb9960ac0aeca67ff1c35d418d0bcced56697c"
}
```

### Sample 82: `4ea4f6dd439a54cd`

| Field | Value |
|---|---|
| SHA-256 | `4ea4f6dd439a54cd36d8194c14c1673c6e935b1a493f27bf4df83a2b96ceedb6` |
| Family label | `Mirai` |
| File name | `mpsl32` |
| File type | `elf` |
| First seen | `2026-10-31 18:47:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e86320a470de050f38dcbe0940820e41` |
| SHA-1 | `f4a45be4f735b44bb6d6508ad76ffc5d4c6650cc` |
| SHA-256 | `4ea4f6dd439a54cd36d8194c14c1673c6e935b1a493f27bf4df83a2b96ceedb6` |
| SHA3-384 | `b13fd1e96871505c180e03f1d1205373685998706cb02194c923ab99413c48345bb59ba074b904a27ac3ca7ab09d7b90` |
| TLSH | `T11273FA03FFA15F6BC81FDD7246F95912384C5CAE0BA1263A627CDCAC7A6618309D3D54` |
| SSDEEP | `1536:871ACBv2ZTMBFrfjKBTyEifEpZYDIsuO/nKI2SsB:SVXj2+fEpAvYSs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_4ea4f6dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ea4f6dd439a54cd36d8194c14c1673c6e935b1a493f27bf4df83a2b96ceedb6"
    family = "Mirai"
    file_name = "mpsl32"
    file_type = "elf"
    first_seen = "2026-10-31 18:47:35"
  condition:
    hash.sha256(0, filesize) == "4ea4f6dd439a54cd36d8194c14c1673c6e935b1a493f27bf4df83a2b96ceedb6"
}
```

### Sample 83: `edbb2619827bab21`

| Field | Value |
|---|---|
| SHA-256 | `edbb2619827bab21ed33fdd1c9ebe83f07c6db7ce92598eca7fb0aa2cd85a639` |
| Family label | `unknown` |
| File name | `alpme-1.0.25.vsix` |
| File type | `zip` |
| First seen | `2026-10-31 18:47:11` |
| Reporter | `mindhas403` |
| Tags | `Alpme, Geaix, infostealer, VSCode, vsix, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe98d8d85e2a019466aecc126d1aa052` |
| SHA-1 | `572f46f0ecd0e42d1cbc8fcd79b15dceba05e938` |
| SHA-256 | `edbb2619827bab21ed33fdd1c9ebe83f07c6db7ce92598eca7fb0aa2cd85a639` |
| SHA3-384 | `5b610592327cddf93f74956cc96914d6a278dcc770efcc5093fd1fd75800cc82d1847e57b1ca10f7ffada41f07c131ec` |
| TLSH | `T15157336A14FD004BCA7AFCB4E8E11B63CF2AA7DFEC42F89B20E8550965F27918755530` |
| SSDEEP | `786432:Klw3x1RIO+54eMdfWpXMLd2kJnj2k4lmXAOm:CwB1GO+54eMhjrPvm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_edbb2619
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edbb2619827bab21ed33fdd1c9ebe83f07c6db7ce92598eca7fb0aa2cd85a639"
    family = "unknown"
    file_name = "alpme-1.0.25.vsix"
    file_type = "zip"
    first_seen = "2026-10-31 18:47:11"
  condition:
    hash.sha256(0, filesize) == "edbb2619827bab21ed33fdd1c9ebe83f07c6db7ce92598eca7fb0aa2cd85a639"
}
```

### Sample 84: `05fafc00e36ebaec`

| Field | Value |
|---|---|
| SHA-256 | `05fafc00e36ebaec146e64c9ad7bb3bc7a733c2dd99fff954e8ef1736b1e04a3` |
| Family label | `unknown` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-31 18:40:13` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfb032a705e47794d6f766aaa881537d` |
| SHA-1 | `7cd81fa4aeb7d03b81a2aaaa265d0a6028072f04` |
| SHA-256 | `05fafc00e36ebaec146e64c9ad7bb3bc7a733c2dd99fff954e8ef1736b1e04a3` |
| SHA3-384 | `e4e95e4c3f8b4b102c252ae1b503c7d802e1a27d412f7067857e649fa219a3fa1a2f078e45fa58e35efc00e0bf667da4` |
| TLSH | `T185667C45BC2C7462D9CAB5B42F7622967A38BC488F81C7275614FB3CBAF27648F13161` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:RltQDhv/uj2/GnWOEK0tzdfcWOHHjipwtL4uI89O0MR4uj+5Et:RltQdv/uHnEtzyLTMpRrUEt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_05fafc00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05fafc00e36ebaec146e64c9ad7bb3bc7a733c2dd99fff954e8ef1736b1e04a3"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-31 18:40:13"
  condition:
    hash.sha256(0, filesize) == "05fafc00e36ebaec146e64c9ad7bb3bc7a733c2dd99fff954e8ef1736b1e04a3"
}
```

### Sample 85: `fa647a4d12cc887b`

| Field | Value |
|---|---|
| SHA-256 | `fa647a4d12cc887bd96cb2eb126f161cbcf47e84312094bb0dcc2429e7c8e296` |
| Family label | `unknown` |
| File name | `dvnx_kit2_lold_inner.exe` |
| File type | `exe` |
| First seen | `2026-10-31 18:35:18` |
| Reporter | `Daydream` |
| Tags | `DvnX, exe, loader, Lold, unpacked` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cd789e114e93b06e5162f8d7b462fe3` |
| SHA-1 | `bfbee31e792d296f2ea8b10443588f4b617422ad` |
| SHA-256 | `fa647a4d12cc887bd96cb2eb126f161cbcf47e84312094bb0dcc2429e7c8e296` |
| SHA3-384 | `5a7a81bd30947d415e318e8a656f973bb536d470ce34c2865fa1fc28570e25eda323afcc70b60b253b4ef0042ddfa9da` |
| IMPHASH | `7be476d096ff2d43b2380de66c82171e` |
| TLSH | `T14D944B1692E901BCF0BBA3389D575902E77E780A03B1DADF07D095772E666D09E3EB10` |
| SSDEEP | `12288:PzbANGIcymiSuf17H2FSTxEEPrJQ7os7kC:LfjyH2FQPrYz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_fa647a4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa647a4d12cc887bd96cb2eb126f161cbcf47e84312094bb0dcc2429e7c8e296"
    family = "unknown"
    file_name = "dvnx_kit2_lold_inner.exe"
    file_type = "exe"
    first_seen = "2026-10-31 18:35:18"
  condition:
    hash.sha256(0, filesize) == "fa647a4d12cc887bd96cb2eb126f161cbcf47e84312094bb0dcc2429e7c8e296"
}
```

### Sample 86: `578cc6d26bf7c553`

| Field | Value |
|---|---|
| SHA-256 | `578cc6d26bf7c5536d2c0ea0df5a788155e15d09e49054303915b535f4012791` |
| Family label | `unknown` |
| File name | `dvnx_kit2_inner_payload.dll` |
| File type | `exe` |
| First seen | `2026-10-31 18:35:10` |
| Reporter | `Daydream` |
| Tags | `Donut, DvnX, exe, loader, Lold, unpacked` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33fae333c2500a8958ccd7620f0c8eca` |
| SHA-1 | `3bb2cc4f7bc18130eebdd36443ecec78f3252cf0` |
| SHA-256 | `578cc6d26bf7c5536d2c0ea0df5a788155e15d09e49054303915b535f4012791` |
| SHA3-384 | `5eda4ca4a787821dd8f0f9bbcacfb8720d70a12672b4177840bafe21d0f6197687ced6fa8d9d76293278f7fcba000a09` |
| IMPHASH | `1148b81c44d42f8f4ec360100f5088c4` |
| TLSH | `T1FB85C0DE769412ACD5726138D80A4511F6BA7C0A4FB2CEEF1FCE865A39158C0DF39B21` |
| SSDEEP | `24576:dfjyH2FQPrYzIy6mQPOUmQeLvB4Voc4scMXU3FLbA7YkrdGj8hE86wInH:JGH2FQMQ9LeL54es8bAcydi8hE86F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_578cc6d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "578cc6d26bf7c5536d2c0ea0df5a788155e15d09e49054303915b535f4012791"
    family = "unknown"
    file_name = "dvnx_kit2_inner_payload.dll"
    file_type = "exe"
    first_seen = "2026-10-31 18:35:10"
  condition:
    hash.sha256(0, filesize) == "578cc6d26bf7c5536d2c0ea0df5a788155e15d09e49054303915b535f4012791"
}
```

### Sample 87: `1370f67acce699e1`

| Field | Value |
|---|---|
| SHA-256 | `1370f67acce699e1ac078821d846f70703934ca5c847c17fee444f31d0953483` |
| Family label | `AokigaharaStealer` |
| File name | `novaforge_static_unpacked.disk.exe` |
| File type | `exe` |
| First seen | `2026-10-31 18:34:57` |
| Reporter | `Daydream` |
| Tags | `aokigahara, AokigaharaStealer, exe, NovaForge, stealer, unpacked` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16b3ce9802f5602e9f54ca4e5776aa33` |
| SHA-1 | `4f2e6269dd16466ad781ad415919448ae19ea607` |
| SHA-256 | `1370f67acce699e1ac078821d846f70703934ca5c847c17fee444f31d0953483` |
| SHA3-384 | `69a92f182b08083b92229259d3b29d6c98d1e8ae211f231b3a6297fdb8331d03b8118d18852fdca7c87f77863354dce1` |
| IMPHASH | `98683c7201eb519500562ed22ebf8969` |
| TLSH | `T13D144B03D68149FDD826C5B4CEC7D23BDAB2BC480575B6EB6FA0CE22AD51B50B93C509` |
| SSDEEP | `3072:mHXYhQ1r7MMVpBjCr9zUCMgYA3s1qu9WNT0zP7ns8G61KcKIpXvcjtf/:m3Y21r7MMVpBMiZA36q0Wt0LG61KckjZ` |

#### Technical Assessment

- The sample is tracked as `AokigaharaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AokigaharaStealer_087_1370f67a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1370f67acce699e1ac078821d846f70703934ca5c847c17fee444f31d0953483"
    family = "AokigaharaStealer"
    file_name = "novaforge_static_unpacked.disk.exe"
    file_type = "exe"
    first_seen = "2026-10-31 18:34:57"
  condition:
    hash.sha256(0, filesize) == "1370f67acce699e1ac078821d846f70703934ca5c847c17fee444f31d0953483"
}
```

### Sample 88: `4bcb5301211ab257`

| Field | Value |
|---|---|
| SHA-256 | `4bcb5301211ab257543812405ca80cbecab8938a8a5a2fd0c7d65d75db9bc1a9` |
| Family label | `unknown` |
| File name | `4bcb5301211ab257543812405ca80cbecab8938a8a5a2fd0c7d65d75db9bc1a9` |
| File type | `elf` |
| First seen | `2026-10-31 18:31:13` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91fb725f5647b6583a0c6aa9e4d58704` |
| SHA-1 | `6f134cada7131e3158c749934b1076abb0979354` |
| SHA-256 | `4bcb5301211ab257543812405ca80cbecab8938a8a5a2fd0c7d65d75db9bc1a9` |
| SHA3-384 | `7ca392379a02adb5ea886ca77af110ee2f74009d11e22b929fcbc1b1e24cc3c1c8b4d0c0a298878be96b1ff63e2ee1fb` |
| TLSH | `T1AAA5AE1BB59250FDC1D6C070839B9633AA32B49952347E7F62C4AF312E26F20675EF61` |
| SSDEEP | `49152:MOpFRF8oFPvnl50p+0eVlvviccJ1TbXLP9TIy2o16k:FprnVnq+Zvqz1vL9TWo16k` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_4bcb5301
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bcb5301211ab257543812405ca80cbecab8938a8a5a2fd0c7d65d75db9bc1a9"
    family = "unknown"
    file_name = "4bcb5301211ab257543812405ca80cbecab8938a8a5a2fd0c7d65d75db9bc1a9"
    file_type = "elf"
    first_seen = "2026-10-31 18:31:13"
  condition:
    hash.sha256(0, filesize) == "4bcb5301211ab257543812405ca80cbecab8938a8a5a2fd0c7d65d75db9bc1a9"
}
```

### Sample 89: `21498faad7283839`

| Field | Value |
|---|---|
| SHA-256 | `21498faad7283839d0b055c618693eb2affe910b6e8d030592d92a94cd266144` |
| Family label | `unknown` |
| File name | `IEProc.exe` |
| File type | `exe` |
| First seen | `2026-10-31 18:19:15` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87aa5e20909f7eab688a533cf26b604f` |
| SHA-1 | `4894bd80b86cad291ebe764768ef0607b4a4bf32` |
| SHA-256 | `21498faad7283839d0b055c618693eb2affe910b6e8d030592d92a94cd266144` |
| SHA3-384 | `7907276ad74ad2e5c516f83680e7ed9638b43a0f727911839a8cf169b17c7eaf5bd32f467d430ef0b7e921d616781452` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1ED442AF843948AB6D7CD47B8D0838AE683FDD75A2547EFD9AC6040E65A0F393A11214F` |
| SSDEEP | `6144:atRPLdhXmFVUSlMg3Z2J0fXX3VGpqtI4ES7:atBXUVblPPrL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_21498faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21498faad7283839d0b055c618693eb2affe910b6e8d030592d92a94cd266144"
    family = "unknown"
    file_name = "IEProc.exe"
    file_type = "exe"
    first_seen = "2026-10-31 18:19:15"
  condition:
    hash.sha256(0, filesize) == "21498faad7283839d0b055c618693eb2affe910b6e8d030592d92a94cd266144"
}
```

### Sample 90: `d4b9c2118987d0b7`

| Field | Value |
|---|---|
| SHA-256 | `d4b9c2118987d0b7ef0df12b27e8f4bab0152c8d50bf0bed7e937c215a42ccd7` |
| Family label | `RustyStealer` |
| File name | `Xenonsable.exe` |
| File type | `exe` |
| First seen | `2026-10-31 18:14:24` |
| Reporter | `wok` |
| Tags | `exe, salatstealer, stealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd7ee73478bf1ad2586ba2ccbbef2be4` |
| SHA-1 | `484fcdccc5ff1f7afa87dbf9eb5fa9429046dbdd` |
| SHA-256 | `d4b9c2118987d0b7ef0df12b27e8f4bab0152c8d50bf0bed7e937c215a42ccd7` |
| SHA3-384 | `6d6f106c3dc5388af32e6955a4830815760070ee9bff74d9e376c1502a9bfbf47f6357a9ac224c34a87554ec7550f605` |
| IMPHASH | `1c8506581759e6cc7d372a1695f4abcd` |
| TLSH | `T10F748D19F7A914FAE667C17CC9524902EA737C060761ABDF13A04AA72F236E05E3F711` |
| SSDEEP | `6144:f4huQdi68Vvn2jpR9S2VxvBePS8zjdtAQnouBX:CS4LHxJevtt7ou` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_090_d4b9c211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4b9c2118987d0b7ef0df12b27e8f4bab0152c8d50bf0bed7e937c215a42ccd7"
    family = "RustyStealer"
    file_name = "Xenonsable.exe"
    file_type = "exe"
    first_seen = "2026-10-31 18:14:24"
  condition:
    hash.sha256(0, filesize) == "d4b9c2118987d0b7ef0df12b27e8f4bab0152c8d50bf0bed7e937c215a42ccd7"
}
```

### Sample 91: `ccfd73a74d8830d8`

| Field | Value |
|---|---|
| SHA-256 | `ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91` |
| Family label | `Mirai` |
| File name | `ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91` |
| File type | `elf` |
| First seen | `2026-10-31 18:08:59` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, Mirai, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a24f40c32e8f457f60564da77289cb4` |
| SHA-1 | `e1902093fce89f2a699164adecf87e78abbe9e1a` |
| SHA-256 | `ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91` |
| SHA3-384 | `e71d929b7787a6059a96846612cbab15e739377957b91fb3e06fee6c22f0cee920f69b61800d6eb5819277d87926a182` |
| TLSH | `T107F49D2BB2B2B67DC017C0304BDBCAB14132F4756A322D7B26C4DA343E96DE5175AB25` |
| SSDEEP | `12288:DbPWXlNgpICnsdwH/of4ZGmy9jfjDxayzsXnHX0mJcurn2B:nglNgpjuay9jfjCU4cur` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_ccfd73a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91"
    family = "Mirai"
    file_name = "ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91"
    file_type = "elf"
    first_seen = "2026-10-31 18:08:59"
  condition:
    hash.sha256(0, filesize) == "ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91"
}
```

### Sample 92: `03575d5232dd841c`

| Field | Value |
|---|---|
| SHA-256 | `03575d5232dd841c5c94238c6666ea30272e0826c466dba22a4c2445188dba58` |
| Family label | `ValleyRAT` |
| File name | `14e70f4c893a3534c55a0f9ed251a40b.exe` |
| File type | `exe` |
| First seen | `2026-10-31 17:35:14` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14e70f4c893a3534c55a0f9ed251a40b` |
| SHA-1 | `f60124be014895927242df9240296382f80b2ea1` |
| SHA-256 | `03575d5232dd841c5c94238c6666ea30272e0826c466dba22a4c2445188dba58` |
| SHA3-384 | `e0ff8520fae76f4f568f8ad6ebcfd183ce4aea2e74b8a4971f192663098db33aab2e7da0c754a9e3cf83adbf4e8cc310` |
| IMPHASH | `b1c5b1beabd90d9fdabd1df0779ea832` |
| TLSH | `T1FC362219A950C6E4F7D6B7B4864565F0C77B3C262A36E6DF02B031261F776C3CA36222` |
| SSDEEP | `98304:I3GUKTKK4KKDyK5FZ1EEEEmEEE1EEEEEEEEEEElKK1KKK1KKKCeAOpk/wRUb70/K:I3GxpSwmJ3Zj5nTBVJ9nTXc72N` |
| ICON-DHASH | `c488b8f0e2b692cc` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_092_03575d52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03575d5232dd841c5c94238c6666ea30272e0826c466dba22a4c2445188dba58"
    family = "ValleyRAT"
    file_name = "14e70f4c893a3534c55a0f9ed251a40b.exe"
    file_type = "exe"
    first_seen = "2026-10-31 17:35:14"
  condition:
    hash.sha256(0, filesize) == "03575d5232dd841c5c94238c6666ea30272e0826c466dba22a4c2445188dba58"
}
```

### Sample 93: `ea3b82d9a70295c7`

| Field | Value |
|---|---|
| SHA-256 | `ea3b82d9a70295c74edd17b90c549a84ca05a31f07c9a398b0c945493fb0dc5c` |
| Family label | `unknown` |
| File name | `gitlосitу64-v.3.122.exe` |
| File type | `exe` |
| First seen | `2026-10-31 17:32:59` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed, Stealer, Vidar, VidarStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52ecfe174f1c113c417a435eb2b7fd57` |
| SHA-1 | `8ec8afbb1e96172f95e35cc595f0a56dba1d1546` |
| SHA-256 | `ea3b82d9a70295c74edd17b90c549a84ca05a31f07c9a398b0c945493fb0dc5c` |
| SHA3-384 | `47b6a36ea5db05c4382ffce7328f244bd183fa38d03638b3103683cbf76708232cf9773a93eb449338b5af32da23c11d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T182964B036BA940ADD49AEE38C57A4652B714BC4C873037EB7FA06BB01F117D0ABB9751` |
| SSDEEP | `49152:+d0QhxSSbaorOCcqMZUjK4AOIeopkZZ1iZ/f16XVbf+DJkrXFMRF5gNTOKAUSHYJ:+D3wOBAjQvGCIMg0ksINh3zMD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_ea3b82d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea3b82d9a70295c74edd17b90c549a84ca05a31f07c9a398b0c945493fb0dc5c"
    family = "unknown"
    file_name = "gitlосitу64-v.3.122.exe"
    file_type = "exe"
    first_seen = "2026-10-31 17:32:59"
  condition:
    hash.sha256(0, filesize) == "ea3b82d9a70295c74edd17b90c549a84ca05a31f07c9a398b0c945493fb0dc5c"
}
```

### Sample 94: `0d359ccbc02f125f`

| Field | Value |
|---|---|
| SHA-256 | `0d359ccbc02f125f943b726794b0b9b73090698f5fb8170682fbfdb1f121091a` |
| Family label | `unknown` |
| File name | `fuck_niggers_39.hta` |
| File type | `hta` |
| First seen | `2026-10-31 17:30:10` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1961669551dde101ccdcc2d8f5571689` |
| SHA-1 | `73102bc1ab68501e632844d5c61308b6bf4bd2a6` |
| SHA-256 | `0d359ccbc02f125f943b726794b0b9b73090698f5fb8170682fbfdb1f121091a` |
| SHA3-384 | `48627f4c9a1a5d4c929156bf6d773de77ba3845dfe69437070331eebabcb1200e81c3f134f679bf74792bd382cafb16b` |
| TLSH | `T19232195CAED161B0EA1707DEB3AF24690228A0C7240DD484F54CEDE8BF46BDC4A56B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzNbqFtC9S3QpRUM:sXX+/DV7k/3IFtoRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_0d359ccb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d359ccbc02f125f943b726794b0b9b73090698f5fb8170682fbfdb1f121091a"
    family = "unknown"
    file_name = "fuck_niggers_39.hta"
    file_type = "hta"
    first_seen = "2026-10-31 17:30:10"
  condition:
    hash.sha256(0, filesize) == "0d359ccbc02f125f943b726794b0b9b73090698f5fb8170682fbfdb1f121091a"
}
```

### Sample 95: `87adc00cc7aa18d8`

| Field | Value |
|---|---|
| SHA-256 | `87adc00cc7aa18d84c0b047bc186b34e48715b89f8d2f40278f7eb3a01d05223` |
| Family label | `WannaCry` |
| File name | `3d18ae12b9d8edc29ee15d0cf72d854e` |
| File type | `dll` |
| First seen | `2026-10-31 17:06:58` |
| Reporter | `malwareontap` |
| Tags | `dionaea, dll, honeypot, pe, WannaCry, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d18ae12b9d8edc29ee15d0cf72d854e` |
| SHA-1 | `ec4fb6e6ccfc3b1c12557f99e870b07fec6c20eb` |
| SHA-256 | `87adc00cc7aa18d84c0b047bc186b34e48715b89f8d2f40278f7eb3a01d05223` |
| SHA3-384 | `e5ac532d46c1a64dd6ec1c5b249da00bbdbb470881eead8f86a1678f7bf086825fbf853dbc3b4a21d75277bdd948931b` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1D2363368723CD5FCD10519B404A7C927A7B33C6656FE6A0F8F5089660D13B6AFBE0B42` |
| SSDEEP | `49152:SnAQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnvxJM0H9PA:+DqPoBhz1aRxcSUDk36SAEdhvxWa9P` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_095_87adc00c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87adc00cc7aa18d84c0b047bc186b34e48715b89f8d2f40278f7eb3a01d05223"
    family = "WannaCry"
    file_name = "3d18ae12b9d8edc29ee15d0cf72d854e"
    file_type = "dll"
    first_seen = "2026-10-31 17:06:58"
  condition:
    hash.sha256(0, filesize) == "87adc00cc7aa18d84c0b047bc186b34e48715b89f8d2f40278f7eb3a01d05223"
}
```

### Sample 96: `8cc8bf1f64417890`

| Field | Value |
|---|---|
| SHA-256 | `8cc8bf1f64417890f7d4ebd7bce8ef55fbe724a70d8de9355bf027c92380c8eb` |
| Family label | `unknown` |
| File name | `fuck_niggers_21.hta` |
| File type | `hta` |
| First seen | `2026-10-31 16:55:11` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef8a90d417dd70c0a844c3fca7531f30` |
| SHA-1 | `26893321179940a4c88b4bc2152dc562bb7f0abe` |
| SHA-256 | `8cc8bf1f64417890f7d4ebd7bce8ef55fbe724a70d8de9355bf027c92380c8eb` |
| SHA3-384 | `6b0632f0721c2194dfe384d5bfb81f304323f0a02d1951c499526114c905f3d8091abbd3c9d7ce1cc84f011ecc529415` |
| TLSH | `T110422A5CAEE1A1B0EB0707DEB3AF24690268A0C72409C484F54CDEE87F46BDD4A57B57` |
| SSDEEP | `192:sWHNsGeTHQpD+da6+888+UV7tDoj/pxzAbqFtCQSpRUzHM:sWX+/DV7k/3LFtkRUzHM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_8cc8bf1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cc8bf1f64417890f7d4ebd7bce8ef55fbe724a70d8de9355bf027c92380c8eb"
    family = "unknown"
    file_name = "fuck_niggers_21.hta"
    file_type = "hta"
    first_seen = "2026-10-31 16:55:11"
  condition:
    hash.sha256(0, filesize) == "8cc8bf1f64417890f7d4ebd7bce8ef55fbe724a70d8de9355bf027c92380c8eb"
}
```

### Sample 97: `82ea0074e950a589`

| Field | Value |
|---|---|
| SHA-256 | `82ea0074e950a589422046178545acaa950b5f0b61760630af27546741a02dfc` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-10-31 16:43:45` |
| Reporter | `Jerry1113` |
| Tags | `cowrie, elf, honeypot, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d50ab61bd25b9ef197a0b3fee13d7300` |
| SHA-1 | `05596f177a99371fdffb55f6626b8f26c8e0555a` |
| SHA-256 | `82ea0074e950a589422046178545acaa950b5f0b61760630af27546741a02dfc` |
| SHA3-384 | `a294edc4292c6ec9c98d62fdf2b56f3c5d86908d046199d965e14a0f42dc41071427d3212c5b5eabf04c30ff95594682` |
| TLSH | `T1C9143B46AA408B13C4D627B9FADF424533339B64D3E773069918AFB43F8679E4F26502` |
| TELFHASH | `t1ce311671562412265a91ed68dde997a3152fc7125340ff37cf12c4cc680e05ee636c4f` |
| SSDEEP | `6144:aKXesyHt88UT8Vc1NToaV9KtivzTJCLIT5Feuc0IM/R3G9:aKXehhUT71NToaV9KtivzT8s9rc8/pW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_82ea0074
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82ea0074e950a589422046178545acaa950b5f0b61760630af27546741a02dfc"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-10-31 16:43:45"
  condition:
    hash.sha256(0, filesize) == "82ea0074e950a589422046178545acaa950b5f0b61760630af27546741a02dfc"
}
```

### Sample 98: `c5418c52bdf33f70`

| Field | Value |
|---|---|
| SHA-256 | `c5418c52bdf33f70aff9bcf014d3f10c4661a87ff2dbc8747feaa10415fc5e52` |
| Family label | `Gh0stRAT` |
| File name | `BANDIZIPSETUP.exe` |
| File type | `exe` |
| First seen | `2026-10-31 16:40:33` |
| Reporter | `CNGaoLing` |
| Tags | `exe, Gh0stRAT, signed, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d52e600aa64cc141628c3e9ea3b871e6` |
| SHA-1 | `e647a44181857ab6eb2c1611ec1aaf3b9951039b` |
| SHA-256 | `c5418c52bdf33f70aff9bcf014d3f10c4661a87ff2dbc8747feaa10415fc5e52` |
| SHA3-384 | `59f5381451d686e50b90647a8c3034bf3ed118676aca1b7d600109532773a4641cedab8f4e06549a570d8f8434153129` |
| IMPHASH | `6d5e13c0269946a5a10390c178d8e9a5` |
| TLSH | `T158871231369EC43BE16905B15A2CAEAA913C6E360FB154C7B3EC7D5A17754C20237E2B` |
| SSDEEP | `786432:tJqHlyDSs9Jf3ASYa4hyI30fC/hl8K9HHHVq/1yfgYZ+8ddqbr4:tJqHlyDSsL/BqyI30ADl9HHs/1SdA` |
| ICON-DHASH | `68f8d9d3d9d83c80` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_098_c5418c52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5418c52bdf33f70aff9bcf014d3f10c4661a87ff2dbc8747feaa10415fc5e52"
    family = "Gh0stRAT"
    file_name = "BANDIZIPSETUP.exe"
    file_type = "exe"
    first_seen = "2026-10-31 16:40:33"
  condition:
    hash.sha256(0, filesize) == "c5418c52bdf33f70aff9bcf014d3f10c4661a87ff2dbc8747feaa10415fc5e52"
}
```

### Sample 99: `1b01265fc95eecf5`

| Field | Value |
|---|---|
| SHA-256 | `1b01265fc95eecf548211be11cb8708d63f774d92ca98be3d2edba6e6e1a7fc5` |
| Family label | `Mirai` |
| File name | `bot-linux-arm64` |
| File type | `elf` |
| First seen | `2026-10-31 16:35:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce56434eb51ce020101d676ce42f804b` |
| SHA-1 | `c5c4789e7b7be8f3fd3ad4657db2d491461327dc` |
| SHA-256 | `1b01265fc95eecf548211be11cb8708d63f774d92ca98be3d2edba6e6e1a7fc5` |
| SHA3-384 | `c5350b1b4902c4fdadb1d4067b369e1cce87549ad0e7adb86df1987482e1010511eaee273f4e82d7b21129d8dab5b810` |
| TLSH | `T13D969D56BC1D6862C6CE79711F7712847339AC448B82D3266B14BB3DF9F276C8F22261` |
| TELFHASH | `t1213454a3cc26bf5b4fc403229cf6c5c55357e04608927b996fb08336d4eb48da5ba35a` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:Cmx/azyZAf/rvctftePH3s0KE6aZDijAoPtK2FbOX0zM9/:Cm8uZMo54Ps0XpoVK2FbOXsMB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_1b01265f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b01265fc95eecf548211be11cb8708d63f774d92ca98be3d2edba6e6e1a7fc5"
    family = "Mirai"
    file_name = "bot-linux-arm64"
    file_type = "elf"
    first_seen = "2026-10-31 16:35:11"
  condition:
    hash.sha256(0, filesize) == "1b01265fc95eecf548211be11cb8708d63f774d92ca98be3d2edba6e6e1a7fc5"
}
```

### Sample 100: `a2fa3be9c8bb4108`

| Field | Value |
|---|---|
| SHA-256 | `a2fa3be9c8bb41089d27885e686ea74f7250a54d8a3dd6613e0bbad94a92bd2e` |
| Family label | `unknown` |
| File name | `a2fa3be9c8bb41089d27885e686ea74f7250a54d8a3dd6613e0bbad94a92bd2e` |
| File type | `elf` |
| First seen | `2026-10-31 16:34:42` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76c25549df53a4af2c47175d24b6855c` |
| SHA-1 | `7b6c9ce8cc576c02e8a8218036f9886e5c5caa21` |
| SHA-256 | `a2fa3be9c8bb41089d27885e686ea74f7250a54d8a3dd6613e0bbad94a92bd2e` |
| SHA3-384 | `23037c859e3fe1a25e3447d64cede48ba9454e40a4395cd4a6185ea01097593d5c8682f2acf3e345b339de456aa96364` |
| TLSH | `T13FF6AD77914338E9E5A98CB4D11025426DAC388B5738A3C7BAC471F667BA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQg:cqYUQuVDt0TZED` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_a2fa3be9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2fa3be9c8bb41089d27885e686ea74f7250a54d8a3dd6613e0bbad94a92bd2e"
    family = "unknown"
    file_name = "a2fa3be9c8bb41089d27885e686ea74f7250a54d8a3dd6613e0bbad94a92bd2e"
    file_type = "elf"
    first_seen = "2026-10-31 16:34:42"
  condition:
    hash.sha256(0, filesize) == "a2fa3be9c8bb41089d27885e686ea74f7250a54d8a3dd6613e0bbad94a92bd2e"
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
 * Generated: 2026-11-01T06:22:24.591918+00:00
 */

rule MalwareBazaar_unknown_001_981ff25c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "981ff25c886308d5350b4446184f14406be6cc01186bb19ebf0de8cf843e392f"
    family = "unknown"
    file_name = "macho_981ff25c8863.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:57:47"
  condition:
    hash.sha256(0, filesize) == "981ff25c886308d5350b4446184f14406be6cc01186bb19ebf0de8cf843e392f"
}

rule MalwareBazaar_unknown_002_8aa9c734
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8aa9c73475a64d9d5ef62124ff91f6de00eac4ccf9258152bd795a808a17eecb"
    family = "unknown"
    file_name = "macho_8aa9c73475a6.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:49:34"
  condition:
    hash.sha256(0, filesize) == "8aa9c73475a64d9d5ef62124ff91f6de00eac4ccf9258152bd795a808a17eecb"
}

rule MalwareBazaar_unknown_003_ff19f83f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff19f83f177ee4eac22c9fa447e932e56f5a91032c130a8bd30b69e0f7eed3d5"
    family = "unknown"
    file_name = "macho_ff19f83f177e.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:44:20"
  condition:
    hash.sha256(0, filesize) == "ff19f83f177ee4eac22c9fa447e932e56f5a91032c130a8bd30b69e0f7eed3d5"
}

rule MalwareBazaar_unknown_004_42949634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42949634a09db058449c1c51a80ebfbad074ea1a6b6f14a583604a138a9f561b"
    family = "unknown"
    file_name = "macho_42949634a09d.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:32:48"
  condition:
    hash.sha256(0, filesize) == "42949634a09db058449c1c51a80ebfbad074ea1a6b6f14a583604a138a9f561b"
}

rule MalwareBazaar_unknown_005_1ec92977
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ec9297709a225f912fc7145f43654bc1a6b61e56c9684bf22c6aaf0fad98289"
    family = "unknown"
    file_name = "macho_1ec9297709a2.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:31:11"
  condition:
    hash.sha256(0, filesize) == "1ec9297709a225f912fc7145f43654bc1a6b61e56c9684bf22c6aaf0fad98289"
}

rule MalwareBazaar_unknown_006_95b3a52b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95b3a52bad5da0468d6af8a8c56e0ca7e307c2c0151f2531903e27c49458d308"
    family = "unknown"
    file_name = "macho_95b3a52bad5d.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:29:33"
  condition:
    hash.sha256(0, filesize) == "95b3a52bad5da0468d6af8a8c56e0ca7e307c2c0151f2531903e27c49458d308"
}

rule MalwareBazaar_Mirai_007_faf25e8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faf25e8e778647deb0d0b30927eeaae9bc2d860cc317bb2d76ab48e84e82a001"
    family = "Mirai"
    file_name = "nyx_bot_linux_amd64"
    file_type = "elf"
    first_seen = "2026-11-01 05:29:20"
  condition:
    hash.sha256(0, filesize) == "faf25e8e778647deb0d0b30927eeaae9bc2d860cc317bb2d76ab48e84e82a001"
}

rule MalwareBazaar_unknown_008_6ee52429
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee52429a22ee09c723794eaa590cd4f08a4109d5e3bd9bb7e71f94de3e3851a"
    family = "unknown"
    file_name = "macho_6ee52429a22e.bin"
    file_type = "macho"
    first_seen = "2026-11-01 05:28:56"
  condition:
    hash.sha256(0, filesize) == "6ee52429a22ee09c723794eaa590cd4f08a4109d5e3bd9bb7e71f94de3e3851a"
}

rule MalwareBazaar_Mirai_009_f9b3091f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9b3091f6fd32546606eb05dec4cbccf331df02c15da8d2f5bc760ee06197a4f"
    family = "Mirai"
    file_name = "f9b3091f6fd32546606eb05dec4cbccf331df02c15da8d2f5bc760ee06197a4f.elf"
    file_type = "elf"
    first_seen = "2026-11-01 05:20:09"
  condition:
    hash.sha256(0, filesize) == "f9b3091f6fd32546606eb05dec4cbccf331df02c15da8d2f5bc760ee06197a4f"
}

rule MalwareBazaar_Mirai_010_cca729f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cca729f2af3ca4622d1e23f2c149ae2ea7d50b52f4ed729cf3eba33b4fd605c1"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-01 04:37:53"
  condition:
    hash.sha256(0, filesize) == "cca729f2af3ca4622d1e23f2c149ae2ea7d50b52f4ed729cf3eba33b4fd605c1"
}

rule MalwareBazaar_unknown_011_cfa2bac4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfa2bac42af30c732cda9939159c3f41996cf074c2f7f3e3b21d38d944ff3e0e"
    family = "unknown"
    file_name = "cfa2bac42af30c732cda9939159c3f41996cf074c2f7f3e3b21d38d944ff3e0e.sh"
    file_type = "sh"
    first_seen = "2026-11-01 04:09:26"
  condition:
    hash.sha256(0, filesize) == "cfa2bac42af30c732cda9939159c3f41996cf074c2f7f3e3b21d38d944ff3e0e"
}

rule MalwareBazaar_unknown_012_ae278113
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae278113941181d7e1bcac838910e29667527f6388bfab8b543fcb46827df3b6"
    family = "unknown"
    file_name = "install.1.2.04.exe"
    file_type = "exe"
    first_seen = "2026-11-01 03:50:03"
  condition:
    hash.sha256(0, filesize) == "ae278113941181d7e1bcac838910e29667527f6388bfab8b543fcb46827df3b6"
}

rule MalwareBazaar_unknown_013_36f6f933
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36f6f9331b5efe7124f043b8a3b922a6c4df5cb3cf37cb14827baab47aa70c7c"
    family = "unknown"
    file_name = "install.1.2.03.exe"
    file_type = "exe"
    first_seen = "2026-11-01 03:49:12"
  condition:
    hash.sha256(0, filesize) == "36f6f9331b5efe7124f043b8a3b922a6c4df5cb3cf37cb14827baab47aa70c7c"
}

rule MalwareBazaar_Mirai_014_eaa1e4a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaa1e4a9281a77116892f2ca249ac07f123a96a148afe2dbf1a9d3080fc834d6"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-11-01 03:24:11"
  condition:
    hash.sha256(0, filesize) == "eaa1e4a9281a77116892f2ca249ac07f123a96a148afe2dbf1a9d3080fc834d6"
}

rule MalwareBazaar_unknown_015_c363b017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c363b0179cbd542865af005d2cc861525e5a5fdb2cd955eeb45741e99690be45"
    family = "unknown"
    file_name = "c363b0179cbd542865af005d2cc861525e5a5fdb2cd955eeb45741e99690be45"
    file_type = "sh"
    first_seen = "2026-11-01 03:08:47"
  condition:
    hash.sha256(0, filesize) == "c363b0179cbd542865af005d2cc861525e5a5fdb2cd955eeb45741e99690be45"
}

rule MalwareBazaar_Mirai_016_fcb12e0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcb12e0ae3f50e171a814269e3c8174c613204b40d64bfb855d93668517104ba"
    family = "Mirai"
    file_name = "fcb12e0ae3f50e17.bin"
    file_type = "elf"
    first_seen = "2026-11-01 02:23:57"
  condition:
    hash.sha256(0, filesize) == "fcb12e0ae3f50e171a814269e3c8174c613204b40d64bfb855d93668517104ba"
}

rule MalwareBazaar_NanoCore_017_95cca0c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95cca0c53fb872f2133364e7590d816a39983bf7aacab30768472cd45845ddfb"
    family = "NanoCore"
    file_name = "B923F381A98DEAFF472A4BD021172712.exe"
    file_type = "exe"
    first_seen = "2026-11-01 02:20:07"
  condition:
    hash.sha256(0, filesize) == "95cca0c53fb872f2133364e7590d816a39983bf7aacab30768472cd45845ddfb"
}

rule MalwareBazaar_unknown_018_b37413c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b37413c715212c655c328e99657f9a50bdcaf7366f74935fe232663a5d156698"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-01 02:15:17"
  condition:
    hash.sha256(0, filesize) == "b37413c715212c655c328e99657f9a50bdcaf7366f74935fe232663a5d156698"
}

rule MalwareBazaar_unknown_019_077cae04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "077cae04215aca2c742ceaf837fd8293671c9b0fa9b58de0e8bb106072796482"
    family = "unknown"
    file_name = "077cae04215aca2c742ceaf837fd8293671c9b0fa9b58de0e8bb106072796482.exe"
    file_type = "exe"
    first_seen = "2026-11-01 01:49:00"
  condition:
    hash.sha256(0, filesize) == "077cae04215aca2c742ceaf837fd8293671c9b0fa9b58de0e8bb106072796482"
}

rule MalwareBazaar_unknown_020_7ec8a376
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ec8a37604d9119055090f201a07f54619c29ccbdf14f65cf6198e529345ca07"
    family = "unknown"
    file_name = "slod.msi"
    file_type = "msi"
    first_seen = "2026-11-01 01:05:49"
  condition:
    hash.sha256(0, filesize) == "7ec8a37604d9119055090f201a07f54619c29ccbdf14f65cf6198e529345ca07"
}

rule MalwareBazaar_unknown_021_fd133e64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd133e64799ab52e50eb290d44e446c426a9f91096f8ac7b5293ce81b7bf58e2"
    family = "unknown"
    file_name = "cler.msi"
    file_type = "msi"
    first_seen = "2026-11-01 01:05:13"
  condition:
    hash.sha256(0, filesize) == "fd133e64799ab52e50eb290d44e446c426a9f91096f8ac7b5293ce81b7bf58e2"
}

rule MalwareBazaar_Mirai_022_c3925c81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3925c81ab10d0121609552738cdff4bf8b621c8392522435d46d0c9a9d39d89"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-11-01 00:49:13"
  condition:
    hash.sha256(0, filesize) == "c3925c81ab10d0121609552738cdff4bf8b621c8392522435d46d0c9a9d39d89"
}

rule MalwareBazaar_Mirai_023_c54c3592
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c54c3592e1c1bc94f81646ac0051fbac4109811b21a3831f91b3a77b0d8def11"
    family = "Mirai"
    file_name = "c54c3592e1c1bc94.bin"
    file_type = "elf"
    first_seen = "2026-11-01 00:25:54"
  condition:
    hash.sha256(0, filesize) == "c54c3592e1c1bc94f81646ac0051fbac4109811b21a3831f91b3a77b0d8def11"
}

rule MalwareBazaar_Mirai_024_a0432d0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0432d0a7ca04b53e130a54710338385de639fe9a9cc0b858bd1649d539630e5"
    family = "Mirai"
    file_name = "a0432d0a7ca04b53.bin"
    file_type = "elf"
    first_seen = "2026-11-01 00:25:47"
  condition:
    hash.sha256(0, filesize) == "a0432d0a7ca04b53e130a54710338385de639fe9a9cc0b858bd1649d539630e5"
}

rule MalwareBazaar_unknown_025_931195a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "931195a7237f8213f80a0a76c76a9663061793e5b74ece9975d489c0eb971e2b"
    family = "unknown"
    file_name = "931195a7237f8213.bin"
    file_type = "exe"
    first_seen = "2026-11-01 00:25:41"
  condition:
    hash.sha256(0, filesize) == "931195a7237f8213f80a0a76c76a9663061793e5b74ece9975d489c0eb971e2b"
}

rule MalwareBazaar_Mirai_026_586cddc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "586cddc7b67e1c2072b39cc6d0669b3031ab66c0075e91f8a81b8bd92b2e5c8e"
    family = "Mirai"
    file_name = "586cddc7b67e1c20.bin"
    file_type = "elf"
    first_seen = "2026-11-01 00:25:30"
  condition:
    hash.sha256(0, filesize) == "586cddc7b67e1c2072b39cc6d0669b3031ab66c0075e91f8a81b8bd92b2e5c8e"
}

rule MalwareBazaar_Mirai_027_d5156852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51568526eb146d673f4864629f21b40d70b35f5e25b88074a8bc63719cd67a8"
    family = "Mirai"
    file_name = "d51568526eb146d6.bin"
    file_type = "elf"
    first_seen = "2026-11-01 00:25:23"
  condition:
    hash.sha256(0, filesize) == "d51568526eb146d673f4864629f21b40d70b35f5e25b88074a8bc63719cd67a8"
}

rule MalwareBazaar_unknown_028_bc7615f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc7615f394446ebec2ee732636de22153f38756f63277359ca2f78eadb07f42a"
    family = "unknown"
    file_name = "FACEITInstaller_64.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:23:24"
  condition:
    hash.sha256(0, filesize) == "bc7615f394446ebec2ee732636de22153f38756f63277359ca2f78eadb07f42a"
}

rule MalwareBazaar_unknown_029_f860fc87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f860fc8792473baefb1cbeb5f6d59c0107ce1ee53c43742a124ee6316f08d9cb"
    family = "unknown"
    file_name = "payload_decrypted.zip"
    file_type = "zip"
    first_seen = "2026-11-01 00:23:04"
  condition:
    hash.sha256(0, filesize) == "f860fc8792473baefb1cbeb5f6d59c0107ce1ee53c43742a124ee6316f08d9cb"
}

rule MalwareBazaar_unknown_030_30e6f653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30e6f65380198bd4d49227d780f19a01d297aa8ed7ae643167e490f5e7b8fca5"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-01 00:12:19"
  condition:
    hash.sha256(0, filesize) == "30e6f65380198bd4d49227d780f19a01d297aa8ed7ae643167e490f5e7b8fca5"
}

rule MalwareBazaar_unknown_031_d9fead88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9fead88582068c1d9642a109ab73669f168e7f7a45554cda6069819baf0dde0"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:11:11"
  condition:
    hash.sha256(0, filesize) == "d9fead88582068c1d9642a109ab73669f168e7f7a45554cda6069819baf0dde0"
}

rule MalwareBazaar_ValleyRAT_032_b2925532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b292553214c1eb0e0aa485a4835f213547856bb3580171f2c2bcb97ab0a40b0e"
    family = "ValleyRAT"
    file_name = "A283C881A189A50B3C861A8BB37C5CB9.dll"
    file_type = "dll"
    first_seen = "2026-11-01 00:10:10"
  condition:
    hash.sha256(0, filesize) == "b292553214c1eb0e0aa485a4835f213547856bb3580171f2c2bcb97ab0a40b0e"
}

rule MalwareBazaar_unknown_033_19520eea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19520eea568e1e804292e3a60765dedea5462561d75b0ba49eaf7ef8ef13602b"
    family = "unknown"
    file_name = "Installer41805x64.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:09:54"
  condition:
    hash.sha256(0, filesize) == "19520eea568e1e804292e3a60765dedea5462561d75b0ba49eaf7ef8ef13602b"
}

rule MalwareBazaar_unknown_034_c51e37c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c51e37c1622bff8c874a6452c30f70f0aef59ca9f2c09cf98e8e7c406535e4f3"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-11-01 00:09:27"
  condition:
    hash.sha256(0, filesize) == "c51e37c1622bff8c874a6452c30f70f0aef59ca9f2c09cf98e8e7c406535e4f3"
}

rule MalwareBazaar_unknown_035_a6284a9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6284a9e3cd2414a72d5a183353fc76fd994510af1eb2921e8d2c9ccf84c9517"
    family = "unknown"
    file_name = "Installer_L_X64_x86_2024.zip"
    file_type = "zip"
    first_seen = "2026-11-01 00:08:19"
  condition:
    hash.sha256(0, filesize) == "a6284a9e3cd2414a72d5a183353fc76fd994510af1eb2921e8d2c9ccf84c9517"
}

rule MalwareBazaar_unknown_036_0b4e389e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b4e389ea5d262b3e6689847d53900a3c508572c7165e7d6b0fba384fd86a1ca"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:07:08"
  condition:
    hash.sha256(0, filesize) == "0b4e389ea5d262b3e6689847d53900a3c508572c7165e7d6b0fba384fd86a1ca"
}

rule MalwareBazaar_unknown_037_43db1c8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43db1c8b806fcecdd4b752e8d093ff9c16c7ed7ee6333ff76807f2fe6c4c3ed4"
    family = "unknown"
    file_name = "Setup_latest.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:05:57"
  condition:
    hash.sha256(0, filesize) == "43db1c8b806fcecdd4b752e8d093ff9c16c7ed7ee6333ff76807f2fe6c4c3ed4"
}

rule MalwareBazaar_unknown_038_0d071eae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d071eaede91a8c31dfe5fa25859e944e62e967d6a1a1316b9845778b5fe38af"
    family = "unknown"
    file_name = "application_patched.exe"
    file_type = "exe"
    first_seen = "2026-11-01 00:04:15"
  condition:
    hash.sha256(0, filesize) == "0d071eaede91a8c31dfe5fa25859e944e62e967d6a1a1316b9845778b5fe38af"
}

rule MalwareBazaar_unknown_039_14dc82bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14dc82bc5ee7c606e862a702666cc1b314179545f3a56fa68fc76b29d5900576"
    family = "unknown"
    file_name = "application.7z"
    file_type = "7z"
    first_seen = "2026-11-01 00:03:42"
  condition:
    hash.sha256(0, filesize) == "14dc82bc5ee7c606e862a702666cc1b314179545f3a56fa68fc76b29d5900576"
}

rule MalwareBazaar_unknown_040_a722772d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a722772daefdf8c9630c00ec51a176f3b53cdf35a9133b91abd0121517f66f34"
    family = "unknown"
    file_name = "client2.google.com.cup2key.zip"
    file_type = "zip"
    first_seen = "2026-11-01 00:02:27"
  condition:
    hash.sha256(0, filesize) == "a722772daefdf8c9630c00ec51a176f3b53cdf35a9133b91abd0121517f66f34"
}

rule MalwareBazaar_unknown_041_3e64a72d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb"
    family = "unknown"
    file_name = "3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb"
    file_type = "exe"
    first_seen = "2026-11-01 00:02:20"
  condition:
    hash.sha256(0, filesize) == "3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb"
}

rule MalwareBazaar_unknown_042_7d33d778
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d33d7780e4de1b568c1a99eaadb4895e16fc0ae7a72a25e5cc115b6b218e381"
    family = "unknown"
    file_name = "eda1686d-c620-49a0-ab53-6b6659f6cad1.ps1"
    file_type = "ps1"
    first_seen = "2026-11-01 00:01:42"
  condition:
    hash.sha256(0, filesize) == "7d33d7780e4de1b568c1a99eaadb4895e16fc0ae7a72a25e5cc115b6b218e381"
}

rule MalwareBazaar_unknown_043_60f4f3fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60f4f3fd202f77f14d1eda4829c48b5c5fcd170951c914a0a73428c332df9844"
    family = "unknown"
    file_name = "bbd224f8-8296-404b-ab7c-c93301380271.ps1"
    file_type = "ps1"
    first_seen = "2026-10-31 23:59:25"
  condition:
    hash.sha256(0, filesize) == "60f4f3fd202f77f14d1eda4829c48b5c5fcd170951c914a0a73428c332df9844"
}

rule MalwareBazaar_unknown_044_5d4ccb77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d4ccb77b6ae228cfd09641816d538f8336084ef0e93c90453b60e1b04be99bb"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-10-31 23:57:03"
  condition:
    hash.sha256(0, filesize) == "5d4ccb77b6ae228cfd09641816d538f8336084ef0e93c90453b60e1b04be99bb"
}

rule MalwareBazaar_unknown_045_ae79a18f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae79a18faa326d8522701a36850a9d511cdf0450f59ee5cf678b5ddf1bd441cb"
    family = "unknown"
    file_name = "task_360.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:45:15"
  condition:
    hash.sha256(0, filesize) == "ae79a18faa326d8522701a36850a9d511cdf0450f59ee5cf678b5ddf1bd441cb"
}

rule MalwareBazaar_RaspberryRobin_046_d0897e93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0897e93090efa7e0ca7b2a0913f45d908c436dc4b9def8a60f82e435247a26d"
    family = "RaspberryRobin"
    file_name = "task_354.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:44:13"
  condition:
    hash.sha256(0, filesize) == "d0897e93090efa7e0ca7b2a0913f45d908c436dc4b9def8a60f82e435247a26d"
}

rule MalwareBazaar_Mirai_047_9d248e41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d248e41c44dc04235c3fa71f09bbc620e1e4cd4a488436effdfa0de47a092b7"
    family = "Mirai"
    file_name = "bot-linux-amd64"
    file_type = "elf"
    first_seen = "2026-10-31 23:44:12"
  condition:
    hash.sha256(0, filesize) == "9d248e41c44dc04235c3fa71f09bbc620e1e4cd4a488436effdfa0de47a092b7"
}

rule MalwareBazaar_Tofsee_048_30438ad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30438ad34a3f3a4c0d8ca14cee517eee0f2465a027c2f806c91d262283a2bff9"
    family = "Tofsee"
    file_name = "𝐏𝐑𝐎 𝐒𝐄𝐓𝐔𝐏.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:41:50"
  condition:
    hash.sha256(0, filesize) == "30438ad34a3f3a4c0d8ca14cee517eee0f2465a027c2f806c91d262283a2bff9"
}

rule MalwareBazaar_unknown_049_2c868a4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c868a4a61dfc58fa73b87a9e68c7876f836c608c539558053d829ea462064cb"
    family = "unknown"
    file_name = "Setup-2.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:24:58"
  condition:
    hash.sha256(0, filesize) == "2c868a4a61dfc58fa73b87a9e68c7876f836c608c539558053d829ea462064cb"
}

rule MalwareBazaar_unknown_050_0cffe2b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cffe2b753674df357aa2980e349765dc763602149f1a61de87cf817506857eb"
    family = "unknown"
    file_name = "Setup-1.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:23:28"
  condition:
    hash.sha256(0, filesize) == "0cffe2b753674df357aa2980e349765dc763602149f1a61de87cf817506857eb"
}

rule MalwareBazaar_unknown_051_73c6c7a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73c6c7a8ee2b650316b8723b9b581b200678329fac21f4bb73e11f6adf81bf01"
    family = "unknown"
    file_name = "gitlосitу64-v.5.502.exe"
    file_type = "exe"
    first_seen = "2026-10-31 23:05:53"
  condition:
    hash.sha256(0, filesize) == "73c6c7a8ee2b650316b8723b9b581b200678329fac21f4bb73e11f6adf81bf01"
}

rule MalwareBazaar_Mirai_052_3cbaae89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cbaae896e2ac678aa0a43622ab6025d3cd3f9b5bf3970feccd2662b12b15dea"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-10-31 23:01:35"
  condition:
    hash.sha256(0, filesize) == "3cbaae896e2ac678aa0a43622ab6025d3cd3f9b5bf3970feccd2662b12b15dea"
}

rule MalwareBazaar_unknown_053_5b6f9a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b6f9a43cbd0e7608ff4b6bdae43a66dd5d435caa1c078f39955dae1bb703965"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-10-31 22:52:29"
  condition:
    hash.sha256(0, filesize) == "5b6f9a43cbd0e7608ff4b6bdae43a66dd5d435caa1c078f39955dae1bb703965"
}

rule MalwareBazaar_Mirai_054_7b026f26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b026f26374a7aea28f4c4e483fe9aad004ee3a7e33d308aa3a8de0bd5dfb303"
    family = "Mirai"
    file_name = "bot-linux-mips"
    file_type = "elf"
    first_seen = "2026-10-31 22:51:45"
  condition:
    hash.sha256(0, filesize) == "7b026f26374a7aea28f4c4e483fe9aad004ee3a7e33d308aa3a8de0bd5dfb303"
}

rule MalwareBazaar_Mirai_055_d35eea4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d35eea4fca7cf1b35418f3fe62f5fc442b2af9a73e8b665961f915611895d12b"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-31 22:51:42"
  condition:
    hash.sha256(0, filesize) == "d35eea4fca7cf1b35418f3fe62f5fc442b2af9a73e8b665961f915611895d12b"
}

rule MalwareBazaar_CoinMiner_056_a84568d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a84568d291f3ab3e2862c875d57657236258fa591ae251f379c23263885ead4b"
    family = "CoinMiner"
    file_name = "CenterMSI_drive11.164.10.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:43:13"
  condition:
    hash.sha256(0, filesize) == "a84568d291f3ab3e2862c875d57657236258fa591ae251f379c23263885ead4b"
}

rule MalwareBazaar_CoinMiner_057_9c3a7607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c3a760765258f5e7802e828af6d5b88d69eee4bfc497e741d1bc4d80738242b"
    family = "CoinMiner"
    file_name = "CenterMSI_drive11.164.10.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:42:06"
  condition:
    hash.sha256(0, filesize) == "9c3a760765258f5e7802e828af6d5b88d69eee4bfc497e741d1bc4d80738242b"
}

rule MalwareBazaar_unknown_058_ba4ee6ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba4ee6ce0b34b33d2b9494f45ef059e7360dcf783240674ca06a61e352667908"
    family = "unknown"
    file_name = "pyservice64.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:40:50"
  condition:
    hash.sha256(0, filesize) == "ba4ee6ce0b34b33d2b9494f45ef059e7360dcf783240674ca06a61e352667908"
}

rule MalwareBazaar_unknown_059_5795fe67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5795fe674d0f9759cdfc26217924dcbdcf37f23a78131bce6d92b3398f608d0d"
    family = "unknown"
    file_name = "vcomp140.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:39:49"
  condition:
    hash.sha256(0, filesize) == "5795fe674d0f9759cdfc26217924dcbdcf37f23a78131bce6d92b3398f608d0d"
}

rule MalwareBazaar_CoinMiner_060_806351b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "806351b3460f58bd7a3a4f939ab78f8faa076fffa38628fb516b9716394e62f6"
    family = "CoinMiner"
    file_name = "IntelRMS_service112.90.988.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:39:20"
  condition:
    hash.sha256(0, filesize) == "806351b3460f58bd7a3a4f939ab78f8faa076fffa38628fb516b9716394e62f6"
}

rule MalwareBazaar_CoinMiner_061_6c9c45fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c9c45fbe531f5a89190a1b6ddf674edb4aa2d1b53e215e237b78ab7cd7bfb8b"
    family = "CoinMiner"
    file_name = "IntelRMS_service112.90.988.exe"
    file_type = "exe"
    first_seen = "2026-10-31 22:36:21"
  condition:
    hash.sha256(0, filesize) == "6c9c45fbe531f5a89190a1b6ddf674edb4aa2d1b53e215e237b78ab7cd7bfb8b"
}

rule MalwareBazaar_unknown_062_ab1cee0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab1cee0ca786d407e2d0ef724056d6ec47092587b71ec23e41fc9bd495c8cd3e"
    family = "unknown"
    file_name = "ab1cee0ca786d407e2d0ef724056d6ec47092587b71ec23e41fc9bd495c8cd3e.dll"
    file_type = "exe"
    first_seen = "2026-10-31 22:21:35"
  condition:
    hash.sha256(0, filesize) == "ab1cee0ca786d407e2d0ef724056d6ec47092587b71ec23e41fc9bd495c8cd3e"
}

rule MalwareBazaar_RustyStealer_063_1e48eb75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e48eb751699f706278e798d3d8f679fefe3f4fc1347d68f3d875d8a366e4075"
    family = "RustyStealer"
    file_name = "1e48eb751699f706278e798d3d8f679fefe3f4fc1347d68f3d875d8a366e4075.dll"
    file_type = "exe"
    first_seen = "2026-10-31 22:20:52"
  condition:
    hash.sha256(0, filesize) == "1e48eb751699f706278e798d3d8f679fefe3f4fc1347d68f3d875d8a366e4075"
}

rule MalwareBazaar_Mirai_064_4f64901c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f64901c53e903309136e13892c4c8a5c4c57550b08acd1ae53757ca43c7d8e5"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-10-31 22:16:43"
  condition:
    hash.sha256(0, filesize) == "4f64901c53e903309136e13892c4c8a5c4c57550b08acd1ae53757ca43c7d8e5"
}

rule MalwareBazaar_Mirai_065_d912ad77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d912ad7735ac150a5b289f5c7f4ed61971288433786c5212d329e33037a9bf5a"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-31 22:14:15"
  condition:
    hash.sha256(0, filesize) == "d912ad7735ac150a5b289f5c7f4ed61971288433786c5212d329e33037a9bf5a"
}

rule MalwareBazaar_unknown_066_d8c97a23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8c97a23c53348a4070186283e3ac0aabce26e33e8f5bd64731408eb768dd40d"
    family = "unknown"
    file_name = "Dhcud0.hta"
    file_type = "hta"
    first_seen = "2026-10-31 21:55:40"
  condition:
    hash.sha256(0, filesize) == "d8c97a23c53348a4070186283e3ac0aabce26e33e8f5bd64731408eb768dd40d"
}

rule MalwareBazaar_Mirai_067_323c3cff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "323c3cff3088cebcb9d637896828aa4f29a3a5e726b7b0cf1a6ecf6fe8d8883e"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-10-31 21:55:36"
  condition:
    hash.sha256(0, filesize) == "323c3cff3088cebcb9d637896828aa4f29a3a5e726b7b0cf1a6ecf6fe8d8883e"
}

rule MalwareBazaar_unknown_068_c5906f39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5906f3997ae2a42761bcf036e9da971a7f372dbd8013884fd8934b6e48b28db"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-10-31 21:52:26"
  condition:
    hash.sha256(0, filesize) == "c5906f3997ae2a42761bcf036e9da971a7f372dbd8013884fd8934b6e48b28db"
}

rule MalwareBazaar_Mirai_069_b054dff8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b054dff887f2fde959f25b42dc49d6dc0dd504f863d0a896a143fc01b21a2de6"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-31 21:48:13"
  condition:
    hash.sha256(0, filesize) == "b054dff887f2fde959f25b42dc49d6dc0dd504f863d0a896a143fc01b21a2de6"
}

rule MalwareBazaar_unknown_070_d7006d30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7006d308ee13d9b4324a2fbd91549ef9604c3313486ce991f7eb3ceedb55140"
    family = "unknown"
    file_name = "interview_jibril_rajoub.hta"
    file_type = "hta"
    first_seen = "2026-10-31 21:33:55"
  condition:
    hash.sha256(0, filesize) == "d7006d308ee13d9b4324a2fbd91549ef9604c3313486ce991f7eb3ceedb55140"
}

rule MalwareBazaar_unknown_071_2cf2922d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cf2922d0df1857f9fe38b3ab7666f85f791e68ee648e3790630c7ac4136a978"
    family = "unknown"
    file_name = "CV_israa_Jerusalem.hta"
    file_type = "hta"
    first_seen = "2026-10-31 21:29:25"
  condition:
    hash.sha256(0, filesize) == "2cf2922d0df1857f9fe38b3ab7666f85f791e68ee648e3790630c7ac4136a978"
}

rule MalwareBazaar_unknown_072_2dc9ea3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dc9ea3c14cb2af3a4eb4cd4688a3540cae434b4e5394ea09b4b64eb6d4a81cc"
    family = "unknown"
    file_name = "CV_israa_Jerusalem.docm"
    file_type = "docm"
    first_seen = "2026-10-31 21:28:37"
  condition:
    hash.sha256(0, filesize) == "2dc9ea3c14cb2af3a4eb4cd4688a3540cae434b4e5394ea09b4b64eb6d4a81cc"
}

rule MalwareBazaar_unknown_073_e34efe9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e34efe9b7001f45cbf03764eb9658c3c3e4889b1c81454758df799fa7dc40e9e"
    family = "unknown"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-10-31 21:01:00"
  condition:
    hash.sha256(0, filesize) == "e34efe9b7001f45cbf03764eb9658c3c3e4889b1c81454758df799fa7dc40e9e"
}

rule MalwareBazaar_unknown_074_42b9001b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42b9001bc3cba3459607da359512d20adf4453f74d7ed793d39d77be465ee9c2"
    family = "unknown"
    file_name = "OurNew.exe"
    file_type = "exe"
    first_seen = "2026-10-31 20:52:37"
  condition:
    hash.sha256(0, filesize) == "42b9001bc3cba3459607da359512d20adf4453f74d7ed793d39d77be465ee9c2"
}

rule MalwareBazaar_unknown_075_e3b3d631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3b3d631cba7f3ff41d6dcc207a52bc84e096facec79953684849564d85d40e3"
    family = "unknown"
    file_name = "newisbest.exe"
    file_type = "exe"
    first_seen = "2026-10-31 20:52:31"
  condition:
    hash.sha256(0, filesize) == "e3b3d631cba7f3ff41d6dcc207a52bc84e096facec79953684849564d85d40e3"
}

rule MalwareBazaar_Mirai_076_449162c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "449162c0118749eb2c836d1c8af26976f010a1842e04743694d6d5479a7542d9"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-10-31 20:27:40"
  condition:
    hash.sha256(0, filesize) == "449162c0118749eb2c836d1c8af26976f010a1842e04743694d6d5479a7542d9"
}

rule MalwareBazaar_unknown_077_b25a7521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b25a752117a9f7072929b88771a281fc7a412a2955b087ef6b3741e8a2434343"
    family = "unknown"
    file_name = "rvtools-4.8.1.msi"
    file_type = "msi"
    first_seen = "2026-10-31 19:29:06"
  condition:
    hash.sha256(0, filesize) == "b25a752117a9f7072929b88771a281fc7a412a2955b087ef6b3741e8a2434343"
}

rule MalwareBazaar_unknown_078_4757f0ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4757f0ad27bc4a13d3c9c50645359a19e6658962f864c4c580323e32824d33c6"
    family = "unknown"
    file_name = "4757f0ad27bc4a13d3c9c50645359a19e6658962f864c4c580323e32824d33c6"
    file_type = "elf"
    first_seen = "2026-10-31 19:00:14"
  condition:
    hash.sha256(0, filesize) == "4757f0ad27bc4a13d3c9c50645359a19e6658962f864c4c580323e32824d33c6"
}

rule MalwareBazaar_unknown_079_3102a25b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3102a25b1ff3c13468769f7fe38ebaf50cf6660e7a533e2bde723bc17b8f6e39"
    family = "unknown"
    file_name = "3102a25b1ff3c13468769f7fe38ebaf50cf6660e7a533e2bde723bc17b8f6e39"
    file_type = "elf"
    first_seen = "2026-10-31 18:53:39"
  condition:
    hash.sha256(0, filesize) == "3102a25b1ff3c13468769f7fe38ebaf50cf6660e7a533e2bde723bc17b8f6e39"
}

rule MalwareBazaar_unknown_080_7cd4c78e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cd4c78e13625706f3012bb236b48afcab8f4ef1ec4e9b7fc4c13a87a3cced02"
    family = "unknown"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-10-31 18:49:22"
  condition:
    hash.sha256(0, filesize) == "7cd4c78e13625706f3012bb236b48afcab8f4ef1ec4e9b7fc4c13a87a3cced02"
}

rule MalwareBazaar_unknown_081_4a0b3f9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a0b3f9aaf8214e7b3a4ea6784fb9960ac0aeca67ff1c35d418d0bcced56697c"
    family = "unknown"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-10-31 18:48:01"
  condition:
    hash.sha256(0, filesize) == "4a0b3f9aaf8214e7b3a4ea6784fb9960ac0aeca67ff1c35d418d0bcced56697c"
}

rule MalwareBazaar_Mirai_082_4ea4f6dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ea4f6dd439a54cd36d8194c14c1673c6e935b1a493f27bf4df83a2b96ceedb6"
    family = "Mirai"
    file_name = "mpsl32"
    file_type = "elf"
    first_seen = "2026-10-31 18:47:35"
  condition:
    hash.sha256(0, filesize) == "4ea4f6dd439a54cd36d8194c14c1673c6e935b1a493f27bf4df83a2b96ceedb6"
}

rule MalwareBazaar_unknown_083_edbb2619
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edbb2619827bab21ed33fdd1c9ebe83f07c6db7ce92598eca7fb0aa2cd85a639"
    family = "unknown"
    file_name = "alpme-1.0.25.vsix"
    file_type = "zip"
    first_seen = "2026-10-31 18:47:11"
  condition:
    hash.sha256(0, filesize) == "edbb2619827bab21ed33fdd1c9ebe83f07c6db7ce92598eca7fb0aa2cd85a639"
}

rule MalwareBazaar_unknown_084_05fafc00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05fafc00e36ebaec146e64c9ad7bb3bc7a733c2dd99fff954e8ef1736b1e04a3"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-31 18:40:13"
  condition:
    hash.sha256(0, filesize) == "05fafc00e36ebaec146e64c9ad7bb3bc7a733c2dd99fff954e8ef1736b1e04a3"
}

rule MalwareBazaar_unknown_085_fa647a4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa647a4d12cc887bd96cb2eb126f161cbcf47e84312094bb0dcc2429e7c8e296"
    family = "unknown"
    file_name = "dvnx_kit2_lold_inner.exe"
    file_type = "exe"
    first_seen = "2026-10-31 18:35:18"
  condition:
    hash.sha256(0, filesize) == "fa647a4d12cc887bd96cb2eb126f161cbcf47e84312094bb0dcc2429e7c8e296"
}

rule MalwareBazaar_unknown_086_578cc6d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "578cc6d26bf7c5536d2c0ea0df5a788155e15d09e49054303915b535f4012791"
    family = "unknown"
    file_name = "dvnx_kit2_inner_payload.dll"
    file_type = "exe"
    first_seen = "2026-10-31 18:35:10"
  condition:
    hash.sha256(0, filesize) == "578cc6d26bf7c5536d2c0ea0df5a788155e15d09e49054303915b535f4012791"
}

rule MalwareBazaar_AokigaharaStealer_087_1370f67a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1370f67acce699e1ac078821d846f70703934ca5c847c17fee444f31d0953483"
    family = "AokigaharaStealer"
    file_name = "novaforge_static_unpacked.disk.exe"
    file_type = "exe"
    first_seen = "2026-10-31 18:34:57"
  condition:
    hash.sha256(0, filesize) == "1370f67acce699e1ac078821d846f70703934ca5c847c17fee444f31d0953483"
}

rule MalwareBazaar_unknown_088_4bcb5301
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bcb5301211ab257543812405ca80cbecab8938a8a5a2fd0c7d65d75db9bc1a9"
    family = "unknown"
    file_name = "4bcb5301211ab257543812405ca80cbecab8938a8a5a2fd0c7d65d75db9bc1a9"
    file_type = "elf"
    first_seen = "2026-10-31 18:31:13"
  condition:
    hash.sha256(0, filesize) == "4bcb5301211ab257543812405ca80cbecab8938a8a5a2fd0c7d65d75db9bc1a9"
}

rule MalwareBazaar_unknown_089_21498faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21498faad7283839d0b055c618693eb2affe910b6e8d030592d92a94cd266144"
    family = "unknown"
    file_name = "IEProc.exe"
    file_type = "exe"
    first_seen = "2026-10-31 18:19:15"
  condition:
    hash.sha256(0, filesize) == "21498faad7283839d0b055c618693eb2affe910b6e8d030592d92a94cd266144"
}

rule MalwareBazaar_RustyStealer_090_d4b9c211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4b9c2118987d0b7ef0df12b27e8f4bab0152c8d50bf0bed7e937c215a42ccd7"
    family = "RustyStealer"
    file_name = "Xenonsable.exe"
    file_type = "exe"
    first_seen = "2026-10-31 18:14:24"
  condition:
    hash.sha256(0, filesize) == "d4b9c2118987d0b7ef0df12b27e8f4bab0152c8d50bf0bed7e937c215a42ccd7"
}

rule MalwareBazaar_Mirai_091_ccfd73a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91"
    family = "Mirai"
    file_name = "ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91"
    file_type = "elf"
    first_seen = "2026-10-31 18:08:59"
  condition:
    hash.sha256(0, filesize) == "ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91"
}

rule MalwareBazaar_ValleyRAT_092_03575d52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03575d5232dd841c5c94238c6666ea30272e0826c466dba22a4c2445188dba58"
    family = "ValleyRAT"
    file_name = "14e70f4c893a3534c55a0f9ed251a40b.exe"
    file_type = "exe"
    first_seen = "2026-10-31 17:35:14"
  condition:
    hash.sha256(0, filesize) == "03575d5232dd841c5c94238c6666ea30272e0826c466dba22a4c2445188dba58"
}

rule MalwareBazaar_unknown_093_ea3b82d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea3b82d9a70295c74edd17b90c549a84ca05a31f07c9a398b0c945493fb0dc5c"
    family = "unknown"
    file_name = "gitlосitу64-v.3.122.exe"
    file_type = "exe"
    first_seen = "2026-10-31 17:32:59"
  condition:
    hash.sha256(0, filesize) == "ea3b82d9a70295c74edd17b90c549a84ca05a31f07c9a398b0c945493fb0dc5c"
}

rule MalwareBazaar_unknown_094_0d359ccb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d359ccbc02f125f943b726794b0b9b73090698f5fb8170682fbfdb1f121091a"
    family = "unknown"
    file_name = "fuck_niggers_39.hta"
    file_type = "hta"
    first_seen = "2026-10-31 17:30:10"
  condition:
    hash.sha256(0, filesize) == "0d359ccbc02f125f943b726794b0b9b73090698f5fb8170682fbfdb1f121091a"
}

rule MalwareBazaar_WannaCry_095_87adc00c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87adc00cc7aa18d84c0b047bc186b34e48715b89f8d2f40278f7eb3a01d05223"
    family = "WannaCry"
    file_name = "3d18ae12b9d8edc29ee15d0cf72d854e"
    file_type = "dll"
    first_seen = "2026-10-31 17:06:58"
  condition:
    hash.sha256(0, filesize) == "87adc00cc7aa18d84c0b047bc186b34e48715b89f8d2f40278f7eb3a01d05223"
}

rule MalwareBazaar_unknown_096_8cc8bf1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cc8bf1f64417890f7d4ebd7bce8ef55fbe724a70d8de9355bf027c92380c8eb"
    family = "unknown"
    file_name = "fuck_niggers_21.hta"
    file_type = "hta"
    first_seen = "2026-10-31 16:55:11"
  condition:
    hash.sha256(0, filesize) == "8cc8bf1f64417890f7d4ebd7bce8ef55fbe724a70d8de9355bf027c92380c8eb"
}

rule MalwareBazaar_Mirai_097_82ea0074
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82ea0074e950a589422046178545acaa950b5f0b61760630af27546741a02dfc"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-10-31 16:43:45"
  condition:
    hash.sha256(0, filesize) == "82ea0074e950a589422046178545acaa950b5f0b61760630af27546741a02dfc"
}

rule MalwareBazaar_Gh0stRAT_098_c5418c52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5418c52bdf33f70aff9bcf014d3f10c4661a87ff2dbc8747feaa10415fc5e52"
    family = "Gh0stRAT"
    file_name = "BANDIZIPSETUP.exe"
    file_type = "exe"
    first_seen = "2026-10-31 16:40:33"
  condition:
    hash.sha256(0, filesize) == "c5418c52bdf33f70aff9bcf014d3f10c4661a87ff2dbc8747feaa10415fc5e52"
}

rule MalwareBazaar_Mirai_099_1b01265f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b01265fc95eecf548211be11cb8708d63f774d92ca98be3d2edba6e6e1a7fc5"
    family = "Mirai"
    file_name = "bot-linux-arm64"
    file_type = "elf"
    first_seen = "2026-10-31 16:35:11"
  condition:
    hash.sha256(0, filesize) == "1b01265fc95eecf548211be11cb8708d63f774d92ca98be3d2edba6e6e1a7fc5"
}

rule MalwareBazaar_unknown_100_a2fa3be9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2fa3be9c8bb41089d27885e686ea74f7250a54d8a3dd6613e0bbad94a92bd2e"
    family = "unknown"
    file_name = "a2fa3be9c8bb41089d27885e686ea74f7250a54d8a3dd6613e0bbad94a92bd2e"
    file_type = "elf"
    first_seen = "2026-10-31 16:34:42"
  condition:
    hash.sha256(0, filesize) == "a2fa3be9c8bb41089d27885e686ea74f7250a54d8a3dd6613e0bbad94a92bd2e"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-26

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 665 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 665 |
| Unique family labels | 11 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 60 |
| Mirai | 23 |
| Phorpiex | 4 |
| RemusStealer | 4 |
| CoinMiner | 2 |
| Vidar | 2 |
| Hajime | 1 |
| Worm.Virut | 1 |
| NanoCore | 1 |
| WannaCry | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 42 |
| elf | 34 |
| sh | 18 |
| unknown | 2 |
| 7z | 2 |
| msi | 1 |
| apk | 1 |

## Per-Sample Analysis

### Sample 1: `0bc71f56b650c93a`

| Field | Value |
|---|---|
| SHA-256 | `0bc71f56b650c93a4f50e11ba41af659c46fba843cd019e2dbb152a536ed714f` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-26 03:52:29` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ff0126ed66be4858a161aa773cd9a76` |
| SHA-1 | `904da862281f6a19155a5710c9bfb26f81485a26` |
| SHA-256 | `0bc71f56b650c93a4f50e11ba41af659c46fba843cd019e2dbb152a536ed714f` |
| SHA3-384 | `29683aa05c183dfc484058933e60280c57827a3a61e841b1c5c7cbc52a47a2f3308864a16b06d336458d095b23228696` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T15BE6331576E001FEDA730239EDE20659F9F1B4B68731C19B1BA88B756A231A0CD3D763` |
| SSDEEP | `393216:1gp7tsvr/AAD9Jy9ap2OOXMCHWUjX0cuI3/PGTAI:1gxOz/dD9JyM4xXMb8XhH/O7` |
| ICON-DHASH | `d4f8fcbc8cc47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_0bc71f56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc71f56b650c93a4f50e11ba41af659c46fba843cd019e2dbb152a536ed714f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 03:52:29"
  condition:
    hash.sha256(0, filesize) == "0bc71f56b650c93a4f50e11ba41af659c46fba843cd019e2dbb152a536ed714f"
}
```

### Sample 2: `63c5f9fbf4bebf78`

| Field | Value |
|---|---|
| SHA-256 | `63c5f9fbf4bebf78e476a90b5115b46f493ef3be5a56dafcec6c825160913645` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-26 03:41:28` |
| Reporter | `Bitsight` |
| Tags | `3fc2270f9ceb525e5c2d1d101bccd90f, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `450e0227f0118633049d3c4f1e79fafc` |
| SHA-1 | `53de9d6e3d7816d949aa1adcb479f73367da8cc2` |
| SHA-256 | `63c5f9fbf4bebf78e476a90b5115b46f493ef3be5a56dafcec6c825160913645` |
| SHA3-384 | `e0a0c1431dde40a1ff41a54b95ae2137a4bff4d57179a224e75eda5b7a4c814f43ec78509d5885b60efd911761981778` |
| IMPHASH | `71b008ad892c449add994b5e45fffabc` |
| TLSH | `T16AB67B15A3A15EE8D226817CCA964232F6B57741C760AACB0274D2193E37BF46E3FF11` |
| SSDEEP | `24576:iY6TYOe2pP1y2DjTHcmQhPT+mP82giMTRuccsUCsRq:iY6TYOEmQB+mmB9UCaq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_63c5f9fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c5f9fbf4bebf78e476a90b5115b46f493ef3be5a56dafcec6c825160913645"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 03:41:28"
  condition:
    hash.sha256(0, filesize) == "63c5f9fbf4bebf78e476a90b5115b46f493ef3be5a56dafcec6c825160913645"
}
```

### Sample 3: `c7dc544ed14e7521`

| Field | Value |
|---|---|
| SHA-256 | `c7dc544ed14e75219a4eb0b02690d47e412f615f2f1329f99a00337a72b17256` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-26 03:38:38` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7790768e8fe6d3bbe1b36e5457895b22` |
| SHA-1 | `170e68634eb1f8e2523da558f7de4c15d55568f8` |
| SHA-256 | `c7dc544ed14e75219a4eb0b02690d47e412f615f2f1329f99a00337a72b17256` |
| SHA3-384 | `6535e895940bbc6d7bb37d294e0847ece268b3a328686947b87c5e864a5e76059d752e6295726cd0848f04a22a5aec76` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T151624B0BA4808035EBF14474827F526649FEACB623C5F9DBF7E0648A5AB46E1F43116F` |
| SSDEEP | `192:AWTsGnjXgjk8LcRI+gRdjMlIfeF5oIV1BKUSfEzQLd1gJxTmv8U9cth29ik:A6ScS9feroFE+yav8U9coX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_c7dc544e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7dc544ed14e75219a4eb0b02690d47e412f615f2f1329f99a00337a72b17256"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 03:38:38"
  condition:
    hash.sha256(0, filesize) == "c7dc544ed14e75219a4eb0b02690d47e412f615f2f1329f99a00337a72b17256"
}
```

### Sample 4: `2fed5d0552cf80ea`

| Field | Value |
|---|---|
| SHA-256 | `2fed5d0552cf80eaae1928150238397a632ebb9521e98129daa71eb46ea1f113` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-26 02:53:11` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e11f99e1017209acc1ecd207f1c5832` |
| SHA-1 | `ffbe00b65889aa4554fb6aef8cac9383652dae6e` |
| SHA-256 | `2fed5d0552cf80eaae1928150238397a632ebb9521e98129daa71eb46ea1f113` |
| SHA3-384 | `93ab89c03b8c67a48db45ef8ef82be1e7a08af10ee0537637dc13fa14f71abb811096bd3a2d7dc05fde6b6e97ebfdc33` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T14722191ABE850331D39049F4517A824F557D2623A783B3EFF373929A0B963858410EEE` |
| SSDEEP | `96:2KedvoJYz/J4hSWKB2dS6BDrVx+ZQSlctTKzsg9PFJxGE9mZ2FFhxC7tCEKAYv/9:2K6oiEKBEx+eSlRPFJxTEZmFhSKtV` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_004_2fed5d05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fed5d0552cf80eaae1928150238397a632ebb9521e98129daa71eb46ea1f113"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 02:53:11"
  condition:
    hash.sha256(0, filesize) == "2fed5d0552cf80eaae1928150238397a632ebb9521e98129daa71eb46ea1f113"
}
```

### Sample 5: `3a0ecd128bddb650`

| Field | Value |
|---|---|
| SHA-256 | `3a0ecd128bddb650c684af39de612fb50953c76e1be4677afff1b0a3ae7e01f8` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-26 02:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f19a0eda7ff0268f6c6faccfdce0879e` |
| SHA-1 | `d37a15e402c7d41e6139e563ff0f9696cf288a94` |
| SHA-256 | `3a0ecd128bddb650c684af39de612fb50953c76e1be4677afff1b0a3ae7e01f8` |
| SHA3-384 | `1c9bf8479faf29324051f36afca007dedcb1bda6e66e3c29085f122439c8d4ec1fdbc9b949d5388da57f7b634d9fdf9d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F9E6336CAAE012FEED23943CEAE05551E4B2B8731774C5DF975883B46E572F08839923` |
| SSDEEP | `393216:Af3QH6q+q9U1hsaR1JbKKjHNNf9HNThCXMCHWUjXdcuI3/PGTAI:APO/Om21bPf9tTYXMb8XqH/O7` |
| ICON-DHASH | `38fcf8f8fcf8e040` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_3a0ecd12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a0ecd128bddb650c684af39de612fb50953c76e1be4677afff1b0a3ae7e01f8"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 02:52:30"
  condition:
    hash.sha256(0, filesize) == "3a0ecd128bddb650c684af39de612fb50953c76e1be4677afff1b0a3ae7e01f8"
}
```

### Sample 6: `2cf0bc8361e716ff`

| Field | Value |
|---|---|
| SHA-256 | `2cf0bc8361e716ffb2dbfa4c680028bf6b2dcbcd84a14c511dfec0af523860c8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-26 02:25:21` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8a3dc6184e2e05d6b0f0262640bfaa0` |
| SHA-1 | `ba7eef5b9ff3e388335540385f336de4dfe8f1f6` |
| SHA-256 | `2cf0bc8361e716ffb2dbfa4c680028bf6b2dcbcd84a14c511dfec0af523860c8` |
| SHA3-384 | `ced0964d56ac3ac6319fc5b599f3024f53e8afeda0baa04517d72dbde1b865f10d5ded3cb39d14280396c01cd0d82b9d` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T1E6623C0BB4808035EBE144B4827F526645BDADB623C5F9CBF7E0648A5EB46E1F43216F` |
| SSDEEP | `192:AWhsGnjXgjk8LMRI+wBdzMRJFeIFFBKUSfEzQbd1gJxTmv8U9cth+9ik:AYSMygUlEOyav8U9cAX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_2cf0bc83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cf0bc8361e716ffb2dbfa4c680028bf6b2dcbcd84a14c511dfec0af523860c8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 02:25:21"
  condition:
    hash.sha256(0, filesize) == "2cf0bc8361e716ffb2dbfa4c680028bf6b2dcbcd84a14c511dfec0af523860c8"
}
```

### Sample 7: `6543a1888c58d583`

| Field | Value |
|---|---|
| SHA-256 | `6543a1888c58d583be80f8f2749c4a0631c6f3d82a9b64a42b657d874f5d2b90` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-26 01:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73500ed71f4efbb76ec31499a32e83f9` |
| SHA-1 | `f0ff9433d77ca5bce3e904dcd48e9745caa24913` |
| SHA-256 | `6543a1888c58d583be80f8f2749c4a0631c6f3d82a9b64a42b657d874f5d2b90` |
| SHA3-384 | `8c8ae45f27cc30a6fe1972beac3f42f74ab8efc99e42a4c488b1a2f2299b5099143548cdcf938b886313a0ce2fdc55c1` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T108E6330C97D023EDE6334039F9A18596E5E970A84B32C3DF0B5993A6AD571E08D7DB13` |
| SSDEEP | `393216:kfFRWqbGeEbx//s1+0zCXMCHWUjX7cuI3/PGTAI:kV6R5/s1+0zCXMb8X4H/O7` |
| ICON-DHASH | `e8686461d8e8ec58` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_6543a188
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6543a1888c58d583be80f8f2749c4a0631c6f3d82a9b64a42b657d874f5d2b90"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 01:52:30"
  condition:
    hash.sha256(0, filesize) == "6543a1888c58d583be80f8f2749c4a0631c6f3d82a9b64a42b657d874f5d2b90"
}
```

### Sample 8: `7053ae123ff7a0f9`

| Field | Value |
|---|---|
| SHA-256 | `7053ae123ff7a0f94df6b88f2110e66c9797b8b32db55e6d78d3035221a268aa` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-26 01:23:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06ddbc00bef66d0048eea14759484ce4` |
| SHA-1 | `e63cb7bae6256e4f1d96fba3ed93a8e0c05e130b` |
| SHA-256 | `7053ae123ff7a0f94df6b88f2110e66c9797b8b32db55e6d78d3035221a268aa` |
| SHA3-384 | `b3ca02e02b844554f8fed5727769c43c34c659ebb0677ddd25bf9c08541fb62ef95d3f3e28e8c41fdab81520b33958c4` |
| TLSH | `T143235C6516857C24AE98C4361C7E2F0CB9AD83E6324452EE7FCB3CF68C4A69DD109B1D` |
| SSDEEP | `768:z+49GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:z+lcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_7053ae12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7053ae123ff7a0f94df6b88f2110e66c9797b8b32db55e6d78d3035221a268aa"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-26 01:23:58"
  condition:
    hash.sha256(0, filesize) == "7053ae123ff7a0f94df6b88f2110e66c9797b8b32db55e6d78d3035221a268aa"
}
```

### Sample 9: `09b7fa9a1bc1c3f3`

| Field | Value |
|---|---|
| SHA-256 | `09b7fa9a1bc1c3f34bcca306c1f9e3971083ebf265adf5f7684e4a320b5d562e` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-26 00:56:04` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3884d3a6319f468c296a90668f127d4` |
| SHA-1 | `eaec84b9becc94401a51ef501247022b39460e86` |
| SHA-256 | `09b7fa9a1bc1c3f34bcca306c1f9e3971083ebf265adf5f7684e4a320b5d562e` |
| SHA3-384 | `ff2ba561bf871cd5c3692e0bcdb1473635421a9c764728a0eb18d535b91038a1bd52b6b94d98cbf0ee4223c14b020d41` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T14E624C0BA4808035EBF14474827F526644FEADB623C5F9DBF7E0648A5AB46E1F43116F` |
| SSDEEP | `192:AWEsGnjXgjk8LcRI+gRdjMlIfeF5oIV1BKUSfEzQLd1gJxTmv8U9cthK9ik:A5ScS9feroFE+yav8U9csX` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_009_09b7fa9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09b7fa9a1bc1c3f34bcca306c1f9e3971083ebf265adf5f7684e4a320b5d562e"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 00:56:04"
  condition:
    hash.sha256(0, filesize) == "09b7fa9a1bc1c3f34bcca306c1f9e3971083ebf265adf5f7684e4a320b5d562e"
}
```

### Sample 10: `d7be04c19b1d908e`

| Field | Value |
|---|---|
| SHA-256 | `d7be04c19b1d908e4d33edfdcf3fbcb15812763edb905ce1fa46233368181086` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-26 00:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2ba2c17a668eb9c2cea61159e061e60` |
| SHA-1 | `cc8121380454762068053a195ef20e5798a6a859` |
| SHA-256 | `d7be04c19b1d908e4d33edfdcf3fbcb15812763edb905ce1fa46233368181086` |
| SHA3-384 | `3979a68fcbe3f7889b40fa922efe550022deb46696f1d5e07f199877ae3060eec0fe615691c6dfdd098c02045cfdb610` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T161E63358A9E011FDE933803CDDF0A588F226B4A60BB1C6DF5F98D3E16E531D0897DA16` |
| SSDEEP | `393216:9Y1/oYRdlIdFqw+XMCHWUjXacuI3/PGTAI:9qhL2R+XMb8XXH/O7` |
| ICON-DHASH | `d4e8d4d8e8e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_d7be04c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7be04c19b1d908e4d33edfdcf3fbcb15812763edb905ce1fa46233368181086"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 00:52:31"
  condition:
    hash.sha256(0, filesize) == "d7be04c19b1d908e4d33edfdcf3fbcb15812763edb905ce1fa46233368181086"
}
```

### Sample 11: `a0e0ed3de12c74a7`

| Field | Value |
|---|---|
| SHA-256 | `a0e0ed3de12c74a73c79f5ec6beb9b73d663d7795ff90d2159a183c9af153975` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-26 00:42:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffffd8a2d7379f4c9dd76a242e2ab5dd` |
| SHA-1 | `d375cc63e7a5db89997eff43a4c01192021cd334` |
| SHA-256 | `a0e0ed3de12c74a73c79f5ec6beb9b73d663d7795ff90d2159a183c9af153975` |
| SHA3-384 | `0fdd0addc44b48e7415532f1b843527fab68065bfb7c47b159d597484193b932499ef02a61fa80fc94e461bffec50166` |
| TLSH | `T146235C651A857C14AA98C4361D7F2F0CB9AD43E6320452EE7FCF3CF28C5A6ADA10572D` |
| SSDEEP | `768:yt6Utd8/k9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:tcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_a0e0ed3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0e0ed3de12c74a73c79f5ec6beb9b73d663d7795ff90d2159a183c9af153975"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-26 00:42:00"
  condition:
    hash.sha256(0, filesize) == "a0e0ed3de12c74a73c79f5ec6beb9b73d663d7795ff90d2159a183c9af153975"
}
```

### Sample 12: `5414c823040b8549`

| Field | Value |
|---|---|
| SHA-256 | `5414c823040b85495f88add29911ec42836277d9b1732468f70c29140cb198be` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-26 00:36:27` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b19dfd6c5c708e860712654606dfc5c2` |
| SHA-1 | `dad9595d91e785ef247b7fef94e8b6e780383431` |
| SHA-256 | `5414c823040b85495f88add29911ec42836277d9b1732468f70c29140cb198be` |
| SHA3-384 | `35ca5d71975128b933dd910cd8ed845e33cd7e74de0f253879a38ed07ff8dd2922c0616b2122e3384534f615550ac2f7` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T167624C0BB4818035EBE14474827F526645BDADB623C4F9CBF7E0648A5EB46E1F43116F` |
| SSDEEP | `192:AWtsGnjXgjk8LMRI+wBdzM1JFeIFFBKUSfEzQbd1gJxTmv8U9cth39ik:A8SMykUlEOyav8U9cNX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_5414c823
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5414c823040b85495f88add29911ec42836277d9b1732468f70c29140cb198be"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 00:36:27"
  condition:
    hash.sha256(0, filesize) == "5414c823040b85495f88add29911ec42836277d9b1732468f70c29140cb198be"
}
```

### Sample 13: `d3eb1b2e2fab88aa`

| Field | Value |
|---|---|
| SHA-256 | `d3eb1b2e2fab88aad1ee2766aa4c0e8dc48f610f8c43bfdd654d0b35d926b0f3` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-26 00:31:04` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb32d0112a42ea06111dc597a73400ef` |
| SHA-1 | `c2ddd3a1f3e1462802ed5d2a076a81f775a5162e` |
| SHA-256 | `d3eb1b2e2fab88aad1ee2766aa4c0e8dc48f610f8c43bfdd654d0b35d926b0f3` |
| SHA3-384 | `0e0245d0ca8b83b2947fac33530669af2eff4761835ebfec19c0cf49a02404c4bc424b0a807430d850bfef063bcfba83` |
| TLSH | `T1B401AFCAD250992050AAA41D32D75166F431C3C715CB5BA6BF6CE47D9B98E04B026F98` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaaCXCJGFF9x8C7nvCw1QCLBCNX:kXCKysE2hi0ziQvZohanY68avSAUX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_d3eb1b2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3eb1b2e2fab88aad1ee2766aa4c0e8dc48f610f8c43bfdd654d0b35d926b0f3"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-26 00:31:04"
  condition:
    hash.sha256(0, filesize) == "d3eb1b2e2fab88aad1ee2766aa4c0e8dc48f610f8c43bfdd654d0b35d926b0f3"
}
```

### Sample 14: `77a84e50efc64c42`

| Field | Value |
|---|---|
| SHA-256 | `77a84e50efc64c4248f38bc33aef956f4f8ea899760185f17caed1711da14981` |
| Family label | `Hajime` |
| File name | `i` |
| File type | `elf` |
| First seen | `2026-07-26 00:31:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Hajime` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3228c751712188ea561aa314880e6300` |
| SHA-1 | `d624ed6b2849f43cca656bab30c63b799d7effef` |
| SHA-256 | `77a84e50efc64c4248f38bc33aef956f4f8ea899760185f17caed1711da14981` |
| SHA3-384 | `4cfa0ca9d581b5e1a73d4d9020215586110d520572ad5d9522e8c28758db3fa49533832c3c0b7b6e234a7d64eb25acba` |
| TLSH | `T1ECA2F146269C3743E86255F1F37DBFC9B2026DBCAB7B58275088212370A314B62088BF` |
| SSDEEP | `384:YTYXvQDuYY2xZ6VTgDK4mpwTl5yejHSDeWBbo7hcXBOo3g1qsb:YTYIDfYG6ZmewZ59+Nw1qsb` |

#### Technical Assessment

- The sample is tracked as `Hajime` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Hajime_014_77a84e50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77a84e50efc64c4248f38bc33aef956f4f8ea899760185f17caed1711da14981"
    family = "Hajime"
    file_name = "i"
    file_type = "elf"
    first_seen = "2026-07-26 00:31:03"
  condition:
    hash.sha256(0, filesize) == "77a84e50efc64c4248f38bc33aef956f4f8ea899760185f17caed1711da14981"
}
```

### Sample 15: `63559cb87098de64`

| Field | Value |
|---|---|
| SHA-256 | `63559cb87098de64cbe5f1d981bf782283a8e24e3d81926a3ddb80cae5b5d856` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-26 00:26:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b933c74c0a98bcdb4f78a38957c24b16` |
| SHA-1 | `2b359eb0ae2ade043e348233d4035da6784e230e` |
| SHA-256 | `63559cb87098de64cbe5f1d981bf782283a8e24e3d81926a3ddb80cae5b5d856` |
| SHA3-384 | `e1f22a09f6b699da10bc313040d59b702c6fc5319ce449a7e50489134dd0c00ea6c1d66ad1d6a915ed6eedbfb77a8604` |
| TLSH | `T1BFC27D966A967C44BDC94A3E4CBE2B1D6DF5C3D1224D42AC3D4B3C719C11FACC618B1A` |
| SSDEEP | `768:C08vCB+25j6es8RI9FYpMSUpi+20qUpi+20YQX:C08l25Jed2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_63559cb8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63559cb87098de64cbe5f1d981bf782283a8e24e3d81926a3ddb80cae5b5d856"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-26 00:26:11"
  condition:
    hash.sha256(0, filesize) == "63559cb87098de64cbe5f1d981bf782283a8e24e3d81926a3ddb80cae5b5d856"
}
```

### Sample 16: `9be1d33e17a0048a`

| Field | Value |
|---|---|
| SHA-256 | `9be1d33e17a0048a7b145cdc604e60048dc8bc26decd065ec3b5404a58bce9ef` |
| Family label | `Worm.Virut` |
| File name | `studiomdl.exe` |
| File type | `exe` |
| First seen | `2026-07-26 00:23:38` |
| Reporter | `JaffaCakes118` |
| Tags | `exe, Worm.Virut` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c41d08dccbffc2447d518b80726303ce` |
| SHA-1 | `de31dada1dcffe49288518afb66c321ee2a96263` |
| SHA-256 | `9be1d33e17a0048a7b145cdc604e60048dc8bc26decd065ec3b5404a58bce9ef` |
| SHA3-384 | `dc1dd05bb58c064445400589d5df7a8524c86423d67d6ae1fbc962dbb7bfec25773fa1f8e0f464d6267b4c1e8094ada2` |
| IMPHASH | `60d4babbb56c8e3577a277a2e561f73c` |
| TLSH | `T12DE3D02572E080F1D1AE01F425E95F7BDF3CE67241359A93DF98E9962E24CE0E12734A` |
| SSDEEP | `3072:JLXIQ7qz1YneW+pzYMvfXjuek5oN4Oh+UyBsEN:JLxoWUYMvfzu5issE` |

#### Technical Assessment

- The sample is tracked as `Worm.Virut` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Worm_Virut_016_9be1d33e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9be1d33e17a0048a7b145cdc604e60048dc8bc26decd065ec3b5404a58bce9ef"
    family = "Worm.Virut"
    file_name = "studiomdl.exe"
    file_type = "exe"
    first_seen = "2026-07-26 00:23:38"
  condition:
    hash.sha256(0, filesize) == "9be1d33e17a0048a7b145cdc604e60048dc8bc26decd065ec3b5404a58bce9ef"
}
```

### Sample 17: `977399df67a510fd`

| Field | Value |
|---|---|
| SHA-256 | `977399df67a510fdb6fb6f9eb7a63a5bc8a178e0dd6cd6321c02b68c94681cef` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-26 00:17:15` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9178cbc7e2eae63e8a491fff565d6272` |
| SHA-1 | `4a2c8e355fccffaa60869e4e6e4cf0bc55ff0aa9` |
| SHA-256 | `977399df67a510fdb6fb6f9eb7a63a5bc8a178e0dd6cd6321c02b68c94681cef` |
| SHA3-384 | `4f81573383017c08ababc848d5c8e7b3c40534353e300e3e420048365a7514c3521ab813ba2887125b468c827d7bf8a6` |
| TLSH | `T1AFC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:h8vCB+25j6es8Rb9FYpMSUpi+20qUpi+20YQX:h8l25Jtd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_977399df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "977399df67a510fdb6fb6f9eb7a63a5bc8a178e0dd6cd6321c02b68c94681cef"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-26 00:17:15"
  condition:
    hash.sha256(0, filesize) == "977399df67a510fdb6fb6f9eb7a63a5bc8a178e0dd6cd6321c02b68c94681cef"
}
```

### Sample 18: `8fc661e3c83b3108`

| Field | Value |
|---|---|
| SHA-256 | `8fc661e3c83b3108e1281d1270c26fcfe19038916ee7f14142880a6807416343` |
| Family label | `unknown` |
| File name | `8fc661e3c83b3108e1281d1270c26fcfe19038916ee7f14142880a6807416343` |
| File type | `sh` |
| First seen | `2026-07-26 00:00:47` |
| Reporter | `anonymous` |
| Tags | `cowrie, hermes-noc, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3d9860e56afe4138d644068b2e275a7` |
| SHA-1 | `88f7eaf50f58205d0f50f7eda50b1f21c037b5d3` |
| SHA-256 | `8fc661e3c83b3108e1281d1270c26fcfe19038916ee7f14142880a6807416343` |
| SHA3-384 | `fcf3af2c739b6bfb35690cbb863caa479db3c99364142a8ef5d01d9b8131cafb4c0158d22db9a5d7f9a7b3171d72ad01` |
| TLSH | `T16B3141DA09655E391217CAEE73723588B14CC1F72C9BC7E4ED0C0EAE86589CD7291F85` |
| SSDEEP | `24:gWeFFKDkDwVXhyFG2TJDe1Ysv82j0PBXxi8Q8hFK25Evuc0v:ghv2yw2TJDe1rv8y8Q8hF5rv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_8fc661e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fc661e3c83b3108e1281d1270c26fcfe19038916ee7f14142880a6807416343"
    family = "unknown"
    file_name = "8fc661e3c83b3108e1281d1270c26fcfe19038916ee7f14142880a6807416343"
    file_type = "sh"
    first_seen = "2026-07-26 00:00:47"
  condition:
    hash.sha256(0, filesize) == "8fc661e3c83b3108e1281d1270c26fcfe19038916ee7f14142880a6807416343"
}
```

### Sample 19: `62ac78326c0ebec7`

| Field | Value |
|---|---|
| SHA-256 | `62ac78326c0ebec72a44b0037290c5b221c75a6cf1a7281d2795691581f67058` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-26 00:00:11` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remus, e3aaa940c8c30f0571cc42a6e9260f60, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16fa9ffcb7431cbcd23d636718770ee4` |
| SHA-1 | `c822be1598310509a54fc03602eaddd1524f5133` |
| SHA-256 | `62ac78326c0ebec72a44b0037290c5b221c75a6cf1a7281d2795691581f67058` |
| SHA3-384 | `3cda3add762e569ac604de41f3f55755936c46c23734824b8805f95120286c62a5a0f63344da45550c25ecff9233e163` |
| IMPHASH | `71b008ad892c449add994b5e45fffabc` |
| TLSH | `T174969D15A3E0F2FCD6268174CA964232F6B574CD0763AACB0255D2152F37ADC6E3AF21` |
| SSDEEP | `24576:EY6TYOe2pP1y2DjTHcmQhPT+mP82giM7Ruof/CbcyIQ:EY6TYOEmQB+mmFbCgG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_62ac7832
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62ac78326c0ebec72a44b0037290c5b221c75a6cf1a7281d2795691581f67058"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 00:00:11"
  condition:
    hash.sha256(0, filesize) == "62ac78326c0ebec72a44b0037290c5b221c75a6cf1a7281d2795691581f67058"
}
```

### Sample 20: `c97311cbfd923b18`

| Field | Value |
|---|---|
| SHA-256 | `c97311cbfd923b181a76dbc92ff029e2dd33870458bc24c73be9d5074f388e66` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-25 23:52:33` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5486e84151a82e8cc42624e85ff9fc6f` |
| SHA-1 | `de632e92a37155fce6f841d2b1a6afbeab46be3a` |
| SHA-256 | `c97311cbfd923b181a76dbc92ff029e2dd33870458bc24c73be9d5074f388e66` |
| SHA3-384 | `5d828523db9ffaf10ed6e133009dc7b13fa8ecfd5463354f3f41d924a1d8dc09446d0e1cc440b8f46d240d0371a49cd4` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T19FE63308E6E402EFEAE2813DBDD26167E9A434624B71C55F1B8443B6BE573E04A3D713` |
| SSDEEP | `393216:i1E9jZcMwYemsvaPIcSF4XMCHWUjXKcuI3/PGTAI:iuJ5bemLSF4XMb8XnH/O7` |
| ICON-DHASH | `30f8fc9ccce4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_c97311cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c97311cbfd923b181a76dbc92ff029e2dd33870458bc24c73be9d5074f388e66"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 23:52:33"
  condition:
    hash.sha256(0, filesize) == "c97311cbfd923b181a76dbc92ff029e2dd33870458bc24c73be9d5074f388e66"
}
```

### Sample 21: `170175f699d31ba1`

| Field | Value |
|---|---|
| SHA-256 | `170175f699d31ba16e1def49684a8b37034863a045a6ab9910e91dd568049b9b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 23:29:14` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d1f898379640ff3b9d61d256ede418f` |
| SHA-1 | `81d2e79fad91ff217b57dd13f23600e365997bbf` |
| SHA-256 | `170175f699d31ba16e1def49684a8b37034863a045a6ab9910e91dd568049b9b` |
| SHA3-384 | `0930bd89e92e68bd1de81654bce008e43fb8475e6567ea4c11b7ea29eb28b738805283e520eb49555cb5453e3194dbbb` |
| IMPHASH | `08e71dc3a4ed4919ed4f88f99fab3457` |
| TLSH | `T119623B0BB8814036EAE14079477F422644BE6CB623C0F8DBF7F0698A5AB46E1F43156F` |
| SSDEEP | `192:D9BErjXgjo8P0UI+TemM2l1WFeI82IKUSfEzQyFJxTmv8U9cthBM9c+F:ou0IzWUoERav8U9cgzF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_170175f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "170175f699d31ba16e1def49684a8b37034863a045a6ab9910e91dd568049b9b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 23:29:14"
  condition:
    hash.sha256(0, filesize) == "170175f699d31ba16e1def49684a8b37034863a045a6ab9910e91dd568049b9b"
}
```

### Sample 22: `ad61a41009aaf87b`

| Field | Value |
|---|---|
| SHA-256 | `ad61a41009aaf87bc4c2a33f5d5ae7ed2491ef00d82bc024882b041af9334b90` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-25 23:20:03` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29733b8c7e51d9832bb50e9d491fb1db` |
| SHA-1 | `a3d90b6dac95a2f960321336aa4320e1da6e2dcf` |
| SHA-256 | `ad61a41009aaf87bc4c2a33f5d5ae7ed2491ef00d82bc024882b041af9334b90` |
| SHA3-384 | `d78ba04c55102be6b6a384eb67d2d5833a5d5e446652d5b85090db8313d666a24120c9e4d5d4e8436ff3b5e050528879` |
| TLSH | `T14601AFDAE2509920402A941D62D751A1B421C3C709CB1BA87F9C946DAB98E00B126F99` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohanYR28aTv+eeE/Y7:e9Qp+Msn0aTv+BEQ7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_ad61a410
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad61a41009aaf87bc4c2a33f5d5ae7ed2491ef00d82bc024882b041af9334b90"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-25 23:20:03"
  condition:
    hash.sha256(0, filesize) == "ad61a41009aaf87bc4c2a33f5d5ae7ed2491ef00d82bc024882b041af9334b90"
}
```

### Sample 23: `fd0466080f4a0836`

| Field | Value |
|---|---|
| SHA-256 | `fd0466080f4a0836beab8ddd824540dcf47a32e4f1cbc95274a455d18f3dfbf9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 23:03:31` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4bf72c31058da40e162ec2e1a567f14` |
| SHA-1 | `77c75c1b005d3f5a386deec95a671d529319b2f1` |
| SHA-256 | `fd0466080f4a0836beab8ddd824540dcf47a32e4f1cbc95274a455d18f3dfbf9` |
| SHA3-384 | `fd0b3d2a7cfb5888d16be2df1f87fb7691d7c3b44de246a02349b53f61689fd1cc46add42429e1942bbb81577b34b6f9` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T141624C0BA4818035EBF14474827F526644FEACB623C5F9DBF7E0648A4AB46E1F43206F` |
| SSDEEP | `192:AWAsGnjXgjk8LcRI+gRdjMBIfeF5oIV1BKUSfEzQLd1gJxTmv8U9cthN9ik:AFScSxferoFE+yav8U9cnX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_fd046608
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd0466080f4a0836beab8ddd824540dcf47a32e4f1cbc95274a455d18f3dfbf9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 23:03:31"
  condition:
    hash.sha256(0, filesize) == "fd0466080f4a0836beab8ddd824540dcf47a32e4f1cbc95274a455d18f3dfbf9"
}
```

### Sample 24: `925278940fe96bc0`

| Field | Value |
|---|---|
| SHA-256 | `925278940fe96bc04d406ebdffa8e3431b64e76ff0d22b23b53b47d5cd360200` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-25 22:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65039b94fe764e2d6f2d679c16fe0b64` |
| SHA-1 | `953cf0e5c83ba87b7a09e669b9eaacebce66ed2e` |
| SHA-256 | `925278940fe96bc04d406ebdffa8e3431b64e76ff0d22b23b53b47d5cd360200` |
| SHA3-384 | `da06c01ca94f04bab3bf8d01d0f947a9b7f6997b82996909af5ddac5d3eb70c3f063dbea9710133f2b20029f5dd233f9` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D9E633986ED011DFF972D13DEDA155E0D579BCA28732CAAB8BA823D12E131A00C3D757` |
| SSDEEP | `393216:bmUvs0akwI/h4jRpntE71sqPBXMCHWUjXycuI3/PGTAI:bmUke4jRpn2PBXMb8XPH/O7` |
| ICON-DHASH | `71f0d4d8c8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_92527894
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "925278940fe96bc04d406ebdffa8e3431b64e76ff0d22b23b53b47d5cd360200"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 22:52:31"
  condition:
    hash.sha256(0, filesize) == "925278940fe96bc04d406ebdffa8e3431b64e76ff0d22b23b53b47d5cd360200"
}
```

### Sample 25: `58e1678501dae58d`

| Field | Value |
|---|---|
| SHA-256 | `58e1678501dae58d824c8e305be61ee55f642af2e0c36259cf14501cf58c9687` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 22:26:03` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac6e007de84a362b97f5614d4725d534` |
| SHA-1 | `ca3414eddd6c823a58bb6c315009a61eca0c23d3` |
| SHA-256 | `58e1678501dae58d824c8e305be61ee55f642af2e0c36259cf14501cf58c9687` |
| SHA3-384 | `5d494445479c2373308fd431945a5d25d3db7abf49b7d6089df68d91ec45b0cd5b09b0a51bcc0717dceb711da3a04d48` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T10A624C0BB4808035EBE144B4827F526645BDADB623C4F9CBF7E0648A5AB46E1F43116F` |
| SSDEEP | `192:AWpsGnjXgjk8LMRI+wBdzMRJFeIFFBKUSfEzQbd1gJxTmv8U9cthW39ik:AoSMygUlEOyav8U9cWNX` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_025_58e16785
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58e1678501dae58d824c8e305be61ee55f642af2e0c36259cf14501cf58c9687"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 22:26:03"
  condition:
    hash.sha256(0, filesize) == "58e1678501dae58d824c8e305be61ee55f642af2e0c36259cf14501cf58c9687"
}
```

### Sample 26: `56c44ee6a052c967`

| Field | Value |
|---|---|
| SHA-256 | `56c44ee6a052c9679d8dd05d2338bf2c2a0a2e0ce0242bf5472e870768ab7466` |
| Family label | `NanoCore` |
| File name | `E31AB3ECA717E815F942F242E1CCCC09.exe` |
| File type | `exe` |
| First seen | `2026-07-25 22:25:04` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e31ab3eca717e815f942f242e1cccc09` |
| SHA-1 | `0c13d9cb3704eb6820a3043f5931b39853347824` |
| SHA-256 | `56c44ee6a052c9679d8dd05d2338bf2c2a0a2e0ce0242bf5472e870768ab7466` |
| SHA3-384 | `cd152d35f0115f4dfe7adc1450864797e061171f26c98ca9fa13987e0323d346385db895765efcbbad293be751f63d44` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1FC14CF1677A84A2FE2DE85B9611212129379C2E3A8D3F3DF2CD451B75F267E14A0B0D3` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5VRytPfyPxvc3sNr6:MLV6BtpmkOAPKLNr6` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_026_56c44ee6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56c44ee6a052c9679d8dd05d2338bf2c2a0a2e0ce0242bf5472e870768ab7466"
    family = "NanoCore"
    file_name = "E31AB3ECA717E815F942F242E1CCCC09.exe"
    file_type = "exe"
    first_seen = "2026-07-25 22:25:04"
  condition:
    hash.sha256(0, filesize) == "56c44ee6a052c9679d8dd05d2338bf2c2a0a2e0ce0242bf5472e870768ab7466"
}
```

### Sample 27: `55035e8193aa4548`

| Field | Value |
|---|---|
| SHA-256 | `55035e8193aa4548ea63d72c51744739cb51b1fb3e19a40907233608c62473c1` |
| Family label | `unknown` |
| File name | `55035e8193aa4548ea63d72c51744739cb51b1fb3e19a40907233608c62473c1` |
| File type | `sh` |
| First seen | `2026-07-25 22:16:56` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90262af511f7d47e973977cc3997f46b` |
| SHA-1 | `4d5b5e6514031b70af9f43fe77bf5352df47f0dd` |
| SHA-256 | `55035e8193aa4548ea63d72c51744739cb51b1fb3e19a40907233608c62473c1` |
| SHA3-384 | `c5407afd6e17f819bf3076b9213bf2cc8b16ab92480b16c2a25b9b4c38303a6ac6d4d6564036652ba27f5cf7476c18c4` |
| TLSH | `T1DC1253E1FCB0ED38378EC03D655E9596384B142F08593D14B58FE4196F6C228A3B97BA` |
| SSDEEP | `192:Q5HBE7lI7lR9vvPboG5LTGh+oKq801l0z46UOaWF+HKm7X+tBTLG/znZiQ:Q157RPR5LK01a0MHUF+F7OtVLg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_55035e81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55035e8193aa4548ea63d72c51744739cb51b1fb3e19a40907233608c62473c1"
    family = "unknown"
    file_name = "55035e8193aa4548ea63d72c51744739cb51b1fb3e19a40907233608c62473c1"
    file_type = "sh"
    first_seen = "2026-07-25 22:16:56"
  condition:
    hash.sha256(0, filesize) == "55035e8193aa4548ea63d72c51744739cb51b1fb3e19a40907233608c62473c1"
}
```

### Sample 28: `1a5fc161c39e639f`

| Field | Value |
|---|---|
| SHA-256 | `1a5fc161c39e639f6c053ad79040e2f18827c0d8df3e39b5202a3920fcc9b4b9` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 22:16:14` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e164b983245b5c4a83f912ae694f94a` |
| SHA-1 | `d5a0a87dc48e302eb622c66664e6c00cdf9cb1e9` |
| SHA-256 | `1a5fc161c39e639f6c053ad79040e2f18827c0d8df3e39b5202a3920fcc9b4b9` |
| SHA3-384 | `af94fc5f8675a2aada54da3ab45e3a76641747cf092adf4133d9769c9eb1be230989a50dcc649f0660fa4d00b4e4b7da` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T10122381F7E890231E39448B4157A864F553D1233A383B3EBF773E19D0B953498840AAF` |
| SSDEEP | `96:U2gwdfnoeYz/J4hrt6KBWdCZaDbFx+ZQKl6ETZjH/CPFJxGE9mZ2FFhxC7tCEe/o:mwoNScKB6x+eKlKPFJxTEZmFhSer` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_028_1a5fc161
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a5fc161c39e639f6c053ad79040e2f18827c0d8df3e39b5202a3920fcc9b4b9"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 22:16:14"
  condition:
    hash.sha256(0, filesize) == "1a5fc161c39e639f6c053ad79040e2f18827c0d8df3e39b5202a3920fcc9b4b9"
}
```

### Sample 29: `e69cad1fc4f37b15`

| Field | Value |
|---|---|
| SHA-256 | `e69cad1fc4f37b152dec7c2c8c80b9516ff10a28a04041fdeb0294bd8f0dbf78` |
| Family label | `unknown` |
| File name | `e69cad1fc4f37b152dec7c2c8c80b9516ff10a28a04041fdeb0294bd8f0dbf78` |
| File type | `sh` |
| First seen | `2026-07-25 22:06:59` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `351daac6ec97ffddb26b8e2d86360377` |
| SHA-1 | `2483acd76189628741372b41a3f0c7c354bc32ec` |
| SHA-256 | `e69cad1fc4f37b152dec7c2c8c80b9516ff10a28a04041fdeb0294bd8f0dbf78` |
| SHA3-384 | `0d27e34bd466a1359928213041b9036f1fbfc6563bf89ebc511895f4d5ed8a1038f83704ad3771e3b876576ece8de9e5` |
| TLSH | `T1132276E1F8A0DD38378DC03EA44E9581354F142B05492C68B59FE4646F7D6A4A3BC7FA` |
| SSDEEP | `192:8WEPNWcD9Ck0hXmtnTtxLKkT+2Kq801HzZ69UkOaWF+HKmciGSOSo2aH9AZIkw:8xP8ClXtTtxL3yzItbkUF+FciG1S4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_e69cad1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e69cad1fc4f37b152dec7c2c8c80b9516ff10a28a04041fdeb0294bd8f0dbf78"
    family = "unknown"
    file_name = "e69cad1fc4f37b152dec7c2c8c80b9516ff10a28a04041fdeb0294bd8f0dbf78"
    file_type = "sh"
    first_seen = "2026-07-25 22:06:59"
  condition:
    hash.sha256(0, filesize) == "e69cad1fc4f37b152dec7c2c8c80b9516ff10a28a04041fdeb0294bd8f0dbf78"
}
```

### Sample 30: `f1f22912b7a9999e`

| Field | Value |
|---|---|
| SHA-256 | `f1f22912b7a9999e3df0c2deea7158c9b64a0bd5370710f7cac9e745683194ff` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-25 21:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e0559341981ea975fe99657f4f417e2` |
| SHA-1 | `6d68b60d681b7984a1517927362901a3fa56ba2b` |
| SHA-256 | `f1f22912b7a9999e3df0c2deea7158c9b64a0bd5370710f7cac9e745683194ff` |
| SHA3-384 | `6683c1f702b9cb375e9305b00c2a2ececd94e2154b5768b44c26edb6e9cafb03a8fbaf3fd2a62a8ef79dec3d2193460b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1BDE633989AD012FFF562923C9ED363E1E5E970274B73C69B1BC485E53D632E0093A247` |
| SSDEEP | `393216:5/erMWYkwgaA6f9NJpYU5XMCHWUjXtcuI3/PGTAI:5/eYUwk6YgXMb8XaH/O7` |
| ICON-DHASH | `407860c0dcf9f100` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_f1f22912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1f22912b7a9999e3df0c2deea7158c9b64a0bd5370710f7cac9e745683194ff"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 21:52:30"
  condition:
    hash.sha256(0, filesize) == "f1f22912b7a9999e3df0c2deea7158c9b64a0bd5370710f7cac9e745683194ff"
}
```

### Sample 31: `983755ac9112bdf7`

| Field | Value |
|---|---|
| SHA-256 | `983755ac9112bdf7487e53017fd2f14af59c0537bcad36ec302d92563636df70` |
| Family label | `unknown` |
| File name | `983755ac9112bdf7487e53017fd2f14af59c0537bcad36ec302d92563636df70` |
| File type | `elf` |
| First seen | `2026-07-25 21:36:44` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e0aa1397faa7da231133511d3b9f930` |
| SHA-1 | `f8ac99fb0ee95f82dbbeabc79793041b2abe77a2` |
| SHA-256 | `983755ac9112bdf7487e53017fd2f14af59c0537bcad36ec302d92563636df70` |
| SHA3-384 | `0235ae4c46bdc17aca52b2542bf29f5bc1d7227651a212fa41bc7803563d860dcd2ae3aa364c4937bb1d062ab761ec49` |
| TLSH | `T1E447DF77814238E9E5B98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ6:cqYUQuVDt0TZEl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_983755ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "983755ac9112bdf7487e53017fd2f14af59c0537bcad36ec302d92563636df70"
    family = "unknown"
    file_name = "983755ac9112bdf7487e53017fd2f14af59c0537bcad36ec302d92563636df70"
    file_type = "elf"
    first_seen = "2026-07-25 21:36:44"
  condition:
    hash.sha256(0, filesize) == "983755ac9112bdf7487e53017fd2f14af59c0537bcad36ec302d92563636df70"
}
```

### Sample 32: `2c8301d65528cc47`

| Field | Value |
|---|---|
| SHA-256 | `2c8301d65528cc47b1d99ceb850d39bfb4d5c90ca771b9ec483280e3be67dcd5` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-25 21:32:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `536fab297f29ea750594e251814f1085` |
| SHA-1 | `187adba06daf53bcf7e924a7cb07940de66b156b` |
| SHA-256 | `2c8301d65528cc47b1d99ceb850d39bfb4d5c90ca771b9ec483280e3be67dcd5` |
| SHA3-384 | `278bc1f6f3889b903dd45258bed2912026c230bf2a34359289d20be5092b1dea381db6097190a8f3819e9d78f2fac078` |
| TLSH | `T189137D595A953C259E89893B1D7E2F0CBDAA83E5300851DDBFCB3CF28C45A9CE21871D` |
| SSDEEP | `768:uVEJVIhtMH9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:MEJ2Mwco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_2c8301d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c8301d65528cc47b1d99ceb850d39bfb4d5c90ca771b9ec483280e3be67dcd5"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-25 21:32:27"
  condition:
    hash.sha256(0, filesize) == "2c8301d65528cc47b1d99ceb850d39bfb4d5c90ca771b9ec483280e3be67dcd5"
}
```

### Sample 33: `620ba6ad0d361d38`

| Field | Value |
|---|---|
| SHA-256 | `620ba6ad0d361d38e0af1f8f472f37b1a8a58a2fc13f278be085b5ed319444a9` |
| Family label | `unknown` |
| File name | `620ba6ad0d361d38e0af1f8f472f37b1a8a58a2fc13f278be085b5ed319444a9.bin` |
| File type | `unknown` |
| First seen | `2026-07-25 21:25:18` |
| Reporter | `whack` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa79735a117ed7f163f3a389016ff749` |
| SHA-256 | `620ba6ad0d361d38e0af1f8f472f37b1a8a58a2fc13f278be085b5ed319444a9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_620ba6ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "620ba6ad0d361d38e0af1f8f472f37b1a8a58a2fc13f278be085b5ed319444a9"
    family = "unknown"
    file_name = "620ba6ad0d361d38e0af1f8f472f37b1a8a58a2fc13f278be085b5ed319444a9.bin"
    file_type = "unknown"
    first_seen = "2026-07-25 21:25:18"
  condition:
    hash.sha256(0, filesize) == "620ba6ad0d361d38e0af1f8f472f37b1a8a58a2fc13f278be085b5ed319444a9"
}
```

### Sample 34: `5d6baae899049b43`

| Field | Value |
|---|---|
| SHA-256 | `5d6baae899049b430146689556c6b7e9668996b5e64449ef733ac061cf61451b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 21:21:18` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95e8cdb73cd2ae5ae5cf67c0b1df7705` |
| SHA-1 | `ff43ef2c451a968cd2b9b02fe6abacfc43683a07` |
| SHA-256 | `5d6baae899049b430146689556c6b7e9668996b5e64449ef733ac061cf61451b` |
| SHA3-384 | `4ca7e8e2a0e062454d44894764c9e1be73505ffe4b6862ea064d9a1f80cef2957459771605c786f36516274033ab413c` |
| IMPHASH | `08e71dc3a4ed4919ed4f88f99fab3457` |
| TLSH | `T19F623C0BA8818036EAE14479537F422645BE7CB623C0F8DBF7F0698A59B46E1F43156F` |
| SSDEEP | `192:J9BErjXgjo8PEUI+jum8mBzfxmF5oIsGIKUSfEzQiFJxTmv8U9cthG9c+F:SuEIxfxmroIEBav8U9c4zF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_5d6baae8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d6baae899049b430146689556c6b7e9668996b5e64449ef733ac061cf61451b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 21:21:18"
  condition:
    hash.sha256(0, filesize) == "5d6baae899049b430146689556c6b7e9668996b5e64449ef733ac061cf61451b"
}
```

### Sample 35: `26be0774f5483770`

| Field | Value |
|---|---|
| SHA-256 | `26be0774f54837706f579d6e75cc8ae2262ec54aeee2d5944cb2cd3308ffe1f3` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-25 21:16:20` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `638375618fc15b94d2e3527509e7261c` |
| SHA-1 | `9e394d3ca661807b3194e1f2502fa0bf4fc5c111` |
| SHA-256 | `26be0774f54837706f579d6e75cc8ae2262ec54aeee2d5944cb2cd3308ffe1f3` |
| SHA3-384 | `eeb9a78249ac74162ca03e70d41ac053092b39f980d24fcfe5d3007e6ecf580b689093b6adbac61d72f92c94d3087b0c` |
| TLSH | `T159C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:LY8vCB+25j6es8R49FYpMSUpi+20qUpi+20YQX:LY8l25JOd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_26be0774
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26be0774f54837706f579d6e75cc8ae2262ec54aeee2d5944cb2cd3308ffe1f3"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-25 21:16:20"
  condition:
    hash.sha256(0, filesize) == "26be0774f54837706f579d6e75cc8ae2262ec54aeee2d5944cb2cd3308ffe1f3"
}
```

### Sample 36: `343e294624c93543`

| Field | Value |
|---|---|
| SHA-256 | `343e294624c935431cf4ec28cf998a7e0d459c9b41361d539f221406fee5a16d` |
| Family label | `WannaCry` |
| File name | `343e294624c935431cf4ec28cf998a7e0d459c9b41361d539f221406fee5a16d` |
| File type | `exe` |
| First seen | `2026-07-25 21:15:16` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48eaace18c29524535a84ea5bc6e71cb` |
| SHA-1 | `b0252b35aa23ba91066b7055af3e94947a1f25ba` |
| SHA-256 | `343e294624c935431cf4ec28cf998a7e0d459c9b41361d539f221406fee5a16d` |
| SHA3-384 | `9e44e54fbd8cdd609717c417a3886414e68f1acdf9eb00600174fe8f6b29266c4f0104898e6b1152c70b8b2685d4701f` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1FA361259336C81BCC11B523494B34D26E7B3BC5A227D970F8B948B6A0E13790BB78B57` |
| SSDEEP | `12288:jbLgmwbLgPluxQhMbaIMu7L5NVErCA4z2g6rTcbckPU82900Ve7zw+K+D:jbLg1bLgdeQhfdmMSirYbcMNgef0` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_036_343e2946
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "343e294624c935431cf4ec28cf998a7e0d459c9b41361d539f221406fee5a16d"
    family = "WannaCry"
    file_name = "343e294624c935431cf4ec28cf998a7e0d459c9b41361d539f221406fee5a16d"
    file_type = "exe"
    first_seen = "2026-07-25 21:15:16"
  condition:
    hash.sha256(0, filesize) == "343e294624c935431cf4ec28cf998a7e0d459c9b41361d539f221406fee5a16d"
}
```

### Sample 37: `9ca662bf15428a6d`

| Field | Value |
|---|---|
| SHA-256 | `9ca662bf15428a6d68ce134206cdaac5a4f5146ea6e8d3637a33627487106be3` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 21:08:33` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e55393f22a1baefe9348c497f82270ff` |
| SHA-1 | `a1803603524108ad1a4752c5b991aef2bda7c602` |
| SHA-256 | `9ca662bf15428a6d68ce134206cdaac5a4f5146ea6e8d3637a33627487106be3` |
| SHA3-384 | `4dc2efb1779a17480f4111ba4dfa989f5e9f8a6efc8d6c9648f3108ed3b26dfc35563740b739163b94fcbeb1cb761a99` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T179623C0AB4808035EBE14474827F526645BDADB623C4F9CBF7E0648A5AB46E1F83116F` |
| SSDEEP | `192:AW9sGnjXgjk8LMRI+wBdzMRJFeIFFBKUSfEzQbd1gJxTmv8U9cthT9ik:AMSMygUlEOyav8U9c5X` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_037_9ca662bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ca662bf15428a6d68ce134206cdaac5a4f5146ea6e8d3637a33627487106be3"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 21:08:33"
  condition:
    hash.sha256(0, filesize) == "9ca662bf15428a6d68ce134206cdaac5a4f5146ea6e8d3637a33627487106be3"
}
```

### Sample 38: `d1515ff3e467c83d`

| Field | Value |
|---|---|
| SHA-256 | `d1515ff3e467c83dff345353f38acc27ac1788964a7b5a320fb2f3b1c0eb63a6` |
| Family label | `unknown` |
| File name | `d1515ff3e467c83dff345353f38acc27ac1788964a7b5a320fb2f3b1c0eb63a6` |
| File type | `unknown` |
| First seen | `2026-07-25 21:06:43` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de43dce2be14532ba86a530b150e621e` |
| SHA-256 | `d1515ff3e467c83dff345353f38acc27ac1788964a7b5a320fb2f3b1c0eb63a6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_d1515ff3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1515ff3e467c83dff345353f38acc27ac1788964a7b5a320fb2f3b1c0eb63a6"
    family = "unknown"
    file_name = "d1515ff3e467c83dff345353f38acc27ac1788964a7b5a320fb2f3b1c0eb63a6"
    file_type = "unknown"
    first_seen = "2026-07-25 21:06:43"
  condition:
    hash.sha256(0, filesize) == "d1515ff3e467c83dff345353f38acc27ac1788964a7b5a320fb2f3b1c0eb63a6"
}
```

### Sample 39: `5486a8ff6e41a7c3`

| Field | Value |
|---|---|
| SHA-256 | `5486a8ff6e41a7c383aa88eed922b79361344fd0d41b8302c929ebd9600a7531` |
| Family label | `unknown` |
| File name | `5486a8ff6e41a7c383aa88eed922b79361344fd0d41b8302c929ebd9600a7531` |
| File type | `sh` |
| First seen | `2026-07-25 21:06:02` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `700a8b7e8ddbaf6e41ca3f2fd40f6289` |
| SHA-1 | `22e8d4f1c8139d93c94fc266ee4ce71f37ef272a` |
| SHA-256 | `5486a8ff6e41a7c383aa88eed922b79361344fd0d41b8302c929ebd9600a7531` |
| SHA3-384 | `a7f1bb02a6f8927d8737669076a2e7b46db059f51e0c222d757015d4c9abbbb1a49c9e10d0e2cdaac2c1113b4b4dd606` |
| TLSH | `T17E410FE0F479CC38B688E039A48F11683C96546F58997E18BDDEB83C5B5C50C20BE3B9` |
| SSDEEP | `48:nN4YAKdjO5f8XVyOWyBZu6Y5oAl4KxY5oAlXKG:nqYACO8XVyOjBZu6z9KxzdG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_5486a8ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5486a8ff6e41a7c383aa88eed922b79361344fd0d41b8302c929ebd9600a7531"
    family = "unknown"
    file_name = "5486a8ff6e41a7c383aa88eed922b79361344fd0d41b8302c929ebd9600a7531"
    file_type = "sh"
    first_seen = "2026-07-25 21:06:02"
  condition:
    hash.sha256(0, filesize) == "5486a8ff6e41a7c383aa88eed922b79361344fd0d41b8302c929ebd9600a7531"
}
```

### Sample 40: `6cd950c1729a136b`

| Field | Value |
|---|---|
| SHA-256 | `6cd950c1729a136be666fe0f23a9de400124c0e301a03b7f0095f8b41576bb11` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-25 20:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6aeedcaed66e73c88766f39b36b033e` |
| SHA-1 | `14f03d3697922304f19d25e885cba9eee5934e39` |
| SHA-256 | `6cd950c1729a136be666fe0f23a9de400124c0e301a03b7f0095f8b41576bb11` |
| SHA3-384 | `6e4973da0b4f2a34ee0855acc4ad75b62fd4630e76bdfd5f644babef56651eac466d0be1ad88870b90e4162afd94afaf` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T191E633185AE041FEE6A7C13C9E928866E195B4B22732C5CB4BFCC7656D6B2F0493C317` |
| SSDEEP | `393216:hk2XXX7mMYM0rz1lkinG7eUjHFoXMCHWUjXFcuI3/PGTAI:hkvrz1mE8jHFoXMb8XyH/O7` |
| ICON-DHASH | `30f8fcdccce4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_6cd950c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cd950c1729a136be666fe0f23a9de400124c0e301a03b7f0095f8b41576bb11"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 20:52:32"
  condition:
    hash.sha256(0, filesize) == "6cd950c1729a136be666fe0f23a9de400124c0e301a03b7f0095f8b41576bb11"
}
```

### Sample 41: `6ca9586045248392`

| Field | Value |
|---|---|
| SHA-256 | `6ca95860452483923f168b85287051f7914f8d30c608147542237262a603ffb6` |
| Family label | `ValleyRAT` |
| File name | `5D5477120A75161AD3ED0023C36F3284.exe` |
| File type | `exe` |
| First seen | `2026-07-25 20:50:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d5477120a75161ad3ed0023c36f3284` |
| SHA-1 | `c8ae9e00ad2f9febb8cb1eb6a47b75f8e716890c` |
| SHA-256 | `6ca95860452483923f168b85287051f7914f8d30c608147542237262a603ffb6` |
| SHA3-384 | `75c80c470cfcc9a5b65409ff7ab8fc5c352124f469d8754b1b0bd20a0a75296e4b71599af5cb32969446cf072fe43613` |
| IMPHASH | `40ab50289f7ef5fae60801f88d4541fc` |
| TLSH | `T1E5B5E123B2CBE53EE05D0B3B4572A25494FBAB216523BD579BE4849CCF250602E3E747` |
| SSDEEP | `49152:z+MRvHInhFxqZ2JY467MZ2Z9ftchfudg87dqn7iMb:zrcxqEJp+MYchXqdnMb` |
| ICON-DHASH | `71f096a2a296c4c1` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_041_6ca95860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ca95860452483923f168b85287051f7914f8d30c608147542237262a603ffb6"
    family = "ValleyRAT"
    file_name = "5D5477120A75161AD3ED0023C36F3284.exe"
    file_type = "exe"
    first_seen = "2026-07-25 20:50:06"
  condition:
    hash.sha256(0, filesize) == "6ca95860452483923f168b85287051f7914f8d30c608147542237262a603ffb6"
}
```

### Sample 42: `afc5fa1343a544b6`

| Field | Value |
|---|---|
| SHA-256 | `afc5fa1343a544b6a918ed331efc7ba9ee88c045bc6fd8fb9ac662107c552295` |
| Family label | `unknown` |
| File name | `Sheldon.7z` |
| File type | `7z` |
| First seen | `2026-07-25 20:03:08` |
| Reporter | `anonymous` |
| Tags | `7z` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cbfee3655a0e56275db5a501e560459` |
| SHA-1 | `93932d02a11f7a1214fcded019abd64163f9fd9f` |
| SHA-256 | `afc5fa1343a544b6a918ed331efc7ba9ee88c045bc6fd8fb9ac662107c552295` |
| SHA3-384 | `9ae27454012156cb1ba7c927dce6540701cf2e14be46f0fd04334cbcd92544fb92509010ae568c2c79987dc61db1dd17` |
| TLSH | `T15DC633A44C61A812F9E0DC36CD735DF6DAEB4DD23654FE6E40ABE3AA431206F0199C17` |
| SSDEEP | `196608:wOP3lnHuzyrYyonpZJk6fTuHjTWet1hOy7U/X4c1lkj3oYft81bqLP6qIvmjlbGn:xlnHuzpnWRHnZjt7mXZ1l+Ft81bqLP6l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_afc5fa13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afc5fa1343a544b6a918ed331efc7ba9ee88c045bc6fd8fb9ac662107c552295"
    family = "unknown"
    file_name = "Sheldon.7z"
    file_type = "7z"
    first_seen = "2026-07-25 20:03:08"
  condition:
    hash.sha256(0, filesize) == "afc5fa1343a544b6a918ed331efc7ba9ee88c045bc6fd8fb9ac662107c552295"
}
```

### Sample 43: `ca7fa72c6642d5cb`

| Field | Value |
|---|---|
| SHA-256 | `ca7fa72c6642d5cb83ea60ce873964eff752e6ad66aac959da25d722ce19256e` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-25 19:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17ac3a4c603191a68d14a046245ba522` |
| SHA-1 | `514dc84190643116c35edba01dcf2eee6c908fcd` |
| SHA-256 | `ca7fa72c6642d5cb83ea60ce873964eff752e6ad66aac959da25d722ce19256e` |
| SHA3-384 | `af41b0140818f0a6adc497485d95437323e8332180729e4d5fd9997aeffd0e58cabb75b0e652fbf9696f5bab1369ba6d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T190E63388A8D105EEDDA7513CFEF26841F8A838791F36C5CF17405764AD2B1F09A3D29A` |
| SSDEEP | `393216:WMaY0ydC3a09+yWnmlT8kW3ryCtiXMCHWUjXucuI3/PGTAI:W3rjK0zs3ryvXMb8XDH/O7` |
| ICON-DHASH | `30f1f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_ca7fa72c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca7fa72c6642d5cb83ea60ce873964eff752e6ad66aac959da25d722ce19256e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 19:52:31"
  condition:
    hash.sha256(0, filesize) == "ca7fa72c6642d5cb83ea60ce873964eff752e6ad66aac959da25d722ce19256e"
}
```

### Sample 44: `bcee095afc805eb5`

| Field | Value |
|---|---|
| SHA-256 | `bcee095afc805eb5f164059598f97b5b01d1015afb496b19c640a4d01766765c` |
| Family label | `unknown` |
| File name | `0e649edddaf-12.msi` |
| File type | `msi` |
| First seen | `2026-07-25 19:50:30` |
| Reporter | `skocherhan` |
| Tags | `aethernetworking-cc, cehamilton-com, microlsireqjn-com, msi, pop-aethernetworking-cc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `331dc3004c365938ff7c66177e36a25f` |
| SHA-1 | `569a5b25daa810e7b8f8586ca2401a3f98a7e4c0` |
| SHA-256 | `bcee095afc805eb5f164059598f97b5b01d1015afb496b19c640a4d01766765c` |
| SHA3-384 | `ff4e850810cedf5dad8e37642ad98c4212d2e037f3807894cf662fee123a113270ae6c9ce65f94421db39c2b48b0baf2` |
| TLSH | `T1205651626C4F138ED0DF0536FB13E0B2967F98B3D78A52DA848B543E35990EE540EA74` |
| SSDEEP | `49152:2pMOxyuQz5DYGZMte29mqkdFPRo0V6Yz2mbm1XIoj1W9bPjvhPlYt47Vhl5j5cQI:2pH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_bcee095a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcee095afc805eb5f164059598f97b5b01d1015afb496b19c640a4d01766765c"
    family = "unknown"
    file_name = "0e649edddaf-12.msi"
    file_type = "msi"
    first_seen = "2026-07-25 19:50:30"
  condition:
    hash.sha256(0, filesize) == "bcee095afc805eb5f164059598f97b5b01d1015afb496b19c640a4d01766765c"
}
```

### Sample 45: `3100f5931301a796`

| Field | Value |
|---|---|
| SHA-256 | `3100f5931301a7968b274bc718c8363fe8b73cab7b997cf4ae161e39d06197ef` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-25 19:47:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54ce2b38d32b12708dc5b4f00430f284` |
| SHA-1 | `4022c1f0fa37d2ef0775a5cb6a411b27321d657c` |
| SHA-256 | `3100f5931301a7968b274bc718c8363fe8b73cab7b997cf4ae161e39d06197ef` |
| SHA3-384 | `e397157989c41faee818dbbfd37cda8a423fe158aae118568f87e755087a6b704162455b6353f6e5018e4be6e63002e0` |
| TLSH | `T1A2167C94ED0F3912F3C7E23CCF4A97E1761735A4E32390B279D2524DC59E9E4CAA2A11` |
| SSDEEP | `98304:Azb9UwGPrUaw8E1nUTpRtJ3gqQuUAmt+sFvz:0b9Uwza2yT4Nd77` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_3100f593
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3100f5931301a7968b274bc718c8363fe8b73cab7b997cf4ae161e39d06197ef"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-25 19:47:50"
  condition:
    hash.sha256(0, filesize) == "3100f5931301a7968b274bc718c8363fe8b73cab7b997cf4ae161e39d06197ef"
}
```

### Sample 46: `be24e3ff143568fc`

| Field | Value |
|---|---|
| SHA-256 | `be24e3ff143568fc82e42ed4aeee92e3f6f58c5fe3c5bb442cf4b998c90463d2` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-25 19:46:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7bd06aa7a2d38ea34c14eccbb4509ca` |
| SHA-1 | `b6fbcceda95dbb54494fa579e8e6ce6b614d4e70` |
| SHA-256 | `be24e3ff143568fc82e42ed4aeee92e3f6f58c5fe3c5bb442cf4b998c90463d2` |
| SHA3-384 | `b165a1acfadb817470ff8d77ff660b5c7d245649844125fb510ccd9209cff8fd28b283fdeb8fb80e3217b2952e434649` |
| TLSH | `T1E37533814CEF74B5F17C95B71435D09E2A4C9A146C6B3B42AE1B608C83BDA7075ECFA8` |
| SSDEEP | `49152:GMdGK1dku/5jm/DmE43BruAM7kjZwl2axtg6cYTOQw:GYjdkuxKDmN3BruhmC2Mw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_be24e3ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be24e3ff143568fc82e42ed4aeee92e3f6f58c5fe3c5bb442cf4b998c90463d2"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-25 19:46:28"
  condition:
    hash.sha256(0, filesize) == "be24e3ff143568fc82e42ed4aeee92e3f6f58c5fe3c5bb442cf4b998c90463d2"
}
```

### Sample 47: `0aa8796ec42231ee`

| Field | Value |
|---|---|
| SHA-256 | `0aa8796ec42231ee70586d3d48c7271bad38377c208fbbbfad578f6eef04313d` |
| Family label | `unknown` |
| File name | `Loader.7z` |
| File type | `7z` |
| First seen | `2026-07-25 19:46:13` |
| Reporter | `anonymous` |
| Tags | `7z` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc96309caf93421f63c646c5b94194d5` |
| SHA-1 | `b6de0cd902523e50da8c248935d83b1f31135835` |
| SHA-256 | `0aa8796ec42231ee70586d3d48c7271bad38377c208fbbbfad578f6eef04313d` |
| SHA3-384 | `8080369d5a3c23e2cf3c6458f20de273a81b148972f6b9d38c376ee8d039d2acabb9ff45d4b6739328197d93b8ccd8ee` |
| TLSH | `T1F2B6332345E5CF3F9F2E2C1C964E465D75BA8A9FB091D320CB6A9A4624DDA0CD4321FC` |
| SSDEEP | `196608:JIs1tRMNHL5V5yn3E6Ywo8aQZeolG9+5xru8xwGxtNrHPHBIhpI93hGAwIjZ:D7GHFan06Yr8hUQGMru8t98C3hJw2Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_0aa8796e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0aa8796ec42231ee70586d3d48c7271bad38377c208fbbbfad578f6eef04313d"
    family = "unknown"
    file_name = "Loader.7z"
    file_type = "7z"
    first_seen = "2026-07-25 19:46:13"
  condition:
    hash.sha256(0, filesize) == "0aa8796ec42231ee70586d3d48c7271bad38377c208fbbbfad578f6eef04313d"
}
```

### Sample 48: `57de376767a78229`

| Field | Value |
|---|---|
| SHA-256 | `57de376767a78229701434a2efe5d6410132b208417e8d9fc0891405dfc7be09` |
| Family label | `unknown` |
| File name | `riscv` |
| File type | `elf` |
| First seen | `2026-07-25 19:43:20` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ef5af0e6e1118cac43b9228b03f0f75` |
| SHA-1 | `6ef59381a18edcbb4f6a3214ce8c889cf0429486` |
| SHA-256 | `57de376767a78229701434a2efe5d6410132b208417e8d9fc0891405dfc7be09` |
| SHA3-384 | `779733410a11314afc6bf6a497ce1220d37c10090890563c6284a41f5c977e1f58dcd94e02573ef60d14fd5aec840fce` |
| TLSH | `T14B85337BF919F930EC00066F7F7DE510AA3872FD8F4909F86B6C16E8AD1A641466ED40` |
| SSDEEP | `49152:gX5cEmPm23feVa0JN/IsAZ7+FnPwM9MUwVM1B7VFg:gX54O8feVBUsEYPwKNBB7VO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_57de3767
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57de376767a78229701434a2efe5d6410132b208417e8d9fc0891405dfc7be09"
    family = "unknown"
    file_name = "riscv"
    file_type = "elf"
    first_seen = "2026-07-25 19:43:20"
  condition:
    hash.sha256(0, filesize) == "57de376767a78229701434a2efe5d6410132b208417e8d9fc0891405dfc7be09"
}
```

### Sample 49: `2f92eccabc10aa2d`

| Field | Value |
|---|---|
| SHA-256 | `2f92eccabc10aa2ddd4ec44fe4ab67deb30535ff885acb8b1aee4686be47523d` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-25 19:35:25` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7be394c41b9b147fc81bdc08100447e5` |
| SHA-1 | `c07a1579d0935642d14f2b2ce07ffc816275c74c` |
| SHA-256 | `2f92eccabc10aa2ddd4ec44fe4ab67deb30535ff885acb8b1aee4686be47523d` |
| SHA3-384 | `f5eff9d5f04c4c2cf9292f7a11b1974bfe3dcaa19daca046a1bb71d2132fb0c6c00e29ecf8d899cdac6f36098b1c5d4d` |
| TLSH | `T1B5C26C966A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:c8vCB+25j6es8R/9FYpMSUpi+20qUpi+20YQX:c8l25JJd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_2f92ecca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f92eccabc10aa2ddd4ec44fe4ab67deb30535ff885acb8b1aee4686be47523d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-25 19:35:25"
  condition:
    hash.sha256(0, filesize) == "2f92eccabc10aa2ddd4ec44fe4ab67deb30535ff885acb8b1aee4686be47523d"
}
```

### Sample 50: `efa742f512968d4e`

| Field | Value |
|---|---|
| SHA-256 | `efa742f512968d4e7c320f426551b3f4aa21e80ce8b40ebfdfe228e1f1980d4c` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-25 19:33:18` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3703292caefe9b29f637f7d768e7fdf5` |
| SHA-1 | `3e47108ad6f49a1f63f5bf71b716aed2750adab0` |
| SHA-256 | `efa742f512968d4e7c320f426551b3f4aa21e80ce8b40ebfdfe228e1f1980d4c` |
| SHA3-384 | `eaa00c7906244b4afdf78625612ff979f9997f689ccc35e4fd40c1e631295627b2ba84d6440369f4707797c50c7e61ff` |
| TLSH | `T131C27D96AA867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:B8vCB+25j6es8RLK9FYpMSUpi+20qUpi+20YQX:B8l25JL8d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_efa742f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efa742f512968d4e7c320f426551b3f4aa21e80ce8b40ebfdfe228e1f1980d4c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-25 19:33:18"
  condition:
    hash.sha256(0, filesize) == "efa742f512968d4e7c320f426551b3f4aa21e80ce8b40ebfdfe228e1f1980d4c"
}
```

### Sample 51: `fb4c3e7dc26b9803`

| Field | Value |
|---|---|
| SHA-256 | `fb4c3e7dc26b98030ee6f118356105780a293aff695652df6edd3f1058cc5d85` |
| Family label | `unknown` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-25 19:22:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfeeb80755e1ea1911232eacfe7dcc0a` |
| SHA-1 | `bd01100e2e3d5ad028806ca3bc70885442ddfb37` |
| SHA-256 | `fb4c3e7dc26b98030ee6f118356105780a293aff695652df6edd3f1058cc5d85` |
| SHA3-384 | `44b271d83ddf1c922b81bc8fbdc82a4d8a6e563eaa6357c373926ca54f217e6e86cbc44cf3b82c1b6108c830dc3d073b` |
| TLSH | `T1C8065C85FC41CF52C9D03A7AFB6E828833130779C2EA70059D255B7467DF99A0F3AA52` |
| TELFHASH | `t1733100a44c8674f8e2c552c159b974a6ec7f35ecdf2110e646857c7f5d034c2a495407` |
| SSDEEP | `49152:k0QkUw6lt8SLNxTP55iPqE71SEA3omiCWfbplVH:/UpltxPTP55i3G4miCWTpl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_fb4c3e7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb4c3e7dc26b98030ee6f118356105780a293aff695652df6edd3f1058cc5d85"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-25 19:22:50"
  condition:
    hash.sha256(0, filesize) == "fb4c3e7dc26b98030ee6f118356105780a293aff695652df6edd3f1058cc5d85"
}
```

### Sample 52: `1eecf2377d20768c`

| Field | Value |
|---|---|
| SHA-256 | `1eecf2377d20768c28d741e21affaa53cf26db0d083efdbf43a92fa938b7e4be` |
| Family label | `unknown` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-25 19:22:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db923bdcc2637822ad560a7fdaf291c2` |
| SHA-1 | `6d1127c9fdadb9e8881b534ccc7cfff4068e464e` |
| SHA-256 | `1eecf2377d20768c28d741e21affaa53cf26db0d083efdbf43a92fa938b7e4be` |
| SHA3-384 | `9762c60ef81ebae767bc39f366cfe8d5650f838fa5eb369a0880e1a4b8b8fff3cf0520512233a8af4b0ad0bd06d56e0c` |
| TLSH | `T1086533B4441EE3AB73889DD0745702691E4297B5CC92F01AE6FAFEF84385EA277D2443` |
| SSDEEP | `24576:SC6e8+QxSkuRCyUQhqWLE/oKaqVNAGZTUUrQhJX7Psc5pbqs6i2hAyBU3G:SXOOyU+dL0aIAsTyhNdus6iAAkeG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_1eecf237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eecf2377d20768c28d741e21affaa53cf26db0d083efdbf43a92fa938b7e4be"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-25 19:22:09"
  condition:
    hash.sha256(0, filesize) == "1eecf2377d20768c28d741e21affaa53cf26db0d083efdbf43a92fa938b7e4be"
}
```

### Sample 53: `fb2aca6aa66d3f3a`

| Field | Value |
|---|---|
| SHA-256 | `fb2aca6aa66d3f3ac1f3df3f3d95a8bde050698e576404d5d5d9ec218407f86d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 19:20:00` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `037e28e730a293fcb69c68bceac4bdb1` |
| SHA-1 | `6f2ebd1d9f5194252cd0417a1195cf5369f7b0a7` |
| SHA-256 | `fb2aca6aa66d3f3ac1f3df3f3d95a8bde050698e576404d5d5d9ec218407f86d` |
| SHA3-384 | `ce895bf18fd7c63c1f86d8b9a9b8ebb4f1173e40a951020c413d42f26010bd372c8a1138a1097cce237ed2dbec9cde94` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T19F623C0AB4818035EBE144B4827F526645FEADB623C4F9CBF7E064CA5AB46E1F43116F` |
| SSDEEP | `192:AWdsGnjXgjk8LMRI+wBdzMtJFeIFFBKUSfEzQbd1gJxTmv8U9cthf9ik:AUSMycUlEOyav8U9clX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_fb2aca6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb2aca6aa66d3f3ac1f3df3f3d95a8bde050698e576404d5d5d9ec218407f86d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 19:20:00"
  condition:
    hash.sha256(0, filesize) == "fb2aca6aa66d3f3ac1f3df3f3d95a8bde050698e576404d5d5d9ec218407f86d"
}
```

### Sample 54: `b75a1f635e976190`

| Field | Value |
|---|---|
| SHA-256 | `b75a1f635e976190bbe1155b244f655937693fb868d27f9010813ce64f210d45` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-25 19:08:23` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44af521011206ecad327046ad626ff19` |
| SHA-1 | `0a8f31649223164c4839a2e7f560e8d61e133286` |
| SHA-256 | `b75a1f635e976190bbe1155b244f655937693fb868d27f9010813ce64f210d45` |
| SHA3-384 | `85fd6b428088733609b5fe54cf3fc59fef49b2debbfb66eb365b33937a386764eae5ec63b522ed9f39f1175af968271f` |
| TLSH | `T13E136C6516953C28AE99883B5C7F2F0CBDA983E2304491DDBF8B3CF18C55A9CE21875D` |
| SSDEEP | `768:a9NyXsZztCD9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:aHusZ1co` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_b75a1f63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b75a1f635e976190bbe1155b244f655937693fb868d27f9010813ce64f210d45"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-25 19:08:23"
  condition:
    hash.sha256(0, filesize) == "b75a1f635e976190bbe1155b244f655937693fb868d27f9010813ce64f210d45"
}
```

### Sample 55: `a007111bc2e22b8f`

| Field | Value |
|---|---|
| SHA-256 | `a007111bc2e22b8f34440012d21d7e265d0c349b9e2b2aa2568397238974ec08` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-25 18:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f64c86017ea3629c645c5695e4dd136b` |
| SHA-1 | `c6eae2916af4e8603c51e6b27b6e6f8b068284b1` |
| SHA-256 | `a007111bc2e22b8f34440012d21d7e265d0c349b9e2b2aa2568397238974ec08` |
| SHA3-384 | `b5a343afd2437f40a0409f27a851f8b3756ee545f4fd84753d46d7e984abab6de88f21665d116e29873bef7ab59b5bf3` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T188E6335864D413F8EAF3417CAFE18692E558F8B42736C69F179403A17E232E14D3EA27` |
| SSDEEP | `393216:d4EIFrol2nfRUTzdKWmLg+iXMCHWUjX4cuI3/PGTAI:dGvfRUTld+iXMb8XNH/O7` |
| ICON-DHASH | `e8e864e0d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_a007111b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a007111bc2e22b8f34440012d21d7e265d0c349b9e2b2aa2568397238974ec08"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 18:52:32"
  condition:
    hash.sha256(0, filesize) == "a007111bc2e22b8f34440012d21d7e265d0c349b9e2b2aa2568397238974ec08"
}
```

### Sample 56: `864239d4d6d18ac4`

| Field | Value |
|---|---|
| SHA-256 | `864239d4d6d18ac41b16fec2b40f2fc647881dfdf66ac00db5e41d823ba8411c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 18:51:30` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04a9708ff36968dabec9c9922b958071` |
| SHA-1 | `bce0d27bab5a8192d6b6308f30cd558969692f4a` |
| SHA-256 | `864239d4d6d18ac41b16fec2b40f2fc647881dfdf66ac00db5e41d823ba8411c` |
| SHA3-384 | `7da1715199e9902a3207d40069c0af7718b97467433d24542e8d4df82061a71cc70d14c72ccf184ca66b8805d66ce74c` |
| IMPHASH | `08e71dc3a4ed4919ed4f88f99fab3457` |
| TLSH | `T153624C0BB8814036EAE14079477F4226447E6CB623C0F8DBF7F0698A59B46E1F43116F` |
| SSDEEP | `192:u9BErjXgjo8P0UI+TemM2B1WFeI82IKUSfEzQyFJxTmv8U9cth99c+F:ju0IHWUoERav8U9cXzF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_864239d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "864239d4d6d18ac41b16fec2b40f2fc647881dfdf66ac00db5e41d823ba8411c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 18:51:30"
  condition:
    hash.sha256(0, filesize) == "864239d4d6d18ac41b16fec2b40f2fc647881dfdf66ac00db5e41d823ba8411c"
}
```

### Sample 57: `bdabc7198cc94abb`

| Field | Value |
|---|---|
| SHA-256 | `bdabc7198cc94abbf0446bda43a21128c548f8fa3e039562502e308de3a890b6` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 18:50:48` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b27f8fc61f3c0d5798c71e88678c68a` |
| SHA-1 | `783c6ce7d746798196c687e507a4be2f99b58618` |
| SHA-256 | `bdabc7198cc94abbf0446bda43a21128c548f8fa3e039562502e308de3a890b6` |
| SHA3-384 | `8512f7cf89c753c6d870ee27ddc4346ad9cdbb5175c311d12c34c7f95f51c2c2f3570209d1032c01449ab6ac5e48e692` |
| IMPHASH | `08e71dc3a4ed4919ed4f88f99fab3457` |
| TLSH | `T12F623C0BA8818036EAE14079537F422645BE7CB623C0F8DBF7F0698A59B56E1F43156F` |
| SSDEEP | `192:a9BErjXgjo8PEUI+jum8mdzfxmF5oIsGIKUSfEzQiFJxTmv8U9cthL9c+F:vuEIlfxmroIEBav8U9chzF` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_057_bdabc719
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdabc7198cc94abbf0446bda43a21128c548f8fa3e039562502e308de3a890b6"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 18:50:48"
  condition:
    hash.sha256(0, filesize) == "bdabc7198cc94abbf0446bda43a21128c548f8fa3e039562502e308de3a890b6"
}
```

### Sample 58: `54f3f2e7df81774a`

| Field | Value |
|---|---|
| SHA-256 | `54f3f2e7df81774a39f1495389d76826758c76f2a86536b4e67b17c0f624076d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 18:47:53` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `797b6854e9063df0803ed118373965a9` |
| SHA-1 | `d3425e001a6e58653b90b92ff29a851453453a7b` |
| SHA-256 | `54f3f2e7df81774a39f1495389d76826758c76f2a86536b4e67b17c0f624076d` |
| SHA3-384 | `58afa7672f8f35b76c03fa03ae1afd5fa7562c7e5b277677502f080cf268d6b5290a5e3019ae5be8217c505080ed571c` |
| IMPHASH | `08e71dc3a4ed4919ed4f88f99fab3457` |
| TLSH | `T1A8623B0BB8814036EAE14079477F4226447A6CB623C0F9DBF7F0A98A59B46E1F43156F` |
| SSDEEP | `192:r9BErjXgjo8P0UI+TemM2l1WFeI82IKUSfEzQyFJxTmv8U9cthI9c+F:wu0IzWUoERav8U9c+zF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_54f3f2e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54f3f2e7df81774a39f1495389d76826758c76f2a86536b4e67b17c0f624076d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 18:47:53"
  condition:
    hash.sha256(0, filesize) == "54f3f2e7df81774a39f1495389d76826758c76f2a86536b4e67b17c0f624076d"
}
```

### Sample 59: `9aa2c888e7d2a08a`

| Field | Value |
|---|---|
| SHA-256 | `9aa2c888e7d2a08a0172e9967ce715124ccceddecbaf47a319fa78c6629015b4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 18:36:40` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c95ecf6510b6bfa5105c32f029c6ef2a` |
| SHA-1 | `075c02b15f15af36b8cf119fb997664c173b145d` |
| SHA-256 | `9aa2c888e7d2a08a0172e9967ce715124ccceddecbaf47a319fa78c6629015b4` |
| SHA3-384 | `22816898db73448d67ea40f4251636f32b7f4efcec0d3b1802cb29bd164e5e538792c6f479e0e02e60297fda1b826f37` |
| IMPHASH | `08e71dc3a4ed4919ed4f88f99fab3457` |
| TLSH | `T136623C0BA8814036EAE14079537F422645BE7CB623C0F8DBF7F0698A59B56E1F43156F` |
| SSDEEP | `192:r9BErjXgjo8PEUI+jum8mlzfxmF5oIsGIKUSfEzQiFJxTmv8U9cthm9c+F:wuEItfxmroIEBav8U9cYzF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_9aa2c888
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9aa2c888e7d2a08a0172e9967ce715124ccceddecbaf47a319fa78c6629015b4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 18:36:40"
  condition:
    hash.sha256(0, filesize) == "9aa2c888e7d2a08a0172e9967ce715124ccceddecbaf47a319fa78c6629015b4"
}
```

### Sample 60: `3d5af7ca987b1434`

| Field | Value |
|---|---|
| SHA-256 | `3d5af7ca987b143447b7ab87c304d6c2b58f924ac4e99fe76270d1214d2783fc` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-25 18:36:28` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c13750b309f114c028bc5fa65ff0390` |
| SHA-1 | `3cbf2c66ed26a7f2628a962be125644adaebd4aa` |
| SHA-256 | `3d5af7ca987b143447b7ab87c304d6c2b58f924ac4e99fe76270d1214d2783fc` |
| SHA3-384 | `0651c5606b794b841ded0b43c9ae476d304b227e6ee205687d5387450a7f53b34e0db5c3844b0dc8508708b26577ac93` |
| TLSH | `T1E4137D6566913C24AE9998371D7E1F0CBDAA83E23104A1DDBFCB3CF18C59A9CD21871D` |
| SSDEEP | `768:LXRWNGxVr9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:Flx2co` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_3d5af7ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d5af7ca987b143447b7ab87c304d6c2b58f924ac4e99fe76270d1214d2783fc"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-25 18:36:28"
  condition:
    hash.sha256(0, filesize) == "3d5af7ca987b143447b7ab87c304d6c2b58f924ac4e99fe76270d1214d2783fc"
}
```

### Sample 61: `c43396e514f92076`

| Field | Value |
|---|---|
| SHA-256 | `c43396e514f92076c9a0c7e22248af8d60714a83eeab866d52dab13808a8bc32` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-25 18:23:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6d4b591a37ee2fb74339e1938e9dc85` |
| SHA-1 | `0907eb14d4092ecf9ca3c0c5957f985b7e3bb4ee` |
| SHA-256 | `c43396e514f92076c9a0c7e22248af8d60714a83eeab866d52dab13808a8bc32` |
| SHA3-384 | `62e2f0fa264c1bc329111e029b2dfc82e0409fa337c9ffb5280a12fdf9a9275c12368e2eacf2ca4e1dda513a804a508b` |
| TLSH | `T1EA365D4BF5A320FCC19BC434875B99A2B935786901207EBB66D4DA302B33F605B59F72` |
| TELFHASH | `t1d37251f067d534e065a2ca59dbb6f470da3308b757e0b5b14437bc53cfa4e490c6a822` |
| SSDEEP | `98304:mriPpW09jtrs9zPMfPTipUYLBRKVbv59uKLKL8PWhzZPs+3go:X8MjfipUQBws6WEx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_c43396e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c43396e514f92076c9a0c7e22248af8d60714a83eeab866d52dab13808a8bc32"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-25 18:23:00"
  condition:
    hash.sha256(0, filesize) == "c43396e514f92076c9a0c7e22248af8d60714a83eeab866d52dab13808a8bc32"
}
```

### Sample 62: `bf8b6b4846ad5426`

| Field | Value |
|---|---|
| SHA-256 | `bf8b6b4846ad542696304b6d7e339d2c1425cd27aa61ac48df08c1de2dc4fabb` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-25 18:22:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc74f44f207e7ea443ff9ee494450ac8` |
| SHA-1 | `7b2c02a774056b8e7c01b7323795fe45c7e39fca` |
| SHA-256 | `bf8b6b4846ad542696304b6d7e339d2c1425cd27aa61ac48df08c1de2dc4fabb` |
| SHA3-384 | `3044733489510a38f6e934786fb33a101f7d874e1d60efbc2087d5f37e350c3eb68bf4bb73c7a7d3db18f2c5ac965376` |
| TLSH | `T1A295330274A0F537BC35F2F1BD1BE653960CB12E9A1099FF1BE5604466ABE187CC6239` |
| SSDEEP | `49152:MRpdjtrx7OG3LpamJh5xSP0W9wY1qQ2093y0Npv:M3djtFOG3/Jh5xWz9wYMU939x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_bf8b6b48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf8b6b4846ad542696304b6d7e339d2c1425cd27aa61ac48df08c1de2dc4fabb"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-25 18:22:30"
  condition:
    hash.sha256(0, filesize) == "bf8b6b4846ad542696304b6d7e339d2c1425cd27aa61ac48df08c1de2dc4fabb"
}
```

### Sample 63: `dc863b3db099b101`

| Field | Value |
|---|---|
| SHA-256 | `dc863b3db099b101c6c95a17b70bfccbb9826916e6a27c13d6315a5568ba3f13` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-07-25 18:21:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30aadf0ed97011225745dccdb9571165` |
| SHA-1 | `3b8d8e7c437c79f2fdc0ef89d1fe6d6fc7e1dd97` |
| SHA-256 | `dc863b3db099b101c6c95a17b70bfccbb9826916e6a27c13d6315a5568ba3f13` |
| SHA3-384 | `092a4ecca8dd4066a5a1b4ba713cb63d49ee316c1495e873c4670753b08e2af4b9310a353f4253907977e93c9b02b2c8` |
| TLSH | `T134367C88E793E0F4E25308F0559BD7F761201A355053F6F2EB8A6F65B4327816F093AA` |
| TELFHASH | `t18282a173449864e977f04407d3af7674cfa6e0eb179024f225f97ce096b2cc2a626d68` |
| SSDEEP | `98304:d6X6ucuDOb2KZ+5qxyEnJh5eE9iY6TcqyHcdeMk3DfX8mTqSqkS+QNx:d6XvcuDOb2K+qwEJF+Vds8T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_dc863b3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc863b3db099b101c6c95a17b70bfccbb9826916e6a27c13d6315a5568ba3f13"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-25 18:21:59"
  condition:
    hash.sha256(0, filesize) == "dc863b3db099b101c6c95a17b70bfccbb9826916e6a27c13d6315a5568ba3f13"
}
```

### Sample 64: `2f206563640dd66a`

| Field | Value |
|---|---|
| SHA-256 | `2f206563640dd66a743ffd493ce0e3c31a8fc5a24b9f5d2b540fc22d45c13d66` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-07-25 18:21:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `026312ed570610d33bbebb999b095668` |
| SHA-1 | `5c54973e56a98a414d865f4e32f508f7579066d3` |
| SHA-256 | `2f206563640dd66a743ffd493ce0e3c31a8fc5a24b9f5d2b540fc22d45c13d66` |
| SHA3-384 | `c8b7e34cf8da07f69504c098bc527f69b5b4d80fa88763762337aba2372984028d60e94d87c6ab3087b45a470bc77897` |
| TLSH | `T15E85337339E27BF5CCBFA6F0A649EF19919E2260690FDF88E452CA55C4D90A37311384` |
| TELFHASH | `t1ffb001baca4a7c82e9467252428fe3c5dd47977a96b42883400d44101aaba132a96507` |
| SSDEEP | `49152:SeI/oZTjidHVh3oUgnTUQzlT3chu8MRejJ/V1a4:NaoZXW3oUOlx3cqRo/Xt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_2f206563
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f206563640dd66a743ffd493ce0e3c31a8fc5a24b9f5d2b540fc22d45c13d66"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-25 18:21:22"
  condition:
    hash.sha256(0, filesize) == "2f206563640dd66a743ffd493ce0e3c31a8fc5a24b9f5d2b540fc22d45c13d66"
}
```

### Sample 65: `3a79f8de2e26382a`

| Field | Value |
|---|---|
| SHA-256 | `3a79f8de2e26382af0127a263f6bb9c242a6c75c598e7e33792d2a96e956bda4` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-07-25 18:17:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5374257d10b3f07c1ad046c900e57afe` |
| SHA-1 | `ad7491bb3dea856d5e2e6a5993c0a641c05e1825` |
| SHA-256 | `3a79f8de2e26382af0127a263f6bb9c242a6c75c598e7e33792d2a96e956bda4` |
| SHA3-384 | `7942a4c649b2c97a825bfe6d2dc29dc5de53da4da5f062c4d3f246cb35be86b363b9b8d0eb615fc431572201d6d74397` |
| TLSH | `T1E3E3D61E7E618F3CFBE9823047B79E26975833D636D1D595D1ACE6001E2028E241FFA4` |
| TELFHASH | `t1be115b1c497822f09b751c9d6beeff72e59070ef06266d378e40e96daa6d9419e00c1c` |
| SSDEEP | `3072:K2JG2CYTcYpA5C7gMtspYX29A8uXENQDw/HKK9t/w+T+7oywvyMiRZtkpUptH/tI:PJG2CYTcYpA5C7gMtspYX29A8uXENQD8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_3a79f8de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a79f8de2e26382af0127a263f6bb9c242a6c75c598e7e33792d2a96e956bda4"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-25 18:17:39"
  condition:
    hash.sha256(0, filesize) == "3a79f8de2e26382af0127a263f6bb9c242a6c75c598e7e33792d2a96e956bda4"
}
```

### Sample 66: `cd8103d0eaab7ebd`

| Field | Value |
|---|---|
| SHA-256 | `cd8103d0eaab7ebdf0617da38859a0274505986ff9c45583d4e4d95886f8e3d7` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-07-25 18:17:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `516530f3f64449f4377bbd06fc4d7486` |
| SHA-1 | `302a2cc6c98fb2647fb7c6d16b4fd85d91b113b2` |
| SHA-256 | `cd8103d0eaab7ebdf0617da38859a0274505986ff9c45583d4e4d95886f8e3d7` |
| SHA3-384 | `acd964b63857f472a0d20eb8b077fab4100afaaeb50d18d3e8bde19ace236bdbadb38614785c5ed726e0b055da830301` |
| TLSH | `T1B733F1DC239205C4E09E84F9CF21DFA4FB1A17E5D1C7CD496E2761029D8D8A9B40BFA6` |
| SSDEEP | `1536:PnBL63RmqXNJgQxJ7FQQ5Wq95IY5As9VJuCA:P96BzJRQQ59X5As9VQCA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_cd8103d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd8103d0eaab7ebdf0617da38859a0274505986ff9c45583d4e4d95886f8e3d7"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-25 18:17:25"
  condition:
    hash.sha256(0, filesize) == "cd8103d0eaab7ebdf0617da38859a0274505986ff9c45583d4e4d95886f8e3d7"
}
```

### Sample 67: `655e66d1fc8aa77d`

| Field | Value |
|---|---|
| SHA-256 | `655e66d1fc8aa77dae0bef3ffd4016566a6c3e4e7ed44d163d7adc84361fe326` |
| Family label | `Mirai` |
| File name | `nz.arc` |
| File type | `elf` |
| First seen | `2026-07-25 18:16:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `872b08c43c7293a1626625c92030ab17` |
| SHA-1 | `0215ddbeed30d7fb451a8f56f74d4795c724e287` |
| SHA-256 | `655e66d1fc8aa77dae0bef3ffd4016566a6c3e4e7ed44d163d7adc84361fe326` |
| SHA3-384 | `1a070fa8400fbdeb64379a240ef8e4d046f61733a61669c34fd5291bb95e17aefff0c863602b4b4c6799947c643d8384` |
| TLSH | `T1FFE3BEA7F78B2091C96302F407CB6BCD6E1722825F5BD9E76D6F303B597A0DA0502B91` |
| SSDEEP | `3072:iek++sK6WpE1JyQ1U1s9jbvEnVOkvg176q:iedWcfDbCg76q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_655e66d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "655e66d1fc8aa77dae0bef3ffd4016566a6c3e4e7ed44d163d7adc84361fe326"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-25 18:16:15"
  condition:
    hash.sha256(0, filesize) == "655e66d1fc8aa77dae0bef3ffd4016566a6c3e4e7ed44d163d7adc84361fe326"
}
```

### Sample 68: `ea31e8a1d6cb9142`

| Field | Value |
|---|---|
| SHA-256 | `ea31e8a1d6cb9142b29a79592436a4842065bd9604349e564e6489c486837509` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-25 17:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33387319481f1758bed1546cded72d14` |
| SHA-1 | `586f0e187204b43b3007740ccefb61c7868511c9` |
| SHA-256 | `ea31e8a1d6cb9142b29a79592436a4842065bd9604349e564e6489c486837509` |
| SHA3-384 | `85e4a0eace31bbb3fae8241ea43a17f3ac8c6b4f363d127799b475d7c760b67ef7ee0d4f59aa52ca38c898f5386dd9a9` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1A1E6334C57D016EFE5A3513CEDE24965E8693CAA0771C8CB07A1C362BE1B3D09A7D227` |
| SSDEEP | `393216:JqEgE4WzMrUvY2LYLQPwINXMCHWUjXVcuI3/PGTAI:JqjLWgIvY2LwINXMb8XiH/O7` |
| ICON-DHASH | `30f8fcdccce4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_ea31e8a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea31e8a1d6cb9142b29a79592436a4842065bd9604349e564e6489c486837509"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 17:52:30"
  condition:
    hash.sha256(0, filesize) == "ea31e8a1d6cb9142b29a79592436a4842065bd9604349e564e6489c486837509"
}
```

### Sample 69: `4f8df06e14378fef`

| Field | Value |
|---|---|
| SHA-256 | `4f8df06e14378fef16c78183525ba7c0dbcc5176e92ae20102d6ea25dbccbf1d` |
| Family label | `Vidar` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-25 17:39:00` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6ea03ecc9f09124603cfde6c0017483` |
| SHA-1 | `44bc98bc9831d5a22e7dcddd7dbbb6387f9e17cc` |
| SHA-256 | `4f8df06e14378fef16c78183525ba7c0dbcc5176e92ae20102d6ea25dbccbf1d` |
| SHA3-384 | `db2cc84506687b4a16c02763c6a3b05d968c58f727371fb5f691905b0d37362c3d9d6328c43436ad6d98820fdc310336` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D7068C13AC950AF5D099A331C9B79611B735BC091B3233EB2E60BB782EB27D05D79B50` |
| SSDEEP | `49152:eupKXGeiLFcVG5VBPYscMAdeHFR0BnPTl//2WJNJuqH:eRqAsFROwWhu` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_069_4f8df06e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f8df06e14378fef16c78183525ba7c0dbcc5176e92ae20102d6ea25dbccbf1d"
    family = "Vidar"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:39:00"
  condition:
    hash.sha256(0, filesize) == "4f8df06e14378fef16c78183525ba7c0dbcc5176e92ae20102d6ea25dbccbf1d"
}
```

### Sample 70: `c1a2cfb94aca34a4`

| Field | Value |
|---|---|
| SHA-256 | `c1a2cfb94aca34a4088d036c4833c08d113ee4618bdbc25b3a937da5eb225e1e` |
| Family label | `unknown` |
| File name | `launcher.exe` |
| File type | `exe` |
| First seen | `2026-07-25 17:36:12` |
| Reporter | `Kejult` |
| Tags | `dropper, exe, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f99072e2f99208d8b03135b11f70dc49` |
| SHA-1 | `6983c82ab97d3509e9d8428c42f213420343f063` |
| SHA-256 | `c1a2cfb94aca34a4088d036c4833c08d113ee4618bdbc25b3a937da5eb225e1e` |
| SHA3-384 | `e79b0e662032578dd4273a1f5062b153aa19ba4d18d2878dc6047f086592866b824555070d829c31626827f572fd731c` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T11908334D1C68C887C27F8AFAB962347AE34499372DB4B82E1B190BDC79E1D5114BC53B` |
| SSDEEP | `1572864:Mt9IKP7ULJKc3tORWYKJImKljUoEkB9dNDsMLXgiMZrIuEtTZSm7:MUKix3tORWjImKljUvOhLXMxIuNm7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_c1a2cfb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1a2cfb94aca34a4088d036c4833c08d113ee4618bdbc25b3a937da5eb225e1e"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:36:12"
  condition:
    hash.sha256(0, filesize) == "c1a2cfb94aca34a4088d036c4833c08d113ee4618bdbc25b3a937da5eb225e1e"
}
```

### Sample 71: `cf426ee0da8f8907`

| Field | Value |
|---|---|
| SHA-256 | `cf426ee0da8f8907c42dfe264552ec560d5a97ff85ec7a7bf4518e773b19ce50` |
| Family label | `RemusStealer` |
| File name | `Phantom Loader.exe` |
| File type | `exe` |
| First seen | `2026-07-25 17:35:04` |
| Reporter | `Kejult` |
| Tags | `exe, remus, remusstealer, signed, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0755a7cc6c033ed6f38280a4dd78c3e8` |
| SHA-1 | `94a74afe4341f23d776410d413582e0f78110ec6` |
| SHA-256 | `cf426ee0da8f8907c42dfe264552ec560d5a97ff85ec7a7bf4518e773b19ce50` |
| SHA3-384 | `b4ab49ffaedbc860c869e6b7e2c0957cb8fd3a780142d4b571ae18e18919e67a29902b01e0618a91ba393807b6018897` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T19FA63917BD9048E5C09AE23289B75256BB75BC0C0B3233E72EA1BA782F727D05D35B54` |
| SSDEEP | `49152:5Pj8nkvVzCnN8/IeVB0ysiBzk+coP998B:5wLXY5cKg` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_071_cf426ee0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf426ee0da8f8907c42dfe264552ec560d5a97ff85ec7a7bf4518e773b19ce50"
    family = "RemusStealer"
    file_name = "Phantom Loader.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:35:04"
  condition:
    hash.sha256(0, filesize) == "cf426ee0da8f8907c42dfe264552ec560d5a97ff85ec7a7bf4518e773b19ce50"
}
```

### Sample 72: `58285829ced385a7`

| Field | Value |
|---|---|
| SHA-256 | `58285829ced385a7d48785af5efa36f3f99150af8c1d73514653c2b62b9abb04` |
| Family label | `unknown` |
| File name | `HitWave.exe` |
| File type | `exe` |
| First seen | `2026-07-25 17:33:50` |
| Reporter | `Kejult` |
| Tags | `exe, Generic, signed, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dca0c8f9acd74a49eb22b849943c3e25` |
| SHA-1 | `264ec9388b930c2e6e9a3dfbfcfbae465745f88b` |
| SHA-256 | `58285829ced385a7d48785af5efa36f3f99150af8c1d73514653c2b62b9abb04` |
| SHA3-384 | `754a2dd924ff9460895e79de0de4f3c025eff10615ee23007435ed5a3354b72ab8f536932af3c72fcaec35c9da854b7a` |
| IMPHASH | `f23ee6cae9102afbfd90f52d60f792d8` |
| TLSH | `T1ACC52907BD9148E6C0AA92318972D7A97B21FC442F2123D73EA0BB793EB67D09D35354` |
| SSDEEP | `24576:j3sq0P+RXi9XkdvsgTMiUMCuiF8XLPMrIJjcT8fEXBelesaKD0kov4sS8cXL:j3sbPiXiSdkgTjrnbPR6fc8cXL` |
| ICON-DHASH | `b271e8f0f0f87192` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_58285829
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58285829ced385a7d48785af5efa36f3f99150af8c1d73514653c2b62b9abb04"
    family = "unknown"
    file_name = "HitWave.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:33:50"
  condition:
    hash.sha256(0, filesize) == "58285829ced385a7d48785af5efa36f3f99150af8c1d73514653c2b62b9abb04"
}
```

### Sample 73: `440789c3674469c6`

| Field | Value |
|---|---|
| SHA-256 | `440789c3674469c66bbdcb706c8fc7af666b67cfb1fba4ae4886bc94b66aeaef` |
| Family label | `unknown` |
| File name | `curl_ext.dll` |
| File type | `exe` |
| First seen | `2026-07-25 17:32:54` |
| Reporter | `Kejult` |
| Tags | `dll, exe, signed, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5efca39b93a87eeddac34b384725d16d` |
| SHA-1 | `63687fb994e368b3b6c3a0afbdfc37d93559669d` |
| SHA-256 | `440789c3674469c66bbdcb706c8fc7af666b67cfb1fba4ae4886bc94b66aeaef` |
| SHA3-384 | `e6f33c49ef8702651f5476556f5a83e5420c2a0aee1cac99923cac710f27afdf6775e7c06cec6e428cd94bc86e3ee74a` |
| IMPHASH | `4d791c7ff8a04656c4df23bdb9ebb892` |
| TLSH | `T15AC56C07FDA1C8B5D0AB92318972A2917B30BD452F2123CF2A90B7792FB27D05975778` |
| SSDEEP | `24576:x7pxugvZkqGyGEwjQ498inZml46wvi86XpfEXBelesaKDQepY4sTG3oFB:x7pxxv2qGawk49bZkY96m5e3o7` |
| ICON-DHASH | `923078c0dcf17294` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_440789c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "440789c3674469c66bbdcb706c8fc7af666b67cfb1fba4ae4886bc94b66aeaef"
    family = "unknown"
    file_name = "curl_ext.dll"
    file_type = "exe"
    first_seen = "2026-07-25 17:32:54"
  condition:
    hash.sha256(0, filesize) == "440789c3674469c66bbdcb706c8fc7af666b67cfb1fba4ae4886bc94b66aeaef"
}
```

### Sample 74: `93f44970a8af6f0f`

| Field | Value |
|---|---|
| SHA-256 | `93f44970a8af6f0f348f79843fb0e182d5057e4eb4e3a0623b1aebf27251fe5d` |
| Family label | `RemusStealer` |
| File name | `NexusMods.exe` |
| File type | `exe` |
| First seen | `2026-07-25 17:31:53` |
| Reporter | `Kejult` |
| Tags | `exe, remus, remusstealer, signed, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ed591cb63556c9df3ccc1077c9a434d` |
| SHA-1 | `e313d6933faa4dda9cc8667d3c4926f0186249a7` |
| SHA-256 | `93f44970a8af6f0f348f79843fb0e182d5057e4eb4e3a0623b1aebf27251fe5d` |
| SHA3-384 | `1a1f7ee876483cafd2b9fcae067d843a8f4d2dc9ebf4986dee62e480a2b2c28fe13da7f640ef9ae152763be488492a18` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T153B74917BC9148EAC0A9A331C9B65246BB35BC081B3637EB2E90BB782F727D05D35754` |
| SSDEEP | `49152:BixUPCYWAuvNx8GxHvGy5jqU751C1LK25an:BXKHAU751C1+KC` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_074_93f44970
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93f44970a8af6f0f348f79843fb0e182d5057e4eb4e3a0623b1aebf27251fe5d"
    family = "RemusStealer"
    file_name = "NexusMods.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:31:53"
  condition:
    hash.sha256(0, filesize) == "93f44970a8af6f0f348f79843fb0e182d5057e4eb4e3a0623b1aebf27251fe5d"
}
```

### Sample 75: `535b129126e50497`

| Field | Value |
|---|---|
| SHA-256 | `535b129126e50497bc83afe22e97dbcec6236b0836a15b41f3af89dd9c6a4f1a` |
| Family label | `Mirai` |
| File name | `libkys.elf` |
| File type | `elf` |
| First seen | `2026-07-25 17:30:37` |
| Reporter | `BastianHein_` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae3af8af72c62c6283431c05b181fcb4` |
| SHA-1 | `ef4555dc63fe79aa360b23bab3711c88b609fd1b` |
| SHA-256 | `535b129126e50497bc83afe22e97dbcec6236b0836a15b41f3af89dd9c6a4f1a` |
| SHA3-384 | `e5cbeca8ab7f8f35e7d111642368b9dbf00232f9e0254ed9cdefa5510247f9438b96014306a181b51e44ccea59d8e790` |
| TLSH | `T1AFB30946A9429F11D5C631FAFBAF414933136FB8E3FA7111D9205F6023C699B0EB7612` |
| TELFHASH | `t14de0c002d71c18ec63c9801812fab228fc62f2a01c3426913f95ec9d9157995712dc35` |
| SSDEEP | `3072:pqiy9qVvpOFnQfG/7/0NZYjYhOn1NaVF7h1ubWczgflZI04MbHPsf:pqiJKdQe/7/0NZYjWK1NaVF7h1Hczgkd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_535b1291
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "535b129126e50497bc83afe22e97dbcec6236b0836a15b41f3af89dd9c6a4f1a"
    family = "Mirai"
    file_name = "libkys.elf"
    file_type = "elf"
    first_seen = "2026-07-25 17:30:37"
  condition:
    hash.sha256(0, filesize) == "535b129126e50497bc83afe22e97dbcec6236b0836a15b41f3af89dd9c6a4f1a"
}
```

### Sample 76: `2a5050ebca4c8fa1`

| Field | Value |
|---|---|
| SHA-256 | `2a5050ebca4c8fa135b80503d1d2bdf77ec30e8089cbd318a939888048957b55` |
| Family label | `Vidar` |
| File name | `Mod Menu.exe` |
| File type | `exe` |
| First seen | `2026-07-25 17:30:31` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7fe8f4f25bad097efcadcd798da0a46` |
| SHA-1 | `9b45d7455d950bf89bacd045a5b5545c2ede865e` |
| SHA-256 | `2a5050ebca4c8fa135b80503d1d2bdf77ec30e8089cbd318a939888048957b55` |
| SHA3-384 | `75a1059cdebe649208fac00844cc25434cb45c7c980d096b25cf32bbbbc4b82f07c1d7a6a6a4b74a863fcfff5022fb55` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T126068E03ECA588F5C4AAA33289A752567B75BC091B3223E72E606B383F737D09C35755` |
| SSDEEP | `49152:POQXcLIFCIz4JECtAhFS5Eg70z6iITtC3jI7pQpK7:PIeC/7Y6iItIjQo6` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_076_2a5050eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a5050ebca4c8fa135b80503d1d2bdf77ec30e8089cbd318a939888048957b55"
    family = "Vidar"
    file_name = "Mod Menu.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:30:31"
  condition:
    hash.sha256(0, filesize) == "2a5050ebca4c8fa135b80503d1d2bdf77ec30e8089cbd318a939888048957b55"
}
```

### Sample 77: `d925bd9a7e6d71e0`

| Field | Value |
|---|---|
| SHA-256 | `d925bd9a7e6d71e02f34624223878a090efd5f9ae2c55e80efb14e53cf3c4c7e` |
| Family label | `unknown` |
| File name | `base_temp.apk` |
| File type | `apk` |
| First seen | `2026-07-25 17:30:25` |
| Reporter | `BastianHein_` |
| Tags | `apk, Mparivahan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ec01a39ef6bae851be7b05fe9114a6e` |
| SHA-1 | `602e7a42bf703159e3b06a8ca1411fa86e7cff30` |
| SHA-256 | `d925bd9a7e6d71e02f34624223878a090efd5f9ae2c55e80efb14e53cf3c4c7e` |
| SHA3-384 | `1c090d5ae47efe6e5d1ee950cafe6b92bf537f6139a7a101f9121c44a0ee2849e2eafaa9aef9d81f546e57ac02ec3424` |
| TLSH | `T18AB61299FBD8EA2BC437513349665275518B4C0A9E42DB537A4C7B0C38BB9D40F8BBC8` |
| SSDEEP | `196608:+aiy69mRB/Lj3StQgJlihDFccUrJR731xq9ZTBAR+LIUyMLPVVyH4:BJBD2CcihBcRDGbg+pyGyY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_d925bd9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d925bd9a7e6d71e02f34624223878a090efd5f9ae2c55e80efb14e53cf3c4c7e"
    family = "unknown"
    file_name = "base_temp.apk"
    file_type = "apk"
    first_seen = "2026-07-25 17:30:25"
  condition:
    hash.sha256(0, filesize) == "d925bd9a7e6d71e02f34624223878a090efd5f9ae2c55e80efb14e53cf3c4c7e"
}
```

### Sample 78: `655762d13640a024`

| Field | Value |
|---|---|
| SHA-256 | `655762d13640a024bfebb418ce4d1a349ddfdef357600eaab420b7a4d9c04b98` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-25 17:07:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `414491976d6da13dcc2d624dbaee0a5c` |
| SHA-1 | `c1f4d46c62eb48db7c1521f41feb61a7cee091a8` |
| SHA-256 | `655762d13640a024bfebb418ce4d1a349ddfdef357600eaab420b7a4d9c04b98` |
| SHA3-384 | `9a7cebe903b5e0e6661d70654571fc0e86b9cdab12162f78cbc6beb49c14cb3e9e2f11d2121e00a24afe7d06f7de6303` |
| TLSH | `T13C136D6566813C28AE9998371D7E1F0CBDAA83E2310491DDBFCB3CF18C59A9CD21971D` |
| SSDEEP | `768:WXRWNGxVC9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:Slxtco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_655762d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "655762d13640a024bfebb418ce4d1a349ddfdef357600eaab420b7a4d9c04b98"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-25 17:07:36"
  condition:
    hash.sha256(0, filesize) == "655762d13640a024bfebb418ce4d1a349ddfdef357600eaab420b7a4d9c04b98"
}
```

### Sample 79: `2880c19f853059ba`

| Field | Value |
|---|---|
| SHA-256 | `2880c19f853059bae15a838d1320f728d3f681ff8bdfe22d455bc0335d317c7f` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 17:07:00` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX3.file, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5cd6f31554350d552c42dc0320c85cb` |
| SHA-1 | `2a67068602cd24a96338010fb040eccd08b60aa3` |
| SHA-256 | `2880c19f853059bae15a838d1320f728d3f681ff8bdfe22d455bc0335d317c7f` |
| SHA3-384 | `d44a605dcdd738bfa12dbfa4280f48b5fb68fc31821ecdb23b9a0b946d3663cf610469ebfa3dedb7de1696854691deaa` |
| IMPHASH | `7d0290492937921b604a72fe395319d0` |
| TLSH | `T1F8253A5BB3E930F9E137C27985924A05EB72B4354721ABEF0360576A1F632D48D3EB21` |
| SSDEEP | `3072:P53+Z2c90aq86nJ4YvsaLuiv0SQyd9sODvm3klPnR8YQpl29p8:P53+Zz6JD0Gugdd9bvf/OC9p` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_079_2880c19f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2880c19f853059bae15a838d1320f728d3f681ff8bdfe22d455bc0335d317c7f"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 17:07:00"
  condition:
    hash.sha256(0, filesize) == "2880c19f853059bae15a838d1320f728d3f681ff8bdfe22d455bc0335d317c7f"
}
```

### Sample 80: `e76d373869783dc1`

| Field | Value |
|---|---|
| SHA-256 | `e76d373869783dc10414994a1f2a052f8740e257372f4d4de17615cde3c87a3f` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-25 17:06:48` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, PMIX1.file, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c04e7af16f472c1354448f81b7a7ffe` |
| SHA-1 | `bfdbd7aeeca0e7d995cac4a2567a18bcab1eca50` |
| SHA-256 | `e76d373869783dc10414994a1f2a052f8740e257372f4d4de17615cde3c87a3f` |
| SHA3-384 | `32bc1810173e4cf1c191c01419e543bbaeea2cc0f3fa94301a424f88a54be0d63be9d6bcb1c34d3420fe469f200a042a` |
| IMPHASH | `6a368102586dffa13aabff685459b467` |
| TLSH | `T14BC61257BB859394C0D30E306A46C3D933D0FD1986E98B2B35CB6C03BE61DDB4E4A5A6` |
| SSDEEP | `196608:egc04g/pEb/JhzsW+rlS1+LSuExEnMkWhLIPdfeZCNJJ/T9BS3gVw8KC2jpk5eN3:14g/pEDQRrcoLDE6mhL6eZCNJFT9BS3R` |
| ICON-DHASH | `10e8c8e8e8ccd420` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_080_e76d3738
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e76d373869783dc10414994a1f2a052f8740e257372f4d4de17615cde3c87a3f"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 17:06:48"
  condition:
    hash.sha256(0, filesize) == "e76d373869783dc10414994a1f2a052f8740e257372f4d4de17615cde3c87a3f"
}
```

### Sample 81: `ef97a019a136f7e4`

| Field | Value |
|---|---|
| SHA-256 | `ef97a019a136f7e43ad006f8a7fd44236df44058053b5e01dd60755d24c86011` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-07-25 17:00:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b0d92f5955366d23ce0bfc548a40136` |
| SHA-1 | `00dc110cdaf86dc8e511c820c6d7a0c145d5cf5a` |
| SHA-256 | `ef97a019a136f7e43ad006f8a7fd44236df44058053b5e01dd60755d24c86011` |
| SHA3-384 | `12611bea0a9f2b17be1a6a38129af23bee53cec55032c1c4975b5dcb61d44f86f3aa14678ff41419a3b78e3564a2d4ea` |
| TLSH | `T156246D46EA414E23C0D7177AB6AF114A33329BA4D3DB730699286FB43B8779E0D63705` |
| TELFHASH | `t12d312db2933052266a61d924d9ec97b2162ec7071288fe33df36889c141a48ee53bc1f` |
| SSDEEP | `6144:pxrU3P5KyEowlaNKmHtNgrufdCzCaHIVL5FM/9uk/:pxrUBKyEowlaNKmHtNgrqdK2ni/l` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_ef97a019
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef97a019a136f7e43ad006f8a7fd44236df44058053b5e01dd60755d24c86011"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-25 17:00:21"
  condition:
    hash.sha256(0, filesize) == "ef97a019a136f7e43ad006f8a7fd44236df44058053b5e01dd60755d24c86011"
}
```

### Sample 82: `a1c56f08572af0a5`

| Field | Value |
|---|---|
| SHA-256 | `a1c56f08572af0a55fd0756b613047cd3da1c78654a06952f7fd9621208a88e7` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-25 17:00:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15aa882b9093ec46b91c65318d1555d6` |
| SHA-1 | `87065e63dce3958fea3b161b0fbae9b7b6954e63` |
| SHA-256 | `a1c56f08572af0a55fd0756b613047cd3da1c78654a06952f7fd9621208a88e7` |
| SHA3-384 | `1a2ee73ab71b60d36ee5324b87d7439cd241c12f5f5d7e63e030d017422a739b2612455a5ae39d96d12d37563746cd47` |
| TLSH | `T1A9931881BC828A2AC6D4237AF66E328D3761B3E5D2CF3117DD214B12778518B1D67FA1` |
| TELFHASH | `t187e06140fe764b1844e75634ecdd07b49511211761664710cf54daf0883f118a31cd5e` |
| SSDEEP | `1536:/MVGhGaG08HQleJNHixp38aPwG9FJ633L5C41KrOOgHbn2n:/MVGhGa4I9ToZIzgHb2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_a1c56f08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1c56f08572af0a55fd0756b613047cd3da1c78654a06952f7fd9621208a88e7"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-25 17:00:00"
  condition:
    hash.sha256(0, filesize) == "a1c56f08572af0a55fd0756b613047cd3da1c78654a06952f7fd9621208a88e7"
}
```

### Sample 83: `c8be56f0838af7ed`

| Field | Value |
|---|---|
| SHA-256 | `c8be56f0838af7ed2133b264c5159ae079a74796a761bbf0764eaec8987cc5b9` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-25 16:59:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `489a7d8d98d1cc478e4f96f148277c2a` |
| SHA-1 | `60aa2522499bc3614b3bbb8b854579019c672895` |
| SHA-256 | `c8be56f0838af7ed2133b264c5159ae079a74796a761bbf0764eaec8987cc5b9` |
| SHA3-384 | `19efc326f7ceb191dc261ac60840143eed1f67c019645b2466ec0a53beaf75cee840d8d88c02361c4a897bdfe486779c` |
| TLSH | `T191C35C0673180F47C5930AB01E3E3BE987BEE5E421E0BA8A650F9B564675DB7144AFCC` |
| SSDEEP | `1536:Womlj+GZ9yPwTlm55Tjoei9NyR4IEsFZ+FmY5tNVYvQHe3jt:Wo4w5BjoPqLFkmEXHe3jt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_c8be56f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8be56f0838af7ed2133b264c5159ae079a74796a761bbf0764eaec8987cc5b9"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-25 16:59:56"
  condition:
    hash.sha256(0, filesize) == "c8be56f0838af7ed2133b264c5159ae079a74796a761bbf0764eaec8987cc5b9"
}
```

### Sample 84: `beaec3c0d393c462`

| Field | Value |
|---|---|
| SHA-256 | `beaec3c0d393c4627f951eb7f96a9ff38fed82982705dbe1b66e85b2efc21c92` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-07-25 16:59:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70b3e71df56e7699d1a59e655ce2f918` |
| SHA-1 | `ffebe9f80cfba1f8aa8d3c99e47fefb501b5e548` |
| SHA-256 | `beaec3c0d393c4627f951eb7f96a9ff38fed82982705dbe1b66e85b2efc21c92` |
| SHA3-384 | `3523749f702b1464a51d0a6222ff64797422ba9eb9fa6e25063285fc72f542355b41d5dfe4dc4aff4282268b2e43c3bf` |
| TLSH | `T124C32A41F8825622CAD727BAF66E21CD332163E9E3DF7103CE255F21378658B0D67A81` |
| TELFHASH | `t11f31ef67ef901ecc17f6965490baf52616f832cd1f2411528b29af5b4c839c8702de27` |
| SSDEEP | `1536:yBEpm3SV4j3WqCz6eMKVhEag5+2AV3j6K639tp10DyPY4fPdHA32+wWgPUpidDpX:yBEMiV4z3eK1xo+lfPlA3xxgSHt2h` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_beaec3c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "beaec3c0d393c4627f951eb7f96a9ff38fed82982705dbe1b66e85b2efc21c92"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-25 16:59:54"
  condition:
    hash.sha256(0, filesize) == "beaec3c0d393c4627f951eb7f96a9ff38fed82982705dbe1b66e85b2efc21c92"
}
```

### Sample 85: `97e22980e077925d`

| Field | Value |
|---|---|
| SHA-256 | `97e22980e077925d8a249b948dcb9d7de5b20395386dcd86b9d42ef580fa3c33` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-25 16:59:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10d8383e53195c3b2aa589c3e900cf3e` |
| SHA-1 | `f88091ba4fa76aff047834e9c0f07944006fc372` |
| SHA-256 | `97e22980e077925d8a249b948dcb9d7de5b20395386dcd86b9d42ef580fa3c33` |
| SHA3-384 | `07821a12bc68ed9a36871952515ae547a2661c2744c676067014c05c2b796736241287a53d6c74af8204530c3a5c3d75` |
| TLSH | `T1F4B35BD5E243E0F5DD6645306172FB3BAD72E0BE132DDA82E3B58A32B8225C1D41675C` |
| TELFHASH | `t18731e2f9f2b208dd97e0a807d68f0b71ad0d767b312476bc09f72921367264091b9d36` |
| SSDEEP | `3072:Md0DvGUN4spxfT+FcXRGMd5wuP5j/8lkz99/rFQHYCbBr:Y0DvGE3xfTscQMdu2/ZpQHYCbBr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_97e22980
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97e22980e077925d8a249b948dcb9d7de5b20395386dcd86b9d42ef580fa3c33"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-25 16:59:49"
  condition:
    hash.sha256(0, filesize) == "97e22980e077925d8a249b948dcb9d7de5b20395386dcd86b9d42ef580fa3c33"
}
```

### Sample 86: `6d8249f94461455b`

| Field | Value |
|---|---|
| SHA-256 | `6d8249f94461455b8fdf679cb0c22c40e6d87d7ed7e79bcd7a48ada72e75ec92` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-07-25 16:58:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a7c208feff1f8143f042a38e01fb577` |
| SHA-1 | `4653f4095c08a8ee0985d3548c245d54bc9e4c14` |
| SHA-256 | `6d8249f94461455b8fdf679cb0c22c40e6d87d7ed7e79bcd7a48ada72e75ec92` |
| SHA3-384 | `b4c772cbf6682f8075009ab0d0ed13939d46a8e5365f26fab5dc6e4d8e11d7ca4da0749b3d78afdd1339bd779f7fda45` |
| TLSH | `T15C730112854094FAD0681873DEEF9FE91B1F1BFA637529673B76C79834020867BBCA41` |
| SSDEEP | `1536:VjqvyRgfCD7QpWJh/D9IJA3mtMGviTMNRHSLrMDZYFIfflg:VjMCDzh/D9Ie3meJTMNRyLoHa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_6d8249f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d8249f94461455b8fdf679cb0c22c40e6d87d7ed7e79bcd7a48ada72e75ec92"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:39"
  condition:
    hash.sha256(0, filesize) == "6d8249f94461455b8fdf679cb0c22c40e6d87d7ed7e79bcd7a48ada72e75ec92"
}
```

### Sample 87: `1ad0053c9f4d5810`

| Field | Value |
|---|---|
| SHA-256 | `1ad0053c9f4d5810a0433f6778c35cc7afbb765df0985621cf4c0346a2cff72f` |
| Family label | `Mirai` |
| File name | `nz.arc` |
| File type | `elf` |
| First seen | `2026-07-25 16:58:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ccaab535c7fdb826116f815f1553c5b` |
| SHA-1 | `573995b4861a29d76ea4ad697842d06f05dab3e1` |
| SHA-256 | `1ad0053c9f4d5810a0433f6778c35cc7afbb765df0985621cf4c0346a2cff72f` |
| SHA3-384 | `28ec898c405ee6a534cc1ed971a58c8881afc3a274b2582dd0470d501601b9ab6636764dde10bbfbc1a743f315763ac5` |
| TLSH | `T164E3BEA7F74B20A1C86306F407CB7BCD2E6762825F5B95E36C6B713B597A0DA0402BD1` |
| SSDEEP | `1536:PpkHkSTXXdfs7Zk4J26ACwVTg1Ia+keSVrBcGln6cMrRVOHxZJk3LgJ7s/LWnz:PpkHR27HDWVM1Idk9UWngRVOWbgJ7sq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_1ad0053c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ad0053c9f4d5810a0433f6778c35cc7afbb765df0985621cf4c0346a2cff72f"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:38"
  condition:
    hash.sha256(0, filesize) == "1ad0053c9f4d5810a0433f6778c35cc7afbb765df0985621cf4c0346a2cff72f"
}
```

### Sample 88: `3d5b9c3821fae13d`

| Field | Value |
|---|---|
| SHA-256 | `3d5b9c3821fae13dea78b113f90985fed0b7f43b2d975411907130e48bbfcd2c` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-07-25 16:58:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edeb0a83030d1efdcebcabaaa955108d` |
| SHA-1 | `5e37bf7b91db4b6ccff8e6ccf56bbcdec31cee4d` |
| SHA-256 | `3d5b9c3821fae13dea78b113f90985fed0b7f43b2d975411907130e48bbfcd2c` |
| SHA3-384 | `24795c9079224c3970f289178f05fad006051d1c399948cbfe750e51eda2561bd01fc3e7c3415f288b9a3f7c1e25829d` |
| TLSH | `T1B9E3D61E7E618F3CFBE982304BB79E26975833D636D1D595D1ACE6001E2028E241FFA4` |
| TELFHASH | `t168115b1c497812f097751c9d6beeff72e59070ef06266d378e00e86daa2dd419e00c1c` |
| SSDEEP | `3072:pJG2CYTcYpA5C7gMtspYX29A8uXENQDw/HKK9tedw+T+7oywvyMiRZtkpUptH/th:pJG2CYTcYpA5C7gMtspYX29A8uXENQDY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_3d5b9c38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d5b9c3821fae13dea78b113f90985fed0b7f43b2d975411907130e48bbfcd2c"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:37"
  condition:
    hash.sha256(0, filesize) == "3d5b9c3821fae13dea78b113f90985fed0b7f43b2d975411907130e48bbfcd2c"
}
```

### Sample 89: `e9df735ea30bc4e9`

| Field | Value |
|---|---|
| SHA-256 | `e9df735ea30bc4e950ab968c75569b83d5c6bb0d2e4a5e442ff21c3b1320cb01` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-25 16:58:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b1b906c2fd668d818421a72d658aa1e` |
| SHA-1 | `452b5134586c0b4de8dea14bcbe4a3edb1c6700a` |
| SHA-256 | `e9df735ea30bc4e950ab968c75569b83d5c6bb0d2e4a5e442ff21c3b1320cb01` |
| SHA3-384 | `cb019bbbbf2dab7db91e2b7b12405078a295fd7539c1f1f07665f63fbeb1d63dbbd10dba1feaec1fa9f24b7d81abb4a5` |
| TLSH | `T135E2E0B1A5C0AD04C7A014FE8D998FC3AF4D4F79E1D2774B2A08575B928318A67BE4D3` |
| SSDEEP | `768:avRZrkQEbcMLSWN3Sz5atCpQNrnhS6Bz96z/T4Ps3UozB1:QReLN0pohBBMrTzT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_e9df735e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9df735ea30bc4e950ab968c75569b83d5c6bb0d2e4a5e442ff21c3b1320cb01"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:36"
  condition:
    hash.sha256(0, filesize) == "e9df735ea30bc4e950ab968c75569b83d5c6bb0d2e4a5e442ff21c3b1320cb01"
}
```

### Sample 90: `405b89d887891e0d`

| Field | Value |
|---|---|
| SHA-256 | `405b89d887891e0d43b349c8415edb18d75773205bc98a11676d6f7150bba858` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-25 16:58:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa9b53884143e6becc80c5ee0a5ed752` |
| SHA-1 | `e037841b9ac68e793d258c74d9f93867f43181ef` |
| SHA-256 | `405b89d887891e0d43b349c8415edb18d75773205bc98a11676d6f7150bba858` |
| SHA3-384 | `c1fd533c98edbd199780ec1148d557b6fa3de44031c50a7ea987712e1e5ac1f98304aaba071ed78813cf45a20e240b89` |
| TLSH | `T14023F174B7880DE9DEBB6AA32D50A6873B7D4FDA6503CE81280C0FC655839287715CEC` |
| SSDEEP | `768:Rd9F63jUNTmVcehlibeJAeqSvErYqN86hzsOXM4RHJqyNZYxuwUHjLAug1+fNfRV:lF6iSmgibKQGErYwrzsMv3ecIN1+pRdz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_405b89d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "405b89d887891e0d43b349c8415edb18d75773205bc98a11676d6f7150bba858"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:35"
  condition:
    hash.sha256(0, filesize) == "405b89d887891e0d43b349c8415edb18d75773205bc98a11676d6f7150bba858"
}
```

### Sample 91: `5a69f79a35ba2ef2`

| Field | Value |
|---|---|
| SHA-256 | `5a69f79a35ba2ef2714c2e0babded61cd52f4bac1b67a53fdcf7361ca261670a` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-25 16:58:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f09686f346f5a893d8d8851019f9f5a` |
| SHA-1 | `1f6674c0fcf51a58361cbb0ac58f09548a5b2da7` |
| SHA-256 | `5a69f79a35ba2ef2714c2e0babded61cd52f4bac1b67a53fdcf7361ca261670a` |
| SHA3-384 | `204b785bedb708b65caaae17566ccb89cd2fce7dc4f11cb4a384c2883a02f6fdbbdb7201c88c28778d319c00e6d498e8` |
| TLSH | `T11BF30715BB610FFBE89BCC3705E92B0618CD565732B87F36B530D918B64B28B25E3960` |
| SSDEEP | `3072:RSMQ/jMdZtaieD+fK+QKWGNOfpolzt9sDUzZTHU:RSMWMdZsjD+fK+QKWGNOfp69sD+HU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_5a69f79a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a69f79a35ba2ef2714c2e0babded61cd52f4bac1b67a53fdcf7361ca261670a"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:35"
  condition:
    hash.sha256(0, filesize) == "5a69f79a35ba2ef2714c2e0babded61cd52f4bac1b67a53fdcf7361ca261670a"
}
```

### Sample 92: `eb3f90ca702eb638`

| Field | Value |
|---|---|
| SHA-256 | `eb3f90ca702eb63880546c67d1530a9a994e66fdca6d0567b2860887fdcba14b` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-07-25 16:58:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d1f8674b83f0e45fe44c289bc5b2127` |
| SHA-1 | `8aed28fe6d23f513a74fe8103a8a07b3a6ef0559` |
| SHA-256 | `eb3f90ca702eb63880546c67d1530a9a994e66fdca6d0567b2860887fdcba14b` |
| SHA3-384 | `d26361769e64b42078833fa9e867cb0fb4cbcab80ca7d5b9b858afee0642ea1993878c8e4370ef3105042265fe33d78a` |
| TLSH | `T1BB230271F23DDD28E5E08EB679F4186750A24B2DE2EE703614055B8CD09F60A34BADD3` |
| SSDEEP | `768:IlRnxlPQhwrSdyGsBpxd7A0a+YMAi76lqhpQA3CvFGSd4jlT2qqYE/YVqYs3Uozp:sRArdyhBF7pfgi7UeDyGKIlzPLVszp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_eb3f90ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb3f90ca702eb63880546c67d1530a9a994e66fdca6d0567b2860887fdcba14b"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:34"
  condition:
    hash.sha256(0, filesize) == "eb3f90ca702eb63880546c67d1530a9a994e66fdca6d0567b2860887fdcba14b"
}
```

### Sample 93: `1691335759096e56`

| Field | Value |
|---|---|
| SHA-256 | `1691335759096e562729e38e60abbf270a7c285c241ea095a2e69e737a8bdbcd` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-25 16:58:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50e97e03937457e907234f6f78614a00` |
| SHA-1 | `0155955bcc8ccafd7408b366c7c6c9036a57ffd0` |
| SHA-256 | `1691335759096e562729e38e60abbf270a7c285c241ea095a2e69e737a8bdbcd` |
| SHA3-384 | `b78f56c41ac22c7929bcb94871d14fdb832dd1acda62aa6ccad461dad8d5624f51676a309f175d72550919196b2f627a` |
| TLSH | `T12233026789FD9288D47DB1B76CEA7E720230D8875108A4263F8C297D9DCBE5C57153C2` |
| SSDEEP | `1536:ETDIHJFmoOaW59p9LyiwcV79mLOFiiaYnouy8Hyg:QDWJbR69Pwc19DLoutn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_16913357
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1691335759096e562729e38e60abbf270a7c285c241ea095a2e69e737a8bdbcd"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:33"
  condition:
    hash.sha256(0, filesize) == "1691335759096e562729e38e60abbf270a7c285c241ea095a2e69e737a8bdbcd"
}
```

### Sample 94: `72715b5e55871336`

| Field | Value |
|---|---|
| SHA-256 | `72715b5e55871336b8edc4d23d970792b1422f052c7c599c191d72b3d191f5eb` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-07-25 16:58:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d045723afe105822684c1215764aa6f2` |
| SHA-1 | `d2d38c48e39cb46149cc486f70549e40e39f47c4` |
| SHA-256 | `72715b5e55871336b8edc4d23d970792b1422f052c7c599c191d72b3d191f5eb` |
| SHA3-384 | `2cda1b470e551d06389a59d2bc382efbfe3e4764ba54dc94cf5a184d2734b521f5988f06a3dd321689c4ed4e1de3a9cb` |
| TLSH | `T1E0D33A46F8814A21D5DB12BEFA2E218E331317B8E3DE72139E255F2133C669B0D77A45` |
| TELFHASH | `t1d6b012551b0826fc17c1428884f4a02523fc301a00010047888e4f4602009027e2b823` |
| SSDEEP | `3072:Y/KgDAvbqH7rJ4cSJN+UjX7qapNoOxH4BatMIHLRBRo:eKQrJ4PAUjX+aM84BTIHLRBRo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_72715b5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72715b5e55871336b8edc4d23d970792b1422f052c7c599c191d72b3d191f5eb"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:33"
  condition:
    hash.sha256(0, filesize) == "72715b5e55871336b8edc4d23d970792b1422f052c7c599c191d72b3d191f5eb"
}
```

### Sample 95: `ca51b527012988ed`

| Field | Value |
|---|---|
| SHA-256 | `ca51b527012988ed642adf53be6123f74fb2bd0017871a07d935f69fd321518c` |
| Family label | `Mirai` |
| File name | `nz.m68k` |
| File type | `elf` |
| First seen | `2026-07-25 16:58:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd90463bdef0a76a0f0a3211d4ae13a8` |
| SHA-1 | `7ada067c7334f5a24fe0b16f28139cb2336eb4f0` |
| SHA-256 | `ca51b527012988ed642adf53be6123f74fb2bd0017871a07d935f69fd321518c` |
| SHA3-384 | `02a5da686a18c08a2e6fe63396ef4a85784c6725795158649000862c31bc4969f2ed86fe6bcf1102e65872ad3dc31c8f` |
| TLSH | `T11FC34BCAB801DE7DF90FD5BA542B1D0AB921A3515683172623ABFD936D321E4BD03F81` |
| SSDEEP | `3072:qjZpROP0/IM1PQsekJHkzQYjmTXqKYt+RtFm+B+:ERO8/IM1oss0gmLqERtFm+B+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_ca51b527
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca51b527012988ed642adf53be6123f74fb2bd0017871a07d935f69fd321518c"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:32"
  condition:
    hash.sha256(0, filesize) == "ca51b527012988ed642adf53be6123f74fb2bd0017871a07d935f69fd321518c"
}
```

### Sample 96: `ffbfd13c46e2940b`

| Field | Value |
|---|---|
| SHA-256 | `ffbfd13c46e2940bad1fb91a9ce11e282cdb4e22acd648e5fcdf13ac9b1ecd30` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-25 16:57:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44b7b58590a28f5f7ac666fc7a6e2798` |
| SHA-1 | `61cbb608f971011a2e5a61173ae9f3cc7d9a46cc` |
| SHA-256 | `ffbfd13c46e2940bad1fb91a9ce11e282cdb4e22acd648e5fcdf13ac9b1ecd30` |
| SHA3-384 | `2508cb12dab75d0d4f96c937e67a07fa56ccfdf2b3f04b834da23bde43d1ffb3d1c0780d6c69605ac8ede26de39b5ffd` |
| TLSH | `T1D7B35CC5E243D0F9EC6605742136FB3BDE72E4BA1229DA43D3F89B66AC52681C40679C` |
| TELFHASH | `t12a31e8b8516708986bc0a842b18daf32cd1d272b321077fb4df7642531a3582877fc39` |
| SSDEEP | `3072:jHgHynlsNpZEWPMwZ83h1VvP+S2NUsDMHmn6n8:TgHynmpZEWkH3hmfMHm68` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_ffbfd13c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffbfd13c46e2940bad1fb91a9ce11e282cdb4e22acd648e5fcdf13ac9b1ecd30"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-25 16:57:36"
  condition:
    hash.sha256(0, filesize) == "ffbfd13c46e2940bad1fb91a9ce11e282cdb4e22acd648e5fcdf13ac9b1ecd30"
}
```

### Sample 97: `513fdafabf21c835`

| Field | Value |
|---|---|
| SHA-256 | `513fdafabf21c835cebd9a81046e705f8b0c1722129b90c25bf48e1594cf2cdb` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-25 16:57:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0922f98b6900f30abe48313b38e1c3e3` |
| SHA-1 | `1047061069938b96c354fe3e7c12c10bf0a59384` |
| SHA-256 | `513fdafabf21c835cebd9a81046e705f8b0c1722129b90c25bf48e1594cf2cdb` |
| SHA3-384 | `e5f2b83d6a04b788a3a624b3249e031fbebdd4a33326a000028315f695500b75e3ef0bd80db77606a5ae95aa04cb97bf` |
| TLSH | `T15FC32980F58F85F6C50B8D3060A6F63FDA31D5A981A3C66EDF949F72CA63581921238D` |
| TELFHASH | `t1363149b9fa6208ed6fc05d03d34d9321ca0ee6bb382436fd19f265a036b24015079c39` |
| SSDEEP | `3072:U8LBPXPd4yN/ExuVLgv3fv7/tGTXLVOAPRX9qs8Hp:UsPXPd4yNMIVEv3X7t+LCrHp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_513fdafa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "513fdafabf21c835cebd9a81046e705f8b0c1722129b90c25bf48e1594cf2cdb"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-25 16:57:34"
  condition:
    hash.sha256(0, filesize) == "513fdafabf21c835cebd9a81046e705f8b0c1722129b90c25bf48e1594cf2cdb"
}
```

### Sample 98: `a66945cecdcbd17b`

| Field | Value |
|---|---|
| SHA-256 | `a66945cecdcbd17b30aff446095c7d661a97dfcacdc39b1a4a1de4aa9c19161a` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-25 16:57:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0517e4d80b51bd0611f4494b3ff6e6d3` |
| SHA-1 | `0740de66cfbb19cbb7a561aeca722543bdb28b0b` |
| SHA-256 | `a66945cecdcbd17b30aff446095c7d661a97dfcacdc39b1a4a1de4aa9c19161a` |
| SHA3-384 | `a1b2b3b143a004c9cd8d5be96630555618bea41f11fe60a11d758347d0d5703562f9e6c4e44c923da2c5f3689e1986a9` |
| TLSH | `T1E6C30802B9C18DFDC089C034577FB93AD825F0DE0239B2AB6BD4AF27694DE901A1DE55` |
| TELFHASH | `t1562147742ee3395ca2d7438a730eee2ad5f20a116cc2b5969f0b7de84905fc41d42462` |
| SSDEEP | `3072:9QUXFHNzBNaH/41XvHWCh690jCCqRTdJrTqytsXBmL:6UXFtzBNaf41/HWCsJrTWXBmL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_a66945ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a66945cecdcbd17b30aff446095c7d661a97dfcacdc39b1a4a1de4aa9c19161a"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-25 16:57:31"
  condition:
    hash.sha256(0, filesize) == "a66945cecdcbd17b30aff446095c7d661a97dfcacdc39b1a4a1de4aa9c19161a"
}
```

### Sample 99: `c0a3d78c3b6fd101`

| Field | Value |
|---|---|
| SHA-256 | `c0a3d78c3b6fd101bced1d133cbef5e1e7f731b161cff64a651ce537d246370f` |
| Family label | `unknown` |
| File name | `nz.sh` |
| File type | `sh` |
| First seen | `2026-07-25 16:57:28` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94fe567e721a7fb49b1a5fc0c7711e68` |
| SHA-1 | `cd06b04bb364590056fd539a7279b2f1f0ea405e` |
| SHA-256 | `c0a3d78c3b6fd101bced1d133cbef5e1e7f731b161cff64a651ce537d246370f` |
| SHA3-384 | `4a2a6adc6ad9759a1342c43697474c039cba0e361fa1f4d2647ed237627f0dd5c6bd961c54056471cdf2b82cfd6d106b` |
| TLSH | `T1C221A7D6100543302DA2DD23FABA4C2D70B5A1DA54D39FDD64D8B8F681CDE2D394968F` |
| SSDEEP | `24:ItGDZsGp6pIhOEGxs3GcLAGO3PsGaoGfTRfTGFC:i/5Ep3SYQyTFTGFC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_c0a3d78c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0a3d78c3b6fd101bced1d133cbef5e1e7f731b161cff64a651ce537d246370f"
    family = "unknown"
    file_name = "nz.sh"
    file_type = "sh"
    first_seen = "2026-07-25 16:57:28"
  condition:
    hash.sha256(0, filesize) == "c0a3d78c3b6fd101bced1d133cbef5e1e7f731b161cff64a651ce537d246370f"
}
```

### Sample 100: `94359c560a51affe`

| Field | Value |
|---|---|
| SHA-256 | `94359c560a51affe2473af30ac83d559877975d2b8fd9c825c1c6e5b43002d5f` |
| Family label | `Mirai` |
| File name | `nz.sh4` |
| File type | `elf` |
| First seen | `2026-07-25 16:57:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28ddffa7dc1471802e1b20eea0e4abd3` |
| SHA-1 | `cbc5db370d2be0830f717ad4fdd996b82146d3a1` |
| SHA-256 | `94359c560a51affe2473af30ac83d559877975d2b8fd9c825c1c6e5b43002d5f` |
| SHA3-384 | `a113be490f57f103f302df4ee6e777ebc647ad56eadb6d9b8c4a90c7eb914a7816d7278ff4af9abf04eb18bc31d79825` |
| TLSH | `T132B3AE32D8295CD8C1944178E4A4BD361B23E18162772EFB1BE5C6F64487ED6F849BF0` |
| SSDEEP | `1536:C/aRpT3mojgnYduM+4idUdj6rxAZLKfVN275mp19C+Vaarx+H/gl:CCRpb5gncu7NEj6r2ZufqAp19PT1+Ha` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_94359c56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94359c560a51affe2473af30ac83d559877975d2b8fd9c825c1c6e5b43002d5f"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-25 16:57:27"
  condition:
    hash.sha256(0, filesize) == "94359c560a51affe2473af30ac83d559877975d2b8fd9c825c1c6e5b43002d5f"
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
 * Generated: 2026-07-26T04:02:05.754984+00:00
 */

rule MalwareBazaar_unknown_001_0bc71f56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc71f56b650c93a4f50e11ba41af659c46fba843cd019e2dbb152a536ed714f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 03:52:29"
  condition:
    hash.sha256(0, filesize) == "0bc71f56b650c93a4f50e11ba41af659c46fba843cd019e2dbb152a536ed714f"
}

rule MalwareBazaar_unknown_002_63c5f9fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c5f9fbf4bebf78e476a90b5115b46f493ef3be5a56dafcec6c825160913645"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 03:41:28"
  condition:
    hash.sha256(0, filesize) == "63c5f9fbf4bebf78e476a90b5115b46f493ef3be5a56dafcec6c825160913645"
}

rule MalwareBazaar_unknown_003_c7dc544e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7dc544ed14e75219a4eb0b02690d47e412f615f2f1329f99a00337a72b17256"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 03:38:38"
  condition:
    hash.sha256(0, filesize) == "c7dc544ed14e75219a4eb0b02690d47e412f615f2f1329f99a00337a72b17256"
}

rule MalwareBazaar_CoinMiner_004_2fed5d05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fed5d0552cf80eaae1928150238397a632ebb9521e98129daa71eb46ea1f113"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 02:53:11"
  condition:
    hash.sha256(0, filesize) == "2fed5d0552cf80eaae1928150238397a632ebb9521e98129daa71eb46ea1f113"
}

rule MalwareBazaar_unknown_005_3a0ecd12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a0ecd128bddb650c684af39de612fb50953c76e1be4677afff1b0a3ae7e01f8"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 02:52:30"
  condition:
    hash.sha256(0, filesize) == "3a0ecd128bddb650c684af39de612fb50953c76e1be4677afff1b0a3ae7e01f8"
}

rule MalwareBazaar_unknown_006_2cf0bc83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cf0bc8361e716ffb2dbfa4c680028bf6b2dcbcd84a14c511dfec0af523860c8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 02:25:21"
  condition:
    hash.sha256(0, filesize) == "2cf0bc8361e716ffb2dbfa4c680028bf6b2dcbcd84a14c511dfec0af523860c8"
}

rule MalwareBazaar_unknown_007_6543a188
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6543a1888c58d583be80f8f2749c4a0631c6f3d82a9b64a42b657d874f5d2b90"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 01:52:30"
  condition:
    hash.sha256(0, filesize) == "6543a1888c58d583be80f8f2749c4a0631c6f3d82a9b64a42b657d874f5d2b90"
}

rule MalwareBazaar_unknown_008_7053ae12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7053ae123ff7a0f94df6b88f2110e66c9797b8b32db55e6d78d3035221a268aa"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-26 01:23:58"
  condition:
    hash.sha256(0, filesize) == "7053ae123ff7a0f94df6b88f2110e66c9797b8b32db55e6d78d3035221a268aa"
}

rule MalwareBazaar_Phorpiex_009_09b7fa9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09b7fa9a1bc1c3f34bcca306c1f9e3971083ebf265adf5f7684e4a320b5d562e"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 00:56:04"
  condition:
    hash.sha256(0, filesize) == "09b7fa9a1bc1c3f34bcca306c1f9e3971083ebf265adf5f7684e4a320b5d562e"
}

rule MalwareBazaar_unknown_010_d7be04c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7be04c19b1d908e4d33edfdcf3fbcb15812763edb905ce1fa46233368181086"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-26 00:52:31"
  condition:
    hash.sha256(0, filesize) == "d7be04c19b1d908e4d33edfdcf3fbcb15812763edb905ce1fa46233368181086"
}

rule MalwareBazaar_unknown_011_a0e0ed3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0e0ed3de12c74a73c79f5ec6beb9b73d663d7795ff90d2159a183c9af153975"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-26 00:42:00"
  condition:
    hash.sha256(0, filesize) == "a0e0ed3de12c74a73c79f5ec6beb9b73d663d7795ff90d2159a183c9af153975"
}

rule MalwareBazaar_unknown_012_5414c823
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5414c823040b85495f88add29911ec42836277d9b1732468f70c29140cb198be"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 00:36:27"
  condition:
    hash.sha256(0, filesize) == "5414c823040b85495f88add29911ec42836277d9b1732468f70c29140cb198be"
}

rule MalwareBazaar_unknown_013_d3eb1b2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3eb1b2e2fab88aad1ee2766aa4c0e8dc48f610f8c43bfdd654d0b35d926b0f3"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-26 00:31:04"
  condition:
    hash.sha256(0, filesize) == "d3eb1b2e2fab88aad1ee2766aa4c0e8dc48f610f8c43bfdd654d0b35d926b0f3"
}

rule MalwareBazaar_Hajime_014_77a84e50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77a84e50efc64c4248f38bc33aef956f4f8ea899760185f17caed1711da14981"
    family = "Hajime"
    file_name = "i"
    file_type = "elf"
    first_seen = "2026-07-26 00:31:03"
  condition:
    hash.sha256(0, filesize) == "77a84e50efc64c4248f38bc33aef956f4f8ea899760185f17caed1711da14981"
}

rule MalwareBazaar_unknown_015_63559cb8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63559cb87098de64cbe5f1d981bf782283a8e24e3d81926a3ddb80cae5b5d856"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-26 00:26:11"
  condition:
    hash.sha256(0, filesize) == "63559cb87098de64cbe5f1d981bf782283a8e24e3d81926a3ddb80cae5b5d856"
}

rule MalwareBazaar_Worm_Virut_016_9be1d33e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9be1d33e17a0048a7b145cdc604e60048dc8bc26decd065ec3b5404a58bce9ef"
    family = "Worm.Virut"
    file_name = "studiomdl.exe"
    file_type = "exe"
    first_seen = "2026-07-26 00:23:38"
  condition:
    hash.sha256(0, filesize) == "9be1d33e17a0048a7b145cdc604e60048dc8bc26decd065ec3b5404a58bce9ef"
}

rule MalwareBazaar_unknown_017_977399df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "977399df67a510fdb6fb6f9eb7a63a5bc8a178e0dd6cd6321c02b68c94681cef"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-26 00:17:15"
  condition:
    hash.sha256(0, filesize) == "977399df67a510fdb6fb6f9eb7a63a5bc8a178e0dd6cd6321c02b68c94681cef"
}

rule MalwareBazaar_unknown_018_8fc661e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fc661e3c83b3108e1281d1270c26fcfe19038916ee7f14142880a6807416343"
    family = "unknown"
    file_name = "8fc661e3c83b3108e1281d1270c26fcfe19038916ee7f14142880a6807416343"
    file_type = "sh"
    first_seen = "2026-07-26 00:00:47"
  condition:
    hash.sha256(0, filesize) == "8fc661e3c83b3108e1281d1270c26fcfe19038916ee7f14142880a6807416343"
}

rule MalwareBazaar_unknown_019_62ac7832
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62ac78326c0ebec72a44b0037290c5b221c75a6cf1a7281d2795691581f67058"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-26 00:00:11"
  condition:
    hash.sha256(0, filesize) == "62ac78326c0ebec72a44b0037290c5b221c75a6cf1a7281d2795691581f67058"
}

rule MalwareBazaar_unknown_020_c97311cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c97311cbfd923b181a76dbc92ff029e2dd33870458bc24c73be9d5074f388e66"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 23:52:33"
  condition:
    hash.sha256(0, filesize) == "c97311cbfd923b181a76dbc92ff029e2dd33870458bc24c73be9d5074f388e66"
}

rule MalwareBazaar_unknown_021_170175f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "170175f699d31ba16e1def49684a8b37034863a045a6ab9910e91dd568049b9b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 23:29:14"
  condition:
    hash.sha256(0, filesize) == "170175f699d31ba16e1def49684a8b37034863a045a6ab9910e91dd568049b9b"
}

rule MalwareBazaar_unknown_022_ad61a410
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad61a41009aaf87bc4c2a33f5d5ae7ed2491ef00d82bc024882b041af9334b90"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-25 23:20:03"
  condition:
    hash.sha256(0, filesize) == "ad61a41009aaf87bc4c2a33f5d5ae7ed2491ef00d82bc024882b041af9334b90"
}

rule MalwareBazaar_unknown_023_fd046608
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd0466080f4a0836beab8ddd824540dcf47a32e4f1cbc95274a455d18f3dfbf9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 23:03:31"
  condition:
    hash.sha256(0, filesize) == "fd0466080f4a0836beab8ddd824540dcf47a32e4f1cbc95274a455d18f3dfbf9"
}

rule MalwareBazaar_unknown_024_92527894
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "925278940fe96bc04d406ebdffa8e3431b64e76ff0d22b23b53b47d5cd360200"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 22:52:31"
  condition:
    hash.sha256(0, filesize) == "925278940fe96bc04d406ebdffa8e3431b64e76ff0d22b23b53b47d5cd360200"
}

rule MalwareBazaar_Phorpiex_025_58e16785
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58e1678501dae58d824c8e305be61ee55f642af2e0c36259cf14501cf58c9687"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 22:26:03"
  condition:
    hash.sha256(0, filesize) == "58e1678501dae58d824c8e305be61ee55f642af2e0c36259cf14501cf58c9687"
}

rule MalwareBazaar_NanoCore_026_56c44ee6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56c44ee6a052c9679d8dd05d2338bf2c2a0a2e0ce0242bf5472e870768ab7466"
    family = "NanoCore"
    file_name = "E31AB3ECA717E815F942F242E1CCCC09.exe"
    file_type = "exe"
    first_seen = "2026-07-25 22:25:04"
  condition:
    hash.sha256(0, filesize) == "56c44ee6a052c9679d8dd05d2338bf2c2a0a2e0ce0242bf5472e870768ab7466"
}

rule MalwareBazaar_unknown_027_55035e81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55035e8193aa4548ea63d72c51744739cb51b1fb3e19a40907233608c62473c1"
    family = "unknown"
    file_name = "55035e8193aa4548ea63d72c51744739cb51b1fb3e19a40907233608c62473c1"
    file_type = "sh"
    first_seen = "2026-07-25 22:16:56"
  condition:
    hash.sha256(0, filesize) == "55035e8193aa4548ea63d72c51744739cb51b1fb3e19a40907233608c62473c1"
}

rule MalwareBazaar_CoinMiner_028_1a5fc161
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a5fc161c39e639f6c053ad79040e2f18827c0d8df3e39b5202a3920fcc9b4b9"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 22:16:14"
  condition:
    hash.sha256(0, filesize) == "1a5fc161c39e639f6c053ad79040e2f18827c0d8df3e39b5202a3920fcc9b4b9"
}

rule MalwareBazaar_unknown_029_e69cad1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e69cad1fc4f37b152dec7c2c8c80b9516ff10a28a04041fdeb0294bd8f0dbf78"
    family = "unknown"
    file_name = "e69cad1fc4f37b152dec7c2c8c80b9516ff10a28a04041fdeb0294bd8f0dbf78"
    file_type = "sh"
    first_seen = "2026-07-25 22:06:59"
  condition:
    hash.sha256(0, filesize) == "e69cad1fc4f37b152dec7c2c8c80b9516ff10a28a04041fdeb0294bd8f0dbf78"
}

rule MalwareBazaar_unknown_030_f1f22912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1f22912b7a9999e3df0c2deea7158c9b64a0bd5370710f7cac9e745683194ff"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 21:52:30"
  condition:
    hash.sha256(0, filesize) == "f1f22912b7a9999e3df0c2deea7158c9b64a0bd5370710f7cac9e745683194ff"
}

rule MalwareBazaar_unknown_031_983755ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "983755ac9112bdf7487e53017fd2f14af59c0537bcad36ec302d92563636df70"
    family = "unknown"
    file_name = "983755ac9112bdf7487e53017fd2f14af59c0537bcad36ec302d92563636df70"
    file_type = "elf"
    first_seen = "2026-07-25 21:36:44"
  condition:
    hash.sha256(0, filesize) == "983755ac9112bdf7487e53017fd2f14af59c0537bcad36ec302d92563636df70"
}

rule MalwareBazaar_unknown_032_2c8301d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c8301d65528cc47b1d99ceb850d39bfb4d5c90ca771b9ec483280e3be67dcd5"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-25 21:32:27"
  condition:
    hash.sha256(0, filesize) == "2c8301d65528cc47b1d99ceb850d39bfb4d5c90ca771b9ec483280e3be67dcd5"
}

rule MalwareBazaar_unknown_033_620ba6ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "620ba6ad0d361d38e0af1f8f472f37b1a8a58a2fc13f278be085b5ed319444a9"
    family = "unknown"
    file_name = "620ba6ad0d361d38e0af1f8f472f37b1a8a58a2fc13f278be085b5ed319444a9.bin"
    file_type = "unknown"
    first_seen = "2026-07-25 21:25:18"
  condition:
    hash.sha256(0, filesize) == "620ba6ad0d361d38e0af1f8f472f37b1a8a58a2fc13f278be085b5ed319444a9"
}

rule MalwareBazaar_unknown_034_5d6baae8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d6baae899049b430146689556c6b7e9668996b5e64449ef733ac061cf61451b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 21:21:18"
  condition:
    hash.sha256(0, filesize) == "5d6baae899049b430146689556c6b7e9668996b5e64449ef733ac061cf61451b"
}

rule MalwareBazaar_unknown_035_26be0774
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26be0774f54837706f579d6e75cc8ae2262ec54aeee2d5944cb2cd3308ffe1f3"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-25 21:16:20"
  condition:
    hash.sha256(0, filesize) == "26be0774f54837706f579d6e75cc8ae2262ec54aeee2d5944cb2cd3308ffe1f3"
}

rule MalwareBazaar_WannaCry_036_343e2946
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "343e294624c935431cf4ec28cf998a7e0d459c9b41361d539f221406fee5a16d"
    family = "WannaCry"
    file_name = "343e294624c935431cf4ec28cf998a7e0d459c9b41361d539f221406fee5a16d"
    file_type = "exe"
    first_seen = "2026-07-25 21:15:16"
  condition:
    hash.sha256(0, filesize) == "343e294624c935431cf4ec28cf998a7e0d459c9b41361d539f221406fee5a16d"
}

rule MalwareBazaar_Phorpiex_037_9ca662bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ca662bf15428a6d68ce134206cdaac5a4f5146ea6e8d3637a33627487106be3"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 21:08:33"
  condition:
    hash.sha256(0, filesize) == "9ca662bf15428a6d68ce134206cdaac5a4f5146ea6e8d3637a33627487106be3"
}

rule MalwareBazaar_unknown_038_d1515ff3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1515ff3e467c83dff345353f38acc27ac1788964a7b5a320fb2f3b1c0eb63a6"
    family = "unknown"
    file_name = "d1515ff3e467c83dff345353f38acc27ac1788964a7b5a320fb2f3b1c0eb63a6"
    file_type = "unknown"
    first_seen = "2026-07-25 21:06:43"
  condition:
    hash.sha256(0, filesize) == "d1515ff3e467c83dff345353f38acc27ac1788964a7b5a320fb2f3b1c0eb63a6"
}

rule MalwareBazaar_unknown_039_5486a8ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5486a8ff6e41a7c383aa88eed922b79361344fd0d41b8302c929ebd9600a7531"
    family = "unknown"
    file_name = "5486a8ff6e41a7c383aa88eed922b79361344fd0d41b8302c929ebd9600a7531"
    file_type = "sh"
    first_seen = "2026-07-25 21:06:02"
  condition:
    hash.sha256(0, filesize) == "5486a8ff6e41a7c383aa88eed922b79361344fd0d41b8302c929ebd9600a7531"
}

rule MalwareBazaar_unknown_040_6cd950c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cd950c1729a136be666fe0f23a9de400124c0e301a03b7f0095f8b41576bb11"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 20:52:32"
  condition:
    hash.sha256(0, filesize) == "6cd950c1729a136be666fe0f23a9de400124c0e301a03b7f0095f8b41576bb11"
}

rule MalwareBazaar_ValleyRAT_041_6ca95860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ca95860452483923f168b85287051f7914f8d30c608147542237262a603ffb6"
    family = "ValleyRAT"
    file_name = "5D5477120A75161AD3ED0023C36F3284.exe"
    file_type = "exe"
    first_seen = "2026-07-25 20:50:06"
  condition:
    hash.sha256(0, filesize) == "6ca95860452483923f168b85287051f7914f8d30c608147542237262a603ffb6"
}

rule MalwareBazaar_unknown_042_afc5fa13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afc5fa1343a544b6a918ed331efc7ba9ee88c045bc6fd8fb9ac662107c552295"
    family = "unknown"
    file_name = "Sheldon.7z"
    file_type = "7z"
    first_seen = "2026-07-25 20:03:08"
  condition:
    hash.sha256(0, filesize) == "afc5fa1343a544b6a918ed331efc7ba9ee88c045bc6fd8fb9ac662107c552295"
}

rule MalwareBazaar_unknown_043_ca7fa72c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca7fa72c6642d5cb83ea60ce873964eff752e6ad66aac959da25d722ce19256e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 19:52:31"
  condition:
    hash.sha256(0, filesize) == "ca7fa72c6642d5cb83ea60ce873964eff752e6ad66aac959da25d722ce19256e"
}

rule MalwareBazaar_unknown_044_bcee095a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcee095afc805eb5f164059598f97b5b01d1015afb496b19c640a4d01766765c"
    family = "unknown"
    file_name = "0e649edddaf-12.msi"
    file_type = "msi"
    first_seen = "2026-07-25 19:50:30"
  condition:
    hash.sha256(0, filesize) == "bcee095afc805eb5f164059598f97b5b01d1015afb496b19c640a4d01766765c"
}

rule MalwareBazaar_unknown_045_3100f593
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3100f5931301a7968b274bc718c8363fe8b73cab7b997cf4ae161e39d06197ef"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-25 19:47:50"
  condition:
    hash.sha256(0, filesize) == "3100f5931301a7968b274bc718c8363fe8b73cab7b997cf4ae161e39d06197ef"
}

rule MalwareBazaar_unknown_046_be24e3ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be24e3ff143568fc82e42ed4aeee92e3f6f58c5fe3c5bb442cf4b998c90463d2"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-25 19:46:28"
  condition:
    hash.sha256(0, filesize) == "be24e3ff143568fc82e42ed4aeee92e3f6f58c5fe3c5bb442cf4b998c90463d2"
}

rule MalwareBazaar_unknown_047_0aa8796e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0aa8796ec42231ee70586d3d48c7271bad38377c208fbbbfad578f6eef04313d"
    family = "unknown"
    file_name = "Loader.7z"
    file_type = "7z"
    first_seen = "2026-07-25 19:46:13"
  condition:
    hash.sha256(0, filesize) == "0aa8796ec42231ee70586d3d48c7271bad38377c208fbbbfad578f6eef04313d"
}

rule MalwareBazaar_unknown_048_57de3767
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57de376767a78229701434a2efe5d6410132b208417e8d9fc0891405dfc7be09"
    family = "unknown"
    file_name = "riscv"
    file_type = "elf"
    first_seen = "2026-07-25 19:43:20"
  condition:
    hash.sha256(0, filesize) == "57de376767a78229701434a2efe5d6410132b208417e8d9fc0891405dfc7be09"
}

rule MalwareBazaar_unknown_049_2f92ecca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f92eccabc10aa2ddd4ec44fe4ab67deb30535ff885acb8b1aee4686be47523d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-25 19:35:25"
  condition:
    hash.sha256(0, filesize) == "2f92eccabc10aa2ddd4ec44fe4ab67deb30535ff885acb8b1aee4686be47523d"
}

rule MalwareBazaar_unknown_050_efa742f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efa742f512968d4e7c320f426551b3f4aa21e80ce8b40ebfdfe228e1f1980d4c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-25 19:33:18"
  condition:
    hash.sha256(0, filesize) == "efa742f512968d4e7c320f426551b3f4aa21e80ce8b40ebfdfe228e1f1980d4c"
}

rule MalwareBazaar_unknown_051_fb4c3e7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb4c3e7dc26b98030ee6f118356105780a293aff695652df6edd3f1058cc5d85"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-25 19:22:50"
  condition:
    hash.sha256(0, filesize) == "fb4c3e7dc26b98030ee6f118356105780a293aff695652df6edd3f1058cc5d85"
}

rule MalwareBazaar_unknown_052_1eecf237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eecf2377d20768c28d741e21affaa53cf26db0d083efdbf43a92fa938b7e4be"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-25 19:22:09"
  condition:
    hash.sha256(0, filesize) == "1eecf2377d20768c28d741e21affaa53cf26db0d083efdbf43a92fa938b7e4be"
}

rule MalwareBazaar_unknown_053_fb2aca6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb2aca6aa66d3f3ac1f3df3f3d95a8bde050698e576404d5d5d9ec218407f86d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 19:20:00"
  condition:
    hash.sha256(0, filesize) == "fb2aca6aa66d3f3ac1f3df3f3d95a8bde050698e576404d5d5d9ec218407f86d"
}

rule MalwareBazaar_unknown_054_b75a1f63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b75a1f635e976190bbe1155b244f655937693fb868d27f9010813ce64f210d45"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-25 19:08:23"
  condition:
    hash.sha256(0, filesize) == "b75a1f635e976190bbe1155b244f655937693fb868d27f9010813ce64f210d45"
}

rule MalwareBazaar_unknown_055_a007111b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a007111bc2e22b8f34440012d21d7e265d0c349b9e2b2aa2568397238974ec08"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 18:52:32"
  condition:
    hash.sha256(0, filesize) == "a007111bc2e22b8f34440012d21d7e265d0c349b9e2b2aa2568397238974ec08"
}

rule MalwareBazaar_unknown_056_864239d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "864239d4d6d18ac41b16fec2b40f2fc647881dfdf66ac00db5e41d823ba8411c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 18:51:30"
  condition:
    hash.sha256(0, filesize) == "864239d4d6d18ac41b16fec2b40f2fc647881dfdf66ac00db5e41d823ba8411c"
}

rule MalwareBazaar_Phorpiex_057_bdabc719
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdabc7198cc94abbf0446bda43a21128c548f8fa3e039562502e308de3a890b6"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 18:50:48"
  condition:
    hash.sha256(0, filesize) == "bdabc7198cc94abbf0446bda43a21128c548f8fa3e039562502e308de3a890b6"
}

rule MalwareBazaar_unknown_058_54f3f2e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54f3f2e7df81774a39f1495389d76826758c76f2a86536b4e67b17c0f624076d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 18:47:53"
  condition:
    hash.sha256(0, filesize) == "54f3f2e7df81774a39f1495389d76826758c76f2a86536b4e67b17c0f624076d"
}

rule MalwareBazaar_unknown_059_9aa2c888
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9aa2c888e7d2a08a0172e9967ce715124ccceddecbaf47a319fa78c6629015b4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 18:36:40"
  condition:
    hash.sha256(0, filesize) == "9aa2c888e7d2a08a0172e9967ce715124ccceddecbaf47a319fa78c6629015b4"
}

rule MalwareBazaar_unknown_060_3d5af7ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d5af7ca987b143447b7ab87c304d6c2b58f924ac4e99fe76270d1214d2783fc"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-25 18:36:28"
  condition:
    hash.sha256(0, filesize) == "3d5af7ca987b143447b7ab87c304d6c2b58f924ac4e99fe76270d1214d2783fc"
}

rule MalwareBazaar_unknown_061_c43396e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c43396e514f92076c9a0c7e22248af8d60714a83eeab866d52dab13808a8bc32"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-25 18:23:00"
  condition:
    hash.sha256(0, filesize) == "c43396e514f92076c9a0c7e22248af8d60714a83eeab866d52dab13808a8bc32"
}

rule MalwareBazaar_unknown_062_bf8b6b48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf8b6b4846ad542696304b6d7e339d2c1425cd27aa61ac48df08c1de2dc4fabb"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-25 18:22:30"
  condition:
    hash.sha256(0, filesize) == "bf8b6b4846ad542696304b6d7e339d2c1425cd27aa61ac48df08c1de2dc4fabb"
}

rule MalwareBazaar_unknown_063_dc863b3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc863b3db099b101c6c95a17b70bfccbb9826916e6a27c13d6315a5568ba3f13"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-25 18:21:59"
  condition:
    hash.sha256(0, filesize) == "dc863b3db099b101c6c95a17b70bfccbb9826916e6a27c13d6315a5568ba3f13"
}

rule MalwareBazaar_unknown_064_2f206563
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f206563640dd66a743ffd493ce0e3c31a8fc5a24b9f5d2b540fc22d45c13d66"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-25 18:21:22"
  condition:
    hash.sha256(0, filesize) == "2f206563640dd66a743ffd493ce0e3c31a8fc5a24b9f5d2b540fc22d45c13d66"
}

rule MalwareBazaar_Mirai_065_3a79f8de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a79f8de2e26382af0127a263f6bb9c242a6c75c598e7e33792d2a96e956bda4"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-25 18:17:39"
  condition:
    hash.sha256(0, filesize) == "3a79f8de2e26382af0127a263f6bb9c242a6c75c598e7e33792d2a96e956bda4"
}

rule MalwareBazaar_Mirai_066_cd8103d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd8103d0eaab7ebdf0617da38859a0274505986ff9c45583d4e4d95886f8e3d7"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-25 18:17:25"
  condition:
    hash.sha256(0, filesize) == "cd8103d0eaab7ebdf0617da38859a0274505986ff9c45583d4e4d95886f8e3d7"
}

rule MalwareBazaar_Mirai_067_655e66d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "655e66d1fc8aa77dae0bef3ffd4016566a6c3e4e7ed44d163d7adc84361fe326"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-25 18:16:15"
  condition:
    hash.sha256(0, filesize) == "655e66d1fc8aa77dae0bef3ffd4016566a6c3e4e7ed44d163d7adc84361fe326"
}

rule MalwareBazaar_unknown_068_ea31e8a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea31e8a1d6cb9142b29a79592436a4842065bd9604349e564e6489c486837509"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-25 17:52:30"
  condition:
    hash.sha256(0, filesize) == "ea31e8a1d6cb9142b29a79592436a4842065bd9604349e564e6489c486837509"
}

rule MalwareBazaar_Vidar_069_4f8df06e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f8df06e14378fef16c78183525ba7c0dbcc5176e92ae20102d6ea25dbccbf1d"
    family = "Vidar"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:39:00"
  condition:
    hash.sha256(0, filesize) == "4f8df06e14378fef16c78183525ba7c0dbcc5176e92ae20102d6ea25dbccbf1d"
}

rule MalwareBazaar_unknown_070_c1a2cfb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1a2cfb94aca34a4088d036c4833c08d113ee4618bdbc25b3a937da5eb225e1e"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:36:12"
  condition:
    hash.sha256(0, filesize) == "c1a2cfb94aca34a4088d036c4833c08d113ee4618bdbc25b3a937da5eb225e1e"
}

rule MalwareBazaar_RemusStealer_071_cf426ee0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf426ee0da8f8907c42dfe264552ec560d5a97ff85ec7a7bf4518e773b19ce50"
    family = "RemusStealer"
    file_name = "Phantom Loader.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:35:04"
  condition:
    hash.sha256(0, filesize) == "cf426ee0da8f8907c42dfe264552ec560d5a97ff85ec7a7bf4518e773b19ce50"
}

rule MalwareBazaar_unknown_072_58285829
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58285829ced385a7d48785af5efa36f3f99150af8c1d73514653c2b62b9abb04"
    family = "unknown"
    file_name = "HitWave.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:33:50"
  condition:
    hash.sha256(0, filesize) == "58285829ced385a7d48785af5efa36f3f99150af8c1d73514653c2b62b9abb04"
}

rule MalwareBazaar_unknown_073_440789c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "440789c3674469c66bbdcb706c8fc7af666b67cfb1fba4ae4886bc94b66aeaef"
    family = "unknown"
    file_name = "curl_ext.dll"
    file_type = "exe"
    first_seen = "2026-07-25 17:32:54"
  condition:
    hash.sha256(0, filesize) == "440789c3674469c66bbdcb706c8fc7af666b67cfb1fba4ae4886bc94b66aeaef"
}

rule MalwareBazaar_RemusStealer_074_93f44970
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93f44970a8af6f0f348f79843fb0e182d5057e4eb4e3a0623b1aebf27251fe5d"
    family = "RemusStealer"
    file_name = "NexusMods.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:31:53"
  condition:
    hash.sha256(0, filesize) == "93f44970a8af6f0f348f79843fb0e182d5057e4eb4e3a0623b1aebf27251fe5d"
}

rule MalwareBazaar_Mirai_075_535b1291
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "535b129126e50497bc83afe22e97dbcec6236b0836a15b41f3af89dd9c6a4f1a"
    family = "Mirai"
    file_name = "libkys.elf"
    file_type = "elf"
    first_seen = "2026-07-25 17:30:37"
  condition:
    hash.sha256(0, filesize) == "535b129126e50497bc83afe22e97dbcec6236b0836a15b41f3af89dd9c6a4f1a"
}

rule MalwareBazaar_Vidar_076_2a5050eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a5050ebca4c8fa135b80503d1d2bdf77ec30e8089cbd318a939888048957b55"
    family = "Vidar"
    file_name = "Mod Menu.exe"
    file_type = "exe"
    first_seen = "2026-07-25 17:30:31"
  condition:
    hash.sha256(0, filesize) == "2a5050ebca4c8fa135b80503d1d2bdf77ec30e8089cbd318a939888048957b55"
}

rule MalwareBazaar_unknown_077_d925bd9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d925bd9a7e6d71e02f34624223878a090efd5f9ae2c55e80efb14e53cf3c4c7e"
    family = "unknown"
    file_name = "base_temp.apk"
    file_type = "apk"
    first_seen = "2026-07-25 17:30:25"
  condition:
    hash.sha256(0, filesize) == "d925bd9a7e6d71e02f34624223878a090efd5f9ae2c55e80efb14e53cf3c4c7e"
}

rule MalwareBazaar_unknown_078_655762d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "655762d13640a024bfebb418ce4d1a349ddfdef357600eaab420b7a4d9c04b98"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-25 17:07:36"
  condition:
    hash.sha256(0, filesize) == "655762d13640a024bfebb418ce4d1a349ddfdef357600eaab420b7a4d9c04b98"
}

rule MalwareBazaar_RemusStealer_079_2880c19f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2880c19f853059bae15a838d1320f728d3f681ff8bdfe22d455bc0335d317c7f"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 17:07:00"
  condition:
    hash.sha256(0, filesize) == "2880c19f853059bae15a838d1320f728d3f681ff8bdfe22d455bc0335d317c7f"
}

rule MalwareBazaar_RemusStealer_080_e76d3738
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e76d373869783dc10414994a1f2a052f8740e257372f4d4de17615cde3c87a3f"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-25 17:06:48"
  condition:
    hash.sha256(0, filesize) == "e76d373869783dc10414994a1f2a052f8740e257372f4d4de17615cde3c87a3f"
}

rule MalwareBazaar_Mirai_081_ef97a019
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef97a019a136f7e43ad006f8a7fd44236df44058053b5e01dd60755d24c86011"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-25 17:00:21"
  condition:
    hash.sha256(0, filesize) == "ef97a019a136f7e43ad006f8a7fd44236df44058053b5e01dd60755d24c86011"
}

rule MalwareBazaar_Mirai_082_a1c56f08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1c56f08572af0a55fd0756b613047cd3da1c78654a06952f7fd9621208a88e7"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-25 17:00:00"
  condition:
    hash.sha256(0, filesize) == "a1c56f08572af0a55fd0756b613047cd3da1c78654a06952f7fd9621208a88e7"
}

rule MalwareBazaar_Mirai_083_c8be56f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8be56f0838af7ed2133b264c5159ae079a74796a761bbf0764eaec8987cc5b9"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-25 16:59:56"
  condition:
    hash.sha256(0, filesize) == "c8be56f0838af7ed2133b264c5159ae079a74796a761bbf0764eaec8987cc5b9"
}

rule MalwareBazaar_Mirai_084_beaec3c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "beaec3c0d393c4627f951eb7f96a9ff38fed82982705dbe1b66e85b2efc21c92"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-25 16:59:54"
  condition:
    hash.sha256(0, filesize) == "beaec3c0d393c4627f951eb7f96a9ff38fed82982705dbe1b66e85b2efc21c92"
}

rule MalwareBazaar_Mirai_085_97e22980
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97e22980e077925d8a249b948dcb9d7de5b20395386dcd86b9d42ef580fa3c33"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-25 16:59:49"
  condition:
    hash.sha256(0, filesize) == "97e22980e077925d8a249b948dcb9d7de5b20395386dcd86b9d42ef580fa3c33"
}

rule MalwareBazaar_Mirai_086_6d8249f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d8249f94461455b8fdf679cb0c22c40e6d87d7ed7e79bcd7a48ada72e75ec92"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:39"
  condition:
    hash.sha256(0, filesize) == "6d8249f94461455b8fdf679cb0c22c40e6d87d7ed7e79bcd7a48ada72e75ec92"
}

rule MalwareBazaar_Mirai_087_1ad0053c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ad0053c9f4d5810a0433f6778c35cc7afbb765df0985621cf4c0346a2cff72f"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:38"
  condition:
    hash.sha256(0, filesize) == "1ad0053c9f4d5810a0433f6778c35cc7afbb765df0985621cf4c0346a2cff72f"
}

rule MalwareBazaar_Mirai_088_3d5b9c38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d5b9c3821fae13dea78b113f90985fed0b7f43b2d975411907130e48bbfcd2c"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:37"
  condition:
    hash.sha256(0, filesize) == "3d5b9c3821fae13dea78b113f90985fed0b7f43b2d975411907130e48bbfcd2c"
}

rule MalwareBazaar_Mirai_089_e9df735e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9df735ea30bc4e950ab968c75569b83d5c6bb0d2e4a5e442ff21c3b1320cb01"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:36"
  condition:
    hash.sha256(0, filesize) == "e9df735ea30bc4e950ab968c75569b83d5c6bb0d2e4a5e442ff21c3b1320cb01"
}

rule MalwareBazaar_Mirai_090_405b89d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "405b89d887891e0d43b349c8415edb18d75773205bc98a11676d6f7150bba858"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:35"
  condition:
    hash.sha256(0, filesize) == "405b89d887891e0d43b349c8415edb18d75773205bc98a11676d6f7150bba858"
}

rule MalwareBazaar_Mirai_091_5a69f79a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a69f79a35ba2ef2714c2e0babded61cd52f4bac1b67a53fdcf7361ca261670a"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:35"
  condition:
    hash.sha256(0, filesize) == "5a69f79a35ba2ef2714c2e0babded61cd52f4bac1b67a53fdcf7361ca261670a"
}

rule MalwareBazaar_Mirai_092_eb3f90ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb3f90ca702eb63880546c67d1530a9a994e66fdca6d0567b2860887fdcba14b"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:34"
  condition:
    hash.sha256(0, filesize) == "eb3f90ca702eb63880546c67d1530a9a994e66fdca6d0567b2860887fdcba14b"
}

rule MalwareBazaar_Mirai_093_16913357
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1691335759096e562729e38e60abbf270a7c285c241ea095a2e69e737a8bdbcd"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:33"
  condition:
    hash.sha256(0, filesize) == "1691335759096e562729e38e60abbf270a7c285c241ea095a2e69e737a8bdbcd"
}

rule MalwareBazaar_Mirai_094_72715b5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72715b5e55871336b8edc4d23d970792b1422f052c7c599c191d72b3d191f5eb"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:33"
  condition:
    hash.sha256(0, filesize) == "72715b5e55871336b8edc4d23d970792b1422f052c7c599c191d72b3d191f5eb"
}

rule MalwareBazaar_Mirai_095_ca51b527
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca51b527012988ed642adf53be6123f74fb2bd0017871a07d935f69fd321518c"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-07-25 16:58:32"
  condition:
    hash.sha256(0, filesize) == "ca51b527012988ed642adf53be6123f74fb2bd0017871a07d935f69fd321518c"
}

rule MalwareBazaar_Mirai_096_ffbfd13c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffbfd13c46e2940bad1fb91a9ce11e282cdb4e22acd648e5fcdf13ac9b1ecd30"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-25 16:57:36"
  condition:
    hash.sha256(0, filesize) == "ffbfd13c46e2940bad1fb91a9ce11e282cdb4e22acd648e5fcdf13ac9b1ecd30"
}

rule MalwareBazaar_Mirai_097_513fdafa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "513fdafabf21c835cebd9a81046e705f8b0c1722129b90c25bf48e1594cf2cdb"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-25 16:57:34"
  condition:
    hash.sha256(0, filesize) == "513fdafabf21c835cebd9a81046e705f8b0c1722129b90c25bf48e1594cf2cdb"
}

rule MalwareBazaar_Mirai_098_a66945ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a66945cecdcbd17b30aff446095c7d661a97dfcacdc39b1a4a1de4aa9c19161a"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-25 16:57:31"
  condition:
    hash.sha256(0, filesize) == "a66945cecdcbd17b30aff446095c7d661a97dfcacdc39b1a4a1de4aa9c19161a"
}

rule MalwareBazaar_unknown_099_c0a3d78c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0a3d78c3b6fd101bced1d133cbef5e1e7f731b161cff64a651ce537d246370f"
    family = "unknown"
    file_name = "nz.sh"
    file_type = "sh"
    first_seen = "2026-07-25 16:57:28"
  condition:
    hash.sha256(0, filesize) == "c0a3d78c3b6fd101bced1d133cbef5e1e7f731b161cff64a651ce537d246370f"
}

rule MalwareBazaar_Mirai_100_94359c56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94359c560a51affe2473af30ac83d559877975d2b8fd9c825c1c6e5b43002d5f"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-25 16:57:27"
  condition:
    hash.sha256(0, filesize) == "94359c560a51affe2473af30ac83d559877975d2b8fd9c825c1c6e5b43002d5f"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

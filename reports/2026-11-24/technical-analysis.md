# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-24

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 643 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 643 |
| Unique family labels | 20 |
| Unique file types | 14 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| RemcosRAT | 28 |
| unknown | 19 |
| Formbook | 17 |
| EasyShell | 10 |
| AgentTesla | 4 |
| AsyncRAT | 3 |
| njrat | 3 |
| PureLogsStealer | 3 |
| DarkCoreRAT | 2 |
| Ransomware.WannaCry | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 30 |
| js | 20 |
| hta | 16 |
| ps1 | 12 |
| elf | 8 |
| zip | 2 |
| sh | 2 |
| vbe | 2 |
| jse | 2 |
| macho | 2 |

## Per-Sample Analysis

### Sample 1: `972d8d61394f08fd`

| Field | Value |
|---|---|
| SHA-256 | `972d8d61394f08fdae76bde12e86a6faa7663978f442e4f2b9b6a4c580a75ea1` |
| Family label | `unknown` |
| File name | `CopiadetransferenciaUSD46.200.00PDF.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:50:13` |
| Reporter | `ni_fi_70` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `927330fd0da9daa4c8d943b3e8522bd2` |
| SHA-1 | `8dcef21bd0f819d2d99258a6b4bf5cfcbeba11e6` |
| SHA-256 | `972d8d61394f08fdae76bde12e86a6faa7663978f442e4f2b9b6a4c580a75ea1` |
| SHA3-384 | `3801cc65615cc0892c3c59242733c94248abc81abe7a4df19cea3677d08065999ddc39b157658e37f8dcebc6d7e42d9d` |
| IMPHASH | `6e7f9a29f2c85394521a08b9f31f6275` |
| TLSH | `T1A6251277B7D39745D46FF8F4AEC563AC22E1DD5E2243958BD38D3A4ACE7090A8809807` |
| SSDEEP | `24576:ZTpCfs7HXj38avpZXCN4ROd/oLJ5i2lWTgc/:ZT4fs7HXj8GpU+mEUgc/` |
| ICON-DHASH | `a38ec0e48c8ce861` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_972d8d61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "972d8d61394f08fdae76bde12e86a6faa7663978f442e4f2b9b6a4c580a75ea1"
    family = "unknown"
    file_name = "CopiadetransferenciaUSD46.200.00PDF.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:50:13"
  condition:
    hash.sha256(0, filesize) == "972d8d61394f08fdae76bde12e86a6faa7663978f442e4f2b9b6a4c580a75ea1"
}
```

### Sample 2: `5482a9cc3854baff`

| Field | Value |
|---|---|
| SHA-256 | `5482a9cc3854baff32b3bb8ad6a8fdd68e3485d2c9b26ef3d7f8c7bd77dcdc9f` |
| Family label | `unknown` |
| File name | `5482a9cc3854baff32b3bb8ad6a8fdd68e3485d2c9b26ef3d7f8c7bd77dcdc9f` |
| File type | `exe` |
| First seen | `2026-11-24 09:44:54` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e9c063d128feeb34c6939aa82e0ed7b` |
| SHA-1 | `3feab1db015a8bd82d0cff18e116d5b724c07ef4` |
| SHA-256 | `5482a9cc3854baff32b3bb8ad6a8fdd68e3485d2c9b26ef3d7f8c7bd77dcdc9f` |
| SHA3-384 | `1372f075515b82e6f6b534dfd189f6828898dedfd5f1c0a0096702a1a5b1bcec1e187f65cfc81951e9eaa54df148f199` |
| IMPHASH | `6732989f7f3dc425afb3e1f08e4c2772` |
| TLSH | `T16AA3364565B47CB8C52680399203632253A23C4DC33166A7BEE9DD643F97FA06B2E7E1` |
| SSDEEP | `3072:TDTcb/jeZy1Bg8Pt46f44OInucFi7YBOIrSMcf34hyLcL18jK5AWfIAMpxu5KEn6:vTcjQhInucFi7YBOIrSMcf34hyLcL18Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_5482a9cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5482a9cc3854baff32b3bb8ad6a8fdd68e3485d2c9b26ef3d7f8c7bd77dcdc9f"
    family = "unknown"
    file_name = "5482a9cc3854baff32b3bb8ad6a8fdd68e3485d2c9b26ef3d7f8c7bd77dcdc9f"
    file_type = "exe"
    first_seen = "2026-11-24 09:44:54"
  condition:
    hash.sha256(0, filesize) == "5482a9cc3854baff32b3bb8ad6a8fdd68e3485d2c9b26ef3d7f8c7bd77dcdc9f"
}
```

### Sample 3: `a8512dd24bd9776b`

| Field | Value |
|---|---|
| SHA-256 | `a8512dd24bd9776b143fa9a23058e03c7c4c36e9bad839a028137b782855ab5a` |
| Family label | `unknown` |
| File name | `ad0a11b87b468cbd4d9555d4f845e9256370ff631f7cafc063d6e0a59e98c777.zip` |
| File type | `zip` |
| First seen | `2026-11-24 09:44:06` |
| Reporter | `DarkDataLabs` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b285eddc8096d9f4dfc82c316c45d56f` |
| SHA-1 | `59cce4b6fdedc4448e389007344bd5acc3a0d07e` |
| SHA-256 | `a8512dd24bd9776b143fa9a23058e03c7c4c36e9bad839a028137b782855ab5a` |
| SHA3-384 | `f11d8b39eb5f250b7a9e236af053fbc6ba867f683f6f20ef40fe9c888831c787494944d69ac7abba3dfe1421b80260f4` |
| TLSH | `T1E3073347EC45ADD180D7D83A8BE53CAF330C4697B86A7D1565CACB7B9A763302210C6E` |
| SSDEEP | `393216:tXI5q+a50l9AywlnOcF4waVY4lyw2ihHEe:tXIm5+9b2n/FzWDaMHEe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_a8512dd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8512dd24bd9776b143fa9a23058e03c7c4c36e9bad839a028137b782855ab5a"
    family = "unknown"
    file_name = "ad0a11b87b468cbd4d9555d4f845e9256370ff631f7cafc063d6e0a59e98c777.zip"
    file_type = "zip"
    first_seen = "2026-11-24 09:44:06"
  condition:
    hash.sha256(0, filesize) == "a8512dd24bd9776b143fa9a23058e03c7c4c36e9bad839a028137b782855ab5a"
}
```

### Sample 4: `72307be53f03d307`

| Field | Value |
|---|---|
| SHA-256 | `72307be53f03d307833108f592a631ea3e70840042f7925c1f3247796d4262d7` |
| Family label | `unknown` |
| File name | `72307be53f03d307833108f592a631ea3e70840042f7925c1f3247796d4262d7` |
| File type | `sh` |
| First seen | `2026-11-24 09:43:52` |
| Reporter | `hett` |
| Tags | `bash, honeypot, script, sh, shardlure` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5f5c13161d9190a3e4e1607a915790c` |
| SHA-1 | `adf71a9a53c8acddecc91010a4bedae14cb8bc0a` |
| SHA-256 | `72307be53f03d307833108f592a631ea3e70840042f7925c1f3247796d4262d7` |
| SHA3-384 | `9dba15aca70611d097be11b43c5fcbcf0716827c77781751154d4cfe7df7f88cd32c278a7d39ba46566ed7635fe435c1` |
| TLSH | `T18F81A0916CB18C32A5B5906EE7E5516167CF4A23442C7C04FA4EBD18BF3C2A4F1B0A5E` |
| SSDEEP | `96:/n8xOxIN7c39UCSObrgvKyH+gRJ7E2FxGoLzoCr5Jia5+2leVHYCGnDrWNpuD:P8xOqNnargvKyH+gRRE2FxGoLzoCr58O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_72307be5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72307be53f03d307833108f592a631ea3e70840042f7925c1f3247796d4262d7"
    family = "unknown"
    file_name = "72307be53f03d307833108f592a631ea3e70840042f7925c1f3247796d4262d7"
    file_type = "sh"
    first_seen = "2026-11-24 09:43:52"
  condition:
    hash.sha256(0, filesize) == "72307be53f03d307833108f592a631ea3e70840042f7925c1f3247796d4262d7"
}
```

### Sample 5: `885d654b11869e83`

| Field | Value |
|---|---|
| SHA-256 | `885d654b11869e83f55ae4a18dcd8ad182d0da81faf2d54c145ba9cdc830c270` |
| Family label | `unknown` |
| File name | `885d654b11869e83f55ae4a18dcd8ad182d0da81faf2d54c145ba9cdc830c270` |
| File type | `sh` |
| First seen | `2026-11-24 09:43:51` |
| Reporter | `hett` |
| Tags | `bash, honeypot, script, sh, shardlure` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd62b501f8fbe6f6ee09afe916fa062b` |
| SHA-1 | `779016cee64de2c279a7ba7019146b8a8d360bf9` |
| SHA-256 | `885d654b11869e83f55ae4a18dcd8ad182d0da81faf2d54c145ba9cdc830c270` |
| SHA3-384 | `1c708785730db8d6fd5462b4a6ecec29ccdb4799e5036c88c996e82a69a37cba19556de98c5745cb82cad71d4b6b91e1` |
| TLSH | `T11081C0916CA18C32A5B5906EE7E9516167CF4E23442C7C04FA4EBD18BF7C2A4F1B0A5E` |
| SSDEEP | `96:/n8xOxIN7c39UCSObrgvKyH+gRJ7E2FxGoLzoCr5Jia5+2leVHYCGnDrWjpuD:P8xOqNnargvKyH+gRRE2FxGoLzoCr58s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_885d654b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "885d654b11869e83f55ae4a18dcd8ad182d0da81faf2d54c145ba9cdc830c270"
    family = "unknown"
    file_name = "885d654b11869e83f55ae4a18dcd8ad182d0da81faf2d54c145ba9cdc830c270"
    file_type = "sh"
    first_seen = "2026-11-24 09:43:51"
  condition:
    hash.sha256(0, filesize) == "885d654b11869e83f55ae4a18dcd8ad182d0da81faf2d54c145ba9cdc830c270"
}
```

### Sample 6: `e671e8522520cc88`

| Field | Value |
|---|---|
| SHA-256 | `e671e8522520cc8895516adea27487dd9b582c7cbf63e08314f60d05f8050d0f` |
| Family label | `Formbook` |
| File name | `KMK.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:42:40` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c90498606c62cc9a2b6f367f9563da04` |
| SHA-1 | `d7de3b41567184f315413558a94359cee45a19fe` |
| SHA-256 | `e671e8522520cc8895516adea27487dd9b582c7cbf63e08314f60d05f8050d0f` |
| SHA3-384 | `249ed893dd0482a68aadba50c55fe709f3f72eff761d3505412afdb5ef38cf3b5b4956e83a8aedf2c0aaaa8ff100bd87` |
| TLSH | `T1CD652314CACD11EF4930D0B67356F8C4B2ED23C68E82026797FC94E532A54E6DB679B2` |
| SSDEEP | `24576:Ev1i018E/JSmCDF7Wo01n794aa0zW67a+JJJa31yrH9k0GzWso:EvMdrj017c1k9W6so` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_006_e671e852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e671e8522520cc8895516adea27487dd9b582c7cbf63e08314f60d05f8050d0f"
    family = "Formbook"
    file_name = "KMK.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:42:40"
  condition:
    hash.sha256(0, filesize) == "e671e8522520cc8895516adea27487dd9b582c7cbf63e08314f60d05f8050d0f"
}
```

### Sample 7: `bb6e8a09dea7742f`

| Field | Value |
|---|---|
| SHA-256 | `bb6e8a09dea7742fdf5fd584446c998041c4e77c635aea0343e0b769cf3fccd3` |
| Family label | `Formbook` |
| File name | `PWKMK.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:42:36` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48170c15cd949dcd0b941cb2074a8152` |
| SHA-1 | `f90be134e9c5110f7f18b7fa3a11d56a69cf64cf` |
| SHA-256 | `bb6e8a09dea7742fdf5fd584446c998041c4e77c635aea0343e0b769cf3fccd3` |
| SHA3-384 | `e9e58b7a05cbf1f06eb8d30a6b3fe55a291f6cc7a17d04574272ed4a9f662e926f685592664b69270b3701c378dd7649` |
| TLSH | `T10A652334C5DEA3DF0B5097FB750A9804A1DD774F8D82425273BCC2B2B6A41688A77CB6` |
| SSDEEP | `24576:pI2p6fkSDAmzT6aKWP+q1x6X976Q1nyIFCzUltdSAXM6WD16fn43L9w0Jy:plSx6apf6XaUlXHXRZi9I` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_007_bb6e8a09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb6e8a09dea7742fdf5fd584446c998041c4e77c635aea0343e0b769cf3fccd3"
    family = "Formbook"
    file_name = "PWKMK.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:42:36"
  condition:
    hash.sha256(0, filesize) == "bb6e8a09dea7742fdf5fd584446c998041c4e77c635aea0343e0b769cf3fccd3"
}
```

### Sample 8: `1d548ed2c6bf9f6d`

| Field | Value |
|---|---|
| SHA-256 | `1d548ed2c6bf9f6de674ebab42371bb7c5b35f5eae8aed01f48be85ec4b72dfc` |
| Family label | `Ransomware.WannaCry` |
| File name | `379cf4fce883e5853294990f94c082eb971db7b0e3a817f7abd4facffc4fe23f.zip` |
| File type | `zip` |
| First seen | `2026-11-24 09:41:26` |
| Reporter | `DarkDataLabs` |
| Tags | `Ransomware.WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `636b13e49bb8af3caf6ce825e690b3f9` |
| SHA-1 | `727fd5e7791d1f44b3d73c0726e9cac7fcb85f2c` |
| SHA-256 | `1d548ed2c6bf9f6de674ebab42371bb7c5b35f5eae8aed01f48be85ec4b72dfc` |
| SHA3-384 | `08ac328c0a0699688243f6720d7e0175ebb3df9acef080a31ee7f1dbc507fc874af5aa4b9e7a36d9060eed68cd6926dd` |
| TLSH | `T17DF5338A584C7B9F8886CBC827B41F802BB437CE9DCD75915EAAE1530DC4F76D1AA5C0` |
| SSDEEP | `49152:tExZZ3/1k5HIUEWlD8cLoCOaaHK3ZpSsA23gCwoko05twTla5JS4P+aQ7LSBXSLJ:taZZvW6WlD8MozaVkCWwTEw2QAHgYfU7` |

#### Technical Assessment

- The sample is tracked as `Ransomware.WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Ransomware_WannaCry_008_1d548ed2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d548ed2c6bf9f6de674ebab42371bb7c5b35f5eae8aed01f48be85ec4b72dfc"
    family = "Ransomware.WannaCry"
    file_name = "379cf4fce883e5853294990f94c082eb971db7b0e3a817f7abd4facffc4fe23f.zip"
    file_type = "zip"
    first_seen = "2026-11-24 09:41:26"
  condition:
    hash.sha256(0, filesize) == "1d548ed2c6bf9f6de674ebab42371bb7c5b35f5eae8aed01f48be85ec4b72dfc"
}
```

### Sample 9: `59d56653d79c40e1`

| Field | Value |
|---|---|
| SHA-256 | `59d56653d79c40e190b929f43cf50712e0595b12f7a7ebcc31ec116a919cd57b` |
| Family label | `SnappyClient` |
| File name | `1.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:39:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, SnappyClient` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5673918fbd3913d7159e6b5764f103c6` |
| SHA-1 | `61fe641241a3e299c296c28824125134aca72400` |
| SHA-256 | `59d56653d79c40e190b929f43cf50712e0595b12f7a7ebcc31ec116a919cd57b` |
| SHA3-384 | `8c0f367de79523c23436c35e8247cbaa4cfa9dc6fba86eb1c4591741e3acc8dd4060c8ef29643ef606fbe2abd84cf50d` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T16D5633E9B7846FF0E7A1C5F65F0DCB2062B3DB7DA2C0AE56D1191E1A1C870A243172E5` |
| SSDEEP | `196608:+pAsrBI/6arWnYKmTYkgloRqIE0H0S0FhZMok/X:+pAsrwNWr36qaH0S0Fh6om` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_009_59d56653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59d56653d79c40e190b929f43cf50712e0595b12f7a7ebcc31ec116a919cd57b"
    family = "SnappyClient"
    file_name = "1.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:39:38"
  condition:
    hash.sha256(0, filesize) == "59d56653d79c40e190b929f43cf50712e0595b12f7a7ebcc31ec116a919cd57b"
}
```

### Sample 10: `fc7c1cc3664fb63c`

| Field | Value |
|---|---|
| SHA-256 | `fc7c1cc3664fb63c309c9cdc5a3e5b6477507e8922e3d7a011635e0f86057474` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.msi` |
| File type | `msi` |
| First seen | `2026-11-24 09:39:34` |
| Reporter | `abuse_ch` |
| Tags | `ConnectWise, msi, RMM, ScreenConnect` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26a23df7b211344d475cf062fbae4de2` |
| SHA-1 | `bef6730a00771a3697609c39f95f7d239517466e` |
| SHA-256 | `fc7c1cc3664fb63c309c9cdc5a3e5b6477507e8922e3d7a011635e0f86057474` |
| SHA3-384 | `699ebd4ec06840dcbd2237656901087d0003cb1f5810804650cbf2d77264826ffef1a9fc238d13d98754d73b7d8d76a5` |
| TLSH | `T1C1E623116BF89668F1F22A79E876A071A13B7C125D36D12E2324791E2C75EC0C9B3737` |
| SSDEEP | `196608:lHxcp9ym3nltDUJVxHxcp9ym3yHxcp9ym3DHxcp9ym3OHxcp9ym3dAHxcp9ym3do:XGplpmGpAGptGpcGpduGpdvGpdT` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_010_fc7c1cc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc7c1cc3664fb63c309c9cdc5a3e5b6477507e8922e3d7a011635e0f86057474"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-11-24 09:39:34"
  condition:
    hash.sha256(0, filesize) == "fc7c1cc3664fb63c309c9cdc5a3e5b6477507e8922e3d7a011635e0f86057474"
}
```

### Sample 11: `7549be014bfdb35f`

| Field | Value |
|---|---|
| SHA-256 | `7549be014bfdb35fc54f11ee9013872deb17b1d6c19c51386d4bd4cb0383f7ce` |
| Family label | `Formbook` |
| File name | `M2KMK.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:39:25` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f8f50fd0d7a93898a7e3ab2d5346fb8` |
| SHA-1 | `b4e1e0603ff372bdf7067b429d24b1bfa1db3257` |
| SHA-256 | `7549be014bfdb35fc54f11ee9013872deb17b1d6c19c51386d4bd4cb0383f7ce` |
| SHA3-384 | `8213bae887a6084010802348cf77e1d21d8ce3e88bad28ea6b9b1732da4882203448e981fc52ab1da8f370f2c181111f` |
| TLSH | `T13565235C8748A7FE0802F4BEF6A6B94471AE138B4D43065683BCCAD5317647DAF67CA0` |
| SSDEEP | `24576:6Hd0mmxiaNJvUrTdpkRlcdk7l1Kiq+RCG8uSv9D0z7mxFRJ:BGaN0dOode/uuSCaJ` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_011_7549be01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7549be014bfdb35fc54f11ee9013872deb17b1d6c19c51386d4bd4cb0383f7ce"
    family = "Formbook"
    file_name = "M2KMK.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:39:25"
  condition:
    hash.sha256(0, filesize) == "7549be014bfdb35fc54f11ee9013872deb17b1d6c19c51386d4bd4cb0383f7ce"
}
```

### Sample 12: `11b3f76d94cf66e4`

| Field | Value |
|---|---|
| SHA-256 | `11b3f76d94cf66e4c02aa96bcbec88044d55c506ffe0c5bdc39b3fc3b2f185cf` |
| Family label | `Formbook` |
| File name | `36KMK.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:38:50` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df87974bef069c47764330d7d4198235` |
| SHA-1 | `8a8eac170b0303de575691ac90d92c978dfe32d2` |
| SHA-256 | `11b3f76d94cf66e4c02aa96bcbec88044d55c506ffe0c5bdc39b3fc3b2f185cf` |
| SHA3-384 | `514ab8855883ce0a30f3993ffa3ff46d8fc3cff4f480173d5cbf94f6da3bd7565bde9a9d3c61f386ce4541a48c7be8bc` |
| TLSH | `T1D475233C859CB3CE0914E2F9EA59FC45B0FD638788858303A1FDC7D435EA0A5A676D62` |
| SSDEEP | `24576:9USgbg5Ta/CePNlMQo9ncyoh6GpTKcVInCktr7ijqBNGgpeQ1xzDrk19kecn51tw:9GbgYzNe5cp1pOy8Ltw` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_012_11b3f76d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11b3f76d94cf66e4c02aa96bcbec88044d55c506ffe0c5bdc39b3fc3b2f185cf"
    family = "Formbook"
    file_name = "36KMK.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:38:50"
  condition:
    hash.sha256(0, filesize) == "11b3f76d94cf66e4c02aa96bcbec88044d55c506ffe0c5bdc39b3fc3b2f185cf"
}
```

### Sample 13: `f658be3f57702aff`

| Field | Value |
|---|---|
| SHA-256 | `f658be3f57702affa9839ed7e1e70b7875d533015c5864af6a7408c50859f66e` |
| Family label | `WARDENStealer` |
| File name | `kliulij.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:38:41` |
| Reporter | `abuse_ch` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9cda3142eb2042ecc99a7c25983a9a4e` |
| SHA-1 | `c53a0714bb20db16cdaf857b01d873d7506ef1d0` |
| SHA-256 | `f658be3f57702affa9839ed7e1e70b7875d533015c5864af6a7408c50859f66e` |
| SHA3-384 | `1a4ceb4d74939099ad179225278f8ab4795cdd91d999172762e26c89c95fe1cc6edcdd8df4433809f4495be0bd868355` |
| IMPHASH | `907207c5aacbafdc3fd09a7fe0ab61f3` |
| TLSH | `T1BD150256F38500FEC417C23B86216612F7B13C465B60ABFF57941B662E3AAE88E3D711` |
| SSDEEP | `12288:PQPbIYbVIXjeM8UhSBqlEbNOfeoJ/MxXBYIAZTVfsg6rtXvlk2FyytuzdsRkkDvN:PQ0tT8+OThdo5njTGZflnDQCRvLTu` |
| ICON-DHASH | `4496716969719744` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_013_f658be3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f658be3f57702affa9839ed7e1e70b7875d533015c5864af6a7408c50859f66e"
    family = "WARDENStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:38:41"
  condition:
    hash.sha256(0, filesize) == "f658be3f57702affa9839ed7e1e70b7875d533015c5864af6a7408c50859f66e"
}
```

### Sample 14: `9a012924a61ea03d`

| Field | Value |
|---|---|
| SHA-256 | `9a012924a61ea03dc8ce6f94467658595abd374d2523230497f7569e6c0db23a` |
| Family label | `AgentTesla` |
| File name | `Booking_Confirmation.js` |
| File type | `js` |
| First seen | `2026-11-24 09:38:21` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ce6abd9a849ea49a22472790654ccb2` |
| SHA-1 | `acd64c580c3f97436188bd20b99f276c2d4aedef` |
| SHA-256 | `9a012924a61ea03dc8ce6f94467658595abd374d2523230497f7569e6c0db23a` |
| SHA3-384 | `f6794f9f64e354fa6aeba9a603ccffcbb4fc971c158f00279565f98b9fb34698a33fd80b662d554bb0ed954b6feb4a66` |
| TLSH | `T15194F60802650705FBB7AD40E96745B54D3BA68BAAF493C5806F2E592FB3C3144AFF1B` |
| SSDEEP | `3072:f+v9oxcFyWe+GwBSPZwfW6SFHFTEYf5SpSmdsExy6phfrJHR8zYK9UHu7mDpT6ng:OfRsSS8NZVAc` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_014_9a012924
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a012924a61ea03dc8ce6f94467658595abd374d2523230497f7569e6c0db23a"
    family = "AgentTesla"
    file_name = "Booking_Confirmation.js"
    file_type = "js"
    first_seen = "2026-11-24 09:38:21"
  condition:
    hash.sha256(0, filesize) == "9a012924a61ea03dc8ce6f94467658595abd374d2523230497f7569e6c0db23a"
}
```

### Sample 15: `fffa988426ff3c81`

| Field | Value |
|---|---|
| SHA-256 | `fffa988426ff3c813effd541c226f5168c0bc6e4045d5adc10d4855ca475c456` |
| Family label | `RemcosRAT` |
| File name | `updated.vbe` |
| File type | `vbe` |
| First seen | `2026-11-24 09:38:16` |
| Reporter | `abuse_ch` |
| Tags | `RAT, RemcosRAT, vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdb165412609238d854895d34f0bbd95` |
| SHA-1 | `8d94cef6f6dcab1bd15fd8ae194694ba3f36e2d2` |
| SHA-256 | `fffa988426ff3c813effd541c226f5168c0bc6e4045d5adc10d4855ca475c456` |
| SHA3-384 | `888899012275f24ce2ffdc83779cb58376d70f2faaaf2949cd979a13bfc82f5770bd80d804a23bd002cba0e29530d856` |
| TLSH | `T13FE5F25088C03FE4EAB9561840FD663EA3B14A9B5C2D6D49EB33BD46EFB7540930718B` |
| SSDEEP | `24576:HFPXgUaDF8OCuIHi+T870+f0c0gZ4m+bOXiJ4FE+hUqZifaPg1h+GEtiEk4L+zod:ZaeOKCx/ctWDYa41mNjN6syuFJNvh` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_015_fffa9884
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fffa988426ff3c813effd541c226f5168c0bc6e4045d5adc10d4855ca475c456"
    family = "RemcosRAT"
    file_name = "updated.vbe"
    file_type = "vbe"
    first_seen = "2026-11-24 09:38:16"
  condition:
    hash.sha256(0, filesize) == "fffa988426ff3c813effd541c226f5168c0bc6e4045d5adc10d4855ca475c456"
}
```

### Sample 16: `43b4ab9772c9b90c`

| Field | Value |
|---|---|
| SHA-256 | `43b4ab9772c9b90cdd8f3995f892cc9b708116498366f759a9c2f78272035518` |
| Family label | `RemcosRAT` |
| File name | `ipad.vbe` |
| File type | `vbe` |
| First seen | `2026-11-24 09:38:12` |
| Reporter | `abuse_ch` |
| Tags | `RAT, RemcosRAT, vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba5ffb9e5849cf8a1f287b2bcb6c4c40` |
| SHA-1 | `dfbd12a08e8e3e198ee8944cacd037d136123e8c` |
| SHA-256 | `43b4ab9772c9b90cdd8f3995f892cc9b708116498366f759a9c2f78272035518` |
| SHA3-384 | `0e29aa1bfcb9e87336a38958cba874c1bc29487e7a415d78170288ad37ed0606e0f1c83aac8a86701e037df3f23abd1a` |
| TLSH | `T196E5F15185C43FE8EFB9960840FD663DA3B10A9B5C2E6949A733BD45EFB754082071CB` |
| SSDEEP | `49152:C9z12Ag37fzprk9SVcrym2Ixg3rJPTlTbDpGSvqAhQ:g` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_016_43b4ab97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43b4ab9772c9b90cdd8f3995f892cc9b708116498366f759a9c2f78272035518"
    family = "RemcosRAT"
    file_name = "ipad.vbe"
    file_type = "vbe"
    first_seen = "2026-11-24 09:38:12"
  condition:
    hash.sha256(0, filesize) == "43b4ab9772c9b90cdd8f3995f892cc9b708116498366f759a9c2f78272035518"
}
```

### Sample 17: `6efa87978c4c29d6`

| Field | Value |
|---|---|
| SHA-256 | `6efa87978c4c29d6c85994ec9dc9e280f12f1569a5f85688865af25f36527cf2` |
| Family label | `RemcosRAT` |
| File name | `secured_stub.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:37:31` |
| Reporter | `abuse_ch` |
| Tags | `ps1, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11204f704ba0a677799982a2dd957dd5` |
| SHA-1 | `0c71fb37d4ef781176936e0c2177f1c35b44dcf3` |
| SHA-256 | `6efa87978c4c29d6c85994ec9dc9e280f12f1569a5f85688865af25f36527cf2` |
| SHA3-384 | `09955fe00235f321a9cc26d5daed87cb27e0a5be343bab4bdc3e6e830f834933c9e6e8c139ceb5ea6a5afec45c92939b` |
| TLSH | `T105C52328DB5B21DE0D20A6F9F611F89976AC67C64A42231743BCC6B134F94B49F33C69` |
| SSDEEP | `24576:97JkMy1gHp/LSLQiYEJpyNRkdyjz7BZQBvTYmVDd/ZDtrZhOkL/ukA7vtEclqGd6:NtdDpMEZMBcljNwIpMSZy5J` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_017_6efa8797
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6efa87978c4c29d6c85994ec9dc9e280f12f1569a5f85688865af25f36527cf2"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:37:31"
  condition:
    hash.sha256(0, filesize) == "6efa87978c4c29d6c85994ec9dc9e280f12f1569a5f85688865af25f36527cf2"
}
```

### Sample 18: `889af64a3f1e8210`

| Field | Value |
|---|---|
| SHA-256 | `889af64a3f1e8210003a729d8b55d807f69858fdd5f0e754e90218f19cd8ec2e` |
| Family label | `RemcosRAT` |
| File name | `secured_stub.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:36:19` |
| Reporter | `abuse_ch` |
| Tags | `ps1, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb50288245d3fce984d3cf017240106b` |
| SHA-1 | `2fc992613a223bdffe12c57b49ff23a73f4387d6` |
| SHA-256 | `889af64a3f1e8210003a729d8b55d807f69858fdd5f0e754e90218f19cd8ec2e` |
| SHA3-384 | `26159b10c27afe2a468ea76d0f7d339463b3a15223c1edb93885d901f76f52c88e182c20a2528f5df0a1760eabd5dcd2` |
| TLSH | `T1D9C5233CAA9C06DF0501D6FABD0AB59AF5CC23CB4D83475643BCC1A439DA474E663CA6` |
| SSDEEP | `24576:fDqIzwYkPdSUCepYqyR4UzepkEaMUOZNs8J5tjEASWnwxELtg1dapMkiTXO2jNHH:4h7t0ms8J1NMdsMXN4bBJ0FD` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_018_889af64a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889af64a3f1e8210003a729d8b55d807f69858fdd5f0e754e90218f19cd8ec2e"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:36:19"
  condition:
    hash.sha256(0, filesize) == "889af64a3f1e8210003a729d8b55d807f69858fdd5f0e754e90218f19cd8ec2e"
}
```

### Sample 19: `9a46c78920200428`

| Field | Value |
|---|---|
| SHA-256 | `9a46c78920200428c73737ffc7751df004a0a9f6c092aff0c28da8403a4a0ad7` |
| Family label | `RemcosRAT` |
| File name | `secured_stub.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:35:00` |
| Reporter | `abuse_ch` |
| Tags | `ps1, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd0378f6c0bdc80a2f09873c63256ff6` |
| SHA-1 | `e97313592cfdde641923b0f4892cddbede7f5df1` |
| SHA-256 | `9a46c78920200428c73737ffc7751df004a0a9f6c092aff0c28da8403a4a0ad7` |
| SHA3-384 | `fdf3aa7fa08520a47c0c1282bc71123e11aa2322bf322421d93628d177213c267ecf5534ee085128fc6f64e99bff45ce` |
| TLSH | `T176B52329485921FF4E01F2F6BF17B461B98D23C38E821707537C85A438E8A799F67C96` |
| SSDEEP | `49152:mzELAt2zqRhcoLBN8FKAGzcOXyBbYMi6k4:b` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_019_9a46c789
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a46c78920200428c73737ffc7751df004a0a9f6c092aff0c28da8403a4a0ad7"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:35:00"
  condition:
    hash.sha256(0, filesize) == "9a46c78920200428c73737ffc7751df004a0a9f6c092aff0c28da8403a4a0ad7"
}
```

### Sample 20: `fd0514bef8da697f`

| Field | Value |
|---|---|
| SHA-256 | `fd0514bef8da697fde6c1d8f1968ca7246eb8e79c5672a010f4241e96c3d3bf2` |
| Family label | `RemcosRAT` |
| File name | `secured_stub.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:33:48` |
| Reporter | `abuse_ch` |
| Tags | `ps1, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `189cdaa9802e8fe245871e9a1ca472be` |
| SHA-1 | `763f0b00defb408dfcfbe39f0d66d10c1679cd3c` |
| SHA-256 | `fd0514bef8da697fde6c1d8f1968ca7246eb8e79c5672a010f4241e96c3d3bf2` |
| SHA3-384 | `def73233cfb5684c64e84a249519cb46adbf5837985082c5da2ccc189b3397b03640447176fdcea254300306e4beebb0` |
| TLSH | `T1B6B52329496E23CF0601E1FB7612B452B1E722C74E8612A313BDC7A832F8975D727D97` |
| SSDEEP | `24576:aDk2WvzYWUvHemUJh0a6QOgyvnU/aY3mx8ZaMAV+o7ztMDIbB0MN7qJuC/oLaFyw:akE7HLwKx8JEd2MKCslz/U1VQ7dpTZ` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_020_fd0514be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd0514bef8da697fde6c1d8f1968ca7246eb8e79c5672a010f4241e96c3d3bf2"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:33:48"
  condition:
    hash.sha256(0, filesize) == "fd0514bef8da697fde6c1d8f1968ca7246eb8e79c5672a010f4241e96c3d3bf2"
}
```

### Sample 21: `f6d69ff1e14768a8`

| Field | Value |
|---|---|
| SHA-256 | `f6d69ff1e14768a8baebedfd572e8804ea46d24ebe02490d3d84562e10b0b0d8` |
| Family label | `RemcosRAT` |
| File name | `secured_stub.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:32:56` |
| Reporter | `abuse_ch` |
| Tags | `ps1, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fff1f0a9fb2867e2a41aabb98164b59d` |
| SHA-1 | `2e3b0245fc02b93ee2c755ca945cc330fb133103` |
| SHA-256 | `f6d69ff1e14768a8baebedfd572e8804ea46d24ebe02490d3d84562e10b0b0d8` |
| SHA3-384 | `ea58e4413bc65b7d3f04c0758e93e11b5033ca0f83d7727508eedfc43320d0e97b53ec6c1efbd5ea05f29b7977e8f240` |
| TLSH | `T196B52354AA8E13DF0E12B3FDB755B44566CA03C34D434327836D8670B7F9AB89AA3C52` |
| SSDEEP | `24576:1Ft5R+vYuuYRD7atRFHQJmKztUpvGEx7GQX1LYQFq2uF3QvonjCvf3Ak7oftDsgM:1LzzuctRWzMuG7x1WvwofZgyJKj` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_021_f6d69ff1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6d69ff1e14768a8baebedfd572e8804ea46d24ebe02490d3d84562e10b0b0d8"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:32:56"
  condition:
    hash.sha256(0, filesize) == "f6d69ff1e14768a8baebedfd572e8804ea46d24ebe02490d3d84562e10b0b0d8"
}
```

### Sample 22: `6e886c90177dbca7`

| Field | Value |
|---|---|
| SHA-256 | `6e886c90177dbca761234b09ebc8493699b3925332ccf0ed1c178214a6c6b657` |
| Family label | `RemcosRAT` |
| File name | `secured_stub.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:32:05` |
| Reporter | `abuse_ch` |
| Tags | `ps1, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c71642651236bd61cf9321de321dcac9` |
| SHA-1 | `4d1316931852af2c54dd29015d2fe2b570d4716f` |
| SHA-256 | `6e886c90177dbca761234b09ebc8493699b3925332ccf0ed1c178214a6c6b657` |
| SHA3-384 | `00c290a3a21837c52da73c4b7a0db7bf10f22240745495552735f00c8324eacfcce02537c76c425d5ee4b8581220a0ce` |
| TLSH | `T1C7B52335D5CF33CF0615A2FAF162A8C5B5AE12838A814257436CC3F832E95F9AB53D61` |
| SSDEEP | `24576:zxKHbyhV9xNGPfdkuyKmgQrtYGI2Oqx4oT/IVoPFSx/jKrI+N/NGrDFfErgl5x+Y:gWH1bY6xBCnGVzxZnMzgYnW301` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_022_6e886c90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e886c90177dbca761234b09ebc8493699b3925332ccf0ed1c178214a6c6b657"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:32:05"
  condition:
    hash.sha256(0, filesize) == "6e886c90177dbca761234b09ebc8493699b3925332ccf0ed1c178214a6c6b657"
}
```

### Sample 23: `2f1bd42fedeadb24`

| Field | Value |
|---|---|
| SHA-256 | `2f1bd42fedeadb2418d125a9484cace882b47c48b14f6d55fbf9173d8d857106` |
| Family label | `RemcosRAT` |
| File name | `secured_stub.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:30:52` |
| Reporter | `abuse_ch` |
| Tags | `ps1, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ba67f736230448cc508d368c8e8d36d` |
| SHA-1 | `17874efe763f157f94ab235a9a4799199db864e7` |
| SHA-256 | `2f1bd42fedeadb2418d125a9484cace882b47c48b14f6d55fbf9173d8d857106` |
| SHA3-384 | `34cabd3c6720e76905b38af5737c4da34c2f95e6a81a050ce66a328f5ba820b2501ed323c80dbe8e5e7f9b5264a0d08e` |
| TLSH | `T136B5231CE64926EB0900E2F5BD05ED4962DE93C74C86035A43EC427833F49B5ABB7DA7` |
| SSDEEP | `49152:aHW39op0Umt4EmjDqghSDB9O6Hin1qbJ+JZ:M` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_023_2f1bd42f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f1bd42fedeadb2418d125a9484cace882b47c48b14f6d55fbf9173d8d857106"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:30:52"
  condition:
    hash.sha256(0, filesize) == "2f1bd42fedeadb2418d125a9484cace882b47c48b14f6d55fbf9173d8d857106"
}
```

### Sample 24: `9c7b899c08a1c236`

| Field | Value |
|---|---|
| SHA-256 | `9c7b899c08a1c2368bc8dc090a535e4c41113bef8b7d2d300629f93f3e0c1a94` |
| Family label | `RemcosRAT` |
| File name | `Contract000388122-LSI-TQVL-PDF.jse` |
| File type | `jse` |
| First seen | `2026-11-24 09:30:41` |
| Reporter | `ni_fi_70` |
| Tags | `jse, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe083a7b00e45e1bba2168167265b6cd` |
| SHA-1 | `f1acc5047b8badb282b576f71c01d0174e2867e5` |
| SHA-256 | `9c7b899c08a1c2368bc8dc090a535e4c41113bef8b7d2d300629f93f3e0c1a94` |
| SHA3-384 | `c33be3665f71771eb01836651d15e079d5b4b584e3b411a88d15413a94587b496e15c4fb3578cafea7fbddf514922a88` |
| TLSH | `T187F1319DAD66A0759977B33E8F1B9509F73A842B4205C158B88CC2D81F7135082E9FFE` |
| SSDEEP | `96:CVx4Dz2HnfayVd0kZiKMcYxDb/YPD2sHcCsgmz7xE11PHajOk/wbyE:C2AhX0eMc6Db/IHgF1E1hHaKk/wbz` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `jse`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_024_9c7b899c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c7b899c08a1c2368bc8dc090a535e4c41113bef8b7d2d300629f93f3e0c1a94"
    family = "RemcosRAT"
    file_name = "Contract000388122-LSI-TQVL-PDF.jse"
    file_type = "jse"
    first_seen = "2026-11-24 09:30:41"
  condition:
    hash.sha256(0, filesize) == "9c7b899c08a1c2368bc8dc090a535e4c41113bef8b7d2d300629f93f3e0c1a94"
}
```

### Sample 25: `22722a6aba316405`

| Field | Value |
|---|---|
| SHA-256 | `22722a6aba31640558e50a48c9d661f12d7d259859b66a7dae97ec08e6f47d42` |
| Family label | `unknown` |
| File name | `ARRIVALNOTICE-77B738.jse` |
| File type | `jse` |
| First seen | `2026-11-24 09:30:38` |
| Reporter | `ni_fi_70` |
| Tags | `jse` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf0f1522a5d1bf2c13a40482875a0c44` |
| SHA-1 | `a92f439d99abfd2d3522f69810cdf22f878b1527` |
| SHA-256 | `22722a6aba31640558e50a48c9d661f12d7d259859b66a7dae97ec08e6f47d42` |
| SHA3-384 | `b4f2bdf4f96187e7541626df028a68018fbe7b713a229279ab8ad354d44627eb6bbc108e2da21f08e1a6cb683a89a13c` |
| TLSH | `T153F1E09D995250758E73637ACF2B8519FB6A043B0605C21DB48CC2D95FB135482E8FFE` |
| SSDEEP | `96:gRTLfXlimPYkhxVLiGjD2XlY+gDZVEB0aIG:ALUmPLFLiTYx3EB0aIG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jse`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_22722a6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22722a6aba31640558e50a48c9d661f12d7d259859b66a7dae97ec08e6f47d42"
    family = "unknown"
    file_name = "ARRIVALNOTICE-77B738.jse"
    file_type = "jse"
    first_seen = "2026-11-24 09:30:38"
  condition:
    hash.sha256(0, filesize) == "22722a6aba31640558e50a48c9d661f12d7d259859b66a7dae97ec08e6f47d42"
}
```

### Sample 26: `a4b3375b314ac700`

| Field | Value |
|---|---|
| SHA-256 | `a4b3375b314ac7009639ae894b765e4703f50a03e02cebba7b81169df7e06bbd` |
| Family label | `unknown` |
| File name | `RFQSpecs.js` |
| File type | `js` |
| First seen | `2026-11-24 09:30:35` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a78d2396506ef7894fd55adda04bfc9f` |
| SHA-1 | `da9132de061dd56086bd79b700a45c475e93d715` |
| SHA-256 | `a4b3375b314ac7009639ae894b765e4703f50a03e02cebba7b81169df7e06bbd` |
| SHA3-384 | `ab8f52b5e3f77793e2c293156bf21110c7b015f842c51df0f201c108e47e10e661358789dd946f53c5a89c462109e4d6` |
| TLSH | `T123054C61ED25067E0E4713AEBCA50BA2CB7D8509452754F6E6CE070E60069ECF3BE76C` |
| SSDEEP | `6144:i5anl5anX5anv5aQ5g5ae5anJo5anw5Z5an7l55anW:i545s5S5V5g5f52o5/5Z5Ml55P` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_a4b3375b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4b3375b314ac7009639ae894b765e4703f50a03e02cebba7b81169df7e06bbd"
    family = "unknown"
    file_name = "RFQSpecs.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:35"
  condition:
    hash.sha256(0, filesize) == "a4b3375b314ac7009639ae894b765e4703f50a03e02cebba7b81169df7e06bbd"
}
```

### Sample 27: `9e462be7ae0d8392`

| Field | Value |
|---|---|
| SHA-256 | `9e462be7ae0d8392cf880b91abad62d66f370ee134d7d96dbf611d9d3e6e7843` |
| Family label | `XWorm` |
| File name | `Statement_of_acccount.js` |
| File type | `js` |
| First seen | `2026-11-24 09:30:32` |
| Reporter | `ni_fi_70` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58adb575111c651ffbef129e0e5d3064` |
| SHA-1 | `30883dfff7357e586d443fca886468ac673b7267` |
| SHA-256 | `9e462be7ae0d8392cf880b91abad62d66f370ee134d7d96dbf611d9d3e6e7843` |
| SHA3-384 | `a9bee75be496df37e75297866df871e691fbab2a37d5dc048fa3ad68889db884c73b3314870e512efcd68c7822eb521b` |
| TLSH | `T1AD5220C820A4FFAC359E13D3162CEE01938D8A59E95696D1269F3ECC3975C2A7B3075C` |
| SSDEEP | `192:2yx6RWDyx6RWDyx6RWz8W/hMivQyx6RWDyx6RWDyx6RWc:29AD9AD9Az8WJMi49AD9AD9Ac` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_027_9e462be7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e462be7ae0d8392cf880b91abad62d66f370ee134d7d96dbf611d9d3e6e7843"
    family = "XWorm"
    file_name = "Statement_of_acccount.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:32"
  condition:
    hash.sha256(0, filesize) == "9e462be7ae0d8392cf880b91abad62d66f370ee134d7d96dbf611d9d3e6e7843"
}
```

### Sample 28: `3fd469cbd20391b8`

| Field | Value |
|---|---|
| SHA-256 | `3fd469cbd20391b891c4ee210c121780cf44f09e49e7d1b25fbc8913bffead5e` |
| Family label | `unknown` |
| File name | `attachment.js` |
| File type | `js` |
| First seen | `2026-11-24 09:30:29` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `421bbbb5e4945820885988d07602dd37` |
| SHA-1 | `46556eb731e2dd49fbb4f73809fba8a07d16b2e4` |
| SHA-256 | `3fd469cbd20391b891c4ee210c121780cf44f09e49e7d1b25fbc8913bffead5e` |
| SHA3-384 | `04ceab7c5ee244427f519f7da038db0d9922e4603e5b6b89f0d690228d59ef30fbe01a351fec60da88caf81948d28983` |
| TLSH | `T128054C61ED25066E0E4713AEBCA50BB2CB7D8509852754F6E6CE070E60065ECF3BE76C` |
| SSDEEP | `6144:CG5ani5anX5anf5aU5K5ae5anio5anV5Z5anZSi5anT:CG5N5s5K5R5K5f5Fo5g5Z5KSi5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_3fd469cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fd469cbd20391b891c4ee210c121780cf44f09e49e7d1b25fbc8913bffead5e"
    family = "unknown"
    file_name = "attachment.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:29"
  condition:
    hash.sha256(0, filesize) == "3fd469cbd20391b891c4ee210c121780cf44f09e49e7d1b25fbc8913bffead5e"
}
```

### Sample 29: `26e898f52eb5a272`

| Field | Value |
|---|---|
| SHA-256 | `26e898f52eb5a272323374a4816fcfe762bad2dc32bbb4b98fe3f817818f1adb` |
| Family label | `Formbook` |
| File name | `MaterialLists-ItemsRequirements.js` |
| File type | `js` |
| First seen | `2026-11-24 09:30:22` |
| Reporter | `ni_fi_70` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6d43dbc4a98997f811136a1f4cdf053` |
| SHA-1 | `159921f8ff57049fc30773154bf31262a2347602` |
| SHA-256 | `26e898f52eb5a272323374a4816fcfe762bad2dc32bbb4b98fe3f817818f1adb` |
| SHA3-384 | `519d1a4a970febe36dc271690eeea9eebddddfda6c02ec6cf48d7716dbecdd65e0b33a9d02b40907917bd732bd9299c0` |
| TLSH | `T1B4C4131BDBE1B4C6182C0520B34D1D2978EF256E289995E1378ED2D61FEC7028E97DCB` |
| SSDEEP | `12288:o98phmT02FVVwdtY/iJ7O1LIFjOoNnInm/H5GFJHrrKkk:oephmFVGU/ipGLSNInA5GFJHu` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_029_26e898f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26e898f52eb5a272323374a4816fcfe762bad2dc32bbb4b98fe3f817818f1adb"
    family = "Formbook"
    file_name = "MaterialLists-ItemsRequirements.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:22"
  condition:
    hash.sha256(0, filesize) == "26e898f52eb5a272323374a4816fcfe762bad2dc32bbb4b98fe3f817818f1adb"
}
```

### Sample 30: `56539d7e09290ccd`

| Field | Value |
|---|---|
| SHA-256 | `56539d7e09290ccd0068252f1dccca3b910bd31eee9d4e37c6d48dc10a828259` |
| Family label | `RemcosRAT` |
| File name | `invoice.js` |
| File type | `js` |
| First seen | `2026-11-24 09:30:19` |
| Reporter | `ni_fi_70` |
| Tags | `js, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87476c95d3732030344c7daf14b24f05` |
| SHA-1 | `2aa6a618ebc7d87b7fcd973a0ee72045d73d6609` |
| SHA-256 | `56539d7e09290ccd0068252f1dccca3b910bd31eee9d4e37c6d48dc10a828259` |
| SHA3-384 | `bbb7d74e54c2e5923791e4966a523ae369fa2289beaea93e810cb04b1603aa9ec611926575764d487f4cecb83744708e` |
| TLSH | `T144E423039AA24CCA12401974F301A13F69AF174DA98B55A637DEE0C11FAD7D3AC9FC97` |
| SSDEEP | `12288:rvMu6MohopBU3tWW554WgypuU2mt+IubtV/PeOHaD7RJ/KQnF/lKiqQ:rZ4ooWWLEknIPeOU7RhjK6` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_030_56539d7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56539d7e09290ccd0068252f1dccca3b910bd31eee9d4e37c6d48dc10a828259"
    family = "RemcosRAT"
    file_name = "invoice.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:19"
  condition:
    hash.sha256(0, filesize) == "56539d7e09290ccd0068252f1dccca3b910bd31eee9d4e37c6d48dc10a828259"
}
```

### Sample 31: `e1fd622d7bfe5be1`

| Field | Value |
|---|---|
| SHA-256 | `e1fd622d7bfe5be1d17f19d4ec9e7e39d5224e658be885ced429848630f87bc5` |
| Family label | `AsyncRAT` |
| File name | `CotizacinOrdendecompra.js` |
| File type | `js` |
| First seen | `2026-11-24 09:30:16` |
| Reporter | `ni_fi_70` |
| Tags | `AsyncRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70855d363f7989bd6cf056758cac617f` |
| SHA-1 | `f172f4bce90a76c833c6628732ce062641fe81e6` |
| SHA-256 | `e1fd622d7bfe5be1d17f19d4ec9e7e39d5224e658be885ced429848630f87bc5` |
| SHA3-384 | `7f171c23049516973e80ff84005d6e378d0c32417eea8cb091b8839503849c49ff8dd9c5b52372816f1e4abf198fa6c5` |
| TLSH | `T1B063CF1B867F206722462B789A4B142205DC201F145ED14C7A4CE2E66FF9FC4AEF6BD3` |
| SSDEEP | `768:XYwJuqhRc3ckYnfLGCr+uZIezm1UJ4JD//r3IWVB4E2kQMXPDik3+TDYHWBrIqVj:XO2BMU2j3fYE2x3k6mC7j8aQF1eonGV` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_031_e1fd622d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1fd622d7bfe5be1d17f19d4ec9e7e39d5224e658be885ced429848630f87bc5"
    family = "AsyncRAT"
    file_name = "CotizacinOrdendecompra.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:16"
  condition:
    hash.sha256(0, filesize) == "e1fd622d7bfe5be1d17f19d4ec9e7e39d5224e658be885ced429848630f87bc5"
}
```

### Sample 32: `5b08d49c1b4bc0dd`

| Field | Value |
|---|---|
| SHA-256 | `5b08d49c1b4bc0dd521c8376f1f0e78de58fdaa2fd4638a8a1616e31ae3b1d5e` |
| Family label | `FormBook` |
| File name | `PO_Eco-26112418EA1.js` |
| File type | `js` |
| First seen | `2026-11-24 09:30:13` |
| Reporter | `ni_fi_70` |
| Tags | `FormBook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d341f6579caf1c7cb60b19604fde0f4` |
| SHA-1 | `c1b0841cd8a3dfec879c23aaa3d3640121e93e69` |
| SHA-256 | `5b08d49c1b4bc0dd521c8376f1f0e78de58fdaa2fd4638a8a1616e31ae3b1d5e` |
| SHA3-384 | `ac7588634152cd6c58c351ead50d50d702e9cc08dc2f27e00bf6dbcd386051c82387d02126c25a7074d66078751cb9e9` |
| TLSH | `T1425402071AFA5841365A44BD824FAD2AACED348F64AF92C4734D71C91FAE7025E4ECD3` |
| SSDEEP | `6144:9Qi7CFxFP7ZlOjEh/hJ/9lWFVuGelhm223MZGAFjkTqn:wF7ZlGEhpo1el8MZGAF+qn` |

#### Technical Assessment

- The sample is tracked as `FormBook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_FormBook_032_5b08d49c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b08d49c1b4bc0dd521c8376f1f0e78de58fdaa2fd4638a8a1616e31ae3b1d5e"
    family = "FormBook"
    file_name = "PO_Eco-26112418EA1.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:13"
  condition:
    hash.sha256(0, filesize) == "5b08d49c1b4bc0dd521c8376f1f0e78de58fdaa2fd4638a8a1616e31ae3b1d5e"
}
```

### Sample 33: `d6c8a5606c18820a`

| Field | Value |
|---|---|
| SHA-256 | `d6c8a5606c18820ac76563beb915d6ce0b8100da5eff096a50817c0fb72957fc` |
| Family label | `unknown` |
| File name | `update.js` |
| File type | `js` |
| First seen | `2026-11-24 09:29:20` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81cc99e4d483131f3f879262f7873978` |
| SHA-1 | `28c8a41c06bf15547cab8685762aa0b296b38e05` |
| SHA-256 | `d6c8a5606c18820ac76563beb915d6ce0b8100da5eff096a50817c0fb72957fc` |
| SHA3-384 | `f9f159041166082619fb62e63ffdf11fd6f441496999a0630de97e8f80f03bd3f41d1b739a92b4c26fe299076727e191` |
| TLSH | `T134054C21DE3506268F471B9EBCE10661CABD851E522794B0F6DA430E61068ECD3BF7BD` |
| SSDEEP | `12288:ubbbrxbR+8b7b0bybXbEbRbWZCKb8MbF4obCsSZbjbaz:uv/xN+8v4ObXoVqZCKQMB4omsSZX+z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_d6c8a560
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6c8a5606c18820ac76563beb915d6ce0b8100da5eff096a50817c0fb72957fc"
    family = "unknown"
    file_name = "update.js"
    file_type = "js"
    first_seen = "2026-11-24 09:29:20"
  condition:
    hash.sha256(0, filesize) == "d6c8a5606c18820ac76563beb915d6ce0b8100da5eff096a50817c0fb72957fc"
}
```

### Sample 34: `b20034a10e4334fe`

| Field | Value |
|---|---|
| SHA-256 | `b20034a10e4334fe85a949df3e281b7d25cdce02afd8122b23471205cb33e975` |
| Family label | `RemcosRAT` |
| File name | `secured_stub.ps1` |
| File type | `ps1` |
| First seen | `2026-11-24 09:26:57` |
| Reporter | `abuse_ch` |
| Tags | `ps1, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2430270164d653bc80ef2818f032710f` |
| SHA-1 | `71fd44e41e37d0181b4029801c7f4e8494abfbb1` |
| SHA-256 | `b20034a10e4334fe85a949df3e281b7d25cdce02afd8122b23471205cb33e975` |
| SHA3-384 | `66921c98ed07e47efeca6a8fd0779c1bdfdf435fd0d014ca9a675bdb61c9a5e23ce81c2565efbf0c0df23ab4c27e1663` |
| TLSH | `T1B9B5232D585E53FF0D0163BBB2697C5530AE568E4D83036642FCC6A431F50B89BEBDA2` |
| SSDEEP | `24576:rGHjM9tMD+oPjZpF9h4NBOEP/ytQu/5kOStF6iviH2iLQIyhChWvWtTKyInogi3A:rcP9ENB1TI5StWjEjAMgsLoY` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_034_b20034a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b20034a10e4334fe85a949df3e281b7d25cdce02afd8122b23471205cb33e975"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:26:57"
  condition:
    hash.sha256(0, filesize) == "b20034a10e4334fe85a949df3e281b7d25cdce02afd8122b23471205cb33e975"
}
```

### Sample 35: `19aa0b9ad7c714ad`

| Field | Value |
|---|---|
| SHA-256 | `19aa0b9ad7c714ad82d396640df2d30723cda6ad0863186a285b540de1a8d06b` |
| Family label | `NanoCore` |
| File name | `77458DAD3B4731D80ECE2DA6C8A0EF60.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:25:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77458dad3b4731d80ece2da6c8a0ef60` |
| SHA-1 | `d3d307160efab509c5011d633332d7875c64f447` |
| SHA-256 | `19aa0b9ad7c714ad82d396640df2d30723cda6ad0863186a285b540de1a8d06b` |
| SHA3-384 | `306bedaa023e5765faf8201ee98d9046d995db7342cdbd257424c35d96dcf6929dffea3a2d316dc52549fe70a5642914` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C9D4125826588A23D47667740DB1F778837E2EAED811E3478FD86CEBB862E100D607D7` |
| SSDEEP | `12288:XrxZDhmKv2MVaq44AM8EEd4uSqnItCDvqIQpTFTkya:9ZNmAhD/8EYSqBDv6TFTkN` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_035_19aa0b9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19aa0b9ad7c714ad82d396640df2d30723cda6ad0863186a285b540de1a8d06b"
    family = "NanoCore"
    file_name = "77458DAD3B4731D80ECE2DA6C8A0EF60.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:25:09"
  condition:
    hash.sha256(0, filesize) == "19aa0b9ad7c714ad82d396640df2d30723cda6ad0863186a285b540de1a8d06b"
}
```

### Sample 36: `ac9e1ddf68eb15ce`

| Field | Value |
|---|---|
| SHA-256 | `ac9e1ddf68eb15cecae4844c87edc69ab90948599c321cc55394b60dcdf27d79` |
| Family label | `Formbook` |
| File name | `DQpvdsX6JmqGDcC.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:21:14` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9b91b56315e8f2618adcb33944b283c` |
| SHA-1 | `e3e6f3abd0192274fb0b421d3a3a7ec58d463a09` |
| SHA-256 | `ac9e1ddf68eb15cecae4844c87edc69ab90948599c321cc55394b60dcdf27d79` |
| SHA3-384 | `3afe19c0b62156506137d5f0fba71af801d54a26a2135d49c7f711f685ccc67ac596159002f4219530c2c40d62bc646c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T197158BDFF56AC802C8610E7ED8A0F1F462B55D79D522C2471AD63EAF7F32B41098126E` |
| SSDEEP | `24576:mvex2swlanZC3lrXkUPYQ1wTqYm2lj1XZVZf1qwm:oanVA1wTjTZR` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_036_ac9e1ddf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac9e1ddf68eb15cecae4844c87edc69ab90948599c321cc55394b60dcdf27d79"
    family = "Formbook"
    file_name = "DQpvdsX6JmqGDcC.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:21:14"
  condition:
    hash.sha256(0, filesize) == "ac9e1ddf68eb15cecae4844c87edc69ab90948599c321cc55394b60dcdf27d79"
}
```

### Sample 37: `4d6983a6925d67a3`

| Field | Value |
|---|---|
| SHA-256 | `4d6983a6925d67a38f1b3f663d92af15854440c05fa4e16e82126f53bb71c4a1` |
| Family label | `Formbook` |
| File name | `pd224334177.att` |
| File type | `exe` |
| First seen | `2026-11-24 09:21:11` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4433d2718b4a8a1bd35d6152ad6ead4` |
| SHA-1 | `e6703e6fa04e08b9c4da4f6a7967d5b50bf8b94e` |
| SHA-256 | `4d6983a6925d67a38f1b3f663d92af15854440c05fa4e16e82126f53bb71c4a1` |
| SHA3-384 | `2656fc867831bdf8e30d718f92249702b82415a3e2c82edc48a46e4f263229f2590ec49fcd95d03bcab1557e4afa427d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19215ACDFF15AC802C8615E7EE891F1F422705D79D922C60B1AD63EAF7F32B51198026E` |
| SSDEEP | `12288:DyXJfqwmxieG2PB0FoFlbm7nxAeSHsQ01rAqIr032eN0uAH3ZHueW7+nc:mRqwmy250ifSlAhboAqf32equAXZH1` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_037_4d6983a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d6983a6925d67a38f1b3f663d92af15854440c05fa4e16e82126f53bb71c4a1"
    family = "Formbook"
    file_name = "pd224334177.att"
    file_type = "exe"
    first_seen = "2026-11-24 09:21:11"
  condition:
    hash.sha256(0, filesize) == "4d6983a6925d67a38f1b3f663d92af15854440c05fa4e16e82126f53bb71c4a1"
}
```

### Sample 38: `ce0b584bb313f25d`

| Field | Value |
|---|---|
| SHA-256 | `ce0b584bb313f25d2c1ade13b3084e75959132fcb9994a63d3d37ac717f68a59` |
| Family label | `Formbook` |
| File name | `Comprobante_SWIFT_Transferencia_Internacional.pdf.pif` |
| File type | `exe` |
| First seen | `2026-11-24 09:21:08` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df2fadc0ec1662b8555b11139ce7c307` |
| SHA-1 | `2e9c0185bd9a7b764b93b632c0af4b73412473d5` |
| SHA-256 | `ce0b584bb313f25d2c1ade13b3084e75959132fcb9994a63d3d37ac717f68a59` |
| SHA3-384 | `29b99c20857fc1d7b557b07ce48f7e0f0926a605c4fe02ecd45c9f449617f7d78e3f3d7928947c198dcac8e653e9667b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C415ACDFF158C906D8620EBEE821F2F466B5AEB5E521C1075AD27DAF7F35B00094026E` |
| SSDEEP | `24576:6sqwmMh727kfoHcu8lIVz0yp4BSLzjhw72k:Bd6kzKz0oL5w72` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_038_ce0b584b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce0b584bb313f25d2c1ade13b3084e75959132fcb9994a63d3d37ac717f68a59"
    family = "Formbook"
    file_name = "Comprobante_SWIFT_Transferencia_Internacional.pdf.pif"
    file_type = "exe"
    first_seen = "2026-11-24 09:21:08"
  condition:
    hash.sha256(0, filesize) == "ce0b584bb313f25d2c1ade13b3084e75959132fcb9994a63d3d37ac717f68a59"
}
```

### Sample 39: `12d250da2d8b2ec0`

| Field | Value |
|---|---|
| SHA-256 | `12d250da2d8b2ec0c8857c3c3b7fe9343429f7702ac9eda3627f789a93cda436` |
| Family label | `unknown` |
| File name | `PRO-D3.js` |
| File type | `js` |
| First seen | `2026-11-24 09:21:05` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3fdc3fd983f9bb35310498a3485deea` |
| SHA-1 | `f7e90843b02774f55e20ffe60cc95a0f87396776` |
| SHA-256 | `12d250da2d8b2ec0c8857c3c3b7fe9343429f7702ac9eda3627f789a93cda436` |
| SHA3-384 | `d5c150e61218ba2158e2f193375435e3b0c7aec96854556992ddd8f8eee3f178537e0e073e78099003d179ea0be8cf66` |
| TLSH | `T14E1402809F965D9F53B5EF19644D29048AFC8A312CDCF15F1BB8D0C64B3E6A01366C4B` |
| SSDEEP | `3072:D3CRxRl+ia+cZUZZaDFD4Qed6Rq+cv1Im2q3hwK8boIs/M+CK0V3UcrEPPWD:D3Z9+vat4QeZ4mN8bA/M+CBwP2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_12d250da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12d250da2d8b2ec0c8857c3c3b7fe9343429f7702ac9eda3627f789a93cda436"
    family = "unknown"
    file_name = "PRO-D3.js"
    file_type = "js"
    first_seen = "2026-11-24 09:21:05"
  condition:
    hash.sha256(0, filesize) == "12d250da2d8b2ec0c8857c3c3b7fe9343429f7702ac9eda3627f789a93cda436"
}
```

### Sample 40: `3af3760b0ccace98`

| Field | Value |
|---|---|
| SHA-256 | `3af3760b0ccace9887e3ea58b0dece8ff3f701dfa255695ce92e50a58ab9a2fa` |
| Family label | `AsyncRAT` |
| File name | `OrdendeCompra_PO4501887325.pdf.js` |
| File type | `js` |
| First seen | `2026-11-24 09:21:00` |
| Reporter | `ni_fi_70` |
| Tags | `AsyncRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b61852b0776c35f30f04a59e79ab09c8` |
| SHA-1 | `8e43bc323192b536c534f39265cd1f72b3acfb48` |
| SHA-256 | `3af3760b0ccace9887e3ea58b0dece8ff3f701dfa255695ce92e50a58ab9a2fa` |
| SHA3-384 | `37f4425ee71be0d8cd108d74e5a2d36e7b3c78a3bc559510be1cac0079668d29502c00fbfc72ed8b22dea25437bd7662` |
| TLSH | `T12EB3F2C2A7D224ABC270CD39041F1B09CEE9E9A67D8EB90AD97CD0875B7CA1741F9C45` |
| SSDEEP | `3072:GNpfHuJIZQcSgdUt3kqG8E6Nc0SmAPwzZ0Vvie/dqoho:9WZvfut3kKEMdl8v30oho` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_040_3af3760b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3af3760b0ccace9887e3ea58b0dece8ff3f701dfa255695ce92e50a58ab9a2fa"
    family = "AsyncRAT"
    file_name = "OrdendeCompra_PO4501887325.pdf.js"
    file_type = "js"
    first_seen = "2026-11-24 09:21:00"
  condition:
    hash.sha256(0, filesize) == "3af3760b0ccace9887e3ea58b0dece8ff3f701dfa255695ce92e50a58ab9a2fa"
}
```

### Sample 41: `a5e4fab4958854fa`

| Field | Value |
|---|---|
| SHA-256 | `a5e4fab4958854fa69b330d2294d80566b966b9b7f50ae40c2478375ff010991` |
| Family label | `AsyncRAT` |
| File name | `PO.js` |
| File type | `js` |
| First seen | `2026-11-24 09:20:58` |
| Reporter | `ni_fi_70` |
| Tags | `AsyncRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bdc93af9056b2fb0af34f5f87ba801a` |
| SHA-1 | `8f8875020bc3404af2d55efcabb7f3046029bd98` |
| SHA-256 | `a5e4fab4958854fa69b330d2294d80566b966b9b7f50ae40c2478375ff010991` |
| SHA3-384 | `885f86ac5722fd328c359f84713e1abab3f9771360215bc9e8a13892e8739f2b4810fc0a339e1dc469f04efb5ff998c4` |
| TLSH | `T114B302955BE60FAFC2F4DDE80C2E062E5AF499355D5C5888D398C4C3173E62883E5CAB` |
| SSDEEP | `1536:sUI54j9vwv9HBGeEESZCIP7eBPVNFenvZCWsnzY7jFJGWO8y+53ZEUTklOi2QDRv:si9ov9QTLCn/YxUnzWjFrmG9S9yBWZ` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_041_a5e4fab4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5e4fab4958854fa69b330d2294d80566b966b9b7f50ae40c2478375ff010991"
    family = "AsyncRAT"
    file_name = "PO.js"
    file_type = "js"
    first_seen = "2026-11-24 09:20:58"
  condition:
    hash.sha256(0, filesize) == "a5e4fab4958854fa69b330d2294d80566b966b9b7f50ae40c2478375ff010991"
}
```

### Sample 42: `a2aa32f80d0504fc`

| Field | Value |
|---|---|
| SHA-256 | `a2aa32f80d0504fc57b110d8e06177cfb754eba889c816fc72d5a4226c846a4d` |
| Family label | `Formbook` |
| File name | `SWIFTMESAJIPDF.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:20:55` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86a380e44c772ce6dd6bc830297718b5` |
| SHA-1 | `c5816d42737f1711b67e7d26bb7345d239646aaf` |
| SHA-256 | `a2aa32f80d0504fc57b110d8e06177cfb754eba889c816fc72d5a4226c846a4d` |
| SHA3-384 | `e140c1b0ee82966545a3e159fa67937bb7c1847fd7fa78b197f0e198cde91278f9ff55a64862a8a6f7537da6ef539e27` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C205F115263CCF02E8B71BF90A62E1B463F66C89A531D2029EE66DEF7D357404E507A3` |
| SSDEEP | `24576:pFCTs7qwm5V4ONWR70r74yR97tc3XNmceaUwIbvyae:HCT0wVRNWRWv6NmctULvX` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_042_a2aa32f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2aa32f80d0504fc57b110d8e06177cfb754eba889c816fc72d5a4226c846a4d"
    family = "Formbook"
    file_name = "SWIFTMESAJIPDF.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:55"
  condition:
    hash.sha256(0, filesize) == "a2aa32f80d0504fc57b110d8e06177cfb754eba889c816fc72d5a4226c846a4d"
}
```

### Sample 43: `bc2df196c06783ea`

| Field | Value |
|---|---|
| SHA-256 | `bc2df196c06783eabf71cef8d859abec8b298f44a52e3f56e22dc02f30f52411` |
| Family label | `AgentTesla` |
| File name | `PO_4500102673_S.S.Grow.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:20:52` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79eb44278321375cdb8bf37d04dd9669` |
| SHA-1 | `178086d7263e634398d4c11934364537b9959eb0` |
| SHA-256 | `bc2df196c06783eabf71cef8d859abec8b298f44a52e3f56e22dc02f30f52411` |
| SHA3-384 | `1bec4cfd55050ea770d5c572e20923d1a693997ef8de766a6621be06f2fe8e60b5722f9d8becac2189ba2d4ef57bdc82` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1DD05F014262DCF06E8B75BF90EA2E1F403B9AD896531D2464ED66DDF7D3A7001E00BA3` |
| SSDEEP | `24576:wrN8TaJqwm5eGmteRVjIcikVYaau+vhQltZU+:88T4SEtetfNauGhQg` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_043_bc2df196
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc2df196c06783eabf71cef8d859abec8b298f44a52e3f56e22dc02f30f52411"
    family = "AgentTesla"
    file_name = "PO_4500102673_S.S.Grow.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:52"
  condition:
    hash.sha256(0, filesize) == "bc2df196c06783eabf71cef8d859abec8b298f44a52e3f56e22dc02f30f52411"
}
```

### Sample 44: `810648609fcf3b6f`

| Field | Value |
|---|---|
| SHA-256 | `810648609fcf3b6f5ec40a58fe3fc725b95fedfc67dea283e8936ab89d4a9d55` |
| Family label | `AgentTesla` |
| File name | `NewPurchaseOrderPO367328911.bat` |
| File type | `exe` |
| First seen | `2026-11-24 09:20:49` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `756040c2604d3651dbcb3f677a1fbb8d` |
| SHA-1 | `62a93b24338658a0857372346b92e3b6f5ea1627` |
| SHA-256 | `810648609fcf3b6f5ec40a58fe3fc725b95fedfc67dea283e8936ab89d4a9d55` |
| SHA3-384 | `b07ab4554b77ed05216700fc385f3de60607d1996d0b5c6c2846942637a91235f08feb7af4fe3446ec288cb8d976ea8b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11B05ACEFF168C601C8661EBEE860F2F456B46DB6D922D1075AD27DAF7F35B00094026E` |
| SSDEEP | `12288:qOrHVPqwmFUSPwvZzDFmg6WnDCojbTqqjJVkAgM38VR8eG4Pz+FQbQINud1:1hqwmuxhFmz8+yfkAg12+ayc4C` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_044_81064860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "810648609fcf3b6f5ec40a58fe3fc725b95fedfc67dea283e8936ab89d4a9d55"
    family = "AgentTesla"
    file_name = "NewPurchaseOrderPO367328911.bat"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:49"
  condition:
    hash.sha256(0, filesize) == "810648609fcf3b6f5ec40a58fe3fc725b95fedfc67dea283e8936ab89d4a9d55"
}
```

### Sample 45: `bc27e0e70082a895`

| Field | Value |
|---|---|
| SHA-256 | `bc27e0e70082a89585735e049adbe6e1ff0e01d8972780416b7938880ffbc6b0` |
| Family label | `unknown` |
| File name | `PRO-T07.js` |
| File type | `js` |
| First seen | `2026-11-24 09:20:46` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6448cdf239f26318a1e111aab1104eb9` |
| SHA-1 | `c21dd567869c82647f0aaeaeb656b23efc16b326` |
| SHA-256 | `bc27e0e70082a89585735e049adbe6e1ff0e01d8972780416b7938880ffbc6b0` |
| SHA3-384 | `bf6cda574e87c0edb4412a03036c41e5ce93e9d820e3046ed38c9bb65f77f29d1c7e3887133347927519383f1a9e5b15` |
| TLSH | `T1861412831B858CBBC568C6176CAF120479F5EB83DF58BA0F92BC64C32A3D2750275D1A` |
| SSDEEP | `3072:y81NxEmU+/UbQIAvKQnhXhF2gUVGszo119Vv2Ke05Hh/p8HKRc23tuOM5Yb:y3mBw3ahxF2gUMsyVOf+/p8HUuOt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_bc27e0e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc27e0e70082a89585735e049adbe6e1ff0e01d8972780416b7938880ffbc6b0"
    family = "unknown"
    file_name = "PRO-T07.js"
    file_type = "js"
    first_seen = "2026-11-24 09:20:46"
  condition:
    hash.sha256(0, filesize) == "bc27e0e70082a89585735e049adbe6e1ff0e01d8972780416b7938880ffbc6b0"
}
```

### Sample 46: `2505f0c934f22649`

| Field | Value |
|---|---|
| SHA-256 | `2505f0c934f22649ee6ae0ef092a52ef289a919bfd830e53a8e1f5acbf6bc137` |
| Family label | `unknown` |
| File name | `VCRUNTIME140.dll` |
| File type | `dll` |
| First seen | `2026-11-24 09:20:43` |
| Reporter | `ni_fi_70` |
| Tags | `dll` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c176252532f42d843ac8df3a137bd55` |
| SHA-1 | `8d94ca86ebbe3a2216fd90fe87da0ad8d1088323` |
| SHA-256 | `2505f0c934f22649ee6ae0ef092a52ef289a919bfd830e53a8e1f5acbf6bc137` |
| SHA3-384 | `26498e496e26f5d32ca26566527481d799fd30d675ba1fedbb957279dfe369ea2b374fc7da364a417fd34226d40ef2d5` |
| IMPHASH | `c3f4b93e60dadfffe33a1d525898f94e` |
| TLSH | `T12FE5CA159B88BFBBA1D2D739A65C82FCC075146C69BB3305385FC10FB418821A9FD6E6` |
| SSDEEP | `6144:3fiBhTjuMkbhmU58wfidPuCBWN0dIecbQY3pKyYmNApfSIniSMT8ZyW:3fWhTjrkbhmU5bE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_2505f0c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2505f0c934f22649ee6ae0ef092a52ef289a919bfd830e53a8e1f5acbf6bc137"
    family = "unknown"
    file_name = "VCRUNTIME140.dll"
    file_type = "dll"
    first_seen = "2026-11-24 09:20:43"
  condition:
    hash.sha256(0, filesize) == "2505f0c934f22649ee6ae0ef092a52ef289a919bfd830e53a8e1f5acbf6bc137"
}
```

### Sample 47: `9f94ab1a0c5c315c`

| Field | Value |
|---|---|
| SHA-256 | `9f94ab1a0c5c315cccf7686cc21cd89506e972524ca5cc038b3cc2c5aed79b1d` |
| Family label | `Formbook` |
| File name | `POHTS-PO-0893.scr` |
| File type | `exe` |
| First seen | `2026-11-24 09:20:38` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f50d36e6e6f53dc28e2910b1adc2d6b` |
| SHA-1 | `1381534c9defedb61bcac55ad69afd9535146ad5` |
| SHA-256 | `9f94ab1a0c5c315cccf7686cc21cd89506e972524ca5cc038b3cc2c5aed79b1d` |
| SHA3-384 | `8149f5f7b377ee77ea22d8256ddee676a1f5ce5333ee543e4d293b38643f4aeb616ac7626a656364690c436f62f5a11b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18805F154323DCF06E8B71BF50A61E2B413B5AE896931D2065FE62DDF793A7402E10B63` |
| SSDEEP | `12288:A9ao9T4HqwmPq3Ik8c8ucl14XrEiwRmMr5uAMZvX4KBjIgj6OdzDexY:AZ9T4Hqwm5H1gX4iWlFOAzgj6Odve` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_047_9f94ab1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f94ab1a0c5c315cccf7686cc21cd89506e972524ca5cc038b3cc2c5aed79b1d"
    family = "Formbook"
    file_name = "POHTS-PO-0893.scr"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:38"
  condition:
    hash.sha256(0, filesize) == "9f94ab1a0c5c315cccf7686cc21cd89506e972524ca5cc038b3cc2c5aed79b1d"
}
```

### Sample 48: `0200cd503802d0ab`

| Field | Value |
|---|---|
| SHA-256 | `0200cd503802d0ab38b1c71731e041067e9230f90131d3322df85a80b1beb4c4` |
| Family label | `RemcosRAT` |
| File name | `PNlist_KBD_09112026_final.scr` |
| File type | `exe` |
| First seen | `2026-11-24 09:20:35` |
| Reporter | `ni_fi_70` |
| Tags | `exe, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a0f9cddcddfd376e76cc7450b11b79c` |
| SHA-1 | `16ebe36b85acf2904b7ee752d4408cd38abf94f0` |
| SHA-256 | `0200cd503802d0ab38b1c71731e041067e9230f90131d3322df85a80b1beb4c4` |
| SHA3-384 | `4d46a72d039970c22e3d92413e1874a328b3c272e7d795cd18579c8f158820e7bff46c5a76b3297a329cbf5c2cb54249` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T123350124252CCB06D9B75FF90AA2E1F423F5AE866532D2464FD62DEF79367005B00B63` |
| SSDEEP | `24576:vdLThwqwmg0rv8guVtGf+n4qMzoFnzmasBjWX9eL3wa8bWcnrcnGuZve:FLTIT0z8RtGf+njO8zmnUX9U3wtacYh` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_048_0200cd50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0200cd503802d0ab38b1c71731e041067e9230f90131d3322df85a80b1beb4c4"
    family = "RemcosRAT"
    file_name = "PNlist_KBD_09112026_final.scr"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:35"
  condition:
    hash.sha256(0, filesize) == "0200cd503802d0ab38b1c71731e041067e9230f90131d3322df85a80b1beb4c4"
}
```

### Sample 49: `64dee9d78f858bee`

| Field | Value |
|---|---|
| SHA-256 | `64dee9d78f858bee43021c117bb69acea4f042bc7791881969c8d29c4ff24f68` |
| Family label | `Formbook` |
| File name | `SOA_9904029_PWS022948_WA192026_PDF.com` |
| File type | `exe` |
| First seen | `2026-11-24 09:20:30` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `424f23e01cff7acb7fb8522fc591136c` |
| SHA-1 | `6f7fd353ba2b3d99802d1b0ba764d4ade662e0f5` |
| SHA-256 | `64dee9d78f858bee43021c117bb69acea4f042bc7791881969c8d29c4ff24f68` |
| SHA3-384 | `838f5933ec5ef171e918daa72dfa23bfe875a1f4b7f2116ceea0ff65123ed44cfb107d42addf8d3445e719786541d6f2` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19D050154362DCF02D8B72BFA0A61D2B413F56D866832D2069FE72DEF393A7415A04763` |
| SSDEEP | `24576:8xUTOaqwm5e0q9hv45ov9+gQmWDrXuNKhFUOUlba:qUThSA9hv4uv9+gQmWDreNKbUOUh` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_049_64dee9d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64dee9d78f858bee43021c117bb69acea4f042bc7791881969c8d29c4ff24f68"
    family = "Formbook"
    file_name = "SOA_9904029_PWS022948_WA192026_PDF.com"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:30"
  condition:
    hash.sha256(0, filesize) == "64dee9d78f858bee43021c117bb69acea4f042bc7791881969c8d29c4ff24f68"
}
```

### Sample 50: `c809fb2964bb7eb7`

| Field | Value |
|---|---|
| SHA-256 | `c809fb2964bb7eb701c6777a72bc5af82d7f0c95eac3fa324b684bd06ab309bd` |
| Family label | `unknown` |
| File name | `PO21636.js` |
| File type | `js` |
| First seen | `2026-11-24 09:20:27` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2db0e03a17d952fb6860889452b8a267` |
| SHA-1 | `0becc0a869164cd446f2fdd7c072399d22856218` |
| SHA-256 | `c809fb2964bb7eb701c6777a72bc5af82d7f0c95eac3fa324b684bd06ab309bd` |
| SHA3-384 | `f8a1c39469432cae9e9f638531b5949f8b4fa98a3cb06e8bf78ad1b38685770fd0e769c1300c305a59c1017b56fa4ddd` |
| TLSH | `T1A41412C167C518AF8BBCCA3C58CB670565948A9A3D6EFD49E01ED5C39F6CC720267C0A` |
| SSDEEP | `6144:q4txQNpcpydyGHkZRrcqemszWo7LtncBxw5KRpS:qoypx7HkZNcqxsy0Lt4yME` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_c809fb29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c809fb2964bb7eb701c6777a72bc5af82d7f0c95eac3fa324b684bd06ab309bd"
    family = "unknown"
    file_name = "PO21636.js"
    file_type = "js"
    first_seen = "2026-11-24 09:20:27"
  condition:
    hash.sha256(0, filesize) == "c809fb2964bb7eb701c6777a72bc5af82d7f0c95eac3fa324b684bd06ab309bd"
}
```

### Sample 51: `f42522e5eef67cdd`

| Field | Value |
|---|---|
| SHA-256 | `f42522e5eef67cdd01eaf2bb77e6f58ab1feb3b537884bb951e987ee546a438e` |
| Family label | `Formbook` |
| File name | `IYTDY6355.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:20:24` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20cb78a970baf63b33663855f8f472f0` |
| SHA-1 | `96e9132e3515db94045e5d8aae0a4f283d559656` |
| SHA-256 | `f42522e5eef67cdd01eaf2bb77e6f58ab1feb3b537884bb951e987ee546a438e` |
| SHA3-384 | `74adc50ba329b1dcb14dfc2d57107c99db6351ff179ea7f607f34c1079747300c1191ef2324ff90452270750d99867df` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17525479BBD56F802C8551A7BD891B1FC12655D6DFDD2C2071ADE3EAFFE32B80058021A` |
| SSDEEP | `24576:RbnqwmiaHOVYhvz0aPlg5uTT2xW6agq2L4hx4:V0xhL0h4GPHa4` |
| ICON-DHASH | `4c33d8d4d4d8324c` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_051_f42522e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f42522e5eef67cdd01eaf2bb77e6f58ab1feb3b537884bb951e987ee546a438e"
    family = "Formbook"
    file_name = "IYTDY6355.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:24"
  condition:
    hash.sha256(0, filesize) == "f42522e5eef67cdd01eaf2bb77e6f58ab1feb3b537884bb951e987ee546a438e"
}
```

### Sample 52: `3c7ac61372dd44f2`

| Field | Value |
|---|---|
| SHA-256 | `3c7ac61372dd44f281174df32948ede3ecc379c70464f52d0c0f008b73a0a564` |
| Family label | `Formbook` |
| File name | `Invoice.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:20:20` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `196bc50ddcccfd57a24ded02c6a08fae` |
| SHA-1 | `fedb4e7200cee70ce52db9b4bee77adda9216e8c` |
| SHA-256 | `3c7ac61372dd44f281174df32948ede3ecc379c70464f52d0c0f008b73a0a564` |
| SHA3-384 | `1c08ccfbc6cda0ab7f6338881d878797db337e4f806fb2d5e8297283e6620d26fbb289e6dbe61d5402cd5d0be7ac8196` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A405F154362CDF05E8B72BFA0A61E2B413B5AD896832D2465FD62CEF393A7405F40763` |
| SSDEEP | `12288:N9aX8Trhqwm5exYTyWoffcunStksw/55uLeEHZ/ACis48pN1ReG4:NY8Trhqwm5eOyWokksYIZ/Aa4831IG` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_052_3c7ac613
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c7ac61372dd44f281174df32948ede3ecc379c70464f52d0c0f008b73a0a564"
    family = "Formbook"
    file_name = "Invoice.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:20"
  condition:
    hash.sha256(0, filesize) == "3c7ac61372dd44f281174df32948ede3ecc379c70464f52d0c0f008b73a0a564"
}
```

### Sample 53: `290ba056ff6bbb76`

| Field | Value |
|---|---|
| SHA-256 | `290ba056ff6bbb7632c50b729cca188f8d59130731a72f48e25ff7ea21f91e08` |
| Family label | `Formbook` |
| File name | `TTSlip_WEC-LDV-2610-00112R_Advance.bat` |
| File type | `exe` |
| First seen | `2026-11-24 09:20:17` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b10d66c8ddda00af927a90302c9d71f` |
| SHA-1 | `f276403af30c4a697b723686108d287fdbf07f25` |
| SHA-256 | `290ba056ff6bbb7632c50b729cca188f8d59130731a72f48e25ff7ea21f91e08` |
| SHA3-384 | `5cd9d5c8f4ce7a9ee6d473e798739846caa628f1e6ac5017429681a5bcdace1ac7bd5f8061ded362d4948a38a931935a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14905F160263DCF05D8B75BF90AA1E1B013B69D8A6532D6068FD62ECF3E367501E14B63` |
| SSDEEP | `24576:qIwT+eqwm5ebO03EPzjrbJZlfGETpm5G:3wT5Sk/3ur+G` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_053_290ba056
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "290ba056ff6bbb7632c50b729cca188f8d59130731a72f48e25ff7ea21f91e08"
    family = "Formbook"
    file_name = "TTSlip_WEC-LDV-2610-00112R_Advance.bat"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:17"
  condition:
    hash.sha256(0, filesize) == "290ba056ff6bbb7632c50b729cca188f8d59130731a72f48e25ff7ea21f91e08"
}
```

### Sample 54: `1b126bd1d906810d`

| Field | Value |
|---|---|
| SHA-256 | `1b126bd1d906810d8bcb5ff61e3502420244e754c5398d78c654dce7d212adec` |
| Family label | `AgentTesla` |
| File name | `ORDERWAL076N14435SH0November2026PO3011921.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:20:14` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01c59299a0de205a62d1f673e7a7d2f9` |
| SHA-1 | `4c8a5ad9a212d1191805d9236028f905c3b56544` |
| SHA-256 | `1b126bd1d906810d8bcb5ff61e3502420244e754c5398d78c654dce7d212adec` |
| SHA3-384 | `d1ee8406fa73f7ca901470630601533836b7deb4e8004c6e040d3e8253ce6ea35d028576cd1993cfaa91c2d481cdf609` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T159159CDFF656C806C9610E7EE8A1F2F412B15DB5D412C20B1AD63EAF7F32B91158026E` |
| SSDEEP | `12288:PW/JeoN+T9PuLjnVI5nKMMvj38vzBwjJa/0ahTcjqwm:swpT9PcjVbMMjaBw5hjqwm` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_054_1b126bd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b126bd1d906810d8bcb5ff61e3502420244e754c5398d78c654dce7d212adec"
    family = "AgentTesla"
    file_name = "ORDERWAL076N14435SH0November2026PO3011921.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:14"
  condition:
    hash.sha256(0, filesize) == "1b126bd1d906810d8bcb5ff61e3502420244e754c5398d78c654dce7d212adec"
}
```

### Sample 55: `1446cc50fa039d88`

| Field | Value |
|---|---|
| SHA-256 | `1446cc50fa039d8859063af64c5ef37dd730c1dd42793f729773dc38f3810978` |
| Family label | `njrat` |
| File name | `13d80f4e9330faf865623999e45f703b.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:15:15` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13d80f4e9330faf865623999e45f703b` |
| SHA-1 | `1417db227888829a80c12c8e36c39a9061986a04` |
| SHA-256 | `1446cc50fa039d8859063af64c5ef37dd730c1dd42793f729773dc38f3810978` |
| SHA3-384 | `727fa5459d7a9b744e6d5144afe7c54ac7d2d7a361a60b47c08d3e84133d1b6d3b592875bed8db1afa07f022b9819dde` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1FCA2084E7B688219C3AD1A7849B2232447F1F68B8941DF4B0CDA50DE6F236D06646FFD` |
| SSDEEP | `384:lW6pUSl8WEXMpW8gjm6BIXfJhcBdrmHMaOWQ+dcs//34LAZSTn/O:k6pUq8WEXoW8gjm6gxiBdCMWQuHqFO` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_055_1446cc50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1446cc50fa039d8859063af64c5ef37dd730c1dd42793f729773dc38f3810978"
    family = "njrat"
    file_name = "13d80f4e9330faf865623999e45f703b.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:15:15"
  condition:
    hash.sha256(0, filesize) == "1446cc50fa039d8859063af64c5ef37dd730c1dd42793f729773dc38f3810978"
}
```

### Sample 56: `99dacf89b6c3df8e`

| Field | Value |
|---|---|
| SHA-256 | `99dacf89b6c3df8e101338ae02c3dd432bbed0b002d7dc1b9c230b5af198c8cf` |
| Family label | `njrat` |
| File name | `01d3fa8e5da2b4a46ac93546952e1895.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:15:10` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01d3fa8e5da2b4a46ac93546952e1895` |
| SHA-1 | `235210d1b45d639c0933eaf679cb402a238b51cd` |
| SHA-256 | `99dacf89b6c3df8e101338ae02c3dd432bbed0b002d7dc1b9c230b5af198c8cf` |
| SHA3-384 | `ce4a3d6c43198259b73d6da52a9188f28a59e88fa337ce0dc3c17c04da817e89e7c047320df85b3c5ce01056e22938c8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18BB43B4C9098774BE204B9300EA62D6213D5574468FDE81E8E73AAF32D670FCFD2B5A5` |
| SSDEEP | `6144:CvlHvr05mPYb1R1dZpOhzjTg9UkjeDz/UDpCNqsfHD3B:CvlPr05mPYBvdfOoaCpCNDLB` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_056_99dacf89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99dacf89b6c3df8e101338ae02c3dd432bbed0b002d7dc1b9c230b5af198c8cf"
    family = "njrat"
    file_name = "01d3fa8e5da2b4a46ac93546952e1895.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:15:10"
  condition:
    hash.sha256(0, filesize) == "99dacf89b6c3df8e101338ae02c3dd432bbed0b002d7dc1b9c230b5af198c8cf"
}
```

### Sample 57: `dd66fc9d2e919a11`

| Field | Value |
|---|---|
| SHA-256 | `dd66fc9d2e919a11ab0cca9dab0b41e755a26ae60ed6acc42fec266f7d662d64` |
| Family label | `Formbook` |
| File name | `goodness.js` |
| File type | `js` |
| First seen | `2026-11-24 09:15:08` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `563cddd2ea6cd7b6361609f8126839ef` |
| SHA-1 | `7b2c9c49dd5d16d511fa69d6d4f8161e6713d197` |
| SHA-256 | `dd66fc9d2e919a11ab0cca9dab0b41e755a26ae60ed6acc42fec266f7d662d64` |
| SHA3-384 | `4ce1fc2d10e254614b6758cfb6c9573458420ec426dca9463bb5de22b9b20a12e012af1e88b4c79cc503e96b2df479ad` |
| TLSH | `T16D75B7E337DF6947180673A7D44FAA898B89C1145F83EFC450DB1BACA40B58669D0BCB` |
| SSDEEP | `24576:+KQPErnnlmCvLju882oec60svdFu9oBmI4grGzNv3GEVuni:UErnnlm23fRzokdFuiYgrGzNvGEVui` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_057_dd66fc9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd66fc9d2e919a11ab0cca9dab0b41e755a26ae60ed6acc42fec266f7d662d64"
    family = "Formbook"
    file_name = "goodness.js"
    file_type = "js"
    first_seen = "2026-11-24 09:15:08"
  condition:
    hash.sha256(0, filesize) == "dd66fc9d2e919a11ab0cca9dab0b41e755a26ae60ed6acc42fec266f7d662d64"
}
```

### Sample 58: `32b5b5f419d97ff9`

| Field | Value |
|---|---|
| SHA-256 | `32b5b5f419d97ff94bfb7ddc647b331533ec53c1ff3646ec55adbca9d3ccd658` |
| Family label | `unknown` |
| File name | `ProjectExb.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:12:12` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dedaab2d3209e37df4efb09c1e7e70c` |
| SHA-1 | `f86235b791cb1eb7b0d8fe438c82e2d377cb57eb` |
| SHA-256 | `32b5b5f419d97ff94bfb7ddc647b331533ec53c1ff3646ec55adbca9d3ccd658` |
| SHA3-384 | `181c3d743d22c020707cd085aa4e595fabd4d02f034e20e4b4cedc3b91ee62b45e21ada5e98622755468c3bff45a2263` |
| IMPHASH | `20dd26497880c05caed9305b3c8b9109` |
| TLSH | `T172D73314FAD281B5F9056D35C84A0807DC1F7D198BD152DD3D70EBEEAA70E40EAB92A3` |
| SSDEEP | `1572864:3WUuQtlpZpLgxe8LYiK24de43wP9ti1RAy8GDeqB:3WRwtBgg8YiziAP63Adgf` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_32b5b5f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32b5b5f419d97ff94bfb7ddc647b331533ec53c1ff3646ec55adbca9d3ccd658"
    family = "unknown"
    file_name = "ProjectExb.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:12:12"
  condition:
    hash.sha256(0, filesize) == "32b5b5f419d97ff94bfb7ddc647b331533ec53c1ff3646ec55adbca9d3ccd658"
}
```

### Sample 59: `ad56c22a8c4e3c80`

| Field | Value |
|---|---|
| SHA-256 | `ad56c22a8c4e3c80636bfeb2179c9759a9642300abb27284ea2c87fa65f894bc` |
| Family label | `GuLoader` |
| File name | `DHL_Awb_Shipping#Tracking_commercial_INV_PL_BL_11_24_2026_PDF.js` |
| File type | `js` |
| First seen | `2026-11-24 09:11:47` |
| Reporter | `lowmal3` |
| Tags | `GuLoader, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83351e8f8a1b8fd71d479b72132e0a8d` |
| SHA-1 | `ffe440277fd1f86e25856c01c1707b7cfff880ee` |
| SHA-256 | `ad56c22a8c4e3c80636bfeb2179c9759a9642300abb27284ea2c87fa65f894bc` |
| SHA3-384 | `acf18c951d4897075e09fb91abb7d5c3aed55e28fdca937d8e2702df2093aaa9f6522f653353b0e2c6cb2d3f7f5b1f96` |
| TLSH | `T16C433C6FF9160BFB8F867FD87CE40921CE698215452205B0B199CF0DA1439DCD7BA1AB` |
| SSDEEP | `768:4IRrIRlZRJvxU3ATXiK1KQvX/kaFdL85Z6BkhMol/v0gU2YiRuOrkNOR1Ga8rm:4ltg38i0K1aFV85Z3eo90ngVm21b8rm` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_059_ad56c22a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad56c22a8c4e3c80636bfeb2179c9759a9642300abb27284ea2c87fa65f894bc"
    family = "GuLoader"
    file_name = "DHL_Awb_Shipping#Tracking_commercial_INV_PL_BL_11_24_2026_PDF.js"
    file_type = "js"
    first_seen = "2026-11-24 09:11:47"
  condition:
    hash.sha256(0, filesize) == "ad56c22a8c4e3c80636bfeb2179c9759a9642300abb27284ea2c87fa65f894bc"
}
```

### Sample 60: `6d04bed858ce107d`

| Field | Value |
|---|---|
| SHA-256 | `6d04bed858ce107dd3eaaf2648c577bfb9ccec87faa71f9dba2c4d4a8d77582b` |
| Family label | `RemcosRAT` |
| File name | `Afla_GmbH_Purchase_Order_2120_2110921_Amendment_Updated_2026-11-22_pdf.js` |
| File type | `js` |
| First seen | `2026-11-24 09:10:16` |
| Reporter | `ni_fi_70` |
| Tags | `js, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0d8165eda67a311b1b53805ba40b2ce` |
| SHA-1 | `9a51fc170683bc110f270ed20f636df8a77b4c76` |
| SHA-256 | `6d04bed858ce107dd3eaaf2648c577bfb9ccec87faa71f9dba2c4d4a8d77582b` |
| SHA3-384 | `48749229bb933081c995c12ef8a14042a3e3bcb4e3c089258b225c6fe0863d3364ce0ebf53f2a8d0ff3530cafb103f4d` |
| TLSH | `T1A135180F554D6C3D4410C40273EE5B23EAEE9F95869CD0A1FC5EDB26B3090ACA5F692E` |
| SSDEEP | `12288:zej8X3avAHtL644R+r9ncsIcaOZ3ZbcZ739CW7ZZtVLmZMxFC2SV3VTtGvdQjT8b:tqGJlJbY39fZZXL/yVTUvdQPQ` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_060_6d04bed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d04bed858ce107dd3eaaf2648c577bfb9ccec87faa71f9dba2c4d4a8d77582b"
    family = "RemcosRAT"
    file_name = "Afla_GmbH_Purchase_Order_2120_2110921_Amendment_Updated_2026-11-22_pdf.js"
    file_type = "js"
    first_seen = "2026-11-24 09:10:16"
  condition:
    hash.sha256(0, filesize) == "6d04bed858ce107dd3eaaf2648c577bfb9ccec87faa71f9dba2c4d4a8d77582b"
}
```

### Sample 61: `ffd5b0344123a984`

| Field | Value |
|---|---|
| SHA-256 | `ffd5b0344123a984d27c4aa624215fa6452c3849522803b2bc3a6ee0bcb23809` |
| Family label | `unknown` |
| File name | `tmpuo0zf7rz.php` |
| File type | `php` |
| First seen | `2026-11-24 09:07:57` |
| Reporter | `smica83` |
| Tags | `backdoor, php` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f016d58f4bee86cd43f3d21d1e445e81` |
| SHA-1 | `3498c7c540f41d1eec61b5f6cdc37820c05c4821` |
| SHA-256 | `ffd5b0344123a984d27c4aa624215fa6452c3849522803b2bc3a6ee0bcb23809` |
| SHA3-384 | `11fef115c3e66e29c57af21ce16f39b83ac1e0a62bf1f7bddcea31137d9535b10017fdcf1df50243e9a837cbb3cc23c8` |
| TLSH | `T1AC54E795BAD759B16273B4BD4BAF900976B96833500ACC117C8C80D46FC467887FAEF8` |
| SSDEEP | `3072:ZZNnZB1lCi3Jufys/Ga//Cp5KY8L2YNf6AuFn8s76/3VuoFGvzHiVQVIkK0H86tf:HNnZgOJu0a//C+ReIzcAz1Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_ffd5b034
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffd5b0344123a984d27c4aa624215fa6452c3849522803b2bc3a6ee0bcb23809"
    family = "unknown"
    file_name = "tmpuo0zf7rz.php"
    file_type = "php"
    first_seen = "2026-11-24 09:07:57"
  condition:
    hash.sha256(0, filesize) == "ffd5b0344123a984d27c4aa624215fa6452c3849522803b2bc3a6ee0bcb23809"
}
```

### Sample 62: `ea4ac6017a5a5c15`

| Field | Value |
|---|---|
| SHA-256 | `ea4ac6017a5a5c1520afbd48465d2127be51917fafec9f3850102db614cbace2` |
| Family label | `unknown` |
| File name | `LeronX.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:07:53` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a28ca174963f2d161a93e4ec2dbc8fa5` |
| SHA-1 | `6615c58a92337530d0b2c0f86c324dbfe74e81db` |
| SHA-256 | `ea4ac6017a5a5c1520afbd48465d2127be51917fafec9f3850102db614cbace2` |
| SHA3-384 | `b0982af8b74c5f8001e01038763901add15b15283572760ece4fcc80dc495f601ac45a67ff1e5e0dded294754d21edf7` |
| IMPHASH | `20dd26497880c05caed9305b3c8b9109` |
| TLSH | `T18ED7339D61E384FCDA942B309DA65500BC0B72E453E2119CAD30DF6DA77EF8295327E2` |
| SSDEEP | `1572864:UQ3drpNwz6qv1RFP/KVBsxN3i1RAy8GDeqdRFk:UQNrGv7FPCBszy3Adgrk` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_ea4ac601
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea4ac6017a5a5c1520afbd48465d2127be51917fafec9f3850102db614cbace2"
    family = "unknown"
    file_name = "LeronX.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:07:53"
  condition:
    hash.sha256(0, filesize) == "ea4ac6017a5a5c1520afbd48465d2127be51917fafec9f3850102db614cbace2"
}
```

### Sample 63: `581abe92dd2db265`

| Field | Value |
|---|---|
| SHA-256 | `581abe92dd2db2650e43ab26614595bd82f92be10619d5337afd5ae51d67115e` |
| Family label | `EasyShell` |
| File name | `easyshell-l64-581abe92dd2db265.bin` |
| File type | `elf` |
| First seen | `2026-11-24 09:06:23` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3e422c30c437dd760e2a215c5c33c2c` |
| SHA-1 | `9a063cf456b0e7e2bf6767e36ccdbc0fbcffb065` |
| SHA-256 | `581abe92dd2db2650e43ab26614595bd82f92be10619d5337afd5ae51d67115e` |
| SHA3-384 | `92e23dfd4143584ae557b4cf9b067054addb54483d2db56f826c71229b1c8cd38bfd5d592e7f860eb4e50ac0d9e25a78` |
| TLSH | `T16E267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxiBH8hIU6iKHh:OYjiiKgib9qRGcEulBcW+gh` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_063_581abe92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "581abe92dd2db2650e43ab26614595bd82f92be10619d5337afd5ae51d67115e"
    family = "EasyShell"
    file_name = "easyshell-l64-581abe92dd2db265.bin"
    file_type = "elf"
    first_seen = "2026-11-24 09:06:23"
  condition:
    hash.sha256(0, filesize) == "581abe92dd2db2650e43ab26614595bd82f92be10619d5337afd5ae51d67115e"
}
```

### Sample 64: `3d0209c42fe3f5ed`

| Field | Value |
|---|---|
| SHA-256 | `3d0209c42fe3f5ed693c1f2ed87b0d132894fda4514c36642e84db3278b531af` |
| Family label | `EasyShell` |
| File name | `easyshell-l32-3d0209c42fe3f5ed.bin` |
| File type | `elf` |
| First seen | `2026-11-24 09:06:14` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b41e8aa5ca524c8f8a291e9484b18104` |
| SHA-1 | `1c5add9262dc628560daf1e9a5431c1afb539c41` |
| SHA-256 | `3d0209c42fe3f5ed693c1f2ed87b0d132894fda4514c36642e84db3278b531af` |
| SHA3-384 | `d94a96c41075ada34e6ffe4cf3c21dc3b1938493df6c60d0416d33677c9764fe9241cd0965092aa0d3f75addf14de3ce` |
| TLSH | `T10E068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1WF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1Wdb` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_064_3d0209c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d0209c42fe3f5ed693c1f2ed87b0d132894fda4514c36642e84db3278b531af"
    family = "EasyShell"
    file_name = "easyshell-l32-3d0209c42fe3f5ed.bin"
    file_type = "elf"
    first_seen = "2026-11-24 09:06:14"
  condition:
    hash.sha256(0, filesize) == "3d0209c42fe3f5ed693c1f2ed87b0d132894fda4514c36642e84db3278b531af"
}
```

### Sample 65: `f1ecffc9d4663647`

| Field | Value |
|---|---|
| SHA-256 | `f1ecffc9d4663647f2c88877d3751a989a6bcdd69d20f3f479e52e196d53466e` |
| Family label | `EasyShell` |
| File name | `easyshell-l128-f1ecffc9d4663647.bin` |
| File type | `elf` |
| First seen | `2026-11-24 09:06:06` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89c8c82363c5d0ecfb926b128dd8f28f` |
| SHA-1 | `1b39d2e11605056dec4d59c1a297d503e65108a9` |
| SHA-256 | `f1ecffc9d4663647f2c88877d3751a989a6bcdd69d20f3f479e52e196d53466e` |
| SHA3-384 | `e6c64f9906bdb8c006fa92e4767b4eb9566c628b8f7509a35b63d06091b1f658c4be2490d275c11c9ee414cf5386de53` |
| TLSH | `T1D3067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1Cc:FUkCxwUGnaPdX8PtAS` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_065_f1ecffc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1ecffc9d4663647f2c88877d3751a989a6bcdd69d20f3f479e52e196d53466e"
    family = "EasyShell"
    file_name = "easyshell-l128-f1ecffc9d4663647.bin"
    file_type = "elf"
    first_seen = "2026-11-24 09:06:06"
  condition:
    hash.sha256(0, filesize) == "f1ecffc9d4663647f2c88877d3751a989a6bcdd69d20f3f479e52e196d53466e"
}
```

### Sample 66: `4c27444529d206bb`

| Field | Value |
|---|---|
| SHA-256 | `4c27444529d206bb6b373f531a04f59c0025d5d78823f70e6231fac112367801` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_arm64-4c27444529d206bb.bin` |
| File type | `macho` |
| First seen | `2026-11-24 09:05:57` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `982b4e86a6d0486d38c6050106cdb809` |
| SHA-1 | `9095f38abd95e5b8a91066af5964e66cbf5a822f` |
| SHA-256 | `4c27444529d206bb6b373f531a04f59c0025d5d78823f70e6231fac112367801` |
| SHA3-384 | `3927f2f7211a914dfc1d2f140b4533234ea78a5d0eb2638c3cbacd8c19b96881b1a00e8b496ae9f5a61db816cc7ac334` |
| TLSH | `T180F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1TgIsj5g5FIU6icBV8GQU5NZm+lzM:8SeI1gkkvTgIt5C+OGU5NZm+lzM` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_066_4c274445
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c27444529d206bb6b373f531a04f59c0025d5d78823f70e6231fac112367801"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-4c27444529d206bb.bin"
    file_type = "macho"
    first_seen = "2026-11-24 09:05:57"
  condition:
    hash.sha256(0, filesize) == "4c27444529d206bb6b373f531a04f59c0025d5d78823f70e6231fac112367801"
}
```

### Sample 67: `71f3c7a370b91849`

| Field | Value |
|---|---|
| SHA-256 | `71f3c7a370b91849836a7b7ed0a7f2be125e161ff58d9d22e339ffc9eba0fab8` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_amd64-71f3c7a370b91849.bin` |
| File type | `macho` |
| First seen | `2026-11-24 09:05:49` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce2d2642d4bbd0f8cb3ff373ea4eada3` |
| SHA-1 | `1f6cf5c84915b35e182f184775f99eaf7619ea09` |
| SHA-256 | `71f3c7a370b91849836a7b7ed0a7f2be125e161ff58d9d22e339ffc9eba0fab8` |
| SHA3-384 | `6ca6bb322f37fef1aa00abf43770fa422b26a32668db7375edd88b17fed4c442c58b2100180dce66a800141105e7a75c` |
| TLSH | `T1CE168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6tKhx+wgbZmBlz8X:kyLbLNomEr6tKja` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_067_71f3c7a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71f3c7a370b91849836a7b7ed0a7f2be125e161ff58d9d22e339ffc9eba0fab8"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-71f3c7a370b91849.bin"
    file_type = "macho"
    first_seen = "2026-11-24 09:05:49"
  condition:
    hash.sha256(0, filesize) == "71f3c7a370b91849836a7b7ed0a7f2be125e161ff58d9d22e339ffc9eba0fab8"
}
```

### Sample 68: `bcd193715c8354e6`

| Field | Value |
|---|---|
| SHA-256 | `bcd193715c8354e64e938c3c3f35200ce7c5299c94cf5d7eaa6090dc16ecbabe` |
| Family label | `EasyShell` |
| File name | `easyshell-a64-bcd193715c8354e6.bin` |
| File type | `elf` |
| First seen | `2026-11-24 09:05:37` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69e478857cf22664353cf7924928bddf` |
| SHA-1 | `f8c3ab8f556bd528518eca6bb6788641fda5530f` |
| SHA-256 | `bcd193715c8354e64e938c3c3f35200ce7c5299c94cf5d7eaa6090dc16ecbabe` |
| SHA3-384 | `31202152c911f05abd41b2e884e2dd87be74dbef8196f3470122208ec843feb4e205afdbad38e6efada61b528f0abee4` |
| TLSH | `T13006B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WgGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WgLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_068_bcd19371
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcd193715c8354e64e938c3c3f35200ce7c5299c94cf5d7eaa6090dc16ecbabe"
    family = "EasyShell"
    file_name = "easyshell-a64-bcd193715c8354e6.bin"
    file_type = "elf"
    first_seen = "2026-11-24 09:05:37"
  condition:
    hash.sha256(0, filesize) == "bcd193715c8354e64e938c3c3f35200ce7c5299c94cf5d7eaa6090dc16ecbabe"
}
```

### Sample 69: `e813a271b68c3afa`

| Field | Value |
|---|---|
| SHA-256 | `e813a271b68c3afa8654e2704282a079eb2de96a32dc1fd5d08d14daf764caec` |
| Family label | `EasyShell` |
| File name | `easyshell-a32-e813a271b68c3afa.bin` |
| File type | `elf` |
| First seen | `2026-11-24 09:05:29` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f8e4fa4b6fd3f46b7bec8bd5fa3a9aa` |
| SHA-1 | `4590022226125c133c336994e93681173b387708` |
| SHA-256 | `e813a271b68c3afa8654e2704282a079eb2de96a32dc1fd5d08d14daf764caec` |
| SHA3-384 | `2ae89b7ea7fb0a003142757f18c9c1125e8f7d0b3dd7659daa04a18ad0c9504d9600044afe79d39865274ba0e51975e9` |
| TLSH | `T17DF53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBv:FhvZpiEGUx+pVdqm2laB` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_069_e813a271
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e813a271b68c3afa8654e2704282a079eb2de96a32dc1fd5d08d14daf764caec"
    family = "EasyShell"
    file_name = "easyshell-a32-e813a271b68c3afa.bin"
    file_type = "elf"
    first_seen = "2026-11-24 09:05:29"
  condition:
    hash.sha256(0, filesize) == "e813a271b68c3afa8654e2704282a079eb2de96a32dc1fd5d08d14daf764caec"
}
```

### Sample 70: `57f957cda33dc5cb`

| Field | Value |
|---|---|
| SHA-256 | `57f957cda33dc5cb52307d173607633615c27c97a5f469f60fa6837cd140b7d4` |
| Family label | `DarkCoreRAT` |
| File name | `Cheque's.JS` |
| File type | `js` |
| First seen | `2026-11-24 09:04:35` |
| Reporter | `abuse_ch` |
| Tags | `DarkCoreRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5fe47f3c34c9a3cbe258471471febd6` |
| SHA-1 | `8334177aca5b2e67c4b19c3f85fdbf44d9d7b32b` |
| SHA-256 | `57f957cda33dc5cb52307d173607633615c27c97a5f469f60fa6837cd140b7d4` |
| SHA3-384 | `195ba7ffcbac2be14acb3a748df771e7b1105d70478d09982c529a12b3a3166779b4212d3a507ecd3e4a0d449f3104d5` |
| TLSH | `T19C46B38E6FB692323321AB8D93B5D831A50A556335AACB32305DDE08351DD4FA3DC6D3` |
| SSDEEP | `98304:6Ay/mJa2uY/qiTBRVmHU3beGqRQurcozWoxFnSg6lzm286MqG7LXMDP1WzK4EewE:6Ay/mJa2uYCiTBRVmHU3beGgQurnZx9v` |

#### Technical Assessment

- The sample is tracked as `DarkCoreRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkCoreRAT_070_57f957cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57f957cda33dc5cb52307d173607633615c27c97a5f469f60fa6837cd140b7d4"
    family = "DarkCoreRAT"
    file_name = "Cheque's.JS"
    file_type = "js"
    first_seen = "2026-11-24 09:04:35"
  condition:
    hash.sha256(0, filesize) == "57f957cda33dc5cb52307d173607633615c27c97a5f469f60fa6837cd140b7d4"
}
```

### Sample 71: `bc956c2793ca1cc8`

| Field | Value |
|---|---|
| SHA-256 | `bc956c2793ca1cc874d8c5eaaffefde74aba692b53c808b7ca9d61d635dd34e8` |
| Family label | `DarkCoreRAT` |
| File name | `Request for Quotation..JS` |
| File type | `js` |
| First seen | `2026-11-24 09:04:26` |
| Reporter | `abuse_ch` |
| Tags | `DarkCoreRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9c0cd297431cdc08af50b1d026d663a` |
| SHA-1 | `fa24ae67ef7a408094e2c92e5e518d5ecd3211bb` |
| SHA-256 | `bc956c2793ca1cc874d8c5eaaffefde74aba692b53c808b7ca9d61d635dd34e8` |
| SHA3-384 | `c585e266c2777ab5c28daa229f8b1e6db87281ace2359a6e771231213447706107d316ba8eac8c6498fe19027d0bd77b` |
| TLSH | `T19C46B38A2FB792323321AB9E83B5DD31980A512335A5CB32705DDE18751DD4EA3DCAD3` |
| SSDEEP | `98304:dQAA8qQSzewH+lWpjIZi9SvGQMF0m4cOU8Uoro3O5Og6JkKXNPx1zSGb3vTo+9XM:yBQSzewelWpjI0wvGrF0m4cOU8Uv3MOo` |

#### Technical Assessment

- The sample is tracked as `DarkCoreRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkCoreRAT_071_bc956c27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc956c2793ca1cc874d8c5eaaffefde74aba692b53c808b7ca9d61d635dd34e8"
    family = "DarkCoreRAT"
    file_name = "Request for Quotation..JS"
    file_type = "js"
    first_seen = "2026-11-24 09:04:26"
  condition:
    hash.sha256(0, filesize) == "bc956c2793ca1cc874d8c5eaaffefde74aba692b53c808b7ca9d61d635dd34e8"
}
```

### Sample 72: `8b1d7e1ca7dad1a6`

| Field | Value |
|---|---|
| SHA-256 | `8b1d7e1ca7dad1a68d23db0540508e70445cdec09165631c5035fd5aebcee7d9` |
| Family label | `PureLogsStealer` |
| File name | `78de2e25277ab8885ef8ebdf9ea477c4.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:04:23` |
| Reporter | `abuse_ch` |
| Tags | `exe, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78de2e25277ab8885ef8ebdf9ea477c4` |
| SHA-1 | `6d9853fe6cfc2c4ffda67f42a406d816b67d245f` |
| SHA-256 | `8b1d7e1ca7dad1a68d23db0540508e70445cdec09165631c5035fd5aebcee7d9` |
| SHA3-384 | `50aef08b0b77be8f16d284003bfe7db050d8733989e1743129a42bc5d28dab3482bb896e017d010841d7252b51a2a131` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A494197A76918F21C2461B73C2CB490087E6A6477697FB0B318513D71D833FEDA4A29B` |
| SSDEEP | `6144:xzAXW+kUS39Ac21VivaYg10oW3hz39ihk+3u+C03l:FXRUSScLaY9o0n4kr03l` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_072_8b1d7e1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b1d7e1ca7dad1a68d23db0540508e70445cdec09165631c5035fd5aebcee7d9"
    family = "PureLogsStealer"
    file_name = "78de2e25277ab8885ef8ebdf9ea477c4.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:04:23"
  condition:
    hash.sha256(0, filesize) == "8b1d7e1ca7dad1a68d23db0540508e70445cdec09165631c5035fd5aebcee7d9"
}
```

### Sample 73: `3807511b4d501263`

| Field | Value |
|---|---|
| SHA-256 | `3807511b4d501263d5e49f55f5dd5aad519b370c5962014588b8781452f6e0ca` |
| Family label | `Vidar` |
| File name | `31903a7995c12fe0255ff5eabc9e971c.exe` |
| File type | `exe` |
| First seen | `2026-11-24 09:04:20` |
| Reporter | `abuse_ch` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31903a7995c12fe0255ff5eabc9e971c` |
| SHA-1 | `7af2e7b48e3c71a5a5bf1ec3ec9b606bf457a3da` |
| SHA-256 | `3807511b4d501263d5e49f55f5dd5aad519b370c5962014588b8781452f6e0ca` |
| SHA3-384 | `9f3bbfde0c4e3eb62197438407e10f4edb8cf85814c2e15b3ebc8bbb226b10f769a5f6eb6842292c73766ce8d1411bb9` |
| IMPHASH | `2f97d5a03679c29a93ce4a399b582382` |
| TLSH | `T1E7B52911E505C479E0340A3C23DDFA9C8B2D8A1373B4F0E76B681C4BAEE558A767476B` |
| SSDEEP | `3072:ygrY9VIJR4kv7MDsGjTCWjZb8KSbBO134qCAbUDMViXC8u9RDVS:ypCEZbjSY134qC+4MOAg` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_073_3807511b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3807511b4d501263d5e49f55f5dd5aad519b370c5962014588b8781452f6e0ca"
    family = "Vidar"
    file_name = "31903a7995c12fe0255ff5eabc9e971c.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:04:20"
  condition:
    hash.sha256(0, filesize) == "3807511b4d501263d5e49f55f5dd5aad519b370c5962014588b8781452f6e0ca"
}
```

### Sample 74: `4d77a20b9ee1596b`

| Field | Value |
|---|---|
| SHA-256 | `4d77a20b9ee1596be3e61cae6d552a1fe8fce5864437b69e697d7630e203de01` |
| Family label | `unknown` |
| File name | `4d77a20b9ee1596be3e61cae6d552a1fe8fce5864437b69e697d7630e203de01` |
| File type | `exe` |
| First seen | `2026-11-24 09:01:01` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c784c56d6cfa5bc6975ad116c4e740e2` |
| SHA-1 | `d6bfe482ef365861405db059b8367c2edfff945f` |
| SHA-256 | `4d77a20b9ee1596be3e61cae6d552a1fe8fce5864437b69e697d7630e203de01` |
| SHA3-384 | `ab57d7cc3156e423bf9c583d8d540a81aec7261ed2d844ee6bb34365d99f5aa0b7396a22ae74ca005b52a854c14bc200` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T1DFA78B03E89534A8C59DD230CAB79253BB717C591B3227E71B50B7382E72FD0A6BA714` |
| SSDEEP | `98304:48ktlX1g37G9dE0CkNS5px0nppvSmgEqqrFCcJDvSSIZ6ooG48TSNJjCIk/k+laK:41IGhC+tppaWnIOOQIONJ2G+lbR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_4d77a20b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d77a20b9ee1596be3e61cae6d552a1fe8fce5864437b69e697d7630e203de01"
    family = "unknown"
    file_name = "4d77a20b9ee1596be3e61cae6d552a1fe8fce5864437b69e697d7630e203de01"
    file_type = "exe"
    first_seen = "2026-11-24 09:01:01"
  condition:
    hash.sha256(0, filesize) == "4d77a20b9ee1596be3e61cae6d552a1fe8fce5864437b69e697d7630e203de01"
}
```

### Sample 75: `f31740641da982b9`

| Field | Value |
|---|---|
| SHA-256 | `f31740641da982b932e6547c4787c9816e39c94b2a4571ecd9521f6de12f8b3e` |
| Family label | `njrat` |
| File name | `45eac95fdd4f9c019caec4332c802807.exe` |
| File type | `exe` |
| First seen | `2026-11-24 08:50:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45eac95fdd4f9c019caec4332c802807` |
| SHA-1 | `eba0a3a23d7e17e55e35fffcd05a33516e8c8b6f` |
| SHA-256 | `f31740641da982b932e6547c4787c9816e39c94b2a4571ecd9521f6de12f8b3e` |
| SHA3-384 | `ba5855aaed871517877184a56926e7d62897a9d8466723b299863f5c41b32d82d9510f2528969fae978f7b8426d59f7c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1ECA2F98E77A88518E3AD1A7849F2A31487B1F68B8541DF4F0CDA10DE6F236D01646BFD` |
| SSDEEP | `384:uW65USlhWPAXMFC82jpp746hbeImHaaOWQ+dcs//34LAZSTvuJ:f65UqhWPAXYC82jptJeb2WQuHqsJ` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_075_f3174064
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f31740641da982b932e6547c4787c9816e39c94b2a4571ecd9521f6de12f8b3e"
    family = "njrat"
    file_name = "45eac95fdd4f9c019caec4332c802807.exe"
    file_type = "exe"
    first_seen = "2026-11-24 08:50:07"
  condition:
    hash.sha256(0, filesize) == "f31740641da982b932e6547c4787c9816e39c94b2a4571ecd9521f6de12f8b3e"
}
```

### Sample 76: `ba3c37dab3a316c0`

| Field | Value |
|---|---|
| SHA-256 | `ba3c37dab3a316c0f036fe72d463568cdec8917067e4aa846cbb804a2d633e09` |
| Family label | `unknown` |
| File name | `543e35f4a58b7c8c12b0b5f4e40f4fdf.exe` |
| File type | `exe` |
| First seen | `2026-11-24 08:40:32` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `543e35f4a58b7c8c12b0b5f4e40f4fdf` |
| SHA-1 | `8bdbde650977801c7b8cf965da2b6e0fa98722bb` |
| SHA-256 | `ba3c37dab3a316c0f036fe72d463568cdec8917067e4aa846cbb804a2d633e09` |
| SHA3-384 | `f44a3b6b8732a4418740922a09367d030939ab747799521b313e0a1d2ed594c00793e9bde77de13fea47fe5534262474` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A513E40577E88918F2FE4F71ACB2521409B6F85B6D35D74E0DCA048E1DB2BD0D9A2B72` |
| SSDEEP | `768:d/mzKV6Q7zSEZpugeDL1p4xAok24TDK9Rzi3:d/p9JVUhp4xpk2UK9RzI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_ba3c37da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba3c37dab3a316c0f036fe72d463568cdec8917067e4aa846cbb804a2d633e09"
    family = "unknown"
    file_name = "543e35f4a58b7c8c12b0b5f4e40f4fdf.exe"
    file_type = "exe"
    first_seen = "2026-11-24 08:40:32"
  condition:
    hash.sha256(0, filesize) == "ba3c37dab3a316c0f036fe72d463568cdec8917067e4aa846cbb804a2d633e09"
}
```

### Sample 77: `60c49f80313bf0d8`

| Field | Value |
|---|---|
| SHA-256 | `60c49f80313bf0d82f448270e3e0c2a205ea221ed291dc98b73e740896a1b949` |
| Family label | `PureLogsStealer` |
| File name | `FINAL INV - TELEX FEE.pdf` |
| File type | `exe` |
| First seen | `2026-11-24 08:40:20` |
| Reporter | `abuse_ch` |
| Tags | `exe, pdf, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `681ba8e6a3999e86d1221ddee948a0f0` |
| SHA-1 | `9333aa9b9f8f86af5f1fc08be500d07530795fa7` |
| SHA-256 | `60c49f80313bf0d82f448270e3e0c2a205ea221ed291dc98b73e740896a1b949` |
| SHA3-384 | `f5506c5a4a11e6f659589ab05ed9dc8e8c2666bd30a5ceb6b7622ddc7e99a944062a3d50dafc2640e31a35c61fd77cb7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C6551264322CCB01E8B79FF90A61E1F413B95D866532C20A6FE62DDF39367905E147A3` |
| SSDEEP | `24576:9ckT4eqwm5e23/BJMLNl/Jy8PVxFHv9dwoPpCcqOV7Q5BXo9NR9m5Veqal:KkT/SB/PMLNlBxPnFP91Pv7Q5aR9mydl` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_077_60c49f80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60c49f80313bf0d82f448270e3e0c2a205ea221ed291dc98b73e740896a1b949"
    family = "PureLogsStealer"
    file_name = "FINAL INV - TELEX FEE.pdf"
    file_type = "exe"
    first_seen = "2026-11-24 08:40:20"
  condition:
    hash.sha256(0, filesize) == "60c49f80313bf0d82f448270e3e0c2a205ea221ed291dc98b73e740896a1b949"
}
```

### Sample 78: `f876ff86a490ee6e`

| Field | Value |
|---|---|
| SHA-256 | `f876ff86a490ee6e6ed495262af9ce7ddbadb7d2f229dcedb866ce9e4c0b043c` |
| Family label | `PureLogsStealer` |
| File name | `Request for Quotation (RFQ) 󈦝 (2).js` |
| File type | `js` |
| First seen | `2026-11-24 08:40:14` |
| Reporter | `abuse_ch` |
| Tags | `js, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44a7b7c70b4c92a3fefe464104a8d8b3` |
| SHA-1 | `16e28cd77a8eec587721446438de349eee5473e3` |
| SHA-256 | `f876ff86a490ee6e6ed495262af9ce7ddbadb7d2f229dcedb866ce9e4c0b043c` |
| SHA3-384 | `963a93cb8f2391f11643bfef00e50f5c8599b53bb11eb84e6b7bdd325aa0f48cee4f24563d18e85d50d3b7de9c9f5b47` |
| TLSH | `T115754B0F454D6C3D4410C54273EE4B23EAEE9F95869CD0A5FC5EDB26B3090ACA5F292E` |
| SSDEEP | `49152:cqcY3qCrKHTFLxl4kIajff4GXkk9ktE/Qo30cJgOxBPUZ:ZmzFLxl4ijff4GXkk9ktE/QC02dmZ` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_078_f876ff86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f876ff86a490ee6e6ed495262af9ce7ddbadb7d2f229dcedb866ce9e4c0b043c"
    family = "PureLogsStealer"
    file_name = "Request for Quotation (RFQ) 󈦝 (2).js"
    file_type = "js"
    first_seen = "2026-11-24 08:40:14"
  condition:
    hash.sha256(0, filesize) == "f876ff86a490ee6e6ed495262af9ce7ddbadb7d2f229dcedb866ce9e4c0b043c"
}
```

### Sample 79: `89d213c5684a99c7`

| Field | Value |
|---|---|
| SHA-256 | `89d213c5684a99c768faeb461c848bfffa3b61c7b8b225f22198ba7cd6d19e4c` |
| Family label | `unknown` |
| File name | `a04b62ea07658d93417ddefa137c78f9.exe` |
| File type | `exe` |
| First seen | `2026-11-24 08:40:08` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a04b62ea07658d93417ddefa137c78f9` |
| SHA-1 | `6c0c063141e78f07ccb6ebec0ea9171210b85f86` |
| SHA-256 | `89d213c5684a99c768faeb461c848bfffa3b61c7b8b225f22198ba7cd6d19e4c` |
| SHA3-384 | `4883a1b20c876cf7c7b8f5cb808141fbc8aa46ed531b3f7a03cb0f856677f0c093eaaaf6e052cbe93fbe35c35e30e2d2` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BC66B4DD726072EFC85BD462DEA82DA8FA5174BB831F4203902715ADEA4D897DF140F2` |
| SSDEEP | `98304:SJEqYiO/ad2MJwo+k46G6UiGmxYvasD3sAnEAPmoEhzIlEntvKndg:SJq/4Kom6SLm2vaacAnpPalIlEtS` |
| ICON-DHASH | `09981b69b4da3d29` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_89d213c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89d213c5684a99c768faeb461c848bfffa3b61c7b8b225f22198ba7cd6d19e4c"
    family = "unknown"
    file_name = "a04b62ea07658d93417ddefa137c78f9.exe"
    file_type = "exe"
    first_seen = "2026-11-24 08:40:08"
  condition:
    hash.sha256(0, filesize) == "89d213c5684a99c768faeb461c848bfffa3b61c7b8b225f22198ba7cd6d19e4c"
}
```

### Sample 80: `40ca657db1c767a0`

| Field | Value |
|---|---|
| SHA-256 | `40ca657db1c767a075742575ed53fdb35b836b5cb91a1b98be48b98a5e77f00a` |
| Family label | `EasyShell` |
| File name | `easyshell-a32-40ca657db1c767a0.bin` |
| File type | `elf` |
| First seen | `2026-11-24 08:35:14` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f18b63a023c3ec7645675957cf8abf29` |
| SHA-1 | `68071f71fbaaae34be900ba49b7ea2543ae2664b` |
| SHA-256 | `40ca657db1c767a075742575ed53fdb35b836b5cb91a1b98be48b98a5e77f00a` |
| SHA3-384 | `4c96717d2fb03aff23a4a22c485b3bea458e3c7a357153331f49c463ccbd015860ba2ed0d990b45e43c7135d4dcd3fab` |
| TLSH | `T140F53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBB:FhvZpiEGUx+pVdqk2laB` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_080_40ca657d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ca657db1c767a075742575ed53fdb35b836b5cb91a1b98be48b98a5e77f00a"
    family = "EasyShell"
    file_name = "easyshell-a32-40ca657db1c767a0.bin"
    file_type = "elf"
    first_seen = "2026-11-24 08:35:14"
  condition:
    hash.sha256(0, filesize) == "40ca657db1c767a075742575ed53fdb35b836b5cb91a1b98be48b98a5e77f00a"
}
```

### Sample 81: `9f233ad78da2079a`

| Field | Value |
|---|---|
| SHA-256 | `9f233ad78da2079a0de31cd5a08e37d861a10e145d17b6ad1572226e25af2b06` |
| Family label | `RemcosRAT` |
| File name | `greattimefor.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:32:10` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebfc649e4b098b717bf336995655fcbe` |
| SHA-1 | `c3e359ec4dc572048b5574e2c7efb081b5ceebbe` |
| SHA-256 | `9f233ad78da2079a0de31cd5a08e37d861a10e145d17b6ad1572226e25af2b06` |
| SHA3-384 | `6491e5f9f55b961ea17dd20e53699eb0eff52bb88a9d3b312c984677a5a46fbd2e2026cb0bd5e86836a32a51095d4c0a` |
| TLSH | `T17D820B584997748463376B3FF72AF894F6BA0A7B0154090BB4BC74909FB2D0AD9D0C7A` |
| SSDEEP | `384:5dHu4DkseILOQplNO0ELVEQWqw3ztx92X9sof5/myTJkKlWZDuccGT/XeB9K:5dVDkseILpplNO0ELVEQWqw3ztx92X9u` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_081_9f233ad7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f233ad78da2079a0de31cd5a08e37d861a10e145d17b6ad1572226e25af2b06"
    family = "RemcosRAT"
    file_name = "greattimefor.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:32:10"
  condition:
    hash.sha256(0, filesize) == "9f233ad78da2079a0de31cd5a08e37d861a10e145d17b6ad1572226e25af2b06"
}
```

### Sample 82: `5aea893c52a41e29`

| Field | Value |
|---|---|
| SHA-256 | `5aea893c52a41e29dbf4e9549170b1d35ab969c99a93f493d8da3506de9c0733` |
| Family label | `RemcosRAT` |
| File name | `CNNupdate.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:32:08` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4566264eb1ba31b746d6b56a508a11b9` |
| SHA-1 | `bbf054ae2c01046a21f5f65a2cc8e5f2747149d4` |
| SHA-256 | `5aea893c52a41e29dbf4e9549170b1d35ab969c99a93f493d8da3506de9c0733` |
| SHA3-384 | `d3ce296d61cd2b988247708208e7531bf84b9a683cb851dc8838bf56e4801fa91cbc412b67aed7a3235889d808fd3e9e` |
| TLSH | `T14762EF3C8450FF64869251FC94683283E4AAD57F2D147E4F75EE802BFB26A594E38487` |
| SSDEEP | `48:3kFSBtVNSwFSBlM2VNSrErhUtp90MsRbuuuru36jFSB2ZFSB611IEVNSd8FSBDPG:0onqwoFq4rmURr6joyo8qKoJ+` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_082_5aea893c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5aea893c52a41e29dbf4e9549170b1d35ab969c99a93f493d8da3506de9c0733"
    family = "RemcosRAT"
    file_name = "CNNupdate.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:32:08"
  condition:
    hash.sha256(0, filesize) == "5aea893c52a41e29dbf4e9549170b1d35ab969c99a93f493d8da3506de9c0733"
}
```

### Sample 83: `8924805e933bee83`

| Field | Value |
|---|---|
| SHA-256 | `8924805e933bee83f5097275f742685443f09cf23ee2f6fb4474d1c4610ad1d7` |
| Family label | `Formbook` |
| File name | `cloudsoon.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:32:06` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7a16ed17f73432eb45b3340a794d3ed` |
| SHA-1 | `44eb121425048f1d2fcb96c8db853ebac2d2536a` |
| SHA-256 | `8924805e933bee83f5097275f742685443f09cf23ee2f6fb4474d1c4610ad1d7` |
| SHA3-384 | `149c352e2e14298072a57b8e2e22e56a20261c3f716f8e8e9c767a827622388be7e6b393293cd0e0c1867602bed135b3` |
| TLSH | `T19F62067D8EF9ACD0C3939AD4C02A5F074409AA376240273F78CC21A7AB0875958B66CB` |
| SSDEEP | `48:3x5b1uDPMwy5b1uWSPMwmE9uuuEuuq6kN0ZN0cuur5b1uQ5b1u8pPMwx5b1unG:B54DPMF54WSPME9ZIk54Q548pPME54G` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_083_8924805e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8924805e933bee83f5097275f742685443f09cf23ee2f6fb4474d1c4610ad1d7"
    family = "Formbook"
    file_name = "cloudsoon.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:32:06"
  condition:
    hash.sha256(0, filesize) == "8924805e933bee83f5097275f742685443f09cf23ee2f6fb4474d1c4610ad1d7"
}
```

### Sample 84: `211e6199925a0cc1`

| Field | Value |
|---|---|
| SHA-256 | `211e6199925a0cc1d3457dcbb5fcf0ac330366990777d3b7d0ca210b86973d5c` |
| Family label | `RemcosRAT` |
| File name | `goodkings.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:31:07` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db265a7234f65155b40b6a19088f29b3` |
| SHA-1 | `3ebd520b3b760e616c46b518cbfa4d1983ef59c6` |
| SHA-256 | `211e6199925a0cc1d3457dcbb5fcf0ac330366990777d3b7d0ca210b86973d5c` |
| SHA3-384 | `f6e6a68973f0d168d41ccd3cba974c01fe5c92bf68554b302d1c98acdbdb9fca9a56bc62c984468e2790a056a3003473` |
| TLSH | `T14782FB584997748463376B3FF72AF894F6BA0A7B0154090BB4BC74909FB2D0AD9D0C7A` |
| SSDEEP | `384:5dHu4DkseILOQplNO0ELVEQWqw3ztx92X9sof5/myTxkKlWZDuccGT/XeB9K:5dVDkseILpplNO0ELVEQWqw3ztx92X9y` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_084_211e6199
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "211e6199925a0cc1d3457dcbb5fcf0ac330366990777d3b7d0ca210b86973d5c"
    family = "RemcosRAT"
    file_name = "goodkings.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:31:07"
  condition:
    hash.sha256(0, filesize) == "211e6199925a0cc1d3457dcbb5fcf0ac330366990777d3b7d0ca210b86973d5c"
}
```

### Sample 85: `d9b7d897e7deab7c`

| Field | Value |
|---|---|
| SHA-256 | `d9b7d897e7deab7cd9a2ba49908888181f79451372622371bbcb6b127411c089` |
| Family label | `RemcosRAT` |
| File name | `greathrome.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:31:04` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce81fb4fedba8d5ba5f202d537a530a8` |
| SHA-1 | `3bcbf5822b0994bf2c17b72eb4cec72f96189f61` |
| SHA-256 | `d9b7d897e7deab7cd9a2ba49908888181f79451372622371bbcb6b127411c089` |
| SHA3-384 | `7a34efee2f0d8b401fcc4cd212c8631a02ed12df7ac7d152a34777291454cafac6b404e62e6656bd0d78378394e904b8` |
| TLSH | `T1E582FB584997748463376B3FF72AE894F6BA0A7B0154090BB4BC74909FB2D0AD9D0C7A` |
| SSDEEP | `384:5dHu4DkseILOQplNO0ELVEQWqw3ztx92X9sof5/myTgkKlWZDuccGT/XeB9K:5dVDkseILpplNO0ELVEQWqw3ztx92X9/` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_085_d9b7d897
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9b7d897e7deab7cd9a2ba49908888181f79451372622371bbcb6b127411c089"
    family = "RemcosRAT"
    file_name = "greathrome.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:31:04"
  condition:
    hash.sha256(0, filesize) == "d9b7d897e7deab7cd9a2ba49908888181f79451372622371bbcb6b127411c089"
}
```

### Sample 86: `99abd64e24245367`

| Field | Value |
|---|---|
| SHA-256 | `99abd64e2424536741538724eaca9088273c42755dc8840008c52a86cbf6bdf1` |
| Family label | `Formbook` |
| File name | `cleanthepciture.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:30:08` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca97697002267fa08b66713ec47fb3b4` |
| SHA-1 | `55699c9a4bb02c6357dcf183f2ff93d142cae127` |
| SHA-256 | `99abd64e2424536741538724eaca9088273c42755dc8840008c52a86cbf6bdf1` |
| SHA3-384 | `526491c209cfaac9817993113327db845fcc4d33875e23d20e74e74e2005b903896c130aa27a6c0d91534328b642c5e0` |
| TLSH | `T18382FB584997748463376B3FF72AF894F6BA0A7B0154090BB4BC74909FB2D0AD9D0C7A` |
| SSDEEP | `384:5dHu4DkseILOQplNO0ELVEQWqw3ztx92X9sof5/myTFkKlWZDuccGT/XeB9K:5dVDkseILpplNO0ELVEQWqw3ztx92X9q` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_086_99abd64e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99abd64e2424536741538724eaca9088273c42755dc8840008c52a86cbf6bdf1"
    family = "Formbook"
    file_name = "cleanthepciture.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:30:08"
  condition:
    hash.sha256(0, filesize) == "99abd64e2424536741538724eaca9088273c42755dc8840008c52a86cbf6bdf1"
}
```

### Sample 87: `192d4159f5d72a8c`

| Field | Value |
|---|---|
| SHA-256 | `192d4159f5d72a8cf0c3ceb415f14775c18af1282af084df2472b60032752430` |
| Family label | `RemcosRAT` |
| File name | `updated.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:29:08` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cde89283ecfb86c67847e1970092793a` |
| SHA-1 | `99c49e9c2798bb8b96b0ef15742952c5bee2c558` |
| SHA-256 | `192d4159f5d72a8cf0c3ceb415f14775c18af1282af084df2472b60032752430` |
| SHA3-384 | `7f4045dfb557f496e14825b315f988a114138fdeb8d8788fdf658cb7674fb35fad73164164feace2a4135a2bc48ca532` |
| TLSH | `T1CC82FB584997748463376B3FF72AE894F6BA0A7B0154090BB4BC74909FB2D0AD9D0C7A` |
| SSDEEP | `384:5dHu4DkseILOQplNO0ELVEQWqw3ztx92X9sof5/myTpkKlWZDuccGT/XeB9K:5dVDkseILpplNO0ELVEQWqw3ztx92X92` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_087_192d4159
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "192d4159f5d72a8cf0c3ceb415f14775c18af1282af084df2472b60032752430"
    family = "RemcosRAT"
    file_name = "updated.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:29:08"
  condition:
    hash.sha256(0, filesize) == "192d4159f5d72a8cf0c3ceb415f14775c18af1282af084df2472b60032752430"
}
```

### Sample 88: `87d941841e4de71f`

| Field | Value |
|---|---|
| SHA-256 | `87d941841e4de71f079ffe798bd6e5e9bfb2ab1574e0557001a6cf6d905e7e29` |
| Family label | `RemcosRAT` |
| File name | `workonfixed.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:29:05` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1e2465ce7083f24f998a79d2da96dbf` |
| SHA-1 | `82509c02d5cd281cac5f93e8154217de85a46d7e` |
| SHA-256 | `87d941841e4de71f079ffe798bd6e5e9bfb2ab1574e0557001a6cf6d905e7e29` |
| SHA3-384 | `bd5b7151ea5068772e9488f0f8812328fec035fe2124ea3ed9d6cf2586a60a20fc5bf30f800c7581769e6f56bbc58478` |
| TLSH | `T1EC820C584997748463376B3FF72AF894F6BA0A7B0154090BB4BC74909FB2D0AD9D0C7A` |
| SSDEEP | `384:5dHu4DkseILOQplNO0ELVEQWqw3ztx92X9sof5/myTakKlWZDuccGT/XeB9K:5dVDkseILpplNO0ELVEQWqw3ztx92X9V` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_088_87d94184
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87d941841e4de71f079ffe798bd6e5e9bfb2ab1574e0557001a6cf6d905e7e29"
    family = "RemcosRAT"
    file_name = "workonfixed.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:29:05"
  condition:
    hash.sha256(0, filesize) == "87d941841e4de71f079ffe798bd6e5e9bfb2ab1574e0557001a6cf6d905e7e29"
}
```

### Sample 89: `40ffbc67720452f8`

| Field | Value |
|---|---|
| SHA-256 | `40ffbc67720452f883bfdcadd434bd2237c5a34272cfe350d049e8a34be8fdf0` |
| Family label | `RemcosRAT` |
| File name | `soonwillbe.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:28:06` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3eb76ac1abb9721fa641ce7f6bf3015` |
| SHA-1 | `30811dcb79696dcbc876eaffc366025e23ca49c0` |
| SHA-256 | `40ffbc67720452f883bfdcadd434bd2237c5a34272cfe350d049e8a34be8fdf0` |
| SHA3-384 | `888d0385442e2f408bf3a9cbf5b5ba97da105c024d08e5a1130fa4d1fd7e3850c35627eef6e3815ca48798ca94cffc4e` |
| TLSH | `T15282FB584997748463376B3FF72AF894F6BA0A7B0154090BB4BC74909FB2D0AD9D0C7A` |
| SSDEEP | `384:5dHu4DkseILOQplNO0ELVEQWqw3ztx92X9sof5/myTwkKlWZDuccGT/XeB9K:5dVDkseILpplNO0ELVEQWqw3ztx92X9v` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_089_40ffbc67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ffbc67720452f883bfdcadd434bd2237c5a34272cfe350d049e8a34be8fdf0"
    family = "RemcosRAT"
    file_name = "soonwillbe.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:28:06"
  condition:
    hash.sha256(0, filesize) == "40ffbc67720452f883bfdcadd434bd2237c5a34272cfe350d049e8a34be8fdf0"
}
```

### Sample 90: `7c488a802c93094c`

| Field | Value |
|---|---|
| SHA-256 | `7c488a802c93094cf156b83ab492a08d50e8ff8fc067056b716d21319622dfa2` |
| Family label | `RemcosRAT` |
| File name | `CNNupdate.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:27:05` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b57828d5084d8dd7a69db11f981db28` |
| SHA-1 | `425bab3cd9bf0038d916b1af3fa96f0c8076b1aa` |
| SHA-256 | `7c488a802c93094cf156b83ab492a08d50e8ff8fc067056b716d21319622dfa2` |
| SHA3-384 | `da8e7a5ccc29417b10fffc2551b9807aee0c04aea7be4dbd6ccebcefe0f80ac1ad35aacfa4ffcfd621e9f7073e5d90be` |
| TLSH | `T18082FC584997748463376B3FF72AF894F6BA0A7B0154090BB4BC74909FB2D0AD9D0C7A` |
| SSDEEP | `384:5dHu4DkseILOQplNO0ELVEQWqw3ztx92X9sof5/myTWkKlWZDuccGT/XeB9K:5dVDkseILpplNO0ELVEQWqw3ztx92X9Z` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_090_7c488a80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c488a802c93094cf156b83ab492a08d50e8ff8fc067056b716d21319622dfa2"
    family = "RemcosRAT"
    file_name = "CNNupdate.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:27:05"
  condition:
    hash.sha256(0, filesize) == "7c488a802c93094cf156b83ab492a08d50e8ff8fc067056b716d21319622dfa2"
}
```

### Sample 91: `c594fa82bef6210f`

| Field | Value |
|---|---|
| SHA-256 | `c594fa82bef6210f081cbbfd3ac0b4f3e7f8f229ee15f596d84a357cec632d62` |
| Family label | `DarkCloud` |
| File name | `Urgent Order.exe` |
| File type | `exe` |
| First seen | `2026-11-24 08:25:34` |
| Reporter | `threatcat_ch` |
| Tags | `DarkCloud, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46e9093bcfd9e1c1cd2a852e5900ea08` |
| SHA-1 | `289d0028bb9e9b4ce307ed04e395f4659b54e01c` |
| SHA-256 | `c594fa82bef6210f081cbbfd3ac0b4f3e7f8f229ee15f596d84a357cec632d62` |
| SHA3-384 | `7847d674a2d40d4cc33bb9be874238987dbd1b4ba3b1099861449f6f596a44acb1800f576d37dec14edfd8a16b7d0385` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18F250111266DEF06D87B5FF90961E1F413B5AD8A2432C2468EE66EEF3D367401E407A3` |
| SSDEEP | `24576:8AYTQjqwmH9ouIFMvGgdtZ6RoYb6//9XCcdIe:LYT0soxOt4Z+1CcdI` |

#### Technical Assessment

- The sample is tracked as `DarkCloud` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkCloud_091_c594fa82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c594fa82bef6210f081cbbfd3ac0b4f3e7f8f229ee15f596d84a357cec632d62"
    family = "DarkCloud"
    file_name = "Urgent Order.exe"
    file_type = "exe"
    first_seen = "2026-11-24 08:25:34"
  condition:
    hash.sha256(0, filesize) == "c594fa82bef6210f081cbbfd3ac0b4f3e7f8f229ee15f596d84a357cec632d62"
}
```

### Sample 92: `f82f3dda93876f1c`

| Field | Value |
|---|---|
| SHA-256 | `f82f3dda93876f1cb3d9380efd32d045bb5b6593da5b7ed869f8798e489c76c3` |
| Family label | `SalatStealer` |
| File name | `f82f3dda93876f1c.bin` |
| File type | `bat` |
| First seen | `2026-11-24 08:25:01` |
| Reporter | `Tuxxin` |
| Tags | `bat, powershell, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cf5170474f8db2aec5e7fc96d849cd3` |
| SHA-1 | `f1b0deb11e001b46c572ac466ad1cfe5085ad2f7` |
| SHA-256 | `f82f3dda93876f1cb3d9380efd32d045bb5b6593da5b7ed869f8798e489c76c3` |
| SHA3-384 | `27fef6b1543b4fafb6448cc254163841fc3a841c38c2a81c962e638786f56427c02dd8a88af90c645bfef80d35a85342` |
| TLSH | `T1DED69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzh:u` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_092_f82f3dda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f82f3dda93876f1cb3d9380efd32d045bb5b6593da5b7ed869f8798e489c76c3"
    family = "SalatStealer"
    file_name = "f82f3dda93876f1c.bin"
    file_type = "bat"
    first_seen = "2026-11-24 08:25:01"
  condition:
    hash.sha256(0, filesize) == "f82f3dda93876f1cb3d9380efd32d045bb5b6593da5b7ed869f8798e489c76c3"
}
```

### Sample 93: `a8b44ff9d650dfa4`

| Field | Value |
|---|---|
| SHA-256 | `a8b44ff9d650dfa4157024c8fa99a9dbc51c57cb25c56798aefa2fe6733c49eb` |
| Family label | `RemcosRAT` |
| File name | `studyforbest.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:19:06` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e1a60175b0c8d461dda5a04e63467be` |
| SHA-1 | `2dcf49f210ae5ad81945777b7b16da9d2cfe8eb6` |
| SHA-256 | `a8b44ff9d650dfa4157024c8fa99a9dbc51c57cb25c56798aefa2fe6733c49eb` |
| SHA3-384 | `e9e4d239c787467557e8b0122c82c4f08c2b324c75c779e848a6dd78c6155b3ab258660a3308becb041262b3d2a06d2b` |
| TLSH | `T13E72652DBE94FDA683D3D35CB5A0D50AA698077778011539B8EC08F6B31435E5D7C18B` |
| SSDEEP | `48:3XAeaoJRKoAedoJRKkWADuu7eLiYxIsDdAedAe2loJRK/AeQPG:ApoOioYtGiK3ZlotH+` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_093_a8b44ff9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8b44ff9d650dfa4157024c8fa99a9dbc51c57cb25c56798aefa2fe6733c49eb"
    family = "RemcosRAT"
    file_name = "studyforbest.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:19:06"
  condition:
    hash.sha256(0, filesize) == "a8b44ff9d650dfa4157024c8fa99a9dbc51c57cb25c56798aefa2fe6733c49eb"
}
```

### Sample 94: `3ea19eda84232ad5`

| Field | Value |
|---|---|
| SHA-256 | `3ea19eda84232ad534581ed5597e8b55379cee85a13e3c81bcfbe033b0e3d302` |
| Family label | `RemcosRAT` |
| File name | `goodboss.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:16:06` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9332b1bfe1153d072f59d9b6a5f98a95` |
| SHA-1 | `d049b0469ceb46fb09ffad393029daac4fa3b997` |
| SHA-256 | `3ea19eda84232ad534581ed5597e8b55379cee85a13e3c81bcfbe033b0e3d302` |
| SHA3-384 | `19d0c42f36f5cb01277de35bd7c370755544847773a7ae2b8d082861b1499655cee711ba1be607f0df18485f1556ab30` |
| TLSH | `T1AB72FE3DA720FC96C0AA83EA508D751750A1C6BFFA158601B89D0DB7BBA585E4C3468E` |
| SSDEEP | `48:3PiJWC7Aim5dWC7AkLEm5duyFiOwuq60gmuuuuuBuuuuBi0gmoduuuuu35WC7AHB:/il7AV7AI0GXniXE17Ah7AdM7A/+` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_094_3ea19eda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ea19eda84232ad534581ed5597e8b55379cee85a13e3c81bcfbe033b0e3d302"
    family = "RemcosRAT"
    file_name = "goodboss.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:16:06"
  condition:
    hash.sha256(0, filesize) == "3ea19eda84232ad534581ed5597e8b55379cee85a13e3c81bcfbe033b0e3d302"
}
```

### Sample 95: `afca63cf3aa67778`

| Field | Value |
|---|---|
| SHA-256 | `afca63cf3aa6777889d358eff16ea481e2857f8b983a396c2266a7115b854c23` |
| Family label | `RemcosRAT` |
| File name | `goodkings.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:15:08` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49bd0dce713fdd911743ec9fb6b0f730` |
| SHA-1 | `b09b1fa1f4a770fb823ddcd46f49d25c07724d5c` |
| SHA-256 | `afca63cf3aa6777889d358eff16ea481e2857f8b983a396c2266a7115b854c23` |
| SHA3-384 | `d6b2621f53812304e1bcf26cf954412ebff7404e9c37951a159dbe895c0b7abfee72e5efd5fa05ca9782e7a8e7bbb10e` |
| TLSH | `T120620378DA91FCC8A6EB63BCA54025110D19882FB600ED297D9D8CD7672013D58EF61B` |
| SSDEEP | `48:3vaLFaLZNN1uuusQf45N8k8uoBuuuuu6i0gVaLDaLQLaLaPG:YKf7QfWNROiX6UQca+` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_095_afca63cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afca63cf3aa6777889d358eff16ea481e2857f8b983a396c2266a7115b854c23"
    family = "RemcosRAT"
    file_name = "goodkings.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:15:08"
  condition:
    hash.sha256(0, filesize) == "afca63cf3aa6777889d358eff16ea481e2857f8b983a396c2266a7115b854c23"
}
```

### Sample 96: `efccf7d45feab094`

| Field | Value |
|---|---|
| SHA-256 | `efccf7d45feab094c0b38c0db69c86788532a3b5f155cb2307e3d1fec62affa8` |
| Family label | `RemcosRAT` |
| File name | `cloudfree.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:14:06` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af7ad7cabfaa21c8ca84746ed9c67d2b` |
| SHA-1 | `0aa657f63426d07d06c7e4d74c509872454a0ad7` |
| SHA-256 | `efccf7d45feab094c0b38c0db69c86788532a3b5f155cb2307e3d1fec62affa8` |
| SHA3-384 | `cbca6d9ff5c8bcf61c30d34a39ebfafb16e5c33a2183223f04ccc0cf03dd180dbf9005ed94254c6fb4e55a39047fd7e0` |
| TLSH | `T17A72533801D0BCE4A3D761ACF2197B611D8AB50FF501A100748D49EBB7CAA5EA93C3CB` |
| SSDEEP | `48:3lsfPr54fVKr5S13puwroJN8kLuuuuGi0gfAN8kMfAfhr5BfIPG:CfPrWfVKrEKNRiiXoNRMfAfhrffI+` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_096_efccf7d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efccf7d45feab094c0b38c0db69c86788532a3b5f155cb2307e3d1fec62affa8"
    family = "RemcosRAT"
    file_name = "cloudfree.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:14:06"
  condition:
    hash.sha256(0, filesize) == "efccf7d45feab094c0b38c0db69c86788532a3b5f155cb2307e3d1fec62affa8"
}
```

### Sample 97: `93877d0cf89a19e1`

| Field | Value |
|---|---|
| SHA-256 | `93877d0cf89a19e113e98c6f54b2d7de6dd82e1c9700f1b98dc8cf79b4dceb8d` |
| Family label | `RemcosRAT` |
| File name | `grg.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:12:08` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c84ee4f82b47000ce93c551850802044` |
| SHA-1 | `5b28bed1433ab9abbc37e8c26994df6c21db9e51` |
| SHA-256 | `93877d0cf89a19e113e98c6f54b2d7de6dd82e1c9700f1b98dc8cf79b4dceb8d` |
| SHA3-384 | `ff9429f92143bd5d4393198daa8ca0c7287df5c1749b86eb167fb944f173d8c23bad285b90aeb5f319f375de46c882a2` |
| TLSH | `T1A962427E0620FAD9C67663FE5698B40381C6F976898C9A217C8C41032BB068CAC7B04F` |
| SSDEEP | `48:3u5oR8somdCWQj0SGu6uuuuuuuvA1f5ru1VRZoiCEPG:gmAFDl+` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_097_93877d0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93877d0cf89a19e113e98c6f54b2d7de6dd82e1c9700f1b98dc8cf79b4dceb8d"
    family = "RemcosRAT"
    file_name = "grg.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:12:08"
  condition:
    hash.sha256(0, filesize) == "93877d0cf89a19e113e98c6f54b2d7de6dd82e1c9700f1b98dc8cf79b4dceb8d"
}
```

### Sample 98: `8eea9e128e3e2b59`

| Field | Value |
|---|---|
| SHA-256 | `8eea9e128e3e2b599d443f49006739f8bdb92daa1a6cccf4db79babfbd0dadcf` |
| Family label | `RemcosRAT` |
| File name | `cleaning.hta` |
| File type | `hta` |
| First seen | `2026-11-24 08:12:05` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fae365edb2ba165ed9235442232bb0e1` |
| SHA-1 | `ca622dd87c292484f7f4efcc127b038779291269` |
| SHA-256 | `8eea9e128e3e2b599d443f49006739f8bdb92daa1a6cccf4db79babfbd0dadcf` |
| SHA3-384 | `6ecddf20d15bdae900d846c428de3c523190501fe4d93fa5276d0e42f25d93fbbde45d0578d121acb54af689c3b9ba97` |
| TLSH | `T1AC62327CE982BED493DBE0D18446F211E35D878FE016275CF48C417A87082B9447E15A` |
| SSDEEP | `48:3AkvTfJUkvAj5fJ44WaIv9UwaqVAkvRkvNhVfJrkvdPG:h7bYNxRw9RiVPyl+` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_098_8eea9e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8eea9e128e3e2b599d443f49006739f8bdb92daa1a6cccf4db79babfbd0dadcf"
    family = "RemcosRAT"
    file_name = "cleaning.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:12:05"
  condition:
    hash.sha256(0, filesize) == "8eea9e128e3e2b599d443f49006739f8bdb92daa1a6cccf4db79babfbd0dadcf"
}
```

### Sample 99: `88b016f66c1bbc47`

| Field | Value |
|---|---|
| SHA-256 | `88b016f66c1bbc47c7515a369baf1270fd5afd73c15ee715172f34c6956c4bf8` |
| Family label | `EasyShell` |
| File name | `easyshell-l64-88b016f66c1bbc47.bin` |
| File type | `elf` |
| First seen | `2026-11-24 08:06:14` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cc785c0edaf92fc3e507b40489ac1b1` |
| SHA-1 | `7277e1273e73065bc1de046bad8f1044f16ab69b` |
| SHA-256 | `88b016f66c1bbc47c7515a369baf1270fd5afd73c15ee715172f34c6956c4bf8` |
| SHA3-384 | `24ac0fd7a4692182e350ffc3c87c98a9bb71d97cdebaed010d04874f1cc136dfe8a5e414cd6ce3246f09b0a52a9bd10f` |
| TLSH | `T169267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxiyH8hIU6iKHh:OYjiiKgib9qRGcEulycW+gh` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_099_88b016f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88b016f66c1bbc47c7515a369baf1270fd5afd73c15ee715172f34c6956c4bf8"
    family = "EasyShell"
    file_name = "easyshell-l64-88b016f66c1bbc47.bin"
    file_type = "elf"
    first_seen = "2026-11-24 08:06:14"
  condition:
    hash.sha256(0, filesize) == "88b016f66c1bbc47c7515a369baf1270fd5afd73c15ee715172f34c6956c4bf8"
}
```

### Sample 100: `ff7bc41ef3835302`

| Field | Value |
|---|---|
| SHA-256 | `ff7bc41ef3835302c0dc1e115a13076069743255287c006fb5f4febd3016b2ed` |
| Family label | `EasyShell` |
| File name | `easyshell-l32-ff7bc41ef3835302.bin` |
| File type | `elf` |
| First seen | `2026-11-24 08:06:04` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `039bc6d2e82736e52283046d7999e839` |
| SHA-1 | `6dfa263c0f462afeb55dd8764af8d4c200bdef60` |
| SHA-256 | `ff7bc41ef3835302c0dc1e115a13076069743255287c006fb5f4febd3016b2ed` |
| SHA3-384 | `13b27b3c7ced4bfcea7a40d4e80984b9cd4ea95f0d5be339d42eeddd9d9cc3a59640a999e710a840ece015bc474d58c8` |
| TLSH | `T16B068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1PF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1Pdb` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_100_ff7bc41e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff7bc41ef3835302c0dc1e115a13076069743255287c006fb5f4febd3016b2ed"
    family = "EasyShell"
    file_name = "easyshell-l32-ff7bc41ef3835302.bin"
    file_type = "elf"
    first_seen = "2026-11-24 08:06:04"
  condition:
    hash.sha256(0, filesize) == "ff7bc41ef3835302c0dc1e115a13076069743255287c006fb5f4febd3016b2ed"
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
 * Generated: 2026-11-24T10:03:53.086047+00:00
 */

rule MalwareBazaar_unknown_001_972d8d61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "972d8d61394f08fdae76bde12e86a6faa7663978f442e4f2b9b6a4c580a75ea1"
    family = "unknown"
    file_name = "CopiadetransferenciaUSD46.200.00PDF.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:50:13"
  condition:
    hash.sha256(0, filesize) == "972d8d61394f08fdae76bde12e86a6faa7663978f442e4f2b9b6a4c580a75ea1"
}

rule MalwareBazaar_unknown_002_5482a9cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5482a9cc3854baff32b3bb8ad6a8fdd68e3485d2c9b26ef3d7f8c7bd77dcdc9f"
    family = "unknown"
    file_name = "5482a9cc3854baff32b3bb8ad6a8fdd68e3485d2c9b26ef3d7f8c7bd77dcdc9f"
    file_type = "exe"
    first_seen = "2026-11-24 09:44:54"
  condition:
    hash.sha256(0, filesize) == "5482a9cc3854baff32b3bb8ad6a8fdd68e3485d2c9b26ef3d7f8c7bd77dcdc9f"
}

rule MalwareBazaar_unknown_003_a8512dd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8512dd24bd9776b143fa9a23058e03c7c4c36e9bad839a028137b782855ab5a"
    family = "unknown"
    file_name = "ad0a11b87b468cbd4d9555d4f845e9256370ff631f7cafc063d6e0a59e98c777.zip"
    file_type = "zip"
    first_seen = "2026-11-24 09:44:06"
  condition:
    hash.sha256(0, filesize) == "a8512dd24bd9776b143fa9a23058e03c7c4c36e9bad839a028137b782855ab5a"
}

rule MalwareBazaar_unknown_004_72307be5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72307be53f03d307833108f592a631ea3e70840042f7925c1f3247796d4262d7"
    family = "unknown"
    file_name = "72307be53f03d307833108f592a631ea3e70840042f7925c1f3247796d4262d7"
    file_type = "sh"
    first_seen = "2026-11-24 09:43:52"
  condition:
    hash.sha256(0, filesize) == "72307be53f03d307833108f592a631ea3e70840042f7925c1f3247796d4262d7"
}

rule MalwareBazaar_unknown_005_885d654b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "885d654b11869e83f55ae4a18dcd8ad182d0da81faf2d54c145ba9cdc830c270"
    family = "unknown"
    file_name = "885d654b11869e83f55ae4a18dcd8ad182d0da81faf2d54c145ba9cdc830c270"
    file_type = "sh"
    first_seen = "2026-11-24 09:43:51"
  condition:
    hash.sha256(0, filesize) == "885d654b11869e83f55ae4a18dcd8ad182d0da81faf2d54c145ba9cdc830c270"
}

rule MalwareBazaar_Formbook_006_e671e852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e671e8522520cc8895516adea27487dd9b582c7cbf63e08314f60d05f8050d0f"
    family = "Formbook"
    file_name = "KMK.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:42:40"
  condition:
    hash.sha256(0, filesize) == "e671e8522520cc8895516adea27487dd9b582c7cbf63e08314f60d05f8050d0f"
}

rule MalwareBazaar_Formbook_007_bb6e8a09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb6e8a09dea7742fdf5fd584446c998041c4e77c635aea0343e0b769cf3fccd3"
    family = "Formbook"
    file_name = "PWKMK.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:42:36"
  condition:
    hash.sha256(0, filesize) == "bb6e8a09dea7742fdf5fd584446c998041c4e77c635aea0343e0b769cf3fccd3"
}

rule MalwareBazaar_Ransomware_WannaCry_008_1d548ed2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d548ed2c6bf9f6de674ebab42371bb7c5b35f5eae8aed01f48be85ec4b72dfc"
    family = "Ransomware.WannaCry"
    file_name = "379cf4fce883e5853294990f94c082eb971db7b0e3a817f7abd4facffc4fe23f.zip"
    file_type = "zip"
    first_seen = "2026-11-24 09:41:26"
  condition:
    hash.sha256(0, filesize) == "1d548ed2c6bf9f6de674ebab42371bb7c5b35f5eae8aed01f48be85ec4b72dfc"
}

rule MalwareBazaar_SnappyClient_009_59d56653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59d56653d79c40e190b929f43cf50712e0595b12f7a7ebcc31ec116a919cd57b"
    family = "SnappyClient"
    file_name = "1.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:39:38"
  condition:
    hash.sha256(0, filesize) == "59d56653d79c40e190b929f43cf50712e0595b12f7a7ebcc31ec116a919cd57b"
}

rule MalwareBazaar_ConnectWise_010_fc7c1cc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc7c1cc3664fb63c309c9cdc5a3e5b6477507e8922e3d7a011635e0f86057474"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-11-24 09:39:34"
  condition:
    hash.sha256(0, filesize) == "fc7c1cc3664fb63c309c9cdc5a3e5b6477507e8922e3d7a011635e0f86057474"
}

rule MalwareBazaar_Formbook_011_7549be01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7549be014bfdb35fc54f11ee9013872deb17b1d6c19c51386d4bd4cb0383f7ce"
    family = "Formbook"
    file_name = "M2KMK.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:39:25"
  condition:
    hash.sha256(0, filesize) == "7549be014bfdb35fc54f11ee9013872deb17b1d6c19c51386d4bd4cb0383f7ce"
}

rule MalwareBazaar_Formbook_012_11b3f76d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11b3f76d94cf66e4c02aa96bcbec88044d55c506ffe0c5bdc39b3fc3b2f185cf"
    family = "Formbook"
    file_name = "36KMK.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:38:50"
  condition:
    hash.sha256(0, filesize) == "11b3f76d94cf66e4c02aa96bcbec88044d55c506ffe0c5bdc39b3fc3b2f185cf"
}

rule MalwareBazaar_WARDENStealer_013_f658be3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f658be3f57702affa9839ed7e1e70b7875d533015c5864af6a7408c50859f66e"
    family = "WARDENStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:38:41"
  condition:
    hash.sha256(0, filesize) == "f658be3f57702affa9839ed7e1e70b7875d533015c5864af6a7408c50859f66e"
}

rule MalwareBazaar_AgentTesla_014_9a012924
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a012924a61ea03dc8ce6f94467658595abd374d2523230497f7569e6c0db23a"
    family = "AgentTesla"
    file_name = "Booking_Confirmation.js"
    file_type = "js"
    first_seen = "2026-11-24 09:38:21"
  condition:
    hash.sha256(0, filesize) == "9a012924a61ea03dc8ce6f94467658595abd374d2523230497f7569e6c0db23a"
}

rule MalwareBazaar_RemcosRAT_015_fffa9884
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fffa988426ff3c813effd541c226f5168c0bc6e4045d5adc10d4855ca475c456"
    family = "RemcosRAT"
    file_name = "updated.vbe"
    file_type = "vbe"
    first_seen = "2026-11-24 09:38:16"
  condition:
    hash.sha256(0, filesize) == "fffa988426ff3c813effd541c226f5168c0bc6e4045d5adc10d4855ca475c456"
}

rule MalwareBazaar_RemcosRAT_016_43b4ab97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43b4ab9772c9b90cdd8f3995f892cc9b708116498366f759a9c2f78272035518"
    family = "RemcosRAT"
    file_name = "ipad.vbe"
    file_type = "vbe"
    first_seen = "2026-11-24 09:38:12"
  condition:
    hash.sha256(0, filesize) == "43b4ab9772c9b90cdd8f3995f892cc9b708116498366f759a9c2f78272035518"
}

rule MalwareBazaar_RemcosRAT_017_6efa8797
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6efa87978c4c29d6c85994ec9dc9e280f12f1569a5f85688865af25f36527cf2"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:37:31"
  condition:
    hash.sha256(0, filesize) == "6efa87978c4c29d6c85994ec9dc9e280f12f1569a5f85688865af25f36527cf2"
}

rule MalwareBazaar_RemcosRAT_018_889af64a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889af64a3f1e8210003a729d8b55d807f69858fdd5f0e754e90218f19cd8ec2e"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:36:19"
  condition:
    hash.sha256(0, filesize) == "889af64a3f1e8210003a729d8b55d807f69858fdd5f0e754e90218f19cd8ec2e"
}

rule MalwareBazaar_RemcosRAT_019_9a46c789
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a46c78920200428c73737ffc7751df004a0a9f6c092aff0c28da8403a4a0ad7"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:35:00"
  condition:
    hash.sha256(0, filesize) == "9a46c78920200428c73737ffc7751df004a0a9f6c092aff0c28da8403a4a0ad7"
}

rule MalwareBazaar_RemcosRAT_020_fd0514be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd0514bef8da697fde6c1d8f1968ca7246eb8e79c5672a010f4241e96c3d3bf2"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:33:48"
  condition:
    hash.sha256(0, filesize) == "fd0514bef8da697fde6c1d8f1968ca7246eb8e79c5672a010f4241e96c3d3bf2"
}

rule MalwareBazaar_RemcosRAT_021_f6d69ff1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6d69ff1e14768a8baebedfd572e8804ea46d24ebe02490d3d84562e10b0b0d8"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:32:56"
  condition:
    hash.sha256(0, filesize) == "f6d69ff1e14768a8baebedfd572e8804ea46d24ebe02490d3d84562e10b0b0d8"
}

rule MalwareBazaar_RemcosRAT_022_6e886c90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e886c90177dbca761234b09ebc8493699b3925332ccf0ed1c178214a6c6b657"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:32:05"
  condition:
    hash.sha256(0, filesize) == "6e886c90177dbca761234b09ebc8493699b3925332ccf0ed1c178214a6c6b657"
}

rule MalwareBazaar_RemcosRAT_023_2f1bd42f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f1bd42fedeadb2418d125a9484cace882b47c48b14f6d55fbf9173d8d857106"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:30:52"
  condition:
    hash.sha256(0, filesize) == "2f1bd42fedeadb2418d125a9484cace882b47c48b14f6d55fbf9173d8d857106"
}

rule MalwareBazaar_RemcosRAT_024_9c7b899c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c7b899c08a1c2368bc8dc090a535e4c41113bef8b7d2d300629f93f3e0c1a94"
    family = "RemcosRAT"
    file_name = "Contract000388122-LSI-TQVL-PDF.jse"
    file_type = "jse"
    first_seen = "2026-11-24 09:30:41"
  condition:
    hash.sha256(0, filesize) == "9c7b899c08a1c2368bc8dc090a535e4c41113bef8b7d2d300629f93f3e0c1a94"
}

rule MalwareBazaar_unknown_025_22722a6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22722a6aba31640558e50a48c9d661f12d7d259859b66a7dae97ec08e6f47d42"
    family = "unknown"
    file_name = "ARRIVALNOTICE-77B738.jse"
    file_type = "jse"
    first_seen = "2026-11-24 09:30:38"
  condition:
    hash.sha256(0, filesize) == "22722a6aba31640558e50a48c9d661f12d7d259859b66a7dae97ec08e6f47d42"
}

rule MalwareBazaar_unknown_026_a4b3375b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4b3375b314ac7009639ae894b765e4703f50a03e02cebba7b81169df7e06bbd"
    family = "unknown"
    file_name = "RFQSpecs.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:35"
  condition:
    hash.sha256(0, filesize) == "a4b3375b314ac7009639ae894b765e4703f50a03e02cebba7b81169df7e06bbd"
}

rule MalwareBazaar_XWorm_027_9e462be7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e462be7ae0d8392cf880b91abad62d66f370ee134d7d96dbf611d9d3e6e7843"
    family = "XWorm"
    file_name = "Statement_of_acccount.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:32"
  condition:
    hash.sha256(0, filesize) == "9e462be7ae0d8392cf880b91abad62d66f370ee134d7d96dbf611d9d3e6e7843"
}

rule MalwareBazaar_unknown_028_3fd469cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fd469cbd20391b891c4ee210c121780cf44f09e49e7d1b25fbc8913bffead5e"
    family = "unknown"
    file_name = "attachment.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:29"
  condition:
    hash.sha256(0, filesize) == "3fd469cbd20391b891c4ee210c121780cf44f09e49e7d1b25fbc8913bffead5e"
}

rule MalwareBazaar_Formbook_029_26e898f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26e898f52eb5a272323374a4816fcfe762bad2dc32bbb4b98fe3f817818f1adb"
    family = "Formbook"
    file_name = "MaterialLists-ItemsRequirements.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:22"
  condition:
    hash.sha256(0, filesize) == "26e898f52eb5a272323374a4816fcfe762bad2dc32bbb4b98fe3f817818f1adb"
}

rule MalwareBazaar_RemcosRAT_030_56539d7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56539d7e09290ccd0068252f1dccca3b910bd31eee9d4e37c6d48dc10a828259"
    family = "RemcosRAT"
    file_name = "invoice.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:19"
  condition:
    hash.sha256(0, filesize) == "56539d7e09290ccd0068252f1dccca3b910bd31eee9d4e37c6d48dc10a828259"
}

rule MalwareBazaar_AsyncRAT_031_e1fd622d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1fd622d7bfe5be1d17f19d4ec9e7e39d5224e658be885ced429848630f87bc5"
    family = "AsyncRAT"
    file_name = "CotizacinOrdendecompra.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:16"
  condition:
    hash.sha256(0, filesize) == "e1fd622d7bfe5be1d17f19d4ec9e7e39d5224e658be885ced429848630f87bc5"
}

rule MalwareBazaar_FormBook_032_5b08d49c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b08d49c1b4bc0dd521c8376f1f0e78de58fdaa2fd4638a8a1616e31ae3b1d5e"
    family = "FormBook"
    file_name = "PO_Eco-26112418EA1.js"
    file_type = "js"
    first_seen = "2026-11-24 09:30:13"
  condition:
    hash.sha256(0, filesize) == "5b08d49c1b4bc0dd521c8376f1f0e78de58fdaa2fd4638a8a1616e31ae3b1d5e"
}

rule MalwareBazaar_unknown_033_d6c8a560
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6c8a5606c18820ac76563beb915d6ce0b8100da5eff096a50817c0fb72957fc"
    family = "unknown"
    file_name = "update.js"
    file_type = "js"
    first_seen = "2026-11-24 09:29:20"
  condition:
    hash.sha256(0, filesize) == "d6c8a5606c18820ac76563beb915d6ce0b8100da5eff096a50817c0fb72957fc"
}

rule MalwareBazaar_RemcosRAT_034_b20034a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b20034a10e4334fe85a949df3e281b7d25cdce02afd8122b23471205cb33e975"
    family = "RemcosRAT"
    file_name = "secured_stub.ps1"
    file_type = "ps1"
    first_seen = "2026-11-24 09:26:57"
  condition:
    hash.sha256(0, filesize) == "b20034a10e4334fe85a949df3e281b7d25cdce02afd8122b23471205cb33e975"
}

rule MalwareBazaar_NanoCore_035_19aa0b9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19aa0b9ad7c714ad82d396640df2d30723cda6ad0863186a285b540de1a8d06b"
    family = "NanoCore"
    file_name = "77458DAD3B4731D80ECE2DA6C8A0EF60.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:25:09"
  condition:
    hash.sha256(0, filesize) == "19aa0b9ad7c714ad82d396640df2d30723cda6ad0863186a285b540de1a8d06b"
}

rule MalwareBazaar_Formbook_036_ac9e1ddf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac9e1ddf68eb15cecae4844c87edc69ab90948599c321cc55394b60dcdf27d79"
    family = "Formbook"
    file_name = "DQpvdsX6JmqGDcC.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:21:14"
  condition:
    hash.sha256(0, filesize) == "ac9e1ddf68eb15cecae4844c87edc69ab90948599c321cc55394b60dcdf27d79"
}

rule MalwareBazaar_Formbook_037_4d6983a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d6983a6925d67a38f1b3f663d92af15854440c05fa4e16e82126f53bb71c4a1"
    family = "Formbook"
    file_name = "pd224334177.att"
    file_type = "exe"
    first_seen = "2026-11-24 09:21:11"
  condition:
    hash.sha256(0, filesize) == "4d6983a6925d67a38f1b3f663d92af15854440c05fa4e16e82126f53bb71c4a1"
}

rule MalwareBazaar_Formbook_038_ce0b584b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce0b584bb313f25d2c1ade13b3084e75959132fcb9994a63d3d37ac717f68a59"
    family = "Formbook"
    file_name = "Comprobante_SWIFT_Transferencia_Internacional.pdf.pif"
    file_type = "exe"
    first_seen = "2026-11-24 09:21:08"
  condition:
    hash.sha256(0, filesize) == "ce0b584bb313f25d2c1ade13b3084e75959132fcb9994a63d3d37ac717f68a59"
}

rule MalwareBazaar_unknown_039_12d250da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12d250da2d8b2ec0c8857c3c3b7fe9343429f7702ac9eda3627f789a93cda436"
    family = "unknown"
    file_name = "PRO-D3.js"
    file_type = "js"
    first_seen = "2026-11-24 09:21:05"
  condition:
    hash.sha256(0, filesize) == "12d250da2d8b2ec0c8857c3c3b7fe9343429f7702ac9eda3627f789a93cda436"
}

rule MalwareBazaar_AsyncRAT_040_3af3760b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3af3760b0ccace9887e3ea58b0dece8ff3f701dfa255695ce92e50a58ab9a2fa"
    family = "AsyncRAT"
    file_name = "OrdendeCompra_PO4501887325.pdf.js"
    file_type = "js"
    first_seen = "2026-11-24 09:21:00"
  condition:
    hash.sha256(0, filesize) == "3af3760b0ccace9887e3ea58b0dece8ff3f701dfa255695ce92e50a58ab9a2fa"
}

rule MalwareBazaar_AsyncRAT_041_a5e4fab4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5e4fab4958854fa69b330d2294d80566b966b9b7f50ae40c2478375ff010991"
    family = "AsyncRAT"
    file_name = "PO.js"
    file_type = "js"
    first_seen = "2026-11-24 09:20:58"
  condition:
    hash.sha256(0, filesize) == "a5e4fab4958854fa69b330d2294d80566b966b9b7f50ae40c2478375ff010991"
}

rule MalwareBazaar_Formbook_042_a2aa32f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2aa32f80d0504fc57b110d8e06177cfb754eba889c816fc72d5a4226c846a4d"
    family = "Formbook"
    file_name = "SWIFTMESAJIPDF.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:55"
  condition:
    hash.sha256(0, filesize) == "a2aa32f80d0504fc57b110d8e06177cfb754eba889c816fc72d5a4226c846a4d"
}

rule MalwareBazaar_AgentTesla_043_bc2df196
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc2df196c06783eabf71cef8d859abec8b298f44a52e3f56e22dc02f30f52411"
    family = "AgentTesla"
    file_name = "PO_4500102673_S.S.Grow.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:52"
  condition:
    hash.sha256(0, filesize) == "bc2df196c06783eabf71cef8d859abec8b298f44a52e3f56e22dc02f30f52411"
}

rule MalwareBazaar_AgentTesla_044_81064860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "810648609fcf3b6f5ec40a58fe3fc725b95fedfc67dea283e8936ab89d4a9d55"
    family = "AgentTesla"
    file_name = "NewPurchaseOrderPO367328911.bat"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:49"
  condition:
    hash.sha256(0, filesize) == "810648609fcf3b6f5ec40a58fe3fc725b95fedfc67dea283e8936ab89d4a9d55"
}

rule MalwareBazaar_unknown_045_bc27e0e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc27e0e70082a89585735e049adbe6e1ff0e01d8972780416b7938880ffbc6b0"
    family = "unknown"
    file_name = "PRO-T07.js"
    file_type = "js"
    first_seen = "2026-11-24 09:20:46"
  condition:
    hash.sha256(0, filesize) == "bc27e0e70082a89585735e049adbe6e1ff0e01d8972780416b7938880ffbc6b0"
}

rule MalwareBazaar_unknown_046_2505f0c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2505f0c934f22649ee6ae0ef092a52ef289a919bfd830e53a8e1f5acbf6bc137"
    family = "unknown"
    file_name = "VCRUNTIME140.dll"
    file_type = "dll"
    first_seen = "2026-11-24 09:20:43"
  condition:
    hash.sha256(0, filesize) == "2505f0c934f22649ee6ae0ef092a52ef289a919bfd830e53a8e1f5acbf6bc137"
}

rule MalwareBazaar_Formbook_047_9f94ab1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f94ab1a0c5c315cccf7686cc21cd89506e972524ca5cc038b3cc2c5aed79b1d"
    family = "Formbook"
    file_name = "POHTS-PO-0893.scr"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:38"
  condition:
    hash.sha256(0, filesize) == "9f94ab1a0c5c315cccf7686cc21cd89506e972524ca5cc038b3cc2c5aed79b1d"
}

rule MalwareBazaar_RemcosRAT_048_0200cd50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0200cd503802d0ab38b1c71731e041067e9230f90131d3322df85a80b1beb4c4"
    family = "RemcosRAT"
    file_name = "PNlist_KBD_09112026_final.scr"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:35"
  condition:
    hash.sha256(0, filesize) == "0200cd503802d0ab38b1c71731e041067e9230f90131d3322df85a80b1beb4c4"
}

rule MalwareBazaar_Formbook_049_64dee9d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64dee9d78f858bee43021c117bb69acea4f042bc7791881969c8d29c4ff24f68"
    family = "Formbook"
    file_name = "SOA_9904029_PWS022948_WA192026_PDF.com"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:30"
  condition:
    hash.sha256(0, filesize) == "64dee9d78f858bee43021c117bb69acea4f042bc7791881969c8d29c4ff24f68"
}

rule MalwareBazaar_unknown_050_c809fb29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c809fb2964bb7eb701c6777a72bc5af82d7f0c95eac3fa324b684bd06ab309bd"
    family = "unknown"
    file_name = "PO21636.js"
    file_type = "js"
    first_seen = "2026-11-24 09:20:27"
  condition:
    hash.sha256(0, filesize) == "c809fb2964bb7eb701c6777a72bc5af82d7f0c95eac3fa324b684bd06ab309bd"
}

rule MalwareBazaar_Formbook_051_f42522e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f42522e5eef67cdd01eaf2bb77e6f58ab1feb3b537884bb951e987ee546a438e"
    family = "Formbook"
    file_name = "IYTDY6355.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:24"
  condition:
    hash.sha256(0, filesize) == "f42522e5eef67cdd01eaf2bb77e6f58ab1feb3b537884bb951e987ee546a438e"
}

rule MalwareBazaar_Formbook_052_3c7ac613
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c7ac61372dd44f281174df32948ede3ecc379c70464f52d0c0f008b73a0a564"
    family = "Formbook"
    file_name = "Invoice.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:20"
  condition:
    hash.sha256(0, filesize) == "3c7ac61372dd44f281174df32948ede3ecc379c70464f52d0c0f008b73a0a564"
}

rule MalwareBazaar_Formbook_053_290ba056
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "290ba056ff6bbb7632c50b729cca188f8d59130731a72f48e25ff7ea21f91e08"
    family = "Formbook"
    file_name = "TTSlip_WEC-LDV-2610-00112R_Advance.bat"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:17"
  condition:
    hash.sha256(0, filesize) == "290ba056ff6bbb7632c50b729cca188f8d59130731a72f48e25ff7ea21f91e08"
}

rule MalwareBazaar_AgentTesla_054_1b126bd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b126bd1d906810d8bcb5ff61e3502420244e754c5398d78c654dce7d212adec"
    family = "AgentTesla"
    file_name = "ORDERWAL076N14435SH0November2026PO3011921.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:20:14"
  condition:
    hash.sha256(0, filesize) == "1b126bd1d906810d8bcb5ff61e3502420244e754c5398d78c654dce7d212adec"
}

rule MalwareBazaar_njrat_055_1446cc50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1446cc50fa039d8859063af64c5ef37dd730c1dd42793f729773dc38f3810978"
    family = "njrat"
    file_name = "13d80f4e9330faf865623999e45f703b.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:15:15"
  condition:
    hash.sha256(0, filesize) == "1446cc50fa039d8859063af64c5ef37dd730c1dd42793f729773dc38f3810978"
}

rule MalwareBazaar_njrat_056_99dacf89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99dacf89b6c3df8e101338ae02c3dd432bbed0b002d7dc1b9c230b5af198c8cf"
    family = "njrat"
    file_name = "01d3fa8e5da2b4a46ac93546952e1895.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:15:10"
  condition:
    hash.sha256(0, filesize) == "99dacf89b6c3df8e101338ae02c3dd432bbed0b002d7dc1b9c230b5af198c8cf"
}

rule MalwareBazaar_Formbook_057_dd66fc9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd66fc9d2e919a11ab0cca9dab0b41e755a26ae60ed6acc42fec266f7d662d64"
    family = "Formbook"
    file_name = "goodness.js"
    file_type = "js"
    first_seen = "2026-11-24 09:15:08"
  condition:
    hash.sha256(0, filesize) == "dd66fc9d2e919a11ab0cca9dab0b41e755a26ae60ed6acc42fec266f7d662d64"
}

rule MalwareBazaar_unknown_058_32b5b5f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32b5b5f419d97ff94bfb7ddc647b331533ec53c1ff3646ec55adbca9d3ccd658"
    family = "unknown"
    file_name = "ProjectExb.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:12:12"
  condition:
    hash.sha256(0, filesize) == "32b5b5f419d97ff94bfb7ddc647b331533ec53c1ff3646ec55adbca9d3ccd658"
}

rule MalwareBazaar_GuLoader_059_ad56c22a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad56c22a8c4e3c80636bfeb2179c9759a9642300abb27284ea2c87fa65f894bc"
    family = "GuLoader"
    file_name = "DHL_Awb_Shipping#Tracking_commercial_INV_PL_BL_11_24_2026_PDF.js"
    file_type = "js"
    first_seen = "2026-11-24 09:11:47"
  condition:
    hash.sha256(0, filesize) == "ad56c22a8c4e3c80636bfeb2179c9759a9642300abb27284ea2c87fa65f894bc"
}

rule MalwareBazaar_RemcosRAT_060_6d04bed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d04bed858ce107dd3eaaf2648c577bfb9ccec87faa71f9dba2c4d4a8d77582b"
    family = "RemcosRAT"
    file_name = "Afla_GmbH_Purchase_Order_2120_2110921_Amendment_Updated_2026-11-22_pdf.js"
    file_type = "js"
    first_seen = "2026-11-24 09:10:16"
  condition:
    hash.sha256(0, filesize) == "6d04bed858ce107dd3eaaf2648c577bfb9ccec87faa71f9dba2c4d4a8d77582b"
}

rule MalwareBazaar_unknown_061_ffd5b034
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffd5b0344123a984d27c4aa624215fa6452c3849522803b2bc3a6ee0bcb23809"
    family = "unknown"
    file_name = "tmpuo0zf7rz.php"
    file_type = "php"
    first_seen = "2026-11-24 09:07:57"
  condition:
    hash.sha256(0, filesize) == "ffd5b0344123a984d27c4aa624215fa6452c3849522803b2bc3a6ee0bcb23809"
}

rule MalwareBazaar_unknown_062_ea4ac601
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea4ac6017a5a5c1520afbd48465d2127be51917fafec9f3850102db614cbace2"
    family = "unknown"
    file_name = "LeronX.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:07:53"
  condition:
    hash.sha256(0, filesize) == "ea4ac6017a5a5c1520afbd48465d2127be51917fafec9f3850102db614cbace2"
}

rule MalwareBazaar_EasyShell_063_581abe92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "581abe92dd2db2650e43ab26614595bd82f92be10619d5337afd5ae51d67115e"
    family = "EasyShell"
    file_name = "easyshell-l64-581abe92dd2db265.bin"
    file_type = "elf"
    first_seen = "2026-11-24 09:06:23"
  condition:
    hash.sha256(0, filesize) == "581abe92dd2db2650e43ab26614595bd82f92be10619d5337afd5ae51d67115e"
}

rule MalwareBazaar_EasyShell_064_3d0209c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d0209c42fe3f5ed693c1f2ed87b0d132894fda4514c36642e84db3278b531af"
    family = "EasyShell"
    file_name = "easyshell-l32-3d0209c42fe3f5ed.bin"
    file_type = "elf"
    first_seen = "2026-11-24 09:06:14"
  condition:
    hash.sha256(0, filesize) == "3d0209c42fe3f5ed693c1f2ed87b0d132894fda4514c36642e84db3278b531af"
}

rule MalwareBazaar_EasyShell_065_f1ecffc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1ecffc9d4663647f2c88877d3751a989a6bcdd69d20f3f479e52e196d53466e"
    family = "EasyShell"
    file_name = "easyshell-l128-f1ecffc9d4663647.bin"
    file_type = "elf"
    first_seen = "2026-11-24 09:06:06"
  condition:
    hash.sha256(0, filesize) == "f1ecffc9d4663647f2c88877d3751a989a6bcdd69d20f3f479e52e196d53466e"
}

rule MalwareBazaar_EasyShell_066_4c274445
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c27444529d206bb6b373f531a04f59c0025d5d78823f70e6231fac112367801"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-4c27444529d206bb.bin"
    file_type = "macho"
    first_seen = "2026-11-24 09:05:57"
  condition:
    hash.sha256(0, filesize) == "4c27444529d206bb6b373f531a04f59c0025d5d78823f70e6231fac112367801"
}

rule MalwareBazaar_EasyShell_067_71f3c7a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71f3c7a370b91849836a7b7ed0a7f2be125e161ff58d9d22e339ffc9eba0fab8"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-71f3c7a370b91849.bin"
    file_type = "macho"
    first_seen = "2026-11-24 09:05:49"
  condition:
    hash.sha256(0, filesize) == "71f3c7a370b91849836a7b7ed0a7f2be125e161ff58d9d22e339ffc9eba0fab8"
}

rule MalwareBazaar_EasyShell_068_bcd19371
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcd193715c8354e64e938c3c3f35200ce7c5299c94cf5d7eaa6090dc16ecbabe"
    family = "EasyShell"
    file_name = "easyshell-a64-bcd193715c8354e6.bin"
    file_type = "elf"
    first_seen = "2026-11-24 09:05:37"
  condition:
    hash.sha256(0, filesize) == "bcd193715c8354e64e938c3c3f35200ce7c5299c94cf5d7eaa6090dc16ecbabe"
}

rule MalwareBazaar_EasyShell_069_e813a271
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e813a271b68c3afa8654e2704282a079eb2de96a32dc1fd5d08d14daf764caec"
    family = "EasyShell"
    file_name = "easyshell-a32-e813a271b68c3afa.bin"
    file_type = "elf"
    first_seen = "2026-11-24 09:05:29"
  condition:
    hash.sha256(0, filesize) == "e813a271b68c3afa8654e2704282a079eb2de96a32dc1fd5d08d14daf764caec"
}

rule MalwareBazaar_DarkCoreRAT_070_57f957cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57f957cda33dc5cb52307d173607633615c27c97a5f469f60fa6837cd140b7d4"
    family = "DarkCoreRAT"
    file_name = "Cheque's.JS"
    file_type = "js"
    first_seen = "2026-11-24 09:04:35"
  condition:
    hash.sha256(0, filesize) == "57f957cda33dc5cb52307d173607633615c27c97a5f469f60fa6837cd140b7d4"
}

rule MalwareBazaar_DarkCoreRAT_071_bc956c27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc956c2793ca1cc874d8c5eaaffefde74aba692b53c808b7ca9d61d635dd34e8"
    family = "DarkCoreRAT"
    file_name = "Request for Quotation..JS"
    file_type = "js"
    first_seen = "2026-11-24 09:04:26"
  condition:
    hash.sha256(0, filesize) == "bc956c2793ca1cc874d8c5eaaffefde74aba692b53c808b7ca9d61d635dd34e8"
}

rule MalwareBazaar_PureLogsStealer_072_8b1d7e1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b1d7e1ca7dad1a68d23db0540508e70445cdec09165631c5035fd5aebcee7d9"
    family = "PureLogsStealer"
    file_name = "78de2e25277ab8885ef8ebdf9ea477c4.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:04:23"
  condition:
    hash.sha256(0, filesize) == "8b1d7e1ca7dad1a68d23db0540508e70445cdec09165631c5035fd5aebcee7d9"
}

rule MalwareBazaar_Vidar_073_3807511b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3807511b4d501263d5e49f55f5dd5aad519b370c5962014588b8781452f6e0ca"
    family = "Vidar"
    file_name = "31903a7995c12fe0255ff5eabc9e971c.exe"
    file_type = "exe"
    first_seen = "2026-11-24 09:04:20"
  condition:
    hash.sha256(0, filesize) == "3807511b4d501263d5e49f55f5dd5aad519b370c5962014588b8781452f6e0ca"
}

rule MalwareBazaar_unknown_074_4d77a20b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d77a20b9ee1596be3e61cae6d552a1fe8fce5864437b69e697d7630e203de01"
    family = "unknown"
    file_name = "4d77a20b9ee1596be3e61cae6d552a1fe8fce5864437b69e697d7630e203de01"
    file_type = "exe"
    first_seen = "2026-11-24 09:01:01"
  condition:
    hash.sha256(0, filesize) == "4d77a20b9ee1596be3e61cae6d552a1fe8fce5864437b69e697d7630e203de01"
}

rule MalwareBazaar_njrat_075_f3174064
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f31740641da982b932e6547c4787c9816e39c94b2a4571ecd9521f6de12f8b3e"
    family = "njrat"
    file_name = "45eac95fdd4f9c019caec4332c802807.exe"
    file_type = "exe"
    first_seen = "2026-11-24 08:50:07"
  condition:
    hash.sha256(0, filesize) == "f31740641da982b932e6547c4787c9816e39c94b2a4571ecd9521f6de12f8b3e"
}

rule MalwareBazaar_unknown_076_ba3c37da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba3c37dab3a316c0f036fe72d463568cdec8917067e4aa846cbb804a2d633e09"
    family = "unknown"
    file_name = "543e35f4a58b7c8c12b0b5f4e40f4fdf.exe"
    file_type = "exe"
    first_seen = "2026-11-24 08:40:32"
  condition:
    hash.sha256(0, filesize) == "ba3c37dab3a316c0f036fe72d463568cdec8917067e4aa846cbb804a2d633e09"
}

rule MalwareBazaar_PureLogsStealer_077_60c49f80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60c49f80313bf0d82f448270e3e0c2a205ea221ed291dc98b73e740896a1b949"
    family = "PureLogsStealer"
    file_name = "FINAL INV - TELEX FEE.pdf"
    file_type = "exe"
    first_seen = "2026-11-24 08:40:20"
  condition:
    hash.sha256(0, filesize) == "60c49f80313bf0d82f448270e3e0c2a205ea221ed291dc98b73e740896a1b949"
}

rule MalwareBazaar_PureLogsStealer_078_f876ff86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f876ff86a490ee6e6ed495262af9ce7ddbadb7d2f229dcedb866ce9e4c0b043c"
    family = "PureLogsStealer"
    file_name = "Request for Quotation (RFQ) 󈦝 (2).js"
    file_type = "js"
    first_seen = "2026-11-24 08:40:14"
  condition:
    hash.sha256(0, filesize) == "f876ff86a490ee6e6ed495262af9ce7ddbadb7d2f229dcedb866ce9e4c0b043c"
}

rule MalwareBazaar_unknown_079_89d213c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89d213c5684a99c768faeb461c848bfffa3b61c7b8b225f22198ba7cd6d19e4c"
    family = "unknown"
    file_name = "a04b62ea07658d93417ddefa137c78f9.exe"
    file_type = "exe"
    first_seen = "2026-11-24 08:40:08"
  condition:
    hash.sha256(0, filesize) == "89d213c5684a99c768faeb461c848bfffa3b61c7b8b225f22198ba7cd6d19e4c"
}

rule MalwareBazaar_EasyShell_080_40ca657d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ca657db1c767a075742575ed53fdb35b836b5cb91a1b98be48b98a5e77f00a"
    family = "EasyShell"
    file_name = "easyshell-a32-40ca657db1c767a0.bin"
    file_type = "elf"
    first_seen = "2026-11-24 08:35:14"
  condition:
    hash.sha256(0, filesize) == "40ca657db1c767a075742575ed53fdb35b836b5cb91a1b98be48b98a5e77f00a"
}

rule MalwareBazaar_RemcosRAT_081_9f233ad7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f233ad78da2079a0de31cd5a08e37d861a10e145d17b6ad1572226e25af2b06"
    family = "RemcosRAT"
    file_name = "greattimefor.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:32:10"
  condition:
    hash.sha256(0, filesize) == "9f233ad78da2079a0de31cd5a08e37d861a10e145d17b6ad1572226e25af2b06"
}

rule MalwareBazaar_RemcosRAT_082_5aea893c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5aea893c52a41e29dbf4e9549170b1d35ab969c99a93f493d8da3506de9c0733"
    family = "RemcosRAT"
    file_name = "CNNupdate.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:32:08"
  condition:
    hash.sha256(0, filesize) == "5aea893c52a41e29dbf4e9549170b1d35ab969c99a93f493d8da3506de9c0733"
}

rule MalwareBazaar_Formbook_083_8924805e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8924805e933bee83f5097275f742685443f09cf23ee2f6fb4474d1c4610ad1d7"
    family = "Formbook"
    file_name = "cloudsoon.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:32:06"
  condition:
    hash.sha256(0, filesize) == "8924805e933bee83f5097275f742685443f09cf23ee2f6fb4474d1c4610ad1d7"
}

rule MalwareBazaar_RemcosRAT_084_211e6199
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "211e6199925a0cc1d3457dcbb5fcf0ac330366990777d3b7d0ca210b86973d5c"
    family = "RemcosRAT"
    file_name = "goodkings.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:31:07"
  condition:
    hash.sha256(0, filesize) == "211e6199925a0cc1d3457dcbb5fcf0ac330366990777d3b7d0ca210b86973d5c"
}

rule MalwareBazaar_RemcosRAT_085_d9b7d897
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9b7d897e7deab7cd9a2ba49908888181f79451372622371bbcb6b127411c089"
    family = "RemcosRAT"
    file_name = "greathrome.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:31:04"
  condition:
    hash.sha256(0, filesize) == "d9b7d897e7deab7cd9a2ba49908888181f79451372622371bbcb6b127411c089"
}

rule MalwareBazaar_Formbook_086_99abd64e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99abd64e2424536741538724eaca9088273c42755dc8840008c52a86cbf6bdf1"
    family = "Formbook"
    file_name = "cleanthepciture.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:30:08"
  condition:
    hash.sha256(0, filesize) == "99abd64e2424536741538724eaca9088273c42755dc8840008c52a86cbf6bdf1"
}

rule MalwareBazaar_RemcosRAT_087_192d4159
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "192d4159f5d72a8cf0c3ceb415f14775c18af1282af084df2472b60032752430"
    family = "RemcosRAT"
    file_name = "updated.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:29:08"
  condition:
    hash.sha256(0, filesize) == "192d4159f5d72a8cf0c3ceb415f14775c18af1282af084df2472b60032752430"
}

rule MalwareBazaar_RemcosRAT_088_87d94184
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87d941841e4de71f079ffe798bd6e5e9bfb2ab1574e0557001a6cf6d905e7e29"
    family = "RemcosRAT"
    file_name = "workonfixed.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:29:05"
  condition:
    hash.sha256(0, filesize) == "87d941841e4de71f079ffe798bd6e5e9bfb2ab1574e0557001a6cf6d905e7e29"
}

rule MalwareBazaar_RemcosRAT_089_40ffbc67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ffbc67720452f883bfdcadd434bd2237c5a34272cfe350d049e8a34be8fdf0"
    family = "RemcosRAT"
    file_name = "soonwillbe.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:28:06"
  condition:
    hash.sha256(0, filesize) == "40ffbc67720452f883bfdcadd434bd2237c5a34272cfe350d049e8a34be8fdf0"
}

rule MalwareBazaar_RemcosRAT_090_7c488a80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c488a802c93094cf156b83ab492a08d50e8ff8fc067056b716d21319622dfa2"
    family = "RemcosRAT"
    file_name = "CNNupdate.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:27:05"
  condition:
    hash.sha256(0, filesize) == "7c488a802c93094cf156b83ab492a08d50e8ff8fc067056b716d21319622dfa2"
}

rule MalwareBazaar_DarkCloud_091_c594fa82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c594fa82bef6210f081cbbfd3ac0b4f3e7f8f229ee15f596d84a357cec632d62"
    family = "DarkCloud"
    file_name = "Urgent Order.exe"
    file_type = "exe"
    first_seen = "2026-11-24 08:25:34"
  condition:
    hash.sha256(0, filesize) == "c594fa82bef6210f081cbbfd3ac0b4f3e7f8f229ee15f596d84a357cec632d62"
}

rule MalwareBazaar_SalatStealer_092_f82f3dda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f82f3dda93876f1cb3d9380efd32d045bb5b6593da5b7ed869f8798e489c76c3"
    family = "SalatStealer"
    file_name = "f82f3dda93876f1c.bin"
    file_type = "bat"
    first_seen = "2026-11-24 08:25:01"
  condition:
    hash.sha256(0, filesize) == "f82f3dda93876f1cb3d9380efd32d045bb5b6593da5b7ed869f8798e489c76c3"
}

rule MalwareBazaar_RemcosRAT_093_a8b44ff9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8b44ff9d650dfa4157024c8fa99a9dbc51c57cb25c56798aefa2fe6733c49eb"
    family = "RemcosRAT"
    file_name = "studyforbest.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:19:06"
  condition:
    hash.sha256(0, filesize) == "a8b44ff9d650dfa4157024c8fa99a9dbc51c57cb25c56798aefa2fe6733c49eb"
}

rule MalwareBazaar_RemcosRAT_094_3ea19eda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ea19eda84232ad534581ed5597e8b55379cee85a13e3c81bcfbe033b0e3d302"
    family = "RemcosRAT"
    file_name = "goodboss.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:16:06"
  condition:
    hash.sha256(0, filesize) == "3ea19eda84232ad534581ed5597e8b55379cee85a13e3c81bcfbe033b0e3d302"
}

rule MalwareBazaar_RemcosRAT_095_afca63cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afca63cf3aa6777889d358eff16ea481e2857f8b983a396c2266a7115b854c23"
    family = "RemcosRAT"
    file_name = "goodkings.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:15:08"
  condition:
    hash.sha256(0, filesize) == "afca63cf3aa6777889d358eff16ea481e2857f8b983a396c2266a7115b854c23"
}

rule MalwareBazaar_RemcosRAT_096_efccf7d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efccf7d45feab094c0b38c0db69c86788532a3b5f155cb2307e3d1fec62affa8"
    family = "RemcosRAT"
    file_name = "cloudfree.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:14:06"
  condition:
    hash.sha256(0, filesize) == "efccf7d45feab094c0b38c0db69c86788532a3b5f155cb2307e3d1fec62affa8"
}

rule MalwareBazaar_RemcosRAT_097_93877d0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93877d0cf89a19e113e98c6f54b2d7de6dd82e1c9700f1b98dc8cf79b4dceb8d"
    family = "RemcosRAT"
    file_name = "grg.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:12:08"
  condition:
    hash.sha256(0, filesize) == "93877d0cf89a19e113e98c6f54b2d7de6dd82e1c9700f1b98dc8cf79b4dceb8d"
}

rule MalwareBazaar_RemcosRAT_098_8eea9e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8eea9e128e3e2b599d443f49006739f8bdb92daa1a6cccf4db79babfbd0dadcf"
    family = "RemcosRAT"
    file_name = "cleaning.hta"
    file_type = "hta"
    first_seen = "2026-11-24 08:12:05"
  condition:
    hash.sha256(0, filesize) == "8eea9e128e3e2b599d443f49006739f8bdb92daa1a6cccf4db79babfbd0dadcf"
}

rule MalwareBazaar_EasyShell_099_88b016f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88b016f66c1bbc47c7515a369baf1270fd5afd73c15ee715172f34c6956c4bf8"
    family = "EasyShell"
    file_name = "easyshell-l64-88b016f66c1bbc47.bin"
    file_type = "elf"
    first_seen = "2026-11-24 08:06:14"
  condition:
    hash.sha256(0, filesize) == "88b016f66c1bbc47c7515a369baf1270fd5afd73c15ee715172f34c6956c4bf8"
}

rule MalwareBazaar_EasyShell_100_ff7bc41e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff7bc41ef3835302c0dc1e115a13076069743255287c006fb5f4febd3016b2ed"
    family = "EasyShell"
    file_name = "easyshell-l32-ff7bc41ef3835302.bin"
    file_type = "elf"
    first_seen = "2026-11-24 08:06:04"
  condition:
    hash.sha256(0, filesize) == "ff7bc41ef3835302c0dc1e115a13076069743255287c006fb5f4febd3016b2ed"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

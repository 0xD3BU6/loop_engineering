# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-14

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 661 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 661 |
| Unique family labels | 16 |
| Unique file types | 15 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 40 |
| Mirai | 17 |
| RemusStealer | 8 |
| Vidar | 6 |
| AgentTesla | 6 |
| RemcosRAT | 4 |
| DarkTortilla | 3 |
| Stealc | 3 |
| Efimer | 3 |
| AsyncRAT | 2 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 35 |
| elf | 29 |
| sh | 10 |
| hta | 7 |
| 7z | 3 |
| zip | 3 |
| vbs | 2 |
| js | 2 |
| tar | 2 |
| lnk | 2 |

## Per-Sample Analysis

### Sample 1: `708bebf7661a2646`

| Field | Value |
|---|---|
| SHA-256 | `708bebf7661a2646921dea4f826e4d6a2a5a35087c72c0e00bd2cd0c9b894316` |
| Family label | `unknown` |
| File name | `708bebf7661a2646921dea4f826e4d6a2a5a35087c72c0e00bd2cd0c9b894316` |
| File type | `sh` |
| First seen | `2026-07-14 03:30:11` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88baea9de0c8539fce1d3e117ed5665b` |
| SHA-1 | `99dd7ed1925461448de4a94f6569966803334a52` |
| SHA-256 | `708bebf7661a2646921dea4f826e4d6a2a5a35087c72c0e00bd2cd0c9b894316` |
| SHA3-384 | `cf7253317ca9287efd0efa182075eeca2d9717d17c83bce1166bbcd17841eb4251c43ebff7198b229c6f0e588f699663` |
| TLSH | `T13C118CC404644AEEEE838E40F77741C8CA4D41E7FD83BA5AD559049AE55CA28F2DE6C8` |
| SSDEEP | `12:MC20Wg0W2zWDNWOWKW4oWQW7WDfKTWeNIymWAAa:H2/g/BDkRd4Tb6zKyeNIUu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_708bebf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "708bebf7661a2646921dea4f826e4d6a2a5a35087c72c0e00bd2cd0c9b894316"
    family = "unknown"
    file_name = "708bebf7661a2646921dea4f826e4d6a2a5a35087c72c0e00bd2cd0c9b894316"
    file_type = "sh"
    first_seen = "2026-07-14 03:30:11"
  condition:
    hash.sha256(0, filesize) == "708bebf7661a2646921dea4f826e4d6a2a5a35087c72c0e00bd2cd0c9b894316"
}
```

### Sample 2: `249d3ed7abfde117`

| Field | Value |
|---|---|
| SHA-256 | `249d3ed7abfde1173249b693c7f64b7c7c6b6dffb11277e205bccff88447feae` |
| Family label | `unknown` |
| File name | `249d3ed7abfde1173249b693c7f64b7c7c6b6dffb11277e205bccff88447feae` |
| File type | `sh` |
| First seen | `2026-07-14 03:30:09` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2dc0768b02714eaa0e1050772cb8bbe3` |
| SHA-1 | `85ff2c293c1dbac90159712420a4ee410358f12e` |
| SHA-256 | `249d3ed7abfde1173249b693c7f64b7c7c6b6dffb11277e205bccff88447feae` |
| SHA3-384 | `52232b82f9921cab91b6811c4005d9f0a5349b4bb485529b44b246b0c624bad335333d1c20983e1643818cf9c0e26845` |
| TLSH | `T1AB115B84056449DEEE138E44F76740C8DA4942E7FD83BA2AE5A1056AE45CA38F6DE6C0` |
| SSDEEP | `12:MCQe3W7W2xrWDLWUW1iW47iWOW5WDfKMiWeNIycWAAa:HBG6PDqf114ZRAzKIeNIau` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_249d3ed7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "249d3ed7abfde1173249b693c7f64b7c7c6b6dffb11277e205bccff88447feae"
    family = "unknown"
    file_name = "249d3ed7abfde1173249b693c7f64b7c7c6b6dffb11277e205bccff88447feae"
    file_type = "sh"
    first_seen = "2026-07-14 03:30:09"
  condition:
    hash.sha256(0, filesize) == "249d3ed7abfde1173249b693c7f64b7c7c6b6dffb11277e205bccff88447feae"
}
```

### Sample 3: `56e7837e2855d749`

| Field | Value |
|---|---|
| SHA-256 | `56e7837e2855d749d9848d20ffb2e682f2288b7f10156597abd2fdee543e79c6` |
| Family label | `unknown` |
| File name | `RFQ.vbs` |
| File type | `vbs` |
| First seen | `2026-07-14 03:29:03` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ad46a612d77078adb84e4c3b59113b8` |
| SHA-1 | `b02c41d732c05efc3c1b48b59bc0c23c3e586908` |
| SHA-256 | `56e7837e2855d749d9848d20ffb2e682f2288b7f10156597abd2fdee543e79c6` |
| SHA3-384 | `3f9cf927a6ebb20005703cb01e415dd001014b8f36939a8930bc5e80c678b821e5a8a00e031b1ed6a4bf0af0eff4d24e` |
| TLSH | `T152B229A27F9409578D8F21A7993C4F6AC9149995C8713CA8BCBDFB0DE844B1C36AC41E` |
| SSDEEP | `768:fW6bdxnzBW/LwLaYxCqer6s5/cSCkibE0+6yqvWmhxMjF0MiNi+08J:j5wH5r3/cSab1dyqvWIOjG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_56e7837e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56e7837e2855d749d9848d20ffb2e682f2288b7f10156597abd2fdee543e79c6"
    family = "unknown"
    file_name = "RFQ.vbs"
    file_type = "vbs"
    first_seen = "2026-07-14 03:29:03"
  condition:
    hash.sha256(0, filesize) == "56e7837e2855d749d9848d20ffb2e682f2288b7f10156597abd2fdee543e79c6"
}
```

### Sample 4: `6773709e7c85e57a`

| Field | Value |
|---|---|
| SHA-256 | `6773709e7c85e57a2ed16ac1f162b02bb35a7c516927b99d483c72dfbf88664a` |
| Family label | `AsyncRAT` |
| File name | `NEW88APP.exe` |
| File type | `exe` |
| First seen | `2026-07-14 03:17:32` |
| Reporter | `anonymous` |
| Tags | `AsyncRAT, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00ac5aa32e0cb96c1f2034deb5604094` |
| SHA-1 | `765b077c6c0bb51c987af9644d31cfcbae93d36b` |
| SHA-256 | `6773709e7c85e57a2ed16ac1f162b02bb35a7c516927b99d483c72dfbf88664a` |
| SHA3-384 | `56762d68507b6bd03486593d4c2a506f5a498188e747c5ffea9373a609c2c952c7450828388b217e2afe44c6e0f5245c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D2C22B0833E4C576D2FD4ABE8C33E6008B75A55B9913D75A6FC490AD29237CD8A14FE4` |
| SSDEEP | `384:cgSVEEMiNPWmvHtZARPn9jaH9qbuUs/bQxnCJfJBndnjJ6Kb6:cgSVXFdt+kIb7BiBnLW` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_004_6773709e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6773709e7c85e57a2ed16ac1f162b02bb35a7c516927b99d483c72dfbf88664a"
    family = "AsyncRAT"
    file_name = "NEW88APP.exe"
    file_type = "exe"
    first_seen = "2026-07-14 03:17:32"
  condition:
    hash.sha256(0, filesize) == "6773709e7c85e57a2ed16ac1f162b02bb35a7c516927b99d483c72dfbf88664a"
}
```

### Sample 5: `3bce373a6a8b4a35`

| Field | Value |
|---|---|
| SHA-256 | `3bce373a6a8b4a35e50d54469fe16ad229267578960589bdc6951195b6de98fb` |
| Family label | `DarkTortilla` |
| File name | `PURCHASE_ORDER_202606001.exe` |
| File type | `exe` |
| First seen | `2026-07-14 03:16:25` |
| Reporter | `threatcat_ch` |
| Tags | `DarkTortilla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34c3f92bf36ced3543c545065cfe6095` |
| SHA-1 | `c72b9041cad9d401989976bee11a8a08b99153e8` |
| SHA-256 | `3bce373a6a8b4a35e50d54469fe16ad229267578960589bdc6951195b6de98fb` |
| SHA3-384 | `a76bb25d3ad5dd610169e502812dc5a520b4d6618b1a64c746373ac435d1d85e647107127d340a23c0dc9eecad02b412` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A745E1259D466635CA3C0A74C0D6749C13F0FEF79296E71A2EE831ECDB727A4A9D3081` |
| SSDEEP | `12288:GfG5ANoT2CPpHAP/iGc1ZOM+FhWF2hekxpp4yh8G1R12Vg5CkCThajRtvA2pV:GuZ2UxAPqGcv/+Duyx4O0kYa9tvlp` |
| ICON-DHASH | `926d69b2696dd628` |

#### Technical Assessment

- The sample is tracked as `DarkTortilla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkTortilla_005_3bce373a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bce373a6a8b4a35e50d54469fe16ad229267578960589bdc6951195b6de98fb"
    family = "DarkTortilla"
    file_name = "PURCHASE_ORDER_202606001.exe"
    file_type = "exe"
    first_seen = "2026-07-14 03:16:25"
  condition:
    hash.sha256(0, filesize) == "3bce373a6a8b4a35e50d54469fe16ad229267578960589bdc6951195b6de98fb"
}
```

### Sample 6: `7f1c566eee880bce`

| Field | Value |
|---|---|
| SHA-256 | `7f1c566eee880bce9a3f80880badee548b53ab3aded225c654faeff9cf0349df` |
| Family label | `DarkTortilla` |
| File name | `HSBC_BANK_CONFIRMATION_SWIFT_MT103.exe` |
| File type | `exe` |
| First seen | `2026-07-14 03:16:01` |
| Reporter | `threatcat_ch` |
| Tags | `DarkTortilla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df8e26f66145f175ecff2cef4ee76b01` |
| SHA-1 | `18d4c8b9aa9034fa358fb580713a5a7534176110` |
| SHA-256 | `7f1c566eee880bce9a3f80880badee548b53ab3aded225c654faeff9cf0349df` |
| SHA3-384 | `15313bba3f8e855aa6b5b8ed93a9eccbc8302ff544460cddeaa69699daf7c95d8e12011c8e63af74539b802e704af73d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13D45F12549461635CA3D0A75C1D974A813F0FEF39266E71A2EE830FDCBB3794A9D7082` |
| SSDEEP | `12288:yF6htfT2CPpHAP/iGc1ZOM+FhWF2hekxpp4yy8G1R12Vg5CaCThajRlbrjV:f2UxAPqGcv/+Duyx4N0aYa95` |
| ICON-DHASH | `926d69b2696dd628` |

#### Technical Assessment

- The sample is tracked as `DarkTortilla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkTortilla_006_7f1c566e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f1c566eee880bce9a3f80880badee548b53ab3aded225c654faeff9cf0349df"
    family = "DarkTortilla"
    file_name = "HSBC_BANK_CONFIRMATION_SWIFT_MT103.exe"
    file_type = "exe"
    first_seen = "2026-07-14 03:16:01"
  condition:
    hash.sha256(0, filesize) == "7f1c566eee880bce9a3f80880badee548b53ab3aded225c654faeff9cf0349df"
}
```

### Sample 7: `0e4e0247476003c3`

| Field | Value |
|---|---|
| SHA-256 | `0e4e0247476003c3efef81eba6fdc6c98876d15ae4fd81994a2a58c598c2011d` |
| Family label | `DarkTortilla` |
| File name | `MV.CORNELIA.M_VESSEL_INFORMATION.exe` |
| File type | `exe` |
| First seen | `2026-07-14 03:15:44` |
| Reporter | `threatcat_ch` |
| Tags | `DarkTortilla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d245eadb186f026bc1bc70fd0e2273ac` |
| SHA-1 | `c3c5f2b383a4b4a6ee335a3b5bb9de182cb3cc82` |
| SHA-256 | `0e4e0247476003c3efef81eba6fdc6c98876d15ae4fd81994a2a58c598c2011d` |
| SHA3-384 | `c7ac55c7e4b56f3925c9b62d767e7ff9c86d32cd20b510ab253f5cb7f2b6b5c87c9008f6d044b070f7352c933fc1f5b9` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14F45E12549466536DB3D0A74C2D6749C13F0FDF39292E71A2EE870FCDB727A4A9D2082` |
| SSDEEP | `12288:qi2amT2CPpHAP/iGc1ZOM+FhWF2hekxpp4y98G1R12Vg5CkCThajRxBV:G/2UxAPqGcv/+Duyx4K0kYa9xB` |
| ICON-DHASH | `926d69b2696dd628` |

#### Technical Assessment

- The sample is tracked as `DarkTortilla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkTortilla_007_0e4e0247
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e4e0247476003c3efef81eba6fdc6c98876d15ae4fd81994a2a58c598c2011d"
    family = "DarkTortilla"
    file_name = "MV.CORNELIA.M_VESSEL_INFORMATION.exe"
    file_type = "exe"
    first_seen = "2026-07-14 03:15:44"
  condition:
    hash.sha256(0, filesize) == "0e4e0247476003c3efef81eba6fdc6c98876d15ae4fd81994a2a58c598c2011d"
}
```

### Sample 8: `a6ec0a5f8122e29d`

| Field | Value |
|---|---|
| SHA-256 | `a6ec0a5f8122e29d1e951b907f673da4b481ab5f4a368c5c171433640d53a3a0` |
| Family label | `AsyncRAT` |
| File name | `F8BETAPP.exe` |
| File type | `exe` |
| First seen | `2026-07-14 03:04:26` |
| Reporter | `anonymous` |
| Tags | `AsyncRAT, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a95f70e998254f132b5270c74183bf6` |
| SHA-1 | `7f645193d7060e8636e9ef740aceaf914d9717ec` |
| SHA-256 | `a6ec0a5f8122e29d1e951b907f673da4b481ab5f4a368c5c171433640d53a3a0` |
| SHA3-384 | `957df191a49b45fa35cb88a78cd303e8c28cdca746f1c734493c7369140ccc875dd846e0fcb47a4b2cdc41838347a09c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T167C22B0837E4C571E2FD4ABA8833D6008B75E55B9913D76A6FC890AD2E237CD8A14FD4` |
| SSDEEP | `384:yN3SaTSXW9bVWw7HtZARPn9jnH9qbuUsMbQxnCJfJBndnjJ6JKci+:yN3SaT5Lt+zIbIBiBnLci+` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_008_a6ec0a5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6ec0a5f8122e29d1e951b907f673da4b481ab5f4a368c5c171433640d53a3a0"
    family = "AsyncRAT"
    file_name = "F8BETAPP.exe"
    file_type = "exe"
    first_seen = "2026-07-14 03:04:26"
  condition:
    hash.sha256(0, filesize) == "a6ec0a5f8122e29d1e951b907f673da4b481ab5f4a368c5c171433640d53a3a0"
}
```

### Sample 9: `fe33733d353438f4`

| Field | Value |
|---|---|
| SHA-256 | `fe33733d353438f4edcf5baf73b602a3a668cc5a948e4a685b13d5d4bfc16b12` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 02:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e097be87d39d5673afd233fbb535d768` |
| SHA-1 | `4920e8b0a9e9975aa3f032dc234937b053738114` |
| SHA-256 | `fe33733d353438f4edcf5baf73b602a3a668cc5a948e4a685b13d5d4bfc16b12` |
| SHA3-384 | `1af79300e88a2bf4188f4f97571655f6eb6c50d626a888605f28da9d26397850c82dfc9115ca6a931ea67ce80ad0a522` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D9E63359A9E000FFC8B3847DE9E15695E5B1B4BA47B2C9CB5A34C2763D032E1493A733` |
| SSDEEP | `393216:GgtTYVvhwkt1E7PnFgaLmohSkZm9XMCHWUjXicuI3/PGTAI:GgiVv7t1YPnJKoG9XMb8XfH/O7` |
| ICON-DHASH | `18dcf8f8fcf8e040` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_fe33733d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe33733d353438f4edcf5baf73b602a3a668cc5a948e4a685b13d5d4bfc16b12"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 02:52:09"
  condition:
    hash.sha256(0, filesize) == "fe33733d353438f4edcf5baf73b602a3a668cc5a948e4a685b13d5d4bfc16b12"
}
```

### Sample 10: `fc397bf8ddae5d01`

| Field | Value |
|---|---|
| SHA-256 | `fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de` |
| Family label | `unknown` |
| File name | `app_setup.6653002.msi` |
| File type | `msi` |
| First seen | `2026-07-14 02:18:12` |
| Reporter | `CNGaoLing` |
| Tags | `msi, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07c01de3b6ff6532cf58f7cab029d26f` |
| SHA-1 | `611b5f4ac204e4ea14b8d9d32727fb49d418726d` |
| SHA-256 | `fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de` |
| SHA3-384 | `4898d6b53c440dd088f949e854de43495e45327e4b6c11b3c636aaa64f29bd39b1f665c84fb0af469e5e7475a546cb6d` |
| TLSH | `T1ED6633D178C529B1E083DB785822767EB1393FC37FAB4D053AA97A145EB331221B5386` |
| SSDEEP | `98304:pB6B0TitPiEW/IaMIpMDH2SGck+LfdKYyrKqN6qinuy8wTTUw2sRxVlFtRx+TNjW:pB6fPq0iA++LOrK+6243RxRtRsx6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_fc397bf8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de"
    family = "unknown"
    file_name = "app_setup.6653002.msi"
    file_type = "msi"
    first_seen = "2026-07-14 02:18:12"
  condition:
    hash.sha256(0, filesize) == "fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de"
}
```

### Sample 11: `f13cb360768363d3`

| Field | Value |
|---|---|
| SHA-256 | `f13cb360768363d3424e2192c7805b8c8015eb8706dbbbcdead6aed8cf390109` |
| Family label | `unknown` |
| File name | `kworkerd-rcu` |
| File type | `elf` |
| First seen | `2026-07-14 02:17:04` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `531dca50d5fd9c6f6ba3e5d7aaf42a2c` |
| SHA-1 | `4c7b271348d729f72f776d9b6284d1b32f01b17e` |
| SHA-256 | `f13cb360768363d3424e2192c7805b8c8015eb8706dbbbcdead6aed8cf390109` |
| SHA3-384 | `ab1350ae1c085c79ed2ea1284eae1a27b1ebe53ac05cab97118dc7264577fdec293f453b00691180e716637ad22e3762` |
| TLSH | `T1D8A4231594079D8BFC19FCF90D7B01351E887E0F29D7A2A48024FD7E36BE9A64CD2A58` |
| SSDEEP | `12288:CcGbDx0EgHJ25HHUUZvRF14Tfr20lbsaJbah:5CD6HJmUU5HaTfr7sob` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_f13cb360
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f13cb360768363d3424e2192c7805b8c8015eb8706dbbbcdead6aed8cf390109"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-07-14 02:17:04"
  condition:
    hash.sha256(0, filesize) == "f13cb360768363d3424e2192c7805b8c8015eb8706dbbbcdead6aed8cf390109"
}
```

### Sample 12: `3e4c1ea078d58322`

| Field | Value |
|---|---|
| SHA-256 | `3e4c1ea078d583222246945d10b5c14d4a3f23348c1f03596652def4e71f88a7` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 01:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `349d379be2d0acb13076bf1822cfe0bd` |
| SHA-1 | `3b656f12223e98a6fcaa095d5e568fe64544a673` |
| SHA-256 | `3e4c1ea078d583222246945d10b5c14d4a3f23348c1f03596652def4e71f88a7` |
| SHA3-384 | `96ee315fb11eae3a66b15a6b1c87a693255c06bc2707e025f96ff3fc82c9be8e36ec1dd925cb834d463ef75bc17d0793` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T117E6330999E116EEE9B3513DEFE207A1E085B4B053B1C89F8E58A362BE471D04D7C727` |
| SSDEEP | `393216:bX7+WGeQ7uCD08NWprTQ0xXMCHWUjXkcuI3/PGTAI:r7fGeQqkBWpndxXMb8XxH/O7` |
| ICON-DHASH | `71f0d4d8c8ec7055` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_3e4c1ea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e4c1ea078d583222246945d10b5c14d4a3f23348c1f03596652def4e71f88a7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 01:52:10"
  condition:
    hash.sha256(0, filesize) == "3e4c1ea078d583222246945d10b5c14d4a3f23348c1f03596652def4e71f88a7"
}
```

### Sample 13: `5f1b3de37a17a72b`

| Field | Value |
|---|---|
| SHA-256 | `5f1b3de37a17a72b53cdfa6051205d37d351b050be7500306ed65772557e6fb0` |
| Family label | `unknown` |
| File name | `5f1b3de37a17a72b53cdfa6051205d37d351b050be7500306ed65772557e6fb0` |
| File type | `unknown` |
| First seen | `2026-07-14 01:30:14` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f9fb3eafc86bd59ea7b11c73f4d835d` |
| SHA-256 | `5f1b3de37a17a72b53cdfa6051205d37d351b050be7500306ed65772557e6fb0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_5f1b3de3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f1b3de37a17a72b53cdfa6051205d37d351b050be7500306ed65772557e6fb0"
    family = "unknown"
    file_name = "5f1b3de37a17a72b53cdfa6051205d37d351b050be7500306ed65772557e6fb0"
    file_type = "unknown"
    first_seen = "2026-07-14 01:30:14"
  condition:
    hash.sha256(0, filesize) == "5f1b3de37a17a72b53cdfa6051205d37d351b050be7500306ed65772557e6fb0"
}
```

### Sample 14: `b59d2b3abdd4ddba`

| Field | Value |
|---|---|
| SHA-256 | `b59d2b3abdd4ddba0f35d200324f1fd55998b76f55e1692c66829b5d49808534` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-14 01:21:41` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX5.file, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `124dd264fb05821fcbbcaba2b4b30a0e` |
| SHA-1 | `873c12124d7d95bd232aa3493b84bcc2a87c49d2` |
| SHA-256 | `b59d2b3abdd4ddba0f35d200324f1fd55998b76f55e1692c66829b5d49808534` |
| SHA3-384 | `ba49fe6aa45512a99b65707e5d21426c27054f421d27b79954f2a6d89e390c6e98862b1cb387e7102566d38b8c520c0a` |
| IMPHASH | `646167cce332c1c252cdcb1839e0cf48` |
| TLSH | `T14F953302AEECC4A1CEA096B54CF86467137A3D918EF959873384BDDE3C392D495B0397` |
| SSDEEP | `49152:5vc+/gQBs5fLQpWrs5Ud3bNRYkCwkGRLJa2Qc:By2Wrs5Ud3bEwdL3Qc` |
| ICON-DHASH | `4310d0403038364a` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_014_b59d2b3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b59d2b3abdd4ddba0f35d200324f1fd55998b76f55e1692c66829b5d49808534"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-14 01:21:41"
  condition:
    hash.sha256(0, filesize) == "b59d2b3abdd4ddba0f35d200324f1fd55998b76f55e1692c66829b5d49808534"
}
```

### Sample 15: `343309939613a1aa`

| Field | Value |
|---|---|
| SHA-256 | `343309939613a1aaaf46375d390e26ba60a91e6026ec2de237fd1e19a2bd267f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-14 01:20:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c864ae8a8327f64eb43edfb897839077` |
| SHA-1 | `425bc3b429bc70b9574d53d2ea5f6d2600b8e727` |
| SHA-256 | `343309939613a1aaaf46375d390e26ba60a91e6026ec2de237fd1e19a2bd267f` |
| SHA3-384 | `a79aa5fc91e9271419cf1e96e2fae97345dc6d5e06860ca779bbfee2c51271b0b7163e5feeb7f97888024d94713da384` |
| TLSH | `T190236D6516857C24AA98D4371D7E2F0CBDAD43E6320492EE7FCB3CF28C5AA9D910871D` |
| SSDEEP | `768:HXRWNGxV89GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Blxncr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_34330993
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "343309939613a1aaaf46375d390e26ba60a91e6026ec2de237fd1e19a2bd267f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-14 01:20:07"
  condition:
    hash.sha256(0, filesize) == "343309939613a1aaaf46375d390e26ba60a91e6026ec2de237fd1e19a2bd267f"
}
```

### Sample 16: `5aa92ab04d89876d`

| Field | Value |
|---|---|
| SHA-256 | `5aa92ab04d89876d4cbf86d39bf1858bb7ff77c8acc40301965309387f09eb88` |
| Family label | `unknown` |
| File name | `kworkerd-netns-rt` |
| File type | `elf` |
| First seen | `2026-07-14 01:06:09` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51087b22397006bce91c8b32f1fd2c13` |
| SHA-1 | `a7333b545833e2be5990fb5d3211819c00c7bfc2` |
| SHA-256 | `5aa92ab04d89876d4cbf86d39bf1858bb7ff77c8acc40301965309387f09eb88` |
| SHA3-384 | `723a30a996f9c1502edb9b41d25347a8585c87103c715d7fa7788439a77bf55d34d8c39f92c7fc0c8b0afd821b6d0341` |
| TLSH | `T12094221E6233C99AD344A57F4973C0192FBDAA053AA2F218F479DC403F1C2ED9694BD8` |
| TELFHASH | `t192d00224587813b052cd8c6e55dceb08a860a5e7aaa31d1fdd94c899ea26e4b9d01d2c` |
| SSDEEP | `6144:6cCEm/L4tRN7icJHR/KBYwWHRZLXRWGeNfhoBPvH07QOgY9yl8khlTwZJlqnECga:6nEm/cl7ic3/9r7RWyRH0TvkIDlqfN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_5aa92ab0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5aa92ab04d89876d4cbf86d39bf1858bb7ff77c8acc40301965309387f09eb88"
    family = "unknown"
    file_name = "kworkerd-netns-rt"
    file_type = "elf"
    first_seen = "2026-07-14 01:06:09"
  condition:
    hash.sha256(0, filesize) == "5aa92ab04d89876d4cbf86d39bf1858bb7ff77c8acc40301965309387f09eb88"
}
```

### Sample 17: `8c4cac17d41571cc`

| Field | Value |
|---|---|
| SHA-256 | `8c4cac17d41571cc262de43846310440f0d0e31bd3dfa6e5c9df00bcbd5b323e` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-14 00:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7849b8d963c64b913d89f8d512559119` |
| SHA-1 | `b67922864eb02abffbb792e59749553b4ba80df3` |
| SHA-256 | `8c4cac17d41571cc262de43846310440f0d0e31bd3dfa6e5c9df00bcbd5b323e` |
| SHA3-384 | `ebfb39c0df9cb55410bccb75a3231eb89b712606ce1a0b1cbebae59c55f2f525fcf3f7b56706f01858bf0631e7de20a9` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T168E6335CE5E022FFE6639138E9F242D4E598B4760BB3D5DB479493B27E172E0093C622` |
| SSDEEP | `393216:dnoTR43c2YufRJOX9NXMCHWUjX8cuI3/PGTAI:dod2c18AHXMb8XpH/O7` |
| ICON-DHASH | `70f0f0f8f8f0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_8c4cac17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c4cac17d41571cc262de43846310440f0d0e31bd3dfa6e5c9df00bcbd5b323e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 00:52:11"
  condition:
    hash.sha256(0, filesize) == "8c4cac17d41571cc262de43846310440f0d0e31bd3dfa6e5c9df00bcbd5b323e"
}
```

### Sample 18: `9b9999e19c8c0aab`

| Field | Value |
|---|---|
| SHA-256 | `9b9999e19c8c0aab1ee141dc985454251f602e388f55f323eb1d17083cd8098e` |
| Family label | `Mirai` |
| File name | `bot_x86_64` |
| File type | `elf` |
| First seen | `2026-07-14 00:46:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72b1e7c2846860a4dc684e8b8062aea1` |
| SHA-1 | `dee1645e7f95a397113531c9915de0d93268fc01` |
| SHA-256 | `9b9999e19c8c0aab1ee141dc985454251f602e388f55f323eb1d17083cd8098e` |
| SHA3-384 | `13b00ae1c0a9741a19d93ef8fdee3e060e771501ce18c0c7c930bbc435a4bd780f7d30019212d20bf029afb7c2d2939c` |
| TLSH | `T1B9456B57B2F364FDC053C430879BDAA2A931B42546226E7F66C4CB302F66E741B1DB62` |
| TELFHASH | `t1ac2141e7543da4a04adeac80e59b2724e10ff19458b10a23fca0c65c72fe61f49674eb` |
| SSDEEP | `24576:Iy7ZDK4ktU8MwKBn9ExlWhGVfwXMS+KguK79qvB/eH:H7BK4ktU8g1hM0MSLP09qkH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_9b9999e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b9999e19c8c0aab1ee141dc985454251f602e388f55f323eb1d17083cd8098e"
    family = "Mirai"
    file_name = "bot_x86_64"
    file_type = "elf"
    first_seen = "2026-07-14 00:46:21"
  condition:
    hash.sha256(0, filesize) == "9b9999e19c8c0aab1ee141dc985454251f602e388f55f323eb1d17083cd8098e"
}
```

### Sample 19: `99688efb61464aca`

| Field | Value |
|---|---|
| SHA-256 | `99688efb61464aca1b733c7824d247637f259bd9dae86a06969e3fe748dddc45` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-14 00:44:12` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `973a62a7624943aa89b1379b41160c3d` |
| SHA-1 | `133dc1a73a4712c3159b59a050a76cf214e24d9f` |
| SHA-256 | `99688efb61464aca1b733c7824d247637f259bd9dae86a06969e3fe748dddc45` |
| SHA3-384 | `34f575d58b3eb98472cd10b5c3b4d112c95b09de3178c4a6d70e394c616f1a317ff164a45fd69719557e6efe8d65eba8` |
| TLSH | `T1A0C27D966A867C44BEC98A3E4CBD2B0D6DF5C3D1224D52AC3D4A3C719C11FACD618B1A` |
| SSDEEP | `768:P58vCB+25j6es8R5B9FYpMSUpi+20qUpi+20YQX:P58l25J53d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_99688efb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99688efb61464aca1b733c7824d247637f259bd9dae86a06969e3fe748dddc45"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-14 00:44:12"
  condition:
    hash.sha256(0, filesize) == "99688efb61464aca1b733c7824d247637f259bd9dae86a06969e3fe748dddc45"
}
```

### Sample 20: `50bbda75075dc003`

| Field | Value |
|---|---|
| SHA-256 | `50bbda75075dc0030f4bb96ede4c874e21812dac690c2d0ed0ceb7474e967a1a` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-14 00:28:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d53656eb44d807a69b41c6c1becbe65` |
| SHA-1 | `2bab912b8c816b8099af80cdda78cb5d4c0c665f` |
| SHA-256 | `50bbda75075dc0030f4bb96ede4c874e21812dac690c2d0ed0ceb7474e967a1a` |
| SHA3-384 | `bbb3c1a020a3a0a280137ba69ef79960eb5d61346338ff1c982163f9a7bdd5abe9b33d782eb8388d9729580030bc1a3f` |
| TLSH | `T1BB849FA2A41159CFCE4089BA736C4F3563822C70C21B1FBD5E568519A28F8DFF1D6BE4` |
| SSDEEP | `6144:kFolo7L7T5Xk5B5jVF9tQy3rWVdkYGvXZX:hS7L/5XkV9t536VdavX1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_50bbda75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50bbda75075dc0030f4bb96ede4c874e21812dac690c2d0ed0ceb7474e967a1a"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-14 00:28:26"
  condition:
    hash.sha256(0, filesize) == "50bbda75075dc0030f4bb96ede4c874e21812dac690c2d0ed0ceb7474e967a1a"
}
```

### Sample 21: `ada0d9426190134f`

| Field | Value |
|---|---|
| SHA-256 | `ada0d9426190134f8a1829a16b1a001d781a5ad656042d43cff7fd082c771ba1` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-14 00:15:18` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e460df77f903c9e6c4bf24171597cfc` |
| SHA-1 | `eb6a4b330c18b80c9559baf4dc5f451226361608` |
| SHA-256 | `ada0d9426190134f8a1829a16b1a001d781a5ad656042d43cff7fd082c771ba1` |
| SHA3-384 | `28fa9a3911812db32fa4cb359e0bf425fb299e2f849801018882706cb7b1ad2fc571d6e97a08ee00b65d4842806204d6` |
| TLSH | `T1B3C312970247977ACE00B4317C0A6840E56B68BEA6AD4BA50D5153FCCC57CC7EBAD253` |
| SSDEEP | `3072:yA+E5VsLyQM95fo7eCwAPxFUq+2AwjhYSnI7empNCVP/r9/0:t+E39VoSCDEdxBCVP/Z/0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_ada0d942
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ada0d9426190134f8a1829a16b1a001d781a5ad656042d43cff7fd082c771ba1"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-14 00:15:18"
  condition:
    hash.sha256(0, filesize) == "ada0d9426190134f8a1829a16b1a001d781a5ad656042d43cff7fd082c771ba1"
}
```

### Sample 22: `e986c08a9dacb351`

| Field | Value |
|---|---|
| SHA-256 | `e986c08a9dacb351fc1da3906edaac7fffbc813ed9d31460a6d9743cda8a29fc` |
| Family label | `unknown` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-14 00:12:09` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07ab156cb87c710968fb7b0dd89c90f1` |
| SHA-1 | `fe21afd862f879e5e8fa45b0735338f2a713fc8b` |
| SHA-256 | `e986c08a9dacb351fc1da3906edaac7fffbc813ed9d31460a6d9743cda8a29fc` |
| SHA3-384 | `dea7063958a3ce4bbc8280ade40bf5091360d6fcda20b454cacf1a641397985db08a7a45258ee8df8b445eb5a08456f0` |
| TLSH | `T113B31210D20C9E11D8CFA89D43E5DF9A77FADF8A25F685B66011A7E282CBD146603FD0` |
| SSDEEP | `3072:ZUiAvPnyCHeIuQgRNf845R9pvVqYSk4BN4u+qgw2ui:Olvvr+RNp5DFVqhr7i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_e986c08a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e986c08a9dacb351fc1da3906edaac7fffbc813ed9d31460a6d9743cda8a29fc"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-14 00:12:09"
  condition:
    hash.sha256(0, filesize) == "e986c08a9dacb351fc1da3906edaac7fffbc813ed9d31460a6d9743cda8a29fc"
}
```

### Sample 23: `d9414d5407b92d58`

| Field | Value |
|---|---|
| SHA-256 | `d9414d5407b92d58f72222063c2f39c49c33ee5eec7ff00a2a99f2ecca2866f5` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-14 00:06:28` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11d9c26f611acf1e1a95d597bfda7fe9` |
| SHA-1 | `bf1570ff09199a3f315d22a58b39ef3dfd59a827` |
| SHA-256 | `d9414d5407b92d58f72222063c2f39c49c33ee5eec7ff00a2a99f2ecca2866f5` |
| SHA3-384 | `af34dda744291ca0d2fe3aa386039aafeb3c27f7cac8c2059fa041cbd4fae7d666113f982b7739e2600b06b62ba75ee4` |
| TLSH | `T149A31265EF58CF09C8B6517786DA7843370442CF976058B7ACCAA4EF948EB191D30376` |
| SSDEEP | `3072:Te8GSZ+TnZ2BN5OBs/CjsSfPFBG8xHnuy+m8T5FoSpouty:q87M4BN5Qs/CI4xH3z8tFrpoSy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_d9414d54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9414d5407b92d58f72222063c2f39c49c33ee5eec7ff00a2a99f2ecca2866f5"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-14 00:06:28"
  condition:
    hash.sha256(0, filesize) == "d9414d5407b92d58f72222063c2f39c49c33ee5eec7ff00a2a99f2ecca2866f5"
}
```

### Sample 24: `00d4ea0d9de91024`

| Field | Value |
|---|---|
| SHA-256 | `00d4ea0d9de91024a65081ff5c5270c4c23d90acaa80d08040c79974f8539317` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-14 00:04:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fdbb3f4a82f122c88991605f58c66a7` |
| SHA-1 | `afdc3d01fa992ee2a86d6c72718b9ec54dcbdffd` |
| SHA-256 | `00d4ea0d9de91024a65081ff5c5270c4c23d90acaa80d08040c79974f8539317` |
| SHA3-384 | `935e0b72afa1348159fdd0977201908e62c82f735cb13932d4882423d27caff6472e855413f7971dbe99d158e828e2e3` |
| TLSH | `T10CC27D956A867C44BDC98A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC12FACD618B1A` |
| SSDEEP | `768:0E8vCB+25j6es8R+9FYpMSUpi+20qUpi+20YQX:0E8l25JYd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_00d4ea0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00d4ea0d9de91024a65081ff5c5270c4c23d90acaa80d08040c79974f8539317"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-14 00:04:11"
  condition:
    hash.sha256(0, filesize) == "00d4ea0d9de91024a65081ff5c5270c4c23d90acaa80d08040c79974f8539317"
}
```

### Sample 25: `a395a7b8c501b479`

| Field | Value |
|---|---|
| SHA-256 | `a395a7b8c501b4795ef03fcdcce4fb5192e67c8f2a9685dd817997c155fbedfc` |
| Family label | `unknown` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-07-13 23:55:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb308b3e5ba96755d751acde50928fd7` |
| SHA-1 | `a9c3ef51b440fc7685096a59a63e761929d5f9f8` |
| SHA-256 | `a395a7b8c501b4795ef03fcdcce4fb5192e67c8f2a9685dd817997c155fbedfc` |
| SHA3-384 | `1e5ee4397a10d0006e716d411019241810b4a266b95195e335e95d8ce212a62b4dcc6e5d686d79e2ba848c869d823a8b` |
| TLSH | `T17FA3023A035574E2C2EFADF2455E87979E452E65FAEED528F108CBB0780284B2C3A053` |
| SSDEEP | `3072:lx/A0+j0u+SFsF38yEbffI3fD1Hhrd7upTdjtMOK+:lxf+jaQk38BfqfDxTGTdjGOK+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_a395a7b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a395a7b8c501b4795ef03fcdcce4fb5192e67c8f2a9685dd817997c155fbedfc"
    family = "unknown"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-07-13 23:55:15"
  condition:
    hash.sha256(0, filesize) == "a395a7b8c501b4795ef03fcdcce4fb5192e67c8f2a9685dd817997c155fbedfc"
}
```

### Sample 26: `0d68f94463f8fa35`

| Field | Value |
|---|---|
| SHA-256 | `0d68f94463f8fa351000dfcd3c7188f18d3819aef2d5cf6022e9bf3154d0fcf1` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-13 23:54:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22bdb9487166406910bb579d6e579c85` |
| SHA-1 | `eba43b390a02a9d3c0527c0fe94c04aae2e7387c` |
| SHA-256 | `0d68f94463f8fa351000dfcd3c7188f18d3819aef2d5cf6022e9bf3154d0fcf1` |
| SHA3-384 | `443b2b4f0c2291d7e1b4d73f696ee71782e552d8b66a030b3f31043b606060ca70107bbda010a470ff3578140a6dc68e` |
| TLSH | `T1EC647EE3FC01E9BFFC6ED332CC174A04B134E31154921A3A62A37779A92B1595973E86` |
| SSDEEP | `6144:xcztYdmgkJEhCvBofz9hiFs0U5Tyt5zTh8Ks+XlLdsBC:xat9pvBofz9hiFs04KNsBC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_0d68f944
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d68f94463f8fa351000dfcd3c7188f18d3819aef2d5cf6022e9bf3154d0fcf1"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-13 23:54:11"
  condition:
    hash.sha256(0, filesize) == "0d68f94463f8fa351000dfcd3c7188f18d3819aef2d5cf6022e9bf3154d0fcf1"
}
```

### Sample 27: `8d0201c41efbe907`

| Field | Value |
|---|---|
| SHA-256 | `8d0201c41efbe90707b12ba9b0694ea74a1a8e3a4887064ed9eafb62dad6ed7c` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-13 23:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9eeb3d4db1dde204249bf0786cb3c342` |
| SHA-1 | `5a5d996461b4f2e7916a00c65f4487f8a35cac17` |
| SHA-256 | `8d0201c41efbe90707b12ba9b0694ea74a1a8e3a4887064ed9eafb62dad6ed7c` |
| SHA3-384 | `f4f55577cc180d33d92f75acb9937cc0070b7e2ef428b4eeba5ea525742e306c6cc98612516203b2bc6ccf99a6832323` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1B4E6330816F023FEEBB3443DD9E116E5D160389617B2CBAF1B90C6E16E571A1AE3C617` |
| SSDEEP | `393216:1qiWFIzu3ymozwvXMCHWUjXScuI3/PGTAI:1Tzb8vXMb8XvH/O7` |
| ICON-DHASH | `d4f8d1f0e0e971b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_8d0201c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d0201c41efbe90707b12ba9b0694ea74a1a8e3a4887064ed9eafb62dad6ed7c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 23:52:11"
  condition:
    hash.sha256(0, filesize) == "8d0201c41efbe90707b12ba9b0694ea74a1a8e3a4887064ed9eafb62dad6ed7c"
}
```

### Sample 28: `f28e85cb1e61807d`

| Field | Value |
|---|---|
| SHA-256 | `f28e85cb1e61807d9c6f3a9f4f5216d1ae02ad97287626a896151f94116d1e6c` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan-Downloader.Win32.Minix.cyb.30070.6663` |
| File type | `exe` |
| First seen | `2026-07-13 23:42:59` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7a41bf0be011bef97636dff7741b02d` |
| SHA-1 | `80099b56c7b7e9431423b934df2584b9c97eccc7` |
| SHA-256 | `f28e85cb1e61807d9c6f3a9f4f5216d1ae02ad97287626a896151f94116d1e6c` |
| SHA3-384 | `15d53b5590f56d2d2c65a5c4a6148b4fd5510151bfb78e74d7159edea7dfc28658fd60b5904ebc1039d3e0857ef060c4` |
| IMPHASH | `9be4f90f50c714bc00cc8beb2e137299` |
| TLSH | `T1D6C41240FFD65CDED8B0897949F361634934BCDC8824A65B1288AFAF7E75E40DE39248` |
| SSDEEP | `12288:NtgXdATvgWrc7iDSCNvpsXfD7NeQSt+Pl:N6uz/cu9NiXfD7rlP` |
| ICON-DHASH | `e590b4cc98929e9c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_f28e85cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f28e85cb1e61807d9c6f3a9f4f5216d1ae02ad97287626a896151f94116d1e6c"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan-Downloader.Win32.Minix.cyb.30070.6663"
    file_type = "exe"
    first_seen = "2026-07-13 23:42:59"
  condition:
    hash.sha256(0, filesize) == "f28e85cb1e61807d9c6f3a9f4f5216d1ae02ad97287626a896151f94116d1e6c"
}
```

### Sample 29: `cc6720ae14382b85`

| Field | Value |
|---|---|
| SHA-256 | `cc6720ae14382b85c1eafa9d5a04460d2e434d1cfc618dbaf9e0d6679989f535` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-13 23:37:29` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b89602cea499c0d4623f1ae8dc779cd` |
| SHA-1 | `8b1a3273fa3c4d1b329b7ea8d0247a6fffe6d6a3` |
| SHA-256 | `cc6720ae14382b85c1eafa9d5a04460d2e434d1cfc618dbaf9e0d6679989f535` |
| SHA3-384 | `cfcd84b33533151efeec6418a6548dac112a25c3f6d8b55f194f1badd622eb3105f02e26ccb00f3de2db77e620a1296b` |
| TLSH | `T19D237C652A817C14AA98C4371D7E2F0CB9AD43E6320492ED7FCF3CF68C5A69D921871D` |
| SSDEEP | `768:8XOGVv6q9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:CLy/cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_cc6720ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc6720ae14382b85c1eafa9d5a04460d2e434d1cfc618dbaf9e0d6679989f535"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-13 23:37:29"
  condition:
    hash.sha256(0, filesize) == "cc6720ae14382b85c1eafa9d5a04460d2e434d1cfc618dbaf9e0d6679989f535"
}
```

### Sample 30: `d9a2381a471f6c93`

| Field | Value |
|---|---|
| SHA-256 | `d9a2381a471f6c93606f393561c4aca8568313f1d992d9973b7d97821b37ba2c` |
| Family label | `AnyDesk` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-13 23:35:55` |
| Reporter | `Bitsight` |
| Tags | `AnyDesk, dropped-by-GCleaner, E, exe, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da3d9a45621fa28b45e1d5b1f0b9e326` |
| SHA-1 | `0966650e7bd62bce926142f51deba6f81f8078b1` |
| SHA-256 | `d9a2381a471f6c93606f393561c4aca8568313f1d992d9973b7d97821b37ba2c` |
| SHA3-384 | `595148d30209983561e87a3f0474b6f9a4330d4a862e7a5ef43ed670ffabd505ebf078c4de87ed233cd6ab2a3aff7be0` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T127D6233FB28B303EE06E1A7A3672E210953BAA61A5178C57D6F4C44CCF154B11D3EB96` |
| SSDEEP | `393216:0til1h22ExhnFJly7ROyPFPXww9v2J77G71sms:iHTs1OXiv2J7a7u` |
| ICON-DHASH | `28542a79792a5420` |

#### Technical Assessment

- The sample is tracked as `AnyDesk` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AnyDesk_030_d9a2381a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9a2381a471f6c93606f393561c4aca8568313f1d992d9973b7d97821b37ba2c"
    family = "AnyDesk"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-13 23:35:55"
  condition:
    hash.sha256(0, filesize) == "d9a2381a471f6c93606f393561c4aca8568313f1d992d9973b7d97821b37ba2c"
}
```

### Sample 31: `be52dd73c5626d66`

| Field | Value |
|---|---|
| SHA-256 | `be52dd73c5626d66c2c6325810921db26b1ca421c9d08e844a9f621bf1b5aeb2` |
| Family label | `unknown` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-07-13 23:34:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2498761039531a8db058f399a6fb8021` |
| SHA-1 | `dbf21df008bed59f21c44e18ee996851206861da` |
| SHA-256 | `be52dd73c5626d66c2c6325810921db26b1ca421c9d08e844a9f621bf1b5aeb2` |
| SHA3-384 | `71079be2961a9d1990a55075a69027ed21dcfa39a7479d8cd4657ac1c7e69dcfe8d7d67e06e6d21d99bac80ead535214` |
| TLSH | `T103A312B3A9C0F211DC3110749F31CA8973F39A68CF76D29599C8D59E5E0A32927ED2C5` |
| SSDEEP | `3072:0zsHKt6p3j9TXkdx+ekLhLrzeUZgZcDxGg8k0TmBT:023hNXoixCWgZGz0TGT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_be52dd73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be52dd73c5626d66c2c6325810921db26b1ca421c9d08e844a9f621bf1b5aeb2"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-13 23:34:22"
  condition:
    hash.sha256(0, filesize) == "be52dd73c5626d66c2c6325810921db26b1ca421c9d08e844a9f621bf1b5aeb2"
}
```

### Sample 32: `7b9959d43d48dadc`

| Field | Value |
|---|---|
| SHA-256 | `7b9959d43d48dadc1139e45c07978eea4f7e314c328050e860c538dbcd48ede6` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-07-13 23:33:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3df67d1d03f2c5e2ddbf0c15d23636ee` |
| SHA-1 | `a373f5e0b90b1cb62f1506b7954a0f376d3d6f41` |
| SHA-256 | `7b9959d43d48dadc1139e45c07978eea4f7e314c328050e860c538dbcd48ede6` |
| SHA3-384 | `574c3ea016a2624196fb00b7fb1383175d54f960ac5f0a4897398017cd48954b1327c1c6aa10c4705dc7343f451dcede` |
| TLSH | `T1B4A312EE37FCB63894F87939DD98E5007E2D739514FBB0B368585AD10B80069A0D93A3` |
| SSDEEP | `3072:WZ6srvQPEFQcpowVzK1aIyvQFvYzvWic/aBI:WZ/rqhZyveYqi7C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_7b9959d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b9959d43d48dadc1139e45c07978eea4f7e314c328050e860c538dbcd48ede6"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-13 23:33:18"
  condition:
    hash.sha256(0, filesize) == "7b9959d43d48dadc1139e45c07978eea4f7e314c328050e860c538dbcd48ede6"
}
```

### Sample 33: `1e716a69b81f3272`

| Field | Value |
|---|---|
| SHA-256 | `1e716a69b81f3272b10e3cc7b919e1a1f03005115fbf18ac8b1958a111a8f185` |
| Family label | `njrat` |
| File name | `220c8ef9ac545f54ae0998d260221f45.exe` |
| File type | `exe` |
| First seen | `2026-07-13 23:20:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `220c8ef9ac545f54ae0998d260221f45` |
| SHA-1 | `465b707813253d90bfe72eb8a24797335c5bcec1` |
| SHA-256 | `1e716a69b81f3272b10e3cc7b919e1a1f03005115fbf18ac8b1958a111a8f185` |
| SHA3-384 | `bc6e2a81d178a529c58f38900895a423936246aac3a89066a303710afe2c6cb7c1a6c9157ba7b6805ce2784d5646405c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BB93D74977E52524E4BF56F79472F2004E34B44B1602E39E49F259EA0A33AC44F89FEB` |
| SSDEEP | `1536:rUwC+xhUa9urgOBPRNvM4jEwzGi1dD3DVgS:rUmUa9urgObdGi1d3i` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_033_1e716a69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e716a69b81f3272b10e3cc7b919e1a1f03005115fbf18ac8b1958a111a8f185"
    family = "njrat"
    file_name = "220c8ef9ac545f54ae0998d260221f45.exe"
    file_type = "exe"
    first_seen = "2026-07-13 23:20:05"
  condition:
    hash.sha256(0, filesize) == "1e716a69b81f3272b10e3cc7b919e1a1f03005115fbf18ac8b1958a111a8f185"
}
```

### Sample 34: `b480ccc572874300`

| Field | Value |
|---|---|
| SHA-256 | `b480ccc5728743005a359d21b7c999a1b9b9d5f7a05176ac338926d3c514d7f5` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-13 22:51:50` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83e7e4736d1c22f92243d488a75d4f96` |
| SHA-1 | `bf05b380e38947849ccc7b661eba40b51f126f34` |
| SHA-256 | `b480ccc5728743005a359d21b7c999a1b9b9d5f7a05176ac338926d3c514d7f5` |
| SHA3-384 | `c4a6acb8ff23ffb9b78676d3e66a1d60bb28d831a53b9e1e35aa96a12f7679fac79214268e25b9da67be103cd9de475c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1A0E63308B6E111EDE6B3423CFDB14ADAD4B578210BB2C7DB17A81B646E470908F7D58B` |
| SSDEEP | `393216:OjBBnSPns0QmrthNYyURglm97XMCHWUjX3cuI3/PGTAI:Ojnmns0drLKd6A97XMb8XMH/O7` |
| ICON-DHASH | `38dcf8f8fcf8e040` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_b480ccc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b480ccc5728743005a359d21b7c999a1b9b9d5f7a05176ac338926d3c514d7f5"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 22:51:50"
  condition:
    hash.sha256(0, filesize) == "b480ccc5728743005a359d21b7c999a1b9b9d5f7a05176ac338926d3c514d7f5"
}
```

### Sample 35: `95f08187d0a5572a`

| Field | Value |
|---|---|
| SHA-256 | `95f08187d0a5572a0b2efba21b0dae6155d7a1b4a4b17034c768b2fbe920626e` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.ELF.Mirai-DJO.89223942` |
| File type | `elf` |
| First seen | `2026-07-13 22:44:36` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67303ac025d6465b544cd4fb5dd65b35` |
| SHA-1 | `03a43e57d8820b5c9da2e87cf8bd937ba682ed85` |
| SHA-256 | `95f08187d0a5572a0b2efba21b0dae6155d7a1b4a4b17034c768b2fbe920626e` |
| SHA3-384 | `bc525e694b55ce99285e77ce9d1be223d3516b006349ecb77465b6e5cdd41836ee26e68eafe33226db1ce26d827dfda1` |
| TLSH | `T151838D68AA0F6D81C2C7E3BEBD560FB271333CB48364C1B26A01E65DD8E9EC48D95157` |
| SSDEEP | `1536:XTBEk/gqHdJedilmIWxYY/3zIExThFd1/rnE8KOC54L6CjIr:jBEsdJFqbjIE5hFd1rE8KhRV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_95f08187
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95f08187d0a5572a0b2efba21b0dae6155d7a1b4a4b17034c768b2fbe920626e"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai-DJO.89223942"
    file_type = "elf"
    first_seen = "2026-07-13 22:44:36"
  condition:
    hash.sha256(0, filesize) == "95f08187d0a5572a0b2efba21b0dae6155d7a1b4a4b17034c768b2fbe920626e"
}
```

### Sample 36: `4978da802792479e`

| Field | Value |
|---|---|
| SHA-256 | `4978da802792479e84ccf497a16f7021096cf2cc0ae871c25fb62e60d6a63f5e` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-07-13 22:06:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d0d70272e1f86b9f22b27d9001a3456` |
| SHA-1 | `80f800d081dc4403442b72723febdd773d94c322` |
| SHA-256 | `4978da802792479e84ccf497a16f7021096cf2cc0ae871c25fb62e60d6a63f5e` |
| SHA3-384 | `e9d213529157ec5099a2c55fef6dca67e1700a82452827ef7c4824a3eca8636548ddaae2e57d8d7706a475c21254a8fd` |
| TLSH | `T170B312614AAEB856C7BA2237791D812130AF675CEFCE5376F254E6C0895382223FCD47` |
| SSDEEP | `1536:WgQBimNIGc69af5Wc183EYr7Bbcj1Helr++1tykTUo72pviLJ8l5st9q/SLRCq8V:TCiiIkcSEYrtYHwtbUoCIAI98XJv1Dk0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_4978da80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4978da802792479e84ccf497a16f7021096cf2cc0ae871c25fb62e60d6a63f5e"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-13 22:06:25"
  condition:
    hash.sha256(0, filesize) == "4978da802792479e84ccf497a16f7021096cf2cc0ae871c25fb62e60d6a63f5e"
}
```

### Sample 37: `a8c5a790eb2df505`

| Field | Value |
|---|---|
| SHA-256 | `a8c5a790eb2df505f426a9a5ac165e720d2a5e2e1b57538aab7b6b89824af7c2` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-13 21:51:51` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `655e402302522f78f1264785f7f0b37b` |
| SHA-1 | `9119b5709911d28f77c7e423a899455eef9ae506` |
| SHA-256 | `a8c5a790eb2df505f426a9a5ac165e720d2a5e2e1b57538aab7b6b89824af7c2` |
| SHA3-384 | `b250dc9eeacd0ead698c2d0452f5dfc4834c43fbd1f73bbe1426d14cb9a516af15b37ad5308a3fd3b6dec822912e1a5a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T12CE6332879D006FEF6B3503CDEF08686E56570B90B32C9EB17A88B91ED471E0493975B` |
| SSDEEP | `393216:u3jfoeWzJqSsmm9BSXMCHWUjXocuI3/PGTAI:ujy9qq1XMb8XdH/O7` |
| ICON-DHASH | `f0d88ea29ac6f4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_a8c5a790
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8c5a790eb2df505f426a9a5ac165e720d2a5e2e1b57538aab7b6b89824af7c2"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 21:51:51"
  condition:
    hash.sha256(0, filesize) == "a8c5a790eb2df505f426a9a5ac165e720d2a5e2e1b57538aab7b6b89824af7c2"
}
```

### Sample 38: `6a88e77d52212abb`

| Field | Value |
|---|---|
| SHA-256 | `6a88e77d52212abb66102febdc5a396d4b3e9bb85a093762e646e3e91fe2ce97` |
| Family label | `unknown` |
| File name | `renewcrypterforresults.hta` |
| File type | `hta` |
| First seen | `2026-07-13 21:48:03` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22ceb9b054edff91b17be26e0acc0553` |
| SHA-1 | `bd1b6701ed597f8db6189b303877dcc14e35f215` |
| SHA-256 | `6a88e77d52212abb66102febdc5a396d4b3e9bb85a093762e646e3e91fe2ce97` |
| SHA3-384 | `86456d60040ecdeb1066771487d514ef0c62ca254d1019b7f519962d18517680526340eee649f597e08ec24bdc735b1a` |
| TLSH | `T1ACF1AB6219215E041873933735FEA118FB63285B82401F703D9C47139F3229989833A8` |
| SSDEEP | `12:TkWqk18F5EbifWW0igOHo7qGMCH4AzsqKBPGb:VH8F5EOfWWHbHiXMCH9zAk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_6a88e77d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a88e77d52212abb66102febdc5a396d4b3e9bb85a093762e646e3e91fe2ce97"
    family = "unknown"
    file_name = "renewcrypterforresults.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:48:03"
  condition:
    hash.sha256(0, filesize) == "6a88e77d52212abb66102febdc5a396d4b3e9bb85a093762e646e3e91fe2ce97"
}
```

### Sample 39: `9d4a3ef6fa7b16b9`

| Field | Value |
|---|---|
| SHA-256 | `9d4a3ef6fa7b16b9d9646c3db7ad08e465797a9fbf1f6abde0708cf06b1181fe` |
| Family label | `unknown` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-07-13 21:40:00` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f620444361bddbb7e881822996a4b2c6` |
| SHA-1 | `fb1a78bbed8716a73590358943619396f7281ee4` |
| SHA-256 | `9d4a3ef6fa7b16b9d9646c3db7ad08e465797a9fbf1f6abde0708cf06b1181fe` |
| SHA3-384 | `45c8963e403b2e079b7552b0b05ef0b6025e61081f9e8c58bb4c580c94092258cd8c37a3a1f478df3218dff9b6dd25b8` |
| TLSH | `T1F4649E13BB878FA6E121B67549F3C178A9E93A0606F7C426C3796B17079D1C0B81DEC9` |
| TELFHASH | `t196111448683ec45a7de30664cc3c5a95d70fcd3538514720df08c7c4897e4059219f5f` |
| SSDEEP | `6144:g+eQOF9sIrei9VoG5bYREEBQ6QnIJWJaoVz6zMwTGe:g+eQOzFrVVPbYGEBVWJao96zMwqe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_9d4a3ef6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d4a3ef6fa7b16b9d9646c3db7ad08e465797a9fbf1f6abde0708cf06b1181fe"
    family = "unknown"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-07-13 21:40:00"
  condition:
    hash.sha256(0, filesize) == "9d4a3ef6fa7b16b9d9646c3db7ad08e465797a9fbf1f6abde0708cf06b1181fe"
}
```

### Sample 40: `45a697782d4edbda`

| Field | Value |
|---|---|
| SHA-256 | `45a697782d4edbda5824e944a10fc4de2b1dd6e24fa638e52e79b52b4ac11dbd` |
| Family label | `unknown` |
| File name | `Reezn.apk` |
| File type | `apk` |
| First seen | `2026-07-13 21:36:06` |
| Reporter | `Fox707` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6d7c52c544ef56417c317f83b4a37cf` |
| SHA-1 | `1e122ae0e3848dc9c71b267cb125099fc0ab234d` |
| SHA-256 | `45a697782d4edbda5824e944a10fc4de2b1dd6e24fa638e52e79b52b4ac11dbd` |
| SHA3-384 | `1f0c5b9322447dfc9dd29aeafcfbf8b0f09f48b366bc6bba4d0d65de98c0ae0d9dcc7b31a3f6135cd0b72c1e1398ce13` |
| TLSH | `T1A237F143F75A8E3FCCF638B0149F533A66245C59874296875A04FA287EB72E04F2A7D4` |
| SSDEEP | `393216:15TaraEkTYjFJOSD+/nIxPqcY9g0053dhKEj7cWFdF:1xwaLEjySUyB7syzdF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_45a69778
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45a697782d4edbda5824e944a10fc4de2b1dd6e24fa638e52e79b52b4ac11dbd"
    family = "unknown"
    file_name = "Reezn.apk"
    file_type = "apk"
    first_seen = "2026-07-13 21:36:06"
  condition:
    hash.sha256(0, filesize) == "45a697782d4edbda5824e944a10fc4de2b1dd6e24fa638e52e79b52b4ac11dbd"
}
```

### Sample 41: `fa38f6539af74b5b`

| Field | Value |
|---|---|
| SHA-256 | `fa38f6539af74b5b355c532a3c71c588960d34abd825442fea98c2177375d010` |
| Family label | `RemusStealer` |
| File name | `recuva_professional__technician_(2026)_full_español_[mega].exe` |
| File type | `exe` |
| First seen | `2026-07-13 21:32:15` |
| Reporter | `abuse_ch` |
| Tags | `de-pumped, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3421de0f4fe56f3d6a7c86f281f5115e` |
| SHA-1 | `bd93017965afb4ff0ed13768b450aa56e0fc7231` |
| SHA-256 | `fa38f6539af74b5b355c532a3c71c588960d34abd825442fea98c2177375d010` |
| SHA3-384 | `ff8cf61810d0beb9e4f25170a08c6201d10a14e5114249328bf445f2c1f976342ae906fda5e56736057a9df2eb19d07b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17FA56B0B7CD049E9C8AA673188B261927B35BC194F3627D32E90B7783E727E15D36784` |
| SSDEEP | `24576:LfRbwvSN00WoClYV67JJxAkJ4vFXaNQ5r+NVMuzSBqAnQTXN69txzBele5rK263G:LfNCS20WFuixUFB6QemqAnC8ng` |
| ICON-DHASH | `c1a9b98981a1d1d9` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_041_fa38f653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa38f6539af74b5b355c532a3c71c588960d34abd825442fea98c2177375d010"
    family = "RemusStealer"
    file_name = "recuva_professional__technician_(2026)_full_español_[mega].exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:32:15"
  condition:
    hash.sha256(0, filesize) == "fa38f6539af74b5b355c532a3c71c588960d34abd825442fea98c2177375d010"
}
```

### Sample 42: `aec2007bddf386d7`

| Field | Value |
|---|---|
| SHA-256 | `aec2007bddf386d7659b60f712334d7f277f65edfd9f11a61c711b7b4b7119e2` |
| Family label | `RemusStealer` |
| File name | `jee chahta hai movie 720p download utorrent movies.exe` |
| File type | `exe` |
| First seen | `2026-07-13 21:31:54` |
| Reporter | `abuse_ch` |
| Tags | `de-pumped, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12241c02cb660a70f4aeb83d287c7bce` |
| SHA-1 | `1166cb6addd7f8083632ceb3aa2612008a3f52f9` |
| SHA-256 | `aec2007bddf386d7659b60f712334d7f277f65edfd9f11a61c711b7b4b7119e2` |
| SHA3-384 | `c1b406c991fb097f1be565bfc9c7baa2d70453fbfacaf3dff2fb58e77d312a00adceee9282f08ef9d7ce5859bf612635` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T181A56B0B6CD049E9C8AA673188B261927B35BC094F3623D72E90B7783F327E15D76794` |
| SSDEEP | `49152:c1ixTd3MJ+5rEAzgJvAz9EJ0jOPipSDADt+B2g:c1WdwAF` |
| ICON-DHASH | `00d4c4d2d0df2700` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_042_aec2007b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aec2007bddf386d7659b60f712334d7f277f65edfd9f11a61c711b7b4b7119e2"
    family = "RemusStealer"
    file_name = "jee chahta hai movie 720p download utorrent movies.exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:31:54"
  condition:
    hash.sha256(0, filesize) == "aec2007bddf386d7659b60f712334d7f277f65edfd9f11a61c711b7b4b7119e2"
}
```

### Sample 43: `d5d5465b53f72727`

| Field | Value |
|---|---|
| SHA-256 | `d5d5465b53f72727b8218dab4165b954748d29ab8f8de275fbd3a6fac0e08b6d` |
| Family label | `RemusStealer` |
| File name | `jahan i danish book free download.exe` |
| File type | `exe` |
| First seen | `2026-07-13 21:31:28` |
| Reporter | `abuse_ch` |
| Tags | `de-pumped, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48c1aaa457882fdcca82c647071c1eb8` |
| SHA-1 | `fec96bfbea1db91d9dad11a2873b503bc8c00645` |
| SHA-256 | `d5d5465b53f72727b8218dab4165b954748d29ab8f8de275fbd3a6fac0e08b6d` |
| SHA3-384 | `75c43026ad7342c3f691bb68fc99a9049ef22a1ee3337548b2240e7bc2f18b072672b9323731c6cb33facf097fd317be` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1DCB56B0B7CD149E9C8AA6B3188B261927B35BC090F3623D72E9077782F327E15D76794` |
| SSDEEP | `49152:a1ixTd3MJ+5rEAzgJvAz9EJ0jOPipSDADt+B2g:a1WdwAF` |
| ICON-DHASH | `c4c4e4f4d0e4d4d4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_043_d5d5465b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5d5465b53f72727b8218dab4165b954748d29ab8f8de275fbd3a6fac0e08b6d"
    family = "RemusStealer"
    file_name = "jahan i danish book free download.exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:31:28"
  condition:
    hash.sha256(0, filesize) == "d5d5465b53f72727b8218dab4165b954748d29ab8f8de275fbd3a6fac0e08b6d"
}
```

### Sample 44: `41f04280d3247586`

| Field | Value |
|---|---|
| SHA-256 | `41f04280d3247586155c62404609431b378f99bd7c7aff4e711e15330ee978c9` |
| Family label | `RemcosRAT` |
| File name | `weneedbestthingswithbestversionsneed.hta` |
| File type | `hta` |
| First seen | `2026-07-13 21:31:05` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94e1df21f51089cf6a9f5f59ec6c0d00` |
| SHA-1 | `47d8b23d30b7ca009b99d920a4d27e909d30b446` |
| SHA-256 | `41f04280d3247586155c62404609431b378f99bd7c7aff4e711e15330ee978c9` |
| SHA3-384 | `43fbd32917ddcf93cf0063882c329ff2f161d1f42cd5e0f875978a14eb2211bbc9d22daaec3d0415246aed462ca25bb1` |
| TLSH | `T19403E93C6E0481E7894EA05D2CB53A36241A517781AE9FA7348D0C73FFB65AD48B8C8D` |
| SSDEEP | `96:fTVlyCeycOyZak+6Z1Uy1t6bjgdtIM5gdtIMmgdtIMUgdtIMogdtIMZygdtIM0gr:rVYICp+6T1t6bfG64MQlDzAmkpZSg` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_044_41f04280
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41f04280d3247586155c62404609431b378f99bd7c7aff4e711e15330ee978c9"
    family = "RemcosRAT"
    file_name = "weneedbestthingswithbestversionsneed.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:31:05"
  condition:
    hash.sha256(0, filesize) == "41f04280d3247586155c62404609431b378f99bd7c7aff4e711e15330ee978c9"
}
```

### Sample 45: `ed38c22c7385998f`

| Field | Value |
|---|---|
| SHA-256 | `ed38c22c7385998f5182bfae0a235faee616ed19fb34b945b1b8e211e3001e96` |
| Family label | `RemusStealer` |
| File name | `recuva_professional__technician_(2026)_full_español_[mega].7z` |
| File type | `7z` |
| First seen | `2026-07-13 21:28:06` |
| Reporter | `iamaachum` |
| Tags | `7z, file-pumped, pw-5856, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2278019b15ee469c70ca3f5f48bcef20` |
| SHA-1 | `14c5fda8f8477efebe248f1f563fa1aaa06c6fd1` |
| SHA-256 | `ed38c22c7385998f5182bfae0a235faee616ed19fb34b945b1b8e211e3001e96` |
| SHA3-384 | `fd58a40b1b47a072c1985bc35fdea7fc2d5171663f7151583e3479bcfa78904b3ce8db9121493126727bcf23dfc5dda6` |
| TLSH | `T1CA06332EF535E9F2C7D1EA61410F3F89096C241F288216D8F5863D50A8F67AD47B886F` |
| SSDEEP | `98304:5guuNEmm51x/nc4PSbZ7i5It8WmbEkckqhdrVHfhYcmabsA1X0Du:5gJN2TZvGZ7MIWXAkckOdtJYbabsMX0S` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_045_ed38c22c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed38c22c7385998f5182bfae0a235faee616ed19fb34b945b1b8e211e3001e96"
    family = "RemusStealer"
    file_name = "recuva_professional__technician_(2026)_full_español_[mega].7z"
    file_type = "7z"
    first_seen = "2026-07-13 21:28:06"
  condition:
    hash.sha256(0, filesize) == "ed38c22c7385998f5182bfae0a235faee616ed19fb34b945b1b8e211e3001e96"
}
```

### Sample 46: `16a1260ae199d83c`

| Field | Value |
|---|---|
| SHA-256 | `16a1260ae199d83c537b65ca558b33c7a783d28c5547b5fcb35dee4cceb5f12e` |
| Family label | `RemusStealer` |
| File name | `jee chahta hai movie 720p download utorrent movies.7z` |
| File type | `7z` |
| First seen | `2026-07-13 21:27:10` |
| Reporter | `iamaachum` |
| Tags | `7z, file-pumped, pw-8121, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `811f014bacdcbb056db397f13d528405` |
| SHA-1 | `3cd8a6d94465a9e266f9869051bf7df2316069bf` |
| SHA-256 | `16a1260ae199d83c537b65ca558b33c7a783d28c5547b5fcb35dee4cceb5f12e` |
| SHA3-384 | `669ac66520a36381aedc48524cf301aea879c5e0d86d7f902a1d78980ad0f6e46378e288717f5db9450ad9a023ffc459` |
| TLSH | `T17C0733DFA7CCA6823251FDC10DAE118771904F7FDE24F687ED505276099D0BAB2D8A88` |
| SSDEEP | `393216:9FZk52cpSFRZh9UHaMFD+nl2nnVT0nFTdBN+ym:uppSFxnnoVTQV9+ym` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_046_16a1260a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16a1260ae199d83c537b65ca558b33c7a783d28c5547b5fcb35dee4cceb5f12e"
    family = "RemusStealer"
    file_name = "jee chahta hai movie 720p download utorrent movies.7z"
    file_type = "7z"
    first_seen = "2026-07-13 21:27:10"
  condition:
    hash.sha256(0, filesize) == "16a1260ae199d83c537b65ca558b33c7a783d28c5547b5fcb35dee4cceb5f12e"
}
```

### Sample 47: `d871b4706e6410c4`

| Field | Value |
|---|---|
| SHA-256 | `d871b4706e6410c4170a03a86629822e046d81e15f6a50d905059d7f2383f1de` |
| Family label | `RemusStealer` |
| File name | `jahan i danish book free download.7z` |
| File type | `7z` |
| First seen | `2026-07-13 21:26:14` |
| Reporter | `iamaachum` |
| Tags | `7z, file-pumped, pw-5231, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7a90be977a8f4fd0889e7454faa7b10` |
| SHA-1 | `0f9eb6fb312fd3501c973ef194102899a5c0f5b5` |
| SHA-256 | `d871b4706e6410c4170a03a86629822e046d81e15f6a50d905059d7f2383f1de` |
| SHA3-384 | `e3edbdf61e0fb5bfa40fa981cb97c77680e5fcc4f92a58c9fbe4bcf1139045f3044f02681bcace609252203d21fcb11b` |
| TLSH | `T1EA07335B7FB833C4E23C5A4739893C4BFC78DE4322C9E6960105A181EE24697CA6D59F` |
| SSDEEP | `393216:Z01xEMIocb2SpCNXDJiuOsesooNvPVhXlZvYq+dQWm269ikaeW0:Zgbc/CNVksioNXVhXsq+Rm26aeW0` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_047_d871b470
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d871b4706e6410c4170a03a86629822e046d81e15f6a50d905059d7f2383f1de"
    family = "RemusStealer"
    file_name = "jahan i danish book free download.7z"
    file_type = "7z"
    first_seen = "2026-07-13 21:26:14"
  condition:
    hash.sha256(0, filesize) == "d871b4706e6410c4170a03a86629822e046d81e15f6a50d905059d7f2383f1de"
}
```

### Sample 48: `352944118ad77aea`

| Field | Value |
|---|---|
| SHA-256 | `352944118ad77aea5df1707fbbb541ae7b47421f05f148512d074a108097d0a8` |
| Family label | `ZigClipper` |
| File name | `qwe-23wq-e.exe` |
| File type | `exe` |
| First seen | `2026-07-13 21:25:04` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, dropped-by-RemusStealer, exe, kffd3-vexlatech-cc, ZigClipper` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36bcc9fcb9343ac2b013a91ee4faeba6` |
| SHA-1 | `5fb63984e5912c8350bca86f7b97fd1bbb1ed157` |
| SHA-256 | `352944118ad77aea5df1707fbbb541ae7b47421f05f148512d074a108097d0a8` |
| SHA3-384 | `8d215aabd0dbede974407af8aaa2eb1c81b137aa92043aa4fde37b0d1ef89f1b46e52a3b68ba33c4985ddb869f1b86c0` |
| IMPHASH | `f765367f0a88e2dcf14edcaad7ab658b` |
| TLSH | `T1B645AE1DE3CD12E8D227C234CBA29232E7B5B4560761BADB1799C6152FB39D02F7A311` |
| SSDEEP | `24576:SS9jVBUaZP732a4Cd9rfG8GcbGz2wdgVlNTZR6A1UP:SS9ZGKd9rfG8GcW2wdgVD6M` |

#### Technical Assessment

- The sample is tracked as `ZigClipper` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ZigClipper_048_35294411
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "352944118ad77aea5df1707fbbb541ae7b47421f05f148512d074a108097d0a8"
    family = "ZigClipper"
    file_name = "qwe-23wq-e.exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:25:04"
  condition:
    hash.sha256(0, filesize) == "352944118ad77aea5df1707fbbb541ae7b47421f05f148512d074a108097d0a8"
}
```

### Sample 49: `34647bbf33ca3f21`

| Field | Value |
|---|---|
| SHA-256 | `34647bbf33ca3f21aa3dcd604e62dce27198bb6b451e9a00a1d72fe23400da1c` |
| Family label | `RemcosRAT` |
| File name | `privatethignsareverygoodformaitiasentriethinsgs.hta` |
| File type | `hta` |
| First seen | `2026-07-13 21:17:59` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d9e7a5e24681bbcc2efa3e97c1e66e6` |
| SHA-1 | `5b977a9783682e41d67c84f3e524ca61749dfaa5` |
| SHA-256 | `34647bbf33ca3f21aa3dcd604e62dce27198bb6b451e9a00a1d72fe23400da1c` |
| SHA3-384 | `baea3d58e48b944e5bb32532e5a3716fff1eda30e59a920205cab2d5c460025a4538ef0555ad1c21bee0a38b4e6e1d37` |
| TLSH | `T15F03C67D8954ACD2726336999C2AC1102C8CAA5BB4535C7439BF38C94B7634EBA3F1CC` |
| SSDEEP | `384:kBmvQRjXzhzeWvCubmrMx0rsJdEACqC3Cf8L7B/3:imoVDVRirMx0r8dEJ1Sf8J/3` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_049_34647bbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34647bbf33ca3f21aa3dcd604e62dce27198bb6b451e9a00a1d72fe23400da1c"
    family = "RemcosRAT"
    file_name = "privatethignsareverygoodformaitiasentriethinsgs.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:17:59"
  condition:
    hash.sha256(0, filesize) == "34647bbf33ca3f21aa3dcd604e62dce27198bb6b451e9a00a1d72fe23400da1c"
}
```

### Sample 50: `c20a551057c10e69`

| Field | Value |
|---|---|
| SHA-256 | `c20a551057c10e699156ebeb57677cb51625534d8256a3dd3cd8b3efbca5235c` |
| Family label | `RemusStealer` |
| File name | `?????.exe` |
| File type | `exe` |
| First seen | `2026-07-13 21:11:47` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05ca1d2a774b90c4c7e8fe4d3ca57c60` |
| SHA-1 | `2c25171cc19add57d27074daeb96c159b391a992` |
| SHA-256 | `c20a551057c10e699156ebeb57677cb51625534d8256a3dd3cd8b3efbca5235c` |
| SHA3-384 | `f1a98b47276def90696921f38f8a720abc72c0330e0a864315f11cc67f6de5ff761c3b1c95aba5c31fd9044c22b85962` |
| IMPHASH | `20f35ed688f00eacb2c7ea603d9f248e` |
| TLSH | `T1C5241967C25371FCD642C07863667232AB33BA3947349EF707A2C7359E22AC05E79925` |
| SSDEEP | `3072:fp4sTRjivIaGBjkdWRBHgT6vrbq3l6gVu1nZw5lmiRyFZg7x55eZ:C+HHvz8l6gVu1nZwyicZg7x55eZ` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_050_c20a5510
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c20a551057c10e699156ebeb57677cb51625534d8256a3dd3cd8b3efbca5235c"
    family = "RemusStealer"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:11:47"
  condition:
    hash.sha256(0, filesize) == "c20a551057c10e699156ebeb57677cb51625534d8256a3dd3cd8b3efbca5235c"
}
```

### Sample 51: `b999fba4d4db5bdb`

| Field | Value |
|---|---|
| SHA-256 | `b999fba4d4db5bdbfa86d6744ba53b4473f37b53d0fe74c47f7c8238350a11d8` |
| Family label | `ACRStealer` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-07-13 21:10:40` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, releases-cloudgateway-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46106561962c79d6cfbc597f630ff9aa` |
| SHA-1 | `1592e5fe3881646b3bbda9079b3f7bb327d66762` |
| SHA-256 | `b999fba4d4db5bdbfa86d6744ba53b4473f37b53d0fe74c47f7c8238350a11d8` |
| SHA3-384 | `371a0f4022745f3079ea4fa7cb60cdcbdb5bcc8ab0ac53468c48b93e9667730b60ae321b6d9ec4c31242991ca894af0c` |
| TLSH | `T1181723BCB4B5B95AF5D4433BC6C12CB2DB2CA540D7D93D9B8E2041927EC320E5F6A861` |
| SSDEEP | `393216:4voJYOm4PaJBjPvwL4835pf/9vV0LCqUMMeEHjtWehhfkiI7UXFDxiOk:4voJd5EtgL445ptvV0+sMLEgh9I7m6Ok` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_051_b999fba4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b999fba4d4db5bdbfa86d6744ba53b4473f37b53d0fe74c47f7c8238350a11d8"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-13 21:10:40"
  condition:
    hash.sha256(0, filesize) == "b999fba4d4db5bdbfa86d6744ba53b4473f37b53d0fe74c47f7c8238350a11d8"
}
```

### Sample 52: `b50f2a725bec5a13`

| Field | Value |
|---|---|
| SHA-256 | `b50f2a725bec5a139e3bebe5d823af0c25d0a7335adab21b53743c2afdc0b6cb` |
| Family label | `ACRStealer` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-07-13 21:09:40` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, telemetry-incidentcenter-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8031d7489e07833ca8c4cbc436ce7c8` |
| SHA-1 | `20467c3c230c63ddec1917ea5a4efc3f46d49a7a` |
| SHA-256 | `b50f2a725bec5a139e3bebe5d823af0c25d0a7335adab21b53743c2afdc0b6cb` |
| SHA3-384 | `7ddc5928d413e911e59fe123e0c38aa07e287549095944199b631c28b51a32e2866dfe6d802d73e81b8e65a1b5d3ff4c` |
| TLSH | `T1B8373312C56A4F55E68C253AC8C78F016205D7E78501CF9F575AE39FBFE2BF08A21892` |
| SSDEEP | `393216:JPJant0N1jQ9K68zkw2UJTcy4BmCoz3ycGprtbbXpNFk6E1oV/Z4ukZ6Y6P1:JPkniN1j/68LzS8nJGpNbpOmV/uukZwt` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_052_b50f2a72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b50f2a725bec5a139e3bebe5d823af0c25d0a7335adab21b53743c2afdc0b6cb"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-13 21:09:40"
  condition:
    hash.sha256(0, filesize) == "b50f2a725bec5a139e3bebe5d823af0c25d0a7335adab21b53743c2afdc0b6cb"
}
```

### Sample 53: `52ebf27411484098`

| Field | Value |
|---|---|
| SHA-256 | `52ebf27411484098f4643ea8d0d4ca154d66e78de8121d0809ccb437d9f8eeed` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-13 21:08:18` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, PMIX0.file, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2615ab4cea60edc85df76ee114f7da8f` |
| SHA-1 | `17018a9310d84a740b36be20ed01d309b4db919f` |
| SHA-256 | `52ebf27411484098f4643ea8d0d4ca154d66e78de8121d0809ccb437d9f8eeed` |
| SHA3-384 | `b21517c558ca4bfd2a3aa1a0d982475775c6403326f32f369e56a6e9dd5eddd8fb5bca131ab4bad8bd0fef298993c459` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T192E5AE077CE148E9D4AA627289B650917B35BC180F3A23D72F50B3782FB27C19D3AB55` |
| SSDEEP | `49152:Vv8ejMjobvYHEnxXr4hurBxogIMJeIScnL/XWyi+oKKcwIW:VvZ5X4urBx5lBScnL/XWTNcwB` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_053_52ebf274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52ebf27411484098f4643ea8d0d4ca154d66e78de8121d0809ccb437d9f8eeed"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-13 21:08:18"
  condition:
    hash.sha256(0, filesize) == "52ebf27411484098f4643ea8d0d4ca154d66e78de8121d0809ccb437d9f8eeed"
}
```

### Sample 54: `8aa914b8fa0f9cf9`

| Field | Value |
|---|---|
| SHA-256 | `8aa914b8fa0f9cf953f3cd9a9bcbfa27c43a7b7be8ba39d780fb80eaaf3766ff` |
| Family label | `Vidar` |
| File name | `#Pa$$w0rD__2024--0peɴ_Set-Up!.zip` |
| File type | `zip` |
| First seen | `2026-07-13 21:06:19` |
| Reporter | `iamaachum` |
| Tags | `193-24-123-38, HijackLoader, IDATLoader, pw-2024, SnappyClient, Vidar, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4faa5a640a510a889c794892bd35a8fa` |
| SHA-1 | `acb5bb5a847851b6d4f88dafe877a83aa4b418a0` |
| SHA-256 | `8aa914b8fa0f9cf953f3cd9a9bcbfa27c43a7b7be8ba39d780fb80eaaf3766ff` |
| SHA3-384 | `b87b5a6f759d0d6fdd0915e13f5b3c39e08b3810820c2e540787f395d170486109190332ca5bf485530be2d3a614487d` |
| TLSH | `T1F3C73375AB5A110DE74AAF7AE449235DE4F0960ECFB1BD0F9E6810807C923F59F06913` |
| SSDEEP | `1572864:1QMQNr1kuwU9EknWcgOyy/e5SP6XQGEP9Xc:6MQNrOdUKSWT//5SCXlEPdc` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_054_8aa914b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8aa914b8fa0f9cf953f3cd9a9bcbfa27c43a7b7be8ba39d780fb80eaaf3766ff"
    family = "Vidar"
    file_name = "#Pa$$w0rD__2024--0peɴ_Set-Up!.zip"
    file_type = "zip"
    first_seen = "2026-07-13 21:06:19"
  condition:
    hash.sha256(0, filesize) == "8aa914b8fa0f9cf953f3cd9a9bcbfa27c43a7b7be8ba39d780fb80eaaf3766ff"
}
```

### Sample 55: `8e97301bed92f00d`

| Field | Value |
|---|---|
| SHA-256 | `8e97301bed92f00dbd667e65c4e10f7c5d53789eeff64fb067c13a7b66985a48` |
| Family label | `PureLogsStealer` |
| File name | `cxx.hta` |
| File type | `hta` |
| First seen | `2026-07-13 21:06:01` |
| Reporter | `abuse_ch` |
| Tags | `hta, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80413e594c109940b980c2b9c0341f89` |
| SHA-1 | `6a40d6cd9aef9ca7c441d268139666a4da07472d` |
| SHA-256 | `8e97301bed92f00dbd667e65c4e10f7c5d53789eeff64fb067c13a7b66985a48` |
| SHA3-384 | `23de977a2d0669f130423ea465fd651e543036a14ff76380ae3f32460e968e5f9f6a6b234a637cb6c681c1bea9dec998` |
| TLSH | `T1D303096EADC0E4125ECEA175489DE9E33AD6CE4C3521B97D786C03E34BA44B73D6260C` |
| SSDEEP | `192:f5VKQoMhQMHjMrqUKQFUKxCMBx0W0b0E0Q0y0s0z03u0h0JKQHMGKQjb3MhySKQO:f5joM6MDMpF4MbHM6jzMPjSj4MFp` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_055_8e97301b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e97301bed92f00dbd667e65c4e10f7c5d53789eeff64fb067c13a7b66985a48"
    family = "PureLogsStealer"
    file_name = "cxx.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:06:01"
  condition:
    hash.sha256(0, filesize) == "8e97301bed92f00dbd667e65c4e10f7c5d53789eeff64fb067c13a7b66985a48"
}
```

### Sample 56: `5536939f5e284524`

| Field | Value |
|---|---|
| SHA-256 | `5536939f5e284524a0ee5f1fe401ac92237e4fb013b8c5adfc5b84d3b6d95017` |
| Family label | `Vidar` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-07-13 21:03:42` |
| Reporter | `iamaachum` |
| Tags | `exe, micronsoftwares-com, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `caeabf7b665b7c9e38ca0dc7788c9a2e` |
| SHA-1 | `35d8ee05bace89a278cfd9f7eb6ce625b27c002f` |
| SHA-256 | `5536939f5e284524a0ee5f1fe401ac92237e4fb013b8c5adfc5b84d3b6d95017` |
| SHA3-384 | `25acf459fd8d402333e3585937744ade346583559e9fb5886a81aef0a9ec50ba763da0644481bf65f4cf56886cb6441e` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T107E59D077CE248E9D49E633289B251927B35BC190F3A23D72E50BA783E36BD09D35B45` |
| SSDEEP | `49152:JR5W2I0EUxlVC+TatRp96qDL4IkhaAKijNTWNkamSyGmG9fI/G:JRr/TG5iCiZTWNkT9GmGlN` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_056_5536939f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5536939f5e284524a0ee5f1fe401ac92237e4fb013b8c5adfc5b84d3b6d95017"
    family = "Vidar"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:03:42"
  condition:
    hash.sha256(0, filesize) == "5536939f5e284524a0ee5f1fe401ac92237e4fb013b8c5adfc5b84d3b6d95017"
}
```

### Sample 57: `c73c47b851402122`

| Field | Value |
|---|---|
| SHA-256 | `c73c47b85140212238b5fa19dd5753ac0962c03df4c2bb4afbf25e43c23a2d0b` |
| Family label | `RemcosRAT` |
| File name | `givemebestthingswithbestprocssionthigns.hta` |
| File type | `hta` |
| First seen | `2026-07-13 21:02:59` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01056cfcb7496b040d87a1a2dc92a66f` |
| SHA-1 | `8ec8005b9ee19c4f457fbd53a811fed8dbe1510f` |
| SHA-256 | `c73c47b85140212238b5fa19dd5753ac0962c03df4c2bb4afbf25e43c23a2d0b` |
| SHA3-384 | `e98e71d636689c858004d12c6d724057f20353feb13dbe1ab3c4bcb6ed61075686acfa0f8469d4dc8ca13214720502ba` |
| TLSH | `T11E03D87EE334EF7E8BE6D5A4802C5ED098B5C576F8588610B6ACC1633BF8119CE24274` |
| SSDEEP | `96:KQ27xsUneBln0BdnZBGBNxgqB9BLntbTKoMWcnUxCUx3UxDUxrUxUKoMWcIUx7U4:KZcINw3DLXSWUL28YaWLUjQexYXEVZDX` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_057_c73c47b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c73c47b85140212238b5fa19dd5753ac0962c03df4c2bb4afbf25e43c23a2d0b"
    family = "RemcosRAT"
    file_name = "givemebestthingswithbestprocssionthigns.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:02:59"
  condition:
    hash.sha256(0, filesize) == "c73c47b85140212238b5fa19dd5753ac0962c03df4c2bb4afbf25e43c23a2d0b"
}
```

### Sample 58: `48dbf74443280fa3`

| Field | Value |
|---|---|
| SHA-256 | `48dbf74443280fa3f68e0cb00c2c482f5692428b56c95f44ee0246aab27e3cd6` |
| Family label | `RemcosRAT` |
| File name | `bissbetnetorkingmarketthingscomingfor.hta` |
| File type | `hta` |
| First seen | `2026-07-13 21:01:02` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3742ad85877e2c70bb25b59b0c38434a` |
| SHA-1 | `472759fc8cd4edcbf29dff9abb209ba9e8fe1b4b` |
| SHA-256 | `48dbf74443280fa3f68e0cb00c2c482f5692428b56c95f44ee0246aab27e3cd6` |
| SHA3-384 | `c70476876695560b1db6b84476f39013aba417d35e8c6804c62da07962549e368bd229b4049b04b84678f8069fa7f03a` |
| TLSH | `T14D031B77C1885CD7846640BACC1EEEFA3007099E100105B8FDEE1DE5732B16B5A7ABAD` |
| SSDEEP | `192:r3w87eSepeVcww2eIoNoeMQwoejcJWULyoTwewXedG:r3F7LIqc12hoNovQD4cIULyoTdgAG` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_058_48dbf744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48dbf74443280fa3f68e0cb00c2c482f5692428b56c95f44ee0246aab27e3cd6"
    family = "RemcosRAT"
    file_name = "bissbetnetorkingmarketthingscomingfor.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:01:02"
  condition:
    hash.sha256(0, filesize) == "48dbf74443280fa3f68e0cb00c2c482f5692428b56c95f44ee0246aab27e3cd6"
}
```

### Sample 59: `d39142fd261676d1`

| Field | Value |
|---|---|
| SHA-256 | `d39142fd261676d1c0ef0b817c44afddc800f6e7b3b1ffa2f2d9a27f548a5095` |
| Family label | `PureLogsStealer` |
| File name | `cxc.hta` |
| File type | `hta` |
| First seen | `2026-07-13 20:58:54` |
| Reporter | `abuse_ch` |
| Tags | `hta, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02d68788bbd86f7df4c18ba9fbdf80ac` |
| SHA-1 | `c842bcbd2fcc07f1a51f6233c00f9c6b16910352` |
| SHA-256 | `d39142fd261676d1c0ef0b817c44afddc800f6e7b3b1ffa2f2d9a27f548a5095` |
| SHA3-384 | `58850b886b631911136ddb7dd5f3c123338e4c1d61638faa189ce227b1e5c6c69865c7936d9a411b0fdeadbb81c02bf7` |
| TLSH | `T18603DA783D808D62579222E50A569E3561F24F5C76480C3CBEFD813A9324C6A5F677CE` |
| SSDEEP | `384:fF1VVnOKVrFTCvSu9wkv4V723+V65VfRFdqVKVeFiFYqVp:9gUEV` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_059_d39142fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d39142fd261676d1c0ef0b817c44afddc800f6e7b3b1ffa2f2d9a27f548a5095"
    family = "PureLogsStealer"
    file_name = "cxc.hta"
    file_type = "hta"
    first_seen = "2026-07-13 20:58:54"
  condition:
    hash.sha256(0, filesize) == "d39142fd261676d1c0ef0b817c44afddc800f6e7b3b1ffa2f2d9a27f548a5095"
}
```

### Sample 60: `de561c4a3b59f035`

| Field | Value |
|---|---|
| SHA-256 | `de561c4a3b59f0351d866721a5a204bb9c1396f5a2b4d9140f7385b0c2ea102d` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-13 20:44:59` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX5.file, signed, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e82a85c73e02ad9fa4d8e5d60c2e8be4` |
| SHA-1 | `c0b978b82ab3159467feaf61bee001381317e75e` |
| SHA-256 | `de561c4a3b59f0351d866721a5a204bb9c1396f5a2b4d9140f7385b0c2ea102d` |
| SHA3-384 | `cfe9303e91bed8aa319768dd52dc9bf4c6d72d1e021c88b7d5ae99f9632cb1bbe1e75260d724efa8bde326d03b3fbf34` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1B5C57E01FCD349B5E802323259E7727F7335AC051F399B97DA547EB9AA3B291182B309` |
| SSDEEP | `49152:UGrnB4Fm4OH8v6nAxWlhIZHeOYP/gbsHM3z:h94FuBlhQH4PDHMD` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_060_de561c4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de561c4a3b59f0351d866721a5a204bb9c1396f5a2b4d9140f7385b0c2ea102d"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-13 20:44:59"
  condition:
    hash.sha256(0, filesize) == "de561c4a3b59f0351d866721a5a204bb9c1396f5a2b4d9140f7385b0c2ea102d"
}
```

### Sample 61: `d9824b3a6894de06`

| Field | Value |
|---|---|
| SHA-256 | `d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e` |
| Family label | `RemusStealer` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-07-13 19:52:17` |
| Reporter | `iamaachum` |
| Tags | `AsgardProtector, dropped-by-OffLoader, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fa9ff04979f656ba3975f6ec98efcba` |
| SHA-1 | `5203a18ead55b15a7cfba434fcdbbd7281de8fe1` |
| SHA-256 | `d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e` |
| SHA3-384 | `ce1bd206deefe5a610675c8795b6c2381c5ca13d4bb16a274f7c5ef0646ffd4707d76c90a821f771bd8465a8d7d3107f` |
| IMPHASH | `646167cce332c1c252cdcb1839e0cf48` |
| TLSH | `T1C165232246E48517E6A40FF408FA42A30531BCE2577A91FF33C69D4C1567BE1663A3FA` |
| SSDEEP | `24576:2vj0f+jhnPvPy/8tdGag0q3DAu/33bwRu+Yb6mQR5+b4qcNcjXT/:sgWjhX+8tdS0qZ8Eh6mQR56eaXT` |
| ICON-DHASH | `63000208000a1a10` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_061_d9824b3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e"
    family = "RemusStealer"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-13 19:52:17"
  condition:
    hash.sha256(0, filesize) == "d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e"
}
```

### Sample 62: `627a15798107d91a`

| Field | Value |
|---|---|
| SHA-256 | `627a15798107d91a19c04b691c85f8aa09f131d155e98c1a681edd21e9bea0f8` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-13 19:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3300bfc707c48bfeb577a5afa19a4f5a` |
| SHA-1 | `a0e35fa95e6e84e9f731542787a2f29694ae5531` |
| SHA-256 | `627a15798107d91a19c04b691c85f8aa09f131d155e98c1a681edd21e9bea0f8` |
| SHA3-384 | `773f622ec1893f49dcb3ac050e274d753fa2ce38aa30d2920ef490f35e854513300a7ae03204b544585803be77924ebc` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T198E6332469D016FEE963413CEC636962E5E5B8B60F32C9DB671483663E170E06DBD323` |
| SSDEEP | `393216:yi4pl6J+YmMrQ5HOwbV7o0/K81wOUUXMCHWUjXUcuI3/PGTAI:yL6TmMk5HOAVM98FfXMb8XBH/O7` |
| ICON-DHASH | `f8f8f8f8f8f8e0c0` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_062_627a1579
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "627a15798107d91a19c04b691c85f8aa09f131d155e98c1a681edd21e9bea0f8"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 19:52:10"
  condition:
    hash.sha256(0, filesize) == "627a15798107d91a19c04b691c85f8aa09f131d155e98c1a681edd21e9bea0f8"
}
```

### Sample 63: `2c6011645daa6ea1`

| Field | Value |
|---|---|
| SHA-256 | `2c6011645daa6ea192a6a23ef564753e20b4f65e7b90b7e202ff84a835fcdc27` |
| Family label | `AgentTesla` |
| File name | `MT103.JS` |
| File type | `js` |
| First seen | `2026-07-13 19:47:42` |
| Reporter | `James_inthe_box` |
| Tags | `AgentTesla, exe, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd960fcde32eb18f1b2e0a3adcf999f2` |
| SHA-1 | `9b3bcee35529ab8dbff186c748c29df2f0455de8` |
| SHA-256 | `2c6011645daa6ea192a6a23ef564753e20b4f65e7b90b7e202ff84a835fcdc27` |
| SHA3-384 | `6d1839443e8cf509e015cd900b09031edd2487a58b54be5fd2d25fb529c0137755db23545eefd8633c54fc21919c8f80` |
| TLSH | `T14EE5295295E862233320FBED962DDE38940EE4432D198F54798EEB387D2CF89E214757` |
| SSDEEP | `98304:sQmBnsiupkZ3h/1/P174AMoQLb302UgFAdF8e2n+Ft33x5yU3vF0yunBE644uNJH:GBns3pkZh/1/P174AMoQLb302UgFAdFT` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_063_2c601164
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c6011645daa6ea192a6a23ef564753e20b4f65e7b90b7e202ff84a835fcdc27"
    family = "AgentTesla"
    file_name = "MT103.JS"
    file_type = "js"
    first_seen = "2026-07-13 19:47:42"
  condition:
    hash.sha256(0, filesize) == "2c6011645daa6ea192a6a23ef564753e20b4f65e7b90b7e202ff84a835fcdc27"
}
```

### Sample 64: `81c589fae253795f`

| Field | Value |
|---|---|
| SHA-256 | `81c589fae253795f2a6625709d192409df2349b929b3ea692b8ea3af08767ffd` |
| Family label | `AgentTesla` |
| File name | `CTM.exe` |
| File type | `exe` |
| First seen | `2026-07-13 19:46:52` |
| Reporter | `James_inthe_box` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eaff05ace23686b52695ea35367725fd` |
| SHA-1 | `3f81b9e39a7a60bd964308548dda75c1d7bc4350` |
| SHA-256 | `81c589fae253795f2a6625709d192409df2349b929b3ea692b8ea3af08767ffd` |
| SHA3-384 | `58e699ddfdaeed8ae19e4de50afe5ac517ba18e2b0d7f533b518fc49294bc424191e1473c6fe0fa8f691d2b64faf835b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T10D45F1256A866A56CB3E0B74C026488823F0CD52AA77E71F3EEDB0F85B737C52D17452` |
| SSDEEP | `24576:uO02UxAPqGcv/+Duyx42IPOr+e4ggVq3XOI0Nd:uFqPRcvEnyggiXOIO` |
| ICON-DHASH | `39f8d894f2d8cc62` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_064_81c589fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81c589fae253795f2a6625709d192409df2349b929b3ea692b8ea3af08767ffd"
    family = "AgentTesla"
    file_name = "CTM.exe"
    file_type = "exe"
    first_seen = "2026-07-13 19:46:52"
  condition:
    hash.sha256(0, filesize) == "81c589fae253795f2a6625709d192409df2349b929b3ea692b8ea3af08767ffd"
}
```

### Sample 65: `1caafa7cb71ac850`

| Field | Value |
|---|---|
| SHA-256 | `1caafa7cb71ac8506fae18f174afbe3594c47d18a5a1f2976b16abf0191f5c1a` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-13 19:23:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5344f49920d27358cf85af76ed438bd8` |
| SHA-1 | `545eb952dfad2fc7b85e8f00e4ed5edd1d28821f` |
| SHA-256 | `1caafa7cb71ac8506fae18f174afbe3594c47d18a5a1f2976b16abf0191f5c1a` |
| SHA3-384 | `2cd2096d5889dbdfe486410b3b18445754c341a55162fb5483c2c2022d59fedd27139b914815eb62d0c905089a94a6ce` |
| TLSH | `T131C312848A2D95F881CB66B5301D1336554C61D1770A632F7BE28EC263747DBFA0CDAB` |
| SSDEEP | `1536:V6hcH3oye3ACx1oMA+wZIUGxho8cIGVFih5/TCFUgXut5tCO2i76tFjoNcqeFt0Y:V6hJH3Pc4g1VFizEUGK5t7L6jB0Y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_1caafa7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1caafa7cb71ac8506fae18f174afbe3594c47d18a5a1f2976b16abf0191f5c1a"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-13 19:23:58"
  condition:
    hash.sha256(0, filesize) == "1caafa7cb71ac8506fae18f174afbe3594c47d18a5a1f2976b16abf0191f5c1a"
}
```

### Sample 66: `cf21abb094564456`

| Field | Value |
|---|---|
| SHA-256 | `cf21abb094564456f930a36e5276b1a7e70290c91c04058c603fd14a078d1c56` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-13 19:21:55` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89f1489da995dedb3a96144d7095a8d8` |
| SHA-1 | `a1b28cd1addf6161fd9e34fb8299737698161abe` |
| SHA-256 | `cf21abb094564456f930a36e5276b1a7e70290c91c04058c603fd14a078d1c56` |
| SHA3-384 | `11b4fb9ae409308901ff0edb976bb73308995b43b99e91c96783917e43bf91afae361bbab4fe44abda600db5145c8e75` |
| TLSH | `T145C27D966A867C44BEC98A3E4CBD2B0D6DF5C3D1324942AC3D4B3C719C15FACD618B1A` |
| SSDEEP | `768:R8vCB+25j6es8RF9FYpMSUpi+20qUpi+20YQX:R8l25Jjd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_cf21abb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf21abb094564456f930a36e5276b1a7e70290c91c04058c603fd14a078d1c56"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-13 19:21:55"
  condition:
    hash.sha256(0, filesize) == "cf21abb094564456f930a36e5276b1a7e70290c91c04058c603fd14a078d1c56"
}
```

### Sample 67: `4bff43d7576d4b03`

| Field | Value |
|---|---|
| SHA-256 | `4bff43d7576d4b037cae2af1eedffb2c09d19211312d2920db6e840c8528a1ad` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-13 19:19:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac4f59c2ef55f8e7273a0184f0120351` |
| SHA-1 | `c922c060d80564fe405c9f0d934b92f952e3ac88` |
| SHA-256 | `4bff43d7576d4b037cae2af1eedffb2c09d19211312d2920db6e840c8528a1ad` |
| SHA3-384 | `e39d5e120b934b3c4ce8a48a2f7f0404b3dd87189eef2fc2900d3f4cc98ba18d02fd773a60192863106a0b4cde3c6fac` |
| TLSH | `T1A6C31210CA559B6DF1F2067C2388B76BE1306B6A1350EDCA136BD3D73A2E081B6B7174` |
| SSDEEP | `1536:gnLxtt+jNe7Wf9jzuLwtJefHbZ3bFmkBc/mYwCHt/53h5EVSB:29/+jwWF/l7MHbZrFmKcOit/53jEVK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_4bff43d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bff43d7576d4b037cae2af1eedffb2c09d19211312d2920db6e840c8528a1ad"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-13 19:19:54"
  condition:
    hash.sha256(0, filesize) == "4bff43d7576d4b037cae2af1eedffb2c09d19211312d2920db6e840c8528a1ad"
}
```

### Sample 68: `1d08b5a056f3e2d9`

| Field | Value |
|---|---|
| SHA-256 | `1d08b5a056f3e2d966fcadda088946c760f69b30cb578be619abddc27803c7e8` |
| Family label | `unknown` |
| File name | `bundle.tar` |
| File type | `tar` |
| First seen | `2026-07-13 19:17:41` |
| Reporter | `skocherhan` |
| Tags | `curl-t-com, tar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bcb2d9fed62f007d35999ceb884a7a7` |
| SHA-1 | `3d9e727e26c450913785d74ca3c534f2cf1019da` |
| SHA-256 | `1d08b5a056f3e2d966fcadda088946c760f69b30cb578be619abddc27803c7e8` |
| SHA3-384 | `907fe74e2bb9a4c055d1d0883699eaaa7f75ef59e3e4a8dc73fc09b4bb14c510c84b84ee943f78c353f5d53d452b0118` |
| TLSH | `T145B57C03E69580BDC06BC170875B9773FA31F8490234BA5F6798DB212F25FA09B2E759` |
| SSDEEP | `49152:70uLZnkcL/tZPhoR6WpCQAQlx1QBPfkkNWPZs1qXLVVzCdf:7vrPQSBX4Dq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `tar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_1d08b5a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d08b5a056f3e2d966fcadda088946c760f69b30cb578be619abddc27803c7e8"
    family = "unknown"
    file_name = "bundle.tar"
    file_type = "tar"
    first_seen = "2026-07-13 19:17:41"
  condition:
    hash.sha256(0, filesize) == "1d08b5a056f3e2d966fcadda088946c760f69b30cb578be619abddc27803c7e8"
}
```

### Sample 69: `8602256dc0387297`

| Field | Value |
|---|---|
| SHA-256 | `8602256dc03872979558ef52ba97e43aebdfb866088b95dec044987b7a7c60f3` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-13 19:09:53` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cca89f9d4f5e6bf767464943d77cc37` |
| SHA-1 | `ab2b36167a59e6663257e132a9e9473d35cb4ede` |
| SHA-256 | `8602256dc03872979558ef52ba97e43aebdfb866088b95dec044987b7a7c60f3` |
| SHA3-384 | `a7e76b4fc054668dbf3b61f553ae1e4d1e381c47cdd7ef670d860e46bd67d7bcf50b922d58ae41433bd46a1cd1b43ae1` |
| TLSH | `T10BB3125651145FB8CCFBEA765D0363B8863B73BD8B63A2AB0220CE3D44C9C53DD26856` |
| SSDEEP | `3072:osN34BgN9TT0Zp+Dobveet2ChtJ/K/vZFI4:5NkgHTloJzDJ/yf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_8602256d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8602256dc03872979558ef52ba97e43aebdfb866088b95dec044987b7a7c60f3"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-13 19:09:53"
  condition:
    hash.sha256(0, filesize) == "8602256dc03872979558ef52ba97e43aebdfb866088b95dec044987b7a7c60f3"
}
```

### Sample 70: `3c137b5aa7f4ebd9`

| Field | Value |
|---|---|
| SHA-256 | `3c137b5aa7f4ebd915927ada5c1a201d0dbf3d482a2048791ac60d349167db74` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-13 19:02:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6aa73566cc270fdf4e816150a528fb39` |
| SHA-1 | `68897f2e2ff9c6ba65ca88a09da7645fc4a1b467` |
| SHA-256 | `3c137b5aa7f4ebd915927ada5c1a201d0dbf3d482a2048791ac60d349167db74` |
| SHA3-384 | `c1ec037277d141d2086d2c066d7638ca633e29e78ef20847396c5fd4edfae1a523835c91a8b52bcf46b3788e77ec0eb2` |
| TLSH | `T1E1331895FD41AA12C6C1157BFF0F828D77264398E2EF7303AA256F20369786B0E3B545` |
| TELFHASH | `t123b01220484814ac4082002341c44d23b184b3543c5c2e320214a09d01334c64013818` |
| SSDEEP | `768:zOSSiI9lNMwwVVQGkbof3UMhVkwkleEOMyYiwDyW61bjpPPnWmjngRbI:YiIKLpVhV+eEOMZDJ6HnLbgRb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_3c137b5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c137b5aa7f4ebd915927ada5c1a201d0dbf3d482a2048791ac60d349167db74"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-13 19:02:01"
  condition:
    hash.sha256(0, filesize) == "3c137b5aa7f4ebd915927ada5c1a201d0dbf3d482a2048791ac60d349167db74"
}
```

### Sample 71: `5238b57ce76064b9`

| Field | Value |
|---|---|
| SHA-256 | `5238b57ce76064b977a6d5800f00f4120d795381f12fab93c7491997de6cfe67` |
| Family label | `ConnectWise` |
| File name | `screenconnect.clientservice.exe` |
| File type | `exe` |
| First seen | `2026-07-13 19:00:03` |
| Reporter | `SquiblydooBlog` |
| Tags | `ConnectWise, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb864ece91436663c54d926996958e12` |
| SHA-1 | `7817bbc1fce9863bb4f9a8214ba5a84423331d3f` |
| SHA-256 | `5238b57ce76064b977a6d5800f00f4120d795381f12fab93c7491997de6cfe67` |
| SHA3-384 | `9afc93d345da2df415f0dcfd5dcdec68c4ad790c1b2d7f8e71772b8c8ac3b62ecb9b8b2b22292aab3293d2f03bd13b66` |
| IMPHASH | `5f510e22d141c137199e2ff4021a57be` |
| TLSH | `T17B935B13B5C28472E573093158E0DAA09A3FF9215E61DEAB3798032E4F642C1BE75E77` |
| SSDEEP | `1536:Kg1s9pgbNBAklbZfe2+zRVdHeDxGXAorrCnBsWBcd6myJkgsT0HMgdYU:LhbNDxZGXfdHrX7rAc6myJkgsT0Hh7` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_071_5238b57c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5238b57ce76064b977a6d5800f00f4120d795381f12fab93c7491997de6cfe67"
    family = "ConnectWise"
    file_name = "screenconnect.clientservice.exe"
    file_type = "exe"
    first_seen = "2026-07-13 19:00:03"
  condition:
    hash.sha256(0, filesize) == "5238b57ce76064b977a6d5800f00f4120d795381f12fab93c7491997de6cfe67"
}
```

### Sample 72: `9b9f01a45caf0aa8`

| Field | Value |
|---|---|
| SHA-256 | `9b9f01a45caf0aa8968ae28849b1034616dbd3f578a01fa2ecab926be9c1a5d8` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-13 18:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `506b8b08b9043d3be86a8f4793a2feb5` |
| SHA-1 | `08f0e4b3560a94939d9d1696096aa3e5f2fcd9d2` |
| SHA-256 | `9b9f01a45caf0aa8968ae28849b1034616dbd3f578a01fa2ecab926be9c1a5d8` |
| SHA3-384 | `065618bbdf81e0ff0a62ad88d41cefba50d2e05c751b50472c417228c8d19b5fed64d9a31e480206c8f155f7d5b9aa23` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1E3E633082AD005FEE4B3517DF9A28162D6B478BA47B2C5CF1F84C259BD071E14E3E6A7` |
| SSDEEP | `393216:OKrO5v2ECmoSTL2PEhmSoHhU3poV7Bwm9kuIXMCHWUjXXcuI3/PGTAI:OKMrivPNhUZoFBwwIXMb8XsH/O7` |
| ICON-DHASH | `30f1f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_072_9b9f01a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b9f01a45caf0aa8968ae28849b1034616dbd3f578a01fa2ecab926be9c1a5d8"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 18:52:09"
  condition:
    hash.sha256(0, filesize) == "9b9f01a45caf0aa8968ae28849b1034616dbd3f578a01fa2ecab926be9c1a5d8"
}
```

### Sample 73: `1528fbea80a84107`

| Field | Value |
|---|---|
| SHA-256 | `1528fbea80a84107c096ea816c078b98150a36a2f1735772b6544e0fad063849` |
| Family label | `unknown` |
| File name | `full_aes.pyw` |
| File type | `pyw` |
| First seen | `2026-07-13 18:50:43` |
| Reporter | `KaiErikNiermann` |
| Tags | `AES-loader, clipper, hvnc, py, pyAdmin2, python, pyw, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d337f572afd9f3de1a5786d1dd90366d` |
| SHA-1 | `23e2939ee1c36ee56d205793fc9a7c7ff84384a1` |
| SHA-256 | `1528fbea80a84107c096ea816c078b98150a36a2f1735772b6544e0fad063849` |
| SHA3-384 | `20572fd5cfd2ac43fd172958a80e4edf831d92af16cd57de138108674f532b0aefeeb0ad36cf4f04ed620aee88067d53` |
| TLSH | `T1B0B42308BFF50DBAC30857A8719FA68D8BA70D1016E4BE9716C1A5479BB9F4BC03361D` |
| SSDEEP | `12288:bwD5oFeQCtz1oCv2I5YaU6c1gXJRkxPrMKF:09RJ2Oxd5KjMKF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `pyw`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_1528fbea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1528fbea80a84107c096ea816c078b98150a36a2f1735772b6544e0fad063849"
    family = "unknown"
    file_name = "full_aes.pyw"
    file_type = "pyw"
    first_seen = "2026-07-13 18:50:43"
  condition:
    hash.sha256(0, filesize) == "1528fbea80a84107c096ea816c078b98150a36a2f1735772b6544e0fad063849"
}
```

### Sample 74: `71fbffcbab0e585a`

| Field | Value |
|---|---|
| SHA-256 | `71fbffcbab0e585ae33ff277a076366955661e39fee25b62c9f59392263025b3` |
| Family label | `unknown` |
| File name | `request.vbs` |
| File type | `vbs` |
| First seen | `2026-07-13 18:50:39` |
| Reporter | `KaiErikNiermann` |
| Tags | `ClickFix, dropper, pyAdmin2, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b35ee8435fff328b3b7b4be7e94c5f8` |
| SHA-1 | `c4db4f01f13e2074b5367959119736ac5f7ea0a5` |
| SHA-256 | `71fbffcbab0e585ae33ff277a076366955661e39fee25b62c9f59392263025b3` |
| SHA3-384 | `0d92193913e12b9d8c5c99df19e139e67d893c1c0232d039ef3515785ed1200915635b0bf8a76631bdc591c3dd6c6072` |
| TLSH | `T13491FE0B7922E0B4443116EE6A1E742DD66285BF4600445E7D7C44DE4F3EB7ED2682EF` |
| SSDEEP | `96:ykjVUKd4WE/RlPj6LacSmt/eEje3kJsTNaFr/Q:9RvE/XPmt/XarQB/Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_71fbffcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71fbffcbab0e585ae33ff277a076366955661e39fee25b62c9f59392263025b3"
    family = "unknown"
    file_name = "request.vbs"
    file_type = "vbs"
    first_seen = "2026-07-13 18:50:39"
  condition:
    hash.sha256(0, filesize) == "71fbffcbab0e585ae33ff277a076366955661e39fee25b62c9f59392263025b3"
}
```

### Sample 75: `6ab43460e36b904d`

| Field | Value |
|---|---|
| SHA-256 | `6ab43460e36b904dad331bb3b59cb2a341539b63af791013b2163e5bab8b85a4` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-13 18:47:53` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ad8c68e6389feb708b852d37da31334` |
| SHA-1 | `a698dc2b5385cf74ad7e70362e54059c8cdb6fbd` |
| SHA-256 | `6ab43460e36b904dad331bb3b59cb2a341539b63af791013b2163e5bab8b85a4` |
| SHA3-384 | `dca8cf016f8deadd163ef926df424a249d85c0a174babbba34ab0d4198325ec62cdd748b7ecb654e63d9768135287384` |
| TLSH | `T1D4C3120F8173B07AEA37757852A69F05F3323D234226843FA9F0722DF5B96759620385` |
| SSDEEP | `3072:Y/SrSyKmhOynFNhVzOPWIMjCCLxTKEQtlT:MNahDAziVd8DT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_6ab43460
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ab43460e36b904dad331bb3b59cb2a341539b63af791013b2163e5bab8b85a4"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-13 18:47:53"
  condition:
    hash.sha256(0, filesize) == "6ab43460e36b904dad331bb3b59cb2a341539b63af791013b2163e5bab8b85a4"
}
```

### Sample 76: `c5208ea8562b3627`

| Field | Value |
|---|---|
| SHA-256 | `c5208ea8562b3627eded9f9ea09290d132c29fcf8046061d37069056d1128890` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-13 18:45:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e94a5f067de835076a8f178cf59c53d6` |
| SHA-1 | `a30f8433e27eac5c1f81c3934dbe8902c9f94c40` |
| SHA-256 | `c5208ea8562b3627eded9f9ea09290d132c29fcf8046061d37069056d1128890` |
| SHA3-384 | `40a692c0dce4cd9aa5619303bb10b5b11ad9fc87325a0cb20d4938ed2bc91cff51adf97c51e0ef3c6756e3889f99ce3b` |
| TLSH | `T10EB3124C29356D13FF11D9388A9507B7F6F58E1ABE457A84605080C28F667C8AC8EFED` |
| SSDEEP | `3072:ginlm1hxqIAekxiVVqHcY7BEddnj91xAVI:9nouekxqFYSHoI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_c5208ea8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5208ea8562b3627eded9f9ea09290d132c29fcf8046061d37069056d1128890"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-13 18:45:55"
  condition:
    hash.sha256(0, filesize) == "c5208ea8562b3627eded9f9ea09290d132c29fcf8046061d37069056d1128890"
}
```

### Sample 77: `e7f36ff4274b1fa4`

| Field | Value |
|---|---|
| SHA-256 | `e7f36ff4274b1fa4afb48a002b85aed82d788a399b0db3d5a4e886238777fb37` |
| Family label | `unknown` |
| File name | `Document.lnk` |
| File type | `lnk` |
| First seen | `2026-07-13 18:45:44` |
| Reporter | `smica83` |
| Tags | `lnk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba109362e9a98b65761041a92f46e9d1` |
| SHA-1 | `6a30740ca02c1aa44fe00e511348614245346bfc` |
| SHA-256 | `e7f36ff4274b1fa4afb48a002b85aed82d788a399b0db3d5a4e886238777fb37` |
| SHA3-384 | `2f8620ce6135a1b50b9ae0dccd7689fb189fdb9d455751b84ccc64bb0a085a803f020f959de4b5422492ba87027e555f` |
| TLSH | `T1E2232912CE9F2D40CB6842BBA1CF05E5195D079F32A20DCF269BF740EE5B4B521D5AE4` |
| SSDEEP | `768:wSN7u11CTYLfuI1XrhCZDx2HT7TKjntRqoRs0WQS90i73ErsOToBZE06/6DL5z3:wv40LfuI1bhCZduGjnrxS90i70TiZE0L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `lnk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_e7f36ff4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7f36ff4274b1fa4afb48a002b85aed82d788a399b0db3d5a4e886238777fb37"
    family = "unknown"
    file_name = "Document.lnk"
    file_type = "lnk"
    first_seen = "2026-07-13 18:45:44"
  condition:
    hash.sha256(0, filesize) == "e7f36ff4274b1fa4afb48a002b85aed82d788a399b0db3d5a4e886238777fb37"
}
```

### Sample 78: `fd1f37c361549bbc`

| Field | Value |
|---|---|
| SHA-256 | `fd1f37c361549bbcc18cbc17a40bb571dc3ba1703e517c9816b8e4452543666b` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-13 18:42:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29b96de24e7b9808eb419625d5587331` |
| SHA-1 | `025f482a5ad9505f73914160f674624a77668167` |
| SHA-256 | `fd1f37c361549bbcc18cbc17a40bb571dc3ba1703e517c9816b8e4452543666b` |
| SHA3-384 | `406bddf9a2890d6e174d37c57dc7edf3be155a8be726d7d45976fae973023e5381a605a9fbcacb229e0811820485d040` |
| TLSH | `T163C27D956A867C44BEC94A3E8CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:Mk8vCB+25j6es8RB9FYpMSUpi+20qUpi+20YQX:Mk8l25J3d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_fd1f37c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd1f37c361549bbcc18cbc17a40bb571dc3ba1703e517c9816b8e4452543666b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-13 18:42:54"
  condition:
    hash.sha256(0, filesize) == "fd1f37c361549bbcc18cbc17a40bb571dc3ba1703e517c9816b8e4452543666b"
}
```

### Sample 79: `ed57f128d6f463da`

| Field | Value |
|---|---|
| SHA-256 | `ed57f128d6f463dac2a6975006a7100cb8978167ce422398e1d4e4b7fe40f934` |
| Family label | `unknown` |
| File name | `Untitled Document.lnk` |
| File type | `lnk` |
| First seen | `2026-07-13 18:40:24` |
| Reporter | `smica83` |
| Tags | `lnk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b938ed556ebe2affa6715de612ccce0f` |
| SHA-1 | `65ac5bf8a90fe3b5b06f60326b7c1989d64dd1ca` |
| SHA-256 | `ed57f128d6f463dac2a6975006a7100cb8978167ce422398e1d4e4b7fe40f934` |
| SHA3-384 | `cc2c5cc1d04ac7ac22bda393a23e25eab7ab4b76bbe8638a9beef6ad9c01baa30e776d16b671ffc2778ed425d1614541` |
| TLSH | `T13751416E44BEFC10C2E7C373C1BEF3194D2AB48FC664B527426888AC00068D1A5C9AC3` |
| SSDEEP | `48:855IC6G3hHgo4oVdwLCLtSWz/tFK9Uo5A8OADN8+5Mzuzkt8ta8NM:85d6G3SX+hSGVFK9Z5A8OA5t3A8tacM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `lnk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_ed57f128
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed57f128d6f463dac2a6975006a7100cb8978167ce422398e1d4e4b7fe40f934"
    family = "unknown"
    file_name = "Untitled Document.lnk"
    file_type = "lnk"
    first_seen = "2026-07-13 18:40:24"
  condition:
    hash.sha256(0, filesize) == "ed57f128d6f463dac2a6975006a7100cb8978167ce422398e1d4e4b7fe40f934"
}
```

### Sample 80: `fb53841dd0925261`

| Field | Value |
|---|---|
| SHA-256 | `fb53841dd09252611470ab59b7455cb8a25679ee145d65210ffb179167a6f452` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-13 18:30:59` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe, signed, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5db4d6f453638ed0efa2b0da08bac381` |
| SHA-1 | `c22ae328f8c98b7730ccefdeb0e85085ae7bd84a` |
| SHA-256 | `fb53841dd09252611470ab59b7455cb8a25679ee145d65210ffb179167a6f452` |
| SHA3-384 | `5b17ff9a0977df9bcea50021498848bb9b539d724098527734017d6fc430582a92d6afe734901f7ee9cf6d34e1ed0e17` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T164968C0BBCD148E9C8AA673288B651917B35BC090F3A27D72E60B7382F367D15D36B45` |
| SSDEEP | `49152:fWYBW/GyruukxsBe+mti/AE8n+VM1E9UeAjYaIUbDR:fWYy5e+mdd51YAjYaFbDR` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_080_fb53841d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb53841dd09252611470ab59b7455cb8a25679ee145d65210ffb179167a6f452"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-13 18:30:59"
  condition:
    hash.sha256(0, filesize) == "fb53841dd09252611470ab59b7455cb8a25679ee145d65210ffb179167a6f452"
}
```

### Sample 81: `c08d7b0a6a2c416b`

| Field | Value |
|---|---|
| SHA-256 | `c08d7b0a6a2c416b664182e5715c49ceb62efa0eea3181f684d308a7e1fa3bd1` |
| Family label | `Vidar` |
| File name | `62.60.226.198.exe` |
| File type | `exe` |
| First seen | `2026-07-13 18:29:19` |
| Reporter | `JaffaCakes118` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b35489477782e38489f738b306249cd1` |
| SHA-1 | `c3195fc2bf45567a2a9f55fdb7b4387ffefca328` |
| SHA-256 | `c08d7b0a6a2c416b664182e5715c49ceb62efa0eea3181f684d308a7e1fa3bd1` |
| SHA3-384 | `696133ec281fa66136a30ee4d78fe4da09a5a1f976abe4b12986ace53b68c794a25cecd06c408dcf86d7af4efeea14eb` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1CDE5AE0B6CD108F4D4AAA77288F661917B31BC084F3A27C72E94B7782E727D14E36B55` |
| SSDEEP | `49152:CXOOByJm0EtiISCM0jPmGBbBSQ+mNDhZza+AWqH3FrUDWg9p4BIT2:CXJq1Cf6GBbBB+mNDhMlH3u68eR` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_081_c08d7b0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c08d7b0a6a2c416b664182e5715c49ceb62efa0eea3181f684d308a7e1fa3bd1"
    family = "Vidar"
    file_name = "62.60.226.198.exe"
    file_type = "exe"
    first_seen = "2026-07-13 18:29:19"
  condition:
    hash.sha256(0, filesize) == "c08d7b0a6a2c416b664182e5715c49ceb62efa0eea3181f684d308a7e1fa3bd1"
}
```

### Sample 82: `07d05727718563e2`

| Field | Value |
|---|---|
| SHA-256 | `07d05727718563e2e21b06cc7b92c3c67efaf3b5b978e6f98823ba9e6608d2dd` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-13 18:27:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b02cf0e2480ee061c12b94893ea0e92` |
| SHA-1 | `b7783cc01366627fe798f2b9aca6c8079053fe30` |
| SHA-256 | `07d05727718563e2e21b06cc7b92c3c67efaf3b5b978e6f98823ba9e6608d2dd` |
| SHA3-384 | `20cc18e86b006717d6f6aa9192ec00e3947cee67a581b9d7b8b2b5c056a780c56305527f2b9868600791d16db2544bf7` |
| TLSH | `T160C27D956A867C44BEC98B3E4CBD2B0D6DF5C3D1224942AC3D8A3C719C15FACD618B1A` |
| SSDEEP | `768:ab8vCB+25j6es8RwD9FYpMSUpi+20qUpi+20YQX:W8l25JCd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_07d05727
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07d05727718563e2e21b06cc7b92c3c67efaf3b5b978e6f98823ba9e6608d2dd"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-13 18:27:54"
  condition:
    hash.sha256(0, filesize) == "07d05727718563e2e21b06cc7b92c3c67efaf3b5b978e6f98823ba9e6608d2dd"
}
```

### Sample 83: `179042e8ce848a0d`

| Field | Value |
|---|---|
| SHA-256 | `179042e8ce848a0da871bc39c08f63285971d5c3470dc06fcb987f324d564d36` |
| Family label | `unknown` |
| File name | `launcher.exe` |
| File type | `exe` |
| First seen | `2026-07-13 18:18:25` |
| Reporter | `JaffaCakes118` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b23376e0511c920e54199a577acbde4b` |
| SHA-1 | `c5abb30c93f75efe4ab93cb515d2f59993a76833` |
| SHA-256 | `179042e8ce848a0da871bc39c08f63285971d5c3470dc06fcb987f324d564d36` |
| SHA3-384 | `d1c25b6a7d7fc4e56e515f130a929a133b0fad9e3a7133468bb5ec55831e72b554a699c87917becbc792722680ad6824` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T19F08330851A5C15BC05ACFB1B4F3642152D88DABE1F42DD6E3540A3DB4FEA8860EDB7B` |
| SSDEEP | `1572864:Ct9IKPNwmgsdm42sKrRWYi9oH61M3E3ATXemPC7tssiT0EHN9lRFrZSA7:CUKmmgsn2sKrRWr9oHEUE+umP4WZz6A7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_179042e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "179042e8ce848a0da871bc39c08f63285971d5c3470dc06fcb987f324d564d36"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-07-13 18:18:25"
  condition:
    hash.sha256(0, filesize) == "179042e8ce848a0da871bc39c08f63285971d5c3470dc06fcb987f324d564d36"
}
```

### Sample 84: `07c295310759ecd7`

| Field | Value |
|---|---|
| SHA-256 | `07c295310759ecd7a42fbf3cb96ca1c5b7f45c7e59ac9704b78431000fae5a87` |
| Family label | `Vidar` |
| File name | `Extreme Injector.exe` |
| File type | `exe` |
| First seen | `2026-07-13 18:18:12` |
| Reporter | `JaffaCakes118` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc0c93a66edc35a092d48a503b6e4901` |
| SHA-1 | `e40c17a79d7afb53b610f7db1650c4bcbc87e0a9` |
| SHA-256 | `07c295310759ecd7a42fbf3cb96ca1c5b7f45c7e59ac9704b78431000fae5a87` |
| SHA3-384 | `f6a26531b1a7ac773d19cfddab7c1298fea13d939db82bc2f833e1bb7cb1d604720c56b7ea5e7aa56ea0e0fdd65b47ed` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T15FF7339043858759D1CBAFF8617F1EE3EE2B1EE0B219A09F46A28431F5D9467C68C14F` |
| SSDEEP | `1572864:2LdkWMp0R6FIABZI48z2Fi/S8JKBUmy+N5Xe6EfB7w7:22HI6aABZVPArg/bXeB7w7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_084_07c29531
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07c295310759ecd7a42fbf3cb96ca1c5b7f45c7e59ac9704b78431000fae5a87"
    family = "Vidar"
    file_name = "Extreme Injector.exe"
    file_type = "exe"
    first_seen = "2026-07-13 18:18:12"
  condition:
    hash.sha256(0, filesize) == "07c295310759ecd7a42fbf3cb96ca1c5b7f45c7e59ac9704b78431000fae5a87"
}
```

### Sample 85: `436f9df181fc37d9`

| Field | Value |
|---|---|
| SHA-256 | `436f9df181fc37d9b278995235a3819af6aa1251f6b790c541002136c090f00b` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-13 18:17:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25582c5a6ed63c594a58e0cf119e1de5` |
| SHA-1 | `cc9abc1dd168bc6cad4cbf78d2e8ff85192d4424` |
| SHA-256 | `436f9df181fc37d9b278995235a3819af6aa1251f6b790c541002136c090f00b` |
| SHA3-384 | `104bc5d237877add76796255b36c506728dc67828d8a9c3578e262c0454d0f0f8e5d83578c4d0ec971e52edf8e05fd50` |
| TLSH | `T151D3078AF8819F21C4D612BEFA4F518D332367E8E3EE7112DD245B2477CA55B0A7B211` |
| TELFHASH | `t116d05e46f7924cc85ec1006180cfa316ab6aa1aa27010005f9906f428d82c83b43b406` |
| SSDEEP | `3072:Ixr0ks87LO6T34Nc4uPOs4tsFzuaa4KaLaOrKVQ72O0KJ5dqxnbWq:Ixr0G/hTINZu/4oyaa4KaLaOrKQIKPdK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_436f9df1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "436f9df181fc37d9b278995235a3819af6aa1251f6b790c541002136c090f00b"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-13 18:17:54"
  condition:
    hash.sha256(0, filesize) == "436f9df181fc37d9b278995235a3819af6aa1251f6b790c541002136c090f00b"
}
```

### Sample 86: `39d21c33b65d3d58`

| Field | Value |
|---|---|
| SHA-256 | `39d21c33b65d3d58abe2908b4660ce4ca29f18068d7062c1c85fda21a85dce95` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-13 18:15:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52cf976b44dbf932b7d28b8a97a7c27f` |
| SHA-1 | `74dcb115015c9bbb2ba703ab2e45927c9f8f7a83` |
| SHA-256 | `39d21c33b65d3d58abe2908b4660ce4ca29f18068d7062c1c85fda21a85dce95` |
| SHA3-384 | `03a1fee08ff20509f6c86fc639067621130d1ca39cc78549ac5a4202bbf4d75c4677b6acb9a9b40f80dd0947d1f2df86` |
| TLSH | `T1DF235C6516857C24AE98C4361C7E2F0CB9AD83E6324452EE7FCB3CF68C4A69DD10971D` |
| SSDEEP | `768:c+u9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:c+7cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_39d21c33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39d21c33b65d3d58abe2908b4660ce4ca29f18068d7062c1c85fda21a85dce95"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-13 18:15:52"
  condition:
    hash.sha256(0, filesize) == "39d21c33b65d3d58abe2908b4660ce4ca29f18068d7062c1c85fda21a85dce95"
}
```

### Sample 87: `435f496a7e937b1b`

| Field | Value |
|---|---|
| SHA-256 | `435f496a7e937b1bcccfd9f49d66daf69049942f00e5a11fb1c32f71ba978fde` |
| Family label | `unknown` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-07-13 18:02:56` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd466f9dc7bce74c9feb00fd614c9ac9` |
| SHA-1 | `a8a3d4b63682d9da41e0c1c619209ff06b8c6a4f` |
| SHA-256 | `435f496a7e937b1bcccfd9f49d66daf69049942f00e5a11fb1c32f71ba978fde` |
| SHA3-384 | `819e6fff8f13158399ff6f2b92e75ba70f8a3d92cac9f9fde85fbe6fed43e44d88c3cde5bcee4fb907f0334fed29002c` |
| TLSH | `T127A312E8AFEC7CC1D3692E74818D5240168576B0B2BBF9336233D9A692C1D4463B9707` |
| SSDEEP | `3072:8jgYH9rF7uWW1kvZGj0Zvc4Rta4/+xxo5Jr21b:4V4WW1WnREx2Jr21b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_435f496a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "435f496a7e937b1bcccfd9f49d66daf69049942f00e5a11fb1c32f71ba978fde"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-13 18:02:56"
  condition:
    hash.sha256(0, filesize) == "435f496a7e937b1bcccfd9f49d66daf69049942f00e5a11fb1c32f71ba978fde"
}
```

### Sample 88: `3cf1f8d7848fdc5d`

| Field | Value |
|---|---|
| SHA-256 | `3cf1f8d7848fdc5de0685bc7b46869ca30df9e0e776d1a485f27354065fcde69` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-07-13 18:01:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13a5094a5e4087d08aadfad6835ba3a9` |
| SHA-1 | `9f099afae93b360b249e4ab1269ca1fba070f84e` |
| SHA-256 | `3cf1f8d7848fdc5de0685bc7b46869ca30df9e0e776d1a485f27354065fcde69` |
| SHA3-384 | `79ae96a55279a44f53a6513cd6e5fa2bbe1979441e1d293d6689c73b648fcd7e00994d2fbfe52b025bc0ee06a1a22b3d` |
| TLSH | `T152B302277C43B9FC947B29B6AE7C5D636E1F05A6E59B20090B8DCBE18D4181D863C383` |
| SSDEEP | `1536:WBTBQEQC8NMqX8ZD/3CVlazMDFKXLXNT6ZKRjI/vLomg9hhuVInDOJ6OST0TAm70:g9DKUOVl+pTaWs/vLomg9iV8SJ6OaXP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_3cf1f8d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cf1f8d7848fdc5de0685bc7b46869ca30df9e0e776d1a485f27354065fcde69"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-13 18:01:59"
  condition:
    hash.sha256(0, filesize) == "3cf1f8d7848fdc5de0685bc7b46869ca30df9e0e776d1a485f27354065fcde69"
}
```

### Sample 89: `6b7a81fd67e8e470`

| Field | Value |
|---|---|
| SHA-256 | `6b7a81fd67e8e470ca2513338a511ceaef6f04d034f9fc4fb54c992135524dee` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-13 17:58:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e47d354b7a485195b90f2ac77243412c` |
| SHA-1 | `e22c58a3698a5c8ca50dd3315a495f8fe7cad58e` |
| SHA-256 | `6b7a81fd67e8e470ca2513338a511ceaef6f04d034f9fc4fb54c992135524dee` |
| SHA3-384 | `340741901d44ad84308c8d4f36ad85f321669834a7cf32b0e917c4a7991a2cb4139168132479122c2a95c41c28b144be` |
| TLSH | `T14DB31899B8D29A22C6D316BFFA4F428D773663E4E3DF7107DD145B21338752A0E6A201` |
| TELFHASH | `t198d0a723ff966ee44f664296c88d521213ddb2784a3048467fef6f8f4902486760e443` |
| SSDEEP | `3072:gLLU/lW6pdDDz8eciU5IFa9MPfJMTWLK+BnbV:gLLUA+oecioISyfJ3KGV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_6b7a81fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b7a81fd67e8e470ca2513338a511ceaef6f04d034f9fc4fb54c992135524dee"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-13 17:58:50"
  condition:
    hash.sha256(0, filesize) == "6b7a81fd67e8e470ca2513338a511ceaef6f04d034f9fc4fb54c992135524dee"
}
```

### Sample 90: `421798ea7bd98b70`

| Field | Value |
|---|---|
| SHA-256 | `421798ea7bd98b7027ae3965fba2e50464a5c8da3d0b5f77e7bfded1e3dc01f9` |
| Family label | `AgentTesla` |
| File name | `justificanteTransferencia.JS` |
| File type | `js` |
| First seen | `2026-07-13 17:56:03` |
| Reporter | `JAMESWT_WT` |
| Tags | `AgentTesla, ftp-telewatte-pe-com, js, spam-ita` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd14d2460ed0b968499bd8f7a1133b54` |
| SHA-1 | `9af50ed498012828b892ba8eb3500e7b89a20fc5` |
| SHA-256 | `421798ea7bd98b7027ae3965fba2e50464a5c8da3d0b5f77e7bfded1e3dc01f9` |
| SHA3-384 | `84078982e76f593d4d5ec634cec5cf8a3eae1502b03dbcecc7410966406f994ae80c3675c95877232ceb93708748ecb1` |
| TLSH | `T1E0F5294193A5A5377321E7AD523AEE3DA40E500328EACF04345ED638791CE9BD349BE7` |
| SSDEEP | `98304:tTxA2NAr44fMNVIIA/aYXYXPBOd41IazLJtk9Cg5zpIpVj/Wjl6IWM:tTxBNAr4IuVzANX0l1IuFC9CWzpIjj/w` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_090_421798ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "421798ea7bd98b7027ae3965fba2e50464a5c8da3d0b5f77e7bfded1e3dc01f9"
    family = "AgentTesla"
    file_name = "justificanteTransferencia.JS"
    file_type = "js"
    first_seen = "2026-07-13 17:56:03"
  condition:
    hash.sha256(0, filesize) == "421798ea7bd98b7027ae3965fba2e50464a5c8da3d0b5f77e7bfded1e3dc01f9"
}
```

### Sample 91: `b9496b034ca77f4a`

| Field | Value |
|---|---|
| SHA-256 | `b9496b034ca77f4adbdb02044acac18e6f074ff75c9089c55e33b330c4e5f87c` |
| Family label | `AgentTesla` |
| File name | `justificanteTransferencia.tar` |
| File type | `tar` |
| First seen | `2026-07-13 17:55:55` |
| Reporter | `JAMESWT_WT` |
| Tags | `AgentTesla, ftp-telewatte-pe-com, spam-ita, tar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e61ed24b5ab58820bf7621bb51c2299` |
| SHA-1 | `d176953770876df715ddaf312093d7a1490db492` |
| SHA-256 | `b9496b034ca77f4adbdb02044acac18e6f074ff75c9089c55e33b330c4e5f87c` |
| SHA3-384 | `5d687b8fa302d5015fc8922b9aa5850551a744e054856480681a9fe9cec9818114ea375b6b6512c5b43829f06d107d9d` |
| TLSH | `T1E945334E38BF5519F9CB5BBC939A810FA66B05AE4254A660FC38813B716D5B3423FCD0` |
| SSDEEP | `24576:AyVlFOYJeBMKMfO9jv4ZpqvQI0sQrSNNUYuujTpCFiR+au6iDMBc:NnFBzW9r4D9iUYzRJiqc` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `tar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_091_b9496b03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9496b034ca77f4adbdb02044acac18e6f074ff75c9089c55e33b330c4e5f87c"
    family = "AgentTesla"
    file_name = "justificanteTransferencia.tar"
    file_type = "tar"
    first_seen = "2026-07-13 17:55:55"
  condition:
    hash.sha256(0, filesize) == "b9496b034ca77f4adbdb02044acac18e6f074ff75c9089c55e33b330c4e5f87c"
}
```

### Sample 92: `7400181ed90f2888`

| Field | Value |
|---|---|
| SHA-256 | `7400181ed90f288886881c12b8147f905e502d3ab5022836f3663b9bbf35529f` |
| Family label | `AgentTesla` |
| File name | `Materiali da acquistare.exe` |
| File type | `exe` |
| First seen | `2026-07-13 17:55:48` |
| Reporter | `JAMESWT_WT` |
| Tags | `AgentTesla, exe, ftp-4bagh-net, spam-ita` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9010a15f77301b63cc31f68af0e1a62f` |
| SHA-1 | `01cc2e22deb274c5ee3d80a7238cd5534e1ed652` |
| SHA-256 | `7400181ed90f288886881c12b8147f905e502d3ab5022836f3663b9bbf35529f` |
| SHA3-384 | `35803a6b00abc5049038eb0e936e5abd758cf097b2d32f1b867f9881362c12f830a79112da59b07ecf92d083ba9ce6bf` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E23512A89700D513C9461B380D73F778226D6EEEF801D763ABE87EEB7977A154C00286` |
| SSDEEP | `24576:p0jmxcZ7Vl7XBVaFd39Qy8g7iwr4en1ZcVJgPaIeZ:QWofBVaP4en4jgXe` |
| ICON-DHASH | `e0e2aba3a5b8b8a8` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_092_7400181e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7400181ed90f288886881c12b8147f905e502d3ab5022836f3663b9bbf35529f"
    family = "AgentTesla"
    file_name = "Materiali da acquistare.exe"
    file_type = "exe"
    first_seen = "2026-07-13 17:55:48"
  condition:
    hash.sha256(0, filesize) == "7400181ed90f288886881c12b8147f905e502d3ab5022836f3663b9bbf35529f"
}
```

### Sample 93: `e168a23711f5c8cd`

| Field | Value |
|---|---|
| SHA-256 | `e168a23711f5c8cd4a1039c5da8b430636414145083bc1e5a4bb283f96f3492f` |
| Family label | `AgentTesla` |
| File name | `Materiali da acquistare.rar` |
| File type | `rar` |
| First seen | `2026-07-13 17:55:42` |
| Reporter | `JAMESWT_WT` |
| Tags | `AgentTesla, ftp-4bagh-net, rar, spam-ita` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f819085335563edecd178db684bb31f4` |
| SHA-1 | `10a19fb8ce8fc8a9a4827ac773ab67115ddbe899` |
| SHA-256 | `e168a23711f5c8cd4a1039c5da8b430636414145083bc1e5a4bb283f96f3492f` |
| SHA3-384 | `06b665a7dfcffd8490a6f1cb98a7e85cdb109e5882c54ca1932c9cb668cdaa83e8ab7f5f238b86fd1d9177cc948a6840` |
| TLSH | `T1DC25335479742F9B1CBA325DDF22D37A186FCB9510970833266D2B2EAEC731B901D18E` |
| SSDEEP | `24576:7VZY08ZtE6TiYj38dQ9Dz/wNvb3bW3gZtqNDYb63UIqJ7D5Zf1T:hZ78c6eYD80DbwNv7bWQqiyUJxDDfB` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_093_e168a237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e168a23711f5c8cd4a1039c5da8b430636414145083bc1e5a4bb283f96f3492f"
    family = "AgentTesla"
    file_name = "Materiali da acquistare.rar"
    file_type = "rar"
    first_seen = "2026-07-13 17:55:42"
  condition:
    hash.sha256(0, filesize) == "e168a23711f5c8cd4a1039c5da8b430636414145083bc1e5a4bb283f96f3492f"
}
```

### Sample 94: `4bd416d58b21d19d`

| Field | Value |
|---|---|
| SHA-256 | `4bd416d58b21d19d81db3da8256f2c68b3770cedb27dde7c74e5cb43eae2442e` |
| Family label | `unknown` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-07-13 17:52:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `922304995fff0cac380276a39a3e88ff` |
| SHA-1 | `49e56ff56339c40bcdf469af9a9178ca0d1dfb3e` |
| SHA-256 | `4bd416d58b21d19d81db3da8256f2c68b3770cedb27dde7c74e5cb43eae2442e` |
| SHA3-384 | `9e91094bf7dcf45eb8043344d748278273d6cf1ddec0ae5934512948995260bfe4e7c036b61b86bb794823ab92777026` |
| TLSH | `T10BA30262BB7E93B288A05E3219F76232B400F26ED4913DC5DB65721336DD6B724FC641` |
| SSDEEP | `1536:NYKufXyB4EuKbpCJII8kl2p0zuMxzVM5qzz1smaDAufDbvj0aXkeYxWKO9sh:NuKBvuKwaNKxxMyz1sFDAiHlKcU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_4bd416d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bd416d58b21d19d81db3da8256f2c68b3770cedb27dde7c74e5cb43eae2442e"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-13 17:52:49"
  condition:
    hash.sha256(0, filesize) == "4bd416d58b21d19d81db3da8256f2c68b3770cedb27dde7c74e5cb43eae2442e"
}
```

### Sample 95: `bf8e3c6ce89c7f3c`

| Field | Value |
|---|---|
| SHA-256 | `bf8e3c6ce89c7f3cfa2a04d93b719b84f83aff5d9bc6fa6e2b7daca71931ee12` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-13 17:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1e0d83edc1d1ee22583a41a1bdceff6` |
| SHA-1 | `be01d7e111e00833c6ae7062269adb3c2096382b` |
| SHA-256 | `bf8e3c6ce89c7f3cfa2a04d93b719b84f83aff5d9bc6fa6e2b7daca71931ee12` |
| SHA3-384 | `e6b549ad512b8804cb193b22fd3b5b7a2824f2e6b5503272eba8cbae47bf2c420d9e6eb802b291fe8d935d33860c0828` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T17AE63348AAE102FEEBB6513CDEA25569E0A9F4760730D68F03E49BF10D471E14E3D64B` |
| SSDEEP | `393216:kJssVc7bcpc/D/7J/ywJTxVXFXMCHWUjX1cuI3/PGTAI:kJRcMoDJawJTxXXMb8XCH/O7` |
| ICON-DHASH | `d4f87cbc8cc47130` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_095_bf8e3c6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf8e3c6ce89c7f3cfa2a04d93b719b84f83aff5d9bc6fa6e2b7daca71931ee12"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 17:52:11"
  condition:
    hash.sha256(0, filesize) == "bf8e3c6ce89c7f3cfa2a04d93b719b84f83aff5d9bc6fa6e2b7daca71931ee12"
}
```

### Sample 96: `28cf909b7a9e41e8`

| Field | Value |
|---|---|
| SHA-256 | `28cf909b7a9e41e8827851995aa6ccb1f56fe54c126c69eb8a5f9bb211ab9ba5` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-13 17:51:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2de0defebe44afa7bf53dd9b53d44f5e` |
| SHA-1 | `4e734e5e5d695ce2e5ee7ed5c0d8844ebd9cc750` |
| SHA-256 | `28cf909b7a9e41e8827851995aa6ccb1f56fe54c126c69eb8a5f9bb211ab9ba5` |
| SHA3-384 | `1433302951e49071ecffa4d0b6a244c0716d43493287f7afa6bb72594a741789fe2f3c46d1c6c7aea3936aae385cd074` |
| TLSH | `T152C31889B8929A22C6D316BFFA4F42CD773663E4E3DF7107DD195B21328742A0D6B211` |
| TELFHASH | `t198d0a723ff966ee44f664296c88d521213ddb2784a3048467fef6f8f4902486760e443` |
| SSDEEP | `3072:jnREVsW6L1KD5GAciU5IFaOcyZHE7YPASVtBnbV:jnRE9EhAcioIhnZHgYPASfV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_28cf909b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28cf909b7a9e41e8827851995aa6ccb1f56fe54c126c69eb8a5f9bb211ab9ba5"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-13 17:51:50"
  condition:
    hash.sha256(0, filesize) == "28cf909b7a9e41e8827851995aa6ccb1f56fe54c126c69eb8a5f9bb211ab9ba5"
}
```

### Sample 97: `5821480d830bb3d6`

| Field | Value |
|---|---|
| SHA-256 | `5821480d830bb3d696560af6dcd83d16aa1dc04825052d4e0e137c5cb8a158db` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-13 17:50:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42dce969626e7797c785648ef1f23478` |
| SHA-1 | `42fcce29ec98a325901834bbcf0b257aeda43962` |
| SHA-256 | `5821480d830bb3d696560af6dcd83d16aa1dc04825052d4e0e137c5cb8a158db` |
| SHA3-384 | `1e585747e54c131b2c619746f9b8a77af8bf2a8545afadfbd13f6658c430e4cf689c0309fbbb5baed837aca1f73afacc` |
| TLSH | `T175D38E5C9D1E7DC2C2C3F2FE6D450F66312675744A68C3F6190062CEEB9EED698B1421` |
| SSDEEP | `3072:q8FvTnMv6y7VDwwGBelXwzm0aVM2RNPXmhdCKhR2Jjq:ZVwC+B7Xwq0a5RRmh4K6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_5821480d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5821480d830bb3d696560af6dcd83d16aa1dc04825052d4e0e137c5cb8a158db"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-13 17:50:51"
  condition:
    hash.sha256(0, filesize) == "5821480d830bb3d696560af6dcd83d16aa1dc04825052d4e0e137c5cb8a158db"
}
```

### Sample 98: `f3ba907b03f07e28`

| Field | Value |
|---|---|
| SHA-256 | `f3ba907b03f07e2886fe2012a5f40d4d1c7edfb655b1b2d5d9452234a694edbe` |
| Family label | `Stealc` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-13 17:50:22` |
| Reporter | `iamaachum` |
| Tags | `103-101-85-184, exe, SalatStealer, Stealc, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a99f45b68c21a8965a7bbbcc759cd6af` |
| SHA-1 | `8e8512cda86f235652d21189e40f80f851c77f9b` |
| SHA-256 | `f3ba907b03f07e2886fe2012a5f40d4d1c7edfb655b1b2d5d9452234a694edbe` |
| SHA3-384 | `359c224f9f6df56436f59794f5d95a03e39e068a881d3adfcf7f628030747c78fb39d1d195acbeb1459ced4b089449c5` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1F3666C03EC5555E8C0AED2718A729263BB717C885B3163D32B50F2392F76BD0ADB9358` |
| SSDEEP | `49152:fe2+gG6Lzc7xuSdwNayNzDeDqkogzWzFzcavSz2jPH/EWuyouMwLw8v4KQK1K6eA:fenb6fO8eRkvHQybvJeNnAuiEE` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_098_f3ba907b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3ba907b03f07e2886fe2012a5f40d4d1c7edfb655b1b2d5d9452234a694edbe"
    family = "Stealc"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-13 17:50:22"
  condition:
    hash.sha256(0, filesize) == "f3ba907b03f07e2886fe2012a5f40d4d1c7edfb655b1b2d5d9452234a694edbe"
}
```

### Sample 99: `09e16e8c91a64af5`

| Field | Value |
|---|---|
| SHA-256 | `09e16e8c91a64af5fc48711eb65e89ef3f7480a4fb540270b3a6c9328360735d` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-13 17:47:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5cd5a4c0c32f522bbb866a1264bd9b7` |
| SHA-1 | `7c5460ca9f9eb2c634c9fc2a37ab2feda1356198` |
| SHA-256 | `09e16e8c91a64af5fc48711eb65e89ef3f7480a4fb540270b3a6c9328360735d` |
| SHA3-384 | `f2fdd3e55e3a185400271506f37a2b8bf544aa349ea5fad937b1724e268641435e17aa1fa477aae81a625ea368a43d35` |
| TLSH | `T12A647EE3FC01E9BEFC6ED732CC174A04B135E31158521A3A32A37779A92B0595973E86` |
| SSDEEP | `6144:mKv0rfkQbS6AhhvBoCzihiFs7uYdyn8zjE8Lh9uqLmU2p1:vZnvBoCzihiFs7ZLKZp1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_09e16e8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09e16e8c91a64af5fc48711eb65e89ef3f7480a4fb540270b3a6c9328360735d"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-13 17:47:55"
  condition:
    hash.sha256(0, filesize) == "09e16e8c91a64af5fc48711eb65e89ef3f7480a4fb540270b3a6c9328360735d"
}
```

### Sample 100: `4f70c1cec3c4453c`

| Field | Value |
|---|---|
| SHA-256 | `4f70c1cec3c4453c7d78a48cf688d1f22813d4b90ef4d86a75979afc1345387b` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-13 17:46:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df5260e3bd31fc01144e7674b738294e` |
| SHA-1 | `40f30c40630d2a27aa870de47ab75869e96a1dcc` |
| SHA-256 | `4f70c1cec3c4453c7d78a48cf688d1f22813d4b90ef4d86a75979afc1345387b` |
| SHA3-384 | `b818b149a580c1735103886720e68510e230b6af10d1392e1c527ab3c0bf74b78bb811431ae953b9af7fe18c64d9a51a` |
| TLSH | `T18FC3128EAFD73888EF371FB68847F39223149117A5074FD4159EC211AAB1228B39F166` |
| SSDEEP | `3072:OP7n7wtZXgpUoMd7YAsdHfP86r58HidtH6qsO:OD7EXGUoMdkd8KMsQO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_4f70c1ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f70c1cec3c4453c7d78a48cf688d1f22813d4b90ef4d86a75979afc1345387b"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-13 17:46:50"
  condition:
    hash.sha256(0, filesize) == "4f70c1cec3c4453c7d78a48cf688d1f22813d4b90ef4d86a75979afc1345387b"
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
 * Generated: 2026-07-14T03:39:58.676526+00:00
 */

rule MalwareBazaar_unknown_001_708bebf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "708bebf7661a2646921dea4f826e4d6a2a5a35087c72c0e00bd2cd0c9b894316"
    family = "unknown"
    file_name = "708bebf7661a2646921dea4f826e4d6a2a5a35087c72c0e00bd2cd0c9b894316"
    file_type = "sh"
    first_seen = "2026-07-14 03:30:11"
  condition:
    hash.sha256(0, filesize) == "708bebf7661a2646921dea4f826e4d6a2a5a35087c72c0e00bd2cd0c9b894316"
}

rule MalwareBazaar_unknown_002_249d3ed7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "249d3ed7abfde1173249b693c7f64b7c7c6b6dffb11277e205bccff88447feae"
    family = "unknown"
    file_name = "249d3ed7abfde1173249b693c7f64b7c7c6b6dffb11277e205bccff88447feae"
    file_type = "sh"
    first_seen = "2026-07-14 03:30:09"
  condition:
    hash.sha256(0, filesize) == "249d3ed7abfde1173249b693c7f64b7c7c6b6dffb11277e205bccff88447feae"
}

rule MalwareBazaar_unknown_003_56e7837e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56e7837e2855d749d9848d20ffb2e682f2288b7f10156597abd2fdee543e79c6"
    family = "unknown"
    file_name = "RFQ.vbs"
    file_type = "vbs"
    first_seen = "2026-07-14 03:29:03"
  condition:
    hash.sha256(0, filesize) == "56e7837e2855d749d9848d20ffb2e682f2288b7f10156597abd2fdee543e79c6"
}

rule MalwareBazaar_AsyncRAT_004_6773709e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6773709e7c85e57a2ed16ac1f162b02bb35a7c516927b99d483c72dfbf88664a"
    family = "AsyncRAT"
    file_name = "NEW88APP.exe"
    file_type = "exe"
    first_seen = "2026-07-14 03:17:32"
  condition:
    hash.sha256(0, filesize) == "6773709e7c85e57a2ed16ac1f162b02bb35a7c516927b99d483c72dfbf88664a"
}

rule MalwareBazaar_DarkTortilla_005_3bce373a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bce373a6a8b4a35e50d54469fe16ad229267578960589bdc6951195b6de98fb"
    family = "DarkTortilla"
    file_name = "PURCHASE_ORDER_202606001.exe"
    file_type = "exe"
    first_seen = "2026-07-14 03:16:25"
  condition:
    hash.sha256(0, filesize) == "3bce373a6a8b4a35e50d54469fe16ad229267578960589bdc6951195b6de98fb"
}

rule MalwareBazaar_DarkTortilla_006_7f1c566e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f1c566eee880bce9a3f80880badee548b53ab3aded225c654faeff9cf0349df"
    family = "DarkTortilla"
    file_name = "HSBC_BANK_CONFIRMATION_SWIFT_MT103.exe"
    file_type = "exe"
    first_seen = "2026-07-14 03:16:01"
  condition:
    hash.sha256(0, filesize) == "7f1c566eee880bce9a3f80880badee548b53ab3aded225c654faeff9cf0349df"
}

rule MalwareBazaar_DarkTortilla_007_0e4e0247
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e4e0247476003c3efef81eba6fdc6c98876d15ae4fd81994a2a58c598c2011d"
    family = "DarkTortilla"
    file_name = "MV.CORNELIA.M_VESSEL_INFORMATION.exe"
    file_type = "exe"
    first_seen = "2026-07-14 03:15:44"
  condition:
    hash.sha256(0, filesize) == "0e4e0247476003c3efef81eba6fdc6c98876d15ae4fd81994a2a58c598c2011d"
}

rule MalwareBazaar_AsyncRAT_008_a6ec0a5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6ec0a5f8122e29d1e951b907f673da4b481ab5f4a368c5c171433640d53a3a0"
    family = "AsyncRAT"
    file_name = "F8BETAPP.exe"
    file_type = "exe"
    first_seen = "2026-07-14 03:04:26"
  condition:
    hash.sha256(0, filesize) == "a6ec0a5f8122e29d1e951b907f673da4b481ab5f4a368c5c171433640d53a3a0"
}

rule MalwareBazaar_unknown_009_fe33733d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe33733d353438f4edcf5baf73b602a3a668cc5a948e4a685b13d5d4bfc16b12"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 02:52:09"
  condition:
    hash.sha256(0, filesize) == "fe33733d353438f4edcf5baf73b602a3a668cc5a948e4a685b13d5d4bfc16b12"
}

rule MalwareBazaar_unknown_010_fc397bf8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de"
    family = "unknown"
    file_name = "app_setup.6653002.msi"
    file_type = "msi"
    first_seen = "2026-07-14 02:18:12"
  condition:
    hash.sha256(0, filesize) == "fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de"
}

rule MalwareBazaar_unknown_011_f13cb360
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f13cb360768363d3424e2192c7805b8c8015eb8706dbbbcdead6aed8cf390109"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-07-14 02:17:04"
  condition:
    hash.sha256(0, filesize) == "f13cb360768363d3424e2192c7805b8c8015eb8706dbbbcdead6aed8cf390109"
}

rule MalwareBazaar_unknown_012_3e4c1ea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e4c1ea078d583222246945d10b5c14d4a3f23348c1f03596652def4e71f88a7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 01:52:10"
  condition:
    hash.sha256(0, filesize) == "3e4c1ea078d583222246945d10b5c14d4a3f23348c1f03596652def4e71f88a7"
}

rule MalwareBazaar_unknown_013_5f1b3de3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f1b3de37a17a72b53cdfa6051205d37d351b050be7500306ed65772557e6fb0"
    family = "unknown"
    file_name = "5f1b3de37a17a72b53cdfa6051205d37d351b050be7500306ed65772557e6fb0"
    file_type = "unknown"
    first_seen = "2026-07-14 01:30:14"
  condition:
    hash.sha256(0, filesize) == "5f1b3de37a17a72b53cdfa6051205d37d351b050be7500306ed65772557e6fb0"
}

rule MalwareBazaar_Vidar_014_b59d2b3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b59d2b3abdd4ddba0f35d200324f1fd55998b76f55e1692c66829b5d49808534"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-14 01:21:41"
  condition:
    hash.sha256(0, filesize) == "b59d2b3abdd4ddba0f35d200324f1fd55998b76f55e1692c66829b5d49808534"
}

rule MalwareBazaar_unknown_015_34330993
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "343309939613a1aaaf46375d390e26ba60a91e6026ec2de237fd1e19a2bd267f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-14 01:20:07"
  condition:
    hash.sha256(0, filesize) == "343309939613a1aaaf46375d390e26ba60a91e6026ec2de237fd1e19a2bd267f"
}

rule MalwareBazaar_unknown_016_5aa92ab0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5aa92ab04d89876d4cbf86d39bf1858bb7ff77c8acc40301965309387f09eb88"
    family = "unknown"
    file_name = "kworkerd-netns-rt"
    file_type = "elf"
    first_seen = "2026-07-14 01:06:09"
  condition:
    hash.sha256(0, filesize) == "5aa92ab04d89876d4cbf86d39bf1858bb7ff77c8acc40301965309387f09eb88"
}

rule MalwareBazaar_unknown_017_8c4cac17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c4cac17d41571cc262de43846310440f0d0e31bd3dfa6e5c9df00bcbd5b323e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-14 00:52:11"
  condition:
    hash.sha256(0, filesize) == "8c4cac17d41571cc262de43846310440f0d0e31bd3dfa6e5c9df00bcbd5b323e"
}

rule MalwareBazaar_Mirai_018_9b9999e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b9999e19c8c0aab1ee141dc985454251f602e388f55f323eb1d17083cd8098e"
    family = "Mirai"
    file_name = "bot_x86_64"
    file_type = "elf"
    first_seen = "2026-07-14 00:46:21"
  condition:
    hash.sha256(0, filesize) == "9b9999e19c8c0aab1ee141dc985454251f602e388f55f323eb1d17083cd8098e"
}

rule MalwareBazaar_unknown_019_99688efb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99688efb61464aca1b733c7824d247637f259bd9dae86a06969e3fe748dddc45"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-14 00:44:12"
  condition:
    hash.sha256(0, filesize) == "99688efb61464aca1b733c7824d247637f259bd9dae86a06969e3fe748dddc45"
}

rule MalwareBazaar_Mirai_020_50bbda75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50bbda75075dc0030f4bb96ede4c874e21812dac690c2d0ed0ceb7474e967a1a"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-14 00:28:26"
  condition:
    hash.sha256(0, filesize) == "50bbda75075dc0030f4bb96ede4c874e21812dac690c2d0ed0ceb7474e967a1a"
}

rule MalwareBazaar_unknown_021_ada0d942
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ada0d9426190134f8a1829a16b1a001d781a5ad656042d43cff7fd082c771ba1"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-14 00:15:18"
  condition:
    hash.sha256(0, filesize) == "ada0d9426190134f8a1829a16b1a001d781a5ad656042d43cff7fd082c771ba1"
}

rule MalwareBazaar_unknown_022_e986c08a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e986c08a9dacb351fc1da3906edaac7fffbc813ed9d31460a6d9743cda8a29fc"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-14 00:12:09"
  condition:
    hash.sha256(0, filesize) == "e986c08a9dacb351fc1da3906edaac7fffbc813ed9d31460a6d9743cda8a29fc"
}

rule MalwareBazaar_unknown_023_d9414d54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9414d5407b92d58f72222063c2f39c49c33ee5eec7ff00a2a99f2ecca2866f5"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-14 00:06:28"
  condition:
    hash.sha256(0, filesize) == "d9414d5407b92d58f72222063c2f39c49c33ee5eec7ff00a2a99f2ecca2866f5"
}

rule MalwareBazaar_unknown_024_00d4ea0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00d4ea0d9de91024a65081ff5c5270c4c23d90acaa80d08040c79974f8539317"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-14 00:04:11"
  condition:
    hash.sha256(0, filesize) == "00d4ea0d9de91024a65081ff5c5270c4c23d90acaa80d08040c79974f8539317"
}

rule MalwareBazaar_unknown_025_a395a7b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a395a7b8c501b4795ef03fcdcce4fb5192e67c8f2a9685dd817997c155fbedfc"
    family = "unknown"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-07-13 23:55:15"
  condition:
    hash.sha256(0, filesize) == "a395a7b8c501b4795ef03fcdcce4fb5192e67c8f2a9685dd817997c155fbedfc"
}

rule MalwareBazaar_Mirai_026_0d68f944
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d68f94463f8fa351000dfcd3c7188f18d3819aef2d5cf6022e9bf3154d0fcf1"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-13 23:54:11"
  condition:
    hash.sha256(0, filesize) == "0d68f94463f8fa351000dfcd3c7188f18d3819aef2d5cf6022e9bf3154d0fcf1"
}

rule MalwareBazaar_unknown_027_8d0201c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d0201c41efbe90707b12ba9b0694ea74a1a8e3a4887064ed9eafb62dad6ed7c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 23:52:11"
  condition:
    hash.sha256(0, filesize) == "8d0201c41efbe90707b12ba9b0694ea74a1a8e3a4887064ed9eafb62dad6ed7c"
}

rule MalwareBazaar_unknown_028_f28e85cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f28e85cb1e61807d9c6f3a9f4f5216d1ae02ad97287626a896151f94116d1e6c"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan-Downloader.Win32.Minix.cyb.30070.6663"
    file_type = "exe"
    first_seen = "2026-07-13 23:42:59"
  condition:
    hash.sha256(0, filesize) == "f28e85cb1e61807d9c6f3a9f4f5216d1ae02ad97287626a896151f94116d1e6c"
}

rule MalwareBazaar_unknown_029_cc6720ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc6720ae14382b85c1eafa9d5a04460d2e434d1cfc618dbaf9e0d6679989f535"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-13 23:37:29"
  condition:
    hash.sha256(0, filesize) == "cc6720ae14382b85c1eafa9d5a04460d2e434d1cfc618dbaf9e0d6679989f535"
}

rule MalwareBazaar_AnyDesk_030_d9a2381a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9a2381a471f6c93606f393561c4aca8568313f1d992d9973b7d97821b37ba2c"
    family = "AnyDesk"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-13 23:35:55"
  condition:
    hash.sha256(0, filesize) == "d9a2381a471f6c93606f393561c4aca8568313f1d992d9973b7d97821b37ba2c"
}

rule MalwareBazaar_unknown_031_be52dd73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be52dd73c5626d66c2c6325810921db26b1ca421c9d08e844a9f621bf1b5aeb2"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-13 23:34:22"
  condition:
    hash.sha256(0, filesize) == "be52dd73c5626d66c2c6325810921db26b1ca421c9d08e844a9f621bf1b5aeb2"
}

rule MalwareBazaar_Mirai_032_7b9959d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b9959d43d48dadc1139e45c07978eea4f7e314c328050e860c538dbcd48ede6"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-13 23:33:18"
  condition:
    hash.sha256(0, filesize) == "7b9959d43d48dadc1139e45c07978eea4f7e314c328050e860c538dbcd48ede6"
}

rule MalwareBazaar_njrat_033_1e716a69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e716a69b81f3272b10e3cc7b919e1a1f03005115fbf18ac8b1958a111a8f185"
    family = "njrat"
    file_name = "220c8ef9ac545f54ae0998d260221f45.exe"
    file_type = "exe"
    first_seen = "2026-07-13 23:20:05"
  condition:
    hash.sha256(0, filesize) == "1e716a69b81f3272b10e3cc7b919e1a1f03005115fbf18ac8b1958a111a8f185"
}

rule MalwareBazaar_unknown_034_b480ccc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b480ccc5728743005a359d21b7c999a1b9b9d5f7a05176ac338926d3c514d7f5"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 22:51:50"
  condition:
    hash.sha256(0, filesize) == "b480ccc5728743005a359d21b7c999a1b9b9d5f7a05176ac338926d3c514d7f5"
}

rule MalwareBazaar_Mirai_035_95f08187
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95f08187d0a5572a0b2efba21b0dae6155d7a1b4a4b17034c768b2fbe920626e"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai-DJO.89223942"
    file_type = "elf"
    first_seen = "2026-07-13 22:44:36"
  condition:
    hash.sha256(0, filesize) == "95f08187d0a5572a0b2efba21b0dae6155d7a1b4a4b17034c768b2fbe920626e"
}

rule MalwareBazaar_Mirai_036_4978da80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4978da802792479e84ccf497a16f7021096cf2cc0ae871c25fb62e60d6a63f5e"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-13 22:06:25"
  condition:
    hash.sha256(0, filesize) == "4978da802792479e84ccf497a16f7021096cf2cc0ae871c25fb62e60d6a63f5e"
}

rule MalwareBazaar_unknown_037_a8c5a790
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8c5a790eb2df505f426a9a5ac165e720d2a5e2e1b57538aab7b6b89824af7c2"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 21:51:51"
  condition:
    hash.sha256(0, filesize) == "a8c5a790eb2df505f426a9a5ac165e720d2a5e2e1b57538aab7b6b89824af7c2"
}

rule MalwareBazaar_unknown_038_6a88e77d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a88e77d52212abb66102febdc5a396d4b3e9bb85a093762e646e3e91fe2ce97"
    family = "unknown"
    file_name = "renewcrypterforresults.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:48:03"
  condition:
    hash.sha256(0, filesize) == "6a88e77d52212abb66102febdc5a396d4b3e9bb85a093762e646e3e91fe2ce97"
}

rule MalwareBazaar_unknown_039_9d4a3ef6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d4a3ef6fa7b16b9d9646c3db7ad08e465797a9fbf1f6abde0708cf06b1181fe"
    family = "unknown"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-07-13 21:40:00"
  condition:
    hash.sha256(0, filesize) == "9d4a3ef6fa7b16b9d9646c3db7ad08e465797a9fbf1f6abde0708cf06b1181fe"
}

rule MalwareBazaar_unknown_040_45a69778
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45a697782d4edbda5824e944a10fc4de2b1dd6e24fa638e52e79b52b4ac11dbd"
    family = "unknown"
    file_name = "Reezn.apk"
    file_type = "apk"
    first_seen = "2026-07-13 21:36:06"
  condition:
    hash.sha256(0, filesize) == "45a697782d4edbda5824e944a10fc4de2b1dd6e24fa638e52e79b52b4ac11dbd"
}

rule MalwareBazaar_RemusStealer_041_fa38f653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa38f6539af74b5b355c532a3c71c588960d34abd825442fea98c2177375d010"
    family = "RemusStealer"
    file_name = "recuva_professional__technician_(2026)_full_español_[mega].exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:32:15"
  condition:
    hash.sha256(0, filesize) == "fa38f6539af74b5b355c532a3c71c588960d34abd825442fea98c2177375d010"
}

rule MalwareBazaar_RemusStealer_042_aec2007b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aec2007bddf386d7659b60f712334d7f277f65edfd9f11a61c711b7b4b7119e2"
    family = "RemusStealer"
    file_name = "jee chahta hai movie 720p download utorrent movies.exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:31:54"
  condition:
    hash.sha256(0, filesize) == "aec2007bddf386d7659b60f712334d7f277f65edfd9f11a61c711b7b4b7119e2"
}

rule MalwareBazaar_RemusStealer_043_d5d5465b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5d5465b53f72727b8218dab4165b954748d29ab8f8de275fbd3a6fac0e08b6d"
    family = "RemusStealer"
    file_name = "jahan i danish book free download.exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:31:28"
  condition:
    hash.sha256(0, filesize) == "d5d5465b53f72727b8218dab4165b954748d29ab8f8de275fbd3a6fac0e08b6d"
}

rule MalwareBazaar_RemcosRAT_044_41f04280
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41f04280d3247586155c62404609431b378f99bd7c7aff4e711e15330ee978c9"
    family = "RemcosRAT"
    file_name = "weneedbestthingswithbestversionsneed.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:31:05"
  condition:
    hash.sha256(0, filesize) == "41f04280d3247586155c62404609431b378f99bd7c7aff4e711e15330ee978c9"
}

rule MalwareBazaar_RemusStealer_045_ed38c22c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed38c22c7385998f5182bfae0a235faee616ed19fb34b945b1b8e211e3001e96"
    family = "RemusStealer"
    file_name = "recuva_professional__technician_(2026)_full_español_[mega].7z"
    file_type = "7z"
    first_seen = "2026-07-13 21:28:06"
  condition:
    hash.sha256(0, filesize) == "ed38c22c7385998f5182bfae0a235faee616ed19fb34b945b1b8e211e3001e96"
}

rule MalwareBazaar_RemusStealer_046_16a1260a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16a1260ae199d83c537b65ca558b33c7a783d28c5547b5fcb35dee4cceb5f12e"
    family = "RemusStealer"
    file_name = "jee chahta hai movie 720p download utorrent movies.7z"
    file_type = "7z"
    first_seen = "2026-07-13 21:27:10"
  condition:
    hash.sha256(0, filesize) == "16a1260ae199d83c537b65ca558b33c7a783d28c5547b5fcb35dee4cceb5f12e"
}

rule MalwareBazaar_RemusStealer_047_d871b470
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d871b4706e6410c4170a03a86629822e046d81e15f6a50d905059d7f2383f1de"
    family = "RemusStealer"
    file_name = "jahan i danish book free download.7z"
    file_type = "7z"
    first_seen = "2026-07-13 21:26:14"
  condition:
    hash.sha256(0, filesize) == "d871b4706e6410c4170a03a86629822e046d81e15f6a50d905059d7f2383f1de"
}

rule MalwareBazaar_ZigClipper_048_35294411
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "352944118ad77aea5df1707fbbb541ae7b47421f05f148512d074a108097d0a8"
    family = "ZigClipper"
    file_name = "qwe-23wq-e.exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:25:04"
  condition:
    hash.sha256(0, filesize) == "352944118ad77aea5df1707fbbb541ae7b47421f05f148512d074a108097d0a8"
}

rule MalwareBazaar_RemcosRAT_049_34647bbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34647bbf33ca3f21aa3dcd604e62dce27198bb6b451e9a00a1d72fe23400da1c"
    family = "RemcosRAT"
    file_name = "privatethignsareverygoodformaitiasentriethinsgs.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:17:59"
  condition:
    hash.sha256(0, filesize) == "34647bbf33ca3f21aa3dcd604e62dce27198bb6b451e9a00a1d72fe23400da1c"
}

rule MalwareBazaar_RemusStealer_050_c20a5510
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c20a551057c10e699156ebeb57677cb51625534d8256a3dd3cd8b3efbca5235c"
    family = "RemusStealer"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:11:47"
  condition:
    hash.sha256(0, filesize) == "c20a551057c10e699156ebeb57677cb51625534d8256a3dd3cd8b3efbca5235c"
}

rule MalwareBazaar_ACRStealer_051_b999fba4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b999fba4d4db5bdbfa86d6744ba53b4473f37b53d0fe74c47f7c8238350a11d8"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-13 21:10:40"
  condition:
    hash.sha256(0, filesize) == "b999fba4d4db5bdbfa86d6744ba53b4473f37b53d0fe74c47f7c8238350a11d8"
}

rule MalwareBazaar_ACRStealer_052_b50f2a72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b50f2a725bec5a139e3bebe5d823af0c25d0a7335adab21b53743c2afdc0b6cb"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-13 21:09:40"
  condition:
    hash.sha256(0, filesize) == "b50f2a725bec5a139e3bebe5d823af0c25d0a7335adab21b53743c2afdc0b6cb"
}

rule MalwareBazaar_Vidar_053_52ebf274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52ebf27411484098f4643ea8d0d4ca154d66e78de8121d0809ccb437d9f8eeed"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-13 21:08:18"
  condition:
    hash.sha256(0, filesize) == "52ebf27411484098f4643ea8d0d4ca154d66e78de8121d0809ccb437d9f8eeed"
}

rule MalwareBazaar_Vidar_054_8aa914b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8aa914b8fa0f9cf953f3cd9a9bcbfa27c43a7b7be8ba39d780fb80eaaf3766ff"
    family = "Vidar"
    file_name = "#Pa$$w0rD__2024--0peɴ_Set-Up!.zip"
    file_type = "zip"
    first_seen = "2026-07-13 21:06:19"
  condition:
    hash.sha256(0, filesize) == "8aa914b8fa0f9cf953f3cd9a9bcbfa27c43a7b7be8ba39d780fb80eaaf3766ff"
}

rule MalwareBazaar_PureLogsStealer_055_8e97301b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e97301bed92f00dbd667e65c4e10f7c5d53789eeff64fb067c13a7b66985a48"
    family = "PureLogsStealer"
    file_name = "cxx.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:06:01"
  condition:
    hash.sha256(0, filesize) == "8e97301bed92f00dbd667e65c4e10f7c5d53789eeff64fb067c13a7b66985a48"
}

rule MalwareBazaar_Vidar_056_5536939f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5536939f5e284524a0ee5f1fe401ac92237e4fb013b8c5adfc5b84d3b6d95017"
    family = "Vidar"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-07-13 21:03:42"
  condition:
    hash.sha256(0, filesize) == "5536939f5e284524a0ee5f1fe401ac92237e4fb013b8c5adfc5b84d3b6d95017"
}

rule MalwareBazaar_RemcosRAT_057_c73c47b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c73c47b85140212238b5fa19dd5753ac0962c03df4c2bb4afbf25e43c23a2d0b"
    family = "RemcosRAT"
    file_name = "givemebestthingswithbestprocssionthigns.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:02:59"
  condition:
    hash.sha256(0, filesize) == "c73c47b85140212238b5fa19dd5753ac0962c03df4c2bb4afbf25e43c23a2d0b"
}

rule MalwareBazaar_RemcosRAT_058_48dbf744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48dbf74443280fa3f68e0cb00c2c482f5692428b56c95f44ee0246aab27e3cd6"
    family = "RemcosRAT"
    file_name = "bissbetnetorkingmarketthingscomingfor.hta"
    file_type = "hta"
    first_seen = "2026-07-13 21:01:02"
  condition:
    hash.sha256(0, filesize) == "48dbf74443280fa3f68e0cb00c2c482f5692428b56c95f44ee0246aab27e3cd6"
}

rule MalwareBazaar_PureLogsStealer_059_d39142fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d39142fd261676d1c0ef0b817c44afddc800f6e7b3b1ffa2f2d9a27f548a5095"
    family = "PureLogsStealer"
    file_name = "cxc.hta"
    file_type = "hta"
    first_seen = "2026-07-13 20:58:54"
  condition:
    hash.sha256(0, filesize) == "d39142fd261676d1c0ef0b817c44afddc800f6e7b3b1ffa2f2d9a27f548a5095"
}

rule MalwareBazaar_Stealc_060_de561c4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de561c4a3b59f0351d866721a5a204bb9c1396f5a2b4d9140f7385b0c2ea102d"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-13 20:44:59"
  condition:
    hash.sha256(0, filesize) == "de561c4a3b59f0351d866721a5a204bb9c1396f5a2b4d9140f7385b0c2ea102d"
}

rule MalwareBazaar_RemusStealer_061_d9824b3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e"
    family = "RemusStealer"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-13 19:52:17"
  condition:
    hash.sha256(0, filesize) == "d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e"
}

rule MalwareBazaar_Efimer_062_627a1579
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "627a15798107d91a19c04b691c85f8aa09f131d155e98c1a681edd21e9bea0f8"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 19:52:10"
  condition:
    hash.sha256(0, filesize) == "627a15798107d91a19c04b691c85f8aa09f131d155e98c1a681edd21e9bea0f8"
}

rule MalwareBazaar_AgentTesla_063_2c601164
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c6011645daa6ea192a6a23ef564753e20b4f65e7b90b7e202ff84a835fcdc27"
    family = "AgentTesla"
    file_name = "MT103.JS"
    file_type = "js"
    first_seen = "2026-07-13 19:47:42"
  condition:
    hash.sha256(0, filesize) == "2c6011645daa6ea192a6a23ef564753e20b4f65e7b90b7e202ff84a835fcdc27"
}

rule MalwareBazaar_AgentTesla_064_81c589fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81c589fae253795f2a6625709d192409df2349b929b3ea692b8ea3af08767ffd"
    family = "AgentTesla"
    file_name = "CTM.exe"
    file_type = "exe"
    first_seen = "2026-07-13 19:46:52"
  condition:
    hash.sha256(0, filesize) == "81c589fae253795f2a6625709d192409df2349b929b3ea692b8ea3af08767ffd"
}

rule MalwareBazaar_Mirai_065_1caafa7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1caafa7cb71ac8506fae18f174afbe3594c47d18a5a1f2976b16abf0191f5c1a"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-13 19:23:58"
  condition:
    hash.sha256(0, filesize) == "1caafa7cb71ac8506fae18f174afbe3594c47d18a5a1f2976b16abf0191f5c1a"
}

rule MalwareBazaar_unknown_066_cf21abb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf21abb094564456f930a36e5276b1a7e70290c91c04058c603fd14a078d1c56"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-13 19:21:55"
  condition:
    hash.sha256(0, filesize) == "cf21abb094564456f930a36e5276b1a7e70290c91c04058c603fd14a078d1c56"
}

rule MalwareBazaar_Mirai_067_4bff43d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bff43d7576d4b037cae2af1eedffb2c09d19211312d2920db6e840c8528a1ad"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-13 19:19:54"
  condition:
    hash.sha256(0, filesize) == "4bff43d7576d4b037cae2af1eedffb2c09d19211312d2920db6e840c8528a1ad"
}

rule MalwareBazaar_unknown_068_1d08b5a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d08b5a056f3e2d966fcadda088946c760f69b30cb578be619abddc27803c7e8"
    family = "unknown"
    file_name = "bundle.tar"
    file_type = "tar"
    first_seen = "2026-07-13 19:17:41"
  condition:
    hash.sha256(0, filesize) == "1d08b5a056f3e2d966fcadda088946c760f69b30cb578be619abddc27803c7e8"
}

rule MalwareBazaar_unknown_069_8602256d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8602256dc03872979558ef52ba97e43aebdfb866088b95dec044987b7a7c60f3"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-13 19:09:53"
  condition:
    hash.sha256(0, filesize) == "8602256dc03872979558ef52ba97e43aebdfb866088b95dec044987b7a7c60f3"
}

rule MalwareBazaar_Mirai_070_3c137b5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c137b5aa7f4ebd915927ada5c1a201d0dbf3d482a2048791ac60d349167db74"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-13 19:02:01"
  condition:
    hash.sha256(0, filesize) == "3c137b5aa7f4ebd915927ada5c1a201d0dbf3d482a2048791ac60d349167db74"
}

rule MalwareBazaar_ConnectWise_071_5238b57c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5238b57ce76064b977a6d5800f00f4120d795381f12fab93c7491997de6cfe67"
    family = "ConnectWise"
    file_name = "screenconnect.clientservice.exe"
    file_type = "exe"
    first_seen = "2026-07-13 19:00:03"
  condition:
    hash.sha256(0, filesize) == "5238b57ce76064b977a6d5800f00f4120d795381f12fab93c7491997de6cfe67"
}

rule MalwareBazaar_Efimer_072_9b9f01a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b9f01a45caf0aa8968ae28849b1034616dbd3f578a01fa2ecab926be9c1a5d8"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 18:52:09"
  condition:
    hash.sha256(0, filesize) == "9b9f01a45caf0aa8968ae28849b1034616dbd3f578a01fa2ecab926be9c1a5d8"
}

rule MalwareBazaar_unknown_073_1528fbea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1528fbea80a84107c096ea816c078b98150a36a2f1735772b6544e0fad063849"
    family = "unknown"
    file_name = "full_aes.pyw"
    file_type = "pyw"
    first_seen = "2026-07-13 18:50:43"
  condition:
    hash.sha256(0, filesize) == "1528fbea80a84107c096ea816c078b98150a36a2f1735772b6544e0fad063849"
}

rule MalwareBazaar_unknown_074_71fbffcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71fbffcbab0e585ae33ff277a076366955661e39fee25b62c9f59392263025b3"
    family = "unknown"
    file_name = "request.vbs"
    file_type = "vbs"
    first_seen = "2026-07-13 18:50:39"
  condition:
    hash.sha256(0, filesize) == "71fbffcbab0e585ae33ff277a076366955661e39fee25b62c9f59392263025b3"
}

rule MalwareBazaar_unknown_075_6ab43460
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ab43460e36b904dad331bb3b59cb2a341539b63af791013b2163e5bab8b85a4"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-13 18:47:53"
  condition:
    hash.sha256(0, filesize) == "6ab43460e36b904dad331bb3b59cb2a341539b63af791013b2163e5bab8b85a4"
}

rule MalwareBazaar_Mirai_076_c5208ea8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5208ea8562b3627eded9f9ea09290d132c29fcf8046061d37069056d1128890"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-13 18:45:55"
  condition:
    hash.sha256(0, filesize) == "c5208ea8562b3627eded9f9ea09290d132c29fcf8046061d37069056d1128890"
}

rule MalwareBazaar_unknown_077_e7f36ff4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7f36ff4274b1fa4afb48a002b85aed82d788a399b0db3d5a4e886238777fb37"
    family = "unknown"
    file_name = "Document.lnk"
    file_type = "lnk"
    first_seen = "2026-07-13 18:45:44"
  condition:
    hash.sha256(0, filesize) == "e7f36ff4274b1fa4afb48a002b85aed82d788a399b0db3d5a4e886238777fb37"
}

rule MalwareBazaar_unknown_078_fd1f37c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd1f37c361549bbcc18cbc17a40bb571dc3ba1703e517c9816b8e4452543666b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-13 18:42:54"
  condition:
    hash.sha256(0, filesize) == "fd1f37c361549bbcc18cbc17a40bb571dc3ba1703e517c9816b8e4452543666b"
}

rule MalwareBazaar_unknown_079_ed57f128
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed57f128d6f463dac2a6975006a7100cb8978167ce422398e1d4e4b7fe40f934"
    family = "unknown"
    file_name = "Untitled Document.lnk"
    file_type = "lnk"
    first_seen = "2026-07-13 18:40:24"
  condition:
    hash.sha256(0, filesize) == "ed57f128d6f463dac2a6975006a7100cb8978167ce422398e1d4e4b7fe40f934"
}

rule MalwareBazaar_Stealc_080_fb53841d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb53841dd09252611470ab59b7455cb8a25679ee145d65210ffb179167a6f452"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-13 18:30:59"
  condition:
    hash.sha256(0, filesize) == "fb53841dd09252611470ab59b7455cb8a25679ee145d65210ffb179167a6f452"
}

rule MalwareBazaar_Vidar_081_c08d7b0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c08d7b0a6a2c416b664182e5715c49ceb62efa0eea3181f684d308a7e1fa3bd1"
    family = "Vidar"
    file_name = "62.60.226.198.exe"
    file_type = "exe"
    first_seen = "2026-07-13 18:29:19"
  condition:
    hash.sha256(0, filesize) == "c08d7b0a6a2c416b664182e5715c49ceb62efa0eea3181f684d308a7e1fa3bd1"
}

rule MalwareBazaar_unknown_082_07d05727
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07d05727718563e2e21b06cc7b92c3c67efaf3b5b978e6f98823ba9e6608d2dd"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-13 18:27:54"
  condition:
    hash.sha256(0, filesize) == "07d05727718563e2e21b06cc7b92c3c67efaf3b5b978e6f98823ba9e6608d2dd"
}

rule MalwareBazaar_unknown_083_179042e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "179042e8ce848a0da871bc39c08f63285971d5c3470dc06fcb987f324d564d36"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-07-13 18:18:25"
  condition:
    hash.sha256(0, filesize) == "179042e8ce848a0da871bc39c08f63285971d5c3470dc06fcb987f324d564d36"
}

rule MalwareBazaar_Vidar_084_07c29531
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07c295310759ecd7a42fbf3cb96ca1c5b7f45c7e59ac9704b78431000fae5a87"
    family = "Vidar"
    file_name = "Extreme Injector.exe"
    file_type = "exe"
    first_seen = "2026-07-13 18:18:12"
  condition:
    hash.sha256(0, filesize) == "07c295310759ecd7a42fbf3cb96ca1c5b7f45c7e59ac9704b78431000fae5a87"
}

rule MalwareBazaar_Mirai_085_436f9df1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "436f9df181fc37d9b278995235a3819af6aa1251f6b790c541002136c090f00b"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-13 18:17:54"
  condition:
    hash.sha256(0, filesize) == "436f9df181fc37d9b278995235a3819af6aa1251f6b790c541002136c090f00b"
}

rule MalwareBazaar_unknown_086_39d21c33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39d21c33b65d3d58abe2908b4660ce4ca29f18068d7062c1c85fda21a85dce95"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-13 18:15:52"
  condition:
    hash.sha256(0, filesize) == "39d21c33b65d3d58abe2908b4660ce4ca29f18068d7062c1c85fda21a85dce95"
}

rule MalwareBazaar_unknown_087_435f496a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "435f496a7e937b1bcccfd9f49d66daf69049942f00e5a11fb1c32f71ba978fde"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-13 18:02:56"
  condition:
    hash.sha256(0, filesize) == "435f496a7e937b1bcccfd9f49d66daf69049942f00e5a11fb1c32f71ba978fde"
}

rule MalwareBazaar_Mirai_088_3cf1f8d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cf1f8d7848fdc5de0685bc7b46869ca30df9e0e776d1a485f27354065fcde69"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-13 18:01:59"
  condition:
    hash.sha256(0, filesize) == "3cf1f8d7848fdc5de0685bc7b46869ca30df9e0e776d1a485f27354065fcde69"
}

rule MalwareBazaar_Mirai_089_6b7a81fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b7a81fd67e8e470ca2513338a511ceaef6f04d034f9fc4fb54c992135524dee"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-13 17:58:50"
  condition:
    hash.sha256(0, filesize) == "6b7a81fd67e8e470ca2513338a511ceaef6f04d034f9fc4fb54c992135524dee"
}

rule MalwareBazaar_AgentTesla_090_421798ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "421798ea7bd98b7027ae3965fba2e50464a5c8da3d0b5f77e7bfded1e3dc01f9"
    family = "AgentTesla"
    file_name = "justificanteTransferencia.JS"
    file_type = "js"
    first_seen = "2026-07-13 17:56:03"
  condition:
    hash.sha256(0, filesize) == "421798ea7bd98b7027ae3965fba2e50464a5c8da3d0b5f77e7bfded1e3dc01f9"
}

rule MalwareBazaar_AgentTesla_091_b9496b03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9496b034ca77f4adbdb02044acac18e6f074ff75c9089c55e33b330c4e5f87c"
    family = "AgentTesla"
    file_name = "justificanteTransferencia.tar"
    file_type = "tar"
    first_seen = "2026-07-13 17:55:55"
  condition:
    hash.sha256(0, filesize) == "b9496b034ca77f4adbdb02044acac18e6f074ff75c9089c55e33b330c4e5f87c"
}

rule MalwareBazaar_AgentTesla_092_7400181e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7400181ed90f288886881c12b8147f905e502d3ab5022836f3663b9bbf35529f"
    family = "AgentTesla"
    file_name = "Materiali da acquistare.exe"
    file_type = "exe"
    first_seen = "2026-07-13 17:55:48"
  condition:
    hash.sha256(0, filesize) == "7400181ed90f288886881c12b8147f905e502d3ab5022836f3663b9bbf35529f"
}

rule MalwareBazaar_AgentTesla_093_e168a237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e168a23711f5c8cd4a1039c5da8b430636414145083bc1e5a4bb283f96f3492f"
    family = "AgentTesla"
    file_name = "Materiali da acquistare.rar"
    file_type = "rar"
    first_seen = "2026-07-13 17:55:42"
  condition:
    hash.sha256(0, filesize) == "e168a23711f5c8cd4a1039c5da8b430636414145083bc1e5a4bb283f96f3492f"
}

rule MalwareBazaar_unknown_094_4bd416d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bd416d58b21d19d81db3da8256f2c68b3770cedb27dde7c74e5cb43eae2442e"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-13 17:52:49"
  condition:
    hash.sha256(0, filesize) == "4bd416d58b21d19d81db3da8256f2c68b3770cedb27dde7c74e5cb43eae2442e"
}

rule MalwareBazaar_Efimer_095_bf8e3c6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf8e3c6ce89c7f3cfa2a04d93b719b84f83aff5d9bc6fa6e2b7daca71931ee12"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-13 17:52:11"
  condition:
    hash.sha256(0, filesize) == "bf8e3c6ce89c7f3cfa2a04d93b719b84f83aff5d9bc6fa6e2b7daca71931ee12"
}

rule MalwareBazaar_Mirai_096_28cf909b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28cf909b7a9e41e8827851995aa6ccb1f56fe54c126c69eb8a5f9bb211ab9ba5"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-13 17:51:50"
  condition:
    hash.sha256(0, filesize) == "28cf909b7a9e41e8827851995aa6ccb1f56fe54c126c69eb8a5f9bb211ab9ba5"
}

rule MalwareBazaar_Mirai_097_5821480d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5821480d830bb3d696560af6dcd83d16aa1dc04825052d4e0e137c5cb8a158db"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-13 17:50:51"
  condition:
    hash.sha256(0, filesize) == "5821480d830bb3d696560af6dcd83d16aa1dc04825052d4e0e137c5cb8a158db"
}

rule MalwareBazaar_Stealc_098_f3ba907b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3ba907b03f07e2886fe2012a5f40d4d1c7edfb655b1b2d5d9452234a694edbe"
    family = "Stealc"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-13 17:50:22"
  condition:
    hash.sha256(0, filesize) == "f3ba907b03f07e2886fe2012a5f40d4d1c7edfb655b1b2d5d9452234a694edbe"
}

rule MalwareBazaar_Mirai_099_09e16e8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09e16e8c91a64af5fc48711eb65e89ef3f7480a4fb540270b3a6c9328360735d"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-13 17:47:55"
  condition:
    hash.sha256(0, filesize) == "09e16e8c91a64af5fc48711eb65e89ef3f7480a4fb540270b3a6c9328360735d"
}

rule MalwareBazaar_Mirai_100_4f70c1ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f70c1cec3c4453c7d78a48cf688d1f22813d4b90ef4d86a75979afc1345387b"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-13 17:46:50"
  condition:
    hash.sha256(0, filesize) == "4f70c1cec3c4453c7d78a48cf688d1f22813d4b90ef4d86a75979afc1345387b"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

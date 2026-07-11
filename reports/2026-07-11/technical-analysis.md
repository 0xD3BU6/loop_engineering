# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-11

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 693 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 693 |
| Unique family labels | 19 |
| Unique file types | 13 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 57 |
| Mirai | 13 |
| SilentNet | 6 |
| RemcosRAT | 3 |
| QuasarRAT | 2 |
| DCRat | 2 |
| ValleyRAT | 2 |
| AgentTesla | 2 |
| RemusStealer | 2 |
| SalatStealer | 2 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 54 |
| elf | 15 |
| apk | 9 |
| jar | 5 |
| zip | 4 |
| js | 3 |
| xapk | 2 |
| msi | 2 |
| rar | 2 |
| dll | 1 |

## Per-Sample Analysis

### Sample 1: `49e3dd606bf5bf7e`

| Field | Value |
|---|---|
| SHA-256 | `49e3dd606bf5bf7e1c49b26a25135b2be18ee75c7b8e751c3dc538c0043e5a3f` |
| Family label | `Pony` |
| File name | `406453301fc2f6c6be8838cfda572f09.exe` |
| File type | `exe` |
| First seen | `2026-07-11 03:40:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, Pony` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `406453301fc2f6c6be8838cfda572f09` |
| SHA-1 | `06cc92450ee23832c765eb727645667141fc1e72` |
| SHA-256 | `49e3dd606bf5bf7e1c49b26a25135b2be18ee75c7b8e751c3dc538c0043e5a3f` |
| SHA3-384 | `3b2a149599e4224dc1947d252fe1c4e0317e6b68fde4f2a0e595fcf608ce5a943c5912432e807e15bb44c4aa7ce77763` |
| IMPHASH | `09070e021d4505e6183701ac6e022a16` |
| TLSH | `T156930903FA80E0F1C0A22A7137C15761E7FD9E797C3A8D4AEF9C49856DB22877B16152` |
| SSDEEP | `1536:UnSncgyGqTDRXmGcwSCfZDalZNg9tvo0iO3AX4ApTvMEIWkzmt2l:2SnMuGc/CfZDap6COU45EIGtm` |

#### Technical Assessment

- The sample is tracked as `Pony` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Pony_001_49e3dd60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49e3dd606bf5bf7e1c49b26a25135b2be18ee75c7b8e751c3dc538c0043e5a3f"
    family = "Pony"
    file_name = "406453301fc2f6c6be8838cfda572f09.exe"
    file_type = "exe"
    first_seen = "2026-07-11 03:40:05"
  condition:
    hash.sha256(0, filesize) == "49e3dd606bf5bf7e1c49b26a25135b2be18ee75c7b8e751c3dc538c0043e5a3f"
}
```

### Sample 2: `6451eb28eb29c067`

| Field | Value |
|---|---|
| SHA-256 | `6451eb28eb29c067d8ca421b7a73462b669562ef5e06c447d13914c5d4116150` |
| Family label | `unknown` |
| File name | `TXTconverterSetup.exe` |
| File type | `exe` |
| First seen | `2026-07-11 03:37:50` |
| Reporter | `andrewpetrus` |
| Tags | `.NET, C, EvilAI, exe, FakePDF, KALIM LIMITED, signed, TamperedChef, TXTconverter` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d46017a3c37466dcecf99dcc1632bcc` |
| SHA-1 | `e8ab7406d6f6430f7c6aba21607d12e7815702f6` |
| SHA-256 | `6451eb28eb29c067d8ca421b7a73462b669562ef5e06c447d13914c5d4116150` |
| SHA3-384 | `1ba04f4eb5ef83166f0d491db6ef4dbf562d32cb2a63005158e4a3e3b6f8282b2fd302ec25f19fde93925c259ccc9145` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F4659F19D646DE2EFF028C745B6338224BC5E900CB9617C2D2AC4EBBACB92444D5EDD7` |
| SSDEEP | `24576:qFFEsF/21U4S/4Y01vzu/IJVU14K+mFlVm/n7seNw9CAtIISv3S:SFEsF/v` |
| ICON-DHASH | `88a8808cc48cc068` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_6451eb28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6451eb28eb29c067d8ca421b7a73462b669562ef5e06c447d13914c5d4116150"
    family = "unknown"
    file_name = "TXTconverterSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-11 03:37:50"
  condition:
    hash.sha256(0, filesize) == "6451eb28eb29c067d8ca421b7a73462b669562ef5e06c447d13914c5d4116150"
}
```

### Sample 3: `71f020cf04e4105a`

| Field | Value |
|---|---|
| SHA-256 | `71f020cf04e4105ab29e14afd46d07c7723d182c8b1ca5cb4d57c54833a83a18` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-11 02:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77b9c6d7b2b77e01fdde901f15591951` |
| SHA-1 | `678763f0b4da8c252856f4e21a1b872e1e92fbee` |
| SHA-256 | `71f020cf04e4105ab29e14afd46d07c7723d182c8b1ca5cb4d57c54833a83a18` |
| SHA3-384 | `915afb001aed1d51534e4831f7a3d032ddd0b21d0f4f6a3c1c85f1957c992bde3718b2d24b0178e6f1d7b1724dac609a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T120E6335CAAD121FEF9F3007D59A141E1E094B8769B70C9AF2390D3E16E5B2D20E3971B` |
| SSDEEP | `393216:M9jzEcrNDI3jvNjdQhRSmXMCHWUjXKcuI3/PGTAI:MREcrNU3bN5eRSmXMb8XnH/O7` |
| ICON-DHASH | `e8e864e0d8e8e848` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_71f020cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71f020cf04e4105ab29e14afd46d07c7723d182c8b1ca5cb4d57c54833a83a18"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 02:52:08"
  condition:
    hash.sha256(0, filesize) == "71f020cf04e4105ab29e14afd46d07c7723d182c8b1ca5cb4d57c54833a83a18"
}
```

### Sample 4: `718efee62a3e13cf`

| Field | Value |
|---|---|
| SHA-256 | `718efee62a3e13cfe598008f7df9cbab9c738dafb2457f93e1ed00bd1a407c97` |
| Family label | `unknown` |
| File name | `Plus+PDF+Scanner_1.0.1.xapk` |
| File type | `xapk` |
| First seen | `2026-07-11 02:19:37` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c64b6998cc1b9d810f06b3f75651a866` |
| SHA-1 | `c3b49b2e51deff34945e85c844d1bf9dc0eb78f1` |
| SHA-256 | `718efee62a3e13cfe598008f7df9cbab9c738dafb2457f93e1ed00bd1a407c97` |
| SHA3-384 | `b28c83c394153e1331322ceea4011797c79b6450701b0459cbe417ed2c665f949ecd83beb9b2e73a38f838a94c5c55d8` |
| TLSH | `T17797CF5EB74CA82BDDC670BD8C1A0691B17A7C042611D09B2C17B30EEDB77E60F697A1` |
| SSDEEP | `393216:Z9PW3SLIuTZlSxlES3C+E1vDWFVVhu/Jf3XP06eT0xOQjw7OXgL2Pn7X0Y3SKCT:fPZ/TZIXJCLZOkfX+0fjpK2Pz0Y31CT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_718efee6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "718efee62a3e13cfe598008f7df9cbab9c738dafb2457f93e1ed00bd1a407c97"
    family = "unknown"
    file_name = "Plus+PDF+Scanner_1.0.1.xapk"
    file_type = "xapk"
    first_seen = "2026-07-11 02:19:37"
  condition:
    hash.sha256(0, filesize) == "718efee62a3e13cfe598008f7df9cbab9c738dafb2457f93e1ed00bd1a407c97"
}
```

### Sample 5: `40ec19f9ca8dd33c`

| Field | Value |
|---|---|
| SHA-256 | `40ec19f9ca8dd33ca1d90a447ea3b9d2b9dd8691eea1dd5195f4868197c035a2` |
| Family label | `unknown` |
| File name | `com.tachating.messagesms_16.0.xapk` |
| File type | `xapk` |
| First seen | `2026-07-11 02:18:36` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd95c35cb7ba021ef249ae4b7a2d080c` |
| SHA-1 | `7dcb405a539f5b145913e86705cc6246381a5994` |
| SHA-256 | `40ec19f9ca8dd33ca1d90a447ea3b9d2b9dd8691eea1dd5195f4868197c035a2` |
| SHA3-384 | `e2cf0a2e68018f35c45c3db26cac1c2678333a773e482a32d737d1e109a0bc8af97a209ad4b0ffeb9d68ce02e4da9201` |
| TLSH | `T11D97E149F50CD52BEEC9B0BC8F8A06D3F43AB9151650C19B3C22860EFD977D55A22BB1` |
| SSDEEP | `786432:o5TsgF3DGRnwy1pzf29LVEjg4ajh9+EKJah4vcFv4BmHZy:o5TsgJw29LVagncEiahPWBmc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_40ec19f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ec19f9ca8dd33ca1d90a447ea3b9d2b9dd8691eea1dd5195f4868197c035a2"
    family = "unknown"
    file_name = "com.tachating.messagesms_16.0.xapk"
    file_type = "xapk"
    first_seen = "2026-07-11 02:18:36"
  condition:
    hash.sha256(0, filesize) == "40ec19f9ca8dd33ca1d90a447ea3b9d2b9dd8691eea1dd5195f4868197c035a2"
}
```

### Sample 6: `b36b132b5d8a5f3a`

| Field | Value |
|---|---|
| SHA-256 | `b36b132b5d8a5f3a3239302f8ca730c4a76f8abf4783cd670a5f4fd7a35a32c9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-11 01:55:06` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f98c7a63264e13054f9a2535a0c712d` |
| SHA-1 | `2e8a2a6e4775d89e51d8465d9a4b6e56040a6b9e` |
| SHA-256 | `b36b132b5d8a5f3a3239302f8ca730c4a76f8abf4783cd670a5f4fd7a35a32c9` |
| SHA3-384 | `8e1b050141ca71a6aff4628d292e4078a4c9b2cc75983795f793ec8dc85eda625bf3166380b5c49af1f8789d56962130` |
| IMPHASH | `a9cfe4d59b4347e623a95ee9979ae52c` |
| TLSH | `T1A3C59E03E7A580EAD49AC138C7568223FB72B4891730B6EF57D48A253F67BA15F1D305` |
| SSDEEP | `49152:kMnxytwSJNrKzpmKBA8/8yp2ggP4ZQTAIzHY2uR:kMnMKzAoBxIm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_b36b132b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b36b132b5d8a5f3a3239302f8ca730c4a76f8abf4783cd670a5f4fd7a35a32c9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-11 01:55:06"
  condition:
    hash.sha256(0, filesize) == "b36b132b5d8a5f3a3239302f8ca730c4a76f8abf4783cd670a5f4fd7a35a32c9"
}
```

### Sample 7: `2db0b1f45b14652b`

| Field | Value |
|---|---|
| SHA-256 | `2db0b1f45b14652b69ec0a626e0d21f33218dd5ef99017f80e010c7744a44b41` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-11 01:52:07` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4c787bb3a1f5bf7c0824bf9ff0b9302` |
| SHA-1 | `4e13c20a58b916a79f40758ef991fbd5908fd180` |
| SHA-256 | `2db0b1f45b14652b69ec0a626e0d21f33218dd5ef99017f80e010c7744a44b41` |
| SHA3-384 | `f72f8ee92a688e96f17ae4b0c7f55220c5c350fa90018ecefb40aae7adbe740b9719e97a987608d69ba981795b1df03b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T16AE6335876E411EEFCB3403DEDB285A5E12538721B71C9BB0798A7A26F271D04C3CB66` |
| SSDEEP | `393216:7KTwXtEgiYt093MbHdMXMCHWUjXtcuI3/PGTAI:7KIOgiYtGaHdMXMb8XaH/O7` |
| ICON-DHASH | `f0d88ea29ac6f4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_2db0b1f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2db0b1f45b14652b69ec0a626e0d21f33218dd5ef99017f80e010c7744a44b41"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 01:52:07"
  condition:
    hash.sha256(0, filesize) == "2db0b1f45b14652b69ec0a626e0d21f33218dd5ef99017f80e010c7744a44b41"
}
```

### Sample 8: `ed1565803c87371b`

| Field | Value |
|---|---|
| SHA-256 | `ed1565803c87371b03b576b6fcfb47ba3aeebdcfa07010f1c27ed9c91a70b074` |
| Family label | `QuasarRAT` |
| File name | `ed1565803c87371b03b576b6fcfb47ba3aeebdcfa0701.exe` |
| File type | `exe` |
| First seen | `2026-07-11 00:10:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, QuasarRAT, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `270193694f668c8717d9d0dfebd04312` |
| SHA-1 | `b2ac5549f03df90f9f916fc7e7d3b746a7cb6041` |
| SHA-256 | `ed1565803c87371b03b576b6fcfb47ba3aeebdcfa07010f1c27ed9c91a70b074` |
| SHA3-384 | `804439777aa0516dd59c4f92713369c508637031259b7e02ec71d5442ce39a0b3d243a52e4fa0e983e9ffb7eafafab13` |
| IMPHASH | `d9cf11d5ad37e7ba4c5b3ed284f1150d` |
| TLSH | `T103751114A91878D9C86946FBA0DA3B1D5862ED4434D05CCABECF31B51E78BE2EED3C14` |
| SSDEEP | `24576:+qIWqz2eyCi4bXzBA3ULXDt6ZZr6+q/6+NV7bAnaULZ/X4EYM+6:+osyKNAQIZghrNRcNY` |
| ICON-DHASH | `78f8bcf2b2b0f059` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_008_ed156580
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed1565803c87371b03b576b6fcfb47ba3aeebdcfa07010f1c27ed9c91a70b074"
    family = "QuasarRAT"
    file_name = "ed1565803c87371b03b576b6fcfb47ba3aeebdcfa0701.exe"
    file_type = "exe"
    first_seen = "2026-07-11 00:10:07"
  condition:
    hash.sha256(0, filesize) == "ed1565803c87371b03b576b6fcfb47ba3aeebdcfa07010f1c27ed9c91a70b074"
}
```

### Sample 9: `bdbacc0365e49c8d`

| Field | Value |
|---|---|
| SHA-256 | `bdbacc0365e49c8df5d9f604db4bed0a67c161e82c4d6a06cca9bba101db7d30` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 23:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e29dbe534aefb80c169bfb057a94acc3` |
| SHA-1 | `d035e574daf220495be1ed33e07793005bd2bbe2` |
| SHA-256 | `bdbacc0365e49c8df5d9f604db4bed0a67c161e82c4d6a06cca9bba101db7d30` |
| SHA3-384 | `208e399e8c8ca68b38b331fc4ecd0f3dfbb8f96038541d9298a64b2108cf79939ef1f03667442fecb98dddf7b4fe3d46` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T114E63358A9D049FEDEB3003CADE2A9A5F53978740B23C99B039857A0BD572F44E3D352` |
| SSDEEP | `393216:8g3xxOJ81gIfhohIlyS6drXMCHWUjXGcuI3/PGTAI:8g3HpohI0drXMb8X7H/O7` |
| ICON-DHASH | `71d88ea29ac6e471` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_bdbacc03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdbacc0365e49c8df5d9f604db4bed0a67c161e82c4d6a06cca9bba101db7d30"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 23:52:08"
  condition:
    hash.sha256(0, filesize) == "bdbacc0365e49c8df5d9f604db4bed0a67c161e82c4d6a06cca9bba101db7d30"
}
```

### Sample 10: `60314e99e9c7cf30`

| Field | Value |
|---|---|
| SHA-256 | `60314e99e9c7cf30f9b51fb1956852dafc4d87d996cb56cd05040640cdad99a8` |
| Family label | `RemcosRAT` |
| File name | `SecuriteInfo.com.Trojan.Remcos.1074.656.7210` |
| File type | `exe` |
| First seen | `2026-07-10 23:50:26` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a4e204497445c36a0de08a68e0f6af2` |
| SHA-1 | `345e668fb8a5200cb437ff160f79d4882b2d2b96` |
| SHA-256 | `60314e99e9c7cf30f9b51fb1956852dafc4d87d996cb56cd05040640cdad99a8` |
| SHA3-384 | `19d82343fd1b8e416942f4d41975384d1eb3f7536ddcabf4c6da9d96aafc6c55cad88ddf07cc1b3c6b9d55c20d80915f` |
| IMPHASH | `cd443d07fb22cc071cc33eee6cd16e2e` |
| TLSH | `T10DB4BF01B6F2C1B2DA7654300936E735CEBC7C21183699AB63D61D5BBD30191DB39BB2` |
| SSDEEP | `12288:i97mmDmUefn1CvVkeClYRLwvcHk2c+IsPZOr4s:ilxDmRnkvVkhYHk2c+DZe` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_010_60314e99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60314e99e9c7cf30f9b51fb1956852dafc4d87d996cb56cd05040640cdad99a8"
    family = "RemcosRAT"
    file_name = "SecuriteInfo.com.Trojan.Remcos.1074.656.7210"
    file_type = "exe"
    first_seen = "2026-07-10 23:50:26"
  condition:
    hash.sha256(0, filesize) == "60314e99e9c7cf30f9b51fb1956852dafc4d87d996cb56cd05040640cdad99a8"
}
```

### Sample 11: `c97f1f67e5730c1c`

| Field | Value |
|---|---|
| SHA-256 | `c97f1f67e5730c1cb688c7759f5189917c70566480eefa69e873c24cdaa65219` |
| Family label | `QuasarRAT` |
| File name | `SecuriteInfo.com.Win32.Dh-A.52397922` |
| File type | `exe` |
| First seen | `2026-07-10 23:50:25` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, QuasarRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `433d134b90303d5d690d76e47a70a427` |
| SHA-1 | `e9866eb5c5630df8783b96292a2e23fc25388428` |
| SHA-256 | `c97f1f67e5730c1cb688c7759f5189917c70566480eefa69e873c24cdaa65219` |
| SHA3-384 | `d38f4761bd35b91fe668f92ed15903514d669afe5bb8ccca0862b0f8d2b0248cc6c00055b05acde230ebece134472d87` |
| IMPHASH | `91c15b4b4bd0b0e28e33db730aa2d50c` |
| TLSH | `T1C4752323BBD139EDC2768235E0A78A1A9B71BCB84464DB1F47D0C1F21F677504E1BA26` |
| SSDEEP | `24576:m55L+lL2r60FZ3NI561UMk4sSmAHgpIBBXXEJ32cQHtAB4rrHRT4HvOTD1eKs75J:aClUpAZG4WrGPm6V` |
| ICON-DHASH | `c003c0d4c4c403c0` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_011_c97f1f67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c97f1f67e5730c1cb688c7759f5189917c70566480eefa69e873c24cdaa65219"
    family = "QuasarRAT"
    file_name = "SecuriteInfo.com.Win32.Dh-A.52397922"
    file_type = "exe"
    first_seen = "2026-07-10 23:50:25"
  condition:
    hash.sha256(0, filesize) == "c97f1f67e5730c1cb688c7759f5189917c70566480eefa69e873c24cdaa65219"
}
```

### Sample 12: `cc4b2f37dfdd748e`

| Field | Value |
|---|---|
| SHA-256 | `cc4b2f37dfdd748e224622cf88dde7d0bfc016cb81f5b67fc9573b1431b866e8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `msi` |
| First seen | `2026-07-10 23:25:51` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6858b951c569fed45dbe5fbb9137a53b` |
| SHA-1 | `675641ec81bbbd70c8128018dcdbbb06d1f48ac4` |
| SHA-256 | `cc4b2f37dfdd748e224622cf88dde7d0bfc016cb81f5b67fc9573b1431b866e8` |
| SHA3-384 | `b4c48c41289cfc8db2e2c74a8f6d984c6e6c4cfeeaed3a2ae757fc55d9d4632d33e84c0335f066d22b136658ed3e7d47` |
| TLSH | `T1192733A628222D83CA6266FB2353134EAF310DB13B1287552D75F90D1CBD1FA4B5D78B` |
| SSDEEP | `393216:pnchrExS3glvWv87upe4GCAKUdSCu3et11G0bpqTiY:pCgxpe06lA7dNIeKmY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_cc4b2f37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc4b2f37dfdd748e224622cf88dde7d0bfc016cb81f5b67fc9573b1431b866e8"
    family = "unknown"
    file_name = "file"
    file_type = "msi"
    first_seen = "2026-07-10 23:25:51"
  condition:
    hash.sha256(0, filesize) == "cc4b2f37dfdd748e224622cf88dde7d0bfc016cb81f5b67fc9573b1431b866e8"
}
```

### Sample 13: `a2f29f078ddd41e2`

| Field | Value |
|---|---|
| SHA-256 | `a2f29f078ddd41e2544e3750feba5e60c6f70a8a185e1ec960fcf3cadd663d28` |
| Family label | `unknown` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-07-10 22:52:17` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, AsgardProtector, dropped-by-OffLoader, exe, static-stacksupport-cc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8adb10c728ac1d7bd528d53153d98be7` |
| SHA-1 | `8e86a7d71809de8baf27b2a9e16787145e504ce0` |
| SHA-256 | `a2f29f078ddd41e2544e3750feba5e60c6f70a8a185e1ec960fcf3cadd663d28` |
| SHA3-384 | `09e8887d48a2a8c2bde703d2eae1a06d6be16b836936f4ad74b2eac3dc2b9a214b2b7fb2b1540af68a494197ad6d31ec` |
| IMPHASH | `e387f9bdbdc891a56417c52c45ed0b91` |
| TLSH | `T1B485231912D8506EE0A28B748DF256A65575FC668B309FDF22C4B93E2E33ED5A130F07` |
| SSDEEP | `49152:5reBF2S+F8WNvvK064gHFuih7B6mahZP5YRaSRfGcShCpAMTi:xfCB06rFuCcmI5e0C` |
| ICON-DHASH | `961709040c303848` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_a2f29f07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2f29f078ddd41e2544e3750feba5e60c6f70a8a185e1ec960fcf3cadd663d28"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-10 22:52:17"
  condition:
    hash.sha256(0, filesize) == "a2f29f078ddd41e2544e3750feba5e60c6f70a8a185e1ec960fcf3cadd663d28"
}
```

### Sample 14: `a62121caf724e944`

| Field | Value |
|---|---|
| SHA-256 | `a62121caf724e944291bd1733fd65da8af3d205d27be8f40af9d02cb647189a7` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 22:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a23aa949c4d73e0d6f58d978783f2535` |
| SHA-1 | `3b635fade4c6edc611c76b78093543a7e7908c3f` |
| SHA-256 | `a62121caf724e944291bd1733fd65da8af3d205d27be8f40af9d02cb647189a7` |
| SHA3-384 | `aa38ad61d1670a4f503f5b309321a50754d9ebb0f7ae9db968f7171ec950ea6c3639db535161079931c0f467551fcc10` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T19DE6331879F043DBF2738039CEA254A5F569B8BA47B2C9DB4794A3A53E1B1E04D3C613` |
| SSDEEP | `196608:aw2+i7T54wViXEGv1Kb/3JAaxXMCHGLLc54i1wN+MCmPIcu9KYK39sI3PPGTMrRd:aoi7TEXMJAaxXMCHWUjXRcuI3/PGTAI` |
| ICON-DHASH | `70f0f0d8f8e8f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_a62121ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a62121caf724e944291bd1733fd65da8af3d205d27be8f40af9d02cb647189a7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 22:52:09"
  condition:
    hash.sha256(0, filesize) == "a62121caf724e944291bd1733fd65da8af3d205d27be8f40af9d02cb647189a7"
}
```

### Sample 15: `6144677a8ff6d6cb`

| Field | Value |
|---|---|
| SHA-256 | `6144677a8ff6d6cb5b04403c9f07ea326419600f9b469a95502fa022613c56bd` |
| Family label | `RemcosRAT` |
| File name | `6144677a8ff6d6cb5b04403c9f07ea326419600f9b469.exe` |
| File type | `exe` |
| First seen | `2026-07-10 22:20:13` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd1f184d36cb8474315a807522efa3fc` |
| SHA-1 | `c61820b5c586d328c1afa4196a67132eaa81d316` |
| SHA-256 | `6144677a8ff6d6cb5b04403c9f07ea326419600f9b469a95502fa022613c56bd` |
| SHA3-384 | `bb9742e2e9ee4e73fa6e0b603bffc78fcd2db9c94206dc83fa2da37448b029bc82b71761c5527772e92c498a42542702` |
| IMPHASH | `7d5125df1b721f19e7f94988d3e3ee5a` |
| TLSH | `T15DB4BF02B6F2C0B2DA7664300936E735DEBC7C31183699AB63D61D5BBD30151DB39AB2` |
| SSDEEP | `12288:VlQAiR49ckiK7JV8AuE4lKC/kPHM9/IsPZSZj/:Vl0GcNUJV8i4mHM9/DZK` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_015_6144677a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6144677a8ff6d6cb5b04403c9f07ea326419600f9b469a95502fa022613c56bd"
    family = "RemcosRAT"
    file_name = "6144677a8ff6d6cb5b04403c9f07ea326419600f9b469.exe"
    file_type = "exe"
    first_seen = "2026-07-10 22:20:13"
  condition:
    hash.sha256(0, filesize) == "6144677a8ff6d6cb5b04403c9f07ea326419600f9b469a95502fa022613c56bd"
}
```

### Sample 16: `350db1326d8bdf92`

| Field | Value |
|---|---|
| SHA-256 | `350db1326d8bdf921d5dfcea54a713d19c8d4b6dddc265b14c55ae0646eecb7e` |
| Family label | `RemoteManipulator` |
| File name | `200c4f697289035f228c5915a5cc6115.exe` |
| File type | `exe` |
| First seen | `2026-07-10 22:20:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemoteManipulator` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `200c4f697289035f228c5915a5cc6115` |
| SHA-1 | `2bb9ded1f4a462336e0f02c8642f5e6fdf70260b` |
| SHA-256 | `350db1326d8bdf921d5dfcea54a713d19c8d4b6dddc265b14c55ae0646eecb7e` |
| SHA3-384 | `a598d2afa8f19c74bc91a9af044fe8ce331530056562086d6e252af9c4cb00ec82be834403c9145d9461f61911947df9` |
| IMPHASH | `9eb20214673ee9d29dd988abf1e53afe` |
| TLSH | `T18EC7C013F2865439D4A71F35697BE3766A3EBE204616CD5BFBE4290C5E322C02D2A347` |
| SSDEEP | `393216:2nxlOJDm13rc2EeJUO9WLcbKb/fNRvvA9a1DJMsd035QLVvucFEg1O0PfDWh3dOD:eGmN/bKfvAARptBe0D0dd1IMTM` |
| ICON-DHASH | `f0c4b27139b2e4e8` |

#### Technical Assessment

- The sample is tracked as `RemoteManipulator` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemoteManipulator_016_350db132
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "350db1326d8bdf921d5dfcea54a713d19c8d4b6dddc265b14c55ae0646eecb7e"
    family = "RemoteManipulator"
    file_name = "200c4f697289035f228c5915a5cc6115.exe"
    file_type = "exe"
    first_seen = "2026-07-10 22:20:09"
  condition:
    hash.sha256(0, filesize) == "350db1326d8bdf921d5dfcea54a713d19c8d4b6dddc265b14c55ae0646eecb7e"
}
```

### Sample 17: `29c252a26f6b8c08`

| Field | Value |
|---|---|
| SHA-256 | `29c252a26f6b8c08a89e1b83255bee5637819c50f72b1b974af217540df8fff7` |
| Family label | `unknown` |
| File name | `Clash-X64.exe` |
| File type | `exe` |
| First seen | `2026-07-10 22:18:41` |
| Reporter | `CNGaoLing` |
| Tags | `Androm, Backdoor, exe, Zbot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3703e233b1a8dbd2010a2b7e6aa136fb` |
| SHA-1 | `4b6d2d3d8b7a8d0e53f9e305e3b4cebf8f9e6820` |
| SHA-256 | `29c252a26f6b8c08a89e1b83255bee5637819c50f72b1b974af217540df8fff7` |
| SHA3-384 | `d0bea89497fa01a3d172fe0de94a71d1adc96c0f282795aa46bd67b69a5c7b4bd5713a5259713310098037f95e17d6c6` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T120183333A25A602DE07A5F39697BE0368537FD316D274C5B66F4901CDF260903A3B39A` |
| SSDEEP | `1572864:4P5AgEP+C5MDEl4TKAAdVx5TL1/Ih1xdnoI+dgRH9qxKYmZf+DbEpX9d2sB0lOFf:X9DyAlSMxZBIPx6IJbq4LZ+DbE19d2sn` |
| ICON-DHASH | `0049c8e9d4d6d410` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_29c252a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29c252a26f6b8c08a89e1b83255bee5637819c50f72b1b974af217540df8fff7"
    family = "unknown"
    file_name = "Clash-X64.exe"
    file_type = "exe"
    first_seen = "2026-07-10 22:18:41"
  condition:
    hash.sha256(0, filesize) == "29c252a26f6b8c08a89e1b83255bee5637819c50f72b1b974af217540df8fff7"
}
```

### Sample 18: `bfcab5e114b87543`

| Field | Value |
|---|---|
| SHA-256 | `bfcab5e114b87543cb400b328ba6555da34ddc0bcd05e0313baa3236e6cd671c` |
| Family label | `RemcosRAT` |
| File name | `xbfcab5e114b87543cb400b328ba6555da34ddc0bcd05.exe` |
| File type | `exe` |
| First seen | `2026-07-10 22:10:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9b604db90c598ac9815aa3b61a0f489` |
| SHA-1 | `ea06cbe5a6380dfe388e5c84f75b113d6b83a2b0` |
| SHA-256 | `bfcab5e114b87543cb400b328ba6555da34ddc0bcd05e0313baa3236e6cd671c` |
| SHA3-384 | `7e08170803c83c8f4de4af415c5dd8ef91491f36311cd2a3bc41f7c6c1cfba9d71fecf03a3e86d16f74720a3520bc43d` |
| IMPHASH | `86f1f56935451fab526b19f6de359407` |
| TLSH | `T196C4AE19F75404F9D167D178C9624946FA727C4E47606ACF23A03AAB2F376E09E3EB00` |
| SSDEEP | `6144:yL+n1/BbtB4ztYG4x3zu9lq/dPd/KyvzhbdKukf1/L1OfKZ4YETd9q:71pbtKe3zu81dPNgZmfc4nTd9q` |
| ICON-DHASH | `8806aea95d3c1600` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_018_bfcab5e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfcab5e114b87543cb400b328ba6555da34ddc0bcd05e0313baa3236e6cd671c"
    family = "RemcosRAT"
    file_name = "xbfcab5e114b87543cb400b328ba6555da34ddc0bcd05.exe"
    file_type = "exe"
    first_seen = "2026-07-10 22:10:07"
  condition:
    hash.sha256(0, filesize) == "bfcab5e114b87543cb400b328ba6555da34ddc0bcd05e0313baa3236e6cd671c"
}
```

### Sample 19: `fd6de1ced6710985`

| Field | Value |
|---|---|
| SHA-256 | `fd6de1ced67109859d1bf654a54819598cbbd7eca0bd380168e1360da13abec6` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 21:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70590faba1ddaeb364cbc168363f6348` |
| SHA-1 | `d7f5ef2e007d1d29b8a889e830af7ae8bd148925` |
| SHA-256 | `fd6de1ced67109859d1bf654a54819598cbbd7eca0bd380168e1360da13abec6` |
| SHA3-384 | `7f3d484c5af29e287eecbda8e8ea25c4f7381c5ed1db43b9236a57ec1b8451ba03d1d615069ed18a409169a3d417a76c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1B0E6330879D212FDE667423CEEF2A584D4A878A72371C9CF47D842E27E172D04D3D9A6` |
| SSDEEP | `393216:YB842xw6qZwu3ALqfIiPAXMCHWUjXccuI3/PGTAI:YsOvwLwYXMb8XJH/O7` |
| ICON-DHASH | `7071e4d6e6e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_fd6de1ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd6de1ced67109859d1bf654a54819598cbbd7eca0bd380168e1360da13abec6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 21:52:10"
  condition:
    hash.sha256(0, filesize) == "fd6de1ced67109859d1bf654a54819598cbbd7eca0bd380168e1360da13abec6"
}
```

### Sample 20: `9d33fa3e21518a55`

| Field | Value |
|---|---|
| SHA-256 | `9d33fa3e21518a55d1ca0e332aa81bc552c2384c4323f70e8ac8070d8920910b` |
| Family label | `unknown` |
| File name | `file.js` |
| File type | `js` |
| First seen | `2026-07-10 21:04:52` |
| Reporter | `skocherhan` |
| Tags | `js, thibahlt-lol` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33874b4eecadf538643639e789b90dbb` |
| SHA-1 | `715d8010a479506e3e137359c366fbc3fac1cc3d` |
| SHA-256 | `9d33fa3e21518a55d1ca0e332aa81bc552c2384c4323f70e8ac8070d8920910b` |
| SHA3-384 | `581e19f848085c4c9d19182994432c90805c1b879b9e631111aa45731f68d4a07d012b7a0c73a157d45f2708dc0ad1b1` |
| TLSH | `T1AF02D82A737450BB95EA2CD74C2F410620B5A13B7D45E092CA25FD6660FDF4288B7B7C` |
| SSDEEP | `96:25SVnnvaxvNLa93zLciOVgQ5mTwP1x/aI8m8//m257bAyzsQRyFtrorTC453ccOw:bvaZR23FoRnPL8pG0y/q3ccz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_9d33fa3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d33fa3e21518a55d1ca0e332aa81bc552c2384c4323f70e8ac8070d8920910b"
    family = "unknown"
    file_name = "file.js"
    file_type = "js"
    first_seen = "2026-07-10 21:04:52"
  condition:
    hash.sha256(0, filesize) == "9d33fa3e21518a55d1ca0e332aa81bc552c2384c4323f70e8ac8070d8920910b"
}
```

### Sample 21: `dc2a074cd511f6a1`

| Field | Value |
|---|---|
| SHA-256 | `dc2a074cd511f6a130c72a365c0139399610eee9e50368b9f3be20016ede4a4e` |
| Family label | `DCRat` |
| File name | `RAYCl0udExecutor.exe` |
| File type | `exe` |
| First seen | `2026-07-10 21:00:09` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a2be6a44b16de6ec59a8ad599eff2b1` |
| SHA-1 | `15aeb7fa04098f60e937e0b8e2a6431d2ef30ffe` |
| SHA-256 | `dc2a074cd511f6a130c72a365c0139399610eee9e50368b9f3be20016ede4a4e` |
| SHA3-384 | `6fdca7ac53b71cf6217c5eb2b9f0b113613eccea6ba19f540e371a3ad2fbd242d11163a89e93757f40b85b8e3d1ec32e` |
| IMPHASH | `fcf1390e9ce472c7270447fc5c61a0c1` |
| TLSH | `T17D557C01BE44CE21F0181633C2EF450447B4BC516AAAEB2B7EBA376D59123977D1DACB` |
| SSDEEP | `24576:u2G/nvxW3WieCWl3xoQXp1UqKd8wwHcxhIDS5+u9sgzDk7on2kC:ubA3jQ3n1GuUuO9sgzd2d` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_021_dc2a074c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc2a074cd511f6a130c72a365c0139399610eee9e50368b9f3be20016ede4a4e"
    family = "DCRat"
    file_name = "RAYCl0udExecutor.exe"
    file_type = "exe"
    first_seen = "2026-07-10 21:00:09"
  condition:
    hash.sha256(0, filesize) == "dc2a074cd511f6a130c72a365c0139399610eee9e50368b9f3be20016ede4a4e"
}
```

### Sample 22: `d1e0a027f32603f1`

| Field | Value |
|---|---|
| SHA-256 | `d1e0a027f32603f16a20f9f380b6770a9533ea9d5e02bc62b6a59a47a2200f02` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 20:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e95f345ef9235bf0698f9a91efb3cf2a` |
| SHA-1 | `648f9c5c117053f69f94095c15ca251fe4ebcbac` |
| SHA-256 | `d1e0a027f32603f16a20f9f380b6770a9533ea9d5e02bc62b6a59a47a2200f02` |
| SHA3-384 | `3d3426358672f62ca6dd27bf2ce8034d3dcd285b782929a12383bcff08874159f6375811a9e8cf964e76011d6582d5df` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T192E63354EAC002FFF663023EDEE25999D96CF0364732CBCB135C4BA52E5B1E1883A556` |
| SSDEEP | `393216:ldbIy0D0w2p6exHrpH8XXMCHWUjXgcuI3/PGTAI:lRw2phlVH8XXMb8X1H/O7` |
| ICON-DHASH | `5471f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_d1e0a027
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1e0a027f32603f16a20f9f380b6770a9533ea9d5e02bc62b6a59a47a2200f02"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 20:52:10"
  condition:
    hash.sha256(0, filesize) == "d1e0a027f32603f16a20f9f380b6770a9533ea9d5e02bc62b6a59a47a2200f02"
}
```

### Sample 23: `d0c75fc6832d501c`

| Field | Value |
|---|---|
| SHA-256 | `d0c75fc6832d501cafa08ee2b0e7af722542da38116be5c9d1f86f28c54b1f6e` |
| Family label | `unknown` |
| File name | `YuboAPP.exe` |
| File type | `exe` |
| First seen | `2026-07-10 20:51:22` |
| Reporter | `anonymous` |
| Tags | `discord, exe, generic, stealer, TwizGrabber, TwizStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4647a28f31bf02a62f32bab629e3758e` |
| SHA-1 | `186e1099f525a4129d0e833b17f1845a26e62738` |
| SHA-256 | `d0c75fc6832d501cafa08ee2b0e7af722542da38116be5c9d1f86f28c54b1f6e` |
| SHA3-384 | `77f77a88993bfea9feffd9cd7deea97594b93ec7429cc94b94a1f6212e5a28cec05160e33be29a84cd43946e2fa5b26a` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T15F1833D8B2C480EFD891A2F1F2591E3BE766F1A0460692FF4E149725F0279CC6F1562B` |
| SSDEEP | `1572864:NejOYfXbs+CngyA/0q4aVHKffSQTIfr/DkspncMA9F1BrPw7:N4fbonKMq94fqLfn1pKF11Y7` |
| ICON-DHASH | `009c633c2f278e79` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_d0c75fc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0c75fc6832d501cafa08ee2b0e7af722542da38116be5c9d1f86f28c54b1f6e"
    family = "unknown"
    file_name = "YuboAPP.exe"
    file_type = "exe"
    first_seen = "2026-07-10 20:51:22"
  condition:
    hash.sha256(0, filesize) == "d0c75fc6832d501cafa08ee2b0e7af722542da38116be5c9d1f86f28c54b1f6e"
}
```

### Sample 24: `c7ca320e009e41f1`

| Field | Value |
|---|---|
| SHA-256 | `c7ca320e009e41f13cb676d63a6b84d8d6810e9dc2ad4e6cbd44aa7f90ffcdf3` |
| Family label | `unknown` |
| File name | `data_01.jar` |
| File type | `jar` |
| First seen | `2026-07-10 20:50:51` |
| Reporter | `anonymous` |
| Tags | `discord, generic, jar, stealer, TwizGrabber, TwizStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c83f838d309b887b9b33132838b28b1` |
| SHA-1 | `cf42e9b409cf675768e5553ea29dc60d80de95d9` |
| SHA-256 | `c7ca320e009e41f13cb676d63a6b84d8d6810e9dc2ad4e6cbd44aa7f90ffcdf3` |
| SHA3-384 | `bf4cdc14a55d454bb4a411c215196ca93abdbc3bcf300cfa862f470929c56fa9f09b186e4ca355220ce5d8529e4614ef` |
| TLSH | `T16C0723236EDECE29DF6755B395C28246247F65B4AC0B807E03985DC6CA20C4B1752FFA` |
| SSDEEP | `393216:mYHqYSyfCS8/EJ6pGBw1i8nJ0Hp+tR/qPyHJf3CADsob:mYJSyfyEopGa1nJgeR5HJvjjb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_c7ca320e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7ca320e009e41f13cb676d63a6b84d8d6810e9dc2ad4e6cbd44aa7f90ffcdf3"
    family = "unknown"
    file_name = "data_01.jar"
    file_type = "jar"
    first_seen = "2026-07-10 20:50:51"
  condition:
    hash.sha256(0, filesize) == "c7ca320e009e41f13cb676d63a6b84d8d6810e9dc2ad4e6cbd44aa7f90ffcdf3"
}
```

### Sample 25: `8a400cbce796481b`

| Field | Value |
|---|---|
| SHA-256 | `8a400cbce796481b2cf5d7db0c864f7abd88428724c02dae5504292430afd50b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 20:46:41` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fbf7d22bfe700c3d86deb1d43a6b477` |
| SHA-1 | `10a46fc3532287c8c7c4e096cc5a1fc09437acd0` |
| SHA-256 | `8a400cbce796481b2cf5d7db0c864f7abd88428724c02dae5504292430afd50b` |
| SHA3-384 | `aad0b434efbc52aac14f28808006f5077c2ebb20484453376e377ea2a9b3f986ade3f06cb278b9f9e66e5693b90978ca` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T16AD62233724B613DE02E15396E7AA122543B6E717D624E0F96E434ACCF3D1603EBA647` |
| SSDEEP | `196608:Heb0GbB4dfuubX/ZBZf0vghMFne2nPreLoKXrYVN:HHIB4dfBrTaA2Paz7YVN` |
| ICON-DHASH | `14cbc4d2d2c4cb14` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_8a400cbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a400cbce796481b2cf5d7db0c864f7abd88428724c02dae5504292430afd50b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 20:46:41"
  condition:
    hash.sha256(0, filesize) == "8a400cbce796481b2cf5d7db0c864f7abd88428724c02dae5504292430afd50b"
}
```

### Sample 26: `b3369a20d7c603b4`

| Field | Value |
|---|---|
| SHA-256 | `b3369a20d7c603b4d1078010b008a9db1b49dccf694a05e6bd49ede2762a8075` |
| Family label | `ValleyRAT` |
| File name | `16307d047efe925e8c34064306948541.exe` |
| File type | `exe` |
| First seen | `2026-07-10 20:25:10` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16307d047efe925e8c34064306948541` |
| SHA-1 | `56fa917487e7a2aee0b8327774cc99c6a9b86651` |
| SHA-256 | `b3369a20d7c603b4d1078010b008a9db1b49dccf694a05e6bd49ede2762a8075` |
| SHA3-384 | `5ed902d8c49e5793320dba88210c63b185831c3067ccbdb167d5e2041c34359eb8e0ff1fcd83a94a83c67c489a9e54e1` |
| IMPHASH | `95d95a460e8783695f0245e2dce92576` |
| TLSH | `T1AEE37C21B1C1C0B3C8B6253158F4EE759A3DF9701F245DDB63980AB99F302D29B39A67` |
| SSDEEP | `3072:2L+xFSlh/WjgRGGs1tsNA1m8omzdZfwcMorHShKLBUpFUJKHclbafkj54J:GqSv+jgYT/s6MmzffwPIyhKWmAIyJ` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_026_b3369a20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3369a20d7c603b4d1078010b008a9db1b49dccf694a05e6bd49ede2762a8075"
    family = "ValleyRAT"
    file_name = "16307d047efe925e8c34064306948541.exe"
    file_type = "exe"
    first_seen = "2026-07-10 20:25:10"
  condition:
    hash.sha256(0, filesize) == "b3369a20d7c603b4d1078010b008a9db1b49dccf694a05e6bd49ede2762a8075"
}
```

### Sample 27: `d804d93cd08b0b38`

| Field | Value |
|---|---|
| SHA-256 | `d804d93cd08b0b38db03156e20382ca34980c5b9ec604f450c5563cc588a01de` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 19:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6a22bc6d1025589aed446466980d1ad` |
| SHA-1 | `85a6bb9ba170d55b36a3cf476343ec0dfed06269` |
| SHA-256 | `d804d93cd08b0b38db03156e20382ca34980c5b9ec604f450c5563cc588a01de` |
| SHA3-384 | `30f6b6947c9e2d17de13b66da198db3e16ec53196510b4ba5f8c7820610c8b4577b3bc10eca41193c00e568eaa80d930` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T12DE6330863F041FFFA67403C9EA16966D7A978274B31C68F5BE41269BC072E09C3DB52` |
| SSDEEP | `393216:XUXl1D0+WYh39h/rhUy3/u+XMCHWUjX/cuI3/PGTAI:Xa5WYJ/rCy32+XMb8XUH/O7` |
| ICON-DHASH | `b270e8cccce8f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_d804d93c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d804d93cd08b0b38db03156e20382ca34980c5b9ec604f450c5563cc588a01de"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 19:52:10"
  condition:
    hash.sha256(0, filesize) == "d804d93cd08b0b38db03156e20382ca34980c5b9ec604f450c5563cc588a01de"
}
```

### Sample 28: `b8a082c41ffee3ae`

| Field | Value |
|---|---|
| SHA-256 | `b8a082c41ffee3aed36cf5e6746bb9cbd7cd50fb5f40f8d645bbe3727b7655ff` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 19:13:51` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX7.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9827a9093277e0eca14ea6cc158ed1eb` |
| SHA-1 | `4d6ed0fbe709e88eb86c48f0c7800a370a6c0500` |
| SHA-256 | `b8a082c41ffee3aed36cf5e6746bb9cbd7cd50fb5f40f8d645bbe3727b7655ff` |
| SHA3-384 | `ce598121c283138675683593bfecc7da4d6136e90ab6669b6b1fa648b244d073c9bfefdc029e5a90da3abd92ebb1dae1` |
| IMPHASH | `6ae4905beb20d7fee037c53c118208fc` |
| TLSH | `T14AD512527F51E942C1966A71CAA4C7F86332FC0C9A62839B74E3AE5BBDDC6C34D120D4` |
| SSDEEP | `49152:k6UtbIX+WoUA2KBz1dPQjnnxXwhXeKeVJa+EbWxLK8yLR:GqKZPs+beVJaxWZKlLR` |
| ICON-DHASH | `30f8c8d4c4ccf030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_b8a082c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8a082c41ffee3aed36cf5e6746bb9cbd7cd50fb5f40f8d645bbe3727b7655ff"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 19:13:51"
  condition:
    hash.sha256(0, filesize) == "b8a082c41ffee3aed36cf5e6746bb9cbd7cd50fb5f40f8d645bbe3727b7655ff"
}
```

### Sample 29: `a76c02a5dc0c2c12`

| Field | Value |
|---|---|
| SHA-256 | `a76c02a5dc0c2c128e5876f96acf02f63fc1607b9d3a8912d9fd173cc41e65b7` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 18:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `085818055b8b99a09609f586d16009fa` |
| SHA-1 | `e39bc2faae65006681841431c3db7e9e96d44b24` |
| SHA-256 | `a76c02a5dc0c2c128e5876f96acf02f63fc1607b9d3a8912d9fd173cc41e65b7` |
| SHA3-384 | `2e659d48e2c4adbacc0523322718acc24a8eb80b3475d1a580dd96c775fb976fbef640a0ec55b048037cfc2251d02c2a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T106E6339C9BD011FED677903CEEE366D6E0A5B8B217B5DE4B175882257E231E0083B742` |
| SSDEEP | `393216:ENOBO9wf7h8utkrXMCHWUjXxcuI3/PGTAI:EgI2V8umrXMb8XmH/O7` |
| ICON-DHASH | `5479fcbccce4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_a76c02a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a76c02a5dc0c2c128e5876f96acf02f63fc1607b9d3a8912d9fd173cc41e65b7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 18:52:10"
  condition:
    hash.sha256(0, filesize) == "a76c02a5dc0c2c128e5876f96acf02f63fc1607b9d3a8912d9fd173cc41e65b7"
}
```

### Sample 30: `31d54f8ca8b8f388`

| Field | Value |
|---|---|
| SHA-256 | `31d54f8ca8b8f38857b719f97ad4e88218256bcf2690b3ae876196a4366abf57` |
| Family label | `unknown` |
| File name | `NursultanCrack.exe` |
| File type | `exe` |
| First seen | `2026-07-10 18:41:19` |
| Reporter | `Alex_sev` |
| Tags | `AgentTesla, Bobik, exe, Generic, Spyware, TrojanSpy` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35e7f4289f5856d4265ec67987f8d30d` |
| SHA-1 | `dd053a9b191b448d1db8bd3722a902c86b0f02d3` |
| SHA-256 | `31d54f8ca8b8f38857b719f97ad4e88218256bcf2690b3ae876196a4366abf57` |
| SHA3-384 | `b34846e18e9ffc40755eeb8f4a48091a464237c8e9d12c032f579a443aa7a7dc6c29aba97a3de7946e439bb8afea92c1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BA74811CBE51E8C4CE692FF38BE65061577315C63EE2E253364A6EF8C7443A649A207C` |
| SSDEEP | `6144:u52Ewp4YM3bxNF3r209EdRh+7lb8qFjG5ccRFRwWaXv6:A2EfY6J34dRWiqjCtnG` |
| ICON-DHASH | `248ad9d964649b64` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_31d54f8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31d54f8ca8b8f38857b719f97ad4e88218256bcf2690b3ae876196a4366abf57"
    family = "unknown"
    file_name = "NursultanCrack.exe"
    file_type = "exe"
    first_seen = "2026-07-10 18:41:19"
  condition:
    hash.sha256(0, filesize) == "31d54f8ca8b8f38857b719f97ad4e88218256bcf2690b3ae876196a4366abf57"
}
```

### Sample 31: `d623e58c95bfcedd`

| Field | Value |
|---|---|
| SHA-256 | `d623e58c95bfcedd6ad8d02bd4ad7adf98150e8781f37ab9bcd2547b59d5f901` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-10 17:57:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `516031a72d5fab13389bf92c6568cb23` |
| SHA-1 | `2309915dd006b8af62a47e27e9231ed987e8e9d3` |
| SHA-256 | `d623e58c95bfcedd6ad8d02bd4ad7adf98150e8781f37ab9bcd2547b59d5f901` |
| SHA3-384 | `de21a94b4cfaa45f17e47659ac3ae392cf70214333cfe7c0cecfb879dc41d7d1e03f9626e065a2629012ccd9e626cfea` |
| TLSH | `T1F4631955BD82A906C6C943B7FB1E028D332623D8E2ED3217DD156F1177CB62B0D6B162` |
| TELFHASH | `t179c08c4b5a884fcca8d443852929320794a435aa2b52e1f9d6a83f2e09128d5f4c2032` |
| SSDEEP | `1536:2SFzSvpQwD6MjU5c9xE03m/Ng2nlbTrAq+Yr9l2QpXvxdzhvv3FkwbZnU:xzSvp36z5uE0MWCA5YzrJ7v1kwbZnU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_d623e58c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d623e58c95bfcedd6ad8d02bd4ad7adf98150e8781f37ab9bcd2547b59d5f901"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-10 17:57:28"
  condition:
    hash.sha256(0, filesize) == "d623e58c95bfcedd6ad8d02bd4ad7adf98150e8781f37ab9bcd2547b59d5f901"
}
```

### Sample 32: `056fe98ea7435067`

| Field | Value |
|---|---|
| SHA-256 | `056fe98ea74350671b92200b7ec69cb79bf2c389e9a08392b9feaefcd46912da` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-10 17:57:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `251135040156bed88a5b66123b4987f6` |
| SHA-1 | `e2955873af2440b674fbe77043a32dd75592003e` |
| SHA-256 | `056fe98ea74350671b92200b7ec69cb79bf2c389e9a08392b9feaefcd46912da` |
| SHA3-384 | `d75b1cf0454d3bdca7ad9201b07889e2ad15c2233dae527e897f584bbe3f51a861350837bd17f480ae884ada33f891c2` |
| TLSH | `T1B073194AB9829A11D5C5037BFE1E018D731327A8E3DD7223DD24AF21B7CA56B0E7B452` |
| TELFHASH | `t144c08c06da380bec2388c34a56de070e0af27b0b240150736e3b1bd3840f8c2ba0b030` |
| SSDEEP | `1536:EJnqSz2t3hyBuG6I7XZeya8Ev85Augc7am8B13VMmicFTzrwI53YgwbZnZ:DU2t3hyBmI7pREv8gc7abFTzrrhBwbZZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_056fe98e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "056fe98ea74350671b92200b7ec69cb79bf2c389e9a08392b9feaefcd46912da"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-10 17:57:27"
  condition:
    hash.sha256(0, filesize) == "056fe98ea74350671b92200b7ec69cb79bf2c389e9a08392b9feaefcd46912da"
}
```

### Sample 33: `0bfa168904c244a3`

| Field | Value |
|---|---|
| SHA-256 | `0bfa168904c244a3e126040f7b5c675044f8da1a98e533c71c3f2b7c74922d25` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-10 17:57:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c49af552b60e23a6a509de917b5614d` |
| SHA-1 | `cde33c8929fd2640b7232e663682ceea7a732970` |
| SHA-256 | `0bfa168904c244a3e126040f7b5c675044f8da1a98e533c71c3f2b7c74922d25` |
| SHA3-384 | `8c090577d74c36b4837b7c839010349c9461b2c01bb221864361d99fd210fb572772856c3058c5d48956691e90fda431` |
| TLSH | `T114631845BD82A906C6C943B7FA1E428D332563D8E2ED3213DD257F1177CBA2B0D6B162` |
| TELFHASH | `t179c08c4b5a884fcca8d443852929320794a435aa2b52e1f9d6a83f2e09128d5f4c2032` |
| SSDEEP | `1536:FSFzCvpQwv6MbMYtaC/hiG/xw2Vqw7a5IvqchmcoXvSUa3zqwbZnU:0zCvpz6rYR/h5qLtIvXCaUoGwbZnU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_0bfa1689
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bfa168904c244a3e126040f7b5c675044f8da1a98e533c71c3f2b7c74922d25"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-10 17:57:26"
  condition:
    hash.sha256(0, filesize) == "0bfa168904c244a3e126040f7b5c675044f8da1a98e533c71c3f2b7c74922d25"
}
```

### Sample 34: `15e2819ed08fa0da`

| Field | Value |
|---|---|
| SHA-256 | `15e2819ed08fa0daa1a860bc198fd91ad35a67f35bf4dc8f27a785bbd9393384` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-10 17:56:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e12fec5836fd3c68d81ea84332336e5` |
| SHA-1 | `7c57347e935329648b02319c5951adc77d9da178` |
| SHA-256 | `15e2819ed08fa0daa1a860bc198fd91ad35a67f35bf4dc8f27a785bbd9393384` |
| SHA3-384 | `02fe48f30073e6578a622a018c13dd3380232a1dd8231f51e4a6cf6d94eb4250bf4fb75b646b59f7fc1427d9fdbfe9a8` |
| TLSH | `T18493950E2E218FADF76C833447B74E22F25963D622E1C645E15CE5012E6434EB85FBAD` |
| TELFHASH | `t14911ad18883c03f097815d9e2bedff36e4a150ef5a264e338d10f8aeaa206425d00c2c` |
| SSDEEP | `1536:Dx3WMEmSVjU2EhiS1bjERBbI/JE0AXCzenxRwbZn+jcc:5EhkhhERBbI/OyGRwbZn+j/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_15e2819e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15e2819ed08fa0daa1a860bc198fd91ad35a67f35bf4dc8f27a785bbd9393384"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-10 17:56:26"
  condition:
    hash.sha256(0, filesize) == "15e2819ed08fa0daa1a860bc198fd91ad35a67f35bf4dc8f27a785bbd9393384"
}
```

### Sample 35: `b3e2986e69683d45`

| Field | Value |
|---|---|
| SHA-256 | `b3e2986e69683d452f04b4305f5454f03bda2b8a6fce080a97ea9d77699291b1` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-07-10 17:56:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96560e9b05192dc7282076cfa9e943b4` |
| SHA-1 | `072d2670585d2bccabb59ec1b6c1d95d09209cf8` |
| SHA-256 | `b3e2986e69683d452f04b4305f5454f03bda2b8a6fce080a97ea9d77699291b1` |
| SHA3-384 | `655deb595eb195cc7d3c6c5eb8e77de04ea5c4863b88ddbff7526b14a0e0ead90631c60271771373843abe8faeb0452a` |
| TLSH | `T1E693830AAF611EF7EC2FCD3B46E81B06318C640A11A93F797974D928FA1A10B45E3C75` |
| SSDEEP | `1536:zc6DcA5z2G1lkTVH5gldNsxnuWMviN4p5tso/wbZnq:7DcIz2glkeCnukeeWwbZnq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_b3e2986e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3e2986e69683d452f04b4305f5454f03bda2b8a6fce080a97ea9d77699291b1"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-10 17:56:24"
  condition:
    hash.sha256(0, filesize) == "b3e2986e69683d452f04b4305f5454f03bda2b8a6fce080a97ea9d77699291b1"
}
```

### Sample 36: `735bc2580f394934`

| Field | Value |
|---|---|
| SHA-256 | `735bc2580f3949340bb0118c2c926f3036ece7ccef54c3d503584295b2409562` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 17:55:56` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, PMIX0.file, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82c702a0029990197ecb1b7a60bef9cc` |
| SHA-1 | `2fc558a2d35539f332f012e16a7f4745e8b2ac0a` |
| SHA-256 | `735bc2580f3949340bb0118c2c926f3036ece7ccef54c3d503584295b2409562` |
| SHA3-384 | `ff546dc72b50f320136ac5c6caaf637098f30b25c8f59b252d734f30b07fdb8a0b434454e11bb9976527c64772132899` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T12CE59C06BC9208FBC4A9733189B2A1917735BC441B3A37D32E50B7782E72BE16D36795` |
| SSDEEP | `49152:z0z+fvxISXFNU5CSgIBLO/AZd3TSd9+gch9UGAh7R0:z08eUSTYje/Uzi` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_036_735bc258
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "735bc2580f3949340bb0118c2c926f3036ece7ccef54c3d503584295b2409562"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 17:55:56"
  condition:
    hash.sha256(0, filesize) == "735bc2580f3949340bb0118c2c926f3036ece7ccef54c3d503584295b2409562"
}
```

### Sample 37: `64e7d1a4a87ecc13`

| Field | Value |
|---|---|
| SHA-256 | `64e7d1a4a87ecc13cac7f59d2994e1bd0ed1fd275fc98a03a144b1ba4dd68e57` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 17:52:13` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b71e1c8f90b62ce4e508fdf18ff64230` |
| SHA-1 | `ff8a8b823b2bfe485dbfb864e97f043d135b3562` |
| SHA-256 | `64e7d1a4a87ecc13cac7f59d2994e1bd0ed1fd275fc98a03a144b1ba4dd68e57` |
| SHA3-384 | `79725c48249a16ad8930a8a186d55e4823dd0e8fb1e50a3a99b72a7254cb1e1731b29316dfbc12b9ff9ff812c618a5f9` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C2E6334C76E006EEE2B7813CEDD2A590E67574754B32C9DB63A4A7A12D272E04C3E713` |
| SSDEEP | `393216:9rKcJmB32qBzvApItjktyxe8uOtXMCHWUjXycuI3/PGTAI:9uca32MztjktyxefEXMb8XPH/O7` |
| ICON-DHASH | `d4f071e8e8607030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_64e7d1a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64e7d1a4a87ecc13cac7f59d2994e1bd0ed1fd275fc98a03a144b1ba4dd68e57"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 17:52:13"
  condition:
    hash.sha256(0, filesize) == "64e7d1a4a87ecc13cac7f59d2994e1bd0ed1fd275fc98a03a144b1ba4dd68e57"
}
```

### Sample 38: `8c87d9fadaa62189`

| Field | Value |
|---|---|
| SHA-256 | `8c87d9fadaa62189faa0030d6ac78fd6026de5c5d0116ab82a0f11887f398fdc` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 17:19:25` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d587896e00d5dda2713fd07f0440e548` |
| SHA-1 | `6aba8b5c15231806c787f343ff6349a03ff6e389` |
| SHA-256 | `8c87d9fadaa62189faa0030d6ac78fd6026de5c5d0116ab82a0f11887f398fdc` |
| SHA3-384 | `1fc758261c06a2a6629a083f64213fda66e7097069ffbab0a8ffde41e5349d2f8107183af26da745e2adc7dd204399ab` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D7E6334CA6D102FEF973803DDAE155A5E4AA74769B71C8AF079483B4AD030E04D7CE6B` |
| SSDEEP | `393216:bnirm9x1SAtU4PVK5nPjh94EHXMCHWUjX7cuI3/PGTAI:bDx1FtXE5HvHXMb8X4H/O7` |
| ICON-DHASH | `e86864e0d8e8ec4a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_8c87d9fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c87d9fadaa62189faa0030d6ac78fd6026de5c5d0116ab82a0f11887f398fdc"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 17:19:25"
  condition:
    hash.sha256(0, filesize) == "8c87d9fadaa62189faa0030d6ac78fd6026de5c5d0116ab82a0f11887f398fdc"
}
```

### Sample 39: `3600a7ce118dbf99`

| Field | Value |
|---|---|
| SHA-256 | `3600a7ce118dbf9950ac2734abcb8648408b3638085397b94e0c19c193cae3b4` |
| Family label | `unknown` |
| File name | `PQ02HilYcX` |
| File type | `exe` |
| First seen | `2026-07-10 17:08:32` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `844c772727f2c39aaeb04c2e37aa2e63` |
| SHA-1 | `757921e440465cdfaf33b11bd9a567ee0e364314` |
| SHA-256 | `3600a7ce118dbf9950ac2734abcb8648408b3638085397b94e0c19c193cae3b4` |
| SHA3-384 | `a29b50f7b8f6dc15bb968d53a8e17423c081a41eb72ad96a76f50671e6dfebc904bcd070c9e909583af717b6f822660b` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T151E73337F049523BE0AA2B355EB3A024983B96504D928D1BC7EC759CDB356303E7B297` |
| SSDEEP | `1572864:4Ab5tU/EvsBLTW4qIIbDNCRJ062JC3JuuODB7SUOTa1B5n:4Ab5tUesoaI/NS2KJ0DUUaa1Bh` |
| ICON-DHASH | `5050d270cccc82ae` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_3600a7ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3600a7ce118dbf9950ac2734abcb8648408b3638085397b94e0c19c193cae3b4"
    family = "unknown"
    file_name = "PQ02HilYcX"
    file_type = "exe"
    first_seen = "2026-07-10 17:08:32"
  condition:
    hash.sha256(0, filesize) == "3600a7ce118dbf9950ac2734abcb8648408b3638085397b94e0c19c193cae3b4"
}
```

### Sample 40: `3907be4e7ba8c00e`

| Field | Value |
|---|---|
| SHA-256 | `3907be4e7ba8c00e7ed8222ed801fab49272147cd1e37120db827ba81e327853` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 16:48:21` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60dc698929db79870c6d04ddd5eab49e` |
| SHA-1 | `9583d61bb8d6eef05472fa306e585f5c95526a7b` |
| SHA-256 | `3907be4e7ba8c00e7ed8222ed801fab49272147cd1e37120db827ba81e327853` |
| SHA3-384 | `045751e78e228ea5562120e3bf928bb640dd4076489737c6a42d2ffff3a5bda7c808ebd8d54fc904258ac2959aa2f079` |
| IMPHASH | `e387f9bdbdc891a56417c52c45ed0b91` |
| TLSH | `T11795234B07D590AAF1354375D6F281AB9234FD661B7892FF3241B62D2F325C8E630B16` |
| SSDEEP | `49152:oGjHg2Hw4eSgvZDXr0WGPq7vCSlvHPBfe:TjHgbgg9gKWSl5f` |
| ICON-DHASH | `0b075dba73949456` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_040_3907be4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3907be4e7ba8c00e7ed8222ed801fab49272147cd1e37120db827ba81e327853"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 16:48:21"
  condition:
    hash.sha256(0, filesize) == "3907be4e7ba8c00e7ed8222ed801fab49272147cd1e37120db827ba81e327853"
}
```

### Sample 41: `8715bb53fad907f1`

| Field | Value |
|---|---|
| SHA-256 | `8715bb53fad907f12ab1b5ec7bad49d2a4f72bf07f81bb2a6621fd1f9f55ffa1` |
| Family label | `unknown` |
| File name | `tmpe485.exe` |
| File type | `exe` |
| First seen | `2026-07-10 16:30:41` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bg[qtsc], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7eaf75b3eefe5ea0939330effc356fc1` |
| SHA-1 | `b25a6e42ab7f2eecd5554780c3bfca14a8bbc0d8` |
| SHA-256 | `8715bb53fad907f12ab1b5ec7bad49d2a4f72bf07f81bb2a6621fd1f9f55ffa1` |
| SHA3-384 | `579ba908fe548cf56d4402d9c29e4ff064aefffb7435ab5679d3cc79801987dc0cc7d202bebff4ef9cdb94e7189f9415` |
| IMPHASH | `5bf3e23a459983ccf98096c50cb7d303` |
| TLSH | `T163E52C2ED6A9C2F8C7BAC0348A1F4133F5B1781A971897C75028C6726EFB6C56E39714` |
| SSDEEP | `98304:mf5wcbhKfSxJvZb+Gey3FaeW0Z24tRuYOcLDw3:mf5wcbhKfSxJvZb+GJ3FaeW0Z24tRuYg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_8715bb53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8715bb53fad907f12ab1b5ec7bad49d2a4f72bf07f81bb2a6621fd1f9f55ffa1"
    family = "unknown"
    file_name = "tmpe485.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:30:41"
  condition:
    hash.sha256(0, filesize) == "8715bb53fad907f12ab1b5ec7bad49d2a4f72bf07f81bb2a6621fd1f9f55ffa1"
}
```

### Sample 42: `edb371be39673ca2`

| Field | Value |
|---|---|
| SHA-256 | `edb371be39673ca248b4dcb168de0efd90e9d7a39d7cc096c83c435bd6fe260b` |
| Family label | `unknown` |
| File name | `Soda_Music_12.8.1.exe` |
| File type | `exe` |
| First seen | `2026-07-10 16:29:51` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.wos[dll], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75271cf0161e8511b7be50b0e838c4da` |
| SHA-1 | `a312052ffe4b7ba74aa2dbba29ae35904abc09f3` |
| SHA-256 | `edb371be39673ca248b4dcb168de0efd90e9d7a39d7cc096c83c435bd6fe260b` |
| SHA3-384 | `0d74474a8789b496d93eb05704e73a693e15353c3a91662103c16cb7daad086a46af979695ba39f8b12e51e16f27a699` |
| IMPHASH | `928fb3a3e14a2213f2685176d1af18ce` |
| TLSH | `T15E272316A3FD579AF1F7D6709FB4C919F82ABC3AE932E79D0581211D2A21A104C61F33` |
| SSDEEP | `393216:nYzGVwNvb/3F1CedyoXbs9GEike+84hEYzZk0SEeE:svb/3FUedVXAAEie84h5VLSEeE` |
| ICON-DHASH | `c8c917aa8c8696b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_edb371be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edb371be39673ca248b4dcb168de0efd90e9d7a39d7cc096c83c435bd6fe260b"
    family = "unknown"
    file_name = "Soda_Music_12.8.1.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:29:51"
  condition:
    hash.sha256(0, filesize) == "edb371be39673ca248b4dcb168de0efd90e9d7a39d7cc096c83c435bd6fe260b"
}
```

### Sample 43: `a0d1e6b471522635`

| Field | Value |
|---|---|
| SHA-256 | `a0d1e6b471522635bcf7ca0176d6ee8febcf90184078b5e8ce24e0eca970b532` |
| Family label | `unknown` |
| File name | `photo_2026-07-08_16-28-06.exe` |
| File type | `exe` |
| First seen | `2026-07-10 16:28:17` |
| Reporter | `CNGaoLing` |
| Tags | `Cobalt Strike, CobaltStrike, exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbcbd3d66765a89838836454aee4e406` |
| SHA-1 | `caf2122b8035e68df8ab0d61b03661661cd807a4` |
| SHA-256 | `a0d1e6b471522635bcf7ca0176d6ee8febcf90184078b5e8ce24e0eca970b532` |
| SHA3-384 | `08b580b71c0d4734baafa02f7bcf537b4ea397d8a17de56a5ea88944987bf32b3168158c2b77c7134131fa6517df78bc` |
| IMPHASH | `8933df726af36aee00de71ce238a1868` |
| TLSH | `T1912533AACA3C1504E2AF33B333DB7079E43A546D6345E264311BA59A4FD2981531FF2B` |
| SSDEEP | `24576:FO0LWRegDmPzReD55m4k2sgC71BWQ3+UmqzQSHFfs:g0LOade95mKCr+UfMEFU` |
| ICON-DHASH | `82aee0e8e8e8f0e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_a0d1e6b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0d1e6b471522635bcf7ca0176d6ee8febcf90184078b5e8ce24e0eca970b532"
    family = "unknown"
    file_name = "photo_2026-07-08_16-28-06.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:28:17"
  condition:
    hash.sha256(0, filesize) == "a0d1e6b471522635bcf7ca0176d6ee8febcf90184078b5e8ce24e0eca970b532"
}
```

### Sample 44: `d95b179001682c28`

| Field | Value |
|---|---|
| SHA-256 | `d95b179001682c28bdadf09f6e344285562d68f15a2194b0234117de3c5e8408` |
| Family label | `unknown` |
| File name | `2hao.exe` |
| File type | `exe` |
| First seen | `2026-07-10 16:27:22` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.sa, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bf6db92c8daaf9125b79d207cf51893` |
| SHA-1 | `ed5d3fdfa520b24147e5afe2de6748098af26c14` |
| SHA-256 | `d95b179001682c28bdadf09f6e344285562d68f15a2194b0234117de3c5e8408` |
| SHA3-384 | `c52a520ca169f9c7e3b94a348e74e5ee6228ebf37b91ebcf2296dfe6519d9e061bd85f69e2a0412d385e4110a34842f3` |
| IMPHASH | `6d97d5004bf284a38f3ea8331d741a98` |
| TLSH | `T16D74F197A477AA2BE14D24F14FA8452031B5B6DFEB9442C2B089F31E4BC8E5C4917B73` |
| SSDEEP | `6144:fBK23YctT/hE2PL/gggP9d7+3H9t+uv8OIzXgUDvWzDZQNdQ:foWYMLm2PDg3P9d7+3d2zXgUKCNdQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_d95b1790
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d95b179001682c28bdadf09f6e344285562d68f15a2194b0234117de3c5e8408"
    family = "unknown"
    file_name = "2hao.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:27:22"
  condition:
    hash.sha256(0, filesize) == "d95b179001682c28bdadf09f6e344285562d68f15a2194b0234117de3c5e8408"
}
```

### Sample 45: `76d09603b6280d22`

| Field | Value |
|---|---|
| SHA-256 | `76d09603b6280d22dcd73e00a87210a9b24273f93074031fd6a7134559544eae` |
| Family label | `DCRat` |
| File name | `SpooferTracex.bat.exe` |
| File type | `exe` |
| First seen | `2026-07-10 16:20:09` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d82f8f7b42041ebb28438c9bb0a40520` |
| SHA-1 | `0acb7e84cec264ac0f560a5fdf3035ed67236e1d` |
| SHA-256 | `76d09603b6280d22dcd73e00a87210a9b24273f93074031fd6a7134559544eae` |
| SHA3-384 | `c515cfa1ddb72c06735fa2d7fd6ee57ca56f60dff08d732d06ba765681d0c86c51a5892ac59944abe0a84041b34d1e69` |
| IMPHASH | `fcf1390e9ce472c7270447fc5c61a0c1` |
| TLSH | `T1594539017E44CE11F0191633C2EF490847B4AC552BA6E72B7EBA376E65123A37D1DACB` |
| SSDEEP | `12288:aRZ+IoG/n9IQxW3OBsee2X+t4RbZtBUPaHG8dasZPB877aMJO9R8rfQ5KAPVnYlG:U2G/nvxW3Ww0tQaHtasE7297Y9e77SzE` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_045_76d09603
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76d09603b6280d22dcd73e00a87210a9b24273f93074031fd6a7134559544eae"
    family = "DCRat"
    file_name = "SpooferTracex.bat.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:20:09"
  condition:
    hash.sha256(0, filesize) == "76d09603b6280d22dcd73e00a87210a9b24273f93074031fd6a7134559544eae"
}
```

### Sample 46: `9f572140cf3347a0`

| Field | Value |
|---|---|
| SHA-256 | `9f572140cf3347a0485bc0fccb82e04c71558f5eb3e34627ff8ea292fcbf76e4` |
| Family label | `unknown` |
| File name | `NAOLS_win_x64.exe` |
| File type | `exe` |
| First seen | `2026-07-10 16:12:01` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d27193d133a072ec98e7fb763942319` |
| SHA-1 | `6d61d91f9fc66e399998b6615a3e4aa089e030f5` |
| SHA-256 | `9f572140cf3347a0485bc0fccb82e04c71558f5eb3e34627ff8ea292fcbf76e4` |
| SHA3-384 | `4cfbf303fd0dd1ef8a74c9300ed6e47542e660db1f3d50cd91bfc1627744c6844f1dbfad438e4fecb3d1fc15c9e0ecf7` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T12808337AACF08B10C0AF5CF11CB2DB25D26843B62275572E0B2694CDBCD1A74DADF661` |
| SSDEEP | `1572864:Ct9IKPMMIEgA0neSZfNgJtWEd5lGLcN8daRJNV2yaCOfUuolzIsAOTFdLtA97:CUKF7gA0JC3xf8LHdanNV2yyfUJlM23q` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_9f572140
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f572140cf3347a0485bc0fccb82e04c71558f5eb3e34627ff8ea292fcbf76e4"
    family = "unknown"
    file_name = "NAOLS_win_x64.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:12:01"
  condition:
    hash.sha256(0, filesize) == "9f572140cf3347a0485bc0fccb82e04c71558f5eb3e34627ff8ea292fcbf76e4"
}
```

### Sample 47: `0b454d10005df0fb`

| Field | Value |
|---|---|
| SHA-256 | `0b454d10005df0fbe3be6963d95956ae87b32345f8c487feb13b2fa380817184` |
| Family label | `unknown` |
| File name | `package` |
| File type | `zip` |
| First seen | `2026-07-10 16:09:31` |
| Reporter | `monitorsg` |
| Tags | `KongTuke, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bd6a40cc6579453c05d925f6b0b2895` |
| SHA-1 | `5f4ef87a4fe793b5dce840d452b6bee734f90eab` |
| SHA-256 | `0b454d10005df0fbe3be6963d95956ae87b32345f8c487feb13b2fa380817184` |
| SHA3-384 | `1d2157d92aa088bd5a25fa805574e837bff2f7e5d262ee2426e7a60eda0b89fe05143a419d5859f26064b46923b25fb2` |
| TLSH | `T15F6633D8053DAC6ECA1F5BBC15A832785280DB471FC722511473AA029EDD881EEFA7D7` |
| SSDEEP | `196608:ImDKjIkptC5nCJCHUxrlWOnD+toeTDDiWss5iX:b+jIcmnCDrlWOatzTDTssI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_0b454d10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b454d10005df0fbe3be6963d95956ae87b32345f8c487feb13b2fa380817184"
    family = "unknown"
    file_name = "package"
    file_type = "zip"
    first_seen = "2026-07-10 16:09:31"
  condition:
    hash.sha256(0, filesize) == "0b454d10005df0fbe3be6963d95956ae87b32345f8c487feb13b2fa380817184"
}
```

### Sample 48: `c80fc0ffdd56020a`

| Field | Value |
|---|---|
| SHA-256 | `c80fc0ffdd56020a481dd2b4fdd94d44399616da08575546e770fa61bbd14e9c` |
| Family label | `N-W0rm` |
| File name | `1259D26DA885E746C7287A9B6AF34BA2.dll` |
| File type | `dll` |
| First seen | `2026-07-10 15:55:09` |
| Reporter | `abuse_ch` |
| Tags | `dll, N-W0rm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1259d26da885e746c7287a9b6af34ba2` |
| SHA-1 | `d76f64d7f7012be058de050e51742db01ea1feb8` |
| SHA-256 | `c80fc0ffdd56020a481dd2b4fdd94d44399616da08575546e770fa61bbd14e9c` |
| SHA3-384 | `f235e756cb978f60a20d6f55d10645591f487ba0c8d02bc820c8e5df1c17050dc1f6acacd9e19a8032c3657af744138c` |
| IMPHASH | `22b71eafe851b23553c49cc2b572d2ff` |
| TLSH | `T168059EA2E6C3C0F2F8862874927FB77B49385B26031595DBE3846DD79D305D2A938387` |
| SSDEEP | `24576:30M2KO0wUhdSQ0kcEGYyPvFHoLpgUysDAIcSGYk+pxShY9g:DSQPsIcSGYk+DSeg` |

#### Technical Assessment

- The sample is tracked as `N-W0rm` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_N_W0rm_048_c80fc0ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c80fc0ffdd56020a481dd2b4fdd94d44399616da08575546e770fa61bbd14e9c"
    family = "N-W0rm"
    file_name = "1259D26DA885E746C7287A9B6AF34BA2.dll"
    file_type = "dll"
    first_seen = "2026-07-10 15:55:09"
  condition:
    hash.sha256(0, filesize) == "c80fc0ffdd56020a481dd2b4fdd94d44399616da08575546e770fa61bbd14e9c"
}
```

### Sample 49: `6ecef1c94e9d47e2`

| Field | Value |
|---|---|
| SHA-256 | `6ecef1c94e9d47e2da55d0a8c4ee45ddbf289bfe4bcbf7787b994d669b3009e4` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-07-10 15:31:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b87b7f4a28382e04494f7ca1158a75dd` |
| SHA-1 | `89b9882c336c3c0965477cd84d84b29aaef36a76` |
| SHA-256 | `6ecef1c94e9d47e2da55d0a8c4ee45ddbf289bfe4bcbf7787b994d669b3009e4` |
| SHA3-384 | `78ec3f319fbc5d75e4b0f7dd01518d4100644f3d4788755b224b0b2fd12abd84672dc5f7b2cba58e946bb72220af8e72` |
| TLSH | `T1D1334A02726C0F57C0A31674252F1BE487FFEAD122E4F249655F8B6A8A38D371489F9D` |
| SSDEEP | `768:aOXp1s5T7RrIhC3hI68OjAbYXQXaRHVo6rnFRf6eeGyyQgIktHwD:ZEHS683sXT9VouFQG8gI8QD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_6ecef1c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ecef1c94e9d47e2da55d0a8c4ee45ddbf289bfe4bcbf7787b994d669b3009e4"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-07-10 15:31:10"
  condition:
    hash.sha256(0, filesize) == "6ecef1c94e9d47e2da55d0a8c4ee45ddbf289bfe4bcbf7787b994d669b3009e4"
}
```

### Sample 50: `7e2c800894dda7d8`

| Field | Value |
|---|---|
| SHA-256 | `7e2c800894dda7d82725919c109efaeefdf7141391cd6321ea4791a52d450f7f` |
| Family label | `Mirai` |
| File name | `boatnet.arm` |
| File type | `elf` |
| First seen | `2026-07-10 15:31:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8156f6715ba565b9ea1aa92dd51b2d06` |
| SHA-1 | `a35554e185f247291a9c005cf090793fc8533415` |
| SHA-256 | `7e2c800894dda7d82725919c109efaeefdf7141391cd6321ea4791a52d450f7f` |
| SHA3-384 | `021f6c6f778215e0bb4ccb29f27f2d4e7cec74a61f3c55f6fddb5b387df23b2431095f6d975d19a46bc19372dce10e73` |
| TLSH | `T143431881BC819A23C5D4137AF5AE468D3B2133E8E2DF7217DE214F5176C682F0CAAE55` |
| TELFHASH | `t17831cdb54e6c0bcc67e4c34506ca26a8bef831f817016a66de3f3bab51424d1376e427` |
| SSDEEP | `768:bOeMEMDNVo829FdOcuYbb/Yi5ZQ/Ey8WbXZFP8Rt+sZ/Q16NS06gDAvUGFG7aJPE:uEMqdOcBb/lPry8kADPC1EWjbaoZa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_7e2c8008
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e2c800894dda7d82725919c109efaeefdf7141391cd6321ea4791a52d450f7f"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-07-10 15:31:03"
  condition:
    hash.sha256(0, filesize) == "7e2c800894dda7d82725919c109efaeefdf7141391cd6321ea4791a52d450f7f"
}
```

### Sample 51: `5126cc4c568a9b98`

| Field | Value |
|---|---|
| SHA-256 | `5126cc4c568a9b9894b04bdb9d9e095a22483a88c5a99da294e0d3844646f6ba` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-07-10 15:29:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e5899dcc38a475ac4de9430d47c9bfc` |
| SHA-1 | `c217b736cb2ab49cfb1287c18dabb061270a72be` |
| SHA-256 | `5126cc4c568a9b9894b04bdb9d9e095a22483a88c5a99da294e0d3844646f6ba` |
| SHA3-384 | `b18e400497e9208589b3afe329c38754aa6ce5dd90770a62b7fc15556e3033687db85c4ebca83adf55517d5f086ae1d4` |
| TLSH | `T186A2D078C5118FB1EADE5E320E00B1A1B6E41F1E3B9B9CD276829F81561BC636D01ED5` |
| SSDEEP | `384:VoioDiGCDfeIepTfnCy8rdX0BmtUObk1/fQIFxpB/+RlnSHesEMfpM4uVcqgw05j:VovDeCprCyA0syam/DvpB/+eHQx4uVc5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_5126cc4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5126cc4c568a9b9894b04bdb9d9e095a22483a88c5a99da294e0d3844646f6ba"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-07-10 15:29:27"
  condition:
    hash.sha256(0, filesize) == "5126cc4c568a9b9894b04bdb9d9e095a22483a88c5a99da294e0d3844646f6ba"
}
```

### Sample 52: `db19786c2dc80ede`

| Field | Value |
|---|---|
| SHA-256 | `db19786c2dc80edea728fc17f8ae309fcdd6a54a7c1802334f655a83626223cc` |
| Family label | `Mirai` |
| File name | `boatnet.arm` |
| File type | `elf` |
| First seen | `2026-07-10 15:29:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a094397afd9ce4cd35c96c11dd75626d` |
| SHA-1 | `91a0b5466118d1bac2a5c115d8985ec8f911b3f0` |
| SHA-256 | `db19786c2dc80edea728fc17f8ae309fcdd6a54a7c1802334f655a83626223cc` |
| SHA3-384 | `7ae19fab45f60fc466bec3c07ccd62abf93a2186a96333c0beb213f49d2665c8051a9f08c9056f723ebf263167ac641c` |
| TLSH | `T15AA2D0BC6665DC31C3B8583FEB145DC2791B1BF4D1F479B64B90AA6048C622B92F038B` |
| SSDEEP | `384:wPzRL5/AbWpWJ/hxL3JksgSRTmibYyC9uj9OS8vDShymdGUop5h2:SzRL5CTJUSRTmEouYnus3Uozw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_db19786c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db19786c2dc80edea728fc17f8ae309fcdd6a54a7c1802334f655a83626223cc"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-07-10 15:29:25"
  condition:
    hash.sha256(0, filesize) == "db19786c2dc80edea728fc17f8ae309fcdd6a54a7c1802334f655a83626223cc"
}
```

### Sample 53: `5b9df6a1e5aac721`

| Field | Value |
|---|---|
| SHA-256 | `5b9df6a1e5aac72129980b89d769d7aab0a35099cec7c8559346f22f33093fcf` |
| Family label | `Mirai` |
| File name | `boatnet.arm6` |
| File type | `elf` |
| First seen | `2026-07-10 15:28:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1350bd23dccc878dd53fc6a7fb253e6a` |
| SHA-1 | `817866dc59399b00f62f7060e918f2c427d83d01` |
| SHA-256 | `5b9df6a1e5aac72129980b89d769d7aab0a35099cec7c8559346f22f33093fcf` |
| SHA3-384 | `cf54b40b47928904fa5dbbaf777a8f371a4b75ffd602d4a204a2ca53b14aa9e53b7747aa4c40aff0fd81602e69061e31` |
| TLSH | `T1B4630A45F8818E26C5D5027EF92D128E371267E9E2DFB2239E205F203BC692B0D77D59` |
| TELFHASH | `t1bf01c6694f8d266c57c0415dc146821ee9a134d9572215e5df6f5bcf4f13d61345a070` |
| SSDEEP | `1536:6tnSZigkxMwIaIWDxqKlFaQz4dBALr5Bjc1I7iUCnr02fh:XihxdIUDxhjbVtCnr02fh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_5b9df6a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b9df6a1e5aac72129980b89d769d7aab0a35099cec7c8559346f22f33093fcf"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-07-10 15:28:36"
  condition:
    hash.sha256(0, filesize) == "5b9df6a1e5aac72129980b89d769d7aab0a35099cec7c8559346f22f33093fcf"
}
```

### Sample 54: `100498a8d749a4fa`

| Field | Value |
|---|---|
| SHA-256 | `100498a8d749a4fab8176bde19dc864190fcff5c1d38008a5bbbeda0e8254027` |
| Family label | `Mirai` |
| File name | `boatnet.arm6` |
| File type | `elf` |
| First seen | `2026-07-10 15:28:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2a8952931a4c76ae45127ee0960602a` |
| SHA-1 | `2dd93576f7d7181f1db0377c95501e8c53a979e6` |
| SHA-256 | `100498a8d749a4fab8176bde19dc864190fcff5c1d38008a5bbbeda0e8254027` |
| SHA3-384 | `3327b788bac601e2a978f409614307814de4f4efb8e6693b66a6bb76ccd31250ad6fbacb0f5edb2bade321e7361e8c9a` |
| TLSH | `T18EC2D06422316E72C4A50E769C7510C3FF29BFBCD99F612872190C58A3DAA912D781CF` |
| SSDEEP | `768:IYC5mKrXEjfUoOoApAGhYoB0k92z63vGDAsK9q3UELoZ:nC5m6EYQAeY0w21DAUL+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_100498a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "100498a8d749a4fab8176bde19dc864190fcff5c1d38008a5bbbeda0e8254027"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-07-10 15:28:24"
  condition:
    hash.sha256(0, filesize) == "100498a8d749a4fab8176bde19dc864190fcff5c1d38008a5bbbeda0e8254027"
}
```

### Sample 55: `340bfb0fb2d53cb3`

| Field | Value |
|---|---|
| SHA-256 | `340bfb0fb2d53cb31ef8b089ef07b35d2a313dee510ea67b31c2dab1722fb14a` |
| Family label | `Mirai` |
| File name | `boatnet.arc` |
| File type | `elf` |
| First seen | `2026-07-10 15:27:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed1aab5ca873d27dcd23f617a1c39057` |
| SHA-1 | `d9e2675a2da983d227552ff5a92e9f436e59a92a` |
| SHA-256 | `340bfb0fb2d53cb31ef8b089ef07b35d2a313dee510ea67b31c2dab1722fb14a` |
| SHA3-384 | `ebd54e3e9ef919957bdeb7be0cd048c041fdf829a2534c9ad26c1b0b874d64fa11868569559db457692f0d843dc43971` |
| TLSH | `T170B39DDBF2471260C86246F007CB4BED3E2322816F27C5E77D2A657968791CF8906F96` |
| SSDEEP | `768:yK85XyaNNPzJPyTne9iXOCB/wsECoeIpCu2SZmKRT0FzBAVmmMRgIwXzpn554RZ+:ydX5NcheCBAPUuTAKJahmqgJXQ/LW5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_340bfb0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "340bfb0fb2d53cb31ef8b089ef07b35d2a313dee510ea67b31c2dab1722fb14a"
    family = "Mirai"
    file_name = "boatnet.arc"
    file_type = "elf"
    first_seen = "2026-07-10 15:27:25"
  condition:
    hash.sha256(0, filesize) == "340bfb0fb2d53cb31ef8b089ef07b35d2a313dee510ea67b31c2dab1722fb14a"
}
```

### Sample 56: `f6fabebcbfe563fd`

| Field | Value |
|---|---|
| SHA-256 | `f6fabebcbfe563fd6757c5cdf528d97ddd14ffcad1a90c4149ba9993f8da9ae0` |
| Family label | `Mirai` |
| File name | `boatnet.spc` |
| File type | `elf` |
| First seen | `2026-07-10 15:27:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6615c5d0010b68510f555684227af9f` |
| SHA-1 | `ae185a0986ef918aa7f9da00d2b2ed2a489f57eb` |
| SHA-256 | `f6fabebcbfe563fd6757c5cdf528d97ddd14ffcad1a90c4149ba9993f8da9ae0` |
| SHA3-384 | `63c441d0ba49bc5e9ea15503a4c300a06de6a3e0f69d77fc410c162ce72e7eebf65412783a851778d2150e5144e4e8de` |
| TLSH | `T1C2432925B57A1F23D0D0A4BD11FB8B59B2A15ADE26A4C64E7D720F8FFF216406803DB4` |
| SSDEEP | `1536:fOeCbzFJjlxC0SnNoudzHOGuLNrBNLfiO:GLYEGuNBN7iO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_f6fabebc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6fabebcbfe563fd6757c5cdf528d97ddd14ffcad1a90c4149ba9993f8da9ae0"
    family = "Mirai"
    file_name = "boatnet.spc"
    file_type = "elf"
    first_seen = "2026-07-10 15:27:24"
  condition:
    hash.sha256(0, filesize) == "f6fabebcbfe563fd6757c5cdf528d97ddd14ffcad1a90c4149ba9993f8da9ae0"
}
```

### Sample 57: `aedf930f08b6f91f`

| Field | Value |
|---|---|
| SHA-256 | `aedf930f08b6f91f5762aaab686d143cd519ea6c0bf4c648337a98e56e14e8a8` |
| Family label | `AgentTesla` |
| File name | `CELSIUS GALWAY.js` |
| File type | `js` |
| First seen | `2026-07-10 15:12:25` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a92a378389972228b965e99541c9b2cf` |
| SHA-1 | `a1759f9932359ed0a9e93708db29b5070f29bf49` |
| SHA-256 | `aedf930f08b6f91f5762aaab686d143cd519ea6c0bf4c648337a98e56e14e8a8` |
| SHA3-384 | `f2dc09337bad3739beec8b28c1c2118844ff496533cbcd3786d535962abda9f3dce0351bcbca2cd696662965fbe9a429` |
| TLSH | `T1C165F2105FC46F7B86AC5A28E07F266DF3E10AC551976CCAFB727D09AFA670042235B4` |
| SSDEEP | `24576:4cbnQu7OrWD+WfixfvZDBxeTZ7EoRd9cFRF/TzlcTsxR:fkaYfNe97r2pT+k` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_057_aedf930f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aedf930f08b6f91f5762aaab686d143cd519ea6c0bf4c648337a98e56e14e8a8"
    family = "AgentTesla"
    file_name = "CELSIUS GALWAY.js"
    file_type = "js"
    first_seen = "2026-07-10 15:12:25"
  condition:
    hash.sha256(0, filesize) == "aedf930f08b6f91f5762aaab686d143cd519ea6c0bf4c648337a98e56e14e8a8"
}
```

### Sample 58: `c3ae0e4beedf2368`

| Field | Value |
|---|---|
| SHA-256 | `c3ae0e4beedf236835a3ae14298f43f41485502275f53d35be5a5e5c663ac054` |
| Family label | `unknown` |
| File name | `api.rkey` |
| File type | `exe` |
| First seen | `2026-07-10 15:12:20` |
| Reporter | `monitorsg` |
| Tags | `ClearFake, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0190cbb61f333a6f881c97d0901a041c` |
| SHA-1 | `920028f890dcf59100e4e88eacfbde7ff5e51726` |
| SHA-256 | `c3ae0e4beedf236835a3ae14298f43f41485502275f53d35be5a5e5c663ac054` |
| SHA3-384 | `b8cb655b7ae8192ba31cf5b368e55eae342ffc3d9da07ad4e8701a7675d78e416082afa9b6b82b778d059edfd4276dd5` |
| IMPHASH | `4d4fc581fa558ff2e34dd9c7e03574ec` |
| TLSH | `T14D768C0BFDF954CDC55EB2388063B611FD357C008252676329D8B3381E775A8AA9EB39` |
| SSDEEP | `49152:1VRG82E1xfDWblsebSDIQZO8rUT7MG4GfiBKUXl2x9GdCQJgubFuQ4TWiGHC+BNS:amDI7QQu9k9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_c3ae0e4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3ae0e4beedf236835a3ae14298f43f41485502275f53d35be5a5e5c663ac054"
    family = "unknown"
    file_name = "api.rkey"
    file_type = "exe"
    first_seen = "2026-07-10 15:12:20"
  condition:
    hash.sha256(0, filesize) == "c3ae0e4beedf236835a3ae14298f43f41485502275f53d35be5a5e5c663ac054"
}
```

### Sample 59: `8a9f9f3f3e38327b`

| Field | Value |
|---|---|
| SHA-256 | `8a9f9f3f3e38327bebc5096ba195d1d93c61bc277734fb18c4ce2f281bd08f3e` |
| Family label | `unknown` |
| File name | `nexuspay.apk` |
| File type | `apk` |
| First seen | `2026-07-10 14:52:08` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Malware, NexusPay, signed, SpyAgent, Spyware, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1aff26dd5a0d1d4677475c6397ca1f0` |
| SHA-1 | `73770f486f96e103010dc0d4d94677a5c4edf9ce` |
| SHA-256 | `8a9f9f3f3e38327bebc5096ba195d1d93c61bc277734fb18c4ce2f281bd08f3e` |
| SHA3-384 | `505e322f0214226fe1e82bdc9e0dd21e0df35485eec3e2b6f6f527c49726a85cedce7f8d146bc3a458e9d31bb6806ed5` |
| TLSH | `T1747602CAF7C8992BC4735032C57A56F2454B4D1A8E83DF876A14360C6CBBAD44F4ABC9` |
| SSDEEP | `196608:67VQLc7rx9QYHxZyMPtWR8rz1DAmYtXs4f3KFL0W6wvZW33S3gq6:L4r3QYHHyMPBLYOg3fwA3S8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_8a9f9f3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a9f9f3f3e38327bebc5096ba195d1d93c61bc277734fb18c4ce2f281bd08f3e"
    family = "unknown"
    file_name = "nexuspay.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:52:08"
  condition:
    hash.sha256(0, filesize) == "8a9f9f3f3e38327bebc5096ba195d1d93c61bc277734fb18c4ce2f281bd08f3e"
}
```

### Sample 60: `f651876e9185c206`

| Field | Value |
|---|---|
| SHA-256 | `f651876e9185c206d770229b0cb312b7ae620225e0e6768709b93d4258bbbced` |
| Family label | `unknown` |
| File name | `app.apk` |
| File type | `apk` |
| First seen | `2026-07-10 14:42:25` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, GiftVault, Malware, signed, Spyware, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3f27683415acb46724aba86b949acc4` |
| SHA-1 | `9cb266426261bb8e2c4488d1ac316fc0b98454b5` |
| SHA-256 | `f651876e9185c206d770229b0cb312b7ae620225e0e6768709b93d4258bbbced` |
| SHA3-384 | `f6975c24ba98071a23fd9862ab3825c994a9dc31d38c47d0d5e2709ab03d7065b47cf7fe1c19251a7c4f94471a9eccd9` |
| TLSH | `T1C317239BEBC45D5AC8F31732843A5AA244478C268B839BC79F44367C58B76D40F4EBC9` |
| SSDEEP | `393216:0m1Bl750UVXv+kV0kloCLCE5UDjFz3icErnex3Sjvw99H/6:h3J50UVXv+w0BCL8YcEb83SC9H/6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_f651876e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f651876e9185c206d770229b0cb312b7ae620225e0e6768709b93d4258bbbced"
    family = "unknown"
    file_name = "app.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:42:25"
  condition:
    hash.sha256(0, filesize) == "f651876e9185c206d770229b0cb312b7ae620225e0e6768709b93d4258bbbced"
}
```

### Sample 61: `9d924e9bd656a47c`

| Field | Value |
|---|---|
| SHA-256 | `9d924e9bd656a47ca6503d98f389ae94b83a1dd1cc459eefa00d914f61c1acbe` |
| Family label | `unknown` |
| File name | `text.0RsqxRdk.dll.part` |
| File type | `exe` |
| First seen | `2026-07-10 14:30:48` |
| Reporter | `johnk3r` |
| Tags | `exe, misty-violet-6f68-protexweer-workers-dev, stealer, still-snow-667e-protexweer-workers-dev` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bed271d3aefe39f58883888d5ddfe9e` |
| SHA-1 | `d5d41463803243ae888b10ecb76237259eaee4c5` |
| SHA-256 | `9d924e9bd656a47ca6503d98f389ae94b83a1dd1cc459eefa00d914f61c1acbe` |
| SHA3-384 | `2ee86e54827978fe7addaf34f0ed7cf1025f10fb7719a250f19972292ed13ffa42ae30543a09e3480b077fee2c7680f1` |
| IMPHASH | `fbb0f170512b58f09c3280d8814858df` |
| TLSH | `T12205E9535AE70CA9DDD36FBC21D7633AB635FD208B7A8B6B9244C23128131D16E2E744` |
| SSDEEP | `12288:JQYZspWzfV2XTe70oauVFfSHL6feQFZQ/EJH6rjbR:DfzfVxVVFjQ/EJH6rjbR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_9d924e9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d924e9bd656a47ca6503d98f389ae94b83a1dd1cc459eefa00d914f61c1acbe"
    family = "unknown"
    file_name = "text.0RsqxRdk.dll.part"
    file_type = "exe"
    first_seen = "2026-07-10 14:30:48"
  condition:
    hash.sha256(0, filesize) == "9d924e9bd656a47ca6503d98f389ae94b83a1dd1cc459eefa00d914f61c1acbe"
}
```

### Sample 62: `ee4169ae62236462`

| Field | Value |
|---|---|
| SHA-256 | `ee4169ae62236462925b7ef0934d2fd4e10d8d64f97ce4555d625aa390c73041` |
| Family label | `unknown` |
| File name | `mparivahan.apk` |
| File type | `apk` |
| First seen | `2026-07-10 14:12:10` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, GOI, Malware, mParivahan, Riskware, signed, Spyware, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9791ad718e91c69e6802f529bfd1b110` |
| SHA-1 | `5e353a4eaad8d448cd288b92e69f561af57a126a` |
| SHA-256 | `ee4169ae62236462925b7ef0934d2fd4e10d8d64f97ce4555d625aa390c73041` |
| SHA3-384 | `18241df8dde17557b3ffdee0dab424755f1d3dca3702221a53e4c910b3ca785bc937c5078da4ec525bd3bd63ad07622c` |
| TLSH | `T12C1633163799E23DC876513A6C6FA2B27B61BC638D4282577441332F7EB32E04F11DA9` |
| SSDEEP | `98304:xnkJz8YZAq7bdol+UiUJs/+SI2MadhTHVgQwVElPx:iJz8VO89RjSDHMfElJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_ee4169ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee4169ae62236462925b7ef0934d2fd4e10d8d64f97ce4555d625aa390c73041"
    family = "unknown"
    file_name = "mparivahan.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:12:10"
  condition:
    hash.sha256(0, filesize) == "ee4169ae62236462925b7ef0934d2fd4e10d8d64f97ce4555d625aa390c73041"
}
```

### Sample 63: `8c5e495c1e26a4bb`

| Field | Value |
|---|---|
| SHA-256 | `8c5e495c1e26a4bb6aee1a881ace6e7f139e03509cf09f98d7c687710899d383` |
| Family label | `unknown` |
| File name | `TITUR18VIDEO.apk` |
| File type | `apk` |
| First seen | `2026-07-10 14:07:23` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, Riskware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `436eb488e9e99d0dc67b6688885e822e` |
| SHA-1 | `36216a12373e2e4f5dec45c9febebdf5bc6bd433` |
| SHA-256 | `8c5e495c1e26a4bb6aee1a881ace6e7f139e03509cf09f98d7c687710899d383` |
| SHA3-384 | `2ff448e5b92a28d35460e11c1744d462419639b8eafd21fce75d4d0fa274065b7dfe130eddbe0008c11be25714b1ed52` |
| TLSH | `T1A2662382EF56C92ED57381370E9607312266DE2ECA86B70384EC36586C7B6D44FD9EC4` |
| SSDEEP | `98304:UJvBH9nCrjHohW88Zt26oyHQXdcpXuQIwDtx+O/+gRpY1MEIr:OB4PHoQrtpHmdyXMO3IMEIr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_8c5e495c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c5e495c1e26a4bb6aee1a881ace6e7f139e03509cf09f98d7c687710899d383"
    family = "unknown"
    file_name = "TITUR18VIDEO.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:07:23"
  condition:
    hash.sha256(0, filesize) == "8c5e495c1e26a4bb6aee1a881ace6e7f139e03509cf09f98d7c687710899d383"
}
```

### Sample 64: `2290af43f9cecfcf`

| Field | Value |
|---|---|
| SHA-256 | `2290af43f9cecfcfcb7dc0a11318c7fb0b94f43356bd20b9ef8516dea0b05e3a` |
| Family label | `unknown` |
| File name | `PоpkаUz18+.apk` |
| File type | `apk` |
| First seen | `2026-07-10 14:04:18` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, Riskware, signed, SmsSpy, Spyware, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5db3b86e25a7da6a12b0c47bc9a8662d` |
| SHA-1 | `750a6419ad1324fc63567b8ff3162b5850198135` |
| SHA-256 | `2290af43f9cecfcfcb7dc0a11318c7fb0b94f43356bd20b9ef8516dea0b05e3a` |
| SHA3-384 | `f77ce04538beca661fb442be5050a96725a88a42a5bfa3ef6143add1a4b5a924a8c97c9119e1b36a44a9810b0f47de57` |
| TLSH | `T121662380FF55D92FC4BB05334AA3073536669E1E8682A70749EC722C587BAD85FC9EC4` |
| SSDEEP | `98304:amD8iCdtjRIgeZx1KM3lE09EiclUsO4ysCTZOL5wS1bFdCyM4w3nMlGMcmFi:amD8fRSZ3A+C+Zk5wSdFdnM4w3SQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_2290af43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2290af43f9cecfcfcb7dc0a11318c7fb0b94f43356bd20b9ef8516dea0b05e3a"
    family = "unknown"
    file_name = "PоpkаUz18+.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:04:18"
  condition:
    hash.sha256(0, filesize) == "2290af43f9cecfcfcb7dc0a11318c7fb0b94f43356bd20b9ef8516dea0b05e3a"
}
```

### Sample 65: `049adafe2b168d59`

| Field | Value |
|---|---|
| SHA-256 | `049adafe2b168d59f8bc48e1809392a525475778b5f9d3576a6fcfbacf47b899` |
| Family label | `unknown` |
| File name | `? ???_??????+.apk` |
| File type | `apk` |
| First seen | `2026-07-10 14:01:37` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, Riskware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `590f705b018e3310912a0c84ebcdacb7` |
| SHA-1 | `b0a6bf38104b81d1eb559a18edabde415215288e` |
| SHA-256 | `049adafe2b168d59f8bc48e1809392a525475778b5f9d3576a6fcfbacf47b899` |
| SHA3-384 | `c03a269312d500f456a7e4e605243320bb71ad2f7d47f3b45a0167a282db61c48d72c0d50eada582fb3820f4465845b0` |
| TLSH | `T170662381FF86E92FC4B785375993073222559C1EC28297434AEC362D6CBB6D84FD9AD0` |
| SSDEEP | `98304:gwGm934No3dRawGy1qbjW66tE9Ga4kpKIZ98rKbJYrueTua/WehQ38BZ:gZpSvabjtd9Ga4kpKoRJiurqP/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_049adafe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049adafe2b168d59f8bc48e1809392a525475778b5f9d3576a6fcfbacf47b899"
    family = "unknown"
    file_name = "? ???_??????+.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:01:37"
  condition:
    hash.sha256(0, filesize) == "049adafe2b168d59f8bc48e1809392a525475778b5f9d3576a6fcfbacf47b899"
}
```

### Sample 66: `20fbd73d688c4458`

| Field | Value |
|---|---|
| SHA-256 | `20fbd73d688c4458e00668df492de296dc836a480237ad7aeece700aa0a63448` |
| Family label | `unknown` |
| File name | `? ????_?????+.apk` |
| File type | `apk` |
| First seen | `2026-07-10 13:59:31` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, Riskware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `117648e1c3c44a7ca0f77b30e9b9c583` |
| SHA-1 | `85f234f119b7c4bdc401fd96afac2d27cba69abb` |
| SHA-256 | `20fbd73d688c4458e00668df492de296dc836a480237ad7aeece700aa0a63448` |
| SHA3-384 | `0becf8a20642896d6f9d1c0e9d6f1f4bac2ec5ea7763e562fd415363fc5b41fb44823d99db88e8a7851a5017e7a5f665` |
| TLSH | `T1A2562282FF46D82EC07785374A564B3262569D2FCA83930785EC7A281D776E80FD9EC4` |
| SSDEEP | `98304:NvORfCppHmqkp7UcaK0IqKf1zr3WLJoSNlGgYUQNuPDZCmd0pRGNOx5SrGNOcb8M:Vg8axUcrqC1WNoSNl/+YPDhGp6MwGOiH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_20fbd73d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20fbd73d688c4458e00668df492de296dc836a480237ad7aeece700aa0a63448"
    family = "unknown"
    file_name = "? ????_?????+.apk"
    file_type = "apk"
    first_seen = "2026-07-10 13:59:31"
  condition:
    hash.sha256(0, filesize) == "20fbd73d688c4458e00668df492de296dc836a480237ad7aeece700aa0a63448"
}
```

### Sample 67: `9e9bbc587df1ca7d`

| Field | Value |
|---|---|
| SHA-256 | `9e9bbc587df1ca7d228791996f906303c720ad04ceb1692dbdae1f31b050f38a` |
| Family label | `unknown` |
| File name | `Privаt21+.apk` |
| File type | `apk` |
| First seen | `2026-07-10 13:57:55` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, Riskware, signed, SmsSpy, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `530b62315763fd66102c97bac3be2c82` |
| SHA-1 | `c8f18cc5ed49e786385cfcf67337c5334913309c` |
| SHA-256 | `9e9bbc587df1ca7d228791996f906303c720ad04ceb1692dbdae1f31b050f38a` |
| SHA3-384 | `7e27c7fddd3327cca9c7a8ebb7b815408beac8c55bd77881fbfb8e8215c862b5e658c5b21b50e19a8631b6d6fe1c572d` |
| TLSH | `T16C662382EF82C82ED4B7413359A70B3162569D2ECA96938788EC772C5C777D40FD9AC4` |
| SSDEEP | `98304:mrJ41+hrrWF8jufn+WFtsIpADZBHBvjAiAoD/pdAsVtmKbI9JUoXjAoPG:h1+5rWFzvG3DDHGuhEKWXXQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_9e9bbc58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e9bbc587df1ca7d228791996f906303c720ad04ceb1692dbdae1f31b050f38a"
    family = "unknown"
    file_name = "Privаt21+.apk"
    file_type = "apk"
    first_seen = "2026-07-10 13:57:55"
  condition:
    hash.sha256(0, filesize) == "9e9bbc587df1ca7d228791996f906303c720ad04ceb1692dbdae1f31b050f38a"
}
```

### Sample 68: `6963d22462fb4525`

| Field | Value |
|---|---|
| SHA-256 | `6963d22462fb4525e0e3208190906f545b8e507753b2146ffc9f5f7183042fa0` |
| Family label | `unknown` |
| File name | `tuktuk185245.apk` |
| File type | `apk` |
| First seen | `2026-07-10 13:56:39` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, Riskware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `015770c97dcdf990a54b0f9124375cac` |
| SHA-1 | `df57abb605546b0956f92fae2d4b818aea070e3c` |
| SHA-256 | `6963d22462fb4525e0e3208190906f545b8e507753b2146ffc9f5f7183042fa0` |
| SHA3-384 | `3a8239be06b15992e33f26e31a09ac628be0e0d8953b734049f826e19bd1307fb177890fd97a2cad6a7cc2606c2b66d7` |
| TLSH | `T13A562281FF86C52EC4B754374E9206326696DD3ECA87A30784EC36285CB76D84FD9AC4` |
| SSDEEP | `196608:zczRly96o+DTCIPz5k8xFxUpWJK579zd3BAh5rEV:Gy96oU+Yk8xFqc679zdwO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_6963d224
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6963d22462fb4525e0e3208190906f545b8e507753b2146ffc9f5f7183042fa0"
    family = "unknown"
    file_name = "tuktuk185245.apk"
    file_type = "apk"
    first_seen = "2026-07-10 13:56:39"
  condition:
    hash.sha256(0, filesize) == "6963d22462fb4525e0e3208190906f545b8e507753b2146ffc9f5f7183042fa0"
}
```

### Sample 69: `e1a7aead734c79d3`

| Field | Value |
|---|---|
| SHA-256 | `e1a7aead734c79d37f42cbc8fac0f9fddfe6154ad8a892bb679fd9eb0fa49ee7` |
| Family label | `unknown` |
| File name | `e1a7aead734c79d37f42cbc8fac0f9fddfe6154ad8a892bb679fd9eb0fa49ee7` |
| File type | `elf` |
| First seen | `2026-07-10 13:33:19` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `916d46726f95a3036201ec83f9868e5c` |
| SHA-1 | `66634f5ea96d79ac686db29a9c575eeba264e8ac` |
| SHA-256 | `e1a7aead734c79d37f42cbc8fac0f9fddfe6154ad8a892bb679fd9eb0fa49ee7` |
| SHA3-384 | `9904464bd3f75e9480b0641b0eed2f8e7a689d39ad46764608e659419c82660e71c696125d09c0d4ff0ff0b16dc17708` |
| TLSH | `T12255E657E89580F4C1EFE174C726A213B9A13489473437E76FA18AF11B26FE866BC314` |
| SSDEEP | `24576:ci3nHRD3wC7g9rb/TBvO90dL3BmAFd4A64nsfJ7FOQzjFyaWPli9+clei:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64k` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_e1a7aead
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1a7aead734c79d37f42cbc8fac0f9fddfe6154ad8a892bb679fd9eb0fa49ee7"
    family = "unknown"
    file_name = "e1a7aead734c79d37f42cbc8fac0f9fddfe6154ad8a892bb679fd9eb0fa49ee7"
    file_type = "elf"
    first_seen = "2026-07-10 13:33:19"
  condition:
    hash.sha256(0, filesize) == "e1a7aead734c79d37f42cbc8fac0f9fddfe6154ad8a892bb679fd9eb0fa49ee7"
}
```

### Sample 70: `b134976f75a1260a`

| Field | Value |
|---|---|
| SHA-256 | `b134976f75a1260a86d00ac5c7b990bf29c2e45daa6e7c320835132b0956ddee` |
| Family label | `AgentTesla` |
| File name | `Especificaciones del producto.js` |
| File type | `js` |
| First seen | `2026-07-10 13:25:20` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e82d1b7c45bb678e013aa2594d11af2` |
| SHA-1 | `6bab197cb7b96f763a0e253443a5f48ddd87c343` |
| SHA-256 | `b134976f75a1260a86d00ac5c7b990bf29c2e45daa6e7c320835132b0956ddee` |
| SHA3-384 | `48769ce6620998a0cb7db55a1755b0b99bfbd0303b0b1da055f7ebf32d35b9d12e3855c2cec948d393d4a6c98b36413b` |
| TLSH | `T1A165B9C8636D4E5797E4DB6A6F42BC66ACC84207878187353438354AA8FF060DE6CD7B` |
| SSDEEP | `384:h1CllbJZ/rPYcxDl6GZzlJ31WG565wS68DJUdJeZlMdCUNcOalzda5hzciK/qAc1:fqN` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_070_b134976f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b134976f75a1260a86d00ac5c7b990bf29c2e45daa6e7c320835132b0956ddee"
    family = "AgentTesla"
    file_name = "Especificaciones del producto.js"
    file_type = "js"
    first_seen = "2026-07-10 13:25:20"
  condition:
    hash.sha256(0, filesize) == "b134976f75a1260a86d00ac5c7b990bf29c2e45daa6e7c320835132b0956ddee"
}
```

### Sample 71: `28c594c6a9290f69`

| Field | Value |
|---|---|
| SHA-256 | `28c594c6a9290f6953fdc578618f8f5ee0d96bedec6223f0ddef95beb92f121e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 13:22:52` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `324eaa1afb425f7668c54b618f24ed83` |
| SHA-1 | `9ec1e2bbf0e39cc0e672ce2f06d2330a64e6c3e1` |
| SHA-256 | `28c594c6a9290f6953fdc578618f8f5ee0d96bedec6223f0ddef95beb92f121e` |
| SHA3-384 | `401986c4abefe7bbddd6ce51cbac75ac54eb0b71a8e1a17cf6e5816bea506c9f1b8a5858cbebe60d1f0271316845dbd5` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T187C63394F2A409F7F4EB413CC653D439B676B9120F71C59F07B889A22E636E1593AB30` |
| SSDEEP | `196608:4tokexuWZC0W+t2PKMmjdV6kh1DvgKaZca1pqhMkMgQvK3ehQeH2dCkBtp88cWt9:4oxuWZC0W+tHjdl15tFQvK3eaeKBpVtd` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_28c594c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28c594c6a9290f6953fdc578618f8f5ee0d96bedec6223f0ddef95beb92f121e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 13:22:52"
  condition:
    hash.sha256(0, filesize) == "28c594c6a9290f6953fdc578618f8f5ee0d96bedec6223f0ddef95beb92f121e"
}
```

### Sample 72: `1ab810f65b846b0d`

| Field | Value |
|---|---|
| SHA-256 | `1ab810f65b846b0d1aef311bda3d0e96dcc806dd7bdfc7eb414a68d53786a6ad` |
| Family label | `WannaCry` |
| File name | `1ab810f65b846b0d1aef311bda3d0e96dcc806dd7bdfc7eb414a68d53786a6ad` |
| File type | `exe` |
| First seen | `2026-07-10 13:15:10` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `981d4eb72393f6460c64e5444c963d19` |
| SHA-1 | `040ec489b5490566e5f254d4a2ae864901878372` |
| SHA-256 | `1ab810f65b846b0d1aef311bda3d0e96dcc806dd7bdfc7eb414a68d53786a6ad` |
| SHA3-384 | `1a5f84b54bcfae13f35e13c34b62f27f86243f91f16b03166ea554874dd37454ea2402d0f459a2e32a41a3f48b7d1767` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1EB063358626CA1FCE0450AB844B38E1AB7B37C5967BE4B0F87C0866B0D53B57EFA4741` |
| SSDEEP | `98304:DI8qPoBhz1aRxcSUDk36SAEdhvxWa9P5S3R8yAVp2H:DI8qPe1Cxcxk3ZAEUadWR8yc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_072_1ab810f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ab810f65b846b0d1aef311bda3d0e96dcc806dd7bdfc7eb414a68d53786a6ad"
    family = "WannaCry"
    file_name = "1ab810f65b846b0d1aef311bda3d0e96dcc806dd7bdfc7eb414a68d53786a6ad"
    file_type = "exe"
    first_seen = "2026-07-10 13:15:10"
  condition:
    hash.sha256(0, filesize) == "1ab810f65b846b0d1aef311bda3d0e96dcc806dd7bdfc7eb414a68d53786a6ad"
}
```

### Sample 73: `769346ae394c7731`

| Field | Value |
|---|---|
| SHA-256 | `769346ae394c77317f2254e53b376ec2439d26b9fabe637cb2320c7825195103` |
| Family label | `unknown` |
| File name | `769346ae394c77317f2254e53b376ec2439d26b9fabe637cb2320c7825195103` |
| File type | `py` |
| First seen | `2026-07-10 12:22:33` |
| Reporter | `c2hunter` |
| Tags | `py, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `926ee009a6caf31dc4f9b47681967a3c` |
| SHA-1 | `31356200f805fa98779c149d358d7ab64b1d68b3` |
| SHA-256 | `769346ae394c77317f2254e53b376ec2439d26b9fabe637cb2320c7825195103` |
| SHA3-384 | `49f6ebd7ea3dd1f5fa48844a49d7526554fdb98169e55a4e8b96ef4e8adc48ed9afd0e49bffdbc3a85206df7c078fc9f` |
| TLSH | `T1D9D16492DD248422D342ED8C84B28D50731E6E57D9096829FDEC66D02FB903DDE706FE` |
| SSDEEP | `192:D77QErXfeY0x1dazVS/1CxoTQkPS6B/4ty8ZhCHbXD5encoqcQte:D7rX2x1dazeeWZAQg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `py`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_769346ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "769346ae394c77317f2254e53b376ec2439d26b9fabe637cb2320c7825195103"
    family = "unknown"
    file_name = "769346ae394c77317f2254e53b376ec2439d26b9fabe637cb2320c7825195103"
    file_type = "py"
    first_seen = "2026-07-10 12:22:33"
  condition:
    hash.sha256(0, filesize) == "769346ae394c77317f2254e53b376ec2439d26b9fabe637cb2320c7825195103"
}
```

### Sample 74: `b433ecdf855beaaf`

| Field | Value |
|---|---|
| SHA-256 | `b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c` |
| Family label | `ValleyRAT` |
| File name | `LetsVPN.zip` |
| File type | `zip` |
| First seen | `2026-07-10 12:19:38` |
| Reporter | `smica83` |
| Tags | `ValleyRAT, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99a4d8df4398e163b45594e6204fd2c3` |
| SHA-1 | `cca9f72a37173b12d4812644dd288909133cf6e4` |
| SHA-256 | `b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c` |
| SHA3-384 | `591fc75318a4518798d34f30bf00042205b476bc2ee7fb0ec869409d70cbf32efa1c5fc38cf6aeb96f3513881bb48e7f` |
| TLSH | `T1975733157B6EC27CDA99441EFC64B28938A5FAE531BCB048C03E68E904BD0FBB076D55` |
| SSDEEP | `786432:KHnTi9j9jG4zU+ocyToF08XOVh301iyNKtKTP:On6jG+ocyE1Q301LsATP` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_074_b433ecdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c"
    family = "ValleyRAT"
    file_name = "LetsVPN.zip"
    file_type = "zip"
    first_seen = "2026-07-10 12:19:38"
  condition:
    hash.sha256(0, filesize) == "b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c"
}
```

### Sample 75: `8c7f9ec84782eac0`

| Field | Value |
|---|---|
| SHA-256 | `8c7f9ec84782eac067ec0c97a307ad21b6283c2800c02293d2cc4bc789df95e0` |
| Family label | `unknown` |
| File name | `1.exe` |
| File type | `exe` |
| First seen | `2026-07-10 12:16:32` |
| Reporter | `skocherhan` |
| Tags | `103-68-109-59, exe, opendir` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73e09c0e119cd881f4f8266bc9a1305c` |
| SHA-1 | `92b79c546c4c189814363f6d5e808464a25a33ca` |
| SHA-256 | `8c7f9ec84782eac067ec0c97a307ad21b6283c2800c02293d2cc4bc789df95e0` |
| SHA3-384 | `04a7ac43e248365495fb3fbd9c575857b82393fe8dce2aefa7a492a334d81812fc6a1d889a68db9dd997b7daae8450ac` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16D044B55B3A45E43E5BF0BBB59731A1003F1B817A836D35E0DC250DE2EB1B908EA6B53` |
| SSDEEP | `3072:J4z0wC4tQve0koVQ6i4AxZU/j0jPwa/6jdFKbXpdBVYhpjkW:5q0bVQHZU/jgwa/6jdFK7pD2k` |
| ICON-DHASH | `e0d8b54d4ebbd8c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_8c7f9ec8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7f9ec84782eac067ec0c97a307ad21b6283c2800c02293d2cc4bc789df95e0"
    family = "unknown"
    file_name = "1.exe"
    file_type = "exe"
    first_seen = "2026-07-10 12:16:32"
  condition:
    hash.sha256(0, filesize) == "8c7f9ec84782eac067ec0c97a307ad21b6283c2800c02293d2cc4bc789df95e0"
}
```

### Sample 76: `ad6b7658635192bb`

| Field | Value |
|---|---|
| SHA-256 | `ad6b7658635192bbbb428c0b8b78db842c7d4f3501a4998cd69def8a1fa84b20` |
| Family label | `unknown` |
| File name | `ការផ្លាស់ប្តូរថ្មីចំពោះលេខកូដ QR របស់ ABA.rar` |
| File type | `rar` |
| First seen | `2026-07-10 12:15:44` |
| Reporter | `smica83` |
| Tags | `rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f29f918a99b09d05051326d623df89ba` |
| SHA-1 | `a34e0d1f408d7df4130c6b3c972cdf1ebb51d354` |
| SHA-256 | `ad6b7658635192bbbb428c0b8b78db842c7d4f3501a4998cd69def8a1fa84b20` |
| SHA3-384 | `42bb61b3cddb9dad64b363889dfc4a883e4e81dc753682e4b0bd14ad8ce3e5f2bdcb0537ba27c677fa5783612b3f75dd` |
| TLSH | `T1AE1733855FC31D28FD437DDBF9AD757C898A28BFA8E6C4586405AF21BCCA07C848522D` |
| SSDEEP | `393216:DmOZMpIyjgrMw5qELNwRPrPTeXWVCSObfaLbbu14kRVob6aDiYu:lZmjWb5qIepSYOW09n8pfu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_ad6b7658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad6b7658635192bbbb428c0b8b78db842c7d4f3501a4998cd69def8a1fa84b20"
    family = "unknown"
    file_name = "ការផ្លាស់ប្តូរថ្មីចំពោះលេខកូដ QR របស់ ABA.rar"
    file_type = "rar"
    first_seen = "2026-07-10 12:15:44"
  condition:
    hash.sha256(0, filesize) == "ad6b7658635192bbbb428c0b8b78db842c7d4f3501a4998cd69def8a1fa84b20"
}
```

### Sample 77: `ae887a7346ca3547`

| Field | Value |
|---|---|
| SHA-256 | `ae887a7346ca3547c459962ff760fda8b221c16d96fcde758422586fe7a886e3` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 12:11:36` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX1.file, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb7d6536cecdff9abacfb25618aeb2d6` |
| SHA-1 | `0a23a08199e61347c0f4a56fa3204b5774e1b63a` |
| SHA-256 | `ae887a7346ca3547c459962ff760fda8b221c16d96fcde758422586fe7a886e3` |
| SHA3-384 | `daccf8e3085441707726866adab89b06ac96ef3095dc8ee7ef69a92cb83173dfb237b58f949cedeb4b85d527cdd5b7fc` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F7B56A06BCA149FAC4A9733189B261927B75BC081F3A23D72F90B7382E727D16C36755` |
| SSDEEP | `24576:QL4eysWJfTgzkGi1yCHsEPOdYvC/CkVq6nyJJxBpOgwFPZ2Bele5IK2J8ypKJVeu:QLhPWJLgXio78OakI6nQr6Tb7M` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_077_ae887a73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae887a7346ca3547c459962ff760fda8b221c16d96fcde758422586fe7a886e3"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 12:11:36"
  condition:
    hash.sha256(0, filesize) == "ae887a7346ca3547c459962ff760fda8b221c16d96fcde758422586fe7a886e3"
}
```

### Sample 78: `c14b1373052bbc14`

| Field | Value |
|---|---|
| SHA-256 | `c14b1373052bbc14adf5e2ac8f24b5cd97bc4794a18128a33e344db0b4e825f8` |
| Family label | `unknown` |
| File name | `Cty TNHH Truong Minh.zip` |
| File type | `zip` |
| First seen | `2026-07-10 12:08:57` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be1bc331e3173151e72c095a018b4262` |
| SHA-1 | `729c82af1d958b58659f226882ef58583b5dd1e0` |
| SHA-256 | `c14b1373052bbc14adf5e2ac8f24b5cd97bc4794a18128a33e344db0b4e825f8` |
| SHA3-384 | `0d10fb2074151d51162a5f0f85c59206c64d0a6a8113e666903c8477bfcf05ddc004be7a68853a5387f787db7d4d49bf` |
| TLSH | `T1A04131171BE14CC1C1B173B7B8FD81C3D84A91AE23E5201BA8CFC7A2C94AB635352AC4` |
| SSDEEP | `48:vIMf/2pyf1XoDeRMf/2pyf1XoDeLKMf/2pyf1XoDK5JW1RYW:gUupyf14DyUupyf14DLUupyf14DKoP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_c14b1373
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c14b1373052bbc14adf5e2ac8f24b5cd97bc4794a18128a33e344db0b4e825f8"
    family = "unknown"
    file_name = "Cty TNHH Truong Minh.zip"
    file_type = "zip"
    first_seen = "2026-07-10 12:08:57"
  condition:
    hash.sha256(0, filesize) == "c14b1373052bbc14adf5e2ac8f24b5cd97bc4794a18128a33e344db0b4e825f8"
}
```

### Sample 79: `74fef06cff2bb57c`

| Field | Value |
|---|---|
| SHA-256 | `74fef06cff2bb57ccfa1916228ff751ffda777c37f03fc92c46139311020900d` |
| Family label | `unknown` |
| File name | `wdatasvc.exe` |
| File type | `exe` |
| First seen | `2026-07-10 12:02:07` |
| Reporter | `smica83` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7716e278a4fa0db12ef08524f3815fa1` |
| SHA-1 | `973502bf2fb6319e18573f589daa99be9900dd77` |
| SHA-256 | `74fef06cff2bb57ccfa1916228ff751ffda777c37f03fc92c46139311020900d` |
| SHA3-384 | `402cfcee1bf70d116e92061bb9fb52bf06b128f8736ff10a6a5943835cb5f1434c180b90ca180d1abbc8ed5a42901cec` |
| IMPHASH | `b51ccfc346077e98b4127daaef96f8e5` |
| TLSH | `T162C76BC09F02E5689AF7BD720949633DF38603214CB287799962F615797896FF343B0A` |
| SSDEEP | `393216:85T/1bCIC5CQaeXpiboTf9SDW7v9RAOqUGQswQiz:taeYbw9t0Ojq` |
| ICON-DHASH | `f0f0aacecceed8f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_74fef06c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74fef06cff2bb57ccfa1916228ff751ffda777c37f03fc92c46139311020900d"
    family = "unknown"
    file_name = "wdatasvc.exe"
    file_type = "exe"
    first_seen = "2026-07-10 12:02:07"
  condition:
    hash.sha256(0, filesize) == "74fef06cff2bb57ccfa1916228ff751ffda777c37f03fc92c46139311020900d"
}
```

### Sample 80: `27ed20da0e17778e`

| Field | Value |
|---|---|
| SHA-256 | `27ed20da0e17778ec924f06b0acaa955c288a1075c28106a3a3b5ac5292464e3` |
| Family label | `unknown` |
| File name | `LG's Advertising Contract, Application Form and Products.zip` |
| File type | `zip` |
| First seen | `2026-07-10 11:54:47` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6859032df5ceb172a3f8dd34eb22186f` |
| SHA-1 | `69c198cd3c292eee4fb5b477c2ee86ee0e110c35` |
| SHA-256 | `27ed20da0e17778ec924f06b0acaa955c288a1075c28106a3a3b5ac5292464e3` |
| SHA3-384 | `3cbc20ff7abe5b9bab724089658df1993b48d314e7df98f2172890a714a14f39bb07ac6af5e283028324f5b463e8b8c7` |
| TLSH | `T1BA3833D0AE4BDAD111CF104A780EDD9B340EBE2FD0877292C8A8D2CF51F499E55D929B` |
| SSDEEP | `3145728:uORGqO4k5q9KeLrVVLUaUJai0Vg4iYf7++v:uORGperVVfUJZ0C4iyz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_27ed20da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27ed20da0e17778ec924f06b0acaa955c288a1075c28106a3a3b5ac5292464e3"
    family = "unknown"
    file_name = "LG's Advertising Contract, Application Form and Products.zip"
    file_type = "zip"
    first_seen = "2026-07-10 11:54:47"
  condition:
    hash.sha256(0, filesize) == "27ed20da0e17778ec924f06b0acaa955c288a1075c28106a3a3b5ac5292464e3"
}
```

### Sample 81: `062f32dddb6b1263`

| Field | Value |
|---|---|
| SHA-256 | `062f32dddb6b1263f3f20cbc48c5b7f9e1e65521d72c01d87ef50bf4c21d3bfb` |
| Family label | `unknown` |
| File name | `ssa_document.exe` |
| File type | `unknown` |
| First seen | `2026-07-10 11:49:52` |
| Reporter | `smica83` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7af1b86526a4a09c582594445d731bcb` |
| SHA-256 | `062f32dddb6b1263f3f20cbc48c5b7f9e1e65521d72c01d87ef50bf4c21d3bfb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_062f32dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "062f32dddb6b1263f3f20cbc48c5b7f9e1e65521d72c01d87ef50bf4c21d3bfb"
    family = "unknown"
    file_name = "ssa_document.exe"
    file_type = "unknown"
    first_seen = "2026-07-10 11:49:52"
  condition:
    hash.sha256(0, filesize) == "062f32dddb6b1263f3f20cbc48c5b7f9e1e65521d72c01d87ef50bf4c21d3bfb"
}
```

### Sample 82: `bc238716915c3041`

| Field | Value |
|---|---|
| SHA-256 | `bc238716915c304156134fbea50602ff998524470d72bd71edd69d7c943c76a0` |
| Family label | `PureLogsStealer` |
| File name | `IMG00300 Rechnung DE00320-003200.vbs` |
| File type | `vbs` |
| First seen | `2026-07-10 11:34:21` |
| Reporter | `threatcat_ch` |
| Tags | `PureLogsStealer, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c9f8c3f1a7a6cb53ac3520d2247e4ae` |
| SHA-1 | `6c4a2488daf41cff420b9e05815cc6fa4636289e` |
| SHA-256 | `bc238716915c304156134fbea50602ff998524470d72bd71edd69d7c943c76a0` |
| SHA3-384 | `639ff7481b893bfe9614bad494adb708a989b65a6475dd92fa0f3eb3165e984b0b8727bd431693345a73a65fc6a2b72a` |
| TLSH | `T17CE6E4AAFD454B6762F624C83EBB23E4861B56B10C994D45FED0CD0C483794C8EDBDA8` |
| SSDEEP | `384:8vtjBks2RU2u6LYMR5bP/KE7PuFQgjNI/ox1T5CO49r7WpDwaiw8zMvTjqUqL+QS:ZrC3` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_082_bc238716
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc238716915c304156134fbea50602ff998524470d72bd71edd69d7c943c76a0"
    family = "PureLogsStealer"
    file_name = "IMG00300 Rechnung DE00320-003200.vbs"
    file_type = "vbs"
    first_seen = "2026-07-10 11:34:21"
  condition:
    hash.sha256(0, filesize) == "bc238716915c304156134fbea50602ff998524470d72bd71edd69d7c943c76a0"
}
```

### Sample 83: `db6b320a2d734a81`

| Field | Value |
|---|---|
| SHA-256 | `db6b320a2d734a81d7b5c5ffeb47d01629ebc4db7023c89ff19eeffbbaa2fbe4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 11:20:03` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ab6f60914969e057a812ae7997faad2` |
| SHA-1 | `169f94f86e1fb1e9dff68373e5dbc9e77ca6a2e5` |
| SHA-256 | `db6b320a2d734a81d7b5c5ffeb47d01629ebc4db7023c89ff19eeffbbaa2fbe4` |
| SHA3-384 | `9e88f73459679dfcf88942ce2150a6a27216021d6244cb7a9119924b78dae0b82129981cc64efe8b12868fb9982165bf` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T156E6F11BBE83447AC69124B4C6DC72A56F79B488071366839E0BF32C5E762D478BE3D4` |
| SSDEEP | `196608:1hlSJalL9Sr94a++C6Q4Cb70lng+bMvqKMP7BXM7j+3daOTTok03By:1hf9SZaL70oSKMz1XMy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_db6b320a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db6b320a2d734a81d7b5c5ffeb47d01629ebc4db7023c89ff19eeffbbaa2fbe4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 11:20:03"
  condition:
    hash.sha256(0, filesize) == "db6b320a2d734a81d7b5c5ffeb47d01629ebc4db7023c89ff19eeffbbaa2fbe4"
}
```

### Sample 84: `00164d07594203e5`

| Field | Value |
|---|---|
| SHA-256 | `00164d07594203e5db9b29f9f5d731a5c177bda5b536fd83d50cf96fd0afd64c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 10:56:08` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06ab6a6078e179de8afd02a6318c395a` |
| SHA-1 | `dc0cca199f3134f8caba5c6964f71b91c41566b4` |
| SHA-256 | `00164d07594203e5db9b29f9f5d731a5c177bda5b536fd83d50cf96fd0afd64c` |
| SHA3-384 | `09675e88567c1a30f26eacac95cf57544690b867a81c9af97f67822321366ef0da54efc910e4b91a0d3b6aed6260be64` |
| IMPHASH | `5a08440e22a99b9fda864d620400de65` |
| TLSH | `T1B495128FEEA513F6D53E407890115211AB98BC124B10DEEF2B463DB66D63AEA0F39711` |
| SSDEEP | `49152:7uWM0auU4uMuiu1u6CnFwJXPDj3fBHspgnNMHaSXs2/nXf:elj3fBH1MLsA` |
| ICON-DHASH | `f0f89a9a9adcf830` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_00164d07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00164d07594203e5db9b29f9f5d731a5c177bda5b536fd83d50cf96fd0afd64c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 10:56:08"
  condition:
    hash.sha256(0, filesize) == "00164d07594203e5db9b29f9f5d731a5c177bda5b536fd83d50cf96fd0afd64c"
}
```

### Sample 85: `5a2f726ab9db35f6`

| Field | Value |
|---|---|
| SHA-256 | `5a2f726ab9db35f6fe00d364f017e09cb0cbd7a13d98e2a9cdbb12cc7676ce51` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-10 10:52:01` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `982be584be605ccc38f90ff57060efbc` |
| SHA-1 | `e4f5fa66cc88f57cbf61c8d1881f36585298a466` |
| SHA-256 | `5a2f726ab9db35f6fe00d364f017e09cb0cbd7a13d98e2a9cdbb12cc7676ce51` |
| SHA3-384 | `ffe1aa2ede9518818f3adacb320633f5743bb518523f6514838a2561fb3de369684320667a87eafc908366df237c4142` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T17FE6331C36D012EDEAE7503DBED60192E9A434A70B72D5DF07A8C7A12E773E08C39656` |
| SSDEEP | `393216:BXP7iBftKT6H7S8k16GOwoh9vXMCHWUjXCWcuI3/PGTAI:BTWPH7S1TYDXMb8XoH/O7` |
| ICON-DHASH | `e8e86560d8e8ec58` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_085_5a2f726a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a2f726ab9db35f6fe00d364f017e09cb0cbd7a13d98e2a9cdbb12cc7676ce51"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 10:52:01"
  condition:
    hash.sha256(0, filesize) == "5a2f726ab9db35f6fe00d364f017e09cb0cbd7a13d98e2a9cdbb12cc7676ce51"
}
```

### Sample 86: `c3742e8050b86645`

| Field | Value |
|---|---|
| SHA-256 | `c3742e8050b8664520fc1a00b7c84c2aac7eac7cec6249b7be5468504ce22d7c` |
| Family label | `SalatStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 10:49:52` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d7abaa64f6ee8117b900cb20ea8d893` |
| SHA-1 | `4503d6b9653b4ed66da01b3f3c1c8b688841c9fc` |
| SHA-256 | `c3742e8050b8664520fc1a00b7c84c2aac7eac7cec6249b7be5468504ce22d7c` |
| SHA3-384 | `59c4e70987767a45f106bfb7530a5102a98eab84ab642bf4d3e6db9c8a995b6850b2e704a5a00a3cbafef88bc6a5cca1` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T134C65C11FACB54F1F903583140ABB27F23315D048B28CBDBEB547B6AF87B6A1196A705` |
| SSDEEP | `98304:3o/UkrAlUr2piSTwis2Yt4l7hA4fG2IflEk:wAJxTF44lFAxOk` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_086_c3742e80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3742e8050b8664520fc1a00b7c84c2aac7eac7cec6249b7be5468504ce22d7c"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 10:49:52"
  condition:
    hash.sha256(0, filesize) == "c3742e8050b8664520fc1a00b7c84c2aac7eac7cec6249b7be5468504ce22d7c"
}
```

### Sample 87: `38b184d316cda036`

| Field | Value |
|---|---|
| SHA-256 | `38b184d316cda0368a6dcead584e84fa7bdc53fd12b117860e16bee849f46963` |
| Family label | `SalatStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 10:48:37` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3298425727d0644a337faeef0a259802` |
| SHA-1 | `507b161a23629d5a6ede55c8ba9bad5f6e0ed513` |
| SHA-256 | `38b184d316cda0368a6dcead584e84fa7bdc53fd12b117860e16bee849f46963` |
| SHA3-384 | `e474e3ba3263777c3ed8e53164428d5df4476abf9d1e4426fd7a101a99fabc6e0fa15127ad637383799ddb2ed3e2cd51` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T143F533239BDA3521CB4F81BA3E943AB233BF7949E4E34600E134EE9C65B93D54891D4D` |
| SSDEEP | `49152:buI8DepXqD3xooImioqgsuGbJF+VBuN8IG39zdsiYJ2Fdsv0qO3TF0h6n/sS:yI8AqDmToqgsuyY3uN3Gcig24q0h6E` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_087_38b184d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38b184d316cda0368a6dcead584e84fa7bdc53fd12b117860e16bee849f46963"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 10:48:37"
  condition:
    hash.sha256(0, filesize) == "38b184d316cda0368a6dcead584e84fa7bdc53fd12b117860e16bee849f46963"
}
```

### Sample 88: `78ebdfb4809d0889`

| Field | Value |
|---|---|
| SHA-256 | `78ebdfb4809d08896e072f3abb9948d1de9f6adc5f70a994b5d7d033f642abca` |
| Family label | `unknown` |
| File name | `zinstll.86382tt009.msi` |
| File type | `msi` |
| First seen | `2026-07-10 10:43:51` |
| Reporter | `CNGaoLing` |
| Tags | `msi, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20bc3246227cffd9a5ae73c575cf1ef5` |
| SHA-1 | `d0f655c1a2a2f0f66073d610344f750b30fae4b3` |
| SHA-256 | `78ebdfb4809d08896e072f3abb9948d1de9f6adc5f70a994b5d7d033f642abca` |
| SHA3-384 | `843aa47f13372b346de64eaab8a95dfc2e44f3f19f5d8c8fe55fc2edbdbc23335ce2f442ad3496ea28d39da611441b09` |
| TLSH | `T1997633A6B48B3570C98FC7B4845328AE793E3FC879AB4C0B79E93D120E33255557634A` |
| SSDEEP | `196608:vXmrJlA7IAt/U8v6zySm3KzwhW+yvzNvx07me:vXmrJ+V3yu9aHNvxsme` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_78ebdfb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78ebdfb4809d08896e072f3abb9948d1de9f6adc5f70a994b5d7d033f642abca"
    family = "unknown"
    file_name = "zinstll.86382tt009.msi"
    file_type = "msi"
    first_seen = "2026-07-10 10:43:51"
  condition:
    hash.sha256(0, filesize) == "78ebdfb4809d08896e072f3abb9948d1de9f6adc5f70a994b5d7d033f642abca"
}
```

### Sample 89: `485163c279b9dced`

| Field | Value |
|---|---|
| SHA-256 | `485163c279b9dced626742d7fbb6dc9deb989459ba4781aac1a733c9f9b67596` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-10 10:39:13` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX3.file, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19f235b2a219eaa317bb0cdf87464175` |
| SHA-1 | `747d3e6a68f00e4d2f65a4bf071d2c2752a7d1ea` |
| SHA-256 | `485163c279b9dced626742d7fbb6dc9deb989459ba4781aac1a733c9f9b67596` |
| SHA3-384 | `d6aad04a41c9a31a984ba032bad601df1d0e6db14e1ee3edb2fa47c9bed64c97aa98bba1ee04c51f7b1214b001be6cf2` |
| IMPHASH | `67f6728bb9c2c56c262f6da70935d9d5` |
| TLSH | `T1ED548E1AF7A908FAEE77913CC9524505EA727C164761E6CF03A04A672F237E09E3E711` |
| SSDEEP | `3072:CpD/7+957J14/FtcrTx+h0KpnzB0f1gHhCgw5m9FlIsinqKxVqNSwnQ5udgMH4Vw:KT0Uhr1zBE6YwLmCE69kikuRE` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_089_485163c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "485163c279b9dced626742d7fbb6dc9deb989459ba4781aac1a733c9f9b67596"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 10:39:13"
  condition:
    hash.sha256(0, filesize) == "485163c279b9dced626742d7fbb6dc9deb989459ba4781aac1a733c9f9b67596"
}
```

### Sample 90: `29f7aa7843b05ad7`

| Field | Value |
|---|---|
| SHA-256 | `29f7aa7843b05ad7daec3204cabef2baea00f2ceba88f48724452bf6c54edcd2` |
| Family label | `unknown` |
| File name | `29f7aa7843b05ad7daec3204cabef2baea00f2ceba88f48724452bf6c54edcd2` |
| File type | `elf` |
| First seen | `2026-07-10 10:38:45` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b07f90a3df677165306a30d7fc479060` |
| SHA-1 | `e8cb329108a77c9bec44566c97e9076d822daaaa` |
| SHA-256 | `29f7aa7843b05ad7daec3204cabef2baea00f2ceba88f48724452bf6c54edcd2` |
| SHA3-384 | `27c9b6361f7ac81108516ccaecec11fa7170678ce2d20f8851ef229cde64438da49c64d5e54e6e653ae2889bf7b39863` |
| TLSH | `T14057CF7792067CEDE9B94DB4C41015816DA878874778E3C7BAC8B0E666EB6D08D3E730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQq:cqYUQuVDt0TZEAe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_29f7aa78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29f7aa7843b05ad7daec3204cabef2baea00f2ceba88f48724452bf6c54edcd2"
    family = "unknown"
    file_name = "29f7aa7843b05ad7daec3204cabef2baea00f2ceba88f48724452bf6c54edcd2"
    file_type = "elf"
    first_seen = "2026-07-10 10:38:45"
  condition:
    hash.sha256(0, filesize) == "29f7aa7843b05ad7daec3204cabef2baea00f2ceba88f48724452bf6c54edcd2"
}
```

### Sample 91: `5c8f6b545303f7fb`

| Field | Value |
|---|---|
| SHA-256 | `5c8f6b545303f7fb165ad781a113df34ed5008767888e129b4181cdada3977d1` |
| Family label | `unknown` |
| File name | `Lumen.exe` |
| File type | `exe` |
| First seen | `2026-07-10 10:26:14` |
| Reporter | `burger403` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1234de8debf75c7dcebd01e419614fc5` |
| SHA-1 | `c573df87b4536a01149db7ba3b6f1bc2f25173a6` |
| SHA-256 | `5c8f6b545303f7fb165ad781a113df34ed5008767888e129b4181cdada3977d1` |
| SHA3-384 | `2ac6184cec15af5897ac7aaf4c519d704fb20b97ea39ad5b7cf59fa011d7921ab36ab63d78465d8dd26954a1278dacf2` |
| IMPHASH | `c8dddb2d43dd7ad64cab9cd918876bab` |
| TLSH | `T14BB6E67B63E44168C19E813AC052CF50D9F3BE76073FC6E702A11B1A9E617C4DE7AA25` |
| SSDEEP | `49152:oATO0GILCbQ6nBQwEeygpI1qSWihTbviZZS4Acs+oeojrpLI2o4dienqZe95Zuae:zYnTNNLfoeojtdph9LuaHHsfN8jUYar` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_5c8f6b54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c8f6b545303f7fb165ad781a113df34ed5008767888e129b4181cdada3977d1"
    family = "unknown"
    file_name = "Lumen.exe"
    file_type = "exe"
    first_seen = "2026-07-10 10:26:14"
  condition:
    hash.sha256(0, filesize) == "5c8f6b545303f7fb165ad781a113df34ed5008767888e129b4181cdada3977d1"
}
```

### Sample 92: `6fb08191292b05a4`

| Field | Value |
|---|---|
| SHA-256 | `6fb08191292b05a4f8deee0561634954736f6ca0ab25b25f09bdbb12b1ba6560` |
| Family label | `unknown` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-07-10 10:22:09` |
| Reporter | `burger403` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd8916cd89710e5ef14fc1745c848b94` |
| SHA-1 | `706395bd0edba3ca8ff1bb3e9cb9880651064321` |
| SHA-256 | `6fb08191292b05a4f8deee0561634954736f6ca0ab25b25f09bdbb12b1ba6560` |
| SHA3-384 | `9ee352309d253f23f83ce8d4b6e2c29f3223caffdb6edd22f83d4008e5d0968d68be18f060bf28685ea81ecf43e3db46` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1C5168C06B8915D6AC499373148F27112B728B8085B3E27D72E61A6B63F333D25CB3F56` |
| SSDEEP | `49152:CBcFzF6h5a1ejI/Xc0hdLJf3qSXfE0uJ+H7GXT2YRY99NaVIU:CBguI/sgeSFuT2bACU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_6fb08191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fb08191292b05a4f8deee0561634954736f6ca0ab25b25f09bdbb12b1ba6560"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-07-10 10:22:09"
  condition:
    hash.sha256(0, filesize) == "6fb08191292b05a4f8deee0561634954736f6ca0ab25b25f09bdbb12b1ba6560"
}
```

### Sample 93: `09b4fcab98b3288d`

| Field | Value |
|---|---|
| SHA-256 | `09b4fcab98b3288dd1e7f586a1aa0edce9737bdbc32a889dc5a57dc4eb20546f` |
| Family label | `SilentNet` |
| File name | `Prestige1.21-1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-07-10 10:16:06` |
| Reporter | `burger403` |
| Tags | `jar, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdb078c737c4710932d64f1be5459e83` |
| SHA-1 | `1998235767dc86656ecabadcb124ad6c9436762d` |
| SHA-256 | `09b4fcab98b3288dd1e7f586a1aa0edce9737bdbc32a889dc5a57dc4eb20546f` |
| SHA3-384 | `7eb68e9bcb340a74d08a18d2f9e9a31a42bd7afd01efbdc0ce267e500a4f6ada8b3e9554e574593572248dbfac9b670c` |
| TLSH | `T1B67533B909BE731DCFA3D9E1A2E5850C3D682BDB264F11B4B7690B40CDB9103DC629B5` |
| SSDEEP | `49152:l7Gs18zeNIdhKr2lWNraMEzHwJNAXvX5vgBK09kiX:l7GG8zeNcha2YhjovX5IQ09r` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_093_09b4fcab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09b4fcab98b3288dd1e7f586a1aa0edce9737bdbc32a889dc5a57dc4eb20546f"
    family = "SilentNet"
    file_name = "Prestige1.21-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-07-10 10:16:06"
  condition:
    hash.sha256(0, filesize) == "09b4fcab98b3288dd1e7f586a1aa0edce9737bdbc32a889dc5a57dc4eb20546f"
}
```

### Sample 94: `f99db7a12ab80b11`

| Field | Value |
|---|---|
| SHA-256 | `f99db7a12ab80b11c3fdec7bf6688e3f6a8d028fe07de01d5fd8fc5d5ac8a577` |
| Family label | `OverlordRAT` |
| File name | `VMAX_spoof_cracked.exe` |
| File type | `exe` |
| First seen | `2026-07-10 10:13:37` |
| Reporter | `burger403` |
| Tags | `exe, OverlordRAT, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ac739f69647379eb083546f9c126bf3` |
| SHA-1 | `c779ca8d539832e84941e51c4e557a454680b984` |
| SHA-256 | `f99db7a12ab80b11c3fdec7bf6688e3f6a8d028fe07de01d5fd8fc5d5ac8a577` |
| SHA3-384 | `85752ccc8ffd5fd6c9136a5aed095a4030d8d1f7b9babdbb8a9fb7b2b314b02282a8f35b81893395c5c0a081b353582e` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T1D0B74B53F8E22A85D4EAC570C772817BBB613C19077823D70691F7206F3ABD0AAB6745` |
| SSDEEP | `393216:wu2mri78R33vqe6cA2z1m21UYxYGLeo2GBwsg2duWbq6YioaUrRKBA9Nrm2XE:wu2nG3fFAP2GtquWbLEKBCNr` |
| ICON-DHASH | `20d06c3931100a0c` |

#### Technical Assessment

- The sample is tracked as `OverlordRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_OverlordRAT_094_f99db7a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f99db7a12ab80b11c3fdec7bf6688e3f6a8d028fe07de01d5fd8fc5d5ac8a577"
    family = "OverlordRAT"
    file_name = "VMAX_spoof_cracked.exe"
    file_type = "exe"
    first_seen = "2026-07-10 10:13:37"
  condition:
    hash.sha256(0, filesize) == "f99db7a12ab80b11c3fdec7bf6688e3f6a8d028fe07de01d5fd8fc5d5ac8a577"
}
```

### Sample 95: `5867c518b37d2321`

| Field | Value |
|---|---|
| SHA-256 | `5867c518b37d23212e74e19ddfca7c78c1ffee07de17db413a75ded7d2d58b7c` |
| Family label | `SilentNet` |
| File name | `Prestige injector.exe` |
| File type | `exe` |
| First seen | `2026-07-10 10:12:03` |
| Reporter | `burger403` |
| Tags | `exe, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d55d6a4722973772857f242f86a2ef4a` |
| SHA-1 | `255f8f700beb2825b333fbb78ec584816a6c2954` |
| SHA-256 | `5867c518b37d23212e74e19ddfca7c78c1ffee07de17db413a75ded7d2d58b7c` |
| SHA3-384 | `7d6649fc10e8ae5893c4e8dffa38c35f523b1abfbb8cfdaa934f0e386bd2f31977bd4482fb96f57631e0e8112aacbb3f` |
| IMPHASH | `73f461c771aef77ec43d53a0c54f0c8d` |
| TLSH | `T1C6357C83EBA385D8C156C8B5534FF137F9627C8E4A157196ABC41E633E67B64E22CB00` |
| SSDEEP | `12288:SZ+OE4MmD6/Oyspc5EEBBBHGBgzGerwGpvPqItNquB:Scb4M06WpoPrwCvP3f5` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_095_5867c518
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5867c518b37d23212e74e19ddfca7c78c1ffee07de17db413a75ded7d2d58b7c"
    family = "SilentNet"
    file_name = "Prestige injector.exe"
    file_type = "exe"
    first_seen = "2026-07-10 10:12:03"
  condition:
    hash.sha256(0, filesize) == "5867c518b37d23212e74e19ddfca7c78c1ffee07de17db413a75ded7d2d58b7c"
}
```

### Sample 96: `d4d16e820f6ca79b`

| Field | Value |
|---|---|
| SHA-256 | `d4d16e820f6ca79bf362d7bf90656c9a063658bfca57713658cd6253cc34e5d1` |
| Family label | `SilentNet` |
| File name | `RUNFIRST.exe` |
| File type | `exe` |
| First seen | `2026-07-10 10:09:54` |
| Reporter | `burger403` |
| Tags | `exe, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0823dfc3073cb32be7c4ede5f17ed10` |
| SHA-1 | `226d89e2a300032ca5b72b622a71579040e0af9b` |
| SHA-256 | `d4d16e820f6ca79bf362d7bf90656c9a063658bfca57713658cd6253cc34e5d1` |
| SHA3-384 | `c3ab854bfbdbab9033950d25ac44e7de56277402d0234375bf1676603bdeea29eb03163b67904b67965ece706b3d770f` |
| IMPHASH | `73f461c771aef77ec43d53a0c54f0c8d` |
| TLSH | `T1B8357C83EBA3C5D8C156C8B5534BF137F9627C8E4A157196ABC41E633E67B64E22CB00` |
| SSDEEP | `12288:TZ+OE4MmD6/Oyspc5EEBBBHGBgzGerwG7TvPqItNquB:Tcb4M06WpoPrwmTvP3f5` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_096_d4d16e82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4d16e820f6ca79bf362d7bf90656c9a063658bfca57713658cd6253cc34e5d1"
    family = "SilentNet"
    file_name = "RUNFIRST.exe"
    file_type = "exe"
    first_seen = "2026-07-10 10:09:54"
  condition:
    hash.sha256(0, filesize) == "d4d16e820f6ca79bf362d7bf90656c9a063658bfca57713658cd6253cc34e5d1"
}
```

### Sample 97: `482eaafcd2e09b3c`

| Field | Value |
|---|---|
| SHA-256 | `482eaafcd2e09b3c766c51546bbe1a2af495eb1c7bada6f87deec4d27ce8c837` |
| Family label | `unknown` |
| File name | `1_11_4_1480_11.02.2026.rar` |
| File type | `rar` |
| First seen | `2026-07-10 10:08:29` |
| Reporter | `smica83` |
| Tags | `CVE-2025-8088, rar, UKR` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0b61343e6d42bf08e24f95ef1a9fcee` |
| SHA-1 | `08a13e0f2f53e7972a4bb3c30d9310ced8a6afb9` |
| SHA-256 | `482eaafcd2e09b3c766c51546bbe1a2af495eb1c7bada6f87deec4d27ce8c837` |
| SHA3-384 | `4ef70038f5e6ddb0b6572370f16188aec29bc3c7bb507d20856dff2375ac1d9fdaccc998da896bdd60d21ada778708c5` |
| TLSH | `T101938EB2291D7178DA056BF4788B2966524013CCFADC7F17CB40D358EF8EA6B1858E93` |
| SSDEEP | `768:Ewq2XJPB4reOEPPaK6SRFaRXWlCs/1ui2HuwSFzeCpF7gz0Uw0y0y0y0y0y0y0yg:ENRnEPPtXAWlv1ui2HDSFzew7gwYf7kK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_482eaafc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "482eaafcd2e09b3c766c51546bbe1a2af495eb1c7bada6f87deec4d27ce8c837"
    family = "unknown"
    file_name = "1_11_4_1480_11.02.2026.rar"
    file_type = "rar"
    first_seen = "2026-07-10 10:08:29"
  condition:
    hash.sha256(0, filesize) == "482eaafcd2e09b3c766c51546bbe1a2af495eb1c7bada6f87deec4d27ce8c837"
}
```

### Sample 98: `f843b48137d1137d`

| Field | Value |
|---|---|
| SHA-256 | `f843b48137d1137d96e9a9da1fb4b2fdcee3a502925009382ef118abd79fc7fa` |
| Family label | `SilentNet` |
| File name | `Pulse_client-1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-07-10 10:07:44` |
| Reporter | `burger403` |
| Tags | `jar, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dea4721c6d2694770c60297ed38f24b1` |
| SHA-1 | `4fd52653cbb86b5c098261344d88aca1d2ee6add` |
| SHA-256 | `f843b48137d1137d96e9a9da1fb4b2fdcee3a502925009382ef118abd79fc7fa` |
| SHA3-384 | `5e019e24cadb6fb719896d6c606c46d448d7cebbbc33513e981364a5cc329fc738aa62270e1f23debd2ded8d90a95d15` |
| TLSH | `T1F244235E7E49005AF413E17FDFB42C9AED0393E05009582BD83CBE5CA12EEBEA15D661` |
| SSDEEP | `6144:IoSJZ0QONIPA8mp2edLfDb2BEPZN4/giGdGa2RMxDoV/uK9mcEqv0bi01:IoSr0Qo0A1VDb2BEM/gMFR0Dzopmik` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_098_f843b481
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f843b48137d1137d96e9a9da1fb4b2fdcee3a502925009382ef118abd79fc7fa"
    family = "SilentNet"
    file_name = "Pulse_client-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-07-10 10:07:44"
  condition:
    hash.sha256(0, filesize) == "f843b48137d1137d96e9a9da1fb4b2fdcee3a502925009382ef118abd79fc7fa"
}
```

### Sample 99: `3539dbf3d81846f8`

| Field | Value |
|---|---|
| SHA-256 | `3539dbf3d81846f8d7276dd66c63c210d6f50d622d1fad39ee371d1dab5760e2` |
| Family label | `SilentNet` |
| File name | `wockyupdate2-1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-07-10 10:07:43` |
| Reporter | `burger403` |
| Tags | `jar, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `359c70e0164079efe7f10ca0faafa725` |
| SHA-1 | `22e7cf24e898f8c6afceea396ebd5b4b3e3ac490` |
| SHA-256 | `3539dbf3d81846f8d7276dd66c63c210d6f50d622d1fad39ee371d1dab5760e2` |
| SHA3-384 | `0602b24a43be9223453b48efa2c11371a3afccf33a12584b8226709eb12ef5490627a94e4e6c81a75121937cb4730835` |
| TLSH | `T1DBD63303FF29BEBED13FB23751808FD2FA2C05D1C016612E3761588E99C66AB4715A5B` |
| SSDEEP | `393216:RvaDe2kSKV6sIWl8SPam58zrdecXmewRu7t+:FaBkS4IWlBP2vxmiU` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_099_3539dbf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3539dbf3d81846f8d7276dd66c63c210d6f50d622d1fad39ee371d1dab5760e2"
    family = "SilentNet"
    file_name = "wockyupdate2-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-07-10 10:07:43"
  condition:
    hash.sha256(0, filesize) == "3539dbf3d81846f8d7276dd66c63c210d6f50d622d1fad39ee371d1dab5760e2"
}
```

### Sample 100: `f38c4ec565e4b4d2`

| Field | Value |
|---|---|
| SHA-256 | `f38c4ec565e4b4d2ef603e26ee5d226a43d3b8f4bcd84f77cb857f730ec13847` |
| Family label | `SilentNet` |
| File name | `FastCrystals-1.21.1-fabric-1.5.3.jar` |
| File type | `jar` |
| First seen | `2026-07-10 10:07:36` |
| Reporter | `burger403` |
| Tags | `jar, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `619ecac4ac487ce74331cae8258c4227` |
| SHA-1 | `4c14bec1f13ed925955e364ccbabe14792644666` |
| SHA-256 | `f38c4ec565e4b4d2ef603e26ee5d226a43d3b8f4bcd84f77cb857f730ec13847` |
| SHA3-384 | `5e7ee9bcef7bab3b2c0dc5e1267d12fbfe98bd03504ce0396ee549ea750ffed4ef74c599187b0caf42e752852391ca37` |
| TLSH | `T13B14127A915FA12AECB7A73E8790DD92B97693D47206366F03E058414CC0CAF1B44FAD` |
| SSDEEP | `6144:MLODuw3yvA1tDkE70+6xJUqHj6m17980Grnfwa:XjCvARkEoRJVHj6u9lGrfwa` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_100_f38c4ec5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f38c4ec565e4b4d2ef603e26ee5d226a43d3b8f4bcd84f77cb857f730ec13847"
    family = "SilentNet"
    file_name = "FastCrystals-1.21.1-fabric-1.5.3.jar"
    file_type = "jar"
    first_seen = "2026-07-10 10:07:36"
  condition:
    hash.sha256(0, filesize) == "f38c4ec565e4b4d2ef603e26ee5d226a43d3b8f4bcd84f77cb857f730ec13847"
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
 * Generated: 2026-07-11T03:46:43.942072+00:00
 */

rule MalwareBazaar_Pony_001_49e3dd60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49e3dd606bf5bf7e1c49b26a25135b2be18ee75c7b8e751c3dc538c0043e5a3f"
    family = "Pony"
    file_name = "406453301fc2f6c6be8838cfda572f09.exe"
    file_type = "exe"
    first_seen = "2026-07-11 03:40:05"
  condition:
    hash.sha256(0, filesize) == "49e3dd606bf5bf7e1c49b26a25135b2be18ee75c7b8e751c3dc538c0043e5a3f"
}

rule MalwareBazaar_unknown_002_6451eb28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6451eb28eb29c067d8ca421b7a73462b669562ef5e06c447d13914c5d4116150"
    family = "unknown"
    file_name = "TXTconverterSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-11 03:37:50"
  condition:
    hash.sha256(0, filesize) == "6451eb28eb29c067d8ca421b7a73462b669562ef5e06c447d13914c5d4116150"
}

rule MalwareBazaar_unknown_003_71f020cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71f020cf04e4105ab29e14afd46d07c7723d182c8b1ca5cb4d57c54833a83a18"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 02:52:08"
  condition:
    hash.sha256(0, filesize) == "71f020cf04e4105ab29e14afd46d07c7723d182c8b1ca5cb4d57c54833a83a18"
}

rule MalwareBazaar_unknown_004_718efee6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "718efee62a3e13cfe598008f7df9cbab9c738dafb2457f93e1ed00bd1a407c97"
    family = "unknown"
    file_name = "Plus+PDF+Scanner_1.0.1.xapk"
    file_type = "xapk"
    first_seen = "2026-07-11 02:19:37"
  condition:
    hash.sha256(0, filesize) == "718efee62a3e13cfe598008f7df9cbab9c738dafb2457f93e1ed00bd1a407c97"
}

rule MalwareBazaar_unknown_005_40ec19f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ec19f9ca8dd33ca1d90a447ea3b9d2b9dd8691eea1dd5195f4868197c035a2"
    family = "unknown"
    file_name = "com.tachating.messagesms_16.0.xapk"
    file_type = "xapk"
    first_seen = "2026-07-11 02:18:36"
  condition:
    hash.sha256(0, filesize) == "40ec19f9ca8dd33ca1d90a447ea3b9d2b9dd8691eea1dd5195f4868197c035a2"
}

rule MalwareBazaar_unknown_006_b36b132b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b36b132b5d8a5f3a3239302f8ca730c4a76f8abf4783cd670a5f4fd7a35a32c9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-11 01:55:06"
  condition:
    hash.sha256(0, filesize) == "b36b132b5d8a5f3a3239302f8ca730c4a76f8abf4783cd670a5f4fd7a35a32c9"
}

rule MalwareBazaar_unknown_007_2db0b1f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2db0b1f45b14652b69ec0a626e0d21f33218dd5ef99017f80e010c7744a44b41"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 01:52:07"
  condition:
    hash.sha256(0, filesize) == "2db0b1f45b14652b69ec0a626e0d21f33218dd5ef99017f80e010c7744a44b41"
}

rule MalwareBazaar_QuasarRAT_008_ed156580
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed1565803c87371b03b576b6fcfb47ba3aeebdcfa07010f1c27ed9c91a70b074"
    family = "QuasarRAT"
    file_name = "ed1565803c87371b03b576b6fcfb47ba3aeebdcfa0701.exe"
    file_type = "exe"
    first_seen = "2026-07-11 00:10:07"
  condition:
    hash.sha256(0, filesize) == "ed1565803c87371b03b576b6fcfb47ba3aeebdcfa07010f1c27ed9c91a70b074"
}

rule MalwareBazaar_unknown_009_bdbacc03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdbacc0365e49c8df5d9f604db4bed0a67c161e82c4d6a06cca9bba101db7d30"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 23:52:08"
  condition:
    hash.sha256(0, filesize) == "bdbacc0365e49c8df5d9f604db4bed0a67c161e82c4d6a06cca9bba101db7d30"
}

rule MalwareBazaar_RemcosRAT_010_60314e99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60314e99e9c7cf30f9b51fb1956852dafc4d87d996cb56cd05040640cdad99a8"
    family = "RemcosRAT"
    file_name = "SecuriteInfo.com.Trojan.Remcos.1074.656.7210"
    file_type = "exe"
    first_seen = "2026-07-10 23:50:26"
  condition:
    hash.sha256(0, filesize) == "60314e99e9c7cf30f9b51fb1956852dafc4d87d996cb56cd05040640cdad99a8"
}

rule MalwareBazaar_QuasarRAT_011_c97f1f67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c97f1f67e5730c1cb688c7759f5189917c70566480eefa69e873c24cdaa65219"
    family = "QuasarRAT"
    file_name = "SecuriteInfo.com.Win32.Dh-A.52397922"
    file_type = "exe"
    first_seen = "2026-07-10 23:50:25"
  condition:
    hash.sha256(0, filesize) == "c97f1f67e5730c1cb688c7759f5189917c70566480eefa69e873c24cdaa65219"
}

rule MalwareBazaar_unknown_012_cc4b2f37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc4b2f37dfdd748e224622cf88dde7d0bfc016cb81f5b67fc9573b1431b866e8"
    family = "unknown"
    file_name = "file"
    file_type = "msi"
    first_seen = "2026-07-10 23:25:51"
  condition:
    hash.sha256(0, filesize) == "cc4b2f37dfdd748e224622cf88dde7d0bfc016cb81f5b67fc9573b1431b866e8"
}

rule MalwareBazaar_unknown_013_a2f29f07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2f29f078ddd41e2544e3750feba5e60c6f70a8a185e1ec960fcf3cadd663d28"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-10 22:52:17"
  condition:
    hash.sha256(0, filesize) == "a2f29f078ddd41e2544e3750feba5e60c6f70a8a185e1ec960fcf3cadd663d28"
}

rule MalwareBazaar_unknown_014_a62121ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a62121caf724e944291bd1733fd65da8af3d205d27be8f40af9d02cb647189a7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 22:52:09"
  condition:
    hash.sha256(0, filesize) == "a62121caf724e944291bd1733fd65da8af3d205d27be8f40af9d02cb647189a7"
}

rule MalwareBazaar_RemcosRAT_015_6144677a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6144677a8ff6d6cb5b04403c9f07ea326419600f9b469a95502fa022613c56bd"
    family = "RemcosRAT"
    file_name = "6144677a8ff6d6cb5b04403c9f07ea326419600f9b469.exe"
    file_type = "exe"
    first_seen = "2026-07-10 22:20:13"
  condition:
    hash.sha256(0, filesize) == "6144677a8ff6d6cb5b04403c9f07ea326419600f9b469a95502fa022613c56bd"
}

rule MalwareBazaar_RemoteManipulator_016_350db132
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "350db1326d8bdf921d5dfcea54a713d19c8d4b6dddc265b14c55ae0646eecb7e"
    family = "RemoteManipulator"
    file_name = "200c4f697289035f228c5915a5cc6115.exe"
    file_type = "exe"
    first_seen = "2026-07-10 22:20:09"
  condition:
    hash.sha256(0, filesize) == "350db1326d8bdf921d5dfcea54a713d19c8d4b6dddc265b14c55ae0646eecb7e"
}

rule MalwareBazaar_unknown_017_29c252a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29c252a26f6b8c08a89e1b83255bee5637819c50f72b1b974af217540df8fff7"
    family = "unknown"
    file_name = "Clash-X64.exe"
    file_type = "exe"
    first_seen = "2026-07-10 22:18:41"
  condition:
    hash.sha256(0, filesize) == "29c252a26f6b8c08a89e1b83255bee5637819c50f72b1b974af217540df8fff7"
}

rule MalwareBazaar_RemcosRAT_018_bfcab5e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfcab5e114b87543cb400b328ba6555da34ddc0bcd05e0313baa3236e6cd671c"
    family = "RemcosRAT"
    file_name = "xbfcab5e114b87543cb400b328ba6555da34ddc0bcd05.exe"
    file_type = "exe"
    first_seen = "2026-07-10 22:10:07"
  condition:
    hash.sha256(0, filesize) == "bfcab5e114b87543cb400b328ba6555da34ddc0bcd05e0313baa3236e6cd671c"
}

rule MalwareBazaar_unknown_019_fd6de1ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd6de1ced67109859d1bf654a54819598cbbd7eca0bd380168e1360da13abec6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 21:52:10"
  condition:
    hash.sha256(0, filesize) == "fd6de1ced67109859d1bf654a54819598cbbd7eca0bd380168e1360da13abec6"
}

rule MalwareBazaar_unknown_020_9d33fa3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d33fa3e21518a55d1ca0e332aa81bc552c2384c4323f70e8ac8070d8920910b"
    family = "unknown"
    file_name = "file.js"
    file_type = "js"
    first_seen = "2026-07-10 21:04:52"
  condition:
    hash.sha256(0, filesize) == "9d33fa3e21518a55d1ca0e332aa81bc552c2384c4323f70e8ac8070d8920910b"
}

rule MalwareBazaar_DCRat_021_dc2a074c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc2a074cd511f6a130c72a365c0139399610eee9e50368b9f3be20016ede4a4e"
    family = "DCRat"
    file_name = "RAYCl0udExecutor.exe"
    file_type = "exe"
    first_seen = "2026-07-10 21:00:09"
  condition:
    hash.sha256(0, filesize) == "dc2a074cd511f6a130c72a365c0139399610eee9e50368b9f3be20016ede4a4e"
}

rule MalwareBazaar_unknown_022_d1e0a027
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1e0a027f32603f16a20f9f380b6770a9533ea9d5e02bc62b6a59a47a2200f02"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 20:52:10"
  condition:
    hash.sha256(0, filesize) == "d1e0a027f32603f16a20f9f380b6770a9533ea9d5e02bc62b6a59a47a2200f02"
}

rule MalwareBazaar_unknown_023_d0c75fc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0c75fc6832d501cafa08ee2b0e7af722542da38116be5c9d1f86f28c54b1f6e"
    family = "unknown"
    file_name = "YuboAPP.exe"
    file_type = "exe"
    first_seen = "2026-07-10 20:51:22"
  condition:
    hash.sha256(0, filesize) == "d0c75fc6832d501cafa08ee2b0e7af722542da38116be5c9d1f86f28c54b1f6e"
}

rule MalwareBazaar_unknown_024_c7ca320e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7ca320e009e41f13cb676d63a6b84d8d6810e9dc2ad4e6cbd44aa7f90ffcdf3"
    family = "unknown"
    file_name = "data_01.jar"
    file_type = "jar"
    first_seen = "2026-07-10 20:50:51"
  condition:
    hash.sha256(0, filesize) == "c7ca320e009e41f13cb676d63a6b84d8d6810e9dc2ad4e6cbd44aa7f90ffcdf3"
}

rule MalwareBazaar_unknown_025_8a400cbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a400cbce796481b2cf5d7db0c864f7abd88428724c02dae5504292430afd50b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 20:46:41"
  condition:
    hash.sha256(0, filesize) == "8a400cbce796481b2cf5d7db0c864f7abd88428724c02dae5504292430afd50b"
}

rule MalwareBazaar_ValleyRAT_026_b3369a20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3369a20d7c603b4d1078010b008a9db1b49dccf694a05e6bd49ede2762a8075"
    family = "ValleyRAT"
    file_name = "16307d047efe925e8c34064306948541.exe"
    file_type = "exe"
    first_seen = "2026-07-10 20:25:10"
  condition:
    hash.sha256(0, filesize) == "b3369a20d7c603b4d1078010b008a9db1b49dccf694a05e6bd49ede2762a8075"
}

rule MalwareBazaar_unknown_027_d804d93c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d804d93cd08b0b38db03156e20382ca34980c5b9ec604f450c5563cc588a01de"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 19:52:10"
  condition:
    hash.sha256(0, filesize) == "d804d93cd08b0b38db03156e20382ca34980c5b9ec604f450c5563cc588a01de"
}

rule MalwareBazaar_unknown_028_b8a082c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8a082c41ffee3aed36cf5e6746bb9cbd7cd50fb5f40f8d645bbe3727b7655ff"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 19:13:51"
  condition:
    hash.sha256(0, filesize) == "b8a082c41ffee3aed36cf5e6746bb9cbd7cd50fb5f40f8d645bbe3727b7655ff"
}

rule MalwareBazaar_unknown_029_a76c02a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a76c02a5dc0c2c128e5876f96acf02f63fc1607b9d3a8912d9fd173cc41e65b7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 18:52:10"
  condition:
    hash.sha256(0, filesize) == "a76c02a5dc0c2c128e5876f96acf02f63fc1607b9d3a8912d9fd173cc41e65b7"
}

rule MalwareBazaar_unknown_030_31d54f8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31d54f8ca8b8f38857b719f97ad4e88218256bcf2690b3ae876196a4366abf57"
    family = "unknown"
    file_name = "NursultanCrack.exe"
    file_type = "exe"
    first_seen = "2026-07-10 18:41:19"
  condition:
    hash.sha256(0, filesize) == "31d54f8ca8b8f38857b719f97ad4e88218256bcf2690b3ae876196a4366abf57"
}

rule MalwareBazaar_Mirai_031_d623e58c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d623e58c95bfcedd6ad8d02bd4ad7adf98150e8781f37ab9bcd2547b59d5f901"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-10 17:57:28"
  condition:
    hash.sha256(0, filesize) == "d623e58c95bfcedd6ad8d02bd4ad7adf98150e8781f37ab9bcd2547b59d5f901"
}

rule MalwareBazaar_Mirai_032_056fe98e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "056fe98ea74350671b92200b7ec69cb79bf2c389e9a08392b9feaefcd46912da"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-10 17:57:27"
  condition:
    hash.sha256(0, filesize) == "056fe98ea74350671b92200b7ec69cb79bf2c389e9a08392b9feaefcd46912da"
}

rule MalwareBazaar_Mirai_033_0bfa1689
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bfa168904c244a3e126040f7b5c675044f8da1a98e533c71c3f2b7c74922d25"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-10 17:57:26"
  condition:
    hash.sha256(0, filesize) == "0bfa168904c244a3e126040f7b5c675044f8da1a98e533c71c3f2b7c74922d25"
}

rule MalwareBazaar_Mirai_034_15e2819e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15e2819ed08fa0daa1a860bc198fd91ad35a67f35bf4dc8f27a785bbd9393384"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-10 17:56:26"
  condition:
    hash.sha256(0, filesize) == "15e2819ed08fa0daa1a860bc198fd91ad35a67f35bf4dc8f27a785bbd9393384"
}

rule MalwareBazaar_Mirai_035_b3e2986e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3e2986e69683d452f04b4305f5454f03bda2b8a6fce080a97ea9d77699291b1"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-10 17:56:24"
  condition:
    hash.sha256(0, filesize) == "b3e2986e69683d452f04b4305f5454f03bda2b8a6fce080a97ea9d77699291b1"
}

rule MalwareBazaar_Vidar_036_735bc258
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "735bc2580f3949340bb0118c2c926f3036ece7ccef54c3d503584295b2409562"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 17:55:56"
  condition:
    hash.sha256(0, filesize) == "735bc2580f3949340bb0118c2c926f3036ece7ccef54c3d503584295b2409562"
}

rule MalwareBazaar_unknown_037_64e7d1a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64e7d1a4a87ecc13cac7f59d2994e1bd0ed1fd275fc98a03a144b1ba4dd68e57"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 17:52:13"
  condition:
    hash.sha256(0, filesize) == "64e7d1a4a87ecc13cac7f59d2994e1bd0ed1fd275fc98a03a144b1ba4dd68e57"
}

rule MalwareBazaar_unknown_038_8c87d9fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c87d9fadaa62189faa0030d6ac78fd6026de5c5d0116ab82a0f11887f398fdc"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 17:19:25"
  condition:
    hash.sha256(0, filesize) == "8c87d9fadaa62189faa0030d6ac78fd6026de5c5d0116ab82a0f11887f398fdc"
}

rule MalwareBazaar_unknown_039_3600a7ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3600a7ce118dbf9950ac2734abcb8648408b3638085397b94e0c19c193cae3b4"
    family = "unknown"
    file_name = "PQ02HilYcX"
    file_type = "exe"
    first_seen = "2026-07-10 17:08:32"
  condition:
    hash.sha256(0, filesize) == "3600a7ce118dbf9950ac2734abcb8648408b3638085397b94e0c19c193cae3b4"
}

rule MalwareBazaar_Stealc_040_3907be4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3907be4e7ba8c00e7ed8222ed801fab49272147cd1e37120db827ba81e327853"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 16:48:21"
  condition:
    hash.sha256(0, filesize) == "3907be4e7ba8c00e7ed8222ed801fab49272147cd1e37120db827ba81e327853"
}

rule MalwareBazaar_unknown_041_8715bb53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8715bb53fad907f12ab1b5ec7bad49d2a4f72bf07f81bb2a6621fd1f9f55ffa1"
    family = "unknown"
    file_name = "tmpe485.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:30:41"
  condition:
    hash.sha256(0, filesize) == "8715bb53fad907f12ab1b5ec7bad49d2a4f72bf07f81bb2a6621fd1f9f55ffa1"
}

rule MalwareBazaar_unknown_042_edb371be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edb371be39673ca248b4dcb168de0efd90e9d7a39d7cc096c83c435bd6fe260b"
    family = "unknown"
    file_name = "Soda_Music_12.8.1.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:29:51"
  condition:
    hash.sha256(0, filesize) == "edb371be39673ca248b4dcb168de0efd90e9d7a39d7cc096c83c435bd6fe260b"
}

rule MalwareBazaar_unknown_043_a0d1e6b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0d1e6b471522635bcf7ca0176d6ee8febcf90184078b5e8ce24e0eca970b532"
    family = "unknown"
    file_name = "photo_2026-07-08_16-28-06.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:28:17"
  condition:
    hash.sha256(0, filesize) == "a0d1e6b471522635bcf7ca0176d6ee8febcf90184078b5e8ce24e0eca970b532"
}

rule MalwareBazaar_unknown_044_d95b1790
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d95b179001682c28bdadf09f6e344285562d68f15a2194b0234117de3c5e8408"
    family = "unknown"
    file_name = "2hao.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:27:22"
  condition:
    hash.sha256(0, filesize) == "d95b179001682c28bdadf09f6e344285562d68f15a2194b0234117de3c5e8408"
}

rule MalwareBazaar_DCRat_045_76d09603
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76d09603b6280d22dcd73e00a87210a9b24273f93074031fd6a7134559544eae"
    family = "DCRat"
    file_name = "SpooferTracex.bat.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:20:09"
  condition:
    hash.sha256(0, filesize) == "76d09603b6280d22dcd73e00a87210a9b24273f93074031fd6a7134559544eae"
}

rule MalwareBazaar_unknown_046_9f572140
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f572140cf3347a0485bc0fccb82e04c71558f5eb3e34627ff8ea292fcbf76e4"
    family = "unknown"
    file_name = "NAOLS_win_x64.exe"
    file_type = "exe"
    first_seen = "2026-07-10 16:12:01"
  condition:
    hash.sha256(0, filesize) == "9f572140cf3347a0485bc0fccb82e04c71558f5eb3e34627ff8ea292fcbf76e4"
}

rule MalwareBazaar_unknown_047_0b454d10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b454d10005df0fbe3be6963d95956ae87b32345f8c487feb13b2fa380817184"
    family = "unknown"
    file_name = "package"
    file_type = "zip"
    first_seen = "2026-07-10 16:09:31"
  condition:
    hash.sha256(0, filesize) == "0b454d10005df0fbe3be6963d95956ae87b32345f8c487feb13b2fa380817184"
}

rule MalwareBazaar_N_W0rm_048_c80fc0ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c80fc0ffdd56020a481dd2b4fdd94d44399616da08575546e770fa61bbd14e9c"
    family = "N-W0rm"
    file_name = "1259D26DA885E746C7287A9B6AF34BA2.dll"
    file_type = "dll"
    first_seen = "2026-07-10 15:55:09"
  condition:
    hash.sha256(0, filesize) == "c80fc0ffdd56020a481dd2b4fdd94d44399616da08575546e770fa61bbd14e9c"
}

rule MalwareBazaar_Mirai_049_6ecef1c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ecef1c94e9d47e2da55d0a8c4ee45ddbf289bfe4bcbf7787b994d669b3009e4"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-07-10 15:31:10"
  condition:
    hash.sha256(0, filesize) == "6ecef1c94e9d47e2da55d0a8c4ee45ddbf289bfe4bcbf7787b994d669b3009e4"
}

rule MalwareBazaar_Mirai_050_7e2c8008
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e2c800894dda7d82725919c109efaeefdf7141391cd6321ea4791a52d450f7f"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-07-10 15:31:03"
  condition:
    hash.sha256(0, filesize) == "7e2c800894dda7d82725919c109efaeefdf7141391cd6321ea4791a52d450f7f"
}

rule MalwareBazaar_Mirai_051_5126cc4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5126cc4c568a9b9894b04bdb9d9e095a22483a88c5a99da294e0d3844646f6ba"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-07-10 15:29:27"
  condition:
    hash.sha256(0, filesize) == "5126cc4c568a9b9894b04bdb9d9e095a22483a88c5a99da294e0d3844646f6ba"
}

rule MalwareBazaar_Mirai_052_db19786c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db19786c2dc80edea728fc17f8ae309fcdd6a54a7c1802334f655a83626223cc"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-07-10 15:29:25"
  condition:
    hash.sha256(0, filesize) == "db19786c2dc80edea728fc17f8ae309fcdd6a54a7c1802334f655a83626223cc"
}

rule MalwareBazaar_Mirai_053_5b9df6a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b9df6a1e5aac72129980b89d769d7aab0a35099cec7c8559346f22f33093fcf"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-07-10 15:28:36"
  condition:
    hash.sha256(0, filesize) == "5b9df6a1e5aac72129980b89d769d7aab0a35099cec7c8559346f22f33093fcf"
}

rule MalwareBazaar_Mirai_054_100498a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "100498a8d749a4fab8176bde19dc864190fcff5c1d38008a5bbbeda0e8254027"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-07-10 15:28:24"
  condition:
    hash.sha256(0, filesize) == "100498a8d749a4fab8176bde19dc864190fcff5c1d38008a5bbbeda0e8254027"
}

rule MalwareBazaar_Mirai_055_340bfb0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "340bfb0fb2d53cb31ef8b089ef07b35d2a313dee510ea67b31c2dab1722fb14a"
    family = "Mirai"
    file_name = "boatnet.arc"
    file_type = "elf"
    first_seen = "2026-07-10 15:27:25"
  condition:
    hash.sha256(0, filesize) == "340bfb0fb2d53cb31ef8b089ef07b35d2a313dee510ea67b31c2dab1722fb14a"
}

rule MalwareBazaar_Mirai_056_f6fabebc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6fabebcbfe563fd6757c5cdf528d97ddd14ffcad1a90c4149ba9993f8da9ae0"
    family = "Mirai"
    file_name = "boatnet.spc"
    file_type = "elf"
    first_seen = "2026-07-10 15:27:24"
  condition:
    hash.sha256(0, filesize) == "f6fabebcbfe563fd6757c5cdf528d97ddd14ffcad1a90c4149ba9993f8da9ae0"
}

rule MalwareBazaar_AgentTesla_057_aedf930f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aedf930f08b6f91f5762aaab686d143cd519ea6c0bf4c648337a98e56e14e8a8"
    family = "AgentTesla"
    file_name = "CELSIUS GALWAY.js"
    file_type = "js"
    first_seen = "2026-07-10 15:12:25"
  condition:
    hash.sha256(0, filesize) == "aedf930f08b6f91f5762aaab686d143cd519ea6c0bf4c648337a98e56e14e8a8"
}

rule MalwareBazaar_unknown_058_c3ae0e4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3ae0e4beedf236835a3ae14298f43f41485502275f53d35be5a5e5c663ac054"
    family = "unknown"
    file_name = "api.rkey"
    file_type = "exe"
    first_seen = "2026-07-10 15:12:20"
  condition:
    hash.sha256(0, filesize) == "c3ae0e4beedf236835a3ae14298f43f41485502275f53d35be5a5e5c663ac054"
}

rule MalwareBazaar_unknown_059_8a9f9f3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a9f9f3f3e38327bebc5096ba195d1d93c61bc277734fb18c4ce2f281bd08f3e"
    family = "unknown"
    file_name = "nexuspay.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:52:08"
  condition:
    hash.sha256(0, filesize) == "8a9f9f3f3e38327bebc5096ba195d1d93c61bc277734fb18c4ce2f281bd08f3e"
}

rule MalwareBazaar_unknown_060_f651876e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f651876e9185c206d770229b0cb312b7ae620225e0e6768709b93d4258bbbced"
    family = "unknown"
    file_name = "app.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:42:25"
  condition:
    hash.sha256(0, filesize) == "f651876e9185c206d770229b0cb312b7ae620225e0e6768709b93d4258bbbced"
}

rule MalwareBazaar_unknown_061_9d924e9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d924e9bd656a47ca6503d98f389ae94b83a1dd1cc459eefa00d914f61c1acbe"
    family = "unknown"
    file_name = "text.0RsqxRdk.dll.part"
    file_type = "exe"
    first_seen = "2026-07-10 14:30:48"
  condition:
    hash.sha256(0, filesize) == "9d924e9bd656a47ca6503d98f389ae94b83a1dd1cc459eefa00d914f61c1acbe"
}

rule MalwareBazaar_unknown_062_ee4169ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee4169ae62236462925b7ef0934d2fd4e10d8d64f97ce4555d625aa390c73041"
    family = "unknown"
    file_name = "mparivahan.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:12:10"
  condition:
    hash.sha256(0, filesize) == "ee4169ae62236462925b7ef0934d2fd4e10d8d64f97ce4555d625aa390c73041"
}

rule MalwareBazaar_unknown_063_8c5e495c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c5e495c1e26a4bb6aee1a881ace6e7f139e03509cf09f98d7c687710899d383"
    family = "unknown"
    file_name = "TITUR18VIDEO.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:07:23"
  condition:
    hash.sha256(0, filesize) == "8c5e495c1e26a4bb6aee1a881ace6e7f139e03509cf09f98d7c687710899d383"
}

rule MalwareBazaar_unknown_064_2290af43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2290af43f9cecfcfcb7dc0a11318c7fb0b94f43356bd20b9ef8516dea0b05e3a"
    family = "unknown"
    file_name = "PоpkаUz18+.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:04:18"
  condition:
    hash.sha256(0, filesize) == "2290af43f9cecfcfcb7dc0a11318c7fb0b94f43356bd20b9ef8516dea0b05e3a"
}

rule MalwareBazaar_unknown_065_049adafe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049adafe2b168d59f8bc48e1809392a525475778b5f9d3576a6fcfbacf47b899"
    family = "unknown"
    file_name = "? ???_??????+.apk"
    file_type = "apk"
    first_seen = "2026-07-10 14:01:37"
  condition:
    hash.sha256(0, filesize) == "049adafe2b168d59f8bc48e1809392a525475778b5f9d3576a6fcfbacf47b899"
}

rule MalwareBazaar_unknown_066_20fbd73d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20fbd73d688c4458e00668df492de296dc836a480237ad7aeece700aa0a63448"
    family = "unknown"
    file_name = "? ????_?????+.apk"
    file_type = "apk"
    first_seen = "2026-07-10 13:59:31"
  condition:
    hash.sha256(0, filesize) == "20fbd73d688c4458e00668df492de296dc836a480237ad7aeece700aa0a63448"
}

rule MalwareBazaar_unknown_067_9e9bbc58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e9bbc587df1ca7d228791996f906303c720ad04ceb1692dbdae1f31b050f38a"
    family = "unknown"
    file_name = "Privаt21+.apk"
    file_type = "apk"
    first_seen = "2026-07-10 13:57:55"
  condition:
    hash.sha256(0, filesize) == "9e9bbc587df1ca7d228791996f906303c720ad04ceb1692dbdae1f31b050f38a"
}

rule MalwareBazaar_unknown_068_6963d224
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6963d22462fb4525e0e3208190906f545b8e507753b2146ffc9f5f7183042fa0"
    family = "unknown"
    file_name = "tuktuk185245.apk"
    file_type = "apk"
    first_seen = "2026-07-10 13:56:39"
  condition:
    hash.sha256(0, filesize) == "6963d22462fb4525e0e3208190906f545b8e507753b2146ffc9f5f7183042fa0"
}

rule MalwareBazaar_unknown_069_e1a7aead
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1a7aead734c79d37f42cbc8fac0f9fddfe6154ad8a892bb679fd9eb0fa49ee7"
    family = "unknown"
    file_name = "e1a7aead734c79d37f42cbc8fac0f9fddfe6154ad8a892bb679fd9eb0fa49ee7"
    file_type = "elf"
    first_seen = "2026-07-10 13:33:19"
  condition:
    hash.sha256(0, filesize) == "e1a7aead734c79d37f42cbc8fac0f9fddfe6154ad8a892bb679fd9eb0fa49ee7"
}

rule MalwareBazaar_AgentTesla_070_b134976f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b134976f75a1260a86d00ac5c7b990bf29c2e45daa6e7c320835132b0956ddee"
    family = "AgentTesla"
    file_name = "Especificaciones del producto.js"
    file_type = "js"
    first_seen = "2026-07-10 13:25:20"
  condition:
    hash.sha256(0, filesize) == "b134976f75a1260a86d00ac5c7b990bf29c2e45daa6e7c320835132b0956ddee"
}

rule MalwareBazaar_unknown_071_28c594c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28c594c6a9290f6953fdc578618f8f5ee0d96bedec6223f0ddef95beb92f121e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 13:22:52"
  condition:
    hash.sha256(0, filesize) == "28c594c6a9290f6953fdc578618f8f5ee0d96bedec6223f0ddef95beb92f121e"
}

rule MalwareBazaar_WannaCry_072_1ab810f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ab810f65b846b0d1aef311bda3d0e96dcc806dd7bdfc7eb414a68d53786a6ad"
    family = "WannaCry"
    file_name = "1ab810f65b846b0d1aef311bda3d0e96dcc806dd7bdfc7eb414a68d53786a6ad"
    file_type = "exe"
    first_seen = "2026-07-10 13:15:10"
  condition:
    hash.sha256(0, filesize) == "1ab810f65b846b0d1aef311bda3d0e96dcc806dd7bdfc7eb414a68d53786a6ad"
}

rule MalwareBazaar_unknown_073_769346ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "769346ae394c77317f2254e53b376ec2439d26b9fabe637cb2320c7825195103"
    family = "unknown"
    file_name = "769346ae394c77317f2254e53b376ec2439d26b9fabe637cb2320c7825195103"
    file_type = "py"
    first_seen = "2026-07-10 12:22:33"
  condition:
    hash.sha256(0, filesize) == "769346ae394c77317f2254e53b376ec2439d26b9fabe637cb2320c7825195103"
}

rule MalwareBazaar_ValleyRAT_074_b433ecdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c"
    family = "ValleyRAT"
    file_name = "LetsVPN.zip"
    file_type = "zip"
    first_seen = "2026-07-10 12:19:38"
  condition:
    hash.sha256(0, filesize) == "b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c"
}

rule MalwareBazaar_unknown_075_8c7f9ec8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7f9ec84782eac067ec0c97a307ad21b6283c2800c02293d2cc4bc789df95e0"
    family = "unknown"
    file_name = "1.exe"
    file_type = "exe"
    first_seen = "2026-07-10 12:16:32"
  condition:
    hash.sha256(0, filesize) == "8c7f9ec84782eac067ec0c97a307ad21b6283c2800c02293d2cc4bc789df95e0"
}

rule MalwareBazaar_unknown_076_ad6b7658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad6b7658635192bbbb428c0b8b78db842c7d4f3501a4998cd69def8a1fa84b20"
    family = "unknown"
    file_name = "ការផ្លាស់ប្តូរថ្មីចំពោះលេខកូដ QR របស់ ABA.rar"
    file_type = "rar"
    first_seen = "2026-07-10 12:15:44"
  condition:
    hash.sha256(0, filesize) == "ad6b7658635192bbbb428c0b8b78db842c7d4f3501a4998cd69def8a1fa84b20"
}

rule MalwareBazaar_RemusStealer_077_ae887a73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae887a7346ca3547c459962ff760fda8b221c16d96fcde758422586fe7a886e3"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 12:11:36"
  condition:
    hash.sha256(0, filesize) == "ae887a7346ca3547c459962ff760fda8b221c16d96fcde758422586fe7a886e3"
}

rule MalwareBazaar_unknown_078_c14b1373
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c14b1373052bbc14adf5e2ac8f24b5cd97bc4794a18128a33e344db0b4e825f8"
    family = "unknown"
    file_name = "Cty TNHH Truong Minh.zip"
    file_type = "zip"
    first_seen = "2026-07-10 12:08:57"
  condition:
    hash.sha256(0, filesize) == "c14b1373052bbc14adf5e2ac8f24b5cd97bc4794a18128a33e344db0b4e825f8"
}

rule MalwareBazaar_unknown_079_74fef06c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74fef06cff2bb57ccfa1916228ff751ffda777c37f03fc92c46139311020900d"
    family = "unknown"
    file_name = "wdatasvc.exe"
    file_type = "exe"
    first_seen = "2026-07-10 12:02:07"
  condition:
    hash.sha256(0, filesize) == "74fef06cff2bb57ccfa1916228ff751ffda777c37f03fc92c46139311020900d"
}

rule MalwareBazaar_unknown_080_27ed20da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27ed20da0e17778ec924f06b0acaa955c288a1075c28106a3a3b5ac5292464e3"
    family = "unknown"
    file_name = "LG's Advertising Contract, Application Form and Products.zip"
    file_type = "zip"
    first_seen = "2026-07-10 11:54:47"
  condition:
    hash.sha256(0, filesize) == "27ed20da0e17778ec924f06b0acaa955c288a1075c28106a3a3b5ac5292464e3"
}

rule MalwareBazaar_unknown_081_062f32dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "062f32dddb6b1263f3f20cbc48c5b7f9e1e65521d72c01d87ef50bf4c21d3bfb"
    family = "unknown"
    file_name = "ssa_document.exe"
    file_type = "unknown"
    first_seen = "2026-07-10 11:49:52"
  condition:
    hash.sha256(0, filesize) == "062f32dddb6b1263f3f20cbc48c5b7f9e1e65521d72c01d87ef50bf4c21d3bfb"
}

rule MalwareBazaar_PureLogsStealer_082_bc238716
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc238716915c304156134fbea50602ff998524470d72bd71edd69d7c943c76a0"
    family = "PureLogsStealer"
    file_name = "IMG00300 Rechnung DE00320-003200.vbs"
    file_type = "vbs"
    first_seen = "2026-07-10 11:34:21"
  condition:
    hash.sha256(0, filesize) == "bc238716915c304156134fbea50602ff998524470d72bd71edd69d7c943c76a0"
}

rule MalwareBazaar_unknown_083_db6b320a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db6b320a2d734a81d7b5c5ffeb47d01629ebc4db7023c89ff19eeffbbaa2fbe4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 11:20:03"
  condition:
    hash.sha256(0, filesize) == "db6b320a2d734a81d7b5c5ffeb47d01629ebc4db7023c89ff19eeffbbaa2fbe4"
}

rule MalwareBazaar_unknown_084_00164d07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00164d07594203e5db9b29f9f5d731a5c177bda5b536fd83d50cf96fd0afd64c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 10:56:08"
  condition:
    hash.sha256(0, filesize) == "00164d07594203e5db9b29f9f5d731a5c177bda5b536fd83d50cf96fd0afd64c"
}

rule MalwareBazaar_Efimer_085_5a2f726a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a2f726ab9db35f6fe00d364f017e09cb0cbd7a13d98e2a9cdbb12cc7676ce51"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-10 10:52:01"
  condition:
    hash.sha256(0, filesize) == "5a2f726ab9db35f6fe00d364f017e09cb0cbd7a13d98e2a9cdbb12cc7676ce51"
}

rule MalwareBazaar_SalatStealer_086_c3742e80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3742e8050b8664520fc1a00b7c84c2aac7eac7cec6249b7be5468504ce22d7c"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 10:49:52"
  condition:
    hash.sha256(0, filesize) == "c3742e8050b8664520fc1a00b7c84c2aac7eac7cec6249b7be5468504ce22d7c"
}

rule MalwareBazaar_SalatStealer_087_38b184d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38b184d316cda0368a6dcead584e84fa7bdc53fd12b117860e16bee849f46963"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 10:48:37"
  condition:
    hash.sha256(0, filesize) == "38b184d316cda0368a6dcead584e84fa7bdc53fd12b117860e16bee849f46963"
}

rule MalwareBazaar_unknown_088_78ebdfb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78ebdfb4809d08896e072f3abb9948d1de9f6adc5f70a994b5d7d033f642abca"
    family = "unknown"
    file_name = "zinstll.86382tt009.msi"
    file_type = "msi"
    first_seen = "2026-07-10 10:43:51"
  condition:
    hash.sha256(0, filesize) == "78ebdfb4809d08896e072f3abb9948d1de9f6adc5f70a994b5d7d033f642abca"
}

rule MalwareBazaar_RemusStealer_089_485163c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "485163c279b9dced626742d7fbb6dc9deb989459ba4781aac1a733c9f9b67596"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-10 10:39:13"
  condition:
    hash.sha256(0, filesize) == "485163c279b9dced626742d7fbb6dc9deb989459ba4781aac1a733c9f9b67596"
}

rule MalwareBazaar_unknown_090_29f7aa78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29f7aa7843b05ad7daec3204cabef2baea00f2ceba88f48724452bf6c54edcd2"
    family = "unknown"
    file_name = "29f7aa7843b05ad7daec3204cabef2baea00f2ceba88f48724452bf6c54edcd2"
    file_type = "elf"
    first_seen = "2026-07-10 10:38:45"
  condition:
    hash.sha256(0, filesize) == "29f7aa7843b05ad7daec3204cabef2baea00f2ceba88f48724452bf6c54edcd2"
}

rule MalwareBazaar_unknown_091_5c8f6b54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c8f6b545303f7fb165ad781a113df34ed5008767888e129b4181cdada3977d1"
    family = "unknown"
    file_name = "Lumen.exe"
    file_type = "exe"
    first_seen = "2026-07-10 10:26:14"
  condition:
    hash.sha256(0, filesize) == "5c8f6b545303f7fb165ad781a113df34ed5008767888e129b4181cdada3977d1"
}

rule MalwareBazaar_unknown_092_6fb08191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fb08191292b05a4f8deee0561634954736f6ca0ab25b25f09bdbb12b1ba6560"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-07-10 10:22:09"
  condition:
    hash.sha256(0, filesize) == "6fb08191292b05a4f8deee0561634954736f6ca0ab25b25f09bdbb12b1ba6560"
}

rule MalwareBazaar_SilentNet_093_09b4fcab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09b4fcab98b3288dd1e7f586a1aa0edce9737bdbc32a889dc5a57dc4eb20546f"
    family = "SilentNet"
    file_name = "Prestige1.21-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-07-10 10:16:06"
  condition:
    hash.sha256(0, filesize) == "09b4fcab98b3288dd1e7f586a1aa0edce9737bdbc32a889dc5a57dc4eb20546f"
}

rule MalwareBazaar_OverlordRAT_094_f99db7a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f99db7a12ab80b11c3fdec7bf6688e3f6a8d028fe07de01d5fd8fc5d5ac8a577"
    family = "OverlordRAT"
    file_name = "VMAX_spoof_cracked.exe"
    file_type = "exe"
    first_seen = "2026-07-10 10:13:37"
  condition:
    hash.sha256(0, filesize) == "f99db7a12ab80b11c3fdec7bf6688e3f6a8d028fe07de01d5fd8fc5d5ac8a577"
}

rule MalwareBazaar_SilentNet_095_5867c518
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5867c518b37d23212e74e19ddfca7c78c1ffee07de17db413a75ded7d2d58b7c"
    family = "SilentNet"
    file_name = "Prestige injector.exe"
    file_type = "exe"
    first_seen = "2026-07-10 10:12:03"
  condition:
    hash.sha256(0, filesize) == "5867c518b37d23212e74e19ddfca7c78c1ffee07de17db413a75ded7d2d58b7c"
}

rule MalwareBazaar_SilentNet_096_d4d16e82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4d16e820f6ca79bf362d7bf90656c9a063658bfca57713658cd6253cc34e5d1"
    family = "SilentNet"
    file_name = "RUNFIRST.exe"
    file_type = "exe"
    first_seen = "2026-07-10 10:09:54"
  condition:
    hash.sha256(0, filesize) == "d4d16e820f6ca79bf362d7bf90656c9a063658bfca57713658cd6253cc34e5d1"
}

rule MalwareBazaar_unknown_097_482eaafc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "482eaafcd2e09b3c766c51546bbe1a2af495eb1c7bada6f87deec4d27ce8c837"
    family = "unknown"
    file_name = "1_11_4_1480_11.02.2026.rar"
    file_type = "rar"
    first_seen = "2026-07-10 10:08:29"
  condition:
    hash.sha256(0, filesize) == "482eaafcd2e09b3c766c51546bbe1a2af495eb1c7bada6f87deec4d27ce8c837"
}

rule MalwareBazaar_SilentNet_098_f843b481
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f843b48137d1137d96e9a9da1fb4b2fdcee3a502925009382ef118abd79fc7fa"
    family = "SilentNet"
    file_name = "Pulse_client-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-07-10 10:07:44"
  condition:
    hash.sha256(0, filesize) == "f843b48137d1137d96e9a9da1fb4b2fdcee3a502925009382ef118abd79fc7fa"
}

rule MalwareBazaar_SilentNet_099_3539dbf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3539dbf3d81846f8d7276dd66c63c210d6f50d622d1fad39ee371d1dab5760e2"
    family = "SilentNet"
    file_name = "wockyupdate2-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-07-10 10:07:43"
  condition:
    hash.sha256(0, filesize) == "3539dbf3d81846f8d7276dd66c63c210d6f50d622d1fad39ee371d1dab5760e2"
}

rule MalwareBazaar_SilentNet_100_f38c4ec5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f38c4ec565e4b4d2ef603e26ee5d226a43d3b8f4bcd84f77cb857f730ec13847"
    family = "SilentNet"
    file_name = "FastCrystals-1.21.1-fabric-1.5.3.jar"
    file_type = "jar"
    first_seen = "2026-07-10 10:07:36"
  condition:
    hash.sha256(0, filesize) == "f38c4ec565e4b4d2ef603e26ee5d226a43d3b8f4bcd84f77cb857f730ec13847"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

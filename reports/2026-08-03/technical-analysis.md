# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-03

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
| Unique family labels | 7 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 49 |
| Mirai | 44 |
| CoinMiner | 2 |
| RemusStealer | 2 |
| ConnectWise | 1 |
| NetSupport | 1 |
| AsyncRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 56 |
| exe | 16 |
| sh | 16 |
| xapk | 6 |
| zip | 2 |
| msi | 2 |
| bat | 1 |
| jar | 1 |

## Per-Sample Analysis

### Sample 1: `fecb8fedf9ff1495`

| Field | Value |
|---|---|
| SHA-256 | `fecb8fedf9ff14958a45077626ace3d82347ac5207c7c123aa4e19c355e28ebc` |
| Family label | `unknown` |
| File name | `File+Cleaner+Pro_1.0.8.xapk` |
| File type | `xapk` |
| First seen | `2026-08-03 03:58:09` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11b56316b8c79adec9701856c22f1497` |
| SHA-256 | `fecb8fedf9ff14958a45077626ace3d82347ac5207c7c123aa4e19c355e28ebc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_fecb8fed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fecb8fedf9ff14958a45077626ace3d82347ac5207c7c123aa4e19c355e28ebc"
    family = "unknown"
    file_name = "File+Cleaner+Pro_1.0.8.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:58:09"
  condition:
    hash.sha256(0, filesize) == "fecb8fedf9ff14958a45077626ace3d82347ac5207c7c123aa4e19c355e28ebc"
}
```

### Sample 2: `36e7192787f1d6b2`

| Field | Value |
|---|---|
| SHA-256 | `36e7192787f1d6b26b8f285ecfad5d719a37b9dc2882fbce735477a29867de9f` |
| Family label | `unknown` |
| File name | `com.mrdu.forkap.phoneclean_1.0.2.xapk` |
| File type | `xapk` |
| First seen | `2026-08-03 03:53:50` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1af860f02ca4bb660259dfa083f18437` |
| SHA-256 | `36e7192787f1d6b26b8f285ecfad5d719a37b9dc2882fbce735477a29867de9f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_36e71927
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36e7192787f1d6b26b8f285ecfad5d719a37b9dc2882fbce735477a29867de9f"
    family = "unknown"
    file_name = "com.mrdu.forkap.phoneclean_1.0.2.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:53:50"
  condition:
    hash.sha256(0, filesize) == "36e7192787f1d6b26b8f285ecfad5d719a37b9dc2882fbce735477a29867de9f"
}
```

### Sample 3: `8eb363f0bffd4300`

| Field | Value |
|---|---|
| SHA-256 | `8eb363f0bffd430059369aa2c40d2bba8492a0fa58c159fdf2cf93f4d8084e75` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-03 03:32:26` |
| Reporter | `Bitsight` |
| Tags | `424e51f31d68f573a4621aaede8044aa, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a81c38635fe029b2be1bf9285afd031` |
| SHA-1 | `89142aa9e2d4194ca55aa7ca160162d6954213e7` |
| SHA-256 | `8eb363f0bffd430059369aa2c40d2bba8492a0fa58c159fdf2cf93f4d8084e75` |
| SHA3-384 | `c04f4173caa63738629c9dc8519c38a796e7b17868182cb4f29986d20a247e65a2756d3852c1cd83f7a5780ef75064e5` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1413633D279C214B4D022D7F80696646DF4B6F77249703C6B39CC2A99DF9AE18423F392` |
| SSDEEP | `98304:DXJaIWTANn38mgLEkIjk6LwwtgI+mqthG+XyBqCso0LW1QHUt+u1r:DiTIn3UMjrL6n5thGyyBwXLWKer` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_003_8eb363f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8eb363f0bffd430059369aa2c40d2bba8492a0fa58c159fdf2cf93f4d8084e75"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-03 03:32:26"
  condition:
    hash.sha256(0, filesize) == "8eb363f0bffd430059369aa2c40d2bba8492a0fa58c159fdf2cf93f4d8084e75"
}
```

### Sample 4: `fc029c04afaa0cff`

| Field | Value |
|---|---|
| SHA-256 | `fc029c04afaa0cff7e8baab3a7c7688d00d6d1b9157390071ea3399f1c53b2a6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-03 03:32:07` |
| Reporter | `Bitsight` |
| Tags | `424e51f31d68f573a4621aaede8044aa, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fc570b518436ff8daf43a4a429c3470` |
| SHA-1 | `fd249494617a367b641da71a704b117629d4dcf8` |
| SHA-256 | `fc029c04afaa0cff7e8baab3a7c7688d00d6d1b9157390071ea3399f1c53b2a6` |
| SHA3-384 | `868c8300b191987c03ee27d005c1c5acfce9e0c78f89bd98d1017bc1f63a247ca05cba3dc6d905cc8e334f8332e24498` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T13DD5229939FA1EB0C43AD7F68F92E06EB05A7B9183709E9772CD68109E6315C1C353B1` |
| SSDEEP | `49152:EigDgFAnnlN3hyHuVis1tm729RItA4QwQgAtUHHLV37EqHpnoSuMRuZlceAJyOS2:WDnlphWuVPtm74RItbVQSxAqHpnbuGB2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_fc029c04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc029c04afaa0cff7e8baab3a7c7688d00d6d1b9157390071ea3399f1c53b2a6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-03 03:32:07"
  condition:
    hash.sha256(0, filesize) == "fc029c04afaa0cff7e8baab3a7c7688d00d6d1b9157390071ea3399f1c53b2a6"
}
```

### Sample 5: `ebfd170776d67428`

| Field | Value |
|---|---|
| SHA-256 | `ebfd170776d67428de1053ae6c92a6dee25614c8ec61f488b6f5228b58bbe003` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-03 03:32:00` |
| Reporter | `Bitsight` |
| Tags | `424e51f31d68f573a4621aaede8044aa, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fb5dc247a10522712c342871c58a143` |
| SHA-1 | `9f18b6a81334aab60c6168bed636897ee279b3b8` |
| SHA-256 | `ebfd170776d67428de1053ae6c92a6dee25614c8ec61f488b6f5228b58bbe003` |
| SHA3-384 | `d9414177ff2cfeb3e0f589ee21e0e0e8b4c294f5a812b0aee4be38b72bb86074d1b49f8ef2d1c15719a5c3110dd4cd0f` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T1F6D5228DFCB30E74E873C7E7859764BDB16E77448AA08D1A35892B102D12A397C36376` |
| SSDEEP | `49152:HsDadQo+Oss/hMxu93HPF/jOnLuual/BrbNRNX1mTl7XL/UyOF2DY6xa7LOvU9o5:Zd3iERFLOLuual/XoB7XYyO8Ss5bys4a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_ebfd1707
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebfd170776d67428de1053ae6c92a6dee25614c8ec61f488b6f5228b58bbe003"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-03 03:32:00"
  condition:
    hash.sha256(0, filesize) == "ebfd170776d67428de1053ae6c92a6dee25614c8ec61f488b6f5228b58bbe003"
}
```

### Sample 6: `9dd8f8f1de9603e0`

| Field | Value |
|---|---|
| SHA-256 | `9dd8f8f1de9603e04453600d0427345a01d2ab4229cf29d4527ef0cf95b4c75d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-03 03:31:50` |
| Reporter | `Bitsight` |
| Tags | `424e51f31d68f573a4621aaede8044aa, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d8205a57cf51a79767dfda015ccbe18` |
| SHA-1 | `08868d1d10ce21f6e09d0b8ba218bbcc12ae08da` |
| SHA-256 | `9dd8f8f1de9603e04453600d0427345a01d2ab4229cf29d4527ef0cf95b4c75d` |
| SHA3-384 | `57d6112d1ac9421f9849ff170b0cccae02492d23f7cbd2baedd6e2a1d63e7c5df45dfa15873fa5536dcfe48313bad5e1` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T1CDD523D77AF12AB1C863C7B58FD2F9BCB12A7B8587918C12B2CD2A006D53584257B731` |
| SSDEEP | `49152:qZ+FQfW/LgwyrgBTJMFxYwLYdwZxVtIVX7Kidq4dActJXFf/VmpbbqXY/YkLfPo:0kgBcBTEMdyrKVX7Kn4dAmXFf/VmB7T4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_9dd8f8f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dd8f8f1de9603e04453600d0427345a01d2ab4229cf29d4527ef0cf95b4c75d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-03 03:31:50"
  condition:
    hash.sha256(0, filesize) == "9dd8f8f1de9603e04453600d0427345a01d2ab4229cf29d4527ef0cf95b4c75d"
}
```

### Sample 7: `2428e3bc10482c8f`

| Field | Value |
|---|---|
| SHA-256 | `2428e3bc10482c8fcb0362b8d95dadeb0231b258e2606b7bd6adcc7e5664578d` |
| Family label | `unknown` |
| File name | `File+Cleaner+Master_1.0.6.xapk` |
| File type | `xapk` |
| First seen | `2026-08-03 03:29:28` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `320f5589d9891941101c48e7d31580bf` |
| SHA-1 | `91186e06fcc0ced484f2a4861bd8ebaf4ddf912d` |
| SHA-256 | `2428e3bc10482c8fcb0362b8d95dadeb0231b258e2606b7bd6adcc7e5664578d` |
| SHA3-384 | `3101c54ce09786d68745f3ac768e3a29311c593c29aa8c860b5c7d88c17e6824deb032d3bcc816f212aa60b6c3b4fa94` |
| TLSH | `T10EA6239AE70CE02FC477643689BE0330915754478E83BB93B914961C6EAB6C89F5EFC4` |
| SSDEEP | `196608:nSDhk+TyYZgHMTLOksv0veRgn295f/lZQZVMG:nSDytYLHOkshRgOf/4VMG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_2428e3bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2428e3bc10482c8fcb0362b8d95dadeb0231b258e2606b7bd6adcc7e5664578d"
    family = "unknown"
    file_name = "File+Cleaner+Master_1.0.6.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:29:28"
  condition:
    hash.sha256(0, filesize) == "2428e3bc10482c8fcb0362b8d95dadeb0231b258e2606b7bd6adcc7e5664578d"
}
```

### Sample 8: `d6eb48ecc1a0831a`

| Field | Value |
|---|---|
| SHA-256 | `d6eb48ecc1a0831a805c5920b2cf9655e60097eb6c7eb822bf87003d71afce95` |
| Family label | `unknown` |
| File name | `File+Cache+Cleaner_2.1.3.xapk` |
| File type | `xapk` |
| First seen | `2026-08-03 03:25:48` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d83b5b9d0200cd0e7b3f5581a1090244` |
| SHA-256 | `d6eb48ecc1a0831a805c5920b2cf9655e60097eb6c7eb822bf87003d71afce95` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_d6eb48ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6eb48ecc1a0831a805c5920b2cf9655e60097eb6c7eb822bf87003d71afce95"
    family = "unknown"
    file_name = "File+Cache+Cleaner_2.1.3.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:25:48"
  condition:
    hash.sha256(0, filesize) == "d6eb48ecc1a0831a805c5920b2cf9655e60097eb6c7eb822bf87003d71afce95"
}
```

### Sample 9: `1f14be1a82024cba`

| Field | Value |
|---|---|
| SHA-256 | `1f14be1a82024cbaf1e203547a8a0ffdd2598c407d4fca59b5d4f9b3379e7780` |
| Family label | `unknown` |
| File name | `com.techgiant.imagetopdf.converter_1.6.2.xapk` |
| File type | `xapk` |
| First seen | `2026-08-03 03:22:26` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `712615e029f0179c8703c93f07517bbb` |
| SHA-256 | `1f14be1a82024cbaf1e203547a8a0ffdd2598c407d4fca59b5d4f9b3379e7780` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_1f14be1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f14be1a82024cbaf1e203547a8a0ffdd2598c407d4fca59b5d4f9b3379e7780"
    family = "unknown"
    file_name = "com.techgiant.imagetopdf.converter_1.6.2.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:22:26"
  condition:
    hash.sha256(0, filesize) == "1f14be1a82024cbaf1e203547a8a0ffdd2598c407d4fca59b5d4f9b3379e7780"
}
```

### Sample 10: `36cefed9bdb1d3c2`

| Field | Value |
|---|---|
| SHA-256 | `36cefed9bdb1d3c2bdc91aca29ba6f8b06002019ef6432df922a106acf371177` |
| Family label | `unknown` |
| File name | `com.easytexting.messagingme.sms_1.46.xapk` |
| File type | `xapk` |
| First seen | `2026-08-03 03:19:35` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49eb701418e071e0d0363dac415162c4` |
| SHA-256 | `36cefed9bdb1d3c2bdc91aca29ba6f8b06002019ef6432df922a106acf371177` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_36cefed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36cefed9bdb1d3c2bdc91aca29ba6f8b06002019ef6432df922a106acf371177"
    family = "unknown"
    file_name = "com.easytexting.messagingme.sms_1.46.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:19:35"
  condition:
    hash.sha256(0, filesize) == "36cefed9bdb1d3c2bdc91aca29ba6f8b06002019ef6432df922a106acf371177"
}
```

### Sample 11: `eeafcefee69c0942`

| Field | Value |
|---|---|
| SHA-256 | `eeafcefee69c094284b3d652a0d96f30e37e7fe05da7e10a08bc536a744e8e61` |
| Family label | `Mirai` |
| File name | `eeafcefee69c094284b3d652a0d96f30e37e7fe05da7e10a08bc536a744e8e61` |
| File type | `elf` |
| First seen | `2026-08-03 03:18:10` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd61ef1eb6f48668ca9360adc3820ed6` |
| SHA-1 | `5cbe66ff9a9d01b226a3d756e0218f287b8b0c4e` |
| SHA-256 | `eeafcefee69c094284b3d652a0d96f30e37e7fe05da7e10a08bc536a744e8e61` |
| SHA3-384 | `d52bfc512a84981191176091514d2124c9affd93c9a776430cf31b97049d4ce0b9eac44b9baf340dd47b011815679fdd` |
| TLSH | `T152E3BEA7F7471091C9A302F407CB6BCD6E6322825F5B99E36D2F753B497A0DA4402BD2` |
| SSDEEP | `3072:wrEfRgCsyMXbJohs9gLeLuwO5rgW75qC:8Av0NQLUq75q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_eeafcefe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeafcefee69c094284b3d652a0d96f30e37e7fe05da7e10a08bc536a744e8e61"
    family = "Mirai"
    file_name = "eeafcefee69c094284b3d652a0d96f30e37e7fe05da7e10a08bc536a744e8e61"
    file_type = "elf"
    first_seen = "2026-08-03 03:18:10"
  condition:
    hash.sha256(0, filesize) == "eeafcefee69c094284b3d652a0d96f30e37e7fe05da7e10a08bc536a744e8e61"
}
```

### Sample 12: `9af478edec362f2f`

| Field | Value |
|---|---|
| SHA-256 | `9af478edec362f2ff147458b9581e94dacc7648f5b736975429dc0f2315b9a2d` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-03 03:11:53` |
| Reporter | `Bitsight` |
| Tags | `1TEST.file, B, dropped-by-GCleaner, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaa2d1a6e036ff38f7bc318687aedb4c` |
| SHA-1 | `3ce6bfda80c7aa24be952c48ae759cfee09dc054` |
| SHA-256 | `9af478edec362f2ff147458b9581e94dacc7648f5b736975429dc0f2315b9a2d` |
| SHA3-384 | `8707dbc500dc8507f36c1b439faa0963a20f5724420c82e816e7049bbdd8d6665685979bd2d459df1a5f4b197610cdf9` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B4B52A203BEE55D9F1377E32CBEBB555D66FB7722A068A4F0605034B0562A02CE93D39` |
| SSDEEP | `49152:0kUv1BL0xjJR/gz/QdRFYy3qW546O2TUY9zc6:YXoxjzpNVfN5` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_012_9af478ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9af478edec362f2ff147458b9581e94dacc7648f5b736975429dc0f2315b9a2d"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-03 03:11:53"
  condition:
    hash.sha256(0, filesize) == "9af478edec362f2ff147458b9581e94dacc7648f5b736975429dc0f2315b9a2d"
}
```

### Sample 13: `361fd82dba53c49c`

| Field | Value |
|---|---|
| SHA-256 | `361fd82dba53c49c5f1cdfc1b3ca658339726a60a1e921ad52d437c0e62a6f85` |
| Family label | `ConnectWise` |
| File name | `Adobe_Reader_uk_install.bat` |
| File type | `bat` |
| First seen | `2026-08-03 03:00:39` |
| Reporter | `nat` |
| Tags | `bat, ConnectWise` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1baad0bd794724693201b43a4202050` |
| SHA-1 | `e94f92514df496ab0a3be24261325124bc7372af` |
| SHA-256 | `361fd82dba53c49c5f1cdfc1b3ca658339726a60a1e921ad52d437c0e62a6f85` |
| SHA3-384 | `47f69d1f3b1deca09e61b7be0b9c81f63a1ab3db074c1762cba0be083d6e2e341a146fcebd021523f11e417b80216edf` |
| TLSH | `T19372FD3D22003AA617EE4A1A8E2F11812E76444F0315BDD571AE917FDB72F947BBE1C2` |
| SSDEEP | `384:BMWSSOYIJ1xmPjC+U+ps6VpftQG6OncDa:vstusxGVncDa` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_013_361fd82d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "361fd82dba53c49c5f1cdfc1b3ca658339726a60a1e921ad52d437c0e62a6f85"
    family = "ConnectWise"
    file_name = "Adobe_Reader_uk_install.bat"
    file_type = "bat"
    first_seen = "2026-08-03 03:00:39"
  condition:
    hash.sha256(0, filesize) == "361fd82dba53c49c5f1cdfc1b3ca658339726a60a1e921ad52d437c0e62a6f85"
}
```

### Sample 14: `d95e8aef883002d3`

| Field | Value |
|---|---|
| SHA-256 | `d95e8aef883002d34e9687c04b9dd1370e9c8c6b08ba2e1a7e1ecb9e07a3576b` |
| Family label | `unknown` |
| File name | `d95e8aef883002d34e9687c04b9dd1370e9c8c6b08ba2e1a7e1ecb9e07a3576b` |
| File type | `elf` |
| First seen | `2026-08-03 02:39:54` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf78bb7d5ee99c0251b82a9019535d58` |
| SHA-1 | `0632be1827f851ef385eea9da3aaf7d5ead47ff6` |
| SHA-256 | `d95e8aef883002d34e9687c04b9dd1370e9c8c6b08ba2e1a7e1ecb9e07a3576b` |
| SHA3-384 | `2793a7b305f29880094dc84bafaa7361aba8636302bf690cc58441286f0c7f4808c96532cbcc9f329cd1238563a4a120` |
| TLSH | `T1D3765B73905624D8E1ADC974D5151213BEA8384B673863DBBBC076F11BBABE49E78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQC:cqYUQuVDt0TZEF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_d95e8aef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d95e8aef883002d34e9687c04b9dd1370e9c8c6b08ba2e1a7e1ecb9e07a3576b"
    family = "unknown"
    file_name = "d95e8aef883002d34e9687c04b9dd1370e9c8c6b08ba2e1a7e1ecb9e07a3576b"
    file_type = "elf"
    first_seen = "2026-08-03 02:39:54"
  condition:
    hash.sha256(0, filesize) == "d95e8aef883002d34e9687c04b9dd1370e9c8c6b08ba2e1a7e1ecb9e07a3576b"
}
```

### Sample 15: `13d4561d9e33998b`

| Field | Value |
|---|---|
| SHA-256 | `13d4561d9e33998b2459ade45408ac962e468bd7b076d49d1313dd442f34e909` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-08-03 02:21:28` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f6c419988e7588c7abee23c8b3ab597` |
| SHA-1 | `176d22312713ee5001c99c4870cd83fed02d0d08` |
| SHA-256 | `13d4561d9e33998b2459ade45408ac962e468bd7b076d49d1313dd442f34e909` |
| SHA3-384 | `96c5846dd9d64d575f4bcc9ec3bf1bedb3100a0ce7bf482a32473b55bccc31a9f0972a8e397ff8c6ac838a93149ee562` |
| TLSH | `T17F016FD6D25095104019D95E6AE75290B421C3C7094A0BB87FDC983DEB98D15B027F95` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohauUFFN/EZt8E2MUSH7:e9Qp+MsuccZaE2MUA7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_13d4561d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13d4561d9e33998b2459ade45408ac962e468bd7b076d49d1313dd442f34e909"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-03 02:21:28"
  condition:
    hash.sha256(0, filesize) == "13d4561d9e33998b2459ade45408ac962e468bd7b076d49d1313dd442f34e909"
}
```

### Sample 16: `9cabe19e0f845ef0`

| Field | Value |
|---|---|
| SHA-256 | `9cabe19e0f845ef04507786eb7b6120eea5c04dd08dae799fcaf7b3a90c6d858` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-03 02:15:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bf6bcd5dda32a27f112357f6289cb19` |
| SHA-1 | `54720dc95149ba67b589dec224880cb2edc009de` |
| SHA-256 | `9cabe19e0f845ef04507786eb7b6120eea5c04dd08dae799fcaf7b3a90c6d858` |
| SHA3-384 | `fb57d51df085940a268b6936b1fa83bacad06c1d6088cd60e64dc095e4c5085774387f40fb67cf9d676485cd4bdc69c2` |
| TLSH | `T190C27D966A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:z8vCB+25j6es8Rk9FYpMSUpi+20qUpi+20YQX:z8l25JCd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_9cabe19e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cabe19e0f845ef04507786eb7b6120eea5c04dd08dae799fcaf7b3a90c6d858"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-03 02:15:11"
  condition:
    hash.sha256(0, filesize) == "9cabe19e0f845ef04507786eb7b6120eea5c04dd08dae799fcaf7b3a90c6d858"
}
```

### Sample 17: `f0acfe5618c3350d`

| Field | Value |
|---|---|
| SHA-256 | `f0acfe5618c3350d21e42a9784c8275e0be4745522a0ba1137ef52d1fd429388` |
| Family label | `unknown` |
| File name | `a.sh` |
| File type | `sh` |
| First seen | `2026-08-03 02:13:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6da0654c4e9943abbe500228107b5a5e` |
| SHA-1 | `344d002a326f1d30af09a6c374b62abf50eb362f` |
| SHA-256 | `f0acfe5618c3350d21e42a9784c8275e0be4745522a0ba1137ef52d1fd429388` |
| SHA3-384 | `efd4998fbedc3637fa850d7da4b57eea294bd27e5a6460d69a7c02b809cd0feeea3e1fdf63f92a7829fb1272bbc319f9` |
| TLSH | `T12111D0D6105559669A5B8A03F274DF3DA22B7FB47EBE3B0ACF849E13444444031E3DA1` |
| SSDEEP | `24:5XQ9QwtxnQw+pQEJQRQPoQIpQwXx9QwwpQwSxGQw9pQujQvQwEx+DQwiDFFdsxqH:eahTeJGlIe5heJUeVYB/vRms` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_f0acfe56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0acfe5618c3350d21e42a9784c8275e0be4745522a0ba1137ef52d1fd429388"
    family = "unknown"
    file_name = "a.sh"
    file_type = "sh"
    first_seen = "2026-08-03 02:13:07"
  condition:
    hash.sha256(0, filesize) == "f0acfe5618c3350d21e42a9784c8275e0be4745522a0ba1137ef52d1fd429388"
}
```

### Sample 18: `858dccc67180f5a9`

| Field | Value |
|---|---|
| SHA-256 | `858dccc67180f5a95a51e0f80e5adb603c0b9dce7d9a8999a964eeb884498e9f` |
| Family label | `unknown` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-08-03 02:09:28` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73d28313ee1738761e81e47ab77e780d` |
| SHA-1 | `20e68c410cff500cf758d3d376ad7c412ba43afa` |
| SHA-256 | `858dccc67180f5a95a51e0f80e5adb603c0b9dce7d9a8999a964eeb884498e9f` |
| SHA3-384 | `1cea4660d545415bd96d5ad1e786fb2e6036e5fd3455f5712f08622c98b04c7299fde3978a38468af1daa67da8b1f5e9` |
| TLSH | `T120E4AD03FA20DFADD515613128B38A5567FA15870BE71247C368DE31BBA036C892FBE5` |
| SSDEEP | `12288:b/czJzU6gWPOXZPa4v37jPceRqHuek23iOJ6:aeXXZF3VIEC6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_858dccc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "858dccc67180f5a95a51e0f80e5adb603c0b9dce7d9a8999a964eeb884498e9f"
    family = "unknown"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:28"
  condition:
    hash.sha256(0, filesize) == "858dccc67180f5a95a51e0f80e5adb603c0b9dce7d9a8999a964eeb884498e9f"
}
```

### Sample 19: `ca0c2a644f6c4053`

| Field | Value |
|---|---|
| SHA-256 | `ca0c2a644f6c40533811c879c7b0559cb7d01c4399eb2806d3bee0b2f4eaf350` |
| Family label | `unknown` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-08-03 02:09:27` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baa5c780254e69ed390ed4e1b5ce2867` |
| SHA-1 | `7a36c0c3268bf6a5ac8890db45ba8c98d9396a55` |
| SHA-256 | `ca0c2a644f6c40533811c879c7b0559cb7d01c4399eb2806d3bee0b2f4eaf350` |
| SHA3-384 | `41fea53e9c9a46e2fcd98657aae3486dc4a023c2af02be1fe38cb1f7faca87116b49b15d99af3a703f0323811f21231a` |
| TLSH | `T15EB4D029B58C2532E2C7F47FDE4E96B1E027B4FD93A5C0207912824EF2809A55F79F61` |
| SSDEEP | `12288:J7rwb9cvslT4sVPwxt75tgoFSd2ndOREh/8+9f:J7OuOTlst7Xg3Ynd4Eikf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_ca0c2a64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca0c2a644f6c40533811c879c7b0559cb7d01c4399eb2806d3bee0b2f4eaf350"
    family = "unknown"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:27"
  condition:
    hash.sha256(0, filesize) == "ca0c2a644f6c40533811c879c7b0559cb7d01c4399eb2806d3bee0b2f4eaf350"
}
```

### Sample 20: `d51b92caded0f974`

| Field | Value |
|---|---|
| SHA-256 | `d51b92caded0f974b04482d2db03cc38bb3137ef6955436681bfd9874d9701ee` |
| Family label | `unknown` |
| File name | `bot.armv6` |
| File type | `elf` |
| First seen | `2026-08-03 02:09:26` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca460eb36ee2fa23f4ea1ae2178d1a4b` |
| SHA-1 | `2cfb0fbac21312adad943df382719c8a61639cdc` |
| SHA-256 | `d51b92caded0f974b04482d2db03cc38bb3137ef6955436681bfd9874d9701ee` |
| SHA3-384 | `ba9b89e3d1753a9b3818759448a590545ecdaa379ba35b5c0068c630e611ae8ddb53615f49f7028737c99d9098ea5d10` |
| TLSH | `T16DA47C66FC519A52C4D0267AFA6E8188330353BCC3DE7106EE15CB3576EF89E0E39A51` |
| SSDEEP | `12288:4N8ULRxQbKJlsxHTLTWhf7UWaPnzfObWXz+:vOQ0SzLTWhAFL+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_d51b92ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51b92caded0f974b04482d2db03cc38bb3137ef6955436681bfd9874d9701ee"
    family = "unknown"
    file_name = "bot.armv6"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:26"
  condition:
    hash.sha256(0, filesize) == "d51b92caded0f974b04482d2db03cc38bb3137ef6955436681bfd9874d9701ee"
}
```

### Sample 21: `f705b64b8a8dcf8d`

| Field | Value |
|---|---|
| SHA-256 | `f705b64b8a8dcf8de34dd9c6f1ebcbb5aee140dd973ec70bf998d172ea7d6893` |
| Family label | `unknown` |
| File name | `bot.armv7-a` |
| File type | `elf` |
| First seen | `2026-08-03 02:09:25` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4999d5b25ce7f13028f35b1997f8078d` |
| SHA-1 | `3938a62b0b1b07f7571607ee748d642cf8df6d8a` |
| SHA-256 | `f705b64b8a8dcf8de34dd9c6f1ebcbb5aee140dd973ec70bf998d172ea7d6893` |
| SHA3-384 | `2c619ccc5d822ea644e01ee6b5a4365c5f8eb3319b994bf311673f7220e7e53ccbe3341fb7bb17673e4b39f17a4ec179` |
| TLSH | `T10AA48C6ABD419A52C4C426BAF96D918C730313BCC3DA710AEE05CB3576EF48E4D3AB45` |
| SSDEEP | `12288:c4ZS+vgMq1opmuADzQAZtMko+HfL2GUer33DL:V8+Wu60QW+HfLcer33f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_f705b64b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f705b64b8a8dcf8de34dd9c6f1ebcbb5aee140dd973ec70bf998d172ea7d6893"
    family = "unknown"
    file_name = "bot.armv7-a"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:25"
  condition:
    hash.sha256(0, filesize) == "f705b64b8a8dcf8de34dd9c6f1ebcbb5aee140dd973ec70bf998d172ea7d6893"
}
```

### Sample 22: `f87136be73f25c47`

| Field | Value |
|---|---|
| SHA-256 | `f87136be73f25c4716fcfbd96499b78ad81093f01484d6edc894a8ca26146bf1` |
| Family label | `unknown` |
| File name | `bot.armv5te` |
| File type | `elf` |
| First seen | `2026-08-03 02:09:23` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa8f58846f86c07b99c44eb7eb61d54b` |
| SHA-1 | `e2d70c9fa672681ea0deaf7fa1280b18fd79faaa` |
| SHA-256 | `f87136be73f25c4716fcfbd96499b78ad81093f01484d6edc894a8ca26146bf1` |
| SHA3-384 | `5ebbf6f32c06c51a86415981979910835e3b30785f3353a1044bc84fe493fe10f5b1e37ab909b0b8e9046e6f05c9bf28` |
| TLSH | `T1A4B47C6ABC419A52C4C4367AFA6E9198330313BCC3DE710AED15CB3576EF49E0D3AA51` |
| SSDEEP | `12288:aYMoxgnE+JHSdsRhaEb25V3luXEHAaRZAPtde2j:RqHSOhMFlPl4tdeo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_f87136be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f87136be73f25c4716fcfbd96499b78ad81093f01484d6edc894a8ca26146bf1"
    family = "unknown"
    file_name = "bot.armv5te"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:23"
  condition:
    hash.sha256(0, filesize) == "f87136be73f25c4716fcfbd96499b78ad81093f01484d6edc894a8ca26146bf1"
}
```

### Sample 23: `9bc92b9cc544a29b`

| Field | Value |
|---|---|
| SHA-256 | `9bc92b9cc544a29b7937678496e117902123af821188bad287ef809daaee8a09` |
| Family label | `unknown` |
| File name | `bot.powerpc` |
| File type | `elf` |
| First seen | `2026-08-03 02:09:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87480dca99aab4eee9552f96207d83eb` |
| SHA-1 | `4d96895965ccb6e1f5f395d3be8c50415224115f` |
| SHA-256 | `9bc92b9cc544a29b7937678496e117902123af821188bad287ef809daaee8a09` |
| SHA3-384 | `3a16e2c952f3eaa296de1cf416d57a0dea2a754208cea26c4f603f4777f9b6ee6e5cd91710b003db98742fe5b71aa470` |
| TLSH | `T140D4AE4177084E63C0E33D70353F1329E79E4D8B42A8A41D192FA71A5272E756B8EBDB` |
| SSDEEP | `12288:6QnA3nygyIuG5L1HwV+/N8DJdUgojK/24bIuhhhajMEJ:6QYTwBURx+thLa9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_9bc92b9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bc92b9cc544a29b7937678496e117902123af821188bad287ef809daaee8a09"
    family = "unknown"
    file_name = "bot.powerpc"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:22"
  condition:
    hash.sha256(0, filesize) == "9bc92b9cc544a29b7937678496e117902123af821188bad287ef809daaee8a09"
}
```

### Sample 24: `87eadab4c1b3397a`

| Field | Value |
|---|---|
| SHA-256 | `87eadab4c1b3397ac16fdf6807843c0a3da617ff4a2bfe97f015d9e104578859` |
| Family label | `unknown` |
| File name | `bot.x86` |
| File type | `elf` |
| First seen | `2026-08-03 02:09:21` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ceb5049e9053e91f09b6d5fc15c68fe` |
| SHA-1 | `c3cff1b684c332f1ee9d519fb9429f4bc2b94dae` |
| SHA-256 | `87eadab4c1b3397ac16fdf6807843c0a3da617ff4a2bfe97f015d9e104578859` |
| SHA3-384 | `62947891c6d7eb9ffa9d6c201b0e637881fb1c9402822a9f477e7cdcd90003dcce757d7902717a1e93d5716a4b5e356b` |
| TLSH | `T1FDC4CE06FA0181B9D4B3A4B2520FD37AC93067349123899BFF5D5D64A63E6C0AF2E357` |
| TELFHASH | `t180229af27fa94dedb390a848d31e6b52ee06d373491831b700f3699532f2a529e35835` |
| SSDEEP | `12288:9AwJBh86mlQPFFBmLv6hgKTD11Z/B6k2OA/s0Lx4oEKDcxvRU8tnQ+8TshKBS/6:2wjh8nlQVmrITL6kx8xeBRU8tQ+8gwBJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_87eadab4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87eadab4c1b3397ac16fdf6807843c0a3da617ff4a2bfe97f015d9e104578859"
    family = "unknown"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:21"
  condition:
    hash.sha256(0, filesize) == "87eadab4c1b3397ac16fdf6807843c0a3da617ff4a2bfe97f015d9e104578859"
}
```

### Sample 25: `cb29d2fd5f6bdeff`

| Field | Value |
|---|---|
| SHA-256 | `cb29d2fd5f6bdeffaa330573085ac178cba392e1037fb522a9734d82bf249eed` |
| Family label | `unknown` |
| File name | `bot.mipsel` |
| File type | `elf` |
| First seen | `2026-08-03 02:09:20` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f39601867c4fc02bcc1fa4aa7754331e` |
| SHA-1 | `a6522e629db025487b8a60f8e5262f0b94f9eac6` |
| SHA-256 | `cb29d2fd5f6bdeffaa330573085ac178cba392e1037fb522a9734d82bf249eed` |
| SHA3-384 | `69447ef830e137b41f536d30f19fc55e540d981702a4464e950215c02732ac421201de36aec9a291e042be4f38cbafa5` |
| TLSH | `T1ADE4B00ABF481FAFC05ECF70856EC727466C459686F32B24F62C8644BA592CA1F67D4C` |
| SSDEEP | `12288:h8PVZ7cUk3pw7lhAvzGz/6e8zoR5mYLjvfeI2eLj:4MpK6izOMmYLpLj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_cb29d2fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb29d2fd5f6bdeffaa330573085ac178cba392e1037fb522a9734d82bf249eed"
    family = "unknown"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:20"
  condition:
    hash.sha256(0, filesize) == "cb29d2fd5f6bdeffaa330573085ac178cba392e1037fb522a9734d82bf249eed"
}
```

### Sample 26: `2bd04baefb1f340e`

| Field | Value |
|---|---|
| SHA-256 | `2bd04baefb1f340e0c7d816c96db0078c4eb8b7cfce6689fbb187e5696bc7a3a` |
| Family label | `unknown` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-08-03 02:09:18` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `486c8fa64b8d20d789a32a363531c322` |
| SHA-1 | `8e187058c73ea0ff5c7c20a06f2ffc6c09da4051` |
| SHA-256 | `2bd04baefb1f340e0c7d816c96db0078c4eb8b7cfce6689fbb187e5696bc7a3a` |
| SHA3-384 | `01a0f4e0232717777b926f2914389717f17680d399a9dcb0ee6ef45a8caae49ba8c5f93277a5588cb76c9b8f89a8f7b2` |
| TLSH | `T1F8C4AE07FAB114E8D9AECC348A1A9133EA29BCD8421676777FD45B213F25A10EF0E751` |
| TELFHASH | `t13081b7348fac5461ebd70ce0a5f792656cba149ee3c469e18782aebc6df2dc01035d23` |
| SSDEEP | `12288:LYt8cChCRDDJPnKG4olirFdk+hVyT0QJ9D3ZjHUIhGW:KHRDHwhVI0c3ZjHToW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_2bd04bae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bd04baefb1f340e0c7d816c96db0078c4eb8b7cfce6689fbb187e5696bc7a3a"
    family = "unknown"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:18"
  condition:
    hash.sha256(0, filesize) == "2bd04baefb1f340e0c7d816c96db0078c4eb8b7cfce6689fbb187e5696bc7a3a"
}
```

### Sample 27: `76c488739cdb46ae`

| Field | Value |
|---|---|
| SHA-256 | `76c488739cdb46ae9bea8ab5d34fb49e7345fba3bcdb9cf3b24cc2e7cd7667f2` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-03 02:08:18` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6b4aa6734a025740b12b09f9a8bcee5` |
| SHA-1 | `d31af00c35a2640d9f9a0a748d2e29b966f50993` |
| SHA-256 | `76c488739cdb46ae9bea8ab5d34fb49e7345fba3bcdb9cf3b24cc2e7cd7667f2` |
| SHA3-384 | `5459eb0e3f88ac99d433f8c06052d73d8304d1e4639de7a7bf159dfa643dd50613ef5b6c5bed6e26ba57c56c24226701` |
| TLSH | `T11A236C651A957C149E98C4371D7E2F0CB9AD43E6320452EE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:QVEJVIhtMq9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:OEJ2M/cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_76c48873
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76c488739cdb46ae9bea8ab5d34fb49e7345fba3bcdb9cf3b24cc2e7cd7667f2"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-03 02:08:18"
  condition:
    hash.sha256(0, filesize) == "76c488739cdb46ae9bea8ab5d34fb49e7345fba3bcdb9cf3b24cc2e7cd7667f2"
}
```

### Sample 28: `9554d42935b9036d`

| Field | Value |
|---|---|
| SHA-256 | `9554d42935b9036d49d299e582e1488b3e55fe27f2745ae49955a06a06425584` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-03 02:02:12` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1e100e1a6cd2af5a91806983d3a8c92` |
| SHA-1 | `7779b1b483ab11a4bd1e33ebbae3371c1056532e` |
| SHA-256 | `9554d42935b9036d49d299e582e1488b3e55fe27f2745ae49955a06a06425584` |
| SHA3-384 | `17d765b0aac6823470614047538df170ffd9f09b3b1b26844564cdd2930b9274ea3726cf1da989b0b11065507517f243` |
| TLSH | `T1CD236C651A857C24AA98C4371D7E2F0CBDAD43E6320492EE7FCA3CF28C5A69DD10871D` |
| SSDEEP | `768:eXRWNGxV5k9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:alxJcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_9554d429
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9554d42935b9036d49d299e582e1488b3e55fe27f2745ae49955a06a06425584"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-03 02:02:12"
  condition:
    hash.sha256(0, filesize) == "9554d42935b9036d49d299e582e1488b3e55fe27f2745ae49955a06a06425584"
}
```

### Sample 29: `ac48d17645e060f4`

| Field | Value |
|---|---|
| SHA-256 | `ac48d17645e060f4ce0b9e22c43e7175ecc0c304fb2a4a3cc8a377a0548f2fed` |
| Family label | `unknown` |
| File name | `loader.sh` |
| File type | `sh` |
| First seen | `2026-08-03 02:02:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbfd16a655e1fb1ab26d45137339f09b` |
| SHA-1 | `a9e054e0ba6c6ed134d69c144714cb6f6ab448e3` |
| SHA-256 | `ac48d17645e060f4ce0b9e22c43e7175ecc0c304fb2a4a3cc8a377a0548f2fed` |
| SHA3-384 | `1776ff8b044a35ceb3f997c4c4bd11c669b9d8c42aa55ec0d626e313ca578a729cade4478e1847ef0e7a3da43fa00520` |
| TLSH | `T1BD31BCD9B090B132B489E7FCEF1EAF5875033AAD75648E0894F17C64E66D8047C8A5E0` |
| SSDEEP | `24:rjLhUWKqJMaXMMdSRmBLrZsCD6yqJpYX8vpvpIrlgPocoLH:rPfKqJMANdSRmBLNsCuyqJSXAVH4H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_ac48d176
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac48d17645e060f4ce0b9e22c43e7175ecc0c304fb2a4a3cc8a377a0548f2fed"
    family = "unknown"
    file_name = "loader.sh"
    file_type = "sh"
    first_seen = "2026-08-03 02:02:11"
  condition:
    hash.sha256(0, filesize) == "ac48d17645e060f4ce0b9e22c43e7175ecc0c304fb2a4a3cc8a377a0548f2fed"
}
```

### Sample 30: `565105c1ba3b1802`

| Field | Value |
|---|---|
| SHA-256 | `565105c1ba3b1802e13798bd17e3a167e6ff4eadc19179028fa9627ab5fe708d` |
| Family label | `unknown` |
| File name | `X-Force Essential Loader.exe` |
| File type | `exe` |
| First seen | `2026-08-03 01:48:34` |
| Reporter | `KnownSpotter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4f8754aa9dcf8d062f9fe73b2f25a01` |
| SHA-1 | `8c6c6a76359577941a6c0e412e06f8010dbb3b04` |
| SHA-256 | `565105c1ba3b1802e13798bd17e3a167e6ff4eadc19179028fa9627ab5fe708d` |
| SHA3-384 | `f5f82fd359a5524dae02916a8cdd73539731d275c92e4df3f9c623d82305350cd74c66d4d9ba71adc977e207401097b1` |
| IMPHASH | `1688a11aba03a74e45ff7fad63aea685` |
| TLSH | `T1BD2633AD34016A1EEA09E478D31D69E417234216CD083536CF6F93D764BF6CBAEB41A3` |
| SSDEEP | `98304:KGaQ/xNNMmXbWwW5+n8Bw8WUj9xZyLYsuFrLYjwIdgNu/c:DaaCmXxE+nVPoxRwdgI` |
| ICON-DHASH | `c813ccf2b0cc13c8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_565105c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "565105c1ba3b1802e13798bd17e3a167e6ff4eadc19179028fa9627ab5fe708d"
    family = "unknown"
    file_name = "X-Force Essential Loader.exe"
    file_type = "exe"
    first_seen = "2026-08-03 01:48:34"
  condition:
    hash.sha256(0, filesize) == "565105c1ba3b1802e13798bd17e3a167e6ff4eadc19179028fa9627ab5fe708d"
}
```

### Sample 31: `f32e6d2dcbab3176`

| Field | Value |
|---|---|
| SHA-256 | `f32e6d2dcbab31760194ac911b76dbb89561a32bb53d76a1b5c2b16c5f5f3548` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-08-03 01:35:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6b4ac3e034edef770dca6f3d5e7b338` |
| SHA-1 | `c23aa9096629e7c50f54116108a1fc241233a978` |
| SHA-256 | `f32e6d2dcbab31760194ac911b76dbb89561a32bb53d76a1b5c2b16c5f5f3548` |
| SHA3-384 | `a135a8097fab1271628a07d1011dce5bbdc561a2d019bb31cd8addda5fdc0566125baa80df9d0ce7239c547cc4a621ae` |
| TLSH | `T1B3C34B0273180F4BC4A31AB11E3E37E587FBE5E021E4BB89251E8B564675EB76449FC8` |
| SSDEEP | `1536:qdanlx5A0NMvRnbZAVAmivlJNOY9y/+Fx+1mGlXyykjPHr4:qd0li6AVnjFcmDBHr4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_f32e6d2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f32e6d2dcbab31760194ac911b76dbb89561a32bb53d76a1b5c2b16c5f5f3548"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-03 01:35:33"
  condition:
    hash.sha256(0, filesize) == "f32e6d2dcbab31760194ac911b76dbb89561a32bb53d76a1b5c2b16c5f5f3548"
}
```

### Sample 32: `17e95878a491590b`

| Field | Value |
|---|---|
| SHA-256 | `17e95878a491590bfdc24a82270bc318e59fd426a850dc219c65b711e9425f25` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-08-03 01:35:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8f4be867a5f1202acacd8fb8e96c554` |
| SHA-1 | `63b895cd76c37f8d4be59ffed7e7cd6a37eb972d` |
| SHA-256 | `17e95878a491590bfdc24a82270bc318e59fd426a850dc219c65b711e9425f25` |
| SHA3-384 | `bf3a751aefba307d330861156d91b7012cd6351f019fe25863950a449b58e5fd421b3aeeead9ae58944c82df8b48fb64` |
| TLSH | `T11D230237E038AD4FE25E0E187DE5F67A23F68B26939944ACB0C87F103747185A250CC6` |
| SSDEEP | `768:45vgNzjXZDtZ1NSLrVaw8SpIQ/NHvDx2xf8hQycQy73LC2VlRcq1NcegTkEkKGx/:45ItXZBZ6rV78vwx2xfFyc17CMlhTsYD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_17e95878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17e95878a491590bfdc24a82270bc318e59fd426a850dc219c65b711e9425f25"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-03 01:35:04"
  condition:
    hash.sha256(0, filesize) == "17e95878a491590bfdc24a82270bc318e59fd426a850dc219c65b711e9425f25"
}
```

### Sample 33: `443f9eafda59dc44`

| Field | Value |
|---|---|
| SHA-256 | `443f9eafda59dc44d6da1c0d0363e02d3cee019405c872676ba45e11c03b39e8` |
| Family label | `Mirai` |
| File name | `nz.sh4` |
| File type | `elf` |
| First seen | `2026-08-03 01:20:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4dce131015e855a98ab4a0a2adfd5ed5` |
| SHA-1 | `fde78486dcb9fb810b79cb667113906e69309f1f` |
| SHA-256 | `443f9eafda59dc44d6da1c0d0363e02d3cee019405c872676ba45e11c03b39e8` |
| SHA3-384 | `1a92bab364a5da294f3c963c832fed0d39fe9759a1833dce5c2b0d811e6df344e4bfe53518a55ed8ceb1e069e18d1278` |
| TLSH | `T18BB3AF32D41568E4C15E4578B9E4BE7D0BA3E08052A31EF71AFAC5B29457EE8F805BF0` |
| SSDEEP | `1536:4/KNSYcgiWv/jo/bICvRirenKXBz17Ykm0B9Crv1VV5oHV:4yNS7/E/EECwrZXDtm0B9mXzoHV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_443f9eaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "443f9eafda59dc44d6da1c0d0363e02d3cee019405c872676ba45e11c03b39e8"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-08-03 01:20:18"
  condition:
    hash.sha256(0, filesize) == "443f9eafda59dc44d6da1c0d0363e02d3cee019405c872676ba45e11c03b39e8"
}
```

### Sample 34: `7229420792cf2ed0`

| Field | Value |
|---|---|
| SHA-256 | `7229420792cf2ed0803b978655c0afc86e543f5343d73af490c097db9e021fbc` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-08-03 01:18:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fba46ccd1790d7462954eafe7bfad008` |
| SHA-1 | `b1b2a4c52f611bfb014dccfba764b889e9023ab7` |
| SHA-256 | `7229420792cf2ed0803b978655c0afc86e543f5343d73af490c097db9e021fbc` |
| SHA3-384 | `6eb9e9e6770ebaae19a0b870b1e09d3e5a68b2294044afd885f7a65a2a8a402627cda064636b3b56836dfcfc37cf0137` |
| TLSH | `T17DC32AC0F98B81F6C40B88305166F63FDF3199A85163DA9DEF999F72DA73981912234C` |
| TELFHASH | `t19331f4b5f9b21eec5bd19813c6cf5b41ec1deabb355021fd09fa165032b2141517ac3a` |
| SSDEEP | `3072:6ncCIGcJvNoHW8/ySBV/tI6QyK4BUlsWrhKHHT:UIGcJvyHh6SH/tf1K9wHHT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_72294207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7229420792cf2ed0803b978655c0afc86e543f5343d73af490c097db9e021fbc"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-08-03 01:18:26"
  condition:
    hash.sha256(0, filesize) == "7229420792cf2ed0803b978655c0afc86e543f5343d73af490c097db9e021fbc"
}
```

### Sample 35: `c7789b031f5c4ce0`

| Field | Value |
|---|---|
| SHA-256 | `c7789b031f5c4ce0889b07507bae51be96b442512e31d72a45ebe22464308926` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-08-03 01:18:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c03022460eea9c321c91ab4dc7ed4425` |
| SHA-1 | `91187f29c7aad937c01a58c6299757e402ee3338` |
| SHA-256 | `c7789b031f5c4ce0889b07507bae51be96b442512e31d72a45ebe22464308926` |
| SHA3-384 | `57f3c7e7f720cdf4908e2b172c8923dcc5096260b2fcc82ab0fb1fa19347de5064a4fa1b3b41d386ed9cd360be44f79c` |
| TLSH | `T114230197E28353F1E2EE197748BF76986ED1C30C60500B958BE07B3D9D80F55B822689` |
| SSDEEP | `768:JkZve2hs6Cc3Y+KAgwbhx4eY1xXRnuToDN0Pc3FTmF1j7FFRIayDnbcuyD7UHQRW:+Vs3dLw4eYn8TA+F17nOaOnouy8HyW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_c7789b03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7789b031f5c4ce0889b07507bae51be96b442512e31d72a45ebe22464308926"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-08-03 01:18:10"
  condition:
    hash.sha256(0, filesize) == "c7789b031f5c4ce0889b07507bae51be96b442512e31d72a45ebe22464308926"
}
```

### Sample 36: `caac25321fb3b2ec`

| Field | Value |
|---|---|
| SHA-256 | `caac25321fb3b2ec530de8c37fd032b560885dc487f72f72a861ec9c20ae33f9` |
| Family label | `unknown` |
| File name | `Setup - USDT Flasher.exe` |
| File type | `exe` |
| First seen | `2026-08-03 01:11:10` |
| Reporter | `paradiseisnear` |
| Tags | `discord, exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3bf6b7ebded22e3403e71575bc97ec5` |
| SHA-1 | `ebaf8d039b4a685e055c1a17862d5d4699f94eef` |
| SHA-256 | `caac25321fb3b2ec530de8c37fd032b560885dc487f72f72a861ec9c20ae33f9` |
| SHA3-384 | `3133b97ebb2d6cc36db5e26d3dea3d195e86997bfb5096f85a30086b366c3235c77d752c7ec3421f7c816098176fb774` |
| IMPHASH | `1a5ad9ae5d9a2a6b6f1f886640a0523a` |
| TLSH | `T15C36C027B384643EC06B1A394827D314993BFA703A139D5B67F49D6C8F35940AE3A787` |
| SSDEEP | `98304:SmKmn0WMQ9mAHSvQF9QtdqBqJlQ0twTbUijeN0:SZW0IDCSQtdqcJqLbUdN0` |
| ICON-DHASH | `f8f89c969392ece4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_caac2532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caac25321fb3b2ec530de8c37fd032b560885dc487f72f72a861ec9c20ae33f9"
    family = "unknown"
    file_name = "Setup - USDT Flasher.exe"
    file_type = "exe"
    first_seen = "2026-08-03 01:11:10"
  condition:
    hash.sha256(0, filesize) == "caac25321fb3b2ec530de8c37fd032b560885dc487f72f72a861ec9c20ae33f9"
}
```

### Sample 37: `4d8329523495fd8f`

| Field | Value |
|---|---|
| SHA-256 | `4d8329523495fd8ff834bd5ec68964ca7eb896010abcebb4238dff3900d7f63b` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-08-03 01:02:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf077e4bba64c807686980efcad7b4b5` |
| SHA-1 | `45c49a97ab3971468aedd0dfa11359df98693173` |
| SHA-256 | `4d8329523495fd8ff834bd5ec68964ca7eb896010abcebb4238dff3900d7f63b` |
| SHA3-384 | `6e40d8d63dfd3297bcf4ca497e5c382ef2bbcc79947a5e27d56dd3135d5d1b5c7f5424429e5c4f7130240fba76321ea3` |
| TLSH | `T194B35AC5E247D0F9D91209302276FB375E76E1BB1329DA83D7F49A32AC12AC1D4167AC` |
| TELFHASH | `t18a31c5faf2770cedabe09803964f27719c0d697b74a022fd09f22816367714151b9d3a` |
| SSDEEP | `3072:ONyJqCDagG4/4NRWFR7+66Ul8zDs3SUBN1H0CFB3:ayJqCiq4NRGR7RzQw1H0CFB3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_4d832952
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d8329523495fd8ff834bd5ec68964ca7eb896010abcebb4238dff3900d7f63b"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-03 01:02:32"
  condition:
    hash.sha256(0, filesize) == "4d8329523495fd8ff834bd5ec68964ca7eb896010abcebb4238dff3900d7f63b"
}
```

### Sample 38: `30fb755b87d11dee`

| Field | Value |
|---|---|
| SHA-256 | `30fb755b87d11dee9fa92ff4adcefb4d15a36b3323f4b879e8d96fb2c3cdbbaf` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-08-03 01:02:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a68102afd6a1badcb38c020cead5d92b` |
| SHA-1 | `bd71f8e7990bf0e29afd786e223199dcb5d1a6b4` |
| SHA-256 | `30fb755b87d11dee9fa92ff4adcefb4d15a36b3323f4b879e8d96fb2c3cdbbaf` |
| SHA3-384 | `91b5ee7de7a1a6b6ea36ec5aced4024aa75dedb4c680b9728c16ffb9763b2c4e650d5a7ea87538ef305aa431f2591e9c` |
| TLSH | `T105C32945B8829622C6D723BAFA6E21CD336163E9D3DF31038E219F1137C659B0D67B91` |
| TELFHASH | `t17931ed37ef912aac97c98149519be01a1acc70dd2b6c18929f3c5b8f98029c1b43ed57` |
| SSDEEP | `1536:ny1E/bPRgWJs+T2K7zlLpC+k4bNp1SBWmY4nuyJRjP1bJS46mOlcQBPLv7H6t:nyq/Dls+n7e4qYb0P1bJmxn7H6t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_30fb755b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30fb755b87d11dee9fa92ff4adcefb4d15a36b3323f4b879e8d96fb2c3cdbbaf"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-08-03 01:02:30"
  condition:
    hash.sha256(0, filesize) == "30fb755b87d11dee9fa92ff4adcefb4d15a36b3323f4b879e8d96fb2c3cdbbaf"
}
```

### Sample 39: `56dae62fb116198d`

| Field | Value |
|---|---|
| SHA-256 | `56dae62fb116198deafa855c97074040505f57cff61fe012a096a50531ff4b34` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-08-03 01:01:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02b35dd0adb50524f54db3b8c39b9248` |
| SHA-1 | `8e862cacf128efe6b77b9a8782c8dec10e728dc8` |
| SHA-256 | `56dae62fb116198deafa855c97074040505f57cff61fe012a096a50531ff4b34` |
| SHA3-384 | `d6f434b3a9070c2a8a726a7c7761fee58006cc905f9a8904373dc0777cb9456c2352bb7b7787c7c0049827d6d7d6ee3b` |
| TLSH | `T138245D46EA814E23C0D71779B6AF114A333297E4D3DB730699286FB43B8679E0E63705` |
| TELFHASH | `t118311e72933052266a61d924ddec97b2162ec7071688fe33df36849c141a49ee53fc1f` |
| SSDEEP | `6144:CNCeEkM2ck+akkDDdYn4txaCGtLHueLavM/9Fs:CNCrkhck+akkDDdYn4DaHoNk/M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_56dae62f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56dae62fb116198deafa855c97074040505f57cff61fe012a096a50531ff4b34"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-08-03 01:01:35"
  condition:
    hash.sha256(0, filesize) == "56dae62fb116198deafa855c97074040505f57cff61fe012a096a50531ff4b34"
}
```

### Sample 40: `c3c4f28ac31b86c7`

| Field | Value |
|---|---|
| SHA-256 | `c3c4f28ac31b86c7b7212831712cbd11bdd58155e57e4e21200754c691992150` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-08-03 01:01:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1a1e488733ebde9fccf29a52fb0432a` |
| SHA-1 | `8a833af98a694fe50ef3babe045c239e179853b0` |
| SHA-256 | `c3c4f28ac31b86c7b7212831712cbd11bdd58155e57e4e21200754c691992150` |
| SHA3-384 | `ee204bef41ae6a6211f1856370fead8db5dc115bfac387928eecbce4a2006ce32a85eca6a8f17f5489f193bfecb461b6` |
| TLSH | `T12D230293E7EF6440C42921F9929BB6A48900D27DE54C0976ABC584BB55AFF339310BCF` |
| SSDEEP | `1536:1SFhK7ZwAfM32X+vM2tPVK5OJwf0oLQqSKNnouy8HyRq:1S4fMW+U2tNcOSzSK1outSq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_c3c4f28a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3c4f28ac31b86c7b7212831712cbd11bdd58155e57e4e21200754c691992150"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-03 01:01:18"
  condition:
    hash.sha256(0, filesize) == "c3c4f28ac31b86c7b7212831712cbd11bdd58155e57e4e21200754c691992150"
}
```

### Sample 41: `3799f7600cb8a8e0`

| Field | Value |
|---|---|
| SHA-256 | `3799f7600cb8a8e0582bacf44e373ab26f414f456ebeab4f0d6095a239647813` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-08-03 01:01:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d8ed4734b02eb26951c0cd5c37e3632` |
| SHA-1 | `30853410f30e04b26e7863c3c7cab2cd3934ab3e` |
| SHA-256 | `3799f7600cb8a8e0582bacf44e373ab26f414f456ebeab4f0d6095a239647813` |
| SHA3-384 | `2f2f5fe5488e5046bc3d585f54c223adb0552af16012172df56196b2d2e08d54cf7fe1f5651f10be2727133d8b930ccd` |
| TLSH | `T1BB23F19937434509E0FBDD73E688F184EB9646B0EABB25BE309C45ECD1C080378F95A6` |
| SSDEEP | `1536:ELqlspf2tTov/xftB9gQfIC506oO9CMzk:DlsN5pftj5fICf9CMQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_3799f760
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3799f7600cb8a8e0582bacf44e373ab26f414f456ebeab4f0d6095a239647813"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-08-03 01:01:16"
  condition:
    hash.sha256(0, filesize) == "3799f7600cb8a8e0582bacf44e373ab26f414f456ebeab4f0d6095a239647813"
}
```

### Sample 42: `1722375fa81d3e17`

| Field | Value |
|---|---|
| SHA-256 | `1722375fa81d3e17092350c51ee6d7068c556c1d137c6d47aa027a18f84f4817` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-08-03 00:59:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b9fe9dd8d2464d6c99ffa574bb162d0` |
| SHA-1 | `a29b808f1b0fdc46dd8c8f9a26e112a623a296e1` |
| SHA-256 | `1722375fa81d3e17092350c51ee6d7068c556c1d137c6d47aa027a18f84f4817` |
| SHA3-384 | `35da7e8353adcc32f146171a26a6439d48da7b53766981a0c03dd64df705d1ad0477c531267212bc4cd3db723e8c4896` |
| TLSH | `T154730296630B7475C53179B2BC378066220CFBFA66E247772A13C768CA11586C7760EB` |
| SSDEEP | `1536:T5dqNXmO6/QhEvlC5bPpsB7MJ69JVLjrAf4YfIcIA6:T5dqNM/QhCCtP2xMoRLj84p5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_1722375f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1722375fa81d3e17092350c51ee6d7068c556c1d137c6d47aa027a18f84f4817"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-08-03 00:59:33"
  condition:
    hash.sha256(0, filesize) == "1722375fa81d3e17092350c51ee6d7068c556c1d137c6d47aa027a18f84f4817"
}
```

### Sample 43: `379d88307d819bdc`

| Field | Value |
|---|---|
| SHA-256 | `379d88307d819bdc60fd02afef40a9ff593bfb637f463daa21e42248b24fda5d` |
| Family label | `Mirai` |
| File name | `nz.spc` |
| File type | `elf` |
| First seen | `2026-08-03 00:58:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c84cef5b1d460e635eb3f21190ce8134` |
| SHA-1 | `0ecb6b6e96c9f9de1819a8c32bfb2436f2f0c633` |
| SHA-256 | `379d88307d819bdc60fd02afef40a9ff593bfb637f463daa21e42248b24fda5d` |
| SHA3-384 | `4d65cbb78639722fc72383f88258d26ac85662f56bb647ea30aee35cab70f7d02ad8dd66dea39d935f45b6cbc2590297` |
| TLSH | `T19CC36C22B4391E27C4E0A47A12F75366F1F657C915A8C65E7E720E8FBF112D02A07BB4` |
| SSDEEP | `1536:dyjL/F9rOYI9P3PKRHTceSkPr1KEpXF5F2r+FFgJafJj2QAhwIiDlut4gPYm5kkY:UP3HI9azceJ1jchwISgiOYOkoNKX0sks` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_379d8830
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "379d88307d819bdc60fd02afef40a9ff593bfb637f463daa21e42248b24fda5d"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-08-03 00:58:30"
  condition:
    hash.sha256(0, filesize) == "379d88307d819bdc60fd02afef40a9ff593bfb637f463daa21e42248b24fda5d"
}
```

### Sample 44: `7dd3530e0ca2e0bb`

| Field | Value |
|---|---|
| SHA-256 | `7dd3530e0ca2e0bbe2852f09685019c2e38c70866213d937539ff2060d46e819` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-08-03 00:57:26` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81da3ae86d90a32028a6538ce1cb53b0` |
| SHA-1 | `d649e53bb2afc44404187477bc1b6c3b54a7541a` |
| SHA-256 | `7dd3530e0ca2e0bbe2852f09685019c2e38c70866213d937539ff2060d46e819` |
| SHA3-384 | `fb40dbb5e5c68399ce8be8d76729fc8c5a9a7921ab0651cc956234e1342fc911eb0d48f6f2550fc2cf7c0ea0718ccf17` |
| TLSH | `T15901AFC6E1109500409AD55D2AE75455F821C3C71A4B4BB9BFECAC3E9B98D14B036F95` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohau6FyQEZVSEpUSdX:e9Qp+Msuuy3ZVSEpUEX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_7dd3530e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dd3530e0ca2e0bbe2852f09685019c2e38c70866213d937539ff2060d46e819"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-03 00:57:26"
  condition:
    hash.sha256(0, filesize) == "7dd3530e0ca2e0bbe2852f09685019c2e38c70866213d937539ff2060d46e819"
}
```

### Sample 45: `07bbab1d1641808a`

| Field | Value |
|---|---|
| SHA-256 | `07bbab1d1641808a5c3cecea3710d4ae5c481decddc49675adb0f096610a529d` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-08-03 00:54:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80cf33ae18550313eaab6c7b921a47b8` |
| SHA-1 | `5e87b5906083607c099c89d4059e5673db0b3e1b` |
| SHA-256 | `07bbab1d1641808a5c3cecea3710d4ae5c481decddc49675adb0f096610a529d` |
| SHA3-384 | `f203236da9027ac9dda0a22f3fcf05e5f46cc044f473739c6b17cc94df816c1d3fade9496007da065fe0bb59cf37bc27` |
| TLSH | `T133D32A46F8824A22C5D722BEF92D218E332317B8E3DE32129E245F6137C659F0D77A55` |
| TELFHASH | `t198b012972b5906582298104881cf590594e01681130005b2806e0d031d03c43752c317` |
| SSDEEP | `3072:jcEmwP9WEHpwI24eGL4d7dafrDyxCKCqR/oHPc:jxmw9pwIxB4dxaHVKC8oHPc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_07bbab1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07bbab1d1641808a5c3cecea3710d4ae5c481decddc49675adb0f096610a529d"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-03 00:54:34"
  condition:
    hash.sha256(0, filesize) == "07bbab1d1641808a5c3cecea3710d4ae5c481decddc49675adb0f096610a529d"
}
```

### Sample 46: `2b873c8e53c32d19`

| Field | Value |
|---|---|
| SHA-256 | `2b873c8e53c32d1947f8b0edbaea7fbf208ab1e202ff1cb07adde58d84894140` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-08-03 00:54:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39bf981ac3ee5852950080fcf5a82ecb` |
| SHA-1 | `ca7507d60425cef9e617595140ef5c61966b24e3` |
| SHA-256 | `2b873c8e53c32d1947f8b0edbaea7fbf208ab1e202ff1cb07adde58d84894140` |
| SHA3-384 | `64ee72e5f5f94691eabdcb6637d658dce5d9d70c9ef4698c03542129f6a9c1de4044dc9a625ab084d50372fff36f0ecc` |
| TLSH | `T17A330279E061DAA39D60847F6FDF5484308735B8917EB4311939C4E89CE121AA7DEF0E` |
| SSDEEP | `1536:6NyNNXEw2PWNLqp2J1yML/w9mIYg1Pp5IMLO:6YXXApmjQmI11Pz5LO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_2b873c8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b873c8e53c32d1947f8b0edbaea7fbf208ab1e202ff1cb07adde58d84894140"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-03 00:54:17"
  condition:
    hash.sha256(0, filesize) == "2b873c8e53c32d1947f8b0edbaea7fbf208ab1e202ff1cb07adde58d84894140"
}
```

### Sample 47: `3be39d081294ea74`

| Field | Value |
|---|---|
| SHA-256 | `3be39d081294ea74566be909ab5eeb988ba85d16b1c137b3a4bfd7dc728d52a5` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-08-03 00:51:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68386c6a758146d50d31714c0cdf0b6a` |
| SHA-1 | `d665b281c6e7dbdaf7eaa3e1be808262a5bd8f1e` |
| SHA-256 | `3be39d081294ea74566be909ab5eeb988ba85d16b1c137b3a4bfd7dc728d52a5` |
| SHA3-384 | `edbe76af81c2ce75d86d1a27944fe39c6371e353b595bc80dcdc7b322bec54227c1415efce98219a59bcab6ee8482191` |
| TLSH | `T1AEB31907BDC08CFDC089C038477F753ED832F5ED0239B2AB67D4AE26295DEA11A19A55` |
| TELFHASH | `t1ca2147b03e937a5c20c7d39ab29ede6ae1f209241e91f1e58f0b6dd94a46fc80c01456` |
| SSDEEP | `3072:U30FlN2APZDK9V5TgkDewBayOPCv8R0PTIc2UZXYHkN+:FFlN2APZDK9fTgkCgaqrLIaXYHkN+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_3be39d08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3be39d081294ea74566be909ab5eeb988ba85d16b1c137b3a4bfd7dc728d52a5"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-08-03 00:51:26"
  condition:
    hash.sha256(0, filesize) == "3be39d081294ea74566be909ab5eeb988ba85d16b1c137b3a4bfd7dc728d52a5"
}
```

### Sample 48: `98cf52a25bbc4e42`

| Field | Value |
|---|---|
| SHA-256 | `98cf52a25bbc4e4287656eb28daaeb01bebfe6c7aa9a0af31f5f811b520cb783` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-08-03 00:51:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4da4afe016b5021d60867ec4051fcf1c` |
| SHA-1 | `041e4cb3f7dd340b2df14fac2bf9f54bddfa6edb` |
| SHA-256 | `98cf52a25bbc4e4287656eb28daaeb01bebfe6c7aa9a0af31f5f811b520cb783` |
| SHA3-384 | `cd9ac75148df35998164f6c0800a42d7a5d7d4046aa710dcbc8bae4e379acb440891e12ff3e55b71ce8287133a952993` |
| TLSH | `T13F23F19BD52BEA3CC06E80309C8692CCFFFAB6021267179B06EF235C55B9A413519B12` |
| SSDEEP | `768:VPpbug3hrv2WQOHSf4vBEtTCpM54PoS4vbadGzwlWekofkuUqrDonnCx0YO:++hrv2WQOHI8p2s7GMkekoMbqrknCxO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_98cf52a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98cf52a25bbc4e4287656eb28daaeb01bebfe6c7aa9a0af31f5f811b520cb783"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-08-03 00:51:10"
  condition:
    hash.sha256(0, filesize) == "98cf52a25bbc4e4287656eb28daaeb01bebfe6c7aa9a0af31f5f811b520cb783"
}
```

### Sample 49: `08a91019ff7ba6f7`

| Field | Value |
|---|---|
| SHA-256 | `08a91019ff7ba6f77de3b774dc201cca18edfd264f9a46e34f243f6d76e37077` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-03 00:49:06` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89ccf0e628a266b5764c9602279451a3` |
| SHA-1 | `59669e051d7915e5af98a69aca8716f4fcd95ec2` |
| SHA-256 | `08a91019ff7ba6f77de3b774dc201cca18edfd264f9a46e34f243f6d76e37077` |
| SHA3-384 | `456c8ab579d26ad5ef7f9b597a81eaf82d783e0698a3a0a8d5336b316af7a6637ffffabdd839aa20e566d33bb18ad9e8` |
| TLSH | `T13FC27D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:FQV8vCB+25j6es8R1X9FYpMSUpi+20qUpi+20YQX:W8l25J1xd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_08a91019
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08a91019ff7ba6f77de3b774dc201cca18edfd264f9a46e34f243f6d76e37077"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-03 00:49:06"
  condition:
    hash.sha256(0, filesize) == "08a91019ff7ba6f77de3b774dc201cca18edfd264f9a46e34f243f6d76e37077"
}
```

### Sample 50: `1d87d05a3772a774`

| Field | Value |
|---|---|
| SHA-256 | `1d87d05a3772a774667df44d1ebdec9a31eb460d8e6fb4ea4ed4ab9314dcaa78` |
| Family label | `Mirai` |
| File name | `nz.m68k` |
| File type | `elf` |
| First seen | `2026-08-03 00:48:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de7d971ad4d0c117e755fa2a7dfe8f17` |
| SHA-1 | `c1bf0e08626e4b6b17fe464e3228913370245e7f` |
| SHA-256 | `1d87d05a3772a774667df44d1ebdec9a31eb460d8e6fb4ea4ed4ab9314dcaa78` |
| SHA3-384 | `5793cf5a6cd264b250042f4b91e0242d144b1fc7b1e07a53bf4b14a73b1a763e4498a9638a23d9579baa216df4cecfce` |
| TLSH | `T16BC33BDAB401DD7DF94FD6BB48632D1AB921A35252831726239BFD93AC321E47C02F85` |
| SSDEEP | `3072:GQKrXvsHp3Zldglu0jIhdkPud51qOijI2lF1sh9:vKjvsJ3ZldglCmWdvqe2lF1sh9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_1d87d05a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d87d05a3772a774667df44d1ebdec9a31eb460d8e6fb4ea4ed4ab9314dcaa78"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-08-03 00:48:03"
  condition:
    hash.sha256(0, filesize) == "1d87d05a3772a774667df44d1ebdec9a31eb460d8e6fb4ea4ed4ab9314dcaa78"
}
```

### Sample 51: `33ede9583b474ce9`

| Field | Value |
|---|---|
| SHA-256 | `33ede9583b474ce942e4fe36f7336b9b09552209230b4576860342ed56bd0d76` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-08-03 00:46:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4768b5df89b877414e044e154dc79247` |
| SHA-1 | `d5eb05efff86af9eb62559cb98e48c7851257a08` |
| SHA-256 | `33ede9583b474ce942e4fe36f7336b9b09552209230b4576860342ed56bd0d76` |
| SHA3-384 | `f33fd836b3c4d93b4a062fc7501820202fda2f605ec05be9cd7994acc342b46981527f664be7ef6aa9821e92372a2d93` |
| TLSH | `T1BFF3F805BB610EF7E85FCC3706E9270128CDA51622A97F36B534D958F64B28B26E3D70` |
| SSDEEP | `3072:Wdrx+Fzsw8TONAdQLty5l6Gm7UxbiuyZ6RlLP4FQQm8DrfWH6:WJx+FzXUONAdQLtKlTm7UxbiuyZ6RlLm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_33ede958
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33ede9583b474ce942e4fe36f7336b9b09552209230b4576860342ed56bd0d76"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-03 00:46:21"
  condition:
    hash.sha256(0, filesize) == "33ede9583b474ce942e4fe36f7336b9b09552209230b4576860342ed56bd0d76"
}
```

### Sample 52: `b40a8ddcb9e9da71`

| Field | Value |
|---|---|
| SHA-256 | `b40a8ddcb9e9da71f24f4459cbc7fd9a9c807d172082c0cc4ea6238b7ea9b003` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-08-03 00:46:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `114493ebbcf497fb3089023224ae0665` |
| SHA-1 | `f05ad5b0c172d38f53a8aaa500ba92feba9c7d80` |
| SHA-256 | `b40a8ddcb9e9da71f24f4459cbc7fd9a9c807d172082c0cc4ea6238b7ea9b003` |
| SHA3-384 | `23934c34eaf965dddd28a5cf667d7f24ee120336c62154003141fd538457f15bc79e0b6774c90130fd21d1a3f6a7fcff` |
| TLSH | `T11F93F781BC824A2AC6E013B9A66E728E3361B3F5D2CF3117DD615B12378528F1D67F91` |
| TELFHASH | `t187e06140fe764b1844e75634ecdd07b49511211761664710cf54daf0883f118a31cd5e` |
| SSDEEP | `1536:TMqCAyYDftxiBqVu90Zn/mwLUhLqsKzltFaDfqk98oZIH:TMqCAti8X914uTQmH+IH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_b40a8ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b40a8ddcb9e9da71f24f4459cbc7fd9a9c807d172082c0cc4ea6238b7ea9b003"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-08-03 00:46:12"
  condition:
    hash.sha256(0, filesize) == "b40a8ddcb9e9da71f24f4459cbc7fd9a9c807d172082c0cc4ea6238b7ea9b003"
}
```

### Sample 53: `b46800eb4eb3fbc6`

| Field | Value |
|---|---|
| SHA-256 | `b46800eb4eb3fbc6decc75bad5ebb5b400e27200c50da23199bd1f6a07537820` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-08-03 00:45:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5927426cf05a4b5fd0410a55b6236936` |
| SHA-1 | `fc9113f3f04609cd5dbaf391d75585d3b5d9c91e` |
| SHA-256 | `b46800eb4eb3fbc6decc75bad5ebb5b400e27200c50da23199bd1f6a07537820` |
| SHA3-384 | `68ce54563fe175d0b475f4d1ce6065b80273f1e75d6932f45a22c1878518d28306e69965db72ba2c25a241bfc6b45938` |
| TLSH | `T1B333F18CBCE1794AE969027243CE0F514A602575719F878E670586CEF6DE32FE80A1F4` |
| SSDEEP | `768:A82KPy+WUJ1G4GcPXqa7itQ2Rn/arWaY3eRV014fw/J2B9YszEKSmskTAJOTWG:5LK+Neavqdpaqvev014f+JS/Fjzj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_b46800eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b46800eb4eb3fbc6decc75bad5ebb5b400e27200c50da23199bd1f6a07537820"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-03 00:45:31"
  condition:
    hash.sha256(0, filesize) == "b46800eb4eb3fbc6decc75bad5ebb5b400e27200c50da23199bd1f6a07537820"
}
```

### Sample 54: `1018201ac9e47403`

| Field | Value |
|---|---|
| SHA-256 | `1018201ac9e47403b240fdcbce9ab1fca8837694a92ffab02089eceef7541ede` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-08-03 00:45:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `844ea552dab68db838c2d682fec39274` |
| SHA-1 | `6a441f2146a49485764a7673dfd1e2fe835a6cd9` |
| SHA-256 | `1018201ac9e47403b240fdcbce9ab1fca8837694a92ffab02089eceef7541ede` |
| SHA3-384 | `4163f34c179314ce2e54aa301a2c805fc878993f0e6685ddd8fc2ec240046e9378d926efdd8c89665c42cba75bc0c0a7` |
| TLSH | `T1F2E3E80E7E218F7CF795823447B79F1A965833C637E1C585D1ACEA012E2068E645FFA8` |
| TELFHASH | `t1ce114c184d7813f097755d9d5adeff72e59170eb06225d378e00e8adaa6d9429e00c2c` |
| SSDEEP | `3072:0dK+SE7ktsNOT8wR41M7qlkoKrMh8XQPr6elpEqRzrnPcH+14tTI7V7mFM7mYIrz:0dK+SE7ktsNOT8wR41M7qlkoKrMh8XQ8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_1018201a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1018201ac9e47403b240fdcbce9ab1fca8837694a92ffab02089eceef7541ede"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-08-03 00:45:30"
  condition:
    hash.sha256(0, filesize) == "1018201ac9e47403b240fdcbce9ab1fca8837694a92ffab02089eceef7541ede"
}
```

### Sample 55: `7e149890b2a6443e`

| Field | Value |
|---|---|
| SHA-256 | `7e149890b2a6443eaf6d2569c824d5d578c7f6f1a55452e552a452c4f930d922` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-08-03 00:45:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `291d80a4aee0ef703af75ef933af467a` |
| SHA-1 | `d8bfaa78073e0dc39003b9870218c6a86c0d99c4` |
| SHA-256 | `7e149890b2a6443eaf6d2569c824d5d578c7f6f1a55452e552a452c4f930d922` |
| SHA3-384 | `636aa53f9a3715178b59d4c6bcdcd58a4c0b98dbd731f39198a1d038121d9f07844656800f2fc7d2b21b0a5ce6d883ee` |
| TLSH | `T18FE2F12002BA5E75D02089FD6779C7194B6F0BB4C7E63671692BC53CA94800DE6BD7A3` |
| SSDEEP | `768:5Z+aFyUpi8s74xEOo0gYqLQmF78H+jPGfW8s3Uoz3P:5ZVs73sgJLQAdaQzf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_7e149890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e149890b2a6443eaf6d2569c824d5d578c7f6f1a55452e552a452c4f930d922"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-08-03 00:45:30"
  condition:
    hash.sha256(0, filesize) == "7e149890b2a6443eaf6d2569c824d5d578c7f6f1a55452e552a452c4f930d922"
}
```

### Sample 56: `99e62f03ab120c32`

| Field | Value |
|---|---|
| SHA-256 | `99e62f03ab120c32193fa4170496e4fdcc80b4a952956874d7f3585c8a07dff7` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-08-03 00:44:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3baee05365e895a7ee708ea1b6b6f92` |
| SHA-1 | `175737b3bba2c847068bae995f085dbe3085419c` |
| SHA-256 | `99e62f03ab120c32193fa4170496e4fdcc80b4a952956874d7f3585c8a07dff7` |
| SHA3-384 | `15b5db34119d248ca99109c344495e6046d3e5df8706733fb0ea0c643caa98e519d988eace56bc812af751479631f0cf` |
| TLSH | `T16A33F15F670296BDCA1EA0F297404B1D3D020FA6E05BCE68A5656523DFF79F06843E88` |
| SSDEEP | `1536:cGT0Vj6MgC434blTxPzIC1dCGjwoNa5MlmVJue:c80VHb9blFPcMNdcVQe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_99e62f03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99e62f03ab120c32193fa4170496e4fdcc80b4a952956874d7f3585c8a07dff7"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-08-03 00:44:28"
  condition:
    hash.sha256(0, filesize) == "99e62f03ab120c32193fa4170496e4fdcc80b4a952956874d7f3585c8a07dff7"
}
```

### Sample 57: `655f3fa43344394e`

| Field | Value |
|---|---|
| SHA-256 | `655f3fa43344394e6c4e57a769486e619339f9951092499c250ec7445c1bc4d4` |
| Family label | `Mirai` |
| File name | `mkno` |
| File type | `elf` |
| First seen | `2026-08-03 00:30:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd4d9a4205a814bb954fc1307776a821` |
| SHA-1 | `8ccb5ece553691199a52fb662450d5cc7dec86db` |
| SHA-256 | `655f3fa43344394e6c4e57a769486e619339f9951092499c250ec7445c1bc4d4` |
| SHA3-384 | `421bb9e16d8ad7cdf6ee328ceeae2e340f559e76cd08969ad1b0f83ea598d67c1d10604adbc48086209ade3f778ed91c` |
| TLSH | `T1B783071ABE419F15D4D526BAFF1E534933132BBCE3EE7112EE146B25278A91F0F2A401` |
| TELFHASH | `t120f08b7002aa4edc6ae0c445d1ef972985b8b92e2710884b69e8be1a40f39c2762560b` |
| SSDEEP | `1536:UbnIR8TuYEHi0VAeq+2Gr6wRZAdV0771IcDsWBqiG0XKdlH7izOiwQTV:DR8j0i06UfAU71IcDsWBqidwCnwq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_655f3fa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "655f3fa43344394e6c4e57a769486e619339f9951092499c250ec7445c1bc4d4"
    family = "Mirai"
    file_name = "mkno"
    file_type = "elf"
    first_seen = "2026-08-03 00:30:21"
  condition:
    hash.sha256(0, filesize) == "655f3fa43344394e6c4e57a769486e619339f9951092499c250ec7445c1bc4d4"
}
```

### Sample 58: `42496537fd1dd885`

| Field | Value |
|---|---|
| SHA-256 | `42496537fd1dd885373c5a0b513e17965aee0302816527907a7c9c0967029873` |
| Family label | `Mirai` |
| File name | `Qtj` |
| File type | `elf` |
| First seen | `2026-08-03 00:30:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ce987f55bf2af048348022a7c2a9a17` |
| SHA-1 | `e956f68a202f118c84233562d24984790a1bbbf2` |
| SHA-256 | `42496537fd1dd885373c5a0b513e17965aee0302816527907a7c9c0967029873` |
| SHA3-384 | `beadf891051873100ed5cc98dce5117063e9bc3c2dd6d85b446f8b5371ecbd4524fa35bb3b0d05ca8e2cdd31a55ac6bd` |
| TLSH | `T117632965BC819F1AC1D5167BFF1E838C332623A8E3DA7113DE1A6F6537CB51A0E2A141` |
| TELFHASH | `t18df08b7648a719dc2fe0c19946dfa287946d74713b404609a1e9af8780b3963f631809` |
| SSDEEP | `1536:VszjECNeiyj+LWdU+GtMh7Q/tvvsQsvbnRY6GZcGoFXEo3RBFq:VszjECciq+p/tMpQVvvsQcnZIFoFXEgR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_42496537
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42496537fd1dd885373c5a0b513e17965aee0302816527907a7c9c0967029873"
    family = "Mirai"
    file_name = "Qtj"
    file_type = "elf"
    first_seen = "2026-08-03 00:30:19"
  condition:
    hash.sha256(0, filesize) == "42496537fd1dd885373c5a0b513e17965aee0302816527907a7c9c0967029873"
}
```

### Sample 59: `62550c7ec27b0499`

| Field | Value |
|---|---|
| SHA-256 | `62550c7ec27b049999506513f37f06eb5e2e1bf3c8fd1d2487e15ef70cdb2949` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-08-03 00:16:41` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `760fe8bf8cc842ba63103ed461c199e0` |
| SHA-1 | `d5897c9f6682da07be7c6682307b30aab2c7cd48` |
| SHA-256 | `62550c7ec27b049999506513f37f06eb5e2e1bf3c8fd1d2487e15ef70cdb2949` |
| SHA3-384 | `ffb210386bac0d2c1f8aaa95133ce22d86d040de377a34efb25b53da7492da5c4f04cc3eadf198c743bae30d76ce2f4e` |
| TLSH | `T133D35C85FA87C0F6F80708725027B33EDA31D228403AD956DBA69F36DD17941BE1B399` |
| TELFHASH | `t189610af91e760ceca7c05801e24e6b21be6d677b3460767705b3156432aa90152bbc39` |
| SSDEEP | `1536:EuMmJNTqHggn7QQIahoTrynxW6KTQkoZOK7k+BZf5FfAU:EuMmXuHgu/Oz1noZOMvt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_62550c7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62550c7ec27b049999506513f37f06eb5e2e1bf3c8fd1d2487e15ef70cdb2949"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-03 00:16:41"
  condition:
    hash.sha256(0, filesize) == "62550c7ec27b049999506513f37f06eb5e2e1bf3c8fd1d2487e15ef70cdb2949"
}
```

### Sample 60: `312fbbedbe184110`

| Field | Value |
|---|---|
| SHA-256 | `312fbbedbe184110665f336846fff7a36d2c211b484e87fd7f57962267bbd66c` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-08-03 00:06:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e9cafeb7276fc942635606fc770ada1` |
| SHA-1 | `0974de6ef4f4536349ce31415975e6f63486625e` |
| SHA-256 | `312fbbedbe184110665f336846fff7a36d2c211b484e87fd7f57962267bbd66c` |
| SHA3-384 | `f7ea550b3797fdf5a32562711d3ce68f9193c653da1129d25e09a7c103cb4a473bff1d8396205dc7fa7f4954403acec7` |
| TLSH | `T110B33AC4E243D0F9EC160534213BFB379A73E5BF212DDA43D3A49AA26C96AC1D41679C` |
| TELFHASH | `t1e531d1fcb2770ce45bc0a902f68e8b21cd4d7b6f296072a345b66924322755253bfc39` |
| SSDEEP | `3072:/Wd7t7hm8ba3D2RI+DB2M5Jfebx/SHhA9:/Wd7tE8ba3q1B3GJSHhA9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_312fbbed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "312fbbedbe184110665f336846fff7a36d2c211b484e87fd7f57962267bbd66c"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-08-03 00:06:35"
  condition:
    hash.sha256(0, filesize) == "312fbbedbe184110665f336846fff7a36d2c211b484e87fd7f57962267bbd66c"
}
```

### Sample 61: `2c19cd42e8cbfd4f`

| Field | Value |
|---|---|
| SHA-256 | `2c19cd42e8cbfd4f3b6d72ba98f4d90540bc711af6d7ccb7d94202257397b9c9` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-08-03 00:06:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ded1882dcf2f4a3a68432ed9951a0273` |
| SHA-1 | `a64b50444ad1c911c5e84187e1a40fbd8554d9ea` |
| SHA-256 | `2c19cd42e8cbfd4f3b6d72ba98f4d90540bc711af6d7ccb7d94202257397b9c9` |
| SHA3-384 | `e4fba66e76535ec316a788663eb4a20d50b9401e97ee1cbaa30ec2bf67697c88078febe6f4436e5a258f5f594345a985` |
| TLSH | `T11A23F14BD0F127AC936F953F0D6B3A1907D0AD0FCA98DC22FFC420605856B5D1B69A57` |
| SSDEEP | `768:IDsFQuY4dWeVFNdXJHYkR4bCKwOBwPHWdOLWL8znTlIaS8IIicb2pndEhY5nbcua:ILuY4EevNZJ4k25+PWdinTlicb2Nj5nW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_2c19cd42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c19cd42e8cbfd4f3b6d72ba98f4d90540bc711af6d7ccb7d94202257397b9c9"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-08-03 00:06:17"
  condition:
    hash.sha256(0, filesize) == "2c19cd42e8cbfd4f3b6d72ba98f4d90540bc711af6d7ccb7d94202257397b9c9"
}
```

### Sample 62: `7e750d93404ccb98`

| Field | Value |
|---|---|
| SHA-256 | `7e750d93404ccb98bfab8ca03c5b64e09ac4933a404d6f4596ff9897ad3b43e3` |
| Family label | `NetSupport` |
| File name | `nets.zip` |
| File type | `zip` |
| First seen | `2026-08-03 00:04:59` |
| Reporter | `skocherhan` |
| Tags | `216-158-95-194, 45-227-254-179, 89-34-90-203, jpgomd-com, NetSupport, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce65b3efe7b1bdb095ab16ad58083901` |
| SHA-1 | `0f834a421edb4cdf3ff51c175664b3e5cf37a7ce` |
| SHA-256 | `7e750d93404ccb98bfab8ca03c5b64e09ac4933a404d6f4596ff9897ad3b43e3` |
| SHA3-384 | `2de4e2491364d891157fffd8b56b19426ca6b7def46ba63402f0b6bdccea0f7d2e98873996b3d11e9f4d49e56fc3c1b3` |
| TLSH | `T183B53378C801BBF1DA773735080B9B672E3A9F35AC248956D9243D9347FD67E680E428` |
| SSDEEP | `49152:Q7i8f2FbXks7Wq1V+rbmeu9vRoooGR7hgT37nupwcrUU:Qu8f2hkEWqsrbJ6DoGRlgT37SnP` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_062_7e750d93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e750d93404ccb98bfab8ca03c5b64e09ac4933a404d6f4596ff9897ad3b43e3"
    family = "NetSupport"
    file_name = "nets.zip"
    file_type = "zip"
    first_seen = "2026-08-03 00:04:59"
  condition:
    hash.sha256(0, filesize) == "7e750d93404ccb98bfab8ca03c5b64e09ac4933a404d6f4596ff9897ad3b43e3"
}
```

### Sample 63: `46e7c38344a335e4`

| Field | Value |
|---|---|
| SHA-256 | `46e7c38344a335e4c6100799372959a12fc17781bee2352ef2797633b657bbb0` |
| Family label | `unknown` |
| File name | `echovoice-beta-1.0.0-fabric.jar` |
| File type | `jar` |
| First seen | `2026-08-02 23:24:14` |
| Reporter | `stdptr` |
| Tags | `curseforge, discord, irahook, jar, minecraft, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc0b91d4a1ae518c93180b337b9b7a2f` |
| SHA-1 | `aae1ce877d8d26079ea8e19e21b55df9109cebc0` |
| SHA-256 | `46e7c38344a335e4c6100799372959a12fc17781bee2352ef2797633b657bbb0` |
| SHA3-384 | `9e44100e0a98cb1c94c428b73227281bf2f8849a9b8f6bc07468f6677ea634434afe6cbf484801b2a583620a21066c55` |
| TLSH | `T16305336B78F1DE34D543727C3943409ED57D259A3B8BDDF0AA3020D0BD844288E5B9AB` |
| SSDEEP | `24576:sZWt7uS39zcwAd7dR2cvBuUnppKtCSckQt/USj:xt7uggw49vEQKtwhUK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_46e7c383
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46e7c38344a335e4c6100799372959a12fc17781bee2352ef2797633b657bbb0"
    family = "unknown"
    file_name = "echovoice-beta-1.0.0-fabric.jar"
    file_type = "jar"
    first_seen = "2026-08-02 23:24:14"
  condition:
    hash.sha256(0, filesize) == "46e7c38344a335e4c6100799372959a12fc17781bee2352ef2797633b657bbb0"
}
```

### Sample 64: `ce7757d30cf3e83f`

| Field | Value |
|---|---|
| SHA-256 | `ce7757d30cf3e83fd573935d57860d45682e9dff2a1a4947857a58e49125960f` |
| Family label | `unknown` |
| File name | `hnap` |
| File type | `sh` |
| First seen | `2026-08-02 23:13:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9b8cc0c63d547582b45e2ab2cedb83d` |
| SHA-1 | `1442cf7b9df0a5e174abf5ce2f6e2911bfd20b1d` |
| SHA-256 | `ce7757d30cf3e83fd573935d57860d45682e9dff2a1a4947857a58e49125960f` |
| SHA3-384 | `cc1f4cba74c059c01969fc32c79ef87ae7a81bcfc43828f8e5f8d63e6c7c5c882c978f7565ac4b90a7c9cf4c3d9fe0d1` |
| TLSH | `T105F08BED949640323F0D5437711A4C652642082F24B95BDD224E9A635E0CFA8234EF33` |
| SSDEEP | `12:ZsU9jWijWr5jW2FFl7jN/OQrNaQQTERE5YXmY6uYCYEeyH:Zp9jWijWr5jW2Fr7jN/Vs9BYXmYRYCYQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_ce7757d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce7757d30cf3e83fd573935d57860d45682e9dff2a1a4947857a58e49125960f"
    family = "unknown"
    file_name = "hnap"
    file_type = "sh"
    first_seen = "2026-08-02 23:13:10"
  condition:
    hash.sha256(0, filesize) == "ce7757d30cf3e83fd573935d57860d45682e9dff2a1a4947857a58e49125960f"
}
```

### Sample 65: `b17643a10894128e`

| Field | Value |
|---|---|
| SHA-256 | `b17643a10894128e150cec8f619be1c1960bc99eb789eeb4b5f6fa370265e2c3` |
| Family label | `Mirai` |
| File name | `xd.mips64` |
| File type | `elf` |
| First seen | `2026-08-02 23:13:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b59805a7a15900d4ef15916841a3417` |
| SHA-1 | `d25eb3e68b9f205116656c408a70418dcb2ec9e5` |
| SHA-256 | `b17643a10894128e150cec8f619be1c1960bc99eb789eeb4b5f6fa370265e2c3` |
| SHA3-384 | `3155129cdf0e109100692b590679e237239e3828631a037d1946c3c1a34221987f3be3b28dcfcb5610af1c533a101a2f` |
| TLSH | `T159E46C6277228FA4F360D17105F38B659AA921630EF250C2937CC610BB51A7D6C6FFE9` |
| TELFHASH | `t14f417d18097813f0a6795c5d48deff36d6a330db7e1a2c238a51e86ea768b839d11d1c` |
| SSDEEP | `12288:U70Sy2742fuAM9Co3Y3yOseJQO+QhUG1tw8NGV8pG5kBSXi:Y742fuA213Y31seJQO+IUGI8Nqkz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_b17643a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b17643a10894128e150cec8f619be1c1960bc99eb789eeb4b5f6fa370265e2c3"
    family = "Mirai"
    file_name = "xd.mips64"
    file_type = "elf"
    first_seen = "2026-08-02 23:13:08"
  condition:
    hash.sha256(0, filesize) == "b17643a10894128e150cec8f619be1c1960bc99eb789eeb4b5f6fa370265e2c3"
}
```

### Sample 66: `2a490acd4bd1f94e`

| Field | Value |
|---|---|
| SHA-256 | `2a490acd4bd1f94e0f68377566a5e2ab1640af5b7ec8e4410813c25d56fc5d33` |
| Family label | `Mirai` |
| File name | `g.mpsl` |
| File type | `elf` |
| First seen | `2026-08-02 23:13:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5de80c1edd7f287b8fe18147d1763a9c` |
| SHA-1 | `a2e0019d6da746c3674cc27b68f5b7e82a045e7e` |
| SHA-256 | `2a490acd4bd1f94e0f68377566a5e2ab1640af5b7ec8e4410813c25d56fc5d33` |
| SHA3-384 | `e5a462f62edbd9d343511b48bb23c5adecd28713090e0172598dc236056f4bf36de5799cf182ef21c57da731b137cd37` |
| TLSH | `T112D46C06EF850FEBC4AFCD30852E831B19DD898702D1A678A1FC899CBB5D65A4FD3548` |
| SSDEEP | `12288:td0u7GoRrfb3h72lWh7hSYAy44BtThSZ/YzeazzHxQNkMeZkJ+I4yTNNSICVXur9:9QNk/zQNkICoi34xhV+Lc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_2a490acd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a490acd4bd1f94e0f68377566a5e2ab1640af5b7ec8e4410813c25d56fc5d33"
    family = "Mirai"
    file_name = "g.mpsl"
    file_type = "elf"
    first_seen = "2026-08-02 23:13:07"
  condition:
    hash.sha256(0, filesize) == "2a490acd4bd1f94e0f68377566a5e2ab1640af5b7ec8e4410813c25d56fc5d33"
}
```

### Sample 67: `97b72577f7b3cea0`

| Field | Value |
|---|---|
| SHA-256 | `97b72577f7b3cea01e2a992a345f56a197a859700a7a781a77204990f64f1c35` |
| Family label | `Mirai` |
| File name | `g.mips` |
| File type | `elf` |
| First seen | `2026-08-02 23:13:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `038aac342016e6d0a013e336e39c909c` |
| SHA-1 | `43faf054a368e95696fe7df5b72f519627f794b2` |
| SHA-256 | `97b72577f7b3cea01e2a992a345f56a197a859700a7a781a77204990f64f1c35` |
| SHA3-384 | `9cb16461c1348dcc03ef096b67d1c012433251aaad6d683b72f72b35d34b06404a810316581fe8d37967617eb57827c3` |
| TLSH | `T143D47C6377228FA4E361D67005F387259AA521B30FE254C293BCD2147E11A6D2D6FFE8` |
| TELFHASH | `t1e9417d0c097813e0a3756c5a59ddfb76e6a330db7e262c238e10e86aa76da834d11c1c` |
| SSDEEP | `12288:x15AD44DxuWmdndeG86N1ejG4PI/cmYTS/hB8pQu4BD2/:xg44DxuWmddel6N1wA/gTS/q4C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_97b72577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97b72577f7b3cea01e2a992a345f56a197a859700a7a781a77204990f64f1c35"
    family = "Mirai"
    file_name = "g.mips"
    file_type = "elf"
    first_seen = "2026-08-02 23:13:06"
  condition:
    hash.sha256(0, filesize) == "97b72577f7b3cea01e2a992a345f56a197a859700a7a781a77204990f64f1c35"
}
```

### Sample 68: `4f957ced7aeec095`

| Field | Value |
|---|---|
| SHA-256 | `4f957ced7aeec095681d6140d0c7246983626a308060b1a1df3b55fbd3478da5` |
| Family label | `Mirai` |
| File name | `xd.x86` |
| File type | `elf` |
| First seen | `2026-08-02 23:13:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73f28226204a2800076d944f77e21c06` |
| SHA-1 | `6d71e7ac9138763edf954c3bf65dee409f6e1e19` |
| SHA-256 | `4f957ced7aeec095681d6140d0c7246983626a308060b1a1df3b55fbd3478da5` |
| SHA3-384 | `8c22be286358e8c97f2a4d4c03fd8e43b649d239070f49bae608efa56f6ba9329389fa8d28bc64fbfb5435544d41478b` |
| TLSH | `T108058D8AFB93D0F2F5A341F9124FC7F60530A11A9013F6F2EB49977678717622E1A219` |
| TELFHASH | `t1fdf07d300f2136315752d95c58eda753242d5b4bd748ae73d635805d25180ffe62fc8e` |
| SSDEEP | `24576:zOqfGWkYLc9hVzh9uhVoXtKZJWPdgNG8kp97jZWOp:zOqfNk7DVzh9uhGCWPbX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_4f957ced
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f957ced7aeec095681d6140d0c7246983626a308060b1a1df3b55fbd3478da5"
    family = "Mirai"
    file_name = "xd.x86"
    file_type = "elf"
    first_seen = "2026-08-02 23:13:04"
  condition:
    hash.sha256(0, filesize) == "4f957ced7aeec095681d6140d0c7246983626a308060b1a1df3b55fbd3478da5"
}
```

### Sample 69: `f1e420fee19df82b`

| Field | Value |
|---|---|
| SHA-256 | `f1e420fee19df82b35d05e445eaeab7cb1e8998665794898e3c0049b7cfde7aa` |
| Family label | `unknown` |
| File name | `gpon` |
| File type | `sh` |
| First seen | `2026-08-02 23:13:03` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ccbf4dccac4bb7e5cd7b9c3b6513c75` |
| SHA-1 | `1578cfef86c5ad6eedd87f65ae598026c16acd7e` |
| SHA-256 | `f1e420fee19df82b35d05e445eaeab7cb1e8998665794898e3c0049b7cfde7aa` |
| SHA3-384 | `fd0b8ea612ece442a750c22ecd6763f99e0dfa7060d00145eb5fd7db9ff0c2f2b434d72ab91eb916cfc48be930c97bc8` |
| TLSH | `T16B019CCDDCD54170FA488A2A75BA6691E34D694F48C82E0DB01EDBA0DF4C961B21B737` |
| SSDEEP | `12:8e9LxyxA2XdG06P91KQ1KN51KUFFtTHXYX6QyTkyMxS:8e9FyK2Ul9TqDFDTHydyTIg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_f1e420fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1e420fee19df82b35d05e445eaeab7cb1e8998665794898e3c0049b7cfde7aa"
    family = "unknown"
    file_name = "gpon"
    file_type = "sh"
    first_seen = "2026-08-02 23:13:03"
  condition:
    hash.sha256(0, filesize) == "f1e420fee19df82b35d05e445eaeab7cb1e8998665794898e3c0049b7cfde7aa"
}
```

### Sample 70: `68f1d97aa77845a9`

| Field | Value |
|---|---|
| SHA-256 | `68f1d97aa77845a936ec0d51bdcf605d97e10e7866fb5438ee49793c286d352f` |
| Family label | `unknown` |
| File name | `realtek` |
| File type | `sh` |
| First seen | `2026-08-02 23:13:01` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52c186266d0cf6e2ef02d372739fe830` |
| SHA-1 | `4a6ad101422ed2379df58a7cb4ac96bd879cb15b` |
| SHA-256 | `68f1d97aa77845a936ec0d51bdcf605d97e10e7866fb5438ee49793c286d352f` |
| SHA3-384 | `0e05380fcdf1d5fd54fefde9129e487b78669f81907b8f3dc4ff1effda091449faad263a3f166a62b8abddbc85282325` |
| TLSH | `T11FF08BED949640323F0D543775194C562602086F24B95BDD224ED9639E0CFA8234EB33` |
| SSDEEP | `12:ZsU9jWijWr5jW2FFl7jN/OQrNaQiByTERE5YXmY6uYCYEeyH:Zp9jWijWr5jW2Fr7jN/VsrByBYXmYRYW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_68f1d97a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68f1d97aa77845a936ec0d51bdcf605d97e10e7866fb5438ee49793c286d352f"
    family = "unknown"
    file_name = "realtek"
    file_type = "sh"
    first_seen = "2026-08-02 23:13:01"
  condition:
    hash.sha256(0, filesize) == "68f1d97aa77845a936ec0d51bdcf605d97e10e7866fb5438ee49793c286d352f"
}
```

### Sample 71: `cae41900fd831579`

| Field | Value |
|---|---|
| SHA-256 | `cae41900fd831579de5bc9650a22a1123f28a1874106f56870b81f7682d9287e` |
| Family label | `unknown` |
| File name | `huawei` |
| File type | `sh` |
| First seen | `2026-08-02 23:13:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ee4cc3f90269c5b46d4121be30451d2` |
| SHA-1 | `1826208cf0ea6b30ec56b6102ab10f4e61728cac` |
| SHA-256 | `cae41900fd831579de5bc9650a22a1123f28a1874106f56870b81f7682d9287e` |
| SHA3-384 | `251a4e5f94f2e0278a69b22a788907ce1250e8b2fd3810c8687abd3a5ef5510fbbc54294d36f85770ca95f4e6a348518` |
| TLSH | `T119F08BED949640323F0D5437711A4C652602082F24B95BDD224E99635E0CFA8235EF33` |
| SSDEEP | `12:ZsU9jWijWr5jW2FFl7jN/OQrNaQCTERE5YXmY6uYCYEeyH:Zp9jWijWr5jW2Fr7jN/VszBYXmYRYCYQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_cae41900
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae41900fd831579de5bc9650a22a1123f28a1874106f56870b81f7682d9287e"
    family = "unknown"
    file_name = "huawei"
    file_type = "sh"
    first_seen = "2026-08-02 23:13:00"
  condition:
    hash.sha256(0, filesize) == "cae41900fd831579de5bc9650a22a1123f28a1874106f56870b81f7682d9287e"
}
```

### Sample 72: `0314e5776227f605`

| Field | Value |
|---|---|
| SHA-256 | `0314e5776227f605417d00977137f1b637ab8b4760ec3b1fb3030d1907854c39` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-02 23:04:49` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d1be377fc84754c93e74eb6eb7cd2f3` |
| SHA-1 | `f0d03b9d05d2311d1137f20083e413222043405e` |
| SHA-256 | `0314e5776227f605417d00977137f1b637ab8b4760ec3b1fb3030d1907854c39` |
| SHA3-384 | `9664f83e9108a9d9ae66d939c3be59af5894ac6cee8c93ffdf6b4068a1d4b437528fc7c4790411c4f84159647fec1a9e` |
| IMPHASH | `013c74198fc6e42dcf33737d6c40c012` |
| TLSH | `T18385238313E08172D4B6537AD8F9425365B0BCA06F62D2CF32E1F6DD1A326D15AB6327` |
| SSDEEP | `49152:tphAst555bs57g+3bCeNvFkpzwaODPLH:tphAst5Pbs53Owipz/O` |
| ICON-DHASH | `00606161f9e96968` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_0314e577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0314e5776227f605417d00977137f1b637ab8b4760ec3b1fb3030d1907854c39"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 23:04:49"
  condition:
    hash.sha256(0, filesize) == "0314e5776227f605417d00977137f1b637ab8b4760ec3b1fb3030d1907854c39"
}
```

### Sample 73: `0bbee3979b0327b6`

| Field | Value |
|---|---|
| SHA-256 | `0bbee3979b0327b6c327c4522414a90d18164af3846ea6a8e62e5fee861f6d51` |
| Family label | `unknown` |
| File name | `0bbee3979b0327b6c327c4522414a90d18164af3846ea6a8e62e5fee861f6d51` |
| File type | `elf` |
| First seen | `2026-08-02 23:00:21` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3a3c44d80e98b8abaeaa40bf04441b2` |
| SHA-1 | `a6a3a0793241779fbc6e54974473256a63802ea5` |
| SHA-256 | `0bbee3979b0327b6c327c4522414a90d18164af3846ea6a8e62e5fee861f6d51` |
| SHA3-384 | `3739bafcb45f0553c2b7f58474e74aa32c0e919241cc917ab6258122fbbb8b826545a043b11cfe05b1b0292992d9eae6` |
| TLSH | `T19AD68C77914338E9E5A98CB4D11025426DAC388B5738A3C7BAC471F667BA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQz:cqYUQuVDt0TZEA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_0bbee397
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bbee3979b0327b6c327c4522414a90d18164af3846ea6a8e62e5fee861f6d51"
    family = "unknown"
    file_name = "0bbee3979b0327b6c327c4522414a90d18164af3846ea6a8e62e5fee861f6d51"
    file_type = "elf"
    first_seen = "2026-08-02 23:00:21"
  condition:
    hash.sha256(0, filesize) == "0bbee3979b0327b6c327c4522414a90d18164af3846ea6a8e62e5fee861f6d51"
}
```

### Sample 74: `6106d8452e2cbc42`

| Field | Value |
|---|---|
| SHA-256 | `6106d8452e2cbc4281303e007a37c427ce397d7725b4f90143307c18649c9445` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-02 22:53:01` |
| Reporter | `Bitsight` |
| Tags | `42d208560b5e968930dcedab3c2bf57b, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c395bd554be042ff13206a52bbef11b3` |
| SHA-1 | `fa47a0b31aa995823f088d0b2538a1b2248664c5` |
| SHA-256 | `6106d8452e2cbc4281303e007a37c427ce397d7725b4f90143307c18649c9445` |
| SHA3-384 | `ed70160cfeb1adae018b58d5e1ca0e57c622b845cdce3417181645276df1a41ab77a2f9b6ef16a5d463cd10d87d3ba4e` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1813633823CDBB8F4D097C7B98272647EB175B76A4A79BC4739C86A0C0EA3E50543D781` |
| SSDEEP | `98304:Oj+BaspIGj0cBs7Z7lkTi/i2A0hCdJjeXykCfg7A7oxafj3er:OaxR0cCNl4iSeUHY7A7d` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_074_6106d845
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6106d8452e2cbc4281303e007a37c427ce397d7725b4f90143307c18649c9445"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 22:53:01"
  condition:
    hash.sha256(0, filesize) == "6106d8452e2cbc4281303e007a37c427ce397d7725b4f90143307c18649c9445"
}
```

### Sample 75: `bdcffdf543d7de80`

| Field | Value |
|---|---|
| SHA-256 | `bdcffdf543d7de8063d07d54f90f30d837fc872ed2f09b000788c6559a9af568` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-02 22:52:41` |
| Reporter | `Bitsight` |
| Tags | `42d208560b5e968930dcedab3c2bf57b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8394961d8e735d603d9ebdc61a27700` |
| SHA-1 | `0ff2653c33ee0aaa511f5b457368f0938d782143` |
| SHA-256 | `bdcffdf543d7de8063d07d54f90f30d837fc872ed2f09b000788c6559a9af568` |
| SHA3-384 | `2ac8c5bf346187a057bb8d82417aed23e666a4cbe87164c609d3b4206fcbbe6fcee573e679e742bb641ed5d453ca4c2b` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1DED522D5B5BA2DB0C877CBBA4FC2F47DB168778087658E9B738C76008E526041C7A276` |
| SSDEEP | `49152:k3t6WH39O9wnibP2nuU89IK2Al77eVEQ+hAnrdrW8X0XjDllrh9lEGRaWc2Bo:kNX9BDh8qzQ7bh8dqDlxdB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_bdcffdf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdcffdf543d7de8063d07d54f90f30d837fc872ed2f09b000788c6559a9af568"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 22:52:41"
  condition:
    hash.sha256(0, filesize) == "bdcffdf543d7de8063d07d54f90f30d837fc872ed2f09b000788c6559a9af568"
}
```

### Sample 76: `46470c9a7ee88955`

| Field | Value |
|---|---|
| SHA-256 | `46470c9a7ee889553a1861cc782cf4b938d6712364a25c095ad5b50cf2f826f9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-02 22:52:34` |
| Reporter | `Bitsight` |
| Tags | `42d208560b5e968930dcedab3c2bf57b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7ce22213122e05bf441624ec748209f` |
| SHA-1 | `98959ed8341204208848014eb9ba686af40ae790` |
| SHA-256 | `46470c9a7ee889553a1861cc782cf4b938d6712364a25c095ad5b50cf2f826f9` |
| SHA3-384 | `b401f33e36a9c91239ec160f85dc7e8f27447a246015e8018a0ae250f7be44f212f537b845bc44fa6f1b9fbea8a460ed` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T1FAD5229DFCB21271E432C3B38683256DB12A774183B48C9776DD5B102E53909AC7E2BA` |
| SSDEEP | `49152:ZLUrhaiiXCjYucFrKuOdkAxcHW453qj86A8TRkzkr57xa4GOZhrNiBF/OFXN7wIu:ZLPyETrFOdkt/qjgW6kr57xa4hZZkX/G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_46470c9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46470c9a7ee889553a1861cc782cf4b938d6712364a25c095ad5b50cf2f826f9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 22:52:34"
  condition:
    hash.sha256(0, filesize) == "46470c9a7ee889553a1861cc782cf4b938d6712364a25c095ad5b50cf2f826f9"
}
```

### Sample 77: `2236e527e4aa90f1`

| Field | Value |
|---|---|
| SHA-256 | `2236e527e4aa90f170150cd4c8622054f478418befd1be1b3d9280c2bcd2ac87` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-02 22:52:25` |
| Reporter | `Bitsight` |
| Tags | `42d208560b5e968930dcedab3c2bf57b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df0e74d96afbbb98aa250d778bf3c9ef` |
| SHA-1 | `a1d0b4cda58d74f54a11d93faa06e3f4a95ec1c3` |
| SHA-256 | `2236e527e4aa90f170150cd4c8622054f478418befd1be1b3d9280c2bcd2ac87` |
| SHA3-384 | `c6fb8632ea623efeeab5a8454a18e5e772475bad6ee2ca74a207c4e4e2bfb1b7e2b6a60ce59251439e47c9c42b929e05` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T14AD5239A6CF65A70E47BCBB6CF93F86E742A3B84CA750C4F758C68005E511182C7A376` |
| SSDEEP | `49152:HleNBrMm/65H/Lt93UlZRD1OxyiQwcf+KP9Wj0c/huzlI19+x0GLtn++d3:FezpQLD3UlTYci8f9Wj0Ih6y+BZn+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_2236e527
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2236e527e4aa90f170150cd4c8622054f478418befd1be1b3d9280c2bcd2ac87"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 22:52:25"
  condition:
    hash.sha256(0, filesize) == "2236e527e4aa90f170150cd4c8622054f478418befd1be1b3d9280c2bcd2ac87"
}
```

### Sample 78: `ca98331f359b0aa1`

| Field | Value |
|---|---|
| SHA-256 | `ca98331f359b0aa194ec6afc7783923fa9395146a369bce5e14ebc9270d6e64d` |
| Family label | `unknown` |
| File name | `7b17z.exe` |
| File type | `exe` |
| First seen | `2026-08-02 22:47:13` |
| Reporter | `KnownSpotter` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `111da74df7de47e068b7d6acc5ccb3b9` |
| SHA-1 | `816eb49586ed7830e487b26485eb9ad16f3f2877` |
| SHA-256 | `ca98331f359b0aa194ec6afc7783923fa9395146a369bce5e14ebc9270d6e64d` |
| SHA3-384 | `191ffea0a831f3fb078c92d59bc5623209e5d940ba362728930fcb17172859420f41d6d6fbfb90e6ca0dbb4ccb9b15f0` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T135166B03BD9448F9C0E9A7368863621ABB71B8088B3173D72E51BE792F767D09E35744` |
| SSDEEP | `49152:ETboedodgS5eWe8d2mkEIu2HYfWwFni+m4lxpGZ:E7dX74sKFFps` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_ca98331f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca98331f359b0aa194ec6afc7783923fa9395146a369bce5e14ebc9270d6e64d"
    family = "unknown"
    file_name = "7b17z.exe"
    file_type = "exe"
    first_seen = "2026-08-02 22:47:13"
  condition:
    hash.sha256(0, filesize) == "ca98331f359b0aa194ec6afc7783923fa9395146a369bce5e14ebc9270d6e64d"
}
```

### Sample 79: `c285743be1d2f01e`

| Field | Value |
|---|---|
| SHA-256 | `c285743be1d2f01eb3d134750b71571797eb5d18affd0715ba2286da23580763` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-02 22:00:21` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cb7115ecc997d8730305579eae518eb` |
| SHA-1 | `8d4d1cebc2ef6cf6c8b2b3a335ce189864eb270d` |
| SHA-256 | `c285743be1d2f01eb3d134750b71571797eb5d18affd0715ba2286da23580763` |
| SHA3-384 | `350d36fec8a803ac990f29c055099405a29e63e50978a78e2e35baa614c3b64295eec86d33a68142fd12410af784da69` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T1CD824B0FB9424326D0E11070A276567BDA79A8B637C414DBF7E48AED0A6C6D1FC3215F` |
| SSDEEP | `384:Zl6I8vVaF6OeYUQQlmLu94gXfc4lmxav8U9cXl:ZlPvUQQt9v8a0U` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_c285743b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c285743be1d2f01eb3d134750b71571797eb5d18affd0715ba2286da23580763"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 22:00:21"
  condition:
    hash.sha256(0, filesize) == "c285743be1d2f01eb3d134750b71571797eb5d18affd0715ba2286da23580763"
}
```

### Sample 80: `1756d6f4348931af`

| Field | Value |
|---|---|
| SHA-256 | `1756d6f4348931af8d3029384ccee8d7281673a627ca753d7c3ea3e7881356d8` |
| Family label | `Mirai` |
| File name | `cekizsafu` |
| File type | `elf` |
| First seen | `2026-08-02 20:40:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4af09feda9882d137c97d6705bc718d0` |
| SHA-1 | `d275fde856caf6965a6103ab7bb626b4e08ddb16` |
| SHA-256 | `1756d6f4348931af8d3029384ccee8d7281673a627ca753d7c3ea3e7881356d8` |
| SHA3-384 | `8fe841626a91fdb3a5ddd29ef0a0c2779d055be58e11cf4ae87b8da5f19949d034a74cbcd1de65feb437aec7a99db9bf` |
| TLSH | `T12A337B82EE83E1F1F58341311056D7ABAB34ED350010DAABF7553E31FCB5A02869AB1E` |
| TELFHASH | `t1073133f07ea609f8f2d0684dc75f23931b29d6735a21b0f648e22dc136f2a648062d34` |
| SSDEEP | `1536:bcjItMqvZLDWtw9cp650lF8C1lgam4KcmZXVNE4IdoordB:bciMmDWtws6ylFd1Oam4oRXE4GBdB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_1756d6f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1756d6f4348931af8d3029384ccee8d7281673a627ca753d7c3ea3e7881356d8"
    family = "Mirai"
    file_name = "cekizsafu"
    file_type = "elf"
    first_seen = "2026-08-02 20:40:30"
  condition:
    hash.sha256(0, filesize) == "1756d6f4348931af8d3029384ccee8d7281673a627ca753d7c3ea3e7881356d8"
}
```

### Sample 81: `d3998ff200687491`

| Field | Value |
|---|---|
| SHA-256 | `d3998ff200687491baefd3038f06c9b891aabb3193be52fa14070c644c00b8e0` |
| Family label | `unknown` |
| File name | `Violence.msi` |
| File type | `msi` |
| First seen | `2026-08-02 20:34:24` |
| Reporter | `hexinglarps` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d821eb73ab51a02f5852c28af4b78c3a` |
| SHA-1 | `c1977685379884b09bbaf788da96bd19a962fef2` |
| SHA-256 | `d3998ff200687491baefd3038f06c9b891aabb3193be52fa14070c644c00b8e0` |
| SHA3-384 | `b5c56a43ee3b524847bdc99d7f41a01b9fdc656060ce22b90cefd0133b06d04fb1f132bb967ae72c02656704893e2131` |
| TLSH | `T1212733A66C262F83CA6566BB23531302AF310DB33B1147512D39E92D1CBD1FA5B4D39B` |
| SSDEEP | `393216:d26ctwbS3glvEv87upq4GCAKUduCu3et11G0YF0niA:dCwbps06JA7dBIeTiA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_d3998ff2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3998ff200687491baefd3038f06c9b891aabb3193be52fa14070c644c00b8e0"
    family = "unknown"
    file_name = "Violence.msi"
    file_type = "msi"
    first_seen = "2026-08-02 20:34:24"
  condition:
    hash.sha256(0, filesize) == "d3998ff200687491baefd3038f06c9b891aabb3193be52fa14070c644c00b8e0"
}
```

### Sample 82: `fe45008262803405`

| Field | Value |
|---|---|
| SHA-256 | `fe4500826280340597344445a1734897495008210740ea41f80f3b5dbc908184` |
| Family label | `Mirai` |
| File name | `xd.arm6` |
| File type | `elf` |
| First seen | `2026-08-02 20:16:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7950b0362b06908c1ee4c058bf1a95c0` |
| SHA-1 | `d53a17e201b2b80588439c3ad420cc1e5103a038` |
| SHA-256 | `fe4500826280340597344445a1734897495008210740ea41f80f3b5dbc908184` |
| SHA3-384 | `d3c5c5aa03d87015a1369f6764fea226e998db22e3c2d2e376b16a573418e813b56bcd632a83d50c74254bcb1e0389fd` |
| TLSH | `T1BFC44A55F880AF61C6C539B6F64D42AC73074BB9D3EB72069A144B343BDB86B0B3A705` |
| TELFHASH | `t156f0d41559c815f0c4d0d1544641262b55bd39d63b6639e39bfdb35e0f11d50b0c3c37` |
| SSDEEP | `12288:+W9tt/OIgS0XDjqo58WeiF3ZfZy8pLb/B:Fft/OTjqdg5n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_fe450082
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe4500826280340597344445a1734897495008210740ea41f80f3b5dbc908184"
    family = "Mirai"
    file_name = "xd.arm6"
    file_type = "elf"
    first_seen = "2026-08-02 20:16:30"
  condition:
    hash.sha256(0, filesize) == "fe4500826280340597344445a1734897495008210740ea41f80f3b5dbc908184"
}
```

### Sample 83: `db4c3aa640d2be4e`

| Field | Value |
|---|---|
| SHA-256 | `db4c3aa640d2be4ed97fbe502e2b27683a6ba3318524181bc4ab570bafe8c26d` |
| Family label | `unknown` |
| File name | `zapret-discord-youtube-1.10.0.zip` |
| File type | `zip` |
| First seen | `2026-08-02 20:12:52` |
| Reporter | `Alex_sev` |
| Tags | `bat, dropper, muldrop, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2554316da2f58f58842e658619a40a61` |
| SHA-1 | `f05369f1fce6a5a049036e66e27292c163ac15d0` |
| SHA-256 | `db4c3aa640d2be4ed97fbe502e2b27683a6ba3318524181bc4ab570bafe8c26d` |
| SHA3-384 | `3562cfe9695ebe8649fed0539283e6bdd4d29df222dfa2e1bf0b5d42db57f8b7d1096d980e5d3e8f43dbd353439c6b11` |
| TLSH | `T129E53379F4D81B4DE242DB332448C19096D2B81175E0ED4B97E8231E4F63CEB9B907BA` |
| SSDEEP | `49152:JnQ9qVFhBu5NAr5z0xvI9Q5tvz0qWcQeXdY7TZ4E1GW4aLksf/dsIvid4/T4Ur4D:Jn24hsHsqRZ7b0qm4dY/Z4C4E/id4LLI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_db4c3aa6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db4c3aa640d2be4ed97fbe502e2b27683a6ba3318524181bc4ab570bafe8c26d"
    family = "unknown"
    file_name = "zapret-discord-youtube-1.10.0.zip"
    file_type = "zip"
    first_seen = "2026-08-02 20:12:52"
  condition:
    hash.sha256(0, filesize) == "db4c3aa640d2be4ed97fbe502e2b27683a6ba3318524181bc4ab570bafe8c26d"
}
```

### Sample 84: `bb71186aa5e8ce28`

| Field | Value |
|---|---|
| SHA-256 | `bb71186aa5e8ce286c5e8698adf22aac802615856dbab846a88e740cb5ce4316` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-02 20:07:49` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX5.file, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a4457475ca594ab4a17b8158d7d63c7` |
| SHA-1 | `85df2e4cafb6310b7430f9b69ba1d40f8b255562` |
| SHA-256 | `bb71186aa5e8ce286c5e8698adf22aac802615856dbab846a88e740cb5ce4316` |
| SHA3-384 | `2d4432e38bad42f4ea4b7450ce0cd0a09ccaad60f468ac27a664cdf24fa56596bcf830f7cecbe1f0b6ae5b602f0b7704` |
| IMPHASH | `d9c0bfb4053066384ee7484b4c2917f9` |
| TLSH | `T1F106334703457C8AD8746BB1AC28CD2DE7C495634BBC46E5384FDD8A8BA2329C3DC764` |
| SSDEEP | `49152:pitrizwS/XN5k2W6LPjElRxSJUO8/gvAiMCtq45NQHkwndRKwtQyKgY4NP0W:pWrc7fc29LjSTg7uiNQldRzI4NP0W` |
| ICON-DHASH | `28d4d4f8d000c000` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_084_bb71186a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb71186aa5e8ce286c5e8698adf22aac802615856dbab846a88e740cb5ce4316"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 20:07:49"
  condition:
    hash.sha256(0, filesize) == "bb71186aa5e8ce286c5e8698adf22aac802615856dbab846a88e740cb5ce4316"
}
```

### Sample 85: `f73e07daa7a1016e`

| Field | Value |
|---|---|
| SHA-256 | `f73e07daa7a1016efd4ee10266960549d4e2f85d0bc840d4c6a0a632e19e6c05` |
| Family label | `Mirai` |
| File name | `xd.ppc` |
| File type | `elf` |
| First seen | `2026-08-02 19:56:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d26b9c07506277b333c59717889565a` |
| SHA-1 | `599261168e55439762d3525bafe293333e84b5ea` |
| SHA-256 | `f73e07daa7a1016efd4ee10266960549d4e2f85d0bc840d4c6a0a632e19e6c05` |
| SHA3-384 | `764a84339a4f888ddfb0906863331b1e8e720d3122399335e37569abc5410c3af52b7ce4926f0c6e02dba32cef4a0b8f` |
| TLSH | `T1BDF45A82FF1C0563C9570DF0293E43E5F3217A9240F98239371E5B572622E76AAC779A` |
| SSDEEP | `12288:ilnmKEVm7gNYIosWSjigaKpZcGuyIFhuI1EOvpepTTS/Q0f:mPEVm7gN2SRaKsFhhELS/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_f73e07da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f73e07daa7a1016efd4ee10266960549d4e2f85d0bc840d4c6a0a632e19e6c05"
    family = "Mirai"
    file_name = "xd.ppc"
    file_type = "elf"
    first_seen = "2026-08-02 19:56:34"
  condition:
    hash.sha256(0, filesize) == "f73e07daa7a1016efd4ee10266960549d4e2f85d0bc840d4c6a0a632e19e6c05"
}
```

### Sample 86: `1f9fa9f15dd3b67c`

| Field | Value |
|---|---|
| SHA-256 | `1f9fa9f15dd3b67c9af0a0af8377fd65ee6fe838ce55c5eb9fc26565449d9ae4` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-02 19:54:12` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5348d5b511198874aaf019dcbb8e6a8a` |
| SHA-1 | `79914831791a91c13b7989bd066ed5fe1b433d8f` |
| SHA-256 | `1f9fa9f15dd3b67c9af0a0af8377fd65ee6fe838ce55c5eb9fc26565449d9ae4` |
| SHA3-384 | `ed033b51e239d88313ca2f0450279ec4c7b31b9ea23bcda6dc7b6d6d3e8de2e55ff8c5f651dcd47c12c3b6c6bd9d0cbb` |
| TLSH | `T19BC27D956A967C44BEC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:78vCB+25j6es8R+9FYpMSUpi+20qUpi+20YQX:78l25JYd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_1f9fa9f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f9fa9f15dd3b67c9af0a0af8377fd65ee6fe838ce55c5eb9fc26565449d9ae4"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-02 19:54:12"
  condition:
    hash.sha256(0, filesize) == "1f9fa9f15dd3b67c9af0a0af8377fd65ee6fe838ce55c5eb9fc26565449d9ae4"
}
```

### Sample 87: `976286fb575cf6c6`

| Field | Value |
|---|---|
| SHA-256 | `976286fb575cf6c6dcfd50695cb538d3d764642ea36122209d11d104d0ca5182` |
| Family label | `unknown` |
| File name | `systemd` |
| File type | `elf` |
| First seen | `2026-08-02 19:50:14` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d643efa94609f81116f476e3186815b4` |
| SHA-1 | `6c7fcd72d3e5a6984a2b2d2cd52fa409e6c48b08` |
| SHA-256 | `976286fb575cf6c6dcfd50695cb538d3d764642ea36122209d11d104d0ca5182` |
| SHA3-384 | `89b884611ceda2ed23e8a26eebe0b8995864cb0b77b8bff80b36ea19fc9a1072285718562263bf948e3d4570c6cda06d` |
| TLSH | `T178D5012BF66154BCE96BC434438ED572EA39B4250225BA3B7BD496203F2AC718F1D712` |
| SSDEEP | `49152:sx+H3Pv2kvxObfy+qdlFm5NNUgn1A5JUMt6oE5/p7SEi3+/xQaSk25s3nvLO:pH/+kvAb0lUvmMy5qUVkf3xQa52+3z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_976286fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "976286fb575cf6c6dcfd50695cb538d3d764642ea36122209d11d104d0ca5182"
    family = "unknown"
    file_name = "systemd"
    file_type = "elf"
    first_seen = "2026-08-02 19:50:14"
  condition:
    hash.sha256(0, filesize) == "976286fb575cf6c6dcfd50695cb538d3d764642ea36122209d11d104d0ca5182"
}
```

### Sample 88: `e9fe35015e5ef9a7`

| Field | Value |
|---|---|
| SHA-256 | `e9fe35015e5ef9a7d7d0b07b5fee72f2bc55882175447bfe8a5bb7da2535101a` |
| Family label | `unknown` |
| File name | `sensi.sh` |
| File type | `sh` |
| First seen | `2026-08-02 19:50:13` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f43f81ef4c4cb8a5c210c25362f41eeb` |
| SHA-1 | `fc8f0d5af29e8434e98531e8e7dc0272ae2eaac1` |
| SHA-256 | `e9fe35015e5ef9a7d7d0b07b5fee72f2bc55882175447bfe8a5bb7da2535101a` |
| SHA3-384 | `685ccfb74137cd20cb6b24acf22b251a33b0935ca6c0597bae7efe882e5e09a1d2ba28b7d96c08418387ce2c95cff3a9` |
| TLSH | `T1AAF08BED949640323F0D543775194C552602082F24B95BDD224E99635E0CFA8235EB33` |
| SSDEEP | `12:ZsU9jWijWr5jW2FFl7jN/OQrNaQJTERE5YXmY6uYCYEeyH:Zp9jWijWr5jW2Fr7jN/VsuBYXmYRYCYQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_e9fe3501
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9fe35015e5ef9a7d7d0b07b5fee72f2bc55882175447bfe8a5bb7da2535101a"
    family = "unknown"
    file_name = "sensi.sh"
    file_type = "sh"
    first_seen = "2026-08-02 19:50:13"
  condition:
    hash.sha256(0, filesize) == "e9fe35015e5ef9a7d7d0b07b5fee72f2bc55882175447bfe8a5bb7da2535101a"
}
```

### Sample 89: `e731201a0924332f`

| Field | Value |
|---|---|
| SHA-256 | `e731201a0924332f0b694e1e17958b4c70f274b22ad0b80a8face370cc921549` |
| Family label | `Mirai` |
| File name | `xd.m68k` |
| File type | `elf` |
| First seen | `2026-08-02 19:44:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5788a702a9e4b556ccae32e772c939a` |
| SHA-1 | `4d782e5387592222f8f730b9cf53a1ec43d8180e` |
| SHA-256 | `e731201a0924332f0b694e1e17958b4c70f274b22ad0b80a8face370cc921549` |
| SHA3-384 | `6573760d5f9a285d218f129e2b47e08d0f0231a22bd85eeb4e395a6e3b9fd5a4d6d6c6316f0b18a51aeaa2618ba4eac8` |
| TLSH | `T10CB4C08663023D3FE0B3893A80EA4F17A735D784558327473169F9696923AF86F316C7` |
| SSDEEP | `12288:OshrdnYE1p2CluL+m6XAjR1JuMNB5VLhV+p:OcdYE+Flmi73Vy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_e731201a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e731201a0924332f0b694e1e17958b4c70f274b22ad0b80a8face370cc921549"
    family = "Mirai"
    file_name = "xd.m68k"
    file_type = "elf"
    first_seen = "2026-08-02 19:44:34"
  condition:
    hash.sha256(0, filesize) == "e731201a0924332f0b694e1e17958b4c70f274b22ad0b80a8face370cc921549"
}
```

### Sample 90: `f51484af77409f59`

| Field | Value |
|---|---|
| SHA-256 | `f51484af77409f59acb111f5a88417d7a8890591050aa51ddf0102fd1540aaf3` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-02 19:39:24` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `669e74c08eb9d7cbdbf135497f9f46f0` |
| SHA-1 | `5111da6cd9bc6346181a5238d75ba7b6ee884bf4` |
| SHA-256 | `f51484af77409f59acb111f5a88417d7a8890591050aa51ddf0102fd1540aaf3` |
| SHA3-384 | `5b1e3d7a9eb8d4b94686e1de4c1689a465a8d644d19512d51f9f7c232443fe036248a1bebdb62b4c6b398c7d1a203f21` |
| TLSH | `T1A5235C5516867C24AA99C8361C7E2F0CB9AD43E6324452EE7FCB3CF28C4A6ADD10971D` |
| SSDEEP | `768:BHl+H9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:BF+wcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_f51484af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f51484af77409f59acb111f5a88417d7a8890591050aa51ddf0102fd1540aaf3"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-02 19:39:24"
  condition:
    hash.sha256(0, filesize) == "f51484af77409f59acb111f5a88417d7a8890591050aa51ddf0102fd1540aaf3"
}
```

### Sample 91: `35e790ee32623b31`

| Field | Value |
|---|---|
| SHA-256 | `35e790ee32623b31fee32c012f415086c892d6f7f3d4d947dda20e90428d25ae` |
| Family label | `Mirai` |
| File name | `loader.sh` |
| File type | `sh` |
| First seen | `2026-08-02 19:38:12` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da59b268ef01d47538ed733794366be1` |
| SHA-1 | `e82ec8f0ff02391558e33363cf0fe30e52439f81` |
| SHA-256 | `35e790ee32623b31fee32c012f415086c892d6f7f3d4d947dda20e90428d25ae` |
| SHA3-384 | `178e583476c6b4b421c6ec351ce8fcb330370e03f3509d6ec08d494c16b956bdde1a69e01d708e890e5817e6b2863823` |
| TLSH | `T1DEC080F6413454739504C54F33DC819971544CF55DD6F43D58174C71840F55C70057A2` |
| SSDEEP | `3:6SDtFUSKjJUWu7cy+iQQ3ZN1Ltq286iC8u7cyY0GNIa0dog1VZHevDv:5DtSZJUr7x+lqZNZY96iCt7xY0axdJvz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_35e790ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35e790ee32623b31fee32c012f415086c892d6f7f3d4d947dda20e90428d25ae"
    family = "Mirai"
    file_name = "loader.sh"
    file_type = "sh"
    first_seen = "2026-08-02 19:38:12"
  condition:
    hash.sha256(0, filesize) == "35e790ee32623b31fee32c012f415086c892d6f7f3d4d947dda20e90428d25ae"
}
```

### Sample 92: `cc55866a9fef4473`

| Field | Value |
|---|---|
| SHA-256 | `cc55866a9fef44732dfd16da90241e024dc5ec416aff55f377b082c265e2bcc2` |
| Family label | `Mirai` |
| File name | `xd.arm7` |
| File type | `elf` |
| First seen | `2026-08-02 19:26:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1c1836c3a1b79919267dab2278e17f4` |
| SHA-1 | `a96ca1593464654bebf70e5c84ed6e147f83e898` |
| SHA-256 | `cc55866a9fef44732dfd16da90241e024dc5ec416aff55f377b082c265e2bcc2` |
| SHA3-384 | `2e95fbed6dddd180d75f6f9f0faf9795d0fb36cb14796415f1d7aa27ced1db6c5267a141af3118c97f7f2f6df7b69a30` |
| TLSH | `T1AD94E09AF7572E42C8C7857518C64146574DE59B33F393463B43AABB38293368F283C9` |
| SSDEEP | `12288:MeziCjLXECA/WfkxbwWe648XfH8pLB/3:9hW4kVwL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_cc55866a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc55866a9fef44732dfd16da90241e024dc5ec416aff55f377b082c265e2bcc2"
    family = "Mirai"
    file_name = "xd.arm7"
    file_type = "elf"
    first_seen = "2026-08-02 19:26:17"
  condition:
    hash.sha256(0, filesize) == "cc55866a9fef44732dfd16da90241e024dc5ec416aff55f377b082c265e2bcc2"
}
```

### Sample 93: `2093072334c5b854`

| Field | Value |
|---|---|
| SHA-256 | `2093072334c5b85464a0b733ea4f6abe35d074db34304e0d3b5d18132b09ba22` |
| Family label | `Mirai` |
| File name | `xd.mpsl` |
| File type | `elf` |
| First seen | `2026-08-02 19:07:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29851c443170c66e15d3daadba0140ea` |
| SHA-1 | `2ce8222a021420bb598fd9bfd47839f90a0fed23` |
| SHA-256 | `2093072334c5b85464a0b733ea4f6abe35d074db34304e0d3b5d18132b09ba22` |
| SHA3-384 | `0dcb627362ceb25040a2c171caf0f6ea4f7a565c8e0c9833f81f779622353de246d2c55ae028ef4127b8ad770f968fff` |
| TLSH | `T16BE45D06EF440FEBC8AFCD30856E425B14ED998712C1AB74A1FC499CB69D7994FE3488` |
| SSDEEP | `12288:5AWy6uJu23rf3jB/AB7uNRJic7mqNhZlJ88yC3pqo29LewwN1oatIwUwjcs/VQo0:58HhS5LeX1gScC+QHG6lghC/aVu4Q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_20930723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2093072334c5b85464a0b733ea4f6abe35d074db34304e0d3b5d18132b09ba22"
    family = "Mirai"
    file_name = "xd.mpsl"
    file_type = "elf"
    first_seen = "2026-08-02 19:07:28"
  condition:
    hash.sha256(0, filesize) == "2093072334c5b85464a0b733ea4f6abe35d074db34304e0d3b5d18132b09ba22"
}
```

### Sample 94: `8c19a8ace6a6cbeb`

| Field | Value |
|---|---|
| SHA-256 | `8c19a8ace6a6cbeb8d68c82a270659fb03160f263d15cd31db6e6317a148fee7` |
| Family label | `Mirai` |
| File name | `xd.arm5` |
| File type | `elf` |
| First seen | `2026-08-02 19:04:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa3866764ac0c9f005a6ccaae129949f` |
| SHA-1 | `c56c63ff80d54ac836458a83adbbdfcdd162126d` |
| SHA-256 | `8c19a8ace6a6cbeb8d68c82a270659fb03160f263d15cd31db6e6317a148fee7` |
| SHA3-384 | `1d66e6fe78512f30743373b0de0e243066b56985fa9262d573558820850c5ce9d7fb237ca3ab3d7465aadf1616e885cf` |
| TLSH | `T19F631981A8D1EE52C6D96A76FA1E059E332253BCD3DF3303CD144A1527CE4995A3AB0E` |
| TELFHASH | `t115e02610ecb88b2c98d799b0dc9c06a0a9012222504a4f10cf11daf0dc3f454e709d59` |
| SSDEEP | `1536:WwCFj8VbIZvTx5xD7/mHmv8YQi9VefxOUmtGX:XEe85x7/mHm0iXefsM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_8c19a8ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c19a8ace6a6cbeb8d68c82a270659fb03160f263d15cd31db6e6317a148fee7"
    family = "Mirai"
    file_name = "xd.arm5"
    file_type = "elf"
    first_seen = "2026-08-02 19:04:38"
  condition:
    hash.sha256(0, filesize) == "8c19a8ace6a6cbeb8d68c82a270659fb03160f263d15cd31db6e6317a148fee7"
}
```

### Sample 95: `d054f4822da5ea5e`

| Field | Value |
|---|---|
| SHA-256 | `d054f4822da5ea5e99edb57d809b9bacf86cfa3def04fa3711ddf88be7a68790` |
| Family label | `Mirai` |
| File name | `xd.spc` |
| File type | `elf` |
| First seen | `2026-08-02 18:56:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac539a9c34155edf95faf0d4c73d128b` |
| SHA-1 | `c0f546d400cee6435e7414737bc8be58edbf2376` |
| SHA-256 | `d054f4822da5ea5e99edb57d809b9bacf86cfa3def04fa3711ddf88be7a68790` |
| SHA3-384 | `2a75603b82195a1c5e756b3e968eb3a19d2a528880b571a7d65633afc00d232434334840577979f8d40b84d76c5fcb03` |
| TLSH | `T12F259D12B7F102A6D28087354662D7A0BA47A7A665E0430FDF608EDFEF562650EC4CF7` |
| SSDEEP | `12288:EnM7NKSw8SUyr2m6Av/H0A6YHQsRVs51g3d+:ygLwQm6kv0AJH1f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_d054f482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d054f4822da5ea5e99edb57d809b9bacf86cfa3def04fa3711ddf88be7a68790"
    family = "Mirai"
    file_name = "xd.spc"
    file_type = "elf"
    first_seen = "2026-08-02 18:56:13"
  condition:
    hash.sha256(0, filesize) == "d054f4822da5ea5e99edb57d809b9bacf86cfa3def04fa3711ddf88be7a68790"
}
```

### Sample 96: `9b272fcffe76786a`

| Field | Value |
|---|---|
| SHA-256 | `9b272fcffe76786a28735e9f4f1d17d8eefcac68ae15a8f8dea05e07ba9f8dca` |
| Family label | `Mirai` |
| File name | `Mddos.arm5` |
| File type | `elf` |
| First seen | `2026-08-02 18:49:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9a3568c14432836e0ec5094712c7a43` |
| SHA-1 | `b3060422f53d26e41f1baaf8453d17fde7863090` |
| SHA-256 | `9b272fcffe76786a28735e9f4f1d17d8eefcac68ae15a8f8dea05e07ba9f8dca` |
| SHA3-384 | `39ce41ca77737a4e01da4df963e1017ca9c08705220f78509f43a35ebd1d666bf13a77cb30b5d1ddd32894d4c7e0cf4a` |
| TLSH | `T1DC631982FCC1D902CAD4237ABA5E55DE331563D5E2DE3203AE122F51378AD5F0E6B192` |
| TELFHASH | `t17421beeb978c06ed43e5c30588d4a21c0ab838db2b1225976f1eab5f0022c927128d36` |
| SSDEEP | `768:wsQ7SmH4ISy1wirLextskYOIXqsrRyJo0zj4rISb0weHpU8ovowaWCBNnqmooOR5:ZO4ISyOYLe3IXnrRCzjmqW8oqwmgRaS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_9b272fcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b272fcffe76786a28735e9f4f1d17d8eefcac68ae15a8f8dea05e07ba9f8dca"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-02 18:49:22"
  condition:
    hash.sha256(0, filesize) == "9b272fcffe76786a28735e9f4f1d17d8eefcac68ae15a8f8dea05e07ba9f8dca"
}
```

### Sample 97: `8b7fcb7a8ca318bb`

| Field | Value |
|---|---|
| SHA-256 | `8b7fcb7a8ca318bbaefb05dec4c4c4910811658e8987ab0360d63548c0990103` |
| Family label | `Mirai` |
| File name | `xd.sh4` |
| File type | `elf` |
| First seen | `2026-08-02 18:46:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f26a48d0535575bd674c3f71ab52d80` |
| SHA-1 | `162fdaaee2fe937b2860573ae7f2fe70dd681db2` |
| SHA-256 | `8b7fcb7a8ca318bbaefb05dec4c4c4910811658e8987ab0360d63548c0990103` |
| SHA3-384 | `5544a1a5643fa8e206a5bf0aca91963696c1554e5a4c7ffb4b5dc6ce1a9ea5d863d29c4ccc6bceceec29ae14bda1b57f` |
| TLSH | `T116B4DF63F6B05ED1C4020A741CFAD2340755F39213D26A51E7FEC9242C8B6767E9EBA2` |
| SSDEEP | `12288:a1ldFi74SaKs6Z6ot38pzwe36iHmJD/GTY8pBP/C:mzF+rZT34ziiG1a` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_8b7fcb7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b7fcb7a8ca318bbaefb05dec4c4c4910811658e8987ab0360d63548c0990103"
    family = "Mirai"
    file_name = "xd.sh4"
    file_type = "elf"
    first_seen = "2026-08-02 18:46:41"
  condition:
    hash.sha256(0, filesize) == "8b7fcb7a8ca318bbaefb05dec4c4c4910811658e8987ab0360d63548c0990103"
}
```

### Sample 98: `fbbb632f5eb001ae`

| Field | Value |
|---|---|
| SHA-256 | `fbbb632f5eb001ae9e45b6d47d388e78de432a08a8366b111c98fc952c482cb7` |
| Family label | `unknown` |
| File name | `install_ehe006.msi` |
| File type | `msi` |
| First seen | `2026-08-02 18:28:11` |
| Reporter | `CNGaoLing` |
| Tags | `msi, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ef1b6156debab0301ffc1dbea6227ca` |
| SHA-1 | `4dfc28af216b6f9a7edc09b4b45901daf2ade90a` |
| SHA-256 | `fbbb632f5eb001ae9e45b6d47d388e78de432a08a8366b111c98fc952c482cb7` |
| SHA3-384 | `21418063ffa1c5d630118cf78185ef05b5b1319803d336db8ac034fbb1ece3c82b5a446bad6d6d7d9ab37d0f7d5d33c7` |
| TLSH | `T169A63382BDCE23B0D18BD374A50A659E38683FD9BAB258417ADD72012EB37371379750` |
| SSDEEP | `196608:l2cqthMixMRIa2mMtqn0IWK8HtDkY/HlYkW222C0RkyWdTOEnwEhPy6A7M:ltLIMHH4DZx97ahOQw3M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_fbbb632f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbbb632f5eb001ae9e45b6d47d388e78de432a08a8366b111c98fc952c482cb7"
    family = "unknown"
    file_name = "install_ehe006.msi"
    file_type = "msi"
    first_seen = "2026-08-02 18:28:11"
  condition:
    hash.sha256(0, filesize) == "fbbb632f5eb001ae9e45b6d47d388e78de432a08a8366b111c98fc952c482cb7"
}
```

### Sample 99: `a2bf687d8dee6a3a`

| Field | Value |
|---|---|
| SHA-256 | `a2bf687d8dee6a3a4d1531a46a3291e2f17a7a165ae40647621a72322b432e0e` |
| Family label | `Mirai` |
| File name | `eclipse.x86_64` |
| File type | `elf` |
| First seen | `2026-08-02 18:21:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ee6967ec03d02d3f25be3dd9a9f672e` |
| SHA-1 | `f2314f43f7fc53d4dde9523c70921785e1d03dd9` |
| SHA-256 | `a2bf687d8dee6a3a4d1531a46a3291e2f17a7a165ae40647621a72322b432e0e` |
| SHA3-384 | `f48f377c95bc3def5166c61109c2833757646f781b6f71838a08b3c5844601e67f85c6c84e12a14e1e05d8cd20e1e557` |
| TLSH | `T1D6858D5AF6E364BCC097C430835FD753A935F4A911227E7B26849E302E66E705B2DF22` |
| TELFHASH | `t1c642403408b9346172e3d916f312f5b96d3210b982f436f05a526ddadfe9f814ca982f` |
| SSDEEP | `24576:tC7+cWufxGPdVHf+6YVN3JLl3UiifSJXSFi9xYv4yC28uEUyo:tJc9fxGFVFY3ZLl3UjfsXSFi9xYeJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_a2bf687d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2bf687d8dee6a3a4d1531a46a3291e2f17a7a165ae40647621a72322b432e0e"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-08-02 18:21:26"
  condition:
    hash.sha256(0, filesize) == "a2bf687d8dee6a3a4d1531a46a3291e2f17a7a165ae40647621a72322b432e0e"
}
```

### Sample 100: `26d90f32df1cd821`

| Field | Value |
|---|---|
| SHA-256 | `26d90f32df1cd821e0995026c4528b22ffacb0e6c6acfb07eec0fcb3eb7a03ac` |
| Family label | `AsyncRAT` |
| File name | `SHBETAPP.exe` |
| File type | `exe` |
| First seen | `2026-08-02 18:15:39` |
| Reporter | `anonymous` |
| Tags | `AsyncRAT, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `631222ce7e5d47d35734ba11a15e7eee` |
| SHA-1 | `235e8d1826b5d6248edec1b51737c155045f4055` |
| SHA-256 | `26d90f32df1cd821e0995026c4528b22ffacb0e6c6acfb07eec0fcb3eb7a03ac` |
| SHA3-384 | `5208e59895dacfd591296858b3083820c8c4484684a3cfdb616132675f584aa40f5488733bfa783b83b0e6945b3bd6e0` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16FC22C0833E4C571E2FD4ABA9833D5008B75E95B9913D76A6FC890AD2E237CD8A14FD4` |
| SSDEEP | `384:KQpwoOiZTWq7HtZARPn9jWH9qbuUszbQxnCJfJBndnjJ1Kc/+:KQpVdt+IIb3BiBncc/+` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_100_26d90f32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26d90f32df1cd821e0995026c4528b22ffacb0e6c6acfb07eec0fcb3eb7a03ac"
    family = "AsyncRAT"
    file_name = "SHBETAPP.exe"
    file_type = "exe"
    first_seen = "2026-08-02 18:15:39"
  condition:
    hash.sha256(0, filesize) == "26d90f32df1cd821e0995026c4528b22ffacb0e6c6acfb07eec0fcb3eb7a03ac"
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
 * Generated: 2026-08-03T04:00:33.220287+00:00
 */

rule MalwareBazaar_unknown_001_fecb8fed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fecb8fedf9ff14958a45077626ace3d82347ac5207c7c123aa4e19c355e28ebc"
    family = "unknown"
    file_name = "File+Cleaner+Pro_1.0.8.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:58:09"
  condition:
    hash.sha256(0, filesize) == "fecb8fedf9ff14958a45077626ace3d82347ac5207c7c123aa4e19c355e28ebc"
}

rule MalwareBazaar_unknown_002_36e71927
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36e7192787f1d6b26b8f285ecfad5d719a37b9dc2882fbce735477a29867de9f"
    family = "unknown"
    file_name = "com.mrdu.forkap.phoneclean_1.0.2.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:53:50"
  condition:
    hash.sha256(0, filesize) == "36e7192787f1d6b26b8f285ecfad5d719a37b9dc2882fbce735477a29867de9f"
}

rule MalwareBazaar_CoinMiner_003_8eb363f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8eb363f0bffd430059369aa2c40d2bba8492a0fa58c159fdf2cf93f4d8084e75"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-03 03:32:26"
  condition:
    hash.sha256(0, filesize) == "8eb363f0bffd430059369aa2c40d2bba8492a0fa58c159fdf2cf93f4d8084e75"
}

rule MalwareBazaar_unknown_004_fc029c04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc029c04afaa0cff7e8baab3a7c7688d00d6d1b9157390071ea3399f1c53b2a6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-03 03:32:07"
  condition:
    hash.sha256(0, filesize) == "fc029c04afaa0cff7e8baab3a7c7688d00d6d1b9157390071ea3399f1c53b2a6"
}

rule MalwareBazaar_unknown_005_ebfd1707
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebfd170776d67428de1053ae6c92a6dee25614c8ec61f488b6f5228b58bbe003"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-03 03:32:00"
  condition:
    hash.sha256(0, filesize) == "ebfd170776d67428de1053ae6c92a6dee25614c8ec61f488b6f5228b58bbe003"
}

rule MalwareBazaar_unknown_006_9dd8f8f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dd8f8f1de9603e04453600d0427345a01d2ab4229cf29d4527ef0cf95b4c75d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-03 03:31:50"
  condition:
    hash.sha256(0, filesize) == "9dd8f8f1de9603e04453600d0427345a01d2ab4229cf29d4527ef0cf95b4c75d"
}

rule MalwareBazaar_unknown_007_2428e3bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2428e3bc10482c8fcb0362b8d95dadeb0231b258e2606b7bd6adcc7e5664578d"
    family = "unknown"
    file_name = "File+Cleaner+Master_1.0.6.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:29:28"
  condition:
    hash.sha256(0, filesize) == "2428e3bc10482c8fcb0362b8d95dadeb0231b258e2606b7bd6adcc7e5664578d"
}

rule MalwareBazaar_unknown_008_d6eb48ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6eb48ecc1a0831a805c5920b2cf9655e60097eb6c7eb822bf87003d71afce95"
    family = "unknown"
    file_name = "File+Cache+Cleaner_2.1.3.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:25:48"
  condition:
    hash.sha256(0, filesize) == "d6eb48ecc1a0831a805c5920b2cf9655e60097eb6c7eb822bf87003d71afce95"
}

rule MalwareBazaar_unknown_009_1f14be1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f14be1a82024cbaf1e203547a8a0ffdd2598c407d4fca59b5d4f9b3379e7780"
    family = "unknown"
    file_name = "com.techgiant.imagetopdf.converter_1.6.2.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:22:26"
  condition:
    hash.sha256(0, filesize) == "1f14be1a82024cbaf1e203547a8a0ffdd2598c407d4fca59b5d4f9b3379e7780"
}

rule MalwareBazaar_unknown_010_36cefed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36cefed9bdb1d3c2bdc91aca29ba6f8b06002019ef6432df922a106acf371177"
    family = "unknown"
    file_name = "com.easytexting.messagingme.sms_1.46.xapk"
    file_type = "xapk"
    first_seen = "2026-08-03 03:19:35"
  condition:
    hash.sha256(0, filesize) == "36cefed9bdb1d3c2bdc91aca29ba6f8b06002019ef6432df922a106acf371177"
}

rule MalwareBazaar_Mirai_011_eeafcefe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeafcefee69c094284b3d652a0d96f30e37e7fe05da7e10a08bc536a744e8e61"
    family = "Mirai"
    file_name = "eeafcefee69c094284b3d652a0d96f30e37e7fe05da7e10a08bc536a744e8e61"
    file_type = "elf"
    first_seen = "2026-08-03 03:18:10"
  condition:
    hash.sha256(0, filesize) == "eeafcefee69c094284b3d652a0d96f30e37e7fe05da7e10a08bc536a744e8e61"
}

rule MalwareBazaar_RemusStealer_012_9af478ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9af478edec362f2ff147458b9581e94dacc7648f5b736975429dc0f2315b9a2d"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-03 03:11:53"
  condition:
    hash.sha256(0, filesize) == "9af478edec362f2ff147458b9581e94dacc7648f5b736975429dc0f2315b9a2d"
}

rule MalwareBazaar_ConnectWise_013_361fd82d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "361fd82dba53c49c5f1cdfc1b3ca658339726a60a1e921ad52d437c0e62a6f85"
    family = "ConnectWise"
    file_name = "Adobe_Reader_uk_install.bat"
    file_type = "bat"
    first_seen = "2026-08-03 03:00:39"
  condition:
    hash.sha256(0, filesize) == "361fd82dba53c49c5f1cdfc1b3ca658339726a60a1e921ad52d437c0e62a6f85"
}

rule MalwareBazaar_unknown_014_d95e8aef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d95e8aef883002d34e9687c04b9dd1370e9c8c6b08ba2e1a7e1ecb9e07a3576b"
    family = "unknown"
    file_name = "d95e8aef883002d34e9687c04b9dd1370e9c8c6b08ba2e1a7e1ecb9e07a3576b"
    file_type = "elf"
    first_seen = "2026-08-03 02:39:54"
  condition:
    hash.sha256(0, filesize) == "d95e8aef883002d34e9687c04b9dd1370e9c8c6b08ba2e1a7e1ecb9e07a3576b"
}

rule MalwareBazaar_unknown_015_13d4561d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13d4561d9e33998b2459ade45408ac962e468bd7b076d49d1313dd442f34e909"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-03 02:21:28"
  condition:
    hash.sha256(0, filesize) == "13d4561d9e33998b2459ade45408ac962e468bd7b076d49d1313dd442f34e909"
}

rule MalwareBazaar_unknown_016_9cabe19e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cabe19e0f845ef04507786eb7b6120eea5c04dd08dae799fcaf7b3a90c6d858"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-03 02:15:11"
  condition:
    hash.sha256(0, filesize) == "9cabe19e0f845ef04507786eb7b6120eea5c04dd08dae799fcaf7b3a90c6d858"
}

rule MalwareBazaar_unknown_017_f0acfe56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0acfe5618c3350d21e42a9784c8275e0be4745522a0ba1137ef52d1fd429388"
    family = "unknown"
    file_name = "a.sh"
    file_type = "sh"
    first_seen = "2026-08-03 02:13:07"
  condition:
    hash.sha256(0, filesize) == "f0acfe5618c3350d21e42a9784c8275e0be4745522a0ba1137ef52d1fd429388"
}

rule MalwareBazaar_unknown_018_858dccc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "858dccc67180f5a95a51e0f80e5adb603c0b9dce7d9a8999a964eeb884498e9f"
    family = "unknown"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:28"
  condition:
    hash.sha256(0, filesize) == "858dccc67180f5a95a51e0f80e5adb603c0b9dce7d9a8999a964eeb884498e9f"
}

rule MalwareBazaar_unknown_019_ca0c2a64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca0c2a644f6c40533811c879c7b0559cb7d01c4399eb2806d3bee0b2f4eaf350"
    family = "unknown"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:27"
  condition:
    hash.sha256(0, filesize) == "ca0c2a644f6c40533811c879c7b0559cb7d01c4399eb2806d3bee0b2f4eaf350"
}

rule MalwareBazaar_unknown_020_d51b92ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51b92caded0f974b04482d2db03cc38bb3137ef6955436681bfd9874d9701ee"
    family = "unknown"
    file_name = "bot.armv6"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:26"
  condition:
    hash.sha256(0, filesize) == "d51b92caded0f974b04482d2db03cc38bb3137ef6955436681bfd9874d9701ee"
}

rule MalwareBazaar_unknown_021_f705b64b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f705b64b8a8dcf8de34dd9c6f1ebcbb5aee140dd973ec70bf998d172ea7d6893"
    family = "unknown"
    file_name = "bot.armv7-a"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:25"
  condition:
    hash.sha256(0, filesize) == "f705b64b8a8dcf8de34dd9c6f1ebcbb5aee140dd973ec70bf998d172ea7d6893"
}

rule MalwareBazaar_unknown_022_f87136be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f87136be73f25c4716fcfbd96499b78ad81093f01484d6edc894a8ca26146bf1"
    family = "unknown"
    file_name = "bot.armv5te"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:23"
  condition:
    hash.sha256(0, filesize) == "f87136be73f25c4716fcfbd96499b78ad81093f01484d6edc894a8ca26146bf1"
}

rule MalwareBazaar_unknown_023_9bc92b9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bc92b9cc544a29b7937678496e117902123af821188bad287ef809daaee8a09"
    family = "unknown"
    file_name = "bot.powerpc"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:22"
  condition:
    hash.sha256(0, filesize) == "9bc92b9cc544a29b7937678496e117902123af821188bad287ef809daaee8a09"
}

rule MalwareBazaar_unknown_024_87eadab4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87eadab4c1b3397ac16fdf6807843c0a3da617ff4a2bfe97f015d9e104578859"
    family = "unknown"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:21"
  condition:
    hash.sha256(0, filesize) == "87eadab4c1b3397ac16fdf6807843c0a3da617ff4a2bfe97f015d9e104578859"
}

rule MalwareBazaar_unknown_025_cb29d2fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb29d2fd5f6bdeffaa330573085ac178cba392e1037fb522a9734d82bf249eed"
    family = "unknown"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:20"
  condition:
    hash.sha256(0, filesize) == "cb29d2fd5f6bdeffaa330573085ac178cba392e1037fb522a9734d82bf249eed"
}

rule MalwareBazaar_unknown_026_2bd04bae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bd04baefb1f340e0c7d816c96db0078c4eb8b7cfce6689fbb187e5696bc7a3a"
    family = "unknown"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-08-03 02:09:18"
  condition:
    hash.sha256(0, filesize) == "2bd04baefb1f340e0c7d816c96db0078c4eb8b7cfce6689fbb187e5696bc7a3a"
}

rule MalwareBazaar_unknown_027_76c48873
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76c488739cdb46ae9bea8ab5d34fb49e7345fba3bcdb9cf3b24cc2e7cd7667f2"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-03 02:08:18"
  condition:
    hash.sha256(0, filesize) == "76c488739cdb46ae9bea8ab5d34fb49e7345fba3bcdb9cf3b24cc2e7cd7667f2"
}

rule MalwareBazaar_unknown_028_9554d429
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9554d42935b9036d49d299e582e1488b3e55fe27f2745ae49955a06a06425584"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-03 02:02:12"
  condition:
    hash.sha256(0, filesize) == "9554d42935b9036d49d299e582e1488b3e55fe27f2745ae49955a06a06425584"
}

rule MalwareBazaar_unknown_029_ac48d176
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac48d17645e060f4ce0b9e22c43e7175ecc0c304fb2a4a3cc8a377a0548f2fed"
    family = "unknown"
    file_name = "loader.sh"
    file_type = "sh"
    first_seen = "2026-08-03 02:02:11"
  condition:
    hash.sha256(0, filesize) == "ac48d17645e060f4ce0b9e22c43e7175ecc0c304fb2a4a3cc8a377a0548f2fed"
}

rule MalwareBazaar_unknown_030_565105c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "565105c1ba3b1802e13798bd17e3a167e6ff4eadc19179028fa9627ab5fe708d"
    family = "unknown"
    file_name = "X-Force Essential Loader.exe"
    file_type = "exe"
    first_seen = "2026-08-03 01:48:34"
  condition:
    hash.sha256(0, filesize) == "565105c1ba3b1802e13798bd17e3a167e6ff4eadc19179028fa9627ab5fe708d"
}

rule MalwareBazaar_Mirai_031_f32e6d2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f32e6d2dcbab31760194ac911b76dbb89561a32bb53d76a1b5c2b16c5f5f3548"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-03 01:35:33"
  condition:
    hash.sha256(0, filesize) == "f32e6d2dcbab31760194ac911b76dbb89561a32bb53d76a1b5c2b16c5f5f3548"
}

rule MalwareBazaar_Mirai_032_17e95878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17e95878a491590bfdc24a82270bc318e59fd426a850dc219c65b711e9425f25"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-03 01:35:04"
  condition:
    hash.sha256(0, filesize) == "17e95878a491590bfdc24a82270bc318e59fd426a850dc219c65b711e9425f25"
}

rule MalwareBazaar_Mirai_033_443f9eaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "443f9eafda59dc44d6da1c0d0363e02d3cee019405c872676ba45e11c03b39e8"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-08-03 01:20:18"
  condition:
    hash.sha256(0, filesize) == "443f9eafda59dc44d6da1c0d0363e02d3cee019405c872676ba45e11c03b39e8"
}

rule MalwareBazaar_Mirai_034_72294207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7229420792cf2ed0803b978655c0afc86e543f5343d73af490c097db9e021fbc"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-08-03 01:18:26"
  condition:
    hash.sha256(0, filesize) == "7229420792cf2ed0803b978655c0afc86e543f5343d73af490c097db9e021fbc"
}

rule MalwareBazaar_Mirai_035_c7789b03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7789b031f5c4ce0889b07507bae51be96b442512e31d72a45ebe22464308926"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-08-03 01:18:10"
  condition:
    hash.sha256(0, filesize) == "c7789b031f5c4ce0889b07507bae51be96b442512e31d72a45ebe22464308926"
}

rule MalwareBazaar_unknown_036_caac2532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caac25321fb3b2ec530de8c37fd032b560885dc487f72f72a861ec9c20ae33f9"
    family = "unknown"
    file_name = "Setup - USDT Flasher.exe"
    file_type = "exe"
    first_seen = "2026-08-03 01:11:10"
  condition:
    hash.sha256(0, filesize) == "caac25321fb3b2ec530de8c37fd032b560885dc487f72f72a861ec9c20ae33f9"
}

rule MalwareBazaar_Mirai_037_4d832952
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d8329523495fd8ff834bd5ec68964ca7eb896010abcebb4238dff3900d7f63b"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-03 01:02:32"
  condition:
    hash.sha256(0, filesize) == "4d8329523495fd8ff834bd5ec68964ca7eb896010abcebb4238dff3900d7f63b"
}

rule MalwareBazaar_Mirai_038_30fb755b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30fb755b87d11dee9fa92ff4adcefb4d15a36b3323f4b879e8d96fb2c3cdbbaf"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-08-03 01:02:30"
  condition:
    hash.sha256(0, filesize) == "30fb755b87d11dee9fa92ff4adcefb4d15a36b3323f4b879e8d96fb2c3cdbbaf"
}

rule MalwareBazaar_Mirai_039_56dae62f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56dae62fb116198deafa855c97074040505f57cff61fe012a096a50531ff4b34"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-08-03 01:01:35"
  condition:
    hash.sha256(0, filesize) == "56dae62fb116198deafa855c97074040505f57cff61fe012a096a50531ff4b34"
}

rule MalwareBazaar_Mirai_040_c3c4f28a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3c4f28ac31b86c7b7212831712cbd11bdd58155e57e4e21200754c691992150"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-03 01:01:18"
  condition:
    hash.sha256(0, filesize) == "c3c4f28ac31b86c7b7212831712cbd11bdd58155e57e4e21200754c691992150"
}

rule MalwareBazaar_Mirai_041_3799f760
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3799f7600cb8a8e0582bacf44e373ab26f414f456ebeab4f0d6095a239647813"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-08-03 01:01:16"
  condition:
    hash.sha256(0, filesize) == "3799f7600cb8a8e0582bacf44e373ab26f414f456ebeab4f0d6095a239647813"
}

rule MalwareBazaar_Mirai_042_1722375f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1722375fa81d3e17092350c51ee6d7068c556c1d137c6d47aa027a18f84f4817"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-08-03 00:59:33"
  condition:
    hash.sha256(0, filesize) == "1722375fa81d3e17092350c51ee6d7068c556c1d137c6d47aa027a18f84f4817"
}

rule MalwareBazaar_Mirai_043_379d8830
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "379d88307d819bdc60fd02afef40a9ff593bfb637f463daa21e42248b24fda5d"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-08-03 00:58:30"
  condition:
    hash.sha256(0, filesize) == "379d88307d819bdc60fd02afef40a9ff593bfb637f463daa21e42248b24fda5d"
}

rule MalwareBazaar_unknown_044_7dd3530e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dd3530e0ca2e0bbe2852f09685019c2e38c70866213d937539ff2060d46e819"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-03 00:57:26"
  condition:
    hash.sha256(0, filesize) == "7dd3530e0ca2e0bbe2852f09685019c2e38c70866213d937539ff2060d46e819"
}

rule MalwareBazaar_Mirai_045_07bbab1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07bbab1d1641808a5c3cecea3710d4ae5c481decddc49675adb0f096610a529d"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-03 00:54:34"
  condition:
    hash.sha256(0, filesize) == "07bbab1d1641808a5c3cecea3710d4ae5c481decddc49675adb0f096610a529d"
}

rule MalwareBazaar_Mirai_046_2b873c8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b873c8e53c32d1947f8b0edbaea7fbf208ab1e202ff1cb07adde58d84894140"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-03 00:54:17"
  condition:
    hash.sha256(0, filesize) == "2b873c8e53c32d1947f8b0edbaea7fbf208ab1e202ff1cb07adde58d84894140"
}

rule MalwareBazaar_Mirai_047_3be39d08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3be39d081294ea74566be909ab5eeb988ba85d16b1c137b3a4bfd7dc728d52a5"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-08-03 00:51:26"
  condition:
    hash.sha256(0, filesize) == "3be39d081294ea74566be909ab5eeb988ba85d16b1c137b3a4bfd7dc728d52a5"
}

rule MalwareBazaar_Mirai_048_98cf52a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98cf52a25bbc4e4287656eb28daaeb01bebfe6c7aa9a0af31f5f811b520cb783"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-08-03 00:51:10"
  condition:
    hash.sha256(0, filesize) == "98cf52a25bbc4e4287656eb28daaeb01bebfe6c7aa9a0af31f5f811b520cb783"
}

rule MalwareBazaar_unknown_049_08a91019
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08a91019ff7ba6f77de3b774dc201cca18edfd264f9a46e34f243f6d76e37077"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-03 00:49:06"
  condition:
    hash.sha256(0, filesize) == "08a91019ff7ba6f77de3b774dc201cca18edfd264f9a46e34f243f6d76e37077"
}

rule MalwareBazaar_Mirai_050_1d87d05a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d87d05a3772a774667df44d1ebdec9a31eb460d8e6fb4ea4ed4ab9314dcaa78"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-08-03 00:48:03"
  condition:
    hash.sha256(0, filesize) == "1d87d05a3772a774667df44d1ebdec9a31eb460d8e6fb4ea4ed4ab9314dcaa78"
}

rule MalwareBazaar_Mirai_051_33ede958
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33ede9583b474ce942e4fe36f7336b9b09552209230b4576860342ed56bd0d76"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-03 00:46:21"
  condition:
    hash.sha256(0, filesize) == "33ede9583b474ce942e4fe36f7336b9b09552209230b4576860342ed56bd0d76"
}

rule MalwareBazaar_Mirai_052_b40a8ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b40a8ddcb9e9da71f24f4459cbc7fd9a9c807d172082c0cc4ea6238b7ea9b003"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-08-03 00:46:12"
  condition:
    hash.sha256(0, filesize) == "b40a8ddcb9e9da71f24f4459cbc7fd9a9c807d172082c0cc4ea6238b7ea9b003"
}

rule MalwareBazaar_Mirai_053_b46800eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b46800eb4eb3fbc6decc75bad5ebb5b400e27200c50da23199bd1f6a07537820"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-03 00:45:31"
  condition:
    hash.sha256(0, filesize) == "b46800eb4eb3fbc6decc75bad5ebb5b400e27200c50da23199bd1f6a07537820"
}

rule MalwareBazaar_Mirai_054_1018201a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1018201ac9e47403b240fdcbce9ab1fca8837694a92ffab02089eceef7541ede"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-08-03 00:45:30"
  condition:
    hash.sha256(0, filesize) == "1018201ac9e47403b240fdcbce9ab1fca8837694a92ffab02089eceef7541ede"
}

rule MalwareBazaar_Mirai_055_7e149890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e149890b2a6443eaf6d2569c824d5d578c7f6f1a55452e552a452c4f930d922"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-08-03 00:45:30"
  condition:
    hash.sha256(0, filesize) == "7e149890b2a6443eaf6d2569c824d5d578c7f6f1a55452e552a452c4f930d922"
}

rule MalwareBazaar_Mirai_056_99e62f03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99e62f03ab120c32193fa4170496e4fdcc80b4a952956874d7f3585c8a07dff7"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-08-03 00:44:28"
  condition:
    hash.sha256(0, filesize) == "99e62f03ab120c32193fa4170496e4fdcc80b4a952956874d7f3585c8a07dff7"
}

rule MalwareBazaar_Mirai_057_655f3fa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "655f3fa43344394e6c4e57a769486e619339f9951092499c250ec7445c1bc4d4"
    family = "Mirai"
    file_name = "mkno"
    file_type = "elf"
    first_seen = "2026-08-03 00:30:21"
  condition:
    hash.sha256(0, filesize) == "655f3fa43344394e6c4e57a769486e619339f9951092499c250ec7445c1bc4d4"
}

rule MalwareBazaar_Mirai_058_42496537
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42496537fd1dd885373c5a0b513e17965aee0302816527907a7c9c0967029873"
    family = "Mirai"
    file_name = "Qtj"
    file_type = "elf"
    first_seen = "2026-08-03 00:30:19"
  condition:
    hash.sha256(0, filesize) == "42496537fd1dd885373c5a0b513e17965aee0302816527907a7c9c0967029873"
}

rule MalwareBazaar_unknown_059_62550c7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62550c7ec27b049999506513f37f06eb5e2e1bf3c8fd1d2487e15ef70cdb2949"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-03 00:16:41"
  condition:
    hash.sha256(0, filesize) == "62550c7ec27b049999506513f37f06eb5e2e1bf3c8fd1d2487e15ef70cdb2949"
}

rule MalwareBazaar_Mirai_060_312fbbed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "312fbbedbe184110665f336846fff7a36d2c211b484e87fd7f57962267bbd66c"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-08-03 00:06:35"
  condition:
    hash.sha256(0, filesize) == "312fbbedbe184110665f336846fff7a36d2c211b484e87fd7f57962267bbd66c"
}

rule MalwareBazaar_Mirai_061_2c19cd42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c19cd42e8cbfd4f3b6d72ba98f4d90540bc711af6d7ccb7d94202257397b9c9"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-08-03 00:06:17"
  condition:
    hash.sha256(0, filesize) == "2c19cd42e8cbfd4f3b6d72ba98f4d90540bc711af6d7ccb7d94202257397b9c9"
}

rule MalwareBazaar_NetSupport_062_7e750d93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e750d93404ccb98bfab8ca03c5b64e09ac4933a404d6f4596ff9897ad3b43e3"
    family = "NetSupport"
    file_name = "nets.zip"
    file_type = "zip"
    first_seen = "2026-08-03 00:04:59"
  condition:
    hash.sha256(0, filesize) == "7e750d93404ccb98bfab8ca03c5b64e09ac4933a404d6f4596ff9897ad3b43e3"
}

rule MalwareBazaar_unknown_063_46e7c383
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46e7c38344a335e4c6100799372959a12fc17781bee2352ef2797633b657bbb0"
    family = "unknown"
    file_name = "echovoice-beta-1.0.0-fabric.jar"
    file_type = "jar"
    first_seen = "2026-08-02 23:24:14"
  condition:
    hash.sha256(0, filesize) == "46e7c38344a335e4c6100799372959a12fc17781bee2352ef2797633b657bbb0"
}

rule MalwareBazaar_unknown_064_ce7757d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce7757d30cf3e83fd573935d57860d45682e9dff2a1a4947857a58e49125960f"
    family = "unknown"
    file_name = "hnap"
    file_type = "sh"
    first_seen = "2026-08-02 23:13:10"
  condition:
    hash.sha256(0, filesize) == "ce7757d30cf3e83fd573935d57860d45682e9dff2a1a4947857a58e49125960f"
}

rule MalwareBazaar_Mirai_065_b17643a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b17643a10894128e150cec8f619be1c1960bc99eb789eeb4b5f6fa370265e2c3"
    family = "Mirai"
    file_name = "xd.mips64"
    file_type = "elf"
    first_seen = "2026-08-02 23:13:08"
  condition:
    hash.sha256(0, filesize) == "b17643a10894128e150cec8f619be1c1960bc99eb789eeb4b5f6fa370265e2c3"
}

rule MalwareBazaar_Mirai_066_2a490acd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a490acd4bd1f94e0f68377566a5e2ab1640af5b7ec8e4410813c25d56fc5d33"
    family = "Mirai"
    file_name = "g.mpsl"
    file_type = "elf"
    first_seen = "2026-08-02 23:13:07"
  condition:
    hash.sha256(0, filesize) == "2a490acd4bd1f94e0f68377566a5e2ab1640af5b7ec8e4410813c25d56fc5d33"
}

rule MalwareBazaar_Mirai_067_97b72577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97b72577f7b3cea01e2a992a345f56a197a859700a7a781a77204990f64f1c35"
    family = "Mirai"
    file_name = "g.mips"
    file_type = "elf"
    first_seen = "2026-08-02 23:13:06"
  condition:
    hash.sha256(0, filesize) == "97b72577f7b3cea01e2a992a345f56a197a859700a7a781a77204990f64f1c35"
}

rule MalwareBazaar_Mirai_068_4f957ced
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f957ced7aeec095681d6140d0c7246983626a308060b1a1df3b55fbd3478da5"
    family = "Mirai"
    file_name = "xd.x86"
    file_type = "elf"
    first_seen = "2026-08-02 23:13:04"
  condition:
    hash.sha256(0, filesize) == "4f957ced7aeec095681d6140d0c7246983626a308060b1a1df3b55fbd3478da5"
}

rule MalwareBazaar_unknown_069_f1e420fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1e420fee19df82b35d05e445eaeab7cb1e8998665794898e3c0049b7cfde7aa"
    family = "unknown"
    file_name = "gpon"
    file_type = "sh"
    first_seen = "2026-08-02 23:13:03"
  condition:
    hash.sha256(0, filesize) == "f1e420fee19df82b35d05e445eaeab7cb1e8998665794898e3c0049b7cfde7aa"
}

rule MalwareBazaar_unknown_070_68f1d97a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68f1d97aa77845a936ec0d51bdcf605d97e10e7866fb5438ee49793c286d352f"
    family = "unknown"
    file_name = "realtek"
    file_type = "sh"
    first_seen = "2026-08-02 23:13:01"
  condition:
    hash.sha256(0, filesize) == "68f1d97aa77845a936ec0d51bdcf605d97e10e7866fb5438ee49793c286d352f"
}

rule MalwareBazaar_unknown_071_cae41900
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae41900fd831579de5bc9650a22a1123f28a1874106f56870b81f7682d9287e"
    family = "unknown"
    file_name = "huawei"
    file_type = "sh"
    first_seen = "2026-08-02 23:13:00"
  condition:
    hash.sha256(0, filesize) == "cae41900fd831579de5bc9650a22a1123f28a1874106f56870b81f7682d9287e"
}

rule MalwareBazaar_unknown_072_0314e577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0314e5776227f605417d00977137f1b637ab8b4760ec3b1fb3030d1907854c39"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 23:04:49"
  condition:
    hash.sha256(0, filesize) == "0314e5776227f605417d00977137f1b637ab8b4760ec3b1fb3030d1907854c39"
}

rule MalwareBazaar_unknown_073_0bbee397
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bbee3979b0327b6c327c4522414a90d18164af3846ea6a8e62e5fee861f6d51"
    family = "unknown"
    file_name = "0bbee3979b0327b6c327c4522414a90d18164af3846ea6a8e62e5fee861f6d51"
    file_type = "elf"
    first_seen = "2026-08-02 23:00:21"
  condition:
    hash.sha256(0, filesize) == "0bbee3979b0327b6c327c4522414a90d18164af3846ea6a8e62e5fee861f6d51"
}

rule MalwareBazaar_CoinMiner_074_6106d845
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6106d8452e2cbc4281303e007a37c427ce397d7725b4f90143307c18649c9445"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 22:53:01"
  condition:
    hash.sha256(0, filesize) == "6106d8452e2cbc4281303e007a37c427ce397d7725b4f90143307c18649c9445"
}

rule MalwareBazaar_unknown_075_bdcffdf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdcffdf543d7de8063d07d54f90f30d837fc872ed2f09b000788c6559a9af568"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 22:52:41"
  condition:
    hash.sha256(0, filesize) == "bdcffdf543d7de8063d07d54f90f30d837fc872ed2f09b000788c6559a9af568"
}

rule MalwareBazaar_unknown_076_46470c9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46470c9a7ee889553a1861cc782cf4b938d6712364a25c095ad5b50cf2f826f9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 22:52:34"
  condition:
    hash.sha256(0, filesize) == "46470c9a7ee889553a1861cc782cf4b938d6712364a25c095ad5b50cf2f826f9"
}

rule MalwareBazaar_unknown_077_2236e527
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2236e527e4aa90f170150cd4c8622054f478418befd1be1b3d9280c2bcd2ac87"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 22:52:25"
  condition:
    hash.sha256(0, filesize) == "2236e527e4aa90f170150cd4c8622054f478418befd1be1b3d9280c2bcd2ac87"
}

rule MalwareBazaar_unknown_078_ca98331f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca98331f359b0aa194ec6afc7783923fa9395146a369bce5e14ebc9270d6e64d"
    family = "unknown"
    file_name = "7b17z.exe"
    file_type = "exe"
    first_seen = "2026-08-02 22:47:13"
  condition:
    hash.sha256(0, filesize) == "ca98331f359b0aa194ec6afc7783923fa9395146a369bce5e14ebc9270d6e64d"
}

rule MalwareBazaar_unknown_079_c285743b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c285743be1d2f01eb3d134750b71571797eb5d18affd0715ba2286da23580763"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 22:00:21"
  condition:
    hash.sha256(0, filesize) == "c285743be1d2f01eb3d134750b71571797eb5d18affd0715ba2286da23580763"
}

rule MalwareBazaar_Mirai_080_1756d6f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1756d6f4348931af8d3029384ccee8d7281673a627ca753d7c3ea3e7881356d8"
    family = "Mirai"
    file_name = "cekizsafu"
    file_type = "elf"
    first_seen = "2026-08-02 20:40:30"
  condition:
    hash.sha256(0, filesize) == "1756d6f4348931af8d3029384ccee8d7281673a627ca753d7c3ea3e7881356d8"
}

rule MalwareBazaar_unknown_081_d3998ff2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3998ff200687491baefd3038f06c9b891aabb3193be52fa14070c644c00b8e0"
    family = "unknown"
    file_name = "Violence.msi"
    file_type = "msi"
    first_seen = "2026-08-02 20:34:24"
  condition:
    hash.sha256(0, filesize) == "d3998ff200687491baefd3038f06c9b891aabb3193be52fa14070c644c00b8e0"
}

rule MalwareBazaar_Mirai_082_fe450082
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe4500826280340597344445a1734897495008210740ea41f80f3b5dbc908184"
    family = "Mirai"
    file_name = "xd.arm6"
    file_type = "elf"
    first_seen = "2026-08-02 20:16:30"
  condition:
    hash.sha256(0, filesize) == "fe4500826280340597344445a1734897495008210740ea41f80f3b5dbc908184"
}

rule MalwareBazaar_unknown_083_db4c3aa6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db4c3aa640d2be4ed97fbe502e2b27683a6ba3318524181bc4ab570bafe8c26d"
    family = "unknown"
    file_name = "zapret-discord-youtube-1.10.0.zip"
    file_type = "zip"
    first_seen = "2026-08-02 20:12:52"
  condition:
    hash.sha256(0, filesize) == "db4c3aa640d2be4ed97fbe502e2b27683a6ba3318524181bc4ab570bafe8c26d"
}

rule MalwareBazaar_RemusStealer_084_bb71186a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb71186aa5e8ce286c5e8698adf22aac802615856dbab846a88e740cb5ce4316"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-02 20:07:49"
  condition:
    hash.sha256(0, filesize) == "bb71186aa5e8ce286c5e8698adf22aac802615856dbab846a88e740cb5ce4316"
}

rule MalwareBazaar_Mirai_085_f73e07da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f73e07daa7a1016efd4ee10266960549d4e2f85d0bc840d4c6a0a632e19e6c05"
    family = "Mirai"
    file_name = "xd.ppc"
    file_type = "elf"
    first_seen = "2026-08-02 19:56:34"
  condition:
    hash.sha256(0, filesize) == "f73e07daa7a1016efd4ee10266960549d4e2f85d0bc840d4c6a0a632e19e6c05"
}

rule MalwareBazaar_unknown_086_1f9fa9f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f9fa9f15dd3b67c9af0a0af8377fd65ee6fe838ce55c5eb9fc26565449d9ae4"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-02 19:54:12"
  condition:
    hash.sha256(0, filesize) == "1f9fa9f15dd3b67c9af0a0af8377fd65ee6fe838ce55c5eb9fc26565449d9ae4"
}

rule MalwareBazaar_unknown_087_976286fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "976286fb575cf6c6dcfd50695cb538d3d764642ea36122209d11d104d0ca5182"
    family = "unknown"
    file_name = "systemd"
    file_type = "elf"
    first_seen = "2026-08-02 19:50:14"
  condition:
    hash.sha256(0, filesize) == "976286fb575cf6c6dcfd50695cb538d3d764642ea36122209d11d104d0ca5182"
}

rule MalwareBazaar_unknown_088_e9fe3501
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9fe35015e5ef9a7d7d0b07b5fee72f2bc55882175447bfe8a5bb7da2535101a"
    family = "unknown"
    file_name = "sensi.sh"
    file_type = "sh"
    first_seen = "2026-08-02 19:50:13"
  condition:
    hash.sha256(0, filesize) == "e9fe35015e5ef9a7d7d0b07b5fee72f2bc55882175447bfe8a5bb7da2535101a"
}

rule MalwareBazaar_Mirai_089_e731201a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e731201a0924332f0b694e1e17958b4c70f274b22ad0b80a8face370cc921549"
    family = "Mirai"
    file_name = "xd.m68k"
    file_type = "elf"
    first_seen = "2026-08-02 19:44:34"
  condition:
    hash.sha256(0, filesize) == "e731201a0924332f0b694e1e17958b4c70f274b22ad0b80a8face370cc921549"
}

rule MalwareBazaar_unknown_090_f51484af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f51484af77409f59acb111f5a88417d7a8890591050aa51ddf0102fd1540aaf3"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-02 19:39:24"
  condition:
    hash.sha256(0, filesize) == "f51484af77409f59acb111f5a88417d7a8890591050aa51ddf0102fd1540aaf3"
}

rule MalwareBazaar_Mirai_091_35e790ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35e790ee32623b31fee32c012f415086c892d6f7f3d4d947dda20e90428d25ae"
    family = "Mirai"
    file_name = "loader.sh"
    file_type = "sh"
    first_seen = "2026-08-02 19:38:12"
  condition:
    hash.sha256(0, filesize) == "35e790ee32623b31fee32c012f415086c892d6f7f3d4d947dda20e90428d25ae"
}

rule MalwareBazaar_Mirai_092_cc55866a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc55866a9fef44732dfd16da90241e024dc5ec416aff55f377b082c265e2bcc2"
    family = "Mirai"
    file_name = "xd.arm7"
    file_type = "elf"
    first_seen = "2026-08-02 19:26:17"
  condition:
    hash.sha256(0, filesize) == "cc55866a9fef44732dfd16da90241e024dc5ec416aff55f377b082c265e2bcc2"
}

rule MalwareBazaar_Mirai_093_20930723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2093072334c5b85464a0b733ea4f6abe35d074db34304e0d3b5d18132b09ba22"
    family = "Mirai"
    file_name = "xd.mpsl"
    file_type = "elf"
    first_seen = "2026-08-02 19:07:28"
  condition:
    hash.sha256(0, filesize) == "2093072334c5b85464a0b733ea4f6abe35d074db34304e0d3b5d18132b09ba22"
}

rule MalwareBazaar_Mirai_094_8c19a8ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c19a8ace6a6cbeb8d68c82a270659fb03160f263d15cd31db6e6317a148fee7"
    family = "Mirai"
    file_name = "xd.arm5"
    file_type = "elf"
    first_seen = "2026-08-02 19:04:38"
  condition:
    hash.sha256(0, filesize) == "8c19a8ace6a6cbeb8d68c82a270659fb03160f263d15cd31db6e6317a148fee7"
}

rule MalwareBazaar_Mirai_095_d054f482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d054f4822da5ea5e99edb57d809b9bacf86cfa3def04fa3711ddf88be7a68790"
    family = "Mirai"
    file_name = "xd.spc"
    file_type = "elf"
    first_seen = "2026-08-02 18:56:13"
  condition:
    hash.sha256(0, filesize) == "d054f4822da5ea5e99edb57d809b9bacf86cfa3def04fa3711ddf88be7a68790"
}

rule MalwareBazaar_Mirai_096_9b272fcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b272fcffe76786a28735e9f4f1d17d8eefcac68ae15a8f8dea05e07ba9f8dca"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-02 18:49:22"
  condition:
    hash.sha256(0, filesize) == "9b272fcffe76786a28735e9f4f1d17d8eefcac68ae15a8f8dea05e07ba9f8dca"
}

rule MalwareBazaar_Mirai_097_8b7fcb7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b7fcb7a8ca318bbaefb05dec4c4c4910811658e8987ab0360d63548c0990103"
    family = "Mirai"
    file_name = "xd.sh4"
    file_type = "elf"
    first_seen = "2026-08-02 18:46:41"
  condition:
    hash.sha256(0, filesize) == "8b7fcb7a8ca318bbaefb05dec4c4c4910811658e8987ab0360d63548c0990103"
}

rule MalwareBazaar_unknown_098_fbbb632f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbbb632f5eb001ae9e45b6d47d388e78de432a08a8366b111c98fc952c482cb7"
    family = "unknown"
    file_name = "install_ehe006.msi"
    file_type = "msi"
    first_seen = "2026-08-02 18:28:11"
  condition:
    hash.sha256(0, filesize) == "fbbb632f5eb001ae9e45b6d47d388e78de432a08a8366b111c98fc952c482cb7"
}

rule MalwareBazaar_Mirai_099_a2bf687d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2bf687d8dee6a3a4d1531a46a3291e2f17a7a165ae40647621a72322b432e0e"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-08-02 18:21:26"
  condition:
    hash.sha256(0, filesize) == "a2bf687d8dee6a3a4d1531a46a3291e2f17a7a165ae40647621a72322b432e0e"
}

rule MalwareBazaar_AsyncRAT_100_26d90f32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26d90f32df1cd821e0995026c4528b22ffacb0e6c6acfb07eec0fcb3eb7a03ac"
    family = "AsyncRAT"
    file_name = "SHBETAPP.exe"
    file_type = "exe"
    first_seen = "2026-08-02 18:15:39"
  condition:
    hash.sha256(0, filesize) == "26d90f32df1cd821e0995026c4528b22ffacb0e6c6acfb07eec0fcb3eb7a03ac"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

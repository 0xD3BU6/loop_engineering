# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-07

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
| Unique family labels | 14 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 41 |
| unknown | 36 |
| CoinMiner | 4 |
| AsyncRAT | 3 |
| RatonRAT | 3 |
| AgentTesla | 2 |
| RemcosRAT | 2 |
| ValleyRAT | 2 |
| Adware.Techsnab | 2 |
| Formbook | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 44 |
| exe | 32 |
| sh | 9 |
| js | 5 |
| unknown | 4 |
| zip | 3 |
| ps1 | 3 |

## Per-Sample Analysis

### Sample 1: `9cbb12444a989d93`

| Field | Value |
|---|---|
| SHA-256 | `9cbb12444a989d93979727d190b7f61f558917569c513956a90970866447ab00` |
| Family label | `unknown` |
| File name | `Details07.06.zip` |
| File type | `zip` |
| First seen | `2026-07-07 04:14:15` |
| Reporter | `anonymous` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `437c6b940a84fa6c25b5de9963d1fd94` |
| SHA-1 | `150a1831e28b2e016da40752b50833bc8d9ede89` |
| SHA-256 | `9cbb12444a989d93979727d190b7f61f558917569c513956a90970866447ab00` |
| SHA3-384 | `9203c40d74fb59576fe3b1f1f2c018d4dbe8493c85556446f6ff97e91661ebdc69190113e039bbb45c7986f8f0261fc0` |
| TLSH | `T18B6733880600AADB54F47F82524E721AEED75831FFD49CD358D06E544A87B0AF0FE76A` |
| SSDEEP | `786432:9XVJJAHRNsXWWxwvyVAqN7JW1Emo0q8E/iILJg/:8ZiwvO9N7yEAILC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_9cbb1244
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cbb12444a989d93979727d190b7f61f558917569c513956a90970866447ab00"
    family = "unknown"
    file_name = "Details07.06.zip"
    file_type = "zip"
    first_seen = "2026-07-07 04:14:15"
  condition:
    hash.sha256(0, filesize) == "9cbb12444a989d93979727d190b7f61f558917569c513956a90970866447ab00"
}
```

### Sample 2: `094bc9cce12a0be4`

| Field | Value |
|---|---|
| SHA-256 | `094bc9cce12a0be4ccd399a355cd3444fb189e1f58109d5f799ed1719cd81993` |
| Family label | `AgentTesla` |
| File name | `Vessel Details.js` |
| File type | `js` |
| First seen | `2026-07-07 03:57:42` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0915fe7ea6eb514de76bab0e3f09f56` |
| SHA-1 | `d5f22c335719f1c2a08fdd29e7a311e86982cbca` |
| SHA-256 | `094bc9cce12a0be4ccd399a355cd3444fb189e1f58109d5f799ed1719cd81993` |
| SHA3-384 | `26a68939c2d710c0aca09f1395648ec51afb6e4d6973a87af5b951c566459c0a29d2b441303aea92ca5b7708d7293b29` |
| TLSH | `T1F355F1104AC05FA88FF95B2E60FE2189F2E20ADF5465A84BE723FC45EFF66049953174` |
| SSDEEP | `12288:wRfhXcws/5Vam0sNZ98ez0MYRYfYlvmvlu6rKfoh92FrLf6eIP5EoZlNllfAKeFZ:w9mwSR0sNZ98w8KTf1mFXmDWUXM0g8YD` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_002_094bc9cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "094bc9cce12a0be4ccd399a355cd3444fb189e1f58109d5f799ed1719cd81993"
    family = "AgentTesla"
    file_name = "Vessel Details.js"
    file_type = "js"
    first_seen = "2026-07-07 03:57:42"
  condition:
    hash.sha256(0, filesize) == "094bc9cce12a0be4ccd399a355cd3444fb189e1f58109d5f799ed1719cd81993"
}
```

### Sample 3: `9580ade23d0a14b7`

| Field | Value |
|---|---|
| SHA-256 | `9580ade23d0a14b7c944beed4bc8b5a5ed838846a951b25a97108c3494a8e19d` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-07 03:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04da9815f316a2963538292b3a68955c` |
| SHA-1 | `695a83b9b083ec51bf204dab666c144501db8ce6` |
| SHA-256 | `9580ade23d0a14b7c944beed4bc8b5a5ed838846a951b25a97108c3494a8e19d` |
| SHA3-384 | `0a7a7c89823e7c7a944f3826e4f57c65a263459858d18c297ec26832ffc781188d9633d9175028e46a04ca5379abddfe` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T183E633085BD105DFDAB3817CDEF11AB5E595B0B54372CACB47A8878BAE170E0887D722` |
| SSDEEP | `393216:JDCnrokXqi5rWHoN0HCqf779uXMCHWUjXEcuI3/PGTAI:JSWHoeCAn9uXMb8XRH/O7` |
| ICON-DHASH | `70f0f0e8e8f0f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_9580ade2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9580ade23d0a14b7c944beed4bc8b5a5ed838846a951b25a97108c3494a8e19d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 03:52:11"
  condition:
    hash.sha256(0, filesize) == "9580ade23d0a14b7c944beed4bc8b5a5ed838846a951b25a97108c3494a8e19d"
}
```

### Sample 4: `95817406c54a108c`

| Field | Value |
|---|---|
| SHA-256 | `95817406c54a108cb2728e5f5b75501e3d958f0b538d5f1cb283d8935d0d80f3` |
| Family label | `Formbook` |
| File name | `NEW_MV_SHINNING_STAR_VESSEL_DETAILS.exe` |
| File type | `exe` |
| First seen | `2026-07-07 03:42:30` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f18588d2592b2d86bbdc5bb0d69ed244` |
| SHA-1 | `cd41a137314508621b6c795b4d0adb6cc01636ac` |
| SHA-256 | `95817406c54a108cb2728e5f5b75501e3d958f0b538d5f1cb283d8935d0d80f3` |
| SHA3-384 | `41c2fff4b186f19a4389606f15a84f58c09540216ea7e2cf934e671a0db2bd343201b7fe0693c8c405ef8841be5cf64a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F235F1151E876B98CABE6FBCC063149437F0DA0782A6D76E3FED11F49EA3B85C901452` |
| SSDEEP | `12288:87G6scWh5YX8kBzdG7oe9mxHewPrQjMvNQMRkSPRHO8W/OhBGu:V50jhwH7krK+QoDPHW/Sf` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_004_95817406
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95817406c54a108cb2728e5f5b75501e3d958f0b538d5f1cb283d8935d0d80f3"
    family = "Formbook"
    file_name = "NEW_MV_SHINNING_STAR_VESSEL_DETAILS.exe"
    file_type = "exe"
    first_seen = "2026-07-07 03:42:30"
  condition:
    hash.sha256(0, filesize) == "95817406c54a108cb2728e5f5b75501e3d958f0b538d5f1cb283d8935d0d80f3"
}
```

### Sample 5: `5489a805b1e17f8c`

| Field | Value |
|---|---|
| SHA-256 | `5489a805b1e17f8c133f9947aa6b317524c7ee5a341bd3f2aee85b3a111f8f6a` |
| Family label | `RemcosRAT` |
| File name | `德驭】INVOICE-0609 - HT 260615 (MTR26-06-13).scr` |
| File type | `exe` |
| First seen | `2026-07-07 03:33:43` |
| Reporter | `threatcat_ch` |
| Tags | `exe, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d127480989efd5de1a793404e4be648b` |
| SHA-1 | `52955161c914f81587d4c3c8f8043ee6d139c2ad` |
| SHA-256 | `5489a805b1e17f8c133f9947aa6b317524c7ee5a341bd3f2aee85b3a111f8f6a` |
| SHA3-384 | `b4053704181a00021e0a4eec15670ce79a44254b8ccc967d6fdd3350f348fe1527d6aa87a0573f15d0cadc326fa769f2` |
| TLSH | `T1D7652250AE5CC802C4E21B750A61F33553F85D8DF621CE129BFCBCA77ABAB07AC60655` |
| SSDEEP | `24576:ml9tn48n0/z7jpp0vLNwuk/H/E6f1/SLSrYJRWXh7TopkgJpeMQC9Fsm9sZYtiO6:ml9tn48n0/zXpp0DNA86f1xMW16vXc0j` |
| ICON-DHASH | `3096968e8eb2b230` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_005_5489a805
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5489a805b1e17f8c133f9947aa6b317524c7ee5a341bd3f2aee85b3a111f8f6a"
    family = "RemcosRAT"
    file_name = "德驭】INVOICE-0609 - HT 260615 (MTR26-06-13).scr"
    file_type = "exe"
    first_seen = "2026-07-07 03:33:43"
  condition:
    hash.sha256(0, filesize) == "5489a805b1e17f8c133f9947aa6b317524c7ee5a341bd3f2aee85b3a111f8f6a"
}
```

### Sample 6: `5de8f96372fba00a`

| Field | Value |
|---|---|
| SHA-256 | `5de8f96372fba00afca1eab7df600d5584e93b87ce9363cbfcb0ce44fd742b38` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-07 03:25:20` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `637653f36fb554d30c536fae10b791be` |
| SHA-1 | `b57d8fcd61d430df2111fcd338a20a2997ada635` |
| SHA-256 | `5de8f96372fba00afca1eab7df600d5584e93b87ce9363cbfcb0ce44fd742b38` |
| SHA3-384 | `a8486476e2ba7b423e827c24f2d1944e9615f1eb80815d0aa7b7fa9a26c72bd210fbfe660baf1d1fb1433a9a854a9c91` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T123A5230E43D09011F0652B3484E905969733BC9069FEAAAF22C4B67A7F734E5B175B0F` |
| SSDEEP | `49152:Bu09dMbDQCtFfhcy5GAhxjNFtGUGlBURdXmRS9zimaAsmY:rUlByyRhxjlGUcURQ0la/` |
| ICON-DHASH | `002561790f333333` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_5de8f963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5de8f96372fba00afca1eab7df600d5584e93b87ce9363cbfcb0ce44fd742b38"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 03:25:20"
  condition:
    hash.sha256(0, filesize) == "5de8f96372fba00afca1eab7df600d5584e93b87ce9363cbfcb0ce44fd742b38"
}
```

### Sample 7: `6ee3cd19645816a6`

| Field | Value |
|---|---|
| SHA-256 | `6ee3cd19645816a60c51c362a125837d49e066ca0d0c1f03cc2a40f0a45739d2` |
| Family label | `unknown` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-07 03:23:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70364db2c4af939908d2cfd9eba780d8` |
| SHA-1 | `ff4cdc52fb404bdf1692ceed0dc363d07ac1b88a` |
| SHA-256 | `6ee3cd19645816a60c51c362a125837d49e066ca0d0c1f03cc2a40f0a45739d2` |
| SHA3-384 | `cd02f67dbc6f1a495e201d0bc927cc8be8e22b30bbf99214da6f67283e68fc264672284afa1057840f886028445795fc` |
| TLSH | `T131936D02B70C0E43D1675DF02A3F27D1D3EEA6E121F4F688691F9A8591B2E335586EC9` |
| SSDEEP | `1536:2ylR4eY8zrTgbrO0wV4SKUgZ5VvHfNa4Y0XM1y8pAzKYfud29MuXyC47UwUR3Bwu:22RvfzrTT0wqkBbAzJxMVCsDu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_6ee3cd19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee3cd19645816a60c51c362a125837d49e066ca0d0c1f03cc2a40f0a45739d2"
    family = "unknown"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-07 03:23:49"
  condition:
    hash.sha256(0, filesize) == "6ee3cd19645816a60c51c362a125837d49e066ca0d0c1f03cc2a40f0a45739d2"
}
```

### Sample 8: `4221c1eee1c15d74`

| Field | Value |
|---|---|
| SHA-256 | `4221c1eee1c15d74837a34ee1ccc5693271c4ad9570bada0f9bea03a1e104013` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-07 03:22:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e32c749314f9e173f75ae3fea45faad` |
| SHA-1 | `812a63aa0c769489f4b3fa416a35acba4795730c` |
| SHA-256 | `4221c1eee1c15d74837a34ee1ccc5693271c4ad9570bada0f9bea03a1e104013` |
| SHA3-384 | `f957440cbf219b9ca2cc5e3ff6f6454febff0398d2190726c7a5fc72fc3da44dd73276acd9974e83391e62d6a0dbfbee` |
| TLSH | `T1D903E0B8C2E60F80EAB78DA35D0296D3B7C0E26F0AA6D6D331C6DE110255417A352CE4` |
| SSDEEP | `768:dCTJXa0i57PpqZnFoIdNumO6IHC/psK9md/YTcMao3usSZl4uVcqgw0IP:8JXtiq3oocmB/pp9Q/YAMP3uFl4u+qgo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_4221c1ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4221c1eee1c15d74837a34ee1ccc5693271c4ad9570bada0f9bea03a1e104013"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-07 03:22:58"
  condition:
    hash.sha256(0, filesize) == "4221c1eee1c15d74837a34ee1ccc5693271c4ad9570bada0f9bea03a1e104013"
}
```

### Sample 9: `0c62a122eba57c96`

| Field | Value |
|---|---|
| SHA-256 | `0c62a122eba57c96a909e337501955b1bb2705c3ba56a6ef1d9b75f090404a34` |
| Family label | `AsyncRAT` |
| File name | `SKJG09876545678900.js` |
| File type | `js` |
| First seen | `2026-07-07 03:05:03` |
| Reporter | `nat` |
| Tags | `AsyncRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2525d443e0db2762e4790e0aa17cbd14` |
| SHA-1 | `53d088784623c22d3d2d493e8b2e4a536d95afb5` |
| SHA-256 | `0c62a122eba57c96a909e337501955b1bb2705c3ba56a6ef1d9b75f090404a34` |
| SHA3-384 | `89023b4c57ab7b7ff805af90f387c846704775b05abbb8c4d49e2004edf8dfd50ffc15139cceef642bfe3f3e305788ca` |
| TLSH | `T12C64B0482BC1BE6CDF6AB43B283BB196E2B90DC452C485CCF725FD59FB657089436224` |
| SSDEEP | `3072:DH213XOxs1IjMPi1orQe8hcHo3d4FOyGyXwJPC0L0hbhQarqcUlgTGJJ0Laul7fy:4KsBP7QFhZmOTxCk0hh3iJSHlflORMs` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_009_0c62a122
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c62a122eba57c96a909e337501955b1bb2705c3ba56a6ef1d9b75f090404a34"
    family = "AsyncRAT"
    file_name = "SKJG09876545678900.js"
    file_type = "js"
    first_seen = "2026-07-07 03:05:03"
  condition:
    hash.sha256(0, filesize) == "0c62a122eba57c96a909e337501955b1bb2705c3ba56a6ef1d9b75f090404a34"
}
```

### Sample 10: `80789973e5d19076`

| Field | Value |
|---|---|
| SHA-256 | `80789973e5d190760951dd7405369778d02644451b4888b4c45517dc5c0a75c0` |
| Family label | `AsyncRAT` |
| File name | `HGF09876543456789000.js` |
| File type | `js` |
| First seen | `2026-07-07 03:04:29` |
| Reporter | `nat` |
| Tags | `AsyncRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0013532339b5c49e54d0b403dc4be69` |
| SHA-1 | `c4cd5d816b9d84afadc6277258da2b6a5a2c5794` |
| SHA-256 | `80789973e5d190760951dd7405369778d02644451b4888b4c45517dc5c0a75c0` |
| SHA3-384 | `25edecc82ffdd83838834e88b93b630af666055fe73c26dda557459fa35dd3eb20d313bfa0dc75dec45712804bf37709` |
| TLSH | `T1E764BF492EC1B6729E4AF53F1D3EB19BF33A0C81B254A444F32FF499F866714E226644` |
| SSDEEP | `6144:Bjzy8ZuhTFkwc62ZZp8cH2+P+X+yBA76x0jvARTGWckStgCnrr:B3w496OAcH2hXXBNx0jvARkz` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_010_80789973
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80789973e5d190760951dd7405369778d02644451b4888b4c45517dc5c0a75c0"
    family = "AsyncRAT"
    file_name = "HGF09876543456789000.js"
    file_type = "js"
    first_seen = "2026-07-07 03:04:29"
  condition:
    hash.sha256(0, filesize) == "80789973e5d190760951dd7405369778d02644451b4888b4c45517dc5c0a75c0"
}
```

### Sample 11: `e2142a125e3a4f48`

| Field | Value |
|---|---|
| SHA-256 | `e2142a125e3a4f48394f0fdbb8f8255a17332d6d935c579ea5471cde59a6b40c` |
| Family label | `unknown` |
| File name | `e2142a125e3a4f48394f0fdbb8f8255a17332d6d935c579ea5471cde59a6b40c` |
| File type | `elf` |
| First seen | `2026-07-07 03:01:50` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32e588bcfc8a428a7d5fafd1545d6069` |
| SHA-1 | `149ca363552155d9791e625c0b952c613b0f20a7` |
| SHA-256 | `e2142a125e3a4f48394f0fdbb8f8255a17332d6d935c579ea5471cde59a6b40c` |
| SHA3-384 | `76e66271e31a95e2ed29b87335aaa0dd275dd2f7b455beed13da445ed286962dec652dd8c06131f48bd1e7dde461daf0` |
| TLSH | `T1AE37CF77914338E9E5A98DB4D01025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQi:cqYUQuVDt0TZEp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_e2142a12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2142a125e3a4f48394f0fdbb8f8255a17332d6d935c579ea5471cde59a6b40c"
    family = "unknown"
    file_name = "e2142a125e3a4f48394f0fdbb8f8255a17332d6d935c579ea5471cde59a6b40c"
    file_type = "elf"
    first_seen = "2026-07-07 03:01:50"
  condition:
    hash.sha256(0, filesize) == "e2142a125e3a4f48394f0fdbb8f8255a17332d6d935c579ea5471cde59a6b40c"
}
```

### Sample 12: `72933ef50ec23c6a`

| Field | Value |
|---|---|
| SHA-256 | `72933ef50ec23c6a08d001677636dcf2a4b49fdb82437dccb1c806d147786054` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-07 02:52:16` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1059af699b8fa97a56e4902152f5611f` |
| SHA-1 | `6b0382764f4d6cd36eee184f1105e705ced14c4f` |
| SHA-256 | `72933ef50ec23c6a08d001677636dcf2a4b49fdb82437dccb1c806d147786054` |
| SHA3-384 | `40888587edf162acf618ef27f6fa42774645a77aba35f6ed1eb617daf7d1923eb207bb87305ae61594c35bfe4e823965` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1B2E6338C6AE406FDE6B3C03DDEA20155C179B0655B71CE8FABE8C3A52D2B1C0493D65B` |
| SSDEEP | `393216:T5VXyjtW47A6pmufB6LXMCHWUjX9cuI3/PGTAI:T5d8X7A6LCXMb8XKH/O7` |
| ICON-DHASH | `9878e0e0d8f8f022` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_72933ef5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72933ef50ec23c6a08d001677636dcf2a4b49fdb82437dccb1c806d147786054"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 02:52:16"
  condition:
    hash.sha256(0, filesize) == "72933ef50ec23c6a08d001677636dcf2a4b49fdb82437dccb1c806d147786054"
}
```

### Sample 13: `40d8a88490a6c1a8`

| Field | Value |
|---|---|
| SHA-256 | `40d8a88490a6c1a847de73aaf34d9bf440e98232e6f568bd33ceaf77a0b15a30` |
| Family label | `ValleyRAT` |
| File name | `08b9ae7e5a6abdeb98f18bc1e22b2341.exe` |
| File type | `exe` |
| First seen | `2026-07-07 02:45:33` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08b9ae7e5a6abdeb98f18bc1e22b2341` |
| SHA-1 | `4d2d27b9944a58b5a5be28c8845748db1697870f` |
| SHA-256 | `40d8a88490a6c1a847de73aaf34d9bf440e98232e6f568bd33ceaf77a0b15a30` |
| SHA3-384 | `31770b1d1ad60277c937585d63d4f1ee081343c2ee9f3da9caecc628bf7ccf5ea7fcfc81518373c92fdacd8af25fc5d7` |
| IMPHASH | `f00286a7ad92e4220bda35c68491c0a8` |
| TLSH | `T1A3163ABBB632865CC0CAC5B468978BEA6F217C150CB5030722DE371F6E76A401D7E59E` |
| SSDEEP | `49152:tgxey6WBtMd/zsyKbqe222oTViUE/E7JQhFz7Xfi9NihJwy2bFynuOwmwO4tGTHw:key6WBBbqe0mV/8L7C+HMcFi` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_013_40d8a884
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40d8a88490a6c1a847de73aaf34d9bf440e98232e6f568bd33ceaf77a0b15a30"
    family = "ValleyRAT"
    file_name = "08b9ae7e5a6abdeb98f18bc1e22b2341.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:33"
  condition:
    hash.sha256(0, filesize) == "40d8a88490a6c1a847de73aaf34d9bf440e98232e6f568bd33ceaf77a0b15a30"
}
```

### Sample 14: `1fc8fb8d201439bb`

| Field | Value |
|---|---|
| SHA-256 | `1fc8fb8d201439bb948274e247603eeec57c830e1ba49d05fdb361256103be45` |
| Family label | `RatonRAT` |
| File name | `xeno.exe` |
| File type | `exe` |
| First seen | `2026-07-07 02:45:29` |
| Reporter | `abuse_ch` |
| Tags | `exe, RatonRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f2f615adf21e9c86d63cf4aa25ba1c1` |
| SHA-1 | `e3f112b6ed40a35ebb4e2b19fa4ebecaf23e2b3f` |
| SHA-256 | `1fc8fb8d201439bb948274e247603eeec57c830e1ba49d05fdb361256103be45` |
| SHA3-384 | `542de9df9c817680283c4ca748559be5aff6c50f9daa143a94ed8b0ebae5e4c0f6d9d4c2a762b576bb2d3fad1637626f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17C55DF5C33F98A48F2AF0BF4E8B1851A0771FD579922D76D19A678DE04B1F44EA10B23` |
| SSDEEP | `24576:HBXUXSrtv94TP0lRRkxYcxMNnyFoBOkA6s4iIqu7:tdsclR0BxMsaRw4ou7` |

#### Technical Assessment

- The sample is tracked as `RatonRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RatonRAT_014_1fc8fb8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fc8fb8d201439bb948274e247603eeec57c830e1ba49d05fdb361256103be45"
    family = "RatonRAT"
    file_name = "xeno.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:29"
  condition:
    hash.sha256(0, filesize) == "1fc8fb8d201439bb948274e247603eeec57c830e1ba49d05fdb361256103be45"
}
```

### Sample 15: `6bedbe1c3e8eceb6`

| Field | Value |
|---|---|
| SHA-256 | `6bedbe1c3e8eceb69531c82728290394fabf5475a0a830e807a89ccbcc92bd18` |
| Family label | `RatonRAT` |
| File name | `Delta.289.12323.exe` |
| File type | `exe` |
| First seen | `2026-07-07 02:45:27` |
| Reporter | `abuse_ch` |
| Tags | `exe, RatonRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3317da6ae819a40cb8d980f29e9e7766` |
| SHA-1 | `a4ac78e04f75a1801ae4a2abd5fb342543571aa0` |
| SHA-256 | `6bedbe1c3e8eceb69531c82728290394fabf5475a0a830e807a89ccbcc92bd18` |
| SHA3-384 | `72f1d8a59ffe3cc31cfd616e1a93fff67110fcb7aeaef1c9ca921d5c3d4f1c3ab2215ec21413f96681af758696eedcb7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T170D40204B7FC3615E7BE8B3E59B090440F76B2534A20D21C5D83D4AA1675F82EA64FA7` |
| SSDEEP | `12288:QQQR3374rIkzE7tnXknXQaBFJi4RkTAJ0MK86WoLb66OPfD9piIBIk:SL4kkA7lXkXDDuAOFhWSApia` |

#### Technical Assessment

- The sample is tracked as `RatonRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RatonRAT_015_6bedbe1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bedbe1c3e8eceb69531c82728290394fabf5475a0a830e807a89ccbcc92bd18"
    family = "RatonRAT"
    file_name = "Delta.289.12323.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:27"
  condition:
    hash.sha256(0, filesize) == "6bedbe1c3e8eceb69531c82728290394fabf5475a0a830e807a89ccbcc92bd18"
}
```

### Sample 16: `005945a8e74e5d96`

| Field | Value |
|---|---|
| SHA-256 | `005945a8e74e5d961d46014e3fd9129cbe213cac8de08423624c5d6fdc156614` |
| Family label | `RatonRAT` |
| File name | `045009f3c826acbe3decbd486ff24ec9.exe` |
| File type | `exe` |
| First seen | `2026-07-07 02:45:24` |
| Reporter | `abuse_ch` |
| Tags | `exe, RatonRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `045009f3c826acbe3decbd486ff24ec9` |
| SHA-1 | `759ac3d7f2115b4e85e9a9bfd48b52ebd31b242a` |
| SHA-256 | `005945a8e74e5d961d46014e3fd9129cbe213cac8de08423624c5d6fdc156614` |
| SHA3-384 | `af839f622ab86ed0b1df4173e9beb676fadfea771fd9be24d71c9aed85bd9233c93c912b09628ff162ff666b0b3bc140` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CD934B0473FC2929E3FF8FBD29B524510F72B917AE31D64D498A60980A71B869D20F77` |
| SSDEEP | `1536:Psgaafih7U78PrTsqa4tsi5s7sQI36SbhKp+C+C82v1B:Psgaa6FUYjAX4tnm7sLKSbhKz+Cvv7` |

#### Technical Assessment

- The sample is tracked as `RatonRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RatonRAT_016_005945a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "005945a8e74e5d961d46014e3fd9129cbe213cac8de08423624c5d6fdc156614"
    family = "RatonRAT"
    file_name = "045009f3c826acbe3decbd486ff24ec9.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:24"
  condition:
    hash.sha256(0, filesize) == "005945a8e74e5d961d46014e3fd9129cbe213cac8de08423624c5d6fdc156614"
}
```

### Sample 17: `b8979e31b0e18fd5`

| Field | Value |
|---|---|
| SHA-256 | `b8979e31b0e18fd57d4e0a7512e9e0109d68312fd9a5837d62fcb11ace457c2f` |
| Family label | `ValleyRAT` |
| File name | `b8979e31b0e18fd57d4e0a7512e9e0109d68312fd9a58.exe` |
| File type | `exe` |
| First seen | `2026-07-07 02:45:21` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d024110d1f4fe0b49f380bfd0616235a` |
| SHA-1 | `a4efdf1eb61e282ca28b1e578551b10d7fb2883d` |
| SHA-256 | `b8979e31b0e18fd57d4e0a7512e9e0109d68312fd9a5837d62fcb11ace457c2f` |
| SHA3-384 | `1f00bf2d382aee8125c9b9b9ecf124a08dbba808d4bab45446a838ad1762966d389752310414a0931794718c6e2ae25b` |
| IMPHASH | `d22381cfae0e69f47071aad66e3887af` |
| TLSH | `T19646AE46AAAE10E8DCB6D07DC953891BD7B27C911331D78B0261ABAB6F333514D3E325` |
| SSDEEP | `98304:8y373G3+5cUOJHfWIXFeFLOAkGkzdnEVomFHKnPIS:XrNOQIXFeFLOyomFHKnPZ` |
| ICON-DHASH | `787c78fa87f7e6c4` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_017_b8979e31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8979e31b0e18fd57d4e0a7512e9e0109d68312fd9a5837d62fcb11ace457c2f"
    family = "ValleyRAT"
    file_name = "b8979e31b0e18fd57d4e0a7512e9e0109d68312fd9a58.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:21"
  condition:
    hash.sha256(0, filesize) == "b8979e31b0e18fd57d4e0a7512e9e0109d68312fd9a5837d62fcb11ace457c2f"
}
```

### Sample 18: `b4fdd082603796a0`

| Field | Value |
|---|---|
| SHA-256 | `b4fdd082603796a0bd9a765ca326fe643e8b4bc62e5fa9d472cadb221c509711` |
| Family label | `RemcosRAT` |
| File name | `106264855SPECIFICATION.js` |
| File type | `js` |
| First seen | `2026-07-07 02:45:18` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a859ffdcd82ad30b16a1a4958f6a875` |
| SHA-1 | `91e3d273db632961f9818c5a8bf5c96e95950f33` |
| SHA-256 | `b4fdd082603796a0bd9a765ca326fe643e8b4bc62e5fa9d472cadb221c509711` |
| SHA3-384 | `e6b2450ded763f0d7a01e240e7e5cccdb17ec93a95c58f8ddeda8426ff8a93c609bbf52b814e7f0a7775ed4dc7aa579a` |
| TLSH | `T1C7E502014AC43FB5CF9C5A1950FE160EE3A04D8A511AB58AFB63FD4AFFB7A04411B2D9` |
| SSDEEP | `49152:zZPHeyc0xfT98EUzFXMCemi/0hms2p9N5khwJ:D` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_018_b4fdd082
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4fdd082603796a0bd9a765ca326fe643e8b4bc62e5fa9d472cadb221c509711"
    family = "RemcosRAT"
    file_name = "106264855SPECIFICATION.js"
    file_type = "js"
    first_seen = "2026-07-07 02:45:18"
  condition:
    hash.sha256(0, filesize) == "b4fdd082603796a0bd9a765ca326fe643e8b4bc62e5fa9d472cadb221c509711"
}
```

### Sample 19: `d5cc60331e5cdf13`

| Field | Value |
|---|---|
| SHA-256 | `d5cc60331e5cdf13972eb713eec4b1dee1c24d2bb3bd4140e2e7ae9c52eb8c38` |
| Family label | `QuasarRAT` |
| File name | `Client-built.exe` |
| File type | `exe` |
| First seen | `2026-07-07 02:45:15` |
| Reporter | `abuse_ch` |
| Tags | `exe, QuasarRAT, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7fa31bdc4fa74aed393948ed15c1ded` |
| SHA-1 | `aa40ceddd6e59ef412b40562940600e8feab40d6` |
| SHA-256 | `d5cc60331e5cdf13972eb713eec4b1dee1c24d2bb3bd4140e2e7ae9c52eb8c38` |
| SHA3-384 | `11df132294a6e0d1e4bb53517b47a272931aefb4fe2f07957ee9a73557f4d05ea37f5d72093a422be8bd31d16ee9abff` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T103E56B143BF85E27E1BBE277E5B0041267F0FC1AB363EB0B6581677A1C53B5098426A7` |
| SSDEEP | `49152:ivIt62XlaSFNWPjljiFa2RoUYI1tRJ6IbR3LoGdbFTHHB72eh2NT:ivE62XlaSFNWPjljiFXRoUYI1tRJ6i` |
| ICON-DHASH | `f280d496369cc0e0` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_019_d5cc6033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5cc60331e5cdf13972eb713eec4b1dee1c24d2bb3bd4140e2e7ae9c52eb8c38"
    family = "QuasarRAT"
    file_name = "Client-built.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:15"
  condition:
    hash.sha256(0, filesize) == "d5cc60331e5cdf13972eb713eec4b1dee1c24d2bb3bd4140e2e7ae9c52eb8c38"
}
```

### Sample 20: `cbb753220731503e`

| Field | Value |
|---|---|
| SHA-256 | `cbb753220731503e7974588a48305dcf19d8528d7299f695e05211f845a8f720` |
| Family label | `RedLineStealer` |
| File name | `0cba9117934ea7e8457efacdd87beff5.exe` |
| File type | `exe` |
| First seen | `2026-07-07 02:45:12` |
| Reporter | `abuse_ch` |
| Tags | `exe, RedLineStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cba9117934ea7e8457efacdd87beff5` |
| SHA-1 | `2eaae56c9b7bfee7ab671da182a3f0eece3a3a84` |
| SHA-256 | `cbb753220731503e7974588a48305dcf19d8528d7299f695e05211f845a8f720` |
| SHA3-384 | `7ced060039da94fac1af2632f6105005aa0717c80efe7433d68b67c18d891344493e73dbbb89dabd7bb1cc4444973380` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D7051220578CC461D6A095701EF9F33542BA7D1DF071DB26CFDCBDAB3B22606A450BAA` |
| SSDEEP | `12288:/aRSqhtK4a/bTSVG0MLKmyO5y0zE36jghQASjMHVZwgQy+LWAn6UIn99Lc4:/aQqh0Ykyqy0zShNf1g9In99Q4` |
| ICON-DHASH | `f2ceaeaeb2968eaa` |

#### Technical Assessment

- The sample is tracked as `RedLineStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RedLineStealer_020_cbb75322
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbb753220731503e7974588a48305dcf19d8528d7299f695e05211f845a8f720"
    family = "RedLineStealer"
    file_name = "0cba9117934ea7e8457efacdd87beff5.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:12"
  condition:
    hash.sha256(0, filesize) == "cbb753220731503e7974588a48305dcf19d8528d7299f695e05211f845a8f720"
}
```

### Sample 21: `5f6e4a8d17a5d15c`

| Field | Value |
|---|---|
| SHA-256 | `5f6e4a8d17a5d15cc001300ad8373515b8f548c0ab129fe67ef597a59467423f` |
| Family label | `AsyncRAT` |
| File name | `5f6e4a8d17a5d15cc001300ad8373515b8f548c0ab129.exe` |
| File type | `exe` |
| First seen | `2026-07-07 02:45:08` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b006f81b6a3ac28939054c3aac4d4426` |
| SHA-1 | `73252df38b2d70138fe4fba069f46cd9aef601a8` |
| SHA-256 | `5f6e4a8d17a5d15cc001300ad8373515b8f548c0ab129fe67ef597a59467423f` |
| SHA3-384 | `a244e2520ede44a20c1c7d29fb97ca12e0136ebd12cd787b3da8e60ab0c7ffcbbb9442dc91a4cb9452b17a06c0a52cd9` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16953F7013BE8812AF3BE8F7469F262854AF9F4AB2D12D55D0C8514DF0532B829951BFF` |
| SSDEEP | `1536:xW8+SnDy2k6hwvKufUYFTCApXwbrAPKn0+rQTGdx:xWBSDy2k6SKufUYFWA1wbrn3Gux` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_021_5f6e4a8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f6e4a8d17a5d15cc001300ad8373515b8f548c0ab129fe67ef597a59467423f"
    family = "AsyncRAT"
    file_name = "5f6e4a8d17a5d15cc001300ad8373515b8f548c0ab129.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:08"
  condition:
    hash.sha256(0, filesize) == "5f6e4a8d17a5d15cc001300ad8373515b8f548c0ab129fe67ef597a59467423f"
}
```

### Sample 22: `c6ad18d01c5ee9f6`

| Field | Value |
|---|---|
| SHA-256 | `c6ad18d01c5ee9f6edbb8c79f8ff8786762eb63d1b341997eb39f51a67f4ae7b` |
| Family label | `NanoCore` |
| File name | `1028037eae53b90c967d82953f20d8e6.exe` |
| File type | `exe` |
| First seen | `2026-07-07 02:45:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1028037eae53b90c967d82953f20d8e6` |
| SHA-1 | `afcc57899b40d9522b46f54a198946c023f32d1f` |
| SHA-256 | `c6ad18d01c5ee9f6edbb8c79f8ff8786762eb63d1b341997eb39f51a67f4ae7b` |
| SHA3-384 | `17c4d5cb13d22552f89e2fa5fad6ed2ed4d361fbd7ae7852a558cc148f2aac3c428247acfdd92cde4766b27180801ed8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1ED74E0963BEA092FE29F817E601242534378C2E398C3F3DE19D455B69E2A7E507871D3` |
| SSDEEP | `6144:gLV6Bta6dtJmakIM5ilvLqygbJLYeDc05slm/cq7FmG0PStR/N4mG/6SyORjbH5q:gLV6BtpmkRlveFzNWlC7ZG/nQ` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_022_c6ad18d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6ad18d01c5ee9f6edbb8c79f8ff8786762eb63d1b341997eb39f51a67f4ae7b"
    family = "NanoCore"
    file_name = "1028037eae53b90c967d82953f20d8e6.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:05"
  condition:
    hash.sha256(0, filesize) == "c6ad18d01c5ee9f6edbb8c79f8ff8786762eb63d1b341997eb39f51a67f4ae7b"
}
```

### Sample 23: `f2f077f3c330a5a4`

| Field | Value |
|---|---|
| SHA-256 | `f2f077f3c330a5a4a0732e692d7ae938db5897f6b97193db9c85de91fbf34ced` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-07 02:37:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b91f87369c7ebf5e8342b5bc45a0021` |
| SHA-1 | `30496f45cc5b701c8c98aec37a7a3a8eb980f042` |
| SHA-256 | `f2f077f3c330a5a4a0732e692d7ae938db5897f6b97193db9c85de91fbf34ced` |
| SHA3-384 | `79033f4df849bb60103955ca6ebd051883372f417b1cb06d9c597b96603e1956bd97134edb381a6eb41ae02df25d6593` |
| TLSH | `T16D137D6956857C24AE99883B1C7E2F0CB9A983E1310451DDBFCB3CF58C19ADCD219B1D` |
| SSDEEP | `768:E+h9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnp:E+Kcy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_f2f077f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2f077f3c330a5a4a0732e692d7ae938db5897f6b97193db9c85de91fbf34ced"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-07 02:37:59"
  condition:
    hash.sha256(0, filesize) == "f2f077f3c330a5a4a0732e692d7ae938db5897f6b97193db9c85de91fbf34ced"
}
```

### Sample 24: `9d50989f6ff8bb05`

| Field | Value |
|---|---|
| SHA-256 | `9d50989f6ff8bb05cf9839d2d888e6e90a8e137b2670140efea5ff5398230e83` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-07 02:37:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `514f626b4f5eadcc15c9121b079c2d0e` |
| SHA-1 | `a982ab74aa1670caa23f9d5ac431f3fe51e8a9f2` |
| SHA-256 | `9d50989f6ff8bb05cf9839d2d888e6e90a8e137b2670140efea5ff5398230e83` |
| SHA3-384 | `d93743c4a9077b0a747b2108a2169c2ba6ef904d2e350c3b4bf7a0036fe044e88d554a148989377327f10c409ec46c15` |
| TLSH | `T1F3430893FD9246AAC5C027B6776F968A33A267A5C2DF3313C8140B11378A90F4E77A51` |
| TELFHASH | `t1a1f0c084fe764f1589e1a574dcbc0360e9436126a5625b20df52cad0883e149d30cd1d` |
| SSDEEP | `1536:y7Xww9m9AtkxttbuE1G/9HFeBzoaJlCQ:y7XN9m2tkYDCBzoS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_9d50989f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d50989f6ff8bb05cf9839d2d888e6e90a8e137b2670140efea5ff5398230e83"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-07 02:37:46"
  condition:
    hash.sha256(0, filesize) == "9d50989f6ff8bb05cf9839d2d888e6e90a8e137b2670140efea5ff5398230e83"
}
```

### Sample 25: `3f7309f58c8e64d4`

| Field | Value |
|---|---|
| SHA-256 | `3f7309f58c8e64d475ecfe5b81cc11ea804f39498f9956df35dec7ecdb508c96` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-07 02:36:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `986c2788f21742ed2c20619056d0eaec` |
| SHA-1 | `bb5712e4684e3320dbdb1ae02c81bd4ce3b3500b` |
| SHA-256 | `3f7309f58c8e64d475ecfe5b81cc11ea804f39498f9956df35dec7ecdb508c96` |
| SHA3-384 | `8b797496b46361ebe5ca1de1cc154f4e1d3a21353aacac8438a5faf97ec0a47b53320a98f02c77a535c2e5e38708a842` |
| TLSH | `T1E2B2E13534352AB1DF73443BECAAC54837A242BEF9B8311912D44AB4A2C615F53398F7` |
| SSDEEP | `384:q1GmQzxUvHl/8CEvsQumGJ3QQ0R1u3xV5F2o84jGdhRM6lTyAKfgICj5Eur6hymC:YRmsdlZPX5F2o8zo6lOLCFF6s3UozN7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_3f7309f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f7309f58c8e64d475ecfe5b81cc11ea804f39498f9956df35dec7ecdb508c96"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-07 02:36:57"
  condition:
    hash.sha256(0, filesize) == "3f7309f58c8e64d475ecfe5b81cc11ea804f39498f9956df35dec7ecdb508c96"
}
```

### Sample 26: `1ba2b89f9601d192`

| Field | Value |
|---|---|
| SHA-256 | `1ba2b89f9601d1923c88bcb1643ab6b4c10a83dbae02975dbfafe76ebaac0431` |
| Family label | `BlackMatter` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-07 02:10:11` |
| Reporter | `Bitsight` |
| Tags | `BlackMatter, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0257d8caf8776762f5e36d49f7ae563c` |
| SHA-1 | `ace20f30fc820391f1827baffd1c4fb435ff8137` |
| SHA-256 | `1ba2b89f9601d1923c88bcb1643ab6b4c10a83dbae02975dbfafe76ebaac0431` |
| SHA3-384 | `7ba37702e2eb5baa1b353827bef15e34abd0d38e81ae826f358bdce8ddaf8988e8299f7895bb2b7a6419347f5b7d1c76` |
| IMPHASH | `41fb8cb2943df6de998b35a9d28668e8` |
| TLSH | `T103F37D21F213D0B3D87718F12736B5B2F39E4D6C19996847EAE80F99BCA48236F05593` |
| SSDEEP | `3072:16glyuxE4GsUPnliByocWepsrddeEflPgpJhPMe:16gDBGpvEByocWeAwqg32e` |
| ICON-DHASH | `00231d5101010100` |

#### Technical Assessment

- The sample is tracked as `BlackMatter` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BlackMatter_026_1ba2b89f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ba2b89f9601d1923c88bcb1643ab6b4c10a83dbae02975dbfafe76ebaac0431"
    family = "BlackMatter"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 02:10:11"
  condition:
    hash.sha256(0, filesize) == "1ba2b89f9601d1923c88bcb1643ab6b4c10a83dbae02975dbfafe76ebaac0431"
}
```

### Sample 27: `e1e3829d5bdae031`

| Field | Value |
|---|---|
| SHA-256 | `e1e3829d5bdae0315b4fbe9e296dd642514570f5f07a86c0aacc86fd121aa36f` |
| Family label | `Mirai` |
| File name | `bin.sh` |
| File type | `elf` |
| First seen | `2026-07-07 01:59:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b87667dda9fdaeb8eb33eb8937a1d14e` |
| SHA-1 | `20f574ae425122660fcb1435366b5c5ba2a03d7c` |
| SHA-256 | `e1e3829d5bdae0315b4fbe9e296dd642514570f5f07a86c0aacc86fd121aa36f` |
| SHA3-384 | `832ebbe79045fd23cf6c84b45ae0bacaba869fe976c9a9c792dee1a789f9d9e85d08a913b91d59e4b3a86ada4068089f` |
| TLSH | `T1E763F786BC918A9655C423BBBA7D81CE331337B8D2DF7103DD151F18B6CA84F0E6A952` |
| SSDEEP | `1536:CMn12A//SrRftY97WARbIcbboW+zLsYtJ913DhrPDysX+4if3LEVa:T2s/ITo7WCkybotgsJ913DhrbW4UYQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_e1e3829d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1e3829d5bdae0315b4fbe9e296dd642514570f5f07a86c0aacc86fd121aa36f"
    family = "Mirai"
    file_name = "bin.sh"
    file_type = "elf"
    first_seen = "2026-07-07 01:59:55"
  condition:
    hash.sha256(0, filesize) == "e1e3829d5bdae0315b4fbe9e296dd642514570f5f07a86c0aacc86fd121aa36f"
}
```

### Sample 28: `393683cb84df747b`

| Field | Value |
|---|---|
| SHA-256 | `393683cb84df747b671414d49ac04eef066618216c26927b4ad4532ba2d9b2ad` |
| Family label | `unknown` |
| File name | `393683cb84df747b671414d49ac04eef066618216c26927b4ad4532ba2d9b2ad` |
| File type | `elf` |
| First seen | `2026-07-07 01:22:52` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfaddea4e002e0d6b63ffea05776c423` |
| SHA-1 | `9e7b847775183746fd50d31f08ed801bfa5ba2d0` |
| SHA-256 | `393683cb84df747b671414d49ac04eef066618216c26927b4ad4532ba2d9b2ad` |
| SHA3-384 | `2bd1684077b76a33fced175c8077733a36f8f975f637e6bcb816aab056430a24c5ea037bed082e2bdc9df6eda519300a` |
| TLSH | `T1AD9533EF28B91D21FE90E2F15E23D00E99586E77C774EC3AB5D4C684092CD86BB1095B` |
| SSDEEP | `24576:SYEcSZaVBOWjhINd6Nkdj5H/HNtJ8C4gtt+EaARr7ymUcwCtAmOka21yqP5K9ekH:ShdF6+Nd6KPNT1tdjRCpoymZoqcRxL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_393683cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "393683cb84df747b671414d49ac04eef066618216c26927b4ad4532ba2d9b2ad"
    family = "unknown"
    file_name = "393683cb84df747b671414d49ac04eef066618216c26927b4ad4532ba2d9b2ad"
    file_type = "elf"
    first_seen = "2026-07-07 01:22:52"
  condition:
    hash.sha256(0, filesize) == "393683cb84df747b671414d49ac04eef066618216c26927b4ad4532ba2d9b2ad"
}
```

### Sample 29: `c390b9e50b5aa198`

| Field | Value |
|---|---|
| SHA-256 | `c390b9e50b5aa198e6985219929ee564fd019a1d8a54c069ecf3df161f35f624` |
| Family label | `unknown` |
| File name | `c390b9e50b5aa198e6985219929ee564fd019a1d8a54c069ecf3df161f35f624` |
| File type | `unknown` |
| First seen | `2026-07-07 01:17:25` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ad6554d33ad9d33604ec7288be1be1d` |
| SHA-256 | `c390b9e50b5aa198e6985219929ee564fd019a1d8a54c069ecf3df161f35f624` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_c390b9e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c390b9e50b5aa198e6985219929ee564fd019a1d8a54c069ecf3df161f35f624"
    family = "unknown"
    file_name = "c390b9e50b5aa198e6985219929ee564fd019a1d8a54c069ecf3df161f35f624"
    file_type = "unknown"
    first_seen = "2026-07-07 01:17:25"
  condition:
    hash.sha256(0, filesize) == "c390b9e50b5aa198e6985219929ee564fd019a1d8a54c069ecf3df161f35f624"
}
```

### Sample 30: `8770a3fead8861b8`

| Field | Value |
|---|---|
| SHA-256 | `8770a3fead8861b818e32c832fc3411699dbb35e2f178ca0be6b2d7f9bc48140` |
| Family label | `unknown` |
| File name | `8770a3fead8861b818e32c832fc3411699dbb35e2f178ca0be6b2d7f9bc48140` |
| File type | `sh` |
| First seen | `2026-07-07 01:11:30` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fe73dd33321c953ea6317cddb51c0d7` |
| SHA-1 | `4279782257256f89a2f00d43fca839b79ba58e22` |
| SHA-256 | `8770a3fead8861b818e32c832fc3411699dbb35e2f178ca0be6b2d7f9bc48140` |
| SHA3-384 | `2e416450fd736d1da38c8be2dfc174a711bbb4eeef3c1f8191b895ee52855ba71725d2a75dfe784af5846c2d3e89a8b3` |
| TLSH | `T1E141BDCA7AA3D97197C7C4391FDAE101E35624430995ADA8B08EBC303F69120FCB1E56` |
| SSDEEP | `48:+VdxxzGG1eCFeZdzVKN5Q1f/neHuDmmlBFInKIYgQAul4N7vGxQ:MdnIu2mQlGaL2nKI3QaTGC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_8770a3fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8770a3fead8861b818e32c832fc3411699dbb35e2f178ca0be6b2d7f9bc48140"
    family = "unknown"
    file_name = "8770a3fead8861b818e32c832fc3411699dbb35e2f178ca0be6b2d7f9bc48140"
    file_type = "sh"
    first_seen = "2026-07-07 01:11:30"
  condition:
    hash.sha256(0, filesize) == "8770a3fead8861b818e32c832fc3411699dbb35e2f178ca0be6b2d7f9bc48140"
}
```

### Sample 31: `4a8aa017e3bda8b3`

| Field | Value |
|---|---|
| SHA-256 | `4a8aa017e3bda8b370335b21c58a8918c5ea163e8b4364837fb15fccdbd15e02` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-07 01:10:10` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdbb0e5c27d6debc8bedaa701f9de00d` |
| SHA-1 | `6b488a3e731dd3fea573c5313d815e28d33cdabf` |
| SHA-256 | `4a8aa017e3bda8b370335b21c58a8918c5ea163e8b4364837fb15fccdbd15e02` |
| SHA3-384 | `ba95f6fb3427c7df804117bd3d726ee6885debb3b7dbdbd39d84a33c5a582325f0b80a1759ff01e1423356a72d446fa2` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T1EE624C0BB8818035EBE14474827F526645BDACB623D4F9CBF7E0648A5EB46E1F43116F` |
| SSDEEP | `192:AWisGnjXgjk8LMRAW4NJTMRJFeIFFBKUSf/zwsd1gJxTmv8U9cthk9ik:AvSMqAUl/Zyav8U9cqX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_4a8aa017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a8aa017e3bda8b370335b21c58a8918c5ea163e8b4364837fb15fccdbd15e02"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 01:10:10"
  condition:
    hash.sha256(0, filesize) == "4a8aa017e3bda8b370335b21c58a8918c5ea163e8b4364837fb15fccdbd15e02"
}
```

### Sample 32: `d117ee4a24495962`

| Field | Value |
|---|---|
| SHA-256 | `d117ee4a244959625a761696a9c719d161e6b11a7e880ada14ec8dde3f88d0ef` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-07 01:10:07` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `504dabe5363684f91a38690962c97a30` |
| SHA-1 | `707b490de6c0571e5d2867788e9bf8743549bac9` |
| SHA-256 | `d117ee4a244959625a761696a9c719d161e6b11a7e880ada14ec8dde3f88d0ef` |
| SHA3-384 | `900d134dcae68d0e86f44f5caacb51192c12e9915f9fc1caffdb5cc6ffd811b36cc4f7a5f1dca736a4dbaeb318f34b3f` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T1EE624C0BB4808035EBE14474827F526645BDACB623D4F9CBF7E0648A5EB46E1F43116F` |
| SSDEEP | `192:AWzsGnjXgjk8LMRAW4NJTMRJFeIFFBKUSf/zwsd1gJxTmv8U9cthq9ik:AeSMqAUl/Zyav8U9cMX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_d117ee4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d117ee4a244959625a761696a9c719d161e6b11a7e880ada14ec8dde3f88d0ef"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 01:10:07"
  condition:
    hash.sha256(0, filesize) == "d117ee4a244959625a761696a9c719d161e6b11a7e880ada14ec8dde3f88d0ef"
}
```

### Sample 33: `3aac5e3fce6038cf`

| Field | Value |
|---|---|
| SHA-256 | `3aac5e3fce6038cf911ac31dd206a1109c78177d26b382412797d9da9840af53` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-07 01:08:58` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c3ce7d856f41f8a795945419b3ca5d6` |
| SHA-1 | `63bf9118c972884f7ff27ee153d588e171f36460` |
| SHA-256 | `3aac5e3fce6038cf911ac31dd206a1109c78177d26b382412797d9da9840af53` |
| SHA3-384 | `da04cb3c05a80511fd22b99dcaaf36d4682f1b14ee3084171c4367509531beb7a2af03b3e9e9a3af4d46d1ba0822f26e` |
| IMPHASH | `fd58a0a623207f17310b91d0844de66f` |
| TLSH | `T19EE53343BF10E912C2952E7599F1C3E92B66FD4C5B56C70B30C2CE1BACEB2C64C26599` |
| SSDEEP | `49152:5GU8RAdxwPCF4yRX7TZeDtih1assueLhvl2JrT8HgZ75rirysoOgc7CydFWKXa0:50edxz46P1Zeqnxliry8gcuyaq` |
| ICON-DHASH | `9010f0e869694c10` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_3aac5e3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3aac5e3fce6038cf911ac31dd206a1109c78177d26b382412797d9da9840af53"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 01:08:58"
  condition:
    hash.sha256(0, filesize) == "3aac5e3fce6038cf911ac31dd206a1109c78177d26b382412797d9da9840af53"
}
```

### Sample 34: `dcd93e03208c3f5d`

| Field | Value |
|---|---|
| SHA-256 | `dcd93e03208c3f5d2f946023e2bd0e13c58ba275e71208921e62d2ddc03762b4` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-07 01:05:01` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e5837abe7607a39fadbdbfd36c34e8c` |
| SHA-1 | `8fd0c332d03133389c24184c88fc8ba309d83dc9` |
| SHA-256 | `dcd93e03208c3f5d2f946023e2bd0e13c58ba275e71208921e62d2ddc03762b4` |
| SHA3-384 | `317756fbbc5201155f07873be9466dbc3595f4ff4ad202e01e8ad067f306af22919eb56bcc233b81061b20c57cd7efe3` |
| TLSH | `T17AD097A311230134C0A34904F0D2A800BA104FBFAC91C35DBA07DA302F01308F2E23B0` |
| SSDEEP | `6:hTgwKMUAq2wtUTbAulNXYq4HvXDG+NjVsNXYrkJ:VZK3tIPiq4HvXDGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_dcd93e03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcd93e03208c3f5d2f946023e2bd0e13c58ba275e71208921e62d2ddc03762b4"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-07 01:05:01"
  condition:
    hash.sha256(0, filesize) == "dcd93e03208c3f5d2f946023e2bd0e13c58ba275e71208921e62d2ddc03762b4"
}
```

### Sample 35: `e8bc62068f3ec843`

| Field | Value |
|---|---|
| SHA-256 | `e8bc62068f3ec8434e4658afea482cdb340b88ddaae63c28dfcf6140c82620a1` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-07 00:57:38` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73c91e0421b72d506c64e9c5027287c3` |
| SHA-1 | `0675642d872f9511ae7580856091ab43197e4baf` |
| SHA-256 | `e8bc62068f3ec8434e4658afea482cdb340b88ddaae63c28dfcf6140c82620a1` |
| SHA3-384 | `2ef736b43d2dcad4d85b6627429336838c581c18d895b6f3d6b6b5e57fc8fdbf1dad22f1866ddf96e1a6b875df2532a5` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T17C3209197E494331D3A089F85479838B953D5633E7C3E3EBF373965E4A962448840EAF` |
| SSDEEP | `192:HnomWEzBa/Vx+eTRHj5PFJxTEZmFhSac:Hno+w9w2lPFwZ` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_035_e8bc6206
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8bc62068f3ec8434e4658afea482cdb340b88ddaae63c28dfcf6140c82620a1"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 00:57:38"
  condition:
    hash.sha256(0, filesize) == "e8bc62068f3ec8434e4658afea482cdb340b88ddaae63c28dfcf6140c82620a1"
}
```

### Sample 36: `32f4dc44d81286d2`

| Field | Value |
|---|---|
| SHA-256 | `32f4dc44d81286d23683761744153d06c37df34eb6e9c95de020bfc3fccf74fb` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-07 00:52:12` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d031ed9d1e744f1df9e61457beb7620d` |
| SHA-1 | `61b57fafca9d334b89d311331c65423918d0e365` |
| SHA-256 | `32f4dc44d81286d23683761744153d06c37df34eb6e9c95de020bfc3fccf74fb` |
| SHA3-384 | `42b3bdc9d80f730c352f6be16d0064a01da653b523fa1d0d1cabca98f6fd5acfda537c019f6a5e72aa370181067670e5` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C0E6335C8EE02BDDF073417CE9A11253F5FAB0B61B72CB9B976C42A22D471A04D39663` |
| SSDEEP | `393216:TonN5Fg8Ol8zDx2B3geXMCHWUjXHcuI3/PGTAI:TIF2leVgHXMb8X8H/O7` |
| ICON-DHASH | `f0f89ca69ac6f4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_32f4dc44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f4dc44d81286d23683761744153d06c37df34eb6e9c95de020bfc3fccf74fb"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 00:52:12"
  condition:
    hash.sha256(0, filesize) == "32f4dc44d81286d23683761744153d06c37df34eb6e9c95de020bfc3fccf74fb"
}
```

### Sample 37: `4196d8f75e231e00`

| Field | Value |
|---|---|
| SHA-256 | `4196d8f75e231e009033437d53451e3e30a6487f8ead8e411be11a9b3ace682d` |
| Family label | `Mirai` |
| File name | `johenlastgen.sh` |
| File type | `sh` |
| First seen | `2026-07-07 00:50:08` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `140e9ca762cb02c6d41e0f63d61b6292` |
| SHA-1 | `db42adcba39fc6e46eeddb44687d115a24337b4c` |
| SHA-256 | `4196d8f75e231e009033437d53451e3e30a6487f8ead8e411be11a9b3ace682d` |
| SHA3-384 | `112ef1dfc0507eb5a99afcf793bdc6380755ce9d2ec9d2fba285d325e89e8c6307fbfa89d47ab0fe1efc46e0364d6a68` |
| TLSH | `T1B881B38E174357E53E7DDA2279DFC61C728448D984C03F86F2DAFCE14E98CCA2846622` |
| SSDEEP | `48:vJp0aJAAaJs2slaJhoaJWzEaJTGaJM8aJuQaJdOaJCYaJDkaJLIaJ+YaJG4aJcgd:vganaGa8aqEa0afaxaualaOaCa9a9a7d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_4196d8f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4196d8f75e231e009033437d53451e3e30a6487f8ead8e411be11a9b3ace682d"
    family = "Mirai"
    file_name = "johenlastgen.sh"
    file_type = "sh"
    first_seen = "2026-07-07 00:50:08"
  condition:
    hash.sha256(0, filesize) == "4196d8f75e231e009033437d53451e3e30a6487f8ead8e411be11a9b3ace682d"
}
```

### Sample 38: `3afca0f0f28a8e8a`

| Field | Value |
|---|---|
| SHA-256 | `3afca0f0f28a8e8a57ea459ec7bbc8ec03082e8c818b521687c36e9375fef784` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-07 00:27:42` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93ae08f02238e69cb17f93c247b93528` |
| SHA-1 | `e15944099f6fcc275a4d584411e1a1d25f08f90f` |
| SHA-256 | `3afca0f0f28a8e8a57ea459ec7bbc8ec03082e8c818b521687c36e9375fef784` |
| SHA3-384 | `3a8a9986bf3560d43e61716fe2b7478fcaa3cfab762ecf0adf3321d837d0b070f3e0d9b87e6bc0ccd689305a0f023200` |
| IMPHASH | `d9cdc56d00b82d68dd1cc6a7338127bf` |
| TLSH | `T157320729FE490331E3A488F45475439BA53D9623A393E3EBF333964E4D662449840E7F` |
| SSDEEP | `192:SgHvoF2WbrBxl+W4uT+PFJxTEZmFhvGcJb:rvoXf0luT+PFwZe` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_038_3afca0f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3afca0f0f28a8e8a57ea459ec7bbc8ec03082e8c818b521687c36e9375fef784"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 00:27:42"
  condition:
    hash.sha256(0, filesize) == "3afca0f0f28a8e8a57ea459ec7bbc8ec03082e8c818b521687c36e9375fef784"
}
```

### Sample 39: `caccb7aa5c67860a`

| Field | Value |
|---|---|
| SHA-256 | `caccb7aa5c67860ab942576d7466e126eb94c538a91bb4e7d2cdf3eb9992f818` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-06 23:57:32` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `500b3ec4308048b37ce8a66f3614d7c4` |
| SHA-1 | `e48b683ab9577ea681bfd76e363993f94ed10ffe` |
| SHA-256 | `caccb7aa5c67860ab942576d7466e126eb94c538a91bb4e7d2cdf3eb9992f818` |
| SHA3-384 | `da883c0f8feec98b92f4169471281b5aad4df4df92185eb256d888ea00404b31dfbf14ec9a132560032d0c93e5697227` |
| IMPHASH | `d9cdc56d00b82d68dd1cc6a7338127bf` |
| TLSH | `T14232921DAE4B0331EEA049B4E475424AA46C1EE37357EBEBE333D18B49C5E4488C192F` |
| SSDEEP | `192:R0o92WaqBBFQlSHO0UOJu+PFJxTEZmFh3ScP:eobQwu3OJu+PFwZ` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_039_caccb7aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caccb7aa5c67860ab942576d7466e126eb94c538a91bb4e7d2cdf3eb9992f818"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-06 23:57:32"
  condition:
    hash.sha256(0, filesize) == "caccb7aa5c67860ab942576d7466e126eb94c538a91bb4e7d2cdf3eb9992f818"
}
```

### Sample 40: `8cc325c1243fc3fe`

| Field | Value |
|---|---|
| SHA-256 | `8cc325c1243fc3fe72ac7875646dce2aa70973a8b8b6877d9537ea90fb4e1b02` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-06 23:52:21` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb9b66769f3340cc98b290487e64f0e5` |
| SHA-1 | `7ccde4ebbaf92491c8d4deca03f307f3e8a0bc8e` |
| SHA-256 | `8cc325c1243fc3fe72ac7875646dce2aa70973a8b8b6877d9537ea90fb4e1b02` |
| SHA3-384 | `00ad307ce7fdda6b65cf11ac52f8f5822f485bb0ef1674687cbebc6087f9394a535fd111f32a15d2b1a39d2ecc05745b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1A6E6335CBAD512FEE973413CAEF160D2D465B8B20B71CAC747A893706E573E04938A27` |
| SSDEEP | `393216:SQn6mTGyTk/2v2g9fpV8p22y1Xz6XMCHWUjXtcuI3/PGTAI:SQ6QGKlBP22Xz6XMb8XaH/O7` |
| ICON-DHASH | `70f8f8dccce4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_8cc325c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cc325c1243fc3fe72ac7875646dce2aa70973a8b8b6877d9537ea90fb4e1b02"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-06 23:52:21"
  condition:
    hash.sha256(0, filesize) == "8cc325c1243fc3fe72ac7875646dce2aa70973a8b8b6877d9537ea90fb4e1b02"
}
```

### Sample 41: `795dd9b56b65ddab`

| Field | Value |
|---|---|
| SHA-256 | `795dd9b56b65ddab01a5ff024232d4b94aad299ccdfa0da940a9804f1a6bcbb5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-06 23:48:08` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b49d3c1193ac5e850d478d8aa3ec833b` |
| SHA-1 | `97bd303bc315b49252bc2e90592963ab335f4ea2` |
| SHA-256 | `795dd9b56b65ddab01a5ff024232d4b94aad299ccdfa0da940a9804f1a6bcbb5` |
| SHA3-384 | `a26ef68aa47874d515613e5cf6fdb020f9a12580a8668cc9d16122d05277a852863ff7fef06e899249e0117840c4687b` |
| IMPHASH | `5a08440e22a99b9fda864d620400de65` |
| TLSH | `T146B5024EEB8A07F9C93D80B850219252B7C1BD178F10EEAF36552C666E67DE85F39700` |
| SSDEEP | `49152:EhAzoqxbxPRu6XXwM7g5r+4UYlGfkxiA9nKLnqKlEsez3CGNJlk6r12Q:Jj4U4Gfkkxq2Ep+k12` |
| ICON-DHASH | `f0f89a9a9adcf830` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_795dd9b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "795dd9b56b65ddab01a5ff024232d4b94aad299ccdfa0da940a9804f1a6bcbb5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-06 23:48:08"
  condition:
    hash.sha256(0, filesize) == "795dd9b56b65ddab01a5ff024232d4b94aad299ccdfa0da940a9804f1a6bcbb5"
}
```

### Sample 42: `e3070290906a9eda`

| Field | Value |
|---|---|
| SHA-256 | `e3070290906a9eda5855e73545e4a349e3db06a6be3479e46ec19b26dd073c33` |
| Family label | `AgentTesla` |
| File name | `Muestra y especificaciones del producto.exe` |
| File type | `exe` |
| First seen | `2026-07-06 23:41:25` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e97a23b000d8b8955f1fdbf1d7576675` |
| SHA-1 | `7c9000955642ce7a1f2aa06bc053ad4aa9a8e461` |
| SHA-256 | `e3070290906a9eda5855e73545e4a349e3db06a6be3479e46ec19b26dd073c33` |
| SHA3-384 | `140a0b9a4ae6bcec32de06da10eee8a51750b69d7301f17d2240d251d01a6477bbd26cac49f2405eaefebd4451d704fc` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F93501446B5CDE02C1AA177464B4E2380B786E5AF910E3171FD4BDEB7DBBB128C1528B` |
| SSDEEP | `24576:PAfvV0LAfT29SgkZFtcopU74g4aT2sJN6Nsslyv:PAfN0LAr29bklcoDXTsJNwsB` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_042_e3070290
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3070290906a9eda5855e73545e4a349e3db06a6be3479e46ec19b26dd073c33"
    family = "AgentTesla"
    file_name = "Muestra y especificaciones del producto.exe"
    file_type = "exe"
    first_seen = "2026-07-06 23:41:25"
  condition:
    hash.sha256(0, filesize) == "e3070290906a9eda5855e73545e4a349e3db06a6be3479e46ec19b26dd073c33"
}
```

### Sample 43: `a7365f1b0defac95`

| Field | Value |
|---|---|
| SHA-256 | `a7365f1b0defac950f0d60df3b1685f1e2f0d5d75f328a01c1cfaaa71f0690c4` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-06 23:39:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55130c7671b3a9ac54ca79fb7ec489ba` |
| SHA-1 | `c5fad4d6d6c06082f9eb950268df55b90c76ce8e` |
| SHA-256 | `a7365f1b0defac950f0d60df3b1685f1e2f0d5d75f328a01c1cfaaa71f0690c4` |
| SHA3-384 | `105739f8e7f62d8dae26a6683f1c49b0d61d19099d0c8b69a37b41af57e847502fab5ba899521bcc9ac65744a026de42` |
| TLSH | `T187D097B76133027420B60808F1D2B040B421E7BE0C81C82AFE0B38722F4034AF0C32A1` |
| SSDEEP | `6:hT0omiCOpsrVmIuAulNXYq9DG+NjVsNXYrkJ:VpXCOQVmIuPiq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_a7365f1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7365f1b0defac950f0d60df3b1685f1e2f0d5d75f328a01c1cfaaa71f0690c4"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-06 23:39:49"
  condition:
    hash.sha256(0, filesize) == "a7365f1b0defac950f0d60df3b1685f1e2f0d5d75f328a01c1cfaaa71f0690c4"
}
```

### Sample 44: `ca9c127d65c5e983`

| Field | Value |
|---|---|
| SHA-256 | `ca9c127d65c5e9839cf02053e8dffb3869f086bd606badbfbf866e348db12612` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-06 23:30:00` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d8c0025ba0d1ee7a92fdf94be9e6476` |
| SHA-1 | `c3f7d5b3b26dd52d238c215f561736e0e3c89c54` |
| SHA-256 | `ca9c127d65c5e9839cf02053e8dffb3869f086bd606badbfbf866e348db12612` |
| SHA3-384 | `395556367152b7d435d9b8e8eb1ec9edf98415c884ab19203d87855c0e7469cb2a187bd3f4fb43f707bd897f702747fd` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T15E32901E2E4B0332DE5049B4E471424A552C1EE37347EBEBE633D6DB4AD6E4484C1AAF` |
| SSDEEP | `192:yoTW/S5BQWxSHO865hyPFJxTEZmFhquc:yoCWsufjyPFwZ` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_044_ca9c127d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca9c127d65c5e9839cf02053e8dffb3869f086bd606badbfbf866e348db12612"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-06 23:30:00"
  condition:
    hash.sha256(0, filesize) == "ca9c127d65c5e9839cf02053e8dffb3869f086bd606badbfbf866e348db12612"
}
```

### Sample 45: `b2609edca5ece9fa`

| Field | Value |
|---|---|
| SHA-256 | `b2609edca5ece9fa595ae63c619ea84f966280e1c831fbee0e8be4fca20d801a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-06 22:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f087b8b69ef7340a7df9330190a360c` |
| SHA-1 | `9db6835f11acc54381d8b7258efb748f4bfa3d00` |
| SHA-256 | `b2609edca5ece9fa595ae63c619ea84f966280e1c831fbee0e8be4fca20d801a` |
| SHA3-384 | `8f7dc892e5322584bd1f1755c41aee405f80e022110a140c9365bef04eab5f384c1c6004c438e04aeaae0941e08bf2c9` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T188E6330C6AD415FEFE63903C9EE299E4E47874B40BB2CA8B075887E4EC531D4993971B` |
| SSDEEP | `393216:imsW1iwhmr5jvXMCHWUjXucuI3/PGTAI:ic1iwhmrVXMb8XDH/O7` |
| ICON-DHASH | `3371e4d6a2e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_b2609edc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2609edca5ece9fa595ae63c619ea84f966280e1c831fbee0e8be4fca20d801a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-06 22:52:11"
  condition:
    hash.sha256(0, filesize) == "b2609edca5ece9fa595ae63c619ea84f966280e1c831fbee0e8be4fca20d801a"
}
```

### Sample 46: `1fc2619aa6e2dec3`

| Field | Value |
|---|---|
| SHA-256 | `1fc2619aa6e2dec3609bb34769017ec200f01b9d2be51a6e3a4c1dae5a148019` |
| Family label | `Mirai` |
| File name | `tarm7` |
| File type | `elf` |
| First seen | `2026-07-06 22:41:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edc8dc4c24fffc7eb3c1b24e28588625` |
| SHA-1 | `869d4c99b5093a4dab74ae1b249ba19e57cc84a5` |
| SHA-256 | `1fc2619aa6e2dec3609bb34769017ec200f01b9d2be51a6e3a4c1dae5a148019` |
| SHA3-384 | `605a0bc163dbbcd326829122d8e3e7a7ab83ae31647e4e3a38cfe9262681379b6d7b32f58d0f576779d112704ad7b702` |
| TLSH | `T14AB31A89B841AB20D2D226BBFE5F014E33534BECD3EA72129D245F6477CB95B0E36605` |
| TELFHASH | `t196e06827efac215867fa801750ae511689f5f2ac2b11180482ac3f995981482f12e805` |
| SSDEEP | `3072:/VVaNIRMt++3jTgvD+On7PNsJzRk2MawOVDoELOBqxdef1nsz:/VEr++3j8vDrP+zRRMawOVDoEiB9Sz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_1fc2619a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fc2619aa6e2dec3609bb34769017ec200f01b9d2be51a6e3a4c1dae5a148019"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-06 22:41:33"
  condition:
    hash.sha256(0, filesize) == "1fc2619aa6e2dec3609bb34769017ec200f01b9d2be51a6e3a4c1dae5a148019"
}
```

### Sample 47: `82d1721a528d7030`

| Field | Value |
|---|---|
| SHA-256 | `82d1721a528d70301513d391d0e356a69ebc8af40e64f2546cccfadd08f3f156` |
| Family label | `Mirai` |
| File name | `tmpsl` |
| File type | `elf` |
| First seen | `2026-07-06 22:41:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43341202f687c7d2c07c979b296730d6` |
| SHA-1 | `1fe7fb4922e5206cf1e8ce9524a2c093ca528042` |
| SHA-256 | `82d1721a528d70301513d391d0e356a69ebc8af40e64f2546cccfadd08f3f156` |
| SHA3-384 | `8bcd08734fce5907fc83659746a919276389d56f88f570243dec52ccae2fd106209b19f1a96d8123718a150a2915243f` |
| TLSH | `T16BB3F806BF611FF7E89FDC3746B91B0925AC540A12A87B76B634D428F64B18F49D38B0` |
| SSDEEP | `1536:BFymVVcL1yM89AAkp1R6ErEImQr18NFDXy/NM2ZAFnswo:BQmVVcoStEFDXytens9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_82d1721a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82d1721a528d70301513d391d0e356a69ebc8af40e64f2546cccfadd08f3f156"
    family = "Mirai"
    file_name = "tmpsl"
    file_type = "elf"
    first_seen = "2026-07-06 22:41:32"
  condition:
    hash.sha256(0, filesize) == "82d1721a528d70301513d391d0e356a69ebc8af40e64f2546cccfadd08f3f156"
}
```

### Sample 48: `1a79ab7090db6c42`

| Field | Value |
|---|---|
| SHA-256 | `1a79ab7090db6c42752c45524edae6a9c042afc59d6754748a5dd3e3154a6ad0` |
| Family label | `Mirai` |
| File name | `tarm` |
| File type | `elf` |
| First seen | `2026-07-06 22:41:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b1dbd9ea84e2e5c7124b70581a962c2` |
| SHA-1 | `9daffe61c8d5bf814eb8c14a51583da7f5b89f83` |
| SHA-256 | `1a79ab7090db6c42752c45524edae6a9c042afc59d6754748a5dd3e3154a6ad0` |
| SHA3-384 | `9eb590fb44a7eac0538053773efaa4ee06e048b9f9170f97b52f004665463a88b1f82b3ad0c53cb70818671dbe006448` |
| TLSH | `T1C3932984BC81A622C7C1127BEE5F018D331647E8D2EA3347DD254FA4778A96B0E37B42` |
| TELFHASH | `t15651df1aff641bdd57f68094919ea01a07f9358d171a3c439e2da74f9882782f02d86b` |
| SSDEEP | `1536:+RMo0AsDcBr9s5ZrGAS458T3byOwMSI1pX0qAdJ2ivpj4LCvbzUBVkyi5lnswC:+RMo0AsDcBr9sfGA158T3b0ZI1iq+J2z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_1a79ab70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a79ab7090db6c42752c45524edae6a9c042afc59d6754748a5dd3e3154a6ad0"
    family = "Mirai"
    file_name = "tarm"
    file_type = "elf"
    first_seen = "2026-07-06 22:41:30"
  condition:
    hash.sha256(0, filesize) == "1a79ab7090db6c42752c45524edae6a9c042afc59d6754748a5dd3e3154a6ad0"
}
```

### Sample 49: `938f4f03d862992f`

| Field | Value |
|---|---|
| SHA-256 | `938f4f03d862992f23684eb6f7f50ebdd06a7283f6d4a3b2626ee7610e6a9294` |
| Family label | `Mirai` |
| File name | `tarm5` |
| File type | `elf` |
| First seen | `2026-07-06 22:41:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66f3f3995d8981cd53c62fe6564a27aa` |
| SHA-1 | `85b605fc7d11d40829dfcf9fc3a11bb756a18326` |
| SHA-256 | `938f4f03d862992f23684eb6f7f50ebdd06a7283f6d4a3b2626ee7610e6a9294` |
| SHA3-384 | `3a916e7a2af9db6da503e98c8cfe4b88db79fe3849942b42a98e087de0337c493b0dbbf6040c3e687cffd679cc1ab48f` |
| TLSH | `T1399329C4BC81A622C6C126BBFF5F018D371697D8D2EA3243DD280BA5778A95B0D37B45` |
| TELFHASH | `t11651ff6afb751f9c47eb956482cce00f57f9309e07173ca78a5d6b4f8686146b01e823` |
| SSDEEP | `1536:wFpQHUQ+j+nhLEXIrPMcBCisMKwHDNUGW7UbVWSI1pX0qAvR+dQh398vnU7bDXdy:wFpQ0QpnhLE4zMc/s7wHBUF7UbVzI1i+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_938f4f03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "938f4f03d862992f23684eb6f7f50ebdd06a7283f6d4a3b2626ee7610e6a9294"
    family = "Mirai"
    file_name = "tarm5"
    file_type = "elf"
    first_seen = "2026-07-06 22:41:28"
  condition:
    hash.sha256(0, filesize) == "938f4f03d862992f23684eb6f7f50ebdd06a7283f6d4a3b2626ee7610e6a9294"
}
```

### Sample 50: `ff154b904f5a717d`

| Field | Value |
|---|---|
| SHA-256 | `ff154b904f5a717d7a14eee46fe8439e3c5b68c80f151ce958a64b24884f1c6f` |
| Family label | `Mirai` |
| File name | `tarm6` |
| File type | `elf` |
| First seen | `2026-07-06 22:41:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d18a43b24e5e74427f3e74e8e0d7d09` |
| SHA-1 | `3dbef410627344fcf495142f593f04d9f9617b1e` |
| SHA-256 | `ff154b904f5a717d7a14eee46fe8439e3c5b68c80f151ce958a64b24884f1c6f` |
| SHA3-384 | `e34de9bd96a70ed0b731dbbae1e7ac34867ef8f0e365fc5b3c1b157e8f0b46ae0c942a293c11b2e940a86e00b43f36d9` |
| TLSH | `T1EEA3198AB881A721C2C216BBFE1F018E331357E8D3DE73529D145F64778B96B0E36A15` |
| TELFHASH | `t12ae0c22bff27578993e71041406c75134bdcb29d5704352396b96f0b0a41601f01c831` |
| SSDEEP | `3072:R7otYB7iE8MvswjK+O+2t8rgJSaotqpLlSrVR3nst:R7iWpvswjK7CYSawqpG8t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_ff154b90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff154b904f5a717d7a14eee46fe8439e3c5b68c80f151ce958a64b24884f1c6f"
    family = "Mirai"
    file_name = "tarm6"
    file_type = "elf"
    first_seen = "2026-07-06 22:41:27"
  condition:
    hash.sha256(0, filesize) == "ff154b904f5a717d7a14eee46fe8439e3c5b68c80f151ce958a64b24884f1c6f"
}
```

### Sample 51: `a2ff251395e9f34a`

| Field | Value |
|---|---|
| SHA-256 | `a2ff251395e9f34a538c6692e41104eb4646fdaed03c06420bcb348b90162aba` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-06 21:52:13` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3311d2a09a143330380cdd63831f937d` |
| SHA-1 | `e769acd9bb6ee110e42720db83a5fe7df282835f` |
| SHA-256 | `a2ff251395e9f34a538c6692e41104eb4646fdaed03c06420bcb348b90162aba` |
| SHA3-384 | `cd3e0feae287dd1c50ad33ff0eb2b4205b0175f65836a16f32ce62c8227f75b30d8c22792fd5af2cab387d760ba95754` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T19FE6338CEAE011FFD677013CEED15285E6B8B4611775CAEB179483E1AC271E0C93A663` |
| SSDEEP | `393216:6RnX5SFdqHcDWpr1EvXOWNXMCHWUjXPcuI3/PGTAI:6HCdzypr1khXMb8XEH/O7` |
| ICON-DHASH | `d4f87cbc8cc47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_a2ff2513
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2ff251395e9f34a538c6692e41104eb4646fdaed03c06420bcb348b90162aba"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-06 21:52:13"
  condition:
    hash.sha256(0, filesize) == "a2ff251395e9f34a538c6692e41104eb4646fdaed03c06420bcb348b90162aba"
}
```

### Sample 52: `3fcc8667d73fc631`

| Field | Value |
|---|---|
| SHA-256 | `3fcc8667d73fc631206bd32191db3d5ab96667a1fe6e9d67e15892e0f3a9f122` |
| Family label | `unknown` |
| File name | `mwZhV1.ps1` |
| File type | `ps1` |
| First seen | `2026-07-06 21:34:48` |
| Reporter | `Cephal0x` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85a253c748b836b083d3ad2c33c0d6f8` |
| SHA-256 | `3fcc8667d73fc631206bd32191db3d5ab96667a1fe6e9d67e15892e0f3a9f122` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_3fcc8667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fcc8667d73fc631206bd32191db3d5ab96667a1fe6e9d67e15892e0f3a9f122"
    family = "unknown"
    file_name = "mwZhV1.ps1"
    file_type = "ps1"
    first_seen = "2026-07-06 21:34:48"
  condition:
    hash.sha256(0, filesize) == "3fcc8667d73fc631206bd32191db3d5ab96667a1fe6e9d67e15892e0f3a9f122"
}
```

### Sample 53: `97bef8934a732bbf`

| Field | Value |
|---|---|
| SHA-256 | `97bef8934a732bbfd6e8bfb1fa68d42c5604b44beb8c4fc5e34c2020a02b6e28` |
| Family label | `unknown` |
| File name | `o` |
| File type | `unknown` |
| First seen | `2026-07-06 21:07:09` |
| Reporter | `monitorsg` |
| Tags | `KongTuke` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcad94a58a1f2c4f7fd932c722533ff1` |
| SHA-256 | `97bef8934a732bbfd6e8bfb1fa68d42c5604b44beb8c4fc5e34c2020a02b6e28` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_97bef893
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97bef8934a732bbfd6e8bfb1fa68d42c5604b44beb8c4fc5e34c2020a02b6e28"
    family = "unknown"
    file_name = "o"
    file_type = "unknown"
    first_seen = "2026-07-06 21:07:09"
  condition:
    hash.sha256(0, filesize) == "97bef8934a732bbfd6e8bfb1fa68d42c5604b44beb8c4fc5e34c2020a02b6e28"
}
```

### Sample 54: `30c015f869758be9`

| Field | Value |
|---|---|
| SHA-256 | `30c015f869758be97e2d4454830241d67f8f8095e6cf38a60d8372070d0df0ef` |
| Family label | `unknown` |
| File name | `30c015f869758be97e2d4454830241d67f8f8095e6cf38a60d8372070d0df0ef` |
| File type | `unknown` |
| First seen | `2026-07-06 20:31:41` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdc9bfa3cec2e231fbdb84b61a2aba13` |
| SHA-256 | `30c015f869758be97e2d4454830241d67f8f8095e6cf38a60d8372070d0df0ef` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_30c015f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30c015f869758be97e2d4454830241d67f8f8095e6cf38a60d8372070d0df0ef"
    family = "unknown"
    file_name = "30c015f869758be97e2d4454830241d67f8f8095e6cf38a60d8372070d0df0ef"
    file_type = "unknown"
    first_seen = "2026-07-06 20:31:41"
  condition:
    hash.sha256(0, filesize) == "30c015f869758be97e2d4454830241d67f8f8095e6cf38a60d8372070d0df0ef"
}
```

### Sample 55: `5b64550c87fc3a57`

| Field | Value |
|---|---|
| SHA-256 | `5b64550c87fc3a579694133117a265c756fe36cd31de5ef0b87a6f2faae7f791` |
| Family label | `unknown` |
| File name | `5b64550c87fc3a579694133117a265c756fe36cd31de5ef0b87a6f2faae7f791` |
| File type | `sh` |
| First seen | `2026-07-06 20:31:39` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a1798dde285e6d3139cb85808f95658` |
| SHA-1 | `f6593e0832f2ac7bd81a73883fd9a1703fad5349` |
| SHA-256 | `5b64550c87fc3a579694133117a265c756fe36cd31de5ef0b87a6f2faae7f791` |
| SHA3-384 | `da3cff08b832f769f815228eaf94dc42ea28c1e6a391c5761449a5c3c10b0b3fa976b924918b8df8a7a0ae1b9d5eb4d8` |
| TLSH | `T18FB022E822028030B88CC00800A3C030828288A8AC02AEA28A0808A2A208B82B00CB38` |
| SSDEEP | `3:TKH4v9+gqRqFg2TP7XmhYVxQpqquAwWV0v:h82u0D2hqK0PW0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_5b64550c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b64550c87fc3a579694133117a265c756fe36cd31de5ef0b87a6f2faae7f791"
    family = "unknown"
    file_name = "5b64550c87fc3a579694133117a265c756fe36cd31de5ef0b87a6f2faae7f791"
    file_type = "sh"
    first_seen = "2026-07-06 20:31:39"
  condition:
    hash.sha256(0, filesize) == "5b64550c87fc3a579694133117a265c756fe36cd31de5ef0b87a6f2faae7f791"
}
```

### Sample 56: `810d409aef915e09`

| Field | Value |
|---|---|
| SHA-256 | `810d409aef915e09eaa59b1cb8df60559c72b2da1ac0ab14ec875fbe58ac03d9` |
| Family label | `unknown` |
| File name | `810d409aef915e09eaa59b1cb8df60559c72b2da1ac0ab14ec875fbe58ac03d9` |
| File type | `sh` |
| First seen | `2026-07-06 20:31:37` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c152e2900dbc5cd70baeca720727bffd` |
| SHA-1 | `1d0890de5ab61b1ce14dbbe035e5687bbd0ecac1` |
| SHA-256 | `810d409aef915e09eaa59b1cb8df60559c72b2da1ac0ab14ec875fbe58ac03d9` |
| SHA3-384 | `a4a416bb78ee7b369f7dd478226b616e2dd7f3a3c8729ce0937029628222826e1e8222ed3a031633b55cf0fea10f8cd7` |
| TLSH | `T1F7B012B84112C430F40C441771B6C8A18682E479B819AF32CA414C12440C60D310DB36` |
| SSDEEP | `3:TKH4vSCAtFg2TP7XmhYVxQ1OBVN0:hZAtu0D2hqK1OBc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_810d409a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "810d409aef915e09eaa59b1cb8df60559c72b2da1ac0ab14ec875fbe58ac03d9"
    family = "unknown"
    file_name = "810d409aef915e09eaa59b1cb8df60559c72b2da1ac0ab14ec875fbe58ac03d9"
    file_type = "sh"
    first_seen = "2026-07-06 20:31:37"
  condition:
    hash.sha256(0, filesize) == "810d409aef915e09eaa59b1cb8df60559c72b2da1ac0ab14ec875fbe58ac03d9"
}
```

### Sample 57: `7ba090e0c3807dbc`

| Field | Value |
|---|---|
| SHA-256 | `7ba090e0c3807dbccd450d7125b48195e65dbea71187aec571ae69d15d46f9ba` |
| Family label | `unknown` |
| File name | `7ba090e0c3807dbccd450d7125b48195e65dbea71187aec571ae69d15d46f9ba` |
| File type | `unknown` |
| First seen | `2026-07-06 20:31:34` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `716476925c51141fff2f86700d82c36b` |
| SHA-1 | `77b0e047e52c115d79cc0dc860996e8e013a99bb` |
| SHA-256 | `7ba090e0c3807dbccd450d7125b48195e65dbea71187aec571ae69d15d46f9ba` |
| SHA3-384 | `763dbdc6c7d4b388bdbdc78221a81ba43914860d747eb8ce59ef4556eb58aad14cb9bea6a4ab3aebb98d2390ab06016f` |
| TLSH | `T1D9B09B427C099426DF505505517090965614545A4F4189F4D7F1C264849AB10850BA0D` |
| SSDEEP | `3:JSdRx9AhfvpLZJuKOCHNwoXmhYVNFVwFrJA7An:G/9AhfvHJuzto2hqNFVwrH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_7ba090e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ba090e0c3807dbccd450d7125b48195e65dbea71187aec571ae69d15d46f9ba"
    family = "unknown"
    file_name = "7ba090e0c3807dbccd450d7125b48195e65dbea71187aec571ae69d15d46f9ba"
    file_type = "unknown"
    first_seen = "2026-07-06 20:31:34"
  condition:
    hash.sha256(0, filesize) == "7ba090e0c3807dbccd450d7125b48195e65dbea71187aec571ae69d15d46f9ba"
}
```

### Sample 58: `cc668803553940c2`

| Field | Value |
|---|---|
| SHA-256 | `cc668803553940c2c7ee1f6e7929d487b7c07fc41d8bc3f19c773bb67bf27eaf` |
| Family label | `Mirai` |
| File name | `Mozi.a` |
| File type | `elf` |
| First seen | `2026-07-06 20:27:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd91111603d3a7cbc16ef04105e19bb0` |
| SHA-1 | `eb4eedc53d642b38bd928cb75dc0cd6a9496f2be` |
| SHA-256 | `cc668803553940c2c7ee1f6e7929d487b7c07fc41d8bc3f19c773bb67bf27eaf` |
| SHA3-384 | `e69d41828b167b01eb164e1a567df25a42d5470b4e5a6767ea8b2667d01fde94a358cdcd4f6f79e06db0ffb1a23d33f2` |
| TLSH | `T12A230681BC82869689D413BEFD7D81CD331273B9D2DF7112CD115F18B6CA94F0E6AA92` |
| SSDEEP | `1536:CMn12A//SrRftY97WARbIcbboW+zLsYtJ913DA:T2s/ITo7WCkybotgsJ913DA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_cc668803
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc668803553940c2c7ee1f6e7929d487b7c07fc41d8bc3f19c773bb67bf27eaf"
    family = "Mirai"
    file_name = "Mozi.a"
    file_type = "elf"
    first_seen = "2026-07-06 20:27:10"
  condition:
    hash.sha256(0, filesize) == "cc668803553940c2c7ee1f6e7929d487b7c07fc41d8bc3f19c773bb67bf27eaf"
}
```

### Sample 59: `4b06e4c33a3ed626`

| Field | Value |
|---|---|
| SHA-256 | `4b06e4c33a3ed62617c059ef47629b426971f2796f486449e19ae421f229fc16` |
| Family label | `unknown` |
| File name | `Swift ref. TT 810-363295460.js` |
| File type | `js` |
| First seen | `2026-07-06 20:25:49` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `399705c07d18922e905baf255aee15ed` |
| SHA-1 | `2a11606de451c734115180696a7d1dc5531fce2f` |
| SHA-256 | `4b06e4c33a3ed62617c059ef47629b426971f2796f486449e19ae421f229fc16` |
| SHA3-384 | `f2657d0e6c78fa64ec8557bbeec8b8cde5c0c774e9120daf3458e6063ff5831aec608592da840b16e91d5b5f697f146e` |
| TLSH | `T11A453360DE2A7E690AE8DA3470B71F1A0FD18DD8D4297073BE8636C35736AD06C27C59` |
| SSDEEP | `24576:FoPcnZQuCGU2vPpGmH3fpm/9IGnpYs59+OhQwnPEQFQadQuQDj8:lHvsmvoDBhdIadxl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_4b06e4c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b06e4c33a3ed62617c059ef47629b426971f2796f486449e19ae421f229fc16"
    family = "unknown"
    file_name = "Swift ref. TT 810-363295460.js"
    file_type = "js"
    first_seen = "2026-07-06 20:25:49"
  condition:
    hash.sha256(0, filesize) == "4b06e4c33a3ed62617c059ef47629b426971f2796f486449e19ae421f229fc16"
}
```

### Sample 60: `29e90df3f89e3430`

| Field | Value |
|---|---|
| SHA-256 | `29e90df3f89e343059d0925b933b09237457401a1a1278fb1275fa3c5c80ef29` |
| Family label | `unknown` |
| File name | `29e90df3f89e343059d0925b933b09237457401a1a1278fb1275fa3c5c80ef29` |
| File type | `exe` |
| First seen | `2026-07-06 20:15:13` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68eafb9dddd7562e46a0e30c9593848e` |
| SHA-1 | `181e08e7771394902aa70fe29c481d030783bdbe` |
| SHA-256 | `29e90df3f89e343059d0925b933b09237457401a1a1278fb1275fa3c5c80ef29` |
| SHA3-384 | `3536b701dfa5b1ffe8eb210450801f3ecec099f7807c15a9df3d6af3ef7a6762c1b66408ead998d27861cab476e8b175` |
| TLSH | `T18F524ACE33D040F5D8BAA274C876B51BE3B1BC5A2655970F877842A72F23A63660F351` |
| SSDEEP | `384:5tutOLIhxmaDNKfly0l8+UqlC57GXOK5A9Sf4EEdMTfT:2OLgYfly/+lAFK5AUf4JMTL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_29e90df3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29e90df3f89e343059d0925b933b09237457401a1a1278fb1275fa3c5c80ef29"
    family = "unknown"
    file_name = "29e90df3f89e343059d0925b933b09237457401a1a1278fb1275fa3c5c80ef29"
    file_type = "exe"
    first_seen = "2026-07-06 20:15:13"
  condition:
    hash.sha256(0, filesize) == "29e90df3f89e343059d0925b933b09237457401a1a1278fb1275fa3c5c80ef29"
}
```

### Sample 61: `0f9e9e3f242dce4f`

| Field | Value |
|---|---|
| SHA-256 | `0f9e9e3f242dce4f85b98819a8b9db4d28634e5147a832e3f4c24218eb1c8489` |
| Family label | `unknown` |
| File name | `Pivlex_CRM_API_Documentation.zip` |
| File type | `zip` |
| First seen | `2026-07-06 19:55:36` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd543142955d6c68e6af2acaa0f92b51` |
| SHA-1 | `300f6d824ac368cbd0db059ea048820989dc9715` |
| SHA-256 | `0f9e9e3f242dce4f85b98819a8b9db4d28634e5147a832e3f4c24218eb1c8489` |
| SHA3-384 | `ed3a884ffcdc39ff2bfdf21cef431e01bcc996940c1b498277ce9bb0912531d5803e7df9e8d53e3ae223a85874b27a16` |
| TLSH | `T198410B8043A18992E18F8E79F518D8D9E32CAF113D5EF57A3C1664C1A4C2CFB650156F` |
| SSDEEP | `48:9N7vq8gkkUlBii59TDPgb1POwu/UPVlhziVJR+5aFP7Tr05alXxFt:LbNgkXBB/POLUZrAab3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_0f9e9e3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f9e9e3f242dce4f85b98819a8b9db4d28634e5147a832e3f4c24218eb1c8489"
    family = "unknown"
    file_name = "Pivlex_CRM_API_Documentation.zip"
    file_type = "zip"
    first_seen = "2026-07-06 19:55:36"
  condition:
    hash.sha256(0, filesize) == "0f9e9e3f242dce4f85b98819a8b9db4d28634e5147a832e3f4c24218eb1c8489"
}
```

### Sample 62: `b94f04ed23e299dc`

| Field | Value |
|---|---|
| SHA-256 | `b94f04ed23e299dcabcddbf467dfe029f839bda0d5250f7c983d1ade04aa23d3` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-06 19:53:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bfa56f0c2066a3b6b581aaf0bb080ed` |
| SHA-1 | `ef6c9141d114667136cd8ffc94e94dae22e9d71d` |
| SHA-256 | `b94f04ed23e299dcabcddbf467dfe029f839bda0d5250f7c983d1ade04aa23d3` |
| SHA3-384 | `2c68ba2459722abc199179f913c909e937e5243d4bd79c511315a0f4eca2824da2026940938eb76feea392a11a5be256` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1CDE63349B9E102EEFAA7813DEDE352A2D46570615771CCCB07AC8266BF132D64C3A317` |
| SSDEEP | `393216:onuak25IFuDQgUIOcpoHX/yJXMCHWUjXzcuI3/PGTAI:oSFhc46JXMb8XwH/O7` |
| ICON-DHASH | `e8e864e0d8e8e848` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_b94f04ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b94f04ed23e299dcabcddbf467dfe029f839bda0d5250f7c983d1ade04aa23d3"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-06 19:53:08"
  condition:
    hash.sha256(0, filesize) == "b94f04ed23e299dcabcddbf467dfe029f839bda0d5250f7c983d1ade04aa23d3"
}
```

### Sample 63: `c45d98ff74ce7927`

| Field | Value |
|---|---|
| SHA-256 | `c45d98ff74ce79277bcb8e298115511b618e0b94bff33dddec56a440afae59b0` |
| Family label | `unknown` |
| File name | `dg.mips` |
| File type | `elf` |
| First seen | `2026-07-06 19:51:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b41d72c1c9b7af192e5014343c91a8bc` |
| SHA-1 | `783a260abccc22585ed7aded55bef09f37c5298c` |
| SHA-256 | `c45d98ff74ce79277bcb8e298115511b618e0b94bff33dddec56a440afae59b0` |
| SHA3-384 | `6b47a82588de97facbecf140193949f03d61329ec719c7b411dd83125fc46c850100e635ab14abe265e9fe14cf7d7ecd` |
| TLSH | `T1FD83022E2E145EE8C433F47F20AAAF580F774B46DD41F189FE69E1806A9171D5800EDE` |
| SSDEEP | `1536:0+a9/Qom9Tnyjo7DxpvsB/9Vf78VCj+DsT0UcskwNer4pZwV8A:0Pxm9TxXxpyKCj+DwcSfsVt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_c45d98ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c45d98ff74ce79277bcb8e298115511b618e0b94bff33dddec56a440afae59b0"
    family = "unknown"
    file_name = "dg.mips"
    file_type = "elf"
    first_seen = "2026-07-06 19:51:32"
  condition:
    hash.sha256(0, filesize) == "c45d98ff74ce79277bcb8e298115511b618e0b94bff33dddec56a440afae59b0"
}
```

### Sample 64: `72cdf2c971f2a498`

| Field | Value |
|---|---|
| SHA-256 | `72cdf2c971f2a498a7bc1ea88e248945e8adf6e946273db0c5a533e8f0c0eae9` |
| Family label | `Mirai` |
| File name | `m68k.ghost` |
| File type | `elf` |
| First seen | `2026-07-06 19:50:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9ad29e991fcffebb40e9e6e7f7c435c` |
| SHA-1 | `646264959d1d8d6771770b45d0dced44de948f32` |
| SHA-256 | `72cdf2c971f2a498a7bc1ea88e248945e8adf6e946273db0c5a533e8f0c0eae9` |
| SHA3-384 | `90679cfbdec57c06567c31894606e5ed0450fbe347f87cc28041cf7b90e7afa615fe84659eb8f8913287d2132100ca86` |
| TLSH | `T1B3C36B92BB197E3FD5B6493A848783057B38ED409E463613502D76576EB32D00E3B7CA` |
| SSDEEP | `1536:yN8l06ExEUF+Ap9HR0w1azgUoiTAT7oCvJ+EGMaGjQrRQrYxewBOUMwNN5X:c8lw52w1azXXQ7Jv2voYt7Mkh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_72cdf2c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72cdf2c971f2a498a7bc1ea88e248945e8adf6e946273db0c5a533e8f0c0eae9"
    family = "Mirai"
    file_name = "m68k.ghost"
    file_type = "elf"
    first_seen = "2026-07-06 19:50:54"
  condition:
    hash.sha256(0, filesize) == "72cdf2c971f2a498a7bc1ea88e248945e8adf6e946273db0c5a533e8f0c0eae9"
}
```

### Sample 65: `e065ef9893248626`

| Field | Value |
|---|---|
| SHA-256 | `e065ef98932486261dd7fcb412521e987b0884b1e9feddf25daae2ad7a52420c` |
| Family label | `Mirai` |
| File name | `i686.ghost` |
| File type | `elf` |
| First seen | `2026-07-06 19:50:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edf88c7816498966c788625c9fbcb2e2` |
| SHA-1 | `3a8a993d2feacb766eaff31161f5ec863b0260aa` |
| SHA-256 | `e065ef98932486261dd7fcb412521e987b0884b1e9feddf25daae2ad7a52420c` |
| SHA3-384 | `b0fc1b873c2ff054f07d51e0ebf9104a380d644b41a6e9c1308822b8e490e31d7d3bf532bd8ee0db98c57357940f1f7e` |
| TLSH | `T128C35B46F792D4F3E18302331053CBA65771EA31014ACE0BF7083A759D667898E6BBAD` |
| SSDEEP | `3072:1NbL8D/4ytg1xi+uU+a63iTrAo4ETlb3VGvXgWnjt5:1NbUg1xvEIAEbsvn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_e065ef98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e065ef98932486261dd7fcb412521e987b0884b1e9feddf25daae2ad7a52420c"
    family = "Mirai"
    file_name = "i686.ghost"
    file_type = "elf"
    first_seen = "2026-07-06 19:50:17"
  condition:
    hash.sha256(0, filesize) == "e065ef98932486261dd7fcb412521e987b0884b1e9feddf25daae2ad7a52420c"
}
```

### Sample 66: `cf284583db104e70`

| Field | Value |
|---|---|
| SHA-256 | `cf284583db104e7032876733467e77b25637a8a5d908c7b0d1582bac6c576eb7` |
| Family label | `unknown` |
| File name | `cf284583db104e7032876733467e77b25637a8a5d908c7b0d1582bac6c576eb7` |
| File type | `sh` |
| First seen | `2026-07-06 19:46:46` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dd9cf50fdf6e042f914ebf9904bd036` |
| SHA-1 | `063e006e2a67193b0fa8604895bb3d5f4b79c268` |
| SHA-256 | `cf284583db104e7032876733467e77b25637a8a5d908c7b0d1582bac6c576eb7` |
| SHA3-384 | `7e168963ed8cdf6c0eb0d702e591773009ccb065683e4923807c2a29ec12c61e11675f2f11da23b49bd71be7caea71f3` |
| TLSH | `T142A0110EF22288380E2808B2800AC0A08200032888AA8AB00202A0B2AE08328228A882` |
| SSDEEP | `3:TKH4vSNMOY8toKBjIShldh:hirtLBjZN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_cf284583
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf284583db104e7032876733467e77b25637a8a5d908c7b0d1582bac6c576eb7"
    family = "unknown"
    file_name = "cf284583db104e7032876733467e77b25637a8a5d908c7b0d1582bac6c576eb7"
    file_type = "sh"
    first_seen = "2026-07-06 19:46:46"
  condition:
    hash.sha256(0, filesize) == "cf284583db104e7032876733467e77b25637a8a5d908c7b0d1582bac6c576eb7"
}
```

### Sample 67: `981cc9005fb224a3`

| Field | Value |
|---|---|
| SHA-256 | `981cc9005fb224a31130f9b8185976f51a0c705cde4e3d5818bda3a726f80826` |
| Family label | `unknown` |
| File name | `981cc9005fb224a31130f9b8185976f51a0c705cde4e3d5818bda3a726f80826` |
| File type | `exe` |
| First seen | `2026-07-06 19:33:56` |
| Reporter | `JAMESWT_WT` |
| Tags | `booking-customerhotelinfo-com, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec2e4ccde275477539e7f509f58f832b` |
| SHA-1 | `361ff73e7003ff2b9c6b118217da68c5940eb459` |
| SHA-256 | `981cc9005fb224a31130f9b8185976f51a0c705cde4e3d5818bda3a726f80826` |
| SHA3-384 | `35f95b3852248956789d57b176c9cbb927e9eccc6f95a9dfd8830093c510d49e33cd4639f3200e70aa2afa7280e3aa25` |
| IMPHASH | `45c50c088695685800c4e9820ae701cc` |
| TLSH | `T1F894236FC963EC8EC4EBD2BD6A23A761E430BC57746435404D51BB222B87F49CA6C2D4` |
| SSDEEP | `6144:QWMy5Z/0JzznxpNNIqLvKybfrKZt0MQvcdi2Byb69ctmMo+OZGZO2Juho+xX+BA:QW95ZYl5IU/bfrKxQ+cc3NZGQ5+akA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_981cc900
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "981cc9005fb224a31130f9b8185976f51a0c705cde4e3d5818bda3a726f80826"
    family = "unknown"
    file_name = "981cc9005fb224a31130f9b8185976f51a0c705cde4e3d5818bda3a726f80826"
    file_type = "exe"
    first_seen = "2026-07-06 19:33:56"
  condition:
    hash.sha256(0, filesize) == "981cc9005fb224a31130f9b8185976f51a0c705cde4e3d5818bda3a726f80826"
}
```

### Sample 68: `863454d9d304f370`

| Field | Value |
|---|---|
| SHA-256 | `863454d9d304f37003a7d301e543fb08a7fe6ac7853f1405ded6f3f64ba1532e` |
| Family label | `Adware.Techsnab` |
| File name | `863454d9d304f37003a7d301e543fb08a7fe6ac7853f1405ded6f3f64ba1532e.ps1` |
| File type | `ps1` |
| First seen | `2026-07-06 19:33:42` |
| Reporter | `JAMESWT_WT` |
| Tags | `Adware.Techsnab, booking-customerhotelinfo-com, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `627b462fe78575f12f53c9a6c3e34535` |
| SHA-1 | `02ac405d4e4affca7cd87891ecf99fe38b4afdcd` |
| SHA-256 | `863454d9d304f37003a7d301e543fb08a7fe6ac7853f1405ded6f3f64ba1532e` |
| SHA3-384 | `5a1292d7e2b573ca0a75a1b06b36000ecb25e827b00ea72517918493073d6652ac9f3f8a7f67b038c2690e955d40c434` |
| TLSH | `T12412081B263B09B1434226F7C4EEE309F926417B26057E8874DC90DDAF2667483F9A5F` |
| SSDEEP | `192:4svWAEmcDFYGMAHIiCzVtv1JiJU5M/sCzridUfNeoaOFhx:4scVs+Eom8` |

#### Technical Assessment

- The sample is tracked as `Adware.Techsnab` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_Techsnab_068_863454d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "863454d9d304f37003a7d301e543fb08a7fe6ac7853f1405ded6f3f64ba1532e"
    family = "Adware.Techsnab"
    file_name = "863454d9d304f37003a7d301e543fb08a7fe6ac7853f1405ded6f3f64ba1532e.ps1"
    file_type = "ps1"
    first_seen = "2026-07-06 19:33:42"
  condition:
    hash.sha256(0, filesize) == "863454d9d304f37003a7d301e543fb08a7fe6ac7853f1405ded6f3f64ba1532e"
}
```

### Sample 69: `47575a1410088886`

| Field | Value |
|---|---|
| SHA-256 | `47575a1410088886820cff310c133c2501874381ea30174cc05077b3c208ad4d` |
| Family label | `Adware.Techsnab` |
| File name | `47575a1410088886820cff310c133c2501874381ea30174cc05077b3c208ad4d.ps1` |
| File type | `ps1` |
| First seen | `2026-07-06 19:33:31` |
| Reporter | `JAMESWT_WT` |
| Tags | `Adware.Techsnab, booking-customerhotelinfo-com, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74b52f4242957dc94230fec4839eec17` |
| SHA-1 | `ec601c0b2ed4ad0daf2b0dc8e4c4d7cc359c9d28` |
| SHA-256 | `47575a1410088886820cff310c133c2501874381ea30174cc05077b3c208ad4d` |
| SHA3-384 | `a1f389759a8497ef618961670a9a5e628702e50f020db83d13a989c0a358def384d59ff97ca5fc3c7d49b9806bbd9f89` |
| TLSH | `T14912192227A10D7543D396D7EAEEE20879A60177210AFDCE709D9719AF2347013ECB5A` |
| SSDEEP | `192:E2AElcocWIiCzR0DP5JiJ65AMeACKriB+mHNeoAONhx:hxzq` |

#### Technical Assessment

- The sample is tracked as `Adware.Techsnab` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_Techsnab_069_47575a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47575a1410088886820cff310c133c2501874381ea30174cc05077b3c208ad4d"
    family = "Adware.Techsnab"
    file_name = "47575a1410088886820cff310c133c2501874381ea30174cc05077b3c208ad4d.ps1"
    file_type = "ps1"
    first_seen = "2026-07-06 19:33:31"
  condition:
    hash.sha256(0, filesize) == "47575a1410088886820cff310c133c2501874381ea30174cc05077b3c208ad4d"
}
```

### Sample 70: `576d30ad74e1b571`

| Field | Value |
|---|---|
| SHA-256 | `576d30ad74e1b571446c130d5e2fc440f422432cd8b2df8f1a1de9eaaf1b580a` |
| Family label | `Mirai` |
| File name | `armv7l.ghost` |
| File type | `elf` |
| First seen | `2026-07-06 19:22:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `875ad8844a200f9db41a093c2b84b24c` |
| SHA-1 | `911256ef355462d4707f891bc954e319a8ca01ff` |
| SHA-256 | `576d30ad74e1b571446c130d5e2fc440f422432cd8b2df8f1a1de9eaaf1b580a` |
| SHA3-384 | `af493a8c1e96cd01afcd6b87c3183ef09381a81f3c92be1450654eab68e07f5d4c4ecbd925662a4256be7273476a7f94` |
| TLSH | `T1DEF31A5CF9518716C6D0257AF69B128C33735B24FFDA3B06DD146B283BD27299E2B201` |
| SSDEEP | `3072:gFrnevRROKunMFOXW/+ayDED3zp/Vi7h26xt/goQMLX1:gFjevSnMFOXW/+S3z5VZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_576d30ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "576d30ad74e1b571446c130d5e2fc440f422432cd8b2df8f1a1de9eaaf1b580a"
    family = "Mirai"
    file_name = "armv7l.ghost"
    file_type = "elf"
    first_seen = "2026-07-06 19:22:02"
  condition:
    hash.sha256(0, filesize) == "576d30ad74e1b571446c130d5e2fc440f422432cd8b2df8f1a1de9eaaf1b580a"
}
```

### Sample 71: `4741797701244022`

| Field | Value |
|---|---|
| SHA-256 | `474179770124402269511865d3b4677e9ccb7e0423049df67e937936888a96e0` |
| Family label | `Mirai` |
| File name | `mipsel.ghost` |
| File type | `elf` |
| First seen | `2026-07-06 19:15:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38323ec18938e26093001c72587e8f46` |
| SHA-1 | `a178d220588b3fad68502a40095e5d418a515d77` |
| SHA-256 | `474179770124402269511865d3b4677e9ccb7e0423049df67e937936888a96e0` |
| SHA3-384 | `71e6daa3f658fc481139d30b331d6cd3b2761d7b4466341c31ba13a0c721a4904d3bf6f45f74df6112e667b0df6dbc56` |
| TLSH | `T1A7141842EF414AABC45ECF31411B838A13EDD48643FB571B6178C95E7E4AA0E2DC7E98` |
| TELFHASH | `t13501cb4db27909ab6df38264c8a50f65d283e85bb4f21a25db04fbc08276489d11fe0e` |
| SSDEEP | `3072:o8yNtGGmOt4Eq+JLxxFJUgyyJifx6I96ox1t35K8e2nVxua24XbeWD4hfgEpnNGv:oMKxFJUgzsp6IooLh5KUD47G` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_47417977
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "474179770124402269511865d3b4677e9ccb7e0423049df67e937936888a96e0"
    family = "Mirai"
    file_name = "mipsel.ghost"
    file_type = "elf"
    first_seen = "2026-07-06 19:15:58"
  condition:
    hash.sha256(0, filesize) == "474179770124402269511865d3b4677e9ccb7e0423049df67e937936888a96e0"
}
```

### Sample 72: `277e1e7a41cdc475`

| Field | Value |
|---|---|
| SHA-256 | `277e1e7a41cdc47542136aee56cf6850cb940baf9f4d9d7250a1672b1771f204` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-06 19:14:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4979bf9dd91f16d5447638ec5106df62` |
| SHA-1 | `d64926edec35318a70bfe4f57631ba9bd247196b` |
| SHA-256 | `277e1e7a41cdc47542136aee56cf6850cb940baf9f4d9d7250a1672b1771f204` |
| SHA3-384 | `033827b4746173ecd3280b8d5624617d86fbbaaedc6a7b00aa87ae386601bb361f0a5fdb408b4efab5741e03f76ff7cb` |
| TLSH | `T15653C605FB511FF7DCABCD3746AD1B0134CC695A22E9AB367234C868B50B25B1AE3C64` |
| SSDEEP | `768:CpT92U1MMcsX9FUdKhVGOeazleJx7oh84XCZKydXiuS9mJrfw:qT92U1MM5//7zl+x7oh84yZKyKB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_277e1e7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "277e1e7a41cdc47542136aee56cf6850cb940baf9f4d9d7250a1672b1771f204"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-06 19:14:28"
  condition:
    hash.sha256(0, filesize) == "277e1e7a41cdc47542136aee56cf6850cb940baf9f4d9d7250a1672b1771f204"
}
```

### Sample 73: `80dec65aefed6083`

| Field | Value |
|---|---|
| SHA-256 | `80dec65aefed608345d3baf92464aead3333ea1e880ea0c04c6ccb136c839436` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-06 19:14:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `552dc99b79beadfd071232c318ac9c34` |
| SHA-1 | `511c0fe4c310c7b0c3bca8f80d85bc36691518b5` |
| SHA-256 | `80dec65aefed608345d3baf92464aead3333ea1e880ea0c04c6ccb136c839436` |
| SHA3-384 | `a198beb1204845d62bb2e150555d51918ff625dd5e5fcfd9a15a63ee9b24c9201eae6e402377f355103ccfb2e535f6ac` |
| TLSH | `T1DE43F755F8814B22C5D5027AF92D118D332367E8E3DFB2139E206F607BC696B0E36E56` |
| TELFHASH | `t1e801d0a42b484efdf7d0cc28c3ecb274341131a1ef1301514fa75d854329fd66521834` |
| SSDEEP | `1536:GInoHzdydabeUeJj8VK1D/QJ+Mfwi7rzSm14M:QzsdysyrzSm14M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_80dec65a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80dec65aefed608345d3baf92464aead3333ea1e880ea0c04c6ccb136c839436"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-06 19:14:11"
  condition:
    hash.sha256(0, filesize) == "80dec65aefed608345d3baf92464aead3333ea1e880ea0c04c6ccb136c839436"
}
```

### Sample 74: `2b9fa53f8372c441`

| Field | Value |
|---|---|
| SHA-256 | `2b9fa53f8372c4413775650e9383d4f552aab63ffe298c21186674c3a4527f7e` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-06 19:14:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af3df0763365b756a3455222bf0cb93f` |
| SHA-1 | `70b635d8269a31dd1cbb1cdbe9574455e614ff1a` |
| SHA-256 | `2b9fa53f8372c4413775650e9383d4f552aab63ffe298c21186674c3a4527f7e` |
| SHA3-384 | `a82baf8b18153211ceb8fa528c3fa410af5c2f61889420baaa04aed7d4c508f19628f683cb967e3d4d5a541382be0e97` |
| TLSH | `T163C32A46FB414B13C4D61779BAEF42453322E790A3DB730699286FB43F8679B4E23906` |
| TELFHASH | `t10121fe356b25a1295d61dd949cfe47b1262c87132780ef33ef25c4cc641909aea2bc4f` |
| SSDEEP | `3072:V+iATXVHT+nK4UrNaxnlR+39WM/9lk1Yj:V+iA5T+nK4Upa3R+3AM/9cYj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_2b9fa53f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b9fa53f8372c4413775650e9383d4f552aab63ffe298c21186674c3a4527f7e"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-06 19:14:00"
  condition:
    hash.sha256(0, filesize) == "2b9fa53f8372c4413775650e9383d4f552aab63ffe298c21186674c3a4527f7e"
}
```

### Sample 75: `83f1f077cd9cc9e2`

| Field | Value |
|---|---|
| SHA-256 | `83f1f077cd9cc9e28452ccd254cae3c798fbc83e8dfa7377cd896dc8063ed0b4` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-06 19:13:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `872598096edeab592aeaa0243f3bf54b` |
| SHA-1 | `eed85f111f6771810f9cc5b99b44263a7093a999` |
| SHA-256 | `83f1f077cd9cc9e28452ccd254cae3c798fbc83e8dfa7377cd896dc8063ed0b4` |
| SHA3-384 | `b08cdb03b22ae24e2516e7445c44ce3eaa5587af4aeab28398db37ca48f2b807a0c44567f70e51c3907cde9b85e24c76` |
| TLSH | `T1DF132B12B21C0F27C4A31970253F6BD09BFBEAD022E4F285655E5B9A8A75D371482FCD` |
| SSDEEP | `768:JrTD7IA5FIRg+R3pRrhUGGTSXNkR2igTEqJAd/ucuoIaJWwA:pTSLbQTH44LZuFoImPA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_83f1f077
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83f1f077cd9cc9e28452ccd254cae3c798fbc83e8dfa7377cd896dc8063ed0b4"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-06 19:13:52"
  condition:
    hash.sha256(0, filesize) == "83f1f077cd9cc9e28452ccd254cae3c798fbc83e8dfa7377cd896dc8063ed0b4"
}
```

### Sample 76: `4e753042b8710bff`

| Field | Value |
|---|---|
| SHA-256 | `4e753042b8710bff8c99e045663b43c907c1a2dff5c1a3fc5947af0525978f33` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-06 19:13:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7883b90652285bdd7c3286f48456872b` |
| SHA-1 | `e23c59848c5833fb829cc4e328a2cd0da4ead605` |
| SHA-256 | `4e753042b8710bff8c99e045663b43c907c1a2dff5c1a3fc5947af0525978f33` |
| SHA3-384 | `07fac7e68930f718ede7d9c9ba1446d1f554163161797054c47bb381bdfb3b1e2365d9524e7d3595c3f477c37d264be7` |
| TLSH | `T1A823F707B54681FDC88AC174476BBA3ED92275FD0238F2A67BD4BB222997D215E0DC48` |
| TELFHASH | `t1ed1140a13e220ca0f0e7e0627746e0660d381e0440e431fbe2b1b4fb9b21b420638c37` |
| SSDEEP | `768:PsxkeNSDkPQ/xPpTk3jA3dxMi75QD9Bt9+Vj85e0PIgGC1ue+v3SbI34rP9ms:MN8DkPQ/Vpg3jA3dxMi75Q5BtUJQZn1N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_4e753042
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e753042b8710bff8c99e045663b43c907c1a2dff5c1a3fc5947af0525978f33"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-06 19:13:37"
  condition:
    hash.sha256(0, filesize) == "4e753042b8710bff8c99e045663b43c907c1a2dff5c1a3fc5947af0525978f33"
}
```

### Sample 77: `5a1100bac5fa9236`

| Field | Value |
|---|---|
| SHA-256 | `5a1100bac5fa923697e05864a0c8e362e5c50638421f572fbb4abb3b99f10c73` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-06 19:13:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f47b41ed97de32c7c3aa6e1f0152bcf0` |
| SHA-1 | `d5ef235de9c61159fd7ebae0929ce5541b4c353d` |
| SHA-256 | `5a1100bac5fa923697e05864a0c8e362e5c50638421f572fbb4abb3b99f10c73` |
| SHA3-384 | `7d586b1c207ebfd1d1f0aa6c779df2f96092c1fab17eecbb15b3f8f215b9466a48a38b6f658dbb96826c929256bb7719` |
| TLSH | `T1A503E895F8825B27C6E0137AB6BE968C376063E893CFB61BC8115B247AC591F0C63F51` |
| TELFHASH | `t194e0c600bc748b2c48cb9a74dcec03b49400221321268b00cf00cbf0c83f008e30ca8e` |
| SSDEEP | `768:5o6wGtK0G5ijUddkRBKLeIZdMPMZqb/wm9d0+Chw/W5oPoDw:bt1G5ijNBKS8dMHMKlChwWg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_5a1100ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a1100bac5fa923697e05864a0c8e362e5c50638421f572fbb4abb3b99f10c73"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-06 19:13:30"
  condition:
    hash.sha256(0, filesize) == "5a1100bac5fa923697e05864a0c8e362e5c50638421f572fbb4abb3b99f10c73"
}
```

### Sample 78: `4fc8c90b927b8008`

| Field | Value |
|---|---|
| SHA-256 | `4fc8c90b927b80081134e6ef7c3b471b6d6679270a9705a90ed1a9fcd1cc6979` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-06 19:13:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9221b3c732a3fc85f2c38961c083a7b0` |
| SHA-1 | `e82f84399986570ead185890b70006be4ae83dcd` |
| SHA-256 | `4fc8c90b927b80081134e6ef7c3b471b6d6679270a9705a90ed1a9fcd1cc6979` |
| SHA3-384 | `1ee29cebdc3df98715f87b424878dbf4946e07af4b5a5631a4a1be442ec96b81c371fdfe0c78bfa19e9b8ce2054ab1d2` |
| TLSH | `T15723F741B8815A23C6D1137AB56E46CD3B3563E8E2DFB21B9D225F6037C682F0C67E85` |
| TELFHASH | `t10531ec905e9c1acc67e04801839bb13f3d863974df21295d8f5b6f6f46138d17024037` |
| SSDEEP | `768:XwsEiiF6sw2qzKVWGMd2f+ur19/m/e9CE4v3omnE4rPu0IIyEJvw:eiiF6x2qzSv+0f9Czvd2JiK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_4fc8c90b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fc8c90b927b80081134e6ef7c3b471b6d6679270a9705a90ed1a9fcd1cc6979"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-06 19:13:20"
  condition:
    hash.sha256(0, filesize) == "4fc8c90b927b80081134e6ef7c3b471b6d6679270a9705a90ed1a9fcd1cc6979"
}
```

### Sample 79: `ef9686c22bbbfd18`

| Field | Value |
|---|---|
| SHA-256 | `ef9686c22bbbfd18eb7402292bf730396675b00fd35e575bfdecca683d06007f` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-06 19:13:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af7855a7e1d272624fb7194b9c91d1a6` |
| SHA-1 | `98c9c2df880d4d4d5a1901baa09c0b0b5cf2d236` |
| SHA-256 | `ef9686c22bbbfd18eb7402292bf730396675b00fd35e575bfdecca683d06007f` |
| SHA3-384 | `8948b558206a082b27686c62227307627a13ef26a8b9572de45516c6fd65c8f2e9a80f1058129083648ca64787f0c374` |
| TLSH | `T15753840E7E22CFBCF665C63447B78E25A65833D627E1D542E26CD6101EA024E205FFA9` |
| TELFHASH | `t11c012c5c8db413e46b3a4c19180defabe1a530de6b266c278f51b9bc6abdd424e00c08` |
| SSDEEP | `768:WNK4cvvwVlm/2TyOTTm0tnWaLi1ehhNfTX8EsRVKKIef+e+2ww1:l7OTbX538EQTL7+2x1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_ef9686c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef9686c22bbbfd18eb7402292bf730396675b00fd35e575bfdecca683d06007f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-06 19:13:03"
  condition:
    hash.sha256(0, filesize) == "ef9686c22bbbfd18eb7402292bf730396675b00fd35e575bfdecca683d06007f"
}
```

### Sample 80: `9c7a29eb83b53217`

| Field | Value |
|---|---|
| SHA-256 | `9c7a29eb83b5321700242247eb96b1aed5b141ef1b5adc6f1fe3489567e2907b` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-06 19:12:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b86ec40356d4b04c957c91081c33e0e` |
| SHA-1 | `f843a8e9fa8b2cecc77545bedf462c6a979a535a` |
| SHA-256 | `9c7a29eb83b5321700242247eb96b1aed5b141ef1b5adc6f1fe3489567e2907b` |
| SHA3-384 | `03d2ee4ddbe070915f153d39e98ea2eff0f07212f2e00c8af947805df193cfe59db5ac65c73a3cba1ee76a1b3741a569` |
| TLSH | `T1E3132BC4F643DCF1D85706B03176EB365B3AF1F6226CE543D7A89A72BC52202E94299C` |
| TELFHASH | `t11211a3f65ea648fcf7e1bd1cda6f43d32a38ca635a7019f440ba156637f21058072930` |
| SSDEEP | `768:1y4BQvEURm7DjqdN8OVWzv9rlOUwGj2aTFaF5HEvms:n+8mm7DGdN8Oozv9rALGaaTQTHEvz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_9c7a29eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c7a29eb83b5321700242247eb96b1aed5b141ef1b5adc6f1fe3489567e2907b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-06 19:12:55"
  condition:
    hash.sha256(0, filesize) == "9c7a29eb83b5321700242247eb96b1aed5b141ef1b5adc6f1fe3489567e2907b"
}
```

### Sample 81: `fe1789defdc5b8dd`

| Field | Value |
|---|---|
| SHA-256 | `fe1789defdc5b8ddfe6f89d3b46711b2f469f31a8b7b933d924c4946f1b8bb15` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-07-06 19:12:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a080c5b33576b92bb9be0080d85a6b7` |
| SHA-1 | `f16d136bf891d47b8425346a2db4469717f28d06` |
| SHA-256 | `fe1789defdc5b8ddfe6f89d3b46711b2f469f31a8b7b933d924c4946f1b8bb15` |
| SHA3-384 | `c39f03a5ce9e4e22695e7d6fd991889576362f4c68ae358588b823a78d68e3df0ac6ff26cdfa569e7c041033614d7db0` |
| TLSH | `T121230984F44B81F6C00B4D3011A7FA3FCE32D8E951B0956EEFA98F71DE676429112A8D` |
| TELFHASH | `t11911e7a72eb60dfc73f56804c76d22621977c66b1a2023e805b31dc923f24c1d1ed83a` |
| SSDEEP | `768:QY6gpkHJUMG2nZfi21FHVITAWKTIEUcpqHs+QGR+IkQ9NND9uvqsLssnYu4dsr:KgpkiMGmZfi27ITA1IENQHBJsIkQhD9m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_fe1789de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe1789defdc5b8ddfe6f89d3b46711b2f469f31a8b7b933d924c4946f1b8bb15"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-06 19:12:32"
  condition:
    hash.sha256(0, filesize) == "fe1789defdc5b8ddfe6f89d3b46711b2f469f31a8b7b933d924c4946f1b8bb15"
}
```

### Sample 82: `f09b2a34fe99172c`

| Field | Value |
|---|---|
| SHA-256 | `f09b2a34fe99172cea1bde32a741d88e35a7929004e408ea25690467fcb17171` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3a21b0dcdea62456191fc6087d081df` |
| SHA-1 | `365e86791616b545dde87e6841cf6e021143772f` |
| SHA-256 | `f09b2a34fe99172cea1bde32a741d88e35a7929004e408ea25690467fcb17171` |
| SHA3-384 | `7c1d0ca535fc8ed8dd584ba382fae55ecaff112ea15f5f32e0b8e3f43701d55f28fed0f8c6a0e255310899a882a9a6ed` |
| TLSH | `T1E2136C7AE86E5E94C4464130B9698E3C1F13F1C493531EFB1AA982B16447EACF905FF8` |
| SSDEEP | `768:ZazOCe8YypLq0WsDLr+mMdx0mVCCFodehttruMBCsnwR4:Za6Ct/RqwXPSxPVCNw3BCswa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_f09b2a34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f09b2a34fe99172cea1bde32a741d88e35a7929004e408ea25690467fcb17171"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:45"
  condition:
    hash.sha256(0, filesize) == "f09b2a34fe99172cea1bde32a741d88e35a7929004e408ea25690467fcb17171"
}
```

### Sample 83: `6cc4c210350ead3c`

| Field | Value |
|---|---|
| SHA-256 | `6cc4c210350ead3c781a49ab47cbb19b72439b078826a6cf1ebd06bad21fc45d` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `360e13a823722f5c9a2cb5fe0232a147` |
| SHA-1 | `15fa1bc6bdb51b636cc9347afeab07864fa651ba` |
| SHA-256 | `6cc4c210350ead3c781a49ab47cbb19b72439b078826a6cf1ebd06bad21fc45d` |
| SHA3-384 | `adb7a7b4cc9c84a137bf08ecfc4baf291db69fd755878c216ae2d823bcd485339e10de748fb1923a60b36c6a3c3e8545` |
| TLSH | `T162B2D0AEE23471C1D38D7A7E108E17B21C946580339E879C73E24D9CBA3575EF0680BA` |
| SSDEEP | `384:X0kOhodP2pvafAXVdBT3yNwp/zlFEoCXhGV31tUcQb6AwMLRWGVCz0NvEZ8:XthsWUd4wprlbmGt1lQhTWA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_6cc4c210
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cc4c210350ead3c781a49ab47cbb19b72439b078826a6cf1ebd06bad21fc45d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:43"
  condition:
    hash.sha256(0, filesize) == "6cc4c210350ead3c781a49ab47cbb19b72439b078826a6cf1ebd06bad21fc45d"
}
```

### Sample 84: `051b8ecbadfebcc4`

| Field | Value |
|---|---|
| SHA-256 | `051b8ecbadfebcc4b5d799e95850be6453a59c0aeb9b5749a2d6496df750e8f1` |
| Family label | `Mirai` |
| File name | `armv5l.ghost` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bad36f22218937ef83ef428d020dff8` |
| SHA-1 | `001fcaeabbb9321e5c2a00c210f87be49e0447a0` |
| SHA-256 | `051b8ecbadfebcc4b5d799e95850be6453a59c0aeb9b5749a2d6496df750e8f1` |
| SHA3-384 | `736be63ffc63fc3f01e7087a8701eb8e4f047f9e5b881aa4f6f62cd5fe582cba9f4df2da377473d3125030083f6431e3` |
| TLSH | `T1C1F31A5CF550872BC6D0267AF69B128C33725B64FFDE3705E9146B383BD2B299D2A201` |
| SSDEEP | `3072:k9kOu/XUAUm8okWStdAtZuflbWDshGNWM7hkqPYjQNrki:k9Vu8b1okWSTAtrDshMWlGY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_051b8ecb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "051b8ecbadfebcc4b5d799e95850be6453a59c0aeb9b5749a2d6496df750e8f1"
    family = "Mirai"
    file_name = "armv5l.ghost"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:41"
  condition:
    hash.sha256(0, filesize) == "051b8ecbadfebcc4b5d799e95850be6453a59c0aeb9b5749a2d6496df750e8f1"
}
```

### Sample 85: `78af04bcad709ab4`

| Field | Value |
|---|---|
| SHA-256 | `78af04bcad709ab444daa65faff1b3eb8c9f96f06cd410bf813c476bae331845` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `870a2227b86a14d96f4d3ae931aac385` |
| SHA-1 | `9460fb90e25f693b112458e6ea1936ad6ab92229` |
| SHA-256 | `78af04bcad709ab444daa65faff1b3eb8c9f96f06cd410bf813c476bae331845` |
| SHA3-384 | `e6d1ef9a6859fe3bbab635017b7d8ea8c5e8de93fb99b7f1a3aaa7ae349e6888a5339347b4599e1fb2f7da9a71971870` |
| TLSH | `T139C2D034D706A894DAD02D7DD8394485EF4EBBFDD0FD3D222984A63C9683045A9FB386` |
| SSDEEP | `768:0CCpJ6UTh3QjB1CbHBwmr8nDlYS9q3UELj8:0NJ6QhgV1MwZhYHLI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_78af04bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78af04bcad709ab444daa65faff1b3eb8c9f96f06cd410bf813c476bae331845"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:39"
  condition:
    hash.sha256(0, filesize) == "78af04bcad709ab444daa65faff1b3eb8c9f96f06cd410bf813c476bae331845"
}
```

### Sample 86: `06faf46de9d8f10e`

| Field | Value |
|---|---|
| SHA-256 | `06faf46de9d8f10ed2105832aae85584ef20dfe3aa24e572608044b61347ac44` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fce69c75cc1b05f4f77c2a2fa1c6db4e` |
| SHA-1 | `fdd347448b7e7337d7af563f824f1b573f20cba7` |
| SHA-256 | `06faf46de9d8f10ed2105832aae85584ef20dfe3aa24e572608044b61347ac44` |
| SHA3-384 | `dfa65aa983815a6a238db60912092001ce1cf3689ff2fd541ed2ab0654de44bc1df3f24c7cd400b3706c65454dee6322` |
| TLSH | `T11923F121B343ADA3CB28BC7D9F51CA42791553A1DAF4755100F869497EE2500CBAF78F` |
| SSDEEP | `768:H22vyz90222y7vrLJRwN6Dr2Op7c9i3489q3UELIK2rqYcbYBbc6iTO:WBz9022HrLos2Opv34FLVb8bc5O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_06faf46d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06faf46de9d8f10ed2105832aae85584ef20dfe3aa24e572608044b61347ac44"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:36"
  condition:
    hash.sha256(0, filesize) == "06faf46de9d8f10ed2105832aae85584ef20dfe3aa24e572608044b61347ac44"
}
```

### Sample 87: `977943f436219be2`

| Field | Value |
|---|---|
| SHA-256 | `977943f436219be2f612a5dde5e39ccb904606c6e34f9e76e75af31b98c24550` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00c08b9bfc3eb667ca2d13764bcba2da` |
| SHA-1 | `03a1f839d37cee0894898183b09e700d58c8160b` |
| SHA-256 | `977943f436219be2f612a5dde5e39ccb904606c6e34f9e76e75af31b98c24550` |
| SHA3-384 | `5d23253f3334a5d25e175df28293728fb032a1f2a83315f53c891f43f0274b41e27aaa450f2579554f96b5556db90548` |
| TLSH | `T1B692D159FC615EBADFEB5FF409B0C3460BA116E56FE99AC1A490A303CB2250921317FC` |
| SSDEEP | `384:890KV5GsLVHhlTtDZddn+UOcqjXvgTmyBEVz8gNA+z6M4uVcqgw05VxJC:y0KbVLTldn+UOceITmgEF8uzB4uVcqgc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_977943f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "977943f436219be2f612a5dde5e39ccb904606c6e34f9e76e75af31b98c24550"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:34"
  condition:
    hash.sha256(0, filesize) == "977943f436219be2f612a5dde5e39ccb904606c6e34f9e76e75af31b98c24550"
}
```

### Sample 88: `45f9416fc1d42cf2`

| Field | Value |
|---|---|
| SHA-256 | `45f9416fc1d42cf2f14a381346665e8a8642aa10c47ee554770626b7fdedd2c3` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01a233c285edb607d81ec40afaccb657` |
| SHA-1 | `849d86304bd903b644169f1fe7369ffbd5072333` |
| SHA-256 | `45f9416fc1d42cf2f14a381346665e8a8642aa10c47ee554770626b7fdedd2c3` |
| SHA3-384 | `56b8ed32b8d2334bfd826fefb7b74c00fae1c62d4a35e8b6c0385bc912f2420bdabd6a6aef3993c382e2109c79da51cc` |
| TLSH | `T16D23189AF8029D7DF94BE37E5006490DB92163D512931B2723BBFEA3BC721591D22E42` |
| SSDEEP | `768:0peS55dx5Sd+5cdg5Ld35+dy5oIiYa1rz9lHmsZ/j9Asrq6WjnmDS4qA08am8rDQ:+v55dx5Sd+5cdg5Ld35+dy5ohrz/Hms3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_45f9416f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45f9416fc1d42cf2f14a381346665e8a8642aa10c47ee554770626b7fdedd2c3"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:33"
  condition:
    hash.sha256(0, filesize) == "45f9416fc1d42cf2f14a381346665e8a8642aa10c47ee554770626b7fdedd2c3"
}
```

### Sample 89: `60e17abbe2312405`

| Field | Value |
|---|---|
| SHA-256 | `60e17abbe2312405cda7ea5de18b632abcb7e4e20eed09ec1bec9c7351e90884` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92e018eb7fa1898845ba5bcd882cc8fc` |
| SHA-1 | `778e3fa4c2c4412b5ab5ce10e99099843fd87f09` |
| SHA-256 | `60e17abbe2312405cda7ea5de18b632abcb7e4e20eed09ec1bec9c7351e90884` |
| SHA3-384 | `74e4d9d045357145fa227107fbe02d79b68b78d8bfef65b8e222b5b0544d3273eb17e274b24d2a5e3381f5c4e187f3eb` |
| TLSH | `T1B7A2E13AC31F5A66CAB2C63A40233EEB0AE9EF591F9D1C39E58455D7016311A3A32631` |
| SSDEEP | `384:EKEIEdCUUnLyusfDh1liQWFKvZn9kuYfAFRUiTVekMOYzuk20PR+d+YcSiFqcJE:BYck/fWFon9Uf6RUWDYK0PRc+YvsW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_60e17abb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60e17abbe2312405cda7ea5de18b632abcb7e4e20eed09ec1bec9c7351e90884"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:30"
  condition:
    hash.sha256(0, filesize) == "60e17abbe2312405cda7ea5de18b632abcb7e4e20eed09ec1bec9c7351e90884"
}
```

### Sample 90: `329a84a476ebb1c1`

| Field | Value |
|---|---|
| SHA-256 | `329a84a476ebb1c17958dacf6a19488150038b955f8b66a0c241748626c75b89` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1dd36b1119fe822a48650802beaf3702` |
| SHA-1 | `4cfe81da194bd51e4bd4a5742c08fac046424db9` |
| SHA-256 | `329a84a476ebb1c17958dacf6a19488150038b955f8b66a0c241748626c75b89` |
| SHA3-384 | `d7f910a0954d2b29aacea7e2e4c2f64d04cac0fc923e3b38f2016f32977d5989936df50dcdd81cb6b27a849bf94d47d1` |
| TLSH | `T1DF82CF74A51A14F1C3B1CE37FA2DC99636C38EBD11DB32723294226256A74C63AB47C2` |
| SSDEEP | `384:fg6WkVgGBj1fl6jXS52uJau1dGtNXyTIebBzWhymdGUop5hI9:YigGB5tuVuJl4NidNWs3Uoza9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_329a84a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "329a84a476ebb1c17958dacf6a19488150038b955f8b66a0c241748626c75b89"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:28"
  condition:
    hash.sha256(0, filesize) == "329a84a476ebb1c17958dacf6a19488150038b955f8b66a0c241748626c75b89"
}
```

### Sample 91: `b6c75912dc0fb738`

| Field | Value |
|---|---|
| SHA-256 | `b6c75912dc0fb738b35e2c0706fb7b9c964e7644c6bcb0662165c89a7d81cff5` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b7d420745c79601e81085ae61fbc80b` |
| SHA-1 | `d3ae454670150caca119bc4ae58df97becc55ed3` |
| SHA-256 | `b6c75912dc0fb738b35e2c0706fb7b9c964e7644c6bcb0662165c89a7d81cff5` |
| SHA3-384 | `ce292c270da70497fd09247e4feb3ab1e8cbd0bce834ff749f5deb2ae2deee37fd93ad3fb8b54fdadfdc42a2a018241e` |
| TLSH | `T1D0A2D16563299862E7F0DD3E9D10C647B5BA1FB8E6EA36333E18123883D110DB17C6C6` |
| SSDEEP | `384:um+DsHSkBedsaJ1y9ftwhWY4Au3lV/GwRwvIsUFPphQQhymdGUop5hu:umlSMjaJo2WUuuwOITIQs3Uoz8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_b6c75912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6c75912dc0fb738b35e2c0706fb7b9c964e7644c6bcb0662165c89a7d81cff5"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:26"
  condition:
    hash.sha256(0, filesize) == "b6c75912dc0fb738b35e2c0706fb7b9c964e7644c6bcb0662165c89a7d81cff5"
}
```

### Sample 92: `ea62ee769f7c022f`

| Field | Value |
|---|---|
| SHA-256 | `ea62ee769f7c022f8443741081e8ae49e90904a8f048328ac72eaa30c58a6ca1` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59cb3065831367f862dcd8dfe3955170` |
| SHA-1 | `36c3670d61fb3b1af4a1c0e57127a5f93a59d098` |
| SHA-256 | `ea62ee769f7c022f8443741081e8ae49e90904a8f048328ac72eaa30c58a6ca1` |
| SHA3-384 | `e49e806989e5c03b35e8843e8214139453cce0aa0279524c850b1b9ce2ae2a4d7652e80cb04c2ce2f4f5f2d703de72a3` |
| TLSH | `T117332A24B9760E17C0C1647A61EB4B24B6F153CF26E8C94E7DB20E9EFF619406913AF4` |
| SSDEEP | `768:0DaozBBMC9Xbu1sPt53sgrtrX+inn/jMsnpfgzfeO+lsB55bOPOw2:0Daw7MC9XCO53sg5rXPjTSsl0Gv2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_ea62ee76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea62ee769f7c022f8443741081e8ae49e90904a8f048328ac72eaa30c58a6ca1"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:25"
  condition:
    hash.sha256(0, filesize) == "ea62ee769f7c022f8443741081e8ae49e90904a8f048328ac72eaa30c58a6ca1"
}
```

### Sample 93: `224dc35892d3df24`

| Field | Value |
|---|---|
| SHA-256 | `224dc35892d3df241b9d773363ccfcb05ff24189cf7de96783069848b786c0ca` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f3dc43bff5b2d1930ee6eff9d827e3f` |
| SHA-1 | `d5bff429ed766fc0714d6c1809a81a64bc12d64f` |
| SHA-256 | `224dc35892d3df241b9d773363ccfcb05ff24189cf7de96783069848b786c0ca` |
| SHA3-384 | `b6ffb8490c9862d590aa2a3ea2976b58269af9037e4f08689e1a39a4fc9d5f146efb5d29995a204ffaf30bf292c467f2` |
| TLSH | `T1B7A2D0BC225249EAC887D7BC2BF317A2AD35026895534C663AC5E3076E434F274937E1` |
| SSDEEP | `384:LGLz5nv4juxf/0XPPKh3z4VRlaITdIV1+Y5AsbBVth5P2dFJgGlzDpH7uNj1Jgw2:Lczaju1qblWrb39EFJgGlzDpbuR1Jj+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_224dc358
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "224dc35892d3df241b9d773363ccfcb05ff24189cf7de96783069848b786c0ca"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:22"
  condition:
    hash.sha256(0, filesize) == "224dc35892d3df241b9d773363ccfcb05ff24189cf7de96783069848b786c0ca"
}
```

### Sample 94: `2fab0ae2bcb1f7d0`

| Field | Value |
|---|---|
| SHA-256 | `2fab0ae2bcb1f7d031ae3e6112c82532e2f1b1b3999c462d58f2e599f681a2b4` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbecbd8d7c12cb97233d0856eb8553fa` |
| SHA-1 | `0cdd3e3eb128cc51e1de4f22374be58bc4b38e0f` |
| SHA-256 | `2fab0ae2bcb1f7d031ae3e6112c82532e2f1b1b3999c462d58f2e599f681a2b4` |
| SHA3-384 | `f074ad4415a0bb4aa02f30be5fd0e5cdbdd5273fe8adaa53534fc3d3b5eef07edb3ed8a2c091857acfb257b07afaa4ce` |
| TLSH | `T17092E0A5AE5BB88AD1EAAB75112E7033B2A20593030DCFD9B3AC62D5F0C1017857DF5D` |
| SSDEEP | `384:MX8FoU1J/5eCVxNUa2HL//KTdq9qGOgy/0Cpe4+v1RFp:tFl1J/XVxqVr//eoOBVsFp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_2fab0ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fab0ae2bcb1f7d031ae3e6112c82532e2f1b1b3999c462d58f2e599f681a2b4"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:20"
  condition:
    hash.sha256(0, filesize) == "2fab0ae2bcb1f7d031ae3e6112c82532e2f1b1b3999c462d58f2e599f681a2b4"
}
```

### Sample 95: `ec3b2457d48f1dba`

| Field | Value |
|---|---|
| SHA-256 | `ec3b2457d48f1dba9b8ca71dd89de10ef433f5f6de682ab42a2130d024866823` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3209e1081034163929cf323ad3646dd2` |
| SHA-1 | `62a5641e4698aab8b93cc40f7aa2a0992497506c` |
| SHA-256 | `ec3b2457d48f1dba9b8ca71dd89de10ef433f5f6de682ab42a2130d024866823` |
| SHA3-384 | `5fef4f86eec169b1d39370f35eb93923aba99053d5b6177415596085021ec0ed99785a1452b2859c6dd5507bb7724770` |
| TLSH | `T1A4B39CDBF64716A1C86246F007CB4BDE3E2322825F5789E33D6D213A6C791CB4D06B91` |
| SSDEEP | `1536:C7AUdB5VdhQlMHfBkIkk+WC6+iOg0i/LWi:C7AUdjV7TH/b+WC6+dg0iq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_ec3b2457
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec3b2457d48f1dba9b8ca71dd89de10ef433f5f6de682ab42a2130d024866823"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:18"
  condition:
    hash.sha256(0, filesize) == "ec3b2457d48f1dba9b8ca71dd89de10ef433f5f6de682ab42a2130d024866823"
}
```

### Sample 96: `94516ed729fd8f66`

| Field | Value |
|---|---|
| SHA-256 | `94516ed729fd8f667865ee3e6c94ad451ae9c255b99b8b9b2920bf4d89205a9e` |
| Family label | `Mirai` |
| File name | `debug.dbg` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ec8d10dc31842f0a1149cd407ecde90` |
| SHA-1 | `a24908233eae896e740e641297a61a6f5b0069d9` |
| SHA-256 | `94516ed729fd8f667865ee3e6c94ad451ae9c255b99b8b9b2920bf4d89205a9e` |
| SHA3-384 | `35e19ca41f2758c3f937c98aba27b1f24ec37fae6d3fda7e2d3a88ee1603814068afed436f881b08ebb0e44c89b36297` |
| TLSH | `T185D2F220904DE26FD25C137CD765C4DF604E9549AF88849810C4F063A7DADFAD6347DA` |
| SSDEEP | `384:MijEmUFUkj8a6Ds3JM2AT4FdPKR5FifpWBft60F8p0Djri2ByNeexNAiyCWCiG7E:Hkj8tb2Awq+c/b0OXinSiZW5G/Jy1OFk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_94516ed7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94516ed729fd8f667865ee3e6c94ad451ae9c255b99b8b9b2920bf4d89205a9e"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:16"
  condition:
    hash.sha256(0, filesize) == "94516ed729fd8f667865ee3e6c94ad451ae9c255b99b8b9b2920bf4d89205a9e"
}
```

### Sample 97: `da8595d1467da72c`

| Field | Value |
|---|---|
| SHA-256 | `da8595d1467da72c1f2e120420ab91e4a06d6cd065cbead1c9ce3a4d28011494` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-07-06 19:09:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b675d0bd6ddf42a2d9259a67ba66e32` |
| SHA-1 | `e4f6516a830f4b52c4048d9567af4d9574c5d944` |
| SHA-256 | `da8595d1467da72c1f2e120420ab91e4a06d6cd065cbead1c9ce3a4d28011494` |
| SHA3-384 | `c3a10901c6c7a0a3b3c98cc01771af2e3f60353f0272beb291701c5359ccef45fd2509229e24274972065cdc74ee21ba` |
| TLSH | `T13E92D0C5629B0276CC2DD237B25F81D794F6F98C52CC738416939DA9D88A83ECB6C64C` |
| SSDEEP | `384:ME2VapcuS61t2ce5NTzgWx4ggLgRAt9zDUoH7UB9u6+v1Rn:wQvKP5NPR6v0ifPUoIB2n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_da8595d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da8595d1467da72c1f2e120420ab91e4a06d6cd065cbead1c9ce3a4d28011494"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:14"
  condition:
    hash.sha256(0, filesize) == "da8595d1467da72c1f2e120420ab91e4a06d6cd065cbead1c9ce3a4d28011494"
}
```

### Sample 98: `5eea3112b54a0305`

| Field | Value |
|---|---|
| SHA-256 | `5eea3112b54a03056353f435e042c331073427d2cf4401829098c3e9cc5f19ab` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-06 19:06:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50514b9b645b6115642ac19bce164eb1` |
| SHA-1 | `b4a7a1df6ba304cb458f6e3fc8e6cea54f7ee555` |
| SHA-256 | `5eea3112b54a03056353f435e042c331073427d2cf4401829098c3e9cc5f19ab` |
| SHA3-384 | `9cd56ebbbbabd1cba885fed586923cf1aa0ac39b83344843dfcddfaaf1b13db09e9c71c55f47994202ebd22dff8ddf2d` |
| TLSH | `T124137D6566813C28AE9998371D7E1F0CBDAA83E2310491DDBFCB3CF18C59A9CD21871D` |
| SSDEEP | `768:TXRWNGxVi89GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnp:tlxocy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_5eea3112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5eea3112b54a03056353f435e042c331073427d2cf4401829098c3e9cc5f19ab"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-06 19:06:41"
  condition:
    hash.sha256(0, filesize) == "5eea3112b54a03056353f435e042c331073427d2cf4401829098c3e9cc5f19ab"
}
```

### Sample 99: `3ee6743541857a15`

| Field | Value |
|---|---|
| SHA-256 | `3ee6743541857a15df54cb62cdb44f492031824d284a8e5ccc5faf43cc21873a` |
| Family label | `unknown` |
| File name | `libpsl-5.dll` |
| File type | `exe` |
| First seen | `2026-07-06 19:00:23` |
| Reporter | `JAMESWT_WT` |
| Tags | `0zbqnac1t4dv2t2wuodv1m-com, booking, exe, sizyrotiqnsa-com, spam-ita, v0hkpadr04mbz5lkearqa-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87f456559c2aaaacf762b7e4fae67547` |
| SHA-1 | `8de79ee55a4dfde719b4c1c3050c6351dada7e85` |
| SHA-256 | `3ee6743541857a15df54cb62cdb44f492031824d284a8e5ccc5faf43cc21873a` |
| SHA3-384 | `d99e8ca3c20f70b243f672d34df36f0eae5c197f494d37ea1dc16c1100f7d024523a406f96930cc2f0c588f1f444e052` |
| IMPHASH | `8017092fc768a78ac8ff054ccfcdb949` |
| TLSH | `T19916BF02B7D41A94D467CA30C61FD732D2B2BD260731E28B1996D7492FB3B914F7A722` |
| SSDEEP | `98304:NR6GYB2WGYTaXiQDPS/If8pC5WwxbXfXBIeOW8CgLZ8MxpL5:N6GB7DPSicq1uR9CgLdr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_3ee67435
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ee6743541857a15df54cb62cdb44f492031824d284a8e5ccc5faf43cc21873a"
    family = "unknown"
    file_name = "libpsl-5.dll"
    file_type = "exe"
    first_seen = "2026-07-06 19:00:23"
  condition:
    hash.sha256(0, filesize) == "3ee6743541857a15df54cb62cdb44f492031824d284a8e5ccc5faf43cc21873a"
}
```

### Sample 100: `b3fb3762edd5c26d`

| Field | Value |
|---|---|
| SHA-256 | `b3fb3762edd5c26da3b55dcf98c7acc6e1c4ec7445c26a468c1659c33af4dc10` |
| Family label | `unknown` |
| File name | `kenwillzltd.zip` |
| File type | `zip` |
| First seen | `2026-07-06 19:00:10` |
| Reporter | `JAMESWT_WT` |
| Tags | `0zbqnac1t4dv2t2wuodv1m-com, booking, sizyrotiqnsa-com, spam-ita, v0hkpadr04mbz5lkearqa-com, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3395921c195b14deca0908aa0131d59` |
| SHA-1 | `9eba182c5c739b212090920391b688015b32c3d7` |
| SHA-256 | `b3fb3762edd5c26da3b55dcf98c7acc6e1c4ec7445c26a468c1659c33af4dc10` |
| SHA3-384 | `6e3ef947a403c320147f835ed95d3738df90fbccebd3522e0441283ae7e43d7ba7f35eb4804ffd7a7f5f71fa2636fdae` |
| TLSH | `T1A32633CFC8FAF2EED8B75020C6DC0992436740B69BD31E2B45524FD2E1E0B90A577999` |
| SSDEEP | `98304:SXrg18sb7bEU8oDoSJuoKAFXr8YO7A24FhLV/jvVLOrn40K0aBfrzd:S72lb7bEtpa78YO7A2oVvROrkpzd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_b3fb3762
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3fb3762edd5c26da3b55dcf98c7acc6e1c4ec7445c26a468c1659c33af4dc10"
    family = "unknown"
    file_name = "kenwillzltd.zip"
    file_type = "zip"
    first_seen = "2026-07-06 19:00:10"
  condition:
    hash.sha256(0, filesize) == "b3fb3762edd5c26da3b55dcf98c7acc6e1c4ec7445c26a468c1659c33af4dc10"
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
 * Generated: 2026-07-07T04:27:26.311463+00:00
 */

rule MalwareBazaar_unknown_001_9cbb1244
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cbb12444a989d93979727d190b7f61f558917569c513956a90970866447ab00"
    family = "unknown"
    file_name = "Details07.06.zip"
    file_type = "zip"
    first_seen = "2026-07-07 04:14:15"
  condition:
    hash.sha256(0, filesize) == "9cbb12444a989d93979727d190b7f61f558917569c513956a90970866447ab00"
}

rule MalwareBazaar_AgentTesla_002_094bc9cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "094bc9cce12a0be4ccd399a355cd3444fb189e1f58109d5f799ed1719cd81993"
    family = "AgentTesla"
    file_name = "Vessel Details.js"
    file_type = "js"
    first_seen = "2026-07-07 03:57:42"
  condition:
    hash.sha256(0, filesize) == "094bc9cce12a0be4ccd399a355cd3444fb189e1f58109d5f799ed1719cd81993"
}

rule MalwareBazaar_unknown_003_9580ade2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9580ade23d0a14b7c944beed4bc8b5a5ed838846a951b25a97108c3494a8e19d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 03:52:11"
  condition:
    hash.sha256(0, filesize) == "9580ade23d0a14b7c944beed4bc8b5a5ed838846a951b25a97108c3494a8e19d"
}

rule MalwareBazaar_Formbook_004_95817406
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95817406c54a108cb2728e5f5b75501e3d958f0b538d5f1cb283d8935d0d80f3"
    family = "Formbook"
    file_name = "NEW_MV_SHINNING_STAR_VESSEL_DETAILS.exe"
    file_type = "exe"
    first_seen = "2026-07-07 03:42:30"
  condition:
    hash.sha256(0, filesize) == "95817406c54a108cb2728e5f5b75501e3d958f0b538d5f1cb283d8935d0d80f3"
}

rule MalwareBazaar_RemcosRAT_005_5489a805
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5489a805b1e17f8c133f9947aa6b317524c7ee5a341bd3f2aee85b3a111f8f6a"
    family = "RemcosRAT"
    file_name = "德驭】INVOICE-0609 - HT 260615 (MTR26-06-13).scr"
    file_type = "exe"
    first_seen = "2026-07-07 03:33:43"
  condition:
    hash.sha256(0, filesize) == "5489a805b1e17f8c133f9947aa6b317524c7ee5a341bd3f2aee85b3a111f8f6a"
}

rule MalwareBazaar_unknown_006_5de8f963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5de8f96372fba00afca1eab7df600d5584e93b87ce9363cbfcb0ce44fd742b38"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 03:25:20"
  condition:
    hash.sha256(0, filesize) == "5de8f96372fba00afca1eab7df600d5584e93b87ce9363cbfcb0ce44fd742b38"
}

rule MalwareBazaar_unknown_007_6ee3cd19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee3cd19645816a60c51c362a125837d49e066ca0d0c1f03cc2a40f0a45739d2"
    family = "unknown"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-07 03:23:49"
  condition:
    hash.sha256(0, filesize) == "6ee3cd19645816a60c51c362a125837d49e066ca0d0c1f03cc2a40f0a45739d2"
}

rule MalwareBazaar_Mirai_008_4221c1ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4221c1eee1c15d74837a34ee1ccc5693271c4ad9570bada0f9bea03a1e104013"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-07 03:22:58"
  condition:
    hash.sha256(0, filesize) == "4221c1eee1c15d74837a34ee1ccc5693271c4ad9570bada0f9bea03a1e104013"
}

rule MalwareBazaar_AsyncRAT_009_0c62a122
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c62a122eba57c96a909e337501955b1bb2705c3ba56a6ef1d9b75f090404a34"
    family = "AsyncRAT"
    file_name = "SKJG09876545678900.js"
    file_type = "js"
    first_seen = "2026-07-07 03:05:03"
  condition:
    hash.sha256(0, filesize) == "0c62a122eba57c96a909e337501955b1bb2705c3ba56a6ef1d9b75f090404a34"
}

rule MalwareBazaar_AsyncRAT_010_80789973
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80789973e5d190760951dd7405369778d02644451b4888b4c45517dc5c0a75c0"
    family = "AsyncRAT"
    file_name = "HGF09876543456789000.js"
    file_type = "js"
    first_seen = "2026-07-07 03:04:29"
  condition:
    hash.sha256(0, filesize) == "80789973e5d190760951dd7405369778d02644451b4888b4c45517dc5c0a75c0"
}

rule MalwareBazaar_unknown_011_e2142a12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2142a125e3a4f48394f0fdbb8f8255a17332d6d935c579ea5471cde59a6b40c"
    family = "unknown"
    file_name = "e2142a125e3a4f48394f0fdbb8f8255a17332d6d935c579ea5471cde59a6b40c"
    file_type = "elf"
    first_seen = "2026-07-07 03:01:50"
  condition:
    hash.sha256(0, filesize) == "e2142a125e3a4f48394f0fdbb8f8255a17332d6d935c579ea5471cde59a6b40c"
}

rule MalwareBazaar_unknown_012_72933ef5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72933ef50ec23c6a08d001677636dcf2a4b49fdb82437dccb1c806d147786054"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 02:52:16"
  condition:
    hash.sha256(0, filesize) == "72933ef50ec23c6a08d001677636dcf2a4b49fdb82437dccb1c806d147786054"
}

rule MalwareBazaar_ValleyRAT_013_40d8a884
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40d8a88490a6c1a847de73aaf34d9bf440e98232e6f568bd33ceaf77a0b15a30"
    family = "ValleyRAT"
    file_name = "08b9ae7e5a6abdeb98f18bc1e22b2341.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:33"
  condition:
    hash.sha256(0, filesize) == "40d8a88490a6c1a847de73aaf34d9bf440e98232e6f568bd33ceaf77a0b15a30"
}

rule MalwareBazaar_RatonRAT_014_1fc8fb8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fc8fb8d201439bb948274e247603eeec57c830e1ba49d05fdb361256103be45"
    family = "RatonRAT"
    file_name = "xeno.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:29"
  condition:
    hash.sha256(0, filesize) == "1fc8fb8d201439bb948274e247603eeec57c830e1ba49d05fdb361256103be45"
}

rule MalwareBazaar_RatonRAT_015_6bedbe1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bedbe1c3e8eceb69531c82728290394fabf5475a0a830e807a89ccbcc92bd18"
    family = "RatonRAT"
    file_name = "Delta.289.12323.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:27"
  condition:
    hash.sha256(0, filesize) == "6bedbe1c3e8eceb69531c82728290394fabf5475a0a830e807a89ccbcc92bd18"
}

rule MalwareBazaar_RatonRAT_016_005945a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "005945a8e74e5d961d46014e3fd9129cbe213cac8de08423624c5d6fdc156614"
    family = "RatonRAT"
    file_name = "045009f3c826acbe3decbd486ff24ec9.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:24"
  condition:
    hash.sha256(0, filesize) == "005945a8e74e5d961d46014e3fd9129cbe213cac8de08423624c5d6fdc156614"
}

rule MalwareBazaar_ValleyRAT_017_b8979e31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8979e31b0e18fd57d4e0a7512e9e0109d68312fd9a5837d62fcb11ace457c2f"
    family = "ValleyRAT"
    file_name = "b8979e31b0e18fd57d4e0a7512e9e0109d68312fd9a58.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:21"
  condition:
    hash.sha256(0, filesize) == "b8979e31b0e18fd57d4e0a7512e9e0109d68312fd9a5837d62fcb11ace457c2f"
}

rule MalwareBazaar_RemcosRAT_018_b4fdd082
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4fdd082603796a0bd9a765ca326fe643e8b4bc62e5fa9d472cadb221c509711"
    family = "RemcosRAT"
    file_name = "106264855SPECIFICATION.js"
    file_type = "js"
    first_seen = "2026-07-07 02:45:18"
  condition:
    hash.sha256(0, filesize) == "b4fdd082603796a0bd9a765ca326fe643e8b4bc62e5fa9d472cadb221c509711"
}

rule MalwareBazaar_QuasarRAT_019_d5cc6033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5cc60331e5cdf13972eb713eec4b1dee1c24d2bb3bd4140e2e7ae9c52eb8c38"
    family = "QuasarRAT"
    file_name = "Client-built.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:15"
  condition:
    hash.sha256(0, filesize) == "d5cc60331e5cdf13972eb713eec4b1dee1c24d2bb3bd4140e2e7ae9c52eb8c38"
}

rule MalwareBazaar_RedLineStealer_020_cbb75322
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbb753220731503e7974588a48305dcf19d8528d7299f695e05211f845a8f720"
    family = "RedLineStealer"
    file_name = "0cba9117934ea7e8457efacdd87beff5.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:12"
  condition:
    hash.sha256(0, filesize) == "cbb753220731503e7974588a48305dcf19d8528d7299f695e05211f845a8f720"
}

rule MalwareBazaar_AsyncRAT_021_5f6e4a8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f6e4a8d17a5d15cc001300ad8373515b8f548c0ab129fe67ef597a59467423f"
    family = "AsyncRAT"
    file_name = "5f6e4a8d17a5d15cc001300ad8373515b8f548c0ab129.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:08"
  condition:
    hash.sha256(0, filesize) == "5f6e4a8d17a5d15cc001300ad8373515b8f548c0ab129fe67ef597a59467423f"
}

rule MalwareBazaar_NanoCore_022_c6ad18d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6ad18d01c5ee9f6edbb8c79f8ff8786762eb63d1b341997eb39f51a67f4ae7b"
    family = "NanoCore"
    file_name = "1028037eae53b90c967d82953f20d8e6.exe"
    file_type = "exe"
    first_seen = "2026-07-07 02:45:05"
  condition:
    hash.sha256(0, filesize) == "c6ad18d01c5ee9f6edbb8c79f8ff8786762eb63d1b341997eb39f51a67f4ae7b"
}

rule MalwareBazaar_unknown_023_f2f077f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2f077f3c330a5a4a0732e692d7ae938db5897f6b97193db9c85de91fbf34ced"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-07 02:37:59"
  condition:
    hash.sha256(0, filesize) == "f2f077f3c330a5a4a0732e692d7ae938db5897f6b97193db9c85de91fbf34ced"
}

rule MalwareBazaar_Mirai_024_9d50989f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d50989f6ff8bb05cf9839d2d888e6e90a8e137b2670140efea5ff5398230e83"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-07 02:37:46"
  condition:
    hash.sha256(0, filesize) == "9d50989f6ff8bb05cf9839d2d888e6e90a8e137b2670140efea5ff5398230e83"
}

rule MalwareBazaar_Mirai_025_3f7309f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f7309f58c8e64d475ecfe5b81cc11ea804f39498f9956df35dec7ecdb508c96"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-07 02:36:57"
  condition:
    hash.sha256(0, filesize) == "3f7309f58c8e64d475ecfe5b81cc11ea804f39498f9956df35dec7ecdb508c96"
}

rule MalwareBazaar_BlackMatter_026_1ba2b89f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ba2b89f9601d1923c88bcb1643ab6b4c10a83dbae02975dbfafe76ebaac0431"
    family = "BlackMatter"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 02:10:11"
  condition:
    hash.sha256(0, filesize) == "1ba2b89f9601d1923c88bcb1643ab6b4c10a83dbae02975dbfafe76ebaac0431"
}

rule MalwareBazaar_Mirai_027_e1e3829d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1e3829d5bdae0315b4fbe9e296dd642514570f5f07a86c0aacc86fd121aa36f"
    family = "Mirai"
    file_name = "bin.sh"
    file_type = "elf"
    first_seen = "2026-07-07 01:59:55"
  condition:
    hash.sha256(0, filesize) == "e1e3829d5bdae0315b4fbe9e296dd642514570f5f07a86c0aacc86fd121aa36f"
}

rule MalwareBazaar_unknown_028_393683cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "393683cb84df747b671414d49ac04eef066618216c26927b4ad4532ba2d9b2ad"
    family = "unknown"
    file_name = "393683cb84df747b671414d49ac04eef066618216c26927b4ad4532ba2d9b2ad"
    file_type = "elf"
    first_seen = "2026-07-07 01:22:52"
  condition:
    hash.sha256(0, filesize) == "393683cb84df747b671414d49ac04eef066618216c26927b4ad4532ba2d9b2ad"
}

rule MalwareBazaar_unknown_029_c390b9e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c390b9e50b5aa198e6985219929ee564fd019a1d8a54c069ecf3df161f35f624"
    family = "unknown"
    file_name = "c390b9e50b5aa198e6985219929ee564fd019a1d8a54c069ecf3df161f35f624"
    file_type = "unknown"
    first_seen = "2026-07-07 01:17:25"
  condition:
    hash.sha256(0, filesize) == "c390b9e50b5aa198e6985219929ee564fd019a1d8a54c069ecf3df161f35f624"
}

rule MalwareBazaar_unknown_030_8770a3fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8770a3fead8861b818e32c832fc3411699dbb35e2f178ca0be6b2d7f9bc48140"
    family = "unknown"
    file_name = "8770a3fead8861b818e32c832fc3411699dbb35e2f178ca0be6b2d7f9bc48140"
    file_type = "sh"
    first_seen = "2026-07-07 01:11:30"
  condition:
    hash.sha256(0, filesize) == "8770a3fead8861b818e32c832fc3411699dbb35e2f178ca0be6b2d7f9bc48140"
}

rule MalwareBazaar_unknown_031_4a8aa017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a8aa017e3bda8b370335b21c58a8918c5ea163e8b4364837fb15fccdbd15e02"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 01:10:10"
  condition:
    hash.sha256(0, filesize) == "4a8aa017e3bda8b370335b21c58a8918c5ea163e8b4364837fb15fccdbd15e02"
}

rule MalwareBazaar_unknown_032_d117ee4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d117ee4a244959625a761696a9c719d161e6b11a7e880ada14ec8dde3f88d0ef"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 01:10:07"
  condition:
    hash.sha256(0, filesize) == "d117ee4a244959625a761696a9c719d161e6b11a7e880ada14ec8dde3f88d0ef"
}

rule MalwareBazaar_unknown_033_3aac5e3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3aac5e3fce6038cf911ac31dd206a1109c78177d26b382412797d9da9840af53"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 01:08:58"
  condition:
    hash.sha256(0, filesize) == "3aac5e3fce6038cf911ac31dd206a1109c78177d26b382412797d9da9840af53"
}

rule MalwareBazaar_unknown_034_dcd93e03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcd93e03208c3f5d2f946023e2bd0e13c58ba275e71208921e62d2ddc03762b4"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-07 01:05:01"
  condition:
    hash.sha256(0, filesize) == "dcd93e03208c3f5d2f946023e2bd0e13c58ba275e71208921e62d2ddc03762b4"
}

rule MalwareBazaar_CoinMiner_035_e8bc6206
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8bc62068f3ec8434e4658afea482cdb340b88ddaae63c28dfcf6140c82620a1"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 00:57:38"
  condition:
    hash.sha256(0, filesize) == "e8bc62068f3ec8434e4658afea482cdb340b88ddaae63c28dfcf6140c82620a1"
}

rule MalwareBazaar_unknown_036_32f4dc44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f4dc44d81286d23683761744153d06c37df34eb6e9c95de020bfc3fccf74fb"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 00:52:12"
  condition:
    hash.sha256(0, filesize) == "32f4dc44d81286d23683761744153d06c37df34eb6e9c95de020bfc3fccf74fb"
}

rule MalwareBazaar_Mirai_037_4196d8f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4196d8f75e231e009033437d53451e3e30a6487f8ead8e411be11a9b3ace682d"
    family = "Mirai"
    file_name = "johenlastgen.sh"
    file_type = "sh"
    first_seen = "2026-07-07 00:50:08"
  condition:
    hash.sha256(0, filesize) == "4196d8f75e231e009033437d53451e3e30a6487f8ead8e411be11a9b3ace682d"
}

rule MalwareBazaar_CoinMiner_038_3afca0f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3afca0f0f28a8e8a57ea459ec7bbc8ec03082e8c818b521687c36e9375fef784"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 00:27:42"
  condition:
    hash.sha256(0, filesize) == "3afca0f0f28a8e8a57ea459ec7bbc8ec03082e8c818b521687c36e9375fef784"
}

rule MalwareBazaar_CoinMiner_039_caccb7aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caccb7aa5c67860ab942576d7466e126eb94c538a91bb4e7d2cdf3eb9992f818"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-06 23:57:32"
  condition:
    hash.sha256(0, filesize) == "caccb7aa5c67860ab942576d7466e126eb94c538a91bb4e7d2cdf3eb9992f818"
}

rule MalwareBazaar_unknown_040_8cc325c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cc325c1243fc3fe72ac7875646dce2aa70973a8b8b6877d9537ea90fb4e1b02"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-06 23:52:21"
  condition:
    hash.sha256(0, filesize) == "8cc325c1243fc3fe72ac7875646dce2aa70973a8b8b6877d9537ea90fb4e1b02"
}

rule MalwareBazaar_unknown_041_795dd9b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "795dd9b56b65ddab01a5ff024232d4b94aad299ccdfa0da940a9804f1a6bcbb5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-06 23:48:08"
  condition:
    hash.sha256(0, filesize) == "795dd9b56b65ddab01a5ff024232d4b94aad299ccdfa0da940a9804f1a6bcbb5"
}

rule MalwareBazaar_AgentTesla_042_e3070290
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3070290906a9eda5855e73545e4a349e3db06a6be3479e46ec19b26dd073c33"
    family = "AgentTesla"
    file_name = "Muestra y especificaciones del producto.exe"
    file_type = "exe"
    first_seen = "2026-07-06 23:41:25"
  condition:
    hash.sha256(0, filesize) == "e3070290906a9eda5855e73545e4a349e3db06a6be3479e46ec19b26dd073c33"
}

rule MalwareBazaar_unknown_043_a7365f1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7365f1b0defac950f0d60df3b1685f1e2f0d5d75f328a01c1cfaaa71f0690c4"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-06 23:39:49"
  condition:
    hash.sha256(0, filesize) == "a7365f1b0defac950f0d60df3b1685f1e2f0d5d75f328a01c1cfaaa71f0690c4"
}

rule MalwareBazaar_CoinMiner_044_ca9c127d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca9c127d65c5e9839cf02053e8dffb3869f086bd606badbfbf866e348db12612"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-06 23:30:00"
  condition:
    hash.sha256(0, filesize) == "ca9c127d65c5e9839cf02053e8dffb3869f086bd606badbfbf866e348db12612"
}

rule MalwareBazaar_unknown_045_b2609edc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2609edca5ece9fa595ae63c619ea84f966280e1c831fbee0e8be4fca20d801a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-06 22:52:11"
  condition:
    hash.sha256(0, filesize) == "b2609edca5ece9fa595ae63c619ea84f966280e1c831fbee0e8be4fca20d801a"
}

rule MalwareBazaar_Mirai_046_1fc2619a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fc2619aa6e2dec3609bb34769017ec200f01b9d2be51a6e3a4c1dae5a148019"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-06 22:41:33"
  condition:
    hash.sha256(0, filesize) == "1fc2619aa6e2dec3609bb34769017ec200f01b9d2be51a6e3a4c1dae5a148019"
}

rule MalwareBazaar_Mirai_047_82d1721a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82d1721a528d70301513d391d0e356a69ebc8af40e64f2546cccfadd08f3f156"
    family = "Mirai"
    file_name = "tmpsl"
    file_type = "elf"
    first_seen = "2026-07-06 22:41:32"
  condition:
    hash.sha256(0, filesize) == "82d1721a528d70301513d391d0e356a69ebc8af40e64f2546cccfadd08f3f156"
}

rule MalwareBazaar_Mirai_048_1a79ab70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a79ab7090db6c42752c45524edae6a9c042afc59d6754748a5dd3e3154a6ad0"
    family = "Mirai"
    file_name = "tarm"
    file_type = "elf"
    first_seen = "2026-07-06 22:41:30"
  condition:
    hash.sha256(0, filesize) == "1a79ab7090db6c42752c45524edae6a9c042afc59d6754748a5dd3e3154a6ad0"
}

rule MalwareBazaar_Mirai_049_938f4f03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "938f4f03d862992f23684eb6f7f50ebdd06a7283f6d4a3b2626ee7610e6a9294"
    family = "Mirai"
    file_name = "tarm5"
    file_type = "elf"
    first_seen = "2026-07-06 22:41:28"
  condition:
    hash.sha256(0, filesize) == "938f4f03d862992f23684eb6f7f50ebdd06a7283f6d4a3b2626ee7610e6a9294"
}

rule MalwareBazaar_Mirai_050_ff154b90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff154b904f5a717d7a14eee46fe8439e3c5b68c80f151ce958a64b24884f1c6f"
    family = "Mirai"
    file_name = "tarm6"
    file_type = "elf"
    first_seen = "2026-07-06 22:41:27"
  condition:
    hash.sha256(0, filesize) == "ff154b904f5a717d7a14eee46fe8439e3c5b68c80f151ce958a64b24884f1c6f"
}

rule MalwareBazaar_unknown_051_a2ff2513
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2ff251395e9f34a538c6692e41104eb4646fdaed03c06420bcb348b90162aba"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-06 21:52:13"
  condition:
    hash.sha256(0, filesize) == "a2ff251395e9f34a538c6692e41104eb4646fdaed03c06420bcb348b90162aba"
}

rule MalwareBazaar_unknown_052_3fcc8667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fcc8667d73fc631206bd32191db3d5ab96667a1fe6e9d67e15892e0f3a9f122"
    family = "unknown"
    file_name = "mwZhV1.ps1"
    file_type = "ps1"
    first_seen = "2026-07-06 21:34:48"
  condition:
    hash.sha256(0, filesize) == "3fcc8667d73fc631206bd32191db3d5ab96667a1fe6e9d67e15892e0f3a9f122"
}

rule MalwareBazaar_unknown_053_97bef893
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97bef8934a732bbfd6e8bfb1fa68d42c5604b44beb8c4fc5e34c2020a02b6e28"
    family = "unknown"
    file_name = "o"
    file_type = "unknown"
    first_seen = "2026-07-06 21:07:09"
  condition:
    hash.sha256(0, filesize) == "97bef8934a732bbfd6e8bfb1fa68d42c5604b44beb8c4fc5e34c2020a02b6e28"
}

rule MalwareBazaar_unknown_054_30c015f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30c015f869758be97e2d4454830241d67f8f8095e6cf38a60d8372070d0df0ef"
    family = "unknown"
    file_name = "30c015f869758be97e2d4454830241d67f8f8095e6cf38a60d8372070d0df0ef"
    file_type = "unknown"
    first_seen = "2026-07-06 20:31:41"
  condition:
    hash.sha256(0, filesize) == "30c015f869758be97e2d4454830241d67f8f8095e6cf38a60d8372070d0df0ef"
}

rule MalwareBazaar_unknown_055_5b64550c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b64550c87fc3a579694133117a265c756fe36cd31de5ef0b87a6f2faae7f791"
    family = "unknown"
    file_name = "5b64550c87fc3a579694133117a265c756fe36cd31de5ef0b87a6f2faae7f791"
    file_type = "sh"
    first_seen = "2026-07-06 20:31:39"
  condition:
    hash.sha256(0, filesize) == "5b64550c87fc3a579694133117a265c756fe36cd31de5ef0b87a6f2faae7f791"
}

rule MalwareBazaar_unknown_056_810d409a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "810d409aef915e09eaa59b1cb8df60559c72b2da1ac0ab14ec875fbe58ac03d9"
    family = "unknown"
    file_name = "810d409aef915e09eaa59b1cb8df60559c72b2da1ac0ab14ec875fbe58ac03d9"
    file_type = "sh"
    first_seen = "2026-07-06 20:31:37"
  condition:
    hash.sha256(0, filesize) == "810d409aef915e09eaa59b1cb8df60559c72b2da1ac0ab14ec875fbe58ac03d9"
}

rule MalwareBazaar_unknown_057_7ba090e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ba090e0c3807dbccd450d7125b48195e65dbea71187aec571ae69d15d46f9ba"
    family = "unknown"
    file_name = "7ba090e0c3807dbccd450d7125b48195e65dbea71187aec571ae69d15d46f9ba"
    file_type = "unknown"
    first_seen = "2026-07-06 20:31:34"
  condition:
    hash.sha256(0, filesize) == "7ba090e0c3807dbccd450d7125b48195e65dbea71187aec571ae69d15d46f9ba"
}

rule MalwareBazaar_Mirai_058_cc668803
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc668803553940c2c7ee1f6e7929d487b7c07fc41d8bc3f19c773bb67bf27eaf"
    family = "Mirai"
    file_name = "Mozi.a"
    file_type = "elf"
    first_seen = "2026-07-06 20:27:10"
  condition:
    hash.sha256(0, filesize) == "cc668803553940c2c7ee1f6e7929d487b7c07fc41d8bc3f19c773bb67bf27eaf"
}

rule MalwareBazaar_unknown_059_4b06e4c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b06e4c33a3ed62617c059ef47629b426971f2796f486449e19ae421f229fc16"
    family = "unknown"
    file_name = "Swift ref. TT 810-363295460.js"
    file_type = "js"
    first_seen = "2026-07-06 20:25:49"
  condition:
    hash.sha256(0, filesize) == "4b06e4c33a3ed62617c059ef47629b426971f2796f486449e19ae421f229fc16"
}

rule MalwareBazaar_unknown_060_29e90df3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29e90df3f89e343059d0925b933b09237457401a1a1278fb1275fa3c5c80ef29"
    family = "unknown"
    file_name = "29e90df3f89e343059d0925b933b09237457401a1a1278fb1275fa3c5c80ef29"
    file_type = "exe"
    first_seen = "2026-07-06 20:15:13"
  condition:
    hash.sha256(0, filesize) == "29e90df3f89e343059d0925b933b09237457401a1a1278fb1275fa3c5c80ef29"
}

rule MalwareBazaar_unknown_061_0f9e9e3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f9e9e3f242dce4f85b98819a8b9db4d28634e5147a832e3f4c24218eb1c8489"
    family = "unknown"
    file_name = "Pivlex_CRM_API_Documentation.zip"
    file_type = "zip"
    first_seen = "2026-07-06 19:55:36"
  condition:
    hash.sha256(0, filesize) == "0f9e9e3f242dce4f85b98819a8b9db4d28634e5147a832e3f4c24218eb1c8489"
}

rule MalwareBazaar_unknown_062_b94f04ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b94f04ed23e299dcabcddbf467dfe029f839bda0d5250f7c983d1ade04aa23d3"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-06 19:53:08"
  condition:
    hash.sha256(0, filesize) == "b94f04ed23e299dcabcddbf467dfe029f839bda0d5250f7c983d1ade04aa23d3"
}

rule MalwareBazaar_unknown_063_c45d98ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c45d98ff74ce79277bcb8e298115511b618e0b94bff33dddec56a440afae59b0"
    family = "unknown"
    file_name = "dg.mips"
    file_type = "elf"
    first_seen = "2026-07-06 19:51:32"
  condition:
    hash.sha256(0, filesize) == "c45d98ff74ce79277bcb8e298115511b618e0b94bff33dddec56a440afae59b0"
}

rule MalwareBazaar_Mirai_064_72cdf2c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72cdf2c971f2a498a7bc1ea88e248945e8adf6e946273db0c5a533e8f0c0eae9"
    family = "Mirai"
    file_name = "m68k.ghost"
    file_type = "elf"
    first_seen = "2026-07-06 19:50:54"
  condition:
    hash.sha256(0, filesize) == "72cdf2c971f2a498a7bc1ea88e248945e8adf6e946273db0c5a533e8f0c0eae9"
}

rule MalwareBazaar_Mirai_065_e065ef98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e065ef98932486261dd7fcb412521e987b0884b1e9feddf25daae2ad7a52420c"
    family = "Mirai"
    file_name = "i686.ghost"
    file_type = "elf"
    first_seen = "2026-07-06 19:50:17"
  condition:
    hash.sha256(0, filesize) == "e065ef98932486261dd7fcb412521e987b0884b1e9feddf25daae2ad7a52420c"
}

rule MalwareBazaar_unknown_066_cf284583
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf284583db104e7032876733467e77b25637a8a5d908c7b0d1582bac6c576eb7"
    family = "unknown"
    file_name = "cf284583db104e7032876733467e77b25637a8a5d908c7b0d1582bac6c576eb7"
    file_type = "sh"
    first_seen = "2026-07-06 19:46:46"
  condition:
    hash.sha256(0, filesize) == "cf284583db104e7032876733467e77b25637a8a5d908c7b0d1582bac6c576eb7"
}

rule MalwareBazaar_unknown_067_981cc900
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "981cc9005fb224a31130f9b8185976f51a0c705cde4e3d5818bda3a726f80826"
    family = "unknown"
    file_name = "981cc9005fb224a31130f9b8185976f51a0c705cde4e3d5818bda3a726f80826"
    file_type = "exe"
    first_seen = "2026-07-06 19:33:56"
  condition:
    hash.sha256(0, filesize) == "981cc9005fb224a31130f9b8185976f51a0c705cde4e3d5818bda3a726f80826"
}

rule MalwareBazaar_Adware_Techsnab_068_863454d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "863454d9d304f37003a7d301e543fb08a7fe6ac7853f1405ded6f3f64ba1532e"
    family = "Adware.Techsnab"
    file_name = "863454d9d304f37003a7d301e543fb08a7fe6ac7853f1405ded6f3f64ba1532e.ps1"
    file_type = "ps1"
    first_seen = "2026-07-06 19:33:42"
  condition:
    hash.sha256(0, filesize) == "863454d9d304f37003a7d301e543fb08a7fe6ac7853f1405ded6f3f64ba1532e"
}

rule MalwareBazaar_Adware_Techsnab_069_47575a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47575a1410088886820cff310c133c2501874381ea30174cc05077b3c208ad4d"
    family = "Adware.Techsnab"
    file_name = "47575a1410088886820cff310c133c2501874381ea30174cc05077b3c208ad4d.ps1"
    file_type = "ps1"
    first_seen = "2026-07-06 19:33:31"
  condition:
    hash.sha256(0, filesize) == "47575a1410088886820cff310c133c2501874381ea30174cc05077b3c208ad4d"
}

rule MalwareBazaar_Mirai_070_576d30ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "576d30ad74e1b571446c130d5e2fc440f422432cd8b2df8f1a1de9eaaf1b580a"
    family = "Mirai"
    file_name = "armv7l.ghost"
    file_type = "elf"
    first_seen = "2026-07-06 19:22:02"
  condition:
    hash.sha256(0, filesize) == "576d30ad74e1b571446c130d5e2fc440f422432cd8b2df8f1a1de9eaaf1b580a"
}

rule MalwareBazaar_Mirai_071_47417977
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "474179770124402269511865d3b4677e9ccb7e0423049df67e937936888a96e0"
    family = "Mirai"
    file_name = "mipsel.ghost"
    file_type = "elf"
    first_seen = "2026-07-06 19:15:58"
  condition:
    hash.sha256(0, filesize) == "474179770124402269511865d3b4677e9ccb7e0423049df67e937936888a96e0"
}

rule MalwareBazaar_Mirai_072_277e1e7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "277e1e7a41cdc47542136aee56cf6850cb940baf9f4d9d7250a1672b1771f204"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-06 19:14:28"
  condition:
    hash.sha256(0, filesize) == "277e1e7a41cdc47542136aee56cf6850cb940baf9f4d9d7250a1672b1771f204"
}

rule MalwareBazaar_Mirai_073_80dec65a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80dec65aefed608345d3baf92464aead3333ea1e880ea0c04c6ccb136c839436"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-06 19:14:11"
  condition:
    hash.sha256(0, filesize) == "80dec65aefed608345d3baf92464aead3333ea1e880ea0c04c6ccb136c839436"
}

rule MalwareBazaar_Mirai_074_2b9fa53f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b9fa53f8372c4413775650e9383d4f552aab63ffe298c21186674c3a4527f7e"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-06 19:14:00"
  condition:
    hash.sha256(0, filesize) == "2b9fa53f8372c4413775650e9383d4f552aab63ffe298c21186674c3a4527f7e"
}

rule MalwareBazaar_Mirai_075_83f1f077
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83f1f077cd9cc9e28452ccd254cae3c798fbc83e8dfa7377cd896dc8063ed0b4"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-06 19:13:52"
  condition:
    hash.sha256(0, filesize) == "83f1f077cd9cc9e28452ccd254cae3c798fbc83e8dfa7377cd896dc8063ed0b4"
}

rule MalwareBazaar_Mirai_076_4e753042
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e753042b8710bff8c99e045663b43c907c1a2dff5c1a3fc5947af0525978f33"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-06 19:13:37"
  condition:
    hash.sha256(0, filesize) == "4e753042b8710bff8c99e045663b43c907c1a2dff5c1a3fc5947af0525978f33"
}

rule MalwareBazaar_Mirai_077_5a1100ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a1100bac5fa923697e05864a0c8e362e5c50638421f572fbb4abb3b99f10c73"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-06 19:13:30"
  condition:
    hash.sha256(0, filesize) == "5a1100bac5fa923697e05864a0c8e362e5c50638421f572fbb4abb3b99f10c73"
}

rule MalwareBazaar_Mirai_078_4fc8c90b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fc8c90b927b80081134e6ef7c3b471b6d6679270a9705a90ed1a9fcd1cc6979"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-06 19:13:20"
  condition:
    hash.sha256(0, filesize) == "4fc8c90b927b80081134e6ef7c3b471b6d6679270a9705a90ed1a9fcd1cc6979"
}

rule MalwareBazaar_Mirai_079_ef9686c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef9686c22bbbfd18eb7402292bf730396675b00fd35e575bfdecca683d06007f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-06 19:13:03"
  condition:
    hash.sha256(0, filesize) == "ef9686c22bbbfd18eb7402292bf730396675b00fd35e575bfdecca683d06007f"
}

rule MalwareBazaar_Mirai_080_9c7a29eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c7a29eb83b5321700242247eb96b1aed5b141ef1b5adc6f1fe3489567e2907b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-06 19:12:55"
  condition:
    hash.sha256(0, filesize) == "9c7a29eb83b5321700242247eb96b1aed5b141ef1b5adc6f1fe3489567e2907b"
}

rule MalwareBazaar_Mirai_081_fe1789de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe1789defdc5b8ddfe6f89d3b46711b2f469f31a8b7b933d924c4946f1b8bb15"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-06 19:12:32"
  condition:
    hash.sha256(0, filesize) == "fe1789defdc5b8ddfe6f89d3b46711b2f469f31a8b7b933d924c4946f1b8bb15"
}

rule MalwareBazaar_Mirai_082_f09b2a34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f09b2a34fe99172cea1bde32a741d88e35a7929004e408ea25690467fcb17171"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:45"
  condition:
    hash.sha256(0, filesize) == "f09b2a34fe99172cea1bde32a741d88e35a7929004e408ea25690467fcb17171"
}

rule MalwareBazaar_Mirai_083_6cc4c210
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cc4c210350ead3c781a49ab47cbb19b72439b078826a6cf1ebd06bad21fc45d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:43"
  condition:
    hash.sha256(0, filesize) == "6cc4c210350ead3c781a49ab47cbb19b72439b078826a6cf1ebd06bad21fc45d"
}

rule MalwareBazaar_Mirai_084_051b8ecb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "051b8ecbadfebcc4b5d799e95850be6453a59c0aeb9b5749a2d6496df750e8f1"
    family = "Mirai"
    file_name = "armv5l.ghost"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:41"
  condition:
    hash.sha256(0, filesize) == "051b8ecbadfebcc4b5d799e95850be6453a59c0aeb9b5749a2d6496df750e8f1"
}

rule MalwareBazaar_Mirai_085_78af04bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78af04bcad709ab444daa65faff1b3eb8c9f96f06cd410bf813c476bae331845"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:39"
  condition:
    hash.sha256(0, filesize) == "78af04bcad709ab444daa65faff1b3eb8c9f96f06cd410bf813c476bae331845"
}

rule MalwareBazaar_Mirai_086_06faf46d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06faf46de9d8f10ed2105832aae85584ef20dfe3aa24e572608044b61347ac44"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:36"
  condition:
    hash.sha256(0, filesize) == "06faf46de9d8f10ed2105832aae85584ef20dfe3aa24e572608044b61347ac44"
}

rule MalwareBazaar_Mirai_087_977943f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "977943f436219be2f612a5dde5e39ccb904606c6e34f9e76e75af31b98c24550"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:34"
  condition:
    hash.sha256(0, filesize) == "977943f436219be2f612a5dde5e39ccb904606c6e34f9e76e75af31b98c24550"
}

rule MalwareBazaar_Mirai_088_45f9416f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45f9416fc1d42cf2f14a381346665e8a8642aa10c47ee554770626b7fdedd2c3"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:33"
  condition:
    hash.sha256(0, filesize) == "45f9416fc1d42cf2f14a381346665e8a8642aa10c47ee554770626b7fdedd2c3"
}

rule MalwareBazaar_Mirai_089_60e17abb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60e17abbe2312405cda7ea5de18b632abcb7e4e20eed09ec1bec9c7351e90884"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:30"
  condition:
    hash.sha256(0, filesize) == "60e17abbe2312405cda7ea5de18b632abcb7e4e20eed09ec1bec9c7351e90884"
}

rule MalwareBazaar_Mirai_090_329a84a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "329a84a476ebb1c17958dacf6a19488150038b955f8b66a0c241748626c75b89"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:28"
  condition:
    hash.sha256(0, filesize) == "329a84a476ebb1c17958dacf6a19488150038b955f8b66a0c241748626c75b89"
}

rule MalwareBazaar_Mirai_091_b6c75912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6c75912dc0fb738b35e2c0706fb7b9c964e7644c6bcb0662165c89a7d81cff5"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:26"
  condition:
    hash.sha256(0, filesize) == "b6c75912dc0fb738b35e2c0706fb7b9c964e7644c6bcb0662165c89a7d81cff5"
}

rule MalwareBazaar_Mirai_092_ea62ee76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea62ee769f7c022f8443741081e8ae49e90904a8f048328ac72eaa30c58a6ca1"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:25"
  condition:
    hash.sha256(0, filesize) == "ea62ee769f7c022f8443741081e8ae49e90904a8f048328ac72eaa30c58a6ca1"
}

rule MalwareBazaar_Mirai_093_224dc358
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "224dc35892d3df241b9d773363ccfcb05ff24189cf7de96783069848b786c0ca"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:22"
  condition:
    hash.sha256(0, filesize) == "224dc35892d3df241b9d773363ccfcb05ff24189cf7de96783069848b786c0ca"
}

rule MalwareBazaar_Mirai_094_2fab0ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fab0ae2bcb1f7d031ae3e6112c82532e2f1b1b3999c462d58f2e599f681a2b4"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:20"
  condition:
    hash.sha256(0, filesize) == "2fab0ae2bcb1f7d031ae3e6112c82532e2f1b1b3999c462d58f2e599f681a2b4"
}

rule MalwareBazaar_Mirai_095_ec3b2457
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec3b2457d48f1dba9b8ca71dd89de10ef433f5f6de682ab42a2130d024866823"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:18"
  condition:
    hash.sha256(0, filesize) == "ec3b2457d48f1dba9b8ca71dd89de10ef433f5f6de682ab42a2130d024866823"
}

rule MalwareBazaar_Mirai_096_94516ed7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94516ed729fd8f667865ee3e6c94ad451ae9c255b99b8b9b2920bf4d89205a9e"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:16"
  condition:
    hash.sha256(0, filesize) == "94516ed729fd8f667865ee3e6c94ad451ae9c255b99b8b9b2920bf4d89205a9e"
}

rule MalwareBazaar_Mirai_097_da8595d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da8595d1467da72c1f2e120420ab91e4a06d6cd065cbead1c9ce3a4d28011494"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-06 19:09:14"
  condition:
    hash.sha256(0, filesize) == "da8595d1467da72c1f2e120420ab91e4a06d6cd065cbead1c9ce3a4d28011494"
}

rule MalwareBazaar_unknown_098_5eea3112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5eea3112b54a03056353f435e042c331073427d2cf4401829098c3e9cc5f19ab"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-06 19:06:41"
  condition:
    hash.sha256(0, filesize) == "5eea3112b54a03056353f435e042c331073427d2cf4401829098c3e9cc5f19ab"
}

rule MalwareBazaar_unknown_099_3ee67435
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ee6743541857a15df54cb62cdb44f492031824d284a8e5ccc5faf43cc21873a"
    family = "unknown"
    file_name = "libpsl-5.dll"
    file_type = "exe"
    first_seen = "2026-07-06 19:00:23"
  condition:
    hash.sha256(0, filesize) == "3ee6743541857a15df54cb62cdb44f492031824d284a8e5ccc5faf43cc21873a"
}

rule MalwareBazaar_unknown_100_b3fb3762
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3fb3762edd5c26da3b55dcf98c7acc6e1c4ec7445c26a468c1659c33af4dc10"
    family = "unknown"
    file_name = "kenwillzltd.zip"
    file_type = "zip"
    first_seen = "2026-07-06 19:00:10"
  condition:
    hash.sha256(0, filesize) == "b3fb3762edd5c26da3b55dcf98c7acc6e1c4ec7445c26a468c1659c33af4dc10"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

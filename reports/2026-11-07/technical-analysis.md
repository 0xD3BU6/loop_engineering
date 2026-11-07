# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-07

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 662 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 662 |
| Unique family labels | 13 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 42 |
| unknown | 31 |
| Snowlight | 7 |
| RevStealer | 4 |
| VShell | 4 |
| Prometei | 2 |
| ValleyRAT | 2 |
| SalatStealer | 2 |
| ConnectWise | 2 |
| Loki | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 53 |
| exe | 23 |
| macho | 20 |
| sh | 2 |
| msi | 1 |
| js | 1 |

## Per-Sample Analysis

### Sample 1: `133b66956fee0920`

| Field | Value |
|---|---|
| SHA-256 | `133b66956fee092042543cbd67da59ce0d1fb308f6afb83ce5bba735941246d9` |
| Family label | `Mirai` |
| File name | `e` |
| File type | `sh` |
| First seen | `2026-11-07 06:09:05` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1501396a2ba95b0cb1602e586cebd7ed` |
| SHA-1 | `c561d898ed3716d36bf8c5757cb69d2534f7b570` |
| SHA-256 | `133b66956fee092042543cbd67da59ce0d1fb308f6afb83ce5bba735941246d9` |
| SHA3-384 | `4060845df07559a4678c7647390465c78fe7aa27f36829fe7a626c1db56b80302e6a3dd5ffcf575cfef2358337b7e680` |
| TLSH | `T140212ECA66B25E712CA5ED27727F480836A0D5CA54C66F467CEC38FA94CDE087041A97` |
| SSDEEP | `24:I22CcqJBsrbQtc4kqc6q2Kb2NIVks2WLiub++AV:H2CcDrbB4k2q2ORJ2WLi6hAV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_133b6695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "133b66956fee092042543cbd67da59ce0d1fb308f6afb83ce5bba735941246d9"
    family = "Mirai"
    file_name = "e"
    file_type = "sh"
    first_seen = "2026-11-07 06:09:05"
  condition:
    hash.sha256(0, filesize) == "133b66956fee092042543cbd67da59ce0d1fb308f6afb83ce5bba735941246d9"
}
```

### Sample 2: `d4ea0857eff726c6`

| Field | Value |
|---|---|
| SHA-256 | `d4ea0857eff726c6bdf502461ccfe6d90e8a4808df1b78d39f548057cdfb6883` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-11-07 05:09:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baa614a16cdb991daca80246c68a7c01` |
| SHA-1 | `0ee3e63e7947553b9f03e6e5bbb479049c525d88` |
| SHA-256 | `d4ea0857eff726c6bdf502461ccfe6d90e8a4808df1b78d39f548057cdfb6883` |
| SHA3-384 | `bbcc0d6ed7144638c199c7b184216e7a27bd42744c26a214a2b9bca1bf3d66a1e647432cb9b2d565e6f8fdcca1a09465` |
| TLSH | `T1A3834AC4D183D8F2E95B42B435AEF3336231DAB40568BDE3F754A3B64821BA1B44A74D` |
| TELFHASH | `t1ef21f2ba1a751dedabc05d10f20e97617e5deb7b20107ba35a63a8390276442837bc3d` |
| SSDEEP | `1536:uV0rPXvAapKP1xfPRZ1z16l+P6Cxijl2NY2z4Bevy3r66b9syO0hNcfQ5O0MLewN:uV0rPXvAapKP1xfPR/URCGQNH4Y2fxn0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_d4ea0857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4ea0857eff726c6bdf502461ccfe6d90e8a4808df1b78d39f548057cdfb6883"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-07 05:09:04"
  condition:
    hash.sha256(0, filesize) == "d4ea0857eff726c6bdf502461ccfe6d90e8a4808df1b78d39f548057cdfb6883"
}
```

### Sample 3: `a996b6b9d64d12f5`

| Field | Value |
|---|---|
| SHA-256 | `a996b6b9d64d12f50e1b490b9ad54ae9b06c147ef29fb73e028b315b2e0ff209` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-11-07 05:08:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5ac5f6df8da43d36ba739c829c61c3d` |
| SHA-1 | `f66ef1737e05fcdbbcbe8a5ea6342e32342f70af` |
| SHA-256 | `a996b6b9d64d12f50e1b490b9ad54ae9b06c147ef29fb73e028b315b2e0ff209` |
| SHA3-384 | `80477b24788bdb01bfa316239c0d1c7f43e19083a4df8b53cc67038f4e6f56aa777f90343ca7c192e641856a9e8a3475` |
| TLSH | `T174C3190ABFB11EF7D4EECD3344B9874928AC096A21B83B752574E818B65F14F16D3CA4` |
| SSDEEP | `1536:KIcJ3YjBSxAJ9rby5Gz9W+pDxfA+Qpao/bdEb8QzO5fMoO95aqyhAex+5tl6retR:KzWTz9W+p5AUuSNWtLOU1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_a996b6b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a996b6b9d64d12f50e1b490b9ad54ae9b06c147ef29fb73e028b315b2e0ff209"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-07 05:08:03"
  condition:
    hash.sha256(0, filesize) == "a996b6b9d64d12f50e1b490b9ad54ae9b06c147ef29fb73e028b315b2e0ff209"
}
```

### Sample 4: `870e679d592adb9c`

| Field | Value |
|---|---|
| SHA-256 | `870e679d592adb9ca80ffc61582d6ced9e6ce522a5623e031b9d69f083239cf8` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-07 04:58:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `704094e04e5ecc547626f8b8c99b734b` |
| SHA-1 | `b3dbea488f1b041324ebc96166cee7ec6cae275e` |
| SHA-256 | `870e679d592adb9ca80ffc61582d6ced9e6ce522a5623e031b9d69f083239cf8` |
| SHA3-384 | `021eccb7eff6a2693b676281b2286690c8802b56de6317e3a230c7b7fb8eccdbfbd45aef03193e510447c26564203f3b` |
| TLSH | `T1B4F36B03B9E114ACD8A5C134AB2EA623EB343C0C5331B69F6BD876A63E25E547F5D314` |
| TELFHASH | `t1ef312a0eb3d87a66a1e50601ca495e3f2cd31592584b6caeb7f8cb460d78fc33960831` |
| SSDEEP | `3072:p4i3KBqFV5cloWMrtwB/BkqaTzd1/D7RgwPI2lTCzH:ai3K05EBBSTD7RgEXFmH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_870e679d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "870e679d592adb9ca80ffc61582d6ced9e6ce522a5623e031b9d69f083239cf8"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-07 04:58:03"
  condition:
    hash.sha256(0, filesize) == "870e679d592adb9ca80ffc61582d6ced9e6ce522a5623e031b9d69f083239cf8"
}
```

### Sample 5: `4ec220894d9c50b0`

| Field | Value |
|---|---|
| SHA-256 | `4ec220894d9c50b012c95d8b3842dfab945ff161563979419ace88db4166dd72` |
| Family label | `Loki` |
| File name | `A18DAB00E1356CEDE97CED4493640D01.exe` |
| File type | `exe` |
| First seen | `2026-11-07 04:55:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, Loki` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a18dab00e1356cede97ced4493640d01` |
| SHA-1 | `af58c8555d30dd80129a796c3e6388358eba0b12` |
| SHA-256 | `4ec220894d9c50b012c95d8b3842dfab945ff161563979419ace88db4166dd72` |
| SHA3-384 | `a4a4848f0dd1d33206994953e982c72595889e84051046d5acc19ebc352ed4800676713d38818e1e05994863c261a7a6` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15EB46C5876A8B79EC5EB8E3589B83C105B31B4274A3BD307615B119C5E1DBDACE00BE3` |
| SSDEEP | `12288:DnFVZ44ZHt60juGZbdO4IgrpiACYH09cs+H09c:D944ZHt9juGe8QAlN` |

#### Technical Assessment

- The sample is tracked as `Loki` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Loki_005_4ec22089
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ec220894d9c50b012c95d8b3842dfab945ff161563979419ace88db4166dd72"
    family = "Loki"
    file_name = "A18DAB00E1356CEDE97CED4493640D01.exe"
    file_type = "exe"
    first_seen = "2026-11-07 04:55:05"
  condition:
    hash.sha256(0, filesize) == "4ec220894d9c50b012c95d8b3842dfab945ff161563979419ace88db4166dd72"
}
```

### Sample 6: `8c7994818bf87741`

| Field | Value |
|---|---|
| SHA-256 | `8c7994818bf877418e701f3d8aa4e1cbb24d9031e8f36c577c3541193baf96df` |
| Family label | `njrat` |
| File name | `98CEE2774E0C79C0B39EAC01817D9457.exe` |
| File type | `exe` |
| First seen | `2026-11-07 04:45:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98cee2774e0c79c0b39eac01817d9457` |
| SHA-1 | `0bbfdc4f56303b4aae4da03e531cb6e58e921d25` |
| SHA-256 | `8c7994818bf877418e701f3d8aa4e1cbb24d9031e8f36c577c3541193baf96df` |
| SHA3-384 | `1bab247574d759b92026932cbdfce5fc5913aec4944940a572f2b82764d421f2685638ea8e2caee5e5ce6f091a0fcc04` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D9535A44BF964671D5AE4B7884B7761197B5E8036813FB2F48C160EF2B233D90E41BE6` |
| SSDEEP | `1536:ItQIPMtSww5GiVUlTOvwo0ia9P3AemF9bq:ICIPMRNiVlIHn9PrmF9b` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_006_8c799481
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7994818bf877418e701f3d8aa4e1cbb24d9031e8f36c577c3541193baf96df"
    family = "njrat"
    file_name = "98CEE2774E0C79C0B39EAC01817D9457.exe"
    file_type = "exe"
    first_seen = "2026-11-07 04:45:07"
  condition:
    hash.sha256(0, filesize) == "8c7994818bf877418e701f3d8aa4e1cbb24d9031e8f36c577c3541193baf96df"
}
```

### Sample 7: `4392cb9d92a49126`

| Field | Value |
|---|---|
| SHA-256 | `4392cb9d92a4912687f12a462b346e7f0b4316f1ce9f31be4d8b0cb383e07b16` |
| Family label | `Mirai` |
| File name | `4392cb9d92a4912687f12a462b346e7f0b4316f1ce9f31be4d8b0cb383e07b16.bin` |
| File type | `sh` |
| First seen | `2026-11-07 04:32:35` |
| Reporter | `Tuxxin` |
| Tags | `Mirai, script, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5302d938682841020fbbb5c096bdf5a2` |
| SHA-1 | `875b89eae44e3452b608177cb5d58abb1bd3d8be` |
| SHA-256 | `4392cb9d92a4912687f12a462b346e7f0b4316f1ce9f31be4d8b0cb383e07b16` |
| SHA3-384 | `9541fa9b4cb95985bedaa07f6014857a225b33153f46aa3b0d1def441655ffc3d8d240745676a1cb9028870bbf4ac30d` |
| TLSH | `T1D3319CCA63E65E742DE4E92331AB48047AE0E8C714C79F46B8EC38FE948DF447051A83` |
| SSDEEP | `24:I22Ifs8taruM6IRHt2LvUHZC0+cyPUasUG5bGlsZkv:H2SsNrrjRHMLs5C0dyPUasXiiZkv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_4392cb9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4392cb9d92a4912687f12a462b346e7f0b4316f1ce9f31be4d8b0cb383e07b16"
    family = "Mirai"
    file_name = "4392cb9d92a4912687f12a462b346e7f0b4316f1ce9f31be4d8b0cb383e07b16.bin"
    file_type = "sh"
    first_seen = "2026-11-07 04:32:35"
  condition:
    hash.sha256(0, filesize) == "4392cb9d92a4912687f12a462b346e7f0b4316f1ce9f31be4d8b0cb383e07b16"
}
```

### Sample 8: `796d79206eb13e8f`

| Field | Value |
|---|---|
| SHA-256 | `796d79206eb13e8f7ea9e9b2d0b6e2054ae2f7792fa8571bd53671e398ae6531` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-07 04:30:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3118bd1da80c0300b283bf48eb119a7e` |
| SHA-1 | `d717f007bd288cbf683f5af11e14bc6dba679118` |
| SHA-256 | `796d79206eb13e8f7ea9e9b2d0b6e2054ae2f7792fa8571bd53671e398ae6531` |
| SHA3-384 | `b663d7abd307469005de1674d2e9da463fb2abff42ee216a984e4aed30dc55f0a0579e548fdd15a28aee1c01dccb2eae` |
| TLSH | `T1B3556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS4:SDjxB4m5n8XlaPWi+d+a4TjxQP46` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_796d7920
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "796d79206eb13e8f7ea9e9b2d0b6e2054ae2f7792fa8571bd53671e398ae6531"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-07 04:30:04"
  condition:
    hash.sha256(0, filesize) == "796d79206eb13e8f7ea9e9b2d0b6e2054ae2f7792fa8571bd53671e398ae6531"
}
```

### Sample 9: `67219af1d55f4d94`

| Field | Value |
|---|---|
| SHA-256 | `67219af1d55f4d943632a26b7f072709f3334f58424808d1e217ddb06b3a35d1` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-07 04:17:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dbc2f9afd5375658b26c6a982d44796` |
| SHA-1 | `6917148d4b405ac8870f60d483d5369c8934f32a` |
| SHA-256 | `67219af1d55f4d943632a26b7f072709f3334f58424808d1e217ddb06b3a35d1` |
| SHA3-384 | `0c377ae9b7b29cff4047f487a4bae2a8951b7e6b6706b83dd7cd523e8b4444104d2920c9d5357dd94bd6e51fea334463` |
| TLSH | `T15FD33917B4D1C0FDCCD9D2B84BAEE226E9B3B4A91138B51E27D46E275E4DE201F1D620` |
| TELFHASH | `t15751a9b03daa3994b1e7f3776346e5959c390a2104e071e5d8f2b9e6df12bc00d62c63` |
| SSDEEP | `1536:Vm/3hs5ZvivqBpsqopCJRoI8/BhtMrk9mgi8ewATUsZ1zoEg3L4:Vm/3hsbiDCJX8/BhtMBgi8EUOzr00` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_67219af1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67219af1d55f4d943632a26b7f072709f3334f58424808d1e217ddb06b3a35d1"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-07 04:17:12"
  condition:
    hash.sha256(0, filesize) == "67219af1d55f4d943632a26b7f072709f3334f58424808d1e217ddb06b3a35d1"
}
```

### Sample 10: `aa423ec2fbdb1835`

| Field | Value |
|---|---|
| SHA-256 | `aa423ec2fbdb1835e1ad69c81db4d6c1b710faa27c192ac77e55d4f74a47325d` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-07 04:17:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07c11099162459a85dcfd03741a1aa88` |
| SHA-1 | `c08ec219333e27c1356d800b421ce7e1d9489ec2` |
| SHA-256 | `aa423ec2fbdb1835e1ad69c81db4d6c1b710faa27c192ac77e55d4f74a47325d` |
| SHA3-384 | `79e5fe0e76695b3d815bae16dedf4896430e8c04f5fe25d4c4e90d118342c6ee64a3ee21f13995205de5951a2c5eb6be` |
| TLSH | `T13D3301F24296EFE8C252A571C21044A3DE35D64D784B2BBB08D9343FE673186EF81B61` |
| SSDEEP | `1536:cF96MNCjCp7mWNFaUxWZvDMn786I9K03FuHU:cFk+paIahN+7MKEuHU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_aa423ec2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa423ec2fbdb1835e1ad69c81db4d6c1b710faa27c192ac77e55d4f74a47325d"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-07 04:17:04"
  condition:
    hash.sha256(0, filesize) == "aa423ec2fbdb1835e1ad69c81db4d6c1b710faa27c192ac77e55d4f74a47325d"
}
```

### Sample 11: `86758b3b84a49814`

| Field | Value |
|---|---|
| SHA-256 | `86758b3b84a49814be23e532ecaedd74c1d31a2ee6ffcfb45afd91aedcffaa5d` |
| Family label | `unknown` |
| File name | `gitl__it_64-v.8.927.exe` |
| File type | `exe` |
| First seen | `2026-11-07 03:38:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17153a0422b9de589cb7ed632bef99d8` |
| SHA-1 | `42f5def9a42304e26df2deaad4f2c219f08757c0` |
| SHA-256 | `86758b3b84a49814be23e532ecaedd74c1d31a2ee6ffcfb45afd91aedcffaa5d` |
| SHA3-384 | `b2725e90cec6496107f49f0316008a191b8c5bb8685e1691d84718a750a44b56f6c480b2c2d84f611a19416a8f856ecd` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1CC464B23EED955AEC0AAFB70C8A751426254BC0DBB3133E72960BF741F213D09A39B55` |
| SSDEEP | `24576:Mow41qXu13Y2YxmpZ3yKw597yYhSFt5X2GkYJmh/S1NDPAoEogdK5hzpTlzmG9DA:Mo/1qXc5Yxoi3DmgUv2GkYZbRTJjEdSo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_86758b3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86758b3b84a49814be23e532ecaedd74c1d31a2ee6ffcfb45afd91aedcffaa5d"
    family = "unknown"
    file_name = "gitl__it_64-v.8.927.exe"
    file_type = "exe"
    first_seen = "2026-11-07 03:38:18"
  condition:
    hash.sha256(0, filesize) == "86758b3b84a49814be23e532ecaedd74c1d31a2ee6ffcfb45afd91aedcffaa5d"
}
```

### Sample 12: `c5335a5256eab2b0`

| Field | Value |
|---|---|
| SHA-256 | `c5335a5256eab2b0d3e953cb5311442b31c79c9ed0d8bb30ade184ae0f7df85d` |
| Family label | `unknown` |
| File name | `gitl__it_64-v.8.927.exe` |
| File type | `exe` |
| First seen | `2026-11-07 03:37:10` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, Stealer, upx, Vidar, VidarStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a97089586be547315f987eb9f3036427` |
| SHA-1 | `837c9020fc6c713585f2eb8e10c904126775bfe9` |
| SHA-256 | `c5335a5256eab2b0d3e953cb5311442b31c79c9ed0d8bb30ade184ae0f7df85d` |
| SHA3-384 | `0152e0334286c6f634dab077893a580116676c02f0c0a57ab92ea8928cd768f32bea6b2b433c8dd49032adb9c067bb7c` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1875533ACCDD4A13AEC819C340B95F227E33097A176732963DD217F967CA11922D352ED` |
| SSDEEP | `24576:DmjrEhe9aO23ho1/QvvvgxEZRj+7As/rGIK6jhPLyq9m:Dm3E8Uho5QPgxEDq7AYrXjhPLy1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_c5335a52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5335a5256eab2b0d3e953cb5311442b31c79c9ed0d8bb30ade184ae0f7df85d"
    family = "unknown"
    file_name = "gitl__it_64-v.8.927.exe"
    file_type = "exe"
    first_seen = "2026-11-07 03:37:10"
  condition:
    hash.sha256(0, filesize) == "c5335a5256eab2b0d3e953cb5311442b31c79c9ed0d8bb30ade184ae0f7df85d"
}
```

### Sample 13: `6946548ce23106e7`

| Field | Value |
|---|---|
| SHA-256 | `6946548ce23106e70957952fc2fa08c8459fb4b2ea3e6b513e8a7387cc115cf3` |
| Family label | `unknown` |
| File name | `gitl__it_64-v.8.927.exe` |
| File type | `exe` |
| First seen | `2026-11-07 03:22:14` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed, Stealer, Vidar, VidarStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c81f3be4e57ba7ba0e0aa85165d19a7` |
| SHA-1 | `974ee605397ebc51180ff1e08801b1fa2065e310` |
| SHA-256 | `6946548ce23106e70957952fc2fa08c8459fb4b2ea3e6b513e8a7387cc115cf3` |
| SHA3-384 | `e6373f39647073e6950c0884c04ea317e381fdfff760a3ea0db283b2608993bb49ec1ddb42cae042947e3db370aad256` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T182464B23EED955AEC0AAFB70C8A751426254BC0DBB3133E72960BF741F213D09A39B55` |
| SSDEEP | `24576:Pow41qXu13Y2YxmpZ3yKw597yYhSFt5X2GkYJmh/S1NDPAoEogdK5hzpTlzmG9Dx:Po/1qXc5Yxoi3DmgUv2GkYZbRTJjEdLo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_6946548c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6946548ce23106e70957952fc2fa08c8459fb4b2ea3e6b513e8a7387cc115cf3"
    family = "unknown"
    file_name = "gitl__it_64-v.8.927.exe"
    file_type = "exe"
    first_seen = "2026-11-07 03:22:14"
  condition:
    hash.sha256(0, filesize) == "6946548ce23106e70957952fc2fa08c8459fb4b2ea3e6b513e8a7387cc115cf3"
}
```

### Sample 14: `e66171f991282ef6`

| Field | Value |
|---|---|
| SHA-256 | `e66171f991282ef661e3f3d8baba57f320759820bb768c647ac8f4be9ab0f11c` |
| Family label | `Prometei` |
| File name | `e66171f991282ef661e3f3d8baba57f320759820bb768c647ac8f4be9ab0f11c` |
| File type | `elf` |
| First seen | `2026-11-07 02:56:04` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7872bff63a58d56726cbaf95d0e6ed4a` |
| SHA-1 | `ba21484e02eda23e73dca71bcc642162012a481c` |
| SHA-256 | `e66171f991282ef661e3f3d8baba57f320759820bb768c647ac8f4be9ab0f11c` |
| SHA3-384 | `7f4a5e0d070b51c7f51ff4dfff344f758646ba938d7dd165fdcdd2cd7726ee361b88ddf7e9e71325bb865149fbbbef30` |
| TLSH | `T1BAA4237EBAE3213FF8259970770F75CAD010A0E89A6F0A7B931C6A138B3D4525D75872` |
| SSDEEP | `12288:qooQepOXnbyu+aDL9nS19GEMFz3D9p4FRVeTm7H8Vaa4:zo7peVVnSizT9pqHoVaa4` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_014_e66171f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e66171f991282ef661e3f3d8baba57f320759820bb768c647ac8f4be9ab0f11c"
    family = "Prometei"
    file_name = "e66171f991282ef661e3f3d8baba57f320759820bb768c647ac8f4be9ab0f11c"
    file_type = "elf"
    first_seen = "2026-11-07 02:56:04"
  condition:
    hash.sha256(0, filesize) == "e66171f991282ef661e3f3d8baba57f320759820bb768c647ac8f4be9ab0f11c"
}
```

### Sample 15: `11d82e97c16e41bc`

| Field | Value |
|---|---|
| SHA-256 | `11d82e97c16e41bc4b8f54da1c0adb898aa0bee29950f62252a058437d69a660` |
| Family label | `ValleyRAT` |
| File name | `398FC22A131AC9CDADB46DF21E2337C7.exe` |
| File type | `exe` |
| First seen | `2026-11-07 02:45:34` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `398fc22a131ac9cdadb46df21e2337c7` |
| SHA-1 | `8182b7c7f57b94a88bbe356f9e390bb202ef76fe` |
| SHA-256 | `11d82e97c16e41bc4b8f54da1c0adb898aa0bee29950f62252a058437d69a660` |
| SHA3-384 | `0c4e889b1b828ccfe781afb3efd3cead6e71bb03751c089c92a3d15bd1fa5f0f0dc6f0a632b1f67f45459a6e15cef9b6` |
| IMPHASH | `5a594319a0d69dbc452e748bcf05892e` |
| TLSH | `T18657333FF258A13ED46E0B3256B3D360597B7A65A81A8C0F53F0451CDF2A4601E3FA66` |
| SSDEEP | `786432:/3dZrElYpa2H470frvFzpaG26dtYIl0pKnl4gw/+kE4e:vHrQYADgUxuCImp4qgw/rpe` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_015_11d82e97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11d82e97c16e41bc4b8f54da1c0adb898aa0bee29950f62252a058437d69a660"
    family = "ValleyRAT"
    file_name = "398FC22A131AC9CDADB46DF21E2337C7.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:45:34"
  condition:
    hash.sha256(0, filesize) == "11d82e97c16e41bc4b8f54da1c0adb898aa0bee29950f62252a058437d69a660"
}
```

### Sample 16: `36b2235d3bf3299a`

| Field | Value |
|---|---|
| SHA-256 | `36b2235d3bf3299a52ca3ba676bc56a419e362ac156e637f513ede00838cb648` |
| Family label | `ValleyRAT` |
| File name | `321E9076E970BC97C7D87201E196233B.exe` |
| File type | `exe` |
| First seen | `2026-11-07 02:40:11` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `321e9076e970bc97c7d87201e196233b` |
| SHA-1 | `6b3b6802ab43da2cc9271ac09eb4aa492ed78834` |
| SHA-256 | `36b2235d3bf3299a52ca3ba676bc56a419e362ac156e637f513ede00838cb648` |
| SHA3-384 | `52f5c40b6821c345dafec8455d5d71727431dcd4f5239f8d366cef12515aaf95206c2328984d0b801a1336027c04e75a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1809633817801A9A6DA733671E590EAAF900C9FA92B2C497FB8F37D5DB1F65118C00F74` |
| SSDEEP | `196608:/6kgDLGmqkpdqYnKCYRPSSQ/1z8o+c5lgaCMfIIvh2wRj:/wnOsOPSSk1/+c8zYIIX` |
| ICON-DHASH | `31f0c0829094f474` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_016_36b2235d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36b2235d3bf3299a52ca3ba676bc56a419e362ac156e637f513ede00838cb648"
    family = "ValleyRAT"
    file_name = "321E9076E970BC97C7D87201E196233B.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:40:11"
  condition:
    hash.sha256(0, filesize) == "36b2235d3bf3299a52ca3ba676bc56a419e362ac156e637f513ede00838cb648"
}
```

### Sample 17: `4f2bac667f5b4022`

| Field | Value |
|---|---|
| SHA-256 | `4f2bac667f5b40227f7537e75ad1283d7ae328362681066a55bf007a6884246c` |
| Family label | `Prometei` |
| File name | `4f2bac667f5b40227f7537e75ad1283d7ae328362681066a55bf007a6884246c` |
| File type | `elf` |
| First seen | `2026-11-07 02:30:34` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29ae232684666dfb516ba2bfb0e846f2` |
| SHA-1 | `518d373e23a347d837bef2171dce114f32ae053c` |
| SHA-256 | `4f2bac667f5b40227f7537e75ad1283d7ae328362681066a55bf007a6884246c` |
| SHA3-384 | `7072298dec088f40cb936c1508fe1618ace9e2f2aef70c689a75d793d1ee9c88d3fec0ce99893d03fa3ddf0bd18b835a` |
| TLSH | `T1BCA423EF776C8D3DF62AE674FB998342C420647054D6248B9F6E5BC88230983092D76F` |
| SSDEEP | `6144:T0QXWJDXKRRBkJyEYxGpCH+aXOWYLr+G+0zgT6kUPrXH6sYvOffPlY7girs47kFL:otJDkjyyVGpCif+G0nGrKK3P+blSoHc` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_017_4f2bac66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f2bac667f5b40227f7537e75ad1283d7ae328362681066a55bf007a6884246c"
    family = "Prometei"
    file_name = "4f2bac667f5b40227f7537e75ad1283d7ae328362681066a55bf007a6884246c"
    file_type = "elf"
    first_seen = "2026-11-07 02:30:34"
  condition:
    hash.sha256(0, filesize) == "4f2bac667f5b40227f7537e75ad1283d7ae328362681066a55bf007a6884246c"
}
```

### Sample 18: `db6e10fc0cef5dd1`

| Field | Value |
|---|---|
| SHA-256 | `db6e10fc0cef5dd1331f3f2b1b8e51e53ce8c5485bf8908ccbd5c7b2046488f7` |
| Family label | `SalatStealer` |
| File name | `a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe.exe` |
| File type | `exe` |
| First seen | `2026-11-07 02:18:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e72b2fb68bf40910df81d71b7b7c134` |
| SHA-1 | `ac39d3f636d3cd8cc70b800951097b0ec18c0e34` |
| SHA-256 | `db6e10fc0cef5dd1331f3f2b1b8e51e53ce8c5485bf8908ccbd5c7b2046488f7` |
| SHA3-384 | `728f0296256a10a7bfe87f2d5349f615f445a4149b01d54220fee0835751e21aa3f6d6b3846d2827f00973f321a781d4` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T13FC65B11FADB95F1E903183141ABB37F23315D048B28DB9BEB547B2AF87B6A11C66305` |
| SSDEEP | `98304:DYZRvB6FCeCH1/aplmwreXsVlFhF7r4tG20CWE6:+vZ/1iewrnfHC6` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_018_db6e10fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db6e10fc0cef5dd1331f3f2b1b8e51e53ce8c5485bf8908ccbd5c7b2046488f7"
    family = "SalatStealer"
    file_name = "a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:18:18"
  condition:
    hash.sha256(0, filesize) == "db6e10fc0cef5dd1331f3f2b1b8e51e53ce8c5485bf8908ccbd5c7b2046488f7"
}
```

### Sample 19: `a0e992bfeea621b4`

| Field | Value |
|---|---|
| SHA-256 | `a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe` |
| Family label | `SalatStealer` |
| File name | `a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe.exe` |
| File type | `exe` |
| First seen | `2026-11-07 02:17:15` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17b0e41e695b2c4744f74233d30b2095` |
| SHA-1 | `3e531ee1401f926846e3413794c2be52ebadfd18` |
| SHA-256 | `a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe` |
| SHA3-384 | `da64d6ec7c4f61cc4a7ab2801b039467268ed35dc4679431852c9ab027a62e8c33b1bf5cd8868d9a82bfb2f828286ce8` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T10FF5334DB6ADEC17F3197537751A8AAB8E1B9280E020573F4546483C7823E32764B6FB` |
| SSDEEP | `98304:dHgydpXG1k9PKajadFpV1R7TfOYBfIf/wchc:7pEkpXadFxR/zwwch` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_019_a0e992bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe"
    family = "SalatStealer"
    file_name = "a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:17:15"
  condition:
    hash.sha256(0, filesize) == "a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe"
}
```

### Sample 20: `dfcddf48d5902420`

| Field | Value |
|---|---|
| SHA-256 | `dfcddf48d59024204b75d8cc04bbc1b03d7be9df3a836cafabc02c2d03bf935b` |
| Family label | `RevStealer` |
| File name | `dfcddf48d59024204b75d8cc04bbc1b03d7be9df3a836cafabc02c2d03bf935b.exe` |
| File type | `exe` |
| First seen | `2026-11-07 02:17:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a2025aba8a9538b5f03e12ed99b488e` |
| SHA-1 | `12f3aaff50cd39f2ecdc46855437fb545774afdb` |
| SHA-256 | `dfcddf48d59024204b75d8cc04bbc1b03d7be9df3a836cafabc02c2d03bf935b` |
| SHA3-384 | `348bc1c852e083fe98442d2e9ce911a93435d6e67d02dd871c6f432406fd81edae16753151ee77a20e610b11362b5640` |
| IMPHASH | `3b33063fa6540cfc510bd20fcc99cc96` |
| TLSH | `T16DD52399FC826475E8B7C7734393642EB12C7B8143A08D57B1C86B607DA2A18AC7737D` |
| SSDEEP | `49152:hRE/RBRj4Rc1eCIzpCs6dLUdJEl71IOJBtMbz9PeU2kYY15uGm1fLJVhyg3ufoR0:I/rRjT1enpCRLCs71Brw9WLjcuGMLfZF` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_020_dfcddf48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfcddf48d59024204b75d8cc04bbc1b03d7be9df3a836cafabc02c2d03bf935b"
    family = "RevStealer"
    file_name = "dfcddf48d59024204b75d8cc04bbc1b03d7be9df3a836cafabc02c2d03bf935b.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:17:11"
  condition:
    hash.sha256(0, filesize) == "dfcddf48d59024204b75d8cc04bbc1b03d7be9df3a836cafabc02c2d03bf935b"
}
```

### Sample 21: `2a0792e2b1e1470d`

| Field | Value |
|---|---|
| SHA-256 | `2a0792e2b1e1470dab303ac04a901b688438478d5150c1f7a28a4cf027f33ad0` |
| Family label | `RevStealer` |
| File name | `2a0792e2b1e1470dab303ac04a901b688438478d5150c1f7a28a4cf027f33ad0.exe` |
| File type | `exe` |
| First seen | `2026-11-07 02:14:53` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd6e1518845e5f6c219cdbaae282b1ff` |
| SHA-1 | `d9b521a514ae89c7846e2b17dc072fec338306d0` |
| SHA-256 | `2a0792e2b1e1470dab303ac04a901b688438478d5150c1f7a28a4cf027f33ad0` |
| SHA3-384 | `e74ee1694ae909f3d79418e5c41b774bb4e08020e479e3357b5755b78c793095c3ae47b220c7156ee37644f4691f8986` |
| IMPHASH | `5647fb939de4e6e2843458a387335597` |
| TLSH | `T1ECE523A5FCF61AB4F876C3BB4253602CB13D3B4559219C9BB7C92B008D21A686D37739` |
| SSDEEP | `49152:jCMJkWTZ4dyJqf8w4drP8PTvs3adSe3pjJwkD+RlxnDNjBK1Z16/64ZRosYGU/oa:jtnTZ4dyJRw4droJd3je0qxKx2ZRosxm` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_021_2a0792e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a0792e2b1e1470dab303ac04a901b688438478d5150c1f7a28a4cf027f33ad0"
    family = "RevStealer"
    file_name = "2a0792e2b1e1470dab303ac04a901b688438478d5150c1f7a28a4cf027f33ad0.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:14:53"
  condition:
    hash.sha256(0, filesize) == "2a0792e2b1e1470dab303ac04a901b688438478d5150c1f7a28a4cf027f33ad0"
}
```

### Sample 22: `8e9ba9cfa85d8cf5`

| Field | Value |
|---|---|
| SHA-256 | `8e9ba9cfa85d8cf529d51ba8a2fbf5fa2e843c713a7a3a57d05769cd7b1fa820` |
| Family label | `VShell` |
| File name | `23767a958594045ceaf056ac0ae56636.exe` |
| File type | `exe` |
| First seen | `2026-11-07 02:10:17` |
| Reporter | `abuse_ch` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23767a958594045ceaf056ac0ae56636` |
| SHA-1 | `5dde04e006ae1340d12e0af988d01d022642cebd` |
| SHA-256 | `8e9ba9cfa85d8cf529d51ba8a2fbf5fa2e843c713a7a3a57d05769cd7b1fa820` |
| SHA3-384 | `5f40ef1f385f0a91927b137dfe0c67dfd67167e75bbd8a88340540d2caeaf06ca1fc88d745510fc97538e600d72d2d24` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1B7716188F3136AF5E42C47F940D3A524D019ABB8C150BF4D5F60381D3C210BA265EF97` |
| SSDEEP | `48:6Icwm0BRt2WGJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jetESNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_022_8e9ba9cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e9ba9cfa85d8cf529d51ba8a2fbf5fa2e843c713a7a3a57d05769cd7b1fa820"
    family = "VShell"
    file_name = "23767a958594045ceaf056ac0ae56636.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:10:17"
  condition:
    hash.sha256(0, filesize) == "8e9ba9cfa85d8cf529d51ba8a2fbf5fa2e843c713a7a3a57d05769cd7b1fa820"
}
```

### Sample 23: `3c862dafda302843`

| Field | Value |
|---|---|
| SHA-256 | `3c862dafda302843f1604b919fd1bc179feea49e396bc648915ca19d59ea0c9f` |
| Family label | `unknown` |
| File name | `3c862dafda302843f1604b919fd1bc179feea49e396bc648915ca19d59ea0c9f.bin` |
| File type | `macho` |
| First seen | `2026-11-07 02:07:09` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9c795021f12645abb24926ed5c85d4f` |
| SHA-1 | `1dac6ab8e00c94b04c2c2e12dae6c9d9bde019ba` |
| SHA-256 | `3c862dafda302843f1604b919fd1bc179feea49e396bc648915ca19d59ea0c9f` |
| SHA3-384 | `73049438a99e867295ac1ad71cc5ca046372ac55bedfdce50943f4cdd361afb6dc49b9c3ed12726d50adbe4209294d1a` |
| TLSH | `T1DBF25F139B1C1A61C45D633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BEB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRoPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfLlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_3c862daf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c862dafda302843f1604b919fd1bc179feea49e396bc648915ca19d59ea0c9f"
    family = "unknown"
    file_name = "3c862dafda302843f1604b919fd1bc179feea49e396bc648915ca19d59ea0c9f.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:07:09"
  condition:
    hash.sha256(0, filesize) == "3c862dafda302843f1604b919fd1bc179feea49e396bc648915ca19d59ea0c9f"
}
```

### Sample 24: `0a221a2b52fbd475`

| Field | Value |
|---|---|
| SHA-256 | `0a221a2b52fbd475d24a0e5f19fa53bd7e49e07b0eec9a16b35c01bbe3480252` |
| Family label | `unknown` |
| File name | `0a221a2b52fbd475d24a0e5f19fa53bd7e49e07b0eec9a16b35c01bbe3480252.bin` |
| File type | `macho` |
| First seen | `2026-11-07 02:07:02` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a600723141522973baba4bedd01af25f` |
| SHA-1 | `5c874364e7f0010ef28f7097da0e9e5daa8f2e7c` |
| SHA-256 | `0a221a2b52fbd475d24a0e5f19fa53bd7e49e07b0eec9a16b35c01bbe3480252` |
| SHA3-384 | `6288705b2d61611cbe36f84c873a15a173a9a35a64f23a74e7c975d957be2b3ecfd69db03421b193557f0010d95827de` |
| TLSH | `T144F24E239B1C0A61C05D633C92BB1B026236F5D086C56B674B10C72CAFCA3C5BEB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMROHPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJfDlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_0a221a2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a221a2b52fbd475d24a0e5f19fa53bd7e49e07b0eec9a16b35c01bbe3480252"
    family = "unknown"
    file_name = "0a221a2b52fbd475d24a0e5f19fa53bd7e49e07b0eec9a16b35c01bbe3480252.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:07:02"
  condition:
    hash.sha256(0, filesize) == "0a221a2b52fbd475d24a0e5f19fa53bd7e49e07b0eec9a16b35c01bbe3480252"
}
```

### Sample 25: `40ee99127a64b7de`

| Field | Value |
|---|---|
| SHA-256 | `40ee99127a64b7de2e2c52dc5a97a0d3c406e7f4573fb8d4afcbd9064cffd4b5` |
| Family label | `unknown` |
| File name | `40ee99127a64b7de2e2c52dc5a97a0d3c406e7f4573fb8d4afcbd9064cffd4b5.bin` |
| File type | `macho` |
| First seen | `2026-11-07 02:05:23` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee3434389a4103d8cf15e34556f58cdc` |
| SHA-1 | `6cddbd2890e9d84abd83fbc8bb311bb2017b00c9` |
| SHA-256 | `40ee99127a64b7de2e2c52dc5a97a0d3c406e7f4573fb8d4afcbd9064cffd4b5` |
| SHA3-384 | `fb9a8aa0c41ce0362765f6a4e2a9ad86435ae0381134cf32e77af05c27ccc1e89fbaa77867a9bd08a04c4b1a6e14e49d` |
| TLSH | `T154F25F139B1C0A61C15C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRXUPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJfMWlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_40ee9912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ee99127a64b7de2e2c52dc5a97a0d3c406e7f4573fb8d4afcbd9064cffd4b5"
    family = "unknown"
    file_name = "40ee99127a64b7de2e2c52dc5a97a0d3c406e7f4573fb8d4afcbd9064cffd4b5.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:05:23"
  condition:
    hash.sha256(0, filesize) == "40ee99127a64b7de2e2c52dc5a97a0d3c406e7f4573fb8d4afcbd9064cffd4b5"
}
```

### Sample 26: `a0f6a045559171f6`

| Field | Value |
|---|---|
| SHA-256 | `a0f6a045559171f656e64c8a141eb3d839a0c6f961d76d69093189a75b6260c7` |
| Family label | `unknown` |
| File name | `a0f6a045559171f656e64c8a141eb3d839a0c6f961d76d69093189a75b6260c7.bin` |
| File type | `macho` |
| First seen | `2026-11-07 02:04:57` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d88117b89d4911bc332d400ff9bd55c` |
| SHA-1 | `597fba970cab18e89d342099c7764e56fedfaa10` |
| SHA-256 | `a0f6a045559171f656e64c8a141eb3d839a0c6f961d76d69093189a75b6260c7` |
| SHA3-384 | `325e72a5d8051550af711c5e550d457e8fcf8fa7b81643d920be299567f5c6c0882d426ed77625942b05f5613e3dee84` |
| TLSH | `T18BF273239B1C5922C48C623C42BB6742A23AF1A145C677674B00872DAFCA3C5B9E5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7AHe4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7weMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_a0f6a045
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0f6a045559171f656e64c8a141eb3d839a0c6f961d76d69093189a75b6260c7"
    family = "unknown"
    file_name = "a0f6a045559171f656e64c8a141eb3d839a0c6f961d76d69093189a75b6260c7.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:04:57"
  condition:
    hash.sha256(0, filesize) == "a0f6a045559171f656e64c8a141eb3d839a0c6f961d76d69093189a75b6260c7"
}
```

### Sample 27: `b9ccb3f0b7de8d35`

| Field | Value |
|---|---|
| SHA-256 | `b9ccb3f0b7de8d35d7de8b6d6e3a1040b7faa088b7c002c69f063ee871bfb77f` |
| Family label | `unknown` |
| File name | `b9ccb3f0b7de8d35d7de8b6d6e3a1040b7faa088b7c002c69f063ee871bfb77f.bin` |
| File type | `macho` |
| First seen | `2026-11-07 02:04:51` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e408f7e4425bae35f1dd8493318b0d5` |
| SHA-1 | `af11d27dee1c6f498df17ffc39fcf8e228652591` |
| SHA-256 | `b9ccb3f0b7de8d35d7de8b6d6e3a1040b7faa088b7c002c69f063ee871bfb77f` |
| SHA3-384 | `c9e734d1f9e2bf3929abbe1b6d5466bb615b24949cd33a57990a21f5921421dca460cd784d616e7ca7e782f94b1af7a4` |
| TLSH | `T186F25F139B1C0A61C05C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BEB9D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRcEPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJfPmlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_b9ccb3f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9ccb3f0b7de8d35d7de8b6d6e3a1040b7faa088b7c002c69f063ee871bfb77f"
    family = "unknown"
    file_name = "b9ccb3f0b7de8d35d7de8b6d6e3a1040b7faa088b7c002c69f063ee871bfb77f.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:04:51"
  condition:
    hash.sha256(0, filesize) == "b9ccb3f0b7de8d35d7de8b6d6e3a1040b7faa088b7c002c69f063ee871bfb77f"
}
```

### Sample 28: `c7f7208ec7dc9627`

| Field | Value |
|---|---|
| SHA-256 | `c7f7208ec7dc96270f9d6f2c2005a70c31de9424f76f399a5ebe6139206bce30` |
| Family label | `unknown` |
| File name | `c7f7208ec7dc96270f9d6f2c2005a70c31de9424f76f399a5ebe6139206bce30.bin` |
| File type | `macho` |
| First seen | `2026-11-07 02:02:25` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `534b2db2fb223f37d9bdb813ad5626a4` |
| SHA-1 | `00236e2dcce90ca2c13cbe634189aa068d5e24d6` |
| SHA-256 | `c7f7208ec7dc96270f9d6f2c2005a70c31de9424f76f399a5ebe6139206bce30` |
| SHA3-384 | `74f56f451e1000f03d27055a41e7d2694ed70f6e4c5f0cb2c95f0f84bea76392b02ec2f7e94a894acd732f2c128dfc08` |
| TLSH | `T111E24E43675C5929D05D83BA22FB1B976609F8A009E45B432F50DA282FE23C47CB0FDB` |
| SSDEEP | `96:xcIZEq5DbDP67li97WsCZwYjqclS06W1YbqclSl:GI2q5DbDyPwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_c7f7208e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7f7208ec7dc96270f9d6f2c2005a70c31de9424f76f399a5ebe6139206bce30"
    family = "unknown"
    file_name = "c7f7208ec7dc96270f9d6f2c2005a70c31de9424f76f399a5ebe6139206bce30.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:02:25"
  condition:
    hash.sha256(0, filesize) == "c7f7208ec7dc96270f9d6f2c2005a70c31de9424f76f399a5ebe6139206bce30"
}
```

### Sample 29: `80c4995fe223a8d7`

| Field | Value |
|---|---|
| SHA-256 | `80c4995fe223a8d7d8e564312477173eccf913d05a9469abfcc6f7fb4abb5d87` |
| Family label | `unknown` |
| File name | `80c4995fe223a8d7d8e564312477173eccf913d05a9469abfcc6f7fb4abb5d87.bin` |
| File type | `macho` |
| First seen | `2026-11-07 02:01:57` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `905af077bb4e25de039f157f3c879306` |
| SHA-1 | `110ec34b2e43d4c7e862ac5ed5e9ca24af8d33ad` |
| SHA-256 | `80c4995fe223a8d7d8e564312477173eccf913d05a9469abfcc6f7fb4abb5d87` |
| SHA3-384 | `cdc1173c533d39506b5fcd592491fb61ad70cfe9750644d4081be6853aff3a50a86ad518e61333932b7ea6dd7772dba3` |
| TLSH | `T1EDF263239B1C5922C48C623C42BB6742A23AF1E145D677774B00872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7pH14z1dgngS6BndngN/4B0:RUdp8j3jvpWK7t1MdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_80c4995f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80c4995fe223a8d7d8e564312477173eccf913d05a9469abfcc6f7fb4abb5d87"
    family = "unknown"
    file_name = "80c4995fe223a8d7d8e564312477173eccf913d05a9469abfcc6f7fb4abb5d87.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:01:57"
  condition:
    hash.sha256(0, filesize) == "80c4995fe223a8d7d8e564312477173eccf913d05a9469abfcc6f7fb4abb5d87"
}
```

### Sample 30: `772cc0958a947357`

| Field | Value |
|---|---|
| SHA-256 | `772cc0958a947357d1f811613552322d716604ad4c516d08d58a1a99ffd002a0` |
| Family label | `VShell` |
| File name | `772cc0958a947357d1f811613552322d716604ad4c516d08d58a1a99ffd002a0.exe` |
| File type | `exe` |
| First seen | `2026-11-07 02:00:59` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0ea773a7455615c4e07fce8ffeb2eaf` |
| SHA-1 | `6a78041bd61ae26818860739e80cb1263c050118` |
| SHA-256 | `772cc0958a947357d1f811613552322d716604ad4c516d08d58a1a99ffd002a0` |
| SHA3-384 | `e2248688d0663f68991611c0c683e6f035d3e18ee51d8ba2a6ec5443023d9dc30d9d2bb543e696f3a4f1f8f39cf7e00a` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T186715098F3135AF1E42C86F840D3A654D0199BB8C250BF4D5A60281D7C210BA265EF97` |
| SSDEEP | `48:6Icwm0zqymVt2WdJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jW4Vt/SNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_030_772cc095
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "772cc0958a947357d1f811613552322d716604ad4c516d08d58a1a99ffd002a0"
    family = "VShell"
    file_name = "772cc0958a947357d1f811613552322d716604ad4c516d08d58a1a99ffd002a0.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:00:59"
  condition:
    hash.sha256(0, filesize) == "772cc0958a947357d1f811613552322d716604ad4c516d08d58a1a99ffd002a0"
}
```

### Sample 31: `71246175047a03e5`

| Field | Value |
|---|---|
| SHA-256 | `71246175047a03e547f8b5aa848af2a026331aa6d5e06bbef02e669713e628b2` |
| Family label | `SnappyClient` |
| File name | `71246175047a03e547f8b5aa848af2a026331aa6d5e06bbef02e669713e628b2.exe` |
| File type | `exe` |
| First seen | `2026-11-07 02:00:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, SnappyClient` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51e8bab5336f625687b639bde7c97859` |
| SHA-1 | `b87956aae8d81ea647db8b532183824ba49382a7` |
| SHA-256 | `71246175047a03e547f8b5aa848af2a026331aa6d5e06bbef02e669713e628b2` |
| SHA3-384 | `206fb1bcd052a5c44d8e5038fdefa339f4058d3a357956c461bbc5360ffd2484a8bf30f661859866657a5de17311b3d2` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T1D646330277C87CB1CA6684B39F06FB47A7B7EB3A49426F52D7091E561CD30A182173E6` |
| SSDEEP | `98304:+puH9faDBbvEM1/vbo1gmCS/vpRBHHC18HnJSfDn6Ugd/V3oJHM/qbs1GiDzzGk4:+puoVvEMhDwFHC1Mnsj6Ugd/VYK/RYcU` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_031_71246175
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71246175047a03e547f8b5aa848af2a026331aa6d5e06bbef02e669713e628b2"
    family = "SnappyClient"
    file_name = "71246175047a03e547f8b5aa848af2a026331aa6d5e06bbef02e669713e628b2.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:00:54"
  condition:
    hash.sha256(0, filesize) == "71246175047a03e547f8b5aa848af2a026331aa6d5e06bbef02e669713e628b2"
}
```

### Sample 32: `575e8dab342418ff`

| Field | Value |
|---|---|
| SHA-256 | `575e8dab342418ffddba02c2cb323a9a1c25f50c334994438364fbeb8176e261` |
| Family label | `VShell` |
| File name | `575e8dab342418ffddba02c2cb323a9a1c25f50c334994438364fbeb8176e261.exe` |
| File type | `exe` |
| First seen | `2026-11-07 01:59:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae2e591dcc5d27533dec1449a29d9812` |
| SHA-1 | `2567f0c8d64ddd8a1849f5c85a7dac3a9258c09e` |
| SHA-256 | `575e8dab342418ffddba02c2cb323a9a1c25f50c334994438364fbeb8176e261` |
| SHA3-384 | `62b0632e0cc5ea62e92120c377f275589e4306405f0794058cc59b1458b8997330ff36a89904a408984017f970ed3690` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1EF71A541605456F2D98DA37F8587B895FD4EB248A2D84B0F0798A81A2F7607BB0D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DZmryqBjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DZmr/Z++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_032_575e8dab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "575e8dab342418ffddba02c2cb323a9a1c25f50c334994438364fbeb8176e261"
    family = "VShell"
    file_name = "575e8dab342418ffddba02c2cb323a9a1c25f50c334994438364fbeb8176e261.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:59:54"
  condition:
    hash.sha256(0, filesize) == "575e8dab342418ffddba02c2cb323a9a1c25f50c334994438364fbeb8176e261"
}
```

### Sample 33: `a67bf1dd75bc49b6`

| Field | Value |
|---|---|
| SHA-256 | `a67bf1dd75bc49b6408e6e7084be2cfba721d14ba744b3f40d8aa55a19b72017` |
| Family label | `VShell` |
| File name | `a67bf1dd75bc49b6408e6e7084be2cfba721d14ba744b3f40d8aa55a19b72017.exe` |
| File type | `exe` |
| First seen | `2026-11-07 01:57:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee42bb46d3274f7204b74b3fa1018595` |
| SHA-1 | `d5efdab65ecabfe080b07eacb7fd865845d9f2b9` |
| SHA-256 | `a67bf1dd75bc49b6408e6e7084be2cfba721d14ba744b3f40d8aa55a19b72017` |
| SHA3-384 | `5a84b42bbb665b315b37a0d859bde2fb7c70a2db53710b1db700cc4cede1cf08cd7597829d7e6847835a64bea5f9654a` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1E3716198F3136AF1E43C47F840D3A564C019ABBCC250BF8D5F60381D3C210BA259AF96` |
| SSDEEP | `48:6Icwm05t2WSJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4j0tQSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_033_a67bf1dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a67bf1dd75bc49b6408e6e7084be2cfba721d14ba744b3f40d8aa55a19b72017"
    family = "VShell"
    file_name = "a67bf1dd75bc49b6408e6e7084be2cfba721d14ba744b3f40d8aa55a19b72017.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:57:01"
  condition:
    hash.sha256(0, filesize) == "a67bf1dd75bc49b6408e6e7084be2cfba721d14ba744b3f40d8aa55a19b72017"
}
```

### Sample 34: `48caf733e828a95f`

| Field | Value |
|---|---|
| SHA-256 | `48caf733e828a95f3d5801e7dce826dbd14f8661705236bb6eff7c06d2a077ba` |
| Family label | `WARDENStealer` |
| File name | `48caf733e828a95f3d5801e7dce826dbd14f8661705236bb6eff7c06d2a077ba.exe` |
| File type | `exe` |
| First seen | `2026-11-07 01:56:56` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5474b3e2e0ae7825e946a2d2cdf0881` |
| SHA-1 | `7b250f3afe217c26759cfd757851fb44d3d30ee7` |
| SHA-256 | `48caf733e828a95f3d5801e7dce826dbd14f8661705236bb6eff7c06d2a077ba` |
| SHA3-384 | `a46af3cbadd51b841c6d96e4efb05971bc9c512617db9a5669033f40dee06d52542512706fb8fbdfadb6fe653a387042` |
| IMPHASH | `21b10276259fcc16372b6a191bd19db8` |
| TLSH | `T18E35E081AFC74AF5F116B13457210D0DDEA53871369056AAF2CC76E71A226BECAF9F00` |
| SSDEEP | `24576:6wJ0lAqPzz2IEua6sWCmMfvWKOvIZdPPSM1p31t:DKOqvx4mMXWQnp` |
| ICON-DHASH | `9671f0d4d4f07196` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_034_48caf733
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48caf733e828a95f3d5801e7dce826dbd14f8661705236bb6eff7c06d2a077ba"
    family = "WARDENStealer"
    file_name = "48caf733e828a95f3d5801e7dce826dbd14f8661705236bb6eff7c06d2a077ba.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:56:56"
  condition:
    hash.sha256(0, filesize) == "48caf733e828a95f3d5801e7dce826dbd14f8661705236bb6eff7c06d2a077ba"
}
```

### Sample 35: `ef7cdf4246b43dd4`

| Field | Value |
|---|---|
| SHA-256 | `ef7cdf4246b43dd4cfcfcfd904f75bc25133064761309439bebd5607d96c04a0` |
| Family label | `unknown` |
| File name | `ef7cdf4246b43dd4cfcfcfd904f75bc25133064761309439bebd5607d96c04a0.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:55:38` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6f83405a7b66350b61076acc52af658` |
| SHA-1 | `9e85af05c55c9315297c643d4dc0258f190a0d51` |
| SHA-256 | `ef7cdf4246b43dd4cfcfcfd904f75bc25133064761309439bebd5607d96c04a0` |
| SHA3-384 | `3271457fc25c8295cd1d63e99567b93b50e7745932583367a3a9b222a53f077c0fccd1e007d41bcc3bb9378fc8df28ed` |
| TLSH | `T15FF24E139B1C0A61C05D633C92BB1B426276F5D086C56B674B10C72CAFCA3C5BEB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRePlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfNlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_ef7cdf42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef7cdf4246b43dd4cfcfcfd904f75bc25133064761309439bebd5607d96c04a0"
    family = "unknown"
    file_name = "ef7cdf4246b43dd4cfcfcfd904f75bc25133064761309439bebd5607d96c04a0.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:55:38"
  condition:
    hash.sha256(0, filesize) == "ef7cdf4246b43dd4cfcfcfd904f75bc25133064761309439bebd5607d96c04a0"
}
```

### Sample 36: `c54c960b487ecaba`

| Field | Value |
|---|---|
| SHA-256 | `c54c960b487ecababb42d7e91787ad0b5c41d8c1c0d762ac18e4155f1efb1d2b` |
| Family label | `unknown` |
| File name | `c54c960b487ecababb42d7e91787ad0b5c41d8c1c0d762ac18e4155f1efb1d2b.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:55:33` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58ce578af01166efc334902fced5d796` |
| SHA-1 | `3124d7fce039b45354b1f958c4e9aaa8858ba654` |
| SHA-256 | `c54c960b487ecababb42d7e91787ad0b5c41d8c1c0d762ac18e4155f1efb1d2b` |
| SHA3-384 | `6bc625ec431e2b69231010457631ac63cad4ef3308ad3f75c07178a8c56510b55ee6b025c73e5f97c29e1441e3b44d11` |
| TLSH | `T178F25E139B1C0A61C05C633C92BB1B026236F5D086C56B674B10C72CAFCA3C5BEB9D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRBPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfQlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_c54c960b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c54c960b487ecababb42d7e91787ad0b5c41d8c1c0d762ac18e4155f1efb1d2b"
    family = "unknown"
    file_name = "c54c960b487ecababb42d7e91787ad0b5c41d8c1c0d762ac18e4155f1efb1d2b.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:55:33"
  condition:
    hash.sha256(0, filesize) == "c54c960b487ecababb42d7e91787ad0b5c41d8c1c0d762ac18e4155f1efb1d2b"
}
```

### Sample 37: `2b0ad3caef7e974a`

| Field | Value |
|---|---|
| SHA-256 | `2b0ad3caef7e974a1766b135433bfaeceb5ee4266dc410e5bd7dfb4ddc184622` |
| Family label | `unknown` |
| File name | `2b0ad3caef7e974a1766b135433bfaeceb5ee4266dc410e5bd7dfb4ddc184622.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:55:28` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2dd1f2cfb959d42e30c01e2daccbafdc` |
| SHA-1 | `3cc580b773a468dbda2843570ea3bb5250c37ee2` |
| SHA-256 | `2b0ad3caef7e974a1766b135433bfaeceb5ee4266dc410e5bd7dfb4ddc184622` |
| SHA3-384 | `5256490b1b1cd53bbd8dfa4d8ad7dbdf4ce1f2761c5403e5c7a91ddc16b1e0b9f708aed45f9d55047db707ce14136816` |
| TLSH | `T133F25F139B1C1A61C05C633C92BB1B026276F5D086C56B674B10C72CAFCA3C9BEB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMREbPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJfxlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_2b0ad3ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b0ad3caef7e974a1766b135433bfaeceb5ee4266dc410e5bd7dfb4ddc184622"
    family = "unknown"
    file_name = "2b0ad3caef7e974a1766b135433bfaeceb5ee4266dc410e5bd7dfb4ddc184622.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:55:28"
  condition:
    hash.sha256(0, filesize) == "2b0ad3caef7e974a1766b135433bfaeceb5ee4266dc410e5bd7dfb4ddc184622"
}
```

### Sample 38: `38d9ca4f66cbff9e`

| Field | Value |
|---|---|
| SHA-256 | `38d9ca4f66cbff9e4af7bdde9c43ced323cf3498b2e728e52fb9eb1508e2fa32` |
| Family label | `unknown` |
| File name | `38d9ca4f66cbff9e4af7bdde9c43ced323cf3498b2e728e52fb9eb1508e2fa32.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:55:23` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f68e2e88a387d37571bc3045f7bf44d4` |
| SHA-1 | `24ec291b4b39467e9f3961fbac3d8e953c7d65b1` |
| SHA-256 | `38d9ca4f66cbff9e4af7bdde9c43ced323cf3498b2e728e52fb9eb1508e2fa32` |
| SHA3-384 | `e0b7cd592a896afc8beab1e0dd3d48d918b508141589440e419bf86ef227eced90641964e0537261a9007c1674ff31f9` |
| TLSH | `T1DFF25F139B1C1A61C45C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRoPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJf7lilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_38d9ca4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38d9ca4f66cbff9e4af7bdde9c43ced323cf3498b2e728e52fb9eb1508e2fa32"
    family = "unknown"
    file_name = "38d9ca4f66cbff9e4af7bdde9c43ced323cf3498b2e728e52fb9eb1508e2fa32.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:55:23"
  condition:
    hash.sha256(0, filesize) == "38d9ca4f66cbff9e4af7bdde9c43ced323cf3498b2e728e52fb9eb1508e2fa32"
}
```

### Sample 39: `6b3a8efc982740a6`

| Field | Value |
|---|---|
| SHA-256 | `6b3a8efc982740a6057ed77f868f9119c6b5b02a1f20979e27368d8a6b771425` |
| Family label | `unknown` |
| File name | `6b3a8efc982740a6057ed77f868f9119c6b5b02a1f20979e27368d8a6b771425.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:52:01` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e77e3d6fbc1b9a8fbadfb723b8c21cd4` |
| SHA-1 | `38b647ca7c2c226bc530ced3992e92644e6965c3` |
| SHA-256 | `6b3a8efc982740a6057ed77f868f9119c6b5b02a1f20979e27368d8a6b771425` |
| SHA3-384 | `7667517ca29bf4616ee12e630592fc9f84e0cb28ff680a0c10f41e727c16311480ebbd78647181c0fbf85a50e43f66f1` |
| TLSH | `T130F263239B2C5922C48C623882BB6742A23AF1A145D577774B04872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK72HO4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7aOMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_6b3a8efc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b3a8efc982740a6057ed77f868f9119c6b5b02a1f20979e27368d8a6b771425"
    family = "unknown"
    file_name = "6b3a8efc982740a6057ed77f868f9119c6b5b02a1f20979e27368d8a6b771425.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:52:01"
  condition:
    hash.sha256(0, filesize) == "6b3a8efc982740a6057ed77f868f9119c6b5b02a1f20979e27368d8a6b771425"
}
```

### Sample 40: `b19b0bdcc8c17188`

| Field | Value |
|---|---|
| SHA-256 | `b19b0bdcc8c171883229630f33d95ad49189b3aaa402c103869c20843b46e640` |
| Family label | `unknown` |
| File name | `b19b0bdcc8c171883229630f33d95ad49189b3aaa402c103869c20843b46e640.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:51:57` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b8be2be5735e244798fd2eac0fb69c2` |
| SHA-1 | `d4aa306a0f643e916d18edcc1243120e4d9320c1` |
| SHA-256 | `b19b0bdcc8c171883229630f33d95ad49189b3aaa402c103869c20843b46e640` |
| SHA3-384 | `7c91e88b1903ea0ca99e734e750623a4968bb8a8f3f2cfbcd0fe37fdb3d81bfa4f931f041096c7fb7ceb7137c7a9f89c` |
| TLSH | `T163E24F43675C5929D05D83BE22FB1B576609F8A009D45B432F90DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEN+5DbDP67li97WsCLwYjqclS06W1YbqclSl:GI2N+5DbDyJwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_b19b0bdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b19b0bdcc8c171883229630f33d95ad49189b3aaa402c103869c20843b46e640"
    family = "unknown"
    file_name = "b19b0bdcc8c171883229630f33d95ad49189b3aaa402c103869c20843b46e640.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:57"
  condition:
    hash.sha256(0, filesize) == "b19b0bdcc8c171883229630f33d95ad49189b3aaa402c103869c20843b46e640"
}
```

### Sample 41: `057e4508e805e721`

| Field | Value |
|---|---|
| SHA-256 | `057e4508e805e7218daa6f1daa058f11116fdec2a74dc865319b556ebd640e82` |
| Family label | `unknown` |
| File name | `057e4508e805e7218daa6f1daa058f11116fdec2a74dc865319b556ebd640e82.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:51:15` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdf8d316981893d59b1f1189ba09310f` |
| SHA-1 | `ae64d95aa4895fbd83d5b6914bd1e749484803b7` |
| SHA-256 | `057e4508e805e7218daa6f1daa058f11116fdec2a74dc865319b556ebd640e82` |
| SHA3-384 | `a4820cfb479417e6911aa6f3c34fd94cd64619123f13c76eddc20aff67efebeb5c0830010eb43eca932c2a9abfba5c67` |
| TLSH | `T19CF25F139B1C1A61C05D633C92BB1B426276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRbPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfSlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_057e4508
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "057e4508e805e7218daa6f1daa058f11116fdec2a74dc865319b556ebd640e82"
    family = "unknown"
    file_name = "057e4508e805e7218daa6f1daa058f11116fdec2a74dc865319b556ebd640e82.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:15"
  condition:
    hash.sha256(0, filesize) == "057e4508e805e7218daa6f1daa058f11116fdec2a74dc865319b556ebd640e82"
}
```

### Sample 42: `b86f8878b103c994`

| Field | Value |
|---|---|
| SHA-256 | `b86f8878b103c994ca14bdba4586e4a5ce8fda22e4407281214bd5481743b632` |
| Family label | `unknown` |
| File name | `b86f8878b103c994ca14bdba4586e4a5ce8fda22e4407281214bd5481743b632.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:51:12` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af90be679654d53f431e5d3d7cd3c9a3` |
| SHA-1 | `992ee04a9fbf604e116a150f3a1fd93fada3c82c` |
| SHA-256 | `b86f8878b103c994ca14bdba4586e4a5ce8fda22e4407281214bd5481743b632` |
| SHA3-384 | `c2d9e52720b862357876575ade77a96c21b1b9337a650c2702f49a8686e3733ea0824d3de81058f2cbe1b0c9043f693a` |
| TLSH | `T115F273239B1C5922C44C623C42BB6742A23AF1E145D677774B00872DAFCA3C5B9E5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7FHm4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7BmMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_b86f8878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b86f8878b103c994ca14bdba4586e4a5ce8fda22e4407281214bd5481743b632"
    family = "unknown"
    file_name = "b86f8878b103c994ca14bdba4586e4a5ce8fda22e4407281214bd5481743b632.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:12"
  condition:
    hash.sha256(0, filesize) == "b86f8878b103c994ca14bdba4586e4a5ce8fda22e4407281214bd5481743b632"
}
```

### Sample 43: `7cc114bd86274f42`

| Field | Value |
|---|---|
| SHA-256 | `7cc114bd86274f4266b402a1881fdb2d22cccb9d92d94186dfd7629ed6b1e39b` |
| Family label | `unknown` |
| File name | `7cc114bd86274f4266b402a1881fdb2d22cccb9d92d94186dfd7629ed6b1e39b.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:51:08` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a1b81b57a4c2506508dba49242a9247` |
| SHA-1 | `497419daa3c776cb2aa078c58ae26652e658d7c4` |
| SHA-256 | `7cc114bd86274f4266b402a1881fdb2d22cccb9d92d94186dfd7629ed6b1e39b` |
| SHA3-384 | `e59d4a06734019d0e9f2b8c0d8f505d74fa09d9f1f99cbde6ce97242201d23062711835b41b9a99d5bfe7330204c10a7` |
| TLSH | `T1EBF263239B1C9922C48C623842BB6742A23AF1E145D577674B04872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7BHg4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7FgMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_7cc114bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cc114bd86274f4266b402a1881fdb2d22cccb9d92d94186dfd7629ed6b1e39b"
    family = "unknown"
    file_name = "7cc114bd86274f4266b402a1881fdb2d22cccb9d92d94186dfd7629ed6b1e39b.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:08"
  condition:
    hash.sha256(0, filesize) == "7cc114bd86274f4266b402a1881fdb2d22cccb9d92d94186dfd7629ed6b1e39b"
}
```

### Sample 44: `d9bf992ad7e94e8a`

| Field | Value |
|---|---|
| SHA-256 | `d9bf992ad7e94e8a810ed950148522f45ca3a68521df6bd275c9f539740268f6` |
| Family label | `unknown` |
| File name | `d9bf992ad7e94e8a810ed950148522f45ca3a68521df6bd275c9f539740268f6.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:51:04` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2eeab1695e0fa587ae6496e14a162557` |
| SHA-1 | `2081fb104821c7d989fc785fecfb9911b4af8533` |
| SHA-256 | `d9bf992ad7e94e8a810ed950148522f45ca3a68521df6bd275c9f539740268f6` |
| SHA3-384 | `c7440a65a1d8199963034f41e94c48c224ec6ff3cc88a57dbfc9ea007139aaaa368da288f5cce773b0f0682c66534762` |
| TLSH | `T182E24F43675C5929D45D83BA22FB1B976609F8A00AD45B432F50DA282FE23C47CB0FDB` |
| SSDEEP | `96:xcIZEu5DbDP67li97WsC+wYjqclS06W1YbqclSl:GI2u5DbDyowYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_d9bf992a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9bf992ad7e94e8a810ed950148522f45ca3a68521df6bd275c9f539740268f6"
    family = "unknown"
    file_name = "d9bf992ad7e94e8a810ed950148522f45ca3a68521df6bd275c9f539740268f6.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:04"
  condition:
    hash.sha256(0, filesize) == "d9bf992ad7e94e8a810ed950148522f45ca3a68521df6bd275c9f539740268f6"
}
```

### Sample 45: `740363a0b979cd45`

| Field | Value |
|---|---|
| SHA-256 | `740363a0b979cd4504857b39288ca1897256c6ed0ca280c6b0dc9e129523bef4` |
| Family label | `unknown` |
| File name | `740363a0b979cd4504857b39288ca1897256c6ed0ca280c6b0dc9e129523bef4.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:51:00` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06e86a10960eed5a1d42db9c2d43bf24` |
| SHA-1 | `3509d76b03c098694da00136bc5291f6fb47ffba` |
| SHA-256 | `740363a0b979cd4504857b39288ca1897256c6ed0ca280c6b0dc9e129523bef4` |
| SHA3-384 | `bb9b6f20627898a62abe89947cdd60743be0b297ca25e6d6272af88fff6cca321c25eb8a0afc17433d34a5579732cb6b` |
| TLSH | `T188F263239B1C5962C44C623C42BB6742A23AF1E145D577B74B00872DAFCA3C5B9A5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7RH14z1dgngS6BndngN/4B0:RUdp8j3jvpWK7V1MdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_740363a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "740363a0b979cd4504857b39288ca1897256c6ed0ca280c6b0dc9e129523bef4"
    family = "unknown"
    file_name = "740363a0b979cd4504857b39288ca1897256c6ed0ca280c6b0dc9e129523bef4.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:00"
  condition:
    hash.sha256(0, filesize) == "740363a0b979cd4504857b39288ca1897256c6ed0ca280c6b0dc9e129523bef4"
}
```

### Sample 46: `3e3a53b7016a9426`

| Field | Value |
|---|---|
| SHA-256 | `3e3a53b7016a9426cbd7e77ed22429ee2e84eb5033700a1f7c373c139e5dd26a` |
| Family label | `unknown` |
| File name | `3e3a53b7016a9426cbd7e77ed22429ee2e84eb5033700a1f7c373c139e5dd26a.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:50:56` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f97d86c462d1e49c4ef709453681b1b6` |
| SHA-1 | `94835e4256840d4dcef4f0c6a9b61df5314e2fc3` |
| SHA-256 | `3e3a53b7016a9426cbd7e77ed22429ee2e84eb5033700a1f7c373c139e5dd26a` |
| SHA3-384 | `e01d8c38f581ec43c010ed4b57eae22474c6e326654830d6c73b17b222a1c67c1e303ad92b96c71f202188cc28abd6fc` |
| TLSH | `T18DE23D43AB4C8965C26D42301AF70BC6A616F6B09EE16B875750C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUVVZqDDt0TOTLZ0BbFw2GHKk6XrMclSibFqAMcl:z4ZZXvvMVZMt0TO2bVq/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_3e3a53b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e3a53b7016a9426cbd7e77ed22429ee2e84eb5033700a1f7c373c139e5dd26a"
    family = "unknown"
    file_name = "3e3a53b7016a9426cbd7e77ed22429ee2e84eb5033700a1f7c373c139e5dd26a.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:50:56"
  condition:
    hash.sha256(0, filesize) == "3e3a53b7016a9426cbd7e77ed22429ee2e84eb5033700a1f7c373c139e5dd26a"
}
```

### Sample 47: `5dead91acf4972d1`

| Field | Value |
|---|---|
| SHA-256 | `5dead91acf4972d1503e4abc8b223767d78373f15066aa79e252557dc8894786` |
| Family label | `Mirai` |
| File name | `5dead91acf4972d1503e4abc8b223767d78373f15066aa79e252557dc8894786.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:43:12` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a1e31bfd53641a65595116427d5f78c` |
| SHA-1 | `7d3b2f6a88298785f2e088c4c94028e664903ac4` |
| SHA-256 | `5dead91acf4972d1503e4abc8b223767d78373f15066aa79e252557dc8894786` |
| SHA3-384 | `ae9cfe34fb47bc138e94bd9050321a8e5958439bec46320351af202263f0a5486621f87e2a35dff3fb8a066bdca2e2cc` |
| TLSH | `T156F13356BAEBCD73CCAD233A07678714337588D2AF42AB13511C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtAsWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7ma4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_5dead91a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dead91acf4972d1503e4abc8b223767d78373f15066aa79e252557dc8894786"
    family = "Mirai"
    file_name = "5dead91acf4972d1503e4abc8b223767d78373f15066aa79e252557dc8894786.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:43:12"
  condition:
    hash.sha256(0, filesize) == "5dead91acf4972d1503e4abc8b223767d78373f15066aa79e252557dc8894786"
}
```

### Sample 48: `f2aa4b6d21735451`

| Field | Value |
|---|---|
| SHA-256 | `f2aa4b6d2173545191741e3726f09e86bfc36a2cfbb562a60da7e059fc0689f3` |
| Family label | `Mirai` |
| File name | `f2aa4b6d2173545191741e3726f09e86bfc36a2cfbb562a60da7e059fc0689f3.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:43:09` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa6ff0c7f4ca5e0d2e3c509348bb891d` |
| SHA-1 | `f7fe95d19534c437efd6711bc137d026b0f68f71` |
| SHA-256 | `f2aa4b6d2173545191741e3726f09e86bfc36a2cfbb562a60da7e059fc0689f3` |
| SHA3-384 | `7d0c427ea9877a687ff062989a9d27a7c98879182eefe97b3adb7c7454bd228a0483a63cb0916faa5877a04250a3b0fa` |
| TLSH | `T1FA125047A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5/PlTTej6TNJ9VONddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTN9TTfTpVCdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_f2aa4b6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2aa4b6d2173545191741e3726f09e86bfc36a2cfbb562a60da7e059fc0689f3"
    family = "Mirai"
    file_name = "f2aa4b6d2173545191741e3726f09e86bfc36a2cfbb562a60da7e059fc0689f3.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:43:09"
  condition:
    hash.sha256(0, filesize) == "f2aa4b6d2173545191741e3726f09e86bfc36a2cfbb562a60da7e059fc0689f3"
}
```

### Sample 49: `1df069b263d1f07c`

| Field | Value |
|---|---|
| SHA-256 | `1df069b263d1f07cde52576d3a0c8935edca42d6d68ca2b32f849e1049204f92` |
| Family label | `Mirai` |
| File name | `1df069b263d1f07cde52576d3a0c8935edca42d6d68ca2b32f849e1049204f92.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:43:05` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f049ba1b1d1c2ca7b8ac81985f53c9ee` |
| SHA-1 | `69d66c5f579591dc9e1f6250a219b44daf7c8d08` |
| SHA-256 | `1df069b263d1f07cde52576d3a0c8935edca42d6d68ca2b32f849e1049204f92` |
| SHA3-384 | `af5bc0c460e06d5813832488b436333e9afb7ea41003df22b83b1a9caa622b99c557719767b9c05f02dad731fec59fc4` |
| TLSH | `T1C3E16217E2D5CD72D8CD133846931749213AC86EAB83AF03650C5A9AEE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFjd146mwz7cSym4S2ofahbpZiQ:fsue7cIJRFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_1df069b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1df069b263d1f07cde52576d3a0c8935edca42d6d68ca2b32f849e1049204f92"
    family = "Mirai"
    file_name = "1df069b263d1f07cde52576d3a0c8935edca42d6d68ca2b32f849e1049204f92.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:43:05"
  condition:
    hash.sha256(0, filesize) == "1df069b263d1f07cde52576d3a0c8935edca42d6d68ca2b32f849e1049204f92"
}
```

### Sample 50: `c45b668f7ea3c32f`

| Field | Value |
|---|---|
| SHA-256 | `c45b668f7ea3c32faa3f51ef20a234efef9290f7fcca1b4326dc20719d0cb4e7` |
| Family label | `unknown` |
| File name | `c45b668f7ea3c32faa3f51ef20a234efef9290f7fcca1b4326dc20719d0cb4e7.exe` |
| File type | `exe` |
| First seen | `2026-11-07 01:43:02` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b1bf7d4fd2126be2267b8a390ae57d4` |
| SHA-1 | `f5fbcce4dcc9fbd5dc66bd6a18966fe6b335ddad` |
| SHA-256 | `c45b668f7ea3c32faa3f51ef20a234efef9290f7fcca1b4326dc20719d0cb4e7` |
| SHA3-384 | `51af430876600973fdadd8924d5a6de850b0c6d2eeeb4a8d13998625268b4b8fd180a68672cc2f868eb36152ba20fed4` |
| IMPHASH | `d2ac65482652218bcee03d8f34b609fc` |
| TLSH | `T10335BD51A7852FF8F4278D3EC6055602F6613C4B4BD37AAB529C076A1E22DB44EF9F20` |
| SSDEEP | `12288:kXPoeKoBKjoJLAnmhY81/v+P4y5kwNpl8f7eU3eZaAtuLnZXbhJMmU1WZIGEZ1vE:cMoRAnwmPpvl89uZFuLn1hJMm5zEc` |
| ICON-DHASH | `8e7168d4d468718e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_c45b668f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c45b668f7ea3c32faa3f51ef20a234efef9290f7fcca1b4326dc20719d0cb4e7"
    family = "unknown"
    file_name = "c45b668f7ea3c32faa3f51ef20a234efef9290f7fcca1b4326dc20719d0cb4e7.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:43:02"
  condition:
    hash.sha256(0, filesize) == "c45b668f7ea3c32faa3f51ef20a234efef9290f7fcca1b4326dc20719d0cb4e7"
}
```

### Sample 51: `a39f83a2be41f4d8`

| Field | Value |
|---|---|
| SHA-256 | `a39f83a2be41f4d8f898ac977b7be9fba5ef7ec3cfd3ff7edea623405cfa8ce2` |
| Family label | `RevStealer` |
| File name | `a39f83a2be41f4d8f898ac977b7be9fba5ef7ec3cfd3ff7edea623405cfa8ce2.exe` |
| File type | `exe` |
| First seen | `2026-11-07 01:42:57` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c94a6beb63702678bfa4a6460d41e66a` |
| SHA-1 | `e653de440029818fca7ae39a3e5fec1ac09d83ce` |
| SHA-256 | `a39f83a2be41f4d8f898ac977b7be9fba5ef7ec3cfd3ff7edea623405cfa8ce2` |
| SHA3-384 | `ab57efc7125991b79d571a1cb765cf3a13b0af0d3f2910e2e8ccc032a6196739fb3cdf79c6d19a04bfd29ca23a2193ad` |
| IMPHASH | `3b33063fa6540cfc510bd20fcc99cc96` |
| TLSH | `T1E6D52289FCB644B5F437C3A79A93B02EB13977814F758D46BA8C6B102E026587C76378` |
| SSDEEP | `49152:kge+A7gBOx0Zbt/+/hJQlK/M8W9TcUCb/lDRPGIRrQH1A5cDvkNOKWVwjkQIsJn:TpLma+HZUdMb/lDRPGorQVA5AcnWVtsh` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_051_a39f83a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a39f83a2be41f4d8f898ac977b7be9fba5ef7ec3cfd3ff7edea623405cfa8ce2"
    family = "RevStealer"
    file_name = "a39f83a2be41f4d8f898ac977b7be9fba5ef7ec3cfd3ff7edea623405cfa8ce2.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:42:57"
  condition:
    hash.sha256(0, filesize) == "a39f83a2be41f4d8f898ac977b7be9fba5ef7ec3cfd3ff7edea623405cfa8ce2"
}
```

### Sample 52: `9cdafa22837b0a4f`

| Field | Value |
|---|---|
| SHA-256 | `9cdafa22837b0a4f995b6aa30a19806be94132559c8cbf4271347151b47a627d` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `772023307c041e91398cf80812310bce` |
| SHA-1 | `cd4934fd427a4b30849d132f965256493030943f` |
| SHA-256 | `9cdafa22837b0a4f995b6aa30a19806be94132559c8cbf4271347151b47a627d` |
| SHA3-384 | `79828b0512962d7a01eadb22f864a0ab3ad086b2953f92716fe3159ca5e57006aac494f97a1b4f098e8608af27738b54` |
| TLSH | `T1600408A2BD42D961C5D428BBEA2F80CC338313ACC7EF7112CD159B35A5DF5990A3AE45` |
| SSDEEP | `3072:Xnh75pDNDu0I+/bcRJvfltHoImG+ZeB/ZAYmbP1AicIOIXXXZg1MvgdHL7:XnndIRJvflt6rUZZADbdFcj4XZsMvgdX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_9cdafa22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cdafa22837b0a4f995b6aa30a19806be94132559c8cbf4271347151b47a627d"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:54"
  condition:
    hash.sha256(0, filesize) == "9cdafa22837b0a4f995b6aa30a19806be94132559c8cbf4271347151b47a627d"
}
```

### Sample 53: `e3136233f560e857`

| Field | Value |
|---|---|
| SHA-256 | `e3136233f560e85717a03a58c1595e1ca8418bd1846f7290dd920dd1c185fe58` |
| Family label | `RevStealer` |
| File name | `e3136233f560e85717a03a58c1595e1ca8418bd1846f7290dd920dd1c185fe58.exe` |
| File type | `exe` |
| First seen | `2026-11-07 01:42:53` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37619b1a772b379e7bce8d89bd3251f9` |
| SHA-1 | `4ea0f99755805d83e8c0bf6d9d8333dfdfc7d610` |
| SHA-256 | `e3136233f560e85717a03a58c1595e1ca8418bd1846f7290dd920dd1c185fe58` |
| SHA3-384 | `3a73fb1bf0453add779f3210cf99121bf69dfa2aec6c6e84889977674e834653c71d3456748644db161a40e247476187` |
| IMPHASH | `5647fb939de4e6e2843458a387335597` |
| TLSH | `T191D52366FDF209B9F877C7A2859374ACB02A7B4609710D5F36CC2B114E02848BD7677A` |
| SSDEEP | `49152:sspxubvNHf+HJD790D9qbFEjVHvYkxna+EjS56FE17vM+MHZiAc5FQlpCYTpB:sQkJfe79+HCSIwMHQilp9TpB` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_053_e3136233
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3136233f560e85717a03a58c1595e1ca8418bd1846f7290dd920dd1c185fe58"
    family = "RevStealer"
    file_name = "e3136233f560e85717a03a58c1595e1ca8418bd1846f7290dd920dd1c185fe58.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:42:53"
  condition:
    hash.sha256(0, filesize) == "e3136233f560e85717a03a58c1595e1ca8418bd1846f7290dd920dd1c185fe58"
}
```

### Sample 54: `b98c78937928f955`

| Field | Value |
|---|---|
| SHA-256 | `b98c78937928f955938e3ef1c7f2f43b1c2b2f8ee10fbbf3742062ce3e608c21` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8afc58b1ffdea8a6419e27fbf373d9c` |
| SHA-1 | `41552013b9a1cc8a6a3ba3d403129399ce80a617` |
| SHA-256 | `b98c78937928f955938e3ef1c7f2f43b1c2b2f8ee10fbbf3742062ce3e608c21` |
| SHA3-384 | `473167cb1caeb36a3a55b5bdbaad40c5e822fe0604ce891db84fa505f9672c1fed55f3420854808f144e5b5cbe7f6a41` |
| TLSH | `T10334298BB2FBADE0DAF78474206257BD8461D4A25FB8E48CDB465CE0ED17100B52D3DA` |
| SSDEEP | `3072:ZaHZs1/PN4llnTAueE1qVl+OX3Q8xT8gJUWRaKDM/m8aXiTLWeWaGL/9hSZN5H5U:L1N4llniEKpnfSOJH8aCWu5H54+y3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_b98c7893
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98c78937928f955938e3ef1c7f2f43b1c2b2f8ee10fbbf3742062ce3e608c21"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:52"
  condition:
    hash.sha256(0, filesize) == "b98c78937928f955938e3ef1c7f2f43b1c2b2f8ee10fbbf3742062ce3e608c21"
}
```

### Sample 55: `3f995d003997e5a8`

| Field | Value |
|---|---|
| SHA-256 | `3f995d003997e5a87ef43da077c3cef430899def1d5d327816435137437be84a` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06bec81990de492d878204752bdc7563` |
| SHA-1 | `8d50bb80a16e640131e5a7f6ffec6964392143d0` |
| SHA-256 | `3f995d003997e5a87ef43da077c3cef430899def1d5d327816435137437be84a` |
| SHA3-384 | `3ba90c350d893db0a6dcd9a387e49af128cdd15ff204513207c24712c90edf6f90f86762f4c63b05b6c9effb4e54b1ba` |
| TLSH | `T1D6B328C1FC819611C6D56277FE6E558C331613A8E3EB3207DD256B60678E85F0E3B982` |
| TELFHASH | `t1d8d02201fb3027c8db8402f198ce359e200476772f0a3039d1888a0b4c838907828f02` |
| SSDEEP | `3072:qsVsLf6eLDpd8JR158Ziz5NheNWqnncmQjlGQ7UbQ5:qsVsL17ixRR8I4Q7Um` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_3f995d00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f995d003997e5a87ef43da077c3cef430899def1d5d327816435137437be84a"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:50"
  condition:
    hash.sha256(0, filesize) == "3f995d003997e5a87ef43da077c3cef430899def1d5d327816435137437be84a"
}
```

### Sample 56: `f75e42d8f866eff2`

| Field | Value |
|---|---|
| SHA-256 | `f75e42d8f866eff24afafe196c069e197dda6da79efbf01cc56066b378b10178` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `761d5a0c8ac17b5811124ae4095f049d` |
| SHA-1 | `943e25fdc17f1c32b9c97e2cbffde40dd3cd5453` |
| SHA-256 | `f75e42d8f866eff24afafe196c069e197dda6da79efbf01cc56066b378b10178` |
| SHA3-384 | `44c80555fc008c42e9db3a9b78449d7ccb59bee0ddbabab19576f55713df61d76d22556ed7eb56a7409097305a5c51c6` |
| TLSH | `T1DAB3AD35D9A05ED4C1544BB191F5EE3E0323D960454A2FB3A6998B5E4083FC8B82EFF9` |
| SSDEEP | `3072:GXF5liqGm5c+E6/HFt/928a0Xjsfz7UbY5:GVvDXNxHFvPH47Um` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_f75e42d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f75e42d8f866eff24afafe196c069e197dda6da79efbf01cc56066b378b10178"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:48"
  condition:
    hash.sha256(0, filesize) == "f75e42d8f866eff24afafe196c069e197dda6da79efbf01cc56066b378b10178"
}
```

### Sample 57: `1b05960b8416d815`

| Field | Value |
|---|---|
| SHA-256 | `1b05960b8416d815d0656bce0682e83fb5ab2a56c6cb258e3d2d963727249261` |
| Family label | `Mirai` |
| File name | `main_mips` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20964d181ea976cb78b22774e66d6c95` |
| SHA-1 | `09a0cf23d7a55242317eabdbf8ddf73812c28521` |
| SHA-256 | `1b05960b8416d815d0656bce0682e83fb5ab2a56c6cb258e3d2d963727249261` |
| SHA3-384 | `0bc2578cf5dc5f46d2df349e0dfa68101581655777b58628c1bc6e6e20732573305c68039dac11de0093f0a132be54cc` |
| TLSH | `T157144C52BF219FA2C659C171CFB38A5746D8158227D0908BB3ACDB187A21B452D8FFF4` |
| TELFHASH | `t17b3112309b305a01aba2da64dced5763611ed9175658af33de30809c502a0fde22bc8f` |
| SSDEEP | `3072:nShZOnO/DiFZ1i6n9RM8vdj7O9i2gUQ8vpGKXJ0Lc5nBrcS/:ShZGObwi6n9i81GI2gUQYpGsQ4Bp/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_1b05960b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b05960b8416d815d0656bce0682e83fb5ab2a56c6cb258e3d2d963727249261"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:45"
  condition:
    hash.sha256(0, filesize) == "1b05960b8416d815d0656bce0682e83fb5ab2a56c6cb258e3d2d963727249261"
}
```

### Sample 58: `d68dc2fc3c9fcfe1`

| Field | Value |
|---|---|
| SHA-256 | `d68dc2fc3c9fcfe120d1447e1b536eceeb324e2b12865ed108e8b7cfeca55749` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ece62f65dfd1812c846e8cbda08a7321` |
| SHA-1 | `dd89df3c1429fb19f3bb26b41cfc3e6a046665df` |
| SHA-256 | `d68dc2fc3c9fcfe120d1447e1b536eceeb324e2b12865ed108e8b7cfeca55749` |
| SHA3-384 | `03f9cc70f67e1d44e686fc60e59aae7214890211950f2f506f522f336cdaa98d49047dcab2ed9ebfc97b3f0986e63b42` |
| TLSH | `T184047C85F3A28AF4F90740F1C01EF3359F355E292131AE9FEFC626726D616124A67329` |
| TELFHASH | `t1212131724fbba870d70149b50b71ada8012d0c4eff371ef10995bc5c1c06a45a9fae23` |
| SSDEEP | `3072:Pw/0gerQy4HPEm1hH6Q827yxXmBTBkzRX4levNce7DOfcFUdpS4lTV:PNgerQyS8OhaVaevue7D54j` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_d68dc2fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d68dc2fc3c9fcfe120d1447e1b536eceeb324e2b12865ed108e8b7cfeca55749"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:42"
  condition:
    hash.sha256(0, filesize) == "d68dc2fc3c9fcfe120d1447e1b536eceeb324e2b12865ed108e8b7cfeca55749"
}
```

### Sample 59: `86c34631ee3ed2ea`

| Field | Value |
|---|---|
| SHA-256 | `86c34631ee3ed2eaa38ad409cabe601a2e74308886c4c6c98eac244298d638ab` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad717c41908b873fe141aa6538df99a9` |
| SHA-1 | `85d532b64e5dea9fdb69c22eba8b424fcf878363` |
| SHA-256 | `86c34631ee3ed2eaa38ad409cabe601a2e74308886c4c6c98eac244298d638ab` |
| SHA3-384 | `378d8d52a3910f3861fe6237300715fd9dc816d73e40f76ce08d1ac65bf77cc67ebb9bc951c2f6742daf3695d7d7bfe8` |
| TLSH | `T1B9A328C5FC919611C5D46277FE6E558C331613A4D2EA330BCE266B60778E82F0E7B981` |
| TELFHASH | `t1abd01253ae1109e41b5841a288d93a6141fd725d4f052c96d7e4a609d52b222641f62b` |
| SSDEEP | `3072:bxdIyC+h+s298f+DDZKRhA5tYZE+b7Ub9v5:bxdIC+so8fOA9ZTb7UH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_86c34631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c34631ee3ed2eaa38ad409cabe601a2e74308886c4c6c98eac244298d638ab"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:40"
  condition:
    hash.sha256(0, filesize) == "86c34631ee3ed2eaa38ad409cabe601a2e74308886c4c6c98eac244298d638ab"
}
```

### Sample 60: `5852806b591e5223`

| Field | Value |
|---|---|
| SHA-256 | `5852806b591e522302cd6d968057f30491cf3dda5811989cb8f1ac882d4168fd` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e44c83e3ec47412f96838d14b2592cc` |
| SHA-1 | `622c1607bfad276194c5bd6efab331a7a1e3ebda` |
| SHA-256 | `5852806b591e522302cd6d968057f30491cf3dda5811989cb8f1ac882d4168fd` |
| SHA3-384 | `8345687c33b23066e6db7cbb99af6e0e4ba36d39c1f880ded9226d45fa9dcae7fb5c48edd50a9f184eec5d98bb6c7a72` |
| TLSH | `T11E0419A6BE82D962C5D429BBEA1F85CC334313ACC7EE7002CD15DB2565DF4990B3AE44` |
| SSDEEP | `3072:hN8pDNDuuy0EZQ04AQ88YZ17Rrz1adF0A0sJ+chZMlkOqG+fMmLyVjKNdGt5Gx7:hN8EjZQ04AQk5Rf1a4Oc4yVjKNdG327` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_5852806b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5852806b591e522302cd6d968057f30491cf3dda5811989cb8f1ac882d4168fd"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:38"
  condition:
    hash.sha256(0, filesize) == "5852806b591e522302cd6d968057f30491cf3dda5811989cb8f1ac882d4168fd"
}
```

### Sample 61: `82a93421807c958f`

| Field | Value |
|---|---|
| SHA-256 | `82a93421807c958fb8b5c803e5c6f20fd84363ffb0705c3c0885c1533244084a` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b282ce349178d324545d6eb8389993c` |
| SHA-1 | `37c086374b06d98d7a3d225aeda8b08f52315a10` |
| SHA-256 | `82a93421807c958fb8b5c803e5c6f20fd84363ffb0705c3c0885c1533244084a` |
| SHA3-384 | `1441ae4c2a3654e6a263eb8b4cee9369824243ba7732a45a6d3ba96f4c4ff811f23ab1b73387724ab232b40a4cb6b68a` |
| TLSH | `T1AE54D75EEE3EED50CDAA853860F00BB7742994DDC3E8F05BCA0A49E6F55F0C0A26C556` |
| SSDEEP | `6144:E/jS/4ByMk4hVyM3TD9eD09qUN2Y/OKK5M5cU+s:sOEV3yM3YGcicUD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_82a93421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82a93421807c958fb8b5c803e5c6f20fd84363ffb0705c3c0885c1533244084a"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:36"
  condition:
    hash.sha256(0, filesize) == "82a93421807c958fb8b5c803e5c6f20fd84363ffb0705c3c0885c1533244084a"
}
```

### Sample 62: `3ad972f9a1b2a914`

| Field | Value |
|---|---|
| SHA-256 | `3ad972f9a1b2a9144e28a905cea945e422b118171f406e3c8dd8d42e1d3e74ba` |
| Family label | `Mirai` |
| File name | `main_x86` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02566478dc698c27ee843bf07582c272` |
| SHA-1 | `289fd0727a44eddaa0fa1f740dbe0d2e2e721669` |
| SHA-256 | `3ad972f9a1b2a9144e28a905cea945e422b118171f406e3c8dd8d42e1d3e74ba` |
| SHA3-384 | `18d8e9808ca7a50c0e882931396dbe0e844232e211a42a2e2a64cc79c17fa63308b174d95a23a7d5961d7b3d0a860b74` |
| TLSH | `T1ADE35B88EB52D9F6E09346700AA7D3D105349936416BEBD7FF4DA620BD32740BE4A31E` |
| TELFHASH | `t1823132309b201a01ab92ca64dcee4723651ec9175258af33de31c09c501a0fde22bc4f` |
| SSDEEP | `3072:dgXjYw5I5mL0NB9W9ZlorkHrdMs5XnzWuBkSz:wjf5IS0T9WHlorkLd9XntaSz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_3ad972f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ad972f9a1b2a9144e28a905cea945e422b118171f406e3c8dd8d42e1d3e74ba"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:34"
  condition:
    hash.sha256(0, filesize) == "3ad972f9a1b2a9144e28a905cea945e422b118171f406e3c8dd8d42e1d3e74ba"
}
```

### Sample 63: `6303ba90e3f83402`

| Field | Value |
|---|---|
| SHA-256 | `6303ba90e3f834029386e5df29d02f5239ffca6e56160ffde5b69183c62c4215` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d49f77ac31490291acaf4e8550a0286f` |
| SHA-1 | `717b11feaa27015d1333ad781b1369b2a2c1d037` |
| SHA-256 | `6303ba90e3f834029386e5df29d02f5239ffca6e56160ffde5b69183c62c4215` |
| SHA3-384 | `0937d3936b1106df20ebb362314c8309ae214997a207ede49b1aa8b953d5320895e418114e3bf230a0196ba6072f39ba` |
| TLSH | `T13624F986B5B5AEA0CAE74439B59407BC324687E9C3FEB00DCE118DE1BB5D1056A3D2C6` |
| SSDEEP | `3072:fYG7uTs0VYzJTsE8nWv4p2X2fC51ZzdXANHy3trALXw05O5n7:gvs4Er4p2X2f+nhXA5wAj5O5n7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_6303ba90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6303ba90e3f834029386e5df29d02f5239ffca6e56160ffde5b69183c62c4215"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:32"
  condition:
    hash.sha256(0, filesize) == "6303ba90e3f834029386e5df29d02f5239ffca6e56160ffde5b69183c62c4215"
}
```

### Sample 64: `15b3e5817bdff762`

| Field | Value |
|---|---|
| SHA-256 | `15b3e5817bdff76269c324f0d18ff2159f3fac14700350e384b18a53ff3e778a` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e43e6815ff8aaa0509b111a6fdf47df2` |
| SHA-1 | `7a48874323f640368c6286f4e9857133b306111d` |
| SHA-256 | `15b3e5817bdff76269c324f0d18ff2159f3fac14700350e384b18a53ff3e778a` |
| SHA3-384 | `c1c2a15547ec6d314bca6821ae18e197bb0d5ba50ad2f2e1aa1bae76130f674ee9e5d9ddb88d373c6efb6de3065d69b3` |
| TLSH | `T1B8344C6BFE54DF6FC40FA23059B3C7705AD65D712EA216AB2354C69C2E311B90E0B6E0` |
| SSDEEP | `6144:AbnGUyXrHBIj2BjxQSG1vZE/VhaJK4uMIJp2OubqsXF:A69rmj2BjxQSG1c4Vw6F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_15b3e581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15b3e5817bdff76269c324f0d18ff2159f3fac14700350e384b18a53ff3e778a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:29"
  condition:
    hash.sha256(0, filesize) == "15b3e5817bdff76269c324f0d18ff2159f3fac14700350e384b18a53ff3e778a"
}
```

### Sample 65: `1b63e86aca168a98`

| Field | Value |
|---|---|
| SHA-256 | `1b63e86aca168a9804c1778e99cdada533aa094e175e81b63e896cbeb033b540` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4462cb43b46af308812483025d93d26` |
| SHA-1 | `3b1cf9c21dad4bd5b14dd1f13bf22f111473434b` |
| SHA-256 | `1b63e86aca168a9804c1778e99cdada533aa094e175e81b63e896cbeb033b540` |
| SHA3-384 | `b5ebddb789fc6355307dae2ca4e45995716404d9f05932345fbd050be82272a7118216875f7cc5f017b0cf2c7d218f23` |
| TLSH | `T161B36CD7F400CE7DFCAED63A40574A06F235B6652E831B57A266FCA36D321845D22EC1` |
| SSDEEP | `3072:BnoDfzGmllBkJ4NQ7XXSt6RJJ/Sx35LnO7AhC9Uqb:SDfzGmllBkJwQ7XXL/Sl5k4C9U+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_1b63e86a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b63e86aca168a9804c1778e99cdada533aa094e175e81b63e896cbeb033b540"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:27"
  condition:
    hash.sha256(0, filesize) == "1b63e86aca168a9804c1778e99cdada533aa094e175e81b63e896cbeb033b540"
}
```

### Sample 66: `320f879bc3955052`

| Field | Value |
|---|---|
| SHA-256 | `320f879bc3955052d92275fcfbad5754373d0a432f13f0e58028e54a9105bfca` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a99db5b52c0183419d1498a929081dd` |
| SHA-1 | `594c600ec453202117830b64a9c29d160f2e0062` |
| SHA-256 | `320f879bc3955052d92275fcfbad5754373d0a432f13f0e58028e54a9105bfca` |
| SHA3-384 | `10e1e2e71debbdba5c975a598bf6e4be2f6116f32844dc6b9bb18903cf9d8ae9045b5da8479e617c53d5baa58d71b50e` |
| TLSH | `T13FC37D22A97E192BC1C0A57B01F74735F2FA474A31A8C61E7D720EADEF157202117BB9` |
| SSDEEP | `1536:Fr0KmH3dB6lE9WQ6lG4cn6MW8cVClANoTM9ktY0c5sOtG88IIa4/7URbE4XkBY9j:Fr0KyB6+lz4cnrWOSoYp5nAtD/7UNN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_320f879b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "320f879bc3955052d92275fcfbad5754373d0a432f13f0e58028e54a9105bfca"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:25"
  condition:
    hash.sha256(0, filesize) == "320f879bc3955052d92275fcfbad5754373d0a432f13f0e58028e54a9105bfca"
}
```

### Sample 67: `f3fd933c2d1589f8`

| Field | Value |
|---|---|
| SHA-256 | `f3fd933c2d1589f8f9975a3b79fd160d8305f13d05aa96fb54bc8009b44e9e83` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `239f80de54aa092da96ca1456f9bce20` |
| SHA-1 | `e4532b1d55f96d41334ec42e61ac81bff1425e3f` |
| SHA-256 | `f3fd933c2d1589f8f9975a3b79fd160d8305f13d05aa96fb54bc8009b44e9e83` |
| SHA3-384 | `4c459b6349955525fd54f7a19150f5bd142bb3c33d1a32e9a9803b850210935ca08475cc448c8b5429eccd01b66dad9a` |
| TLSH | `T148B35C0177584A47E5671EF4393F2BF183AEE99424F0F688794EEA098271E734546ECC` |
| SSDEEP | `1536:t6NvTSNDD456SJFtiMM6yWcsU+dxljZrQI6GeFEiY8O7U/7fX0QLp:ITSNDc56SJFIMrTUaDZrQILZ57UTX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_f3fd933c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3fd933c2d1589f8f9975a3b79fd160d8305f13d05aa96fb54bc8009b44e9e83"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:23"
  condition:
    hash.sha256(0, filesize) == "f3fd933c2d1589f8f9975a3b79fd160d8305f13d05aa96fb54bc8009b44e9e83"
}
```

### Sample 68: `2ed94ae8f35e9d37`

| Field | Value |
|---|---|
| SHA-256 | `2ed94ae8f35e9d3777dbd51863dda9140532b9b67b90271d7eecf9df82cec102` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1429c8a38ea4711b0ff815925592d489` |
| SHA-1 | `0ed25a096455baa7926d0e2aef595f679f596c17` |
| SHA-256 | `2ed94ae8f35e9d3777dbd51863dda9140532b9b67b90271d7eecf9df82cec102` |
| SHA3-384 | `675fe1cb706c9cdc2a6b65b69644dc2ca8a582873b0612a1c6f2674a155131ecf85c2ab657e2ad22f614e368049719f5` |
| TLSH | `T1C924098675B5AEA0CAF74439B19803BC364687E9C3FEB04DCE118DE1BB5D4056A3D2C6` |
| SSDEEP | `3072:mYubjjO51VHAum+bh9ublz6GhDziX+/c9ATaAeXw05O5n+:XuOgumAublz6GhD2X+05A+5O5n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_2ed94ae8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ed94ae8f35e9d3777dbd51863dda9140532b9b67b90271d7eecf9df82cec102"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:21"
  condition:
    hash.sha256(0, filesize) == "2ed94ae8f35e9d3777dbd51863dda9140532b9b67b90271d7eecf9df82cec102"
}
```

### Sample 69: `26e83ad77774fc32`

| Field | Value |
|---|---|
| SHA-256 | `26e83ad77774fc32a27ff868eb6339e9e574278172d2a053311ca1ddd475fdee` |
| Family label | `Mirai` |
| File name | `main_arm6` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7c2d0359809e47a11b5acaacb4bffbf` |
| SHA-1 | `9cc777a88d657d329e93f2fbdeec73ee29d099c5` |
| SHA-256 | `26e83ad77774fc32a27ff868eb6339e9e574278172d2a053311ca1ddd475fdee` |
| SHA3-384 | `fd212c86afdae198ee40e164e040d6e20c654c153465ed045884addf5049ae1843ae3ac4d1fca2999fd75b482247f874` |
| TLSH | `T17CE31951F8608A67C6D5177AB65F429C33328768D3DB3312692C96383FA771E0F2BA41` |
| TELFHASH | `t10c3112309b305a01aba2da64dced5763651ed9175658bf33de30809c502a0fde22bc8f` |
| SSDEEP | `3072:LQGWjEbGIafGNXVtmkjkRLmvSIqlKVa2ZZTTy6wYfr:LgDZkBoRmvS4FZvy6wQr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_26e83ad7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26e83ad77774fc32a27ff868eb6339e9e574278172d2a053311ca1ddd475fdee"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:19"
  condition:
    hash.sha256(0, filesize) == "26e83ad77774fc32a27ff868eb6339e9e574278172d2a053311ca1ddd475fdee"
}
```

### Sample 70: `5cf03b5ea2fc3eb7`

| Field | Value |
|---|---|
| SHA-256 | `5cf03b5ea2fc3eb7f05f08f233ab43ba2a4b5cdbdcee1b50696646b359891d42` |
| Family label | `Mirai` |
| File name | `main_x86_64` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7c4c75b14bc489ada95a490b7882af6` |
| SHA-1 | `243b500f57387eef2039fa3f216be7bc9149b8c1` |
| SHA-256 | `5cf03b5ea2fc3eb7f05f08f233ab43ba2a4b5cdbdcee1b50696646b359891d42` |
| SHA3-384 | `74443c8e5656f51a4dc1b75908b4d55e0862c812f6b2cb7b91d4a46afd805becb57d960e4c7288ae377519da370ea2a6` |
| TLSH | `T1C3D32B03B6D26CFEC583C035575F9562AA32F8740211AE3B77D8EA352E39D902F19B25` |
| TELFHASH | `t1273112309b205a15ab92ca64dced5763611ed9175258ae33de30c09d502a0fde22bc4f` |
| SSDEEP | `1536:fTwdYaT9wj4CXdtVAysd0Tlxj1RcfHznZVKp6N/tWe/wXxxSU3mjXUQeD+C4TQwU:rUjSjnXzVHTlxj/cfKXC+CQ8MPgp2Zj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_5cf03b5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cf03b5ea2fc3eb7f05f08f233ab43ba2a4b5cdbdcee1b50696646b359891d42"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:17"
  condition:
    hash.sha256(0, filesize) == "5cf03b5ea2fc3eb7f05f08f233ab43ba2a4b5cdbdcee1b50696646b359891d42"
}
```

### Sample 71: `2446366133412703`

| Field | Value |
|---|---|
| SHA-256 | `24463661334127036d64b10684763dda3f9086469aa9ef1d0545bc45e5812a22` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98065057ec571c528f1c32d48aed0768` |
| SHA-1 | `8266c28e71793587e71d77b661da739cf5eadd97` |
| SHA-256 | `24463661334127036d64b10684763dda3f9086469aa9ef1d0545bc45e5812a22` |
| SHA3-384 | `5e8d256f3fd2b983d148b8905726ac21fec77105f225ab7d22520e8c05608022b55671a8cfa9618f676d542f6eafcd39` |
| TLSH | `T139046B03B9E250ECD8AAC434AB6ED622EB343C4D5331B79F67D87A613E25E142F59314` |
| TELFHASH | `t116314805625a3aa57b541e07da8d7c3f2cc712d2d58b7a8f66e883811cadfc22a95037` |
| SSDEEP | `3072:A50oE3Xd9gYhELgpT1uQBW/aTz+rQSDegv8MRlKKjQ:ASXUH2NBWS3SDegUc0aQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_24463661
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24463661334127036d64b10684763dda3f9086469aa9ef1d0545bc45e5812a22"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:14"
  condition:
    hash.sha256(0, filesize) == "24463661334127036d64b10684763dda3f9086469aa9ef1d0545bc45e5812a22"
}
```

### Sample 72: `23da61097e552caa`

| Field | Value |
|---|---|
| SHA-256 | `23da61097e552caabaaf2d083a695c442543de5935af8f05f317f096434904b4` |
| Family label | `unknown` |
| File name | `23da61097e552caabaaf2d083a695c442543de5935af8f05f317f096434904b4.exe` |
| File type | `exe` |
| First seen | `2026-11-07 01:42:14` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ace4d645674fad68c74a004e7ac19e34` |
| SHA-1 | `749e3cd2f609303f3d626a022d8b5912604d044c` |
| SHA-256 | `23da61097e552caabaaf2d083a695c442543de5935af8f05f317f096434904b4` |
| SHA3-384 | `c74fa39cbe1d4c0a1f4c3802d1c666d1dfc8bd1d137a1e668aa6f355a9442cc80ef04b4ab7f2e4790cc392d2aead22df` |
| IMPHASH | `e81d90b230abc81b286482b9dba12e35` |
| TLSH | `T1D7363300D1038853FE65427FA4E3FE7E4D6AA9992B7415E6AE407F2D7BA5933A5F00C0` |
| SSDEEP | `98304:KcPQOJVw8hqS3YemC8scbOHWJi/Uk1BchXpExToLQ:KcPTJVwqqS3Yev8sciHWgc8Bch5EGQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_23da6109
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23da61097e552caabaaf2d083a695c442543de5935af8f05f317f096434904b4"
    family = "unknown"
    file_name = "23da61097e552caabaaf2d083a695c442543de5935af8f05f317f096434904b4.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:42:14"
  condition:
    hash.sha256(0, filesize) == "23da61097e552caabaaf2d083a695c442543de5935af8f05f317f096434904b4"
}
```

### Sample 73: `9c202ddb2194b277`

| Field | Value |
|---|---|
| SHA-256 | `9c202ddb2194b27710d7a67c4eccca8dbdaccf15ca1bbb43b41065947d4c5ebc` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce5b7d63b37319cf295c93f442e1d0d3` |
| SHA-1 | `b13959a6dffa5b5b4f683dbc07db2cedc4eee8bd` |
| SHA-256 | `9c202ddb2194b27710d7a67c4eccca8dbdaccf15ca1bbb43b41065947d4c5ebc` |
| SHA3-384 | `83b569c689b9f746d0ce3a67eb9d1add247fa902ecd55c63105aa0001bb96bbbc81f8f7b17718cb90ea743ab7ccaaa6a` |
| TLSH | `T159E3D70AAF610FFBE8AFCD3346D90709198C561622F96F767634D818B74B24F19E3864` |
| SSDEEP | `3072:U+KOA1ez2fxbNiN9CSHW6HmzeJqL8mMxdofUIK7U0Y5:rKOA1eqfxbNiN9CS1Q2VmMxdofK7U/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_9c202ddb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c202ddb2194b27710d7a67c4eccca8dbdaccf15ca1bbb43b41065947d4c5ebc"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:12"
  condition:
    hash.sha256(0, filesize) == "9c202ddb2194b27710d7a67c4eccca8dbdaccf15ca1bbb43b41065947d4c5ebc"
}
```

### Sample 74: `32984eb6ccebb8a2`

| Field | Value |
|---|---|
| SHA-256 | `32984eb6ccebb8a271f109aaf549dc0c7c0eb5e03172e05b4c677d281e7b9327` |
| Family label | `Mirai` |
| File name | `main_sh4` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd39baa711c2826bd225d96011729b8c` |
| SHA-1 | `2c33c565dbb518ecd527513b905bc709be647a15` |
| SHA-256 | `32984eb6ccebb8a271f109aaf549dc0c7c0eb5e03172e05b4c677d281e7b9327` |
| SHA3-384 | `b7315a67e21ab7a7cb9b13ee59efa5caa20799fe46f9a172b1aaacf0d79b95cef9cde9c2a928475e9d674b7161c2d99d` |
| TLSH | `T16773AE72F1482CA6CC211AF5F435CAB803126CF141D61C75BDEDE5AA68A3E8CFA4E754` |
| SSDEEP | `1536:TJ2MoM7yobEl7Xj+qxSV6Hh6z+ahP6wJrc:NVWobgzDxCwhql3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_32984eb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32984eb6ccebb8a271f109aaf549dc0c7c0eb5e03172e05b4c677d281e7b9327"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:10"
  condition:
    hash.sha256(0, filesize) == "32984eb6ccebb8a271f109aaf549dc0c7c0eb5e03172e05b4c677d281e7b9327"
}
```

### Sample 75: `40a964d9b667ce4f`

| Field | Value |
|---|---|
| SHA-256 | `40a964d9b667ce4fa7cf504fb112fd6aa3c2d5d6b26248fc189b153b0ba11f45` |
| Family label | `unknown` |
| File name | `40a964d9b667ce4fa7cf504fb112fd6aa3c2d5d6b26248fc189b153b0ba11f45.msi` |
| File type | `msi` |
| First seen | `2026-11-07 01:42:09` |
| Reporter | `Tuxxin` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `057ebf391ee79a39617c05119022e69a` |
| SHA-1 | `6069d14cfd1fa340c5857183d77765c94d55fdc5` |
| SHA-256 | `40a964d9b667ce4fa7cf504fb112fd6aa3c2d5d6b26248fc189b153b0ba11f45` |
| SHA3-384 | `92fa894d85e007e2ba2eda67b5575e37dffcc05a03eecc8a96406c99aff3f7596285c18b89bda7c92974887515285ff9` |
| TLSH | `T1E25633D76ED88E0DD837A9B80770E93DD636BC219903552C05D6B1AD3A327C9BF90352` |
| SSDEEP | `98304:FmrqGTV7vDdEzqfaDiSL9yo0mlusxI55ct1bFqHhrmwFtipVd/4qHHX:0Ggc3Lhx8oIOFwhrxFtqj/nH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_40a964d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40a964d9b667ce4fa7cf504fb112fd6aa3c2d5d6b26248fc189b153b0ba11f45"
    family = "unknown"
    file_name = "40a964d9b667ce4fa7cf504fb112fd6aa3c2d5d6b26248fc189b153b0ba11f45.msi"
    file_type = "msi"
    first_seen = "2026-11-07 01:42:09"
  condition:
    hash.sha256(0, filesize) == "40a964d9b667ce4fa7cf504fb112fd6aa3c2d5d6b26248fc189b153b0ba11f45"
}
```

### Sample 76: `3774f83a28267cf1`

| Field | Value |
|---|---|
| SHA-256 | `3774f83a28267cf11886cdf70a820809162b672a151f33bbc7161901e8df1afb` |
| Family label | `Mirai` |
| File name | `main_ppc` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47d807ff290fc8f37b11ee4f0dd5ab74` |
| SHA-1 | `ae26b1ab084a00443d64b5e18c9a60a66f08730c` |
| SHA-256 | `3774f83a28267cf11886cdf70a820809162b672a151f33bbc7161901e8df1afb` |
| SHA3-384 | `e92bfcdac10599769896e985708a1b654bfeaf8265d30f4f1696eca814932ac205f0c759df1401785fee6039168225b8` |
| TLSH | `T1F4932B01B7250A47E1B65DF02E3F2BE1C7AA8E9210F47288795FBB45D672E321446ECD` |
| SSDEEP | `1536:aUvFGDEI3p1SrhlH/VCFszcV4JIQfL7pXXoddMA3fvIvLSrw:REWlXpYHMAoDKw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_3774f83a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3774f83a28267cf11886cdf70a820809162b672a151f33bbc7161901e8df1afb"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:07"
  condition:
    hash.sha256(0, filesize) == "3774f83a28267cf11886cdf70a820809162b672a151f33bbc7161901e8df1afb"
}
```

### Sample 77: `d2a5c223232a7dfb`

| Field | Value |
|---|---|
| SHA-256 | `d2a5c223232a7dfbc28bfada6f7d67f76da713f5e02a6464422d31a992919df4` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a62421c8cd8ac2472b11e64ddbd13e3c` |
| SHA-1 | `db528a884534aa7469b36a29f0267be26700a75c` |
| SHA-256 | `d2a5c223232a7dfbc28bfada6f7d67f76da713f5e02a6464422d31a992919df4` |
| SHA3-384 | `59630ca6f941c7a3f0875e1329366658b8feb240df7f597c72cfac01338ea46d9d8a3bee94a55ea45b7a655690337182` |
| TLSH | `T16AC329C6B8919B11C5D456BAFE6E218D331317B8E3DE73138E245B74278A82F0E3B546` |
| TELFHASH | `t110c08009fa544ed437c7024541945000c6bbf19f3760150d11b81fb1d6a1d5f311d813` |
| SSDEEP | `3072:7FVHRJVi39kCvRRhWBbBhCCkhe07lrs97CR0chc48j0kbe7UbQ5:7Ri3pseCYMCLh98j0Ie7Uu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_d2a5c223
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2a5c223232a7dfbc28bfada6f7d67f76da713f5e02a6464422d31a992919df4"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:05"
  condition:
    hash.sha256(0, filesize) == "d2a5c223232a7dfbc28bfada6f7d67f76da713f5e02a6464422d31a992919df4"
}
```

### Sample 78: `a676b80a15dac6dc`

| Field | Value |
|---|---|
| SHA-256 | `a676b80a15dac6dcfbccd81498b82141aee6f229728f8632d12c4d4329bfd5fe` |
| Family label | `ConnectWise` |
| File name | `a676b80a15dac6dcfbccd81498b82141aee6f229728f8632d12c4d4329bfd5fe.exe` |
| File type | `exe` |
| First seen | `2026-11-07 01:42:04` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `141563daf07744384d07f4510d2abafb` |
| SHA-1 | `0bda43e86a72e5673e5eaa351985d91a5707a5f4` |
| SHA-256 | `a676b80a15dac6dcfbccd81498b82141aee6f229728f8632d12c4d4329bfd5fe` |
| SHA3-384 | `3f2d9df8422f648465f5b90c12436c7ae2af839168e35ad6f5b265b72598d567744cb54e19a482da06360a715cb5fbb4` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T134D61211B3F59675D1FB0638E87AA3615A35BC014B12C7AF6794792A2D327C08E323B7` |
| SSDEEP | `393216:yFri04SOLiX1eFri04SOLmFri04SOLyFri04SOLR:yMrSOL4gMrSOLmMrSOLyMrSOLR` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_078_a676b80a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a676b80a15dac6dcfbccd81498b82141aee6f229728f8632d12c4d4329bfd5fe"
    family = "ConnectWise"
    file_name = "a676b80a15dac6dcfbccd81498b82141aee6f229728f8632d12c4d4329bfd5fe.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:42:04"
  condition:
    hash.sha256(0, filesize) == "a676b80a15dac6dcfbccd81498b82141aee6f229728f8632d12c4d4329bfd5fe"
}
```

### Sample 79: `b8bfcdc686ec1020`

| Field | Value |
|---|---|
| SHA-256 | `b8bfcdc686ec102054afe9a4ca344a82a47e0a60c41da85fef032a5820a107d1` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-11-07 01:42:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb8a287985a80e7d0c2572440e5b76ba` |
| SHA-1 | `8e531cc681567f130e3ee287ae607f65b9680099` |
| SHA-256 | `b8bfcdc686ec102054afe9a4ca344a82a47e0a60c41da85fef032a5820a107d1` |
| SHA3-384 | `d725a5868cbf533d0dcf1bc30060344fedfd01018207677cd69b157646d12834b4ac3125f17cea489cbc3743dedd826a` |
| TLSH | `T14D04AE404C2DFAB3DBC5E4FD4D5C0F14322B38B91579D32A1E1252AED847650AFE6BA2` |
| SSDEEP | `3072:HSZSNdGsopd4NzHwLQGjXxstW7WVyOqfZzkKxJ2DQrgjzUgZukISweTQ:nkxnqkjxTSVyOqhzkKxYUmNZukISw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_b8bfcdc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8bfcdc686ec102054afe9a4ca344a82a47e0a60c41da85fef032a5820a107d1"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:03"
  condition:
    hash.sha256(0, filesize) == "b8bfcdc686ec102054afe9a4ca344a82a47e0a60c41da85fef032a5820a107d1"
}
```

### Sample 80: `cc965e6df4b6bcf2`

| Field | Value |
|---|---|
| SHA-256 | `cc965e6df4b6bcf2512131d889fac685f2b14f3d37cdbecd4fce2a7d4d5a9fad` |
| Family label | `ConnectWise` |
| File name | `cc965e6df4b6bcf2512131d889fac685f2b14f3d37cdbecd4fce2a7d4d5a9fad.exe` |
| File type | `exe` |
| First seen | `2026-11-07 01:41:58` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8233b7e9c75a81d7963006804d984d16` |
| SHA-1 | `760b8eb26993b341513e8b6efb395653b20c7ff5` |
| SHA-256 | `cc965e6df4b6bcf2512131d889fac685f2b14f3d37cdbecd4fce2a7d4d5a9fad` |
| SHA3-384 | `b3993299f815203e4fe3c799a06d6847ff9e00ff5fceb7b43a975bd321b403df7ab21f148e6aabbdd3b8fcd364af22ae` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T111D61211B3F59675D1FB0638E87AA3615A35BC014B12C7AF6794792A2D327C08E323B7` |
| SSDEEP | `393216:JFri04SOLbX1QFri04SOLmFri04SOLeFri04SOLg:JMrSOLreMrSOLmMrSOLeMrSOLg` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_080_cc965e6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc965e6df4b6bcf2512131d889fac685f2b14f3d37cdbecd4fce2a7d4d5a9fad"
    family = "ConnectWise"
    file_name = "cc965e6df4b6bcf2512131d889fac685f2b14f3d37cdbecd4fce2a7d4d5a9fad.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:41:58"
  condition:
    hash.sha256(0, filesize) == "cc965e6df4b6bcf2512131d889fac685f2b14f3d37cdbecd4fce2a7d4d5a9fad"
}
```

### Sample 81: `fa0b28bcc9df5f00`

| Field | Value |
|---|---|
| SHA-256 | `fa0b28bcc9df5f0014191a163fa9d7936698d29d865e8160b4f19e823aa51246` |
| Family label | `Mirai` |
| File name | `fa0b28bcc9df5f0014191a163fa9d7936698d29d865e8160b4f19e823aa51246.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:41:53` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffb3e240089b0e7e0fbafae369781dd8` |
| SHA-1 | `111a063cf63580a76ef1aeed00b187e07d3d7077` |
| SHA-256 | `fa0b28bcc9df5f0014191a163fa9d7936698d29d865e8160b4f19e823aa51246` |
| SHA3-384 | `073edd6225de8e65a21e5ac8285a41389b8378618a747f1308500dce9dbf2a1a60b5b5d5197e1cdff2b7e5d1ceea74f8` |
| TLSH | `T125F13256BAEBCD73CCAD233A07678714337588D2AB42AB13611C08752D835ECAD77AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtLWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/774OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_fa0b28bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa0b28bcc9df5f0014191a163fa9d7936698d29d865e8160b4f19e823aa51246"
    family = "Mirai"
    file_name = "fa0b28bcc9df5f0014191a163fa9d7936698d29d865e8160b4f19e823aa51246.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:41:53"
  condition:
    hash.sha256(0, filesize) == "fa0b28bcc9df5f0014191a163fa9d7936698d29d865e8160b4f19e823aa51246"
}
```

### Sample 82: `45af486893fbc5ec`

| Field | Value |
|---|---|
| SHA-256 | `45af486893fbc5ecfefd0a883fac4e61cb6f4fe197d607a2db5fc4f9102d75cf` |
| Family label | `Mirai` |
| File name | `45af486893fbc5ecfefd0a883fac4e61cb6f4fe197d607a2db5fc4f9102d75cf.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:40:25` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c361cfaf8ac995329fb452258887c2f` |
| SHA-1 | `229441ac754f34281027c6540a250ec5e8cfff5a` |
| SHA-256 | `45af486893fbc5ecfefd0a883fac4e61cb6f4fe197d607a2db5fc4f9102d75cf` |
| SHA3-384 | `a9acbd88b474620563b80d290fb4a58f30e10d702092f3c0e4c55c6db47ec3cf4bb257949e7d8a346f3f8b4e2f0fd1ec` |
| TLSH | `T1E7E15207E2D5CD72D8CD133846935649213AC86EAA83AF03650C5999EE43BDC7A63752` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFz146owz7cSym4S2ofahbpZiQ:fsue7c+JDFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_45af4868
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45af486893fbc5ecfefd0a883fac4e61cb6f4fe197d607a2db5fc4f9102d75cf"
    family = "Mirai"
    file_name = "45af486893fbc5ecfefd0a883fac4e61cb6f4fe197d607a2db5fc4f9102d75cf.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:40:25"
  condition:
    hash.sha256(0, filesize) == "45af486893fbc5ecfefd0a883fac4e61cb6f4fe197d607a2db5fc4f9102d75cf"
}
```

### Sample 83: `f8c2baa82c618ced`

| Field | Value |
|---|---|
| SHA-256 | `f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb` |
| Family label | `Snowlight` |
| File name | `f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:40:21` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f48c869830db970c3cda8c656f9ee8d0` |
| SHA-1 | `02aa5e3d3186d93fb0ce69c0b852e0c3721b87c1` |
| SHA-256 | `f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb` |
| SHA3-384 | `89296aed6214dc32a085f463defba8fdcd4b6cd5c33631c469f2087afcb5f6da00bc7582c4a0994042ef8f72eda47696` |
| TLSH | `T11A123047A2D0CE3FC8E953384467122472B794BEDF629713064915B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6hH5ML09V1J9G8YmF+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWH+ZMWT1YmYhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_083_f8c2baa8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb"
    family = "Snowlight"
    file_name = "f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:40:21"
  condition:
    hash.sha256(0, filesize) == "f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb"
}
```

### Sample 84: `d1dfbe3dc672cfe4`

| Field | Value |
|---|---|
| SHA-256 | `d1dfbe3dc672cfe43cbb53911b0cf5a1ecd9ea66cf3a901a804b665eb11755de` |
| Family label | `Snowlight` |
| File name | `d1dfbe3dc672cfe43cbb53911b0cf5a1ecd9ea66cf3a901a804b665eb11755de.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:37:57` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fead2d5d08347d9b26a203690e2d315` |
| SHA-1 | `0ea3d3332434115e7801e5a0a41f35c0593f8f10` |
| SHA-256 | `d1dfbe3dc672cfe43cbb53911b0cf5a1ecd9ea66cf3a901a804b665eb11755de` |
| SHA3-384 | `3393dab291a22e16ebbaddf28731f4ec1f6e04ec190c9fc8ad7093fd332a1efe8824e906d2e0f559672284ede372f861` |
| TLSH | `T103122F47A2D0CE3FC8D953384467122472B794BADF629713064915B53F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6pH5ML09V1J9G8Ymf+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHqZMWT1Ym2hrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_084_d1dfbe3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1dfbe3dc672cfe43cbb53911b0cf5a1ecd9ea66cf3a901a804b665eb11755de"
    family = "Snowlight"
    file_name = "d1dfbe3dc672cfe43cbb53911b0cf5a1ecd9ea66cf3a901a804b665eb11755de.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:57"
  condition:
    hash.sha256(0, filesize) == "d1dfbe3dc672cfe43cbb53911b0cf5a1ecd9ea66cf3a901a804b665eb11755de"
}
```

### Sample 85: `5e6c245a96999367`

| Field | Value |
|---|---|
| SHA-256 | `5e6c245a96999367701dfa2288b391a6dad9ec2044744291b61af665ae6f30e4` |
| Family label | `Snowlight` |
| File name | `5e6c245a96999367701dfa2288b391a6dad9ec2044744291b61af665ae6f30e4.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:37:54` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `add0f9597456e77547906917ed382af3` |
| SHA-1 | `819582f0d9bfebb08359d1652c408acb4e3c81f6` |
| SHA-256 | `5e6c245a96999367701dfa2288b391a6dad9ec2044744291b61af665ae6f30e4` |
| SHA3-384 | `d304e831c76c3f5af646a395b232c339c2bf49a3841d6a152345ef962934f4bc1241e5308bdda672661a888b2f8e761c` |
| TLSH | `T124E17117E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3QJheuhip5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbgJhAHZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_085_5e6c245a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e6c245a96999367701dfa2288b391a6dad9ec2044744291b61af665ae6f30e4"
    family = "Snowlight"
    file_name = "5e6c245a96999367701dfa2288b391a6dad9ec2044744291b61af665ae6f30e4.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:54"
  condition:
    hash.sha256(0, filesize) == "5e6c245a96999367701dfa2288b391a6dad9ec2044744291b61af665ae6f30e4"
}
```

### Sample 86: `4eb5ddf388f28859`

| Field | Value |
|---|---|
| SHA-256 | `4eb5ddf388f28859e833577f4af9856af671f5a2967755c8fd66cde77bace586` |
| Family label | `Mirai` |
| File name | `4eb5ddf388f28859e833577f4af9856af671f5a2967755c8fd66cde77bace586.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:37:50` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cce0634d05eb6e7f3ed786d859c34d0b` |
| SHA-1 | `ed4c504c5daf2eba8886826c7f95477c6236c313` |
| SHA-256 | `4eb5ddf388f28859e833577f4af9856af671f5a2967755c8fd66cde77bace586` |
| SHA3-384 | `3516555505b7ffe29c651163796f13b3170f730ee46ecd0f5256f75a4ec849bc65569a7754054c0cd0eccdefe44e713a` |
| TLSH | `T167E15207E2D5CE72D8CD133846935749213AC86EAB83AF03650C5999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFl146awz7cSym4S2ofahbpZiQ:fsue7cUJVFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_4eb5ddf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eb5ddf388f28859e833577f4af9856af671f5a2967755c8fd66cde77bace586"
    family = "Mirai"
    file_name = "4eb5ddf388f28859e833577f4af9856af671f5a2967755c8fd66cde77bace586.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:50"
  condition:
    hash.sha256(0, filesize) == "4eb5ddf388f28859e833577f4af9856af671f5a2967755c8fd66cde77bace586"
}
```

### Sample 87: `2496f931855e64d0`

| Field | Value |
|---|---|
| SHA-256 | `2496f931855e64d06bc570a5f8bcdf8759c3ce485641fe76ed8033392a173844` |
| Family label | `unknown` |
| File name | `2496f931855e64d06bc570a5f8bcdf8759c3ce485641fe76ed8033392a173844.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:37:09` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ae9ca6e9ec2d23d5f8dbf103b741699` |
| SHA-1 | `f63c860048531df79c1723de62a4ffc7faec8de1` |
| SHA-256 | `2496f931855e64d06bc570a5f8bcdf8759c3ce485641fe76ed8033392a173844` |
| SHA3-384 | `ad5d9a9d031e19f4c015551973eb5a911250573fbf03ce870ffa96d76b8371dc8ed3e1c1079882342cc94e0d55860b59` |
| TLSH | `T1AFE12482B9D6CE3BCCE962761673C6203372C951AB439B17210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsTILmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSv5g/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_2496f931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2496f931855e64d06bc570a5f8bcdf8759c3ce485641fe76ed8033392a173844"
    family = "unknown"
    file_name = "2496f931855e64d06bc570a5f8bcdf8759c3ce485641fe76ed8033392a173844.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:09"
  condition:
    hash.sha256(0, filesize) == "2496f931855e64d06bc570a5f8bcdf8759c3ce485641fe76ed8033392a173844"
}
```

### Sample 88: `c6aec0447e9ce24c`

| Field | Value |
|---|---|
| SHA-256 | `c6aec0447e9ce24cda96a29676761459e6a44580db5965b39520593268304e16` |
| Family label | `unknown` |
| File name | `c6aec0447e9ce24c.js` |
| File type | `js` |
| First seen | `2026-11-07 01:37:07` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c36b07444aec0d67843bb87065a173d5` |
| SHA-1 | `c46e41a70080bedc5b87ae176dbfb9761aa20c4a` |
| SHA-256 | `c6aec0447e9ce24cda96a29676761459e6a44580db5965b39520593268304e16` |
| SHA3-384 | `1dc43915f11bacdd34946a09ffe38cf3b650d8de4b936f67120d89924f8ad816e04ef3aa52d8c38a6d834bedc87d908a` |
| TLSH | `T144426313534043BBE29409E5E319365B66F2D98BE428204D6FA36DFEF82D5979438B33` |
| SSDEEP | `384:SBR0L8GRqRrfU8FoyrT/4hViJVqYvE/htp:0qL8KqRrM8uyrT+yw/J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_c6aec044
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6aec0447e9ce24cda96a29676761459e6a44580db5965b39520593268304e16"
    family = "unknown"
    file_name = "c6aec0447e9ce24c.js"
    file_type = "js"
    first_seen = "2026-11-07 01:37:07"
  condition:
    hash.sha256(0, filesize) == "c6aec0447e9ce24cda96a29676761459e6a44580db5965b39520593268304e16"
}
```

### Sample 89: `4932caeb67bf5cac`

| Field | Value |
|---|---|
| SHA-256 | `4932caeb67bf5cacdc0feb01c6852952c02f62a2141b13b979fc06f99c923a76` |
| Family label | `Mirai` |
| File name | `4932caeb67bf5cacdc0feb01c6852952c02f62a2141b13b979fc06f99c923a76.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:37:05` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2e10a64f02c519450913c9a599f13f4` |
| SHA-1 | `8d69ce81f244d850093924aba8cf2baf34761c76` |
| SHA-256 | `4932caeb67bf5cacdc0feb01c6852952c02f62a2141b13b979fc06f99c923a76` |
| SHA3-384 | `8888893e04e2b55dd47a9e39c55323e93a062cf1768d1b82ababe259890a996aa134965aa68ef63cd542c0123d73397d` |
| TLSH | `T1DC125147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5XlTTej6TNJ9VENddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTjTTfTpV8dfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_4932caeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4932caeb67bf5cacdc0feb01c6852952c02f62a2141b13b979fc06f99c923a76"
    family = "Mirai"
    file_name = "4932caeb67bf5cacdc0feb01c6852952c02f62a2141b13b979fc06f99c923a76.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:05"
  condition:
    hash.sha256(0, filesize) == "4932caeb67bf5cacdc0feb01c6852952c02f62a2141b13b979fc06f99c923a76"
}
```

### Sample 90: `d56193bee7108d0e`

| Field | Value |
|---|---|
| SHA-256 | `d56193bee7108d0e9e695eaed33db5c326a5c4560cbcaab4e1978b3847db3a10` |
| Family label | `Mirai` |
| File name | `d56193bee7108d0e9e695eaed33db5c326a5c4560cbcaab4e1978b3847db3a10.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:37:02` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aee73f6776f3aec62a838a7968bdf2fb` |
| SHA-1 | `8eef4a1fe335c86794dac9cb219ccd5a52a24144` |
| SHA-256 | `d56193bee7108d0e9e695eaed33db5c326a5c4560cbcaab4e1978b3847db3a10` |
| SHA3-384 | `e6fc84589c3372e80ee485a001f7322fae5cb977f6dab2ddf053eecb550a507d73d449ce5aab1df03945b3d3c0cbd629` |
| TLSH | `T158F13256BAEBCD73CCAD233A07678714337588D2AB43AB13611C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtjWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7n4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_d56193be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d56193bee7108d0e9e695eaed33db5c326a5c4560cbcaab4e1978b3847db3a10"
    family = "Mirai"
    file_name = "d56193bee7108d0e9e695eaed33db5c326a5c4560cbcaab4e1978b3847db3a10.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:02"
  condition:
    hash.sha256(0, filesize) == "d56193bee7108d0e9e695eaed33db5c326a5c4560cbcaab4e1978b3847db3a10"
}
```

### Sample 91: `e8c485f648fb4b8c`

| Field | Value |
|---|---|
| SHA-256 | `e8c485f648fb4b8ca501418e308e41c87f357f0f9e08cf81094a85a3c38f6215` |
| Family label | `Snowlight` |
| File name | `e8c485f648fb4b8ca501418e308e41c87f357f0f9e08cf81094a85a3c38f6215.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:36:58` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f219a876e795cdc0b224c1ef1924a159` |
| SHA-1 | `97cf3addf6b81bdbb135b5dacf44edfd4fd2e120` |
| SHA-256 | `e8c485f648fb4b8ca501418e308e41c87f357f0f9e08cf81094a85a3c38f6215` |
| SHA3-384 | `323ff9f89dfb35cf1cadba2c483049f2b2e159614d79f57dae9bfbb526389abbb56f2397865405237b74fe1398b90f33` |
| TLSH | `T122123047A2D0CE3FC8D953384467122472B794BEDF629713064915B53F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6WH5ML09V1J9G8YmF+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHJZMWT1YmYhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_091_e8c485f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8c485f648fb4b8ca501418e308e41c87f357f0f9e08cf81094a85a3c38f6215"
    family = "Snowlight"
    file_name = "e8c485f648fb4b8ca501418e308e41c87f357f0f9e08cf81094a85a3c38f6215.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:36:58"
  condition:
    hash.sha256(0, filesize) == "e8c485f648fb4b8ca501418e308e41c87f357f0f9e08cf81094a85a3c38f6215"
}
```

### Sample 92: `d29eaf9f612b2bd0`

| Field | Value |
|---|---|
| SHA-256 | `d29eaf9f612b2bd0b033911c27f7f83a4f9c4fcc0787af316e3ec9437710edc6` |
| Family label | `unknown` |
| File name | `d29eaf9f612b2bd0b033911c27f7f83a4f9c4fcc0787af316e3ec9437710edc6.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:36:55` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45007b00f7e39d9c80403bdd64fe224f` |
| SHA-1 | `202846aaca5e4869770230800080136341de569c` |
| SHA-256 | `d29eaf9f612b2bd0b033911c27f7f83a4f9c4fcc0787af316e3ec9437710edc6` |
| SHA3-384 | `2b2f64d1087e55087c7702a68575b6ecf0f25426042775621d5e80ab1bbc07df8c6875b1de895275447529a6dacce8a5` |
| TLSH | `T18BE12382BED6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScshGLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvtg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_d29eaf9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d29eaf9f612b2bd0b033911c27f7f83a4f9c4fcc0787af316e3ec9437710edc6"
    family = "unknown"
    file_name = "d29eaf9f612b2bd0b033911c27f7f83a4f9c4fcc0787af316e3ec9437710edc6.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:36:55"
  condition:
    hash.sha256(0, filesize) == "d29eaf9f612b2bd0b033911c27f7f83a4f9c4fcc0787af316e3ec9437710edc6"
}
```

### Sample 93: `065a9d9e67102f16`

| Field | Value |
|---|---|
| SHA-256 | `065a9d9e67102f1600e8de5b3d10073b42dc3be609734c7a43356ff710aff724` |
| Family label | `Snowlight` |
| File name | `065a9d9e67102f1600e8de5b3d10073b42dc3be609734c7a43356ff710aff724.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:36:51` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85ec7b9d3ba4d516d85dde4eb0943fcc` |
| SHA-1 | `46b38f0d3778fe792e471eed83fe8b3cf96f1807` |
| SHA-256 | `065a9d9e67102f1600e8de5b3d10073b42dc3be609734c7a43356ff710aff724` |
| SHA3-384 | `4b0dd954b108b96a20e50c504cf037fa3f81a2eee3e09227f4d3f77aad88dff87eddfb250e56dd2c4b8fe1c5dc41db92` |
| TLSH | `T1A2123047A2D0CE3FC8D9533844A7122472B794BEDF629713064915B53F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6WH5ML09V1J9G8YmS+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHJZMWT1YmfhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_093_065a9d9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "065a9d9e67102f1600e8de5b3d10073b42dc3be609734c7a43356ff710aff724"
    family = "Snowlight"
    file_name = "065a9d9e67102f1600e8de5b3d10073b42dc3be609734c7a43356ff710aff724.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:36:51"
  condition:
    hash.sha256(0, filesize) == "065a9d9e67102f1600e8de5b3d10073b42dc3be609734c7a43356ff710aff724"
}
```

### Sample 94: `ac495c8fa0c6d582`

| Field | Value |
|---|---|
| SHA-256 | `ac495c8fa0c6d582efa44659ed03059c81e22edbb3e8aed5994688787cc112c0` |
| Family label | `Snowlight` |
| File name | `ac495c8fa0c6d582efa44659ed03059c81e22edbb3e8aed5994688787cc112c0.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:32:58` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42b3956772b4b71e8d254723011c3480` |
| SHA-1 | `a575ab137738a4631b89727894db590487d09fed` |
| SHA-256 | `ac495c8fa0c6d582efa44659ed03059c81e22edbb3e8aed5994688787cc112c0` |
| SHA3-384 | `b7e630f280c4c6e4b919676939edab2d32aac2e59c388772c0e3a112eb6afb3a33e736a8b2a183e32da4d4724ac400b6` |
| TLSH | `T1DDE18117E2E2CD32D8D0137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3PJheuhi55Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcb/JhAXZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_094_ac495c8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac495c8fa0c6d582efa44659ed03059c81e22edbb3e8aed5994688787cc112c0"
    family = "Snowlight"
    file_name = "ac495c8fa0c6d582efa44659ed03059c81e22edbb3e8aed5994688787cc112c0.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:32:58"
  condition:
    hash.sha256(0, filesize) == "ac495c8fa0c6d582efa44659ed03059c81e22edbb3e8aed5994688787cc112c0"
}
```

### Sample 95: `c272740a1f634caf`

| Field | Value |
|---|---|
| SHA-256 | `c272740a1f634caf2693d9a5ee01d4e1c70269474c87eecfd9be3fbe7ae79e87` |
| Family label | `Mirai` |
| File name | `c272740a1f634caf2693d9a5ee01d4e1c70269474c87eecfd9be3fbe7ae79e87.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:32:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97f8a02cb78431a416a4868ffa65d0f5` |
| SHA-1 | `f1f6f4445d4f624d0cd414c497892c2cce8d879e` |
| SHA-256 | `c272740a1f634caf2693d9a5ee01d4e1c70269474c87eecfd9be3fbe7ae79e87` |
| SHA3-384 | `92d4feecb1b4d1fd50035810b73bfab8ac83aefb4ab2674c0538feca3efa0cfd9a2143bbba92e338569fc5e7378e77d2` |
| TLSH | `T1D1125147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65766E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5cSlTTej6TNJ9ViNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WT9TTfTpVOdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_c272740a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c272740a1f634caf2693d9a5ee01d4e1c70269474c87eecfd9be3fbe7ae79e87"
    family = "Mirai"
    file_name = "c272740a1f634caf2693d9a5ee01d4e1c70269474c87eecfd9be3fbe7ae79e87.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:32:55"
  condition:
    hash.sha256(0, filesize) == "c272740a1f634caf2693d9a5ee01d4e1c70269474c87eecfd9be3fbe7ae79e87"
}
```

### Sample 96: `d0f8b472d3361453`

| Field | Value |
|---|---|
| SHA-256 | `d0f8b472d336145317ab4c20cd6ac1c5c9c47510e4f69c9b2cad4ea516736a7e` |
| Family label | `Snowlight` |
| File name | `d0f8b472d336145317ab4c20cd6ac1c5c9c47510e4f69c9b2cad4ea516736a7e.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:32:51` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9d93114908376143535a4602e7ed72e` |
| SHA-1 | `aa7039a9fa506527ca43994e295bf9ba7dfdc6ab` |
| SHA-256 | `d0f8b472d336145317ab4c20cd6ac1c5c9c47510e4f69c9b2cad4ea516736a7e` |
| SHA3-384 | `d8b3cfdc0e9b48ae8abb43bfe58aa73d9d2dba6eb2194010b7c0a5ed18408365537dd0a391e755343b0a0444f32d115a` |
| TLSH | `T191E17217E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3PJheuhix5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcb/JhAPZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_096_d0f8b472
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0f8b472d336145317ab4c20cd6ac1c5c9c47510e4f69c9b2cad4ea516736a7e"
    family = "Snowlight"
    file_name = "d0f8b472d336145317ab4c20cd6ac1c5c9c47510e4f69c9b2cad4ea516736a7e.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:32:51"
  condition:
    hash.sha256(0, filesize) == "d0f8b472d336145317ab4c20cd6ac1c5c9c47510e4f69c9b2cad4ea516736a7e"
}
```

### Sample 97: `37023f0d47db2c18`

| Field | Value |
|---|---|
| SHA-256 | `37023f0d47db2c181d07ff28efa6b6d8b7bba2d07dc2cc8d7c5b9b549ec416f3` |
| Family label | `unknown` |
| File name | `37023f0d47db2c181d07ff28efa6b6d8b7bba2d07dc2cc8d7c5b9b549ec416f3.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:32:47` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `040c5b761ef8c56703518c698c1d17df` |
| SHA-1 | `a0b5f85b8d526bc8431faff080dd1ba46362c464` |
| SHA-256 | `37023f0d47db2c181d07ff28efa6b6d8b7bba2d07dc2cc8d7c5b9b549ec416f3` |
| SHA3-384 | `0ed396fcaa3754126fb597a48dc4d1df02193b7e20440fbf5b7c2a0081e8ab30c610322171488e8651339cf8f2d1c0ef` |
| TLSH | `T16FE12382B9D6CE3BCCE9627A1673C6203372C551AB439B17210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsOLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvDg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_37023f0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37023f0d47db2c181d07ff28efa6b6d8b7bba2d07dc2cc8d7c5b9b549ec416f3"
    family = "unknown"
    file_name = "37023f0d47db2c181d07ff28efa6b6d8b7bba2d07dc2cc8d7c5b9b549ec416f3.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:32:47"
  condition:
    hash.sha256(0, filesize) == "37023f0d47db2c181d07ff28efa6b6d8b7bba2d07dc2cc8d7c5b9b549ec416f3"
}
```

### Sample 98: `f83322c2ba37c1bc`

| Field | Value |
|---|---|
| SHA-256 | `f83322c2ba37c1bc7b409b30d2bd96a206245cd99872cac82c455d53145c9f2d` |
| Family label | `unknown` |
| File name | `f83322c2ba37c1bc7b409b30d2bd96a206245cd99872cac82c455d53145c9f2d.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:31:42` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dd812b040388e00aace3fa10dd004b0` |
| SHA-1 | `9e28d7bfc0c735701fcfdfb7be7db3df5d8e124a` |
| SHA-256 | `f83322c2ba37c1bc7b409b30d2bd96a206245cd99872cac82c455d53145c9f2d` |
| SHA3-384 | `286a1e11bae61ab1ee7fd5b68a0e0d1e7ab97cd15e2f0f13a7457fecc874aa39c801e94714b834ee94416c124b91ab84` |
| TLSH | `T1FAE13382BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AEC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsNBLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvNsg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_f83322c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f83322c2ba37c1bc7b409b30d2bd96a206245cd99872cac82c455d53145c9f2d"
    family = "unknown"
    file_name = "f83322c2ba37c1bc7b409b30d2bd96a206245cd99872cac82c455d53145c9f2d.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:31:42"
  condition:
    hash.sha256(0, filesize) == "f83322c2ba37c1bc7b409b30d2bd96a206245cd99872cac82c455d53145c9f2d"
}
```

### Sample 99: `e96866fcca87e0d0`

| Field | Value |
|---|---|
| SHA-256 | `e96866fcca87e0d06b0f6b76708f8a0fe602f7d9cf1977896cdbffb37ea9e1c5` |
| Family label | `unknown` |
| File name | `e96866fcca87e0d06b0f6b76708f8a0fe602f7d9cf1977896cdbffb37ea9e1c5.bin` |
| File type | `macho` |
| First seen | `2026-11-07 01:30:01` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec196d832e8374082f8119889949aed2` |
| SHA-1 | `1380833db9d0cfeadb6451e5dbbbe8c12f1e4243` |
| SHA-256 | `e96866fcca87e0d06b0f6b76708f8a0fe602f7d9cf1977896cdbffb37ea9e1c5` |
| SHA3-384 | `c9d2f7a66aa040d730a1a85b66a57a86e44a0720432f7cf4192b5e11691236b6d4f3232ff30d283446c67493211aa48e` |
| TLSH | `T15CE24F43675C5929D05D83BD22FB1B576609F8A009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEP5DbDP67li97WsCS9wYjqclS06W1YbqclSl:GI2P5DbDys9wYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_e96866fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e96866fcca87e0d06b0f6b76708f8a0fe602f7d9cf1977896cdbffb37ea9e1c5"
    family = "unknown"
    file_name = "e96866fcca87e0d06b0f6b76708f8a0fe602f7d9cf1977896cdbffb37ea9e1c5.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:30:01"
  condition:
    hash.sha256(0, filesize) == "e96866fcca87e0d06b0f6b76708f8a0fe602f7d9cf1977896cdbffb37ea9e1c5"
}
```

### Sample 100: `fd5305985b2556c9`

| Field | Value |
|---|---|
| SHA-256 | `fd5305985b2556c9e6c2089a88e98c033ab80668053be4838c9dcd74b36e6b31` |
| Family label | `Mirai` |
| File name | `fd5305985b2556c9e6c2089a88e98c033ab80668053be4838c9dcd74b36e6b31.elf` |
| File type | `elf` |
| First seen | `2026-11-07 01:24:51` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50c328a4333755ec3cfe99e9ee6408c8` |
| SHA-1 | `de7038d13e9a4f39677b8b85b7141689b98df2af` |
| SHA-256 | `fd5305985b2556c9e6c2089a88e98c033ab80668053be4838c9dcd74b36e6b31` |
| SHA3-384 | `edd8e093e84666b19924cde37e047c58f62c34974467471e139affcb21124ecb54bf5ebcdec076b7dafee9b0faf17a96` |
| TLSH | `T1E3125147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5AlTTej6TNJ9VzNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTcTTfTpVXdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_fd530598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd5305985b2556c9e6c2089a88e98c033ab80668053be4838c9dcd74b36e6b31"
    family = "Mirai"
    file_name = "fd5305985b2556c9e6c2089a88e98c033ab80668053be4838c9dcd74b36e6b31.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:24:51"
  condition:
    hash.sha256(0, filesize) == "fd5305985b2556c9e6c2089a88e98c033ab80668053be4838c9dcd74b36e6b31"
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
 * Generated: 2026-11-07T06:11:32.495506+00:00
 */

rule MalwareBazaar_Mirai_001_133b6695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "133b66956fee092042543cbd67da59ce0d1fb308f6afb83ce5bba735941246d9"
    family = "Mirai"
    file_name = "e"
    file_type = "sh"
    first_seen = "2026-11-07 06:09:05"
  condition:
    hash.sha256(0, filesize) == "133b66956fee092042543cbd67da59ce0d1fb308f6afb83ce5bba735941246d9"
}

rule MalwareBazaar_Mirai_002_d4ea0857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4ea0857eff726c6bdf502461ccfe6d90e8a4808df1b78d39f548057cdfb6883"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-07 05:09:04"
  condition:
    hash.sha256(0, filesize) == "d4ea0857eff726c6bdf502461ccfe6d90e8a4808df1b78d39f548057cdfb6883"
}

rule MalwareBazaar_Mirai_003_a996b6b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a996b6b9d64d12f50e1b490b9ad54ae9b06c147ef29fb73e028b315b2e0ff209"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-07 05:08:03"
  condition:
    hash.sha256(0, filesize) == "a996b6b9d64d12f50e1b490b9ad54ae9b06c147ef29fb73e028b315b2e0ff209"
}

rule MalwareBazaar_Mirai_004_870e679d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "870e679d592adb9ca80ffc61582d6ced9e6ce522a5623e031b9d69f083239cf8"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-07 04:58:03"
  condition:
    hash.sha256(0, filesize) == "870e679d592adb9ca80ffc61582d6ced9e6ce522a5623e031b9d69f083239cf8"
}

rule MalwareBazaar_Loki_005_4ec22089
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ec220894d9c50b012c95d8b3842dfab945ff161563979419ace88db4166dd72"
    family = "Loki"
    file_name = "A18DAB00E1356CEDE97CED4493640D01.exe"
    file_type = "exe"
    first_seen = "2026-11-07 04:55:05"
  condition:
    hash.sha256(0, filesize) == "4ec220894d9c50b012c95d8b3842dfab945ff161563979419ace88db4166dd72"
}

rule MalwareBazaar_njrat_006_8c799481
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7994818bf877418e701f3d8aa4e1cbb24d9031e8f36c577c3541193baf96df"
    family = "njrat"
    file_name = "98CEE2774E0C79C0B39EAC01817D9457.exe"
    file_type = "exe"
    first_seen = "2026-11-07 04:45:07"
  condition:
    hash.sha256(0, filesize) == "8c7994818bf877418e701f3d8aa4e1cbb24d9031e8f36c577c3541193baf96df"
}

rule MalwareBazaar_Mirai_007_4392cb9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4392cb9d92a4912687f12a462b346e7f0b4316f1ce9f31be4d8b0cb383e07b16"
    family = "Mirai"
    file_name = "4392cb9d92a4912687f12a462b346e7f0b4316f1ce9f31be4d8b0cb383e07b16.bin"
    file_type = "sh"
    first_seen = "2026-11-07 04:32:35"
  condition:
    hash.sha256(0, filesize) == "4392cb9d92a4912687f12a462b346e7f0b4316f1ce9f31be4d8b0cb383e07b16"
}

rule MalwareBazaar_Mirai_008_796d7920
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "796d79206eb13e8f7ea9e9b2d0b6e2054ae2f7792fa8571bd53671e398ae6531"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-07 04:30:04"
  condition:
    hash.sha256(0, filesize) == "796d79206eb13e8f7ea9e9b2d0b6e2054ae2f7792fa8571bd53671e398ae6531"
}

rule MalwareBazaar_Mirai_009_67219af1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67219af1d55f4d943632a26b7f072709f3334f58424808d1e217ddb06b3a35d1"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-07 04:17:12"
  condition:
    hash.sha256(0, filesize) == "67219af1d55f4d943632a26b7f072709f3334f58424808d1e217ddb06b3a35d1"
}

rule MalwareBazaar_Mirai_010_aa423ec2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa423ec2fbdb1835e1ad69c81db4d6c1b710faa27c192ac77e55d4f74a47325d"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-07 04:17:04"
  condition:
    hash.sha256(0, filesize) == "aa423ec2fbdb1835e1ad69c81db4d6c1b710faa27c192ac77e55d4f74a47325d"
}

rule MalwareBazaar_unknown_011_86758b3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86758b3b84a49814be23e532ecaedd74c1d31a2ee6ffcfb45afd91aedcffaa5d"
    family = "unknown"
    file_name = "gitl__it_64-v.8.927.exe"
    file_type = "exe"
    first_seen = "2026-11-07 03:38:18"
  condition:
    hash.sha256(0, filesize) == "86758b3b84a49814be23e532ecaedd74c1d31a2ee6ffcfb45afd91aedcffaa5d"
}

rule MalwareBazaar_unknown_012_c5335a52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5335a5256eab2b0d3e953cb5311442b31c79c9ed0d8bb30ade184ae0f7df85d"
    family = "unknown"
    file_name = "gitl__it_64-v.8.927.exe"
    file_type = "exe"
    first_seen = "2026-11-07 03:37:10"
  condition:
    hash.sha256(0, filesize) == "c5335a5256eab2b0d3e953cb5311442b31c79c9ed0d8bb30ade184ae0f7df85d"
}

rule MalwareBazaar_unknown_013_6946548c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6946548ce23106e70957952fc2fa08c8459fb4b2ea3e6b513e8a7387cc115cf3"
    family = "unknown"
    file_name = "gitl__it_64-v.8.927.exe"
    file_type = "exe"
    first_seen = "2026-11-07 03:22:14"
  condition:
    hash.sha256(0, filesize) == "6946548ce23106e70957952fc2fa08c8459fb4b2ea3e6b513e8a7387cc115cf3"
}

rule MalwareBazaar_Prometei_014_e66171f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e66171f991282ef661e3f3d8baba57f320759820bb768c647ac8f4be9ab0f11c"
    family = "Prometei"
    file_name = "e66171f991282ef661e3f3d8baba57f320759820bb768c647ac8f4be9ab0f11c"
    file_type = "elf"
    first_seen = "2026-11-07 02:56:04"
  condition:
    hash.sha256(0, filesize) == "e66171f991282ef661e3f3d8baba57f320759820bb768c647ac8f4be9ab0f11c"
}

rule MalwareBazaar_ValleyRAT_015_11d82e97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11d82e97c16e41bc4b8f54da1c0adb898aa0bee29950f62252a058437d69a660"
    family = "ValleyRAT"
    file_name = "398FC22A131AC9CDADB46DF21E2337C7.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:45:34"
  condition:
    hash.sha256(0, filesize) == "11d82e97c16e41bc4b8f54da1c0adb898aa0bee29950f62252a058437d69a660"
}

rule MalwareBazaar_ValleyRAT_016_36b2235d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36b2235d3bf3299a52ca3ba676bc56a419e362ac156e637f513ede00838cb648"
    family = "ValleyRAT"
    file_name = "321E9076E970BC97C7D87201E196233B.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:40:11"
  condition:
    hash.sha256(0, filesize) == "36b2235d3bf3299a52ca3ba676bc56a419e362ac156e637f513ede00838cb648"
}

rule MalwareBazaar_Prometei_017_4f2bac66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f2bac667f5b40227f7537e75ad1283d7ae328362681066a55bf007a6884246c"
    family = "Prometei"
    file_name = "4f2bac667f5b40227f7537e75ad1283d7ae328362681066a55bf007a6884246c"
    file_type = "elf"
    first_seen = "2026-11-07 02:30:34"
  condition:
    hash.sha256(0, filesize) == "4f2bac667f5b40227f7537e75ad1283d7ae328362681066a55bf007a6884246c"
}

rule MalwareBazaar_SalatStealer_018_db6e10fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db6e10fc0cef5dd1331f3f2b1b8e51e53ce8c5485bf8908ccbd5c7b2046488f7"
    family = "SalatStealer"
    file_name = "a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:18:18"
  condition:
    hash.sha256(0, filesize) == "db6e10fc0cef5dd1331f3f2b1b8e51e53ce8c5485bf8908ccbd5c7b2046488f7"
}

rule MalwareBazaar_SalatStealer_019_a0e992bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe"
    family = "SalatStealer"
    file_name = "a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:17:15"
  condition:
    hash.sha256(0, filesize) == "a0e992bfeea621b4f6e3d837cd43806f3a9b939f59309d19becae3d4ca6e3afe"
}

rule MalwareBazaar_RevStealer_020_dfcddf48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfcddf48d59024204b75d8cc04bbc1b03d7be9df3a836cafabc02c2d03bf935b"
    family = "RevStealer"
    file_name = "dfcddf48d59024204b75d8cc04bbc1b03d7be9df3a836cafabc02c2d03bf935b.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:17:11"
  condition:
    hash.sha256(0, filesize) == "dfcddf48d59024204b75d8cc04bbc1b03d7be9df3a836cafabc02c2d03bf935b"
}

rule MalwareBazaar_RevStealer_021_2a0792e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a0792e2b1e1470dab303ac04a901b688438478d5150c1f7a28a4cf027f33ad0"
    family = "RevStealer"
    file_name = "2a0792e2b1e1470dab303ac04a901b688438478d5150c1f7a28a4cf027f33ad0.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:14:53"
  condition:
    hash.sha256(0, filesize) == "2a0792e2b1e1470dab303ac04a901b688438478d5150c1f7a28a4cf027f33ad0"
}

rule MalwareBazaar_VShell_022_8e9ba9cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e9ba9cfa85d8cf529d51ba8a2fbf5fa2e843c713a7a3a57d05769cd7b1fa820"
    family = "VShell"
    file_name = "23767a958594045ceaf056ac0ae56636.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:10:17"
  condition:
    hash.sha256(0, filesize) == "8e9ba9cfa85d8cf529d51ba8a2fbf5fa2e843c713a7a3a57d05769cd7b1fa820"
}

rule MalwareBazaar_unknown_023_3c862daf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c862dafda302843f1604b919fd1bc179feea49e396bc648915ca19d59ea0c9f"
    family = "unknown"
    file_name = "3c862dafda302843f1604b919fd1bc179feea49e396bc648915ca19d59ea0c9f.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:07:09"
  condition:
    hash.sha256(0, filesize) == "3c862dafda302843f1604b919fd1bc179feea49e396bc648915ca19d59ea0c9f"
}

rule MalwareBazaar_unknown_024_0a221a2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a221a2b52fbd475d24a0e5f19fa53bd7e49e07b0eec9a16b35c01bbe3480252"
    family = "unknown"
    file_name = "0a221a2b52fbd475d24a0e5f19fa53bd7e49e07b0eec9a16b35c01bbe3480252.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:07:02"
  condition:
    hash.sha256(0, filesize) == "0a221a2b52fbd475d24a0e5f19fa53bd7e49e07b0eec9a16b35c01bbe3480252"
}

rule MalwareBazaar_unknown_025_40ee9912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ee99127a64b7de2e2c52dc5a97a0d3c406e7f4573fb8d4afcbd9064cffd4b5"
    family = "unknown"
    file_name = "40ee99127a64b7de2e2c52dc5a97a0d3c406e7f4573fb8d4afcbd9064cffd4b5.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:05:23"
  condition:
    hash.sha256(0, filesize) == "40ee99127a64b7de2e2c52dc5a97a0d3c406e7f4573fb8d4afcbd9064cffd4b5"
}

rule MalwareBazaar_unknown_026_a0f6a045
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0f6a045559171f656e64c8a141eb3d839a0c6f961d76d69093189a75b6260c7"
    family = "unknown"
    file_name = "a0f6a045559171f656e64c8a141eb3d839a0c6f961d76d69093189a75b6260c7.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:04:57"
  condition:
    hash.sha256(0, filesize) == "a0f6a045559171f656e64c8a141eb3d839a0c6f961d76d69093189a75b6260c7"
}

rule MalwareBazaar_unknown_027_b9ccb3f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9ccb3f0b7de8d35d7de8b6d6e3a1040b7faa088b7c002c69f063ee871bfb77f"
    family = "unknown"
    file_name = "b9ccb3f0b7de8d35d7de8b6d6e3a1040b7faa088b7c002c69f063ee871bfb77f.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:04:51"
  condition:
    hash.sha256(0, filesize) == "b9ccb3f0b7de8d35d7de8b6d6e3a1040b7faa088b7c002c69f063ee871bfb77f"
}

rule MalwareBazaar_unknown_028_c7f7208e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7f7208ec7dc96270f9d6f2c2005a70c31de9424f76f399a5ebe6139206bce30"
    family = "unknown"
    file_name = "c7f7208ec7dc96270f9d6f2c2005a70c31de9424f76f399a5ebe6139206bce30.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:02:25"
  condition:
    hash.sha256(0, filesize) == "c7f7208ec7dc96270f9d6f2c2005a70c31de9424f76f399a5ebe6139206bce30"
}

rule MalwareBazaar_unknown_029_80c4995f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80c4995fe223a8d7d8e564312477173eccf913d05a9469abfcc6f7fb4abb5d87"
    family = "unknown"
    file_name = "80c4995fe223a8d7d8e564312477173eccf913d05a9469abfcc6f7fb4abb5d87.bin"
    file_type = "macho"
    first_seen = "2026-11-07 02:01:57"
  condition:
    hash.sha256(0, filesize) == "80c4995fe223a8d7d8e564312477173eccf913d05a9469abfcc6f7fb4abb5d87"
}

rule MalwareBazaar_VShell_030_772cc095
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "772cc0958a947357d1f811613552322d716604ad4c516d08d58a1a99ffd002a0"
    family = "VShell"
    file_name = "772cc0958a947357d1f811613552322d716604ad4c516d08d58a1a99ffd002a0.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:00:59"
  condition:
    hash.sha256(0, filesize) == "772cc0958a947357d1f811613552322d716604ad4c516d08d58a1a99ffd002a0"
}

rule MalwareBazaar_SnappyClient_031_71246175
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71246175047a03e547f8b5aa848af2a026331aa6d5e06bbef02e669713e628b2"
    family = "SnappyClient"
    file_name = "71246175047a03e547f8b5aa848af2a026331aa6d5e06bbef02e669713e628b2.exe"
    file_type = "exe"
    first_seen = "2026-11-07 02:00:54"
  condition:
    hash.sha256(0, filesize) == "71246175047a03e547f8b5aa848af2a026331aa6d5e06bbef02e669713e628b2"
}

rule MalwareBazaar_VShell_032_575e8dab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "575e8dab342418ffddba02c2cb323a9a1c25f50c334994438364fbeb8176e261"
    family = "VShell"
    file_name = "575e8dab342418ffddba02c2cb323a9a1c25f50c334994438364fbeb8176e261.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:59:54"
  condition:
    hash.sha256(0, filesize) == "575e8dab342418ffddba02c2cb323a9a1c25f50c334994438364fbeb8176e261"
}

rule MalwareBazaar_VShell_033_a67bf1dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a67bf1dd75bc49b6408e6e7084be2cfba721d14ba744b3f40d8aa55a19b72017"
    family = "VShell"
    file_name = "a67bf1dd75bc49b6408e6e7084be2cfba721d14ba744b3f40d8aa55a19b72017.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:57:01"
  condition:
    hash.sha256(0, filesize) == "a67bf1dd75bc49b6408e6e7084be2cfba721d14ba744b3f40d8aa55a19b72017"
}

rule MalwareBazaar_WARDENStealer_034_48caf733
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48caf733e828a95f3d5801e7dce826dbd14f8661705236bb6eff7c06d2a077ba"
    family = "WARDENStealer"
    file_name = "48caf733e828a95f3d5801e7dce826dbd14f8661705236bb6eff7c06d2a077ba.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:56:56"
  condition:
    hash.sha256(0, filesize) == "48caf733e828a95f3d5801e7dce826dbd14f8661705236bb6eff7c06d2a077ba"
}

rule MalwareBazaar_unknown_035_ef7cdf42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef7cdf4246b43dd4cfcfcfd904f75bc25133064761309439bebd5607d96c04a0"
    family = "unknown"
    file_name = "ef7cdf4246b43dd4cfcfcfd904f75bc25133064761309439bebd5607d96c04a0.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:55:38"
  condition:
    hash.sha256(0, filesize) == "ef7cdf4246b43dd4cfcfcfd904f75bc25133064761309439bebd5607d96c04a0"
}

rule MalwareBazaar_unknown_036_c54c960b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c54c960b487ecababb42d7e91787ad0b5c41d8c1c0d762ac18e4155f1efb1d2b"
    family = "unknown"
    file_name = "c54c960b487ecababb42d7e91787ad0b5c41d8c1c0d762ac18e4155f1efb1d2b.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:55:33"
  condition:
    hash.sha256(0, filesize) == "c54c960b487ecababb42d7e91787ad0b5c41d8c1c0d762ac18e4155f1efb1d2b"
}

rule MalwareBazaar_unknown_037_2b0ad3ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b0ad3caef7e974a1766b135433bfaeceb5ee4266dc410e5bd7dfb4ddc184622"
    family = "unknown"
    file_name = "2b0ad3caef7e974a1766b135433bfaeceb5ee4266dc410e5bd7dfb4ddc184622.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:55:28"
  condition:
    hash.sha256(0, filesize) == "2b0ad3caef7e974a1766b135433bfaeceb5ee4266dc410e5bd7dfb4ddc184622"
}

rule MalwareBazaar_unknown_038_38d9ca4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38d9ca4f66cbff9e4af7bdde9c43ced323cf3498b2e728e52fb9eb1508e2fa32"
    family = "unknown"
    file_name = "38d9ca4f66cbff9e4af7bdde9c43ced323cf3498b2e728e52fb9eb1508e2fa32.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:55:23"
  condition:
    hash.sha256(0, filesize) == "38d9ca4f66cbff9e4af7bdde9c43ced323cf3498b2e728e52fb9eb1508e2fa32"
}

rule MalwareBazaar_unknown_039_6b3a8efc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b3a8efc982740a6057ed77f868f9119c6b5b02a1f20979e27368d8a6b771425"
    family = "unknown"
    file_name = "6b3a8efc982740a6057ed77f868f9119c6b5b02a1f20979e27368d8a6b771425.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:52:01"
  condition:
    hash.sha256(0, filesize) == "6b3a8efc982740a6057ed77f868f9119c6b5b02a1f20979e27368d8a6b771425"
}

rule MalwareBazaar_unknown_040_b19b0bdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b19b0bdcc8c171883229630f33d95ad49189b3aaa402c103869c20843b46e640"
    family = "unknown"
    file_name = "b19b0bdcc8c171883229630f33d95ad49189b3aaa402c103869c20843b46e640.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:57"
  condition:
    hash.sha256(0, filesize) == "b19b0bdcc8c171883229630f33d95ad49189b3aaa402c103869c20843b46e640"
}

rule MalwareBazaar_unknown_041_057e4508
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "057e4508e805e7218daa6f1daa058f11116fdec2a74dc865319b556ebd640e82"
    family = "unknown"
    file_name = "057e4508e805e7218daa6f1daa058f11116fdec2a74dc865319b556ebd640e82.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:15"
  condition:
    hash.sha256(0, filesize) == "057e4508e805e7218daa6f1daa058f11116fdec2a74dc865319b556ebd640e82"
}

rule MalwareBazaar_unknown_042_b86f8878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b86f8878b103c994ca14bdba4586e4a5ce8fda22e4407281214bd5481743b632"
    family = "unknown"
    file_name = "b86f8878b103c994ca14bdba4586e4a5ce8fda22e4407281214bd5481743b632.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:12"
  condition:
    hash.sha256(0, filesize) == "b86f8878b103c994ca14bdba4586e4a5ce8fda22e4407281214bd5481743b632"
}

rule MalwareBazaar_unknown_043_7cc114bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cc114bd86274f4266b402a1881fdb2d22cccb9d92d94186dfd7629ed6b1e39b"
    family = "unknown"
    file_name = "7cc114bd86274f4266b402a1881fdb2d22cccb9d92d94186dfd7629ed6b1e39b.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:08"
  condition:
    hash.sha256(0, filesize) == "7cc114bd86274f4266b402a1881fdb2d22cccb9d92d94186dfd7629ed6b1e39b"
}

rule MalwareBazaar_unknown_044_d9bf992a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9bf992ad7e94e8a810ed950148522f45ca3a68521df6bd275c9f539740268f6"
    family = "unknown"
    file_name = "d9bf992ad7e94e8a810ed950148522f45ca3a68521df6bd275c9f539740268f6.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:04"
  condition:
    hash.sha256(0, filesize) == "d9bf992ad7e94e8a810ed950148522f45ca3a68521df6bd275c9f539740268f6"
}

rule MalwareBazaar_unknown_045_740363a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "740363a0b979cd4504857b39288ca1897256c6ed0ca280c6b0dc9e129523bef4"
    family = "unknown"
    file_name = "740363a0b979cd4504857b39288ca1897256c6ed0ca280c6b0dc9e129523bef4.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:51:00"
  condition:
    hash.sha256(0, filesize) == "740363a0b979cd4504857b39288ca1897256c6ed0ca280c6b0dc9e129523bef4"
}

rule MalwareBazaar_unknown_046_3e3a53b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e3a53b7016a9426cbd7e77ed22429ee2e84eb5033700a1f7c373c139e5dd26a"
    family = "unknown"
    file_name = "3e3a53b7016a9426cbd7e77ed22429ee2e84eb5033700a1f7c373c139e5dd26a.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:50:56"
  condition:
    hash.sha256(0, filesize) == "3e3a53b7016a9426cbd7e77ed22429ee2e84eb5033700a1f7c373c139e5dd26a"
}

rule MalwareBazaar_Mirai_047_5dead91a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dead91acf4972d1503e4abc8b223767d78373f15066aa79e252557dc8894786"
    family = "Mirai"
    file_name = "5dead91acf4972d1503e4abc8b223767d78373f15066aa79e252557dc8894786.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:43:12"
  condition:
    hash.sha256(0, filesize) == "5dead91acf4972d1503e4abc8b223767d78373f15066aa79e252557dc8894786"
}

rule MalwareBazaar_Mirai_048_f2aa4b6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2aa4b6d2173545191741e3726f09e86bfc36a2cfbb562a60da7e059fc0689f3"
    family = "Mirai"
    file_name = "f2aa4b6d2173545191741e3726f09e86bfc36a2cfbb562a60da7e059fc0689f3.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:43:09"
  condition:
    hash.sha256(0, filesize) == "f2aa4b6d2173545191741e3726f09e86bfc36a2cfbb562a60da7e059fc0689f3"
}

rule MalwareBazaar_Mirai_049_1df069b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1df069b263d1f07cde52576d3a0c8935edca42d6d68ca2b32f849e1049204f92"
    family = "Mirai"
    file_name = "1df069b263d1f07cde52576d3a0c8935edca42d6d68ca2b32f849e1049204f92.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:43:05"
  condition:
    hash.sha256(0, filesize) == "1df069b263d1f07cde52576d3a0c8935edca42d6d68ca2b32f849e1049204f92"
}

rule MalwareBazaar_unknown_050_c45b668f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c45b668f7ea3c32faa3f51ef20a234efef9290f7fcca1b4326dc20719d0cb4e7"
    family = "unknown"
    file_name = "c45b668f7ea3c32faa3f51ef20a234efef9290f7fcca1b4326dc20719d0cb4e7.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:43:02"
  condition:
    hash.sha256(0, filesize) == "c45b668f7ea3c32faa3f51ef20a234efef9290f7fcca1b4326dc20719d0cb4e7"
}

rule MalwareBazaar_RevStealer_051_a39f83a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a39f83a2be41f4d8f898ac977b7be9fba5ef7ec3cfd3ff7edea623405cfa8ce2"
    family = "RevStealer"
    file_name = "a39f83a2be41f4d8f898ac977b7be9fba5ef7ec3cfd3ff7edea623405cfa8ce2.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:42:57"
  condition:
    hash.sha256(0, filesize) == "a39f83a2be41f4d8f898ac977b7be9fba5ef7ec3cfd3ff7edea623405cfa8ce2"
}

rule MalwareBazaar_Mirai_052_9cdafa22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cdafa22837b0a4f995b6aa30a19806be94132559c8cbf4271347151b47a627d"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:54"
  condition:
    hash.sha256(0, filesize) == "9cdafa22837b0a4f995b6aa30a19806be94132559c8cbf4271347151b47a627d"
}

rule MalwareBazaar_RevStealer_053_e3136233
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3136233f560e85717a03a58c1595e1ca8418bd1846f7290dd920dd1c185fe58"
    family = "RevStealer"
    file_name = "e3136233f560e85717a03a58c1595e1ca8418bd1846f7290dd920dd1c185fe58.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:42:53"
  condition:
    hash.sha256(0, filesize) == "e3136233f560e85717a03a58c1595e1ca8418bd1846f7290dd920dd1c185fe58"
}

rule MalwareBazaar_Mirai_054_b98c7893
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98c78937928f955938e3ef1c7f2f43b1c2b2f8ee10fbbf3742062ce3e608c21"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:52"
  condition:
    hash.sha256(0, filesize) == "b98c78937928f955938e3ef1c7f2f43b1c2b2f8ee10fbbf3742062ce3e608c21"
}

rule MalwareBazaar_Mirai_055_3f995d00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f995d003997e5a87ef43da077c3cef430899def1d5d327816435137437be84a"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:50"
  condition:
    hash.sha256(0, filesize) == "3f995d003997e5a87ef43da077c3cef430899def1d5d327816435137437be84a"
}

rule MalwareBazaar_Mirai_056_f75e42d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f75e42d8f866eff24afafe196c069e197dda6da79efbf01cc56066b378b10178"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:48"
  condition:
    hash.sha256(0, filesize) == "f75e42d8f866eff24afafe196c069e197dda6da79efbf01cc56066b378b10178"
}

rule MalwareBazaar_Mirai_057_1b05960b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b05960b8416d815d0656bce0682e83fb5ab2a56c6cb258e3d2d963727249261"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:45"
  condition:
    hash.sha256(0, filesize) == "1b05960b8416d815d0656bce0682e83fb5ab2a56c6cb258e3d2d963727249261"
}

rule MalwareBazaar_Mirai_058_d68dc2fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d68dc2fc3c9fcfe120d1447e1b536eceeb324e2b12865ed108e8b7cfeca55749"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:42"
  condition:
    hash.sha256(0, filesize) == "d68dc2fc3c9fcfe120d1447e1b536eceeb324e2b12865ed108e8b7cfeca55749"
}

rule MalwareBazaar_Mirai_059_86c34631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c34631ee3ed2eaa38ad409cabe601a2e74308886c4c6c98eac244298d638ab"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:40"
  condition:
    hash.sha256(0, filesize) == "86c34631ee3ed2eaa38ad409cabe601a2e74308886c4c6c98eac244298d638ab"
}

rule MalwareBazaar_Mirai_060_5852806b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5852806b591e522302cd6d968057f30491cf3dda5811989cb8f1ac882d4168fd"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:38"
  condition:
    hash.sha256(0, filesize) == "5852806b591e522302cd6d968057f30491cf3dda5811989cb8f1ac882d4168fd"
}

rule MalwareBazaar_Mirai_061_82a93421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82a93421807c958fb8b5c803e5c6f20fd84363ffb0705c3c0885c1533244084a"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:36"
  condition:
    hash.sha256(0, filesize) == "82a93421807c958fb8b5c803e5c6f20fd84363ffb0705c3c0885c1533244084a"
}

rule MalwareBazaar_Mirai_062_3ad972f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ad972f9a1b2a9144e28a905cea945e422b118171f406e3c8dd8d42e1d3e74ba"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:34"
  condition:
    hash.sha256(0, filesize) == "3ad972f9a1b2a9144e28a905cea945e422b118171f406e3c8dd8d42e1d3e74ba"
}

rule MalwareBazaar_Mirai_063_6303ba90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6303ba90e3f834029386e5df29d02f5239ffca6e56160ffde5b69183c62c4215"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:32"
  condition:
    hash.sha256(0, filesize) == "6303ba90e3f834029386e5df29d02f5239ffca6e56160ffde5b69183c62c4215"
}

rule MalwareBazaar_Mirai_064_15b3e581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15b3e5817bdff76269c324f0d18ff2159f3fac14700350e384b18a53ff3e778a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:29"
  condition:
    hash.sha256(0, filesize) == "15b3e5817bdff76269c324f0d18ff2159f3fac14700350e384b18a53ff3e778a"
}

rule MalwareBazaar_Mirai_065_1b63e86a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b63e86aca168a9804c1778e99cdada533aa094e175e81b63e896cbeb033b540"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:27"
  condition:
    hash.sha256(0, filesize) == "1b63e86aca168a9804c1778e99cdada533aa094e175e81b63e896cbeb033b540"
}

rule MalwareBazaar_Mirai_066_320f879b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "320f879bc3955052d92275fcfbad5754373d0a432f13f0e58028e54a9105bfca"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:25"
  condition:
    hash.sha256(0, filesize) == "320f879bc3955052d92275fcfbad5754373d0a432f13f0e58028e54a9105bfca"
}

rule MalwareBazaar_Mirai_067_f3fd933c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3fd933c2d1589f8f9975a3b79fd160d8305f13d05aa96fb54bc8009b44e9e83"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:23"
  condition:
    hash.sha256(0, filesize) == "f3fd933c2d1589f8f9975a3b79fd160d8305f13d05aa96fb54bc8009b44e9e83"
}

rule MalwareBazaar_Mirai_068_2ed94ae8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ed94ae8f35e9d3777dbd51863dda9140532b9b67b90271d7eecf9df82cec102"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:21"
  condition:
    hash.sha256(0, filesize) == "2ed94ae8f35e9d3777dbd51863dda9140532b9b67b90271d7eecf9df82cec102"
}

rule MalwareBazaar_Mirai_069_26e83ad7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26e83ad77774fc32a27ff868eb6339e9e574278172d2a053311ca1ddd475fdee"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:19"
  condition:
    hash.sha256(0, filesize) == "26e83ad77774fc32a27ff868eb6339e9e574278172d2a053311ca1ddd475fdee"
}

rule MalwareBazaar_Mirai_070_5cf03b5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cf03b5ea2fc3eb7f05f08f233ab43ba2a4b5cdbdcee1b50696646b359891d42"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:17"
  condition:
    hash.sha256(0, filesize) == "5cf03b5ea2fc3eb7f05f08f233ab43ba2a4b5cdbdcee1b50696646b359891d42"
}

rule MalwareBazaar_Mirai_071_24463661
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24463661334127036d64b10684763dda3f9086469aa9ef1d0545bc45e5812a22"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:14"
  condition:
    hash.sha256(0, filesize) == "24463661334127036d64b10684763dda3f9086469aa9ef1d0545bc45e5812a22"
}

rule MalwareBazaar_unknown_072_23da6109
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23da61097e552caabaaf2d083a695c442543de5935af8f05f317f096434904b4"
    family = "unknown"
    file_name = "23da61097e552caabaaf2d083a695c442543de5935af8f05f317f096434904b4.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:42:14"
  condition:
    hash.sha256(0, filesize) == "23da61097e552caabaaf2d083a695c442543de5935af8f05f317f096434904b4"
}

rule MalwareBazaar_Mirai_073_9c202ddb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c202ddb2194b27710d7a67c4eccca8dbdaccf15ca1bbb43b41065947d4c5ebc"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:12"
  condition:
    hash.sha256(0, filesize) == "9c202ddb2194b27710d7a67c4eccca8dbdaccf15ca1bbb43b41065947d4c5ebc"
}

rule MalwareBazaar_Mirai_074_32984eb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32984eb6ccebb8a271f109aaf549dc0c7c0eb5e03172e05b4c677d281e7b9327"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:10"
  condition:
    hash.sha256(0, filesize) == "32984eb6ccebb8a271f109aaf549dc0c7c0eb5e03172e05b4c677d281e7b9327"
}

rule MalwareBazaar_unknown_075_40a964d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40a964d9b667ce4fa7cf504fb112fd6aa3c2d5d6b26248fc189b153b0ba11f45"
    family = "unknown"
    file_name = "40a964d9b667ce4fa7cf504fb112fd6aa3c2d5d6b26248fc189b153b0ba11f45.msi"
    file_type = "msi"
    first_seen = "2026-11-07 01:42:09"
  condition:
    hash.sha256(0, filesize) == "40a964d9b667ce4fa7cf504fb112fd6aa3c2d5d6b26248fc189b153b0ba11f45"
}

rule MalwareBazaar_Mirai_076_3774f83a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3774f83a28267cf11886cdf70a820809162b672a151f33bbc7161901e8df1afb"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:07"
  condition:
    hash.sha256(0, filesize) == "3774f83a28267cf11886cdf70a820809162b672a151f33bbc7161901e8df1afb"
}

rule MalwareBazaar_Mirai_077_d2a5c223
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2a5c223232a7dfbc28bfada6f7d67f76da713f5e02a6464422d31a992919df4"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:05"
  condition:
    hash.sha256(0, filesize) == "d2a5c223232a7dfbc28bfada6f7d67f76da713f5e02a6464422d31a992919df4"
}

rule MalwareBazaar_ConnectWise_078_a676b80a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a676b80a15dac6dcfbccd81498b82141aee6f229728f8632d12c4d4329bfd5fe"
    family = "ConnectWise"
    file_name = "a676b80a15dac6dcfbccd81498b82141aee6f229728f8632d12c4d4329bfd5fe.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:42:04"
  condition:
    hash.sha256(0, filesize) == "a676b80a15dac6dcfbccd81498b82141aee6f229728f8632d12c4d4329bfd5fe"
}

rule MalwareBazaar_Mirai_079_b8bfcdc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8bfcdc686ec102054afe9a4ca344a82a47e0a60c41da85fef032a5820a107d1"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-11-07 01:42:03"
  condition:
    hash.sha256(0, filesize) == "b8bfcdc686ec102054afe9a4ca344a82a47e0a60c41da85fef032a5820a107d1"
}

rule MalwareBazaar_ConnectWise_080_cc965e6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc965e6df4b6bcf2512131d889fac685f2b14f3d37cdbecd4fce2a7d4d5a9fad"
    family = "ConnectWise"
    file_name = "cc965e6df4b6bcf2512131d889fac685f2b14f3d37cdbecd4fce2a7d4d5a9fad.exe"
    file_type = "exe"
    first_seen = "2026-11-07 01:41:58"
  condition:
    hash.sha256(0, filesize) == "cc965e6df4b6bcf2512131d889fac685f2b14f3d37cdbecd4fce2a7d4d5a9fad"
}

rule MalwareBazaar_Mirai_081_fa0b28bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa0b28bcc9df5f0014191a163fa9d7936698d29d865e8160b4f19e823aa51246"
    family = "Mirai"
    file_name = "fa0b28bcc9df5f0014191a163fa9d7936698d29d865e8160b4f19e823aa51246.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:41:53"
  condition:
    hash.sha256(0, filesize) == "fa0b28bcc9df5f0014191a163fa9d7936698d29d865e8160b4f19e823aa51246"
}

rule MalwareBazaar_Mirai_082_45af4868
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45af486893fbc5ecfefd0a883fac4e61cb6f4fe197d607a2db5fc4f9102d75cf"
    family = "Mirai"
    file_name = "45af486893fbc5ecfefd0a883fac4e61cb6f4fe197d607a2db5fc4f9102d75cf.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:40:25"
  condition:
    hash.sha256(0, filesize) == "45af486893fbc5ecfefd0a883fac4e61cb6f4fe197d607a2db5fc4f9102d75cf"
}

rule MalwareBazaar_Snowlight_083_f8c2baa8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb"
    family = "Snowlight"
    file_name = "f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:40:21"
  condition:
    hash.sha256(0, filesize) == "f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb"
}

rule MalwareBazaar_Snowlight_084_d1dfbe3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1dfbe3dc672cfe43cbb53911b0cf5a1ecd9ea66cf3a901a804b665eb11755de"
    family = "Snowlight"
    file_name = "d1dfbe3dc672cfe43cbb53911b0cf5a1ecd9ea66cf3a901a804b665eb11755de.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:57"
  condition:
    hash.sha256(0, filesize) == "d1dfbe3dc672cfe43cbb53911b0cf5a1ecd9ea66cf3a901a804b665eb11755de"
}

rule MalwareBazaar_Snowlight_085_5e6c245a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e6c245a96999367701dfa2288b391a6dad9ec2044744291b61af665ae6f30e4"
    family = "Snowlight"
    file_name = "5e6c245a96999367701dfa2288b391a6dad9ec2044744291b61af665ae6f30e4.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:54"
  condition:
    hash.sha256(0, filesize) == "5e6c245a96999367701dfa2288b391a6dad9ec2044744291b61af665ae6f30e4"
}

rule MalwareBazaar_Mirai_086_4eb5ddf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eb5ddf388f28859e833577f4af9856af671f5a2967755c8fd66cde77bace586"
    family = "Mirai"
    file_name = "4eb5ddf388f28859e833577f4af9856af671f5a2967755c8fd66cde77bace586.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:50"
  condition:
    hash.sha256(0, filesize) == "4eb5ddf388f28859e833577f4af9856af671f5a2967755c8fd66cde77bace586"
}

rule MalwareBazaar_unknown_087_2496f931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2496f931855e64d06bc570a5f8bcdf8759c3ce485641fe76ed8033392a173844"
    family = "unknown"
    file_name = "2496f931855e64d06bc570a5f8bcdf8759c3ce485641fe76ed8033392a173844.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:09"
  condition:
    hash.sha256(0, filesize) == "2496f931855e64d06bc570a5f8bcdf8759c3ce485641fe76ed8033392a173844"
}

rule MalwareBazaar_unknown_088_c6aec044
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6aec0447e9ce24cda96a29676761459e6a44580db5965b39520593268304e16"
    family = "unknown"
    file_name = "c6aec0447e9ce24c.js"
    file_type = "js"
    first_seen = "2026-11-07 01:37:07"
  condition:
    hash.sha256(0, filesize) == "c6aec0447e9ce24cda96a29676761459e6a44580db5965b39520593268304e16"
}

rule MalwareBazaar_Mirai_089_4932caeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4932caeb67bf5cacdc0feb01c6852952c02f62a2141b13b979fc06f99c923a76"
    family = "Mirai"
    file_name = "4932caeb67bf5cacdc0feb01c6852952c02f62a2141b13b979fc06f99c923a76.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:05"
  condition:
    hash.sha256(0, filesize) == "4932caeb67bf5cacdc0feb01c6852952c02f62a2141b13b979fc06f99c923a76"
}

rule MalwareBazaar_Mirai_090_d56193be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d56193bee7108d0e9e695eaed33db5c326a5c4560cbcaab4e1978b3847db3a10"
    family = "Mirai"
    file_name = "d56193bee7108d0e9e695eaed33db5c326a5c4560cbcaab4e1978b3847db3a10.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:37:02"
  condition:
    hash.sha256(0, filesize) == "d56193bee7108d0e9e695eaed33db5c326a5c4560cbcaab4e1978b3847db3a10"
}

rule MalwareBazaar_Snowlight_091_e8c485f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8c485f648fb4b8ca501418e308e41c87f357f0f9e08cf81094a85a3c38f6215"
    family = "Snowlight"
    file_name = "e8c485f648fb4b8ca501418e308e41c87f357f0f9e08cf81094a85a3c38f6215.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:36:58"
  condition:
    hash.sha256(0, filesize) == "e8c485f648fb4b8ca501418e308e41c87f357f0f9e08cf81094a85a3c38f6215"
}

rule MalwareBazaar_unknown_092_d29eaf9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d29eaf9f612b2bd0b033911c27f7f83a4f9c4fcc0787af316e3ec9437710edc6"
    family = "unknown"
    file_name = "d29eaf9f612b2bd0b033911c27f7f83a4f9c4fcc0787af316e3ec9437710edc6.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:36:55"
  condition:
    hash.sha256(0, filesize) == "d29eaf9f612b2bd0b033911c27f7f83a4f9c4fcc0787af316e3ec9437710edc6"
}

rule MalwareBazaar_Snowlight_093_065a9d9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "065a9d9e67102f1600e8de5b3d10073b42dc3be609734c7a43356ff710aff724"
    family = "Snowlight"
    file_name = "065a9d9e67102f1600e8de5b3d10073b42dc3be609734c7a43356ff710aff724.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:36:51"
  condition:
    hash.sha256(0, filesize) == "065a9d9e67102f1600e8de5b3d10073b42dc3be609734c7a43356ff710aff724"
}

rule MalwareBazaar_Snowlight_094_ac495c8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac495c8fa0c6d582efa44659ed03059c81e22edbb3e8aed5994688787cc112c0"
    family = "Snowlight"
    file_name = "ac495c8fa0c6d582efa44659ed03059c81e22edbb3e8aed5994688787cc112c0.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:32:58"
  condition:
    hash.sha256(0, filesize) == "ac495c8fa0c6d582efa44659ed03059c81e22edbb3e8aed5994688787cc112c0"
}

rule MalwareBazaar_Mirai_095_c272740a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c272740a1f634caf2693d9a5ee01d4e1c70269474c87eecfd9be3fbe7ae79e87"
    family = "Mirai"
    file_name = "c272740a1f634caf2693d9a5ee01d4e1c70269474c87eecfd9be3fbe7ae79e87.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:32:55"
  condition:
    hash.sha256(0, filesize) == "c272740a1f634caf2693d9a5ee01d4e1c70269474c87eecfd9be3fbe7ae79e87"
}

rule MalwareBazaar_Snowlight_096_d0f8b472
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0f8b472d336145317ab4c20cd6ac1c5c9c47510e4f69c9b2cad4ea516736a7e"
    family = "Snowlight"
    file_name = "d0f8b472d336145317ab4c20cd6ac1c5c9c47510e4f69c9b2cad4ea516736a7e.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:32:51"
  condition:
    hash.sha256(0, filesize) == "d0f8b472d336145317ab4c20cd6ac1c5c9c47510e4f69c9b2cad4ea516736a7e"
}

rule MalwareBazaar_unknown_097_37023f0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37023f0d47db2c181d07ff28efa6b6d8b7bba2d07dc2cc8d7c5b9b549ec416f3"
    family = "unknown"
    file_name = "37023f0d47db2c181d07ff28efa6b6d8b7bba2d07dc2cc8d7c5b9b549ec416f3.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:32:47"
  condition:
    hash.sha256(0, filesize) == "37023f0d47db2c181d07ff28efa6b6d8b7bba2d07dc2cc8d7c5b9b549ec416f3"
}

rule MalwareBazaar_unknown_098_f83322c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f83322c2ba37c1bc7b409b30d2bd96a206245cd99872cac82c455d53145c9f2d"
    family = "unknown"
    file_name = "f83322c2ba37c1bc7b409b30d2bd96a206245cd99872cac82c455d53145c9f2d.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:31:42"
  condition:
    hash.sha256(0, filesize) == "f83322c2ba37c1bc7b409b30d2bd96a206245cd99872cac82c455d53145c9f2d"
}

rule MalwareBazaar_unknown_099_e96866fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e96866fcca87e0d06b0f6b76708f8a0fe602f7d9cf1977896cdbffb37ea9e1c5"
    family = "unknown"
    file_name = "e96866fcca87e0d06b0f6b76708f8a0fe602f7d9cf1977896cdbffb37ea9e1c5.bin"
    file_type = "macho"
    first_seen = "2026-11-07 01:30:01"
  condition:
    hash.sha256(0, filesize) == "e96866fcca87e0d06b0f6b76708f8a0fe602f7d9cf1977896cdbffb37ea9e1c5"
}

rule MalwareBazaar_Mirai_100_fd530598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd5305985b2556c9e6c2089a88e98c033ab80668053be4838c9dcd74b36e6b31"
    family = "Mirai"
    file_name = "fd5305985b2556c9e6c2089a88e98c033ab80668053be4838c9dcd74b36e6b31.elf"
    file_type = "elf"
    first_seen = "2026-11-07 01:24:51"
  condition:
    hash.sha256(0, filesize) == "fd5305985b2556c9e6c2089a88e98c033ab80668053be4838c9dcd74b36e6b31"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

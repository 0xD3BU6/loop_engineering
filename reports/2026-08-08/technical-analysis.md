# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-08

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 634 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 634 |
| Unique family labels | 9 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 76 |
| Mirai | 15 |
| Prometei | 2 |
| WannaCry | 2 |
| NanoCore | 1 |
| RemusStealer | 1 |
| RustyStealer | 1 |
| CoinMiner | 1 |
| RemcosRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 68 |
| sh | 15 |
| exe | 13 |
| dll | 2 |
| apk | 1 |
| zip | 1 |

## Per-Sample Analysis

### Sample 1: `0392ae75588dc502`

| Field | Value |
|---|---|
| SHA-256 | `0392ae75588dc502f3f3c15fca4b32d9e49baa4e3b2301baaee1a05c7a30e3d5` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-08 02:16:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74ab9aa9a6ebcbbf80e566ce37de88d4` |
| SHA-1 | `0901bacfcff6d71f86f60a1a02d27a66c7faf941` |
| SHA-256 | `0392ae75588dc502f3f3c15fca4b32d9e49baa4e3b2301baaee1a05c7a30e3d5` |
| SHA3-384 | `03fb1eb9e6c7f5df870a88ef5599128532ac0eee6d345faf4c9b1838e9848e902cdb291b88d25098cc1ff1bacb053210` |
| TLSH | `T1D9317C9B09545A760013CA8E73A231886A4EE1F7285FC7E0DD490DFE42483CCF295B5D` |
| SSDEEP | `12:USi6Ssg1QNvi6Nv/c0IDc768nBJi16iDL9smX6+zy7ZFC76FClg6qjRN6PFTIsDN:VI0c0VfIfDL99yqvh5+Jyy8cWOcz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_0392ae75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0392ae75588dc502f3f3c15fca4b32d9e49baa4e3b2301baaee1a05c7a30e3d5"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-08 02:16:41"
  condition:
    hash.sha256(0, filesize) == "0392ae75588dc502f3f3c15fca4b32d9e49baa4e3b2301baaee1a05c7a30e3d5"
}
```

### Sample 2: `abde5216ecf909d7`

| Field | Value |
|---|---|
| SHA-256 | `abde5216ecf909d73c6acc4dec9eaf4e74e423785abe148aa66f867813341f39` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-08 02:01:06` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8dacc8bcfc72d8dc1a06f84ccadc0551` |
| SHA-1 | `27a00e1c1160bbdb97384c53966b2ece3479b2b0` |
| SHA-256 | `abde5216ecf909d73c6acc4dec9eaf4e74e423785abe148aa66f867813341f39` |
| SHA3-384 | `f117a57f4527d5a5033ff448d95c47a437d5e9be5b3c682ee546a82c1ccf5e2c439dbe4f06085afc883b6c9e4bf48459` |
| TLSH | `T110C27D956A867C44BEC94A3E4CBE2B1D6DF5C3D1324952AC3D8A3C719C11FACC618B1A` |
| SSDEEP | `768:W8vCB+25j6es8Rr9FYpMSUpi+20qUpi+20YQX:W8l25J9d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_abde5216
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abde5216ecf909d73c6acc4dec9eaf4e74e423785abe148aa66f867813341f39"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-08 02:01:06"
  condition:
    hash.sha256(0, filesize) == "abde5216ecf909d73c6acc4dec9eaf4e74e423785abe148aa66f867813341f39"
}
```

### Sample 3: `65b2323aae580d70`

| Field | Value |
|---|---|
| SHA-256 | `65b2323aae580d701f621bd5e775271a85938e5e571eecf34ab3804d53156752` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-08 01:36:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c5cdc7f5c017de27b4a92964adece10` |
| SHA-1 | `4765f1373a6b25945c9d80a25870bef8a52ed61f` |
| SHA-256 | `65b2323aae580d701f621bd5e775271a85938e5e571eecf34ab3804d53156752` |
| SHA3-384 | `7fd7f9bf481a8accec9bac834c90654e3f8347cfdc43c953a8e174871e5d7ea7dced7bf58b978e3e7da9f48cf59fcc73` |
| TLSH | `T148236C651A857C149E99C4371D7E2F0CB9AD43E6320452DE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:tJVEJVIhtMr9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:tnEJ2Mccr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_65b2323a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65b2323aae580d701f621bd5e775271a85938e5e571eecf34ab3804d53156752"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-08 01:36:46"
  condition:
    hash.sha256(0, filesize) == "65b2323aae580d701f621bd5e775271a85938e5e571eecf34ab3804d53156752"
}
```

### Sample 4: `63ebc5bb3a36ac82`

| Field | Value |
|---|---|
| SHA-256 | `63ebc5bb3a36ac820fddc9ccdd48a19bf8fc4b08fa4b5044bdf1027dbdce42e8` |
| Family label | `unknown` |
| File name | `63ebc5bb3a36ac820fddc9ccdd48a19bf8fc4b08fa4b5044bdf1027dbdce42e8` |
| File type | `dll` |
| First seen | `2026-08-08 01:25:11` |
| Reporter | `johnk3r` |
| Tags | `blogdosucesso-blog, dll` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9245195efcc99981f609520dbd16d07` |
| SHA-1 | `66bdb2a46282ee680445034e0f99a01ab1f977de` |
| SHA-256 | `63ebc5bb3a36ac820fddc9ccdd48a19bf8fc4b08fa4b5044bdf1027dbdce42e8` |
| SHA3-384 | `54b7b6406b883bf49c7abedd8ca6b8e98a4675bea5eb3bddc6b786daaaef42eb18ebe257fad41019bc31b48c28507798` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T11F71CB1693E84A2BE4BA4B38EEB303162BE4FC50CE73576F49C4121A6C612601932FB0` |
| SSDEEP | `24:etGSU8mmzUe6J39GgFKdgKkjhtkZfemQEhWI+ycuZhNOakS2PNnq:6GjpEfS/jsJem61ulOa3Kq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_63ebc5bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63ebc5bb3a36ac820fddc9ccdd48a19bf8fc4b08fa4b5044bdf1027dbdce42e8"
    family = "unknown"
    file_name = "63ebc5bb3a36ac820fddc9ccdd48a19bf8fc4b08fa4b5044bdf1027dbdce42e8"
    file_type = "dll"
    first_seen = "2026-08-08 01:25:11"
  condition:
    hash.sha256(0, filesize) == "63ebc5bb3a36ac820fddc9ccdd48a19bf8fc4b08fa4b5044bdf1027dbdce42e8"
}
```

### Sample 5: `4575b7164cec44ce`

| Field | Value |
|---|---|
| SHA-256 | `4575b7164cec44cee5891b3c5ffcc9af663139717c64572e1a0fcef57f8a3c12` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-08-08 01:24:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a02fa277962248d3077a3be7abc4a30f` |
| SHA-1 | `e1f8ee45326ad4c84c69fe3a4292f7e700f1ecb6` |
| SHA-256 | `4575b7164cec44cee5891b3c5ffcc9af663139717c64572e1a0fcef57f8a3c12` |
| SHA3-384 | `6a59c179e561314d4cfd0cfcc2404065a6d84453eac6a3de0cc2526171c575b9f06a09aa8ecf70a266c7c51eb4319529` |
| TLSH | `T14C018EDAE1609610406AD91E629752E0F430C3C7494A0FB8BF9C947DBB8DE14F16AF5C` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaFpPiFoMqL/XZ5j33A7:e9Qp+MsFpPmQLPT33A7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_4575b716
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4575b7164cec44cee5891b3c5ffcc9af663139717c64572e1a0fcef57f8a3c12"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-08 01:24:42"
  condition:
    hash.sha256(0, filesize) == "4575b7164cec44cee5891b3c5ffcc9af663139717c64572e1a0fcef57f8a3c12"
}
```

### Sample 6: `8743a8f2075c8033`

| Field | Value |
|---|---|
| SHA-256 | `8743a8f2075c8033558c39f321c306c3497c7d41bc272740d3ad6fc404063efe` |
| Family label | `unknown` |
| File name | `8743a8f2075c8033558c39f321c306c3497c7d41bc272740d3ad6fc404063efe` |
| File type | `dll` |
| First seen | `2026-08-08 01:24:38` |
| Reporter | `johnk3r` |
| Tags | `blogdosucesso-blog, dll` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1d0f818432c189a500fbefd0dd1dca6` |
| SHA-1 | `10d0d12473d843d4e4af74fcebf6d0fe4e70df26` |
| SHA-256 | `8743a8f2075c8033558c39f321c306c3497c7d41bc272740d3ad6fc404063efe` |
| SHA3-384 | `a82fee0c96af040d867b0c38f1061e9bba94cac3c7ab3e463595bbcec889addff6488205a1f3e6544aec826a898ed3af` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T195B1530A67D90973ECBE077468F313932670EE518E568F9F08C4212D7EA67545A327E1` |
| SSDEEP | `96:z/iZpTpIFzdMjys6VO0CGaBgf0llA90K:GazdRPCGays/+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_8743a8f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8743a8f2075c8033558c39f321c306c3497c7d41bc272740d3ad6fc404063efe"
    family = "unknown"
    file_name = "8743a8f2075c8033558c39f321c306c3497c7d41bc272740d3ad6fc404063efe"
    file_type = "dll"
    first_seen = "2026-08-08 01:24:38"
  condition:
    hash.sha256(0, filesize) == "8743a8f2075c8033558c39f321c306c3497c7d41bc272740d3ad6fc404063efe"
}
```

### Sample 7: `872abdb9f8f06277`

| Field | Value |
|---|---|
| SHA-256 | `872abdb9f8f06277cd14890d9ba6a392f1caef42d07bf3271f1d5485ac0f12e2` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487476.27219.14846` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:59` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ccbf83098b8fe8471878a1e590fb6f6` |
| SHA-1 | `d7f7db3e2cbf8dba4f6f5b8f201b5e3240f6af5f` |
| SHA-256 | `872abdb9f8f06277cd14890d9ba6a392f1caef42d07bf3271f1d5485ac0f12e2` |
| SHA3-384 | `29ec3d58daafa0c74bad91b99f9569b05c236cb97aae032a0211c90483854deeef29d0b5dbf4fc91a5bda5ba67c6f80c` |
| TLSH | `T152A36C47770B2880F82202F067DDA3E03F1561DBAB361EB7586A62F77F731991D05A92` |
| SSDEEP | `1536:E037cBIxUGhOCgZKK8nuekvJhtvbu34jgLuUn5p5M/LW:77pxUAJgGGJhzgahq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_872abdb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "872abdb9f8f06277cd14890d9ba6a392f1caef42d07bf3271f1d5485ac0f12e2"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487476.27219.14846"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:59"
  condition:
    hash.sha256(0, filesize) == "872abdb9f8f06277cd14890d9ba6a392f1caef42d07bf3271f1d5485ac0f12e2"
}
```

### Sample 8: `fa99ae5885e684bc`

| Field | Value |
|---|---|
| SHA-256 | `fa99ae5885e684bc7d8223a3864f952eac501f79ccaa3badf4daffce168adef7` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487480.8646.13191` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:57` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47a66830114124add8b7d02746b9ec22` |
| SHA-1 | `f2033632c5714b35e2cfaf8e2318db7822ba0726` |
| SHA-256 | `fa99ae5885e684bc7d8223a3864f952eac501f79ccaa3badf4daffce168adef7` |
| SHA3-384 | `c0d0758d4a621e21933a26c550b787f9a213de565da975c972a58819103af37392e6242ec3b75b74f5b906d5cfec3ae3` |
| TLSH | `T1A8131ABBDE0E3941D3C4E338E7590BE1A02FB964D29640B77E42718DC4ED9DD8DA2246` |
| SSDEEP | `768:tw3E/xfKgmx0BHXAa7WekjHAipfgTp1lxLtzoCeRmlKJ:t2MfKglJAmkciFgTpD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_fa99ae58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa99ae5885e684bc7d8223a3864f952eac501f79ccaa3badf4daffce168adef7"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487480.8646.13191"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:57"
  condition:
    hash.sha256(0, filesize) == "fa99ae5885e684bc7d8223a3864f952eac501f79ccaa3badf4daffce168adef7"
}
```

### Sample 9: `9915e6f62c19a7c6`

| Field | Value |
|---|---|
| SHA-256 | `9915e6f62c19a7c6622f15bca906b805bb9cde4a5b3e56bbfc586f1ef84a461e` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487453.74.4059` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:56` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bacbfd94eb36a8c7057ab7b492cb7c7` |
| SHA-1 | `c74659e2ffe818d8af5692e1963a6c006f211f46` |
| SHA-256 | `9915e6f62c19a7c6622f15bca906b805bb9cde4a5b3e56bbfc586f1ef84a461e` |
| SHA3-384 | `a16c8dea5bbd71bacfc1671b7665c613589a397f3e4f79e5e9fcf57d791ccd736b61536b3529adbabd738e661d655b3c` |
| TLSH | `T1C2F22B93C52A9EFAC106B4B195F58E780B267D468B2B0EA9E135CBE0024FDC8F145776` |
| SSDEEP | `384:fJorpUf2XgC1KLJYNaR/WgR2NFGgKiNEF2M8aQj2m2sj4XjUHnCCCV9wIurWRPzd:OdQ2jIOgUXKiNNzcUHnwV2rKRr71e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_9915e6f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9915e6f62c19a7c6622f15bca906b805bb9cde4a5b3e56bbfc586f1ef84a461e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487453.74.4059"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:56"
  condition:
    hash.sha256(0, filesize) == "9915e6f62c19a7c6622f15bca906b805bb9cde4a5b3e56bbfc586f1ef84a461e"
}
```

### Sample 10: `32c7f6c4fb71e747`

| Field | Value |
|---|---|
| SHA-256 | `32c7f6c4fb71e747151758b54a2cfcf7c03373fcccfbdd4aa48f54d8b9e2077a` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487450.23052.18422` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:55` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fce8d45117b748ebd85d2261715defc` |
| SHA-1 | `d897ae7824c4be3762da1a2acf42a8a2304c66e5` |
| SHA-256 | `32c7f6c4fb71e747151758b54a2cfcf7c03373fcccfbdd4aa48f54d8b9e2077a` |
| SHA3-384 | `045746192fb24914b26b16524415237aa2d6c52e45e9891967ba2259f400f76e2a15569bfaa0b89b9cb193b5e71782b2` |
| TLSH | `T1E9234C46FD268720D3A216F05FF65A4257816E2638D37300D8A8F63CF9AD0A86793DDD` |
| SSDEEP | `768:axWLyvOReZHXivVBmvsR1V7lEAYtXaZUQBV5gGkHkl6oZerArRhy/lTTVDeyLkZd:HLKBHXQmGlYTrqXytTj0a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_32c7f6c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32c7f6c4fb71e747151758b54a2cfcf7c03373fcccfbdd4aa48f54d8b9e2077a"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487450.23052.18422"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:55"
  condition:
    hash.sha256(0, filesize) == "32c7f6c4fb71e747151758b54a2cfcf7c03373fcccfbdd4aa48f54d8b9e2077a"
}
```

### Sample 11: `1324ef0b2345c32e`

| Field | Value |
|---|---|
| SHA-256 | `1324ef0b2345c32e885fe9b14e455f54369ca28ac656949871da8c9ffd427416` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487467.20708.3214` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:53` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4391b5371f9f9686c6c81c88906d83c` |
| SHA-1 | `1fa832d5492fc8ea76e4eccdbf9fded03245b6b5` |
| SHA-256 | `1324ef0b2345c32e885fe9b14e455f54369ca28ac656949871da8c9ffd427416` |
| SHA3-384 | `eb59b0863480762932cd45fbcc740746d9b0e3fea815498b635d225f9a4f17f10604262ac2b22436544ba44a69ec4d9f` |
| TLSH | `T160536F31F94267F1CC720A38979B2E496E3709655EEB16615E1B233EED76810CA30F8D` |
| SSDEEP | `1536:Wps1gmV6GGx9uuODuuuuuuuuu3GIoXuEnsbz13PHXLANj8pxVA:BSmVs4+oXnK/xS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_1324ef0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1324ef0b2345c32e885fe9b14e455f54369ca28ac656949871da8c9ffd427416"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487467.20708.3214"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:53"
  condition:
    hash.sha256(0, filesize) == "1324ef0b2345c32e885fe9b14e455f54369ca28ac656949871da8c9ffd427416"
}
```

### Sample 12: `70523584108df858`

| Field | Value |
|---|---|
| SHA-256 | `70523584108df8582ecbc942e0ddf2caa32810c8634d0217fbed663d7563825c` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487481.3064.13601` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:50` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0c2c15e7befe9cc0ccd789470b4219f` |
| SHA-1 | `8701b0e835d93f579049008c24f6c5e13baa187a` |
| SHA-256 | `70523584108df8582ecbc942e0ddf2caa32810c8634d0217fbed663d7563825c` |
| SHA3-384 | `c783b660ca1c4d66b385a1b66872455e6d14bfb95852e44d7d82b205b07f331c7d2a617684abe46a2b97a691cbc269aa` |
| TLSH | `T182933B4B660779C4F17101F4A3CE4BD03F2260DB6B3A5DB6AC7902F2ABB319A1D1DA51` |
| SSDEEP | `1536:XlcR27hEbhjjHb1aJIxYBfDjwIwyRGAEgdUn5p5M/LWi:XlcRGg5bb1aqxYdDBdJEgdhq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_70523584
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70523584108df8582ecbc942e0ddf2caa32810c8634d0217fbed663d7563825c"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487481.3064.13601"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:50"
  condition:
    hash.sha256(0, filesize) == "70523584108df8582ecbc942e0ddf2caa32810c8634d0217fbed663d7563825c"
}
```

### Sample 13: `1d8871eca20bb9b4`

| Field | Value |
|---|---|
| SHA-256 | `1d8871eca20bb9b4173bc7c6fafe3ee354081ce77832ac7c014f28e3e0d91d78` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487460.10599.10981` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:49` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d05fda13fe9e787e4d149bae39f2f0b4` |
| SHA-1 | `fcc2b06017177abf9a379d071de508c92e4ff537` |
| SHA-256 | `1d8871eca20bb9b4173bc7c6fafe3ee354081ce77832ac7c014f28e3e0d91d78` |
| SHA3-384 | `060263e63dc5fbea9484610ce9f86d03e705983e25444bb72477d25e0ca69fa526fb6de1f45a393f000c0c506c7d1fef` |
| TLSH | `T1A1C44BD4F2C65D7DF00219321A83DB16D6165FD2E3295BAF892947492C8CBEBCF32168` |
| SSDEEP | `6144:VeJZkHnXRYqvzVsF7qQCFPl0pLAlPSTgS+60tkLZOYWDG+5VQyQp3q3KIO:V0o3zWs0d//+6mSZ67Qp3q3pO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_1d8871ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d8871eca20bb9b4173bc7c6fafe3ee354081ce77832ac7c014f28e3e0d91d78"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487460.10599.10981"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:49"
  condition:
    hash.sha256(0, filesize) == "1d8871eca20bb9b4173bc7c6fafe3ee354081ce77832ac7c014f28e3e0d91d78"
}
```

### Sample 14: `6ee096499b5bf336`

| Field | Value |
|---|---|
| SHA-256 | `6ee096499b5bf33626de5fc8e21200103fe69825cc33cad951d23b85990f593d` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487488.28323.32157` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:48` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15906c3de1ef63a97fd0f15c4bbe3524` |
| SHA-1 | `48c7a5c67d0de7ab76e29de00ed783d5b42e4d62` |
| SHA-256 | `6ee096499b5bf33626de5fc8e21200103fe69825cc33cad951d23b85990f593d` |
| SHA3-384 | `fe2e9942305d9ab80741b8816a08ac5685edc886d37e769eaf83f4e1b678458049c28c121bbdf0714234b03f138ec2bf` |
| TLSH | `T16943E62B3584A3F4F58157B077E7A3B27C680BFF1096A05B6A4216167AF07BB603C947` |
| SSDEEP | `1536:3pO7JkN6os4c3dscp9RILT4S633oPCUKtkJl1+nUo:58JuZ/cp4LTN6HwC/tkMV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_6ee09649
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee096499b5bf33626de5fc8e21200103fe69825cc33cad951d23b85990f593d"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487488.28323.32157"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:48"
  condition:
    hash.sha256(0, filesize) == "6ee096499b5bf33626de5fc8e21200103fe69825cc33cad951d23b85990f593d"
}
```

### Sample 15: `ed96fbe0486a2a17`

| Field | Value |
|---|---|
| SHA-256 | `ed96fbe0486a2a17f309608fa7900fa0a8ca7999537084efd5f863ee7ccf5b5f` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487483.10694.24323` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:47` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63581800ecdfdb736b9dd984f635612a` |
| SHA-1 | `fac78ec838b97c71c90216b2ee3e27ee5677a44c` |
| SHA-256 | `ed96fbe0486a2a17f309608fa7900fa0a8ca7999537084efd5f863ee7ccf5b5f` |
| SHA3-384 | `0c335a5b3a1c01151be03741685b9bdec150cffb9808eb1eed4beb7b04fa2fbc8465adb948eefe654c97b28f5de56a32` |
| TLSH | `T1E153D60F7C1ECAB2CA919634C63F00511655CB5158BB9F326ABAD61EDBB212BD317CC8` |
| SSDEEP | `1536:Z5BOgxjMM7l19SDFdpPeb2gZ8Maf9BTv:3BvxjMMZ19UFdpQyMaf/T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_ed96fbe0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed96fbe0486a2a17f309608fa7900fa0a8ca7999537084efd5f863ee7ccf5b5f"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487483.10694.24323"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:47"
  condition:
    hash.sha256(0, filesize) == "ed96fbe0486a2a17f309608fa7900fa0a8ca7999537084efd5f863ee7ccf5b5f"
}
```

### Sample 16: `5526877a74df0836`

| Field | Value |
|---|---|
| SHA-256 | `5526877a74df083601ea0141b7ad632420535197faff34b3854e7c74407bde09` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487490.20116.20536` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:45` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bc53a6b4cc8ee93eeecc9fde17a29fd` |
| SHA-1 | `b258a63023fb893b7b9fa1a326a66ac20d1eb09d` |
| SHA-256 | `5526877a74df083601ea0141b7ad632420535197faff34b3854e7c74407bde09` |
| SHA3-384 | `45c1e93cd0d8f489a36f087fa70bb14f9040989d26dc0c2ac9ff08b69157c075bd85aa39c1a21b313b549e97a9105d3c` |
| TLSH | `T18C43935133079D6FFD6A17B48AE28AF0B3C5BD9634B14696E226BB8C0F300ED5D4C685` |
| SSDEEP | `1536:kdPDgXMvBqQKrG7CMWdz4n2B1u/AYDXbRRFaL51B1sw/APf53HXiUaHEHRyXMnkv:kdPC4ZDXZm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_5526877a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5526877a74df083601ea0141b7ad632420535197faff34b3854e7c74407bde09"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487490.20116.20536"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:45"
  condition:
    hash.sha256(0, filesize) == "5526877a74df083601ea0141b7ad632420535197faff34b3854e7c74407bde09"
}
```

### Sample 17: `4536e5392385b70c`

| Field | Value |
|---|---|
| SHA-256 | `4536e5392385b70cde63388193086d9034c687b0530702634f88c943a888b5ef` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.39487491.12968.2034` |
| File type | `elf` |
| First seen | `2026-08-08 01:18:44` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d95dca231ef6e894db41765c4bdec22b` |
| SHA-1 | `95c3a61a16ccf9f39a2c44c377537e99ffd4b44e` |
| SHA-256 | `4536e5392385b70cde63388193086d9034c687b0530702634f88c943a888b5ef` |
| SHA3-384 | `36fa5f1395939d646f3970ff21eb42e07ffac282a759522dbef45e57a96e35f4a65669fcc547bb560025ad0da46d1099` |
| TLSH | `T193130A424C218314C6E512BC57F94A59E3C15F0739DB2701CA72FB387DAE1A8BA93DDA` |
| SSDEEP | `768:QLMeJWnaT0bO08QuAUyEYsAzfOchXlTA2J4G+MyZBJEE13Pohi6W:CRdbXYFO2afG+ZBDoo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_4536e539
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4536e5392385b70cde63388193086d9034c687b0530702634f88c943a888b5ef"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487491.12968.2034"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:44"
  condition:
    hash.sha256(0, filesize) == "4536e5392385b70cde63388193086d9034c687b0530702634f88c943a888b5ef"
}
```

### Sample 18: `310dc2fc8724899d`

| Field | Value |
|---|---|
| SHA-256 | `310dc2fc8724899d5d2e1a2c2d8516c3585304a481109eeeacef24d51d689d57` |
| Family label | `Mirai` |
| File name | `data_x86` |
| File type | `elf` |
| First seen | `2026-08-08 01:12:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `226ab591c62085e52d98a15583bc21a1` |
| SHA-1 | `b8ca0b94ec937ffb83364fc83aa32b4211a4ef7a` |
| SHA-256 | `310dc2fc8724899d5d2e1a2c2d8516c3585304a481109eeeacef24d51d689d57` |
| SHA3-384 | `83c16d3691847aee914379bebd8337db285c9d871be0536c0c1a2f54b2f9527275b3b917f42d429cb9c7969a164cdd8c` |
| TLSH | `T18E157D9DEBC6E4E1F26300F1025ED7F75534A12A8053FAF2EF462663B4327A16F16219` |
| TELFHASH | `t14fe148b32a79a8ec77e08415826bb220ce26e13725f0347215f364927a73d136f76d79` |
| SSDEEP | `24576:YduS8qwHhQohHWluURwstEeo1GaFIpj0Nn:ZHhQohHWjws7A4j2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_310dc2fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310dc2fc8724899d5d2e1a2c2d8516c3585304a481109eeeacef24d51d689d57"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:52"
  condition:
    hash.sha256(0, filesize) == "310dc2fc8724899d5d2e1a2c2d8516c3585304a481109eeeacef24d51d689d57"
}
```

### Sample 19: `f6aefcfa94b8339c`

| Field | Value |
|---|---|
| SHA-256 | `f6aefcfa94b8339ca4c2358a3f316647ae1e2d10d9e528e75b57f58bc2878889` |
| Family label | `Mirai` |
| File name | `data_arm4` |
| File type | `elf` |
| First seen | `2026-08-08 01:12:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa42eead33058c71616b171cb995b240` |
| SHA-1 | `76bb93ef3f9246f7c28a839ef026e050d19f5f34` |
| SHA-256 | `f6aefcfa94b8339ca4c2358a3f316647ae1e2d10d9e528e75b57f58bc2878889` |
| SHA3-384 | `8b101c75f7996664b326340f8307c270fef8d9c689be158d5824708934ed6efb4acd06e93b8ac04425c80dd2be2bdd19` |
| TLSH | `T1EAC30A427D529F13C6C321F7FBAE42583B136BBDD7EA3102E9247F50274B89A0E26951` |
| TELFHASH | `t1f9213171ef9005ec53e54162c9eee2120bf5369d27293c13866d9e9e4a731cb343c839` |
| SSDEEP | `3072:WRUJP1WddniCcEL0mfnKS7EidTl/zjd6K:WRU4FiCxw+KS7DXjd6K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_f6aefcfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6aefcfa94b8339ca4c2358a3f316647ae1e2d10d9e528e75b57f58bc2878889"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:49"
  condition:
    hash.sha256(0, filesize) == "f6aefcfa94b8339ca4c2358a3f316647ae1e2d10d9e528e75b57f58bc2878889"
}
```

### Sample 20: `96b57aef07bb0c43`

| Field | Value |
|---|---|
| SHA-256 | `96b57aef07bb0c43a540f0fd16284e7d6d67d2530fea2c9134bd34b1230d6d0d` |
| Family label | `Mirai` |
| File name | `data_arm7` |
| File type | `elf` |
| First seen | `2026-08-08 01:12:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `374574fcb1a9d53fed777fb9ed16ef57` |
| SHA-1 | `fd6361d95ffb3621a3c10776cd2da67d43aaa04a` |
| SHA-256 | `96b57aef07bb0c43a540f0fd16284e7d6d67d2530fea2c9134bd34b1230d6d0d` |
| SHA3-384 | `5848d5f6911cfd4646fe5d26422568df12f1bf911010a6a7059fc934ee3e42377dbd64dc17727f4bf086de5f16abf5df` |
| TLSH | `T177E31946B9519F12D5C321FAFB9F814933136FB8E3FA7102DD206F60238A99B0E76512` |
| TELFHASH | `t177213e00879418dc5fe043d8c2eeb026c7b875db570618528a3de2cf8b26ee5741682f` |
| SSDEEP | `3072:6cnkpxeH97eOPuvY4MNvVUYiahtQEuNauZ8ifYIVA7pX3mJSYFsFDvTIPs:6cnkpxeQiuv+vu0h5maq8ifYIVANX3rX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_96b57aef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96b57aef07bb0c43a540f0fd16284e7d6d67d2530fea2c9134bd34b1230d6d0d"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:48"
  condition:
    hash.sha256(0, filesize) == "96b57aef07bb0c43a540f0fd16284e7d6d67d2530fea2c9134bd34b1230d6d0d"
}
```

### Sample 21: `1b8c1267dcab40e4`

| Field | Value |
|---|---|
| SHA-256 | `1b8c1267dcab40e4f24090f24dca941a16cce9328c810d4a0ec2b8ba907cb6e5` |
| Family label | `Mirai` |
| File name | `data_powerpc` |
| File type | `elf` |
| First seen | `2026-08-08 01:12:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32e3a53c94029ce890d0d0d51e62c038` |
| SHA-1 | `56bfd7e20c43ce423efb9dc4d8cd9d91d6616a4f` |
| SHA-256 | `1b8c1267dcab40e4f24090f24dca941a16cce9328c810d4a0ec2b8ba907cb6e5` |
| SHA3-384 | `9440cfe05a12c162928b9deab5e4125971adccb46704afa5e66c68d2536d3f55f2a698ed4a356b14e0d24a6cd040449f` |
| TLSH | `T1D8C31902770D0F43E1232CF02B7B1BE087A9BEA219F5E584651EBEC652B5DB12245EDD` |
| SSDEEP | `1536:2cFb8lWRU/Ltjyv9UaFlfGyD4bXNEvWsbnXsBDGO7ZXKAaiOvJjBawei1civp0We:RWT10rFlfZW0XsBVUAgNfciv2Wz1voUS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_1b8c1267
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b8c1267dcab40e4f24090f24dca941a16cce9328c810d4a0ec2b8ba907cb6e5"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:47"
  condition:
    hash.sha256(0, filesize) == "1b8c1267dcab40e4f24090f24dca941a16cce9328c810d4a0ec2b8ba907cb6e5"
}
```

### Sample 22: `7bbb3ebef9e0d665`

| Field | Value |
|---|---|
| SHA-256 | `7bbb3ebef9e0d6651fae88c088ae0c4245bae265991baca2585740e60e2f55fe` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-08 01:12:45` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba700f91437eb432259b34f29715117f` |
| SHA-1 | `58e4aca7177c98d0c81b98ff08375c0964cc23ca` |
| SHA-256 | `7bbb3ebef9e0d6651fae88c088ae0c4245bae265991baca2585740e60e2f55fe` |
| SHA3-384 | `a940c788a190d073faccdd1b13d40e9455fee1044d020ce6a296364f42cf4b6fcbdd93af1721741c77efc4706af01fc3` |
| TLSH | `T1BCC26D956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C12F9CD618B1A` |
| SSDEEP | `768:O8vCB+25j6es8Ry9FYpMSUpi+20qUpi+20YQX:O8l25JUd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_7bbb3ebe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bbb3ebef9e0d6651fae88c088ae0c4245bae265991baca2585740e60e2f55fe"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-08 01:12:45"
  condition:
    hash.sha256(0, filesize) == "7bbb3ebef9e0d6651fae88c088ae0c4245bae265991baca2585740e60e2f55fe"
}
```

### Sample 23: `1ca16bc34b14b276`

| Field | Value |
|---|---|
| SHA-256 | `1ca16bc34b14b276183cee1f95e26759c5aa6c5136c7082a3b1e4503838cc4f5` |
| Family label | `Mirai` |
| File name | `data_arm5` |
| File type | `elf` |
| First seen | `2026-08-08 01:12:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3166995ba679103f617ab6896014a57a` |
| SHA-1 | `8076f3a0e0e5d38249a87522bbfb744f469d1835` |
| SHA-256 | `1ca16bc34b14b276183cee1f95e26759c5aa6c5136c7082a3b1e4503838cc4f5` |
| SHA3-384 | `8c1d97e93ebfd746eac1ab5908eb0e5ab61c51ad740d74670d92a7537219056e3c1a097e69d837f45b314fd757a4e215` |
| TLSH | `T1C2C30B52BE419F13C5C321F6BBAE465837176B7CD7EA3102E924BF9027478EA0E36511` |
| TELFHASH | `t1f9211c31cf540adca7e2414994de70512bed316a370424939b2dba8e8a771d2782d82b` |
| SSDEEP | `3072:F0EF0ssSFe2+6ONbPG/RwG1czDoXGigDK:FNFwSF31IG/RjKo2igDK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_1ca16bc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ca16bc34b14b276183cee1f95e26759c5aa6c5136c7082a3b1e4503838cc4f5"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:44"
  condition:
    hash.sha256(0, filesize) == "1ca16bc34b14b276183cee1f95e26759c5aa6c5136c7082a3b1e4503838cc4f5"
}
```

### Sample 24: `389e175ec8c0e429`

| Field | Value |
|---|---|
| SHA-256 | `389e175ec8c0e4295620e2e56ed431ee6e19702bd10bc087c210473206c5d2ef` |
| Family label | `Mirai` |
| File name | `data_arm6` |
| File type | `elf` |
| First seen | `2026-08-08 01:12:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd0b0ffe469faed8d4851ce15cfc6ed1` |
| SHA-1 | `5f4513a9282e7b39318562284d0b2e7b2c51c973` |
| SHA-256 | `389e175ec8c0e4295620e2e56ed431ee6e19702bd10bc087c210473206c5d2ef` |
| SHA3-384 | `7e070b0bda6727f3501313efa4af619bcbad5dedda9c2f7ab244ff82d856c5e5416f1027d315d7f3ca2f436c013fe3b3` |
| TLSH | `T18CD32A56B9518B12C1C321BAFB5F514D33136FB8E3ED72129D14AF60278B8DB0E7A912` |
| SSDEEP | `3072:aUwhx8ScyIZ+jSkXSEDNaZ2NJsB/aNlmG2E2MQNrI9qP8L:aUwhx0y6+OjaaZqJsRaPmGIMQAqP8L` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_389e175e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "389e175ec8c0e4295620e2e56ed431ee6e19702bd10bc087c210473206c5d2ef"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:43"
  condition:
    hash.sha256(0, filesize) == "389e175ec8c0e4295620e2e56ed431ee6e19702bd10bc087c210473206c5d2ef"
}
```

### Sample 25: `ce1358a99e19d0f4`

| Field | Value |
|---|---|
| SHA-256 | `ce1358a99e19d0f421c959f66e4b89c12cf13180f4bd3dac2a070e5dd290130b` |
| Family label | `Mirai` |
| File name | `data_x86_64` |
| File type | `elf` |
| First seen | `2026-08-08 01:12:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84c811697a91bf9cdbcfe3ee2577d025` |
| SHA-1 | `7d04e0d84c15f6c9bb79ffb7fcc78f504ae1793f` |
| SHA-256 | `ce1358a99e19d0f421c959f66e4b89c12cf13180f4bd3dac2a070e5dd290130b` |
| SHA3-384 | `d3c236787a397b1d9e5b00dcb99d877b3d72bcdb10af72c150e4ac24ad8e814a9f2fe2158c4552592df73627d8b4f91d` |
| TLSH | `T13D845B92F2A228FDD952C930835D6523F63870494311AAFB27C8EB753D16AD06F3EB51` |
| TELFHASH | `t158a105f1018a65f8d562f9d5ceb2b721d6b203ea93246935423ded70dd43be86961c03` |
| SSDEEP | `6144:6wVN4I5NJSOceuwrADMWUKC7FxozrNNPWoTQ9NE8LOMPEz8zUCuW/6Gk:6yJ5DP5MAWUKoAvWoynLOMMu5SG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_ce1358a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce1358a99e19d0f421c959f66e4b89c12cf13180f4bd3dac2a070e5dd290130b"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:42"
  condition:
    hash.sha256(0, filesize) == "ce1358a99e19d0f421c959f66e4b89c12cf13180f4bd3dac2a070e5dd290130b"
}
```

### Sample 26: `b88ffb509409384a`

| Field | Value |
|---|---|
| SHA-256 | `b88ffb509409384a8190be6d022df92f537a5d3ce728efa2e4ab18ae7e76f5d5` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-08-08 01:04:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69bb8d8218ed4f7f293a736c748bfa52` |
| SHA-1 | `16d79ca4744aa1178c22fad25bf8dc9f2a5e58e1` |
| SHA-256 | `b88ffb509409384a8190be6d022df92f537a5d3ce728efa2e4ab18ae7e76f5d5` |
| SHA3-384 | `d6a6adab70695add6b9af7e791c7593690470d8f904e6191f9609150de87151752772fbb3b37615d92d5274e4354973a` |
| TLSH | `T18E018EDAE160961040AAD91D22975194F830C3C7194A4FB5FF6C647DAB8DD14B07AF98` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaF1GFoMqJB/XZ5jb3EX:e9Qp+MsF1SQfPTb3EX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_b88ffb50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b88ffb509409384a8190be6d022df92f537a5d3ce728efa2e4ab18ae7e76f5d5"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-08 01:04:42"
  condition:
    hash.sha256(0, filesize) == "b88ffb509409384a8190be6d022df92f537a5d3ce728efa2e4ab18ae7e76f5d5"
}
```

### Sample 27: `4eecc63d8e969003`

| Field | Value |
|---|---|
| SHA-256 | `4eecc63d8e969003394c69f1c47c8afb253071935e13bfcf23eebda3184269e0` |
| Family label | `Mirai` |
| File name | `data_mips` |
| File type | `elf` |
| First seen | `2026-08-08 01:02:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `248cc71c0be7a7516fcb478d6bf3c042` |
| SHA-1 | `3fc058f94ae552c715fb5a9bfe0384a5d220a8e3` |
| SHA-256 | `4eecc63d8e969003394c69f1c47c8afb253071935e13bfcf23eebda3184269e0` |
| SHA3-384 | `5647490577cf7a415bf59f98f790a2b958acc1618ac0be51ec1f2aa6d2f97b2cd0ec8bcddce6688f6fcfd5ba027f9698` |
| TLSH | `T1B6F3855A3F228F7EF369877447B38E21975977E626E1C681F1ACD5401E202CE241FBA4` |
| TELFHASH | `t17c41861849b417e066756c9d449dfb67d6a330da7e166c338e11f86eeb69f834e10c0c` |
| SSDEEP | `3072:Ztuyugv8viadgaUQjedsn8RobcfMag4yz7j+:Zagv8vivasdsb4fMky7j+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_4eecc63d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eecc63d8e969003394c69f1c47c8afb253071935e13bfcf23eebda3184269e0"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-08-08 01:02:48"
  condition:
    hash.sha256(0, filesize) == "4eecc63d8e969003394c69f1c47c8afb253071935e13bfcf23eebda3184269e0"
}
```

### Sample 28: `7a53cf03464fb5ed`

| Field | Value |
|---|---|
| SHA-256 | `7a53cf03464fb5ed8a6bf0eeb905cc1dfd655626fe42980008e7897ac70847c0` |
| Family label | `Mirai` |
| File name | `data_mipsel` |
| File type | `elf` |
| First seen | `2026-08-08 01:02:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c654f788a109430f0c03f37cac08c46` |
| SHA-1 | `a552e1be97b208720be1ad383a7ad80f8f900b28` |
| SHA-256 | `7a53cf03464fb5ed8a6bf0eeb905cc1dfd655626fe42980008e7897ac70847c0` |
| SHA3-384 | `d4a1cffb87e564ad15e25a265dcb058350636c5d52626c0d492e798b331a85f5b7296ee830c3864299447864746a4b02` |
| TLSH | `T1B4F3F80AAB610FF7D86BDD3702E90B1129CCAD5725B53B797534E818B50B18B89E3C78` |
| SSDEEP | `3072:s5gMP0KXroPi3jF93lBWNTGyOOWD7sKaLl:sOMP0ZPi3jFhfWNTI7sBZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_7a53cf03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a53cf03464fb5ed8a6bf0eeb905cc1dfd655626fe42980008e7897ac70847c0"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-08-08 01:02:47"
  condition:
    hash.sha256(0, filesize) == "7a53cf03464fb5ed8a6bf0eeb905cc1dfd655626fe42980008e7897ac70847c0"
}
```

### Sample 29: `60a779d7f51d106e`

| Field | Value |
|---|---|
| SHA-256 | `60a779d7f51d106e4a8d14e6fe987ca6b7ec4b6c7942c665bb6653a0dae0fc4d` |
| Family label | `NanoCore` |
| File name | `9209C4F81950DA9422311103C970CB42.exe` |
| File type | `exe` |
| First seen | `2026-08-08 00:55:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9209c4f81950da9422311103c970cb42` |
| SHA-1 | `29581ba87e3feedf1dafcc133820f9259fb38e0c` |
| SHA-256 | `60a779d7f51d106e4a8d14e6fe987ca6b7ec4b6c7942c665bb6653a0dae0fc4d` |
| SHA3-384 | `401d3c3bad1142310e09cdff80d9d7f6986922c41b4cd4f1f85e7b98afb796803905cc3fae5c1d5d7bfa6fb9840792b7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F014CF1A77A94A2FE2DE86B9611212579379C2E3D8C3F3EF28D454B34B163E506071D3` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5pMluAJDAxGJg09osK:MLV6BtpmkWRAioJgzZ` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_029_60a779d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60a779d7f51d106e4a8d14e6fe987ca6b7ec4b6c7942c665bb6653a0dae0fc4d"
    family = "NanoCore"
    file_name = "9209C4F81950DA9422311103C970CB42.exe"
    file_type = "exe"
    first_seen = "2026-08-08 00:55:05"
  condition:
    hash.sha256(0, filesize) == "60a779d7f51d106e4a8d14e6fe987ca6b7ec4b6c7942c665bb6653a0dae0fc4d"
}
```

### Sample 30: `604540e8f61d04ed`

| Field | Value |
|---|---|
| SHA-256 | `604540e8f61d04ed0bde2678ace8d1d9a43461e0a2b8533d371891d6bf4089a2` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-07 23:52:34` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e964a5e37ad3c1c0478ff13ac5b32c65` |
| SHA-1 | `53f5dc9f1f5b05d38f927b11145a4fb93351324b` |
| SHA-256 | `604540e8f61d04ed0bde2678ace8d1d9a43461e0a2b8533d371891d6bf4089a2` |
| SHA3-384 | `b7b32079c7b4e6b59b000fe887789f3f75cd6d5fdef4a1a9fa7145613e2cf8b5f926507e3918a7d549a13792dfe64415` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T198E6336C6A9022FFFAB3503CECD24278967874A85371CD9B07D857A56E531E0C93C7A2` |
| SSDEEP | `393216:4YGmy0DB/d4cBls/PregDxXMCHWUjvcuI3/PGTAI:ZGwQnlxXMb8kH/O7` |
| ICON-DHASH | `71f0e4d6e6e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_604540e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "604540e8f61d04ed0bde2678ace8d1d9a43461e0a2b8533d371891d6bf4089a2"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-07 23:52:34"
  condition:
    hash.sha256(0, filesize) == "604540e8f61d04ed0bde2678ace8d1d9a43461e0a2b8533d371891d6bf4089a2"
}
```

### Sample 31: `3119fd7988607b0c`

| Field | Value |
|---|---|
| SHA-256 | `3119fd7988607b0c3a5eb5256ee942d5c711d1141e831742f433d8f58d56b900` |
| Family label | `Prometei` |
| File name | `3119fd7988607b0c3a5eb5256ee942d5c711d1141e831742f433d8f58d56b900` |
| File type | `elf` |
| First seen | `2026-08-07 23:24:56` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8fd9f9dd386d1e8b55a1b31cd53bf3b` |
| SHA-1 | `62fbeec3e944a13d5f101df06c916e3f8c6ca90e` |
| SHA-256 | `3119fd7988607b0c3a5eb5256ee942d5c711d1141e831742f433d8f58d56b900` |
| SHA3-384 | `383d2cb8875923d0f6ea0bd520385f89e52742f82482091bd802741e57fbbfac9c46896b18518fe068152a051e79fffa` |
| TLSH | `T184A423B4F9229E8F6DD769F91B24835DE182C172589D4C1313AE94A34F3D632BF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdZ:Fs6pyCC/Ya2hpi6T6N4L` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_031_3119fd79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3119fd7988607b0c3a5eb5256ee942d5c711d1141e831742f433d8f58d56b900"
    family = "Prometei"
    file_name = "3119fd7988607b0c3a5eb5256ee942d5c711d1141e831742f433d8f58d56b900"
    file_type = "elf"
    first_seen = "2026-08-07 23:24:56"
  condition:
    hash.sha256(0, filesize) == "3119fd7988607b0c3a5eb5256ee942d5c711d1141e831742f433d8f58d56b900"
}
```

### Sample 32: `10505f035b1e6569`

| Field | Value |
|---|---|
| SHA-256 | `10505f035b1e6569cb22d42614829e85fd432e014418f457e2e1dfc31dcd505c` |
| Family label | `Prometei` |
| File name | `10505f035b1e6569cb22d42614829e85fd432e014418f457e2e1dfc31dcd505c` |
| File type | `exe` |
| First seen | `2026-08-07 23:24:28` |
| Reporter | `c2hunter` |
| Tags | `exe, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fde4bb9242202ad2ec42ab19a0fdd453` |
| SHA-1 | `cd1378bb22fa98439afecc6cf3e657b3633ed37b` |
| SHA-256 | `10505f035b1e6569cb22d42614829e85fd432e014418f457e2e1dfc31dcd505c` |
| SHA3-384 | `bffdf21b0f8e361499c13f07787f06fde80c30c8ddf80c1aa5e3d46d8cae83760065d84307fd52ed2afb2105a5d3ed91` |
| IMPHASH | `899ad1596f9c6642245b3fb721bae585` |
| TLSH | `T17E34BE63A4BCAA9FDDD82F379C4E880713B66FE4D890603E1C44710EFE2A5095F7A516` |
| SSDEEP | `6144:2GxCfPf0s3KPHfBxR8jPs1F1yD9jvryfL9SqXVdOK:2G60BpL8jk1FGjDc8GVdOK` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_032_10505f03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10505f035b1e6569cb22d42614829e85fd432e014418f457e2e1dfc31dcd505c"
    family = "Prometei"
    file_name = "10505f035b1e6569cb22d42614829e85fd432e014418f457e2e1dfc31dcd505c"
    file_type = "exe"
    first_seen = "2026-08-07 23:24:28"
  condition:
    hash.sha256(0, filesize) == "10505f035b1e6569cb22d42614829e85fd432e014418f457e2e1dfc31dcd505c"
}
```

### Sample 33: `e234be44eeafaf02`

| Field | Value |
|---|---|
| SHA-256 | `e234be44eeafaf0250d9ef2cef198e223264e1541cff78d30a98163c5a7dde67` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-07 22:22:50` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX5.file, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a216558b0c9403010e3682e37bad4b0c` |
| SHA-1 | `50e9dd0c02bc1927862be248b90d3d9bdb0fcc86` |
| SHA-256 | `e234be44eeafaf0250d9ef2cef198e223264e1541cff78d30a98163c5a7dde67` |
| SHA3-384 | `efcaa3c30fb64498aaebb8f70a8012dacb9e765d961cea0cf542ba76171dc01f1656242889942c64fdc56a37c3abf889` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19F1663383CFB502DE073FF716EE8B99ADD9F7633660A645A204503478A12E81EE5253D` |
| SSDEEP | `49152:51d2YWDAZF5tcUoB9D6tzcCyYWCjKHfpmpWAMvZ8jmaL/qRvBQq6:gYF5tcUK6tzc` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_033_e234be44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e234be44eeafaf0250d9ef2cef198e223264e1541cff78d30a98163c5a7dde67"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-07 22:22:50"
  condition:
    hash.sha256(0, filesize) == "e234be44eeafaf0250d9ef2cef198e223264e1541cff78d30a98163c5a7dde67"
}
```

### Sample 34: `7834f2efa3912d96`

| Field | Value |
|---|---|
| SHA-256 | `7834f2efa3912d964764357bbf96752ba2f4ea2712c814664a1bd32ee95616e3` |
| Family label | `unknown` |
| File name | `7834f2efa3912d964764357bbf96752ba2f4ea2712c814664a1bd32ee95616e3.apk` |
| File type | `apk` |
| First seen | `2026-08-07 21:57:30` |
| Reporter | `johnk3r` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `326e607e62c25fb7dee34c95fc404c45` |
| SHA-1 | `5f282b55912913f79c1688efde6fc4a1fb33a490` |
| SHA-256 | `7834f2efa3912d964764357bbf96752ba2f4ea2712c814664a1bd32ee95616e3` |
| SHA3-384 | `e6df4542acf6ac90ca094f739783b5369309ad15986d162f0b62240b85e2eea7c20457a3cfb6aa93d42d72f6f8fb6100` |
| TLSH | `T12976128FEF136EA4D4CD65358CBA2F49BB7D169EA3405B0B43B1E130ADCB6D50069A4C` |
| SSDEEP | `98304:riQTRMN6xgFSJvrTxZ4a4xQoeapcZ6DonUZnq5Ia843faHX:riQTRMN6xgFSJjHd4SDaKZ68UZnqQ4fO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_7834f2ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7834f2efa3912d964764357bbf96752ba2f4ea2712c814664a1bd32ee95616e3"
    family = "unknown"
    file_name = "7834f2efa3912d964764357bbf96752ba2f4ea2712c814664a1bd32ee95616e3.apk"
    file_type = "apk"
    first_seen = "2026-08-07 21:57:30"
  condition:
    hash.sha256(0, filesize) == "7834f2efa3912d964764357bbf96752ba2f4ea2712c814664a1bd32ee95616e3"
}
```

### Sample 35: `ddf8b517a8fed544`

| Field | Value |
|---|---|
| SHA-256 | `ddf8b517a8fed544e1adac815a5d85d4c917717449dd52d1354c03f599f05779` |
| Family label | `unknown` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-08-07 21:52:43` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58a519430128d0e52fc10b3bc7fdb717` |
| SHA-1 | `a4933d27e1f7f7331a3a0ab54d6b53339a412777` |
| SHA-256 | `ddf8b517a8fed544e1adac815a5d85d4c917717449dd52d1354c03f599f05779` |
| SHA3-384 | `ef450c2708cb1671d77ae13e6efdac2dabffe732b9c15dfeea72f93f9c1eb79afcd6df05931d98177c4e3ad9739ec9f3` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16A068C03AC9249F5C0A9B731C8B7425277A5BC489B3237D72EA1BAB82F327C15E35754` |
| SSDEEP | `98304:qbOjLYrCy3QaujOhsqgm9ivYauj9wRp78l5wR1M0Hi1lrD0/BmKVsMVhmYR/A:qFGmYRI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_ddf8b517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddf8b517a8fed544e1adac815a5d85d4c917717449dd52d1354c03f599f05779"
    family = "unknown"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-07 21:52:43"
  condition:
    hash.sha256(0, filesize) == "ddf8b517a8fed544e1adac815a5d85d4c917717449dd52d1354c03f599f05779"
}
```

### Sample 36: `c5125a9712a4bece`

| Field | Value |
|---|---|
| SHA-256 | `c5125a9712a4bece5cc1d53da1914ec5ac7ba147ab37242b03ce488bc2909137` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-07 21:52:29` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9c8477a7011ac3fdc936f8b57ae9344` |
| SHA-1 | `8a7ad515a23953f1dc2eebd140f434e7a61cda9d` |
| SHA-256 | `c5125a9712a4bece5cc1d53da1914ec5ac7ba147ab37242b03ce488bc2909137` |
| SHA3-384 | `6bc046449c0b1db618f7c367b7a1fdcfbf6d739d51692b2689f99824bceb3df611b5aa9a09b1f9e0dba9f1d86958a592` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T123E6334C9AC152BBEAB3817CBDD26094E07C78661362C9EB5BE843651CA74E04D3BB17` |
| SSDEEP | `393216:ubGmCCSCWPWaDSgvk644NL7fXMCHWUjwcuI3/PGTAI:ubGhCSWRuksvXMb8lH/O7` |
| ICON-DHASH | `54f0d4d8c8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_c5125a97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5125a9712a4bece5cc1d53da1914ec5ac7ba147ab37242b03ce488bc2909137"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-07 21:52:29"
  condition:
    hash.sha256(0, filesize) == "c5125a9712a4bece5cc1d53da1914ec5ac7ba147ab37242b03ce488bc2909137"
}
```

### Sample 37: `0f70f67227bd3fe8`

| Field | Value |
|---|---|
| SHA-256 | `0f70f67227bd3fe8f54711e10bb622384b3d4b5df5069ce24e160dddfd235ef1` |
| Family label | `unknown` |
| File name | `main.sh4musl` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:20` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4158820ddb64db53ad3c18f9e5616234` |
| SHA-1 | `f4806a27af4af8cfdcbe573531d282cab7735078` |
| SHA-256 | `0f70f67227bd3fe8f54711e10bb622384b3d4b5df5069ce24e160dddfd235ef1` |
| SHA3-384 | `76a4f288333eea69490152b24eef0cee700c9c36982a1cc581b74b5b8deafc3983fc64c65a5b2a6a186ce3856e2e1c08` |
| TLSH | `T12A537E6AF0DA9CF6DC5088F6E876A1340B013CB123D90C95B95DF2944B3F99A7D8DB60` |
| SSDEEP | `768:vVbDl/r4xAYQDB5HZnWEbDGoUyIE/wIzmzicgc8QElQWalIteJ32CQjWt:ddUxeBWEbD1BIEpuictGaFlT2tC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_0f70f672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f70f67227bd3fe8f54711e10bb622384b3d4b5df5069ce24e160dddfd235ef1"
    family = "unknown"
    file_name = "main.sh4musl"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:20"
  condition:
    hash.sha256(0, filesize) == "0f70f67227bd3fe8f54711e10bb622384b3d4b5df5069ce24e160dddfd235ef1"
}
```

### Sample 38: `3052ea8b43bf40e9`

| Field | Value |
|---|---|
| SHA-256 | `3052ea8b43bf40e9d4060c95523c7e194238d1ad941f5df06d01ee04cbdb2985` |
| Family label | `unknown` |
| File name | `main.sparc64` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:18` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82b77e89caaf3c25b47a82d978cdea84` |
| SHA-1 | `c243e96593606df91ecf10cc60fb387478a111c7` |
| SHA-256 | `3052ea8b43bf40e9d4060c95523c7e194238d1ad941f5df06d01ee04cbdb2985` |
| SHA3-384 | `e6ce34ea68537327bddaa96c3f1a70abc2901be7fce38c90d624a89e6f41c5d0165a4f447ab82c288700ea11c8c027bd` |
| TLSH | `T11525BF5237F61461D74086398FE2E321724ADBB824D54A4B9F508EEFDF072651E82CFA` |
| SSDEEP | `12288:0At/M8JU4OshB0JRDi0FLbCRpKPakyiSUa5g6eyY:d/GrJmvpKVyid` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_3052ea8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3052ea8b43bf40e9d4060c95523c7e194238d1ad941f5df06d01ee04cbdb2985"
    family = "unknown"
    file_name = "main.sparc64"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:18"
  condition:
    hash.sha256(0, filesize) == "3052ea8b43bf40e9d4060c95523c7e194238d1ad941f5df06d01ee04cbdb2985"
}
```

### Sample 39: `932d3d78df3a50c0`

| Field | Value |
|---|---|
| SHA-256 | `932d3d78df3a50c022caecb3a4cce6731e3416ece00ac2a4f596b3335a3930b4` |
| Family label | `unknown` |
| File name | `main.power8` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:16` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1e337556b001a4f75cbf0df6d5a1375` |
| SHA-1 | `bd1bfd055de38f330a492e4331bff62d0573f4ff` |
| SHA-256 | `932d3d78df3a50c022caecb3a4cce6731e3416ece00ac2a4f596b3335a3930b4` |
| SHA3-384 | `22c098e146e3148c64210455a909053e9947bdf3b98bcd86a64d1832c0f7f4f54c9ed6ad1372f2f86869f1877e3aa9fc` |
| TLSH | `T126531A11DF0C6826CD726AB595F72BA1B791B8D01030CD2177053B6F1973A36AC8BF9A` |
| SSDEEP | `1536:KoQUZsWBplZZ6gzvHNtARFHBIrcW4e+TUYrcUYTOTy:KoQQBpBVltaFHBIrcW4JTUYrEQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_932d3d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "932d3d78df3a50c022caecb3a4cce6731e3416ece00ac2a4f596b3335a3930b4"
    family = "unknown"
    file_name = "main.power8"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:16"
  condition:
    hash.sha256(0, filesize) == "932d3d78df3a50c022caecb3a4cce6731e3416ece00ac2a4f596b3335a3930b4"
}
```

### Sample 40: `77581bb0c0240474`

| Field | Value |
|---|---|
| SHA-256 | `77581bb0c0240474d2674a2401faa2d2d0f7f63a5f74713661d40b19b0f265e8` |
| Family label | `unknown` |
| File name | `main.sparcv8` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f5bcfa79ceb4480b77a0ac9615b38a0` |
| SHA-1 | `b0a021cd056b7d773e18863c5afa2ebc1cb58cae` |
| SHA-256 | `77581bb0c0240474d2674a2401faa2d2d0f7f63a5f74713661d40b19b0f265e8` |
| SHA3-384 | `5ceca6d0988be75ed65cf91848dc97240815478e8da83f00b84b5bd284f49fb5146c93e8e1ebecf796d78553d8bb52e2` |
| TLSH | `T10BD308177A270D22F4D14135A2FF43E2BFE583CB25784E97B65209C9AF276A074832B5` |
| SSDEEP | `1536:BNJHcQN8e3BDlsM0E9JR6238UC5t7rk+n5p5L1lPZ:BNJ888Q/sMj9GUWpZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_77581bb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77581bb0c0240474d2674a2401faa2d2d0f7f63a5f74713661d40b19b0f265e8"
    family = "unknown"
    file_name = "main.sparcv8"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:15"
  condition:
    hash.sha256(0, filesize) == "77581bb0c0240474d2674a2401faa2d2d0f7f63a5f74713661d40b19b0f265e8"
}
```

### Sample 41: `84798233fabd3ce3`

| Field | Value |
|---|---|
| SHA-256 | `84798233fabd3ce3ad0fc51625578c42445838385078062cc5e9cfd1efc81c0c` |
| Family label | `unknown` |
| File name | `main.e6500` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:14` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d52075dd350cae4bfab4100c72f92b51` |
| SHA-1 | `c640147077aa344efed1a9a8520d7058e52ba7a4` |
| SHA-256 | `84798233fabd3ce3ad0fc51625578c42445838385078062cc5e9cfd1efc81c0c` |
| SHA3-384 | `b84f2022c5670c837702987c1ff3d5b645a8c5511dcf254b6785dcae0b178a129a1791ed172ba39e87f2ced55e663d61` |
| TLSH | `T18D530A51EF0CA817C9666639A5372FA9F3A0B8D11170CD11B3053B6F16F3632AC87E5A` |
| SSDEEP | `1536:T4pJZ76lYMNn67lUAhvFahOQs/AtgsLShOPMpefoFH:T4pClYnlUAhvF5/Atgnhkgp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_84798233
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84798233fabd3ce3ad0fc51625578c42445838385078062cc5e9cfd1efc81c0c"
    family = "unknown"
    file_name = "main.e6500"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:14"
  condition:
    hash.sha256(0, filesize) == "84798233fabd3ce3ad0fc51625578c42445838385078062cc5e9cfd1efc81c0c"
}
```

### Sample 42: `56d359239b3a9cb3`

| Field | Value |
|---|---|
| SHA-256 | `56d359239b3a9cb3c88ada62cfbb61d0b114f425ce4fbbffefb680918bbcaf50` |
| Family label | `unknown` |
| File name | `main.ppc440fp` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:12` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e167840827da4d204e88a20da0d28554` |
| SHA-1 | `38fa62b116d96182a1f07a0d703901c4c6442ca4` |
| SHA-256 | `56d359239b3a9cb3c88ada62cfbb61d0b114f425ce4fbbffefb680918bbcaf50` |
| SHA3-384 | `77e0011454dec814d71fa3918d749b5930ef7923ad084067e4b2e71504780f38711783446dc1fd2c2073bfd8a55dba41` |
| TLSH | `T14E531A23FB0C0467D8936DB81E3F0BE683159D5220FE901575096EAE1736F31A647BDA` |
| SSDEEP | `768:wDA96Go5/2GpUWTGLShvLvxDFkZmKjrIISHa/5iI3nnr29Hwc+rSKiq:wDA96GypUW6LQv4mKjEIwjknr2Wc+rDv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_56d35923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56d359239b3a9cb3c88ada62cfbb61d0b114f425ce4fbbffefb680918bbcaf50"
    family = "unknown"
    file_name = "main.ppc440fp"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:12"
  condition:
    hash.sha256(0, filesize) == "56d359239b3a9cb3c88ada62cfbb61d0b114f425ce4fbbffefb680918bbcaf50"
}
```

### Sample 43: `6f4cb391752d2a60`

| Field | Value |
|---|---|
| SHA-256 | `6f4cb391752d2a60c5e55a0c4512aad680e71d26b0606a2b43196c63c0170be2` |
| Family label | `unknown` |
| File name | `main.mips32r5el` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:11` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b93d9e06b145dbbcd1adc6ea508953c2` |
| SHA-1 | `66fc428572a1353b166e780ddf755ab3d34782ac` |
| SHA-256 | `6f4cb391752d2a60c5e55a0c4512aad680e71d26b0606a2b43196c63c0170be2` |
| SHA3-384 | `c2794ca65f65f3372bf9124de7db3e52d01cb45096ea77d50c6c691caf1137c483b22dcfa221520f140ca03cfc12d1a3` |
| TLSH | `T1A663F903EE926AF7C45ECD70452DC24A11DE5CBE92E9511B71F8C98CBBBD3194AD3888` |
| SSDEEP | `1536:Vh2RfSKH5r/hSspPXXE1WvtqFc3kJ5snFVCQ8EXb:j+qKH5tXEYFI5sFVC+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_6f4cb391
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f4cb391752d2a60c5e55a0c4512aad680e71d26b0606a2b43196c63c0170be2"
    family = "unknown"
    file_name = "main.mips32r5el"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:11"
  condition:
    hash.sha256(0, filesize) == "6f4cb391752d2a60c5e55a0c4512aad680e71d26b0606a2b43196c63c0170be2"
}
```

### Sample 44: `bddf96d519e14dce`

| Field | Value |
|---|---|
| SHA-256 | `bddf96d519e14dce50aed9c7c539256bddd3888c16da38d2487bfa39596b5ff6` |
| Family label | `unknown` |
| File name | `main.aarch64be` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:09` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3bd623f5f15b65add20b78bf1f40a8e` |
| SHA-1 | `fe1906f8565a87ab3d6dde1d8002cabf4bf3e24e` |
| SHA-256 | `bddf96d519e14dce50aed9c7c539256bddd3888c16da38d2487bfa39596b5ff6` |
| SHA3-384 | `57d63d0fe0e0f1361218e07b3f8625bc0595479095d9bca403d55db7397dc2f0f07e9c7331dd78ec1ee1a8c57a13a41f` |
| TLSH | `T1FA133BBADF0E3941E3D4E339E7590BE1603F7924D35680B73E42B18DC4E99DD8A92246` |
| SSDEEP | `768:lFYcSx5F4pPGTXcafULXTvjIiyjEyGJ1L3vReDT3C3NO0w:lFYbx5yPQcDvfwIJ7s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_bddf96d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bddf96d519e14dce50aed9c7c539256bddd3888c16da38d2487bfa39596b5ff6"
    family = "unknown"
    file_name = "main.aarch64be"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:09"
  condition:
    hash.sha256(0, filesize) == "bddf96d519e14dce50aed9c7c539256bddd3888c16da38d2487bfa39596b5ff6"
}
```

### Sample 45: `83abdb13cedfd71e`

| Field | Value |
|---|---|
| SHA-256 | `83abdb13cedfd71e237b3ecb2ce8d88d0160098a0a3cefd5750c1d3412e69ae3` |
| Family label | `unknown` |
| File name | `main.x86-64-v4` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:07` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dd209e5fe97f7f73676441ad3a0e82b` |
| SHA-1 | `194e99268082cfdb319a58f0994406eaf59acb88` |
| SHA-256 | `83abdb13cedfd71e237b3ecb2ce8d88d0160098a0a3cefd5750c1d3412e69ae3` |
| SHA3-384 | `30f1b861aec5b26b8b80321242f8a5d7522b6c1bd8368669b368becd068e9a26d45375f7c34145ad37772b63e7b99201` |
| TLSH | `T18D23D517B6A3B4BCC34BC0B45A9BD5F1B8317CE402253E3F97C9EA302E359116A59A71` |
| TELFHASH | `t18811a7f149df34e0a2d3e8617369e5719d3a1956015032e092b5fef8ee02f4206b5c37` |
| SSDEEP | `768:FTfm+CmyF+mMEUU7UYBKMaScHw5eYtPwOkMO/Tlj4J:Jfm+C/KS9B3/cQ5eYtPmJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_83abdb13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83abdb13cedfd71e237b3ecb2ce8d88d0160098a0a3cefd5750c1d3412e69ae3"
    family = "unknown"
    file_name = "main.x86-64-v4"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:07"
  condition:
    hash.sha256(0, filesize) == "83abdb13cedfd71e237b3ecb2ce8d88d0160098a0a3cefd5750c1d3412e69ae3"
}
```

### Sample 46: `d08221a100c55996`

| Field | Value |
|---|---|
| SHA-256 | `d08221a100c5599634143212a5ffa574455da350a7773b280e9a74d9d67546dd` |
| Family label | `unknown` |
| File name | `main.x86-64-i7` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:06` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0185a472ab9b3d0782d4c5f7030badfe` |
| SHA-1 | `bee45b0369f2f6f2ba8a6612020add26f4cd3cd8` |
| SHA-256 | `d08221a100c5599634143212a5ffa574455da350a7773b280e9a74d9d67546dd` |
| SHA3-384 | `ccc5e74ebcdf2e0989cc4a0940a297bda350ab415e21f4593032a80d50fd5249eb79fab3318cf220eefd11475909c081` |
| TLSH | `T19323C51BB6A3B07CC24BD0B45A9AC5F1B93178B402213D3FA3C9FA312D35D516A59E72` |
| TELFHASH | `t12211bff14d9e34e0a1d7e8216318e43088390c6251e032f49ab8f9e8de10f820bb6c37` |
| SSDEEP | `768:koZxzHpMepJ85Z1f+57AJh01aoNowMTCJwGXQ3pTiTTljiJ:HxzHqeQxkAJhgamJwGXQ3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_d08221a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d08221a100c5599634143212a5ffa574455da350a7773b280e9a74d9d67546dd"
    family = "unknown"
    file_name = "main.x86-64-i7"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:06"
  condition:
    hash.sha256(0, filesize) == "d08221a100c5599634143212a5ffa574455da350a7773b280e9a74d9d67546dd"
}
```

### Sample 47: `8a9432a29d1dc5ee`

| Field | Value |
|---|---|
| SHA-256 | `8a9432a29d1dc5ee40e7b0381aa03c92d1a299817d780ef8d4259537d2f384af` |
| Family label | `unknown` |
| File name | `main.power8le` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:04` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e940582331226833360d34f1ba6a807` |
| SHA-1 | `85c5361531bd0b28aff461910c2ce8546c639335` |
| SHA-256 | `8a9432a29d1dc5ee40e7b0381aa03c92d1a299817d780ef8d4259537d2f384af` |
| SHA3-384 | `f7c9156ee0ca0b6764b46fe97f171ed410e4237047577770f4986e061f9508cfe8890be0a9ca07e2fa5ce0a5ae722aa9` |
| TLSH | `T1E053A4133348BA9ADF47AC3F95C7BA117392BD94125145A2BB00110FAB77B26CF0EB59` |
| SSDEEP | `768:1VpP4Ch2YYbrtJi4clS+Q6cE9Jn0VJq/fy4balAionhvXY9YUcNi1SrDyHfaa319:6TYa1UamXYKUcNv3yHd1kPVO7SD2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_8a9432a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a9432a29d1dc5ee40e7b0381aa03c92d1a299817d780ef8d4259537d2f384af"
    family = "unknown"
    file_name = "main.power8le"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:04"
  condition:
    hash.sha256(0, filesize) == "8a9432a29d1dc5ee40e7b0381aa03c92d1a299817d780ef8d4259537d2f384af"
}
```

### Sample 48: `4eb8ca26a953e5d5`

| Field | Value |
|---|---|
| SHA-256 | `4eb8ca26a953e5d5f4bb50c7e46c2276410a9c05f17c8df0e5ae9680dee6fa9f` |
| Family label | `unknown` |
| File name | `main.mips64el-n32` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:03` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e675bbacc06129fd8edd3ecbeff318a6` |
| SHA-1 | `c3ce9d72b08db867b4c8b1f5d703f241af1fc4c5` |
| SHA-256 | `4eb8ca26a953e5d5f4bb50c7e46c2276410a9c05f17c8df0e5ae9680dee6fa9f` |
| SHA3-384 | `80d4445acdb0ffa00450dcf8cc387a36ad50eeaf44a3c0033bbe485496192a784db7035479b865dffeb00a73f7dde3c6` |
| TLSH | `T15B63CB49EF41AA7BC09FCF34896E814B04D53DB552E8432E72E8EA8D7B7D25C4BC2944` |
| SSDEEP | `768:9Sf/vc/S2m1aWl5gF5ii2oP+/rAsdpymeq55Cey4m4eMEkoS1Y:Avc/SpaW4F5iiHP+jAs2meOLyBfHk9Y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_4eb8ca26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eb8ca26a953e5d5f4bb50c7e46c2276410a9c05f17c8df0e5ae9680dee6fa9f"
    family = "unknown"
    file_name = "main.mips64el-n32"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:03"
  condition:
    hash.sha256(0, filesize) == "4eb8ca26a953e5d5f4bb50c7e46c2276410a9c05f17c8df0e5ae9680dee6fa9f"
}
```

### Sample 49: `203548104d9582d1`

| Field | Value |
|---|---|
| SHA-256 | `203548104d9582d155e95123af5f8f5bc3a8f07436ba47d318ab6ff0bf11db9f` |
| Family label | `unknown` |
| File name | `main.x86-64-v3` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:02` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16f5c276640ad55736617aa899c00919` |
| SHA-1 | `706471d39c4bb754ded04f5d9dd29f6fd9e75770` |
| SHA-256 | `203548104d9582d155e95123af5f8f5bc3a8f07436ba47d318ab6ff0bf11db9f` |
| SHA3-384 | `1842342255dbe86cbb48cc65321466309e51cc494f67157ef4a46fa8b95791e2165b6e3e2f23af1495e66a8711176181` |
| TLSH | `T1DA23D627B6A3B47CC24BC0785A9AD9F1B8317CE402213E3F97C9FA312D35D116A59A71` |
| TELFHASH | `t19511c4b1089e34d1a3d7e8617368b5319c362856119032e091b8fae8de01f4207b5c37` |
| SSDEEP | `768:vTOu57X4mJtlTqtc4vQVcu9x5jSY9vwO9YolljwJ:bOu5rHTSc7cK5uY9vz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_20354810
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "203548104d9582d155e95123af5f8f5bc3a8f07436ba47d318ab6ff0bf11db9f"
    family = "unknown"
    file_name = "main.x86-64-v3"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:02"
  condition:
    hash.sha256(0, filesize) == "203548104d9582d155e95123af5f8f5bc3a8f07436ba47d318ab6ff0bf11db9f"
}
```

### Sample 50: `1e05be6774dcb4e8`

| Field | Value |
|---|---|
| SHA-256 | `1e05be6774dcb4e877b68d645a328e32a6f061d1198888ce6b370558f2f8c74b` |
| Family label | `unknown` |
| File name | `main.x86-64` |
| File type | `elf` |
| First seen | `2026-08-07 21:25:00` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4369a7773e4e4c40061bba26bf19c8c` |
| SHA-1 | `d4e961231e9e14d872b8b19d466eebcf5a563a08` |
| SHA-256 | `1e05be6774dcb4e877b68d645a328e32a6f061d1198888ce6b370558f2f8c74b` |
| SHA3-384 | `7ff48cedc20a3e08ea40828b481f89ea34b168a113a22a1ae55aa838561680dd9d665f0d82621be260ee8715e1ee7c68` |
| TLSH | `T17B23C516B6A3B07CC24BC0B45A9AD5F1B93178B402213D3FA7C9FA312E35D116B59E72` |
| TELFHASH | `t15f118cf14d9e35e0a2d7e921a758e4309d790c57519032f59ab8b9e8de10f830bb6c37` |
| SSDEEP | `768:wYFrwOKcpJ85Z1f+5uA5h01aoNowG8CJwGXQ3pqiOTljz1J:rEOKcoxdA5hgadJwGXQ3i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_1e05be67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e05be6774dcb4e877b68d645a328e32a6f061d1198888ce6b370558f2f8c74b"
    family = "unknown"
    file_name = "main.x86-64"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:00"
  condition:
    hash.sha256(0, filesize) == "1e05be6774dcb4e877b68d645a328e32a6f061d1198888ce6b370558f2f8c74b"
}
```

### Sample 51: `52eed4374640ea09`

| Field | Value |
|---|---|
| SHA-256 | `52eed4374640ea0926abcd5fd3723f47476225ecda14f6b2d9659ec5ff06b374` |
| Family label | `unknown` |
| File name | `main.x86-core2` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:59` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e22b9d67637ab422225c59aab92f0e7d` |
| SHA-1 | `556d0056c3bb5a441905f5d644391c805427cf9f` |
| SHA-256 | `52eed4374640ea0926abcd5fd3723f47476225ecda14f6b2d9659ec5ff06b374` |
| SHA3-384 | `ea7e8b9210f3b8f5297f70bb01717745a51b9f8e467cc191c62efa5d79f1a30945f0717f0684117e44b5c2ff990de5d1` |
| TLSH | `T1BE231981FA53C1B4E19382F008A7C7EA9634CE37505BE6EAEB4D3921FD317018D9666D` |
| TELFHASH | `t12521d46b5e106dfcf3e0a806c76fa6d38e39d8176b71686b01b02e8137f14a19225c35` |
| SSDEEP | `768:BPLC+X5txkB4zS5QnGMFAg96B/cEGylxPZyuSSgXvcIT:BPLfX5tCwS5QnOgU0yV4cI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_52eed437
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52eed4374640ea0926abcd5fd3723f47476225ecda14f6b2d9659ec5ff06b374"
    family = "unknown"
    file_name = "main.x86-core2"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:59"
  condition:
    hash.sha256(0, filesize) == "52eed4374640ea0926abcd5fd3723f47476225ecda14f6b2d9659ec5ff06b374"
}
```

### Sample 52: `412c7713c1ea7772`

| Field | Value |
|---|---|
| SHA-256 | `412c7713c1ea777268ce5e434c51bb467a3078e331363f3d1f6333c2f45ebbb8` |
| Family label | `unknown` |
| File name | `main.mips32r6el` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:56` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8203eb6a6606da60989a9f54b2e3353c` |
| SHA-1 | `d90591a4274b3d8e8f1f13d17664f3db2cf61994` |
| SHA-256 | `412c7713c1ea777268ce5e434c51bb467a3078e331363f3d1f6333c2f45ebbb8` |
| SHA3-384 | `1ce50a7c379be497e34b20743eb9ecca06d8645c4d14c1108559bc1753d646540b9a727b5dc2cfd85ceaf5eddda855a2` |
| TLSH | `T10463F813EE91B9BBC40B9DB4416EC29214DB6CFEA3E6523A71E4469DAF7C30705C3588` |
| SSDEEP | `768:hPDkC1UXUPTcvJKm0oNG0K3vuZTWh5g9/TxFNSesRlwHrIiJVIJ4X5/ju:NDkCiXUPTcr+0mvuZsqbxOZRl+EiX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_412c7713
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "412c7713c1ea777268ce5e434c51bb467a3078e331363f3d1f6333c2f45ebbb8"
    family = "unknown"
    file_name = "main.mips32r6el"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:56"
  condition:
    hash.sha256(0, filesize) == "412c7713c1ea777268ce5e434c51bb467a3078e331363f3d1f6333c2f45ebbb8"
}
```

### Sample 53: `e52f270af5de9c05`

| Field | Value |
|---|---|
| SHA-256 | `e52f270af5de9c0561b1c6572a2debed721b5c655a4b0589fc4de31ab21eeeac` |
| Family label | `unknown` |
| File name | `main.x86-64-v2` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecb4a5fbd760d74b4cff1b17c42a2a4a` |
| SHA-1 | `2c8c1ece6384bceccc74bc6284183a47560e9c23` |
| SHA-256 | `e52f270af5de9c0561b1c6572a2debed721b5c655a4b0589fc4de31ab21eeeac` |
| SHA3-384 | `b95e7995f7535e132fc9df2671a32528309b13cb927e9842e0d94fb82cc0352f9001246464a61fdac3c1214c0a1b5106` |
| TLSH | `T1AF23C51BB6A3B07CC24BD0B45A9AC5F1B93178B402213D3FA3C9FA312D35D516A59E72` |
| TELFHASH | `t12211bff14d9e34e0a1d7e8216318e43088390c6251e032f49ab8f9e8de10f820bb6c37` |
| SSDEEP | `768:koXxzHpMepJ85Z1f+57AJh01aoNowMTCJwGXQ3pTiTTljiJ:RxzHqeQxkAJhgamJwGXQ3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_e52f270a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e52f270af5de9c0561b1c6572a2debed721b5c655a4b0589fc4de31ab21eeeac"
    family = "unknown"
    file_name = "main.x86-64-v2"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:55"
  condition:
    hash.sha256(0, filesize) == "e52f270af5de9c0561b1c6572a2debed721b5c655a4b0589fc4de31ab21eeeac"
}
```

### Sample 54: `bdfbd1883d34b2ad`

| Field | Value |
|---|---|
| SHA-256 | `bdfbd1883d34b2adae5ee7aac342226be93f09b1e0e0f11c0df7bfee7c24ed40` |
| Family label | `unknown` |
| File name | `main.s390x` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ceee5d336eb8ca141db9a9a100d6a6b` |
| SHA-1 | `30c975d0bc43925a47162b4835800665dcc1cd2b` |
| SHA-256 | `bdfbd1883d34b2adae5ee7aac342226be93f09b1e0e0f11c0df7bfee7c24ed40` |
| SHA3-384 | `5a0641ca842af354b793fd93acef165ebe7add7c9dea64730abd866e7ca9addbab060806457ab89fdc73c0b45938bdbc` |
| TLSH | `T152333B8791B4D5AAC470BB37E557FBF68396BDF884D84B1D1C89EB2B58B0B004724D22` |
| SSDEEP | `1536:ZiFD4wE2nUsk1EPEJhe4ZLy3cR8hLK7X2yRSH:ZiFD4wEZBY4ZOu8hLG8H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_bdfbd188
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdfbd1883d34b2adae5ee7aac342226be93f09b1e0e0f11c0df7bfee7c24ed40"
    family = "unknown"
    file_name = "main.s390x"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:54"
  condition:
    hash.sha256(0, filesize) == "bdfbd1883d34b2adae5ee7aac342226be93f09b1e0e0f11c0df7bfee7c24ed40"
}
```

### Sample 55: `84ebfb4b1c8c375e`

| Field | Value |
|---|---|
| SHA-256 | `84ebfb4b1c8c375ed9feb70c75651a4fc49feaa8c4acabd0a39048a0b2f0b4ab` |
| Family label | `unknown` |
| File name | `main.x86-i686` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d38e5cbd1bd843e73feeb6904ccffc4` |
| SHA-1 | `0b38f4794c90bebdea8178bbbb2a67ec1870db73` |
| SHA-256 | `84ebfb4b1c8c375ed9feb70c75651a4fc49feaa8c4acabd0a39048a0b2f0b4ab` |
| SHA3-384 | `1a2d0859ef244461825f7aa58e7a21a636479ca611cbdd2522e737d8215a407bf4c3bc6e4fe90c5a916d4428d70fcd4a` |
| TLSH | `T130230885F653C1B0E18392F008A7C7EA9634DE37505BE6EAEB8E3921FC313418D9656D` |
| TELFHASH | `t1f421d1675d2068ecf3e09546c3afa193ce31d9536b31587b00f02e8237f14a19276e76` |
| SSDEEP | `768:2rL4//mD+rVkX4dMQKGMUAAW6BNcEgxvPSOSSgpKcV:2rLA/mD+CoMQKlA3kPc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_84ebfb4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84ebfb4b1c8c375ed9feb70c75651a4fc49feaa8c4acabd0a39048a0b2f0b4ab"
    family = "unknown"
    file_name = "main.x86-i686"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:52"
  condition:
    hash.sha256(0, filesize) == "84ebfb4b1c8c375ed9feb70c75651a4fc49feaa8c4acabd0a39048a0b2f0b4ab"
}
```

### Sample 56: `1ea36fd1287782a9`

| Field | Value |
|---|---|
| SHA-256 | `1ea36fd1287782a96bc746848356a7993d92f6aac8a5f65112fd0d2b97b551ce` |
| Family label | `unknown` |
| File name | `main.e500mc` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99354009214779d165368905702a27f6` |
| SHA-1 | `9d4fe37c130f7f4a1bb3fc012ea6e3ccc1d21d76` |
| SHA-256 | `1ea36fd1287782a96bc746848356a7993d92f6aac8a5f65112fd0d2b97b551ce` |
| SHA3-384 | `42ed3bbfa73dad82205fba5360a35bf95f3921318c4c90a65a4567a91d4ec6a6f4fa4a9b6653848f0ec19dad2439e3ca` |
| TLSH | `T11353F723FF0C4017D49369380A3B47AEB311BD5160BE9516330A6B6F2776E31A647B9A` |
| SSDEEP | `768:cyUSBMK5b+7cChVOM8HxOGJjv2QwmoJuHGj5en8Y35v7I6zI+kJkN:cyUSBMB7dhsM8H4i16JsD8Y35vTzIpy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_1ea36fd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ea36fd1287782a96bc746848356a7993d92f6aac8a5f65112fd0d2b97b551ce"
    family = "unknown"
    file_name = "main.e500mc"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:50"
  condition:
    hash.sha256(0, filesize) == "1ea36fd1287782a96bc746848356a7993d92f6aac8a5f65112fd0d2b97b551ce"
}
```

### Sample 57: `4d5d94834459317b`

| Field | Value |
|---|---|
| SHA-256 | `4d5d94834459317b9810a6e11789106f1b7e328058bb4f238fb5746f7f290c7c` |
| Family label | `unknown` |
| File name | `main.sh4aeb` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58b2dc6bf10924f6167a734128c25173` |
| SHA-1 | `1616d1772470a526fc11f329c4604708c425c5bd` |
| SHA-256 | `4d5d94834459317b9810a6e11789106f1b7e328058bb4f238fb5746f7f290c7c` |
| SHA3-384 | `6233c40acdff985feff757279ea67970b62fc6fb9a8f82d14ce493fd42aecfe44474b8cd553bb20c05c88465710741f9` |
| TLSH | `T1F0533A12B348FEF2CE903A3060C1D1B0234D1CE217C5A9E6E54CB2A57973617BAAD79D` |
| SSDEEP | `768:21mTkC3qj2h8iCt8X0ZCjhUI/CLoE/qYJYaoOxTBCGizoVMzvGPMzK:4mTvdhlCiX0ZEUI/jE/1JpB6Mezvm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_4d5d9483
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d5d94834459317b9810a6e11789106f1b7e328058bb4f238fb5746f7f290c7c"
    family = "unknown"
    file_name = "main.sh4aeb"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:48"
  condition:
    hash.sha256(0, filesize) == "4d5d94834459317b9810a6e11789106f1b7e328058bb4f238fb5746f7f290c7c"
}
```

### Sample 58: `d26a76e53bb19c14`

| Field | Value |
|---|---|
| SHA-256 | `d26a76e53bb19c1459a4eee5c1a15bb97fc05177b4042666f99b0191a2b86d03` |
| Family label | `unknown` |
| File name | `main.e5500` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49f6d6a73fb26c0f7d912a49fa52d6fd` |
| SHA-1 | `0a2a35affd6e656b6a4c005f199d056e363abd5a` |
| SHA-256 | `d26a76e53bb19c1459a4eee5c1a15bb97fc05177b4042666f99b0191a2b86d03` |
| SHA3-384 | `d498c6ac62e69446de667903fa5fa30e19a4d37c40d5727f5b582b6f28d205603258e24b8bdeee3da407ea2ee1a11d8d` |
| TLSH | `T18C055B12FF4C2517CB0D0671A96A9778F792748381F4C6133B0857AF68D223A1DEBE99` |
| SSDEEP | `24576:re8qZs2mW6+TDq3x8BEueg4wUK5yyTLOi/hjM3/qL9lFKA/Gao2Hcq:re7mW6+TDq3x8BEueg4wUw2i/hjM3/q7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_d26a76e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d26a76e53bb19c1459a4eee5c1a15bb97fc05177b4042666f99b0191a2b86d03"
    family = "unknown"
    file_name = "main.e5500"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:47"
  condition:
    hash.sha256(0, filesize) == "d26a76e53bb19c1459a4eee5c1a15bb97fc05177b4042666f99b0191a2b86d03"
}
```

### Sample 59: `3ae5aaf19ca80419`

| Field | Value |
|---|---|
| SHA-256 | `3ae5aaf19ca804193a1fc773256c7aa0369369c0141ec50251e691c9bd75decc` |
| Family label | `unknown` |
| File name | `main.mips32` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `834f048ac141ba852bdc53501ebb73e1` |
| SHA-1 | `0957f8e8b24edbf2c93e3ac2e9894869aea22336` |
| SHA-256 | `3ae5aaf19ca804193a1fc773256c7aa0369369c0141ec50251e691c9bd75decc` |
| SHA3-384 | `d5839ba0713f6707ac942239adcaee7fb332941783d0beeed47687744c6a151baf7cfa52caae53c05a0081fd32a0a5fd` |
| TLSH | `T11F630A3A7711AFA9C3ACC53009F2CAE58AF51A6329E280853365DB1C6E7150D2C9FDF5` |
| SSDEEP | `1536:SaD9rB93OYau0EYvv+cqVuMEdYioziTN7OiqcYglDW6fb8QnvnnXDM:Ux7Oiq9glDW63nvnTM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_3ae5aaf1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ae5aaf19ca804193a1fc773256c7aa0369369c0141ec50251e691c9bd75decc"
    family = "unknown"
    file_name = "main.mips32"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:45"
  condition:
    hash.sha256(0, filesize) == "3ae5aaf19ca804193a1fc773256c7aa0369369c0141ec50251e691c9bd75decc"
}
```

### Sample 60: `edfac2aacde2c5ad`

| Field | Value |
|---|---|
| SHA-256 | `edfac2aacde2c5ad263d08023383743db8ceab54659ac5cca9d1d39098000bc2` |
| Family label | `unknown` |
| File name | `main.mips64r6el-n32` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b62051833870df91f3d755925545820` |
| SHA-1 | `1585447d8606243699f0e47b792fc668bb8e443c` |
| SHA-256 | `edfac2aacde2c5ad263d08023383743db8ceab54659ac5cca9d1d39098000bc2` |
| SHA3-384 | `a0c66c13b8a617abe6b7d80cc84f10029c40a0ef7f52754699dfdfa9b8f371c0d10a1d94bd5a7e1f2143f5e20d3d7bb3` |
| TLSH | `T1CB63E809AF15BA7BC09E4E7445FFC49204D63DBAA2C4833975E47A9DAF3C25902C3698` |
| SSDEEP | `768:7797wyVjdEnPzvr+vBX6zPQYvkRTGlmFIpv/dB:7ZBV2r84QeEGlx7B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_edfac2aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edfac2aacde2c5ad263d08023383743db8ceab54659ac5cca9d1d39098000bc2"
    family = "unknown"
    file_name = "main.mips64r6el-n32"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:43"
  condition:
    hash.sha256(0, filesize) == "edfac2aacde2c5ad263d08023383743db8ceab54659ac5cca9d1d39098000bc2"
}
```

### Sample 61: `d81610a8d26388e9`

| Field | Value |
|---|---|
| SHA-256 | `d81610a8d26388e9a4b446d5740984990f9ecaae2af7bb3576e02864c4f522cd` |
| Family label | `unknown` |
| File name | `main.m68k-68xxx` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9858aa6ef071b542b3d9727009c108d` |
| SHA-1 | `e58ae2e4ff3d37ab4ee7568f38ae7f20cba13714` |
| SHA-256 | `d81610a8d26388e9a4b446d5740984990f9ecaae2af7bb3576e02864c4f522cd` |
| SHA3-384 | `a1e883b38d897da59518cf1cbea20d80faa47568ac0ce282fd7d78e007b34ed0dbcea133088602e3aec3f5573be1b150` |
| TLSH | `T1DE138C41762EBFDFE0259A3AC116855A7F34AEF0B1839632F1937C22923F1631E5E905` |
| SSDEEP | `768:xHE0kgFa4oDM5xX+6EZfPYQlz1Of387ckETQOne4TOCrZKvyKp:xsgmDp6EdB4fh7rZK6c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_d81610a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d81610a8d26388e9a4b446d5740984990f9ecaae2af7bb3576e02864c4f522cd"
    family = "unknown"
    file_name = "main.m68k-68xxx"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:42"
  condition:
    hash.sha256(0, filesize) == "d81610a8d26388e9a4b446d5740984990f9ecaae2af7bb3576e02864c4f522cd"
}
```

### Sample 62: `9ef2504a2d6fda7c`

| Field | Value |
|---|---|
| SHA-256 | `9ef2504a2d6fda7c83170f620e1cebe67d24ac47239d2bd28df7cd13d2e84f43` |
| Family label | `unknown` |
| File name | `main.mips64-n32` |
| File type | `elf` |
| First seen | `2026-08-07 21:24:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96b5f80af852448a03b5faf666cd4de4` |
| SHA-1 | `13d780707bc8ca94b0654c52793c207b2b702d53` |
| SHA-256 | `9ef2504a2d6fda7c83170f620e1cebe67d24ac47239d2bd28df7cd13d2e84f43` |
| SHA3-384 | `3a13b2fadc4b35be25d0064e357e582867916a366a6e63c18248e55c655a7655a2f24165ebf3238160c129f167087950` |
| TLSH | `T1206318367706AF63CA7D92350FF2CAB9E9E0365118E690487342DB1C6E392686C1DCF5` |
| SSDEEP | `1536:2bMvZFLk6l42BVquclz77enocQCQhP7DI:rKAVqFxnejrQhQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_9ef2504a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ef2504a2d6fda7c83170f620e1cebe67d24ac47239d2bd28df7cd13d2e84f43"
    family = "unknown"
    file_name = "main.mips64-n32"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:41"
  condition:
    hash.sha256(0, filesize) == "9ef2504a2d6fda7c83170f620e1cebe67d24ac47239d2bd28df7cd13d2e84f43"
}
```

### Sample 63: `e1ee2b7aeeb62f06`

| Field | Value |
|---|---|
| SHA-256 | `e1ee2b7aeeb62f063134d78df6e522afde0952eca1701fb8d0835abe18ef16bc` |
| Family label | `WannaCry` |
| File name | `e1ee2b7aeeb62f063134d78df6e522afde0952eca1701fb8d0835abe18ef16bc` |
| File type | `exe` |
| First seen | `2026-08-07 21:15:58` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0d062c4f07188525d9b14c975e871ed` |
| SHA-1 | `8616383a669c0d3ba743bc9f122954257fb28bd9` |
| SHA-256 | `e1ee2b7aeeb62f063134d78df6e522afde0952eca1701fb8d0835abe18ef16bc` |
| SHA3-384 | `df3e480cad1a4c5c4ac107b3073ae6214bfbecef20ef15b96d0d39e1600b359a8c3b371c09f5890b3f385719a1b4568a` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T16536238A31B881FCD1072AB584B78E16F3B37C5E22F95B0F9B40457A1E13755BB60B52` |
| SSDEEP | `49152:jnsntqMSPbcBVQej/1INRx+TSqTFQo6SAAR:DMtqPoBhz1aRxcSUF36SAE` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_063_e1ee2b7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1ee2b7aeeb62f063134d78df6e522afde0952eca1701fb8d0835abe18ef16bc"
    family = "WannaCry"
    file_name = "e1ee2b7aeeb62f063134d78df6e522afde0952eca1701fb8d0835abe18ef16bc"
    file_type = "exe"
    first_seen = "2026-08-07 21:15:58"
  condition:
    hash.sha256(0, filesize) == "e1ee2b7aeeb62f063134d78df6e522afde0952eca1701fb8d0835abe18ef16bc"
}
```

### Sample 64: `d2ece067dae0c692`

| Field | Value |
|---|---|
| SHA-256 | `d2ece067dae0c6921b68ade8a9779b92da96f940437b8e192f9ed89a175fcd62` |
| Family label | `unknown` |
| File name | `update1.zip` |
| File type | `zip` |
| First seen | `2026-08-07 20:53:43` |
| Reporter | `skocherhan` |
| Tags | `192-252-178-228, opendir, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ee33f76b0a2f488b546a19d0cf918f2` |
| SHA-1 | `46499d2aa76f6cf6087d84d6bc0dd8abbb4a10df` |
| SHA-256 | `d2ece067dae0c6921b68ade8a9779b92da96f940437b8e192f9ed89a175fcd62` |
| SHA3-384 | `7a03916823003f609c0d04fff3fe498aeb152e08b6dffa9f72b26027ee9f4b02c1d07b2f75ddc02cd690309be881f467` |
| TLSH | `T180853389BDED61135D26FEA2E0F319E8322385C72CEAFB4070BD8C15D7654E960A7316` |
| SSDEEP | `49152:e0bzvKcRYebVwQ/+0IXhUJ0oD01udiHDNoTJgf:jbrKcVbVQFXhg3DIukhoWf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_d2ece067
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2ece067dae0c6921b68ade8a9779b92da96f940437b8e192f9ed89a175fcd62"
    family = "unknown"
    file_name = "update1.zip"
    file_type = "zip"
    first_seen = "2026-08-07 20:53:43"
  condition:
    hash.sha256(0, filesize) == "d2ece067dae0c6921b68ade8a9779b92da96f940437b8e192f9ed89a175fcd62"
}
```

### Sample 65: `59dbc8aa281e432d`

| Field | Value |
|---|---|
| SHA-256 | `59dbc8aa281e432de685e318cc8e3f318eb58bfc122063c1ab74cfd8d5732f18` |
| Family label | `unknown` |
| File name | `huawei` |
| File type | `sh` |
| First seen | `2026-08-07 20:52:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0bf4392f0b6c2efc7eab197b6392665` |
| SHA-1 | `1ce03cfff28d4350b1b63e6b2caa290ecd3bb5c8` |
| SHA-256 | `59dbc8aa281e432de685e318cc8e3f318eb58bfc122063c1ab74cfd8d5732f18` |
| SHA3-384 | `7921c355285508a22a1935d65a85943995a30b785abce9b3a5980e15fd56d9a59aa11e64b9a45b15206221025db9f418` |
| TLSH | `T1D81194D9A8D64C317F095C2765184CD7B281142B00F51DE5B25DAA236E0C6B96679F33` |
| SSDEEP | `24:qh/tD9jWijWr5jW2Fr7jN/F5haHifMDsxVexUQjjJjCmYDYXmYRYE:qh/d9jpjY5jPnjN/zACfMDqe6g1n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_59dbc8aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59dbc8aa281e432de685e318cc8e3f318eb58bfc122063c1ab74cfd8d5732f18"
    family = "unknown"
    file_name = "huawei"
    file_type = "sh"
    first_seen = "2026-08-07 20:52:39"
  condition:
    hash.sha256(0, filesize) == "59dbc8aa281e432de685e318cc8e3f318eb58bfc122063c1ab74cfd8d5732f18"
}
```

### Sample 66: `cdde719462e36f6a`

| Field | Value |
|---|---|
| SHA-256 | `cdde719462e36f6a902e40859fab9e057acc944a02cc56c43353ab449efe6105` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-07 20:52:37` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11f2b24989b0edce6ffa5113c7e61470` |
| SHA-1 | `8a7cc667b001f6c5e2eb56759ca725c3a1694276` |
| SHA-256 | `cdde719462e36f6a902e40859fab9e057acc944a02cc56c43353ab449efe6105` |
| SHA3-384 | `1bfa71e2c27b7be74d68658de74cbb4f4e7c6e3860acd45058586dd09ea58362e82baed807a57b24cadcadd6c000fded` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F9E6330826D001FEE6B395BCDAD156D4F8B4B46987B0CAAB47DC87785D27090863BB73` |
| SSDEEP | `393216:6GmOGRvrGuf7XU2jACGXMCHWUjVcuI3/PGTAI:6GT+aujhACGXMb8iH/O7` |
| ICON-DHASH | `7071e4d6e6e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_cdde7194
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdde719462e36f6a902e40859fab9e057acc944a02cc56c43353ab449efe6105"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-07 20:52:37"
  condition:
    hash.sha256(0, filesize) == "cdde719462e36f6a902e40859fab9e057acc944a02cc56c43353ab449efe6105"
}
```

### Sample 67: `4c88965c8181ea12`

| Field | Value |
|---|---|
| SHA-256 | `4c88965c8181ea12c34f98eadebbf65f046ab6d428afe94048a497cf65df9bb2` |
| Family label | `unknown` |
| File name | `main.nios2` |
| File type | `elf` |
| First seen | `2026-08-07 20:50:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e51e49773ab2d2f086680afda973bd2` |
| SHA-1 | `39770685a93845ae4ba22809428e435e709077a7` |
| SHA-256 | `4c88965c8181ea12c34f98eadebbf65f046ab6d428afe94048a497cf65df9bb2` |
| SHA3-384 | `4c038a93a33fe329eadd3056f040147b5b0a596ba71db1d5e4e1bf2917811825830fac09b9a24db656583ec1216be026` |
| TLSH | `T1E2C44BD4F2C65D7DF00219321A83DB16D6165FD2E3295BAF892947492C8CBEBCF32168` |
| SSDEEP | `6144:1eJZkHnXRYqvzVsF7qQCFPl0pLAlPSTgS+60tkLZOYWDG+5VQyQp3q3KIO:10o3zWs0d//+6mSZ67Qp3q3pO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_4c88965c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c88965c8181ea12c34f98eadebbf65f046ab6d428afe94048a497cf65df9bb2"
    family = "unknown"
    file_name = "main.nios2"
    file_type = "elf"
    first_seen = "2026-08-07 20:50:45"
  condition:
    hash.sha256(0, filesize) == "4c88965c8181ea12c34f98eadebbf65f046ab6d428afe94048a497cf65df9bb2"
}
```

### Sample 68: `731a24357717027f`

| Field | Value |
|---|---|
| SHA-256 | `731a24357717027f186b142b5efb8b5aea73071245b70ce5883f69f5c8bb13d2` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-08-07 20:50:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c879a354dd67eeb6b4f05d80e2ffa801` |
| SHA-1 | `90ace25a1351470cb8d29ddcd0ad29c4a400bd19` |
| SHA-256 | `731a24357717027f186b142b5efb8b5aea73071245b70ce5883f69f5c8bb13d2` |
| SHA3-384 | `e738ef3a7831154a2f9eee9e4e61fecbc7305f1bae73a811759a76154aa5a584c32ee0da859bcde321c130d1998cfb64` |
| TLSH | `T17501ABCAD154484050AE886C32E76594F430C3CB2A8A4F69FF6CA63D9B98E00B07AF84` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaxjXIjFMmVI5nqK+jRX:e9Qp+Msxj45fIN3+lX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_731a2435
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "731a24357717027f186b142b5efb8b5aea73071245b70ce5883f69f5c8bb13d2"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-07 20:50:44"
  condition:
    hash.sha256(0, filesize) == "731a24357717027f186b142b5efb8b5aea73071245b70ce5883f69f5c8bb13d2"
}
```

### Sample 69: `254412f2ca69b69f`

| Field | Value |
|---|---|
| SHA-256 | `254412f2ca69b69f8b686f874374e2584aaf55ad5c3e8ed6eddfa69f3fe6ea2b` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-07 20:49:55` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11b388e073236318b3851c168aa1abde` |
| SHA-1 | `3b2ce84bea55b35c195a046f40dd838931960270` |
| SHA-256 | `254412f2ca69b69f8b686f874374e2584aaf55ad5c3e8ed6eddfa69f3fe6ea2b` |
| SHA3-384 | `81e6a679fa985f025e296c11a87c9ec5c1820ecd3ca1c39c35ef2b35473c63adaa1723f56453fb99a0111d31fd1bb5c3` |
| IMPHASH | `05dfa411eaf5e24de0f77bb28b01c408` |
| TLSH | `T1A9565B12BB9A55ADC05BC07482464773AB7270CA0B35BAFF419486393F6AAF11F3D358` |
| SSDEEP | `49152:Prkotepov6CNp+cQiHo+kPYKOUJYrMyiGVKoZP1jjGsRH/nEEnm/IMr8XNKCiEfv:gizibmXH/MrgggIxQ2XHInt4Kj9` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_069_254412f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "254412f2ca69b69f8b686f874374e2584aaf55ad5c3e8ed6eddfa69f3fe6ea2b"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-07 20:49:55"
  condition:
    hash.sha256(0, filesize) == "254412f2ca69b69f8b686f874374e2584aaf55ad5c3e8ed6eddfa69f3fe6ea2b"
}
```

### Sample 70: `4e8807b243df0c6a`

| Field | Value |
|---|---|
| SHA-256 | `4e8807b243df0c6a7561061f10e4f8be103a9185d07144442023b7cd4b73767b` |
| Family label | `unknown` |
| File name | `main.archs38` |
| File type | `elf` |
| First seen | `2026-08-07 20:48:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a90711e78958dcac12d55a32af85b4b` |
| SHA-1 | `58e08e085761a9bf36d56ad251d77156beb16f30` |
| SHA-256 | `4e8807b243df0c6a7561061f10e4f8be103a9185d07144442023b7cd4b73767b` |
| SHA3-384 | `a6bd5b4aefcdc857be11639eed70a83babe9b1edb49ff5775deabfad8f7de538c8c8148d9644fca79daa49e307435ca4` |
| TLSH | `T1CBA36C47770B2880F82202F067DDA3E03F1561DBAB361EB7586A62F77F731991D05A92` |
| SSDEEP | `1536:EpU37cBIxUGhOCgZKK8nuekvJhtvbu34jgLuUn5p5M/LW:F7pxUAJgGGJhzgahq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_4e8807b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e8807b243df0c6a7561061f10e4f8be103a9185d07144442023b7cd4b73767b"
    family = "unknown"
    file_name = "main.archs38"
    file_type = "elf"
    first_seen = "2026-08-07 20:48:43"
  condition:
    hash.sha256(0, filesize) == "4e8807b243df0c6a7561061f10e4f8be103a9185d07144442023b7cd4b73767b"
}
```

### Sample 71: `a2710ae2c19298d4`

| Field | Value |
|---|---|
| SHA-256 | `a2710ae2c19298d4f6a362b3a32d17c4f2b0e138c163c3442f350bd5a44fadeb` |
| Family label | `Mirai` |
| File name | `xd.m68k` |
| File type | `elf` |
| First seen | `2026-08-07 20:46:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e58a6434feb1668f6f157fe55e789c6` |
| SHA-1 | `bceabf9508d52c0dada61c967f3bf616cb8f516b` |
| SHA-256 | `a2710ae2c19298d4f6a362b3a32d17c4f2b0e138c163c3442f350bd5a44fadeb` |
| SHA3-384 | `143314fccc89cad71c954b0697d8c2f717ecb7353ef81f1ee87236dbda1ac9b58cc81f05104fab1c31d9ffb8452dd00b` |
| TLSH | `T18FB4C08763093E3EF1F7543E84E64F17AB35A38451832B5B2135F96A69232F43E31686` |
| SSDEEP | `12288:HcOUpdISThsRZ35YHbVFKUkMNBLVLhVo9:HDZmIZJ8H3V0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_a2710ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2710ae2c19298d4f6a362b3a32d17c4f2b0e138c163c3442f350bd5a44fadeb"
    family = "Mirai"
    file_name = "xd.m68k"
    file_type = "elf"
    first_seen = "2026-08-07 20:46:54"
  condition:
    hash.sha256(0, filesize) == "a2710ae2c19298d4f6a362b3a32d17c4f2b0e138c163c3442f350bd5a44fadeb"
}
```

### Sample 72: `09868f351219ae10`

| Field | Value |
|---|---|
| SHA-256 | `09868f351219ae109efb1b40104f888990961a31d63ce88e11f0f976a4220b6b` |
| Family label | `unknown` |
| File name | `main.sparc` |
| File type | `elf` |
| First seen | `2026-08-07 20:46:53` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d754e8b6d7442121afc23e25e6d4e87` |
| SHA-1 | `9b00ccc0f9ef21b7ebab78ca96ce8ce260e6ea02` |
| SHA-256 | `09868f351219ae109efb1b40104f888990961a31d63ce88e11f0f976a4220b6b` |
| SHA3-384 | `a69c7ad3b79363cc268ed4637e514ddfaa836cfee9ef06943973af1f6e4f9e1f6582f015849925717294553c853dbf7d` |
| TLSH | `T1DA23E67727630D23C0D6517592E34336B6FAEB4628B88A577960AED81F485E032633FD` |
| SSDEEP | `768:SxudEJ4tFhMPbQ4pqQ1O+C0lOF3atwl6BO3S:1sQ4pqIFe3atw4BOC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_09868f35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09868f351219ae109efb1b40104f888990961a31d63ce88e11f0f976a4220b6b"
    family = "unknown"
    file_name = "main.sparc"
    file_type = "elf"
    first_seen = "2026-08-07 20:46:53"
  condition:
    hash.sha256(0, filesize) == "09868f351219ae109efb1b40104f888990961a31d63ce88e11f0f976a4220b6b"
}
```

### Sample 73: `467ed1f5cfbbb2bb`

| Field | Value |
|---|---|
| SHA-256 | `467ed1f5cfbbb2bbb6f90f75d1b2bcd99dbeb38a65cc4bcc7bd39767a62d5676` |
| Family label | `CoinMiner` |
| File name | `467ed1f5cfbbb2bbb6f90f75d1b2bcd99dbeb38a65cc4bcc7bd39767a62d5676.exe` |
| File type | `exe` |
| First seen | `2026-08-07 20:45:40` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f89f9431bd97dba2fab3cd2f02d6f10` |
| SHA-1 | `912baf829d387831d0dd450744b5cc0d5496000d` |
| SHA-256 | `467ed1f5cfbbb2bbb6f90f75d1b2bcd99dbeb38a65cc4bcc7bd39767a62d5676` |
| SHA3-384 | `eb91e9fabe353dbe0eadd8cdc1b46a029bff4ddc9e11b3c740b979b0f2504f7c5577d6c6458ba2decec90bb4e9a23f87` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1D746339238CAC1F8E443CBB8865B757DB36E3B5249A43D5F37CD7A009D1AA18647E381` |
| SSDEEP | `98304:2LnzhCZQXR+2V88cf4E+BWG2oLehWT29vlVVKCawyLBMeIMH8o:2TzgZQXR+2V81gnBjP3yVLZ5A8` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_073_467ed1f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "467ed1f5cfbbb2bbb6f90f75d1b2bcd99dbeb38a65cc4bcc7bd39767a62d5676"
    family = "CoinMiner"
    file_name = "467ed1f5cfbbb2bbb6f90f75d1b2bcd99dbeb38a65cc4bcc7bd39767a62d5676.exe"
    file_type = "exe"
    first_seen = "2026-08-07 20:45:40"
  condition:
    hash.sha256(0, filesize) == "467ed1f5cfbbb2bbb6f90f75d1b2bcd99dbeb38a65cc4bcc7bd39767a62d5676"
}
```

### Sample 74: `7e6815495d078bff`

| Field | Value |
|---|---|
| SHA-256 | `7e6815495d078bff962365cd929cdcf8f0c25f24b9de5ee89bebec4af778d76f` |
| Family label | `unknown` |
| File name | `7e6815495d078bff962365cd929cdcf8f0c25f24b9de5ee89bebec4af778d76f.exe` |
| File type | `exe` |
| First seen | `2026-08-07 20:45:34` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed737662652daac313618aff6e994975` |
| SHA-1 | `094e1a1da47df8b7d75e969854cd955b29de5e9b` |
| SHA-256 | `7e6815495d078bff962365cd929cdcf8f0c25f24b9de5ee89bebec4af778d76f` |
| SHA3-384 | `d641f8df8ec38206f4655463cfb8068a6abc98f1a04a0ecf665a5f74622deec3765bbfe1f926df061930c0f31faa0284` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T191D5239928B50EB4D877C7728F43F1BEB0697B854F655D47B78C19408C22AA4AC3B378` |
| SSDEEP | `49152:E0pDIE5NvwSmpma1FtDwTBP2N2/qo8AUwC2heC57UueBAVKtbiF+2sSKDHkYO4cj:E0D5BwL4ajth2/qtXqv1eBASig2TKDHB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_7e681549
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e6815495d078bff962365cd929cdcf8f0c25f24b9de5ee89bebec4af778d76f"
    family = "unknown"
    file_name = "7e6815495d078bff962365cd929cdcf8f0c25f24b9de5ee89bebec4af778d76f.exe"
    file_type = "exe"
    first_seen = "2026-08-07 20:45:34"
  condition:
    hash.sha256(0, filesize) == "7e6815495d078bff962365cd929cdcf8f0c25f24b9de5ee89bebec4af778d76f"
}
```

### Sample 75: `4c05595080efd5b9`

| Field | Value |
|---|---|
| SHA-256 | `4c05595080efd5b9ba7c55f1d8fba88025b4737b905119fd728b7e40c17e89a7` |
| Family label | `unknown` |
| File name | `Error84` |
| File type | `elf` |
| First seen | `2026-08-07 20:42:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bd6bad16df527be7162da5bde59cd48` |
| SHA-1 | `0937c31f7d0ff7344a73b2bb073987f9b3606c91` |
| SHA-256 | `4c05595080efd5b9ba7c55f1d8fba88025b4737b905119fd728b7e40c17e89a7` |
| SHA3-384 | `75954483e717ec823e4092f9a6e4d104cb485375a59793ae13c3315d304ee39d21a3ffafec10c2156778a696f22da72b` |
| TLSH | `T13F365AD5ED1E3841F2C7F2BDDF965BF2702BA6A4D32780F27A924548D1CDAD8C2A1520` |
| SSDEEP | `98304:IB2FSpFA3Hvf+nMwX+CoM/Wdc5Gbz+2Oqb:1SGHvfpdQWdc5Gbz+2Oqb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_4c055950
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c05595080efd5b9ba7c55f1d8fba88025b4737b905119fd728b7e40c17e89a7"
    family = "unknown"
    file_name = "Error84"
    file_type = "elf"
    first_seen = "2026-08-07 20:42:42"
  condition:
    hash.sha256(0, filesize) == "4c05595080efd5b9ba7c55f1d8fba88025b4737b905119fd728b7e40c17e89a7"
}
```

### Sample 76: `86c285b71638c91f`

| Field | Value |
|---|---|
| SHA-256 | `86c285b71638c91f36b35eb40b282f997396f6015d9821a2e446bf677703c8c6` |
| Family label | `unknown` |
| File name | `realtek` |
| File type | `sh` |
| First seen | `2026-08-07 20:42:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c469c6fca01a124a937fd30006b26025` |
| SHA-1 | `5e4e45308c48e6c701418ae90fbafbc6693558e7` |
| SHA-256 | `86c285b71638c91f36b35eb40b282f997396f6015d9821a2e446bf677703c8c6` |
| SHA3-384 | `196723239ce7090612a1072f2b2fc12b445af60f41b1f184325d71f1e3b91ce03cdbd700f1bd1c80b66bb414d6f852e4` |
| TLSH | `T1AC1171E5A8D648326F095C27741C5C97B281042B00F92DD5A25DA9636E0CAB96679F33` |
| SSDEEP | `24:aotD9jWijWr5jW2Fr7jN/F5haHifMDsxVexUQjjJjCmYXmYRYCYJ:aod9jpjY5jPnjN/zACfMDqe6g1f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_86c285b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c285b71638c91f36b35eb40b282f997396f6015d9821a2e446bf677703c8c6"
    family = "unknown"
    file_name = "realtek"
    file_type = "sh"
    first_seen = "2026-08-07 20:42:40"
  condition:
    hash.sha256(0, filesize) == "86c285b71638c91f36b35eb40b282f997396f6015d9821a2e446bf677703c8c6"
}
```

### Sample 77: `f2e2ffc024ab99eb`

| Field | Value |
|---|---|
| SHA-256 | `f2e2ffc024ab99eb49fa207756481aa80713398142f30888aebace5706909b36` |
| Family label | `unknown` |
| File name | `twget.sh` |
| File type | `sh` |
| First seen | `2026-08-07 20:40:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e47fdbb60152c2dc8d364d6dfb8df4fc` |
| SHA-1 | `40e2278c49d112b0037d97f8819bc49e91898901` |
| SHA-256 | `f2e2ffc024ab99eb49fa207756481aa80713398142f30888aebace5706909b36` |
| SHA3-384 | `887926bf4871f8a85b7d70895368088a0e490045cda9fc9c8ff1c5c467f391e137003dfc64873e19af8a6f0e5dc226dd` |
| TLSH | `T1500167CC41611971CC82CDEAB663DD7554C4EDC42BD14E5CAECC24B1908CDD5F961F98` |
| SSDEEP | `12:my+KWK4GqYEeREe5vEebmEevEeRI3vEeL:mjbHiE8EOE6mE6E4I3vEk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_f2e2ffc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2e2ffc024ab99eb49fa207756481aa80713398142f30888aebace5706909b36"
    family = "unknown"
    file_name = "twget.sh"
    file_type = "sh"
    first_seen = "2026-08-07 20:40:48"
  condition:
    hash.sha256(0, filesize) == "f2e2ffc024ab99eb49fa207756481aa80713398142f30888aebace5706909b36"
}
```

### Sample 78: `17d3d77a919c0f84`

| Field | Value |
|---|---|
| SHA-256 | `17d3d77a919c0f84bdbbb8c4796d0ef2169fc11511adf33a1e179b9a816769ce` |
| Family label | `unknown` |
| File name | `main.arm7` |
| File type | `elf` |
| First seen | `2026-08-07 20:38:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16c66bd6d43b9f74158f77d9744a2760` |
| SHA-1 | `2c581ef08b6f160c7af7f9e55a6137e20cadb192` |
| SHA-256 | `17d3d77a919c0f84bdbbb8c4796d0ef2169fc11511adf33a1e179b9a816769ce` |
| SHA3-384 | `23a7fd44e98f2fb9def302ffd0594982f300b142e2a45be208916b9e3767c98a654715602eba4482c28c108b570f1e37` |
| TLSH | `T14333D645EA41AB05D5E232FAFB8E414D3317AFA8E3F9312199306F9013C6ADB0B76525` |
| SSDEEP | `1536:dNnv9qKqvYiSrdwotXAGfflUyGAig4zurEy:v9qhSrdwotXoq4zMEy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_17d3d77a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17d3d77a919c0f84bdbbb8c4796d0ef2169fc11511adf33a1e179b9a816769ce"
    family = "unknown"
    file_name = "main.arm7"
    file_type = "elf"
    first_seen = "2026-08-07 20:38:46"
  condition:
    hash.sha256(0, filesize) == "17d3d77a919c0f84bdbbb8c4796d0ef2169fc11511adf33a1e179b9a816769ce"
}
```

### Sample 79: `ce6877673a5562fd`

| Field | Value |
|---|---|
| SHA-256 | `ce6877673a5562fddb23109127fb9534be420e0a3191284c06775b277295fa90` |
| Family label | `unknown` |
| File name | `main.armv4` |
| File type | `elf` |
| First seen | `2026-08-07 20:38:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b7e26afd03bc448bb151204581a390b` |
| SHA-1 | `a99e32b761be01e5c341f6460032ee344b09eb76` |
| SHA-256 | `ce6877673a5562fddb23109127fb9534be420e0a3191284c06775b277295fa90` |
| SHA3-384 | `b28c45a4e91a3d785e4169ab1c03ec4f5257b68035121d3417596e6b076b2c87abb258ea44e2a33fc27deb46a9dd425d` |
| TLSH | `T1A003E882FE1A8607C2C273FBF75D428C7B2A6EA8B7F932155A306FF133865D11526161` |
| TELFHASH | `t1b701bd214d8c0e853bc8441cb03e71260a37e0feb53e2c133a7bd85e5311cf2682086c` |
| SSDEEP | `768:HNp77c3DLaPZRaPyOhaadPbUk/V7FQFGPpLIvQ8DKHBjxD6:H7Af2KhxV4k/QFYLIIVh6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_ce687767
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce6877673a5562fddb23109127fb9534be420e0a3191284c06775b277295fa90"
    family = "unknown"
    file_name = "main.armv4"
    file_type = "elf"
    first_seen = "2026-08-07 20:38:45"
  condition:
    hash.sha256(0, filesize) == "ce6877673a5562fddb23109127fb9534be420e0a3191284c06775b277295fa90"
}
```

### Sample 80: `85e137cce38fd043`

| Field | Value |
|---|---|
| SHA-256 | `85e137cce38fd043ff723f80610d52adae34db5b2a4d528273308225efa0688f` |
| Family label | `unknown` |
| File name | `main.armv7-eabihf` |
| File type | `elf` |
| First seen | `2026-08-07 20:36:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3099419fd31e65cfd1e84f57e4d2ba0` |
| SHA-1 | `182c3222e4fa05bb453d8106acec821b440c9046` |
| SHA-256 | `85e137cce38fd043ff723f80610d52adae34db5b2a4d528273308225efa0688f` |
| SHA3-384 | `0789f8f8ec00e21d1c91019feed78de477d497ea40ac9c29cc1ef1d2ebfbb74dfbb9fa675122ee7cee2ae2a2bedb20a6` |
| TLSH | `T175230998F8449B39CBD475FAF50E43DD33020FA8E6E671118E219B313BB79194A3B952` |
| SSDEEP | `768:e165UO1K+wRsvX3lsWK0kSf+9iGUAl3pZtV96c0YSWfwRJAVLxiyrEx:e165Up+qsvXVsVfSfaiZe3pPVH07ReVF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_85e137cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85e137cce38fd043ff723f80610d52adae34db5b2a4d528273308225efa0688f"
    family = "unknown"
    file_name = "main.armv7-eabihf"
    file_type = "elf"
    first_seen = "2026-08-07 20:36:49"
  condition:
    hash.sha256(0, filesize) == "85e137cce38fd043ff723f80610d52adae34db5b2a4d528273308225efa0688f"
}
```

### Sample 81: `08b2f8080a69d822`

| Field | Value |
|---|---|
| SHA-256 | `08b2f8080a69d822cd030695a824bb12b75949d98e810c620daeca70735da1d7` |
| Family label | `unknown` |
| File name | `tplink.sh` |
| File type | `sh` |
| First seen | `2026-08-07 20:33:14` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b9b86a4c08823ad5e23145ab0f8be11` |
| SHA-1 | `18f5534aa9bd8c62272c5fa600e97f9b56ab8aca` |
| SHA-256 | `08b2f8080a69d822cd030695a824bb12b75949d98e810c620daeca70735da1d7` |
| SHA3-384 | `4c8fb362c1319e60712061b3b5fc68d2db188665fb390ba026d1b0b15542dfa5502e9a374010023ac7a3068d94ef4c3c` |
| TLSH | `T1FE51748E14A0563DA4BFDD9C76F74600E84887E135B23B289EB41C639CC7A34B369E5D` |
| SSDEEP | `48:7aDU1aT8GWAxqcF6EFGOe9GGGVUBSA65Xr8DYXO8GmIHbQjfZbMPf9JSXLcTYleN:7aDU1aAyxpF6EFGOe9GGGVUBSAyr84Oz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_08b2f808
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08b2f8080a69d822cd030695a824bb12b75949d98e810c620daeca70735da1d7"
    family = "unknown"
    file_name = "tplink.sh"
    file_type = "sh"
    first_seen = "2026-08-07 20:33:14"
  condition:
    hash.sha256(0, filesize) == "08b2f8080a69d822cd030695a824bb12b75949d98e810c620daeca70735da1d7"
}
```

### Sample 82: `e3a3ea4778ea5d97`

| Field | Value |
|---|---|
| SHA-256 | `e3a3ea4778ea5d97a92d3ec0924cfae0f21163ca492d1fa776fe065867c9e5ad` |
| Family label | `unknown` |
| File name | `main.i486` |
| File type | `elf` |
| First seen | `2026-08-07 20:31:23` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f4782a82256b175fc934e581e477c12` |
| SHA-1 | `fce12783edbbcff005367f40847013eec471e012` |
| SHA-256 | `e3a3ea4778ea5d97a92d3ec0924cfae0f21163ca492d1fa776fe065867c9e5ad` |
| SHA3-384 | `59bbe16c6ff5b874bc31cbce01c52484bdc0d1fa56344f1b36dff3f5a885a0cda4f084f179e6dc8c99b84b73adb4a836` |
| TLSH | `T1B8C2B603A643C472D50321B152F2DF625930F87FAA268546E77DAFF1EA6A0C0925377E` |
| TELFHASH | `t10b214752be9118e4f2e0ac5f922a5382cf355e73552569db48f177023be23b29261825` |
| SSDEEP | `384:ffD3O/nElk0q4PUuiKDTgCPgQP9oug8/HanjPBlUQiTmN4ZfUB:HDInElkP4oKDTdIKT+FlFXYfU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_e3a3ea47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3a3ea4778ea5d97a92d3ec0924cfae0f21163ca492d1fa776fe065867c9e5ad"
    family = "unknown"
    file_name = "main.i486"
    file_type = "elf"
    first_seen = "2026-08-07 20:31:23"
  condition:
    hash.sha256(0, filesize) == "e3a3ea4778ea5d97a92d3ec0924cfae0f21163ca492d1fa776fe065867c9e5ad"
}
```

### Sample 83: `5efd3f43074c5bb7`

| Field | Value |
|---|---|
| SHA-256 | `5efd3f43074c5bb7b180da4993b5db062bdd099be08b29b8a3d9d2e847fc6fa0` |
| Family label | `unknown` |
| File name | `main.armebv7` |
| File type | `elf` |
| First seen | `2026-08-07 20:31:21` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dde7125d9efe6899fcd683289a73aa3` |
| SHA-1 | `22a8ff8c28dc9b8b7ae55d86a8435d01bbfb7199` |
| SHA-256 | `5efd3f43074c5bb7b180da4993b5db062bdd099be08b29b8a3d9d2e847fc6fa0` |
| SHA3-384 | `acff49a71e031f440c8752ff1763df20b618850ad7eaa2568fa19ede4105619fe1b542d5b2a6a3d7def73b6c99463950` |
| TLSH | `T14323F9D4F844D635CBD075FAF50E83DD73030FA8E6E671119E21AA312BB79094A3B992` |
| SSDEEP | `768:l0m5OXs2geJzHyArNPJWgc5akMWk3IXAxS3hh4gVfUGEAjikwLBt8YvS7o5:l0m5O82BJzHyArNPQ7Yk1k0Ax6KGEAOX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_5efd3f43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5efd3f43074c5bb7b180da4993b5db062bdd099be08b29b8a3d9d2e847fc6fa0"
    family = "unknown"
    file_name = "main.armebv7"
    file_type = "elf"
    first_seen = "2026-08-07 20:31:21"
  condition:
    hash.sha256(0, filesize) == "5efd3f43074c5bb7b180da4993b5db062bdd099be08b29b8a3d9d2e847fc6fa0"
}
```

### Sample 84: `d1bac5d40cd98f05`

| Field | Value |
|---|---|
| SHA-256 | `d1bac5d40cd98f05ef8e605931a4ed9a619171ad8f0cba785560da36c3ca85f9` |
| Family label | `unknown` |
| File name | `sensi.sh` |
| File type | `sh` |
| First seen | `2026-08-07 20:25:12` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `febfddc8add63ac563833c9664d85319` |
| SHA-1 | `206bdbb52545c9426c69ee8da16ea9b2904b53c4` |
| SHA-256 | `d1bac5d40cd98f05ef8e605931a4ed9a619171ad8f0cba785560da36c3ca85f9` |
| SHA3-384 | `a27b2f6600a6810a907b1ce2f708a65ae3e8b1deae9a135b8f02d0d6cea982cbc30fc43ea18e5adfb9a65849fb5fc2e7` |
| TLSH | `T1B11194D9A4D688313F0D5C27641D4CC7B2C1052B00F92DD4B35DA9635E0CAB5557AF33` |
| SSDEEP | `24:HmtD9jWijWr5jW2Fr7jN/F5haHifMDsxVexUQkjJjCDYXmYRYCYJ:Hmd9jpjY5jPnjN/zACfMDqe6B1O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_d1bac5d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1bac5d40cd98f05ef8e605931a4ed9a619171ad8f0cba785560da36c3ca85f9"
    family = "unknown"
    file_name = "sensi.sh"
    file_type = "sh"
    first_seen = "2026-08-07 20:25:12"
  condition:
    hash.sha256(0, filesize) == "d1bac5d40cd98f05ef8e605931a4ed9a619171ad8f0cba785560da36c3ca85f9"
}
```

### Sample 85: `b9cf80a5e63577b0`

| Field | Value |
|---|---|
| SHA-256 | `b9cf80a5e63577b018937534f6219eb29876c2163f0cdad7341acc2deef2859f` |
| Family label | `WannaCry` |
| File name | `b9cf80a5e63577b018937534f6219eb29876c2163f0cdad7341acc2deef2859f` |
| File type | `exe` |
| First seen | `2026-08-07 20:16:34` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6da5f33515b187df3620e7463fab9995` |
| SHA-1 | `02c8512b8bc8cce7e46a4d28ea46250076edef9c` |
| SHA-256 | `b9cf80a5e63577b018937534f6219eb29876c2163f0cdad7341acc2deef2859f` |
| SHA3-384 | `3e707b201161f7a2ee49996acb26d57d4c008ca73dca9ea41456d3b117faa167107b0a08bb7d1e2134af238bbebcde31` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1EC36125A326C80BCC11B6274A4B34E26E7B37C5A227D930F8B5487661E13790BF78B57` |
| SSDEEP | `24576:jbLg8bLguVQhfdmMSirYbcMNgef0QeQjG:jnRnFQqMSPbcBVQej` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_085_b9cf80a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9cf80a5e63577b018937534f6219eb29876c2163f0cdad7341acc2deef2859f"
    family = "WannaCry"
    file_name = "b9cf80a5e63577b018937534f6219eb29876c2163f0cdad7341acc2deef2859f"
    file_type = "exe"
    first_seen = "2026-08-07 20:16:34"
  condition:
    hash.sha256(0, filesize) == "b9cf80a5e63577b018937534f6219eb29876c2163f0cdad7341acc2deef2859f"
}
```

### Sample 86: `7099805ddc064712`

| Field | Value |
|---|---|
| SHA-256 | `7099805ddc0647122cfd66d28fcd68c462e8d1c9fe9869221d6e0fe4129d820e` |
| Family label | `unknown` |
| File name | `main.armv5-eabi` |
| File type | `elf` |
| First seen | `2026-08-07 20:15:17` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89010b4bdd5247e7a182471ff797152e` |
| SHA-1 | `37013ab1071cb60f819a599ee95b4ea7e74d3b94` |
| SHA-256 | `7099805ddc0647122cfd66d28fcd68c462e8d1c9fe9869221d6e0fe4129d820e` |
| SHA3-384 | `2d195393a6c2aa1beed8ef10b5a914f0297b1dda7d20f509751cc7fd7ed2b49461880e828bb9c42fbc5d286b52c3a15b` |
| TLSH | `T10923D694F9409B39C7D074BAF95E42DD33130FA8E2EA31159E216B313BF79194A37A12` |
| SSDEEP | `768:viZXnppnxvdw/z9M7kfpL1ZFWSPGZhTHUD7fhDHOmXBw4AOpOUO9Ok57YUQVaR5/:viZXnppntdw/z9M7kBBZFlevTABXK4A/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_7099805d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7099805ddc0647122cfd66d28fcd68c462e8d1c9fe9869221d6e0fe4129d820e"
    family = "unknown"
    file_name = "main.armv5-eabi"
    file_type = "elf"
    first_seen = "2026-08-07 20:15:17"
  condition:
    hash.sha256(0, filesize) == "7099805ddc0647122cfd66d28fcd68c462e8d1c9fe9869221d6e0fe4129d820e"
}
```

### Sample 87: `d3ab958551ae4b0c`

| Field | Value |
|---|---|
| SHA-256 | `d3ab958551ae4b0c4d3086b00804e00b52c612cd5e19ac28dfb5fa969585d65d` |
| Family label | `Mirai` |
| File name | `main.mipsel` |
| File type | `elf` |
| First seen | `2026-08-07 20:15:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da74e2ccd46fd3bc17ee253b4a45ab48` |
| SHA-1 | `34cd05b7eeca263fb4eed5253bd50d0b0fb8f507` |
| SHA-256 | `d3ab958551ae4b0c4d3086b00804e00b52c612cd5e19ac28dfb5fa969585d65d` |
| SHA3-384 | `af739556ef2a98c41601dea3fa4979fb69663828b9b9a655f92af352f2dcae982acb6688a8ffeb288f7320c81970dbf1` |
| TLSH | `T100435316ABA1DE77DC1FDD7305E8860124CCA49762A92B2B7170CA6CF75B88F09D3C94` |
| SSDEEP | `1536:afGi9vflsdMus5KEd9llnrQUFpVlzIlZj65ApLWg6wKIpjH:aei9vNsdMus5ZJ9rQUjA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_d3ab9585
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3ab958551ae4b0c4d3086b00804e00b52c612cd5e19ac28dfb5fa969585d65d"
    family = "Mirai"
    file_name = "main.mipsel"
    file_type = "elf"
    first_seen = "2026-08-07 20:15:15"
  condition:
    hash.sha256(0, filesize) == "d3ab958551ae4b0c4d3086b00804e00b52c612cd5e19ac28dfb5fa969585d65d"
}
```

### Sample 88: `59caa54df4e941f1`

| Field | Value |
|---|---|
| SHA-256 | `59caa54df4e941f1fa20795b58cc02420c9e4400ba44a178614d330d5bfca79b` |
| Family label | `unknown` |
| File name | `main.xtensa` |
| File type | `elf` |
| First seen | `2026-08-07 20:15:14` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4b3b2fa6c6624e7343bf5d4223dd5c4` |
| SHA-1 | `14c61c80c0e0609074cbaacb27c50c94d6808e24` |
| SHA-256 | `59caa54df4e941f1fa20795b58cc02420c9e4400ba44a178614d330d5bfca79b` |
| SHA3-384 | `5b0fb6cf1c6883fb01f8d9c4b8d7c745a17b4b7f3202c6932ff8a037ad4c9b45ff3dfd83692a3119eeb4b3096c116c79` |
| TLSH | `T1A4C3C4476A16187EF0B203B115DEC6F83E23A2F792B70C16686B1DED5F13E959E060C2` |
| SSDEEP | `1536:wakivttNCmu9I0OU7Pf1tlXMUn5p5M/LWVG65/T8p2UU99yvlWNOz:wakCf5usU77lXMhqVZIp2UUA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_59caa54d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59caa54df4e941f1fa20795b58cc02420c9e4400ba44a178614d330d5bfca79b"
    family = "unknown"
    file_name = "main.xtensa"
    file_type = "elf"
    first_seen = "2026-08-07 20:15:14"
  condition:
    hash.sha256(0, filesize) == "59caa54df4e941f1fa20795b58cc02420c9e4400ba44a178614d330d5bfca79b"
}
```

### Sample 89: `e10e3cb9d4a4cdb0`

| Field | Value |
|---|---|
| SHA-256 | `e10e3cb9d4a4cdb0733eb120a7500996e854b01466d7a42b99414598324f8084` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-07 20:13:18` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96c62dff8336e957434a3277f45b6d16` |
| SHA-1 | `5bc7e23a41af4d7df9456448e4263f2216235ab4` |
| SHA-256 | `e10e3cb9d4a4cdb0733eb120a7500996e854b01466d7a42b99414598324f8084` |
| SHA3-384 | `49faff344bb83d5a3f383c005249fa026463299c8144b06dd7e6ed49e70c2deae24465e0202b4e34b05763e6c54f4da0` |
| TLSH | `T120C27D956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC12F9CD618B1A` |
| SSDEEP | `768:48vCB+25j6es8RL9FYpMSUpi+20qUpi+20YQX:48l25Jdd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_e10e3cb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e10e3cb9d4a4cdb0733eb120a7500996e854b01466d7a42b99414598324f8084"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-07 20:13:18"
  condition:
    hash.sha256(0, filesize) == "e10e3cb9d4a4cdb0733eb120a7500996e854b01466d7a42b99414598324f8084"
}
```

### Sample 90: `1af80d8f770ff150`

| Field | Value |
|---|---|
| SHA-256 | `1af80d8f770ff150a11955a217608d63a7078b5d9852a0929747109ad2cbfbb7` |
| Family label | `unknown` |
| File name | `main.armv4tl` |
| File type | `elf` |
| First seen | `2026-08-07 20:13:17` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `296ef28ce9fa00f6664939354da4d75e` |
| SHA-1 | `4c4cda10c7eeb924adbb2b73f95e1c6d61ba1866` |
| SHA-256 | `1af80d8f770ff150a11955a217608d63a7078b5d9852a0929747109ad2cbfbb7` |
| SHA3-384 | `984e1c0af3cb1f46385eacc3823a1e49d5637efc8c8ffed89416000a7ff5ac350d4c938ba0b5348ea0614075c0d1fe4e` |
| TLSH | `T1D4030A42EA519B09C6D232BEFB8E414E37176F78E7ED32359A306FE013825E70939525` |
| SSDEEP | `768:yGntfD+gTFvggM749NLD1m3AJWMP/SiNBhYYwD9yaVdz/2:yGntfD+gTFvhM74jMQ0MCiNB2YwDX/2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_1af80d8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1af80d8f770ff150a11955a217608d63a7078b5d9852a0929747109ad2cbfbb7"
    family = "unknown"
    file_name = "main.armv4tl"
    file_type = "elf"
    first_seen = "2026-08-07 20:13:17"
  condition:
    hash.sha256(0, filesize) == "1af80d8f770ff150a11955a217608d63a7078b5d9852a0929747109ad2cbfbb7"
}
```

### Sample 91: `61ba1a0e43e061fc`

| Field | Value |
|---|---|
| SHA-256 | `61ba1a0e43e061fc00224e3d2c3f4fcb269b7830eb7dff8059e12b69de42c4eb` |
| Family label | `unknown` |
| File name | `main.armv6-eabihf` |
| File type | `elf` |
| First seen | `2026-08-07 20:11:23` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdfba871c0eae3a5d2796130351e3839` |
| SHA-1 | `557ccf65d13b4c77490e75890385d91a2083b74c` |
| SHA-256 | `61ba1a0e43e061fc00224e3d2c3f4fcb269b7830eb7dff8059e12b69de42c4eb` |
| SHA3-384 | `448d9c62813ec273b4fe7cd9b4f9458f8438a0e212c4a4eea58821545fe526b5574c3ab834e1fc4c53c8039da3156ac2` |
| TLSH | `T1A823F798F944D635CAE071BAF61E02DD33030FBCD2E631159E216A347BB79194E3BA52` |
| SSDEEP | `768:tFpyPbys3IJdXlxnCpA2J5Pjffwz3Pc8O5Q2Kv2a7vmUEbLQ32nRrMP3Sg9Qktlt:tFpyPbys4JdXlxnCpA2J9Df43tOm2Kv+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_61ba1a0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61ba1a0e43e061fc00224e3d2c3f4fcb269b7830eb7dff8059e12b69de42c4eb"
    family = "unknown"
    file_name = "main.armv6-eabihf"
    file_type = "elf"
    first_seen = "2026-08-07 20:11:23"
  condition:
    hash.sha256(0, filesize) == "61ba1a0e43e061fc00224e3d2c3f4fcb269b7830eb7dff8059e12b69de42c4eb"
}
```

### Sample 92: `bb70c62afb7cd5c6`

| Field | Value |
|---|---|
| SHA-256 | `bb70c62afb7cd5c6637680558a40916333a5d785192495620db58fc185f5ac6c` |
| Family label | `unknown` |
| File name | `main.sh4` |
| File type | `elf` |
| First seen | `2026-08-07 20:11:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64dd2a909b0e2f4683f1616e24de6fe1` |
| SHA-1 | `852f3ca9e2b37eb6a7a0a5cc63fad65e435e5ff2` |
| SHA-256 | `bb70c62afb7cd5c6637680558a40916333a5d785192495620db58fc185f5ac6c` |
| SHA3-384 | `3b5aa5a160e242f9a7b766847d31171f80f26353238574b0c0aecde9c28c7d9cd3e04522b284969c676132170e970217` |
| TLSH | `T1B2F22B93C52A9EFAC106B4B195F58E780B267D468B2B0EA9E135CBE0024FDC8F145776` |
| SSDEEP | `384:f5Uf2XgC1KLJYNaR/WgR2NFGgKiNEF2M8aQj2m2sj4XjUHnCCCV9wIurWRPzH/jB:xQ2jIOgUXKiNNzcUHnwV2rKRr71e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_bb70c62a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb70c62afb7cd5c6637680558a40916333a5d785192495620db58fc185f5ac6c"
    family = "unknown"
    file_name = "main.sh4"
    file_type = "elf"
    first_seen = "2026-08-07 20:11:22"
  condition:
    hash.sha256(0, filesize) == "bb70c62afb7cd5c6637680558a40916333a5d785192495620db58fc185f5ac6c"
}
```

### Sample 93: `7a23ed995778d308`

| Field | Value |
|---|---|
| SHA-256 | `7a23ed995778d3080036322c53b859ea91a149c656fe900328b7d5814ff42aa3` |
| Family label | `unknown` |
| File name | `main.armv6` |
| File type | `elf` |
| First seen | `2026-08-07 20:09:21` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94010dd77b300345a17068387030fde3` |
| SHA-1 | `634ddb536d4e9e1df73b6e957d83aff4ad0b4f6e` |
| SHA-256 | `7a23ed995778d3080036322c53b859ea91a149c656fe900328b7d5814ff42aa3` |
| SHA3-384 | `33a0c487ffd8b6628de46b5754d110f06198441cb32de15a0126f2288d74539681e34a675eb2fddc573c9e59ce6a23f2` |
| TLSH | `T197030A42E9519B09C6D232BEFB8E414E37176F78E7ED32359A306FE013825E70939525` |
| SSDEEP | `768:yGnDfD+gTFvggM749NLD1m3AJWMP/SiNBhYYwD9yaVdzR2:yGnDfD+gTFvhM74jMQ0MCiNB2YwDXR2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_7a23ed99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a23ed995778d3080036322c53b859ea91a149c656fe900328b7d5814ff42aa3"
    family = "unknown"
    file_name = "main.armv6"
    file_type = "elf"
    first_seen = "2026-08-07 20:09:21"
  condition:
    hash.sha256(0, filesize) == "7a23ed995778d3080036322c53b859ea91a149c656fe900328b7d5814ff42aa3"
}
```

### Sample 94: `54c38e4fcde2afc3`

| Field | Value |
|---|---|
| SHA-256 | `54c38e4fcde2afc3b93bad341ca08dd475f47eb7a0843aa979e030831f251061` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-07 20:07:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86c49422d7b3ed2598c50899485536fb` |
| SHA-1 | `b3ec8b38b32fd8054bd4206cd424c9e8694395a4` |
| SHA-256 | `54c38e4fcde2afc3b93bad341ca08dd475f47eb7a0843aa979e030831f251061` |
| SHA3-384 | `54a96fa44335c757c4804a30d4e1b6b17f8bb69ee361c9da6c710fdcde852644696bdeda0d514f060acf803223421fa0` |
| TLSH | `T135C329A9F890DE52C6C52676FB4E418C33231778D3DA7105CE249E34F7EB95A0E3A942` |
| SSDEEP | `3072:Is3MwjVxhyC400VIUccYEEUQPOMWG6NwhQBmBkPLfHNwFCmluGf1Dl:I7K4VlccYEEUQPOMWGswwkkPLmV0G95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_54c38e4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54c38e4fcde2afc3b93bad341ca08dd475f47eb7a0843aa979e030831f251061"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-07 20:07:46"
  condition:
    hash.sha256(0, filesize) == "54c38e4fcde2afc3b93bad341ca08dd475f47eb7a0843aa979e030831f251061"
}
```

### Sample 95: `8355b042d1d2e9e3`

| Field | Value |
|---|---|
| SHA-256 | `8355b042d1d2e9e3276091ff1998ba3295304314ae54e5655bc9945693362cdc` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-07 20:07:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa0e91a2b43f3c9b00629d4b9acdfc58` |
| SHA-1 | `1a6f275f6fb4e11bdff8db0d94a4863d36247551` |
| SHA-256 | `8355b042d1d2e9e3276091ff1998ba3295304314ae54e5655bc9945693362cdc` |
| SHA3-384 | `1e830a9643c577a4b762cb6184af4a3d1d6f6193306fcf7c35a73e0432dcfd7704a44741ce475b57ab7c151d399b2db7` |
| TLSH | `T11A43F2424441ACB4FAB02FF8C8248310291FDDB4FF3E7961585B9679AF411977BF46A8` |
| SSDEEP | `1536:rvSjITxfWMovH0oZpsaaaZa7H3K/MlPbuCQfB:7SjmOMQ0oZp4aZaH6EBbTQZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_8355b042
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8355b042d1d2e9e3276091ff1998ba3295304314ae54e5655bc9945693362cdc"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-07 20:07:24"
  condition:
    hash.sha256(0, filesize) == "8355b042d1d2e9e3276091ff1998ba3295304314ae54e5655bc9945693362cdc"
}
```

### Sample 96: `07b1a32c53c1efab`

| Field | Value |
|---|---|
| SHA-256 | `07b1a32c53c1efab24f54151b1158bad7404374f0dfdee558e7ad80ad278575a` |
| Family label | `RemcosRAT` |
| File name | `rcx1.exe` |
| File type | `exe` |
| First seen | `2026-08-07 20:05:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d4fe10deb30092875ad0e5327904cd9` |
| SHA-1 | `bbdbbbaa2596aa7a8a85fa4d4090c4a0387d7d74` |
| SHA-256 | `07b1a32c53c1efab24f54151b1158bad7404374f0dfdee558e7ad80ad278575a` |
| SHA3-384 | `1225d045f7cc75d19063a53d139d8b94ef251a784284500058caee89a3664b0a6cf068923865ee864d0563eeaae18151` |
| IMPHASH | `0cc8e2c6f08a90a370d78009080edfef` |
| TLSH | `T127D47D4AA3A441F4D077C235CA838537E6B2BC056670862F13D74E5B6F273A15F2EB26` |
| SSDEEP | `12288:YZL8K7flZQP2MfAeWoqOKpqs3+Jt6eJcJYYoF5Zr:eQKjlZQuaVWoqVpqsuJt6YcJYY05` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_096_07b1a32c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07b1a32c53c1efab24f54151b1158bad7404374f0dfdee558e7ad80ad278575a"
    family = "RemcosRAT"
    file_name = "rcx1.exe"
    file_type = "exe"
    first_seen = "2026-08-07 20:05:07"
  condition:
    hash.sha256(0, filesize) == "07b1a32c53c1efab24f54151b1158bad7404374f0dfdee558e7ad80ad278575a"
}
```

### Sample 97: `003924f140e5ce4e`

| Field | Value |
|---|---|
| SHA-256 | `003924f140e5ce4ec27ffed10e9927c3a361786a19982dfe538e68dee3e194fe` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-08-07 20:03:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe26ed1c99da5ef20a762d68b769aa54` |
| SHA-1 | `578b0464975e0a183e4db76cd4e88994aab32301` |
| SHA-256 | `003924f140e5ce4ec27ffed10e9927c3a361786a19982dfe538e68dee3e194fe` |
| SHA3-384 | `3aee603ec1bc40fe29323df63ab6f057abcc2fa158b8c5ff88c0f3976dfcf7ccd6329bc1d1e6fba5ddbd90337c035a0b` |
| TLSH | `T141C32A0275A154FCC156C074C77FE927EA31785D13343AAF7B84BA31AE22E365B0AB52` |
| SSDEEP | `3072:KVSRi5S54Aie1G2OAuAfQLuKoshRzLIK7XG4f+m:KVI54uGCQ6KRzt7Xx3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_003924f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "003924f140e5ce4ec27ffed10e9927c3a361786a19982dfe538e68dee3e194fe"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 20:03:39"
  condition:
    hash.sha256(0, filesize) == "003924f140e5ce4ec27ffed10e9927c3a361786a19982dfe538e68dee3e194fe"
}
```

### Sample 98: `6ff2f87766864992`

| Field | Value |
|---|---|
| SHA-256 | `6ff2f877668649928a1a510d79e961e5f13408c729f648bd45cf24f22b011509` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-08-07 20:03:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92c8896539b471d1b16aaa7bbedc204e` |
| SHA-1 | `64d1457ba453305cd8a35b67cee7e84aa586beaf` |
| SHA-256 | `6ff2f877668649928a1a510d79e961e5f13408c729f648bd45cf24f22b011509` |
| SHA3-384 | `4531a8c5821300f8c5ea4178dbb707f283d6f8508db4f3833ee268bac1742f125b9299cf2985ac378f9b2836522c7f2e` |
| TLSH | `T1915302EDD0DB6CDEDC20867904B68198399E1F44F617934C16AB81F3981ED02F85FB86` |
| SSDEEP | `1536:nydummH09WI1OWUSXEkX7P1jCQuCOVvA2O2:nZtZSXE2PFCQudi2O2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_6ff2f877
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ff2f877668649928a1a510d79e961e5f13408c729f648bd45cf24f22b011509"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 20:03:24"
  condition:
    hash.sha256(0, filesize) == "6ff2f877668649928a1a510d79e961e5f13408c729f648bd45cf24f22b011509"
}
```

### Sample 99: `a10a1246b36d37c7`

| Field | Value |
|---|---|
| SHA-256 | `a10a1246b36d37c7b5dc44884584790a291558414f5b965210423a398c113c18` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-07 19:57:13` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97b9e2b3ea8680faf200027db6a17181` |
| SHA-1 | `9eee763b77e4cb8bd32d8df6724d4d4f6c049626` |
| SHA-256 | `a10a1246b36d37c7b5dc44884584790a291558414f5b965210423a398c113c18` |
| SHA3-384 | `225470333416d09042bf9a5d92fb80aaf61ac88a7331468b603e6b57b05f39c96f34c3573686160c90fc8f996e0dd2bc` |
| TLSH | `T1163134DA00241E311543DACE73B73488768EA5EB185FC7D4CC4C5EAA538979CF261B8E` |
| SSDEEP | `24:y8LQYetCtPbrc2bfWfrOtNogDBX+uXmxJ:y8LicpbrjSOnogD0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_a10a1246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a10a1246b36d37c7b5dc44884584790a291558414f5b965210423a398c113c18"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-07 19:57:13"
  condition:
    hash.sha256(0, filesize) == "a10a1246b36d37c7b5dc44884584790a291558414f5b965210423a398c113c18"
}
```

### Sample 100: `2d573ab28d97298b`

| Field | Value |
|---|---|
| SHA-256 | `2d573ab28d97298b53d789d6ffe1ce976d4c32e83d22f85d877cc688013301d1` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-07 19:55:16` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f03d324ae6c499fda8f3142f35c7d1c3` |
| SHA-1 | `5bb1895c14a2304b3998b97d0d3e8bdd9a74816c` |
| SHA-256 | `2d573ab28d97298b53d789d6ffe1ce976d4c32e83d22f85d877cc688013301d1` |
| SHA3-384 | `18898b660ade00865e6e10f99772b2ed8e81d3f41dced58064d107398caa83cf8c8a055ea7cdae7f39574ea21dc9c041` |
| TLSH | `T118C27D956A867C44BEC94A3E4CBD2B1D6DF5C3E1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:vC8vCB+25j6es8Rj9FYpMSUpi+20qUpi+20YQX:K8l25Jld2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_2d573ab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d573ab28d97298b53d789d6ffe1ce976d4c32e83d22f85d877cc688013301d1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-07 19:55:16"
  condition:
    hash.sha256(0, filesize) == "2d573ab28d97298b53d789d6ffe1ce976d4c32e83d22f85d877cc688013301d1"
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
 * Generated: 2026-08-08T02:24:23.323749+00:00
 */

rule MalwareBazaar_unknown_001_0392ae75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0392ae75588dc502f3f3c15fca4b32d9e49baa4e3b2301baaee1a05c7a30e3d5"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-08 02:16:41"
  condition:
    hash.sha256(0, filesize) == "0392ae75588dc502f3f3c15fca4b32d9e49baa4e3b2301baaee1a05c7a30e3d5"
}

rule MalwareBazaar_unknown_002_abde5216
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abde5216ecf909d73c6acc4dec9eaf4e74e423785abe148aa66f867813341f39"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-08 02:01:06"
  condition:
    hash.sha256(0, filesize) == "abde5216ecf909d73c6acc4dec9eaf4e74e423785abe148aa66f867813341f39"
}

rule MalwareBazaar_unknown_003_65b2323a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65b2323aae580d701f621bd5e775271a85938e5e571eecf34ab3804d53156752"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-08 01:36:46"
  condition:
    hash.sha256(0, filesize) == "65b2323aae580d701f621bd5e775271a85938e5e571eecf34ab3804d53156752"
}

rule MalwareBazaar_unknown_004_63ebc5bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63ebc5bb3a36ac820fddc9ccdd48a19bf8fc4b08fa4b5044bdf1027dbdce42e8"
    family = "unknown"
    file_name = "63ebc5bb3a36ac820fddc9ccdd48a19bf8fc4b08fa4b5044bdf1027dbdce42e8"
    file_type = "dll"
    first_seen = "2026-08-08 01:25:11"
  condition:
    hash.sha256(0, filesize) == "63ebc5bb3a36ac820fddc9ccdd48a19bf8fc4b08fa4b5044bdf1027dbdce42e8"
}

rule MalwareBazaar_unknown_005_4575b716
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4575b7164cec44cee5891b3c5ffcc9af663139717c64572e1a0fcef57f8a3c12"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-08 01:24:42"
  condition:
    hash.sha256(0, filesize) == "4575b7164cec44cee5891b3c5ffcc9af663139717c64572e1a0fcef57f8a3c12"
}

rule MalwareBazaar_unknown_006_8743a8f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8743a8f2075c8033558c39f321c306c3497c7d41bc272740d3ad6fc404063efe"
    family = "unknown"
    file_name = "8743a8f2075c8033558c39f321c306c3497c7d41bc272740d3ad6fc404063efe"
    file_type = "dll"
    first_seen = "2026-08-08 01:24:38"
  condition:
    hash.sha256(0, filesize) == "8743a8f2075c8033558c39f321c306c3497c7d41bc272740d3ad6fc404063efe"
}

rule MalwareBazaar_unknown_007_872abdb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "872abdb9f8f06277cd14890d9ba6a392f1caef42d07bf3271f1d5485ac0f12e2"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487476.27219.14846"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:59"
  condition:
    hash.sha256(0, filesize) == "872abdb9f8f06277cd14890d9ba6a392f1caef42d07bf3271f1d5485ac0f12e2"
}

rule MalwareBazaar_unknown_008_fa99ae58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa99ae5885e684bc7d8223a3864f952eac501f79ccaa3badf4daffce168adef7"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487480.8646.13191"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:57"
  condition:
    hash.sha256(0, filesize) == "fa99ae5885e684bc7d8223a3864f952eac501f79ccaa3badf4daffce168adef7"
}

rule MalwareBazaar_unknown_009_9915e6f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9915e6f62c19a7c6622f15bca906b805bb9cde4a5b3e56bbfc586f1ef84a461e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487453.74.4059"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:56"
  condition:
    hash.sha256(0, filesize) == "9915e6f62c19a7c6622f15bca906b805bb9cde4a5b3e56bbfc586f1ef84a461e"
}

rule MalwareBazaar_unknown_010_32c7f6c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32c7f6c4fb71e747151758b54a2cfcf7c03373fcccfbdd4aa48f54d8b9e2077a"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487450.23052.18422"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:55"
  condition:
    hash.sha256(0, filesize) == "32c7f6c4fb71e747151758b54a2cfcf7c03373fcccfbdd4aa48f54d8b9e2077a"
}

rule MalwareBazaar_unknown_011_1324ef0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1324ef0b2345c32e885fe9b14e455f54369ca28ac656949871da8c9ffd427416"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487467.20708.3214"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:53"
  condition:
    hash.sha256(0, filesize) == "1324ef0b2345c32e885fe9b14e455f54369ca28ac656949871da8c9ffd427416"
}

rule MalwareBazaar_unknown_012_70523584
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70523584108df8582ecbc942e0ddf2caa32810c8634d0217fbed663d7563825c"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487481.3064.13601"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:50"
  condition:
    hash.sha256(0, filesize) == "70523584108df8582ecbc942e0ddf2caa32810c8634d0217fbed663d7563825c"
}

rule MalwareBazaar_unknown_013_1d8871ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d8871eca20bb9b4173bc7c6fafe3ee354081ce77832ac7c014f28e3e0d91d78"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487460.10599.10981"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:49"
  condition:
    hash.sha256(0, filesize) == "1d8871eca20bb9b4173bc7c6fafe3ee354081ce77832ac7c014f28e3e0d91d78"
}

rule MalwareBazaar_unknown_014_6ee09649
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee096499b5bf33626de5fc8e21200103fe69825cc33cad951d23b85990f593d"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487488.28323.32157"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:48"
  condition:
    hash.sha256(0, filesize) == "6ee096499b5bf33626de5fc8e21200103fe69825cc33cad951d23b85990f593d"
}

rule MalwareBazaar_unknown_015_ed96fbe0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed96fbe0486a2a17f309608fa7900fa0a8ca7999537084efd5f863ee7ccf5b5f"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487483.10694.24323"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:47"
  condition:
    hash.sha256(0, filesize) == "ed96fbe0486a2a17f309608fa7900fa0a8ca7999537084efd5f863ee7ccf5b5f"
}

rule MalwareBazaar_unknown_016_5526877a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5526877a74df083601ea0141b7ad632420535197faff34b3854e7c74407bde09"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487490.20116.20536"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:45"
  condition:
    hash.sha256(0, filesize) == "5526877a74df083601ea0141b7ad632420535197faff34b3854e7c74407bde09"
}

rule MalwareBazaar_unknown_017_4536e539
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4536e5392385b70cde63388193086d9034c687b0530702634f88c943a888b5ef"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.39487491.12968.2034"
    file_type = "elf"
    first_seen = "2026-08-08 01:18:44"
  condition:
    hash.sha256(0, filesize) == "4536e5392385b70cde63388193086d9034c687b0530702634f88c943a888b5ef"
}

rule MalwareBazaar_Mirai_018_310dc2fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310dc2fc8724899d5d2e1a2c2d8516c3585304a481109eeeacef24d51d689d57"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:52"
  condition:
    hash.sha256(0, filesize) == "310dc2fc8724899d5d2e1a2c2d8516c3585304a481109eeeacef24d51d689d57"
}

rule MalwareBazaar_Mirai_019_f6aefcfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6aefcfa94b8339ca4c2358a3f316647ae1e2d10d9e528e75b57f58bc2878889"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:49"
  condition:
    hash.sha256(0, filesize) == "f6aefcfa94b8339ca4c2358a3f316647ae1e2d10d9e528e75b57f58bc2878889"
}

rule MalwareBazaar_Mirai_020_96b57aef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96b57aef07bb0c43a540f0fd16284e7d6d67d2530fea2c9134bd34b1230d6d0d"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:48"
  condition:
    hash.sha256(0, filesize) == "96b57aef07bb0c43a540f0fd16284e7d6d67d2530fea2c9134bd34b1230d6d0d"
}

rule MalwareBazaar_Mirai_021_1b8c1267
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b8c1267dcab40e4f24090f24dca941a16cce9328c810d4a0ec2b8ba907cb6e5"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:47"
  condition:
    hash.sha256(0, filesize) == "1b8c1267dcab40e4f24090f24dca941a16cce9328c810d4a0ec2b8ba907cb6e5"
}

rule MalwareBazaar_unknown_022_7bbb3ebe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bbb3ebef9e0d6651fae88c088ae0c4245bae265991baca2585740e60e2f55fe"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-08 01:12:45"
  condition:
    hash.sha256(0, filesize) == "7bbb3ebef9e0d6651fae88c088ae0c4245bae265991baca2585740e60e2f55fe"
}

rule MalwareBazaar_Mirai_023_1ca16bc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ca16bc34b14b276183cee1f95e26759c5aa6c5136c7082a3b1e4503838cc4f5"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:44"
  condition:
    hash.sha256(0, filesize) == "1ca16bc34b14b276183cee1f95e26759c5aa6c5136c7082a3b1e4503838cc4f5"
}

rule MalwareBazaar_Mirai_024_389e175e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "389e175ec8c0e4295620e2e56ed431ee6e19702bd10bc087c210473206c5d2ef"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:43"
  condition:
    hash.sha256(0, filesize) == "389e175ec8c0e4295620e2e56ed431ee6e19702bd10bc087c210473206c5d2ef"
}

rule MalwareBazaar_Mirai_025_ce1358a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce1358a99e19d0f421c959f66e4b89c12cf13180f4bd3dac2a070e5dd290130b"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-08 01:12:42"
  condition:
    hash.sha256(0, filesize) == "ce1358a99e19d0f421c959f66e4b89c12cf13180f4bd3dac2a070e5dd290130b"
}

rule MalwareBazaar_unknown_026_b88ffb50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b88ffb509409384a8190be6d022df92f537a5d3ce728efa2e4ab18ae7e76f5d5"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-08 01:04:42"
  condition:
    hash.sha256(0, filesize) == "b88ffb509409384a8190be6d022df92f537a5d3ce728efa2e4ab18ae7e76f5d5"
}

rule MalwareBazaar_Mirai_027_4eecc63d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eecc63d8e969003394c69f1c47c8afb253071935e13bfcf23eebda3184269e0"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-08-08 01:02:48"
  condition:
    hash.sha256(0, filesize) == "4eecc63d8e969003394c69f1c47c8afb253071935e13bfcf23eebda3184269e0"
}

rule MalwareBazaar_Mirai_028_7a53cf03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a53cf03464fb5ed8a6bf0eeb905cc1dfd655626fe42980008e7897ac70847c0"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-08-08 01:02:47"
  condition:
    hash.sha256(0, filesize) == "7a53cf03464fb5ed8a6bf0eeb905cc1dfd655626fe42980008e7897ac70847c0"
}

rule MalwareBazaar_NanoCore_029_60a779d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60a779d7f51d106e4a8d14e6fe987ca6b7ec4b6c7942c665bb6653a0dae0fc4d"
    family = "NanoCore"
    file_name = "9209C4F81950DA9422311103C970CB42.exe"
    file_type = "exe"
    first_seen = "2026-08-08 00:55:05"
  condition:
    hash.sha256(0, filesize) == "60a779d7f51d106e4a8d14e6fe987ca6b7ec4b6c7942c665bb6653a0dae0fc4d"
}

rule MalwareBazaar_unknown_030_604540e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "604540e8f61d04ed0bde2678ace8d1d9a43461e0a2b8533d371891d6bf4089a2"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-07 23:52:34"
  condition:
    hash.sha256(0, filesize) == "604540e8f61d04ed0bde2678ace8d1d9a43461e0a2b8533d371891d6bf4089a2"
}

rule MalwareBazaar_Prometei_031_3119fd79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3119fd7988607b0c3a5eb5256ee942d5c711d1141e831742f433d8f58d56b900"
    family = "Prometei"
    file_name = "3119fd7988607b0c3a5eb5256ee942d5c711d1141e831742f433d8f58d56b900"
    file_type = "elf"
    first_seen = "2026-08-07 23:24:56"
  condition:
    hash.sha256(0, filesize) == "3119fd7988607b0c3a5eb5256ee942d5c711d1141e831742f433d8f58d56b900"
}

rule MalwareBazaar_Prometei_032_10505f03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10505f035b1e6569cb22d42614829e85fd432e014418f457e2e1dfc31dcd505c"
    family = "Prometei"
    file_name = "10505f035b1e6569cb22d42614829e85fd432e014418f457e2e1dfc31dcd505c"
    file_type = "exe"
    first_seen = "2026-08-07 23:24:28"
  condition:
    hash.sha256(0, filesize) == "10505f035b1e6569cb22d42614829e85fd432e014418f457e2e1dfc31dcd505c"
}

rule MalwareBazaar_RemusStealer_033_e234be44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e234be44eeafaf0250d9ef2cef198e223264e1541cff78d30a98163c5a7dde67"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-07 22:22:50"
  condition:
    hash.sha256(0, filesize) == "e234be44eeafaf0250d9ef2cef198e223264e1541cff78d30a98163c5a7dde67"
}

rule MalwareBazaar_unknown_034_7834f2ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7834f2efa3912d964764357bbf96752ba2f4ea2712c814664a1bd32ee95616e3"
    family = "unknown"
    file_name = "7834f2efa3912d964764357bbf96752ba2f4ea2712c814664a1bd32ee95616e3.apk"
    file_type = "apk"
    first_seen = "2026-08-07 21:57:30"
  condition:
    hash.sha256(0, filesize) == "7834f2efa3912d964764357bbf96752ba2f4ea2712c814664a1bd32ee95616e3"
}

rule MalwareBazaar_unknown_035_ddf8b517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddf8b517a8fed544e1adac815a5d85d4c917717449dd52d1354c03f599f05779"
    family = "unknown"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-07 21:52:43"
  condition:
    hash.sha256(0, filesize) == "ddf8b517a8fed544e1adac815a5d85d4c917717449dd52d1354c03f599f05779"
}

rule MalwareBazaar_unknown_036_c5125a97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5125a9712a4bece5cc1d53da1914ec5ac7ba147ab37242b03ce488bc2909137"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-07 21:52:29"
  condition:
    hash.sha256(0, filesize) == "c5125a9712a4bece5cc1d53da1914ec5ac7ba147ab37242b03ce488bc2909137"
}

rule MalwareBazaar_unknown_037_0f70f672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f70f67227bd3fe8f54711e10bb622384b3d4b5df5069ce24e160dddfd235ef1"
    family = "unknown"
    file_name = "main.sh4musl"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:20"
  condition:
    hash.sha256(0, filesize) == "0f70f67227bd3fe8f54711e10bb622384b3d4b5df5069ce24e160dddfd235ef1"
}

rule MalwareBazaar_unknown_038_3052ea8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3052ea8b43bf40e9d4060c95523c7e194238d1ad941f5df06d01ee04cbdb2985"
    family = "unknown"
    file_name = "main.sparc64"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:18"
  condition:
    hash.sha256(0, filesize) == "3052ea8b43bf40e9d4060c95523c7e194238d1ad941f5df06d01ee04cbdb2985"
}

rule MalwareBazaar_unknown_039_932d3d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "932d3d78df3a50c022caecb3a4cce6731e3416ece00ac2a4f596b3335a3930b4"
    family = "unknown"
    file_name = "main.power8"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:16"
  condition:
    hash.sha256(0, filesize) == "932d3d78df3a50c022caecb3a4cce6731e3416ece00ac2a4f596b3335a3930b4"
}

rule MalwareBazaar_unknown_040_77581bb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77581bb0c0240474d2674a2401faa2d2d0f7f63a5f74713661d40b19b0f265e8"
    family = "unknown"
    file_name = "main.sparcv8"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:15"
  condition:
    hash.sha256(0, filesize) == "77581bb0c0240474d2674a2401faa2d2d0f7f63a5f74713661d40b19b0f265e8"
}

rule MalwareBazaar_unknown_041_84798233
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84798233fabd3ce3ad0fc51625578c42445838385078062cc5e9cfd1efc81c0c"
    family = "unknown"
    file_name = "main.e6500"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:14"
  condition:
    hash.sha256(0, filesize) == "84798233fabd3ce3ad0fc51625578c42445838385078062cc5e9cfd1efc81c0c"
}

rule MalwareBazaar_unknown_042_56d35923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56d359239b3a9cb3c88ada62cfbb61d0b114f425ce4fbbffefb680918bbcaf50"
    family = "unknown"
    file_name = "main.ppc440fp"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:12"
  condition:
    hash.sha256(0, filesize) == "56d359239b3a9cb3c88ada62cfbb61d0b114f425ce4fbbffefb680918bbcaf50"
}

rule MalwareBazaar_unknown_043_6f4cb391
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f4cb391752d2a60c5e55a0c4512aad680e71d26b0606a2b43196c63c0170be2"
    family = "unknown"
    file_name = "main.mips32r5el"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:11"
  condition:
    hash.sha256(0, filesize) == "6f4cb391752d2a60c5e55a0c4512aad680e71d26b0606a2b43196c63c0170be2"
}

rule MalwareBazaar_unknown_044_bddf96d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bddf96d519e14dce50aed9c7c539256bddd3888c16da38d2487bfa39596b5ff6"
    family = "unknown"
    file_name = "main.aarch64be"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:09"
  condition:
    hash.sha256(0, filesize) == "bddf96d519e14dce50aed9c7c539256bddd3888c16da38d2487bfa39596b5ff6"
}

rule MalwareBazaar_unknown_045_83abdb13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83abdb13cedfd71e237b3ecb2ce8d88d0160098a0a3cefd5750c1d3412e69ae3"
    family = "unknown"
    file_name = "main.x86-64-v4"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:07"
  condition:
    hash.sha256(0, filesize) == "83abdb13cedfd71e237b3ecb2ce8d88d0160098a0a3cefd5750c1d3412e69ae3"
}

rule MalwareBazaar_unknown_046_d08221a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d08221a100c5599634143212a5ffa574455da350a7773b280e9a74d9d67546dd"
    family = "unknown"
    file_name = "main.x86-64-i7"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:06"
  condition:
    hash.sha256(0, filesize) == "d08221a100c5599634143212a5ffa574455da350a7773b280e9a74d9d67546dd"
}

rule MalwareBazaar_unknown_047_8a9432a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a9432a29d1dc5ee40e7b0381aa03c92d1a299817d780ef8d4259537d2f384af"
    family = "unknown"
    file_name = "main.power8le"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:04"
  condition:
    hash.sha256(0, filesize) == "8a9432a29d1dc5ee40e7b0381aa03c92d1a299817d780ef8d4259537d2f384af"
}

rule MalwareBazaar_unknown_048_4eb8ca26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eb8ca26a953e5d5f4bb50c7e46c2276410a9c05f17c8df0e5ae9680dee6fa9f"
    family = "unknown"
    file_name = "main.mips64el-n32"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:03"
  condition:
    hash.sha256(0, filesize) == "4eb8ca26a953e5d5f4bb50c7e46c2276410a9c05f17c8df0e5ae9680dee6fa9f"
}

rule MalwareBazaar_unknown_049_20354810
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "203548104d9582d155e95123af5f8f5bc3a8f07436ba47d318ab6ff0bf11db9f"
    family = "unknown"
    file_name = "main.x86-64-v3"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:02"
  condition:
    hash.sha256(0, filesize) == "203548104d9582d155e95123af5f8f5bc3a8f07436ba47d318ab6ff0bf11db9f"
}

rule MalwareBazaar_unknown_050_1e05be67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e05be6774dcb4e877b68d645a328e32a6f061d1198888ce6b370558f2f8c74b"
    family = "unknown"
    file_name = "main.x86-64"
    file_type = "elf"
    first_seen = "2026-08-07 21:25:00"
  condition:
    hash.sha256(0, filesize) == "1e05be6774dcb4e877b68d645a328e32a6f061d1198888ce6b370558f2f8c74b"
}

rule MalwareBazaar_unknown_051_52eed437
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52eed4374640ea0926abcd5fd3723f47476225ecda14f6b2d9659ec5ff06b374"
    family = "unknown"
    file_name = "main.x86-core2"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:59"
  condition:
    hash.sha256(0, filesize) == "52eed4374640ea0926abcd5fd3723f47476225ecda14f6b2d9659ec5ff06b374"
}

rule MalwareBazaar_unknown_052_412c7713
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "412c7713c1ea777268ce5e434c51bb467a3078e331363f3d1f6333c2f45ebbb8"
    family = "unknown"
    file_name = "main.mips32r6el"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:56"
  condition:
    hash.sha256(0, filesize) == "412c7713c1ea777268ce5e434c51bb467a3078e331363f3d1f6333c2f45ebbb8"
}

rule MalwareBazaar_unknown_053_e52f270a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e52f270af5de9c0561b1c6572a2debed721b5c655a4b0589fc4de31ab21eeeac"
    family = "unknown"
    file_name = "main.x86-64-v2"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:55"
  condition:
    hash.sha256(0, filesize) == "e52f270af5de9c0561b1c6572a2debed721b5c655a4b0589fc4de31ab21eeeac"
}

rule MalwareBazaar_unknown_054_bdfbd188
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdfbd1883d34b2adae5ee7aac342226be93f09b1e0e0f11c0df7bfee7c24ed40"
    family = "unknown"
    file_name = "main.s390x"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:54"
  condition:
    hash.sha256(0, filesize) == "bdfbd1883d34b2adae5ee7aac342226be93f09b1e0e0f11c0df7bfee7c24ed40"
}

rule MalwareBazaar_unknown_055_84ebfb4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84ebfb4b1c8c375ed9feb70c75651a4fc49feaa8c4acabd0a39048a0b2f0b4ab"
    family = "unknown"
    file_name = "main.x86-i686"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:52"
  condition:
    hash.sha256(0, filesize) == "84ebfb4b1c8c375ed9feb70c75651a4fc49feaa8c4acabd0a39048a0b2f0b4ab"
}

rule MalwareBazaar_unknown_056_1ea36fd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ea36fd1287782a96bc746848356a7993d92f6aac8a5f65112fd0d2b97b551ce"
    family = "unknown"
    file_name = "main.e500mc"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:50"
  condition:
    hash.sha256(0, filesize) == "1ea36fd1287782a96bc746848356a7993d92f6aac8a5f65112fd0d2b97b551ce"
}

rule MalwareBazaar_unknown_057_4d5d9483
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d5d94834459317b9810a6e11789106f1b7e328058bb4f238fb5746f7f290c7c"
    family = "unknown"
    file_name = "main.sh4aeb"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:48"
  condition:
    hash.sha256(0, filesize) == "4d5d94834459317b9810a6e11789106f1b7e328058bb4f238fb5746f7f290c7c"
}

rule MalwareBazaar_unknown_058_d26a76e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d26a76e53bb19c1459a4eee5c1a15bb97fc05177b4042666f99b0191a2b86d03"
    family = "unknown"
    file_name = "main.e5500"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:47"
  condition:
    hash.sha256(0, filesize) == "d26a76e53bb19c1459a4eee5c1a15bb97fc05177b4042666f99b0191a2b86d03"
}

rule MalwareBazaar_unknown_059_3ae5aaf1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ae5aaf19ca804193a1fc773256c7aa0369369c0141ec50251e691c9bd75decc"
    family = "unknown"
    file_name = "main.mips32"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:45"
  condition:
    hash.sha256(0, filesize) == "3ae5aaf19ca804193a1fc773256c7aa0369369c0141ec50251e691c9bd75decc"
}

rule MalwareBazaar_unknown_060_edfac2aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edfac2aacde2c5ad263d08023383743db8ceab54659ac5cca9d1d39098000bc2"
    family = "unknown"
    file_name = "main.mips64r6el-n32"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:43"
  condition:
    hash.sha256(0, filesize) == "edfac2aacde2c5ad263d08023383743db8ceab54659ac5cca9d1d39098000bc2"
}

rule MalwareBazaar_unknown_061_d81610a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d81610a8d26388e9a4b446d5740984990f9ecaae2af7bb3576e02864c4f522cd"
    family = "unknown"
    file_name = "main.m68k-68xxx"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:42"
  condition:
    hash.sha256(0, filesize) == "d81610a8d26388e9a4b446d5740984990f9ecaae2af7bb3576e02864c4f522cd"
}

rule MalwareBazaar_unknown_062_9ef2504a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ef2504a2d6fda7c83170f620e1cebe67d24ac47239d2bd28df7cd13d2e84f43"
    family = "unknown"
    file_name = "main.mips64-n32"
    file_type = "elf"
    first_seen = "2026-08-07 21:24:41"
  condition:
    hash.sha256(0, filesize) == "9ef2504a2d6fda7c83170f620e1cebe67d24ac47239d2bd28df7cd13d2e84f43"
}

rule MalwareBazaar_WannaCry_063_e1ee2b7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1ee2b7aeeb62f063134d78df6e522afde0952eca1701fb8d0835abe18ef16bc"
    family = "WannaCry"
    file_name = "e1ee2b7aeeb62f063134d78df6e522afde0952eca1701fb8d0835abe18ef16bc"
    file_type = "exe"
    first_seen = "2026-08-07 21:15:58"
  condition:
    hash.sha256(0, filesize) == "e1ee2b7aeeb62f063134d78df6e522afde0952eca1701fb8d0835abe18ef16bc"
}

rule MalwareBazaar_unknown_064_d2ece067
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2ece067dae0c6921b68ade8a9779b92da96f940437b8e192f9ed89a175fcd62"
    family = "unknown"
    file_name = "update1.zip"
    file_type = "zip"
    first_seen = "2026-08-07 20:53:43"
  condition:
    hash.sha256(0, filesize) == "d2ece067dae0c6921b68ade8a9779b92da96f940437b8e192f9ed89a175fcd62"
}

rule MalwareBazaar_unknown_065_59dbc8aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59dbc8aa281e432de685e318cc8e3f318eb58bfc122063c1ab74cfd8d5732f18"
    family = "unknown"
    file_name = "huawei"
    file_type = "sh"
    first_seen = "2026-08-07 20:52:39"
  condition:
    hash.sha256(0, filesize) == "59dbc8aa281e432de685e318cc8e3f318eb58bfc122063c1ab74cfd8d5732f18"
}

rule MalwareBazaar_unknown_066_cdde7194
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdde719462e36f6a902e40859fab9e057acc944a02cc56c43353ab449efe6105"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-07 20:52:37"
  condition:
    hash.sha256(0, filesize) == "cdde719462e36f6a902e40859fab9e057acc944a02cc56c43353ab449efe6105"
}

rule MalwareBazaar_unknown_067_4c88965c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c88965c8181ea12c34f98eadebbf65f046ab6d428afe94048a497cf65df9bb2"
    family = "unknown"
    file_name = "main.nios2"
    file_type = "elf"
    first_seen = "2026-08-07 20:50:45"
  condition:
    hash.sha256(0, filesize) == "4c88965c8181ea12c34f98eadebbf65f046ab6d428afe94048a497cf65df9bb2"
}

rule MalwareBazaar_unknown_068_731a2435
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "731a24357717027f186b142b5efb8b5aea73071245b70ce5883f69f5c8bb13d2"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-07 20:50:44"
  condition:
    hash.sha256(0, filesize) == "731a24357717027f186b142b5efb8b5aea73071245b70ce5883f69f5c8bb13d2"
}

rule MalwareBazaar_RustyStealer_069_254412f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "254412f2ca69b69f8b686f874374e2584aaf55ad5c3e8ed6eddfa69f3fe6ea2b"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-07 20:49:55"
  condition:
    hash.sha256(0, filesize) == "254412f2ca69b69f8b686f874374e2584aaf55ad5c3e8ed6eddfa69f3fe6ea2b"
}

rule MalwareBazaar_unknown_070_4e8807b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e8807b243df0c6a7561061f10e4f8be103a9185d07144442023b7cd4b73767b"
    family = "unknown"
    file_name = "main.archs38"
    file_type = "elf"
    first_seen = "2026-08-07 20:48:43"
  condition:
    hash.sha256(0, filesize) == "4e8807b243df0c6a7561061f10e4f8be103a9185d07144442023b7cd4b73767b"
}

rule MalwareBazaar_Mirai_071_a2710ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2710ae2c19298d4f6a362b3a32d17c4f2b0e138c163c3442f350bd5a44fadeb"
    family = "Mirai"
    file_name = "xd.m68k"
    file_type = "elf"
    first_seen = "2026-08-07 20:46:54"
  condition:
    hash.sha256(0, filesize) == "a2710ae2c19298d4f6a362b3a32d17c4f2b0e138c163c3442f350bd5a44fadeb"
}

rule MalwareBazaar_unknown_072_09868f35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09868f351219ae109efb1b40104f888990961a31d63ce88e11f0f976a4220b6b"
    family = "unknown"
    file_name = "main.sparc"
    file_type = "elf"
    first_seen = "2026-08-07 20:46:53"
  condition:
    hash.sha256(0, filesize) == "09868f351219ae109efb1b40104f888990961a31d63ce88e11f0f976a4220b6b"
}

rule MalwareBazaar_CoinMiner_073_467ed1f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "467ed1f5cfbbb2bbb6f90f75d1b2bcd99dbeb38a65cc4bcc7bd39767a62d5676"
    family = "CoinMiner"
    file_name = "467ed1f5cfbbb2bbb6f90f75d1b2bcd99dbeb38a65cc4bcc7bd39767a62d5676.exe"
    file_type = "exe"
    first_seen = "2026-08-07 20:45:40"
  condition:
    hash.sha256(0, filesize) == "467ed1f5cfbbb2bbb6f90f75d1b2bcd99dbeb38a65cc4bcc7bd39767a62d5676"
}

rule MalwareBazaar_unknown_074_7e681549
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e6815495d078bff962365cd929cdcf8f0c25f24b9de5ee89bebec4af778d76f"
    family = "unknown"
    file_name = "7e6815495d078bff962365cd929cdcf8f0c25f24b9de5ee89bebec4af778d76f.exe"
    file_type = "exe"
    first_seen = "2026-08-07 20:45:34"
  condition:
    hash.sha256(0, filesize) == "7e6815495d078bff962365cd929cdcf8f0c25f24b9de5ee89bebec4af778d76f"
}

rule MalwareBazaar_unknown_075_4c055950
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c05595080efd5b9ba7c55f1d8fba88025b4737b905119fd728b7e40c17e89a7"
    family = "unknown"
    file_name = "Error84"
    file_type = "elf"
    first_seen = "2026-08-07 20:42:42"
  condition:
    hash.sha256(0, filesize) == "4c05595080efd5b9ba7c55f1d8fba88025b4737b905119fd728b7e40c17e89a7"
}

rule MalwareBazaar_unknown_076_86c285b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c285b71638c91f36b35eb40b282f997396f6015d9821a2e446bf677703c8c6"
    family = "unknown"
    file_name = "realtek"
    file_type = "sh"
    first_seen = "2026-08-07 20:42:40"
  condition:
    hash.sha256(0, filesize) == "86c285b71638c91f36b35eb40b282f997396f6015d9821a2e446bf677703c8c6"
}

rule MalwareBazaar_unknown_077_f2e2ffc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2e2ffc024ab99eb49fa207756481aa80713398142f30888aebace5706909b36"
    family = "unknown"
    file_name = "twget.sh"
    file_type = "sh"
    first_seen = "2026-08-07 20:40:48"
  condition:
    hash.sha256(0, filesize) == "f2e2ffc024ab99eb49fa207756481aa80713398142f30888aebace5706909b36"
}

rule MalwareBazaar_unknown_078_17d3d77a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17d3d77a919c0f84bdbbb8c4796d0ef2169fc11511adf33a1e179b9a816769ce"
    family = "unknown"
    file_name = "main.arm7"
    file_type = "elf"
    first_seen = "2026-08-07 20:38:46"
  condition:
    hash.sha256(0, filesize) == "17d3d77a919c0f84bdbbb8c4796d0ef2169fc11511adf33a1e179b9a816769ce"
}

rule MalwareBazaar_unknown_079_ce687767
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce6877673a5562fddb23109127fb9534be420e0a3191284c06775b277295fa90"
    family = "unknown"
    file_name = "main.armv4"
    file_type = "elf"
    first_seen = "2026-08-07 20:38:45"
  condition:
    hash.sha256(0, filesize) == "ce6877673a5562fddb23109127fb9534be420e0a3191284c06775b277295fa90"
}

rule MalwareBazaar_unknown_080_85e137cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85e137cce38fd043ff723f80610d52adae34db5b2a4d528273308225efa0688f"
    family = "unknown"
    file_name = "main.armv7-eabihf"
    file_type = "elf"
    first_seen = "2026-08-07 20:36:49"
  condition:
    hash.sha256(0, filesize) == "85e137cce38fd043ff723f80610d52adae34db5b2a4d528273308225efa0688f"
}

rule MalwareBazaar_unknown_081_08b2f808
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08b2f8080a69d822cd030695a824bb12b75949d98e810c620daeca70735da1d7"
    family = "unknown"
    file_name = "tplink.sh"
    file_type = "sh"
    first_seen = "2026-08-07 20:33:14"
  condition:
    hash.sha256(0, filesize) == "08b2f8080a69d822cd030695a824bb12b75949d98e810c620daeca70735da1d7"
}

rule MalwareBazaar_unknown_082_e3a3ea47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3a3ea4778ea5d97a92d3ec0924cfae0f21163ca492d1fa776fe065867c9e5ad"
    family = "unknown"
    file_name = "main.i486"
    file_type = "elf"
    first_seen = "2026-08-07 20:31:23"
  condition:
    hash.sha256(0, filesize) == "e3a3ea4778ea5d97a92d3ec0924cfae0f21163ca492d1fa776fe065867c9e5ad"
}

rule MalwareBazaar_unknown_083_5efd3f43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5efd3f43074c5bb7b180da4993b5db062bdd099be08b29b8a3d9d2e847fc6fa0"
    family = "unknown"
    file_name = "main.armebv7"
    file_type = "elf"
    first_seen = "2026-08-07 20:31:21"
  condition:
    hash.sha256(0, filesize) == "5efd3f43074c5bb7b180da4993b5db062bdd099be08b29b8a3d9d2e847fc6fa0"
}

rule MalwareBazaar_unknown_084_d1bac5d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1bac5d40cd98f05ef8e605931a4ed9a619171ad8f0cba785560da36c3ca85f9"
    family = "unknown"
    file_name = "sensi.sh"
    file_type = "sh"
    first_seen = "2026-08-07 20:25:12"
  condition:
    hash.sha256(0, filesize) == "d1bac5d40cd98f05ef8e605931a4ed9a619171ad8f0cba785560da36c3ca85f9"
}

rule MalwareBazaar_WannaCry_085_b9cf80a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9cf80a5e63577b018937534f6219eb29876c2163f0cdad7341acc2deef2859f"
    family = "WannaCry"
    file_name = "b9cf80a5e63577b018937534f6219eb29876c2163f0cdad7341acc2deef2859f"
    file_type = "exe"
    first_seen = "2026-08-07 20:16:34"
  condition:
    hash.sha256(0, filesize) == "b9cf80a5e63577b018937534f6219eb29876c2163f0cdad7341acc2deef2859f"
}

rule MalwareBazaar_unknown_086_7099805d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7099805ddc0647122cfd66d28fcd68c462e8d1c9fe9869221d6e0fe4129d820e"
    family = "unknown"
    file_name = "main.armv5-eabi"
    file_type = "elf"
    first_seen = "2026-08-07 20:15:17"
  condition:
    hash.sha256(0, filesize) == "7099805ddc0647122cfd66d28fcd68c462e8d1c9fe9869221d6e0fe4129d820e"
}

rule MalwareBazaar_Mirai_087_d3ab9585
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3ab958551ae4b0c4d3086b00804e00b52c612cd5e19ac28dfb5fa969585d65d"
    family = "Mirai"
    file_name = "main.mipsel"
    file_type = "elf"
    first_seen = "2026-08-07 20:15:15"
  condition:
    hash.sha256(0, filesize) == "d3ab958551ae4b0c4d3086b00804e00b52c612cd5e19ac28dfb5fa969585d65d"
}

rule MalwareBazaar_unknown_088_59caa54d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59caa54df4e941f1fa20795b58cc02420c9e4400ba44a178614d330d5bfca79b"
    family = "unknown"
    file_name = "main.xtensa"
    file_type = "elf"
    first_seen = "2026-08-07 20:15:14"
  condition:
    hash.sha256(0, filesize) == "59caa54df4e941f1fa20795b58cc02420c9e4400ba44a178614d330d5bfca79b"
}

rule MalwareBazaar_unknown_089_e10e3cb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e10e3cb9d4a4cdb0733eb120a7500996e854b01466d7a42b99414598324f8084"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-07 20:13:18"
  condition:
    hash.sha256(0, filesize) == "e10e3cb9d4a4cdb0733eb120a7500996e854b01466d7a42b99414598324f8084"
}

rule MalwareBazaar_unknown_090_1af80d8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1af80d8f770ff150a11955a217608d63a7078b5d9852a0929747109ad2cbfbb7"
    family = "unknown"
    file_name = "main.armv4tl"
    file_type = "elf"
    first_seen = "2026-08-07 20:13:17"
  condition:
    hash.sha256(0, filesize) == "1af80d8f770ff150a11955a217608d63a7078b5d9852a0929747109ad2cbfbb7"
}

rule MalwareBazaar_unknown_091_61ba1a0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61ba1a0e43e061fc00224e3d2c3f4fcb269b7830eb7dff8059e12b69de42c4eb"
    family = "unknown"
    file_name = "main.armv6-eabihf"
    file_type = "elf"
    first_seen = "2026-08-07 20:11:23"
  condition:
    hash.sha256(0, filesize) == "61ba1a0e43e061fc00224e3d2c3f4fcb269b7830eb7dff8059e12b69de42c4eb"
}

rule MalwareBazaar_unknown_092_bb70c62a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb70c62afb7cd5c6637680558a40916333a5d785192495620db58fc185f5ac6c"
    family = "unknown"
    file_name = "main.sh4"
    file_type = "elf"
    first_seen = "2026-08-07 20:11:22"
  condition:
    hash.sha256(0, filesize) == "bb70c62afb7cd5c6637680558a40916333a5d785192495620db58fc185f5ac6c"
}

rule MalwareBazaar_unknown_093_7a23ed99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a23ed995778d3080036322c53b859ea91a149c656fe900328b7d5814ff42aa3"
    family = "unknown"
    file_name = "main.armv6"
    file_type = "elf"
    first_seen = "2026-08-07 20:09:21"
  condition:
    hash.sha256(0, filesize) == "7a23ed995778d3080036322c53b859ea91a149c656fe900328b7d5814ff42aa3"
}

rule MalwareBazaar_Mirai_094_54c38e4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54c38e4fcde2afc3b93bad341ca08dd475f47eb7a0843aa979e030831f251061"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-07 20:07:46"
  condition:
    hash.sha256(0, filesize) == "54c38e4fcde2afc3b93bad341ca08dd475f47eb7a0843aa979e030831f251061"
}

rule MalwareBazaar_Mirai_095_8355b042
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8355b042d1d2e9e3276091ff1998ba3295304314ae54e5655bc9945693362cdc"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-07 20:07:24"
  condition:
    hash.sha256(0, filesize) == "8355b042d1d2e9e3276091ff1998ba3295304314ae54e5655bc9945693362cdc"
}

rule MalwareBazaar_RemcosRAT_096_07b1a32c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07b1a32c53c1efab24f54151b1158bad7404374f0dfdee558e7ad80ad278575a"
    family = "RemcosRAT"
    file_name = "rcx1.exe"
    file_type = "exe"
    first_seen = "2026-08-07 20:05:07"
  condition:
    hash.sha256(0, filesize) == "07b1a32c53c1efab24f54151b1158bad7404374f0dfdee558e7ad80ad278575a"
}

rule MalwareBazaar_Mirai_097_003924f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "003924f140e5ce4ec27ffed10e9927c3a361786a19982dfe538e68dee3e194fe"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 20:03:39"
  condition:
    hash.sha256(0, filesize) == "003924f140e5ce4ec27ffed10e9927c3a361786a19982dfe538e68dee3e194fe"
}

rule MalwareBazaar_Mirai_098_6ff2f877
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ff2f877668649928a1a510d79e961e5f13408c729f648bd45cf24f22b011509"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 20:03:24"
  condition:
    hash.sha256(0, filesize) == "6ff2f877668649928a1a510d79e961e5f13408c729f648bd45cf24f22b011509"
}

rule MalwareBazaar_unknown_099_a10a1246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a10a1246b36d37c7b5dc44884584790a291558414f5b965210423a398c113c18"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-07 19:57:13"
  condition:
    hash.sha256(0, filesize) == "a10a1246b36d37c7b5dc44884584790a291558414f5b965210423a398c113c18"
}

rule MalwareBazaar_unknown_100_2d573ab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d573ab28d97298b53d789d6ffe1ce976d4c32e83d22f85d877cc688013301d1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-07 19:55:16"
  condition:
    hash.sha256(0, filesize) == "2d573ab28d97298b53d789d6ffe1ce976d4c32e83d22f85d877cc688013301d1"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

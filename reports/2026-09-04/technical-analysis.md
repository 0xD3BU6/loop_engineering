# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-04

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 631 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 631 |
| Unique family labels | 13 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 61 |
| Vidar | 21 |
| Formbook | 4 |
| Hajime | 3 |
| CoinMiner | 2 |
| ValleyRAT | 2 |
| AgentTesla | 1 |
| a310Logger | 1 |
| Mirai | 1 |
| DarkCloud | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 53 |
| sh | 17 |
| elf | 9 |
| unknown | 8 |
| ps1 | 7 |
| js | 2 |
| apk | 1 |
| vbs | 1 |
| hta | 1 |
| dll | 1 |

## Per-Sample Analysis

### Sample 1: `948435372615e8fc`

| Field | Value |
|---|---|
| SHA-256 | `948435372615e8fcd975eb30e921851be5396ae6238986ea782b0ae1743ffb44` |
| Family label | `unknown` |
| File name | `948435372615e8fcd975eb30e921851be5396ae6238986ea782b0ae1743ffb44.bin` |
| File type | `exe` |
| First seen | `2026-09-04 04:40:16` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bb520c9c7f9c6c649629831592e7dce` |
| SHA-1 | `804a37d65cf317432b686d51f68dd76861ffb690` |
| SHA-256 | `948435372615e8fcd975eb30e921851be5396ae6238986ea782b0ae1743ffb44` |
| SHA3-384 | `9442237556ce1180656ed4c6029bf05fcce52dc786c922de293fede388550651d47483dd66e1a98c8d88bb5fa8e54012` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T166567C077CA5A4A4C9DA9638D27542937634789A9B3037E72F91F2B02F327E1AF75310` |
| SSDEEP | `49152:lEG+tHRCWkfmIrb/TgvO90d7HjmAFd4A64nsfJT+A24cKuyC/ofxSXgzAX3e+qst:6euQcyC/WYIjdvyWM0RaaMzKO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_94843537
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "948435372615e8fcd975eb30e921851be5396ae6238986ea782b0ae1743ffb44"
    family = "unknown"
    file_name = "948435372615e8fcd975eb30e921851be5396ae6238986ea782b0ae1743ffb44.bin"
    file_type = "exe"
    first_seen = "2026-09-04 04:40:16"
  condition:
    hash.sha256(0, filesize) == "948435372615e8fcd975eb30e921851be5396ae6238986ea782b0ae1743ffb44"
}
```

### Sample 2: `eeffc79d077be873`

| Field | Value |
|---|---|
| SHA-256 | `eeffc79d077be873b173dd0cdd919f8e2d869c5a079034bf9f2a8641d7668a4e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-04 04:07:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f8edc5e571104fe34354f0bbc500338` |
| SHA-1 | `96c05bdb2c5f54ab6a3e07244ee9ae408dee515f` |
| SHA-256 | `eeffc79d077be873b173dd0cdd919f8e2d869c5a079034bf9f2a8641d7668a4e` |
| SHA3-384 | `77046fdc4cb1e687fb557b19a724cf9d11ce18c4c39a5a8e7117b2eb5f6a85cd1948f9a08b261bbbd192143d23fc6e04` |
| TLSH | `T17FC27D966A867C44BDC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:d8vCB+25j6es8RLe9FYpMSUpi+20qUpi+20YQX:d8l25JL4d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_eeffc79d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeffc79d077be873b173dd0cdd919f8e2d869c5a079034bf9f2a8641d7668a4e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-04 04:07:31"
  condition:
    hash.sha256(0, filesize) == "eeffc79d077be873b173dd0cdd919f8e2d869c5a079034bf9f2a8641d7668a4e"
}
```

### Sample 3: `f8b0897860157869`

| Field | Value |
|---|---|
| SHA-256 | `f8b0897860157869bc70f941750ca5e8de199736df83a70f4780af771338a685` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-04 04:05:30` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f06d921efbfc0f43043b1878cd823ad9` |
| SHA-256 | `f8b0897860157869bc70f941750ca5e8de199736df83a70f4780af771338a685` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_f8b08978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b0897860157869bc70f941750ca5e8de199736df83a70f4780af771338a685"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-04 04:05:30"
  condition:
    hash.sha256(0, filesize) == "f8b0897860157869bc70f941750ca5e8de199736df83a70f4780af771338a685"
}
```

### Sample 4: `82e64906d1187ae3`

| Field | Value |
|---|---|
| SHA-256 | `82e64906d1187ae30b21d3cbc0988e3fafe9980684ce8ebf2483f6865c615573` |
| Family label | `unknown` |
| File name | `.i` |
| File type | `elf` |
| First seen | `2026-09-04 04:03:25` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da6d2ee28c71e74d9bb04d93ec906f60` |
| SHA-1 | `48c1503f95cc0ac629a86b54a7459c1c1baa54c7` |
| SHA-256 | `82e64906d1187ae30b21d3cbc0988e3fafe9980684ce8ebf2483f6865c615573` |
| SHA3-384 | `3d44105e2710fbca9adf25b3939ff64ce0dfef5c850a4231a849d34b30b91b3fc69c1dc0a5d47bb0d1e344ef08f20316` |
| TLSH | `T15933024623A62EB6C57548F1E3F8FF89B14A7DA49FE65C0A7C217649A43236C28C481D` |
| SSDEEP | `1536:yYI0ARqw1qAEW67UIWi7M8gmfmJo0WgswnD2:yYI0ARqw1qAEv7UIFM8oJorFqi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_82e64906
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82e64906d1187ae30b21d3cbc0988e3fafe9980684ce8ebf2483f6865c615573"
    family = "unknown"
    file_name = ".i"
    file_type = "elf"
    first_seen = "2026-09-04 04:03:25"
  condition:
    hash.sha256(0, filesize) == "82e64906d1187ae30b21d3cbc0988e3fafe9980684ce8ebf2483f6865c615573"
}
```

### Sample 5: `3efcccb330511f01`

| Field | Value |
|---|---|
| SHA-256 | `3efcccb330511f012f1e6a70a989c97d9da951a86cfa24135df5de43748b5645` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-04 04:02:14` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17c18322a9420b7ac0355ba8235ebd8f` |
| SHA-256 | `3efcccb330511f012f1e6a70a989c97d9da951a86cfa24135df5de43748b5645` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_3efcccb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3efcccb330511f012f1e6a70a989c97d9da951a86cfa24135df5de43748b5645"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-04 04:02:14"
  condition:
    hash.sha256(0, filesize) == "3efcccb330511f012f1e6a70a989c97d9da951a86cfa24135df5de43748b5645"
}
```

### Sample 6: `2d8f5d005671ea3d`

| Field | Value |
|---|---|
| SHA-256 | `2d8f5d005671ea3d53be84782493fddb3fd75c496ab712a15a88707cc84e2f82` |
| Family label | `Hajime` |
| File name | `.i` |
| File type | `elf` |
| First seen | `2026-09-04 03:48:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Hajime` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10232d386f884160bd4cd07c80b1951b` |
| SHA-1 | `cceafc7f9255d0d0154b6f0620c12694031f778c` |
| SHA-256 | `2d8f5d005671ea3d53be84782493fddb3fd75c496ab712a15a88707cc84e2f82` |
| SHA3-384 | `9689d2f5577356678931561efa169474d5c94f232fc1d3d82f283fdbdf128e3f3948d6f07432b5513c98afef0d7504ad` |
| TLSH | `T1FCF2F24632943B73E16255F4E3BDAFCA611E7D649FEE242BA4403A6270B211D24CD42A` |
| SSDEEP | `768:YTYIDfYG6ZmewZ59+Nw1qsREH20j7UNqVwi7M8W:yYI0ARqw1qAEW67UIWi7M8W` |

#### Technical Assessment

- The sample is tracked as `Hajime` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Hajime_006_2d8f5d00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d8f5d005671ea3d53be84782493fddb3fd75c496ab712a15a88707cc84e2f82"
    family = "Hajime"
    file_name = ".i"
    file_type = "elf"
    first_seen = "2026-09-04 03:48:06"
  condition:
    hash.sha256(0, filesize) == "2d8f5d005671ea3d53be84782493fddb3fd75c496ab712a15a88707cc84e2f82"
}
```

### Sample 7: `9644bd301c54b532`

| Field | Value |
|---|---|
| SHA-256 | `9644bd301c54b5328829dc3df461d626c5957190954fdc40ca4eb83b2a0842a5` |
| Family label | `unknown` |
| File name | `poop` |
| File type | `elf` |
| First seen | `2026-09-04 03:43:59` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a96687c02a1c9dd27437e4fa6315528d` |
| SHA-1 | `6ce3d8fc4392af426d6478e2baca1d436a638cdf` |
| SHA-256 | `9644bd301c54b5328829dc3df461d626c5957190954fdc40ca4eb83b2a0842a5` |
| SHA3-384 | `78f7dfaef84336c032fb3ccebe2ef0666ce28e161090253cb95d89ca1e4a4e64b59ae8925910f2aabf76f0783c8a8e72` |
| TLSH | `T16A353374DBA9D148FE69BD7E0CB458744D2D7C8536FFDB61C8A0A9081AABC07874AD0C` |
| SSDEEP | `24576:8xjYKXhddU2aABFkxaU1D6tFrGQhl4PRecoNy53r8Nioi5+AWk6dlehh:8+KxdmybkoU1DgFlNcCyNf0e/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_9644bd30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9644bd301c54b5328829dc3df461d626c5957190954fdc40ca4eb83b2a0842a5"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-09-04 03:43:59"
  condition:
    hash.sha256(0, filesize) == "9644bd301c54b5328829dc3df461d626c5957190954fdc40ca4eb83b2a0842a5"
}
```

### Sample 8: `9cc59a6e37685c6b`

| Field | Value |
|---|---|
| SHA-256 | `9cc59a6e37685c6b866e2dc8e2b21569a218915e2ea224e6f43207928838521e` |
| Family label | `unknown` |
| File name | `9cc59a6e37685c6b866e2dc8e2b21569a218915e2ea224e6f43207928838521e.bin` |
| File type | `exe` |
| First seen | `2026-09-04 03:31:07` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab900efc40b8b53aaa5a66db2dfcf1a8` |
| SHA-1 | `8df86b2dd31cae047c3b61bd505b5393a3cb2ab7` |
| SHA-256 | `9cc59a6e37685c6b866e2dc8e2b21569a218915e2ea224e6f43207928838521e` |
| SHA3-384 | `439b11f08e183d5db81dac389972597720469388939f990296ef1dc0eca409bd8a3027166700afbbdadeef5ed7669117` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1DFE65B07260442E8E892D778F17F06B16A76FC4CE33136A71E9AB4B47EB67C164B5B10` |
| SSDEEP | `49152:Xnf+Un0xsT2ylBIaPEbG8+Bo1XNcqO12L6ke1oR10X3ha2YDrAoqb5JVpHiUUvZT:3gsDhp+OsLH2TYfqbVpHiUURuO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_9cc59a6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cc59a6e37685c6b866e2dc8e2b21569a218915e2ea224e6f43207928838521e"
    family = "unknown"
    file_name = "9cc59a6e37685c6b866e2dc8e2b21569a218915e2ea224e6f43207928838521e.bin"
    file_type = "exe"
    first_seen = "2026-09-04 03:31:07"
  condition:
    hash.sha256(0, filesize) == "9cc59a6e37685c6b866e2dc8e2b21569a218915e2ea224e6f43207928838521e"
}
```

### Sample 9: `2149f36bbe37f8fb`

| Field | Value |
|---|---|
| SHA-256 | `2149f36bbe37f8fb8e079f77e286df45719a51442ed8b3c1fed6d25d74eb1fec` |
| Family label | `unknown` |
| File name | `2149f36bbe37f8fb8e079f77e286df45719a51442ed8b3c1fed6d25d74eb1fec.exe` |
| File type | `exe` |
| First seen | `2026-09-04 03:17:50` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96803abb9dbeb9a80cf33f819fe8032d` |
| SHA-1 | `d79ade081523b8727c44176d11264959686c6462` |
| SHA-256 | `2149f36bbe37f8fb8e079f77e286df45719a51442ed8b3c1fed6d25d74eb1fec` |
| SHA3-384 | `7ef11f34c2742d6968dd7cd5c494cf2597cf5e9dde3ad80a02b949036d8da4930f2a7e7d86e0c2c12d482dc7a7ca5f49` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T1CFD523867DB319B5D432C7B68EA7F47CB23D3B824BA08C9B39CC1A104E129595D713B9` |
| SSDEEP | `49152:HuuaNHnGGYDXihRyrT1yCbmEBYAblA5kXI7PZTTWqBaucFKofF22yKX+LP0NQIbj:OBmGzhRWDmiYuA5p7ZT/0NI2yFLsNvo4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_2149f36b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2149f36bbe37f8fb8e079f77e286df45719a51442ed8b3c1fed6d25d74eb1fec"
    family = "unknown"
    file_name = "2149f36bbe37f8fb8e079f77e286df45719a51442ed8b3c1fed6d25d74eb1fec.exe"
    file_type = "exe"
    first_seen = "2026-09-04 03:17:50"
  condition:
    hash.sha256(0, filesize) == "2149f36bbe37f8fb8e079f77e286df45719a51442ed8b3c1fed6d25d74eb1fec"
}
```

### Sample 10: `d29fced48d33419f`

| Field | Value |
|---|---|
| SHA-256 | `d29fced48d33419fc4241ca8ae6dba28e45e4217c4722e58b58d803b79d93d40` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-04 03:17:13` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `756ba09da859a01032ce6b66ecffb6e7` |
| SHA-1 | `3e92c3ec83cdf45c7ec8132893d9c784e538691c` |
| SHA-256 | `d29fced48d33419fc4241ca8ae6dba28e45e4217c4722e58b58d803b79d93d40` |
| SHA3-384 | `1d6210b9d80800772c96d4e95b85596a7b92df3bdca08c2b2dd210fd03bfed9070c680aa4b349ada154694961db4b4d5` |
| TLSH | `T135C28E966A867C44BDC94A3E4CBD1B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:Cb8vCB+25j6es8Rv9FYpMSUpi+20qUpi+20YQX:88l25J5d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_d29fced4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d29fced48d33419fc4241ca8ae6dba28e45e4217c4722e58b58d803b79d93d40"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-04 03:17:13"
  condition:
    hash.sha256(0, filesize) == "d29fced48d33419fc4241ca8ae6dba28e45e4217c4722e58b58d803b79d93d40"
}
```

### Sample 11: `912cb2fd882c70b7`

| Field | Value |
|---|---|
| SHA-256 | `912cb2fd882c70b7f8bcf2fa377740ed8b23e13f1c9a63df37350d8a62a613fc` |
| Family label | `AgentTesla` |
| File name | `NEW_ORDER13470_QUOTATION_FORM.js` |
| File type | `js` |
| First seen | `2026-09-04 03:14:25` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54aef9233210c37f8a5900b495a458a9` |
| SHA-1 | `40ca5f6ccff9a1b0e28a9c7c22a947048a623210` |
| SHA-256 | `912cb2fd882c70b7f8bcf2fa377740ed8b23e13f1c9a63df37350d8a62a613fc` |
| SHA3-384 | `3c8465ce48a9d45e46e368d1eb35ff5859780643d34d7377be74e15ed87e8a718fbd2e7e32b300eacf340355514f8682` |
| TLSH | `T135A5E9F292AE9E826630B67D145C1E489F9FC10151C3B5E4D48EAEC4E20FCDE16E5D8E` |
| SSDEEP | `12288:TiYL8sw+RlWmcxTrO+hUfD8ff9pacl9isY2PFNdIk74D37u5ta7ZBaeU8:OFfFdI04jU8` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_011_912cb2fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "912cb2fd882c70b7f8bcf2fa377740ed8b23e13f1c9a63df37350d8a62a613fc"
    family = "AgentTesla"
    file_name = "NEW_ORDER13470_QUOTATION_FORM.js"
    file_type = "js"
    first_seen = "2026-09-04 03:14:25"
  condition:
    hash.sha256(0, filesize) == "912cb2fd882c70b7f8bcf2fa377740ed8b23e13f1c9a63df37350d8a62a613fc"
}
```

### Sample 12: `a90bceeb8cd9c597`

| Field | Value |
|---|---|
| SHA-256 | `a90bceeb8cd9c5978939ed48fd545cc3ac98b8831a1e7a9438b3795372f4d4a6` |
| Family label | `unknown` |
| File name | `.X0-lock_x86_64` |
| File type | `elf` |
| First seen | `2026-09-04 03:07:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f032ff1ecd22df6c597274c49da02e4c` |
| SHA-1 | `db496c0b438b5ceb0050dcf11c9cd95dcd437e07` |
| SHA-256 | `a90bceeb8cd9c5978939ed48fd545cc3ac98b8831a1e7a9438b3795372f4d4a6` |
| SHA3-384 | `5be16b5019fa64066dd58fd0739f7ce5bdf45505a540d323eee1cac644bab0363f535e1bc4af3ce1dfd8364c571e386c` |
| TLSH | `T145E55C06B6A244BEC0E6D470878FD5B3AD35B8594221397F3685AB302E76E305F1DFA1` |
| SSDEEP | `49152:2z5hzV1qTBU9kQTXv8J8VBybvJAjV7LuQr7vYn+0b90jLVqqiw2R3ZR:eha10Hv8J8VWRAp7LuA+AjLYlXRpR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_a90bceeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a90bceeb8cd9c5978939ed48fd545cc3ac98b8831a1e7a9438b3795372f4d4a6"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-09-04 03:07:46"
  condition:
    hash.sha256(0, filesize) == "a90bceeb8cd9c5978939ed48fd545cc3ac98b8831a1e7a9438b3795372f4d4a6"
}
```

### Sample 13: `a11795543eb20972`

| Field | Value |
|---|---|
| SHA-256 | `a11795543eb20972c510ded46edef5d4b31e653d56fbd2af0e30b0b2f25a36e1` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-04 03:04:29` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e5a6576b4946a1a57c68921c8cbc358` |
| SHA-1 | `98ef0136822c37d8aad21433e63ae5ca3035e057` |
| SHA-256 | `a11795543eb20972c510ded46edef5d4b31e653d56fbd2af0e30b0b2f25a36e1` |
| SHA3-384 | `f1e914cd708cbd578c5acea18dc5310f06909289064ef84a60cb127c5c3ae7e88fd81b3ed8252e39e8775dafd73dc6fa` |
| TLSH | `T189236C651A857C149A99C4371D7E2F0CBDAD43E6320452EE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:TVEJVIhtMJ9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:pEJ2MCcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_a1179554
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a11795543eb20972c510ded46edef5d4b31e653d56fbd2af0e30b0b2f25a36e1"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-04 03:04:29"
  condition:
    hash.sha256(0, filesize) == "a11795543eb20972c510ded46edef5d4b31e653d56fbd2af0e30b0b2f25a36e1"
}
```

### Sample 14: `4603b304465a4eb7`

| Field | Value |
|---|---|
| SHA-256 | `4603b304465a4eb78408eaa74d2d2753c3d022d043197a3bbb8a1d05070f5c2f` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-04 02:58:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `082226a5636c03a2fcb9b35cf306fc5b` |
| SHA-1 | `4609e25f4a9d5c179ca0cb8aa42d169465bc7ba6` |
| SHA-256 | `4603b304465a4eb78408eaa74d2d2753c3d022d043197a3bbb8a1d05070f5c2f` |
| SHA3-384 | `682a146d0291b04a796f1a928e718c44affb37d33079077934e37736a4704a2f4a94cb947592621a35a3d4d9daa69001` |
| TLSH | `T185312F8F00155E321046CAAE73663948B38E95FB2C5FC7E0CD0C0DEA9A9879CF221B5D` |
| SSDEEP | `24:kiiPkNRshKuZyGMHhjHZajgvR8Tmd5c2xs:kiiPkMhKFZogvQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_4603b304
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4603b304465a4eb78408eaa74d2d2753c3d022d043197a3bbb8a1d05070f5c2f"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-04 02:58:57"
  condition:
    hash.sha256(0, filesize) == "4603b304465a4eb78408eaa74d2d2753c3d022d043197a3bbb8a1d05070f5c2f"
}
```

### Sample 15: `8a4b80dcab4bb563`

| Field | Value |
|---|---|
| SHA-256 | `8a4b80dcab4bb563fd0220c4268582303ef3816f8eb56b6fa6a5d4b734b913e2` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-04 02:58:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19d09283ff939f23bab84de537fe9573` |
| SHA-1 | `9ada33d144b143cf30d80ec71fc9577fb681c61e` |
| SHA-256 | `8a4b80dcab4bb563fd0220c4268582303ef3816f8eb56b6fa6a5d4b734b913e2` |
| SHA3-384 | `f16c33e2c70ef4fb5b1849392f4cd4905cdb39d1c667ea9a711165647e11e5c3300069e4c4dc45982eb745ed94ce487a` |
| TLSH | `T19E236C6516857C14AE98C4365C7F2F0CBDAD43E6314492EE7FCA3CF28C4A6ADA20875D` |
| SSDEEP | `768:jr9NyXsZztCC9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:XHusZacr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_8a4b80dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a4b80dcab4bb563fd0220c4268582303ef3816f8eb56b6fa6a5d4b734b913e2"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-04 02:58:56"
  condition:
    hash.sha256(0, filesize) == "8a4b80dcab4bb563fd0220c4268582303ef3816f8eb56b6fa6a5d4b734b913e2"
}
```

### Sample 16: `e9b770b2539cb842`

| Field | Value |
|---|---|
| SHA-256 | `e9b770b2539cb842ad643706c54286b6b22ef9ec59996dcd9715f54f6b9fdf3f` |
| Family label | `unknown` |
| File name | `e9b770b2539cb842ad643706c54286b6b22ef9ec59996dcd9715f54f6b9fdf3f.exe` |
| File type | `exe` |
| First seen | `2026-09-04 02:32:41` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5c1310b5d7dbf68a42c0dd4f4619fee` |
| SHA-1 | `7a012c50b513221461d9fe92ce1d99355828e7d0` |
| SHA-256 | `e9b770b2539cb842ad643706c54286b6b22ef9ec59996dcd9715f54f6b9fdf3f` |
| SHA3-384 | `48e0efce845ffdc8024f062ce893513799098f543a94720313662c435845b0f5f7b0846c43789bf44012c3e4e8ff136e` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T118D5238AA9F61975E43BC7B5DF87E5AD702E3B9847608E8BB5CD21004E125842C3F772` |
| SSDEEP | `49152:2Li4WA267Gx/3kY4E5NfMaBYzS+Ny2dThJntsZhFDu91U/Dr5PK3:14A66lAotD+vphJtwho91Us3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_e9b770b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9b770b2539cb842ad643706c54286b6b22ef9ec59996dcd9715f54f6b9fdf3f"
    family = "unknown"
    file_name = "e9b770b2539cb842ad643706c54286b6b22ef9ec59996dcd9715f54f6b9fdf3f.exe"
    file_type = "exe"
    first_seen = "2026-09-04 02:32:41"
  condition:
    hash.sha256(0, filesize) == "e9b770b2539cb842ad643706c54286b6b22ef9ec59996dcd9715f54f6b9fdf3f"
}
```

### Sample 17: `2072c29a227b8cd1`

| Field | Value |
|---|---|
| SHA-256 | `2072c29a227b8cd181ad8fe67a07f75c4de34fed5f824706316bcb6bd804bda7` |
| Family label | `unknown` |
| File name | `Rasmlar5⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀.apk` |
| File type | `apk` |
| First seen | `2026-09-04 02:15:53` |
| Reporter | `Alex_sev` |
| Tags | `apk, dropper` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `252083667078cb107e7d146c25d7743c` |
| SHA-1 | `ed0f1030e32d8ec0bee806fbe4ea438bcdcb7192` |
| SHA-256 | `2072c29a227b8cd181ad8fe67a07f75c4de34fed5f824706316bcb6bd804bda7` |
| SHA3-384 | `0f8b0945f054362f04e6a84a443bce7384725cce4688636fc66ad523e99010ab5e98cc1cc3c9b14aebe6ce7632ef029b` |
| TLSH | `T18646E4AECE6D6825DA44AF35045B0EEBD10903815642F33F5E78A9A03C8BDD95D23D3B` |
| SSDEEP | `49152:zQDaKCd/6FStCEYUf98S9401URYw1PmD/RPjn3SPWkE+lMLIiU6y4IPd/6Ou3uWL:zQOGGR971y1PmbRPj36E+Mi7rdWL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_2072c29a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2072c29a227b8cd181ad8fe67a07f75c4de34fed5f824706316bcb6bd804bda7"
    family = "unknown"
    file_name = "Rasmlar5⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀.apk"
    file_type = "apk"
    first_seen = "2026-09-04 02:15:53"
  condition:
    hash.sha256(0, filesize) == "2072c29a227b8cd181ad8fe67a07f75c4de34fed5f824706316bcb6bd804bda7"
}
```

### Sample 18: `a6451ad4f82ed52f`

| Field | Value |
|---|---|
| SHA-256 | `a6451ad4f82ed52fdb02fd705438fe1dfc0fcc3b27e4ff3943413fa1e4dcd13e` |
| Family label | `CoinMiner` |
| File name | `a6451ad4f82ed52fdb02fd705438fe1dfc0fcc3b27e4ff3943413fa1e4dcd13e.exe` |
| File type | `exe` |
| First seen | `2026-09-04 02:12:32` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf09050bc0fca7db56fa1b2fdfa04ec8` |
| SHA-1 | `1fe52fc21ac253d0a9cb6ecd889483e2fbccaf12` |
| SHA-256 | `a6451ad4f82ed52fdb02fd705438fe1dfc0fcc3b27e4ff3943413fa1e4dcd13e` |
| SHA3-384 | `49a48b067cf7670d0946f904e0d6ad6835b1cd830d9e1e95a56901f6603a5c1e955ee08c4b8ce48349377499e630fe13` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T14D3633EA68CB56B5C886C3B89302706DF13B7B5546207D4B73CE59489E76F28903A3C7` |
| SSDEEP | `98304:yNQH/UA5dwuQpMcgvtyv+2Kh/AUPUkZRxzXaQuBvcMAx7uTbRhi59:4e/UmwuZvthh/AUMEZuBEMAx7uv7W9` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_018_a6451ad4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6451ad4f82ed52fdb02fd705438fe1dfc0fcc3b27e4ff3943413fa1e4dcd13e"
    family = "CoinMiner"
    file_name = "a6451ad4f82ed52fdb02fd705438fe1dfc0fcc3b27e4ff3943413fa1e4dcd13e.exe"
    file_type = "exe"
    first_seen = "2026-09-04 02:12:32"
  condition:
    hash.sha256(0, filesize) == "a6451ad4f82ed52fdb02fd705438fe1dfc0fcc3b27e4ff3943413fa1e4dcd13e"
}
```

### Sample 19: `5dd3e4893fdfc147`

| Field | Value |
|---|---|
| SHA-256 | `5dd3e4893fdfc14725eaf22eee3fcf35517cf5f9c71b371632b221daa16f073b` |
| Family label | `Vidar` |
| File name | `5dd3e4893fdfc14725eaf22eee3fcf35517cf5f9c71b371632b221daa16f073b.bin` |
| File type | `exe` |
| First seen | `2026-09-04 01:13:02` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01dbd98d27c2281bfb2e524243172992` |
| SHA-1 | `b7d29f9d5471d0edddd11ed57c69b635e86e5efb` |
| SHA-256 | `5dd3e4893fdfc14725eaf22eee3fcf35517cf5f9c71b371632b221daa16f073b` |
| SHA3-384 | `e1c395dbc29af090a10fca7dd00f34e6a561ee8b2e520c2d4f7b8ab70ffe856522176344b1e35f2338d4625bf492b0fe` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B5E66B03A94655E8C5819E39C0779F11FA68B88CCB3037B76E90EEB42F363D1A979750` |
| SSDEEP | `393216:nNhIgefohvgPHEJiBinV0lk4A2xOXYoUeXusT1oBsQ8hgZeLmlx+IWAdMLNh5eLv:er` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_019_5dd3e489
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dd3e4893fdfc14725eaf22eee3fcf35517cf5f9c71b371632b221daa16f073b"
    family = "Vidar"
    file_name = "5dd3e4893fdfc14725eaf22eee3fcf35517cf5f9c71b371632b221daa16f073b.bin"
    file_type = "exe"
    first_seen = "2026-09-04 01:13:02"
  condition:
    hash.sha256(0, filesize) == "5dd3e4893fdfc14725eaf22eee3fcf35517cf5f9c71b371632b221daa16f073b"
}
```

### Sample 20: `af3b02f403d1c158`

| Field | Value |
|---|---|
| SHA-256 | `af3b02f403d1c158b5bf6a0c8c3297b6c98bd665f76a1714220241f88c29c19c` |
| Family label | `unknown` |
| File name | `af3b02f403d1c158b5bf6a0c8c3297b6c98bd665f76a1714220241f88c29c19c.bin` |
| File type | `exe` |
| First seen | `2026-09-04 01:13:00` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd30a19289c177848f75dc56692ac7b2` |
| SHA-1 | `dac3cc59e66aa8a7ceca499d92f10266816dc9e1` |
| SHA-256 | `af3b02f403d1c158b5bf6a0c8c3297b6c98bd665f76a1714220241f88c29c19c` |
| SHA3-384 | `f64fb8aef17c01d1e8e9f3f6d81f7562ff74fc8b60cae6250244ae78d04b91196d11fb2ee82074700a6f5b628018a497` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T149667C836D8661B4E499DB75D0662195E2207C8D6B7033D72D05FBB12E33BC82EB8F58` |
| SSDEEP | `98304:spDUCilNDrAJ7CR33lESRNioba8s3VwzIzO:spyNDuW9lpRNtpsUP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_af3b02f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af3b02f403d1c158b5bf6a0c8c3297b6c98bd665f76a1714220241f88c29c19c"
    family = "unknown"
    file_name = "af3b02f403d1c158b5bf6a0c8c3297b6c98bd665f76a1714220241f88c29c19c.bin"
    file_type = "exe"
    first_seen = "2026-09-04 01:13:00"
  condition:
    hash.sha256(0, filesize) == "af3b02f403d1c158b5bf6a0c8c3297b6c98bd665f76a1714220241f88c29c19c"
}
```

### Sample 21: `e8ea06ea59484643`

| Field | Value |
|---|---|
| SHA-256 | `e8ea06ea59484643d43227b3ceb46a914e214ff5744d80c0324b80cf5afbb954` |
| Family label | `unknown` |
| File name | `e8ea06ea59484643d43227b3ceb46a914e214ff5744d80c0324b80cf5afbb954.bin` |
| File type | `exe` |
| First seen | `2026-09-04 01:12:58` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca7ca4816f3263902d5c60434d3aff35` |
| SHA-1 | `aa2dad2dd06b7be5e613398507fa024f82eb5aff` |
| SHA-256 | `e8ea06ea59484643d43227b3ceb46a914e214ff5744d80c0324b80cf5afbb954` |
| SHA3-384 | `2a295c78095e352db78f7bd689b4a90999d4530c74d24bdc546ea9f190b48f89e763ef49d16a2c694844b17b88bb866e` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1FBE64A07254442E8E892E37CE07F02B15976FC4CE33136A71E8AB5B47EB6BC5A5B5B10` |
| SSDEEP | `98304:MacYnw2GIwOpQO3TvQBq8RxLR6HtdGW85x:MIw25wOpQODoBq8RxLRiEV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_e8ea06ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8ea06ea59484643d43227b3ceb46a914e214ff5744d80c0324b80cf5afbb954"
    family = "unknown"
    file_name = "e8ea06ea59484643d43227b3ceb46a914e214ff5744d80c0324b80cf5afbb954.bin"
    file_type = "exe"
    first_seen = "2026-09-04 01:12:58"
  condition:
    hash.sha256(0, filesize) == "e8ea06ea59484643d43227b3ceb46a914e214ff5744d80c0324b80cf5afbb954"
}
```

### Sample 22: `7450f96b28ad9b0b`

| Field | Value |
|---|---|
| SHA-256 | `7450f96b28ad9b0ba92afbaef480f63d61105afcdb451650ed3a04269ff428ce` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-04 00:23:06` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e812865a0bee8712993d1a3ea72429f` |
| SHA-1 | `0cede6c3efdf7e4c0fb91a771ea95b753c577124` |
| SHA-256 | `7450f96b28ad9b0ba92afbaef480f63d61105afcdb451650ed3a04269ff428ce` |
| SHA3-384 | `8d742ff7eac97df475a482b5682e777978b80b2ebc5f169e004f82eae99bfdbf56e8a2496ac3367641342f938e5caf95` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T101771256E2FD00E8D5BAC0BCC6575517EBB23459173097EB52A48A692F33BE0AE3D310` |
| SSDEEP | `786432:quMLaAXoeOvHiwB3sn+h1hO25F+wX0ff6yajCs6+4S3NftY:q5joeeCwDrhOG+tf6fj4ulY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_7450f96b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7450f96b28ad9b0ba92afbaef480f63d61105afcdb451650ed3a04269ff428ce"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-04 00:23:06"
  condition:
    hash.sha256(0, filesize) == "7450f96b28ad9b0ba92afbaef480f63d61105afcdb451650ed3a04269ff428ce"
}
```

### Sample 23: `cd6c8133df97e789`

| Field | Value |
|---|---|
| SHA-256 | `cd6c8133df97e789160d9c5cc6ef385c2fbe69055b3d7d89d7a14d642a6e4371` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-04 00:22:11` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b69247e1eb1d465f69d4b70d560709c8` |
| SHA-1 | `7cdcb306f8b6a9081da35e52f478b816fef31732` |
| SHA-256 | `cd6c8133df97e789160d9c5cc6ef385c2fbe69055b3d7d89d7a14d642a6e4371` |
| SHA3-384 | `06cff032247d1a454bc7e7feb4a213ac34669c58b423291c4b935d86975163cbc6a91542ebb42d0770af29727d991f52` |
| IMPHASH | `1dcd477cce07724ec6b817b3be71540e` |
| TLSH | `T1667633557AE108FAF4A3833C4D934D12EB75F8631371E6CB07A185A62F236F2293A355` |
| SSDEEP | `196608:5tG9mt9nGCxdGjP5HMwJTWe88E0MFtBwtw:/G8t9nGCnGj5MwBWj8E0MF0m` |
| ICON-DHASH | `c8f0ce4e8e8eb082` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_cd6c8133
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd6c8133df97e789160d9c5cc6ef385c2fbe69055b3d7d89d7a14d642a6e4371"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-04 00:22:11"
  condition:
    hash.sha256(0, filesize) == "cd6c8133df97e789160d9c5cc6ef385c2fbe69055b3d7d89d7a14d642a6e4371"
}
```

### Sample 24: `1f38faff67a42b61`

| Field | Value |
|---|---|
| SHA-256 | `1f38faff67a42b61ebd3fd6dfe2d5cffcd612336d7a6ec4e6dd491322fedd2e3` |
| Family label | `Vidar` |
| File name | `1f38faff67a42b61ebd3fd6dfe2d5cffcd612336d7a6ec4e6dd491322fedd2e3.bin` |
| File type | `exe` |
| First seen | `2026-09-04 00:09:30` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acc7bc23283c51d57a568f79ecad4cc7` |
| SHA-1 | `e8d9066c1365262bbe581790cc2a728c2815e0ba` |
| SHA-256 | `1f38faff67a42b61ebd3fd6dfe2d5cffcd612336d7a6ec4e6dd491322fedd2e3` |
| SHA3-384 | `49bfeda2e7644f2bedd2d349c9a2a7e071d34d31f5da72baa3a65f95c79e0f7623e2ce2610aab364a7f61f89f99b2397` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1B1E64B03660442E4E892E778F17F12B16976F84CE33536A31E8AF4B4BEB67D564B4B10` |
| SSDEEP | `49152:7jQ2MrCTrl6xLISqmET0/AUcVOdaFTyKtR8U7XHp1C/xVT0sVh16DbvqvM3iCeS5:HlsLZxW0/fomKtpHqNWOkckH` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_024_1f38faff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f38faff67a42b61ebd3fd6dfe2d5cffcd612336d7a6ec4e6dd491322fedd2e3"
    family = "Vidar"
    file_name = "1f38faff67a42b61ebd3fd6dfe2d5cffcd612336d7a6ec4e6dd491322fedd2e3.bin"
    file_type = "exe"
    first_seen = "2026-09-04 00:09:30"
  condition:
    hash.sha256(0, filesize) == "1f38faff67a42b61ebd3fd6dfe2d5cffcd612336d7a6ec4e6dd491322fedd2e3"
}
```

### Sample 25: `6dc13963c781c3ad`

| Field | Value |
|---|---|
| SHA-256 | `6dc13963c781c3adb3a3b4bc264ee1370ea2c914ca8d728d7d3c740b8375fbeb` |
| Family label | `Vidar` |
| File name | `6dc13963c781c3adb3a3b4bc264ee1370ea2c914ca8d728d7d3c740b8375fbeb.bin` |
| File type | `exe` |
| First seen | `2026-09-04 00:09:27` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45d233e81ed77def3bfad051c18a2f0a` |
| SHA-1 | `7556369bd5e77d3ba91c1163baff3bf0d74b53dc` |
| SHA-256 | `6dc13963c781c3adb3a3b4bc264ee1370ea2c914ca8d728d7d3c740b8375fbeb` |
| SHA3-384 | `31b54a0c9731f370840a61d057d43d620f9e3870d06b98215ea7cdc4d71ec5d0047996af0b53a8f783101187e386eca8` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T18A666B836E86A178E499DB76E06511A5E2207C8D6B7033D32D09FBB11D327D82FB8F54` |
| SSDEEP | `49152:+m9iy90wMqWfZyT3qobMtiK0ecdrxqaA+K23si3BkfLH43G+V8aemRscO51J/Mef:VMMog7A+KFiure3VRscT5yH` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_025_6dc13963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dc13963c781c3adb3a3b4bc264ee1370ea2c914ca8d728d7d3c740b8375fbeb"
    family = "Vidar"
    file_name = "6dc13963c781c3adb3a3b4bc264ee1370ea2c914ca8d728d7d3c740b8375fbeb.bin"
    file_type = "exe"
    first_seen = "2026-09-04 00:09:27"
  condition:
    hash.sha256(0, filesize) == "6dc13963c781c3adb3a3b4bc264ee1370ea2c914ca8d728d7d3c740b8375fbeb"
}
```

### Sample 26: `534f3a82e34e3ac9`

| Field | Value |
|---|---|
| SHA-256 | `534f3a82e34e3ac9a8254229595be2a4e8b07e2373c6a5314f4d1f1b16cf988b` |
| Family label | `a310Logger` |
| File name | `Nuevo pedido.exe` |
| File type | `exe` |
| First seen | `2026-09-03 23:33:18` |
| Reporter | `threatcat_ch` |
| Tags | `a310Logger, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10050bf5bdc1517c62cdd778d4963c12` |
| SHA-1 | `af747328934bb8f65c7511212465b4714e243971` |
| SHA-256 | `534f3a82e34e3ac9a8254229595be2a4e8b07e2373c6a5314f4d1f1b16cf988b` |
| SHA3-384 | `1b862d5b499706397b7f9c9ccfef156305aa0305ca39ae20b65b3fec9ffff12f48df04adcbf850ef4d9ef82f5f6d101a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D015D006BBE4EB14C28FA73DF1E4715D0B72F6195417DB4E6888F6E428A3B2E4D40297` |
| SSDEEP | `12288:NEcBa6ZLRTXK2t1WbLuEHlP5LoG7hvORDW1yJ0yoDoSbVqDuSxBGIZbm1ER15J+/:NEMaCbIbqEFaAORXocSSvzGIZSiF0/` |

#### Technical Assessment

- The sample is tracked as `a310Logger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_a310Logger_026_534f3a82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "534f3a82e34e3ac9a8254229595be2a4e8b07e2373c6a5314f4d1f1b16cf988b"
    family = "a310Logger"
    file_name = "Nuevo pedido.exe"
    file_type = "exe"
    first_seen = "2026-09-03 23:33:18"
  condition:
    hash.sha256(0, filesize) == "534f3a82e34e3ac9a8254229595be2a4e8b07e2373c6a5314f4d1f1b16cf988b"
}
```

### Sample 27: `510b4341c6763d5b`

| Field | Value |
|---|---|
| SHA-256 | `510b4341c6763d5bf045973f4f9832cb8b66a414abda634d4fafed05cba03058` |
| Family label | `Vidar` |
| File name | `510b4341c6763d5bf045973f4f9832cb8b66a414abda634d4fafed05cba03058.exe` |
| File type | `exe` |
| First seen | `2026-09-03 22:53:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, Vidar, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8613f7cf245682042c40cb4a91ed7e4` |
| SHA-1 | `2097a671c1791c402cf2c1d7bde3e1715766cd44` |
| SHA-256 | `510b4341c6763d5bf045973f4f9832cb8b66a414abda634d4fafed05cba03058` |
| SHA3-384 | `fb3f3d925b663970ee771d3c3e81523b09904fcf61458865c5617ed87e50ef9f3f2e942b77ec85189155bc3c223ee669` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T16E05CE04A259B4D8E06644F784C1371DAA66FE0032C06EDA7ACFB6716E31BD0EDDBE50` |
| SSDEEP | `24576:e/Ksjp4tiFKMV4Ta8FUa6+f8VnMsLCGJK6M3Lyj1:MK1k7V4rS+f8LCGJ9MGj` |
| ICON-DHASH | `78f8bcf2b2b0f059` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_027_510b4341
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "510b4341c6763d5bf045973f4f9832cb8b66a414abda634d4fafed05cba03058"
    family = "Vidar"
    file_name = "510b4341c6763d5bf045973f4f9832cb8b66a414abda634d4fafed05cba03058.exe"
    file_type = "exe"
    first_seen = "2026-09-03 22:53:10"
  condition:
    hash.sha256(0, filesize) == "510b4341c6763d5bf045973f4f9832cb8b66a414abda634d4fafed05cba03058"
}
```

### Sample 28: `446cd26639c2d1e0`

| Field | Value |
|---|---|
| SHA-256 | `446cd26639c2d1e09dd9d9edebbd7150d6d5c0f40a4f63c534430c5974a95879` |
| Family label | `Vidar` |
| File name | `446cd26639c2d1e09dd9d9edebbd7150d6d5c0f40a4f63c534430c5974a95879.exe` |
| File type | `exe` |
| First seen | `2026-09-03 22:53:07` |
| Reporter | `Tuxxin` |
| Tags | `exe, Vidar, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10093ec92c6e6e7f65adfc8221558abe` |
| SHA-1 | `8282e870a739bae872ceee177065582e80c92118` |
| SHA-256 | `446cd26639c2d1e09dd9d9edebbd7150d6d5c0f40a4f63c534430c5974a95879` |
| SHA3-384 | `ad87e0a57a7071989f46cd8ab8dca9bc45384bcfdab14b0418a650ab98803473b6dfd644d1fd537a8ebe224b98b12e2a` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T12205CE04A56A70E8E06645F384D1771DA636BE0472D05DDA3ADFB271AE327D0ECEBE10` |
| SSDEEP | `12288:pVrlS/4bYBrT7WAV8K3RNPdaOekFd58CUsIYDJKDfnP4aH4kmP4mdSjc103nY3:k/48BrhtjXH1dI4aH4kmP4mAY1gnM` |
| ICON-DHASH | `78f8bcf2b2b0f059` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_028_446cd266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "446cd26639c2d1e09dd9d9edebbd7150d6d5c0f40a4f63c534430c5974a95879"
    family = "Vidar"
    file_name = "446cd26639c2d1e09dd9d9edebbd7150d6d5c0f40a4f63c534430c5974a95879.exe"
    file_type = "exe"
    first_seen = "2026-09-03 22:53:07"
  condition:
    hash.sha256(0, filesize) == "446cd26639c2d1e09dd9d9edebbd7150d6d5c0f40a4f63c534430c5974a95879"
}
```

### Sample 29: `10c378d0449cf705`

| Field | Value |
|---|---|
| SHA-256 | `10c378d0449cf7055587933980da9a48ad35a9f71543276573318a6b898c5734` |
| Family label | `unknown` |
| File name | `10c378d0449cf7055587933980da9a48ad35a9f71543276573318a6b898c5734.bin` |
| File type | `exe` |
| First seen | `2026-09-03 22:44:01` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1eb1591a170833c1744859e0462ba9d` |
| SHA-1 | `ee301fa152cce60a04038cbe58d7eeb445cede16` |
| SHA-256 | `10c378d0449cf7055587933980da9a48ad35a9f71543276573318a6b898c5734` |
| SHA3-384 | `2fe83d037df9a3e10a04a3a31107234d7e8ed8103e73cdfec17d504bdfe75a457d1ac79174bf097ba320e97736f37e41` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T161668D03A98554F4D865DE34C27A9662BA74FC8EDB3533D31E40AAB42F357D09AFA340` |
| SSDEEP | `98304:5uJHHEvQIUVhAItXBrzhfmn1jgaNSxib9PvlCeCf3f:5KHrIUVR9lxxKlgz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_10c378d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10c378d0449cf7055587933980da9a48ad35a9f71543276573318a6b898c5734"
    family = "unknown"
    file_name = "10c378d0449cf7055587933980da9a48ad35a9f71543276573318a6b898c5734.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:44:01"
  condition:
    hash.sha256(0, filesize) == "10c378d0449cf7055587933980da9a48ad35a9f71543276573318a6b898c5734"
}
```

### Sample 30: `c2673f1f23d1d4e6`

| Field | Value |
|---|---|
| SHA-256 | `c2673f1f23d1d4e65091b266a84020252600f71f1469f3bbce928f0ffb2468ce` |
| Family label | `unknown` |
| File name | `c2673f1f23d1d4e65091b266a84020252600f71f1469f3bbce928f0ffb2468ce.bin` |
| File type | `exe` |
| First seen | `2026-09-03 22:43:59` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `471a67e954a37edaa1684977797ff023` |
| SHA-1 | `e9d243139f9f805be7da3b0b7342cf3eef55b66d` |
| SHA-256 | `c2673f1f23d1d4e65091b266a84020252600f71f1469f3bbce928f0ffb2468ce` |
| SHA3-384 | `6bb6f33e897a75000c9f3be134e893f0c44eeb6d91204d699087983ddb56cc2b7f141061ea83b69c85e59f03faf23ec8` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1092833077CA565A4CADA9638C2B542523634788DAB3137EB2F91F2B42F327D1AF75310` |
| SSDEEP | `1572864:cP085tT9cx8jFxVDSnjG26puhVsM3ViJE5gRdX0/lRlCybp7lVkRwxtdgJlR:u0wexYxVDSnj3hViG5SDyd7luR/R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_c2673f1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2673f1f23d1d4e65091b266a84020252600f71f1469f3bbce928f0ffb2468ce"
    family = "unknown"
    file_name = "c2673f1f23d1d4e65091b266a84020252600f71f1469f3bbce928f0ffb2468ce.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:43:59"
  condition:
    hash.sha256(0, filesize) == "c2673f1f23d1d4e65091b266a84020252600f71f1469f3bbce928f0ffb2468ce"
}
```

### Sample 31: `23343f092bcd84f3`

| Field | Value |
|---|---|
| SHA-256 | `23343f092bcd84f3781c7946aa827dcaf19beedcf09d72358bcbff6d203a4190` |
| Family label | `unknown` |
| File name | `23343f092bcd84f3781c7946aa827dcaf19beedcf09d72358bcbff6d203a4190.bin` |
| File type | `exe` |
| First seen | `2026-09-03 22:43:51` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a98a2a9a2aeecfc4bfc0c4c9bf68828a` |
| SHA-1 | `5a49dc2ea74b20d0996e37631377f53cad11ccab` |
| SHA-256 | `23343f092bcd84f3781c7946aa827dcaf19beedcf09d72358bcbff6d203a4190` |
| SHA3-384 | `3491fcd3eafc4bb7df730dd3246971d808b7531ec326309e82e4b237c89b592c8991b4710c33c4622d10f49666a29c7e` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1A32833077CEAA498CADA8638D67542527634784EAB3137E72F92F2B02F767D05B74310` |
| SSDEEP | `1572864:cPy6CUYQmbND6WhvGS8Ew4moctL8QWidC2o3ZMLeHsmQmEOtTFvqfkJ0lIij3XD:u/16NlhM4moctL8QWidC/MLvbmESBvKB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_23343f09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23343f092bcd84f3781c7946aa827dcaf19beedcf09d72358bcbff6d203a4190"
    family = "unknown"
    file_name = "23343f092bcd84f3781c7946aa827dcaf19beedcf09d72358bcbff6d203a4190.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:43:51"
  condition:
    hash.sha256(0, filesize) == "23343f092bcd84f3781c7946aa827dcaf19beedcf09d72358bcbff6d203a4190"
}
```

### Sample 32: `c69a7da796aba716`

| Field | Value |
|---|---|
| SHA-256 | `c69a7da796aba7168e1edd6c7b8d573592f17a1a8fb74d3307cc68ccf8203bde` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-03 22:37:45` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX11.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d0bcbf2bb061671bacfb953cc4a40d6` |
| SHA-1 | `e5acc02151fc53d6cd6ee357d38df47f5ca30e17` |
| SHA-256 | `c69a7da796aba7168e1edd6c7b8d573592f17a1a8fb74d3307cc68ccf8203bde` |
| SHA3-384 | `5cf8c58f8b772d77c67070b16b325dff48197c94b4a64b8c8aa4c662d6a75e4dbbddde2852f0a18323bbef802a020910` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1B5E67B4BE85555E9C1AD9231CAA692137BB17C090B3263C71B60F7383F76BD46EBA310` |
| SSDEEP | `196608:AMGgWWV5cVARrbDHqKNJ9zZTgqemC88xbXVY5i6:AIzrVNJ9dUqey0XVY86` |
| ICON-DHASH | `8e33d4d4d4d433cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_c69a7da7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c69a7da796aba7168e1edd6c7b8d573592f17a1a8fb74d3307cc68ccf8203bde"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 22:37:45"
  condition:
    hash.sha256(0, filesize) == "c69a7da796aba7168e1edd6c7b8d573592f17a1a8fb74d3307cc68ccf8203bde"
}
```

### Sample 33: `e811d2180a7fecb0`

| Field | Value |
|---|---|
| SHA-256 | `e811d2180a7fecb0b594623846198e963e5172caa40bcaa2e50577fdde49a422` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-03 22:05:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd91da9333af65ffde2611a52b1f9b75` |
| SHA-1 | `1e00a50f2cc1a44243d748d774d6e38ba52d0cac` |
| SHA-256 | `e811d2180a7fecb0b594623846198e963e5172caa40bcaa2e50577fdde49a422` |
| SHA3-384 | `6c6d94ed5153a875d26f9f1d1da2c8af2418e1b6af580ebfc84263073395334b6dc238e180395fb09146a524339ba323` |
| TLSH | `T1BA235C512A857C14AA98C8371D7F2F0CB9A943E6324452DE7FCF3CF68C4AA9DA10971D` |
| SSDEEP | `768:RkFWzZx5S9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Skzdcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_e811d218
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e811d2180a7fecb0b594623846198e963e5172caa40bcaa2e50577fdde49a422"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 22:05:27"
  condition:
    hash.sha256(0, filesize) == "e811d2180a7fecb0b594623846198e963e5172caa40bcaa2e50577fdde49a422"
}
```

### Sample 34: `b84f28bf2872715a`

| Field | Value |
|---|---|
| SHA-256 | `b84f28bf2872715a977aafd9215358d078ae942c6e8ab1c5b397c189c9f5f970` |
| Family label | `Vidar` |
| File name | `b84f28bf2872715a977aafd9215358d078ae942c6e8ab1c5b397c189c9f5f970.bin` |
| File type | `exe` |
| First seen | `2026-09-03 22:03:23` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41bad6cfd16b196a7359a0a18e20bb2c` |
| SHA-1 | `cad93a89919df37befb609fdb0d99ea2a0eecdcd` |
| SHA-256 | `b84f28bf2872715a977aafd9215358d078ae942c6e8ab1c5b397c189c9f5f970` |
| SHA3-384 | `fa98d162d3b339fc1e52d30d74c4ddf01d6e10e3fbe5c03c35b1f75b7b4e4013148bc2953b182a7dcbb68d361bf69f31` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T155C67C17A92502E9C9A5DB74C4B742427B78B84C8B3133E76E10BA742F757D0BEBA314` |
| SSDEEP | `98304:deXjoMk15VpUgM75QSPecpiFn7n07M7SRhS++ccTRT5:dmoMip1MQSPecYR07fls15` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_034_b84f28bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b84f28bf2872715a977aafd9215358d078ae942c6e8ab1c5b397c189c9f5f970"
    family = "Vidar"
    file_name = "b84f28bf2872715a977aafd9215358d078ae942c6e8ab1c5b397c189c9f5f970.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:03:23"
  condition:
    hash.sha256(0, filesize) == "b84f28bf2872715a977aafd9215358d078ae942c6e8ab1c5b397c189c9f5f970"
}
```

### Sample 35: `f0ceeb924803c553`

| Field | Value |
|---|---|
| SHA-256 | `f0ceeb924803c55384a7491af8af5e229bf25e7e9864e3a94f5eaad4a07d925d` |
| Family label | `unknown` |
| File name | `f0ceeb924803c55384a7491af8af5e229bf25e7e9864e3a94f5eaad4a07d925d.bin` |
| File type | `exe` |
| First seen | `2026-09-03 22:03:20` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46933c3231ec5e14f6817ae25a736099` |
| SHA-1 | `1d0fdef1370805a220a13f209f3cee1e02a15afa` |
| SHA-256 | `f0ceeb924803c55384a7491af8af5e229bf25e7e9864e3a94f5eaad4a07d925d` |
| SHA3-384 | `6935c75c46dccaae36d6e5fffb20d9814696cae29129dcb8b1356893e342048a78fe7617bdac4482116b5ac50bafdc61` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T16E2833077CA664A8CADA9638D67542533634784DAB3037EB2F91F2B42F767E09B74310` |
| SSDEEP | `1572864:cP2JF+Vah6bjEO1BX1usrH6Im02+UDIZa4NGrCPKim8JoknepIfsakftsiEi5w:u2PXJOjFrrH5brUDbUGrCCcJ8eefre` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_f0ceeb92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0ceeb924803c55384a7491af8af5e229bf25e7e9864e3a94f5eaad4a07d925d"
    family = "unknown"
    file_name = "f0ceeb924803c55384a7491af8af5e229bf25e7e9864e3a94f5eaad4a07d925d.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:03:20"
  condition:
    hash.sha256(0, filesize) == "f0ceeb924803c55384a7491af8af5e229bf25e7e9864e3a94f5eaad4a07d925d"
}
```

### Sample 36: `56b77af451ae0a13`

| Field | Value |
|---|---|
| SHA-256 | `56b77af451ae0a131689e1cb3a8964b210403cded8d5ea67fa2b6ec24edabab7` |
| Family label | `unknown` |
| File name | `56b77af451ae0a131689e1cb3a8964b210403cded8d5ea67fa2b6ec24edabab7.bin` |
| File type | `exe` |
| First seen | `2026-09-03 22:03:12` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fb71121735dce231c14f87acb1ee271` |
| SHA-1 | `392bd45a3274658c49b3156da00cbbd78f62cfd9` |
| SHA-256 | `56b77af451ae0a131689e1cb3a8964b210403cded8d5ea67fa2b6ec24edabab7` |
| SHA3-384 | `7d0cc1148d8367eed18db231b7a02d1e42dda0388670f9ab2992621663ac0a3e3965b30de3336678a31071f57c152d6d` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1332833077CA565A8CADE9638D6B542537634784EAB3033EB2F82B2B42F727D15B74310` |
| SSDEEP | `1572864:cPOgijZQ1YG2q7+d8zRXHUSXofymkRf1GeW4WUGKwl/Qsnv:uSZQ1YG2q7LzR3UScyrfceBjE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_56b77af4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56b77af451ae0a131689e1cb3a8964b210403cded8d5ea67fa2b6ec24edabab7"
    family = "unknown"
    file_name = "56b77af451ae0a131689e1cb3a8964b210403cded8d5ea67fa2b6ec24edabab7.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:03:12"
  condition:
    hash.sha256(0, filesize) == "56b77af451ae0a131689e1cb3a8964b210403cded8d5ea67fa2b6ec24edabab7"
}
```

### Sample 37: `593b391a23ff5669`

| Field | Value |
|---|---|
| SHA-256 | `593b391a23ff56696eb2ba54a45ec5eb9c6c574d2b45f5da8ef324cfa3dca95e` |
| Family label | `unknown` |
| File name | `593b391a23ff56696eb2ba54a45ec5eb9c6c574d2b45f5da8ef324cfa3dca95e.bin` |
| File type | `exe` |
| First seen | `2026-09-03 22:03:05` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68a302bd4a8f9bd9a533b3f80771e21f` |
| SHA-1 | `1673484eda0df81c82544935795534d40ea46396` |
| SHA-256 | `593b391a23ff56696eb2ba54a45ec5eb9c6c574d2b45f5da8ef324cfa3dca95e` |
| SHA3-384 | `fdcb8943d88360986c2f1e4aa7bf95b98fc8bd76ae04bcd0aeeab9491055b9fb7fab44da54e8fd0f96f736ef645edfca` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1C92833037CA564A4CADA9638D2B642427734784E9B3033EB2F92F2B42F767E15B75311` |
| SSDEEP | `1572864:cPu1innTA/MUU6RXj3lrCJwIe+udZy1e9NfX9uLAgeVufKV5crN/j+W59OW7L/:uBTA/MhUj3cheR8yZX9tT5c5B591H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_593b391a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "593b391a23ff56696eb2ba54a45ec5eb9c6c574d2b45f5da8ef324cfa3dca95e"
    family = "unknown"
    file_name = "593b391a23ff56696eb2ba54a45ec5eb9c6c574d2b45f5da8ef324cfa3dca95e.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:03:05"
  condition:
    hash.sha256(0, filesize) == "593b391a23ff56696eb2ba54a45ec5eb9c6c574d2b45f5da8ef324cfa3dca95e"
}
```

### Sample 38: `27acfd79d14615e5`

| Field | Value |
|---|---|
| SHA-256 | `27acfd79d14615e57aaaf388585dcd0be08ec68e2b5518f01e9e34fccb0bc580` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-03 21:59:10` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6f5e367cf7db179a4cd2b4dc9510c2c` |
| SHA-1 | `ce39c3c968ba57475d0317f54f9a86ffb0536584` |
| SHA-256 | `27acfd79d14615e57aaaf388585dcd0be08ec68e2b5518f01e9e34fccb0bc580` |
| SHA3-384 | `33a6247aaf9536516a8b3735a2b2acca733b193a65a92a3718a329690654dab96a89053915652c6f80393f3931dd1cb2` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T130771256E2FD00E8D5BAC0BCC6575517EBB23459173097EB52A48A692F33BE0AE3D310` |
| SSDEEP | `786432:/uMLDPXoeOvHiwBBsn+h1hW25F+wX0ff6yajCs6+4S3NftH:/5ToeeCwBrhWG+tf6fj4ulH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_27acfd79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27acfd79d14615e57aaaf388585dcd0be08ec68e2b5518f01e9e34fccb0bc580"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 21:59:10"
  condition:
    hash.sha256(0, filesize) == "27acfd79d14615e57aaaf388585dcd0be08ec68e2b5518f01e9e34fccb0bc580"
}
```

### Sample 39: `9d167a03a2b930cd`

| Field | Value |
|---|---|
| SHA-256 | `9d167a03a2b930cd2a35629de0bccb266650b00b3fafa30536f354b58d2364b0` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-03 21:56:09` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64529579182264a1c870bfbed7863602` |
| SHA-256 | `9d167a03a2b930cd2a35629de0bccb266650b00b3fafa30536f354b58d2364b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_9d167a03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d167a03a2b930cd2a35629de0bccb266650b00b3fafa30536f354b58d2364b0"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 21:56:09"
  condition:
    hash.sha256(0, filesize) == "9d167a03a2b930cd2a35629de0bccb266650b00b3fafa30536f354b58d2364b0"
}
```

### Sample 40: `f5c154134bce86be`

| Field | Value |
|---|---|
| SHA-256 | `f5c154134bce86beb4386680a8b5ae47dde22bbba2de5930451a4799c84ed9a8` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-03 21:47:35` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58851fa3aea1642f3b503e2d008ba249` |
| SHA-1 | `73923d74032ec6c12889d76f0bdb900fe252b9c2` |
| SHA-256 | `f5c154134bce86beb4386680a8b5ae47dde22bbba2de5930451a4799c84ed9a8` |
| SHA3-384 | `2fb5aed43594bc9f591f26d1ac13945bbdddb77b41459fa814e554572b242f1d649404e03bafc66dea72b5388f2d9ac7` |
| TLSH | `T18D3172DE00255B351542CE8E77B33048A18DB1EB689FD7D898580EE98288BCCF576F8D` |
| SSDEEP | `24:zX6l/EJbd0I4e2VpQGtPrkJvHdyeZ+688K:b6lcKVpQGxaAey` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_f5c15413
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c154134bce86beb4386680a8b5ae47dde22bbba2de5930451a4799c84ed9a8"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-03 21:47:35"
  condition:
    hash.sha256(0, filesize) == "f5c154134bce86beb4386680a8b5ae47dde22bbba2de5930451a4799c84ed9a8"
}
```

### Sample 41: `d6a5ec91bf15db17`

| Field | Value |
|---|---|
| SHA-256 | `d6a5ec91bf15db1764e679ad0c72e83231c4558df1b670435db983c387183cab` |
| Family label | `unknown` |
| File name | `asir.vbs` |
| File type | `vbs` |
| First seen | `2026-09-03 21:46:08` |
| Reporter | `skocherhan` |
| Tags | `baolongwes-oss-ap-southeast-1-aliyuncs-com, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae5ae7829e21ae0e9fbf4b7c62531417` |
| SHA-1 | `970b364f63dfa99692e2a829f732d5159b7ada77` |
| SHA-256 | `d6a5ec91bf15db1764e679ad0c72e83231c4558df1b670435db983c387183cab` |
| SHA3-384 | `1e130aa4aaa689d0250c280b4049f6685c512ed260d5209ebda55dda426953c8d2af3664fc52dc1811b1283d83a7fc77` |
| TLSH | `T12722B463120BE2F2C0F261072677A50EFA41B57755F2B439BDDC4400DF61B5993DA8DA` |
| SSDEEP | `192:g+Sydu0/9do26pC7cDYF7HL1zU1/qVauF/f/7A/egUwbO4PgQC8:gzydVfo/pC41/SaMJ3wb/17` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_d6a5ec91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6a5ec91bf15db1764e679ad0c72e83231c4558df1b670435db983c387183cab"
    family = "unknown"
    file_name = "asir.vbs"
    file_type = "vbs"
    first_seen = "2026-09-03 21:46:08"
  condition:
    hash.sha256(0, filesize) == "d6a5ec91bf15db1764e679ad0c72e83231c4558df1b670435db983c387183cab"
}
```

### Sample 42: `74405a7d486faf2f`

| Field | Value |
|---|---|
| SHA-256 | `74405a7d486faf2f6f860ea2ef655057ff24ed4291f8f6f5fae1476438cf83ec` |
| Family label | `Hajime` |
| File name | `.i` |
| File type | `elf` |
| First seen | `2026-09-03 21:38:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Hajime` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0520090c03dcc7fc1d8ac3c1caa3d1fb` |
| SHA-1 | `50c5b5f32c053f705c7ba045cf18715b824f42cf` |
| SHA-256 | `74405a7d486faf2f6f860ea2ef655057ff24ed4291f8f6f5fae1476438cf83ec` |
| SHA3-384 | `fdb49c2f5bed36998788c020c8db48336f60dbda09eb74fbbc337eaa3878ec869614a7de93aed789766913df5c6a69dd` |
| TLSH | `T1C973121623AD296552214AF1E7FE6B88E10E3A688FF16C247C217C68E9323AD1CD8519` |
| SSDEEP | `1536:yYI0ARqw1qAEW67UIWi7M8gmfmJo0WgswnD6Efyq8PxlRkp2K3f:yYI0ARqw1qAEv7UIFM8oJorFquyjkRkd` |

#### Technical Assessment

- The sample is tracked as `Hajime` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Hajime_042_74405a7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74405a7d486faf2f6f860ea2ef655057ff24ed4291f8f6f5fae1476438cf83ec"
    family = "Hajime"
    file_name = ".i"
    file_type = "elf"
    first_seen = "2026-09-03 21:38:21"
  condition:
    hash.sha256(0, filesize) == "74405a7d486faf2f6f860ea2ef655057ff24ed4291f8f6f5fae1476438cf83ec"
}
```

### Sample 43: `8d052ddfa9a02d35`

| Field | Value |
|---|---|
| SHA-256 | `8d052ddfa9a02d357839dfcbf9bb6e339e7d96006e01c63738dcca15088c515d` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-03 21:26:08` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b84e2026b398745062a1174149be1fd3` |
| SHA-1 | `c7f3b0673f614ec6c983027a79324cb865e00ae1` |
| SHA-256 | `8d052ddfa9a02d357839dfcbf9bb6e339e7d96006e01c63738dcca15088c515d` |
| SHA3-384 | `5d48bd2f56c12ea6f26b1c30e3aea01fa33a6bb8f474537c8647537aad4f6dcd25ea364c899b8bfef4142e96be9f6dd2` |
| TLSH | `T13E235C552A857C14AA98C8371D7F2F0CB9A943E6320452DE7FCF3CF68C4AA9D920961D` |
| SSDEEP | `768:YQFWzZx5b9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:rkzWcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_8d052ddf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d052ddfa9a02d357839dfcbf9bb6e339e7d96006e01c63738dcca15088c515d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 21:26:08"
  condition:
    hash.sha256(0, filesize) == "8d052ddfa9a02d357839dfcbf9bb6e339e7d96006e01c63738dcca15088c515d"
}
```

### Sample 44: `f3448e6541987ff3`

| Field | Value |
|---|---|
| SHA-256 | `f3448e6541987ff34dfdbf86b8041f2965bae032a6c07275cf581278e3f9e87c` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-03 21:19:57` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb0b43b99de90c77dc7fd731e08e83cb` |
| SHA-256 | `f3448e6541987ff34dfdbf86b8041f2965bae032a6c07275cf581278e3f9e87c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_f3448e65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3448e6541987ff34dfdbf86b8041f2965bae032a6c07275cf581278e3f9e87c"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 21:19:57"
  condition:
    hash.sha256(0, filesize) == "f3448e6541987ff34dfdbf86b8041f2965bae032a6c07275cf581278e3f9e87c"
}
```

### Sample 45: `468e9a99e5396616`

| Field | Value |
|---|---|
| SHA-256 | `468e9a99e5396616920ed8fbfcb805cf41744e825a51f97182b4c32265d9e5c0` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-03 21:19:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `189d471c5d96cf926778ebb85ae88758` |
| SHA-1 | `011fefd2707fbe2038e29ed838748d8ea55f58b9` |
| SHA-256 | `468e9a99e5396616920ed8fbfcb805cf41744e825a51f97182b4c32265d9e5c0` |
| SHA3-384 | `5211ddd23852fb47079b469b20dab65c0597013906648e0a495b659de07fa1201115de9154a58af4207d46572cd6694f` |
| TLSH | `T1E8C27E956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:F8vCB+25j6es8R4p9FYpMSUpi+20qUpi+20YQX:F8l25J6d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_468e9a99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "468e9a99e5396616920ed8fbfcb805cf41744e825a51f97182b4c32265d9e5c0"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 21:19:56"
  condition:
    hash.sha256(0, filesize) == "468e9a99e5396616920ed8fbfcb805cf41744e825a51f97182b4c32265d9e5c0"
}
```

### Sample 46: `364430d2928b2093`

| Field | Value |
|---|---|
| SHA-256 | `364430d2928b2093931be171cbb7843362e58e84909c69f94afd8031669fc147` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-03 21:12:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfd3937a0520f29d03854891c6106e58` |
| SHA-1 | `b794d150a045eb1267e989ec430c06128fd43cb8` |
| SHA-256 | `364430d2928b2093931be171cbb7843362e58e84909c69f94afd8031669fc147` |
| SHA3-384 | `0995fb02fb4487b0c939ce3f603bb49a010800285e1bb032caf483f795347b7adc0be36f2206d1e6d1a923c88daa7bb6` |
| TLSH | `T198C27D956A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:/e8vCB+25j6es8Rp9FYpMSUpi+20qUpi+20YQX:/e8l25JPd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_364430d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "364430d2928b2093931be171cbb7843362e58e84909c69f94afd8031669fc147"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 21:12:54"
  condition:
    hash.sha256(0, filesize) == "364430d2928b2093931be171cbb7843362e58e84909c69f94afd8031669fc147"
}
```

### Sample 47: `6ae6dffd29777f4d`

| Field | Value |
|---|---|
| SHA-256 | `6ae6dffd29777f4d2b12c4eeccfcc5098455b7a7965af4a8de60d62c4b62161b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-03 21:12:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `add81dabf53ccac96dd7bd168e629e42` |
| SHA-1 | `c664e4a2d22cfb3569ec3680858f07b2b312152f` |
| SHA-256 | `6ae6dffd29777f4d2b12c4eeccfcc5098455b7a7965af4a8de60d62c4b62161b` |
| SHA3-384 | `4fda45c13701abb1a1027a92c7382e9ad2912e43c5ab1fe5b6c5eaa451109fd608b60a437a7b00c2f52e21262c55c10d` |
| TLSH | `T136235C6516857C24AE98C8361C7E2F0CB9AD43E6324452EE7FCB3CF68C4A69DD109B1D` |
| SSDEEP | `768:C+F9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:C+Wcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_6ae6dffd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ae6dffd29777f4d2b12c4eeccfcc5098455b7a7965af4a8de60d62c4b62161b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 21:12:53"
  condition:
    hash.sha256(0, filesize) == "6ae6dffd29777f4d2b12c4eeccfcc5098455b7a7965af4a8de60d62c4b62161b"
}
```

### Sample 48: `78d45a3d9b2e82f6`

| Field | Value |
|---|---|
| SHA-256 | `78d45a3d9b2e82f6a181d42f6bf9262d2685bafb84a848201a4377c815c2f50c` |
| Family label | `unknown` |
| File name | `78d45a3d9b2e82f6a181d42f6bf9262d2685bafb84a848201a4377c815c2f50c.exe` |
| File type | `exe` |
| First seen | `2026-09-03 21:12:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `870af744cfdcfbb86a7581cb266fa057` |
| SHA-1 | `8ff2166ccb0d10b97526717ea292ceac18691349` |
| SHA-256 | `78d45a3d9b2e82f6a181d42f6bf9262d2685bafb84a848201a4377c815c2f50c` |
| SHA3-384 | `e945ca758f331a424dd913d7471a8def7d4084002f6e31d46d91c048f28ad43d633b9b663201fed22ccb54b0b9336066` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T105D52399A5B69E74C8B7C3B58F52F4BDB02D3BA44B748E8B77CC68145E126441C3A3B0` |
| SSDEEP | `49152:CFM3jEOLhF8bkgQSjJhi2ntLlm6QwLltQVrtYYHVeJsXFsdQbK4lhNS4Yen:C+TE2hFWBTi2jLQwB2YYVeJX+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_78d45a3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78d45a3d9b2e82f6a181d42f6bf9262d2685bafb84a848201a4377c815c2f50c"
    family = "unknown"
    file_name = "78d45a3d9b2e82f6a181d42f6bf9262d2685bafb84a848201a4377c815c2f50c.exe"
    file_type = "exe"
    first_seen = "2026-09-03 21:12:45"
  condition:
    hash.sha256(0, filesize) == "78d45a3d9b2e82f6a181d42f6bf9262d2685bafb84a848201a4377c815c2f50c"
}
```

### Sample 49: `6e5096f66eb3085e`

| Field | Value |
|---|---|
| SHA-256 | `6e5096f66eb3085ec5d46ddf615298155ef1c46190d56b049fc1c58a145a96b5` |
| Family label | `Hajime` |
| File name | `.i` |
| File type | `elf` |
| First seen | `2026-09-03 21:11:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Hajime` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fe856d558bcae4b0a33000ccb699292` |
| SHA-1 | `e4e08c8d83010d870113cb17b36c1829e117ad7e` |
| SHA-256 | `6e5096f66eb3085ec5d46ddf615298155ef1c46190d56b049fc1c58a145a96b5` |
| SHA3-384 | `72e2ba4d0c9840754a0ad376b79e224d5b288066e9fc36573dd7c0a7de2c7cb5f1e90b2de0c5197556f5c4875d613a6b` |
| TLSH | `T1E673121623E925A1663146F1E3FD2F88F94D6B6C8FF1AC24AC117C98E93336D1CD9518` |
| SSDEEP | `1536:yYI0ARqw1qAEW67UIWi7M8gmfmJo0WgswnD6Efyq8PxlRkp2K3/JV:yYI0ARqw1qAEv7UIFM8oJorFquyjkRkl` |

#### Technical Assessment

- The sample is tracked as `Hajime` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Hajime_049_6e5096f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e5096f66eb3085ec5d46ddf615298155ef1c46190d56b049fc1c58a145a96b5"
    family = "Hajime"
    file_name = ".i"
    file_type = "elf"
    first_seen = "2026-09-03 21:11:51"
  condition:
    hash.sha256(0, filesize) == "6e5096f66eb3085ec5d46ddf615298155ef1c46190d56b049fc1c58a145a96b5"
}
```

### Sample 50: `963724d1dda73996`

| Field | Value |
|---|---|
| SHA-256 | `963724d1dda73996ac4f1f3c323fb731a6151ecde39a14cf0e630b35a739c6fa` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-03 21:04:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21536a3657a291e5747cbf057f37449f` |
| SHA-1 | `a34d139ed7e14b0f9560cf0d7040c481ea06cbed` |
| SHA-256 | `963724d1dda73996ac4f1f3c323fb731a6151ecde39a14cf0e630b35a739c6fa` |
| SHA3-384 | `eb9df1b2054362ce770c77bce2bbbbd8f11055211e16071cd969af874b2bc052302b86bf04dc77b7f11e642a0c4d26e4` |
| TLSH | `T13FC27D966A867C44BDC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11FACD618B2A` |
| SSDEEP | `768:R8vCB+25j6es8Ry9FYpMSUpi+20qUpi+20YQX:R8l25JUd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_963724d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "963724d1dda73996ac4f1f3c323fb731a6151ecde39a14cf0e630b35a739c6fa"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 21:04:33"
  condition:
    hash.sha256(0, filesize) == "963724d1dda73996ac4f1f3c323fb731a6151ecde39a14cf0e630b35a739c6fa"
}
```

### Sample 51: `32bc638e0ae70b24`

| Field | Value |
|---|---|
| SHA-256 | `32bc638e0ae70b242880865bf149dbb8f6a9e8b30211e01382074a234beaa73e` |
| Family label | `unknown` |
| File name | `install.sh` |
| File type | `sh` |
| First seen | `2026-09-03 21:00:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed5518897fb571236ef010e377f8c0ae` |
| SHA-1 | `48687dc7b5a6de60e967e0c1f683d3fdcefa5ca4` |
| SHA-256 | `32bc638e0ae70b242880865bf149dbb8f6a9e8b30211e01382074a234beaa73e` |
| SHA3-384 | `3d54bd3f3760d5fc62bcfca9ed30d0f42e0bac8989dbce1a21b7a19ce22968bd6b08673b342020bbed1ba0b9ce4bef0a` |
| TLSH | `T1A683B622388559B425CCDE6C49FA5C502739C00BCA1A2D2CF05EE5D83F76A78F5FA2D9` |
| SSDEEP | `1536:mUEDcQPyTuvb6jGa5lRUH5Dvf00NRwaEo60D:mW0I5lRUHV00NRwaEo6i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_32bc638e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32bc638e0ae70b242880865bf149dbb8f6a9e8b30211e01382074a234beaa73e"
    family = "unknown"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-09-03 21:00:59"
  condition:
    hash.sha256(0, filesize) == "32bc638e0ae70b242880865bf149dbb8f6a9e8b30211e01382074a234beaa73e"
}
```

### Sample 52: `cd4fe48bb85f3614`

| Field | Value |
|---|---|
| SHA-256 | `cd4fe48bb85f3614623571ffbdc253e6b6d3fec7d90f45fe70febbeff2df3a5b` |
| Family label | `unknown` |
| File name | `.X0-lock_x86_64` |
| File type | `elf` |
| First seen | `2026-09-03 20:48:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ab46f95eb50211ba19d661603b56e50` |
| SHA-1 | `fff69862b8977dc1a885bc3531301b2491bbd2b6` |
| SHA-256 | `cd4fe48bb85f3614623571ffbdc253e6b6d3fec7d90f45fe70febbeff2df3a5b` |
| SHA3-384 | `583f4c50942e0d29c02613516cbe866bbbe58776d17a602c5b5a6e95d0eda4333651b06309460608d13121c091976918` |
| TLSH | `T1DAE56C06B6A244BEC0E6D430838FD573AD35B8594221397F3685AB312E76E305F6DFA1` |
| SSDEEP | `49152:yfZBnpOznLVmmIgfa/rly0j7bdo9fLZPIS5BYDr6awnVCp6RvMYSR:uBWnRo5rl/HJifLZlYLwnVnRXSR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_cd4fe48b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd4fe48bb85f3614623571ffbdc253e6b6d3fec7d90f45fe70febbeff2df3a5b"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-09-03 20:48:52"
  condition:
    hash.sha256(0, filesize) == "cd4fe48bb85f3614623571ffbdc253e6b6d3fec7d90f45fe70febbeff2df3a5b"
}
```

### Sample 53: `1c8be957532c4c60`

| Field | Value |
|---|---|
| SHA-256 | `1c8be957532c4c60de31a897fe0555388e6c1e87ff22199d45ddcbbeee65203c` |
| Family label | `Vidar` |
| File name | `1c8be957532c4c60de31a897fe0555388e6c1e87ff22199d45ddcbbeee65203c.bin` |
| File type | `exe` |
| First seen | `2026-09-03 20:48:13` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd29bb055f538fae540afda8e906ec03` |
| SHA-1 | `648fcafcdaf34c05e1e80bb4e3ce269e63639587` |
| SHA-256 | `1c8be957532c4c60de31a897fe0555388e6c1e87ff22199d45ddcbbeee65203c` |
| SHA3-384 | `5d65000465cb480356d31635188bed2eccd7c10334ec76f52b469606874507fe59357a19f553395847eb7c009a273252` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T164667C836E8662B4E599C771E0612195E2207C8E6F7033D72D45FBB11E32BD82EB8F54` |
| SSDEEP | `49152:9XPUVRM5bHwLGq2b5W3xn7YK8zKSJz26fU0ScP7WB00UTMV8bM/8HYt4iaNAW4Ha:xzbQwOIm8zWBbUA6A5WbNAW4Dcamh` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_053_1c8be957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c8be957532c4c60de31a897fe0555388e6c1e87ff22199d45ddcbbeee65203c"
    family = "Vidar"
    file_name = "1c8be957532c4c60de31a897fe0555388e6c1e87ff22199d45ddcbbeee65203c.bin"
    file_type = "exe"
    first_seen = "2026-09-03 20:48:13"
  condition:
    hash.sha256(0, filesize) == "1c8be957532c4c60de31a897fe0555388e6c1e87ff22199d45ddcbbeee65203c"
}
```

### Sample 54: `0b3c50255286e948`

| Field | Value |
|---|---|
| SHA-256 | `0b3c50255286e9484b4cc1dadad98849d3f5aeb3de6d69345a7786c441473b89` |
| Family label | `unknown` |
| File name | `0b3c50255286e9484b4cc1dadad98849d3f5aeb3de6d69345a7786c441473b89.bin` |
| File type | `exe` |
| First seen | `2026-09-03 20:48:11` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f7852b268a3153f64b45676f131343d` |
| SHA-1 | `f5a97846b0a986dcb7bc4cacd4ea9994f2517a97` |
| SHA-256 | `0b3c50255286e9484b4cc1dadad98849d3f5aeb3de6d69345a7786c441473b89` |
| SHA3-384 | `4a1d98750241bfe409382ce791667cacd524e4e270d5f86fcdcdccac24f6b3919d15c3fccb700be36d9582f60ca770a2` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1D02833077CA66994CADA9238D67542433A34B88E973033EB2F91F2B42F767D19B74311` |
| SSDEEP | `1572864:cPVb0WUw1lmBFjjGHuFesJ9osM/U82oTzzun6T5JyxRjC75ymp2jf59SgZF9+Hu:uCJwjmjjjheXLTzzFFMx5e1p2HnvsHu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_0b3c5025
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b3c50255286e9484b4cc1dadad98849d3f5aeb3de6d69345a7786c441473b89"
    family = "unknown"
    file_name = "0b3c50255286e9484b4cc1dadad98849d3f5aeb3de6d69345a7786c441473b89.bin"
    file_type = "exe"
    first_seen = "2026-09-03 20:48:11"
  condition:
    hash.sha256(0, filesize) == "0b3c50255286e9484b4cc1dadad98849d3f5aeb3de6d69345a7786c441473b89"
}
```

### Sample 55: `54f54235295cf9e4`

| Field | Value |
|---|---|
| SHA-256 | `54f54235295cf9e4cead191b7fd2e027a4bda1c03e163e44f5c3b4f40e1489ce` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-03 20:45:54` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23ce88b7b29615d79fefd90c871a6a8d` |
| SHA-256 | `54f54235295cf9e4cead191b7fd2e027a4bda1c03e163e44f5c3b4f40e1489ce` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_54f54235
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54f54235295cf9e4cead191b7fd2e027a4bda1c03e163e44f5c3b4f40e1489ce"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 20:45:54"
  condition:
    hash.sha256(0, filesize) == "54f54235295cf9e4cead191b7fd2e027a4bda1c03e163e44f5c3b4f40e1489ce"
}
```

### Sample 56: `7a8a6244a95c1ab2`

| Field | Value |
|---|---|
| SHA-256 | `7a8a6244a95c1ab28655155f24e6aee56510b285180aaee49a188127ecf15718` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-03 20:44:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bb14956041a475cad6511c19cc73f0b` |
| SHA-1 | `b5ae15f0173835c2efd0c388c09cb0a6f0803717` |
| SHA-256 | `7a8a6244a95c1ab28655155f24e6aee56510b285180aaee49a188127ecf15718` |
| SHA3-384 | `ac97b0f216236babf7b2f149a3ab001b9c520ccbb3371511c860fe1f0a1702b52d538beca0bc82697f2ad8c696b74219` |
| TLSH | `T1F5315CCA05101A311146CE8F73B2314CB24EA5FB29AFD7E9D8580EAD97886CCF661F4D` |
| SSDEEP | `12:Um6ZpBh2J6QFKMc6MaM6NACrmt6/4wld36dXbDJ36djfE376EhEAmR0YRklSyI6J:svhGjIuAL7z91dMFLEArFi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_7a8a6244
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a8a6244a95c1ab28655155f24e6aee56510b285180aaee49a188127ecf15718"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-03 20:44:48"
  condition:
    hash.sha256(0, filesize) == "7a8a6244a95c1ab28655155f24e6aee56510b285180aaee49a188127ecf15718"
}
```

### Sample 57: `704dcac75a1ac1d0`

| Field | Value |
|---|---|
| SHA-256 | `704dcac75a1ac1d08bc97d3c837a9cd4dc5f7b3ba84056b2557dcf4063638640` |
| Family label | `unknown` |
| File name | `main` |
| File type | `elf` |
| First seen | `2026-09-03 20:37:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `161a727ce030284f7ce094c8eadfcd39` |
| SHA-1 | `c0d088b0b70b8b1c056febef43c2430520743933` |
| SHA-256 | `704dcac75a1ac1d08bc97d3c837a9cd4dc5f7b3ba84056b2557dcf4063638640` |
| SHA3-384 | `36f7990a98a06e0bc4f789698470e52a82d91cb7843eb2e4a3877d9c24d6d9a0834e4c2c5b50f213ec5a81f8ffd9f047` |
| TLSH | `T1F4C57B177CE118AAC0AA92328AB2A692BB71FC490B3123D73F50B37C2F767D45975744` |
| TELFHASH | `t1f6b00121eb906524a6b1da0a6a533e48b46a31e5b0756164299f6101b61c64526d3004` |
| SSDEEP | `49152:6lhAPIoHwyHKx+pF/lHDYAMHajKBDPbAJeIz:QEX/lHDdODPbAJ7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_704dcac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "704dcac75a1ac1d08bc97d3c837a9cd4dc5f7b3ba84056b2557dcf4063638640"
    family = "unknown"
    file_name = "main"
    file_type = "elf"
    first_seen = "2026-09-03 20:37:55"
  condition:
    hash.sha256(0, filesize) == "704dcac75a1ac1d08bc97d3c837a9cd4dc5f7b3ba84056b2557dcf4063638640"
}
```

### Sample 58: `f957c0945b74dbc5`

| Field | Value |
|---|---|
| SHA-256 | `f957c0945b74dbc576c0a945151f1de1e33dc51562003ff2d931e972106cb2d7` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-03 20:36:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff9e194bec5019b6615b1ab08a624248` |
| SHA-1 | `cb6b07fc2f8e4c9b453d81fec5192be9bcfdee53` |
| SHA-256 | `f957c0945b74dbc576c0a945151f1de1e33dc51562003ff2d931e972106cb2d7` |
| SHA3-384 | `ae006a2e218cc35cd370967cc565bb298c0ed599ab6d91f6fb27ec9e7bba21e8bc96281341e46f11175a292ff5e51743` |
| TLSH | `T137236C6516857C14AE99C4365C7F2F0CBDAD43E6314492EE7FCA3CF28C4A6ADA20871D` |
| SSDEEP | `768:Yr9NyXsZztCZ9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:GHusZLcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_f957c094
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f957c0945b74dbc576c0a945151f1de1e33dc51562003ff2d931e972106cb2d7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 20:36:50"
  condition:
    hash.sha256(0, filesize) == "f957c0945b74dbc576c0a945151f1de1e33dc51562003ff2d931e972106cb2d7"
}
```

### Sample 59: `306ce2d64f374155`

| Field | Value |
|---|---|
| SHA-256 | `306ce2d64f3741554000297cc8b8f7ace47c03691e2ec1ee8c5fb4032457430a` |
| Family label | `unknown` |
| File name | `boss` |
| File type | `elf` |
| First seen | `2026-09-03 20:34:59` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bceb746f01ed70443bcd0eace2ef6996` |
| SHA-1 | `018c110769a65955709ef8481f34241766eea57a` |
| SHA-256 | `306ce2d64f3741554000297cc8b8f7ace47c03691e2ec1ee8c5fb4032457430a` |
| SHA3-384 | `9632e8e44c14bc22d41dd585407040fc9e5a94445e8579eaff7cff5bddea7724bcebec4d069017e986b7c20cfdf8decb` |
| TLSH | `T106B57C077CE118AAC0AA93328DB651A27BB2FC490B7123D72E50B3782F727D45E75794` |
| TELFHASH | `t1f6b00121eb906524a6b1da0a6a533e48b46a31e5b0756164299f6101b61c64526d3004` |
| SSDEEP | `49152:6V/nWnNxAfQ03yTWP9Z/EWQJottSsAd7Mqy:Yf4PsAZMb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_306ce2d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "306ce2d64f3741554000297cc8b8f7ace47c03691e2ec1ee8c5fb4032457430a"
    family = "unknown"
    file_name = "boss"
    file_type = "elf"
    first_seen = "2026-09-03 20:34:59"
  condition:
    hash.sha256(0, filesize) == "306ce2d64f3741554000297cc8b8f7ace47c03691e2ec1ee8c5fb4032457430a"
}
```

### Sample 60: `1a522d46b6fae707`

| Field | Value |
|---|---|
| SHA-256 | `1a522d46b6fae707730f6461728e873b8b9ef12b0628b118c699722a564722e7` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-03 20:29:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2968f8352a64b94bff815af7dc2cb676` |
| SHA-1 | `0f888de3c340c81c4e3469483119ef055e85cac1` |
| SHA-256 | `1a522d46b6fae707730f6461728e873b8b9ef12b0628b118c699722a564722e7` |
| SHA3-384 | `042b6e53163571d9ab44b7452370110da0a51ec2c10c67507a5dd19bbd901c6f1a28a2c1b016bf7e17d46cdb9c402840` |
| TLSH | `T11DC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:l8vCB+25j6es8Rd9FYpMSUpi+20qUpi+20YQX:l8l25JLd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_1a522d46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a522d46b6fae707730f6461728e873b8b9ef12b0628b118c699722a564722e7"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 20:29:50"
  condition:
    hash.sha256(0, filesize) == "1a522d46b6fae707730f6461728e873b8b9ef12b0628b118c699722a564722e7"
}
```

### Sample 61: `88bba386083e9344`

| Field | Value |
|---|---|
| SHA-256 | `88bba386083e93441241f99a728f93d11200d7c6709d69619d2a7cc551b17b79` |
| Family label | `unknown` |
| File name | `88bba386083e93441241f99a728f93d11200d7c6709d69619d2a7cc551b17b79.exe` |
| File type | `exe` |
| First seen | `2026-09-03 20:27:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b49d19e27b5106541902d7959f2e1010` |
| SHA-1 | `e6f77fd492f93773e42434aac4f3a59b4811cd0a` |
| SHA-256 | `88bba386083e93441241f99a728f93d11200d7c6709d69619d2a7cc551b17b79` |
| SHA3-384 | `94ff5a0ab98e99e5ad3d6a1271d1f6dd4ebd4d8aaaf68c74d3603bebb63cef07102074370bb105f43a44e1eb866dec0d` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T1A1D523C678F52AB8C47EC3B28F82F12EB12EB7944B6A8E9377CC1A015D525446C36735` |
| SSDEEP | `49152:7tkpH3rBhHmWS+KwxUmUmMvmeTGXGlXnJ993fEt6zFuT/I++ZsR9CZOM+ph:7aH3thFbxLMOvXi3fEtguzlDqZOM+r` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_88bba386
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88bba386083e93441241f99a728f93d11200d7c6709d69619d2a7cc551b17b79"
    family = "unknown"
    file_name = "88bba386083e93441241f99a728f93d11200d7c6709d69619d2a7cc551b17b79.exe"
    file_type = "exe"
    first_seen = "2026-09-03 20:27:32"
  condition:
    hash.sha256(0, filesize) == "88bba386083e93441241f99a728f93d11200d7c6709d69619d2a7cc551b17b79"
}
```

### Sample 62: `f7362f301153af7d`

| Field | Value |
|---|---|
| SHA-256 | `f7362f301153af7d0d5007ccee3c134e4558f561a3331df84de7ae39d0b16587` |
| Family label | `DarkCloud` |
| File name | `PAGO (FACTURAS VENCIDAS).js` |
| File type | `js` |
| First seen | `2026-09-03 20:22:44` |
| Reporter | `threatcat_ch` |
| Tags | `DarkCloud, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af7eafad8a32a0c7a97ca859dd4e9dd8` |
| SHA-1 | `174c4fab96762e136e7702c261eb1cefde190bb1` |
| SHA-256 | `f7362f301153af7d0d5007ccee3c134e4558f561a3331df84de7ae39d0b16587` |
| SHA3-384 | `f6caff42a70d5c20a7a52c62c894e8b063a503543228d8e15a31db0483858337ce37f5e572923f4c66a6b1b1b60aeeb4` |
| TLSH | `T1AB05230F63956C3D437D2720647FDA0E0ED90A14CE5CF5CF921AD8F6AA68F49247246D` |
| SSDEEP | `24576:tzppUFagseczF3m/uaWtY5HnkTG5xTZsSlJxwbpLG:LbFwkAybp6` |

#### Technical Assessment

- The sample is tracked as `DarkCloud` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkCloud_062_f7362f30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7362f301153af7d0d5007ccee3c134e4558f561a3331df84de7ae39d0b16587"
    family = "DarkCloud"
    file_name = "PAGO (FACTURAS VENCIDAS).js"
    file_type = "js"
    first_seen = "2026-09-03 20:22:44"
  condition:
    hash.sha256(0, filesize) == "f7362f301153af7d0d5007ccee3c134e4558f561a3331df84de7ae39d0b16587"
}
```

### Sample 63: `94892ba2d9046b9c`

| Field | Value |
|---|---|
| SHA-256 | `94892ba2d9046b9c53ac9e9e44587e613a6049e3f9637d98c4f08c9202e23dae` |
| Family label | `unknown` |
| File name | `goodthingsforbestpersonforme.hta` |
| File type | `hta` |
| First seen | `2026-09-03 20:20:53` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07863f3a810756289506ddd3a3617db5` |
| SHA-1 | `c87ee9bae178383dc1c951d40b11a88d19c43d9d` |
| SHA-256 | `94892ba2d9046b9c53ac9e9e44587e613a6049e3f9637d98c4f08c9202e23dae` |
| SHA3-384 | `67718f10c54eb546e69d9d954ff56c162b6e3895f83edc0f6f0745173c8cbfffa89739d557de450a46fffc01cae35f4b` |
| TLSH | `T195F0DC0184E08918223002202EC0F9091AD6EA478349AD0832AA61B90FC4BC1CDCF47C` |
| SSDEEP | `6:qTIuJzhqIwGiY63fAbplilAl3t11/+SR0AqIbR2AWHwlxd1/vV4LKTjawleLYdFa:qTp0JYyg9193R5qsPW8RvVxdqAEd2QL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_94892ba2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94892ba2d9046b9c53ac9e9e44587e613a6049e3f9637d98c4f08c9202e23dae"
    family = "unknown"
    file_name = "goodthingsforbestpersonforme.hta"
    file_type = "hta"
    first_seen = "2026-09-03 20:20:53"
  condition:
    hash.sha256(0, filesize) == "94892ba2d9046b9c53ac9e9e44587e613a6049e3f9637d98c4f08c9202e23dae"
}
```

### Sample 64: `e78dffa0d3611393`

| Field | Value |
|---|---|
| SHA-256 | `e78dffa0d36113939f1c96bcd004002d5fc802346a04533a8237daabf6a41ec4` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-03 20:15:46` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6837e8386a2971f54689fee66a76936` |
| SHA-256 | `e78dffa0d36113939f1c96bcd004002d5fc802346a04533a8237daabf6a41ec4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_e78dffa0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e78dffa0d36113939f1c96bcd004002d5fc802346a04533a8237daabf6a41ec4"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 20:15:46"
  condition:
    hash.sha256(0, filesize) == "e78dffa0d36113939f1c96bcd004002d5fc802346a04533a8237daabf6a41ec4"
}
```

### Sample 65: `5086b7c16787a690`

| Field | Value |
|---|---|
| SHA-256 | `5086b7c16787a690f8f37ca6c99424e8f469c994d9129abdc81a798602de07f7` |
| Family label | `Formbook` |
| File name | `ps_LdSxTLJsoHK1_1780649359263.ps1` |
| File type | `ps1` |
| First seen | `2026-09-03 20:12:07` |
| Reporter | `BastianHein_` |
| Tags | `Formbook, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2a33cdd913a60a80ad292e5aaf0a0ea` |
| SHA-1 | `863f0461f44170dafcdb979a08b468f2877f6587` |
| SHA-256 | `5086b7c16787a690f8f37ca6c99424e8f469c994d9129abdc81a798602de07f7` |
| SHA3-384 | `a00a9b9e26105c5c18f73488b9bb575b422d8c30650072b10b71b6e3c0dba9d1a4bcc285cccd052382fa2852aa489e01` |
| TLSH | `T13AB5BFCAD56E44D29C053FC9A8242BC78B2546328A7400183A7F7D899F774FEC15EEE6` |
| SSDEEP | `24576:bHV624BuwoOW5UjEMgztDhVArA1EEc5z/39I2X45Zu4ATrBdZuJ4tBO4wqwF:d` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_065_5086b7c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5086b7c16787a690f8f37ca6c99424e8f469c994d9129abdc81a798602de07f7"
    family = "Formbook"
    file_name = "ps_LdSxTLJsoHK1_1780649359263.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:12:07"
  condition:
    hash.sha256(0, filesize) == "5086b7c16787a690f8f37ca6c99424e8f469c994d9129abdc81a798602de07f7"
}
```

### Sample 66: `9e42364846f90f1d`

| Field | Value |
|---|---|
| SHA-256 | `9e42364846f90f1d69fa58908a3fda721d82673a46bba32a971c6e8d0096ec85` |
| Family label | `Formbook` |
| File name | `ps_fVCnsMA0wimh_1780714347070.ps1` |
| File type | `ps1` |
| First seen | `2026-09-03 20:12:01` |
| Reporter | `BastianHein_` |
| Tags | `Formbook, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8053e22ea5845a6f19cddbf1e8bc5c5` |
| SHA-1 | `093ef674f81063fa9de9da0c4a91d149a166db55` |
| SHA-256 | `9e42364846f90f1d69fa58908a3fda721d82673a46bba32a971c6e8d0096ec85` |
| SHA3-384 | `977e595c49353e78ef80b197b39e7f9fc5fe09a29b13a3c52907eeae077ec734283f631188e5f9d0c1637972521805f9` |
| TLSH | `T180B5BFCAD56E44D29C053FC9A8142BC78B2546328A7400283A6F7D498F7B5FFC15EEE6` |
| SSDEEP | `24576:Px6qBfhRpDnPCJqfqnmvf5wvOAOxXJr9cxG85xBfpr2yBLtEifWUOvrjF:n` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_066_9e423648
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e42364846f90f1d69fa58908a3fda721d82673a46bba32a971c6e8d0096ec85"
    family = "Formbook"
    file_name = "ps_fVCnsMA0wimh_1780714347070.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:12:01"
  condition:
    hash.sha256(0, filesize) == "9e42364846f90f1d69fa58908a3fda721d82673a46bba32a971c6e8d0096ec85"
}
```

### Sample 67: `896d7475d148a41c`

| Field | Value |
|---|---|
| SHA-256 | `896d7475d148a41cc8975671a96501aa53dc0eab1066b61180d1a21287fa00c4` |
| Family label | `Formbook` |
| File name | `ps_bG5HYG6hsI6T_1780650001945.ps1` |
| File type | `ps1` |
| First seen | `2026-09-03 20:11:52` |
| Reporter | `BastianHein_` |
| Tags | `Formbook, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a9842814076857c0eb2201a7864f5fd` |
| SHA-1 | `c0c6806ae67126098797eed9d87c94f4d032dd16` |
| SHA-256 | `896d7475d148a41cc8975671a96501aa53dc0eab1066b61180d1a21287fa00c4` |
| SHA3-384 | `c16860e766a4bffbe9ee8261ee7d7f400d409562b970090fd2d18583f57ae6f71d03db13d03c7625ef810fcacc1f8818` |
| TLSH | `T132B5BFCAD56E44D29C053FC9A8142AC78B2547728A7400283A6FBD498F774FFC15EEE6` |
| SSDEEP | `24576:RwlqD7ZXACPId08eAKbUgYI1K9MfwK6m1oublj2wrPUc8yzUBg4VODfnkK:Z` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_067_896d7475
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "896d7475d148a41cc8975671a96501aa53dc0eab1066b61180d1a21287fa00c4"
    family = "Formbook"
    file_name = "ps_bG5HYG6hsI6T_1780650001945.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:11:52"
  condition:
    hash.sha256(0, filesize) == "896d7475d148a41cc8975671a96501aa53dc0eab1066b61180d1a21287fa00c4"
}
```

### Sample 68: `cdda430869d4232d`

| Field | Value |
|---|---|
| SHA-256 | `cdda430869d4232ddb7dbfefe83847c3d3b87a30e8c8847f9b88b282e6eba3b6` |
| Family label | `unknown` |
| File name | `hrmmt4a6k03.ps1` |
| File type | `ps1` |
| First seen | `2026-09-03 20:11:44` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1734ed218dda9d1adbeb2a353be9122f` |
| SHA-1 | `b0ea4308a356e7645f848da2d65f580d6d927b21` |
| SHA-256 | `cdda430869d4232ddb7dbfefe83847c3d3b87a30e8c8847f9b88b282e6eba3b6` |
| SHA3-384 | `6d30917802feb6630aea43b14ed7da245f5fee25b44a3242472dce5b234042f614916a3f07438e62ce15c656fe6f8b82` |
| TLSH | `T1263185A102E3CFA802C481A39F10166F517CAD4CF64C9B49F389CD0AE34A8856BE9B47` |
| SSDEEP | `48:0132S132TTWoj6jBpYfiahbpNRMlzbYmubNiu2m2h2j:05r50W46tp8iIpNs3Ym61KS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_cdda4308
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdda430869d4232ddb7dbfefe83847c3d3b87a30e8c8847f9b88b282e6eba3b6"
    family = "unknown"
    file_name = "hrmmt4a6k03.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:11:44"
  condition:
    hash.sha256(0, filesize) == "cdda430869d4232ddb7dbfefe83847c3d3b87a30e8c8847f9b88b282e6eba3b6"
}
```

### Sample 69: `bb9dd11647c31cdf`

| Field | Value |
|---|---|
| SHA-256 | `bb9dd11647c31cdff00e53d1aff330f55c7e1f5d8ad7fa2e33b34ac795be05fc` |
| Family label | `unknown` |
| File name | `cfg_92023_c3ee.ps1` |
| File type | `ps1` |
| First seen | `2026-09-03 20:11:39` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7a9cf6741d6f24e6be5037d55c70c74` |
| SHA-1 | `096553c7491d5f7a3648b751677420c173447ce1` |
| SHA-256 | `bb9dd11647c31cdff00e53d1aff330f55c7e1f5d8ad7fa2e33b34ac795be05fc` |
| SHA3-384 | `258b391ab4772b2d831c54cfbae9a5e7f86e5dbddca129ca07700fdb62d2dbf1c679efed9b5e74356f7ec1d982a791c8` |
| TLSH | `T1F98422005A5D5CBB85BF7D24C0EE2A0377E88E31405423E4BBFD96DF9B899B420E6167` |
| SSDEEP | `6144:QvYv55jE4NNbrtg4Qcbv/VJJCW2BzWGZDjh/DL7RDdlpJa3/ZziQFLspmbe7PxUs:JvLFrbJg4Zj12B71DddlDKPlspm+aGU6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_bb9dd116
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb9dd11647c31cdff00e53d1aff330f55c7e1f5d8ad7fa2e33b34ac795be05fc"
    family = "unknown"
    file_name = "cfg_92023_c3ee.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:11:39"
  condition:
    hash.sha256(0, filesize) == "bb9dd11647c31cdff00e53d1aff330f55c7e1f5d8ad7fa2e33b34ac795be05fc"
}
```

### Sample 70: `b2660a2e88514b6f`

| Field | Value |
|---|---|
| SHA-256 | `b2660a2e88514b6fe1ff2f776c96ab852b0ce563c5a2258a199a2eb2bdb19a1d` |
| Family label | `AveMariaRAT` |
| File name | `BJ8HSYL8.ps1` |
| File type | `ps1` |
| First seen | `2026-09-03 20:11:32` |
| Reporter | `BastianHein_` |
| Tags | `AveMariaRAT, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `225e7c0a027dafcbab661a207718c704` |
| SHA-1 | `bf105f6f7fca1ab6e06af5d54bd61c972da01db9` |
| SHA-256 | `b2660a2e88514b6fe1ff2f776c96ab852b0ce563c5a2258a199a2eb2bdb19a1d` |
| SHA3-384 | `a098a45ff8bf30e4ba8273475aceba901a020ece39bcad66fee1ba77a15f4d45248816f3c05ec64bf4082ccd6b1d97af` |
| TLSH | `T12A9665F9761D7C96F6F07239F56AC2826EBDB7231F04D4638CD920A55082BA4AD48337` |
| SSDEEP | `24576:SUI6cblOaTmVgTIwZMnUdaOcuCnHGlPCmwqKq5oks8xPBZBSTFpVBYdaVT+w840D:8` |

#### Technical Assessment

- The sample is tracked as `AveMariaRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AveMariaRAT_070_b2660a2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2660a2e88514b6fe1ff2f776c96ab852b0ce563c5a2258a199a2eb2bdb19a1d"
    family = "AveMariaRAT"
    file_name = "BJ8HSYL8.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:11:32"
  condition:
    hash.sha256(0, filesize) == "b2660a2e88514b6fe1ff2f776c96ab852b0ce563c5a2258a199a2eb2bdb19a1d"
}
```

### Sample 71: `a9b17c0d8d304986`

| Field | Value |
|---|---|
| SHA-256 | `a9b17c0d8d304986e1f0ece95c3ef34d8ebc755484fe95320b8dccfc41bd74e4` |
| Family label | `unknown` |
| File name | `208kmt4a58cq.ps1` |
| File type | `ps1` |
| First seen | `2026-09-03 20:11:19` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22dd2ebc414743254dda5e1b350af108` |
| SHA-1 | `b67fe533efc178031903965adf06deac0ffd0f79` |
| SHA-256 | `a9b17c0d8d304986e1f0ece95c3ef34d8ebc755484fe95320b8dccfc41bd74e4` |
| SHA3-384 | `0a2439edf4a6542e0866b3f7bb82efb989eed7ac0306e44b5baad5c9c35f37aa972f4e280f5da5fc633ade902a2b1a37` |
| TLSH | `T1593122214BCAEEE90050C03BDDA3C49DC0349D4D6F4DBB1DFB55C958768EA87DE89286` |
| SSDEEP | `48:Y132u132/HuDVqNNb1kZkdq4ebuHOhUGQ7M2q2V2P:Y5T5VDCb1kwq4ebuHUUGQ7MdyK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_a9b17c0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9b17c0d8d304986e1f0ece95c3ef34d8ebc755484fe95320b8dccfc41bd74e4"
    family = "unknown"
    file_name = "208kmt4a58cq.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:11:19"
  condition:
    hash.sha256(0, filesize) == "a9b17c0d8d304986e1f0ece95c3ef34d8ebc755484fe95320b8dccfc41bd74e4"
}
```

### Sample 72: `2faf35c81460f594`

| Field | Value |
|---|---|
| SHA-256 | `2faf35c81460f594d5471186c8a9be65c004c92c5f3968a67e8e88c11a35d347` |
| Family label | `ValleyRAT` |
| File name | `1582E41E322D062A5DF941B89184047F.dll` |
| File type | `dll` |
| First seen | `2026-09-03 20:10:19` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1582e41e322d062a5df941b89184047f` |
| SHA-1 | `4ca46cedae2a9e48e54ee77a75c56645ed07a7fc` |
| SHA-256 | `2faf35c81460f594d5471186c8a9be65c004c92c5f3968a67e8e88c11a35d347` |
| SHA3-384 | `63864091755ebd0136cc95e6d243d0bf24358b331b886a69ab342d18d77c10476fb87b2e3feeb608a54c7a1b385be7c6` |
| IMPHASH | `c4f22e20975a9d3fe84957d0cc941d87` |
| TLSH | `T14B26490336E1C4EBF22642B1E485DAFA926D6D501ED4808339CFBF3739678509E762D6` |
| SSDEEP | `98304:AzmgmbAKZGfcFy9/ZB/TSVXRWNoDhCWt8ZQjg61EsQDdjbhCzJK3w:e8sPbxvoDhCWTwb0zg` |
| ICON-DHASH | `8660a2b2b5d861a4` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_072_2faf35c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2faf35c81460f594d5471186c8a9be65c004c92c5f3968a67e8e88c11a35d347"
    family = "ValleyRAT"
    file_name = "1582E41E322D062A5DF941B89184047F.dll"
    file_type = "dll"
    first_seen = "2026-09-03 20:10:19"
  condition:
    hash.sha256(0, filesize) == "2faf35c81460f594d5471186c8a9be65c004c92c5f3968a67e8e88c11a35d347"
}
```

### Sample 73: `52e889aa77ee3e84`

| Field | Value |
|---|---|
| SHA-256 | `52e889aa77ee3e84835f700f19ea091d48b7e0682c13cba6941129cdf9de27ba` |
| Family label | `ValleyRAT` |
| File name | `CD4F959C7AAC421945DD04A12535941C.exe` |
| File type | `exe` |
| First seen | `2026-09-03 20:10:13` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd4f959c7aac421945dd04a12535941c` |
| SHA-1 | `3dae30779eede30da4c74692bb6303f7c5943009` |
| SHA-256 | `52e889aa77ee3e84835f700f19ea091d48b7e0682c13cba6941129cdf9de27ba` |
| SHA3-384 | `c9ef0352d1b557fe2f6b3abe77b7228a7b777a5da8e031a11ebf9f4f6bab5133cad220cbbb56a74e0e1d2bdd96b5bdbb` |
| IMPHASH | `95d95a460e8783695f0245e2dce92576` |
| TLSH | `T180E37C21B1C1C0B3C8B6253158F4EE759A3DF9701F245DDB63980AB99F302D29B39A67` |
| SSDEEP | `3072:tiZ+xFSlh/WjgRGGs1tsNA1m8omzdZfwcMorHShKLBUpFUJKnclbaRmdu4J:2qSv+jgYT/s6MmzffwPIyhKW2agzJ` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_073_52e889aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52e889aa77ee3e84835f700f19ea091d48b7e0682c13cba6941129cdf9de27ba"
    family = "ValleyRAT"
    file_name = "CD4F959C7AAC421945DD04A12535941C.exe"
    file_type = "exe"
    first_seen = "2026-09-03 20:10:13"
  condition:
    hash.sha256(0, filesize) == "52e889aa77ee3e84835f700f19ea091d48b7e0682c13cba6941129cdf9de27ba"
}
```

### Sample 74: `64d8f6456140746a`

| Field | Value |
|---|---|
| SHA-256 | `64d8f6456140746ac1e5131ab8ada166c62893d53e7daf3d6a829292a7cfefd8` |
| Family label | `njrat` |
| File name | `743759338B45950208EA9D6CB6A99AA1.exe` |
| File type | `exe` |
| First seen | `2026-09-03 20:10:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `743759338b45950208ea9d6cb6a99aa1` |
| SHA-1 | `0784ebd2aa021e89f12a06a7345ae81556ac3a7a` |
| SHA-256 | `64d8f6456140746ac1e5131ab8ada166c62893d53e7daf3d6a829292a7cfefd8` |
| SHA3-384 | `b9461e16422300a49ceec681820e14eb731e0ac7f6c0f26a5d09f3eca5272a0949daa73acb2d2297fb5b6b78a406ca8d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14BB22B4E3FB98856C5AC17748AA5965003B4D1870423EE2FCCC550CBAFB3ADA5D4CAF9` |
| SSDEEP | `384:LweXCQIreJig/8Z7SS1fEBpng6tgL2IBPZVmRvR6JZlbw8hqIusZzZjyr:sLq411eRpcnumw` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_074_64d8f645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64d8f6456140746ac1e5131ab8ada166c62893d53e7daf3d6a829292a7cfefd8"
    family = "njrat"
    file_name = "743759338B45950208EA9D6CB6A99AA1.exe"
    file_type = "exe"
    first_seen = "2026-09-03 20:10:07"
  condition:
    hash.sha256(0, filesize) == "64d8f6456140746ac1e5131ab8ada166c62893d53e7daf3d6a829292a7cfefd8"
}
```

### Sample 75: `e3fc2840cec07dff`

| Field | Value |
|---|---|
| SHA-256 | `e3fc2840cec07dff9c35f528bbe7b3efbe1d60d9a8de9d1467a47cfa7016c278` |
| Family label | `CoinMiner` |
| File name | `e3fc2840cec07dff9c35f528bbe7b3efbe1d60d9a8de9d1467a47cfa7016c278.exe` |
| File type | `exe` |
| First seen | `2026-09-03 20:07:35` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32ec145d7a9d191831e30f782ae2b950` |
| SHA-1 | `466582a1fb4067184d922c8bb99b6b80446d9acf` |
| SHA-256 | `e3fc2840cec07dff9c35f528bbe7b3efbe1d60d9a8de9d1467a47cfa7016c278` |
| SHA3-384 | `578cca37f99d3681b48718f0e081496bd4806af8060f474ffa1b30267f2ee94d74949253da830e895d93f59fd45a4d40` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T11A3633AE6CC611B0D586C778162324BEB13EBBE6C591BD07BBDC29058D93D09A07D3D2` |
| SSDEEP | `98304:O0RmZOA3EC7F0Tb5m9E9E2QMEgejq1GbycH5F37tFHWUc+zid3r:OSmZOA3EWCWE9vkgKF3LHWUc+ud` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_075_e3fc2840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3fc2840cec07dff9c35f528bbe7b3efbe1d60d9a8de9d1467a47cfa7016c278"
    family = "CoinMiner"
    file_name = "e3fc2840cec07dff9c35f528bbe7b3efbe1d60d9a8de9d1467a47cfa7016c278.exe"
    file_type = "exe"
    first_seen = "2026-09-03 20:07:35"
  condition:
    hash.sha256(0, filesize) == "e3fc2840cec07dff9c35f528bbe7b3efbe1d60d9a8de9d1467a47cfa7016c278"
}
```

### Sample 76: `b70cb5ed22247c42`

| Field | Value |
|---|---|
| SHA-256 | `b70cb5ed22247c42ec5fa7d1f4bdfb570355067dc70ac05adeff8c6d70e57aec` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-03 20:04:47` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f5ea8a33af79206ba7d77d6ce8cc3dc` |
| SHA-256 | `b70cb5ed22247c42ec5fa7d1f4bdfb570355067dc70ac05adeff8c6d70e57aec` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_b70cb5ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b70cb5ed22247c42ec5fa7d1f4bdfb570355067dc70ac05adeff8c6d70e57aec"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 20:04:47"
  condition:
    hash.sha256(0, filesize) == "b70cb5ed22247c42ec5fa7d1f4bdfb570355067dc70ac05adeff8c6d70e57aec"
}
```

### Sample 77: `6173641022865c70`

| Field | Value |
|---|---|
| SHA-256 | `6173641022865c703539ad968331c59f1d5da03add825a79b6d0719bf7c07ed1` |
| Family label | `Vidar` |
| File name | `6173641022865c703539ad968331c59f1d5da03add825a79b6d0719bf7c07ed1.bin` |
| File type | `exe` |
| First seen | `2026-09-03 19:36:32` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4feb548c7f76dfd9b9ad4d5588dad9b` |
| SHA-1 | `eb71bc697acb76f83df8f125373790b43cabfe39` |
| SHA-256 | `6173641022865c703539ad968331c59f1d5da03add825a79b6d0719bf7c07ed1` |
| SHA3-384 | `c31636b3d22239ab0c4e3cb57fb360aa46262b82f2cbcd3e41bac78753862758b8446f748f26d4f44433f51ccd5d606b` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T12DA64A03655452E8C889EB38D17B567AABB4F8CDE33672875E82747C2F287E16C39740` |
| SSDEEP | `98304:FIedad3A4ZyTCbd7dQTHsKeUdiRRJnLx5T1K:Ft0A4ZIS7mHsKbiR3xh1K` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_077_61736410
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6173641022865c703539ad968331c59f1d5da03add825a79b6d0719bf7c07ed1"
    family = "Vidar"
    file_name = "6173641022865c703539ad968331c59f1d5da03add825a79b6d0719bf7c07ed1.bin"
    file_type = "exe"
    first_seen = "2026-09-03 19:36:32"
  condition:
    hash.sha256(0, filesize) == "6173641022865c703539ad968331c59f1d5da03add825a79b6d0719bf7c07ed1"
}
```

### Sample 78: `bec2b8cf49b15d40`

| Field | Value |
|---|---|
| SHA-256 | `bec2b8cf49b15d40abc3d0f8d36ee3a2282928f36250278b1f27d9236e0d90db` |
| Family label | `Formbook` |
| File name | `Ref 2026093-2694.exe` |
| File type | `exe` |
| First seen | `2026-09-03 19:36:31` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61d0703268bfae9f0c1d324bdb760eac` |
| SHA-1 | `ce6a59e8be4cd1f34eb455cf7a0537c6a4ad12bd` |
| SHA-256 | `bec2b8cf49b15d40abc3d0f8d36ee3a2282928f36250278b1f27d9236e0d90db` |
| SHA3-384 | `c6ca40a3a938c61216d3df706486a4beea304406f8d0a199c66af7086115eef6c5bfdae11a7987aa7953480a5e754575` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18035DF2C052B4502E9F26EF01EB1A1F06B617C66B139E4295FD20DAFF277614BD8533A` |
| SSDEEP | `24576:SVF656ChEK4bPbE3gxfwEBpYJK27jpXuQoYYSTTBRYDe6xHlT3T:/JPObsUpk77Zz7BTNRYi65lX` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_078_bec2b8cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bec2b8cf49b15d40abc3d0f8d36ee3a2282928f36250278b1f27d9236e0d90db"
    family = "Formbook"
    file_name = "Ref 2026093-2694.exe"
    file_type = "exe"
    first_seen = "2026-09-03 19:36:31"
  condition:
    hash.sha256(0, filesize) == "bec2b8cf49b15d40abc3d0f8d36ee3a2282928f36250278b1f27d9236e0d90db"
}
```

### Sample 79: `1465f0a6ed279e87`

| Field | Value |
|---|---|
| SHA-256 | `1465f0a6ed279e87983f39f9b81e989eb0e92898e21a364ab7fc17a84c808079` |
| Family label | `Vidar` |
| File name | `1465f0a6ed279e87983f39f9b81e989eb0e92898e21a364ab7fc17a84c808079.bin` |
| File type | `exe` |
| First seen | `2026-09-03 19:36:29` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a53b229d106a2d28972648d61c761958` |
| SHA-1 | `8c6da1e9b8d37322f70d240165bbe316b257d928` |
| SHA-256 | `1465f0a6ed279e87983f39f9b81e989eb0e92898e21a364ab7fc17a84c808079` |
| SHA3-384 | `67a0164fcd1440f29ec5f16b236a8887000315162ff6a7097a50af648956442d7e577563eabe4d9571c2b5d62ef38965` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1B0282307659051A4C889EB38D0BB527AAB74F8CDE33672871DC274BC2F697E6AC35740` |
| SSDEEP | `1572864:Md1iAfkajdeMAOmKEopE4xXn2NWCjWN10ZP3mJkO4+kEzrDVDH6VdU2o:MdYAfkjOHEEE452NJjWN2Z/mJVP5uM2o` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_079_1465f0a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1465f0a6ed279e87983f39f9b81e989eb0e92898e21a364ab7fc17a84c808079"
    family = "Vidar"
    file_name = "1465f0a6ed279e87983f39f9b81e989eb0e92898e21a364ab7fc17a84c808079.bin"
    file_type = "exe"
    first_seen = "2026-09-03 19:36:29"
  condition:
    hash.sha256(0, filesize) == "1465f0a6ed279e87983f39f9b81e989eb0e92898e21a364ab7fc17a84c808079"
}
```

### Sample 80: `0f08da5bc3d2c32b`

| Field | Value |
|---|---|
| SHA-256 | `0f08da5bc3d2c32bd0367d586279d4c7cfc7d35d7ac97cd2ead4b7f4327a8a3a` |
| Family label | `Vidar` |
| File name | `0f08da5bc3d2c32bd0367d586279d4c7cfc7d35d7ac97cd2ead4b7f4327a8a3a.bin` |
| File type | `exe` |
| First seen | `2026-09-03 19:36:21` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bd50237408f3358f83908686be7c228` |
| SHA-1 | `0a22f99e456e4142143d5fd2d20967bbcd0ede41` |
| SHA-256 | `0f08da5bc3d2c32bd0367d586279d4c7cfc7d35d7ac97cd2ead4b7f4327a8a3a` |
| SHA3-384 | `5cc57d041cdf5e2c63f9fa0a053c36713e067a1da75961dd5203c32ab8cc0a5672a1a2376e2b6a409492982efd1413ff` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T125568C437CA5A4A4C99AC678D27542533634B89E9B3137EB2F92F2B02F727D06B75310` |
| SSDEEP | `49152:9I4tTJDjqAtvDHyrb/TgvO90d7HjmAFd4A64nsfJRA9yEsp53AvStoyYGn1LLMH9:LzpDHqEsX36SNnxIwgcO/vvqNlAF` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_080_0f08da5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f08da5bc3d2c32bd0367d586279d4c7cfc7d35d7ac97cd2ead4b7f4327a8a3a"
    family = "Vidar"
    file_name = "0f08da5bc3d2c32bd0367d586279d4c7cfc7d35d7ac97cd2ead4b7f4327a8a3a.bin"
    file_type = "exe"
    first_seen = "2026-09-03 19:36:21"
  condition:
    hash.sha256(0, filesize) == "0f08da5bc3d2c32bd0367d586279d4c7cfc7d35d7ac97cd2ead4b7f4327a8a3a"
}
```

### Sample 81: `07936bd8a05d6db7`

| Field | Value |
|---|---|
| SHA-256 | `07936bd8a05d6db787bfa5f8b10c1335ef708f660dcd2b1eee715c9b66283e80` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-03 19:08:42` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8e241d06a6d1e478faa13871667eb58` |
| SHA-1 | `f3cf4d17e050f36e77b1a127d310bc224922aa65` |
| SHA-256 | `07936bd8a05d6db787bfa5f8b10c1335ef708f660dcd2b1eee715c9b66283e80` |
| SHA3-384 | `bf95433156f83f780d415f8fe4022d46dbdb4f6a7dfdce46002c4c10ae2dd77e47db8705e92032cf0caccd39f7155af4` |
| IMPHASH | `bafce9e261c83620861e15bf9e5ac9e6` |
| TLSH | `T1DF261237F929259DC638757766047D40528A7A03BE7790B83ECF258FA43EC5B297230A` |
| SSDEEP | `49152:Gpn4zO6uAhwdTlYFro+7P20mokjj+6ZfWJR6aW/QgN9BtpSCV0SCaCTAVbYvnGnJ:QYnKZa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_07936bd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07936bd8a05d6db787bfa5f8b10c1335ef708f660dcd2b1eee715c9b66283e80"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 19:08:42"
  condition:
    hash.sha256(0, filesize) == "07936bd8a05d6db787bfa5f8b10c1335ef708f660dcd2b1eee715c9b66283e80"
}
```

### Sample 82: `d43ee01d07e64fd8`

| Field | Value |
|---|---|
| SHA-256 | `d43ee01d07e64fd87dc611ea826f31109971e6a2d52acc47fbb08d2dcf5567de` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-03 19:08:32` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX2.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2cda6ce9a9027026ed9099f395e2480a` |
| SHA-1 | `99e2528270f70679e922995b536c759172ada53a` |
| SHA-256 | `d43ee01d07e64fd87dc611ea826f31109971e6a2d52acc47fbb08d2dcf5567de` |
| SHA3-384 | `8072846ec2896e7767e33048049b61aead495aad2b721ac198b3f911dc5ef5c9719f9717d1b9a46b6b6e00880511e5a1` |
| IMPHASH | `6d2ae5572abc52c9c89737f04ced7506` |
| TLSH | `T1DC964D7144874C96E0DFC2218248EF3AA91D7384ED9E7DB368EA7E9DC67AB318440F15` |
| SSDEEP | `196608:nKBB3BQzXBQb0cGdHUZDf4iDrr42ALoY/ZZhNCF:nKBB3BQzXBQ7Gyd4ibkL7N` |
| ICON-DHASH | `b2e1ec6ce43365b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_d43ee01d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d43ee01d07e64fd87dc611ea826f31109971e6a2d52acc47fbb08d2dcf5567de"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 19:08:32"
  condition:
    hash.sha256(0, filesize) == "d43ee01d07e64fd87dc611ea826f31109971e6a2d52acc47fbb08d2dcf5567de"
}
```

### Sample 83: `ffb3eacf4164d66a`

| Field | Value |
|---|---|
| SHA-256 | `ffb3eacf4164d66a8d5e591c043f3f86d599e8d39384417d6fdf78796ae18a84` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-03 18:38:25` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48f182330f3013bdd050de44bbc9cf12` |
| SHA-1 | `0f5044a736202fb614a5ddcd7899c4644d96f360` |
| SHA-256 | `ffb3eacf4164d66a8d5e591c043f3f86d599e8d39384417d6fdf78796ae18a84` |
| SHA3-384 | `05d02d795926f27e72606fcad1369a966821eaeacce397f163457a036b46997c53f1f47e535253545b316ed2f9d2a55c` |
| IMPHASH | `78b4191a12298dc481fadc827b5ec239` |
| TLSH | `T1FB664B41BA6B58BCD557C87487468A239E2130DB0B36BAFF018486383F6ABF15B3D754` |
| SSDEEP | `49152:f24aKFtcsHcQQSXnf3ngE1Dh3Y9NIYbqmmwqw9W0lKBwss+/SJLvXlDctrM2BNcw:YuJeqjLK9LvJcPcs7H/0pA6S+fmry` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_083_ffb3eacf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffb3eacf4164d66a8d5e591c043f3f86d599e8d39384417d6fdf78796ae18a84"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 18:38:25"
  condition:
    hash.sha256(0, filesize) == "ffb3eacf4164d66a8d5e591c043f3f86d599e8d39384417d6fdf78796ae18a84"
}
```

### Sample 84: `117e2c3d3b40a2b2`

| Field | Value |
|---|---|
| SHA-256 | `117e2c3d3b40a2b2cbb2001fa0c1109e51cdec777672d5b325e7edecac442fdd` |
| Family label | `Vidar` |
| File name | `117e2c3d3b40a2b2cbb2001fa0c1109e51cdec777672d5b325e7edecac442fdd.bin` |
| File type | `exe` |
| First seen | `2026-09-03 18:25:10` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe21f0d15ab0a6fdac95a318d7a34e64` |
| SHA-1 | `12275bd106fb6812411bc28d40cd71079c0e0639` |
| SHA-256 | `117e2c3d3b40a2b2cbb2001fa0c1109e51cdec777672d5b325e7edecac442fdd` |
| SHA3-384 | `5f0b9f0bd8ce939644baa8f53bbffa8ab12643d7cb8aa8bf7cf9d3a9867dd01d2f261b735cf78d4e13821436cb620d6d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T176668D036A9505E5D854DE30C27A57127A71FC8DDB3673E32F41AB742F29BD0AABA700` |
| SSDEEP | `49152:hzFbOw/jm7ir8Tl4z2xcgpsKh53WDuFwiOTxwUZfb+DD:hf+7ljjj31Fw1aCfqv` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_084_117e2c3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "117e2c3d3b40a2b2cbb2001fa0c1109e51cdec777672d5b325e7edecac442fdd"
    family = "Vidar"
    file_name = "117e2c3d3b40a2b2cbb2001fa0c1109e51cdec777672d5b325e7edecac442fdd.bin"
    file_type = "exe"
    first_seen = "2026-09-03 18:25:10"
  condition:
    hash.sha256(0, filesize) == "117e2c3d3b40a2b2cbb2001fa0c1109e51cdec777672d5b325e7edecac442fdd"
}
```

### Sample 85: `06d242a6f28c23fd`

| Field | Value |
|---|---|
| SHA-256 | `06d242a6f28c23fd708289cd8d40ec6d1fec310559d9f4c13b4ad4703cd99c31` |
| Family label | `unknown` |
| File name | `06d242a6f28c23fd708289cd8d40ec6d1fec310559d9f4c13b4ad4703cd99c31.exe` |
| File type | `exe` |
| First seen | `2026-09-03 17:42:34` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b58062491bfb51b366d04487c44ef820` |
| SHA-1 | `7aa95f02b0ccba6cc910e2c86636270fd931f2ad` |
| SHA-256 | `06d242a6f28c23fd708289cd8d40ec6d1fec310559d9f4c13b4ad4703cd99c31` |
| SHA3-384 | `bfc59023af8a758087f4e6978c2c53016e302bdee7a558b3e8b88e1ec009f1e438f5982d608b526b9d3617af44d07e2c` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T1ADD52299BC821972E436C7B74BD3A47EB129B7518A219C0F36CD67102E229287D3737D` |
| SSDEEP | `49152:JewXepJmxPHZVu1BJNwbwzDVNyd/7oQUX9byH5BsrOI:JepJmtZYVXL5Nby5B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_06d242a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06d242a6f28c23fd708289cd8d40ec6d1fec310559d9f4c13b4ad4703cd99c31"
    family = "unknown"
    file_name = "06d242a6f28c23fd708289cd8d40ec6d1fec310559d9f4c13b4ad4703cd99c31.exe"
    file_type = "exe"
    first_seen = "2026-09-03 17:42:34"
  condition:
    hash.sha256(0, filesize) == "06d242a6f28c23fd708289cd8d40ec6d1fec310559d9f4c13b4ad4703cd99c31"
}
```

### Sample 86: `cfad7093da1fc7ac`

| Field | Value |
|---|---|
| SHA-256 | `cfad7093da1fc7ac1ea128ce094bad881aa0efae772ed7e19dc915baaae41ae6` |
| Family label | `Vidar` |
| File name | `cfad7093da1fc7ac1ea128ce094bad881aa0efae772ed7e19dc915baaae41ae6.bin` |
| File type | `exe` |
| First seen | `2026-09-03 17:19:24` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `927a8c5452a1dd69b31b73d64b74a9d3` |
| SHA-1 | `5aef12d202373668373093a8763ba13ab45cc08a` |
| SHA-256 | `cfad7093da1fc7ac1ea128ce094bad881aa0efae772ed7e19dc915baaae41ae6` |
| SHA3-384 | `7916616ba867791cfcb9d2c4e13ebc69c20ae19d2fe0415d39ccc0d4faf11cf21f533d0df33f7de3656fb0bacc6090c8` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1E2282303A55452A8C489EB38D1BB427AA7B4F8CDE73672875DC274BC2F287E5AC35740` |
| SSDEEP | `1572864:ZSXYogIjGNRKHJvpU0X4syXRpvajS+YkKw5hacGSH8FAmZHxj692:SYogoMqJxU0IsGRpIAkKwvE1b/j6A` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_086_cfad7093
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfad7093da1fc7ac1ea128ce094bad881aa0efae772ed7e19dc915baaae41ae6"
    family = "Vidar"
    file_name = "cfad7093da1fc7ac1ea128ce094bad881aa0efae772ed7e19dc915baaae41ae6.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:19:24"
  condition:
    hash.sha256(0, filesize) == "cfad7093da1fc7ac1ea128ce094bad881aa0efae772ed7e19dc915baaae41ae6"
}
```

### Sample 87: `fd4958729e313d36`

| Field | Value |
|---|---|
| SHA-256 | `fd4958729e313d36cb6073de5bbf2e3958d22cb6164e724bd62f6ecd08d1b6f8` |
| Family label | `Vidar` |
| File name | `fd4958729e313d36cb6073de5bbf2e3958d22cb6164e724bd62f6ecd08d1b6f8.bin` |
| File type | `exe` |
| First seen | `2026-09-03 17:19:16` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a0008bbf5eb21f58ad97dc7619e1ed5` |
| SHA-1 | `c77cd79d41538a10536c3e1e80c4943b3bf966fa` |
| SHA-256 | `fd4958729e313d36cb6073de5bbf2e3958d22cb6164e724bd62f6ecd08d1b6f8` |
| SHA3-384 | `36814127a007c82eb61f8fdfdea77b5af00f28a53344ebd9d090b973b718423e670ce4c2855ccc2be4bb1361806ceb22` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T148867B43BA98A094C5E9D634C5BA12217B647848CB3033F33E91AAB52F373D56FB9750` |
| SSDEEP | `49152:uH4drz5Hpvb8rb/TMvO90d7HjmAFd4A64nsfJIvMai7Mshv6hBC4Ld3V25XmR3My:RJTEVr4FmXVBb1EzumbjCQG0` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_087_fd495872
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd4958729e313d36cb6073de5bbf2e3958d22cb6164e724bd62f6ecd08d1b6f8"
    family = "Vidar"
    file_name = "fd4958729e313d36cb6073de5bbf2e3958d22cb6164e724bd62f6ecd08d1b6f8.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:19:16"
  condition:
    hash.sha256(0, filesize) == "fd4958729e313d36cb6073de5bbf2e3958d22cb6164e724bd62f6ecd08d1b6f8"
}
```

### Sample 88: `303c0c4820a3b87f`

| Field | Value |
|---|---|
| SHA-256 | `303c0c4820a3b87f871a11c375b710841db12a436274481c4268150aba9c684a` |
| Family label | `Vidar` |
| File name | `303c0c4820a3b87f871a11c375b710841db12a436274481c4268150aba9c684a.bin` |
| File type | `exe` |
| First seen | `2026-09-03 17:19:14` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0eb603ba3cdf78949576c97c6dd9c4ef` |
| SHA-1 | `40f33165c6615e146508a099874cf76853d670cf` |
| SHA-256 | `303c0c4820a3b87f871a11c375b710841db12a436274481c4268150aba9c684a` |
| SHA3-384 | `0a1069b0ef062960dcd438555691184b340e94cf494dfaed1bf127ea5f8346651320b502b83262fde5d85cbc47b06b2d` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T196382303655052E4C889EB38D17B427AABB4F8CDE73672875D8278BC2F687E5AC35740` |
| SSDEEP | `1572864:m5LWIu8S77RTyo4dGY2vMFlue5BZDTKIOtd9LXp5+Yu1aIxJghYum1C:m5SIL2noGYPFlZxKIQzjVItA` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_088_303c0c48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "303c0c4820a3b87f871a11c375b710841db12a436274481c4268150aba9c684a"
    family = "Vidar"
    file_name = "303c0c4820a3b87f871a11c375b710841db12a436274481c4268150aba9c684a.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:19:14"
  condition:
    hash.sha256(0, filesize) == "303c0c4820a3b87f871a11c375b710841db12a436274481c4268150aba9c684a"
}
```

### Sample 89: `282b9ca1179778a4`

| Field | Value |
|---|---|
| SHA-256 | `282b9ca1179778a4fd508369f34eb5d7f89db4c657923990291a508bd34c7502` |
| Family label | `Vidar` |
| File name | `282b9ca1179778a4fd508369f34eb5d7f89db4c657923990291a508bd34c7502.bin` |
| File type | `exe` |
| First seen | `2026-09-03 17:19:06` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `700fbe50c53c269d9b701685f4722b38` |
| SHA-1 | `f318d307a8ed2e2fa604557139c820b4f20144c4` |
| SHA-256 | `282b9ca1179778a4fd508369f34eb5d7f89db4c657923990291a508bd34c7502` |
| SHA3-384 | `03ad91acbdf8114bd39dfcae4e15624725f06526c723dbf860bce389e2c6aeb1b9dd34731132f2727af07efee54bba57` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T13B667C836E866174E499DB71E06521D9E220788D6B7033D72C0AFBB41D32BD92EBCF54` |
| SSDEEP | `49152:GdnkU4YmxAta8WmpcAe8bd4Y0TCvIZq5YDm4xR78nUQ6bEnNqTAPpMmFqYg1s8Y1:GmuBaqK8L4xh8nGENqTKppqOp` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_089_282b9ca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "282b9ca1179778a4fd508369f34eb5d7f89db4c657923990291a508bd34c7502"
    family = "Vidar"
    file_name = "282b9ca1179778a4fd508369f34eb5d7f89db4c657923990291a508bd34c7502.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:19:06"
  condition:
    hash.sha256(0, filesize) == "282b9ca1179778a4fd508369f34eb5d7f89db4c657923990291a508bd34c7502"
}
```

### Sample 90: `e9cbdf075ce85bfc`

| Field | Value |
|---|---|
| SHA-256 | `e9cbdf075ce85bfcfe248335ecbd64d99e8335db88bbf3d7016e1f52c8bce72d` |
| Family label | `Vidar` |
| File name | `e9cbdf075ce85bfcfe248335ecbd64d99e8335db88bbf3d7016e1f52c8bce72d.bin` |
| File type | `exe` |
| First seen | `2026-09-03 17:19:03` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `514a59a3588166cdd52719e1672706d4` |
| SHA-1 | `629e005f3728e9eb2aa10e29386244b4eae2a6bb` |
| SHA-256 | `e9cbdf075ce85bfcfe248335ecbd64d99e8335db88bbf3d7016e1f52c8bce72d` |
| SHA3-384 | `9e8500515d4b3a31f87bed2605f83ac97109ffa8513cad4cb586f199f3cf429c321027339054fea3d71563d23c6d0fb8` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T198382303659452A8C889EB38D17B427AAB74F8CDE33672875DC274BC6F297E1AC35740` |
| SSDEEP | `1572864:yqQfqqG10QZKXuREUfp2b1Lq3TopnhXcTPh5uFuvvYV:y1yqGSQZ1b02iNcrh5uFum` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_090_e9cbdf07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9cbdf075ce85bfcfe248335ecbd64d99e8335db88bbf3d7016e1f52c8bce72d"
    family = "Vidar"
    file_name = "e9cbdf075ce85bfcfe248335ecbd64d99e8335db88bbf3d7016e1f52c8bce72d.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:19:03"
  condition:
    hash.sha256(0, filesize) == "e9cbdf075ce85bfcfe248335ecbd64d99e8335db88bbf3d7016e1f52c8bce72d"
}
```

### Sample 91: `f8ca909c103deea0`

| Field | Value |
|---|---|
| SHA-256 | `f8ca909c103deea084f14d8d9361b783b75f18b73107863f6105ab5037ef8d54` |
| Family label | `Vidar` |
| File name | `f8ca909c103deea084f14d8d9361b783b75f18b73107863f6105ab5037ef8d54.bin` |
| File type | `exe` |
| First seen | `2026-09-03 17:18:53` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76f3c7c32a13e04517a13bcb0955a540` |
| SHA-1 | `9986f39b7b150a3e2eb12f56d0c8ef424981d82c` |
| SHA-256 | `f8ca909c103deea084f14d8d9361b783b75f18b73107863f6105ab5037ef8d54` |
| SHA3-384 | `ba82eb1cd38facc76dd692b57b4eb57ce320709709d66ecf85d8ddebf4624a1c7359ec9ae3821bc8b4123899aacd0b0f` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1DA282303659052A4C989EB38D17B527AABB4F8CDE33672875DC274BC2F287E5AC35740` |
| SSDEEP | `1572864:EOGZW8UjizqI4gUW7kva3EWkslywfyXGO9Qe/7hdwEJN3pIJhB3:pibUepmC3E/slywmAMfrZIV` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_091_f8ca909c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8ca909c103deea084f14d8d9361b783b75f18b73107863f6105ab5037ef8d54"
    family = "Vidar"
    file_name = "f8ca909c103deea084f14d8d9361b783b75f18b73107863f6105ab5037ef8d54.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:18:53"
  condition:
    hash.sha256(0, filesize) == "f8ca909c103deea084f14d8d9361b783b75f18b73107863f6105ab5037ef8d54"
}
```

### Sample 92: `fcfe6b8eb9523a10`

| Field | Value |
|---|---|
| SHA-256 | `fcfe6b8eb9523a107d294f79f65a66995cc6237985f89db67f4cd7ce9264243e` |
| Family label | `Vidar` |
| File name | `fcfe6b8eb9523a107d294f79f65a66995cc6237985f89db67f4cd7ce9264243e.bin` |
| File type | `exe` |
| First seen | `2026-09-03 17:18:45` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a421f0f3f9df6ad120f23937328eccd9` |
| SHA-1 | `ad8f69db2a551d8230baa2f39f72b654759df8ce` |
| SHA-256 | `fcfe6b8eb9523a107d294f79f65a66995cc6237985f89db67f4cd7ce9264243e` |
| SHA3-384 | `4aa131feff9f4f2e7759b23d5d07e14eb4ea7fc5971452d21494ff5b8a62ec0d24289c24505c15d0abf0ed9c2eba75d7` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T12F382303659052E4C889EB38D17B527AABB4F8CDE73672871D8278BC6F687E16C35740` |
| SSDEEP | `1572864:Na9qKZF96ToS07wxzr5UdgnSccm0g4gazWpqNdEw6nYFaG2Vv:NCfAkxAzYgnnx47WqdknwcR` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_092_fcfe6b8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcfe6b8eb9523a107d294f79f65a66995cc6237985f89db67f4cd7ce9264243e"
    family = "Vidar"
    file_name = "fcfe6b8eb9523a107d294f79f65a66995cc6237985f89db67f4cd7ce9264243e.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:18:45"
  condition:
    hash.sha256(0, filesize) == "fcfe6b8eb9523a107d294f79f65a66995cc6237985f89db67f4cd7ce9264243e"
}
```

### Sample 93: `239e0d138b7d137a`

| Field | Value |
|---|---|
| SHA-256 | `239e0d138b7d137ae4f76476fdf2ba10d17dcf0b40a5d818b7e01612ac69dcb2` |
| Family label | `Vidar` |
| File name | `239e0d138b7d137ae4f76476fdf2ba10d17dcf0b40a5d818b7e01612ac69dcb2.bin` |
| File type | `exe` |
| First seen | `2026-09-03 17:17:12` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d1aefec6cf1353efc2a95b1b9404449` |
| SHA-1 | `b65e4730d6b8d68034c34980840c4d9ca9f8100b` |
| SHA-256 | `239e0d138b7d137ae4f76476fdf2ba10d17dcf0b40a5d818b7e01612ac69dcb2` |
| SHA3-384 | `6d74a95700c889cc1dd06ce13a4a75c5a7ea1d565cb11ac899b7e71a0b257c7f696267ec49ed23aedbbed041a9123cef` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T14D567C03BD558CA9D598D6398CBA761A7ABCB84C833037971D727E776F227E08A34740` |
| SSDEEP | `98304:YZLiCYdi4Va/5Q6fC1IKhZzdI5LRlZCPt1mr440Q:Ygdi4VGQ6fC+Kjz/Pt80U` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_093_239e0d13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "239e0d138b7d137ae4f76476fdf2ba10d17dcf0b40a5d818b7e01612ac69dcb2"
    family = "Vidar"
    file_name = "239e0d138b7d137ae4f76476fdf2ba10d17dcf0b40a5d818b7e01612ac69dcb2.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:17:12"
  condition:
    hash.sha256(0, filesize) == "239e0d138b7d137ae4f76476fdf2ba10d17dcf0b40a5d818b7e01612ac69dcb2"
}
```

### Sample 94: `1c852cc5ab0847f5`

| Field | Value |
|---|---|
| SHA-256 | `1c852cc5ab0847f57908869ad14b2c1385bec46a8377f67b779aada5a5d59dc0` |
| Family label | `unknown` |
| File name | `secondfast.exe` |
| File type | `exe` |
| First seen | `2026-09-03 16:52:12` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c17489d4bf43f077ba749f2d8b3077d` |
| SHA-1 | `53463b42aeab2ea25d9b3ff639d3fef0323aa1c3` |
| SHA-256 | `1c852cc5ab0847f57908869ad14b2c1385bec46a8377f67b779aada5a5d59dc0` |
| SHA3-384 | `be33d6bcd1fd7843593d1aad943ce8f00a9314c7fb2c446cff6fe7ce14967067ac6f0276e3b70bdb0d70b2eb4728c38d` |
| IMPHASH | `5bba269219581ca7e7f1399fefe94ece` |
| TLSH | `T161C4F117BBD805FEC056C37E99950531A6B2B8121BA497EF47A402170F6BBD06FBEB10` |
| SSDEEP | `6144:oSZgV/h/3pFiPAHRzb3fV6PmHbksHvIxzdS+u+N08Z3oe44AagjJFosZZbrjJwq0:1WhXvHh3dbVHXnAi4Avjro6bnJwu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_1c852cc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c852cc5ab0847f57908869ad14b2c1385bec46a8377f67b779aada5a5d59dc0"
    family = "unknown"
    file_name = "secondfast.exe"
    file_type = "exe"
    first_seen = "2026-09-03 16:52:12"
  condition:
    hash.sha256(0, filesize) == "1c852cc5ab0847f57908869ad14b2c1385bec46a8377f67b779aada5a5d59dc0"
}
```

### Sample 95: `bff3cd04c6b600b8`

| Field | Value |
|---|---|
| SHA-256 | `bff3cd04c6b600b87ac9ef4365ef39701c512ce41079d124aa6e0ac06be38e03` |
| Family label | `unknown` |
| File name | `sunwukongs.exe` |
| File type | `unknown` |
| First seen | `2026-09-03 16:52:03` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, SunWukong` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56f72694f1e5ac9501b3a291535d32b8` |
| SHA-256 | `bff3cd04c6b600b87ac9ef4365ef39701c512ce41079d124aa6e0ac06be38e03` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_bff3cd04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bff3cd04c6b600b87ac9ef4365ef39701c512ce41079d124aa6e0ac06be38e03"
    family = "unknown"
    file_name = "sunwukongs.exe"
    file_type = "unknown"
    first_seen = "2026-09-03 16:52:03"
  condition:
    hash.sha256(0, filesize) == "bff3cd04c6b600b87ac9ef4365ef39701c512ce41079d124aa6e0ac06be38e03"
}
```

### Sample 96: `533a9a6ff75a172b`

| Field | Value |
|---|---|
| SHA-256 | `533a9a6ff75a172b2e996391ad2dd93e615b31fd6f920e28a111f94284400440` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-03 16:51:19` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `111eebbdb30ac11494f769e6652d32f1` |
| SHA-1 | `14968edb0bcd9fde9d3151872dba0fe40318571a` |
| SHA-256 | `533a9a6ff75a172b2e996391ad2dd93e615b31fd6f920e28a111f94284400440` |
| SHA3-384 | `5d8ee8fac592db93d683ed7d94ba52e05f668a53c3a33023abbf0e64b3e71e4d34465e647b9920cca13393f5cd0cb98f` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1EC4523A111F08577F97A93790CE6C223A532BC905B758B8F2396B29E1F33AC05532767` |
| SSDEEP | `24576:w/uno+72IgalbAco+P94kfjdpGW+4QmeWvf6GlIY6Ih+:Pmc32+PGW/QmeWvrL6I` |
| ICON-DHASH | `2a78fc92a6dca975` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_533a9a6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "533a9a6ff75a172b2e996391ad2dd93e615b31fd6f920e28a111f94284400440"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 16:51:19"
  condition:
    hash.sha256(0, filesize) == "533a9a6ff75a172b2e996391ad2dd93e615b31fd6f920e28a111f94284400440"
}
```

### Sample 97: `acde9620e5ca90b9`

| Field | Value |
|---|---|
| SHA-256 | `acde9620e5ca90b9033d6f42c260c8dc99a54d6b447fa4d6648ed3e99c80b68b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-03 16:50:58` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX1.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fbd002da9ac54d1decb26d50086d5b5` |
| SHA-1 | `1e90c3a67d5e15f4bcb526ccf15f4abd9bb09713` |
| SHA-256 | `acde9620e5ca90b9033d6f42c260c8dc99a54d6b447fa4d6648ed3e99c80b68b` |
| SHA3-384 | `66830de8b7e3049d6e965478ed29140c203f47a63c927ee82fdf46deeb861165c92148c9297587424305e70af9aebf43` |
| IMPHASH | `db58864f9a39d180bc07f47882380f8e` |
| TLSH | `T13DB4F157FB9803F9C429D5BD89101142FAF6B851BB6186EF47E4069B0F376C42E3AB21` |
| SSDEEP | `12288:vor8vaDDsIxBA36Z1bRhhKTuXiJvw/Qttj0f4C:wrPXas1lgwItb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_acde9620
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acde9620e5ca90b9033d6f42c260c8dc99a54d6b447fa4d6648ed3e99c80b68b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 16:50:58"
  condition:
    hash.sha256(0, filesize) == "acde9620e5ca90b9033d6f42c260c8dc99a54d6b447fa4d6648ed3e99c80b68b"
}
```

### Sample 98: `ec7b0194baf1566c`

| Field | Value |
|---|---|
| SHA-256 | `ec7b0194baf1566c838ace76958ac4e3a2d47fb082d861f9a2e81004cbae9809` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-03 16:44:08` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c08cd63178860ab289584dd9239a17bd` |
| SHA-1 | `dbbaf7c319cd231ad8921bce12bbe246ed1600d1` |
| SHA-256 | `ec7b0194baf1566c838ace76958ac4e3a2d47fb082d861f9a2e81004cbae9809` |
| SHA3-384 | `2dc2e196a4c3110b3c6e39097a8c2138cc25bc54c1e97f7f5cf91d146c88664e20376aab2588af89d546b4fd64c7e294` |
| TLSH | `T1723162EA02545A300113CA8EB7B33488724DE2EB2D5FC7E1D84C1DED954978CF2A2F49` |
| SSDEEP | `24:i81EpdwUunAPieit1S6BZbo2JLI9yjHjlhnCzC8F:i86psneRwLoAI9yj5FCzCk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_ec7b0194
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec7b0194baf1566c838ace76958ac4e3a2d47fb082d861f9a2e81004cbae9809"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-03 16:44:08"
  condition:
    hash.sha256(0, filesize) == "ec7b0194baf1566c838ace76958ac4e3a2d47fb082d861f9a2e81004cbae9809"
}
```

### Sample 99: `9ac9ca5ebfe5c1cb`

| Field | Value |
|---|---|
| SHA-256 | `9ac9ca5ebfe5c1cba3785c7666bf58420a06b1e41796d3f137289b7d528c71bd` |
| Family label | `Vidar` |
| File name | `9ac9ca5ebfe5c1cba3785c7666bf58420a06b1e41796d3f137289b7d528c71bd.bin` |
| File type | `exe` |
| First seen | `2026-09-03 16:42:41` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f8b7284d31aa685a91dea1fb7598fce` |
| SHA-1 | `d5508a6f1a113dd8b03e58717d65229d624ba001` |
| SHA-256 | `9ac9ca5ebfe5c1cba3785c7666bf58420a06b1e41796d3f137289b7d528c71bd` |
| SHA3-384 | `4d1a9623f8c683d1683296418308ff4b2f44d355e9247be7cd2fb2a3861944490a7504ee66d2f8e639da7a83adeed445` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T100667C836E8661B4E495DB72D06521E5E2207C896B7033D32D0AFBB51D32BD82EBCF54` |
| SSDEEP | `49152:4x1dnCITCf0voSPeZM6JI3XD0si9oILcdwUS0xoHgMa5TQr7CpysbTWqYg1s8YG/:jfohIoVxoAMl+0cfRX` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_099_9ac9ca5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ac9ca5ebfe5c1cba3785c7666bf58420a06b1e41796d3f137289b7d528c71bd"
    family = "Vidar"
    file_name = "9ac9ca5ebfe5c1cba3785c7666bf58420a06b1e41796d3f137289b7d528c71bd.bin"
    file_type = "exe"
    first_seen = "2026-09-03 16:42:41"
  condition:
    hash.sha256(0, filesize) == "9ac9ca5ebfe5c1cba3785c7666bf58420a06b1e41796d3f137289b7d528c71bd"
}
```

### Sample 100: `995e67cd9eac4262`

| Field | Value |
|---|---|
| SHA-256 | `995e67cd9eac426284a4b701380a5e675e6459ea47cace9cfd5b8cc87a2ebbf2` |
| Family label | `Vidar` |
| File name | `995e67cd9eac426284a4b701380a5e675e6459ea47cace9cfd5b8cc87a2ebbf2.bin` |
| File type | `exe` |
| First seen | `2026-09-03 16:42:39` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e072571c2874e7b426c9c77a5acc0d3` |
| SHA-1 | `4c18dc6b83440f606a6585135b1459e602e268b2` |
| SHA-256 | `995e67cd9eac426284a4b701380a5e675e6459ea47cace9cfd5b8cc87a2ebbf2` |
| SHA3-384 | `da59a4d396e6677b9d2e74f36806b086f2145bbd7d7f1f6bd744db957e17d141a4d36858e5098ef1d337441bfcf1ffaf` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1B0282307619051A4C989EF38D17B527AABB4F8CDE73672871D8278BC2F687E66C35340` |
| SSDEEP | `3145728:LGpC7lIrDh+g48Rg11QASFDYnUYiAUOjF:wQaJ7GjQASFD6gOjF` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_100_995e67cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "995e67cd9eac426284a4b701380a5e675e6459ea47cace9cfd5b8cc87a2ebbf2"
    family = "Vidar"
    file_name = "995e67cd9eac426284a4b701380a5e675e6459ea47cace9cfd5b8cc87a2ebbf2.bin"
    file_type = "exe"
    first_seen = "2026-09-03 16:42:39"
  condition:
    hash.sha256(0, filesize) == "995e67cd9eac426284a4b701380a5e675e6459ea47cace9cfd5b8cc87a2ebbf2"
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
 * Generated: 2026-09-04T04:42:11.495877+00:00
 */

rule MalwareBazaar_unknown_001_94843537
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "948435372615e8fcd975eb30e921851be5396ae6238986ea782b0ae1743ffb44"
    family = "unknown"
    file_name = "948435372615e8fcd975eb30e921851be5396ae6238986ea782b0ae1743ffb44.bin"
    file_type = "exe"
    first_seen = "2026-09-04 04:40:16"
  condition:
    hash.sha256(0, filesize) == "948435372615e8fcd975eb30e921851be5396ae6238986ea782b0ae1743ffb44"
}

rule MalwareBazaar_unknown_002_eeffc79d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeffc79d077be873b173dd0cdd919f8e2d869c5a079034bf9f2a8641d7668a4e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-04 04:07:31"
  condition:
    hash.sha256(0, filesize) == "eeffc79d077be873b173dd0cdd919f8e2d869c5a079034bf9f2a8641d7668a4e"
}

rule MalwareBazaar_unknown_003_f8b08978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b0897860157869bc70f941750ca5e8de199736df83a70f4780af771338a685"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-04 04:05:30"
  condition:
    hash.sha256(0, filesize) == "f8b0897860157869bc70f941750ca5e8de199736df83a70f4780af771338a685"
}

rule MalwareBazaar_unknown_004_82e64906
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82e64906d1187ae30b21d3cbc0988e3fafe9980684ce8ebf2483f6865c615573"
    family = "unknown"
    file_name = ".i"
    file_type = "elf"
    first_seen = "2026-09-04 04:03:25"
  condition:
    hash.sha256(0, filesize) == "82e64906d1187ae30b21d3cbc0988e3fafe9980684ce8ebf2483f6865c615573"
}

rule MalwareBazaar_unknown_005_3efcccb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3efcccb330511f012f1e6a70a989c97d9da951a86cfa24135df5de43748b5645"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-04 04:02:14"
  condition:
    hash.sha256(0, filesize) == "3efcccb330511f012f1e6a70a989c97d9da951a86cfa24135df5de43748b5645"
}

rule MalwareBazaar_Hajime_006_2d8f5d00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d8f5d005671ea3d53be84782493fddb3fd75c496ab712a15a88707cc84e2f82"
    family = "Hajime"
    file_name = ".i"
    file_type = "elf"
    first_seen = "2026-09-04 03:48:06"
  condition:
    hash.sha256(0, filesize) == "2d8f5d005671ea3d53be84782493fddb3fd75c496ab712a15a88707cc84e2f82"
}

rule MalwareBazaar_unknown_007_9644bd30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9644bd301c54b5328829dc3df461d626c5957190954fdc40ca4eb83b2a0842a5"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-09-04 03:43:59"
  condition:
    hash.sha256(0, filesize) == "9644bd301c54b5328829dc3df461d626c5957190954fdc40ca4eb83b2a0842a5"
}

rule MalwareBazaar_unknown_008_9cc59a6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cc59a6e37685c6b866e2dc8e2b21569a218915e2ea224e6f43207928838521e"
    family = "unknown"
    file_name = "9cc59a6e37685c6b866e2dc8e2b21569a218915e2ea224e6f43207928838521e.bin"
    file_type = "exe"
    first_seen = "2026-09-04 03:31:07"
  condition:
    hash.sha256(0, filesize) == "9cc59a6e37685c6b866e2dc8e2b21569a218915e2ea224e6f43207928838521e"
}

rule MalwareBazaar_unknown_009_2149f36b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2149f36bbe37f8fb8e079f77e286df45719a51442ed8b3c1fed6d25d74eb1fec"
    family = "unknown"
    file_name = "2149f36bbe37f8fb8e079f77e286df45719a51442ed8b3c1fed6d25d74eb1fec.exe"
    file_type = "exe"
    first_seen = "2026-09-04 03:17:50"
  condition:
    hash.sha256(0, filesize) == "2149f36bbe37f8fb8e079f77e286df45719a51442ed8b3c1fed6d25d74eb1fec"
}

rule MalwareBazaar_unknown_010_d29fced4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d29fced48d33419fc4241ca8ae6dba28e45e4217c4722e58b58d803b79d93d40"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-04 03:17:13"
  condition:
    hash.sha256(0, filesize) == "d29fced48d33419fc4241ca8ae6dba28e45e4217c4722e58b58d803b79d93d40"
}

rule MalwareBazaar_AgentTesla_011_912cb2fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "912cb2fd882c70b7f8bcf2fa377740ed8b23e13f1c9a63df37350d8a62a613fc"
    family = "AgentTesla"
    file_name = "NEW_ORDER13470_QUOTATION_FORM.js"
    file_type = "js"
    first_seen = "2026-09-04 03:14:25"
  condition:
    hash.sha256(0, filesize) == "912cb2fd882c70b7f8bcf2fa377740ed8b23e13f1c9a63df37350d8a62a613fc"
}

rule MalwareBazaar_unknown_012_a90bceeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a90bceeb8cd9c5978939ed48fd545cc3ac98b8831a1e7a9438b3795372f4d4a6"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-09-04 03:07:46"
  condition:
    hash.sha256(0, filesize) == "a90bceeb8cd9c5978939ed48fd545cc3ac98b8831a1e7a9438b3795372f4d4a6"
}

rule MalwareBazaar_unknown_013_a1179554
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a11795543eb20972c510ded46edef5d4b31e653d56fbd2af0e30b0b2f25a36e1"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-04 03:04:29"
  condition:
    hash.sha256(0, filesize) == "a11795543eb20972c510ded46edef5d4b31e653d56fbd2af0e30b0b2f25a36e1"
}

rule MalwareBazaar_unknown_014_4603b304
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4603b304465a4eb78408eaa74d2d2753c3d022d043197a3bbb8a1d05070f5c2f"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-04 02:58:57"
  condition:
    hash.sha256(0, filesize) == "4603b304465a4eb78408eaa74d2d2753c3d022d043197a3bbb8a1d05070f5c2f"
}

rule MalwareBazaar_unknown_015_8a4b80dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a4b80dcab4bb563fd0220c4268582303ef3816f8eb56b6fa6a5d4b734b913e2"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-04 02:58:56"
  condition:
    hash.sha256(0, filesize) == "8a4b80dcab4bb563fd0220c4268582303ef3816f8eb56b6fa6a5d4b734b913e2"
}

rule MalwareBazaar_unknown_016_e9b770b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9b770b2539cb842ad643706c54286b6b22ef9ec59996dcd9715f54f6b9fdf3f"
    family = "unknown"
    file_name = "e9b770b2539cb842ad643706c54286b6b22ef9ec59996dcd9715f54f6b9fdf3f.exe"
    file_type = "exe"
    first_seen = "2026-09-04 02:32:41"
  condition:
    hash.sha256(0, filesize) == "e9b770b2539cb842ad643706c54286b6b22ef9ec59996dcd9715f54f6b9fdf3f"
}

rule MalwareBazaar_unknown_017_2072c29a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2072c29a227b8cd181ad8fe67a07f75c4de34fed5f824706316bcb6bd804bda7"
    family = "unknown"
    file_name = "Rasmlar5⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀.apk"
    file_type = "apk"
    first_seen = "2026-09-04 02:15:53"
  condition:
    hash.sha256(0, filesize) == "2072c29a227b8cd181ad8fe67a07f75c4de34fed5f824706316bcb6bd804bda7"
}

rule MalwareBazaar_CoinMiner_018_a6451ad4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6451ad4f82ed52fdb02fd705438fe1dfc0fcc3b27e4ff3943413fa1e4dcd13e"
    family = "CoinMiner"
    file_name = "a6451ad4f82ed52fdb02fd705438fe1dfc0fcc3b27e4ff3943413fa1e4dcd13e.exe"
    file_type = "exe"
    first_seen = "2026-09-04 02:12:32"
  condition:
    hash.sha256(0, filesize) == "a6451ad4f82ed52fdb02fd705438fe1dfc0fcc3b27e4ff3943413fa1e4dcd13e"
}

rule MalwareBazaar_Vidar_019_5dd3e489
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dd3e4893fdfc14725eaf22eee3fcf35517cf5f9c71b371632b221daa16f073b"
    family = "Vidar"
    file_name = "5dd3e4893fdfc14725eaf22eee3fcf35517cf5f9c71b371632b221daa16f073b.bin"
    file_type = "exe"
    first_seen = "2026-09-04 01:13:02"
  condition:
    hash.sha256(0, filesize) == "5dd3e4893fdfc14725eaf22eee3fcf35517cf5f9c71b371632b221daa16f073b"
}

rule MalwareBazaar_unknown_020_af3b02f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af3b02f403d1c158b5bf6a0c8c3297b6c98bd665f76a1714220241f88c29c19c"
    family = "unknown"
    file_name = "af3b02f403d1c158b5bf6a0c8c3297b6c98bd665f76a1714220241f88c29c19c.bin"
    file_type = "exe"
    first_seen = "2026-09-04 01:13:00"
  condition:
    hash.sha256(0, filesize) == "af3b02f403d1c158b5bf6a0c8c3297b6c98bd665f76a1714220241f88c29c19c"
}

rule MalwareBazaar_unknown_021_e8ea06ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8ea06ea59484643d43227b3ceb46a914e214ff5744d80c0324b80cf5afbb954"
    family = "unknown"
    file_name = "e8ea06ea59484643d43227b3ceb46a914e214ff5744d80c0324b80cf5afbb954.bin"
    file_type = "exe"
    first_seen = "2026-09-04 01:12:58"
  condition:
    hash.sha256(0, filesize) == "e8ea06ea59484643d43227b3ceb46a914e214ff5744d80c0324b80cf5afbb954"
}

rule MalwareBazaar_unknown_022_7450f96b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7450f96b28ad9b0ba92afbaef480f63d61105afcdb451650ed3a04269ff428ce"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-04 00:23:06"
  condition:
    hash.sha256(0, filesize) == "7450f96b28ad9b0ba92afbaef480f63d61105afcdb451650ed3a04269ff428ce"
}

rule MalwareBazaar_unknown_023_cd6c8133
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd6c8133df97e789160d9c5cc6ef385c2fbe69055b3d7d89d7a14d642a6e4371"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-04 00:22:11"
  condition:
    hash.sha256(0, filesize) == "cd6c8133df97e789160d9c5cc6ef385c2fbe69055b3d7d89d7a14d642a6e4371"
}

rule MalwareBazaar_Vidar_024_1f38faff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f38faff67a42b61ebd3fd6dfe2d5cffcd612336d7a6ec4e6dd491322fedd2e3"
    family = "Vidar"
    file_name = "1f38faff67a42b61ebd3fd6dfe2d5cffcd612336d7a6ec4e6dd491322fedd2e3.bin"
    file_type = "exe"
    first_seen = "2026-09-04 00:09:30"
  condition:
    hash.sha256(0, filesize) == "1f38faff67a42b61ebd3fd6dfe2d5cffcd612336d7a6ec4e6dd491322fedd2e3"
}

rule MalwareBazaar_Vidar_025_6dc13963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dc13963c781c3adb3a3b4bc264ee1370ea2c914ca8d728d7d3c740b8375fbeb"
    family = "Vidar"
    file_name = "6dc13963c781c3adb3a3b4bc264ee1370ea2c914ca8d728d7d3c740b8375fbeb.bin"
    file_type = "exe"
    first_seen = "2026-09-04 00:09:27"
  condition:
    hash.sha256(0, filesize) == "6dc13963c781c3adb3a3b4bc264ee1370ea2c914ca8d728d7d3c740b8375fbeb"
}

rule MalwareBazaar_a310Logger_026_534f3a82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "534f3a82e34e3ac9a8254229595be2a4e8b07e2373c6a5314f4d1f1b16cf988b"
    family = "a310Logger"
    file_name = "Nuevo pedido.exe"
    file_type = "exe"
    first_seen = "2026-09-03 23:33:18"
  condition:
    hash.sha256(0, filesize) == "534f3a82e34e3ac9a8254229595be2a4e8b07e2373c6a5314f4d1f1b16cf988b"
}

rule MalwareBazaar_Vidar_027_510b4341
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "510b4341c6763d5bf045973f4f9832cb8b66a414abda634d4fafed05cba03058"
    family = "Vidar"
    file_name = "510b4341c6763d5bf045973f4f9832cb8b66a414abda634d4fafed05cba03058.exe"
    file_type = "exe"
    first_seen = "2026-09-03 22:53:10"
  condition:
    hash.sha256(0, filesize) == "510b4341c6763d5bf045973f4f9832cb8b66a414abda634d4fafed05cba03058"
}

rule MalwareBazaar_Vidar_028_446cd266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "446cd26639c2d1e09dd9d9edebbd7150d6d5c0f40a4f63c534430c5974a95879"
    family = "Vidar"
    file_name = "446cd26639c2d1e09dd9d9edebbd7150d6d5c0f40a4f63c534430c5974a95879.exe"
    file_type = "exe"
    first_seen = "2026-09-03 22:53:07"
  condition:
    hash.sha256(0, filesize) == "446cd26639c2d1e09dd9d9edebbd7150d6d5c0f40a4f63c534430c5974a95879"
}

rule MalwareBazaar_unknown_029_10c378d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10c378d0449cf7055587933980da9a48ad35a9f71543276573318a6b898c5734"
    family = "unknown"
    file_name = "10c378d0449cf7055587933980da9a48ad35a9f71543276573318a6b898c5734.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:44:01"
  condition:
    hash.sha256(0, filesize) == "10c378d0449cf7055587933980da9a48ad35a9f71543276573318a6b898c5734"
}

rule MalwareBazaar_unknown_030_c2673f1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2673f1f23d1d4e65091b266a84020252600f71f1469f3bbce928f0ffb2468ce"
    family = "unknown"
    file_name = "c2673f1f23d1d4e65091b266a84020252600f71f1469f3bbce928f0ffb2468ce.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:43:59"
  condition:
    hash.sha256(0, filesize) == "c2673f1f23d1d4e65091b266a84020252600f71f1469f3bbce928f0ffb2468ce"
}

rule MalwareBazaar_unknown_031_23343f09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23343f092bcd84f3781c7946aa827dcaf19beedcf09d72358bcbff6d203a4190"
    family = "unknown"
    file_name = "23343f092bcd84f3781c7946aa827dcaf19beedcf09d72358bcbff6d203a4190.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:43:51"
  condition:
    hash.sha256(0, filesize) == "23343f092bcd84f3781c7946aa827dcaf19beedcf09d72358bcbff6d203a4190"
}

rule MalwareBazaar_unknown_032_c69a7da7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c69a7da796aba7168e1edd6c7b8d573592f17a1a8fb74d3307cc68ccf8203bde"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 22:37:45"
  condition:
    hash.sha256(0, filesize) == "c69a7da796aba7168e1edd6c7b8d573592f17a1a8fb74d3307cc68ccf8203bde"
}

rule MalwareBazaar_unknown_033_e811d218
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e811d2180a7fecb0b594623846198e963e5172caa40bcaa2e50577fdde49a422"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 22:05:27"
  condition:
    hash.sha256(0, filesize) == "e811d2180a7fecb0b594623846198e963e5172caa40bcaa2e50577fdde49a422"
}

rule MalwareBazaar_Vidar_034_b84f28bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b84f28bf2872715a977aafd9215358d078ae942c6e8ab1c5b397c189c9f5f970"
    family = "Vidar"
    file_name = "b84f28bf2872715a977aafd9215358d078ae942c6e8ab1c5b397c189c9f5f970.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:03:23"
  condition:
    hash.sha256(0, filesize) == "b84f28bf2872715a977aafd9215358d078ae942c6e8ab1c5b397c189c9f5f970"
}

rule MalwareBazaar_unknown_035_f0ceeb92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0ceeb924803c55384a7491af8af5e229bf25e7e9864e3a94f5eaad4a07d925d"
    family = "unknown"
    file_name = "f0ceeb924803c55384a7491af8af5e229bf25e7e9864e3a94f5eaad4a07d925d.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:03:20"
  condition:
    hash.sha256(0, filesize) == "f0ceeb924803c55384a7491af8af5e229bf25e7e9864e3a94f5eaad4a07d925d"
}

rule MalwareBazaar_unknown_036_56b77af4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56b77af451ae0a131689e1cb3a8964b210403cded8d5ea67fa2b6ec24edabab7"
    family = "unknown"
    file_name = "56b77af451ae0a131689e1cb3a8964b210403cded8d5ea67fa2b6ec24edabab7.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:03:12"
  condition:
    hash.sha256(0, filesize) == "56b77af451ae0a131689e1cb3a8964b210403cded8d5ea67fa2b6ec24edabab7"
}

rule MalwareBazaar_unknown_037_593b391a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "593b391a23ff56696eb2ba54a45ec5eb9c6c574d2b45f5da8ef324cfa3dca95e"
    family = "unknown"
    file_name = "593b391a23ff56696eb2ba54a45ec5eb9c6c574d2b45f5da8ef324cfa3dca95e.bin"
    file_type = "exe"
    first_seen = "2026-09-03 22:03:05"
  condition:
    hash.sha256(0, filesize) == "593b391a23ff56696eb2ba54a45ec5eb9c6c574d2b45f5da8ef324cfa3dca95e"
}

rule MalwareBazaar_unknown_038_27acfd79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27acfd79d14615e57aaaf388585dcd0be08ec68e2b5518f01e9e34fccb0bc580"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 21:59:10"
  condition:
    hash.sha256(0, filesize) == "27acfd79d14615e57aaaf388585dcd0be08ec68e2b5518f01e9e34fccb0bc580"
}

rule MalwareBazaar_unknown_039_9d167a03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d167a03a2b930cd2a35629de0bccb266650b00b3fafa30536f354b58d2364b0"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 21:56:09"
  condition:
    hash.sha256(0, filesize) == "9d167a03a2b930cd2a35629de0bccb266650b00b3fafa30536f354b58d2364b0"
}

rule MalwareBazaar_Mirai_040_f5c15413
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c154134bce86beb4386680a8b5ae47dde22bbba2de5930451a4799c84ed9a8"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-03 21:47:35"
  condition:
    hash.sha256(0, filesize) == "f5c154134bce86beb4386680a8b5ae47dde22bbba2de5930451a4799c84ed9a8"
}

rule MalwareBazaar_unknown_041_d6a5ec91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6a5ec91bf15db1764e679ad0c72e83231c4558df1b670435db983c387183cab"
    family = "unknown"
    file_name = "asir.vbs"
    file_type = "vbs"
    first_seen = "2026-09-03 21:46:08"
  condition:
    hash.sha256(0, filesize) == "d6a5ec91bf15db1764e679ad0c72e83231c4558df1b670435db983c387183cab"
}

rule MalwareBazaar_Hajime_042_74405a7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74405a7d486faf2f6f860ea2ef655057ff24ed4291f8f6f5fae1476438cf83ec"
    family = "Hajime"
    file_name = ".i"
    file_type = "elf"
    first_seen = "2026-09-03 21:38:21"
  condition:
    hash.sha256(0, filesize) == "74405a7d486faf2f6f860ea2ef655057ff24ed4291f8f6f5fae1476438cf83ec"
}

rule MalwareBazaar_unknown_043_8d052ddf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d052ddfa9a02d357839dfcbf9bb6e339e7d96006e01c63738dcca15088c515d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 21:26:08"
  condition:
    hash.sha256(0, filesize) == "8d052ddfa9a02d357839dfcbf9bb6e339e7d96006e01c63738dcca15088c515d"
}

rule MalwareBazaar_unknown_044_f3448e65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3448e6541987ff34dfdbf86b8041f2965bae032a6c07275cf581278e3f9e87c"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 21:19:57"
  condition:
    hash.sha256(0, filesize) == "f3448e6541987ff34dfdbf86b8041f2965bae032a6c07275cf581278e3f9e87c"
}

rule MalwareBazaar_unknown_045_468e9a99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "468e9a99e5396616920ed8fbfcb805cf41744e825a51f97182b4c32265d9e5c0"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 21:19:56"
  condition:
    hash.sha256(0, filesize) == "468e9a99e5396616920ed8fbfcb805cf41744e825a51f97182b4c32265d9e5c0"
}

rule MalwareBazaar_unknown_046_364430d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "364430d2928b2093931be171cbb7843362e58e84909c69f94afd8031669fc147"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 21:12:54"
  condition:
    hash.sha256(0, filesize) == "364430d2928b2093931be171cbb7843362e58e84909c69f94afd8031669fc147"
}

rule MalwareBazaar_unknown_047_6ae6dffd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ae6dffd29777f4d2b12c4eeccfcc5098455b7a7965af4a8de60d62c4b62161b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 21:12:53"
  condition:
    hash.sha256(0, filesize) == "6ae6dffd29777f4d2b12c4eeccfcc5098455b7a7965af4a8de60d62c4b62161b"
}

rule MalwareBazaar_unknown_048_78d45a3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78d45a3d9b2e82f6a181d42f6bf9262d2685bafb84a848201a4377c815c2f50c"
    family = "unknown"
    file_name = "78d45a3d9b2e82f6a181d42f6bf9262d2685bafb84a848201a4377c815c2f50c.exe"
    file_type = "exe"
    first_seen = "2026-09-03 21:12:45"
  condition:
    hash.sha256(0, filesize) == "78d45a3d9b2e82f6a181d42f6bf9262d2685bafb84a848201a4377c815c2f50c"
}

rule MalwareBazaar_Hajime_049_6e5096f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e5096f66eb3085ec5d46ddf615298155ef1c46190d56b049fc1c58a145a96b5"
    family = "Hajime"
    file_name = ".i"
    file_type = "elf"
    first_seen = "2026-09-03 21:11:51"
  condition:
    hash.sha256(0, filesize) == "6e5096f66eb3085ec5d46ddf615298155ef1c46190d56b049fc1c58a145a96b5"
}

rule MalwareBazaar_unknown_050_963724d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "963724d1dda73996ac4f1f3c323fb731a6151ecde39a14cf0e630b35a739c6fa"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 21:04:33"
  condition:
    hash.sha256(0, filesize) == "963724d1dda73996ac4f1f3c323fb731a6151ecde39a14cf0e630b35a739c6fa"
}

rule MalwareBazaar_unknown_051_32bc638e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32bc638e0ae70b242880865bf149dbb8f6a9e8b30211e01382074a234beaa73e"
    family = "unknown"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-09-03 21:00:59"
  condition:
    hash.sha256(0, filesize) == "32bc638e0ae70b242880865bf149dbb8f6a9e8b30211e01382074a234beaa73e"
}

rule MalwareBazaar_unknown_052_cd4fe48b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd4fe48bb85f3614623571ffbdc253e6b6d3fec7d90f45fe70febbeff2df3a5b"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-09-03 20:48:52"
  condition:
    hash.sha256(0, filesize) == "cd4fe48bb85f3614623571ffbdc253e6b6d3fec7d90f45fe70febbeff2df3a5b"
}

rule MalwareBazaar_Vidar_053_1c8be957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c8be957532c4c60de31a897fe0555388e6c1e87ff22199d45ddcbbeee65203c"
    family = "Vidar"
    file_name = "1c8be957532c4c60de31a897fe0555388e6c1e87ff22199d45ddcbbeee65203c.bin"
    file_type = "exe"
    first_seen = "2026-09-03 20:48:13"
  condition:
    hash.sha256(0, filesize) == "1c8be957532c4c60de31a897fe0555388e6c1e87ff22199d45ddcbbeee65203c"
}

rule MalwareBazaar_unknown_054_0b3c5025
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b3c50255286e9484b4cc1dadad98849d3f5aeb3de6d69345a7786c441473b89"
    family = "unknown"
    file_name = "0b3c50255286e9484b4cc1dadad98849d3f5aeb3de6d69345a7786c441473b89.bin"
    file_type = "exe"
    first_seen = "2026-09-03 20:48:11"
  condition:
    hash.sha256(0, filesize) == "0b3c50255286e9484b4cc1dadad98849d3f5aeb3de6d69345a7786c441473b89"
}

rule MalwareBazaar_unknown_055_54f54235
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54f54235295cf9e4cead191b7fd2e027a4bda1c03e163e44f5c3b4f40e1489ce"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 20:45:54"
  condition:
    hash.sha256(0, filesize) == "54f54235295cf9e4cead191b7fd2e027a4bda1c03e163e44f5c3b4f40e1489ce"
}

rule MalwareBazaar_unknown_056_7a8a6244
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a8a6244a95c1ab28655155f24e6aee56510b285180aaee49a188127ecf15718"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-03 20:44:48"
  condition:
    hash.sha256(0, filesize) == "7a8a6244a95c1ab28655155f24e6aee56510b285180aaee49a188127ecf15718"
}

rule MalwareBazaar_unknown_057_704dcac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "704dcac75a1ac1d08bc97d3c837a9cd4dc5f7b3ba84056b2557dcf4063638640"
    family = "unknown"
    file_name = "main"
    file_type = "elf"
    first_seen = "2026-09-03 20:37:55"
  condition:
    hash.sha256(0, filesize) == "704dcac75a1ac1d08bc97d3c837a9cd4dc5f7b3ba84056b2557dcf4063638640"
}

rule MalwareBazaar_unknown_058_f957c094
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f957c0945b74dbc576c0a945151f1de1e33dc51562003ff2d931e972106cb2d7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 20:36:50"
  condition:
    hash.sha256(0, filesize) == "f957c0945b74dbc576c0a945151f1de1e33dc51562003ff2d931e972106cb2d7"
}

rule MalwareBazaar_unknown_059_306ce2d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "306ce2d64f3741554000297cc8b8f7ace47c03691e2ec1ee8c5fb4032457430a"
    family = "unknown"
    file_name = "boss"
    file_type = "elf"
    first_seen = "2026-09-03 20:34:59"
  condition:
    hash.sha256(0, filesize) == "306ce2d64f3741554000297cc8b8f7ace47c03691e2ec1ee8c5fb4032457430a"
}

rule MalwareBazaar_unknown_060_1a522d46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a522d46b6fae707730f6461728e873b8b9ef12b0628b118c699722a564722e7"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 20:29:50"
  condition:
    hash.sha256(0, filesize) == "1a522d46b6fae707730f6461728e873b8b9ef12b0628b118c699722a564722e7"
}

rule MalwareBazaar_unknown_061_88bba386
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88bba386083e93441241f99a728f93d11200d7c6709d69619d2a7cc551b17b79"
    family = "unknown"
    file_name = "88bba386083e93441241f99a728f93d11200d7c6709d69619d2a7cc551b17b79.exe"
    file_type = "exe"
    first_seen = "2026-09-03 20:27:32"
  condition:
    hash.sha256(0, filesize) == "88bba386083e93441241f99a728f93d11200d7c6709d69619d2a7cc551b17b79"
}

rule MalwareBazaar_DarkCloud_062_f7362f30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7362f301153af7d0d5007ccee3c134e4558f561a3331df84de7ae39d0b16587"
    family = "DarkCloud"
    file_name = "PAGO (FACTURAS VENCIDAS).js"
    file_type = "js"
    first_seen = "2026-09-03 20:22:44"
  condition:
    hash.sha256(0, filesize) == "f7362f301153af7d0d5007ccee3c134e4558f561a3331df84de7ae39d0b16587"
}

rule MalwareBazaar_unknown_063_94892ba2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94892ba2d9046b9c53ac9e9e44587e613a6049e3f9637d98c4f08c9202e23dae"
    family = "unknown"
    file_name = "goodthingsforbestpersonforme.hta"
    file_type = "hta"
    first_seen = "2026-09-03 20:20:53"
  condition:
    hash.sha256(0, filesize) == "94892ba2d9046b9c53ac9e9e44587e613a6049e3f9637d98c4f08c9202e23dae"
}

rule MalwareBazaar_unknown_064_e78dffa0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e78dffa0d36113939f1c96bcd004002d5fc802346a04533a8237daabf6a41ec4"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 20:15:46"
  condition:
    hash.sha256(0, filesize) == "e78dffa0d36113939f1c96bcd004002d5fc802346a04533a8237daabf6a41ec4"
}

rule MalwareBazaar_Formbook_065_5086b7c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5086b7c16787a690f8f37ca6c99424e8f469c994d9129abdc81a798602de07f7"
    family = "Formbook"
    file_name = "ps_LdSxTLJsoHK1_1780649359263.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:12:07"
  condition:
    hash.sha256(0, filesize) == "5086b7c16787a690f8f37ca6c99424e8f469c994d9129abdc81a798602de07f7"
}

rule MalwareBazaar_Formbook_066_9e423648
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e42364846f90f1d69fa58908a3fda721d82673a46bba32a971c6e8d0096ec85"
    family = "Formbook"
    file_name = "ps_fVCnsMA0wimh_1780714347070.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:12:01"
  condition:
    hash.sha256(0, filesize) == "9e42364846f90f1d69fa58908a3fda721d82673a46bba32a971c6e8d0096ec85"
}

rule MalwareBazaar_Formbook_067_896d7475
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "896d7475d148a41cc8975671a96501aa53dc0eab1066b61180d1a21287fa00c4"
    family = "Formbook"
    file_name = "ps_bG5HYG6hsI6T_1780650001945.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:11:52"
  condition:
    hash.sha256(0, filesize) == "896d7475d148a41cc8975671a96501aa53dc0eab1066b61180d1a21287fa00c4"
}

rule MalwareBazaar_unknown_068_cdda4308
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdda430869d4232ddb7dbfefe83847c3d3b87a30e8c8847f9b88b282e6eba3b6"
    family = "unknown"
    file_name = "hrmmt4a6k03.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:11:44"
  condition:
    hash.sha256(0, filesize) == "cdda430869d4232ddb7dbfefe83847c3d3b87a30e8c8847f9b88b282e6eba3b6"
}

rule MalwareBazaar_unknown_069_bb9dd116
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb9dd11647c31cdff00e53d1aff330f55c7e1f5d8ad7fa2e33b34ac795be05fc"
    family = "unknown"
    file_name = "cfg_92023_c3ee.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:11:39"
  condition:
    hash.sha256(0, filesize) == "bb9dd11647c31cdff00e53d1aff330f55c7e1f5d8ad7fa2e33b34ac795be05fc"
}

rule MalwareBazaar_AveMariaRAT_070_b2660a2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2660a2e88514b6fe1ff2f776c96ab852b0ce563c5a2258a199a2eb2bdb19a1d"
    family = "AveMariaRAT"
    file_name = "BJ8HSYL8.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:11:32"
  condition:
    hash.sha256(0, filesize) == "b2660a2e88514b6fe1ff2f776c96ab852b0ce563c5a2258a199a2eb2bdb19a1d"
}

rule MalwareBazaar_unknown_071_a9b17c0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9b17c0d8d304986e1f0ece95c3ef34d8ebc755484fe95320b8dccfc41bd74e4"
    family = "unknown"
    file_name = "208kmt4a58cq.ps1"
    file_type = "ps1"
    first_seen = "2026-09-03 20:11:19"
  condition:
    hash.sha256(0, filesize) == "a9b17c0d8d304986e1f0ece95c3ef34d8ebc755484fe95320b8dccfc41bd74e4"
}

rule MalwareBazaar_ValleyRAT_072_2faf35c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2faf35c81460f594d5471186c8a9be65c004c92c5f3968a67e8e88c11a35d347"
    family = "ValleyRAT"
    file_name = "1582E41E322D062A5DF941B89184047F.dll"
    file_type = "dll"
    first_seen = "2026-09-03 20:10:19"
  condition:
    hash.sha256(0, filesize) == "2faf35c81460f594d5471186c8a9be65c004c92c5f3968a67e8e88c11a35d347"
}

rule MalwareBazaar_ValleyRAT_073_52e889aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52e889aa77ee3e84835f700f19ea091d48b7e0682c13cba6941129cdf9de27ba"
    family = "ValleyRAT"
    file_name = "CD4F959C7AAC421945DD04A12535941C.exe"
    file_type = "exe"
    first_seen = "2026-09-03 20:10:13"
  condition:
    hash.sha256(0, filesize) == "52e889aa77ee3e84835f700f19ea091d48b7e0682c13cba6941129cdf9de27ba"
}

rule MalwareBazaar_njrat_074_64d8f645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64d8f6456140746ac1e5131ab8ada166c62893d53e7daf3d6a829292a7cfefd8"
    family = "njrat"
    file_name = "743759338B45950208EA9D6CB6A99AA1.exe"
    file_type = "exe"
    first_seen = "2026-09-03 20:10:07"
  condition:
    hash.sha256(0, filesize) == "64d8f6456140746ac1e5131ab8ada166c62893d53e7daf3d6a829292a7cfefd8"
}

rule MalwareBazaar_CoinMiner_075_e3fc2840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3fc2840cec07dff9c35f528bbe7b3efbe1d60d9a8de9d1467a47cfa7016c278"
    family = "CoinMiner"
    file_name = "e3fc2840cec07dff9c35f528bbe7b3efbe1d60d9a8de9d1467a47cfa7016c278.exe"
    file_type = "exe"
    first_seen = "2026-09-03 20:07:35"
  condition:
    hash.sha256(0, filesize) == "e3fc2840cec07dff9c35f528bbe7b3efbe1d60d9a8de9d1467a47cfa7016c278"
}

rule MalwareBazaar_unknown_076_b70cb5ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b70cb5ed22247c42ec5fa7d1f4bdfb570355067dc70ac05adeff8c6d70e57aec"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 20:04:47"
  condition:
    hash.sha256(0, filesize) == "b70cb5ed22247c42ec5fa7d1f4bdfb570355067dc70ac05adeff8c6d70e57aec"
}

rule MalwareBazaar_Vidar_077_61736410
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6173641022865c703539ad968331c59f1d5da03add825a79b6d0719bf7c07ed1"
    family = "Vidar"
    file_name = "6173641022865c703539ad968331c59f1d5da03add825a79b6d0719bf7c07ed1.bin"
    file_type = "exe"
    first_seen = "2026-09-03 19:36:32"
  condition:
    hash.sha256(0, filesize) == "6173641022865c703539ad968331c59f1d5da03add825a79b6d0719bf7c07ed1"
}

rule MalwareBazaar_Formbook_078_bec2b8cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bec2b8cf49b15d40abc3d0f8d36ee3a2282928f36250278b1f27d9236e0d90db"
    family = "Formbook"
    file_name = "Ref 2026093-2694.exe"
    file_type = "exe"
    first_seen = "2026-09-03 19:36:31"
  condition:
    hash.sha256(0, filesize) == "bec2b8cf49b15d40abc3d0f8d36ee3a2282928f36250278b1f27d9236e0d90db"
}

rule MalwareBazaar_Vidar_079_1465f0a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1465f0a6ed279e87983f39f9b81e989eb0e92898e21a364ab7fc17a84c808079"
    family = "Vidar"
    file_name = "1465f0a6ed279e87983f39f9b81e989eb0e92898e21a364ab7fc17a84c808079.bin"
    file_type = "exe"
    first_seen = "2026-09-03 19:36:29"
  condition:
    hash.sha256(0, filesize) == "1465f0a6ed279e87983f39f9b81e989eb0e92898e21a364ab7fc17a84c808079"
}

rule MalwareBazaar_Vidar_080_0f08da5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f08da5bc3d2c32bd0367d586279d4c7cfc7d35d7ac97cd2ead4b7f4327a8a3a"
    family = "Vidar"
    file_name = "0f08da5bc3d2c32bd0367d586279d4c7cfc7d35d7ac97cd2ead4b7f4327a8a3a.bin"
    file_type = "exe"
    first_seen = "2026-09-03 19:36:21"
  condition:
    hash.sha256(0, filesize) == "0f08da5bc3d2c32bd0367d586279d4c7cfc7d35d7ac97cd2ead4b7f4327a8a3a"
}

rule MalwareBazaar_unknown_081_07936bd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07936bd8a05d6db787bfa5f8b10c1335ef708f660dcd2b1eee715c9b66283e80"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 19:08:42"
  condition:
    hash.sha256(0, filesize) == "07936bd8a05d6db787bfa5f8b10c1335ef708f660dcd2b1eee715c9b66283e80"
}

rule MalwareBazaar_unknown_082_d43ee01d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d43ee01d07e64fd87dc611ea826f31109971e6a2d52acc47fbb08d2dcf5567de"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 19:08:32"
  condition:
    hash.sha256(0, filesize) == "d43ee01d07e64fd87dc611ea826f31109971e6a2d52acc47fbb08d2dcf5567de"
}

rule MalwareBazaar_RustyStealer_083_ffb3eacf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffb3eacf4164d66a8d5e591c043f3f86d599e8d39384417d6fdf78796ae18a84"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 18:38:25"
  condition:
    hash.sha256(0, filesize) == "ffb3eacf4164d66a8d5e591c043f3f86d599e8d39384417d6fdf78796ae18a84"
}

rule MalwareBazaar_Vidar_084_117e2c3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "117e2c3d3b40a2b2cbb2001fa0c1109e51cdec777672d5b325e7edecac442fdd"
    family = "Vidar"
    file_name = "117e2c3d3b40a2b2cbb2001fa0c1109e51cdec777672d5b325e7edecac442fdd.bin"
    file_type = "exe"
    first_seen = "2026-09-03 18:25:10"
  condition:
    hash.sha256(0, filesize) == "117e2c3d3b40a2b2cbb2001fa0c1109e51cdec777672d5b325e7edecac442fdd"
}

rule MalwareBazaar_unknown_085_06d242a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06d242a6f28c23fd708289cd8d40ec6d1fec310559d9f4c13b4ad4703cd99c31"
    family = "unknown"
    file_name = "06d242a6f28c23fd708289cd8d40ec6d1fec310559d9f4c13b4ad4703cd99c31.exe"
    file_type = "exe"
    first_seen = "2026-09-03 17:42:34"
  condition:
    hash.sha256(0, filesize) == "06d242a6f28c23fd708289cd8d40ec6d1fec310559d9f4c13b4ad4703cd99c31"
}

rule MalwareBazaar_Vidar_086_cfad7093
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfad7093da1fc7ac1ea128ce094bad881aa0efae772ed7e19dc915baaae41ae6"
    family = "Vidar"
    file_name = "cfad7093da1fc7ac1ea128ce094bad881aa0efae772ed7e19dc915baaae41ae6.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:19:24"
  condition:
    hash.sha256(0, filesize) == "cfad7093da1fc7ac1ea128ce094bad881aa0efae772ed7e19dc915baaae41ae6"
}

rule MalwareBazaar_Vidar_087_fd495872
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd4958729e313d36cb6073de5bbf2e3958d22cb6164e724bd62f6ecd08d1b6f8"
    family = "Vidar"
    file_name = "fd4958729e313d36cb6073de5bbf2e3958d22cb6164e724bd62f6ecd08d1b6f8.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:19:16"
  condition:
    hash.sha256(0, filesize) == "fd4958729e313d36cb6073de5bbf2e3958d22cb6164e724bd62f6ecd08d1b6f8"
}

rule MalwareBazaar_Vidar_088_303c0c48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "303c0c4820a3b87f871a11c375b710841db12a436274481c4268150aba9c684a"
    family = "Vidar"
    file_name = "303c0c4820a3b87f871a11c375b710841db12a436274481c4268150aba9c684a.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:19:14"
  condition:
    hash.sha256(0, filesize) == "303c0c4820a3b87f871a11c375b710841db12a436274481c4268150aba9c684a"
}

rule MalwareBazaar_Vidar_089_282b9ca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "282b9ca1179778a4fd508369f34eb5d7f89db4c657923990291a508bd34c7502"
    family = "Vidar"
    file_name = "282b9ca1179778a4fd508369f34eb5d7f89db4c657923990291a508bd34c7502.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:19:06"
  condition:
    hash.sha256(0, filesize) == "282b9ca1179778a4fd508369f34eb5d7f89db4c657923990291a508bd34c7502"
}

rule MalwareBazaar_Vidar_090_e9cbdf07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9cbdf075ce85bfcfe248335ecbd64d99e8335db88bbf3d7016e1f52c8bce72d"
    family = "Vidar"
    file_name = "e9cbdf075ce85bfcfe248335ecbd64d99e8335db88bbf3d7016e1f52c8bce72d.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:19:03"
  condition:
    hash.sha256(0, filesize) == "e9cbdf075ce85bfcfe248335ecbd64d99e8335db88bbf3d7016e1f52c8bce72d"
}

rule MalwareBazaar_Vidar_091_f8ca909c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8ca909c103deea084f14d8d9361b783b75f18b73107863f6105ab5037ef8d54"
    family = "Vidar"
    file_name = "f8ca909c103deea084f14d8d9361b783b75f18b73107863f6105ab5037ef8d54.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:18:53"
  condition:
    hash.sha256(0, filesize) == "f8ca909c103deea084f14d8d9361b783b75f18b73107863f6105ab5037ef8d54"
}

rule MalwareBazaar_Vidar_092_fcfe6b8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcfe6b8eb9523a107d294f79f65a66995cc6237985f89db67f4cd7ce9264243e"
    family = "Vidar"
    file_name = "fcfe6b8eb9523a107d294f79f65a66995cc6237985f89db67f4cd7ce9264243e.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:18:45"
  condition:
    hash.sha256(0, filesize) == "fcfe6b8eb9523a107d294f79f65a66995cc6237985f89db67f4cd7ce9264243e"
}

rule MalwareBazaar_Vidar_093_239e0d13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "239e0d138b7d137ae4f76476fdf2ba10d17dcf0b40a5d818b7e01612ac69dcb2"
    family = "Vidar"
    file_name = "239e0d138b7d137ae4f76476fdf2ba10d17dcf0b40a5d818b7e01612ac69dcb2.bin"
    file_type = "exe"
    first_seen = "2026-09-03 17:17:12"
  condition:
    hash.sha256(0, filesize) == "239e0d138b7d137ae4f76476fdf2ba10d17dcf0b40a5d818b7e01612ac69dcb2"
}

rule MalwareBazaar_unknown_094_1c852cc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c852cc5ab0847f57908869ad14b2c1385bec46a8377f67b779aada5a5d59dc0"
    family = "unknown"
    file_name = "secondfast.exe"
    file_type = "exe"
    first_seen = "2026-09-03 16:52:12"
  condition:
    hash.sha256(0, filesize) == "1c852cc5ab0847f57908869ad14b2c1385bec46a8377f67b779aada5a5d59dc0"
}

rule MalwareBazaar_unknown_095_bff3cd04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bff3cd04c6b600b87ac9ef4365ef39701c512ce41079d124aa6e0ac06be38e03"
    family = "unknown"
    file_name = "sunwukongs.exe"
    file_type = "unknown"
    first_seen = "2026-09-03 16:52:03"
  condition:
    hash.sha256(0, filesize) == "bff3cd04c6b600b87ac9ef4365ef39701c512ce41079d124aa6e0ac06be38e03"
}

rule MalwareBazaar_unknown_096_533a9a6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "533a9a6ff75a172b2e996391ad2dd93e615b31fd6f920e28a111f94284400440"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 16:51:19"
  condition:
    hash.sha256(0, filesize) == "533a9a6ff75a172b2e996391ad2dd93e615b31fd6f920e28a111f94284400440"
}

rule MalwareBazaar_unknown_097_acde9620
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acde9620e5ca90b9033d6f42c260c8dc99a54d6b447fa4d6648ed3e99c80b68b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 16:50:58"
  condition:
    hash.sha256(0, filesize) == "acde9620e5ca90b9033d6f42c260c8dc99a54d6b447fa4d6648ed3e99c80b68b"
}

rule MalwareBazaar_unknown_098_ec7b0194
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec7b0194baf1566c838ace76958ac4e3a2d47fb082d861f9a2e81004cbae9809"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-03 16:44:08"
  condition:
    hash.sha256(0, filesize) == "ec7b0194baf1566c838ace76958ac4e3a2d47fb082d861f9a2e81004cbae9809"
}

rule MalwareBazaar_Vidar_099_9ac9ca5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ac9ca5ebfe5c1cba3785c7666bf58420a06b1e41796d3f137289b7d528c71bd"
    family = "Vidar"
    file_name = "9ac9ca5ebfe5c1cba3785c7666bf58420a06b1e41796d3f137289b7d528c71bd.bin"
    file_type = "exe"
    first_seen = "2026-09-03 16:42:41"
  condition:
    hash.sha256(0, filesize) == "9ac9ca5ebfe5c1cba3785c7666bf58420a06b1e41796d3f137289b7d528c71bd"
}

rule MalwareBazaar_Vidar_100_995e67cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "995e67cd9eac426284a4b701380a5e675e6459ea47cace9cfd5b8cc87a2ebbf2"
    family = "Vidar"
    file_name = "995e67cd9eac426284a4b701380a5e675e6459ea47cace9cfd5b8cc87a2ebbf2.bin"
    file_type = "exe"
    first_seen = "2026-09-03 16:42:39"
  condition:
    hash.sha256(0, filesize) == "995e67cd9eac426284a4b701380a5e675e6459ea47cace9cfd5b8cc87a2ebbf2"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

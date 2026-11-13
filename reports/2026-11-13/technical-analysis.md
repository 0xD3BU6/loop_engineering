# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-13

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 679 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 679 |
| Unique family labels | 20 |
| Unique file types | 11 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 31 |
| Mirai | 22 |
| RustyStealer | 6 |
| ConnectWise | 6 |
| WARDENStealer | 5 |
| GuLoader | 4 |
| CoinMiner | 4 |
| njrat | 3 |
| Adware.OfferCore | 3 |
| RevStealer | 3 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 47 |
| elf | 24 |
| js | 7 |
| ps1 | 6 |
| msi | 6 |
| vbs | 4 |
| zip | 2 |
| sh | 1 |
| apk | 1 |
| macho | 1 |

## Per-Sample Analysis

### Sample 1: `b97b08b19719bafd`

| Field | Value |
|---|---|
| SHA-256 | `b97b08b19719bafde8bfc9c571b280352313c292fc055044eb2f8158df4d5b9f` |
| Family label | `unknown` |
| File name | `modules.cache` |
| File type | `zip` |
| First seen | `2026-11-13 06:32:45` |
| Reporter | `LoneNco` |
| Tags | `ens, etherhiding, ewa, irahook, jar, java, qProtect, RAT, stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `979aa153c981f33c8c8b62c78d00cc3c` |
| SHA-1 | `c756aded3efaa10fb43516ba92d5a6df1b96dc29` |
| SHA-256 | `b97b08b19719bafde8bfc9c571b280352313c292fc055044eb2f8158df4d5b9f` |
| SHA3-384 | `7f375d70ba2a5ef845eae20686cb29d4af8ea0d153c329712a3b3552237fe881856dba0ee3b2c2a2279240617451ab48` |
| TLSH | `T177773316BFD5E528D97350B359C3C3D3642B26D9980AC12F1AE04DC48DB1EAA0B52FED` |
| SSDEEP | `786432:/yJDM5DOvbkwytYr2oi1MBa6WCeZN8EjVLuvbvBiui6tJSBOEA:/QAO/KogMonHZN86LmBiuiScA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_b97b08b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b97b08b19719bafde8bfc9c571b280352313c292fc055044eb2f8158df4d5b9f"
    family = "unknown"
    file_name = "modules.cache"
    file_type = "zip"
    first_seen = "2026-11-13 06:32:45"
  condition:
    hash.sha256(0, filesize) == "b97b08b19719bafde8bfc9c571b280352313c292fc055044eb2f8158df4d5b9f"
}
```

### Sample 2: `79ad7957bee56165`

| Field | Value |
|---|---|
| SHA-256 | `79ad7957bee56165aa1b7f5a8e352918373c37ef830193deb47f002b03ef7b75` |
| Family label | `GuLoader` |
| File name | `Afgringernes.vbs` |
| File type | `vbs` |
| First seen | `2026-11-13 06:05:01` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f7e84a73a817212398b08224669a989` |
| SHA-1 | `1210dae8274ad205fd5542f66bd1c91747d81e4c` |
| SHA-256 | `79ad7957bee56165aa1b7f5a8e352918373c37ef830193deb47f002b03ef7b75` |
| SHA3-384 | `488cbfb8e70f5b01b56be203993255d5cd8e8cbcfdba54a2c3f6fcb6682ea1bf42ce0bd0411ef04ec70bd32db7216f69` |
| TLSH | `T145C37278B5642739EDBA165DB8C8F650C5E8E187023320A7BF84124B500EDDCE77AE97` |
| SSDEEP | `1536:kNVWCb5SiQGYxkX+B/1VWIIC8BoO1J4occRZOs6S26ra70nVfBp4gsW:kPWeh/X41IY2X1ycRZ64Gq4gsW` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_002_79ad7957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79ad7957bee56165aa1b7f5a8e352918373c37ef830193deb47f002b03ef7b75"
    family = "GuLoader"
    file_name = "Afgringernes.vbs"
    file_type = "vbs"
    first_seen = "2026-11-13 06:05:01"
  condition:
    hash.sha256(0, filesize) == "79ad7957bee56165aa1b7f5a8e352918373c37ef830193deb47f002b03ef7b75"
}
```

### Sample 3: `6694a062d8e52456`

| Field | Value |
|---|---|
| SHA-256 | `6694a062d8e52456c9a4b4d691109d7521edc25e8b8861f99a464fa346814713` |
| Family label | `AgentTesla` |
| File name | `datos bancarios.js` |
| File type | `js` |
| First seen | `2026-11-13 05:57:33` |
| Reporter | `lowmal3` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3cab25a07dfdb079e6d66867e8265b2` |
| SHA-1 | `54b7ecba5709286f5f94b5ba27b67ac8277be73c` |
| SHA-256 | `6694a062d8e52456c9a4b4d691109d7521edc25e8b8861f99a464fa346814713` |
| SHA3-384 | `c652719300691d591807cd73d2f8d0e750a5d15003c50a8abc7d34c43d3e0b63267809681c49477576ef9c366d80dfbe` |
| TLSH | `T1DA054B60EE24066A4F475BADFDD54762CABCC50A422754F1E6DE030E61069FCE3BE26C` |
| SSDEEP | `24576:1OYUOcwCOcEwsOcE0OcEuOcEwOocO78OcEwkjgcOcEcOcEOSlOcEWcPOcEw/uOcG:8DEwgE4EyEw+EwQEQEXEBEwaEwYEtjEl` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_003_6694a062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6694a062d8e52456c9a4b4d691109d7521edc25e8b8861f99a464fa346814713"
    family = "AgentTesla"
    file_name = "datos bancarios.js"
    file_type = "js"
    first_seen = "2026-11-13 05:57:33"
  condition:
    hash.sha256(0, filesize) == "6694a062d8e52456c9a4b4d691109d7521edc25e8b8861f99a464fa346814713"
}
```

### Sample 4: `47c4acbf6d15b61a`

| Field | Value |
|---|---|
| SHA-256 | `47c4acbf6d15b61a12d3411c0caea69751c6e86ccc91c894619ed8dfe3ebcc8f` |
| Family label | `FormBook` |
| File name | `DHL_AWB#6078538091.JS` |
| File type | `js` |
| First seen | `2026-11-13 05:57:11` |
| Reporter | `lowmal3` |
| Tags | `FormBook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43c09c761e7f19310e15de0c3984b32e` |
| SHA-1 | `a486879b3887657695f663b115c6f6b0c8e6ac92` |
| SHA-256 | `47c4acbf6d15b61a12d3411c0caea69751c6e86ccc91c894619ed8dfe3ebcc8f` |
| SHA3-384 | `2e675ee6974e590443e9d0c11fce097db7c07fb45cac50f5a4f24ab80e901a8abfd20b7264ffb5ae4e5a19d06df3fc10` |
| TLSH | `T150D529742520E6B3A474D49D4F4BAAD91CC8BF0FB8E1D4B37612F5BA4A06BE02DC4365` |
| SSDEEP | `49152:geP7kDQz7WQlyLRyDstBmfU2cJUZhYoFMDb:geP7kDQziQlyLRyDmAUHJUZhYoFMDb` |

#### Technical Assessment

- The sample is tracked as `FormBook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_FormBook_004_47c4acbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47c4acbf6d15b61a12d3411c0caea69751c6e86ccc91c894619ed8dfe3ebcc8f"
    family = "FormBook"
    file_name = "DHL_AWB#6078538091.JS"
    file_type = "js"
    first_seen = "2026-11-13 05:57:11"
  condition:
    hash.sha256(0, filesize) == "47c4acbf6d15b61a12d3411c0caea69751c6e86ccc91c894619ed8dfe3ebcc8f"
}
```

### Sample 5: `c59fae03348d1a48`

| Field | Value |
|---|---|
| SHA-256 | `c59fae03348d1a48c1d0e4164284d06d44b13abc39fc76037d00e3b244ddafac` |
| Family label | `unknown` |
| File name | `348277489244739494.js` |
| File type | `js` |
| First seen | `2026-11-13 05:56:54` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c416421aea5ae2818086ed01a04d0719` |
| SHA-1 | `4b9421d5b6357a201d90316a3fa7f10b8261914a` |
| SHA-256 | `c59fae03348d1a48c1d0e4164284d06d44b13abc39fc76037d00e3b244ddafac` |
| SHA3-384 | `f974bf1b095fe7af161058436c4562a1483e4c5b10c84c31e654ea6465939288e1a1943fcb92aa293793b41b7cbe0054` |
| TLSH | `T160B485960295960CF3758E2DF1650225426F6F99E93C532E648C1D8C7B63D00BEB2BBF` |
| SSDEEP | `3072:hzZDvRinjW0URznWKnR+at4JYpIhhRYKB/zS0C/37UiHwfb6NH7AnC+kdoD+VbI7:HNmdzh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_c59fae03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c59fae03348d1a48c1d0e4164284d06d44b13abc39fc76037d00e3b244ddafac"
    family = "unknown"
    file_name = "348277489244739494.js"
    file_type = "js"
    first_seen = "2026-11-13 05:56:54"
  condition:
    hash.sha256(0, filesize) == "c59fae03348d1a48c1d0e4164284d06d44b13abc39fc76037d00e3b244ddafac"
}
```

### Sample 6: `29bc436d3e36f991`

| Field | Value |
|---|---|
| SHA-256 | `29bc436d3e36f9910bb5eca219c3e2ef3c222a28f56d6dabef8f4f034e90b072` |
| Family label | `unknown` |
| File name | `Fiyat teklifi isteği.js` |
| File type | `js` |
| First seen | `2026-11-13 05:56:30` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ab41fd305eda84bd5a6b23547daa5b2` |
| SHA-1 | `1d1f648969d618be4d62b4fd044af91ca18588ae` |
| SHA-256 | `29bc436d3e36f9910bb5eca219c3e2ef3c222a28f56d6dabef8f4f034e90b072` |
| SHA3-384 | `f1ef773ad13523628dfea0656446778bb32729aae31fdbb4e73871382129b91d7c63ec9c9d4a08af8af5abc5542d8c3c` |
| TLSH | `T1630211886EFA602A8C3373788F2F9308F7A528175544C5617D6CA2909F34B6443E5FDD` |
| SSDEEP | `192:m4B/Wsas4FjfAVsQchr6SWA9odpKUTiyUx:hB/WDFFjYVsVh7WA9oPjY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_29bc436d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29bc436d3e36f9910bb5eca219c3e2ef3c222a28f56d6dabef8f4f034e90b072"
    family = "unknown"
    file_name = "Fiyat teklifi isteği.js"
    file_type = "js"
    first_seen = "2026-11-13 05:56:30"
  condition:
    hash.sha256(0, filesize) == "29bc436d3e36f9910bb5eca219c3e2ef3c222a28f56d6dabef8f4f034e90b072"
}
```

### Sample 7: `2057f65c6a9aee75`

| Field | Value |
|---|---|
| SHA-256 | `2057f65c6a9aee75b7c86ee73b61816a805a38581dfd18d229f6b5741fd9506b` |
| Family label | `njrat` |
| File name | `25c1dca57b882d184f6a0c426ea06c62.exe` |
| File type | `exe` |
| First seen | `2026-11-13 05:45:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25c1dca57b882d184f6a0c426ea06c62` |
| SHA-1 | `ec77662d1d154d144789ac1848d04200f3acfc7f` |
| SHA-256 | `2057f65c6a9aee75b7c86ee73b61816a805a38581dfd18d229f6b5741fd9506b` |
| SHA3-384 | `96d927e326b4b4af6bc7a74c24da842228b7a8e8b2c8cdca1a5e1be05235a156ebca9a9b8e3a213b208f1adfd4e9296f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C7A2074EB7758219C2EC5AB80DA2631447B1F68BC941DB4B0CDA10DE2F23AD16251BFE` |
| SSDEEP | `384:JW6PUSlfXMv1UmTJsgrhCDmHIaOWQ+dcs//34LAZSTbS9:Y6PUqfX4Vrc6AWQuHqg9` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_007_2057f65c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2057f65c6a9aee75b7c86ee73b61816a805a38581dfd18d229f6b5741fd9506b"
    family = "njrat"
    file_name = "25c1dca57b882d184f6a0c426ea06c62.exe"
    file_type = "exe"
    first_seen = "2026-11-13 05:45:06"
  condition:
    hash.sha256(0, filesize) == "2057f65c6a9aee75b7c86ee73b61816a805a38581dfd18d229f6b5741fd9506b"
}
```

### Sample 8: `692fe65847368bbc`

| Field | Value |
|---|---|
| SHA-256 | `692fe65847368bbc2598ddfb97abeabd13f788b1708908ccc57925f7af234c9e` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 05:31:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37aaf2646d19f7d1cce5c622148ebafb` |
| SHA-1 | `077bee952e968624946913a0bc3075371854c271` |
| SHA-256 | `692fe65847368bbc2598ddfb97abeabd13f788b1708908ccc57925f7af234c9e` |
| SHA3-384 | `fa90f9660f0903726fe21e0358908d08d7b24d619135b35b7b26e5555f65065e590465cca9218565184c7ad59770ac59` |
| TLSH | `T127556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcST:SDjxB4m5n8XlaPWi+d+a4TjxQP4F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_692fe658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "692fe65847368bbc2598ddfb97abeabd13f788b1708908ccc57925f7af234c9e"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:31:05"
  condition:
    hash.sha256(0, filesize) == "692fe65847368bbc2598ddfb97abeabd13f788b1708908ccc57925f7af234c9e"
}
```

### Sample 9: `f2b96274eb91cbe1`

| Field | Value |
|---|---|
| SHA-256 | `f2b96274eb91cbe17d11173d74baaeecd4d11f15e4afe670affce8e76b61c534` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 05:25:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `325ff4ac064578707bb89af1f1a5a802` |
| SHA-1 | `a954d684578fd4ff315531b8bea2f9053f7d12bf` |
| SHA-256 | `f2b96274eb91cbe17d11173d74baaeecd4d11f15e4afe670affce8e76b61c534` |
| SHA3-384 | `2e5d940f722ad0e4dd3928a8a2f6daed675889a477162f67b132982e040fb2418642a91d710e439301e7d818bc4969a9` |
| TLSH | `T18D556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSu:SDjxB4m5n8XlaPWi+d+a4TjxQP40` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_f2b96274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b96274eb91cbe17d11173d74baaeecd4d11f15e4afe670affce8e76b61c534"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:25:04"
  condition:
    hash.sha256(0, filesize) == "f2b96274eb91cbe17d11173d74baaeecd4d11f15e4afe670affce8e76b61c534"
}
```

### Sample 10: `250111c343dc7cc0`

| Field | Value |
|---|---|
| SHA-256 | `250111c343dc7cc001a2e2c80c5e96b8b3ace9f0341f31c0272f6e325a1d483a` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 05:22:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `918acbfe1c3ee69016577a47abddd286` |
| SHA-1 | `754a5e1bf0ff47c2d9c363aba669ebe2853213e5` |
| SHA-256 | `250111c343dc7cc001a2e2c80c5e96b8b3ace9f0341f31c0272f6e325a1d483a` |
| SHA3-384 | `eef1399aae85453b82793462a7c4b15a5926b8d7938041b4cf157a48bf6800762cb83266388c4010344720ab9ec5c517` |
| TLSH | `T19A556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS+:SDjxB4m5n8XlaPWi+d+a4TjxQP4o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_250111c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "250111c343dc7cc001a2e2c80c5e96b8b3ace9f0341f31c0272f6e325a1d483a"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:22:05"
  condition:
    hash.sha256(0, filesize) == "250111c343dc7cc001a2e2c80c5e96b8b3ace9f0341f31c0272f6e325a1d483a"
}
```

### Sample 11: `c1a75ab5a565dc7e`

| Field | Value |
|---|---|
| SHA-256 | `c1a75ab5a565dc7e937656b65669ce39e417d26b68d5a5d583c1ead5463c0539` |
| Family label | `unknown` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 05:21:04` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d804b160a5fe91b25194ecbcdaf55430` |
| SHA-1 | `a0c0d4e109112e95d823d897046c90b7e8cd4412` |
| SHA-256 | `c1a75ab5a565dc7e937656b65669ce39e417d26b68d5a5d583c1ead5463c0539` |
| SHA3-384 | `1d84473e001044142f39ceda5313f1ceaafad53a8a56ae201e537c16b370f6cb4f667bcd1df931b5b00684a0004aabae` |
| TLSH | `T1BE76199BB9914942C4E83A77B8BE80C833630EB99B9716175D05FE383EBE5D90E34714` |
| TELFHASH | `t1fbd09704adeef3ecb2c240886530425e2bc830fc1000b3547fbeb2cf0e8022060e90ba` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:vZEAv5WEV2kDKWtoQXXRgRPV+aeq8MDPopdzXgxq0Dl5E9:xEAsEV2kDKWtoQHuqLvMDPo7zX+bE9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_c1a75ab5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1a75ab5a565dc7e937656b65669ce39e417d26b68d5a5d583c1ead5463c0539"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:21:04"
  condition:
    hash.sha256(0, filesize) == "c1a75ab5a565dc7e937656b65669ce39e417d26b68d5a5d583c1ead5463c0539"
}
```

### Sample 12: `65ed7ba78dbb34a2`

| Field | Value |
|---|---|
| SHA-256 | `65ed7ba78dbb34a2a2ed47650b0b79ae3ebd3bd6910e3882414b99fafa155c4b` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 05:19:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ba7374bbb1bd8716dc57d6509a06cd9` |
| SHA-1 | `6a3a737d7f72a2aee2a4d4928a2064b03449a021` |
| SHA-256 | `65ed7ba78dbb34a2a2ed47650b0b79ae3ebd3bd6910e3882414b99fafa155c4b` |
| SHA3-384 | `84051ded2980e1542524d38b92816e27ad618a0feb7f6ef39c46eb884ecd5e96a17b9e5f59761c34af1ae848c7483823` |
| TLSH | `T1A9556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSt:SDjxB4m5n8XlaPWi+d+a4TjxQP4n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_65ed7ba7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65ed7ba78dbb34a2a2ed47650b0b79ae3ebd3bd6910e3882414b99fafa155c4b"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:19:05"
  condition:
    hash.sha256(0, filesize) == "65ed7ba78dbb34a2a2ed47650b0b79ae3ebd3bd6910e3882414b99fafa155c4b"
}
```

### Sample 13: `68ea1d7b41b3c8a3`

| Field | Value |
|---|---|
| SHA-256 | `68ea1d7b41b3c8a3c6c3e3b03f8cfafbb20470981a1674e6844679d91df7ae93` |
| Family label | `unknown` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 05:17:05` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61d57f16f7fcd8c4cd467d53887abd53` |
| SHA-1 | `cdba767226bdbcd11f0ec6a22a4736be1f7bf24f` |
| SHA-256 | `68ea1d7b41b3c8a3c6c3e3b03f8cfafbb20470981a1674e6844679d91df7ae93` |
| SHA3-384 | `52388e7190e2e07af8d792916caf0b5b8a1c87194d53538f8da44f33a4684b78052350f20f77fc67c6d2804bd8405ce4` |
| TLSH | `T11B667C45BC2C7462D9CAB5B42F7622967A38BC488F81C7275614FB3CBAF27648F13161` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:RltQDhv/uj2/GnWOEK0tzdfcWOHHjipwtL4uI89O0MR4uj+5Eb:RltQdv/uHnEtzyLTMpRrUEb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_68ea1d7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68ea1d7b41b3c8a3c6c3e3b03f8cfafbb20470981a1674e6844679d91df7ae93"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:17:05"
  condition:
    hash.sha256(0, filesize) == "68ea1d7b41b3c8a3c6c3e3b03f8cfafbb20470981a1674e6844679d91df7ae93"
}
```

### Sample 14: `69769ea6ce90420a`

| Field | Value |
|---|---|
| SHA-256 | `69769ea6ce90420aa08968c589ee96f23a602bc8f9483b4a7af8dfe058cca460` |
| Family label | `WannaCry` |
| File name | `69769ea6ce90420aa08968c589ee96f23a602bc8f9483b4a7af8dfe058cca460` |
| File type | `exe` |
| First seen | `2026-11-13 05:15:14` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2464420ca60f61d7438f13633db34e86` |
| SHA-1 | `042ba6e13440028b31f32c04809ba964a57f0da1` |
| SHA-256 | `69769ea6ce90420aa08968c589ee96f23a602bc8f9483b4a7af8dfe058cca460` |
| SHA3-384 | `f23487fbaef88a80a72f027808888976ea698de16679ebe68eb69276f30481829e67c022ea9cc38fcf1e453a9fd441be` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1A6361202F6E8465DEC62477044F39F626BB57E525735460F2A803B6B1D333A86F21FA2` |
| SSDEEP | `98304:DXDqPoBhz1aRxcSUDk36SAEdhvxWa9doXoSv0GIjm8:DXDqPe1Cxcxk3ZAEUaM3sE` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_014_69769ea6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69769ea6ce90420aa08968c589ee96f23a602bc8f9483b4a7af8dfe058cca460"
    family = "WannaCry"
    file_name = "69769ea6ce90420aa08968c589ee96f23a602bc8f9483b4a7af8dfe058cca460"
    file_type = "exe"
    first_seen = "2026-11-13 05:15:14"
  condition:
    hash.sha256(0, filesize) == "69769ea6ce90420aa08968c589ee96f23a602bc8f9483b4a7af8dfe058cca460"
}
```

### Sample 15: `28ffea472ed7e230`

| Field | Value |
|---|---|
| SHA-256 | `28ffea472ed7e2300fdde6d3f1074608dbe415d5d851834e96052f65dd0ca386` |
| Family label | `njrat` |
| File name | `AF1669913E244DEEBB9496A33264741B.exe` |
| File type | `exe` |
| First seen | `2026-11-13 05:15:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af1669913e244deebb9496a33264741b` |
| SHA-1 | `f45b1b15466a574ceecaa380efc0dc4b3596ef70` |
| SHA-256 | `28ffea472ed7e2300fdde6d3f1074608dbe415d5d851834e96052f65dd0ca386` |
| SHA3-384 | `129ce78038e2b50d3f3ed7b22c6497965c3d4ff8375e462177ac70d095ea2ac77ca6838d88071b3f1dbd3c53d215128a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16CB2E649B3A54715D3EE4A7908B3231447B1F2D7E980CB9B0DD6008E1E17BD4A962FBE` |
| SSDEEP | `384:uW6XoUSlajXMrhRPx//8Bh6ZmHQ1aOWQ+dcs//34LAZSTErK2L2bOL28mzqo:f64UqQX2htaUkCWQuHqOr7KbOL28mOo` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_015_28ffea47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28ffea472ed7e2300fdde6d3f1074608dbe415d5d851834e96052f65dd0ca386"
    family = "njrat"
    file_name = "AF1669913E244DEEBB9496A33264741B.exe"
    file_type = "exe"
    first_seen = "2026-11-13 05:15:06"
  condition:
    hash.sha256(0, filesize) == "28ffea472ed7e2300fdde6d3f1074608dbe415d5d851834e96052f65dd0ca386"
}
```

### Sample 16: `8b806570dd2eb0c8`

| Field | Value |
|---|---|
| SHA-256 | `8b806570dd2eb0c8d71497fce40e4bdf5b85039a788cfdd9e1ae95a5b9bd788c` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 05:13:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `676243b026b8f3fbec50052b076a82ac` |
| SHA-1 | `493bd2f32102092b5acc7f28dcbe7f2d8b1eb94e` |
| SHA-256 | `8b806570dd2eb0c8d71497fce40e4bdf5b85039a788cfdd9e1ae95a5b9bd788c` |
| SHA3-384 | `47d36c3965cb3bbbb9b792be54ef59bd7ba0695f93916188db5aff126d69b3b813c182bb3c59a337f190aeda15b05059` |
| TLSH | `T15D556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSc:SDjxB4m5n8XlaPWi+d+a4TjxQP4O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_8b806570
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b806570dd2eb0c8d71497fce40e4bdf5b85039a788cfdd9e1ae95a5b9bd788c"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:13:05"
  condition:
    hash.sha256(0, filesize) == "8b806570dd2eb0c8d71497fce40e4bdf5b85039a788cfdd9e1ae95a5b9bd788c"
}
```

### Sample 17: `a931b9e97f99c559`

| Field | Value |
|---|---|
| SHA-256 | `a931b9e97f99c5597dcf862ee4015ff069c68c4e3981c965803e0af89c443628` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 05:11:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `806a38d2367ef4b491b935d92c96ff96` |
| SHA-1 | `aa6f505ee00b770ae9c53405eebe56e80b2d5492` |
| SHA-256 | `a931b9e97f99c5597dcf862ee4015ff069c68c4e3981c965803e0af89c443628` |
| SHA3-384 | `d25c428030c4cc7361c2936d82e7a84f644db88402b3cdcd32d3ad6f80dedcfd429bdec5d5c977931119fef39a9020db` |
| TLSH | `T194556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSx:SDjxB4m5n8XlaPWi+d+a4TjxQP4r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_a931b9e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a931b9e97f99c5597dcf862ee4015ff069c68c4e3981c965803e0af89c443628"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:11:05"
  condition:
    hash.sha256(0, filesize) == "a931b9e97f99c5597dcf862ee4015ff069c68c4e3981c965803e0af89c443628"
}
```

### Sample 18: `266d96922afb1c69`

| Field | Value |
|---|---|
| SHA-256 | `266d96922afb1c69035a5045b90d664f4afcbbac4233b228d061b14ab28ab636` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-13 05:06:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba77dc3aa9dd83cc77c3d3c457923d72` |
| SHA-1 | `73428214363b8dc1b9f5fe775c1f0b3108b0f1f1` |
| SHA-256 | `266d96922afb1c69035a5045b90d664f4afcbbac4233b228d061b14ab28ab636` |
| SHA3-384 | `0749afbb1c0f52c21a77f648ecfff3bd16359ab7df75566453ddf80653ea3ca7ac9d484451bcf075a26629aedcbb080e` |
| TLSH | `T1D0945B4B67508FA5F364DA7007F38B67AAB9169316E3C581D27DD9103E9034C682FFA8` |
| TELFHASH | `t174f0da2c183823f1d2c58d6e67edff70e85181eb5d761e3bc954e9a9a720e829d00d6c` |
| SSDEEP | `6144:/d8MRspUIcQYFLHBzn7vfvq97t7WeAFlYT/+HQ5PYIAG9gBFjnG78vmt:llImhvXvet7zAFaT28j9arGovy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_266d9692
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "266d96922afb1c69035a5045b90d664f4afcbbac4233b228d061b14ab28ab636"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-13 05:06:19"
  condition:
    hash.sha256(0, filesize) == "266d96922afb1c69035a5045b90d664f4afcbbac4233b228d061b14ab28ab636"
}
```

### Sample 19: `268924660854ff06`

| Field | Value |
|---|---|
| SHA-256 | `268924660854ff06f59245f765634c5ba991b8e035811e1e974a6655a75727e6` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-13 05:06:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b60f55a5dd63e9e69bf640f0ade073d` |
| SHA-1 | `a9cb93762c30bb8961ca4b023048b5df6121be77` |
| SHA-256 | `268924660854ff06f59245f765634c5ba991b8e035811e1e974a6655a75727e6` |
| SHA3-384 | `995740a4877505e9821f1b935dd0221d7bb20f553eb2cac26083831d51b825639d58f51ea6dc20b8441945072dc4465b` |
| TLSH | `T157F322BC5A135EF8FD6896B805690BD626B80CB0C006DCF25936475ACE1BB0D20FBDD6` |
| SSDEEP | `3072:f/bNeK+UUtLlJQhSaA3BqYPQ+L7AbAfAJDYETGOKEnKrjJqzVM:n0K+N5JQhSaARqY4UeDrFnUd8M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_26892466
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "268924660854ff06f59245f765634c5ba991b8e035811e1e974a6655a75727e6"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-13 05:06:05"
  condition:
    hash.sha256(0, filesize) == "268924660854ff06f59245f765634c5ba991b8e035811e1e974a6655a75727e6"
}
```

### Sample 20: `ac88d3f113aa54d1`

| Field | Value |
|---|---|
| SHA-256 | `ac88d3f113aa54d11f34703d0ae48a3a44a3cc061f8477055419a0aac0146854` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 04:54:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26fd729783b15edfcf966db17cfe4170` |
| SHA-1 | `27995ddb8465badcb3fe70f2f5c3a0e665942442` |
| SHA-256 | `ac88d3f113aa54d11f34703d0ae48a3a44a3cc061f8477055419a0aac0146854` |
| SHA3-384 | `b0aa984b4f19fbddefeda957edd70deb0bb152eed829d502ab6b30c90267e4e8357ef6023a9ed7aa55047f4f8c1bc74f` |
| TLSH | `T145556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSN:SDjxB4m5n8XlaPWi+d+a4TjxQP4j` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_ac88d3f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac88d3f113aa54d11f34703d0ae48a3a44a3cc061f8477055419a0aac0146854"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 04:54:05"
  condition:
    hash.sha256(0, filesize) == "ac88d3f113aa54d11f34703d0ae48a3a44a3cc061f8477055419a0aac0146854"
}
```

### Sample 21: `72cf74a14f597896`

| Field | Value |
|---|---|
| SHA-256 | `72cf74a14f59789640f164bab0ab76992e194b0c962829b8bc52a5fb1212ce32` |
| Family label | `unknown` |
| File name | `72cf74a14f597896.ps1` |
| File type | `ps1` |
| First seen | `2026-11-13 04:51:39` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c50d6f6a41287a34f884e394de280c7d` |
| SHA-1 | `5399651408f73907dd57a78c20b2f61d0fdf3e38` |
| SHA-256 | `72cf74a14f59789640f164bab0ab76992e194b0c962829b8bc52a5fb1212ce32` |
| SHA3-384 | `a59337c89ae064af0ad6eb52c1fd560ed3c0c20b838d65e498c6002ed4467f1c571d9fbf011df09108d749e81e7ab949` |
| TLSH | `T1F3E46D34BA462EFF5BB820C248D5C11C563C22B5C9686CF56ACF4CA2391D77627B79B0` |
| SSDEEP | `12288:CgQ5a5T0hMYJqg6jPq5smXqz8Qqv5vvomYoPOfEtIDY2mLzcuuH:CoqKyfvvocWfEtIDkLzw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_72cf74a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72cf74a14f59789640f164bab0ab76992e194b0c962829b8bc52a5fb1212ce32"
    family = "unknown"
    file_name = "72cf74a14f597896.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 04:51:39"
  condition:
    hash.sha256(0, filesize) == "72cf74a14f59789640f164bab0ab76992e194b0c962829b8bc52a5fb1212ce32"
}
```

### Sample 22: `b2550d2c1b7b9a8d`

| Field | Value |
|---|---|
| SHA-256 | `b2550d2c1b7b9a8d58e2b5a0171a175809e9deedde12fe4a58fc951861d55d84` |
| Family label | `njrat` |
| File name | `8AFC276D54258CDE26AA5259A4D51729.exe` |
| File type | `exe` |
| First seen | `2026-11-13 04:45:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8afc276d54258cde26aa5259a4d51729` |
| SHA-1 | `9bbcc904ed42b0baa4e975828daa61a2a2e93c8d` |
| SHA-256 | `b2550d2c1b7b9a8d58e2b5a0171a175809e9deedde12fe4a58fc951861d55d84` |
| SHA3-384 | `2c0ab7760d11a8419b24d6f77623108eb1d279e3875cc1c3a844e15f0379d2242df0901caaa8ae644d2e89812b960a8c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A8A2094E77688219C3BE1A780DB3632487B1F68BC551DF4B1CDA10DA6F23AD05642AFD` |
| SSDEEP | `384:hW6gAUSl+XM6mswzmqBZYKhw4mH+aOWQ+dcs//34LAZSTjXPy:w6ZUq+X/mswzmqriLSWQuHq9Py` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_022_b2550d2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2550d2c1b7b9a8d58e2b5a0171a175809e9deedde12fe4a58fc951861d55d84"
    family = "njrat"
    file_name = "8AFC276D54258CDE26AA5259A4D51729.exe"
    file_type = "exe"
    first_seen = "2026-11-13 04:45:06"
  condition:
    hash.sha256(0, filesize) == "b2550d2c1b7b9a8d58e2b5a0171a175809e9deedde12fe4a58fc951861d55d84"
}
```

### Sample 23: `afd4e4e8c20c1392`

| Field | Value |
|---|---|
| SHA-256 | `afd4e4e8c20c13920b718aa6c417e005c5bf3648f1462d18faa29194b9dffa40` |
| Family label | `GuLoader` |
| File name | `SHIPMENT DELIVERY- Booking AYN1343237.vbs` |
| File type | `vbs` |
| First seen | `2026-11-13 04:04:19` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6b618e822635e505e610bd84c43b356` |
| SHA-1 | `20668c7ded7dd287e078632fdb4fadc1b8f37bbc` |
| SHA-256 | `afd4e4e8c20c13920b718aa6c417e005c5bf3648f1462d18faa29194b9dffa40` |
| SHA3-384 | `3e4e2cbd88b93414bfcf1ec531376aa70d5023dc9ce538c20fedfd527389058d986077599270101db1a0cfcd8b7a6bca` |
| TLSH | `T14FD31AEBF9B42F3989761657E8C02550839B6D0D813A60A07DB78F89102DCE8DF6DD87` |
| SSDEEP | `1536:2zbaINKEp+1mFPOGbLKIfs1NvRwQM4knyf10rhsEGUynLGbd6RGHSgIIp4gOuie:2vaK42HLhk11RGnywOEGPLePGgO3e` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_023_afd4e4e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afd4e4e8c20c13920b718aa6c417e005c5bf3648f1462d18faa29194b9dffa40"
    family = "GuLoader"
    file_name = "SHIPMENT DELIVERY- Booking AYN1343237.vbs"
    file_type = "vbs"
    first_seen = "2026-11-13 04:04:19"
  condition:
    hash.sha256(0, filesize) == "afd4e4e8c20c13920b718aa6c417e005c5bf3648f1462d18faa29194b9dffa40"
}
```

### Sample 24: `7232d7791ac68310`

| Field | Value |
|---|---|
| SHA-256 | `7232d7791ac683102556cd203e4613dbbc606a32a7bd6ed6808e171afe81c96c` |
| Family label | `RustyStealer` |
| File name | `Release.exe.exe` |
| File type | `exe` |
| First seen | `2026-11-13 03:38:55` |
| Reporter | `josie` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e466d4a4a6a9fcfa3e53d485ec09873` |
| SHA-1 | `f96e4518fc730672702d5e2dccd1b33823c305e5` |
| SHA-256 | `7232d7791ac683102556cd203e4613dbbc606a32a7bd6ed6808e171afe81c96c` |
| SHA3-384 | `042232c4ae8e38517403196a40958fe1f5a52f7f93cf9e306f353953608352cd5cc5c9f04fe79de8b84855975fb70978` |
| IMPHASH | `2c983f29837c6e472d242fd4e45c5d82` |
| TLSH | `T18FF5224761315CABE452C4708636D573AA2BFC8C6B32B3EF069571363E369D1AB39B00` |
| SSDEEP | `12288:MSe/cHCn3BYaa6e97OzFy9nl6udUveiIt8dpVLhE1/q2ZuKKU35JMUFh31ZS7VL1:BmcHy3x` |
| ICON-DHASH | `c433d4d4d4d433c4` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_024_7232d779
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7232d7791ac683102556cd203e4613dbbc606a32a7bd6ed6808e171afe81c96c"
    family = "RustyStealer"
    file_name = "Release.exe.exe"
    file_type = "exe"
    first_seen = "2026-11-13 03:38:55"
  condition:
    hash.sha256(0, filesize) == "7232d7791ac683102556cd203e4613dbbc606a32a7bd6ed6808e171afe81c96c"
}
```

### Sample 25: `ab7a7a88a90d3c26`

| Field | Value |
|---|---|
| SHA-256 | `ab7a7a88a90d3c26df5be69a41d7bb9251defae4a057cf2d23bb9dbc22ec4c62` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-13 03:35:26` |
| Reporter | `RogueBoulder3285` |
| Tags | `cowrie, elf, Gafgyt, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `708604e00ac1756da44737ede661a3c3` |
| SHA-1 | `424586fd5f0f5afd3f7ebaf8ea9180da236fc202` |
| SHA-256 | `ab7a7a88a90d3c26df5be69a41d7bb9251defae4a057cf2d23bb9dbc22ec4c62` |
| SHA3-384 | `eb6b0508904134433e0ccc6a4170a0a245bb6f51d7c55ba0dc3b25477003ce1feff3bef878a3c451957f03c2509e7dc4` |
| TLSH | `T1A3043BA5FB40FB6FC00F7234A573D72157D01D722E901ABA3254DA6C9E341AA6E1F6E0` |
| SSDEEP | `3072:IvYbPYLTqhI1VIHn4+N/JA/KBtI3L3kOGS2NYsn4K/iAhcVJmoaYmhNTMjz5jjH8:LsT+QVA4+hOGV4K/i6cVJmoaT8jc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_ab7a7a88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab7a7a88a90d3c26df5be69a41d7bb9251defae4a057cf2d23bb9dbc22ec4c62"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-13 03:35:26"
  condition:
    hash.sha256(0, filesize) == "ab7a7a88a90d3c26df5be69a41d7bb9251defae4a057cf2d23bb9dbc22ec4c62"
}
```

### Sample 26: `2ca14ca257abab46`

| Field | Value |
|---|---|
| SHA-256 | `2ca14ca257abab463641f49b757c8fdf322d32930d3acecfa2e3fb681b19ec3c` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-11-13 03:35:23` |
| Reporter | `RogueBoulder3285` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d531b2304bbe7c4fb5c51046bd0bb26` |
| SHA-1 | `cd3eade38a7536dd70aa0be96855b0c90f2a8910` |
| SHA-256 | `2ca14ca257abab463641f49b757c8fdf322d32930d3acecfa2e3fb681b19ec3c` |
| SHA3-384 | `a4baccf4da0dfc0d8feed856bd4681adfdd4b338582f42613d4e36b850386f25a39568365931be62fb749cef7d69b90b` |
| TLSH | `T1AEE33A96B821DA11C994ACBFFE1E84CC33034B9ED5DF33298C1556607A8F6D54E7AB20` |
| SSDEEP | `3072:yvWjR5rTSjTohaB/p+tGX1QfNSmobVF6dT7:hj4ocB/pvX6fNRSVF6dT7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_2ca14ca2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ca14ca257abab463641f49b757c8fdf322d32930d3acecfa2e3fb681b19ec3c"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-11-13 03:35:23"
  condition:
    hash.sha256(0, filesize) == "2ca14ca257abab463641f49b757c8fdf322d32930d3acecfa2e3fb681b19ec3c"
}
```

### Sample 27: `2bf1aaa147e4d77e`

| Field | Value |
|---|---|
| SHA-256 | `2bf1aaa147e4d77e8e6d2268b011e7557d14f461d9e92c8c5700fe6021633fd1` |
| Family label | `unknown` |
| File name | `2bf1aaa147e4d77e.ps1` |
| File type | `ps1` |
| First seen | `2026-11-13 03:26:44` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5005bcdab6971a7a03acc5204aef0ecd` |
| SHA-1 | `1312bbad2f53b66e8616f4f00a06989e843bd284` |
| SHA-256 | `2bf1aaa147e4d77e8e6d2268b011e7557d14f461d9e92c8c5700fe6021633fd1` |
| SHA3-384 | `37d812d5147ffc4ecf5b68fb81c56b6a4d5a9db9ea5c8944e24c23a07c3bc5199336fbb914bc5234e1c03d92d66ae63f` |
| TLSH | `T1E651979289940370DE552397348F4BC5BAD7C736528E07C0F2EEF604F2A151D43DB1AA` |
| SSDEEP | `48:+Vdodye1EEnR4Ztyx+PG7GmthVkrPVaDfwPi2rTnu7bn3dDSvqs:oEn+Ztyx+PG7GmthVv+rTKD8p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_2bf1aaa1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bf1aaa147e4d77e8e6d2268b011e7557d14f461d9e92c8c5700fe6021633fd1"
    family = "unknown"
    file_name = "2bf1aaa147e4d77e.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 03:26:44"
  condition:
    hash.sha256(0, filesize) == "2bf1aaa147e4d77e8e6d2268b011e7557d14f461d9e92c8c5700fe6021633fd1"
}
```

### Sample 28: `851653f6c0196701`

| Field | Value |
|---|---|
| SHA-256 | `851653f6c0196701e61a9a684cbb0bb427f169e0d16e7d80f5ccc7a8feeaca1e` |
| Family label | `unknown` |
| File name | `ZolacanCraft.zip` |
| File type | `zip` |
| First seen | `2026-11-13 02:38:05` |
| Reporter | `milliesolem` |
| Tags | `kurdishmyth, minecraft, MythJs, MythPrivate, RAT, stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62b307da9779fbdc1a7ba43d2ea46525` |
| SHA-1 | `7589831b6192f0bfc5cb48bd8bca031d243077ac` |
| SHA-256 | `851653f6c0196701e61a9a684cbb0bb427f169e0d16e7d80f5ccc7a8feeaca1e` |
| SHA3-384 | `b4dd204a4910a630e184a4f93ab787ca8ccd5a071cb6044f303501523f0e4c0a7092fb9521d200c29c0719403a428c81` |
| TLSH | `T1A61733D0B488F4BB68BD4B7A177A9CE316DD9AFC90645EEAB8E7553765C00C018FC260` |
| SSDEEP | `393216:aLOpuXnvQSOEGgn1XZj38u63z2Z89mIZTL55O1Hr848jvbZlig:aLtvcq38uCSIZew4qNz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_851653f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "851653f6c0196701e61a9a684cbb0bb427f169e0d16e7d80f5ccc7a8feeaca1e"
    family = "unknown"
    file_name = "ZolacanCraft.zip"
    file_type = "zip"
    first_seen = "2026-11-13 02:38:05"
  condition:
    hash.sha256(0, filesize) == "851653f6c0196701e61a9a684cbb0bb427f169e0d16e7d80f5ccc7a8feeaca1e"
}
```

### Sample 29: `2fb07d96121058a0`

| Field | Value |
|---|---|
| SHA-256 | `2fb07d96121058a0a1d7d28a950e95246ed82f9d19cd0b112ae43c401aace8b0` |
| Family label | `RustyStealer` |
| File name | `2fb07d96121058a0.bin` |
| File type | `exe` |
| First seen | `2026-11-13 02:26:17` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37fc80c2735e68045fca2491784d92ac` |
| SHA-1 | `eb63d23ab0b1415e7a625edf8513d00d6323112d` |
| SHA-256 | `2fb07d96121058a0a1d7d28a950e95246ed82f9d19cd0b112ae43c401aace8b0` |
| SHA3-384 | `f682f3b4b8b6cc1d8fc82625b03dcfa7af6fbead7eb06a28dcb364df802678695a9d5de33c6f260e97119dfeb96867e6` |
| IMPHASH | `603a12af845feb44eeaee4af0f3efa0b` |
| TLSH | `T1D6957C43F69580FCC49EC078C347A632EA22BC8D092576AB27D09B653E76F905F4DB19` |
| SSDEEP | `49152:v/d2b3eMr59FfL4VD9tDo92napO5nIU6isO:v/dCV5E3nY3+sO` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_029_2fb07d96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fb07d96121058a0a1d7d28a950e95246ed82f9d19cd0b112ae43c401aace8b0"
    family = "RustyStealer"
    file_name = "2fb07d96121058a0.bin"
    file_type = "exe"
    first_seen = "2026-11-13 02:26:17"
  condition:
    hash.sha256(0, filesize) == "2fb07d96121058a0a1d7d28a950e95246ed82f9d19cd0b112ae43c401aace8b0"
}
```

### Sample 30: `1eaba93e79031f44`

| Field | Value |
|---|---|
| SHA-256 | `1eaba93e79031f4402debb37e18cac5959a579e20d281566ce4df124c608b2fc` |
| Family label | `Mirai` |
| File name | `1eaba93e79031f44.bin` |
| File type | `elf` |
| First seen | `2026-11-13 02:26:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai, tsunami` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98b1c7e30f8d66eb97cc3ba7b57cff96` |
| SHA-1 | `a976ef3ab01ac3298efe79fc534b48ccf83c5a10` |
| SHA-256 | `1eaba93e79031f4402debb37e18cac5959a579e20d281566ce4df124c608b2fc` |
| SHA3-384 | `d93a20e3656f8daa686ecf5749f9b2ea8f7104a8a3bd86e2f2592c284d6f2c3fd64ee589d6cf19859fbf55f3529c52f6` |
| TLSH | `T188F35D86EA408A13C4C61777FAAF014E3322A755E3DB73068D185FB43F87A5E4E67606` |
| TELFHASH | `t10721dfb69b21573a5a61cc5489ee53b2162c97166389ff33ef34848c20190dee63bc5f` |
| SSDEEP | `3072:x4emW1uRb+I6E46qH/eUFiYq5wwCjSrwGy/tBF1EYfX6OxM/9a+XcAr:DluRb+I6WqH2V0SrwGy/HFLfKQM/9aAH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_1eaba93e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eaba93e79031f4402debb37e18cac5959a579e20d281566ce4df124c608b2fc"
    family = "Mirai"
    file_name = "1eaba93e79031f44.bin"
    file_type = "elf"
    first_seen = "2026-11-13 02:26:07"
  condition:
    hash.sha256(0, filesize) == "1eaba93e79031f4402debb37e18cac5959a579e20d281566ce4df124c608b2fc"
}
```

### Sample 31: `1677cd1d51eac543`

| Field | Value |
|---|---|
| SHA-256 | `1677cd1d51eac543fe942e20a4a39eab1ac10b985dacad5f5246b6a3bea4b8e4` |
| Family label | `unknown` |
| File name | `1677cd1d51eac543.ps1` |
| File type | `ps1` |
| First seen | `2026-11-13 02:01:39` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08f0bbfa28aef2ea7903fd45795b3167` |
| SHA-1 | `8d8b30a5759c422b5b218bfdd79cc4f7ab0e05bf` |
| SHA-256 | `1677cd1d51eac543fe942e20a4a39eab1ac10b985dacad5f5246b6a3bea4b8e4` |
| SHA3-384 | `20a926a945851cee595fd1dc172fb1b1c7ee2abface27a00ced9afd554943240fcca65006dbc86cf4282f13b4b7ef371` |
| TLSH | `T1798133405D189CA1C56B6A93BC322F53D72911EECACF93890289FB46257BF39DA5CC80` |
| SSDEEP | `96:nOwSY9pICCtOwnhAczqM0qsGXdY8WsPCKF2q9tnHbmCOHip:OMJEucz9sGm8WslF2qtnHyCOHip` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_1677cd1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1677cd1d51eac543fe942e20a4a39eab1ac10b985dacad5f5246b6a3bea4b8e4"
    family = "unknown"
    file_name = "1677cd1d51eac543.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 02:01:39"
  condition:
    hash.sha256(0, filesize) == "1677cd1d51eac543fe942e20a4a39eab1ac10b985dacad5f5246b6a3bea4b8e4"
}
```

### Sample 32: `afcb187858135123`

| Field | Value |
|---|---|
| SHA-256 | `afcb187858135123cc4bf27c0d1923ee08716c0a3f7ee3c3f94a9b6c75dc1dfa` |
| Family label | `unknown` |
| File name | `afcb187858135123.ps1` |
| File type | `ps1` |
| First seen | `2026-11-13 01:57:01` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1056f5bc954f859da72a40c8bf9837b` |
| SHA-1 | `2e84dd65883fbec9f7de3c79ac369ee4dce1db58` |
| SHA-256 | `afcb187858135123cc4bf27c0d1923ee08716c0a3f7ee3c3f94a9b6c75dc1dfa` |
| SHA3-384 | `d64c2285b92dbbde63202f73225e203bf9d4ae871fd3fa3e79e4c9bd893205837304beb0512c3c41f06b10133654a38c` |
| TLSH | `T10B814418AE48B4D14B975913BCE53F67A23216AA4ECE73110395F2E8367AB3E0F05C85` |
| SSDEEP | `96:+eHMurTGGC3BHJp3Y21DpQzrV1A6Br8PETxmYT1IU46:+eHMrBH/x5pOsEtuUh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_afcb1878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afcb187858135123cc4bf27c0d1923ee08716c0a3f7ee3c3f94a9b6c75dc1dfa"
    family = "unknown"
    file_name = "afcb187858135123.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 01:57:01"
  condition:
    hash.sha256(0, filesize) == "afcb187858135123cc4bf27c0d1923ee08716c0a3f7ee3c3f94a9b6c75dc1dfa"
}
```

### Sample 33: `d45361634083c162`

| Field | Value |
|---|---|
| SHA-256 | `d45361634083c162b50eca92a50e0410c538e31f51508b74f047415ab8ebb9e1` |
| Family label | `unknown` |
| File name | `50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b.exe` |
| File type | `exe` |
| First seen | `2026-11-13 01:53:13` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4df68e033eec7ee2ccf8474607ae1f7c` |
| SHA-1 | `dba026b327c383284a01e36c955d7c97d4aec6e3` |
| SHA-256 | `d45361634083c162b50eca92a50e0410c538e31f51508b74f047415ab8ebb9e1` |
| SHA3-384 | `9a9fa8dc46b800a84d4b1a0894a9151eb49d1b97b914851ba49976498db31237d09b052e749d444c6c44f123e85b9b88` |
| TLSH | `T181155C14779341D9E432593AD6CEAB17B1B2BC195AE4DF7B0B448FC26AD3261233B312` |
| SSDEEP | `12288:OY17Gl+SRbMFPCwwYktSwav7m6+NBjh58Qii1CItIcWgpko+1YAgo4owRYin96UD:O0S7wqwwYKSwavSJN9h5zJkjNmjQ5yJ1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_d4536163
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d45361634083c162b50eca92a50e0410c538e31f51508b74f047415ab8ebb9e1"
    family = "unknown"
    file_name = "50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b.exe"
    file_type = "exe"
    first_seen = "2026-11-13 01:53:13"
  condition:
    hash.sha256(0, filesize) == "d45361634083c162b50eca92a50e0410c538e31f51508b74f047415ab8ebb9e1"
}
```

### Sample 34: `50774628062fd31b`

| Field | Value |
|---|---|
| SHA-256 | `50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b` |
| Family label | `unknown` |
| File name | `50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b.exe` |
| File type | `exe` |
| First seen | `2026-11-13 01:52:29` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb7c579ab778ffd1751dcd9b5f036589` |
| SHA-1 | `aa3e9d882ac75c22f1843b6e7b2706b1b3fc9829` |
| SHA-256 | `50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b` |
| SHA3-384 | `d317dbeed4f9e7dfb58b53f474ac5c637af5f43ab6ccad768ce2dde645ac2947b847ab4c858bf3d9aba079b67f59aa48` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1476423A73BA19F6ACEAEEA74D2F5B470BD920F4FC3AB021867CC09961C3D4544C65907` |
| SSDEEP | `6144:tWGD1VFXWo+A+9bjGDkt4w7CGV/tEpdgkqai/6o/yHbsABG03ahlDzzH:R1VFmHAQu+4wB4pdgUiSo3AB+vT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_50774628
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b"
    family = "unknown"
    file_name = "50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b.exe"
    file_type = "exe"
    first_seen = "2026-11-13 01:52:29"
  condition:
    hash.sha256(0, filesize) == "50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b"
}
```

### Sample 35: `9c9baabdd7b08ca2`

| Field | Value |
|---|---|
| SHA-256 | `9c9baabdd7b08ca2f9e76be7987780dcb25d0ae45dc2d5f1962fd5ca8e42c129` |
| Family label | `unknown` |
| File name | `9c9baabdd7b08ca2.msi` |
| File type | `msi` |
| First seen | `2026-11-13 01:40:11` |
| Reporter | `Tuxxin` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `579e45fa55c874b4a45e35d768e520d8` |
| SHA-1 | `8928e83e5211d5c7ad779e702c8f2466ac3752bb` |
| SHA-256 | `9c9baabdd7b08ca2f9e76be7987780dcb25d0ae45dc2d5f1962fd5ca8e42c129` |
| SHA3-384 | `a3961da07fa783f1b1394031c11af22b79ff72d1c3de09bb9dc4644a61be10c3ac73a2c0cacd1a756b7559d8ccbd38f4` |
| TLSH | `T121183333324ECF76C6BF5830447A5A9F01657D630B3190E7A39CAC3AA4B64C29675E93` |
| SSDEEP | `1572864:HwyX3aBYOLbD6TY/dRvhrWorchGgsU27ehxIlOX3k/lVvMRhuZSKc4Do0nejkXsx:nqYOLPd7fgs+hR3k/Hn1s0ejkXsT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_9c9baabd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c9baabdd7b08ca2f9e76be7987780dcb25d0ae45dc2d5f1962fd5ca8e42c129"
    family = "unknown"
    file_name = "9c9baabdd7b08ca2.msi"
    file_type = "msi"
    first_seen = "2026-11-13 01:40:11"
  condition:
    hash.sha256(0, filesize) == "9c9baabdd7b08ca2f9e76be7987780dcb25d0ae45dc2d5f1962fd5ca8e42c129"
}
```

### Sample 36: `944bfe82b949fcb0`

| Field | Value |
|---|---|
| SHA-256 | `944bfe82b949fcb067d4aa0463af94a13cfd7c97dfdd8ae8d9ff5ebcebaa22f2` |
| Family label | `unknown` |
| File name | `944bfe82b949fcb0.ps1` |
| File type | `ps1` |
| First seen | `2026-11-13 01:36:38` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f208c8afb9b34f05ea38c406659bb6f0` |
| SHA-1 | `37fce4d43c2a5a6989376aec0f464e2ea048d984` |
| SHA-256 | `944bfe82b949fcb067d4aa0463af94a13cfd7c97dfdd8ae8d9ff5ebcebaa22f2` |
| SHA3-384 | `6a58ec210dfe8c66cb5ce44c2697fea6829dfad8f379c9129742dcf8f78125ac82c5dacdb6247a5b8e366579830f9f32` |
| TLSH | `T11B813590FE48E4D1896759F7FC6A3E56D23812B1DCCA26C80398B2D927B7B359718CC0` |
| SSDEEP | `96:Pm2c+RZ2rDum2GGErLqalNJ7DK+B2JG+E7Reakj0FstAhF6B+pzmUgn:Pc+R0rDuDErxf7DK+84R9FFob2zmt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_944bfe82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "944bfe82b949fcb067d4aa0463af94a13cfd7c97dfdd8ae8d9ff5ebcebaa22f2"
    family = "unknown"
    file_name = "944bfe82b949fcb0.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 01:36:38"
  condition:
    hash.sha256(0, filesize) == "944bfe82b949fcb067d4aa0463af94a13cfd7c97dfdd8ae8d9ff5ebcebaa22f2"
}
```

### Sample 37: `f61e9548ea915f7d`

| Field | Value |
|---|---|
| SHA-256 | `f61e9548ea915f7d052b1b929bb5ddf597a3fd93ee208b14b0e03553b98f7583` |
| Family label | `unknown` |
| File name | `f61e9548ea915f7d052b1b929bb5ddf597a3fd93ee208b14b0e03553b98f7583.bin` |
| File type | `sh` |
| First seen | `2026-11-13 01:33:25` |
| Reporter | `Tuxxin` |
| Tags | `script, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2af8f3fa2d09843e46becc78f966484` |
| SHA-1 | `53239a8ae1dd6b778ca2a51798d05a8a9093db1a` |
| SHA-256 | `f61e9548ea915f7d052b1b929bb5ddf597a3fd93ee208b14b0e03553b98f7583` |
| SHA3-384 | `92eb5cf073e95c521463e1790b60b5b10dfbd9b3e7ad1fbbc461acc92fcc57fdfc61df5a43a5c77e7ba8ef974f18ffc4` |
| TLSH | `T1FCD1BDAFB22AD83A399FD83637A099CD8503B4C33C11DD4EB55CAC50AF5B941B925734` |
| SSDEEP | `96:5Fin+uKBiqTamLrDCkxwqyWuIRJxQaPpHnUgGIGBKuedMD1ollG2ns1/7vpyqGUe:rin+uOHB3BWoMDCn0wAe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_f61e9548
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f61e9548ea915f7d052b1b929bb5ddf597a3fd93ee208b14b0e03553b98f7583"
    family = "unknown"
    file_name = "f61e9548ea915f7d052b1b929bb5ddf597a3fd93ee208b14b0e03553b98f7583.bin"
    file_type = "sh"
    first_seen = "2026-11-13 01:33:25"
  condition:
    hash.sha256(0, filesize) == "f61e9548ea915f7d052b1b929bb5ddf597a3fd93ee208b14b0e03553b98f7583"
}
```

### Sample 38: `299ae99b84de74b7`

| Field | Value |
|---|---|
| SHA-256 | `299ae99b84de74b70699d7bb6b946b5f550153288c3fcb854459008ef926b8df` |
| Family label | `unknown` |
| File name | `299ae99b84de74b7.apk` |
| File type | `apk` |
| First seen | `2026-11-13 01:30:08` |
| Reporter | `Tuxxin` |
| Tags | `AndroiddropperfakePlaylisting, apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f6eca86760b4ab7a9b44e4762f51858` |
| SHA-1 | `15f83454db603eb00cbedbf60bab92213dbc20de` |
| SHA-256 | `299ae99b84de74b70699d7bb6b946b5f550153288c3fcb854459008ef926b8df` |
| SHA3-384 | `d9602d87010b66e9816167f75d15cbc0039c608b65bad27f3bfc777b2341e14c2f9ef8e1b5d6d1619a83370daa8dd0c0` |
| TLSH | `T10447337CE7155A2AD47AB6B0AEF02851FE1B153C5AD6D71327087C219ED687E3A2F003` |
| SSDEEP | `393216:da35wVLwC1tztoeoGDPa+Q/4wLM2/08DcV1fBJeBULUpiIMjx1sHOZmE6Sf7Rflr:DuAdTNza3/4QtjqfXMUaiPxO0VttfV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_299ae99b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "299ae99b84de74b70699d7bb6b946b5f550153288c3fcb854459008ef926b8df"
    family = "unknown"
    file_name = "299ae99b84de74b7.apk"
    file_type = "apk"
    first_seen = "2026-11-13 01:30:08"
  condition:
    hash.sha256(0, filesize) == "299ae99b84de74b70699d7bb6b946b5f550153288c3fcb854459008ef926b8df"
}
```

### Sample 39: `4fede1be1261e93e`

| Field | Value |
|---|---|
| SHA-256 | `4fede1be1261e93eac85fbf92813548279ff1ba58bf831b22e9c4e088d292f5c` |
| Family label | `GuLoader` |
| File name | `Tabelsatsen.vbs` |
| File type | `vbs` |
| First seen | `2026-11-13 01:25:07` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b49ef8b296a4b0008c5fe07debb6583c` |
| SHA-1 | `97033edd48938b188f95b041e45c307c0caecdb7` |
| SHA-256 | `4fede1be1261e93eac85fbf92813548279ff1ba58bf831b22e9c4e088d292f5c` |
| SHA3-384 | `398cc4c3304dbf1408e4cf3daf15d237be5ad4442d4b50aab91fe36d3229313875989c13c1a2ad14988302a40ffd90b2` |
| TLSH | `T11FC37D71BD7403158D4A17DFABAC2D9D85FCC187033240E5FDA91369A00EDAEA3F961A` |
| SSDEEP | `1536:B02l/00ECJN4Bzupm1Mv1bOcypmepuDsLmbAcOzfp4e68pzcLr44gU0xq:Bp/Xi2mK1ycFhshcOz7D4gU6q` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_039_4fede1be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fede1be1261e93eac85fbf92813548279ff1ba58bf831b22e9c4e088d292f5c"
    family = "GuLoader"
    file_name = "Tabelsatsen.vbs"
    file_type = "vbs"
    first_seen = "2026-11-13 01:25:07"
  condition:
    hash.sha256(0, filesize) == "4fede1be1261e93eac85fbf92813548279ff1ba58bf831b22e9c4e088d292f5c"
}
```

### Sample 40: `520c9ba8bd33902e`

| Field | Value |
|---|---|
| SHA-256 | `520c9ba8bd33902ee505fc335e403e1595e9c084a80f4fca755fe4edc54b6ab4` |
| Family label | `unknown` |
| File name | `520c9ba8bd33902e.ps1` |
| File type | `ps1` |
| First seen | `2026-11-13 01:12:07` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce0b8da86a05459a9fa0d8c17e86b506` |
| SHA-1 | `3280dc2c1066908e033b04e4587a7214abd4f5bd` |
| SHA-256 | `520c9ba8bd33902ee505fc335e403e1595e9c084a80f4fca755fe4edc54b6ab4` |
| SHA3-384 | `9439471718b428beb7cda24516167ded01dbccb49cc80bf4d49d039675a813776b5360bfebba95bfab26b53248a36c17` |
| TLSH | `T14ED45D347E062DFF5BB860C248D6C11C563C26B9CA682CF669CB1CA2391D77927B7970` |
| SSDEEP | `12288:BoKd6eRkEpqAydsql3/HBZh1l8yAiN1MdsTVaFeA3hzvXY:Pc/Hjh1l8l5sxaFeA3hzvo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_520c9ba8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "520c9ba8bd33902ee505fc335e403e1595e9c084a80f4fca755fe4edc54b6ab4"
    family = "unknown"
    file_name = "520c9ba8bd33902e.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 01:12:07"
  condition:
    hash.sha256(0, filesize) == "520c9ba8bd33902ee505fc335e403e1595e9c084a80f4fca755fe4edc54b6ab4"
}
```

### Sample 41: `13bbd78a44da51ed`

| Field | Value |
|---|---|
| SHA-256 | `13bbd78a44da51ed393884aa3cec179ea10f519a36e43e981523a3784d276725` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 01:04:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3f20bbd2fcbd864b52a18ab5827b2ee` |
| SHA-1 | `d65917c3ee2aeab87cdb1ba7f040ff3724a361b4` |
| SHA-256 | `13bbd78a44da51ed393884aa3cec179ea10f519a36e43e981523a3784d276725` |
| SHA3-384 | `a75be1818b95abb26e70d2218f6b9136c440f5c21a4850b3a9477c37511c9eacb074fea935ec1eaefa086f935a8d3369` |
| TLSH | `T15D556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSv:SDjxB4m5n8XlaPWi+d+a4TjxQP45` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_13bbd78a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13bbd78a44da51ed393884aa3cec179ea10f519a36e43e981523a3784d276725"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 01:04:05"
  condition:
    hash.sha256(0, filesize) == "13bbd78a44da51ed393884aa3cec179ea10f519a36e43e981523a3784d276725"
}
```

### Sample 42: `77682550aefde97b`

| Field | Value |
|---|---|
| SHA-256 | `77682550aefde97b1fb4e6fdf5127d2bbd54ac00be2360b738dc4be82e745b55` |
| Family label | `Meterpreter` |
| File name | `77682550aefde97b1fb4e6fdf5127d2bbd54ac00be2360b738dc4be82e745b55.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:56:44` |
| Reporter | `Tuxxin` |
| Tags | `exe, Meterpreter` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e178908eeae1ce9eb025d91076101039` |
| SHA-1 | `f9a00ebde97b4becbf1d12934b16ab4535b7292e` |
| SHA-256 | `77682550aefde97b1fb4e6fdf5127d2bbd54ac00be2360b738dc4be82e745b55` |
| SHA3-384 | `b15a3a651dde7efce2e2c7ff9270740b1b6d4cc095e2a69d010db67050e7bd17cd4b6455956103aabb9afd27551d9ce3` |
| IMPHASH | `c2d02fc98f1d75d7b9457468ec75da0e` |
| TLSH | `T1A4F1658273162C76F6790AFFC283CB9792FDBB3412B7071B061C002A625151A7975B42` |
| SSDEEP | `24:ev1GSkiiljEB04pFNknehtht6dp5JxFFW3KZqx2MYbmIY+k6lMd6ZAFp:qkfj+04anehthEdxFW3T2FbLY+kMmx` |

#### Technical Assessment

- The sample is tracked as `Meterpreter` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Meterpreter_042_77682550
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77682550aefde97b1fb4e6fdf5127d2bbd54ac00be2360b738dc4be82e745b55"
    family = "Meterpreter"
    file_name = "77682550aefde97b1fb4e6fdf5127d2bbd54ac00be2360b738dc4be82e745b55.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:56:44"
  condition:
    hash.sha256(0, filesize) == "77682550aefde97b1fb4e6fdf5127d2bbd54ac00be2360b738dc4be82e745b55"
}
```

### Sample 43: `ae3401fa05cc4e3c`

| Field | Value |
|---|---|
| SHA-256 | `ae3401fa05cc4e3c6ac68e79c5a82a7cdc1e9de7d69309d8256aa2d544564825` |
| Family label | `unknown` |
| File name | `ae3401fa05cc4e3c6ac68e79c5a82a7cdc1e9de7d69309d8256aa2d544564825.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:53:45` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `678e6dea175345fb084b12605b649813` |
| SHA-1 | `2074684670f9052842fe14f2fd5b86868f81b622` |
| SHA-256 | `ae3401fa05cc4e3c6ac68e79c5a82a7cdc1e9de7d69309d8256aa2d544564825` |
| SHA3-384 | `a8021bd49e0bbf2a61959a5dd8b323e059bee92bfd44c78e070813fc745473c7256413936ff00e77e65f55548e660631` |
| IMPHASH | `d893487fd0e3377b6ebb07a696df1a67` |
| TLSH | `T154F618065E0BC8DDEBD2907860FAC4F482347D5C49E5908E2CD7B7E8A17C16E6267D2B` |
| SSDEEP | `12288:4E/SnJlydlCL7uPXxEk/DUeqfLFAPQEVuVzY/M:4YLCL7u/lUeqf+PQEVuFY/M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_ae3401fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae3401fa05cc4e3c6ac68e79c5a82a7cdc1e9de7d69309d8256aa2d544564825"
    family = "unknown"
    file_name = "ae3401fa05cc4e3c6ac68e79c5a82a7cdc1e9de7d69309d8256aa2d544564825.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:53:45"
  condition:
    hash.sha256(0, filesize) == "ae3401fa05cc4e3c6ac68e79c5a82a7cdc1e9de7d69309d8256aa2d544564825"
}
```

### Sample 44: `c2550d821b1f29ed`

| Field | Value |
|---|---|
| SHA-256 | `c2550d821b1f29ed3196ebdaf9ddfa9ab49fe3200e85c5ff7e2c1edf9130b2a9` |
| Family label | `unknown` |
| File name | `c2550d821b1f29ed3196ebdaf9ddfa9ab49fe3200e85c5ff7e2c1edf9130b2a9.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:52:46` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15a12bca4b520b8952c6c684669d3c96` |
| SHA-1 | `8bd0b5fa1235aa0fb086d43c1c5c7cdb7599a81a` |
| SHA-256 | `c2550d821b1f29ed3196ebdaf9ddfa9ab49fe3200e85c5ff7e2c1edf9130b2a9` |
| SHA3-384 | `5dff3de13532fc0d2f275a5b1167b38e10eb3ea613a4b9a29f8b5defed280e80a14b9eae1e30c6e31068863b63558fb2` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D793A2486EAA6140D83BF37D9FAF4D0CE77981235109D202BD6CA1955FB1A2085EDFEC` |
| SSDEEP | `1536:ker+dXQsjKhNJGj60MAQ9QCzTzQ9y6zICeZOUtxS:keQD5C9XXzQclwUtE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_c2550d82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2550d821b1f29ed3196ebdaf9ddfa9ab49fe3200e85c5ff7e2c1edf9130b2a9"
    family = "unknown"
    file_name = "c2550d821b1f29ed3196ebdaf9ddfa9ab49fe3200e85c5ff7e2c1edf9130b2a9.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:52:46"
  condition:
    hash.sha256(0, filesize) == "c2550d821b1f29ed3196ebdaf9ddfa9ab49fe3200e85c5ff7e2c1edf9130b2a9"
}
```

### Sample 45: `d99eb978d6c2a2a7`

| Field | Value |
|---|---|
| SHA-256 | `d99eb978d6c2a2a737a6ccf16441a46c83ae7fa0ab827720e957eda4f77dba18` |
| Family label | `Adware.360SafeBrowse` |
| File name | `d99eb978d6c2a2a737a6ccf16441a46c83ae7fa0ab827720e957eda4f77dba18.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:48:45` |
| Reporter | `Tuxxin` |
| Tags | `Adware.360SafeBrowse, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `552d979fea44774298a7bc6c40f9044d` |
| SHA-1 | `0609b6e551ae04085b9b1e39a053365b498377d1` |
| SHA-256 | `d99eb978d6c2a2a737a6ccf16441a46c83ae7fa0ab827720e957eda4f77dba18` |
| SHA3-384 | `eda0f6241de6b71c9884f2cfb196dd4aa790f24a8681a5008e40560f3d75779c7e90509abc963c3ed57bbc3b7ae17a6f` |
| IMPHASH | `e450699ab5212aaec51dcc1a43a85d7c` |
| TLSH | `T1EF256C11F2B2F039CD96D0FD8AEB537B582C9B254B94BCC7E2845D6E2B103D0B57528A` |
| SSDEEP | `24576:mHB/e7SdgIMw6fr967Vqr8Oe4Jz2gRWQQQQQQQQQQ+QQQQQQQQQQQQQQlQQQQQQs:+SSdFMC7kxJz3WQQQQQQQQQQ+QQQQQQy` |
| ICON-DHASH | `f0f82026a464e070` |

#### Technical Assessment

- The sample is tracked as `Adware.360SafeBrowse` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_360SafeBrowse_045_d99eb978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d99eb978d6c2a2a737a6ccf16441a46c83ae7fa0ab827720e957eda4f77dba18"
    family = "Adware.360SafeBrowse"
    file_name = "d99eb978d6c2a2a737a6ccf16441a46c83ae7fa0ab827720e957eda4f77dba18.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:48:45"
  condition:
    hash.sha256(0, filesize) == "d99eb978d6c2a2a737a6ccf16441a46c83ae7fa0ab827720e957eda4f77dba18"
}
```

### Sample 46: `3c556cee98201f29`

| Field | Value |
|---|---|
| SHA-256 | `3c556cee98201f2954c99668178b5f5d6be967c3ac2a1f4f2e6f10edff5b90ff` |
| Family label | `Adware.OfferCore` |
| File name | `3c556cee98201f2954c99668178b5f5d6be967c3ac2a1f4f2e6f10edff5b90ff.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:46:03` |
| Reporter | `Tuxxin` |
| Tags | `Adware.OfferCore, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f99f94acaab4d1c43205f8db4fef2b5b` |
| SHA-1 | `7b62e4022d1983a8797d02b636494d489ab48a64` |
| SHA-256 | `3c556cee98201f2954c99668178b5f5d6be967c3ac2a1f4f2e6f10edff5b90ff` |
| SHA3-384 | `02ad4d8272cceba15af1c45719ec37494e3b14eb5ba6d2a9f8fc34067f8fd99ed87e75264571ba352bc7dfc8ba9d9b99` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T14FA5D03FB28B653EE06E5A397A72E210583B7A6165138C5696F4C88CCF254701E3F787` |
| SSDEEP | `24576:6XNrSLScusMmOvjjhzvLj51x6jMgkcXjPeynRkIegf+Sve+9Cx+gBbfWzOUxSXcn:FuI2hzxRHcTeynRkfg7ve+AhrWzOUh` |
| ICON-DHASH | `b36494a8cca2cc4d` |

#### Technical Assessment

- The sample is tracked as `Adware.OfferCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_OfferCore_046_3c556cee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c556cee98201f2954c99668178b5f5d6be967c3ac2a1f4f2e6f10edff5b90ff"
    family = "Adware.OfferCore"
    file_name = "3c556cee98201f2954c99668178b5f5d6be967c3ac2a1f4f2e6f10edff5b90ff.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:46:03"
  condition:
    hash.sha256(0, filesize) == "3c556cee98201f2954c99668178b5f5d6be967c3ac2a1f4f2e6f10edff5b90ff"
}
```

### Sample 47: `85a9c228e57e4096`

| Field | Value |
|---|---|
| SHA-256 | `85a9c228e57e4096458d611f25c7df639369abc31db06f141c5b87bb51859c6d` |
| Family label | `unknown` |
| File name | `85a9c228e57e4096.js` |
| File type | `js` |
| First seen | `2026-11-13 00:36:41` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac673a6f80fe89b068163060fb5d21ee` |
| SHA-1 | `d1758363d118f9474cae25565a11006f78aec843` |
| SHA-256 | `85a9c228e57e4096458d611f25c7df639369abc31db06f141c5b87bb51859c6d` |
| SHA3-384 | `83b5a73bc08bffb77f37e8a54ca78f135db020fb4c24f3ba96e7b261a3cf1e4b16d38c015728a949be07dbde107b938c` |
| TLSH | `T1F05198A9358234A142FB64B4D67F650EE2B802D0B80B4480E67955817FB3DF35617FAC` |
| SSDEEP | `48:l0CubQ8Xl8ecwac90w9mKvzBoysBGumLlTvs3yNJ9fqKVEYaIz+oItu:GCt6n6M9Noy62T0CNXSjYfz+oItu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_85a9c228
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85a9c228e57e4096458d611f25c7df639369abc31db06f141c5b87bb51859c6d"
    family = "unknown"
    file_name = "85a9c228e57e4096.js"
    file_type = "js"
    first_seen = "2026-11-13 00:36:41"
  condition:
    hash.sha256(0, filesize) == "85a9c228e57e4096458d611f25c7df639369abc31db06f141c5b87bb51859c6d"
}
```

### Sample 48: `7d8e2ed973eccede`

| Field | Value |
|---|---|
| SHA-256 | `7d8e2ed973eccedea4a76edcdca0860b37dda12e27404da0520da32f0b74d937` |
| Family label | `Mirai` |
| File name | `7d8e2ed973eccedea4a76edcdca0860b37dda12e27404da0520da32f0b74d937.elf` |
| File type | `elf` |
| First seen | `2026-11-13 00:36:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed1dc36f8823fd61cf944e9eb57fcadb` |
| SHA-1 | `eed404b5dd59b2ff1afa65e71102ef5f9be32ff9` |
| SHA-256 | `7d8e2ed973eccedea4a76edcdca0860b37dda12e27404da0520da32f0b74d937` |
| SHA3-384 | `d2489482d254658d3ce1929f7a1034447771bfbe883c4f64992e7bf9a32745c2f2d18eccc3ddb3855300e6112d364ace` |
| TLSH | `T199C31B86BC81C612C5E260B7FB1E91CD376643B8D3E67103DD19AB29374B86B0E7B251` |
| TELFHASH | `t19b311f46ef881eec77e8451980ab917a19ea31fe071111c3af6dab8f5613f51323847a` |
| SSDEEP | `1536:3zwzsvB1rkXfVyl70K5has/QlDfiA7X1zRSmYNfiH5loXTqgSv98cRY:3zw4jrQfAIUasYBfiAJ9YNfKmQ9m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_7d8e2ed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d8e2ed973eccedea4a76edcdca0860b37dda12e27404da0520da32f0b74d937"
    family = "Mirai"
    file_name = "7d8e2ed973eccedea4a76edcdca0860b37dda12e27404da0520da32f0b74d937.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:36:08"
  condition:
    hash.sha256(0, filesize) == "7d8e2ed973eccedea4a76edcdca0860b37dda12e27404da0520da32f0b74d937"
}
```

### Sample 49: `bd402aa2ee74ee9c`

| Field | Value |
|---|---|
| SHA-256 | `bd402aa2ee74ee9c8f13d0250f0816b662a438de1df56480983628b2397eabc9` |
| Family label | `Mirai` |
| File name | `bd402aa2ee74ee9c8f13d0250f0816b662a438de1df56480983628b2397eabc9.elf` |
| File type | `elf` |
| First seen | `2026-11-13 00:33:30` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2018a55bf132f14ea3ed977feda6befa` |
| SHA-1 | `ee94cb79c9dc4700225920bc8f36920f08821c41` |
| SHA-256 | `bd402aa2ee74ee9c8f13d0250f0816b662a438de1df56480983628b2397eabc9` |
| SHA3-384 | `e57ca1388c928b999e8e74f23a9590a60afd681baa7f9c3a8818ccdc1066c40679385398fa134d3c38128e886b05d138` |
| TLSH | `T12CB39E02CD745D9CE03E6E7110B496BE4B13E580981A7EBB3C5682994057EC8F9AFBF4` |
| SSDEEP | `3072:20SWwYlnu3PtR3kkNcUtTnK2CgVSgQlLqKs:20SVsnu3Pt5k4cArVShAP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_bd402aa2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd402aa2ee74ee9c8f13d0250f0816b662a438de1df56480983628b2397eabc9"
    family = "Mirai"
    file_name = "bd402aa2ee74ee9c8f13d0250f0816b662a438de1df56480983628b2397eabc9.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:33:30"
  condition:
    hash.sha256(0, filesize) == "bd402aa2ee74ee9c8f13d0250f0816b662a438de1df56480983628b2397eabc9"
}
```

### Sample 50: `98244dada836addb`

| Field | Value |
|---|---|
| SHA-256 | `98244dada836addb8910fdc27b155b97c4ba35c7d8e2098ed84f9df01ec0b7c6` |
| Family label | `Mirai` |
| File name | `98244dada836addb8910fdc27b155b97c4ba35c7d8e2098ed84f9df01ec0b7c6.elf` |
| File type | `elf` |
| First seen | `2026-11-13 00:32:30` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90e530f5eed35372e33b1be0ce4f18ba` |
| SHA-1 | `3ee24c6f66b5508d813a83f4bb807fb7f67e7583` |
| SHA-256 | `98244dada836addb8910fdc27b155b97c4ba35c7d8e2098ed84f9df01ec0b7c6` |
| SHA3-384 | `2154cf00a6ab254e406697f65c7289c75285b952020c7e7830a4419536fed7056fa75b8022066101068459010541ab49` |
| TLSH | `T17BC31C9ABC818B11D6C555BAFD1E51CD33134BBCE3EA72139E14AB2D278B86B0E37501` |
| TELFHASH | `t13ae02612bd949eade7ca08a6c2fd6206a2c6f48f3b0c24263d1cc74f8952c60341b81a` |
| SSDEEP | `3072:mOMARAXEnJaINmnEFVYeigrCHEg48UY2oVaRUmIvWDIQ7jouvL+uS:mwdmEVdigrC1RXDammI1QPoOQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_98244dad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98244dada836addb8910fdc27b155b97c4ba35c7d8e2098ed84f9df01ec0b7c6"
    family = "Mirai"
    file_name = "98244dada836addb8910fdc27b155b97c4ba35c7d8e2098ed84f9df01ec0b7c6.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:32:30"
  condition:
    hash.sha256(0, filesize) == "98244dada836addb8910fdc27b155b97c4ba35c7d8e2098ed84f9df01ec0b7c6"
}
```

### Sample 51: `f208e22323d690f5`

| Field | Value |
|---|---|
| SHA-256 | `f208e22323d690f516a92c8de55b319d1904f57bf06d58a6e2633e217a9995f0` |
| Family label | `Mirai` |
| File name | `f208e22323d690f516a92c8de55b319d1904f57bf06d58a6e2633e217a9995f0.elf` |
| File type | `elf` |
| First seen | `2026-11-13 00:31:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ce5fd7d2f8109da0cfa2c6b886e16d7` |
| SHA-1 | `8d49666d934e58a3af0c71cafded672a269aaf79` |
| SHA-256 | `f208e22323d690f516a92c8de55b319d1904f57bf06d58a6e2633e217a9995f0` |
| SHA3-384 | `33a10a44c10490ae87d3c2877e0246b544dc54079ff1a1dff89634585addf761fc235dde9475b88c0afbaf4b6b0fd706` |
| TLSH | `T146931996F500DCBDF84AD73780474A06BAB1F3650F520E33B35AF9A7E9B5094482EE85` |
| SSDEEP | `1536:tL95hBgf0O9KKOOOOOOOOOgxxvZmHHp88/M+wDn0Y4CSkExmpNbNOx8HtE+Pqo:l95Af0O9KKOOOOOOOOOgxLiHpWfnH4N0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_f208e223
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f208e22323d690f516a92c8de55b319d1904f57bf06d58a6e2633e217a9995f0"
    family = "Mirai"
    file_name = "f208e22323d690f516a92c8de55b319d1904f57bf06d58a6e2633e217a9995f0.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:31:04"
  condition:
    hash.sha256(0, filesize) == "f208e22323d690f516a92c8de55b319d1904f57bf06d58a6e2633e217a9995f0"
}
```

### Sample 52: `b483560be21a3986`

| Field | Value |
|---|---|
| SHA-256 | `b483560be21a39860b6f1d14fdce20c58971b56c5877eee6992a8b7bc2c149b2` |
| Family label | `Mirai` |
| File name | `b483560be21a39860b6f1d14fdce20c58971b56c5877eee6992a8b7bc2c149b2.elf` |
| File type | `elf` |
| First seen | `2026-11-13 00:28:34` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d2ec3ea7d2ba71c30d59a3c86349734` |
| SHA-1 | `f2d267b01e10e8b843ca68a3a7f24d038d37a0ee` |
| SHA-256 | `b483560be21a39860b6f1d14fdce20c58971b56c5877eee6992a8b7bc2c149b2` |
| SHA3-384 | `190c6c3480096341d3a076c23e11364fa5453979f03a711a9435731155671712684d4790ce9f8113d5d1cdcd6db672a8` |
| TLSH | `T1DCB34A4173694407F3AB4DB1283F6BE597EEC6A031E0A285A54DEB4F8171E322546FCD` |
| SSDEEP | `1536:Ck82fKLIJpxc22/krLYIHiv27M1SL7UAxBuMqWezBQIhUcnzaCTU5aqMsDFTKu2i:h8RIJ0sMQLTxcvoTxxFWu5YqVt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_b483560b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b483560be21a39860b6f1d14fdce20c58971b56c5877eee6992a8b7bc2c149b2"
    family = "Mirai"
    file_name = "b483560be21a39860b6f1d14fdce20c58971b56c5877eee6992a8b7bc2c149b2.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:28:34"
  condition:
    hash.sha256(0, filesize) == "b483560be21a39860b6f1d14fdce20c58971b56c5877eee6992a8b7bc2c149b2"
}
```

### Sample 53: `fa0d4f7ee7b98832`

| Field | Value |
|---|---|
| SHA-256 | `fa0d4f7ee7b98832254aaac4ffbde039db206d61b6586cf054fced284233408f` |
| Family label | `Mirai` |
| File name | `fa0d4f7ee7b98832254aaac4ffbde039db206d61b6586cf054fced284233408f.elf` |
| File type | `elf` |
| First seen | `2026-11-13 00:28:28` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6849524229a50da188ac329a440cf8bd` |
| SHA-1 | `c00dfca07def521679c03c5f29c1391bf98631f4` |
| SHA-256 | `fa0d4f7ee7b98832254aaac4ffbde039db206d61b6586cf054fced284233408f` |
| SHA3-384 | `e2b747579522e86f92789fe6ecd8834c42f92b0fd60230339f931d175ff96f6acedde956b9808ca1c82209aef12406a2` |
| TLSH | `T108B32B86BC81C602C6E1A0B7FB1F91CD372643B8D3E671139D19AB29774B8670E7B641` |
| TELFHASH | `t12c316353ee840eec6bf18244409e502b85ea39fd2b5124c3ab7c9b8f5612fe1743403e` |
| SSDEEP | `3072:6a6AY7cH6BJEaHGKwdhHW159m7czMMs1aB:6aYcwEaHPwdh2dm7cQMs0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_fa0d4f7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa0d4f7ee7b98832254aaac4ffbde039db206d61b6586cf054fced284233408f"
    family = "Mirai"
    file_name = "fa0d4f7ee7b98832254aaac4ffbde039db206d61b6586cf054fced284233408f.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:28:28"
  condition:
    hash.sha256(0, filesize) == "fa0d4f7ee7b98832254aaac4ffbde039db206d61b6586cf054fced284233408f"
}
```

### Sample 54: `2d1bf8db3a4c31b7`

| Field | Value |
|---|---|
| SHA-256 | `2d1bf8db3a4c31b7a9446a8d5335b5a25bf836b27c1143617aa833163cfd8595` |
| Family label | `Mirai` |
| File name | `2d1bf8db3a4c31b7a9446a8d5335b5a25bf836b27c1143617aa833163cfd8595.elf` |
| File type | `elf` |
| First seen | `2026-11-13 00:27:30` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `285eeb2a2098dc79f3c290b7f30d48eb` |
| SHA-1 | `4523c76b265a0a6c73299e8f1fe57da2cd7a84a3` |
| SHA-256 | `2d1bf8db3a4c31b7a9446a8d5335b5a25bf836b27c1143617aa833163cfd8595` |
| SHA3-384 | `f1b4cdd0a17772a4d517a25b69ed28513ae63978bcf8d2dba702ba8afddcb766031b1e02d39de57e13f229e5d3ad91a3` |
| TLSH | `T19FB39E12DDB05DECE13A6D7160B486B94B23E180991B2DF73C46CA66408BEC8F59B7F4` |
| SSDEEP | `3072:KiggUduYVbLcYMusX2ltOtTxq5Ojw/z59Hg6di:KignkYVbLcRufltzCSzNw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_2d1bf8db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d1bf8db3a4c31b7a9446a8d5335b5a25bf836b27c1143617aa833163cfd8595"
    family = "Mirai"
    file_name = "2d1bf8db3a4c31b7a9446a8d5335b5a25bf836b27c1143617aa833163cfd8595.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:27:30"
  condition:
    hash.sha256(0, filesize) == "2d1bf8db3a4c31b7a9446a8d5335b5a25bf836b27c1143617aa833163cfd8595"
}
```

### Sample 55: `5c5ad5591079d436`

| Field | Value |
|---|---|
| SHA-256 | `5c5ad5591079d436119cddd217ce7248e15119a4fbb5e826d6cdf0f1cae06d93` |
| Family label | `unknown` |
| File name | `5c5ad5591079d436.js` |
| File type | `js` |
| First seen | `2026-11-13 00:26:55` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f01374d555aa49c2107c0424537156e6` |
| SHA-1 | `5e5b89bd0a5e16ebbeb95638bc3c514873b388c4` |
| SHA-256 | `5c5ad5591079d436119cddd217ce7248e15119a4fbb5e826d6cdf0f1cae06d93` |
| SHA3-384 | `40c04531687e909789184a7a02271fa4faf414942c4ad487e7952b4f0bcb7f10dff129db6a936f2a22a85153a98d4200` |
| TLSH | `T186837F135710477EA3DC0AC48216750B1FE9E61BE235648FBF82ADEEBA1D4D2647C623` |
| SSDEEP | `768:O2ajqZmthJoWI21oGqyrT+yw/gyrT+yw/jWu+OaRIxWu+OaRIWTSBQA+J464Eq6G:OhMNWdo+HkTE64PyfTE64PyfTE64Py4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_5c5ad559
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c5ad5591079d436119cddd217ce7248e15119a4fbb5e826d6cdf0f1cae06d93"
    family = "unknown"
    file_name = "5c5ad5591079d436.js"
    file_type = "js"
    first_seen = "2026-11-13 00:26:55"
  condition:
    hash.sha256(0, filesize) == "5c5ad5591079d436119cddd217ce7248e15119a4fbb5e826d6cdf0f1cae06d93"
}
```

### Sample 56: `2fb33c9d4e10b8dc`

| Field | Value |
|---|---|
| SHA-256 | `2fb33c9d4e10b8dcf773cf10994821d5d99401dbd0067ab05a34ff4fa72eb626` |
| Family label | `unknown` |
| File name | `2fb33c9d4e10b8dc.js` |
| File type | `js` |
| First seen | `2026-11-13 00:26:49` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c39f2234546ac9f1ad1156a11b3d0691` |
| SHA-1 | `e8f1ae816051781afd97fcac9edf5c1a218dc175` |
| SHA-256 | `2fb33c9d4e10b8dcf773cf10994821d5d99401dbd0067ab05a34ff4fa72eb626` |
| SHA3-384 | `d9fb9bb5fc85d858605a913b84166dee2b3a1ad13089c6884ef9943a9e4f094453413d02a8b50a1fd20ae0d4ec193fac` |
| TLSH | `T16EB308DB7389712257EB21F5402F610BB2B6998FA80C4058F355D4E9BC7C98A413BF7A` |
| SSDEEP | `1536:/KRUXRa8Dgwxcy2jpBNwch96SLk8Ek2BSrBGS1ia/eEk4aV2EXi8SMpQ47GKUTET:/u1zNwcv9qBy1HOg8SMpQ47GKdo4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_2fb33c9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fb33c9d4e10b8dcf773cf10994821d5d99401dbd0067ab05a34ff4fa72eb626"
    family = "unknown"
    file_name = "2fb33c9d4e10b8dc.js"
    file_type = "js"
    first_seen = "2026-11-13 00:26:49"
  condition:
    hash.sha256(0, filesize) == "2fb33c9d4e10b8dcf773cf10994821d5d99401dbd0067ab05a34ff4fa72eb626"
}
```

### Sample 57: `81f4401376558048`

| Field | Value |
|---|---|
| SHA-256 | `81f44013765580486de77bead284d978da7f8c873873854c176873afc6f690ea` |
| Family label | `WARDENStealer` |
| File name | `81f44013765580486de77bead284d978da7f8c873873854c176873afc6f690ea.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:26:06` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f072063feeea686498156ca7553eb770` |
| SHA-1 | `86784be672eef4da7d2215b99b1b196a299b6131` |
| SHA-256 | `81f44013765580486de77bead284d978da7f8c873873854c176873afc6f690ea` |
| SHA3-384 | `f8ef4f8c999d1cea489aeb9eaf7638dae439edc67949c00e94b9a45bd99682c88cd29d4079cb3bd1c125144800aa78cd` |
| IMPHASH | `40cd6baf768c0bc4682b7fa1e156180c` |
| TLSH | `T14E0501D0F79217E8D52AC67489525E16EA613C011B3065FF178833A60E32BD2EF7BB25` |
| SSDEEP | `12288:O44Ls6dc0Lnr098BJHklgjcNMFGkQtmTwvwD2nyksmsJpGhkVcxbNvakd6wTnuun:6/687WggywzmbDcyklCGOVcxxvZd6kf` |
| ICON-DHASH | `300c9e469d864c10` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_057_81f44013
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81f44013765580486de77bead284d978da7f8c873873854c176873afc6f690ea"
    family = "WARDENStealer"
    file_name = "81f44013765580486de77bead284d978da7f8c873873854c176873afc6f690ea.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:26:06"
  condition:
    hash.sha256(0, filesize) == "81f44013765580486de77bead284d978da7f8c873873854c176873afc6f690ea"
}
```

### Sample 58: `385d24abef98cb9d`

| Field | Value |
|---|---|
| SHA-256 | `385d24abef98cb9d1c0a9e78090cac4da444becc638f312ff80fff400ae235fb` |
| Family label | `GuLoader` |
| File name | `Stenstraum V.2413.vbs` |
| File type | `vbs` |
| First seen | `2026-11-13 00:23:53` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f2664d04df0ef1a7262030401fce0a3` |
| SHA-1 | `e404ec679755ecf212fde18e70cc7b97a9662c25` |
| SHA-256 | `385d24abef98cb9d1c0a9e78090cac4da444becc638f312ff80fff400ae235fb` |
| SHA3-384 | `9270e41c9d28761535e70ea0ee56615151b55a010589acc0802fc1f57b586e635c91c229f36a22b1282e57dbd1438924` |
| TLSH | `T12DC3B330D95621153B0B179FB8E32753B3E8A115F1132CA4ADEB028950EED5CE2ADFD6` |
| SSDEEP | `1536:/lUuOcIsRmLeZFB39dP+1g0Y2cdACNrYUpkn41po5ly664pR1trHxX4g1X:/yu8FSB3W132ASYxapJqwg1X` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_058_385d24ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "385d24abef98cb9d1c0a9e78090cac4da444becc638f312ff80fff400ae235fb"
    family = "GuLoader"
    file_name = "Stenstraum V.2413.vbs"
    file_type = "vbs"
    first_seen = "2026-11-13 00:23:53"
  condition:
    hash.sha256(0, filesize) == "385d24abef98cb9d1c0a9e78090cac4da444becc638f312ff80fff400ae235fb"
}
```

### Sample 59: `3f61eca59a92f673`

| Field | Value |
|---|---|
| SHA-256 | `3f61eca59a92f6737fe01a5ed5e2f184ebcc3a7720afc016e16727361dd36e08` |
| Family label | `ZeuS` |
| File name | `3f61eca59a92f6737fe01a5ed5e2f184ebcc3a7720afc016e16727361dd36e08.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:23:31` |
| Reporter | `Tuxxin` |
| Tags | `exe, ZeuS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d0af4e06258c8ccc9728a7937edbf62` |
| SHA-1 | `98e75ac228c5f57adad715304525413decd2a844` |
| SHA-256 | `3f61eca59a92f6737fe01a5ed5e2f184ebcc3a7720afc016e16727361dd36e08` |
| SHA3-384 | `fa88789392e4d6d3464792e663fa37aae5618f56581f4cc3d16c0f1936ef9dbd994bc2e47ef77e206a602062c15c895b` |
| IMPHASH | `1c2489367a741a394ef5f46c06397c1b` |
| TLSH | `T122D3AF677480A0B2C5A73671AEA9B26523FFDD3427399C83E3980D6D25B1893731D34B` |
| SSDEEP | `3072:/caqyte6vV77snHLLxtSyaXOqdPNbnhW4IxZx5kCZuubFrhU1wKKrONmv:/caBtJ77snHRFY7PNNW4IxZ7zbC0rONa` |

#### Technical Assessment

- The sample is tracked as `ZeuS` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ZeuS_059_3f61eca5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f61eca59a92f6737fe01a5ed5e2f184ebcc3a7720afc016e16727361dd36e08"
    family = "ZeuS"
    file_name = "3f61eca59a92f6737fe01a5ed5e2f184ebcc3a7720afc016e16727361dd36e08.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:23:31"
  condition:
    hash.sha256(0, filesize) == "3f61eca59a92f6737fe01a5ed5e2f184ebcc3a7720afc016e16727361dd36e08"
}
```

### Sample 60: `fdae956fecfd2244`

| Field | Value |
|---|---|
| SHA-256 | `fdae956fecfd22448b0719e66d8ed669b5acf52dca4472e849d9f141d102fe6b` |
| Family label | `Adware.OfferCore` |
| File name | `fdae956fecfd22448b0719e66d8ed669b5acf52dca4472e849d9f141d102fe6b.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:22:37` |
| Reporter | `Tuxxin` |
| Tags | `Adware.OfferCore, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec4c2db69ea4ea123f80fec06431f50a` |
| SHA-1 | `0ea8637cab0ef3e0c5c58b55bb1d917055867ff8` |
| SHA-256 | `fdae956fecfd22448b0719e66d8ed669b5acf52dca4472e849d9f141d102fe6b` |
| SHA3-384 | `b17594fad1b1fbdaab79a9a894f958c58b6826aed6c34fc5aab016983b22a56b005e134e7ac67867ff222534e11edd8a` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T199A5D03FB28B653EE06E5A3A7A72E210583B7A6165164C4696F4C88CCF254701E3F787` |
| SSDEEP | `24576:eXNrSLScusMmOvjjhzvL5qtRgkcXjPeynRkIegf+Sve+9Cx+gBbfWzOUxSXc64de:BuI2hkHcTeynRkfg7ve+AhrWzOUA` |
| ICON-DHASH | `b36494a8cca2cc4d` |

#### Technical Assessment

- The sample is tracked as `Adware.OfferCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_OfferCore_060_fdae956f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdae956fecfd22448b0719e66d8ed669b5acf52dca4472e849d9f141d102fe6b"
    family = "Adware.OfferCore"
    file_name = "fdae956fecfd22448b0719e66d8ed669b5acf52dca4472e849d9f141d102fe6b.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:22:37"
  condition:
    hash.sha256(0, filesize) == "fdae956fecfd22448b0719e66d8ed669b5acf52dca4472e849d9f141d102fe6b"
}
```

### Sample 61: `32f8f9789dfd279e`

| Field | Value |
|---|---|
| SHA-256 | `32f8f9789dfd279e8faaf275f096f7ef8329b15efe0ce0f558064da906bd7cc5` |
| Family label | `unknown` |
| File name | `32f8f9789dfd279e8faaf275f096f7ef8329b15efe0ce0f558064da906bd7cc5.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:22:31` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccf738214c030c03b0dc36acc3d9ff6e` |
| SHA-1 | `acc707b0d7f9a96ca9b337cae215a2544490ebbe` |
| SHA-256 | `32f8f9789dfd279e8faaf275f096f7ef8329b15efe0ce0f558064da906bd7cc5` |
| SHA3-384 | `3c25cff15030978c4d8d62df06b3041676585d35e52b59be515eb614c4f9d9e4a82ccc65ceb0d7e99a541a5901d90de3` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15A5533463980A172E9AE97B3B572210AD7B46D638860E61D50DB41FC3BB3F6D0A45CF3` |
| SSDEEP | `24576:XaY9hhEPNyleMmQGH6Ou0pxgvEjW3038bc9iug3BPNCMJu2:X9hEQ3mQG4BK003Li93BPNCMg` |
| ICON-DHASH | `2485636263435b84` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_32f8f978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f8f9789dfd279e8faaf275f096f7ef8329b15efe0ce0f558064da906bd7cc5"
    family = "unknown"
    file_name = "32f8f9789dfd279e8faaf275f096f7ef8329b15efe0ce0f558064da906bd7cc5.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:22:31"
  condition:
    hash.sha256(0, filesize) == "32f8f9789dfd279e8faaf275f096f7ef8329b15efe0ce0f558064da906bd7cc5"
}
```

### Sample 62: `88e2d46aec44dc1d`

| Field | Value |
|---|---|
| SHA-256 | `88e2d46aec44dc1d4bddcee934b7345c1d9463d8ce02d3aa3f2413df65c72bef` |
| Family label | `SalatStealer` |
| File name | `329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:22:22` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1f451b7857974e623921d1a6f64f8b9` |
| SHA-1 | `d1bfbcb6bb3f2d5a58a7c8ff9786daf1ccb0a056` |
| SHA-256 | `88e2d46aec44dc1d4bddcee934b7345c1d9463d8ce02d3aa3f2413df65c72bef` |
| SHA3-384 | `bb8add81fcafac97aef8b06a9e230f85cd3f5cdc83d3b19e190c53d18adbee81f610b0bc74e6d43a068a1513228a1a6f` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A3C66C11FACB54F6F8036831416BB27F23355D048B28DB9BEB587B2AF8776911C6A305` |
| SSDEEP | `98304:aJkQLcy5utC5tGkCqi0hH4S3HVd/EuO/:4LeatVrdHTCuO/` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_062_88e2d46a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88e2d46aec44dc1d4bddcee934b7345c1d9463d8ce02d3aa3f2413df65c72bef"
    family = "SalatStealer"
    file_name = "329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:22:22"
  condition:
    hash.sha256(0, filesize) == "88e2d46aec44dc1d4bddcee934b7345c1d9463d8ce02d3aa3f2413df65c72bef"
}
```

### Sample 63: `329a6bc97fe8a015`

| Field | Value |
|---|---|
| SHA-256 | `329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4` |
| Family label | `SalatStealer` |
| File name | `329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:21:15` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd1b7c45f69fc2135d960a1bfdb0f3e7` |
| SHA-1 | `c40e7cff9087dbe00023c505ce549a19a14c73e5` |
| SHA-256 | `329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4` |
| SHA3-384 | `7660f5f89a7af306e805e5e5a12ad525963468bc5ed754c220356b43594c9a229df06764be33827d0724d9f7fdc78220` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T169F5334B6905CAF6DA7332B7C6C2CB5295640F6BE2413E9FE0AC17DA05B466398374C3` |
| SSDEEP | `49152:mX24YH2XouH1jBglgrUO6MP9mRyOgIr1qOqIRQjeYF0GB5fTYlbYX8xX2a:mXOH2NHca4OTVs+IhWQgeYOGLY5YX` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_063_329a6bc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4"
    family = "SalatStealer"
    file_name = "329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:21:15"
  condition:
    hash.sha256(0, filesize) == "329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4"
}
```

### Sample 64: `6ace5308f7dbbb74`

| Field | Value |
|---|---|
| SHA-256 | `6ace5308f7dbbb74e690461a52045c5b976c811014f33216c9c95e229a571081` |
| Family label | `RevStealer` |
| File name | `6ace5308f7dbbb74e690461a52045c5b976c811014f33216c9c95e229a571081.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:21:07` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1efb5cf95fb0ff208e3b62f7fc71911f` |
| SHA-1 | `109cb350672bf17ff503592df4383cd0d2c66212` |
| SHA-256 | `6ace5308f7dbbb74e690461a52045c5b976c811014f33216c9c95e229a571081` |
| SHA3-384 | `661266b25bd90c3f0c176f8ff79eeb15acb9360628f728f7af9af9654017ec7f903987e3fe592612454e37bb9461805f` |
| IMPHASH | `3b33063fa6540cfc510bd20fcc99cc96` |
| TLSH | `T119D52349FCBA19B4F477C3B68797A0AFB06A375086B14C5776CC1B205D12E582C3A73A` |
| SSDEEP | `49152:DPy4acC/5zyYRwEQGoGbjQtdLbooBJwdM+QCVDwNeUCOcAy4KQIIck4j3o:Da4a55xyEiGf0BooIdMYMNeVO8QvM` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_064_6ace5308
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ace5308f7dbbb74e690461a52045c5b976c811014f33216c9c95e229a571081"
    family = "RevStealer"
    file_name = "6ace5308f7dbbb74e690461a52045c5b976c811014f33216c9c95e229a571081.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:21:07"
  condition:
    hash.sha256(0, filesize) == "6ace5308f7dbbb74e690461a52045c5b976c811014f33216c9c95e229a571081"
}
```

### Sample 65: `d421ea33f2b56e66`

| Field | Value |
|---|---|
| SHA-256 | `d421ea33f2b56e665424dcb501dd4925fdf81307c94dc183a120886f6a978112` |
| Family label | `SnappyClient` |
| File name | `d421ea33f2b56e665424dcb501dd4925fdf81307c94dc183a120886f6a978112.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:21:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, SnappyClient` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62352f4abbf89126b776e982e6abb2de` |
| SHA-1 | `145cec38750ce7052583e3f9b7018349828ea62a` |
| SHA-256 | `d421ea33f2b56e665424dcb501dd4925fdf81307c94dc183a120886f6a978112` |
| SHA3-384 | `1336bba2aa44c04cb298da157572e2aeaa0390f043c187456045d1c4f27018e92c19dbbfb99e9af28feddb2266b0f62e` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T1AC56338177D4B8F2C166DE32DF8ED3114272D79980D20E8F2A6AAF052DC71F626075E9` |
| SSDEEP | `98304:+phBbxffWv0ZE2F0HMtJ6IKmfzWGeNgZNf6hqPD20FCTdH15YnxnE8O3xeu:+phB1ffG2gMtJ6Ijb5NShuDAsnmheu` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_065_d421ea33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d421ea33f2b56e665424dcb501dd4925fdf81307c94dc183a120886f6a978112"
    family = "SnappyClient"
    file_name = "d421ea33f2b56e665424dcb501dd4925fdf81307c94dc183a120886f6a978112.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:21:01"
  condition:
    hash.sha256(0, filesize) == "d421ea33f2b56e665424dcb501dd4925fdf81307c94dc183a120886f6a978112"
}
```

### Sample 66: `61fac349b03e9ff3`

| Field | Value |
|---|---|
| SHA-256 | `61fac349b03e9ff3163f1096351028991a45071654cbc60cd418e513e7f378c4` |
| Family label | `CoinMiner` |
| File name | `20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:19:21` |
| Reporter | `abuse_ch` |
| Tags | `CoinMiner, exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14660e7e53a980ef6b5ab45f9c354d29` |
| SHA-1 | `c1d75ff641e6238b0088536b81a6f2adb4143c5c` |
| SHA-256 | `61fac349b03e9ff3163f1096351028991a45071654cbc60cd418e513e7f378c4` |
| SHA3-384 | `2721c65bb12983392b656e817674165c537d881309961ed1b90710447fd7eae13ae18587522f956721e28c9a961d012c` |
| IMPHASH | `647682b4d75cdea8fce680da1b53837a` |
| TLSH | `T103047C1673A521FAE1778238C9544646FB73B8250720DB5F03A447BAEF27391AD3EB21` |
| SSDEEP | `3072:IaZNBkadrgruCwAA/Fx4nCmzpPD+RQHD0oDG/SguvNS5:IGYigrkAA9GCm1D7Hgoq7` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_066_61fac349
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61fac349b03e9ff3163f1096351028991a45071654cbc60cd418e513e7f378c4"
    family = "CoinMiner"
    file_name = "20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:19:21"
  condition:
    hash.sha256(0, filesize) == "61fac349b03e9ff3163f1096351028991a45071654cbc60cd418e513e7f378c4"
}
```

### Sample 67: `d22bd62514f9dfc0`

| Field | Value |
|---|---|
| SHA-256 | `d22bd62514f9dfc0d6cf3c5f7ec87aa8e35d74fddde708b1e9187edd7a851e77` |
| Family label | `Adware.OfferCore` |
| File name | `d22bd62514f9dfc0d6cf3c5f7ec87aa8e35d74fddde708b1e9187edd7a851e77.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:18:38` |
| Reporter | `Tuxxin` |
| Tags | `Adware.OfferCore, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7994d90837702ca6252ab99e659464fe` |
| SHA-1 | `fa4e247fb445bcf3f08594c098d259258651069a` |
| SHA-256 | `d22bd62514f9dfc0d6cf3c5f7ec87aa8e35d74fddde708b1e9187edd7a851e77` |
| SHA3-384 | `84f3e30367a3d401c09821ede623d62b767a6717a720affae2a167b5374c1ae66eb9b24724920b20085402202b6c363a` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T13BA5D03FB28B653EE06E5A3A79B2E110583B7A6165138C5696F4C88CCF254701E3F787` |
| SSDEEP | `24576:1XNrSLScusMmOvjjhzvL3kYVgkcXjPeynRkIegf+Sve+9Cx+gBbfWzOUxSXc64dM:2uI2h7HcTeynRkfg7ve+AhrWzOUG` |
| ICON-DHASH | `b36494a8cca2cc4d` |

#### Technical Assessment

- The sample is tracked as `Adware.OfferCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_OfferCore_067_d22bd625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d22bd62514f9dfc0d6cf3c5f7ec87aa8e35d74fddde708b1e9187edd7a851e77"
    family = "Adware.OfferCore"
    file_name = "d22bd62514f9dfc0d6cf3c5f7ec87aa8e35d74fddde708b1e9187edd7a851e77.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:18:38"
  condition:
    hash.sha256(0, filesize) == "d22bd62514f9dfc0d6cf3c5f7ec87aa8e35d74fddde708b1e9187edd7a851e77"
}
```

### Sample 68: `20983573b840447e`

| Field | Value |
|---|---|
| SHA-256 | `20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0` |
| Family label | `CoinMiner` |
| File name | `20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:18:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fd491c23561b3332b0ae7dddda262ea` |
| SHA-1 | `1fee6ba4f8609b52737880651298bd0afb5de4a4` |
| SHA-256 | `20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0` |
| SHA3-384 | `43cb3d1bfa189a6ad1864e6c54869f534d8ee6b71a8490fbc8c20770dc0cbd3c788a5c62e421330e86a73d97ec9d885d` |
| IMPHASH | `e7f7dc86cd91396e74fe392c54623fff` |
| TLSH | `T1FD830227818EEC2FD74834BD194BB8835FAE9B5A81DA8D853F52C1E053712F14DDB8A1` |
| SSDEEP | `1536:Qu0dcnQOM/KVtpu5m+YGH0TgD2B48tm5Wmo2w51nZdlRj/9Bm5ZDsI:p0dcnQOMyVtWYGOn48cBJw55Zt/3mPI` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_068_20983573
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0"
    family = "CoinMiner"
    file_name = "20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:18:32"
  condition:
    hash.sha256(0, filesize) == "20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0"
}
```

### Sample 69: `b229269204e6db66`

| Field | Value |
|---|---|
| SHA-256 | `b229269204e6db6613793c412437025e826e05c51022d05e0b98f07617bbfd8b` |
| Family label | `ConnectWise` |
| File name | `b229269204e6db6613793c412437025e826e05c51022d05e0b98f07617bbfd8b.msi` |
| File type | `msi` |
| First seen | `2026-11-13 00:17:50` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e56518bea293008d7751054f8884e34b` |
| SHA-1 | `7af155b7efb6e22b04a241da979fd8a3269724f3` |
| SHA-256 | `b229269204e6db6613793c412437025e826e05c51022d05e0b98f07617bbfd8b` |
| SHA3-384 | `6929bf5770a2dee1c1061f1d63054450c2b9e8c3b47c6da23f92cca5a2698c75692cab06b59fb0da868363023ffcd714` |
| TLSH | `T12AA6237262F8D225E2F34639FE7992E1583A7D51DD12C01F5B28381EA271E808A77377` |
| SSDEEP | `196608:LFrg904SOLNY5V1tFrg904SOLmFrg904SOLGFrg904SOL:LFri04SOL2X1tFri04SOLmFri04SOLGg` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_069_b2292692
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b229269204e6db6613793c412437025e826e05c51022d05e0b98f07617bbfd8b"
    family = "ConnectWise"
    file_name = "b229269204e6db6613793c412437025e826e05c51022d05e0b98f07617bbfd8b.msi"
    file_type = "msi"
    first_seen = "2026-11-13 00:17:50"
  condition:
    hash.sha256(0, filesize) == "b229269204e6db6613793c412437025e826e05c51022d05e0b98f07617bbfd8b"
}
```

### Sample 70: `685e8598094f32f6`

| Field | Value |
|---|---|
| SHA-256 | `685e8598094f32f60fd2b4f37720b3e4d28ad643115f3714040e02271d1310f1` |
| Family label | `ConnectWise` |
| File name | `685e8598094f32f60fd2b4f37720b3e4d28ad643115f3714040e02271d1310f1.msi` |
| File type | `msi` |
| First seen | `2026-11-13 00:17:43` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3beaf7931cbdd502005722ddeaa3c9ad` |
| SHA-1 | `5a13c3ddff1a44dd2a05e01bb158e09c1c192a73` |
| SHA-256 | `685e8598094f32f60fd2b4f37720b3e4d28ad643115f3714040e02271d1310f1` |
| SHA3-384 | `6f45958d93369b1882e9f8020f2ffde97e73e925a2387b8bc6ea336e26aa6566574c3345d9d49354cb5fc72ffc2bb060` |
| TLSH | `T13DA6232123FAC168F1B61B35D93965B56936BD12DA22C04F1364BE6E3C31F949A72333` |
| SSDEEP | `98304:eMn1Giy8E1PqhrG6ztZNK9aNGXMn1Giy8E1PqhAMn1Giy8E1PqhNMn1Giy8E1Pqh:JZWi/z3I96/ZWijZWisZWi` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_070_685e8598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "685e8598094f32f60fd2b4f37720b3e4d28ad643115f3714040e02271d1310f1"
    family = "ConnectWise"
    file_name = "685e8598094f32f60fd2b4f37720b3e4d28ad643115f3714040e02271d1310f1.msi"
    file_type = "msi"
    first_seen = "2026-11-13 00:17:43"
  condition:
    hash.sha256(0, filesize) == "685e8598094f32f60fd2b4f37720b3e4d28ad643115f3714040e02271d1310f1"
}
```

### Sample 71: `465fb11f51863b34`

| Field | Value |
|---|---|
| SHA-256 | `465fb11f51863b34d21e1ad8943795813a7694b755a5eb109c816aa47d5ddc1f` |
| Family label | `ConnectWise` |
| File name | `465fb11f51863b34d21e1ad8943795813a7694b755a5eb109c816aa47d5ddc1f.msi` |
| File type | `msi` |
| First seen | `2026-11-13 00:17:36` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45ba46d199bd445b6135f7ec1cd44d72` |
| SHA-1 | `1aa2b758336fd13301d53bc2d5e6bdd6987041fe` |
| SHA-256 | `465fb11f51863b34d21e1ad8943795813a7694b755a5eb109c816aa47d5ddc1f` |
| SHA3-384 | `efdc3800648a6606f5344475a854487c2a01c1f200bd46e52e16bec59eb152b667c79516aa2fea5056732e31727f4c29` |
| TLSH | `T10FA6237262F8D225E2F34639FE7992E1583A7D51DD12C01F5B28381EA271E808A77377` |
| SSDEEP | `196608:kFrg904SOLJY5V1bFrg904SOLmFrg904SOLGFrg904SOL:kFri04SOL6X1bFri04SOLmFri04SOLGg` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_071_465fb11f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "465fb11f51863b34d21e1ad8943795813a7694b755a5eb109c816aa47d5ddc1f"
    family = "ConnectWise"
    file_name = "465fb11f51863b34d21e1ad8943795813a7694b755a5eb109c816aa47d5ddc1f.msi"
    file_type = "msi"
    first_seen = "2026-11-13 00:17:36"
  condition:
    hash.sha256(0, filesize) == "465fb11f51863b34d21e1ad8943795813a7694b755a5eb109c816aa47d5ddc1f"
}
```

### Sample 72: `d2413f9b81a6785d`

| Field | Value |
|---|---|
| SHA-256 | `d2413f9b81a6785de7125066d8d2ea0caabd90863c5739487d199aa8cd41d405` |
| Family label | `ConnectWise` |
| File name | `d2413f9b81a6785de7125066d8d2ea0caabd90863c5739487d199aa8cd41d405.msi` |
| File type | `msi` |
| First seen | `2026-11-13 00:17:30` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79912fba5ffe71cb409c3aa6c907a66f` |
| SHA-1 | `6633eb012dcd8da060fd9fcb5b5d17760d5324e7` |
| SHA-256 | `d2413f9b81a6785de7125066d8d2ea0caabd90863c5739487d199aa8cd41d405` |
| SHA3-384 | `7ee430d755741b57447d63c1fba26b85130fbc164fab8ce256f1aeec7731db4cbc3956eb60d29d9117da77b5a9e27f02` |
| TLSH | `T1BEA6232027F99129F1FA0639EE3992B529767D10DB23D06F53693D0E1A71E40D7A23B3` |
| SSDEEP | `196608:tMOo/K6Sdr3tJiCFKpj10XMOo/K6Sdr3t+MOo/K6Sdr3tLMOo/K6Sdr3t:tyK6cX1K70XyK6cUyK6c1yK6c` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_072_d2413f9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2413f9b81a6785de7125066d8d2ea0caabd90863c5739487d199aa8cd41d405"
    family = "ConnectWise"
    file_name = "d2413f9b81a6785de7125066d8d2ea0caabd90863c5739487d199aa8cd41d405.msi"
    file_type = "msi"
    first_seen = "2026-11-13 00:17:30"
  condition:
    hash.sha256(0, filesize) == "d2413f9b81a6785de7125066d8d2ea0caabd90863c5739487d199aa8cd41d405"
}
```

### Sample 73: `91af9fb3cfdd4fb9`

| Field | Value |
|---|---|
| SHA-256 | `91af9fb3cfdd4fb955b15d9b074c782a2100a5287765fbf3f75ec73486c3c815` |
| Family label | `ConnectWise` |
| File name | `91af9fb3cfdd4fb955b15d9b074c782a2100a5287765fbf3f75ec73486c3c815.msi` |
| File type | `msi` |
| First seen | `2026-11-13 00:16:21` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccdc693a3c5c7803d37addee376a7264` |
| SHA-1 | `9f6963eb0d168b547f400c7a42734c9e2709a07c` |
| SHA-256 | `91af9fb3cfdd4fb955b15d9b074c782a2100a5287765fbf3f75ec73486c3c815` |
| SHA3-384 | `45a06a8e6dc881e9efd0610b152d79595afcc3b7c57ea5abc859e033108b644fc0861280a345f2ea13d580eee83f8456` |
| TLSH | `T17EA6232027F99129F1FA0639EE3992B529767D10DB23C16F53693D0E1A71E40D7A23B3` |
| SSDEEP | `196608:RMOo/K6Sdr3tyiCFKpj10LMOo/K6Sdr3t+MOo/K6Sdr3tLMOo/K6Sdr3t:RyK6ck1K70LyK6cUyK6c1yK6c` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_073_91af9fb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91af9fb3cfdd4fb955b15d9b074c782a2100a5287765fbf3f75ec73486c3c815"
    family = "ConnectWise"
    file_name = "91af9fb3cfdd4fb955b15d9b074c782a2100a5287765fbf3f75ec73486c3c815.msi"
    file_type = "msi"
    first_seen = "2026-11-13 00:16:21"
  condition:
    hash.sha256(0, filesize) == "91af9fb3cfdd4fb955b15d9b074c782a2100a5287765fbf3f75ec73486c3c815"
}
```

### Sample 74: `8f9d6582e6d6a76c`

| Field | Value |
|---|---|
| SHA-256 | `8f9d6582e6d6a76c19fc20c24a499160f4ccd26955354599ee7ceef7404f418f` |
| Family label | `unknown` |
| File name | `8f9d6582e6d6a76c19fc20c24a499160f4ccd26955354599ee7ceef7404f418f.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:16:13` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edf68ab4d701cbaf57f8c143a032645d` |
| SHA-1 | `002bc1a74ff95bd6fdc3ba2b9b65d869b0f2a36e` |
| SHA-256 | `8f9d6582e6d6a76c19fc20c24a499160f4ccd26955354599ee7ceef7404f418f` |
| SHA3-384 | `ea7bbd32d880a16b167d12ba65bcb390173a26a6f2fe509121e259c5cf92bd5f27a37a2fa77f7a0da5bc7be2ceb2196b` |
| IMPHASH | `cd99bb6e675be8efd18677badcf67dd2` |
| TLSH | `T136923F06E72584F5E8B5CE3027FB1E768D70BC630D55929B4A16FE9DA830708AB2734D` |
| SSDEEP | `96:4lC8Vk7CvuHrvcQ7HKcWw4bRcpWw4bdPtboynyEKPJab3G4yeTF+:YqCWLkQ7KXbjbdP1oynyEKUb3yex+` |
| ICON-DHASH | `71b119dcce576333` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_8f9d6582
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f9d6582e6d6a76c19fc20c24a499160f4ccd26955354599ee7ceef7404f418f"
    family = "unknown"
    file_name = "8f9d6582e6d6a76c19fc20c24a499160f4ccd26955354599ee7ceef7404f418f.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:16:13"
  condition:
    hash.sha256(0, filesize) == "8f9d6582e6d6a76c19fc20c24a499160f4ccd26955354599ee7ceef7404f418f"
}
```

### Sample 75: `7684d3b137509a92`

| Field | Value |
|---|---|
| SHA-256 | `7684d3b137509a92d4f9590cddaf3392cb9e67683a39463008f5e162e28ca9d9` |
| Family label | `unknown` |
| File name | `7684d3b137509a92d4f9590cddaf3392cb9e67683a39463008f5e162e28ca9d9.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:16:05` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b05e21b769e1fd15f3ec24290637fdb` |
| SHA-1 | `0f2b138006102d20dbad9fb475a47ab7a17a67af` |
| SHA-256 | `7684d3b137509a92d4f9590cddaf3392cb9e67683a39463008f5e162e28ca9d9` |
| SHA3-384 | `94112fb428fd28bca7f060960159a55d9dd47100656ff561a965afa83e782f849e5d932a872164b3d74d70ca4e299ffd` |
| IMPHASH | `f0d05c1dd5ba1ed096c85a04a8275fec` |
| TLSH | `T15F073379738499E5F5E3B536AE0380116A72BC200F51CAEF02D4AB557E371F42F36AA1` |
| SSDEEP | `393216:gVUnB5c02mfCS+aCuC9hHTodRGkXMk74V/Lg7Adgdo4:Dzc4aS+eCX0LhXMz/hgC` |
| ICON-DHASH | `aebc385c4ce0e8f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_7684d3b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7684d3b137509a92d4f9590cddaf3392cb9e67683a39463008f5e162e28ca9d9"
    family = "unknown"
    file_name = "7684d3b137509a92d4f9590cddaf3392cb9e67683a39463008f5e162e28ca9d9.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:16:05"
  condition:
    hash.sha256(0, filesize) == "7684d3b137509a92d4f9590cddaf3392cb9e67683a39463008f5e162e28ca9d9"
}
```

### Sample 76: `af0dd4cca95985ac`

| Field | Value |
|---|---|
| SHA-256 | `af0dd4cca95985acfeea79f51fd864d0219041b6121edd1bb1216ac156fec18e` |
| Family label | `CoinMiner` |
| File name | `f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:14:18` |
| Reporter | `abuse_ch` |
| Tags | `CoinMiner, exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19df15e87216a5caa96c6f9c4f584df5` |
| SHA-1 | `87e810df95e4ee3b64293ab661ea98ad7e266b49` |
| SHA-256 | `af0dd4cca95985acfeea79f51fd864d0219041b6121edd1bb1216ac156fec18e` |
| SHA3-384 | `3c743378f11c023e12b54ce85bebce9eb19023ac18ce61edfa8bae350ccc8afdcfb5b60afc02c7406d8913713972c6b7` |
| IMPHASH | `32bc57b45a7a4c3a8a03b803d14864f0` |
| TLSH | `T1E7A43B4BFA6510E5D4BBC038C543251AFE7178A64334A7CB57989A671F23BE4AE3DB00` |
| SSDEEP | `6144:uL+JZmxy7ehwxQG5iPwadUXYQ25mdpqDBeNBd+JrYmSlB:sqZms7ehSqa25mdpquP+y9lB` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_076_af0dd4cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af0dd4cca95985acfeea79f51fd864d0219041b6121edd1bb1216ac156fec18e"
    family = "CoinMiner"
    file_name = "f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:14:18"
  condition:
    hash.sha256(0, filesize) == "af0dd4cca95985acfeea79f51fd864d0219041b6121edd1bb1216ac156fec18e"
}
```

### Sample 77: `f16c65dedf8f35e5`

| Field | Value |
|---|---|
| SHA-256 | `f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446` |
| Family label | `CoinMiner` |
| File name | `f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:13:23` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a90ef879082096dd6ee10f1bbb95de6` |
| SHA-1 | `87d5379e13c8b73ddea7a4f99d234a0c27ce30c8` |
| SHA-256 | `f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446` |
| SHA3-384 | `3648ad562284b5f9c0b8c414d66a9620854600f12bd5f76e3c9239e78bd051c5dca8ad7937e7360c1fbfdd32d8801da5` |
| IMPHASH | `4be82721af9084f58885735e3dbeb458` |
| TLSH | `T16504123293280144D76BCE724996F9A40565B817207A859FB7CCB84D3F32FEAD973A43` |
| SSDEEP | `3072:KmETe1Fz1JssDuJqcATZEjkiCdDUVsucCI7BKZ7fQ4ZbvsSqLTgGm/3X1n:KmSe15Osc0e1Cu9c77Boxb6ol/3ln` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_077_f16c65de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446"
    family = "CoinMiner"
    file_name = "f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:13:23"
  condition:
    hash.sha256(0, filesize) == "f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446"
}
```

### Sample 78: `da4128aa5d006e05`

| Field | Value |
|---|---|
| SHA-256 | `da4128aa5d006e05c58f0d240c2d8e5fb02774b6acf314f1230059c7a3498724` |
| Family label | `unknown` |
| File name | `da4128aa5d006e05c58f0d240c2d8e5fb02774b6acf314f1230059c7a3498724.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:12:44` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb1b836f3a974d498be0c8814b5ad1f1` |
| SHA-1 | `02e4df7b238e9a2cd3f8e3751660e297a4c25426` |
| SHA-256 | `da4128aa5d006e05c58f0d240c2d8e5fb02774b6acf314f1230059c7a3498724` |
| SHA3-384 | `3568fd56b0275e8163e18ff198c36d68d9fdfb5db39e869fcab0dedcf320f373b9333bfcd5bba08846ba447288ff27a0` |
| IMPHASH | `db1b93de154dee1a827b9e1481781dbd` |
| TLSH | `T10766332F5F4CBC87C8F15BB956504A86CB04AE758CEF9E2D349F5997C98820C07B628D` |
| SSDEEP | `98304:rhVDfkSejWPYkkjX6PVdG7+k16YLNjwECJ5I6VB+a51kdO57376Couqtd5DnqxTz:ffk1Mc1bCN+arv7vojVDnqA+9` |
| ICON-DHASH | `d48ceae4b0dad444` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_da4128aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da4128aa5d006e05c58f0d240c2d8e5fb02774b6acf314f1230059c7a3498724"
    family = "unknown"
    file_name = "da4128aa5d006e05c58f0d240c2d8e5fb02774b6acf314f1230059c7a3498724.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:12:44"
  condition:
    hash.sha256(0, filesize) == "da4128aa5d006e05c58f0d240c2d8e5fb02774b6acf314f1230059c7a3498724"
}
```

### Sample 79: `3f64b0146b323c57`

| Field | Value |
|---|---|
| SHA-256 | `3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0` |
| Family label | `Nitol` |
| File name | `3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:12:38` |
| Reporter | `Tuxxin` |
| Tags | `exe, Nitol` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3d08af95c2a2d086b4a776817b6f5b2` |
| SHA-1 | `2915848428eebd92156fa96797c165be8581d00f` |
| SHA-256 | `3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0` |
| SHA3-384 | `aa5ed57ea524ca452dec03b12da21f5364a00b435ba8f7049a088ae9496b128fbca283b803109092e592ebfe15af0a6d` |
| IMPHASH | `9b42918b4db03118c7d3c2b66b906ffc` |
| TLSH | `T18836332340517E42E95AC337B852E8C0C860F8769B4232B7B51F6981D2693DEEFF4B59` |
| SSDEEP | `98304:woehpAXzHlJnnH7Ptee6XUuxloGH2cwTIy+tuZj+p6m9SdIYI:wo1jrRJKUWGGH2zI7mxIYI` |

#### Technical Assessment

- The sample is tracked as `Nitol` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Nitol_079_3f64b014
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0"
    family = "Nitol"
    file_name = "3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:12:38"
  condition:
    hash.sha256(0, filesize) == "3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0"
}
```

### Sample 80: `2a23e10bfc097e98`

| Field | Value |
|---|---|
| SHA-256 | `2a23e10bfc097e98295cbff8124bd403c4cb677e709b48ccc53d6aca216c3061` |
| Family label | `unknown` |
| File name | `2a23e10bfc097e98295cbff8124bd403c4cb677e709b48ccc53d6aca216c3061.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:12:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aace3f86f4ca25bab44094ed74240e37` |
| SHA-1 | `630121d82cbd5b82c38bdf86f80cd6ba49dc3695` |
| SHA-256 | `2a23e10bfc097e98295cbff8124bd403c4cb677e709b48ccc53d6aca216c3061` |
| SHA3-384 | `77483818483cc8eea370e90bc991ab1c78de615d83cfae30fa6f280c421014a4833f45db4f8b9afa09a6299b9ba9e80a` |
| IMPHASH | `db1b93de154dee1a827b9e1481781dbd` |
| TLSH | `T1F36633A91CDEBCDBD0D663782CAE0103080397374DA745AD9B4FAFB6816511CCBF661A` |
| SSDEEP | `196608:fCno67YwQWU6TXKlD8s3WsIdARDt5gSw56K:f0ovjWU6e2smpWA0K` |
| ICON-DHASH | `d48ceae4b0dad444` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_2a23e10b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a23e10bfc097e98295cbff8124bd403c4cb677e709b48ccc53d6aca216c3061"
    family = "unknown"
    file_name = "2a23e10bfc097e98295cbff8124bd403c4cb677e709b48ccc53d6aca216c3061.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:12:32"
  condition:
    hash.sha256(0, filesize) == "2a23e10bfc097e98295cbff8124bd403c4cb677e709b48ccc53d6aca216c3061"
}
```

### Sample 81: `80024c8787c29cad`

| Field | Value |
|---|---|
| SHA-256 | `80024c8787c29cad1241ba6480cc45fb770c639524bddf308160fb121117158a` |
| Family label | `ConnectWise` |
| File name | `80024c8787c29cad1241ba6480cc45fb770c639524bddf308160fb121117158a.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:12:22` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac7d66c7221adf1fa5522a76bc96c3af` |
| SHA-1 | `5fc9c8c786ee2719f24fcf44f14276912acd73b1` |
| SHA-256 | `80024c8787c29cad1241ba6480cc45fb770c639524bddf308160fb121117158a` |
| SHA3-384 | `73ec6c962fb170811d9679088a64f0aa56357ad7acfea15510c5bc77c54c21523c77bf94c7d6d5a62446147e3ab6d8d2` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T137E62311B3F59675D1FB0638E87A93A15A35BC014B12C7AF6794792A2D337C08E323B6` |
| SSDEEP | `393216:MFri04SOL2X18Fri04SOLOFri04SOL/Fri04SOLTFri04SOLQ:MMrSOLseMrSOLOMrSOL/MrSOLTMrSOLQ` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_081_80024c87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80024c8787c29cad1241ba6480cc45fb770c639524bddf308160fb121117158a"
    family = "ConnectWise"
    file_name = "80024c8787c29cad1241ba6480cc45fb770c639524bddf308160fb121117158a.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:12:22"
  condition:
    hash.sha256(0, filesize) == "80024c8787c29cad1241ba6480cc45fb770c639524bddf308160fb121117158a"
}
```

### Sample 82: `b43866cec329650b`

| Field | Value |
|---|---|
| SHA-256 | `b43866cec329650bff964813ff8cebb93b50a537434ff7fc561a542891f74e8d` |
| Family label | `RustyStealer` |
| File name | `b43866cec329650bff964813ff8cebb93b50a537434ff7fc561a542891f74e8d.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:11:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c915802296a889a95aed8e3dcbba7379` |
| SHA-1 | `1d6c5fb09e2a2b96edf41c2aa5a75c41eeb6a435` |
| SHA-256 | `b43866cec329650bff964813ff8cebb93b50a537434ff7fc561a542891f74e8d` |
| SHA3-384 | `6ec100dd72b2d66771668c0902087e2d3bedb4d2d9ee2873626b4a89709067a8e7307c693d578a7130dfd932abe946b8` |
| IMPHASH | `2c983f29837c6e472d242fd4e45c5d82` |
| TLSH | `T107162363B12098F9E00BC0798716E6B7237A78890F26B9AF17D856253F75984BF3C605` |
| SSDEEP | `12288:Tfe/cHSHu7Jo3fDst0nXqroGo3BehcYWR7IXj3d8LvqUzLhf5AFIhPShM+X8iB4W:TmcH6uJ` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_082_b43866ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b43866cec329650bff964813ff8cebb93b50a537434ff7fc561a542891f74e8d"
    family = "RustyStealer"
    file_name = "b43866cec329650bff964813ff8cebb93b50a537434ff7fc561a542891f74e8d.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:11:13"
  condition:
    hash.sha256(0, filesize) == "b43866cec329650bff964813ff8cebb93b50a537434ff7fc561a542891f74e8d"
}
```

### Sample 83: `3fa5c736efc543db`

| Field | Value |
|---|---|
| SHA-256 | `3fa5c736efc543db373581f2e22addff05516fbc2b606fa04ff47488eae60f7e` |
| Family label | `unknown` |
| File name | `3fa5c736efc543db373581f2e22addff05516fbc2b606fa04ff47488eae60f7e.bin` |
| File type | `macho` |
| First seen | `2026-11-13 00:08:35` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bcc06464a66e5d76ff5fb5963f158ae` |
| SHA-1 | `35d9804fe024ddfe8e17a3cd055274fb223af6e7` |
| SHA-256 | `3fa5c736efc543db373581f2e22addff05516fbc2b606fa04ff47488eae60f7e` |
| SHA3-384 | `0a506e35f3494efdf2d0133b00f3c9290f58989ec98286fac1c9afd8be4ab4bd7f561f69ae6cfc12ceb76ae99b8984ac` |
| TLSH | `T1850517173379540ADC1A71387F926DB6FA20B5B66320E89B5E0B1210DFF50789B1A27F` |
| SSDEEP | `12288:ijp0QoUrfLPg7dMqUaAhooQeJbef8qfBmPunkT2P3C:8pkGtJSf8Lu1y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_3fa5c736
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa5c736efc543db373581f2e22addff05516fbc2b606fa04ff47488eae60f7e"
    family = "unknown"
    file_name = "3fa5c736efc543db373581f2e22addff05516fbc2b606fa04ff47488eae60f7e.bin"
    file_type = "macho"
    first_seen = "2026-11-13 00:08:35"
  condition:
    hash.sha256(0, filesize) == "3fa5c736efc543db373581f2e22addff05516fbc2b606fa04ff47488eae60f7e"
}
```

### Sample 84: `aa7d68624eb88508`

| Field | Value |
|---|---|
| SHA-256 | `aa7d68624eb88508703ed8bab98c99ee05f689b328debdfe2f1b3504976f5542` |
| Family label | `Mirai` |
| File name | `aa7d68624eb88508703ed8bab98c99ee05f689b328debdfe2f1b3504976f5542.elf` |
| File type | `elf` |
| First seen | `2026-11-13 00:08:26` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9fef1297539620673e61ac209c25f30` |
| SHA-1 | `2905f4b9787bbbb32f4a59bed6be8aea7c126d4c` |
| SHA-256 | `aa7d68624eb88508703ed8bab98c99ee05f689b328debdfe2f1b3504976f5542` |
| SHA3-384 | `136e6c0cbc3e59ec27e626ba59a715fec101239a8977c690c005c677a2127ed05140fb8d4287beebcd3b201821b635da` |
| TLSH | `T1F5A39D02CD746DACE03F6D7110B496BE8B13A580941A7EBB3856C2594057EC8F5AFBF4` |
| SSDEEP | `3072:9CRqKPXlnWnDQR3AgUhsjtTrf6Cb4wcZPxweEs:9CRqG1nWnDQ5AHsIQ43tTF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_aa7d6862
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa7d68624eb88508703ed8bab98c99ee05f689b328debdfe2f1b3504976f5542"
    family = "Mirai"
    file_name = "aa7d68624eb88508703ed8bab98c99ee05f689b328debdfe2f1b3504976f5542.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:08:26"
  condition:
    hash.sha256(0, filesize) == "aa7d68624eb88508703ed8bab98c99ee05f689b328debdfe2f1b3504976f5542"
}
```

### Sample 85: `8c0ca438c0809b37`

| Field | Value |
|---|---|
| SHA-256 | `8c0ca438c0809b37c717a8eb6c3d565b4147bf4ea97c05df6989909a798c9ef3` |
| Family label | `Mirai` |
| File name | `8c0ca438c0809b37c717a8eb6c3d565b4147bf4ea97c05df6989909a798c9ef3.elf` |
| File type | `elf` |
| First seen | `2026-11-13 00:08:20` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3512bfa90cb91b1d3a515456df12b684` |
| SHA-1 | `0708a89a9a1914336802c4d2c60d2e2e17ccdd15` |
| SHA-256 | `8c0ca438c0809b37c717a8eb6c3d565b4147bf4ea97c05df6989909a798c9ef3` |
| SHA3-384 | `1b46a8eb7b48b6cd982437bd8c9f3aeaeda15ece7c2613268b05bba279c55e85e08d2d580a6fc79f33784b1478f540a4` |
| TLSH | `T1C5E3080ABFB25EFBD46FCE3345BA4705299C095622B42B3A2570D81CF65B18F1AD3C64` |
| SSDEEP | `1536:MRS49IY/BmxA59zfu9HEU14iPxrfQteoffdwb88DT5fMoO95aqyhAexKpKNIKt6e:MRZjSEU14i1fH1HEqA7uvR95Ihx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_8c0ca438
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c0ca438c0809b37c717a8eb6c3d565b4147bf4ea97c05df6989909a798c9ef3"
    family = "Mirai"
    file_name = "8c0ca438c0809b37c717a8eb6c3d565b4147bf4ea97c05df6989909a798c9ef3.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:08:20"
  condition:
    hash.sha256(0, filesize) == "8c0ca438c0809b37c717a8eb6c3d565b4147bf4ea97c05df6989909a798c9ef3"
}
```

### Sample 86: `b834bc2a2c14ad7a`

| Field | Value |
|---|---|
| SHA-256 | `b834bc2a2c14ad7ae30043fcb1f53a78f7cc069bb93c7e903006eb183c446222` |
| Family label | `AgentTesla` |
| File name | `b834bc2a2c14ad7ae30043fcb1f53a78f7cc069bb93c7e903006eb183c446222.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:07:27` |
| Reporter | `Tuxxin` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6659c9df4bd93d524830ce4cef41d49` |
| SHA-1 | `6d2ce3be9c820104f96bbd1aa3e08e7f268efefc` |
| SHA-256 | `b834bc2a2c14ad7ae30043fcb1f53a78f7cc069bb93c7e903006eb183c446222` |
| SHA3-384 | `9ce305f5ecf3ed07eff7071acc87bae54a68c4a8f2a8d72b2605b2b9d18a325e4b7dbf413e3feb4b8ae879e234271fd4` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17DD53B147ED4EB27C16BCE33D5E25011E3F1E5532AB1EB0E66D397A8184234678863AF` |
| SSDEEP | `49152:vuKw6ZkAIKyo+HgbY8DkRmaZ8V7Fy1tb1Rm:vtw6KA7yB4Ob3m` |
| ICON-DHASH | `660e6a66d62e2b12` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_086_b834bc2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b834bc2a2c14ad7ae30043fcb1f53a78f7cc069bb93c7e903006eb183c446222"
    family = "AgentTesla"
    file_name = "b834bc2a2c14ad7ae30043fcb1f53a78f7cc069bb93c7e903006eb183c446222.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:07:27"
  condition:
    hash.sha256(0, filesize) == "b834bc2a2c14ad7ae30043fcb1f53a78f7cc069bb93c7e903006eb183c446222"
}
```

### Sample 87: `7cd2a351bf0f2cb3`

| Field | Value |
|---|---|
| SHA-256 | `7cd2a351bf0f2cb30a144a98c8e903582b83d4ef5116786fb766e221a5d697c2` |
| Family label | `WARDENStealer` |
| File name | `7cd2a351bf0f2cb30a144a98c8e903582b83d4ef5116786fb766e221a5d697c2.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:07:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bd65e86f2bbf31f672b89d4d6d27cd7` |
| SHA-1 | `324f21229ff3fb704abbb5e3cf412ae4712382e2` |
| SHA-256 | `7cd2a351bf0f2cb30a144a98c8e903582b83d4ef5116786fb766e221a5d697c2` |
| SHA3-384 | `fde62d9179c310a91490ca35a5d99b39e5e6ee2a4dbd305a20021e7867d1e44dd5391899fc0db09d69825629f54df7e3` |
| IMPHASH | `82749593e685eee5200e0e053340b187` |
| TLSH | `T18D05F1A1FA501BE5E93DC6348A9A9A2995723C121F2168FF53E0138F0F32BD19F37615` |
| SSDEEP | `24576:1eKMGhkUjYp4DyoZTtmWrjsTIl54sqQmZzKz:cQIpc5ZT3j1e5` |
| ICON-DHASH | `6068626169692004` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_087_7cd2a351
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cd2a351bf0f2cb30a144a98c8e903582b83d4ef5116786fb766e221a5d697c2"
    family = "WARDENStealer"
    file_name = "7cd2a351bf0f2cb30a144a98c8e903582b83d4ef5116786fb766e221a5d697c2.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:07:18"
  condition:
    hash.sha256(0, filesize) == "7cd2a351bf0f2cb30a144a98c8e903582b83d4ef5116786fb766e221a5d697c2"
}
```

### Sample 88: `d7fa54fc22418134`

| Field | Value |
|---|---|
| SHA-256 | `d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066` |
| Family label | `RevStealer` |
| File name | `d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:02:21` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d8b9c21d51ad17ada6895888149bd1f` |
| SHA-1 | `709cb6d34c394171c26e5f5d7625f4ffffeb327b` |
| SHA-256 | `d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066` |
| SHA3-384 | `35b95528e64dbcf6f4e0a9c010ce4b0f9ec0df4994b1a08e77d784e2b5005f12faa55386144403fde5b13fdee872d296` |
| IMPHASH | `3b33063fa6540cfc510bd20fcc99cc96` |
| TLSH | `T1B5E52389FC827976F433C3A38383716DB56D37458A704D5EB6CA6B601C62928AD37339` |
| SSDEEP | `49152:U55jo36EQ2dRDPe81Lx1r7wGk5IfBlH+TFGcwaicZ3740maGCYK/mXrCU9AOWhB8:6nUPeO1pyIfBqFHwaicZ37ACv/mbyzQ` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_088_d7fa54fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066"
    family = "RevStealer"
    file_name = "d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:02:21"
  condition:
    hash.sha256(0, filesize) == "d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066"
}
```

### Sample 89: `d1f1e7613b9d6e10`

| Field | Value |
|---|---|
| SHA-256 | `d1f1e7613b9d6e10565cd9736fcfc5631f54291bfca49f011d402c5e394daa3e` |
| Family label | `RevStealer` |
| File name | `d1f1e7613b9d6e10565cd9736fcfc5631f54291bfca49f011d402c5e394daa3e.exe` |
| File type | `exe` |
| First seen | `2026-11-13 00:02:15` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3a074549733a9c587a8f96e2d679103` |
| SHA-1 | `c9d4331bc53e433c276ce7b6320c2bc9023110de` |
| SHA-256 | `d1f1e7613b9d6e10565cd9736fcfc5631f54291bfca49f011d402c5e394daa3e` |
| SHA3-384 | `d78b12cca783eebe9881bb379bbd855795b3aa16663175236ca004cf3d1b53b6b685da51f3fbacb40e6f808af80b2468` |
| IMPHASH | `5647fb939de4e6e2843458a387335597` |
| TLSH | `T1CCD523C9FDB326B6D836C7B59C87E86D7129779212B40E5636CC1B008E53A942C3A33D` |
| SSDEEP | `49152:hnI7JT1M2H8fRVacOBUNHZgpGJo78ZIT9fnjO9XO6K/wblFRgOzmPU0Lpa:9IQfRVdeUZx6nTNG+ReFR9zI` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_089_d1f1e761
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1f1e7613b9d6e10565cd9736fcfc5631f54291bfca49f011d402c5e394daa3e"
    family = "RevStealer"
    file_name = "d1f1e7613b9d6e10565cd9736fcfc5631f54291bfca49f011d402c5e394daa3e.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:02:15"
  condition:
    hash.sha256(0, filesize) == "d1f1e7613b9d6e10565cd9736fcfc5631f54291bfca49f011d402c5e394daa3e"
}
```

### Sample 90: `b57703e260720b7e`

| Field | Value |
|---|---|
| SHA-256 | `b57703e260720b7e628d7aaec16a6d88969bead14b01550ad74b4a2146527ad7` |
| Family label | `unknown` |
| File name | `launcher.exe` |
| File type | `exe` |
| First seen | `2026-11-12 23:57:27` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `623e98cb440f04e44a635acf90c6e68b` |
| SHA-1 | `971e0d7965b709345eb4c680f574b9ad56542367` |
| SHA-256 | `b57703e260720b7e628d7aaec16a6d88969bead14b01550ad74b4a2146527ad7` |
| SHA3-384 | `7f6e66df09255a88520443bfa2e10b30db95042e448cd4d62d8fbe7460eb2b9bd830eaba4982414423389f1de0b5fe05` |
| IMPHASH | `6c1a59be05edca4468df8bc4f3785f19` |
| TLSH | `T1EBD623DE949032E4D8D34980768E53CE75D0A56D84E89D2C3AD62C02AF31D6F3649EFB` |
| SSDEEP | `196608:Q9q/CRcuOzpwToXxuQuLLxyJQlfFJSaW2W9F2BjunaXg20NVN:sqTuO+6xp+yASaA9F2snXNVN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_b57703e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b57703e260720b7e628d7aaec16a6d88969bead14b01550ad74b4a2146527ad7"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:57:27"
  condition:
    hash.sha256(0, filesize) == "b57703e260720b7e628d7aaec16a6d88969bead14b01550ad74b4a2146527ad7"
}
```

### Sample 91: `c1eb38faaaa974aa`

| Field | Value |
|---|---|
| SHA-256 | `c1eb38faaaa974aace8962bd6c71b4d4e6c4781d6f3e19e167c77e6e063f1ce8` |
| Family label | `unknown` |
| File name | `launcher.exe` |
| File type | `exe` |
| First seen | `2026-11-12 23:57:04` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85094750b00331c6f202a4c804102605` |
| SHA-1 | `627dbb98ceb9fb0cc77264d3cb3d0bfbe4d90065` |
| SHA-256 | `c1eb38faaaa974aace8962bd6c71b4d4e6c4781d6f3e19e167c77e6e063f1ce8` |
| SHA3-384 | `b97c399c6ceb2ff63df9e5e08efd676c8deaccff17f498eb9be02db1fc8386b93b4b3e45d866bb776bc40df667f19a6c` |
| IMPHASH | `a26392cd3040dad01a42d698c8f313eb` |
| TLSH | `T130C6332C29DB5EB1DCD6EC3C20BFCC01D18696921FB52A97B7B7AB048F8583458D7612` |
| SSDEEP | `196608:KeDR8P3lx2B9tv93Lu0ZbS7f2wde7d0LSdbAzAGkV/DYA9Ym1KaBA8HUJN:ixQ9PJm7XOQS9UANT9Y+bBA8S` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_c1eb38fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1eb38faaaa974aace8962bd6c71b4d4e6c4781d6f3e19e167c77e6e063f1ce8"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:57:04"
  condition:
    hash.sha256(0, filesize) == "c1eb38faaaa974aace8962bd6c71b4d4e6c4781d6f3e19e167c77e6e063f1ce8"
}
```

### Sample 92: `b1580e6fd0af88d1`

| Field | Value |
|---|---|
| SHA-256 | `b1580e6fd0af88d13c3cc5927b94a898519de499bf33ea4a56e565b98ea503cd` |
| Family label | `RustyStealer` |
| File name | `glaicer.exe` |
| File type | `exe` |
| First seen | `2026-11-12 23:56:21` |
| Reporter | `abuse_ch` |
| Tags | `exe, RustyStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df67702f5dcd48a6a6ce6c5b3607ef85` |
| SHA-1 | `90ba00cd35a0de2e54ae3acc2ad01f09908de914` |
| SHA-256 | `b1580e6fd0af88d13c3cc5927b94a898519de499bf33ea4a56e565b98ea503cd` |
| SHA3-384 | `325fc154616437acc1a148fb9b4f20c4083970b30ba2961c12eb597361ec6b3ebcae89548f8649e92421f492e18ce055` |
| IMPHASH | `7818b3a165ec3e23ff242b125dc232c1` |
| TLSH | `T19C362313B2559DF9E647C0BC8212D073EA3338561B28F6EF17E829343E539D5BA38A51` |
| SSDEEP | `12288:Qfe/cHYrgXXLVzy4xioSrXj66xQO9YFXvOyE2rKc/7959XCDXiitT5RtXE4GXVmY:gmcHCI` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_092_b1580e6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1580e6fd0af88d13c3cc5927b94a898519de499bf33ea4a56e565b98ea503cd"
    family = "RustyStealer"
    file_name = "glaicer.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:56:21"
  condition:
    hash.sha256(0, filesize) == "b1580e6fd0af88d13c3cc5927b94a898519de499bf33ea4a56e565b98ea503cd"
}
```

### Sample 93: `f68ee515ed1a7de9`

| Field | Value |
|---|---|
| SHA-256 | `f68ee515ed1a7de93935c8b7024c1c79ab90b6c447a074c563b372f153928671` |
| Family label | `unknown` |
| File name | `launcher.exe` |
| File type | `exe` |
| First seen | `2026-11-12 23:56:14` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12f06cc11da67e2d936cf7914867ae8b` |
| SHA-1 | `6bcabae60c078416e264f7ee04563793e3459265` |
| SHA-256 | `f68ee515ed1a7de93935c8b7024c1c79ab90b6c447a074c563b372f153928671` |
| SHA3-384 | `212b67587b3ba095cdd95d183f176e1069889293aa3184207d7441b993d0eb5704720864692ca9fff831cb529c997058` |
| IMPHASH | `3e6b861c53e749521be0bd963192d68e` |
| TLSH | `T118D623DE949032E4D8D34980768E53CE75D0A56D84E89D2C3AD62C02AF31D6F3649EFB` |
| SSDEEP | `196608:s9U/CRcuOzpwToXxuQuLLxyJQlfFJSaW2wpF2BjunaXg20NVS:IUTuO+6xp+yASaepF2snXNVS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_f68ee515
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f68ee515ed1a7de93935c8b7024c1c79ab90b6c447a074c563b372f153928671"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:56:14"
  condition:
    hash.sha256(0, filesize) == "f68ee515ed1a7de93935c8b7024c1c79ab90b6c447a074c563b372f153928671"
}
```

### Sample 94: `b99825060eafdd66`

| Field | Value |
|---|---|
| SHA-256 | `b99825060eafdd661039eff03cbe4264662267265b01caecaf56e1991287d277` |
| Family label | `RustyStealer` |
| File name | `glaicer.exe` |
| File type | `exe` |
| First seen | `2026-11-12 23:56:05` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `065f122d5553341285e57667c555183a` |
| SHA-1 | `963ce8942f407386a39d1a6bb27918a0a1ac1d86` |
| SHA-256 | `b99825060eafdd661039eff03cbe4264662267265b01caecaf56e1991287d277` |
| SHA3-384 | `6f416dd3bacfa5af73aa5cedae3fca0f84e66b79cbf5aba405b89e5a12e4e7fb3c1eed55fd671ad9b2c2a17bffae2727` |
| IMPHASH | `94d60e2d3ae8f21d8466f53c009f1e00` |
| TLSH | `T15926335326689F35E74713FC50A1D019DA53363B395CBB593BEA38247AC394EA890CF2` |
| SSDEEP | `12288:FNgl9Jf6BCxJOwXXLVzy4xioSrXj66xQO9YFXvOyE2rKc/7959XCDXiitT5RtXEp:S90CxJO4` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_094_b9982506
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b99825060eafdd661039eff03cbe4264662267265b01caecaf56e1991287d277"
    family = "RustyStealer"
    file_name = "glaicer.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:56:05"
  condition:
    hash.sha256(0, filesize) == "b99825060eafdd661039eff03cbe4264662267265b01caecaf56e1991287d277"
}
```

### Sample 95: `22fa9659e5f5c5cd`

| Field | Value |
|---|---|
| SHA-256 | `22fa9659e5f5c5cd338432ac1b2b2b466faa341b9a845f98b50f99b36adacb2f` |
| Family label | `RustyStealer` |
| File name | `glaicer.exe` |
| File type | `exe` |
| First seen | `2026-11-12 23:55:44` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f53e58d7ad8bd8598badee95aa3d99e7` |
| SHA-1 | `ac04f081fbb0e0862580400f7b010d0b6cfd9480` |
| SHA-256 | `22fa9659e5f5c5cd338432ac1b2b2b466faa341b9a845f98b50f99b36adacb2f` |
| SHA3-384 | `aa8f10cd0a457150081f544595a177b104ff2621c83f3d22d1fe3f2e5822660bb89365a2cacf5cc3ff6b7605df5ea109` |
| IMPHASH | `2c983f29837c6e472d242fd4e45c5d82` |
| TLSH | `T12D362313B2559DF9E647C0B88212D073EB3338561B28F6EF17E829343E539D5BA34A61` |
| SSDEEP | `12288:ife/cHYB1mXXLVzy4xioSrXj66xQO9YFXvOyE2rKc/7959XCDXiitT5RtXE4GXVZ:6mcH61e` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_095_22fa9659
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22fa9659e5f5c5cd338432ac1b2b2b466faa341b9a845f98b50f99b36adacb2f"
    family = "RustyStealer"
    file_name = "glaicer.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:55:44"
  condition:
    hash.sha256(0, filesize) == "22fa9659e5f5c5cd338432ac1b2b2b466faa341b9a845f98b50f99b36adacb2f"
}
```

### Sample 96: `b07b17b3cf0ec6d9`

| Field | Value |
|---|---|
| SHA-256 | `b07b17b3cf0ec6d943e7af638c6f973240b87b7a25168c84eef54bc4a7c95680` |
| Family label | `WannaCry` |
| File name | `535a76d61f726e23fe5f93a8ecc3415b` |
| File type | `dll` |
| First seen | `2026-11-12 23:53:54` |
| Reporter | `malwareontap` |
| Tags | `dionaea, dll, honeypot, pe, WannaCry, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `535a76d61f726e23fe5f93a8ecc3415b` |
| SHA-1 | `02fd44ab6dbc48ae9914656b2074a9ba246db4f4` |
| SHA-256 | `b07b17b3cf0ec6d943e7af638c6f973240b87b7a25168c84eef54bc4a7c95680` |
| SHA3-384 | `c5ac7cbeacf31707869ee80e11fd4d37198894c8c9e01f3270b642bcef94d128a434480c90c13ddefaa94edc3a1356a0` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1A6363314B42952B8F0830DF004BBDA1BB7BA7C5557B596CF9B8046B60D62BC6AFB0743` |
| SSDEEP | `98304:TDqPoBhz1aRxcSUDk36SAEdhvxWa9P59Uc/EAVp2H:TDqPe1Cxcxk3ZAEUadvEc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_096_b07b17b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b07b17b3cf0ec6d943e7af638c6f973240b87b7a25168c84eef54bc4a7c95680"
    family = "WannaCry"
    file_name = "535a76d61f726e23fe5f93a8ecc3415b"
    file_type = "dll"
    first_seen = "2026-11-12 23:53:54"
  condition:
    hash.sha256(0, filesize) == "b07b17b3cf0ec6d943e7af638c6f973240b87b7a25168c84eef54bc4a7c95680"
}
```

### Sample 97: `e94e3854db4dd36c`

| Field | Value |
|---|---|
| SHA-256 | `e94e3854db4dd36cf8aa084136cdc99c2fb72591c8b4dd89aff786a6048b373d` |
| Family label | `Vidar` |
| File name | `gitlосitу64-v.9.111.exe` |
| File type | `exe` |
| First seen | `2026-11-12 23:52:50` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed, vidar, vidarstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba663e964d604085bea3910ccd14caa5` |
| SHA-1 | `5e8534af20a47bb76b5910b6c795a74525178de7` |
| SHA-256 | `e94e3854db4dd36cf8aa084136cdc99c2fb72591c8b4dd89aff786a6048b373d` |
| SHA3-384 | `75a45afed42ed666157d3f542d30c6d41cac1df04fd59c0bd9552e80c35f18fde3a6acaa3454145d49db0009288a5deb` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T16D265B03BAA50179E1EAE734A9F6554277617C0C5332B3D33A00A73C6EB27C5997A72C` |
| SSDEEP | `98304:UPktDk8X2yz6ICqrdI0Esnvtejf66n+Y2:+8X2yz6ICqrdI0EsnvterVn+Y2` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_097_e94e3854
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e94e3854db4dd36cf8aa084136cdc99c2fb72591c8b4dd89aff786a6048b373d"
    family = "Vidar"
    file_name = "gitlосitу64-v.9.111.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:52:50"
  condition:
    hash.sha256(0, filesize) == "e94e3854db4dd36cf8aa084136cdc99c2fb72591c8b4dd89aff786a6048b373d"
}
```

### Sample 98: `ffe87766f7ee26d5`

| Field | Value |
|---|---|
| SHA-256 | `ffe87766f7ee26d57508f630f54f79cfe65888e1e9825bf0aa1fba1e5cbc5437` |
| Family label | `WARDENStealer` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-12 23:50:21` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f7dbc120c4d0d4a8160e5965b536030` |
| SHA-1 | `1fb2d9d375f63de7ed6b1d3a792c0c6ce9653628` |
| SHA-256 | `ffe87766f7ee26d57508f630f54f79cfe65888e1e9825bf0aa1fba1e5cbc5437` |
| SHA3-384 | `f9dbb2b5239c00ebb7ca73570fe7229baf813e040a97890c90b4c06ac0e401922ebfc823808a3202f8b2bdae25c9fb62` |
| IMPHASH | `ddaec19a12ad38f4c1d7ae1dd5d23d9b` |
| TLSH | `T1B3F4F1A4F75129E9DA7C8774C65B5D89826238220F125CEF86D433960E337D0DB3AF26` |
| SSDEEP | `12288:wvImbooGxSYe+hoSvZhywvPuXnNi316Cf9zmQ1ndkfBvND7/JH:w39Y5HdUnNS16Y9lndkb7/l` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_098_ffe87766
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffe87766f7ee26d57508f630f54f79cfe65888e1e9825bf0aa1fba1e5cbc5437"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-12 23:50:21"
  condition:
    hash.sha256(0, filesize) == "ffe87766f7ee26d57508f630f54f79cfe65888e1e9825bf0aa1fba1e5cbc5437"
}
```

### Sample 99: `c266833d1ca0b41a`

| Field | Value |
|---|---|
| SHA-256 | `c266833d1ca0b41a8d455a13202b76a9fdc734ea556ced624f2b90d0ecd122f7` |
| Family label | `WARDENStealer` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-12 23:49:50` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, stealer, upx, Warden, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c246694dae0f87df93f503c9e136695` |
| SHA-1 | `05729277452b2e8d4d4b5648fec1777fc8ab3160` |
| SHA-256 | `c266833d1ca0b41a8d455a13202b76a9fdc734ea556ced624f2b90d0ecd122f7` |
| SHA3-384 | `094412bb77ab9ae734bbf25c2815431a7405382f992482b8b3365c09967a73ec80f6fee12adea5d37da765882cd149b4` |
| IMPHASH | `a426b2cbef1f0c4f54be9fd7fd5c4e53` |
| TLSH | `T139A42337475F2D32F17A6B32E63720F61983D974B901EF38982D3E9A61EA1E14360356` |
| SSDEEP | `6144:SxiGtGOGxc63ysFIOqwIpvN/aoDDyvozkObHcjRGG0CSnVMnGejla3Ydh:+cxcYJqPp1SoDYVObybSnVYZa4` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_099_c266833d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c266833d1ca0b41a8d455a13202b76a9fdc734ea556ced624f2b90d0ecd122f7"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-12 23:49:50"
  condition:
    hash.sha256(0, filesize) == "c266833d1ca0b41a8d455a13202b76a9fdc734ea556ced624f2b90d0ecd122f7"
}
```

### Sample 100: `ed48cec14bb71a10`

| Field | Value |
|---|---|
| SHA-256 | `ed48cec14bb71a10d08b0dcbcdf40b51d48a7b795963e3e05c969b229e6fdf83` |
| Family label | `WARDENStealer` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-12 23:49:29` |
| Reporter | `AmadeyHunter` |
| Tags | `DIVINEX, exe, stealer, Warden, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a99b4322292571142e7d75da2f4254ae` |
| SHA-1 | `a714de2a4ac7379f7f398b8ccb03761e43159c92` |
| SHA-256 | `ed48cec14bb71a10d08b0dcbcdf40b51d48a7b795963e3e05c969b229e6fdf83` |
| SHA3-384 | `4b96875f849972539af1407c9ba21cb855999c65fa7b59fc985d78a4d0f1ecb06e7ea84e16328fcf41c84740f473313c` |
| IMPHASH | `4792c6415b4a22c0095e01a4653c6096` |
| TLSH | `T1ADF4F1A4F75129E9DA7C8774C65B5D89826238220F125CEF86D433960E337D0DB3AF26` |
| SSDEEP | `12288:8vImbooGFSYe+hoSvZhywvPuXnNi3164f9zmQ1ndkfBvND7/JH:83JY5HdUnNS1629lndkb7/l` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_100_ed48cec1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed48cec14bb71a10d08b0dcbcdf40b51d48a7b795963e3e05c969b229e6fdf83"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-12 23:49:29"
  condition:
    hash.sha256(0, filesize) == "ed48cec14bb71a10d08b0dcbcdf40b51d48a7b795963e3e05c969b229e6fdf83"
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
 * Generated: 2026-11-13T06:55:51.813503+00:00
 */

rule MalwareBazaar_unknown_001_b97b08b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b97b08b19719bafde8bfc9c571b280352313c292fc055044eb2f8158df4d5b9f"
    family = "unknown"
    file_name = "modules.cache"
    file_type = "zip"
    first_seen = "2026-11-13 06:32:45"
  condition:
    hash.sha256(0, filesize) == "b97b08b19719bafde8bfc9c571b280352313c292fc055044eb2f8158df4d5b9f"
}

rule MalwareBazaar_GuLoader_002_79ad7957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79ad7957bee56165aa1b7f5a8e352918373c37ef830193deb47f002b03ef7b75"
    family = "GuLoader"
    file_name = "Afgringernes.vbs"
    file_type = "vbs"
    first_seen = "2026-11-13 06:05:01"
  condition:
    hash.sha256(0, filesize) == "79ad7957bee56165aa1b7f5a8e352918373c37ef830193deb47f002b03ef7b75"
}

rule MalwareBazaar_AgentTesla_003_6694a062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6694a062d8e52456c9a4b4d691109d7521edc25e8b8861f99a464fa346814713"
    family = "AgentTesla"
    file_name = "datos bancarios.js"
    file_type = "js"
    first_seen = "2026-11-13 05:57:33"
  condition:
    hash.sha256(0, filesize) == "6694a062d8e52456c9a4b4d691109d7521edc25e8b8861f99a464fa346814713"
}

rule MalwareBazaar_FormBook_004_47c4acbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47c4acbf6d15b61a12d3411c0caea69751c6e86ccc91c894619ed8dfe3ebcc8f"
    family = "FormBook"
    file_name = "DHL_AWB#6078538091.JS"
    file_type = "js"
    first_seen = "2026-11-13 05:57:11"
  condition:
    hash.sha256(0, filesize) == "47c4acbf6d15b61a12d3411c0caea69751c6e86ccc91c894619ed8dfe3ebcc8f"
}

rule MalwareBazaar_unknown_005_c59fae03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c59fae03348d1a48c1d0e4164284d06d44b13abc39fc76037d00e3b244ddafac"
    family = "unknown"
    file_name = "348277489244739494.js"
    file_type = "js"
    first_seen = "2026-11-13 05:56:54"
  condition:
    hash.sha256(0, filesize) == "c59fae03348d1a48c1d0e4164284d06d44b13abc39fc76037d00e3b244ddafac"
}

rule MalwareBazaar_unknown_006_29bc436d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29bc436d3e36f9910bb5eca219c3e2ef3c222a28f56d6dabef8f4f034e90b072"
    family = "unknown"
    file_name = "Fiyat teklifi isteği.js"
    file_type = "js"
    first_seen = "2026-11-13 05:56:30"
  condition:
    hash.sha256(0, filesize) == "29bc436d3e36f9910bb5eca219c3e2ef3c222a28f56d6dabef8f4f034e90b072"
}

rule MalwareBazaar_njrat_007_2057f65c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2057f65c6a9aee75b7c86ee73b61816a805a38581dfd18d229f6b5741fd9506b"
    family = "njrat"
    file_name = "25c1dca57b882d184f6a0c426ea06c62.exe"
    file_type = "exe"
    first_seen = "2026-11-13 05:45:06"
  condition:
    hash.sha256(0, filesize) == "2057f65c6a9aee75b7c86ee73b61816a805a38581dfd18d229f6b5741fd9506b"
}

rule MalwareBazaar_Mirai_008_692fe658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "692fe65847368bbc2598ddfb97abeabd13f788b1708908ccc57925f7af234c9e"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:31:05"
  condition:
    hash.sha256(0, filesize) == "692fe65847368bbc2598ddfb97abeabd13f788b1708908ccc57925f7af234c9e"
}

rule MalwareBazaar_Mirai_009_f2b96274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b96274eb91cbe17d11173d74baaeecd4d11f15e4afe670affce8e76b61c534"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:25:04"
  condition:
    hash.sha256(0, filesize) == "f2b96274eb91cbe17d11173d74baaeecd4d11f15e4afe670affce8e76b61c534"
}

rule MalwareBazaar_Mirai_010_250111c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "250111c343dc7cc001a2e2c80c5e96b8b3ace9f0341f31c0272f6e325a1d483a"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:22:05"
  condition:
    hash.sha256(0, filesize) == "250111c343dc7cc001a2e2c80c5e96b8b3ace9f0341f31c0272f6e325a1d483a"
}

rule MalwareBazaar_unknown_011_c1a75ab5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1a75ab5a565dc7e937656b65669ce39e417d26b68d5a5d583c1ead5463c0539"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:21:04"
  condition:
    hash.sha256(0, filesize) == "c1a75ab5a565dc7e937656b65669ce39e417d26b68d5a5d583c1ead5463c0539"
}

rule MalwareBazaar_Mirai_012_65ed7ba7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65ed7ba78dbb34a2a2ed47650b0b79ae3ebd3bd6910e3882414b99fafa155c4b"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:19:05"
  condition:
    hash.sha256(0, filesize) == "65ed7ba78dbb34a2a2ed47650b0b79ae3ebd3bd6910e3882414b99fafa155c4b"
}

rule MalwareBazaar_unknown_013_68ea1d7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68ea1d7b41b3c8a3c6c3e3b03f8cfafbb20470981a1674e6844679d91df7ae93"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:17:05"
  condition:
    hash.sha256(0, filesize) == "68ea1d7b41b3c8a3c6c3e3b03f8cfafbb20470981a1674e6844679d91df7ae93"
}

rule MalwareBazaar_WannaCry_014_69769ea6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69769ea6ce90420aa08968c589ee96f23a602bc8f9483b4a7af8dfe058cca460"
    family = "WannaCry"
    file_name = "69769ea6ce90420aa08968c589ee96f23a602bc8f9483b4a7af8dfe058cca460"
    file_type = "exe"
    first_seen = "2026-11-13 05:15:14"
  condition:
    hash.sha256(0, filesize) == "69769ea6ce90420aa08968c589ee96f23a602bc8f9483b4a7af8dfe058cca460"
}

rule MalwareBazaar_njrat_015_28ffea47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28ffea472ed7e2300fdde6d3f1074608dbe415d5d851834e96052f65dd0ca386"
    family = "njrat"
    file_name = "AF1669913E244DEEBB9496A33264741B.exe"
    file_type = "exe"
    first_seen = "2026-11-13 05:15:06"
  condition:
    hash.sha256(0, filesize) == "28ffea472ed7e2300fdde6d3f1074608dbe415d5d851834e96052f65dd0ca386"
}

rule MalwareBazaar_Mirai_016_8b806570
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b806570dd2eb0c8d71497fce40e4bdf5b85039a788cfdd9e1ae95a5b9bd788c"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:13:05"
  condition:
    hash.sha256(0, filesize) == "8b806570dd2eb0c8d71497fce40e4bdf5b85039a788cfdd9e1ae95a5b9bd788c"
}

rule MalwareBazaar_Mirai_017_a931b9e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a931b9e97f99c5597dcf862ee4015ff069c68c4e3981c965803e0af89c443628"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 05:11:05"
  condition:
    hash.sha256(0, filesize) == "a931b9e97f99c5597dcf862ee4015ff069c68c4e3981c965803e0af89c443628"
}

rule MalwareBazaar_Mirai_018_266d9692
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "266d96922afb1c69035a5045b90d664f4afcbbac4233b228d061b14ab28ab636"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-13 05:06:19"
  condition:
    hash.sha256(0, filesize) == "266d96922afb1c69035a5045b90d664f4afcbbac4233b228d061b14ab28ab636"
}

rule MalwareBazaar_Mirai_019_26892466
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "268924660854ff06f59245f765634c5ba991b8e035811e1e974a6655a75727e6"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-13 05:06:05"
  condition:
    hash.sha256(0, filesize) == "268924660854ff06f59245f765634c5ba991b8e035811e1e974a6655a75727e6"
}

rule MalwareBazaar_Mirai_020_ac88d3f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac88d3f113aa54d11f34703d0ae48a3a44a3cc061f8477055419a0aac0146854"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 04:54:05"
  condition:
    hash.sha256(0, filesize) == "ac88d3f113aa54d11f34703d0ae48a3a44a3cc061f8477055419a0aac0146854"
}

rule MalwareBazaar_unknown_021_72cf74a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72cf74a14f59789640f164bab0ab76992e194b0c962829b8bc52a5fb1212ce32"
    family = "unknown"
    file_name = "72cf74a14f597896.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 04:51:39"
  condition:
    hash.sha256(0, filesize) == "72cf74a14f59789640f164bab0ab76992e194b0c962829b8bc52a5fb1212ce32"
}

rule MalwareBazaar_njrat_022_b2550d2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2550d2c1b7b9a8d58e2b5a0171a175809e9deedde12fe4a58fc951861d55d84"
    family = "njrat"
    file_name = "8AFC276D54258CDE26AA5259A4D51729.exe"
    file_type = "exe"
    first_seen = "2026-11-13 04:45:06"
  condition:
    hash.sha256(0, filesize) == "b2550d2c1b7b9a8d58e2b5a0171a175809e9deedde12fe4a58fc951861d55d84"
}

rule MalwareBazaar_GuLoader_023_afd4e4e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afd4e4e8c20c13920b718aa6c417e005c5bf3648f1462d18faa29194b9dffa40"
    family = "GuLoader"
    file_name = "SHIPMENT DELIVERY- Booking AYN1343237.vbs"
    file_type = "vbs"
    first_seen = "2026-11-13 04:04:19"
  condition:
    hash.sha256(0, filesize) == "afd4e4e8c20c13920b718aa6c417e005c5bf3648f1462d18faa29194b9dffa40"
}

rule MalwareBazaar_RustyStealer_024_7232d779
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7232d7791ac683102556cd203e4613dbbc606a32a7bd6ed6808e171afe81c96c"
    family = "RustyStealer"
    file_name = "Release.exe.exe"
    file_type = "exe"
    first_seen = "2026-11-13 03:38:55"
  condition:
    hash.sha256(0, filesize) == "7232d7791ac683102556cd203e4613dbbc606a32a7bd6ed6808e171afe81c96c"
}

rule MalwareBazaar_Mirai_025_ab7a7a88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab7a7a88a90d3c26df5be69a41d7bb9251defae4a057cf2d23bb9dbc22ec4c62"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-13 03:35:26"
  condition:
    hash.sha256(0, filesize) == "ab7a7a88a90d3c26df5be69a41d7bb9251defae4a057cf2d23bb9dbc22ec4c62"
}

rule MalwareBazaar_Mirai_026_2ca14ca2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ca14ca257abab463641f49b757c8fdf322d32930d3acecfa2e3fb681b19ec3c"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-11-13 03:35:23"
  condition:
    hash.sha256(0, filesize) == "2ca14ca257abab463641f49b757c8fdf322d32930d3acecfa2e3fb681b19ec3c"
}

rule MalwareBazaar_unknown_027_2bf1aaa1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bf1aaa147e4d77e8e6d2268b011e7557d14f461d9e92c8c5700fe6021633fd1"
    family = "unknown"
    file_name = "2bf1aaa147e4d77e.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 03:26:44"
  condition:
    hash.sha256(0, filesize) == "2bf1aaa147e4d77e8e6d2268b011e7557d14f461d9e92c8c5700fe6021633fd1"
}

rule MalwareBazaar_unknown_028_851653f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "851653f6c0196701e61a9a684cbb0bb427f169e0d16e7d80f5ccc7a8feeaca1e"
    family = "unknown"
    file_name = "ZolacanCraft.zip"
    file_type = "zip"
    first_seen = "2026-11-13 02:38:05"
  condition:
    hash.sha256(0, filesize) == "851653f6c0196701e61a9a684cbb0bb427f169e0d16e7d80f5ccc7a8feeaca1e"
}

rule MalwareBazaar_RustyStealer_029_2fb07d96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fb07d96121058a0a1d7d28a950e95246ed82f9d19cd0b112ae43c401aace8b0"
    family = "RustyStealer"
    file_name = "2fb07d96121058a0.bin"
    file_type = "exe"
    first_seen = "2026-11-13 02:26:17"
  condition:
    hash.sha256(0, filesize) == "2fb07d96121058a0a1d7d28a950e95246ed82f9d19cd0b112ae43c401aace8b0"
}

rule MalwareBazaar_Mirai_030_1eaba93e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eaba93e79031f4402debb37e18cac5959a579e20d281566ce4df124c608b2fc"
    family = "Mirai"
    file_name = "1eaba93e79031f44.bin"
    file_type = "elf"
    first_seen = "2026-11-13 02:26:07"
  condition:
    hash.sha256(0, filesize) == "1eaba93e79031f4402debb37e18cac5959a579e20d281566ce4df124c608b2fc"
}

rule MalwareBazaar_unknown_031_1677cd1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1677cd1d51eac543fe942e20a4a39eab1ac10b985dacad5f5246b6a3bea4b8e4"
    family = "unknown"
    file_name = "1677cd1d51eac543.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 02:01:39"
  condition:
    hash.sha256(0, filesize) == "1677cd1d51eac543fe942e20a4a39eab1ac10b985dacad5f5246b6a3bea4b8e4"
}

rule MalwareBazaar_unknown_032_afcb1878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afcb187858135123cc4bf27c0d1923ee08716c0a3f7ee3c3f94a9b6c75dc1dfa"
    family = "unknown"
    file_name = "afcb187858135123.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 01:57:01"
  condition:
    hash.sha256(0, filesize) == "afcb187858135123cc4bf27c0d1923ee08716c0a3f7ee3c3f94a9b6c75dc1dfa"
}

rule MalwareBazaar_unknown_033_d4536163
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d45361634083c162b50eca92a50e0410c538e31f51508b74f047415ab8ebb9e1"
    family = "unknown"
    file_name = "50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b.exe"
    file_type = "exe"
    first_seen = "2026-11-13 01:53:13"
  condition:
    hash.sha256(0, filesize) == "d45361634083c162b50eca92a50e0410c538e31f51508b74f047415ab8ebb9e1"
}

rule MalwareBazaar_unknown_034_50774628
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b"
    family = "unknown"
    file_name = "50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b.exe"
    file_type = "exe"
    first_seen = "2026-11-13 01:52:29"
  condition:
    hash.sha256(0, filesize) == "50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b"
}

rule MalwareBazaar_unknown_035_9c9baabd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c9baabdd7b08ca2f9e76be7987780dcb25d0ae45dc2d5f1962fd5ca8e42c129"
    family = "unknown"
    file_name = "9c9baabdd7b08ca2.msi"
    file_type = "msi"
    first_seen = "2026-11-13 01:40:11"
  condition:
    hash.sha256(0, filesize) == "9c9baabdd7b08ca2f9e76be7987780dcb25d0ae45dc2d5f1962fd5ca8e42c129"
}

rule MalwareBazaar_unknown_036_944bfe82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "944bfe82b949fcb067d4aa0463af94a13cfd7c97dfdd8ae8d9ff5ebcebaa22f2"
    family = "unknown"
    file_name = "944bfe82b949fcb0.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 01:36:38"
  condition:
    hash.sha256(0, filesize) == "944bfe82b949fcb067d4aa0463af94a13cfd7c97dfdd8ae8d9ff5ebcebaa22f2"
}

rule MalwareBazaar_unknown_037_f61e9548
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f61e9548ea915f7d052b1b929bb5ddf597a3fd93ee208b14b0e03553b98f7583"
    family = "unknown"
    file_name = "f61e9548ea915f7d052b1b929bb5ddf597a3fd93ee208b14b0e03553b98f7583.bin"
    file_type = "sh"
    first_seen = "2026-11-13 01:33:25"
  condition:
    hash.sha256(0, filesize) == "f61e9548ea915f7d052b1b929bb5ddf597a3fd93ee208b14b0e03553b98f7583"
}

rule MalwareBazaar_unknown_038_299ae99b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "299ae99b84de74b70699d7bb6b946b5f550153288c3fcb854459008ef926b8df"
    family = "unknown"
    file_name = "299ae99b84de74b7.apk"
    file_type = "apk"
    first_seen = "2026-11-13 01:30:08"
  condition:
    hash.sha256(0, filesize) == "299ae99b84de74b70699d7bb6b946b5f550153288c3fcb854459008ef926b8df"
}

rule MalwareBazaar_GuLoader_039_4fede1be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fede1be1261e93eac85fbf92813548279ff1ba58bf831b22e9c4e088d292f5c"
    family = "GuLoader"
    file_name = "Tabelsatsen.vbs"
    file_type = "vbs"
    first_seen = "2026-11-13 01:25:07"
  condition:
    hash.sha256(0, filesize) == "4fede1be1261e93eac85fbf92813548279ff1ba58bf831b22e9c4e088d292f5c"
}

rule MalwareBazaar_unknown_040_520c9ba8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "520c9ba8bd33902ee505fc335e403e1595e9c084a80f4fca755fe4edc54b6ab4"
    family = "unknown"
    file_name = "520c9ba8bd33902e.ps1"
    file_type = "ps1"
    first_seen = "2026-11-13 01:12:07"
  condition:
    hash.sha256(0, filesize) == "520c9ba8bd33902ee505fc335e403e1595e9c084a80f4fca755fe4edc54b6ab4"
}

rule MalwareBazaar_Mirai_041_13bbd78a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13bbd78a44da51ed393884aa3cec179ea10f519a36e43e981523a3784d276725"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 01:04:05"
  condition:
    hash.sha256(0, filesize) == "13bbd78a44da51ed393884aa3cec179ea10f519a36e43e981523a3784d276725"
}

rule MalwareBazaar_Meterpreter_042_77682550
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77682550aefde97b1fb4e6fdf5127d2bbd54ac00be2360b738dc4be82e745b55"
    family = "Meterpreter"
    file_name = "77682550aefde97b1fb4e6fdf5127d2bbd54ac00be2360b738dc4be82e745b55.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:56:44"
  condition:
    hash.sha256(0, filesize) == "77682550aefde97b1fb4e6fdf5127d2bbd54ac00be2360b738dc4be82e745b55"
}

rule MalwareBazaar_unknown_043_ae3401fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae3401fa05cc4e3c6ac68e79c5a82a7cdc1e9de7d69309d8256aa2d544564825"
    family = "unknown"
    file_name = "ae3401fa05cc4e3c6ac68e79c5a82a7cdc1e9de7d69309d8256aa2d544564825.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:53:45"
  condition:
    hash.sha256(0, filesize) == "ae3401fa05cc4e3c6ac68e79c5a82a7cdc1e9de7d69309d8256aa2d544564825"
}

rule MalwareBazaar_unknown_044_c2550d82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2550d821b1f29ed3196ebdaf9ddfa9ab49fe3200e85c5ff7e2c1edf9130b2a9"
    family = "unknown"
    file_name = "c2550d821b1f29ed3196ebdaf9ddfa9ab49fe3200e85c5ff7e2c1edf9130b2a9.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:52:46"
  condition:
    hash.sha256(0, filesize) == "c2550d821b1f29ed3196ebdaf9ddfa9ab49fe3200e85c5ff7e2c1edf9130b2a9"
}

rule MalwareBazaar_Adware_360SafeBrowse_045_d99eb978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d99eb978d6c2a2a737a6ccf16441a46c83ae7fa0ab827720e957eda4f77dba18"
    family = "Adware.360SafeBrowse"
    file_name = "d99eb978d6c2a2a737a6ccf16441a46c83ae7fa0ab827720e957eda4f77dba18.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:48:45"
  condition:
    hash.sha256(0, filesize) == "d99eb978d6c2a2a737a6ccf16441a46c83ae7fa0ab827720e957eda4f77dba18"
}

rule MalwareBazaar_Adware_OfferCore_046_3c556cee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c556cee98201f2954c99668178b5f5d6be967c3ac2a1f4f2e6f10edff5b90ff"
    family = "Adware.OfferCore"
    file_name = "3c556cee98201f2954c99668178b5f5d6be967c3ac2a1f4f2e6f10edff5b90ff.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:46:03"
  condition:
    hash.sha256(0, filesize) == "3c556cee98201f2954c99668178b5f5d6be967c3ac2a1f4f2e6f10edff5b90ff"
}

rule MalwareBazaar_unknown_047_85a9c228
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85a9c228e57e4096458d611f25c7df639369abc31db06f141c5b87bb51859c6d"
    family = "unknown"
    file_name = "85a9c228e57e4096.js"
    file_type = "js"
    first_seen = "2026-11-13 00:36:41"
  condition:
    hash.sha256(0, filesize) == "85a9c228e57e4096458d611f25c7df639369abc31db06f141c5b87bb51859c6d"
}

rule MalwareBazaar_Mirai_048_7d8e2ed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d8e2ed973eccedea4a76edcdca0860b37dda12e27404da0520da32f0b74d937"
    family = "Mirai"
    file_name = "7d8e2ed973eccedea4a76edcdca0860b37dda12e27404da0520da32f0b74d937.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:36:08"
  condition:
    hash.sha256(0, filesize) == "7d8e2ed973eccedea4a76edcdca0860b37dda12e27404da0520da32f0b74d937"
}

rule MalwareBazaar_Mirai_049_bd402aa2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd402aa2ee74ee9c8f13d0250f0816b662a438de1df56480983628b2397eabc9"
    family = "Mirai"
    file_name = "bd402aa2ee74ee9c8f13d0250f0816b662a438de1df56480983628b2397eabc9.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:33:30"
  condition:
    hash.sha256(0, filesize) == "bd402aa2ee74ee9c8f13d0250f0816b662a438de1df56480983628b2397eabc9"
}

rule MalwareBazaar_Mirai_050_98244dad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98244dada836addb8910fdc27b155b97c4ba35c7d8e2098ed84f9df01ec0b7c6"
    family = "Mirai"
    file_name = "98244dada836addb8910fdc27b155b97c4ba35c7d8e2098ed84f9df01ec0b7c6.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:32:30"
  condition:
    hash.sha256(0, filesize) == "98244dada836addb8910fdc27b155b97c4ba35c7d8e2098ed84f9df01ec0b7c6"
}

rule MalwareBazaar_Mirai_051_f208e223
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f208e22323d690f516a92c8de55b319d1904f57bf06d58a6e2633e217a9995f0"
    family = "Mirai"
    file_name = "f208e22323d690f516a92c8de55b319d1904f57bf06d58a6e2633e217a9995f0.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:31:04"
  condition:
    hash.sha256(0, filesize) == "f208e22323d690f516a92c8de55b319d1904f57bf06d58a6e2633e217a9995f0"
}

rule MalwareBazaar_Mirai_052_b483560b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b483560be21a39860b6f1d14fdce20c58971b56c5877eee6992a8b7bc2c149b2"
    family = "Mirai"
    file_name = "b483560be21a39860b6f1d14fdce20c58971b56c5877eee6992a8b7bc2c149b2.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:28:34"
  condition:
    hash.sha256(0, filesize) == "b483560be21a39860b6f1d14fdce20c58971b56c5877eee6992a8b7bc2c149b2"
}

rule MalwareBazaar_Mirai_053_fa0d4f7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa0d4f7ee7b98832254aaac4ffbde039db206d61b6586cf054fced284233408f"
    family = "Mirai"
    file_name = "fa0d4f7ee7b98832254aaac4ffbde039db206d61b6586cf054fced284233408f.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:28:28"
  condition:
    hash.sha256(0, filesize) == "fa0d4f7ee7b98832254aaac4ffbde039db206d61b6586cf054fced284233408f"
}

rule MalwareBazaar_Mirai_054_2d1bf8db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d1bf8db3a4c31b7a9446a8d5335b5a25bf836b27c1143617aa833163cfd8595"
    family = "Mirai"
    file_name = "2d1bf8db3a4c31b7a9446a8d5335b5a25bf836b27c1143617aa833163cfd8595.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:27:30"
  condition:
    hash.sha256(0, filesize) == "2d1bf8db3a4c31b7a9446a8d5335b5a25bf836b27c1143617aa833163cfd8595"
}

rule MalwareBazaar_unknown_055_5c5ad559
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c5ad5591079d436119cddd217ce7248e15119a4fbb5e826d6cdf0f1cae06d93"
    family = "unknown"
    file_name = "5c5ad5591079d436.js"
    file_type = "js"
    first_seen = "2026-11-13 00:26:55"
  condition:
    hash.sha256(0, filesize) == "5c5ad5591079d436119cddd217ce7248e15119a4fbb5e826d6cdf0f1cae06d93"
}

rule MalwareBazaar_unknown_056_2fb33c9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fb33c9d4e10b8dcf773cf10994821d5d99401dbd0067ab05a34ff4fa72eb626"
    family = "unknown"
    file_name = "2fb33c9d4e10b8dc.js"
    file_type = "js"
    first_seen = "2026-11-13 00:26:49"
  condition:
    hash.sha256(0, filesize) == "2fb33c9d4e10b8dcf773cf10994821d5d99401dbd0067ab05a34ff4fa72eb626"
}

rule MalwareBazaar_WARDENStealer_057_81f44013
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81f44013765580486de77bead284d978da7f8c873873854c176873afc6f690ea"
    family = "WARDENStealer"
    file_name = "81f44013765580486de77bead284d978da7f8c873873854c176873afc6f690ea.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:26:06"
  condition:
    hash.sha256(0, filesize) == "81f44013765580486de77bead284d978da7f8c873873854c176873afc6f690ea"
}

rule MalwareBazaar_GuLoader_058_385d24ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "385d24abef98cb9d1c0a9e78090cac4da444becc638f312ff80fff400ae235fb"
    family = "GuLoader"
    file_name = "Stenstraum V.2413.vbs"
    file_type = "vbs"
    first_seen = "2026-11-13 00:23:53"
  condition:
    hash.sha256(0, filesize) == "385d24abef98cb9d1c0a9e78090cac4da444becc638f312ff80fff400ae235fb"
}

rule MalwareBazaar_ZeuS_059_3f61eca5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f61eca59a92f6737fe01a5ed5e2f184ebcc3a7720afc016e16727361dd36e08"
    family = "ZeuS"
    file_name = "3f61eca59a92f6737fe01a5ed5e2f184ebcc3a7720afc016e16727361dd36e08.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:23:31"
  condition:
    hash.sha256(0, filesize) == "3f61eca59a92f6737fe01a5ed5e2f184ebcc3a7720afc016e16727361dd36e08"
}

rule MalwareBazaar_Adware_OfferCore_060_fdae956f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdae956fecfd22448b0719e66d8ed669b5acf52dca4472e849d9f141d102fe6b"
    family = "Adware.OfferCore"
    file_name = "fdae956fecfd22448b0719e66d8ed669b5acf52dca4472e849d9f141d102fe6b.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:22:37"
  condition:
    hash.sha256(0, filesize) == "fdae956fecfd22448b0719e66d8ed669b5acf52dca4472e849d9f141d102fe6b"
}

rule MalwareBazaar_unknown_061_32f8f978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f8f9789dfd279e8faaf275f096f7ef8329b15efe0ce0f558064da906bd7cc5"
    family = "unknown"
    file_name = "32f8f9789dfd279e8faaf275f096f7ef8329b15efe0ce0f558064da906bd7cc5.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:22:31"
  condition:
    hash.sha256(0, filesize) == "32f8f9789dfd279e8faaf275f096f7ef8329b15efe0ce0f558064da906bd7cc5"
}

rule MalwareBazaar_SalatStealer_062_88e2d46a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88e2d46aec44dc1d4bddcee934b7345c1d9463d8ce02d3aa3f2413df65c72bef"
    family = "SalatStealer"
    file_name = "329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:22:22"
  condition:
    hash.sha256(0, filesize) == "88e2d46aec44dc1d4bddcee934b7345c1d9463d8ce02d3aa3f2413df65c72bef"
}

rule MalwareBazaar_SalatStealer_063_329a6bc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4"
    family = "SalatStealer"
    file_name = "329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:21:15"
  condition:
    hash.sha256(0, filesize) == "329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4"
}

rule MalwareBazaar_RevStealer_064_6ace5308
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ace5308f7dbbb74e690461a52045c5b976c811014f33216c9c95e229a571081"
    family = "RevStealer"
    file_name = "6ace5308f7dbbb74e690461a52045c5b976c811014f33216c9c95e229a571081.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:21:07"
  condition:
    hash.sha256(0, filesize) == "6ace5308f7dbbb74e690461a52045c5b976c811014f33216c9c95e229a571081"
}

rule MalwareBazaar_SnappyClient_065_d421ea33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d421ea33f2b56e665424dcb501dd4925fdf81307c94dc183a120886f6a978112"
    family = "SnappyClient"
    file_name = "d421ea33f2b56e665424dcb501dd4925fdf81307c94dc183a120886f6a978112.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:21:01"
  condition:
    hash.sha256(0, filesize) == "d421ea33f2b56e665424dcb501dd4925fdf81307c94dc183a120886f6a978112"
}

rule MalwareBazaar_CoinMiner_066_61fac349
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61fac349b03e9ff3163f1096351028991a45071654cbc60cd418e513e7f378c4"
    family = "CoinMiner"
    file_name = "20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:19:21"
  condition:
    hash.sha256(0, filesize) == "61fac349b03e9ff3163f1096351028991a45071654cbc60cd418e513e7f378c4"
}

rule MalwareBazaar_Adware_OfferCore_067_d22bd625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d22bd62514f9dfc0d6cf3c5f7ec87aa8e35d74fddde708b1e9187edd7a851e77"
    family = "Adware.OfferCore"
    file_name = "d22bd62514f9dfc0d6cf3c5f7ec87aa8e35d74fddde708b1e9187edd7a851e77.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:18:38"
  condition:
    hash.sha256(0, filesize) == "d22bd62514f9dfc0d6cf3c5f7ec87aa8e35d74fddde708b1e9187edd7a851e77"
}

rule MalwareBazaar_CoinMiner_068_20983573
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0"
    family = "CoinMiner"
    file_name = "20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:18:32"
  condition:
    hash.sha256(0, filesize) == "20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0"
}

rule MalwareBazaar_ConnectWise_069_b2292692
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b229269204e6db6613793c412437025e826e05c51022d05e0b98f07617bbfd8b"
    family = "ConnectWise"
    file_name = "b229269204e6db6613793c412437025e826e05c51022d05e0b98f07617bbfd8b.msi"
    file_type = "msi"
    first_seen = "2026-11-13 00:17:50"
  condition:
    hash.sha256(0, filesize) == "b229269204e6db6613793c412437025e826e05c51022d05e0b98f07617bbfd8b"
}

rule MalwareBazaar_ConnectWise_070_685e8598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "685e8598094f32f60fd2b4f37720b3e4d28ad643115f3714040e02271d1310f1"
    family = "ConnectWise"
    file_name = "685e8598094f32f60fd2b4f37720b3e4d28ad643115f3714040e02271d1310f1.msi"
    file_type = "msi"
    first_seen = "2026-11-13 00:17:43"
  condition:
    hash.sha256(0, filesize) == "685e8598094f32f60fd2b4f37720b3e4d28ad643115f3714040e02271d1310f1"
}

rule MalwareBazaar_ConnectWise_071_465fb11f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "465fb11f51863b34d21e1ad8943795813a7694b755a5eb109c816aa47d5ddc1f"
    family = "ConnectWise"
    file_name = "465fb11f51863b34d21e1ad8943795813a7694b755a5eb109c816aa47d5ddc1f.msi"
    file_type = "msi"
    first_seen = "2026-11-13 00:17:36"
  condition:
    hash.sha256(0, filesize) == "465fb11f51863b34d21e1ad8943795813a7694b755a5eb109c816aa47d5ddc1f"
}

rule MalwareBazaar_ConnectWise_072_d2413f9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2413f9b81a6785de7125066d8d2ea0caabd90863c5739487d199aa8cd41d405"
    family = "ConnectWise"
    file_name = "d2413f9b81a6785de7125066d8d2ea0caabd90863c5739487d199aa8cd41d405.msi"
    file_type = "msi"
    first_seen = "2026-11-13 00:17:30"
  condition:
    hash.sha256(0, filesize) == "d2413f9b81a6785de7125066d8d2ea0caabd90863c5739487d199aa8cd41d405"
}

rule MalwareBazaar_ConnectWise_073_91af9fb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91af9fb3cfdd4fb955b15d9b074c782a2100a5287765fbf3f75ec73486c3c815"
    family = "ConnectWise"
    file_name = "91af9fb3cfdd4fb955b15d9b074c782a2100a5287765fbf3f75ec73486c3c815.msi"
    file_type = "msi"
    first_seen = "2026-11-13 00:16:21"
  condition:
    hash.sha256(0, filesize) == "91af9fb3cfdd4fb955b15d9b074c782a2100a5287765fbf3f75ec73486c3c815"
}

rule MalwareBazaar_unknown_074_8f9d6582
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f9d6582e6d6a76c19fc20c24a499160f4ccd26955354599ee7ceef7404f418f"
    family = "unknown"
    file_name = "8f9d6582e6d6a76c19fc20c24a499160f4ccd26955354599ee7ceef7404f418f.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:16:13"
  condition:
    hash.sha256(0, filesize) == "8f9d6582e6d6a76c19fc20c24a499160f4ccd26955354599ee7ceef7404f418f"
}

rule MalwareBazaar_unknown_075_7684d3b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7684d3b137509a92d4f9590cddaf3392cb9e67683a39463008f5e162e28ca9d9"
    family = "unknown"
    file_name = "7684d3b137509a92d4f9590cddaf3392cb9e67683a39463008f5e162e28ca9d9.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:16:05"
  condition:
    hash.sha256(0, filesize) == "7684d3b137509a92d4f9590cddaf3392cb9e67683a39463008f5e162e28ca9d9"
}

rule MalwareBazaar_CoinMiner_076_af0dd4cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af0dd4cca95985acfeea79f51fd864d0219041b6121edd1bb1216ac156fec18e"
    family = "CoinMiner"
    file_name = "f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:14:18"
  condition:
    hash.sha256(0, filesize) == "af0dd4cca95985acfeea79f51fd864d0219041b6121edd1bb1216ac156fec18e"
}

rule MalwareBazaar_CoinMiner_077_f16c65de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446"
    family = "CoinMiner"
    file_name = "f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:13:23"
  condition:
    hash.sha256(0, filesize) == "f16c65dedf8f35e58716c488393555564f076a6407636b1d691dc6674b5f4446"
}

rule MalwareBazaar_unknown_078_da4128aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da4128aa5d006e05c58f0d240c2d8e5fb02774b6acf314f1230059c7a3498724"
    family = "unknown"
    file_name = "da4128aa5d006e05c58f0d240c2d8e5fb02774b6acf314f1230059c7a3498724.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:12:44"
  condition:
    hash.sha256(0, filesize) == "da4128aa5d006e05c58f0d240c2d8e5fb02774b6acf314f1230059c7a3498724"
}

rule MalwareBazaar_Nitol_079_3f64b014
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0"
    family = "Nitol"
    file_name = "3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:12:38"
  condition:
    hash.sha256(0, filesize) == "3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0"
}

rule MalwareBazaar_unknown_080_2a23e10b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a23e10bfc097e98295cbff8124bd403c4cb677e709b48ccc53d6aca216c3061"
    family = "unknown"
    file_name = "2a23e10bfc097e98295cbff8124bd403c4cb677e709b48ccc53d6aca216c3061.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:12:32"
  condition:
    hash.sha256(0, filesize) == "2a23e10bfc097e98295cbff8124bd403c4cb677e709b48ccc53d6aca216c3061"
}

rule MalwareBazaar_ConnectWise_081_80024c87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80024c8787c29cad1241ba6480cc45fb770c639524bddf308160fb121117158a"
    family = "ConnectWise"
    file_name = "80024c8787c29cad1241ba6480cc45fb770c639524bddf308160fb121117158a.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:12:22"
  condition:
    hash.sha256(0, filesize) == "80024c8787c29cad1241ba6480cc45fb770c639524bddf308160fb121117158a"
}

rule MalwareBazaar_RustyStealer_082_b43866ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b43866cec329650bff964813ff8cebb93b50a537434ff7fc561a542891f74e8d"
    family = "RustyStealer"
    file_name = "b43866cec329650bff964813ff8cebb93b50a537434ff7fc561a542891f74e8d.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:11:13"
  condition:
    hash.sha256(0, filesize) == "b43866cec329650bff964813ff8cebb93b50a537434ff7fc561a542891f74e8d"
}

rule MalwareBazaar_unknown_083_3fa5c736
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa5c736efc543db373581f2e22addff05516fbc2b606fa04ff47488eae60f7e"
    family = "unknown"
    file_name = "3fa5c736efc543db373581f2e22addff05516fbc2b606fa04ff47488eae60f7e.bin"
    file_type = "macho"
    first_seen = "2026-11-13 00:08:35"
  condition:
    hash.sha256(0, filesize) == "3fa5c736efc543db373581f2e22addff05516fbc2b606fa04ff47488eae60f7e"
}

rule MalwareBazaar_Mirai_084_aa7d6862
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa7d68624eb88508703ed8bab98c99ee05f689b328debdfe2f1b3504976f5542"
    family = "Mirai"
    file_name = "aa7d68624eb88508703ed8bab98c99ee05f689b328debdfe2f1b3504976f5542.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:08:26"
  condition:
    hash.sha256(0, filesize) == "aa7d68624eb88508703ed8bab98c99ee05f689b328debdfe2f1b3504976f5542"
}

rule MalwareBazaar_Mirai_085_8c0ca438
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c0ca438c0809b37c717a8eb6c3d565b4147bf4ea97c05df6989909a798c9ef3"
    family = "Mirai"
    file_name = "8c0ca438c0809b37c717a8eb6c3d565b4147bf4ea97c05df6989909a798c9ef3.elf"
    file_type = "elf"
    first_seen = "2026-11-13 00:08:20"
  condition:
    hash.sha256(0, filesize) == "8c0ca438c0809b37c717a8eb6c3d565b4147bf4ea97c05df6989909a798c9ef3"
}

rule MalwareBazaar_AgentTesla_086_b834bc2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b834bc2a2c14ad7ae30043fcb1f53a78f7cc069bb93c7e903006eb183c446222"
    family = "AgentTesla"
    file_name = "b834bc2a2c14ad7ae30043fcb1f53a78f7cc069bb93c7e903006eb183c446222.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:07:27"
  condition:
    hash.sha256(0, filesize) == "b834bc2a2c14ad7ae30043fcb1f53a78f7cc069bb93c7e903006eb183c446222"
}

rule MalwareBazaar_WARDENStealer_087_7cd2a351
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cd2a351bf0f2cb30a144a98c8e903582b83d4ef5116786fb766e221a5d697c2"
    family = "WARDENStealer"
    file_name = "7cd2a351bf0f2cb30a144a98c8e903582b83d4ef5116786fb766e221a5d697c2.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:07:18"
  condition:
    hash.sha256(0, filesize) == "7cd2a351bf0f2cb30a144a98c8e903582b83d4ef5116786fb766e221a5d697c2"
}

rule MalwareBazaar_RevStealer_088_d7fa54fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066"
    family = "RevStealer"
    file_name = "d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:02:21"
  condition:
    hash.sha256(0, filesize) == "d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066"
}

rule MalwareBazaar_RevStealer_089_d1f1e761
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1f1e7613b9d6e10565cd9736fcfc5631f54291bfca49f011d402c5e394daa3e"
    family = "RevStealer"
    file_name = "d1f1e7613b9d6e10565cd9736fcfc5631f54291bfca49f011d402c5e394daa3e.exe"
    file_type = "exe"
    first_seen = "2026-11-13 00:02:15"
  condition:
    hash.sha256(0, filesize) == "d1f1e7613b9d6e10565cd9736fcfc5631f54291bfca49f011d402c5e394daa3e"
}

rule MalwareBazaar_unknown_090_b57703e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b57703e260720b7e628d7aaec16a6d88969bead14b01550ad74b4a2146527ad7"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:57:27"
  condition:
    hash.sha256(0, filesize) == "b57703e260720b7e628d7aaec16a6d88969bead14b01550ad74b4a2146527ad7"
}

rule MalwareBazaar_unknown_091_c1eb38fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1eb38faaaa974aace8962bd6c71b4d4e6c4781d6f3e19e167c77e6e063f1ce8"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:57:04"
  condition:
    hash.sha256(0, filesize) == "c1eb38faaaa974aace8962bd6c71b4d4e6c4781d6f3e19e167c77e6e063f1ce8"
}

rule MalwareBazaar_RustyStealer_092_b1580e6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1580e6fd0af88d13c3cc5927b94a898519de499bf33ea4a56e565b98ea503cd"
    family = "RustyStealer"
    file_name = "glaicer.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:56:21"
  condition:
    hash.sha256(0, filesize) == "b1580e6fd0af88d13c3cc5927b94a898519de499bf33ea4a56e565b98ea503cd"
}

rule MalwareBazaar_unknown_093_f68ee515
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f68ee515ed1a7de93935c8b7024c1c79ab90b6c447a074c563b372f153928671"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:56:14"
  condition:
    hash.sha256(0, filesize) == "f68ee515ed1a7de93935c8b7024c1c79ab90b6c447a074c563b372f153928671"
}

rule MalwareBazaar_RustyStealer_094_b9982506
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b99825060eafdd661039eff03cbe4264662267265b01caecaf56e1991287d277"
    family = "RustyStealer"
    file_name = "glaicer.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:56:05"
  condition:
    hash.sha256(0, filesize) == "b99825060eafdd661039eff03cbe4264662267265b01caecaf56e1991287d277"
}

rule MalwareBazaar_RustyStealer_095_22fa9659
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22fa9659e5f5c5cd338432ac1b2b2b466faa341b9a845f98b50f99b36adacb2f"
    family = "RustyStealer"
    file_name = "glaicer.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:55:44"
  condition:
    hash.sha256(0, filesize) == "22fa9659e5f5c5cd338432ac1b2b2b466faa341b9a845f98b50f99b36adacb2f"
}

rule MalwareBazaar_WannaCry_096_b07b17b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b07b17b3cf0ec6d943e7af638c6f973240b87b7a25168c84eef54bc4a7c95680"
    family = "WannaCry"
    file_name = "535a76d61f726e23fe5f93a8ecc3415b"
    file_type = "dll"
    first_seen = "2026-11-12 23:53:54"
  condition:
    hash.sha256(0, filesize) == "b07b17b3cf0ec6d943e7af638c6f973240b87b7a25168c84eef54bc4a7c95680"
}

rule MalwareBazaar_Vidar_097_e94e3854
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e94e3854db4dd36cf8aa084136cdc99c2fb72591c8b4dd89aff786a6048b373d"
    family = "Vidar"
    file_name = "gitlосitу64-v.9.111.exe"
    file_type = "exe"
    first_seen = "2026-11-12 23:52:50"
  condition:
    hash.sha256(0, filesize) == "e94e3854db4dd36cf8aa084136cdc99c2fb72591c8b4dd89aff786a6048b373d"
}

rule MalwareBazaar_WARDENStealer_098_ffe87766
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffe87766f7ee26d57508f630f54f79cfe65888e1e9825bf0aa1fba1e5cbc5437"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-12 23:50:21"
  condition:
    hash.sha256(0, filesize) == "ffe87766f7ee26d57508f630f54f79cfe65888e1e9825bf0aa1fba1e5cbc5437"
}

rule MalwareBazaar_WARDENStealer_099_c266833d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c266833d1ca0b41a8d455a13202b76a9fdc734ea556ced624f2b90d0ecd122f7"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-12 23:49:50"
  condition:
    hash.sha256(0, filesize) == "c266833d1ca0b41a8d455a13202b76a9fdc734ea556ced624f2b90d0ecd122f7"
}

rule MalwareBazaar_WARDENStealer_100_ed48cec1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed48cec14bb71a10d08b0dcbcdf40b51d48a7b795963e3e05c969b229e6fdf83"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-12 23:49:29"
  condition:
    hash.sha256(0, filesize) == "ed48cec14bb71a10d08b0dcbcdf40b51d48a7b795963e3e05c969b229e6fdf83"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

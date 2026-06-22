# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-06-22

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 639 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 639 |
| Unique family labels | 11 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 47 |
| unknown | 38 |
| Vidar | 5 |
| GuLoader | 2 |
| NanoCore | 2 |
| WannaCry | 1 |
| Vjw0rm | 1 |
| Prometei | 1 |
| SalatStealer | 1 |
| Stealc | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 45 |
| exe | 22 |
| ps1 | 13 |
| sh | 7 |
| vbs | 3 |
| js | 2 |
| bat | 2 |
| zip | 2 |
| rar | 1 |
| unknown | 1 |

## Per-Sample Analysis

### Sample 1: `2b188dfd9fd2275f`

| Field | Value |
|---|---|
| SHA-256 | `2b188dfd9fd2275fc1da25e159ed1d4c765d03db073e72210043556ad2baf1e5` |
| Family label | `WannaCry` |
| File name | `2b188dfd9fd2275fc1da25e159ed1d4c765d03db073e72210043556ad2baf1e5` |
| File type | `exe` |
| First seen | `2026-06-22 05:15:13` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2c8937f009447ae8b2cd293ea28f5d1` |
| SHA-1 | `2f6edb119475b7a7b41b1186eedb3057efb96d04` |
| SHA-256 | `2b188dfd9fd2275fc1da25e159ed1d4c765d03db073e72210043556ad2baf1e5` |
| SHA3-384 | `75584c087a23e1638ea9d88fe62ba5a054e11d4d8fd5ee5b7c2b5cdcc05969a842b762ea7aa35a392dcdc23ac2ec866b` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1BC36F115B1E85A70E6F31EB2217B8B1047797E458967928E2760A04F1C33F5CDEB2F29` |
| SSDEEP | `49152:jnsnpEKUacBVQej/1INRx+TSqTdX1HkQo6SAA:DMpyfBhz1aRxcSUDk36SA` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_001_2b188dfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b188dfd9fd2275fc1da25e159ed1d4c765d03db073e72210043556ad2baf1e5"
    family = "WannaCry"
    file_name = "2b188dfd9fd2275fc1da25e159ed1d4c765d03db073e72210043556ad2baf1e5"
    file_type = "exe"
    first_seen = "2026-06-22 05:15:13"
  condition:
    hash.sha256(0, filesize) == "2b188dfd9fd2275fc1da25e159ed1d4c765d03db073e72210043556ad2baf1e5"
}
```

### Sample 2: `b26fb4df0dced524`

| Field | Value |
|---|---|
| SHA-256 | `b26fb4df0dced5245969f72924d7aa27de5e9c7c526365fd0545dca7bd79e5fa` |
| Family label | `Vjw0rm` |
| File name | `ePRzHXrdth.js` |
| File type | `js` |
| First seen | `2026-06-22 05:01:15` |
| Reporter | `BastianHein_` |
| Tags | `js, Vjw0rm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40ac4f5981a284239f2ebea2ed2584c1` |
| SHA-1 | `9da279b4fd55277b4bd2e81f34515717643c7d00` |
| SHA-256 | `b26fb4df0dced5245969f72924d7aa27de5e9c7c526365fd0545dca7bd79e5fa` |
| SHA3-384 | `b301646a643f88011cbbb4177a2b5832ae851069c559ac32717b6ca9a8785b0d6d9b36da97ba11869a1f03b159fcf71c` |
| TLSH | `T13842A5784C07E314C795E7C06E0B8A9A7E6E97635366604FB548E1C03BB0C98E15DBF8` |
| SSDEEP | `192:cbx96AfiuTeweFAJOFskwf94RCA2C73d5Yvq4i6vLdI9lUcOOIGr1EhUu:W9625TeweFAJ5kwf+0S73dbRn9RIGrmB` |

#### Technical Assessment

- The sample is tracked as `Vjw0rm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vjw0rm_002_b26fb4df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b26fb4df0dced5245969f72924d7aa27de5e9c7c526365fd0545dca7bd79e5fa"
    family = "Vjw0rm"
    file_name = "ePRzHXrdth.js"
    file_type = "js"
    first_seen = "2026-06-22 05:01:15"
  condition:
    hash.sha256(0, filesize) == "b26fb4df0dced5245969f72924d7aa27de5e9c7c526365fd0545dca7bd79e5fa"
}
```

### Sample 3: `89b0bae4decab7d7`

| Field | Value |
|---|---|
| SHA-256 | `89b0bae4decab7d725cc35fd6f7004eb1255980961449b1ef79db23091654643` |
| Family label | `unknown` |
| File name | `TT_Slip_SOA_Proforma Invoices.vbs` |
| File type | `vbs` |
| First seen | `2026-06-22 04:52:54` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f3ec0d0085e21427939cf1a2679ad05` |
| SHA-1 | `d19e87bdcdc396de338ef52d689b4cdfb8232ccf` |
| SHA-256 | `89b0bae4decab7d725cc35fd6f7004eb1255980961449b1ef79db23091654643` |
| SHA3-384 | `b291d5cf7ed9a7cdd13647e283f538f2496495b065109554fa4730b651ab6140f7962ef98600b43ef52e69fa51bb1466` |
| TLSH | `T107934A30DE9407990E4B1BAEFC951A61C5BCC619512200F4FEEA170D510AAECF7BE76D` |
| SSDEEP | `1536:WBA7qO5fqnFO40xIlnYSOndli/dKuDnQsF81mcfxGOTdddJUPP564G:WC7qO5SOjGQK/dKuDnBu1m2xGOTdhUPo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_89b0bae4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89b0bae4decab7d725cc35fd6f7004eb1255980961449b1ef79db23091654643"
    family = "unknown"
    file_name = "TT_Slip_SOA_Proforma Invoices.vbs"
    file_type = "vbs"
    first_seen = "2026-06-22 04:52:54"
  condition:
    hash.sha256(0, filesize) == "89b0bae4decab7d725cc35fd6f7004eb1255980961449b1ef79db23091654643"
}
```

### Sample 4: `dc1d0d968707d8f2`

| Field | Value |
|---|---|
| SHA-256 | `dc1d0d968707d8f28bc9e5d27f883ac5d6ac4ec49623dd02db79f6ea28062cf5` |
| Family label | `Mirai` |
| File name | `nerv.ppc` |
| File type | `elf` |
| First seen | `2026-06-22 04:47:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20402cfcd33cb67bb667334f3dee8bd3` |
| SHA-1 | `d92c3c091644960bbaf0f5cd35b76dd226bd8420` |
| SHA-256 | `dc1d0d968707d8f28bc9e5d27f883ac5d6ac4ec49623dd02db79f6ea28062cf5` |
| SHA3-384 | `6b8f5a253b295c7d09db020ca7be305aaef7e2b220d971ef274ccec555bab9cd12ad0526ad0744b515237173f2a80ab1` |
| TLSH | `T1A2B34C02731C0F47C5B75AB02D3F57E1A3FE999021F4BA89251EAB5692B1E361182FCD` |
| SSDEEP | `1536:bL8aGHx7rZazxJWsvNW/GHogtC4sr3L2LLOpHqDXz+bJ6ecKwgmkyRwPIeSZ:bKKNvjoUsWerb9BjAZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_dc1d0d96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc1d0d968707d8f28bc9e5d27f883ac5d6ac4ec49623dd02db79f6ea28062cf5"
    family = "Mirai"
    file_name = "nerv.ppc"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:31"
  condition:
    hash.sha256(0, filesize) == "dc1d0d968707d8f28bc9e5d27f883ac5d6ac4ec49623dd02db79f6ea28062cf5"
}
```

### Sample 5: `2ea382e20ccd7f19`

| Field | Value |
|---|---|
| SHA-256 | `2ea382e20ccd7f1909e432fecf9ce41594a3a49e9a1a692433a982d2a778312b` |
| Family label | `Mirai` |
| File name | `adb.sh` |
| File type | `sh` |
| First seen | `2026-06-22 04:47:29` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `837e17f7f0c271785f3cec21142334e2` |
| SHA-1 | `5632776e1f14abdeb2cf348e14fc5c47e3e224c7` |
| SHA-256 | `2ea382e20ccd7f1909e432fecf9ce41594a3a49e9a1a692433a982d2a778312b` |
| SHA3-384 | `50296f5edbffa76409fe1a5db8b4905e7fc69cfa143dc2770f071064cae288be1c30aa14ff807fb78e5eea6d8371c639` |
| TLSH | `T11C410BD6200107E64F1BCD68FEAA5CDD460E41EEB25B8675CBC0C829F85C6283CB5A86` |
| SSDEEP | `48:a7l1WcWh0GOlQVUR/Th/TG0vHV1EwkjrWxKZdFx3tnIEucsn:a7fWVh0GOlQVUR/l/awHV1E5jrWxKZd+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_2ea382e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ea382e20ccd7f1909e432fecf9ce41594a3a49e9a1a692433a982d2a778312b"
    family = "Mirai"
    file_name = "adb.sh"
    file_type = "sh"
    first_seen = "2026-06-22 04:47:29"
  condition:
    hash.sha256(0, filesize) == "2ea382e20ccd7f1909e432fecf9ce41594a3a49e9a1a692433a982d2a778312b"
}
```

### Sample 6: `f27a165f3cdcb6f7`

| Field | Value |
|---|---|
| SHA-256 | `f27a165f3cdcb6f72dceaf130398fa7f78b2a5c7e5a22cb14db5e8c5b4151cb9` |
| Family label | `Mirai` |
| File name | `nerv.mips` |
| File type | `elf` |
| First seen | `2026-06-22 04:47:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a71c0fdb99d6723b47f54f81cf5b3a4` |
| SHA-1 | `2b674e64329b508e29531403a5211db7bdef8ffa` |
| SHA-256 | `f27a165f3cdcb6f72dceaf130398fa7f78b2a5c7e5a22cb14db5e8c5b4151cb9` |
| SHA3-384 | `55349ac74e881abf6d23b651259b258d8532ff9f053c51d5c807dc5c2f42ffdae5e8a9b275d2ffd4ee79cd74d77985df` |
| TLSH | `T184D3E71E6E218FBDF769C33447B78E25A39873C622E1C641E17CD6115E6028E641FFA8` |
| TELFHASH | `t1022151584e7827e477365c89559dfb7bd2a130ef3b125c378e11a8aab76cc819e20c0c` |
| SSDEEP | `3072:z0SBJcnFwP9oYCz0iXC6dw9BaFZnugRQeAgs9:vJoFwP7Cz0iaiUz9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_f27a165f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f27a165f3cdcb6f72dceaf130398fa7f78b2a5c7e5a22cb14db5e8c5b4151cb9"
    family = "Mirai"
    file_name = "nerv.mips"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:28"
  condition:
    hash.sha256(0, filesize) == "f27a165f3cdcb6f72dceaf130398fa7f78b2a5c7e5a22cb14db5e8c5b4151cb9"
}
```

### Sample 7: `c7d5e21a01ce8ab4`

| Field | Value |
|---|---|
| SHA-256 | `c7d5e21a01ce8ab4083c588d8050b286d375eeb88f41fe68b22ca02cf1bb8f8a` |
| Family label | `Mirai` |
| File name | `nerv.arm6` |
| File type | `elf` |
| First seen | `2026-06-22 04:47:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a5e7aefd7fb06de1567879d3244d917` |
| SHA-1 | `0cf1ff8eef7876143ffd7b5a4a3ed83724bac64b` |
| SHA-256 | `c7d5e21a01ce8ab4083c588d8050b286d375eeb88f41fe68b22ca02cf1bb8f8a` |
| SHA3-384 | `8373ac74bd87f1396e3f5a08cff33c0440e34f7a13ce089262a7bbe942d31b7ab24c1f0c28859f8ab5f8b3a8aa728222` |
| TLSH | `T120B32A86AC814A11C5D613BFFA2E118D3313277CE3DE72129D205F2477CA96B0E7BA56` |
| TELFHASH | `t1bdf08bd4a085318cabd51a95d5adb69114e638f83f4a1cc2ab8e5a4e13484f1b834c3f` |
| SSDEEP | `3072:RfxGIfE1qVXbO4bnOfGZKuafrfLcTVLao66XmfeaMFM6xu9:SIfvlDDOeZKuazLcTpaPImgMmE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_c7d5e21a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7d5e21a01ce8ab4083c588d8050b286d375eeb88f41fe68b22ca02cf1bb8f8a"
    family = "Mirai"
    file_name = "nerv.arm6"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:27"
  condition:
    hash.sha256(0, filesize) == "c7d5e21a01ce8ab4083c588d8050b286d375eeb88f41fe68b22ca02cf1bb8f8a"
}
```

### Sample 8: `2522ea59162e569a`

| Field | Value |
|---|---|
| SHA-256 | `2522ea59162e569aa18244b99521f597f0bd5082c767b80c6cf09d0dd3c8b9a5` |
| Family label | `Mirai` |
| File name | `nerv.x86` |
| File type | `elf` |
| First seen | `2026-06-22 04:47:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad7cfa5a1beeacb45f477ffa33b92051` |
| SHA-1 | `6da100e1fc45cdddb2953d98b7b7941e9b52436c` |
| SHA-256 | `2522ea59162e569aa18244b99521f597f0bd5082c767b80c6cf09d0dd3c8b9a5` |
| SHA3-384 | `8d672b6bce98196e1cac8c8cd2866b3066692317a83086c503212a88532955cfd0ca92a2eb1a19f04c37986c28252e9c` |
| TLSH | `T156935BC1E653E8F5ED1705751133E33B4B37F539102DD697DBA8AA32BCA2A00D5262AC` |
| TELFHASH | `t196410cfa197f0cd897d4a802d20e2f31798eab3b656073e206f3b5753067501517ac39` |
| SSDEEP | `1536:Lh+jn2+ifI/EIzRBIepUGzX+VCW+XpElUxc2V7pd3OQ37PKlCdg71G+dkChCz:9+jn2tA/EIzPIepUG6VCPulY7p9OQ3rz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_2522ea59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2522ea59162e569aa18244b99521f597f0bd5082c767b80c6cf09d0dd3c8b9a5"
    family = "Mirai"
    file_name = "nerv.x86"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:26"
  condition:
    hash.sha256(0, filesize) == "2522ea59162e569aa18244b99521f597f0bd5082c767b80c6cf09d0dd3c8b9a5"
}
```

### Sample 9: `d76c60aac76d0118`

| Field | Value |
|---|---|
| SHA-256 | `d76c60aac76d011874dd64ffd9009413f0edf34556005195561199f54598b6a9` |
| Family label | `Mirai` |
| File name | `nerv.sparc` |
| File type | `elf` |
| First seen | `2026-06-22 04:47:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50d3418a9687f68738fef893e3307620` |
| SHA-1 | `99f4c90af50abf80c5196a0d8f9d3a8f4944c521` |
| SHA-256 | `d76c60aac76d011874dd64ffd9009413f0edf34556005195561199f54598b6a9` |
| SHA3-384 | `9c7c49d9dc72bff692e7dfee4b1568f679b7d81fc3434c62e05f5f166db62655ad32ad41b6de0672ee04fd98f2c1ebb3` |
| TLSH | `T1CEB35D22B9751E2BC4D4A8BA61F74365F1F2578A21ECC51E3D710E8EEF242503257BB8` |
| SSDEEP | `1536:X1/ik8w0iX/SSqcYI8kKrN0v4oOaOHykDfZAXQChlhIyyLtSHWcuw9t9fDNWq5SR:XhjQN0Ao8JHipV9PfDNlCG4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_d76c60aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d76c60aac76d011874dd64ffd9009413f0edf34556005195561199f54598b6a9"
    family = "Mirai"
    file_name = "nerv.sparc"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:24"
  condition:
    hash.sha256(0, filesize) == "d76c60aac76d011874dd64ffd9009413f0edf34556005195561199f54598b6a9"
}
```

### Sample 10: `57fa061f794297b1`

| Field | Value |
|---|---|
| SHA-256 | `57fa061f794297b1b23aa1bbf4a552d8e403568f6b01a24aa9b64257aecc8553` |
| Family label | `Mirai` |
| File name | `nerv.m68k` |
| File type | `elf` |
| First seen | `2026-06-22 04:47:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52b0c909b30a86a79a016161f9212b70` |
| SHA-1 | `d2c4a16895edf91e22695bc240ff1811661ef0ce` |
| SHA-256 | `57fa061f794297b1b23aa1bbf4a552d8e403568f6b01a24aa9b64257aecc8553` |
| SHA3-384 | `5dce362044b62bb0dd5cd17a33620ded316e47311a2572ee4a12ad9f1d94cd474949823674d80d8705e24d08f8983d91` |
| TLSH | `T121B34AD2F401DDBDFC0ED77F4453060AB631A36116935F3B675BBAA3AC310A56922E82` |
| SSDEEP | `1536:iT5dgyt7gtSZrttjUqaxnJAAtK8FhBeAw19j8TfBc/3b+dHMakFuzrE:Y5dZ2YtjDaxJAAtXBY8NKlakFOrE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_57fa061f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57fa061f794297b1b23aa1bbf4a552d8e403568f6b01a24aa9b64257aecc8553"
    family = "Mirai"
    file_name = "nerv.m68k"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:23"
  condition:
    hash.sha256(0, filesize) == "57fa061f794297b1b23aa1bbf4a552d8e403568f6b01a24aa9b64257aecc8553"
}
```

### Sample 11: `a4e9e03516d572e9`

| Field | Value |
|---|---|
| SHA-256 | `a4e9e03516d572e9b0f3238e7693b2fe69358f4b7cbe545adbe56f0397726df4` |
| Family label | `Mirai` |
| File name | `nerv.arm7` |
| File type | `elf` |
| First seen | `2026-06-22 04:47:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7f59ae704fb7ac9118024b31ebc5309` |
| SHA-1 | `b0995dd30c44aa4f54c631b8f089616d9ade0893` |
| SHA-256 | `a4e9e03516d572e9b0f3238e7693b2fe69358f4b7cbe545adbe56f0397726df4` |
| SHA3-384 | `8ec86873659ad5a7568987b522c335f00c011ac15d3815f45bbdd6c915abd3e9f22797089e62d68d6e1ecd1be5ad8167` |
| TLSH | `T1CBD32A46B9425A12D5D732FAFAAE408933137F79E3FA7102DD205F5023C9A9B0E77612` |
| TELFHASH | `t1d0b0120fa520205d076180bac0c7d869807034df15002940c5541609a0a0a12380b267` |
| SSDEEP | `3072:U0+3mS15aqVxO4nnPfGxKKEd/gUBzaVYScU04lElEfMKV0KebCoC:3S1RbnPexKKEhg+zaVYScU/ElEr0XeoC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_a4e9e035
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4e9e03516d572e9b0f3238e7693b2fe69358f4b7cbe545adbe56f0397726df4"
    family = "Mirai"
    file_name = "nerv.arm7"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:22"
  condition:
    hash.sha256(0, filesize) == "a4e9e03516d572e9b0f3238e7693b2fe69358f4b7cbe545adbe56f0397726df4"
}
```

### Sample 12: `8de571b44211ec6f`

| Field | Value |
|---|---|
| SHA-256 | `8de571b44211ec6fd985428d1464daf0e4d31202c8286de9c2c496d026595caa` |
| Family label | `Mirai` |
| File name | `nerv.arm5` |
| File type | `elf` |
| First seen | `2026-06-22 04:47:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b93f554871277f82a082602190c0c548` |
| SHA-1 | `c0dfc2b92c3610c1448094b7e0aca300cd376590` |
| SHA-256 | `8de571b44211ec6fd985428d1464daf0e4d31202c8286de9c2c496d026595caa` |
| SHA3-384 | `86bcd5bea0cd394684b6f13f51a49e7ada112b71a905786ff5da465f94b34df11786ae45bcd4e0249763284b3ad02052` |
| TLSH | `T18DB32986BD826622C5D423BBFA6E418E772623A8D3EF72138D215F2037C791B0D77651` |
| TELFHASH | `t1afb012a1222077f6f7ce248200fb33110a84900f25ad15e162e86c4e01c7413b27bd12` |
| SSDEEP | `1536:vOlvWIlGPodwHHK7CDvDNUsdnYkqlGBPRLUW7aMyfr0V5EcFYlTWzLxuIeK:vOlezoONUsdnYkq4CyDyfr/nW//` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_8de571b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8de571b44211ec6fd985428d1464daf0e4d31202c8286de9c2c496d026595caa"
    family = "Mirai"
    file_name = "nerv.arm5"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:21"
  condition:
    hash.sha256(0, filesize) == "8de571b44211ec6fd985428d1464daf0e4d31202c8286de9c2c496d026595caa"
}
```

### Sample 13: `584d6786596e0a2e`

| Field | Value |
|---|---|
| SHA-256 | `584d6786596e0a2e8ae08a0de55676e10a9e5f12f7efac9e073c7f517cece228` |
| Family label | `Mirai` |
| File name | `nerv.x86_64` |
| File type | `elf` |
| First seen | `2026-06-22 04:45:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9738e2d56a47f806eb1f0f4dccf4595` |
| SHA-1 | `4e6e2c09098f8251fcc32dec84d496db0095031a` |
| SHA-256 | `584d6786596e0a2e8ae08a0de55676e10a9e5f12f7efac9e073c7f517cece228` |
| SHA3-384 | `1ef5c3cdaf4db9d367bba91c1661b779346597d7161d1ea05e8ab89e85a564427399dd9a004dd0f8b8ac38eb84c3153e` |
| TLSH | `T1D1A33903B4C088FDC18AC17817AF763AD972F56E0139F1FB2BD0EA166D4DE215A1EA54` |
| TELFHASH | `t1cb317d701d9d28a850eb5729734ee0f9e9b1092504f235e65d37ecd2cf57b804ea50d3` |
| SSDEEP | `3072:EpSf3dIub3tZGahSksTYjSSgYQ2V1E1oRi6LbDMfsVs4/Uu:MSmub3tZrhSYjSS6iax6HDhs4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_584d6786
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "584d6786596e0a2e8ae08a0de55676e10a9e5f12f7efac9e073c7f517cece228"
    family = "Mirai"
    file_name = "nerv.x86_64"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:33"
  condition:
    hash.sha256(0, filesize) == "584d6786596e0a2e8ae08a0de55676e10a9e5f12f7efac9e073c7f517cece228"
}
```

### Sample 14: `088b936614445d0e`

| Field | Value |
|---|---|
| SHA-256 | `088b936614445d0ef54c838f10b563343efedc68209c482d0155221de613ec18` |
| Family label | `Mirai` |
| File name | `nerv.mpsl` |
| File type | `elf` |
| First seen | `2026-06-22 04:45:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8c666895b971ac5d206caf89e5f1ec8` |
| SHA-1 | `712034e892b96eba3c73053b8828abff9e6b1283` |
| SHA-256 | `088b936614445d0ef54c838f10b563343efedc68209c482d0155221de613ec18` |
| SHA3-384 | `ff133adbefaa7b528c383357f6636708edb86706f9e38458ba63a2e342731df9affbb33328639d122c07af14e8caf30a` |
| TLSH | `T100D30816FB210EFBDCABCD374AE91705258C651A22AE7F367934C928F44B15B16E3C60` |
| SSDEEP | `3072:NXj17Jo82I/GFSiPep063os51hERGjPrzz:NXFLOPX8RxERmfz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_088b9366
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "088b936614445d0ef54c838f10b563343efedc68209c482d0155221de613ec18"
    family = "Mirai"
    file_name = "nerv.mpsl"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:31"
  condition:
    hash.sha256(0, filesize) == "088b936614445d0ef54c838f10b563343efedc68209c482d0155221de613ec18"
}
```

### Sample 15: `bd0d1fab22f6f81c`

| Field | Value |
|---|---|
| SHA-256 | `bd0d1fab22f6f81ce82f0fbc1831091bbac6311db2cfc8f610fb83fac2fd66d1` |
| Family label | `Mirai` |
| File name | `nerv.x86_32` |
| File type | `elf` |
| First seen | `2026-06-22 04:45:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `578a1fb9ebb26473cef37fbc3cc03140` |
| SHA-1 | `a6d18d510c57d1daa4f2f9589ca6492e68f212cd` |
| SHA-256 | `bd0d1fab22f6f81ce82f0fbc1831091bbac6311db2cfc8f610fb83fac2fd66d1` |
| SHA3-384 | `6989d58ae67feadff061124bd9ca66a523c3c02dabf6358274ad21fc02c08479ea4ce1877be51b79f99d9e9b2e10ecaa` |
| TLSH | `T1AFA329C1F68B84F9D54B48304066F33FCE32E5268071C9AEDF99AF36DA37641921629D` |
| TELFHASH | `t1db411afa56760cd8a7d0ac03a64e5730ad0d27bb546076a309f72924331fd8645bbc3d` |
| SSDEEP | `3072:ZTdeqPbQ0yhOEckEUI6An128egcTz3E6Sdq0YKc7sEW+QuQFK6P:ZTFPbQ0yhOEckEUI6A12ZHTz96G70jnF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_bd0d1fab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd0d1fab22f6f81ce82f0fbc1831091bbac6311db2cfc8f610fb83fac2fd66d1"
    family = "Mirai"
    file_name = "nerv.x86_32"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:30"
  condition:
    hash.sha256(0, filesize) == "bd0d1fab22f6f81ce82f0fbc1831091bbac6311db2cfc8f610fb83fac2fd66d1"
}
```

### Sample 16: `cc281983d78727a9`

| Field | Value |
|---|---|
| SHA-256 | `cc281983d78727a9db9a1cfd24cbd45b2cc98025d5da262a93dca5a6b16075c0` |
| Family label | `Mirai` |
| File name | `nerv.arm4` |
| File type | `elf` |
| First seen | `2026-06-22 04:45:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8401e0ad8b9268122f444a5eac24fbc8` |
| SHA-1 | `f036f8698588b5a7bcd156bd4919d14bd9e5887d` |
| SHA-256 | `cc281983d78727a9db9a1cfd24cbd45b2cc98025d5da262a93dca5a6b16075c0` |
| SHA3-384 | `2c94aa0d2383424e02977d2490ccdedae31bc0caff9f23f08f9d08e81813cb42e29fb0f0462e4d652207e97c60532f6e` |
| TLSH | `T1D0B31851BC825612C6D612BBFA6E418E375623A8D3EF3213CD255F203BC7A1B0E77652` |
| SSDEEP | `1536:bjcuL8lzTm/NWSGmQAf3ilNUsdnS3qF4h7Fo1YWDavLKbU/t5ttm1rO4nl6DoRa4:bjcKamISANUsdnS3qWJnW0LUU/t5nDu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_cc281983
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc281983d78727a9db9a1cfd24cbd45b2cc98025d5da262a93dca5a6b16075c0"
    family = "Mirai"
    file_name = "nerv.arm4"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:29"
  condition:
    hash.sha256(0, filesize) == "cc281983d78727a9db9a1cfd24cbd45b2cc98025d5da262a93dca5a6b16075c0"
}
```

### Sample 17: `31ce2168fbd4fd0f`

| Field | Value |
|---|---|
| SHA-256 | `31ce2168fbd4fd0f4c42fd9eb59b581384784e363bc0fc07f008076644b42623` |
| Family label | `Mirai` |
| File name | `nerv.sh4` |
| File type | `elf` |
| First seen | `2026-06-22 04:45:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ccd7a789f27d801374e8285d7228c31` |
| SHA-1 | `d682967dc70d2530ca7b73fa09afd3b227e8ebb0` |
| SHA-256 | `31ce2168fbd4fd0f4c42fd9eb59b581384784e363bc0fc07f008076644b42623` |
| SHA3-384 | `9ee1994fd9f75725d69c3f0f61d1bde505c720392f64ccce716a67581978378564458f75ebea9e8e593bb2b7feec3c72` |
| TLSH | `T19593AD33C92A6DD4E6519674E4F48AF81B63E50082671FBB19D8C5B95087EBCF2093F8` |
| SSDEEP | `1536:CGKS0rFc8wtAGzd8qjeCckbJcNcnwCQQjCTFilb76KGUFeo7UzECUvCxuJo99C8K:CG70rFc89GBxjeCcEeWnDWY7dGOmECU5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_31ce2168
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31ce2168fbd4fd0f4c42fd9eb59b581384784e363bc0fc07f008076644b42623"
    family = "Mirai"
    file_name = "nerv.sh4"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:27"
  condition:
    hash.sha256(0, filesize) == "31ce2168fbd4fd0f4c42fd9eb59b581384784e363bc0fc07f008076644b42623"
}
```

### Sample 18: `8bff0eab714ae1b7`

| Field | Value |
|---|---|
| SHA-256 | `8bff0eab714ae1b746abeca672ec23ff941d6748027318f9006221151c0b81f6` |
| Family label | `Mirai` |
| File name | `nerv.dbg` |
| File type | `elf` |
| First seen | `2026-06-22 04:45:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da754c10c761ae9a8a03eec7c1497840` |
| SHA-1 | `3fb9bccc73670b7a03fdf922defc58083f9c891e` |
| SHA-256 | `8bff0eab714ae1b746abeca672ec23ff941d6748027318f9006221151c0b81f6` |
| SHA3-384 | `70ac1a9d899e26a58460cacc9ad8cda67c7305ef95ff630b3065f22f4118b6e6e1418111808c6315c6096348185c511d` |
| TLSH | `T169833917B5C088FCC18AC174072AB13FE976F1AD123DB2F79794EA166C0DD608E2E958` |
| TELFHASH | `t1712102307c992c9861e367a6f30be9d19422296409f5b8e4ed37a4e3cf523940d91452` |
| SSDEEP | `1536:KK1yStwBjvszIlQG7ZS4enmB/ljLSl1VKVBi8R6OnFn45yrkOz4sm:tUSovU4D7enmBRLSliVBi88GFn14U4sm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_8bff0eab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bff0eab714ae1b746abeca672ec23ff941d6748027318f9006221151c0b81f6"
    family = "Mirai"
    file_name = "nerv.dbg"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:26"
  condition:
    hash.sha256(0, filesize) == "8bff0eab714ae1b746abeca672ec23ff941d6748027318f9006221151c0b81f6"
}
```

### Sample 19: `262f001ebc264ea9`

| Field | Value |
|---|---|
| SHA-256 | `262f001ebc264ea9f90b90f9abcfdbfa5781811e01cf7ca74f95a92238a857fe` |
| Family label | `unknown` |
| File name | `tmp_downloader.bat` |
| File type | `bat` |
| First seen | `2026-06-22 04:39:27` |
| Reporter | `Kejult` |
| Tags | `bat, downloader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7bebc76359e50b4e24cffbce895dd4a2` |
| SHA-1 | `43ba339a94021e6c86db74de180d15b64e97923c` |
| SHA-256 | `262f001ebc264ea9f90b90f9abcfdbfa5781811e01cf7ca74f95a92238a857fe` |
| SHA3-384 | `9a4213a0f52ce4dc7608688cc353462b046aa91f9ebac4f2fb0156402dba9404a85d0ee50cac3da1de32602082f5b84e` |
| TLSH | `T129C08CEA98CF0AE8CB45EB017DFD2406A50FC0CA22714828AE0354207A8405BAE2618B` |
| SSDEEP | `3:BKDD/2qJJyQZTGNjmsKLxvMIMLkXiEIusKpFbAsGIBJpQXbJJFISFeBgolCVJov:STGGGhukIMCiRb8bQ98SFMlCLov` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_262f001e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "262f001ebc264ea9f90b90f9abcfdbfa5781811e01cf7ca74f95a92238a857fe"
    family = "unknown"
    file_name = "tmp_downloader.bat"
    file_type = "bat"
    first_seen = "2026-06-22 04:39:27"
  condition:
    hash.sha256(0, filesize) == "262f001ebc264ea9f90b90f9abcfdbfa5781811e01cf7ca74f95a92238a857fe"
}
```

### Sample 20: `d135ddfe09f72f00`

| Field | Value |
|---|---|
| SHA-256 | `d135ddfe09f72f009766f84ff20adc24162c9656782ba77ca247783757e46b94` |
| Family label | `Prometei` |
| File name | `d135ddfe09f72f009766f84ff20adc24162c9656782ba77ca247783757e46b94` |
| File type | `elf` |
| First seen | `2026-06-22 03:55:18` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4e975ef56c7a94c4201b559f429345e` |
| SHA-1 | `d566539d48c058526f35c0ff809605fe8f2f459c` |
| SHA-256 | `d135ddfe09f72f009766f84ff20adc24162c9656782ba77ca247783757e46b94` |
| SHA3-384 | `d0739a03e07464c7b3ba1028265085d34344872609f7da0093cfcaee1a441ad7699e78e07872b68ba668e3d5fa5c4a0d` |
| TLSH | `T13CA423B4F9229E8F6DD769B91B24C35DE181C172589D4C2313AE94A34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdl:Fs6pyCC/Ya2hpi6T6N4T` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_020_d135ddfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d135ddfe09f72f009766f84ff20adc24162c9656782ba77ca247783757e46b94"
    family = "Prometei"
    file_name = "d135ddfe09f72f009766f84ff20adc24162c9656782ba77ca247783757e46b94"
    file_type = "elf"
    first_seen = "2026-06-22 03:55:18"
  condition:
    hash.sha256(0, filesize) == "d135ddfe09f72f009766f84ff20adc24162c9656782ba77ca247783757e46b94"
}
```

### Sample 21: `9d88938e65802ec2`

| Field | Value |
|---|---|
| SHA-256 | `9d88938e65802ec240969c1a290e493fe8381c225375082785877da2b1244198` |
| Family label | `Mirai` |
| File name | `sora.mpsl` |
| File type | `elf` |
| First seen | `2026-06-22 03:30:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e70f8cd6f50650e5ba55e3ef22ddf504` |
| SHA-1 | `7c7857e2deb01968fe634aa2085a820d7663e3ce` |
| SHA-256 | `9d88938e65802ec240969c1a290e493fe8381c225375082785877da2b1244198` |
| SHA3-384 | `6e0ea9c59b53276029466168069f2e8ecdf8ca3347a0f6c42dc6ee1423206a9e987dbd510129e74f87e69ef7a919b9d0` |
| TLSH | `T181D2D1ADE4B441C5ED8E1C7A80DC3FA14E56E681231BDB9673218C895B33C57F16A4B8` |
| SSDEEP | `384:h8pVWtmRsLYEpB6V8S628FuRUuNJG9whQ3Cfbo6w+K95orjez0kgRWGVCz0Nvx:uMYHb62x4ahQ3CfdwLjhYWQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_9d88938e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d88938e65802ec240969c1a290e493fe8381c225375082785877da2b1244198"
    family = "Mirai"
    file_name = "sora.mpsl"
    file_type = "elf"
    first_seen = "2026-06-22 03:30:40"
  condition:
    hash.sha256(0, filesize) == "9d88938e65802ec240969c1a290e493fe8381c225375082785877da2b1244198"
}
```

### Sample 22: `3c685414f77a1f91`

| Field | Value |
|---|---|
| SHA-256 | `3c685414f77a1f913c1cf41c95c1bf74c067687366be3d451db9b4dd1b1631dd` |
| Family label | `Mirai` |
| File name | `data_arm6` |
| File type | `elf` |
| First seen | `2026-06-22 03:30:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebe31d53fe27dc0a0981a772d397410e` |
| SHA-1 | `d41306b4b0d37f8376ddcfdeffebedfc888aeff8` |
| SHA-256 | `3c685414f77a1f913c1cf41c95c1bf74c067687366be3d451db9b4dd1b1631dd` |
| SHA3-384 | `d3fbacf4297a57da84b9c35bcc13716fd01ae05cee3ef022a000f6aeb692a06df8cc822678661d7708f1558d84e2c8f4` |
| TLSH | `T1E9D31952B9528B12D1C311BAFB9F518D33136FB8E3ED32029D246F60678B9DB0E76512` |
| TELFHASH | `t198f005275f500e6cbbd9038518df2416efa475d89b9277436f4c164f544b981b038d03` |
| SSDEEP | `3072:8VavE23NpT9SmpWXWP6yGAXW/VxoM79PaYjd0BfsqO5rKK3:8Ox9pTYmpWXK8Vxl7NaCYfspKK3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_3c685414
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c685414f77a1f913c1cf41c95c1bf74c067687366be3d451db9b4dd1b1631dd"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-06-22 03:30:39"
  condition:
    hash.sha256(0, filesize) == "3c685414f77a1f913c1cf41c95c1bf74c067687366be3d451db9b4dd1b1631dd"
}
```

### Sample 23: `00109ee92a3ccea9`

| Field | Value |
|---|---|
| SHA-256 | `00109ee92a3ccea9d23621fe1e2e6f73cab1616c585da67ec9da59fa086cc848` |
| Family label | `Mirai` |
| File name | `data_aarch64` |
| File type | `elf` |
| First seen | `2026-06-22 03:12:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a78a8fc065f1b5a70fd6256b28d760b1` |
| SHA-1 | `786ca2096a9fcd63676d4afde2ab3a3782b7dd5d` |
| SHA-256 | `00109ee92a3ccea9d23621fe1e2e6f73cab1616c585da67ec9da59fa086cc848` |
| SHA3-384 | `85715a41290d7b385266166e52ded5091f6085129a10005aac74b2bd95863ea5260722c4dab6959ceb488c343aabfab4` |
| TLSH | `T102E47D9DFE4E3C42E2D7E37C9E4987E1721B75E0D32391A23982430DD5C69D8CBA1A25` |
| SSDEEP | `12288:xx0iWHV/WD3MqMfZFrr5j+v1uQjmOyt5YXlzT9vpwnJSw5Ldtc7:T+pWD3Mppj+v17jYunyj6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_00109ee9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00109ee92a3ccea9d23621fe1e2e6f73cab1616c585da67ec9da59fa086cc848"
    family = "Mirai"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-06-22 03:12:15"
  condition:
    hash.sha256(0, filesize) == "00109ee92a3ccea9d23621fe1e2e6f73cab1616c585da67ec9da59fa086cc848"
}
```

### Sample 24: `8f220944e1c64266`

| Field | Value |
|---|---|
| SHA-256 | `8f220944e1c64266ef33f1ebbf64d0e6ebbaea6262137fffced01443bd12fe96` |
| Family label | `Mirai` |
| File name | `data_arm5` |
| File type | `elf` |
| First seen | `2026-06-22 03:10:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cab67f8dc2ea81b6e2d5c72259a3b9ad` |
| SHA-1 | `48f8118706835ba5fd8e1a43ec71cdaf8bb9d917` |
| SHA-256 | `8f220944e1c64266ef33f1ebbf64d0e6ebbaea6262137fffced01443bd12fe96` |
| SHA3-384 | `b4a5e122a726fbf0a049a5d06f3dc97f9d8fe8b395b1a45be5107a1e7924876b9c6308332557fe5265ff7712a0e45b89` |
| TLSH | `T106C3F952BD429B13C6C311F7FBAE42583B136B79D7EA3102A9247FA0274B8DA0F27551` |
| TELFHASH | `t18cf0e1c1fbe0175db7ee841c4aac40100b64bccdbb712c0d9b1ea25fe006e45b00a585` |
| SSDEEP | `3072:22s2IHs09ZZtD/pPDfKzyhhdY85KRkDn2:VIHs0zHDBbKzyhDY8KeDn2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_8f220944
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f220944e1c64266ef33f1ebbf64d0e6ebbaea6262137fffced01443bd12fe96"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-06-22 03:10:43"
  condition:
    hash.sha256(0, filesize) == "8f220944e1c64266ef33f1ebbf64d0e6ebbaea6262137fffced01443bd12fe96"
}
```

### Sample 25: `135984a39fef8cc5`

| Field | Value |
|---|---|
| SHA-256 | `135984a39fef8cc561b56a3331c9217ac30617a6dce97840519bad571e6c433e` |
| Family label | `Mirai` |
| File name | `sora.spc` |
| File type | `elf` |
| First seen | `2026-06-22 03:10:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `469e50f1396e689ba2be532bc207868d` |
| SHA-1 | `d426fe2d1bfe5d6ead86618d40d4b27c8e3dc22f` |
| SHA-256 | `135984a39fef8cc561b56a3331c9217ac30617a6dce97840519bad571e6c433e` |
| SHA3-384 | `fe9bb125e2f9fcd6c7d5c007098a0d0b2f3fb2cd95e049269b483513d80e4ada899d9d7b2cc8174cefd66c0f409d64fe` |
| TLSH | `T15F732A26B97A1E26C0D4B57E60FB8B11F6E1278E26B4C50A7D720E5EEF147006502AF7` |
| SSDEEP | `1536:hD/B6f6UD5hAS7mo0DCCAXpSKV6v3G78nN9WQ:927jqCt8v3GI/z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_135984a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "135984a39fef8cc561b56a3331c9217ac30617a6dce97840519bad571e6c433e"
    family = "Mirai"
    file_name = "sora.spc"
    file_type = "elf"
    first_seen = "2026-06-22 03:10:42"
  condition:
    hash.sha256(0, filesize) == "135984a39fef8cc561b56a3331c9217ac30617a6dce97840519bad571e6c433e"
}
```

### Sample 26: `7a14e4c99413fb08`

| Field | Value |
|---|---|
| SHA-256 | `7a14e4c99413fb0873b9497a7e2981335514434a9c1b922c9c48ce969be11c4c` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-06-22 03:09:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `605b32f92cc2c144a56e8570ed2cad20` |
| SHA-1 | `30650227421a0d68baaaf8d9811c05613ad9afdd` |
| SHA-256 | `7a14e4c99413fb0873b9497a7e2981335514434a9c1b922c9c48ce969be11c4c` |
| SHA3-384 | `40296988bfe647a02923d90e92d2adffa9bf08234389456223e95bd579a616f4f8cc8ff2d581cad32450bbb5e81ffa0c` |
| TLSH | `T166D02EA310230230A0628827F2E69498B4854BBF8C0AC11EBA4320B11E40648F0803A4` |
| SSDEEP | `6:hTqsShxIn8Z+Unx0bAulNXYq9DG+NjVsNXYrkJ:VIhCUxQPiq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_7a14e4c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a14e4c99413fb0873b9497a7e2981335514434a9c1b922c9c48ce969be11c4c"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-22 03:09:27"
  condition:
    hash.sha256(0, filesize) == "7a14e4c99413fb0873b9497a7e2981335514434a9c1b922c9c48ce969be11c4c"
}
```

### Sample 27: `df0f17370665acba`

| Field | Value |
|---|---|
| SHA-256 | `df0f17370665acba778dffb57135a02abc34c6bf9399347ee20c689433401d44` |
| Family label | `Mirai` |
| File name | `data_arm4` |
| File type | `elf` |
| First seen | `2026-06-22 03:08:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `261c0baf5a81ed4ab9408f93dce90211` |
| SHA-1 | `96f1ed6cb6a747ee2af85fa9e138cb11806b372f` |
| SHA-256 | `df0f17370665acba778dffb57135a02abc34c6bf9399347ee20c689433401d44` |
| SHA3-384 | `d9adb131e43e2f06269d7cf54600b34d62a715b8c549d63faa88aedc2f21bacddce8a04e130fec3edea249912d6632c6` |
| TLSH | `T18FD30A42BD429F13C5C311F7FBAE42983B136BB9D7EA3102ED246F91234B89B0E26551` |
| SSDEEP | `3072:opkdNPyiJWoPvICBNrnmUrCfiz3EW4Ese7Eg2:eiJWoP7NmUEiz3E3EDEg2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_df0f1737
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df0f17370665acba778dffb57135a02abc34c6bf9399347ee20c689433401d44"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-06-22 03:08:14"
  condition:
    hash.sha256(0, filesize) == "df0f17370665acba778dffb57135a02abc34c6bf9399347ee20c689433401d44"
}
```

### Sample 28: `3a016609b672a548`

| Field | Value |
|---|---|
| SHA-256 | `3a016609b672a54877b85f589ebf5ced4ee41503c850d5798fce36325f20f96f` |
| Family label | `Mirai` |
| File name | `data_mipsel-uclibc` |
| File type | `elf` |
| First seen | `2026-06-22 03:05:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddbc9edf3723f92a749154b93aee403e` |
| SHA-1 | `b2abcaddbb7da2723c4591109c79e21d1f92bfea` |
| SHA-256 | `3a016609b672a54877b85f589ebf5ced4ee41503c850d5798fce36325f20f96f` |
| SHA3-384 | `e9a87460cc603a32c43e3a7044d479205298a3670a593e8e68c0d630443ef6782ab263877b51fb1271dd18e9717c9b2e` |
| TLSH | `T1E1245B43EE890ADFC86BCDF086BE83AB1DE7559B48C1F2F5447C8C4C745D28956A3688` |
| SSDEEP | `3072:xK5B+osGSVQkCzq3/hiOZgldQ/ek3uSIyLrj6laktvzS2fksDrq4+qzi:xKnfsVMi5cQbNIyLrjq/vb3Drq4+qO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_3a016609
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a016609b672a54877b85f589ebf5ced4ee41503c850d5798fce36325f20f96f"
    family = "Mirai"
    file_name = "data_mipsel-uclibc"
    file_type = "elf"
    first_seen = "2026-06-22 03:05:27"
  condition:
    hash.sha256(0, filesize) == "3a016609b672a54877b85f589ebf5ced4ee41503c850d5798fce36325f20f96f"
}
```

### Sample 29: `3838403ebb9150e2`

| Field | Value |
|---|---|
| SHA-256 | `3838403ebb9150e24ab326f6b72f3dabab0804d5ccd83a5805a2fc1a48cdf27c` |
| Family label | `Mirai` |
| File name | `sora.arm` |
| File type | `elf` |
| First seen | `2026-06-22 03:03:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf70855b305c11f43cb5d94f0c2488f7` |
| SHA-1 | `96b284f26cb4d36606c5bc18628b2afc51c76fb4` |
| SHA-256 | `3838403ebb9150e24ab326f6b72f3dabab0804d5ccd83a5805a2fc1a48cdf27c` |
| SHA3-384 | `e60498f7be90598fb3234080bd0580b99f160652789c15dd486a1e41038a191bea8e6eb724b163e5a7abf0fb3c77b8fe` |
| TLSH | `T115630891B881A626C2D1537BFA6F008E372457D8E2DA33139D255FA0778AC1F0D57F8A` |
| TELFHASH | `t14a41d1f74ba40bcc67e8a149c98c711c5ff5b05aaf092483590caa4fc85b5d2b00e437` |
| SSDEEP | `1536:pOTAiIYaMBktkIwn8U0yaPSmuSt8M8fhWtu5v36L:pOTAiLaMH+uSerpeu5+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_3838403e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3838403ebb9150e24ab326f6b72f3dabab0804d5ccd83a5805a2fc1a48cdf27c"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-06-22 03:03:41"
  condition:
    hash.sha256(0, filesize) == "3838403ebb9150e24ab326f6b72f3dabab0804d5ccd83a5805a2fc1a48cdf27c"
}
```

### Sample 30: `d66d8002d603c897`

| Field | Value |
|---|---|
| SHA-256 | `d66d8002d603c89701071c6be50b479410b017203e85bb20f9b15860574dc617` |
| Family label | `Mirai` |
| File name | `sora.arm` |
| File type | `elf` |
| First seen | `2026-06-22 03:02:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `695a3854751efbe066f0accc1a617297` |
| SHA-1 | `38eebf535f914cf41e7f3f84e9a8a15e44ed18d3` |
| SHA-256 | `d66d8002d603c89701071c6be50b479410b017203e85bb20f9b15860574dc617` |
| SHA3-384 | `938415de5d8b5663af398e840ac6f26342c02ca84e1932bcc72e7a233c6a3e97a08345f9f1ffddad58cfc66dd463bd31` |
| TLSH | `T14EC2D1322EFF28B1C2A460B6FC7C86C7625F4BB975F56521364057A1DDE100352B68E7` |
| SSDEEP | `384:kXNSIfjdxuZ1DUofVOyPqMvt6GqAAdq1K0jzNH7EUz6z6RNo9chTvGrhymdGUopA:AjKX9vt6GqA3Q0jzV7EUyUq90Ys3UozG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_d66d8002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d66d8002d603c89701071c6be50b479410b017203e85bb20f9b15860574dc617"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-06-22 03:02:43"
  condition:
    hash.sha256(0, filesize) == "d66d8002d603c89701071c6be50b479410b017203e85bb20f9b15860574dc617"
}
```

### Sample 31: `a558714eb3c35a8f`

| Field | Value |
|---|---|
| SHA-256 | `a558714eb3c35a8f99c7991292f45b3edf3af2e08c151b6f74afb0691c189851` |
| Family label | `Mirai` |
| File name | `data_x86_64` |
| File type | `elf` |
| First seen | `2026-06-22 02:57:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d825cbe08ea10150385fe97f1e95779b` |
| SHA-1 | `8d7f1ad5f017d81502cc7afa8d0e1b4b92b90494` |
| SHA-256 | `a558714eb3c35a8f99c7991292f45b3edf3af2e08c151b6f74afb0691c189851` |
| SHA3-384 | `51b94386efc6376961e370ad7bf0eff8915bd642a43a5156b0bd92572ed0bd4184c4fea2dad71ba3de46a313288b3866` |
| TLSH | `T14C844A92F1A22CFCD952C930825D6223E63434594311AEFB27C8EF753956AD0AF3EB51` |
| TELFHASH | `t1d0a17e71428a65b4d092f9e9ceb2f732ebba03e893506935422dfd70ed42f746921c03` |
| SSDEEP | `12288:3Dr/gekdnXYMKVNywDZQY0sHLOMI4PHfQX:f/gvEFiY0sXhHfQX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_a558714e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a558714eb3c35a8f99c7991292f45b3edf3af2e08c151b6f74afb0691c189851"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-06-22 02:57:13"
  condition:
    hash.sha256(0, filesize) == "a558714eb3c35a8f99c7991292f45b3edf3af2e08c151b6f74afb0691c189851"
}
```

### Sample 32: `4121a0bfb7059830`

| Field | Value |
|---|---|
| SHA-256 | `4121a0bfb7059830e5ec9cc01126e37a5840987833ed524707356ae493d29b33` |
| Family label | `Mirai` |
| File name | `sora.arm7` |
| File type | `elf` |
| First seen | `2026-06-22 02:56:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `807c73039d6f413d6f496bac16cb4f2a` |
| SHA-1 | `0d65ac92f0ab24da9a7493ac973fdfb4d627f112` |
| SHA-256 | `4121a0bfb7059830e5ec9cc01126e37a5840987833ed524707356ae493d29b33` |
| SHA3-384 | `8eca65987a2b292944b23925d729de75cc7c2c50037de1d73754d151f94b8b8ce467d07cc89068e6c91ddda15cd2c0f8` |
| TLSH | `T18FE32B46F6418B13C5D61777FAAF414A3322D794A3DB330699285BF43F86A9F0E13A06` |
| TELFHASH | `t1b4219bb1572aa6245969cbec89dc73b9122c86121247df33ef2184bca41949df525c4f` |
| SSDEEP | `3072:5IvM9qqxuvV8yAzltJXu9CttQJ2Ed83zGCzTX0clM/9REw/kP:mvM9qqxuvV8yAzYaQJ2EduGQX0aM/9pO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_4121a0bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4121a0bfb7059830e5ec9cc01126e37a5840987833ed524707356ae493d29b33"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-06-22 02:56:33"
  condition:
    hash.sha256(0, filesize) == "4121a0bfb7059830e5ec9cc01126e37a5840987833ed524707356ae493d29b33"
}
```

### Sample 33: `b92abe3dde271635`

| Field | Value |
|---|---|
| SHA-256 | `b92abe3dde271635548f3b6c2e93f24548c2f11611bac731d6e01d835ec95775` |
| Family label | `Mirai` |
| File name | `sora.arm5` |
| File type | `elf` |
| First seen | `2026-06-22 02:55:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4108ab76360876c3d7e863193df66de8` |
| SHA-1 | `f720556c0f788a02121e14efaac69857f1bd8234` |
| SHA-256 | `b92abe3dde271635548f3b6c2e93f24548c2f11611bac731d6e01d835ec95775` |
| SHA3-384 | `f921f40d42f4267ed89b3d933d702a5cbe5fa10c8c08ee6dcb545730b038de033dd9423daf45008408ea9cc2f0f6eee1` |
| TLSH | `T14453F891B8426A3AC2D1577BEDAF548E3314A7D8D1DB3213CD240BA07B8694F1C97F86` |
| TELFHASH | `t1c5e02600ac759a2c98d7aa74dded07a496016222505a4b10cf11daf4c83f448e30cd5a` |
| SSDEEP | `1536:dn385gSW19bj2h1XBfpu2ac/ISDMSvhWy5pXS:dn3QxJpRISDMKf5g` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_b92abe3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b92abe3dde271635548f3b6c2e93f24548c2f11611bac731d6e01d835ec95775"
    family = "Mirai"
    file_name = "sora.arm5"
    file_type = "elf"
    first_seen = "2026-06-22 02:55:52"
  condition:
    hash.sha256(0, filesize) == "b92abe3dde271635548f3b6c2e93f24548c2f11611bac731d6e01d835ec95775"
}
```

### Sample 34: `d0345ab1663c0153`

| Field | Value |
|---|---|
| SHA-256 | `d0345ab1663c0153617184e5c970a566e0b8965ab364a1c9eea7cdecad15cd61` |
| Family label | `Mirai` |
| File name | `sora.arm7` |
| File type | `elf` |
| First seen | `2026-06-22 02:55:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `992a89dd9d5edcca926b68e4afab8188` |
| SHA-1 | `1e1bb6b35dbaa899052e3a48fa91d27688f104bb` |
| SHA-256 | `d0345ab1663c0153617184e5c970a566e0b8965ab364a1c9eea7cdecad15cd61` |
| SHA3-384 | `36fb904d04856fdd0e45f25e30bfee3740600305b4c7df87242f2b2202edde6da3654f038026667b73ee8e613dc7db74` |
| TLSH | `T1F0330223B358FDA2CE751D3972FD8C8E3144466DD4ECA82236C459A162C225BFBD04E3` |
| SSDEEP | `768:kfZYvZxNZ/SPjiUv0w0zyIvfgJy2LHRfb+4Dd9q3UEL2qEK5J6OAsNTGjf2tl8Xb:zPtQjiZVcykHRDiL15J6RN2tAb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_d0345ab1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0345ab1663c0153617184e5c970a566e0b8965ab364a1c9eea7cdecad15cd61"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-06-22 02:55:40"
  condition:
    hash.sha256(0, filesize) == "d0345ab1663c0153617184e5c970a566e0b8965ab364a1c9eea7cdecad15cd61"
}
```

### Sample 35: `ce0b3137383e4112`

| Field | Value |
|---|---|
| SHA-256 | `ce0b3137383e4112269155f36dfa6c238f6e4d57d73555c15b2c4ef796afbab3` |
| Family label | `Mirai` |
| File name | `sora.arm5` |
| File type | `elf` |
| First seen | `2026-06-22 02:54:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `356a1243d88a22d8221d57aea7c3caa0` |
| SHA-1 | `abfd63d9eb74c5e6167850a2ef375e81893adab5` |
| SHA-256 | `ce0b3137383e4112269155f36dfa6c238f6e4d57d73555c15b2c4ef796afbab3` |
| SHA3-384 | `c24bff910c1e5889d198cb6b4d2731a59623ccce34cf82acb82a965ae8d1e55a1dfc2bc6083744d60e55786b67b78830` |
| TLSH | `T16EB2DF34A2A964F0CD306034F57D8D47A7DA41FED0FD7622326750E85A468CD1AAC6D3` |
| SSDEEP | `384:IoBE5aNSS75BOI+ypZ5vTlYIwcvsdTf5MF1iAUgefoeDYbZXGcH1bUhymdGUop5w:4aNSq5sOHpTqncvsdDePiAUgefoeDeXO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_ce0b3137
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce0b3137383e4112269155f36dfa6c238f6e4d57d73555c15b2c4ef796afbab3"
    family = "Mirai"
    file_name = "sora.arm5"
    file_type = "elf"
    first_seen = "2026-06-22 02:54:29"
  condition:
    hash.sha256(0, filesize) == "ce0b3137383e4112269155f36dfa6c238f6e4d57d73555c15b2c4ef796afbab3"
}
```

### Sample 36: `0238e06a1ac58756`

| Field | Value |
|---|---|
| SHA-256 | `0238e06a1ac58756abb6a5d261aa720ee600d7a8bf16fc50bf134251f6df5efd` |
| Family label | `Mirai` |
| File name | `data_x86` |
| File type | `elf` |
| First seen | `2026-06-22 02:53:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bcc0ba9cec4a6580ab067f1b33876dc` |
| SHA-1 | `b69a1964323a8b04985028616e15338f35324b90` |
| SHA-256 | `0238e06a1ac58756abb6a5d261aa720ee600d7a8bf16fc50bf134251f6df5efd` |
| SHA3-384 | `c5f12d812c796e0b8953621ce825afa7c29782e9a82955cfd6eed38bf2f1c6e986f24783130e57e17e8f4e82a2b97102` |
| TLSH | `T102157CDDE7C7E0E1F62300F1025EDBF61934A12A5013FAF6EF45266274727A16F1A21A` |
| TELFHASH | `t10ae15ab715a999ec63f0841182ab7220ce3ad12b25f0397319f365e56a33d035f76c79` |
| SSDEEP | `24576:vQu5hIphla3ngNmi23pxl/VE8lxAyiErC:jhIphlaTi27UIpC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_0238e06a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0238e06a1ac58756abb6a5d261aa720ee600d7a8bf16fc50bf134251f6df5efd"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-06-22 02:53:19"
  condition:
    hash.sha256(0, filesize) == "0238e06a1ac58756abb6a5d261aa720ee600d7a8bf16fc50bf134251f6df5efd"
}
```

### Sample 37: `3b11d33e8f3ca263`

| Field | Value |
|---|---|
| SHA-256 | `3b11d33e8f3ca26375350fe631f78c09d42a017d156c8022b74c4a9c280c1381` |
| Family label | `Mirai` |
| File name | `data_mipsel` |
| File type | `elf` |
| First seen | `2026-06-22 02:50:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e887f45934e73f7257aa5fd81fb1cba3` |
| SHA-1 | `99892a76c13ed20a478b8843e65f33764f691df6` |
| SHA-256 | `3b11d33e8f3ca26375350fe631f78c09d42a017d156c8022b74c4a9c280c1381` |
| SHA3-384 | `5c3036a995645a1fc6fecde4f23d46c9874996916186ce6509b2c8cf75eaa02b69d9f6676d37fc9473910a6c99f9edfd` |
| TLSH | `T1F204E50AAB610FF7E86BDD7706E90B0528CCB91B15A53B797538EC18B50B18B49D3C78` |
| SSDEEP | `3072:Q/r7lPt/EHPwNQqIqjKQ15Rp2/+aBAIBBrE:QVqWQqIqjKQ1BA+ai4E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_3b11d33e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b11d33e8f3ca26375350fe631f78c09d42a017d156c8022b74c4a9c280c1381"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-06-22 02:50:33"
  condition:
    hash.sha256(0, filesize) == "3b11d33e8f3ca26375350fe631f78c09d42a017d156c8022b74c4a9c280c1381"
}
```

### Sample 38: `3585bbb1adae6cca`

| Field | Value |
|---|---|
| SHA-256 | `3585bbb1adae6cca2e8c084e893cc05c81c11fab54f53c22567bc683aa0f8774` |
| Family label | `Mirai` |
| File name | `sora.sh4` |
| File type | `elf` |
| First seen | `2026-06-22 02:50:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `caee427aa16d2ec15ded83a7934d7ce4` |
| SHA-1 | `958cf6ea61616a5441fad255ef1a4b1e5f1626fa` |
| SHA-256 | `3585bbb1adae6cca2e8c084e893cc05c81c11fab54f53c22567bc683aa0f8774` |
| SHA3-384 | `87ed4c64414386d69cbd20d26f443f3c0773596cb008e8d929fb82b537b03de7a72bc8a5d458abeba31ed501ef39c34d` |
| TLSH | `T1A5538D75D15DAEA8C0414AB4A9198E704F13E4C046733EFBEA9587A68443DBCF858FF8` |
| SSDEEP | `1536:ragXV1f1Fl/wtknCPQauiufs3Ii3O/qyD6EZeCc:r57f1b/0QHf+Iey6EZe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_3585bbb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3585bbb1adae6cca2e8c084e893cc05c81c11fab54f53c22567bc683aa0f8774"
    family = "Mirai"
    file_name = "sora.sh4"
    file_type = "elf"
    first_seen = "2026-06-22 02:50:31"
  condition:
    hash.sha256(0, filesize) == "3585bbb1adae6cca2e8c084e893cc05c81c11fab54f53c22567bc683aa0f8774"
}
```

### Sample 39: `9a73e54c5aaf4ae3`

| Field | Value |
|---|---|
| SHA-256 | `9a73e54c5aaf4ae3291fd4ae23059c5a9bfbebd4abbf794d1840362a81bfb9ec` |
| Family label | `Mirai` |
| File name | `data_mips` |
| File type | `elf` |
| First seen | `2026-06-22 02:50:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `340c04ab6937d66e9147488c236183ec` |
| SHA-1 | `46dc3a8244b871c3b11f19f676bb3688d335ae1a` |
| SHA-256 | `9a73e54c5aaf4ae3291fd4ae23059c5a9bfbebd4abbf794d1840362a81bfb9ec` |
| SHA3-384 | `7d2e7deaad1c5db22110bcfcfc9b789bb6831454df65e742fbc39d96573aac9f12e9aef74db47469999368479c7be5a0` |
| TLSH | `T170F3860A6F228F7EF269877047B78A31E75977D616E1C680F1ACD5041E602CE641FFA8` |
| TELFHASH | `t1a64185180eb813a4a6356c5d441dff67d6a330db3e1a6c238e11e86aeb69f835d24c0c` |
| SSDEEP | `3072:XATkUaFPDUSyOh6ZXfQZOi98l7M3neKCeCGfg3:QTkUMwSyOsV8Oiu6nJ1fC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_9a73e54c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a73e54c5aaf4ae3291fd4ae23059c5a9bfbebd4abbf794d1840362a81bfb9ec"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-06-22 02:50:30"
  condition:
    hash.sha256(0, filesize) == "9a73e54c5aaf4ae3291fd4ae23059c5a9bfbebd4abbf794d1840362a81bfb9ec"
}
```

### Sample 40: `f197de37ab531b3d`

| Field | Value |
|---|---|
| SHA-256 | `f197de37ab531b3db10d24757e3668602901389878afe2e11546a3f6be5d818d` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-22 02:48:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e66f444d93ca51f3a3630e847b29bbd9` |
| SHA-1 | `f96c95e4dc4cf85aa315a34d4815225f2324b0d1` |
| SHA-256 | `f197de37ab531b3db10d24757e3668602901389878afe2e11546a3f6be5d818d` |
| SHA3-384 | `cf77a458bd426e6e671c82b04880e869396a1bdabecf0c47b7897cc80a374705e630294954ef342dc664a20cd8dbbb3b` |
| TLSH | `T16C136D6516953C25AE99883B5C7F2F0CBDA983E1304491DDBF8A3CF18C15A9CE718B1D` |
| SSDEEP | `768:Jr9NyXsZztC+9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:BHusZOco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_f197de37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f197de37ab531b3db10d24757e3668602901389878afe2e11546a3f6be5d818d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-22 02:48:11"
  condition:
    hash.sha256(0, filesize) == "f197de37ab531b3db10d24757e3668602901389878afe2e11546a3f6be5d818d"
}
```

### Sample 41: `639015f49fe00afa`

| Field | Value |
|---|---|
| SHA-256 | `639015f49fe00afa52244a61ddc8b32969ce8c884fc709281cb1f2938b447e4a` |
| Family label | `Mirai` |
| File name | `sora.m68k` |
| File type | `elf` |
| First seen | `2026-06-22 02:46:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf1d682e438d6a4abf7750dae5e07739` |
| SHA-1 | `28132b173a0b5cad81efc69bf6ec11eaaf0efe61` |
| SHA-256 | `639015f49fe00afa52244a61ddc8b32969ce8c884fc709281cb1f2938b447e4a` |
| SHA3-384 | `0835a728599e7cfb022a63416c1aabdb811904017426bcab22c5d129e001471def5f1b96a48a1c092aacb8557070c8dc` |
| TLSH | `T188533B99F4029E3DF88FE9BA84160E05B93023D212931B2767ABFDE37D331659D12E45` |
| SSDEEP | `768:me4gpsM204GEkRbjveXd/nQi122EQtBSv3gFHn1eu48B8vB6J7EzNfXQuJpozTy1:mo3EkRbDmoiz6IFn1X48B2SEzNfAuJL1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_639015f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "639015f49fe00afa52244a61ddc8b32969ce8c884fc709281cb1f2938b447e4a"
    family = "Mirai"
    file_name = "sora.m68k"
    file_type = "elf"
    first_seen = "2026-06-22 02:46:43"
  condition:
    hash.sha256(0, filesize) == "639015f49fe00afa52244a61ddc8b32969ce8c884fc709281cb1f2938b447e4a"
}
```

### Sample 42: `c03210e941c3de90`

| Field | Value |
|---|---|
| SHA-256 | `c03210e941c3de902810021ae1364922f797eb3432f5d4390d3982c495961d36` |
| Family label | `Mirai` |
| File name | `data_arm7` |
| File type | `elf` |
| First seen | `2026-06-22 02:45:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44e38bcd5b2a92cb32d7e794b3b150ef` |
| SHA-1 | `e0faa89c46071c3d554513ad1f08d07563963ce4` |
| SHA-256 | `c03210e941c3de902810021ae1364922f797eb3432f5d4390d3982c495961d36` |
| SHA3-384 | `dcfa1790a68b4f1324f5d8fb0185ac6e5d0aa64dbd8d9690d98871ccbd252ba90e0267db6e56d38242b001330487d0a4` |
| TLSH | `T140E31A56B9519F11D5C321FAFB9E918933136FB8E3F93102AD206F60638A99F0E77502` |
| TELFHASH | `t19df00555da341bbc67ce40141e79292cb76a78f41761e5834588cb4f8707cea703901b` |
| SSDEEP | `3072:qwPFV1semWe8fn/I073ESgXnq0xc4/oaN7cD57mS8hquQiaurvlJDP8swL:qOXNmD8fn/H73b0xxoaN7cD57mS8Tfar` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_c03210e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c03210e941c3de902810021ae1364922f797eb3432f5d4390d3982c495961d36"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-06-22 02:45:30"
  condition:
    hash.sha256(0, filesize) == "c03210e941c3de902810021ae1364922f797eb3432f5d4390d3982c495961d36"
}
```

### Sample 43: `a3cb43a29e0f181f`

| Field | Value |
|---|---|
| SHA-256 | `a3cb43a29e0f181f1145426e70fccdce8e04ce82c667ab0861426f31670e75a5` |
| Family label | `Mirai` |
| File name | `data_mips-uclibc` |
| File type | `elf` |
| First seen | `2026-06-22 02:45:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4f2c59ced19e9a2ae4868be4aabc945` |
| SHA-1 | `6ba0f101b6bc7293221ad9cce2eac1ecbc627ffa` |
| SHA-256 | `a3cb43a29e0f181f1145426e70fccdce8e04ce82c667ab0861426f31670e75a5` |
| SHA3-384 | `3b62e766f79f4587c0b9d6413429a9011f6e63d6d1d1f1d8e1a7c232b5312db2a4f72e460172c41f64e844638f7f9b5e` |
| TLSH | `T1D6242C4377324FA0D326D2724BB38F5A59EB11D12EE288D5935CCB143A207A9685FFE4` |
| TELFHASH | `t19cf01228547c23b4d2c5dc5d55dcff19e8a1d4db99762e17c504c9a9e771e838d00d38` |
| SSDEEP | `3072:bktAgn6ojH+ZfFpcE7YX7Oj5/tVth0zbm374xKsyT9lEKYIhpDZAg:AHJD+ZfLN/zth0/e44h93YI7ZAg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_a3cb43a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3cb43a29e0f181f1145426e70fccdce8e04ce82c667ab0861426f31670e75a5"
    family = "Mirai"
    file_name = "data_mips-uclibc"
    file_type = "elf"
    first_seen = "2026-06-22 02:45:29"
  condition:
    hash.sha256(0, filesize) == "a3cb43a29e0f181f1145426e70fccdce8e04ce82c667ab0861426f31670e75a5"
}
```

### Sample 44: `9bbed06deb57b262`

| Field | Value |
|---|---|
| SHA-256 | `9bbed06deb57b262ed1a74cdb6d17ca21161163cbada6538267b6afd00e61cb6` |
| Family label | `Mirai` |
| File name | `data_powerpc` |
| File type | `elf` |
| First seen | `2026-06-22 02:43:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8aaa95c71829fa18af3cd9799954962` |
| SHA-1 | `2d0fe4b80d5064ed72dad730e4c26e60506517f3` |
| SHA-256 | `9bbed06deb57b262ed1a74cdb6d17ca21161163cbada6538267b6afd00e61cb6` |
| SHA3-384 | `d65abdf0c21f67183fb026742b585d60c8f138d0e4313bbd21c86c62af16aa6aed7d75b6510e9b7c7fbed90b962629c6` |
| TLSH | `T115D32A02770D0F43D1232CF02B7B5BE18799BDE119F5E584A51DBECA52B4EB22182ED9` |
| SSDEEP | `3072:h2hagMAZpx89Vzo0+P8WLQJWIn0b57+VUT:h2h1ZpxiLe8QMWIn017GUT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_9bbed06d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bbed06deb57b262ed1a74cdb6d17ca21161163cbada6538267b6afd00e61cb6"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-06-22 02:43:10"
  condition:
    hash.sha256(0, filesize) == "9bbed06deb57b262ed1a74cdb6d17ca21161163cbada6538267b6afd00e61cb6"
}
```

### Sample 45: `84bf32c6c5852dcf`

| Field | Value |
|---|---|
| SHA-256 | `84bf32c6c5852dcfe76cfe8ce6b40a4408603b3e52137a9562bfddbaddc760b2` |
| Family label | `Mirai` |
| File name | `sora.mips` |
| File type | `elf` |
| First seen | `2026-06-22 02:40:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74e71ccc947d89710a89e6055c25178f` |
| SHA-1 | `18dc5ac54947125482d8ee2e5fd89e11400715cf` |
| SHA-256 | `84bf32c6c5852dcfe76cfe8ce6b40a4408603b3e52137a9562bfddbaddc760b2` |
| SHA3-384 | `a82bc9eac2d2a591894a3c13893e73d35f08b1bfe25238ace22148103b5fb1f919f336fc6e3ceb75df4a3a54e05099a1` |
| TLSH | `T1E683C6297E218FBEF79D823947B78F22964837C637E1D581D15CDA005E7028E641BFA8` |
| TELFHASH | `t175014948893c57f0d7665ddc6bddff76e05260cf49615e778e00b9aa9b6c9428e00c1c` |
| SSDEEP | `1536:E6/iw/0w8HoQ5uy8NxqlcJ0vXxh11xYqcn6BZOpkMoAfEG:x/8RHTgMcJ0fmqJZOpkM/8G` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_84bf32c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84bf32c6c5852dcfe76cfe8ce6b40a4408603b3e52137a9562bfddbaddc760b2"
    family = "Mirai"
    file_name = "sora.mips"
    file_type = "elf"
    first_seen = "2026-06-22 02:40:51"
  condition:
    hash.sha256(0, filesize) == "84bf32c6c5852dcfe76cfe8ce6b40a4408603b3e52137a9562bfddbaddc760b2"
}
```

### Sample 46: `84a09f4fdf90abd5`

| Field | Value |
|---|---|
| SHA-256 | `84a09f4fdf90abd5364f982b3d7d49aabf862a38bc78b66bf23014daaf19d8ae` |
| Family label | `Mirai` |
| File name | `sora.mips` |
| File type | `elf` |
| First seen | `2026-06-22 02:39:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c54dc573e8fdb22cc507602674636d7` |
| SHA-1 | `dd3ddefdd068758e48d29a10d1ea2d88c150faeb` |
| SHA-256 | `84a09f4fdf90abd5364f982b3d7d49aabf862a38bc78b66bf23014daaf19d8ae` |
| SHA3-384 | `5d7b8e7287f2156c8036b5a8f12b79ddcd0fe1d1a6175476349f200e0ab89b895c471c310b1d5fafc2fc12a3bf193280` |
| TLSH | `T1DBD2D1B86B1249D7CB6EA2B44EE50B272D708FA2E0426C076564D5D77B0A86C3CB6DC1` |
| SSDEEP | `768:U4ylAtv6pqLJM0RXaxGyUbXtheU/SA+iJgGlzDpbuR1Jc:HMBqTRXa+Zhr/fVJua` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_84a09f4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84a09f4fdf90abd5364f982b3d7d49aabf862a38bc78b66bf23014daaf19d8ae"
    family = "Mirai"
    file_name = "sora.mips"
    file_type = "elf"
    first_seen = "2026-06-22 02:39:19"
  condition:
    hash.sha256(0, filesize) == "84a09f4fdf90abd5364f982b3d7d49aabf862a38bc78b66bf23014daaf19d8ae"
}
```

### Sample 47: `fcc9249b4f188e5a`

| Field | Value |
|---|---|
| SHA-256 | `fcc9249b4f188e5a66fca4fd3811585f16438e7dd0542301f1575209010fad90` |
| Family label | `Mirai` |
| File name | `sora.x86` |
| File type | `elf` |
| First seen | `2026-06-22 02:34:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b406c155f39aaaadb6f988b63e30f76` |
| SHA-1 | `4d12d9960de695d0e8bdb5f79497e8c8f181f367` |
| SHA-256 | `fcc9249b4f188e5a66fca4fd3811585f16438e7dd0542301f1575209010fad90` |
| SHA3-384 | `433b32bd1bb251abe16dbc401368dcde35624c308f47b9a5ca14af0358c981c65df831832927f7f791e04f14cd1272f4` |
| TLSH | `T1FCC2E1A350F6CA03C8F2837A6E3C5AA662605834A34EED2D77794BC477460D4657ACCB` |
| SSDEEP | `768:w5+Kcrb9VDJee2KTgdTHOBcK5ZCAyukANg:Plrb9veKTg9QB5VjK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_fcc9249b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcc9249b4f188e5a66fca4fd3811585f16438e7dd0542301f1575209010fad90"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-06-22 02:34:19"
  condition:
    hash.sha256(0, filesize) == "fcc9249b4f188e5a66fca4fd3811585f16438e7dd0542301f1575209010fad90"
}
```

### Sample 48: `2ec11059183fff0a`

| Field | Value |
|---|---|
| SHA-256 | `2ec11059183fff0a0da44a9e8a4bffea0d55dd8e31dc966bbb52c5435530dc48` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-06-22 02:34:18` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `873970375886a32afcc8c2a885c4d52c` |
| SHA-1 | `8ed7ed488f074eb7bcf5cc856b43d07a192ebdf3` |
| SHA-256 | `2ec11059183fff0a0da44a9e8a4bffea0d55dd8e31dc966bbb52c5435530dc48` |
| SHA3-384 | `a6dffa8895325a2d27da485a557eace0942e57107b4841c387c5df352215d6afb0551bf98066723b3a1c2eb1f9a758e4` |
| TLSH | `T198312E9A05155B3A0242CADE737B368CB00CC5FB2C5FD794DD894EA982985CDB262BC5` |
| SSDEEP | `12:Ubx6bXDxkIZt5ljr6l/q2XgwB6qpq5hAtL6AtyJzY86oKmgqlM6+nqcHPZ6Pd+t9:GWXDKUtHo/DJkhM8S2sHHAb4cFP+PXD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_2ec11059
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec11059183fff0a0da44a9e8a4bffea0d55dd8e31dc966bbb52c5435530dc48"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-22 02:34:18"
  condition:
    hash.sha256(0, filesize) == "2ec11059183fff0a0da44a9e8a4bffea0d55dd8e31dc966bbb52c5435530dc48"
}
```

### Sample 49: `c6473b0fc4ebd18a`

| Field | Value |
|---|---|
| SHA-256 | `c6473b0fc4ebd18ab4ffe6771c77cece197e40299cac3745bbc12c0bea2261bf` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-22 02:33:26` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41dced704c3d94e43df2e751629ac5ac` |
| SHA-1 | `d4ff06a9937544058e1578e57a4e49fb346b9e80` |
| SHA-256 | `c6473b0fc4ebd18ab4ffe6771c77cece197e40299cac3745bbc12c0bea2261bf` |
| SHA3-384 | `d904c6abb936d16ce208d83f891dfa9690188e6235669ecf1e4752632ed4253977240d74c4c5ad723d1edbea637a8e8b` |
| IMPHASH | `c129097361b8295c6461feaed5b0ddf4` |
| TLSH | `T1A055AE6E0DBC9E77E53387FA451307523EFF1007A07221679D4AEFA97909F49828928D` |
| SSDEEP | `24576:md9eqr39VeX5MWXSd0xX/XNkUO8CtFpQ6ROQTjxPNj37b4qmmX/XngS3q1:md9NNVeX5MC3Ct8STtF7QEg9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_c6473b0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6473b0fc4ebd18ab4ffe6771c77cece197e40299cac3745bbc12c0bea2261bf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-22 02:33:26"
  condition:
    hash.sha256(0, filesize) == "c6473b0fc4ebd18ab4ffe6771c77cece197e40299cac3745bbc12c0bea2261bf"
}
```

### Sample 50: `5ea5fd6006918909`

| Field | Value |
|---|---|
| SHA-256 | `5ea5fd6006918909f9026626019e19b00f8935ec9f03b9cab6d8f88ac8c77e8c` |
| Family label | `Mirai` |
| File name | `sora.arm6` |
| File type | `elf` |
| First seen | `2026-06-22 02:33:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3c863ec3c05591b0b7143a0ead85901` |
| SHA-1 | `2ddbad1e2d138648fab1dd713e739c9d33b84dd7` |
| SHA-256 | `5ea5fd6006918909f9026626019e19b00f8935ec9f03b9cab6d8f88ac8c77e8c` |
| SHA3-384 | `93d25acc17756678b26d9d90ed9d4e997637de66b7f977ea0d99afb9a604d6f23dc0dfd11c948070218188a1878999f6` |
| TLSH | `T160730A81B9819B25C6D513BBF91F018E33165BE8E3DE73129D241F607BCA91B0D27E4A` |
| TELFHASH | `t181f081c90b7846fa37f56b598aad5149acf534fd7f155c17648d734e11120c1706b400` |
| SSDEEP | `1536:y0nC6qYfkiubZwoNCJYDQ7gppg6T63z5yAMw1f9r/1eUc6I+i3JqwsjAgQ:CskiIZJNlDWQpg6Ts4Xwtl/OJqwsjAN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_5ea5fd60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ea5fd6006918909f9026626019e19b00f8935ec9f03b9cab6d8f88ac8c77e8c"
    family = "Mirai"
    file_name = "sora.arm6"
    file_type = "elf"
    first_seen = "2026-06-22 02:33:22"
  condition:
    hash.sha256(0, filesize) == "5ea5fd6006918909f9026626019e19b00f8935ec9f03b9cab6d8f88ac8c77e8c"
}
```

### Sample 51: `0d4ecc9f1c7e94da`

| Field | Value |
|---|---|
| SHA-256 | `0d4ecc9f1c7e94da3e93389cc98088fe162a4ef1ba90d54330411fd92ea3ed3a` |
| Family label | `Mirai` |
| File name | `sora.arm6` |
| File type | `elf` |
| First seen | `2026-06-22 02:33:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c49410048280d5045bf9b3db7253dd3f` |
| SHA-1 | `9db97a15da70e9bb43689fc1199b8d8b457181bc` |
| SHA-256 | `0d4ecc9f1c7e94da3e93389cc98088fe162a4ef1ba90d54330411fd92ea3ed3a` |
| SHA3-384 | `d919bd8da309652116c3a34d738b4bfe707d95d221ab080c8f6e49ed1de86487a6a94bc9ced9a253ad1574e553505a4f` |
| TLSH | `T113E2E1D55576A878CEB10D7AFC670B4E2539C6FC86FB10226BF4372423B09AA4BB0452` |
| SSDEEP | `768:q8Lm6COq1fewdHy62pud4yNOYSOyB8LrBf1s9q3UELde:zLJCmjpkcMKUJ11LA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_0d4ecc9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d4ecc9f1c7e94da3e93389cc98088fe162a4ef1ba90d54330411fd92ea3ed3a"
    family = "Mirai"
    file_name = "sora.arm6"
    file_type = "elf"
    first_seen = "2026-06-22 02:33:07"
  condition:
    hash.sha256(0, filesize) == "0d4ecc9f1c7e94da3e93389cc98088fe162a4ef1ba90d54330411fd92ea3ed3a"
}
```

### Sample 52: `7ba980da964f7c1e`

| Field | Value |
|---|---|
| SHA-256 | `7ba980da964f7c1e6e90364932cc8a4ea035d123dd4e2a8a61fb6a7df130e590` |
| Family label | `unknown` |
| File name | `Launcher.zip` |
| File type | `zip` |
| First seen | `2026-06-22 02:28:44` |
| Reporter | `Epenko1337` |
| Tags | `dropper, lua, SmartLoader, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec130731ffe1aa6f6f2367a5134715a3` |
| SHA-256 | `7ba980da964f7c1e6e90364932cc8a4ea035d123dd4e2a8a61fb6a7df130e590` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_7ba980da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ba980da964f7c1e6e90364932cc8a4ea035d123dd4e2a8a61fb6a7df130e590"
    family = "unknown"
    file_name = "Launcher.zip"
    file_type = "zip"
    first_seen = "2026-06-22 02:28:44"
  condition:
    hash.sha256(0, filesize) == "7ba980da964f7c1e6e90364932cc8a4ea035d123dd4e2a8a61fb6a7df130e590"
}
```

### Sample 53: `2c5260360de10f21`

| Field | Value |
|---|---|
| SHA-256 | `2c5260360de10f214b6ed6b612ad463bb5341ffd17d4900b50bf607d4e94d17e` |
| Family label | `unknown` |
| File name | `loader.zip` |
| File type | `zip` |
| First seen | `2026-06-22 02:17:16` |
| Reporter | `Kejult` |
| Tags | `bun, exe, NWHStealer, stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `818f02e595eb7faa11e0812a11c4a110` |
| SHA-1 | `2590e55014369f1cc7280596d52e147f3da07065` |
| SHA-256 | `2c5260360de10f214b6ed6b612ad463bb5341ffd17d4900b50bf607d4e94d17e` |
| SHA3-384 | `067be861ab81666385316c54b49585c64b3067f2b5bc4d5d35ca9ea0c169341abb2ecbc1124c581bbe89ed78b4e162f4` |
| TLSH | `T11F9733DCCD17164FD4F2783786A5FEDAD7C980A0C4A74933646EC36B0ACB9DA211688D` |
| SSDEEP | `786432:4GycAlwvZlDIHlBCQhRbCZPULyNQ9ELFMNk4Sd4ZqgQqiyGnJrqPEkMwDAH+n:9ILCQhVCZPq4YUtFKxONqPzMwUen` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_2c526036
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c5260360de10f214b6ed6b612ad463bb5341ffd17d4900b50bf607d4e94d17e"
    family = "unknown"
    file_name = "loader.zip"
    file_type = "zip"
    first_seen = "2026-06-22 02:17:16"
  condition:
    hash.sha256(0, filesize) == "2c5260360de10f214b6ed6b612ad463bb5341ffd17d4900b50bf607d4e94d17e"
}
```

### Sample 54: `967e1665f6935556`

| Field | Value |
|---|---|
| SHA-256 | `967e1665f6935556bdaf20d9060eb03d45382a5c0dd232675daac3c6962e2a86` |
| Family label | `unknown` |
| File name | `YimMenuV2.dll` |
| File type | `exe` |
| First seen | `2026-06-22 02:07:35` |
| Reporter | `Kejult` |
| Tags | `dll, exe, GameHack, Riskware` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51a41100fbe14088241bc9a977c820a8` |
| SHA-1 | `c7992d4bc8a2018578a46741548f53aa6a81ad88` |
| SHA-256 | `967e1665f6935556bdaf20d9060eb03d45382a5c0dd232675daac3c6962e2a86` |
| SHA3-384 | `583beb5e2aa4fb2a535f0bfb1de89324afb427d689d916ff9aceb03dc61fb7f37475f3b673b9a421f221fbbe166a0442` |
| IMPHASH | `8c26864f747d8de2cfcda33d420fe52c` |
| TLSH | `T16A667D077E4AA43CC116C6B1A24F4E679D35B4CA1B207CDF86C4A3782E71BF54B3A949` |
| SSDEEP | `98304:w001OmCbfUNjX5hJPQkJdt20PGZyDX+R:w0eBCAByqBG8Ts` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_967e1665
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "967e1665f6935556bdaf20d9060eb03d45382a5c0dd232675daac3c6962e2a86"
    family = "unknown"
    file_name = "YimMenuV2.dll"
    file_type = "exe"
    first_seen = "2026-06-22 02:07:35"
  condition:
    hash.sha256(0, filesize) == "967e1665f6935556bdaf20d9060eb03d45382a5c0dd232675daac3c6962e2a86"
}
```

### Sample 55: `3898a662f25925b6`

| Field | Value |
|---|---|
| SHA-256 | `3898a662f25925b6b46700297832940cfc026f5e59815fe670328a0213094a3b` |
| Family label | `unknown` |
| File name | `Requirement.vbs` |
| File type | `vbs` |
| First seen | `2026-06-22 02:03:33` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `862ce69fbc11bac8f9f122cd40967f63` |
| SHA-1 | `7f574cc31b6a54f454d962344969a55bf64f8afb` |
| SHA-256 | `3898a662f25925b6b46700297832940cfc026f5e59815fe670328a0213094a3b` |
| SHA3-384 | `215f5ee11aac8ab859788a7a29e5066915c11f7b0f8473ffb028f8d86a9feac20a5caac28ebf1e4b1368dfd9931593cc` |
| TLSH | `T106934A21CE6403994E4B17EDFC961A61C9BDC619013310F5FEEA170D600A9ACF7BEA6D` |
| SSDEEP | `1536:v2A74T55qnFOTrslIasg2iE+ZQOAKvLhZjucflo1pkJUzQfH:vB74T5MO3lipZQOAKjTjuIo1WUzQfH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_3898a662
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3898a662f25925b6b46700297832940cfc026f5e59815fe670328a0213094a3b"
    family = "unknown"
    file_name = "Requirement.vbs"
    file_type = "vbs"
    first_seen = "2026-06-22 02:03:33"
  condition:
    hash.sha256(0, filesize) == "3898a662f25925b6b46700297832940cfc026f5e59815fe670328a0213094a3b"
}
```

### Sample 56: `0b8cae277bf0e3f0`

| Field | Value |
|---|---|
| SHA-256 | `0b8cae277bf0e3f0f33c5c44e5fd0dac50278086dd5769f9d96c44d748d8a90b` |
| Family label | `SalatStealer` |
| File name | `SynInstallerV2.exe` |
| File type | `exe` |
| First seen | `2026-06-22 02:00:44` |
| Reporter | `Kejult` |
| Tags | `downloader, exe, loader, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72cc8e3d5bb03a4ee445735a529f2e58` |
| SHA-1 | `951bf64ab8bb44148d29ea2ad3499f706d55e711` |
| SHA-256 | `0b8cae277bf0e3f0f33c5c44e5fd0dac50278086dd5769f9d96c44d748d8a90b` |
| SHA3-384 | `30435fef056587db68d5c6a7ec357bdd716fe87e9f99bcb1564826b604be15482f42d6355dc04101d7225dd714a61650` |
| IMPHASH | `ff8df06a6509fbcb86f708535c6adc45` |
| TLSH | `T17606330B695045F9CC858D30C3959776A23274970B251EFB2BF0B0BD7AFA8E15AB2770` |
| SSDEEP | `98304:IVVMMrfvgSSg+g5NjyIwf1OyIwZ8FoKHb57:QVMMr15+gPnHTwtK757` |
| ICON-DHASH | `71f81c7861c2e170` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_056_0b8cae27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8cae277bf0e3f0f33c5c44e5fd0dac50278086dd5769f9d96c44d748d8a90b"
    family = "SalatStealer"
    file_name = "SynInstallerV2.exe"
    file_type = "exe"
    first_seen = "2026-06-22 02:00:44"
  condition:
    hash.sha256(0, filesize) == "0b8cae277bf0e3f0f33c5c44e5fd0dac50278086dd5769f9d96c44d748d8a90b"
}
```

### Sample 57: `e9b9e9b3ba47548c`

| Field | Value |
|---|---|
| SHA-256 | `e9b9e9b3ba47548c9f0937837bf16550f573c25f7405e8cfbf45519d79ccde4e` |
| Family label | `GuLoader` |
| File name | `rDirectricesdepol__ticasparaempleados_2026_pdf.exe` |
| File type | `exe` |
| First seen | `2026-06-22 02:00:07` |
| Reporter | `fabiodemartin` |
| Tags | `exe, GuLoader, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0e14b749d6ea74efedde6ca496b45d0` |
| SHA-1 | `a0a473dd0296e295d3802c77bbe5766ffb333b0b` |
| SHA-256 | `e9b9e9b3ba47548c9f0937837bf16550f573c25f7405e8cfbf45519d79ccde4e` |
| SHA3-384 | `5fe7050637bad551410a1f0dfd068d051e4323f71f1c458ebd2bdd8affa388fda7aa4b84c7d16a8160415710148779a3` |
| IMPHASH | `6e7f9a29f2c85394521a08b9f31f6275` |
| TLSH | `T1E674126161E5D87AC9645731DC3A07FAA485FD1AC4B48A0B73C17E6939B13C2EE0EB24` |
| SSDEEP | `6144:IMm4CCEv3liZFEDwxQRy4Cm4k2WQ5s9PxVVuVGNZJWG7JtmkfCTydOjkY3NAC:IMw3v3lisDpRfr4c6iPxVVuVG577mkfy` |
| ICON-DHASH | `e4c4cec6c4c4e4f4` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_057_e9b9e9b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9b9e9b3ba47548c9f0937837bf16550f573c25f7405e8cfbf45519d79ccde4e"
    family = "GuLoader"
    file_name = "rDirectricesdepol__ticasparaempleados_2026_pdf.exe"
    file_type = "exe"
    first_seen = "2026-06-22 02:00:07"
  condition:
    hash.sha256(0, filesize) == "e9b9e9b3ba47548c9f0937837bf16550f573c25f7405e8cfbf45519d79ccde4e"
}
```

### Sample 58: `273ec09aec45d6a7`

| Field | Value |
|---|---|
| SHA-256 | `273ec09aec45d6a7996f61e2d4fca07bea84a00f3544fad64091c239f4d93312` |
| Family label | `unknown` |
| File name | `app1f.exe` |
| File type | `exe` |
| First seen | `2026-06-22 01:56:10` |
| Reporter | `Kejult` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `158aa7ed51ab2b75ceb37d9b4aa02a7f` |
| SHA-1 | `4a6e763dc386bdac25a3c93e0c057ccffcffd660` |
| SHA-256 | `273ec09aec45d6a7996f61e2d4fca07bea84a00f3544fad64091c239f4d93312` |
| SHA3-384 | `f390d0166272db6fe41853e3c7525e997e69d8b25deefb1a2ab27004f39eb37f7daafed1eaafeb0623df99ac66d42f64` |
| IMPHASH | `1ad721fd16e1c587fb1df68e5a8a9e9a` |
| TLSH | `T14472E84D378244FDC916C5B4E6FB5B75EAB1B80115101B3E4720E73B1EB0AB0AE7EA49` |
| SSDEEP | `192:uMrKqtE8IRPGA76jJm18iqehNE2efWEQiYAmTCMa6Q7XXSDa5KS62PqTyusqq22:uqgR+Bm18avEBdQtw5KDnTynqqT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_273ec09a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "273ec09aec45d6a7996f61e2d4fca07bea84a00f3544fad64091c239f4d93312"
    family = "unknown"
    file_name = "app1f.exe"
    file_type = "exe"
    first_seen = "2026-06-22 01:56:10"
  condition:
    hash.sha256(0, filesize) == "273ec09aec45d6a7996f61e2d4fca07bea84a00f3544fad64091c239f4d93312"
}
```

### Sample 59: `a1c6e89e932a2d62`

| Field | Value |
|---|---|
| SHA-256 | `a1c6e89e932a2d62b1b2bd848b96e8873d78f324dbfaaca5a2f93d218b47d12f` |
| Family label | `unknown` |
| File name | `Setup.bat` |
| File type | `bat` |
| First seen | `2026-06-22 01:50:57` |
| Reporter | `Kejult` |
| Tags | `bat, downloader, loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdec09e16d03e834d877346f8ebebb8a` |
| SHA-1 | `e94268390a6afe537614d59f86e8c95b7b459051` |
| SHA-256 | `a1c6e89e932a2d62b1b2bd848b96e8873d78f324dbfaaca5a2f93d218b47d12f` |
| SHA3-384 | `055bf13c0906fecf8c229c593a5e76ce7d72294e021fcae2466c7f4ee903367815b793f6382c6a4d882a9cb91bb5c263` |
| TLSH | `T17031230F12E4C019D6D247B64E3939847DAFC2C78730D9C6322EF1298E5A4938EF65D9` |
| SSDEEP | `48:F88X7k9mD7w47xpO+1S2DqTD5+1y2D5dX:F88X7kWc4j2fmzX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_a1c6e89e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1c6e89e932a2d62b1b2bd848b96e8873d78f324dbfaaca5a2f93d218b47d12f"
    family = "unknown"
    file_name = "Setup.bat"
    file_type = "bat"
    first_seen = "2026-06-22 01:50:57"
  condition:
    hash.sha256(0, filesize) == "a1c6e89e932a2d62b1b2bd848b96e8873d78f324dbfaaca5a2f93d218b47d12f"
}
```

### Sample 60: `f9814cb4822b66a5`

| Field | Value |
|---|---|
| SHA-256 | `f9814cb4822b66a5ad8a479656a2fff57ad90d1294a0c4265ae9ab61ac173b80` |
| Family label | `Vidar` |
| File name | `WandEnhancer.exe` |
| File type | `exe` |
| First seen | `2026-06-22 01:33:22` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f724ccfa36870ebfb208d2fcca886fba` |
| SHA-1 | `28461a1b13c0a4287dcb9c8cd76e5aead9335c35` |
| SHA-256 | `f9814cb4822b66a5ad8a479656a2fff57ad90d1294a0c4265ae9ab61ac173b80` |
| SHA3-384 | `f44feb334e37422746fca0f388a4a730430f237079f4894da978435531c166bf8b614d449d48731e65d07f6490849b81` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A2F57B06FC9608FAD49AA23289B29656B775BC080F3227E36E9077783F727C45C39715` |
| SSDEEP | `49152:uz4QF1aIIZYXdCA7ANEw5R6bfhmu1QxtUoZkpNa7OCss7w:uhwAq2bhd1q+oZkpNa7OCsV` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_060_f9814cb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9814cb4822b66a5ad8a479656a2fff57ad90d1294a0c4265ae9ab61ac173b80"
    family = "Vidar"
    file_name = "WandEnhancer.exe"
    file_type = "exe"
    first_seen = "2026-06-22 01:33:22"
  condition:
    hash.sha256(0, filesize) == "f9814cb4822b66a5ad8a479656a2fff57ad90d1294a0c4265ae9ab61ac173b80"
}
```

### Sample 61: `1f3e92fb275fbea7`

| Field | Value |
|---|---|
| SHA-256 | `1f3e92fb275fbea7f31629cfc5621c0e190d0ac7f97bde500b8c029ae2fa1fd1` |
| Family label | `GuLoader` |
| File name | `nxEDticas_para_empleados_2026_pdf.bz2` |
| File type | `rar` |
| First seen | `2026-06-22 01:31:13` |
| Reporter | `fabiodemartin` |
| Tags | `GuLoader, rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62ed34cc988cbb5781823b067fa82522` |
| SHA-1 | `4d1d672c040b57ed7e5ec3b1931f476331621216` |
| SHA-256 | `1f3e92fb275fbea7f31629cfc5621c0e190d0ac7f97bde500b8c029ae2fa1fd1` |
| SHA3-384 | `bf783308ff2c6cdb15255594f2cde04a464c3157f100814b1119a4fa0af8a92d33a0a8b80ce187218db3149048eb9b76` |
| TLSH | `T1FA742354E800CC3A6FB699F6136391E123AA2D8872F7A1D67DFDD9356A3406CE5380DC` |
| SSDEEP | `6144:BG/aNAAw3HQFRdMvwEq5SIEE2ylgI4yco8K7hsqm+IltnDO49qSs+uTny/8pd:aXAmH2RdMvwEqjwylVMaffIldKAqSsjh` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_061_1f3e92fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f3e92fb275fbea7f31629cfc5621c0e190d0ac7f97bde500b8c029ae2fa1fd1"
    family = "GuLoader"
    file_name = "nxEDticas_para_empleados_2026_pdf.bz2"
    file_type = "rar"
    first_seen = "2026-06-22 01:31:13"
  condition:
    hash.sha256(0, filesize) == "1f3e92fb275fbea7f31629cfc5621c0e190d0ac7f97bde500b8c029ae2fa1fd1"
}
```

### Sample 62: `6f0219fb61984586`

| Field | Value |
|---|---|
| SHA-256 | `6f0219fb619845864f18d8dbe093e323fe6bd9a314e10c5affe9549024029b70` |
| Family label | `NanoCore` |
| File name | `skyupdragon.io.exe` |
| File type | `exe` |
| First seen | `2026-06-22 01:25:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c02df52470306dd140e1e93f2e6abd01` |
| SHA-1 | `acfcec5f46e7213c0c4f939fdc181c3e117b97ec` |
| SHA-256 | `6f0219fb619845864f18d8dbe093e323fe6bd9a314e10c5affe9549024029b70` |
| SHA3-384 | `5b5ecbd68f04b883d9af993e1e898310bc8a37c421b8dc758a0f8473e1a3425f8c8f3da661576e19f43a99b222510428` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F8C402467BA9892FE28F85B9601142570379C2E299D3F3EEACD814F25F162F10B1B1D7` |
| SSDEEP | `12288:5LV6BtpmkuMQuET3qGbOQ1YiraHeW9IsJT346S:BApfFO6mOQ1Y0WT9I8TI7` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_062_6f0219fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f0219fb619845864f18d8dbe093e323fe6bd9a314e10c5affe9549024029b70"
    family = "NanoCore"
    file_name = "skyupdragon.io.exe"
    file_type = "exe"
    first_seen = "2026-06-22 01:25:05"
  condition:
    hash.sha256(0, filesize) == "6f0219fb619845864f18d8dbe093e323fe6bd9a314e10c5affe9549024029b70"
}
```

### Sample 63: `d71d22dc0f225dd4`

| Field | Value |
|---|---|
| SHA-256 | `d71d22dc0f225dd41a6bf2571b8206b378a87358d429d8f3a3b4119d59f407d5` |
| Family label | `Vidar` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-06-22 01:21:01` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28e8e2568c7b4416c1ada52b14cc5441` |
| SHA-1 | `8066ca1f3fc9148521d5ade268c90e4b88165862` |
| SHA-256 | `d71d22dc0f225dd41a6bf2571b8206b378a87358d429d8f3a3b4119d59f407d5` |
| SHA3-384 | `43fb38d040597cdd89988cffd0265e95794829a1fbd09293b536925c79a73fe631cad671f96db05abee3e764375731df` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T19EF56B07FD9509F9C4AAA33289B25582BB70BC051B312BE72EA077793E72BD06C35754` |
| SSDEEP | `49152:xRkhP5jMRJIa7KJ8KYuMZ6bDTP8yNyqG+wVicPRkIs0mP:xeuWah6LP8yNyl+AicPHM` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_063_d71d22dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d71d22dc0f225dd41a6bf2571b8206b378a87358d429d8f3a3b4119d59f407d5"
    family = "Vidar"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-22 01:21:01"
  condition:
    hash.sha256(0, filesize) == "d71d22dc0f225dd41a6bf2571b8206b378a87358d429d8f3a3b4119d59f407d5"
}
```

### Sample 64: `dd57db91a672c689`

| Field | Value |
|---|---|
| SHA-256 | `dd57db91a672c68953f58462b9e386591f6731c6ee1ec1b699d29b62d4c18572` |
| Family label | `Vidar` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-06-22 01:14:29` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b52777c279f46bac0590a0af8b279ac` |
| SHA-1 | `0f6e109bb5036a7008356e5e491489b3045adb34` |
| SHA-256 | `dd57db91a672c68953f58462b9e386591f6731c6ee1ec1b699d29b62d4c18572` |
| SHA3-384 | `1cfb3e628ec11bf0f1cf46d10222d6806ac9b80f23911fa9aed0cce3b7d81dd8733a32004fbc0bb38c1daebd12cc7941` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T12EF58D02BDA509EAC05AA23288B751927B75BC491F3127D72F90B7B82FB37D05C36B54` |
| SSDEEP | `49152:4c+kMm5gkLtxovZ2WAFPjDECIX5+6VvZCrN:4ltZ6DECIX5+61kN` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_064_dd57db91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd57db91a672c68953f58462b9e386591f6731c6ee1ec1b699d29b62d4c18572"
    family = "Vidar"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-22 01:14:29"
  condition:
    hash.sha256(0, filesize) == "dd57db91a672c68953f58462b9e386591f6731c6ee1ec1b699d29b62d4c18572"
}
```

### Sample 65: `2a611c288e28b6da`

| Field | Value |
|---|---|
| SHA-256 | `2a611c288e28b6da39219263ae00cb2a7ae710d2fbce76f5668c423f593dfc06` |
| Family label | `unknown` |
| File name | `2a611c288e28b6da39219263ae00cb2a7ae710d2fbce76f5668c423f593dfc06` |
| File type | `unknown` |
| First seen | `2026-06-22 01:01:05` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c4f3981f9716876c79286ef133c9a4b` |
| SHA-256 | `2a611c288e28b6da39219263ae00cb2a7ae710d2fbce76f5668c423f593dfc06` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_2a611c28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a611c288e28b6da39219263ae00cb2a7ae710d2fbce76f5668c423f593dfc06"
    family = "unknown"
    file_name = "2a611c288e28b6da39219263ae00cb2a7ae710d2fbce76f5668c423f593dfc06"
    file_type = "unknown"
    first_seen = "2026-06-22 01:01:05"
  condition:
    hash.sha256(0, filesize) == "2a611c288e28b6da39219263ae00cb2a7ae710d2fbce76f5668c423f593dfc06"
}
```

### Sample 66: `ed8060fe81b7f729`

| Field | Value |
|---|---|
| SHA-256 | `ed8060fe81b7f72936bdda1f1fbb83a96084ad28082ddacb88a59a48b1db0ab5` |
| Family label | `unknown` |
| File name | `Cs2Hack.exe` |
| File type | `exe` |
| First seen | `2026-06-22 00:58:42` |
| Reporter | `Kejult` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac802a6a3fc75926145fd519d8631baa` |
| SHA-1 | `09b15a9014dd9bf94f4afce2b5980c1a58cd38bf` |
| SHA-256 | `ed8060fe81b7f72936bdda1f1fbb83a96084ad28082ddacb88a59a48b1db0ab5` |
| SHA3-384 | `2fa253d8197717c350cc7d09bec5a2dee31a139a648992b0b9785a8f21528dfffc7e77ea383c0ea8bf44d15c89d028c8` |
| IMPHASH | `a5aafbc9f7097539c906c7c235ab5ad4` |
| TLSH | `T10CE623D97A8411D4C49309B0B69A93ED32C0BD5D45ED4E2F39C62D03AF51CEF290AEA7` |
| SSDEEP | `393216:aFWW3ekoc88osa+qwmqufi7Yhp8MefxNAnR2qZy6C7:DW198Ua+qwmquZZePARbY` |
| ICON-DHASH | `00c8f8e0e8f0dc00` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_ed8060fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed8060fe81b7f72936bdda1f1fbb83a96084ad28082ddacb88a59a48b1db0ab5"
    family = "unknown"
    file_name = "Cs2Hack.exe"
    file_type = "exe"
    first_seen = "2026-06-22 00:58:42"
  condition:
    hash.sha256(0, filesize) == "ed8060fe81b7f72936bdda1f1fbb83a96084ad28082ddacb88a59a48b1db0ab5"
}
```

### Sample 67: `dd2fb463fd8857ce`

| Field | Value |
|---|---|
| SHA-256 | `dd2fb463fd8857ce858b96a6b2ec88ebbc2fd724b82a591f69576614f8c81e5b` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-06-22 00:48:30` |
| Reporter | `Kejult` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de786e27c860ef6f357ef831417ef3e3` |
| SHA-1 | `c5a157801a7bda0cc1a9cc3545f52e5b0e893e82` |
| SHA-256 | `dd2fb463fd8857ce858b96a6b2ec88ebbc2fd724b82a591f69576614f8c81e5b` |
| SHA3-384 | `d328c0cb0c6203faf5b42ebeb118003dd3acb9992b2052bde75f0fcea0ea197d88bc86af7bb20353c85c902ca64db7ce` |
| IMPHASH | `e3a511be552b442d33e172edc95820fa` |
| TLSH | `T17845DF03BF50D546D18A2E7489B4C7F92320FC499A65934B34EABE1BBDDE2C39D122C4` |
| SSDEEP | `24576:7yOaX5HT9gFGconk2dHdnc2UiSjCne7ZzqWMaTUdSLc3eSJ2Q9Lb:7yOaXAF0n5cvNvlqaTASL+eSJ2E` |
| ICON-DHASH | `30f0ccccccccf030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_dd2fb463
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd2fb463fd8857ce858b96a6b2ec88ebbc2fd724b82a591f69576614f8c81e5b"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-22 00:48:30"
  condition:
    hash.sha256(0, filesize) == "dd2fb463fd8857ce858b96a6b2ec88ebbc2fd724b82a591f69576614f8c81e5b"
}
```

### Sample 68: `401fa3c82b2b7705`

| Field | Value |
|---|---|
| SHA-256 | `401fa3c82b2b7705753063bc7ea3e752b4bf4939736ea6d5949456a0e0407f64` |
| Family label | `Vidar` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-06-22 00:47:04` |
| Reporter | `Kejult` |
| Tags | `dll, exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e46aca74f19eb406c442e5d28edbdaea` |
| SHA-1 | `ab69678a9c1ab8f7e0994fa1a8ca5213f08bb5e4` |
| SHA-256 | `401fa3c82b2b7705753063bc7ea3e752b4bf4939736ea6d5949456a0e0407f64` |
| SHA3-384 | `11124c44f89e48af8fd4decb012a7700f54784bbcd2d9eb519b192b135222e399470ebb5a7728b078937cb971526df9b` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T11006AE07EFA148B9C497A23188A256817B3CBC491B263BD72F9077762F763C06D36764` |
| SSDEEP | `49152:RxM9PTMKJyspg1uwxLBYaEqxQbX++yaQTqDTbCC:RWQlxAyQbOY623CC` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_068_401fa3c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "401fa3c82b2b7705753063bc7ea3e752b4bf4939736ea6d5949456a0e0407f64"
    family = "Vidar"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-06-22 00:47:04"
  condition:
    hash.sha256(0, filesize) == "401fa3c82b2b7705753063bc7ea3e752b4bf4939736ea6d5949456a0e0407f64"
}
```

### Sample 69: `7a913722f58debf7`

| Field | Value |
|---|---|
| SHA-256 | `7a913722f58debf79258bce36700ee2628f866c81e80bfeb8e1d86a8c42a3a51` |
| Family label | `unknown` |
| File name | `MacOS.Setup.dmg` |
| File type | `dmg` |
| First seen | `2026-06-22 00:45:48` |
| Reporter | `Kejult` |
| Tags | `dmg, macos` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b91737bc193f862bd2e1e11b5716e13` |
| SHA-1 | `6832d096ab47bbdd3f1c001930cf536afe2018fc` |
| SHA-256 | `7a913722f58debf79258bce36700ee2628f866c81e80bfeb8e1d86a8c42a3a51` |
| SHA3-384 | `923f9ea0e48fc5ba27e1cec64b8fcf67ed26ae8a875f0426ad7b3ebd9d6a4a47af4062cafeb1d03dd1e979cbe9efe493` |
| TLSH | `T10EB44B376E296D84DF950FFF8122D5628DD8EAC7A0A5C0E5BC400941BEE97C4F968363` |
| SSDEEP | `6144:8FIRhqO1ViVAj4Z4F7fa72/0O+IL4YCeWj1lPms/:8GBC9Z4la72MONcYAj1//` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dmg`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_7a913722
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a913722f58debf79258bce36700ee2628f866c81e80bfeb8e1d86a8c42a3a51"
    family = "unknown"
    file_name = "MacOS.Setup.dmg"
    file_type = "dmg"
    first_seen = "2026-06-22 00:45:48"
  condition:
    hash.sha256(0, filesize) == "7a913722f58debf79258bce36700ee2628f866c81e80bfeb8e1d86a8c42a3a51"
}
```

### Sample 70: `27be02890b7e55b8`

| Field | Value |
|---|---|
| SHA-256 | `27be02890b7e55b800c6b5cdab16f66af68246472644a2127a564f04f62cde25` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-22 00:43:09` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96ba02421f8b40e0f8ac834b3db0f309` |
| SHA-1 | `15e0fb07a24ce0cb647df8ac104f2e5c3c8905cd` |
| SHA-256 | `27be02890b7e55b800c6b5cdab16f66af68246472644a2127a564f04f62cde25` |
| SHA3-384 | `6fe0e4214308fa123944c4559ccb06b8f22f8e85465790db5f58e99524d6f7a21bdc99b6a66f62d156d3f5686f4ef76b` |
| IMPHASH | `c129097361b8295c6461feaed5b0ddf4` |
| TLSH | `T15A45AEEA1E1F11B1CCD6E8B96A1010E3789552966DC2D8DC96DAFF0D2BD784C22F3B41` |
| SSDEEP | `24576:Pk/rVwkuxQuix2KuD8HQ1/D9kIW3RETcJJbghuDxMZJyJx:sJuxvuuDNR4ETcJJbGoxM0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_27be0289
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27be02890b7e55b800c6b5cdab16f66af68246472644a2127a564f04f62cde25"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-22 00:43:09"
  condition:
    hash.sha256(0, filesize) == "27be02890b7e55b800c6b5cdab16f66af68246472644a2127a564f04f62cde25"
}
```

### Sample 71: `f173bf9573df7fe9`

| Field | Value |
|---|---|
| SHA-256 | `f173bf9573df7fe9137d8c9a4fbac2b108187a250ee9b830ec3873bccd4ea10c` |
| Family label | `Vidar` |
| File name | `loader.exe` |
| File type | `exe` |
| First seen | `2026-06-22 00:42:12` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b9a7a4f3b2961ee4a9a22d43611357c` |
| SHA-1 | `1158a25ac26cfda2289bab9691ff4b556f96ea96` |
| SHA-256 | `f173bf9573df7fe9137d8c9a4fbac2b108187a250ee9b830ec3873bccd4ea10c` |
| SHA3-384 | `6a8248c76e3fe017543609bd586e8b0bb204c99d6702f34ed9cdaada6bde80fef03014b3d582a57bc0d325e0d5002291` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T115F57C07ECD249EAC0A9A3718ABB9582B771B8091F3227D32D50B3382F767D49D75718` |
| SSDEEP | `24576:zqJU4d8s9xh25fYZnhc6ML2CdVOTXWAXCKMhrm2Rw6NRMX/smJKKdhNRXSLWORAD:zqJR+6xgRY1KbNOBQxR/URLwZ8SCl` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_071_f173bf95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f173bf9573df7fe9137d8c9a4fbac2b108187a250ee9b830ec3873bccd4ea10c"
    family = "Vidar"
    file_name = "loader.exe"
    file_type = "exe"
    first_seen = "2026-06-22 00:42:12"
  condition:
    hash.sha256(0, filesize) == "f173bf9573df7fe9137d8c9a4fbac2b108187a250ee9b830ec3873bccd4ea10c"
}
```

### Sample 72: `30a67224d05ec98f`

| Field | Value |
|---|---|
| SHA-256 | `30a67224d05ec98f9412a89018bfebe705d55d36a66e1acaf633713e65f322f8` |
| Family label | `unknown` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-06-22 00:33:11` |
| Reporter | `Kejult` |
| Tags | `dll, exe, signed, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55a2bc9a672184ab0657983b7a8ee391` |
| SHA-1 | `8bd83a23b58f0cc3188b4ad1d347f927cc5f7299` |
| SHA-256 | `30a67224d05ec98f9412a89018bfebe705d55d36a66e1acaf633713e65f322f8` |
| SHA3-384 | `2177f7290eaf838535bebb13fe309e6fdec80543693f9534bddfac4ff21156b4e798592b7193bdb7ab03222028df06f3` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1C326AF07EED54869C49AA23188A39391777CFC441B3237D73F90B6BA2E72BD05A36714` |
| SSDEEP | `98304:ELU6IsRLF7WB9JlzU0wbUxp9X6yIdBxCCw:EYRKLFWB9JR0Ujl678` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_30a67224
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30a67224d05ec98f9412a89018bfebe705d55d36a66e1acaf633713e65f322f8"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-06-22 00:33:11"
  condition:
    hash.sha256(0, filesize) == "30a67224d05ec98f9412a89018bfebe705d55d36a66e1acaf633713e65f322f8"
}
```

### Sample 73: `801e5217b0436f25`

| Field | Value |
|---|---|
| SHA-256 | `801e5217b0436f2531b40777da305d5017d6db19b545db051d82c9910f9d223d` |
| Family label | `unknown` |
| File name | `libcurl.dll` |
| File type | `exe` |
| First seen | `2026-06-22 00:27:23` |
| Reporter | `Kejult` |
| Tags | `dll, exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08ff492d3f19596a9b5b0fc308e88f88` |
| SHA-1 | `6cec4e201d3e58cc108be7f8f215508ccbddf331` |
| SHA-256 | `801e5217b0436f2531b40777da305d5017d6db19b545db051d82c9910f9d223d` |
| SHA3-384 | `da7b28bbdf97ef3b5e1a9867c021b1dbc05eaeefbadd2524646847718c2e6021211b57eb36d5c4dfadcbad0f5419c272` |
| IMPHASH | `d9cdd14f1e51bf231e8fd705275c2c8a` |
| TLSH | `T1C2267D2271455DA9CD13CFBC7026CF85AE69ADF2BA420123A1F5D3A460EB39049DDF2D` |
| SSDEEP | `24576:dSE3hORgdNga3OcqyAiH0ydNAoGCBQlDobvGj7WAt:d3hORnfydWCjGjz` |
| ICON-DHASH | `9270f8e8e8f03194` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_801e5217
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "801e5217b0436f2531b40777da305d5017d6db19b545db051d82c9910f9d223d"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-06-22 00:27:23"
  condition:
    hash.sha256(0, filesize) == "801e5217b0436f2531b40777da305d5017d6db19b545db051d82c9910f9d223d"
}
```

### Sample 74: `19d7901717a2bb73`

| Field | Value |
|---|---|
| SHA-256 | `19d7901717a2bb73ff855bc3e5e652305aa97bd9bb9584ee6efd1b8dc9c5426b` |
| Family label | `unknown` |
| File name | `gup_util.dll` |
| File type | `exe` |
| First seen | `2026-06-22 00:26:51` |
| Reporter | `Kejult` |
| Tags | `dll, exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `376fdb7bf467b3f48fd206bae7e573c9` |
| SHA-1 | `1c0561e53024e81e4356590a55fad2c76ff88435` |
| SHA-256 | `19d7901717a2bb73ff855bc3e5e652305aa97bd9bb9584ee6efd1b8dc9c5426b` |
| SHA3-384 | `b8c41c01f6cb06ab98ae48a3bccdfb18ad51e72a4b0275785cfb51b5f0312e32367f1f9430affb7f2dc1fb0174136c17` |
| IMPHASH | `4d791c7ff8a04656c4df23bdb9ebb892` |
| TLSH | `T1AED56C07FCE148BAD4AA963189729261BB31BC442F3223D72A90BB783FB77D05935754` |
| SSDEEP | `24576:UTh0RtDIR0Zv8NbeAwlvguPC1U1Dgl0wCbfUjrAq6PMU49mESBeleDQaFSbla4KZ:UThqJI2v8N6ASNa1EZ1wrAq6PORhji` |
| ICON-DHASH | `54b279e84c696900` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_19d79017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19d7901717a2bb73ff855bc3e5e652305aa97bd9bb9584ee6efd1b8dc9c5426b"
    family = "unknown"
    file_name = "gup_util.dll"
    file_type = "exe"
    first_seen = "2026-06-22 00:26:51"
  condition:
    hash.sha256(0, filesize) == "19d7901717a2bb73ff855bc3e5e652305aa97bd9bb9584ee6efd1b8dc9c5426b"
}
```

### Sample 75: `74bc14dbea1315b1`

| Field | Value |
|---|---|
| SHA-256 | `74bc14dbea1315b1d953c16382b3373233aa245b9b6ab5301a9f6943c0a67887` |
| Family label | `NanoCore` |
| File name | `2f6a5ce3a14122f2cdfc94278106037e.exe` |
| File type | `exe` |
| First seen | `2026-06-22 00:25:04` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f6a5ce3a14122f2cdfc94278106037e` |
| SHA-1 | `ee62b5a594eb90a1a6e251ccdf8a93dbbfb4e577` |
| SHA-256 | `74bc14dbea1315b1d953c16382b3373233aa245b9b6ab5301a9f6943c0a67887` |
| SHA3-384 | `e33d2d2788c57361b223ffd71670e936efdb7abda595190e40fe1034222024dca8c771b92df4cdaadb587374d0dd9fc3` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D114CF5677A84A2FE2DE867D612212169379C2E39CC3F3DE28D455B78F267E00A071D3` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5d6V2qhLyNPYTbEjr:MLV6BtpmkSM2uL4YTq` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_075_74bc14db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74bc14dbea1315b1d953c16382b3373233aa245b9b6ab5301a9f6943c0a67887"
    family = "NanoCore"
    file_name = "2f6a5ce3a14122f2cdfc94278106037e.exe"
    file_type = "exe"
    first_seen = "2026-06-22 00:25:04"
  condition:
    hash.sha256(0, filesize) == "74bc14dbea1315b1d953c16382b3373233aa245b9b6ab5301a9f6943c0a67887"
}
```

### Sample 76: `77276fd72e3394ab`

| Field | Value |
|---|---|
| SHA-256 | `77276fd72e3394ab7daf64241538e56fe4e742d6e6d1c8649fdff48012a1e6e6` |
| Family label | `unknown` |
| File name | `HSBC_PAYMENT_ADVICEpdf.js` |
| File type | `js` |
| First seen | `2026-06-22 00:00:37` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `171581b5985cc62267113330699b461f` |
| SHA-1 | `eb3673f84d050e05329499fbc6e762c3e663012a` |
| SHA-256 | `77276fd72e3394ab7daf64241538e56fe4e742d6e6d1c8649fdff48012a1e6e6` |
| SHA3-384 | `6637745bef158e409dac89a93334ffe01afb979dd18388ac762b15163b9baf3cf7d2794a317536d57da2b3e3599a6a5a` |
| TLSH | `T1C79501014AC42FE48BAD5B2D50BF255EE3E00E8E6855658FE733FD47EFA760052162B8` |
| SSDEEP | `24576:VNUnT/XbmMgVgbt2xy7fffBrHQiCtWPVFO98zWbyYGA7qINVICG:XobH5eM3CG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_77276fd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77276fd72e3394ab7daf64241538e56fe4e742d6e6d1c8649fdff48012a1e6e6"
    family = "unknown"
    file_name = "HSBC_PAYMENT_ADVICEpdf.js"
    file_type = "js"
    first_seen = "2026-06-22 00:00:37"
  condition:
    hash.sha256(0, filesize) == "77276fd72e3394ab7daf64241538e56fe4e742d6e6d1c8649fdff48012a1e6e6"
}
```

### Sample 77: `8f24897afca9c8fd`

| Field | Value |
|---|---|
| SHA-256 | `8f24897afca9c8fd5a48a78d6ab1476eafb18e7721e7772df114da4f58e1eac1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-21 22:48:40` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f4b9d3c78457ec9a1d0249696e6d131` |
| SHA-1 | `24e797df4c7f078341d7011e0f97f3ead6aff674` |
| SHA-256 | `8f24897afca9c8fd5a48a78d6ab1476eafb18e7721e7772df114da4f58e1eac1` |
| SHA3-384 | `86dee012a11c9d1aa9657452f8eb213da840f6b582186b1491a212881e26529e17f95f12ac7d6d4464dbcdd8d92f49df` |
| IMPHASH | `5b3ebef3da244b3ac4de5a75d6d1e4c5` |
| TLSH | `T1DD3633B9859B61F6CAA3E63753B7627186443F6F2B0047FDCE20E36C1430A664964B9C` |
| SSDEEP | `98304:6u/zsywgrFAvQpJUlV/ROrKNunnjX8a51sujGhHzAXytwv9eaW:hzsdgrFA47UyKajM0uHorv9e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_8f24897a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f24897afca9c8fd5a48a78d6ab1476eafb18e7721e7772df114da4f58e1eac1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 22:48:40"
  condition:
    hash.sha256(0, filesize) == "8f24897afca9c8fd5a48a78d6ab1476eafb18e7721e7772df114da4f58e1eac1"
}
```

### Sample 78: `fdfaed3893bb2cf3`

| Field | Value |
|---|---|
| SHA-256 | `fdfaed3893bb2cf3ebd547c889e17c1e2f0b90208ecccc8591164bec41cfdb85` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-21 21:48:28` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86f1d93516e8e9a5626795670242fec4` |
| SHA-1 | `812de14c2866861965796b7d89225cd559d10e42` |
| SHA-256 | `fdfaed3893bb2cf3ebd547c889e17c1e2f0b90208ecccc8591164bec41cfdb85` |
| SHA3-384 | `8d8d24828eb46304ce673be8d86ffbce9b91350ac6435d8897ae5342743c96275053b006ebf2d0caefce901ff0762cae` |
| IMPHASH | `019ffc24dd80d5fd4d1178857048e434` |
| TLSH | `T1E7268D7FC13B0827ED9B63E58C591ACADC5CE7112710646A62BD189D8728EFEC0E1637` |
| SSDEEP | `49152:ZDwU3chslKfVF3GD3sAZBnl2bAOtvLE2LW4Ow48uHoL4xqRtg/vc2Mrp9lRF5v+M:S` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_078_fdfaed38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdfaed3893bb2cf3ebd547c889e17c1e2f0b90208ecccc8591164bec41cfdb85"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 21:48:28"
  condition:
    hash.sha256(0, filesize) == "fdfaed3893bb2cf3ebd547c889e17c1e2f0b90208ecccc8591164bec41cfdb85"
}
```

### Sample 79: `d9513db87bf97bde`

| Field | Value |
|---|---|
| SHA-256 | `d9513db87bf97bde479458f36a19ece64b1c2dd49e4efc012a7dacca71f43105` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-06-21 21:41:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ad0f2116153ce17daf1867bfcbd063d` |
| SHA-1 | `869da55fea1f5876c22b876d992b938c2f6ead92` |
| SHA-256 | `d9513db87bf97bde479458f36a19ece64b1c2dd49e4efc012a7dacca71f43105` |
| SHA3-384 | `a99475893c38a04ea9cdda5f5db3a2dd44dfe4a1bc798f6a5ea25a9ab542422566d2ff5ce8b6eb52e04d1cc02c9910ad` |
| TLSH | `T166032B42B30D0847D2773EF43A7B27D1E3EFA99021E4F685251E9E4A91B2E724285DCD` |
| SSDEEP | `768:RrnfoA9HZrEHCTgalj8LHcFJotUX2C01Iy:RrnfL5IisMjWoo0c1t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_d9513db8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9513db87bf97bde479458f36a19ece64b1c2dd49e4efc012a7dacca71f43105"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-21 21:41:33"
  condition:
    hash.sha256(0, filesize) == "d9513db87bf97bde479458f36a19ece64b1c2dd49e4efc012a7dacca71f43105"
}
```

### Sample 80: `5a7c140bec69c33b`

| Field | Value |
|---|---|
| SHA-256 | `5a7c140bec69c33b8d5cf065040c6239a231091976e1b8725680539ca5910640` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-21 21:39:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `355073b65e37439ec8f33925d21c229b` |
| SHA-1 | `2f73b3c67790b65694b39b0810a8f277b0f0c382` |
| SHA-256 | `5a7c140bec69c33b8d5cf065040c6239a231091976e1b8725680539ca5910640` |
| SHA3-384 | `5e09d76a832f0d75f88919c16bc3d2b13e5e75d71207069cb6f1f24acfd4c1a7ca1a727774834c25815b98b8d70a2e8e` |
| TLSH | `T19E137D6526853C28AE9988371D7E1F0CBDAA83E2310491DDBFCB3CF18C59A9CD21871D` |
| SSDEEP | `768:aXRWNGxVg9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:mlxnco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_5a7c140b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a7c140bec69c33b8d5cf065040c6239a231091976e1b8725680539ca5910640"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-21 21:39:11"
  condition:
    hash.sha256(0, filesize) == "5a7c140bec69c33b8d5cf065040c6239a231091976e1b8725680539ca5910640"
}
```

### Sample 81: `a31bbac723d61178`

| Field | Value |
|---|---|
| SHA-256 | `a31bbac723d61178ae45f02937f67b694256220327989155044f9cd97763fca6` |
| Family label | `unknown` |
| File name | `Shipping document.vbs` |
| File type | `vbs` |
| First seen | `2026-06-21 21:35:04` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37ffb0bd36bd102e38ee507c1db402e0` |
| SHA-1 | `4f60e7b632cc10721ad63e1396a4204765cef783` |
| SHA-256 | `a31bbac723d61178ae45f02937f67b694256220327989155044f9cd97763fca6` |
| SHA3-384 | `739ccb146931ae154316fc03f08c07b3536bad384f1a25807a4b6ac709b43de21dec8be0280f41669acf0b0945dd2849` |
| TLSH | `T1F2934A30CE64079A4E4B1BADFC911A61C9BC8619113310F4FEEA170D640A9BCF7BE66D` |
| SSDEEP | `1536:jYA72vU57qnFO5pDl/4/71b4SEwaOOqauE/uOdtcpgSjuJU5Yjt:jr72vU5GOz1oOSEwa/qabmOdt4gS2U5i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_a31bbac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a31bbac723d61178ae45f02937f67b694256220327989155044f9cd97763fca6"
    family = "unknown"
    file_name = "Shipping document.vbs"
    file_type = "vbs"
    first_seen = "2026-06-21 21:35:04"
  condition:
    hash.sha256(0, filesize) == "a31bbac723d61178ae45f02937f67b694256220327989155044f9cd97763fca6"
}
```

### Sample 82: `8f4ac0403edc15f1`

| Field | Value |
|---|---|
| SHA-256 | `8f4ac0403edc15f1eddc1da8239319c9df2e86720fc2508746ed0660a0cc2918` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-21 21:12:52` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f102d18fdbc9a87882a2a15a488fac4b` |
| SHA-1 | `45aa0b3e94603ec15c2d38140a7d12fd2114fb60` |
| SHA-256 | `8f4ac0403edc15f1eddc1da8239319c9df2e86720fc2508746ed0660a0cc2918` |
| SHA3-384 | `9d8bd7b5083d9c69483fc8def432b2bc899695286ee013311fc5f23083b49a96dcdf36ad17769b03ce51e563932fdfd9` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T10A172377B24A653DE06E1B765976A210583B6E21AD120D1ACEF034ACCF3D2B03D3F656` |
| SSDEEP | `196608:HoYXWptc00iapAURwsbvZ/HADzx5jFLTBiFEMig5NoJr/Dwzc2xJrxOaMkA2sMWd:HobU1iapAU9Z4XsOgU5cv0aI2l` |
| ICON-DHASH | `8e31e8968ee0718e` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_082_8f4ac040
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f4ac0403edc15f1eddc1da8239319c9df2e86720fc2508746ed0660a0cc2918"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 21:12:52"
  condition:
    hash.sha256(0, filesize) == "8f4ac0403edc15f1eddc1da8239319c9df2e86720fc2508746ed0660a0cc2918"
}
```

### Sample 83: `7ec7b47e370811f8`

| Field | Value |
|---|---|
| SHA-256 | `7ec7b47e370811f8b4188b220bb68d4d4e659d200013b654d0c2b36a37422d89` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-06-21 20:46:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc23dd189e3bd02a01ae4b7f40c671b7` |
| SHA-1 | `1356e1d7a01a5e2da8d357e30f455c3a65c9aecd` |
| SHA-256 | `7ec7b47e370811f8b4188b220bb68d4d4e659d200013b654d0c2b36a37422d89` |
| SHA3-384 | `b5c1758907d7ce5e43a84539615471c3682918bc849f68f17b5347971c5ae2fa646af70e17e630deff18309776bf37a5` |
| TLSH | `T149B32941FC82565AC6D5637BBA6E568C336A13F8C3EB3116DD118B24378A92F0E77B01` |
| TELFHASH | `t1b2f08b00fe7a8e1948f2da70dcac17a0d4439227a1a25b20ef52dad1cc3e459f308d1d` |
| SSDEEP | `3072:eZxWgf6gZXksuuGqZnpx3hUzybpLrp/6LYWoh5:eZxLvDuxqlIybpR/pWs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_7ec7b47e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ec7b47e370811f8b4188b220bb68d4d4e659d200013b654d0c2b36a37422d89"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-06-21 20:46:37"
  condition:
    hash.sha256(0, filesize) == "7ec7b47e370811f8b4188b220bb68d4d4e659d200013b654d0c2b36a37422d89"
}
```

### Sample 84: `13db3cd49df1b6a0`

| Field | Value |
|---|---|
| SHA-256 | `13db3cd49df1b6a09fae27045f6a87fa4ccc413732fa37fc6b1955f38ab0167f` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-06-21 20:45:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5199bf6d0966da9f31afa7c12b2e45d` |
| SHA-1 | `70eb9f68b50ae1afaa8c6a3516595627adbd5f77` |
| SHA-256 | `13db3cd49df1b6a09fae27045f6a87fa4ccc413732fa37fc6b1955f38ab0167f` |
| SHA3-384 | `9feb33be2b3f785e8b40b5212bfdf3b2e0ceeeb520b237f483b874de3b3b8dc75d9f1df17e46d62a292dd23ef5c1b658` |
| TLSH | `T16A23F171665894D9E5F58CF0E978C98124A21C3DD3EFB46815062FACFE7E2952E33205` |
| SSDEEP | `768:U2TcdhwD6n/CMhjDnkY+1KkUUm9s5Se+0pO2Z2LbqV0YakA1s3UozA:zcdhU66cDkY7Uq9H0pZVrpzA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_13db3cd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13db3cd49df1b6a09fae27045f6a87fa4ccc413732fa37fc6b1955f38ab0167f"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-06-21 20:45:46"
  condition:
    hash.sha256(0, filesize) == "13db3cd49df1b6a09fae27045f6a87fa4ccc413732fa37fc6b1955f38ab0167f"
}
```

### Sample 85: `3d21695cf0c4ed58`

| Field | Value |
|---|---|
| SHA-256 | `3d21695cf0c4ed5889dac2d4f13e0b11e585b3ad06dd23e66630b0d86e3e866e` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-06-21 20:38:23` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a75ff8f278a80932f6071baceb9bb68c` |
| SHA-1 | `4577adc4a474294efc1123d2e29b884682b47869` |
| SHA-256 | `3d21695cf0c4ed5889dac2d4f13e0b11e585b3ad06dd23e66630b0d86e3e866e` |
| SHA3-384 | `db1e04350be03d41ace9b3bc41b274ecff6dd61e035e81d17698d9ab0343b0cb6a3df1e9f21211d0b7ea9c8315da3f54` |
| TLSH | `T17831639A00246B385612CADD73733588710C92EB1D9BDBA49D481EE9828C5CDB216FD5` |
| SSDEEP | `12:Uo76C76OUVXj65vl1E61SiiRY6PoxFg6XIJF6omABAS6MoM8z6i53bdiNNgSx6Nm:SBiilcIVmkGpbdreiC7bL/B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_3d21695c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d21695cf0c4ed5889dac2d4f13e0b11e585b3ad06dd23e66630b0d86e3e866e"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-21 20:38:23"
  condition:
    hash.sha256(0, filesize) == "3d21695cf0c4ed5889dac2d4f13e0b11e585b3ad06dd23e66630b0d86e3e866e"
}
```

### Sample 86: `5e0771444dbdd0f4`

| Field | Value |
|---|---|
| SHA-256 | `5e0771444dbdd0f4263d10b3918fa0982191b12494d3cf93002a0ab22bc7ab38` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-06-21 20:38:22` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `432002c05710ec5eff6bcaebd53dcc44` |
| SHA-1 | `cd0055ddb4a30bbca87f2e73b0f1a842cb13a404` |
| SHA-256 | `5e0771444dbdd0f4263d10b3918fa0982191b12494d3cf93002a0ab22bc7ab38` |
| SHA3-384 | `cbb33e7558057346c2c563aef3c73ecb9cff1abbb4035acc8a6a6290553707b9f26b95d58ed5c328ef399c30304eb504` |
| TLSH | `T1200148DB8250AD104029DA5E62E76190B46093CF055A1F787FAC9A3DFB9CE14B037F84` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohap8c17/zh95aJZQ7:e9Qp+Msp8s7LoQ7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_5e077144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e0771444dbdd0f4263d10b3918fa0982191b12494d3cf93002a0ab22bc7ab38"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-21 20:38:22"
  condition:
    hash.sha256(0, filesize) == "5e0771444dbdd0f4263d10b3918fa0982191b12494d3cf93002a0ab22bc7ab38"
}
```

### Sample 87: `0c13889d0f9c8aac`

| Field | Value |
|---|---|
| SHA-256 | `0c13889d0f9c8aac6880838de43150547d8bce4fb8921af47b56db9d4dc65ddd` |
| Family label | `unknown` |
| File name | `pithus_sample_0c13889d0f9c8aac6880838de43150547d8bce4fb8921af47b56db9d4dc65ddd.apk` |
| File type | `apk` |
| First seen | `2026-06-21 20:36:52` |
| Reporter | `trpyn` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66229aa14390e4246c44d8f77d25cb8d` |
| SHA-256 | `0c13889d0f9c8aac6880838de43150547d8bce4fb8921af47b56db9d4dc65ddd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_0c13889d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c13889d0f9c8aac6880838de43150547d8bce4fb8921af47b56db9d4dc65ddd"
    family = "unknown"
    file_name = "pithus_sample_0c13889d0f9c8aac6880838de43150547d8bce4fb8921af47b56db9d4dc65ddd.apk"
    file_type = "apk"
    first_seen = "2026-06-21 20:36:52"
  condition:
    hash.sha256(0, filesize) == "0c13889d0f9c8aac6880838de43150547d8bce4fb8921af47b56db9d4dc65ddd"
}
```

### Sample 88: `28fcf6f84caeadf9`

| Field | Value |
|---|---|
| SHA-256 | `28fcf6f84caeadf9245bb039a2057944eb34a47c1d3a88fd2a0eaefc48e9dbfd` |
| Family label | `unknown` |
| File name | `Vy(1).ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:23:12` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c454fcac4d2d387af52521fa8d39e17` |
| SHA-1 | `82437512e039139a1b25f25c0226548521ebfb76` |
| SHA-256 | `28fcf6f84caeadf9245bb039a2057944eb34a47c1d3a88fd2a0eaefc48e9dbfd` |
| SHA3-384 | `0eae90e8d8e19ca58940906704901ff22373b52a2f3a1050b90059b9f3f6d5786e036b2308316f0261bbfd1235aedabc` |
| TLSH | `T1D5510B106AF94608B5B3AB09D6FEA461583FF91DAE76CB0C0055D14D0BB2A14C967F73` |
| SSDEEP | `48:rsw1sAkD1aaPEYHDY9SAOvn7S5r0xX6YyNRX7Swwx6A4WmxZ5dxGE55Oh47C0/V:rsgsZ5ahQbn+5r0R6xx+z4xxZ5dsEHFV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_28fcf6f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28fcf6f84caeadf9245bb039a2057944eb34a47c1d3a88fd2a0eaefc48e9dbfd"
    family = "unknown"
    file_name = "Vy(1).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:23:12"
  condition:
    hash.sha256(0, filesize) == "28fcf6f84caeadf9245bb039a2057944eb34a47c1d3a88fd2a0eaefc48e9dbfd"
}
```

### Sample 89: `3dda7724f33b2b89`

| Field | Value |
|---|---|
| SHA-256 | `3dda7724f33b2b89585cc36522f167260bda9314eb22e07a370079a51de48439` |
| Family label | `unknown` |
| File name | `Vy.ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:23:06` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8686099cb96a2ff5224c753e5a1f6c7d` |
| SHA-1 | `caf177883cb3bf6523e1445df128573938af2cf3` |
| SHA-256 | `3dda7724f33b2b89585cc36522f167260bda9314eb22e07a370079a51de48439` |
| SHA3-384 | `9c44e5b5c5075123fe03c14d147e6c225ebb4b29a06d25a4ee6be1f9ac80202754dd294b324cf86cdc8b137d084c4dc0` |
| TLSH | `T13B513C1066FD4608B1B3AB09DAFEA4A1583FF91DAE76CB0C0055D14C0BB2A14C967F73` |
| SSDEEP | `48:rsw1sAkD1aaPEYHD0eI7S5r0xX6YyNRX7SwOA4WmxZ5dxGE55OhL7C0/V:rsgsZ5ahQm+5r0R6xx+U4xxZ5dsE0FV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_3dda7724
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dda7724f33b2b89585cc36522f167260bda9314eb22e07a370079a51de48439"
    family = "unknown"
    file_name = "Vy.ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:23:06"
  condition:
    hash.sha256(0, filesize) == "3dda7724f33b2b89585cc36522f167260bda9314eb22e07a370079a51de48439"
}
```

### Sample 90: `858e95756f32a283`

| Field | Value |
|---|---|
| SHA-256 | `858e95756f32a2833275064e8a18ae1a8de873bbf7ed661570cfdfc37953544d` |
| Family label | `unknown` |
| File name | `NgOVP(3).ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:59` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a792e36b5515f947eff274617b134a2` |
| SHA-1 | `fd0180eca4672edd88045bbd27a17e2f9b6fb8d2` |
| SHA-256 | `858e95756f32a2833275064e8a18ae1a8de873bbf7ed661570cfdfc37953544d` |
| SHA3-384 | `a0b0883540da78dc38cf0197e1363da1435a94641133c88af65e3b190909410b302130a66e9872b09c06206f85cba215` |
| TLSH | `T1575108106AF99E04B5B3EA099ABFE462543BBADDDE31CB4C8159C10C07F5A508927F37` |
| SSDEEP | `48:rsw1sAkD1aaPEYHDK37c6YyOvaHr7zXtT4oNQM7ktAGG5FF3F5Ua0xXm7VA/Z:rsgsZ5ahQG46CGdMoO2zxbd70RmsZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_858e9575
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "858e95756f32a2833275064e8a18ae1a8de873bbf7ed661570cfdfc37953544d"
    family = "unknown"
    file_name = "NgOVP(3).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:59"
  condition:
    hash.sha256(0, filesize) == "858e95756f32a2833275064e8a18ae1a8de873bbf7ed661570cfdfc37953544d"
}
```

### Sample 91: `50264e6ef48f2bdf`

| Field | Value |
|---|---|
| SHA-256 | `50264e6ef48f2bdff1180fa72733a8a8a693990d84d1a6ce0009898d81b09a92` |
| Family label | `unknown` |
| File name | `NgOVP(2).ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:53` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ef0e07bd94b4bb9ad682fd92ae4ffc6` |
| SHA-1 | `041f12a4aad97a76e65b449e8a4d6514f4b81c0d` |
| SHA-256 | `50264e6ef48f2bdff1180fa72733a8a8a693990d84d1a6ce0009898d81b09a92` |
| SHA3-384 | `d7b4f44a71d9800987817f88dfb53ee546e0e31b20cd65231bb3821439ae1903cb72af17caaf084e08665f8724014fd9` |
| TLSH | `T1DC611A106AF99F14B573DA099ABEE492543BBADDEE31CB4C8159C10C07B5A408917F37` |
| SSDEEP | `48:rsw1sAkD1aaPEYHDK37c6YyOvaHr7zXtT4oNQM7ktAGG5FF3F5UHk0xXm7VA/Z:rsgsZ5ahQG46CGdMoO2zxbdQk0RmsZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_50264e6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50264e6ef48f2bdff1180fa72733a8a8a693990d84d1a6ce0009898d81b09a92"
    family = "unknown"
    file_name = "NgOVP(2).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:53"
  condition:
    hash.sha256(0, filesize) == "50264e6ef48f2bdff1180fa72733a8a8a693990d84d1a6ce0009898d81b09a92"
}
```

### Sample 92: `9bf3e590250b86e1`

| Field | Value |
|---|---|
| SHA-256 | `9bf3e590250b86e1e9dee20e6200b67983e6f48d1ccc07559a5835d7d85d72e6` |
| Family label | `unknown` |
| File name | `NgOVP(1).ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:46` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ae08c993faa121c8e623893270457c8` |
| SHA-1 | `673e51d59ebb58aef24c1b93d0be4a589ad4777f` |
| SHA-256 | `9bf3e590250b86e1e9dee20e6200b67983e6f48d1ccc07559a5835d7d85d72e6` |
| SHA3-384 | `45cf4675f27096d4360c441e176935e432dbca9f9d842f79e7e5704a51c3ad895956b531499589637700b64aafab2211` |
| TLSH | `T1555117106AF99A04B5B3EA099ABFE462543BBADDDE31CB4C8159C10C07B5A508927F37` |
| SSDEEP | `48:rsw1sAkD1aaPEYHDK37c6YyOvaHr7zXtT4oNQM7ktAGG5FF3F5Ud0xXm7VA/Z:rsgsZ5ahQG46CGdMoO2zxbdg0RmsZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_9bf3e590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bf3e590250b86e1e9dee20e6200b67983e6f48d1ccc07559a5835d7d85d72e6"
    family = "unknown"
    file_name = "NgOVP(1).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:46"
  condition:
    hash.sha256(0, filesize) == "9bf3e590250b86e1e9dee20e6200b67983e6f48d1ccc07559a5835d7d85d72e6"
}
```

### Sample 93: `05d9390632b8587d`

| Field | Value |
|---|---|
| SHA-256 | `05d9390632b8587d961e4fb1b6deb836887852c496f110397121b567e98ac3b8` |
| Family label | `unknown` |
| File name | `NgOVP.ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:40` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b96de001e0a5160f76a237920a0a4a6f` |
| SHA-1 | `492ab202a5395220894e6e0f3adfd574ad979d70` |
| SHA-256 | `05d9390632b8587d961e4fb1b6deb836887852c496f110397121b567e98ac3b8` |
| SHA3-384 | `2682cd99a165b8a0ce850ed542f8839fbbb9d52763b6dba93a04b022c99c998e6c005cded07f4dec3fa09fbdce9e8501` |
| TLSH | `T179614C106AF98A14B573DA099ABFE491583BB6DDEE31CB4C8159C10C07F6A508817F37` |
| SSDEEP | `48:rsw1sAkD1aaPEYHDK37c6YyOvaHr7zXtT4oNQM7ktAGG5FF3F5UbJ0xXm7VA/Z:rsgsZ5ahQG46CGdMoO2zxbdo0RmsZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_05d93906
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05d9390632b8587d961e4fb1b6deb836887852c496f110397121b567e98ac3b8"
    family = "unknown"
    file_name = "NgOVP.ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:40"
  condition:
    hash.sha256(0, filesize) == "05d9390632b8587d961e4fb1b6deb836887852c496f110397121b567e98ac3b8"
}
```

### Sample 94: `b680dc5815223eff`

| Field | Value |
|---|---|
| SHA-256 | `b680dc5815223eff566b30fa251267b91b1f10d2eec2522311def684b4baf59a` |
| Family label | `unknown` |
| File name | `Lwoqo(3).ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:34` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5310a4e454129a4a396555497e7de51e` |
| SHA-1 | `18a35c1e773d8ee850382c7d5007b5c9f1135479` |
| SHA-256 | `b680dc5815223eff566b30fa251267b91b1f10d2eec2522311def684b4baf59a` |
| SHA3-384 | `bf268e715b0d2c0375b2860c03a0d3bbbdb30738cdbfe5f15b2b1726850117dc87e9ae6c95a150bf6210bba3c321dcf1` |
| TLSH | `T10F218E10AAFC8E05B673DA0997BBE49015767AECDD35CB0CC354C10C16AE944D866F37` |
| SSDEEP | `24:Qlv4o4Kzyu52U/tMlBygklBRlB0P8wPMuZJBlBMwA6PFv+F5TK:A4oPtM7ktApDPwF5TK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_b680dc58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b680dc5815223eff566b30fa251267b91b1f10d2eec2522311def684b4baf59a"
    family = "unknown"
    file_name = "Lwoqo(3).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:34"
  condition:
    hash.sha256(0, filesize) == "b680dc5815223eff566b30fa251267b91b1f10d2eec2522311def684b4baf59a"
}
```

### Sample 95: `984ca97d34361caf`

| Field | Value |
|---|---|
| SHA-256 | `984ca97d34361cafaac92a5f2617931f3dd38ef71774eb29cf8a795a31ab3b6b` |
| Family label | `unknown` |
| File name | `Lwoqo(2).ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:29` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c1562f348ee5f02bf27cd4de7c9ad52` |
| SHA-1 | `cd5db6c6bd3df6251b2d3ccea8c09a186391f4dd` |
| SHA-256 | `984ca97d34361cafaac92a5f2617931f3dd38ef71774eb29cf8a795a31ab3b6b` |
| SHA3-384 | `1b2807d97e04eaebda41957904d7a164dc4fe5926941b9f08e92a60cec2389d8d6ee4a45def889ff5a239aaa1d31a2e4` |
| TLSH | `T18A21F310AAFC8E11BA73DB1987BAE08019767AEDED31CB0CC354C10C06AEA449C56F37` |
| SSDEEP | `24:Qlv4o4Kzyu52U/tMlBygklBRlB0P8wPMuZJBlBMwA6PFv+F5ThBmJ:A4oPtM7ktApDPwF5TH0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_984ca97d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "984ca97d34361cafaac92a5f2617931f3dd38ef71774eb29cf8a795a31ab3b6b"
    family = "unknown"
    file_name = "Lwoqo(2).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:29"
  condition:
    hash.sha256(0, filesize) == "984ca97d34361cafaac92a5f2617931f3dd38ef71774eb29cf8a795a31ab3b6b"
}
```

### Sample 96: `fa93ea4a6ce497c4`

| Field | Value |
|---|---|
| SHA-256 | `fa93ea4a6ce497c4f94ef8d50e451ff1ee81825319bfcf180eb003a61bec3568` |
| Family label | `unknown` |
| File name | `Lwoqo(1).ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:23` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c23e9fd391a6e1b4186cdd981523a38` |
| SHA-1 | `ff9d41310d9524a06fa752ba210a567f7ecd204d` |
| SHA-256 | `fa93ea4a6ce497c4f94ef8d50e451ff1ee81825319bfcf180eb003a61bec3568` |
| SHA3-384 | `7c5aa4f6eacf2bfca5d9a14615604fba252c8dc1c0765133d8fe48200fd4278b44d25222a036f5160a9425334a10c419` |
| TLSH | `T134218E10AAFC8E05B673DA0997BBE49015767AECDD35CB0CC354C10C16AE944D866F37` |
| SSDEEP | `24:Qlv4o4Kzyu52U/tMlBygklBRlB0P8wPMuZJBlBMwA6PFv+F5TN:A4oPtM7ktApDPwF5TN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_fa93ea4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa93ea4a6ce497c4f94ef8d50e451ff1ee81825319bfcf180eb003a61bec3568"
    family = "unknown"
    file_name = "Lwoqo(1).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:23"
  condition:
    hash.sha256(0, filesize) == "fa93ea4a6ce497c4f94ef8d50e451ff1ee81825319bfcf180eb003a61bec3568"
}
```

### Sample 97: `363051592819af12`

| Field | Value |
|---|---|
| SHA-256 | `363051592819af125a1b2b5e7b286d7e782267f41e4699db78c91fac2c0b26ee` |
| Family label | `unknown` |
| File name | `Lwoqo.ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:18` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `288e28ea13225c33394aee9d2d8e4c02` |
| SHA-1 | `ead8f8d3fdf1f35cba0672755a7c8a02c27378be` |
| SHA-256 | `363051592819af125a1b2b5e7b286d7e782267f41e4699db78c91fac2c0b26ee` |
| SHA3-384 | `0d728c9fd39e55ff15d7fadee79719e2574b12430b46ada67ccbea6b277c627784aa6e755c29c71be571b544baa568b5` |
| TLSH | `T163219210AAFC8E157673DA0587BAE09059767ADCDD35C70CC354C10C06AE9449C56F37` |
| SSDEEP | `24:Qlv4o4Kzyu52U/tMlBygklBRlB0P8wPMuZJBlBMwA6PFv+F5TqJMJ:A4oPtM7ktApDPwF5TbJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_36305159
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "363051592819af125a1b2b5e7b286d7e782267f41e4699db78c91fac2c0b26ee"
    family = "unknown"
    file_name = "Lwoqo.ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:18"
  condition:
    hash.sha256(0, filesize) == "363051592819af125a1b2b5e7b286d7e782267f41e4699db78c91fac2c0b26ee"
}
```

### Sample 98: `c722b6557d74a0a6`

| Field | Value |
|---|---|
| SHA-256 | `c722b6557d74a0a6eab889a5e7d81032ff18759bb42928be3a8e4393b1e26f39` |
| Family label | `unknown` |
| File name | `DvVbs(1).ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:13` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a652fcb1e5206dd1378ffe1964719677` |
| SHA-1 | `6d19c80aaf6d047f9e5cdaf8cef292a2fa49911e` |
| SHA-256 | `c722b6557d74a0a6eab889a5e7d81032ff18759bb42928be3a8e4393b1e26f39` |
| SHA3-384 | `f4e5a30d90bfa19ff898bc453526cf169c806cdc7e5cac4ae450bb6ff281436254293854726d746245545916891f99d5` |
| TLSH | `T1CC119410AAEC810975736B09C2BE91541577FA2DAD76CB1D0414D14D06B2A48DDB7F72` |
| SSDEEP | `24:Qsx6O/4+yu5b7nxByg5BI8lPMPMuZJYMwA64Ivt55Xhp:7x6A4UnxZ5dM0sg55hp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_c722b655
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c722b6557d74a0a6eab889a5e7d81032ff18759bb42928be3a8e4393b1e26f39"
    family = "unknown"
    file_name = "DvVbs(1).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:13"
  condition:
    hash.sha256(0, filesize) == "c722b6557d74a0a6eab889a5e7d81032ff18759bb42928be3a8e4393b1e26f39"
}
```

### Sample 99: `9e64eab001591124`

| Field | Value |
|---|---|
| SHA-256 | `9e64eab0015911243a17b43f5a4bdbbf41516b1063fc70722acb3d8492434dd2` |
| Family label | `unknown` |
| File name | `DvVbs.ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:08` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `986254c4e7965203bf831482c95c5a43` |
| SHA-1 | `44dde94caf0f2755ce4864302efdf529bcb95f4b` |
| SHA-256 | `9e64eab0015911243a17b43f5a4bdbbf41516b1063fc70722acb3d8492434dd2` |
| SHA3-384 | `e393a6dbb59dd6836b555efa050bb10a75da91c8d99e5e8e6a16504319d32962018863faffdb3c3afe3a7c310e27e150` |
| TLSH | `T1C711C410AAEC810971736F09C3BEA1641477FA2DAD72CB0D0414D04D06B3A48DDB7F72` |
| SSDEEP | `24:Q0D1O/4+yu5b7nxByg5BI8lPMPMuZJYMwA64Ivt55XhXQ:PA4UnxZ5dM0sg55hA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_9e64eab0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e64eab0015911243a17b43f5a4bdbbf41516b1063fc70722acb3d8492434dd2"
    family = "unknown"
    file_name = "DvVbs.ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:08"
  condition:
    hash.sha256(0, filesize) == "9e64eab0015911243a17b43f5a4bdbbf41516b1063fc70722acb3d8492434dd2"
}
```

### Sample 100: `400ca3bc5a546716`

| Field | Value |
|---|---|
| SHA-256 | `400ca3bc5a546716fec62a3f5e5730585d2d0acb24b973e40e4321a4be3ea9d3` |
| Family label | `unknown` |
| File name | `42662A7F.ps1` |
| File type | `ps1` |
| First seen | `2026-06-21 20:22:03` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87ccad3fc97fdedf942ca98ae3686fc4` |
| SHA-1 | `8377f54bd6f278b38d887454fd4c3f2280b87d46` |
| SHA-256 | `400ca3bc5a546716fec62a3f5e5730585d2d0acb24b973e40e4321a4be3ea9d3` |
| SHA3-384 | `03efec9948de0fa352f4a3b3a2a94d0ab82e8d6264c61d8e7ac30b84eadc2c56c56f739a596d8e587bb2b9f44e8128aa` |
| TLSH | `T1CFF512270F9ADE980940BB3460DB52BD88E62B364C48B6B3A9E7BDE51CC5DB4404DCF5` |
| SSDEEP | `49152:2Xqh1HgN3tYGxOsTX2kzSk4JE3BfggLEFx8MSjhnuR:3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_400ca3bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "400ca3bc5a546716fec62a3f5e5730585d2d0acb24b973e40e4321a4be3ea9d3"
    family = "unknown"
    file_name = "42662A7F.ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:03"
  condition:
    hash.sha256(0, filesize) == "400ca3bc5a546716fec62a3f5e5730585d2d0acb24b973e40e4321a4be3ea9d3"
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
 * Generated: 2026-06-22T05:34:48.259878+00:00
 */

rule MalwareBazaar_WannaCry_001_2b188dfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b188dfd9fd2275fc1da25e159ed1d4c765d03db073e72210043556ad2baf1e5"
    family = "WannaCry"
    file_name = "2b188dfd9fd2275fc1da25e159ed1d4c765d03db073e72210043556ad2baf1e5"
    file_type = "exe"
    first_seen = "2026-06-22 05:15:13"
  condition:
    hash.sha256(0, filesize) == "2b188dfd9fd2275fc1da25e159ed1d4c765d03db073e72210043556ad2baf1e5"
}

rule MalwareBazaar_Vjw0rm_002_b26fb4df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b26fb4df0dced5245969f72924d7aa27de5e9c7c526365fd0545dca7bd79e5fa"
    family = "Vjw0rm"
    file_name = "ePRzHXrdth.js"
    file_type = "js"
    first_seen = "2026-06-22 05:01:15"
  condition:
    hash.sha256(0, filesize) == "b26fb4df0dced5245969f72924d7aa27de5e9c7c526365fd0545dca7bd79e5fa"
}

rule MalwareBazaar_unknown_003_89b0bae4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89b0bae4decab7d725cc35fd6f7004eb1255980961449b1ef79db23091654643"
    family = "unknown"
    file_name = "TT_Slip_SOA_Proforma Invoices.vbs"
    file_type = "vbs"
    first_seen = "2026-06-22 04:52:54"
  condition:
    hash.sha256(0, filesize) == "89b0bae4decab7d725cc35fd6f7004eb1255980961449b1ef79db23091654643"
}

rule MalwareBazaar_Mirai_004_dc1d0d96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc1d0d968707d8f28bc9e5d27f883ac5d6ac4ec49623dd02db79f6ea28062cf5"
    family = "Mirai"
    file_name = "nerv.ppc"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:31"
  condition:
    hash.sha256(0, filesize) == "dc1d0d968707d8f28bc9e5d27f883ac5d6ac4ec49623dd02db79f6ea28062cf5"
}

rule MalwareBazaar_Mirai_005_2ea382e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ea382e20ccd7f1909e432fecf9ce41594a3a49e9a1a692433a982d2a778312b"
    family = "Mirai"
    file_name = "adb.sh"
    file_type = "sh"
    first_seen = "2026-06-22 04:47:29"
  condition:
    hash.sha256(0, filesize) == "2ea382e20ccd7f1909e432fecf9ce41594a3a49e9a1a692433a982d2a778312b"
}

rule MalwareBazaar_Mirai_006_f27a165f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f27a165f3cdcb6f72dceaf130398fa7f78b2a5c7e5a22cb14db5e8c5b4151cb9"
    family = "Mirai"
    file_name = "nerv.mips"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:28"
  condition:
    hash.sha256(0, filesize) == "f27a165f3cdcb6f72dceaf130398fa7f78b2a5c7e5a22cb14db5e8c5b4151cb9"
}

rule MalwareBazaar_Mirai_007_c7d5e21a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7d5e21a01ce8ab4083c588d8050b286d375eeb88f41fe68b22ca02cf1bb8f8a"
    family = "Mirai"
    file_name = "nerv.arm6"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:27"
  condition:
    hash.sha256(0, filesize) == "c7d5e21a01ce8ab4083c588d8050b286d375eeb88f41fe68b22ca02cf1bb8f8a"
}

rule MalwareBazaar_Mirai_008_2522ea59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2522ea59162e569aa18244b99521f597f0bd5082c767b80c6cf09d0dd3c8b9a5"
    family = "Mirai"
    file_name = "nerv.x86"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:26"
  condition:
    hash.sha256(0, filesize) == "2522ea59162e569aa18244b99521f597f0bd5082c767b80c6cf09d0dd3c8b9a5"
}

rule MalwareBazaar_Mirai_009_d76c60aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d76c60aac76d011874dd64ffd9009413f0edf34556005195561199f54598b6a9"
    family = "Mirai"
    file_name = "nerv.sparc"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:24"
  condition:
    hash.sha256(0, filesize) == "d76c60aac76d011874dd64ffd9009413f0edf34556005195561199f54598b6a9"
}

rule MalwareBazaar_Mirai_010_57fa061f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57fa061f794297b1b23aa1bbf4a552d8e403568f6b01a24aa9b64257aecc8553"
    family = "Mirai"
    file_name = "nerv.m68k"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:23"
  condition:
    hash.sha256(0, filesize) == "57fa061f794297b1b23aa1bbf4a552d8e403568f6b01a24aa9b64257aecc8553"
}

rule MalwareBazaar_Mirai_011_a4e9e035
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4e9e03516d572e9b0f3238e7693b2fe69358f4b7cbe545adbe56f0397726df4"
    family = "Mirai"
    file_name = "nerv.arm7"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:22"
  condition:
    hash.sha256(0, filesize) == "a4e9e03516d572e9b0f3238e7693b2fe69358f4b7cbe545adbe56f0397726df4"
}

rule MalwareBazaar_Mirai_012_8de571b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8de571b44211ec6fd985428d1464daf0e4d31202c8286de9c2c496d026595caa"
    family = "Mirai"
    file_name = "nerv.arm5"
    file_type = "elf"
    first_seen = "2026-06-22 04:47:21"
  condition:
    hash.sha256(0, filesize) == "8de571b44211ec6fd985428d1464daf0e4d31202c8286de9c2c496d026595caa"
}

rule MalwareBazaar_Mirai_013_584d6786
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "584d6786596e0a2e8ae08a0de55676e10a9e5f12f7efac9e073c7f517cece228"
    family = "Mirai"
    file_name = "nerv.x86_64"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:33"
  condition:
    hash.sha256(0, filesize) == "584d6786596e0a2e8ae08a0de55676e10a9e5f12f7efac9e073c7f517cece228"
}

rule MalwareBazaar_Mirai_014_088b9366
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "088b936614445d0ef54c838f10b563343efedc68209c482d0155221de613ec18"
    family = "Mirai"
    file_name = "nerv.mpsl"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:31"
  condition:
    hash.sha256(0, filesize) == "088b936614445d0ef54c838f10b563343efedc68209c482d0155221de613ec18"
}

rule MalwareBazaar_Mirai_015_bd0d1fab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd0d1fab22f6f81ce82f0fbc1831091bbac6311db2cfc8f610fb83fac2fd66d1"
    family = "Mirai"
    file_name = "nerv.x86_32"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:30"
  condition:
    hash.sha256(0, filesize) == "bd0d1fab22f6f81ce82f0fbc1831091bbac6311db2cfc8f610fb83fac2fd66d1"
}

rule MalwareBazaar_Mirai_016_cc281983
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc281983d78727a9db9a1cfd24cbd45b2cc98025d5da262a93dca5a6b16075c0"
    family = "Mirai"
    file_name = "nerv.arm4"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:29"
  condition:
    hash.sha256(0, filesize) == "cc281983d78727a9db9a1cfd24cbd45b2cc98025d5da262a93dca5a6b16075c0"
}

rule MalwareBazaar_Mirai_017_31ce2168
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31ce2168fbd4fd0f4c42fd9eb59b581384784e363bc0fc07f008076644b42623"
    family = "Mirai"
    file_name = "nerv.sh4"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:27"
  condition:
    hash.sha256(0, filesize) == "31ce2168fbd4fd0f4c42fd9eb59b581384784e363bc0fc07f008076644b42623"
}

rule MalwareBazaar_Mirai_018_8bff0eab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bff0eab714ae1b746abeca672ec23ff941d6748027318f9006221151c0b81f6"
    family = "Mirai"
    file_name = "nerv.dbg"
    file_type = "elf"
    first_seen = "2026-06-22 04:45:26"
  condition:
    hash.sha256(0, filesize) == "8bff0eab714ae1b746abeca672ec23ff941d6748027318f9006221151c0b81f6"
}

rule MalwareBazaar_unknown_019_262f001e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "262f001ebc264ea9f90b90f9abcfdbfa5781811e01cf7ca74f95a92238a857fe"
    family = "unknown"
    file_name = "tmp_downloader.bat"
    file_type = "bat"
    first_seen = "2026-06-22 04:39:27"
  condition:
    hash.sha256(0, filesize) == "262f001ebc264ea9f90b90f9abcfdbfa5781811e01cf7ca74f95a92238a857fe"
}

rule MalwareBazaar_Prometei_020_d135ddfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d135ddfe09f72f009766f84ff20adc24162c9656782ba77ca247783757e46b94"
    family = "Prometei"
    file_name = "d135ddfe09f72f009766f84ff20adc24162c9656782ba77ca247783757e46b94"
    file_type = "elf"
    first_seen = "2026-06-22 03:55:18"
  condition:
    hash.sha256(0, filesize) == "d135ddfe09f72f009766f84ff20adc24162c9656782ba77ca247783757e46b94"
}

rule MalwareBazaar_Mirai_021_9d88938e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d88938e65802ec240969c1a290e493fe8381c225375082785877da2b1244198"
    family = "Mirai"
    file_name = "sora.mpsl"
    file_type = "elf"
    first_seen = "2026-06-22 03:30:40"
  condition:
    hash.sha256(0, filesize) == "9d88938e65802ec240969c1a290e493fe8381c225375082785877da2b1244198"
}

rule MalwareBazaar_Mirai_022_3c685414
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c685414f77a1f913c1cf41c95c1bf74c067687366be3d451db9b4dd1b1631dd"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-06-22 03:30:39"
  condition:
    hash.sha256(0, filesize) == "3c685414f77a1f913c1cf41c95c1bf74c067687366be3d451db9b4dd1b1631dd"
}

rule MalwareBazaar_Mirai_023_00109ee9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00109ee92a3ccea9d23621fe1e2e6f73cab1616c585da67ec9da59fa086cc848"
    family = "Mirai"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-06-22 03:12:15"
  condition:
    hash.sha256(0, filesize) == "00109ee92a3ccea9d23621fe1e2e6f73cab1616c585da67ec9da59fa086cc848"
}

rule MalwareBazaar_Mirai_024_8f220944
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f220944e1c64266ef33f1ebbf64d0e6ebbaea6262137fffced01443bd12fe96"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-06-22 03:10:43"
  condition:
    hash.sha256(0, filesize) == "8f220944e1c64266ef33f1ebbf64d0e6ebbaea6262137fffced01443bd12fe96"
}

rule MalwareBazaar_Mirai_025_135984a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "135984a39fef8cc561b56a3331c9217ac30617a6dce97840519bad571e6c433e"
    family = "Mirai"
    file_name = "sora.spc"
    file_type = "elf"
    first_seen = "2026-06-22 03:10:42"
  condition:
    hash.sha256(0, filesize) == "135984a39fef8cc561b56a3331c9217ac30617a6dce97840519bad571e6c433e"
}

rule MalwareBazaar_unknown_026_7a14e4c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a14e4c99413fb0873b9497a7e2981335514434a9c1b922c9c48ce969be11c4c"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-22 03:09:27"
  condition:
    hash.sha256(0, filesize) == "7a14e4c99413fb0873b9497a7e2981335514434a9c1b922c9c48ce969be11c4c"
}

rule MalwareBazaar_Mirai_027_df0f1737
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df0f17370665acba778dffb57135a02abc34c6bf9399347ee20c689433401d44"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-06-22 03:08:14"
  condition:
    hash.sha256(0, filesize) == "df0f17370665acba778dffb57135a02abc34c6bf9399347ee20c689433401d44"
}

rule MalwareBazaar_Mirai_028_3a016609
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a016609b672a54877b85f589ebf5ced4ee41503c850d5798fce36325f20f96f"
    family = "Mirai"
    file_name = "data_mipsel-uclibc"
    file_type = "elf"
    first_seen = "2026-06-22 03:05:27"
  condition:
    hash.sha256(0, filesize) == "3a016609b672a54877b85f589ebf5ced4ee41503c850d5798fce36325f20f96f"
}

rule MalwareBazaar_Mirai_029_3838403e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3838403ebb9150e24ab326f6b72f3dabab0804d5ccd83a5805a2fc1a48cdf27c"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-06-22 03:03:41"
  condition:
    hash.sha256(0, filesize) == "3838403ebb9150e24ab326f6b72f3dabab0804d5ccd83a5805a2fc1a48cdf27c"
}

rule MalwareBazaar_Mirai_030_d66d8002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d66d8002d603c89701071c6be50b479410b017203e85bb20f9b15860574dc617"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-06-22 03:02:43"
  condition:
    hash.sha256(0, filesize) == "d66d8002d603c89701071c6be50b479410b017203e85bb20f9b15860574dc617"
}

rule MalwareBazaar_Mirai_031_a558714e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a558714eb3c35a8f99c7991292f45b3edf3af2e08c151b6f74afb0691c189851"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-06-22 02:57:13"
  condition:
    hash.sha256(0, filesize) == "a558714eb3c35a8f99c7991292f45b3edf3af2e08c151b6f74afb0691c189851"
}

rule MalwareBazaar_Mirai_032_4121a0bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4121a0bfb7059830e5ec9cc01126e37a5840987833ed524707356ae493d29b33"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-06-22 02:56:33"
  condition:
    hash.sha256(0, filesize) == "4121a0bfb7059830e5ec9cc01126e37a5840987833ed524707356ae493d29b33"
}

rule MalwareBazaar_Mirai_033_b92abe3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b92abe3dde271635548f3b6c2e93f24548c2f11611bac731d6e01d835ec95775"
    family = "Mirai"
    file_name = "sora.arm5"
    file_type = "elf"
    first_seen = "2026-06-22 02:55:52"
  condition:
    hash.sha256(0, filesize) == "b92abe3dde271635548f3b6c2e93f24548c2f11611bac731d6e01d835ec95775"
}

rule MalwareBazaar_Mirai_034_d0345ab1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0345ab1663c0153617184e5c970a566e0b8965ab364a1c9eea7cdecad15cd61"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-06-22 02:55:40"
  condition:
    hash.sha256(0, filesize) == "d0345ab1663c0153617184e5c970a566e0b8965ab364a1c9eea7cdecad15cd61"
}

rule MalwareBazaar_Mirai_035_ce0b3137
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce0b3137383e4112269155f36dfa6c238f6e4d57d73555c15b2c4ef796afbab3"
    family = "Mirai"
    file_name = "sora.arm5"
    file_type = "elf"
    first_seen = "2026-06-22 02:54:29"
  condition:
    hash.sha256(0, filesize) == "ce0b3137383e4112269155f36dfa6c238f6e4d57d73555c15b2c4ef796afbab3"
}

rule MalwareBazaar_Mirai_036_0238e06a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0238e06a1ac58756abb6a5d261aa720ee600d7a8bf16fc50bf134251f6df5efd"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-06-22 02:53:19"
  condition:
    hash.sha256(0, filesize) == "0238e06a1ac58756abb6a5d261aa720ee600d7a8bf16fc50bf134251f6df5efd"
}

rule MalwareBazaar_Mirai_037_3b11d33e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b11d33e8f3ca26375350fe631f78c09d42a017d156c8022b74c4a9c280c1381"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-06-22 02:50:33"
  condition:
    hash.sha256(0, filesize) == "3b11d33e8f3ca26375350fe631f78c09d42a017d156c8022b74c4a9c280c1381"
}

rule MalwareBazaar_Mirai_038_3585bbb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3585bbb1adae6cca2e8c084e893cc05c81c11fab54f53c22567bc683aa0f8774"
    family = "Mirai"
    file_name = "sora.sh4"
    file_type = "elf"
    first_seen = "2026-06-22 02:50:31"
  condition:
    hash.sha256(0, filesize) == "3585bbb1adae6cca2e8c084e893cc05c81c11fab54f53c22567bc683aa0f8774"
}

rule MalwareBazaar_Mirai_039_9a73e54c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a73e54c5aaf4ae3291fd4ae23059c5a9bfbebd4abbf794d1840362a81bfb9ec"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-06-22 02:50:30"
  condition:
    hash.sha256(0, filesize) == "9a73e54c5aaf4ae3291fd4ae23059c5a9bfbebd4abbf794d1840362a81bfb9ec"
}

rule MalwareBazaar_unknown_040_f197de37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f197de37ab531b3db10d24757e3668602901389878afe2e11546a3f6be5d818d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-22 02:48:11"
  condition:
    hash.sha256(0, filesize) == "f197de37ab531b3db10d24757e3668602901389878afe2e11546a3f6be5d818d"
}

rule MalwareBazaar_Mirai_041_639015f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "639015f49fe00afa52244a61ddc8b32969ce8c884fc709281cb1f2938b447e4a"
    family = "Mirai"
    file_name = "sora.m68k"
    file_type = "elf"
    first_seen = "2026-06-22 02:46:43"
  condition:
    hash.sha256(0, filesize) == "639015f49fe00afa52244a61ddc8b32969ce8c884fc709281cb1f2938b447e4a"
}

rule MalwareBazaar_Mirai_042_c03210e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c03210e941c3de902810021ae1364922f797eb3432f5d4390d3982c495961d36"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-06-22 02:45:30"
  condition:
    hash.sha256(0, filesize) == "c03210e941c3de902810021ae1364922f797eb3432f5d4390d3982c495961d36"
}

rule MalwareBazaar_Mirai_043_a3cb43a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3cb43a29e0f181f1145426e70fccdce8e04ce82c667ab0861426f31670e75a5"
    family = "Mirai"
    file_name = "data_mips-uclibc"
    file_type = "elf"
    first_seen = "2026-06-22 02:45:29"
  condition:
    hash.sha256(0, filesize) == "a3cb43a29e0f181f1145426e70fccdce8e04ce82c667ab0861426f31670e75a5"
}

rule MalwareBazaar_Mirai_044_9bbed06d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bbed06deb57b262ed1a74cdb6d17ca21161163cbada6538267b6afd00e61cb6"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-06-22 02:43:10"
  condition:
    hash.sha256(0, filesize) == "9bbed06deb57b262ed1a74cdb6d17ca21161163cbada6538267b6afd00e61cb6"
}

rule MalwareBazaar_Mirai_045_84bf32c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84bf32c6c5852dcfe76cfe8ce6b40a4408603b3e52137a9562bfddbaddc760b2"
    family = "Mirai"
    file_name = "sora.mips"
    file_type = "elf"
    first_seen = "2026-06-22 02:40:51"
  condition:
    hash.sha256(0, filesize) == "84bf32c6c5852dcfe76cfe8ce6b40a4408603b3e52137a9562bfddbaddc760b2"
}

rule MalwareBazaar_Mirai_046_84a09f4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84a09f4fdf90abd5364f982b3d7d49aabf862a38bc78b66bf23014daaf19d8ae"
    family = "Mirai"
    file_name = "sora.mips"
    file_type = "elf"
    first_seen = "2026-06-22 02:39:19"
  condition:
    hash.sha256(0, filesize) == "84a09f4fdf90abd5364f982b3d7d49aabf862a38bc78b66bf23014daaf19d8ae"
}

rule MalwareBazaar_Mirai_047_fcc9249b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcc9249b4f188e5a66fca4fd3811585f16438e7dd0542301f1575209010fad90"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-06-22 02:34:19"
  condition:
    hash.sha256(0, filesize) == "fcc9249b4f188e5a66fca4fd3811585f16438e7dd0542301f1575209010fad90"
}

rule MalwareBazaar_Mirai_048_2ec11059
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec11059183fff0a0da44a9e8a4bffea0d55dd8e31dc966bbb52c5435530dc48"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-22 02:34:18"
  condition:
    hash.sha256(0, filesize) == "2ec11059183fff0a0da44a9e8a4bffea0d55dd8e31dc966bbb52c5435530dc48"
}

rule MalwareBazaar_unknown_049_c6473b0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6473b0fc4ebd18ab4ffe6771c77cece197e40299cac3745bbc12c0bea2261bf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-22 02:33:26"
  condition:
    hash.sha256(0, filesize) == "c6473b0fc4ebd18ab4ffe6771c77cece197e40299cac3745bbc12c0bea2261bf"
}

rule MalwareBazaar_Mirai_050_5ea5fd60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ea5fd6006918909f9026626019e19b00f8935ec9f03b9cab6d8f88ac8c77e8c"
    family = "Mirai"
    file_name = "sora.arm6"
    file_type = "elf"
    first_seen = "2026-06-22 02:33:22"
  condition:
    hash.sha256(0, filesize) == "5ea5fd6006918909f9026626019e19b00f8935ec9f03b9cab6d8f88ac8c77e8c"
}

rule MalwareBazaar_Mirai_051_0d4ecc9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d4ecc9f1c7e94da3e93389cc98088fe162a4ef1ba90d54330411fd92ea3ed3a"
    family = "Mirai"
    file_name = "sora.arm6"
    file_type = "elf"
    first_seen = "2026-06-22 02:33:07"
  condition:
    hash.sha256(0, filesize) == "0d4ecc9f1c7e94da3e93389cc98088fe162a4ef1ba90d54330411fd92ea3ed3a"
}

rule MalwareBazaar_unknown_052_7ba980da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ba980da964f7c1e6e90364932cc8a4ea035d123dd4e2a8a61fb6a7df130e590"
    family = "unknown"
    file_name = "Launcher.zip"
    file_type = "zip"
    first_seen = "2026-06-22 02:28:44"
  condition:
    hash.sha256(0, filesize) == "7ba980da964f7c1e6e90364932cc8a4ea035d123dd4e2a8a61fb6a7df130e590"
}

rule MalwareBazaar_unknown_053_2c526036
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c5260360de10f214b6ed6b612ad463bb5341ffd17d4900b50bf607d4e94d17e"
    family = "unknown"
    file_name = "loader.zip"
    file_type = "zip"
    first_seen = "2026-06-22 02:17:16"
  condition:
    hash.sha256(0, filesize) == "2c5260360de10f214b6ed6b612ad463bb5341ffd17d4900b50bf607d4e94d17e"
}

rule MalwareBazaar_unknown_054_967e1665
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "967e1665f6935556bdaf20d9060eb03d45382a5c0dd232675daac3c6962e2a86"
    family = "unknown"
    file_name = "YimMenuV2.dll"
    file_type = "exe"
    first_seen = "2026-06-22 02:07:35"
  condition:
    hash.sha256(0, filesize) == "967e1665f6935556bdaf20d9060eb03d45382a5c0dd232675daac3c6962e2a86"
}

rule MalwareBazaar_unknown_055_3898a662
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3898a662f25925b6b46700297832940cfc026f5e59815fe670328a0213094a3b"
    family = "unknown"
    file_name = "Requirement.vbs"
    file_type = "vbs"
    first_seen = "2026-06-22 02:03:33"
  condition:
    hash.sha256(0, filesize) == "3898a662f25925b6b46700297832940cfc026f5e59815fe670328a0213094a3b"
}

rule MalwareBazaar_SalatStealer_056_0b8cae27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8cae277bf0e3f0f33c5c44e5fd0dac50278086dd5769f9d96c44d748d8a90b"
    family = "SalatStealer"
    file_name = "SynInstallerV2.exe"
    file_type = "exe"
    first_seen = "2026-06-22 02:00:44"
  condition:
    hash.sha256(0, filesize) == "0b8cae277bf0e3f0f33c5c44e5fd0dac50278086dd5769f9d96c44d748d8a90b"
}

rule MalwareBazaar_GuLoader_057_e9b9e9b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9b9e9b3ba47548c9f0937837bf16550f573c25f7405e8cfbf45519d79ccde4e"
    family = "GuLoader"
    file_name = "rDirectricesdepol__ticasparaempleados_2026_pdf.exe"
    file_type = "exe"
    first_seen = "2026-06-22 02:00:07"
  condition:
    hash.sha256(0, filesize) == "e9b9e9b3ba47548c9f0937837bf16550f573c25f7405e8cfbf45519d79ccde4e"
}

rule MalwareBazaar_unknown_058_273ec09a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "273ec09aec45d6a7996f61e2d4fca07bea84a00f3544fad64091c239f4d93312"
    family = "unknown"
    file_name = "app1f.exe"
    file_type = "exe"
    first_seen = "2026-06-22 01:56:10"
  condition:
    hash.sha256(0, filesize) == "273ec09aec45d6a7996f61e2d4fca07bea84a00f3544fad64091c239f4d93312"
}

rule MalwareBazaar_unknown_059_a1c6e89e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1c6e89e932a2d62b1b2bd848b96e8873d78f324dbfaaca5a2f93d218b47d12f"
    family = "unknown"
    file_name = "Setup.bat"
    file_type = "bat"
    first_seen = "2026-06-22 01:50:57"
  condition:
    hash.sha256(0, filesize) == "a1c6e89e932a2d62b1b2bd848b96e8873d78f324dbfaaca5a2f93d218b47d12f"
}

rule MalwareBazaar_Vidar_060_f9814cb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9814cb4822b66a5ad8a479656a2fff57ad90d1294a0c4265ae9ab61ac173b80"
    family = "Vidar"
    file_name = "WandEnhancer.exe"
    file_type = "exe"
    first_seen = "2026-06-22 01:33:22"
  condition:
    hash.sha256(0, filesize) == "f9814cb4822b66a5ad8a479656a2fff57ad90d1294a0c4265ae9ab61ac173b80"
}

rule MalwareBazaar_GuLoader_061_1f3e92fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f3e92fb275fbea7f31629cfc5621c0e190d0ac7f97bde500b8c029ae2fa1fd1"
    family = "GuLoader"
    file_name = "nxEDticas_para_empleados_2026_pdf.bz2"
    file_type = "rar"
    first_seen = "2026-06-22 01:31:13"
  condition:
    hash.sha256(0, filesize) == "1f3e92fb275fbea7f31629cfc5621c0e190d0ac7f97bde500b8c029ae2fa1fd1"
}

rule MalwareBazaar_NanoCore_062_6f0219fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f0219fb619845864f18d8dbe093e323fe6bd9a314e10c5affe9549024029b70"
    family = "NanoCore"
    file_name = "skyupdragon.io.exe"
    file_type = "exe"
    first_seen = "2026-06-22 01:25:05"
  condition:
    hash.sha256(0, filesize) == "6f0219fb619845864f18d8dbe093e323fe6bd9a314e10c5affe9549024029b70"
}

rule MalwareBazaar_Vidar_063_d71d22dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d71d22dc0f225dd41a6bf2571b8206b378a87358d429d8f3a3b4119d59f407d5"
    family = "Vidar"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-22 01:21:01"
  condition:
    hash.sha256(0, filesize) == "d71d22dc0f225dd41a6bf2571b8206b378a87358d429d8f3a3b4119d59f407d5"
}

rule MalwareBazaar_Vidar_064_dd57db91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd57db91a672c68953f58462b9e386591f6731c6ee1ec1b699d29b62d4c18572"
    family = "Vidar"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-22 01:14:29"
  condition:
    hash.sha256(0, filesize) == "dd57db91a672c68953f58462b9e386591f6731c6ee1ec1b699d29b62d4c18572"
}

rule MalwareBazaar_unknown_065_2a611c28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a611c288e28b6da39219263ae00cb2a7ae710d2fbce76f5668c423f593dfc06"
    family = "unknown"
    file_name = "2a611c288e28b6da39219263ae00cb2a7ae710d2fbce76f5668c423f593dfc06"
    file_type = "unknown"
    first_seen = "2026-06-22 01:01:05"
  condition:
    hash.sha256(0, filesize) == "2a611c288e28b6da39219263ae00cb2a7ae710d2fbce76f5668c423f593dfc06"
}

rule MalwareBazaar_unknown_066_ed8060fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed8060fe81b7f72936bdda1f1fbb83a96084ad28082ddacb88a59a48b1db0ab5"
    family = "unknown"
    file_name = "Cs2Hack.exe"
    file_type = "exe"
    first_seen = "2026-06-22 00:58:42"
  condition:
    hash.sha256(0, filesize) == "ed8060fe81b7f72936bdda1f1fbb83a96084ad28082ddacb88a59a48b1db0ab5"
}

rule MalwareBazaar_unknown_067_dd2fb463
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd2fb463fd8857ce858b96a6b2ec88ebbc2fd724b82a591f69576614f8c81e5b"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-22 00:48:30"
  condition:
    hash.sha256(0, filesize) == "dd2fb463fd8857ce858b96a6b2ec88ebbc2fd724b82a591f69576614f8c81e5b"
}

rule MalwareBazaar_Vidar_068_401fa3c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "401fa3c82b2b7705753063bc7ea3e752b4bf4939736ea6d5949456a0e0407f64"
    family = "Vidar"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-06-22 00:47:04"
  condition:
    hash.sha256(0, filesize) == "401fa3c82b2b7705753063bc7ea3e752b4bf4939736ea6d5949456a0e0407f64"
}

rule MalwareBazaar_unknown_069_7a913722
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a913722f58debf79258bce36700ee2628f866c81e80bfeb8e1d86a8c42a3a51"
    family = "unknown"
    file_name = "MacOS.Setup.dmg"
    file_type = "dmg"
    first_seen = "2026-06-22 00:45:48"
  condition:
    hash.sha256(0, filesize) == "7a913722f58debf79258bce36700ee2628f866c81e80bfeb8e1d86a8c42a3a51"
}

rule MalwareBazaar_unknown_070_27be0289
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27be02890b7e55b800c6b5cdab16f66af68246472644a2127a564f04f62cde25"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-22 00:43:09"
  condition:
    hash.sha256(0, filesize) == "27be02890b7e55b800c6b5cdab16f66af68246472644a2127a564f04f62cde25"
}

rule MalwareBazaar_Vidar_071_f173bf95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f173bf9573df7fe9137d8c9a4fbac2b108187a250ee9b830ec3873bccd4ea10c"
    family = "Vidar"
    file_name = "loader.exe"
    file_type = "exe"
    first_seen = "2026-06-22 00:42:12"
  condition:
    hash.sha256(0, filesize) == "f173bf9573df7fe9137d8c9a4fbac2b108187a250ee9b830ec3873bccd4ea10c"
}

rule MalwareBazaar_unknown_072_30a67224
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30a67224d05ec98f9412a89018bfebe705d55d36a66e1acaf633713e65f322f8"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-06-22 00:33:11"
  condition:
    hash.sha256(0, filesize) == "30a67224d05ec98f9412a89018bfebe705d55d36a66e1acaf633713e65f322f8"
}

rule MalwareBazaar_unknown_073_801e5217
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "801e5217b0436f2531b40777da305d5017d6db19b545db051d82c9910f9d223d"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-06-22 00:27:23"
  condition:
    hash.sha256(0, filesize) == "801e5217b0436f2531b40777da305d5017d6db19b545db051d82c9910f9d223d"
}

rule MalwareBazaar_unknown_074_19d79017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19d7901717a2bb73ff855bc3e5e652305aa97bd9bb9584ee6efd1b8dc9c5426b"
    family = "unknown"
    file_name = "gup_util.dll"
    file_type = "exe"
    first_seen = "2026-06-22 00:26:51"
  condition:
    hash.sha256(0, filesize) == "19d7901717a2bb73ff855bc3e5e652305aa97bd9bb9584ee6efd1b8dc9c5426b"
}

rule MalwareBazaar_NanoCore_075_74bc14db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74bc14dbea1315b1d953c16382b3373233aa245b9b6ab5301a9f6943c0a67887"
    family = "NanoCore"
    file_name = "2f6a5ce3a14122f2cdfc94278106037e.exe"
    file_type = "exe"
    first_seen = "2026-06-22 00:25:04"
  condition:
    hash.sha256(0, filesize) == "74bc14dbea1315b1d953c16382b3373233aa245b9b6ab5301a9f6943c0a67887"
}

rule MalwareBazaar_unknown_076_77276fd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77276fd72e3394ab7daf64241538e56fe4e742d6e6d1c8649fdff48012a1e6e6"
    family = "unknown"
    file_name = "HSBC_PAYMENT_ADVICEpdf.js"
    file_type = "js"
    first_seen = "2026-06-22 00:00:37"
  condition:
    hash.sha256(0, filesize) == "77276fd72e3394ab7daf64241538e56fe4e742d6e6d1c8649fdff48012a1e6e6"
}

rule MalwareBazaar_unknown_077_8f24897a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f24897afca9c8fd5a48a78d6ab1476eafb18e7721e7772df114da4f58e1eac1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 22:48:40"
  condition:
    hash.sha256(0, filesize) == "8f24897afca9c8fd5a48a78d6ab1476eafb18e7721e7772df114da4f58e1eac1"
}

rule MalwareBazaar_Stealc_078_fdfaed38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdfaed3893bb2cf3ebd547c889e17c1e2f0b90208ecccc8591164bec41cfdb85"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 21:48:28"
  condition:
    hash.sha256(0, filesize) == "fdfaed3893bb2cf3ebd547c889e17c1e2f0b90208ecccc8591164bec41cfdb85"
}

rule MalwareBazaar_Mirai_079_d9513db8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9513db87bf97bde479458f36a19ece64b1c2dd49e4efc012a7dacca71f43105"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-21 21:41:33"
  condition:
    hash.sha256(0, filesize) == "d9513db87bf97bde479458f36a19ece64b1c2dd49e4efc012a7dacca71f43105"
}

rule MalwareBazaar_unknown_080_5a7c140b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a7c140bec69c33b8d5cf065040c6239a231091976e1b8725680539ca5910640"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-21 21:39:11"
  condition:
    hash.sha256(0, filesize) == "5a7c140bec69c33b8d5cf065040c6239a231091976e1b8725680539ca5910640"
}

rule MalwareBazaar_unknown_081_a31bbac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a31bbac723d61178ae45f02937f67b694256220327989155044f9cd97763fca6"
    family = "unknown"
    file_name = "Shipping document.vbs"
    file_type = "vbs"
    first_seen = "2026-06-21 21:35:04"
  condition:
    hash.sha256(0, filesize) == "a31bbac723d61178ae45f02937f67b694256220327989155044f9cd97763fca6"
}

rule MalwareBazaar_RemusStealer_082_8f4ac040
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f4ac0403edc15f1eddc1da8239319c9df2e86720fc2508746ed0660a0cc2918"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 21:12:52"
  condition:
    hash.sha256(0, filesize) == "8f4ac0403edc15f1eddc1da8239319c9df2e86720fc2508746ed0660a0cc2918"
}

rule MalwareBazaar_Mirai_083_7ec7b47e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ec7b47e370811f8b4188b220bb68d4d4e659d200013b654d0c2b36a37422d89"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-06-21 20:46:37"
  condition:
    hash.sha256(0, filesize) == "7ec7b47e370811f8b4188b220bb68d4d4e659d200013b654d0c2b36a37422d89"
}

rule MalwareBazaar_Mirai_084_13db3cd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13db3cd49df1b6a09fae27045f6a87fa4ccc413732fa37fc6b1955f38ab0167f"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-06-21 20:45:46"
  condition:
    hash.sha256(0, filesize) == "13db3cd49df1b6a09fae27045f6a87fa4ccc413732fa37fc6b1955f38ab0167f"
}

rule MalwareBazaar_Mirai_085_3d21695c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d21695cf0c4ed5889dac2d4f13e0b11e585b3ad06dd23e66630b0d86e3e866e"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-21 20:38:23"
  condition:
    hash.sha256(0, filesize) == "3d21695cf0c4ed5889dac2d4f13e0b11e585b3ad06dd23e66630b0d86e3e866e"
}

rule MalwareBazaar_unknown_086_5e077144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e0771444dbdd0f4263d10b3918fa0982191b12494d3cf93002a0ab22bc7ab38"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-21 20:38:22"
  condition:
    hash.sha256(0, filesize) == "5e0771444dbdd0f4263d10b3918fa0982191b12494d3cf93002a0ab22bc7ab38"
}

rule MalwareBazaar_unknown_087_0c13889d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c13889d0f9c8aac6880838de43150547d8bce4fb8921af47b56db9d4dc65ddd"
    family = "unknown"
    file_name = "pithus_sample_0c13889d0f9c8aac6880838de43150547d8bce4fb8921af47b56db9d4dc65ddd.apk"
    file_type = "apk"
    first_seen = "2026-06-21 20:36:52"
  condition:
    hash.sha256(0, filesize) == "0c13889d0f9c8aac6880838de43150547d8bce4fb8921af47b56db9d4dc65ddd"
}

rule MalwareBazaar_unknown_088_28fcf6f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28fcf6f84caeadf9245bb039a2057944eb34a47c1d3a88fd2a0eaefc48e9dbfd"
    family = "unknown"
    file_name = "Vy(1).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:23:12"
  condition:
    hash.sha256(0, filesize) == "28fcf6f84caeadf9245bb039a2057944eb34a47c1d3a88fd2a0eaefc48e9dbfd"
}

rule MalwareBazaar_unknown_089_3dda7724
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dda7724f33b2b89585cc36522f167260bda9314eb22e07a370079a51de48439"
    family = "unknown"
    file_name = "Vy.ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:23:06"
  condition:
    hash.sha256(0, filesize) == "3dda7724f33b2b89585cc36522f167260bda9314eb22e07a370079a51de48439"
}

rule MalwareBazaar_unknown_090_858e9575
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "858e95756f32a2833275064e8a18ae1a8de873bbf7ed661570cfdfc37953544d"
    family = "unknown"
    file_name = "NgOVP(3).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:59"
  condition:
    hash.sha256(0, filesize) == "858e95756f32a2833275064e8a18ae1a8de873bbf7ed661570cfdfc37953544d"
}

rule MalwareBazaar_unknown_091_50264e6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50264e6ef48f2bdff1180fa72733a8a8a693990d84d1a6ce0009898d81b09a92"
    family = "unknown"
    file_name = "NgOVP(2).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:53"
  condition:
    hash.sha256(0, filesize) == "50264e6ef48f2bdff1180fa72733a8a8a693990d84d1a6ce0009898d81b09a92"
}

rule MalwareBazaar_unknown_092_9bf3e590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bf3e590250b86e1e9dee20e6200b67983e6f48d1ccc07559a5835d7d85d72e6"
    family = "unknown"
    file_name = "NgOVP(1).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:46"
  condition:
    hash.sha256(0, filesize) == "9bf3e590250b86e1e9dee20e6200b67983e6f48d1ccc07559a5835d7d85d72e6"
}

rule MalwareBazaar_unknown_093_05d93906
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05d9390632b8587d961e4fb1b6deb836887852c496f110397121b567e98ac3b8"
    family = "unknown"
    file_name = "NgOVP.ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:40"
  condition:
    hash.sha256(0, filesize) == "05d9390632b8587d961e4fb1b6deb836887852c496f110397121b567e98ac3b8"
}

rule MalwareBazaar_unknown_094_b680dc58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b680dc5815223eff566b30fa251267b91b1f10d2eec2522311def684b4baf59a"
    family = "unknown"
    file_name = "Lwoqo(3).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:34"
  condition:
    hash.sha256(0, filesize) == "b680dc5815223eff566b30fa251267b91b1f10d2eec2522311def684b4baf59a"
}

rule MalwareBazaar_unknown_095_984ca97d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "984ca97d34361cafaac92a5f2617931f3dd38ef71774eb29cf8a795a31ab3b6b"
    family = "unknown"
    file_name = "Lwoqo(2).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:29"
  condition:
    hash.sha256(0, filesize) == "984ca97d34361cafaac92a5f2617931f3dd38ef71774eb29cf8a795a31ab3b6b"
}

rule MalwareBazaar_unknown_096_fa93ea4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa93ea4a6ce497c4f94ef8d50e451ff1ee81825319bfcf180eb003a61bec3568"
    family = "unknown"
    file_name = "Lwoqo(1).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:23"
  condition:
    hash.sha256(0, filesize) == "fa93ea4a6ce497c4f94ef8d50e451ff1ee81825319bfcf180eb003a61bec3568"
}

rule MalwareBazaar_unknown_097_36305159
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "363051592819af125a1b2b5e7b286d7e782267f41e4699db78c91fac2c0b26ee"
    family = "unknown"
    file_name = "Lwoqo.ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:18"
  condition:
    hash.sha256(0, filesize) == "363051592819af125a1b2b5e7b286d7e782267f41e4699db78c91fac2c0b26ee"
}

rule MalwareBazaar_unknown_098_c722b655
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c722b6557d74a0a6eab889a5e7d81032ff18759bb42928be3a8e4393b1e26f39"
    family = "unknown"
    file_name = "DvVbs(1).ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:13"
  condition:
    hash.sha256(0, filesize) == "c722b6557d74a0a6eab889a5e7d81032ff18759bb42928be3a8e4393b1e26f39"
}

rule MalwareBazaar_unknown_099_9e64eab0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e64eab0015911243a17b43f5a4bdbbf41516b1063fc70722acb3d8492434dd2"
    family = "unknown"
    file_name = "DvVbs.ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:08"
  condition:
    hash.sha256(0, filesize) == "9e64eab0015911243a17b43f5a4bdbbf41516b1063fc70722acb3d8492434dd2"
}

rule MalwareBazaar_unknown_100_400ca3bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "400ca3bc5a546716fec62a3f5e5730585d2d0acb24b973e40e4321a4be3ea9d3"
    family = "unknown"
    file_name = "42662A7F.ps1"
    file_type = "ps1"
    first_seen = "2026-06-21 20:22:03"
  condition:
    hash.sha256(0, filesize) == "400ca3bc5a546716fec62a3f5e5730585d2d0acb24b973e40e4321a4be3ea9d3"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

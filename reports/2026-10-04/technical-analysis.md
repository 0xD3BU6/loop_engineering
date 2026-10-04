# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-04

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 684 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 684 |
| Unique family labels | 8 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 55 |
| Mirai | 30 |
| VShell | 6 |
| Gafgyt | 5 |
| Neshta | 1 |
| CoinMiner | 1 |
| Troldesh | 1 |
| njrat | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 63 |
| exe | 24 |
| zip | 9 |
| sh | 3 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `020562055a7854f8`

| Field | Value |
|---|---|
| SHA-256 | `020562055a7854f8dac64b0e50e8befb6dc238da70bdaca0a1bd77f802a1b815` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-04 05:55:25` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d16a929d53c4969c17b7add10b076c2` |
| SHA-1 | `77404c812afae69ae59652ed96905cba6f4e07ab` |
| SHA-256 | `020562055a7854f8dac64b0e50e8befb6dc238da70bdaca0a1bd77f802a1b815` |
| SHA3-384 | `d2a8285eb1e79291a4174d9a7a6321047a5b82be1717afc7cbd547f3cb132ba8fa8a8e93bdfefbf72e9318f986b0a93e` |
| TLSH | `T160664B537A7CE70EE228223448B2CAC5AB6D1C4641E6991BA391F31DE4F316C4D6EDF1` |
| TELFHASH | `t16db0921788a00a48a0a248c15ec4715140e2ec23282965aebf750d934e0e806006d006` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:vscCGySWYIIILa0iyccz+w0MPx5wx25DJNDOXC5nLyD0nW0qc0sMflGzhH9fOIha:uJ5n4flmWXn4jEv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_02056205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "020562055a7854f8dac64b0e50e8befb6dc238da70bdaca0a1bd77f802a1b815"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-04 05:55:25"
  condition:
    hash.sha256(0, filesize) == "020562055a7854f8dac64b0e50e8befb6dc238da70bdaca0a1bd77f802a1b815"
}
```

### Sample 2: `6f272c85365a1783`

| Field | Value |
|---|---|
| SHA-256 | `6f272c85365a1783eedbf7bc80112db52d13bca5415703df127b869b23bc179f` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-04 05:55:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66ea3e308a7748cc4685b5db0b406ddc` |
| SHA-1 | `065cdd56b75a40e7501f58010324c86cf1f9a7b1` |
| SHA-256 | `6f272c85365a1783eedbf7bc80112db52d13bca5415703df127b869b23bc179f` |
| SHA3-384 | `67f78f3c4956de4a06d6d313ad850a73cdd47bfcf7fdcaa454a0ac2f072ef0e414943ceff4da13f9a309f44e4de4731d` |
| TLSH | `T15FE33C02758194FEC4C6C1708BAFD137D676F89D62303E6F7B903F692E26E612B0A651` |
| TELFHASH | `t18c51ef341f9176786297ab4bb30bdf7df8b6051109f6b1d4ef476de1cc2628a0d4a042` |
| SSDEEP | `3072:IWczVbzMi3z5v9uRlfL/9Oapvl+DIqJl69/f:DcrVuRlfL9OoNzr9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_6f272c85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f272c85365a1783eedbf7bc80112db52d13bca5415703df127b869b23bc179f"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-04 05:55:22"
  condition:
    hash.sha256(0, filesize) == "6f272c85365a1783eedbf7bc80112db52d13bca5415703df127b869b23bc179f"
}
```

### Sample 3: `3a62981cefd10b2f`

| Field | Value |
|---|---|
| SHA-256 | `3a62981cefd10b2f552ad81e90397160f0b986ae09ad711738cb903d82a0db2a` |
| Family label | `unknown` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-10-04 05:50:13` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `319f897636e1e4517425ac40158ca728` |
| SHA-1 | `3e7c19e38b6646f744c24815b82f1f6950d4c2e4` |
| SHA-256 | `3a62981cefd10b2f552ad81e90397160f0b986ae09ad711738cb903d82a0db2a` |
| SHA3-384 | `9c5cc2b56f1aa66761acfe5ff58031607528a20eeea8739a23c36f5ebfcce6001b46a86bcde099bf9c4b50a7b32bc072` |
| TLSH | `T123560797B9D24992C5E43677B8BD80C433630EBA8B8A56675D04FE3C3ABE1D90E35314` |
| TELFHASH | `t12ee068829f1c2a942ae18351069904ae8de530fc13006bcc8faeb7cf4703a25b0d682b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:qxLM9IfT9KLjtvicDk6m7a8Cz9BnYtVNi9MQTgXv5E4:O2mT9KLjZFDk9IBsni9zUE4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_3a62981c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a62981cefd10b2f552ad81e90397160f0b986ae09ad711738cb903d82a0db2a"
    family = "unknown"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-04 05:50:13"
  condition:
    hash.sha256(0, filesize) == "3a62981cefd10b2f552ad81e90397160f0b986ae09ad711738cb903d82a0db2a"
}
```

### Sample 4: `413f1b952a7422b8`

| Field | Value |
|---|---|
| SHA-256 | `413f1b952a7422b8f69418117d1dca5c2898320dd33a89a2ed286afc3c181ffc` |
| Family label | `unknown` |
| File name | `413f1b952a7422b8.bin` |
| File type | `exe` |
| First seen | `2026-10-04 05:25:22` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `610a1ef089b0ae001ad4913376126755` |
| SHA-1 | `3a93cfe8b207ff5c2a98c6f54b964bc2b07c1a59` |
| SHA-256 | `413f1b952a7422b8f69418117d1dca5c2898320dd33a89a2ed286afc3c181ffc` |
| SHA3-384 | `cbe34d7e1174c2eaaa38816bb5869e544ffde85ef12d8a2dbe496a40a4f4157da1ab7b5882b0c800f02d780d57a8aed3` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T14B26023FB28B753EE06E5A3A7A72E210543B7A61A5178C0396F4C84CCF255702D3E796` |
| SSDEEP | `98304:j5Ouz/xxqt3cg8xDVyhg4LlQXD9t0L8sh+v64cU:99Zxqt3cg8xDVD6Y/0vhlZU` |
| ICON-DHASH | `80831f1c691f5035` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_413f1b95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "413f1b952a7422b8f69418117d1dca5c2898320dd33a89a2ed286afc3c181ffc"
    family = "unknown"
    file_name = "413f1b952a7422b8.bin"
    file_type = "exe"
    first_seen = "2026-10-04 05:25:22"
  condition:
    hash.sha256(0, filesize) == "413f1b952a7422b8f69418117d1dca5c2898320dd33a89a2ed286afc3c181ffc"
}
```

### Sample 5: `7b770db576c2f2b2`

| Field | Value |
|---|---|
| SHA-256 | `7b770db576c2f2b2faccff016c1814d80aa4833c075fefc14a093380fa89bc81` |
| Family label | `unknown` |
| File name | `ppc64le` |
| File type | `elf` |
| First seen | `2026-10-04 05:23:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1791d489a7d5cb86e296b584ae5b5070` |
| SHA-1 | `7080ff60c262fb6c1d10412ed8cdcd8c18874e23` |
| SHA-256 | `7b770db576c2f2b2faccff016c1814d80aa4833c075fefc14a093380fa89bc81` |
| SHA3-384 | `33629a2a340773fab2a2da1aa934afda296c179ca4224f476a68345a4d4733d26fe664de69ff3ce0d3f260f5a6d1dff5` |
| TLSH | `T18E564B02FA092F95C964493389B74DA167A26D956B318B53DB04F27F7DB33021F26F88` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:RIExVrAJOziU2XRZfS+Sk31+lzid0glCLAQCW3d5EU:WExVrAMGU2XR9/WlICfBjEU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_7b770db5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b770db576c2f2b2faccff016c1814d80aa4833c075fefc14a093380fa89bc81"
    family = "unknown"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-10-04 05:23:48"
  condition:
    hash.sha256(0, filesize) == "7b770db576c2f2b2faccff016c1814d80aa4833c075fefc14a093380fa89bc81"
}
```

### Sample 6: `cab68c74edbe1f8c`

| Field | Value |
|---|---|
| SHA-256 | `cab68c74edbe1f8c79780c709701eca52fe1c711240d3cde2d186e6062ca28a7` |
| Family label | `unknown` |
| File name | `cab68c74edbe1f8c79780c709701eca52fe1c711240d3cde2d186e6062ca28a7.exe` |
| File type | `exe` |
| First seen | `2026-10-04 05:23:31` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfad2f424d3af96b2817132e83c27038` |
| SHA-1 | `b2d578024e67606d987d4223b454dc4676653484` |
| SHA-256 | `cab68c74edbe1f8c79780c709701eca52fe1c711240d3cde2d186e6062ca28a7` |
| SHA3-384 | `99ffe232bcef7134764bc6fd9cbc785bdafe7032301a9eec8135b1048d8773879d7cf5a1bbae16bacb7575b386318956` |
| IMPHASH | `46ce5c12b293febbeb513b196aa7f843` |
| TLSH | `T1962633F35130C651C83009321CB6196B7E662885852E2A47AE3E4E99FDE53D487BFDE3` |
| SSDEEP | `98304:9tNGKxmPUBUp4VYe5JYKHsOnKQrYheaONo2Mr2m5QGN6yjVQwckMv7XaH2kk:9t9qUBUpuBYXkYheaOtm5Qs6yiwc9rt` |
| ICON-DHASH | `c4dadadad2f492c2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_cab68c74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab68c74edbe1f8c79780c709701eca52fe1c711240d3cde2d186e6062ca28a7"
    family = "unknown"
    file_name = "cab68c74edbe1f8c79780c709701eca52fe1c711240d3cde2d186e6062ca28a7.exe"
    file_type = "exe"
    first_seen = "2026-10-04 05:23:31"
  condition:
    hash.sha256(0, filesize) == "cab68c74edbe1f8c79780c709701eca52fe1c711240d3cde2d186e6062ca28a7"
}
```

### Sample 7: `c34d30c61d5845ac`

| Field | Value |
|---|---|
| SHA-256 | `c34d30c61d5845ac1c62a2e248bf62afb0c2531eb6c140abeea7e6d594dc7449` |
| Family label | `Mirai` |
| File name | `c34d30c61d5845ac1c62a2e248bf62afb0c2531eb6c140abeea7e6d594dc7449` |
| File type | `elf` |
| First seen | `2026-10-04 05:17:16` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a4783039dfbb44e71a04c7b64f3187e` |
| SHA-1 | `79826b94f3b0e0904b37ae2c46e684621d826476` |
| SHA-256 | `c34d30c61d5845ac1c62a2e248bf62afb0c2531eb6c140abeea7e6d594dc7449` |
| SHA3-384 | `0236905561feb09bad16e5ad7b7ad37d1449952e9bf27a801675ee2a2b54a458870567d8ee070717733aaa3fc8923b33` |
| TLSH | `T19744398AFD81AF25D5D4227BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOk:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_c34d30c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c34d30c61d5845ac1c62a2e248bf62afb0c2531eb6c140abeea7e6d594dc7449"
    family = "Mirai"
    file_name = "c34d30c61d5845ac1c62a2e248bf62afb0c2531eb6c140abeea7e6d594dc7449"
    file_type = "elf"
    first_seen = "2026-10-04 05:17:16"
  condition:
    hash.sha256(0, filesize) == "c34d30c61d5845ac1c62a2e248bf62afb0c2531eb6c140abeea7e6d594dc7449"
}
```

### Sample 8: `5c15f8bfcc4d913e`

| Field | Value |
|---|---|
| SHA-256 | `5c15f8bfcc4d913e925f7504233f29b682820fcec3a3cdfc8225d19944ff4bf5` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-10-04 05:09:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `244aa6470f731b1f82cd57b65a6cd87d` |
| SHA-1 | `e0a5b0dfa33f0f1cea8ab78e4d49feef1fb9deda` |
| SHA-256 | `5c15f8bfcc4d913e925f7504233f29b682820fcec3a3cdfc8225d19944ff4bf5` |
| SHA3-384 | `3cec5753e96339a4acd1853658d61e55a6e1c1bdbcbc9eb8573fb2458112dbe057f7da1c5c356fb6ca25b868b75601ab` |
| TLSH | `T1AF347CA8EA0F7C01F1C2D3FDDE5C47E13A1775E3C77699B16D1212ACCAA38D99A90502` |
| SSDEEP | `6144:f8qzLsduCW+s22/PQI6+Qx7zuiJZV8uoq:0tS20oHLZ8uo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_5c15f8bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c15f8bfcc4d913e925f7504233f29b682820fcec3a3cdfc8225d19944ff4bf5"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-04 05:09:26"
  condition:
    hash.sha256(0, filesize) == "5c15f8bfcc4d913e925f7504233f29b682820fcec3a3cdfc8225d19944ff4bf5"
}
```

### Sample 9: `6188fff75bb18c6d`

| Field | Value |
|---|---|
| SHA-256 | `6188fff75bb18c6d61df6b9378542de07cbe01da1c162a5cc6ab6c5130b84457` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-10-04 05:08:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4578e5cd15dcff2e03563ffbfe28fe24` |
| SHA-1 | `1e8ca9dc300234d803e1875db16daf9e89626f30` |
| SHA-256 | `6188fff75bb18c6d61df6b9378542de07cbe01da1c162a5cc6ab6c5130b84457` |
| SHA3-384 | `68a9edafdf0163de312abece717abfbf9921173504e214b818b05a63523b2de3537de3e622d7b8d006496edd6507445c` |
| TLSH | `T1B0A3127EFC81CA27D4D0593E02100E9D26C7B2DE653C608B5725DE676E58A9C4CFD834` |
| SSDEEP | `3072:bx06xHsQ6R+SccDn0VeJuh3bhWw9YjPSed:b1qRFce0OuhL8Jqed` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_6188fff7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6188fff75bb18c6d61df6b9378542de07cbe01da1c162a5cc6ab6c5130b84457"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-04 05:08:48"
  condition:
    hash.sha256(0, filesize) == "6188fff75bb18c6d61df6b9378542de07cbe01da1c162a5cc6ab6c5130b84457"
}
```

### Sample 10: `1fee1a85a3ed0c8b`

| Field | Value |
|---|---|
| SHA-256 | `1fee1a85a3ed0c8b58f6c7eca67936f89a437a85ace95c5017992f853117d1b7` |
| Family label | `VShell` |
| File name | `1fee1a85a3ed0c8b58f6c7eca67936f89a437a85ace95c5017992f853117d1b7.exe` |
| File type | `exe` |
| First seen | `2026-10-04 05:05:20` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0da7f248ddd837ad8f0e18fb085546a6` |
| SHA-1 | `423a9aeff913e0fb6df07d0a23e3e1953df77e6c` |
| SHA-256 | `1fee1a85a3ed0c8b58f6c7eca67936f89a437a85ace95c5017992f853117d1b7` |
| SHA3-384 | `2870ebc73b51c36259920c0c720c4a7cb16df7bab11e97f26f4044f3fe95b7160fccef63f7eb1a035533fc38427c3fcd` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T14491A5C5F757E6B2EC1C17F500A3B9A4C4A82E1492BC9B464FA16F1C7C111AA3D3DA12` |
| SSDEEP | `48:6I7lwe7Ai08SyJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1t09Mq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_010_1fee1a85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fee1a85a3ed0c8b58f6c7eca67936f89a437a85ace95c5017992f853117d1b7"
    family = "VShell"
    file_name = "1fee1a85a3ed0c8b58f6c7eca67936f89a437a85ace95c5017992f853117d1b7.exe"
    file_type = "exe"
    first_seen = "2026-10-04 05:05:20"
  condition:
    hash.sha256(0, filesize) == "1fee1a85a3ed0c8b58f6c7eca67936f89a437a85ace95c5017992f853117d1b7"
}
```

### Sample 11: `0acd3c8901dabc91`

| Field | Value |
|---|---|
| SHA-256 | `0acd3c8901dabc919df29bcf58c70b29b4718d4b0c52538ab309d6582c0da1d1` |
| Family label | `unknown` |
| File name | `rev.sh` |
| File type | `sh` |
| First seen | `2026-10-04 05:03:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd6403ee32f5c11e9f1134799b7bc96d` |
| SHA-1 | `29061ec5362af864da231e55606086437334846e` |
| SHA-256 | `0acd3c8901dabc919df29bcf58c70b29b4718d4b0c52538ab309d6582c0da1d1` |
| SHA3-384 | `db24b064a0f8c0cfc362ab13dff517ef331d6d103b1cc122433ad440f2feb72c90d7b12406618710c8c72b3690d81493` |
| TLSH | `T1A3219AB2F1F12DB53F70845C6106D2313ADA2F528B8C9DF2987C5AA13A23654E090F10` |
| SSDEEP | `24:w1NLQ4e/vvwvvcPr+SrNvNSL5lOKVMst0TGz5lOKVMst0TGP:wTZ0Ou6SuOKv0TGGKv0TGP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_0acd3c89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0acd3c8901dabc919df29bcf58c70b29b4718d4b0c52538ab309d6582c0da1d1"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-10-04 05:03:57"
  condition:
    hash.sha256(0, filesize) == "0acd3c8901dabc919df29bcf58c70b29b4718d4b0c52538ab309d6582c0da1d1"
}
```

### Sample 12: `8ffb027ce4db2ef7`

| Field | Value |
|---|---|
| SHA-256 | `8ffb027ce4db2ef73388d63a5c821e2e5f5b9389264dd01db034f688f7734b3c` |
| Family label | `unknown` |
| File name | `8ffb027ce4db2ef73388d63a5c821e2e5f5b9389264dd01db034f688f7734b3c.exe` |
| File type | `exe` |
| First seen | `2026-10-04 05:03:34` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ae85f694952eb03b475e5ec4fec87ef` |
| SHA-1 | `364d099060ff5b9df20f653ac801ba1e286b0391` |
| SHA-256 | `8ffb027ce4db2ef73388d63a5c821e2e5f5b9389264dd01db034f688f7734b3c` |
| SHA3-384 | `4d90c16f7c87394ef13f0b2d0b2b89b2ed32ba8ae442f75236039892882009a19829629d0fb2da7dcf8bb77306b1ebed` |
| IMPHASH | `46ce5c12b293febbeb513b196aa7f843` |
| TLSH | `T1AC473373C778418EF2E649335F328B294F279DDC80035665AA282538683DB3DA5397B7` |
| SSDEEP | `393216:dGuNi20eg1Y+AwqqaKAm4NH8A+EdHjUsn0xHq3pkUWepQib5M/bZclqHJS48aHn1:dGuNN0h1paKAHNHSY4s0xHqBlpQibGeK` |
| ICON-DHASH | `c4dadadad2f492c2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_8ffb027c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ffb027ce4db2ef73388d63a5c821e2e5f5b9389264dd01db034f688f7734b3c"
    family = "unknown"
    file_name = "8ffb027ce4db2ef73388d63a5c821e2e5f5b9389264dd01db034f688f7734b3c.exe"
    file_type = "exe"
    first_seen = "2026-10-04 05:03:34"
  condition:
    hash.sha256(0, filesize) == "8ffb027ce4db2ef73388d63a5c821e2e5f5b9389264dd01db034f688f7734b3c"
}
```

### Sample 13: `92a2823956dc536c`

| Field | Value |
|---|---|
| SHA-256 | `92a2823956dc536c90228d54ffcf6c89d05c6c25e3746029eecb364a6d5a18f0` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-10-04 04:59:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a6282a3cfaba8d9ef85f67984d56647` |
| SHA-1 | `d02f7da297024147ca65fee0e97679859d2cf8b0` |
| SHA-256 | `92a2823956dc536c90228d54ffcf6c89d05c6c25e3746029eecb364a6d5a18f0` |
| SHA3-384 | `322f62306c2ec01e22543e7c0dc94a61f5cdf3933fe5770ed1fea01850aa90b75129b3a3a2360274cac38bada211018f` |
| TLSH | `T175141856FD419E16CAC256BBFB5E428D37270768D3EE72039D251F20379B86B0E3A141` |
| TELFHASH | `t162e0e517f30425e8b11644a98aff22729ae0a09d27a6357385a8ee8946a3dd06513a23` |
| SSDEEP | `3072:PTBczv4QvMsfSL3yrM09WGtw8d/DlzRJtYAKKBzQw1HPsl6/jPR+5TPVbHj:PTazv4QvMsKL3At9WGtwYpruXKBzQw1w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_92a28239
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92a2823956dc536c90228d54ffcf6c89d05c6c25e3746029eecb364a6d5a18f0"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-10-04 04:59:19"
  condition:
    hash.sha256(0, filesize) == "92a2823956dc536c90228d54ffcf6c89d05c6c25e3746029eecb364a6d5a18f0"
}
```

### Sample 14: `57234a9b103f3637`

| Field | Value |
|---|---|
| SHA-256 | `57234a9b103f3637891e9c54a5b78c04bcc56092b05db7418b4bb433be4dd11e` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-10-04 04:58:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd23bad799df42ed8dd8aa1019441fc5` |
| SHA-1 | `ab2f49ee383e5a290c859371602551b78df2136d` |
| SHA-256 | `57234a9b103f3637891e9c54a5b78c04bcc56092b05db7418b4bb433be4dd11e` |
| SHA3-384 | `33cf12ad5792db9d716a7498aa4e5c1eb42a587b2b79ed53a1242a8b4b9fde3a29c1cd0dfe30eff24fb112421d9529e8` |
| TLSH | `T15E7302F0FCCBFD1623B10D79D91288C172E649B1E49A2F22290369EDD359819F7AD742` |
| SSDEEP | `1536:irdQOs5NdkBBabB+/ZUYqsSJjHK4I4r3XljaZ0iFv2Hl22u141zzsx:4ds5N2B4bB+hUv/HJsZaHs2u1iz2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_57234a9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57234a9b103f3637891e9c54a5b78c04bcc56092b05db7418b4bb433be4dd11e"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-10-04 04:58:44"
  condition:
    hash.sha256(0, filesize) == "57234a9b103f3637891e9c54a5b78c04bcc56092b05db7418b4bb433be4dd11e"
}
```

### Sample 15: `20a73440b9ebfb55`

| Field | Value |
|---|---|
| SHA-256 | `20a73440b9ebfb5545dd0019a19b661b1c6aef5219901f034d1be9d251e5f4de` |
| Family label | `unknown` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-10-04 04:58:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4b0b9c6919a8f775dfd16dcd6cb7582` |
| SHA-1 | `15081e19d3c4cdfa0efee859bf538e2095d50817` |
| SHA-256 | `20a73440b9ebfb5545dd0019a19b661b1c6aef5219901f034d1be9d251e5f4de` |
| SHA3-384 | `42a693889cbc01a52b7e9e4bfc3004a59a1569b4a2632242b95beadf63932d047f4c43ddf9572dae1d05d88d38896fe4` |
| TLSH | `T1C766FA19ADC52BE6C82D5F3484FACA9612B45D100AF1473626A5FFA9BC772347F4388C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:iDvlQjZAhkeP+R3Ye1oY9SYKdnXaWK95EB:ttrlYzzuEB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_20a73440
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20a73440b9ebfb5545dd0019a19b661b1c6aef5219901f034d1be9d251e5f4de"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-04 04:58:41"
  condition:
    hash.sha256(0, filesize) == "20a73440b9ebfb5545dd0019a19b661b1c6aef5219901f034d1be9d251e5f4de"
}
```

### Sample 16: `84b59ccb6d604bee`

| Field | Value |
|---|---|
| SHA-256 | `84b59ccb6d604bee4e04706d70260ea57fca1408a892af95c4c86190414e2eb0` |
| Family label | `unknown` |
| File name | `cnc` |
| File type | `elf` |
| First seen | `2026-10-04 04:58:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6192a87f41c4770b8984ea340b92560` |
| SHA-1 | `c48a079efdb7bef5dcd7e2cf3ea41abb2c7ebefa` |
| SHA-256 | `84b59ccb6d604bee4e04706d70260ea57fca1408a892af95c4c86190414e2eb0` |
| SHA3-384 | `062b32c8ee281d7e0fabc8b7f77be01996a10e69fb5c28ebaa173073f4012b679df5b0869d8c99dfdf6ff27ba2cffc1f` |
| TLSH | `T1F1864943EDA555E8C1AEC23589B29113BB317C8A5B3123D71B50F6382F73BD0AAB9744` |
| TELFHASH | `t1fa4236754abc75b5b696da10b3a2b5f456372c9422f938f11027ec84ffc1e801ca687b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:LGMEobRS3Ji5E5fN6EJfYBaXf6iU1XG2gatizooFiJQnEriBP8Ju49NoUe5KHK5d:L6oNSYSfN6sYXIrz/bX18Jiw28Ej` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_84b59ccb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84b59ccb6d604bee4e04706d70260ea57fca1408a892af95c4c86190414e2eb0"
    family = "unknown"
    file_name = "cnc"
    file_type = "elf"
    first_seen = "2026-10-04 04:58:37"
  condition:
    hash.sha256(0, filesize) == "84b59ccb6d604bee4e04706d70260ea57fca1408a892af95c4c86190414e2eb0"
}
```

### Sample 17: `18b0bf993cf38b15`

| Field | Value |
|---|---|
| SHA-256 | `18b0bf993cf38b1585611b0d3424741955ac76a5d91ca0fa389accbeddce9b50` |
| Family label | `unknown` |
| File name | `zswap_shrinkd` |
| File type | `elf` |
| First seen | `2026-10-04 04:34:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6167135d7473ae2883f266ee362e146` |
| SHA-1 | `1da2b814b930b490cacfaf8a4589f291b87f18ce` |
| SHA-256 | `18b0bf993cf38b1585611b0d3424741955ac76a5d91ca0fa389accbeddce9b50` |
| SHA3-384 | `7cd57c1a7034923e52bedb65057eeb9510e4c273201e95725aef72562744f7bde4925874c2c68608a19aa92959510b72` |
| TLSH | `T1FC564B42FA092F95C524493389E34EA127766D586B314793E744F2BFACB330A0F56F98` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:vS5vyhuhaZRjyKQ7C3wweE0OO7eflmb34RgbwHMHQI35EI:a5vyhuhajjyT7Cgwee2TEI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_18b0bf99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18b0bf993cf38b1585611b0d3424741955ac76a5d91ca0fa389accbeddce9b50"
    family = "unknown"
    file_name = "zswap_shrinkd"
    file_type = "elf"
    first_seen = "2026-10-04 04:34:58"
  condition:
    hash.sha256(0, filesize) == "18b0bf993cf38b1585611b0d3424741955ac76a5d91ca0fa389accbeddce9b50"
}
```

### Sample 18: `57ae15c4725f1c66`

| Field | Value |
|---|---|
| SHA-256 | `57ae15c4725f1c6640905d816160069b6adb3f2b8751087590fe54db235de90e` |
| Family label | `unknown` |
| File name | `rcuop_0` |
| File type | `elf` |
| First seen | `2026-10-04 04:34:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b75da5f283682ebc586532931238468` |
| SHA-1 | `c67030f24349c9270c58963e44fdf48321a1a57e` |
| SHA-256 | `57ae15c4725f1c6640905d816160069b6adb3f2b8751087590fe54db235de90e` |
| SHA3-384 | `f91756ba26db1bf541e2f97314a0b605dd58dc82732174433a7c0f04ea7c85f7a35055285b81a8d19b2ab44961164aa6` |
| TLSH | `T1C6466C55FC1D7462E9C976752F7652983239BC484F82C3272624BB7CEAF23588F23261` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:q8BsmIdZQLpdyX4H0LOArw2B59it6d7CqLOJP+8neZ35Ew:qusmIdZQjyIH0frw2BfityYFeXEw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_57ae15c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57ae15c4725f1c6640905d816160069b6adb3f2b8751087590fe54db235de90e"
    family = "unknown"
    file_name = "rcuop_0"
    file_type = "elf"
    first_seen = "2026-10-04 04:34:52"
  condition:
    hash.sha256(0, filesize) == "57ae15c4725f1c6640905d816160069b6adb3f2b8751087590fe54db235de90e"
}
```

### Sample 19: `eead4ced63cc5350`

| Field | Value |
|---|---|
| SHA-256 | `eead4ced63cc53508d205537583eca3ed32ac2aba488ff55d4ff2153b645d350` |
| Family label | `unknown` |
| File name | `kblockd0` |
| File type | `elf` |
| First seen | `2026-10-04 04:34:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b582553bd57c47f82d34dc73c8ee4082` |
| SHA-1 | `0ed94b5e577ec6ef9c67627ad0f812e476f205f9` |
| SHA-256 | `eead4ced63cc53508d205537583eca3ed32ac2aba488ff55d4ff2153b645d350` |
| SHA3-384 | `7c602e62b82647f593a695654f7e9fc06b3854b10ee48e76f229b6712b8a4954260b11fde1ee5227bec06c1cdce284a0` |
| TLSH | `T1AF560857B8D24942C4E83637B8BE81C433635EBA9B8A52566D05FE3C3EBE1D90E35314` |
| TELFHASH | `t1ced05e66cf1c23cc57d0059249de026a4ee43efc1390bf498e69268a5a660ca709b455` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:MC+Ud92PpZFUS+6WtrcPUFT2kXsNXqUd+g5Ei:p+UT5i9qUdTEi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_eead4ced
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eead4ced63cc53508d205537583eca3ed32ac2aba488ff55d4ff2153b645d350"
    family = "unknown"
    file_name = "kblockd0"
    file_type = "elf"
    first_seen = "2026-10-04 04:34:46"
  condition:
    hash.sha256(0, filesize) == "eead4ced63cc53508d205537583eca3ed32ac2aba488ff55d4ff2153b645d350"
}
```

### Sample 20: `c8ef73f41b3a1e5c`

| Field | Value |
|---|---|
| SHA-256 | `c8ef73f41b3a1e5c876c03e0447ac52ba39e5457b37fa2098398a1d80b5526e4` |
| Family label | `unknown` |
| File name | `kswapd0` |
| File type | `elf` |
| First seen | `2026-10-04 04:34:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b316164f5e0c232ad8129d5d4f09b011` |
| SHA-1 | `2becf3474ca574514d24676529fc1013732e49ce` |
| SHA-256 | `c8ef73f41b3a1e5c876c03e0447ac52ba39e5457b37fa2098398a1d80b5526e4` |
| SHA3-384 | `be4756d20ae344f776f0c4a0d0f2d6b4027049784d9c3ffea8e2e81c393ce3525e5e1264fa73d3a3f45e677b254f6e79` |
| TLSH | `T1896608237B1CE70FC62922341CB2DA98272A1C5A41D6951BB385F31DE9F21AC5D6ECF1` |
| TELFHASH | `t1d49002120445544c65644874ad6cf1016ae0ac22a4340858fa541d83044c415230c568` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:UUOxB6syu1Upy0fxJW7CqKZzASyW7MJ9svX3NW1yW3w5DthrAnHHEt5E3:t54KpMk2eDt1AnnEjE3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_c8ef73f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8ef73f41b3a1e5c876c03e0447ac52ba39e5457b37fa2098398a1d80b5526e4"
    family = "unknown"
    file_name = "kswapd0"
    file_type = "elf"
    first_seen = "2026-10-04 04:34:40"
  condition:
    hash.sha256(0, filesize) == "c8ef73f41b3a1e5c876c03e0447ac52ba39e5457b37fa2098398a1d80b5526e4"
}
```

### Sample 21: `96b288aac49d0adc`

| Field | Value |
|---|---|
| SHA-256 | `96b288aac49d0adc66a3de8855a0f699cb89a02b6861b67fb59ff0ccd8ef15fd` |
| Family label | `unknown` |
| File name | `ecryptfsd` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20c6a451d66d0c88f41983ba39cfea1c` |
| SHA-1 | `53ff3b217e11d832cffd83930645f294a59198c0` |
| SHA-256 | `96b288aac49d0adc66a3de8855a0f699cb89a02b6861b67fb59ff0ccd8ef15fd` |
| SHA3-384 | `fc89cd2b1882626ab1ca7327347d53f1e9864763d07f40c629b4a5df15ecdbaef1b6d665879929b8c601f33b36cbe634` |
| TLSH | `T15466E808BCC43BEAD46C4A7494EACA5622745D104AF1477666A4FBEDFC762387F0788C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:GzVlsBp1GdG+iaJw7xMwYNhqutTHzJ287JFg5Ed:HaJw7+wY3DVUEd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_96b288aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96b288aac49d0adc66a3de8855a0f699cb89a02b6861b67fb59ff0ccd8ef15fd"
    family = "unknown"
    file_name = "ecryptfsd"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:52"
  condition:
    hash.sha256(0, filesize) == "96b288aac49d0adc66a3de8855a0f699cb89a02b6861b67fb59ff0ccd8ef15fd"
}
```

### Sample 22: `f4107a863ce5d1ae`

| Field | Value |
|---|---|
| SHA-256 | `f4107a863ce5d1ae604ec953b5b6c9d3b2f125fc735038bd1a819164d4bf4c5d` |
| Family label | `unknown` |
| File name | `jbd2_sda1d` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a892303e1bb0aeb08b92fd63581eb70b` |
| SHA-1 | `f46708762585623afb779ad7158fe15ad282a5ac` |
| SHA-256 | `f4107a863ce5d1ae604ec953b5b6c9d3b2f125fc735038bd1a819164d4bf4c5d` |
| SHA3-384 | `b58ee0db0531926b78161194a0fa7bd9540f9df4cfe4ca970a56c388f0211b5e281041de9a69bdb8411a5e4b78b73239` |
| TLSH | `T1C2560857B8D24942C4E83637B8BD81C433635EBA9B8A52676D05EE3C3EBE1D90E35704` |
| TELFHASH | `t186d05e758f1c738c73d464994a4a162acad06bf903a0bf98ef09225e4a554db30ca066` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:En/QwQcaNGOkSw28XUoWWqamNLhwP+UmHb/oEeMGPYag5Ez:EntwoxWpJwP+XPEz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_f4107a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4107a863ce5d1ae604ec953b5b6c9d3b2f125fc735038bd1a819164d4bf4c5d"
    family = "unknown"
    file_name = "jbd2_sda1d"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:46"
  condition:
    hash.sha256(0, filesize) == "f4107a863ce5d1ae604ec953b5b6c9d3b2f125fc735038bd1a819164d4bf4c5d"
}
```

### Sample 23: `13c785cd920375e8`

| Field | Value |
|---|---|
| SHA-256 | `13c785cd920375e8e60553d7597c1bca0690335d50f6663f150303770adb5205` |
| Family label | `unknown` |
| File name | `scsi_tmf_0` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:45` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5208d0236ca4c63579994a764815e8c1` |
| SHA-1 | `0c5f477876af165675f876328f4f05fe594a9f87` |
| SHA-256 | `13c785cd920375e8e60553d7597c1bca0690335d50f6663f150303770adb5205` |
| SHA3-384 | `d3c71c64967083a884763301875adcc78ca61ff6fbe857d508305084e76b3d9dcaaf996f4f0e2f2814dd769a786e3025` |
| TLSH | `T1DD66F851BDC26F66C1DC037544EE625A72543E468B91072323A4F7EC3A7B73CAF9A848` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:LLS9FB8alzScVrGVa6EEmItKiV2FYXs6rbyzEgyg5E1:LWTBl9ScV+a6ZIdAME2E1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_13c785cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13c785cd920375e8e60553d7597c1bca0690335d50f6663f150303770adb5205"
    family = "unknown"
    file_name = "scsi_tmf_0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:45"
  condition:
    hash.sha256(0, filesize) == "13c785cd920375e8e60553d7597c1bca0690335d50f6663f150303770adb5205"
}
```

### Sample 24: `a28d65048de7b327`

| Field | Value |
|---|---|
| SHA-256 | `a28d65048de7b3273d86f50a67f709fdde9646dc808ec82bff0f53a13de23ee0` |
| Family label | `unknown` |
| File name | `devfreq_wq` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaea8e1dcc5922131d826f688c9fe731` |
| SHA-1 | `d3bb767d9af434ca6fd19c838f23c1f5990a7c37` |
| SHA-256 | `a28d65048de7b3273d86f50a67f709fdde9646dc808ec82bff0f53a13de23ee0` |
| SHA3-384 | `9cdb0c76c71d5d0eb966916947cc79a2251c1e4144007b4d2088cfa20c8afd2c1ccb3867c0bce246418929d6f4742fc2` |
| TLSH | `T190565A81FB48E126DA9A0B7288630F74B3512D82C1E48D6F5709F32F45B25F6998FED4` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:FTnhwb5AB09CeQgJgOYZPQsDpdsw9oZkq4Zt36c9lj4/8m1HHEt5Ef:wbmB09CeQgJgOYZPQsDpM/5+Pm1nEjEf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_a28d6504
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a28d65048de7b3273d86f50a67f709fdde9646dc808ec82bff0f53a13de23ee0"
    family = "unknown"
    file_name = "devfreq_wq"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:40"
  condition:
    hash.sha256(0, filesize) == "a28d65048de7b3273d86f50a67f709fdde9646dc808ec82bff0f53a13de23ee0"
}
```

### Sample 25: `91968f3511b0ce31`

| Field | Value |
|---|---|
| SHA-256 | `91968f3511b0ce31fc4a13896883790ef4e0371ba229b4c7f5ee696d65286607` |
| Family label | `unknown` |
| File name | `xfsaild_sda` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:38` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bad9bc83f0939f873ed617127ca09f5` |
| SHA-1 | `9f786741455bfcbf7858d0421f50ffbcf86306cd` |
| SHA-256 | `91968f3511b0ce31fc4a13896883790ef4e0371ba229b4c7f5ee696d65286607` |
| SHA3-384 | `c1b7ec5ba0b7519ded02d4433157ea92cc30a162250d8a53793214f1a25daf832ab0b136f61fb87b72bfb99d3f922e20` |
| TLSH | `T14B662852BF88EE5FE29420358AB6C23473D57E00C5E061368656F71D1EBE3A48D6BDC8` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:WBAXf+9b8uvBjcW+kzvL8Igl5FYd16wbefaQqv4HHEt5E7:kZv+kBNv6Sjv4nEjE7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_91968f35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91968f3511b0ce31fc4a13896883790ef4e0371ba229b4c7f5ee696d65286607"
    family = "unknown"
    file_name = "xfsaild_sda"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:38"
  condition:
    hash.sha256(0, filesize) == "91968f3511b0ce31fc4a13896883790ef4e0371ba229b4c7f5ee696d65286607"
}
```

### Sample 26: `0aad1879b98b2148`

| Field | Value |
|---|---|
| SHA-256 | `0aad1879b98b2148b7035c848b1e71f4fa73678fdea2f15442d1552429684b6f` |
| Family label | `unknown` |
| File name | `bioset0` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `879c31b3ba6858c6dd9abf9ce293e675` |
| SHA-1 | `a59d8597e9a596baef36dfd20acabbb3034b5033` |
| SHA-256 | `0aad1879b98b2148b7035c848b1e71f4fa73678fdea2f15442d1552429684b6f` |
| SHA3-384 | `cc64532aca94341b6361d426e1a876af33d14802abed4a58832f1dacb99b178fa779632faa1299c426e7dd0a79cf3889` |
| TLSH | `T141560897B8D24946C4E83677B8BE80C433635EB99B8A52566D05FE3C3EBE1D90E35304` |
| TELFHASH | `t1bfd0a7859f0e23cdafc11895088d42b84ae83ffc03a0bf888f3d56590e968d730da810` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:nPlvYX6nML0ppTblltGpTjx1xm73s+mEqi90/nOD1Og5EM:PbMAz3SSmX/nOD1DEM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_0aad1879
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0aad1879b98b2148b7035c848b1e71f4fa73678fdea2f15442d1552429684b6f"
    family = "unknown"
    file_name = "bioset0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:35"
  condition:
    hash.sha256(0, filesize) == "0aad1879b98b2148b7035c848b1e71f4fa73678fdea2f15442d1552429684b6f"
}
```

### Sample 27: `89ccb497c51c5ce3`

| Field | Value |
|---|---|
| SHA-256 | `89ccb497c51c5ce3a113a52bbfe807028b14d5ecc992e4543e683c91be40855f` |
| Family label | `unknown` |
| File name | `edac_polld` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:33` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50de942947de22ea98100398574dd950` |
| SHA-1 | `7306dac099c3015d27574bc86ead6c8490f9351a` |
| SHA-256 | `89ccb497c51c5ce3a113a52bbfe807028b14d5ecc992e4543e683c91be40855f` |
| SHA3-384 | `982ad23b22fa39f3126197c5ea7bb5bf329e71d3eba1ac31389abcb249b25a59550ecafaf4b300b8f3a98237bbe8e931` |
| TLSH | `T1C166F8C1E991D24AD63D6D31EFEAEFD8E2662E315DC85A4AC9D8F33E0CB214480F5560` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:lhXdR/xufi2dyCXjhwNzdDhecg29fnDjEs:3hn8s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_89ccb497
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89ccb497c51c5ce3a113a52bbfe807028b14d5ecc992e4543e683c91be40855f"
    family = "unknown"
    file_name = "edac_polld"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:33"
  condition:
    hash.sha256(0, filesize) == "89ccb497c51c5ce3a113a52bbfe807028b14d5ecc992e4543e683c91be40855f"
}
```

### Sample 28: `34fb09cae8aa5047`

| Field | Value |
|---|---|
| SHA-256 | `34fb09cae8aa5047478467381f06cad599d2ec08d045e8403b0e67724ab4fbde` |
| Family label | `unknown` |
| File name | `loader.sh` |
| File type | `sh` |
| First seen | `2026-10-04 04:33:27` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07cc3c097cb806b26a240e9f7fa8bdd1` |
| SHA-1 | `3edd32deb0bad009a82aecf203bfe1a83af04672` |
| SHA-256 | `34fb09cae8aa5047478467381f06cad599d2ec08d045e8403b0e67724ab4fbde` |
| SHA3-384 | `7b16f1c1dee3155f6f37cf4c15b093e8f047d05c1124070c2c4c4a6cdd778fa53adfe3a0a121590e2079d5262c8db064` |
| TLSH | `T1A541BDCA7AA3D97297C7C4381FDAE101E35624430996A9D8B08EBC303F69160FCB1E56` |
| SSDEEP | `48:9VdxxzGG1eCFeZdzVKN5Q1f/neHuDmmlBFInKIYgQAul4N7vGxQ:PdnIu2mQlGaL2nKI3QaTGC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_34fb09ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34fb09cae8aa5047478467381f06cad599d2ec08d045e8403b0e67724ab4fbde"
    family = "unknown"
    file_name = "loader.sh"
    file_type = "sh"
    first_seen = "2026-10-04 04:33:27"
  condition:
    hash.sha256(0, filesize) == "34fb09cae8aa5047478467381f06cad599d2ec08d045e8403b0e67724ab4fbde"
}
```

### Sample 29: `5a26a4558246dace`

| Field | Value |
|---|---|
| SHA-256 | `5a26a4558246daced34649ba417445ee547a6afc7a0f66a3204f30ecc4fa6cce` |
| Family label | `unknown` |
| File name | `zswap_shrinkd` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:20` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3694dca14a46200532d07855ddc40cd` |
| SHA-1 | `a96058d20135bc9c162728c64a42c18f93533619` |
| SHA-256 | `5a26a4558246daced34649ba417445ee547a6afc7a0f66a3204f30ecc4fa6cce` |
| SHA3-384 | `65e9b6153ffa1e849466d463ba81065f1c726f52060692b9018100751e7f6d468c17212bf9ea21fff9c4603f183b3911` |
| TLSH | `T19B8533409318C599B4579550D7BB1773640B7C22EE996A23C08A90276CFF131DEBF8BA` |
| SSDEEP | `49152:pLFTGziQ2p2+I1s7ai7qnZ/VJLQl3qFwMDTF:1FGzZY2vA7qn9VxRzfF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_5a26a455
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a26a4558246daced34649ba417445ee547a6afc7a0f66a3204f30ecc4fa6cce"
    family = "unknown"
    file_name = "zswap_shrinkd"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:20"
  condition:
    hash.sha256(0, filesize) == "5a26a4558246daced34649ba417445ee547a6afc7a0f66a3204f30ecc4fa6cce"
}
```

### Sample 30: `b405eb0c7900d92b`

| Field | Value |
|---|---|
| SHA-256 | `b405eb0c7900d92ba655488f855f5e37d7154c077a1f7e4967670453082ddcac` |
| Family label | `unknown` |
| File name | `rcuop_0` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:17` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ccfb76871c75f6cecd39c8579bec77e` |
| SHA-1 | `8b2a29eb0918f9056b1f1414baa2b42577540f84` |
| SHA-256 | `b405eb0c7900d92ba655488f855f5e37d7154c077a1f7e4967670453082ddcac` |
| SHA3-384 | `56190041c917086541e2d2541b869e1de7a605fa9243e133aeeb5f5db2c3e87262f71c0e6927c402299519fe5072db6f` |
| TLSH | `T114853391B5B6EC6500A037B93173612E813477DA28C1D1DFA8572B507FBAB6E4C148FB` |
| SSDEEP | `49152:ZzNwBr0mZUOc7NezFN7+1AUSQP/0UGNeoRx90hXI:BNcrZY7Ne7+1A7QXHGAc9WI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_b405eb0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b405eb0c7900d92ba655488f855f5e37d7154c077a1f7e4967670453082ddcac"
    family = "unknown"
    file_name = "rcuop_0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:17"
  condition:
    hash.sha256(0, filesize) == "b405eb0c7900d92ba655488f855f5e37d7154c077a1f7e4967670453082ddcac"
}
```

### Sample 31: `423ebf3f807b9356`

| Field | Value |
|---|---|
| SHA-256 | `423ebf3f807b93565a2f8752d172f7c63a186c18bc20bf75c8915f0e1f6bbd4d` |
| Family label | `unknown` |
| File name | `kworker_u8` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:16` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9924554fa3a3b3e1cce40c3aaf5f0c8` |
| SHA-1 | `a463391cd267b7695a0bcdf8d740e66be0a63eda` |
| SHA-256 | `423ebf3f807b93565a2f8752d172f7c63a186c18bc20bf75c8915f0e1f6bbd4d` |
| SHA3-384 | `b7140bfe4de5b956d9e0627867a5b513a07f881034dc6f04cec55f465b33f80f1d0a6dfdeddd585b62de872616055399` |
| TLSH | `T17C95331767E246E0C7DFA6BD35771BBE96C7E40A9BC209C0104B1B8701D58D37AA7E0A` |
| SSDEEP | `49152:Ag4rvGn96xSuQbg6ThBJt6DK38Pkak5TAvNpf:AzvGn9Yl6d58K38Pkgpf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_423ebf3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "423ebf3f807b93565a2f8752d172f7c63a186c18bc20bf75c8915f0e1f6bbd4d"
    family = "unknown"
    file_name = "kworker_u8"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:16"
  condition:
    hash.sha256(0, filesize) == "423ebf3f807b93565a2f8752d172f7c63a186c18bc20bf75c8915f0e1f6bbd4d"
}
```

### Sample 32: `2334ba8af1e64f07`

| Field | Value |
|---|---|
| SHA-256 | `2334ba8af1e64f074a98c6be8299e29b6eed8b048dd8a7f1cc98d078eea99984` |
| Family label | `unknown` |
| File name | `kblockd0` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:15` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d74a87f45f139fea69866f0ff64901a6` |
| SHA-1 | `e78e7517187bc4b3d16240c498ee01907ea5e393` |
| SHA-256 | `2334ba8af1e64f074a98c6be8299e29b6eed8b048dd8a7f1cc98d078eea99984` |
| SHA3-384 | `89d0f616d44e9a179383089f3dd63f2dab00d593e3772a2f9a9f4bb3a71ad0154f58656d6ccd9d1e73aa113050e28328` |
| TLSH | `T1F98533977B4EE24AC95FE43679DBA025CB809C94D1641D1274E5C4E033D2FEAE0A3B1D` |
| SSDEEP | `49152:hwJH7MTgq/R43vPlNrs7c2mVoWdVwhbZx6Fbj:hwJHw/KPAcFLdnbj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_2334ba8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2334ba8af1e64f074a98c6be8299e29b6eed8b048dd8a7f1cc98d078eea99984"
    family = "unknown"
    file_name = "kblockd0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:15"
  condition:
    hash.sha256(0, filesize) == "2334ba8af1e64f074a98c6be8299e29b6eed8b048dd8a7f1cc98d078eea99984"
}
```

### Sample 33: `1bc23d3b13d5cae1`

| Field | Value |
|---|---|
| SHA-256 | `1bc23d3b13d5cae1dc3b8064c0e13fd27245c740a6d3aaba761df9443ae2b462` |
| Family label | `unknown` |
| File name | `kswapd0` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:14` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9157fc7b6c98ecbc6564a643c89a2f0` |
| SHA-1 | `625b33020bbf84d834c899e1cf6514a539fcfc11` |
| SHA-256 | `1bc23d3b13d5cae1dc3b8064c0e13fd27245c740a6d3aaba761df9443ae2b462` |
| SHA3-384 | `1aae45a3614443160e849c6cdeda86fbc4c49364da4954c4c1dd3d91779457867d8a55c281718766fd2de9fdf2c6fa98` |
| TLSH | `T1F37533E627BDDA04C2A2DCF0236C02FA4D7E2F67144E849C1C241F6572E439E6E95DDA` |
| SSDEEP | `49152:bNGq/fdhcXR1Svhx18uHnwuIvslPX+/vQfQ52:bwZhAx1bHSO/g4/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_1bc23d3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bc23d3b13d5cae1dc3b8064c0e13fd27245c740a6d3aaba761df9443ae2b462"
    family = "unknown"
    file_name = "kswapd0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:14"
  condition:
    hash.sha256(0, filesize) == "1bc23d3b13d5cae1dc3b8064c0e13fd27245c740a6d3aaba761df9443ae2b462"
}
```

### Sample 34: `728b0daba3251492`

| Field | Value |
|---|---|
| SHA-256 | `728b0daba3251492e419826a104b921bcbd7931c4352da943c4e8cde2c964ce1` |
| Family label | `unknown` |
| File name | `ksoftirqd0` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:13` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32b40b99ef19aadba962e87f3384d560` |
| SHA-1 | `379fe8b6355bafb6bb1a758a623ffebe5623cf11` |
| SHA-256 | `728b0daba3251492e419826a104b921bcbd7931c4352da943c4e8cde2c964ce1` |
| SHA3-384 | `08ff4155ecbadf2a0571af65f3f17c05253bd1e61574f591c40da8ec6a8696430e30d476f7d44459748618328b4a6199` |
| TLSH | `T10B8533BBB3C6DACA84F00BD022A4445D0E5584938DDEEF1416991F9E8FA88F1F4DC95B` |
| TELFHASH | `t15db001a31c8c85fe11dde8848d4bb65c2072c67e0821566d151e3b06b612e68578586a` |
| SSDEEP | `49152:XHRjjy4VBqpoWNS6kNhE54t2ic4+LK4enPh7xJidOxyUW:hjpUoWN0u54t2i1ShePtyA0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_728b0dab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "728b0daba3251492e419826a104b921bcbd7931c4352da943c4e8cde2c964ce1"
    family = "unknown"
    file_name = "ksoftirqd0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:13"
  condition:
    hash.sha256(0, filesize) == "728b0daba3251492e419826a104b921bcbd7931c4352da943c4e8cde2c964ce1"
}
```

### Sample 35: `24fbb7a26e1071d6`

| Field | Value |
|---|---|
| SHA-256 | `24fbb7a26e1071d64f4dfc56273b25f3273906de1548453ee1cddc32526c4ae1` |
| Family label | `unknown` |
| File name | `ecryptfsd` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:13` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d254adcb65ee9fcf11568a4d1a4ded9` |
| SHA-1 | `4a014fefc066a0b11e6832ffb5426054fe99cc9e` |
| SHA-256 | `24fbb7a26e1071d64f4dfc56273b25f3273906de1548453ee1cddc32526c4ae1` |
| SHA3-384 | `8c781455003a5abb1cd6b106135cd34dbf88d1473fdfcaf51ca7d378ca4d34f81fa165629c73f3a7613a40733080a4de` |
| TLSH | `T15485334A12E93AABD20E64FCC20012256F41F7A2BB5C055ABE55CC387B7CD4DB85FD86` |
| SSDEEP | `24576:cEqlaCynujC9jI3nAvheUIdHMtgCg7/DOvB7zXIDsvI83417QIA4jr9SVr2OYDi6:J4w6A8UIaSDuB7rysZd4MtCkMTGVw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_24fbb7a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24fbb7a26e1071d64f4dfc56273b25f3273906de1548453ee1cddc32526c4ae1"
    family = "unknown"
    file_name = "ecryptfsd"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:13"
  condition:
    hash.sha256(0, filesize) == "24fbb7a26e1071d64f4dfc56273b25f3273906de1548453ee1cddc32526c4ae1"
}
```

### Sample 36: `ace3ad11d0edf9c2`

| Field | Value |
|---|---|
| SHA-256 | `ace3ad11d0edf9c2a9b937d4aed1917fd1420e381ce5ad0d5efbc9ddf25f3d9c` |
| Family label | `unknown` |
| File name | `cfg80211d` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:13` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f047c10f8699d4c4225a549e2790fc6` |
| SHA-1 | `bc53c67b35121d3248f49d50d40d49e1868d5009` |
| SHA-256 | `ace3ad11d0edf9c2a9b937d4aed1917fd1420e381ce5ad0d5efbc9ddf25f3d9c` |
| SHA3-384 | `30f298a0c1e4e559b105295b5bea339570a9c5c2baf282eb3c2765190921c6755064ca182de03470b4e6c27f6137a632` |
| TLSH | `T1C3567C0AFD14CF61C2A403B689B912891330AD036FC75713A239F73CBDB66D4ED5A696` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:SY/QEQ+5kW9t6wQG0nX5urOuR/yw+8p15LLKtG7g5EA:OE99t6wQGZRLyGOEA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_ace3ad11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ace3ad11d0edf9c2a9b937d4aed1917fd1420e381ce5ad0d5efbc9ddf25f3d9c"
    family = "unknown"
    file_name = "cfg80211d"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:13"
  condition:
    hash.sha256(0, filesize) == "ace3ad11d0edf9c2a9b937d4aed1917fd1420e381ce5ad0d5efbc9ddf25f3d9c"
}
```

### Sample 37: `5669521dba0e09dc`

| Field | Value |
|---|---|
| SHA-256 | `5669521dba0e09dc22054453be79e37ef4d5fda8413f6457ef8203e8a812625e` |
| Family label | `unknown` |
| File name | `jbd2_sda1d` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:12` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bea94d7613a07d038b621049f9085594` |
| SHA-1 | `74f6ab05cf97d3a0eb6ef507deba24527280d273` |
| SHA-256 | `5669521dba0e09dc22054453be79e37ef4d5fda8413f6457ef8203e8a812625e` |
| SHA3-384 | `5cfcefb97d24b0dd24ffbad160799978f11d9489ef512fb7244ce06314bdfaa983658d5af92affecdc1e9b0acb458cd9` |
| TLSH | `T186853323FA91B25FEC87F863209D44911C5D97DC071C81E2A7FBFA7E5450A923AA143B` |
| SSDEEP | `49152:d2B5fWzTQ+jGvucSzjE3bB+Llgqs8EuI8BysBwu0IbZ:UPsvjGc9ROuIsysSVI9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_5669521d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5669521dba0e09dc22054453be79e37ef4d5fda8413f6457ef8203e8a812625e"
    family = "unknown"
    file_name = "jbd2_sda1d"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:12"
  condition:
    hash.sha256(0, filesize) == "5669521dba0e09dc22054453be79e37ef4d5fda8413f6457ef8203e8a812625e"
}
```

### Sample 38: `fc5b9e6337bbb8ff`

| Field | Value |
|---|---|
| SHA-256 | `fc5b9e6337bbb8ff175b9258c8812efc9f6e35ea0fa1bbe13d18bbe3ccc6cc0e` |
| Family label | `unknown` |
| File name | `devfreq_wq` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:12` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d03335ddcf6ff7492c7067023990744a` |
| SHA-1 | `7c02052e26eac179cd5dfc708be018a12a3821af` |
| SHA-256 | `fc5b9e6337bbb8ff175b9258c8812efc9f6e35ea0fa1bbe13d18bbe3ccc6cc0e` |
| SHA3-384 | `7e5da8e34c8c2714dbc22a400c2a77e83b610054c1d669edd155c1982643e5173df2664a1bbb4734c69882095bc2e6d3` |
| TLSH | `T199753304B3E5DBFEE4060A7CD908417AFB89DFC50F4891246FAAD4FC127C7A46961A27` |
| SSDEEP | `24576://PYEnhWOZ4YZzik59RsfRPK9SkgfyH+RpVTuR9GbdK6CjEvpd3AMSgquRhC11lY://PYb5GlsfEejjBk90U6CjEvp5qT1C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_fc5b9e63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc5b9e6337bbb8ff175b9258c8812efc9f6e35ea0fa1bbe13d18bbe3ccc6cc0e"
    family = "unknown"
    file_name = "devfreq_wq"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:12"
  condition:
    hash.sha256(0, filesize) == "fc5b9e6337bbb8ff175b9258c8812efc9f6e35ea0fa1bbe13d18bbe3ccc6cc0e"
}
```

### Sample 39: `941a0c7f78871c90`

| Field | Value |
|---|---|
| SHA-256 | `941a0c7f78871c908711b09176683928d1899fe284589fc965426f3b143b27be` |
| Family label | `unknown` |
| File name | `bioset0` |
| File type | `elf` |
| First seen | `2026-10-04 04:33:09` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `481edf7cf1a47443cbf8063970fd5ddf` |
| SHA-1 | `d95f6a8cdfcb0b4f75fd2e7e9ec863bdb5fcecc1` |
| SHA-256 | `941a0c7f78871c908711b09176683928d1899fe284589fc965426f3b143b27be` |
| SHA3-384 | `1c88a01e1f3567cfd8c81f20caf199cbe1d5be24b0680ad4e8c68111335e39b251d4a7fdf82ba8a688be28c153aa6a57` |
| TLSH | `T152853308E79F1CF6FC6B3DB2CD57696490010458F4BDD5B802DE23A7AB5B2C285A781B` |
| TELFHASH | `t112900298466180d36119103418ac271e42102a1f2437581fd6140a186180349540243c` |
| SSDEEP | `24576:lVH82KriSB2hMKNvsjiqR1jhtdxTxipHAzUpKirjO1w40cdjjeDtQM:3H8oRhlNUvR1n6H1siu1wOjeDt/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_941a0c7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "941a0c7f78871c908711b09176683928d1899fe284589fc965426f3b143b27be"
    family = "unknown"
    file_name = "bioset0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:09"
  condition:
    hash.sha256(0, filesize) == "941a0c7f78871c908711b09176683928d1899fe284589fc965426f3b143b27be"
}
```

### Sample 40: `0313cef6ee5ccac1`

| Field | Value |
|---|---|
| SHA-256 | `0313cef6ee5ccac16714f02e3ff9dfd5181c55419f96a6443d9812f0d37a8eaa` |
| Family label | `Mirai` |
| File name | `b3c455c0833628ac.bin` |
| File type | `elf` |
| First seen | `2026-10-04 04:25:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17f7833d523f14c0cfcc140eb226bcf4` |
| SHA-1 | `cc3512ed5492ae506dbef5e2c917805ceb1dc9ef` |
| SHA-256 | `0313cef6ee5ccac16714f02e3ff9dfd5181c55419f96a6443d9812f0d37a8eaa` |
| SHA3-384 | `a02166f2c5eda44b1fd919c51272ed88eea8407af8949c09f30d3a1396b9da4cf8885bb8dfb2e70aae6fb7ee40c8d0ec` |
| TLSH | `T102041759FD809F11E9D536BAFA5E428933530BBCE3EE71029E245F2423CA95B0F3A505` |
| TELFHASH | `t183110c288c4c12bc36c9008091dbe239ba9420997b2918559aaddc5dfc236c0f03cc1f` |
| SSDEEP | `3072:FOOwC2bVBcTTJb01VQDhmtDCQ8mToMwgl6/AN/LPq8/P3Tn1MnxkaX46Nsow3p5c:FOO4bVBcTTJbeqDhmtDCQfoUASjpH3jA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_0313cef6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0313cef6ee5ccac16714f02e3ff9dfd5181c55419f96a6443d9812f0d37a8eaa"
    family = "Mirai"
    file_name = "b3c455c0833628ac.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:25:35"
  condition:
    hash.sha256(0, filesize) == "0313cef6ee5ccac16714f02e3ff9dfd5181c55419f96a6443d9812f0d37a8eaa"
}
```

### Sample 41: `3af5d15c8bc300ef`

| Field | Value |
|---|---|
| SHA-256 | `3af5d15c8bc300ef4cce30f60613b5a47cea92c4b23dd0fe0f2ead2b781e9cc6` |
| Family label | `Gafgyt` |
| File name | `3af5d15c8bc300ef.bin` |
| File type | `elf` |
| First seen | `2026-10-04 04:25:29` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b629768ef143c3422a562e12cf0e573d` |
| SHA-1 | `a5e37778627c3fd3ed3549b3d8326e2f41861cc7` |
| SHA-256 | `3af5d15c8bc300ef4cce30f60613b5a47cea92c4b23dd0fe0f2ead2b781e9cc6` |
| SHA3-384 | `314a8516266cb64df37ee1de28eea9984db03ee7ef5bcfca08db42b098a8ffeb1affdbfa7fedd26f2c2cbe673f20f6d6` |
| TLSH | `T16944E707BB918EF7C85FCD3306E6861121CEE05722A56B2B7674D61CBB0A94F49E3C94` |
| TELFHASH | `t125610058a83d05d99e231c1968696fb35957e52a32e6bb18ff1addc0084e428f258e0f` |
| SSDEEP | `6144:uu2ANqG2loyicdSkWNThvjHcWG/EFhCmceavYP:b0dicEFhvjHcWG/EFhCmceavYP` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_041_3af5d15c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3af5d15c8bc300ef4cce30f60613b5a47cea92c4b23dd0fe0f2ead2b781e9cc6"
    family = "Gafgyt"
    file_name = "3af5d15c8bc300ef.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:25:29"
  condition:
    hash.sha256(0, filesize) == "3af5d15c8bc300ef4cce30f60613b5a47cea92c4b23dd0fe0f2ead2b781e9cc6"
}
```

### Sample 42: `2614bd6433ed1004`

| Field | Value |
|---|---|
| SHA-256 | `2614bd6433ed10049482f52bb6da315008f66db4586a896a82f372ba4eefdb09` |
| Family label | `Mirai` |
| File name | `2614bd6433ed1004.bin` |
| File type | `elf` |
| First seen | `2026-10-04 04:25:20` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd0e4fadaf07d6b73b641909da4fd22b` |
| SHA-1 | `175781138548437eb05b7154579452cd141bb52b` |
| SHA-256 | `2614bd6433ed10049482f52bb6da315008f66db4586a896a82f372ba4eefdb09` |
| SHA3-384 | `b8e12c66fc8052178db278ef7bba47039f63880ebdfcb5c1e6909d249b60cb2af90d4047a83404996e85f5c4b0f09b57` |
| TLSH | `T1D5443B01EA408F57C4C2177ABB9F43593333AF6493DB73029A28BBB42F8679D1E29515` |
| TELFHASH | `t1bd610e58a43d05da9e631c19ac686ff34557f62a32e6bb28ff16dcc0084e429f158e0f` |
| SSDEEP | `6144:bCXqGaJXo0u3aIVAxbAAKS96bydLTacC4F4myL3cbVZGyoM5PNt:bCaG+XG3aIqxAnS96bUfKmyL3cbVIyou` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_2614bd64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2614bd6433ed10049482f52bb6da315008f66db4586a896a82f372ba4eefdb09"
    family = "Mirai"
    file_name = "2614bd6433ed1004.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:25:20"
  condition:
    hash.sha256(0, filesize) == "2614bd6433ed10049482f52bb6da315008f66db4586a896a82f372ba4eefdb09"
}
```

### Sample 43: `e1e7c1050ecf9d4a`

| Field | Value |
|---|---|
| SHA-256 | `e1e7c1050ecf9d4a945652b2c6d0707dd33283d750560cbee354bb4c68f98bbe` |
| Family label | `Gafgyt` |
| File name | `e1e7c1050ecf9d4a.bin` |
| File type | `elf` |
| First seen | `2026-10-04 04:25:11` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59e34f5241e1f722c5e726a05833796a` |
| SHA-1 | `663f366b2abaf7756275cb1a2bc75e7149f87641` |
| SHA-256 | `e1e7c1050ecf9d4a945652b2c6d0707dd33283d750560cbee354bb4c68f98bbe` |
| SHA3-384 | `c2c9bc44467235ea645dac7c80140e89d84d231cc7d149d9894186514d67c6d148cb44ec426e0e74239b7682fdf3cec3` |
| TLSH | `T1D5140B41F8144F57C5C22B7BF78F429937376A6897EB3302AA28AEB42F4778D1D29111` |
| TELFHASH | `t125610058a83d05d99e231c1968696fb35957e52a32e6bb18ff1addc0084e428f258e0f` |
| SSDEEP | `6144:hMMLg4Vv4q+Q/wWOp+k8jvzdZPRlZSruNHdsg4IO:Dg4VAeYWO2jvzdZPRlsruNHdsg4IO` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_043_e1e7c105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1e7c1050ecf9d4a945652b2c6d0707dd33283d750560cbee354bb4c68f98bbe"
    family = "Gafgyt"
    file_name = "e1e7c1050ecf9d4a.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:25:11"
  condition:
    hash.sha256(0, filesize) == "e1e7c1050ecf9d4a945652b2c6d0707dd33283d750560cbee354bb4c68f98bbe"
}
```

### Sample 44: `836c3d2f62862223`

| Field | Value |
|---|---|
| SHA-256 | `836c3d2f62862223d559f124b11f039d993df1296904d5d80dbf3ded4aa30d8a` |
| Family label | `unknown` |
| File name | `836c3d2f62862223.bin` |
| File type | `exe` |
| First seen | `2026-10-04 04:25:02` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23bb3c1091af85ce5998cc20214ad13d` |
| SHA-1 | `ecb6b63cc1724c0c3b0acc448ec8bf29a011c8ed` |
| SHA-256 | `836c3d2f62862223d559f124b11f039d993df1296904d5d80dbf3ded4aa30d8a` |
| SHA3-384 | `4c8076cfd92a3f421bbe5024b6107805be9a579db0b7de22a78355836cdeb8e10ca50f22f5e21a68e7ca427834726b0e` |
| IMPHASH | `b2f76a377810c3911d9a29c066358593` |
| TLSH | `T15546225AB39345DFC727463018B92761FE3A8E646C58993EC249E2BD3E70D6E58C13E0` |
| SSDEEP | `49152:ATtmlUNVWzjlMIhmLSDHagGAEqCT68rsGBjAvNaJcGVKM5:AyUN0eFL86gGAENnBBjaNl8/5` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_836c3d2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "836c3d2f62862223d559f124b11f039d993df1296904d5d80dbf3ded4aa30d8a"
    family = "unknown"
    file_name = "836c3d2f62862223.bin"
    file_type = "exe"
    first_seen = "2026-10-04 04:25:02"
  condition:
    hash.sha256(0, filesize) == "836c3d2f62862223d559f124b11f039d993df1296904d5d80dbf3ded4aa30d8a"
}
```

### Sample 45: `8fd8d5ba7d46fc31`

| Field | Value |
|---|---|
| SHA-256 | `8fd8d5ba7d46fc31185131d5a0dafd5d374352b0b0f2d6b816157102289dde50` |
| Family label | `Gafgyt` |
| File name | `8fd8d5ba7d46fc31.bin` |
| File type | `elf` |
| First seen | `2026-10-04 04:24:53` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbb90b4becc44dd93f6634e05082578c` |
| SHA-1 | `f1fdcb9d48a88e00679fe7a0e67243340889b8af` |
| SHA-256 | `8fd8d5ba7d46fc31185131d5a0dafd5d374352b0b0f2d6b816157102289dde50` |
| SHA3-384 | `71ba286158d4ae8b7edadfd62f62cc45db945baf1910c20a856f48b4fb4752fda40f7050756af8322e4c2d17ca0d6c97` |
| TLSH | `T1A3240B01B9104F57C6C22BBBFB8F429937376B6497DB3302AA25BEB42F4678D1D29111` |
| TELFHASH | `t125610058a83d05d99e231c1968696fb35957e52a32e6bb18ff1addc0084e428f258e0f` |
| SSDEEP | `6144:kvELqmC44YnsMLgmLZ4+Mq2UvudZzcWZgut7oYLZJpO:kOC44yNZoqrvudZzcWmut7oYLZJpO` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_045_8fd8d5ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fd8d5ba7d46fc31185131d5a0dafd5d374352b0b0f2d6b816157102289dde50"
    family = "Gafgyt"
    file_name = "8fd8d5ba7d46fc31.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:24:53"
  condition:
    hash.sha256(0, filesize) == "8fd8d5ba7d46fc31185131d5a0dafd5d374352b0b0f2d6b816157102289dde50"
}
```

### Sample 46: `d80e32a0a99e47b8`

| Field | Value |
|---|---|
| SHA-256 | `d80e32a0a99e47b8393a359df841d63be8e42ca0323376660c865a0bdf9b6d0f` |
| Family label | `Gafgyt` |
| File name | `d80e32a0a99e47b8.bin` |
| File type | `elf` |
| First seen | `2026-10-04 04:24:43` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d7e476f3201e3a1ffc97fe5ce4cf16a` |
| SHA-1 | `06a7cfadf4a2e892db031c8a585a6329920e3e1c` |
| SHA-256 | `d80e32a0a99e47b8393a359df841d63be8e42ca0323376660c865a0bdf9b6d0f` |
| SHA3-384 | `890ae0a1478b9964c18378bedd7443b645f6d13f7723a6c34df40a9bb38253de9a964f26b53eaad28b19250d9b33b67d` |
| TLSH | `T11C44A6163A21DFBFF56C863007F38B70879965962AE19746F26CD71C1F2028D681FBA4` |
| TELFHASH | `t125610058a83d05d99e231c1968696fb35957e52a32e6bb18ff1addc0084e428f258e0f` |
| SSDEEP | `6144:m1pzuVSEIvPUN71n5hvIHcWG/EFhCmceavYP:mLzQT5hvIHcWG/EFhCmceavYP` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_046_d80e32a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d80e32a0a99e47b8393a359df841d63be8e42ca0323376660c865a0bdf9b6d0f"
    family = "Gafgyt"
    file_name = "d80e32a0a99e47b8.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:24:43"
  condition:
    hash.sha256(0, filesize) == "d80e32a0a99e47b8393a359df841d63be8e42ca0323376660c865a0bdf9b6d0f"
}
```

### Sample 47: `b3c455c0833628ac`

| Field | Value |
|---|---|
| SHA-256 | `b3c455c0833628acb088290890eb1e44d154c0be5a69de5d52bb39715d0fcb68` |
| Family label | `Mirai` |
| File name | `b3c455c0833628ac.bin` |
| File type | `elf` |
| First seen | `2026-10-04 04:24:35` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e03991f32193cb883996aad7c0d62850` |
| SHA-1 | `fbd7a8eded4c5165d7d75f079fd513c6c3717501` |
| SHA-256 | `b3c455c0833628acb088290890eb1e44d154c0be5a69de5d52bb39715d0fcb68` |
| SHA3-384 | `5fdb3150580f20e94b8d54b57ec5baa165517ba712b8452c581a3f078b27944f5023a7ac354d7825a0dbe4aaafb4e687` |
| TLSH | `T19473F1564669F0E3C8E258E9BCB469FDB51CCBB04DBE25A255004488AF370DE13BB2D7` |
| SSDEEP | `1536:34kSKSY79gLWoi3V9uiOUnuqnrTdF60gQaLsz41v8qx2jgKZoaLB:34wzg03V9uwnuGfdFCQa4U1xx2jgKVLB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_b3c455c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3c455c0833628acb088290890eb1e44d154c0be5a69de5d52bb39715d0fcb68"
    family = "Mirai"
    file_name = "b3c455c0833628ac.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:24:35"
  condition:
    hash.sha256(0, filesize) == "b3c455c0833628acb088290890eb1e44d154c0be5a69de5d52bb39715d0fcb68"
}
```

### Sample 48: `cc17cb6086f10aad`

| Field | Value |
|---|---|
| SHA-256 | `cc17cb6086f10aada5b199a46361996927466128be504943c9fbe2752fe2d558` |
| Family label | `unknown` |
| File name | `cc17cb6086f10aada5b199a46361996927466128be504943c9fbe2752fe2d558.exe` |
| File type | `exe` |
| First seen | `2026-10-04 04:23:46` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcabb61f54ee5e848321acdac6c9039d` |
| SHA-1 | `68a4e27353b4ac06f4ceb3dcb663ca38e5306c59` |
| SHA-256 | `cc17cb6086f10aada5b199a46361996927466128be504943c9fbe2752fe2d558` |
| SHA3-384 | `f27a7d47ad5e03d30b1caeac8c1965cb873d785fbac8b6c60c48ca7bfd3370ff228d82b37313de059de70d47a3ca1ac8` |
| IMPHASH | `cdd8c797c0a8d877f2ad1e12f831782f` |
| TLSH | `T175E633507094CE37D46312738C68E6B9AD2E3D604EB6A6FFE7985B0F5E1C0E05362C69` |
| SSDEEP | `393216:UCT0sLaxGZQ90ajj8ZqQrdgNTMMVKwlGlAX:bjmtjj8Z7rdn6X` |
| ICON-DHASH | `e0ce8aab9baafae8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_cc17cb60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc17cb6086f10aada5b199a46361996927466128be504943c9fbe2752fe2d558"
    family = "unknown"
    file_name = "cc17cb6086f10aada5b199a46361996927466128be504943c9fbe2752fe2d558.exe"
    file_type = "exe"
    first_seen = "2026-10-04 04:23:46"
  condition:
    hash.sha256(0, filesize) == "cc17cb6086f10aada5b199a46361996927466128be504943c9fbe2752fe2d558"
}
```

### Sample 49: `493611327d5d4fe0`

| Field | Value |
|---|---|
| SHA-256 | `493611327d5d4fe06460977a0295586a9a67434ffc90282a69028fa1f12e3ce9` |
| Family label | `Neshta` |
| File name | `493611327d5d4fe06460977a0295586a9a67434ffc90282a69028fa1f12e3ce9.exe` |
| File type | `exe` |
| First seen | `2026-10-04 04:23:31` |
| Reporter | `Tuxxin` |
| Tags | `exe, Neshta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `874c713546c21ca87434f1440843338e` |
| SHA-1 | `3be04f3ded6c292d6dbb1344dc9b53d82a6a31f1` |
| SHA-256 | `493611327d5d4fe06460977a0295586a9a67434ffc90282a69028fa1f12e3ce9` |
| SHA3-384 | `bb5c3e26423de412d2b044f1900daf7150106e800b05643a6f4772b80d44c5e9e551b6b9b2a9ca40d370ac656553b537` |
| IMPHASH | `9f4693fc0c511135129493f2161d1e86` |
| TLSH | `T12B563322BBE406BBF2B21270A93353A05BFFBC344B75455B97A055888F728F5C4A8357` |
| SSDEEP | `196608:p+/eDsP+5nwoADtJmUrVkcKd9o0xQ4TWeVM1/b:p+/eDheoADJrVkcM9qKMhb` |
| ICON-DHASH | `89adace1e18e0183` |

#### Technical Assessment

- The sample is tracked as `Neshta` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Neshta_049_49361132
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "493611327d5d4fe06460977a0295586a9a67434ffc90282a69028fa1f12e3ce9"
    family = "Neshta"
    file_name = "493611327d5d4fe06460977a0295586a9a67434ffc90282a69028fa1f12e3ce9.exe"
    file_type = "exe"
    first_seen = "2026-10-04 04:23:31"
  condition:
    hash.sha256(0, filesize) == "493611327d5d4fe06460977a0295586a9a67434ffc90282a69028fa1f12e3ce9"
}
```

### Sample 50: `95b4e74af25fbe65`

| Field | Value |
|---|---|
| SHA-256 | `95b4e74af25fbe652b36c394e69c5c6c29d9f803f8a81b5ca37021a569910d96` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-10-04 04:21:07` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff33739d20401e9431abe56b4644ed15` |
| SHA-1 | `ea63342636f5dcf396e542dc48f8aec84a124109` |
| SHA-256 | `95b4e74af25fbe652b36c394e69c5c6c29d9f803f8a81b5ca37021a569910d96` |
| SHA3-384 | `4e883d42e8cc6e775ecf3f0f48e02226b518c21be0adf405b11a84b88bca83068918ad25af84d39488d92a0eef03e09b` |
| TLSH | `T137B47D07A7B7E8B1D4A242B1215557B94872C9B31577D88FEFE52CD0DE64280E32C3AB` |
| TELFHASH | `t15ff186f22abd1dec23e09802d24f1b66ed1ad67358d035b649f725993273e428e71c39` |
| SSDEEP | `6144:CYIWnPHERaBpjfdFpxD+6rrBICUJ2gkiGQz6zC4Oj75NYVQccc62+HFtpYo:CYI0/j13ZDgYWVj75NYVQcj63HFfYo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_95b4e74a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95b4e74af25fbe652b36c394e69c5c6c29d9f803f8a81b5ca37021a569910d96"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-10-04 04:21:07"
  condition:
    hash.sha256(0, filesize) == "95b4e74af25fbe652b36c394e69c5c6c29d9f803f8a81b5ca37021a569910d96"
}
```

### Sample 51: `1e6e262dea13e3cb`

| Field | Value |
|---|---|
| SHA-256 | `1e6e262dea13e3cb47fd4b54a2eb52c90ab391c4ea1a0f7d036da5b804c221b1` |
| Family label | `unknown` |
| File name | `install.sh` |
| File type | `sh` |
| First seen | `2026-10-04 04:19:14` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fcf3c0cadef50909529762104d5fba5` |
| SHA-1 | `7aeda7d7d36a6e85b0854c053095068122cdcd8a` |
| SHA-256 | `1e6e262dea13e3cb47fd4b54a2eb52c90ab391c4ea1a0f7d036da5b804c221b1` |
| SHA3-384 | `79b3de0c3e268fd291d7279ce243eabc39dd10d4bf8ef7160d664fca5b4192bc28f9bb3ae9d29cf6384519e67798803e` |
| TLSH | `T13E9143D2B4F1DE72B5CCC87D9ACA1044768B092B896D2C15F4DD7C143F38269F0BA666` |
| SSDEEP | `96:0fy6VIV4ts80EilJT7XhIUI6MNMgtHvZCTiRxdZF+lO:cy6Gh83ilwUI6MmgxPjWO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_1e6e262d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e6e262dea13e3cb47fd4b54a2eb52c90ab391c4ea1a0f7d036da5b804c221b1"
    family = "unknown"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-10-04 04:19:14"
  condition:
    hash.sha256(0, filesize) == "1e6e262dea13e3cb47fd4b54a2eb52c90ab391c4ea1a0f7d036da5b804c221b1"
}
```

### Sample 52: `79db184a2866150c`

| Field | Value |
|---|---|
| SHA-256 | `79db184a2866150c44d5b32f626c0b120188b27dc480401824d327720e8fcb8e` |
| Family label | `unknown` |
| File name | `79db184a2866150c44d5b32f626c0b120188b27dc480401824d327720e8fcb8e` |
| File type | `elf` |
| First seen | `2026-10-04 04:17:24` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d33f3a53121e85deeaa7672266b256c3` |
| SHA-1 | `d5ecc4a0bf8bb2432bd41405e90cf564228c958e` |
| SHA-256 | `79db184a2866150c44d5b32f626c0b120188b27dc480401824d327720e8fcb8e` |
| SHA3-384 | `32a1bc07f6c498d2e37ace0124e47f6511a582aff4181f0911c28e1eba6f02a50d92b963d88df3c628a931cb745cae05` |
| TLSH | `T19A8302299723098DC43A78F9B99BD7262D4A1B2A144F005506B9F5BB5FF31CCE8F5322` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6Dobtae3:biMYFJvw6Yh0b1gKobtH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_79db184a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79db184a2866150c44d5b32f626c0b120188b27dc480401824d327720e8fcb8e"
    family = "unknown"
    file_name = "79db184a2866150c44d5b32f626c0b120188b27dc480401824d327720e8fcb8e"
    file_type = "elf"
    first_seen = "2026-10-04 04:17:24"
  condition:
    hash.sha256(0, filesize) == "79db184a2866150c44d5b32f626c0b120188b27dc480401824d327720e8fcb8e"
}
```

### Sample 53: `0aead3610357cf80`

| Field | Value |
|---|---|
| SHA-256 | `0aead3610357cf808bb61e1b7ff7e6bbe0880c3d91417c8ae78d359417465bc8` |
| Family label | `Mirai` |
| File name | `0aead3610357cf808bb61e1b7ff7e6bbe0880c3d91417c8ae78d359417465bc8` |
| File type | `elf` |
| First seen | `2026-10-04 04:17:17` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2ecbe4f3c37de40051af957faefe9fd` |
| SHA-1 | `024b55db72faba25bb491bfa119e842188dfde61` |
| SHA-256 | `0aead3610357cf808bb61e1b7ff7e6bbe0880c3d91417c8ae78d359417465bc8` |
| SHA3-384 | `2d1b689b1f3cbeb902440bef5bbc9c2ccf20eaa77d3565b60f7804774f2b565a437bd3a79e20acc0d53edf7544afa56f` |
| TLSH | `T115543A8AFD81AE25D5C1267BFE2F428A33131BB8D2EB71129D145F2476CA94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_0aead361
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0aead3610357cf808bb61e1b7ff7e6bbe0880c3d91417c8ae78d359417465bc8"
    family = "Mirai"
    file_name = "0aead3610357cf808bb61e1b7ff7e6bbe0880c3d91417c8ae78d359417465bc8"
    file_type = "elf"
    first_seen = "2026-10-04 04:17:17"
  condition:
    hash.sha256(0, filesize) == "0aead3610357cf808bb61e1b7ff7e6bbe0880c3d91417c8ae78d359417465bc8"
}
```

### Sample 54: `39d6c517b3e44a09`

| Field | Value |
|---|---|
| SHA-256 | `39d6c517b3e44a09d25a7c9cf37b3eb3cb4800ab16f9540012158fd091e37232` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-04 04:11:41` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX8.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2651c2443b350090248035c8473e39b` |
| SHA-1 | `c2066cb9d2e009fc679404ec3b2cb692e5f13c4c` |
| SHA-256 | `39d6c517b3e44a09d25a7c9cf37b3eb3cb4800ab16f9540012158fd091e37232` |
| SHA3-384 | `e11a99e9780626088ca7a7e10d09078ca2dd9393112cf62130762e662509681672f388ad5ac8863ea22ac1162c020bac` |
| IMPHASH | `63b5232b05f13bc210e1b7598daa2f8e` |
| TLSH | `T135353A36E2C3E4FDC02AC5788697AB3EB871741157247D6F6BA4CE342D13E604B2A65C` |
| SSDEEP | `1536:aXx6XjkSOizqGiN3T1VrufF7e4EVFZDPu2rYGouz6UiFXP:pISHqGid8Fa4EVPPu8oy6RFXP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_39d6c517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39d6c517b3e44a09d25a7c9cf37b3eb3cb4800ab16f9540012158fd091e37232"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-04 04:11:41"
  condition:
    hash.sha256(0, filesize) == "39d6c517b3e44a09d25a7c9cf37b3eb3cb4800ab16f9540012158fd091e37232"
}
```

### Sample 55: `a3fcd1222767342c`

| Field | Value |
|---|---|
| SHA-256 | `a3fcd1222767342c0d8962b8828fca4e65424ad76c05fe3144885629397a521c` |
| Family label | `unknown` |
| File name | `a3fcd1222767342c0d8962b8828fca4e65424ad76c05fe3144885629397a521c.exe` |
| File type | `exe` |
| First seen | `2026-10-04 03:39:27` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94e791c4f0e69665c326c0ec634aa0b6` |
| SHA-1 | `a8e2d79ce69eba035dc87ee8730c3d926bcf070a` |
| SHA-256 | `a3fcd1222767342c0d8962b8828fca4e65424ad76c05fe3144885629397a521c` |
| SHA3-384 | `fa1bd37c9fdee30ba48793d277d08aaba2f8a8f29e30d0610c09eb59a0ff92db81529458ebc7a0bfc3874b1b7615edac` |
| IMPHASH | `332f7ce65ead0adfb3d35147033aabe9` |
| TLSH | `T12C6612337E55E03BD0221A3A9C9772D40A2BBE119D362C4A26E71E4F0B26DF7593D193` |
| SSDEEP | `98304:Snsmtk2aYeD21u2seJKLcxndGaX6tJJQv2FKA75OpVclc02vDRZTEw:cLcD21u2segLoo3u0jc02vVZow` |
| ICON-DHASH | `70e49eb2ba9ef870` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_a3fcd122
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3fcd1222767342c0d8962b8828fca4e65424ad76c05fe3144885629397a521c"
    family = "unknown"
    file_name = "a3fcd1222767342c0d8962b8828fca4e65424ad76c05fe3144885629397a521c.exe"
    file_type = "exe"
    first_seen = "2026-10-04 03:39:27"
  condition:
    hash.sha256(0, filesize) == "a3fcd1222767342c0d8962b8828fca4e65424ad76c05fe3144885629397a521c"
}
```

### Sample 56: `e6a0e9ad743a924c`

| Field | Value |
|---|---|
| SHA-256 | `e6a0e9ad743a924c8c746e4dec8e0780843342ffd2b3b0024e25cd19495cfbee` |
| Family label | `unknown` |
| File name | `e6a0e9ad743a924c8c746e4dec8e0780843342ffd2b3b0024e25cd19495cfbee.exe` |
| File type | `exe` |
| First seen | `2026-10-04 03:39:21` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49d8204af7d4ad39086f0b148b6668df` |
| SHA-1 | `e8ad35b9c9786748b402c1c41cea457926372039` |
| SHA-256 | `e6a0e9ad743a924c8c746e4dec8e0780843342ffd2b3b0024e25cd19495cfbee` |
| SHA3-384 | `c92022e471d5571c58be443f46579c5290f5c6eb24fff5ccbfdd1390caccb201b9607d602e0606753dd72a10d40ffdbf` |
| IMPHASH | `2fb819a19fe4dee5c03e8c6a79342f79` |
| TLSH | `T1C03633C39BF3DBB0F5C105B89D26007674861CBD2828385A7F9E6DCE47AB6517B86381` |
| SSDEEP | `98304:ZcfPU9e+2hZJmnqHOg0Pr2hZTLc5JF6Tybp6zIIGTbPA2hNet9f/T1X:ePU9uig0PiTw5JFtbp6zIZvPK/TB` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_e6a0e9ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6a0e9ad743a924c8c746e4dec8e0780843342ffd2b3b0024e25cd19495cfbee"
    family = "unknown"
    file_name = "e6a0e9ad743a924c8c746e4dec8e0780843342ffd2b3b0024e25cd19495cfbee.exe"
    file_type = "exe"
    first_seen = "2026-10-04 03:39:21"
  condition:
    hash.sha256(0, filesize) == "e6a0e9ad743a924c8c746e4dec8e0780843342ffd2b3b0024e25cd19495cfbee"
}
```

### Sample 57: `ed69b232a3ac92a5`

| Field | Value |
|---|---|
| SHA-256 | `ed69b232a3ac92a5e5f43757119af730f5d814305122a456132dad36a1d6a5fd` |
| Family label | `unknown` |
| File name | `ed69b232a3ac92a5e5f43757119af730f5d814305122a456132dad36a1d6a5fd.exe` |
| File type | `exe` |
| First seen | `2026-10-04 03:38:30` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c24fdcd921be5cca6f0ee11156a6bd7d` |
| SHA-1 | `55372e278bc2ef663bd8ade1afab2956ee69c58c` |
| SHA-256 | `ed69b232a3ac92a5e5f43757119af730f5d814305122a456132dad36a1d6a5fd` |
| SHA3-384 | `9927fe69e85c7b6d1519f9cb0aef7660d3b3b6268af05cb2c3b0c7276663250d68486ff9e0a033771ee4d528702e19a6` |
| IMPHASH | `0b5552dccd9d0a834cea55c0c8fc05be` |
| TLSH | `T17927337A2350C8C9E9EA533BDD9FC4A515B5AC360394F6CF526934084DB3252ED3AFA0` |
| SSDEEP | `393216:rZAlqYXJBStt6k/m3pgDOEkSgs+0W8lhNvP4GB3v:rWlqYXJBk0kKlANW8lhNvvB3v` |
| ICON-DHASH | `8084e4e4e4e48480` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_ed69b232
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed69b232a3ac92a5e5f43757119af730f5d814305122a456132dad36a1d6a5fd"
    family = "unknown"
    file_name = "ed69b232a3ac92a5e5f43757119af730f5d814305122a456132dad36a1d6a5fd.exe"
    file_type = "exe"
    first_seen = "2026-10-04 03:38:30"
  condition:
    hash.sha256(0, filesize) == "ed69b232a3ac92a5e5f43757119af730f5d814305122a456132dad36a1d6a5fd"
}
```

### Sample 58: `a1ebed3463fcf073`

| Field | Value |
|---|---|
| SHA-256 | `a1ebed3463fcf073dd0a91a39546d008472040220984b80a78be410ba9721b3a` |
| Family label | `Mirai` |
| File name | `7a2b25d2b1ebef1d.bin` |
| File type | `elf` |
| First seen | `2026-10-04 03:27:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79d8d39c604c6ead773b92bb630dc299` |
| SHA-1 | `547ff8295a7ff58f78d5e6f7db84f86f4b4e98a3` |
| SHA-256 | `a1ebed3463fcf073dd0a91a39546d008472040220984b80a78be410ba9721b3a` |
| SHA3-384 | `5d8c49fe66e841bf2932f118c0deba3c4a78622270a1525b7ea43ea67ca20e514e85cdc529153887a95adf2f8af9b14e` |
| TLSH | `T1FF64E71A3A319F7EF2688B7047F74F30975962D61BE2D684E2ACD5101F1039D681FBA8` |
| TELFHASH | `t1f5816154943d09e9af239c2968ac6bb34957e52a22d2bf29ff16ccc4044e42cf118d0f` |
| SSDEEP | `6144:1xn5xtSVC4HI6NQrd0v+t5xxiSbUTOqHp2XjAEWMSC9glKcYHJICQqerdoVQq3y:1x53ia0v+tXxiS4TOqUaUyKcYHJICQqu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_a1ebed34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1ebed3463fcf073dd0a91a39546d008472040220984b80a78be410ba9721b3a"
    family = "Mirai"
    file_name = "7a2b25d2b1ebef1d.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:27:22"
  condition:
    hash.sha256(0, filesize) == "a1ebed3463fcf073dd0a91a39546d008472040220984b80a78be410ba9721b3a"
}
```

### Sample 59: `78c910c7a45022d5`

| Field | Value |
|---|---|
| SHA-256 | `78c910c7a45022d5537698d103c440f34672bc95a05b47db16cf12afceab4a92` |
| Family label | `Mirai` |
| File name | `78c910c7a45022d5.bin` |
| File type | `elf` |
| First seen | `2026-10-04 03:26:50` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6ebcee81c0755d8c08a271f5163d8f4` |
| SHA-1 | `08496844beb9684eec5946a16c7648783264dbf3` |
| SHA-256 | `78c910c7a45022d5537698d103c440f34672bc95a05b47db16cf12afceab4a92` |
| SHA3-384 | `d06e96731af3351d219cdd18718cd8d8e8d8408e973fd389160e72a8485d7112bc0add64c208b672226e1e5f9a9e0857` |
| TLSH | `T1C4342904EB408F57C5D227B9FB9F425533339B58E7E773069A286BB43B8375A4E22106` |
| TELFHASH | `t13a210f46a53d416a1da12c1ccd286fb2101b9b233292be35ff1adcc5686f802e968d0f` |
| SSDEEP | `6144:J8+mHUweqJAdaB+cZgwKGvpCYydWzvTwpCV/GJvc3mL28fNwhS:J8+m0DqJAdaBNgwKazydWzV/4EmLFfNh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_78c910c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78c910c7a45022d5537698d103c440f34672bc95a05b47db16cf12afceab4a92"
    family = "Mirai"
    file_name = "78c910c7a45022d5.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:50"
  condition:
    hash.sha256(0, filesize) == "78c910c7a45022d5537698d103c440f34672bc95a05b47db16cf12afceab4a92"
}
```

### Sample 60: `01325b5d6ae77781`

| Field | Value |
|---|---|
| SHA-256 | `01325b5d6ae777813bf88b5804468c1a53c3a1e5ad3448ae274f60cb8ea0dcd0` |
| Family label | `Mirai` |
| File name | `01325b5d6ae77781.bin` |
| File type | `elf` |
| First seen | `2026-10-04 03:26:41` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `876794b541d8da0af48ef9c68aa4360a` |
| SHA-1 | `0c6fed040d7d4ace9bbf4cd21e735054674bf25b` |
| SHA-256 | `01325b5d6ae777813bf88b5804468c1a53c3a1e5ad3448ae274f60cb8ea0dcd0` |
| SHA3-384 | `c3832c3cd4b646e8e646d3f8c76a21567a289b0b89a1c237eadba6680e78f30a98c99bdfb2b4056b78ad513d9f131fb9` |
| TLSH | `T1AE045B43AD655FA7C542AFB461B75A710753E8150F4B0F8AA63AEAF4060BACCF80D374` |
| TELFHASH | `t127610058a83d05d99e231c1968696fb35957e52a32e6bb18ff1addc0084e428f158d0f` |
| SSDEEP | `3072:ccMnKyzLU563egFWnEr9HTQdNmqOzEKv2PwE0qzMcxmBOIRpO:CnKyUqwnE9TQd+wKv2PwE0qzMcxmBOIW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_01325b5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01325b5d6ae777813bf88b5804468c1a53c3a1e5ad3448ae274f60cb8ea0dcd0"
    family = "Mirai"
    file_name = "01325b5d6ae77781.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:41"
  condition:
    hash.sha256(0, filesize) == "01325b5d6ae777813bf88b5804468c1a53c3a1e5ad3448ae274f60cb8ea0dcd0"
}
```

### Sample 61: `7a2b25d2b1ebef1d`

| Field | Value |
|---|---|
| SHA-256 | `7a2b25d2b1ebef1d158158ecc4e82a6effc7b8fc6379d3f6e212a731e615d86d` |
| Family label | `Mirai` |
| File name | `7a2b25d2b1ebef1d.bin` |
| File type | `elf` |
| First seen | `2026-10-04 03:26:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65223c6d432547a9de8eb267244d1c88` |
| SHA-1 | `29012e2324265fcd01af81d92b5154810b490c04` |
| SHA-256 | `7a2b25d2b1ebef1d158158ecc4e82a6effc7b8fc6379d3f6e212a731e615d86d` |
| SHA3-384 | `f3ae8f1374f61b160403cebee68609b248ed68dcf02cd6fe1983b50192babdaaf599cebf0a7dd97cb37bcec5681b7dc4` |
| TLSH | `T138A312ACD3031146CE46F2BB29E51189289A1C559743FF5ED9E578DA3F318A812CB7E0` |
| SSDEEP | `3072:TNhUhUIf87EA2ELP9/b63f8x4eNPjCHVQCk2llk0:pOOAA2ENW3f44S7C1QCzlk0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_7a2b25d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a2b25d2b1ebef1d158158ecc4e82a6effc7b8fc6379d3f6e212a731e615d86d"
    family = "Mirai"
    file_name = "7a2b25d2b1ebef1d.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:33"
  condition:
    hash.sha256(0, filesize) == "7a2b25d2b1ebef1d158158ecc4e82a6effc7b8fc6379d3f6e212a731e615d86d"
}
```

### Sample 62: `a6b654ae2af04a24`

| Field | Value |
|---|---|
| SHA-256 | `a6b654ae2af04a247445a3c0958336b17444fd3e282826e12e8798892df681b8` |
| Family label | `Mirai` |
| File name | `a6b654ae2af04a24.bin` |
| File type | `elf` |
| First seen | `2026-10-04 03:26:25` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4240fcad71ba1bf0b03e67d948f67bf6` |
| SHA-1 | `14685568277514d9a5f178e480767c1f2884d3d2` |
| SHA-256 | `a6b654ae2af04a247445a3c0958336b17444fd3e282826e12e8798892df681b8` |
| SHA3-384 | `ae07438a880d0044d6bcff5b22f93716f8ceceb1813e63ea3a3ab240c0ab8dac9ead8ccaec4c2cc1bd11cdc2c304f066` |
| TLSH | `T173D45D66BD919B90C5E159BEFB9E437872035BB9E3FFB006CA045FA06BC54854B3E201` |
| SSDEEP | `12288:bJtnDBrB4uCeom7IvDb7WYBaccoEV9D30dQ+fik3Nfx:HEeow6BTcq3N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_a6b654ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6b654ae2af04a247445a3c0958336b17444fd3e282826e12e8798892df681b8"
    family = "Mirai"
    file_name = "a6b654ae2af04a24.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:25"
  condition:
    hash.sha256(0, filesize) == "a6b654ae2af04a247445a3c0958336b17444fd3e282826e12e8798892df681b8"
}
```

### Sample 63: `619fee538f560558`

| Field | Value |
|---|---|
| SHA-256 | `619fee538f560558ad4a422b64893355e4b650fd81bd443877fa4b2fa4690819` |
| Family label | `Gafgyt` |
| File name | `619fee538f560558.bin` |
| File type | `elf` |
| First seen | `2026-10-04 03:26:16` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db0a0c0fdd0ee834ca047a1f273fb561` |
| SHA-1 | `c72899f19e67bcf33179857b2dc3003014f964aa` |
| SHA-256 | `619fee538f560558ad4a422b64893355e4b650fd81bd443877fa4b2fa4690819` |
| SHA3-384 | `ac00cd2c815d21563d61d889a9e40ac91563a5f4d87afba7ab88a2e398ca3407dadf382eb1d923428fab8082e3deeb8a` |
| TLSH | `T16D14390774D588FBC4C68FB91BDB95218923F8391B32620AB798BDDA1F0DED46E1D214` |
| TELFHASH | `t1fb611108a83d05d99e231c1968686ff35957e52a32e6bb18ff1addc0084e428f258e0f` |
| SSDEEP | `6144:qrln5PIGatHqEw2prvKdZ7vLjII+ndUIbpO:qrx5+5qEZvKdZ7vLjII+ndUIbpO` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_063_619fee53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "619fee538f560558ad4a422b64893355e4b650fd81bd443877fa4b2fa4690819"
    family = "Gafgyt"
    file_name = "619fee538f560558.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:16"
  condition:
    hash.sha256(0, filesize) == "619fee538f560558ad4a422b64893355e4b650fd81bd443877fa4b2fa4690819"
}
```

### Sample 64: `18f1a42c10ee3708`

| Field | Value |
|---|---|
| SHA-256 | `18f1a42c10ee3708c20a3ede9a15ad43ab77852f7693118940cab780fad2ea89` |
| Family label | `Mirai` |
| File name | `18f1a42c10ee3708.bin` |
| File type | `elf` |
| First seen | `2026-10-04 03:26:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6561f6b4ee99d156e69a0d5ab925d11a` |
| SHA-1 | `23185039ad313a57c5f60a6b0217d41b80cee7cd` |
| SHA-256 | `18f1a42c10ee3708c20a3ede9a15ad43ab77852f7693118940cab780fad2ea89` |
| SHA3-384 | `e17adea5443315d3df0da4bf85c2191f0d4a9d6f51cfbe2a836b98bfdb19532027e736f53d118ad24b376df4b25dc733` |
| TLSH | `T112C4B043B77A1490C8A680B8A5F207FC8997928756F7F1DBCF4AE9D5B916490332C3D2` |
| SSDEEP | `6144:HcnKkyjstEONaL63RAoKzyy+l0EMOGff0kekDFTfpOgtOCppe2cw7J4TATqo:HcnY/L6B5KeyzxOGfckemZ9lvJ40T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_18f1a42c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18f1a42c10ee3708c20a3ede9a15ad43ab77852f7693118940cab780fad2ea89"
    family = "Mirai"
    file_name = "18f1a42c10ee3708.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:08"
  condition:
    hash.sha256(0, filesize) == "18f1a42c10ee3708c20a3ede9a15ad43ab77852f7693118940cab780fad2ea89"
}
```

### Sample 65: `cd54c3e06103740a`

| Field | Value |
|---|---|
| SHA-256 | `cd54c3e06103740a88a510c6114e70291b14bc7b3f2cb32be2c0122aa955a037` |
| Family label | `Mirai` |
| File name | `cd54c3e06103740a.bin` |
| File type | `elf` |
| First seen | `2026-10-04 03:25:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7934d65cd20f21e9b7fc8e07c9bf328` |
| SHA-1 | `c7a2b1a6dc35a92c5f01c598d1cf1d80670c71fd` |
| SHA-256 | `cd54c3e06103740a88a510c6114e70291b14bc7b3f2cb32be2c0122aa955a037` |
| SHA3-384 | `df21f0cd742d4766e0ade9bc6f0bf7cd2477171995a5a6316e701e70ffb55338f0f84b03897515ab8a919cb5dcbd7f64` |
| TLSH | `T104D46D07B9F484FEC8D6C0744B8B933A8D62F48A2139F68FABC5AE817E15E50671D741` |
| TELFHASH | `t173f11e340879342972d3c251b703d5ad1d321d2a86f971b43a53a8edeeee7c04db68a2` |
| SSDEEP | `6144:5PjqtaIZ9OWW/7g0hsRYUjZtN1c9bIo8qnc+wOrem6nJR8YBJ1T3I2RLQBWOqfid:5mZALQY6ULemcJRFIGLQOu5g7s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_cd54c3e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd54c3e06103740a88a510c6114e70291b14bc7b3f2cb32be2c0122aa955a037"
    family = "Mirai"
    file_name = "cd54c3e06103740a.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:25:59"
  condition:
    hash.sha256(0, filesize) == "cd54c3e06103740a88a510c6114e70291b14bc7b3f2cb32be2c0122aa955a037"
}
```

### Sample 66: `3c3b6f5f7df0e828`

| Field | Value |
|---|---|
| SHA-256 | `3c3b6f5f7df0e8286fb8a0c2d77a807c132326fa1b3c4187889d188181c1e78b` |
| Family label | `CoinMiner` |
| File name | `3c3b6f5f7df0e828.bin` |
| File type | `exe` |
| First seen | `2026-10-04 03:25:51` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45c87a5582de778121d8e3159c4c78ef` |
| SHA-1 | `66d2039f19d5d877b93f29b73fffeed9af1412be` |
| SHA-256 | `3c3b6f5f7df0e8286fb8a0c2d77a807c132326fa1b3c4187889d188181c1e78b` |
| SHA3-384 | `d83e16a56c2c287f0265eae624236b8c2d9c537b7c6ecb5615cdffe0780613fdf8a1947b687acf0c3e5818804e42c6ea` |
| IMPHASH | `2f395dd587b12a61e6877a545da7a7d8` |
| TLSH | `T196172306B74355CFCA56C2341969A331FE6EEAE46740CB7B8B98D17C3D62C1A28C53D2` |
| SSDEEP | `393216:2O3aS0TOfsDBsQ99499La6vwrWqEMiVkVqkGrWqEMiVkVHkT99a6vJBsQ99Ot3st:lJ06iBs09Yag+WqEMXVqjWqEMXVHwagp` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_066_3c3b6f5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c3b6f5f7df0e8286fb8a0c2d77a807c132326fa1b3c4187889d188181c1e78b"
    family = "CoinMiner"
    file_name = "3c3b6f5f7df0e828.bin"
    file_type = "exe"
    first_seen = "2026-10-04 03:25:51"
  condition:
    hash.sha256(0, filesize) == "3c3b6f5f7df0e8286fb8a0c2d77a807c132326fa1b3c4187889d188181c1e78b"
}
```

### Sample 67: `9cad5794277b3001`

| Field | Value |
|---|---|
| SHA-256 | `9cad5794277b3001b080294fcf1f54350a991b7b59af9a47ad12dc34f3d27439` |
| Family label | `unknown` |
| File name | `9cad5794277b3001b080294fcf1f54350a991b7b59af9a47ad12dc34f3d27439.bin` |
| File type | `zip` |
| First seen | `2026-10-04 02:25:27` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6a9fee823bfe67f25b4e9ad9f8b2fd6` |
| SHA-1 | `1c33d28831aa4f31fc0e1145f67c83c3c2d5f5ec` |
| SHA-256 | `9cad5794277b3001b080294fcf1f54350a991b7b59af9a47ad12dc34f3d27439` |
| SHA3-384 | `b1ae07e976ce95d12b4b4feb1822ed7ca9451948430c8aa6bf6b2c6fd9d84c8f010a153ed8945579c827677207c19b2b` |
| TLSH | `T1AD8302835149CC88CFE98374F8779C877ADED0C2EC6928E9DA1B5BC596F440213C795A` |
| SSDEEP | `1536:0XPhGGSiG6gv+1wAGQyrUItD1DFsAEq4zbE3SXsCRgdsFuWwtu+rUCBT:0/hGGSuhWrUIRdOnzgLCDul5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_9cad5794
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cad5794277b3001b080294fcf1f54350a991b7b59af9a47ad12dc34f3d27439"
    family = "unknown"
    file_name = "9cad5794277b3001b080294fcf1f54350a991b7b59af9a47ad12dc34f3d27439.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:25:27"
  condition:
    hash.sha256(0, filesize) == "9cad5794277b3001b080294fcf1f54350a991b7b59af9a47ad12dc34f3d27439"
}
```

### Sample 68: `b8acf0e39cf6e23f`

| Field | Value |
|---|---|
| SHA-256 | `b8acf0e39cf6e23f1616ec375c794b31f46731e893a7115c187bed03b39d49dc` |
| Family label | `unknown` |
| File name | `b8acf0e39cf6e23f1616ec375c794b31f46731e893a7115c187bed03b39d49dc.bin` |
| File type | `zip` |
| First seen | `2026-10-04 02:25:23` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccfaa5ea9a283cc029f5d285f801db95` |
| SHA-1 | `ed72b6a927b6d1a82a1c2809017969fe5ddbaeb7` |
| SHA-256 | `b8acf0e39cf6e23f1616ec375c794b31f46731e893a7115c187bed03b39d49dc` |
| SHA3-384 | `d9bc2f2fe713c2a42e63beca33af54204b20f60396fe7cbe8ebe93a8f02f10176105be497d9c809cb3378e48314e1c59` |
| TLSH | `T1E2030185B459AE18832ED11FF4DEA8DD8991368FF83E7F80035E156005A3BF8AD015BB` |
| SSDEEP | `768:D4zb+p20gRF8lcGChMvPJrSaK3fPdiUUhlR7KvyP6+EGsBjV+UMzOjdFVYs:D8bOgROlhHPJpAYlR7uq65lL+UMzEdXP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_b8acf0e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8acf0e39cf6e23f1616ec375c794b31f46731e893a7115c187bed03b39d49dc"
    family = "unknown"
    file_name = "b8acf0e39cf6e23f1616ec375c794b31f46731e893a7115c187bed03b39d49dc.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:25:23"
  condition:
    hash.sha256(0, filesize) == "b8acf0e39cf6e23f1616ec375c794b31f46731e893a7115c187bed03b39d49dc"
}
```

### Sample 69: `ca4d077c5679db66`

| Field | Value |
|---|---|
| SHA-256 | `ca4d077c5679db66f958c9c2dbb1710c281340c6f0fefc1883b953bcddc9d120` |
| Family label | `unknown` |
| File name | `ca4d077c5679db66f958c9c2dbb1710c281340c6f0fefc1883b953bcddc9d120.bin` |
| File type | `zip` |
| First seen | `2026-10-04 02:25:18` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5135b99ddfb605c52574cb0a0df57074` |
| SHA-1 | `eb0be26bddc7c3599f379a85be322036a40d8b7d` |
| SHA-256 | `ca4d077c5679db66f958c9c2dbb1710c281340c6f0fefc1883b953bcddc9d120` |
| SHA3-384 | `94c4e9156f4f6fb3331a67757c7213fd936112210c4d531ff92196ba00c656af172e586092cffe658d56ad6e876a9e4a` |
| TLSH | `T19D02B0B3987CF4C6EBAE32A4309460C8CD9C2550BDFA25970CEE661641ECBB12529D96` |
| SSDEEP | `192:HvqyDdkjQ9+rl6UQFSd7OrpsTsCMp8AacTjI63hU:Pqy/9+8qpW0sCo87OkohU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_ca4d077c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca4d077c5679db66f958c9c2dbb1710c281340c6f0fefc1883b953bcddc9d120"
    family = "unknown"
    file_name = "ca4d077c5679db66f958c9c2dbb1710c281340c6f0fefc1883b953bcddc9d120.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:25:18"
  condition:
    hash.sha256(0, filesize) == "ca4d077c5679db66f958c9c2dbb1710c281340c6f0fefc1883b953bcddc9d120"
}
```

### Sample 70: `c05b668f1ba8897a`

| Field | Value |
|---|---|
| SHA-256 | `c05b668f1ba8897a9fe6345b627d696897f4dc6817dc2410600940d25102d740` |
| Family label | `unknown` |
| File name | `c05b668f1ba8897a9fe6345b627d696897f4dc6817dc2410600940d25102d740.bin` |
| File type | `zip` |
| First seen | `2026-10-04 02:25:13` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55560021385bf300bd71bf1e3e93ee51` |
| SHA-1 | `2144098289507714b17747cedbecab4055e185e3` |
| SHA-256 | `c05b668f1ba8897a9fe6345b627d696897f4dc6817dc2410600940d25102d740` |
| SHA3-384 | `4957c66d57cbf7f4627db6893fb4ccb14696dd056660fc56302ab8cf601828dd34c415777231500ed7232755ac7da6f1` |
| TLSH | `T1EF95338109FBCD55ACE1A40FED7585893F0F1DD62E2ABD8F8EF39F2428346610609E46` |
| SSDEEP | `49152:sGTXGE8uwcNL0Qm4VEu3x2ifaCVJsRgj7bdYUuuDFaxluJo:sUGEKcNoQmGd/+E7bdY/Cclx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_c05b668f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c05b668f1ba8897a9fe6345b627d696897f4dc6817dc2410600940d25102d740"
    family = "unknown"
    file_name = "c05b668f1ba8897a9fe6345b627d696897f4dc6817dc2410600940d25102d740.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:25:13"
  condition:
    hash.sha256(0, filesize) == "c05b668f1ba8897a9fe6345b627d696897f4dc6817dc2410600940d25102d740"
}
```

### Sample 71: `40920a84cbcb0b0a`

| Field | Value |
|---|---|
| SHA-256 | `40920a84cbcb0b0a4577bcd85f395cac0ee7de67d36fad3cd4fe8e04a65dce8f` |
| Family label | `unknown` |
| File name | `40920a84cbcb0b0a4577bcd85f395cac0ee7de67d36fad3cd4fe8e04a65dce8f.bin` |
| File type | `zip` |
| First seen | `2026-10-04 02:25:08` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ffec072af4a55111e2352dd2e983405` |
| SHA-1 | `ebcd3cfe99471008e5d858a9fe67eb9ba09140a9` |
| SHA-256 | `40920a84cbcb0b0a4577bcd85f395cac0ee7de67d36fad3cd4fe8e04a65dce8f` |
| SHA3-384 | `8bd752aab17634684b47311353c9ad44391cef358df06fa7a0d357a2897d045050f5f2de49f401caa6480dd1f3b347c5` |
| TLSH | `T1814533E7A5D36080F082D298AF5D095F0FEE359442C8AD98172E374DC56D60F837BB6A` |
| SSDEEP | `24576:SJ1QFxvQyWAH52c0XNpGo4y2DEq0p48J9KfZ9mautj2fn:g10vQac5P1aEq0p4X3utjE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_40920a84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40920a84cbcb0b0a4577bcd85f395cac0ee7de67d36fad3cd4fe8e04a65dce8f"
    family = "unknown"
    file_name = "40920a84cbcb0b0a4577bcd85f395cac0ee7de67d36fad3cd4fe8e04a65dce8f.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:25:08"
  condition:
    hash.sha256(0, filesize) == "40920a84cbcb0b0a4577bcd85f395cac0ee7de67d36fad3cd4fe8e04a65dce8f"
}
```

### Sample 72: `77e81a853bc978c4`

| Field | Value |
|---|---|
| SHA-256 | `77e81a853bc978c41191d3e7f83312e46a925c9464ca55eed5ed6befbb579871` |
| Family label | `unknown` |
| File name | `77e81a853bc978c41191d3e7f83312e46a925c9464ca55eed5ed6befbb579871.bin` |
| File type | `zip` |
| First seen | `2026-10-04 02:23:47` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ba21fa78ee2a964ba9049e9fb7aec3a` |
| SHA-1 | `2762c077e6e8e30dcd87f362aaec08c66cf6c5aa` |
| SHA-256 | `77e81a853bc978c41191d3e7f83312e46a925c9464ca55eed5ed6befbb579871` |
| SHA3-384 | `f2bf1e726933f970c9a4a7387499865e45450f73395f73d24cc9ae625da777acbeac24198f5003a2e3d378e161ef7c0d` |
| TLSH | `T1360423D244314BE922076C1A7EC8D4D9FC9140DE91F53D702B5CCDA29F861BB2EF292A` |
| SSDEEP | `3072:tcuCVoNPGHcBR1WLaJBVtzm7GlDOg+ofmbViyNSxo5XtIZjnvxpJgghCmzMldji5:tPKEPjBBb7zqg+ofmb845aZjn5ddIls5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_77e81a85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77e81a853bc978c41191d3e7f83312e46a925c9464ca55eed5ed6befbb579871"
    family = "unknown"
    file_name = "77e81a853bc978c41191d3e7f83312e46a925c9464ca55eed5ed6befbb579871.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:23:47"
  condition:
    hash.sha256(0, filesize) == "77e81a853bc978c41191d3e7f83312e46a925c9464ca55eed5ed6befbb579871"
}
```

### Sample 73: `95ba4eedec8a0478`

| Field | Value |
|---|---|
| SHA-256 | `95ba4eedec8a047843dd595103de7415c1611c6e19bd5da172bae8c7cce21b4e` |
| Family label | `Troldesh` |
| File name | `95ba4eedec8a047843dd595103de7415c1611c6e19bd5da172bae8c7cce21b4e.bin` |
| File type | `zip` |
| First seen | `2026-10-04 02:23:42` |
| Reporter | `Tuxxin` |
| Tags | `Troldesh, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64d5ccf6b2ad07857ab0d397f69fe6df` |
| SHA-1 | `455d75917f3fb80568e5dfcb43c8e68c7475316d` |
| SHA-256 | `95ba4eedec8a047843dd595103de7415c1611c6e19bd5da172bae8c7cce21b4e` |
| SHA3-384 | `a6ccc6951556751715bc2a2ac674ef6ae1617faf9446d05e899cddeaa51c2f0c89d908825b64b6e05e46786b62062d56` |
| TLSH | `T1E9153316275C62ADCDED20E5704C864104E2ED687CAA1CD1F77884A639628F3F6B74EF` |
| SSDEEP | `24576:wGKkYD9RDVMVL18yueDyqPDWhthqbMPDXnZgBriT:pKNHDVMVL18yuGyEKnPD3KiT` |

#### Technical Assessment

- The sample is tracked as `Troldesh` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Troldesh_073_95ba4eed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95ba4eedec8a047843dd595103de7415c1611c6e19bd5da172bae8c7cce21b4e"
    family = "Troldesh"
    file_name = "95ba4eedec8a047843dd595103de7415c1611c6e19bd5da172bae8c7cce21b4e.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:23:42"
  condition:
    hash.sha256(0, filesize) == "95ba4eedec8a047843dd595103de7415c1611c6e19bd5da172bae8c7cce21b4e"
}
```

### Sample 74: `f57d52559fcd1486`

| Field | Value |
|---|---|
| SHA-256 | `f57d52559fcd14862b5906fe9ddbde34016f752b63ec03e7a1549823046a87c1` |
| Family label | `unknown` |
| File name | `f57d52559fcd14862b5906fe9ddbde34016f752b63ec03e7a1549823046a87c1.bin` |
| File type | `zip` |
| First seen | `2026-10-04 02:23:36` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78cf5b48e651cd6d0ccc16c3c8d1f9bb` |
| SHA-1 | `bf1f61c7ea901e55b62075cf84572807849b1cdf` |
| SHA-256 | `f57d52559fcd14862b5906fe9ddbde34016f752b63ec03e7a1549823046a87c1` |
| SHA3-384 | `bacc1655a04da0d642b7e4f2acc382d2a6fb72a3df8fa9a7054d97e9f2a29deadbc9b2ae6577de3be546f88a39682a29` |
| TLSH | `T1A284230DFA3DE39C8BDA21B7E8C3694BD75B00CC0521A36BE631EA6D19B37512605F06` |
| SSDEEP | `6144:JimVdKyLNAyj/y9EhEbjI/lOavpA6DBzxBgc+sqP5sI4a4pF0ghq/jP:QmVdjJ69yEg/THtgvsqRsGNgh2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_f57d5255
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f57d52559fcd14862b5906fe9ddbde34016f752b63ec03e7a1549823046a87c1"
    family = "unknown"
    file_name = "f57d52559fcd14862b5906fe9ddbde34016f752b63ec03e7a1549823046a87c1.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:23:36"
  condition:
    hash.sha256(0, filesize) == "f57d52559fcd14862b5906fe9ddbde34016f752b63ec03e7a1549823046a87c1"
}
```

### Sample 75: `71d0b3cdb0e21a4e`

| Field | Value |
|---|---|
| SHA-256 | `71d0b3cdb0e21a4ea729a4ab1668ecdd683e252d044b75938f292ea54ac31413` |
| Family label | `VShell` |
| File name | `71d0b3cdb0e21a4ea729a4ab1668ecdd683e252d044b75938f292ea54ac31413.exe` |
| File type | `exe` |
| First seen | `2026-10-04 02:23:31` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e473ccde151acda24cb2c5db83413c0` |
| SHA-1 | `4c28a8efc9ebdc43aecde639ae72787405844cd7` |
| SHA-256 | `71d0b3cdb0e21a4ea729a4ab1668ecdd683e252d044b75938f292ea54ac31413` |
| SHA3-384 | `4793ccee4427a143c7890ed8bad0646c581e6e0c78e42fd911df1a45d3fac4397a3ebbac0d485738f634025bedde84aa` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T168716188F3136AF1E42C86F800D3A564C019ABB8C150BF4D5E60381D3C210BA255AF97` |
| SSDEEP | `48:6Icwm0Mt2WSJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jRtQSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_075_71d0b3cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71d0b3cdb0e21a4ea729a4ab1668ecdd683e252d044b75938f292ea54ac31413"
    family = "VShell"
    file_name = "71d0b3cdb0e21a4ea729a4ab1668ecdd683e252d044b75938f292ea54ac31413.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:23:31"
  condition:
    hash.sha256(0, filesize) == "71d0b3cdb0e21a4ea729a4ab1668ecdd683e252d044b75938f292ea54ac31413"
}
```

### Sample 76: `e31bc5c35b977c16`

| Field | Value |
|---|---|
| SHA-256 | `e31bc5c35b977c1612184a772cbdc5ba5b9137788d399e4ed55521bd5ca43ecd` |
| Family label | `unknown` |
| File name | `e31bc5c35b977c1612184a772cbdc5ba5b9137788d399e4ed55521bd5ca43ecd.exe` |
| File type | `exe` |
| First seen | `2026-10-04 02:20:18` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4206b0678c67c956b3693dae45f0e53d` |
| SHA-1 | `6309a86b86c1a68114a3f3abfa63f4aeff29a1df` |
| SHA-256 | `e31bc5c35b977c1612184a772cbdc5ba5b9137788d399e4ed55521bd5ca43ecd` |
| SHA3-384 | `b677fabd1339746e0b7fb630f87228b67f0defa35aa70e4aff608b5764fe8c6f700750df12353812dc9dfba9774c07a8` |
| IMPHASH | `b2f76a377810c3911d9a29c066358593` |
| TLSH | `T19926222D634BA1FFC3978270D9A46325FD399E686108CD7AD254E1BC3EB1C2E24C56E1` |
| SSDEEP | `49152:9APdVwK8fqmVJEwnNdE/UJC8GnilVFaSL3IhG7G9t:Qz8S/+NUOGiFWhGM` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_e31bc5c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e31bc5c35b977c1612184a772cbdc5ba5b9137788d399e4ed55521bd5ca43ecd"
    family = "unknown"
    file_name = "e31bc5c35b977c1612184a772cbdc5ba5b9137788d399e4ed55521bd5ca43ecd.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:20:18"
  condition:
    hash.sha256(0, filesize) == "e31bc5c35b977c1612184a772cbdc5ba5b9137788d399e4ed55521bd5ca43ecd"
}
```

### Sample 77: `c33bd3ffce08f045`

| Field | Value |
|---|---|
| SHA-256 | `c33bd3ffce08f04552e17b177d6df4f0b0600048f4f158f35c2f46f68c930edd` |
| Family label | `unknown` |
| File name | `c33bd3ffce08f04552e17b177d6df4f0b0600048f4f158f35c2f46f68c930edd.exe` |
| File type | `exe` |
| First seen | `2026-10-04 02:20:12` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5e3b490794b7f493344abcc70664c23` |
| SHA-1 | `492c5ba9f1daa3f091da4a1bdaf48cb4bdebabb1` |
| SHA-256 | `c33bd3ffce08f04552e17b177d6df4f0b0600048f4f158f35c2f46f68c930edd` |
| SHA3-384 | `8577a1765bfe596093b3b1a9064bb3f25d005001024290a9e8b375dcdea845fcceefe299206418df206e403821f4149a` |
| IMPHASH | `ff683e4af414c6e92d70da9834742613` |
| TLSH | `T19637024C736DB291F14F8E3DEC2894DECE4A687AE1603A0E606DDD2B3511BE5519EBC0` |
| SSDEEP | `393216:StWizKEZR8I/WupmBOm+V5ZU8fci08zDEWf1uKfcKO3TCxv9:UWiuEZbDyO7V5ZUqcidz4Wdu1KOjk9` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_c33bd3ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c33bd3ffce08f04552e17b177d6df4f0b0600048f4f158f35c2f46f68c930edd"
    family = "unknown"
    file_name = "c33bd3ffce08f04552e17b177d6df4f0b0600048f4f158f35c2f46f68c930edd.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:20:12"
  condition:
    hash.sha256(0, filesize) == "c33bd3ffce08f04552e17b177d6df4f0b0600048f4f158f35c2f46f68c930edd"
}
```

### Sample 78: `4f99fcc6eefdf350`

| Field | Value |
|---|---|
| SHA-256 | `4f99fcc6eefdf3501f5bdaa92cea2cbfeb58a338ef2b721f4f2992cc51bd7ffc` |
| Family label | `VShell` |
| File name | `4f99fcc6eefdf3501f5bdaa92cea2cbfeb58a338ef2b721f4f2992cc51bd7ffc.exe` |
| File type | `exe` |
| First seen | `2026-10-04 02:20:05` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44ef4338d426cecca8a92bed43cd255c` |
| SHA-1 | `0300faaf45770d1ccbd799e71ab694d777b9c40a` |
| SHA-256 | `4f99fcc6eefdf3501f5bdaa92cea2cbfeb58a338ef2b721f4f2992cc51bd7ffc` |
| SHA3-384 | `c2737f4b87e851758c10c11e88d783e3981fbc134ebd38c9ba378c6b11e3f5f7df471dddcc6a0c9e12ed6fca1741fea3` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1F091B7C5F757D6B2EC1C17F500A37994C8682E1482BC9B574FA16F0C3C111AA3D7EA12` |
| SSDEEP | `48:6I7lwe7TIG08SqJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1l09Eq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_078_4f99fcc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f99fcc6eefdf3501f5bdaa92cea2cbfeb58a338ef2b721f4f2992cc51bd7ffc"
    family = "VShell"
    file_name = "4f99fcc6eefdf3501f5bdaa92cea2cbfeb58a338ef2b721f4f2992cc51bd7ffc.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:20:05"
  condition:
    hash.sha256(0, filesize) == "4f99fcc6eefdf3501f5bdaa92cea2cbfeb58a338ef2b721f4f2992cc51bd7ffc"
}
```

### Sample 79: `7d8798c341ec36d1`

| Field | Value |
|---|---|
| SHA-256 | `7d8798c341ec36d1f49ccdae248557ad35912c6bb77939c1be22aff9e314daef` |
| Family label | `VShell` |
| File name | `7d8798c341ec36d1f49ccdae248557ad35912c6bb77939c1be22aff9e314daef.exe` |
| File type | `exe` |
| First seen | `2026-10-04 02:20:00` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0db8fcf20a6c4033d717dbc102053d37` |
| SHA-1 | `17708e43445cfa77cd435d455c3d8d31f6b85aa5` |
| SHA-256 | `7d8798c341ec36d1f49ccdae248557ad35912c6bb77939c1be22aff9e314daef` |
| SHA3-384 | `b78f0d83391212eaa53b32cd84ceb3401ef297ac3bdd80f7b65f2e4f3ef645db0ae5e415b94737325283dd5f1321c3e6` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1E591D74170B999E7E85C45BB4C0FB8A0B91D740A41C483B70338A5993E3957BF4BCB0E` |
| SSDEEP | `48:6IIF9BlQaexgAgZS7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMgh70cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_079_7d8798c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d8798c341ec36d1f49ccdae248557ad35912c6bb77939c1be22aff9e314daef"
    family = "VShell"
    file_name = "7d8798c341ec36d1f49ccdae248557ad35912c6bb77939c1be22aff9e314daef.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:20:00"
  condition:
    hash.sha256(0, filesize) == "7d8798c341ec36d1f49ccdae248557ad35912c6bb77939c1be22aff9e314daef"
}
```

### Sample 80: `5aec4cf6d50b41c6`

| Field | Value |
|---|---|
| SHA-256 | `5aec4cf6d50b41c6c3477ff429184fe90d65a5c328ea3ea0ac29c6bed029cf83` |
| Family label | `VShell` |
| File name | `5aec4cf6d50b41c6c3477ff429184fe90d65a5c328ea3ea0ac29c6bed029cf83.exe` |
| File type | `exe` |
| First seen | `2026-10-04 02:19:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31747e1bdeeb47c436baea86d770a043` |
| SHA-1 | `1b54793b297dfcd3eeb02ac945e9b051d8aa264f` |
| SHA-256 | `5aec4cf6d50b41c6c3477ff429184fe90d65a5c328ea3ea0ac29c6bed029cf83` |
| SHA3-384 | `aaaaba96ff48f8f43318563b57fc8c6977b3bcb83a11368e3e2d81f0a68247c611b79bb4df48a9f299cb2aa337dfef13` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T17391D74170B989E7E85C41BB4C0FB8A0B919740A41C4C3A74378A5953E3967BF5BCB0E` |
| SSDEEP | `48:6IIF9BlQaexghgZ57An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMgEO0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_080_5aec4cf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5aec4cf6d50b41c6c3477ff429184fe90d65a5c328ea3ea0ac29c6bed029cf83"
    family = "VShell"
    file_name = "5aec4cf6d50b41c6c3477ff429184fe90d65a5c328ea3ea0ac29c6bed029cf83.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:19:11"
  condition:
    hash.sha256(0, filesize) == "5aec4cf6d50b41c6c3477ff429184fe90d65a5c328ea3ea0ac29c6bed029cf83"
}
```

### Sample 81: `137413a0ab6691e6`

| Field | Value |
|---|---|
| SHA-256 | `137413a0ab6691e6ad52963e078f17a1f7817148ccdf7fa4ce462f49a5fcde25` |
| Family label | `VShell` |
| File name | `137413a0ab6691e6ad52963e078f17a1f7817148ccdf7fa4ce462f49a5fcde25.exe` |
| File type | `exe` |
| First seen | `2026-10-04 02:19:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `328accf876c4235aaa874ee1c6b71852` |
| SHA-1 | `f7e8bccd1a20e0f5c9573110f0eb3f70ecd1e443` |
| SHA-256 | `137413a0ab6691e6ad52963e078f17a1f7817148ccdf7fa4ce462f49a5fcde25` |
| SHA3-384 | `9bc39ed1ad1fa47eb18ad58c85f80975f0c11dde3dfb303138b7b59ec1c2c0199c6b0758f0719a67332f5a9b99de2682` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T13571B58160541AF2D94CE37F8487B895FD5EB248A2C80B0F0398981A2F7507BB0DD613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6Dce8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DceG++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_081_137413a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "137413a0ab6691e6ad52963e078f17a1f7817148ccdf7fa4ce462f49a5fcde25"
    family = "VShell"
    file_name = "137413a0ab6691e6ad52963e078f17a1f7817148ccdf7fa4ce462f49a5fcde25.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:19:01"
  condition:
    hash.sha256(0, filesize) == "137413a0ab6691e6ad52963e078f17a1f7817148ccdf7fa4ce462f49a5fcde25"
}
```

### Sample 82: `54ceeda981e136c0`

| Field | Value |
|---|---|
| SHA-256 | `54ceeda981e136c0a50bdb5b52a6db369b4493d35caec5ff97f0bdea7c76f59a` |
| Family label | `Mirai` |
| File name | `234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03.elf` |
| File type | `elf` |
| First seen | `2026-10-04 02:16:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68dc58c7dae2be34d6527cbc96f2f2d3` |
| SHA-1 | `42d35acee613fd21524722aa8eced4d46cb7292c` |
| SHA-256 | `54ceeda981e136c0a50bdb5b52a6db369b4493d35caec5ff97f0bdea7c76f59a` |
| SHA3-384 | `b8cb643a4ec68c7c163f09495febb5e5fd9ae3132f829c42866d2eef147b54e88a08b61ff4fb2680fc425a8311abb019` |
| TLSH | `T1F0142856FD819F16D5C015BAFE1E528E33131B78E2DE72139E246F34278A8AB0E3B505` |
| TELFHASH | `t15411c012b65d40dc7bf40095c5ebb839ba9d322d37101a1561986f5aed23dc2b137c0b` |
| SSDEEP | `6144:YYNSAwPDMfbvUWMo029l5rTOraHrdtK07a5L9EEhNd9ig7/s:nNSAwPDsbvUa02L5fuAdtb7a55lnd9iH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_54ceeda9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54ceeda981e136c0a50bdb5b52a6db369b4493d35caec5ff97f0bdea7c76f59a"
    family = "Mirai"
    file_name = "234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03.elf"
    file_type = "elf"
    first_seen = "2026-10-04 02:16:25"
  condition:
    hash.sha256(0, filesize) == "54ceeda981e136c0a50bdb5b52a6db369b4493d35caec5ff97f0bdea7c76f59a"
}
```

### Sample 83: `234293ba9ac7b8db`

| Field | Value |
|---|---|
| SHA-256 | `234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03` |
| Family label | `Mirai` |
| File name | `234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03.elf` |
| File type | `elf` |
| First seen | `2026-10-04 02:15:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06eb9e8de90578a7c42bad37c4e35c6a` |
| SHA-1 | `4ef7e3ec43594c40f4ede34d008a859ed9dea34b` |
| SHA-256 | `234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03` |
| SHA3-384 | `b389ec6508600932c35dc2160d0b0f94a2c66dc9f31d5bc3cd9ebc624cd2f7d3c89a65eacd1e6fbd4badb4bb0ea70db1` |
| TLSH | `T19F7302586267B417F4718F3BC8ED0ECCEB4D9A654CEA82692BB197087A08061DCF4987` |
| SSDEEP | `1536:gLTG1eMFvxXPIiIjE4vua4NtuXMbU6mP8aejzKfn6OI69jWKUPLq:wTWeeHUEeg8BHgKfn6OI64PLq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_234293ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03"
    family = "Mirai"
    file_name = "234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03.elf"
    file_type = "elf"
    first_seen = "2026-10-04 02:15:59"
  condition:
    hash.sha256(0, filesize) == "234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03"
}
```

### Sample 84: `d804aeb27389fdd6`

| Field | Value |
|---|---|
| SHA-256 | `d804aeb27389fdd6e09f05dddad69dd381b3f03bbfde5db350e004bcf0895588` |
| Family label | `unknown` |
| File name | `d804aeb27389fdd6e09f05dddad69dd381b3f03bbfde5db350e004bcf0895588.exe` |
| File type | `exe` |
| First seen | `2026-10-04 02:14:58` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fadec974df926a141d16cfc0255c8565` |
| SHA-1 | `7446bb27bb9d40a574848e06d77911560604c5ef` |
| SHA-256 | `d804aeb27389fdd6e09f05dddad69dd381b3f03bbfde5db350e004bcf0895588` |
| SHA3-384 | `c0c3811ce32d56a195f5c1335efed11f5ae4f05675b599088fc45bc85f0a7398c29c96086d80c383fd23304ba568b8ca` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1F63723B7A316922DE47E6878123275A8187FAFECF1620C16C9D4E0BDC72D5B01C2F956` |
| SSDEEP | `393216:QNAKtdul9w9uVgQnbFqgG/I3HP4CKEF0Qav74dyA38mW1CjA6kNqCc3FnAVZmFSz:HK70hVgQnbFq+XP4xEFnM4dd61Cjlicm` |
| ICON-DHASH | `f0e4e6cfc8e8f0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_d804aeb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d804aeb27389fdd6e09f05dddad69dd381b3f03bbfde5db350e004bcf0895588"
    family = "unknown"
    file_name = "d804aeb27389fdd6e09f05dddad69dd381b3f03bbfde5db350e004bcf0895588.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:14:58"
  condition:
    hash.sha256(0, filesize) == "d804aeb27389fdd6e09f05dddad69dd381b3f03bbfde5db350e004bcf0895588"
}
```

### Sample 85: `e551441fb55d5180`

| Field | Value |
|---|---|
| SHA-256 | `e551441fb55d5180732d26c2532bb82bde588e970e7bb77e0d0ea86b52bb219d` |
| Family label | `Mirai` |
| File name | `177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e.elf` |
| File type | `elf` |
| First seen | `2026-10-04 02:14:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `303afe4afc45b5fca5a7ed77ffed80cf` |
| SHA-1 | `2d21fa026fafce53cc02ba23a41574cbc3a0b276` |
| SHA-256 | `e551441fb55d5180732d26c2532bb82bde588e970e7bb77e0d0ea86b52bb219d` |
| SHA3-384 | `b30d2c9d5e87e901d679aaca73cb40eb63f617a269fe1026f98c25cb8592a89e812dc62108b09cf7e7e2ef626da8b711` |
| TLSH | `T176144C01B71D0943E2A32EF0373B27D1D3DF9AA125F5EA442A0EBB859271D325585ECE` |
| SSDEEP | `3072:HLddK6idekCRCUnaXxXG5bDv1i4OfsDhXojkqlpHwo:HLddLoxAbDv1i4OfKhXpo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_e551441f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e551441fb55d5180732d26c2532bb82bde588e970e7bb77e0d0ea86b52bb219d"
    family = "Mirai"
    file_name = "177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e.elf"
    file_type = "elf"
    first_seen = "2026-10-04 02:14:22"
  condition:
    hash.sha256(0, filesize) == "e551441fb55d5180732d26c2532bb82bde588e970e7bb77e0d0ea86b52bb219d"
}
```

### Sample 86: `7e99e051cc6a925d`

| Field | Value |
|---|---|
| SHA-256 | `7e99e051cc6a925d1a860d36c332bf8095907823b6bddf5d21ae755e3568defc` |
| Family label | `unknown` |
| File name | `7e99e051cc6a925d1a860d36c332bf8095907823b6bddf5d21ae755e3568defc.bin` |
| File type | `zip` |
| First seen | `2026-10-04 02:13:46` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `284783bce2882423de458e2989a502a9` |
| SHA-1 | `9d798150f8268f367c9aa7a2bf5a2dde07b0376e` |
| SHA-256 | `7e99e051cc6a925d1a860d36c332bf8095907823b6bddf5d21ae755e3568defc` |
| SHA3-384 | `9e86e0f5a41adc29916d4e34db82f169dca3f54815f26ab5d1fc58e74eefa31a2f8e1b06aeb781c1b3b009c10e138896` |
| TLSH | `T1DCA63326F48B282DBBF7B3101A181D4F97F5615AB65A23768CC6097C8CEB77191A02C7` |
| SSDEEP | `196608:TvbaGMlwmaLOPlYYmvkZj8FjZTHIjvkM21pa1WAy4Fk3ou7:Tv2xymaq9/mvkZjQdTHyp21QWAy73ou7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_7e99e051
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e99e051cc6a925d1a860d36c332bf8095907823b6bddf5d21ae755e3568defc"
    family = "unknown"
    file_name = "7e99e051cc6a925d1a860d36c332bf8095907823b6bddf5d21ae755e3568defc.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:13:46"
  condition:
    hash.sha256(0, filesize) == "7e99e051cc6a925d1a860d36c332bf8095907823b6bddf5d21ae755e3568defc"
}
```

### Sample 87: `2b462d51032bd76e`

| Field | Value |
|---|---|
| SHA-256 | `2b462d51032bd76e4f2f9498546e1f18e1510af71231dabf34ac3d5b40a4743c` |
| Family label | `unknown` |
| File name | `2b462d51032bd76e4f2f9498546e1f18e1510af71231dabf34ac3d5b40a4743c.msi` |
| File type | `msi` |
| First seen | `2026-10-04 02:13:40` |
| Reporter | `Tuxxin` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b4c09ecdcef26e6ba014c50162343fb` |
| SHA-1 | `408e55ecafaa2691cd9f5567256dcdec53c7b711` |
| SHA-256 | `2b462d51032bd76e4f2f9498546e1f18e1510af71231dabf34ac3d5b40a4743c` |
| SHA3-384 | `635063245ec1952867a7ded3c61f81246088a348713d75ace0e31683ef7754f5cdc9ed8f0835d9cf3ee4f22dfc4bda8c` |
| TLSH | `T178761221B58E8C35D69A353076359EBEDA38BC345B948BCB938339ED19312C092FD752` |
| SSDEEP | `98304:lqkMMwpD74kF+tyzKgQY0VUKOAj45vvC0eiWctSTNQaJu61VpLpZqtyra4V9eFvt:lvlc4kF+sKgQY3i85vV5tyNJu6BNow3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_2b462d51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b462d51032bd76e4f2f9498546e1f18e1510af71231dabf34ac3d5b40a4743c"
    family = "unknown"
    file_name = "2b462d51032bd76e4f2f9498546e1f18e1510af71231dabf34ac3d5b40a4743c.msi"
    file_type = "msi"
    first_seen = "2026-10-04 02:13:40"
  condition:
    hash.sha256(0, filesize) == "2b462d51032bd76e4f2f9498546e1f18e1510af71231dabf34ac3d5b40a4743c"
}
```

### Sample 88: `326b416caa382326`

| Field | Value |
|---|---|
| SHA-256 | `326b416caa382326e010473e54deb977d69ef1931fa79c32eab4553e887dda1d` |
| Family label | `unknown` |
| File name | `326b416caa382326e010473e54deb977d69ef1931fa79c32eab4553e887dda1d.exe` |
| File type | `exe` |
| First seen | `2026-10-04 02:13:34` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39df579bc3ea833559d5645c46f23a8a` |
| SHA-1 | `35dcacdde6a979f3f48f87814b4abc22034b6489` |
| SHA-256 | `326b416caa382326e010473e54deb977d69ef1931fa79c32eab4553e887dda1d` |
| SHA3-384 | `3767a7add9355a344e3e2869cf9b689f6ea735a00b5fd6757a290e0dbedcfef5daccd8d86783253f2b7a7e64a9886d90` |
| IMPHASH | `2fb819a19fe4dee5c03e8c6a79342f79` |
| TLSH | `T1B9D6334D6EA8C8E9DCF13DB41864898535CE3E87891D2677342E90CCE3DD8B5ADB84C6` |
| SSDEEP | `393216:dtsPIH0FDtu9PyuELQ5QeGsCK49MkqD2o1Q:HAu0FYquEZjY49MdCo1Q` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_326b416c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "326b416caa382326e010473e54deb977d69ef1931fa79c32eab4553e887dda1d"
    family = "unknown"
    file_name = "326b416caa382326e010473e54deb977d69ef1931fa79c32eab4553e887dda1d.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:13:34"
  condition:
    hash.sha256(0, filesize) == "326b416caa382326e010473e54deb977d69ef1931fa79c32eab4553e887dda1d"
}
```

### Sample 89: `177b7520a042e73d`

| Field | Value |
|---|---|
| SHA-256 | `177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e` |
| Family label | `Mirai` |
| File name | `177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e.elf` |
| File type | `elf` |
| First seen | `2026-10-04 02:13:26` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b755452be7f3003ba387a789d84094f` |
| SHA-1 | `41fa705879f0da533bdd8b3df4a3c4a43fa96426` |
| SHA-256 | `177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e` |
| SHA3-384 | `1961c35abd205b7a61c78f1a8daeafd0a337fed83a8df3eef529ad07da2b9d107b432079246692a2315086f26ce659f5` |
| TLSH | `T17C730269D2D0E4A2EE5FB8FB90679A0559900DB47F81DAC513E0FFD1B827816A4387C1` |
| SSDEEP | `1536:Di3BS6WOb545dDJjhyCjtRy4vEP2KQZHjo14u+qgw09t:mpWCclTNjtRy2EP2K4814u+qgwU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_177b7520
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e"
    family = "Mirai"
    file_name = "177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e.elf"
    file_type = "elf"
    first_seen = "2026-10-04 02:13:26"
  condition:
    hash.sha256(0, filesize) == "177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e"
}
```

### Sample 90: `dc5abf20ae0c61cb`

| Field | Value |
|---|---|
| SHA-256 | `dc5abf20ae0c61cb9de2ca80055d369872ef9b6be35fa7ebec386e42e445d13a` |
| Family label | `njrat` |
| File name | `A5F2E89D8926046FB4DE161C78F79B6B.exe` |
| File type | `exe` |
| First seen | `2026-10-04 01:55:08` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5f2e89d8926046fb4de161c78f79b6b` |
| SHA-1 | `80324667cd1ac1f679f28e51a5954c8dae255a6b` |
| SHA-256 | `dc5abf20ae0c61cb9de2ca80055d369872ef9b6be35fa7ebec386e42e445d13a` |
| SHA3-384 | `dbd1f4d5f928291a54aae38e55976a0fedd085ac10d34c5bf2722606685a0fa2b7ea0fd3a0e98c1d50347694079cf44f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T164B21A4E3FA98856C5AC1B74CAB5965003B491470413EE2FCDC560CBABB3AD92D4CEF9` |
| SSDEEP | `384:2c68yCasVKDh3OQyNpsQ1im/VjJs+PyR46vg5J++p57nhmRvR6JZlbw8hqIusZzV:0873Kt+QesGN/VjZPQRpcnus` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_090_dc5abf20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc5abf20ae0c61cb9de2ca80055d369872ef9b6be35fa7ebec386e42e445d13a"
    family = "njrat"
    file_name = "A5F2E89D8926046FB4DE161C78F79B6B.exe"
    file_type = "exe"
    first_seen = "2026-10-04 01:55:08"
  condition:
    hash.sha256(0, filesize) == "dc5abf20ae0c61cb9de2ca80055d369872ef9b6be35fa7ebec386e42e445d13a"
}
```

### Sample 91: `fb7712e35e097c3e`

| Field | Value |
|---|---|
| SHA-256 | `fb7712e35e097c3e6f8f2c1c3e7a6a777290c6df04dfb340c78c75cf33c15606` |
| Family label | `unknown` |
| File name | `fb7712e35e097c3e6f8f2c1c3e7a6a777290c6df04dfb340c78c75cf33c15606.exe` |
| File type | `exe` |
| First seen | `2026-10-04 01:48:33` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e4bfad81a03e1131fd3d3388fb92971` |
| SHA-1 | `ce1c03810bbca23835e6abca23518352b6aabf00` |
| SHA-256 | `fb7712e35e097c3e6f8f2c1c3e7a6a777290c6df04dfb340c78c75cf33c15606` |
| SHA3-384 | `7a4b37a5ce5bbd5ebca0696a150efce247a98c6272f4cea228ccf5765d1a15c1ba78cb8fccd2a51e8285d1cc81c35c24` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T11D56123BB34B653EE5BA26363573A211943B6A1158528C17DAF8948CCF363701E3F687` |
| SSDEEP | `98304:CAt3V/QvifvskbcuKs3qV9ESqmhsljvH4oRsjB4737CXkELcs67J:CAnQv0EqcuB3qDq/xf4QGS7CXv56d` |
| ICON-DHASH | `c003d4d4cccce08e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_fb7712e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb7712e35e097c3e6f8f2c1c3e7a6a777290c6df04dfb340c78c75cf33c15606"
    family = "unknown"
    file_name = "fb7712e35e097c3e6f8f2c1c3e7a6a777290c6df04dfb340c78c75cf33c15606.exe"
    file_type = "exe"
    first_seen = "2026-10-04 01:48:33"
  condition:
    hash.sha256(0, filesize) == "fb7712e35e097c3e6f8f2c1c3e7a6a777290c6df04dfb340c78c75cf33c15606"
}
```

### Sample 92: `044ef3d12efbac04`

| Field | Value |
|---|---|
| SHA-256 | `044ef3d12efbac04a7dbdd40f4e51cd2cdc9c077b0d5d3cb571a2562a74bf9c4` |
| Family label | `unknown` |
| File name | `044ef3d12efbac04a7dbdd40f4e51cd2cdc9c077b0d5d3cb571a2562a74bf9c4.exe` |
| File type | `exe` |
| First seen | `2026-10-04 01:44:15` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c980e5175e8dfd51144181904d7ba33` |
| SHA-1 | `561bb088072fde29c3d2e0b3acc47970423128a5` |
| SHA-256 | `044ef3d12efbac04a7dbdd40f4e51cd2cdc9c077b0d5d3cb571a2562a74bf9c4` |
| SHA3-384 | `4d48d1c8596e58580537e8ce3d3df3d824d22e7fad6b9265fa389743665a88647eb572206cc5e3886db8a09c72a10049` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T102F6333FB28B653DE06D1A3636B2D614543BAE61A5434C16EAF4C84CCF294B01E3FB56` |
| SSDEEP | `393216:L6SGYGqZ5W6r/12hdDgHF+X/k+/cGPB0v+vQo3irXfQ:WSGiWU2PYF+XcucGPCv+PizfQ` |
| ICON-DHASH | `b2f450b296f07010` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_044ef3d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "044ef3d12efbac04a7dbdd40f4e51cd2cdc9c077b0d5d3cb571a2562a74bf9c4"
    family = "unknown"
    file_name = "044ef3d12efbac04a7dbdd40f4e51cd2cdc9c077b0d5d3cb571a2562a74bf9c4.exe"
    file_type = "exe"
    first_seen = "2026-10-04 01:44:15"
  condition:
    hash.sha256(0, filesize) == "044ef3d12efbac04a7dbdd40f4e51cd2cdc9c077b0d5d3cb571a2562a74bf9c4"
}
```

### Sample 93: `2eb07e1b60960bc0`

| Field | Value |
|---|---|
| SHA-256 | `2eb07e1b60960bc08205065a3ca610fbb7dfad5a8710a85cd40e3e7baaa190e6` |
| Family label | `Mirai` |
| File name | `2eb07e1b60960bc08205065a3ca610fbb7dfad5a8710a85cd40e3e7baaa190e6.elf` |
| File type | `elf` |
| First seen | `2026-10-04 01:36:12` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f789647e6c54f8e111134478a63fbdd` |
| SHA-1 | `b4fe3868c3249dedb015a34819b4832bf9f7f88d` |
| SHA-256 | `2eb07e1b60960bc08205065a3ca610fbb7dfad5a8710a85cd40e3e7baaa190e6` |
| SHA3-384 | `ffd7bef047ee05ace9c9e35442c31f962a5ae9709353b768fab4370468d35077419ed1dad687295f34dab14118da7cf7` |
| TLSH | `T121D45D66BC919B90C5D149BEFB6E437C72035B79E2EFB106DA045FA06BC98950F3E201` |
| SSDEEP | `12288:b5EHetA8FO+SujwNDGB2a+fSBaLUJ5zexcj1T:bEQw5LkSLxcj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_2eb07e1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2eb07e1b60960bc08205065a3ca610fbb7dfad5a8710a85cd40e3e7baaa190e6"
    family = "Mirai"
    file_name = "2eb07e1b60960bc08205065a3ca610fbb7dfad5a8710a85cd40e3e7baaa190e6.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:36:12"
  condition:
    hash.sha256(0, filesize) == "2eb07e1b60960bc08205065a3ca610fbb7dfad5a8710a85cd40e3e7baaa190e6"
}
```

### Sample 94: `05e9766f9225f3ae`

| Field | Value |
|---|---|
| SHA-256 | `05e9766f9225f3ae130e9b90832c4a0a5fef3dc07eed7e5095a084f92b9f391b` |
| Family label | `Mirai` |
| File name | `05e9766f9225f3ae130e9b90832c4a0a5fef3dc07eed7e5095a084f92b9f391b.elf` |
| File type | `elf` |
| First seen | `2026-10-04 01:36:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `951b720e4973ed37fbe8ef21c82cb4ee` |
| SHA-1 | `08a915e591c2317130ba0d393b95430173edc7d6` |
| SHA-256 | `05e9766f9225f3ae130e9b90832c4a0a5fef3dc07eed7e5095a084f92b9f391b` |
| SHA3-384 | `4301de509796881d2ae8babc3ea61fda54ec7f033a45b85d9a5485fb204f49e3132715786da37cea78d6b8b56efed8f4` |
| TLSH | `T1CC05F65B2E329F3EF579C6308BF34B74969962C727E1C588E19CD20D1E2024A651F7AC` |
| TELFHASH | `t10aa109a9197803b4bb545c4d45dcef26d9a338ef3e161c239e51e86d971fa839e10c1c` |
| SSDEEP | `6144:MAykaTfQ1ddnRZS0uArO4fIlm0tcOwwcMNVk4Jo3fkY7ULTJ+MbPXSMuxk2Nq2Zf:OdzGrRoxiTq2QLUbimxyuOza` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_05e9766f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05e9766f9225f3ae130e9b90832c4a0a5fef3dc07eed7e5095a084f92b9f391b"
    family = "Mirai"
    file_name = "05e9766f9225f3ae130e9b90832c4a0a5fef3dc07eed7e5095a084f92b9f391b.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:36:07"
  condition:
    hash.sha256(0, filesize) == "05e9766f9225f3ae130e9b90832c4a0a5fef3dc07eed7e5095a084f92b9f391b"
}
```

### Sample 95: `6848afee7a2461d9`

| Field | Value |
|---|---|
| SHA-256 | `6848afee7a2461d9a4d0fef7ef3874f3cba44e308eb5da416d705fa1ef699a62` |
| Family label | `Mirai` |
| File name | `6848afee7a2461d9a4d0fef7ef3874f3cba44e308eb5da416d705fa1ef699a62.elf` |
| File type | `elf` |
| First seen | `2026-10-04 01:35:23` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `044583baff54a3d303bada925b3982ac` |
| SHA-1 | `a477642d572dc6b34553a36e9db87bbc4919b8aa` |
| SHA-256 | `6848afee7a2461d9a4d0fef7ef3874f3cba44e308eb5da416d705fa1ef699a62` |
| SHA3-384 | `0a608212257742046443640e498f94e9dd694ad24bc8f45f40bc20a9d7b78919ffcc5e2b7838b28128459230b0198f17` |
| TLSH | `T1F7C48C239D766F95C4B7C1B4B4B08B780F42A89642EB6EADD5A2CDD58447CC0F22C3B5` |
| SSDEEP | `6144:uGryYVkebyIf2copdCgCY9BEN4uwjyw1WR+0z3iIzahUfTx623f0O9bqEBCxZ:lVqebJ+NBgsywQ+wE6fTx6ucOhBaZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_6848afee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6848afee7a2461d9a4d0fef7ef3874f3cba44e308eb5da416d705fa1ef699a62"
    family = "Mirai"
    file_name = "6848afee7a2461d9a4d0fef7ef3874f3cba44e308eb5da416d705fa1ef699a62.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:35:23"
  condition:
    hash.sha256(0, filesize) == "6848afee7a2461d9a4d0fef7ef3874f3cba44e308eb5da416d705fa1ef699a62"
}
```

### Sample 96: `1bd6853b1074402e`

| Field | Value |
|---|---|
| SHA-256 | `1bd6853b1074402ecb04a5ffb1abbb57e0c95ed83171526c0413d70d88ed74a5` |
| Family label | `Mirai` |
| File name | `1bd6853b1074402ecb04a5ffb1abbb57e0c95ed83171526c0413d70d88ed74a5.elf` |
| File type | `elf` |
| First seen | `2026-10-04 01:35:16` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03f6c43c15479720106ebb0e42730c51` |
| SHA-1 | `408d0e0281292657af8c92918b799f2531f4cfc1` |
| SHA-256 | `1bd6853b1074402ecb04a5ffb1abbb57e0c95ed83171526c0413d70d88ed74a5` |
| SHA3-384 | `3ce2d02e8ec978ea524096634d72ef16d3e359cf47ef0228a044c23f739fbe64a74bbe726d95404aabe05d10328358d3` |
| TLSH | `T15BD47E87BAA0DDFEF896D33644130A256020F6E251E29B2FE15F7D94DF2D0902539BC6` |
| SSDEEP | `6144:+qTy9jTWBr9FNY2VaIK1uwinyvj48WEDAlTbKTjJ8ywI+gcOB5W8BVofLCdtAywG:+HPWtptKxiyvU8YAS8Pd6ywcc2dGK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_1bd6853b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bd6853b1074402ecb04a5ffb1abbb57e0c95ed83171526c0413d70d88ed74a5"
    family = "Mirai"
    file_name = "1bd6853b1074402ecb04a5ffb1abbb57e0c95ed83171526c0413d70d88ed74a5.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:35:16"
  condition:
    hash.sha256(0, filesize) == "1bd6853b1074402ecb04a5ffb1abbb57e0c95ed83171526c0413d70d88ed74a5"
}
```

### Sample 97: `08dec15e72a6c327`

| Field | Value |
|---|---|
| SHA-256 | `08dec15e72a6c327ad91bd773f35b0d17bdf320bda1be6ca3398b99366b0e6cc` |
| Family label | `Mirai` |
| File name | `08dec15e72a6c327ad91bd773f35b0d17bdf320bda1be6ca3398b99366b0e6cc.elf` |
| File type | `elf` |
| First seen | `2026-10-04 01:35:11` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1de598012ba796f019290901338e7f3` |
| SHA-1 | `f1d16d170f5b84d326453a6ae16a5428958b1f7b` |
| SHA-256 | `08dec15e72a6c327ad91bd773f35b0d17bdf320bda1be6ca3398b99366b0e6cc` |
| SHA3-384 | `72d44963801fc414af0f704fdd4b9d976ca7436b7889fbea9b5fa56a98257261586fdafae180032a66257e27f24e7fa5` |
| TLSH | `T1F2D46C56BD919B91C6D24ABBFBAE4368731357BDD2FF7006CA045F903BDA4810A3E241` |
| TELFHASH | `t154f002708f0414c933988765f6d9362c65b5e0bb3e82fcb71b45ad4acef184e7155a1c` |
| SSDEEP | `12288:AaV22zUbKBpbsYliTKMJQv/i0obPSlfeXAXgyhToe:nV22sebsYliTKMJQvZnfVT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_08dec15e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08dec15e72a6c327ad91bd773f35b0d17bdf320bda1be6ca3398b99366b0e6cc"
    family = "Mirai"
    file_name = "08dec15e72a6c327ad91bd773f35b0d17bdf320bda1be6ca3398b99366b0e6cc.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:35:11"
  condition:
    hash.sha256(0, filesize) == "08dec15e72a6c327ad91bd773f35b0d17bdf320bda1be6ca3398b99366b0e6cc"
}
```

### Sample 98: `4217d66857f58ae9`

| Field | Value |
|---|---|
| SHA-256 | `4217d66857f58ae98fec169b21366f81da342d8b54f11d4def15a4ed74eae595` |
| Family label | `Mirai` |
| File name | `4217d66857f58ae98fec169b21366f81da342d8b54f11d4def15a4ed74eae595.elf` |
| File type | `elf` |
| First seen | `2026-10-04 01:35:05` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54b0506cc008d9d693350668779d892b` |
| SHA-1 | `94894b1ce21ac71699849b82f5a10e92f1f45f13` |
| SHA-256 | `4217d66857f58ae98fec169b21366f81da342d8b54f11d4def15a4ed74eae595` |
| SHA3-384 | `9f528a5958fea13f97737a09abef366c38a2cd1cfb404638f7ecc1c7cefedfdf19ec1ee9586872c64c60a8e894e1a4f4` |
| TLSH | `T137D43A03272D0F83D3A75DF0777717F487DAA89621F5E588EA0B69C69271870228D6CE` |
| SSDEEP | `6144:jnKBeCZXIzdmxks7O1xs4DpDnXASIlo/2MlbPnuWi8wjONDHtw77xv8kXJTINSiB:jKBeCWzQd8l5U7tZTI0ituPG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_4217d668
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4217d66857f58ae98fec169b21366f81da342d8b54f11d4def15a4ed74eae595"
    family = "Mirai"
    file_name = "4217d66857f58ae98fec169b21366f81da342d8b54f11d4def15a4ed74eae595.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:35:05"
  condition:
    hash.sha256(0, filesize) == "4217d66857f58ae98fec169b21366f81da342d8b54f11d4def15a4ed74eae595"
}
```

### Sample 99: `d618d9eddfd3150d`

| Field | Value |
|---|---|
| SHA-256 | `d618d9eddfd3150d8f05225bafdeaf8a321e57ab592fa2d5d0ace55edd0341e0` |
| Family label | `Mirai` |
| File name | `d618d9eddfd3150d8f05225bafdeaf8a321e57ab592fa2d5d0ace55edd0341e0.elf` |
| File type | `elf` |
| First seen | `2026-10-04 01:33:52` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f28e96da5d8930303c54d65a3be9d854` |
| SHA-1 | `cf53a39035e3a58ebf93ff588dd93683c7065951` |
| SHA-256 | `d618d9eddfd3150d8f05225bafdeaf8a321e57ab592fa2d5d0ace55edd0341e0` |
| SHA3-384 | `9de26706255d36d5a87e01228d5b36d60267900edb2efce4685cfa9380ae4b8f1405e9930326555d6cdf0f0a56e040ba` |
| TLSH | `T1C4D44B032B2D0B83E3D74CF0777707F4879A985620F9E589EA0AADC69771870625E5CE` |
| SSDEEP | `6144:aykx/NsbA8udlEApZZIlZtDnYMWwlo/Pgmtt+4qX86IpyKGUI5Sx3CVD8+mQwws5:ax/NBdlEcgxm2P8kwa8+mIsUuvJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_d618d9ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d618d9eddfd3150d8f05225bafdeaf8a321e57ab592fa2d5d0ace55edd0341e0"
    family = "Mirai"
    file_name = "d618d9eddfd3150d8f05225bafdeaf8a321e57ab592fa2d5d0ace55edd0341e0.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:33:52"
  condition:
    hash.sha256(0, filesize) == "d618d9eddfd3150d8f05225bafdeaf8a321e57ab592fa2d5d0ace55edd0341e0"
}
```

### Sample 100: `af4c0ebc6170961d`

| Field | Value |
|---|---|
| SHA-256 | `af4c0ebc6170961d5d42bad15599bf48353bb9c5276366581c210eebc7878747` |
| Family label | `Mirai` |
| File name | `af4c0ebc6170961d5d42bad15599bf48353bb9c5276366581c210eebc7878747.elf` |
| File type | `elf` |
| First seen | `2026-10-04 01:33:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e8b5d284c6cbfb0911ace50b043d260` |
| SHA-1 | `30b959178753fe92bc0a6cffcf7620b988a51457` |
| SHA-256 | `af4c0ebc6170961d5d42bad15599bf48353bb9c5276366581c210eebc7878747` |
| SHA3-384 | `553b479808e1429f9b7d3f5620fb42a992c33193eebbfffd3547e259d20db93ab843fb10e61eea58b25153c711e3137c` |
| TLSH | `T1DBD46C16BD919B91C6E24ABBFBAE4368731757BDD2FF7006C9045F903BDA4810A3E241` |
| TELFHASH | `t114f0dd508e4044e263e68185e19d7729b691e9bf3d49e8b701b4bf8fc4e3c0e7026d6c` |
| SSDEEP | `12288:RJl0Qso0hQTnfcslwVaEJqvZ5NXBtc78M6ANjIYjeHquBe:vl0QMSfcslwVaEJqvRM87tqu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_af4c0ebc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af4c0ebc6170961d5d42bad15599bf48353bb9c5276366581c210eebc7878747"
    family = "Mirai"
    file_name = "af4c0ebc6170961d5d42bad15599bf48353bb9c5276366581c210eebc7878747.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:33:47"
  condition:
    hash.sha256(0, filesize) == "af4c0ebc6170961d5d42bad15599bf48353bb9c5276366581c210eebc7878747"
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
 * Generated: 2026-10-04T06:01:41.581717+00:00
 */

rule MalwareBazaar_unknown_001_02056205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "020562055a7854f8dac64b0e50e8befb6dc238da70bdaca0a1bd77f802a1b815"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-04 05:55:25"
  condition:
    hash.sha256(0, filesize) == "020562055a7854f8dac64b0e50e8befb6dc238da70bdaca0a1bd77f802a1b815"
}

rule MalwareBazaar_Mirai_002_6f272c85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f272c85365a1783eedbf7bc80112db52d13bca5415703df127b869b23bc179f"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-04 05:55:22"
  condition:
    hash.sha256(0, filesize) == "6f272c85365a1783eedbf7bc80112db52d13bca5415703df127b869b23bc179f"
}

rule MalwareBazaar_unknown_003_3a62981c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a62981cefd10b2f552ad81e90397160f0b986ae09ad711738cb903d82a0db2a"
    family = "unknown"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-04 05:50:13"
  condition:
    hash.sha256(0, filesize) == "3a62981cefd10b2f552ad81e90397160f0b986ae09ad711738cb903d82a0db2a"
}

rule MalwareBazaar_unknown_004_413f1b95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "413f1b952a7422b8f69418117d1dca5c2898320dd33a89a2ed286afc3c181ffc"
    family = "unknown"
    file_name = "413f1b952a7422b8.bin"
    file_type = "exe"
    first_seen = "2026-10-04 05:25:22"
  condition:
    hash.sha256(0, filesize) == "413f1b952a7422b8f69418117d1dca5c2898320dd33a89a2ed286afc3c181ffc"
}

rule MalwareBazaar_unknown_005_7b770db5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b770db576c2f2b2faccff016c1814d80aa4833c075fefc14a093380fa89bc81"
    family = "unknown"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-10-04 05:23:48"
  condition:
    hash.sha256(0, filesize) == "7b770db576c2f2b2faccff016c1814d80aa4833c075fefc14a093380fa89bc81"
}

rule MalwareBazaar_unknown_006_cab68c74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab68c74edbe1f8c79780c709701eca52fe1c711240d3cde2d186e6062ca28a7"
    family = "unknown"
    file_name = "cab68c74edbe1f8c79780c709701eca52fe1c711240d3cde2d186e6062ca28a7.exe"
    file_type = "exe"
    first_seen = "2026-10-04 05:23:31"
  condition:
    hash.sha256(0, filesize) == "cab68c74edbe1f8c79780c709701eca52fe1c711240d3cde2d186e6062ca28a7"
}

rule MalwareBazaar_Mirai_007_c34d30c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c34d30c61d5845ac1c62a2e248bf62afb0c2531eb6c140abeea7e6d594dc7449"
    family = "Mirai"
    file_name = "c34d30c61d5845ac1c62a2e248bf62afb0c2531eb6c140abeea7e6d594dc7449"
    file_type = "elf"
    first_seen = "2026-10-04 05:17:16"
  condition:
    hash.sha256(0, filesize) == "c34d30c61d5845ac1c62a2e248bf62afb0c2531eb6c140abeea7e6d594dc7449"
}

rule MalwareBazaar_Mirai_008_5c15f8bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c15f8bfcc4d913e925f7504233f29b682820fcec3a3cdfc8225d19944ff4bf5"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-04 05:09:26"
  condition:
    hash.sha256(0, filesize) == "5c15f8bfcc4d913e925f7504233f29b682820fcec3a3cdfc8225d19944ff4bf5"
}

rule MalwareBazaar_Mirai_009_6188fff7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6188fff75bb18c6d61df6b9378542de07cbe01da1c162a5cc6ab6c5130b84457"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-04 05:08:48"
  condition:
    hash.sha256(0, filesize) == "6188fff75bb18c6d61df6b9378542de07cbe01da1c162a5cc6ab6c5130b84457"
}

rule MalwareBazaar_VShell_010_1fee1a85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fee1a85a3ed0c8b58f6c7eca67936f89a437a85ace95c5017992f853117d1b7"
    family = "VShell"
    file_name = "1fee1a85a3ed0c8b58f6c7eca67936f89a437a85ace95c5017992f853117d1b7.exe"
    file_type = "exe"
    first_seen = "2026-10-04 05:05:20"
  condition:
    hash.sha256(0, filesize) == "1fee1a85a3ed0c8b58f6c7eca67936f89a437a85ace95c5017992f853117d1b7"
}

rule MalwareBazaar_unknown_011_0acd3c89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0acd3c8901dabc919df29bcf58c70b29b4718d4b0c52538ab309d6582c0da1d1"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-10-04 05:03:57"
  condition:
    hash.sha256(0, filesize) == "0acd3c8901dabc919df29bcf58c70b29b4718d4b0c52538ab309d6582c0da1d1"
}

rule MalwareBazaar_unknown_012_8ffb027c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ffb027ce4db2ef73388d63a5c821e2e5f5b9389264dd01db034f688f7734b3c"
    family = "unknown"
    file_name = "8ffb027ce4db2ef73388d63a5c821e2e5f5b9389264dd01db034f688f7734b3c.exe"
    file_type = "exe"
    first_seen = "2026-10-04 05:03:34"
  condition:
    hash.sha256(0, filesize) == "8ffb027ce4db2ef73388d63a5c821e2e5f5b9389264dd01db034f688f7734b3c"
}

rule MalwareBazaar_Mirai_013_92a28239
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92a2823956dc536c90228d54ffcf6c89d05c6c25e3746029eecb364a6d5a18f0"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-10-04 04:59:19"
  condition:
    hash.sha256(0, filesize) == "92a2823956dc536c90228d54ffcf6c89d05c6c25e3746029eecb364a6d5a18f0"
}

rule MalwareBazaar_Mirai_014_57234a9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57234a9b103f3637891e9c54a5b78c04bcc56092b05db7418b4bb433be4dd11e"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-10-04 04:58:44"
  condition:
    hash.sha256(0, filesize) == "57234a9b103f3637891e9c54a5b78c04bcc56092b05db7418b4bb433be4dd11e"
}

rule MalwareBazaar_unknown_015_20a73440
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20a73440b9ebfb5545dd0019a19b661b1c6aef5219901f034d1be9d251e5f4de"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-04 04:58:41"
  condition:
    hash.sha256(0, filesize) == "20a73440b9ebfb5545dd0019a19b661b1c6aef5219901f034d1be9d251e5f4de"
}

rule MalwareBazaar_unknown_016_84b59ccb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84b59ccb6d604bee4e04706d70260ea57fca1408a892af95c4c86190414e2eb0"
    family = "unknown"
    file_name = "cnc"
    file_type = "elf"
    first_seen = "2026-10-04 04:58:37"
  condition:
    hash.sha256(0, filesize) == "84b59ccb6d604bee4e04706d70260ea57fca1408a892af95c4c86190414e2eb0"
}

rule MalwareBazaar_unknown_017_18b0bf99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18b0bf993cf38b1585611b0d3424741955ac76a5d91ca0fa389accbeddce9b50"
    family = "unknown"
    file_name = "zswap_shrinkd"
    file_type = "elf"
    first_seen = "2026-10-04 04:34:58"
  condition:
    hash.sha256(0, filesize) == "18b0bf993cf38b1585611b0d3424741955ac76a5d91ca0fa389accbeddce9b50"
}

rule MalwareBazaar_unknown_018_57ae15c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57ae15c4725f1c6640905d816160069b6adb3f2b8751087590fe54db235de90e"
    family = "unknown"
    file_name = "rcuop_0"
    file_type = "elf"
    first_seen = "2026-10-04 04:34:52"
  condition:
    hash.sha256(0, filesize) == "57ae15c4725f1c6640905d816160069b6adb3f2b8751087590fe54db235de90e"
}

rule MalwareBazaar_unknown_019_eead4ced
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eead4ced63cc53508d205537583eca3ed32ac2aba488ff55d4ff2153b645d350"
    family = "unknown"
    file_name = "kblockd0"
    file_type = "elf"
    first_seen = "2026-10-04 04:34:46"
  condition:
    hash.sha256(0, filesize) == "eead4ced63cc53508d205537583eca3ed32ac2aba488ff55d4ff2153b645d350"
}

rule MalwareBazaar_unknown_020_c8ef73f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8ef73f41b3a1e5c876c03e0447ac52ba39e5457b37fa2098398a1d80b5526e4"
    family = "unknown"
    file_name = "kswapd0"
    file_type = "elf"
    first_seen = "2026-10-04 04:34:40"
  condition:
    hash.sha256(0, filesize) == "c8ef73f41b3a1e5c876c03e0447ac52ba39e5457b37fa2098398a1d80b5526e4"
}

rule MalwareBazaar_unknown_021_96b288aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96b288aac49d0adc66a3de8855a0f699cb89a02b6861b67fb59ff0ccd8ef15fd"
    family = "unknown"
    file_name = "ecryptfsd"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:52"
  condition:
    hash.sha256(0, filesize) == "96b288aac49d0adc66a3de8855a0f699cb89a02b6861b67fb59ff0ccd8ef15fd"
}

rule MalwareBazaar_unknown_022_f4107a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4107a863ce5d1ae604ec953b5b6c9d3b2f125fc735038bd1a819164d4bf4c5d"
    family = "unknown"
    file_name = "jbd2_sda1d"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:46"
  condition:
    hash.sha256(0, filesize) == "f4107a863ce5d1ae604ec953b5b6c9d3b2f125fc735038bd1a819164d4bf4c5d"
}

rule MalwareBazaar_unknown_023_13c785cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13c785cd920375e8e60553d7597c1bca0690335d50f6663f150303770adb5205"
    family = "unknown"
    file_name = "scsi_tmf_0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:45"
  condition:
    hash.sha256(0, filesize) == "13c785cd920375e8e60553d7597c1bca0690335d50f6663f150303770adb5205"
}

rule MalwareBazaar_unknown_024_a28d6504
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a28d65048de7b3273d86f50a67f709fdde9646dc808ec82bff0f53a13de23ee0"
    family = "unknown"
    file_name = "devfreq_wq"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:40"
  condition:
    hash.sha256(0, filesize) == "a28d65048de7b3273d86f50a67f709fdde9646dc808ec82bff0f53a13de23ee0"
}

rule MalwareBazaar_unknown_025_91968f35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91968f3511b0ce31fc4a13896883790ef4e0371ba229b4c7f5ee696d65286607"
    family = "unknown"
    file_name = "xfsaild_sda"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:38"
  condition:
    hash.sha256(0, filesize) == "91968f3511b0ce31fc4a13896883790ef4e0371ba229b4c7f5ee696d65286607"
}

rule MalwareBazaar_unknown_026_0aad1879
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0aad1879b98b2148b7035c848b1e71f4fa73678fdea2f15442d1552429684b6f"
    family = "unknown"
    file_name = "bioset0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:35"
  condition:
    hash.sha256(0, filesize) == "0aad1879b98b2148b7035c848b1e71f4fa73678fdea2f15442d1552429684b6f"
}

rule MalwareBazaar_unknown_027_89ccb497
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89ccb497c51c5ce3a113a52bbfe807028b14d5ecc992e4543e683c91be40855f"
    family = "unknown"
    file_name = "edac_polld"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:33"
  condition:
    hash.sha256(0, filesize) == "89ccb497c51c5ce3a113a52bbfe807028b14d5ecc992e4543e683c91be40855f"
}

rule MalwareBazaar_unknown_028_34fb09ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34fb09cae8aa5047478467381f06cad599d2ec08d045e8403b0e67724ab4fbde"
    family = "unknown"
    file_name = "loader.sh"
    file_type = "sh"
    first_seen = "2026-10-04 04:33:27"
  condition:
    hash.sha256(0, filesize) == "34fb09cae8aa5047478467381f06cad599d2ec08d045e8403b0e67724ab4fbde"
}

rule MalwareBazaar_unknown_029_5a26a455
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a26a4558246daced34649ba417445ee547a6afc7a0f66a3204f30ecc4fa6cce"
    family = "unknown"
    file_name = "zswap_shrinkd"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:20"
  condition:
    hash.sha256(0, filesize) == "5a26a4558246daced34649ba417445ee547a6afc7a0f66a3204f30ecc4fa6cce"
}

rule MalwareBazaar_unknown_030_b405eb0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b405eb0c7900d92ba655488f855f5e37d7154c077a1f7e4967670453082ddcac"
    family = "unknown"
    file_name = "rcuop_0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:17"
  condition:
    hash.sha256(0, filesize) == "b405eb0c7900d92ba655488f855f5e37d7154c077a1f7e4967670453082ddcac"
}

rule MalwareBazaar_unknown_031_423ebf3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "423ebf3f807b93565a2f8752d172f7c63a186c18bc20bf75c8915f0e1f6bbd4d"
    family = "unknown"
    file_name = "kworker_u8"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:16"
  condition:
    hash.sha256(0, filesize) == "423ebf3f807b93565a2f8752d172f7c63a186c18bc20bf75c8915f0e1f6bbd4d"
}

rule MalwareBazaar_unknown_032_2334ba8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2334ba8af1e64f074a98c6be8299e29b6eed8b048dd8a7f1cc98d078eea99984"
    family = "unknown"
    file_name = "kblockd0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:15"
  condition:
    hash.sha256(0, filesize) == "2334ba8af1e64f074a98c6be8299e29b6eed8b048dd8a7f1cc98d078eea99984"
}

rule MalwareBazaar_unknown_033_1bc23d3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bc23d3b13d5cae1dc3b8064c0e13fd27245c740a6d3aaba761df9443ae2b462"
    family = "unknown"
    file_name = "kswapd0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:14"
  condition:
    hash.sha256(0, filesize) == "1bc23d3b13d5cae1dc3b8064c0e13fd27245c740a6d3aaba761df9443ae2b462"
}

rule MalwareBazaar_unknown_034_728b0dab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "728b0daba3251492e419826a104b921bcbd7931c4352da943c4e8cde2c964ce1"
    family = "unknown"
    file_name = "ksoftirqd0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:13"
  condition:
    hash.sha256(0, filesize) == "728b0daba3251492e419826a104b921bcbd7931c4352da943c4e8cde2c964ce1"
}

rule MalwareBazaar_unknown_035_24fbb7a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24fbb7a26e1071d64f4dfc56273b25f3273906de1548453ee1cddc32526c4ae1"
    family = "unknown"
    file_name = "ecryptfsd"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:13"
  condition:
    hash.sha256(0, filesize) == "24fbb7a26e1071d64f4dfc56273b25f3273906de1548453ee1cddc32526c4ae1"
}

rule MalwareBazaar_unknown_036_ace3ad11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ace3ad11d0edf9c2a9b937d4aed1917fd1420e381ce5ad0d5efbc9ddf25f3d9c"
    family = "unknown"
    file_name = "cfg80211d"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:13"
  condition:
    hash.sha256(0, filesize) == "ace3ad11d0edf9c2a9b937d4aed1917fd1420e381ce5ad0d5efbc9ddf25f3d9c"
}

rule MalwareBazaar_unknown_037_5669521d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5669521dba0e09dc22054453be79e37ef4d5fda8413f6457ef8203e8a812625e"
    family = "unknown"
    file_name = "jbd2_sda1d"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:12"
  condition:
    hash.sha256(0, filesize) == "5669521dba0e09dc22054453be79e37ef4d5fda8413f6457ef8203e8a812625e"
}

rule MalwareBazaar_unknown_038_fc5b9e63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc5b9e6337bbb8ff175b9258c8812efc9f6e35ea0fa1bbe13d18bbe3ccc6cc0e"
    family = "unknown"
    file_name = "devfreq_wq"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:12"
  condition:
    hash.sha256(0, filesize) == "fc5b9e6337bbb8ff175b9258c8812efc9f6e35ea0fa1bbe13d18bbe3ccc6cc0e"
}

rule MalwareBazaar_unknown_039_941a0c7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "941a0c7f78871c908711b09176683928d1899fe284589fc965426f3b143b27be"
    family = "unknown"
    file_name = "bioset0"
    file_type = "elf"
    first_seen = "2026-10-04 04:33:09"
  condition:
    hash.sha256(0, filesize) == "941a0c7f78871c908711b09176683928d1899fe284589fc965426f3b143b27be"
}

rule MalwareBazaar_Mirai_040_0313cef6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0313cef6ee5ccac16714f02e3ff9dfd5181c55419f96a6443d9812f0d37a8eaa"
    family = "Mirai"
    file_name = "b3c455c0833628ac.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:25:35"
  condition:
    hash.sha256(0, filesize) == "0313cef6ee5ccac16714f02e3ff9dfd5181c55419f96a6443d9812f0d37a8eaa"
}

rule MalwareBazaar_Gafgyt_041_3af5d15c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3af5d15c8bc300ef4cce30f60613b5a47cea92c4b23dd0fe0f2ead2b781e9cc6"
    family = "Gafgyt"
    file_name = "3af5d15c8bc300ef.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:25:29"
  condition:
    hash.sha256(0, filesize) == "3af5d15c8bc300ef4cce30f60613b5a47cea92c4b23dd0fe0f2ead2b781e9cc6"
}

rule MalwareBazaar_Mirai_042_2614bd64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2614bd6433ed10049482f52bb6da315008f66db4586a896a82f372ba4eefdb09"
    family = "Mirai"
    file_name = "2614bd6433ed1004.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:25:20"
  condition:
    hash.sha256(0, filesize) == "2614bd6433ed10049482f52bb6da315008f66db4586a896a82f372ba4eefdb09"
}

rule MalwareBazaar_Gafgyt_043_e1e7c105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1e7c1050ecf9d4a945652b2c6d0707dd33283d750560cbee354bb4c68f98bbe"
    family = "Gafgyt"
    file_name = "e1e7c1050ecf9d4a.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:25:11"
  condition:
    hash.sha256(0, filesize) == "e1e7c1050ecf9d4a945652b2c6d0707dd33283d750560cbee354bb4c68f98bbe"
}

rule MalwareBazaar_unknown_044_836c3d2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "836c3d2f62862223d559f124b11f039d993df1296904d5d80dbf3ded4aa30d8a"
    family = "unknown"
    file_name = "836c3d2f62862223.bin"
    file_type = "exe"
    first_seen = "2026-10-04 04:25:02"
  condition:
    hash.sha256(0, filesize) == "836c3d2f62862223d559f124b11f039d993df1296904d5d80dbf3ded4aa30d8a"
}

rule MalwareBazaar_Gafgyt_045_8fd8d5ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fd8d5ba7d46fc31185131d5a0dafd5d374352b0b0f2d6b816157102289dde50"
    family = "Gafgyt"
    file_name = "8fd8d5ba7d46fc31.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:24:53"
  condition:
    hash.sha256(0, filesize) == "8fd8d5ba7d46fc31185131d5a0dafd5d374352b0b0f2d6b816157102289dde50"
}

rule MalwareBazaar_Gafgyt_046_d80e32a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d80e32a0a99e47b8393a359df841d63be8e42ca0323376660c865a0bdf9b6d0f"
    family = "Gafgyt"
    file_name = "d80e32a0a99e47b8.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:24:43"
  condition:
    hash.sha256(0, filesize) == "d80e32a0a99e47b8393a359df841d63be8e42ca0323376660c865a0bdf9b6d0f"
}

rule MalwareBazaar_Mirai_047_b3c455c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3c455c0833628acb088290890eb1e44d154c0be5a69de5d52bb39715d0fcb68"
    family = "Mirai"
    file_name = "b3c455c0833628ac.bin"
    file_type = "elf"
    first_seen = "2026-10-04 04:24:35"
  condition:
    hash.sha256(0, filesize) == "b3c455c0833628acb088290890eb1e44d154c0be5a69de5d52bb39715d0fcb68"
}

rule MalwareBazaar_unknown_048_cc17cb60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc17cb6086f10aada5b199a46361996927466128be504943c9fbe2752fe2d558"
    family = "unknown"
    file_name = "cc17cb6086f10aada5b199a46361996927466128be504943c9fbe2752fe2d558.exe"
    file_type = "exe"
    first_seen = "2026-10-04 04:23:46"
  condition:
    hash.sha256(0, filesize) == "cc17cb6086f10aada5b199a46361996927466128be504943c9fbe2752fe2d558"
}

rule MalwareBazaar_Neshta_049_49361132
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "493611327d5d4fe06460977a0295586a9a67434ffc90282a69028fa1f12e3ce9"
    family = "Neshta"
    file_name = "493611327d5d4fe06460977a0295586a9a67434ffc90282a69028fa1f12e3ce9.exe"
    file_type = "exe"
    first_seen = "2026-10-04 04:23:31"
  condition:
    hash.sha256(0, filesize) == "493611327d5d4fe06460977a0295586a9a67434ffc90282a69028fa1f12e3ce9"
}

rule MalwareBazaar_Mirai_050_95b4e74a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95b4e74af25fbe652b36c394e69c5c6c29d9f803f8a81b5ca37021a569910d96"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-10-04 04:21:07"
  condition:
    hash.sha256(0, filesize) == "95b4e74af25fbe652b36c394e69c5c6c29d9f803f8a81b5ca37021a569910d96"
}

rule MalwareBazaar_unknown_051_1e6e262d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e6e262dea13e3cb47fd4b54a2eb52c90ab391c4ea1a0f7d036da5b804c221b1"
    family = "unknown"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-10-04 04:19:14"
  condition:
    hash.sha256(0, filesize) == "1e6e262dea13e3cb47fd4b54a2eb52c90ab391c4ea1a0f7d036da5b804c221b1"
}

rule MalwareBazaar_unknown_052_79db184a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79db184a2866150c44d5b32f626c0b120188b27dc480401824d327720e8fcb8e"
    family = "unknown"
    file_name = "79db184a2866150c44d5b32f626c0b120188b27dc480401824d327720e8fcb8e"
    file_type = "elf"
    first_seen = "2026-10-04 04:17:24"
  condition:
    hash.sha256(0, filesize) == "79db184a2866150c44d5b32f626c0b120188b27dc480401824d327720e8fcb8e"
}

rule MalwareBazaar_Mirai_053_0aead361
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0aead3610357cf808bb61e1b7ff7e6bbe0880c3d91417c8ae78d359417465bc8"
    family = "Mirai"
    file_name = "0aead3610357cf808bb61e1b7ff7e6bbe0880c3d91417c8ae78d359417465bc8"
    file_type = "elf"
    first_seen = "2026-10-04 04:17:17"
  condition:
    hash.sha256(0, filesize) == "0aead3610357cf808bb61e1b7ff7e6bbe0880c3d91417c8ae78d359417465bc8"
}

rule MalwareBazaar_unknown_054_39d6c517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39d6c517b3e44a09d25a7c9cf37b3eb3cb4800ab16f9540012158fd091e37232"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-04 04:11:41"
  condition:
    hash.sha256(0, filesize) == "39d6c517b3e44a09d25a7c9cf37b3eb3cb4800ab16f9540012158fd091e37232"
}

rule MalwareBazaar_unknown_055_a3fcd122
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3fcd1222767342c0d8962b8828fca4e65424ad76c05fe3144885629397a521c"
    family = "unknown"
    file_name = "a3fcd1222767342c0d8962b8828fca4e65424ad76c05fe3144885629397a521c.exe"
    file_type = "exe"
    first_seen = "2026-10-04 03:39:27"
  condition:
    hash.sha256(0, filesize) == "a3fcd1222767342c0d8962b8828fca4e65424ad76c05fe3144885629397a521c"
}

rule MalwareBazaar_unknown_056_e6a0e9ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6a0e9ad743a924c8c746e4dec8e0780843342ffd2b3b0024e25cd19495cfbee"
    family = "unknown"
    file_name = "e6a0e9ad743a924c8c746e4dec8e0780843342ffd2b3b0024e25cd19495cfbee.exe"
    file_type = "exe"
    first_seen = "2026-10-04 03:39:21"
  condition:
    hash.sha256(0, filesize) == "e6a0e9ad743a924c8c746e4dec8e0780843342ffd2b3b0024e25cd19495cfbee"
}

rule MalwareBazaar_unknown_057_ed69b232
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed69b232a3ac92a5e5f43757119af730f5d814305122a456132dad36a1d6a5fd"
    family = "unknown"
    file_name = "ed69b232a3ac92a5e5f43757119af730f5d814305122a456132dad36a1d6a5fd.exe"
    file_type = "exe"
    first_seen = "2026-10-04 03:38:30"
  condition:
    hash.sha256(0, filesize) == "ed69b232a3ac92a5e5f43757119af730f5d814305122a456132dad36a1d6a5fd"
}

rule MalwareBazaar_Mirai_058_a1ebed34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1ebed3463fcf073dd0a91a39546d008472040220984b80a78be410ba9721b3a"
    family = "Mirai"
    file_name = "7a2b25d2b1ebef1d.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:27:22"
  condition:
    hash.sha256(0, filesize) == "a1ebed3463fcf073dd0a91a39546d008472040220984b80a78be410ba9721b3a"
}

rule MalwareBazaar_Mirai_059_78c910c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78c910c7a45022d5537698d103c440f34672bc95a05b47db16cf12afceab4a92"
    family = "Mirai"
    file_name = "78c910c7a45022d5.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:50"
  condition:
    hash.sha256(0, filesize) == "78c910c7a45022d5537698d103c440f34672bc95a05b47db16cf12afceab4a92"
}

rule MalwareBazaar_Mirai_060_01325b5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01325b5d6ae777813bf88b5804468c1a53c3a1e5ad3448ae274f60cb8ea0dcd0"
    family = "Mirai"
    file_name = "01325b5d6ae77781.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:41"
  condition:
    hash.sha256(0, filesize) == "01325b5d6ae777813bf88b5804468c1a53c3a1e5ad3448ae274f60cb8ea0dcd0"
}

rule MalwareBazaar_Mirai_061_7a2b25d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a2b25d2b1ebef1d158158ecc4e82a6effc7b8fc6379d3f6e212a731e615d86d"
    family = "Mirai"
    file_name = "7a2b25d2b1ebef1d.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:33"
  condition:
    hash.sha256(0, filesize) == "7a2b25d2b1ebef1d158158ecc4e82a6effc7b8fc6379d3f6e212a731e615d86d"
}

rule MalwareBazaar_Mirai_062_a6b654ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6b654ae2af04a247445a3c0958336b17444fd3e282826e12e8798892df681b8"
    family = "Mirai"
    file_name = "a6b654ae2af04a24.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:25"
  condition:
    hash.sha256(0, filesize) == "a6b654ae2af04a247445a3c0958336b17444fd3e282826e12e8798892df681b8"
}

rule MalwareBazaar_Gafgyt_063_619fee53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "619fee538f560558ad4a422b64893355e4b650fd81bd443877fa4b2fa4690819"
    family = "Gafgyt"
    file_name = "619fee538f560558.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:16"
  condition:
    hash.sha256(0, filesize) == "619fee538f560558ad4a422b64893355e4b650fd81bd443877fa4b2fa4690819"
}

rule MalwareBazaar_Mirai_064_18f1a42c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18f1a42c10ee3708c20a3ede9a15ad43ab77852f7693118940cab780fad2ea89"
    family = "Mirai"
    file_name = "18f1a42c10ee3708.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:26:08"
  condition:
    hash.sha256(0, filesize) == "18f1a42c10ee3708c20a3ede9a15ad43ab77852f7693118940cab780fad2ea89"
}

rule MalwareBazaar_Mirai_065_cd54c3e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd54c3e06103740a88a510c6114e70291b14bc7b3f2cb32be2c0122aa955a037"
    family = "Mirai"
    file_name = "cd54c3e06103740a.bin"
    file_type = "elf"
    first_seen = "2026-10-04 03:25:59"
  condition:
    hash.sha256(0, filesize) == "cd54c3e06103740a88a510c6114e70291b14bc7b3f2cb32be2c0122aa955a037"
}

rule MalwareBazaar_CoinMiner_066_3c3b6f5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c3b6f5f7df0e8286fb8a0c2d77a807c132326fa1b3c4187889d188181c1e78b"
    family = "CoinMiner"
    file_name = "3c3b6f5f7df0e828.bin"
    file_type = "exe"
    first_seen = "2026-10-04 03:25:51"
  condition:
    hash.sha256(0, filesize) == "3c3b6f5f7df0e8286fb8a0c2d77a807c132326fa1b3c4187889d188181c1e78b"
}

rule MalwareBazaar_unknown_067_9cad5794
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cad5794277b3001b080294fcf1f54350a991b7b59af9a47ad12dc34f3d27439"
    family = "unknown"
    file_name = "9cad5794277b3001b080294fcf1f54350a991b7b59af9a47ad12dc34f3d27439.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:25:27"
  condition:
    hash.sha256(0, filesize) == "9cad5794277b3001b080294fcf1f54350a991b7b59af9a47ad12dc34f3d27439"
}

rule MalwareBazaar_unknown_068_b8acf0e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8acf0e39cf6e23f1616ec375c794b31f46731e893a7115c187bed03b39d49dc"
    family = "unknown"
    file_name = "b8acf0e39cf6e23f1616ec375c794b31f46731e893a7115c187bed03b39d49dc.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:25:23"
  condition:
    hash.sha256(0, filesize) == "b8acf0e39cf6e23f1616ec375c794b31f46731e893a7115c187bed03b39d49dc"
}

rule MalwareBazaar_unknown_069_ca4d077c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca4d077c5679db66f958c9c2dbb1710c281340c6f0fefc1883b953bcddc9d120"
    family = "unknown"
    file_name = "ca4d077c5679db66f958c9c2dbb1710c281340c6f0fefc1883b953bcddc9d120.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:25:18"
  condition:
    hash.sha256(0, filesize) == "ca4d077c5679db66f958c9c2dbb1710c281340c6f0fefc1883b953bcddc9d120"
}

rule MalwareBazaar_unknown_070_c05b668f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c05b668f1ba8897a9fe6345b627d696897f4dc6817dc2410600940d25102d740"
    family = "unknown"
    file_name = "c05b668f1ba8897a9fe6345b627d696897f4dc6817dc2410600940d25102d740.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:25:13"
  condition:
    hash.sha256(0, filesize) == "c05b668f1ba8897a9fe6345b627d696897f4dc6817dc2410600940d25102d740"
}

rule MalwareBazaar_unknown_071_40920a84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40920a84cbcb0b0a4577bcd85f395cac0ee7de67d36fad3cd4fe8e04a65dce8f"
    family = "unknown"
    file_name = "40920a84cbcb0b0a4577bcd85f395cac0ee7de67d36fad3cd4fe8e04a65dce8f.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:25:08"
  condition:
    hash.sha256(0, filesize) == "40920a84cbcb0b0a4577bcd85f395cac0ee7de67d36fad3cd4fe8e04a65dce8f"
}

rule MalwareBazaar_unknown_072_77e81a85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77e81a853bc978c41191d3e7f83312e46a925c9464ca55eed5ed6befbb579871"
    family = "unknown"
    file_name = "77e81a853bc978c41191d3e7f83312e46a925c9464ca55eed5ed6befbb579871.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:23:47"
  condition:
    hash.sha256(0, filesize) == "77e81a853bc978c41191d3e7f83312e46a925c9464ca55eed5ed6befbb579871"
}

rule MalwareBazaar_Troldesh_073_95ba4eed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95ba4eedec8a047843dd595103de7415c1611c6e19bd5da172bae8c7cce21b4e"
    family = "Troldesh"
    file_name = "95ba4eedec8a047843dd595103de7415c1611c6e19bd5da172bae8c7cce21b4e.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:23:42"
  condition:
    hash.sha256(0, filesize) == "95ba4eedec8a047843dd595103de7415c1611c6e19bd5da172bae8c7cce21b4e"
}

rule MalwareBazaar_unknown_074_f57d5255
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f57d52559fcd14862b5906fe9ddbde34016f752b63ec03e7a1549823046a87c1"
    family = "unknown"
    file_name = "f57d52559fcd14862b5906fe9ddbde34016f752b63ec03e7a1549823046a87c1.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:23:36"
  condition:
    hash.sha256(0, filesize) == "f57d52559fcd14862b5906fe9ddbde34016f752b63ec03e7a1549823046a87c1"
}

rule MalwareBazaar_VShell_075_71d0b3cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71d0b3cdb0e21a4ea729a4ab1668ecdd683e252d044b75938f292ea54ac31413"
    family = "VShell"
    file_name = "71d0b3cdb0e21a4ea729a4ab1668ecdd683e252d044b75938f292ea54ac31413.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:23:31"
  condition:
    hash.sha256(0, filesize) == "71d0b3cdb0e21a4ea729a4ab1668ecdd683e252d044b75938f292ea54ac31413"
}

rule MalwareBazaar_unknown_076_e31bc5c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e31bc5c35b977c1612184a772cbdc5ba5b9137788d399e4ed55521bd5ca43ecd"
    family = "unknown"
    file_name = "e31bc5c35b977c1612184a772cbdc5ba5b9137788d399e4ed55521bd5ca43ecd.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:20:18"
  condition:
    hash.sha256(0, filesize) == "e31bc5c35b977c1612184a772cbdc5ba5b9137788d399e4ed55521bd5ca43ecd"
}

rule MalwareBazaar_unknown_077_c33bd3ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c33bd3ffce08f04552e17b177d6df4f0b0600048f4f158f35c2f46f68c930edd"
    family = "unknown"
    file_name = "c33bd3ffce08f04552e17b177d6df4f0b0600048f4f158f35c2f46f68c930edd.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:20:12"
  condition:
    hash.sha256(0, filesize) == "c33bd3ffce08f04552e17b177d6df4f0b0600048f4f158f35c2f46f68c930edd"
}

rule MalwareBazaar_VShell_078_4f99fcc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f99fcc6eefdf3501f5bdaa92cea2cbfeb58a338ef2b721f4f2992cc51bd7ffc"
    family = "VShell"
    file_name = "4f99fcc6eefdf3501f5bdaa92cea2cbfeb58a338ef2b721f4f2992cc51bd7ffc.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:20:05"
  condition:
    hash.sha256(0, filesize) == "4f99fcc6eefdf3501f5bdaa92cea2cbfeb58a338ef2b721f4f2992cc51bd7ffc"
}

rule MalwareBazaar_VShell_079_7d8798c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d8798c341ec36d1f49ccdae248557ad35912c6bb77939c1be22aff9e314daef"
    family = "VShell"
    file_name = "7d8798c341ec36d1f49ccdae248557ad35912c6bb77939c1be22aff9e314daef.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:20:00"
  condition:
    hash.sha256(0, filesize) == "7d8798c341ec36d1f49ccdae248557ad35912c6bb77939c1be22aff9e314daef"
}

rule MalwareBazaar_VShell_080_5aec4cf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5aec4cf6d50b41c6c3477ff429184fe90d65a5c328ea3ea0ac29c6bed029cf83"
    family = "VShell"
    file_name = "5aec4cf6d50b41c6c3477ff429184fe90d65a5c328ea3ea0ac29c6bed029cf83.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:19:11"
  condition:
    hash.sha256(0, filesize) == "5aec4cf6d50b41c6c3477ff429184fe90d65a5c328ea3ea0ac29c6bed029cf83"
}

rule MalwareBazaar_VShell_081_137413a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "137413a0ab6691e6ad52963e078f17a1f7817148ccdf7fa4ce462f49a5fcde25"
    family = "VShell"
    file_name = "137413a0ab6691e6ad52963e078f17a1f7817148ccdf7fa4ce462f49a5fcde25.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:19:01"
  condition:
    hash.sha256(0, filesize) == "137413a0ab6691e6ad52963e078f17a1f7817148ccdf7fa4ce462f49a5fcde25"
}

rule MalwareBazaar_Mirai_082_54ceeda9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54ceeda981e136c0a50bdb5b52a6db369b4493d35caec5ff97f0bdea7c76f59a"
    family = "Mirai"
    file_name = "234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03.elf"
    file_type = "elf"
    first_seen = "2026-10-04 02:16:25"
  condition:
    hash.sha256(0, filesize) == "54ceeda981e136c0a50bdb5b52a6db369b4493d35caec5ff97f0bdea7c76f59a"
}

rule MalwareBazaar_Mirai_083_234293ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03"
    family = "Mirai"
    file_name = "234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03.elf"
    file_type = "elf"
    first_seen = "2026-10-04 02:15:59"
  condition:
    hash.sha256(0, filesize) == "234293ba9ac7b8db89f6fd8bbd50348cf0b16a51d6a7328ae94d4f454e2b5a03"
}

rule MalwareBazaar_unknown_084_d804aeb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d804aeb27389fdd6e09f05dddad69dd381b3f03bbfde5db350e004bcf0895588"
    family = "unknown"
    file_name = "d804aeb27389fdd6e09f05dddad69dd381b3f03bbfde5db350e004bcf0895588.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:14:58"
  condition:
    hash.sha256(0, filesize) == "d804aeb27389fdd6e09f05dddad69dd381b3f03bbfde5db350e004bcf0895588"
}

rule MalwareBazaar_Mirai_085_e551441f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e551441fb55d5180732d26c2532bb82bde588e970e7bb77e0d0ea86b52bb219d"
    family = "Mirai"
    file_name = "177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e.elf"
    file_type = "elf"
    first_seen = "2026-10-04 02:14:22"
  condition:
    hash.sha256(0, filesize) == "e551441fb55d5180732d26c2532bb82bde588e970e7bb77e0d0ea86b52bb219d"
}

rule MalwareBazaar_unknown_086_7e99e051
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e99e051cc6a925d1a860d36c332bf8095907823b6bddf5d21ae755e3568defc"
    family = "unknown"
    file_name = "7e99e051cc6a925d1a860d36c332bf8095907823b6bddf5d21ae755e3568defc.bin"
    file_type = "zip"
    first_seen = "2026-10-04 02:13:46"
  condition:
    hash.sha256(0, filesize) == "7e99e051cc6a925d1a860d36c332bf8095907823b6bddf5d21ae755e3568defc"
}

rule MalwareBazaar_unknown_087_2b462d51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b462d51032bd76e4f2f9498546e1f18e1510af71231dabf34ac3d5b40a4743c"
    family = "unknown"
    file_name = "2b462d51032bd76e4f2f9498546e1f18e1510af71231dabf34ac3d5b40a4743c.msi"
    file_type = "msi"
    first_seen = "2026-10-04 02:13:40"
  condition:
    hash.sha256(0, filesize) == "2b462d51032bd76e4f2f9498546e1f18e1510af71231dabf34ac3d5b40a4743c"
}

rule MalwareBazaar_unknown_088_326b416c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "326b416caa382326e010473e54deb977d69ef1931fa79c32eab4553e887dda1d"
    family = "unknown"
    file_name = "326b416caa382326e010473e54deb977d69ef1931fa79c32eab4553e887dda1d.exe"
    file_type = "exe"
    first_seen = "2026-10-04 02:13:34"
  condition:
    hash.sha256(0, filesize) == "326b416caa382326e010473e54deb977d69ef1931fa79c32eab4553e887dda1d"
}

rule MalwareBazaar_Mirai_089_177b7520
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e"
    family = "Mirai"
    file_name = "177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e.elf"
    file_type = "elf"
    first_seen = "2026-10-04 02:13:26"
  condition:
    hash.sha256(0, filesize) == "177b7520a042e73db692da3ff33b17257924826b5da88cd33e3be62f95eab65e"
}

rule MalwareBazaar_njrat_090_dc5abf20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc5abf20ae0c61cb9de2ca80055d369872ef9b6be35fa7ebec386e42e445d13a"
    family = "njrat"
    file_name = "A5F2E89D8926046FB4DE161C78F79B6B.exe"
    file_type = "exe"
    first_seen = "2026-10-04 01:55:08"
  condition:
    hash.sha256(0, filesize) == "dc5abf20ae0c61cb9de2ca80055d369872ef9b6be35fa7ebec386e42e445d13a"
}

rule MalwareBazaar_unknown_091_fb7712e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb7712e35e097c3e6f8f2c1c3e7a6a777290c6df04dfb340c78c75cf33c15606"
    family = "unknown"
    file_name = "fb7712e35e097c3e6f8f2c1c3e7a6a777290c6df04dfb340c78c75cf33c15606.exe"
    file_type = "exe"
    first_seen = "2026-10-04 01:48:33"
  condition:
    hash.sha256(0, filesize) == "fb7712e35e097c3e6f8f2c1c3e7a6a777290c6df04dfb340c78c75cf33c15606"
}

rule MalwareBazaar_unknown_092_044ef3d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "044ef3d12efbac04a7dbdd40f4e51cd2cdc9c077b0d5d3cb571a2562a74bf9c4"
    family = "unknown"
    file_name = "044ef3d12efbac04a7dbdd40f4e51cd2cdc9c077b0d5d3cb571a2562a74bf9c4.exe"
    file_type = "exe"
    first_seen = "2026-10-04 01:44:15"
  condition:
    hash.sha256(0, filesize) == "044ef3d12efbac04a7dbdd40f4e51cd2cdc9c077b0d5d3cb571a2562a74bf9c4"
}

rule MalwareBazaar_Mirai_093_2eb07e1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2eb07e1b60960bc08205065a3ca610fbb7dfad5a8710a85cd40e3e7baaa190e6"
    family = "Mirai"
    file_name = "2eb07e1b60960bc08205065a3ca610fbb7dfad5a8710a85cd40e3e7baaa190e6.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:36:12"
  condition:
    hash.sha256(0, filesize) == "2eb07e1b60960bc08205065a3ca610fbb7dfad5a8710a85cd40e3e7baaa190e6"
}

rule MalwareBazaar_Mirai_094_05e9766f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05e9766f9225f3ae130e9b90832c4a0a5fef3dc07eed7e5095a084f92b9f391b"
    family = "Mirai"
    file_name = "05e9766f9225f3ae130e9b90832c4a0a5fef3dc07eed7e5095a084f92b9f391b.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:36:07"
  condition:
    hash.sha256(0, filesize) == "05e9766f9225f3ae130e9b90832c4a0a5fef3dc07eed7e5095a084f92b9f391b"
}

rule MalwareBazaar_Mirai_095_6848afee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6848afee7a2461d9a4d0fef7ef3874f3cba44e308eb5da416d705fa1ef699a62"
    family = "Mirai"
    file_name = "6848afee7a2461d9a4d0fef7ef3874f3cba44e308eb5da416d705fa1ef699a62.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:35:23"
  condition:
    hash.sha256(0, filesize) == "6848afee7a2461d9a4d0fef7ef3874f3cba44e308eb5da416d705fa1ef699a62"
}

rule MalwareBazaar_Mirai_096_1bd6853b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bd6853b1074402ecb04a5ffb1abbb57e0c95ed83171526c0413d70d88ed74a5"
    family = "Mirai"
    file_name = "1bd6853b1074402ecb04a5ffb1abbb57e0c95ed83171526c0413d70d88ed74a5.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:35:16"
  condition:
    hash.sha256(0, filesize) == "1bd6853b1074402ecb04a5ffb1abbb57e0c95ed83171526c0413d70d88ed74a5"
}

rule MalwareBazaar_Mirai_097_08dec15e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08dec15e72a6c327ad91bd773f35b0d17bdf320bda1be6ca3398b99366b0e6cc"
    family = "Mirai"
    file_name = "08dec15e72a6c327ad91bd773f35b0d17bdf320bda1be6ca3398b99366b0e6cc.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:35:11"
  condition:
    hash.sha256(0, filesize) == "08dec15e72a6c327ad91bd773f35b0d17bdf320bda1be6ca3398b99366b0e6cc"
}

rule MalwareBazaar_Mirai_098_4217d668
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4217d66857f58ae98fec169b21366f81da342d8b54f11d4def15a4ed74eae595"
    family = "Mirai"
    file_name = "4217d66857f58ae98fec169b21366f81da342d8b54f11d4def15a4ed74eae595.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:35:05"
  condition:
    hash.sha256(0, filesize) == "4217d66857f58ae98fec169b21366f81da342d8b54f11d4def15a4ed74eae595"
}

rule MalwareBazaar_Mirai_099_d618d9ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d618d9eddfd3150d8f05225bafdeaf8a321e57ab592fa2d5d0ace55edd0341e0"
    family = "Mirai"
    file_name = "d618d9eddfd3150d8f05225bafdeaf8a321e57ab592fa2d5d0ace55edd0341e0.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:33:52"
  condition:
    hash.sha256(0, filesize) == "d618d9eddfd3150d8f05225bafdeaf8a321e57ab592fa2d5d0ace55edd0341e0"
}

rule MalwareBazaar_Mirai_100_af4c0ebc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af4c0ebc6170961d5d42bad15599bf48353bb9c5276366581c210eebc7878747"
    family = "Mirai"
    file_name = "af4c0ebc6170961d5d42bad15599bf48353bb9c5276366581c210eebc7878747.elf"
    file_type = "elf"
    first_seen = "2026-10-04 01:33:47"
  condition:
    hash.sha256(0, filesize) == "af4c0ebc6170961d5d42bad15599bf48353bb9c5276366581c210eebc7878747"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

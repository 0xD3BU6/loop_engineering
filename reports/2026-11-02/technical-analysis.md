# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-02

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 664 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 664 |
| Unique family labels | 13 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 37 |
| Mirai | 36 |
| SalatStealer | 13 |
| VShell | 3 |
| ValleyRAT | 3 |
| ConnectWise | 1 |
| NanoCore | 1 |
| AveMariaRAT | 1 |
| Gh0stRAT | 1 |
| RustyStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 43 |
| exe | 37 |
| macho | 12 |
| sh | 4 |
| hta | 2 |
| ps1 | 1 |
| jar | 1 |

## Per-Sample Analysis

### Sample 1: `af3ddecb85a7b8e6`

| Field | Value |
|---|---|
| SHA-256 | `af3ddecb85a7b8e63c5ada278c5a746e1908fcc44efc9b017159afdde8736081` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-11-02 06:17:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8b20989c3c3594f5778d7609392e5d6` |
| SHA-1 | `73af69df1e6a3272cf0f1d9b69353361a47af1dd` |
| SHA-256 | `af3ddecb85a7b8e63c5ada278c5a746e1908fcc44efc9b017159afdde8736081` |
| SHA3-384 | `83fda15d57b8ba9bdebf8f4c0288c97663f00acb13a86c225711ef4115a2d8f94119bcd156a3ac7362580a565d183035` |
| TLSH | `T1CC739E77D4265E58C08248B070B49FB44F63A1C442571FB76AA6C2B89483EEDF619FE8` |
| SSDEEP | `1536:2aUJJ0wByu/388tO2l9HxxK/Wfy5NkY9C8F4nkZRKA1:2h00yu/88t1lY/LNkY99h1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_af3ddecb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af3ddecb85a7b8e63c5ada278c5a746e1908fcc44efc9b017159afdde8736081"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-02 06:17:03"
  condition:
    hash.sha256(0, filesize) == "af3ddecb85a7b8e63c5ada278c5a746e1908fcc44efc9b017159afdde8736081"
}
```

### Sample 2: `dcd9db5cfaa4d135`

| Field | Value |
|---|---|
| SHA-256 | `dcd9db5cfaa4d1351d6d54e1be1ab87a21bcd9289e966e79d550ebffb2903660` |
| Family label | `ConnectWise` |
| File name | `dcd9db5cfaa4d135.bin` |
| File type | `exe` |
| First seen | `2026-11-02 05:24:30` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d0c16c7aa8d9f95fca87604031da093` |
| SHA-1 | `c9e8bc251639f0a0e60d8466bacba9100afbecdf` |
| SHA-256 | `dcd9db5cfaa4d1351d6d54e1be1ab87a21bcd9289e966e79d550ebffb2903660` |
| SHA3-384 | `53c95dfc6bc6878b4df7e364b703ac313265e435249747ffc1a11ee9bbf3e4c9465360b86976b75bd06be427daed7e00` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T177D61211B3E691B5E0BF0638D87A62666631BC128751C7AF6794BE792D327C08E31373` |
| SSDEEP | `98304:a3GF0s6efPIMn1Giy8E1PqhQG6ztZNK9aNGVMn1Giy8E1PqhAMn1Giy8E1PqhNM7:MGufefPLZWimz3I96xZWijZWisZWiP` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_002_dcd9db5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcd9db5cfaa4d1351d6d54e1be1ab87a21bcd9289e966e79d550ebffb2903660"
    family = "ConnectWise"
    file_name = "dcd9db5cfaa4d135.bin"
    file_type = "exe"
    first_seen = "2026-11-02 05:24:30"
  condition:
    hash.sha256(0, filesize) == "dcd9db5cfaa4d1351d6d54e1be1ab87a21bcd9289e966e79d550ebffb2903660"
}
```

### Sample 3: `12d98aa4742c04fb`

| Field | Value |
|---|---|
| SHA-256 | `12d98aa4742c04fb8c13f8d5e70aea2fba6bca409f0ebefbf361cc05c4c50c37` |
| Family label | `unknown` |
| File name | `12d98aa4742c04fb8c13f8d5e70aea2fba6bca409f0ebefbf361cc05c4c50c37.exe` |
| File type | `exe` |
| First seen | `2026-11-02 05:21:32` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74bb4a0008d35006d36328e356cdd054` |
| SHA-1 | `fde0d147d2efe089f3d6b108beac2d306e263143` |
| SHA-256 | `12d98aa4742c04fb8c13f8d5e70aea2fba6bca409f0ebefbf361cc05c4c50c37` |
| SHA3-384 | `7388d01f29ab10d1f869fa56db5452cb73d3cd312726aca0cb32774b2e893e163599edd55184a7c3e13d8ba2b7d540ba` |
| IMPHASH | `e3822bd42d2119895568041b12efd53d` |
| TLSH | `T16F352A00FED05D68E02E8D32002EBD1F39AA7F57569469D2C39CD70705ABA512EF6D2E` |
| SSDEEP | `24576:toataV6PT26mbKYyB0X2saCrOSGpDPacbvt:toancbHmsaipKjawF` |
| ICON-DHASH | `fefbb3f7f7b3f33f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_12d98aa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12d98aa4742c04fb8c13f8d5e70aea2fba6bca409f0ebefbf361cc05c4c50c37"
    family = "unknown"
    file_name = "12d98aa4742c04fb8c13f8d5e70aea2fba6bca409f0ebefbf361cc05c4c50c37.exe"
    file_type = "exe"
    first_seen = "2026-11-02 05:21:32"
  condition:
    hash.sha256(0, filesize) == "12d98aa4742c04fb8c13f8d5e70aea2fba6bca409f0ebefbf361cc05c4c50c37"
}
```

### Sample 4: `fac02194cd7deb48`

| Field | Value |
|---|---|
| SHA-256 | `fac02194cd7deb481d16e970e0d7a6d88f85cd758dd34fb7cff5fcfe1e1e375b` |
| Family label | `unknown` |
| File name | `fac02194cd7deb481d16e970e0d7a6d88f85cd758dd34fb7cff5fcfe1e1e375b` |
| File type | `elf` |
| First seen | `2026-11-02 04:50:20` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c23dce7e5161997835e80d60c61c6c15` |
| SHA-1 | `c6f75d6d3b2743cc138429b1f540df606ee8f06b` |
| SHA-256 | `fac02194cd7deb481d16e970e0d7a6d88f85cd758dd34fb7cff5fcfe1e1e375b` |
| SHA3-384 | `0349e0788a1aea664f4a943fe2cbc9b8c67470ecb54d782a8b264d065f1bcf4cd64a081b17658f19c064e75ba78dfc52` |
| TLSH | `T1BAB5BF1BB59250FDC1D7C070879B9633AA32B49952307E7F62C4AF312E26F20675EB61` |
| SSDEEP | `49152:MOpFRF8oFPvnl50p+0eVlvviccJ1TbXLP9TIy2o162i22mJ:FprnVnq+Zvqz1vL9TWo16X22o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_fac02194
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fac02194cd7deb481d16e970e0d7a6d88f85cd758dd34fb7cff5fcfe1e1e375b"
    family = "unknown"
    file_name = "fac02194cd7deb481d16e970e0d7a6d88f85cd758dd34fb7cff5fcfe1e1e375b"
    file_type = "elf"
    first_seen = "2026-11-02 04:50:20"
  condition:
    hash.sha256(0, filesize) == "fac02194cd7deb481d16e970e0d7a6d88f85cd758dd34fb7cff5fcfe1e1e375b"
}
```

### Sample 5: `be9c4db2624c8b74`

| Field | Value |
|---|---|
| SHA-256 | `be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583` |
| Family label | `VShell` |
| File name | `be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583.exe` |
| File type | `exe` |
| First seen | `2026-11-02 04:28:31` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d3b77239914035243d7bc3264500e5c` |
| SHA-1 | `47fac072d219b50249f94333aa3694d14a56eb08` |
| SHA-256 | `be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583` |
| SHA3-384 | `95ecc3dd0ce32a53d2fe28db5be4c1a5c144ed3b81c5ba10a64827283a9cabc7f903c71ca6624ecc1ca55b9c7fae178c` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T17171B541605456F2D94DE37F8487B896FD4EB288A2C80B0B0798D81A2FB607BB0D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DUBjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DUZ++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_005_be9c4db2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583"
    family = "VShell"
    file_name = "be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583.exe"
    file_type = "exe"
    first_seen = "2026-11-02 04:28:31"
  condition:
    hash.sha256(0, filesize) == "be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583"
}
```

### Sample 6: `ce05a292a38bfc0a`

| Field | Value |
|---|---|
| SHA-256 | `ce05a292a38bfc0acd84d41f5ab827ddea81b6aee8075e20e4e5f41f50fae82d` |
| Family label | `unknown` |
| File name | `ce05a292a38bfc0acd84d41f5ab827ddea81b6aee8075e20e4e5f41f50fae82d.exe` |
| File type | `exe` |
| First seen | `2026-11-02 04:27:29` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `045ca812c7ff164dcb2b8f7f22058800` |
| SHA-1 | `021fee8e5c443c4317a853758055b86d953e738c` |
| SHA-256 | `ce05a292a38bfc0acd84d41f5ab827ddea81b6aee8075e20e4e5f41f50fae82d` |
| SHA3-384 | `e5487af8747c1365d56abbb1a0236789230a4b2f2b5289effb0e7fcf8321ce351dfa07de5d3c1cdb65a4c5fadc0dcf62` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17EE309AA94061724DEF209B581284EFF4FF13E789AB69446B29477EF312E356740C0B7` |
| SSDEEP | `1536:mei1sMwfiEw3Y0XhMTE9emEuZGgiLOckUSV94LZxUKkk:meiyMwqHI0XSE9epS+/UKkk` |
| ICON-DHASH | `92307939339a4c8e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_ce05a292
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce05a292a38bfc0acd84d41f5ab827ddea81b6aee8075e20e4e5f41f50fae82d"
    family = "unknown"
    file_name = "ce05a292a38bfc0acd84d41f5ab827ddea81b6aee8075e20e4e5f41f50fae82d.exe"
    file_type = "exe"
    first_seen = "2026-11-02 04:27:29"
  condition:
    hash.sha256(0, filesize) == "ce05a292a38bfc0acd84d41f5ab827ddea81b6aee8075e20e4e5f41f50fae82d"
}
```

### Sample 7: `9c4b36446d28038f`

| Field | Value |
|---|---|
| SHA-256 | `9c4b36446d28038f25b5078d37c071ab90359a9c5dfcc61d04a6f7093a673d6b` |
| Family label | `VShell` |
| File name | `9c4b36446d28038f25b5078d37c071ab90359a9c5dfcc61d04a6f7093a673d6b.exe` |
| File type | `exe` |
| First seen | `2026-11-02 03:22:03` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9809bae19734fe657dbdb0732d048e0` |
| SHA-1 | `e36028a1e08306edca979276be14e794f47bc0ec` |
| SHA-256 | `9c4b36446d28038f25b5078d37c071ab90359a9c5dfcc61d04a6f7093a673d6b` |
| SHA3-384 | `9e6abc774a7adae28b5f67043ed3cc501549d81f2a71f795d978749e3cbf8751f25ff91900887bbbbc04bde67d001b06` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1CB71A541A09456F2D94DE3BF8587B896FD4FB248A2C80B0B0798D81A2F7647BB4DD613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6D8cBjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DNZ++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_007_9c4b3644
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c4b36446d28038f25b5078d37c071ab90359a9c5dfcc61d04a6f7093a673d6b"
    family = "VShell"
    file_name = "9c4b36446d28038f25b5078d37c071ab90359a9c5dfcc61d04a6f7093a673d6b.exe"
    file_type = "exe"
    first_seen = "2026-11-02 03:22:03"
  condition:
    hash.sha256(0, filesize) == "9c4b36446d28038f25b5078d37c071ab90359a9c5dfcc61d04a6f7093a673d6b"
}
```

### Sample 8: `a4a89b60a58553f0`

| Field | Value |
|---|---|
| SHA-256 | `a4a89b60a58553f070061c21b897348218c7cc6c7bc2cef31c4dac218d53b7f2` |
| Family label | `unknown` |
| File name | `a4a89b60a58553f070061c21b897348218c7cc6c7bc2cef31c4dac218d53b7f2.exe` |
| File type | `exe` |
| First seen | `2026-11-02 03:21:59` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad8b1b8c436457b8243bccc9825ac7ff` |
| SHA-1 | `aa43ed58a9a1240165d204d69e1362062238e17b` |
| SHA-256 | `a4a89b60a58553f070061c21b897348218c7cc6c7bc2cef31c4dac218d53b7f2` |
| SHA3-384 | `6e6c930f31c6519ca257bad922b90b7acd3240ba31242b25cf4426196495cc81af05f58c4a9c86ffa1f80aeba64357ce` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T14191C64270B989E7E85C85BB4C0FB8A0B91D740A41C483A70338A5993E3A57BF47CB0E` |
| SSDEEP | `48:6IIF9BlQaexhzT81gZD7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaM98AA0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_a4a89b60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4a89b60a58553f070061c21b897348218c7cc6c7bc2cef31c4dac218d53b7f2"
    family = "unknown"
    file_name = "a4a89b60a58553f070061c21b897348218c7cc6c7bc2cef31c4dac218d53b7f2.exe"
    file_type = "exe"
    first_seen = "2026-11-02 03:21:59"
  condition:
    hash.sha256(0, filesize) == "a4a89b60a58553f070061c21b897348218c7cc6c7bc2cef31c4dac218d53b7f2"
}
```

### Sample 9: `94cd3079455b2c4e`

| Field | Value |
|---|---|
| SHA-256 | `94cd3079455b2c4e3a1d93ed3b9797490d46d17d975b0f4d2453d6bb0bf0189e` |
| Family label | `SalatStealer` |
| File name | `7802b936027bad7c.bin` |
| File type | `exe` |
| First seen | `2026-11-02 02:26:26` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e64aa23b300582e68ea237d0e57cf73` |
| SHA-1 | `6e6ab595042e95af5a7cb15ed14e9a45aa51df53` |
| SHA-256 | `94cd3079455b2c4e3a1d93ed3b9797490d46d17d975b0f4d2453d6bb0bf0189e` |
| SHA3-384 | `0c3d450fea5d2be7423ba6f9892bc42b54182a23bc95302fe297d28a9bee6337124d07bf19846c0108b50f5dda00930a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E5C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+y:yBkKr5rszpNDy+y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_009_94cd3079
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94cd3079455b2c4e3a1d93ed3b9797490d46d17d975b0f4d2453d6bb0bf0189e"
    family = "SalatStealer"
    file_name = "7802b936027bad7c.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:26:26"
  condition:
    hash.sha256(0, filesize) == "94cd3079455b2c4e3a1d93ed3b9797490d46d17d975b0f4d2453d6bb0bf0189e"
}
```

### Sample 10: `dfc1d2ddb25557c2`

| Field | Value |
|---|---|
| SHA-256 | `dfc1d2ddb25557c2d705fd0324d49a379158e9acfeb0d95e0bb63c21624686cc` |
| Family label | `SalatStealer` |
| File name | `fa18cc722d8d95f7.bin` |
| File type | `exe` |
| First seen | `2026-11-02 02:26:21` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15322f6e8958c703ab8bd46c06333773` |
| SHA-1 | `5b93bf7704bfa69ff38f2ebbcf3f9f26ab5786f3` |
| SHA-256 | `dfc1d2ddb25557c2d705fd0324d49a379158e9acfeb0d95e0bb63c21624686cc` |
| SHA3-384 | `6803f4530fac8d84fae30b6614a40b0bafc25ba86332d28f26dd8eb014262a35bebeb7aeca3d1df386d3bbf707a51450` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E5C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Z:yBkKr5rszpNDy+Z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_010_dfc1d2dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfc1d2ddb25557c2d705fd0324d49a379158e9acfeb0d95e0bb63c21624686cc"
    family = "SalatStealer"
    file_name = "fa18cc722d8d95f7.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:26:21"
  condition:
    hash.sha256(0, filesize) == "dfc1d2ddb25557c2d705fd0324d49a379158e9acfeb0d95e0bb63c21624686cc"
}
```

### Sample 11: `861341ebac1af104`

| Field | Value |
|---|---|
| SHA-256 | `861341ebac1af1047c240fa2d349d57599c1ff28d85fa035d0611fc581cef181` |
| Family label | `SalatStealer` |
| File name | `040dfd78f8e10fb4.bin` |
| File type | `exe` |
| First seen | `2026-11-02 02:26:16` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5993536a1bcfba570a7e959e24354081` |
| SHA-1 | `5ef9646a4ab7bb497d75ee71817adee1635b94bc` |
| SHA-256 | `861341ebac1af1047c240fa2d349d57599c1ff28d85fa035d0611fc581cef181` |
| SHA3-384 | `26dd3255d559cce8d43ba5bf0027b0aca08ca2a5c71d44915d0eaa5762c7452424ad93b92c7131b8e5876754d7035cfb` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T184C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+u:yBkKr5rszpNDy+u` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_011_861341eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "861341ebac1af1047c240fa2d349d57599c1ff28d85fa035d0611fc581cef181"
    family = "SalatStealer"
    file_name = "040dfd78f8e10fb4.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:26:16"
  condition:
    hash.sha256(0, filesize) == "861341ebac1af1047c240fa2d349d57599c1ff28d85fa035d0611fc581cef181"
}
```

### Sample 12: `bb9e627173974aa2`

| Field | Value |
|---|---|
| SHA-256 | `bb9e627173974aa28c7583d80af5eb4d626a3ddf7e1926e477d4f29576209a8d` |
| Family label | `Mirai` |
| File name | `bb9e627173974aa2.bin` |
| File type | `elf` |
| First seen | `2026-11-02 02:26:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f96ab05121206e667f97633a7241a2c` |
| SHA-1 | `6e27dce272f4dc27ee230d8f6de1218ac9bd48a5` |
| SHA-256 | `bb9e627173974aa28c7583d80af5eb4d626a3ddf7e1926e477d4f29576209a8d` |
| SHA3-384 | `5fb2a78a3399b16accc787fd9c849fc6bb8273fead625cea45850119a1a0e54e36af37f3103055406d578c462e8bada5` |
| TLSH | `T11E23F851F9829627C2E023B6B5BEA68D333133E9D2CB7667D9210B503A9542F0D73F85` |
| TELFHASH | `t1e4e02600fda88a1859d79a749ddd07a49900220260578720cf14dae4c83f554a308d5e` |
| SSDEEP | `768:0XJOFr/40X2qITzcgG5CNQeFXVDUXmvRjyEH+rY9F1j0b5aioxru/N/I4w+:sU/9mqIXG5CmeFlghgxboa7uBIZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_bb9e6271
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb9e627173974aa28c7583d80af5eb4d626a3ddf7e1926e477d4f29576209a8d"
    family = "Mirai"
    file_name = "bb9e627173974aa2.bin"
    file_type = "elf"
    first_seen = "2026-11-02 02:26:04"
  condition:
    hash.sha256(0, filesize) == "bb9e627173974aa28c7583d80af5eb4d626a3ddf7e1926e477d4f29576209a8d"
}
```

### Sample 13: `7802b936027bad7c`

| Field | Value |
|---|---|
| SHA-256 | `7802b936027bad7c5eba809ba01a4c495cff1922355ad5a1bf32fab2256e54fe` |
| Family label | `SalatStealer` |
| File name | `7802b936027bad7c.bin` |
| File type | `exe` |
| First seen | `2026-11-02 02:25:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `469e4b946e36056d8e7a263dae70a8cb` |
| SHA-1 | `e835c26224a47eb35215b166db3a95f48b884b92` |
| SHA-256 | `7802b936027bad7c5eba809ba01a4c495cff1922355ad5a1bf32fab2256e54fe` |
| SHA3-384 | `a6c5e6b92b6b652c16d11eb525873909667ec8aa9ddd0b37f254d07d9ac72c66b0b6a8bdbc42ea48302cf6a43f6ea537` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1E7F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OW:iJiafuIO7rhWEES4H` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_013_7802b936
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7802b936027bad7c5eba809ba01a4c495cff1922355ad5a1bf32fab2256e54fe"
    family = "SalatStealer"
    file_name = "7802b936027bad7c.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:25:58"
  condition:
    hash.sha256(0, filesize) == "7802b936027bad7c5eba809ba01a4c495cff1922355ad5a1bf32fab2256e54fe"
}
```

### Sample 14: `fa18cc722d8d95f7`

| Field | Value |
|---|---|
| SHA-256 | `fa18cc722d8d95f790dd7e51d50ea3c84b2492fbe68d0f131e46bedd8a0a9d14` |
| Family label | `SalatStealer` |
| File name | `fa18cc722d8d95f7.bin` |
| File type | `exe` |
| First seen | `2026-11-02 02:25:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10a1a6e8ffe33630f8d6b85c3a349855` |
| SHA-1 | `c2d6da79e48d5e995382ec88270a2b626508c49e` |
| SHA-256 | `fa18cc722d8d95f790dd7e51d50ea3c84b2492fbe68d0f131e46bedd8a0a9d14` |
| SHA3-384 | `ade869ef59a265845d8d7559b4b246b4bc5a6a5eeb69b985f6725b48fd6a4d1f1e86a4bb568d1e645781bbaba07fb773` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T106F5335BF1AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O9:iJiafuIO7rhWEES4q` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_014_fa18cc72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa18cc722d8d95f790dd7e51d50ea3c84b2492fbe68d0f131e46bedd8a0a9d14"
    family = "SalatStealer"
    file_name = "fa18cc722d8d95f7.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:25:48"
  condition:
    hash.sha256(0, filesize) == "fa18cc722d8d95f790dd7e51d50ea3c84b2492fbe68d0f131e46bedd8a0a9d14"
}
```

### Sample 15: `040dfd78f8e10fb4`

| Field | Value |
|---|---|
| SHA-256 | `040dfd78f8e10fb48b71be50e84305a6eb8ddc16f7234b0c3e0cb1d159db2f40` |
| Family label | `SalatStealer` |
| File name | `040dfd78f8e10fb4.bin` |
| File type | `exe` |
| First seen | `2026-11-02 02:25:38` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a29545c69b9f59be1e46b35d6cbd8c8` |
| SHA-1 | `7777f5eef791ceb2e711e4814e795287d93c5525` |
| SHA-256 | `040dfd78f8e10fb48b71be50e84305a6eb8ddc16f7234b0c3e0cb1d159db2f40` |
| SHA3-384 | `bc17a138ce5919ab22522438807428ccf32cea225629616dc7ca32059d768171e1c3b81a17bb19b1a24805e5f5d6e13f` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1FDF5335BF1AF47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OC:iJiafuIO7rhWEES4V` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_015_040dfd78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "040dfd78f8e10fb48b71be50e84305a6eb8ddc16f7234b0c3e0cb1d159db2f40"
    family = "SalatStealer"
    file_name = "040dfd78f8e10fb4.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:25:38"
  condition:
    hash.sha256(0, filesize) == "040dfd78f8e10fb48b71be50e84305a6eb8ddc16f7234b0c3e0cb1d159db2f40"
}
```

### Sample 16: `979bcb1667038fa9`

| Field | Value |
|---|---|
| SHA-256 | `979bcb1667038fa9a6dd14571b46ea08443073d6c046f5fc232526f13486cd62` |
| Family label | `VShell` |
| File name | `979bcb1667038fa9a6dd14571b46ea08443073d6c046f5fc232526f13486cd62.exe` |
| File type | `exe` |
| First seen | `2026-11-02 02:20:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `423b996b03a5107e534ea6b913e3cb9d` |
| SHA-1 | `12bfd18010bbc9feac542e47391820bb3799b1c3` |
| SHA-256 | `979bcb1667038fa9a6dd14571b46ea08443073d6c046f5fc232526f13486cd62` |
| SHA3-384 | `c045232cd39c9f70998f181ca484d314ebb5b521798bea78708e0e3ce89e3287318eefed645bf6c1c5618780d6955d07` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1DC716198F3175AF5E42C87F940D3A614C059ABB8C250BF8D5F60381D7C210BA255EF97` |
| SSDEEP | `48:6Icwm0wt2WdJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jJt/SNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_016_979bcb16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "979bcb1667038fa9a6dd14571b46ea08443073d6c046f5fc232526f13486cd62"
    family = "VShell"
    file_name = "979bcb1667038fa9a6dd14571b46ea08443073d6c046f5fc232526f13486cd62.exe"
    file_type = "exe"
    first_seen = "2026-11-02 02:20:48"
  condition:
    hash.sha256(0, filesize) == "979bcb1667038fa9a6dd14571b46ea08443073d6c046f5fc232526f13486cd62"
}
```

### Sample 17: `ceff4e55a0f6d0a0`

| Field | Value |
|---|---|
| SHA-256 | `ceff4e55a0f6d0a0bd19984b46a7c219fa831421c80349e99d42969d63d95a6e` |
| Family label | `NanoCore` |
| File name | `F4EEA136E304FAEB1BF05209EAA08CE1.exe` |
| File type | `exe` |
| First seen | `2026-11-02 02:10:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4eea136e304faeb1bf05209eaa08ce1` |
| SHA-1 | `0964009b7fe789f101691f096575de1dfe176964` |
| SHA-256 | `ceff4e55a0f6d0a0bd19984b46a7c219fa831421c80349e99d42969d63d95a6e` |
| SHA3-384 | `17021703d4e784e35c83935387d227cf4886482bd75bfeca82af3e359d74f905827dd2a1b72434df3fb5c60de4484976` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BD14CF2677A94A2FE2DE86B9701212039778C2E2A8C3F3DF58D454B75F267E406071D7` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5uitzMM3/mpjxE7pzpTV2:MLV6BtpmkRitoxizpZ2` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_017_ceff4e55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceff4e55a0f6d0a0bd19984b46a7c219fa831421c80349e99d42969d63d95a6e"
    family = "NanoCore"
    file_name = "F4EEA136E304FAEB1BF05209EAA08CE1.exe"
    file_type = "exe"
    first_seen = "2026-11-02 02:10:06"
  condition:
    hash.sha256(0, filesize) == "ceff4e55a0f6d0a0bd19984b46a7c219fa831421c80349e99d42969d63d95a6e"
}
```

### Sample 18: `8e9db283c40447a6`

| Field | Value |
|---|---|
| SHA-256 | `8e9db283c40447a6625a2f1b6b992375537f7a9aaed16e0246093314d9780906` |
| Family label | `unknown` |
| File name | `.16` |
| File type | `elf` |
| First seen | `2026-11-02 01:34:29` |
| Reporter | `Jerry1113` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05b14e19b66f5080002c22a6a7031e6b` |
| SHA-1 | `5ce25bf096f74abeb387aa27406f1d3ed43ef74b` |
| SHA-256 | `8e9db283c40447a6625a2f1b6b992375537f7a9aaed16e0246093314d9780906` |
| SHA3-384 | `ee41d23a326b9c920f21df8826d6aacaf4b3338773751da00cf49cfcfaf7943ae22e8c4b2dbea453f2118cd5cb01b673` |
| TLSH | `T13BD5C01BB59250FDC1D7C070879B9633AA32B49952307E7F62C4AF312E26F20675EB61` |
| SSDEEP | `49152:MOpFRF8oFPvnl50p+0eVlvviccJ1TbXLP9TIy2o162i22mG2zs72gt8:FprnVnq+Zvqz1vL9TWo16X22jw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_8e9db283
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e9db283c40447a6625a2f1b6b992375537f7a9aaed16e0246093314d9780906"
    family = "unknown"
    file_name = ".16"
    file_type = "elf"
    first_seen = "2026-11-02 01:34:29"
  condition:
    hash.sha256(0, filesize) == "8e9db283c40447a6625a2f1b6b992375537f7a9aaed16e0246093314d9780906"
}
```

### Sample 19: `b4055673180d1ffb`

| Field | Value |
|---|---|
| SHA-256 | `b4055673180d1ffbe3ad9790e9babd8857740d214ddd832a34f39d960b95fede` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-11-02 01:32:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55d8682d8e40fb36ce6a45721779f0d8` |
| SHA-1 | `94ed9c33313f54e8cf2862777a0644cb8243afde` |
| SHA-256 | `b4055673180d1ffbe3ad9790e9babd8857740d214ddd832a34f39d960b95fede` |
| SHA3-384 | `92acd4c61b5e2c7190c6309bf01c5e73452e8991fd613fd787c99e6435063bc40eb29edf24af439e624c7489dc890aa1` |
| TLSH | `T1B7732B56B9814B22C5C5027AF92E128E332327FCE3DEB2229D215B2477C656F0E77D45` |
| TELFHASH | `t17111a3c0cecd97adb7f00d444389377b35a634f9f61266389e96564e57014a1e05302a` |
| SSDEEP | `1536:qCnn8tXA3QGBwVc36Ge1EKEhaKmQztITi5XzFxNXAE51Yak:IpA3nBeLUNhaYXzFxNXAEr7k` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_b4055673
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4055673180d1ffbe3ad9790e9babd8857740d214ddd832a34f39d960b95fede"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-02 01:32:03"
  condition:
    hash.sha256(0, filesize) == "b4055673180d1ffbe3ad9790e9babd8857740d214ddd832a34f39d960b95fede"
}
```

### Sample 20: `6dfb49cc6916fef8`

| Field | Value |
|---|---|
| SHA-256 | `6dfb49cc6916fef88920780154f2a7577677f5328df182ce4b83870e7e495d11` |
| Family label | `Mirai` |
| File name | `6dfb49cc6916fef8.bin` |
| File type | `elf` |
| First seen | `2026-11-02 01:26:20` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `211790f9a386470ce132e66a937eb2da` |
| SHA-1 | `c08f178f7ff99ffd8086896692adb932f7b36511` |
| SHA-256 | `6dfb49cc6916fef88920780154f2a7577677f5328df182ce4b83870e7e495d11` |
| SHA3-384 | `9dc4651133da2616b4a48a78956bfb289fb68bc5a2d8c25e8f9ddf456c43431cdcb1ef0967b08a62a101c4efdb8e9969` |
| TLSH | `T178734C9AF801CD7DF84BD77B04530909B970A3E156831F266397FEA3BC721A91D26E81` |
| SSDEEP | `1536:65FiRHIlnGrr99vt8sSVRBEo7QZ12fv8NemkWoJ5L:6viZIlnGrh9v4qoEZYqU5L` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_6dfb49cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dfb49cc6916fef88920780154f2a7577677f5328df182ce4b83870e7e495d11"
    family = "Mirai"
    file_name = "6dfb49cc6916fef8.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:26:20"
  condition:
    hash.sha256(0, filesize) == "6dfb49cc6916fef88920780154f2a7577677f5328df182ce4b83870e7e495d11"
}
```

### Sample 21: `0e79e57f073b9311`

| Field | Value |
|---|---|
| SHA-256 | `0e79e57f073b931153db3d531b617f7a996b9fd4756b5a8d54850b3010519ae3` |
| Family label | `Mirai` |
| File name | `0e79e57f073b9311.bin` |
| File type | `elf` |
| First seen | `2026-11-02 01:26:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17f5bc727757c0073effc4e0192cbb71` |
| SHA-1 | `8e8684c8bdb2d881abe5636cfbad67e0bae4080d` |
| SHA-256 | `0e79e57f073b931153db3d531b617f7a996b9fd4756b5a8d54850b3010519ae3` |
| SHA3-384 | `c8cf1e22832f5b21c737b8838e9eb622f61d992521122bd438fad7fa2d2faa586dec8d8cb8907ca0228587a5f1d550c1` |
| TLSH | `T18F733A21B6761A17C0D1A8BA21FB4B25B6F147CE26A8C61B3DB20E4EFF715406543EF4` |
| SSDEEP | `1536:vQzKTB4Kkp+S/qD2cT1P9UwNAFQPGYlYk57tIIovg:vm8uIgwyiGYlYUmvg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_0e79e57f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e79e57f073b931153db3d531b617f7a996b9fd4756b5a8d54850b3010519ae3"
    family = "Mirai"
    file_name = "0e79e57f073b9311.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:26:14"
  condition:
    hash.sha256(0, filesize) == "0e79e57f073b931153db3d531b617f7a996b9fd4756b5a8d54850b3010519ae3"
}
```

### Sample 22: `16fe10a71f77a1e6`

| Field | Value |
|---|---|
| SHA-256 | `16fe10a71f77a1e6150226759ce7971a604ecc21fe54ccce808a00e02a7972c9` |
| Family label | `Mirai` |
| File name | `16fe10a71f77a1e6.bin` |
| File type | `elf` |
| First seen | `2026-11-02 01:26:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c2efdd0a426e18bc6b2d2a0700405a2` |
| SHA-1 | `5b82024084614c46e4f3ff7a96d8fc896d05df4e` |
| SHA-256 | `16fe10a71f77a1e6150226759ce7971a604ecc21fe54ccce808a00e02a7972c9` |
| SHA3-384 | `fc009de5c6c76b10d78457168f77764e0513aa47974ef4ff7c2ef9c971ed086dfaf074554e67604da78c8d9552808b1e` |
| TLSH | `T1E123E892B8819627C2E5237AB67E56CE337037E9D2CFB617D9214B143A8542F0D63F81` |
| TELFHASH | `t1e4e02600fda88a1859d79a749ddd07a49900220260578720cf14dae4c83f554a308d5e` |
| SSDEEP | `768:XYFHLR5j6Q9KgG5ifFCPWOaiW3qK9XLzSx9uWD7i2J+M8jougY6/NB2w:Xo5WcG5itCPKzX7q/p0M8T6n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_16fe10a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16fe10a71f77a1e6150226759ce7971a604ecc21fe54ccce808a00e02a7972c9"
    family = "Mirai"
    file_name = "16fe10a71f77a1e6.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:26:07"
  condition:
    hash.sha256(0, filesize) == "16fe10a71f77a1e6150226759ce7971a604ecc21fe54ccce808a00e02a7972c9"
}
```

### Sample 23: `96993b8671b76325`

| Field | Value |
|---|---|
| SHA-256 | `96993b8671b76325b7b28fc59889e430a6212843a57cf03b9a3ba1725891892a` |
| Family label | `Mirai` |
| File name | `96993b8671b76325.bin` |
| File type | `elf` |
| First seen | `2026-11-02 01:26:01` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17b66e5983c8e9dd6f2098f04717be27` |
| SHA-1 | `59db5d7a43a290c815f4471e9aa2103abc4119cb` |
| SHA-256 | `96993b8671b76325b7b28fc59889e430a6212843a57cf03b9a3ba1725891892a` |
| SHA3-384 | `8347e8b543de1732f65b807be60d98382a18ac29da27ad2cc928c1f0700bbbe87773c2ce3d289275f0e7f609dbc6372d` |
| TLSH | `T1FD538E6BD42A0E64C18640B074689E711F23B1C493536FF76AE6C2B86483EACFD15FE5` |
| SSDEEP | `1536:fy8aSSIZ/VuFQcNkQ9jzKfELoOsMeQCAmFw3SIrf:DgIZ8FQY72fAsMeQ95f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_96993b86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96993b8671b76325b7b28fc59889e430a6212843a57cf03b9a3ba1725891892a"
    family = "Mirai"
    file_name = "96993b8671b76325.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:26:01"
  condition:
    hash.sha256(0, filesize) == "96993b8671b76325b7b28fc59889e430a6212843a57cf03b9a3ba1725891892a"
}
```

### Sample 24: `99123527030ea61b`

| Field | Value |
|---|---|
| SHA-256 | `99123527030ea61be68481460e5f5265096a180c447416b335db4eeef78b2198` |
| Family label | `Mirai` |
| File name | `99123527030ea61b.bin` |
| File type | `elf` |
| First seen | `2026-11-02 01:25:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21740079ac88afd8f1e7b9d63e239c90` |
| SHA-1 | `a3e3ea3f9eecbe80191458c8d0ea18cc5042eb3e` |
| SHA-256 | `99123527030ea61be68481460e5f5265096a180c447416b335db4eeef78b2198` |
| SHA3-384 | `b7f6a26c69c71630cbd6e0983c4773bbf7c5fd4c1bc871f4259e4afef470b7738b99f234dc792ae3ba72605fce82662f` |
| TLSH | `T119635B02B31C0E47D0A35AB0253F5BE0C7BBA9D121E0F689751E8B969A75E371582FCD` |
| SSDEEP | `1536:XjQqocYx8dEHMlvTW9ZE+YyK11NSXqr4ID/y:XWzBMlvTWFINYq3/y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_99123527
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99123527030ea61be68481460e5f5265096a180c447416b335db4eeef78b2198"
    family = "Mirai"
    file_name = "99123527030ea61b.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:25:55"
  condition:
    hash.sha256(0, filesize) == "99123527030ea61be68481460e5f5265096a180c447416b335db4eeef78b2198"
}
```

### Sample 25: `d7f163cd1aa85321`

| Field | Value |
|---|---|
| SHA-256 | `d7f163cd1aa85321a18024a413177256d03638ef7412da66224e7a65b6c951d1` |
| Family label | `Mirai` |
| File name | `d7f163cd1aa85321.bin` |
| File type | `elf` |
| First seen | `2026-11-02 01:25:48` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0714795a2791b5be0d7621a1acf5bb47` |
| SHA-1 | `8b97f260a2939ef123fadc5dc1485703f663a1e4` |
| SHA-256 | `d7f163cd1aa85321a18024a413177256d03638ef7412da66224e7a65b6c951d1` |
| SHA3-384 | `67a4ebc4d653fd1f704a16ec828fbfa5a82d517fb46909070e5418639ce896eaf9119f7fe323d6b9e92598f2db60d979` |
| TLSH | `T1D893E71ABF510FB7DC6BCD3705E91B1538CC554A22E87B36B934D828B65B20B19E3CA4` |
| SSDEEP | `1536:SWzCtvvtke2cHvab0KZXZAWfnz1EuhICv:SW+tvvtC4KZX9vFv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_d7f163cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7f163cd1aa85321a18024a413177256d03638ef7412da66224e7a65b6c951d1"
    family = "Mirai"
    file_name = "d7f163cd1aa85321.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:25:48"
  condition:
    hash.sha256(0, filesize) == "d7f163cd1aa85321a18024a413177256d03638ef7412da66224e7a65b6c951d1"
}
```

### Sample 26: `9c4ddcfb0606a3f9`

| Field | Value |
|---|---|
| SHA-256 | `9c4ddcfb0606a3f9ac5a67b53cf30276a61db873f346c1c2caf5da9c3eb272ad` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-02 01:20:19` |
| Reporter | `ksi_digital` |
| Tags | `cowrie, elf, Gafgyt, honeypot, Mirai, Torii, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abe3e6ae7d1bb3519448d07cc04036bc` |
| SHA-1 | `d066876b10b9160c70b6fb9ced4e491f23a42632` |
| SHA-256 | `9c4ddcfb0606a3f9ac5a67b53cf30276a61db873f346c1c2caf5da9c3eb272ad` |
| SHA3-384 | `01bf2eb4c27fa356e883274e9a6fba28459ced0b1c088d125db844c39c5fe16bf9ebb8acf5d197efb1f3c858a7411366` |
| TLSH | `T1D1243A07B5D08CFBC4C68AB50BD791328973F8291B36664BB7A8FD951F0DED86A1C604` |
| TELFHASH | `t184815244e83c46dddea31e69adb85fa31943e12623916f1aff2acdc4085e418f514d1f` |
| SSDEEP | `6144:6t/nFv+YCUqes73aWrFTxpkvKHg+heN9KAM7pNNle:6hn9CYEkvKHg+heN9KAM7pNNle` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_9c4ddcfb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c4ddcfb0606a3f9ac5a67b53cf30276a61db873f346c1c2caf5da9c3eb272ad"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-02 01:20:19"
  condition:
    hash.sha256(0, filesize) == "9c4ddcfb0606a3f9ac5a67b53cf30276a61db873f346c1c2caf5da9c3eb272ad"
}
```

### Sample 27: `0550a6acf8888eb6`

| Field | Value |
|---|---|
| SHA-256 | `0550a6acf8888eb660a8e7304ac6a789c3f2dc0ea51b25bec438655d03bc9628` |
| Family label | `unknown` |
| File name | `0550a6acf8888eb660a8e7304ac6a789c3f2dc0ea51b25bec438655d03bc9628.exe` |
| File type | `exe` |
| First seen | `2026-11-02 00:54:51` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51dc7362ac68e985e82e3e90874f2e16` |
| SHA-1 | `1f44c3245f90b12c496f29294d16d4840d6c9970` |
| SHA-256 | `0550a6acf8888eb660a8e7304ac6a789c3f2dc0ea51b25bec438655d03bc9628` |
| SHA3-384 | `98e808cbe2ad26659f7d8897f7a623938c73851431c5706047f08942eade62fb603469c6042e48aa094c11b06f70945e` |
| IMPHASH | `3e5c3f09d1122c97a991d9cb858c2932` |
| TLSH | `T10A35EF52BF990EF9F02A8134B5350502EA61384107E1D6AB5B5F07BECE23AD58FFA750` |
| SSDEEP | `12288:fEFVbfR3A73QOqVih/1tVOdJik8IEuqp1t9DuJZzh0/04WlO0GNe9lPmZmlIdrH2:fEFVt3A4G/fwQk+uMXSJQ5B7M/qeYU` |
| ICON-DHASH | `10481671302a4c30` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_0550a6ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0550a6acf8888eb660a8e7304ac6a789c3f2dc0ea51b25bec438655d03bc9628"
    family = "unknown"
    file_name = "0550a6acf8888eb660a8e7304ac6a789c3f2dc0ea51b25bec438655d03bc9628.exe"
    file_type = "exe"
    first_seen = "2026-11-02 00:54:51"
  condition:
    hash.sha256(0, filesize) == "0550a6acf8888eb660a8e7304ac6a789c3f2dc0ea51b25bec438655d03bc9628"
}
```

### Sample 28: `64fb0d531b51a70c`

| Field | Value |
|---|---|
| SHA-256 | `64fb0d531b51a70cd4a40d4b2ece6c98d7a3d453c5d5b148f4cae75208584677` |
| Family label | `unknown` |
| File name | `macho_64fb0d531b51.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:35:05` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fb42340b85cdfe5e03000901402589a` |
| SHA-1 | `83a3f9220ee7aed0294560bf95b77d4997686582` |
| SHA-256 | `64fb0d531b51a70cd4a40d4b2ece6c98d7a3d453c5d5b148f4cae75208584677` |
| SHA3-384 | `11856b2564b48546efe0d08834a2ebad220fc0dfd2ace2b16f6bc59430d08aa3d73e9e87fbe5d2f346f023b3a6c265cf` |
| TLSH | `T10C8501549A654267E8CD2473DC380FD6D4B07A819A4CB7F86230DF1E2D36A93B1733A6` |
| SSDEEP | `24576:lZRC4OLiDE6tJVtr2OI1Mfst0JgHq5+UJGRggG8QR3daXDTn+F2yOX3hkMlbK4CE:lAL4G1upGGgTSo3hkMN9CO+rWi2ZZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_64fb0d53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64fb0d531b51a70cd4a40d4b2ece6c98d7a3d453c5d5b148f4cae75208584677"
    family = "unknown"
    file_name = "macho_64fb0d531b51.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:35:05"
  condition:
    hash.sha256(0, filesize) == "64fb0d531b51a70cd4a40d4b2ece6c98d7a3d453c5d5b148f4cae75208584677"
}
```

### Sample 29: `b01d5a9d05b788cd`

| Field | Value |
|---|---|
| SHA-256 | `b01d5a9d05b788cdbff787e3317e207caec6b6e08979a1efe0f7764cbfdd86dc` |
| Family label | `unknown` |
| File name | `macho_b01d5a9d05b7.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:33:51` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf003ef2782dd8ad11abb7dceef5a53b` |
| SHA-1 | `ed88872b1bc588bbaf0d76ff2c31398a81b29c84` |
| SHA-256 | `b01d5a9d05b788cdbff787e3317e207caec6b6e08979a1efe0f7764cbfdd86dc` |
| SHA3-384 | `2ff9f607654d11f3fa58b938e1144c3e2ab89eceaae407f5e99b4d615303373d68528cc60d664acc1435e7018a8a8420` |
| TLSH | `T1DB950290AB350286E8072473DE474F45A5D0BA811F549BF5A334D73B1E3778BBE6322A` |
| SSDEEP | `49152:M4Fz3H1QsAuvHow7CUHpY9FCiVqSKSeALFd:pjH2ww97` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_b01d5a9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b01d5a9d05b788cdbff787e3317e207caec6b6e08979a1efe0f7764cbfdd86dc"
    family = "unknown"
    file_name = "macho_b01d5a9d05b7.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:33:51"
  condition:
    hash.sha256(0, filesize) == "b01d5a9d05b788cdbff787e3317e207caec6b6e08979a1efe0f7764cbfdd86dc"
}
```

### Sample 30: `5c18af8d98e6b13d`

| Field | Value |
|---|---|
| SHA-256 | `5c18af8d98e6b13dbf5b8b408d817a302a5239311fff0da0319e11c9d5ce76cb` |
| Family label | `unknown` |
| File name | `macho_5c18af8d98e6.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:32:37` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95ebca90f7322e90f055856fcd7cbe27` |
| SHA-1 | `18b13dac99fc5a4168acd2c525f905f8ae82c99d` |
| SHA-256 | `5c18af8d98e6b13dbf5b8b408d817a302a5239311fff0da0319e11c9d5ce76cb` |
| SHA3-384 | `f5619cc773577ef1ebad6c912df5bbdb9ac530a01c3683878810985a8c7e6cfda066fdd8f90c1404ffd610dd62b3f3bd` |
| TLSH | `T179950124067B3128DA432632A8094FD5589476F86E0CBAF72B25D3663E326E37573773` |
| SSDEEP | `24576:iwsPxS9gbLnqYjb0e3O1ljIVPylbwkLJY7lsWJbZuzwvDKMDMjCHOVlvWVtulby/:iR9bLqCuKJJluzwviMWWh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_5c18af8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c18af8d98e6b13dbf5b8b408d817a302a5239311fff0da0319e11c9d5ce76cb"
    family = "unknown"
    file_name = "macho_5c18af8d98e6.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:32:37"
  condition:
    hash.sha256(0, filesize) == "5c18af8d98e6b13dbf5b8b408d817a302a5239311fff0da0319e11c9d5ce76cb"
}
```

### Sample 31: `54e791eba46a6655`

| Field | Value |
|---|---|
| SHA-256 | `54e791eba46a6655cdc58b8dc7813d27d5fcf94a1bc10468e0334f6cb7f3d32f` |
| Family label | `unknown` |
| File name | `Reroll Bootstrapper.exe` |
| File type | `exe` |
| First seen | `2026-11-02 00:32:10` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed, Stealer, Vidar, VidarStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f24490c6ec2c260472881735798302a7` |
| SHA-1 | `2750a97eaacce553e368246590ce0122acc30924` |
| SHA-256 | `54e791eba46a6655cdc58b8dc7813d27d5fcf94a1bc10468e0334f6cb7f3d32f` |
| SHA3-384 | `40b6159f197234860d355fe8f8626ed9e9476d2838cac5186c928444619cb5b62dbcc723b09955dbe557a09c3516fc40` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T135964B036BA940B8D499EA38C57E4251BB25BC4CC73433DB7F616AB42F517D1ABB8780` |
| SSDEEP | `49152:N6JtiF3Q6RydlzsFK/jOmHClE9EnXdK8uB1vU+g8fMyzzKD+0C+2ev5Cz3xRFtY8:NRybij8TPQgt4gTPaspkw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_54e791eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54e791eba46a6655cdc58b8dc7813d27d5fcf94a1bc10468e0334f6cb7f3d32f"
    family = "unknown"
    file_name = "Reroll Bootstrapper.exe"
    file_type = "exe"
    first_seen = "2026-11-02 00:32:10"
  condition:
    hash.sha256(0, filesize) == "54e791eba46a6655cdc58b8dc7813d27d5fcf94a1bc10468e0334f6cb7f3d32f"
}
```

### Sample 32: `e1b5e175d4ffef09`

| Field | Value |
|---|---|
| SHA-256 | `e1b5e175d4ffef096a2e6ae28cbc80983afb09dde44446297ac78290c46b5a59` |
| Family label | `unknown` |
| File name | `e1b5e175d4ffef096a2e6ae28cbc80983afb09dde44446297ac78290c46b5a59.exe` |
| File type | `exe` |
| First seen | `2026-11-02 00:29:02` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `203076e8e348a45c6a395bd12c1996c0` |
| SHA-1 | `777edc50168fcbaca003a4887fab2579d99bb152` |
| SHA-256 | `e1b5e175d4ffef096a2e6ae28cbc80983afb09dde44446297ac78290c46b5a59` |
| SHA3-384 | `e4bdc4745214c52ce45dd3805080bb5f19a632e05b283454ee90b64f0105583df0ed5fa364b6031f3000cf72ef4a7544` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16605D01C73E98E22F1BF6BBA647112466236B897DA35D74C0CC760EC1E70BD18850BA7` |
| SSDEEP | `24576:Q9iGqiSnPNIojxhBEnwRXxjcrEjRZgNIojxhBEn:QSq0L62hCYLgq0L6` |
| ICON-DHASH | `9671d1d4c5553116` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_e1b5e175
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1b5e175d4ffef096a2e6ae28cbc80983afb09dde44446297ac78290c46b5a59"
    family = "unknown"
    file_name = "e1b5e175d4ffef096a2e6ae28cbc80983afb09dde44446297ac78290c46b5a59.exe"
    file_type = "exe"
    first_seen = "2026-11-02 00:29:02"
  condition:
    hash.sha256(0, filesize) == "e1b5e175d4ffef096a2e6ae28cbc80983afb09dde44446297ac78290c46b5a59"
}
```

### Sample 33: `15169c97b1503d59`

| Field | Value |
|---|---|
| SHA-256 | `15169c97b1503d59aa974bad5583e2a0c1fe96a9f00987f9742f18eec7b7d2f0` |
| Family label | `SalatStealer` |
| File name | `a7076f32e0c79a95.bin` |
| File type | `exe` |
| First seen | `2026-11-02 00:25:35` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `624133b8c12959397f188e55934a6df1` |
| SHA-1 | `c45838acd9fd36b23b10fe5f389f0f2ce43b1441` |
| SHA-256 | `15169c97b1503d59aa974bad5583e2a0c1fe96a9f00987f9742f18eec7b7d2f0` |
| SHA3-384 | `36a614ace0426d630564d01872d6d8a2d783b995f266a630a95d12a68d79bed87a9ba49b7db9bdbef5dc42f685776fa8` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T13CC65B11FADB95F1E903183141ABB37F23315D048B28DB9BEB547B2AF87B6A11C66305` |
| SSDEEP | `98304:vLeG61elNbCGfnf0t0E6VzcV57OU714tG20CWEY:N6ajfffE6GZHCY` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_033_15169c97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15169c97b1503d59aa974bad5583e2a0c1fe96a9f00987f9742f18eec7b7d2f0"
    family = "SalatStealer"
    file_name = "a7076f32e0c79a95.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:25:35"
  condition:
    hash.sha256(0, filesize) == "15169c97b1503d59aa974bad5583e2a0c1fe96a9f00987f9742f18eec7b7d2f0"
}
```

### Sample 34: `0540d635edb31efd`

| Field | Value |
|---|---|
| SHA-256 | `0540d635edb31efd4ea4b026f1aa526ae991fc4cd214ba91930ce04a5be280f8` |
| Family label | `SalatStealer` |
| File name | `0be112428e866e9a.bin` |
| File type | `exe` |
| First seen | `2026-11-02 00:25:30` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c1130f742aab9764670c61b91e10596` |
| SHA-1 | `bbcea6218b405ef99e4c2002adae7f3a2d44f32b` |
| SHA-256 | `0540d635edb31efd4ea4b026f1aa526ae991fc4cd214ba91930ce04a5be280f8` |
| SHA3-384 | `d0d276ebf846a17b5e63492ad2e13b8d39fc0c4cde134333c4709f7a715466ac65b8773876bf607709392e75d8c5f36f` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1BFC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+C:yBkKr5rszpNDy+C` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_034_0540d635
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0540d635edb31efd4ea4b026f1aa526ae991fc4cd214ba91930ce04a5be280f8"
    family = "SalatStealer"
    file_name = "0be112428e866e9a.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:25:30"
  condition:
    hash.sha256(0, filesize) == "0540d635edb31efd4ea4b026f1aa526ae991fc4cd214ba91930ce04a5be280f8"
}
```

### Sample 35: `4afc0af2fe1a66a7`

| Field | Value |
|---|---|
| SHA-256 | `4afc0af2fe1a66a740b72a9ab743df63e2b5c2746717c1e7b29828929bf83064` |
| Family label | `SalatStealer` |
| File name | `cd1ce568547d8816.bin` |
| File type | `exe` |
| First seen | `2026-11-02 00:25:25` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1d3049eb3946d624fa4cde56cd08f81` |
| SHA-1 | `2a191bef8a8c91b189af6554231316866069debf` |
| SHA-256 | `4afc0af2fe1a66a740b72a9ab743df63e2b5c2746717c1e7b29828929bf83064` |
| SHA3-384 | `ef246e70c5ca61a97424ef01b1e4955e9b7d243d9e8f5c3c3b1ecf8a5ab50dbe214a8ec6715b1e2537bf4c37168160e5` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T199C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+i:yBkKr5rszpNDy+i` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_035_4afc0af2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4afc0af2fe1a66a740b72a9ab743df63e2b5c2746717c1e7b29828929bf83064"
    family = "SalatStealer"
    file_name = "cd1ce568547d8816.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:25:25"
  condition:
    hash.sha256(0, filesize) == "4afc0af2fe1a66a740b72a9ab743df63e2b5c2746717c1e7b29828929bf83064"
}
```

### Sample 36: `68e2d57df807683c`

| Field | Value |
|---|---|
| SHA-256 | `68e2d57df807683c12accac30940ead9be2b7589e33f8cf20abbdc324f09b112` |
| Family label | `Mirai` |
| File name | `68e2d57df807683c.bin` |
| File type | `elf` |
| First seen | `2026-11-02 00:24:58` |
| Reporter | `Tuxxin` |
| Tags | `elf, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d7cc2984f79f0f0bfc2399c9ef1ff15` |
| SHA-1 | `d0cfcdd95620ee71efb8c296fffcf8ca2e0d74ba` |
| SHA-256 | `68e2d57df807683c12accac30940ead9be2b7589e33f8cf20abbdc324f09b112` |
| SHA3-384 | `999366f2cc199c3d39b3ced998da951d6335bd0c060110ccfcd807c15c55056f03f5418c75e570857945ac043ccaf2c5` |
| TLSH | `T1C0831A56F8814B22C5C512BAF96E118E332327F8E3DEB2129D215F247BC692B0E37D55` |
| TELFHASH | `t13011cc72df942adc53e0879587998a3e4da631f027833962cf2d1b5e0a98dd0b45e031` |
| SSDEEP | `1536:G6ncUVKzSZdfmaBVUvUMe9uCRV+pQ1ai56zc1EIRjijj8Ix/o785qYmIodaEU:tKzSvfxBsUMDK1aIVCj8Ix/o784JaE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_68e2d57d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68e2d57df807683c12accac30940ead9be2b7589e33f8cf20abbdc324f09b112"
    family = "Mirai"
    file_name = "68e2d57df807683c.bin"
    file_type = "elf"
    first_seen = "2026-11-02 00:24:58"
  condition:
    hash.sha256(0, filesize) == "68e2d57df807683c12accac30940ead9be2b7589e33f8cf20abbdc324f09b112"
}
```

### Sample 37: `f12d41436ae0aefe`

| Field | Value |
|---|---|
| SHA-256 | `f12d41436ae0aefec023d75df0f877e2e011bb31e1e3a2ec89f7bda6b483e386` |
| Family label | `AveMariaRAT` |
| File name | `f12d41436ae0aefe.bin` |
| File type | `exe` |
| First seen | `2026-11-02 00:24:49` |
| Reporter | `Tuxxin` |
| Tags | `AveMariaRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5cc56d7103d345de96571630c12e248b` |
| SHA-1 | `b14865f813d66ce7540b84cbd0cd2a5e5815757f` |
| SHA-256 | `f12d41436ae0aefec023d75df0f877e2e011bb31e1e3a2ec89f7bda6b483e386` |
| SHA3-384 | `560fb683b44f8cb8372a0fb1b540c9e7d038b6b95ada6f9bc4e17d83ed4905c6bcffa21ffc235b364f98fc2f297549f5` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T121647C9C726076EFC85BD472DEA82CA4FA64787B831F4243A02715ADDA4D997CF140F2` |
| SSDEEP | `6144:hWFTI7jEYEb1St6mBzyQF/xWKNyD9EOoA8d67C8i9LMyOTvimJJgg671ybI:8N4jEYYqZzyQF0nD6Oo/qipOTvrJJggq` |

#### Technical Assessment

- The sample is tracked as `AveMariaRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AveMariaRAT_037_f12d4143
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f12d41436ae0aefec023d75df0f877e2e011bb31e1e3a2ec89f7bda6b483e386"
    family = "AveMariaRAT"
    file_name = "f12d41436ae0aefe.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:24:49"
  condition:
    hash.sha256(0, filesize) == "f12d41436ae0aefec023d75df0f877e2e011bb31e1e3a2ec89f7bda6b483e386"
}
```

### Sample 38: `a7076f32e0c79a95`

| Field | Value |
|---|---|
| SHA-256 | `a7076f32e0c79a9574f70102a5baba65894fb9e01504b28cbf657ebeb6ebc081` |
| Family label | `SalatStealer` |
| File name | `a7076f32e0c79a95.bin` |
| File type | `exe` |
| First seen | `2026-11-02 00:24:41` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bbd832e0c634d6584c2017b74a941a6` |
| SHA-1 | `e9a440a82ca98f630331c4b7a3b1f7f257a8b1d6` |
| SHA-256 | `a7076f32e0c79a9574f70102a5baba65894fb9e01504b28cbf657ebeb6ebc081` |
| SHA3-384 | `ea821ea062bc0d3be0ef7ab69c7071152c84c85f58af875f05666ae962a64e0ed09fcc938b1fffe8a8b0d0b815dc4988` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T177F533592E8CA07BF1C3427D215CA77F8ACDCAB1CD41B37D2151E672E96C86694902F3` |
| SSDEEP | `49152:hPVUAIkufHAFeyW+TRBq2xsueMAlML0QHHMl8FoJapJQPpCLnci95PqAAh46/1:lOWFJW+TS2heML0qlpJupji9xqp` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_038_a7076f32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7076f32e0c79a9574f70102a5baba65894fb9e01504b28cbf657ebeb6ebc081"
    family = "SalatStealer"
    file_name = "a7076f32e0c79a95.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:24:41"
  condition:
    hash.sha256(0, filesize) == "a7076f32e0c79a9574f70102a5baba65894fb9e01504b28cbf657ebeb6ebc081"
}
```

### Sample 39: `0be112428e866e9a`

| Field | Value |
|---|---|
| SHA-256 | `0be112428e866e9aec6b54629a4e07dc21773764f4dadf33bb81fae0077a4194` |
| Family label | `SalatStealer` |
| File name | `0be112428e866e9a.bin` |
| File type | `exe` |
| First seen | `2026-11-02 00:24:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6816d45dc19afbd7280b75769ed935eb` |
| SHA-1 | `8bbd11947dc8f21e4d4b183c6bccad43e8c0ba6a` |
| SHA-256 | `0be112428e866e9aec6b54629a4e07dc21773764f4dadf33bb81fae0077a4194` |
| SHA3-384 | `262d0c13e67829f0fea8af87f48996ba5ae1bea416e984e807975bfd6e9baf3b3242ad92ff4d30ba462823fdd18a9c18` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T147F5335BF1AB47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ou:iJiafuIO7rhWEES4X` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_039_0be11242
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0be112428e866e9aec6b54629a4e07dc21773764f4dadf33bb81fae0077a4194"
    family = "SalatStealer"
    file_name = "0be112428e866e9a.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:24:35"
  condition:
    hash.sha256(0, filesize) == "0be112428e866e9aec6b54629a4e07dc21773764f4dadf33bb81fae0077a4194"
}
```

### Sample 40: `cd1ce568547d8816`

| Field | Value |
|---|---|
| SHA-256 | `cd1ce568547d88162740ae66190335a2ee53ae0bf69ac6a011ad58b8c703dfe3` |
| Family label | `SalatStealer` |
| File name | `cd1ce568547d8816.bin` |
| File type | `exe` |
| First seen | `2026-11-02 00:24:26` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84df927465d9903362efdfea3ba8b343` |
| SHA-1 | `b797dcceb2a403cf3dfa7e82ce0e1e8afd003bf4` |
| SHA-256 | `cd1ce568547d88162740ae66190335a2ee53ae0bf69ac6a011ad58b8c703dfe3` |
| SHA3-384 | `0c1f7d27c4826d7c373cde7cf36f6237ddb9db37d59c62ccb94a78e43ec425232d46f062f1c9f41339ac491a695efaf5` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T110F5335BF1AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OO:iJiafuIO7rhWEES4T` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_040_cd1ce568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd1ce568547d88162740ae66190335a2ee53ae0bf69ac6a011ad58b8c703dfe3"
    family = "SalatStealer"
    file_name = "cd1ce568547d8816.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:24:26"
  condition:
    hash.sha256(0, filesize) == "cd1ce568547d88162740ae66190335a2ee53ae0bf69ac6a011ad58b8c703dfe3"
}
```

### Sample 41: `badc769369c229bd`

| Field | Value |
|---|---|
| SHA-256 | `badc769369c229bdde0b306aafd47ee59ce052a9dfb741a0b30432af08281328` |
| Family label | `unknown` |
| File name | `temp.hta` |
| File type | `hta` |
| First seen | `2026-11-02 00:24:02` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1560dae7a85178f6e70a40528af498ad` |
| SHA-1 | `7b31775e1c219808892c47e31654720dc93d32e1` |
| SHA-256 | `badc769369c229bdde0b306aafd47ee59ce052a9dfb741a0b30432af08281328` |
| SHA3-384 | `1f4509d151dee7e1669491fa83f650f973a5c2c7f06b122f8be78ca901721c96af06448e8b0e7b0a824c7026dcc97216` |
| TLSH | `T1D132185CAED0A1A0FA0707DEB7AF25690228A0C7200DC484F54CDEE87F4A7DC4A56B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzufbqFtCfS1RUM:sXX+/DV7k/3uWFt1RUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_badc7693
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "badc769369c229bdde0b306aafd47ee59ce052a9dfb741a0b30432af08281328"
    family = "unknown"
    file_name = "temp.hta"
    file_type = "hta"
    first_seen = "2026-11-02 00:24:02"
  condition:
    hash.sha256(0, filesize) == "badc769369c229bdde0b306aafd47ee59ce052a9dfb741a0b30432af08281328"
}
```

### Sample 42: `d1263c84e72f9534`

| Field | Value |
|---|---|
| SHA-256 | `d1263c84e72f95341111a570b633a7fb7ee571ab27bfe7d6eb3de527b127b4e9` |
| Family label | `unknown` |
| File name | `macho_d1263c84e72f.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:23:17` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edf483577b731bdc9cb68f4a054d700a` |
| SHA-1 | `159d9e6e646ef78e77139f1d28db590c688acd3c` |
| SHA-256 | `d1263c84e72f95341111a570b633a7fb7ee571ab27bfe7d6eb3de527b127b4e9` |
| SHA3-384 | `0597fe3bbac31c0f3db72c97e03e69abf71b5d20e9e6ce05effc0f9cd1d9c732e0d0c5b65f77dae403f9cb6f026ee6c5` |
| TLSH | `T1F7A5D050DF1FA0EBD54A11338CAA4F5984746080CE48DEED5381F3AADE367A377129B6` |
| SSDEEP | `24576:LBwGFPWVFjH0Z7Kw1TArBtWrKoCI63CVOtauqLkIq6EALk6aNl60Wz9coEglYtX1:9nK2CtuVIB/r6Eqk/Nl60Wz9coOBm3w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_d1263c84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1263c84e72f95341111a570b633a7fb7ee571ab27bfe7d6eb3de527b127b4e9"
    family = "unknown"
    file_name = "macho_d1263c84e72f.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:23:17"
  condition:
    hash.sha256(0, filesize) == "d1263c84e72f95341111a570b633a7fb7ee571ab27bfe7d6eb3de527b127b4e9"
}
```

### Sample 43: `ba2fb68385233683`

| Field | Value |
|---|---|
| SHA-256 | `ba2fb68385233683f785e3bae69cb79360a2a6c48b43b44f9c43a3b8f54ca1a9` |
| Family label | `unknown` |
| File name | `macho_ba2fb6838523.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:22:03` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d369b210f8dc4d7af2d1f489d59d4c91` |
| SHA-1 | `7f9a895d88aa56323b8f2e6f524fd88e154f3ee3` |
| SHA-256 | `ba2fb68385233683f785e3bae69cb79360a2a6c48b43b44f9c43a3b8f54ca1a9` |
| SHA3-384 | `79b86d759490dbafc3300b224da7cf74577b542474827d2c1a9a5a74344bc5df0351479c626d01788eae8f426534de2b` |
| TLSH | `T1CD850228562752ACE502177A9C540FD114A2A3E12E047FFA2B15F7F52D30EE7FA62372` |
| SSDEEP | `24576:14Myt2Ooy1N6BDYT23sMFoNQ0cJisPA+b6gTMGEKvcBv0kiAMyPsN6dnD9OBn+rP:1jzHGvwSuMeBkiLyPsNcDUBME00ML` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_ba2fb683
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba2fb68385233683f785e3bae69cb79360a2a6c48b43b44f9c43a3b8f54ca1a9"
    family = "unknown"
    file_name = "macho_ba2fb6838523.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:22:03"
  condition:
    hash.sha256(0, filesize) == "ba2fb68385233683f785e3bae69cb79360a2a6c48b43b44f9c43a3b8f54ca1a9"
}
```

### Sample 44: `a881c160d2bec460`

| Field | Value |
|---|---|
| SHA-256 | `a881c160d2bec4607bbd9a0be4e4b5fcd4fa9a230a792df1ff1d049a785b45de` |
| Family label | `unknown` |
| File name | `macho_a881c160d2be.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:20:48` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `756ba0ec897963559a66aae8c52589dd` |
| SHA-1 | `215d4e1a584ac778add2757ca1718ed447d7e543` |
| SHA-256 | `a881c160d2bec4607bbd9a0be4e4b5fcd4fa9a230a792df1ff1d049a785b45de` |
| SHA3-384 | `6089794f7e85b59b72c45c9e782dd0975e728003d427e10450adb28b6483387943b9373515e2b94c8685797ded7e8977` |
| TLSH | `T110B5E1405EAE9216D49900B39C8A8F59467431E0CF88CEE95312A3DADE3D3E377671B7` |
| SSDEEP | `24576:g2vlUzP24JVvHEncLKZ6P2r5LPYIPtRmno0VLL+oWgZGpC15Z1sQhb1k:gFzu43wPano0VLLlPZG0t1U` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_a881c160
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a881c160d2bec4607bbd9a0be4e4b5fcd4fa9a230a792df1ff1d049a785b45de"
    family = "unknown"
    file_name = "macho_a881c160d2be.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:20:48"
  condition:
    hash.sha256(0, filesize) == "a881c160d2bec4607bbd9a0be4e4b5fcd4fa9a230a792df1ff1d049a785b45de"
}
```

### Sample 45: `93c9298f7f23e0bd`

| Field | Value |
|---|---|
| SHA-256 | `93c9298f7f23e0bdfc19785099fc85bb04acae14bbfe9f9cc3cb9355447ac47c` |
| Family label | `unknown` |
| File name | `macho_93c9298f7f23.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:19:31` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d95256b75782301d7e5dd51b8486f2ea` |
| SHA-1 | `2ef73677b8832ad091171452c5e7f31822fc6012` |
| SHA-256 | `93c9298f7f23e0bdfc19785099fc85bb04acae14bbfe9f9cc3cb9355447ac47c` |
| SHA3-384 | `012d404a5aa07971000f0d3bab3956217bc61f1c42c7df0d41644c368236a57f090f4d298b4f626dc8a2210aafab22f7` |
| TLSH | `T15895F158DA75926AE4E2307FCC140F0140D066A0ABD8A6F7A610EF672D395D3F6F3276` |
| SSDEEP | `49152:1ouNAG+uCo5GAxBmfp5zK7hLerhqpOpAX9nGOuoj:MAmfp5zKN9R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_93c9298f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93c9298f7f23e0bdfc19785099fc85bb04acae14bbfe9f9cc3cb9355447ac47c"
    family = "unknown"
    file_name = "macho_93c9298f7f23.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:19:31"
  condition:
    hash.sha256(0, filesize) == "93c9298f7f23e0bdfc19785099fc85bb04acae14bbfe9f9cc3cb9355447ac47c"
}
```

### Sample 46: `a82977df5edeff77`

| Field | Value |
|---|---|
| SHA-256 | `a82977df5edeff7790dd7fc67672afd2fb152fd2584269477a8f353a8384f94a` |
| Family label | `unknown` |
| File name | `macho_a82977df5ede.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:18:14` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2040af4c7f8fae81cfbbe62f6f34972` |
| SHA-1 | `73aab1249b76b5c61a875e8a558d17cfb1c2e993` |
| SHA-256 | `a82977df5edeff7790dd7fc67672afd2fb152fd2584269477a8f353a8384f94a` |
| SHA3-384 | `69857f7b6ed5781228e42f55f1efc110d480a2410162f33c38e182c391019e50e429d695e0497034a813136e6915f4be` |
| TLSH | `T165A5F1581A71037AE58E2033D9060F4A55B0B6F15F4CB6EDE2A6D2426CFE3D3B5A3316` |
| SSDEEP | `24576:6xcQlGkFI8EYnShvZT5V9ULHwxpod+YLP52YJC8wxYpcMJBlaG4EV6cnR/2Dp4J9:gIr9hxqd+FYJPcWpJBai6cED+J+lkZ5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_a82977df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a82977df5edeff7790dd7fc67672afd2fb152fd2584269477a8f353a8384f94a"
    family = "unknown"
    file_name = "macho_a82977df5ede.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:18:14"
  condition:
    hash.sha256(0, filesize) == "a82977df5edeff7790dd7fc67672afd2fb152fd2584269477a8f353a8384f94a"
}
```

### Sample 47: `d3146700547025c3`

| Field | Value |
|---|---|
| SHA-256 | `d3146700547025c387b0f3e707f391d59f2b62c4c60b6ecbf5134c79e01d67e1` |
| Family label | `unknown` |
| File name | `macho_d31467005470.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:16:58` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb29d29507088d065a3f658ee65767e1` |
| SHA-1 | `ca5c2f79df2239aab7f2c2c809aef80ff27a529d` |
| SHA-256 | `d3146700547025c387b0f3e707f391d59f2b62c4c60b6ecbf5134c79e01d67e1` |
| SHA3-384 | `24f585328166f092542c937afddea6dba91f53163ab8e05fc448a26dc4f6154e425d26d9982328f0f0e7bc22f0078d92` |
| TLSH | `T1F285F1E0BBE6015EE4856873ED147F554490B9815B0CEAFCA130CB176D36BB3F6A3262` |
| SSDEEP | `49152:YAN1WBK47L2k33pnnNw4Oh3ZcU4ZRKVFflyKxg:xmKmNw4Oh3ZcwQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_d3146700
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3146700547025c387b0f3e707f391d59f2b62c4c60b6ecbf5134c79e01d67e1"
    family = "unknown"
    file_name = "macho_d31467005470.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:16:58"
  condition:
    hash.sha256(0, filesize) == "d3146700547025c387b0f3e707f391d59f2b62c4c60b6ecbf5134c79e01d67e1"
}
```

### Sample 48: `ec038d8ecdc9f337`

| Field | Value |
|---|---|
| SHA-256 | `ec038d8ecdc9f33786ec79dab5b30ac1682bc9378540e1a7e775dda5c8bdb6b5` |
| Family label | `unknown` |
| File name | `macho_ec038d8ecdc9.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:15:45` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06afcb227e160a245d234005bfa785de` |
| SHA-1 | `1273be400765ec0044ba528f676f762903442d45` |
| SHA-256 | `ec038d8ecdc9f33786ec79dab5b30ac1682bc9378540e1a7e775dda5c8bdb6b5` |
| SHA3-384 | `3d3096b3e9e45995f6c97db9c8ef33b140c29f6e3d3144ee52be16fd4a7e688903b822e0631eeca791e9e0581870b7ae` |
| TLSH | `T18C95F1808EAEE146E48D4173DC898B1A447432E0CE49DDE96302639ADE3D3E777572B7` |
| SSDEEP | `24576:tpLPCX6d149BaLzfARnLxL2fGxZ3UpsNOE317RRVuoatM3/1Bwbkj1DErot:LsAfzfmfLkKNDF7RRVHaKJpQ8t` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_ec038d8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec038d8ecdc9f33786ec79dab5b30ac1682bc9378540e1a7e775dda5c8bdb6b5"
    family = "unknown"
    file_name = "macho_ec038d8ecdc9.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:15:45"
  condition:
    hash.sha256(0, filesize) == "ec038d8ecdc9f33786ec79dab5b30ac1682bc9378540e1a7e775dda5c8bdb6b5"
}
```

### Sample 49: `fbd3d3650f2b9dfe`

| Field | Value |
|---|---|
| SHA-256 | `fbd3d3650f2b9dfe6a0949b42e5ece6757b52506e536481982885619c5e12c74` |
| Family label | `unknown` |
| File name | `a` |
| File type | `elf` |
| First seen | `2026-11-02 00:15:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19df83cd16a818a35e64f14b0bdb1eed` |
| SHA-1 | `5136e91fa0da56054bd22490f53960f37075eb54` |
| SHA-256 | `fbd3d3650f2b9dfe6a0949b42e5ece6757b52506e536481982885619c5e12c74` |
| SHA3-384 | `6367e279908d02bbde22da1e0da7fc013009b345dc54a20896aa6714b1119c91118da53c1bccfc7605149a91a07f9a09` |
| TLSH | `T12BD54A5BBC529992C4D426BAF96DC188330753B8C3DA3206ED04CB397ADF89A0D3DB55` |
| TELFHASH | `t1d3a012554134005c37d1000c08710637058c7c8587104450cb0cd0104a32880324ce31` |
| SSDEEP | `24576:SrfjK8Z5+BOnP3hR5PYK/ZVmty1YZEfpqAMwo1Gz1Tt2RnJ2Tf7kdpkGylyE/17b:SrLX93RYY1SwE1w8dpql1indnr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_fbd3d365
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbd3d3650f2b9dfe6a0949b42e5ece6757b52506e536481982885619c5e12c74"
    family = "unknown"
    file_name = "a"
    file_type = "elf"
    first_seen = "2026-11-02 00:15:26"
  condition:
    hash.sha256(0, filesize) == "fbd3d3650f2b9dfe6a0949b42e5ece6757b52506e536481982885619c5e12c74"
}
```

### Sample 50: `b3b6bcd89152a5e8`

| Field | Value |
|---|---|
| SHA-256 | `b3b6bcd89152a5e8f9f18a814aad8b725ef89675f78f6080b86549b7ee98c5f5` |
| Family label | `unknown` |
| File name | `a` |
| File type | `elf` |
| First seen | `2026-11-02 00:14:37` |
| Reporter | `adliwahid` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `004c4208a37ead7188e6cd658cd6320a` |
| SHA-1 | `ad1d962c1d7a68c2d7682ab475455b5150155443` |
| SHA-256 | `b3b6bcd89152a5e8f9f18a814aad8b725ef89675f78f6080b86549b7ee98c5f5` |
| SHA3-384 | `a538e41700e3c37ebcc5610288779d770a9275e50f16e28770515b88090818a75bd39f97c349964affad557d44baa65e` |
| TLSH | `T17A55337824883B89715F8828E5EF3FB47A1FA656E5744FF11179B21CD7C11029D5AF02` |
| SSDEEP | `24576:QvuFBUGwCGg2bl8zAIOlTU0Q13PAPskG6nSE8NqJda0HBKd6HWVnuV4iZ7X2:7HwTbeFsT0hPIsVNIpX227m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_b3b6bcd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3b6bcd89152a5e8f9f18a814aad8b725ef89675f78f6080b86549b7ee98c5f5"
    family = "unknown"
    file_name = "a"
    file_type = "elf"
    first_seen = "2026-11-02 00:14:37"
  condition:
    hash.sha256(0, filesize) == "b3b6bcd89152a5e8f9f18a814aad8b725ef89675f78f6080b86549b7ee98c5f5"
}
```

### Sample 51: `197596c12388be1a`

| Field | Value |
|---|---|
| SHA-256 | `197596c12388be1a4e07197e5b98535472a672ceab2db16c8c3737a025ffbb0d` |
| Family label | `unknown` |
| File name | `macho_197596c12388.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:14:31` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10f7fc155a0205c298ef1d49e3148fdc` |
| SHA-1 | `845397718228e28f3b7b2694145e765cfbf78ee6` |
| SHA-256 | `197596c12388be1a4e07197e5b98535472a672ceab2db16c8c3737a025ffbb0d` |
| SHA3-384 | `bda033e63ce2445e21ba4e648550ec86c271df7689eb639d4a21aebf5ac21d66dd9b16c7bedce73bdafa0bb7af8d0711` |
| TLSH | `T15785E1202AEDD22AE4952032A8100FFE5170B7B56E0DA5F456278E176C3D9D3B7A731F` |
| SSDEEP | `24576:T2AzZG8Kkp78cPa4Xw7Az1b+NSX/uxve/W6TWflp/pM+hV4IDOhXfw18n/7:0o1jw7gEoyveuPb/pM+huk4Yc7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_197596c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "197596c12388be1a4e07197e5b98535472a672ceab2db16c8c3737a025ffbb0d"
    family = "unknown"
    file_name = "macho_197596c12388.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:14:31"
  condition:
    hash.sha256(0, filesize) == "197596c12388be1a4e07197e5b98535472a672ceab2db16c8c3737a025ffbb0d"
}
```

### Sample 52: `632f6638213ec54c`

| Field | Value |
|---|---|
| SHA-256 | `632f6638213ec54ccbe405cfc1fecbf8bacf137cb945195e7631ac72618721db` |
| Family label | `unknown` |
| File name | `e` |
| File type | `elf` |
| First seen | `2026-11-02 00:14:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e76cd204de945cd0260517096a014ac0` |
| SHA-1 | `8d65b0411699efe32d7d0163656ae73c7947becf` |
| SHA-256 | `632f6638213ec54ccbe405cfc1fecbf8bacf137cb945195e7631ac72618721db` |
| SHA3-384 | `d7a5c199e5181c8eb725507b7b7f104296e92c8c55ebe0b6814886f3e9c07c449de414ddd4341658e6775d1dd5f14050` |
| TLSH | `T1BF066C0E7F081FDBC55ECF30897EC727066C595B4AF21B25AE2C8544BAAA2861F17D1C` |
| SSDEEP | `49152:h/nHVJHL+HLS/hYXtuwSOsh49ZRTXYcUeWNdWkbd8Hkg+5Ly5onA:hLES/hYXtuwSOsh49ZFuzDB6+p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_632f6638
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "632f6638213ec54ccbe405cfc1fecbf8bacf137cb945195e7631ac72618721db"
    family = "unknown"
    file_name = "e"
    file_type = "elf"
    first_seen = "2026-11-02 00:14:16"
  condition:
    hash.sha256(0, filesize) == "632f6638213ec54ccbe405cfc1fecbf8bacf137cb945195e7631ac72618721db"
}
```

### Sample 53: `62afc2f766f957cb`

| Field | Value |
|---|---|
| SHA-256 | `62afc2f766f957cb2508a957b040def43540ad35e6dcdf89c38acd545555393e` |
| Family label | `unknown` |
| File name | `e` |
| File type | `elf` |
| First seen | `2026-11-02 00:13:54` |
| Reporter | `adliwahid` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f145d32beaea164429b678d76a49ce1` |
| SHA-1 | `56c8611395e2d15548ca89d7cf3c4bf77a80b447` |
| SHA-256 | `62afc2f766f957cb2508a957b040def43540ad35e6dcdf89c38acd545555393e` |
| SHA3-384 | `047e6b0765060b1b22015762b521c33e35d87b2c49648efd1d730234d205a46e41b27fd8b5f4629b2d15f8cfb64b7de1` |
| TLSH | `T1AC75332558B3519AE9962831E20473EAA8FBB9E14CDFE7C74C35FE201EFC753A610215` |
| SSDEEP | `24576:70K2icuwb8l1YWdXEHUlXXzhqrklKDMzRGvYdQoL3S03sssKAqbsFtUetYaHQCt:4dhyggtX14DBZj/KAHHQCt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_62afc2f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62afc2f766f957cb2508a957b040def43540ad35e6dcdf89c38acd545555393e"
    family = "unknown"
    file_name = "e"
    file_type = "elf"
    first_seen = "2026-11-02 00:13:54"
  condition:
    hash.sha256(0, filesize) == "62afc2f766f957cb2508a957b040def43540ad35e6dcdf89c38acd545555393e"
}
```

### Sample 54: `b92921e81666ba02`

| Field | Value |
|---|---|
| SHA-256 | `b92921e81666ba02fcd593c5f18aa8952b639d1fe7d13849677dd27954c479e8` |
| Family label | `unknown` |
| File name | `macho_b92921e81666.bin` |
| File type | `macho` |
| First seen | `2026-11-02 00:13:17` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `804032075116752d81b181446eeaa3a8` |
| SHA-1 | `df200beaa43c9ce0522fa047ebc9cc59a1e24be3` |
| SHA-256 | `b92921e81666ba02fcd593c5f18aa8952b639d1fe7d13849677dd27954c479e8` |
| SHA3-384 | `eb7f97e405e5e09d8dad8a4dd174c6ad320b7e456191a20536b5fc852d98bf01ae30f83031297e8b698a2b1d51e4f97b` |
| TLSH | `T1F185F1509B6612AAF583EC718DC80BD0655063B06E887AF97B10C7756E36DE3B4F2372` |
| SSDEEP | `24576:FtHGiBg33IDbdq2fSzBjWjtqiG23b0cxy1nfKUYcXGY2uic8f9TW7/siWcHD83:rHGwnc2faUK29+f5Yc2Y3Qg6mw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_b92921e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b92921e81666ba02fcd593c5f18aa8952b639d1fe7d13849677dd27954c479e8"
    family = "unknown"
    file_name = "macho_b92921e81666.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:13:17"
  condition:
    hash.sha256(0, filesize) == "b92921e81666ba02fcd593c5f18aa8952b639d1fe7d13849677dd27954c479e8"
}
```

### Sample 55: `d831b3af47457188`

| Field | Value |
|---|---|
| SHA-256 | `d831b3af4745718800a65012da063f1ab7a10f0c6853ac4290c8c96621829af3` |
| Family label | `unknown` |
| File name | `zx` |
| File type | `sh` |
| First seen | `2026-11-02 00:12:19` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `169fbfd150e9050ebf39bd28223a14b4` |
| SHA-1 | `46a5dc8f48576198aacb5e06bde7e047f6276db0` |
| SHA-256 | `d831b3af4745718800a65012da063f1ab7a10f0c6853ac4290c8c96621829af3` |
| SHA3-384 | `054853b55d40e5f29605d6ed27e2a757f7cdcf19e9ea04f946c4bda9f109348fc70a7dc663e41d6ee16029d84a3dd7e9` |
| TLSH | `T1EC01C0ACFB300C31F90D0C1C550E5BE49CC7985319606D54D6D67CF0AA6FC0D2241621` |
| SSDEEP | `12:YEkn+peArlN60caViFCZYBvmNMwfwlpka9FhdbxWw0n:YEk+peAtV6C31mjb/WNn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_d831b3af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d831b3af4745718800a65012da063f1ab7a10f0c6853ac4290c8c96621829af3"
    family = "unknown"
    file_name = "zx"
    file_type = "sh"
    first_seen = "2026-11-02 00:12:19"
  condition:
    hash.sha256(0, filesize) == "d831b3af4745718800a65012da063f1ab7a10f0c6853ac4290c8c96621829af3"
}
```

### Sample 56: `f3b9bca4c11c0156`

| Field | Value |
|---|---|
| SHA-256 | `f3b9bca4c11c01561c52db79c81456a70d205a9e333bb27de4a35ad511f2c471` |
| Family label | `Mirai` |
| File name | `x` |
| File type | `elf` |
| First seen | `2026-11-02 00:11:01` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc7596db148b5d0438b5a3c57ac6b4a8` |
| SHA-1 | `73b8de98d107c1f2a9767418f1f77f31cd15a7a1` |
| SHA-256 | `f3b9bca4c11c01561c52db79c81456a70d205a9e333bb27de4a35ad511f2c471` |
| SHA3-384 | `35e74e3d265e963aa5d86ab7b5f007313d5e841826e504ee308e1e5dacfb82b54579c2eef0d4d07e2a8ab93eef444a6a` |
| TLSH | `T1E2765D5BB4BB10ADC65BC070839FD2326E35785801653E7B7A84DAB02F56F601B6EF21` |
| TELFHASH | `t136e220744ae874f2a2e5c99af772f174aa3354fa5be4b57000273d52cff0e5d082a816` |
| SSDEEP | `98304:/VMSb3C9kx9DEITz0JvaMo651RN1OdpwwynfsrWjQTu7a+YN:NVcgRyoW1PXsus1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_f3b9bca4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3b9bca4c11c01561c52db79c81456a70d205a9e333bb27de4a35ad511f2c471"
    family = "Mirai"
    file_name = "x"
    file_type = "elf"
    first_seen = "2026-11-02 00:11:01"
  condition:
    hash.sha256(0, filesize) == "f3b9bca4c11c01561c52db79c81456a70d205a9e333bb27de4a35ad511f2c471"
}
```

### Sample 57: `d2a601d6f8bded9a`

| Field | Value |
|---|---|
| SHA-256 | `d2a601d6f8bded9a1a4b5595b3b94950b72b3a5d25feb64c16f0435d41f8e2d0` |
| Family label | `unknown` |
| File name | `bins.sh` |
| File type | `sh` |
| First seen | `2026-11-02 00:10:09` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bf80ecc102ec7ee8e7bb97a336c2ce7` |
| SHA-1 | `53569f05141234ecd59fe0f47e8169602818652c` |
| SHA-256 | `d2a601d6f8bded9a1a4b5595b3b94950b72b3a5d25feb64c16f0435d41f8e2d0` |
| SHA3-384 | `4f11f13ec7ef705e840b607d6974d47d642c32d37b649465449414493ed29c2e0f2ed7ec578094ce7fd76e99e2eda23c` |
| TLSH | `T198E026B2B65202BA6DDC846BD2ADC5A8308170421845F6FCF537723A478D2E9F526FB1` |
| SSDEEP | `6:h/qVzB+QFnTAJ3lqLeBsAHUoIjFvrQzfbQFxafrFZZKFxe5plVyQJfRX5K:5HQFn8J3lfFUoI5jMTQbafrFbKbgpT18` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_d2a601d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2a601d6f8bded9a1a4b5595b3b94950b72b3a5d25feb64c16f0435d41f8e2d0"
    family = "unknown"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-11-02 00:10:09"
  condition:
    hash.sha256(0, filesize) == "d2a601d6f8bded9a1a4b5595b3b94950b72b3a5d25feb64c16f0435d41f8e2d0"
}
```

### Sample 58: `85bd43e942976b8a`

| Field | Value |
|---|---|
| SHA-256 | `85bd43e942976b8a4ddcfe7ae22154f108139a509acb891f747d70e1cb4bac3d` |
| Family label | `unknown` |
| File name | `s.sh` |
| File type | `sh` |
| First seen | `2026-11-02 00:09:37` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `454d6716ba9fed705c205dd54e0b516e` |
| SHA-1 | `155bdb96cda232e8debf28e9197170367263a773` |
| SHA-256 | `85bd43e942976b8a4ddcfe7ae22154f108139a509acb891f747d70e1cb4bac3d` |
| SHA3-384 | `9a93197d8cce9562262625c35c8ab7169f13df73a67976433296597f91e6728ee3a67968fea6d22242158a079d54a69b` |
| TLSH | `T19A81FA89718207A47E69EA22637EC50D5741D4CFD8CA2FD5F3DEA6B08D8CCC87C54292` |
| SSDEEP | `48:2pH6UpCWUpuOulUpfWUpwZEUp5sUp6aUpEmUpzMUpYOUpFqUptWUpY+UpEeUp+2n:2UUPUmUAUyEUIUTUNUyUhUWUaUVUZUDn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_85bd43e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85bd43e942976b8a4ddcfe7ae22154f108139a509acb891f747d70e1cb4bac3d"
    family = "unknown"
    file_name = "s.sh"
    file_type = "sh"
    first_seen = "2026-11-02 00:09:37"
  condition:
    hash.sha256(0, filesize) == "85bd43e942976b8a4ddcfe7ae22154f108139a509acb891f747d70e1cb4bac3d"
}
```

### Sample 59: `d736ac750da0c632`

| Field | Value |
|---|---|
| SHA-256 | `d736ac750da0c6329ae4f3e25159ea0f02c1a3c850a01ce60f425021e3af0615` |
| Family label | `unknown` |
| File name | `d736ac750da0c6329ae4f3e25159ea0f02c1a3c850a01ce60f425021e3af0615.exe` |
| File type | `exe` |
| First seen | `2026-11-02 00:05:31` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c03f417bd6aa8fa9282d5ada8f0d85a` |
| SHA-1 | `d9eef6277b5b6d6c251261e128739f7545096efd` |
| SHA-256 | `d736ac750da0c6329ae4f3e25159ea0f02c1a3c850a01ce60f425021e3af0615` |
| SHA3-384 | `b719fecb51397e5decec653903621567d2c3427e2e170e533845ea1b60b0c6ed3b232db6b55f67ea0a1e1ef2e0c45933` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T113C4021737911701C564A6F6C0F3883907F3AA8B63B3DA43365653C26E923A5DF4AB8D` |
| SSDEEP | `12288:JrQI47jkB7GD+EPcPP0df8UTTyvncUSh9IRcQ5NC1:JrQIKQgD+cd0NfchqSQ5N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_d736ac75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d736ac750da0c6329ae4f3e25159ea0f02c1a3c850a01ce60f425021e3af0615"
    family = "unknown"
    file_name = "d736ac750da0c6329ae4f3e25159ea0f02c1a3c850a01ce60f425021e3af0615.exe"
    file_type = "exe"
    first_seen = "2026-11-02 00:05:31"
  condition:
    hash.sha256(0, filesize) == "d736ac750da0c6329ae4f3e25159ea0f02c1a3c850a01ce60f425021e3af0615"
}
```

### Sample 60: `254240df904dc29f`

| Field | Value |
|---|---|
| SHA-256 | `254240df904dc29fe2e71e93a1d63c60bbe6dfd67bf3b3bc57f981e86a8dc211` |
| Family label | `Mirai` |
| File name | `e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725.elf` |
| File type | `elf` |
| First seen | `2026-11-02 00:04:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16b9de2f4c045b02af9b0da53f0638ca` |
| SHA-1 | `81f0c6b7a93b77a80bd2007831b5150d9489c1c8` |
| SHA-256 | `254240df904dc29fe2e71e93a1d63c60bbe6dfd67bf3b3bc57f981e86a8dc211` |
| SHA3-384 | `abf7bd4eeecf168a905de26572c8cd465b2b63f15ec6790aae44be0c30c268bd478ba48ea8df369f9a8d0f77f40e227d` |
| TLSH | `T1E4F4E64B6E628F7DF274C7308BF30A24D6AD62D61BE1D681E19CD1141F2029E951FBAC` |
| TELFHASH | `t1eab137a9297813a4ab555c4c49ecef368da338ef3e161c239e51d85deb1fa835e10c1c` |
| SSDEEP | `6144:qf6U55hjKBkRa5N8DhrYvIqK5KjxD0DQ5kmaxQ4po8xxf0PFW0eQD/l7oazk1ZIh:R3qVYvn5Dix2lP+fPj312OaWbC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_254240df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "254240df904dc29fe2e71e93a1d63c60bbe6dfd67bf3b3bc57f981e86a8dc211"
    family = "Mirai"
    file_name = "e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725.elf"
    file_type = "elf"
    first_seen = "2026-11-02 00:04:15"
  condition:
    hash.sha256(0, filesize) == "254240df904dc29fe2e71e93a1d63c60bbe6dfd67bf3b3bc57f981e86a8dc211"
}
```

### Sample 61: `e5488094c4e1433a`

| Field | Value |
|---|---|
| SHA-256 | `e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725` |
| Family label | `Mirai` |
| File name | `e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725.elf` |
| File type | `elf` |
| First seen | `2026-11-02 00:04:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `079a450f60d773d32502c1abfb8e25c2` |
| SHA-1 | `a3e2e29fb428d5167f0fd7e22a388c436fe0e322` |
| SHA-256 | `e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725` |
| SHA3-384 | `eb275e0db8eff70c442d299512d931f93884019ac61452ca08982bf250e580e4fb0d9b4974968ab9d2ab7e8faeead4e6` |
| TLSH | `T10524232E2A1930F2DD6B8B79462201842C933EF75D06A76483D79771D749EB07CC9BE8` |
| SSDEEP | `6144:ZkOQXpbe3uyDzDzvgKlYUNq5jvxWi0oFaBjYu6JMCs1FE2:6OKuzDVlYUI1xWFodvns3E2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_e5488094
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725"
    family = "Mirai"
    file_name = "e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725.elf"
    file_type = "elf"
    first_seen = "2026-11-02 00:04:03"
  condition:
    hash.sha256(0, filesize) == "e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725"
}
```

### Sample 62: `e6400ea4ea364afb`

| Field | Value |
|---|---|
| SHA-256 | `e6400ea4ea364afbc1dd39f6836ddcab26b6653d2c22751aac847112874ad45b` |
| Family label | `unknown` |
| File name | `dvnx_1047c65e_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-11-01 23:41:23` |
| Reporter | `Daydream` |
| Tags | `DvnX, exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef43722a360f0839149e518b7347ea51` |
| SHA-1 | `1072989d09ab34970ee29055373b342a4ea76113` |
| SHA-256 | `e6400ea4ea364afbc1dd39f6836ddcab26b6653d2c22751aac847112874ad45b` |
| SHA3-384 | `fb50c1f0732ef608ad84b09e3284c4f6d7e34a8f8acaa639520f8d3032201846a65e5e0e2a9fe8715fc8c4e0abab2320` |
| IMPHASH | `6cd5283e2a533c4150eb15706394ab56` |
| TLSH | `T184D45B13F39286ECD01AC974876A9133F6757C891A30BA7F57945E211F3ABA0E72D708` |
| SSDEEP | `12288:koJHya7K24UJrVM0RFuREslD98uZggyFrLfz5mjAu:rJHN77zJZL2msJCKcFFAv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_e6400ea4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6400ea4ea364afbc1dd39f6836ddcab26b6653d2c22751aac847112874ad45b"
    family = "unknown"
    file_name = "dvnx_1047c65e_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-11-01 23:41:23"
  condition:
    hash.sha256(0, filesize) == "e6400ea4ea364afbc1dd39f6836ddcab26b6653d2c22751aac847112874ad45b"
}
```

### Sample 63: `26a9c39f6e19e24a`

| Field | Value |
|---|---|
| SHA-256 | `26a9c39f6e19e24a3690aa99d5be2515939d1f292976eb316b7690426f3b4faa` |
| Family label | `unknown` |
| File name | `26a9c39f6e19e24a3690aa99d5be2515939d1f292976eb316b7690426f3b4faa` |
| File type | `elf` |
| First seen | `2026-11-01 22:21:02` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33d35b45100b96ad7233e8b4772fa451` |
| SHA-1 | `486b6daaf96b5a02c34f3aa5caaaf1eaf0f595fd` |
| SHA-256 | `26a9c39f6e19e24a3690aa99d5be2515939d1f292976eb316b7690426f3b4faa` |
| SHA3-384 | `4e5ad3c6b7b6380df0a30c1d6356a6985bf69b4fd3bff372e0e06a2af1f236712fd63458372a4d9a17ec26cdbc641ee5` |
| TLSH | `T1A7355B1BB59250FDC1E6D070879B9633AA32B49952347EBF12C4AF302E26F20675DF61` |
| SSDEEP | `24576:MOWkFlK+FsHoFSMdVnFmyJJd0qO/49CIIep:MOpFRF8oFPvnl50p+0ep` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_26a9c39f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26a9c39f6e19e24a3690aa99d5be2515939d1f292976eb316b7690426f3b4faa"
    family = "unknown"
    file_name = "26a9c39f6e19e24a3690aa99d5be2515939d1f292976eb316b7690426f3b4faa"
    file_type = "elf"
    first_seen = "2026-11-01 22:21:02"
  condition:
    hash.sha256(0, filesize) == "26a9c39f6e19e24a3690aa99d5be2515939d1f292976eb316b7690426f3b4faa"
}
```

### Sample 64: `d729ca1e148048aa`

| Field | Value |
|---|---|
| SHA-256 | `d729ca1e148048aa9d42574d0cbd3486407e2746eab45583167336105637bc53` |
| Family label | `unknown` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-01 21:53:08` |
| Reporter | `AmadeyHunter` |
| Tags | `DIVINEX, exe, stealer, Warden, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8354f8785379bba3b353ae24ed68910f` |
| SHA-1 | `7104caa81e764821defc113bf62630f794394e42` |
| SHA-256 | `d729ca1e148048aa9d42574d0cbd3486407e2746eab45583167336105637bc53` |
| SHA3-384 | `3f14b1a4cd46003abd8b858670bd77348a37133aaa75359fc4654919bbbbd97d46a2ea79cc6e50198429bdf72a2442bc` |
| IMPHASH | `d467950312572a4887917c64c7b0e40d` |
| TLSH | `T1FB15E1E076D5118DD4BCC7718B6BAE7C967335220E2138EF86A023894F3A7D19B35E16` |
| SSDEEP | `24576:GsqaSBiJbkyd9lskkhC0yatEgBYH2QmnuIg1:vma3ef80wKuIg1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_d729ca1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d729ca1e148048aa9d42574d0cbd3486407e2746eab45583167336105637bc53"
    family = "unknown"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-01 21:53:08"
  condition:
    hash.sha256(0, filesize) == "d729ca1e148048aa9d42574d0cbd3486407e2746eab45583167336105637bc53"
}
```

### Sample 65: `45075a965b00a8f0`

| Field | Value |
|---|---|
| SHA-256 | `45075a965b00a8f0248dd4f40ea3621d58cefad5329ac86bf42caacc95729090` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-11-01 21:24:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `beb44290170ac8974547b6df818703a8` |
| SHA-1 | `d6c2632c21326ebd3fdd247cc89ff1a5a015e678` |
| SHA-256 | `45075a965b00a8f0248dd4f40ea3621d58cefad5329ac86bf42caacc95729090` |
| SHA3-384 | `047d72f06d654d7399e262f3e833ce764435d31775a81de49e279cc9a3d13261cc9d928940a2bc55089996f7e253e607` |
| TLSH | `T1DBE34D56EB804B13C4D61779B6EF4345333397A593DB73069928ABB43F8279E0E23A05` |
| TELFHASH | `t1f931fe315761a5156aa1cd6088fe57b2262cdb162748ef33de3584cc68090eee63bc4f` |
| SSDEEP | `3072:CL4Zw3IfhUq7kVaC3+fbVB5f9K0RlNe5F1fcRZM/91kf6mcwPH/H:C4Zw3fGkVaq+fbVBp9RhmF1fcvM/9Bmv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_45075a96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45075a965b00a8f0248dd4f40ea3621d58cefad5329ac86bf42caacc95729090"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-11-01 21:24:04"
  condition:
    hash.sha256(0, filesize) == "45075a965b00a8f0248dd4f40ea3621d58cefad5329ac86bf42caacc95729090"
}
```

### Sample 66: `a5373179735e55f6`

| Field | Value |
|---|---|
| SHA-256 | `a5373179735e55f60f0213c1267e1d8a163357b542de3149e8750aa0c048e39d` |
| Family label | `Mirai` |
| File name | `main_m68k` |
| File type | `elf` |
| First seen | `2026-11-01 21:17:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6de9a953391b420216398bd2315ccec4` |
| SHA-1 | `3c1cc13000a41c899522e4fa8a64e690a5bf6934` |
| SHA-256 | `a5373179735e55f60f0213c1267e1d8a163357b542de3149e8750aa0c048e39d` |
| SHA3-384 | `ba232b4582cc2123c1c495ebf91c9dde05f72934633a810d86015d524f3ae2f4e6650429ca4059a7adf0dce98e0ac704` |
| TLSH | `T176F329C7F900DDBEF80AE33748530909B130BBA214425B377267797BED7A195056BE8A` |
| SSDEEP | `3072:KYP7VwvdgFwGHQs+9zOfoSqvZLgOFLTzm2H0gk4suKuEorLEU03VnjbiuLvn9UyK:X61e16Eg0gk49KgQU07LvSy7v2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_a5373179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5373179735e55f60f0213c1267e1d8a163357b542de3149e8750aa0c048e39d"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-11-01 21:17:03"
  condition:
    hash.sha256(0, filesize) == "a5373179735e55f60f0213c1267e1d8a163357b542de3149e8750aa0c048e39d"
}
```

### Sample 67: `41d9eb2f5418181c`

| Field | Value |
|---|---|
| SHA-256 | `41d9eb2f5418181cfe9a9955bdb1ec99692618759704b92f332d2d6e121fa4aa` |
| Family label | `Gh0stRAT` |
| File name | `BandiZip_Setup_x64-signed.exe` |
| File type | `exe` |
| First seen | `2026-11-01 21:11:19` |
| Reporter | `CNGaoLing` |
| Tags | `exe, Gh0stRAT, signed, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91a14cb2f415d9d8f3b3b608b8de9056` |
| SHA-1 | `44227eec3522e38457032276517d15fc706b37d4` |
| SHA-256 | `41d9eb2f5418181cfe9a9955bdb1ec99692618759704b92f332d2d6e121fa4aa` |
| SHA3-384 | `dbae90a6f3fd393aaa3ca2712f2e6bd88174d2ac49b271d682f61de5165fa63797ed10ae1a07544ba1c7d29f85101cef` |
| IMPHASH | `6d5e13c0269946a5a10390c178d8e9a5` |
| TLSH | `T1A0871221365EC43BE16A05B1992CAEAA913C6E360FB154C7B3EC7D5E17B54C20237E27` |
| SSDEEP | `786432:pJqHlyDSs9J75ASuS4hyI30fC/hqdm23VlNlDIcploOApo7OkOt8FM+Ny:pJqHlyDSsL9BmyI30ASbEcplApoCkOtH` |
| ICON-DHASH | `68f8d9d3d9d83c80` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_067_41d9eb2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41d9eb2f5418181cfe9a9955bdb1ec99692618759704b92f332d2d6e121fa4aa"
    family = "Gh0stRAT"
    file_name = "BandiZip_Setup_x64-signed.exe"
    file_type = "exe"
    first_seen = "2026-11-01 21:11:19"
  condition:
    hash.sha256(0, filesize) == "41d9eb2f5418181cfe9a9955bdb1ec99692618759704b92f332d2d6e121fa4aa"
}
```

### Sample 68: `7653b9b8300f1825`

| Field | Value |
|---|---|
| SHA-256 | `7653b9b8300f1825d8dd067f4f68882181ca67148268368cac430dd7b0b2b219` |
| Family label | `Mirai` |
| File name | `amd64` |
| File type | `elf` |
| First seen | `2026-11-01 21:00:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95cce355006e2ea4f7cb04ba3641f5b1` |
| SHA-1 | `026d928446441cc60e33a9cf01e39f58c67ef19c` |
| SHA-256 | `7653b9b8300f1825d8dd067f4f68882181ca67148268368cac430dd7b0b2b219` |
| SHA3-384 | `667f841f6847ee6e05357a5e59b1d49e7e06cf755a7fcd4954e8a61a0e0b82c34d597dbe3cb391b2afe15b445e321485` |
| TLSH | `T1D1630907F5A1197DC0F5C430869FC232A571F4A89B321A2F6A845BB73D6AF244B3DE61` |
| TELFHASH | `t181e05c45eabd8a1dc6f31a30dc5c0760a143691290231b21ef54d9d0843f158f208d6f` |
| SSDEEP | `768:xZcfLCn4+2OGeWumpR5hJxZBpR5hJxZBpR5hJxZBpR5hJxZB8kM0cEsU8kM0cEsF:xyfuBhITmcybnbMEZs7KPV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_7653b9b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7653b9b8300f1825d8dd067f4f68882181ca67148268368cac430dd7b0b2b219"
    family = "Mirai"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-11-01 21:00:04"
  condition:
    hash.sha256(0, filesize) == "7653b9b8300f1825d8dd067f4f68882181ca67148268368cac430dd7b0b2b219"
}
```

### Sample 69: `c8b1f0e93528ebab`

| Field | Value |
|---|---|
| SHA-256 | `c8b1f0e93528ebabaeb3139f8d22b6ae905df91c85bb4f6052e46e3dd694e649` |
| Family label | `Mirai` |
| File name | `mips64b` |
| File type | `elf` |
| First seen | `2026-11-01 20:50:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2520d019377192418d9eea7311102f9` |
| SHA-1 | `5e58632b8ab0e5639da76d322d379dd6342ea075` |
| SHA-256 | `c8b1f0e93528ebabaeb3139f8d22b6ae905df91c85bb4f6052e46e3dd694e649` |
| SHA3-384 | `fa07273539a98aeb5ba91eae3384c6599de9cc4a10dd991fad837c44164fb01cfd912f2e325f030899b7df21389ce041` |
| TLSH | `T1CFA47DA3EF83CC9EF65D8BB949E387B872D461E32579CAD3D3BD75055A04180481AACC` |
| SSDEEP | `6144:7oQwDvJren9pbf2iOqvGOpZHEZhjiMFV17udqyXkPpOfua:7ov7JI9pf2iwhjUCp6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_c8b1f0e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8b1f0e93528ebabaeb3139f8d22b6ae905df91c85bb4f6052e46e3dd694e649"
    family = "Mirai"
    file_name = "mips64b"
    file_type = "elf"
    first_seen = "2026-11-01 20:50:03"
  condition:
    hash.sha256(0, filesize) == "c8b1f0e93528ebabaeb3139f8d22b6ae905df91c85bb4f6052e46e3dd694e649"
}
```

### Sample 70: `7d67647e69bc453a`

| Field | Value |
|---|---|
| SHA-256 | `7d67647e69bc453a71eb396d90ee995548607c19784f8b063af8304ecc184ae0` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-11-01 20:42:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2169941bd9fac933e5a0b6e4eeddcc5e` |
| SHA-1 | `1d2d789395e3831f8ac50ba4c6aae480c0716008` |
| SHA-256 | `7d67647e69bc453a71eb396d90ee995548607c19784f8b063af8304ecc184ae0` |
| SHA3-384 | `7910eba4115da0f88a095e0d13ca4f767f5124510b87f16613cfe34d61431d289ec7b00b308559cafa6b44ada2b52a80` |
| TLSH | `T139632B21FA720E17C4C1A87A21E74B25B6F153DE26E8CA0A3DB10E8EFF755446543AF4` |
| SSDEEP | `1536:r1PQ23+HH9+omAhaeee/lyrE/QrINk5htkfd:BHO9DEwKINUMfd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_7d67647e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d67647e69bc453a71eb396d90ee995548607c19784f8b063af8304ecc184ae0"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-11-01 20:42:03"
  condition:
    hash.sha256(0, filesize) == "7d67647e69bc453a71eb396d90ee995548607c19784f8b063af8304ecc184ae0"
}
```

### Sample 71: `14abfa8e5cbabc1d`

| Field | Value |
|---|---|
| SHA-256 | `14abfa8e5cbabc1dd53f633dddb91eef1aa5fa8f7ac744a1386bbfd41c899162` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-11-01 20:25:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80e49feff1bb546f6ce2ea4d5eaf4991` |
| SHA-1 | `f21268338257ec1257309ee07ed4a1c2197da3c1` |
| SHA-256 | `14abfa8e5cbabc1dd53f633dddb91eef1aa5fa8f7ac744a1386bbfd41c899162` |
| SHA3-384 | `9d3f72598b91528e7eeedad5b440f58ea9284ea10738f837e5618f4f959edc638145fd9246157e0638c43ad8a780c9ba` |
| TLSH | `T158241A05AA408F53C4D72BB9FB9B435533239764E7EB73059528ABB43B8679E4F22102` |
| TELFHASH | `t11d413e8a957c065a6b623c3cde5cabf2501b8b22a3527f31ff15d9c4691e002e818d7f` |
| SSDEEP | `6144:YSxBsUOnopCBmhXaaAtoY7hvCct6UwOSCEjNquV/O5gQmDm1YhoH:YSzsUKVshXaaAd7hvxvwOSCYqG/6BmDu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_14abfa8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14abfa8e5cbabc1dd53f633dddb91eef1aa5fa8f7ac744a1386bbfd41c899162"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-01 20:25:04"
  condition:
    hash.sha256(0, filesize) == "14abfa8e5cbabc1dd53f633dddb91eef1aa5fa8f7ac744a1386bbfd41c899162"
}
```

### Sample 72: `00ef251f6f49eb50`

| Field | Value |
|---|---|
| SHA-256 | `00ef251f6f49eb50f3300585c814910318e7f09864ed373ec4f078d2c1471d0e` |
| Family label | `unknown` |
| File name | `legionloader_stage5.exe` |
| File type | `exe` |
| First seen | `2026-11-01 20:19:05` |
| Reporter | `Daydream` |
| Tags | `ClickFix, CurlyGate, exe, LegionLoader, loader, Satacom, unpacked` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c375566ba06274968e01443185315a5` |
| SHA-1 | `74887619aa862d49f0f8f87eeb3aa9644d9a48e6` |
| SHA-256 | `00ef251f6f49eb50f3300585c814910318e7f09864ed373ec4f078d2c1471d0e` |
| SHA3-384 | `7f6af696046e12c1b66ef51f3bd40121ea93ebc8c5d7d723677b2304c1bb887c63e51c66e9d1dff670e8a89aa1c1a616` |
| IMPHASH | `48f475f35a8eefbe7477d1efc5eb1f0e` |
| TLSH | `T1A5B4C94BEAB651E5D4BAC0388563712BFC7134694334ABD79B809B531B72BE4E93E700` |
| SSDEEP | `6144:HpJg54HXC1baXFak4UVdTFbYVJ49F8ocgaKsyl2j4YlZK3ftN0xKO:rakXVd8Je8oc/yl2j40Z43sK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_00ef251f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00ef251f6f49eb50f3300585c814910318e7f09864ed373ec4f078d2c1471d0e"
    family = "unknown"
    file_name = "legionloader_stage5.exe"
    file_type = "exe"
    first_seen = "2026-11-01 20:19:05"
  condition:
    hash.sha256(0, filesize) == "00ef251f6f49eb50f3300585c814910318e7f09864ed373ec4f078d2c1471d0e"
}
```

### Sample 73: `0c692fdd1085f2ee`

| Field | Value |
|---|---|
| SHA-256 | `0c692fdd1085f2ee287f305a1f6da6541287d9119fff13a2bd309ac0592f78d3` |
| Family label | `unknown` |
| File name | `ver_pa_stage3.exe` |
| File type | `exe` |
| First seen | `2026-11-01 20:18:09` |
| Reporter | `Daydream` |
| Tags | `ClickFix, CurlyGate, exe, LegionLoader, loader, Satacom, unpacked` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `260ba47078631ea565935db63c9e4ecf` |
| SHA-1 | `e1e38577a76f1a21f19d4ca38531c43a90f41575` |
| SHA-256 | `0c692fdd1085f2ee287f305a1f6da6541287d9119fff13a2bd309ac0592f78d3` |
| SHA3-384 | `d16c3a8791a19d4d81c19e7785a262a27287f4c4a5b413a5364780e1a9e23dbcca4ba33b3e90b02c6227e2905fc486a6` |
| IMPHASH | `791251b8bef78a001e6f932df4ccc24b` |
| TLSH | `T17E86DC13DEAF89DAAB110B360460FA2F4B907946F82CF726FB592654C36631A5107FF4` |
| SSDEEP | `196608:ccV6umEukH6IeysNL/v2OHuADZ2Jn9DorI:JEyQT8C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_0c692fdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c692fdd1085f2ee287f305a1f6da6541287d9119fff13a2bd309ac0592f78d3"
    family = "unknown"
    file_name = "ver_pa_stage3.exe"
    file_type = "exe"
    first_seen = "2026-11-01 20:18:09"
  condition:
    hash.sha256(0, filesize) == "0c692fdd1085f2ee287f305a1f6da6541287d9119fff13a2bd309ac0592f78d3"
}
```

### Sample 74: `7eb0d8e8f74b2988`

| Field | Value |
|---|---|
| SHA-256 | `7eb0d8e8f74b298885fa0ec0a0ee1e87b03e27fbff5fe41ae99edacfaac2d1a3` |
| Family label | `unknown` |
| File name | `281.ps1` |
| File type | `ps1` |
| First seen | `2026-11-01 20:17:58` |
| Reporter | `Daydream` |
| Tags | `ClickFix, CurlyGate, LegionLoader, loader, ps1, Satacom` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfe4df50d25820185868df0ce873e183` |
| SHA-1 | `cc4b5ae054e4e76c210fbd789e886b214aa07be1` |
| SHA-256 | `7eb0d8e8f74b298885fa0ec0a0ee1e87b03e27fbff5fe41ae99edacfaac2d1a3` |
| SHA3-384 | `81fa4dca94ceadb1be736cf17956194962e0f4c6f7e210ffc1d52bff641be49077a16c71026a660101efe125ae5ba3d9` |
| TLSH | `T16EF174F02BD6CD4E1DBC01E67597F04C695A0E78109E684FE2FAA601B0E768CF4D6627` |
| SSDEEP | `192:7dECncpzNqiEWZvlhIIY4HsYfSX6zMzHVRT2lml/hsUsSw9:hECYzNqiXvnz5MhXZsSw9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_7eb0d8e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7eb0d8e8f74b298885fa0ec0a0ee1e87b03e27fbff5fe41ae99edacfaac2d1a3"
    family = "unknown"
    file_name = "281.ps1"
    file_type = "ps1"
    first_seen = "2026-11-01 20:17:58"
  condition:
    hash.sha256(0, filesize) == "7eb0d8e8f74b298885fa0ec0a0ee1e87b03e27fbff5fe41ae99edacfaac2d1a3"
}
```

### Sample 75: `009e0fca1415e84c`

| Field | Value |
|---|---|
| SHA-256 | `009e0fca1415e84c1f302947cb77368e60ab7755a9aadfe2cfbccb3888df1bd6` |
| Family label | `unknown` |
| File name | `009e0fca1415e84c1f302947cb77368e60ab7755a9aadfe2cfbccb3888df1bd6` |
| File type | `sh` |
| First seen | `2026-11-01 20:17:06` |
| Reporter | `thinngo` |
| Tags | `honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78e8e69c4600256523540b944b9924a8` |
| SHA-1 | `9e061943bbb3dd5426685912f375d5c3670e3808` |
| SHA-256 | `009e0fca1415e84c1f302947cb77368e60ab7755a9aadfe2cfbccb3888df1bd6` |
| SHA3-384 | `876e83d05a02b98cbbb17c04b08f5b8563546081cf8911295f9951f027291ed651eafb7a7461b12d9dbc060bf7b6e336` |
| TLSH | `T19D418DCC137281B93CA6DD6F76A9899DB2D450CAACF92F05D4DC7CE8819CE0C1B90693` |
| SSDEEP | `24:v3pl3ecW3GQGGGkn53B53U93kGD3eJ3WVZ3933S1R3pC:vnw6S7iPsWNSc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_009e0fca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "009e0fca1415e84c1f302947cb77368e60ab7755a9aadfe2cfbccb3888df1bd6"
    family = "unknown"
    file_name = "009e0fca1415e84c1f302947cb77368e60ab7755a9aadfe2cfbccb3888df1bd6"
    file_type = "sh"
    first_seen = "2026-11-01 20:17:06"
  condition:
    hash.sha256(0, filesize) == "009e0fca1415e84c1f302947cb77368e60ab7755a9aadfe2cfbccb3888df1bd6"
}
```

### Sample 76: `dfb724d2cf221e47`

| Field | Value |
|---|---|
| SHA-256 | `dfb724d2cf221e476c4f48b70c06b904503efac14d771ee42e47cc0d1640db39` |
| Family label | `SalatStealer` |
| File name | `Xeno-v1.3.65.exe` |
| File type | `exe` |
| First seen | `2026-11-01 19:51:32` |
| Reporter | `josie` |
| Tags | `exe, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a13868cdea28901ecd28ef78bc8f31b9` |
| SHA-1 | `2fc38af0b2a892cde861fc0fdfd890c847653b44` |
| SHA-256 | `dfb724d2cf221e476c4f48b70c06b904503efac14d771ee42e47cc0d1640db39` |
| SHA3-384 | `03f123d4a270660b6d407e3f4ad0a261c7ce6a77a419656048ed2f510ed8454c64459efdaf37aa641f387c2d33a29620` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1B6183317F2917031D0B58CB8088DEB69F673311D2398DBEA2654A25AEFB3D14973B721` |
| SSDEEP | `1572864:gVv3JLlCCLbjdRepF+dRauBDSlVVtPtGgY5/M0aUbVlhi4dyLAA1kXSpyANyAWCL:gVv3JLlFvdRev+d5BC2pM7A840Bkipyq` |
| ICON-DHASH | `00e0c0d10c00a002` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_076_dfb724d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfb724d2cf221e476c4f48b70c06b904503efac14d771ee42e47cc0d1640db39"
    family = "SalatStealer"
    file_name = "Xeno-v1.3.65.exe"
    file_type = "exe"
    first_seen = "2026-11-01 19:51:32"
  condition:
    hash.sha256(0, filesize) == "dfb724d2cf221e476c4f48b70c06b904503efac14d771ee42e47cc0d1640db39"
}
```

### Sample 77: `986f893112027921`

| Field | Value |
|---|---|
| SHA-256 | `986f893112027921a3e40de213b6a5614ed746a9aeba285e1560474f10ba7828` |
| Family label | `Mirai` |
| File name | `main_x86_64` |
| File type | `elf` |
| First seen | `2026-11-01 19:46:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6714a1f15e268e72308196496c3bcfc` |
| SHA-1 | `a824fa34c3b6d2738ae1dfc43a817d6a6252d93e` |
| SHA-256 | `986f893112027921a3e40de213b6a5614ed746a9aeba285e1560474f10ba7828` |
| SHA3-384 | `1ade21a1c6090098d3b9587d5c6bdfbb68e2ecc66d4d478c9c2e2c99af01e03ae23aa3a7ffd8137adff9db9214153d6a` |
| TLSH | `T12B346D17F68140FEC49AC1784BEBF03B9971796D1238B26A1FC4AF222D5AF315A4DB41` |
| TELFHASH | `t15a61ff342cd1340861e6c297b31be76cfc361800dbde76a8af97b8b1ee4b6c54c41826` |
| SSDEEP | `6144:fvWroMueP/8JwCdCnqOJI/pNtT6P8a7QuUb3lOPE04Q:fv6o/ee3s0bdQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_986f8931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "986f893112027921a3e40de213b6a5614ed746a9aeba285e1560474f10ba7828"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-11-01 19:46:03"
  condition:
    hash.sha256(0, filesize) == "986f893112027921a3e40de213b6a5614ed746a9aeba285e1560474f10ba7828"
}
```

### Sample 78: `2b938c21f2e7e5ee`

| Field | Value |
|---|---|
| SHA-256 | `2b938c21f2e7e5ee825c0e7aaa39b16d8a18fe1fc6d3ae3e6227e4fd093fc223` |
| Family label | `unknown` |
| File name | `fuck_niggers_30.hta` |
| File type | `hta` |
| First seen | `2026-11-01 19:41:03` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9541baaf6f6ce2ff07315e7e775511d` |
| SHA-1 | `8349e220a7ebaa84270c81d21856d7d5c053b5e2` |
| SHA-256 | `2b938c21f2e7e5ee825c0e7aaa39b16d8a18fe1fc6d3ae3e6227e4fd093fc223` |
| SHA3-384 | `9253c491c22b78c6e622f85da06af98dc6846e17e96671c1721f75c2b9239be41ab9d1b3afd4a80bc65d6e6224414eb4` |
| TLSH | `T11D422A5CAED1A1B0EA0703DDB3AF28690268A0D72409C484F58CDEE87F46BDC4A57B56` |
| SSDEEP | `192:snHNsGeTHQpD+da6+888+UV7tDoj/pxz5bqFtCPS3NRUzH9:snX+/DV7k/3cFtHRUzH9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_2b938c21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b938c21f2e7e5ee825c0e7aaa39b16d8a18fe1fc6d3ae3e6227e4fd093fc223"
    family = "unknown"
    file_name = "fuck_niggers_30.hta"
    file_type = "hta"
    first_seen = "2026-11-01 19:41:03"
  condition:
    hash.sha256(0, filesize) == "2b938c21f2e7e5ee825c0e7aaa39b16d8a18fe1fc6d3ae3e6227e4fd093fc223"
}
```

### Sample 79: `506b0987334caab3`

| Field | Value |
|---|---|
| SHA-256 | `506b0987334caab33abd876085b30e7853e4e18e9759c5afeeeb890286aba575` |
| Family label | `Mirai` |
| File name | `mips64le` |
| File type | `elf` |
| First seen | `2026-11-01 19:33:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `325a55256dcd303c0a2ad6ec8632e0b1` |
| SHA-1 | `41ef455285154130f5a509e2087ed02e84301de6` |
| SHA-256 | `506b0987334caab33abd876085b30e7853e4e18e9759c5afeeeb890286aba575` |
| SHA3-384 | `cdda5001b3b09e6c60c90d7e75c141d0dec30272fd8989d31c2cae638870c2f2aa77975002d5f6a2f94304e10bf949ca` |
| TLSH | `T1C3054C97AF090F9AE0EF8F30C52E12DB026C5E935651CA7DA6AC3D553F2E3A50BC1509` |
| SSDEEP | `12288:7o1dFVC9vXNd4fha4dNEJaPMxL+O4Ptqs5iPOJ:7YdDwXNdcacPM58q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_506b0987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "506b0987334caab33abd876085b30e7853e4e18e9759c5afeeeb890286aba575"
    family = "Mirai"
    file_name = "mips64le"
    file_type = "elf"
    first_seen = "2026-11-01 19:33:05"
  condition:
    hash.sha256(0, filesize) == "506b0987334caab33abd876085b30e7853e4e18e9759c5afeeeb890286aba575"
}
```

### Sample 80: `6005d03cbe21f51a`

| Field | Value |
|---|---|
| SHA-256 | `6005d03cbe21f51a31b83a9ca019eac9416fe0fb4abdf27387a0e1f119b009d0` |
| Family label | `Mirai` |
| File name | `main_x86` |
| File type | `elf` |
| First seen | `2026-11-01 19:32:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a86afbefb2f0cbe074624a43f82a732` |
| SHA-1 | `0e344d9da0912e53133c604660216ff311d62b4a` |
| SHA-256 | `6005d03cbe21f51a31b83a9ca019eac9416fe0fb4abdf27387a0e1f119b009d0` |
| SHA3-384 | `87c5c1b9e3fce66ace33d6cd80cd14e087227e9140d724ec5ed3b9dcc5b17a2771aa16d772dd4b83f6acf8b8af529256` |
| TLSH | `T1BC246C96F7C3D0F1D8430D70206ABB27AE706D3E5138DB47E7E56D32AC96702951AA2C` |
| TELFHASH | `t1a0617fb237ba6add33e4a642c20a7f10ed1a91bb544424f606f235cd21f5e125772c32` |
| SSDEEP | `6144:nQYsV3CcLb30txRsDHSmYde5Yz48GWRF3RrdSNu:QYAvLb30txurSmT558hmu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_6005d03c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6005d03cbe21f51a31b83a9ca019eac9416fe0fb4abdf27387a0e1f119b009d0"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-11-01 19:32:04"
  condition:
    hash.sha256(0, filesize) == "6005d03cbe21f51a31b83a9ca019eac9416fe0fb4abdf27387a0e1f119b009d0"
}
```

### Sample 81: `5a131246ea315e0c`

| Field | Value |
|---|---|
| SHA-256 | `5a131246ea315e0c3ee4d9d59bceaa7ba8d0123f4ad4eacf3a20b1aaa9037ae5` |
| Family label | `RustyStealer` |
| File name | `Xeno-v1.3.65.exe` |
| File type | `exe` |
| First seen | `2026-11-01 19:31:53` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40a174b07092f743017117c540162e7c` |
| SHA-1 | `9b0240754e1a2c81ab8151e49e678fb82c7291be` |
| SHA-256 | `5a131246ea315e0c3ee4d9d59bceaa7ba8d0123f4ad4eacf3a20b1aaa9037ae5` |
| SHA3-384 | `b6d18af4ed0ef54c125945e3c0cadfd32a61a7e2879050c3533395634cf997b531a68cdb3e6300be1f07fb1a8117a956` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1D418331BF3927470D4B8CCB8098DDB65EE72312E239CDB9A1680A55EAF73944A377311` |
| SSDEEP | `1572864:SVv37MfBtaHySWWkxB7OoZTs5D6RM/LcGrIbqmb2wFXuNVJvvN4RMch2KsBrAezc:SVv37MfuSSWxxd7gIDlbf+73KphfsBR4` |
| ICON-DHASH | `00e0c0d10c00a002` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_081_5a131246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a131246ea315e0c3ee4d9d59bceaa7ba8d0123f4ad4eacf3a20b1aaa9037ae5"
    family = "RustyStealer"
    file_name = "Xeno-v1.3.65.exe"
    file_type = "exe"
    first_seen = "2026-11-01 19:31:53"
  condition:
    hash.sha256(0, filesize) == "5a131246ea315e0c3ee4d9d59bceaa7ba8d0123f4ad4eacf3a20b1aaa9037ae5"
}
```

### Sample 82: `bb3b168332ff1587`

| Field | Value |
|---|---|
| SHA-256 | `bb3b168332ff15870726b09fec2ba68c10f38359feed3596adeb38be85a42f27` |
| Family label | `Mirai` |
| File name | `mips64l` |
| File type | `elf` |
| First seen | `2026-11-01 19:31:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7daa70de7ea030ff6d542727d03aee10` |
| SHA-1 | `3999b2ed8e34e450d9cdcb33fbbec99f67dddfa0` |
| SHA-256 | `bb3b168332ff15870726b09fec2ba68c10f38359feed3596adeb38be85a42f27` |
| SHA3-384 | `90203631c650fcf824afdab083f9fd2cfd4b841e711aa0296ee59f29cb04b662b878bb801588e2d3f4825a8150c188f3` |
| TLSH | `T1E5A439139BDD2F8AE0A7CF358C762067451C5C2A7B948C3A9BF82908761F7A50F4619F` |
| SSDEEP | `12288:QV5aCbNf9kH/wnt/sBqrf/Wl5isyeU9Nmd:c9kH/wt/7PeG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_bb3b1683
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb3b168332ff15870726b09fec2ba68c10f38359feed3596adeb38be85a42f27"
    family = "Mirai"
    file_name = "mips64l"
    file_type = "elf"
    first_seen = "2026-11-01 19:31:03"
  condition:
    hash.sha256(0, filesize) == "bb3b168332ff15870726b09fec2ba68c10f38359feed3596adeb38be85a42f27"
}
```

### Sample 83: `de073af31820a9a8`

| Field | Value |
|---|---|
| SHA-256 | `de073af31820a9a8867ccb0785ab812d0cdb3cf78a3f38d6c59846eb7eedf969` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-11-01 19:27:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a04351f8b0eacf6850ba8a2d2bf476fb` |
| SHA-1 | `ba9bbe6529717338fc81b8cefddb630aa36782f8` |
| SHA-256 | `de073af31820a9a8867ccb0785ab812d0cdb3cf78a3f38d6c59846eb7eedf969` |
| SHA3-384 | `63e592da3dac088636ae22332ea8a7360f55871b6f4498475ae429bb8d6663556d482624742e67c88d6d60ba0cd2a07c` |
| TLSH | `T1EA434AC0F603D4F5E88301705136FB375F71F5E6026AEA53D3B8DA32AC92652A607A9C` |
| TELFHASH | `t19521e5ab2ea345ecf7d0a440c32f66d31675c667167079f90172399423f2e8181bec39` |
| SSDEEP | `1536:eEX1SrTCyz/8xvMP5L+CSh8sDVjDodPpuyS42RI:xX1SrTCyTAExL+JhDtchQyS1R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_de073af3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de073af31820a9a8867ccb0785ab812d0cdb3cf78a3f38d6c59846eb7eedf969"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-01 19:27:03"
  condition:
    hash.sha256(0, filesize) == "de073af31820a9a8867ccb0785ab812d0cdb3cf78a3f38d6c59846eb7eedf969"
}
```

### Sample 84: `d95e4be8f692fba5`

| Field | Value |
|---|---|
| SHA-256 | `d95e4be8f692fba56d27c4d259f92e3c3a79e411cda521e09d92cbfd28535499` |
| Family label | `RemusStealer` |
| File name | `shellcode_dump.bin` |
| File type | `exe` |
| First seen | `2026-11-01 19:23:29` |
| Reporter | `GhostTypes` |
| Tags | `ApexPoint, credential-stealer, discord, exe, fileless, go-loader, minecraft, RemusStealer, Respocket, roblox, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9882e2aac2fe26e6701698fd55cd142f` |
| SHA-1 | `1c957e1461654ec53cbbc461004e868f5c338762` |
| SHA-256 | `d95e4be8f692fba56d27c4d259f92e3c3a79e411cda521e09d92cbfd28535499` |
| SHA3-384 | `0f29207bf6d1c645bb167b77b2a9488d8da6aa2e01d586d460567462efaabd32caf407d5aa2285276bedae9f4edf2f9a` |
| IMPHASH | `de0510482f25644f5d14037b6dc1466f` |
| TLSH | `T136747B6BD35375FCDA92C07892666222B731B93C0324DEF70792D7319D22AD0AE39635` |
| SSDEEP | `3072:xK45qTzJyjWe+wEruf7XQWpqaINnjGKiz8KJLhSAQ/R6CD9AxUl95sFB/qijlcIk:xWTVI+GWjiLhSAOFatqGmoANWSzuYfl5` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_084_d95e4be8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d95e4be8f692fba56d27c4d259f92e3c3a79e411cda521e09d92cbfd28535499"
    family = "RemusStealer"
    file_name = "shellcode_dump.bin"
    file_type = "exe"
    first_seen = "2026-11-01 19:23:29"
  condition:
    hash.sha256(0, filesize) == "d95e4be8f692fba56d27c4d259f92e3c3a79e411cda521e09d92cbfd28535499"
}
```

### Sample 85: `2822ef91dbb3647f`

| Field | Value |
|---|---|
| SHA-256 | `2822ef91dbb3647f7268d8d370e3f5eba7a7bf70cfe594c12bdd96f37f9291a1` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-11-01 19:21:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb48429d341b2c97e9d8959178e575d0` |
| SHA-1 | `dea5ceb4e62e82938834ef8f78621406145c30f5` |
| SHA-256 | `2822ef91dbb3647f7268d8d370e3f5eba7a7bf70cfe594c12bdd96f37f9291a1` |
| SHA3-384 | `f27ef3a5fdecfcc3a8de5de3f7555a15e417bf8a34c56b78c32658808e21adaaf9209147c4c5b1b785103a484ee1c343` |
| TLSH | `T15B042305496424DCFB99D6F8B239413B629F3C96A568060126E9CBBEC3D1E1FB9A440F` |
| SSDEEP | `3072:RbC5UpqW4+M3WFbHI9QSU+moarmzdJnIKMae/h6pgU1qxc1xUJiEkiyqS:RbC5Up/TBbj71xr4nIKMae/ZU1SJxEqS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_2822ef91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2822ef91dbb3647f7268d8d370e3f5eba7a7bf70cfe594c12bdd96f37f9291a1"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-01 19:21:04"
  condition:
    hash.sha256(0, filesize) == "2822ef91dbb3647f7268d8d370e3f5eba7a7bf70cfe594c12bdd96f37f9291a1"
}
```

### Sample 86: `28a4ad963e6dcfc4`

| Field | Value |
|---|---|
| SHA-256 | `28a4ad963e6dcfc4df698332eddfe7c96f6463cbb954ab0a340f375c45b12c20` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-11-01 19:20:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `135ab7faae20dda1ff25d6bca7176fee` |
| SHA-1 | `1e214dece29a5c2d20f150857062a8c7b7a54e0f` |
| SHA-256 | `28a4ad963e6dcfc4df698332eddfe7c96f6463cbb954ab0a340f375c45b12c20` |
| SHA3-384 | `6cf0ffe846c93e9a268cf1a7baf703b03b10a9576a6aedd58e335797048a58fddfb420713d2d09b238ca3db6dd46026d` |
| TLSH | `T1A5634C9AF801DD7DF85FDB7B44574906B530A3D152831B3A23A7FAA3BC720991D22E81` |
| SSDEEP | `1536:5uDgM70T6pTrhiA8KyXNfGYb1AuberLEdAiaSbsH:ygMY2p/hiVMciuy4bby` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_28a4ad96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28a4ad963e6dcfc4df698332eddfe7c96f6463cbb954ab0a340f375c45b12c20"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-01 19:20:03"
  condition:
    hash.sha256(0, filesize) == "28a4ad963e6dcfc4df698332eddfe7c96f6463cbb954ab0a340f375c45b12c20"
}
```

### Sample 87: `66e852d803f12b7d`

| Field | Value |
|---|---|
| SHA-256 | `66e852d803f12b7d7939de8cbede5da5db032f6cebd4e8c5230baf05d5078a97` |
| Family label | `Mirai` |
| File name | `ppc64le` |
| File type | `elf` |
| First seen | `2026-11-01 19:10:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9cb06701f1eb097556f5bf6402362c9` |
| SHA-1 | `f91259e051226d7f76b2accde090622a48945598` |
| SHA-256 | `66e852d803f12b7d7939de8cbede5da5db032f6cebd4e8c5230baf05d5078a97` |
| SHA3-384 | `651c3290ee6d4c58cd9c63927e9777a5902fe7c9937075de6ac4fd95cf24551872054b4da328595442f5f1ce930e0749` |
| TLSH | `T118453927328CB795EF8A6C3B859AFD10338A718516515562BB40134FFBA671F8F0BA4C` |
| SSDEEP | `12288:9B2VEm52h9dkCaGrzcGVsuJzw94kbeHXVax0dl1sFunoYa3IXWnWnU55ABmQov27:z2h5OdWYVJt8FKWAvovO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_66e852d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66e852d803f12b7d7939de8cbede5da5db032f6cebd4e8c5230baf05d5078a97"
    family = "Mirai"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-11-01 19:10:04"
  condition:
    hash.sha256(0, filesize) == "66e852d803f12b7d7939de8cbede5da5db032f6cebd4e8c5230baf05d5078a97"
}
```

### Sample 88: `5cd67fead2ff5418`

| Field | Value |
|---|---|
| SHA-256 | `5cd67fead2ff54187c0ac0b5827fb57569760dafbe860915962bf0aad30ffc49` |
| Family label | `SilentNet` |
| File name | `mod (12).jar` |
| File type | `jar` |
| First seen | `2026-11-01 19:02:23` |
| Reporter | `wok` |
| Tags | `jar, java, python, silentnet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c53c67d8bf94fbeb60d6f987f36bb16` |
| SHA-1 | `48e70b87ebd79da4526b27ec08fefb19761b6898` |
| SHA-256 | `5cd67fead2ff54187c0ac0b5827fb57569760dafbe860915962bf0aad30ffc49` |
| SHA3-384 | `23de475af10ebdabe61ac93087c58a7a7941c2310698ddd3bd21e2bcac9207836312b2c53cb1080bfcc8803343508edd` |
| TLSH | `T1C15302AA3C0AE255C127B63E58A5EE7C87A8C5CF0B1CFEC755615C84B02890FA734ED5` |
| SSDEEP | `1536:76ttcPaoId4Se6UDSdQyz/G8o/2O3Bo37M:wtcPxoe6UDaXo3C3g` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_088_5cd67fea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cd67fead2ff54187c0ac0b5827fb57569760dafbe860915962bf0aad30ffc49"
    family = "SilentNet"
    file_name = "mod (12).jar"
    file_type = "jar"
    first_seen = "2026-11-01 19:02:23"
  condition:
    hash.sha256(0, filesize) == "5cd67fead2ff54187c0ac0b5827fb57569760dafbe860915962bf0aad30ffc49"
}
```

### Sample 89: `7df4e2a779be6b8d`

| Field | Value |
|---|---|
| SHA-256 | `7df4e2a779be6b8d959a6a5776c0635c7d5f2ab3d6cf2d4eacfe36335dc75ae3` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-11-01 18:47:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ea855050daa68eff308d659a1d71055` |
| SHA-1 | `003912387a74bf233fabbff173b5e2167712348f` |
| SHA-256 | `7df4e2a779be6b8d959a6a5776c0635c7d5f2ab3d6cf2d4eacfe36335dc75ae3` |
| SHA3-384 | `22ef691b6cf4058719cf4e77bbc13ba865854acf9436c0d89fbc811283000284cf1c727e55141ac251ca4be22827a9f5` |
| TLSH | `T1EBF45B06EF840FEBC4AFCD30492E835B15ED899706D1A67960FC8D8CBA9D2594FD7848` |
| SSDEEP | `12288:Pax0LY/4Kn7ZTLF/R5gl9MqMfkZbBnTGPnZ9irjcmjPN16huCP7BtDcL52FhQUsr:hrIcPSUU7T02FrBj69t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_7df4e2a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7df4e2a779be6b8d959a6a5776c0635c7d5f2ab3d6cf2d4eacfe36335dc75ae3"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-11-01 18:47:03"
  condition:
    hash.sha256(0, filesize) == "7df4e2a779be6b8d959a6a5776c0635c7d5f2ab3d6cf2d4eacfe36335dc75ae3"
}
```

### Sample 90: `727acdae59678008`

| Field | Value |
|---|---|
| SHA-256 | `727acdae59678008bfc1cd79ebd819bde40f46e916e0ce55ba9af992f9d55f07` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-11-01 18:37:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25d82c0715d43f08ea3ad407ad1efcdd` |
| SHA-1 | `2ed6015ca05d971e1f04cf77d149f79a69aab411` |
| SHA-256 | `727acdae59678008bfc1cd79ebd819bde40f46e916e0ce55ba9af992f9d55f07` |
| SHA3-384 | `d593bbecfdad26c6c60c5aa803cbb1a0b7e1fbfcbe86e5db9fac423f19e9cabf18116e6e4c802df48b52f6ca0886ee09` |
| TLSH | `T132A4D155F2072F82C8D7C935284AC1459B5BE97333E393496F43A9BB38391768F28789` |
| SSDEEP | `12288:OUpZ79OwGckjwFZatpf5Fewrc18pgX6K:O68wowFZk0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_727acdae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "727acdae59678008bfc1cd79ebd819bde40f46e916e0ce55ba9af992f9d55f07"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-01 18:37:04"
  condition:
    hash.sha256(0, filesize) == "727acdae59678008bfc1cd79ebd819bde40f46e916e0ce55ba9af992f9d55f07"
}
```

### Sample 91: `b9b317eb01c0ee91`

| Field | Value |
|---|---|
| SHA-256 | `b9b317eb01c0ee917a3dc4e875d87c0993d3bc3ed866790cebeb5af0fb6e178c` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-11-01 18:32:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e169d081a85571ab7f5edf7f88e478d9` |
| SHA-1 | `fdeaf87542c11b5797513b61aa9ab3fdf20fc7b1` |
| SHA-256 | `b9b317eb01c0ee917a3dc4e875d87c0993d3bc3ed866790cebeb5af0fb6e178c` |
| SHA3-384 | `ceaaa1a01089be9ae65f69b82598117f49e31158976527fb6a0bc85f4501920cc84981645d4d3b71cfacdc227ce1f6ba` |
| TLSH | `T1D5645C45EA404E53C4D62BB9B6FF8189332357B8D3EBB10699245FB4378779E0E36A01` |
| TELFHASH | `t1ea4152355624811697a1cc68cdedabb2552fcb132752fe37ef32c49c241a08ae529c4f` |
| SSDEEP | `6144:DDYkbVLL5rAkugPYPugHWadpOExPAKfzjCW3aIIbloMM/RL2au0NWDm62kqyP8A:D8kbbr5uVugHWad3xPAKfKW3KoB/Fy0y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_b9b317eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9b317eb01c0ee917a3dc4e875d87c0993d3bc3ed866790cebeb5af0fb6e178c"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-11-01 18:32:03"
  condition:
    hash.sha256(0, filesize) == "b9b317eb01c0ee917a3dc4e875d87c0993d3bc3ed866790cebeb5af0fb6e178c"
}
```

### Sample 92: `0d54169c5992c556`

| Field | Value |
|---|---|
| SHA-256 | `0d54169c5992c55640623478ba471445b06631f9e231f8dc649886b4b7d902b0` |
| Family label | `ValleyRAT` |
| File name | `letspnbzstup-x64.8.08.exe` |
| File type | `exe` |
| First seen | `2026-11-01 18:29:18` |
| Reporter | `CNGaoLing` |
| Tags | `Cybercrime, exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa95f35d3f05b1b605fa149a058e1b05` |
| SHA-1 | `aa82476394ce6e4534c9f4e7614a2530d12528a6` |
| SHA-256 | `0d54169c5992c55640623478ba471445b06631f9e231f8dc649886b4b7d902b0` |
| SHA3-384 | `ed2b8f86bcf312adbf28c515e65163f033ed5767a16c5c194de97b430d9c565c4114f432b28df616684428ac8fa349a1` |
| IMPHASH | `48aa5c8931746a9655524f67b25a47ef` |
| TLSH | `T15B772312BB5A15BFC48AC074978B45621DB078CA1F6178EF0A88D13D6EB9EF42F39714` |
| SSDEEP | `786432:vGtCJlhyAtSCeEzPSBw3ObgK3hrxt94mi6fYI4/lCi9iKnfBmd:eMlhy2hUw3ObgK3htTdi6QEi9FnfBA` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_092_0d54169c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d54169c5992c55640623478ba471445b06631f9e231f8dc649886b4b7d902b0"
    family = "ValleyRAT"
    file_name = "letspnbzstup-x64.8.08.exe"
    file_type = "exe"
    first_seen = "2026-11-01 18:29:18"
  condition:
    hash.sha256(0, filesize) == "0d54169c5992c55640623478ba471445b06631f9e231f8dc649886b4b7d902b0"
}
```

### Sample 93: `f02bb49b2f9af8ff`

| Field | Value |
|---|---|
| SHA-256 | `f02bb49b2f9af8ffe36542ca968b150e7911670e8f8daf7d8e401e5b094cf83c` |
| Family label | `ValleyRAT` |
| File name | `instoll.3.1.09.exe` |
| File type | `exe` |
| First seen | `2026-11-01 18:28:20` |
| Reporter | `CNGaoLing` |
| Tags | `exe, PatchedHostLoader, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4eccacdd6dae7e3b719a69fc3fe2e099` |
| SHA-1 | `9ac7d11576eb001e99850430b30032dbd86dff44` |
| SHA-256 | `f02bb49b2f9af8ffe36542ca968b150e7911670e8f8daf7d8e401e5b094cf83c` |
| SHA3-384 | `7b74d0e8064ed3d1ce8823bb7fa9feaf3ec9247bdb2e2980c98334e1fe5f71136cbffa909c4a7de8e02d28084fef6e44` |
| IMPHASH | `a6a6ee3ce2319cb569a489c278731d92` |
| TLSH | `T183879156BA00DCC2F44692F0949BB6E023FEBCB58AE0C35321D47B196FBE14D4EA7165` |
| SSDEEP | `49152:7mOOwpdnt9ePcpPnMBAu7o364VqXkD8oWz2rf8oW7O6C/n0wg/rQAdm8H+pnOug0:agpLfMr7OukQNz2rf8oUrQAHe5gALpH` |
| ICON-DHASH | `696a6ee2b2b2c2cc` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_093_f02bb49b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f02bb49b2f9af8ffe36542ca968b150e7911670e8f8daf7d8e401e5b094cf83c"
    family = "ValleyRAT"
    file_name = "instoll.3.1.09.exe"
    file_type = "exe"
    first_seen = "2026-11-01 18:28:20"
  condition:
    hash.sha256(0, filesize) == "f02bb49b2f9af8ffe36542ca968b150e7911670e8f8daf7d8e401e5b094cf83c"
}
```

### Sample 94: `fb7121430706a638`

| Field | Value |
|---|---|
| SHA-256 | `fb7121430706a6380ad52ed642d93f67936c1ff96cca17f9c23b89acf1652ad1` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-11-01 18:17:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b005ac124bc237070d6e0309738b13b` |
| SHA-1 | `2832c16bfc995a023c7be3f0f3e6b633a3e81520` |
| SHA-256 | `fb7121430706a6380ad52ed642d93f67936c1ff96cca17f9c23b89acf1652ad1` |
| SHA3-384 | `06e6b1facedb8d414033380421247daaacb313866700a9445b0e290b57865c26f1889ee55d20e1bd4ff4a812b4730cba` |
| TLSH | `T10D532A51B8819627C6D5227AFB6E42CD372123E8E2DF7207AD225F10378686F0D67F85` |
| TELFHASH | `t17f31f2744e4419cc2bd0cb84828a523e95b935f9a31036788f6f5b9b02a79c0b379435` |
| SSDEEP | `1536:E1G5GeiZfDotD4W7xyeUzU3n5vPpvg6GA1:ESrBbUA35nNg41` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_fb712143
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb7121430706a6380ad52ed642d93f67936c1ff96cca17f9c23b89acf1652ad1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-01 18:17:07"
  condition:
    hash.sha256(0, filesize) == "fb7121430706a6380ad52ed642d93f67936c1ff96cca17f9c23b89acf1652ad1"
}
```

### Sample 95: `e48f87a83c1a7bd3`

| Field | Value |
|---|---|
| SHA-256 | `e48f87a83c1a7bd39a8328d649e9a5a557eda8fb499c2e1d8e121b67f5481f7b` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-11-01 18:17:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `082041e38fb74c4d0077658e6bb4399b` |
| SHA-1 | `c13a4b656c452b58114408f533b27bf98cc003fa` |
| SHA-256 | `e48f87a83c1a7bd39a8328d649e9a5a557eda8fb499c2e1d8e121b67f5481f7b` |
| SHA3-384 | `160802221af75eda44ac40c4d02463b8103216bacaf69a5ee016d4e3e93c55fad3f835e6675e67d3010085f3e0a6d824` |
| TLSH | `T14783D71AFF540FB7DC6BCD3705A91B0238CC654A22E47B367934D528B65B24B49E3CA8` |
| SSDEEP | `1536:8HzgEC6/4A1fKPhXky8LzZUFSwj0wv1/g:8TgEC6/4AJly8Lzxy1/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_e48f87a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e48f87a83c1a7bd39a8328d649e9a5a557eda8fb499c2e1d8e121b67f5481f7b"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-01 18:17:05"
  condition:
    hash.sha256(0, filesize) == "e48f87a83c1a7bd39a8328d649e9a5a557eda8fb499c2e1d8e121b67f5481f7b"
}
```

### Sample 96: `0798c75906cdcfec`

| Field | Value |
|---|---|
| SHA-256 | `0798c75906cdcfecf6515bba616892908657ca26800510874f57abc8d7af9c28` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-11-01 18:16:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a6ec8f193889fe7947cd24e68812dcd` |
| SHA-1 | `faeaeb027ed20e9005fcc87b8807ea353c4fbcc1` |
| SHA-256 | `0798c75906cdcfecf6515bba616892908657ca26800510874f57abc8d7af9c28` |
| SHA3-384 | `1d015378dae5987ab1d84de35e1e39984a06253e8028ad09d9b9be4eabdbe9217305767c166dbbff6a4447cb40672c61` |
| TLSH | `T168D42955F8809F61C6D539B6F74D42A873070B79D3EB72069A258B343BE786B0F3A601` |
| TELFHASH | `t1c8e02b192dd819ec27f185a383befa1586c81480570578da5f51b79bdc85fd250bac31` |
| SSDEEP | `12288:Kgd+omJwyakNz4Hi2sRukCAL7brGm1f72aWJ8pCHKU:fd+otyZNzNfUzi7nR6H` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_0798c759
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0798c75906cdcfecf6515bba616892908657ca26800510874f57abc8d7af9c28"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-11-01 18:16:04"
  condition:
    hash.sha256(0, filesize) == "0798c75906cdcfecf6515bba616892908657ca26800510874f57abc8d7af9c28"
}
```

### Sample 97: `e8a91238df80f464`

| Field | Value |
|---|---|
| SHA-256 | `e8a91238df80f4649099f7cbec4460e0bc533a046a598392b14a378cc5d56075` |
| Family label | `CoinMiner` |
| File name | `pyservice92.exe` |
| File type | `exe` |
| First seen | `2026-11-01 18:10:10` |
| Reporter | `AmadeyHunter` |
| Tags | `CoinMiner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `446dff23b80ea65a6697abc6a3ba2927` |
| SHA-1 | `36351d6572d6c5089925b766b6c2d03fa3914ccc` |
| SHA-256 | `e8a91238df80f4649099f7cbec4460e0bc533a046a598392b14a378cc5d56075` |
| SHA3-384 | `f892a2c64757b608f8ad0ce78a7540f99582c0a473cbedca6e1bf0ce384df93cff8f5f6c69a67a7e398f9153a8e1b469` |
| IMPHASH | `163e0bcc8e1edaa315413b393934bb4f` |
| TLSH | `T13966CF07FCA559F5C0AAA331893695127B71BC491B3123DB2FA0BAB82F727D09C79714` |
| SSDEEP | `98304:CW4FX5h5yH6Y+DGB73nvHdxt4CUEdZKOcE7GpPs+yzD:Clph5yHKGBDNWXWD` |
| ICON-DHASH | `dcdcdcdcfcfcd4d4` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_097_e8a91238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8a91238df80f4649099f7cbec4460e0bc533a046a598392b14a378cc5d56075"
    family = "CoinMiner"
    file_name = "pyservice92.exe"
    file_type = "exe"
    first_seen = "2026-11-01 18:10:10"
  condition:
    hash.sha256(0, filesize) == "e8a91238df80f4649099f7cbec4460e0bc533a046a598392b14a378cc5d56075"
}
```

### Sample 98: `eaf78cea9535efb0`

| Field | Value |
|---|---|
| SHA-256 | `eaf78cea9535efb02cc7074e5f2d06369ec50f6d13de00e17bed330023951bd2` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-01 18:08:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b57d73d1ab06c3f06596398c00513477` |
| SHA-1 | `3daef32a845c8dfbe881c30a4b1d375e2bded0ef` |
| SHA-256 | `eaf78cea9535efb02cc7074e5f2d06369ec50f6d13de00e17bed330023951bd2` |
| SHA3-384 | `dcda20862c940bea7a3be7ea25f66fbfb94c40d3ff0aafde04c0c14c142d8da97e94d5404b63b8e8fe3e2c1ae256de9b` |
| TLSH | `T1F204127B329EBBCDDD83667111166730E1B296F70543EB43F188C5908DD91CAB2B8AB1` |
| SSDEEP | `3072:EKQ+1Y2qUK7emPnVpIpZ7iRNy2Hswpq5hF/yEU1nqTXJXGCgfB9OupBycNnniboi:RxW2gfVKZ7ohDq5P/yEU1cX+bbp0eniT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_eaf78cea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaf78cea9535efb02cc7074e5f2d06369ec50f6d13de00e17bed330023951bd2"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-01 18:08:06"
  condition:
    hash.sha256(0, filesize) == "eaf78cea9535efb02cc7074e5f2d06369ec50f6d13de00e17bed330023951bd2"
}
```

### Sample 99: `760ed8dbc45a441d`

| Field | Value |
|---|---|
| SHA-256 | `760ed8dbc45a441dd370065b02f942e20445848d350af0c05ee4cd97fb6bf31f` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-11-01 18:08:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ec549801614bde14e38bf1c9c23fa7a` |
| SHA-1 | `c8b4dc53b84745d61d4a8ac193af96536cf9ea40` |
| SHA-256 | `760ed8dbc45a441dd370065b02f942e20445848d350af0c05ee4cd97fb6bf31f` |
| SHA3-384 | `64afbd93327f54e1c08d903e49664fa79d9caf6562658e10bc62197389744d84d70264677b9bf97ab94b6c3c6e5c7600` |
| TLSH | `T145A4E591A4205ACFCE1099BA772C8F3523822C71835B1F7D29568559A28F9CFF1C7BE4` |
| SSDEEP | `6144:v6wrqYExfxYe4y6r8zXlSSQLyy4pc6paMgdS4pPnItXd2:v6vYQiy6DSMyy6aMGS6nIJd2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_760ed8db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "760ed8dbc45a441dd370065b02f942e20445848d350af0c05ee4cd97fb6bf31f"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-01 18:08:03"
  condition:
    hash.sha256(0, filesize) == "760ed8dbc45a441dd370065b02f942e20445848d350af0c05ee4cd97fb6bf31f"
}
```

### Sample 100: `cb1a78b9a84034d0`

| Field | Value |
|---|---|
| SHA-256 | `cb1a78b9a84034d03c92e59bb106a8feb8d26813495925e86aa7efcec160f10e` |
| Family label | `ValleyRAT` |
| File name | `dingtaik_setup.exe` |
| File type | `exe` |
| First seen | `2026-11-01 18:05:43` |
| Reporter | `CNGaoLing` |
| Tags | `Cybercrime, exe, signed, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1abb5cd335b108f063ffe8e0d68b133` |
| SHA-1 | `17237190e5952f397bd21ad327d321cc4bc86a63` |
| SHA-256 | `cb1a78b9a84034d03c92e59bb106a8feb8d26813495925e86aa7efcec160f10e` |
| SHA3-384 | `e6da0cb8341b094815c8703210f8554dd90e205fd5a26cd53ec7692a043bfe2599d634b319cf0e6d5f9e47103dce4f4c` |
| IMPHASH | `7b23e406d8b81f37c02f87947fd56b9e` |
| TLSH | `T172472323B2D9643FD06F1A396827B6545C3BB7512A2A8C4B97F4084C9F296C12F3B747` |
| SSDEEP | `786432:c7o4uM57Pi596bW1sMbLQ4vjZRvTUgOsLM3:c7vuMc5wbWPQ4FBoKM3` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_100_cb1a78b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb1a78b9a84034d03c92e59bb106a8feb8d26813495925e86aa7efcec160f10e"
    family = "ValleyRAT"
    file_name = "dingtaik_setup.exe"
    file_type = "exe"
    first_seen = "2026-11-01 18:05:43"
  condition:
    hash.sha256(0, filesize) == "cb1a78b9a84034d03c92e59bb106a8feb8d26813495925e86aa7efcec160f10e"
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
 * Generated: 2026-11-02T06:23:40.314807+00:00
 */

rule MalwareBazaar_Mirai_001_af3ddecb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af3ddecb85a7b8e63c5ada278c5a746e1908fcc44efc9b017159afdde8736081"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-02 06:17:03"
  condition:
    hash.sha256(0, filesize) == "af3ddecb85a7b8e63c5ada278c5a746e1908fcc44efc9b017159afdde8736081"
}

rule MalwareBazaar_ConnectWise_002_dcd9db5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcd9db5cfaa4d1351d6d54e1be1ab87a21bcd9289e966e79d550ebffb2903660"
    family = "ConnectWise"
    file_name = "dcd9db5cfaa4d135.bin"
    file_type = "exe"
    first_seen = "2026-11-02 05:24:30"
  condition:
    hash.sha256(0, filesize) == "dcd9db5cfaa4d1351d6d54e1be1ab87a21bcd9289e966e79d550ebffb2903660"
}

rule MalwareBazaar_unknown_003_12d98aa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12d98aa4742c04fb8c13f8d5e70aea2fba6bca409f0ebefbf361cc05c4c50c37"
    family = "unknown"
    file_name = "12d98aa4742c04fb8c13f8d5e70aea2fba6bca409f0ebefbf361cc05c4c50c37.exe"
    file_type = "exe"
    first_seen = "2026-11-02 05:21:32"
  condition:
    hash.sha256(0, filesize) == "12d98aa4742c04fb8c13f8d5e70aea2fba6bca409f0ebefbf361cc05c4c50c37"
}

rule MalwareBazaar_unknown_004_fac02194
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fac02194cd7deb481d16e970e0d7a6d88f85cd758dd34fb7cff5fcfe1e1e375b"
    family = "unknown"
    file_name = "fac02194cd7deb481d16e970e0d7a6d88f85cd758dd34fb7cff5fcfe1e1e375b"
    file_type = "elf"
    first_seen = "2026-11-02 04:50:20"
  condition:
    hash.sha256(0, filesize) == "fac02194cd7deb481d16e970e0d7a6d88f85cd758dd34fb7cff5fcfe1e1e375b"
}

rule MalwareBazaar_VShell_005_be9c4db2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583"
    family = "VShell"
    file_name = "be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583.exe"
    file_type = "exe"
    first_seen = "2026-11-02 04:28:31"
  condition:
    hash.sha256(0, filesize) == "be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583"
}

rule MalwareBazaar_unknown_006_ce05a292
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce05a292a38bfc0acd84d41f5ab827ddea81b6aee8075e20e4e5f41f50fae82d"
    family = "unknown"
    file_name = "ce05a292a38bfc0acd84d41f5ab827ddea81b6aee8075e20e4e5f41f50fae82d.exe"
    file_type = "exe"
    first_seen = "2026-11-02 04:27:29"
  condition:
    hash.sha256(0, filesize) == "ce05a292a38bfc0acd84d41f5ab827ddea81b6aee8075e20e4e5f41f50fae82d"
}

rule MalwareBazaar_VShell_007_9c4b3644
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c4b36446d28038f25b5078d37c071ab90359a9c5dfcc61d04a6f7093a673d6b"
    family = "VShell"
    file_name = "9c4b36446d28038f25b5078d37c071ab90359a9c5dfcc61d04a6f7093a673d6b.exe"
    file_type = "exe"
    first_seen = "2026-11-02 03:22:03"
  condition:
    hash.sha256(0, filesize) == "9c4b36446d28038f25b5078d37c071ab90359a9c5dfcc61d04a6f7093a673d6b"
}

rule MalwareBazaar_unknown_008_a4a89b60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4a89b60a58553f070061c21b897348218c7cc6c7bc2cef31c4dac218d53b7f2"
    family = "unknown"
    file_name = "a4a89b60a58553f070061c21b897348218c7cc6c7bc2cef31c4dac218d53b7f2.exe"
    file_type = "exe"
    first_seen = "2026-11-02 03:21:59"
  condition:
    hash.sha256(0, filesize) == "a4a89b60a58553f070061c21b897348218c7cc6c7bc2cef31c4dac218d53b7f2"
}

rule MalwareBazaar_SalatStealer_009_94cd3079
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94cd3079455b2c4e3a1d93ed3b9797490d46d17d975b0f4d2453d6bb0bf0189e"
    family = "SalatStealer"
    file_name = "7802b936027bad7c.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:26:26"
  condition:
    hash.sha256(0, filesize) == "94cd3079455b2c4e3a1d93ed3b9797490d46d17d975b0f4d2453d6bb0bf0189e"
}

rule MalwareBazaar_SalatStealer_010_dfc1d2dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfc1d2ddb25557c2d705fd0324d49a379158e9acfeb0d95e0bb63c21624686cc"
    family = "SalatStealer"
    file_name = "fa18cc722d8d95f7.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:26:21"
  condition:
    hash.sha256(0, filesize) == "dfc1d2ddb25557c2d705fd0324d49a379158e9acfeb0d95e0bb63c21624686cc"
}

rule MalwareBazaar_SalatStealer_011_861341eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "861341ebac1af1047c240fa2d349d57599c1ff28d85fa035d0611fc581cef181"
    family = "SalatStealer"
    file_name = "040dfd78f8e10fb4.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:26:16"
  condition:
    hash.sha256(0, filesize) == "861341ebac1af1047c240fa2d349d57599c1ff28d85fa035d0611fc581cef181"
}

rule MalwareBazaar_Mirai_012_bb9e6271
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb9e627173974aa28c7583d80af5eb4d626a3ddf7e1926e477d4f29576209a8d"
    family = "Mirai"
    file_name = "bb9e627173974aa2.bin"
    file_type = "elf"
    first_seen = "2026-11-02 02:26:04"
  condition:
    hash.sha256(0, filesize) == "bb9e627173974aa28c7583d80af5eb4d626a3ddf7e1926e477d4f29576209a8d"
}

rule MalwareBazaar_SalatStealer_013_7802b936
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7802b936027bad7c5eba809ba01a4c495cff1922355ad5a1bf32fab2256e54fe"
    family = "SalatStealer"
    file_name = "7802b936027bad7c.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:25:58"
  condition:
    hash.sha256(0, filesize) == "7802b936027bad7c5eba809ba01a4c495cff1922355ad5a1bf32fab2256e54fe"
}

rule MalwareBazaar_SalatStealer_014_fa18cc72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa18cc722d8d95f790dd7e51d50ea3c84b2492fbe68d0f131e46bedd8a0a9d14"
    family = "SalatStealer"
    file_name = "fa18cc722d8d95f7.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:25:48"
  condition:
    hash.sha256(0, filesize) == "fa18cc722d8d95f790dd7e51d50ea3c84b2492fbe68d0f131e46bedd8a0a9d14"
}

rule MalwareBazaar_SalatStealer_015_040dfd78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "040dfd78f8e10fb48b71be50e84305a6eb8ddc16f7234b0c3e0cb1d159db2f40"
    family = "SalatStealer"
    file_name = "040dfd78f8e10fb4.bin"
    file_type = "exe"
    first_seen = "2026-11-02 02:25:38"
  condition:
    hash.sha256(0, filesize) == "040dfd78f8e10fb48b71be50e84305a6eb8ddc16f7234b0c3e0cb1d159db2f40"
}

rule MalwareBazaar_VShell_016_979bcb16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "979bcb1667038fa9a6dd14571b46ea08443073d6c046f5fc232526f13486cd62"
    family = "VShell"
    file_name = "979bcb1667038fa9a6dd14571b46ea08443073d6c046f5fc232526f13486cd62.exe"
    file_type = "exe"
    first_seen = "2026-11-02 02:20:48"
  condition:
    hash.sha256(0, filesize) == "979bcb1667038fa9a6dd14571b46ea08443073d6c046f5fc232526f13486cd62"
}

rule MalwareBazaar_NanoCore_017_ceff4e55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceff4e55a0f6d0a0bd19984b46a7c219fa831421c80349e99d42969d63d95a6e"
    family = "NanoCore"
    file_name = "F4EEA136E304FAEB1BF05209EAA08CE1.exe"
    file_type = "exe"
    first_seen = "2026-11-02 02:10:06"
  condition:
    hash.sha256(0, filesize) == "ceff4e55a0f6d0a0bd19984b46a7c219fa831421c80349e99d42969d63d95a6e"
}

rule MalwareBazaar_unknown_018_8e9db283
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e9db283c40447a6625a2f1b6b992375537f7a9aaed16e0246093314d9780906"
    family = "unknown"
    file_name = ".16"
    file_type = "elf"
    first_seen = "2026-11-02 01:34:29"
  condition:
    hash.sha256(0, filesize) == "8e9db283c40447a6625a2f1b6b992375537f7a9aaed16e0246093314d9780906"
}

rule MalwareBazaar_Mirai_019_b4055673
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4055673180d1ffbe3ad9790e9babd8857740d214ddd832a34f39d960b95fede"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-02 01:32:03"
  condition:
    hash.sha256(0, filesize) == "b4055673180d1ffbe3ad9790e9babd8857740d214ddd832a34f39d960b95fede"
}

rule MalwareBazaar_Mirai_020_6dfb49cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dfb49cc6916fef88920780154f2a7577677f5328df182ce4b83870e7e495d11"
    family = "Mirai"
    file_name = "6dfb49cc6916fef8.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:26:20"
  condition:
    hash.sha256(0, filesize) == "6dfb49cc6916fef88920780154f2a7577677f5328df182ce4b83870e7e495d11"
}

rule MalwareBazaar_Mirai_021_0e79e57f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e79e57f073b931153db3d531b617f7a996b9fd4756b5a8d54850b3010519ae3"
    family = "Mirai"
    file_name = "0e79e57f073b9311.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:26:14"
  condition:
    hash.sha256(0, filesize) == "0e79e57f073b931153db3d531b617f7a996b9fd4756b5a8d54850b3010519ae3"
}

rule MalwareBazaar_Mirai_022_16fe10a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16fe10a71f77a1e6150226759ce7971a604ecc21fe54ccce808a00e02a7972c9"
    family = "Mirai"
    file_name = "16fe10a71f77a1e6.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:26:07"
  condition:
    hash.sha256(0, filesize) == "16fe10a71f77a1e6150226759ce7971a604ecc21fe54ccce808a00e02a7972c9"
}

rule MalwareBazaar_Mirai_023_96993b86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96993b8671b76325b7b28fc59889e430a6212843a57cf03b9a3ba1725891892a"
    family = "Mirai"
    file_name = "96993b8671b76325.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:26:01"
  condition:
    hash.sha256(0, filesize) == "96993b8671b76325b7b28fc59889e430a6212843a57cf03b9a3ba1725891892a"
}

rule MalwareBazaar_Mirai_024_99123527
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99123527030ea61be68481460e5f5265096a180c447416b335db4eeef78b2198"
    family = "Mirai"
    file_name = "99123527030ea61b.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:25:55"
  condition:
    hash.sha256(0, filesize) == "99123527030ea61be68481460e5f5265096a180c447416b335db4eeef78b2198"
}

rule MalwareBazaar_Mirai_025_d7f163cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7f163cd1aa85321a18024a413177256d03638ef7412da66224e7a65b6c951d1"
    family = "Mirai"
    file_name = "d7f163cd1aa85321.bin"
    file_type = "elf"
    first_seen = "2026-11-02 01:25:48"
  condition:
    hash.sha256(0, filesize) == "d7f163cd1aa85321a18024a413177256d03638ef7412da66224e7a65b6c951d1"
}

rule MalwareBazaar_Mirai_026_9c4ddcfb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c4ddcfb0606a3f9ac5a67b53cf30276a61db873f346c1c2caf5da9c3eb272ad"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-02 01:20:19"
  condition:
    hash.sha256(0, filesize) == "9c4ddcfb0606a3f9ac5a67b53cf30276a61db873f346c1c2caf5da9c3eb272ad"
}

rule MalwareBazaar_unknown_027_0550a6ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0550a6acf8888eb660a8e7304ac6a789c3f2dc0ea51b25bec438655d03bc9628"
    family = "unknown"
    file_name = "0550a6acf8888eb660a8e7304ac6a789c3f2dc0ea51b25bec438655d03bc9628.exe"
    file_type = "exe"
    first_seen = "2026-11-02 00:54:51"
  condition:
    hash.sha256(0, filesize) == "0550a6acf8888eb660a8e7304ac6a789c3f2dc0ea51b25bec438655d03bc9628"
}

rule MalwareBazaar_unknown_028_64fb0d53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64fb0d531b51a70cd4a40d4b2ece6c98d7a3d453c5d5b148f4cae75208584677"
    family = "unknown"
    file_name = "macho_64fb0d531b51.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:35:05"
  condition:
    hash.sha256(0, filesize) == "64fb0d531b51a70cd4a40d4b2ece6c98d7a3d453c5d5b148f4cae75208584677"
}

rule MalwareBazaar_unknown_029_b01d5a9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b01d5a9d05b788cdbff787e3317e207caec6b6e08979a1efe0f7764cbfdd86dc"
    family = "unknown"
    file_name = "macho_b01d5a9d05b7.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:33:51"
  condition:
    hash.sha256(0, filesize) == "b01d5a9d05b788cdbff787e3317e207caec6b6e08979a1efe0f7764cbfdd86dc"
}

rule MalwareBazaar_unknown_030_5c18af8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c18af8d98e6b13dbf5b8b408d817a302a5239311fff0da0319e11c9d5ce76cb"
    family = "unknown"
    file_name = "macho_5c18af8d98e6.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:32:37"
  condition:
    hash.sha256(0, filesize) == "5c18af8d98e6b13dbf5b8b408d817a302a5239311fff0da0319e11c9d5ce76cb"
}

rule MalwareBazaar_unknown_031_54e791eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54e791eba46a6655cdc58b8dc7813d27d5fcf94a1bc10468e0334f6cb7f3d32f"
    family = "unknown"
    file_name = "Reroll Bootstrapper.exe"
    file_type = "exe"
    first_seen = "2026-11-02 00:32:10"
  condition:
    hash.sha256(0, filesize) == "54e791eba46a6655cdc58b8dc7813d27d5fcf94a1bc10468e0334f6cb7f3d32f"
}

rule MalwareBazaar_unknown_032_e1b5e175
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1b5e175d4ffef096a2e6ae28cbc80983afb09dde44446297ac78290c46b5a59"
    family = "unknown"
    file_name = "e1b5e175d4ffef096a2e6ae28cbc80983afb09dde44446297ac78290c46b5a59.exe"
    file_type = "exe"
    first_seen = "2026-11-02 00:29:02"
  condition:
    hash.sha256(0, filesize) == "e1b5e175d4ffef096a2e6ae28cbc80983afb09dde44446297ac78290c46b5a59"
}

rule MalwareBazaar_SalatStealer_033_15169c97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15169c97b1503d59aa974bad5583e2a0c1fe96a9f00987f9742f18eec7b7d2f0"
    family = "SalatStealer"
    file_name = "a7076f32e0c79a95.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:25:35"
  condition:
    hash.sha256(0, filesize) == "15169c97b1503d59aa974bad5583e2a0c1fe96a9f00987f9742f18eec7b7d2f0"
}

rule MalwareBazaar_SalatStealer_034_0540d635
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0540d635edb31efd4ea4b026f1aa526ae991fc4cd214ba91930ce04a5be280f8"
    family = "SalatStealer"
    file_name = "0be112428e866e9a.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:25:30"
  condition:
    hash.sha256(0, filesize) == "0540d635edb31efd4ea4b026f1aa526ae991fc4cd214ba91930ce04a5be280f8"
}

rule MalwareBazaar_SalatStealer_035_4afc0af2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4afc0af2fe1a66a740b72a9ab743df63e2b5c2746717c1e7b29828929bf83064"
    family = "SalatStealer"
    file_name = "cd1ce568547d8816.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:25:25"
  condition:
    hash.sha256(0, filesize) == "4afc0af2fe1a66a740b72a9ab743df63e2b5c2746717c1e7b29828929bf83064"
}

rule MalwareBazaar_Mirai_036_68e2d57d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68e2d57df807683c12accac30940ead9be2b7589e33f8cf20abbdc324f09b112"
    family = "Mirai"
    file_name = "68e2d57df807683c.bin"
    file_type = "elf"
    first_seen = "2026-11-02 00:24:58"
  condition:
    hash.sha256(0, filesize) == "68e2d57df807683c12accac30940ead9be2b7589e33f8cf20abbdc324f09b112"
}

rule MalwareBazaar_AveMariaRAT_037_f12d4143
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f12d41436ae0aefec023d75df0f877e2e011bb31e1e3a2ec89f7bda6b483e386"
    family = "AveMariaRAT"
    file_name = "f12d41436ae0aefe.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:24:49"
  condition:
    hash.sha256(0, filesize) == "f12d41436ae0aefec023d75df0f877e2e011bb31e1e3a2ec89f7bda6b483e386"
}

rule MalwareBazaar_SalatStealer_038_a7076f32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7076f32e0c79a9574f70102a5baba65894fb9e01504b28cbf657ebeb6ebc081"
    family = "SalatStealer"
    file_name = "a7076f32e0c79a95.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:24:41"
  condition:
    hash.sha256(0, filesize) == "a7076f32e0c79a9574f70102a5baba65894fb9e01504b28cbf657ebeb6ebc081"
}

rule MalwareBazaar_SalatStealer_039_0be11242
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0be112428e866e9aec6b54629a4e07dc21773764f4dadf33bb81fae0077a4194"
    family = "SalatStealer"
    file_name = "0be112428e866e9a.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:24:35"
  condition:
    hash.sha256(0, filesize) == "0be112428e866e9aec6b54629a4e07dc21773764f4dadf33bb81fae0077a4194"
}

rule MalwareBazaar_SalatStealer_040_cd1ce568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd1ce568547d88162740ae66190335a2ee53ae0bf69ac6a011ad58b8c703dfe3"
    family = "SalatStealer"
    file_name = "cd1ce568547d8816.bin"
    file_type = "exe"
    first_seen = "2026-11-02 00:24:26"
  condition:
    hash.sha256(0, filesize) == "cd1ce568547d88162740ae66190335a2ee53ae0bf69ac6a011ad58b8c703dfe3"
}

rule MalwareBazaar_unknown_041_badc7693
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "badc769369c229bdde0b306aafd47ee59ce052a9dfb741a0b30432af08281328"
    family = "unknown"
    file_name = "temp.hta"
    file_type = "hta"
    first_seen = "2026-11-02 00:24:02"
  condition:
    hash.sha256(0, filesize) == "badc769369c229bdde0b306aafd47ee59ce052a9dfb741a0b30432af08281328"
}

rule MalwareBazaar_unknown_042_d1263c84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1263c84e72f95341111a570b633a7fb7ee571ab27bfe7d6eb3de527b127b4e9"
    family = "unknown"
    file_name = "macho_d1263c84e72f.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:23:17"
  condition:
    hash.sha256(0, filesize) == "d1263c84e72f95341111a570b633a7fb7ee571ab27bfe7d6eb3de527b127b4e9"
}

rule MalwareBazaar_unknown_043_ba2fb683
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba2fb68385233683f785e3bae69cb79360a2a6c48b43b44f9c43a3b8f54ca1a9"
    family = "unknown"
    file_name = "macho_ba2fb6838523.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:22:03"
  condition:
    hash.sha256(0, filesize) == "ba2fb68385233683f785e3bae69cb79360a2a6c48b43b44f9c43a3b8f54ca1a9"
}

rule MalwareBazaar_unknown_044_a881c160
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a881c160d2bec4607bbd9a0be4e4b5fcd4fa9a230a792df1ff1d049a785b45de"
    family = "unknown"
    file_name = "macho_a881c160d2be.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:20:48"
  condition:
    hash.sha256(0, filesize) == "a881c160d2bec4607bbd9a0be4e4b5fcd4fa9a230a792df1ff1d049a785b45de"
}

rule MalwareBazaar_unknown_045_93c9298f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93c9298f7f23e0bdfc19785099fc85bb04acae14bbfe9f9cc3cb9355447ac47c"
    family = "unknown"
    file_name = "macho_93c9298f7f23.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:19:31"
  condition:
    hash.sha256(0, filesize) == "93c9298f7f23e0bdfc19785099fc85bb04acae14bbfe9f9cc3cb9355447ac47c"
}

rule MalwareBazaar_unknown_046_a82977df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a82977df5edeff7790dd7fc67672afd2fb152fd2584269477a8f353a8384f94a"
    family = "unknown"
    file_name = "macho_a82977df5ede.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:18:14"
  condition:
    hash.sha256(0, filesize) == "a82977df5edeff7790dd7fc67672afd2fb152fd2584269477a8f353a8384f94a"
}

rule MalwareBazaar_unknown_047_d3146700
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3146700547025c387b0f3e707f391d59f2b62c4c60b6ecbf5134c79e01d67e1"
    family = "unknown"
    file_name = "macho_d31467005470.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:16:58"
  condition:
    hash.sha256(0, filesize) == "d3146700547025c387b0f3e707f391d59f2b62c4c60b6ecbf5134c79e01d67e1"
}

rule MalwareBazaar_unknown_048_ec038d8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec038d8ecdc9f33786ec79dab5b30ac1682bc9378540e1a7e775dda5c8bdb6b5"
    family = "unknown"
    file_name = "macho_ec038d8ecdc9.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:15:45"
  condition:
    hash.sha256(0, filesize) == "ec038d8ecdc9f33786ec79dab5b30ac1682bc9378540e1a7e775dda5c8bdb6b5"
}

rule MalwareBazaar_unknown_049_fbd3d365
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbd3d3650f2b9dfe6a0949b42e5ece6757b52506e536481982885619c5e12c74"
    family = "unknown"
    file_name = "a"
    file_type = "elf"
    first_seen = "2026-11-02 00:15:26"
  condition:
    hash.sha256(0, filesize) == "fbd3d3650f2b9dfe6a0949b42e5ece6757b52506e536481982885619c5e12c74"
}

rule MalwareBazaar_unknown_050_b3b6bcd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3b6bcd89152a5e8f9f18a814aad8b725ef89675f78f6080b86549b7ee98c5f5"
    family = "unknown"
    file_name = "a"
    file_type = "elf"
    first_seen = "2026-11-02 00:14:37"
  condition:
    hash.sha256(0, filesize) == "b3b6bcd89152a5e8f9f18a814aad8b725ef89675f78f6080b86549b7ee98c5f5"
}

rule MalwareBazaar_unknown_051_197596c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "197596c12388be1a4e07197e5b98535472a672ceab2db16c8c3737a025ffbb0d"
    family = "unknown"
    file_name = "macho_197596c12388.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:14:31"
  condition:
    hash.sha256(0, filesize) == "197596c12388be1a4e07197e5b98535472a672ceab2db16c8c3737a025ffbb0d"
}

rule MalwareBazaar_unknown_052_632f6638
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "632f6638213ec54ccbe405cfc1fecbf8bacf137cb945195e7631ac72618721db"
    family = "unknown"
    file_name = "e"
    file_type = "elf"
    first_seen = "2026-11-02 00:14:16"
  condition:
    hash.sha256(0, filesize) == "632f6638213ec54ccbe405cfc1fecbf8bacf137cb945195e7631ac72618721db"
}

rule MalwareBazaar_unknown_053_62afc2f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62afc2f766f957cb2508a957b040def43540ad35e6dcdf89c38acd545555393e"
    family = "unknown"
    file_name = "e"
    file_type = "elf"
    first_seen = "2026-11-02 00:13:54"
  condition:
    hash.sha256(0, filesize) == "62afc2f766f957cb2508a957b040def43540ad35e6dcdf89c38acd545555393e"
}

rule MalwareBazaar_unknown_054_b92921e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b92921e81666ba02fcd593c5f18aa8952b639d1fe7d13849677dd27954c479e8"
    family = "unknown"
    file_name = "macho_b92921e81666.bin"
    file_type = "macho"
    first_seen = "2026-11-02 00:13:17"
  condition:
    hash.sha256(0, filesize) == "b92921e81666ba02fcd593c5f18aa8952b639d1fe7d13849677dd27954c479e8"
}

rule MalwareBazaar_unknown_055_d831b3af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d831b3af4745718800a65012da063f1ab7a10f0c6853ac4290c8c96621829af3"
    family = "unknown"
    file_name = "zx"
    file_type = "sh"
    first_seen = "2026-11-02 00:12:19"
  condition:
    hash.sha256(0, filesize) == "d831b3af4745718800a65012da063f1ab7a10f0c6853ac4290c8c96621829af3"
}

rule MalwareBazaar_Mirai_056_f3b9bca4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3b9bca4c11c01561c52db79c81456a70d205a9e333bb27de4a35ad511f2c471"
    family = "Mirai"
    file_name = "x"
    file_type = "elf"
    first_seen = "2026-11-02 00:11:01"
  condition:
    hash.sha256(0, filesize) == "f3b9bca4c11c01561c52db79c81456a70d205a9e333bb27de4a35ad511f2c471"
}

rule MalwareBazaar_unknown_057_d2a601d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2a601d6f8bded9a1a4b5595b3b94950b72b3a5d25feb64c16f0435d41f8e2d0"
    family = "unknown"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-11-02 00:10:09"
  condition:
    hash.sha256(0, filesize) == "d2a601d6f8bded9a1a4b5595b3b94950b72b3a5d25feb64c16f0435d41f8e2d0"
}

rule MalwareBazaar_unknown_058_85bd43e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85bd43e942976b8a4ddcfe7ae22154f108139a509acb891f747d70e1cb4bac3d"
    family = "unknown"
    file_name = "s.sh"
    file_type = "sh"
    first_seen = "2026-11-02 00:09:37"
  condition:
    hash.sha256(0, filesize) == "85bd43e942976b8a4ddcfe7ae22154f108139a509acb891f747d70e1cb4bac3d"
}

rule MalwareBazaar_unknown_059_d736ac75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d736ac750da0c6329ae4f3e25159ea0f02c1a3c850a01ce60f425021e3af0615"
    family = "unknown"
    file_name = "d736ac750da0c6329ae4f3e25159ea0f02c1a3c850a01ce60f425021e3af0615.exe"
    file_type = "exe"
    first_seen = "2026-11-02 00:05:31"
  condition:
    hash.sha256(0, filesize) == "d736ac750da0c6329ae4f3e25159ea0f02c1a3c850a01ce60f425021e3af0615"
}

rule MalwareBazaar_Mirai_060_254240df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "254240df904dc29fe2e71e93a1d63c60bbe6dfd67bf3b3bc57f981e86a8dc211"
    family = "Mirai"
    file_name = "e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725.elf"
    file_type = "elf"
    first_seen = "2026-11-02 00:04:15"
  condition:
    hash.sha256(0, filesize) == "254240df904dc29fe2e71e93a1d63c60bbe6dfd67bf3b3bc57f981e86a8dc211"
}

rule MalwareBazaar_Mirai_061_e5488094
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725"
    family = "Mirai"
    file_name = "e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725.elf"
    file_type = "elf"
    first_seen = "2026-11-02 00:04:03"
  condition:
    hash.sha256(0, filesize) == "e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725"
}

rule MalwareBazaar_unknown_062_e6400ea4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6400ea4ea364afbc1dd39f6836ddcab26b6653d2c22751aac847112874ad45b"
    family = "unknown"
    file_name = "dvnx_1047c65e_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-11-01 23:41:23"
  condition:
    hash.sha256(0, filesize) == "e6400ea4ea364afbc1dd39f6836ddcab26b6653d2c22751aac847112874ad45b"
}

rule MalwareBazaar_unknown_063_26a9c39f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26a9c39f6e19e24a3690aa99d5be2515939d1f292976eb316b7690426f3b4faa"
    family = "unknown"
    file_name = "26a9c39f6e19e24a3690aa99d5be2515939d1f292976eb316b7690426f3b4faa"
    file_type = "elf"
    first_seen = "2026-11-01 22:21:02"
  condition:
    hash.sha256(0, filesize) == "26a9c39f6e19e24a3690aa99d5be2515939d1f292976eb316b7690426f3b4faa"
}

rule MalwareBazaar_unknown_064_d729ca1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d729ca1e148048aa9d42574d0cbd3486407e2746eab45583167336105637bc53"
    family = "unknown"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-01 21:53:08"
  condition:
    hash.sha256(0, filesize) == "d729ca1e148048aa9d42574d0cbd3486407e2746eab45583167336105637bc53"
}

rule MalwareBazaar_Mirai_065_45075a96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45075a965b00a8f0248dd4f40ea3621d58cefad5329ac86bf42caacc95729090"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-11-01 21:24:04"
  condition:
    hash.sha256(0, filesize) == "45075a965b00a8f0248dd4f40ea3621d58cefad5329ac86bf42caacc95729090"
}

rule MalwareBazaar_Mirai_066_a5373179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5373179735e55f60f0213c1267e1d8a163357b542de3149e8750aa0c048e39d"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-11-01 21:17:03"
  condition:
    hash.sha256(0, filesize) == "a5373179735e55f60f0213c1267e1d8a163357b542de3149e8750aa0c048e39d"
}

rule MalwareBazaar_Gh0stRAT_067_41d9eb2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41d9eb2f5418181cfe9a9955bdb1ec99692618759704b92f332d2d6e121fa4aa"
    family = "Gh0stRAT"
    file_name = "BandiZip_Setup_x64-signed.exe"
    file_type = "exe"
    first_seen = "2026-11-01 21:11:19"
  condition:
    hash.sha256(0, filesize) == "41d9eb2f5418181cfe9a9955bdb1ec99692618759704b92f332d2d6e121fa4aa"
}

rule MalwareBazaar_Mirai_068_7653b9b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7653b9b8300f1825d8dd067f4f68882181ca67148268368cac430dd7b0b2b219"
    family = "Mirai"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-11-01 21:00:04"
  condition:
    hash.sha256(0, filesize) == "7653b9b8300f1825d8dd067f4f68882181ca67148268368cac430dd7b0b2b219"
}

rule MalwareBazaar_Mirai_069_c8b1f0e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8b1f0e93528ebabaeb3139f8d22b6ae905df91c85bb4f6052e46e3dd694e649"
    family = "Mirai"
    file_name = "mips64b"
    file_type = "elf"
    first_seen = "2026-11-01 20:50:03"
  condition:
    hash.sha256(0, filesize) == "c8b1f0e93528ebabaeb3139f8d22b6ae905df91c85bb4f6052e46e3dd694e649"
}

rule MalwareBazaar_Mirai_070_7d67647e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d67647e69bc453a71eb396d90ee995548607c19784f8b063af8304ecc184ae0"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-11-01 20:42:03"
  condition:
    hash.sha256(0, filesize) == "7d67647e69bc453a71eb396d90ee995548607c19784f8b063af8304ecc184ae0"
}

rule MalwareBazaar_Mirai_071_14abfa8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14abfa8e5cbabc1dd53f633dddb91eef1aa5fa8f7ac744a1386bbfd41c899162"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-01 20:25:04"
  condition:
    hash.sha256(0, filesize) == "14abfa8e5cbabc1dd53f633dddb91eef1aa5fa8f7ac744a1386bbfd41c899162"
}

rule MalwareBazaar_unknown_072_00ef251f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00ef251f6f49eb50f3300585c814910318e7f09864ed373ec4f078d2c1471d0e"
    family = "unknown"
    file_name = "legionloader_stage5.exe"
    file_type = "exe"
    first_seen = "2026-11-01 20:19:05"
  condition:
    hash.sha256(0, filesize) == "00ef251f6f49eb50f3300585c814910318e7f09864ed373ec4f078d2c1471d0e"
}

rule MalwareBazaar_unknown_073_0c692fdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c692fdd1085f2ee287f305a1f6da6541287d9119fff13a2bd309ac0592f78d3"
    family = "unknown"
    file_name = "ver_pa_stage3.exe"
    file_type = "exe"
    first_seen = "2026-11-01 20:18:09"
  condition:
    hash.sha256(0, filesize) == "0c692fdd1085f2ee287f305a1f6da6541287d9119fff13a2bd309ac0592f78d3"
}

rule MalwareBazaar_unknown_074_7eb0d8e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7eb0d8e8f74b298885fa0ec0a0ee1e87b03e27fbff5fe41ae99edacfaac2d1a3"
    family = "unknown"
    file_name = "281.ps1"
    file_type = "ps1"
    first_seen = "2026-11-01 20:17:58"
  condition:
    hash.sha256(0, filesize) == "7eb0d8e8f74b298885fa0ec0a0ee1e87b03e27fbff5fe41ae99edacfaac2d1a3"
}

rule MalwareBazaar_unknown_075_009e0fca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "009e0fca1415e84c1f302947cb77368e60ab7755a9aadfe2cfbccb3888df1bd6"
    family = "unknown"
    file_name = "009e0fca1415e84c1f302947cb77368e60ab7755a9aadfe2cfbccb3888df1bd6"
    file_type = "sh"
    first_seen = "2026-11-01 20:17:06"
  condition:
    hash.sha256(0, filesize) == "009e0fca1415e84c1f302947cb77368e60ab7755a9aadfe2cfbccb3888df1bd6"
}

rule MalwareBazaar_SalatStealer_076_dfb724d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfb724d2cf221e476c4f48b70c06b904503efac14d771ee42e47cc0d1640db39"
    family = "SalatStealer"
    file_name = "Xeno-v1.3.65.exe"
    file_type = "exe"
    first_seen = "2026-11-01 19:51:32"
  condition:
    hash.sha256(0, filesize) == "dfb724d2cf221e476c4f48b70c06b904503efac14d771ee42e47cc0d1640db39"
}

rule MalwareBazaar_Mirai_077_986f8931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "986f893112027921a3e40de213b6a5614ed746a9aeba285e1560474f10ba7828"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-11-01 19:46:03"
  condition:
    hash.sha256(0, filesize) == "986f893112027921a3e40de213b6a5614ed746a9aeba285e1560474f10ba7828"
}

rule MalwareBazaar_unknown_078_2b938c21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b938c21f2e7e5ee825c0e7aaa39b16d8a18fe1fc6d3ae3e6227e4fd093fc223"
    family = "unknown"
    file_name = "fuck_niggers_30.hta"
    file_type = "hta"
    first_seen = "2026-11-01 19:41:03"
  condition:
    hash.sha256(0, filesize) == "2b938c21f2e7e5ee825c0e7aaa39b16d8a18fe1fc6d3ae3e6227e4fd093fc223"
}

rule MalwareBazaar_Mirai_079_506b0987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "506b0987334caab33abd876085b30e7853e4e18e9759c5afeeeb890286aba575"
    family = "Mirai"
    file_name = "mips64le"
    file_type = "elf"
    first_seen = "2026-11-01 19:33:05"
  condition:
    hash.sha256(0, filesize) == "506b0987334caab33abd876085b30e7853e4e18e9759c5afeeeb890286aba575"
}

rule MalwareBazaar_Mirai_080_6005d03c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6005d03cbe21f51a31b83a9ca019eac9416fe0fb4abdf27387a0e1f119b009d0"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-11-01 19:32:04"
  condition:
    hash.sha256(0, filesize) == "6005d03cbe21f51a31b83a9ca019eac9416fe0fb4abdf27387a0e1f119b009d0"
}

rule MalwareBazaar_RustyStealer_081_5a131246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a131246ea315e0c3ee4d9d59bceaa7ba8d0123f4ad4eacf3a20b1aaa9037ae5"
    family = "RustyStealer"
    file_name = "Xeno-v1.3.65.exe"
    file_type = "exe"
    first_seen = "2026-11-01 19:31:53"
  condition:
    hash.sha256(0, filesize) == "5a131246ea315e0c3ee4d9d59bceaa7ba8d0123f4ad4eacf3a20b1aaa9037ae5"
}

rule MalwareBazaar_Mirai_082_bb3b1683
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb3b168332ff15870726b09fec2ba68c10f38359feed3596adeb38be85a42f27"
    family = "Mirai"
    file_name = "mips64l"
    file_type = "elf"
    first_seen = "2026-11-01 19:31:03"
  condition:
    hash.sha256(0, filesize) == "bb3b168332ff15870726b09fec2ba68c10f38359feed3596adeb38be85a42f27"
}

rule MalwareBazaar_Mirai_083_de073af3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de073af31820a9a8867ccb0785ab812d0cdb3cf78a3f38d6c59846eb7eedf969"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-01 19:27:03"
  condition:
    hash.sha256(0, filesize) == "de073af31820a9a8867ccb0785ab812d0cdb3cf78a3f38d6c59846eb7eedf969"
}

rule MalwareBazaar_RemusStealer_084_d95e4be8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d95e4be8f692fba56d27c4d259f92e3c3a79e411cda521e09d92cbfd28535499"
    family = "RemusStealer"
    file_name = "shellcode_dump.bin"
    file_type = "exe"
    first_seen = "2026-11-01 19:23:29"
  condition:
    hash.sha256(0, filesize) == "d95e4be8f692fba56d27c4d259f92e3c3a79e411cda521e09d92cbfd28535499"
}

rule MalwareBazaar_Mirai_085_2822ef91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2822ef91dbb3647f7268d8d370e3f5eba7a7bf70cfe594c12bdd96f37f9291a1"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-01 19:21:04"
  condition:
    hash.sha256(0, filesize) == "2822ef91dbb3647f7268d8d370e3f5eba7a7bf70cfe594c12bdd96f37f9291a1"
}

rule MalwareBazaar_Mirai_086_28a4ad96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28a4ad963e6dcfc4df698332eddfe7c96f6463cbb954ab0a340f375c45b12c20"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-01 19:20:03"
  condition:
    hash.sha256(0, filesize) == "28a4ad963e6dcfc4df698332eddfe7c96f6463cbb954ab0a340f375c45b12c20"
}

rule MalwareBazaar_Mirai_087_66e852d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66e852d803f12b7d7939de8cbede5da5db032f6cebd4e8c5230baf05d5078a97"
    family = "Mirai"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-11-01 19:10:04"
  condition:
    hash.sha256(0, filesize) == "66e852d803f12b7d7939de8cbede5da5db032f6cebd4e8c5230baf05d5078a97"
}

rule MalwareBazaar_SilentNet_088_5cd67fea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cd67fead2ff54187c0ac0b5827fb57569760dafbe860915962bf0aad30ffc49"
    family = "SilentNet"
    file_name = "mod (12).jar"
    file_type = "jar"
    first_seen = "2026-11-01 19:02:23"
  condition:
    hash.sha256(0, filesize) == "5cd67fead2ff54187c0ac0b5827fb57569760dafbe860915962bf0aad30ffc49"
}

rule MalwareBazaar_Mirai_089_7df4e2a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7df4e2a779be6b8d959a6a5776c0635c7d5f2ab3d6cf2d4eacfe36335dc75ae3"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-11-01 18:47:03"
  condition:
    hash.sha256(0, filesize) == "7df4e2a779be6b8d959a6a5776c0635c7d5f2ab3d6cf2d4eacfe36335dc75ae3"
}

rule MalwareBazaar_Mirai_090_727acdae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "727acdae59678008bfc1cd79ebd819bde40f46e916e0ce55ba9af992f9d55f07"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-01 18:37:04"
  condition:
    hash.sha256(0, filesize) == "727acdae59678008bfc1cd79ebd819bde40f46e916e0ce55ba9af992f9d55f07"
}

rule MalwareBazaar_Mirai_091_b9b317eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9b317eb01c0ee917a3dc4e875d87c0993d3bc3ed866790cebeb5af0fb6e178c"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-11-01 18:32:03"
  condition:
    hash.sha256(0, filesize) == "b9b317eb01c0ee917a3dc4e875d87c0993d3bc3ed866790cebeb5af0fb6e178c"
}

rule MalwareBazaar_ValleyRAT_092_0d54169c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d54169c5992c55640623478ba471445b06631f9e231f8dc649886b4b7d902b0"
    family = "ValleyRAT"
    file_name = "letspnbzstup-x64.8.08.exe"
    file_type = "exe"
    first_seen = "2026-11-01 18:29:18"
  condition:
    hash.sha256(0, filesize) == "0d54169c5992c55640623478ba471445b06631f9e231f8dc649886b4b7d902b0"
}

rule MalwareBazaar_ValleyRAT_093_f02bb49b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f02bb49b2f9af8ffe36542ca968b150e7911670e8f8daf7d8e401e5b094cf83c"
    family = "ValleyRAT"
    file_name = "instoll.3.1.09.exe"
    file_type = "exe"
    first_seen = "2026-11-01 18:28:20"
  condition:
    hash.sha256(0, filesize) == "f02bb49b2f9af8ffe36542ca968b150e7911670e8f8daf7d8e401e5b094cf83c"
}

rule MalwareBazaar_Mirai_094_fb712143
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb7121430706a6380ad52ed642d93f67936c1ff96cca17f9c23b89acf1652ad1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-01 18:17:07"
  condition:
    hash.sha256(0, filesize) == "fb7121430706a6380ad52ed642d93f67936c1ff96cca17f9c23b89acf1652ad1"
}

rule MalwareBazaar_Mirai_095_e48f87a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e48f87a83c1a7bd39a8328d649e9a5a557eda8fb499c2e1d8e121b67f5481f7b"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-01 18:17:05"
  condition:
    hash.sha256(0, filesize) == "e48f87a83c1a7bd39a8328d649e9a5a557eda8fb499c2e1d8e121b67f5481f7b"
}

rule MalwareBazaar_Mirai_096_0798c759
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0798c75906cdcfecf6515bba616892908657ca26800510874f57abc8d7af9c28"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-11-01 18:16:04"
  condition:
    hash.sha256(0, filesize) == "0798c75906cdcfecf6515bba616892908657ca26800510874f57abc8d7af9c28"
}

rule MalwareBazaar_CoinMiner_097_e8a91238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8a91238df80f4649099f7cbec4460e0bc533a046a598392b14a378cc5d56075"
    family = "CoinMiner"
    file_name = "pyservice92.exe"
    file_type = "exe"
    first_seen = "2026-11-01 18:10:10"
  condition:
    hash.sha256(0, filesize) == "e8a91238df80f4649099f7cbec4460e0bc533a046a598392b14a378cc5d56075"
}

rule MalwareBazaar_Mirai_098_eaf78cea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaf78cea9535efb02cc7074e5f2d06369ec50f6d13de00e17bed330023951bd2"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-01 18:08:06"
  condition:
    hash.sha256(0, filesize) == "eaf78cea9535efb02cc7074e5f2d06369ec50f6d13de00e17bed330023951bd2"
}

rule MalwareBazaar_Mirai_099_760ed8db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "760ed8dbc45a441dd370065b02f942e20445848d350af0c05ee4cd97fb6bf31f"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-01 18:08:03"
  condition:
    hash.sha256(0, filesize) == "760ed8dbc45a441dd370065b02f942e20445848d350af0c05ee4cd97fb6bf31f"
}

rule MalwareBazaar_ValleyRAT_100_cb1a78b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb1a78b9a84034d03c92e59bb106a8feb8d26813495925e86aa7efcec160f10e"
    family = "ValleyRAT"
    file_name = "dingtaik_setup.exe"
    file_type = "exe"
    first_seen = "2026-11-01 18:05:43"
  condition:
    hash.sha256(0, filesize) == "cb1a78b9a84034d03c92e59bb106a8feb8d26813495925e86aa7efcec160f10e"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

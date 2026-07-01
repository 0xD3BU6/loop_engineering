# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-01

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 638 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 638 |
| Unique family labels | 20 |
| Unique file types | 13 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 49 |
| Mirai | 29 |
| KongTuke | 3 |
| RemcosRAT | 2 |
| NetSupport | 2 |
| WannaCry | 1 |
| Formbook | 1 |
| Hajime | 1 |
| LummaStealer | 1 |
| Socks5Systemz | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 37 |
| exe | 22 |
| apk | 11 |
| sh | 10 |
| zip | 9 |
| js | 3 |
| vbs | 2 |
| gz | 1 |
| msi | 1 |
| lnk | 1 |

## Per-Sample Analysis

### Sample 1: `d4c7d4da6b45e6f5`

| Field | Value |
|---|---|
| SHA-256 | `d4c7d4da6b45e6f599f68aa8d579926f80bbb866434109e75932263641a72359` |
| Family label | `unknown` |
| File name | `d4c7d4da6b45e6f599f68aa8d579926f80bbb866434109e75932263641a72359` |
| File type | `exe` |
| First seen | `2026-07-01 04:15:41` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e61779c553760ffac32f0184c3c28e97` |
| SHA-1 | `90fa52fd4f2c963739ab2389dac98ba3eb17e14c` |
| SHA-256 | `d4c7d4da6b45e6f599f68aa8d579926f80bbb866434109e75932263641a72359` |
| SHA3-384 | `1acf537a05f3b59c3106833262de48096c0a14b901065d7c7a977456d0126b8186b238d891bb67e14e8780aa5367ddd1` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1FA36E021F18698F5D06322B051263537EBBDE925073FF5DB6B84C8291E25BC0EB35A87` |
| SSDEEP | `49152:jnsnsQqMSPbcBVQej/1Y0OuNixlZmur2u3+hFJ:DM/qPoBhz1zOuenmur2uuh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_d4c7d4da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4c7d4da6b45e6f599f68aa8d579926f80bbb866434109e75932263641a72359"
    family = "unknown"
    file_name = "d4c7d4da6b45e6f599f68aa8d579926f80bbb866434109e75932263641a72359"
    file_type = "exe"
    first_seen = "2026-07-01 04:15:41"
  condition:
    hash.sha256(0, filesize) == "d4c7d4da6b45e6f599f68aa8d579926f80bbb866434109e75932263641a72359"
}
```

### Sample 2: `ec889a49ebd5ad66`

| Field | Value |
|---|---|
| SHA-256 | `ec889a49ebd5ad66c0499fbc6fbc604363c825abdcb216978d430a40f5fbead0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-01 03:32:59` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f23a46170f50a0a300ee75f32dcb48f8` |
| SHA-1 | `909881eeb554e63f5c01009682a66b86e2bccac1` |
| SHA-256 | `ec889a49ebd5ad66c0499fbc6fbc604363c825abdcb216978d430a40f5fbead0` |
| SHA3-384 | `8b7b29230d33a071df84a9ea8a376dec319c87a92ce089bb4830388a58d35c991b85131c010c2ffa8cc383797afbb3d7` |
| TLSH | `T163665AC367F91732E6AE0F79ACBC45110A71BD06BE2DE60E1945B4AB8977340B903367` |
| SSDEEP | `49152:OA2/PRUj4FOEQSOaYXXpDYALLRENU9Qd+buk1eHxjCJdJdUNAuqeVIpLdcQeBQAc:3eikYJAYXWU9w6ZcHEffv` |
| ICON-DHASH | `4cb26964b0cc45ba` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_ec889a49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec889a49ebd5ad66c0499fbc6fbc604363c825abdcb216978d430a40f5fbead0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-01 03:32:59"
  condition:
    hash.sha256(0, filesize) == "ec889a49ebd5ad66c0499fbc6fbc604363c825abdcb216978d430a40f5fbead0"
}
```

### Sample 3: `3483feeaab0ee0e4`

| Field | Value |
|---|---|
| SHA-256 | `3483feeaab0ee0e47bac105a2e36ff634917228cbbb8e422f1289aeee38a58e8` |
| Family label | `unknown` |
| File name | `3483feeaab0ee0e47bac105a2e36ff634917228cbbb8e422f1289aeee38a58e8` |
| File type | `elf` |
| First seen | `2026-07-01 03:20:48` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3dd18f8204782161243812edb090624` |
| SHA-1 | `45832824be96065601be988aab2eede8a0a048fc` |
| SHA-256 | `3483feeaab0ee0e47bac105a2e36ff634917228cbbb8e422f1289aeee38a58e8` |
| SHA3-384 | `f6c88f66706c8ee16a72365c2e704e98ce0cb7d475fae89522fec299cdb49b778981d22ba45532dd94305198659ff70c` |
| TLSH | `T1D5218420F3E11D56DB1AB53FF85A8702372FF90ACB978307274461EB3C15B40ACA9096` |
| SSDEEP | `24:fLjecrDf2il15x65GWdMJYzrAiJnUOiWo+6+Jk++Dg2:fLCIfVyGaMCHiabsb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_3483feea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3483feeaab0ee0e47bac105a2e36ff634917228cbbb8e422f1289aeee38a58e8"
    family = "unknown"
    file_name = "3483feeaab0ee0e47bac105a2e36ff634917228cbbb8e422f1289aeee38a58e8"
    file_type = "elf"
    first_seen = "2026-07-01 03:20:48"
  condition:
    hash.sha256(0, filesize) == "3483feeaab0ee0e47bac105a2e36ff634917228cbbb8e422f1289aeee38a58e8"
}
```

### Sample 4: `a6904afef81f509d`

| Field | Value |
|---|---|
| SHA-256 | `a6904afef81f509dad199a36cf38a78f4a6b17e15fe867e602a3b953e93fed75` |
| Family label | `unknown` |
| File name | `bbcl` |
| File type | `sh` |
| First seen | `2026-07-01 03:14:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `625ae77aaae292c9dce69e220d823cff` |
| SHA-1 | `8d7f4743b4548bc173ea14bf921a6d0ce2c861bd` |
| SHA-256 | `a6904afef81f509dad199a36cf38a78f4a6b17e15fe867e602a3b953e93fed75` |
| SHA3-384 | `29ef2bbc3ab96b5a8116601781349618677f9213e392bbd22a99addae4c3361647a974465dd649695f90778e9c1d0fcc` |
| TLSH | `T1A4E0CD61C3C6086744BF47C4B477050CF700E033BE154B183B5295B1CA74234605D065` |
| SSDEEP | `6:ho2VLnSDNe1H3EeDZNcAX/6UFxcFs7smI9//Pw81d/D7B/+bZJbKXFs7Yjs:NtHNcAX/6KPUsJbKKEjs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_a6904afe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6904afef81f509dad199a36cf38a78f4a6b17e15fe867e602a3b953e93fed75"
    family = "unknown"
    file_name = "bbcl"
    file_type = "sh"
    first_seen = "2026-07-01 03:14:07"
  condition:
    hash.sha256(0, filesize) == "a6904afef81f509dad199a36cf38a78f4a6b17e15fe867e602a3b953e93fed75"
}
```

### Sample 5: `03fc32e5233fbb4a`

| Field | Value |
|---|---|
| SHA-256 | `03fc32e5233fbb4a0e70c3b424e2bc7ecd3c60a60dda62243c79332accb09ec0` |
| Family label | `unknown` |
| File name | `ccl` |
| File type | `sh` |
| First seen | `2026-07-01 03:12:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b745b465671b9c497c6ec2c179d42833` |
| SHA-1 | `5bb9d451df9e07bd95689b1b32ce005f87df78c1` |
| SHA-256 | `03fc32e5233fbb4a0e70c3b424e2bc7ecd3c60a60dda62243c79332accb09ec0` |
| SHA3-384 | `d2f804d47e02945dc59103aa535c018f65a1e891107ede4425ef32b917bdde0db76d80ba12d914bf61f311728e5d13cc` |
| TLSH | `T16BE0C262C7DA085B487F4BC4B47B050CFB00E033BE164B1C3B9299B0CA78238606D064` |
| SSDEEP | `6:ho2VLnSDNe1H3EeDZNcAX/6UFxcFs7smI9//P5Td/D7B/+bZJbKXFs7YjV:NtHNcAX/6KCdsJbKKEjV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_03fc32e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03fc32e5233fbb4a0e70c3b424e2bc7ecd3c60a60dda62243c79332accb09ec0"
    family = "unknown"
    file_name = "ccl"
    file_type = "sh"
    first_seen = "2026-07-01 03:12:37"
  condition:
    hash.sha256(0, filesize) == "03fc32e5233fbb4a0e70c3b424e2bc7ecd3c60a60dda62243c79332accb09ec0"
}
```

### Sample 6: `4d96c7b298f7572c`

| Field | Value |
|---|---|
| SHA-256 | `4d96c7b298f7572c18106cc803f100062a80ebcd4db11e80b0fece135629bac3` |
| Family label | `unknown` |
| File name | `bwwg` |
| File type | `sh` |
| First seen | `2026-07-01 03:12:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47769afa4e83392aa1970e524498f910` |
| SHA-1 | `a50ced40d975a555ffdfb76d1c69dcd2aaeb1bb6` |
| SHA-256 | `4d96c7b298f7572c18106cc803f100062a80ebcd4db11e80b0fece135629bac3` |
| SHA3-384 | `99d2cd405bd7524eed8452ed8c3fd2d2d3ea44b5c6ab73bb362b2f14c83d32cc04477b2cc1e04dccc2a2ee01a6688296` |
| TLSH | `T162E08CA6C3CA186B84BF4AC4B47B090CFB00E433BE164B1C3B9299B1CA74234A06D464` |
| SSDEEP | `6:ho2VLnSDNe1H3EeDZNcAX/6UFxcFs7smI9//PwfQ//D7B/+bZJbKXFs7Yjs:NtHNcAX/6KPoTsJbKKEjs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_4d96c7b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d96c7b298f7572c18106cc803f100062a80ebcd4db11e80b0fece135629bac3"
    family = "unknown"
    file_name = "bwwg"
    file_type = "sh"
    first_seen = "2026-07-01 03:12:36"
  condition:
    hash.sha256(0, filesize) == "4d96c7b298f7572c18106cc803f100062a80ebcd4db11e80b0fece135629bac3"
}
```

### Sample 7: `4dd8a2c97d66f3a0`

| Field | Value |
|---|---|
| SHA-256 | `4dd8a2c97d66f3a01e73e7e0154de994a08c359674013f1ecc8e61af562d4e2f` |
| Family label | `unknown` |
| File name | `wwg` |
| File type | `sh` |
| First seen | `2026-07-01 03:12:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `faa433cce229925bfff20eba33b17575` |
| SHA-1 | `f0e2e71591de7154b1577ffc8992da79e45f9c80` |
| SHA-256 | `4dd8a2c97d66f3a01e73e7e0154de994a08c359674013f1ecc8e61af562d4e2f` |
| SHA3-384 | `1b21c5c3093be77a9e31f5c07c427650a0a2c2f8c09f99a7fdc9abcfe701194849513f7cf0f26eee1c9d1421afcc7b5e` |
| TLSH | `T164E08C66C3CA186B84BF4AC4B47B090CFA00E033BE164B183B9299B1CA7423460AD454` |
| SSDEEP | `6:ho2VLnSDNe1H3EeDZNcAX/6UFxcFs7smI9//P6Q//D7B/+bZJbKXFs7Yjs:NtHNcAX/6KGTsJbKKEjs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_4dd8a2c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dd8a2c97d66f3a01e73e7e0154de994a08c359674013f1ecc8e61af562d4e2f"
    family = "unknown"
    file_name = "wwg"
    file_type = "sh"
    first_seen = "2026-07-01 03:12:35"
  condition:
    hash.sha256(0, filesize) == "4dd8a2c97d66f3a01e73e7e0154de994a08c359674013f1ecc8e61af562d4e2f"
}
```

### Sample 8: `f4800b200b146914`

| Field | Value |
|---|---|
| SHA-256 | `f4800b200b146914f175228feab170d6cf740a637646d8a03b0a189e60749753` |
| Family label | `unknown` |
| File name | `f4800b200b146914f175228feab170d6cf740a637646d8a03b0a189e60749753` |
| File type | `elf` |
| First seen | `2026-07-01 03:01:12` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c53763fcdad2fd3e673bbe53a9718a4d` |
| SHA-1 | `5569576345dd75f70c6c2670eed106297963c4d2` |
| SHA-256 | `f4800b200b146914f175228feab170d6cf740a637646d8a03b0a189e60749753` |
| SHA3-384 | `5843c05229c33d99e14964ca1ced5d51e387a47a9393eca4e53a68d1799f9053cac01fb7bd8e202625c66c4d7619adfb` |
| TLSH | `T123215060E3E62D8AFE0AB17FF4468711273EF822C367D307178431A23C457941C1D196` |
| SSDEEP | `24:ftle3sf2il15x65vB7jX8leukiWo+6+Jk+EgZ:ftQ8fVyKvkiabJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_f4800b20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4800b200b146914f175228feab170d6cf740a637646d8a03b0a189e60749753"
    family = "unknown"
    file_name = "f4800b200b146914f175228feab170d6cf740a637646d8a03b0a189e60749753"
    file_type = "elf"
    first_seen = "2026-07-01 03:01:12"
  condition:
    hash.sha256(0, filesize) == "f4800b200b146914f175228feab170d6cf740a637646d8a03b0a189e60749753"
}
```

### Sample 9: `abea831cde9d7beb`

| Field | Value |
|---|---|
| SHA-256 | `abea831cde9d7bebf47f5f1c3535ed9c42517ecfaed2fbc0c99477d055f77557` |
| Family label | `RemcosRAT` |
| File name | `Skaaningerne.vbs` |
| File type | `vbs` |
| First seen | `2026-07-01 02:54:37` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b9395e8a1dabab4a54e9775b2f4031a` |
| SHA-1 | `d52bc4c592c99a1b475163c1a7c17144b7425f62` |
| SHA-256 | `abea831cde9d7bebf47f5f1c3535ed9c42517ecfaed2fbc0c99477d055f77557` |
| SHA3-384 | `fddcc93b364bc9299f3dbb270737b4229d8bd4cc1bad296e2d0daffc12c282b8efb48ed0b4705a52ecb93eec6bb5942d` |
| TLSH | `T181534B20DCD00B780E0717BDFD95266089BD8355422144F8EAEE771D644A6FCB7BEA78` |
| SSDEEP | `1536:5RfOII6LcTTPSLBRsc87kXBbElvXhlINmchc:TfOII6LcHPGRsl7665lINmN` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_009_abea831c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abea831cde9d7bebf47f5f1c3535ed9c42517ecfaed2fbc0c99477d055f77557"
    family = "RemcosRAT"
    file_name = "Skaaningerne.vbs"
    file_type = "vbs"
    first_seen = "2026-07-01 02:54:37"
  condition:
    hash.sha256(0, filesize) == "abea831cde9d7bebf47f5f1c3535ed9c42517ecfaed2fbc0c99477d055f77557"
}
```

### Sample 10: `72afe188ce551644`

| Field | Value |
|---|---|
| SHA-256 | `72afe188ce551644d8f437e71bae74c50dbe0b4e0628826241edd48a06d4ab13` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-01 02:35:24` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a1d6b514e6ba5b21750fee4a7d22222` |
| SHA-1 | `2fec08a5c8a5a3dc2f7f76834bcea86ec698765a` |
| SHA-256 | `72afe188ce551644d8f437e71bae74c50dbe0b4e0628826241edd48a06d4ab13` |
| SHA3-384 | `c6938d8dfdd44c65c15a3514b0ebfadeb8ed159932c8391179d4569b19abdf4a45f085213220a24ed6029d1f624daca9` |
| TLSH | `T192236C6516817C24AA99D4371D7F2F0CBDA983E6320492DD7FCA3CF28C59A9CD21871D` |
| SSDEEP | `768:tXRWNGxVa9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:Xlx9cB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_72afe188
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72afe188ce551644d8f437e71bae74c50dbe0b4e0628826241edd48a06d4ab13"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-01 02:35:24"
  condition:
    hash.sha256(0, filesize) == "72afe188ce551644d8f437e71bae74c50dbe0b4e0628826241edd48a06d4ab13"
}
```

### Sample 11: `4c6f74f1ec9009ed`

| Field | Value |
|---|---|
| SHA-256 | `4c6f74f1ec9009ed6ef66b72a8e2412ea2606a2d4788b9b3fa3573a7f080f5c1` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-01 02:22:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eae132b466adc97be5f44fe71ee404ce` |
| SHA-1 | `2fcf0eb7095ff2543568b7c17a3fc70637a08412` |
| SHA-256 | `4c6f74f1ec9009ed6ef66b72a8e2412ea2606a2d4788b9b3fa3573a7f080f5c1` |
| SHA3-384 | `8d7078bdbfa4bd2a26b48473f8d2aa1697223f86b283f54b98a13456aa92d7786ecb8426c4a9181637e6f9a9f38868e6` |
| TLSH | `T1F6246C03B6A254FDC08AC5F0475B9356EE3778A8461B75F77B843B313912EB28E09792` |
| TELFHASH | `t15a5101302ed0ba3c6192ca56b34b4f6efe77141259e276e8af17add4ec07f984c52411` |
| SSDEEP | `6144:YUgJpGaFnjw8wej3nkemVF0xdFvk1oX8AEqyf:Y79zrVtzVE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_4c6f74f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c6f74f1ec9009ed6ef66b72a8e2412ea2606a2d4788b9b3fa3573a7f080f5c1"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-01 02:22:44"
  condition:
    hash.sha256(0, filesize) == "4c6f74f1ec9009ed6ef66b72a8e2412ea2606a2d4788b9b3fa3573a7f080f5c1"
}
```

### Sample 12: `d403aa0e2a7f1ae4`

| Field | Value |
|---|---|
| SHA-256 | `d403aa0e2a7f1ae4d2fb7f4a5e1b543df59063e1fb39bd8c0bd2e11b041677b7` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-07-01 02:22:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42c7e4a3e169011e165fba800783af2b` |
| SHA-1 | `7a742bf2692bf0681cce04ee0a2361c3bd4943d7` |
| SHA-256 | `d403aa0e2a7f1ae4d2fb7f4a5e1b543df59063e1fb39bd8c0bd2e11b041677b7` |
| SHA3-384 | `d930cf11e406a1769a0869109e6f6f6830eb4ea686c689446dde463d3c1f857ccc576e6b977ba5e8c82e629eabb0b98a` |
| TLSH | `T155140842BD51AB13C1E232BBFB9E428D37196BA9D1EB32069C357F5037C68DA0D76241` |
| TELFHASH | `t1be3125715f2809ad37e5c558c1dd2117ae7930b96f5121170f8cab5f8903ec1b02e827` |
| SSDEEP | `3072:pgV+E5w7muIfyqZsJaV0+P0jpRItgHGtACVJSi0Sr1xjfWOd3:pg+FFqt+GtAcJSi0ShxTWOd3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_d403aa0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d403aa0e2a7f1ae4d2fb7f4a5e1b543df59063e1fb39bd8c0bd2e11b041677b7"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-07-01 02:22:41"
  condition:
    hash.sha256(0, filesize) == "d403aa0e2a7f1ae4d2fb7f4a5e1b543df59063e1fb39bd8c0bd2e11b041677b7"
}
```

### Sample 13: `21b135c4cd6885b2`

| Field | Value |
|---|---|
| SHA-256 | `21b135c4cd6885b2cd9f482616ebcc218bde4faa2a94b3597fca99baad695d53` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-01 02:22:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `358bd5b66aa5c914f8d470d479e6069d` |
| SHA-1 | `56d1c08a4442e4b6437269ce78ae321e28c35eeb` |
| SHA-256 | `21b135c4cd6885b2cd9f482616ebcc218bde4faa2a94b3597fca99baad695d53` |
| SHA3-384 | `5367b11041f87cb6ab4e6ff00c76408ab229535f5d88ff5b5f55d4fae03028a1f73362ea484d279514b35aad67567a1a` |
| TLSH | `T1A88312EB483AD730C93591B80DF4546CF5568D35A2488EEA2FCD30399C9A2C43ADC9CD` |
| SSDEEP | `1536:OnxbH5xZuJ+7M35dp111juADX4KtP9ncue4eDYfevqrous9zKFX3MynirxW0/0Wv:a8J+GXp1116ADX4CnyDYfeSr8Oid/bH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_21b135c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21b135c4cd6885b2cd9f482616ebcc218bde4faa2a94b3597fca99baad695d53"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-01 02:22:06"
  condition:
    hash.sha256(0, filesize) == "21b135c4cd6885b2cd9f482616ebcc218bde4faa2a94b3597fca99baad695d53"
}
```

### Sample 14: `446b0339984f9637`

| Field | Value |
|---|---|
| SHA-256 | `446b0339984f9637abd7e2117f969fc56e9f62126ff5f113fd400b3158f89ec2` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-07-01 02:22:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bb2f152e482c61934a873500e0dc191` |
| SHA-1 | `ca609d0ba8c5fdc817a3a921c0b8cf234111f8fa` |
| SHA-256 | `446b0339984f9637abd7e2117f969fc56e9f62126ff5f113fd400b3158f89ec2` |
| SHA3-384 | `0d51e5a6c93b63d8936b4f850adc3a9e03147a2c27f38fc76b0935340a1c2d722c7f3e924948c975b2510a3e0678ceb0` |
| TLSH | `T190530288F9F056B7EAEC5A75AD6BD6420AC1EDF8E03177610068CE727D02C37914EA17` |
| SSDEEP | `1536:Ih418zRoFjJ5Z0x6FZSIgpIp18k3PYEpdG4Rp0FzdbDkIcd+A:EfQjPGsFoIp+2PYmRQZvFA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_446b0339
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "446b0339984f9637abd7e2117f969fc56e9f62126ff5f113fd400b3158f89ec2"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-07-01 02:22:05"
  condition:
    hash.sha256(0, filesize) == "446b0339984f9637abd7e2117f969fc56e9f62126ff5f113fd400b3158f89ec2"
}
```

### Sample 15: `872bfbe51e7f0a27`

| Field | Value |
|---|---|
| SHA-256 | `872bfbe51e7f0a27ce6b21ac735e0640da0b21a1aa4de5051727eb2094e82392` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-07-01 02:19:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `facbbeca95c86df78d30f4edbb6e562b` |
| SHA-1 | `2a1fa219d024cd2d7c8ffbdd31ae39fff7501ad1` |
| SHA-256 | `872bfbe51e7f0a27ce6b21ac735e0640da0b21a1aa4de5051727eb2094e82392` |
| SHA3-384 | `e18d6139e657c81a6e1ce64c9a52d3d7cc176b7d5b0c8158083e5dbafc7203cc5be121529286deb39985d8347a5ca3b7` |
| TLSH | `T13CB32A136F4ECB7EF412EA3A50D7D2F863B9674646A5C46BC37C2B111AC82447C1DE8A` |
| TELFHASH | `t1c23111319b38681698d6ce78a8de1722512bc2524245e93bfe30cadc442f4ece627d5f` |
| SSDEEP | `1536:Kq6NB9+9RSDQERojoEVdYb3DnSv1uq89g5Cm+BFzE5f4bqiDuBC6pL513BWjAz4H:KqW2ErErYrLM6UbrilA3r4GQXPS9g/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_872bfbe5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "872bfbe51e7f0a27ce6b21ac735e0640da0b21a1aa4de5051727eb2094e82392"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-07-01 02:19:26"
  condition:
    hash.sha256(0, filesize) == "872bfbe51e7f0a27ce6b21ac735e0640da0b21a1aa4de5051727eb2094e82392"
}
```

### Sample 16: `0eef5bc2152e354f`

| Field | Value |
|---|---|
| SHA-256 | `0eef5bc2152e354f4650dc37092aca64aa5419fcbcb874f9605a26d3a5389999` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-01 02:16:15` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d31a5728884170e6036524cb564f227b` |
| SHA-1 | `4af17c22f356e09346114a15317a35f27935a9ff` |
| SHA-256 | `0eef5bc2152e354f4650dc37092aca64aa5419fcbcb874f9605a26d3a5389999` |
| SHA3-384 | `ee85601cb64a2c10ba394c1655ca3a1399d7022eba6496847d781f58f63ed74ceee2fbb92f1f5a10ab0b5a5bd4d2ee48` |
| TLSH | `T193018CC98044991040AE895D22976455F82183CE1A4B4B75FFAC693EAB88D04F136F94` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaCRjCgB1CDFFCFCgBnY8CRJKCSosYX:kXCKysE2hi0ziQvZohaC1h1VZ+81Jo/X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_0eef5bc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eef5bc2152e354f4650dc37092aca64aa5419fcbcb874f9605a26d3a5389999"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-01 02:16:15"
  condition:
    hash.sha256(0, filesize) == "0eef5bc2152e354f4650dc37092aca64aa5419fcbcb874f9605a26d3a5389999"
}
```

### Sample 17: `e9ddc2bd6ef86cdd`

| Field | Value |
|---|---|
| SHA-256 | `e9ddc2bd6ef86cddfd3c02413c7e1ed189126b8045325fe09a73aa498583feef` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-01 01:41:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a378598cbec5bcb58e29892bdaa0c850` |
| SHA-1 | `8a851f88cbc20009e40a579b4eaad2da95b3407f` |
| SHA-256 | `e9ddc2bd6ef86cddfd3c02413c7e1ed189126b8045325fe09a73aa498583feef` |
| SHA3-384 | `d43816547525d51b676be66894c19e728a2c991f48f36ffe1738a026d500845605fee2d3f1c43f3f80c9e96439a1f22c` |
| TLSH | `T13244951F2E128F6EF3AA977007B79E20975837D726E1C680E1ACD6115F5028D641FFA8` |
| TELFHASH | `t1ba41901c0d7817b0a6356c5d449def37d6a331db7e162c278e50e86eeb69a838d10c1c` |
| SSDEEP | `3072:ZtSTS08ekwMQ5A63mY8C4avkgxWcJuKfE9uEPaYBQfLrSTYTi:ZtSTS08eb75AOmY85aBVyYErBwrS0Ti` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_e9ddc2bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9ddc2bd6ef86cddfd3c02413c7e1ed189126b8045325fe09a73aa498583feef"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-01 01:41:40"
  condition:
    hash.sha256(0, filesize) == "e9ddc2bd6ef86cddfd3c02413c7e1ed189126b8045325fe09a73aa498583feef"
}
```

### Sample 18: `723999fb1454b2ef`

| Field | Value |
|---|---|
| SHA-256 | `723999fb1454b2ef20154487b1f9004f82ef2f40d9156f9f319b6adc006fa2ca` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-01 01:41:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ab54de26f9b10d2baeb6802d2be7356` |
| SHA-1 | `5a8d51fbe25ec0587c12b4f1acac1bacf0cb5b78` |
| SHA-256 | `723999fb1454b2ef20154487b1f9004f82ef2f40d9156f9f319b6adc006fa2ca` |
| SHA3-384 | `4a285ddcce7a0069efc3b181f592d7b834c14989e0268c4b3cf5b93a47790ee2421f8b925c8667fc31b3be47d8b54781` |
| TLSH | `T11F63012632CB149ADEEBC636449073203A316FA24552890635B7A7E3F7CE3DD6063E75` |
| SSDEEP | `1536:pFI/h2KajYYUfU1FpH+9hE2wLh4Rqzg53Q3uC/k68Ih6dVSZgP:pFI/hwlUoFpe9he4Wgu5/ZtEVEo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_723999fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "723999fb1454b2ef20154487b1f9004f82ef2f40d9156f9f319b6adc006fa2ca"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-01 01:41:23"
  condition:
    hash.sha256(0, filesize) == "723999fb1454b2ef20154487b1f9004f82ef2f40d9156f9f319b6adc006fa2ca"
}
```

### Sample 19: `6a7eac5f0e100bff`

| Field | Value |
|---|---|
| SHA-256 | `6a7eac5f0e100bffed673bf3842bfafaa276054eb99d38d296361794d41f5f81` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-07-01 01:36:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75afccabef383e1b834a3b819c83996e` |
| SHA-1 | `00842db2122ba49125d5bf8ff8bf266f065ebac0` |
| SHA-256 | `6a7eac5f0e100bffed673bf3842bfafaa276054eb99d38d296361794d41f5f81` |
| SHA3-384 | `0a054bed1406305cb6f2d32cd5c857511d1f3db15e4445ed26df55eef8e312aa52a8cac5ea33f4f8f8ec57830f92c48f` |
| TLSH | `T15D242B4278418A16D5C523BAFA6E428D33173B78D2DE7212CC24AF547BCADDB0DB7612` |
| TELFHASH | `t167b0127a22198526e14213c2d4efe23de551e0fc1f40225505c05e241c0f9c26053412` |
| SSDEEP | `3072:0ZdH7GWx4W87T++4k9Q2/Nxf0a4oEEOgOFoJv9yZTssryTAFS:uyWOWkn1NLf0a4iOgvv9qzryTAFS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_6a7eac5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a7eac5f0e100bffed673bf3842bfafaa276054eb99d38d296361794d41f5f81"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-01 01:36:42"
  condition:
    hash.sha256(0, filesize) == "6a7eac5f0e100bffed673bf3842bfafaa276054eb99d38d296361794d41f5f81"
}
```

### Sample 20: `7d658adb48717a16`

| Field | Value |
|---|---|
| SHA-256 | `7d658adb48717a16af4ee9b3c075d5ed7d4903646cb8eadd152191f5fd0d3298` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-07-01 01:36:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c387158ee9e12d18ff2daa9c1fe2eef6` |
| SHA-1 | `d8ac332aa570ca03788f1ecf1d621781af628f33` |
| SHA-256 | `7d658adb48717a16af4ee9b3c075d5ed7d4903646cb8eadd152191f5fd0d3298` |
| SHA3-384 | `1baa05cda981bc7b1fe6145022da5ae8c3c07db962851c47285b76a286e293062cbca720eb67e687061230d9946168e6` |
| TLSH | `T1BA631204C179F59AC6B338B17D3DA443626B0219C1FCBC765392E66D361BD42C6F2B09` |
| SSDEEP | `1536:LSbu5Q7TIlxcTlzWUn9lME8vGLbuoqxSeoB/jOpDn:LqiQ7cs9WUn9aE8TMeuO5n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_7d658adb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d658adb48717a16af4ee9b3c075d5ed7d4903646cb8eadd152191f5fd0d3298"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-01 01:36:27"
  condition:
    hash.sha256(0, filesize) == "7d658adb48717a16af4ee9b3c075d5ed7d4903646cb8eadd152191f5fd0d3298"
}
```

### Sample 21: `6319a8ff4c88f30f`

| Field | Value |
|---|---|
| SHA-256 | `6319a8ff4c88f30f247331f95c814dc8d89e53015f275a8e6af71c25a02149df` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-01 01:29:11` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c138466ffabcf41c0cdc23f78ce18743` |
| SHA-1 | `57f3eb5bba5e419ecdf3e9657cef09f0fcd0f481` |
| SHA-256 | `6319a8ff4c88f30f247331f95c814dc8d89e53015f275a8e6af71c25a02149df` |
| SHA3-384 | `6687691f3772e03124c2baa1bf1c8f31f0b306f9ab6a0435f854d8146d98d31b11776ad658360abb119c97337830d246` |
| IMPHASH | `73f461c771aef77ec43d53a0c54f0c8d` |
| TLSH | `T16D357C83EBA381D8C156C8B5535BF137F9627C8E4A157196ABC41E633E67B64E22CB00` |
| SSDEEP | `12288:DZ+OE4MmD6/Oyspc5EEBBBHGBgzGerwG1vPqItNquB:Dcb4M06WpoPrwivP3f5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_6319a8ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6319a8ff4c88f30f247331f95c814dc8d89e53015f275a8e6af71c25a02149df"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-01 01:29:11"
  condition:
    hash.sha256(0, filesize) == "6319a8ff4c88f30f247331f95c814dc8d89e53015f275a8e6af71c25a02149df"
}
```

### Sample 22: `b45c93767641a85d`

| Field | Value |
|---|---|
| SHA-256 | `b45c93767641a85d59ad8aa0787914fb3276be2b4301c87a2d41e03b166b5316` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-01 01:28:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `847fa977af923481735f4ee8568c51fa` |
| SHA-1 | `c0d45456518e67d6d2495d1a743f193fbf70b911` |
| SHA-256 | `b45c93767641a85d59ad8aa0787914fb3276be2b4301c87a2d41e03b166b5316` |
| SHA3-384 | `6acace15ca1a20b558bd59cb4fe74d79b0c8c98234a6f17a6f88f7fedf205d30ee86fb9b8f556c3d4b28cb366da18ea7` |
| TLSH | `T15B835C86DD8EBFC7C28921B999DFCF623223706D514803BA4E55138E83CDE9E98E3551` |
| TELFHASH | `t1a5f0ac48ac3c866a8ce30e74dd680aa28057d23720628729ff55ded0983f904f224d5f` |
| SSDEEP | `1536:ZjMFrDWuhy5QmfGVBcAL0bONVWxoOsjl0HT6nIHvNKaZKsvBdMi+5HH:5x5tBwlGT6nIPgVGBqJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_b45c9376
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b45c93767641a85d59ad8aa0787914fb3276be2b4301c87a2d41e03b166b5316"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-01 01:28:39"
  condition:
    hash.sha256(0, filesize) == "b45c93767641a85d59ad8aa0787914fb3276be2b4301c87a2d41e03b166b5316"
}
```

### Sample 23: `505a10ef3b0f4206`

| Field | Value |
|---|---|
| SHA-256 | `505a10ef3b0f4206ca9242afa64d14977396223dd5babc0842ed82b49481a95a` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-01 01:28:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91b135ed8ee76e6b428964db5d88a299` |
| SHA-1 | `a09bc4a1b5a022d2bdae76e468c3e7b613394a20` |
| SHA-256 | `505a10ef3b0f4206ca9242afa64d14977396223dd5babc0842ed82b49481a95a` |
| SHA3-384 | `846544912b6be82250fc141766009af6a9a3aa07551e96f74481b4f33e9d0838e7c6fdf6322d5073dded40f4e0b47d11` |
| TLSH | `T1B534D692A4119ADFCE0158FA73AC4F342B817C70861B1FBD59519498A28F8DFF1C6BE4` |
| SSDEEP | `3072:Ichv1aGpZV+eeerlPL85ejF7P0i8lZxDFklWY6/BUtd:IcBIGdPD85Oz0i8lT+QYkUt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_505a10ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "505a10ef3b0f4206ca9242afa64d14977396223dd5babc0842ed82b49481a95a"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-01 01:28:14"
  condition:
    hash.sha256(0, filesize) == "505a10ef3b0f4206ca9242afa64d14977396223dd5babc0842ed82b49481a95a"
}
```

### Sample 24: `5265bf543b697864`

| Field | Value |
|---|---|
| SHA-256 | `5265bf543b697864ea5014f737d219ca427714bbf092610e5dff1bae60f5d015` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-01 01:28:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `682acda74d7f0c1538ca0e3888640611` |
| SHA-1 | `819800c8a903112fa3862a14884277931cd6239a` |
| SHA-256 | `5265bf543b697864ea5014f737d219ca427714bbf092610e5dff1bae60f5d015` |
| SHA3-384 | `bbff2423d53523f88761bb90061683dc5118786b4efffea2ee592e23b9d3f46bdd5f04912fdb9a0ec87c90832d650d88` |
| TLSH | `T13DE2E1801191DFAAD9906CFBE6496FBD34827DAB335AE1293023FDE65B1C858DF86014` |
| SSDEEP | `768:ljGL9K38FtVIdjdp8NZhyPsu6Bugevh+D/nPOj:ljS08mF8ByPHQ1SoDnGj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_5265bf54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5265bf543b697864ea5014f737d219ca427714bbf092610e5dff1bae60f5d015"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-01 01:28:13"
  condition:
    hash.sha256(0, filesize) == "5265bf543b697864ea5014f737d219ca427714bbf092610e5dff1bae60f5d015"
}
```

### Sample 25: `4da2b79b14333be0`

| Field | Value |
|---|---|
| SHA-256 | `4da2b79b14333be0cf00390667dd885068b9d6d51817c7692ce43e3981179231` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-07-01 01:27:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae1cf660236b2bd8158daa3edc531985` |
| SHA-1 | `1a079d73a5a8f4fd87aba687300bf69dd32b30ab` |
| SHA-256 | `4da2b79b14333be0cf00390667dd885068b9d6d51817c7692ce43e3981179231` |
| SHA3-384 | `6159b6c05201bc5b3d394607216ff940691c1bf0c4bce3c02a89d7eb3989ddb19f621b1fdf5c8a807847f1793070261a` |
| TLSH | `T1070408457C419E05D5CA32BAFA6F028933577B79D3EA7102CD205F5527CAE8B0EB3612` |
| TELFHASH | `t13bf0dc61b45d1faaf1e6a0652ddc97509c6390959f280882ae7c82289a02cc10037803` |
| SSDEEP | `3072:ym/KGeGU1UuysUdNIL5J96ozG5ANqxaUh0QNjjMf0z5AT9tczsOi:yWUav1mh6ozuAgxaUh0QNjjMsaTjQsOi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_4da2b79b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4da2b79b14333be0cf00390667dd885068b9d6d51817c7692ce43e3981179231"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-01 01:27:38"
  condition:
    hash.sha256(0, filesize) == "4da2b79b14333be0cf00390667dd885068b9d6d51817c7692ce43e3981179231"
}
```

### Sample 26: `118b1c37983bdb00`

| Field | Value |
|---|---|
| SHA-256 | `118b1c37983bdb0003b871ce946d819fd900959fade81b40fce958d53456dfa8` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-07-01 01:27:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bdf9cf0c4366ccfa37fa5189d176780` |
| SHA-1 | `11bd46719f951dcffa0f43a40d052e14b8ecd929` |
| SHA-256 | `118b1c37983bdb0003b871ce946d819fd900959fade81b40fce958d53456dfa8` |
| SHA3-384 | `ae91146500b032ee8e9a28d438b9008419700345acc135d0938254205d96e934f981abda13bbe20816960d27aced3e5f` |
| TLSH | `T1E4530298D64CACF392F41CB6D0A96238A4DD89D750DCA077F00AE3BDE0ED0955A9D44F` |
| SSDEEP | `1536:BC8ihxlrurRUlhIhj7+/Hvj3e3BM+pHcqwfFri:lcwrRch4jqXj3ex5crfFri` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_118b1c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "118b1c37983bdb0003b871ce946d819fd900959fade81b40fce958d53456dfa8"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-01 01:27:09"
  condition:
    hash.sha256(0, filesize) == "118b1c37983bdb0003b871ce946d819fd900959fade81b40fce958d53456dfa8"
}
```

### Sample 27: `abd87d9c9ea057d7`

| Field | Value |
|---|---|
| SHA-256 | `abd87d9c9ea057d7fe828f5cd13b136220011ef97b4e65b85d3c93628366d7ca` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-01 01:25:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `005163e9b9917d4ee2a3ca605aa75cf4` |
| SHA-1 | `136beacf8c8f8313b44e0536455577156633548b` |
| SHA-256 | `abd87d9c9ea057d7fe828f5cd13b136220011ef97b4e65b85d3c93628366d7ca` |
| SHA3-384 | `b56be3da45ffe34bdc3886bdb123c51412ff63666d0de55c249384f1de7825b2b8a32b6b6bee485b330be8bdd61060a5` |
| TLSH | `T195042902771C0F43D1A36EF0263B27E083ABE96518F4A684751EBFC99371DB25485EDA` |
| SSDEEP | `3072:7SIRVr7nOj6LC4L8hvVAhsLJ+6FPxoyzdbalC6BniHIsQ:7kueV4sLJ+SPxoyJ+lCanbsQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_abd87d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abd87d9c9ea057d7fe828f5cd13b136220011ef97b4e65b85d3c93628366d7ca"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-01 01:25:50"
  condition:
    hash.sha256(0, filesize) == "abd87d9c9ea057d7fe828f5cd13b136220011ef97b4e65b85d3c93628366d7ca"
}
```

### Sample 28: `bd0b8f9db1efebae`

| Field | Value |
|---|---|
| SHA-256 | `bd0b8f9db1efebae48c870bbfbb1f33ae068c13a23149633aeda27c43daadd4b` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-01 01:25:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0eed57f757e116c3322507ad4c19ab0` |
| SHA-1 | `b144946d0209e01c19039fdc4e1d1564558fb120` |
| SHA-256 | `bd0b8f9db1efebae48c870bbfbb1f33ae068c13a23149633aeda27c43daadd4b` |
| SHA3-384 | `c4db60a405dc1e7d54c8e6bf60d972782893dbf2c0b8c241e35e15f57a5cf97f1c1ce6fd7cd6387eb96c1bcb6552cb9a` |
| TLSH | `T18853F15CF184B859EFAB6A66CC9F422217D053DA3D58ACF31E0EFF54B0128407B285E9` |
| SSDEEP | `1536:OPSTTfaaPFAWk1Lbj/daJMXaTBOBLoJx4u+qgw0Vul:/fZk1Lbj/WMqT0Ux4u+qgw2ul` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_bd0b8f9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd0b8f9db1efebae48c870bbfbb1f33ae068c13a23149633aeda27c43daadd4b"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-01 01:25:37"
  condition:
    hash.sha256(0, filesize) == "bd0b8f9db1efebae48c870bbfbb1f33ae068c13a23149633aeda27c43daadd4b"
}
```

### Sample 29: `9c1502fb7bacf86a`

| Field | Value |
|---|---|
| SHA-256 | `9c1502fb7bacf86a0c6b5da53fc6d019f9be27137f149e4f48b6017575678a0e` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-07-01 01:24:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e69b4afa9203c67a600dd36bbb5337d` |
| SHA-1 | `b1eb7ded34e7f113d60bd9cdebe7b4eda6242656` |
| SHA-256 | `9c1502fb7bacf86a0c6b5da53fc6d019f9be27137f149e4f48b6017575678a0e` |
| SHA3-384 | `12aaf7eef656a50e906f7be7a77d9c7b3629f8439bc6834949eae077f571116bd9a77b3b52cd8b66375984a3a45e90fd` |
| TLSH | `T1E014F752BD51AF23C1E232BBFB9E428D37156B69D1EB32069C227F5037C68DA0D76241` |
| TELFHASH | `t14831f1774f5869ec63c5c649d1ee516a2ee470f96f602412995ddb0fc883fc1b02883b` |
| SSDEEP | `3072:uoY5ny1YrGm+85WOYkhUHWkSCII5n8TIEGAzrt2kzYTUvsGGoXe3:vYUHWkSCb1SIEGAvt2kzKUvSoXe3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_9c1502fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c1502fb7bacf86a0c6b5da53fc6d019f9be27137f149e4f48b6017575678a0e"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-01 01:24:35"
  condition:
    hash.sha256(0, filesize) == "9c1502fb7bacf86a0c6b5da53fc6d019f9be27137f149e4f48b6017575678a0e"
}
```

### Sample 30: `e850272e0d23dc74`

| Field | Value |
|---|---|
| SHA-256 | `e850272e0d23dc7490bd4b39d75372f0886f5e2d6ed0ce1aca5ed064bf72d496` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-07-01 01:24:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `108f438519d87bb65e27a6251a09a674` |
| SHA-1 | `4a9bdf3f658edb551cfe3be9c50bbc125997ffd9` |
| SHA-256 | `e850272e0d23dc7490bd4b39d75372f0886f5e2d6ed0ce1aca5ed064bf72d496` |
| SHA3-384 | `93222613dd3d39b6ffd9389795e4716355724d5934d2e093d5532d4652990a0f69f2236f24a2995eef866d10f5def61f` |
| TLSH | `T15D5301900FDF5528D0721AFCC9A51D8CB0AA0F7CE976183B4BDD485A1293EA766F091E` |
| SSDEEP | `1536:thGkDpEwSqiXe+bToo/UY7DukoYH/1T4GLgOe+1K8T6qkL5f:VD17iO+b/UY7KgT4GLG+hkL5f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_e850272e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e850272e0d23dc7490bd4b39d75372f0886f5e2d6ed0ce1aca5ed064bf72d496"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-01 01:24:23"
  condition:
    hash.sha256(0, filesize) == "e850272e0d23dc7490bd4b39d75372f0886f5e2d6ed0ce1aca5ed064bf72d496"
}
```

### Sample 31: `e2b7ae14c2f73b26`

| Field | Value |
|---|---|
| SHA-256 | `e2b7ae14c2f73b26023c1c0c7c7d8c0bff44d121f50d8dd7d538edaeb56cffc6` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-01 01:15:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a29072ab3334680850f5ed5e04c1768` |
| SHA-1 | `7f390fe7324127c868df30a514f1c5134f2b6784` |
| SHA-256 | `e2b7ae14c2f73b26023c1c0c7c7d8c0bff44d121f50d8dd7d538edaeb56cffc6` |
| SHA3-384 | `1d0f98426215132c1c02237077294e2988d931fb8c9cb92e160ce8f422963e51845b0ecf75f6a1043f6ec8800ce06add` |
| TLSH | `T17A44D706AF610FF7D8ABCD7306EA1B0128CC681B16A97F76B634D968B50B58F05C3974` |
| SSDEEP | `3072:wwI+tNbWY/fQFc+8lBCpwlZJ9JibwPnfg5McZeoLBBEltt:wwttNaYXQFcG0ZhikvfSnHBBE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_e2b7ae14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2b7ae14c2f73b26023c1c0c7c7d8c0bff44d121f50d8dd7d538edaeb56cffc6"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-01 01:15:58"
  condition:
    hash.sha256(0, filesize) == "e2b7ae14c2f73b26023c1c0c7c7d8c0bff44d121f50d8dd7d538edaeb56cffc6"
}
```

### Sample 32: `13a61afc3252a69b`

| Field | Value |
|---|---|
| SHA-256 | `13a61afc3252a69bd3ff8b4bd180e261a00dacf1da023b80357be62b3aa67a9e` |
| Family label | `WannaCry` |
| File name | `13a61afc3252a69bd3ff8b4bd180e261a00dacf1da023b80357be62b3aa67a9e` |
| File type | `exe` |
| First seen | `2026-07-01 01:15:13` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7efd4ff709467f3a4de33cd367434861` |
| SHA-1 | `95d56457a12525fb12151405d6ff7b9318760e28` |
| SHA-256 | `13a61afc3252a69bd3ff8b4bd180e261a00dacf1da023b80357be62b3aa67a9e` |
| SHA3-384 | `f88e4486a843727ab288f984fef30bf6bb31b2efc6ec023f1f5c2c12661795c0bdc1ad01738fc9b866b4e633a988c9e3` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1843633546268A1BDE0411AF4C4638D16B3B3BCD567BA4B0F87C4B26F0D73B97AB94702` |
| SSDEEP | `98304:DyDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVpNZH:DyDqPe1Cxcxk3ZAEUadzR8ycPZH` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_032_13a61afc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13a61afc3252a69bd3ff8b4bd180e261a00dacf1da023b80357be62b3aa67a9e"
    family = "WannaCry"
    file_name = "13a61afc3252a69bd3ff8b4bd180e261a00dacf1da023b80357be62b3aa67a9e"
    file_type = "exe"
    first_seen = "2026-07-01 01:15:13"
  condition:
    hash.sha256(0, filesize) == "13a61afc3252a69bd3ff8b4bd180e261a00dacf1da023b80357be62b3aa67a9e"
}
```

### Sample 33: `5df4a21520354416`

| Field | Value |
|---|---|
| SHA-256 | `5df4a215203544161eee5872bd304e9ba17d9aa880fa3a2b089b9ba37720fbee` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-01 01:15:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `842e59861532bd54c658ae1fda142143` |
| SHA-1 | `3210ad76a034276b0c0e6145b71add6d46920e2f` |
| SHA-256 | `5df4a215203544161eee5872bd304e9ba17d9aa880fa3a2b089b9ba37720fbee` |
| SHA3-384 | `d58d3d08cb9b9ccb16ef25b4efbec9a96c47a3c4bae266c75a3256c1ab98d35ff22192fbc24979b653c648d7ed35a037` |
| TLSH | `T19863F17F42242EC8C9AE69BD409873C6392517C4329A9E5932594DCDE1E3E8FFA4C464` |
| SSDEEP | `1536:S1QI7kC5Kx5cVYMUpZbZs/aPKvxFP2/xvLHFOBo:SyIwC8+OM8Z0MYXPMxvLHFx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_5df4a215
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5df4a215203544161eee5872bd304e9ba17d9aa880fa3a2b089b9ba37720fbee"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-01 01:15:12"
  condition:
    hash.sha256(0, filesize) == "5df4a215203544161eee5872bd304e9ba17d9aa880fa3a2b089b9ba37720fbee"
}
```

### Sample 34: `860b79ec3a237149`

| Field | Value |
|---|---|
| SHA-256 | `860b79ec3a237149b42c9c4756cbdd96b27d68fcb782b101c25d3bb506636b3b` |
| Family label | `unknown` |
| File name | `RTO-E-Challan-500.apk` |
| File type | `apk` |
| First seen | `2026-07-01 00:56:04` |
| Reporter | `BastianHein_` |
| Tags | `apk, GhostGrab` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e477925826f9a99575a80bd4c60edda6` |
| SHA-1 | `2eb34d1d5daf626e6c684f5bea63adb86b9b35a3` |
| SHA-256 | `860b79ec3a237149b42c9c4756cbdd96b27d68fcb782b101c25d3bb506636b3b` |
| SHA3-384 | `7543fb4f507a8d57d1f796b7556eceb7e501a23a2fb41fd838c1af68cad44323a093439adb3298b1996c43799927cdcf` |
| TLSH | `T185E622E7BBD55979D432A0B1982D27A5655B9D208F179B4BAC00371C38F72D83F88EC8` |
| SSDEEP | `393216:Seu98GjSi5yEidv7+UgSfJOQ3gLzXo+Qi8h5MAW:1uPSi5yEit7+TSY0gLjEM7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_860b79ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "860b79ec3a237149b42c9c4756cbdd96b27d68fcb782b101c25d3bb506636b3b"
    family = "unknown"
    file_name = "RTO-E-Challan-500.apk"
    file_type = "apk"
    first_seen = "2026-07-01 00:56:04"
  condition:
    hash.sha256(0, filesize) == "860b79ec3a237149b42c9c4756cbdd96b27d68fcb782b101c25d3bb506636b3b"
}
```

### Sample 35: `8bf6dd0572e247d8`

| Field | Value |
|---|---|
| SHA-256 | `8bf6dd0572e247d89f8cd7a99db2557cf4a7e954d8222c0862ad13713f85aaa0` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-01 00:52:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36394d889c85e01d73200bbfecbf0d68` |
| SHA-1 | `77892b584b1978fff16002bc74c3f34eeee04a33` |
| SHA-256 | `8bf6dd0572e247d89f8cd7a99db2557cf4a7e954d8222c0862ad13713f85aaa0` |
| SHA3-384 | `af567af32c5b8635ca67ad57ac335d9ab263291b89daa9130b50dd1922dff69d58649342f676ac5c1254bca2c0afd52a` |
| TLSH | `T17BF30A81FA43CBF7E44706F002BBA7334531FC3A442AE686DBA5FE7669619C0D649358` |
| TELFHASH | `t1a2517bb76ba61eecb7d09901c3cf3700dd0de267791035be06a316d122b6d41a57acba` |
| SSDEEP | `3072:gsJNbqMfYyCI4Bm2jBLsdqU3wHHRdslkKyEYBWLTpqzXNEzjqXAi4ppWzcgEAO5+:3nbqMfYyCI4Bm2jBLsdB3wHHRdwkKyEi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_8bf6dd05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bf6dd0572e247d89f8cd7a99db2557cf4a7e954d8222c0862ad13713f85aaa0"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-01 00:52:42"
  condition:
    hash.sha256(0, filesize) == "8bf6dd0572e247d89f8cd7a99db2557cf4a7e954d8222c0862ad13713f85aaa0"
}
```

### Sample 36: `504590bd0ca8c991`

| Field | Value |
|---|---|
| SHA-256 | `504590bd0ca8c9913dde882532fbcef50b6b6cbb8519bcf55ec1dc76cdd7c2ab` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-01 00:52:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9c78f7f95a5318d6acc21667e71f928` |
| SHA-1 | `c626f7b5e0cba9171c337401e995ae2607d98582` |
| SHA-256 | `504590bd0ca8c9913dde882532fbcef50b6b6cbb8519bcf55ec1dc76cdd7c2ab` |
| SHA3-384 | `6298b631afa43ac250c87dc4ebc932586c1c3208bc72173fca8474eeb26f432cf86be595929bd7eacf58bc2fe22a7127` |
| TLSH | `T1864302A3C4A04BC6E679547915DB5FC1CC89E10C02E85E78FB6975CB1CCEED432146E6` |
| SSDEEP | `1536:lWS7ALSp7WpyQ449XbmrRMyb2k4Owcnznouy8x:lW8pCpyC9XcoJQLoutx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_504590bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "504590bd0ca8c9913dde882532fbcef50b6b6cbb8519bcf55ec1dc76cdd7c2ab"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-01 00:52:06"
  condition:
    hash.sha256(0, filesize) == "504590bd0ca8c9913dde882532fbcef50b6b6cbb8519bcf55ec1dc76cdd7c2ab"
}
```

### Sample 37: `78533e66970f86f2`

| Field | Value |
|---|---|
| SHA-256 | `78533e66970f86f2a8f583b40a54c5c4a70afadda811ace35cd7380352765b1b` |
| Family label | `unknown` |
| File name | `apk.apk` |
| File type | `apk` |
| First seen | `2026-07-01 00:51:22` |
| Reporter | `BastianHein_` |
| Tags | `apk, Herodotus, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11fd8ed08f879873b20a338a2679e259` |
| SHA-1 | `e1549357cdf50b6689a021da9d0ec8d90b49e59f` |
| SHA-256 | `78533e66970f86f2a8f583b40a54c5c4a70afadda811ace35cd7380352765b1b` |
| SHA3-384 | `ac141feca12807cdca97707c4df891b249b3fbd7494d6260c72d396be990cfa8f3cdf123698edb1c49e0569dc3ef262c` |
| TLSH | `T1BBE50253FAE14F57C435C13A29A253A12335AD188A52EF079184B3BA7CF36D95BC62CC` |
| SSDEEP | `49152:tyXeTILBtftZ3B4bTXBy9tP9eacqqU4KQzS9ld/JQ1umSzlSWAPQ:MuIlzvqTX8HDMU4KZ9ldv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_78533e66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78533e66970f86f2a8f583b40a54c5c4a70afadda811ace35cd7380352765b1b"
    family = "unknown"
    file_name = "apk.apk"
    file_type = "apk"
    first_seen = "2026-07-01 00:51:22"
  condition:
    hash.sha256(0, filesize) == "78533e66970f86f2a8f583b40a54c5c4a70afadda811ace35cd7380352765b1b"
}
```

### Sample 38: `9d419c77b9124062`

| Field | Value |
|---|---|
| SHA-256 | `9d419c77b9124062c92de6e7f1140cc4af9f3371a362b0d3aa4a0159647da077` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-01 00:42:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc8bdec930fe5c781fc02cef72786257` |
| SHA-1 | `7de156c3507b5ea6e5f09df7b8b314f69d723f8d` |
| SHA-256 | `9d419c77b9124062c92de6e7f1140cc4af9f3371a362b0d3aa4a0159647da077` |
| SHA3-384 | `97d3c61b64fd99ed34ae9091236888021029541a20e744f0175ca95eaa4bcfab397b476eb748c877e5a6ccb054d6e387` |
| TLSH | `T154016FC941509950506EDD5E22D76590B811C3CE0A4F0B74BFDC593EFB98904F237F98` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaCRjCKB1CDBFCFCgBtXxY8CR1KCSos0auD:kXCKysE2hi0ziQvZohaC111rZC8TJoB7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_9d419c77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d419c77b9124062c92de6e7f1140cc4af9f3371a362b0d3aa4a0159647da077"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-01 00:42:46"
  condition:
    hash.sha256(0, filesize) == "9d419c77b9124062c92de6e7f1140cc4af9f3371a362b0d3aa4a0159647da077"
}
```

### Sample 39: `615302d2052274be`

| Field | Value |
|---|---|
| SHA-256 | `615302d2052274be34164da6f349ecc8a9bc1d8404e10999572beb03dac4b009` |
| Family label | `Formbook` |
| File name | `Purchase_Order_Form.js` |
| File type | `js` |
| First seen | `2026-07-01 00:34:18` |
| Reporter | `threatcat_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c19975c267e1eae827bcca9d2c7333a` |
| SHA-1 | `bc665923ded5680a5cf2b1bb0901fdc72f598c5c` |
| SHA-256 | `615302d2052274be34164da6f349ecc8a9bc1d8404e10999572beb03dac4b009` |
| SHA3-384 | `50dad12d33a153b021a08a7bbe383bdfb0e5ea5d6e9dd82bef810cb5cf66b7fde18a98c43278a44fd9e670b21cd03689` |
| TLSH | `T17D953C77B7C428307760590697EF1697B69E32A237EB1D4A11B4CFCE536340AA0B8E5C` |
| SSDEEP | `12288:xyYxZRjD1plDXYuTB+i6BDApXbReJN99Ad18Bxb8gBeN94uy:rLFYQN94uy` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_039_615302d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "615302d2052274be34164da6f349ecc8a9bc1d8404e10999572beb03dac4b009"
    family = "Formbook"
    file_name = "Purchase_Order_Form.js"
    file_type = "js"
    first_seen = "2026-07-01 00:34:18"
  condition:
    hash.sha256(0, filesize) == "615302d2052274be34164da6f349ecc8a9bc1d8404e10999572beb03dac4b009"
}
```

### Sample 40: `c2d5a838ebf3525e`

| Field | Value |
|---|---|
| SHA-256 | `c2d5a838ebf3525e22fc008b859a8a5e9f1a2fa7bcd351489e7a1310da10d219` |
| Family label | `unknown` |
| File name | `Fexoglobal_CRM_API_Documentation.zip` |
| File type | `zip` |
| First seen | `2026-07-01 00:32:31` |
| Reporter | `smica83` |
| Tags | `UKR, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4668a9265bb682bbecc26a7b47c35985` |
| SHA-1 | `511ad6e38a8569e438c6f21ba873fb7a9d5d3949` |
| SHA-256 | `c2d5a838ebf3525e22fc008b859a8a5e9f1a2fa7bcd351489e7a1310da10d219` |
| SHA3-384 | `c34e39e984127ad738a58a92ba94ba4e00d07f40c9f4b40ede3148ad9b751fedbd0826b50425234df465ec05087c2869` |
| TLSH | `T1E5410933455B706CC15D017F7091315C77FBDB27787EE017ABA590259482AC54B0FB8A` |
| SSDEEP | `48:9jTIICA6GTpJMhkDeBpj7DgiHiR2IphG5G8aICxg6fZ5Gv:od2PMh77jiLphUG8aI0Lfmv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_c2d5a838
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2d5a838ebf3525e22fc008b859a8a5e9f1a2fa7bcd351489e7a1310da10d219"
    family = "unknown"
    file_name = "Fexoglobal_CRM_API_Documentation.zip"
    file_type = "zip"
    first_seen = "2026-07-01 00:32:31"
  condition:
    hash.sha256(0, filesize) == "c2d5a838ebf3525e22fc008b859a8a5e9f1a2fa7bcd351489e7a1310da10d219"
}
```

### Sample 41: `f0ac0e283232df69`

| Field | Value |
|---|---|
| SHA-256 | `f0ac0e283232df690bb16bd7c8194b6ceabacf62807fed0482db9bc1c4c046e9` |
| Family label | `unknown` |
| File name | `f0ac0e283232df690bb16bd7c8194b6ceabacf62807fed0482db9bc1c4c046e9` |
| File type | `gz` |
| First seen | `2026-07-01 00:31:17` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, gz` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4407ba5b0bbbba5e259fc3f55766ae10` |
| SHA-1 | `7c602f287f26a4c6f73c1c97ebc64d82a8179c2a` |
| SHA-256 | `f0ac0e283232df690bb16bd7c8194b6ceabacf62807fed0482db9bc1c4c046e9` |
| SHA3-384 | `7695c51238ca88ed42a39e491a1eedd8ebb61e46bd98c4df9b0cd021deb34f3009ecd748573ed03e7871a8d0b1f8fbc1` |
| TLSH | `T1ECE533522EDA8B2B6AF0E037F25CB430DDF22BB5D23E85A076C5ED61A4994F50D1C078` |
| SSDEEP | `49152:yqCeyU99K8VJRNj6ujE+oGGOlAgmfFbJRDANf9wBL+0s3fXMltEYoTN627WPKZOr:yqbBX3Dw+oWl9m3RMNVwjsPGITN6qWPR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_f0ac0e28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0ac0e283232df690bb16bd7c8194b6ceabacf62807fed0482db9bc1c4c046e9"
    family = "unknown"
    file_name = "f0ac0e283232df690bb16bd7c8194b6ceabacf62807fed0482db9bc1c4c046e9"
    file_type = "gz"
    first_seen = "2026-07-01 00:31:17"
  condition:
    hash.sha256(0, filesize) == "f0ac0e283232df690bb16bd7c8194b6ceabacf62807fed0482db9bc1c4c046e9"
}
```

### Sample 42: `b6a2638a0eaedd60`

| Field | Value |
|---|---|
| SHA-256 | `b6a2638a0eaedd6065b8fae3162ae34685c782efb70282febeef0b9470c5b60d` |
| Family label | `unknown` |
| File name | `PT2600000043.js` |
| File type | `js` |
| First seen | `2026-07-01 00:20:27` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `400ef619ba4d603ec61d5cc687b0370c` |
| SHA-1 | `d17a9771a3b059b47b07c9c548451a64a73496c8` |
| SHA-256 | `b6a2638a0eaedd6065b8fae3162ae34685c782efb70282febeef0b9470c5b60d` |
| SHA3-384 | `4b01cca4a129733d38677e02639846ad34aad797833b9efba031deefbd389eca840e89daedbe4a8ae3900dbb46525aa8` |
| TLSH | `T1F1957128AD3E8029B7B2F58997C11043DD97F6E767388E9052864B8D4713E9E24DF32D` |
| SSDEEP | `12288:MSfRfMgbCdC8SR6ZPFBKQ8/DLWfL3DvvaoyfkjVZST6z:MSGhOM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_b6a2638a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6a2638a0eaedd6065b8fae3162ae34685c782efb70282febeef0b9470c5b60d"
    family = "unknown"
    file_name = "PT2600000043.js"
    file_type = "js"
    first_seen = "2026-07-01 00:20:27"
  condition:
    hash.sha256(0, filesize) == "b6a2638a0eaedd6065b8fae3162ae34685c782efb70282febeef0b9470c5b60d"
}
```

### Sample 43: `b1ee2ec96a5464bd`

| Field | Value |
|---|---|
| SHA-256 | `b1ee2ec96a5464bd5c8658b8b11d62586ef514687ce05280380621565b54254f` |
| Family label | `unknown` |
| File name | `hax.sh` |
| File type | `sh` |
| First seen | `2026-06-30 23:10:32` |
| Reporter | `anonymous` |
| Tags | `crypto, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68ad6a4881f3b60efee20d411729615c` |
| SHA-256 | `b1ee2ec96a5464bd5c8658b8b11d62586ef514687ce05280380621565b54254f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_b1ee2ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1ee2ec96a5464bd5c8658b8b11d62586ef514687ce05280380621565b54254f"
    family = "unknown"
    file_name = "hax.sh"
    file_type = "sh"
    first_seen = "2026-06-30 23:10:32"
  condition:
    hash.sha256(0, filesize) == "b1ee2ec96a5464bd5c8658b8b11d62586ef514687ce05280380621565b54254f"
}
```

### Sample 44: `4ef31fbebeb16219`

| Field | Value |
|---|---|
| SHA-256 | `4ef31fbebeb162195c0facda1be5dd9b9b57fdaf95f39f657bab7681feec0930` |
| Family label | `Hajime` |
| File name | `i` |
| File type | `elf` |
| First seen | `2026-06-30 22:41:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Hajime` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `286fcf6a5a412cf0db7c051cc815cc0b` |
| SHA-1 | `fc973de7896bf295af3fd25497192251466c85c6` |
| SHA-256 | `4ef31fbebeb162195c0facda1be5dd9b9b57fdaf95f39f657bab7681feec0930` |
| SHA3-384 | `07dde0909672842a9481ec776a2a64f290a5bc9e95019b6715abdf0c37bc3a54b6f7ab63cbb8257a0c6e4b6e8f87d2de` |
| TLSH | `T12D831229235514E9D96681F193FC1B846E981FA9CFE2EC147C12BD9CED233AD3CC2618` |
| SSDEEP | `1536:yYI0ARqw1qAEW67UIWi7M8gmfmJo0WgswnD6Efyq8PxlRkp29J1V+uBNu:yYI0ARqw1qAEv7UIFM8oJorFquyjkRkx` |

#### Technical Assessment

- The sample is tracked as `Hajime` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Hajime_044_4ef31fbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ef31fbebeb162195c0facda1be5dd9b9b57fdaf95f39f657bab7681feec0930"
    family = "Hajime"
    file_name = "i"
    file_type = "elf"
    first_seen = "2026-06-30 22:41:37"
  condition:
    hash.sha256(0, filesize) == "4ef31fbebeb162195c0facda1be5dd9b9b57fdaf95f39f657bab7681feec0930"
}
```

### Sample 45: `1a08a7669246227b`

| Field | Value |
|---|---|
| SHA-256 | `1a08a7669246227bf3070bd666e2f8bcf7385d08727ba0b4ab3a9195eaac284d` |
| Family label | `unknown` |
| File name | `1a08a7669246227bf3070bd666e2f8bcf7385d08727ba0b4ab3a9195eaac284d` |
| File type | `elf` |
| First seen | `2026-06-30 22:28:59` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5035d79a634455d6f41b44a6861a5aa5` |
| SHA-1 | `030a55a3070940b2c15211f0965bd51beef3efb4` |
| SHA-256 | `1a08a7669246227bf3070bd666e2f8bcf7385d08727ba0b4ab3a9195eaac284d` |
| SHA3-384 | `f8a0d2f2fe3e670c59696b3e0de522ecd19714557e5f6dc7b66255211fe9d882512d63d976bc9ed1f919a2ffec49e1b1` |
| TLSH | `T191E02B02CB43D56FC1C00273C4C91356B3B4E518860B33D3D0C63E33AC2A5801E03D20` |
| SSDEEP | `6:BnX//InsE/ptkEVtztibP7bQhd9ny5uwvXaBrg0/gWylSMhR1Blq03C:BvwnskAEVFsQh65fKB00/bxOLBl5S` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_1a08a766
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a08a7669246227bf3070bd666e2f8bcf7385d08727ba0b4ab3a9195eaac284d"
    family = "unknown"
    file_name = "1a08a7669246227bf3070bd666e2f8bcf7385d08727ba0b4ab3a9195eaac284d"
    file_type = "elf"
    first_seen = "2026-06-30 22:28:59"
  condition:
    hash.sha256(0, filesize) == "1a08a7669246227bf3070bd666e2f8bcf7385d08727ba0b4ab3a9195eaac284d"
}
```

### Sample 46: `45d3513dc95750c5`

| Field | Value |
|---|---|
| SHA-256 | `45d3513dc95750c55f733fc27f83d009d46631cc1d4494f5d842d42a3ffe9151` |
| Family label | `unknown` |
| File name | `PоpkаUz19+.apk` |
| File type | `apk` |
| First seen | `2026-06-30 21:27:16` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, Riskware, signed, SmsSpy, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c800bab552b8059488b19248837e8127` |
| SHA-1 | `876fedbe6bb2e79e2bb401e7833068492a93e1f6` |
| SHA-256 | `45d3513dc95750c55f733fc27f83d009d46631cc1d4494f5d842d42a3ffe9151` |
| SHA3-384 | `58fd4206d10495695566571f789e10fd55beb721e94e1bf14239f19372b7abc264c5d5fde1d3ec68ac6be5bbb7c96214` |
| TLSH | `T101662381EF41D92EC4B740370D6613356656DE1ECA93A347A5DC362C2C7B6C80FEAAD8` |
| SSDEEP | `196608:T7gRJeDIIo07AOmJt284CPi37q3AwgeZ3T:wRIDIIj7kJMci3bwX3T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_45d3513d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45d3513dc95750c55f733fc27f83d009d46631cc1d4494f5d842d42a3ffe9151"
    family = "unknown"
    file_name = "PоpkаUz19+.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:27:16"
  condition:
    hash.sha256(0, filesize) == "45d3513dc95750c55f733fc27f83d009d46631cc1d4494f5d842d42a3ffe9151"
}
```

### Sample 47: `93ce021f85518306`

| Field | Value |
|---|---|
| SHA-256 | `93ce021f8551830646d4a75a6be6f420fd4d68e65964057d7d91dfee34d3ab0f` |
| Family label | `unknown` |
| File name | `T!kT0k 18+._1782805172643.apk` |
| File type | `apk` |
| First seen | `2026-06-30 21:25:59` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60741b29d109fe799810a60cfa339a10` |
| SHA-1 | `3eeb65c7c1886de2220185cbf4425e8cce5aecf1` |
| SHA-256 | `93ce021f8551830646d4a75a6be6f420fd4d68e65964057d7d91dfee34d3ab0f` |
| SHA3-384 | `0fc0a15556262c113939b4300459500f9b767f7f8d65fcf9ce33af32e91ccb9bad882c09afcf146a678727f691d524d4` |
| TLSH | `T178662382FF46D52FD4B781371E62173262A68D1EC686934785EC762C1CB72D84FCAAC4` |
| SSDEEP | `98304:k83+fxTp9CmpoVTmpu11neBkN6owypRuw9ibvQ25446Rx3gaqtJ3hNdHMQA5KDOb:jO/9CmpoV6Uhu7bvTmrqr3NsMDJ5ds` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_93ce021f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93ce021f8551830646d4a75a6be6f420fd4d68e65964057d7d91dfee34d3ab0f"
    family = "unknown"
    file_name = "T!kT0k 18+._1782805172643.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:25:59"
  condition:
    hash.sha256(0, filesize) == "93ce021f8551830646d4a75a6be6f420fd4d68e65964057d7d91dfee34d3ab0f"
}
```

### Sample 48: `40d224726eacba5b`

| Field | Value |
|---|---|
| SHA-256 | `40d224726eacba5b74eb7c41cacd13ae996b8639148b94be34ce80ca679b2236` |
| Family label | `unknown` |
| File name | `T!kT0k 18+._1782805455920.apk` |
| File type | `apk` |
| First seen | `2026-06-30 21:25:05` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae1894528746e506c8b1cdbb4c7f7ede` |
| SHA-1 | `c44d66bc9fb6d7bc6f9464cb49741616683ee8ae` |
| SHA-256 | `40d224726eacba5b74eb7c41cacd13ae996b8639148b94be34ce80ca679b2236` |
| SHA3-384 | `7b6b0f4f3d7798754098a7766bd4fc9ccca2df11c5cda8cd186c53fc7e7b23d5b52c5a0c73a7ea84e2f0121aeb9af68b` |
| TLSH | `T1ED662381EF42D42EC4B744370D93173622669D1ECA97A34799EC76292C772D80FEAEC4` |
| SSDEEP | `196608:9pzUEH9vY2Ny00M9KkkcSidAf/rrmpWm4wGP:9plH9HpfBOrrjm4wy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_40d22472
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40d224726eacba5b74eb7c41cacd13ae996b8639148b94be34ce80ca679b2236"
    family = "unknown"
    file_name = "T!kT0k 18+._1782805455920.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:25:05"
  condition:
    hash.sha256(0, filesize) == "40d224726eacba5b74eb7c41cacd13ae996b8639148b94be34ce80ca679b2236"
}
```

### Sample 49: `581d28d8f57fca6d`

| Field | Value |
|---|---|
| SHA-256 | `581d28d8f57fca6d65b91a7f44d08e57d43aab20a337aaa9011ff1c8835f71fb` |
| Family label | `unknown` |
| File name | `Т???.Т??.??+.apk` |
| File type | `apk` |
| First seen | `2026-06-30 21:24:08` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, TilTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `714e330c474a6d77cad41c3cee2c3222` |
| SHA-1 | `e23891d1db49284513690da3772b2ed8c9fa0695` |
| SHA-256 | `581d28d8f57fca6d65b91a7f44d08e57d43aab20a337aaa9011ff1c8835f71fb` |
| SHA3-384 | `ad5693512374388d1b01a97dae0639dbf0626560300d60364216141db99b660a3a8a2b13822c043cec16ef6b9ba26ff0` |
| TLSH | `T14F562285EF46D82FC4BB443B1A86473166A69D1EC683E34784EC722C69372D84FD9EC4` |
| SSDEEP | `98304:enj6FGzyS/jcqkCqkbmHpL7PIzl+9a27ULsjKjhxElTNCp6RnOvu94l39fN6a:K6M/jcq3qkbmJL7gzl2jjKlxEnC6lOWg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_581d28d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "581d28d8f57fca6d65b91a7f44d08e57d43aab20a337aaa9011ff1c8835f71fb"
    family = "unknown"
    file_name = "Т???.Т??.??+.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:24:08"
  condition:
    hash.sha256(0, filesize) == "581d28d8f57fca6d65b91a7f44d08e57d43aab20a337aaa9011ff1c8835f71fb"
}
```

### Sample 50: `4e52f85b5be6cdcf`

| Field | Value |
|---|---|
| SHA-256 | `4e52f85b5be6cdcfc8a3493c0d56e99494a36871e53ef90ea915015a9fcbbdff` |
| Family label | `unknown` |
| File name | `TikTok18.apk` |
| File type | `apk` |
| First seen | `2026-06-30 21:21:49` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, Riskware, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e673f474ef3fbfb60c9ae9c32829d4bf` |
| SHA-1 | `44c4be3ecc83a30db2483eb9895e30ec48fb6eaf` |
| SHA-256 | `4e52f85b5be6cdcfc8a3493c0d56e99494a36871e53ef90ea915015a9fcbbdff` |
| SHA3-384 | `4e1161b34bb68654923eb783f7bfa7f95680d65d0dff24838626ca864430859eac30b79f6b55157ef53c154d539f724a` |
| TLSH | `T1DB67231AEFC87A6BC5F74236587A55254C430C44838BCA82EE9A752C2C776F1B71DBC8` |
| SSDEEP | `786432:ctCiCLBpRFLh2AeNlUCwCeoJeZcFQGUBuLbXOQgJ:ctCiCLBTFLhpeNlBwCeoJEcFQGKuLLUJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_4e52f85b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e52f85b5be6cdcfc8a3493c0d56e99494a36871e53ef90ea915015a9fcbbdff"
    family = "unknown"
    file_name = "TikTok18.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:21:49"
  condition:
    hash.sha256(0, filesize) == "4e52f85b5be6cdcfc8a3493c0d56e99494a36871e53ef90ea915015a9fcbbdff"
}
```

### Sample 51: `87b4cae8ed4c474e`

| Field | Value |
|---|---|
| SHA-256 | `87b4cae8ed4c474ece3b42a998fd0f7b86b74cebcd1fbcdc4aca155ce582e7ea` |
| Family label | `unknown` |
| File name | `ŦikŦokprivat.apk` |
| File type | `apk` |
| First seen | `2026-06-30 21:20:29` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3703d7010a1a1e5c4f1558d5012999ae` |
| SHA-1 | `0d93ed635b1917f2a95114b4a4029230b9a18a2d` |
| SHA-256 | `87b4cae8ed4c474ece3b42a998fd0f7b86b74cebcd1fbcdc4aca155ce582e7ea` |
| SHA3-384 | `768b7cba576fdbe7f45adefda34ffb6bf5fbc059c9e02f96d4746cb63c30fe0c7d980378ae16769bbf4f4efb2c265dd6` |
| TLSH | `T152562281EF46E82FC47B45331AA2473526529D1E8A87A7438AEC352C6C777C80FD9ED4` |
| SSDEEP | `98304:aigak5b/8PYYcGGx3lf87+3OZzS06YoDDrS7Zv3dTYaT+0QNAxYR47aS/gfyhU:aig1/8PfGHU7zz+i92ATVxYW2CrhU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_87b4cae8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87b4cae8ed4c474ece3b42a998fd0f7b86b74cebcd1fbcdc4aca155ce582e7ea"
    family = "unknown"
    file_name = "ŦikŦokprivat.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:20:29"
  condition:
    hash.sha256(0, filesize) == "87b4cae8ed4c474ece3b42a998fd0f7b86b74cebcd1fbcdc4aca155ce582e7ea"
}
```

### Sample 52: `51f505968f17455c`

| Field | Value |
|---|---|
| SHA-256 | `51f505968f17455c7ee7c1309064a2ec0870e0e120080d0bbbb19076a1c112c5` |
| Family label | `unknown` |
| File name | `?а?_?о??.??+.apk` |
| File type | `apk` |
| First seen | `2026-06-30 21:19:23` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `318483a4bccf7f42f253d3f5db653707` |
| SHA-1 | `38fafe8732130bd78ef5ca4c156fdba20cad3c6d` |
| SHA-256 | `51f505968f17455c7ee7c1309064a2ec0870e0e120080d0bbbb19076a1c112c5` |
| SHA3-384 | `4fd6b5f2204ee615aae4e112c903b32f0dad13827929135260eec1020db2a0e76d22798d18bbffb82d153f44cb1e20af` |
| TLSH | `T12B562381EF86D82FC8B781375DA60B3122569C1EC787A30795EC365C58776D84FCAAC8` |
| SSDEEP | `196608:LO049WOzEIMNpjkPAqyri/hpbwJS34QhO:qIOze1qdppEJSIQhO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_51f50596
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51f505968f17455c7ee7c1309064a2ec0870e0e120080d0bbbb19076a1c112c5"
    family = "unknown"
    file_name = "?а?_?о??.??+.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:19:23"
  condition:
    hash.sha256(0, filesize) == "51f505968f17455c7ee7c1309064a2ec0870e0e120080d0bbbb19076a1c112c5"
}
```

### Sample 53: `84fdf69c73817014`

| Field | Value |
|---|---|
| SHA-256 | `84fdf69c7381701415d366808450de41e3127d15c497a196bd51cc3ecf3eeaea` |
| Family label | `LummaStealer` |
| File name | `NEET-UG Paper leak legal documents.zip` |
| File type | `zip` |
| First seen | `2026-06-30 21:17:50` |
| Reporter | `smica83` |
| Tags | `APT36, LummaStealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00f341a353de29dfe19e4796d27c1879` |
| SHA-1 | `710e2131d541988134205a9f401f4a3a0d22c8d4` |
| SHA-256 | `84fdf69c7381701415d366808450de41e3127d15c497a196bd51cc3ecf3eeaea` |
| SHA3-384 | `ff6af84d3b7d067e3d3c6354b621a2ca088b9e3f2db0ebc85026ee6526c68c227ea2599e17e9500c78938ff1c39ba324` |
| TLSH | `T1A7D5332575C2BC4DF62B9774C29196904BF6BAB11F934C6220F8C319A379DFB8281877` |
| SSDEEP | `49152:wCSqZy+z99PwNtaC0eXachGt8qGpXlAGL5pvlwRx58a5+71svVjpQF5Eyq3KE:wTqIgLEaeXachGt8tpX17vs78k+7K07S` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_053_84fdf69c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84fdf69c7381701415d366808450de41e3127d15c497a196bd51cc3ecf3eeaea"
    family = "LummaStealer"
    file_name = "NEET-UG Paper leak legal documents.zip"
    file_type = "zip"
    first_seen = "2026-06-30 21:17:50"
  condition:
    hash.sha256(0, filesize) == "84fdf69c7381701415d366808450de41e3127d15c497a196bd51cc3ecf3eeaea"
}
```

### Sample 54: `627451891fcf7498`

| Field | Value |
|---|---|
| SHA-256 | `627451891fcf7498670f2df5e764101ceb2a8e62dc4aa6bdddb3614dae911444` |
| Family label | `unknown` |
| File name | `Xuper TV APK_ películas, series y televisión en....apk` |
| File type | `apk` |
| First seen | `2026-06-30 20:53:47` |
| Reporter | `BastianHein_` |
| Tags | `apk, Konfety, XuperTV` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ca34f7a65f851597317858fdbbd1670` |
| SHA-1 | `e85c1db211e1116160497c707f3dbc43408bfd22` |
| SHA-256 | `627451891fcf7498670f2df5e764101ceb2a8e62dc4aa6bdddb3614dae911444` |
| SHA3-384 | `1990a6a7d036492b22382fcdafa00927faff0dc36c4f44b10675e2d1ca0bfe13a8748827c3f0c51021bdbb5c86de05b0` |
| TLSH | `T154062302F7B9EA5BD8B9C1350D45A334052ABD24CE07B78B3800B7AD29776E84F957D2` |
| SSDEEP | `98304:Aj8m+k+VYrQD5v14jjvpyYrFawcT/X1XvUKte5IDqTmdr:AYm+zV4QNvOjjvpjBajv1sKt0qqSr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_62745189
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "627451891fcf7498670f2df5e764101ceb2a8e62dc4aa6bdddb3614dae911444"
    family = "unknown"
    file_name = "Xuper TV APK_ películas, series y televisión en....apk"
    file_type = "apk"
    first_seen = "2026-06-30 20:53:47"
  condition:
    hash.sha256(0, filesize) == "627451891fcf7498670f2df5e764101ceb2a8e62dc4aa6bdddb3614dae911444"
}
```

### Sample 55: `1afdbb93a7e3858d`

| Field | Value |
|---|---|
| SHA-256 | `1afdbb93a7e3858d99ed41134ce4bda6e48cc6aa5f55b6495d46c0c4b2abb95f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 20:48:56` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0f323561cb0d5ddfddf30408657f60c` |
| SHA-1 | `f71e25ba1f793f9ba9d211389d7613a975cb5853` |
| SHA-256 | `1afdbb93a7e3858d99ed41134ce4bda6e48cc6aa5f55b6495d46c0c4b2abb95f` |
| SHA3-384 | `adfa94795bf2c042a7146fce0a899ec26d2aacf54b9ce75b7c553faff0138c125fa13e8a0b8c8b1aa43e7d65de6c95ef` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T11A1833249B948CD6F45631399A906244E3F3BA6517B08FAE0FC06B212E275FBEC7D351` |
| SSDEEP | `1572864:iAYyyxBU7rUFpYcHK8o8iLxMtQ6ZMo/STJ6ppJ2FNwW5wF:ifxgkCUc4R/U6pXoQF` |
| ICON-DHASH | `82908e8e8e8e39d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_1afdbb93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1afdbb93a7e3858d99ed41134ce4bda6e48cc6aa5f55b6495d46c0c4b2abb95f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 20:48:56"
  condition:
    hash.sha256(0, filesize) == "1afdbb93a7e3858d99ed41134ce4bda6e48cc6aa5f55b6495d46c0c4b2abb95f"
}
```

### Sample 56: `82bfd294e0ee5496`

| Field | Value |
|---|---|
| SHA-256 | `82bfd294e0ee5496229a8734d9d8282fbb1e397c56669c7de579b5951bb44a0b` |
| Family label | `unknown` |
| File name | `poop` |
| File type | `elf` |
| First seen | `2026-06-30 20:23:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9da1414feec33800b7d1e2c11ed2bd28` |
| SHA-1 | `45cad64ac94419c51cbf0fefd7351c9f8f6cdc1e` |
| SHA-256 | `82bfd294e0ee5496229a8734d9d8282fbb1e397c56669c7de579b5951bb44a0b` |
| SHA3-384 | `caa52c6c7c733212e6b0911328588bbdc61928d07e30ec0b475c12fcf2e7b1f90e4ee20d35fffbb3b858201a320e0066` |
| TLSH | `T12BE423F15931A657ECE34426B9AE614091F2BAB1EA4CF2650121FC387E24EC6D70F4E7` |
| SSDEEP | `12288:aejIro9698mOhbGFWoJWdB4QN/42HTp8mFCmGYNDHOTD1lWT1zxIKV6OA:5IrSo8lbGgoJWdBfZlTp8hz5bWTLIKVm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_82bfd294
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82bfd294e0ee5496229a8734d9d8282fbb1e397c56669c7de579b5951bb44a0b"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-06-30 20:23:38"
  condition:
    hash.sha256(0, filesize) == "82bfd294e0ee5496229a8734d9d8282fbb1e397c56669c7de579b5951bb44a0b"
}
```

### Sample 57: `5550e9b063aa3dbf`

| Field | Value |
|---|---|
| SHA-256 | `5550e9b063aa3dbf466593011bc7c1b6c01e54ff2ffeeaad74814a7726c35804` |
| Family label | `Socks5Systemz` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 20:19:04` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, Socks5Systemz, UNIQTWO.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2dfe7a647bfd6602e54d8803a9326207` |
| SHA-1 | `d8d4de8f8a3a4ed9bc97d1423134ec13112bbfaa` |
| SHA-256 | `5550e9b063aa3dbf466593011bc7c1b6c01e54ff2ffeeaad74814a7726c35804` |
| SHA3-384 | `848f6b8d4117a3c1b4679158b6f691924890b3a9b0b5f18ca9e544b6aa46ce3b05dd82b3738ef7c8fa83533fe81d6baf` |
| IMPHASH | `884310b1928934402ea6fec1dbd3cf5e` |
| TLSH | `T17DF53353A0EC9672C0F7A0366C15890364BB65A3261A309D7AAF1DDD1F33E3F9D5132A` |
| SSDEEP | `98304:NpRtf5OOBRInJwIT8Tpmwc4od0aZTJB+jrqW3F:TYiybT8UwroTdBcr33F` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `Socks5Systemz` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Socks5Systemz_057_5550e9b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5550e9b063aa3dbf466593011bc7c1b6c01e54ff2ffeeaad74814a7726c35804"
    family = "Socks5Systemz"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 20:19:04"
  condition:
    hash.sha256(0, filesize) == "5550e9b063aa3dbf466593011bc7c1b6c01e54ff2ffeeaad74814a7726c35804"
}
```

### Sample 58: `932fee49d6fef547`

| Field | Value |
|---|---|
| SHA-256 | `932fee49d6fef5473a0a055a74d17dc880d6996dea36f96a157d78a89c822aa8` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-30 20:17:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a72efa80266d2ec9998fdfc91c82148e` |
| SHA-1 | `a0cb4f19dba018518a7adc1055b3c08136789a5d` |
| SHA-256 | `932fee49d6fef5473a0a055a74d17dc880d6996dea36f96a157d78a89c822aa8` |
| SHA3-384 | `bd08044b53828b7031d00f9e15e3e4348efdc9b242025984365baad7ede1d3a57b844fe4a811303f27a0a2bfa338212b` |
| TLSH | `T186236C6516857C24AE99C4375C7F2F0CB9A983E6310491DDBFCA3CF28C4AA9CE21875D` |
| SSDEEP | `768:Fr9NyXsZztC79GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:NHusZlcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_932fee49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "932fee49d6fef5473a0a055a74d17dc880d6996dea36f96a157d78a89c822aa8"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-30 20:17:39"
  condition:
    hash.sha256(0, filesize) == "932fee49d6fef5473a0a055a74d17dc880d6996dea36f96a157d78a89c822aa8"
}
```

### Sample 59: `6f32c5f4d665488b`

| Field | Value |
|---|---|
| SHA-256 | `6f32c5f4d665488b58eddca27ca5621571d55caccc73012ded3ae898a5721935` |
| Family label | `unknown` |
| File name | `tsetup-x64.6.8.2.zip` |
| File type | `zip` |
| First seen | `2026-06-30 20:10:04` |
| Reporter | `skocherhan` |
| Tags | `feijicz-com-cn, Telegram, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58523a28308d738d8af7b7659db5dc24` |
| SHA-1 | `6e76887630360f5298324c52860e100f43833133` |
| SHA-256 | `6f32c5f4d665488b58eddca27ca5621571d55caccc73012ded3ae898a5721935` |
| SHA3-384 | `7bc9450282330b7be839a13557b2336e59c5fa33c3942e516005bdfc1ace471072f7f9ece02ecbf9499ed4b20cc539af` |
| TLSH | `T10918337B6DAECFFA5A3F5CA5D0A43A9D3500B8F670404679F68A99E4430F8274671CC2` |
| SSDEEP | `1572864:MNVQpHK48Zk+DvAgxGUwtwx2+IWD9XZM8P4YU+ZdBua7tw4/vWmVo3AC1h8wh:MNVQM4W5DA+GUwWx4WRXvgd+Zs42mVGx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_6f32c5f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f32c5f4d665488b58eddca27ca5621571d55caccc73012ded3ae898a5721935"
    family = "unknown"
    file_name = "tsetup-x64.6.8.2.zip"
    file_type = "zip"
    first_seen = "2026-06-30 20:10:04"
  condition:
    hash.sha256(0, filesize) == "6f32c5f4d665488b58eddca27ca5621571d55caccc73012ded3ae898a5721935"
}
```

### Sample 60: `7947220463ee9c53`

| Field | Value |
|---|---|
| SHA-256 | `7947220463ee9c537118d668419b01412a674a5e6eaeaf17fcbe00d121048908` |
| Family label | `unknown` |
| File name | `MeiqiaWinLatest.exe` |
| File type | `exe` |
| First seen | `2026-06-30 19:59:15` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91f406040865b07cd4e9d2e88a0b2ff9` |
| SHA-1 | `20c67828f8abf9f4e3ce5218537bdf98bc124e8f` |
| SHA-256 | `7947220463ee9c537118d668419b01412a674a5e6eaeaf17fcbe00d121048908` |
| SHA3-384 | `bacec5ab2aa81f5d2c99e8fd7cdeb8c3a5e466da3e2dfcfecad13e8630179849ad13f5d149ae2e34962e63ad2f1322a0` |
| IMPHASH | `50da9c66b00fd68bbfb8d54a47418acd` |
| TLSH | `T1D8F7338667A800E8E253D17DC8068A4BEBF2F8910B31C7DF51655A6E1F777E20D2A317` |
| SSDEEP | `1572864:BwJnwjuvAnqUCUYOqPS1CXR+7FfsWynauK1JBWawUpIUCBb1RGfqt:CRwWGqUCUJ4XAFEWynaTBEUCNZ` |
| ICON-DHASH | `fadadac2a2b8c4e4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_79472204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7947220463ee9c537118d668419b01412a674a5e6eaeaf17fcbe00d121048908"
    family = "unknown"
    file_name = "MeiqiaWinLatest.exe"
    file_type = "exe"
    first_seen = "2026-06-30 19:59:15"
  condition:
    hash.sha256(0, filesize) == "7947220463ee9c537118d668419b01412a674a5e6eaeaf17fcbe00d121048908"
}
```

### Sample 61: `5835f5b27cd6f62d`

| Field | Value |
|---|---|
| SHA-256 | `5835f5b27cd6f62d186fa92210f0cae7238e2aa2e030d0f223e1d2adc7016c4b` |
| Family label | `ValleyRAT` |
| File name | `Meiqia-Win.exe` |
| File type | `exe` |
| First seen | `2026-06-30 19:58:12` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43f1a9accf541df4ce951ae76a058597` |
| SHA-1 | `00991fc23b055982b5064518fa7ccf2aadeb841e` |
| SHA-256 | `5835f5b27cd6f62d186fa92210f0cae7238e2aa2e030d0f223e1d2adc7016c4b` |
| SHA3-384 | `3e629f15ca57251fe007f6a1ede0d0fa8edf969b15c3fa18e11030325219aec73ebf6f67c8514757b12d633646e9529f` |
| IMPHASH | `b0130e7048d354c48872be643fd2b583` |
| TLSH | `T1E9082307A3A106E5D237D279CAA69333D7707C905738C68F5198E21A2F33A909F7B365` |
| SSDEEP | `1572864:n4JnwjuvAnqUCUYOqPS1CXR+7FfsWynauK1JBWawUpIUCBb1RGfq4:n4RwWGqUCUJ4XAFEWynaTBEUCN` |
| ICON-DHASH | `71e0d0c8c0f061b2` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_061_5835f5b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5835f5b27cd6f62d186fa92210f0cae7238e2aa2e030d0f223e1d2adc7016c4b"
    family = "ValleyRAT"
    file_name = "Meiqia-Win.exe"
    file_type = "exe"
    first_seen = "2026-06-30 19:58:12"
  condition:
    hash.sha256(0, filesize) == "5835f5b27cd6f62d186fa92210f0cae7238e2aa2e030d0f223e1d2adc7016c4b"
}
```

### Sample 62: `119479bef84f5d0c`

| Field | Value |
|---|---|
| SHA-256 | `119479bef84f5d0c6eaf972fc4b80dfbf04cb8332221a81ccfe214b4100f2ecd` |
| Family label | `unknown` |
| File name | `ainstall-setup63890002.msi` |
| File type | `msi` |
| First seen | `2026-06-30 19:57:16` |
| Reporter | `CNGaoLing` |
| Tags | `msi, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba6b08f590cb1c097458f1a5430b2148` |
| SHA-1 | `886632634824ed62dd6b471019d616cbe9789035` |
| SHA-256 | `119479bef84f5d0c6eaf972fc4b80dfbf04cb8332221a81ccfe214b4100f2ecd` |
| SHA3-384 | `8b6d7bfa4133c34b722cdcd5ebacfff03c95e0cd87b54a4a11d4da083c7f1413b3200f7f87cadfbe25fea03bd439449e` |
| TLSH | `T134A633D1BD8634B5D16BC3F441013A6E7C6A7FC2FBA2DC0A6AB673005D72A1657B6308` |
| SSDEEP | `196608:SLKMQZ06NE+NVKrZHlb8uVqBuXDQ+f5higqWloQp+9k03Sml/9C:YQzNJTKrJlbDVXc+fqfEoQ89kiSmXC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_119479be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "119479bef84f5d0c6eaf972fc4b80dfbf04cb8332221a81ccfe214b4100f2ecd"
    family = "unknown"
    file_name = "ainstall-setup63890002.msi"
    file_type = "msi"
    first_seen = "2026-06-30 19:57:16"
  condition:
    hash.sha256(0, filesize) == "119479bef84f5d0c6eaf972fc4b80dfbf04cb8332221a81ccfe214b4100f2ecd"
}
```

### Sample 63: `2d9945bba8207d41`

| Field | Value |
|---|---|
| SHA-256 | `2d9945bba8207d419dca32e5c2ecc821f3eedd5c48bc1ebfe754133c56a17828` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-06-30 18:29:09` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5afc984a6d0ebb82ea875af5b2ae5b12` |
| SHA-1 | `90da06ce83496aa9f1f0ace48e0751f08fc3327d` |
| SHA-256 | `2d9945bba8207d419dca32e5c2ecc821f3eedd5c48bc1ebfe754133c56a17828` |
| SHA3-384 | `dbcba0b2f8dc4e35044ac8826a7f13a91964f6bad19b16cb48cc4a981168bd39b23815a14ba2cab39d586379ea09eab6` |
| TLSH | `T1BCD097A215B301F0A03E8860F5EAA400B050C37F0D84D219B99734F01E40309F1D1BA0` |
| SSDEEP | `3:TKH4vLYNu/8o/3Y4XseqYMQWtmhHJMPsFZAutDMFsMLONFYqGSrP/c5c/DOOdKXp:hTMToTt+aAulNXYq9DG+NjVsNXYrkJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_2d9945bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d9945bba8207d419dca32e5c2ecc821f3eedd5c48bc1ebfe754133c56a17828"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-30 18:29:09"
  condition:
    hash.sha256(0, filesize) == "2d9945bba8207d419dca32e5c2ecc821f3eedd5c48bc1ebfe754133c56a17828"
}
```

### Sample 64: `75e67e073558cd81`

| Field | Value |
|---|---|
| SHA-256 | `75e67e073558cd811b0053119653eba536f66ac9b01a9a71559225e4b920dea8` |
| Family label | `unknown` |
| File name | `FluxMarket_CRM_API_Credentials.pdf.lnk` |
| File type | `lnk` |
| First seen | `2026-06-30 18:15:21` |
| Reporter | `smica83` |
| Tags | `lnk, UKR` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cebf8d399115e3ab098bbaf6d4bcd7a` |
| SHA-1 | `cb8a7e6126acbeae2c189bbf1c14d6be98f0da30` |
| SHA-256 | `75e67e073558cd811b0053119653eba536f66ac9b01a9a71559225e4b920dea8` |
| SHA3-384 | `448ebb0c06bc4ec8786efac42e38e256ff4714952d6d9a9b4c37e9dcb0e75942df98d9d38664e1154b68d1c986fcfbbf` |
| TLSH | `T1A4516E142FFA5330F3B29EB998F953519877B995EE719B4D006006491823F41ED72F2B` |
| SSDEEP | `48:8NxoSOFMyQoTA409y3yqzfjoE6LtzYo2eQHsbOMw2qdbbYm:8NxqFMZL9y3Hz4RzNQHgO5z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `lnk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_75e67e07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75e67e073558cd811b0053119653eba536f66ac9b01a9a71559225e4b920dea8"
    family = "unknown"
    file_name = "FluxMarket_CRM_API_Credentials.pdf.lnk"
    file_type = "lnk"
    first_seen = "2026-06-30 18:15:21"
  condition:
    hash.sha256(0, filesize) == "75e67e073558cd811b0053119653eba536f66ac9b01a9a71559225e4b920dea8"
}
```

### Sample 65: `a1dbae0dd3e1d72f`

| Field | Value |
|---|---|
| SHA-256 | `a1dbae0dd3e1d72f649be1c8a999274a22127ed27165018af1d96b7d6eda9baa` |
| Family label | `unknown` |
| File name | `NAKAZ_MO_perevirka_mayna.zip` |
| File type | `zip` |
| First seen | `2026-06-30 18:11:11` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `258aa2891f92620aa8540ab6ba13c9f4` |
| SHA-1 | `2167099d63bf1d92b02241312f467a5acbf4f181` |
| SHA-256 | `a1dbae0dd3e1d72f649be1c8a999274a22127ed27165018af1d96b7d6eda9baa` |
| SHA3-384 | `2defb7a55a79b88ee9b7c952cbaedc15952e62621d9cd7624d50467f68dcf9b16eb16a4366b51d96c9d497033fb34b5a` |
| TLSH | `T10E42AF8036E86304F2B2BE3DDE3A5B404537BAD0EE35839C8A10DC1D1966611CD74F36` |
| SSDEEP | `48:V7PtJeQqTellc51WUrfAx7PUuuGJIEuqTelA51WUSxB1Bg/E7o/j27H:V7lJe7ellcn7i7suuGJIYelAnCT7J7H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_a1dbae0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1dbae0dd3e1d72f649be1c8a999274a22127ed27165018af1d96b7d6eda9baa"
    family = "unknown"
    file_name = "NAKAZ_MO_perevirka_mayna.zip"
    file_type = "zip"
    first_seen = "2026-06-30 18:11:11"
  condition:
    hash.sha256(0, filesize) == "a1dbae0dd3e1d72f649be1c8a999274a22127ed27165018af1d96b7d6eda9baa"
}
```

### Sample 66: `90eb69c1b119e418`

| Field | Value |
|---|---|
| SHA-256 | `90eb69c1b119e418b381c5754cbee51d6f4e10018c386228e954759a041eedad` |
| Family label | `KongTuke` |
| File name | `package` |
| File type | `zip` |
| First seen | `2026-06-30 18:10:22` |
| Reporter | `monitorsg` |
| Tags | `KongTuke, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec1d8d98fa14dc02afa2317fa28f52a8` |
| SHA-1 | `2f1513d5f3587bc873523e239e66256ea3bc79c0` |
| SHA-256 | `90eb69c1b119e418b381c5754cbee51d6f4e10018c386228e954759a041eedad` |
| SHA3-384 | `afcc564247ed1938e3215d4068cfdc3940647593f6c17cfe9bbe658638b8612d72da4a83702d7299efb5f9eabfeafc21` |
| TLSH | `T153663354C136061BF95C9A242EFE3BBEA3D5BE852EE1914640A38F70935FCD38216F91` |
| SSDEEP | `196608:iwkTnOb3EJGLYJR0o9in3OjC+mUxivZRIfU6BhDpr:5eOKGGwnoVffUch1r` |

#### Technical Assessment

- The sample is tracked as `KongTuke` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_KongTuke_066_90eb69c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90eb69c1b119e418b381c5754cbee51d6f4e10018c386228e954759a041eedad"
    family = "KongTuke"
    file_name = "package"
    file_type = "zip"
    first_seen = "2026-06-30 18:10:22"
  condition:
    hash.sha256(0, filesize) == "90eb69c1b119e418b381c5754cbee51d6f4e10018c386228e954759a041eedad"
}
```

### Sample 67: `c23e08afa7965cb6`

| Field | Value |
|---|---|
| SHA-256 | `c23e08afa7965cb6e730138f3aef11f1c17693ed508457ff45b2a3880795a59d` |
| Family label | `RemcosRAT` |
| File name | `rCotacaodePedidoNovo-Patagonia-P1441-26-1794.vbs` |
| File type | `vbs` |
| First seen | `2026-06-30 18:00:12` |
| Reporter | `fabiodemartin` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8ca9f204124d1f3f6f9c888f455788a` |
| SHA-1 | `80eb54eaec8d10ea73410e1bf789cd4b67f32779` |
| SHA-256 | `c23e08afa7965cb6e730138f3aef11f1c17693ed508457ff45b2a3880795a59d` |
| SHA3-384 | `1c6efe0628f4e653e763f6002e15a8b8f6ca838f02ba7473a548950683df496fda98d1f73c5cf340b65149fabdfe0cae` |
| TLSH | `T1CBE6AF9E49F5E9EA8AC2EAE0FE5BE1583879172044B44E3452CF552CFE70C664BB4331` |
| SSDEEP | `384:VQcPM0K4m3WO0Nwh12IeOLK6tSyZjiG6XS77nSphrzyT4CuBs2/MhbuGRM0F+SeO:8RrBOgU1c4A` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_067_c23e08af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c23e08afa7965cb6e730138f3aef11f1c17693ed508457ff45b2a3880795a59d"
    family = "RemcosRAT"
    file_name = "rCotacaodePedidoNovo-Patagonia-P1441-26-1794.vbs"
    file_type = "vbs"
    first_seen = "2026-06-30 18:00:12"
  condition:
    hash.sha256(0, filesize) == "c23e08afa7965cb6e730138f3aef11f1c17693ed508457ff45b2a3880795a59d"
}
```

### Sample 68: `59b5e489e93dc76e`

| Field | Value |
|---|---|
| SHA-256 | `59b5e489e93dc76efb705b4ace28efd506c464eda2a2e0591023c0330b5e633f` |
| Family label | `unknown` |
| File name | `atom.xml.ps1` |
| File type | `ps1` |
| First seen | `2026-06-30 17:57:17` |
| Reporter | `James_inthe_box` |
| Tags | `exe, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d2c53607be105a713bad71260687072` |
| SHA-1 | `885d3c08df624ebd93c9010dbff41d3a08e2b0eb` |
| SHA-256 | `59b5e489e93dc76efb705b4ace28efd506c464eda2a2e0591023c0330b5e633f` |
| SHA3-384 | `73982887d388af4e4a8a111ada2e9d1c7de326268cb8ec48a171cb90a120aa44366cd2e1b0d99bfee64378279d17ef87` |
| TLSH | `T13D32AC97A443C26F393FEA3BF68D2E61A9469ECBD9CC870250D8822D53F839570056C7` |
| SSDEEP | `192:OCwkyM/vfikJCY73M8aiDh53a88ppqVW6Un3+RNa36c+16rEsTBWXBr9Wo:OCwSviXuNN4q1m+HaKL6rNmr9Wo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_59b5e489
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59b5e489e93dc76efb705b4ace28efd506c464eda2a2e0591023c0330b5e633f"
    family = "unknown"
    file_name = "atom.xml.ps1"
    file_type = "ps1"
    first_seen = "2026-06-30 17:57:17"
  condition:
    hash.sha256(0, filesize) == "59b5e489e93dc76efb705b4ace28efd506c464eda2a2e0591023c0330b5e633f"
}
```

### Sample 69: `404a771b6be9ee6d`

| Field | Value |
|---|---|
| SHA-256 | `404a771b6be9ee6d97dc2f011ddeeb1b2cd78807298610cb002a3dac868b8cec` |
| Family label | `unknown` |
| File name | `AdjuntoArc_301.zip` |
| File type | `zip` |
| First seen | `2026-06-30 17:57:10` |
| Reporter | `skocherhan` |
| Tags | `mercaciositua-lat, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62f24f70a839054b7658646b93293a66` |
| SHA-1 | `f6d9468c421436b0cc868a02fcb38179b9ae85f5` |
| SHA-256 | `404a771b6be9ee6d97dc2f011ddeeb1b2cd78807298610cb002a3dac868b8cec` |
| SHA3-384 | `5fd5a37f58c43d4f9282631b52465460775a586e40d5535dd7baf6af7c8a5eaee645cbf8affde163f8c2dc9c81d73700` |
| TLSH | `T11EB423E10BB21A5F8F5EC95BFCA3ACC9DA6A05F279521D0E03BA061997C0751586C3CF` |
| SSDEEP | `12288:RnL36rrXKCfTmgyUnOgmM6lxoOo+q3NQzdKrT6BRn:grjFfTfyUnQM6laOo+q3NUdsu9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_404a771b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "404a771b6be9ee6d97dc2f011ddeeb1b2cd78807298610cb002a3dac868b8cec"
    family = "unknown"
    file_name = "AdjuntoArc_301.zip"
    file_type = "zip"
    first_seen = "2026-06-30 17:57:10"
  condition:
    hash.sha256(0, filesize) == "404a771b6be9ee6d97dc2f011ddeeb1b2cd78807298610cb002a3dac868b8cec"
}
```

### Sample 70: `6b05b09d13cbb81a`

| Field | Value |
|---|---|
| SHA-256 | `6b05b09d13cbb81ab4246b98f35b49f6915d31f140acacf6d42e260066fed543` |
| Family label | `Gh0stRAT` |
| File name | `Industrial_Safety_and_Risk_Management_in_the_Industrial_Sector_Online.rar` |
| File type | `rar` |
| First seen | `2026-06-30 17:54:16` |
| Reporter | `smica83` |
| Tags | `Gh0stRAT, rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06c85957125c1f2fd4cee1687c3ec840` |
| SHA-1 | `fb3c77c5b350a5d6e2e467c1d5675a365df9ce35` |
| SHA-256 | `6b05b09d13cbb81ab4246b98f35b49f6915d31f140acacf6d42e260066fed543` |
| SHA3-384 | `d5254245825f832acc3d6506e7965ea89c2cf43ffffbdb33ecdfd1a935dcd413aa6cc7ae72afc6b6f702263ffea0d8ff` |
| TLSH | `T1A0173317ED13C22D6017D2857CBE7A36A662E323C93582F4DD5BE36ACF0A034515E2AD` |
| SSDEEP | `393216:1n/6uz9oy8IX2BLRauqwky752DvAJ4wjjcirpLkrEBJ79qex8jtpliZmEcpN:d6Ioy5X25UsJUD4J4ObrpLtL96kwEcP` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_070_6b05b09d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b05b09d13cbb81ab4246b98f35b49f6915d31f140acacf6d42e260066fed543"
    family = "Gh0stRAT"
    file_name = "Industrial_Safety_and_Risk_Management_in_the_Industrial_Sector_Online.rar"
    file_type = "rar"
    first_seen = "2026-06-30 17:54:16"
  condition:
    hash.sha256(0, filesize) == "6b05b09d13cbb81ab4246b98f35b49f6915d31f140acacf6d42e260066fed543"
}
```

### Sample 71: `ebc9d1abb6949046`

| Field | Value |
|---|---|
| SHA-256 | `ebc9d1abb69490462aa79e0fc4ac987ce5cfe19492832e32f36685859e635fba` |
| Family label | `unknown` |
| File name | `FontCacheSvc.exe` |
| File type | `exe` |
| First seen | `2026-06-30 17:48:44` |
| Reporter | `smica83` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06ed2721fcbf34f6ea5ae1d9c7e68527` |
| SHA-1 | `5e5b537aafffd9aaf53cf30f24cca9dec58540fe` |
| SHA-256 | `ebc9d1abb69490462aa79e0fc4ac987ce5cfe19492832e32f36685859e635fba` |
| SHA3-384 | `682d325ec5243aca9f700979f87cf2a1d8724eef2294d87c34eff16202ff7cb3f48350bd2c9aa62315b1dbdb3c3edb84` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T1ECD63947EC6541E9C0AE9135C6229913BB713C894B3163D36B90F6392F77BD0AEBA740` |
| SSDEEP | `98304:6VxQmw9MykV+Veq2zHdQC6uRMo/oFdSVjHmkrE4:mBkMykV8NL5UoFmmk44` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_ebc9d1ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebc9d1abb69490462aa79e0fc4ac987ce5cfe19492832e32f36685859e635fba"
    family = "unknown"
    file_name = "FontCacheSvc.exe"
    file_type = "exe"
    first_seen = "2026-06-30 17:48:44"
  condition:
    hash.sha256(0, filesize) == "ebc9d1abb69490462aa79e0fc4ac987ce5cfe19492832e32f36685859e635fba"
}
```

### Sample 72: `2ee7da2bc52fa3b7`

| Field | Value |
|---|---|
| SHA-256 | `2ee7da2bc52fa3b794ad34788e87a0aa76dca6f43805fb9cf636f02ac87ebe0b` |
| Family label | `unknown` |
| File name | `obf - Copy.js` |
| File type | `js` |
| First seen | `2026-06-30 17:47:33` |
| Reporter | `James_inthe_box` |
| Tags | `exe, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61d2fd1ec45a1ce7cc0d3f7aac9362a0` |
| SHA-1 | `c389c56b97072ffe0b9e039cebd4817df27c5d16` |
| SHA-256 | `2ee7da2bc52fa3b794ad34788e87a0aa76dca6f43805fb9cf636f02ac87ebe0b` |
| SHA3-384 | `0212177fead0e9bcd2ba3d619746cc4005dc0e32ab28792670e29b9a665c490baf3ad0c4f0a6160e6adf18db9207307f` |
| TLSH | `T124426B8A3C43FCF513A53A83EEEF24F2EC16985549AA4545486FF7310229BC62C176E7` |
| SSDEEP | `384:Zy1cZOjFQAybwka0UoV86wWBuArHlQUYey:ZYcZORQAybXKoOKuADCUY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_2ee7da2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ee7da2bc52fa3b794ad34788e87a0aa76dca6f43805fb9cf636f02ac87ebe0b"
    family = "unknown"
    file_name = "obf - Copy.js"
    file_type = "js"
    first_seen = "2026-06-30 17:47:33"
  condition:
    hash.sha256(0, filesize) == "2ee7da2bc52fa3b794ad34788e87a0aa76dca6f43805fb9cf636f02ac87ebe0b"
}
```

### Sample 73: `a1afd49726ee1f70`

| Field | Value |
|---|---|
| SHA-256 | `a1afd49726ee1f7062654ccb905a79860da26b2d6252b13fb32b65ce4f944a07` |
| Family label | `unknown` |
| File name | `Archivo_Adjunto_637.zip` |
| File type | `zip` |
| First seen | `2026-06-30 17:40:18` |
| Reporter | `skocherhan` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f5be26d392a69b49d1f7cc103de0ee4` |
| SHA-1 | `2ebf45fedce5bbf6118a0dbe0f133dad84b25fb7` |
| SHA-256 | `a1afd49726ee1f7062654ccb905a79860da26b2d6252b13fb32b65ce4f944a07` |
| SHA3-384 | `8efdffc88d4acd1bba133bf75157fedbd2c62bc66ac0e372a16df6de497983ee6628eb0964864d08e3fe289747eee49c` |
| TLSH | `T1C72533E10BB15A5F8E6EC96BFCA3FC899A7605F27D421D4E03BA021597C0652586C3CF` |
| SSDEEP | `24576:crjFfTfyUnQM6laOo+q3NUdsuJTrjFfTfyUnQM6laOo+q3NUdsuY:e5fTfHQnR7JX5fTfHQnR7Y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_a1afd497
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1afd49726ee1f7062654ccb905a79860da26b2d6252b13fb32b65ce4f944a07"
    family = "unknown"
    file_name = "Archivo_Adjunto_637.zip"
    file_type = "zip"
    first_seen = "2026-06-30 17:40:18"
  condition:
    hash.sha256(0, filesize) == "a1afd49726ee1f7062654ccb905a79860da26b2d6252b13fb32b65ce4f944a07"
}
```

### Sample 74: `218f0057a8109666`

| Field | Value |
|---|---|
| SHA-256 | `218f0057a81096662b7277f1ebece79f575c44ca5a46c177e9e72207ecd57270` |
| Family label | `unknown` |
| File name | `Arcane.exe` |
| File type | `exe` |
| First seen | `2026-06-30 17:27:49` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9946341badc6e43fa3df2627cb95b1cd` |
| SHA-1 | `3e5c782e7547eb5cf7a464fb6aa3ae656c0a80bb` |
| SHA-256 | `218f0057a81096662b7277f1ebece79f575c44ca5a46c177e9e72207ecd57270` |
| SHA3-384 | `4e2f62786a239d38947319ad79dabba0ca7457c47c0f01ab4b2eaca72ab8301a840d3eb993ef6285f1fb22eed878bb71` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C8D58C0B6CD048E9C4996B3649B652917B71BC1A0F3223D33E90B77C2E76BE09D39794` |
| SSDEEP | `24576:yFGRkc9k4zXwpvjfIJCq6Tk+StRqbSsEMedcl/x/4Pq9C7MQtmOcxaFjytxzBelL:yFGRp97zEvjgfOtKKx6KOcUgg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_218f0057
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "218f0057a81096662b7277f1ebece79f575c44ca5a46c177e9e72207ecd57270"
    family = "unknown"
    file_name = "Arcane.exe"
    file_type = "exe"
    first_seen = "2026-06-30 17:27:49"
  condition:
    hash.sha256(0, filesize) == "218f0057a81096662b7277f1ebece79f575c44ca5a46c177e9e72207ecd57270"
}
```

### Sample 75: `f17cb686d2371074`

| Field | Value |
|---|---|
| SHA-256 | `f17cb686d2371074b25d8a992014dbd75a454d06d436324001eac3f9f0ecef5a` |
| Family label | `PureLogsStealer` |
| File name | `SecuriteInfo.com.Heur.MSIL.Benin.5.84486846` |
| File type | `exe` |
| First seen | `2026-06-30 17:25:43` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23ac423d9a6adec92d74a8c35cc153b3` |
| SHA-1 | `791057f377abe9f522029fabb8eaf0837d75fe2c` |
| SHA-256 | `f17cb686d2371074b25d8a992014dbd75a454d06d436324001eac3f9f0ecef5a` |
| SHA3-384 | `0f6ef641fc9afcb4a19945f98948f5b643c5c692a8227c9866625d4fb02b72991e0d558d4da125db09a19b81d0d7037d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E105AE6B73628E10C2850637C1EB045183F5AA877AA7F74F768423961C433FEDE466A7` |
| SSDEEP | `12288:447whkcSTVJwoE0UnAxpVEx5iQ34eUv4iQXWkHDqFirZY:4IxJwoEFAxpu5iQobvPDkew` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_075_f17cb686
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f17cb686d2371074b25d8a992014dbd75a454d06d436324001eac3f9f0ecef5a"
    family = "PureLogsStealer"
    file_name = "SecuriteInfo.com.Heur.MSIL.Benin.5.84486846"
    file_type = "exe"
    first_seen = "2026-06-30 17:25:43"
  condition:
    hash.sha256(0, filesize) == "f17cb686d2371074b25d8a992014dbd75a454d06d436324001eac3f9f0ecef5a"
}
```

### Sample 76: `6cff215dcf60fc90`

| Field | Value |
|---|---|
| SHA-256 | `6cff215dcf60fc90e76adfc28b6725b123532365efa504e15d37144bf97d1857` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-06-30 17:22:49` |
| Reporter | `Kejult` |
| Tags | `exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ed8822248ce2d452b9c345cf84536b0` |
| SHA-1 | `4b9a176730491e77ac9ed697bbc68a585c354ccb` |
| SHA-256 | `6cff215dcf60fc90e76adfc28b6725b123532365efa504e15d37144bf97d1857` |
| SHA3-384 | `e789486a9711302716b200b60553962bd49ca68c37e941a8796ee7522dabf5923588e1e196ca32ea975039ea1dca4dd7` |
| IMPHASH | `bd1bed42cfff157c99a6dbc312cee0dd` |
| TLSH | `T129559E10B6968432E5F205758E7D9B66963D7E204F3088DBB3D43A2E1C726C12E35B7B` |
| SSDEEP | `24576:r0YLIuIARGkHOnFm1Psbn51MXHWYoRP+XW/ZG6ekuHcgVq:4O3o1d51vhR2AZFeku8D` |
| ICON-DHASH | `e8e8f4b2dadabaf0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_6cff215d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cff215dcf60fc90e76adfc28b6725b123532365efa504e15d37144bf97d1857"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-30 17:22:49"
  condition:
    hash.sha256(0, filesize) == "6cff215dcf60fc90e76adfc28b6725b123532365efa504e15d37144bf97d1857"
}
```

### Sample 77: `dec98a1ef5d1d1b5`

| Field | Value |
|---|---|
| SHA-256 | `dec98a1ef5d1d1b5a6aa886345de1ac4adcea5829509e375b7cf87b7a22fb91d` |
| Family label | `NetSupport` |
| File name | `Rate_RATE_AGR_Jun29.exe` |
| File type | `exe` |
| First seen | `2026-06-30 17:21:56` |
| Reporter | `smica83` |
| Tags | `exe, NetSupport` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `caf61d5d2d0449eba635f900da57c26c` |
| SHA-1 | `6d17dca898d657f7719d2c021988471061aff173` |
| SHA-256 | `dec98a1ef5d1d1b5a6aa886345de1ac4adcea5829509e375b7cf87b7a22fb91d` |
| SHA3-384 | `c253efda75738f86c169f525acaa9d67ddc2546802aae3241f21fbbaa4fe4428c79921b711ed13cfba36b2ca7af107c5` |
| IMPHASH | `ca7cf48965e5612a16429deba2029941` |
| TLSH | `T1B4146DCBE1D350F9D057C4708BAF96B3B231B82513242ABF53D4DB312572A909A99F26` |
| SSDEEP | `3072:EQKj0jNWOIzCE/OtJnkTFYAeoupW47O0x6MtxRMVMQdiMpdaC6:5Kj0cOgOtp+FYqupW4Kz6xRMOGiwdaz` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_077_dec98a1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dec98a1ef5d1d1b5a6aa886345de1ac4adcea5829509e375b7cf87b7a22fb91d"
    family = "NetSupport"
    file_name = "Rate_RATE_AGR_Jun29.exe"
    file_type = "exe"
    first_seen = "2026-06-30 17:21:56"
  condition:
    hash.sha256(0, filesize) == "dec98a1ef5d1d1b5a6aa886345de1ac4adcea5829509e375b7cf87b7a22fb91d"
}
```

### Sample 78: `f141db13721b9f02`

| Field | Value |
|---|---|
| SHA-256 | `f141db13721b9f0248e4eb482bd0462995c920595ed9e87e704f841543f63621` |
| Family label | `NetSupport` |
| File name | `RELEASE FORM.pdf.url` |
| File type | `url` |
| First seen | `2026-06-30 17:19:06` |
| Reporter | `smica83` |
| Tags | `url` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c28ec6e5ab01038326ab8e850676ca62` |
| SHA-1 | `4f9b13be7a45ee6a7bcb39db850a4c03c8d43726` |
| SHA-256 | `f141db13721b9f0248e4eb482bd0462995c920595ed9e87e704f841543f63621` |
| SHA3-384 | `63a0999edd0d569f6f4c2c08050212f825f89bad8be23427ea7f6a1d8d9aeeda1b28f4ff15a377cd78e59c0cd3ac6671` |
| TLSH | `T176D097BA1B45C0A2C3C6E9803200BC00142F3441AAE58C882088CA8850C0801C34C6C2` |
| SSDEEP | `6:Js1Q/QU9RYFeJ5Zbf5oeTckGhiDNakIenV:zDOFqRzUSnV` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `url`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_078_f141db13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f141db13721b9f0248e4eb482bd0462995c920595ed9e87e704f841543f63621"
    family = "NetSupport"
    file_name = "RELEASE FORM.pdf.url"
    file_type = "url"
    first_seen = "2026-06-30 17:19:06"
  condition:
    hash.sha256(0, filesize) == "f141db13721b9f0248e4eb482bd0462995c920595ed9e87e704f841543f63621"
}
```

### Sample 79: `c3635ad319d02c61`

| Field | Value |
|---|---|
| SHA-256 | `c3635ad319d02c61c07dd3095b4998cf81c6d1e361284fcb67d00fe8b01d1e38` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 17:15:29` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55a77ff1a1fca2d0a2bbf1c5b6d9b6db` |
| SHA-1 | `42cd95b4bd1f9aedfbf2d5f827a053dc9ed7a49f` |
| SHA-256 | `c3635ad319d02c61c07dd3095b4998cf81c6d1e361284fcb67d00fe8b01d1e38` |
| SHA3-384 | `46e91b4643c275e882aff75530b526620092d58a48263d777d0fc5897aacb69d09a3ac442725ec77297e87244be9b270` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1EB85238967E410ADE0BA0B748CF76093D67178A14B7522FF67E0547E3B63AD0A931327` |
| SSDEEP | `49152:4j8JV5d8t/qE6LclO+wQkRwykaFGEFcWQUr/8K:fJVP8tSELlOhQkRaavFcWQUQK` |
| ICON-DHASH | `e0c8e963b3f17071` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_079_c3635ad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3635ad319d02c61c07dd3095b4998cf81c6d1e361284fcb67d00fe8b01d1e38"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 17:15:29"
  condition:
    hash.sha256(0, filesize) == "c3635ad319d02c61c07dd3095b4998cf81c6d1e361284fcb67d00fe8b01d1e38"
}
```

### Sample 80: `13ba8af75fb5088d`

| Field | Value |
|---|---|
| SHA-256 | `13ba8af75fb5088dc269b4a5ee3dcafc8dd397775a1258643eb350871851c1dc` |
| Family label | `RemusStealer` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-06-30 17:15:12` |
| Reporter | `Kejult` |
| Tags | `dll, exe, remus, RemusStealer, signed, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a179cad39a87c82efa611adaa33c40b` |
| SHA-1 | `4223d1a6799967223cf737539863d15dabd7efaa` |
| SHA-256 | `13ba8af75fb5088dc269b4a5ee3dcafc8dd397775a1258643eb350871851c1dc` |
| SHA3-384 | `e76d44caa5ac4499a242b9ad889def3af1b16f30fea9743cb7cb5739a4bb1c16bcf0b65949f0009c45806a9045bf8883` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T18BE54A87BDD558B9C09AA33589B742927B7CBC580B3227D72EA0B27A2F337D05971704` |
| SSDEEP | `49152:CdCL8akbBlubooyR2UsHDwff6hsAAl/VZUzL5e:CKjq2x2f0Wm5e` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_080_13ba8af7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13ba8af75fb5088dc269b4a5ee3dcafc8dd397775a1258643eb350871851c1dc"
    family = "RemusStealer"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-06-30 17:15:12"
  condition:
    hash.sha256(0, filesize) == "13ba8af75fb5088dc269b4a5ee3dcafc8dd397775a1258643eb350871851c1dc"
}
```

### Sample 81: `6b4acfec0d604878`

| Field | Value |
|---|---|
| SHA-256 | `6b4acfec0d604878f445271c3ffb773ff6563affc8064a825c6ecd87b5dd2f61` |
| Family label | `unknown` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-06-30 17:11:43` |
| Reporter | `Kejult` |
| Tags | `dll, exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5de3d57c333fcd83d56210260141ac91` |
| SHA-1 | `2683111fce333ddca6f49172f0e595c3c6626ecd` |
| SHA-256 | `6b4acfec0d604878f445271c3ffb773ff6563affc8064a825c6ecd87b5dd2f61` |
| SHA3-384 | `b86ed62fc774e807d8c06ba9fcc9b1bb5037bf2e5acbe3c014b2ec805e5092083b9028d573e0132434610e4055671425` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T197068D47BDA14C79C0AAA33189B702867B7CBC590B3227E72E60B27A2E737D05D71745` |
| SSDEEP | `49152:rmieDhzXS3nqAXvLh9d0ndYvWiyRk/xT8x13z3Nvnk67/TrDd4/wZyuMSS:rUOjQoW8V8xPnFTrSDSS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_6b4acfec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b4acfec0d604878f445271c3ffb773ff6563affc8064a825c6ecd87b5dd2f61"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-06-30 17:11:43"
  condition:
    hash.sha256(0, filesize) == "6b4acfec0d604878f445271c3ffb773ff6563affc8064a825c6ecd87b5dd2f61"
}
```

### Sample 82: `5fc3616b64a4b020`

| Field | Value |
|---|---|
| SHA-256 | `5fc3616b64a4b02007b3cdaae584a269e6a972e004d5a964097ec67c40983366` |
| Family label | `KongTuke` |
| File name | `package` |
| File type | `zip` |
| First seen | `2026-06-30 17:06:28` |
| Reporter | `monitorsg` |
| Tags | `KongTuke, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ae1f42f6794e949da4303fbb7f65d5d` |
| SHA-1 | `f8ef67f6d039eb4af102f4fa25ab66b440f1c792` |
| SHA-256 | `5fc3616b64a4b02007b3cdaae584a269e6a972e004d5a964097ec67c40983366` |
| SHA3-384 | `232b0af6a290079947a2134a031368efc7bf509304ba9d83354030095d9a091bace541fd4c4427f3bfa57d7a8d41e0b2` |
| TLSH | `T1376633A9862A130FEC4CA53166D86FFDDB46FE0B3A501286C0171CB4E4564BFC796B87` |
| SSDEEP | `196608:rTn+mMGsYJR0o9inYrCSUx07Sg59wfpFmFq1aTzdh:PWGxwnYY+D9wBFmFq1aTzdh` |

#### Technical Assessment

- The sample is tracked as `KongTuke` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_KongTuke_082_5fc3616b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fc3616b64a4b02007b3cdaae584a269e6a972e004d5a964097ec67c40983366"
    family = "KongTuke"
    file_name = "package"
    file_type = "zip"
    first_seen = "2026-06-30 17:06:28"
  condition:
    hash.sha256(0, filesize) == "5fc3616b64a4b02007b3cdaae584a269e6a972e004d5a964097ec67c40983366"
}
```

### Sample 83: `eb815fb77cc1c177`

| Field | Value |
|---|---|
| SHA-256 | `eb815fb77cc1c177f613bb69d349d8bf5150afef03c66005cbbf3767954c279c` |
| Family label | `unknown` |
| File name | `eb815fb77cc1c177f613bb69d349d8bf5150afef03c66005cbbf3767954c279c` |
| File type | `elf` |
| First seen | `2026-06-30 17:01:12` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8757e38549a93a1c2e4e34d36cca0638` |
| SHA-1 | `a1d592f202c82d833f2b8bd1d33a7f78afa1b74a` |
| SHA-256 | `eb815fb77cc1c177f613bb69d349d8bf5150afef03c66005cbbf3767954c279c` |
| SHA3-384 | `4ea93f930c2789ecee8b0e1af18d1835f8c17322b4b0207fdb0cc34d96a9ca7005ede07f9e80511a7b3be754829f98bf` |
| TLSH | `T1FDA5F857E49590E4C0EEE174C726A213BEA13499473837E36FA187F11B26FE4A6BC314` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0f:cqYUQuVDtE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_eb815fb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb815fb77cc1c177f613bb69d349d8bf5150afef03c66005cbbf3767954c279c"
    family = "unknown"
    file_name = "eb815fb77cc1c177f613bb69d349d8bf5150afef03c66005cbbf3767954c279c"
    file_type = "elf"
    first_seen = "2026-06-30 17:01:12"
  condition:
    hash.sha256(0, filesize) == "eb815fb77cc1c177f613bb69d349d8bf5150afef03c66005cbbf3767954c279c"
}
```

### Sample 84: `a9eb130cb5788180`

| Field | Value |
|---|---|
| SHA-256 | `a9eb130cb57881807b7ef072265af0f6ec84e73c728f11ecce8cc01a7b6a1567` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 16:52:15` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, PMIX0.file, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e009d13962fd200cf6259ac69ca86a40` |
| SHA-1 | `4046c6f6becde038870874c2eb82964e730e13f6` |
| SHA-256 | `a9eb130cb57881807b7ef072265af0f6ec84e73c728f11ecce8cc01a7b6a1567` |
| SHA3-384 | `a7797ad1b25142a7fec94a4185fdd0ceb8c51204a8461a297af2c45a4d2d90956949bce5b0edab2ee452eec97543170a` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11DD5AE0B7CD148E9D4AA673288B255567B34BC564F3227C72E90B3382F36BE19D39790` |
| SSDEEP | `49152:PqSSc+dwAfzfOndvsHF7CX2kGUFtrsrpS2zq9hS71kgq:PqQBwF7ClGUFurphzqekf` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_084_a9eb130c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9eb130cb57881807b7ef072265af0f6ec84e73c728f11ecce8cc01a7b6a1567"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 16:52:15"
  condition:
    hash.sha256(0, filesize) == "a9eb130cb57881807b7ef072265af0f6ec84e73c728f11ecce8cc01a7b6a1567"
}
```

### Sample 85: `49a58699c0421dc0`

| Field | Value |
|---|---|
| SHA-256 | `49a58699c0421dc0f5769ec37936b3ae01b7dd5e715a7075e5e39ea78715120e` |
| Family label | `BlankGrabber` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 16:42:44` |
| Reporter | `Bitsight` |
| Tags | `BlankGrabber, C, dropped-by-GCleaner, exe, MIX3.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9be244f13bff51377899f5f50ad7db8` |
| SHA-1 | `05491d34e27818fd94c1baf2c3d630600adaee10` |
| SHA-256 | `49a58699c0421dc0f5769ec37936b3ae01b7dd5e715a7075e5e39ea78715120e` |
| SHA3-384 | `4fa8b0a8e4eab92d8af9795af20bcafefd48ae56346c5d891f867e55b70bd7c881b94f837accbea5d6355f534f783708` |
| IMPHASH | `ad510aa4318530074af11ba8249f6938` |
| TLSH | `T1337733A0F3EDCDFAFD23A6FC55036243765BB4825715C4E622C5AD24FD762A50B2A302` |
| SSDEEP | `786432:ilDGWedYLd1EIXKCKLmln006rqXclVoYd2fLeOHDHAU:iYWedq4tCJx0SXyuQmCOjHt` |
| ICON-DHASH | `f0f0e2ece8e0f050` |

#### Technical Assessment

- The sample is tracked as `BlankGrabber` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BlankGrabber_085_49a58699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49a58699c0421dc0f5769ec37936b3ae01b7dd5e715a7075e5e39ea78715120e"
    family = "BlankGrabber"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 16:42:44"
  condition:
    hash.sha256(0, filesize) == "49a58699c0421dc0f5769ec37936b3ae01b7dd5e715a7075e5e39ea78715120e"
}
```

### Sample 86: `0c212b01802e3eb2`

| Field | Value |
|---|---|
| SHA-256 | `0c212b01802e3eb2f28d2c42afbeb9ac3c6620780d5d7988c6edad310444e477` |
| Family label | `Mirai` |
| File name | `0c212b01802e3eb2f28d2c42afbeb9ac3c6620780d5d7988c6edad310444e477` |
| File type | `elf` |
| First seen | `2026-06-30 16:29:57` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e954408afc5474464dff8b13df17a03` |
| SHA-1 | `970251578b277a0afc2b7c3b02a486dff7da0d4b` |
| SHA-256 | `0c212b01802e3eb2f28d2c42afbeb9ac3c6620780d5d7988c6edad310444e477` |
| SHA3-384 | `49649fabaf6fedff92133eb57ff282313f9b9cef5ee3b28bb162a69facc7dd1aa2e75f599e59cb8f8150a6a70935368c` |
| TLSH | `T1B9967CB3945224D8E1A9C9B4D11416527DB83C8B573873CBBAC471F65BBABE48E38730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQn:cqYUQuVDt0TZEg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_0c212b01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c212b01802e3eb2f28d2c42afbeb9ac3c6620780d5d7988c6edad310444e477"
    family = "Mirai"
    file_name = "0c212b01802e3eb2f28d2c42afbeb9ac3c6620780d5d7988c6edad310444e477"
    file_type = "elf"
    first_seen = "2026-06-30 16:29:57"
  condition:
    hash.sha256(0, filesize) == "0c212b01802e3eb2f28d2c42afbeb9ac3c6620780d5d7988c6edad310444e477"
}
```

### Sample 87: `5a72d52ac0859f83`

| Field | Value |
|---|---|
| SHA-256 | `5a72d52ac0859f831335a2fb1f6756f55822ee71978552c1cabfa3d6f4a08f6c` |
| Family label | `Mirai` |
| File name | `5a72d52ac0859f831335a2fb1f6756f55822ee71978552c1cabfa3d6f4a08f6c` |
| File type | `elf` |
| First seen | `2026-06-30 15:52:32` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3766392b7904fca8ca12c39baa0b2433` |
| SHA-1 | `4482b4ac03cc75d76929e3cdaf82cc3029d3afc8` |
| SHA-256 | `5a72d52ac0859f831335a2fb1f6756f55822ee71978552c1cabfa3d6f4a08f6c` |
| SHA3-384 | `5b17ee34803b2f533e6d3e26f2d4da6ac205428c8ba40e1922d5b8a06fb3d04b89da5e03119326602c4f433a4c48aabc` |
| TLSH | `T14057CF77920678EDE9B98CB4D01025816DAC78875778E3C7BAC470E666EB6D08D3DB30` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQI:cqYUQuVDt0TZEj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_5a72d52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a72d52ac0859f831335a2fb1f6756f55822ee71978552c1cabfa3d6f4a08f6c"
    family = "Mirai"
    file_name = "5a72d52ac0859f831335a2fb1f6756f55822ee71978552c1cabfa3d6f4a08f6c"
    file_type = "elf"
    first_seen = "2026-06-30 15:52:32"
  condition:
    hash.sha256(0, filesize) == "5a72d52ac0859f831335a2fb1f6756f55822ee71978552c1cabfa3d6f4a08f6c"
}
```

### Sample 88: `bba9bc21a322ea0e`

| Field | Value |
|---|---|
| SHA-256 | `bba9bc21a322ea0e1737c5fa64057d12f133a3ebed6007ffed979b3d6099f6aa` |
| Family label | `GoldDigger` |
| File name | `pln_mobile.apk` |
| File type | `apk` |
| First seen | `2026-06-30 15:25:27` |
| Reporter | `BastianHein_` |
| Tags | `apk, Golddigger, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f64f76bb0b20c3be949922bc1ae290d` |
| SHA-1 | `24289aa2d6b5e5735a85a0a0c5670d11b9c0196d` |
| SHA-256 | `bba9bc21a322ea0e1737c5fa64057d12f133a3ebed6007ffed979b3d6099f6aa` |
| SHA3-384 | `763aa2069170bc4e30f2532851fe1b8400de54ce60762c6b322d5e5c2a6c18a775031529e97d30fefe19046383f0ad03` |
| TLSH | `T136D62247F794AC6AC0FB93320675122A96174D624B839AC36E45363C5EB3AD49F0DFC8` |
| SSDEEP | `196608:E7uoUT3zcKTkYzjZ3D1Rii+rfP1XTzsgC0LlIqYtAZofUUpbIDU+nxXIuyb:E7wbwKTkMRs+gjHHKbI5nxXc` |

#### Technical Assessment

- The sample is tracked as `GoldDigger` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoldDigger_088_bba9bc21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bba9bc21a322ea0e1737c5fa64057d12f133a3ebed6007ffed979b3d6099f6aa"
    family = "GoldDigger"
    file_name = "pln_mobile.apk"
    file_type = "apk"
    first_seen = "2026-06-30 15:25:27"
  condition:
    hash.sha256(0, filesize) == "bba9bc21a322ea0e1737c5fa64057d12f133a3ebed6007ffed979b3d6099f6aa"
}
```

### Sample 89: `a4bfe1bcecd9e6f6`

| Field | Value |
|---|---|
| SHA-256 | `a4bfe1bcecd9e6f6d1f3bc661ed80f4ed464c1231eacf609f9423488bf9660b3` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Win32.Waldek.cnei.22087.12105` |
| File type | `exe` |
| First seen | `2026-06-30 15:22:52` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `498e051ac71bb9166edb96e2a16ccdef` |
| SHA-1 | `f6560a3a520bf66a4ef5935a590064c0c3d5e42f` |
| SHA-256 | `a4bfe1bcecd9e6f6d1f3bc661ed80f4ed464c1231eacf609f9423488bf9660b3` |
| SHA3-384 | `bdcba7ded9e015a3216a1ac0f328826019f53131440f2f44fcbdc291c116e387beb78ef9250021f49ffde8d0bf49d79f` |
| IMPHASH | `9fe958a469b30eb456e7beeccce5dbca` |
| TLSH | `T1ABF4F751E3D009BCEDE7457F85561906EAA2BC1E3720C58F22A036EE1E732D1BF2960D` |
| SSDEEP | `6144:ACFUbJ9If+k3RD4hEyUjvs566xRWo2P7k7z:krO3RTyUQ566c7k7z` |
| ICON-DHASH | `f0cc92654d92ccf0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_a4bfe1bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4bfe1bcecd9e6f6d1f3bc661ed80f4ed464c1231eacf609f9423488bf9660b3"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Win32.Waldek.cnei.22087.12105"
    file_type = "exe"
    first_seen = "2026-06-30 15:22:52"
  condition:
    hash.sha256(0, filesize) == "a4bfe1bcecd9e6f6d1f3bc661ed80f4ed464c1231eacf609f9423488bf9660b3"
}
```

### Sample 90: `2143baefd0b108fa`

| Field | Value |
|---|---|
| SHA-256 | `2143baefd0b108fa1f6cfcfa3eb31d87578c6014117768f06bd8544dd02c8adf` |
| Family label | `unknown` |
| File name | `Setup_Network.exe` |
| File type | `exe` |
| First seen | `2026-06-30 15:20:10` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b92adb1db4258756b82e220afc1caa57` |
| SHA-1 | `a12a999c81f313ed7d876fc08f7a6120a9d80bc3` |
| SHA-256 | `2143baefd0b108fa1f6cfcfa3eb31d87578c6014117768f06bd8544dd02c8adf` |
| SHA3-384 | `34cd8a5c730d113ac4d5c0261448687bc0eb8b31a1aa339061903db263035e48bc5b80789d74120377c3656067ec8c69` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T1EFF7338788AC70B9F3D4FB3E075E173BD232006B4264B69593E86DB175D281E98767C2` |
| SSDEEP | `1572864:Rde4hdV6xf1HCueCxli7oTVB/HiXbwXAwh2MBLqGA++ztI6nK:Rde4Doxft1DfO2OUwwxBOTtI6K` |
| ICON-DHASH | `8203010509030382` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_2143baef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2143baefd0b108fa1f6cfcfa3eb31d87578c6014117768f06bd8544dd02c8adf"
    family = "unknown"
    file_name = "Setup_Network.exe"
    file_type = "exe"
    first_seen = "2026-06-30 15:20:10"
  condition:
    hash.sha256(0, filesize) == "2143baefd0b108fa1f6cfcfa3eb31d87578c6014117768f06bd8544dd02c8adf"
}
```

### Sample 91: `2065ac72d90574df`

| Field | Value |
|---|---|
| SHA-256 | `2065ac72d90574df9958e33de5efa2d9a2a7e73fc9d9f9419769f85aad083d93` |
| Family label | `KongTuke` |
| File name | `package` |
| File type | `zip` |
| First seen | `2026-06-30 15:09:41` |
| Reporter | `monitorsg` |
| Tags | `KongTuke, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `094adf26800a7583981600ec680f7eca` |
| SHA-1 | `de74f2d081b6621d9210e012eed799d3b7de70b8` |
| SHA-256 | `2065ac72d90574df9958e33de5efa2d9a2a7e73fc9d9f9419769f85aad083d93` |
| SHA3-384 | `dd6d7d5b68b496e51e07bee3cb95d86a77a6764922b6bc32475e1eb863ad498ac92d10eea3183d72f3667fa799a9a705` |
| TLSH | `T1CC66331E480E766BCCDC53FA14C31ADAF5225D0E0F85A1AB5483F4BD9041C9AFB2976E` |
| SSDEEP | `196608:desYTnk8I4JrWAKDGqGfOL5nVrxUxzFh+dIw3UaWO2Y9yD:56kUBWAKDufOL5nVmJh+NUaX19I` |

#### Technical Assessment

- The sample is tracked as `KongTuke` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_KongTuke_091_2065ac72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2065ac72d90574df9958e33de5efa2d9a2a7e73fc9d9f9419769f85aad083d93"
    family = "KongTuke"
    file_name = "package"
    file_type = "zip"
    first_seen = "2026-06-30 15:09:41"
  condition:
    hash.sha256(0, filesize) == "2065ac72d90574df9958e33de5efa2d9a2a7e73fc9d9f9419769f85aad083d93"
}
```

### Sample 92: `7f163d45fef16ddf`

| Field | Value |
|---|---|
| SHA-256 | `7f163d45fef16ddfc392d08467fbe4e661666921a70ff4e57dc28f066ec4982b` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-06-30 14:56:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07c2ba2897ecf32e95bb9d7924c84b84` |
| SHA-1 | `d531792f7fc20ac55a59960910c87014fb8ac465` |
| SHA-256 | `7f163d45fef16ddfc392d08467fbe4e661666921a70ff4e57dc28f066ec4982b` |
| SHA3-384 | `1eb8f5e6d7c9c936992f177230e227b76fda60cfe49753c4742237e28b4336da3f5aa4b3b7ebfd3e2023ff8fbf15ab96` |
| TLSH | `T10634F816AB710FFBCCABCE3742EA0B4634DC505B22A53B353674D524F44A54BA9E3CA4` |
| SSDEEP | `3072:ZJI6WoQBohjTib40yHxF7R2djhUAPZd+iBXZlDkia+oIjckMqysvgIfCP0:XbcoJTib7hBZd+mj2MUlsvgwC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_7f163d45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f163d45fef16ddfc392d08467fbe4e661666921a70ff4e57dc28f066ec4982b"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-06-30 14:56:22"
  condition:
    hash.sha256(0, filesize) == "7f163d45fef16ddfc392d08467fbe4e661666921a70ff4e57dc28f066ec4982b"
}
```

### Sample 93: `e7e254d63b7a5f49`

| Field | Value |
|---|---|
| SHA-256 | `e7e254d63b7a5f492c6f74ac48393687b57ed10986b2ca7fcd93a7ec6b07bfe8` |
| Family label | `Mirai` |
| File name | `POWERPC` |
| File type | `elf` |
| First seen | `2026-06-30 14:48:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `828ab31848f90b71d8b28f9105fd08a2` |
| SHA-1 | `559875898afdf750623f2d26a3079b9872e2f3d7` |
| SHA-256 | `e7e254d63b7a5f492c6f74ac48393687b57ed10986b2ca7fcd93a7ec6b07bfe8` |
| SHA3-384 | `8fdac857a49fa27bc20a151166bb5652ce303fc16b234c4c9ae04682049dcae552fae9fcadee39304437e7d79af7ab3f` |
| TLSH | `T199B3180FAA2D0F43C59B5AF03D3727E0879DEA6111E452C1A41AFEC147728F66126FE5` |
| SSDEEP | `3072:zuFcBz7ZSJaXiMISqb7Ak7ECNj4+UJWMf5h8p/Bp:zuFcL/qbv4CNj4WMf5hSp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_e7e254d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7e254d63b7a5f492c6f74ac48393687b57ed10986b2ca7fcd93a7ec6b07bfe8"
    family = "Mirai"
    file_name = "POWERPC"
    file_type = "elf"
    first_seen = "2026-06-30 14:48:46"
  condition:
    hash.sha256(0, filesize) == "e7e254d63b7a5f492c6f74ac48393687b57ed10986b2ca7fcd93a7ec6b07bfe8"
}
```

### Sample 94: `ab46c8b82f74508d`

| Field | Value |
|---|---|
| SHA-256 | `ab46c8b82f74508dc98679d5fed21e8a8c0b4ada2c43b061d0e9cc0c43f6f873` |
| Family label | `Mirai` |
| File name | `X86_64` |
| File type | `elf` |
| First seen | `2026-06-30 14:20:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dee9ec644705d0b6ac45c99bed32e71` |
| SHA-1 | `2e139dde7e9b8662cee6da2a99d7a4592854c4cb` |
| SHA-256 | `ab46c8b82f74508dc98679d5fed21e8a8c0b4ada2c43b061d0e9cc0c43f6f873` |
| SHA3-384 | `cd2032265d573ced2b257c95c45b7d95b076faf76192a7fd49b0a54cc44f4a4a55022dd9ea9000f4a720e12e3b0e24e0` |
| TLSH | `T1FFA35B2B7691D47EC00BE1F02BEF9962E921B87E0A71708677C0BD512F69CD15E193A2` |
| TELFHASH | `t1f04187b039952994a2e3b67b7343e5e1d8351a6004e134e1eab25ce9cf967c04c75477` |
| SSDEEP | `3072:WmEpjxRHSRhs/nk/EOU+r2u+qL/oG0phaTJY4lr:WD8Qn1OU+anIupham4l` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_ab46c8b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab46c8b82f74508dc98679d5fed21e8a8c0b4ada2c43b061d0e9cc0c43f6f873"
    family = "Mirai"
    file_name = "X86_64"
    file_type = "elf"
    first_seen = "2026-06-30 14:20:57"
  condition:
    hash.sha256(0, filesize) == "ab46c8b82f74508dc98679d5fed21e8a8c0b4ada2c43b061d0e9cc0c43f6f873"
}
```

### Sample 95: `b8cc02058e1d4c9d`

| Field | Value |
|---|---|
| SHA-256 | `b8cc02058e1d4c9d7efe775cd645685d8fad1d3f90f0572b58262937c7c1b729` |
| Family label | `Mirai` |
| File name | `main_aarch64` |
| File type | `elf` |
| First seen | `2026-06-30 14:15:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7781628c73907d656e9a115978c6b46` |
| SHA-1 | `def80e5842ce89857dce43582b03102032e6d240` |
| SHA-256 | `b8cc02058e1d4c9d7efe775cd645685d8fad1d3f90f0572b58262937c7c1b729` |
| SHA3-384 | `9962a2d617868cd6da1f20e5c481e87882fee3c77ee020b7652907b7a2b646b8dbfca0b7303c7517059e7bb425a82850` |
| TLSH | `T1CA046B2EEE0ADE55CEC6C33E9D9A0F63703634A49752C1B34F42907CB28B6D674B9095` |
| SSDEEP | `3072:JSnQFrTbf0OvBt9DIfEWb4MyBL2SlPHEpWaZg6lZPLCkheKhR1ctaysd+rPHr:7zOc2UlPaWkPLCzKxEVsd+r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_b8cc0205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8cc02058e1d4c9d7efe775cd645685d8fad1d3f90f0572b58262937c7c1b729"
    family = "Mirai"
    file_name = "main_aarch64"
    file_type = "elf"
    first_seen = "2026-06-30 14:15:46"
  condition:
    hash.sha256(0, filesize) == "b8cc02058e1d4c9d7efe775cd645685d8fad1d3f90f0572b58262937c7c1b729"
}
```

### Sample 96: `a1e468b77bab8faa`

| Field | Value |
|---|---|
| SHA-256 | `a1e468b77bab8faa8f6e42c37dd0c8f6556e5c529273118f67c6150fbd96c921` |
| Family label | `Mirai` |
| File name | `ARMV6L` |
| File type | `elf` |
| First seen | `2026-06-30 13:59:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `963bec3d9f789757ce9974c1c973237a` |
| SHA-1 | `9e3b1a9a23ce433cb919ec662b27482f6069cce8` |
| SHA-256 | `a1e468b77bab8faa8f6e42c37dd0c8f6556e5c529273118f67c6150fbd96c921` |
| SHA3-384 | `8d860b816033a63c4ce22551d12ce5fbe6336e5f129898270a4f7a4ae24f991e988b66b3042d316f8630ca4da81278de` |
| TLSH | `T1BDC30849E9109729C3E272FBFB9952CF33271FACA3DB3126C9304F9123C56A65939521` |
| SSDEEP | `3072:Jq90Qn3WzauG01kO93+/YHqfBfv5h8p/V3C:F4mzauG4kO9AfNv5hi3C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_a1e468b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1e468b77bab8faa8f6e42c37dd0c8f6556e5c529273118f67c6150fbd96c921"
    family = "Mirai"
    file_name = "ARMV6L"
    file_type = "elf"
    first_seen = "2026-06-30 13:59:24"
  condition:
    hash.sha256(0, filesize) == "a1e468b77bab8faa8f6e42c37dd0c8f6556e5c529273118f67c6150fbd96c921"
}
```

### Sample 97: `93d63f76261aecda`

| Field | Value |
|---|---|
| SHA-256 | `93d63f76261aecdacafdce0b490cf032c90b48c227f0772d4a5dccc71998beaf` |
| Family label | `Mirai` |
| File name | `I686` |
| File type | `elf` |
| First seen | `2026-06-30 13:59:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ed532a1cdee3ad080c39f1ed2d475c8` |
| SHA-1 | `2142c317b0159cb8f0f87dea69126f815773e795` |
| SHA-256 | `93d63f76261aecdacafdce0b490cf032c90b48c227f0772d4a5dccc71998beaf` |
| SHA3-384 | `95dd1d89197089093cbe7e43667ae71b22d44fb45ad7b474cbedde04b0417390f1909942c3f12da789a54da320a909fe` |
| TLSH | `T1A8932C56E643C9B3C80314F212A7EA6F8A31FE3B8C72DEC6EB942D54FB164C052157A5` |
| TELFHASH | `t1f14135b62ee908d8f7d01804d35f07e26a19e63f155076e346f3692433ebb8151aac39` |
| SSDEEP | `1536:M7EdQR0DU3pxWG3Bf5VAm2OOjy0f5+QZ47JspSJnzgzXAWgmMlymAiiUKGX0wLCA:nQR0DuxWG3Bf5VAm2OOjy0f5+QZ47Jsg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_93d63f76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93d63f76261aecdacafdce0b490cf032c90b48c227f0772d4a5dccc71998beaf"
    family = "Mirai"
    file_name = "I686"
    file_type = "elf"
    first_seen = "2026-06-30 13:59:22"
  condition:
    hash.sha256(0, filesize) == "93d63f76261aecdacafdce0b490cf032c90b48c227f0772d4a5dccc71998beaf"
}
```

### Sample 98: `bbd5232ebe3f65b3`

| Field | Value |
|---|---|
| SHA-256 | `bbd5232ebe3f65b3666a72aefbb30c3f4756f57953279bef51af7f3dbd2a29df` |
| Family label | `Mirai` |
| File name | `main_x86_64` |
| File type | `elf` |
| First seen | `2026-06-30 13:51:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d8f23b6dd7a0c8a7d3c1b6792ec6c99` |
| SHA-1 | `8d7f77e64ee466b91dda0c5b0ed259d805015a92` |
| SHA-256 | `bbd5232ebe3f65b3666a72aefbb30c3f4756f57953279bef51af7f3dbd2a29df` |
| SHA3-384 | `87cf4f4c5cc096cd7820f9c71e800b072f0c24d27777db7a9ef0b0361e9480d750f46b5529bcf5210de35c2c13602ca3` |
| TLSH | `T1D4144B02B1D05CFDC8C9C3784B9FB536A836F0995239B65B6BC5AB212D4DD207F6DA80` |
| TELFHASH | `t11851b2301da935ac60d7d367b30fee99fc7309404ee1b4a45f5b76e1ce967880d92012` |
| SSDEEP | `3072:p/OIBfN73E2D76OG8JP1Dg1NGPkLN8bieY1AsaQHTuKIvN+ME2HO5c468m43DIV/:FOIBfN73E2D76OG8JPhknTJSRkxVUVvn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_bbd5232e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbd5232ebe3f65b3666a72aefbb30c3f4756f57953279bef51af7f3dbd2a29df"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-06-30 13:51:36"
  condition:
    hash.sha256(0, filesize) == "bbd5232ebe3f65b3666a72aefbb30c3f4756f57953279bef51af7f3dbd2a29df"
}
```

### Sample 99: `65550f6d0ffec842`

| Field | Value |
|---|---|
| SHA-256 | `65550f6d0ffec8421f703cdc7273d9c0563b3d480fe6702bad294a18afe72143` |
| Family label | `SilentEncryptor` |
| File name | `65550f6d0ffec8421f703cdc7273d9c0563b3d480fe6702bad294a18afe72143` |
| File type | `exe` |
| First seen | `2026-06-30 13:50:28` |
| Reporter | `Threatray` |
| Tags | `exe, SilentEncryptor` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f8647bbb9fb933a367abf32a6c6821d` |
| SHA-1 | `c8f4474d91fe1a957887a51f212a8fd0d158c282` |
| SHA-256 | `65550f6d0ffec8421f703cdc7273d9c0563b3d480fe6702bad294a18afe72143` |
| SHA3-384 | `fea8eacda4a9e1f5466f63b71bd7eeea4cac172649f8c86f619c15586040032ec4dfdea473451d2c9cc32acac847d6a2` |
| TLSH | `T10273C3043BF94118F1FFAF756DF1A5544A79BA175831D64E0989214E0E32BC0CEA2B7B` |
| SSDEEP | `1536:klMa8RKqtKy0TGDSYH2aOB724eQdG1T9WvCfACRXPik7:YMjtoY4ic81T9MCfACRXPj7` |

#### Technical Assessment

- The sample is tracked as `SilentEncryptor` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentEncryptor_099_65550f6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65550f6d0ffec8421f703cdc7273d9c0563b3d480fe6702bad294a18afe72143"
    family = "SilentEncryptor"
    file_name = "65550f6d0ffec8421f703cdc7273d9c0563b3d480fe6702bad294a18afe72143"
    file_type = "exe"
    first_seen = "2026-06-30 13:50:28"
  condition:
    hash.sha256(0, filesize) == "65550f6d0ffec8421f703cdc7273d9c0563b3d480fe6702bad294a18afe72143"
}
```

### Sample 100: `51c6b54a5b498e78`

| Field | Value |
|---|---|
| SHA-256 | `51c6b54a5b498e78765d8a95c065ede84380ec1f0438462baefb82b7e3967bbb` |
| Family label | `ColorbotStealer` |
| File name | `51c6b54a5b498e78765d8a95c065ede84380ec1f0438462baefb82b7e3967bbb` |
| File type | `exe` |
| First seen | `2026-06-30 13:50:24` |
| Reporter | `Threatray` |
| Tags | `ColorbotStealer, exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `958f3ce99157d6e0c1396d30f4d82e38` |
| SHA-1 | `e9ff8c25cefa6e137606f64cfdc2a4637b834ce9` |
| SHA-256 | `51c6b54a5b498e78765d8a95c065ede84380ec1f0438462baefb82b7e3967bbb` |
| SHA3-384 | `3bf3e133a799866eee3864f234da8202f29bae4b56e674c5108e1b4143f3f72073891ec54bf9872fb9ce09e8105d543d` |
| IMPHASH | `f1abc96631e4b0d194dd10a726e958c5` |
| TLSH | `T120558E3AA7A811ACC2B7D17CDE074D13E672704D0361ABEB02D48AA52F53BE15B3E751` |
| SSDEEP | `24576:1OzLJwUh+blb/V5UCSY7lLbkuEQ/fFT9Ite4YoUuplXUnFyPr0NeSwQz3V:1aL2UhylV5UCvH/044YoUuplXUnEPry3` |

#### Technical Assessment

- The sample is tracked as `ColorbotStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ColorbotStealer_100_51c6b54a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51c6b54a5b498e78765d8a95c065ede84380ec1f0438462baefb82b7e3967bbb"
    family = "ColorbotStealer"
    file_name = "51c6b54a5b498e78765d8a95c065ede84380ec1f0438462baefb82b7e3967bbb"
    file_type = "exe"
    first_seen = "2026-06-30 13:50:24"
  condition:
    hash.sha256(0, filesize) == "51c6b54a5b498e78765d8a95c065ede84380ec1f0438462baefb82b7e3967bbb"
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
 * Generated: 2026-07-01T04:56:47.763536+00:00
 */

rule MalwareBazaar_unknown_001_d4c7d4da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4c7d4da6b45e6f599f68aa8d579926f80bbb866434109e75932263641a72359"
    family = "unknown"
    file_name = "d4c7d4da6b45e6f599f68aa8d579926f80bbb866434109e75932263641a72359"
    file_type = "exe"
    first_seen = "2026-07-01 04:15:41"
  condition:
    hash.sha256(0, filesize) == "d4c7d4da6b45e6f599f68aa8d579926f80bbb866434109e75932263641a72359"
}

rule MalwareBazaar_unknown_002_ec889a49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec889a49ebd5ad66c0499fbc6fbc604363c825abdcb216978d430a40f5fbead0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-01 03:32:59"
  condition:
    hash.sha256(0, filesize) == "ec889a49ebd5ad66c0499fbc6fbc604363c825abdcb216978d430a40f5fbead0"
}

rule MalwareBazaar_unknown_003_3483feea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3483feeaab0ee0e47bac105a2e36ff634917228cbbb8e422f1289aeee38a58e8"
    family = "unknown"
    file_name = "3483feeaab0ee0e47bac105a2e36ff634917228cbbb8e422f1289aeee38a58e8"
    file_type = "elf"
    first_seen = "2026-07-01 03:20:48"
  condition:
    hash.sha256(0, filesize) == "3483feeaab0ee0e47bac105a2e36ff634917228cbbb8e422f1289aeee38a58e8"
}

rule MalwareBazaar_unknown_004_a6904afe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6904afef81f509dad199a36cf38a78f4a6b17e15fe867e602a3b953e93fed75"
    family = "unknown"
    file_name = "bbcl"
    file_type = "sh"
    first_seen = "2026-07-01 03:14:07"
  condition:
    hash.sha256(0, filesize) == "a6904afef81f509dad199a36cf38a78f4a6b17e15fe867e602a3b953e93fed75"
}

rule MalwareBazaar_unknown_005_03fc32e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03fc32e5233fbb4a0e70c3b424e2bc7ecd3c60a60dda62243c79332accb09ec0"
    family = "unknown"
    file_name = "ccl"
    file_type = "sh"
    first_seen = "2026-07-01 03:12:37"
  condition:
    hash.sha256(0, filesize) == "03fc32e5233fbb4a0e70c3b424e2bc7ecd3c60a60dda62243c79332accb09ec0"
}

rule MalwareBazaar_unknown_006_4d96c7b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d96c7b298f7572c18106cc803f100062a80ebcd4db11e80b0fece135629bac3"
    family = "unknown"
    file_name = "bwwg"
    file_type = "sh"
    first_seen = "2026-07-01 03:12:36"
  condition:
    hash.sha256(0, filesize) == "4d96c7b298f7572c18106cc803f100062a80ebcd4db11e80b0fece135629bac3"
}

rule MalwareBazaar_unknown_007_4dd8a2c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dd8a2c97d66f3a01e73e7e0154de994a08c359674013f1ecc8e61af562d4e2f"
    family = "unknown"
    file_name = "wwg"
    file_type = "sh"
    first_seen = "2026-07-01 03:12:35"
  condition:
    hash.sha256(0, filesize) == "4dd8a2c97d66f3a01e73e7e0154de994a08c359674013f1ecc8e61af562d4e2f"
}

rule MalwareBazaar_unknown_008_f4800b20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4800b200b146914f175228feab170d6cf740a637646d8a03b0a189e60749753"
    family = "unknown"
    file_name = "f4800b200b146914f175228feab170d6cf740a637646d8a03b0a189e60749753"
    file_type = "elf"
    first_seen = "2026-07-01 03:01:12"
  condition:
    hash.sha256(0, filesize) == "f4800b200b146914f175228feab170d6cf740a637646d8a03b0a189e60749753"
}

rule MalwareBazaar_RemcosRAT_009_abea831c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abea831cde9d7bebf47f5f1c3535ed9c42517ecfaed2fbc0c99477d055f77557"
    family = "RemcosRAT"
    file_name = "Skaaningerne.vbs"
    file_type = "vbs"
    first_seen = "2026-07-01 02:54:37"
  condition:
    hash.sha256(0, filesize) == "abea831cde9d7bebf47f5f1c3535ed9c42517ecfaed2fbc0c99477d055f77557"
}

rule MalwareBazaar_unknown_010_72afe188
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72afe188ce551644d8f437e71bae74c50dbe0b4e0628826241edd48a06d4ab13"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-01 02:35:24"
  condition:
    hash.sha256(0, filesize) == "72afe188ce551644d8f437e71bae74c50dbe0b4e0628826241edd48a06d4ab13"
}

rule MalwareBazaar_unknown_011_4c6f74f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c6f74f1ec9009ed6ef66b72a8e2412ea2606a2d4788b9b3fa3573a7f080f5c1"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-01 02:22:44"
  condition:
    hash.sha256(0, filesize) == "4c6f74f1ec9009ed6ef66b72a8e2412ea2606a2d4788b9b3fa3573a7f080f5c1"
}

rule MalwareBazaar_Mirai_012_d403aa0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d403aa0e2a7f1ae4d2fb7f4a5e1b543df59063e1fb39bd8c0bd2e11b041677b7"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-07-01 02:22:41"
  condition:
    hash.sha256(0, filesize) == "d403aa0e2a7f1ae4d2fb7f4a5e1b543df59063e1fb39bd8c0bd2e11b041677b7"
}

rule MalwareBazaar_unknown_013_21b135c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21b135c4cd6885b2cd9f482616ebcc218bde4faa2a94b3597fca99baad695d53"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-01 02:22:06"
  condition:
    hash.sha256(0, filesize) == "21b135c4cd6885b2cd9f482616ebcc218bde4faa2a94b3597fca99baad695d53"
}

rule MalwareBazaar_Mirai_014_446b0339
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "446b0339984f9637abd7e2117f969fc56e9f62126ff5f113fd400b3158f89ec2"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-07-01 02:22:05"
  condition:
    hash.sha256(0, filesize) == "446b0339984f9637abd7e2117f969fc56e9f62126ff5f113fd400b3158f89ec2"
}

rule MalwareBazaar_Mirai_015_872bfbe5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "872bfbe51e7f0a27ce6b21ac735e0640da0b21a1aa4de5051727eb2094e82392"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-07-01 02:19:26"
  condition:
    hash.sha256(0, filesize) == "872bfbe51e7f0a27ce6b21ac735e0640da0b21a1aa4de5051727eb2094e82392"
}

rule MalwareBazaar_unknown_016_0eef5bc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eef5bc2152e354f4650dc37092aca64aa5419fcbcb874f9605a26d3a5389999"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-01 02:16:15"
  condition:
    hash.sha256(0, filesize) == "0eef5bc2152e354f4650dc37092aca64aa5419fcbcb874f9605a26d3a5389999"
}

rule MalwareBazaar_Mirai_017_e9ddc2bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9ddc2bd6ef86cddfd3c02413c7e1ed189126b8045325fe09a73aa498583feef"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-01 01:41:40"
  condition:
    hash.sha256(0, filesize) == "e9ddc2bd6ef86cddfd3c02413c7e1ed189126b8045325fe09a73aa498583feef"
}

rule MalwareBazaar_Mirai_018_723999fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "723999fb1454b2ef20154487b1f9004f82ef2f40d9156f9f319b6adc006fa2ca"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-01 01:41:23"
  condition:
    hash.sha256(0, filesize) == "723999fb1454b2ef20154487b1f9004f82ef2f40d9156f9f319b6adc006fa2ca"
}

rule MalwareBazaar_Mirai_019_6a7eac5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a7eac5f0e100bffed673bf3842bfafaa276054eb99d38d296361794d41f5f81"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-01 01:36:42"
  condition:
    hash.sha256(0, filesize) == "6a7eac5f0e100bffed673bf3842bfafaa276054eb99d38d296361794d41f5f81"
}

rule MalwareBazaar_Mirai_020_7d658adb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d658adb48717a16af4ee9b3c075d5ed7d4903646cb8eadd152191f5fd0d3298"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-01 01:36:27"
  condition:
    hash.sha256(0, filesize) == "7d658adb48717a16af4ee9b3c075d5ed7d4903646cb8eadd152191f5fd0d3298"
}

rule MalwareBazaar_unknown_021_6319a8ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6319a8ff4c88f30f247331f95c814dc8d89e53015f275a8e6af71c25a02149df"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-01 01:29:11"
  condition:
    hash.sha256(0, filesize) == "6319a8ff4c88f30f247331f95c814dc8d89e53015f275a8e6af71c25a02149df"
}

rule MalwareBazaar_Mirai_022_b45c9376
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b45c93767641a85d59ad8aa0787914fb3276be2b4301c87a2d41e03b166b5316"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-01 01:28:39"
  condition:
    hash.sha256(0, filesize) == "b45c93767641a85d59ad8aa0787914fb3276be2b4301c87a2d41e03b166b5316"
}

rule MalwareBazaar_Mirai_023_505a10ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "505a10ef3b0f4206ca9242afa64d14977396223dd5babc0842ed82b49481a95a"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-01 01:28:14"
  condition:
    hash.sha256(0, filesize) == "505a10ef3b0f4206ca9242afa64d14977396223dd5babc0842ed82b49481a95a"
}

rule MalwareBazaar_Mirai_024_5265bf54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5265bf543b697864ea5014f737d219ca427714bbf092610e5dff1bae60f5d015"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-01 01:28:13"
  condition:
    hash.sha256(0, filesize) == "5265bf543b697864ea5014f737d219ca427714bbf092610e5dff1bae60f5d015"
}

rule MalwareBazaar_Mirai_025_4da2b79b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4da2b79b14333be0cf00390667dd885068b9d6d51817c7692ce43e3981179231"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-01 01:27:38"
  condition:
    hash.sha256(0, filesize) == "4da2b79b14333be0cf00390667dd885068b9d6d51817c7692ce43e3981179231"
}

rule MalwareBazaar_Mirai_026_118b1c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "118b1c37983bdb0003b871ce946d819fd900959fade81b40fce958d53456dfa8"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-01 01:27:09"
  condition:
    hash.sha256(0, filesize) == "118b1c37983bdb0003b871ce946d819fd900959fade81b40fce958d53456dfa8"
}

rule MalwareBazaar_Mirai_027_abd87d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abd87d9c9ea057d7fe828f5cd13b136220011ef97b4e65b85d3c93628366d7ca"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-01 01:25:50"
  condition:
    hash.sha256(0, filesize) == "abd87d9c9ea057d7fe828f5cd13b136220011ef97b4e65b85d3c93628366d7ca"
}

rule MalwareBazaar_Mirai_028_bd0b8f9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd0b8f9db1efebae48c870bbfbb1f33ae068c13a23149633aeda27c43daadd4b"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-01 01:25:37"
  condition:
    hash.sha256(0, filesize) == "bd0b8f9db1efebae48c870bbfbb1f33ae068c13a23149633aeda27c43daadd4b"
}

rule MalwareBazaar_Mirai_029_9c1502fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c1502fb7bacf86a0c6b5da53fc6d019f9be27137f149e4f48b6017575678a0e"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-01 01:24:35"
  condition:
    hash.sha256(0, filesize) == "9c1502fb7bacf86a0c6b5da53fc6d019f9be27137f149e4f48b6017575678a0e"
}

rule MalwareBazaar_Mirai_030_e850272e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e850272e0d23dc7490bd4b39d75372f0886f5e2d6ed0ce1aca5ed064bf72d496"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-01 01:24:23"
  condition:
    hash.sha256(0, filesize) == "e850272e0d23dc7490bd4b39d75372f0886f5e2d6ed0ce1aca5ed064bf72d496"
}

rule MalwareBazaar_Mirai_031_e2b7ae14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2b7ae14c2f73b26023c1c0c7c7d8c0bff44d121f50d8dd7d538edaeb56cffc6"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-01 01:15:58"
  condition:
    hash.sha256(0, filesize) == "e2b7ae14c2f73b26023c1c0c7c7d8c0bff44d121f50d8dd7d538edaeb56cffc6"
}

rule MalwareBazaar_WannaCry_032_13a61afc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13a61afc3252a69bd3ff8b4bd180e261a00dacf1da023b80357be62b3aa67a9e"
    family = "WannaCry"
    file_name = "13a61afc3252a69bd3ff8b4bd180e261a00dacf1da023b80357be62b3aa67a9e"
    file_type = "exe"
    first_seen = "2026-07-01 01:15:13"
  condition:
    hash.sha256(0, filesize) == "13a61afc3252a69bd3ff8b4bd180e261a00dacf1da023b80357be62b3aa67a9e"
}

rule MalwareBazaar_Mirai_033_5df4a215
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5df4a215203544161eee5872bd304e9ba17d9aa880fa3a2b089b9ba37720fbee"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-01 01:15:12"
  condition:
    hash.sha256(0, filesize) == "5df4a215203544161eee5872bd304e9ba17d9aa880fa3a2b089b9ba37720fbee"
}

rule MalwareBazaar_unknown_034_860b79ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "860b79ec3a237149b42c9c4756cbdd96b27d68fcb782b101c25d3bb506636b3b"
    family = "unknown"
    file_name = "RTO-E-Challan-500.apk"
    file_type = "apk"
    first_seen = "2026-07-01 00:56:04"
  condition:
    hash.sha256(0, filesize) == "860b79ec3a237149b42c9c4756cbdd96b27d68fcb782b101c25d3bb506636b3b"
}

rule MalwareBazaar_Mirai_035_8bf6dd05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bf6dd0572e247d89f8cd7a99db2557cf4a7e954d8222c0862ad13713f85aaa0"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-01 00:52:42"
  condition:
    hash.sha256(0, filesize) == "8bf6dd0572e247d89f8cd7a99db2557cf4a7e954d8222c0862ad13713f85aaa0"
}

rule MalwareBazaar_Mirai_036_504590bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "504590bd0ca8c9913dde882532fbcef50b6b6cbb8519bcf55ec1dc76cdd7c2ab"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-01 00:52:06"
  condition:
    hash.sha256(0, filesize) == "504590bd0ca8c9913dde882532fbcef50b6b6cbb8519bcf55ec1dc76cdd7c2ab"
}

rule MalwareBazaar_unknown_037_78533e66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78533e66970f86f2a8f583b40a54c5c4a70afadda811ace35cd7380352765b1b"
    family = "unknown"
    file_name = "apk.apk"
    file_type = "apk"
    first_seen = "2026-07-01 00:51:22"
  condition:
    hash.sha256(0, filesize) == "78533e66970f86f2a8f583b40a54c5c4a70afadda811ace35cd7380352765b1b"
}

rule MalwareBazaar_unknown_038_9d419c77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d419c77b9124062c92de6e7f1140cc4af9f3371a362b0d3aa4a0159647da077"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-01 00:42:46"
  condition:
    hash.sha256(0, filesize) == "9d419c77b9124062c92de6e7f1140cc4af9f3371a362b0d3aa4a0159647da077"
}

rule MalwareBazaar_Formbook_039_615302d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "615302d2052274be34164da6f349ecc8a9bc1d8404e10999572beb03dac4b009"
    family = "Formbook"
    file_name = "Purchase_Order_Form.js"
    file_type = "js"
    first_seen = "2026-07-01 00:34:18"
  condition:
    hash.sha256(0, filesize) == "615302d2052274be34164da6f349ecc8a9bc1d8404e10999572beb03dac4b009"
}

rule MalwareBazaar_unknown_040_c2d5a838
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2d5a838ebf3525e22fc008b859a8a5e9f1a2fa7bcd351489e7a1310da10d219"
    family = "unknown"
    file_name = "Fexoglobal_CRM_API_Documentation.zip"
    file_type = "zip"
    first_seen = "2026-07-01 00:32:31"
  condition:
    hash.sha256(0, filesize) == "c2d5a838ebf3525e22fc008b859a8a5e9f1a2fa7bcd351489e7a1310da10d219"
}

rule MalwareBazaar_unknown_041_f0ac0e28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0ac0e283232df690bb16bd7c8194b6ceabacf62807fed0482db9bc1c4c046e9"
    family = "unknown"
    file_name = "f0ac0e283232df690bb16bd7c8194b6ceabacf62807fed0482db9bc1c4c046e9"
    file_type = "gz"
    first_seen = "2026-07-01 00:31:17"
  condition:
    hash.sha256(0, filesize) == "f0ac0e283232df690bb16bd7c8194b6ceabacf62807fed0482db9bc1c4c046e9"
}

rule MalwareBazaar_unknown_042_b6a2638a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6a2638a0eaedd6065b8fae3162ae34685c782efb70282febeef0b9470c5b60d"
    family = "unknown"
    file_name = "PT2600000043.js"
    file_type = "js"
    first_seen = "2026-07-01 00:20:27"
  condition:
    hash.sha256(0, filesize) == "b6a2638a0eaedd6065b8fae3162ae34685c782efb70282febeef0b9470c5b60d"
}

rule MalwareBazaar_unknown_043_b1ee2ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1ee2ec96a5464bd5c8658b8b11d62586ef514687ce05280380621565b54254f"
    family = "unknown"
    file_name = "hax.sh"
    file_type = "sh"
    first_seen = "2026-06-30 23:10:32"
  condition:
    hash.sha256(0, filesize) == "b1ee2ec96a5464bd5c8658b8b11d62586ef514687ce05280380621565b54254f"
}

rule MalwareBazaar_Hajime_044_4ef31fbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ef31fbebeb162195c0facda1be5dd9b9b57fdaf95f39f657bab7681feec0930"
    family = "Hajime"
    file_name = "i"
    file_type = "elf"
    first_seen = "2026-06-30 22:41:37"
  condition:
    hash.sha256(0, filesize) == "4ef31fbebeb162195c0facda1be5dd9b9b57fdaf95f39f657bab7681feec0930"
}

rule MalwareBazaar_unknown_045_1a08a766
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a08a7669246227bf3070bd666e2f8bcf7385d08727ba0b4ab3a9195eaac284d"
    family = "unknown"
    file_name = "1a08a7669246227bf3070bd666e2f8bcf7385d08727ba0b4ab3a9195eaac284d"
    file_type = "elf"
    first_seen = "2026-06-30 22:28:59"
  condition:
    hash.sha256(0, filesize) == "1a08a7669246227bf3070bd666e2f8bcf7385d08727ba0b4ab3a9195eaac284d"
}

rule MalwareBazaar_unknown_046_45d3513d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45d3513dc95750c55f733fc27f83d009d46631cc1d4494f5d842d42a3ffe9151"
    family = "unknown"
    file_name = "PоpkаUz19+.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:27:16"
  condition:
    hash.sha256(0, filesize) == "45d3513dc95750c55f733fc27f83d009d46631cc1d4494f5d842d42a3ffe9151"
}

rule MalwareBazaar_unknown_047_93ce021f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93ce021f8551830646d4a75a6be6f420fd4d68e65964057d7d91dfee34d3ab0f"
    family = "unknown"
    file_name = "T!kT0k 18+._1782805172643.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:25:59"
  condition:
    hash.sha256(0, filesize) == "93ce021f8551830646d4a75a6be6f420fd4d68e65964057d7d91dfee34d3ab0f"
}

rule MalwareBazaar_unknown_048_40d22472
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40d224726eacba5b74eb7c41cacd13ae996b8639148b94be34ce80ca679b2236"
    family = "unknown"
    file_name = "T!kT0k 18+._1782805455920.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:25:05"
  condition:
    hash.sha256(0, filesize) == "40d224726eacba5b74eb7c41cacd13ae996b8639148b94be34ce80ca679b2236"
}

rule MalwareBazaar_unknown_049_581d28d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "581d28d8f57fca6d65b91a7f44d08e57d43aab20a337aaa9011ff1c8835f71fb"
    family = "unknown"
    file_name = "Т???.Т??.??+.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:24:08"
  condition:
    hash.sha256(0, filesize) == "581d28d8f57fca6d65b91a7f44d08e57d43aab20a337aaa9011ff1c8835f71fb"
}

rule MalwareBazaar_unknown_050_4e52f85b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e52f85b5be6cdcfc8a3493c0d56e99494a36871e53ef90ea915015a9fcbbdff"
    family = "unknown"
    file_name = "TikTok18.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:21:49"
  condition:
    hash.sha256(0, filesize) == "4e52f85b5be6cdcfc8a3493c0d56e99494a36871e53ef90ea915015a9fcbbdff"
}

rule MalwareBazaar_unknown_051_87b4cae8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87b4cae8ed4c474ece3b42a998fd0f7b86b74cebcd1fbcdc4aca155ce582e7ea"
    family = "unknown"
    file_name = "ŦikŦokprivat.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:20:29"
  condition:
    hash.sha256(0, filesize) == "87b4cae8ed4c474ece3b42a998fd0f7b86b74cebcd1fbcdc4aca155ce582e7ea"
}

rule MalwareBazaar_unknown_052_51f50596
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51f505968f17455c7ee7c1309064a2ec0870e0e120080d0bbbb19076a1c112c5"
    family = "unknown"
    file_name = "?а?_?о??.??+.apk"
    file_type = "apk"
    first_seen = "2026-06-30 21:19:23"
  condition:
    hash.sha256(0, filesize) == "51f505968f17455c7ee7c1309064a2ec0870e0e120080d0bbbb19076a1c112c5"
}

rule MalwareBazaar_LummaStealer_053_84fdf69c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84fdf69c7381701415d366808450de41e3127d15c497a196bd51cc3ecf3eeaea"
    family = "LummaStealer"
    file_name = "NEET-UG Paper leak legal documents.zip"
    file_type = "zip"
    first_seen = "2026-06-30 21:17:50"
  condition:
    hash.sha256(0, filesize) == "84fdf69c7381701415d366808450de41e3127d15c497a196bd51cc3ecf3eeaea"
}

rule MalwareBazaar_unknown_054_62745189
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "627451891fcf7498670f2df5e764101ceb2a8e62dc4aa6bdddb3614dae911444"
    family = "unknown"
    file_name = "Xuper TV APK_ películas, series y televisión en....apk"
    file_type = "apk"
    first_seen = "2026-06-30 20:53:47"
  condition:
    hash.sha256(0, filesize) == "627451891fcf7498670f2df5e764101ceb2a8e62dc4aa6bdddb3614dae911444"
}

rule MalwareBazaar_unknown_055_1afdbb93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1afdbb93a7e3858d99ed41134ce4bda6e48cc6aa5f55b6495d46c0c4b2abb95f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 20:48:56"
  condition:
    hash.sha256(0, filesize) == "1afdbb93a7e3858d99ed41134ce4bda6e48cc6aa5f55b6495d46c0c4b2abb95f"
}

rule MalwareBazaar_unknown_056_82bfd294
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82bfd294e0ee5496229a8734d9d8282fbb1e397c56669c7de579b5951bb44a0b"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-06-30 20:23:38"
  condition:
    hash.sha256(0, filesize) == "82bfd294e0ee5496229a8734d9d8282fbb1e397c56669c7de579b5951bb44a0b"
}

rule MalwareBazaar_Socks5Systemz_057_5550e9b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5550e9b063aa3dbf466593011bc7c1b6c01e54ff2ffeeaad74814a7726c35804"
    family = "Socks5Systemz"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 20:19:04"
  condition:
    hash.sha256(0, filesize) == "5550e9b063aa3dbf466593011bc7c1b6c01e54ff2ffeeaad74814a7726c35804"
}

rule MalwareBazaar_unknown_058_932fee49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "932fee49d6fef5473a0a055a74d17dc880d6996dea36f96a157d78a89c822aa8"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-30 20:17:39"
  condition:
    hash.sha256(0, filesize) == "932fee49d6fef5473a0a055a74d17dc880d6996dea36f96a157d78a89c822aa8"
}

rule MalwareBazaar_unknown_059_6f32c5f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f32c5f4d665488b58eddca27ca5621571d55caccc73012ded3ae898a5721935"
    family = "unknown"
    file_name = "tsetup-x64.6.8.2.zip"
    file_type = "zip"
    first_seen = "2026-06-30 20:10:04"
  condition:
    hash.sha256(0, filesize) == "6f32c5f4d665488b58eddca27ca5621571d55caccc73012ded3ae898a5721935"
}

rule MalwareBazaar_unknown_060_79472204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7947220463ee9c537118d668419b01412a674a5e6eaeaf17fcbe00d121048908"
    family = "unknown"
    file_name = "MeiqiaWinLatest.exe"
    file_type = "exe"
    first_seen = "2026-06-30 19:59:15"
  condition:
    hash.sha256(0, filesize) == "7947220463ee9c537118d668419b01412a674a5e6eaeaf17fcbe00d121048908"
}

rule MalwareBazaar_ValleyRAT_061_5835f5b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5835f5b27cd6f62d186fa92210f0cae7238e2aa2e030d0f223e1d2adc7016c4b"
    family = "ValleyRAT"
    file_name = "Meiqia-Win.exe"
    file_type = "exe"
    first_seen = "2026-06-30 19:58:12"
  condition:
    hash.sha256(0, filesize) == "5835f5b27cd6f62d186fa92210f0cae7238e2aa2e030d0f223e1d2adc7016c4b"
}

rule MalwareBazaar_unknown_062_119479be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "119479bef84f5d0c6eaf972fc4b80dfbf04cb8332221a81ccfe214b4100f2ecd"
    family = "unknown"
    file_name = "ainstall-setup63890002.msi"
    file_type = "msi"
    first_seen = "2026-06-30 19:57:16"
  condition:
    hash.sha256(0, filesize) == "119479bef84f5d0c6eaf972fc4b80dfbf04cb8332221a81ccfe214b4100f2ecd"
}

rule MalwareBazaar_unknown_063_2d9945bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d9945bba8207d419dca32e5c2ecc821f3eedd5c48bc1ebfe754133c56a17828"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-30 18:29:09"
  condition:
    hash.sha256(0, filesize) == "2d9945bba8207d419dca32e5c2ecc821f3eedd5c48bc1ebfe754133c56a17828"
}

rule MalwareBazaar_unknown_064_75e67e07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75e67e073558cd811b0053119653eba536f66ac9b01a9a71559225e4b920dea8"
    family = "unknown"
    file_name = "FluxMarket_CRM_API_Credentials.pdf.lnk"
    file_type = "lnk"
    first_seen = "2026-06-30 18:15:21"
  condition:
    hash.sha256(0, filesize) == "75e67e073558cd811b0053119653eba536f66ac9b01a9a71559225e4b920dea8"
}

rule MalwareBazaar_unknown_065_a1dbae0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1dbae0dd3e1d72f649be1c8a999274a22127ed27165018af1d96b7d6eda9baa"
    family = "unknown"
    file_name = "NAKAZ_MO_perevirka_mayna.zip"
    file_type = "zip"
    first_seen = "2026-06-30 18:11:11"
  condition:
    hash.sha256(0, filesize) == "a1dbae0dd3e1d72f649be1c8a999274a22127ed27165018af1d96b7d6eda9baa"
}

rule MalwareBazaar_KongTuke_066_90eb69c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90eb69c1b119e418b381c5754cbee51d6f4e10018c386228e954759a041eedad"
    family = "KongTuke"
    file_name = "package"
    file_type = "zip"
    first_seen = "2026-06-30 18:10:22"
  condition:
    hash.sha256(0, filesize) == "90eb69c1b119e418b381c5754cbee51d6f4e10018c386228e954759a041eedad"
}

rule MalwareBazaar_RemcosRAT_067_c23e08af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c23e08afa7965cb6e730138f3aef11f1c17693ed508457ff45b2a3880795a59d"
    family = "RemcosRAT"
    file_name = "rCotacaodePedidoNovo-Patagonia-P1441-26-1794.vbs"
    file_type = "vbs"
    first_seen = "2026-06-30 18:00:12"
  condition:
    hash.sha256(0, filesize) == "c23e08afa7965cb6e730138f3aef11f1c17693ed508457ff45b2a3880795a59d"
}

rule MalwareBazaar_unknown_068_59b5e489
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59b5e489e93dc76efb705b4ace28efd506c464eda2a2e0591023c0330b5e633f"
    family = "unknown"
    file_name = "atom.xml.ps1"
    file_type = "ps1"
    first_seen = "2026-06-30 17:57:17"
  condition:
    hash.sha256(0, filesize) == "59b5e489e93dc76efb705b4ace28efd506c464eda2a2e0591023c0330b5e633f"
}

rule MalwareBazaar_unknown_069_404a771b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "404a771b6be9ee6d97dc2f011ddeeb1b2cd78807298610cb002a3dac868b8cec"
    family = "unknown"
    file_name = "AdjuntoArc_301.zip"
    file_type = "zip"
    first_seen = "2026-06-30 17:57:10"
  condition:
    hash.sha256(0, filesize) == "404a771b6be9ee6d97dc2f011ddeeb1b2cd78807298610cb002a3dac868b8cec"
}

rule MalwareBazaar_Gh0stRAT_070_6b05b09d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b05b09d13cbb81ab4246b98f35b49f6915d31f140acacf6d42e260066fed543"
    family = "Gh0stRAT"
    file_name = "Industrial_Safety_and_Risk_Management_in_the_Industrial_Sector_Online.rar"
    file_type = "rar"
    first_seen = "2026-06-30 17:54:16"
  condition:
    hash.sha256(0, filesize) == "6b05b09d13cbb81ab4246b98f35b49f6915d31f140acacf6d42e260066fed543"
}

rule MalwareBazaar_unknown_071_ebc9d1ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebc9d1abb69490462aa79e0fc4ac987ce5cfe19492832e32f36685859e635fba"
    family = "unknown"
    file_name = "FontCacheSvc.exe"
    file_type = "exe"
    first_seen = "2026-06-30 17:48:44"
  condition:
    hash.sha256(0, filesize) == "ebc9d1abb69490462aa79e0fc4ac987ce5cfe19492832e32f36685859e635fba"
}

rule MalwareBazaar_unknown_072_2ee7da2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ee7da2bc52fa3b794ad34788e87a0aa76dca6f43805fb9cf636f02ac87ebe0b"
    family = "unknown"
    file_name = "obf - Copy.js"
    file_type = "js"
    first_seen = "2026-06-30 17:47:33"
  condition:
    hash.sha256(0, filesize) == "2ee7da2bc52fa3b794ad34788e87a0aa76dca6f43805fb9cf636f02ac87ebe0b"
}

rule MalwareBazaar_unknown_073_a1afd497
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1afd49726ee1f7062654ccb905a79860da26b2d6252b13fb32b65ce4f944a07"
    family = "unknown"
    file_name = "Archivo_Adjunto_637.zip"
    file_type = "zip"
    first_seen = "2026-06-30 17:40:18"
  condition:
    hash.sha256(0, filesize) == "a1afd49726ee1f7062654ccb905a79860da26b2d6252b13fb32b65ce4f944a07"
}

rule MalwareBazaar_unknown_074_218f0057
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "218f0057a81096662b7277f1ebece79f575c44ca5a46c177e9e72207ecd57270"
    family = "unknown"
    file_name = "Arcane.exe"
    file_type = "exe"
    first_seen = "2026-06-30 17:27:49"
  condition:
    hash.sha256(0, filesize) == "218f0057a81096662b7277f1ebece79f575c44ca5a46c177e9e72207ecd57270"
}

rule MalwareBazaar_PureLogsStealer_075_f17cb686
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f17cb686d2371074b25d8a992014dbd75a454d06d436324001eac3f9f0ecef5a"
    family = "PureLogsStealer"
    file_name = "SecuriteInfo.com.Heur.MSIL.Benin.5.84486846"
    file_type = "exe"
    first_seen = "2026-06-30 17:25:43"
  condition:
    hash.sha256(0, filesize) == "f17cb686d2371074b25d8a992014dbd75a454d06d436324001eac3f9f0ecef5a"
}

rule MalwareBazaar_unknown_076_6cff215d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cff215dcf60fc90e76adfc28b6725b123532365efa504e15d37144bf97d1857"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-30 17:22:49"
  condition:
    hash.sha256(0, filesize) == "6cff215dcf60fc90e76adfc28b6725b123532365efa504e15d37144bf97d1857"
}

rule MalwareBazaar_NetSupport_077_dec98a1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dec98a1ef5d1d1b5a6aa886345de1ac4adcea5829509e375b7cf87b7a22fb91d"
    family = "NetSupport"
    file_name = "Rate_RATE_AGR_Jun29.exe"
    file_type = "exe"
    first_seen = "2026-06-30 17:21:56"
  condition:
    hash.sha256(0, filesize) == "dec98a1ef5d1d1b5a6aa886345de1ac4adcea5829509e375b7cf87b7a22fb91d"
}

rule MalwareBazaar_NetSupport_078_f141db13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f141db13721b9f0248e4eb482bd0462995c920595ed9e87e704f841543f63621"
    family = "NetSupport"
    file_name = "RELEASE FORM.pdf.url"
    file_type = "url"
    first_seen = "2026-06-30 17:19:06"
  condition:
    hash.sha256(0, filesize) == "f141db13721b9f0248e4eb482bd0462995c920595ed9e87e704f841543f63621"
}

rule MalwareBazaar_Stealc_079_c3635ad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3635ad319d02c61c07dd3095b4998cf81c6d1e361284fcb67d00fe8b01d1e38"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 17:15:29"
  condition:
    hash.sha256(0, filesize) == "c3635ad319d02c61c07dd3095b4998cf81c6d1e361284fcb67d00fe8b01d1e38"
}

rule MalwareBazaar_RemusStealer_080_13ba8af7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13ba8af75fb5088dc269b4a5ee3dcafc8dd397775a1258643eb350871851c1dc"
    family = "RemusStealer"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-06-30 17:15:12"
  condition:
    hash.sha256(0, filesize) == "13ba8af75fb5088dc269b4a5ee3dcafc8dd397775a1258643eb350871851c1dc"
}

rule MalwareBazaar_unknown_081_6b4acfec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b4acfec0d604878f445271c3ffb773ff6563affc8064a825c6ecd87b5dd2f61"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-06-30 17:11:43"
  condition:
    hash.sha256(0, filesize) == "6b4acfec0d604878f445271c3ffb773ff6563affc8064a825c6ecd87b5dd2f61"
}

rule MalwareBazaar_KongTuke_082_5fc3616b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fc3616b64a4b02007b3cdaae584a269e6a972e004d5a964097ec67c40983366"
    family = "KongTuke"
    file_name = "package"
    file_type = "zip"
    first_seen = "2026-06-30 17:06:28"
  condition:
    hash.sha256(0, filesize) == "5fc3616b64a4b02007b3cdaae584a269e6a972e004d5a964097ec67c40983366"
}

rule MalwareBazaar_unknown_083_eb815fb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb815fb77cc1c177f613bb69d349d8bf5150afef03c66005cbbf3767954c279c"
    family = "unknown"
    file_name = "eb815fb77cc1c177f613bb69d349d8bf5150afef03c66005cbbf3767954c279c"
    file_type = "elf"
    first_seen = "2026-06-30 17:01:12"
  condition:
    hash.sha256(0, filesize) == "eb815fb77cc1c177f613bb69d349d8bf5150afef03c66005cbbf3767954c279c"
}

rule MalwareBazaar_Vidar_084_a9eb130c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9eb130cb57881807b7ef072265af0f6ec84e73c728f11ecce8cc01a7b6a1567"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 16:52:15"
  condition:
    hash.sha256(0, filesize) == "a9eb130cb57881807b7ef072265af0f6ec84e73c728f11ecce8cc01a7b6a1567"
}

rule MalwareBazaar_BlankGrabber_085_49a58699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49a58699c0421dc0f5769ec37936b3ae01b7dd5e715a7075e5e39ea78715120e"
    family = "BlankGrabber"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 16:42:44"
  condition:
    hash.sha256(0, filesize) == "49a58699c0421dc0f5769ec37936b3ae01b7dd5e715a7075e5e39ea78715120e"
}

rule MalwareBazaar_Mirai_086_0c212b01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c212b01802e3eb2f28d2c42afbeb9ac3c6620780d5d7988c6edad310444e477"
    family = "Mirai"
    file_name = "0c212b01802e3eb2f28d2c42afbeb9ac3c6620780d5d7988c6edad310444e477"
    file_type = "elf"
    first_seen = "2026-06-30 16:29:57"
  condition:
    hash.sha256(0, filesize) == "0c212b01802e3eb2f28d2c42afbeb9ac3c6620780d5d7988c6edad310444e477"
}

rule MalwareBazaar_Mirai_087_5a72d52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a72d52ac0859f831335a2fb1f6756f55822ee71978552c1cabfa3d6f4a08f6c"
    family = "Mirai"
    file_name = "5a72d52ac0859f831335a2fb1f6756f55822ee71978552c1cabfa3d6f4a08f6c"
    file_type = "elf"
    first_seen = "2026-06-30 15:52:32"
  condition:
    hash.sha256(0, filesize) == "5a72d52ac0859f831335a2fb1f6756f55822ee71978552c1cabfa3d6f4a08f6c"
}

rule MalwareBazaar_GoldDigger_088_bba9bc21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bba9bc21a322ea0e1737c5fa64057d12f133a3ebed6007ffed979b3d6099f6aa"
    family = "GoldDigger"
    file_name = "pln_mobile.apk"
    file_type = "apk"
    first_seen = "2026-06-30 15:25:27"
  condition:
    hash.sha256(0, filesize) == "bba9bc21a322ea0e1737c5fa64057d12f133a3ebed6007ffed979b3d6099f6aa"
}

rule MalwareBazaar_unknown_089_a4bfe1bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4bfe1bcecd9e6f6d1f3bc661ed80f4ed464c1231eacf609f9423488bf9660b3"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Win32.Waldek.cnei.22087.12105"
    file_type = "exe"
    first_seen = "2026-06-30 15:22:52"
  condition:
    hash.sha256(0, filesize) == "a4bfe1bcecd9e6f6d1f3bc661ed80f4ed464c1231eacf609f9423488bf9660b3"
}

rule MalwareBazaar_unknown_090_2143baef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2143baefd0b108fa1f6cfcfa3eb31d87578c6014117768f06bd8544dd02c8adf"
    family = "unknown"
    file_name = "Setup_Network.exe"
    file_type = "exe"
    first_seen = "2026-06-30 15:20:10"
  condition:
    hash.sha256(0, filesize) == "2143baefd0b108fa1f6cfcfa3eb31d87578c6014117768f06bd8544dd02c8adf"
}

rule MalwareBazaar_KongTuke_091_2065ac72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2065ac72d90574df9958e33de5efa2d9a2a7e73fc9d9f9419769f85aad083d93"
    family = "KongTuke"
    file_name = "package"
    file_type = "zip"
    first_seen = "2026-06-30 15:09:41"
  condition:
    hash.sha256(0, filesize) == "2065ac72d90574df9958e33de5efa2d9a2a7e73fc9d9f9419769f85aad083d93"
}

rule MalwareBazaar_Mirai_092_7f163d45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f163d45fef16ddfc392d08467fbe4e661666921a70ff4e57dc28f066ec4982b"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-06-30 14:56:22"
  condition:
    hash.sha256(0, filesize) == "7f163d45fef16ddfc392d08467fbe4e661666921a70ff4e57dc28f066ec4982b"
}

rule MalwareBazaar_Mirai_093_e7e254d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7e254d63b7a5f492c6f74ac48393687b57ed10986b2ca7fcd93a7ec6b07bfe8"
    family = "Mirai"
    file_name = "POWERPC"
    file_type = "elf"
    first_seen = "2026-06-30 14:48:46"
  condition:
    hash.sha256(0, filesize) == "e7e254d63b7a5f492c6f74ac48393687b57ed10986b2ca7fcd93a7ec6b07bfe8"
}

rule MalwareBazaar_Mirai_094_ab46c8b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab46c8b82f74508dc98679d5fed21e8a8c0b4ada2c43b061d0e9cc0c43f6f873"
    family = "Mirai"
    file_name = "X86_64"
    file_type = "elf"
    first_seen = "2026-06-30 14:20:57"
  condition:
    hash.sha256(0, filesize) == "ab46c8b82f74508dc98679d5fed21e8a8c0b4ada2c43b061d0e9cc0c43f6f873"
}

rule MalwareBazaar_Mirai_095_b8cc0205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8cc02058e1d4c9d7efe775cd645685d8fad1d3f90f0572b58262937c7c1b729"
    family = "Mirai"
    file_name = "main_aarch64"
    file_type = "elf"
    first_seen = "2026-06-30 14:15:46"
  condition:
    hash.sha256(0, filesize) == "b8cc02058e1d4c9d7efe775cd645685d8fad1d3f90f0572b58262937c7c1b729"
}

rule MalwareBazaar_Mirai_096_a1e468b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1e468b77bab8faa8f6e42c37dd0c8f6556e5c529273118f67c6150fbd96c921"
    family = "Mirai"
    file_name = "ARMV6L"
    file_type = "elf"
    first_seen = "2026-06-30 13:59:24"
  condition:
    hash.sha256(0, filesize) == "a1e468b77bab8faa8f6e42c37dd0c8f6556e5c529273118f67c6150fbd96c921"
}

rule MalwareBazaar_Mirai_097_93d63f76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93d63f76261aecdacafdce0b490cf032c90b48c227f0772d4a5dccc71998beaf"
    family = "Mirai"
    file_name = "I686"
    file_type = "elf"
    first_seen = "2026-06-30 13:59:22"
  condition:
    hash.sha256(0, filesize) == "93d63f76261aecdacafdce0b490cf032c90b48c227f0772d4a5dccc71998beaf"
}

rule MalwareBazaar_Mirai_098_bbd5232e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbd5232ebe3f65b3666a72aefbb30c3f4756f57953279bef51af7f3dbd2a29df"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-06-30 13:51:36"
  condition:
    hash.sha256(0, filesize) == "bbd5232ebe3f65b3666a72aefbb30c3f4756f57953279bef51af7f3dbd2a29df"
}

rule MalwareBazaar_SilentEncryptor_099_65550f6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65550f6d0ffec8421f703cdc7273d9c0563b3d480fe6702bad294a18afe72143"
    family = "SilentEncryptor"
    file_name = "65550f6d0ffec8421f703cdc7273d9c0563b3d480fe6702bad294a18afe72143"
    file_type = "exe"
    first_seen = "2026-06-30 13:50:28"
  condition:
    hash.sha256(0, filesize) == "65550f6d0ffec8421f703cdc7273d9c0563b3d480fe6702bad294a18afe72143"
}

rule MalwareBazaar_ColorbotStealer_100_51c6b54a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51c6b54a5b498e78765d8a95c065ede84380ec1f0438462baefb82b7e3967bbb"
    family = "ColorbotStealer"
    file_name = "51c6b54a5b498e78765d8a95c065ede84380ec1f0438462baefb82b7e3967bbb"
    file_type = "exe"
    first_seen = "2026-06-30 13:50:24"
  condition:
    hash.sha256(0, filesize) == "51c6b54a5b498e78765d8a95c065ede84380ec1f0438462baefb82b7e3967bbb"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

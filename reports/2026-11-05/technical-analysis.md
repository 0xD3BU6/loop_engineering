# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-05

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 673 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 673 |
| Unique family labels | 17 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 26 |
| SalatStealer | 19 |
| Mirai | 15 |
| VShell | 9 |
| Arechclient2 | 5 |
| RemusStealer | 5 |
| WARDENStealer | 4 |
| NetSupport | 3 |
| RemcosRAT | 2 |
| CoinMiner | 2 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 54 |
| elf | 15 |
| macho | 15 |
| zip | 4 |
| msi | 3 |
| js | 2 |
| ps1 | 2 |
| bat | 1 |
| iso | 1 |
| vbs | 1 |

## Per-Sample Analysis

### Sample 1: `89eda14459e02dba`

| Field | Value |
|---|---|
| SHA-256 | `89eda14459e02dba101cabd74297dc02a6e4bbc957b322c9c6d1d6d4c23372d3` |
| Family label | `unknown` |
| File name | `RuneLiteSetup.exe` |
| File type | `exe` |
| First seen | `2026-11-05 06:52:17` |
| Reporter | `rc4` |
| Tags | `exe, inno, installer, osrs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95c41766872aa11db0beedf6a06ff57d` |
| SHA-1 | `b14b13971c98cae4282064b28443330365c7e12a` |
| SHA-256 | `89eda14459e02dba101cabd74297dc02a6e4bbc957b322c9c6d1d6d4c23372d3` |
| SHA3-384 | `990c2bbf4115bc9ddc8879fb6ff8893001e07c7065c6773da72a77dee36f927c8810950a080714950fe5f373eb287a08` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1F6673337728B213ED12E46397AB6F520953FAA6165538C0697F4C88CCF264702E3E797` |
| SSDEEP | `786432:arucWWKsZjWo4oLvNhx/Ptxibx3Dg8J/7qsnm:FwT4oLvN79uhxJ2snm` |
| ICON-DHASH | `4b26aaa22672c219` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_89eda144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89eda14459e02dba101cabd74297dc02a6e4bbc957b322c9c6d1d6d4c23372d3"
    family = "unknown"
    file_name = "RuneLiteSetup.exe"
    file_type = "exe"
    first_seen = "2026-11-05 06:52:17"
  condition:
    hash.sha256(0, filesize) == "89eda14459e02dba101cabd74297dc02a6e4bbc957b322c9c6d1d6d4c23372d3"
}
```

### Sample 2: `a481fcff23200fdd`

| Field | Value |
|---|---|
| SHA-256 | `a481fcff23200fdd3f0a3b1c869f9628f28e406562d35d405390be74cc5d4240` |
| Family label | `RemcosRAT` |
| File name | `PO# Material&specification.JS.js` |
| File type | `js` |
| First seen | `2026-11-05 06:50:12` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b567d2279b2b58bed39595abf30331f9` |
| SHA-1 | `9fcb81fd037e9f72bd16b4a223edff820f7092a7` |
| SHA-256 | `a481fcff23200fdd3f0a3b1c869f9628f28e406562d35d405390be74cc5d4240` |
| SHA3-384 | `bb94171dc37291812b6e3504649695cbdc31dac8bcd18e5d17e8bf031cc7738dbd7d6bb691d003790aabb730ba41c734` |
| TLSH | `T14F36D4822F8FB2323721AF8C8639DD78950A65C31986CB3C715DF219F52DD4AA7187D2` |
| SSDEEP | `98304:UW6UmFGdX44iwrL3rXNnrx5xAOWCSV1qX017oXt3BdeqLQm/ioLQewkLTpU5jdNP:UWRmFGdX44iwrL37Nnrx5xAOWCSV1qXs` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_002_a481fcff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a481fcff23200fdd3f0a3b1c869f9628f28e406562d35d405390be74cc5d4240"
    family = "RemcosRAT"
    file_name = "PO# Material&specification.JS.js"
    file_type = "js"
    first_seen = "2026-11-05 06:50:12"
  condition:
    hash.sha256(0, filesize) == "a481fcff23200fdd3f0a3b1c869f9628f28e406562d35d405390be74cc5d4240"
}
```

### Sample 3: `8864b90c5709d667`

| Field | Value |
|---|---|
| SHA-256 | `8864b90c5709d66745fa954f692e4d22753c8fd340e37f2cb65e300701e1d268` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-11-05 06:07:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32664c8eba09dcde93b33b76ecb893b1` |
| SHA-1 | `ffc20d3b8642e3f8728c2101c955789fcb16b955` |
| SHA-256 | `8864b90c5709d66745fa954f692e4d22753c8fd340e37f2cb65e300701e1d268` |
| SHA3-384 | `ea85900143cc75c79d6e886257821e13ac1dd115e027525ee097f2a1fc95611dee735442ffec34238d0e8096c77f383f` |
| TLSH | `T12DE3F649FD429B01D5D626FAFE0E428973535B78E3FE71029E245B3163CAA6B0F7A401` |
| TELFHASH | `t16c21fc20fb590de8bff5c4b540ebf826ae5c31dda92a3846063d569b8d22dc4b02640e` |
| SSDEEP | `3072:4fqwxZfzYaVpKYZoGp20F0U680J5mfRG7PwdaBf0Kfrbv3fEACsgwZ/d44DBhU:4fqwxZfzYqNZppTF0U68SmfsbmaBfRfU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_8864b90c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8864b90c5709d66745fa954f692e4d22753c8fd340e37f2cb65e300701e1d268"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:16"
  condition:
    hash.sha256(0, filesize) == "8864b90c5709d66745fa954f692e4d22753c8fd340e37f2cb65e300701e1d268"
}
```

### Sample 4: `9502994b352f7ce5`

| Field | Value |
|---|---|
| SHA-256 | `9502994b352f7ce5c1014ee240393a32798f25101b0f58e3cbf7a0220cbaa628` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-11-05 06:07:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ef99280dfd72b43706132c381714dd1` |
| SHA-1 | `670046c2133dc93ae185aeaec6c1c8b914adc678` |
| SHA-256 | `9502994b352f7ce5c1014ee240393a32798f25101b0f58e3cbf7a0220cbaa628` |
| SHA3-384 | `e7a9213ccf442078f9c579c3997a9a98f420dff08ce893d8db64832b20b4155d3152cc184a7be8c134fc915fa8d5981c` |
| TLSH | `T17BE35AA3CC3A6E98C664E6B0B0318F791B53996051471FBE15B7CA788487DCDF6093B8` |
| SSDEEP | `3072:0kgkyzftnRBxxQA0USb6Il7vWtjajEaSMJ:0kgkyzfhRDSA03T+tjESMJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_9502994b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9502994b352f7ce5c1014ee240393a32798f25101b0f58e3cbf7a0220cbaa628"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:13"
  condition:
    hash.sha256(0, filesize) == "9502994b352f7ce5c1014ee240393a32798f25101b0f58e3cbf7a0220cbaa628"
}
```

### Sample 5: `39cda2690a97dbb6`

| Field | Value |
|---|---|
| SHA-256 | `39cda2690a97dbb6a9f7c8afd807d84d8cadb0a42ec4d7b0772b4f305ee4c721` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-11-05 06:07:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f129182304507a386127fcd41798036` |
| SHA-1 | `5f2ad08efd878149086d58951743d9c0be958850` |
| SHA-256 | `39cda2690a97dbb6a9f7c8afd807d84d8cadb0a42ec4d7b0772b4f305ee4c721` |
| SHA3-384 | `3b0935a863ce1328409a567308e537ef10d5397cf0cfd7ddd2e291cc0947f4aba4227ce72e247b57ae2fe1570294a884` |
| TLSH | `T1E324B50AAF510EBBD8AFDD3706E90B0635CC650722A83B367674D924F64A94F49D3C78` |
| SSDEEP | `3072:wSOTF8vUoIi5eigDuOPzQRTQzejlZUrmZjAX/By1S:wavvNIuOPzQRTQzEZbZj2/By` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_39cda269
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39cda2690a97dbb6a9f7c8afd807d84d8cadb0a42ec4d7b0772b4f305ee4c721"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:11"
  condition:
    hash.sha256(0, filesize) == "39cda2690a97dbb6a9f7c8afd807d84d8cadb0a42ec4d7b0772b4f305ee4c721"
}
```

### Sample 6: `0e60696306f2bd98`

| Field | Value |
|---|---|
| SHA-256 | `0e60696306f2bd98fe97b2e42d1fa4a515904715338b8c3db2ab39084c20e59d` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-11-05 06:07:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `591feedd962d5f7918770da2a47d5d15` |
| SHA-1 | `ec87a9af96cc5d5f3f178c3c259343bbdb59dd48` |
| SHA-256 | `0e60696306f2bd98fe97b2e42d1fa4a515904715338b8c3db2ab39084c20e59d` |
| SHA3-384 | `b86cb6568ef2c8ff66e3b7892655cbc95743c48cc9677046fddda8bf0ec6870415a95c5feb96ae3f01b2ca1994fc1ea2` |
| TLSH | `T116B34B86F783E0F0ED5A0AF0112FE73D8635EE214025DE5AEBE4BD71DD22601A65A71C` |
| TELFHASH | `t16b4126ba4afa0ddcabd05402938e1b315a5db67f2820368207f29914136ef81b07bc3c` |
| SSDEEP | `1536:ctCM7NpSZBF16finG5mgKE3qjDEwvPaiiooM7kcw5LUS314X/yndSdiM8eSrr:ctCM7NK+finGMrDjDEw9oPPdi6qit` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_0e606963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e60696306f2bd98fe97b2e42d1fa4a515904715338b8c3db2ab39084c20e59d"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:09"
  condition:
    hash.sha256(0, filesize) == "0e60696306f2bd98fe97b2e42d1fa4a515904715338b8c3db2ab39084c20e59d"
}
```

### Sample 7: `43eb85040d44c625`

| Field | Value |
|---|---|
| SHA-256 | `43eb85040d44c6253623d26c822b567b9f96f0924fa480a0915db583016c1805` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-11-05 06:07:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f55dc0a2df0ed36d24633fb9da4a45b6` |
| SHA-1 | `f27b2929af41d2ac26a2001b2a02a85da209dd40` |
| SHA-256 | `43eb85040d44c6253623d26c822b567b9f96f0924fa480a0915db583016c1805` |
| SHA3-384 | `e1fb8bf885766884b3640a2b27278ea1dc62fcf386daef179eba69cf9fcb155f88f989a5932628f7ea0da75ce182d8e3` |
| TLSH | `T188F3AF97B30F2450C82206F45BCF5B5E3A2325015F6B9AE36C5E3A3AA6775DF180A3D1` |
| SSDEEP | `3072:jNnLADKNxQfdkTAWQtt/zHLswXEGWwKxKG/gCCDdFc2vvWq:jBLEKNxQfdV3H1XL+0GrCDdFc4Wq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_43eb8504
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43eb85040d44c6253623d26c822b567b9f96f0924fa480a0915db583016c1805"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:06"
  condition:
    hash.sha256(0, filesize) == "43eb85040d44c6253623d26c822b567b9f96f0924fa480a0915db583016c1805"
}
```

### Sample 8: `dc57d578a326799d`

| Field | Value |
|---|---|
| SHA-256 | `dc57d578a326799d2e3c5d9e5b7ffae056245c43644b5d9715e5cd2682f28861` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-11-05 06:07:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd19ecf2097b78c35f1ce4e5f29bcfb3` |
| SHA-1 | `13b4d3d1a2acec035e56160a69d9f0690d09e9ed` |
| SHA-256 | `dc57d578a326799d2e3c5d9e5b7ffae056245c43644b5d9715e5cd2682f28861` |
| SHA3-384 | `e7004bae27dce45c7b19ad8e38e3925e91be9ef0e17a6237ed0cbdb304f9d87b25572d98b97ed9fedd101e71b3cd59ea` |
| TLSH | `T142F30785FD519F16C6C666BBFB4E428C372B1768D3FA72039D295F20378B85A0E36142` |
| TELFHASH | `t19731fea62f484e9c5bc8815482ea35292ff9388d2e222853971d768f0513ec2702e83e` |
| SSDEEP | `3072:6HZjdriwobj4/bXtjNizV1WdSwForitwLjRq8WUlIj3zaF2SQ:8Zjdriwobj4/bXtZFyritwfRq8WiIXa4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_dc57d578
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc57d578a326799d2e3c5d9e5b7ffae056245c43644b5d9715e5cd2682f28861"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:03"
  condition:
    hash.sha256(0, filesize) == "dc57d578a326799d2e3c5d9e5b7ffae056245c43644b5d9715e5cd2682f28861"
}
```

### Sample 9: `88d88b49cdad22a5`

| Field | Value |
|---|---|
| SHA-256 | `88d88b49cdad22a516267f4f8404a0d732f5152d5a0d314273bd1fc132c8861d` |
| Family label | `unknown` |
| File name | `darwin_amd64` |
| File type | `macho` |
| First seen | `2026-11-05 06:02:03` |
| Reporter | `ghozt` |
| Tags | `golang, macho, websocket, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b8045be5429d6aeca91363b762109d2` |
| SHA-1 | `88e1802d5bed34483b70196e0f735e5ec2eab32c` |
| SHA-256 | `88d88b49cdad22a516267f4f8404a0d732f5152d5a0d314273bd1fc132c8861d` |
| SHA3-384 | `256c5a3c4f9fd0411ed575899c0fe5f5b266800f853ff2abb4bd600525740e9f265f359437ee719de55d4fa623705fc5` |
| TLSH | `T12A762807F89051A8C0ADD17486769263BB70BC985B3067D73B10F6B82F36BD46EBA354` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:BZFac82aorb/TOvO90d7HjmAFd4A64nsfJIp7ZFNUO4NsrlRcm5IuV1ceB4SYYPf:Jat8uXXtYi7pS0zEAM71ozjDfV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_88d88b49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88d88b49cdad22a516267f4f8404a0d732f5152d5a0d314273bd1fc132c8861d"
    family = "unknown"
    file_name = "darwin_amd64"
    file_type = "macho"
    first_seen = "2026-11-05 06:02:03"
  condition:
    hash.sha256(0, filesize) == "88d88b49cdad22a516267f4f8404a0d732f5152d5a0d314273bd1fc132c8861d"
}
```

### Sample 10: `e9af795bb6786e77`

| Field | Value |
|---|---|
| SHA-256 | `e9af795bb6786e776a4f5ec420091c8378a168df651feace5c037d884da3904d` |
| Family label | `SalatStealer` |
| File name | `e9af795bb6786e776a4f5ec420091c8378a168df651feace5c037d884da3904d.bin` |
| File type | `bat` |
| First seen | `2026-11-05 05:52:33` |
| Reporter | `Tuxxin` |
| Tags | `bat, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b1d06fbbfd3aa42beb66465096da9b4` |
| SHA-1 | `edb49bd22169dbc1a7144644ef6802838ce082c8` |
| SHA-256 | `e9af795bb6786e776a4f5ec420091c8378a168df651feace5c037d884da3904d` |
| SHA3-384 | `04d94e78545b4614056c2c0fab709af59804f1c8c20426056e8f105c8a7183a040325c5e8a77383bbe29497b8c1e87d1` |
| TLSH | `T195D69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzn:s` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_010_e9af795b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9af795bb6786e776a4f5ec420091c8378a168df651feace5c037d884da3904d"
    family = "SalatStealer"
    file_name = "e9af795bb6786e776a4f5ec420091c8378a168df651feace5c037d884da3904d.bin"
    file_type = "bat"
    first_seen = "2026-11-05 05:52:33"
  condition:
    hash.sha256(0, filesize) == "e9af795bb6786e776a4f5ec420091c8378a168df651feace5c037d884da3904d"
}
```

### Sample 11: `75685ebe92f65ba4`

| Field | Value |
|---|---|
| SHA-256 | `75685ebe92f65ba4d317f9dd6b068e0fbc378cc7d901ca1f24cef9d3d513a7af` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-11-05 05:45:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bbbea675d77710bd54678d55311b009` |
| SHA-1 | `081d4ae3786f9a95ba65a3b9ca58e17d8794ca42` |
| SHA-256 | `75685ebe92f65ba4d317f9dd6b068e0fbc378cc7d901ca1f24cef9d3d513a7af` |
| SHA3-384 | `f6ee2d7c4c7f71c68d0121e2e5a4e2ca618c6a88bb29e80e245f513481dd7e8d03ffe933ddcaab3229fb270b25a259bf` |
| TLSH | `T1B4E37D41F7E2D3F4FD8394B0851EA339AE341E2512729E9FEFC6267198516024F6B62C` |
| TELFHASH | `t199217221ba26ec61e343e4f6c5b744e624ee491ed73e16454293be312d0a6c2e002fa3` |
| SSDEEP | `3072:PbVyxH3q73MwlT4Kf5WVED7cyqHnYJ1cf9h:PbVyNSP5WacypU7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_75685ebe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75685ebe92f65ba4d317f9dd6b068e0fbc378cc7d901ca1f24cef9d3d513a7af"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:23"
  condition:
    hash.sha256(0, filesize) == "75685ebe92f65ba4d317f9dd6b068e0fbc378cc7d901ca1f24cef9d3d513a7af"
}
```

### Sample 12: `660cab5accb26eaa`

| Field | Value |
|---|---|
| SHA-256 | `660cab5accb26eaa2aeef98d7f6fda583a86c99d56a398a3430123f56c17eb2c` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-05 05:45:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c0c57a090db70c8638ecac2f246aa5a` |
| SHA-1 | `5c29a83b2a39b251226cf72020b161bfc0c55efa` |
| SHA-256 | `660cab5accb26eaa2aeef98d7f6fda583a86c99d56a398a3430123f56c17eb2c` |
| SHA3-384 | `9e948f29429fe6f941abd1d1351aeba256b219d61344ab74aabf07fbda32083826686568f2c5b60777d4f8dbe0b071cb` |
| TLSH | `T158242A67FE04DB2FC40F63305CB3CB6096D65E712EA14AAA3254D79C3E311AA1E5B5E0` |
| SSDEEP | `6144:1eooN/b1qz9A3NbYWiGRWdZ5UjETn8sIOM:1K5b1qz9A3Nb+8VOM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_660cab5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "660cab5accb26eaa2aeef98d7f6fda583a86c99d56a398a3430123f56c17eb2c"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:20"
  condition:
    hash.sha256(0, filesize) == "660cab5accb26eaa2aeef98d7f6fda583a86c99d56a398a3430123f56c17eb2c"
}
```

### Sample 13: `f022bc4c2de44d2a`

| Field | Value |
|---|---|
| SHA-256 | `f022bc4c2de44d2aebc1170e0d7985e7486b2e5054eb3c46e47840fb543cbc5f` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-11-05 05:45:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d0c1f811123753c6f68cd58d838611e` |
| SHA-1 | `ca4c9b967eafd458608f45058b4fe535a154b18c` |
| SHA-256 | `f022bc4c2de44d2aebc1170e0d7985e7486b2e5054eb3c46e47840fb543cbc5f` |
| SHA3-384 | `c36fe003ebc05f27523bdf356c44659613497ce05d1c1b35fcc1184e43eb6de672782eedcf5f348e0bb6ad7c71898512` |
| TLSH | `T177241B46BF04EFA7C02C8F70C9AECB160194618569E2E1BF76A487DDBA782550F039DC` |
| SSDEEP | `3072:1L4O5VWjfdLQVJL/G7NM4RCx5jWiSz9v3hCA/LyMH/3Ge2iXEAWb:1L4O5szdCL/ka4wxki6vf2ezEAW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_f022bc4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f022bc4c2de44d2aebc1170e0d7985e7486b2e5054eb3c46e47840fb543cbc5f"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:18"
  condition:
    hash.sha256(0, filesize) == "f022bc4c2de44d2aebc1170e0d7985e7486b2e5054eb3c46e47840fb543cbc5f"
}
```

### Sample 14: `6603f67d9e0947ca`

| Field | Value |
|---|---|
| SHA-256 | `6603f67d9e0947caa92a1614175dc125527eb6dc6ee4d5dfc0330ebd64bd2fea` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-11-05 05:45:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d59d3c40dd7efc0a61bd76bed5cbae1c` |
| SHA-1 | `0a976933fa21cf5e8384903a652e884eb7b3c687` |
| SHA-256 | `6603f67d9e0947caa92a1614175dc125527eb6dc6ee4d5dfc0330ebd64bd2fea` |
| SHA3-384 | `cae01f79217c18bb55e8a4c3ea326ee94740937ae14eaffaed90ec9d69d47210e5c79998ec5309429e8239dcffe6308c` |
| TLSH | `T1D0F38C404C1DFA73DBC5E0FD4D580E14722B3CF51479D32A1E1292AEDC86A54AFE6BA2` |
| SSDEEP | `3072:7nW8JKOomScnkcAaZHbqtMn/NwbGlCf8LYNX/5bgkwrNsaCRl7w82:7lKOomznkq7q2ulf8sNhpMR2l7w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_6603f67d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6603f67d9e0947caa92a1614175dc125527eb6dc6ee4d5dfc0330ebd64bd2fea"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:15"
  condition:
    hash.sha256(0, filesize) == "6603f67d9e0947caa92a1614175dc125527eb6dc6ee4d5dfc0330ebd64bd2fea"
}
```

### Sample 15: `12029b1db51d389f`

| Field | Value |
|---|---|
| SHA-256 | `12029b1db51d389f109b6e78d4e666ee06d9332e9c9e80d942dc09f34ad71cb6` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-11-05 05:45:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b125bcf3a228997bc8ba3d90d6aa043a` |
| SHA-1 | `dd449d86deb2a4b22f5ac7af25301574b3af04a2` |
| SHA-256 | `12029b1db51d389f109b6e78d4e666ee06d9332e9c9e80d942dc09f34ad71cb6` |
| SHA3-384 | `57c1bb3539be3c2b2d0b40b3ee5861eedfdddd3a006812ffdb6311ab248b4be7a997ae7821326b2c81c635f59de51533` |
| TLSH | `T165044A00AB08097AC8F79CB0053F0778F7D56B8352D954251D29EA425771B736B8BEEB` |
| SSDEEP | `3072:x75qWr1ToqJ5/7fpqs+0OoyKBizM36P3hqQsYRabp7i0ESxQoR2:xMWr1ToqJ5/7fpHHyKBizM36PxqVUl+Y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_12029b1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12029b1db51d389f109b6e78d4e666ee06d9332e9c9e80d942dc09f34ad71cb6"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:12"
  condition:
    hash.sha256(0, filesize) == "12029b1db51d389f109b6e78d4e666ee06d9332e9c9e80d942dc09f34ad71cb6"
}
```

### Sample 16: `f8e09b989372403d`

| Field | Value |
|---|---|
| SHA-256 | `f8e09b989372403de2092b322070dc67b5e302faea267d2d251f652314247516` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-11-05 05:45:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ceb800ca0f4147ceef5ebd255dc0220b` |
| SHA-1 | `a360cfe168bf5805bd9c55d2439024db856bc97f` |
| SHA-256 | `f8e09b989372403de2092b322070dc67b5e302faea267d2d251f652314247516` |
| SHA3-384 | `95d1d20c152a2ef971cdc606b1ad4185cfe56948559bf00e0ad84496728aba72049ea14ae2d42d6b07626b8d62aace2f` |
| TLSH | `T1D7F3F7A6FE82D951C4D478BBEA1F81CC334303ACC3EE7402DD259B2565DF59A4A3AE44` |
| SSDEEP | `3072:AlMniBlvG1/B55+hXWMObOgg4oMIkJjmD1kRmdKts7:AlMEl+1/B55hxot8u1kRmdKts7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_f8e09b98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8e09b989372403de2092b322070dc67b5e302faea267d2d251f652314247516"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:10"
  condition:
    hash.sha256(0, filesize) == "f8e09b989372403de2092b322070dc67b5e302faea267d2d251f652314247516"
}
```

### Sample 17: `ca856cd80f9dcbaa`

| Field | Value |
|---|---|
| SHA-256 | `ca856cd80f9dcbaaddaeba08516b7bef12d3fd27150426be9e0fc677fa68a398` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-11-05 05:45:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9613ec24e39d287d639019511a96817` |
| SHA-1 | `3a11d1bef4d96a8184bb91ae2bdaebfea51da33f` |
| SHA-256 | `ca856cd80f9dcbaaddaeba08516b7bef12d3fd27150426be9e0fc677fa68a398` |
| SHA3-384 | `5ca1eb199aa45e256474d2bd343bc375b3f0dfecd11774007f666da8fdc9868a10b08fe6b3d8fffa3005604d513f0698` |
| TLSH | `T1A4F306A2BE82D951C4D428BFEA1F81C8334303ACC7EE7112DD159B35A5DF95A0E3AE45` |
| SSDEEP | `3072:AKfq5TniPuVZH8vdMb/hdPDvz/xpeD0zhux6+oXeNjVqqEJBdow7:AKi5TeaH8vdMvPfZp0chuYwNjVVEJBdb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_ca856cd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca856cd80f9dcbaaddaeba08516b7bef12d3fd27150426be9e0fc677fa68a398"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:07"
  condition:
    hash.sha256(0, filesize) == "ca856cd80f9dcbaaddaeba08516b7bef12d3fd27150426be9e0fc677fa68a398"
}
```

### Sample 18: `aff27ab2c42fcb41`

| Field | Value |
|---|---|
| SHA-256 | `aff27ab2c42fcb41685af982b5b4d29c638a2a465712dc72bb15068f281b5940` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-05 05:45:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8984d5ca2d99ff9fae928597a459d66` |
| SHA-1 | `b23bdbb6558da1e2de34a304b8472899fa485f08` |
| SHA-256 | `aff27ab2c42fcb41685af982b5b4d29c638a2a465712dc72bb15068f281b5940` |
| SHA3-384 | `df532e010a9a7d62458c53b5993775560684ea1a34a95d4b977e0a95a5db68fa53308651438abe99d8229616c700e3f3` |
| TLSH | `T18EE36B03B9F244FCC896C434876EE623EB747C4953217B9B27D47AA53E2AB503B5A350` |
| TELFHASH | `t12c3173406b4829a757696a434b4d6d3b19d360f3f99a7e89db84cfc0206ffd21749431` |
| SSDEEP | `3072:l9GCGueyzw33mSk6B0PaTzH+0tN+gv3RzlqhOvf:lgzu7imCBsSjtN+gvpsMv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_aff27ab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aff27ab2c42fcb41685af982b5b4d29c638a2a465712dc72bb15068f281b5940"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:04"
  condition:
    hash.sha256(0, filesize) == "aff27ab2c42fcb41685af982b5b4d29c638a2a465712dc72bb15068f281b5940"
}
```

### Sample 19: `8561ec7bffde3207`

| Field | Value |
|---|---|
| SHA-256 | `8561ec7bffde32073dc5edab14f4025009c4941a0683bad0eb33d72b37c9caa1` |
| Family label | `RemcosRAT` |
| File name | `Packing List, Commercial Invoice and Bill Of .js` |
| File type | `js` |
| First seen | `2026-11-05 05:30:13` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d99af2ada3ca3776d209448c0a12f33` |
| SHA-1 | `f79f3d8eb55a1aaa3d8718044a0e2a4c158dd3c0` |
| SHA-256 | `8561ec7bffde32073dc5edab14f4025009c4941a0683bad0eb33d72b37c9caa1` |
| SHA3-384 | `d75ea4414cd4fb945ba89f2a74d0d517dc5d0752913bfbbd60fe604f6cdfa45c2febb4d3bab284fa4d494d1b9f6ac016` |
| TLSH | `T14136E4522B4FB1327B21AB5C5676C939994A60C315D6DB3D31ACF218F61CC0BA35CBE2` |
| SSDEEP | `98304:nO00HvtCAWeGRCoFa5vUNky0fc4INJshTMiaFCLgrm08Wh+H9HNNUgyS9EtGLPII:mlsRdE5vU0GMlaFCkV8WmHbUg68LPIB2` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_019_8561ec7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8561ec7bffde32073dc5edab14f4025009c4941a0683bad0eb33d72b37c9caa1"
    family = "RemcosRAT"
    file_name = "Packing List, Commercial Invoice and Bill Of .js"
    file_type = "js"
    first_seen = "2026-11-05 05:30:13"
  condition:
    hash.sha256(0, filesize) == "8561ec7bffde32073dc5edab14f4025009c4941a0683bad0eb33d72b37c9caa1"
}
```

### Sample 20: `62a18370ac853198`

| Field | Value |
|---|---|
| SHA-256 | `62a18370ac853198827085fb01a17b56b9d74b13d0b37e9a37f70be1f8c3d616` |
| Family label | `Mirai` |
| File name | `bot-mips` |
| File type | `elf` |
| First seen | `2026-11-05 04:40:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9beb336f5b6cd0e08482a5aa02982dd` |
| SHA-1 | `4f7231be595240720980e436d2ba949a3f43bc88` |
| SHA-256 | `62a18370ac853198827085fb01a17b56b9d74b13d0b37e9a37f70be1f8c3d616` |
| SHA3-384 | `716bb172b382f59b45de15a450daf052a4cadd8de54a5c2066391a0c0787be53863210eb95c28318251968e3a2a34fb9` |
| TLSH | `T13223F12A0B6501EBCA8611B60B8956212FBB2FD5E541FD1A8814F4B7DC2E1BCB08B3C4` |
| SSDEEP | `768:zshmEUESH422l61oh3REtpc7xJemnMsJbh5vpSkcyl1JgGlzDppMgK1X:zGmE/kOt3Rsp4mZAbDvpL5vV8ZX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_62a18370
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62a18370ac853198827085fb01a17b56b9d74b13d0b37e9a37f70be1f8c3d616"
    family = "Mirai"
    file_name = "bot-mips"
    file_type = "elf"
    first_seen = "2026-11-05 04:40:03"
  condition:
    hash.sha256(0, filesize) == "62a18370ac853198827085fb01a17b56b9d74b13d0b37e9a37f70be1f8c3d616"
}
```

### Sample 21: `3f8bcc5070ae60b4`

| Field | Value |
|---|---|
| SHA-256 | `3f8bcc5070ae60b49d1dd6e804c2a6bcf24165541d8c35b27e646c83e673f36f` |
| Family label | `CoinMiner` |
| File name | `FleetComputeM2.exe` |
| File type | `exe` |
| First seen | `2026-11-05 03:16:23` |
| Reporter | `iamaachum` |
| Tags | `BzMiner, CoinMiner, dropped-by-RemusStealer, exe, mine2-apesniper-xyz, PearlFleet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7a41c5fc35b16f9720c970540102713` |
| SHA-1 | `c40a3e2a7db25667662cc58c3c70b5c502c8c3df` |
| SHA-256 | `3f8bcc5070ae60b49d1dd6e804c2a6bcf24165541d8c35b27e646c83e673f36f` |
| SHA3-384 | `ae4d766244db87925abcfe5ffc97980a4460a27152ad9aa6cb8c6557bf1cb5b8ae708e4852ca12775442a55340e2488f` |
| IMPHASH | `33a82f37223c06f45d6c0987c7b7927b` |
| TLSH | `T106B41F065E0BC8EDEBE2947460FAC4F492317D8C49E5908E2CD7B7E8917C06E2167D6B` |
| SSDEEP | `3072:1cE1ywc4D3izSERyrfhj11NwSKZYqF6pcARAWSWmurWmcZh+F+ScADcAx:1csyw1gkJj114ZYKsVWVZY` |
| ICON-DHASH | `b039f0d4d47139b0` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_021_3f8bcc50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f8bcc5070ae60b49d1dd6e804c2a6bcf24165541d8c35b27e646c83e673f36f"
    family = "CoinMiner"
    file_name = "FleetComputeM2.exe"
    file_type = "exe"
    first_seen = "2026-11-05 03:16:23"
  condition:
    hash.sha256(0, filesize) == "3f8bcc5070ae60b49d1dd6e804c2a6bcf24165541d8c35b27e646c83e673f36f"
}
```

### Sample 22: `35eb9408b68c3b07`

| Field | Value |
|---|---|
| SHA-256 | `35eb9408b68c3b07a4230db82ea75de1bc70e7f0c2c92250aa7d21a12fc88d53` |
| Family label | `VShell` |
| File name | `35eb9408b68c3b07a4230db82ea75de1bc70e7f0c2c92250aa7d21a12fc88d53.exe` |
| File type | `exe` |
| First seen | `2026-11-05 03:04:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cac56d375ca1c0c7bdf897f1d8b236f8` |
| SHA-1 | `1ebfdf41c736bc80fbc645e2dabc167dbbd64d1e` |
| SHA-256 | `35eb9408b68c3b07a4230db82ea75de1bc70e7f0c2c92250aa7d21a12fc88d53` |
| SHA3-384 | `89c80d36b4236d050623388a7e8878d9b06753ccf7ee075017655299f2105db973e8d34553a61b9d018b4a08f98acae7` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T14671B54160501AF2D98CE37F8487B895FD4FB248A2D80B0F4398D81A2F7607BB1D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6D46Bjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6D7Z++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_022_35eb9408
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35eb9408b68c3b07a4230db82ea75de1bc70e7f0c2c92250aa7d21a12fc88d53"
    family = "VShell"
    file_name = "35eb9408b68c3b07a4230db82ea75de1bc70e7f0c2c92250aa7d21a12fc88d53.exe"
    file_type = "exe"
    first_seen = "2026-11-05 03:04:54"
  condition:
    hash.sha256(0, filesize) == "35eb9408b68c3b07a4230db82ea75de1bc70e7f0c2c92250aa7d21a12fc88d53"
}
```

### Sample 23: `9478ccb9b54de308`

| Field | Value |
|---|---|
| SHA-256 | `9478ccb9b54de30851f10cb2e388edd672ef9d94c5f9b252a01126bafbdf4d4a` |
| Family label | `unknown` |
| File name | `eda1686d-c620-49a0-ab53-6b6659f6cad1.ps1` |
| File type | `ps1` |
| First seen | `2026-11-05 02:56:13` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `932411a1b7e67cc66ff6b8ba33ee1d59` |
| SHA-1 | `cbd90188e5bb2b0779b532f0239400250514bd1a` |
| SHA-256 | `9478ccb9b54de30851f10cb2e388edd672ef9d94c5f9b252a01126bafbdf4d4a` |
| SHA3-384 | `3330b2427710863baa94cc671e9f606665a7d5e02555f4f8f224dc8767a8725948f34727bb074dc89de6abc1b431b657` |
| TLSH | `T1E7A4412133C4B962924EDFB96D010C0BE3DDA079EFCFA84DABC9E6844A87574469DC71` |
| SSDEEP | `6144:GLTR9bSOF2zI8u1JVgfwGBrKtIBf/19C9mTP5EW5EEzbGKYFZ5KY0hYkqbGZbGjW:aZIohahYhNhwfefkfEeL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_9478ccb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9478ccb9b54de30851f10cb2e388edd672ef9d94c5f9b252a01126bafbdf4d4a"
    family = "unknown"
    file_name = "eda1686d-c620-49a0-ab53-6b6659f6cad1.ps1"
    file_type = "ps1"
    first_seen = "2026-11-05 02:56:13"
  condition:
    hash.sha256(0, filesize) == "9478ccb9b54de30851f10cb2e388edd672ef9d94c5f9b252a01126bafbdf4d4a"
}
```

### Sample 24: `08f36297e916e158`

| Field | Value |
|---|---|
| SHA-256 | `08f36297e916e15853dcd5c4728f2ad554eda6686e4342867f4653b982d260df` |
| Family label | `Arechclient2` |
| File name | `bbd224f8-8296-404b-ab7c-c93301380271.ps1` |
| File type | `ps1` |
| First seen | `2026-11-05 02:55:53` |
| Reporter | `iamaachum` |
| Tags | `62-238-87-60, Arechclient2, AsgardProtector, dropped-by-ACRStealer, ps1, SectopRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1af3efb0bfab4885d74dd372a84093f9` |
| SHA-1 | `f38a68b52e0a0763f0ebf72286b938d8729c15ce` |
| SHA-256 | `08f36297e916e15853dcd5c4728f2ad554eda6686e4342867f4653b982d260df` |
| SHA3-384 | `03922806b9a332385a482a847d7548a5477d4af8e4032436cf99742ab883e5170c0acd75ef59e33f791fcf1377be1a50` |
| TLSH | `T142A43E2133C4B862514EDFB96C510C0B93DDA06ADFCFA84DABCEE6844B87538469DCB5` |
| SSDEEP | `6144:Iw41H0nnOA/i7ZdDrjqmUHdgEaVN0k4w7OvfkK7Osa0D3K1p1q1E1p1q1KZ/AVSf:24f1G8VAVR` |

#### Technical Assessment

- The sample is tracked as `Arechclient2` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Arechclient2_024_08f36297
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08f36297e916e15853dcd5c4728f2ad554eda6686e4342867f4653b982d260df"
    family = "Arechclient2"
    file_name = "bbd224f8-8296-404b-ab7c-c93301380271.ps1"
    file_type = "ps1"
    first_seen = "2026-11-05 02:55:53"
  condition:
    hash.sha256(0, filesize) == "08f36297e916e15853dcd5c4728f2ad554eda6686e4342867f4653b982d260df"
}
```

### Sample 25: `b4a17536921c2bbc`

| Field | Value |
|---|---|
| SHA-256 | `b4a17536921c2bbcc395bcf97408b88b7827fb77e0b7831f2c0038f85a37594a` |
| Family label | `ACRStealer` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-11-05 02:41:14` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, tunnel-fairmoor-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87432f688e0c8ec7624257ea6915fc24` |
| SHA-1 | `f415c83c9a85b8146daccb23f7af6a9ede938929` |
| SHA-256 | `b4a17536921c2bbcc395bcf97408b88b7827fb77e0b7831f2c0038f85a37594a` |
| SHA3-384 | `4c89380f0c9956224791e53cd0f0f8cdf9874e6ef1010855e58c6f374a8a7d502547f9f8260ef79b065a1eafbbca1fa7` |
| TLSH | `T17A773352ACEB4F45C42E723ED4EF0F0BB981A70680A7920F53ACD15A1DF3A719B9164D` |
| SSDEEP | `786432:cZLrUxexc4dx2mYUEy1/gZxnJQUsN7u3vIlYYOAjUsMAHEkQHbgtklYYOX:MLnxjdMEEOUxGN7ig2YO0ZWH8k2YOX` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_025_b4a17536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4a17536921c2bbcc395bcf97408b88b7827fb77e0b7831f2c0038f85a37594a"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-05 02:41:14"
  condition:
    hash.sha256(0, filesize) == "b4a17536921c2bbcc395bcf97408b88b7827fb77e0b7831f2c0038f85a37594a"
}
```

### Sample 26: `55f7ef2c480e85fe`

| Field | Value |
|---|---|
| SHA-256 | `55f7ef2c480e85fed2b68ac0a6b0a081431cf92118ae0831a8a9275b1eca11e3` |
| Family label | `WARDENStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-11-05 02:40:13` |
| Reporter | `iamaachum` |
| Tags | `95-217-96-240, exe, signed, Stealc, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b7bf173a18b79d76b499e441a1cc884` |
| SHA-1 | `562094fac419503e9cdbaa8b439291531cf4c822` |
| SHA-256 | `55f7ef2c480e85fed2b68ac0a6b0a081431cf92118ae0831a8a9275b1eca11e3` |
| SHA3-384 | `3904ef7350a4c946c0d7576f2eb5e32d65917fb1fbf6082ac4a06434e2cc771febbc69146c66da2500411fe759df7879` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D0368D1BD891D67AE8A7E77DA9AB0141B6A6BC84B73136C32E507A702D733C05D78F04` |
| SSDEEP | `49152:shDcg58gNrVSiEvQVCeB385mUtLje45tPHn2U3l4DS59f4FXLVD:s2gbv8B7eUpQ` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_026_55f7ef2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55f7ef2c480e85fed2b68ac0a6b0a081431cf92118ae0831a8a9275b1eca11e3"
    family = "WARDENStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:40:13"
  condition:
    hash.sha256(0, filesize) == "55f7ef2c480e85fed2b68ac0a6b0a081431cf92118ae0831a8a9275b1eca11e3"
}
```

### Sample 27: `2e71fa8333960948`

| Field | Value |
|---|---|
| SHA-256 | `2e71fa8333960948544fbddbbfb84d6d429aa4accb27016e86b9c2c16a00f49a` |
| Family label | `ACRStealer` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-11-05 02:38:58` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, ipv4-larkfen-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4ce704b41b0be61f1eb662482da6ac5` |
| SHA-1 | `996b96443fe8d3c95fd91ca677ffed7527b77374` |
| SHA-256 | `2e71fa8333960948544fbddbbfb84d6d429aa4accb27016e86b9c2c16a00f49a` |
| SHA3-384 | `fde22be35387cf291bfbcf35f5a280730821672ee6953cc7ab5e4e2bcde512fc8fddb2b3a40d732f4580c9e3da405aa9` |
| TLSH | `T1BD273324F8663651EC0DDAB400F01DA803E6AD7612BB9BC42379750F8963E6E9F74D39` |
| SSDEEP | `393216:flw0higpRSzYnrms2X5P3UEBFtViEfnLiKOLr1j/F0frms2X5P3o8dQFGs9AAWB0:WRgpRSz/s4v36aBO/1j/Fds4v9dQFGkf` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_027_2e71fa83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e71fa8333960948544fbddbbfb84d6d429aa4accb27016e86b9c2c16a00f49a"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-05 02:38:58"
  condition:
    hash.sha256(0, filesize) == "2e71fa8333960948544fbddbbfb84d6d429aa4accb27016e86b9c2c16a00f49a"
}
```

### Sample 28: `f7237fdb6fb01955`

| Field | Value |
|---|---|
| SHA-256 | `f7237fdb6fb01955ed81c50b3b9d52169fd9dba03f03c14c6ee14f66a92bf34c` |
| Family label | `CNBackdoor` |
| File name | `Installer31854.exe` |
| File type | `exe` |
| First seen | `2026-11-05 02:35:13` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8616f2f02d18c394051a7f8b4e2a5c2` |
| SHA-1 | `99b886fb1faa1d63c2978c4704d48ed74afb5bcc` |
| SHA-256 | `f7237fdb6fb01955ed81c50b3b9d52169fd9dba03f03c14c6ee14f66a92bf34c` |
| SHA3-384 | `74afd464a1dc6bfe077850753e2493ec09b9e89ae869cf8be4157f1b43d15d1a70c1a4ba88419601f50bcffc52d58570` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T183F633915395769BEDF163337E88FCE64E0D4FEADB88B702DA231046507AB23D89448D` |
| SSDEEP | `393216:ocoVnT9bfCwtEbmTwDzyRRgonJGwL14Uc:oFVnBbfCbm9gonAW1g` |
| ICON-DHASH | `fe7ee6c292b292c6` |

#### Technical Assessment

- The sample is tracked as `CNBackdoor` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CNBackdoor_028_f7237fdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7237fdb6fb01955ed81c50b3b9d52169fd9dba03f03c14c6ee14f66a92bf34c"
    family = "CNBackdoor"
    file_name = "Installer31854.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:35:13"
  condition:
    hash.sha256(0, filesize) == "f7237fdb6fb01955ed81c50b3b9d52169fd9dba03f03c14c6ee14f66a92bf34c"
}
```

### Sample 29: `ecef5317df8b014e`

| Field | Value |
|---|---|
| SHA-256 | `ecef5317df8b014e1581d7a4e819c3290c846fac20a0423846f1081071c7304d` |
| Family label | `CNBackdoor` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-11-05 02:34:45` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d1f2aebaac881d9385db9886231863b` |
| SHA-1 | `ee47e8d35cde1a4e5982fe6106f9b40ba5495430` |
| SHA-256 | `ecef5317df8b014e1581d7a4e819c3290c846fac20a0423846f1081071c7304d` |
| SHA3-384 | `2c5b6d96e9ad5ffa3c17fbd35c65df070687f5ae5c189425be8838cec24a6e3c54e07f40fdaef13242f710e016e929f6` |
| TLSH | `T127F633905395759BEDF062333D88FCE64E0D4FEADB98B702FA271046527BB23C854589` |
| SSDEEP | `393216:ucoVnT9bfCwtEbmTwDzyRRgonJGwL14Uc:uFVnBbfCbm9gonAW1g` |

#### Technical Assessment

- The sample is tracked as `CNBackdoor` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CNBackdoor_029_ecef5317
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecef5317df8b014e1581d7a4e819c3290c846fac20a0423846f1081071c7304d"
    family = "CNBackdoor"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-11-05 02:34:45"
  condition:
    hash.sha256(0, filesize) == "ecef5317df8b014e1581d7a4e819c3290c846fac20a0423846f1081071c7304d"
}
```

### Sample 30: `b7b67b9bb1053173`

| Field | Value |
|---|---|
| SHA-256 | `b7b67b9bb10531738ad2b46cf7d342b8e326577bef5f3505adfc62ed1fc072fb` |
| Family label | `WARDENStealer` |
| File name | `Installer_L_X64_x86_2024.zip` |
| File type | `zip` |
| First seen | `2026-11-05 02:33:36` |
| Reporter | `iamaachum` |
| Tags | `HijackLoader, IDATLoader, WARDENStealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d3a3aa49f315d9a21e80a77b68f86a1` |
| SHA-1 | `4e0bc042befe71458a18d42ad1f337ef71ccb25a` |
| SHA-256 | `b7b67b9bb10531738ad2b46cf7d342b8e326577bef5f3505adfc62ed1fc072fb` |
| SHA3-384 | `0cb964dc27812752a760cb3e8979a3b3f3a39155b41921222998fb20062f9c0da29f29486545e60521af9c9388791797` |
| TLSH | `T149C73345FA5C528ED7A6ADF2A4C616ADD672C9074731E82F06A840912CD37F70F1EE0B` |
| SSDEEP | `1572864:w1kR7BDwQz7wlnI5WM9Jh2NM9Olqq+xg5Mh81aP/jxu2i:4cDDnPWM9Jh2e9Q5MaYPbxu3` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_030_b7b67b9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7b67b9bb10531738ad2b46cf7d342b8e326577bef5f3505adfc62ed1fc072fb"
    family = "WARDENStealer"
    file_name = "Installer_L_X64_x86_2024.zip"
    file_type = "zip"
    first_seen = "2026-11-05 02:33:36"
  condition:
    hash.sha256(0, filesize) == "b7b67b9bb10531738ad2b46cf7d342b8e326577bef5f3505adfc62ed1fc072fb"
}
```

### Sample 31: `c291358365226f5b`

| Field | Value |
|---|---|
| SHA-256 | `c291358365226f5b3e6910e8523cdec7af0a7ff01cfca7e92f2bd165235f679f` |
| Family label | `RemusStealer` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-11-05 02:30:30` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, wooocommerce-shopping` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e14537726fb814d4fad1b4394185760` |
| SHA-1 | `a63aeb80fafab2abc1616c3292c48116d220f814` |
| SHA-256 | `c291358365226f5b3e6910e8523cdec7af0a7ff01cfca7e92f2bd165235f679f` |
| SHA3-384 | `1f2e9e7e03833a34fa2167e5884d4c43057fa3a2a56b5bb33716d3f224cd80cf4cd9021f2c563f019239b5fa1a21108c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1FE363A13B8C285AAC49AE630CD7E52523AA4F84CAB3133E71E91BB741F727D19C78745` |
| SSDEEP | `49152:TOVYSLT3MB9GGefOoWIQ8sDIPWIeyu0oLTr1xbhi:TmYjNf3hi` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_031_c2913583
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c291358365226f5b3e6910e8523cdec7af0a7ff01cfca7e92f2bd165235f679f"
    family = "RemusStealer"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:30:30"
  condition:
    hash.sha256(0, filesize) == "c291358365226f5b3e6910e8523cdec7af0a7ff01cfca7e92f2bd165235f679f"
}
```

### Sample 32: `b06d0eda8ef44bf0`

| Field | Value |
|---|---|
| SHA-256 | `b06d0eda8ef44bf0846fd029d90541dbb18af17b845cbdbbf4f4003b3ff6dd62` |
| Family label | `WARDENStealer` |
| File name | `x86__setup_now.exe` |
| File type | `exe` |
| First seen | `2026-11-05 02:29:34` |
| Reporter | `iamaachum` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16026c2f3f0a2afe10394e37060921db` |
| SHA-1 | `8ad7c54d3b0d22ca4e4ad82c17c4fa33f2cccc55` |
| SHA-256 | `b06d0eda8ef44bf0846fd029d90541dbb18af17b845cbdbbf4f4003b3ff6dd62` |
| SHA3-384 | `009dd7a84f0d650da1c7f09a6681dd86c608adf6896f5042c7c3b00e03d967eb01d386ab749214571cacf3a43bc4430b` |
| IMPHASH | `e6788820a023ad16805a6730444ced6d` |
| TLSH | `T19BF63392FB859EF6F45986B9073181658A16BC0943D462DB82DC26C36F025C4CBFDF8B` |
| SSDEEP | `196608:4450EHIHQIqxKK6xT+KHsSrcjO245ubFrWR8DjqzTdUbnSdD6z4iQkcY8fiU58Nu:4yHcbGfq3QjegpWeDihUbrjQf/4Msu` |
| ICON-DHASH | `1068b27171b26810` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_032_b06d0eda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b06d0eda8ef44bf0846fd029d90541dbb18af17b845cbdbbf4f4003b3ff6dd62"
    family = "WARDENStealer"
    file_name = "x86__setup_now.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:29:34"
  condition:
    hash.sha256(0, filesize) == "b06d0eda8ef44bf0846fd029d90541dbb18af17b845cbdbbf4f4003b3ff6dd62"
}
```

### Sample 33: `579f433fff0ce878`

| Field | Value |
|---|---|
| SHA-256 | `579f433fff0ce8781b2c5d84ad082746e917f3ddc64f888945484c8366cd6065` |
| Family label | `RemusStealer` |
| File name | `𝗦𝗘𝗧𝗨𝗣.exe` |
| File type | `exe` |
| First seen | `2026-11-05 02:28:47` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afad529565343d1ca1d4d3b621af53b4` |
| SHA-1 | `3a65d11e057fa8bfb5d7ed12a1501aba7c16655e` |
| SHA-256 | `579f433fff0ce8781b2c5d84ad082746e917f3ddc64f888945484c8366cd6065` |
| SHA3-384 | `682d9b92acf7e47661a37fce6950233c41ff291617ed5152d96a92f0a9a8e1561796d1bdc4f7850316d070db46db245c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T105168D07EC9190A2D19AD635C4B652537B607C8CAF3273F31E80B9782F767C49AB6B44` |
| SSDEEP | `24576:GyMbaoIXlYekjl+nR7B9GDXfqLvM73nU4iGHPc+nlaxS6UUcwGKy5r8mG2NEoFrO:GyFoImLl+RlgDXSg3nhPnl5ycw3yipzp` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_033_579f433f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "579f433fff0ce8781b2c5d84ad082746e917f3ddc64f888945484c8366cd6065"
    family = "RemusStealer"
    file_name = "𝗦𝗘𝗧𝗨𝗣.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:28:47"
  condition:
    hash.sha256(0, filesize) == "579f433fff0ce8781b2c5d84ad082746e917f3ddc64f888945484c8366cd6065"
}
```

### Sample 34: `c2d8f64112b56ae8`

| Field | Value |
|---|---|
| SHA-256 | `c2d8f64112b56ae88513b140bdcd57c27d0a722e056ba6946918a0ef791a5877` |
| Family label | `RemusStealer` |
| File name | `Setup_Pro.exe` |
| File type | `exe` |
| First seen | `2026-11-05 02:28:23` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abc44476d676d08a51065e98d842c055` |
| SHA-1 | `90e50d76f83406acde99ae84724397e574990d57` |
| SHA-256 | `c2d8f64112b56ae88513b140bdcd57c27d0a722e056ba6946918a0ef791a5877` |
| SHA3-384 | `16b57e454cd6781a66abc23c034e5ede4a0bc82e1c98ad3c251422f3243c39223756c2ab58e07bdfbcfd0b893cc15235` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T149F55B035E9449BED099B238896B12567620BC48DB3173E72FA2BFB86F727C05E74744` |
| SSDEEP | `24576:gPBrgaYBcP46frtw0f1mYQ+TOrTbti53NH8qC7AFwSbIKmfGiD9mALSJfmM3:gPXYBc7rt7dmsOcH+AG1JRsH` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_034_c2d8f641
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2d8f64112b56ae88513b140bdcd57c27d0a722e056ba6946918a0ef791a5877"
    family = "RemusStealer"
    file_name = "Setup_Pro.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:28:23"
  condition:
    hash.sha256(0, filesize) == "c2d8f64112b56ae88513b140bdcd57c27d0a722e056ba6946918a0ef791a5877"
}
```

### Sample 35: `952c2ec45f737352`

| Field | Value |
|---|---|
| SHA-256 | `952c2ec45f737352610355e570269b25c9cf6e745ca35f7e2d094e20f31ee9b8` |
| Family label | `unknown` |
| File name | `ZA_Access_My_Department.msi` |
| File type | `msi` |
| First seen | `2026-11-05 02:16:21` |
| Reporter | `gleonard0912` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2670d14b39bb99bb45c331dcc9375f02` |
| SHA-1 | `5f23a1dde8283b9b67ced290c0d3a5e5bac0d40d` |
| SHA-256 | `952c2ec45f737352610355e570269b25c9cf6e745ca35f7e2d094e20f31ee9b8` |
| SHA3-384 | `ceefb53cc9f4439180e54b4e42243cd01f9be4b5ee8fadd47a0cb5324a56257fcbbac112d8bf66de5b0bbd85b4bb369d` |
| TLSH | `T1E677337A395B873DC2133CF91C56365CAA93BC84006E245AA17AF47C51B31F7E6B48E2` |
| SSDEEP | `786432:jUxtfSkxj0XSte8vHSDti6bdZudpqQ2wsLQiyMZDAFIDem:wj0iVvyY6bany9UiysD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_952c2ec4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "952c2ec45f737352610355e570269b25c9cf6e745ca35f7e2d094e20f31ee9b8"
    family = "unknown"
    file_name = "ZA_Access_My_Department.msi"
    file_type = "msi"
    first_seen = "2026-11-05 02:16:21"
  condition:
    hash.sha256(0, filesize) == "952c2ec45f737352610355e570269b25c9cf6e745ca35f7e2d094e20f31ee9b8"
}
```

### Sample 36: `d869738e3908aa88`

| Field | Value |
|---|---|
| SHA-256 | `d869738e3908aa88348bf51d97d1a60237f97c0b8850ee6304ff6572451a7f9c` |
| Family label | `LunexLoader` |
| File name | `d869738e3908aa88348bf51d97d1a60237f97c0b8850ee6304ff6572451a7f9c.exe` |
| File type | `exe` |
| First seen | `2026-11-05 02:14:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, LunexLoader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea67ea03946095691692c7e973668fca` |
| SHA-1 | `974f81910f95ac3456f255352fadaf2bf6df94e4` |
| SHA-256 | `d869738e3908aa88348bf51d97d1a60237f97c0b8850ee6304ff6572451a7f9c` |
| SHA3-384 | `dba84099a27f964ba3b71909a18e99f673d6fa7425d627457422648608f7b52ae50344e89ce43970dc748e9cbb1d1364` |
| IMPHASH | `fa08d1b61d1a8acc64f563085702c9ed` |
| TLSH | `T17D066D8682910871EEBBB03605433A124BB7513957A6F150DAE8D13A7CC36DEF6B6F70` |
| SSDEEP | `24576:3pCho/ZzZIc/UweljgtzZfSfCkUJN7EzDNXZhDUEKurh3lo6ODRpbVpyGO7uN3pi:5CheD/jsUVSOjAzDNXTKNldIwMbD+Q` |

#### Technical Assessment

- The sample is tracked as `LunexLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LunexLoader_036_d869738e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d869738e3908aa88348bf51d97d1a60237f97c0b8850ee6304ff6572451a7f9c"
    family = "LunexLoader"
    file_name = "d869738e3908aa88348bf51d97d1a60237f97c0b8850ee6304ff6572451a7f9c.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:14:36"
  condition:
    hash.sha256(0, filesize) == "d869738e3908aa88348bf51d97d1a60237f97c0b8850ee6304ff6572451a7f9c"
}
```

### Sample 37: `c2c956401bb50a69`

| Field | Value |
|---|---|
| SHA-256 | `c2c956401bb50a69e8cb0cbcd57a62ec0d6a5a245a050176e59ff5303574b850` |
| Family label | `ConnectWise` |
| File name | `c2c956401bb50a69e8cb0cbcd57a62ec0d6a5a245a050176e59ff5303574b850.exe` |
| File type | `exe` |
| First seen | `2026-11-05 02:09:32` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `870306c6786af979f664b374f8b37e0f` |
| SHA-1 | `3078f00e6729824a93a7b330669d9a4a3d71a6c3` |
| SHA-256 | `c2c956401bb50a69e8cb0cbcd57a62ec0d6a5a245a050176e59ff5303574b850` |
| SHA3-384 | `6befcca03022e4b10649740f133ac1b5c1047425655e44372eed87ad6a95c567f53d4304e1d962226dac43d884f5afc3` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1AD46E011B3D995B9D07F0638D87A52A9AA74BC044312CBFF57D4BD692D32BC04E323A6` |
| SSDEEP | `98304:Yps6efPi1Evc4/I7Od0jxRGsYh3eqQumU73tc:AfefPdk4/lGjxlYpeqQz` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_037_c2c95640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2c956401bb50a69e8cb0cbcd57a62ec0d6a5a245a050176e59ff5303574b850"
    family = "ConnectWise"
    file_name = "c2c956401bb50a69e8cb0cbcd57a62ec0d6a5a245a050176e59ff5303574b850.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:09:32"
  condition:
    hash.sha256(0, filesize) == "c2c956401bb50a69e8cb0cbcd57a62ec0d6a5a245a050176e59ff5303574b850"
}
```

### Sample 38: `8657c9c9326b795d`

| Field | Value |
|---|---|
| SHA-256 | `8657c9c9326b795d4d9c65f1f1e7a219154d59579cc40709c12fd1fb23a4adcb` |
| Family label | `DonutLoader` |
| File name | `8657c9c9326b795d4d9c65f1f1e7a219154d59579cc40709c12fd1fb23a4adcb.exe` |
| File type | `exe` |
| First seen | `2026-11-05 02:04:34` |
| Reporter | `Tuxxin` |
| Tags | `DonutLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f43b1931ee4ab425f53218d11336c6c0` |
| SHA-1 | `e3b52f8d655ec8ea5a4d424fae9d466e1e0427ba` |
| SHA-256 | `8657c9c9326b795d4d9c65f1f1e7a219154d59579cc40709c12fd1fb23a4adcb` |
| SHA3-384 | `6bc73d69e2f3e4b92ade61159975c1a637c20b33f224a8ed7ce4af8d59d4ddc3b64f88948d8256a406bd7c04be1287d6` |
| IMPHASH | `743c7b35d6407f4f84488dcf9264f61f` |
| TLSH | `T1E9B402C56EB50E83DA75277E81FBD3663A3CB7E48A1307132624A2311F13ED12DE525A` |
| SSDEEP | `12288:fQ+UP3su9AGOZNsZv+5qwtPiNhj0gjSj6d9Msb/BT:w/jyNs85qzNhj0Lj6MsTBT` |

#### Technical Assessment

- The sample is tracked as `DonutLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DonutLoader_038_8657c9c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8657c9c9326b795d4d9c65f1f1e7a219154d59579cc40709c12fd1fb23a4adcb"
    family = "DonutLoader"
    file_name = "8657c9c9326b795d4d9c65f1f1e7a219154d59579cc40709c12fd1fb23a4adcb.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:04:34"
  condition:
    hash.sha256(0, filesize) == "8657c9c9326b795d4d9c65f1f1e7a219154d59579cc40709c12fd1fb23a4adcb"
}
```

### Sample 39: `ad6c822ffbe04fdf`

| Field | Value |
|---|---|
| SHA-256 | `ad6c822ffbe04fdf75c3daa61e02f8754a253e37158ffc888f708bfb0dd9ddd4` |
| Family label | `Arechclient2` |
| File name | `QVKGSYNL(2).exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:39:53` |
| Reporter | `iamaachum` |
| Tags | `31-77-168-93, Arechclient2, dropped-by-CastleLoader, exe, HijackLoader, IDATLoader, SectopRAT, TAG-160` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dfd933d2bfde1c23e556f4a2d83613e` |
| SHA-1 | `b547898a155288a53fdd5043764cef65eac7aeb1` |
| SHA-256 | `ad6c822ffbe04fdf75c3daa61e02f8754a253e37158ffc888f708bfb0dd9ddd4` |
| SHA3-384 | `9d5c17b70cb87ef90708bad28e2afb27ab61dced8f81a7f02af18e3cc1825e329e6be755e16af0c28053b7dd42d45fb4` |
| IMPHASH | `e277f1464e7729ad9df5ec047611738a` |
| TLSH | `T13366233160A15027E6F10577FA2892307DACB7286B9188A9D3C4FD5D3FB85C1A7FB252` |
| SSDEEP | `196608:/LZ2IA/5k3RmD+I8Smti5cbI31/h2kSySC+m:F2IKVfeimbIl/h2bySI` |
| ICON-DHASH | `b2e1b496a6cada72` |

#### Technical Assessment

- The sample is tracked as `Arechclient2` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Arechclient2_039_ad6c822f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad6c822ffbe04fdf75c3daa61e02f8754a253e37158ffc888f708bfb0dd9ddd4"
    family = "Arechclient2"
    file_name = "QVKGSYNL(2).exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:39:53"
  condition:
    hash.sha256(0, filesize) == "ad6c822ffbe04fdf75c3daa61e02f8754a253e37158ffc888f708bfb0dd9ddd4"
}
```

### Sample 40: `5d7c6a2f5171346e`

| Field | Value |
|---|---|
| SHA-256 | `5d7c6a2f5171346e67236e9f4b11a873eae268fa9da744c8951474e168d44727` |
| Family label | `Arechclient2` |
| File name | `QVKGSYNL.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:38:40` |
| Reporter | `iamaachum` |
| Tags | `31-77-168-93, Arechclient2, dropped-by-CastleLoader, exe, HijackLoader, IDATLoader, SectopRAT, TAG-160` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99cfd282879a606bd253ae00348babe6` |
| SHA-1 | `f5c1e12f4fe77602bb0e38db620cd0e4f29737ca` |
| SHA-256 | `5d7c6a2f5171346e67236e9f4b11a873eae268fa9da744c8951474e168d44727` |
| SHA3-384 | `81febda11dbebc89838ea4d99e393356d3c6940b62c6fb9fa62bda086dad50aa9142703fbdd9382f606bb39a57789e65` |
| IMPHASH | `e277f1464e7729ad9df5ec047611738a` |
| TLSH | `T1F6A6333164615037E6F205B3FA2886303DADB7286741D8A9D3C4EE5D3EB89C1A7B7352` |
| SSDEEP | `196608:/LZ2IA/5k3RmD+I8Smti5cbI31/h2kSySC+lFvBSdmh6M9:F2IKVfeimbIl/h2bySzvh6M9` |
| ICON-DHASH | `b2e1b496a6cada72` |

#### Technical Assessment

- The sample is tracked as `Arechclient2` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Arechclient2_040_5d7c6a2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d7c6a2f5171346e67236e9f4b11a873eae268fa9da744c8951474e168d44727"
    family = "Arechclient2"
    file_name = "QVKGSYNL.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:38:40"
  condition:
    hash.sha256(0, filesize) == "5d7c6a2f5171346e67236e9f4b11a873eae268fa9da744c8951474e168d44727"
}
```

### Sample 41: `fcd5efaa02928c1d`

| Field | Value |
|---|---|
| SHA-256 | `fcd5efaa02928c1d90172d17e7c8b46115546aa25338b708c6472488006f64ea` |
| Family label | `Arechclient2` |
| File name | `NexusSoftware.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:35:01` |
| Reporter | `iamaachum` |
| Tags | `31-77-168-93, 85-120-253-85, aafesorder-com, Arechclient2, CastleLoader, exe, NetSupport, SectopRAT, TAG-160, thelkfklef-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fbe9bdf299720f9574e5d0b585d4d642` |
| SHA-1 | `5121c0814867c4e86f4f350faaf6461dcfdb101d` |
| SHA-256 | `fcd5efaa02928c1d90172d17e7c8b46115546aa25338b708c6472488006f64ea` |
| SHA3-384 | `94352aee1471d2b16efe736c388dec2defb6b303aee2ffde924f1cdf0ac889e36f1ef778e8a86365041110f834669475` |
| IMPHASH | `46ce5c12b293febbeb513b196aa7f843` |
| TLSH | `T11797336AF32B496FF04BE77C0C154A30DD69CDF8E4ED19295224F8263B3710F9926689` |
| SSDEEP | `786432:3fn9MtkGFTMBGpJCroIF8bjG1XqKyA/jPoVkn6pbBd06oZ6W+A7ykq5VU6x0C5I:3vKuGFNpsdF8vG1XqKyGoVk6RBnC6W7n` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `Arechclient2` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Arechclient2_041_fcd5efaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcd5efaa02928c1d90172d17e7c8b46115546aa25338b708c6472488006f64ea"
    family = "Arechclient2"
    file_name = "NexusSoftware.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:35:01"
  condition:
    hash.sha256(0, filesize) == "fcd5efaa02928c1d90172d17e7c8b46115546aa25338b708c6472488006f64ea"
}
```

### Sample 42: `a1f020b9708cb37c`

| Field | Value |
|---|---|
| SHA-256 | `a1f020b9708cb37c8e084e24dacc11f5bd42ef4ffdd25724ed9057dfb8879f54` |
| Family label | `Arechclient2` |
| File name | `Broker-Carrier Agreement.vbs` |
| File type | `vbs` |
| First seen | `2026-11-05 01:33:42` |
| Reporter | `iamaachum` |
| Tags | `31-77-168-93, 85-120-253-85, aafesorder-com, Arechclient2, CastleLoader, NetSupport, SectopRAT, TAG-160, thelkfklef-com, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b3773bbe0c7168971d75f0b067cd67a` |
| SHA-1 | `5e64db6fcc0ac6a6f4ebe81f7e80d3f6af84990e` |
| SHA-256 | `a1f020b9708cb37c8e084e24dacc11f5bd42ef4ffdd25724ed9057dfb8879f54` |
| SHA3-384 | `98cf1830a46d3aaa1a04985030d4194b39d93f0dc1aff1b42b16134de4f7b36f487d0a793705a61a900b9cf3d5122301` |
| TLSH | `T176E2D86154F7F62403B2DE684F0B8812FA21573B81987B5E7B6EC06216385CD9CAD4BF` |
| SSDEEP | `384:6GN4dRUHswIx8nn3mdoQ3g3rFNLuCB24VHINohtylW6IqQjA/6CGgs1JXEiRvFKI:fIx83gozDZIkt0IqwX1GsKul4VY1f` |

#### Technical Assessment

- The sample is tracked as `Arechclient2` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Arechclient2_042_a1f020b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1f020b9708cb37c8e084e24dacc11f5bd42ef4ffdd25724ed9057dfb8879f54"
    family = "Arechclient2"
    file_name = "Broker-Carrier Agreement.vbs"
    file_type = "vbs"
    first_seen = "2026-11-05 01:33:42"
  condition:
    hash.sha256(0, filesize) == "a1f020b9708cb37c8e084e24dacc11f5bd42ef4ffdd25724ed9057dfb8879f54"
}
```

### Sample 43: `3fc100302aaf8d3b`

| Field | Value |
|---|---|
| SHA-256 | `3fc100302aaf8d3bf3bf5562454ba01c42dc789bb57435774e8c10c4db25bed8` |
| Family label | `unknown` |
| File name | `media_player.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:30:17` |
| Reporter | `NotAlexei` |
| Tags | `dead-drop, dotnet, downloader, dropper, exe, gist, loader, NativeAOT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70e9ccdecf827db59041da1ea02ed091` |
| SHA-1 | `8061c45047a57be532d0997c16cbcbaae52a1472` |
| SHA-256 | `3fc100302aaf8d3bf3bf5562454ba01c42dc789bb57435774e8c10c4db25bed8` |
| SHA3-384 | `e9fe57026163ecf2752df3964ce0b6ba5d9e2bb3681b49a44b04b313bab8df43504a04726a3a33081bb24682c861f782` |
| IMPHASH | `c3dc3193ad9ea6943d4ce47c03c1d039` |
| TLSH | `T102B68D05A3D40AF5D126D234CAA6D732EA71B8515735C74F166AE30A2F33A809E7FB31` |
| SSDEEP | `98304:ZTr5SB8QCfL4k6zLQKmt4dNs5syx1N3uF:ZBSB8H4k6zLQKuQ65sybN+F` |
| ICON-DHASH | `e88e3b73733b8ee8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_3fc10030
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fc100302aaf8d3bf3bf5562454ba01c42dc789bb57435774e8c10c4db25bed8"
    family = "unknown"
    file_name = "media_player.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:30:17"
  condition:
    hash.sha256(0, filesize) == "3fc100302aaf8d3bf3bf5562454ba01c42dc789bb57435774e8c10c4db25bed8"
}
```

### Sample 44: `fe005e64780077d6`

| Field | Value |
|---|---|
| SHA-256 | `fe005e64780077d6a34da8067819535f6c9e9d77e27efe70bb783c5d6b444519` |
| Family label | `unknown` |
| File name | `main2_crypted.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:28:12` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-Stealc, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a4b0184796db1f4388623bb4b350d68` |
| SHA-1 | `fc29b743151864d9cefa4b24168382c5e3f17239` |
| SHA-256 | `fe005e64780077d6a34da8067819535f6c9e9d77e27efe70bb783c5d6b444519` |
| SHA3-384 | `595740ee4509761f874fe4a8f6e77d3341d7d6117c5458f1b2a20624eb69cee06948847903f323bdd059b07b2eac6cf1` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T14F56E04BECE119E6C0AAA2714967A1867F71BC051F3123D72EA0B7382FB2BD05D79744` |
| SSDEEP | `98304:mLSzYN+gaU/3DG9xGYe58mA1Spln+wCQrmpQFcodCRkd0y9dWND:mLB9zG9herGYn+G2QAKC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_fe005e64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe005e64780077d6a34da8067819535f6c9e9d77e27efe70bb783c5d6b444519"
    family = "unknown"
    file_name = "main2_crypted.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:28:12"
  condition:
    hash.sha256(0, filesize) == "fe005e64780077d6a34da8067819535f6c9e9d77e27efe70bb783c5d6b444519"
}
```

### Sample 45: `ead0b4114887f8b7`

| Field | Value |
|---|---|
| SHA-256 | `ead0b4114887f8b79a888336e1cd67b7f99e5aa5f46cf681bd5d7f88d9022415` |
| Family label | `unknown` |
| File name | `main2_crypted.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:27:49` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-Stealc, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5d57ceccb30d91d928fb845bbec1b2b` |
| SHA-1 | `fbdbb7245b464db2f86078ce30ab2dfcac04e23b` |
| SHA-256 | `ead0b4114887f8b79a888336e1cd67b7f99e5aa5f46cf681bd5d7f88d9022415` |
| SHA3-384 | `cfbbef48ddd14eed3cb9d0de73733f500a6ca61dca0f56c93906eac044e644d0ac7f877031f115f2afc241a57fd87925` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T10E56E00BEDE108F6C0AAA2718967A1457B71BC451F3123D72EA0B7782FB2BE05D75B14` |
| SSDEEP | `98304:PNmxR4qK4sHxWjgpIyUp8R1eF7/EXHzBB8AWEwM3/PMOxg1LIY9:PNp+sRW0SLp8fVDcwoOCIO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_ead0b411
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ead0b4114887f8b79a888336e1cd67b7f99e5aa5f46cf681bd5d7f88d9022415"
    family = "unknown"
    file_name = "main2_crypted.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:27:49"
  condition:
    hash.sha256(0, filesize) == "ead0b4114887f8b79a888336e1cd67b7f99e5aa5f46cf681bd5d7f88d9022415"
}
```

### Sample 46: `a3a6c802f50a8da1`

| Field | Value |
|---|---|
| SHA-256 | `a3a6c802f50a8da181ef46f97c9fd05187aff416c46598351fbd30b254f37d74` |
| Family label | `unknown` |
| File name | `dropper.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:27:05` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-Stealc, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1ca962f53b3aaf3411c720bb3353bad` |
| SHA-1 | `0d06d885834e921d5f82d9a65e97c82984785c7e` |
| SHA-256 | `a3a6c802f50a8da181ef46f97c9fd05187aff416c46598351fbd30b254f37d74` |
| SHA3-384 | `43f14a58f13fb9babd8fb1850b26d1ac71e069402e97fa7f3d75c2e2d0ccf41f9e965f66468835d41cd8ce3117b22596` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1940206057BE48731D57A8F38DCB373006678B3469C67DA5E6D99520F2C7331445A2BB2` |
| SSDEEP | `96:2gnE8B7nDn9iDBkWqdb/LdIq3U/pYIbRh3+D1R8wF3+bsPr7nazNt:2X8eSWqVdIq3spYIbRh3+BR8A3+bsvc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_a3a6c802
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3a6c802f50a8da181ef46f97c9fd05187aff416c46598351fbd30b254f37d74"
    family = "unknown"
    file_name = "dropper.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:27:05"
  condition:
    hash.sha256(0, filesize) == "a3a6c802f50a8da181ef46f97c9fd05187aff416c46598351fbd30b254f37d74"
}
```

### Sample 47: `7ffc9fc2fa198bd1`

| Field | Value |
|---|---|
| SHA-256 | `7ffc9fc2fa198bd14515f90b561d413317f732ddac5a793ba772f490e9992522` |
| Family label | `SalatStealer` |
| File name | `e8b5e1d4d2669aab.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:26:51` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f55776bc8ef25b15c25f6288f9bde5eb` |
| SHA-1 | `00bf9882d15d196e0f4f28612d15790c62ef8a79` |
| SHA-256 | `7ffc9fc2fa198bd14515f90b561d413317f732ddac5a793ba772f490e9992522` |
| SHA3-384 | `e5d286da01fa1213771d22a863c39481c1ebeee6a1504826f9a720b8d910675cffe449cbd48918905537778da5fc6111` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T105C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+j:yBkKr5rszpNDy+j` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_047_7ffc9fc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ffc9fc2fa198bd14515f90b561d413317f732ddac5a793ba772f490e9992522"
    family = "SalatStealer"
    file_name = "e8b5e1d4d2669aab.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:51"
  condition:
    hash.sha256(0, filesize) == "7ffc9fc2fa198bd14515f90b561d413317f732ddac5a793ba772f490e9992522"
}
```

### Sample 48: `a7517036b9a82e11`

| Field | Value |
|---|---|
| SHA-256 | `a7517036b9a82e11861ed4f60eaa696c83cf39d2e60d9a0623eef40b8097cb99` |
| Family label | `SalatStealer` |
| File name | `8a6ad36ce9125cd4.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:26:46` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3caad99dfb897ad1ac0679b15c4b9f50` |
| SHA-1 | `30096909cc698b437cc06ccb5ffdfbc7cd01720d` |
| SHA-256 | `a7517036b9a82e11861ed4f60eaa696c83cf39d2e60d9a0623eef40b8097cb99` |
| SHA3-384 | `4018afc1981dd04aabcb6000e3819e46b953e79008776af7412ba4524dff886a9fdbc477d7aba9447972dc9a62c58055` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1D7C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+y:yBkKr5rszpNDy+y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_048_a7517036
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7517036b9a82e11861ed4f60eaa696c83cf39d2e60d9a0623eef40b8097cb99"
    family = "SalatStealer"
    file_name = "8a6ad36ce9125cd4.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:46"
  condition:
    hash.sha256(0, filesize) == "a7517036b9a82e11861ed4f60eaa696c83cf39d2e60d9a0623eef40b8097cb99"
}
```

### Sample 49: `fb0f82cf43508b91`

| Field | Value |
|---|---|
| SHA-256 | `fb0f82cf43508b9127a7754907ff2015e35e81f2c245220cdd4d1d55c0f203f6` |
| Family label | `SalatStealer` |
| File name | `a993513992e84b87.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:26:41` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03d418aa24e399b91b0201cbd2dfac74` |
| SHA-1 | `2528aa86ede637bedd36fde73f2d45d434f25ec3` |
| SHA-256 | `fb0f82cf43508b9127a7754907ff2015e35e81f2c245220cdd4d1d55c0f203f6` |
| SHA3-384 | `b4bfb1d7d7094f433ea9c5843981ebfb873231225a16dbb8ff61ba28de7164e907613ea6a7d8e27e1d4e806ca70e5bad` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1D5C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+d:yBkKr5rszpNDy+d` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_049_fb0f82cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb0f82cf43508b9127a7754907ff2015e35e81f2c245220cdd4d1d55c0f203f6"
    family = "SalatStealer"
    file_name = "a993513992e84b87.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:41"
  condition:
    hash.sha256(0, filesize) == "fb0f82cf43508b9127a7754907ff2015e35e81f2c245220cdd4d1d55c0f203f6"
}
```

### Sample 50: `c5872379a4e0ef3d`

| Field | Value |
|---|---|
| SHA-256 | `c5872379a4e0ef3d9b8f891cf1a02dc822cbc36514058b91da13405455d2d9a1` |
| Family label | `SalatStealer` |
| File name | `6426415bdbe96a25.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:26:35` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a50fcd68038385032a2f7d1596ce27cf` |
| SHA-1 | `e86c0de77077098f063cd8b9fe52dab3efe4a13e` |
| SHA-256 | `c5872379a4e0ef3d9b8f891cf1a02dc822cbc36514058b91da13405455d2d9a1` |
| SHA3-384 | `26647c9385b735a6fcd70fcaf6c0b0309d0216259d84f34b910f83589370f7f7c9046667c4f7c49679137f481ea05d04` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T102C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+x:yBkKr5rszpNDy+x` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_050_c5872379
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5872379a4e0ef3d9b8f891cf1a02dc822cbc36514058b91da13405455d2d9a1"
    family = "SalatStealer"
    file_name = "6426415bdbe96a25.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:35"
  condition:
    hash.sha256(0, filesize) == "c5872379a4e0ef3d9b8f891cf1a02dc822cbc36514058b91da13405455d2d9a1"
}
```

### Sample 51: `65f98ebab0f692cf`

| Field | Value |
|---|---|
| SHA-256 | `65f98ebab0f692cf186f0336377d079fbc0a4b8335fb7aea8e40e9918ea5b1ef` |
| Family label | `SalatStealer` |
| File name | `879a3ff0164cc29a.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:26:28` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0b771e5fefcc020b593b3dea5bd37d7` |
| SHA-1 | `d4e0f4e5061cdeb2441b5b2ed1899a5a94b0ca14` |
| SHA-256 | `65f98ebab0f692cf186f0336377d079fbc0a4b8335fb7aea8e40e9918ea5b1ef` |
| SHA3-384 | `434118fd2340587b1cb128bc06938bb5ab93aa27eb4f6fd2917738f261692b3b206268419c91cd507e0cb1ddd482990a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T18AC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+L:yBkKr5rszpNDy+L` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_051_65f98eba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65f98ebab0f692cf186f0336377d079fbc0a4b8335fb7aea8e40e9918ea5b1ef"
    family = "SalatStealer"
    file_name = "879a3ff0164cc29a.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:28"
  condition:
    hash.sha256(0, filesize) == "65f98ebab0f692cf186f0336377d079fbc0a4b8335fb7aea8e40e9918ea5b1ef"
}
```

### Sample 52: `94ec0b96dfb8defe`

| Field | Value |
|---|---|
| SHA-256 | `94ec0b96dfb8defe58493f68aa448d62d7fc88b532fc34daaf3010d4b4ab1a6e` |
| Family label | `SalatStealer` |
| File name | `4333e8592959d413.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:26:23` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff0de4d7a87410db12b216ad3c728a9a` |
| SHA-1 | `c4e77415e929efa15e76a52d5e22afffd5cbac01` |
| SHA-256 | `94ec0b96dfb8defe58493f68aa448d62d7fc88b532fc34daaf3010d4b4ab1a6e` |
| SHA3-384 | `3a8a8ac4f4e9936d6c4c689d17941b9d0f36dd5c0be90a5e5ca5c5b30dbe11b845167ee13056ec034bd8c6471293dd78` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E4C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+H:yBkKr5rszpNDy+H` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_052_94ec0b96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94ec0b96dfb8defe58493f68aa448d62d7fc88b532fc34daaf3010d4b4ab1a6e"
    family = "SalatStealer"
    file_name = "4333e8592959d413.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:23"
  condition:
    hash.sha256(0, filesize) == "94ec0b96dfb8defe58493f68aa448d62d7fc88b532fc34daaf3010d4b4ab1a6e"
}
```

### Sample 53: `e8b5e1d4d2669aab`

| Field | Value |
|---|---|
| SHA-256 | `e8b5e1d4d2669aabc7cacb497b98dd2181efe0d241bbf0b94625c447a058c7a0` |
| Family label | `SalatStealer` |
| File name | `e8b5e1d4d2669aab.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:59` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83e88cbb12ef6166b50b19aed18c2a2f` |
| SHA-1 | `8f2dc8ecf6c46ab0ddb9ab7c26cf37146b42f8bd` |
| SHA-256 | `e8b5e1d4d2669aabc7cacb497b98dd2181efe0d241bbf0b94625c447a058c7a0` |
| SHA3-384 | `6d6fe484f0343353c4642058bcb758bd8e6661bc37b40ba303a838e8d05a51bb93d7c13dc5ab1b5895664dc45010712a` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T13FF5335BF1AB4BB3F7D9A931560FC66454B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ov:iJiafuIO7rhWEES4Q` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_053_e8b5e1d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8b5e1d4d2669aabc7cacb497b98dd2181efe0d241bbf0b94625c447a058c7a0"
    family = "SalatStealer"
    file_name = "e8b5e1d4d2669aab.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:59"
  condition:
    hash.sha256(0, filesize) == "e8b5e1d4d2669aabc7cacb497b98dd2181efe0d241bbf0b94625c447a058c7a0"
}
```

### Sample 54: `8a6ad36ce9125cd4`

| Field | Value |
|---|---|
| SHA-256 | `8a6ad36ce9125cd4b6f686b57d80b0bd4de59b1bfd38a7de226ae77fdc0dc9d3` |
| Family label | `SalatStealer` |
| File name | `8a6ad36ce9125cd4.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:52` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54fe26511f4e8325585a4af942b9dccf` |
| SHA-1 | `78ed43dc0e5575a2ded3f5f1605efc496cecda26` |
| SHA-256 | `8a6ad36ce9125cd4b6f686b57d80b0bd4de59b1bfd38a7de226ae77fdc0dc9d3` |
| SHA3-384 | `98917625b41ba5302e8dc09c3f20d19ccc01fc70c4aea4196c7f4a0d75bc11532965fe5bbf89ab1e13fa4bd860fbfc9d` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T135F5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OG:iJiafuIO7rhWEES4X` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_054_8a6ad36c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a6ad36ce9125cd4b6f686b57d80b0bd4de59b1bfd38a7de226ae77fdc0dc9d3"
    family = "SalatStealer"
    file_name = "8a6ad36ce9125cd4.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:52"
  condition:
    hash.sha256(0, filesize) == "8a6ad36ce9125cd4b6f686b57d80b0bd4de59b1bfd38a7de226ae77fdc0dc9d3"
}
```

### Sample 55: `a993513992e84b87`

| Field | Value |
|---|---|
| SHA-256 | `a993513992e84b8784c20634e98a39c2aaf19000f17d3e051172a7770c2372fb` |
| Family label | `SalatStealer` |
| File name | `a993513992e84b87.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:43` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3754712f50608fcd1b13019c4389fdf` |
| SHA-1 | `8cfca3f07557abf15f14da9f074576e58f494c56` |
| SHA-256 | `a993513992e84b8784c20634e98a39c2aaf19000f17d3e051172a7770c2372fb` |
| SHA3-384 | `54292c5000493552c981e5cb3fe90303a5eeb95820fd46b6e6ec235cca3c0af25c3b723e46f17ef4e9cf47a5a4e970f6` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C0F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OZ:iJiafuIO7rhWEES48` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_055_a9935139
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a993513992e84b8784c20634e98a39c2aaf19000f17d3e051172a7770c2372fb"
    family = "SalatStealer"
    file_name = "a993513992e84b87.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:43"
  condition:
    hash.sha256(0, filesize) == "a993513992e84b8784c20634e98a39c2aaf19000f17d3e051172a7770c2372fb"
}
```

### Sample 56: `4ef4d1bec9bc9d18`

| Field | Value |
|---|---|
| SHA-256 | `4ef4d1bec9bc9d189c283e2bf69038016981e259de5e839edb470d7b49decf3b` |
| Family label | `SalatStealer` |
| File name | `69e90c26d71023ac.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:43` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58e5845d73c2254350259985f72460a9` |
| SHA-1 | `8776553da070d27ed208162750d3ffb97473157f` |
| SHA-256 | `4ef4d1bec9bc9d189c283e2bf69038016981e259de5e839edb470d7b49decf3b` |
| SHA3-384 | `38dc159eb106b447d7d42b92f3ed187e44d1a1584efd52b1b8f4ae7270798fa014d47818c036c75eb7a5b4654cdfdcbe` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F1C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+e:yBkKr5rszpNDy+e` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_056_4ef4d1be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ef4d1bec9bc9d189c283e2bf69038016981e259de5e839edb470d7b49decf3b"
    family = "SalatStealer"
    file_name = "69e90c26d71023ac.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:43"
  condition:
    hash.sha256(0, filesize) == "4ef4d1bec9bc9d189c283e2bf69038016981e259de5e839edb470d7b49decf3b"
}
```

### Sample 57: `0958b64b1b8cdb3c`

| Field | Value |
|---|---|
| SHA-256 | `0958b64b1b8cdb3c4bc414a5d602fb3ec68c5f21b3417d5793e481d74850bcc6` |
| Family label | `SalatStealer` |
| File name | `e9c117cb31d3c0f3.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9e1c01a8135754a95bfe4a14c6342eb` |
| SHA-1 | `7169d0f7959a09d46721e478d75d03347636cba2` |
| SHA-256 | `0958b64b1b8cdb3c4bc414a5d602fb3ec68c5f21b3417d5793e481d74850bcc6` |
| SHA3-384 | `9fba32f1bfd01abeb24cded100b21f70ae20d2cd08aeef30c262c7ad99af6644d3832dbbcb912cfa6bd409079ad984d6` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T11BC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+n:yBkKr5rszpNDy+n` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_057_0958b64b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0958b64b1b8cdb3c4bc414a5d602fb3ec68c5f21b3417d5793e481d74850bcc6"
    family = "SalatStealer"
    file_name = "e9c117cb31d3c0f3.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:38"
  condition:
    hash.sha256(0, filesize) == "0958b64b1b8cdb3c4bc414a5d602fb3ec68c5f21b3417d5793e481d74850bcc6"
}
```

### Sample 58: `6426415bdbe96a25`

| Field | Value |
|---|---|
| SHA-256 | `6426415bdbe96a251d2abd46285bf27e751477f2e6da35dd777f5b735e70e37d` |
| Family label | `SalatStealer` |
| File name | `6426415bdbe96a25.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63ab39f1cd1141688eb154987b3bcc8e` |
| SHA-1 | `6c1769e7e3689e004db87e44fb44936c10a8df1a` |
| SHA-256 | `6426415bdbe96a251d2abd46285bf27e751477f2e6da35dd777f5b735e70e37d` |
| SHA3-384 | `90d25b6097228d6181e8aef466341956648815bd4413037b964abd93d23ef40a1510cc2612d1a708c78dca25cc17e7fa` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T15EF5335BF1AB47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O9:iJiafuIO7rhWEES4y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_058_6426415b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6426415bdbe96a251d2abd46285bf27e751477f2e6da35dd777f5b735e70e37d"
    family = "SalatStealer"
    file_name = "6426415bdbe96a25.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:35"
  condition:
    hash.sha256(0, filesize) == "6426415bdbe96a251d2abd46285bf27e751477f2e6da35dd777f5b735e70e37d"
}
```

### Sample 59: `b76fe2d549292ed0`

| Field | Value |
|---|---|
| SHA-256 | `b76fe2d549292ed02ffb467e7c82e8405f5391dbda7a28ee0ba4ea03d785117e` |
| Family label | `CoinMiner` |
| File name | `pyv6.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:28` |
| Reporter | `iamaachum` |
| Tags | `cloudflare-gd, CoinMiner, CorvusMiner, dropped-by-WARDENStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f604b9ba5801485b0e327ce04f5598fb` |
| SHA-1 | `6db5de93a388911926d88bf1c07a42e4b1b7af86` |
| SHA-256 | `b76fe2d549292ed02ffb467e7c82e8405f5391dbda7a28ee0ba4ea03d785117e` |
| SHA3-384 | `0a1533dd07b3d5260a351bcfc366e9f67d26f12cd784e131c3ceb3602e05681e3f3b9b74835967ffa63a94afddb228cd` |
| IMPHASH | `7efdfa8c94589edaffd3bd5d14090af4` |
| TLSH | `T1D366DF47EC9219F6C0AAE231897698527B70BC481F3127DB2BA0B6742F777D09C79724` |
| SSDEEP | `98304:DTS0fmNDPKgM79Mkk8hwY549Hvbd9WFOjK5RC3/7T1LMLACXKzR:6tlKgM7qvuQHvjWFSMw/X1LM8BR` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_059_b76fe2d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b76fe2d549292ed02ffb467e7c82e8405f5391dbda7a28ee0ba4ea03d785117e"
    family = "CoinMiner"
    file_name = "pyv6.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:28"
  condition:
    hash.sha256(0, filesize) == "b76fe2d549292ed02ffb467e7c82e8405f5391dbda7a28ee0ba4ea03d785117e"
}
```

### Sample 60: `879a3ff0164cc29a`

| Field | Value |
|---|---|
| SHA-256 | `879a3ff0164cc29a1c9a3d218c5bb5881d380a92d965cad4b16658aa9ca56373` |
| Family label | `SalatStealer` |
| File name | `879a3ff0164cc29a.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:27` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d67fc597be2ad0c57559319649702d9` |
| SHA-1 | `de0996cd0a9dca4bd2d3d96df67e000430b24d97` |
| SHA-256 | `879a3ff0164cc29a1c9a3d218c5bb5881d380a92d965cad4b16658aa9ca56373` |
| SHA3-384 | `94f0a5790f6108ce72142769d37520d3d6a11a40331da9c4208cc6281550da86d88e147dc180662d64e30367db5da123` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T18CF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ov:iJiafuIO7rhWEES48` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_060_879a3ff0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "879a3ff0164cc29a1c9a3d218c5bb5881d380a92d965cad4b16658aa9ca56373"
    family = "SalatStealer"
    file_name = "879a3ff0164cc29a.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:27"
  condition:
    hash.sha256(0, filesize) == "879a3ff0164cc29a1c9a3d218c5bb5881d380a92d965cad4b16658aa9ca56373"
}
```

### Sample 61: `4333e8592959d413`

| Field | Value |
|---|---|
| SHA-256 | `4333e8592959d413729fba335f1065fad42edc41d3f2c1c458d2b87f51d52908` |
| Family label | `SalatStealer` |
| File name | `4333e8592959d413.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:19` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `399e935ce6284cfa8634e12aae0aa034` |
| SHA-1 | `f57cbea43a1dd8a589e54a588ba8503df8fc441a` |
| SHA-256 | `4333e8592959d413729fba335f1065fad42edc41d3f2c1c458d2b87f51d52908` |
| SHA3-384 | `36b2a31f8b8ec2b77bcae337d996b9a218ddf4ae3fbd71e957ee605eef484834273bbc8ad6a4358088442ca4902b28dc` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1D8F5335BF1AF47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OL:iJiafuIO7rhWEES4a` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_061_4333e859
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4333e8592959d413729fba335f1065fad42edc41d3f2c1c458d2b87f51d52908"
    family = "SalatStealer"
    file_name = "4333e8592959d413.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:19"
  condition:
    hash.sha256(0, filesize) == "4333e8592959d413729fba335f1065fad42edc41d3f2c1c458d2b87f51d52908"
}
```

### Sample 62: `69e90c26d71023ac`

| Field | Value |
|---|---|
| SHA-256 | `69e90c26d71023ac888a93ed063c781eab261bd264597c7eb5ab56592980592f` |
| Family label | `SalatStealer` |
| File name | `69e90c26d71023ac.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf321374bfb40be387f17a5547d45b16` |
| SHA-1 | `e4fe27fade190d298fe79848e38efe5cb437a0b3` |
| SHA-256 | `69e90c26d71023ac888a93ed063c781eab261bd264597c7eb5ab56592980592f` |
| SHA3-384 | `3badc636bbc89f108c0e2593cf9ccf68ce499defa02d2fbd2f57e0fa52f38bb521db570718b357611b8d835e64da1aac` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1A2F5335BF1AF47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O6:iJiafuIO7rhWEES4N` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_062_69e90c26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69e90c26d71023ac888a93ed063c781eab261bd264597c7eb5ab56592980592f"
    family = "SalatStealer"
    file_name = "69e90c26d71023ac.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:11"
  condition:
    hash.sha256(0, filesize) == "69e90c26d71023ac888a93ed063c781eab261bd264597c7eb5ab56592980592f"
}
```

### Sample 63: `e9c117cb31d3c0f3`

| Field | Value |
|---|---|
| SHA-256 | `e9c117cb31d3c0f3799a5a6e108eed3b5670005d93c92fb3b053e2a4978fbd37` |
| Family label | `SalatStealer` |
| File name | `e9c117cb31d3c0f3.bin` |
| File type | `exe` |
| First seen | `2026-11-05 01:25:03` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b15bfb45dbe2b9c90839cffb5b01bba` |
| SHA-1 | `2e47fcabdbb019aff1e3d5221c44dfda57e306b1` |
| SHA-256 | `e9c117cb31d3c0f3799a5a6e108eed3b5670005d93c92fb3b053e2a4978fbd37` |
| SHA3-384 | `bf336683dbc992326b32428679f6a3e2c5cf0f21fd9d553660782180031e14d5396c3315c0cbfd1f1fae25a6ae0d7dae` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1E2F5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0846BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Or:iJiafuIO7rhWEES4+` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_063_e9c117cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9c117cb31d3c0f3799a5a6e108eed3b5670005d93c92fb3b053e2a4978fbd37"
    family = "SalatStealer"
    file_name = "e9c117cb31d3c0f3.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:03"
  condition:
    hash.sha256(0, filesize) == "e9c117cb31d3c0f3799a5a6e108eed3b5670005d93c92fb3b053e2a4978fbd37"
}
```

### Sample 64: `b5d801c674e4e076`

| Field | Value |
|---|---|
| SHA-256 | `b5d801c674e4e0769f83d8eb3b1e4a31c3de18d9a06c9ae9be91a38a8559e6d3` |
| Family label | `SalatStealer` |
| File name | `0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:24:19` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06e734d483b0889462474f446df6e28f` |
| SHA-1 | `c965009b28f0140c1def131f48094b43da8494ac` |
| SHA-256 | `b5d801c674e4e0769f83d8eb3b1e4a31c3de18d9a06c9ae9be91a38a8559e6d3` |
| SHA3-384 | `1c78016d85df9d50b64c22ca5031ef995992db510bdb6bc52d62c4664880bf8506fbf88d7a5bac0ae8ada14ed5e6f8f8` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T16DC65C11FACB54F6F9036831416BB27F23315D048B28DB9BEB583B6AF877691187A305` |
| SSDEEP | `49152:2E6KiXwhZMKX41WQw9JxdNPCpYs2tFVDbwrLyfGvUdP7XVOYHahsnipR6mSMFZOk:aKUwNQw7/RCH25si5uiMWh4CrEvO/` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_064_b5d801c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5d801c674e4e0769f83d8eb3b1e4a31c3de18d9a06c9ae9be91a38a8559e6d3"
    family = "SalatStealer"
    file_name = "0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:24:19"
  condition:
    hash.sha256(0, filesize) == "b5d801c674e4e0769f83d8eb3b1e4a31c3de18d9a06c9ae9be91a38a8559e6d3"
}
```

### Sample 65: `0c0654730121fb29`

| Field | Value |
|---|---|
| SHA-256 | `0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd` |
| Family label | `SalatStealer` |
| File name | `0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:23:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3284e96267d4efd14ed43159e9fc5558` |
| SHA-1 | `9bef17192ca4d41a878892f96ae2d5f5694ad010` |
| SHA-256 | `0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd` |
| SHA3-384 | `87b77715a461b915def3d013d9eb586e9a2999a79dbe42e707e257e219b38721277b8be68d0d0dac590991660ed9a6c3` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T11DF5336BE5283F97F42385FD71028E3672BC54289BBC3D722158A99294BD3A332D1717` |
| SSDEEP | `98304:0Cu8XAtzhCiD3ANmNVOokXg6nP2wHAkc:7SLNkXgOnhc` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_065_0c065473
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd"
    family = "SalatStealer"
    file_name = "0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:23:13"
  condition:
    hash.sha256(0, filesize) == "0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd"
}
```

### Sample 66: `335637b09436eb91`

| Field | Value |
|---|---|
| SHA-256 | `335637b09436eb911f1df4e38c49f363a2d685629e706e81d39af2ba512d75db` |
| Family label | `unknown` |
| File name | `335637b09436eb911f1df4e38c49f363a2d685629e706e81d39af2ba512d75db.bin` |
| File type | `macho` |
| First seen | `2026-11-05 01:23:08` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e5f6159d45bb8c7c2d2fa7eb789d697` |
| SHA-1 | `8dd94b220632d0a6a4b1fef9da2e9288b696e654` |
| SHA-256 | `335637b09436eb911f1df4e38c49f363a2d685629e706e81d39af2ba512d75db` |
| SHA3-384 | `c4dfefe609dc14f70401f0713d9755cbb688250a463a82a7f2f64d2bcba4ecd2fee36b53a35bf900b7d615bfb242096c` |
| TLSH | `T116E23D43AF4C8965C26D82301AF71BC6A616F5B09EE16B875750C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvURVZqDDt0TOTLZ0BbFw2sHKk6XrMclSibFqAMcl:z4ZZXvv4VZMt0TO2bVU/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_335637b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "335637b09436eb911f1df4e38c49f363a2d685629e706e81d39af2ba512d75db"
    family = "unknown"
    file_name = "335637b09436eb911f1df4e38c49f363a2d685629e706e81d39af2ba512d75db.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:23:08"
  condition:
    hash.sha256(0, filesize) == "335637b09436eb911f1df4e38c49f363a2d685629e706e81d39af2ba512d75db"
}
```

### Sample 67: `fc50c17aea0190a2`

| Field | Value |
|---|---|
| SHA-256 | `fc50c17aea0190a2d8096b592c9b7e9ba6bae2026b7010e2291ef6011544ffe4` |
| Family label | `unknown` |
| File name | `fc50c17aea0190a2d8096b592c9b7e9ba6bae2026b7010e2291ef6011544ffe4.bin` |
| File type | `macho` |
| First seen | `2026-11-05 01:21:26` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `188d43e0d69744d852cd57c1c35e65a5` |
| SHA-1 | `f9b90ff2e00f1f5c2d0e4f3852d3248d8e1bae2b` |
| SHA-256 | `fc50c17aea0190a2d8096b592c9b7e9ba6bae2026b7010e2291ef6011544ffe4` |
| SHA3-384 | `2e61a50e9c1c0d80d2cd9bc96a4b19c4ba0b531052bc0c777cb64101eb98fce0ca87b48d05d8e733f71c74a1baf28ad4` |
| TLSH | `T1B8F273239B1C5922C48C663C82BB6742A23BF1A145D577B74B00872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7gHT4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7QTMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_fc50c17a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc50c17aea0190a2d8096b592c9b7e9ba6bae2026b7010e2291ef6011544ffe4"
    family = "unknown"
    file_name = "fc50c17aea0190a2d8096b592c9b7e9ba6bae2026b7010e2291ef6011544ffe4.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:21:26"
  condition:
    hash.sha256(0, filesize) == "fc50c17aea0190a2d8096b592c9b7e9ba6bae2026b7010e2291ef6011544ffe4"
}
```

### Sample 68: `19bec5bf63667616`

| Field | Value |
|---|---|
| SHA-256 | `19bec5bf63667616099fa3d77ee17a62c4fef45916776f6b439ce53c8bca91b7` |
| Family label | `VShell` |
| File name | `19bec5bf63667616099fa3d77ee17a62c4fef45916776f6b439ce53c8bca91b7.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:21:22` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `530bbf5b11297ebad9ef834fcd964844` |
| SHA-1 | `a5446f63f39a39856443e8f3783b3c67ba2a7848` |
| SHA-256 | `19bec5bf63667616099fa3d77ee17a62c4fef45916776f6b439ce53c8bca91b7` |
| SHA3-384 | `c9c66dd4efa687b0eab6d259432875487acda375bd94f5fac7403f4352fb5cdae798e176b8ea4976274d46986c005309` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1A771B54160501AF2D94DA3BFC487B895FD4EB248A2C84B0F07A8981A3F7507BB0D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6Dg+8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6Dg+G++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_068_19bec5bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19bec5bf63667616099fa3d77ee17a62c4fef45916776f6b439ce53c8bca91b7"
    family = "VShell"
    file_name = "19bec5bf63667616099fa3d77ee17a62c4fef45916776f6b439ce53c8bca91b7.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:21:22"
  condition:
    hash.sha256(0, filesize) == "19bec5bf63667616099fa3d77ee17a62c4fef45916776f6b439ce53c8bca91b7"
}
```

### Sample 69: `d51fa4d820d32a6c`

| Field | Value |
|---|---|
| SHA-256 | `d51fa4d820d32a6c6ad71cb715abdebabf5aa0ec4ed07ff4ee3b67e0f208d9ef` |
| Family label | `unknown` |
| File name | `d51fa4d820d32a6c6ad71cb715abdebabf5aa0ec4ed07ff4ee3b67e0f208d9ef.bin` |
| File type | `macho` |
| First seen | `2026-11-05 01:21:18` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1daf542f1a29c2846b036d29ea29c016` |
| SHA-1 | `1193b5eaf1226850b8ad9e3ca5b752119f99b3be` |
| SHA-256 | `d51fa4d820d32a6c6ad71cb715abdebabf5aa0ec4ed07ff4ee3b67e0f208d9ef` |
| SHA3-384 | `b7ce1e3b6c49d02381ae2a3a2c7d1cb72c69bcaa018f96f098f01c9225e35e7afd959cdc3ad1d9b10e50066d9dccddae` |
| TLSH | `T1B9F263239B1C9922C48C623842BB6742A23AF1E145D677774B04C72DAFCA3C5B9E5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7rmHm4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7rKmMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_d51fa4d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51fa4d820d32a6c6ad71cb715abdebabf5aa0ec4ed07ff4ee3b67e0f208d9ef"
    family = "unknown"
    file_name = "d51fa4d820d32a6c6ad71cb715abdebabf5aa0ec4ed07ff4ee3b67e0f208d9ef.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:21:18"
  condition:
    hash.sha256(0, filesize) == "d51fa4d820d32a6c6ad71cb715abdebabf5aa0ec4ed07ff4ee3b67e0f208d9ef"
}
```

### Sample 70: `9ccb2b7d0fdc7d47`

| Field | Value |
|---|---|
| SHA-256 | `9ccb2b7d0fdc7d47b305d9ae9e5703a4fb3f35ded599b27ab4e337f000a57d80` |
| Family label | `VShell` |
| File name | `9ccb2b7d0fdc7d47b305d9ae9e5703a4fb3f35ded599b27ab4e337f000a57d80.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:20:31` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `965e557371a54c1a39af9ff9e66e17eb` |
| SHA-1 | `9aeba23508f969da3d9f15687388d23d7148780f` |
| SHA-256 | `9ccb2b7d0fdc7d47b305d9ae9e5703a4fb3f35ded599b27ab4e337f000a57d80` |
| SHA3-384 | `b8ecec3af3df6de8bab6fc2235074c58c9cc9242a8a833eff74be140c72dcb1202c92a372fbec860f4460fe98dc464c4` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T14091C5C5F757E6B2EC1C07F600A379A4C4682E1882BC9B464FE12F1C3C111AA3C2EA16` |
| SSDEEP | `48:6I7lwe7gi08SwJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1N096q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_070_9ccb2b7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ccb2b7d0fdc7d47b305d9ae9e5703a4fb3f35ded599b27ab4e337f000a57d80"
    family = "VShell"
    file_name = "9ccb2b7d0fdc7d47b305d9ae9e5703a4fb3f35ded599b27ab4e337f000a57d80.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:20:31"
  condition:
    hash.sha256(0, filesize) == "9ccb2b7d0fdc7d47b305d9ae9e5703a4fb3f35ded599b27ab4e337f000a57d80"
}
```

### Sample 71: `b2a789549b2b96e8`

| Field | Value |
|---|---|
| SHA-256 | `b2a789549b2b96e8be6c1a0ca36a6ddbd1e5e02cf428518ab01658abf5b07b17` |
| Family label | `unknown` |
| File name | `b2a789549b2b96e8be6c1a0ca36a6ddbd1e5e02cf428518ab01658abf5b07b17.bin` |
| File type | `macho` |
| First seen | `2026-11-05 01:20:26` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6fb569ee81c45e1b0c9edab5b00c343` |
| SHA-1 | `21f6152e818a2b1dd13d674cf0ff09989886ae99` |
| SHA-256 | `b2a789549b2b96e8be6c1a0ca36a6ddbd1e5e02cf428518ab01658abf5b07b17` |
| SHA3-384 | `42a616bd47a750262157fcda27322381e50333d4bb18a86ee36312f79816b9c44fa0d79af8f003a4e71765fa455d0143` |
| TLSH | `T1E3E26F43675C5929D44D83BA62FB1B936609F8B009D49B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEN+5DbDP67li97WsCcwYjqclS06W1YbqclSl:GI2N+5DbDy6wYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_b2a78954
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2a789549b2b96e8be6c1a0ca36a6ddbd1e5e02cf428518ab01658abf5b07b17"
    family = "unknown"
    file_name = "b2a789549b2b96e8be6c1a0ca36a6ddbd1e5e02cf428518ab01658abf5b07b17.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:20:26"
  condition:
    hash.sha256(0, filesize) == "b2a789549b2b96e8be6c1a0ca36a6ddbd1e5e02cf428518ab01658abf5b07b17"
}
```

### Sample 72: `de182a07b5f109ce`

| Field | Value |
|---|---|
| SHA-256 | `de182a07b5f109ce416f4566f5ba5625bb7dac71b0c1b3a460aa32078e55d31e` |
| Family label | `VShell` |
| File name | `de182a07b5f109ce416f4566f5ba5625bb7dac71b0c1b3a460aa32078e55d31e.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:20:22` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eeee531697244b794770c1f2d230545a` |
| SHA-1 | `0dad0d682d505d67cf99a9122034b957add5c849` |
| SHA-256 | `de182a07b5f109ce416f4566f5ba5625bb7dac71b0c1b3a460aa32078e55d31e` |
| SHA3-384 | `95cacde960ce29ddc0561f71224d09c7dc2073ccf497acc87f1483548db0ab60864459ee003d67d34cddb40534387fa7` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T11591E74270B988E7E85C81BB4D0FB8A0BD1D740A41C483A70338A5953E3953BF4BCB0E` |
| SSDEEP | `48:6IIF9BlQaex2lmgZD7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaM21A0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_072_de182a07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de182a07b5f109ce416f4566f5ba5625bb7dac71b0c1b3a460aa32078e55d31e"
    family = "VShell"
    file_name = "de182a07b5f109ce416f4566f5ba5625bb7dac71b0c1b3a460aa32078e55d31e.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:20:22"
  condition:
    hash.sha256(0, filesize) == "de182a07b5f109ce416f4566f5ba5625bb7dac71b0c1b3a460aa32078e55d31e"
}
```

### Sample 73: `e976532487513f4a`

| Field | Value |
|---|---|
| SHA-256 | `e976532487513f4a01b616760b405cf55a724c9e87d444984eba3a8cc4181504` |
| Family label | `VShell` |
| File name | `e976532487513f4a01b616760b405cf55a724c9e87d444984eba3a8cc4181504.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:20:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4e2f273b4c551cdc6f5e3a374224051` |
| SHA-1 | `e6a9e7aff0dfc720fd2adcc5e89175b497dfc57e` |
| SHA-256 | `e976532487513f4a01b616760b405cf55a724c9e87d444984eba3a8cc4181504` |
| SHA3-384 | `af8be2295af5820da2ef3182ad78335864cfdaca9eb7b9ecfa30f2adc7a56eab9ae2b80c73a358d85fc1ec4083f13f62` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T15991A5C5F757E6B2EC1C07F500A379A4C4682E1482BC9B564FE16F1C3C111AA3C2DA56` |
| SSDEEP | `48:6I7lwe7Bfh08SwJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1dp096q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_073_e9765324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e976532487513f4a01b616760b405cf55a724c9e87d444984eba3a8cc4181504"
    family = "VShell"
    file_name = "e976532487513f4a01b616760b405cf55a724c9e87d444984eba3a8cc4181504.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:20:18"
  condition:
    hash.sha256(0, filesize) == "e976532487513f4a01b616760b405cf55a724c9e87d444984eba3a8cc4181504"
}
```

### Sample 74: `72cf2e12d0a69f0d`

| Field | Value |
|---|---|
| SHA-256 | `72cf2e12d0a69f0d7cfaa0e809cd6c64bd4f588c5c03c7e6e86f992e2ebc4255` |
| Family label | `unknown` |
| File name | `72cf2e12d0a69f0d7cfaa0e809cd6c64bd4f588c5c03c7e6e86f992e2ebc4255.bin` |
| File type | `macho` |
| First seen | `2026-11-05 01:14:31` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1432a296dbd32a0e42be2db5350fa11` |
| SHA-1 | `9958755ff08e6b3a9957d410b3133c70f3877b5c` |
| SHA-256 | `72cf2e12d0a69f0d7cfaa0e809cd6c64bd4f588c5c03c7e6e86f992e2ebc4255` |
| SHA3-384 | `45eadc0eefb4ff9afe0acea715515fa1d79fa8526a157b506dc90faceca314505ce8804969885cb1b8e6f50b6375f62f` |
| TLSH | `T10AF24E139B1C0A61C55C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRtPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfYlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_72cf2e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72cf2e12d0a69f0d7cfaa0e809cd6c64bd4f588c5c03c7e6e86f992e2ebc4255"
    family = "unknown"
    file_name = "72cf2e12d0a69f0d7cfaa0e809cd6c64bd4f588c5c03c7e6e86f992e2ebc4255.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:14:31"
  condition:
    hash.sha256(0, filesize) == "72cf2e12d0a69f0d7cfaa0e809cd6c64bd4f588c5c03c7e6e86f992e2ebc4255"
}
```

### Sample 75: `d585f01b08c96736`

| Field | Value |
|---|---|
| SHA-256 | `d585f01b08c96736c7a9156794b73511e2571e9b5b7320e5eaba9be4c4d9c603` |
| Family label | `unknown` |
| File name | `d585f01b08c96736c7a9156794b73511e2571e9b5b7320e5eaba9be4c4d9c603.bin` |
| File type | `macho` |
| First seen | `2026-11-05 01:14:27` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2278c05c779c6deae7c47283515f0b99` |
| SHA-1 | `0634f07d7fb07756ed5b7346888c36419ba98d7e` |
| SHA-256 | `d585f01b08c96736c7a9156794b73511e2571e9b5b7320e5eaba9be4c4d9c603` |
| SHA3-384 | `2131f740597c05c7dc2477118f2c68ffb76235dd269d463410c64db9b8e16cfb1ca1f16e67ed21deeb2aef7d6956d41d` |
| TLSH | `T13FE24E43675C5929D05D83BA22FB1B976609F8A009D45B832F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEU5DbDP67li97WsC+wYjqclS06W1YbqclSl:GI2U5DbDycwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_d585f01b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d585f01b08c96736c7a9156794b73511e2571e9b5b7320e5eaba9be4c4d9c603"
    family = "unknown"
    file_name = "d585f01b08c96736c7a9156794b73511e2571e9b5b7320e5eaba9be4c4d9c603.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:14:27"
  condition:
    hash.sha256(0, filesize) == "d585f01b08c96736c7a9156794b73511e2571e9b5b7320e5eaba9be4c4d9c603"
}
```

### Sample 76: `2a1b4f0a5e6061de`

| Field | Value |
|---|---|
| SHA-256 | `2a1b4f0a5e6061de7eaf8e5e1b3aa16407522350458d586e05342843b4607875` |
| Family label | `unknown` |
| File name | `2a1b4f0a5e6061de7eaf8e5e1b3aa16407522350458d586e05342843b4607875.bin` |
| File type | `macho` |
| First seen | `2026-11-05 01:14:22` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca42121c9396151d41fa8f194e1806be` |
| SHA-1 | `282a59ef71459db56415b91c0c577c75924f6296` |
| SHA-256 | `2a1b4f0a5e6061de7eaf8e5e1b3aa16407522350458d586e05342843b4607875` |
| SHA3-384 | `fd1ca6d3103de6ba7b68b5171538fd5bdabd751fe9eed352da264ed046d337b85d48560f93adfc560e418b295456117f` |
| TLSH | `T1C9F263239B1C5922C44C623842BB6742A23BF1A145D677A74B04872DAFCA3C5B9A5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7uHQD4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7ywMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_2a1b4f0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a1b4f0a5e6061de7eaf8e5e1b3aa16407522350458d586e05342843b4607875"
    family = "unknown"
    file_name = "2a1b4f0a5e6061de7eaf8e5e1b3aa16407522350458d586e05342843b4607875.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:14:22"
  condition:
    hash.sha256(0, filesize) == "2a1b4f0a5e6061de7eaf8e5e1b3aa16407522350458d586e05342843b4607875"
}
```

### Sample 77: `643d7a79d4adffd0`

| Field | Value |
|---|---|
| SHA-256 | `643d7a79d4adffd085c09ea4aea6333559e3373388a9fc21b8e553d04707c7b0` |
| Family label | `VShell` |
| File name | `643d7a79d4adffd085c09ea4aea6333559e3373388a9fc21b8e553d04707c7b0.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:14:19` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f652a20f0ef1f23e774fb857edff29b3` |
| SHA-1 | `e06c05d07567524a5a629c40ca86529bd252c6e1` |
| SHA-256 | `643d7a79d4adffd085c09ea4aea6333559e3373388a9fc21b8e553d04707c7b0` |
| SHA3-384 | `69fcd85ed9331df2c335c74ed62f87adc50e0427c729e0a061b06eeae1cf9dd0a95cd5d68291efbda78e3e943e0ecafe` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1C991C5C6F35BE6B2EC1C07F500A379A4C4682E14827C9B464FE16F0C3C111AA3D7EA56` |
| SSDEEP | `48:6I7lwe7yf08SwJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1+096q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_077_643d7a79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "643d7a79d4adffd085c09ea4aea6333559e3373388a9fc21b8e553d04707c7b0"
    family = "VShell"
    file_name = "643d7a79d4adffd085c09ea4aea6333559e3373388a9fc21b8e553d04707c7b0.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:14:19"
  condition:
    hash.sha256(0, filesize) == "643d7a79d4adffd085c09ea4aea6333559e3373388a9fc21b8e553d04707c7b0"
}
```

### Sample 78: `904130cdbd874463`

| Field | Value |
|---|---|
| SHA-256 | `904130cdbd874463325c9f90f11ee0cdc74002f217f05364dec89e34b9a03f98` |
| Family label | `unknown` |
| File name | `FarzaCraft.zip` |
| File type | `zip` |
| First seen | `2026-11-05 01:13:19` |
| Reporter | `milliesolem` |
| Tags | `kurdishmyth, MythJs, MythPrivate, RAT, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b220db70085f4df8560d3b80db1ae318` |
| SHA-1 | `cf20ee9c531c2b51eac20fae655be6f514b8f239` |
| SHA-256 | `904130cdbd874463325c9f90f11ee0cdc74002f217f05364dec89e34b9a03f98` |
| SHA3-384 | `a66cdb9dc060bc25e64809e91459d1242cc6e93f185a2e1ca9815be04418412cabfe226a31c79d6b842ec931cd44b7cc` |
| TLSH | `T1D8173381B445F93BB0974E1A16AF4CF362CCD9F85018AAD5ECE6D63BEC408913EBD512` |
| SSDEEP | `393216:uF95mEstyBj1DARYPg8rXk2Roy8ZqNWRzRgI5F7l9iW:AzmEsty0RYPJey8bOI3n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_904130cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "904130cdbd874463325c9f90f11ee0cdc74002f217f05364dec89e34b9a03f98"
    family = "unknown"
    file_name = "FarzaCraft.zip"
    file_type = "zip"
    first_seen = "2026-11-05 01:13:19"
  condition:
    hash.sha256(0, filesize) == "904130cdbd874463325c9f90f11ee0cdc74002f217f05364dec89e34b9a03f98"
}
```

### Sample 79: `550fe7647faf8dd9`

| Field | Value |
|---|---|
| SHA-256 | `550fe7647faf8dd9c0c5166c785fdc754ac444ad3f948eafcbe28a55bfca7cab` |
| Family label | `NetSupport` |
| File name | `swwagger.x64_Ajic.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:09:42` |
| Reporter | `iamaachum` |
| Tags | `31-56-53-146, exe, NetSupport` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34b8196d0b6f8e82ca6534384b07c959` |
| SHA-1 | `558d747d91f19565f3f0d053a9beba9efa3eb90b` |
| SHA-256 | `550fe7647faf8dd9c0c5166c785fdc754ac444ad3f948eafcbe28a55bfca7cab` |
| SHA3-384 | `3a1d44e5b50f3a37c7ffb5fc68a4a5df8e8a784c50db16208cc0510f95e1e24d6a894a782c35aa2e0fc637cd49e26550` |
| IMPHASH | `02e139b212a6f9c3cb63b392aa2b92ce` |
| TLSH | `T13256332636E2DBEEC27644F956573A5B60393E50033096FF07D23FAA2D266F18637091` |
| SSDEEP | `98304:hTQg5OZkl441aJn9hccReAmGfjMlU6vTMuPDsR4MwzPvLK3XpwRzmOphgv8OWTjW:SvaWJnrcKmGl6v4uI6nGHpwRbbfOWP4F` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_079_550fe764
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "550fe7647faf8dd9c0c5166c785fdc754ac444ad3f948eafcbe28a55bfca7cab"
    family = "NetSupport"
    file_name = "swwagger.x64_Ajic.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:09:42"
  condition:
    hash.sha256(0, filesize) == "550fe7647faf8dd9c0c5166c785fdc754ac444ad3f948eafcbe28a55bfca7cab"
}
```

### Sample 80: `da20070812bc969f`

| Field | Value |
|---|---|
| SHA-256 | `da20070812bc969f0460a2841c75a7972d0ffc3a1b3a8b1d53d59a496028722e` |
| Family label | `NetSupport` |
| File name | `AutoAppSetup.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:08:52` |
| Reporter | `iamaachum` |
| Tags | `23-94-252-99, 31-56-53-146, exe, github-desktop-ug, HijackLoader, IDATLoader, NetSupport, service-upgrade-ug, SnappyClient` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `667afda5818ad276e02aed250b0f0c34` |
| SHA-1 | `96928878727a7dd150ebaa1a8b0864b825799215` |
| SHA-256 | `da20070812bc969f0460a2841c75a7972d0ffc3a1b3a8b1d53d59a496028722e` |
| SHA3-384 | `021955c8d8ca6ad38d23b4829cac63792f6f8c99258c63c06ffb8476b5a0107e53b472dcbdf767e63e0c610eae1d19f4` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T13018337BE187A139D02A56377A77E150453F3A2159658D07A6ECF88DEFB25300A2F383` |
| SSDEEP | `1572864:P1UafPmumzMvHT51RaECOFQ4EOwNMZkBJ9vqvP0S6V7F93HmaLE:P1vfPRmzMvHjQKFqvNMOX9yvP0S6V7Fk` |
| ICON-DHASH | `5050d270cccc82ae` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_080_da200708
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da20070812bc969f0460a2841c75a7972d0ffc3a1b3a8b1d53d59a496028722e"
    family = "NetSupport"
    file_name = "AutoAppSetup.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:08:52"
  condition:
    hash.sha256(0, filesize) == "da20070812bc969f0460a2841c75a7972d0ffc3a1b3a8b1d53d59a496028722e"
}
```

### Sample 81: `90bba4c2d5e07c42`

| Field | Value |
|---|---|
| SHA-256 | `90bba4c2d5e07c42ebd2df49c2387a2a73bac01c970ddc9b7a98030c825b04a7` |
| Family label | `NetSupport` |
| File name | `helm3301.msi` |
| File type | `msi` |
| First seen | `2026-11-05 01:07:40` |
| Reporter | `iamaachum` |
| Tags | `23-94-252-99, 31-56-53-146, github-desktop-ug, HijackLoader, IDATLoader, msi, NetSupport, service-upgrade-ug, SnappyClient` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4784578eec43ea3911308721936f9a2d` |
| SHA-1 | `3aab5072884d01ccd25d8768a45cc6213093c882` |
| SHA-256 | `90bba4c2d5e07c42ebd2df49c2387a2a73bac01c970ddc9b7a98030c825b04a7` |
| SHA3-384 | `4d6815b8d7a01f4492cfa43b52343277250d600c7c4bc140aabe716b902a92c5a0976ad2807dcacd99a95187683fb5b7` |
| TLSH | `T1A622D74979028A33C1015F318AA7074A47752C40DF8B260B3BFD735C6FBA5E475AA3E5` |
| SSDEEP | `96:5yWVNmdQhGAL/FCwQlM5Wu+8zL5EzP1zhrsqz5Uf2IpVreWHvbKSd95ApC9o10Uc:xSAz4wvTzL5KdrueI/OSNW0E8SA` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_081_90bba4c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90bba4c2d5e07c42ebd2df49c2387a2a73bac01c970ddc9b7a98030c825b04a7"
    family = "NetSupport"
    file_name = "helm3301.msi"
    file_type = "msi"
    first_seen = "2026-11-05 01:07:40"
  condition:
    hash.sha256(0, filesize) == "90bba4c2d5e07c42ebd2df49c2387a2a73bac01c970ddc9b7a98030c825b04a7"
}
```

### Sample 82: `cd66f76c1487d4d0`

| Field | Value |
|---|---|
| SHA-256 | `cd66f76c1487d4d0bbc4053edf355213cbad9323ded6b4ba910a915e1b5a85c8` |
| Family label | `VShell` |
| File name | `cd66f76c1487d4d0bbc4053edf355213cbad9323ded6b4ba910a915e1b5a85c8.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:07:22` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52c9109aa6e68a58b36f3f7d29cc347a` |
| SHA-1 | `1e74031741b17e910ed22b333de67f80d275c561` |
| SHA-256 | `cd66f76c1487d4d0bbc4053edf355213cbad9323ded6b4ba910a915e1b5a85c8` |
| SHA3-384 | `85b05edc9eaff0e23948d70503b58d3f13f8eb42050352ab4c2703cf4e4acd1ef41e222a4f78aae54d51e6d126926c59` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1E291C5C6F357E6B2EC1C17F500A379A4C4682E14827C9B464FE16F1C3C111AA3C6EA16` |
| SSDEEP | `48:6I7lwe7wHIG08SwJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl109096q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_082_cd66f76c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd66f76c1487d4d0bbc4053edf355213cbad9323ded6b4ba910a915e1b5a85c8"
    family = "VShell"
    file_name = "cd66f76c1487d4d0bbc4053edf355213cbad9323ded6b4ba910a915e1b5a85c8.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:07:22"
  condition:
    hash.sha256(0, filesize) == "cd66f76c1487d4d0bbc4053edf355213cbad9323ded6b4ba910a915e1b5a85c8"
}
```

### Sample 83: `57b017057e372154`

| Field | Value |
|---|---|
| SHA-256 | `57b017057e3721545040cadb9d4cbc3abb945fa405315e8775cadb3b463899b0` |
| Family label | `VShell` |
| File name | `57b017057e3721545040cadb9d4cbc3abb945fa405315e8775cadb3b463899b0.exe` |
| File type | `exe` |
| First seen | `2026-11-05 01:02:17` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e38a3a59c50c4e81141ed234d3e97ee` |
| SHA-1 | `3711681e687109fc5822b77aefec4a720f5ca75e` |
| SHA-256 | `57b017057e3721545040cadb9d4cbc3abb945fa405315e8775cadb3b463899b0` |
| SHA3-384 | `ea1833d07c3f1c515c900891e0f07c244df559dd1cf54ba285a4be7bb281e09e6997ebf377525aa2db6b6eb609fddd08` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T14F91D74270B989E7E85C91BB4C0FB8A0B91D740A41C483A74338A5993E3A57BF5BCB0D` |
| SSDEEP | `48:6IIF9BlQaexpegZD7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMpnA0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_083_57b01705
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57b017057e3721545040cadb9d4cbc3abb945fa405315e8775cadb3b463899b0"
    family = "VShell"
    file_name = "57b017057e3721545040cadb9d4cbc3abb945fa405315e8775cadb3b463899b0.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:02:17"
  condition:
    hash.sha256(0, filesize) == "57b017057e3721545040cadb9d4cbc3abb945fa405315e8775cadb3b463899b0"
}
```

### Sample 84: `092dd2e5365b858d`

| Field | Value |
|---|---|
| SHA-256 | `092dd2e5365b858d6bd6b3c16089752e85ee7f79056f95f6ebc4ce085f7f4b62` |
| Family label | `WannaCry` |
| File name | `7b0707b5317700669e083def02efad58` |
| File type | `dll` |
| First seen | `2026-11-05 00:59:42` |
| Reporter | `malwareontap` |
| Tags | `dionaea, dll, honeypot, pe, WannaCry, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b0707b5317700669e083def02efad58` |
| SHA-1 | `a6de24e53ad203e7a1a75c2b6373f3237bdc83bd` |
| SHA-256 | `092dd2e5365b858d6bd6b3c16089752e85ee7f79056f95f6ebc4ce085f7f4b62` |
| SHA3-384 | `752fec95a99772d0a7ec8b3fb1ad1ce9c14f7c242117b97c86b72a3cd6a0260909ccbb7f99b58a3a40499a73be7704af` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T15436332972BCD1BCE1061A744477CA33D6B27C652ABDAB1F8B40C5661D23B59EF90B03` |
| SSDEEP | `49152:znAQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnvxJM0H9T:TDqPoBhz1aRxcSUDk36SAEdhvxWa9` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_084_092dd2e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "092dd2e5365b858d6bd6b3c16089752e85ee7f79056f95f6ebc4ce085f7f4b62"
    family = "WannaCry"
    file_name = "7b0707b5317700669e083def02efad58"
    file_type = "dll"
    first_seen = "2026-11-05 00:59:42"
  condition:
    hash.sha256(0, filesize) == "092dd2e5365b858d6bd6b3c16089752e85ee7f79056f95f6ebc4ce085f7f4b62"
}
```

### Sample 85: `24b84f2811c12ad7`

| Field | Value |
|---|---|
| SHA-256 | `24b84f2811c12ad7eb4e85720e25baaf073f078152b238bef55badbda59010db` |
| Family label | `unknown` |
| File name | `Unlock_Kit-Pro_v4.3.exe` |
| File type | `exe` |
| First seen | `2026-11-05 00:57:41` |
| Reporter | `iamaachum` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be4680109ddc14947291284190dcdd90` |
| SHA-1 | `87567e935a31e707951e821ca8f199f19f5a86c9` |
| SHA-256 | `24b84f2811c12ad7eb4e85720e25baaf073f078152b238bef55badbda59010db` |
| SHA3-384 | `061faa5dc17cd19e7798c002b85fa236ab21bcc41628947c92e9bff204d7062e38bbb51a89e083a67784c252edf46526` |
| IMPHASH | `2572530e244ca16c7892253dcf633fa5` |
| TLSH | `T1D806AE46AAF60118E2B79A3856F70116963BBD010B38CEDF3A8C55591F73BC46472F3A` |
| SSDEEP | `49152:iezK7JhWbCFTPRBS0oQ7NN5+8COwDlHmHRBBYkxtOkIRTAC3Oyg0ypM7R9GFrdf1:MzBt+8bwhHmA3OFiecETfs` |
| ICON-DHASH | `f0f06969697196cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_24b84f28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24b84f2811c12ad7eb4e85720e25baaf073f078152b238bef55badbda59010db"
    family = "unknown"
    file_name = "Unlock_Kit-Pro_v4.3.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:57:41"
  condition:
    hash.sha256(0, filesize) == "24b84f2811c12ad7eb4e85720e25baaf073f078152b238bef55badbda59010db"
}
```

### Sample 86: `9e96180048ace1c8`

| Field | Value |
|---|---|
| SHA-256 | `9e96180048ace1c8acca44f9da4120f09b08fc593ef987e7ae6494000477070c` |
| Family label | `unknown` |
| File name | `Set-up.msi` |
| File type | `msi` |
| First seen | `2026-11-05 00:57:03` |
| Reporter | `iamaachum` |
| Tags | `chocolatemilf-fun, FunStealer, localhost8000-fun, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd4992a9ed910b0cee67dc5319c61b63` |
| SHA-1 | `22d6362b6698473412dd967254797fd68339e5f5` |
| SHA-256 | `9e96180048ace1c8acca44f9da4120f09b08fc593ef987e7ae6494000477070c` |
| SHA3-384 | `a2b7f4d97ec710986f7b9c077d95f8c4e30c9071a13af9052b1684fdf4f2edf96e14c87490070324afaeda8df21e8504` |
| TLSH | `T103661257B38209F9C567C0398666D3B1E631BC140734EA6F0794F7722E32F605E6BAA4` |
| SSDEEP | `49152:9NmiRKU4DpM5Pu5BO0tUftOEH1x+Wl7I1j37yqjGLleMAAaos3EcObSm:SygEH1I081D7yuGLlnDaoR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_9e961800
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e96180048ace1c8acca44f9da4120f09b08fc593ef987e7ae6494000477070c"
    family = "unknown"
    file_name = "Set-up.msi"
    file_type = "msi"
    first_seen = "2026-11-05 00:57:03"
  condition:
    hash.sha256(0, filesize) == "9e96180048ace1c8acca44f9da4120f09b08fc593ef987e7ae6494000477070c"
}
```

### Sample 87: `9fda93f718605288`

| Field | Value |
|---|---|
| SHA-256 | `9fda93f718605288bcf36aae42183aadb60c91e67e4b98cf94b1ca7105f906c6` |
| Family label | `RemusStealer` |
| File name | `Setup_x64.exe` |
| File type | `exe` |
| First seen | `2026-11-05 00:55:49` |
| Reporter | `iamaachum` |
| Tags | `deplay-cc, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baa6518fce9a9cefad9ec90344d11e85` |
| SHA-1 | `a9e832e8a13e8166721f4e71d9bd153ae426b1ea` |
| SHA-256 | `9fda93f718605288bcf36aae42183aadb60c91e67e4b98cf94b1ca7105f906c6` |
| SHA3-384 | `560f7b8f70a7da1f4a2c6be2e5809d2f97f47a083a3346030469275b7c9c9366f1c57f1760e0f3893ac08ab2097e63f1` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T13CF55C035E9449ADD09AF238897712566530BC48DB3573E72EA2BFB86F327C05EB8744` |
| SSDEEP | `49152:bNLAIlNbu2H9gdkoi0ZOli/PAUCdZIARQj:bFbu23FvCf` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_087_9fda93f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fda93f718605288bcf36aae42183aadb60c91e67e4b98cf94b1ca7105f906c6"
    family = "RemusStealer"
    file_name = "Setup_x64.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:55:49"
  condition:
    hash.sha256(0, filesize) == "9fda93f718605288bcf36aae42183aadb60c91e67e4b98cf94b1ca7105f906c6"
}
```

### Sample 88: `99e5c10c08b4d338`

| Field | Value |
|---|---|
| SHA-256 | `99e5c10c08b4d3389c374622cb506f029ff558e3e6086ac5494c95e75ba1a099` |
| Family label | `RevStealer` |
| File name | `Set-up 2026.exe` |
| File type | `exe` |
| First seen | `2026-11-05 00:54:20` |
| Reporter | `iamaachum` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f88bf3f4022c1b4e6a2631c88107bed` |
| SHA-1 | `b015b48828d342a7629e2f2021c9080a8cfb798b` |
| SHA-256 | `99e5c10c08b4d3389c374622cb506f029ff558e3e6086ac5494c95e75ba1a099` |
| SHA3-384 | `b015f33b4dfb174f08cce55ce5e6dd9c1b22254103b65b1a9dbe0cf717a5a5a24a5c81be8acb40d8b02c99e8e445126c` |
| IMPHASH | `148e42694da50a299abf342896a79de7` |
| TLSH | `T11455F937637DC53780F26282B8444EB65F951E18839B75E9E1F6C7E2A2C140DC6B1BE2` |
| SSDEEP | `12288:9wHRNmdei14XvgoIsmSP+pfh1VilCieeVBONx3x2K7/RJDKFewZPKmTzP57g4OUg:sUeQEyg/Ok95uyPq` |
| ICON-DHASH | `28d4d4e8e800c000` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_088_99e5c10c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99e5c10c08b4d3389c374622cb506f029ff558e3e6086ac5494c95e75ba1a099"
    family = "RevStealer"
    file_name = "Set-up 2026.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:54:20"
  condition:
    hash.sha256(0, filesize) == "99e5c10c08b4d3389c374622cb506f029ff558e3e6086ac5494c95e75ba1a099"
}
```

### Sample 89: `629abf0597954bff`

| Field | Value |
|---|---|
| SHA-256 | `629abf0597954bffd00e8bb645270850e83ee7e3c23d467ed3f4da16169c8da3` |
| Family label | `RemusStealer` |
| File name | `Photoshop.2026.exe` |
| File type | `exe` |
| First seen | `2026-11-05 00:53:11` |
| Reporter | `iamaachum` |
| Tags | `bugerror-info, exe, key5-click, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62ffe92881c7f4a8dc65c2cc73ab1005` |
| SHA-1 | `9e28e03c2055ad24ee993e146902ac18abe78223` |
| SHA-256 | `629abf0597954bffd00e8bb645270850e83ee7e3c23d467ed3f4da16169c8da3` |
| SHA3-384 | `9c2c75ba921d2e384fe55ffdd4bb73aa75dca79441e2825fb4a68e2a622da3205b16d00728939080999c37d476fc1619` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T178F56C03AD9449AED096B2388D7712563621BC48DB3573E72EA2BFB86F327C05E74744` |
| SSDEEP | `24576:KbzbLUMky0yPqHa4ybWy/5UkFW2LcpARuln/cmfGiD9mAzvfnB:KbXLUMTPq6j6y/5nFdCyupRjnB` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_089_629abf05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "629abf0597954bffd00e8bb645270850e83ee7e3c23d467ed3f4da16169c8da3"
    family = "RemusStealer"
    file_name = "Photoshop.2026.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:53:11"
  condition:
    hash.sha256(0, filesize) == "629abf0597954bffd00e8bb645270850e83ee7e3c23d467ed3f4da16169c8da3"
}
```

### Sample 90: `6d1194a3f15a46b0`

| Field | Value |
|---|---|
| SHA-256 | `6d1194a3f15a46b0045f0700f664fe191f8da4502902e85ba55066f386b24650` |
| Family label | `WARDENStealer` |
| File name | `CorelDRAW Graphics Suite 2026 Activator.exe` |
| File type | `exe` |
| First seen | `2026-11-05 00:51:46` |
| Reporter | `iamaachum` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7d322b160c276775140faa5d7b33112` |
| SHA-1 | `37287c3819a5413296fc6a0cc6f79c8ac78aa86c` |
| SHA-256 | `6d1194a3f15a46b0045f0700f664fe191f8da4502902e85ba55066f386b24650` |
| SHA3-384 | `ef314ed91ed3496c2f98270829982cc7b0add27c5a3ebb22143fffe5a66e721cb3a297475ac0e3b3413cedbda21c6f9f` |
| IMPHASH | `8ca87109428396fd29ef98d3bbc5b699` |
| TLSH | `T1FA45497387594EFDF2408676C4921864296E241416D5EBFA2F4EE3EE3D20AC187F7326` |
| SSDEEP | `12288:lyImSSVKSNjMXkLnKOV9roMkDtYvlu5OX6tLH+EsR95G8iIPZcqs3Zi89FKC:lyImDMULfroptou5OKRH2tE399FZ` |
| ICON-DHASH | `0000706969700000` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_090_6d1194a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d1194a3f15a46b0045f0700f664fe191f8da4502902e85ba55066f386b24650"
    family = "WARDENStealer"
    file_name = "CorelDRAW Graphics Suite 2026 Activator.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:51:46"
  condition:
    hash.sha256(0, filesize) == "6d1194a3f15a46b0045f0700f664fe191f8da4502902e85ba55066f386b24650"
}
```

### Sample 91: `4e472f1a5d14cf69`

| Field | Value |
|---|---|
| SHA-256 | `4e472f1a5d14cf690e18943c0fede03185b0faf82429b7ac1ee81e5b7639139c` |
| Family label | `unknown` |
| File name | `Amazon追跡.apk` |
| File type | `apk` |
| First seen | `2026-11-05 00:47:25` |
| Reporter | `masaomi346` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c61f89d5abc8258749c147db6a033c4a` |
| SHA-1 | `5a80465e7c09022ebc842b39961e60d0a4877124` |
| SHA-256 | `4e472f1a5d14cf690e18943c0fede03185b0faf82429b7ac1ee81e5b7639139c` |
| SHA3-384 | `ee2dbe49c0003c39501a9890fb6a0f3cee365b94022fecb80f4dc5a0df411462ae0e43ff31e04b850b7ff922a16498dd` |
| TLSH | `T104F63362EBC9502DFCF7C3358E311AA6E4069D6AC763A28F5960313C28F76D21F459D8` |
| SSDEEP | `393216:DxpD2LO0ZAIU2VHFTGrRXXvQr0d/KPZwv9Rm+lrocntR6lR:DxALOzEVKvm2tW+lroc36T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_4e472f1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e472f1a5d14cf690e18943c0fede03185b0faf82429b7ac1ee81e5b7639139c"
    family = "unknown"
    file_name = "Amazon追跡.apk"
    file_type = "apk"
    first_seen = "2026-11-05 00:47:25"
  condition:
    hash.sha256(0, filesize) == "4e472f1a5d14cf690e18943c0fede03185b0faf82429b7ac1ee81e5b7639139c"
}
```

### Sample 92: `afca81a7e62e4570`

| Field | Value |
|---|---|
| SHA-256 | `afca81a7e62e4570fcb00ddb050a746e15eac6b1dd64a8f2e39778dc63ddfe0f` |
| Family label | `unknown` |
| File name | `afca81a7e62e4570fcb00ddb050a746e15eac6b1dd64a8f2e39778dc63ddfe0f.bin` |
| File type | `macho` |
| First seen | `2026-11-05 00:39:54` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68119dc0ef9d8d160c4c21e57c69ceea` |
| SHA-1 | `5ddb3e0ae1f3f0a5acdf3583687c99782928a6e1` |
| SHA-256 | `afca81a7e62e4570fcb00ddb050a746e15eac6b1dd64a8f2e39778dc63ddfe0f` |
| SHA3-384 | `e6a10c1d74e5150191edd085c9676dff53b2589cd7b2d19ea58d91b65e4b923d0642e1200bd6ce8c45cd0b3d011efc7b` |
| TLSH | `T10AE24E43675C5929D05D83BE22FB1B976609F8A009D49B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEha5DbDP67li97WsCmwYjqclS06W1YbqclSl:GI2M5DbDyowYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_afca81a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afca81a7e62e4570fcb00ddb050a746e15eac6b1dd64a8f2e39778dc63ddfe0f"
    family = "unknown"
    file_name = "afca81a7e62e4570fcb00ddb050a746e15eac6b1dd64a8f2e39778dc63ddfe0f.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:39:54"
  condition:
    hash.sha256(0, filesize) == "afca81a7e62e4570fcb00ddb050a746e15eac6b1dd64a8f2e39778dc63ddfe0f"
}
```

### Sample 93: `502e907908fd37ef`

| Field | Value |
|---|---|
| SHA-256 | `502e907908fd37ef0973fef47ac868af4ab0ced2ec2e3d572904c9d256e60387` |
| Family label | `unknown` |
| File name | `502e907908fd37ef0973fef47ac868af4ab0ced2ec2e3d572904c9d256e60387.bin` |
| File type | `macho` |
| First seen | `2026-11-05 00:39:47` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b462c486f932ab678f408c96e41b8ce` |
| SHA-1 | `60a3f793fdf8ae2582b5e1e06683fc7b3404cd0a` |
| SHA-256 | `502e907908fd37ef0973fef47ac868af4ab0ced2ec2e3d572904c9d256e60387` |
| SHA3-384 | `fe4c290d0b4e76d9dc49686521de172d0dea3507ca214624c5a0c5854d12dec2e1e69c650d93aa876deb0bd05096049e` |
| TLSH | `T1CFF263239B1C5962C48C623842BB6742A23AF1E145D677A74B00872DAFCA3C5BDA5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7pH14z1dgngS6BndngN/4B0:RUdp8j3jvpWK7t1MdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_502e9079
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "502e907908fd37ef0973fef47ac868af4ab0ced2ec2e3d572904c9d256e60387"
    family = "unknown"
    file_name = "502e907908fd37ef0973fef47ac868af4ab0ced2ec2e3d572904c9d256e60387.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:39:47"
  condition:
    hash.sha256(0, filesize) == "502e907908fd37ef0973fef47ac868af4ab0ced2ec2e3d572904c9d256e60387"
}
```

### Sample 94: `14a685db9c2988a2`

| Field | Value |
|---|---|
| SHA-256 | `14a685db9c2988a2a27e5eb0dbd02b70783585155be5120b0d56897297b8ebcf` |
| Family label | `unknown` |
| File name | `14a685db9c2988a2a27e5eb0dbd02b70783585155be5120b0d56897297b8ebcf.bin` |
| File type | `macho` |
| First seen | `2026-11-05 00:39:36` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de494741bd816c17095d9cfa5b4eda90` |
| SHA-1 | `e09e98ef8d25265881eb3eaac79cbd9abe318444` |
| SHA-256 | `14a685db9c2988a2a27e5eb0dbd02b70783585155be5120b0d56897297b8ebcf` |
| SHA3-384 | `491d942e8ef17db5e5efb3d66aa1f7457227db17af923cb3f4c0a8cbf95e71a3e890e6520a8fa760c9373616a231fb75` |
| TLSH | `T1F9E23E43AB4C8965C26D42301AF71BC6A615F5B09EE16B875750C7217FE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUoVZqDDt0TOTLZ0BbFw2yHKk6XrMclSibFqAMcl:z4ZZXvvBVZMt0TO2bV+/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_14a685db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14a685db9c2988a2a27e5eb0dbd02b70783585155be5120b0d56897297b8ebcf"
    family = "unknown"
    file_name = "14a685db9c2988a2a27e5eb0dbd02b70783585155be5120b0d56897297b8ebcf.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:39:36"
  condition:
    hash.sha256(0, filesize) == "14a685db9c2988a2a27e5eb0dbd02b70783585155be5120b0d56897297b8ebcf"
}
```

### Sample 95: `040d963b267aed69`

| Field | Value |
|---|---|
| SHA-256 | `040d963b267aed6952a88bd130bf752156486fde1ca43ab8eae99b97f60a6351` |
| Family label | `unknown` |
| File name | `040d963b267aed6952a88bd130bf752156486fde1ca43ab8eae99b97f60a6351.bin` |
| File type | `macho` |
| First seen | `2026-11-05 00:36:37` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea500dad64bf5dbc971b91fde4ec9e57` |
| SHA-1 | `b01ab4e14c8966c08b1bb60b25887e269c76dc7a` |
| SHA-256 | `040d963b267aed6952a88bd130bf752156486fde1ca43ab8eae99b97f60a6351` |
| SHA3-384 | `0b796ab3a500a74c4ecfd36d72b4255f35c2265b5a8fe3173f81cea1f5cdd989c58cd5cb6c5fe2070726c74e9e61d198` |
| TLSH | `T134E24E43675C5929D05D83BA62FB5B976609F8A00AD45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEA5DbDP67li97WsCdwYjqclS06W1YbqclSl:GI2A5DbDyXwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_040d963b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "040d963b267aed6952a88bd130bf752156486fde1ca43ab8eae99b97f60a6351"
    family = "unknown"
    file_name = "040d963b267aed6952a88bd130bf752156486fde1ca43ab8eae99b97f60a6351.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:36:37"
  condition:
    hash.sha256(0, filesize) == "040d963b267aed6952a88bd130bf752156486fde1ca43ab8eae99b97f60a6351"
}
```

### Sample 96: `914296e90790a586`

| Field | Value |
|---|---|
| SHA-256 | `914296e90790a586056dba87f1d439c69563258fa4bdb596c0c39055e8bcee35` |
| Family label | `unknown` |
| File name | `914296e90790a586056dba87f1d439c69563258fa4bdb596c0c39055e8bcee35.bin` |
| File type | `macho` |
| First seen | `2026-11-05 00:35:54` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f48f6347b451c352efbd9e44e40aaf0` |
| SHA-1 | `eb4e92a3acc8132b357c030d3bda039e6db2a6dd` |
| SHA-256 | `914296e90790a586056dba87f1d439c69563258fa4bdb596c0c39055e8bcee35` |
| SHA3-384 | `da1019149a23bc769785e59866e75a003858125973a813408fc4bbe8454b659b1700edb7dc140e4df94b2dd35d5512e1` |
| TLSH | `T1DBE24E43675C5929D05D83BA22FB5B976609F8A009D45B432F90DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEp5DbDP67li97WsCJwYjqclS06W1YbqclSl:GI2p5DbDyfwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_914296e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "914296e90790a586056dba87f1d439c69563258fa4bdb596c0c39055e8bcee35"
    family = "unknown"
    file_name = "914296e90790a586056dba87f1d439c69563258fa4bdb596c0c39055e8bcee35.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:35:54"
  condition:
    hash.sha256(0, filesize) == "914296e90790a586056dba87f1d439c69563258fa4bdb596c0c39055e8bcee35"
}
```

### Sample 97: `e706e384b5af1a7c`

| Field | Value |
|---|---|
| SHA-256 | `e706e384b5af1a7cb4c8a973f8c98ca7d2d9256168ad68fba3ad38ca7409af63` |
| Family label | `unknown` |
| File name | `e706e384b5af1a7cb4c8a973f8c98ca7d2d9256168ad68fba3ad38ca7409af63.bin` |
| File type | `macho` |
| First seen | `2026-11-05 00:35:45` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11f35b8f0ed4aae1cac78db0cbb46008` |
| SHA-1 | `9d4c4f0a25d868b3fd670720a58c14d2f2f8e5c7` |
| SHA-256 | `e706e384b5af1a7cb4c8a973f8c98ca7d2d9256168ad68fba3ad38ca7409af63` |
| SHA3-384 | `c6fef8161a2311b1fe7ca289ca2b902ec09e51b1cc8deaff03e850d2b22eefadb7d92c62a05229a73bc8339ea160acdb` |
| TLSH | `T1A5F25E139B1C0A61C15C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BEB9D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRzPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfWlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_e706e384
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e706e384b5af1a7cb4c8a973f8c98ca7d2d9256168ad68fba3ad38ca7409af63"
    family = "unknown"
    file_name = "e706e384b5af1a7cb4c8a973f8c98ca7d2d9256168ad68fba3ad38ca7409af63.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:35:45"
  condition:
    hash.sha256(0, filesize) == "e706e384b5af1a7cb4c8a973f8c98ca7d2d9256168ad68fba3ad38ca7409af63"
}
```

### Sample 98: `6de1aad65deeb8d4`

| Field | Value |
|---|---|
| SHA-256 | `6de1aad65deeb8d425e8b3a1b7a7ae23389294e9312d9894592a6d5c70fbc570` |
| Family label | `unknown` |
| File name | `6de1aad65deeb8d425e8b3a1b7a7ae23389294e9312d9894592a6d5c70fbc570.bin` |
| File type | `macho` |
| First seen | `2026-11-05 00:35:39` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4062086c4ebaed67c58cebe778b08b4` |
| SHA-1 | `a389186d1d2663c2cdd332c9e17e5dba23cfc585` |
| SHA-256 | `6de1aad65deeb8d425e8b3a1b7a7ae23389294e9312d9894592a6d5c70fbc570` |
| SHA3-384 | `2df055cf9ebf5a5b50968c7ad645acb79a9b32255947bf8b9a0d4d311bf974bcf5e6ee4964fedda2dda3bce5fbc4f75c` |
| TLSH | `T16AE25E43675C5929C05D83BA22FB1B936609F8B009E45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEn5DbDP67li97WsCvwYjqclS06W1YbqclSl:GI2n5DbDyJwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_6de1aad6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6de1aad65deeb8d425e8b3a1b7a7ae23389294e9312d9894592a6d5c70fbc570"
    family = "unknown"
    file_name = "6de1aad65deeb8d425e8b3a1b7a7ae23389294e9312d9894592a6d5c70fbc570.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:35:39"
  condition:
    hash.sha256(0, filesize) == "6de1aad65deeb8d425e8b3a1b7a7ae23389294e9312d9894592a6d5c70fbc570"
}
```

### Sample 99: `a9e6b663d0bef84c`

| Field | Value |
|---|---|
| SHA-256 | `a9e6b663d0bef84c908daced7319e191d92dc45b8b96cdeddff68998d82d9efb` |
| Family label | `VShell` |
| File name | `a9e6b663d0bef84c908daced7319e191d92dc45b8b96cdeddff68998d82d9efb.exe` |
| File type | `exe` |
| First seen | `2026-11-05 00:35:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e110b6883cc37e21473ab8d52061a8e9` |
| SHA-1 | `cdde0f9a9d6bfb41f53a10e1a5bbd92d2e8c9f7d` |
| SHA-256 | `a9e6b663d0bef84c908daced7319e191d92dc45b8b96cdeddff68998d82d9efb` |
| SHA3-384 | `23960e1d25c47de91851c1e9f960be475e8b9e32cf7408f4ad9850bb2e1abe1bf758a1f1fa058fed8b00758c1ed34ba5` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1F29194C6F757E6B2EC1C17F500A3B994C8682E14927D9B464FA16F1C3C111AA3C2EA12` |
| SSDEEP | `48:6I7lwe7HNU08SLJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1+091q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_099_a9e6b663
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9e6b663d0bef84c908daced7319e191d92dc45b8b96cdeddff68998d82d9efb"
    family = "VShell"
    file_name = "a9e6b663d0bef84c908daced7319e191d92dc45b8b96cdeddff68998d82d9efb.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:35:32"
  condition:
    hash.sha256(0, filesize) == "a9e6b663d0bef84c908daced7319e191d92dc45b8b96cdeddff68998d82d9efb"
}
```

### Sample 100: `7efa266e94b66d38`

| Field | Value |
|---|---|
| SHA-256 | `7efa266e94b66d3826f3a2a36d5985aad96e135f88f37ab589c40bc99ac1ec54` |
| Family label | `RevStealer` |
| File name | `7efa266e94b66d3826f3a2a36d5985aad96e135f88f37ab589c40bc99ac1ec54.exe` |
| File type | `exe` |
| First seen | `2026-11-05 00:34:50` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d32b12952a26d81cc53170ee0a3c48f` |
| SHA-1 | `ba952a3e4958a8ca22e0d4e73ea86c3b261667c7` |
| SHA-256 | `7efa266e94b66d3826f3a2a36d5985aad96e135f88f37ab589c40bc99ac1ec54` |
| SHA3-384 | `33010c2ebd99a43a480f95ac3c553a96936285064e3a22f9ee60facb2ad87a165b17447548f83d7aa64f4cf1ef559888` |
| IMPHASH | `001b63852a413bf6eef528d920bb10b4` |
| TLSH | `T13AE52385BC8635B5F033C3BB426760AFB03937A19BB59C5E2BCA67602D526287C37345` |
| SSDEEP | `49152:k7AgVRQ4bPfarrrLcnkjZ+fvPsRsr5PjEyhGXtD6lva2s3jmKW:aRQ4jfWp+XPtr5b5wGi3s` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_100_7efa266e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7efa266e94b66d3826f3a2a36d5985aad96e135f88f37ab589c40bc99ac1ec54"
    family = "RevStealer"
    file_name = "7efa266e94b66d3826f3a2a36d5985aad96e135f88f37ab589c40bc99ac1ec54.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:34:50"
  condition:
    hash.sha256(0, filesize) == "7efa266e94b66d3826f3a2a36d5985aad96e135f88f37ab589c40bc99ac1ec54"
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
 * Generated: 2026-11-05T06:58:55.340382+00:00
 */

rule MalwareBazaar_unknown_001_89eda144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89eda14459e02dba101cabd74297dc02a6e4bbc957b322c9c6d1d6d4c23372d3"
    family = "unknown"
    file_name = "RuneLiteSetup.exe"
    file_type = "exe"
    first_seen = "2026-11-05 06:52:17"
  condition:
    hash.sha256(0, filesize) == "89eda14459e02dba101cabd74297dc02a6e4bbc957b322c9c6d1d6d4c23372d3"
}

rule MalwareBazaar_RemcosRAT_002_a481fcff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a481fcff23200fdd3f0a3b1c869f9628f28e406562d35d405390be74cc5d4240"
    family = "RemcosRAT"
    file_name = "PO# Material&specification.JS.js"
    file_type = "js"
    first_seen = "2026-11-05 06:50:12"
  condition:
    hash.sha256(0, filesize) == "a481fcff23200fdd3f0a3b1c869f9628f28e406562d35d405390be74cc5d4240"
}

rule MalwareBazaar_Mirai_003_8864b90c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8864b90c5709d66745fa954f692e4d22753c8fd340e37f2cb65e300701e1d268"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:16"
  condition:
    hash.sha256(0, filesize) == "8864b90c5709d66745fa954f692e4d22753c8fd340e37f2cb65e300701e1d268"
}

rule MalwareBazaar_Mirai_004_9502994b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9502994b352f7ce5c1014ee240393a32798f25101b0f58e3cbf7a0220cbaa628"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:13"
  condition:
    hash.sha256(0, filesize) == "9502994b352f7ce5c1014ee240393a32798f25101b0f58e3cbf7a0220cbaa628"
}

rule MalwareBazaar_Mirai_005_39cda269
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39cda2690a97dbb6a9f7c8afd807d84d8cadb0a42ec4d7b0772b4f305ee4c721"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:11"
  condition:
    hash.sha256(0, filesize) == "39cda2690a97dbb6a9f7c8afd807d84d8cadb0a42ec4d7b0772b4f305ee4c721"
}

rule MalwareBazaar_Mirai_006_0e606963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e60696306f2bd98fe97b2e42d1fa4a515904715338b8c3db2ab39084c20e59d"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:09"
  condition:
    hash.sha256(0, filesize) == "0e60696306f2bd98fe97b2e42d1fa4a515904715338b8c3db2ab39084c20e59d"
}

rule MalwareBazaar_Mirai_007_43eb8504
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43eb85040d44c6253623d26c822b567b9f96f0924fa480a0915db583016c1805"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:06"
  condition:
    hash.sha256(0, filesize) == "43eb85040d44c6253623d26c822b567b9f96f0924fa480a0915db583016c1805"
}

rule MalwareBazaar_Mirai_008_dc57d578
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc57d578a326799d2e3c5d9e5b7ffae056245c43644b5d9715e5cd2682f28861"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-11-05 06:07:03"
  condition:
    hash.sha256(0, filesize) == "dc57d578a326799d2e3c5d9e5b7ffae056245c43644b5d9715e5cd2682f28861"
}

rule MalwareBazaar_unknown_009_88d88b49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88d88b49cdad22a516267f4f8404a0d732f5152d5a0d314273bd1fc132c8861d"
    family = "unknown"
    file_name = "darwin_amd64"
    file_type = "macho"
    first_seen = "2026-11-05 06:02:03"
  condition:
    hash.sha256(0, filesize) == "88d88b49cdad22a516267f4f8404a0d732f5152d5a0d314273bd1fc132c8861d"
}

rule MalwareBazaar_SalatStealer_010_e9af795b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9af795bb6786e776a4f5ec420091c8378a168df651feace5c037d884da3904d"
    family = "SalatStealer"
    file_name = "e9af795bb6786e776a4f5ec420091c8378a168df651feace5c037d884da3904d.bin"
    file_type = "bat"
    first_seen = "2026-11-05 05:52:33"
  condition:
    hash.sha256(0, filesize) == "e9af795bb6786e776a4f5ec420091c8378a168df651feace5c037d884da3904d"
}

rule MalwareBazaar_Mirai_011_75685ebe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75685ebe92f65ba4d317f9dd6b068e0fbc378cc7d901ca1f24cef9d3d513a7af"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:23"
  condition:
    hash.sha256(0, filesize) == "75685ebe92f65ba4d317f9dd6b068e0fbc378cc7d901ca1f24cef9d3d513a7af"
}

rule MalwareBazaar_Mirai_012_660cab5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "660cab5accb26eaa2aeef98d7f6fda583a86c99d56a398a3430123f56c17eb2c"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:20"
  condition:
    hash.sha256(0, filesize) == "660cab5accb26eaa2aeef98d7f6fda583a86c99d56a398a3430123f56c17eb2c"
}

rule MalwareBazaar_Mirai_013_f022bc4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f022bc4c2de44d2aebc1170e0d7985e7486b2e5054eb3c46e47840fb543cbc5f"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:18"
  condition:
    hash.sha256(0, filesize) == "f022bc4c2de44d2aebc1170e0d7985e7486b2e5054eb3c46e47840fb543cbc5f"
}

rule MalwareBazaar_Mirai_014_6603f67d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6603f67d9e0947caa92a1614175dc125527eb6dc6ee4d5dfc0330ebd64bd2fea"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:15"
  condition:
    hash.sha256(0, filesize) == "6603f67d9e0947caa92a1614175dc125527eb6dc6ee4d5dfc0330ebd64bd2fea"
}

rule MalwareBazaar_Mirai_015_12029b1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12029b1db51d389f109b6e78d4e666ee06d9332e9c9e80d942dc09f34ad71cb6"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:12"
  condition:
    hash.sha256(0, filesize) == "12029b1db51d389f109b6e78d4e666ee06d9332e9c9e80d942dc09f34ad71cb6"
}

rule MalwareBazaar_Mirai_016_f8e09b98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8e09b989372403de2092b322070dc67b5e302faea267d2d251f652314247516"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:10"
  condition:
    hash.sha256(0, filesize) == "f8e09b989372403de2092b322070dc67b5e302faea267d2d251f652314247516"
}

rule MalwareBazaar_Mirai_017_ca856cd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca856cd80f9dcbaaddaeba08516b7bef12d3fd27150426be9e0fc677fa68a398"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:07"
  condition:
    hash.sha256(0, filesize) == "ca856cd80f9dcbaaddaeba08516b7bef12d3fd27150426be9e0fc677fa68a398"
}

rule MalwareBazaar_Mirai_018_aff27ab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aff27ab2c42fcb41685af982b5b4d29c638a2a465712dc72bb15068f281b5940"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-05 05:45:04"
  condition:
    hash.sha256(0, filesize) == "aff27ab2c42fcb41685af982b5b4d29c638a2a465712dc72bb15068f281b5940"
}

rule MalwareBazaar_RemcosRAT_019_8561ec7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8561ec7bffde32073dc5edab14f4025009c4941a0683bad0eb33d72b37c9caa1"
    family = "RemcosRAT"
    file_name = "Packing List, Commercial Invoice and Bill Of .js"
    file_type = "js"
    first_seen = "2026-11-05 05:30:13"
  condition:
    hash.sha256(0, filesize) == "8561ec7bffde32073dc5edab14f4025009c4941a0683bad0eb33d72b37c9caa1"
}

rule MalwareBazaar_Mirai_020_62a18370
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62a18370ac853198827085fb01a17b56b9d74b13d0b37e9a37f70be1f8c3d616"
    family = "Mirai"
    file_name = "bot-mips"
    file_type = "elf"
    first_seen = "2026-11-05 04:40:03"
  condition:
    hash.sha256(0, filesize) == "62a18370ac853198827085fb01a17b56b9d74b13d0b37e9a37f70be1f8c3d616"
}

rule MalwareBazaar_CoinMiner_021_3f8bcc50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f8bcc5070ae60b49d1dd6e804c2a6bcf24165541d8c35b27e646c83e673f36f"
    family = "CoinMiner"
    file_name = "FleetComputeM2.exe"
    file_type = "exe"
    first_seen = "2026-11-05 03:16:23"
  condition:
    hash.sha256(0, filesize) == "3f8bcc5070ae60b49d1dd6e804c2a6bcf24165541d8c35b27e646c83e673f36f"
}

rule MalwareBazaar_VShell_022_35eb9408
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35eb9408b68c3b07a4230db82ea75de1bc70e7f0c2c92250aa7d21a12fc88d53"
    family = "VShell"
    file_name = "35eb9408b68c3b07a4230db82ea75de1bc70e7f0c2c92250aa7d21a12fc88d53.exe"
    file_type = "exe"
    first_seen = "2026-11-05 03:04:54"
  condition:
    hash.sha256(0, filesize) == "35eb9408b68c3b07a4230db82ea75de1bc70e7f0c2c92250aa7d21a12fc88d53"
}

rule MalwareBazaar_unknown_023_9478ccb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9478ccb9b54de30851f10cb2e388edd672ef9d94c5f9b252a01126bafbdf4d4a"
    family = "unknown"
    file_name = "eda1686d-c620-49a0-ab53-6b6659f6cad1.ps1"
    file_type = "ps1"
    first_seen = "2026-11-05 02:56:13"
  condition:
    hash.sha256(0, filesize) == "9478ccb9b54de30851f10cb2e388edd672ef9d94c5f9b252a01126bafbdf4d4a"
}

rule MalwareBazaar_Arechclient2_024_08f36297
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08f36297e916e15853dcd5c4728f2ad554eda6686e4342867f4653b982d260df"
    family = "Arechclient2"
    file_name = "bbd224f8-8296-404b-ab7c-c93301380271.ps1"
    file_type = "ps1"
    first_seen = "2026-11-05 02:55:53"
  condition:
    hash.sha256(0, filesize) == "08f36297e916e15853dcd5c4728f2ad554eda6686e4342867f4653b982d260df"
}

rule MalwareBazaar_ACRStealer_025_b4a17536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4a17536921c2bbcc395bcf97408b88b7827fb77e0b7831f2c0038f85a37594a"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-05 02:41:14"
  condition:
    hash.sha256(0, filesize) == "b4a17536921c2bbcc395bcf97408b88b7827fb77e0b7831f2c0038f85a37594a"
}

rule MalwareBazaar_WARDENStealer_026_55f7ef2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55f7ef2c480e85fed2b68ac0a6b0a081431cf92118ae0831a8a9275b1eca11e3"
    family = "WARDENStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:40:13"
  condition:
    hash.sha256(0, filesize) == "55f7ef2c480e85fed2b68ac0a6b0a081431cf92118ae0831a8a9275b1eca11e3"
}

rule MalwareBazaar_ACRStealer_027_2e71fa83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e71fa8333960948544fbddbbfb84d6d429aa4accb27016e86b9c2c16a00f49a"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-05 02:38:58"
  condition:
    hash.sha256(0, filesize) == "2e71fa8333960948544fbddbbfb84d6d429aa4accb27016e86b9c2c16a00f49a"
}

rule MalwareBazaar_CNBackdoor_028_f7237fdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7237fdb6fb01955ed81c50b3b9d52169fd9dba03f03c14c6ee14f66a92bf34c"
    family = "CNBackdoor"
    file_name = "Installer31854.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:35:13"
  condition:
    hash.sha256(0, filesize) == "f7237fdb6fb01955ed81c50b3b9d52169fd9dba03f03c14c6ee14f66a92bf34c"
}

rule MalwareBazaar_CNBackdoor_029_ecef5317
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecef5317df8b014e1581d7a4e819c3290c846fac20a0423846f1081071c7304d"
    family = "CNBackdoor"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-11-05 02:34:45"
  condition:
    hash.sha256(0, filesize) == "ecef5317df8b014e1581d7a4e819c3290c846fac20a0423846f1081071c7304d"
}

rule MalwareBazaar_WARDENStealer_030_b7b67b9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7b67b9bb10531738ad2b46cf7d342b8e326577bef5f3505adfc62ed1fc072fb"
    family = "WARDENStealer"
    file_name = "Installer_L_X64_x86_2024.zip"
    file_type = "zip"
    first_seen = "2026-11-05 02:33:36"
  condition:
    hash.sha256(0, filesize) == "b7b67b9bb10531738ad2b46cf7d342b8e326577bef5f3505adfc62ed1fc072fb"
}

rule MalwareBazaar_RemusStealer_031_c2913583
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c291358365226f5b3e6910e8523cdec7af0a7ff01cfca7e92f2bd165235f679f"
    family = "RemusStealer"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:30:30"
  condition:
    hash.sha256(0, filesize) == "c291358365226f5b3e6910e8523cdec7af0a7ff01cfca7e92f2bd165235f679f"
}

rule MalwareBazaar_WARDENStealer_032_b06d0eda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b06d0eda8ef44bf0846fd029d90541dbb18af17b845cbdbbf4f4003b3ff6dd62"
    family = "WARDENStealer"
    file_name = "x86__setup_now.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:29:34"
  condition:
    hash.sha256(0, filesize) == "b06d0eda8ef44bf0846fd029d90541dbb18af17b845cbdbbf4f4003b3ff6dd62"
}

rule MalwareBazaar_RemusStealer_033_579f433f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "579f433fff0ce8781b2c5d84ad082746e917f3ddc64f888945484c8366cd6065"
    family = "RemusStealer"
    file_name = "𝗦𝗘𝗧𝗨𝗣.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:28:47"
  condition:
    hash.sha256(0, filesize) == "579f433fff0ce8781b2c5d84ad082746e917f3ddc64f888945484c8366cd6065"
}

rule MalwareBazaar_RemusStealer_034_c2d8f641
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2d8f64112b56ae88513b140bdcd57c27d0a722e056ba6946918a0ef791a5877"
    family = "RemusStealer"
    file_name = "Setup_Pro.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:28:23"
  condition:
    hash.sha256(0, filesize) == "c2d8f64112b56ae88513b140bdcd57c27d0a722e056ba6946918a0ef791a5877"
}

rule MalwareBazaar_unknown_035_952c2ec4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "952c2ec45f737352610355e570269b25c9cf6e745ca35f7e2d094e20f31ee9b8"
    family = "unknown"
    file_name = "ZA_Access_My_Department.msi"
    file_type = "msi"
    first_seen = "2026-11-05 02:16:21"
  condition:
    hash.sha256(0, filesize) == "952c2ec45f737352610355e570269b25c9cf6e745ca35f7e2d094e20f31ee9b8"
}

rule MalwareBazaar_LunexLoader_036_d869738e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d869738e3908aa88348bf51d97d1a60237f97c0b8850ee6304ff6572451a7f9c"
    family = "LunexLoader"
    file_name = "d869738e3908aa88348bf51d97d1a60237f97c0b8850ee6304ff6572451a7f9c.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:14:36"
  condition:
    hash.sha256(0, filesize) == "d869738e3908aa88348bf51d97d1a60237f97c0b8850ee6304ff6572451a7f9c"
}

rule MalwareBazaar_ConnectWise_037_c2c95640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2c956401bb50a69e8cb0cbcd57a62ec0d6a5a245a050176e59ff5303574b850"
    family = "ConnectWise"
    file_name = "c2c956401bb50a69e8cb0cbcd57a62ec0d6a5a245a050176e59ff5303574b850.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:09:32"
  condition:
    hash.sha256(0, filesize) == "c2c956401bb50a69e8cb0cbcd57a62ec0d6a5a245a050176e59ff5303574b850"
}

rule MalwareBazaar_DonutLoader_038_8657c9c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8657c9c9326b795d4d9c65f1f1e7a219154d59579cc40709c12fd1fb23a4adcb"
    family = "DonutLoader"
    file_name = "8657c9c9326b795d4d9c65f1f1e7a219154d59579cc40709c12fd1fb23a4adcb.exe"
    file_type = "exe"
    first_seen = "2026-11-05 02:04:34"
  condition:
    hash.sha256(0, filesize) == "8657c9c9326b795d4d9c65f1f1e7a219154d59579cc40709c12fd1fb23a4adcb"
}

rule MalwareBazaar_Arechclient2_039_ad6c822f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad6c822ffbe04fdf75c3daa61e02f8754a253e37158ffc888f708bfb0dd9ddd4"
    family = "Arechclient2"
    file_name = "QVKGSYNL(2).exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:39:53"
  condition:
    hash.sha256(0, filesize) == "ad6c822ffbe04fdf75c3daa61e02f8754a253e37158ffc888f708bfb0dd9ddd4"
}

rule MalwareBazaar_Arechclient2_040_5d7c6a2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d7c6a2f5171346e67236e9f4b11a873eae268fa9da744c8951474e168d44727"
    family = "Arechclient2"
    file_name = "QVKGSYNL.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:38:40"
  condition:
    hash.sha256(0, filesize) == "5d7c6a2f5171346e67236e9f4b11a873eae268fa9da744c8951474e168d44727"
}

rule MalwareBazaar_Arechclient2_041_fcd5efaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcd5efaa02928c1d90172d17e7c8b46115546aa25338b708c6472488006f64ea"
    family = "Arechclient2"
    file_name = "NexusSoftware.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:35:01"
  condition:
    hash.sha256(0, filesize) == "fcd5efaa02928c1d90172d17e7c8b46115546aa25338b708c6472488006f64ea"
}

rule MalwareBazaar_Arechclient2_042_a1f020b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1f020b9708cb37c8e084e24dacc11f5bd42ef4ffdd25724ed9057dfb8879f54"
    family = "Arechclient2"
    file_name = "Broker-Carrier Agreement.vbs"
    file_type = "vbs"
    first_seen = "2026-11-05 01:33:42"
  condition:
    hash.sha256(0, filesize) == "a1f020b9708cb37c8e084e24dacc11f5bd42ef4ffdd25724ed9057dfb8879f54"
}

rule MalwareBazaar_unknown_043_3fc10030
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fc100302aaf8d3bf3bf5562454ba01c42dc789bb57435774e8c10c4db25bed8"
    family = "unknown"
    file_name = "media_player.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:30:17"
  condition:
    hash.sha256(0, filesize) == "3fc100302aaf8d3bf3bf5562454ba01c42dc789bb57435774e8c10c4db25bed8"
}

rule MalwareBazaar_unknown_044_fe005e64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe005e64780077d6a34da8067819535f6c9e9d77e27efe70bb783c5d6b444519"
    family = "unknown"
    file_name = "main2_crypted.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:28:12"
  condition:
    hash.sha256(0, filesize) == "fe005e64780077d6a34da8067819535f6c9e9d77e27efe70bb783c5d6b444519"
}

rule MalwareBazaar_unknown_045_ead0b411
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ead0b4114887f8b79a888336e1cd67b7f99e5aa5f46cf681bd5d7f88d9022415"
    family = "unknown"
    file_name = "main2_crypted.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:27:49"
  condition:
    hash.sha256(0, filesize) == "ead0b4114887f8b79a888336e1cd67b7f99e5aa5f46cf681bd5d7f88d9022415"
}

rule MalwareBazaar_unknown_046_a3a6c802
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3a6c802f50a8da181ef46f97c9fd05187aff416c46598351fbd30b254f37d74"
    family = "unknown"
    file_name = "dropper.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:27:05"
  condition:
    hash.sha256(0, filesize) == "a3a6c802f50a8da181ef46f97c9fd05187aff416c46598351fbd30b254f37d74"
}

rule MalwareBazaar_SalatStealer_047_7ffc9fc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ffc9fc2fa198bd14515f90b561d413317f732ddac5a793ba772f490e9992522"
    family = "SalatStealer"
    file_name = "e8b5e1d4d2669aab.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:51"
  condition:
    hash.sha256(0, filesize) == "7ffc9fc2fa198bd14515f90b561d413317f732ddac5a793ba772f490e9992522"
}

rule MalwareBazaar_SalatStealer_048_a7517036
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7517036b9a82e11861ed4f60eaa696c83cf39d2e60d9a0623eef40b8097cb99"
    family = "SalatStealer"
    file_name = "8a6ad36ce9125cd4.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:46"
  condition:
    hash.sha256(0, filesize) == "a7517036b9a82e11861ed4f60eaa696c83cf39d2e60d9a0623eef40b8097cb99"
}

rule MalwareBazaar_SalatStealer_049_fb0f82cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb0f82cf43508b9127a7754907ff2015e35e81f2c245220cdd4d1d55c0f203f6"
    family = "SalatStealer"
    file_name = "a993513992e84b87.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:41"
  condition:
    hash.sha256(0, filesize) == "fb0f82cf43508b9127a7754907ff2015e35e81f2c245220cdd4d1d55c0f203f6"
}

rule MalwareBazaar_SalatStealer_050_c5872379
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5872379a4e0ef3d9b8f891cf1a02dc822cbc36514058b91da13405455d2d9a1"
    family = "SalatStealer"
    file_name = "6426415bdbe96a25.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:35"
  condition:
    hash.sha256(0, filesize) == "c5872379a4e0ef3d9b8f891cf1a02dc822cbc36514058b91da13405455d2d9a1"
}

rule MalwareBazaar_SalatStealer_051_65f98eba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65f98ebab0f692cf186f0336377d079fbc0a4b8335fb7aea8e40e9918ea5b1ef"
    family = "SalatStealer"
    file_name = "879a3ff0164cc29a.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:28"
  condition:
    hash.sha256(0, filesize) == "65f98ebab0f692cf186f0336377d079fbc0a4b8335fb7aea8e40e9918ea5b1ef"
}

rule MalwareBazaar_SalatStealer_052_94ec0b96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94ec0b96dfb8defe58493f68aa448d62d7fc88b532fc34daaf3010d4b4ab1a6e"
    family = "SalatStealer"
    file_name = "4333e8592959d413.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:26:23"
  condition:
    hash.sha256(0, filesize) == "94ec0b96dfb8defe58493f68aa448d62d7fc88b532fc34daaf3010d4b4ab1a6e"
}

rule MalwareBazaar_SalatStealer_053_e8b5e1d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8b5e1d4d2669aabc7cacb497b98dd2181efe0d241bbf0b94625c447a058c7a0"
    family = "SalatStealer"
    file_name = "e8b5e1d4d2669aab.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:59"
  condition:
    hash.sha256(0, filesize) == "e8b5e1d4d2669aabc7cacb497b98dd2181efe0d241bbf0b94625c447a058c7a0"
}

rule MalwareBazaar_SalatStealer_054_8a6ad36c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a6ad36ce9125cd4b6f686b57d80b0bd4de59b1bfd38a7de226ae77fdc0dc9d3"
    family = "SalatStealer"
    file_name = "8a6ad36ce9125cd4.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:52"
  condition:
    hash.sha256(0, filesize) == "8a6ad36ce9125cd4b6f686b57d80b0bd4de59b1bfd38a7de226ae77fdc0dc9d3"
}

rule MalwareBazaar_SalatStealer_055_a9935139
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a993513992e84b8784c20634e98a39c2aaf19000f17d3e051172a7770c2372fb"
    family = "SalatStealer"
    file_name = "a993513992e84b87.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:43"
  condition:
    hash.sha256(0, filesize) == "a993513992e84b8784c20634e98a39c2aaf19000f17d3e051172a7770c2372fb"
}

rule MalwareBazaar_SalatStealer_056_4ef4d1be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ef4d1bec9bc9d189c283e2bf69038016981e259de5e839edb470d7b49decf3b"
    family = "SalatStealer"
    file_name = "69e90c26d71023ac.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:43"
  condition:
    hash.sha256(0, filesize) == "4ef4d1bec9bc9d189c283e2bf69038016981e259de5e839edb470d7b49decf3b"
}

rule MalwareBazaar_SalatStealer_057_0958b64b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0958b64b1b8cdb3c4bc414a5d602fb3ec68c5f21b3417d5793e481d74850bcc6"
    family = "SalatStealer"
    file_name = "e9c117cb31d3c0f3.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:38"
  condition:
    hash.sha256(0, filesize) == "0958b64b1b8cdb3c4bc414a5d602fb3ec68c5f21b3417d5793e481d74850bcc6"
}

rule MalwareBazaar_SalatStealer_058_6426415b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6426415bdbe96a251d2abd46285bf27e751477f2e6da35dd777f5b735e70e37d"
    family = "SalatStealer"
    file_name = "6426415bdbe96a25.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:35"
  condition:
    hash.sha256(0, filesize) == "6426415bdbe96a251d2abd46285bf27e751477f2e6da35dd777f5b735e70e37d"
}

rule MalwareBazaar_CoinMiner_059_b76fe2d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b76fe2d549292ed02ffb467e7c82e8405f5391dbda7a28ee0ba4ea03d785117e"
    family = "CoinMiner"
    file_name = "pyv6.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:28"
  condition:
    hash.sha256(0, filesize) == "b76fe2d549292ed02ffb467e7c82e8405f5391dbda7a28ee0ba4ea03d785117e"
}

rule MalwareBazaar_SalatStealer_060_879a3ff0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "879a3ff0164cc29a1c9a3d218c5bb5881d380a92d965cad4b16658aa9ca56373"
    family = "SalatStealer"
    file_name = "879a3ff0164cc29a.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:27"
  condition:
    hash.sha256(0, filesize) == "879a3ff0164cc29a1c9a3d218c5bb5881d380a92d965cad4b16658aa9ca56373"
}

rule MalwareBazaar_SalatStealer_061_4333e859
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4333e8592959d413729fba335f1065fad42edc41d3f2c1c458d2b87f51d52908"
    family = "SalatStealer"
    file_name = "4333e8592959d413.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:19"
  condition:
    hash.sha256(0, filesize) == "4333e8592959d413729fba335f1065fad42edc41d3f2c1c458d2b87f51d52908"
}

rule MalwareBazaar_SalatStealer_062_69e90c26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69e90c26d71023ac888a93ed063c781eab261bd264597c7eb5ab56592980592f"
    family = "SalatStealer"
    file_name = "69e90c26d71023ac.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:11"
  condition:
    hash.sha256(0, filesize) == "69e90c26d71023ac888a93ed063c781eab261bd264597c7eb5ab56592980592f"
}

rule MalwareBazaar_SalatStealer_063_e9c117cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9c117cb31d3c0f3799a5a6e108eed3b5670005d93c92fb3b053e2a4978fbd37"
    family = "SalatStealer"
    file_name = "e9c117cb31d3c0f3.bin"
    file_type = "exe"
    first_seen = "2026-11-05 01:25:03"
  condition:
    hash.sha256(0, filesize) == "e9c117cb31d3c0f3799a5a6e108eed3b5670005d93c92fb3b053e2a4978fbd37"
}

rule MalwareBazaar_SalatStealer_064_b5d801c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5d801c674e4e0769f83d8eb3b1e4a31c3de18d9a06c9ae9be91a38a8559e6d3"
    family = "SalatStealer"
    file_name = "0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:24:19"
  condition:
    hash.sha256(0, filesize) == "b5d801c674e4e0769f83d8eb3b1e4a31c3de18d9a06c9ae9be91a38a8559e6d3"
}

rule MalwareBazaar_SalatStealer_065_0c065473
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd"
    family = "SalatStealer"
    file_name = "0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:23:13"
  condition:
    hash.sha256(0, filesize) == "0c0654730121fb29936323e2af611d03329b126f94baff113df0313639e778fd"
}

rule MalwareBazaar_unknown_066_335637b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "335637b09436eb911f1df4e38c49f363a2d685629e706e81d39af2ba512d75db"
    family = "unknown"
    file_name = "335637b09436eb911f1df4e38c49f363a2d685629e706e81d39af2ba512d75db.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:23:08"
  condition:
    hash.sha256(0, filesize) == "335637b09436eb911f1df4e38c49f363a2d685629e706e81d39af2ba512d75db"
}

rule MalwareBazaar_unknown_067_fc50c17a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc50c17aea0190a2d8096b592c9b7e9ba6bae2026b7010e2291ef6011544ffe4"
    family = "unknown"
    file_name = "fc50c17aea0190a2d8096b592c9b7e9ba6bae2026b7010e2291ef6011544ffe4.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:21:26"
  condition:
    hash.sha256(0, filesize) == "fc50c17aea0190a2d8096b592c9b7e9ba6bae2026b7010e2291ef6011544ffe4"
}

rule MalwareBazaar_VShell_068_19bec5bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19bec5bf63667616099fa3d77ee17a62c4fef45916776f6b439ce53c8bca91b7"
    family = "VShell"
    file_name = "19bec5bf63667616099fa3d77ee17a62c4fef45916776f6b439ce53c8bca91b7.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:21:22"
  condition:
    hash.sha256(0, filesize) == "19bec5bf63667616099fa3d77ee17a62c4fef45916776f6b439ce53c8bca91b7"
}

rule MalwareBazaar_unknown_069_d51fa4d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51fa4d820d32a6c6ad71cb715abdebabf5aa0ec4ed07ff4ee3b67e0f208d9ef"
    family = "unknown"
    file_name = "d51fa4d820d32a6c6ad71cb715abdebabf5aa0ec4ed07ff4ee3b67e0f208d9ef.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:21:18"
  condition:
    hash.sha256(0, filesize) == "d51fa4d820d32a6c6ad71cb715abdebabf5aa0ec4ed07ff4ee3b67e0f208d9ef"
}

rule MalwareBazaar_VShell_070_9ccb2b7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ccb2b7d0fdc7d47b305d9ae9e5703a4fb3f35ded599b27ab4e337f000a57d80"
    family = "VShell"
    file_name = "9ccb2b7d0fdc7d47b305d9ae9e5703a4fb3f35ded599b27ab4e337f000a57d80.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:20:31"
  condition:
    hash.sha256(0, filesize) == "9ccb2b7d0fdc7d47b305d9ae9e5703a4fb3f35ded599b27ab4e337f000a57d80"
}

rule MalwareBazaar_unknown_071_b2a78954
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2a789549b2b96e8be6c1a0ca36a6ddbd1e5e02cf428518ab01658abf5b07b17"
    family = "unknown"
    file_name = "b2a789549b2b96e8be6c1a0ca36a6ddbd1e5e02cf428518ab01658abf5b07b17.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:20:26"
  condition:
    hash.sha256(0, filesize) == "b2a789549b2b96e8be6c1a0ca36a6ddbd1e5e02cf428518ab01658abf5b07b17"
}

rule MalwareBazaar_VShell_072_de182a07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de182a07b5f109ce416f4566f5ba5625bb7dac71b0c1b3a460aa32078e55d31e"
    family = "VShell"
    file_name = "de182a07b5f109ce416f4566f5ba5625bb7dac71b0c1b3a460aa32078e55d31e.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:20:22"
  condition:
    hash.sha256(0, filesize) == "de182a07b5f109ce416f4566f5ba5625bb7dac71b0c1b3a460aa32078e55d31e"
}

rule MalwareBazaar_VShell_073_e9765324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e976532487513f4a01b616760b405cf55a724c9e87d444984eba3a8cc4181504"
    family = "VShell"
    file_name = "e976532487513f4a01b616760b405cf55a724c9e87d444984eba3a8cc4181504.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:20:18"
  condition:
    hash.sha256(0, filesize) == "e976532487513f4a01b616760b405cf55a724c9e87d444984eba3a8cc4181504"
}

rule MalwareBazaar_unknown_074_72cf2e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72cf2e12d0a69f0d7cfaa0e809cd6c64bd4f588c5c03c7e6e86f992e2ebc4255"
    family = "unknown"
    file_name = "72cf2e12d0a69f0d7cfaa0e809cd6c64bd4f588c5c03c7e6e86f992e2ebc4255.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:14:31"
  condition:
    hash.sha256(0, filesize) == "72cf2e12d0a69f0d7cfaa0e809cd6c64bd4f588c5c03c7e6e86f992e2ebc4255"
}

rule MalwareBazaar_unknown_075_d585f01b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d585f01b08c96736c7a9156794b73511e2571e9b5b7320e5eaba9be4c4d9c603"
    family = "unknown"
    file_name = "d585f01b08c96736c7a9156794b73511e2571e9b5b7320e5eaba9be4c4d9c603.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:14:27"
  condition:
    hash.sha256(0, filesize) == "d585f01b08c96736c7a9156794b73511e2571e9b5b7320e5eaba9be4c4d9c603"
}

rule MalwareBazaar_unknown_076_2a1b4f0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a1b4f0a5e6061de7eaf8e5e1b3aa16407522350458d586e05342843b4607875"
    family = "unknown"
    file_name = "2a1b4f0a5e6061de7eaf8e5e1b3aa16407522350458d586e05342843b4607875.bin"
    file_type = "macho"
    first_seen = "2026-11-05 01:14:22"
  condition:
    hash.sha256(0, filesize) == "2a1b4f0a5e6061de7eaf8e5e1b3aa16407522350458d586e05342843b4607875"
}

rule MalwareBazaar_VShell_077_643d7a79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "643d7a79d4adffd085c09ea4aea6333559e3373388a9fc21b8e553d04707c7b0"
    family = "VShell"
    file_name = "643d7a79d4adffd085c09ea4aea6333559e3373388a9fc21b8e553d04707c7b0.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:14:19"
  condition:
    hash.sha256(0, filesize) == "643d7a79d4adffd085c09ea4aea6333559e3373388a9fc21b8e553d04707c7b0"
}

rule MalwareBazaar_unknown_078_904130cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "904130cdbd874463325c9f90f11ee0cdc74002f217f05364dec89e34b9a03f98"
    family = "unknown"
    file_name = "FarzaCraft.zip"
    file_type = "zip"
    first_seen = "2026-11-05 01:13:19"
  condition:
    hash.sha256(0, filesize) == "904130cdbd874463325c9f90f11ee0cdc74002f217f05364dec89e34b9a03f98"
}

rule MalwareBazaar_NetSupport_079_550fe764
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "550fe7647faf8dd9c0c5166c785fdc754ac444ad3f948eafcbe28a55bfca7cab"
    family = "NetSupport"
    file_name = "swwagger.x64_Ajic.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:09:42"
  condition:
    hash.sha256(0, filesize) == "550fe7647faf8dd9c0c5166c785fdc754ac444ad3f948eafcbe28a55bfca7cab"
}

rule MalwareBazaar_NetSupport_080_da200708
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da20070812bc969f0460a2841c75a7972d0ffc3a1b3a8b1d53d59a496028722e"
    family = "NetSupport"
    file_name = "AutoAppSetup.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:08:52"
  condition:
    hash.sha256(0, filesize) == "da20070812bc969f0460a2841c75a7972d0ffc3a1b3a8b1d53d59a496028722e"
}

rule MalwareBazaar_NetSupport_081_90bba4c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90bba4c2d5e07c42ebd2df49c2387a2a73bac01c970ddc9b7a98030c825b04a7"
    family = "NetSupport"
    file_name = "helm3301.msi"
    file_type = "msi"
    first_seen = "2026-11-05 01:07:40"
  condition:
    hash.sha256(0, filesize) == "90bba4c2d5e07c42ebd2df49c2387a2a73bac01c970ddc9b7a98030c825b04a7"
}

rule MalwareBazaar_VShell_082_cd66f76c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd66f76c1487d4d0bbc4053edf355213cbad9323ded6b4ba910a915e1b5a85c8"
    family = "VShell"
    file_name = "cd66f76c1487d4d0bbc4053edf355213cbad9323ded6b4ba910a915e1b5a85c8.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:07:22"
  condition:
    hash.sha256(0, filesize) == "cd66f76c1487d4d0bbc4053edf355213cbad9323ded6b4ba910a915e1b5a85c8"
}

rule MalwareBazaar_VShell_083_57b01705
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57b017057e3721545040cadb9d4cbc3abb945fa405315e8775cadb3b463899b0"
    family = "VShell"
    file_name = "57b017057e3721545040cadb9d4cbc3abb945fa405315e8775cadb3b463899b0.exe"
    file_type = "exe"
    first_seen = "2026-11-05 01:02:17"
  condition:
    hash.sha256(0, filesize) == "57b017057e3721545040cadb9d4cbc3abb945fa405315e8775cadb3b463899b0"
}

rule MalwareBazaar_WannaCry_084_092dd2e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "092dd2e5365b858d6bd6b3c16089752e85ee7f79056f95f6ebc4ce085f7f4b62"
    family = "WannaCry"
    file_name = "7b0707b5317700669e083def02efad58"
    file_type = "dll"
    first_seen = "2026-11-05 00:59:42"
  condition:
    hash.sha256(0, filesize) == "092dd2e5365b858d6bd6b3c16089752e85ee7f79056f95f6ebc4ce085f7f4b62"
}

rule MalwareBazaar_unknown_085_24b84f28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24b84f2811c12ad7eb4e85720e25baaf073f078152b238bef55badbda59010db"
    family = "unknown"
    file_name = "Unlock_Kit-Pro_v4.3.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:57:41"
  condition:
    hash.sha256(0, filesize) == "24b84f2811c12ad7eb4e85720e25baaf073f078152b238bef55badbda59010db"
}

rule MalwareBazaar_unknown_086_9e961800
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e96180048ace1c8acca44f9da4120f09b08fc593ef987e7ae6494000477070c"
    family = "unknown"
    file_name = "Set-up.msi"
    file_type = "msi"
    first_seen = "2026-11-05 00:57:03"
  condition:
    hash.sha256(0, filesize) == "9e96180048ace1c8acca44f9da4120f09b08fc593ef987e7ae6494000477070c"
}

rule MalwareBazaar_RemusStealer_087_9fda93f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fda93f718605288bcf36aae42183aadb60c91e67e4b98cf94b1ca7105f906c6"
    family = "RemusStealer"
    file_name = "Setup_x64.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:55:49"
  condition:
    hash.sha256(0, filesize) == "9fda93f718605288bcf36aae42183aadb60c91e67e4b98cf94b1ca7105f906c6"
}

rule MalwareBazaar_RevStealer_088_99e5c10c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99e5c10c08b4d3389c374622cb506f029ff558e3e6086ac5494c95e75ba1a099"
    family = "RevStealer"
    file_name = "Set-up 2026.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:54:20"
  condition:
    hash.sha256(0, filesize) == "99e5c10c08b4d3389c374622cb506f029ff558e3e6086ac5494c95e75ba1a099"
}

rule MalwareBazaar_RemusStealer_089_629abf05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "629abf0597954bffd00e8bb645270850e83ee7e3c23d467ed3f4da16169c8da3"
    family = "RemusStealer"
    file_name = "Photoshop.2026.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:53:11"
  condition:
    hash.sha256(0, filesize) == "629abf0597954bffd00e8bb645270850e83ee7e3c23d467ed3f4da16169c8da3"
}

rule MalwareBazaar_WARDENStealer_090_6d1194a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d1194a3f15a46b0045f0700f664fe191f8da4502902e85ba55066f386b24650"
    family = "WARDENStealer"
    file_name = "CorelDRAW Graphics Suite 2026 Activator.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:51:46"
  condition:
    hash.sha256(0, filesize) == "6d1194a3f15a46b0045f0700f664fe191f8da4502902e85ba55066f386b24650"
}

rule MalwareBazaar_unknown_091_4e472f1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e472f1a5d14cf690e18943c0fede03185b0faf82429b7ac1ee81e5b7639139c"
    family = "unknown"
    file_name = "Amazon追跡.apk"
    file_type = "apk"
    first_seen = "2026-11-05 00:47:25"
  condition:
    hash.sha256(0, filesize) == "4e472f1a5d14cf690e18943c0fede03185b0faf82429b7ac1ee81e5b7639139c"
}

rule MalwareBazaar_unknown_092_afca81a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afca81a7e62e4570fcb00ddb050a746e15eac6b1dd64a8f2e39778dc63ddfe0f"
    family = "unknown"
    file_name = "afca81a7e62e4570fcb00ddb050a746e15eac6b1dd64a8f2e39778dc63ddfe0f.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:39:54"
  condition:
    hash.sha256(0, filesize) == "afca81a7e62e4570fcb00ddb050a746e15eac6b1dd64a8f2e39778dc63ddfe0f"
}

rule MalwareBazaar_unknown_093_502e9079
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "502e907908fd37ef0973fef47ac868af4ab0ced2ec2e3d572904c9d256e60387"
    family = "unknown"
    file_name = "502e907908fd37ef0973fef47ac868af4ab0ced2ec2e3d572904c9d256e60387.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:39:47"
  condition:
    hash.sha256(0, filesize) == "502e907908fd37ef0973fef47ac868af4ab0ced2ec2e3d572904c9d256e60387"
}

rule MalwareBazaar_unknown_094_14a685db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14a685db9c2988a2a27e5eb0dbd02b70783585155be5120b0d56897297b8ebcf"
    family = "unknown"
    file_name = "14a685db9c2988a2a27e5eb0dbd02b70783585155be5120b0d56897297b8ebcf.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:39:36"
  condition:
    hash.sha256(0, filesize) == "14a685db9c2988a2a27e5eb0dbd02b70783585155be5120b0d56897297b8ebcf"
}

rule MalwareBazaar_unknown_095_040d963b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "040d963b267aed6952a88bd130bf752156486fde1ca43ab8eae99b97f60a6351"
    family = "unknown"
    file_name = "040d963b267aed6952a88bd130bf752156486fde1ca43ab8eae99b97f60a6351.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:36:37"
  condition:
    hash.sha256(0, filesize) == "040d963b267aed6952a88bd130bf752156486fde1ca43ab8eae99b97f60a6351"
}

rule MalwareBazaar_unknown_096_914296e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "914296e90790a586056dba87f1d439c69563258fa4bdb596c0c39055e8bcee35"
    family = "unknown"
    file_name = "914296e90790a586056dba87f1d439c69563258fa4bdb596c0c39055e8bcee35.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:35:54"
  condition:
    hash.sha256(0, filesize) == "914296e90790a586056dba87f1d439c69563258fa4bdb596c0c39055e8bcee35"
}

rule MalwareBazaar_unknown_097_e706e384
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e706e384b5af1a7cb4c8a973f8c98ca7d2d9256168ad68fba3ad38ca7409af63"
    family = "unknown"
    file_name = "e706e384b5af1a7cb4c8a973f8c98ca7d2d9256168ad68fba3ad38ca7409af63.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:35:45"
  condition:
    hash.sha256(0, filesize) == "e706e384b5af1a7cb4c8a973f8c98ca7d2d9256168ad68fba3ad38ca7409af63"
}

rule MalwareBazaar_unknown_098_6de1aad6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6de1aad65deeb8d425e8b3a1b7a7ae23389294e9312d9894592a6d5c70fbc570"
    family = "unknown"
    file_name = "6de1aad65deeb8d425e8b3a1b7a7ae23389294e9312d9894592a6d5c70fbc570.bin"
    file_type = "macho"
    first_seen = "2026-11-05 00:35:39"
  condition:
    hash.sha256(0, filesize) == "6de1aad65deeb8d425e8b3a1b7a7ae23389294e9312d9894592a6d5c70fbc570"
}

rule MalwareBazaar_VShell_099_a9e6b663
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9e6b663d0bef84c908daced7319e191d92dc45b8b96cdeddff68998d82d9efb"
    family = "VShell"
    file_name = "a9e6b663d0bef84c908daced7319e191d92dc45b8b96cdeddff68998d82d9efb.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:35:32"
  condition:
    hash.sha256(0, filesize) == "a9e6b663d0bef84c908daced7319e191d92dc45b8b96cdeddff68998d82d9efb"
}

rule MalwareBazaar_RevStealer_100_7efa266e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7efa266e94b66d3826f3a2a36d5985aad96e135f88f37ab589c40bc99ac1ec54"
    family = "RevStealer"
    file_name = "7efa266e94b66d3826f3a2a36d5985aad96e135f88f37ab589c40bc99ac1ec54.exe"
    file_type = "exe"
    first_seen = "2026-11-05 00:34:50"
  condition:
    hash.sha256(0, filesize) == "7efa266e94b66d3826f3a2a36d5985aad96e135f88f37ab589c40bc99ac1ec54"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

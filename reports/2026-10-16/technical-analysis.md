# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-16

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 686 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 686 |
| Unique family labels | 16 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 55 |
| Mirai | 26 |
| SalatStealer | 3 |
| AMOS | 3 |
| njrat | 2 |
| AgentTesla | 1 |
| Vidar | 1 |
| ConnectWise | 1 |
| CoinMiner | 1 |
| WannaCry | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 48 |
| elf | 27 |
| hta | 9 |
| zip | 5 |
| macho | 3 |
| rar | 2 |
| sh | 2 |
| js | 2 |
| vbs | 1 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `2fcb530e9fc950da`

| Field | Value |
|---|---|
| SHA-256 | `2fcb530e9fc950da8f43f38beb90beb63b26730f53b7e954b3813fe213ccd060` |
| Family label | `unknown` |
| File name | `mbupload-g68ppj6r.bin` |
| File type | `rar` |
| First seen | `2026-10-16 04:32:46` |
| Reporter | `wristhulk` |
| Tags | `rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd43a6913acedce67511e5f1118eeb93` |
| SHA-1 | `bdb50571a445bb5cc3d0526b99c2d2f8a4fe9fd4` |
| SHA-256 | `2fcb530e9fc950da8f43f38beb90beb63b26730f53b7e954b3813fe213ccd060` |
| SHA3-384 | `9bfdea64b3556b560085d5da6dcb605ab19bd70df5c4d7fd711e54467708fe2b44eb04d21ea25e2c7a5ccb41b5d17f1f` |
| TLSH | `T1E2B633B7E07BC1D84AEC1A04F25995A040A01DA9D0731C26F317AB59BBE0BF70D6677E` |
| SSDEEP | `196608:JNat5ZGfGOSMKFP9QDk/CKC5NqOxd4/9rt6BSQ1Fd4EyVm:Jct5Z6G1MKFP+I//C5N34FroSQf+Eyc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_2fcb530e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fcb530e9fc950da8f43f38beb90beb63b26730f53b7e954b3813fe213ccd060"
    family = "unknown"
    file_name = "mbupload-g68ppj6r.bin"
    file_type = "rar"
    first_seen = "2026-10-16 04:32:46"
  condition:
    hash.sha256(0, filesize) == "2fcb530e9fc950da8f43f38beb90beb63b26730f53b7e954b3813fe213ccd060"
}
```

### Sample 2: `d5d1874bec53d5af`

| Field | Value |
|---|---|
| SHA-256 | `d5d1874bec53d5afa09ef36ae3e88630122e14c6f224b14752e5bd014d51fe16` |
| Family label | `unknown` |
| File name | `mbupload-100x05rt.bin` |
| File type | `rar` |
| First seen | `2026-10-16 04:32:30` |
| Reporter | `wristhulk` |
| Tags | `rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e991f44253df774654ff35853135466` |
| SHA-1 | `04a041139a68e3d40f47d4e428ce1bca25f7e1ee` |
| SHA-256 | `d5d1874bec53d5afa09ef36ae3e88630122e14c6f224b14752e5bd014d51fe16` |
| SHA3-384 | `1f900462a94190f27d2c22501ac36df10d2498fbf4d0244b238b1c9f4c74eb227773b4bff5168cfd3fbfcfd9f8c926ed` |
| TLSH | `T102B633B7E03B81D94AED2904F25991A000B01DA991731C26F31B6B5ABBE0FF70D6577E` |
| SSDEEP | `196608:JNat5ZGfGOSMKFP9QDk/CKC5NqOxd4/9rt6BSQ1Fd4EyVA:Jct5Z6G1MKFP+I//C5N34FroSQf+EyS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_d5d1874b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5d1874bec53d5afa09ef36ae3e88630122e14c6f224b14752e5bd014d51fe16"
    family = "unknown"
    file_name = "mbupload-100x05rt.bin"
    file_type = "rar"
    first_seen = "2026-10-16 04:32:30"
  condition:
    hash.sha256(0, filesize) == "d5d1874bec53d5afa09ef36ae3e88630122e14c6f224b14752e5bd014d51fe16"
}
```

### Sample 3: `dcbe27c0161bdf19`

| Field | Value |
|---|---|
| SHA-256 | `dcbe27c0161bdf1922bf060c50b086031a7ffde000bff3bf4fae3df10bbbd096` |
| Family label | `unknown` |
| File name | `mbupload-g4p5uyvx.bin` |
| File type | `zip` |
| First seen | `2026-10-16 04:31:17` |
| Reporter | `wristhulk` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e810f3f39f28f0335b9c2c5aa589a54a` |
| SHA-1 | `c3bde724d88b047fe11a90ffe31fe9cfa66bc2d8` |
| SHA-256 | `dcbe27c0161bdf1922bf060c50b086031a7ffde000bff3bf4fae3df10bbbd096` |
| SHA3-384 | `162532b23c217d694786fc03e01a619a8713842397c1393f75b34e6757db42e49a9bb43472f5c0129c5285a389a83031` |
| TLSH | `T1DBB633D8DC8615CAF5CB7D399BB434ABD1C02A294B61F2ECD047B3E09A7E1F80D91469` |
| SSDEEP | `196608:+Y2ZBID3eWh6bmh1EtbmJ9DuYOZauzFTyN3mgg/tkJY+0Td5UWmgFzmOO/fb9:+YuID37hjhaxmJ96YrsTy1mNFkJYAWmH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_dcbe27c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcbe27c0161bdf1922bf060c50b086031a7ffde000bff3bf4fae3df10bbbd096"
    family = "unknown"
    file_name = "mbupload-g4p5uyvx.bin"
    file_type = "zip"
    first_seen = "2026-10-16 04:31:17"
  condition:
    hash.sha256(0, filesize) == "dcbe27c0161bdf1922bf060c50b086031a7ffde000bff3bf4fae3df10bbbd096"
}
```

### Sample 4: `77d5542a5b29e500`

| Field | Value |
|---|---|
| SHA-256 | `77d5542a5b29e500d9bb571bb191fc787074c411ed73e543eea8e1769a13105a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 04:31:07` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd342490f4c01ff357fd7c0499f19bfb` |
| SHA-1 | `3bb286174bddfa2007bdd14e462d7e70936c9b72` |
| SHA-256 | `77d5542a5b29e500d9bb571bb191fc787074c411ed73e543eea8e1769a13105a` |
| SHA3-384 | `df48f2497b7766ace076e26a6e55f7d423b5583069f3ab7f4a72dff6ec223dd47ab2db8858ac2b2d538286d7b1f0e03e` |
| IMPHASH | `2e99ad1b4b334717df6cb07076301a4e` |
| TLSH | `T1F206E04326DB0CE5DED32B7865DB233AA735FE748B6A8B6B8114C1302C135D1AD2EB51` |
| SSDEEP | `98304:lSEjBbQ5D/60AD3XqaLxKTFgEuny6FRMOQx90ol4t:i5ADRx6puy6Ijsoqt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_77d5542a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77d5542a5b29e500d9bb571bb191fc787074c411ed73e543eea8e1769a13105a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 04:31:07"
  condition:
    hash.sha256(0, filesize) == "77d5542a5b29e500d9bb571bb191fc787074c411ed73e543eea8e1769a13105a"
}
```

### Sample 5: `2a9d70d79cf080d7`

| Field | Value |
|---|---|
| SHA-256 | `2a9d70d79cf080d7037f624722d40c4f39374f2a4459d3331ed608c293b0176e` |
| Family label | `unknown` |
| File name | `mbupload-wqe_lfhw.bin` |
| File type | `zip` |
| First seen | `2026-10-16 04:31:03` |
| Reporter | `wristhulk` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `536dfb53d4223cb425b53608d3dc78e1` |
| SHA-1 | `7ea22aabd87a55b3b8aca0a815fa8d49c7ac414d` |
| SHA-256 | `2a9d70d79cf080d7037f624722d40c4f39374f2a4459d3331ed608c293b0176e` |
| SHA3-384 | `85c344cae80d33006fa9c96a613188e048d49714fc454cb14b6fe51856d8932e82aee86465963c4551cdf10b8876cc9f` |
| TLSH | `T144B633DCEAD489CDE5C6343A67E449D295D40F3AA791BAD6E00123E104BF1EA1DE10BF` |
| SSDEEP | `196608:PXEpMX+nbohNcYmwDHyymKz5TFlVTWg4+r1kJuCwyJ542MKPdVgM5psa:PX3X+UhKwDsaTFlZ3zxkJuH2MKPdVgMv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_2a9d70d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a9d70d79cf080d7037f624722d40c4f39374f2a4459d3331ed608c293b0176e"
    family = "unknown"
    file_name = "mbupload-wqe_lfhw.bin"
    file_type = "zip"
    first_seen = "2026-10-16 04:31:03"
  condition:
    hash.sha256(0, filesize) == "2a9d70d79cf080d7037f624722d40c4f39374f2a4459d3331ed608c293b0176e"
}
```

### Sample 6: `3f1f116c327d7d35`

| Field | Value |
|---|---|
| SHA-256 | `3f1f116c327d7d35af96e73ccf68b95d2422782d904f0715834b99e27a7465b4` |
| Family label | `unknown` |
| File name | `mbupload-ax2anxuk.bin` |
| File type | `zip` |
| First seen | `2026-10-16 04:30:43` |
| Reporter | `wristhulk` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a6037c08d25d2bf7ec7c54b5241f380` |
| SHA-1 | `3a6e155f31238df153595a5d5282b8bc8e170021` |
| SHA-256 | `3f1f116c327d7d35af96e73ccf68b95d2422782d904f0715834b99e27a7465b4` |
| SHA3-384 | `59e0cb0a714c7b40b6a6e4d483a6bb573cc2748c5b7d5d175e1a15e18366cbcd68b21e0738d1acbaa4b242c71c68c599` |
| TLSH | `T1DEB633ACC7C204F77EC8FDAD52ED8AC6E0855E99CA8CF5EDE604139187266E10D16F09` |
| SSDEEP | `196608:qPpPHZiPIOT5JzQTVd4qOkipVkJ0u7Wh5Q67MViar7XCmqoLOwXg1JTBJ6FUURo:qP1ZiPIiyTT4d/TkJ0c6wiarVLFQ1BBJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_3f1f116c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f1f116c327d7d35af96e73ccf68b95d2422782d904f0715834b99e27a7465b4"
    family = "unknown"
    file_name = "mbupload-ax2anxuk.bin"
    file_type = "zip"
    first_seen = "2026-10-16 04:30:43"
  condition:
    hash.sha256(0, filesize) == "3f1f116c327d7d35af96e73ccf68b95d2422782d904f0715834b99e27a7465b4"
}
```

### Sample 7: `34b78a64d76e3d03`

| Field | Value |
|---|---|
| SHA-256 | `34b78a64d76e3d03455fa25dda4292eea59dea145f0c3f2c2addcb7380ff988b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 04:29:58` |
| Reporter | `Bitsight` |
| Tags | `B, BB1.file, dropped-by-GCleaner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ddabfd1ba4063dfbac30101c47229f8` |
| SHA-1 | `bdcd8c58d06d588362161d325b4e9eee4d44f30c` |
| SHA-256 | `34b78a64d76e3d03455fa25dda4292eea59dea145f0c3f2c2addcb7380ff988b` |
| SHA3-384 | `a8805b3640379a120ecf6a79eaacb6a66f8d1c25b2fca19403d5b5e4985921a05ad95a099f041345a01b6d381913ee0b` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1A0C633A99FD011FAD22EF27485D3372AC77B74291BE39E8F43566CA10F735944829B02` |
| SSDEEP | `196608:tQdpV9sN6fpp1Wqj0gY8HYXQ6ZsIAZaNAextA7e8HLPYRwuZnQQ3ifXURu6qFaDC:usNS1f0D8CTsIAanxuK8c8XUU63YF` |
| ICON-DHASH | `8270e88e61d8a400` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_34b78a64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34b78a64d76e3d03455fa25dda4292eea59dea145f0c3f2c2addcb7380ff988b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 04:29:58"
  condition:
    hash.sha256(0, filesize) == "34b78a64d76e3d03455fa25dda4292eea59dea145f0c3f2c2addcb7380ff988b"
}
```

### Sample 8: `e096855e3202ad91`

| Field | Value |
|---|---|
| SHA-256 | `e096855e3202ad914ea6ff670e1872d813f6104f3c0b4ed878d0fb376a772c5b` |
| Family label | `SalatStealer` |
| File name | `111.exe` |
| File type | `exe` |
| First seen | `2026-10-16 04:26:31` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `420fd012909f99f3f38a16e091e008b5` |
| SHA-1 | `409bddbe8f8348f70acf3a604b39b834a6b5b36f` |
| SHA-256 | `e096855e3202ad914ea6ff670e1872d813f6104f3c0b4ed878d0fb376a772c5b` |
| SHA3-384 | `df079741d47411d556fe2dd8dfbcdfb1382a897b16f203ae752ecd2437010d77d03091e33b950587c10cc7a4b2e7205d` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T184C65C11FACB54F6F9036831416BB37F23315D048B28DB9BEB583B6AF877691186A305` |
| SSDEEP | `49152:UkaoyWxn9wH6bAld59ZZ6eKCDt3Z61ihSxoC5lQidRc63qGSAn+mT4ZOMG8sWctw:UoZxgd57E/CpZfGXNSYQdd0y46eEF` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_008_e096855e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e096855e3202ad914ea6ff670e1872d813f6104f3c0b4ed878d0fb376a772c5b"
    family = "SalatStealer"
    file_name = "111.exe"
    file_type = "exe"
    first_seen = "2026-10-16 04:26:31"
  condition:
    hash.sha256(0, filesize) == "e096855e3202ad914ea6ff670e1872d813f6104f3c0b4ed878d0fb376a772c5b"
}
```

### Sample 9: `93b60bb3affff182`

| Field | Value |
|---|---|
| SHA-256 | `93b60bb3affff182a38cfd66c956204db0509a72844a8ff69582892e16437646` |
| Family label | `SalatStealer` |
| File name | `111.exe` |
| File type | `exe` |
| First seen | `2026-10-16 04:25:59` |
| Reporter | `Parper` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7787b0d859a098508a1e4324ef0338d2` |
| SHA-1 | `9772f0bb6b9b320b0ff95be4a769e00c47966181` |
| SHA-256 | `93b60bb3affff182a38cfd66c956204db0509a72844a8ff69582892e16437646` |
| SHA3-384 | `70ab4b1121b954c5724488648050a57a130766d6f2130d51e7e76991d8c1b7af952077a5991402e9ac8a884ee1e210a0` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T158F533928B2A931CC32AC8FAC7E6385179DDC945F3ADACD584C9270CB2D9DC099CD275` |
| SSDEEP | `98304:lWvMVFU5ozO1d5hqVgstDWSOvsXPEh0Akjr4dcMQ:cQFdK1d50y0QaPImjr+` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_009_93b60bb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93b60bb3affff182a38cfd66c956204db0509a72844a8ff69582892e16437646"
    family = "SalatStealer"
    file_name = "111.exe"
    file_type = "exe"
    first_seen = "2026-10-16 04:25:59"
  condition:
    hash.sha256(0, filesize) == "93b60bb3affff182a38cfd66c956204db0509a72844a8ff69582892e16437646"
}
```

### Sample 10: `3180cf557014640e`

| Field | Value |
|---|---|
| SHA-256 | `3180cf557014640edb8525d0029ca2ccb51ad1515288ba12a7c65fe9d872d91b` |
| Family label | `unknown` |
| File name | `3180cf557014640edb8525d0029ca2ccb51ad1515288ba12a7c65fe9d872d91b` |
| File type | `sh` |
| First seen | `2026-10-16 04:20:59` |
| Reporter | `vlasovmichael` |
| Tags | `downloader.medusa, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `501f0ae78b8d48b23dbdbea312dbe98e` |
| SHA-1 | `a8acb53a3c9aa551c8cc6463c98281f9c22ead3e` |
| SHA-256 | `3180cf557014640edb8525d0029ca2ccb51ad1515288ba12a7c65fe9d872d91b` |
| SHA3-384 | `c0e760f4a9f5d93dcfc3efce93f3a6282c1baae5f0f9521c6be74d8314bdb7b500ff25b8975c3b38970636961ff516af` |
| TLSH | `T12531B9CE21A24A70BCA5B96B337E844031D4E5EF19CA5F986CEC3DF5489EE04B010B93` |
| SSDEEP | `24:vdHK+dHZdHAc4kdHlasdHhdHIsdH7K+dH3EsdHZdHzJdHoGdHa:vTHn4kLbPbA+H3dJHw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_3180cf55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3180cf557014640edb8525d0029ca2ccb51ad1515288ba12a7c65fe9d872d91b"
    family = "unknown"
    file_name = "3180cf557014640edb8525d0029ca2ccb51ad1515288ba12a7c65fe9d872d91b"
    file_type = "sh"
    first_seen = "2026-10-16 04:20:59"
  condition:
    hash.sha256(0, filesize) == "3180cf557014640edb8525d0029ca2ccb51ad1515288ba12a7c65fe9d872d91b"
}
```

### Sample 11: `3fac4942b8c74610`

| Field | Value |
|---|---|
| SHA-256 | `3fac4942b8c7461044de38bdc07fdb7e7f21a70c51434f1248e9c5b85e657e02` |
| Family label | `AgentTesla` |
| File name | `Payment Confirmation - Invoice No. INV-2026-1048.js` |
| File type | `js` |
| First seen | `2026-10-16 04:16:01` |
| Reporter | `nat` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe0fdf817ef154f70dcc44ad6c6343a7` |
| SHA-1 | `ccc8063ee4fb8585a2214aec18d40a6d5f4f6c76` |
| SHA-256 | `3fac4942b8c7461044de38bdc07fdb7e7f21a70c51434f1248e9c5b85e657e02` |
| SHA3-384 | `494bdda2c4b052fb8165ca2e1a0ea300b6a5bcaff47eb3e1ae8b335fb1217e0b5ede985af7c0afff91cd66f41bb8ea58` |
| TLSH | `T147F2D944068578949377AB3BAA26D8D4FB7B067701884503B87CB894EFF2D18DEE4DB1` |
| SSDEEP | `768:rZFmWrA9hmYkjFCkqpm1MzJGv9VXvMAt3gP2QHUOCmQ0VLk5+pn6jdGQ6KF6UvRm:VF3+oreE9yOCKU0E5` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_011_3fac4942
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fac4942b8c7461044de38bdc07fdb7e7f21a70c51434f1248e9c5b85e657e02"
    family = "AgentTesla"
    file_name = "Payment Confirmation - Invoice No. INV-2026-1048.js"
    file_type = "js"
    first_seen = "2026-10-16 04:16:01"
  condition:
    hash.sha256(0, filesize) == "3fac4942b8c7461044de38bdc07fdb7e7f21a70c51434f1248e9c5b85e657e02"
}
```

### Sample 12: `5a417f4582f91f21`

| Field | Value |
|---|---|
| SHA-256 | `5a417f4582f91f21f2842b170d21cf5f92b48fad39183e315d505d5a2deef5c0` |
| Family label | `unknown` |
| File name | `mbupload-94wt5_hu.bin` |
| File type | `zip` |
| First seen | `2026-10-16 04:15:36` |
| Reporter | `wristhulk` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbbef4ff727315c1abc519d74f1af0a8` |
| SHA-1 | `6a813c5e3c77d0e37bd76584caa6c9960391f6e1` |
| SHA-256 | `5a417f4582f91f21f2842b170d21cf5f92b48fad39183e315d505d5a2deef5c0` |
| SHA3-384 | `392d90c1b6566d016b1156731b9ef475b904b702dd741ea11e7ac3975262c436550fb0d9c656a2b39ee8c74b7791ae6b` |
| TLSH | `T1F8B633ECC6403CCDE887BA39CBE819EAE9D58A37CA10E5E6D145A3E024BE1FD1C51457` |
| SSDEEP | `196608:Ooslj+RxnaqYfoYhvhVo6PfrlPW2zvT6VpsaurXkJWcaiJ5uQdQnBhI:OflinDUh7o67QaT6vslTkJWlQdQnBi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_5a417f45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a417f4582f91f21f2842b170d21cf5f92b48fad39183e315d505d5a2deef5c0"
    family = "unknown"
    file_name = "mbupload-94wt5_hu.bin"
    file_type = "zip"
    first_seen = "2026-10-16 04:15:36"
  condition:
    hash.sha256(0, filesize) == "5a417f4582f91f21f2842b170d21cf5f92b48fad39183e315d505d5a2deef5c0"
}
```

### Sample 13: `73b0347a300e8d5b`

| Field | Value |
|---|---|
| SHA-256 | `73b0347a300e8d5b13d37ea451069999b8266093f47c9c461ddf85568e9f9245` |
| Family label | `unknown` |
| File name | `mbupload-fmdqlau9.bin` |
| File type | `zip` |
| First seen | `2026-10-16 04:15:20` |
| Reporter | `wristhulk` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e7938db8d817d0294075aa8975ba419` |
| SHA-1 | `1a0d450e80850c8bc7d5e8e8e8c238e501f71d94` |
| SHA-256 | `73b0347a300e8d5b13d37ea451069999b8266093f47c9c461ddf85568e9f9245` |
| SHA3-384 | `66c5713c4bc5c7e69a4d64f3e729aa6d9533a503b50ea10ea2d10b30905de4bdc830680f56bbff117240d38e042baa16` |
| TLSH | `T142B633E8C64138CDE887BA3D8BE819EBE9C9CA36CA10E5E6D145B3E0247E1FD1C51457` |
| SSDEEP | `196608:roslj+RxnaqYfoYhvhVo6PfrlPW2zvT6VpsaurXkJWcaiJ5uQdQnBhv:rflinDUh7o67QaT6vslTkJWlQdQnBZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_73b0347a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73b0347a300e8d5b13d37ea451069999b8266093f47c9c461ddf85568e9f9245"
    family = "unknown"
    file_name = "mbupload-fmdqlau9.bin"
    file_type = "zip"
    first_seen = "2026-10-16 04:15:20"
  condition:
    hash.sha256(0, filesize) == "73b0347a300e8d5b13d37ea451069999b8266093f47c9c461ddf85568e9f9245"
}
```

### Sample 14: `d172a3bd408a9a96`

| Field | Value |
|---|---|
| SHA-256 | `d172a3bd408a9a96b9e18ca3e7da896ad5c6014cedb61d827919e10df040683e` |
| Family label | `unknown` |
| File name | `fuck_niggers_26.hta` |
| File type | `hta` |
| First seen | `2026-10-16 04:06:29` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `335a0d896586930473fe322b8a31c577` |
| SHA-1 | `a4ab0e542484973bbf3a7d6094eace27ba3e9058` |
| SHA-256 | `d172a3bd408a9a96b9e18ca3e7da896ad5c6014cedb61d827919e10df040683e` |
| SHA3-384 | `78dddb6e1d4028eb18f8049971779b6b30241078209c317d50aa14cb77609798d797e4cc223898c6936ced58ae0957e6` |
| TLSH | `T121422A4CAED1A1B0FA0707DDB3AF24690228A0973009C484F54CDEE87F0ABDC4A57B57` |
| SSDEEP | `192:skHNsGeTHQpD+da6+888+UV7tDoj/pxznbqFtCcSJaoRUzHO:skX+/DV7k/3+Ft2aoRUzHO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_d172a3bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d172a3bd408a9a96b9e18ca3e7da896ad5c6014cedb61d827919e10df040683e"
    family = "unknown"
    file_name = "fuck_niggers_26.hta"
    file_type = "hta"
    first_seen = "2026-10-16 04:06:29"
  condition:
    hash.sha256(0, filesize) == "d172a3bd408a9a96b9e18ca3e7da896ad5c6014cedb61d827919e10df040683e"
}
```

### Sample 15: `74b12e4a6b80ede0`

| Field | Value |
|---|---|
| SHA-256 | `74b12e4a6b80ede0f200112a144043e8441b794b72298358a4fe054dcb925fde` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 04:05:28` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e119917d244df3ef12375757931ff973` |
| SHA-1 | `d59489b2141048963aeb373662f019181b13ed69` |
| SHA-256 | `74b12e4a6b80ede0f200112a144043e8441b794b72298358a4fe054dcb925fde` |
| SHA3-384 | `a95c8d800c4af4942e30b3fd981463b60765877bf2eda40c5149dac522d9d158ede987db08b8d934a8865cab3d0c2342` |
| IMPHASH | `2e99ad1b4b334717df6cb07076301a4e` |
| TLSH | `T1E606E08326DB0CF9DED32B7865DB633AA735FE708B6A4B6B8114C13068131D16D2EB51` |
| SSDEEP | `98304:lSEjBbQ5DVMoBjILzdkcyxRrK6JEKJrR496XaMRlA7:7YcHdkvvK6JjR+lMRlK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_74b12e4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74b12e4a6b80ede0f200112a144043e8441b794b72298358a4fe054dcb925fde"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 04:05:28"
  condition:
    hash.sha256(0, filesize) == "74b12e4a6b80ede0f200112a144043e8441b794b72298358a4fe054dcb925fde"
}
```

### Sample 16: `b19eb1e98d0ebf25`

| Field | Value |
|---|---|
| SHA-256 | `b19eb1e98d0ebf251376dd1c76e2cc6544356adecb415880c6103aae2292dacb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 04:04:13` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX3.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb03491a01603109cc3caaba58bb75ad` |
| SHA-1 | `be808f38f456e5063c1bd33c0a1a327cde1e00ed` |
| SHA-256 | `b19eb1e98d0ebf251376dd1c76e2cc6544356adecb415880c6103aae2292dacb` |
| SHA3-384 | `8dbe03406646156b4209ca5ca75589a5cee9146531a16b26c71aa96b57192e2a336cd5c08bf58120ed5376c8694e2a50` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1F6C6339D9FA011FAD26EF1B08593BA1ADB3BB83D17E29F8F43596C610F371485829710` |
| SSDEEP | `196608:tQdPsCGxQllByuyHb/c2zZ7sNyo8d6h7mNT1VBjuP9GvainYQgSe2qc7df:PCGo3XC/cMZBo8d6hizYQgSRhf` |
| ICON-DHASH | `8270e88e61d8a400` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_b19eb1e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b19eb1e98d0ebf251376dd1c76e2cc6544356adecb415880c6103aae2292dacb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 04:04:13"
  condition:
    hash.sha256(0, filesize) == "b19eb1e98d0ebf251376dd1c76e2cc6544356adecb415880c6103aae2292dacb"
}
```

### Sample 17: `e0b224363b0fac2b`

| Field | Value |
|---|---|
| SHA-256 | `e0b224363b0fac2b9a2ff32f397e1b03feb33b987e8cb85bbfdca2678c7973b1` |
| Family label | `Vidar` |
| File name | `e0b224363b0fac2b9a2ff32f397e1b03feb33b987e8cb85bbfdca2678c7973b1.bin` |
| File type | `exe` |
| First seen | `2026-10-16 03:45:16` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee3196a6eef869b3314c117b85ea4201` |
| SHA-1 | `4822681cf9eb5826c5c1d20df0dd2163e88d67f9` |
| SHA-256 | `e0b224363b0fac2b9a2ff32f397e1b03feb33b987e8cb85bbfdca2678c7973b1` |
| SHA3-384 | `b6ab503b801a50fbbc3ef867855814a9402941e4cf28a79a00679ba20ca6ca33da3c89b3513fcb6f33f57ccaeaea46d7` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T188F5AE0BBE905E78C4DAD73255AA01557A28BC188B383BE71F90B6392F713D18E76F41` |
| SSDEEP | `49152:4iDY/SWowNj6l7eTu3WnlqiVs3cmCNpArsG9Ipb3B:4iiHfqGnIIsHCNpCsG63` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_017_e0b22436
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0b224363b0fac2b9a2ff32f397e1b03feb33b987e8cb85bbfdca2678c7973b1"
    family = "Vidar"
    file_name = "e0b224363b0fac2b9a2ff32f397e1b03feb33b987e8cb85bbfdca2678c7973b1.bin"
    file_type = "exe"
    first_seen = "2026-10-16 03:45:16"
  condition:
    hash.sha256(0, filesize) == "e0b224363b0fac2b9a2ff32f397e1b03feb33b987e8cb85bbfdca2678c7973b1"
}
```

### Sample 18: `2de2cf002786d5e9`

| Field | Value |
|---|---|
| SHA-256 | `2de2cf002786d5e95d2a413aa24e3a7220b62758006cb2ec7c70c3c5ac2d081b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 03:44:38` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa82c2112cdd9c800e9c1a1e9b3f6362` |
| SHA-1 | `704db974905068a9ed6c8f410258bad47c18feab` |
| SHA-256 | `2de2cf002786d5e95d2a413aa24e3a7220b62758006cb2ec7c70c3c5ac2d081b` |
| SHA3-384 | `ac163d0e5732c64f06d97b71797ccd4cb63b7136a5c98c5a15d3ff598441c8077b50c06d691106f82877c5a29e3453f3` |
| IMPHASH | `2e99ad1b4b334717df6cb07076301a4e` |
| TLSH | `T1D706E04326DB1CF9DE932B7864DB633AA735FE708B6A8B6B8104C1305C135D1AC6EB51` |
| SSDEEP | `98304:lSEjBbQ5DfFc5nUe3pt91A3FsHJsYT+4akWY8qI:wiUe3pz1A3aHmgakJI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_2de2cf00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2de2cf002786d5e95d2a413aa24e3a7220b62758006cb2ec7c70c3c5ac2d081b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 03:44:38"
  condition:
    hash.sha256(0, filesize) == "2de2cf002786d5e95d2a413aa24e3a7220b62758006cb2ec7c70c3c5ac2d081b"
}
```

### Sample 19: `b1cc5ad78b72d2f0`

| Field | Value |
|---|---|
| SHA-256 | `b1cc5ad78b72d2f0a94d370e840e24ea38a31690ece3af851da345975da7ca5c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 03:19:08` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, SLOT0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd43519650bf3de09d993e9f01560a78` |
| SHA-1 | `0babeadf546eee56b56c6054bd9fee28372c7411` |
| SHA-256 | `b1cc5ad78b72d2f0a94d370e840e24ea38a31690ece3af851da345975da7ca5c` |
| SHA3-384 | `ea6e89e0483a6cdd434841056346c6d8ff8209022fbbc920dc6f55dcc338568555226487d4d7b933fc68371c738023f8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19454B610F9E58299F0B75B71CBD978FA56ADF6B2AF06522940CD23020E335B1EDD3426` |
| SSDEEP | `3072:YAIg/QxeUMj14glS/FY1uEresLmg69bGWJ3v3sZUBoBFhnPd+h7BOWXw7xI2wllc:AGSlMOVdYtep9btJ3vsmAru7hwymTY` |
| ICON-DHASH | `7179496571597133` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_b1cc5ad7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1cc5ad78b72d2f0a94d370e840e24ea38a31690ece3af851da345975da7ca5c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 03:19:08"
  condition:
    hash.sha256(0, filesize) == "b1cc5ad78b72d2f0a94d370e840e24ea38a31690ece3af851da345975da7ca5c"
}
```

### Sample 20: `51c23cd7ae3be097`

| Field | Value |
|---|---|
| SHA-256 | `51c23cd7ae3be097ad412657d6e03b4794fbc19853da07f24609fb7148610a5f` |
| Family label | `ConnectWise` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 02:57:20` |
| Reporter | `Bitsight` |
| Tags | `B, ConnectWise, dropped-by-GCleaner, exe, MIX4.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ffefcd7dc6e26535d2e89fddc8fac73` |
| SHA-1 | `449222a2b4f7ceb5c42974fcaf994848c55e2254` |
| SHA-256 | `51c23cd7ae3be097ad412657d6e03b4794fbc19853da07f24609fb7148610a5f` |
| SHA3-384 | `a11e751cdcc853c19244a1d6cbecc54e6b69cb02682d77ff44272b4d627d9e2b287525e4bc7b30fd410a9fd7becd877f` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T19246E011B3D295B6C17F0638C87A56A96774BC048316CBBB57D4BD396E32BC04E323A6` |
| SSDEEP | `98304:hzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:hhfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_020_51c23cd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51c23cd7ae3be097ad412657d6e03b4794fbc19853da07f24609fb7148610a5f"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 02:57:20"
  condition:
    hash.sha256(0, filesize) == "51c23cd7ae3be097ad412657d6e03b4794fbc19853da07f24609fb7148610a5f"
}
```

### Sample 21: `8bdb3ce10dee7a32`

| Field | Value |
|---|---|
| SHA-256 | `8bdb3ce10dee7a3249a186050d7f804bca19859f292ddad7ae8c5afbb649a07b` |
| Family label | `unknown` |
| File name | `8bdb3ce10dee7a3249a186050d7f804bca19859f292ddad7ae8c5afbb649a07b.exe` |
| File type | `exe` |
| First seen | `2026-10-16 02:29:38` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `216c3eae24901482bfd26cb9dca1a833` |
| SHA-1 | `f6000cc06cbc9f0e748b81cfac77eb2598f71e69` |
| SHA-256 | `8bdb3ce10dee7a3249a186050d7f804bca19859f292ddad7ae8c5afbb649a07b` |
| SHA3-384 | `3940b544c17d9378cfc864298cf16095ef4d77c2649d1f894196c953ad24d6fecac033cad54cb20903c6793acd6c667e` |
| IMPHASH | `2c4f8364dc2c225221cd7dc66caea7e0` |
| TLSH | `T1B1459D1272C580B2E17202305E7D9B768AFDBD240B2196DF67846B2D9F34FD22D36726` |
| SSDEEP | `24576:gwTJ6A1eP1Pm9zhTaUe0K9XXVYFEjd6/Gr+AK9hhEfSVgPCS3tMrMyj3F9hIF1SR:r5ra0K9ndjd6/GXKvhISVE3tMx3FE1Sr` |
| ICON-DHASH | `e2f2eeaadae4e098` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_8bdb3ce1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bdb3ce10dee7a3249a186050d7f804bca19859f292ddad7ae8c5afbb649a07b"
    family = "unknown"
    file_name = "8bdb3ce10dee7a3249a186050d7f804bca19859f292ddad7ae8c5afbb649a07b.exe"
    file_type = "exe"
    first_seen = "2026-10-16 02:29:38"
  condition:
    hash.sha256(0, filesize) == "8bdb3ce10dee7a3249a186050d7f804bca19859f292ddad7ae8c5afbb649a07b"
}
```

### Sample 22: `0e6d59fcdf8f143e`

| Field | Value |
|---|---|
| SHA-256 | `0e6d59fcdf8f143e23b076cc8380d6d23324839ae4f91793133b600e7eb76eb9` |
| Family label | `unknown` |
| File name | `0e6d59fcdf8f143e23b076cc8380d6d23324839ae4f91793133b600e7eb76eb9.exe` |
| File type | `exe` |
| First seen | `2026-10-16 02:28:48` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f0dd4150efddfc20b70401479964211` |
| SHA-1 | `e97c802a8013b13fb91a831b779ade7c3ca6870b` |
| SHA-256 | `0e6d59fcdf8f143e23b076cc8380d6d23324839ae4f91793133b600e7eb76eb9` |
| SHA3-384 | `f65a6bc6253e6e63a4e6196e964dd0a8f1a0ff27f0042d6c9b2136cf0987e914ad51093de53bab9692999e4a3b53115b` |
| IMPHASH | `d8c629b29d617e5840b52a1eb7e78d11` |
| TLSH | `T15E556D4A77A841F8D076D1758AA78A57E7B2B80A073187EF07D0A25A1F73AF05E3D311` |
| SSDEEP | `24576:uLGfO4noYBPtVY3HPou37urInN48pGrnofSVgPCS3tMrMyj3F9hIF1SqY5cbaF:uLGfKY5tVY3gur9N4p0SVE3tMx3FE1Sr` |
| ICON-DHASH | `e2f2eeaadae4e098` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_0e6d59fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e6d59fcdf8f143e23b076cc8380d6d23324839ae4f91793133b600e7eb76eb9"
    family = "unknown"
    file_name = "0e6d59fcdf8f143e23b076cc8380d6d23324839ae4f91793133b600e7eb76eb9.exe"
    file_type = "exe"
    first_seen = "2026-10-16 02:28:48"
  condition:
    hash.sha256(0, filesize) == "0e6d59fcdf8f143e23b076cc8380d6d23324839ae4f91793133b600e7eb76eb9"
}
```

### Sample 23: `0b8b6f4f90506e65`

| Field | Value |
|---|---|
| SHA-256 | `0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339` |
| Family label | `unknown` |
| File name | `0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339.exe` |
| File type | `exe` |
| First seen | `2026-10-16 02:28:09` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ef2eb622132bd45c41c2cd8ce9af710` |
| SHA-1 | `bd3d5f50ff4210d177cfbc155b679352ac809416` |
| SHA-256 | `0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339` |
| SHA3-384 | `b396728d2dcf64fa8044606ed81f2f6e11f4832566744452306ddd887f4b6bbc3d5a45772759521694f8634669242290` |
| IMPHASH | `d710b3ad33962ff162e3c3aa7722d763` |
| TLSH | `T1EAE55B06B647A46CC84AC0B0524B5A766A2174CA0F35BEEF46D593383FB6BF61F3D604` |
| SSDEEP | `49152:k8cQ+qyxqWqMkqdzUKXQnqWhMrVrYonjvnXqpomoERv:XMS0WqWMmGrE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_0b8b6f4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339"
    family = "unknown"
    file_name = "0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339.exe"
    file_type = "exe"
    first_seen = "2026-10-16 02:28:09"
  condition:
    hash.sha256(0, filesize) == "0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339"
}
```

### Sample 24: `3240e7ab26be062b`

| Field | Value |
|---|---|
| SHA-256 | `3240e7ab26be062b3eba73429916b77a9894fffd76af12ac699a4e15676fc384` |
| Family label | `Mirai` |
| File name | `fghe3tj.arm` |
| File type | `elf` |
| First seen | `2026-10-16 02:14:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3d670161c4c6440d1e75f7e3152fb95` |
| SHA-1 | `ce42dbafe47b296781bdae277324ed9c340ef097` |
| SHA-256 | `3240e7ab26be062b3eba73429916b77a9894fffd76af12ac699a4e15676fc384` |
| SHA3-384 | `0cf7a1d5e51524ae8f4186ea8c92c384ee767d6e2704c0d090c4b077eaf16f7837ffa8b14b4dbca565379f5a7146fcc4` |
| TLSH | `T103142955F8419A17C6D612BBFB4E428D372A23A8D3EE7103DD259F21378B96B0A3B141` |
| TELFHASH | `t158b0124841eb14b47993c96180034b32515010e24b0403a00f800e9840a38c27033c08` |
| SSDEEP | `3072:yDwCqIzPLRjMvbCnsBvkCeQY6Oi7nH4CJT396z8KCJwwqz:yDpPFnsBviTWH4Cl396zKJwd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_3240e7ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3240e7ab26be062b3eba73429916b77a9894fffd76af12ac699a4e15676fc384"
    family = "Mirai"
    file_name = "fghe3tj.arm"
    file_type = "elf"
    first_seen = "2026-10-16 02:14:48"
  condition:
    hash.sha256(0, filesize) == "3240e7ab26be062b3eba73429916b77a9894fffd76af12ac699a4e15676fc384"
}
```

### Sample 25: `19a3b7924c8f764a`

| Field | Value |
|---|---|
| SHA-256 | `19a3b7924c8f764a4fe6fc2c9fff192f7571cd50023fe37f9cc2ab2f3a4fa091` |
| Family label | `Mirai` |
| File name | `fghe3tj.x86` |
| File type | `elf` |
| First seen | `2026-10-16 02:11:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5218729c0febd43a43ac44ed87454646` |
| SHA-1 | `673819764d068489e9a2f2f2fc6ac43a88499b22` |
| SHA-256 | `19a3b7924c8f764a4fe6fc2c9fff192f7571cd50023fe37f9cc2ab2f3a4fa091` |
| SHA3-384 | `a0b8daf33c9de7c6b07c497fc1ad5536ea363f4ee008560ff92f59522d300643d412cb9cdd3f6193073d13aebe4e218d` |
| TLSH | `T135D38DC1E743D1F4E96205B1103FA7218B76D837942BEB56D7B53D319CA26409B1B36C` |
| TELFHASH | `t1e96147f66aba0df96b805902f28f5b21ed0dab7b242075e348f31961336654143b7c39` |
| SSDEEP | `3072:Az8wogTQ6Gi9rvN38dtvpx3rW1y6+zmOG:Ag2Q2rek3SU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_19a3b792
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19a3b7924c8f764a4fe6fc2c9fff192f7571cd50023fe37f9cc2ab2f3a4fa091"
    family = "Mirai"
    file_name = "fghe3tj.x86"
    file_type = "elf"
    first_seen = "2026-10-16 02:11:23"
  condition:
    hash.sha256(0, filesize) == "19a3b7924c8f764a4fe6fc2c9fff192f7571cd50023fe37f9cc2ab2f3a4fa091"
}
```

### Sample 26: `d3ad28e1f88e8a2d`

| Field | Value |
|---|---|
| SHA-256 | `d3ad28e1f88e8a2d4ad820d5c6ff81605932160197b5831de9d32083a776a40b` |
| Family label | `Mirai` |
| File name | `fghe3tj.sh4` |
| File type | `elf` |
| First seen | `2026-10-16 02:01:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0181e94461a4911496ea974baa21e17` |
| SHA-1 | `eea40174783245d3dcf2af6aa3408ca061a83c55` |
| SHA-256 | `d3ad28e1f88e8a2d4ad820d5c6ff81605932160197b5831de9d32083a776a40b` |
| SHA3-384 | `c623ef3b1f73797c144274783aeb75968b41f9bb658a7ddd1738471872047bde7d5f1d76c787bbb3629f4ad9176a494d` |
| TLSH | `T169F39D63D83A3EACC618D4B0B4F19F7C5B13D97581871EAAA4A7C2719043E8DF5493B8` |
| SSDEEP | `3072:BUStkleu+BqRDV34G4fYl/NiI94wxrWWSzywlA7+f:BUUz8VIGWYl/NRVDSdlAO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_d3ad28e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3ad28e1f88e8a2d4ad820d5c6ff81605932160197b5831de9d32083a776a40b"
    family = "Mirai"
    file_name = "fghe3tj.sh4"
    file_type = "elf"
    first_seen = "2026-10-16 02:01:26"
  condition:
    hash.sha256(0, filesize) == "d3ad28e1f88e8a2d4ad820d5c6ff81605932160197b5831de9d32083a776a40b"
}
```

### Sample 27: `c2f097ae54d4379b`

| Field | Value |
|---|---|
| SHA-256 | `c2f097ae54d4379b3d3c3a14f3171557666f522cda5eed3cc4418bc3e38677ab` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 01:58:39` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `408e94dbc73bfe5d755e3562355c7467` |
| SHA-1 | `7a2fc8cc7ce8c95c71746ed4d01b3755156e1758` |
| SHA-256 | `c2f097ae54d4379b3d3c3a14f3171557666f522cda5eed3cc4418bc3e38677ab` |
| SHA3-384 | `8c3b5c3ddb908586a9cfc67b7d68467ac5b607b9ceecf236b28455317fd88fb9b7f91ed61a9c65a067e02dec248e5cba` |
| IMPHASH | `2e99ad1b4b334717df6cb07076301a4e` |
| TLSH | `T16006F04326DB1CFADED32B7854DB633AA735FE748B6A4B2B8118C13068135D16D2EB50` |
| SSDEEP | `98304:lSEjBbQ5DGHmsiKTYU2yd1xuWk1zjB7673kg0Rx7aU4B:9HmsiKTpLkzOKRx7aU4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_c2f097ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2f097ae54d4379b3d3c3a14f3171557666f522cda5eed3cc4418bc3e38677ab"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 01:58:39"
  condition:
    hash.sha256(0, filesize) == "c2f097ae54d4379b3d3c3a14f3171557666f522cda5eed3cc4418bc3e38677ab"
}
```

### Sample 28: `3fa014e6a9d11e43`

| Field | Value |
|---|---|
| SHA-256 | `3fa014e6a9d11e439b01e1c24263471209be3f5b91129564fe43bff0367191b1` |
| Family label | `Mirai` |
| File name | `Space.arm5` |
| File type | `elf` |
| First seen | `2026-10-16 01:56:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c26555822974bbc98e06194032702a6` |
| SHA-1 | `c417528f7e7a05dc2218b773fa6e0825ddc9cdaf` |
| SHA-256 | `3fa014e6a9d11e439b01e1c24263471209be3f5b91129564fe43bff0367191b1` |
| SHA3-384 | `1812fcc0b123a689d7fe89aec62e6c977c9347923968029fb42ecb16d8fc0c12b27e1a67a05a64dff3ec41c49d67e1d8` |
| TLSH | `T161132946FCC24A3FC2C013BAA66E5A4E3761E3E5D2CB760B9E54577136C620F1D6AD80` |
| TELFHASH | `t1e4e06840fc755e1854e76570dcdc47b095012223606a4b20cf55dae0883f110e30ce4d` |
| SSDEEP | `768:DO2bf2SHD3pDi9ZbyE2h44Gi6ZQqQdMOqU1WJdzBNew3oOw:DiSHDUJn2hPq4dMOJWd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_3fa014e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa014e6a9d11e439b01e1c24263471209be3f5b91129564fe43bff0367191b1"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-10-16 01:56:33"
  condition:
    hash.sha256(0, filesize) == "3fa014e6a9d11e439b01e1c24263471209be3f5b91129564fe43bff0367191b1"
}
```

### Sample 29: `5e8e2270f35bed77`

| Field | Value |
|---|---|
| SHA-256 | `5e8e2270f35bed7743c090f0f7bc1c5fd9da2fb1c364ce5019838ae9c3eaec2b` |
| Family label | `Mirai` |
| File name | `Space.x86_64` |
| File type | `elf` |
| First seen | `2026-10-16 01:56:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `645bd6b9cf4c25c811ad8c40c8ef2e41` |
| SHA-1 | `de08f787cf59f3b63e08e9a461acac4328c936f2` |
| SHA-256 | `5e8e2270f35bed7743c090f0f7bc1c5fd9da2fb1c364ce5019838ae9c3eaec2b` |
| SHA3-384 | `025ba16fa3afbce0581c86c1f69c67b5102a15361f49958fe6e1b62e9a8e06b3029a62771fc7da50c352dd376f320f8b` |
| TLSH | `T1B7733A17BA4080FEC899C43843BABA36DC7274FE1379725A17D8FE366D55E601E29C84` |
| TELFHASH | `t1ad2145b039590da0f0ebe468b305e1561d391a6004e2b8f3d9b790f3eb517870db5427` |
| SSDEEP | `1536:DeuIZobS3QEWYAIb/+w4HnC+8l8AnzcfF:quIZrAEzAIf4HT8l8AzcfF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_5e8e2270
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e8e2270f35bed7743c090f0f7bc1c5fd9da2fb1c364ce5019838ae9c3eaec2b"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-10-16 01:56:28"
  condition:
    hash.sha256(0, filesize) == "5e8e2270f35bed7743c090f0f7bc1c5fd9da2fb1c364ce5019838ae9c3eaec2b"
}
```

### Sample 30: `36736d658d375c66`

| Field | Value |
|---|---|
| SHA-256 | `36736d658d375c661de81054af9afd5156fab149feee2c7a9bfc2637de83be18` |
| Family label | `Mirai` |
| File name | `Space.mips` |
| File type | `elf` |
| First seen | `2026-10-16 01:56:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2067c21ce636631d9de69869c718abb2` |
| SHA-1 | `963cc864449a9e2f1cd6cb7f4efe0fb461ee95ed` |
| SHA-256 | `36736d658d375c661de81054af9afd5156fab149feee2c7a9bfc2637de83be18` |
| SHA3-384 | `07a65f7fdf264029478ea685e8b5ba7c6106b63c71e68ff8811e372533bac184271c4efb00815d6df966db8af18eba01` |
| TLSH | `T1ADA3B44D7E318FBEFBEC823447B39A12A65927D533E1C585D2ADD2011E7024E681FBA4` |
| TELFHASH | `t11a117c18893812f097751c9d6bedff76e6a130cf4a265e378d00f85eaa2dd425e00c1c` |
| SSDEEP | `1536:WpaZOuT/Q3oSQXa1r3J62yqPy/RWLW0edmpwjeLNY0:lZzTha1rZ62yqPy/ULWzjeLNP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_36736d65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36736d658d375c661de81054af9afd5156fab149feee2c7a9bfc2637de83be18"
    family = "Mirai"
    file_name = "Space.mips"
    file_type = "elf"
    first_seen = "2026-10-16 01:56:24"
  condition:
    hash.sha256(0, filesize) == "36736d658d375c661de81054af9afd5156fab149feee2c7a9bfc2637de83be18"
}
```

### Sample 31: `8f0d462dcfda9f6f`

| Field | Value |
|---|---|
| SHA-256 | `8f0d462dcfda9f6f862fac32a16e7388feb28a2edd021af00a567e018a24bfb2` |
| Family label | `Mirai` |
| File name | `Space.x86` |
| File type | `elf` |
| First seen | `2026-10-16 01:56:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b194004da739d89e678cbdcce3fc987` |
| SHA-1 | `2eb8e1ca5a90e8aa4a323c1592d121d33adfc4e8` |
| SHA-256 | `8f0d462dcfda9f6f862fac32a16e7388feb28a2edd021af00a567e018a24bfb2` |
| SHA3-384 | `8bd8136bb3ddef24b848f909c5db73a0a27d74a5ae0ae868be3cd71c537a727b6e447962f98b2f68eff40dd73f3d1ac5` |
| TLSH | `T122634BC9F983D5B6F8970930107ABF639DB3D6BE21A8DA43C3B45536AD12502F412E6C` |
| TELFHASH | `t121214cf75e1e48e8f3c4a840c35eaa55192ad677086136e445b2ccd036e7dc194bdc39` |
| SSDEEP | `1536:TtWvgmAC7sTb6vF7lOvZOWsIyq3XkZSQK:TtDmAC7sn6NJOvwfIyq8K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_8f0d462d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f0d462dcfda9f6f862fac32a16e7388feb28a2edd021af00a567e018a24bfb2"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-10-16 01:56:21"
  condition:
    hash.sha256(0, filesize) == "8f0d462dcfda9f6f862fac32a16e7388feb28a2edd021af00a567e018a24bfb2"
}
```

### Sample 32: `a4db7f02e7c9c0c1`

| Field | Value |
|---|---|
| SHA-256 | `a4db7f02e7c9c0c1a3212f9210f7a313ff657615a84a7eb9f11d6790c57503a9` |
| Family label | `Mirai` |
| File name | `Space.arm7` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1c9791110d26a36736f3abbac0278cf` |
| SHA-1 | `aec263efc75b072c18398494b23b8bdda7d22655` |
| SHA-256 | `a4db7f02e7c9c0c1a3212f9210f7a313ff657615a84a7eb9f11d6790c57503a9` |
| SHA3-384 | `e4d15c157cec34eb14307bc20ab4168ae3a8a21aa969abca3340c15e8d07d3b810ca73dbab0f0d2f2e55b94b44caeb72` |
| TLSH | `T18BF33A46F6418B13C0D61775BADF420933239BA4E3DB73069928BFB43F8679A0E67905` |
| TELFHASH | `t1f821f071133645146a71caa88decb7b2052887122385ff33ef3ac8dc5809095e939c0f` |
| SSDEEP | `3072:hZZRsytEwSqa68RFvmMPnwN+WwJxsTFMDDpyoM/93wC/03:hZZRhGqa68RFvXPY+9JxeFgDpJM/93wp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_a4db7f02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4db7f02e7c9c0c1a3212f9210f7a313ff657615a84a7eb9f11d6790c57503a9"
    family = "Mirai"
    file_name = "Space.arm7"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:34"
  condition:
    hash.sha256(0, filesize) == "a4db7f02e7c9c0c1a3212f9210f7a313ff657615a84a7eb9f11d6790c57503a9"
}
```

### Sample 33: `9662a92247bc031c`

| Field | Value |
|---|---|
| SHA-256 | `9662a92247bc031c6f39c8c72853c46b4a22bce6a73d27f3fb8b3b368522f8b0` |
| Family label | `Mirai` |
| File name | `Space.arm5` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b391bbeec437852d0077e9a790de529e` |
| SHA-1 | `186e0ebb5ba3824809abb1906fb76d06c89a825c` |
| SHA-256 | `9662a92247bc031c6f39c8c72853c46b4a22bce6a73d27f3fb8b3b368522f8b0` |
| SHA3-384 | `584dd2cd9d40864cfe6a4f51e445d7313b438972bd4a631a9b038e12432c279921b453b5ff8e6b8ede123d9b3bbc5f4b` |
| TLSH | `T16192D0615183AE32D4304C72EEF142A7A366CFBDD0F636E75310526C6AC059F367998B` |
| SSDEEP | `384:QJTgbm9lMrpGyeqOyNP1QBFLj/PBkKrsqyN/QTvyIhymdGUop5hto:QgjplNtQBp6YG4Tvds3UozLo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_9662a922
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9662a92247bc031c6f39c8c72853c46b4a22bce6a73d27f3fb8b3b368522f8b0"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:29"
  condition:
    hash.sha256(0, filesize) == "9662a92247bc031c6f39c8c72853c46b4a22bce6a73d27f3fb8b3b368522f8b0"
}
```

### Sample 34: `1128b9ab3653d228`

| Field | Value |
|---|---|
| SHA-256 | `1128b9ab3653d22895991962a0aa5217ae6332b079671bf11c6995b4d15f18ec` |
| Family label | `Mirai` |
| File name | `Space.ppc` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84a501cb270ecfa674e12d8b566f3ee8` |
| SHA-1 | `c490831cb1011b2ed7f532a9f51bbd6ac9f6e517` |
| SHA-256 | `1128b9ab3653d22895991962a0aa5217ae6332b079671bf11c6995b4d15f18ec` |
| SHA3-384 | `0d89d376b7967a92fd8177e6f439bc5b9965cb4425cea49c3b44eccb319232a5c5097ced9066e77d4059abb3214f5cf2` |
| TLSH | `T16B735B41B34C0D43D1971DB03A3F2BD697AFD9D122E4FA852A5F9B4691B2A33144EDC8` |
| SSDEEP | `1536:+A3f+NvWGCFW6z9gFggXAfkNn7I7F+VAN6gZk3tTx:+cf+xxCdhgtQw7I5+DLTx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_1128b9ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1128b9ab3653d22895991962a0aa5217ae6332b079671bf11c6995b4d15f18ec"
    family = "Mirai"
    file_name = "Space.ppc"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:29"
  condition:
    hash.sha256(0, filesize) == "1128b9ab3653d22895991962a0aa5217ae6332b079671bf11c6995b4d15f18ec"
}
```

### Sample 35: `a8dd660d3b9533e6`

| Field | Value |
|---|---|
| SHA-256 | `a8dd660d3b9533e614ed85aa9e84b4c8028793305779c7c92819a51f508f5f62` |
| Family label | `Mirai` |
| File name | `Space.x86_64` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61b667aec994811862a0a805c46cc96f` |
| SHA-1 | `ed945f5dcddb08e0977833640f44aee58e306fd6` |
| SHA-256 | `a8dd660d3b9533e614ed85aa9e84b4c8028793305779c7c92819a51f508f5f62` |
| SHA3-384 | `44d726f8351f16dbe54c762c0e5e279d98d6adc3bba541044c116989051650301cc2e3269b6f1010763996058d46bc48` |
| TLSH | `T14DF2D1D352E1D2B9C9115BB358B64749FCA0938DBD0207BBCD9DA76FC5B2A182D00B62` |
| SSDEEP | `768:Gkjvsa/voIZ5ARgUYT6xQLpUge663/NeHH36od0Ux0nZu:dzHx+RBE/pUg+/NeHVlMZu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_a8dd660d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8dd660d3b9533e614ed85aa9e84b4c8028793305779c7c92819a51f508f5f62"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:27"
  condition:
    hash.sha256(0, filesize) == "a8dd660d3b9533e614ed85aa9e84b4c8028793305779c7c92819a51f508f5f62"
}
```

### Sample 36: `63ae61ea6ed10789`

| Field | Value |
|---|---|
| SHA-256 | `63ae61ea6ed10789573a2434003b791b930ba67c4d5011c0433022102b0c6f7a` |
| Family label | `Mirai` |
| File name | `Space.mips` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24ffe5694eb27a5293ddd91e662b21b7` |
| SHA-1 | `e8094b70fb4d967b00c9de2fcf665a71bd1f061d` |
| SHA-256 | `63ae61ea6ed10789573a2434003b791b930ba67c4d5011c0433022102b0c6f7a` |
| SHA3-384 | `6ef80c0d68662b2097551d37d1bd2254c69e16ab6acb0ad81280eeca6b694f10ff873812370347d23ed76b902d530504` |
| TLSH | `T13D03E1A0A9050FA9DD15D07497EC0BD22A763FDBDC234C1B798AEF875A512F4B04AE90` |
| SSDEEP | `768:EyI187BcUqVq3FD2yKkIMClnW7V291rhNUxDXNgJgGlzDpbuR1JH:Eyf7BcS3WVManZTt2FWVJuF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_63ae61ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63ae61ea6ed10789573a2434003b791b930ba67c4d5011c0433022102b0c6f7a"
    family = "Mirai"
    file_name = "Space.mips"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:25"
  condition:
    hash.sha256(0, filesize) == "63ae61ea6ed10789573a2434003b791b930ba67c4d5011c0433022102b0c6f7a"
}
```

### Sample 37: `2b31b7bdafb0d4c0`

| Field | Value |
|---|---|
| SHA-256 | `2b31b7bdafb0d4c08f517882311ff53a597e1b9f09c0473402045dfe636cf5d3` |
| Family label | `Mirai` |
| File name | `Space.x86` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f82cd441e834458b66913d072c4bc02c` |
| SHA-1 | `79b622238deeb18e3ae77ac7abbae6c24a4c667c` |
| SHA-256 | `2b31b7bdafb0d4c08f517882311ff53a597e1b9f09c0473402045dfe636cf5d3` |
| SHA3-384 | `be8b14900f18dc7f51166a789f3884e04285323bbf552eebb55b724b17cec0121d43ff49f35263d624e0af7209a1f7bf` |
| TLSH | `T1C5F2D189E14B329BF14D01BBCCF7F90E166A8B0ED252A4B31ED4D4371824FA786296C5` |
| SSDEEP | `768:AzbGjwng3vdrlTloggTOM/fuOVeR8dKwm4Fufs06YDnbcuyD7UHQRj6:AdnAdlZMqwuOndK94FuV6ynouy8HyW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_2b31b7bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b31b7bdafb0d4c08f517882311ff53a597e1b9f09c0473402045dfe636cf5d3"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:22"
  condition:
    hash.sha256(0, filesize) == "2b31b7bdafb0d4c08f517882311ff53a597e1b9f09c0473402045dfe636cf5d3"
}
```

### Sample 38: `b1290e0cbc7721e2`

| Field | Value |
|---|---|
| SHA-256 | `b1290e0cbc7721e2f33eefb3ed80b9b2d005ab85f29fd89c82b47ba25195b6c4` |
| Family label | `Mirai` |
| File name | `Space.spc` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d217a2d216fc33484f98cc5006c3250` |
| SHA-1 | `d38af5115f188f4aa104ef3d59eee749f61049e0` |
| SHA-256 | `b1290e0cbc7721e2f33eefb3ed80b9b2d005ab85f29fd89c82b47ba25195b6c4` |
| SHA3-384 | `f937adc890cf2d2152964fecb892ce5a657ebb94a591767ec6518f5595c9f552167c6a1aa76c0d74ae8a542c1f3b1064` |
| TLSH | `T166734B31F9390927C0D4917A61F74723B5F297CA20A8861F3E720F9DBF615403A57AB9` |
| SSDEEP | `1536:U2kN6QCXbqt5guvvF7tR7SYm5BHxS1H1tTEfT:HhilL7SYOBR2EfT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_b1290e0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1290e0cbc7721e2f33eefb3ed80b9b2d005ab85f29fd89c82b47ba25195b6c4"
    family = "Mirai"
    file_name = "Space.spc"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:20"
  condition:
    hash.sha256(0, filesize) == "b1290e0cbc7721e2f33eefb3ed80b9b2d005ab85f29fd89c82b47ba25195b6c4"
}
```

### Sample 39: `8f367ef5666641bd`

| Field | Value |
|---|---|
| SHA-256 | `8f367ef5666641bdfac1e6ab117526792cf89570be786b8ddb769838868fa69a` |
| Family label | `Mirai` |
| File name | `Space.m68k` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ba35b9f42991107ecf36c4a11063806` |
| SHA-1 | `09544241779fe0cde6672fd2ea3a5e2a6b7fee57` |
| SHA-256 | `8f367ef5666641bdfac1e6ab117526792cf89570be786b8ddb769838868fa69a` |
| SHA3-384 | `61d71e0ee546b2925f7e67e800250d42f68d64dee0a5d550fa13a489fb43502aaa65acf8928b7956aeb76da59fe1ed45` |
| TLSH | `T18083198BF800DD7DF80FDAB74453490EB931E3910A931A377767BDA7AC721A14826E85` |
| SSDEEP | `1536:XQOjxmw2V2xAYV8aHTybJYxYAhJ6r48980jTUhtIpu1HHr+t2c9I/bz02z:XQO4QHTVdhJ6rk/tCupy9I/P02z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_8f367ef5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f367ef5666641bdfac1e6ab117526792cf89570be786b8ddb769838868fa69a"
    family = "Mirai"
    file_name = "Space.m68k"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:18"
  condition:
    hash.sha256(0, filesize) == "8f367ef5666641bdfac1e6ab117526792cf89570be786b8ddb769838868fa69a"
}
```

### Sample 40: `26017b4203c78795`

| Field | Value |
|---|---|
| SHA-256 | `26017b4203c787953af0d7b0b4b6140a3fa339d333878aeb55c76681ac249273` |
| Family label | `Mirai` |
| File name | `Space.sh4` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddc7f2ec7ac7e7d3e430808bf50ee4d4` |
| SHA-1 | `23d0140762ebbaa9e6a25896c939cdb01a98f232` |
| SHA-256 | `26017b4203c787953af0d7b0b4b6140a3fa339d333878aeb55c76681ac249273` |
| SHA3-384 | `14730b080f9052b55255db9a8517d1dffd654951b45737c5a39270438590944a97ae314c34a0fcdb0a64ba96f13fd852` |
| TLSH | `T164639E16D8211899C286C5B4B1ECCE3A1B13A5C063837EF7566AC375A067D9CF849FB4` |
| SSDEEP | `1536:Qaw/uMkOts9OWQ1KcTlh7BTRLzCIMpCtPKx/:QZVkwsEWQccnxRLz0GCx/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_26017b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26017b4203c787953af0d7b0b4b6140a3fa339d333878aeb55c76681ac249273"
    family = "Mirai"
    file_name = "Space.sh4"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:15"
  condition:
    hash.sha256(0, filesize) == "26017b4203c787953af0d7b0b4b6140a3fa339d333878aeb55c76681ac249273"
}
```

### Sample 41: `35b2eb3312c9b29b`

| Field | Value |
|---|---|
| SHA-256 | `35b2eb3312c9b29b65fe88a5af1d87407c881e42ee39931e81f1e43050e798ed` |
| Family label | `Mirai` |
| File name | `Space.arm7` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7b653530b82e347c9d171d30ba1eadd` |
| SHA-1 | `43217cd563270f4fbf5c48a1f374720de6f701cc` |
| SHA-256 | `35b2eb3312c9b29b65fe88a5af1d87407c881e42ee39931e81f1e43050e798ed` |
| SHA3-384 | `d724d01caa4d0a7bef9bb627c083fce2aee470d35a4f219c7aaa35c0d495601772c76bc98cd8b4d6c4c0aa455de56936` |
| TLSH | `T1265301143596D0BADB733B72ED081309AB0A92ED61939069520AFBCC65E650B6EE53C3` |
| SSDEEP | `1536:Hm4ZsRNIxwGaLh2wuCFK7x53lfYnkDLL7Ugv7Cu:Hm4ZDx3s1uCFETljDLL7fjD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_35b2eb33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35b2eb3312c9b29b65fe88a5af1d87407c881e42ee39931e81f1e43050e798ed"
    family = "Mirai"
    file_name = "Space.arm7"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:13"
  condition:
    hash.sha256(0, filesize) == "35b2eb3312c9b29b65fe88a5af1d87407c881e42ee39931e81f1e43050e798ed"
}
```

### Sample 42: `29f7706aab236475`

| Field | Value |
|---|---|
| SHA-256 | `29f7706aab236475be7099feb866784cbcb8d9b5c8bdce825082addce5a203cb` |
| Family label | `Mirai` |
| File name | `Space.mpsl` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f73a53f69062bf5926e567ba1392e53` |
| SHA-1 | `bb4087c417c5e3ce63688c02becdc9fcfe5dc211` |
| SHA-256 | `29f7706aab236475be7099feb866784cbcb8d9b5c8bdce825082addce5a203cb` |
| SHA3-384 | `e26e0a535fe93829e86cd9e1ca0393ca595b5da0989d96688d84c124c1a15fa4df0e298fb385fae71f7284aab9c130d4` |
| TLSH | `T18E03E1998C599558EF5E4CBFE0E98BA18F5A50DA37CE67DC7701248CB32A0177C890B4` |
| SSDEEP | `768:XhpGLq2YEGFd9/XVE4627Fh2lqBk2WfQ+tllSM22bBIW3:RpD2YldJlx6Kk2UflUR2bj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_29f7706a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29f7706aab236475be7099feb866784cbcb8d9b5c8bdce825082addce5a203cb"
    family = "Mirai"
    file_name = "Space.mpsl"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:10"
  condition:
    hash.sha256(0, filesize) == "29f7706aab236475be7099feb866784cbcb8d9b5c8bdce825082addce5a203cb"
}
```

### Sample 43: `9e26d0fdff3d1b01`

| Field | Value |
|---|---|
| SHA-256 | `9e26d0fdff3d1b01dea60e235b25cb07307a8142cc615969965d8606ba30cb6f` |
| Family label | `Mirai` |
| File name | `Space.ppc` |
| File type | `elf` |
| First seen | `2026-10-16 01:55:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cdca43e611dfb6c1ca4844f5e536faa` |
| SHA-1 | `9715a54c1c9651e64554777ed2e3535df1bf6c78` |
| SHA-256 | `9e26d0fdff3d1b01dea60e235b25cb07307a8142cc615969965d8606ba30cb6f` |
| SHA3-384 | `770045b0dae8e915479ddfc1184170e2e4ab37cb4479f1d90dc81431c0f7d329a74c6e2a78e3a03068def40ee061beef` |
| TLSH | `T16EF2E125E0027CC2DDEA29F42662DDD67BF33B4E734AB36620C68742611A637211DE40` |
| SSDEEP | `768:cl3cWFWtnMBy3lxB7FFuhJo4N6cA8pkdFecntbvaN4uVcqgw09Z:clsW8Ocl/hqA8pklbE4u+qgw09Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_9e26d0fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e26d0fdff3d1b01dea60e235b25cb07307a8142cc615969965d8606ba30cb6f"
    family = "Mirai"
    file_name = "Space.ppc"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:08"
  condition:
    hash.sha256(0, filesize) == "9e26d0fdff3d1b01dea60e235b25cb07307a8142cc615969965d8606ba30cb6f"
}
```

### Sample 44: `8ca1337be559848c`

| Field | Value |
|---|---|
| SHA-256 | `8ca1337be559848cd3239f6f0fb35f31be98dddab1c003e6b57722dd3ae28e95` |
| Family label | `Mirai` |
| File name | `fghe3tj.arm7` |
| File type | `elf` |
| First seen | `2026-10-16 01:46:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b592a76ca07d16a2506ab75db79bbfba` |
| SHA-1 | `3e6836e92c21132a1ed75f4bd87b77fa40a84b70` |
| SHA-256 | `8ca1337be559848cd3239f6f0fb35f31be98dddab1c003e6b57722dd3ae28e95` |
| SHA3-384 | `cee125c1a198564e4338acb6688f17272f0b006f2435fb1583eae6029f4dfd55fdfe1cee081591e9c5f931bbff957c54` |
| TLSH | `T123442A46FA804E17C4D617B9FA9F42453333E768D3EB72069918AFB43BC775A0E62601` |
| TELFHASH | `t1d7410c718b349526aaa1d914e9fa9372251fdb175390fa33df26c88c140508fea2bc0f` |
| SSDEEP | `6144:kYfTgAFXl7QgG6X+sWdt94aadNU/iPudEbGV21PCyc2V/GvTkBZme2/Mpm:kYfTgARl7QgJNWdt9padNU/iPud8cUne` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_8ca1337b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ca1337be559848cd3239f6f0fb35f31be98dddab1c003e6b57722dd3ae28e95"
    family = "Mirai"
    file_name = "fghe3tj.arm7"
    file_type = "elf"
    first_seen = "2026-10-16 01:46:15"
  condition:
    hash.sha256(0, filesize) == "8ca1337be559848cd3239f6f0fb35f31be98dddab1c003e6b57722dd3ae28e95"
}
```

### Sample 45: `4b8fcd336a3f4f2c`

| Field | Value |
|---|---|
| SHA-256 | `4b8fcd336a3f4f2ce2809b3d7079777f78431bebe22e52bbcf630c775561e3ec` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 01:33:52` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e5c8d16f558d44b8cca2e0724bb8e1c` |
| SHA-1 | `e0524074efefcbbff0eb8faf432290d55ffd8fa8` |
| SHA-256 | `4b8fcd336a3f4f2ce2809b3d7079777f78431bebe22e52bbcf630c775561e3ec` |
| SHA3-384 | `70c26d24284800b0c309bbdc04f0818c981c9233ed6daa7e3cd7cf01a163260a0566b90ae5a2f2fe4ca90e109189d451` |
| IMPHASH | `2e99ad1b4b334717df6cb07076301a4e` |
| TLSH | `T13C06F08326DB1CEADED32B7814DB633AA735FE748B6A4B6B8114C1311C135D1AD2EB50` |
| SSDEEP | `98304:lSEjBbQ5D67EW9ZnQ6Au7N+nROhTMwAMkBZxj1QtbI:U2ZnIcN+wGp1UbI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_4b8fcd33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b8fcd336a3f4f2ce2809b3d7079777f78431bebe22e52bbcf630c775561e3ec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 01:33:52"
  condition:
    hash.sha256(0, filesize) == "4b8fcd336a3f4f2ce2809b3d7079777f78431bebe22e52bbcf630c775561e3ec"
}
```

### Sample 46: `a2b27dee9494b597`

| Field | Value |
|---|---|
| SHA-256 | `a2b27dee9494b5978815784900f167ed093028f1eba443a7d02b11b66def9483` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 01:21:35` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9ac245d4b6a01de4ebff52aa77c5c90` |
| SHA-1 | `801d4d1246d394bd04bb7f911ce20c92305830aa` |
| SHA-256 | `a2b27dee9494b5978815784900f167ed093028f1eba443a7d02b11b66def9483` |
| SHA3-384 | `c9b178121e19b8b300add16fcd6cefa6017e646088e4661cce88c05b6af11a0ac1488d55b365dd111472590b15a7b639` |
| IMPHASH | `9bd4d61f2bdd759a3539d644c013268c` |
| TLSH | `T18032E61E2E460331ED6049B0E6B48A0A567D5DE33796FADBE333C1D70ED9E8684C056B` |
| SSDEEP | `96:uFI25jMBoj/13oj/SE5zk9Eh/BdNXd20BD4+86erSgOcbQfZhVOcIGFJxGE9mi2w:4MatgouBg0hleWz2GFJxTEimFhkucj` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_046_a2b27dee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2b27dee9494b5978815784900f167ed093028f1eba443a7d02b11b66def9483"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 01:21:35"
  condition:
    hash.sha256(0, filesize) == "a2b27dee9494b5978815784900f167ed093028f1eba443a7d02b11b66def9483"
}
```

### Sample 47: `39437aaa739756c8`

| Field | Value |
|---|---|
| SHA-256 | `39437aaa739756c8fd63d59e65c7ffa148906cd14fe6d685c2a0a64eec5cd19a` |
| Family label | `unknown` |
| File name | `Sеt_Uр [UРD].exe` |
| File type | `exe` |
| First seen | `2026-10-16 01:16:37` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed, Stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d7c9dba1c64096f420d211d27f5762c` |
| SHA-1 | `08f5795b1b34b943c16f4e3cdf951bb5265d61b9` |
| SHA-256 | `39437aaa739756c8fd63d59e65c7ffa148906cd14fe6d685c2a0a64eec5cd19a` |
| SHA3-384 | `5722bf8c9e5d7c5dec5717386a51bae5147212d717aa700dc48f18b0160e6872a21a17f3369ff4e3f7bca9f19699dd35` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T157368D17BEA985A9C0A9E735C9B365017634BC4C873123D72F91BB781EB17C18AB9F04` |
| SSDEEP | `49152:SMUgr9hs9s32VAoAMrTCK2S9TuvECzIFHhocaQRLoQ02L6G+wVzGYlr:SMHws3gK1gH7aQpoQn64/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_39437aaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39437aaa739756c8fd63d59e65c7ffa148906cd14fe6d685c2a0a64eec5cd19a"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-16 01:16:37"
  condition:
    hash.sha256(0, filesize) == "39437aaa739756c8fd63d59e65c7ffa148906cd14fe6d685c2a0a64eec5cd19a"
}
```

### Sample 48: `b2f356e15402e11f`

| Field | Value |
|---|---|
| SHA-256 | `b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746` |
| Family label | `WannaCry` |
| File name | `b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746` |
| File type | `exe` |
| First seen | `2026-10-16 01:15:09` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `affe4cd2a433123d83231b353a74e4a6` |
| SHA-1 | `0c820a470461c5fe0db226e2dc4485f116a02d95` |
| SHA-256 | `b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746` |
| SHA3-384 | `de10e9224b16f72862331133a20b2abea1d41a867f6d6a371a36887ca6b6ff3344425622d30b7073c019751478f69b1a` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T13336235A32AC90BCD0166374A4B38E26E6B37C56227D970F8F5487661E13790FF68B13` |
| SSDEEP | `24576:jbLg3bLgddQhfdmMSirYbcMNgef0QeQjG/D8kIqRY:jn2nAQqMSPbcBVQej/1` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_048_b2f356e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746"
    family = "WannaCry"
    file_name = "b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746"
    file_type = "exe"
    first_seen = "2026-10-16 01:15:09"
  condition:
    hash.sha256(0, filesize) == "b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746"
}
```

### Sample 49: `0bc73de0da28e716`

| Field | Value |
|---|---|
| SHA-256 | `0bc73de0da28e7160e3e00c2a2305ea4e4bdf35fb471e42d3da1bd5483b2f85f` |
| Family label | `unknown` |
| File name | `PO_22042026_ORDER_DETAILSpdf.js` |
| File type | `js` |
| First seen | `2026-10-16 01:08:35` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `400eb336caa3523daca8b0ac9b136d1f` |
| SHA-1 | `b843fc37e8c0cdaa465c7443d629fd5ada52f5b0` |
| SHA-256 | `0bc73de0da28e7160e3e00c2a2305ea4e4bdf35fb471e42d3da1bd5483b2f85f` |
| SHA3-384 | `b02c0a8525523defe5bfca7cb115590f66f1029b388a87c9ea7d3cc841cd2a083d4d3719105705699cb9e8ebc1ca4ddb` |
| TLSH | `T1CD250209C6465F8A0DB9D06685414EC17C366537D39A71C0318FAAA7D3ADBFB103F29B` |
| SSDEEP | `24576:KgON8qrQjsqRohcrQCIqWhv3Po71SnU035v9FOcuNM:EzxF4M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_0bc73de0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc73de0da28e7160e3e00c2a2305ea4e4bdf35fb471e42d3da1bd5483b2f85f"
    family = "unknown"
    file_name = "PO_22042026_ORDER_DETAILSpdf.js"
    file_type = "js"
    first_seen = "2026-10-16 01:08:35"
  condition:
    hash.sha256(0, filesize) == "0bc73de0da28e7160e3e00c2a2305ea4e4bdf35fb471e42d3da1bd5483b2f85f"
}
```

### Sample 50: `9ccf73fb4b844474`

| Field | Value |
|---|---|
| SHA-256 | `9ccf73fb4b844474210194e3bb87f24e2234ee5eb5f6c8dedb68b942ad737026` |
| Family label | `unknown` |
| File name | `Affektioner.vbs` |
| File type | `vbs` |
| First seen | `2026-10-16 01:01:49` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03021a05776d51db09320466585c1424` |
| SHA-1 | `7c487719ccb47004379c1b62f231fae021a813a0` |
| SHA-256 | `9ccf73fb4b844474210194e3bb87f24e2234ee5eb5f6c8dedb68b942ad737026` |
| SHA3-384 | `fa8e6e301ad2acaade5116b5240443d9c510d612304f756cffba18ffb4d619c2bc5a7a9b0fce2cc7d96d58e50fbde114` |
| TLSH | `T1E292F8665B62A924464328B6886D8875CD7002B6D4260C7C7EBFB634FC16F186E7C1BF` |
| SSDEEP | `384:paXpmwxiRg68BzFFNI/I6xS6UXiU0FNloO0HC8rKAAfW9nv28:pa5mw4M66X+Oi8/AfqZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_9ccf73fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ccf73fb4b844474210194e3bb87f24e2234ee5eb5f6c8dedb68b942ad737026"
    family = "unknown"
    file_name = "Affektioner.vbs"
    file_type = "vbs"
    first_seen = "2026-10-16 01:01:49"
  condition:
    hash.sha256(0, filesize) == "9ccf73fb4b844474210194e3bb87f24e2234ee5eb5f6c8dedb68b942ad737026"
}
```

### Sample 51: `3b3ed840462a50ad`

| Field | Value |
|---|---|
| SHA-256 | `3b3ed840462a50adbae17d5e4c2fc09ae6a48b88e8e5958bc42d6e77702b2e90` |
| Family label | `unknown` |
| File name | `classcomputer.hta` |
| File type | `hta` |
| First seen | `2026-10-16 01:00:24` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `253ea109646a53a68a4e92d739fc085f` |
| SHA-1 | `61d5833caa314e89574d0b5075a425d8fafbd1bd` |
| SHA-256 | `3b3ed840462a50adbae17d5e4c2fc09ae6a48b88e8e5958bc42d6e77702b2e90` |
| SHA3-384 | `6ce87bd75621fd807c48c6fc304dadb8f7cb7fe30a0e8ceb3128e014dc0850d30685f526a81c6d53c37b336a5a4e6ff5` |
| TLSH | `T18B42085CAED1A1B0EB1707DEB3AF24690228A0C7240DC484F94CEDE87F46BDD4A57B56` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzNbqFtCfSmRUM:sXX+/DV7k/3IFt8RUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_3b3ed840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b3ed840462a50adbae17d5e4c2fc09ae6a48b88e8e5958bc42d6e77702b2e90"
    family = "unknown"
    file_name = "classcomputer.hta"
    file_type = "hta"
    first_seen = "2026-10-16 01:00:24"
  condition:
    hash.sha256(0, filesize) == "3b3ed840462a50adbae17d5e4c2fc09ae6a48b88e8e5958bc42d6e77702b2e90"
}
```

### Sample 52: `5fe4d4fff5da2c58`

| Field | Value |
|---|---|
| SHA-256 | `5fe4d4fff5da2c58f4e4450d67f5ab325b78beba7cd294169e9e8af4ef429f6f` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 00:47:02` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX2.file, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49caf47dd348082411c3ca7cabfc49f9` |
| SHA-1 | `6104de77d08b93425640f6be1a101a3aecff9943` |
| SHA-256 | `5fe4d4fff5da2c58f4e4450d67f5ab325b78beba7cd294169e9e8af4ef429f6f` |
| SHA3-384 | `0f35e5180a5a845b7d5b62e2b40d450d39824de532d30e22db511ca8acaa55702e29dcf76a64c4d6500bcbeb2ecf6ce4` |
| IMPHASH | `b8635997f3a07dab85d212950f03571b` |
| TLSH | `T106357D07E65181E8C05DC474C34B9673AA71BCCE0A35B5EF0BD097212EA9FE16B2EB15` |
| SSDEEP | `12288:f55606w1G1UiQQTf4saLsKsHxHfM36KtHQwpWyYq8QrIttY3reTjD06MlNyZFMhz:fa0R0RrozYxHjKVQwFrVIH06iyZFMN` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_052_5fe4d4ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fe4d4fff5da2c58f4e4450d67f5ab325b78beba7cd294169e9e8af4ef429f6f"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 00:47:02"
  condition:
    hash.sha256(0, filesize) == "5fe4d4fff5da2c58f4e4450d67f5ab325b78beba7cd294169e9e8af4ef429f6f"
}
```

### Sample 53: `1e8ed19e771e7a93`

| Field | Value |
|---|---|
| SHA-256 | `1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a` |
| Family label | `AMOS` |
| File name | `macho_1e8ed19e771e.bin` |
| File type | `macho` |
| First seen | `2026-10-16 00:45:10` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed4a6db0e93b62fbb2a65d7b35e2eb87` |
| SHA-1 | `f2154264de088fa51b735357ce775bc9c7a5cc70` |
| SHA-256 | `1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a` |
| SHA3-384 | `aa877199e240c7e3875fb30288d669828f234f114e931135a0fefd1be711d4a8b7a4ff96fc3b0f6c136f83cdc8b39d21` |
| TLSH | `T13395022021776329E4012533BD004BD994D06DB49D5DBAEA672ECF623C36AD7A5B33B3` |
| SSDEEP | `49152:vDo1rzeVDUgj1Cl2WqxNSa3hFUWBNCVeqSVt:vDo1zWt` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_053_1e8ed19e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a"
    family = "AMOS"
    file_name = "macho_1e8ed19e771e.bin"
    file_type = "macho"
    first_seen = "2026-10-16 00:45:10"
  condition:
    hash.sha256(0, filesize) == "1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a"
}
```

### Sample 54: `dbd15a7fdb3753b3`

| Field | Value |
|---|---|
| SHA-256 | `dbd15a7fdb3753b3890cc230208a50bed29bcbd66aa3f0986f69e691456e16d8` |
| Family label | `unknown` |
| File name | `Zjckk0.hta` |
| File type | `hta` |
| First seen | `2026-10-16 00:42:25` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e609bff620b87f45f4d030d2c5e67b0a` |
| SHA-1 | `efdcb6f4e6a05af4c095a52919b41fb6d49c7866` |
| SHA-256 | `dbd15a7fdb3753b3890cc230208a50bed29bcbd66aa3f0986f69e691456e16d8` |
| SHA3-384 | `cf1da06dc0fbba362cb3e05ba68105925eaa35703b56b049ea3cbdaf0b81d177bc9c9a01bbe138337a63229036c92b26` |
| TLSH | `T1C542185CAE91B1A0EA1707DEB3AF24690228A0C7240DC484F94CDEE87F46BDC4A56B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzjbqFtCgSVRUM:sXX+/DV7k/3iFtWRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_dbd15a7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbd15a7fdb3753b3890cc230208a50bed29bcbd66aa3f0986f69e691456e16d8"
    family = "unknown"
    file_name = "Zjckk0.hta"
    file_type = "hta"
    first_seen = "2026-10-16 00:42:25"
  condition:
    hash.sha256(0, filesize) == "dbd15a7fdb3753b3890cc230208a50bed29bcbd66aa3f0986f69e691456e16d8"
}
```

### Sample 55: `12cc08c6601591c3`

| Field | Value |
|---|---|
| SHA-256 | `12cc08c6601591c376125268c78cab8ddb34287e2f40c503b172fc3d132da619` |
| Family label | `unknown` |
| File name | `12cc08c6601591c376125268c78cab8ddb34287e2f40c503b172fc3d132da619.exe` |
| File type | `exe` |
| First seen | `2026-10-16 00:41:57` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baaa649f2b61420b971a73ab9413ddfb` |
| SHA-1 | `048b9204452b9136d62492171fdba916994de2c7` |
| SHA-256 | `12cc08c6601591c376125268c78cab8ddb34287e2f40c503b172fc3d132da619` |
| SHA3-384 | `f640e52c7de17755338fa6142d5c5bcbd34f81c4b4156235657c8ff2c5699ba6a8e9ef9fbd9ca744cfabf9e724ed5e73` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E53549B892924059D2555F3CCE51C371C2728F806A67C313BAE07E9F767DBB8A6101EE` |
| SSDEEP | `6144:fc0kagaMb/B+7fMQ5hrMUPM5GitQ5hrMUPM5GiSMpsr6pqzl3AD/gkQynWgzi9Tn:fcWgaWq5hIX5i5hIX59p6Ks391ai9D` |
| ICON-DHASH | `102800b0b2002810` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_12cc08c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12cc08c6601591c376125268c78cab8ddb34287e2f40c503b172fc3d132da619"
    family = "unknown"
    file_name = "12cc08c6601591c376125268c78cab8ddb34287e2f40c503b172fc3d132da619.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:41:57"
  condition:
    hash.sha256(0, filesize) == "12cc08c6601591c376125268c78cab8ddb34287e2f40c503b172fc3d132da619"
}
```

### Sample 56: `82855f659d8d5b23`

| Field | Value |
|---|---|
| SHA-256 | `82855f659d8d5b23c68205a954a067c183c8af024f2340e3141aaeaad4b1c4b0` |
| Family label | `UmbralStealer` |
| File name | `82855f659d8d5b23c68205a954a067c183c8af024f2340e3141aaeaad4b1c4b0.exe` |
| File type | `exe` |
| First seen | `2026-10-16 00:41:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, UmbralStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c36775d184b8ce09562f299657331f1a` |
| SHA-1 | `5883f53fb05ffb93801cdcbab758d80ff47b30fc` |
| SHA-256 | `82855f659d8d5b23c68205a954a067c183c8af024f2340e3141aaeaad4b1c4b0` |
| SHA3-384 | `2363ce75bc6dba784219de5d2f8a948749349339595ba6e092e7602d47c5525d5d817ac62f119fcdff897ab6e2c3455a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11D346B1937B8CB17E25F8BBDD5B1149F87B2F103E90AF78E0C8895E82411B42E949E57` |
| SSDEEP | `6144:9loZM+rIkd8g+EtXHkv/iD4cTyFVjgULmyD1Ac5Dl1b8e1m5i:foZtL+EP8cTyFVjgULmyD1Ac5Drj` |

#### Technical Assessment

- The sample is tracked as `UmbralStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_UmbralStealer_056_82855f65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82855f659d8d5b23c68205a954a067c183c8af024f2340e3141aaeaad4b1c4b0"
    family = "UmbralStealer"
    file_name = "82855f659d8d5b23c68205a954a067c183c8af024f2340e3141aaeaad4b1c4b0.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:41:13"
  condition:
    hash.sha256(0, filesize) == "82855f659d8d5b23c68205a954a067c183c8af024f2340e3141aaeaad4b1c4b0"
}
```

### Sample 57: `98379ccde6fc0517`

| Field | Value |
|---|---|
| SHA-256 | `98379ccde6fc0517a749bdfb4fa3a384ccc8dbb86f1f4c1ada23a3bf57760d87` |
| Family label | `AsyncRAT` |
| File name | `98379ccde6fc0517a749bdfb4fa3a384ccc8dbb86f1f4c1ada23a3bf57760d87.exe` |
| File type | `exe` |
| First seen | `2026-10-16 00:41:02` |
| Reporter | `Tuxxin` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2c20418550c97b75a6f0aa15aef57d1` |
| SHA-1 | `cad889b19fe5b4efac5b7137aa77056adbc2437b` |
| SHA-256 | `98379ccde6fc0517a749bdfb4fa3a384ccc8dbb86f1f4c1ada23a3bf57760d87` |
| SHA3-384 | `f83ec7cac366e9c858b9816fb91263e37171b4932e8e32c03d3c610341f7244a2aeecaab1343af896449d99c9cc8b97e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16D74558A6F18CD4ECA440E7778D0BF7B003C469CE625A7AAB23011D56F61F353F49A69` |
| SSDEEP | `6144:T86N/av6QEkBVyrS6ztSNfuhGFFBG5ff7bhud2qsp:Y6wv6oyrS6zmfJFFBG5ff7bhud2qsp` |
| ICON-DHASH | `606458f8e1e45090` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_057_98379ccd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98379ccde6fc0517a749bdfb4fa3a384ccc8dbb86f1f4c1ada23a3bf57760d87"
    family = "AsyncRAT"
    file_name = "98379ccde6fc0517a749bdfb4fa3a384ccc8dbb86f1f4c1ada23a3bf57760d87.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:41:02"
  condition:
    hash.sha256(0, filesize) == "98379ccde6fc0517a749bdfb4fa3a384ccc8dbb86f1f4c1ada23a3bf57760d87"
}
```

### Sample 58: `51ef64b51fbc68f3`

| Field | Value |
|---|---|
| SHA-256 | `51ef64b51fbc68f3fdffa43e7c0d89fad5a522a53d5c3930d8145bc96cc62067` |
| Family label | `njrat` |
| File name | `51ef64b51fbc68f3fdffa43e7c0d89fad5a522a53d5c3930d8145bc96cc62067.exe` |
| File type | `exe` |
| First seen | `2026-10-16 00:40:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, njrat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0706cd387a4eba2beaf3325911a4957d` |
| SHA-1 | `d352655da5424c46fdbc6099d9c529a729386e0f` |
| SHA-256 | `51ef64b51fbc68f3fdffa43e7c0d89fad5a522a53d5c3930d8145bc96cc62067` |
| SHA3-384 | `af044f8f8dff0710be66a9b9db12eb1ee0db81ce5cfca1002081fb0504c99d56c17837f9425e25ea71e203663ed20894` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T141A3F160973963F0D15F0671185B6AB23E64A1218935363C19B2C333BAE762DD793BF2` |
| SSDEEP | `1536:eFq6keVv3jkezCLUmtHI9IdX36/W4RjQFxR1YnHEiKmp3EjzArjnCK2/HkgWMspQ:eFRvASmtoeavQFxRwHELmpSzsjCChQ` |
| ICON-DHASH | `8172e2c4d8818000` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_058_51ef64b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51ef64b51fbc68f3fdffa43e7c0d89fad5a522a53d5c3930d8145bc96cc62067"
    family = "njrat"
    file_name = "51ef64b51fbc68f3fdffa43e7c0d89fad5a522a53d5c3930d8145bc96cc62067.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:40:58"
  condition:
    hash.sha256(0, filesize) == "51ef64b51fbc68f3fdffa43e7c0d89fad5a522a53d5c3930d8145bc96cc62067"
}
```

### Sample 59: `bafd3d712a32b884`

| Field | Value |
|---|---|
| SHA-256 | `bafd3d712a32b884001dccd7f6f77fd9aa515b254352310e20f67026364c7884` |
| Family label | `unknown` |
| File name | `bafd3d712a32b884001dccd7f6f77fd9aa515b254352310e20f67026364c7884.exe` |
| File type | `exe` |
| First seen | `2026-10-16 00:40:52` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e69d64dfc3d809dc8dbdda9c367b0afc` |
| SHA-1 | `dc61951ccd463291bb2e2758fc8afebaa8ffadcc` |
| SHA-256 | `bafd3d712a32b884001dccd7f6f77fd9aa515b254352310e20f67026364c7884` |
| SHA3-384 | `174c8e2acceddda2ea817eff68f189d37e22d170eda2a9838751db4bbe2608f6004032857f0a49ef263c3e2da04c4022` |
| IMPHASH | `106168d1bd6a4669e663eb5e822d6613` |
| TLSH | `T127347D21B5C1C4F1F97945356836C9910E6AFC36AF501EAF3298332F0E751E2453AEAE` |
| SSDEEP | `3072:3WiJUpGuEy1AXy4e5II5CoTbLYiBZP5pHQpYR95WPNp/H:GBpduiPRZPPHQpY35WPNpf` |
| ICON-DHASH | `e8d4dcccd4f879b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_bafd3d71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bafd3d712a32b884001dccd7f6f77fd9aa515b254352310e20f67026364c7884"
    family = "unknown"
    file_name = "bafd3d712a32b884001dccd7f6f77fd9aa515b254352310e20f67026364c7884.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:40:52"
  condition:
    hash.sha256(0, filesize) == "bafd3d712a32b884001dccd7f6f77fd9aa515b254352310e20f67026364c7884"
}
```

### Sample 60: `6b9df966d5f85168`

| Field | Value |
|---|---|
| SHA-256 | `6b9df966d5f851687534c1abae51e4287c91484fa5aa6dc45e89ebb8368a02e7` |
| Family label | `unknown` |
| File name | `ffffffffffffffffffffqw.hta` |
| File type | `hta` |
| First seen | `2026-10-16 00:40:30` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `635ff29dd38657da566ceee98aa2b3c6` |
| SHA-1 | `172195dfec63968ece18678e31ac21732517e286` |
| SHA-256 | `6b9df966d5f851687534c1abae51e4287c91484fa5aa6dc45e89ebb8368a02e7` |
| SHA3-384 | `1a18eae217b3877ff5ab28effb2e984f946da370cb8284f92447b82257312d9ee02454df3306a510b926aa737697fc5e` |
| TLSH | `T18342E74CEEB1A3F0F22203DD27AF699D2664A1D31049C540F58CAFE46F0B79D4587E69` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzTQQ9VFAE6+7My3VjtgR:sXX+/DV7k/3UQ9VFAEN7f3VjtgR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_6b9df966
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b9df966d5f851687534c1abae51e4287c91484fa5aa6dc45e89ebb8368a02e7"
    family = "unknown"
    file_name = "ffffffffffffffffffffqw.hta"
    file_type = "hta"
    first_seen = "2026-10-16 00:40:30"
  condition:
    hash.sha256(0, filesize) == "6b9df966d5f851687534c1abae51e4287c91484fa5aa6dc45e89ebb8368a02e7"
}
```

### Sample 61: `3ae3d11cd46aceee`

| Field | Value |
|---|---|
| SHA-256 | `3ae3d11cd46aceee81783fb1204c4ae43459e670a8071f76c8a9a5851287a965` |
| Family label | `AMOS` |
| File name | `macho_3ae3d11cd46a.bin` |
| File type | `macho` |
| First seen | `2026-10-16 00:39:59` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `501a21c84e2a80eee15227c97f401a42` |
| SHA-1 | `85c46e28454aeffe38299fd086b3fa53d8894a55` |
| SHA-256 | `3ae3d11cd46aceee81783fb1204c4ae43459e670a8071f76c8a9a5851287a965` |
| SHA3-384 | `fe968c6bb4bf40888444b8ff67ca18bde19c83eb14d6aa334a3a1591063a3ae7e6fa40bde58a069dd2b9e00ec7687a0c` |
| TLSH | `T150A5F1148A57626AE66A34B39C630FDD646062C05A582EFB6530CF351F33783B967F32` |
| SSDEEP | `49152:GLvJGGszLKQc7x2RnH9urkqSd0sratpkGKNX:YvJT2NdurkqSd0sz` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_061_3ae3d11c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ae3d11cd46aceee81783fb1204c4ae43459e670a8071f76c8a9a5851287a965"
    family = "AMOS"
    file_name = "macho_3ae3d11cd46a.bin"
    file_type = "macho"
    first_seen = "2026-10-16 00:39:59"
  condition:
    hash.sha256(0, filesize) == "3ae3d11cd46aceee81783fb1204c4ae43459e670a8071f76c8a9a5851287a965"
}
```

### Sample 62: `99abb19b58002ac9`

| Field | Value |
|---|---|
| SHA-256 | `99abb19b58002ac9bd71b4d097dbcd63d41cc7e7a21e1e5eadac4b4a75acb4fc` |
| Family label | `njrat` |
| File name | `99abb19b58002ac9bd71b4d097dbcd63d41cc7e7a21e1e5eadac4b4a75acb4fc.exe` |
| File type | `exe` |
| First seen | `2026-10-16 00:39:52` |
| Reporter | `Tuxxin` |
| Tags | `exe, njrat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `048f5b7440b085874c751745877cbaa2` |
| SHA-1 | `4ab8634df00f27ac61276cf5d959cad7cf5b9086` |
| SHA-256 | `99abb19b58002ac9bd71b4d097dbcd63d41cc7e7a21e1e5eadac4b4a75acb4fc` |
| SHA3-384 | `bc9d0c290c1461f46ce9ca8a147be5a12eede22eb65bdb95ec7a778872ab5e81c876fbd6f8721b4e7bf80e012dfb07b1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T10B534B4877558A15D2BD6E7804F2A6518730F50B6D03FB3E48D160EBABB3EC44A42BE7` |
| SSDEEP | `1536:5HJtlQoN36tOQviFw1cP9+BnvbZfLteF3nLrB9z3nd2aF9bPS9vM:5HJtaoN36tOQviFCowBnlfWl9zMaF9bz` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_062_99abb19b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99abb19b58002ac9bd71b4d097dbcd63d41cc7e7a21e1e5eadac4b4a75acb4fc"
    family = "njrat"
    file_name = "99abb19b58002ac9bd71b4d097dbcd63d41cc7e7a21e1e5eadac4b4a75acb4fc.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:39:52"
  condition:
    hash.sha256(0, filesize) == "99abb19b58002ac9bd71b4d097dbcd63d41cc7e7a21e1e5eadac4b4a75acb4fc"
}
```

### Sample 63: `25fff114fe414d96`

| Field | Value |
|---|---|
| SHA-256 | `25fff114fe414d96d6f972134afce96eadff90d5fa05b87a1d3730165dadc489` |
| Family label | `Mirai` |
| File name | `25fff114fe414d96d6f972134afce96eadff90d5fa05b87a1d3730165dadc489` |
| File type | `elf` |
| First seen | `2026-10-16 00:38:42` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, Mirai, Prometei, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ed4bc2c19af9880f3e7ccc02048fa70` |
| SHA-1 | `70e9f248af919bbaff7cf563363f65f3f27de858` |
| SHA-256 | `25fff114fe414d96d6f972134afce96eadff90d5fa05b87a1d3730165dadc489` |
| SHA3-384 | `ec1bdc813034c38325ac7b4d5fee24d377aa9e0167de157133bf7cc27bdb466570e868b1b0bd783aa20c32a7f9a2b5da` |
| TLSH | `T15D555BBAF2A770BCC067D030479BCBA2AC35B4B501212D7B61C4A9763D62DE11766F27` |
| TELFHASH | `t171d1af700bf635b562dbca20f323f4758d3218ba64f435b466227d98ef85e814c6e867` |
| SSDEEP | `24576:s7aPpTWYDnvgFStBCUiEhPGTM2VlPVDYyESkuxJmR:sOPpCYDnv0StwIhPGTM2DJFmZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_25fff114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25fff114fe414d96d6f972134afce96eadff90d5fa05b87a1d3730165dadc489"
    family = "Mirai"
    file_name = "25fff114fe414d96d6f972134afce96eadff90d5fa05b87a1d3730165dadc489"
    file_type = "elf"
    first_seen = "2026-10-16 00:38:42"
  condition:
    hash.sha256(0, filesize) == "25fff114fe414d96d6f972134afce96eadff90d5fa05b87a1d3730165dadc489"
}
```

### Sample 64: `bc6af94ef856472d`

| Field | Value |
|---|---|
| SHA-256 | `bc6af94ef856472d2a5b75de58fc12e9616d37d1b9dba17ffeeda81d77e40b47` |
| Family label | `unknown` |
| File name | `2KeyFactory.exe` |
| File type | `exe` |
| First seen | `2026-10-16 00:37:50` |
| Reporter | `ffforward` |
| Tags | `2KeyFactory, exe, msstore, signed, Unpacked, WailsLoader, XP8LWPQS0M4JV6` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da726563859745e1312b910a2a693762` |
| SHA-1 | `9bbeb66b6a5d41946b9120f47fb2a4809bf89edb` |
| SHA-256 | `bc6af94ef856472d2a5b75de58fc12e9616d37d1b9dba17ffeeda81d77e40b47` |
| SHA3-384 | `79aa65a5bde034cc54d9503039b2288af62bf25132cbd4d3038fa4f0c25fbdc1cd7bd428253702a991fb73ff85afc50c` |
| IMPHASH | `9fb6b035322a759b2acb5f901880ad5b` |
| TLSH | `T176C64A07E8A545E9C1E995348562D232BB317C481B2127C72BD0FF2A3FB6BD06EB9750` |
| SSDEEP | `98304:d6WwVvYSt4QsMWI0Mqr+S+iz26xZmdrcC0p6S64/uFEgKR3:d5at4QEI0Mc+D6PmdQz6qfgW` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_bc6af94e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc6af94ef856472d2a5b75de58fc12e9616d37d1b9dba17ffeeda81d77e40b47"
    family = "unknown"
    file_name = "2KeyFactory.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:37:50"
  condition:
    hash.sha256(0, filesize) == "bc6af94ef856472d2a5b75de58fc12e9616d37d1b9dba17ffeeda81d77e40b47"
}
```

### Sample 65: `e42b8c35db5ab716`

| Field | Value |
|---|---|
| SHA-256 | `e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea` |
| Family label | `AMOS` |
| File name | `macho_e42b8c35db5a.bin` |
| File type | `macho` |
| First seen | `2026-10-16 00:34:53` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2324461d27387a0b7563be0b8cec055d` |
| SHA-1 | `025fe0fb8aa9f3e2aa0b3e34beeedbbed0a46f92` |
| SHA-256 | `e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea` |
| SHA3-384 | `3cb5c00296d8e300ee774308be13d80160d2016f9f9219606d4c8613926737c8e55a6b80dc7324bb2a02deafd3148a94` |
| TLSH | `T1198502545616667FDFC230329D041FE0B4B0D7B00A546AFB2B20CBAAED3599769B7332` |
| SSDEEP | `24576:Sy2SUjNI9qSx4Kek9r7OFCQ+P07T0MH0e8LDLt0JVds3HBzBvMteQOh0pPl:SlO0k5pPP0J8HLt0JVghVvhh0L` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_065_e42b8c35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea"
    family = "AMOS"
    file_name = "macho_e42b8c35db5a.bin"
    file_type = "macho"
    first_seen = "2026-10-16 00:34:53"
  condition:
    hash.sha256(0, filesize) == "e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea"
}
```

### Sample 66: `b7afb7948a27e2c7`

| Field | Value |
|---|---|
| SHA-256 | `b7afb7948a27e2c7ea27aec336486353f2e759ea13e4be4df8c09bce4e139179` |
| Family label | `unknown` |
| File name | `rooming.hta` |
| File type | `hta` |
| First seen | `2026-10-16 00:30:36` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `596204c20803fb5cf16991bc4090bdd7` |
| SHA-1 | `eeabcdd8c669594525b904ccb90cf65c1564d477` |
| SHA-256 | `b7afb7948a27e2c7ea27aec336486353f2e759ea13e4be4df8c09bce4e139179` |
| SHA3-384 | `cf82e1e168e9ce9a16d30a0fc8e7213eabdbfb0fef7b7075d8f7d4deb994424a4eb78625677d43afbaa5f657c620399a` |
| TLSH | `T1FB42185CAED172B0EA1703DEB7AF24690228A0C7600DD484F94CDDE87F0ABDC4A56B56` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzfbqFtCrSLFRUM:sXX+/DV7k/3WFtnRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_b7afb794
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7afb7948a27e2c7ea27aec336486353f2e759ea13e4be4df8c09bce4e139179"
    family = "unknown"
    file_name = "rooming.hta"
    file_type = "hta"
    first_seen = "2026-10-16 00:30:36"
  condition:
    hash.sha256(0, filesize) == "b7afb7948a27e2c7ea27aec336486353f2e759ea13e4be4df8c09bce4e139179"
}
```

### Sample 67: `9e486485817450a9`

| Field | Value |
|---|---|
| SHA-256 | `9e486485817450a9b516ee93d4b85dfc42be16a629087d0954d63577439b8f56` |
| Family label | `Mirai` |
| File name | `fghe3tj.mips` |
| File type | `elf` |
| First seen | `2026-10-16 00:28:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62ad6477c3f0796ff56d939e4632dbac` |
| SHA-1 | `31c2fbc6f49e90bb713cdeeabd3c4a18c9515f50` |
| SHA-256 | `9e486485817450a9b516ee93d4b85dfc42be16a629087d0954d63577439b8f56` |
| SHA3-384 | `361646ced31c53bf89630555bc506b4bb44592c93fd3c00889e41fd8155db2da8a991f43350469dbd65cf572d20077a0` |
| TLSH | `T17B44B40E6E228F2DF269CB7447F74E34975923E726E1D681D1ACD2101E6438E641FBB8` |
| TELFHASH | `t15241b4680db913b4a2656c5d449cff6bd6a331db7e166c238b11e89deb29f839d10c0c` |
| SSDEEP | `3072:+3A4VUSeSp6t4l96ePDvuhUyX4ZZfo02TbPHHtOkLUNdOS:+3CSJwa96SuhcJcbPtOK0OS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_9e486485
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e486485817450a9b516ee93d4b85dfc42be16a629087d0954d63577439b8f56"
    family = "Mirai"
    file_name = "fghe3tj.mips"
    file_type = "elf"
    first_seen = "2026-10-16 00:28:28"
  condition:
    hash.sha256(0, filesize) == "9e486485817450a9b516ee93d4b85dfc42be16a629087d0954d63577439b8f56"
}
```

### Sample 68: `ab0c6d4640de59c9`

| Field | Value |
|---|---|
| SHA-256 | `ab0c6d4640de59c97bcdf9bab4a6cba7523b7d4e48bf56c729ecba9e0c5dd6d1` |
| Family label | `SalatStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 00:22:56` |
| Reporter | `Bitsight` |
| Tags | `B, BB5.file, dropped-by-GCleaner, exe, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78b6e15065dba4e35b56b32ee15b932b` |
| SHA-1 | `5c9653c8915831ff1b4868e0dcbea0c0e431ad76` |
| SHA-256 | `ab0c6d4640de59c97bcdf9bab4a6cba7523b7d4e48bf56c729ecba9e0c5dd6d1` |
| SHA3-384 | `de66a3345bf8a7151ed32cd43622e30ea939dfca0e7c74dfac5be06ef7cedf3da074f196fd3cf2dd6a713a89e4944a5b` |
| IMPHASH | `1c71063094fd0a496838ee494281fbf7` |
| TLSH | `T1CA162389F247D0F5ED1309F0014BF7BF6631F521C8129CB7EAD44C66E8B5AA28E5A721` |
| SSDEEP | `98304:JZt8q8z6L6IOJmGX8fnkJRKfe4frahk/JEZZdJffniGbJ4:Tt8qbzGmGXhKfFEk/JEfdpiKm` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_068_ab0c6d46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab0c6d4640de59c97bcdf9bab4a6cba7523b7d4e48bf56c729ecba9e0c5dd6d1"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 00:22:56"
  condition:
    hash.sha256(0, filesize) == "ab0c6d4640de59c97bcdf9bab4a6cba7523b7d4e48bf56c729ecba9e0c5dd6d1"
}
```

### Sample 69: `4e3ffef03845a1da`

| Field | Value |
|---|---|
| SHA-256 | `4e3ffef03845a1da3f072a92161e3f1b9c86900056f258055908aab0b4cde997` |
| Family label | `unknown` |
| File name | `fuck_niggers_2.hta` |
| File type | `hta` |
| First seen | `2026-10-16 00:20:40` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e96392f6bcc3b9783f1e32f7bf25cf30` |
| SHA-1 | `5e76a2ba59b8f6d7f58d214234e687a17697ba9a` |
| SHA-256 | `4e3ffef03845a1da3f072a92161e3f1b9c86900056f258055908aab0b4cde997` |
| SHA3-384 | `d021f75ec1938e84df7e9bf7cf21fdb36a291f5bc07807d5b3fe6a7121525f995a3984b2009adf96d5acbaff0bde12ad` |
| TLSH | `T18632295CAED1A1A0FA0717DEB3AF25690228A0C7200DC484F94CEDE87F46BDC4A57B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzN3bqFtCXzSBHRUM:sXX+/DV7k/3oFtHRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_4e3ffef0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e3ffef03845a1da3f072a92161e3f1b9c86900056f258055908aab0b4cde997"
    family = "unknown"
    file_name = "fuck_niggers_2.hta"
    file_type = "hta"
    first_seen = "2026-10-16 00:20:40"
  condition:
    hash.sha256(0, filesize) == "4e3ffef03845a1da3f072a92161e3f1b9c86900056f258055908aab0b4cde997"
}
```

### Sample 70: `17abe5685fd70a47`

| Field | Value |
|---|---|
| SHA-256 | `17abe5685fd70a472ed45401a618afa5b628312a7491cd761536b181a2b346c9` |
| Family label | `unknown` |
| File name | `fuck_niggers_39.hta` |
| File type | `hta` |
| First seen | `2026-10-16 00:20:38` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0601c886fb50ae2cdb2adc4df089f224` |
| SHA-1 | `9000631a6de9d18dda213dd7546725eeeca8eea4` |
| SHA-256 | `17abe5685fd70a472ed45401a618afa5b628312a7491cd761536b181a2b346c9` |
| SHA3-384 | `787d543fd3fb1505d08c726bd380769f7ca1ef797c3ed276cd52c703716c4f1291e04b0cbcf9dce864861494a644cfb1` |
| TLSH | `T10042195CAED161A0FA0717DDB3AF25690228A0C7200DC484F94CDDE87F4ABDC4A57B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzN3bqFtCXwSc/cRUM:sXX+/DV7k/3oFtiRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_17abe568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17abe5685fd70a472ed45401a618afa5b628312a7491cd761536b181a2b346c9"
    family = "unknown"
    file_name = "fuck_niggers_39.hta"
    file_type = "hta"
    first_seen = "2026-10-16 00:20:38"
  condition:
    hash.sha256(0, filesize) == "17abe5685fd70a472ed45401a618afa5b628312a7491cd761536b181a2b346c9"
}
```

### Sample 71: `7e1f8efda2aa1e7e`

| Field | Value |
|---|---|
| SHA-256 | `7e1f8efda2aa1e7eb79557ca2275a229a76b55fb98e191d310e5b8e4ad38b954` |
| Family label | `Mirai` |
| File name | `fghe3tj.ppc` |
| File type | `elf` |
| First seen | `2026-10-16 00:10:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `029dfb40a4bde6fb8f486bf861ec3d89` |
| SHA-1 | `e4fd16b9b3139731b39f8debde96aeeafdd51a5d` |
| SHA-256 | `7e1f8efda2aa1e7eb79557ca2275a229a76b55fb98e191d310e5b8e4ad38b954` |
| SHA3-384 | `6412e57c24c928350aa9420b68cc2bf7d593718234821eb3691d121c784326e55c1fa83670f99d824b95ddbcc6355c30` |
| TLSH | `T1F5044C02B31C0847D2632EF0363B17E1D3EF96A221B4F645794F6B8991B2D365586DCE` |
| SSDEEP | `3072:7jQ2QaSYdFCGCe/8DO0ko9mCDE6yQxUTiF4nqQbrWBV5acT:nQsFCKknmZ6yQxUTlnqWrc1T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_7e1f8efd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e1f8efda2aa1e7eb79557ca2275a229a76b55fb98e191d310e5b8e4ad38b954"
    family = "Mirai"
    file_name = "fghe3tj.ppc"
    file_type = "elf"
    first_seen = "2026-10-16 00:10:30"
  condition:
    hash.sha256(0, filesize) == "7e1f8efda2aa1e7eb79557ca2275a229a76b55fb98e191d310e5b8e4ad38b954"
}
```

### Sample 72: `f6ddc131bdfd2631`

| Field | Value |
|---|---|
| SHA-256 | `f6ddc131bdfd26317d1a7f53086f1a1ed17717a631242832abbdaf0506be74ce` |
| Family label | `Mirai` |
| File name | `fghe3tj.arm6` |
| File type | `elf` |
| First seen | `2026-10-16 00:08:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `881955fecc4c0502b123265b8f19066c` |
| SHA-1 | `e4b575a9c803bf878156a83386637d661340f6d4` |
| SHA-256 | `f6ddc131bdfd26317d1a7f53086f1a1ed17717a631242832abbdaf0506be74ce` |
| SHA3-384 | `6cc5fb89cf3946275f702c1335df64e1dc617b25b85dbc09176b4ea3eb0d4592e16a452dce29b1eb0c0f60f6477b873d` |
| TLSH | `T12B141956F8819F15D5C056BAFE0E128E33131BBCE2DE7212AD246F6037CA96F0A3B515` |
| TELFHASH | `t140b012407eed047d25000221e0e5c34080405fde270414a1db04b13c5b039c4202fc12` |
| SSDEEP | `6144:FeVtg2C79Hb4mKDXv1Xf8larWw/KfCm1M3D7Nrx:FeVtg2C5Hb4mo/1XElarXUM3/3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_f6ddc131
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6ddc131bdfd26317d1a7f53086f1a1ed17717a631242832abbdaf0506be74ce"
    family = "Mirai"
    file_name = "fghe3tj.arm6"
    file_type = "elf"
    first_seen = "2026-10-16 00:08:29"
  condition:
    hash.sha256(0, filesize) == "f6ddc131bdfd26317d1a7f53086f1a1ed17717a631242832abbdaf0506be74ce"
}
```

### Sample 73: `01c97268134bd3bc`

| Field | Value |
|---|---|
| SHA-256 | `01c97268134bd3bcb04f32567f2c8b5fa2aafab4f268e7ce70ae3731566133bf` |
| Family label | `Mirai` |
| File name | `mbupload-b9kcd0z1.bin` |
| File type | `elf` |
| First seen | `2026-10-15 23:59:50` |
| Reporter | `wristhulk` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6533b95ad28a9b2e5a3206aea58c5db` |
| SHA-1 | `e569541c5d4665220659da29fa6d85eecbb70f25` |
| SHA-256 | `01c97268134bd3bcb04f32567f2c8b5fa2aafab4f268e7ce70ae3731566133bf` |
| SHA3-384 | `09ee113d968e3dbc501645f4699dec8c9e071875c62dcc06da7609d4e46e002f5dd65be91681e582933177f4fe2e71f9` |
| TLSH | `T150358D1AB2F3F27CD00BC0345BDBC6A14531F07569322D7B26C4DA392EAADE52359B25` |
| TELFHASH | `t10ba012010444810c071b8e14ccb4018920810833e8182c21551dc58100304001618963` |
| SSDEEP | `24576:aTNggxkVMlzgwZLWbTRavXGo/kNSkMkz9Z:aTNggxzzgwZLWbURTk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_01c97268
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01c97268134bd3bcb04f32567f2c8b5fa2aafab4f268e7ce70ae3731566133bf"
    family = "Mirai"
    file_name = "mbupload-b9kcd0z1.bin"
    file_type = "elf"
    first_seen = "2026-10-15 23:59:50"
  condition:
    hash.sha256(0, filesize) == "01c97268134bd3bcb04f32567f2c8b5fa2aafab4f268e7ce70ae3731566133bf"
}
```

### Sample 74: `7169885e9230836c`

| Field | Value |
|---|---|
| SHA-256 | `7169885e9230836cf829ee86035864806a8720cb644e5a1d7f53f914b330cab2` |
| Family label | `unknown` |
| File name | `RDP OfficeX Manager.exe` |
| File type | `exe` |
| First seen | `2026-10-15 23:56:31` |
| Reporter | `ffforward` |
| Tags | `exe, msstore, RDP-OfficeX-Manager, revoked-cert, signed, telegram-version, Unpacked, WailsLoader, XPFCZWR9RK8XL4` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `416655f0370ddb7e0d0fc54f136caecc` |
| SHA-1 | `687807e64cab3c6a581dbb909a793fa527391e1f` |
| SHA-256 | `7169885e9230836cf829ee86035864806a8720cb644e5a1d7f53f914b330cab2` |
| SHA3-384 | `048261b84ae79ae7dcb864f6a489f331ba35465504d6ba1a0290b55443dcadcace56e73ae57498d9612dee74e1dc7b2c` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T134D65A13E85194F8C4AEE13A857B95137B307C440B71A3D79A50F6342FBA7D8AEBA314` |
| SSDEEP | `98304:DdRtkPEdJDNx0v4GIQQ0RpNhK2pOjQxigAekEMZ:N/POhgMpL/AMa` |
| ICON-DHASH | `f0dce26564b4ccf8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_7169885e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7169885e9230836cf829ee86035864806a8720cb644e5a1d7f53f914b330cab2"
    family = "unknown"
    file_name = "RDP OfficeX Manager.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:56:31"
  condition:
    hash.sha256(0, filesize) == "7169885e9230836cf829ee86035864806a8720cb644e5a1d7f53f914b330cab2"
}
```

### Sample 75: `d4bb1f9cc14e1a27`

| Field | Value |
|---|---|
| SHA-256 | `d4bb1f9cc14e1a27aa5d4f5ec397247b06cc5b0ae0b8fd4067a2b10f6223e2ef` |
| Family label | `unknown` |
| File name | `rdp_officex_manager.exe` |
| File type | `exe` |
| First seen | `2026-10-15 23:56:20` |
| Reporter | `ffforward` |
| Tags | `AdvancedInstaller, exe, msstore, RDP-OfficeX-Manager, revoked-cert, signed, telegram-version, WailsLoader, XPFCZWR9RK8XL4` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `309d76027588d6eec3051077bb3b4540` |
| SHA-1 | `a01de3e31567d5393854e8e8d1ef378ef4f454af` |
| SHA-256 | `d4bb1f9cc14e1a27aa5d4f5ec397247b06cc5b0ae0b8fd4067a2b10f6223e2ef` |
| SHA3-384 | `e2481e94ab09cb3653635ee9316183c3bdddd9c8954159e063330b2b7ae14f70a6027e03454cb6ae2a049df75947f3b7` |
| IMPHASH | `c457c3a53f518626ccd02bd56edd9752` |
| TLSH | `T1E1A6BF31714AC4FEDC5D35BE3A3E9A5A8218692A0BB5C0C7F3DC2979537D4C21E36A12` |
| SSDEEP | `196608:rAJ5hg5KEXLlidW0ySN/i55CACmcam11yS6i1hnZcjxJQqXwB:rAJ5hg5KE7QW0ySN/i6GcaIoSj1hZoWB` |
| ICON-DHASH | `c41be66464b42fdc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_d4bb1f9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4bb1f9cc14e1a27aa5d4f5ec397247b06cc5b0ae0b8fd4067a2b10f6223e2ef"
    family = "unknown"
    file_name = "rdp_officex_manager.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:56:20"
  condition:
    hash.sha256(0, filesize) == "d4bb1f9cc14e1a27aa5d4f5ec397247b06cc5b0ae0b8fd4067a2b10f6223e2ef"
}
```

### Sample 76: `82f1b1874d6003e0`

| Field | Value |
|---|---|
| SHA-256 | `82f1b1874d6003e049c69e87ed5fcf64301090dfa275acb98e9938c788ff801d` |
| Family label | `unknown` |
| File name | `fuck_niggers_8.hta` |
| File type | `hta` |
| First seen | `2026-10-15 23:52:31` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70e4d4566190bef880467af4dc68e0f4` |
| SHA-1 | `21016e525b04f61e1d1a5b59f3117b30dde47181` |
| SHA-256 | `82f1b1874d6003e049c69e87ed5fcf64301090dfa275acb98e9938c788ff801d` |
| SHA3-384 | `59ef64f0a8399686e523ed29d21cb226185756fa6db75010f990a92cfbe901a30af60e72b62dc977ba1f4b212a8936ad` |
| TLSH | `T1AD42195CAED1B1B0FA0717DEB3AF28690268A0C72009C484F54CDDE87F0ABDD4A57B56` |
| SSDEEP | `192:sgHNsGeTHQpD+da6+888+UV7tDoj/pxzLbqFtCtS4RUzHm:sgX+/DV7k/3qFtSRUzHm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_82f1b187
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82f1b1874d6003e049c69e87ed5fcf64301090dfa275acb98e9938c788ff801d"
    family = "unknown"
    file_name = "fuck_niggers_8.hta"
    file_type = "hta"
    first_seen = "2026-10-15 23:52:31"
  condition:
    hash.sha256(0, filesize) == "82f1b1874d6003e049c69e87ed5fcf64301090dfa275acb98e9938c788ff801d"
}
```

### Sample 77: `8f0bd3a7009a3a3a`

| Field | Value |
|---|---|
| SHA-256 | `8f0bd3a7009a3a3a22f9d397c22de38052b72db51c13904d596717ca65107908` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Iguanodon.Gen.1.18365638` |
| File type | `msi` |
| First seen | `2026-10-15 23:51:03` |
| Reporter | `SecuriteInfoCom` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72a45ddf1549ea6010a9ea1a920cace4` |
| SHA-1 | `b7e5f503eae6bb5f0f2e28500237759061114dea` |
| SHA-256 | `8f0bd3a7009a3a3a22f9d397c22de38052b72db51c13904d596717ca65107908` |
| SHA3-384 | `8dddd21fe7146826bec8417fc982fe8777c7ee34716152b9de12dc6cf13f6cbdd175d58270545f4aa72116a46f22fb54` |
| TLSH | `T162956D236A50600646B598FABEBD5E37695F7409101AD94EFFD34B86F12EBF80802D1F` |
| SSDEEP | `49152:TsTWI0oNlZyesa3vSOMluMqrqSzSS3InnnnHM:ITq4Q8vahqrvOSN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_8f0bd3a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f0bd3a7009a3a3a22f9d397c22de38052b72db51c13904d596717ca65107908"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Iguanodon.Gen.1.18365638"
    file_type = "msi"
    first_seen = "2026-10-15 23:51:03"
  condition:
    hash.sha256(0, filesize) == "8f0bd3a7009a3a3a22f9d397c22de38052b72db51c13904d596717ca65107908"
}
```

### Sample 78: `069f1429577c2426`

| Field | Value |
|---|---|
| SHA-256 | `069f1429577c2426c7883f392ca6441f1aea464b9b2262ef2fcb25989b701ee0` |
| Family label | `unknown` |
| File name | `PLClean Master.exe` |
| File type | `exe` |
| First seen | `2026-10-15 23:43:53` |
| Reporter | `ffforward` |
| Tags | `exe, msstore, PLClean-Master, revoked-cert, signed, telegram-version, Unpacked, WailsLoader, XP8C9MQ5GXGV8S` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb1e4beb11521b5ba4416704fbd3c102` |
| SHA-1 | `209392c13014dabdc569ddeea5137dd33c4ab82e` |
| SHA-256 | `069f1429577c2426c7883f392ca6441f1aea464b9b2262ef2fcb25989b701ee0` |
| SHA3-384 | `b8ad25e995b5ed258458089a25f8009be369e02e1c726ba79f92a03a0aad863c21d74368ff11b9ee59a5b6f665310923` |
| IMPHASH | `f78124b827b7e981a834f4a15d6b6350` |
| TLSH | `T12AC65A17EDA540E9C0ADC1308966D6767B717C490B2123D35B90FA3A3FB2BD06EBA750` |
| SSDEEP | `98304:ip4gLn3gJ5eQKfaynlzj5nmkNDDL5L0hqvUSOAtuEcApCjqFEw6/82:Gh3kYQpilP5nmkN9L0hqLOQud7t` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_069f1429
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "069f1429577c2426c7883f392ca6441f1aea464b9b2262ef2fcb25989b701ee0"
    family = "unknown"
    file_name = "PLClean Master.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:43:53"
  condition:
    hash.sha256(0, filesize) == "069f1429577c2426c7883f392ca6441f1aea464b9b2262ef2fcb25989b701ee0"
}
```

### Sample 79: `052a2258a185f4c8`

| Field | Value |
|---|---|
| SHA-256 | `052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68` |
| Family label | `unknown` |
| File name | `plclean_master.exe` |
| File type | `exe` |
| First seen | `2026-10-15 23:43:42` |
| Reporter | `ffforward` |
| Tags | `AdvancedInstaller, exe, msstore, PLClean-Master, revoked-cert, signed, telegram-version, WailsLoader, XP8C9MQ5GXGV8S` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c69effcb1c7fd4177a9db86fe6ab8be8` |
| SHA-1 | `7cb95429f6c1ff133c4e2835b28759f878b5be22` |
| SHA-256 | `052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68` |
| SHA3-384 | `cac068e0a0331c001042bed68f66dcb42f70e9d678ddb2e199fc44ee6e9eef97364cd082a77f7dfa29b2d119f7019e44` |
| IMPHASH | `c457c3a53f518626ccd02bd56edd9752` |
| TLSH | `T1F0A6CE31768BC56AD06605F01A2CDABA9328AD3A0B3984C773DC7D5B77744C3163AE27` |
| SSDEEP | `196608:DAJ5hg5KEXLlidW0ySN/i55CACm1+ZHuHMvTZ1bvUyMr5fBqj:DAJ5hg5KE7QW0ySN/i6G1+ZHu61g5fB` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_052a2258
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
    family = "unknown"
    file_name = "plclean_master.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:43:42"
  condition:
    hash.sha256(0, filesize) == "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
}
```

### Sample 80: `9f98e35e878b0694`

| Field | Value |
|---|---|
| SHA-256 | `9f98e35e878b06940f2792ebc45b3f0adc0fb5bfde60f56548a60cfbf71bbe35` |
| Family label | `Meterpreter` |
| File name | `F80E26BD75D1F89BA1501002076195AE.exe` |
| File type | `exe` |
| First seen | `2026-10-15 23:30:11` |
| Reporter | `abuse_ch` |
| Tags | `exe, Meterpreter` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f80e26bd75d1f89ba1501002076195ae` |
| SHA-1 | `8510c66e6cdead6de2a3728fe1c9170c97321bc1` |
| SHA-256 | `9f98e35e878b06940f2792ebc45b3f0adc0fb5bfde60f56548a60cfbf71bbe35` |
| SHA3-384 | `6d46fc5e71ef1dbd50d9a123d36297ddfb9e074fc4f584c7843784fae5922bf0561e73827c4eeec5455a72e25c99ceeb` |
| IMPHASH | `110c6a81db51ff8f15bee3bd1c81e489` |
| TLSH | `T1F2847E77F6D0C833D1331A7C9E0B96A55829BF602D28258A3FE85D8C5F3A781352A1D7` |
| SSDEEP | `6144:TMAT8Jd++oyMyKmkwQgytOmxzcEdeJlz3+G4snQCRjATfwtfFliejvfwmcktO13:Tsd++XMygwbNm2vlOs4TYttl1jXw` |
| ICON-DHASH | `f0dcb6cbab3ab4b0` |

#### Technical Assessment

- The sample is tracked as `Meterpreter` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Meterpreter_080_9f98e35e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f98e35e878b06940f2792ebc45b3f0adc0fb5bfde60f56548a60cfbf71bbe35"
    family = "Meterpreter"
    file_name = "F80E26BD75D1F89BA1501002076195AE.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:30:11"
  condition:
    hash.sha256(0, filesize) == "9f98e35e878b06940f2792ebc45b3f0adc0fb5bfde60f56548a60cfbf71bbe35"
}
```

### Sample 81: `0bcf272d8f22fa30`

| Field | Value |
|---|---|
| SHA-256 | `0bcf272d8f22fa30d327d7c0233b7eae7d50df1ebd95472aae59aef19c8e23bf` |
| Family label | `unknown` |
| File name | `2KeyFactory.exe` |
| File type | `exe` |
| First seen | `2026-10-15 23:27:30` |
| Reporter | `TannerFilip` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `806c58be9684b1bc4af1a9c43763a4ce` |
| SHA-1 | `079e93d82de1e5ab77dd0588242cc6a1e962cef5` |
| SHA-256 | `0bcf272d8f22fa30d327d7c0233b7eae7d50df1ebd95472aae59aef19c8e23bf` |
| SHA3-384 | `cbeb7c0a8d5b59f00ddf1a04c3a91d240da4dee0d32a8e6361cd5dca380e7ec00d3a6816f21d678e32ce57c53a5b92df` |
| IMPHASH | `c457c3a53f518626ccd02bd56edd9752` |
| TLSH | `T142A6CF31B68BC56AD06605F01A2CDABA93286D3A0B3984C773DC7D5B77744C3163AE27` |
| SSDEEP | `196608:KAJ5hg5KEXLlidW0ySN/i55CACm16+3y/k32hATw+xlHAcH:KAJ5hg5KE7QW0ySN/i6G1Fy/k8velXH` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_0bcf272d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bcf272d8f22fa30d327d7c0233b7eae7d50df1ebd95472aae59aef19c8e23bf"
    family = "unknown"
    file_name = "2KeyFactory.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:27:30"
  condition:
    hash.sha256(0, filesize) == "0bcf272d8f22fa30d327d7c0233b7eae7d50df1ebd95472aae59aef19c8e23bf"
}
```

### Sample 82: `6b622569745e1074`

| Field | Value |
|---|---|
| SHA-256 | `6b622569745e1074b4564467c3d694d9cf1db09405a03d8d6ee609c35f417e86` |
| Family label | `Mirai` |
| File name | `fghe3tj.mpsl` |
| File type | `elf` |
| First seen | `2026-10-15 23:23:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f07ec378e4f09b659b984713e3f0156` |
| SHA-1 | `138143720b356b47d8e0631fb6b9ee7ee706fb1f` |
| SHA-256 | `6b622569745e1074b4564467c3d694d9cf1db09405a03d8d6ee609c35f417e86` |
| SHA3-384 | `ed3a5d96454962475bf5eec80bcf7ec64fee5da97bd0612c7983f79a8fa066034ba07c1c151a8e48c068e29a60f03cf6` |
| TLSH | `T13944F80AAB610FFBEC6BDD3705E91B0525CC641722A53B363678D918F94A64F0AD3C78` |
| SSDEEP | `3072:EluPFjYyS0mv8SWmx/In5zSEgGii5a8ssbGvf0OL:E2gOSJw52EisRavfH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_6b622569
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b622569745e1074b4564467c3d694d9cf1db09405a03d8d6ee609c35f417e86"
    family = "Mirai"
    file_name = "fghe3tj.mpsl"
    file_type = "elf"
    first_seen = "2026-10-15 23:23:26"
  condition:
    hash.sha256(0, filesize) == "6b622569745e1074b4564467c3d694d9cf1db09405a03d8d6ee609c35f417e86"
}
```

### Sample 83: `675971cc1e2c889b`

| Field | Value |
|---|---|
| SHA-256 | `675971cc1e2c889b2804336626f4e2d1489b7878c15817b57847d1d88347b76c` |
| Family label | `unknown` |
| File name | `QR2 Auth.exe` |
| File type | `exe` |
| First seen | `2026-10-15 23:21:52` |
| Reporter | `ffforward` |
| Tags | `exe, msstore, QR2-Auth, signed, telegram-version, Unpacked, WailsLoader, XP9M1JZ5PF49KC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7500d0d6eeeda52ed769057153e6c1bb` |
| SHA-1 | `1eb2d00d13c0acbc671369e18e4f0d000079141c` |
| SHA-256 | `675971cc1e2c889b2804336626f4e2d1489b7878c15817b57847d1d88347b76c` |
| SHA3-384 | `3a547f6eaab576194ef962847096539d6668d06ca43c882cd93d7b0528d5511bc8811fc27a6bc57528856094ec6d41fe` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T151E65A17ED9615E8C0ADC130C962D2327B717C895B2027DB1A90BA357F73BE06EBA354` |
| SSDEEP | `98304:duSRDNSBZ1PXPXgK5bI7ghqRrPw880DSP2COpfM8EGDnx:PABfXvFEghqVw8RDuwfM1GDnx` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_675971cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "675971cc1e2c889b2804336626f4e2d1489b7878c15817b57847d1d88347b76c"
    family = "unknown"
    file_name = "QR2 Auth.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:21:52"
  condition:
    hash.sha256(0, filesize) == "675971cc1e2c889b2804336626f4e2d1489b7878c15817b57847d1d88347b76c"
}
```

### Sample 84: `73cb8ff57d809fe1`

| Field | Value |
|---|---|
| SHA-256 | `73cb8ff57d809fe1042ef02ba5571d8ad7ee871cadf01a9bbc609f69f8d407ed` |
| Family label | `unknown` |
| File name | `qr2auth.exe` |
| File type | `exe` |
| First seen | `2026-10-15 23:21:42` |
| Reporter | `ffforward` |
| Tags | `AdvancedInstaller, exe, msstore, QR2-Auth, signed, telegram-version, WailsLoader, XP9M1JZ5PF49KC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f4b2e1530ee264f07e06c8950e2748f` |
| SHA-1 | `61f03e7ac3bce8395a27352b0e4f73b41d5def84` |
| SHA-256 | `73cb8ff57d809fe1042ef02ba5571d8ad7ee871cadf01a9bbc609f69f8d407ed` |
| SHA3-384 | `cd2165d56d21efe33d37b5ad215e54c6605d521e9d78ef443bb2a4031a01dbb548b3eb360030d9978603f0e62f6960de` |
| IMPHASH | `c457c3a53f518626ccd02bd56edd9752` |
| TLSH | `T18CB6BE31F54ACC66D0EE05BC1E289F5AC2386D2A2B2544C373FE7B5D56764C2363AB12` |
| SSDEEP | `196608:EAJ5hg5KEXLlidW0ySN/i55CACmQWkINlEyzSxO44ss9MCpd5h6YV6QwyDxO7n2X:EAJ5hg5KE7QW0ySN/i6GQc/DWxO4MhtZ` |
| ICON-DHASH | `6d6de9c7b1b0a2c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_73cb8ff5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73cb8ff57d809fe1042ef02ba5571d8ad7ee871cadf01a9bbc609f69f8d407ed"
    family = "unknown"
    file_name = "qr2auth.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:21:42"
  condition:
    hash.sha256(0, filesize) == "73cb8ff57d809fe1042ef02ba5571d8ad7ee871cadf01a9bbc609f69f8d407ed"
}
```

### Sample 85: `65bb68bc934757ab`

| Field | Value |
|---|---|
| SHA-256 | `65bb68bc934757abeece91a377d528e4fb1960e9da5f781ee5776b2f6be18c25` |
| Family label | `unknown` |
| File name | `FACodeEngine.exe` |
| File type | `exe` |
| First seen | `2026-10-15 23:21:32` |
| Reporter | `ffforward` |
| Tags | `2FA-Code-Engine, exe, msstore, signed, telegram-version, Unpacked, WailsLoader, XP8C94NJ9JQ6B9` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `976f7e3cfb0e294e91d254e80ee921bf` |
| SHA-1 | `67c2b22f7322ddd72d0b7c97f830a25b5ad51576` |
| SHA-256 | `65bb68bc934757abeece91a377d528e4fb1960e9da5f781ee5776b2f6be18c25` |
| SHA3-384 | `1a7a354464b0cea7415c2a9e4358f248e5a86f599220aaf2b91b66b0a4bed8ab41b779853ac47789f12ddfc5993e1ee7` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T157D65A13ECA554E8C1AED130CAA691627B31BC495F3063DB1A70F6242FB3BD4ADB9354` |
| SSDEEP | `98304:vqPmFvC//fYJSxz2cOrx0zn5D7ZKkZigkEGY:Bdq/I6WKn5ZNi+L` |
| ICON-DHASH | `78e4ce2ef2c67838` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_65bb68bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65bb68bc934757abeece91a377d528e4fb1960e9da5f781ee5776b2f6be18c25"
    family = "unknown"
    file_name = "FACodeEngine.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:21:32"
  condition:
    hash.sha256(0, filesize) == "65bb68bc934757abeece91a377d528e4fb1960e9da5f781ee5776b2f6be18c25"
}
```

### Sample 86: `c2180d18cbdd0f56`

| Field | Value |
|---|---|
| SHA-256 | `c2180d18cbdd0f5667ca61308509eec995dda607a6e47e1c969fc280bb7db796` |
| Family label | `unknown` |
| File name | `MetaSoftware.exe` |
| File type | `exe` |
| First seen | `2026-10-15 22:57:18` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `646ec3a04df68721701b4ffff9d886b6` |
| SHA-1 | `e4aee1ba228e41bd1d888af6e4d287ab384f110c` |
| SHA-256 | `c2180d18cbdd0f5667ca61308509eec995dda607a6e47e1c969fc280bb7db796` |
| SHA3-384 | `59d8b6b9c56774be4bd7738417908ec223399039a3d8ca008c170627da4226e64bfe2e1fa0463b769180eb28e008b75f` |
| IMPHASH | `c34e103a0493d9363e3c7baad663c6ad` |
| TLSH | `T1EAE623FA94C512F4D9E38B50724E5B8EB1D0A05E47ADAC2D37CB1C425731E9B864AE33` |
| SSDEEP | `196608:p5aoWoUvLjdYX/7mZzGOorJlsCLPATfQ1P5c3oLFae+zyYaiRprjnDAxP:P7YLRCjmZKxrJDYT41m3oLFa7dl7juP` |
| ICON-DHASH | `1030b2b27079694c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_c2180d18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2180d18cbdd0f5667ca61308509eec995dda607a6e47e1c969fc280bb7db796"
    family = "unknown"
    file_name = "MetaSoftware.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:57:18"
  condition:
    hash.sha256(0, filesize) == "c2180d18cbdd0f5667ca61308509eec995dda607a6e47e1c969fc280bb7db796"
}
```

### Sample 87: `ff681630d707f590`

| Field | Value |
|---|---|
| SHA-256 | `ff681630d707f5903ea3d75c36f2bb87b2156636907268caa2e512032f5e6bf0` |
| Family label | `RemusStealer` |
| File name | `Xeninester.exe` |
| File type | `exe` |
| First seen | `2026-10-15 22:54:50` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e18b5947f91746179267c88e79e8f1f` |
| SHA-1 | `07d648ac10e4b7d338deab62575b7e57001a7be3` |
| SHA-256 | `ff681630d707f5903ea3d75c36f2bb87b2156636907268caa2e512032f5e6bf0` |
| SHA3-384 | `814f13c43479daa0f4eddbc9cb20b9546c872d1b760b87931fefe76d977df0d3136cf20171982500fab1ffbacf08b78e` |
| IMPHASH | `681b044975068c7ba4d8c68ab99dd3c9` |
| TLSH | `T11E846D3AF7A244FDC15780709797A2B1A532F8280330A95F1BD9DF322E65C605FEDA58` |
| SSDEEP | `6144:X/WHkm1uvM/IGTwk4ZnhrabasKxLEWgsnsoVx4bYCSeUGDSE70bQ0Q0EHfCUXXQk:P2H1a6hd4BhrzLlgVQx4bPSESS` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_087_ff681630
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff681630d707f5903ea3d75c36f2bb87b2156636907268caa2e512032f5e6bf0"
    family = "RemusStealer"
    file_name = "Xeninester.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:54:50"
  condition:
    hash.sha256(0, filesize) == "ff681630d707f5903ea3d75c36f2bb87b2156636907268caa2e512032f5e6bf0"
}
```

### Sample 88: `1350c4c4371a1526`

| Field | Value |
|---|---|
| SHA-256 | `1350c4c4371a1526d54ada91f98e089ffc12ef59df098c97b73e0480efba7daf` |
| Family label | `unknown` |
| File name | `1350c4c4371a1526d54ada91f98e089ffc12ef59df098c97b73e0480efba7daf.exe` |
| File type | `exe` |
| First seen | `2026-10-15 22:51:00` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2c46f02af210ef11267105dbb27c92a` |
| SHA-1 | `1120390111df143ac01ecbf5f66c27822936a475` |
| SHA-256 | `1350c4c4371a1526d54ada91f98e089ffc12ef59df098c97b73e0480efba7daf` |
| SHA3-384 | `a0840ff168747c5849ed30a64e0b02b9705af31405d23def21c34f111cfa2ade87ffad9eab83e5c98ec34b2eb822af31` |
| IMPHASH | `a3f90b9cfb2514d328db28698cb0f066` |
| TLSH | `T1E5E5294AEAB941E1C0BAD07CC683652BFC7134A6833167D766859B572F237E8E93D700` |
| SSDEEP | `49152:NMmKHZo5CyUuk1QT8MSi37Glt9xJ9q0LDFBo:NIHbqk1QOX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_1350c4c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1350c4c4371a1526d54ada91f98e089ffc12ef59df098c97b73e0480efba7daf"
    family = "unknown"
    file_name = "1350c4c4371a1526d54ada91f98e089ffc12ef59df098c97b73e0480efba7daf.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:51:00"
  condition:
    hash.sha256(0, filesize) == "1350c4c4371a1526d54ada91f98e089ffc12ef59df098c97b73e0480efba7daf"
}
```

### Sample 89: `e5b790c3a237edc2`

| Field | Value |
|---|---|
| SHA-256 | `e5b790c3a237edc2c55f01a7c648d0eaf8e969a1a9223aff605a90a1d42900b7` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-15 22:46:19` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, Stealer, Warden, WardenStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f131d1cdf3849e1b627a474bd9460acd` |
| SHA-1 | `dd81532c0e1a95c35bae0ee0bb5b602a13fbfeb0` |
| SHA-256 | `e5b790c3a237edc2c55f01a7c648d0eaf8e969a1a9223aff605a90a1d42900b7` |
| SHA3-384 | `ac1055cd73c4532eddaf863bd79a8cc94c2587260ae1503e4410bfe93a3626002a215959b143e5af5cd798e62617d315` |
| IMPHASH | `26ec5b5ce988c09b6c4642aec7ddbec0` |
| TLSH | `T16135E015BB844DFDF0E2897443416932DA61781ED7E056EB028C5B2ABE265F1ABFCF04` |
| SSDEEP | `24576:bdjTygYizOMr8LquNz5vzGNQML3pFtiW:xj2gF4mEzpSqM` |
| ICON-DHASH | `10689671322a4c30` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_e5b790c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5b790c3a237edc2c55f01a7c648d0eaf8e969a1a9223aff605a90a1d42900b7"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:46:19"
  condition:
    hash.sha256(0, filesize) == "e5b790c3a237edc2c55f01a7c648d0eaf8e969a1a9223aff605a90a1d42900b7"
}
```

### Sample 90: `404e448f179f6624`

| Field | Value |
|---|---|
| SHA-256 | `404e448f179f662439bd08b2abbcddcaaf0034d11d786cc878cce6f9ef57b570` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-15 22:46:16` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, Stealer, Warden, WardenStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d543edb2bb7fa74ab66802f6c9230d25` |
| SHA-1 | `bfb9e9be9f371e7cb9ded4e95cc304a6c6ac62c8` |
| SHA-256 | `404e448f179f662439bd08b2abbcddcaaf0034d11d786cc878cce6f9ef57b570` |
| SHA3-384 | `a944a4d30df77bf54cba67aa7da08d1480672bb2fc5feacdf79d317b5a76d9aa7a024d3d7565cdd6b9001e5fe9c92871` |
| IMPHASH | `2dd01aae00e9afbd6878428c24d913e1` |
| TLSH | `T15C45BE62A1EEE5D9C81DAD3F49204052DBD2BC408FF05EB71A71DA5DDF92B902A3B740` |
| SSDEEP | `24576:61zB0EgZE/0HeVZ4u00OsSvj1cpl1ay9IIDeoXa9BaF:k2EsXmOLcliI3Xa+` |
| ICON-DHASH | `1468969a9a265804` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_404e448f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "404e448f179f662439bd08b2abbcddcaaf0034d11d786cc878cce6f9ef57b570"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:46:16"
  condition:
    hash.sha256(0, filesize) == "404e448f179f662439bd08b2abbcddcaaf0034d11d786cc878cce6f9ef57b570"
}
```

### Sample 91: `bb518757a09ffe9c`

| Field | Value |
|---|---|
| SHA-256 | `bb518757a09ffe9c92755bf86d86d589204ece9869918c7497c8739825bcc914` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-15 22:46:14` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, Stealer, Warden, WardenStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2337ba2ce0d33a9d32b41c23a95cdf0` |
| SHA-1 | `8a7bbe449467067d3798a6478e3c8f0cab63f3c3` |
| SHA-256 | `bb518757a09ffe9c92755bf86d86d589204ece9869918c7497c8739825bcc914` |
| SHA3-384 | `cee52b76550fec980b3f7e983661aee64f4a68a6dd33fff39f63e663828d564ce13a27f247a676af684dbfd9314f9d77` |
| IMPHASH | `df357907a44e6d5a4856023378f55720` |
| TLSH | `T1D8454B93AF69AEB0E856917261EB23002F175EFA05B3C585D6DD8D3708580A839FF14F` |
| SSDEEP | `12288:APhrcBRr8X0Nl6DlnQWGgnPg86QKgp2fW3aUIDU2qIhltdAU1dVu5Zpn+owo4rz:APh4BNGVPg2j4fTUCq4t+U1EptKz` |
| ICON-DHASH | `00041a72721a0400` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_bb518757
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb518757a09ffe9c92755bf86d86d589204ece9869918c7497c8739825bcc914"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:46:14"
  condition:
    hash.sha256(0, filesize) == "bb518757a09ffe9c92755bf86d86d589204ece9869918c7497c8739825bcc914"
}
```

### Sample 92: `fb799fbe2729fa88`

| Field | Value |
|---|---|
| SHA-256 | `fb799fbe2729fa88358d32375c15aa41b2de62e981655e60d4f53efb4e4fee73` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-15 22:46:12` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, Stealer, Warden, WardenStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5657b30f1fb37aa0044380faa3e4187` |
| SHA-1 | `18b52c37e549cd01e4a5acc22c24362c654b82c0` |
| SHA-256 | `fb799fbe2729fa88358d32375c15aa41b2de62e981655e60d4f53efb4e4fee73` |
| SHA3-384 | `eb6cc1ccc9db30d4c331dc120c6781756d6e56414557d5bbc4589ca4b950f8141fa3b59df576d2e286a5ef4ff9e524c0` |
| IMPHASH | `c4442b2bd61521a56d13b9dc1493b1d4` |
| TLSH | `T195552446E7533AB5E01E5030F91FE5449B64E8112AB196B632CDEE060826EC53AFCFDD` |
| SSDEEP | `24576:R36dnpYWhrG/KbRDHX5tnuoSeiFMqpBZ7ejDnjbxT/hh7JVlBHvJgQ1l1S:R3mlr5tn0nFxD1ejD9fjHhd1lo` |
| ICON-DHASH | `6816706969711628` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_fb799fbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb799fbe2729fa88358d32375c15aa41b2de62e981655e60d4f53efb4e4fee73"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:46:12"
  condition:
    hash.sha256(0, filesize) == "fb799fbe2729fa88358d32375c15aa41b2de62e981655e60d4f53efb4e4fee73"
}
```

### Sample 93: `cd0db04913047500`

| Field | Value |
|---|---|
| SHA-256 | `cd0db04913047500d062f676d4099aced7ef039c7e12cebaddff6aac41def3ea` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-15 22:42:20` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, Stealer, Warden, WardenStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `838e3bb35c69f9d5b4d273d6ed222a60` |
| SHA-1 | `bb85eb271baedbdc4c42648d85e1907c2746ae11` |
| SHA-256 | `cd0db04913047500d062f676d4099aced7ef039c7e12cebaddff6aac41def3ea` |
| SHA3-384 | `d9544cb1e86ba237907c7115b01dd0a8116d9eba01c87e6a54db174c8f9c328227ace86efdb5b3dd626ce5079e4b9ee8` |
| IMPHASH | `ac5cde1fff4e169446da0bc260a632db` |
| TLSH | `T1AE352A2A5B98CFFDF479E834B20EC45EC6A11C9246E505C72D6C85E05C72691CEFB83A` |
| SSDEEP | `24576:KuYDUX3Z79tZXC9cawCaHXtkyPHx+GL4WQ:NYwneeCaHX7PHx3L4` |
| ICON-DHASH | `0012716969711200` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_cd0db049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd0db04913047500d062f676d4099aced7ef039c7e12cebaddff6aac41def3ea"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:42:20"
  condition:
    hash.sha256(0, filesize) == "cd0db04913047500d062f676d4099aced7ef039c7e12cebaddff6aac41def3ea"
}
```

### Sample 94: `3508e6cb5ce9a6f5`

| Field | Value |
|---|---|
| SHA-256 | `3508e6cb5ce9a6f5e78e5a636ee358fe47b6496f9af948fcce0cd7bf296d9690` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-15 22:38:07` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX3.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4630bebaa218e456f1752306038973d0` |
| SHA-1 | `e1ba20fad4c44734a8b4900c54b11ff401c24ac5` |
| SHA-256 | `3508e6cb5ce9a6f5e78e5a636ee358fe47b6496f9af948fcce0cd7bf296d9690` |
| SHA3-384 | `7befd10aed631170cf55891fc846a9d91502422ccd6b704c50b292bb3e41f0dd980d45e4d57f02719b1212e6d00dd3b9` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D9E6120BBCE51DEAC0A9A33188B716527B71BC491F2223C72A90B3792F76BD05D39754` |
| SSDEEP | `49152:kzb1eqcZzygbojCgJ1j5PVrqPqLZ8E/vo/CAp4a373zDCCCnYHcuBIjh7GXTQa8R:kH19j/OpB+MWgPG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_3508e6cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3508e6cb5ce9a6f5e78e5a636ee358fe47b6496f9af948fcce0cd7bf296d9690"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-15 22:38:07"
  condition:
    hash.sha256(0, filesize) == "3508e6cb5ce9a6f5e78e5a636ee358fe47b6496f9af948fcce0cd7bf296d9690"
}
```

### Sample 95: `25389448ceaa92b3`

| Field | Value |
|---|---|
| SHA-256 | `25389448ceaa92b3133c26e4fe2cc34cfc908f32cf44d93cc886a2d62deb06e1` |
| Family label | `unknown` |
| File name | `SystemHealthMonitor.exe` |
| File type | `exe` |
| First seen | `2026-10-15 22:26:01` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfe84bfa99992de2e606b2c1c49871a1` |
| SHA-1 | `ff49c5791b4deaf058f0d74d061410319cf95252` |
| SHA-256 | `25389448ceaa92b3133c26e4fe2cc34cfc908f32cf44d93cc886a2d62deb06e1` |
| SHA3-384 | `0954489afa5e22ff9f90f680b3a944f053aca9710807d3251bd88493d3326147f2995c6e862e107270775c9c141da2e1` |
| IMPHASH | `ec533b3e4c20d64408cbc70009cde003` |
| TLSH | `T12AF421AC636D2F17E25171F37A7229206ED115BD037F25C3C24285DA0B273528A6BDEB` |
| SSDEEP | `6144:DeEU7BYrccUZTEJh+brYBKDC42hh1vSZPfcAmAPBpfWiTvzE5ls8qyxYRQ+8xSrU:qlTA2bKkqb1INpOUgiRQfbK6Td` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_25389448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25389448ceaa92b3133c26e4fe2cc34cfc908f32cf44d93cc886a2d62deb06e1"
    family = "unknown"
    file_name = "SystemHealthMonitor.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:26:01"
  condition:
    hash.sha256(0, filesize) == "25389448ceaa92b3133c26e4fe2cc34cfc908f32cf44d93cc886a2d62deb06e1"
}
```

### Sample 96: `8acc511937f2b558`

| Field | Value |
|---|---|
| SHA-256 | `8acc511937f2b5585d58d96bcc7eec719430bcee7c5b088499c81e0b75c040a4` |
| Family label | `FleetDeck` |
| File name | `8acc511937f2b5585d58d96bcc7eec719430bcee7c5b088499c81e0b75c040a4.exe` |
| File type | `exe` |
| First seen | `2026-10-15 22:17:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, FleetDeck, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c48ae59baba99bfeedfee5f3ffcbb5c8` |
| SHA-1 | `5f7206b1ab81931a24aab3e66fa8c05a25bf8430` |
| SHA-256 | `8acc511937f2b5585d58d96bcc7eec719430bcee7c5b088499c81e0b75c040a4` |
| SHA3-384 | `0d0265c7314c6bd4ef42f9faf14c858cb03a3d150dffa019f93a1a900bd97d2b345db104042ef266b1e00f8b33a2a5cd` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T15316CF90FCDB54B5E603553158AB62BF2734AD094F31CBC7D6407BAEAC73AE10936229` |
| SSDEEP | `49152:OP0dfmVfyr+CU8D1i+7BN53NPyVzc9neiUM1kIq8HQ442lyXp8SnUIA26Yu0:OPt6Laeoi+0QFfXp4Oi0` |
| ICON-DHASH | `e4922945552992e4` |

#### Technical Assessment

- The sample is tracked as `FleetDeck` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_FleetDeck_096_8acc5119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8acc511937f2b5585d58d96bcc7eec719430bcee7c5b088499c81e0b75c040a4"
    family = "FleetDeck"
    file_name = "8acc511937f2b5585d58d96bcc7eec719430bcee7c5b088499c81e0b75c040a4.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:17:18"
  condition:
    hash.sha256(0, filesize) == "8acc511937f2b5585d58d96bcc7eec719430bcee7c5b088499c81e0b75c040a4"
}
```

### Sample 97: `dfd08e1d7a34bae6`

| Field | Value |
|---|---|
| SHA-256 | `dfd08e1d7a34bae6836b3915b45b8637b85cdc998198c5bf148fba5e96f15c21` |
| Family label | `unknown` |
| File name | `dfd08e1d7a34bae6836b3915b45b8637b85cdc998198c5bf148fba5e96f15c21.exe` |
| File type | `exe` |
| First seen | `2026-10-15 21:57:20` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5782b8d469bbc9045ebd2316c2aefbd5` |
| SHA-1 | `f679adea19ac0e88a50cfefb88825a086102f77d` |
| SHA-256 | `dfd08e1d7a34bae6836b3915b45b8637b85cdc998198c5bf148fba5e96f15c21` |
| SHA3-384 | `78c97d32c35ef3694f06f42650a9a27ce89929a9f52deb312a2662f2706f49a3fa32de45a9f2c0003229eaeb95d44fd0` |
| IMPHASH | `7182b1ea6f92adbf459a2c65d8d4dd9e` |
| TLSH | `T1F5C33966B2E01198DBB581F6D9921706EB7074761B15A3DB2BB853B31B2B4C68F3C3D0` |
| SSDEEP | `3072:u2sMWkzbJh1qZ9QW69hd1MMdxPe9N9uA0hu9TBfcXnI:PbJhs7QW69hd1MMdxPe9N9uA0hu9TBKI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_dfd08e1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfd08e1d7a34bae6836b3915b45b8637b85cdc998198c5bf148fba5e96f15c21"
    family = "unknown"
    file_name = "dfd08e1d7a34bae6836b3915b45b8637b85cdc998198c5bf148fba5e96f15c21.exe"
    file_type = "exe"
    first_seen = "2026-10-15 21:57:20"
  condition:
    hash.sha256(0, filesize) == "dfd08e1d7a34bae6836b3915b45b8637b85cdc998198c5bf148fba5e96f15c21"
}
```

### Sample 98: `3c51e5995af60587`

| Field | Value |
|---|---|
| SHA-256 | `3c51e5995af60587fbf019f11f94d843b8ae3fb82786b6bd468bc60660783fc5` |
| Family label | `unknown` |
| File name | `fuck_niggers_2.hta` |
| File type | `hta` |
| First seen | `2026-10-15 21:44:51` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `967ef630b3fdd49fe3ac4a1d8d91af3f` |
| SHA-1 | `66ee0aff9f7053828083ff86e20aab5e43f7067e` |
| SHA-256 | `3c51e5995af60587fbf019f11f94d843b8ae3fb82786b6bd468bc60660783fc5` |
| SHA3-384 | `dedc98fe89235a1d6dfe5e7830572877cf012d7e9b1c0b051687befd77363ac96e60f0c3fca34ce28b173f257c936bc1` |
| TLSH | `T14A42195CAED171A0EA1717DEB3AF25690228A0C7200DC484F94CDDE87F46BDC4A57B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzN3bqFtCX6SpnRUM:sXX+/DV7k/3oFtuRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_3c51e599
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c51e5995af60587fbf019f11f94d843b8ae3fb82786b6bd468bc60660783fc5"
    family = "unknown"
    file_name = "fuck_niggers_2.hta"
    file_type = "hta"
    first_seen = "2026-10-15 21:44:51"
  condition:
    hash.sha256(0, filesize) == "3c51e5995af60587fbf019f11f94d843b8ae3fb82786b6bd468bc60660783fc5"
}
```

### Sample 99: `037b186f042dcf92`

| Field | Value |
|---|---|
| SHA-256 | `037b186f042dcf9205fbaf2156965422201be1bbf3e65f7998a8dccb77f6dcf3` |
| Family label | `unknown` |
| File name | `redtail.x86_64` |
| File type | `elf` |
| First seen | `2026-10-15 21:33:54` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41467552946af251d0aaf7352454b05c` |
| SHA-1 | `65479673d1aef77415dc0d9fbd9f1fb6746dac00` |
| SHA-256 | `037b186f042dcf9205fbaf2156965422201be1bbf3e65f7998a8dccb77f6dcf3` |
| SHA3-384 | `5aa02395458847f5c0d509fb6e4234251cfd3877605ba005931a9054d961c0803b8b4ecd9b7ed4e33d968e87b4094f99` |
| TLSH | `T1EFF423BDBF1898EDC32A835874A0E25A4EC5B85B7B279056387D92F853EDDD33813064` |
| SSDEEP | `12288:lertoZakLSHFhOKOEgyPG5/kuxwnIdZofKCHSZyvlJ0k/X3SK53AZa+GySM1VGws:lertoMkebO9ErP4/kuxwn4ZCKBAvck/D` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_037b186f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "037b186f042dcf9205fbaf2156965422201be1bbf3e65f7998a8dccb77f6dcf3"
    family = "unknown"
    file_name = "redtail.x86_64"
    file_type = "elf"
    first_seen = "2026-10-15 21:33:54"
  condition:
    hash.sha256(0, filesize) == "037b186f042dcf9205fbaf2156965422201be1bbf3e65f7998a8dccb77f6dcf3"
}
```

### Sample 100: `47fb5347bb16aac0`

| Field | Value |
|---|---|
| SHA-256 | `47fb5347bb16aac0edc445d921531655792986422c739ba25695c003f7b94c7d` |
| Family label | `unknown` |
| File name | `bot.sh` |
| File type | `sh` |
| First seen | `2026-10-15 21:33:16` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4941d85be6541f15f207d71e9c1e1323` |
| SHA-1 | `b38aee3b8a7a2a9b3ac378bb3b83f4e4f3a404fa` |
| SHA-256 | `47fb5347bb16aac0edc445d921531655792986422c739ba25695c003f7b94c7d` |
| SHA3-384 | `c41c3299684604cb5eb3e3e9ab5bfd39e5d1aa551920452e9c859de3217fdfa9f9b02457ca186647911c53d7b83057e6` |
| TLSH | `T1850175E4E4285830BB0DD13E651EA530CCC2052F4A787038B00FC40BEBFC61B3898326` |
| SSDEEP | `12:MkjJoISGtSHmBOV1x76hyxA0U2L3FM7ou9CZoCVfxq2LaHwCK:9RSqSHH1x76h6UkMox6CBxqez` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_47fb5347
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47fb5347bb16aac0edc445d921531655792986422c739ba25695c003f7b94c7d"
    family = "unknown"
    file_name = "bot.sh"
    file_type = "sh"
    first_seen = "2026-10-15 21:33:16"
  condition:
    hash.sha256(0, filesize) == "47fb5347bb16aac0edc445d921531655792986422c739ba25695c003f7b94c7d"
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
 * Generated: 2026-10-16T04:41:16.162985+00:00
 */

rule MalwareBazaar_unknown_001_2fcb530e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fcb530e9fc950da8f43f38beb90beb63b26730f53b7e954b3813fe213ccd060"
    family = "unknown"
    file_name = "mbupload-g68ppj6r.bin"
    file_type = "rar"
    first_seen = "2026-10-16 04:32:46"
  condition:
    hash.sha256(0, filesize) == "2fcb530e9fc950da8f43f38beb90beb63b26730f53b7e954b3813fe213ccd060"
}

rule MalwareBazaar_unknown_002_d5d1874b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5d1874bec53d5afa09ef36ae3e88630122e14c6f224b14752e5bd014d51fe16"
    family = "unknown"
    file_name = "mbupload-100x05rt.bin"
    file_type = "rar"
    first_seen = "2026-10-16 04:32:30"
  condition:
    hash.sha256(0, filesize) == "d5d1874bec53d5afa09ef36ae3e88630122e14c6f224b14752e5bd014d51fe16"
}

rule MalwareBazaar_unknown_003_dcbe27c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcbe27c0161bdf1922bf060c50b086031a7ffde000bff3bf4fae3df10bbbd096"
    family = "unknown"
    file_name = "mbupload-g4p5uyvx.bin"
    file_type = "zip"
    first_seen = "2026-10-16 04:31:17"
  condition:
    hash.sha256(0, filesize) == "dcbe27c0161bdf1922bf060c50b086031a7ffde000bff3bf4fae3df10bbbd096"
}

rule MalwareBazaar_unknown_004_77d5542a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77d5542a5b29e500d9bb571bb191fc787074c411ed73e543eea8e1769a13105a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 04:31:07"
  condition:
    hash.sha256(0, filesize) == "77d5542a5b29e500d9bb571bb191fc787074c411ed73e543eea8e1769a13105a"
}

rule MalwareBazaar_unknown_005_2a9d70d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a9d70d79cf080d7037f624722d40c4f39374f2a4459d3331ed608c293b0176e"
    family = "unknown"
    file_name = "mbupload-wqe_lfhw.bin"
    file_type = "zip"
    first_seen = "2026-10-16 04:31:03"
  condition:
    hash.sha256(0, filesize) == "2a9d70d79cf080d7037f624722d40c4f39374f2a4459d3331ed608c293b0176e"
}

rule MalwareBazaar_unknown_006_3f1f116c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f1f116c327d7d35af96e73ccf68b95d2422782d904f0715834b99e27a7465b4"
    family = "unknown"
    file_name = "mbupload-ax2anxuk.bin"
    file_type = "zip"
    first_seen = "2026-10-16 04:30:43"
  condition:
    hash.sha256(0, filesize) == "3f1f116c327d7d35af96e73ccf68b95d2422782d904f0715834b99e27a7465b4"
}

rule MalwareBazaar_unknown_007_34b78a64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34b78a64d76e3d03455fa25dda4292eea59dea145f0c3f2c2addcb7380ff988b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 04:29:58"
  condition:
    hash.sha256(0, filesize) == "34b78a64d76e3d03455fa25dda4292eea59dea145f0c3f2c2addcb7380ff988b"
}

rule MalwareBazaar_SalatStealer_008_e096855e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e096855e3202ad914ea6ff670e1872d813f6104f3c0b4ed878d0fb376a772c5b"
    family = "SalatStealer"
    file_name = "111.exe"
    file_type = "exe"
    first_seen = "2026-10-16 04:26:31"
  condition:
    hash.sha256(0, filesize) == "e096855e3202ad914ea6ff670e1872d813f6104f3c0b4ed878d0fb376a772c5b"
}

rule MalwareBazaar_SalatStealer_009_93b60bb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93b60bb3affff182a38cfd66c956204db0509a72844a8ff69582892e16437646"
    family = "SalatStealer"
    file_name = "111.exe"
    file_type = "exe"
    first_seen = "2026-10-16 04:25:59"
  condition:
    hash.sha256(0, filesize) == "93b60bb3affff182a38cfd66c956204db0509a72844a8ff69582892e16437646"
}

rule MalwareBazaar_unknown_010_3180cf55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3180cf557014640edb8525d0029ca2ccb51ad1515288ba12a7c65fe9d872d91b"
    family = "unknown"
    file_name = "3180cf557014640edb8525d0029ca2ccb51ad1515288ba12a7c65fe9d872d91b"
    file_type = "sh"
    first_seen = "2026-10-16 04:20:59"
  condition:
    hash.sha256(0, filesize) == "3180cf557014640edb8525d0029ca2ccb51ad1515288ba12a7c65fe9d872d91b"
}

rule MalwareBazaar_AgentTesla_011_3fac4942
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fac4942b8c7461044de38bdc07fdb7e7f21a70c51434f1248e9c5b85e657e02"
    family = "AgentTesla"
    file_name = "Payment Confirmation - Invoice No. INV-2026-1048.js"
    file_type = "js"
    first_seen = "2026-10-16 04:16:01"
  condition:
    hash.sha256(0, filesize) == "3fac4942b8c7461044de38bdc07fdb7e7f21a70c51434f1248e9c5b85e657e02"
}

rule MalwareBazaar_unknown_012_5a417f45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a417f4582f91f21f2842b170d21cf5f92b48fad39183e315d505d5a2deef5c0"
    family = "unknown"
    file_name = "mbupload-94wt5_hu.bin"
    file_type = "zip"
    first_seen = "2026-10-16 04:15:36"
  condition:
    hash.sha256(0, filesize) == "5a417f4582f91f21f2842b170d21cf5f92b48fad39183e315d505d5a2deef5c0"
}

rule MalwareBazaar_unknown_013_73b0347a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73b0347a300e8d5b13d37ea451069999b8266093f47c9c461ddf85568e9f9245"
    family = "unknown"
    file_name = "mbupload-fmdqlau9.bin"
    file_type = "zip"
    first_seen = "2026-10-16 04:15:20"
  condition:
    hash.sha256(0, filesize) == "73b0347a300e8d5b13d37ea451069999b8266093f47c9c461ddf85568e9f9245"
}

rule MalwareBazaar_unknown_014_d172a3bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d172a3bd408a9a96b9e18ca3e7da896ad5c6014cedb61d827919e10df040683e"
    family = "unknown"
    file_name = "fuck_niggers_26.hta"
    file_type = "hta"
    first_seen = "2026-10-16 04:06:29"
  condition:
    hash.sha256(0, filesize) == "d172a3bd408a9a96b9e18ca3e7da896ad5c6014cedb61d827919e10df040683e"
}

rule MalwareBazaar_unknown_015_74b12e4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74b12e4a6b80ede0f200112a144043e8441b794b72298358a4fe054dcb925fde"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 04:05:28"
  condition:
    hash.sha256(0, filesize) == "74b12e4a6b80ede0f200112a144043e8441b794b72298358a4fe054dcb925fde"
}

rule MalwareBazaar_unknown_016_b19eb1e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b19eb1e98d0ebf251376dd1c76e2cc6544356adecb415880c6103aae2292dacb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 04:04:13"
  condition:
    hash.sha256(0, filesize) == "b19eb1e98d0ebf251376dd1c76e2cc6544356adecb415880c6103aae2292dacb"
}

rule MalwareBazaar_Vidar_017_e0b22436
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0b224363b0fac2b9a2ff32f397e1b03feb33b987e8cb85bbfdca2678c7973b1"
    family = "Vidar"
    file_name = "e0b224363b0fac2b9a2ff32f397e1b03feb33b987e8cb85bbfdca2678c7973b1.bin"
    file_type = "exe"
    first_seen = "2026-10-16 03:45:16"
  condition:
    hash.sha256(0, filesize) == "e0b224363b0fac2b9a2ff32f397e1b03feb33b987e8cb85bbfdca2678c7973b1"
}

rule MalwareBazaar_unknown_018_2de2cf00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2de2cf002786d5e95d2a413aa24e3a7220b62758006cb2ec7c70c3c5ac2d081b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 03:44:38"
  condition:
    hash.sha256(0, filesize) == "2de2cf002786d5e95d2a413aa24e3a7220b62758006cb2ec7c70c3c5ac2d081b"
}

rule MalwareBazaar_unknown_019_b1cc5ad7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1cc5ad78b72d2f0a94d370e840e24ea38a31690ece3af851da345975da7ca5c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 03:19:08"
  condition:
    hash.sha256(0, filesize) == "b1cc5ad78b72d2f0a94d370e840e24ea38a31690ece3af851da345975da7ca5c"
}

rule MalwareBazaar_ConnectWise_020_51c23cd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51c23cd7ae3be097ad412657d6e03b4794fbc19853da07f24609fb7148610a5f"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 02:57:20"
  condition:
    hash.sha256(0, filesize) == "51c23cd7ae3be097ad412657d6e03b4794fbc19853da07f24609fb7148610a5f"
}

rule MalwareBazaar_unknown_021_8bdb3ce1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bdb3ce10dee7a3249a186050d7f804bca19859f292ddad7ae8c5afbb649a07b"
    family = "unknown"
    file_name = "8bdb3ce10dee7a3249a186050d7f804bca19859f292ddad7ae8c5afbb649a07b.exe"
    file_type = "exe"
    first_seen = "2026-10-16 02:29:38"
  condition:
    hash.sha256(0, filesize) == "8bdb3ce10dee7a3249a186050d7f804bca19859f292ddad7ae8c5afbb649a07b"
}

rule MalwareBazaar_unknown_022_0e6d59fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e6d59fcdf8f143e23b076cc8380d6d23324839ae4f91793133b600e7eb76eb9"
    family = "unknown"
    file_name = "0e6d59fcdf8f143e23b076cc8380d6d23324839ae4f91793133b600e7eb76eb9.exe"
    file_type = "exe"
    first_seen = "2026-10-16 02:28:48"
  condition:
    hash.sha256(0, filesize) == "0e6d59fcdf8f143e23b076cc8380d6d23324839ae4f91793133b600e7eb76eb9"
}

rule MalwareBazaar_unknown_023_0b8b6f4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339"
    family = "unknown"
    file_name = "0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339.exe"
    file_type = "exe"
    first_seen = "2026-10-16 02:28:09"
  condition:
    hash.sha256(0, filesize) == "0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339"
}

rule MalwareBazaar_Mirai_024_3240e7ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3240e7ab26be062b3eba73429916b77a9894fffd76af12ac699a4e15676fc384"
    family = "Mirai"
    file_name = "fghe3tj.arm"
    file_type = "elf"
    first_seen = "2026-10-16 02:14:48"
  condition:
    hash.sha256(0, filesize) == "3240e7ab26be062b3eba73429916b77a9894fffd76af12ac699a4e15676fc384"
}

rule MalwareBazaar_Mirai_025_19a3b792
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19a3b7924c8f764a4fe6fc2c9fff192f7571cd50023fe37f9cc2ab2f3a4fa091"
    family = "Mirai"
    file_name = "fghe3tj.x86"
    file_type = "elf"
    first_seen = "2026-10-16 02:11:23"
  condition:
    hash.sha256(0, filesize) == "19a3b7924c8f764a4fe6fc2c9fff192f7571cd50023fe37f9cc2ab2f3a4fa091"
}

rule MalwareBazaar_Mirai_026_d3ad28e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3ad28e1f88e8a2d4ad820d5c6ff81605932160197b5831de9d32083a776a40b"
    family = "Mirai"
    file_name = "fghe3tj.sh4"
    file_type = "elf"
    first_seen = "2026-10-16 02:01:26"
  condition:
    hash.sha256(0, filesize) == "d3ad28e1f88e8a2d4ad820d5c6ff81605932160197b5831de9d32083a776a40b"
}

rule MalwareBazaar_unknown_027_c2f097ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2f097ae54d4379b3d3c3a14f3171557666f522cda5eed3cc4418bc3e38677ab"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 01:58:39"
  condition:
    hash.sha256(0, filesize) == "c2f097ae54d4379b3d3c3a14f3171557666f522cda5eed3cc4418bc3e38677ab"
}

rule MalwareBazaar_Mirai_028_3fa014e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa014e6a9d11e439b01e1c24263471209be3f5b91129564fe43bff0367191b1"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-10-16 01:56:33"
  condition:
    hash.sha256(0, filesize) == "3fa014e6a9d11e439b01e1c24263471209be3f5b91129564fe43bff0367191b1"
}

rule MalwareBazaar_Mirai_029_5e8e2270
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e8e2270f35bed7743c090f0f7bc1c5fd9da2fb1c364ce5019838ae9c3eaec2b"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-10-16 01:56:28"
  condition:
    hash.sha256(0, filesize) == "5e8e2270f35bed7743c090f0f7bc1c5fd9da2fb1c364ce5019838ae9c3eaec2b"
}

rule MalwareBazaar_Mirai_030_36736d65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36736d658d375c661de81054af9afd5156fab149feee2c7a9bfc2637de83be18"
    family = "Mirai"
    file_name = "Space.mips"
    file_type = "elf"
    first_seen = "2026-10-16 01:56:24"
  condition:
    hash.sha256(0, filesize) == "36736d658d375c661de81054af9afd5156fab149feee2c7a9bfc2637de83be18"
}

rule MalwareBazaar_Mirai_031_8f0d462d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f0d462dcfda9f6f862fac32a16e7388feb28a2edd021af00a567e018a24bfb2"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-10-16 01:56:21"
  condition:
    hash.sha256(0, filesize) == "8f0d462dcfda9f6f862fac32a16e7388feb28a2edd021af00a567e018a24bfb2"
}

rule MalwareBazaar_Mirai_032_a4db7f02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4db7f02e7c9c0c1a3212f9210f7a313ff657615a84a7eb9f11d6790c57503a9"
    family = "Mirai"
    file_name = "Space.arm7"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:34"
  condition:
    hash.sha256(0, filesize) == "a4db7f02e7c9c0c1a3212f9210f7a313ff657615a84a7eb9f11d6790c57503a9"
}

rule MalwareBazaar_Mirai_033_9662a922
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9662a92247bc031c6f39c8c72853c46b4a22bce6a73d27f3fb8b3b368522f8b0"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:29"
  condition:
    hash.sha256(0, filesize) == "9662a92247bc031c6f39c8c72853c46b4a22bce6a73d27f3fb8b3b368522f8b0"
}

rule MalwareBazaar_Mirai_034_1128b9ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1128b9ab3653d22895991962a0aa5217ae6332b079671bf11c6995b4d15f18ec"
    family = "Mirai"
    file_name = "Space.ppc"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:29"
  condition:
    hash.sha256(0, filesize) == "1128b9ab3653d22895991962a0aa5217ae6332b079671bf11c6995b4d15f18ec"
}

rule MalwareBazaar_Mirai_035_a8dd660d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8dd660d3b9533e614ed85aa9e84b4c8028793305779c7c92819a51f508f5f62"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:27"
  condition:
    hash.sha256(0, filesize) == "a8dd660d3b9533e614ed85aa9e84b4c8028793305779c7c92819a51f508f5f62"
}

rule MalwareBazaar_Mirai_036_63ae61ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63ae61ea6ed10789573a2434003b791b930ba67c4d5011c0433022102b0c6f7a"
    family = "Mirai"
    file_name = "Space.mips"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:25"
  condition:
    hash.sha256(0, filesize) == "63ae61ea6ed10789573a2434003b791b930ba67c4d5011c0433022102b0c6f7a"
}

rule MalwareBazaar_Mirai_037_2b31b7bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b31b7bdafb0d4c08f517882311ff53a597e1b9f09c0473402045dfe636cf5d3"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:22"
  condition:
    hash.sha256(0, filesize) == "2b31b7bdafb0d4c08f517882311ff53a597e1b9f09c0473402045dfe636cf5d3"
}

rule MalwareBazaar_Mirai_038_b1290e0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1290e0cbc7721e2f33eefb3ed80b9b2d005ab85f29fd89c82b47ba25195b6c4"
    family = "Mirai"
    file_name = "Space.spc"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:20"
  condition:
    hash.sha256(0, filesize) == "b1290e0cbc7721e2f33eefb3ed80b9b2d005ab85f29fd89c82b47ba25195b6c4"
}

rule MalwareBazaar_Mirai_039_8f367ef5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f367ef5666641bdfac1e6ab117526792cf89570be786b8ddb769838868fa69a"
    family = "Mirai"
    file_name = "Space.m68k"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:18"
  condition:
    hash.sha256(0, filesize) == "8f367ef5666641bdfac1e6ab117526792cf89570be786b8ddb769838868fa69a"
}

rule MalwareBazaar_Mirai_040_26017b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26017b4203c787953af0d7b0b4b6140a3fa339d333878aeb55c76681ac249273"
    family = "Mirai"
    file_name = "Space.sh4"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:15"
  condition:
    hash.sha256(0, filesize) == "26017b4203c787953af0d7b0b4b6140a3fa339d333878aeb55c76681ac249273"
}

rule MalwareBazaar_Mirai_041_35b2eb33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35b2eb3312c9b29b65fe88a5af1d87407c881e42ee39931e81f1e43050e798ed"
    family = "Mirai"
    file_name = "Space.arm7"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:13"
  condition:
    hash.sha256(0, filesize) == "35b2eb3312c9b29b65fe88a5af1d87407c881e42ee39931e81f1e43050e798ed"
}

rule MalwareBazaar_Mirai_042_29f7706a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29f7706aab236475be7099feb866784cbcb8d9b5c8bdce825082addce5a203cb"
    family = "Mirai"
    file_name = "Space.mpsl"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:10"
  condition:
    hash.sha256(0, filesize) == "29f7706aab236475be7099feb866784cbcb8d9b5c8bdce825082addce5a203cb"
}

rule MalwareBazaar_Mirai_043_9e26d0fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e26d0fdff3d1b01dea60e235b25cb07307a8142cc615969965d8606ba30cb6f"
    family = "Mirai"
    file_name = "Space.ppc"
    file_type = "elf"
    first_seen = "2026-10-16 01:55:08"
  condition:
    hash.sha256(0, filesize) == "9e26d0fdff3d1b01dea60e235b25cb07307a8142cc615969965d8606ba30cb6f"
}

rule MalwareBazaar_Mirai_044_8ca1337b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ca1337be559848cd3239f6f0fb35f31be98dddab1c003e6b57722dd3ae28e95"
    family = "Mirai"
    file_name = "fghe3tj.arm7"
    file_type = "elf"
    first_seen = "2026-10-16 01:46:15"
  condition:
    hash.sha256(0, filesize) == "8ca1337be559848cd3239f6f0fb35f31be98dddab1c003e6b57722dd3ae28e95"
}

rule MalwareBazaar_unknown_045_4b8fcd33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b8fcd336a3f4f2ce2809b3d7079777f78431bebe22e52bbcf630c775561e3ec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 01:33:52"
  condition:
    hash.sha256(0, filesize) == "4b8fcd336a3f4f2ce2809b3d7079777f78431bebe22e52bbcf630c775561e3ec"
}

rule MalwareBazaar_CoinMiner_046_a2b27dee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2b27dee9494b5978815784900f167ed093028f1eba443a7d02b11b66def9483"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 01:21:35"
  condition:
    hash.sha256(0, filesize) == "a2b27dee9494b5978815784900f167ed093028f1eba443a7d02b11b66def9483"
}

rule MalwareBazaar_unknown_047_39437aaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39437aaa739756c8fd63d59e65c7ffa148906cd14fe6d685c2a0a64eec5cd19a"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-16 01:16:37"
  condition:
    hash.sha256(0, filesize) == "39437aaa739756c8fd63d59e65c7ffa148906cd14fe6d685c2a0a64eec5cd19a"
}

rule MalwareBazaar_WannaCry_048_b2f356e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746"
    family = "WannaCry"
    file_name = "b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746"
    file_type = "exe"
    first_seen = "2026-10-16 01:15:09"
  condition:
    hash.sha256(0, filesize) == "b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746"
}

rule MalwareBazaar_unknown_049_0bc73de0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc73de0da28e7160e3e00c2a2305ea4e4bdf35fb471e42d3da1bd5483b2f85f"
    family = "unknown"
    file_name = "PO_22042026_ORDER_DETAILSpdf.js"
    file_type = "js"
    first_seen = "2026-10-16 01:08:35"
  condition:
    hash.sha256(0, filesize) == "0bc73de0da28e7160e3e00c2a2305ea4e4bdf35fb471e42d3da1bd5483b2f85f"
}

rule MalwareBazaar_unknown_050_9ccf73fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ccf73fb4b844474210194e3bb87f24e2234ee5eb5f6c8dedb68b942ad737026"
    family = "unknown"
    file_name = "Affektioner.vbs"
    file_type = "vbs"
    first_seen = "2026-10-16 01:01:49"
  condition:
    hash.sha256(0, filesize) == "9ccf73fb4b844474210194e3bb87f24e2234ee5eb5f6c8dedb68b942ad737026"
}

rule MalwareBazaar_unknown_051_3b3ed840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b3ed840462a50adbae17d5e4c2fc09ae6a48b88e8e5958bc42d6e77702b2e90"
    family = "unknown"
    file_name = "classcomputer.hta"
    file_type = "hta"
    first_seen = "2026-10-16 01:00:24"
  condition:
    hash.sha256(0, filesize) == "3b3ed840462a50adbae17d5e4c2fc09ae6a48b88e8e5958bc42d6e77702b2e90"
}

rule MalwareBazaar_RustyStealer_052_5fe4d4ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fe4d4fff5da2c58f4e4450d67f5ab325b78beba7cd294169e9e8af4ef429f6f"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 00:47:02"
  condition:
    hash.sha256(0, filesize) == "5fe4d4fff5da2c58f4e4450d67f5ab325b78beba7cd294169e9e8af4ef429f6f"
}

rule MalwareBazaar_AMOS_053_1e8ed19e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a"
    family = "AMOS"
    file_name = "macho_1e8ed19e771e.bin"
    file_type = "macho"
    first_seen = "2026-10-16 00:45:10"
  condition:
    hash.sha256(0, filesize) == "1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a"
}

rule MalwareBazaar_unknown_054_dbd15a7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbd15a7fdb3753b3890cc230208a50bed29bcbd66aa3f0986f69e691456e16d8"
    family = "unknown"
    file_name = "Zjckk0.hta"
    file_type = "hta"
    first_seen = "2026-10-16 00:42:25"
  condition:
    hash.sha256(0, filesize) == "dbd15a7fdb3753b3890cc230208a50bed29bcbd66aa3f0986f69e691456e16d8"
}

rule MalwareBazaar_unknown_055_12cc08c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12cc08c6601591c376125268c78cab8ddb34287e2f40c503b172fc3d132da619"
    family = "unknown"
    file_name = "12cc08c6601591c376125268c78cab8ddb34287e2f40c503b172fc3d132da619.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:41:57"
  condition:
    hash.sha256(0, filesize) == "12cc08c6601591c376125268c78cab8ddb34287e2f40c503b172fc3d132da619"
}

rule MalwareBazaar_UmbralStealer_056_82855f65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82855f659d8d5b23c68205a954a067c183c8af024f2340e3141aaeaad4b1c4b0"
    family = "UmbralStealer"
    file_name = "82855f659d8d5b23c68205a954a067c183c8af024f2340e3141aaeaad4b1c4b0.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:41:13"
  condition:
    hash.sha256(0, filesize) == "82855f659d8d5b23c68205a954a067c183c8af024f2340e3141aaeaad4b1c4b0"
}

rule MalwareBazaar_AsyncRAT_057_98379ccd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98379ccde6fc0517a749bdfb4fa3a384ccc8dbb86f1f4c1ada23a3bf57760d87"
    family = "AsyncRAT"
    file_name = "98379ccde6fc0517a749bdfb4fa3a384ccc8dbb86f1f4c1ada23a3bf57760d87.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:41:02"
  condition:
    hash.sha256(0, filesize) == "98379ccde6fc0517a749bdfb4fa3a384ccc8dbb86f1f4c1ada23a3bf57760d87"
}

rule MalwareBazaar_njrat_058_51ef64b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51ef64b51fbc68f3fdffa43e7c0d89fad5a522a53d5c3930d8145bc96cc62067"
    family = "njrat"
    file_name = "51ef64b51fbc68f3fdffa43e7c0d89fad5a522a53d5c3930d8145bc96cc62067.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:40:58"
  condition:
    hash.sha256(0, filesize) == "51ef64b51fbc68f3fdffa43e7c0d89fad5a522a53d5c3930d8145bc96cc62067"
}

rule MalwareBazaar_unknown_059_bafd3d71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bafd3d712a32b884001dccd7f6f77fd9aa515b254352310e20f67026364c7884"
    family = "unknown"
    file_name = "bafd3d712a32b884001dccd7f6f77fd9aa515b254352310e20f67026364c7884.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:40:52"
  condition:
    hash.sha256(0, filesize) == "bafd3d712a32b884001dccd7f6f77fd9aa515b254352310e20f67026364c7884"
}

rule MalwareBazaar_unknown_060_6b9df966
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b9df966d5f851687534c1abae51e4287c91484fa5aa6dc45e89ebb8368a02e7"
    family = "unknown"
    file_name = "ffffffffffffffffffffqw.hta"
    file_type = "hta"
    first_seen = "2026-10-16 00:40:30"
  condition:
    hash.sha256(0, filesize) == "6b9df966d5f851687534c1abae51e4287c91484fa5aa6dc45e89ebb8368a02e7"
}

rule MalwareBazaar_AMOS_061_3ae3d11c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ae3d11cd46aceee81783fb1204c4ae43459e670a8071f76c8a9a5851287a965"
    family = "AMOS"
    file_name = "macho_3ae3d11cd46a.bin"
    file_type = "macho"
    first_seen = "2026-10-16 00:39:59"
  condition:
    hash.sha256(0, filesize) == "3ae3d11cd46aceee81783fb1204c4ae43459e670a8071f76c8a9a5851287a965"
}

rule MalwareBazaar_njrat_062_99abb19b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99abb19b58002ac9bd71b4d097dbcd63d41cc7e7a21e1e5eadac4b4a75acb4fc"
    family = "njrat"
    file_name = "99abb19b58002ac9bd71b4d097dbcd63d41cc7e7a21e1e5eadac4b4a75acb4fc.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:39:52"
  condition:
    hash.sha256(0, filesize) == "99abb19b58002ac9bd71b4d097dbcd63d41cc7e7a21e1e5eadac4b4a75acb4fc"
}

rule MalwareBazaar_Mirai_063_25fff114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25fff114fe414d96d6f972134afce96eadff90d5fa05b87a1d3730165dadc489"
    family = "Mirai"
    file_name = "25fff114fe414d96d6f972134afce96eadff90d5fa05b87a1d3730165dadc489"
    file_type = "elf"
    first_seen = "2026-10-16 00:38:42"
  condition:
    hash.sha256(0, filesize) == "25fff114fe414d96d6f972134afce96eadff90d5fa05b87a1d3730165dadc489"
}

rule MalwareBazaar_unknown_064_bc6af94e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc6af94ef856472d2a5b75de58fc12e9616d37d1b9dba17ffeeda81d77e40b47"
    family = "unknown"
    file_name = "2KeyFactory.exe"
    file_type = "exe"
    first_seen = "2026-10-16 00:37:50"
  condition:
    hash.sha256(0, filesize) == "bc6af94ef856472d2a5b75de58fc12e9616d37d1b9dba17ffeeda81d77e40b47"
}

rule MalwareBazaar_AMOS_065_e42b8c35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea"
    family = "AMOS"
    file_name = "macho_e42b8c35db5a.bin"
    file_type = "macho"
    first_seen = "2026-10-16 00:34:53"
  condition:
    hash.sha256(0, filesize) == "e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea"
}

rule MalwareBazaar_unknown_066_b7afb794
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7afb7948a27e2c7ea27aec336486353f2e759ea13e4be4df8c09bce4e139179"
    family = "unknown"
    file_name = "rooming.hta"
    file_type = "hta"
    first_seen = "2026-10-16 00:30:36"
  condition:
    hash.sha256(0, filesize) == "b7afb7948a27e2c7ea27aec336486353f2e759ea13e4be4df8c09bce4e139179"
}

rule MalwareBazaar_Mirai_067_9e486485
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e486485817450a9b516ee93d4b85dfc42be16a629087d0954d63577439b8f56"
    family = "Mirai"
    file_name = "fghe3tj.mips"
    file_type = "elf"
    first_seen = "2026-10-16 00:28:28"
  condition:
    hash.sha256(0, filesize) == "9e486485817450a9b516ee93d4b85dfc42be16a629087d0954d63577439b8f56"
}

rule MalwareBazaar_SalatStealer_068_ab0c6d46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab0c6d4640de59c97bcdf9bab4a6cba7523b7d4e48bf56c729ecba9e0c5dd6d1"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 00:22:56"
  condition:
    hash.sha256(0, filesize) == "ab0c6d4640de59c97bcdf9bab4a6cba7523b7d4e48bf56c729ecba9e0c5dd6d1"
}

rule MalwareBazaar_unknown_069_4e3ffef0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e3ffef03845a1da3f072a92161e3f1b9c86900056f258055908aab0b4cde997"
    family = "unknown"
    file_name = "fuck_niggers_2.hta"
    file_type = "hta"
    first_seen = "2026-10-16 00:20:40"
  condition:
    hash.sha256(0, filesize) == "4e3ffef03845a1da3f072a92161e3f1b9c86900056f258055908aab0b4cde997"
}

rule MalwareBazaar_unknown_070_17abe568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17abe5685fd70a472ed45401a618afa5b628312a7491cd761536b181a2b346c9"
    family = "unknown"
    file_name = "fuck_niggers_39.hta"
    file_type = "hta"
    first_seen = "2026-10-16 00:20:38"
  condition:
    hash.sha256(0, filesize) == "17abe5685fd70a472ed45401a618afa5b628312a7491cd761536b181a2b346c9"
}

rule MalwareBazaar_Mirai_071_7e1f8efd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e1f8efda2aa1e7eb79557ca2275a229a76b55fb98e191d310e5b8e4ad38b954"
    family = "Mirai"
    file_name = "fghe3tj.ppc"
    file_type = "elf"
    first_seen = "2026-10-16 00:10:30"
  condition:
    hash.sha256(0, filesize) == "7e1f8efda2aa1e7eb79557ca2275a229a76b55fb98e191d310e5b8e4ad38b954"
}

rule MalwareBazaar_Mirai_072_f6ddc131
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6ddc131bdfd26317d1a7f53086f1a1ed17717a631242832abbdaf0506be74ce"
    family = "Mirai"
    file_name = "fghe3tj.arm6"
    file_type = "elf"
    first_seen = "2026-10-16 00:08:29"
  condition:
    hash.sha256(0, filesize) == "f6ddc131bdfd26317d1a7f53086f1a1ed17717a631242832abbdaf0506be74ce"
}

rule MalwareBazaar_Mirai_073_01c97268
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01c97268134bd3bcb04f32567f2c8b5fa2aafab4f268e7ce70ae3731566133bf"
    family = "Mirai"
    file_name = "mbupload-b9kcd0z1.bin"
    file_type = "elf"
    first_seen = "2026-10-15 23:59:50"
  condition:
    hash.sha256(0, filesize) == "01c97268134bd3bcb04f32567f2c8b5fa2aafab4f268e7ce70ae3731566133bf"
}

rule MalwareBazaar_unknown_074_7169885e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7169885e9230836cf829ee86035864806a8720cb644e5a1d7f53f914b330cab2"
    family = "unknown"
    file_name = "RDP OfficeX Manager.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:56:31"
  condition:
    hash.sha256(0, filesize) == "7169885e9230836cf829ee86035864806a8720cb644e5a1d7f53f914b330cab2"
}

rule MalwareBazaar_unknown_075_d4bb1f9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4bb1f9cc14e1a27aa5d4f5ec397247b06cc5b0ae0b8fd4067a2b10f6223e2ef"
    family = "unknown"
    file_name = "rdp_officex_manager.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:56:20"
  condition:
    hash.sha256(0, filesize) == "d4bb1f9cc14e1a27aa5d4f5ec397247b06cc5b0ae0b8fd4067a2b10f6223e2ef"
}

rule MalwareBazaar_unknown_076_82f1b187
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82f1b1874d6003e049c69e87ed5fcf64301090dfa275acb98e9938c788ff801d"
    family = "unknown"
    file_name = "fuck_niggers_8.hta"
    file_type = "hta"
    first_seen = "2026-10-15 23:52:31"
  condition:
    hash.sha256(0, filesize) == "82f1b1874d6003e049c69e87ed5fcf64301090dfa275acb98e9938c788ff801d"
}

rule MalwareBazaar_unknown_077_8f0bd3a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f0bd3a7009a3a3a22f9d397c22de38052b72db51c13904d596717ca65107908"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Iguanodon.Gen.1.18365638"
    file_type = "msi"
    first_seen = "2026-10-15 23:51:03"
  condition:
    hash.sha256(0, filesize) == "8f0bd3a7009a3a3a22f9d397c22de38052b72db51c13904d596717ca65107908"
}

rule MalwareBazaar_unknown_078_069f1429
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "069f1429577c2426c7883f392ca6441f1aea464b9b2262ef2fcb25989b701ee0"
    family = "unknown"
    file_name = "PLClean Master.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:43:53"
  condition:
    hash.sha256(0, filesize) == "069f1429577c2426c7883f392ca6441f1aea464b9b2262ef2fcb25989b701ee0"
}

rule MalwareBazaar_unknown_079_052a2258
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
    family = "unknown"
    file_name = "plclean_master.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:43:42"
  condition:
    hash.sha256(0, filesize) == "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
}

rule MalwareBazaar_Meterpreter_080_9f98e35e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f98e35e878b06940f2792ebc45b3f0adc0fb5bfde60f56548a60cfbf71bbe35"
    family = "Meterpreter"
    file_name = "F80E26BD75D1F89BA1501002076195AE.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:30:11"
  condition:
    hash.sha256(0, filesize) == "9f98e35e878b06940f2792ebc45b3f0adc0fb5bfde60f56548a60cfbf71bbe35"
}

rule MalwareBazaar_unknown_081_0bcf272d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bcf272d8f22fa30d327d7c0233b7eae7d50df1ebd95472aae59aef19c8e23bf"
    family = "unknown"
    file_name = "2KeyFactory.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:27:30"
  condition:
    hash.sha256(0, filesize) == "0bcf272d8f22fa30d327d7c0233b7eae7d50df1ebd95472aae59aef19c8e23bf"
}

rule MalwareBazaar_Mirai_082_6b622569
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b622569745e1074b4564467c3d694d9cf1db09405a03d8d6ee609c35f417e86"
    family = "Mirai"
    file_name = "fghe3tj.mpsl"
    file_type = "elf"
    first_seen = "2026-10-15 23:23:26"
  condition:
    hash.sha256(0, filesize) == "6b622569745e1074b4564467c3d694d9cf1db09405a03d8d6ee609c35f417e86"
}

rule MalwareBazaar_unknown_083_675971cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "675971cc1e2c889b2804336626f4e2d1489b7878c15817b57847d1d88347b76c"
    family = "unknown"
    file_name = "QR2 Auth.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:21:52"
  condition:
    hash.sha256(0, filesize) == "675971cc1e2c889b2804336626f4e2d1489b7878c15817b57847d1d88347b76c"
}

rule MalwareBazaar_unknown_084_73cb8ff5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73cb8ff57d809fe1042ef02ba5571d8ad7ee871cadf01a9bbc609f69f8d407ed"
    family = "unknown"
    file_name = "qr2auth.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:21:42"
  condition:
    hash.sha256(0, filesize) == "73cb8ff57d809fe1042ef02ba5571d8ad7ee871cadf01a9bbc609f69f8d407ed"
}

rule MalwareBazaar_unknown_085_65bb68bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65bb68bc934757abeece91a377d528e4fb1960e9da5f781ee5776b2f6be18c25"
    family = "unknown"
    file_name = "FACodeEngine.exe"
    file_type = "exe"
    first_seen = "2026-10-15 23:21:32"
  condition:
    hash.sha256(0, filesize) == "65bb68bc934757abeece91a377d528e4fb1960e9da5f781ee5776b2f6be18c25"
}

rule MalwareBazaar_unknown_086_c2180d18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2180d18cbdd0f5667ca61308509eec995dda607a6e47e1c969fc280bb7db796"
    family = "unknown"
    file_name = "MetaSoftware.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:57:18"
  condition:
    hash.sha256(0, filesize) == "c2180d18cbdd0f5667ca61308509eec995dda607a6e47e1c969fc280bb7db796"
}

rule MalwareBazaar_RemusStealer_087_ff681630
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff681630d707f5903ea3d75c36f2bb87b2156636907268caa2e512032f5e6bf0"
    family = "RemusStealer"
    file_name = "Xeninester.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:54:50"
  condition:
    hash.sha256(0, filesize) == "ff681630d707f5903ea3d75c36f2bb87b2156636907268caa2e512032f5e6bf0"
}

rule MalwareBazaar_unknown_088_1350c4c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1350c4c4371a1526d54ada91f98e089ffc12ef59df098c97b73e0480efba7daf"
    family = "unknown"
    file_name = "1350c4c4371a1526d54ada91f98e089ffc12ef59df098c97b73e0480efba7daf.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:51:00"
  condition:
    hash.sha256(0, filesize) == "1350c4c4371a1526d54ada91f98e089ffc12ef59df098c97b73e0480efba7daf"
}

rule MalwareBazaar_unknown_089_e5b790c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5b790c3a237edc2c55f01a7c648d0eaf8e969a1a9223aff605a90a1d42900b7"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:46:19"
  condition:
    hash.sha256(0, filesize) == "e5b790c3a237edc2c55f01a7c648d0eaf8e969a1a9223aff605a90a1d42900b7"
}

rule MalwareBazaar_unknown_090_404e448f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "404e448f179f662439bd08b2abbcddcaaf0034d11d786cc878cce6f9ef57b570"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:46:16"
  condition:
    hash.sha256(0, filesize) == "404e448f179f662439bd08b2abbcddcaaf0034d11d786cc878cce6f9ef57b570"
}

rule MalwareBazaar_unknown_091_bb518757
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb518757a09ffe9c92755bf86d86d589204ece9869918c7497c8739825bcc914"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:46:14"
  condition:
    hash.sha256(0, filesize) == "bb518757a09ffe9c92755bf86d86d589204ece9869918c7497c8739825bcc914"
}

rule MalwareBazaar_unknown_092_fb799fbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb799fbe2729fa88358d32375c15aa41b2de62e981655e60d4f53efb4e4fee73"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:46:12"
  condition:
    hash.sha256(0, filesize) == "fb799fbe2729fa88358d32375c15aa41b2de62e981655e60d4f53efb4e4fee73"
}

rule MalwareBazaar_unknown_093_cd0db049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd0db04913047500d062f676d4099aced7ef039c7e12cebaddff6aac41def3ea"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:42:20"
  condition:
    hash.sha256(0, filesize) == "cd0db04913047500d062f676d4099aced7ef039c7e12cebaddff6aac41def3ea"
}

rule MalwareBazaar_unknown_094_3508e6cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3508e6cb5ce9a6f5e78e5a636ee358fe47b6496f9af948fcce0cd7bf296d9690"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-15 22:38:07"
  condition:
    hash.sha256(0, filesize) == "3508e6cb5ce9a6f5e78e5a636ee358fe47b6496f9af948fcce0cd7bf296d9690"
}

rule MalwareBazaar_unknown_095_25389448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25389448ceaa92b3133c26e4fe2cc34cfc908f32cf44d93cc886a2d62deb06e1"
    family = "unknown"
    file_name = "SystemHealthMonitor.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:26:01"
  condition:
    hash.sha256(0, filesize) == "25389448ceaa92b3133c26e4fe2cc34cfc908f32cf44d93cc886a2d62deb06e1"
}

rule MalwareBazaar_FleetDeck_096_8acc5119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8acc511937f2b5585d58d96bcc7eec719430bcee7c5b088499c81e0b75c040a4"
    family = "FleetDeck"
    file_name = "8acc511937f2b5585d58d96bcc7eec719430bcee7c5b088499c81e0b75c040a4.exe"
    file_type = "exe"
    first_seen = "2026-10-15 22:17:18"
  condition:
    hash.sha256(0, filesize) == "8acc511937f2b5585d58d96bcc7eec719430bcee7c5b088499c81e0b75c040a4"
}

rule MalwareBazaar_unknown_097_dfd08e1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfd08e1d7a34bae6836b3915b45b8637b85cdc998198c5bf148fba5e96f15c21"
    family = "unknown"
    file_name = "dfd08e1d7a34bae6836b3915b45b8637b85cdc998198c5bf148fba5e96f15c21.exe"
    file_type = "exe"
    first_seen = "2026-10-15 21:57:20"
  condition:
    hash.sha256(0, filesize) == "dfd08e1d7a34bae6836b3915b45b8637b85cdc998198c5bf148fba5e96f15c21"
}

rule MalwareBazaar_unknown_098_3c51e599
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c51e5995af60587fbf019f11f94d843b8ae3fb82786b6bd468bc60660783fc5"
    family = "unknown"
    file_name = "fuck_niggers_2.hta"
    file_type = "hta"
    first_seen = "2026-10-15 21:44:51"
  condition:
    hash.sha256(0, filesize) == "3c51e5995af60587fbf019f11f94d843b8ae3fb82786b6bd468bc60660783fc5"
}

rule MalwareBazaar_unknown_099_037b186f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "037b186f042dcf9205fbaf2156965422201be1bbf3e65f7998a8dccb77f6dcf3"
    family = "unknown"
    file_name = "redtail.x86_64"
    file_type = "elf"
    first_seen = "2026-10-15 21:33:54"
  condition:
    hash.sha256(0, filesize) == "037b186f042dcf9205fbaf2156965422201be1bbf3e65f7998a8dccb77f6dcf3"
}

rule MalwareBazaar_unknown_100_47fb5347
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47fb5347bb16aac0edc445d921531655792986422c739ba25695c003f7b94c7d"
    family = "unknown"
    file_name = "bot.sh"
    file_type = "sh"
    first_seen = "2026-10-15 21:33:16"
  condition:
    hash.sha256(0, filesize) == "47fb5347bb16aac0edc445d921531655792986422c739ba25695c003f7b94c7d"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

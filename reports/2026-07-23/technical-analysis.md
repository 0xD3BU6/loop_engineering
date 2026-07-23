# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-23

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 657 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 657 |
| Unique family labels | 8 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 54 |
| unknown | 39 |
| Formbook | 2 |
| AsyncRAT | 1 |
| Vidar | 1 |
| CoinMiner | 1 |
| Gafgyt | 1 |
| RustyStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 68 |
| exe | 18 |
| sh | 7 |
| js | 3 |
| msi | 3 |
| unknown | 1 |

## Per-Sample Analysis

### Sample 1: `1f79f7239d6f8cd9`

| Field | Value |
|---|---|
| SHA-256 | `1f79f7239d6f8cd9224064830720909884f98b989c1d7d01d90a3de686f02641` |
| Family label | `AsyncRAT` |
| File name | `Shipping Documents.js` |
| File type | `js` |
| First seen | `2026-07-23 03:26:53` |
| Reporter | `threatcat_ch` |
| Tags | `AsyncRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b1f73a57a3620ad05115b3db400aa8a` |
| SHA-1 | `7572107528b811fda4cfc165a473c3775e22298f` |
| SHA-256 | `1f79f7239d6f8cd9224064830720909884f98b989c1d7d01d90a3de686f02641` |
| SHA3-384 | `3cc7bf70c6aec20da76cb446b80d20cc51992eca758318f760358c038a8e1ae31277fe97a208e170b498438b009c89cf` |
| TLSH | `T142749F169B05AAC8347DDB88F8C6C35A832B23335DFF454B610177C34A7A6257FE819A` |
| SSDEEP | `6144:WXOYjBzgMKEgkUldni7GLxWwEjtEVT0oLd6a8NBiYsjBLUsuLRxZtuze8af2Ulv:W9NgexEdLd4fi1jNUTHJlv` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_001_1f79f723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f79f7239d6f8cd9224064830720909884f98b989c1d7d01d90a3de686f02641"
    family = "AsyncRAT"
    file_name = "Shipping Documents.js"
    file_type = "js"
    first_seen = "2026-07-23 03:26:53"
  condition:
    hash.sha256(0, filesize) == "1f79f7239d6f8cd9224064830720909884f98b989c1d7d01d90a3de686f02641"
}
```

### Sample 2: `c118f7037676c76b`

| Field | Value |
|---|---|
| SHA-256 | `c118f7037676c76b39d05c16c337158c0d714decee91af1c44f41c899233b265` |
| Family label | `Vidar` |
| File name | `XOR_Loader.exe` |
| File type | `exe` |
| First seen | `2026-07-23 03:23:08` |
| Reporter | `UnknownSilicon` |
| Tags | `clickfix, exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5cc694a33b659fb6c6e18633daea040c` |
| SHA-1 | `c2b2ecfe88e5555a73cd3d893d369b1640b626bd` |
| SHA-256 | `c118f7037676c76b39d05c16c337158c0d714decee91af1c44f41c899233b265` |
| SHA3-384 | `5b50d252494c6559b547a0871554b0a73dd0424a2ae1c8e4b49ef9ea3464cd334c03f5cd0ce9bf08ae7d404e65a2abd5` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B8355F38FF750091A19ACCC2972676DBCD7F13A99F8CFC36A47DDE5258828421B2E184` |
| SSDEEP | `12288:X+Kxnx+uGJgjhjnRiLca/ytoHeVmVgSSF9Xi5Sx+yv09o4ScN:umrGWjRg/yKHeVmVkFw5SE+0tScN` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_002_c118f703
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c118f7037676c76b39d05c16c337158c0d714decee91af1c44f41c899233b265"
    family = "Vidar"
    file_name = "XOR_Loader.exe"
    file_type = "exe"
    first_seen = "2026-07-23 03:23:08"
  condition:
    hash.sha256(0, filesize) == "c118f7037676c76b39d05c16c337158c0d714decee91af1c44f41c899233b265"
}
```

### Sample 3: `c560beb3b567797c`

| Field | Value |
|---|---|
| SHA-256 | `c560beb3b567797cdd3cc478934e27ad2a8991fb5aa350b7effa77a88a94441a` |
| Family label | `unknown` |
| File name | `install.msi` |
| File type | `msi` |
| First seen | `2026-07-23 03:17:48` |
| Reporter | `UnknownSilicon` |
| Tags | `clickfix, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88eb07098c1c8f6475fad46925807ab7` |
| SHA-1 | `9b729c981c0153559303c013a054dbe1018a03b0` |
| SHA-256 | `c560beb3b567797cdd3cc478934e27ad2a8991fb5aa350b7effa77a88a94441a` |
| SHA3-384 | `0bef7504ecf70602810f856ff4ad2bb5eef71ef9a6528064dd9edfa7613dde39c47df282bfa2bdf9751caa73588fb067` |
| TLSH | `T1EC135B6A72609332C08207364B5FC7E56B759C58DFB3522732DAB74D1E72D9413A3AE0` |
| SSDEEP | `384:S6+shIL7iyUrrS15nO2EUIFwmdNb8rdUEeGDGFOzF1XXoP4Csu1XXoP4CY+tcq5n:7IL73KIIUIFwmTbtEVDGcPFCJFCP6q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_c560beb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c560beb3b567797cdd3cc478934e27ad2a8991fb5aa350b7effa77a88a94441a"
    family = "unknown"
    file_name = "install.msi"
    file_type = "msi"
    first_seen = "2026-07-23 03:17:48"
  condition:
    hash.sha256(0, filesize) == "c560beb3b567797cdd3cc478934e27ad2a8991fb5aa350b7effa77a88a94441a"
}
```

### Sample 4: `93988577e3e325cd`

| Field | Value |
|---|---|
| SHA-256 | `93988577e3e325cdb5d1a136d08e6e92572014ad8bbc6f0b6220e456c593270b` |
| Family label | `unknown` |
| File name | `MiniPowerShell.exe` |
| File type | `exe` |
| First seen | `2026-07-23 03:16:29` |
| Reporter | `UnknownSilicon` |
| Tags | `clickfix, exe, minipowershell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `311f6d2ffb67501ef46ed57a18563844` |
| SHA-1 | `9e39731a975ed0b32caff1bbbd7ee7644bbb94fb` |
| SHA-256 | `93988577e3e325cdb5d1a136d08e6e92572014ad8bbc6f0b6220e456c593270b` |
| SHA3-384 | `3aa4441c79682459cba7e1357d09a0469d72ac4efcde482a1d18a17f32e23c30d9d8d36a4f3345b2238d6bea15b6a9a3` |
| TLSH | `T183921849B7F84205D6FEAA398DB393161330FB459A12CB8E1DD1784F1D323548A61FB6` |
| SSDEEP | `384:q222m3S5L0twVN4uGHP/QQUMHKbZvk6Jfgl2AmtQTVW:q2253KLanuu/UCOul4e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_93988577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93988577e3e325cdb5d1a136d08e6e92572014ad8bbc6f0b6220e456c593270b"
    family = "unknown"
    file_name = "MiniPowerShell.exe"
    file_type = "exe"
    first_seen = "2026-07-23 03:16:29"
  condition:
    hash.sha256(0, filesize) == "93988577e3e325cdb5d1a136d08e6e92572014ad8bbc6f0b6220e456c593270b"
}
```

### Sample 5: `98f5e6cc01bd7470`

| Field | Value |
|---|---|
| SHA-256 | `98f5e6cc01bd74709e63639e75a6e4d68b6c5fb9654ae97490155792888bebdd` |
| Family label | `unknown` |
| File name | `Soda_Music_12.8.1_x64.exe` |
| File type | `exe` |
| First seen | `2026-07-23 03:13:57` |
| Reporter | `lighting9999` |
| Tags | `exe, https://qusuiok.com.cn/download.html` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afc61229018541efa19cd9affa1aeb72` |
| SHA-1 | `b6cbc4017ed864b21917e3604c6e5f57d2e9ed0a` |
| SHA-256 | `98f5e6cc01bd74709e63639e75a6e4d68b6c5fb9654ae97490155792888bebdd` |
| SHA3-384 | `5a28ab37aaad667db06e7df8d4688f4c55f8c2c55fd0cd2ea1c12113d4d92cf8231bfb40892528e64d9bd34db0ea39aa` |
| IMPHASH | `7125bbd5137d929edca8dd25eefbdab9` |
| TLSH | `T13D473352F7F20398F4B3553149B8497BF4B6BC2EFA15DA9E018321091B27B9189A4F37` |
| SSDEEP | `393216:sr8iLu03Q36lpfK6lWNHdeRU7eRZ7mnKmn4jSi9daq09l6MPaClTTFNnj3Rbgao:s4iL7QqXRqwZinnn4ueaqEl6MVBp9gF` |
| ICON-DHASH | `a8a686938f9aaa8b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_98f5e6cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98f5e6cc01bd74709e63639e75a6e4d68b6c5fb9654ae97490155792888bebdd"
    family = "unknown"
    file_name = "Soda_Music_12.8.1_x64.exe"
    file_type = "exe"
    first_seen = "2026-07-23 03:13:57"
  condition:
    hash.sha256(0, filesize) == "98f5e6cc01bd74709e63639e75a6e4d68b6c5fb9654ae97490155792888bebdd"
}
```

### Sample 6: `3bb64d86bed83374`

| Field | Value |
|---|---|
| SHA-256 | `3bb64d86bed8337443f4b6f6c981914dd7d94b6fa7b61709015f9698e13bc67c` |
| Family label | `unknown` |
| File name | `build_captcha.exe` |
| File type | `exe` |
| First seen | `2026-07-23 03:12:15` |
| Reporter | `UnknownSilicon` |
| Tags | `clickfix, exe, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e006cb0220146177e684c11e8548ab39` |
| SHA-1 | `5a43ccbb36c23176b99cb7727d338f43319f353f` |
| SHA-256 | `3bb64d86bed8337443f4b6f6c981914dd7d94b6fa7b61709015f9698e13bc67c` |
| SHA3-384 | `5df71c40f6fe7922faa9629be0c025bb53e388c55db62bb3d904bd2458860f143c9e26a83e4cf652c2f8704dbe800754` |
| IMPHASH | `3aac2dc0f6fe0af44b31ce34718a311b` |
| TLSH | `T116053B36872353DBFC3B8137C55AB797FC7079168A34CE3606A00F466AA6622562F317` |
| SSDEEP | `24576:YZV6+m7XOeCYd8QUTuchzWds28Cd9M7Di+lQvVjf2:B+gXtdGsF8CfWDnlyVje` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_3bb64d86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bb64d86bed8337443f4b6f6c981914dd7d94b6fa7b61709015f9698e13bc67c"
    family = "unknown"
    file_name = "build_captcha.exe"
    file_type = "exe"
    first_seen = "2026-07-23 03:12:15"
  condition:
    hash.sha256(0, filesize) == "3bb64d86bed8337443f4b6f6c981914dd7d94b6fa7b61709015f9698e13bc67c"
}
```

### Sample 7: `a5b13da4ffa0bb5d`

| Field | Value |
|---|---|
| SHA-256 | `a5b13da4ffa0bb5df881c213faa08ca92608cd7e4e83142695877923d278a7d2` |
| Family label | `unknown` |
| File name | `ViceCallers.exe` |
| File type | `exe` |
| First seen | `2026-07-23 03:05:57` |
| Reporter | `lighting9999` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9726640ec4772c44485f2717fc177b0f` |
| SHA-1 | `34ed423e09c7c36e718188b4f006b536c959a918` |
| SHA-256 | `a5b13da4ffa0bb5df881c213faa08ca92608cd7e4e83142695877923d278a7d2` |
| SHA3-384 | `523db3882c6d2b9c0639b546c6abd5ab1b5d773dd4f9597246d245bf5b392a8e048657009093a359b2dedc4d2a330312` |
| IMPHASH | `e6c6166959e9db1494bb9a620affb282` |
| TLSH | `T1A8853347C5924361D2BA3774CCAE8F5E4119B9710FCB45CB076A5B09BA32AE1ECF81B4` |
| SSDEEP | `24576:PVw7toKwuCsZ7Us/7x4YtF/g2yTDJWCaSooaeO1cpJkoW//Dy3qRQji/:StoKVxJ7ozgf1kkx/Le0Qa` |
| ICON-DHASH | `2064031713810405` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_a5b13da4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5b13da4ffa0bb5df881c213faa08ca92608cd7e4e83142695877923d278a7d2"
    family = "unknown"
    file_name = "ViceCallers.exe"
    file_type = "exe"
    first_seen = "2026-07-23 03:05:57"
  condition:
    hash.sha256(0, filesize) == "a5b13da4ffa0bb5df881c213faa08ca92608cd7e4e83142695877923d278a7d2"
}
```

### Sample 8: `a21af048f2d0b537`

| Field | Value |
|---|---|
| SHA-256 | `a21af048f2d0b53774660e7304581639c8027808b16ea9dd4bebd0af955124dc` |
| Family label | `Formbook` |
| File name | `PAGO.js` |
| File type | `js` |
| First seen | `2026-07-23 03:03:45` |
| Reporter | `lighting9999` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `615520c6d7b6bd749722f0db2cff1a0f` |
| SHA-1 | `c019d54e4dac9f9e14a383796a1b09c94c5e21c1` |
| SHA-256 | `a21af048f2d0b53774660e7304581639c8027808b16ea9dd4bebd0af955124dc` |
| SHA3-384 | `c321bc3feb77eb064d43a033aac9c8f7e3d33af5457bdb16eb73b6a9ab562af327235a33a965c9c10683537c85b341eb` |
| TLSH | `T183B57BC3785F4C04858ECF39E9A66F119C06B033DD3A71DFB11649BE121A942A6BD4EB` |
| SSDEEP | `192:JTSwHTSwHTSwHTSwHTSwHTSwHTSwHTSwHTSwHTSwHTSwHTSwHTSwHTSwHTSwHTSg:7f3` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_008_a21af048
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a21af048f2d0b53774660e7304581639c8027808b16ea9dd4bebd0af955124dc"
    family = "Formbook"
    file_name = "PAGO.js"
    file_type = "js"
    first_seen = "2026-07-23 03:03:45"
  condition:
    hash.sha256(0, filesize) == "a21af048f2d0b53774660e7304581639c8027808b16ea9dd4bebd0af955124dc"
}
```

### Sample 9: `cc7b6ff483a2c3a0`

| Field | Value |
|---|---|
| SHA-256 | `cc7b6ff483a2c3a0efe7f4d6ecefe00510ebd166723ebf7ad16e665d124245b9` |
| Family label | `Formbook` |
| File name | `PO_2026_0001.pdf.js` |
| File type | `js` |
| First seen | `2026-07-23 03:03:18` |
| Reporter | `lighting9999` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93bc0e2a9639d03ef7a5681c0f9e5ebc` |
| SHA-1 | `66ae14cdc9008569d8cd6e839acc97f33e451401` |
| SHA-256 | `cc7b6ff483a2c3a0efe7f4d6ecefe00510ebd166723ebf7ad16e665d124245b9` |
| SHA3-384 | `d251cf5867910a1a24f258b54e44043a42a11c8ccc1dd6bb81dc54156b1a0d95bc75e72ae7929c4cb5a99a33664527a7` |
| TLSH | `T186757E229DDE21A1F2A7F61DD93BE1E9100B3052A539C9195A2D57684FFFA10232CF4F` |
| SSDEEP | `12288:/OT7srTPxOb7KAdYG5YegWrGEc8c4YWAlHrrttpRc8mEklry7f:2QTPxOb2AdYG5YdX8hAlHNDRcmklry7f` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_009_cc7b6ff4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc7b6ff483a2c3a0efe7f4d6ecefe00510ebd166723ebf7ad16e665d124245b9"
    family = "Formbook"
    file_name = "PO_2026_0001.pdf.js"
    file_type = "js"
    first_seen = "2026-07-23 03:03:18"
  condition:
    hash.sha256(0, filesize) == "cc7b6ff483a2c3a0efe7f4d6ecefe00510ebd166723ebf7ad16e665d124245b9"
}
```

### Sample 10: `9ab9d3ecb256fb82`

| Field | Value |
|---|---|
| SHA-256 | `9ab9d3ecb256fb826e2091209939288a849a7706290b012bfbafafa62eea96ed` |
| Family label | `Mirai` |
| File name | `android_arm64` |
| File type | `elf` |
| First seen | `2026-07-23 02:52:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c46a36ddb13e40c4e45d3167b9b4b7e` |
| SHA-1 | `ec60bbdc9da383ac64f6a0d1ef63a2aaf4c217d8` |
| SHA-256 | `9ab9d3ecb256fb826e2091209939288a849a7706290b012bfbafafa62eea96ed` |
| SHA3-384 | `944758b3daf439c3a5e35fa2e7935b49d7aba93d7eaa2bda91b87f45a8d8d69075b469fef027e9539b4a4f82b28911b5` |
| TLSH | `T1BA56286DFC1EE9A2DDC976B15E2213877239AC085B81C312A714BA3EB9F73C48F12551` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:T0r14+L2hgRrkM9kR70ZdGqFuTofFMpmDeg8DQt5Ee:T0R4E2ED9M0m2fJDb8DQjEe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_9ab9d3ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ab9d3ecb256fb826e2091209939288a849a7706290b012bfbafafa62eea96ed"
    family = "Mirai"
    file_name = "android_arm64"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:39"
  condition:
    hash.sha256(0, filesize) == "9ab9d3ecb256fb826e2091209939288a849a7706290b012bfbafafa62eea96ed"
}
```

### Sample 11: `0fb7ad5dc6c2c8ba`

| Field | Value |
|---|---|
| SHA-256 | `0fb7ad5dc6c2c8bac1dce94687f553c244159ecd079459d53e64a001f94586f9` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-07-23 02:52:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a9dbaf089c6bbf45219667ae24f51b0` |
| SHA-1 | `9ab68bca749d35abccb0ef7c9d2670918a407bf1` |
| SHA-256 | `0fb7ad5dc6c2c8bac1dce94687f553c244159ecd079459d53e64a001f94586f9` |
| SHA3-384 | `52d517d4ad2ae74e2e398a66df81728a837522339d97ef6d8f47430978f7cb41f7b58503a4c56cd04e466d0d90511e9b` |
| TLSH | `T1BE461897BDD25983C4E4367BA8BE80C433634EF99B8652565D08FE383ABE1D90E35314` |
| TELFHASH | `t1f0e0dfa59e2d26a86ad180c01a0c919ecee430fc2b043be84f9e778e53535287589c9f` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:9R1xO2GBCf1NE08ObR7e+9BzDZ9eOjLMmggxUyT5E2:1xO2GWnE0BP9BjLQgxNE2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_0fb7ad5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fb7ad5dc6c2c8bac1dce94687f553c244159ecd079459d53e64a001f94586f9"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:37"
  condition:
    hash.sha256(0, filesize) == "0fb7ad5dc6c2c8bac1dce94687f553c244159ecd079459d53e64a001f94586f9"
}
```

### Sample 12: `d62438047907e77f`

| Field | Value |
|---|---|
| SHA-256 | `d62438047907e77f6e8761ac6976c62971a477c3ecdb090a06d632caf9fb2f93` |
| Family label | `Mirai` |
| File name | `i386` |
| File type | `elf` |
| First seen | `2026-07-23 02:52:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9860261aa472a0a476264d14372f0add` |
| SHA-1 | `d2aee26493a5c19d672d8ebb9f56ecc4938de416` |
| SHA-256 | `d62438047907e77f6e8761ac6976c62971a477c3ecdb090a06d632caf9fb2f93` |
| SHA3-384 | `2d13bac82d7058fb6a68f580341aece9c4367eb553e4c3c2849bdef3ead7a02745c3777718fc5d0b47d970741ca25a02` |
| TLSH | `T1CE462711FECB14F6E9031E3105BBA26F63315D058B24EBD7EB407E29F97B6921932219` |
| TELFHASH | `t1a0d2cdb7159ca4ec63e0840787af7520cef6e43326e0387169e6b9c05b73d935a36978` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:3m9zLdBypE0xg6RzSVdau21rINrbadIyi79o+0ykeEnzO:3udBypRxg6RzSVdau21wrbYy8zO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_d6243804
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d62438047907e77f6e8761ac6976c62971a477c3ecdb090a06d632caf9fb2f93"
    family = "Mirai"
    file_name = "i386"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:35"
  condition:
    hash.sha256(0, filesize) == "d62438047907e77f6e8761ac6976c62971a477c3ecdb090a06d632caf9fb2f93"
}
```

### Sample 13: `11a367066e01e4e4`

| Field | Value |
|---|---|
| SHA-256 | `11a367066e01e4e424487d8d6cf16b763fa81d8f70e029fbb28fb78304d01c97` |
| Family label | `Mirai` |
| File name | `mipsle` |
| File type | `elf` |
| First seen | `2026-07-23 02:52:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5182c562a50b4d2218b2b469c9418f96` |
| SHA-1 | `26ca771bc26f2ed3357dc18444d9f780056d5ebe` |
| SHA-256 | `11a367066e01e4e424487d8d6cf16b763fa81d8f70e029fbb28fb78304d01c97` |
| SHA3-384 | `bf3a2305554cb5c9359f8c8c8f4fd49ec85ca5b34d82624bae7f5c30b4e4e9ad2bf1da7a8a4145eddcfa9fa4ca199291` |
| TLSH | `T12666F805AD842BF6C86D4B3484FACA9502B05E144AF1563A56A4FF6EBC772787F07C8C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:QPYkxDd9xKkR1l+iR887p/Klk1aCw88888f8888888848688888k1SKk2EQJg+bb:mI+d458EV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_11a36706
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11a367066e01e4e424487d8d6cf16b763fa81d8f70e029fbb28fb78304d01c97"
    family = "Mirai"
    file_name = "mipsle"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:33"
  condition:
    hash.sha256(0, filesize) == "11a367066e01e4e424487d8d6cf16b763fa81d8f70e029fbb28fb78304d01c97"
}
```

### Sample 14: `d2c51478b5abf90a`

| Field | Value |
|---|---|
| SHA-256 | `d2c51478b5abf90a4bc9fbdaeefcd3937e12995f1b2df73cdf9d7cc9cd8d0f4f` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-23 02:52:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7075fdce9082c9dbadeed87b70a1e73` |
| SHA-1 | `a01b3dc91695bde30de2f5c71a8df091940b9061` |
| SHA-256 | `d2c51478b5abf90a4bc9fbdaeefcd3937e12995f1b2df73cdf9d7cc9cd8d0f4f` |
| SHA3-384 | `c4305a2070fac0cd6ef522d994d257fa8bdaa253fda5e6af5865fa6587f684f07cf0fd9c8a2d80ab30625a8b1002c3a8` |
| TLSH | `T173561897B9D25942C4E43A7BB8BD80C433630EB99B8712665D14FE383EBE1D90E35358` |
| TELFHASH | `t1dae0d8868e0c269829e483414559069fcfe935fc13446bd98f6f7bcf0741da6b4cb85e` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:KCZ9tXQBM9SF3bxtQdVkj9qNeV95/bWXhpx2gVmKhDkzzgS9diZ+U+1MDgJQMOED:Kdx7I/xL7F0hT8XnPjXWVpVlWc5Eg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_d2c51478
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2c51478b5abf90a4bc9fbdaeefcd3937e12995f1b2df73cdf9d7cc9cd8d0f4f"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:32"
  condition:
    hash.sha256(0, filesize) == "d2c51478b5abf90a4bc9fbdaeefcd3937e12995f1b2df73cdf9d7cc9cd8d0f4f"
}
```

### Sample 15: `e521af827de7136f`

| Field | Value |
|---|---|
| SHA-256 | `e521af827de7136f8f30da5f85c381a387dcb3418a0ade034493faf7c3b840fa` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-23 02:52:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7be3912c7de19d19a111ba55d5ce776` |
| SHA-1 | `9fdf7db6304316d208b8508fa52ff2ed3a85eedf` |
| SHA-256 | `e521af827de7136f8f30da5f85c381a387dcb3418a0ade034493faf7c3b840fa` |
| SHA3-384 | `5cc18221626e0ee17d86a4cf5d4ea88ff5f61ae37de87f4a2e5a73e57176afa333a6ec26582d8893a7e9d55a7621709f` |
| TLSH | `T129461897BDD24943C4E8367BA8BD80C433631EF9AB8652565D18FE383ABE1D90E35344` |
| TELFHASH | `t1c3e0d8658e5c259c26d08280089a02aecee931f8274067eccf9f7b4f0751d96a4ca45f` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:lyEya7MgbQUqaZ5kgj2eZQwZJrY0NrXEOZ/CKROk/pDH5E+:oEy8Mgbx5tjVrxXEy/FpE+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_e521af82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e521af827de7136f8f30da5f85c381a387dcb3418a0ade034493faf7c3b840fa"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:30"
  condition:
    hash.sha256(0, filesize) == "e521af827de7136f8f30da5f85c381a387dcb3418a0ade034493faf7c3b840fa"
}
```

### Sample 16: `39efe58ce69f0463`

| Field | Value |
|---|---|
| SHA-256 | `39efe58ce69f0463a0919451a0cc3242f18726b596bdd7b8000955fbd36fad29` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-23 02:52:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ded63b4eb12566de73dee5033af5ac8` |
| SHA-1 | `6011fc6440d7c8a9daf84f4236149c38685a37cc` |
| SHA-256 | `39efe58ce69f0463a0919451a0cc3242f18726b596bdd7b8000955fbd36fad29` |
| SHA3-384 | `71f5c3987741eff5cfe9ced016a8d0543bba49e65736b49bf108e96f51b2acd935b7e807d33579e1a2ef2aa22614cd9b` |
| TLSH | `T1686618137E2CEB0EE228223458B2CA9567291C5541D7A817A391F318F9F307D9E6EDF1` |
| TELFHASH | `t1ddb0921788a00a48a0a248c14ec4715141e2ed23182965aebf750dd64e0e806006d416` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:ZT4QulGYlVJ3E9nS1PXJy3mrP6qDe7EgpQTR/SVIqyP+aUQ0Ap2va9khRJx00VgJ:yWqEIqyPHCV5n4jEe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_39efe58c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39efe58ce69f0463a0919451a0cc3242f18726b596bdd7b8000955fbd36fad29"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:28"
  condition:
    hash.sha256(0, filesize) == "39efe58ce69f0463a0919451a0cc3242f18726b596bdd7b8000955fbd36fad29"
}
```

### Sample 17: `cc5920f04c766645`

| Field | Value |
|---|---|
| SHA-256 | `cc5920f04c7666458cf9c4f876a54bd20091696a1a66b66f816024467bf2ba26` |
| Family label | `Mirai` |
| File name | `arm64` |
| File type | `elf` |
| First seen | `2026-07-23 02:52:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d3aef582344cc3004f3e3fc2d09e9dd` |
| SHA-1 | `c57add55838466f878f0dc9308c6ef87311eed67` |
| SHA-256 | `cc5920f04c7666458cf9c4f876a54bd20091696a1a66b66f816024467bf2ba26` |
| SHA3-384 | `8bba2791795110291d46ff7207f115d44983c9c27d1504f82e9a63beef09590cb02c67cf485aff4c63c786181d63a29c` |
| TLSH | `T138466C55BC1D6862D6C97A752F3613D87239BC489F81E3131728F73CA9F27988F122A1` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:isshjYSUzgzp8kEpqtjhQzahdgSHdGrhGAKVz/5EB:ism0LgSkEaiendeGHREB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_cc5920f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc5920f04c7666458cf9c4f876a54bd20091696a1a66b66f816024467bf2ba26"
    family = "Mirai"
    file_name = "arm64"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:26"
  condition:
    hash.sha256(0, filesize) == "cc5920f04c7666458cf9c4f876a54bd20091696a1a66b66f816024467bf2ba26"
}
```

### Sample 18: `434a796ad042259a`

| Field | Value |
|---|---|
| SHA-256 | `434a796ad042259ab54d0727fa29b6549ba8624cfa23e8d85323f66c83cce15c` |
| Family label | `Mirai` |
| File name | `amd64` |
| File type | `elf` |
| First seen | `2026-07-23 02:52:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9594b229af9c1424b9ba6dd10a5684a8` |
| SHA-1 | `32ef94745535d0b0b4389ebcad9cb94657db8184` |
| SHA-256 | `434a796ad042259ab54d0727fa29b6549ba8624cfa23e8d85323f66c83cce15c` |
| SHA3-384 | `28319026c7763edd099182eefd76d88b8204bef917e004b4f4330d529530ac137515b8075fffa3ee253f8d9dfac49798` |
| TLSH | `T1C4564A57ECA554E9C0AED2308A629153BB71BC492B3123D72B50F7382F77BD0AA79344` |
| TELFHASH | `t17452977549bd34b5a6aada10f363b5f495332c6532f438f15063a894efc1e801cea87b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:7Ir5gFNm7Ee/5M1IZDknIYAV0Gcl0/nAKs4w7EokX9VYHmiviNP1kAKlK1KcOH9+:7I+FE4QnAewoX9FvROH9DMBEU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_434a796a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "434a796ad042259ab54d0727fa29b6549ba8624cfa23e8d85323f66c83cce15c"
    family = "Mirai"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:24"
  condition:
    hash.sha256(0, filesize) == "434a796ad042259ab54d0727fa29b6549ba8624cfa23e8d85323f66c83cce15c"
}
```

### Sample 19: `e884305886288e46`

| Field | Value |
|---|---|
| SHA-256 | `e884305886288e46cea6630d22737da6c4bfa68b582f2b18b5133aa885c791f3` |
| Family label | `unknown` |
| File name | `bins.sh` |
| File type | `sh` |
| First seen | `2026-07-23 02:52:23` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cd5c5204b515c89ab22f3e77c2de5dd` |
| SHA-1 | `f1378d410c05b3f2a28d083dea8cc143389e2585` |
| SHA-256 | `e884305886288e46cea6630d22737da6c4bfa68b582f2b18b5133aa885c791f3` |
| SHA3-384 | `23c51d509d0d81c256c20f9930c784e4b6d7df27d2b47c2f4220c003235e32f890c3abb3c15e055344852241af661fd5` |
| TLSH | `T12D41B19B33E185B3C4039D65FF5418E0D0C8D6E271F2DBB8F86844A21159D48B19AB63` |
| SSDEEP | `24:u0OJx/YvIst6Fgll4Sj+LB+wReNIV+NI0vKP+PKPRv2vav2vVVM8XiH+iR18U:2l4lU1iKP2KPx2v22vcHbTt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_e8843058
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e884305886288e46cea6630d22737da6c4bfa68b582f2b18b5133aa885c791f3"
    family = "unknown"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-07-23 02:52:23"
  condition:
    hash.sha256(0, filesize) == "e884305886288e46cea6630d22737da6c4bfa68b582f2b18b5133aa885c791f3"
}
```

### Sample 20: `56091719eeba4881`

| Field | Value |
|---|---|
| SHA-256 | `56091719eeba4881f3db1f837feaa9d47a5a275bff6218186d97614e252e6d21` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-23 02:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f3955f8be35326246e2551754bd6d5e` |
| SHA-1 | `432375fba1147d8880a98b149fe7f8f2e4f78d1a` |
| SHA-256 | `56091719eeba4881f3db1f837feaa9d47a5a275bff6218186d97614e252e6d21` |
| SHA3-384 | `2a5e20ba0a0b0b5da8a912d3b2e1804344652efdee24ca27013353eb877d6cd1de0a708be49e1b4f5b934483dcc0af1b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T111E63328ABE011EFF5B3827CDEE215E1E571B0369B72C5CB576493652E032F08D3961A` |
| SSDEEP | `393216:nqU8Ms95fojtvz7q1IaKt9m3vXMCHWUjXDcuI3/PGTAI:nqXrfo5rm1Jam/XMb8XgH/O7` |
| ICON-DHASH | `71f0d0f0f0e0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_56091719
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56091719eeba4881f3db1f837feaa9d47a5a275bff6218186d97614e252e6d21"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 02:52:10"
  condition:
    hash.sha256(0, filesize) == "56091719eeba4881f3db1f837feaa9d47a5a275bff6218186d97614e252e6d21"
}
```

### Sample 21: `983972c15dd1778f`

| Field | Value |
|---|---|
| SHA-256 | `983972c15dd1778fba75deb79fc95008700008e24a08565e2c1d3fef27ee27a4` |
| Family label | `unknown` |
| File name | `setup.1.0.228tt00023.msi` |
| File type | `msi` |
| First seen | `2026-07-23 02:51:19` |
| Reporter | `lighting9999` |
| Tags | `https://www.gnrrn2821.com/22setup, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6eb8cbdf35e46c5bbcbd9ce7de7e380b` |
| SHA-1 | `3d157bd963fd53fd49cdf43ceeb8f7edf040ab2b` |
| SHA-256 | `983972c15dd1778fba75deb79fc95008700008e24a08565e2c1d3fef27ee27a4` |
| SHA3-384 | `d3ad436e24923514aeff3fb934b72f1707a2bb92c4258550ccfd4fe1df169bf4766ffa16c017c656453d36d8ffa92c76` |
| TLSH | `T1A38633C4B85D6772E08BC3304543B86E78363FC6AE678C0EFB987B10A971A29657D741` |
| SSDEEP | `196608:zM5ChD/v6hXdL+Tq2hlQ7ruAtcc5vnpS2VJ:zMAV/v67CTlMDtcgnpScJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_983972c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "983972c15dd1778fba75deb79fc95008700008e24a08565e2c1d3fef27ee27a4"
    family = "unknown"
    file_name = "setup.1.0.228tt00023.msi"
    file_type = "msi"
    first_seen = "2026-07-23 02:51:19"
  condition:
    hash.sha256(0, filesize) == "983972c15dd1778fba75deb79fc95008700008e24a08565e2c1d3fef27ee27a4"
}
```

### Sample 22: `66fbfd8c7d852bf0`

| Field | Value |
|---|---|
| SHA-256 | `66fbfd8c7d852bf002981112505f527d7ca8e581a4e47ce78f272090ec0a7134` |
| Family label | `unknown` |
| File name | `setup.1.0.2286300021.msi` |
| File type | `msi` |
| First seen | `2026-07-23 02:43:42` |
| Reporter | `lighting9999` |
| Tags | `https://www.gw-kaspersky.com.cn, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7b87c4bd99addb370f30263fa880990` |
| SHA-1 | `299cbbb0d845d7be15ff75355879180ad9967202` |
| SHA-256 | `66fbfd8c7d852bf002981112505f527d7ca8e581a4e47ce78f272090ec0a7134` |
| SHA3-384 | `13753cef90037f9b3dc75d9d5b76c641399fbcd9c08e220055a1a86b00d2f88d60635ce0fdb61f990732c57247d5bfea` |
| TLSH | `T1DBA633853DC963B3D547C7318103B49EB9187FD1BE634C1A7BEE36006EB2A15487BA86` |
| SSDEEP | `196608:kN2DBberLFKsUg3Kse7WEXkBV+uLPRDTCnApa5YPZXkLS1qamZ0Yu2:kEBaKK6se7v8PRDmApayZXke1qx0Yu2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_66fbfd8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66fbfd8c7d852bf002981112505f527d7ca8e581a4e47ce78f272090ec0a7134"
    family = "unknown"
    file_name = "setup.1.0.2286300021.msi"
    file_type = "msi"
    first_seen = "2026-07-23 02:43:42"
  condition:
    hash.sha256(0, filesize) == "66fbfd8c7d852bf002981112505f527d7ca8e581a4e47ce78f272090ec0a7134"
}
```

### Sample 23: `694a3bab92e60e67`

| Field | Value |
|---|---|
| SHA-256 | `694a3bab92e60e6760649fd40e97c04ff03faded2073e7a0c2e061229bf7820a` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 02:15:02` |
| Reporter | `Bitsight` |
| Tags | `4372983ee83c7c5a55b3bd05810657d2, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f95d8290bd17c8319a2f3b47db6bd75` |
| SHA-1 | `ce629f8ad9428474bab4b95774102a13b096f516` |
| SHA-256 | `694a3bab92e60e6760649fd40e97c04ff03faded2073e7a0c2e061229bf7820a` |
| SHA3-384 | `454acdcf64360d3a629bde1b0a80595432d6624813fda818e81ed2a3af4c5db3b19ffceec9321a8417583643dcf992bb` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1D63633833CC921B9D165C379A64B64BDB079BBA147A97E2236CC25088DE7F24603F7C5` |
| SSDEEP | `98304:5dpOhAeBQI8l1HYyXYYWQ8IgNTzZ2MGjjPzjU51/3wTPlzDNSvcYSrGORzje:5DOhHBmYyXYb19ZBuj4OFDEcYSrHhje` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_023_694a3bab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "694a3bab92e60e6760649fd40e97c04ff03faded2073e7a0c2e061229bf7820a"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 02:15:02"
  condition:
    hash.sha256(0, filesize) == "694a3bab92e60e6760649fd40e97c04ff03faded2073e7a0c2e061229bf7820a"
}
```

### Sample 24: `2485d9a51fc370a0`

| Field | Value |
|---|---|
| SHA-256 | `2485d9a51fc370a064613f490bd16df1553e3edb4fc38cbede4023e046932a33` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 02:14:53` |
| Reporter | `Bitsight` |
| Tags | `4372983ee83c7c5a55b3bd05810657d2, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6bbdc23fccf0e91ae790d4b8d662ee4` |
| SHA-1 | `940963578895e039a243ab8e76bbfe60e24b2f87` |
| SHA-256 | `2485d9a51fc370a064613f490bd16df1553e3edb4fc38cbede4023e046932a33` |
| SHA3-384 | `11de81a8e70b327676f0b1101008cc7ee21f4b07a49e3f990e57cfc3e997da294db312d2150e91efa27f2c3e6a2596dc` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T15FD523A3ADB75974D437CBB29F52E46EB03A3B8287608E03F1CD6D549E42944D93A370` |
| SSDEEP | `49152:UakLX+McmEzfNTayLArFHwLHzCtQI3O8tEnicsgH2wbAuOvtrQUyUqRvv9C:UakL+Fd5aULvytEnqAD5OtQUyrt9C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_2485d9a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2485d9a51fc370a064613f490bd16df1553e3edb4fc38cbede4023e046932a33"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 02:14:53"
  condition:
    hash.sha256(0, filesize) == "2485d9a51fc370a064613f490bd16df1553e3edb4fc38cbede4023e046932a33"
}
```

### Sample 25: `601080635c9ccd34`

| Field | Value |
|---|---|
| SHA-256 | `601080635c9ccd34b65b0fa5852282a58bac0eee8c01120beb1fd852a2d31e66` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 02:14:47` |
| Reporter | `Bitsight` |
| Tags | `4372983ee83c7c5a55b3bd05810657d2, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8639f5e2de621eaee6e00e97be9c6139` |
| SHA-1 | `8facc65ae4ac1ef7c2476cf39d34f2098c6d6c8c` |
| SHA-256 | `601080635c9ccd34b65b0fa5852282a58bac0eee8c01120beb1fd852a2d31e66` |
| SHA3-384 | `c963e13100737470e7cddd0f1f50922d7c21aa4e3bac0af8faebc46a879a2ef7206b316548ceae500adffef8c2e09aab` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T182D52399FCB106F0D836C7FA928361AE711937408A659D13B6CD6B006C6362D7D3A3BD` |
| SSDEEP | `49152:+sLYZ2QQlxKrAORzIwCHxDBtSYWhzV59WYIUk9EpAwpQqRIHtlbFU5jXjITCZ:+s4N2sr7KwkxD965w3U6EywuD+Vjl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_60108063
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "601080635c9ccd34b65b0fa5852282a58bac0eee8c01120beb1fd852a2d31e66"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 02:14:47"
  condition:
    hash.sha256(0, filesize) == "601080635c9ccd34b65b0fa5852282a58bac0eee8c01120beb1fd852a2d31e66"
}
```

### Sample 26: `60e66eaa948273a5`

| Field | Value |
|---|---|
| SHA-256 | `60e66eaa948273a5fbb3701ce3636d007ab0e91fc98be4801ccedb99b204b313` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 02:14:39` |
| Reporter | `Bitsight` |
| Tags | `4372983ee83c7c5a55b3bd05810657d2, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fbac6e2cdca5f36b9a2bd3bb418cd2a` |
| SHA-1 | `eea16abf13a894c1b9999d85ca4c820c1d94983b` |
| SHA-256 | `60e66eaa948273a5fbb3701ce3636d007ab0e91fc98be4801ccedb99b204b313` |
| SHA3-384 | `c3de2bbc1b9d368c8a9c84c6eca8f109adb4243c02500919201e6342101054090a5c96b7e6535f33fcca474c6fb6937d` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T182D523CA78F66EB0C473C3B5CF82E4ADB16ABB855A704E07BACE6900CD52514953B371` |
| SSDEEP | `49152:gcF+dRID1+TSuFFd6Y6hmLKxVWdWuKCz+46AVJQGb7nQfBSPP3j:5FweLuFFd6SrKCgAPQ8Qf4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_60e66eaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60e66eaa948273a5fbb3701ce3636d007ab0e91fc98be4801ccedb99b204b313"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 02:14:39"
  condition:
    hash.sha256(0, filesize) == "60e66eaa948273a5fbb3701ce3636d007ab0e91fc98be4801ccedb99b204b313"
}
```

### Sample 27: `3f7b8f2badc3c70d`

| Field | Value |
|---|---|
| SHA-256 | `3f7b8f2badc3c70d10827c9b9ce4cbd4b8d2611d78b35ec1590222595794da63` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-23 01:54:21` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `118fe900d90af54bf08062330f721f26` |
| SHA-1 | `4c7ca1b63a6ea220ebd9f305a5dd6489ac57cf7f` |
| SHA-256 | `3f7b8f2badc3c70d10827c9b9ce4cbd4b8d2611d78b35ec1590222595794da63` |
| SHA3-384 | `43c402107008e706e91370df089d1e6c8ef7fea6f8998422ff8195fa08368724407c82973065cd3f8fec83174ccdec1e` |
| TLSH | `T13D136D6566953C28AE9988371D7E1F0CBDAA83E2310491DDBFCB3CF18C59A9CD21871D` |
| SSDEEP | `768:MXRWNGxV29GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:glxZco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_3f7b8f2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f7b8f2badc3c70d10827c9b9ce4cbd4b8d2611d78b35ec1590222595794da63"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 01:54:21"
  condition:
    hash.sha256(0, filesize) == "3f7b8f2badc3c70d10827c9b9ce4cbd4b8d2611d78b35ec1590222595794da63"
}
```

### Sample 28: `366e52b6d95d9478`

| Field | Value |
|---|---|
| SHA-256 | `366e52b6d95d9478a73ffcd659a1807bdea901a0737b7b2532fe11145be03925` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-23 01:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a20052c78501ce91feba8ce56a3aa665` |
| SHA-1 | `18b3741afc2712dafb56505b1c1822372b35cc0b` |
| SHA-256 | `366e52b6d95d9478a73ffcd659a1807bdea901a0737b7b2532fe11145be03925` |
| SHA3-384 | `8ec208105fb224113df3030ea8684c7adf57fa060635ebd1aa06daadeb26ca5a0f8c3202c71fdca6f5e6d96a2d139a44` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1A8E63308A6E041FEE9B241BDEDD161C2E4A1B4F64B76C5EF0B449B611D132E1C83EB63` |
| SSDEEP | `393216:zupEl/NSiZOZcjsSAWWXMCHWUjXZcuI3/PGTAI:zus/NSisejsSAWWXMb8XuH/O7` |
| ICON-DHASH | `7071e4d6a2e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_366e52b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "366e52b6d95d9478a73ffcd659a1807bdea901a0737b7b2532fe11145be03925"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 01:52:09"
  condition:
    hash.sha256(0, filesize) == "366e52b6d95d9478a73ffcd659a1807bdea901a0737b7b2532fe11145be03925"
}
```

### Sample 29: `4119001a7ecd42e4`

| Field | Value |
|---|---|
| SHA-256 | `4119001a7ecd42e4eccf0694011bcccf0205064aaafec0c835c02bc943cb9053` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-23 01:46:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa7dd127fed1555f6e17a7b55054042d` |
| SHA-1 | `ecc3c66c1afe880f88ecdfd30a559db94499d637` |
| SHA-256 | `4119001a7ecd42e4eccf0694011bcccf0205064aaafec0c835c02bc943cb9053` |
| SHA3-384 | `0caa65ec061b3bad56842fec1b43228ba7b7c6ab8578fd0a4c38f28f4c750553b09ecee6695d5013a35514d53f342574` |
| TLSH | `T179F3E80AAF500EB7D82FDD3B06E93B46258C755322E83B757634D918FA0A64B09E3D74` |
| SSDEEP | `3072:/HDROyxMrPexCmoQM+LG+WhveR9BUlrWw:/DAfQM+mWPB2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_4119001a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4119001a7ecd42e4eccf0694011bcccf0205064aaafec0c835c02bc943cb9053"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-23 01:46:38"
  condition:
    hash.sha256(0, filesize) == "4119001a7ecd42e4eccf0694011bcccf0205064aaafec0c835c02bc943cb9053"
}
```

### Sample 30: `99f6342a0808a477`

| Field | Value |
|---|---|
| SHA-256 | `99f6342a0808a4772f275c3127e2e305e57242bb7aae032b5e488b4a6e80a0e4` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-23 01:36:25` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d63d2595794c875cb36798fecf1d69b` |
| SHA-1 | `6fdbfec162f2cc88cb6f0793061f48785c28bdb7` |
| SHA-256 | `99f6342a0808a4772f275c3127e2e305e57242bb7aae032b5e488b4a6e80a0e4` |
| SHA3-384 | `b852fda42fc5fa0f39096697f204bb5a73b6b1223bf565e2c163c03424fda2fa6ad719483fe358100cd4f4edcb267937` |
| TLSH | `T173C28E956A867C44BDC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:t8vCB+25j6es8RS9FYpMSUpi+20qUpi+20YQX:t8l25J0d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_99f6342a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99f6342a0808a4772f275c3127e2e305e57242bb7aae032b5e488b4a6e80a0e4"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-23 01:36:25"
  condition:
    hash.sha256(0, filesize) == "99f6342a0808a4772f275c3127e2e305e57242bb7aae032b5e488b4a6e80a0e4"
}
```

### Sample 31: `81cfb1bfebe07151`

| Field | Value |
|---|---|
| SHA-256 | `81cfb1bfebe07151a744547e40a71ed31038af2487d010a406609e921243f082` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-23 01:24:21` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db20fe2d0a9e61bf776f4606cc587b84` |
| SHA-1 | `b49da8135295643544df3c59eb1c3409ed1ec4f6` |
| SHA-256 | `81cfb1bfebe07151a744547e40a71ed31038af2487d010a406609e921243f082` |
| SHA3-384 | `ebc1c9a81d767c55273435fa26529a69cc3bd9f1a62260c67d7ecd7593a8e8d319460e5777d4ca68e18b56590ccdba8b` |
| TLSH | `T14B138D651A853C24AE9889371C7F2F0CB9A983E1300451DDBFCB3CF58C59AACE21971D` |
| SSDEEP | `768:t6Utd8/f9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:5co` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_81cfb1bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81cfb1bfebe07151a744547e40a71ed31038af2487d010a406609e921243f082"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 01:24:21"
  condition:
    hash.sha256(0, filesize) == "81cfb1bfebe07151a744547e40a71ed31038af2487d010a406609e921243f082"
}
```

### Sample 32: `b6a1b3ec67140548`

| Field | Value |
|---|---|
| SHA-256 | `b6a1b3ec671405487d5f73b95f98f376d902f31a370d67c92081d9d491ca497d` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-23 01:04:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99cc7cb7884383da9601b396c03b9033` |
| SHA-1 | `bb953e21a706145b8a4c4c24d0756936ec19ea34` |
| SHA-256 | `b6a1b3ec671405487d5f73b95f98f376d902f31a370d67c92081d9d491ca497d` |
| SHA3-384 | `cc0a3d7e98f753bc7439a59a57af6622e3bd0da9a96f099aa922e3b61f85b02eaae9010ab3aca46ff72c2fae72bb7288` |
| TLSH | `T1D444F8066F910FF7C8AFDF3702EB0A11248DE41727A62B367638E978B60A54E55D3C64` |
| TELFHASH | `t183815244e83c46dddea31e69adb86fa31943e12623916f1aff2acdc8085e418f114d1f` |
| SSDEEP | `6144:i2RkzMdl1LV9kpBw3AOgP/a6yB1hWF5NqohWUkzn7MwA0:im6MdjVipFnyB1hWF5NqohWUkzn7MwA0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_b6a1b3ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6a1b3ec671405487d5f73b95f98f376d902f31a370d67c92081d9d491ca497d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-23 01:04:33"
  condition:
    hash.sha256(0, filesize) == "b6a1b3ec671405487d5f73b95f98f376d902f31a370d67c92081d9d491ca497d"
}
```

### Sample 33: `3d594ae09c50f0a6`

| Field | Value |
|---|---|
| SHA-256 | `3d594ae09c50f0a63a8b213b6bbdf390f34ddd83900f1e0a9053e17fa20fd643` |
| Family label | `unknown` |
| File name | `3d594ae09c50f0a63a8b213b6bbdf390f34ddd83900f1e0a9053e17fa20fd643` |
| File type | `elf` |
| First seen | `2026-07-23 01:00:25` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e31d00e554f4044c93b6da65c486a369` |
| SHA-1 | `84199c6db29ea7d95b802ebb470d6058289a0757` |
| SHA-256 | `3d594ae09c50f0a63a8b213b6bbdf390f34ddd83900f1e0a9053e17fa20fd643` |
| SHA3-384 | `97274edcf6cc44723b2f598e0e717e88918e3efe12c67c99e627508ec47eb081c437468014ca99dd0692aa7c624b2fbb` |
| TLSH | `T1DA564B73909154D4D2AED974C6156213BEE4388B673863CBBBC076F11B7ABE49A78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ/:cqYUQuVDt0TZE0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_3d594ae0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d594ae09c50f0a63a8b213b6bbdf390f34ddd83900f1e0a9053e17fa20fd643"
    family = "unknown"
    file_name = "3d594ae09c50f0a63a8b213b6bbdf390f34ddd83900f1e0a9053e17fa20fd643"
    file_type = "elf"
    first_seen = "2026-07-23 01:00:25"
  condition:
    hash.sha256(0, filesize) == "3d594ae09c50f0a63a8b213b6bbdf390f34ddd83900f1e0a9053e17fa20fd643"
}
```

### Sample 34: `1bd3745a4f9043ea`

| Field | Value |
|---|---|
| SHA-256 | `1bd3745a4f9043ead807d7777669b0dbf5b56985e5b3dd9d7cff8384154ea4a8` |
| Family label | `unknown` |
| File name | `1bd3745a4f9043ead807d7777669b0dbf5b56985e5b3dd9d7cff8384154ea4a8` |
| File type | `elf` |
| First seen | `2026-07-23 01:00:20` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19cb85db85565e19840d5e6214abb198` |
| SHA-1 | `50d5d3dd9f796be99e2f3ca785f118d34f8f6e73` |
| SHA-256 | `1bd3745a4f9043ead807d7777669b0dbf5b56985e5b3dd9d7cff8384154ea4a8` |
| SHA3-384 | `58052285f20d19af6a45799ced3c315a4307812db90ef7dec02bf58d8dccd8b0dac65447d40557d22128c1a3a93f7b48` |
| TLSH | `T1EE463A73A49114E4D2EED974C6156212BEE4388B273463CB7BD076F11B7ABE49A78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQL:cqYUQuVDt0TZE8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_1bd3745a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bd3745a4f9043ead807d7777669b0dbf5b56985e5b3dd9d7cff8384154ea4a8"
    family = "unknown"
    file_name = "1bd3745a4f9043ead807d7777669b0dbf5b56985e5b3dd9d7cff8384154ea4a8"
    file_type = "elf"
    first_seen = "2026-07-23 01:00:20"
  condition:
    hash.sha256(0, filesize) == "1bd3745a4f9043ead807d7777669b0dbf5b56985e5b3dd9d7cff8384154ea4a8"
}
```

### Sample 35: `a128fc6dffeb0f79`

| Field | Value |
|---|---|
| SHA-256 | `a128fc6dffeb0f7917a07f158dc4fafda4e2cf5c7bfd69d06b56f3db810622e1` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-07-23 00:56:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7c60a24dc1e9bf4f4d4f6a036266c10` |
| SHA-1 | `9547dbe222edb29fa0cb6f46bb02b2dc5d0a5a15` |
| SHA-256 | `a128fc6dffeb0f7917a07f158dc4fafda4e2cf5c7bfd69d06b56f3db810622e1` |
| SHA3-384 | `fddd535ce29d10648df06631c2abfbcfc6b60349471ebfc0821e776b0f8d46e2d8eaa98a03f9826a28086cd5726ffb22` |
| TLSH | `T165831895B8818B12D5D512BAFE1E118E3313177CE3DE73129D206F20778B96B0E7BA16` |
| TELFHASH | `t131f0e1142ec84fcc92f4899c925e802a79953e71c571792e8d97e66f53134c2202441e` |
| SSDEEP | `1536:ijna/CzPC7fG7LnmhsUrrar1FtQtMEig+wG3if7z7ueY52Y0s/hG:rwP0km+Urrar8+wG3if7zKeYw1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_a128fc6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a128fc6dffeb0f7917a07f158dc4fafda4e2cf5c7bfd69d06b56f3db810622e1"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-07-23 00:56:52"
  condition:
    hash.sha256(0, filesize) == "a128fc6dffeb0f7917a07f158dc4fafda4e2cf5c7bfd69d06b56f3db810622e1"
}
```

### Sample 36: `d6981ba0520c7c56`

| Field | Value |
|---|---|
| SHA-256 | `d6981ba0520c7c56c54158f9e6802908999136e3db5a99d93b3f1a792a4d96f1` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-07-23 00:56:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e95d2570f510f3a5af8defccca1080be` |
| SHA-1 | `2540623968fe6613e170cd2ec86f2dbf92de6fa9` |
| SHA-256 | `d6981ba0520c7c56c54158f9e6802908999136e3db5a99d93b3f1a792a4d96f1` |
| SHA3-384 | `ce93e1ab879864a879f214fff6cedb615032f5fb61ebc294a6f72335dd868d82ee2cb89fb91bed04303c560dd2006529` |
| TLSH | `T1B3E32C56E6814B13C0D2177ABADF42453323A764D3EB73059928BFB43F8679E0E63606` |
| TELFHASH | `t1f031fd325721411aae52cc60dcee57f1251d86272744ee33ef3ac8cc651a49ae62bc8f` |
| SSDEEP | `3072:U+Ug9WIx0UEaK0U4560zSlzhXRzM9hO3+keLUM/9g2JCVF:U+ULIxLEaK0U456xl9RI9c3+ZgM/9d8T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_d6981ba0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6981ba0520c7c56c54158f9e6802908999136e3db5a99d93b3f1a792a4d96f1"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-07-23 00:56:49"
  condition:
    hash.sha256(0, filesize) == "d6981ba0520c7c56c54158f9e6802908999136e3db5a99d93b3f1a792a4d96f1"
}
```

### Sample 37: `300aee7894a93235`

| Field | Value |
|---|---|
| SHA-256 | `300aee7894a93235dc4a55fa02914bbb93d67700aa11bdeff252b40d87ac6014` |
| Family label | `Mirai` |
| File name | `pppc` |
| File type | `elf` |
| First seen | `2026-07-23 00:56:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f5bba4dd26bb0397d42831a3aa95d84` |
| SHA-1 | `f5123196d145752e584f5f5c44dbd7b14cfa9268` |
| SHA-256 | `300aee7894a93235dc4a55fa02914bbb93d67700aa11bdeff252b40d87ac6014` |
| SHA3-384 | `cdef7ca3b0864194c2f6853feb3163563aba8ac597a311f65ec1aab7111dfe14c9526b60c8ca4ce8dece0ac3e854121a` |
| TLSH | `T141633B02B31C0E47D16359B02A3F27E183BFA99121F4F689651EDB869276E325186FCD` |
| SSDEEP | `1536:9yJWBrmSTKrF5TQGwITdHQ7+uLxWDeIQS5A16BH17Qs/nXB/:04Ox5TQK1vDeIL5xrB/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_300aee78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "300aee7894a93235dc4a55fa02914bbb93d67700aa11bdeff252b40d87ac6014"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-07-23 00:56:44"
  condition:
    hash.sha256(0, filesize) == "300aee7894a93235dc4a55fa02914bbb93d67700aa11bdeff252b40d87ac6014"
}
```

### Sample 38: `4ca54b07bd66b64c`

| Field | Value |
|---|---|
| SHA-256 | `4ca54b07bd66b64c255400440a513037ed41e0e79eb552bae97928fe1b9aaae4` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-07-23 00:56:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2488367919e0f8f64a0f52678312e281` |
| SHA-1 | `97578c7312509c3a271b421f502b4457286ea010` |
| SHA-256 | `4ca54b07bd66b64c255400440a513037ed41e0e79eb552bae97928fe1b9aaae4` |
| SHA3-384 | `092f71cbf221920508c4f5747050ffbaf094419885f661bea871c9c0cc05fa74ab0aaa5ca9aaace0ad449bde44bc5b24` |
| TLSH | `T115A3E506BB650FF7DC6FCD3706A9070225CCA51B22B83B367674D928B50B65B4AE3874` |
| SSDEEP | `1536:LvGefaZSdtbB4/xl4ExO29zyN0ZNhdZp54crFCZeLs/h5J:LOefaZSdc59zm0Hr6eoJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_4ca54b07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ca54b07bd66b64c255400440a513037ed41e0e79eb552bae97928fe1b9aaae4"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-07-23 00:56:41"
  condition:
    hash.sha256(0, filesize) == "4ca54b07bd66b64c255400440a513037ed41e0e79eb552bae97928fe1b9aaae4"
}
```

### Sample 39: `1d370494366ea996`

| Field | Value |
|---|---|
| SHA-256 | `1d370494366ea99666309ab4e8a906f5bd7ee9fd752d0d8833644921a9ab147e` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e67568d45a238b652ec13e4655b4d5d1` |
| SHA-1 | `9af0315c168e3a737838ea1959538cd272b46543` |
| SHA-256 | `1d370494366ea99666309ab4e8a906f5bd7ee9fd752d0d8833644921a9ab147e` |
| SHA3-384 | `cd3bcc6102bb4cba4590f09d91bad43ede01b74a0725423976bbfdc42d42f4a4a4b171e0da0176aea9403f0b770e08c1` |
| TLSH | `T1A2A3C91E6E218FBDF369C33047B78E21A79837D626E1D685E26CD6011E6034E641FFA4` |
| TELFHASH | `t173217f5c4d7412e48b321d9e2baeff76e19030de0b326d378e11aaadba6d9425d00c1c` |
| SSDEEP | `1536:yk8NZJjWAaKPRcve4meOeuCyTPHvwIp/read7Q1Qs/Rd/uP:WZJjBaKpzhHvlp/o1F/c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_1d370494
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d370494366ea99666309ab4e8a906f5bd7ee9fd752d0d8833644921a9ab147e"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:48"
  condition:
    hash.sha256(0, filesize) == "1d370494366ea99666309ab4e8a906f5bd7ee9fd752d0d8833644921a9ab147e"
}
```

### Sample 40: `23de6ff2926dc77d`

| Field | Value |
|---|---|
| SHA-256 | `23de6ff2926dc77da7736a5a39a0c4a7ba9de838d78c2abbba81402dfd243b56` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c314c9002608b928721a4ce937ae027a` |
| SHA-1 | `10fbd75b6a8844eb7b77623a743908d6527deee2` |
| SHA-256 | `23de6ff2926dc77da7736a5a39a0c4a7ba9de838d78c2abbba81402dfd243b56` |
| SHA3-384 | `b64887cb720ac872146f0760e0b46e1035ab7fe488b171977dbc29c9e9ac0a40abb5329c2a63954d7db4399e9e8bff2b` |
| TLSH | `T119732A91BD815713C6D012BBFB5E028E372A53A8D2EE72179D226F2137C786B0E77641` |
| TELFHASH | `t1cd01f4708f490ef82bc0cf0c908e723db759b118fb1115150e7e6e1a823ae90b31142e` |
| SSDEEP | `1536:86dz9MTC0XU66EespV5brAMjztPz+Sbjt+UvAs/hY:86dS6ER5rAMNb+AA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_23de6ff2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23de6ff2926dc77da7736a5a39a0c4a7ba9de838d78c2abbba81402dfd243b56"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:46"
  condition:
    hash.sha256(0, filesize) == "23de6ff2926dc77da7736a5a39a0c4a7ba9de838d78c2abbba81402dfd243b56"
}
```

### Sample 41: `63aa7d76bee79037`

| Field | Value |
|---|---|
| SHA-256 | `63aa7d76bee790377ac6cb34cbff2fe69694883ef920eb7af3fef2e428bb09de` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5abfb6a9cb7f7a6bd5eab510c3bad11b` |
| SHA-1 | `1beaae69ca44703fa5a7a1f6cb7c00a47725de79` |
| SHA-256 | `63aa7d76bee790377ac6cb34cbff2fe69694883ef920eb7af3fef2e428bb09de` |
| SHA3-384 | `639e17dab116edd1074e5837e6787d2c341ff9ee5da0c01c3128a3cfce7e277519a784a0422df0987e7b3b58ad13286e` |
| TLSH | `T1B8631A91BD819B13C6D0227BFB5E428E372653A8D2EE72079D226F21378785F0E77641` |
| TELFHASH | `t1e3019c605a406bd86ac0cbb8a18e242f34adb575aa24242a695f7e5692532c0e90042a` |
| SSDEEP | `1536:XGBQnw68oqNi5Iaz1/GIw+D3ohyaRdWViEs/hX:XGBBa5Z91w+8kayA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_63aa7d76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63aa7d76bee790377ac6cb34cbff2fe69694883ef920eb7af3fef2e428bb09de"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:43"
  condition:
    hash.sha256(0, filesize) == "63aa7d76bee790377ac6cb34cbff2fe69694883ef920eb7af3fef2e428bb09de"
}
```

### Sample 42: `61de63d750abb376`

| Field | Value |
|---|---|
| SHA-256 | `61de63d750abb376ee07f403a3c4b3a77a6d9a8d68c0c40ed0d0f7ecf0ea53be` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `383951060ca4c6096e61b00a950cc759` |
| SHA-1 | `332d1febd1c52f9612160bae415a4e802b0f4f65` |
| SHA-256 | `61de63d750abb376ee07f403a3c4b3a77a6d9a8d68c0c40ed0d0f7ecf0ea53be` |
| SHA3-384 | `aac305d46b6242dfdc3cb571149d2b8c849783a0931b5b448d7512698c5d40a9e392c25fd8100c128e696a5afd974d76` |
| TLSH | `T16A535BC5AA47D8F6FD5602711173E7378632F13A1129DA87C7A9ED32BC52900EA1739C` |
| TELFHASH | `t11f31b0fa6dee09fcb3d4a808c75a6fd31a7ae177156139b044b5585027f388081b5c3a` |
| SSDEEP | `1536:ahZerRy3lVDKvfb9IZG4R9bdx6pQ7P++CMq32UFSTGhk15uJnaroXf:ahqo3lVDKbd4bVP+zf2UMT2M5O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_61de63d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61de63d750abb376ee07f403a3c4b3a77a6d9a8d68c0c40ed0d0f7ecf0ea53be"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:41"
  condition:
    hash.sha256(0, filesize) == "61de63d750abb376ee07f403a3c4b3a77a6d9a8d68c0c40ed0d0f7ecf0ea53be"
}
```

### Sample 43: `dfe31d54aaf42b09`

| Field | Value |
|---|---|
| SHA-256 | `dfe31d54aaf42b090ce4ceb7c4c33a68acde5862a88ced927968efc8e99bfac5` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c56d3a5a7c1778ebe2b63837b288e5c` |
| SHA-1 | `cbd5854c33f5fd5b17611bec9141918b9d4ec0bb` |
| SHA-256 | `dfe31d54aaf42b090ce4ceb7c4c33a68acde5862a88ced927968efc8e99bfac5` |
| SHA3-384 | `244c80e250553d9c4065a93b4b3f409e922e5f95e5dd0ce18b9c9e07be07fe8396bc446af04d9bcf7c0c68a26443538b` |
| TLSH | `T12803E0345A16AE76CE303C72E9341AC02B1A53EC94FB35422AF4815CA4CE182BEF95D7` |
| SSDEEP | `768:uhbUpgfK/AwseUqfHGmIin9xY00XNkQPLhaYF/Bqlu8LP9q3UEL+c:uxUpgy4iDfHGzdNrPLhGl0Lt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_dfe31d54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfe31d54aaf42b090ce4ceb7c4c33a68acde5862a88ced927968efc8e99bfac5"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:31"
  condition:
    hash.sha256(0, filesize) == "dfe31d54aaf42b090ce4ceb7c4c33a68acde5862a88ced927968efc8e99bfac5"
}
```

### Sample 44: `5dcc401bcba1ccc0`

| Field | Value |
|---|---|
| SHA-256 | `5dcc401bcba1ccc0f65b59c3ec54605cbfa33f970940957bf98af2d7054119a4` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd61f28962b1f049c8ecb58c0a9aeb35` |
| SHA-1 | `78e7916c60f5019760d56246c88a10d604251598` |
| SHA-256 | `5dcc401bcba1ccc0f65b59c3ec54605cbfa33f970940957bf98af2d7054119a4` |
| SHA3-384 | `659de9f9077f9d3774aebb723b02a8a3e87354ab6a57e74f7279497d70fda7937edf40c6cf72200a57a677f60fcfcb5c` |
| TLSH | `T149430265D187177B7B101773F6A474B3AAD71EB6D0FC200BA96AA7F8835481A336C183` |
| SSDEEP | `1536:FbcQZVz41yGuwSQn8tnAB6Luy6tlV1nLa:Ws2saSsqAILd6tlHe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_5dcc401b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dcc401bcba1ccc0f65b59c3ec54605cbfa33f970940957bf98af2d7054119a4"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:30"
  condition:
    hash.sha256(0, filesize) == "5dcc401bcba1ccc0f65b59c3ec54605cbfa33f970940957bf98af2d7054119a4"
}
```

### Sample 45: `218399fcd5f5e41e`

| Field | Value |
|---|---|
| SHA-256 | `218399fcd5f5e41e70d42c49d099ebd7d0cb32452ce547b79d12103a95d8d03f` |
| Family label | `Mirai` |
| File name | `pspc` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c53ec128069bc4d867266c623109f7b` |
| SHA-1 | `cc2d02cb2d444e6bbc49746f2f2c207c55e18263` |
| SHA-256 | `218399fcd5f5e41e70d42c49d099ebd7d0cb32452ce547b79d12103a95d8d03f` |
| SHA3-384 | `48f3181717e415206585421e9b83e7a7340a7bb8aed4176762e8092a41af1e6fcd5ff178c5b1f8ecb2887e41195036d8` |
| TLSH | `T17B735C32B9751D2BC4D0A87A61F30325F2F2478A25ACCA1A7D720D8EBF6565032477F9` |
| SSDEEP | `1536:jP+SbCGR18pspTH1qDQ2tXXUN95s0xwlWptCMR8/pW:zf4yV0pENP1x6MoW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_218399fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "218399fcd5f5e41e70d42c49d099ebd7d0cb32452ce547b79d12103a95d8d03f"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:29"
  condition:
    hash.sha256(0, filesize) == "218399fcd5f5e41e70d42c49d099ebd7d0cb32452ce547b79d12103a95d8d03f"
}
```

### Sample 46: `7ca630f1e4f63aa9`

| Field | Value |
|---|---|
| SHA-256 | `7ca630f1e4f63aa9d483c2d79b53fffd0c8348c26344b61b20562b127e74975a` |
| Family label | `Mirai` |
| File name | `pppc` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9c5052348b55960394c00335c7569f6` |
| SHA-1 | `85d58d562216b6f33d5bc0ef54b1081c6433d761` |
| SHA-256 | `7ca630f1e4f63aa9d483c2d79b53fffd0c8348c26344b61b20562b127e74975a` |
| SHA3-384 | `2645471ba27a83d5ad6faf08c4055f7c098678c0830839ceb8be39dfa2f4bb3a4d74838ea10e696f0bb2244d6cedabda` |
| TLSH | `T17DF2F214D29B0E5BDBFFFAF04982C7C273501E5E62348B2121CA8B215AA3C535D39ED4` |
| SSDEEP | `768:Uk9hrdmlHUzjQZ0S5SF8KcQD36DE4oy4uVcqgw09Z:Uk9Nd6Hj0KSdCloy4u+qgw09Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_7ca630f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ca630f1e4f63aa9d483c2d79b53fffd0c8348c26344b61b20562b127e74975a"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:27"
  condition:
    hash.sha256(0, filesize) == "7ca630f1e4f63aa9d483c2d79b53fffd0c8348c26344b61b20562b127e74975a"
}
```

### Sample 47: `67b3e794aae2500a`

| Field | Value |
|---|---|
| SHA-256 | `67b3e794aae2500ad567d33a4ee563a9476f76fe55b9de8b96fa2e62573278b7` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26467ba071ecd221760fa4eb0562651e` |
| SHA-1 | `2f15781d62beb640c77d03415aed01ffd3b12f90` |
| SHA-256 | `67b3e794aae2500ad567d33a4ee563a9476f76fe55b9de8b96fa2e62573278b7` |
| SHA3-384 | `7346113cd5c115a200316978bbfd846cf8f914dfd83691516a74d587d1642fcba26d3456dba16adff4448702bf71b6b9` |
| TLSH | `T19103F17FED6178DAC8CDA1B9834F12665B4130A03397C659420CD434296EB66E0CC0FE` |
| SSDEEP | `768:2VyIwYjG0JFYWLXfqqvhdsb1aaCnbhSgsJ9w2CV3Q/WJ:2VyYjXJiOfHJdg1aasdsJRO3Qc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_67b3e794
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67b3e794aae2500ad567d33a4ee563a9476f76fe55b9de8b96fa2e62573278b7"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:26"
  condition:
    hash.sha256(0, filesize) == "67b3e794aae2500ad567d33a4ee563a9476f76fe55b9de8b96fa2e62573278b7"
}
```

### Sample 48: `93c43002575153c1`

| Field | Value |
|---|---|
| SHA-256 | `93c43002575153c1ade572ee6e3dab97ce10d7e0f82d1655a1ea3b4a6f33df45` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cec558316acd8008e39f07e5d9906165` |
| SHA-1 | `a62ef6aa8c1726dac1fc0f39df6cfe65e5af0747` |
| SHA-256 | `93c43002575153c1ade572ee6e3dab97ce10d7e0f82d1655a1ea3b4a6f33df45` |
| SHA3-384 | `fd271b591e0765748f0fd378ed041bdcfe58ef7e55c4507ea8233be5da2702488723685ea833b2397210a5a3467c0f2b` |
| TLSH | `T1D3539C73C8296E54D19582B4B871CB781B63B48082471FFA5BD9C2BA9083DFCF6093B4` |
| SSDEEP | `1536:JaDwtqKcomlIFZCXaZMYfPkYPegpK2mP5A/iabC0c/v38Bs/n8a:JwacomlITCXaZMYXkY2gQ2mgiabgXMla` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_93c43002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93c43002575153c1ade572ee6e3dab97ce10d7e0f82d1655a1ea3b4a6f33df45"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:25"
  condition:
    hash.sha256(0, filesize) == "93c43002575153c1ade572ee6e3dab97ce10d7e0f82d1655a1ea3b4a6f33df45"
}
```

### Sample 49: `df835ef7635ffe39`

| Field | Value |
|---|---|
| SHA-256 | `df835ef7635ffe39dda4b14f7987ee7772fdf7c8a41ba8ed304450b2f78e857b` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46bd7559a9df79241d4db5f73068705b` |
| SHA-1 | `03ee83a3b359aa2724e5a69d152888e19d673fa9` |
| SHA-256 | `df835ef7635ffe39dda4b14f7987ee7772fdf7c8a41ba8ed304450b2f78e857b` |
| SHA3-384 | `984f726f49c77949f6e8eb0a6ff6f110245617c829683442573b2e88ea774da1669a983e39edb194d6d09cd66beafd09` |
| TLSH | `T137832A97F400EDBDF80AD77B4453090AB270A3A105830F36A39BB963FD721A45967EC6` |
| SSDEEP | `1536:quKG91w4NgWxYRyRqwwrzPQtav8FjWtFUo/V6OXZJ7/aNSOFmA7ExtX1dT:q5GTPxYRyRqwazPQta6Q9VXXz4FmA7ux` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_df835ef7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df835ef7635ffe39dda4b14f7987ee7772fdf7c8a41ba8ed304450b2f78e857b"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:24"
  condition:
    hash.sha256(0, filesize) == "df835ef7635ffe39dda4b14f7987ee7772fdf7c8a41ba8ed304450b2f78e857b"
}
```

### Sample 50: `0d0f273842095e3c`

| Field | Value |
|---|---|
| SHA-256 | `0d0f273842095e3c540d4192f9231282fef2fbba21f3ae5934471a7b90866ce1` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37b98aba610b3afe1a9b9e2bf2ca0852` |
| SHA-1 | `425447e48bd39dd50952ac9f786a703b3a6e9a8d` |
| SHA-256 | `0d0f273842095e3c540d4192f9231282fef2fbba21f3ae5934471a7b90866ce1` |
| SHA3-384 | `7cb214ffad9b663e90c7ae5dc1e72a6d9687bebb6a22c7c5b43a2ad130e2e86704f18c8b89122cc1a2b1c7732a9c26b4` |
| TLSH | `T185F2F12E218001C8F52685BE80E4475976D80FE2A9874CDFFCA5EF73B91E16927933E4` |
| SSDEEP | `768:gNYKyukZoTMKeOs/JlzzJ2+0Bj5O86amVBOnZhlQJgGlzDpbuR1J4:6YdWle7xlzz1ojgMmVBilQVJuy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_0d0f2738
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d0f273842095e3c540d4192f9231282fef2fbba21f3ae5934471a7b90866ce1"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:22"
  condition:
    hash.sha256(0, filesize) == "0d0f273842095e3c540d4192f9231282fef2fbba21f3ae5934471a7b90866ce1"
}
```

### Sample 51: `e545089130a2fc85`

| Field | Value |
|---|---|
| SHA-256 | `e545089130a2fc85a172fe88fb0ed5482ca50609c6a942e611dcec45f0680c8c` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c0e2a997674b8ec1083efc51a61fe53` |
| SHA-1 | `cb826dc0f5830390e18c02af6572b48688da133b` |
| SHA-256 | `e545089130a2fc85a172fe88fb0ed5482ca50609c6a942e611dcec45f0680c8c` |
| SHA3-384 | `4e0c96d7bed66865e6388185e25bdd993f4d5e60bff6b0d07ebc51f47a3e9bf0dc2ac9c7f5d5a07b0cade77c03fc400f` |
| TLSH | `T104F2E0B1B1397560D7E18C75C63D89CBB6671B34E3A7F9392E0845E4C28176A70BD80E` |
| SSDEEP | `768:uZAb2jdTWDPtuRl/lUofEWlQUZcH1gHJpn/IF00jaEs3UozZ:uZAKjBWDPtuTlxfEsQX0/QbazZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_e5450891
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e545089130a2fc85a172fe88fb0ed5482ca50609c6a942e611dcec45f0680c8c"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:21"
  condition:
    hash.sha256(0, filesize) == "e545089130a2fc85a172fe88fb0ed5482ca50609c6a942e611dcec45f0680c8c"
}
```

### Sample 52: `cb010e06c861fc82`

| Field | Value |
|---|---|
| SHA-256 | `cb010e06c861fc82ec3ebf806beb6ddaddafadc5142d1506d7d67da74f9b709f` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ce1fa67dfee439a1594f7a4db5fd715` |
| SHA-1 | `19bbfe20b781b76610f16536d0c1526a21af0b07` |
| SHA-256 | `cb010e06c861fc82ec3ebf806beb6ddaddafadc5142d1506d7d67da74f9b709f` |
| SHA3-384 | `4051538b6586f7838012edef6669cdf9a6a5e820cacfdd7a56fbe0384c2dab7c2000758065f6acfaa09e3ccdcc20bcc0` |
| TLSH | `T1A5E2E1117605FCA0D1B85632DCB847DAB2D657B4A5DD32BD662C27D436C380CCEBA28B` |
| SSDEEP | `768:heBsVPxhgu4giWJVoBdZR7wI9vygoLY9dpZHs3Uoz+:heGVPxGu/2ZRh96gF9dGz+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_cb010e06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb010e06c861fc82ec3ebf806beb6ddaddafadc5142d1506d7d67da74f9b709f"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:20"
  condition:
    hash.sha256(0, filesize) == "cb010e06c861fc82ec3ebf806beb6ddaddafadc5142d1506d7d67da74f9b709f"
}
```

### Sample 53: `4822b3ecc126f323`

| Field | Value |
|---|---|
| SHA-256 | `4822b3ecc126f323c4356082078cf15157becf47422c6c7c11d6fb230fb79efe` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-23 00:54:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40b8d2f33f35b94f00c778529bced64b` |
| SHA-1 | `b08ea6bcf812613e3e7d0785a50562387686d29c` |
| SHA-256 | `4822b3ecc126f323c4356082078cf15157becf47422c6c7c11d6fb230fb79efe` |
| SHA3-384 | `7ddbe12bc5acf77b43b78ee5c8ed7ed43e71f236b9433b25b5f9f1b7d734af192754f6c054de45702fc386d41bbe129d` |
| TLSH | `T114E2F26A51ECB12CE44E903BC32F998E31E75D11BE1BC69424C475DADF611F914B6833` |
| SSDEEP | `768:g32bRAqg2aQzSPMjFY8AFOEPB6ZSq7xnwNQBUf:DbRAp2a4ECF+FvB6ZSonwN2w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_4822b3ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4822b3ecc126f323c4356082078cf15157becf47422c6c7c11d6fb230fb79efe"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:19"
  condition:
    hash.sha256(0, filesize) == "4822b3ecc126f323c4356082078cf15157becf47422c6c7c11d6fb230fb79efe"
}
```

### Sample 54: `c781c043c269b879`

| Field | Value |
|---|---|
| SHA-256 | `c781c043c269b8795bd66339d042d1700e9ff8707536a08d314555e82cba3651` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-23 00:52:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6276ed7f42307cf630da0f9213f2b292` |
| SHA-1 | `4932c69a627f52e0ac116d4b86412a4d1918b83a` |
| SHA-256 | `c781c043c269b8795bd66339d042d1700e9ff8707536a08d314555e82cba3651` |
| SHA3-384 | `ce7c76111eb7cafffcb3141c535ebad7ac180853edbcbe89744b6fc9ac27958617a62551aa69d30390addaddb08bbada` |
| TLSH | `T1BAE3075AFC819B11D5C626BAFE5E7189331337ACE3EE7212DD244F2523CA91B0E7A501` |
| TELFHASH | `t1d5d0a7f0ca0a808cdb419456c2d9a2ac9ef8fedae40200e147acbe434f43e927664403` |
| SSDEEP | `3072:bmHlCh5KvD5+4lTy+sVhpV8l8Lp0aFQHT89WGCN28n+dMKzv0:bK4h5KvV+4lTAVhp3F0aFQHT89WxN8dK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_c781c043
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c781c043c269b8795bd66339d042d1700e9ff8707536a08d314555e82cba3651"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-23 00:52:35"
  condition:
    hash.sha256(0, filesize) == "c781c043c269b8795bd66339d042d1700e9ff8707536a08d314555e82cba3651"
}
```

### Sample 55: `4d096a4d27f59f46`

| Field | Value |
|---|---|
| SHA-256 | `4d096a4d27f59f46ba928179f912d8df4467b32a7a7ecf70fac63f0d97fc5edf` |
| Family label | `unknown` |
| File name | `EscapetothePast.exe` |
| File type | `exe` |
| First seen | `2026-07-23 00:50:12` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a31d9599908319a3719526026798f572` |
| SHA-1 | `16ff64512593993b3e4264378bf60692740562f5` |
| SHA-256 | `4d096a4d27f59f46ba928179f912d8df4467b32a7a7ecf70fac63f0d97fc5edf` |
| SHA3-384 | `cdaf5c16526736e60c2ef7f7a0c5ec9ce1c09ec80cf87b1ebf8c6c5a742b5339827111fcc6786d937f9f1b83998f6105` |
| TLSH | `T12A287B06B1A298ADD996C030CE5BF232B7347C4547B26AE73198B7743F726D05F39A84` |
| SSDEEP | `786432:zibPia/z0AogG3niVKBuinJuPYFknHrUnJxWb3SmITEgPtA2D1:mb6aQAo4iJuPsknHroJxWb3SmITEgPt` |
| ICON-DHASH | `39e8ccd4f0f8d4cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_4d096a4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d096a4d27f59f46ba928179f912d8df4467b32a7a7ecf70fac63f0d97fc5edf"
    family = "unknown"
    file_name = "EscapetothePast.exe"
    file_type = "exe"
    first_seen = "2026-07-23 00:50:12"
  condition:
    hash.sha256(0, filesize) == "4d096a4d27f59f46ba928179f912d8df4467b32a7a7ecf70fac63f0d97fc5edf"
}
```

### Sample 56: `46b70348d8726264`

| Field | Value |
|---|---|
| SHA-256 | `46b70348d87262640dd2510b0b6c2d0d9ba9ea1de135c7112405fdf7d08a7efd` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.W32.ABTrojan.RBQK-4720.4321.29656` |
| File type | `exe` |
| First seen | `2026-07-23 00:48:41` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20108d55348000903d54dfa3e4f6f021` |
| SHA-1 | `96375a23cb2cc496e61929b6a16437afe7056064` |
| SHA-256 | `46b70348d87262640dd2510b0b6c2d0d9ba9ea1de135c7112405fdf7d08a7efd` |
| SHA3-384 | `df0a8fa0d93e075882b3027c38a678f99fb8fad8ca37364d87e8d31099bb611abf1c10e474dad5abb7d5883b9dc03199` |
| IMPHASH | `46ce5c12b293febbeb513b196aa7f843` |
| TLSH | `T1E0E512201E494D6EFC664CF1C97133E22D98CE9763E4AA16EE6B3C89376744C47EA407` |
| SSDEEP | `49152:XZtA/h+zFSb4V4Xx6Usnj4vYgkqGM6kUSSFvXPPWzJE7ydBqR1MlkNkW:XRh84eXx3YgmM6fSJE7yPqrcikW` |
| ICON-DHASH | `0f3363494d490707` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_46b70348
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46b70348d87262640dd2510b0b6c2d0d9ba9ea1de135c7112405fdf7d08a7efd"
    family = "unknown"
    file_name = "SecuriteInfo.com.W32.ABTrojan.RBQK-4720.4321.29656"
    file_type = "exe"
    first_seen = "2026-07-23 00:48:41"
  condition:
    hash.sha256(0, filesize) == "46b70348d87262640dd2510b0b6c2d0d9ba9ea1de135c7112405fdf7d08a7efd"
}
```

### Sample 57: `84615c4dc89944b6`

| Field | Value |
|---|---|
| SHA-256 | `84615c4dc89944b6f365616ef685ff669bf04a1ef6ccf5e2ac29058a27e94177` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-23 00:48:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee970c2a2064411e99c9770a42e8beff` |
| SHA-1 | `57553abaf579e29bdbd2d5a8ce910073249096c8` |
| SHA-256 | `84615c4dc89944b6f365616ef685ff669bf04a1ef6ccf5e2ac29058a27e94177` |
| SHA3-384 | `8795d76b875e959f397e852ddd3df0e98cf7655e35fe6db0272fbf4f078bd20c464773bb31221c3b0c29e1c9a06a679c` |
| TLSH | `T120C32955BC829A12C6C21677FF5EB2CD371733A8E3EA7117DE249F25338B51A0E2A141` |
| SSDEEP | `1536:+pmbMfFIEzNOqgXxc4ASQQSC78AfCOTyXimCEKQUV8KY8L7pyVhq91vOHd9g5OA5:LMtIsNOq6h78AfCmEZU2q91GHbZR+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_84615c4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84615c4dc89944b6f365616ef685ff669bf04a1ef6ccf5e2ac29058a27e94177"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-23 00:48:26"
  condition:
    hash.sha256(0, filesize) == "84615c4dc89944b6f365616ef685ff669bf04a1ef6ccf5e2ac29058a27e94177"
}
```

### Sample 58: `333774e3405c4e6e`

| Field | Value |
|---|---|
| SHA-256 | `333774e3405c4e6ef3a663bb7fe5e9074f03a6c8bb080e0ff3bcc33eec848b30` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-23 00:43:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1b904203adeb396898e8db646bf21ee` |
| SHA-1 | `320001ad37921d1d470aaa7b43254b12e4dc1b09` |
| SHA-256 | `333774e3405c4e6ef3a663bb7fe5e9074f03a6c8bb080e0ff3bcc33eec848b30` |
| SHA3-384 | `a250660f6441f4419495a7019213ac6e9f4f3fd632889223455f459efa6c1a13109d3b4e771ede99f15354302ca0eec8` |
| TLSH | `T1FAB36C86D743D0F1EC164571243BA3678A35E9360139EF86DBE52E33AC22F019A1BB5D` |
| TELFHASH | `t1d45168f96e761decb7409c06f2ce1b52de0eaa7b143076f505b354a132e719152bac38` |
| SSDEEP | `1536:UXhfBtC39Efu2D5eQfoqz1nKicUq0jqz25Csit0nyYAnEtBmrIXp9yp:eBtCNE9fdpKiU0jH5fitEFAKXy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_333774e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "333774e3405c4e6ef3a663bb7fe5e9074f03a6c8bb080e0ff3bcc33eec848b30"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-23 00:43:32"
  condition:
    hash.sha256(0, filesize) == "333774e3405c4e6ef3a663bb7fe5e9074f03a6c8bb080e0ff3bcc33eec848b30"
}
```

### Sample 59: `1d0a74bde7856d5e`

| Field | Value |
|---|---|
| SHA-256 | `1d0a74bde7856d5e18170590fd2424281001c93833940de6f95dbba1028f57cc` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-23 00:22:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d19d638620d9c13b9d382f0a3261fda6` |
| SHA-1 | `3a01f77c3717e9bfd15c01b0e61eb6bfa54b650a` |
| SHA-256 | `1d0a74bde7856d5e18170590fd2424281001c93833940de6f95dbba1028f57cc` |
| SHA3-384 | `3e96af6958887894c56143e19b38351bc7ff4eb46d7fd1b932e703023a9178b130f953dc3ca6d4a57210918a4d4df1ca` |
| TLSH | `T1B1C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:us8vCB+25j6es8Rg9FYpMSUpi+20qUpi+20YQX:Z8l25Jmd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_1d0a74bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d0a74bde7856d5e18170590fd2424281001c93833940de6f95dbba1028f57cc"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-23 00:22:37"
  condition:
    hash.sha256(0, filesize) == "1d0a74bde7856d5e18170590fd2424281001c93833940de6f95dbba1028f57cc"
}
```

### Sample 60: `7ce8cf71a2111e1e`

| Field | Value |
|---|---|
| SHA-256 | `7ce8cf71a2111e1ebdf8f09565fc2716d84cd5be4d79fc2dc5970454d392df8b` |
| Family label | `Gafgyt` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-23 00:21:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a957b1fae69d4d8f1266a2f86242df92` |
| SHA-1 | `fe37828b1347fcf1c5c5eeb62a3d1e29bfaebcb4` |
| SHA-256 | `7ce8cf71a2111e1ebdf8f09565fc2716d84cd5be4d79fc2dc5970454d392df8b` |
| SHA3-384 | `5c0046cdf924840834defd2afe96807a03d6865e657b22c66225c3cec64a399ba3f304995f0e8f6aeef67ffc6ecb6e96` |
| TLSH | `T1FBF3C51E6E118F7DF668C7344BF77E21929832D726E1C645D2ACD5111E2038EA81FBA8` |
| TELFHASH | `t13b21b01c497423e4a7711c9d26deef77e5a170df0a362d378e01e8a9aa7dd42ad00c1c` |
| SSDEEP | `3072:Zq0Z/3hk1fpEo6DF/XNEDGH2PkjIjJ1iwC6L:Zq0Zhk1fT6DFfNEDGEkkjJrZL` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_060_7ce8cf71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ce8cf71a2111e1ebdf8f09565fc2716d84cd5be4d79fc2dc5970454d392df8b"
    family = "Gafgyt"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-23 00:21:21"
  condition:
    hash.sha256(0, filesize) == "7ce8cf71a2111e1ebdf8f09565fc2716d84cd5be4d79fc2dc5970454d392df8b"
}
```

### Sample 61: `060040eb137e800b`

| Field | Value |
|---|---|
| SHA-256 | `060040eb137e800b59b39b16978531d123bc6555da3b24fb7c3687e1cacf7a07` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-23 00:16:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c87fbde638c92ae00d4d87839e68ac0c` |
| SHA-1 | `07b94e23416d3ee45a3b2a4e0d8866b4063f0a26` |
| SHA-256 | `060040eb137e800b59b39b16978531d123bc6555da3b24fb7c3687e1cacf7a07` |
| SHA3-384 | `7d5f3900d1d59b97e50e69c5e5e4939224476b3a5732fea3ae11a8b48ec78703e1fdb4f11893ccf29fff13aceef617c9` |
| TLSH | `T16DC32855BC829A12C6C22677FB5EB2CD771733A8E3EE7117CE245F21338B51A0E2A541` |
| SSDEEP | `1536:Jb17gxFIEJNOmfoxc4yyQSCLGRhCG6yTUmjU8qCz8KY8LVQyRhH/9vciC3g5Od7I:PgzIeNOmv3LGRhCiUpCnH/9Eia/fzo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_060040eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "060040eb137e800b59b39b16978531d123bc6555da3b24fb7c3687e1cacf7a07"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-23 00:16:32"
  condition:
    hash.sha256(0, filesize) == "060040eb137e800b59b39b16978531d123bc6555da3b24fb7c3687e1cacf7a07"
}
```

### Sample 62: `5872ee7715810307`

| Field | Value |
|---|---|
| SHA-256 | `5872ee77158103070ee4c63ecad9577e6aafe73a6c512aa94e83b0ddaac0fe15` |
| Family label | `Mirai` |
| File name | `sora.arm7` |
| File type | `elf` |
| First seen | `2026-07-23 00:16:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da58972b9147b70ab2c9abe17bd80277` |
| SHA-1 | `bbf61cfcdbb182c48d1e3f983a02831b2ef2cb21` |
| SHA-256 | `5872ee77158103070ee4c63ecad9577e6aafe73a6c512aa94e83b0ddaac0fe15` |
| SHA3-384 | `f5389d124dfbaeaf7b68ce0a00277cfce4e0e58f76e6b10641f551c0f8fec9fc82bf9756c36a797a0e8189c7508a57f0` |
| TLSH | `T127E32B46F6418A13C5D61777FAAF41493322D794A3DB330699285FF43F86A9F0E23A06` |
| TELFHASH | `t1b4219bb1572aa6245969cbec89dc73b9122c86121247df33ef2184bca41949df525c4f` |
| SSDEEP | `3072:FYvMxqixyDJAmUzdBJXu9WRtotmLFQTihvGX0clM/9h4b/kP:yvMxqixyDJAmUzUSotmLFuiYX0aM/9KO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_5872ee77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5872ee77158103070ee4c63ecad9577e6aafe73a6c512aa94e83b0ddaac0fe15"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-07-23 00:16:05"
  condition:
    hash.sha256(0, filesize) == "5872ee77158103070ee4c63ecad9577e6aafe73a6c512aa94e83b0ddaac0fe15"
}
```

### Sample 63: `5f37ff54ed0a5cd7`

| Field | Value |
|---|---|
| SHA-256 | `5f37ff54ed0a5cd7c83423fc801cd3594d8d266a75f449e44ef8b5dc08de61d7` |
| Family label | `Mirai` |
| File name | `sora.arm7` |
| File type | `elf` |
| First seen | `2026-07-23 00:15:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5d910f73d913491c9c542c6bf013a24` |
| SHA-1 | `1e638082beb4918869e0f19d8c56753631cb6148` |
| SHA-256 | `5f37ff54ed0a5cd7c83423fc801cd3594d8d266a75f449e44ef8b5dc08de61d7` |
| SHA3-384 | `d0950cd595d87bdeebea0dfb8241966969e6444ab24510245dbde75f78bef7392fc196c9734aaf60033d5a373b747c18` |
| TLSH | `T17B33F1BA42AB9D71C1B052B71629549D64162738E3F5F00367224470EACB1F35AFE7C3` |
| SSDEEP | `1536:3CoqsGR4eB3g0Vmh1IxIpC8J3/L9VE8amFZP7R3M:Soqs2Twh6P8JPLJ9ZP7R3M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_5f37ff54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f37ff54ed0a5cd7c83423fc801cd3594d8d266a75f449e44ef8b5dc08de61d7"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-07-23 00:15:15"
  condition:
    hash.sha256(0, filesize) == "5f37ff54ed0a5cd7c83423fc801cd3594d8d266a75f449e44ef8b5dc08de61d7"
}
```

### Sample 64: `a73dce30c9734e4a`

| Field | Value |
|---|---|
| SHA-256 | `a73dce30c9734e4a8e4baef959ba91d0759c05450fcd1993f4e9fc0d45142f42` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-23 00:09:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbbb904e2efb76fe21b7e1b8345dcb6b` |
| SHA-1 | `e7a5012a1d4e41e90b3142cd8a52af589d4f18c3` |
| SHA-256 | `a73dce30c9734e4a8e4baef959ba91d0759c05450fcd1993f4e9fc0d45142f42` |
| SHA3-384 | `3e95b6d03699bd404d8de09d76b325411859e58d0ad2e036720e016dc2b19ca2de648ffb8fffb3905c934517b4b81881` |
| TLSH | `T1D2B36BC1E787D4B0F8560671013BB7564A72F93641F8EF86DBA92D32EC23A119A1B35C` |
| TELFHASH | `t1c1512eb96f760cdcb780ac05e34e5791ae0da77b217472f744f2682532e298152bbc38` |
| SSDEEP | `1536:Aa1CzmmCh3CdlcF+VhUumDSBz1lriBPbBwlsgW1/60Nsc9Klx/UiG/OgHrj4M0:M5CQly+D5/ridbBm81/9CcgP/I22u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_a73dce30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a73dce30c9734e4a8e4baef959ba91d0759c05450fcd1993f4e9fc0d45142f42"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-23 00:09:33"
  condition:
    hash.sha256(0, filesize) == "a73dce30c9734e4a8e4baef959ba91d0759c05450fcd1993f4e9fc0d45142f42"
}
```

### Sample 65: `631be62897d57f07`

| Field | Value |
|---|---|
| SHA-256 | `631be62897d57f0740349269a3eb588ecdd2e89bf367b34421ddaaa200ec2711` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-23 00:08:19` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ead70a5038dbd355cbcb8213889bbc62` |
| SHA-1 | `af46db4ed7e1aaba292b25d5b4e22aeaeb321061` |
| SHA-256 | `631be62897d57f0740349269a3eb588ecdd2e89bf367b34421ddaaa200ec2711` |
| SHA3-384 | `59964bdbaabcd1e2ffe6710b48149e69447965d97f3d50fa703fae5eab774075151a0211715714eda75cdb454355ab16` |
| TLSH | `T1DFE39FA8EB4F6D42D2C3E3BEAD593FB3312738B041D5D2B64D00954DE9DAED48CA1522` |
| SSDEEP | `3072:1fqyddj3WZaXTn1aw58147s01BZv4R+uWg3BS+P363KhRW6:1XjmZs1B58+7s0p4R+g3BX3QKv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_631be628
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "631be62897d57f0740349269a3eb588ecdd2e89bf367b34421ddaaa200ec2711"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-23 00:08:19"
  condition:
    hash.sha256(0, filesize) == "631be62897d57f0740349269a3eb588ecdd2e89bf367b34421ddaaa200ec2711"
}
```

### Sample 66: `392571c5abe8c58b`

| Field | Value |
|---|---|
| SHA-256 | `392571c5abe8c58b631fd44b1c2924f7854914754848cb2479ec6889ebce6b4c` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-22 23:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c27853c766cd4c75f096f9743f73b346` |
| SHA-1 | `b37211397a942956f5e79712f7870c5a33b66cc0` |
| SHA-256 | `392571c5abe8c58b631fd44b1c2924f7854914754848cb2479ec6889ebce6b4c` |
| SHA3-384 | `d266b407d48b87b61f74787da1adaef3a31525d95c592d8e63979d388c7e9c5e4842704f4bd6472df5bb893a29cbbc91` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T127E63349EAD102FFE7A7413CEDE151A1E5AB74610732CAE747A493D1BF272C09839A13` |
| SSDEEP | `393216:pqUhd6PX+V0uHPUOGUN37Ez8XMCHWUjXZcuI3/PGTAI:pl6PX+V00UOGqrQ8XMb8XuH/O7` |
| ICON-DHASH | `f0f8dca68ac6f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_392571c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "392571c5abe8c58b631fd44b1c2924f7854914754848cb2479ec6889ebce6b4c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-22 23:52:09"
  condition:
    hash.sha256(0, filesize) == "392571c5abe8c58b631fd44b1c2924f7854914754848cb2479ec6889ebce6b4c"
}
```

### Sample 67: `9bbb4b428b34a0ce`

| Field | Value |
|---|---|
| SHA-256 | `9bbb4b428b34a0ce31da7183bf4a20f48a5a5639d4acf7afb7bd1d0a4205e098` |
| Family label | `unknown` |
| File name | `63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e` |
| File type | `elf` |
| First seen | `2026-07-22 23:31:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed234e65a87f7ecd03727981c841bbfa` |
| SHA-1 | `91dc840927011260b243ad7619bf63d65293ac21` |
| SHA-256 | `9bbb4b428b34a0ce31da7183bf4a20f48a5a5639d4acf7afb7bd1d0a4205e098` |
| SHA3-384 | `d92333a7ebe090fa342bd127c4ae5b31219f4061b2f853d0070d3e6cdf6b0931e0603aedb6c550703461ca9d88b38acb` |
| TLSH | `T1E2366D4BF1A324FCC19BC434875B99A2B935786901247DBB66C4EE302E33F605B59F62` |
| TELFHASH | `t1f6723ff062e434e1a096c95aebb6f4b0d53718bb07d5b6b18437bc63cf64f480d6a812` |
| SSDEEP | `98304:+jbh6zwjVQMJwkLH3M9YmbOB/KvDVaNOKbKz3naV8qOH+8gLJ:+jGw1yY4OBQ33ae2V` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_9bbb4b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bbb4b428b34a0ce31da7183bf4a20f48a5a5639d4acf7afb7bd1d0a4205e098"
    family = "unknown"
    file_name = "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:48"
  condition:
    hash.sha256(0, filesize) == "9bbb4b428b34a0ce31da7183bf4a20f48a5a5639d4acf7afb7bd1d0a4205e098"
}
```

### Sample 68: `161fb327ee8679b3`

| Field | Value |
|---|---|
| SHA-256 | `161fb327ee8679b318533e925b958e2c8ff32dd32afc15be3f426a6c5a21c83e` |
| Family label | `unknown` |
| File name | `b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a` |
| File type | `elf` |
| First seen | `2026-07-22 23:31:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b776f99c3a7e91e18dfdee62b291bac6` |
| SHA-1 | `80a23153c61b0db60a5da7307de73bd9c15cbbcf` |
| SHA-256 | `161fb327ee8679b318533e925b958e2c8ff32dd32afc15be3f426a6c5a21c83e` |
| SHA3-384 | `96d03a1ccbea5350b8e79cbd05932c52d008790d90e6692e4b2dd27c646a78eece126b6f47cbb789bc1aeb7533e1b81c` |
| TLSH | `T19C367C88E793E0F4E25308F0599BD7F761201A355053F6F2EF8A6E65B4327416F093AA` |
| TELFHASH | `t14282a1b305d894f977f04407c3af7128cfa6e0e726d029f166f56ce156b2c82a626d78` |
| SSDEEP | `98304:DGesR9kNAQAM6nLKMZqpJuEh3cgF2T5HLlPdotgBU8f9zSA3j5Qn:DGN3kNMn+MZYHyLIu8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_161fb327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "161fb327ee8679b318533e925b958e2c8ff32dd32afc15be3f426a6c5a21c83e"
    family = "unknown"
    file_name = "b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:43"
  condition:
    hash.sha256(0, filesize) == "161fb327ee8679b318533e925b958e2c8ff32dd32afc15be3f426a6c5a21c83e"
}
```

### Sample 69: `1cf2f74bf9248cad`

| Field | Value |
|---|---|
| SHA-256 | `1cf2f74bf9248cad396a233af682232e9c4bd9a4df068db3847ed43dcb543e0a` |
| Family label | `unknown` |
| File name | `3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e` |
| File type | `elf` |
| First seen | `2026-07-22 23:31:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3d7accbdf6ab432a1c6d0a101253904` |
| SHA-1 | `b0acba759a78a76068ed26a520bf07bca93097c4` |
| SHA-256 | `1cf2f74bf9248cad396a233af682232e9c4bd9a4df068db3847ed43dcb543e0a` |
| SHA3-384 | `639ee6b0fcd5e5bfc582475b05d1d1b10ca42c42d56f2f493041f73ad577f9eb3c81f0e46f4ad4a2f5b4d25ffe1f0868` |
| TLSH | `T1A4168C95ED0F3912F3C7E23CCF4A97E1721735A4E32390B279D2524DD19E9E4CAA2A11` |
| SSDEEP | `98304:qog8R9w6Sl7rFlI+QHUMJfxvWbD/5Pj+4Fk5vv:Rg8R9wV5xNM2LV7Wv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_1cf2f74b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cf2f74bf9248cad396a233af682232e9c4bd9a4df068db3847ed43dcb543e0a"
    family = "unknown"
    file_name = "3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:38"
  condition:
    hash.sha256(0, filesize) == "1cf2f74bf9248cad396a233af682232e9c4bd9a4df068db3847ed43dcb543e0a"
}
```

### Sample 70: `a8b6f96c0e23b700`

| Field | Value |
|---|---|
| SHA-256 | `a8b6f96c0e23b700f97b4104142d75888b2dd2f91d00119810be625958485046` |
| Family label | `unknown` |
| File name | `efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2` |
| File type | `elf` |
| First seen | `2026-07-22 23:31:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6d3283d9bcb36f9a44e0f8b3a14f8d5` |
| SHA-1 | `2c7f9edd1dae4ccc51e203861e7b30085a7cb35a` |
| SHA-256 | `a8b6f96c0e23b700f97b4104142d75888b2dd2f91d00119810be625958485046` |
| SHA3-384 | `a2a65c7cb60e733d6552fecf37d6f6d56f1c32426048fa8222c08f48754055c175118bf7eef5e459f2a6263731941e2a` |
| TLSH | `T10E065C81FC41CF52C9D03A7AF66E828833530779C2EA70099D255B7467DF99B0F3AA52` |
| TELFHASH | `t1ba31f0994e5956fcf2ea999484ef74b9d2fd3dec2b1086a58dd4ea2f6a031c1308140b` |
| SSDEEP | `49152:6FG29jovKdP68uEYsejO9ZvfwFuha4ChU5O/JQpp6:oG27dP4NseiTINhU5ORQpp6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_a8b6f96c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8b6f96c0e23b700f97b4104142d75888b2dd2f91d00119810be625958485046"
    family = "unknown"
    file_name = "efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:33"
  condition:
    hash.sha256(0, filesize) == "a8b6f96c0e23b700f97b4104142d75888b2dd2f91d00119810be625958485046"
}
```

### Sample 71: `63be5f38b520b314`

| Field | Value |
|---|---|
| SHA-256 | `63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e` |
| Family label | `unknown` |
| File name | `63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e` |
| File type | `elf` |
| First seen | `2026-07-22 23:31:19` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c22b2bb85a8e54abfac289f336c24444` |
| SHA-1 | `e47f86d4c08c0674d5315ffdde3e0defc8a4d801` |
| SHA-256 | `63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e` |
| SHA3-384 | `d3d91e4755f3bf03a9cf4971dba165f20350b2bba5a6ab3acbcdfa3952ba44188dd62bda43ba90032ab68e01edfd7c1b` |
| TLSH | `T110953341E03EF59A5411CC9FB74E8E9E1A34306F162EC1460E43EF1E841ADBDEEA9B15` |
| SSDEEP | `49152:1jTI4Rq1eufIidTa+vTISMkJDiJjUE3zE7YhUfQyRq:hoIgTaYTxz+qQyk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_63be5f38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e"
    family = "unknown"
    file_name = "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:19"
  condition:
    hash.sha256(0, filesize) == "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e"
}
```

### Sample 72: `e2bc7981064d3c9e`

| Field | Value |
|---|---|
| SHA-256 | `e2bc7981064d3c9ed898a0f62d659fdc2fc9646dee47a9ca92b9b28b96c27a3b` |
| Family label | `unknown` |
| File name | `e2bc7981064d3c9ed898a0f62d659fdc2fc9646dee47a9ca92b9b28b96c27a3b` |
| File type | `elf` |
| First seen | `2026-07-22 23:31:17` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cdad2d6ad1e55967121ed478bca8243` |
| SHA-1 | `872d7fe3362ae01cfc4430c78f89abae58df6713` |
| SHA-256 | `e2bc7981064d3c9ed898a0f62d659fdc2fc9646dee47a9ca92b9b28b96c27a3b` |
| SHA3-384 | `06b689fdc5d304da1cec0423bad6c7c1a24c6fb8789a3d3a58e9428a341dea724575a92fd55438099b8b75e93ed4798a` |
| TLSH | `T129853376C5647C4AAC4A907DBAF39ED3E3C2C04675186991AB707ACD93A80464E373F3` |
| SSDEEP | `24576:5SMoXbJ4prFSdP1w0OJX9ENKTxeGfL7oYPUZ7uPxskPdXZs4qs14sYkj5cT:ToXGVFkROVagTxSW46SkPdXZTqs14Zq4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_e2bc7981
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2bc7981064d3c9ed898a0f62d659fdc2fc9646dee47a9ca92b9b28b96c27a3b"
    family = "unknown"
    file_name = "e2bc7981064d3c9ed898a0f62d659fdc2fc9646dee47a9ca92b9b28b96c27a3b"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:17"
  condition:
    hash.sha256(0, filesize) == "e2bc7981064d3c9ed898a0f62d659fdc2fc9646dee47a9ca92b9b28b96c27a3b"
}
```

### Sample 73: `b3232d2cd03b051c`

| Field | Value |
|---|---|
| SHA-256 | `b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a` |
| Family label | `unknown` |
| File name | `b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a` |
| File type | `elf` |
| First seen | `2026-07-22 23:31:16` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2eca70f82a952805ab7c2cf79578223` |
| SHA-1 | `84e08fe68fd905b6032d206c33af1e351e1ee73b` |
| SHA-256 | `b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a` |
| SHA3-384 | `fad85361e6cf03a210b16895c6c20dd48e5b28c41f07f45db168af6f238c8db6a4bfe5cde7693a2fca1a7cfd309b11a6` |
| TLSH | `T109853306827ABFD99761F4B0D07B4A297F26DDE4806471A4BD942DF1C2FBE89039B0D4` |
| TELFHASH | `t166b0110023022cc20bfeea882a00bce202022838030a383e00a3c00cc0a202b0c0020e` |
| SSDEEP | `49152:9omBNlGJqFRSu1+Nz5wPg0ZpYHVIJYukcwS6qKCx:vG04g4z5J0ZpYLbcv6q3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_b3232d2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a"
    family = "unknown"
    file_name = "b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:16"
  condition:
    hash.sha256(0, filesize) == "b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a"
}
```

### Sample 74: `3edfb02c0e6b2fe4`

| Field | Value |
|---|---|
| SHA-256 | `3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e` |
| Family label | `unknown` |
| File name | `3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e` |
| File type | `elf` |
| First seen | `2026-07-22 23:31:15` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1383532c32f7ff9655428c9ab91018b4` |
| SHA-1 | `1d8d4703a4cdde85bef57582b15599c9f9cc4718` |
| SHA-256 | `3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e` |
| SHA3-384 | `819442d34ba64512466862e7fbb5bd72a07291585c629341dddd76ec1c1cf984d244beefd1c88b47be7fe71e1ece16c7` |
| TLSH | `T174753392B4C1BC38641605AF4378437C15B82C59ADA1C3A4B1A95AFB3D93A30CADDFD6` |
| SSDEEP | `49152:h8zhvElbdD+IHxGFdVB0hW3g9zrXdP+pLN/biA49PQyVkgS:8vi0dVKhW3cr9+pNH4YgS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_3edfb02c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e"
    family = "unknown"
    file_name = "3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:15"
  condition:
    hash.sha256(0, filesize) == "3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e"
}
```

### Sample 75: `efa731b59f9e2f27`

| Field | Value |
|---|---|
| SHA-256 | `efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2` |
| Family label | `unknown` |
| File name | `efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2` |
| File type | `elf` |
| First seen | `2026-07-22 23:31:13` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f65de2728c489ebec26fe37afbcb9b1e` |
| SHA-1 | `2c1775ee86fa501ef87c7bc14aa849b1716f61ab` |
| SHA-256 | `efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2` |
| SHA3-384 | `eafa0bb8dfd574c2340ea7314a4172a8611e400901a81f256be683ff313728ec9697370d6c2fd35ef914b2982e94e693` |
| TLSH | `T1A165338C02969A7AC27B43F3FD6F4096A5997709FF41F7C3CA2684584DC7E62D881AD0` |
| SSDEEP | `24576:xSAQa9HmfTcRtRRWI+ZDTL9BYBGwevXs/9VYk3covvUq1kPbJY9yjFLqtVKVYeYn:3Qa9H8cXoDvrYBGwxVAobmbJY9WW/K6F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_efa731b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2"
    family = "unknown"
    file_name = "efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:13"
  condition:
    hash.sha256(0, filesize) == "efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2"
}
```

### Sample 76: `e149f36cb6c001aa`

| Field | Value |
|---|---|
| SHA-256 | `e149f36cb6c001aa340c388d7684c8a055f59152026e8e0d1d678264d7c084d7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 22:38:50` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `991f897750ebdb9bf7104ffe4cf3faaf` |
| SHA-1 | `8499f094477c8474c2550929c8fcba3bea310e2b` |
| SHA-256 | `e149f36cb6c001aa340c388d7684c8a055f59152026e8e0d1d678264d7c084d7` |
| SHA3-384 | `223864b4e603e9e0853664976b9961e6162fffd528e875d61831837dfff4dc4df3d18f24c9f85473a130acd566184270` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17796E112EEC508F6D158E2318AE592AA3672BC15AB3117F72A15367C3FB2FE01D76344` |
| SSDEEP | `196608:3wYTW6kTnDWQGAc0CE70GFy/fkl5Mt9TYdBGhN:3xCVzDYuCO0GFy/06YBk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_e149f36c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e149f36cb6c001aa340c388d7684c8a055f59152026e8e0d1d678264d7c084d7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 22:38:50"
  condition:
    hash.sha256(0, filesize) == "e149f36cb6c001aa340c388d7684c8a055f59152026e8e0d1d678264d7c084d7"
}
```

### Sample 77: `1d233362395405a1`

| Field | Value |
|---|---|
| SHA-256 | `1d233362395405a19be5da8fc1f3fba060e658fb30718a47eedc0925a7226e52` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 22:33:39` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7564553469f8675a41cb1ee014b3dfdd` |
| SHA-1 | `4bf5f76757cdf2280df61f970246222aa0b8f8a8` |
| SHA-256 | `1d233362395405a19be5da8fc1f3fba060e658fb30718a47eedc0925a7226e52` |
| SHA3-384 | `1a1470cf1efa05229f9b222ee0d21bbdafab05c176b70390869e2bcd9fb15c67581a9408ffc9f80930ea3dab3a0249e7` |
| IMPHASH | `d10fc36a7f00b607f09003d3da0040cc` |
| TLSH | `T105E52326738501F5D4AAC5BCC2420752BB2674DAE7A29EFF0374C1741F166EA6E3C728` |
| SSDEEP | `49152:lgpyi7hTuUtEcTuu4XG0nBZYnavokJJaRsj4TEwUCNfgBw9:I/dNuuQnBZ0S+REwVI` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_077_1d233362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d233362395405a19be5da8fc1f3fba060e658fb30718a47eedc0925a7226e52"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 22:33:39"
  condition:
    hash.sha256(0, filesize) == "1d233362395405a19be5da8fc1f3fba060e658fb30718a47eedc0925a7226e52"
}
```

### Sample 78: `4e96f12945b9f213`

| Field | Value |
|---|---|
| SHA-256 | `4e96f12945b9f21345137e7873cf6ef06e64baf5d73469e8b7db7c083479bd17` |
| Family label | `Mirai` |
| File name | `sora.mpsl` |
| File type | `elf` |
| First seen | `2026-07-22 22:05:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5bf617e06722cb363ec2b5b53b967fb` |
| SHA-1 | `f8042e7078b3334f2ec1b3620764b3fe8d733e40` |
| SHA-256 | `4e96f12945b9f21345137e7873cf6ef06e64baf5d73469e8b7db7c083479bd17` |
| SHA3-384 | `817d015467615d9658ff4991482e99835efab72cd6b9341e0483940d1ad29c43ec0c20ff9df585556a2a82283d5ff254` |
| TLSH | `T1B793D706BF610FF7DC9BDC3705A92B05289C665A31A97B35BA30D818F64B21F19E3C64` |
| SSDEEP | `1536:NF2GXYZ8a8fnwEvLNPENIdhs9WZx0ZCufqIhK:NFjXYyCEx0NhK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_4e96f129
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e96f12945b9f21345137e7873cf6ef06e64baf5d73469e8b7db7c083479bd17"
    family = "Mirai"
    file_name = "sora.mpsl"
    file_type = "elf"
    first_seen = "2026-07-22 22:05:14"
  condition:
    hash.sha256(0, filesize) == "4e96f12945b9f21345137e7873cf6ef06e64baf5d73469e8b7db7c083479bd17"
}
```

### Sample 79: `315130dbde6535e5`

| Field | Value |
|---|---|
| SHA-256 | `315130dbde6535e561ede03e614340a5bf1ce0a1ca83f89c1a65e8594c1af657` |
| Family label | `Mirai` |
| File name | `sora.arm6` |
| File type | `elf` |
| First seen | `2026-07-22 22:05:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fb89b83c275e07d01a74b238850dd1a` |
| SHA-1 | `0b39866c491389d0ec8bab7eaf6b642737ad2443` |
| SHA-256 | `315130dbde6535e561ede03e614340a5bf1ce0a1ca83f89c1a65e8594c1af657` |
| SHA3-384 | `cfffad67ed09433d5084708a61ecd63b7cf535fce6c4431b858e7f3d1df379d27875c73388a4fcca03ec1c375ef70961` |
| TLSH | `T1C3730A85B9819B25C6D513BBF91F018E331657E8E3DE73129D201F607BCA91B0E27E4A` |
| TELFHASH | `t181f081c90b7846fa37f56b598aad5149acf534fd7f155c17648d734e11120c1706b400` |
| SSDEEP | `1536:q9KnGSGYfkiu/ZwQNCJEHQXglNU6bO3d5yAMw1f91uwcWIWinluUsPMrQ:CEkiUZJNZHKMNU6ba4XwtsluUsPMk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_315130db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "315130dbde6535e561ede03e614340a5bf1ce0a1ca83f89c1a65e8594c1af657"
    family = "Mirai"
    file_name = "sora.arm6"
    file_type = "elf"
    first_seen = "2026-07-22 22:05:07"
  condition:
    hash.sha256(0, filesize) == "315130dbde6535e561ede03e614340a5bf1ce0a1ca83f89c1a65e8594c1af657"
}
```

### Sample 80: `751a620ac5101f69`

| Field | Value |
|---|---|
| SHA-256 | `751a620ac5101f69eb6e3d208eb4ab08cdcf18092d88b2717dfa975e05b88e2f` |
| Family label | `Mirai` |
| File name | `sora.arm` |
| File type | `elf` |
| First seen | `2026-07-22 22:05:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da0b213106d0974cda5ba481a8148167` |
| SHA-1 | `6f18f1f3ae1af9121d2130cce920f466c6eddb78` |
| SHA-256 | `751a620ac5101f69eb6e3d208eb4ab08cdcf18092d88b2717dfa975e05b88e2f` |
| SHA3-384 | `0c743f64e0d09be4cdfcdc6e7aae034e43e42137a0404e897e61d4b8a75a359b6bfcb3660f00f3d0ed4deecf50d0e1eb` |
| TLSH | `T1C2630891B881A626C2D1137BFA6F008E372457D8E2DB33139D255FA0778A81F0D57F8A` |
| TELFHASH | `t14a41d1f74ba40bcc67e8a149c98c711c5ff5b05aaf092483590caa4fc85b5d2b00e437` |
| SSDEEP | `1536:eOTgWIYeMlktkUwnEU0+m7FcWS2RM8fhWtu5zPeH:eOTgWLeMDcJS2Rrpeu5K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_751a620a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "751a620ac5101f69eb6e3d208eb4ab08cdcf18092d88b2717dfa975e05b88e2f"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-07-22 22:05:00"
  condition:
    hash.sha256(0, filesize) == "751a620ac5101f69eb6e3d208eb4ab08cdcf18092d88b2717dfa975e05b88e2f"
}
```

### Sample 81: `ebcdaa839b26cc9a`

| Field | Value |
|---|---|
| SHA-256 | `ebcdaa839b26cc9a2777e6b481e977a77ef77117288fa74b5777a5e9b7f1354a` |
| Family label | `Mirai` |
| File name | `sora.mips` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65f3b1e29756c0bbf9ff50a7f32da34f` |
| SHA-1 | `100af46d32a5efc763c6de92b648c63fb75befd1` |
| SHA-256 | `ebcdaa839b26cc9a2777e6b481e977a77ef77117288fa74b5777a5e9b7f1354a` |
| SHA3-384 | `eab5383e264b32d5c31d56c0ef7b0daba6fd5e4532badccdde312775d1fb967565e5b7dabb969c21fb257473170284b0` |
| TLSH | `T16C83C6297E218FBEF79D823947B78F22964837C637E1D581D15CDA005E7028E641BFA8` |
| TELFHASH | `t175014948893c57f0d7665ddc6bddff76e05260cf49615e778e00b9aa9b6c9428e00c1c` |
| SSDEEP | `1536:E6/iw/0w8HoQ5uy8NxqlcJ0vXxh11xYqcn6BZOpkMoArgR:x/8RHTgMcJ0fmqJZOpkM/sR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_ebcdaa83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebcdaa839b26cc9a2777e6b481e977a77ef77117288fa74b5777a5e9b7f1354a"
    family = "Mirai"
    file_name = "sora.mips"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:57"
  condition:
    hash.sha256(0, filesize) == "ebcdaa839b26cc9a2777e6b481e977a77ef77117288fa74b5777a5e9b7f1354a"
}
```

### Sample 82: `2f15c07433d268f5`

| Field | Value |
|---|---|
| SHA-256 | `2f15c07433d268f50a0e9ba7aa41dfa5f0fd4eeca03b77ab00c222bea1e6f73c` |
| Family label | `Mirai` |
| File name | `sora.x86` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `856e6f37b2093319b4ec27b8f5dbae84` |
| SHA-1 | `9f24921d2fdcf6f96ccd24cdf20a89a9ff12a1d9` |
| SHA-256 | `2f15c07433d268f50a0e9ba7aa41dfa5f0fd4eeca03b77ab00c222bea1e6f73c` |
| SHA3-384 | `926f2b9661be08ed5ac1612c90c0b047aa4878cabd26a449c2bd2862dfa2473f20e007d53cd1b8666efcfc435f8566f0` |
| TLSH | `T16C4349C4B183F9F1DC05017C306AEB326E33F0B6713AED9BD7E455B3A855606960AA9C` |
| TELFHASH | `t1ae11e9fa1a7f18ecfbd8a180c29daf125d5ee13b15d133a45522a9292293c81517ecb8` |
| SSDEEP | `1536:MOssuiundFq4ZthwLi/pXUfx0WbVGoPCdgZl7dbFfGa:xzuXndFq4ZthB/VUfOWhGoPKgj7dpOa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_2f15c074
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f15c07433d268f50a0e9ba7aa41dfa5f0fd4eeca03b77ab00c222bea1e6f73c"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:53"
  condition:
    hash.sha256(0, filesize) == "2f15c07433d268f50a0e9ba7aa41dfa5f0fd4eeca03b77ab00c222bea1e6f73c"
}
```

### Sample 83: `e596320b1d716908`

| Field | Value |
|---|---|
| SHA-256 | `e596320b1d716908045f377f843d5c0c3fadb2dc145d3732f83f8acbf1c2297c` |
| Family label | `Mirai` |
| File name | `sora.arm5` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `625b2fa9f7d3e06966d1bc662384aae5` |
| SHA-1 | `1cd435882b7f298c01dafab1742ae90d425988bf` |
| SHA-256 | `e596320b1d716908045f377f843d5c0c3fadb2dc145d3732f83f8acbf1c2297c` |
| SHA3-384 | `fb743ea6e8c3194d1ec850e0e4412afa7b8230f7f8d3732890f2cbb0f725a0c67951d03cd8cc43b135ea972c25120b91` |
| TLSH | `T1D753F891B8426A39C2D1577BEDAF548E3314A7D8D1DA3213C9244BA07BCA94F0C97F86` |
| TELFHASH | `t1c5e02600ac759a2c98d7aa74dded07a496016222505a4b10cf11daf4c83f448e30cd5a` |
| SSDEEP | `1536:nEbNn3E5sOq19Pj21ZXBbpuW+8nkSXeVSvhWy5UzS:+n3IxdpNkSXsKf5t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_e596320b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e596320b1d716908045f377f843d5c0c3fadb2dc145d3732f83f8acbf1c2297c"
    family = "Mirai"
    file_name = "sora.arm5"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:50"
  condition:
    hash.sha256(0, filesize) == "e596320b1d716908045f377f843d5c0c3fadb2dc145d3732f83f8acbf1c2297c"
}
```

### Sample 84: `c1def8cce8b6ecb6`

| Field | Value |
|---|---|
| SHA-256 | `c1def8cce8b6ecb69adf65c60d132981789e7460c38a043795f6826f7a35f3b9` |
| Family label | `Mirai` |
| File name | `sora.ppc` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18fae24d870fe97bbf3ad0132ced889a` |
| SHA-1 | `9cca0f8a60c4daf61cd2e174ee7ab49e95b4a677` |
| SHA-256 | `c1def8cce8b6ecb69adf65c60d132981789e7460c38a043795f6826f7a35f3b9` |
| SHA3-384 | `2743bd4685943aca93b3aad702272c2b01e542b000e43c6edeecd3d60a3026194a757ca951f53d99a13b33f5d0fdb12d` |
| TLSH | `T13D533B02B2280A5FF9D319B0343F1FE197BEE9C035E0B689695ED7558635E332485E8D` |
| SSDEEP | `768:PtMLxtiRFwLoDnud1kvSeq7Q4dPfGAsLmZ8BBSzjrYiyR7gHX1SPgIaal5:VMLSBq14Se4GHLTBygfGXAgIVn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_c1def8cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1def8cce8b6ecb69adf65c60d132981789e7460c38a043795f6826f7a35f3b9"
    family = "Mirai"
    file_name = "sora.ppc"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:44"
  condition:
    hash.sha256(0, filesize) == "c1def8cce8b6ecb69adf65c60d132981789e7460c38a043795f6826f7a35f3b9"
}
```

### Sample 85: `4d4df29c04bfaa7e`

| Field | Value |
|---|---|
| SHA-256 | `4d4df29c04bfaa7e15f0ed6d6183375aec20e06115da16e6577aa869c0bec081` |
| Family label | `Mirai` |
| File name | `sora.m68k` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c864e7ffab8423349c54fe2f6ff3441` |
| SHA-1 | `d069dd7eddda00f7dd032f4d0c9acdf1426d5bd4` |
| SHA-256 | `4d4df29c04bfaa7e15f0ed6d6183375aec20e06115da16e6577aa869c0bec081` |
| SHA3-384 | `08e78755cd2615c033a417892bca2017f91cf91866ecb36640dac7f48433aa633283a63e28dc70144fe12fc73a3ca513` |
| TLSH | `T139534B99B4028E3DF88FE97984160E05BA2023D112931F276BAFFDE37D331659D16E46` |
| SSDEEP | `768:2eY49YE204qEkRf/36fmODeiuQlJZvTgFHq1euk8B8vpG97ErlfXySJ1oXPo7Po:2Y7EkRfPh3iDx8Fq1Xk8B2aErlfiSJpU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_4d4df29c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d4df29c04bfaa7e15f0ed6d6183375aec20e06115da16e6577aa869c0bec081"
    family = "Mirai"
    file_name = "sora.m68k"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:09"
  condition:
    hash.sha256(0, filesize) == "4d4df29c04bfaa7e15f0ed6d6183375aec20e06115da16e6577aa869c0bec081"
}
```

### Sample 86: `3d5c61ac98e4f457`

| Field | Value |
|---|---|
| SHA-256 | `3d5c61ac98e4f4576bf44d8023a9ff514535d422ec97d2e7aef39fd6ad950035` |
| Family label | `unknown` |
| File name | `ipmiv2.xml` |
| File type | `unknown` |
| First seen | `2026-07-22 22:04:08` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa2641b43e95bd6b04c4c8c80920ca47` |
| SHA-256 | `3d5c61ac98e4f4576bf44d8023a9ff514535d422ec97d2e7aef39fd6ad950035` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_3d5c61ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d5c61ac98e4f4576bf44d8023a9ff514535d422ec97d2e7aef39fd6ad950035"
    family = "unknown"
    file_name = "ipmiv2.xml"
    file_type = "unknown"
    first_seen = "2026-07-22 22:04:08"
  condition:
    hash.sha256(0, filesize) == "3d5c61ac98e4f4576bf44d8023a9ff514535d422ec97d2e7aef39fd6ad950035"
}
```

### Sample 87: `fdf4a9e66cd7709a`

| Field | Value |
|---|---|
| SHA-256 | `fdf4a9e66cd7709a5b9d53ee60640951030550b1f7270f993e5b428264527931` |
| Family label | `Mirai` |
| File name | `sora.mpsl` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6e03a69408dfa0446fdeeb299e446ab` |
| SHA-1 | `96711ed62f6dc508f283e501e09cf20d36ad2373` |
| SHA-256 | `fdf4a9e66cd7709a5b9d53ee60640951030550b1f7270f993e5b428264527931` |
| SHA3-384 | `dc4548cff5aef31fc2746e42992a17db37eb2d668661cb6938f1bdd555399e7a4758b1880a8bc9412706aa3e213c5539` |
| TLSH | `T10CD2D06EE57582C9FD8E5C3E848C3FA10E59E181221BDB9177228C4D5B32C57F27A4B8` |
| SSDEEP | `384:n8pVWtmRsLYEpB6V8S628FuRUuNJG9whQ3Cfbo6w+K95orjEbRWGVCz0Nvi:8MYHb62x4ahQ3CfdwLj9W3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_fdf4a9e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdf4a9e66cd7709a5b9d53ee60640951030550b1f7270f993e5b428264527931"
    family = "Mirai"
    file_name = "sora.mpsl"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:07"
  condition:
    hash.sha256(0, filesize) == "fdf4a9e66cd7709a5b9d53ee60640951030550b1f7270f993e5b428264527931"
}
```

### Sample 88: `baa7ca2de29b4ee5`

| Field | Value |
|---|---|
| SHA-256 | `baa7ca2de29b4ee51bc03301be779a282b55a2e2739d4c0fe6cedaa37b762d08` |
| Family label | `Mirai` |
| File name | `sora.arm6` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e9b5026bed50803df438316b13ae9ed` |
| SHA-1 | `5d88214a6fe4f808ab1106b22c6c538178f3b2c2` |
| SHA-256 | `baa7ca2de29b4ee51bc03301be779a282b55a2e2739d4c0fe6cedaa37b762d08` |
| SHA3-384 | `1ef12d671afbeb5f9c3ec149465d1321c797f5c37ea7f291b466aa08cacfd1ac77c11714552490cb2a7ca84958f3a011` |
| TLSH | `T1CDE2F111691A847AFB30C471E0F6858677691BBCA9FEB1A25462060DDCC3A4293F1ADF` |
| SSDEEP | `768:TEKkUgXAnURCr6HmDFStmYtKq9q3UELdB:/kEn7uHEemTfLz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_baa7ca2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baa7ca2de29b4ee51bc03301be779a282b55a2e2739d4c0fe6cedaa37b762d08"
    family = "Mirai"
    file_name = "sora.arm6"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:06"
  condition:
    hash.sha256(0, filesize) == "baa7ca2de29b4ee51bc03301be779a282b55a2e2739d4c0fe6cedaa37b762d08"
}
```

### Sample 89: `0098ea36c6295429`

| Field | Value |
|---|---|
| SHA-256 | `0098ea36c6295429a874ee13e707c1e05c573f18290f035fac1a64b74c8c2ae6` |
| Family label | `Mirai` |
| File name | `sora.arm` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cd9ff95f53154b23f0af65334ae5e3e` |
| SHA-1 | `b842fdde09502ad46aaf044fac6161c472d20787` |
| SHA-256 | `0098ea36c6295429a874ee13e707c1e05c573f18290f035fac1a64b74c8c2ae6` |
| SHA3-384 | `a44b24a40ab1d594fe55388b74dfca938e37c8030481b89c0e357f2e2ad28cef025c29b67bef9961f7685147a5e754e6` |
| TLSH | `T188C2F0689228D072B1B45836FD6F0103A736CFF8DAEF362622144334E097D26D6B5B4B` |
| SSDEEP | `384:XH2HEdV7UQDoYQHXxcjllK5+AWaFmK0MF9lz7X6AGexXVzonBY6plNaXhymdGUoB:myNUQUfhQllxlaH0MFjlOnGsIs3Uozl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_0098ea36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0098ea36c6295429a874ee13e707c1e05c573f18290f035fac1a64b74c8c2ae6"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:04"
  condition:
    hash.sha256(0, filesize) == "0098ea36c6295429a874ee13e707c1e05c573f18290f035fac1a64b74c8c2ae6"
}
```

### Sample 90: `ea96505d42088957`

| Field | Value |
|---|---|
| SHA-256 | `ea96505d42088957397f4358b6413bae386eae80194ee7252adb0e3ddbcdf096` |
| Family label | `Mirai` |
| File name | `sora.mips` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5092bbec79a17df249d88909a14c06b1` |
| SHA-1 | `94f175765877a0f567c34522ed1bad68a31afe27` |
| SHA-256 | `ea96505d42088957397f4358b6413bae386eae80194ee7252adb0e3ddbcdf096` |
| SHA3-384 | `b57feaa3d194572c426a665693f0f1ed559247824f7c931f19c26adbdbaf996290833644515b0ec1430ac1abb68cb14f` |
| TLSH | `T18BD2D1BC6B0145D7CEAAA1788DE50B262D60CFA2E0426C076558D9D7BB0986D3CBADC1` |
| SSDEEP | `768:E4ylAtv6pqLJM0RXaxGyUbXtheU/S49IJgGlzDpbuR1JT:XMBqTRXa+Zhr/QVJuN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_ea96505d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea96505d42088957397f4358b6413bae386eae80194ee7252adb0e3ddbcdf096"
    family = "Mirai"
    file_name = "sora.mips"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:03"
  condition:
    hash.sha256(0, filesize) == "ea96505d42088957397f4358b6413bae386eae80194ee7252adb0e3ddbcdf096"
}
```

### Sample 91: `7779c5dd83ce0188`

| Field | Value |
|---|---|
| SHA-256 | `7779c5dd83ce0188bc3d6de963e2bccedbdb783a79756fd7881a158d67277b8a` |
| Family label | `Mirai` |
| File name | `sora.spc` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b252f1eb128b57b3c1a6fec167b5e7ff` |
| SHA-1 | `29fec7b5df2b4e75cbb23b9aec9488e78813ecd4` |
| SHA-256 | `7779c5dd83ce0188bc3d6de963e2bccedbdb783a79756fd7881a158d67277b8a` |
| SHA3-384 | `452600292c53d064ca7a8420a59d915a9a9d160b3f2c76fab0723c91ed74912d70baf035d093657da3a48939aa921bc8` |
| TLSH | `T170732A26B97A1E26C0D4B57E60FB8B11F5E1278E26B4C50A7D720E5EEF147006502EF7` |
| SSDEEP | `1536:hD/B6f6UD5hAS7mo0DCCAXpSKV6v3G78nN9WR:927jqCt8v3GI/u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_7779c5dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7779c5dd83ce0188bc3d6de963e2bccedbdb783a79756fd7881a158d67277b8a"
    family = "Mirai"
    file_name = "sora.spc"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:02"
  condition:
    hash.sha256(0, filesize) == "7779c5dd83ce0188bc3d6de963e2bccedbdb783a79756fd7881a158d67277b8a"
}
```

### Sample 92: `0e1d15e29ccec3c4`

| Field | Value |
|---|---|
| SHA-256 | `0e1d15e29ccec3c49b646470a7a483f4cc5a533787c9e91ee8579be0115167fa` |
| Family label | `Mirai` |
| File name | `sora.x86` |
| File type | `elf` |
| First seen | `2026-07-22 22:04:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `211c39ca1eec1cd38a9cdbfb80669e8c` |
| SHA-1 | `68a43009ccd4eb2989f9fbaaede5b09f7fef736e` |
| SHA-256 | `0e1d15e29ccec3c49b646470a7a483f4cc5a533787c9e91ee8579be0115167fa` |
| SHA3-384 | `4c8715ec1d5792f6ffe31c4865afa42147f5cd0b08dd549132b8c4efcd2c7d3b6b2741c9437b7a435bb9f539d807d497` |
| TLSH | `T1EFC2D19394A98D06C862423B6E1F159B61242539134DFE2E373BEFDC63464B8A135DC7` |
| SSDEEP | `384:MRGW9WXUx5+bkbRaliVErjrL9VD9jPwrSaf5dwapDyCTYHHJC8oytPFnAqV/LlgT:45+Kcrb9VDJe5FLTYTlPFnz/mRNX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_0e1d15e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e1d15e29ccec3c49b646470a7a483f4cc5a533787c9e91ee8579be0115167fa"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:01"
  condition:
    hash.sha256(0, filesize) == "0e1d15e29ccec3c49b646470a7a483f4cc5a533787c9e91ee8579be0115167fa"
}
```

### Sample 93: `953b23a485f03ff6`

| Field | Value |
|---|---|
| SHA-256 | `953b23a485f03ff659a570c9f2ff4efa3fa053c13252914112aba5d95302ba97` |
| Family label | `Mirai` |
| File name | `sora.arm5` |
| File type | `elf` |
| First seen | `2026-07-22 22:03:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `450fb13b32e19171dfe5432542f7da29` |
| SHA-1 | `8deccbedb46ba862d250441633d7175b6ae910ed` |
| SHA-256 | `953b23a485f03ff659a570c9f2ff4efa3fa053c13252914112aba5d95302ba97` |
| SHA3-384 | `a80bfa31426c55ac9007f0150e3078dcd7ff4b317140a96e006a178d087e859274b287959a0a0e18ba89f80fef620936` |
| TLSH | `T102B2E161A1853E62D770713AB97CC60157AB97F8B0F672753224B7AC4BE2C47607414F` |
| SSDEEP | `384:5ZUX11S49enZh57fYONQ/yQVQbFxD+ckPvDxqSwPzMvdL6OtRRhymdGUop5hKg:UX1De9kONQG5xD+jHMDzu+Us3UozYg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_953b23a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "953b23a485f03ff659a570c9f2ff4efa3fa053c13252914112aba5d95302ba97"
    family = "Mirai"
    file_name = "sora.arm5"
    file_type = "elf"
    first_seen = "2026-07-22 22:03:59"
  condition:
    hash.sha256(0, filesize) == "953b23a485f03ff659a570c9f2ff4efa3fa053c13252914112aba5d95302ba97"
}
```

### Sample 94: `8d7e5addf9b3c791`

| Field | Value |
|---|---|
| SHA-256 | `8d7e5addf9b3c791a5be49062a69f91c540a6d5c047ec82c20deafe69d4149f3` |
| Family label | `Mirai` |
| File name | `sora.sh4` |
| File type | `elf` |
| First seen | `2026-07-22 22:03:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b40cd455c4d77dfee70a71f8b05d87b` |
| SHA-1 | `7c3a78c9b163d9dafc753f1311c31b785c7e55ab` |
| SHA-256 | `8d7e5addf9b3c791a5be49062a69f91c540a6d5c047ec82c20deafe69d4149f3` |
| SHA3-384 | `d751907e98d0a6c399f1ae10d3efb45a865c8f63d7b0dd45486e5d75104e66bf0728be26bf575bb98674a1cfc1cfe3f8` |
| TLSH | `T147538D75D12DAEA8C0424AB4A9598E704F13A0C046732EF7DA9587A69443DBCF858FF8` |
| SSDEEP | `1536:zag/Vdf5F1LwtkbaOoQ3veifs3guba/qzCEZaCw:zJzf5TLcQfPf+gehCEZa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_8d7e5add
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d7e5addf9b3c791a5be49062a69f91c540a6d5c047ec82c20deafe69d4149f3"
    family = "Mirai"
    file_name = "sora.sh4"
    file_type = "elf"
    first_seen = "2026-07-22 22:03:58"
  condition:
    hash.sha256(0, filesize) == "8d7e5addf9b3c791a5be49062a69f91c540a6d5c047ec82c20deafe69d4149f3"
}
```

### Sample 95: `22967371fd7a84e1`

| Field | Value |
|---|---|
| SHA-256 | `22967371fd7a84e18a2c3551c06d244fd94b747d9e61eef5282c3b04af645f90` |
| Family label | `Mirai` |
| File name | `sora.ppc` |
| File type | `elf` |
| First seen | `2026-07-22 22:03:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `311b75e11aeaf34d28cd09f3c1df3434` |
| SHA-1 | `f84ec702b20711e96713f6a21dcc5250077f3441` |
| SHA-256 | `22967371fd7a84e18a2c3551c06d244fd94b747d9e61eef5282c3b04af645f90` |
| SHA3-384 | `778886e3c429bb67b0c08da782bf0154f5f7167df66bf238ab3a6fdb10010c01600b053274e31269fcc3d89cc866fabc` |
| TLSH | `T181C2E0A1E1F62E86F73A6E601B65D2C177B04E9EA777CCD2255C9F0804A721B07096C8` |
| SSDEEP | `384:lQez9/6Jgn9yMGEGHV4u/DT8HgPEt6seDYc/OzM4uVcqgw05VxJc0i:yG959yM0HWubJsWDYcGw4uVcqgw09S0i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_22967371
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22967371fd7a84e18a2c3551c06d244fd94b747d9e61eef5282c3b04af645f90"
    family = "Mirai"
    file_name = "sora.ppc"
    file_type = "elf"
    first_seen = "2026-07-22 22:03:57"
  condition:
    hash.sha256(0, filesize) == "22967371fd7a84e18a2c3551c06d244fd94b747d9e61eef5282c3b04af645f90"
}
```

### Sample 96: `f5a92dcadc6bed2e`

| Field | Value |
|---|---|
| SHA-256 | `f5a92dcadc6bed2e1cf5efff18221929b0a3fbb7db1a69f26f53f4c7295fab35` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-22 21:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99eeae80567fd81fb151afe190d03e71` |
| SHA-1 | `4358456c8735248e0286d2b91575947364de42af` |
| SHA-256 | `f5a92dcadc6bed2e1cf5efff18221929b0a3fbb7db1a69f26f53f4c7295fab35` |
| SHA3-384 | `794c526a50ab7ba3b6ace89d68ec30d154dfb048d215214eb288401971ec80cea3ef898f4718e130a53f34daeefb7379` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1B2E633184BD426FEEAF3C03CEAD196E5B5A8786107B1D99F17A483615F473D08C3EA06` |
| SSDEEP | `393216:3HXeZbuFpIgMk3GobNOC3mQCvXMCHWUjXWcuI3/PGTAI:3HrdMWf8mPCvXMb8XrH/O7` |
| ICON-DHASH | `71f8fcdccce4f071` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_f5a92dca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5a92dcadc6bed2e1cf5efff18221929b0a3fbb7db1a69f26f53f4c7295fab35"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-22 21:52:09"
  condition:
    hash.sha256(0, filesize) == "f5a92dcadc6bed2e1cf5efff18221929b0a3fbb7db1a69f26f53f4c7295fab35"
}
```

### Sample 97: `4b8af5466ec8215e`

| Field | Value |
|---|---|
| SHA-256 | `4b8af5466ec8215e85333376a4bceefadad95befd9cbb8008567f5cf48fec6bb` |
| Family label | `unknown` |
| File name | `4b8af5466ec8215e85333376a4bceefadad95befd9cbb8008567f5cf48fec6bb.exe.exe` |
| File type | `exe` |
| First seen | `2026-07-22 21:41:12` |
| Reporter | `anonymous` |
| Tags | `exe, hacktool` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf4c2ad3840b56e8c8707075a94536dc` |
| SHA-1 | `ae88399b2da5e9fc310f3c6f490a5e27928b6313` |
| SHA-256 | `4b8af5466ec8215e85333376a4bceefadad95befd9cbb8008567f5cf48fec6bb` |
| SHA3-384 | `1a0d8c774b8cc9721517a4054843c03d32c3502e491f9fb326fed123e614e292fdc707ba7e08edea44035a1e0e045422` |
| IMPHASH | `a7d6882576a765d46604db2074aaeafb` |
| TLSH | `T1DAF6AE39E411E5A8CC56C434BA0AB2215EE03A17CB6695FFD29DC8652E276FD0F34B0D` |
| SSDEEP | `196608:9B+qsJo31B4DCIxZ04kQs3NSNKlNjuLd0L8RWQO9K:vrsg34DCIf04kQs3NXw3` |
| ICON-DHASH | `558eb28eb2a68e55` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_4b8af546
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b8af5466ec8215e85333376a4bceefadad95befd9cbb8008567f5cf48fec6bb"
    family = "unknown"
    file_name = "4b8af5466ec8215e85333376a4bceefadad95befd9cbb8008567f5cf48fec6bb.exe.exe"
    file_type = "exe"
    first_seen = "2026-07-22 21:41:12"
  condition:
    hash.sha256(0, filesize) == "4b8af5466ec8215e85333376a4bceefadad95befd9cbb8008567f5cf48fec6bb"
}
```

### Sample 98: `de366c8e91207ad2`

| Field | Value |
|---|---|
| SHA-256 | `de366c8e91207ad27a30fdf10182d63512dc45aa97f077c9859c5678a7bd144c` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-22 21:38:18` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72772a7b9b2e045b217a07d2bd585d7c` |
| SHA-1 | `0eca05491646d7039a319a5b9bc816142f94bcb1` |
| SHA-256 | `de366c8e91207ad27a30fdf10182d63512dc45aa97f077c9859c5678a7bd144c` |
| SHA3-384 | `f94e0cdacd91d9825cb712c7873fec710f377269f8110d3be439e5cf35234ed2321f262a1ee6aeab0effeaa5ca3cb8bb` |
| TLSH | `T198137D695A953C249E9988371D7E2F0CB9AA83E1300851DDBFCB3CF28C45ADCE21871D` |
| SSDEEP | `768:5VEJVIhtMg9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:XEJ2Mdco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_de366c8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de366c8e91207ad27a30fdf10182d63512dc45aa97f077c9859c5678a7bd144c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-22 21:38:18"
  condition:
    hash.sha256(0, filesize) == "de366c8e91207ad27a30fdf10182d63512dc45aa97f077c9859c5678a7bd144c"
}
```

### Sample 99: `2bddfd2a2be55a42`

| Field | Value |
|---|---|
| SHA-256 | `2bddfd2a2be55a42a621a4c234f39e2a5756557f6ec03ef72eb7d1880e1a02fe` |
| Family label | `unknown` |
| File name | `2bddfd2a2be55a42a621a4c234f39e2a5756557f6ec03ef72eb7d1880e1a02fe` |
| File type | `elf` |
| First seen | `2026-07-22 21:18:53` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf747d1ddb73c3a6cc737894c1742e46` |
| SHA-1 | `48d4045f002ec7faf93853a02f92ccb440e7f805` |
| SHA-256 | `2bddfd2a2be55a42a621a4c234f39e2a5756557f6ec03ef72eb7d1880e1a02fe` |
| SHA3-384 | `01da58c37d4fd8c439c3a038905ce5ea7ffdcd17b0bbcd73779f69e1d30bc32621bcbb45467d8434e03ef69a2502e605` |
| TLSH | `T11457CF7792467CEDE9B98CB4D01015816DA878874778E3C7BAC870E666EB6D08D3E730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQa:cqYUQuVDt0TZEx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_2bddfd2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bddfd2a2be55a42a621a4c234f39e2a5756557f6ec03ef72eb7d1880e1a02fe"
    family = "unknown"
    file_name = "2bddfd2a2be55a42a621a4c234f39e2a5756557f6ec03ef72eb7d1880e1a02fe"
    file_type = "elf"
    first_seen = "2026-07-22 21:18:53"
  condition:
    hash.sha256(0, filesize) == "2bddfd2a2be55a42a621a4c234f39e2a5756557f6ec03ef72eb7d1880e1a02fe"
}
```

### Sample 100: `5b0f66b45f70e197`

| Field | Value |
|---|---|
| SHA-256 | `5b0f66b45f70e1976a61be44739d0e1f2a554a6b314ae4237d670a02e4614fe5` |
| Family label | `unknown` |
| File name | `peak.sh` |
| File type | `sh` |
| First seen | `2026-07-22 21:05:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a39789b544c9fe848a679ac094f620d` |
| SHA-1 | `1881ec168b62ad8b87ada9a3e61cc7da760120e8` |
| SHA-256 | `5b0f66b45f70e1976a61be44739d0e1f2a554a6b314ae4237d670a02e4614fe5` |
| SHA3-384 | `3cbc60915c9965c3d19d6582263778ad162be04e17036df4f14a8ca42578fb3696a39098f4e933cdc94e2e01bdcfc70d` |
| TLSH | `T14D01A9C531907FF3EC049F08FA72466950C7EAE9A2CF07E094C66E155D9D644F917A08` |
| SSDEEP | `6:hZAU0CiG8pKgOoShGSbTgFGpjo9yXuiG9yZJNHu6WKofVxaGfPkdVkCf9FLGERBf:ECinwHBPcyjeyZCAQy24fL3+pH8r` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_5b0f66b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b0f66b45f70e1976a61be44739d0e1f2a554a6b314ae4237d670a02e4614fe5"
    family = "unknown"
    file_name = "peak.sh"
    file_type = "sh"
    first_seen = "2026-07-22 21:05:46"
  condition:
    hash.sha256(0, filesize) == "5b0f66b45f70e1976a61be44739d0e1f2a554a6b314ae4237d670a02e4614fe5"
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
 * Generated: 2026-07-23T03:48:50.368012+00:00
 */

rule MalwareBazaar_AsyncRAT_001_1f79f723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f79f7239d6f8cd9224064830720909884f98b989c1d7d01d90a3de686f02641"
    family = "AsyncRAT"
    file_name = "Shipping Documents.js"
    file_type = "js"
    first_seen = "2026-07-23 03:26:53"
  condition:
    hash.sha256(0, filesize) == "1f79f7239d6f8cd9224064830720909884f98b989c1d7d01d90a3de686f02641"
}

rule MalwareBazaar_Vidar_002_c118f703
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c118f7037676c76b39d05c16c337158c0d714decee91af1c44f41c899233b265"
    family = "Vidar"
    file_name = "XOR_Loader.exe"
    file_type = "exe"
    first_seen = "2026-07-23 03:23:08"
  condition:
    hash.sha256(0, filesize) == "c118f7037676c76b39d05c16c337158c0d714decee91af1c44f41c899233b265"
}

rule MalwareBazaar_unknown_003_c560beb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c560beb3b567797cdd3cc478934e27ad2a8991fb5aa350b7effa77a88a94441a"
    family = "unknown"
    file_name = "install.msi"
    file_type = "msi"
    first_seen = "2026-07-23 03:17:48"
  condition:
    hash.sha256(0, filesize) == "c560beb3b567797cdd3cc478934e27ad2a8991fb5aa350b7effa77a88a94441a"
}

rule MalwareBazaar_unknown_004_93988577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93988577e3e325cdb5d1a136d08e6e92572014ad8bbc6f0b6220e456c593270b"
    family = "unknown"
    file_name = "MiniPowerShell.exe"
    file_type = "exe"
    first_seen = "2026-07-23 03:16:29"
  condition:
    hash.sha256(0, filesize) == "93988577e3e325cdb5d1a136d08e6e92572014ad8bbc6f0b6220e456c593270b"
}

rule MalwareBazaar_unknown_005_98f5e6cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98f5e6cc01bd74709e63639e75a6e4d68b6c5fb9654ae97490155792888bebdd"
    family = "unknown"
    file_name = "Soda_Music_12.8.1_x64.exe"
    file_type = "exe"
    first_seen = "2026-07-23 03:13:57"
  condition:
    hash.sha256(0, filesize) == "98f5e6cc01bd74709e63639e75a6e4d68b6c5fb9654ae97490155792888bebdd"
}

rule MalwareBazaar_unknown_006_3bb64d86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bb64d86bed8337443f4b6f6c981914dd7d94b6fa7b61709015f9698e13bc67c"
    family = "unknown"
    file_name = "build_captcha.exe"
    file_type = "exe"
    first_seen = "2026-07-23 03:12:15"
  condition:
    hash.sha256(0, filesize) == "3bb64d86bed8337443f4b6f6c981914dd7d94b6fa7b61709015f9698e13bc67c"
}

rule MalwareBazaar_unknown_007_a5b13da4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5b13da4ffa0bb5df881c213faa08ca92608cd7e4e83142695877923d278a7d2"
    family = "unknown"
    file_name = "ViceCallers.exe"
    file_type = "exe"
    first_seen = "2026-07-23 03:05:57"
  condition:
    hash.sha256(0, filesize) == "a5b13da4ffa0bb5df881c213faa08ca92608cd7e4e83142695877923d278a7d2"
}

rule MalwareBazaar_Formbook_008_a21af048
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a21af048f2d0b53774660e7304581639c8027808b16ea9dd4bebd0af955124dc"
    family = "Formbook"
    file_name = "PAGO.js"
    file_type = "js"
    first_seen = "2026-07-23 03:03:45"
  condition:
    hash.sha256(0, filesize) == "a21af048f2d0b53774660e7304581639c8027808b16ea9dd4bebd0af955124dc"
}

rule MalwareBazaar_Formbook_009_cc7b6ff4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc7b6ff483a2c3a0efe7f4d6ecefe00510ebd166723ebf7ad16e665d124245b9"
    family = "Formbook"
    file_name = "PO_2026_0001.pdf.js"
    file_type = "js"
    first_seen = "2026-07-23 03:03:18"
  condition:
    hash.sha256(0, filesize) == "cc7b6ff483a2c3a0efe7f4d6ecefe00510ebd166723ebf7ad16e665d124245b9"
}

rule MalwareBazaar_Mirai_010_9ab9d3ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ab9d3ecb256fb826e2091209939288a849a7706290b012bfbafafa62eea96ed"
    family = "Mirai"
    file_name = "android_arm64"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:39"
  condition:
    hash.sha256(0, filesize) == "9ab9d3ecb256fb826e2091209939288a849a7706290b012bfbafafa62eea96ed"
}

rule MalwareBazaar_Mirai_011_0fb7ad5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fb7ad5dc6c2c8bac1dce94687f553c244159ecd079459d53e64a001f94586f9"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:37"
  condition:
    hash.sha256(0, filesize) == "0fb7ad5dc6c2c8bac1dce94687f553c244159ecd079459d53e64a001f94586f9"
}

rule MalwareBazaar_Mirai_012_d6243804
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d62438047907e77f6e8761ac6976c62971a477c3ecdb090a06d632caf9fb2f93"
    family = "Mirai"
    file_name = "i386"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:35"
  condition:
    hash.sha256(0, filesize) == "d62438047907e77f6e8761ac6976c62971a477c3ecdb090a06d632caf9fb2f93"
}

rule MalwareBazaar_Mirai_013_11a36706
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11a367066e01e4e424487d8d6cf16b763fa81d8f70e029fbb28fb78304d01c97"
    family = "Mirai"
    file_name = "mipsle"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:33"
  condition:
    hash.sha256(0, filesize) == "11a367066e01e4e424487d8d6cf16b763fa81d8f70e029fbb28fb78304d01c97"
}

rule MalwareBazaar_Mirai_014_d2c51478
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2c51478b5abf90a4bc9fbdaeefcd3937e12995f1b2df73cdf9d7cc9cd8d0f4f"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:32"
  condition:
    hash.sha256(0, filesize) == "d2c51478b5abf90a4bc9fbdaeefcd3937e12995f1b2df73cdf9d7cc9cd8d0f4f"
}

rule MalwareBazaar_Mirai_015_e521af82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e521af827de7136f8f30da5f85c381a387dcb3418a0ade034493faf7c3b840fa"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:30"
  condition:
    hash.sha256(0, filesize) == "e521af827de7136f8f30da5f85c381a387dcb3418a0ade034493faf7c3b840fa"
}

rule MalwareBazaar_Mirai_016_39efe58c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39efe58ce69f0463a0919451a0cc3242f18726b596bdd7b8000955fbd36fad29"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:28"
  condition:
    hash.sha256(0, filesize) == "39efe58ce69f0463a0919451a0cc3242f18726b596bdd7b8000955fbd36fad29"
}

rule MalwareBazaar_Mirai_017_cc5920f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc5920f04c7666458cf9c4f876a54bd20091696a1a66b66f816024467bf2ba26"
    family = "Mirai"
    file_name = "arm64"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:26"
  condition:
    hash.sha256(0, filesize) == "cc5920f04c7666458cf9c4f876a54bd20091696a1a66b66f816024467bf2ba26"
}

rule MalwareBazaar_Mirai_018_434a796a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "434a796ad042259ab54d0727fa29b6549ba8624cfa23e8d85323f66c83cce15c"
    family = "Mirai"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-07-23 02:52:24"
  condition:
    hash.sha256(0, filesize) == "434a796ad042259ab54d0727fa29b6549ba8624cfa23e8d85323f66c83cce15c"
}

rule MalwareBazaar_unknown_019_e8843058
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e884305886288e46cea6630d22737da6c4bfa68b582f2b18b5133aa885c791f3"
    family = "unknown"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-07-23 02:52:23"
  condition:
    hash.sha256(0, filesize) == "e884305886288e46cea6630d22737da6c4bfa68b582f2b18b5133aa885c791f3"
}

rule MalwareBazaar_unknown_020_56091719
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56091719eeba4881f3db1f837feaa9d47a5a275bff6218186d97614e252e6d21"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 02:52:10"
  condition:
    hash.sha256(0, filesize) == "56091719eeba4881f3db1f837feaa9d47a5a275bff6218186d97614e252e6d21"
}

rule MalwareBazaar_unknown_021_983972c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "983972c15dd1778fba75deb79fc95008700008e24a08565e2c1d3fef27ee27a4"
    family = "unknown"
    file_name = "setup.1.0.228tt00023.msi"
    file_type = "msi"
    first_seen = "2026-07-23 02:51:19"
  condition:
    hash.sha256(0, filesize) == "983972c15dd1778fba75deb79fc95008700008e24a08565e2c1d3fef27ee27a4"
}

rule MalwareBazaar_unknown_022_66fbfd8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66fbfd8c7d852bf002981112505f527d7ca8e581a4e47ce78f272090ec0a7134"
    family = "unknown"
    file_name = "setup.1.0.2286300021.msi"
    file_type = "msi"
    first_seen = "2026-07-23 02:43:42"
  condition:
    hash.sha256(0, filesize) == "66fbfd8c7d852bf002981112505f527d7ca8e581a4e47ce78f272090ec0a7134"
}

rule MalwareBazaar_CoinMiner_023_694a3bab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "694a3bab92e60e6760649fd40e97c04ff03faded2073e7a0c2e061229bf7820a"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 02:15:02"
  condition:
    hash.sha256(0, filesize) == "694a3bab92e60e6760649fd40e97c04ff03faded2073e7a0c2e061229bf7820a"
}

rule MalwareBazaar_unknown_024_2485d9a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2485d9a51fc370a064613f490bd16df1553e3edb4fc38cbede4023e046932a33"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 02:14:53"
  condition:
    hash.sha256(0, filesize) == "2485d9a51fc370a064613f490bd16df1553e3edb4fc38cbede4023e046932a33"
}

rule MalwareBazaar_unknown_025_60108063
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "601080635c9ccd34b65b0fa5852282a58bac0eee8c01120beb1fd852a2d31e66"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 02:14:47"
  condition:
    hash.sha256(0, filesize) == "601080635c9ccd34b65b0fa5852282a58bac0eee8c01120beb1fd852a2d31e66"
}

rule MalwareBazaar_unknown_026_60e66eaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60e66eaa948273a5fbb3701ce3636d007ab0e91fc98be4801ccedb99b204b313"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 02:14:39"
  condition:
    hash.sha256(0, filesize) == "60e66eaa948273a5fbb3701ce3636d007ab0e91fc98be4801ccedb99b204b313"
}

rule MalwareBazaar_unknown_027_3f7b8f2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f7b8f2badc3c70d10827c9b9ce4cbd4b8d2611d78b35ec1590222595794da63"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 01:54:21"
  condition:
    hash.sha256(0, filesize) == "3f7b8f2badc3c70d10827c9b9ce4cbd4b8d2611d78b35ec1590222595794da63"
}

rule MalwareBazaar_unknown_028_366e52b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "366e52b6d95d9478a73ffcd659a1807bdea901a0737b7b2532fe11145be03925"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 01:52:09"
  condition:
    hash.sha256(0, filesize) == "366e52b6d95d9478a73ffcd659a1807bdea901a0737b7b2532fe11145be03925"
}

rule MalwareBazaar_Mirai_029_4119001a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4119001a7ecd42e4eccf0694011bcccf0205064aaafec0c835c02bc943cb9053"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-23 01:46:38"
  condition:
    hash.sha256(0, filesize) == "4119001a7ecd42e4eccf0694011bcccf0205064aaafec0c835c02bc943cb9053"
}

rule MalwareBazaar_unknown_030_99f6342a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99f6342a0808a4772f275c3127e2e305e57242bb7aae032b5e488b4a6e80a0e4"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-23 01:36:25"
  condition:
    hash.sha256(0, filesize) == "99f6342a0808a4772f275c3127e2e305e57242bb7aae032b5e488b4a6e80a0e4"
}

rule MalwareBazaar_unknown_031_81cfb1bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81cfb1bfebe07151a744547e40a71ed31038af2487d010a406609e921243f082"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 01:24:21"
  condition:
    hash.sha256(0, filesize) == "81cfb1bfebe07151a744547e40a71ed31038af2487d010a406609e921243f082"
}

rule MalwareBazaar_Mirai_032_b6a1b3ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6a1b3ec671405487d5f73b95f98f376d902f31a370d67c92081d9d491ca497d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-23 01:04:33"
  condition:
    hash.sha256(0, filesize) == "b6a1b3ec671405487d5f73b95f98f376d902f31a370d67c92081d9d491ca497d"
}

rule MalwareBazaar_unknown_033_3d594ae0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d594ae09c50f0a63a8b213b6bbdf390f34ddd83900f1e0a9053e17fa20fd643"
    family = "unknown"
    file_name = "3d594ae09c50f0a63a8b213b6bbdf390f34ddd83900f1e0a9053e17fa20fd643"
    file_type = "elf"
    first_seen = "2026-07-23 01:00:25"
  condition:
    hash.sha256(0, filesize) == "3d594ae09c50f0a63a8b213b6bbdf390f34ddd83900f1e0a9053e17fa20fd643"
}

rule MalwareBazaar_unknown_034_1bd3745a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bd3745a4f9043ead807d7777669b0dbf5b56985e5b3dd9d7cff8384154ea4a8"
    family = "unknown"
    file_name = "1bd3745a4f9043ead807d7777669b0dbf5b56985e5b3dd9d7cff8384154ea4a8"
    file_type = "elf"
    first_seen = "2026-07-23 01:00:20"
  condition:
    hash.sha256(0, filesize) == "1bd3745a4f9043ead807d7777669b0dbf5b56985e5b3dd9d7cff8384154ea4a8"
}

rule MalwareBazaar_Mirai_035_a128fc6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a128fc6dffeb0f7917a07f158dc4fafda4e2cf5c7bfd69d06b56f3db810622e1"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-07-23 00:56:52"
  condition:
    hash.sha256(0, filesize) == "a128fc6dffeb0f7917a07f158dc4fafda4e2cf5c7bfd69d06b56f3db810622e1"
}

rule MalwareBazaar_Mirai_036_d6981ba0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6981ba0520c7c56c54158f9e6802908999136e3db5a99d93b3f1a792a4d96f1"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-07-23 00:56:49"
  condition:
    hash.sha256(0, filesize) == "d6981ba0520c7c56c54158f9e6802908999136e3db5a99d93b3f1a792a4d96f1"
}

rule MalwareBazaar_Mirai_037_300aee78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "300aee7894a93235dc4a55fa02914bbb93d67700aa11bdeff252b40d87ac6014"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-07-23 00:56:44"
  condition:
    hash.sha256(0, filesize) == "300aee7894a93235dc4a55fa02914bbb93d67700aa11bdeff252b40d87ac6014"
}

rule MalwareBazaar_Mirai_038_4ca54b07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ca54b07bd66b64c255400440a513037ed41e0e79eb552bae97928fe1b9aaae4"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-07-23 00:56:41"
  condition:
    hash.sha256(0, filesize) == "4ca54b07bd66b64c255400440a513037ed41e0e79eb552bae97928fe1b9aaae4"
}

rule MalwareBazaar_Mirai_039_1d370494
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d370494366ea99666309ab4e8a906f5bd7ee9fd752d0d8833644921a9ab147e"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:48"
  condition:
    hash.sha256(0, filesize) == "1d370494366ea99666309ab4e8a906f5bd7ee9fd752d0d8833644921a9ab147e"
}

rule MalwareBazaar_Mirai_040_23de6ff2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23de6ff2926dc77da7736a5a39a0c4a7ba9de838d78c2abbba81402dfd243b56"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:46"
  condition:
    hash.sha256(0, filesize) == "23de6ff2926dc77da7736a5a39a0c4a7ba9de838d78c2abbba81402dfd243b56"
}

rule MalwareBazaar_Mirai_041_63aa7d76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63aa7d76bee790377ac6cb34cbff2fe69694883ef920eb7af3fef2e428bb09de"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:43"
  condition:
    hash.sha256(0, filesize) == "63aa7d76bee790377ac6cb34cbff2fe69694883ef920eb7af3fef2e428bb09de"
}

rule MalwareBazaar_Mirai_042_61de63d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61de63d750abb376ee07f403a3c4b3a77a6d9a8d68c0c40ed0d0f7ecf0ea53be"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:41"
  condition:
    hash.sha256(0, filesize) == "61de63d750abb376ee07f403a3c4b3a77a6d9a8d68c0c40ed0d0f7ecf0ea53be"
}

rule MalwareBazaar_Mirai_043_dfe31d54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfe31d54aaf42b090ce4ceb7c4c33a68acde5862a88ced927968efc8e99bfac5"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:31"
  condition:
    hash.sha256(0, filesize) == "dfe31d54aaf42b090ce4ceb7c4c33a68acde5862a88ced927968efc8e99bfac5"
}

rule MalwareBazaar_Mirai_044_5dcc401b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dcc401bcba1ccc0f65b59c3ec54605cbfa33f970940957bf98af2d7054119a4"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:30"
  condition:
    hash.sha256(0, filesize) == "5dcc401bcba1ccc0f65b59c3ec54605cbfa33f970940957bf98af2d7054119a4"
}

rule MalwareBazaar_Mirai_045_218399fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "218399fcd5f5e41e70d42c49d099ebd7d0cb32452ce547b79d12103a95d8d03f"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:29"
  condition:
    hash.sha256(0, filesize) == "218399fcd5f5e41e70d42c49d099ebd7d0cb32452ce547b79d12103a95d8d03f"
}

rule MalwareBazaar_Mirai_046_7ca630f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ca630f1e4f63aa9d483c2d79b53fffd0c8348c26344b61b20562b127e74975a"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:27"
  condition:
    hash.sha256(0, filesize) == "7ca630f1e4f63aa9d483c2d79b53fffd0c8348c26344b61b20562b127e74975a"
}

rule MalwareBazaar_Mirai_047_67b3e794
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67b3e794aae2500ad567d33a4ee563a9476f76fe55b9de8b96fa2e62573278b7"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:26"
  condition:
    hash.sha256(0, filesize) == "67b3e794aae2500ad567d33a4ee563a9476f76fe55b9de8b96fa2e62573278b7"
}

rule MalwareBazaar_Mirai_048_93c43002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93c43002575153c1ade572ee6e3dab97ce10d7e0f82d1655a1ea3b4a6f33df45"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:25"
  condition:
    hash.sha256(0, filesize) == "93c43002575153c1ade572ee6e3dab97ce10d7e0f82d1655a1ea3b4a6f33df45"
}

rule MalwareBazaar_Mirai_049_df835ef7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df835ef7635ffe39dda4b14f7987ee7772fdf7c8a41ba8ed304450b2f78e857b"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:24"
  condition:
    hash.sha256(0, filesize) == "df835ef7635ffe39dda4b14f7987ee7772fdf7c8a41ba8ed304450b2f78e857b"
}

rule MalwareBazaar_Mirai_050_0d0f2738
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d0f273842095e3c540d4192f9231282fef2fbba21f3ae5934471a7b90866ce1"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:22"
  condition:
    hash.sha256(0, filesize) == "0d0f273842095e3c540d4192f9231282fef2fbba21f3ae5934471a7b90866ce1"
}

rule MalwareBazaar_Mirai_051_e5450891
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e545089130a2fc85a172fe88fb0ed5482ca50609c6a942e611dcec45f0680c8c"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:21"
  condition:
    hash.sha256(0, filesize) == "e545089130a2fc85a172fe88fb0ed5482ca50609c6a942e611dcec45f0680c8c"
}

rule MalwareBazaar_Mirai_052_cb010e06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb010e06c861fc82ec3ebf806beb6ddaddafadc5142d1506d7d67da74f9b709f"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:20"
  condition:
    hash.sha256(0, filesize) == "cb010e06c861fc82ec3ebf806beb6ddaddafadc5142d1506d7d67da74f9b709f"
}

rule MalwareBazaar_Mirai_053_4822b3ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4822b3ecc126f323c4356082078cf15157becf47422c6c7c11d6fb230fb79efe"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-23 00:54:19"
  condition:
    hash.sha256(0, filesize) == "4822b3ecc126f323c4356082078cf15157becf47422c6c7c11d6fb230fb79efe"
}

rule MalwareBazaar_Mirai_054_c781c043
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c781c043c269b8795bd66339d042d1700e9ff8707536a08d314555e82cba3651"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-23 00:52:35"
  condition:
    hash.sha256(0, filesize) == "c781c043c269b8795bd66339d042d1700e9ff8707536a08d314555e82cba3651"
}

rule MalwareBazaar_unknown_055_4d096a4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d096a4d27f59f46ba928179f912d8df4467b32a7a7ecf70fac63f0d97fc5edf"
    family = "unknown"
    file_name = "EscapetothePast.exe"
    file_type = "exe"
    first_seen = "2026-07-23 00:50:12"
  condition:
    hash.sha256(0, filesize) == "4d096a4d27f59f46ba928179f912d8df4467b32a7a7ecf70fac63f0d97fc5edf"
}

rule MalwareBazaar_unknown_056_46b70348
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46b70348d87262640dd2510b0b6c2d0d9ba9ea1de135c7112405fdf7d08a7efd"
    family = "unknown"
    file_name = "SecuriteInfo.com.W32.ABTrojan.RBQK-4720.4321.29656"
    file_type = "exe"
    first_seen = "2026-07-23 00:48:41"
  condition:
    hash.sha256(0, filesize) == "46b70348d87262640dd2510b0b6c2d0d9ba9ea1de135c7112405fdf7d08a7efd"
}

rule MalwareBazaar_Mirai_057_84615c4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84615c4dc89944b6f365616ef685ff669bf04a1ef6ccf5e2ac29058a27e94177"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-23 00:48:26"
  condition:
    hash.sha256(0, filesize) == "84615c4dc89944b6f365616ef685ff669bf04a1ef6ccf5e2ac29058a27e94177"
}

rule MalwareBazaar_Mirai_058_333774e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "333774e3405c4e6ef3a663bb7fe5e9074f03a6c8bb080e0ff3bcc33eec848b30"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-23 00:43:32"
  condition:
    hash.sha256(0, filesize) == "333774e3405c4e6ef3a663bb7fe5e9074f03a6c8bb080e0ff3bcc33eec848b30"
}

rule MalwareBazaar_unknown_059_1d0a74bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d0a74bde7856d5e18170590fd2424281001c93833940de6f95dbba1028f57cc"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-23 00:22:37"
  condition:
    hash.sha256(0, filesize) == "1d0a74bde7856d5e18170590fd2424281001c93833940de6f95dbba1028f57cc"
}

rule MalwareBazaar_Gafgyt_060_7ce8cf71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ce8cf71a2111e1ebdf8f09565fc2716d84cd5be4d79fc2dc5970454d392df8b"
    family = "Gafgyt"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-23 00:21:21"
  condition:
    hash.sha256(0, filesize) == "7ce8cf71a2111e1ebdf8f09565fc2716d84cd5be4d79fc2dc5970454d392df8b"
}

rule MalwareBazaar_Mirai_061_060040eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "060040eb137e800b59b39b16978531d123bc6555da3b24fb7c3687e1cacf7a07"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-23 00:16:32"
  condition:
    hash.sha256(0, filesize) == "060040eb137e800b59b39b16978531d123bc6555da3b24fb7c3687e1cacf7a07"
}

rule MalwareBazaar_Mirai_062_5872ee77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5872ee77158103070ee4c63ecad9577e6aafe73a6c512aa94e83b0ddaac0fe15"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-07-23 00:16:05"
  condition:
    hash.sha256(0, filesize) == "5872ee77158103070ee4c63ecad9577e6aafe73a6c512aa94e83b0ddaac0fe15"
}

rule MalwareBazaar_Mirai_063_5f37ff54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f37ff54ed0a5cd7c83423fc801cd3594d8d266a75f449e44ef8b5dc08de61d7"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-07-23 00:15:15"
  condition:
    hash.sha256(0, filesize) == "5f37ff54ed0a5cd7c83423fc801cd3594d8d266a75f449e44ef8b5dc08de61d7"
}

rule MalwareBazaar_Mirai_064_a73dce30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a73dce30c9734e4a8e4baef959ba91d0759c05450fcd1993f4e9fc0d45142f42"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-23 00:09:33"
  condition:
    hash.sha256(0, filesize) == "a73dce30c9734e4a8e4baef959ba91d0759c05450fcd1993f4e9fc0d45142f42"
}

rule MalwareBazaar_unknown_065_631be628
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "631be62897d57f0740349269a3eb588ecdd2e89bf367b34421ddaaa200ec2711"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-23 00:08:19"
  condition:
    hash.sha256(0, filesize) == "631be62897d57f0740349269a3eb588ecdd2e89bf367b34421ddaaa200ec2711"
}

rule MalwareBazaar_unknown_066_392571c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "392571c5abe8c58b631fd44b1c2924f7854914754848cb2479ec6889ebce6b4c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-22 23:52:09"
  condition:
    hash.sha256(0, filesize) == "392571c5abe8c58b631fd44b1c2924f7854914754848cb2479ec6889ebce6b4c"
}

rule MalwareBazaar_unknown_067_9bbb4b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bbb4b428b34a0ce31da7183bf4a20f48a5a5639d4acf7afb7bd1d0a4205e098"
    family = "unknown"
    file_name = "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:48"
  condition:
    hash.sha256(0, filesize) == "9bbb4b428b34a0ce31da7183bf4a20f48a5a5639d4acf7afb7bd1d0a4205e098"
}

rule MalwareBazaar_unknown_068_161fb327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "161fb327ee8679b318533e925b958e2c8ff32dd32afc15be3f426a6c5a21c83e"
    family = "unknown"
    file_name = "b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:43"
  condition:
    hash.sha256(0, filesize) == "161fb327ee8679b318533e925b958e2c8ff32dd32afc15be3f426a6c5a21c83e"
}

rule MalwareBazaar_unknown_069_1cf2f74b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cf2f74bf9248cad396a233af682232e9c4bd9a4df068db3847ed43dcb543e0a"
    family = "unknown"
    file_name = "3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:38"
  condition:
    hash.sha256(0, filesize) == "1cf2f74bf9248cad396a233af682232e9c4bd9a4df068db3847ed43dcb543e0a"
}

rule MalwareBazaar_unknown_070_a8b6f96c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8b6f96c0e23b700f97b4104142d75888b2dd2f91d00119810be625958485046"
    family = "unknown"
    file_name = "efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:33"
  condition:
    hash.sha256(0, filesize) == "a8b6f96c0e23b700f97b4104142d75888b2dd2f91d00119810be625958485046"
}

rule MalwareBazaar_unknown_071_63be5f38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e"
    family = "unknown"
    file_name = "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:19"
  condition:
    hash.sha256(0, filesize) == "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e"
}

rule MalwareBazaar_unknown_072_e2bc7981
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2bc7981064d3c9ed898a0f62d659fdc2fc9646dee47a9ca92b9b28b96c27a3b"
    family = "unknown"
    file_name = "e2bc7981064d3c9ed898a0f62d659fdc2fc9646dee47a9ca92b9b28b96c27a3b"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:17"
  condition:
    hash.sha256(0, filesize) == "e2bc7981064d3c9ed898a0f62d659fdc2fc9646dee47a9ca92b9b28b96c27a3b"
}

rule MalwareBazaar_unknown_073_b3232d2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a"
    family = "unknown"
    file_name = "b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:16"
  condition:
    hash.sha256(0, filesize) == "b3232d2cd03b051c59aef952ecfea3358c172351a27a989df31720395c3cbb4a"
}

rule MalwareBazaar_unknown_074_3edfb02c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e"
    family = "unknown"
    file_name = "3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:15"
  condition:
    hash.sha256(0, filesize) == "3edfb02c0e6b2fe4894425cd0d4d2507f7cb11e0958674422729366a0d885c7e"
}

rule MalwareBazaar_unknown_075_efa731b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2"
    family = "unknown"
    file_name = "efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2"
    file_type = "elf"
    first_seen = "2026-07-22 23:31:13"
  condition:
    hash.sha256(0, filesize) == "efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2"
}

rule MalwareBazaar_unknown_076_e149f36c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e149f36cb6c001aa340c388d7684c8a055f59152026e8e0d1d678264d7c084d7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 22:38:50"
  condition:
    hash.sha256(0, filesize) == "e149f36cb6c001aa340c388d7684c8a055f59152026e8e0d1d678264d7c084d7"
}

rule MalwareBazaar_RustyStealer_077_1d233362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d233362395405a19be5da8fc1f3fba060e658fb30718a47eedc0925a7226e52"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 22:33:39"
  condition:
    hash.sha256(0, filesize) == "1d233362395405a19be5da8fc1f3fba060e658fb30718a47eedc0925a7226e52"
}

rule MalwareBazaar_Mirai_078_4e96f129
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e96f12945b9f21345137e7873cf6ef06e64baf5d73469e8b7db7c083479bd17"
    family = "Mirai"
    file_name = "sora.mpsl"
    file_type = "elf"
    first_seen = "2026-07-22 22:05:14"
  condition:
    hash.sha256(0, filesize) == "4e96f12945b9f21345137e7873cf6ef06e64baf5d73469e8b7db7c083479bd17"
}

rule MalwareBazaar_Mirai_079_315130db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "315130dbde6535e561ede03e614340a5bf1ce0a1ca83f89c1a65e8594c1af657"
    family = "Mirai"
    file_name = "sora.arm6"
    file_type = "elf"
    first_seen = "2026-07-22 22:05:07"
  condition:
    hash.sha256(0, filesize) == "315130dbde6535e561ede03e614340a5bf1ce0a1ca83f89c1a65e8594c1af657"
}

rule MalwareBazaar_Mirai_080_751a620a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "751a620ac5101f69eb6e3d208eb4ab08cdcf18092d88b2717dfa975e05b88e2f"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-07-22 22:05:00"
  condition:
    hash.sha256(0, filesize) == "751a620ac5101f69eb6e3d208eb4ab08cdcf18092d88b2717dfa975e05b88e2f"
}

rule MalwareBazaar_Mirai_081_ebcdaa83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebcdaa839b26cc9a2777e6b481e977a77ef77117288fa74b5777a5e9b7f1354a"
    family = "Mirai"
    file_name = "sora.mips"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:57"
  condition:
    hash.sha256(0, filesize) == "ebcdaa839b26cc9a2777e6b481e977a77ef77117288fa74b5777a5e9b7f1354a"
}

rule MalwareBazaar_Mirai_082_2f15c074
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f15c07433d268f50a0e9ba7aa41dfa5f0fd4eeca03b77ab00c222bea1e6f73c"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:53"
  condition:
    hash.sha256(0, filesize) == "2f15c07433d268f50a0e9ba7aa41dfa5f0fd4eeca03b77ab00c222bea1e6f73c"
}

rule MalwareBazaar_Mirai_083_e596320b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e596320b1d716908045f377f843d5c0c3fadb2dc145d3732f83f8acbf1c2297c"
    family = "Mirai"
    file_name = "sora.arm5"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:50"
  condition:
    hash.sha256(0, filesize) == "e596320b1d716908045f377f843d5c0c3fadb2dc145d3732f83f8acbf1c2297c"
}

rule MalwareBazaar_Mirai_084_c1def8cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1def8cce8b6ecb69adf65c60d132981789e7460c38a043795f6826f7a35f3b9"
    family = "Mirai"
    file_name = "sora.ppc"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:44"
  condition:
    hash.sha256(0, filesize) == "c1def8cce8b6ecb69adf65c60d132981789e7460c38a043795f6826f7a35f3b9"
}

rule MalwareBazaar_Mirai_085_4d4df29c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d4df29c04bfaa7e15f0ed6d6183375aec20e06115da16e6577aa869c0bec081"
    family = "Mirai"
    file_name = "sora.m68k"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:09"
  condition:
    hash.sha256(0, filesize) == "4d4df29c04bfaa7e15f0ed6d6183375aec20e06115da16e6577aa869c0bec081"
}

rule MalwareBazaar_unknown_086_3d5c61ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d5c61ac98e4f4576bf44d8023a9ff514535d422ec97d2e7aef39fd6ad950035"
    family = "unknown"
    file_name = "ipmiv2.xml"
    file_type = "unknown"
    first_seen = "2026-07-22 22:04:08"
  condition:
    hash.sha256(0, filesize) == "3d5c61ac98e4f4576bf44d8023a9ff514535d422ec97d2e7aef39fd6ad950035"
}

rule MalwareBazaar_Mirai_087_fdf4a9e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdf4a9e66cd7709a5b9d53ee60640951030550b1f7270f993e5b428264527931"
    family = "Mirai"
    file_name = "sora.mpsl"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:07"
  condition:
    hash.sha256(0, filesize) == "fdf4a9e66cd7709a5b9d53ee60640951030550b1f7270f993e5b428264527931"
}

rule MalwareBazaar_Mirai_088_baa7ca2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baa7ca2de29b4ee51bc03301be779a282b55a2e2739d4c0fe6cedaa37b762d08"
    family = "Mirai"
    file_name = "sora.arm6"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:06"
  condition:
    hash.sha256(0, filesize) == "baa7ca2de29b4ee51bc03301be779a282b55a2e2739d4c0fe6cedaa37b762d08"
}

rule MalwareBazaar_Mirai_089_0098ea36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0098ea36c6295429a874ee13e707c1e05c573f18290f035fac1a64b74c8c2ae6"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:04"
  condition:
    hash.sha256(0, filesize) == "0098ea36c6295429a874ee13e707c1e05c573f18290f035fac1a64b74c8c2ae6"
}

rule MalwareBazaar_Mirai_090_ea96505d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea96505d42088957397f4358b6413bae386eae80194ee7252adb0e3ddbcdf096"
    family = "Mirai"
    file_name = "sora.mips"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:03"
  condition:
    hash.sha256(0, filesize) == "ea96505d42088957397f4358b6413bae386eae80194ee7252adb0e3ddbcdf096"
}

rule MalwareBazaar_Mirai_091_7779c5dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7779c5dd83ce0188bc3d6de963e2bccedbdb783a79756fd7881a158d67277b8a"
    family = "Mirai"
    file_name = "sora.spc"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:02"
  condition:
    hash.sha256(0, filesize) == "7779c5dd83ce0188bc3d6de963e2bccedbdb783a79756fd7881a158d67277b8a"
}

rule MalwareBazaar_Mirai_092_0e1d15e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e1d15e29ccec3c49b646470a7a483f4cc5a533787c9e91ee8579be0115167fa"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-07-22 22:04:01"
  condition:
    hash.sha256(0, filesize) == "0e1d15e29ccec3c49b646470a7a483f4cc5a533787c9e91ee8579be0115167fa"
}

rule MalwareBazaar_Mirai_093_953b23a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "953b23a485f03ff659a570c9f2ff4efa3fa053c13252914112aba5d95302ba97"
    family = "Mirai"
    file_name = "sora.arm5"
    file_type = "elf"
    first_seen = "2026-07-22 22:03:59"
  condition:
    hash.sha256(0, filesize) == "953b23a485f03ff659a570c9f2ff4efa3fa053c13252914112aba5d95302ba97"
}

rule MalwareBazaar_Mirai_094_8d7e5add
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d7e5addf9b3c791a5be49062a69f91c540a6d5c047ec82c20deafe69d4149f3"
    family = "Mirai"
    file_name = "sora.sh4"
    file_type = "elf"
    first_seen = "2026-07-22 22:03:58"
  condition:
    hash.sha256(0, filesize) == "8d7e5addf9b3c791a5be49062a69f91c540a6d5c047ec82c20deafe69d4149f3"
}

rule MalwareBazaar_Mirai_095_22967371
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22967371fd7a84e18a2c3551c06d244fd94b747d9e61eef5282c3b04af645f90"
    family = "Mirai"
    file_name = "sora.ppc"
    file_type = "elf"
    first_seen = "2026-07-22 22:03:57"
  condition:
    hash.sha256(0, filesize) == "22967371fd7a84e18a2c3551c06d244fd94b747d9e61eef5282c3b04af645f90"
}

rule MalwareBazaar_unknown_096_f5a92dca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5a92dcadc6bed2e1cf5efff18221929b0a3fbb7db1a69f26f53f4c7295fab35"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-22 21:52:09"
  condition:
    hash.sha256(0, filesize) == "f5a92dcadc6bed2e1cf5efff18221929b0a3fbb7db1a69f26f53f4c7295fab35"
}

rule MalwareBazaar_unknown_097_4b8af546
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b8af5466ec8215e85333376a4bceefadad95befd9cbb8008567f5cf48fec6bb"
    family = "unknown"
    file_name = "4b8af5466ec8215e85333376a4bceefadad95befd9cbb8008567f5cf48fec6bb.exe.exe"
    file_type = "exe"
    first_seen = "2026-07-22 21:41:12"
  condition:
    hash.sha256(0, filesize) == "4b8af5466ec8215e85333376a4bceefadad95befd9cbb8008567f5cf48fec6bb"
}

rule MalwareBazaar_unknown_098_de366c8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de366c8e91207ad27a30fdf10182d63512dc45aa97f077c9859c5678a7bd144c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-22 21:38:18"
  condition:
    hash.sha256(0, filesize) == "de366c8e91207ad27a30fdf10182d63512dc45aa97f077c9859c5678a7bd144c"
}

rule MalwareBazaar_unknown_099_2bddfd2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bddfd2a2be55a42a621a4c234f39e2a5756557f6ec03ef72eb7d1880e1a02fe"
    family = "unknown"
    file_name = "2bddfd2a2be55a42a621a4c234f39e2a5756557f6ec03ef72eb7d1880e1a02fe"
    file_type = "elf"
    first_seen = "2026-07-22 21:18:53"
  condition:
    hash.sha256(0, filesize) == "2bddfd2a2be55a42a621a4c234f39e2a5756557f6ec03ef72eb7d1880e1a02fe"
}

rule MalwareBazaar_unknown_100_5b0f66b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b0f66b45f70e1976a61be44739d0e1f2a554a6b314ae4237d670a02e4614fe5"
    family = "unknown"
    file_name = "peak.sh"
    file_type = "sh"
    first_seen = "2026-07-22 21:05:46"
  condition:
    hash.sha256(0, filesize) == "5b0f66b45f70e1976a61be44739d0e1f2a554a6b314ae4237d670a02e4614fe5"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

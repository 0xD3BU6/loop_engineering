# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-25

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 655 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 655 |
| Unique family labels | 8 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 46 |
| Mirai | 44 |
| SalatStealer | 2 |
| RustyStealer | 2 |
| Amadey | 2 |
| WannaCry | 2 |
| Vidar | 1 |
| ConnectWise | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 45 |
| exe | 19 |
| macho | 18 |
| sh | 5 |
| iso | 3 |
| js | 2 |
| apk | 2 |
| ps1 | 2 |
| gz | 1 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `579080b865b3ad6d`

| Field | Value |
|---|---|
| SHA-256 | `579080b865b3ad6d5801f001c05d63091ece5e6d358a260568cb6471a21dc665` |
| Family label | `unknown` |
| File name | `579080b865b3ad6d.js` |
| File type | `js` |
| First seen | `2026-10-25 04:47:35` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcf5caa6aa08ef4afb3a895803e194ae` |
| SHA-1 | `5433a9666f3b3921dc8156c8f51fa8ddb06d6cea` |
| SHA-256 | `579080b865b3ad6d5801f001c05d63091ece5e6d358a260568cb6471a21dc665` |
| SHA3-384 | `9dfa07a21d2282ecd07991ef7154bb2bb8f044a0ffd342d619ee81e724e13eff731d054ee37f8d6f1b13f0f5a641ff0b` |
| TLSH | `T18B722AF87765206A03633532207F9102D173EB118D5BA050A2E28A917DECF6BE677FC8` |
| SSDEEP | `384:DqgrrNbSeKaCJlcK1BTg9P0pB1xAvnQ7D+sjNU:rvNbSpaSWK1BTg2pvxAvnQ7yspU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_579080b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "579080b865b3ad6d5801f001c05d63091ece5e6d358a260568cb6471a21dc665"
    family = "unknown"
    file_name = "579080b865b3ad6d.js"
    file_type = "js"
    first_seen = "2026-10-25 04:47:35"
  condition:
    hash.sha256(0, filesize) == "579080b865b3ad6d5801f001c05d63091ece5e6d358a260568cb6471a21dc665"
}
```

### Sample 2: `0bdc6590285d46ca`

| Field | Value |
|---|---|
| SHA-256 | `0bdc6590285d46cafdea0cf8f136beeacc120aee708285d2c656a7f615514990` |
| Family label | `unknown` |
| File name | `rev.sh` |
| File type | `sh` |
| First seen | `2026-10-25 04:39:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a730c8ab36c70abe2d7d71003cc7b8a7` |
| SHA-1 | `a8e94b5890d0bd825c1dc2c07e218f965a247473` |
| SHA-256 | `0bdc6590285d46cafdea0cf8f136beeacc120aee708285d2c656a7f615514990` |
| SHA3-384 | `353b71385f9e6818ae95376ed7b0afa3ff8dbad9dc37cc74627162cc8d31ae131d682ae37b6a26d66903e99ee5f76ebd` |
| TLSH | `T12E219AB2F5F169B53B30C898A24691203BDA2BC29B8CD8E2897C5AA13637544E0A0B10` |
| SSDEEP | `24:w1NL+e/2w2Br+SrNvNSL5lOKMt0TGz5lOKMt0TGP:wTaL6SuOKu0TGGKu0TGP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_0bdc6590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bdc6590285d46cafdea0cf8f136beeacc120aee708285d2c656a7f615514990"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-10-25 04:39:43"
  condition:
    hash.sha256(0, filesize) == "0bdc6590285d46cafdea0cf8f136beeacc120aee708285d2c656a7f615514990"
}
```

### Sample 3: `47881d6351a79009`

| Field | Value |
|---|---|
| SHA-256 | `47881d6351a790090a82c7df270b27e430d1d09c967f9e32af40c49edb763791` |
| Family label | `unknown` |
| File name | `47881d6351a790090a82c7df270b27e430d1d09c967f9e32af40c49edb763791` |
| File type | `gz` |
| First seen | `2026-10-25 03:51:08` |
| Reporter | `thinngo` |
| Tags | `dota3, gz, honeypot, outlaw` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3150895aa401e9b2be8d75753b19ea2b` |
| SHA-1 | `0e74d9dc0a3e2b0ca7fa28243eb9c4da892e5bd7` |
| SHA-256 | `47881d6351a790090a82c7df270b27e430d1d09c967f9e32af40c49edb763791` |
| SHA3-384 | `6af03b17e7b66ed6b39206fcb4a337e29933a8de865155bbffb98e507bc48a10db987887823b2ec9cd63075a50e294f0` |
| TLSH | `T19C2633902C652167D6D1F47BCF373B3ADAC77E65A4170308FB2DA5CB629AC41C2E06A4` |
| SSDEEP | `98304:j58JjEg9aVFX604ZT1Zu9dI7qmVZ1X/k3xebJuiga/0/:WJjEXVFK04ZJo9d9mVDexeNuins/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_47881d63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47881d6351a790090a82c7df270b27e430d1d09c967f9e32af40c49edb763791"
    family = "unknown"
    file_name = "47881d6351a790090a82c7df270b27e430d1d09c967f9e32af40c49edb763791"
    file_type = "gz"
    first_seen = "2026-10-25 03:51:08"
  condition:
    hash.sha256(0, filesize) == "47881d6351a790090a82c7df270b27e430d1d09c967f9e32af40c49edb763791"
}
```

### Sample 4: `a016f6371a48aece`

| Field | Value |
|---|---|
| SHA-256 | `a016f6371a48aeceb793cc80e22bbcf2bb946525c6500b56530ee0cd7751ce58` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-25 03:43:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4d003e7bbc2a324e8e53523419cee23` |
| SHA-1 | `1d85e93f1a5c8b7fd35ca1dee48b728a4ccafd28` |
| SHA-256 | `a016f6371a48aeceb793cc80e22bbcf2bb946525c6500b56530ee0cd7751ce58` |
| SHA3-384 | `c4a5fdab37451f1e49cb73b2f412b900e1ccf5634b88f2d4583364c4c579e82d0680171d6e93085fe40458974ebcbb5b` |
| TLSH | `T15A556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmz:OSCX9B9tGNnD+pb0qAYPWTM2wza66` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_a016f637
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a016f6371a48aeceb793cc80e22bbcf2bb946525c6500b56530ee0cd7751ce58"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-25 03:43:50"
  condition:
    hash.sha256(0, filesize) == "a016f6371a48aeceb793cc80e22bbcf2bb946525c6500b56530ee0cd7751ce58"
}
```

### Sample 5: `f7862077e802e8cd`

| Field | Value |
|---|---|
| SHA-256 | `f7862077e802e8cdb0117b2c9c2e43ceeed7dcde5b3e6dd7935cae71afd44d5a` |
| Family label | `Mirai` |
| File name | `f7862077e802e8cdb0117b2c9c2e43ceeed7dcde5b3e6dd7935cae71afd44d5a.elf` |
| File type | `elf` |
| First seen | `2026-10-25 03:27:46` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d586717424fe6b263e787eb3f0cf2ed9` |
| SHA-1 | `6e2b08a1a07562a271f4ea24aaab53c4f1d1fc6f` |
| SHA-256 | `f7862077e802e8cdb0117b2c9c2e43ceeed7dcde5b3e6dd7935cae71afd44d5a` |
| SHA3-384 | `700e1eae4584747fc0628922440121273500af6806db5e33b9eec8c1838aa0836bc2da95318f3ff28afae843e77719e7` |
| TLSH | `T122125047A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5AlTTej6TNJ9VTNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTcTTfTpV3dfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_f7862077
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7862077e802e8cdb0117b2c9c2e43ceeed7dcde5b3e6dd7935cae71afd44d5a"
    family = "Mirai"
    file_name = "f7862077e802e8cdb0117b2c9c2e43ceeed7dcde5b3e6dd7935cae71afd44d5a.elf"
    file_type = "elf"
    first_seen = "2026-10-25 03:27:46"
  condition:
    hash.sha256(0, filesize) == "f7862077e802e8cdb0117b2c9c2e43ceeed7dcde5b3e6dd7935cae71afd44d5a"
}
```

### Sample 6: `f828c277b3316e0e`

| Field | Value |
|---|---|
| SHA-256 | `f828c277b3316e0ee7a13b35b00c26553785e7e260d2d9f386ad97b94e6dbfe2` |
| Family label | `Vidar` |
| File name | `f828c277b3316e0ee7a13b35b00c26553785e7e260d2d9f386ad97b94e6dbfe2.bin` |
| File type | `exe` |
| First seen | `2026-10-25 03:13:56` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `765f611d6825aa47ce5b35d1e5a88c25` |
| SHA-1 | `9b8ff1883024abc42c429a947f24a9858c7a11eb` |
| SHA-256 | `f828c277b3316e0ee7a13b35b00c26553785e7e260d2d9f386ad97b94e6dbfe2` |
| SHA3-384 | `0746673d83239a3d12b8dc3cecf9390a06097472611293a503ddb3a985b47483a2470b7615a72370afa5c40dfa8a2807` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T18D069E03AE915C6AC5A963328DB75652373CBC441B3727C73AA077BA3E727D06836724` |
| SSDEEP | `98304:bY0QXl3ennnZnnQnnnnnnnnnnnnnnnnnPnasCvnxnNKnUHsHnTBGnIECVnnnAnnk:b3QVnBGn32` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_006_f828c277
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f828c277b3316e0ee7a13b35b00c26553785e7e260d2d9f386ad97b94e6dbfe2"
    family = "Vidar"
    file_name = "f828c277b3316e0ee7a13b35b00c26553785e7e260d2d9f386ad97b94e6dbfe2.bin"
    file_type = "exe"
    first_seen = "2026-10-25 03:13:56"
  condition:
    hash.sha256(0, filesize) == "f828c277b3316e0ee7a13b35b00c26553785e7e260d2d9f386ad97b94e6dbfe2"
}
```

### Sample 7: `90950ae9570d317b`

| Field | Value |
|---|---|
| SHA-256 | `90950ae9570d317ba26d8a72f45c3d64821d4d2c8a916e78e01c24b6b13368dd` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-25 03:05:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40779f33f106a3030c65dcb1c50e9079` |
| SHA-1 | `6724aaae4cf0324cf88c4b8d62b19b0cae49254a` |
| SHA-256 | `90950ae9570d317ba26d8a72f45c3d64821d4d2c8a916e78e01c24b6b13368dd` |
| SHA3-384 | `598eeee7eeb2db583422c77ec1e7688b2ac4f3e48aeb8af0f673d75815c164c55d4c39250e7e5da0d2a1650f69214a4a` |
| TLSH | `T177556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmm:OSCX9B9tGNnD+pb0qAYPWTM2wza6r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_90950ae9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90950ae9570d317ba26d8a72f45c3d64821d4d2c8a916e78e01c24b6b13368dd"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-25 03:05:38"
  condition:
    hash.sha256(0, filesize) == "90950ae9570d317ba26d8a72f45c3d64821d4d2c8a916e78e01c24b6b13368dd"
}
```

### Sample 8: `0de787cffbec4dcc`

| Field | Value |
|---|---|
| SHA-256 | `0de787cffbec4dcc42e0ecd9491795c7dfe8fe4a955cb67a87544d5c36070982` |
| Family label | `unknown` |
| File name | `0de787cffbec4dcc42e0ecd9491795c7dfe8fe4a955cb67a87544d5c36070982` |
| File type | `elf` |
| First seen | `2026-10-25 03:00:34` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c492c1c77f913c5e7f54941f1c625db9` |
| SHA-1 | `c9406ef348433c57663bb8c0cf734c00c0e71110` |
| SHA-256 | `0de787cffbec4dcc42e0ecd9491795c7dfe8fe4a955cb67a87544d5c36070982` |
| SHA3-384 | `e4529ef82ee2b94f48c6d4e3dbab5ba10e7c36eb54380359f7207d55e5da9724419eaafd993c75362f467d5c4572f338` |
| TLSH | `T19FE5CF1BB59250FDC1E6C070839B9673AA31B85552307E7F62C4AF312F26F20676EB61` |
| SSDEEP | `49152:MOpFRF8oFPvnl50p+0eVlvviccJ1TbXLP9TIy2o162i22mG2zs72gta:FprnVnq+Zvqz1vL9TWo16X22j2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_0de787cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0de787cffbec4dcc42e0ecd9491795c7dfe8fe4a955cb67a87544d5c36070982"
    family = "unknown"
    file_name = "0de787cffbec4dcc42e0ecd9491795c7dfe8fe4a955cb67a87544d5c36070982"
    file_type = "elf"
    first_seen = "2026-10-25 03:00:34"
  condition:
    hash.sha256(0, filesize) == "0de787cffbec4dcc42e0ecd9491795c7dfe8fe4a955cb67a87544d5c36070982"
}
```

### Sample 9: `3fd5cc721a1bc604`

| Field | Value |
|---|---|
| SHA-256 | `3fd5cc721a1bc604d1300c9063eea7e63a3c9bef34fd1aae438b539980621017` |
| Family label | `unknown` |
| File name | `3fd5cc721a1bc604.js` |
| File type | `js` |
| First seen | `2026-10-25 02:32:25` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e7aad5f8722ed7ca7589f535c5d3738` |
| SHA-1 | `a7335daa6ffeda8606294889f2cdf1286831f9b6` |
| SHA-256 | `3fd5cc721a1bc604d1300c9063eea7e63a3c9bef34fd1aae438b539980621017` |
| SHA3-384 | `8c7f124370725c1b0aa35e522bf012c6e5085f16a58d4eeee05e727b1cbcc3e1070f04015f9ada8dde1dddf8f6533d3e` |
| TLSH | `T16B41C2BD3AE261B04A57A06D523FCB04743270237C45D155BACC89989F70FB9955AECC` |
| SSDEEP | `48:b4Y5IdUozuUaCDa3IBJcbj6TeRAk56FbUtw:cY5IdKCD9BJc69Ue` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_3fd5cc72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fd5cc721a1bc604d1300c9063eea7e63a3c9bef34fd1aae438b539980621017"
    family = "unknown"
    file_name = "3fd5cc721a1bc604.js"
    file_type = "js"
    first_seen = "2026-10-25 02:32:25"
  condition:
    hash.sha256(0, filesize) == "3fd5cc721a1bc604d1300c9063eea7e63a3c9bef34fd1aae438b539980621017"
}
```

### Sample 10: `5efc93a848849593`

| Field | Value |
|---|---|
| SHA-256 | `5efc93a8488495931f5b0eda5413a23077808fdcc676903055901be64ff22024` |
| Family label | `unknown` |
| File name | `5efc93a8488495931f5b0eda5413a23077808fdcc676903055901be64ff22024` |
| File type | `elf` |
| First seen | `2026-10-25 02:30:35` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0e876750046dc28844cb3da564a1ab5` |
| SHA-1 | `3f523f9d4804e6fb4aa492d3916f4e0b7ab4aee5` |
| SHA-256 | `5efc93a8488495931f5b0eda5413a23077808fdcc676903055901be64ff22024` |
| SHA3-384 | `9bedc5292aade36f0a2b91492981f2f3ac44c676bbf986878f1f4785e3d01568f022dc02021080fbfe5ce5c6216f575f` |
| TLSH | `T109A5AE1BB59250FDC1D7C070839B9633AA32B49952347E7F62C4AF312E26F20675EB61` |
| SSDEEP | `49152:MOpFRF8oFPvnl50p+0eVlvviccJ1TbXLP9TIy2o16D:FprnVnq+Zvqz1vL9TWo16D` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_5efc93a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5efc93a8488495931f5b0eda5413a23077808fdcc676903055901be64ff22024"
    family = "unknown"
    file_name = "5efc93a8488495931f5b0eda5413a23077808fdcc676903055901be64ff22024"
    file_type = "elf"
    first_seen = "2026-10-25 02:30:35"
  condition:
    hash.sha256(0, filesize) == "5efc93a8488495931f5b0eda5413a23077808fdcc676903055901be64ff22024"
}
```

### Sample 11: `f7e0b6accc041625`

| Field | Value |
|---|---|
| SHA-256 | `f7e0b6accc041625c706774b9bf0dc832d41c30f0ec63e4dc8aa27c1b062f3a1` |
| Family label | `unknown` |
| File name | `f7e0b6accc041625.bin` |
| File type | `exe` |
| First seen | `2026-10-25 02:25:08` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `292dcf4aada13421a53356640c2d0625` |
| SHA-1 | `5ba5fc3bebf7a0230941b15de1318976a5a7aadb` |
| SHA-256 | `f7e0b6accc041625c706774b9bf0dc832d41c30f0ec63e4dc8aa27c1b062f3a1` |
| SHA3-384 | `163c005eea65b20c0fbf5cc558ddb284f63876211bfb6af40848c1ca1d458cf2b275c639f844a795883b247fff3908fe` |
| IMPHASH | `603a12af845feb44eeaee4af0f3efa0b` |
| TLSH | `T115A58D03F6A580F8D75EC078C3469633EA23B89D0925B6AB27D09B253E36F545F0DB19` |
| SSDEEP | `49152:+yq66hizXRpuk+XZDh5KyR7F/dPTrWwIU6istJ6:+ysQgJF1CP+s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_f7e0b6ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7e0b6accc041625c706774b9bf0dc832d41c30f0ec63e4dc8aa27c1b062f3a1"
    family = "unknown"
    file_name = "f7e0b6accc041625.bin"
    file_type = "exe"
    first_seen = "2026-10-25 02:25:08"
  condition:
    hash.sha256(0, filesize) == "f7e0b6accc041625c706774b9bf0dc832d41c30f0ec63e4dc8aa27c1b062f3a1"
}
```

### Sample 12: `ee4a9b4b2661ebb0`

| Field | Value |
|---|---|
| SHA-256 | `ee4a9b4b2661ebb022274343293643073f13baf29622e889a484fd295f3b6196` |
| Family label | `Mirai` |
| File name | `ee4a9b4b2661ebb022274343293643073f13baf29622e889a484fd295f3b6196` |
| File type | `elf` |
| First seen | `2026-10-25 02:24:36` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, Mirai, superh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c177aa0056877a8ee83b0a81402ce900` |
| SHA-1 | `2cb81800cd1310b3b6aba0bdb9d350648406cc70` |
| SHA-256 | `ee4a9b4b2661ebb022274343293643073f13baf29622e889a484fd295f3b6196` |
| SHA3-384 | `3acd5bd4130521d0aff9974382a229b79898a7cce9532a115bd935ca34df03694433ea051640c944f8d399659cbaee50` |
| TLSH | `T180438D37C4262E58E18481F1B8348F714B93A94881976FFE6667C6668047EECF7493F8` |
| SSDEEP | `768:SMbTsh/+a4k125+JeN+UUc2RtpHiMDS0CXExkKDhjvaSoVE+mIClkF19fCaAlI:SMbTO/+5k9kn2M02KDhjylVMICltaw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_ee4a9b4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee4a9b4b2661ebb022274343293643073f13baf29622e889a484fd295f3b6196"
    family = "Mirai"
    file_name = "ee4a9b4b2661ebb022274343293643073f13baf29622e889a484fd295f3b6196"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:36"
  condition:
    hash.sha256(0, filesize) == "ee4a9b4b2661ebb022274343293643073f13baf29622e889a484fd295f3b6196"
}
```

### Sample 13: `d332dc8d033bf968`

| Field | Value |
|---|---|
| SHA-256 | `d332dc8d033bf9687075a977ec3120bee7fcc4586592cc986fd432bb5525f7bc` |
| Family label | `Mirai` |
| File name | `d332dc8d033bf9687075a977ec3120bee7fcc4586592cc986fd432bb5525f7bc` |
| File type | `elf` |
| First seen | `2026-10-25 02:24:29` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, Mirai, sparc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce52d196138087d618e8745f9e87dab5` |
| SHA-1 | `8c7e27d9b5dffe64356031f664f28defdb4433dd` |
| SHA-256 | `d332dc8d033bf9687075a977ec3120bee7fcc4586592cc986fd432bb5525f7bc` |
| SHA3-384 | `b293392346ae8e663507fca736ea61f0d7091558d967d0b4f2c3b2b2939dd9d38ee8d0850b717b1736d16492dc2de5c7` |
| TLSH | `T1D8635B22AA761D27C4E4A97A31F34324B2F2475E25F8CA1D7D710E4EEF65B4022472F9` |
| SSDEEP | `1536:m7PJ6CDtSrG/pX/zZeDd2f3/uU75Ntb7J:mJ8WPV24uUVH7J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_d332dc8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d332dc8d033bf9687075a977ec3120bee7fcc4586592cc986fd432bb5525f7bc"
    family = "Mirai"
    file_name = "d332dc8d033bf9687075a977ec3120bee7fcc4586592cc986fd432bb5525f7bc"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:29"
  condition:
    hash.sha256(0, filesize) == "d332dc8d033bf9687075a977ec3120bee7fcc4586592cc986fd432bb5525f7bc"
}
```

### Sample 14: `caf3c7832bc299ed`

| Field | Value |
|---|---|
| SHA-256 | `caf3c7832bc299ed1157bfc4c089ca44abc76f58f196c0b70283ab3f0f58938c` |
| Family label | `Mirai` |
| File name | `caf3c7832bc299ed1157bfc4c089ca44abc76f58f196c0b70283ab3f0f58938c` |
| File type | `elf` |
| First seen | `2026-10-25 02:24:23` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, m68k, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a3b2f64709c3ff1983ed573ce350e13` |
| SHA-1 | `44eedb127c0cebe9f10861fb4a6aa624464f496e` |
| SHA-256 | `caf3c7832bc299ed1157bfc4c089ca44abc76f58f196c0b70283ab3f0f58938c` |
| SHA3-384 | `353b43be6fe6e17654d74a8f603a26406b028e0ddd59b6984c5e155b27d345c6e74eb5da6db26cfa9fd98bfbebe147e9` |
| TLSH | `T1D4633BD6B800DD7DF84AD77F8813050AB671A35002931F3A67ABF957EC720E85966E82` |
| SSDEEP | `1536:INTEWCVjtXBs29Spn8Kpsvt+8pPnLOTnnF9dpOXk:INT3CVjtxsCSplD8pvLILok` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_caf3c783
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caf3c7832bc299ed1157bfc4c089ca44abc76f58f196c0b70283ab3f0f58938c"
    family = "Mirai"
    file_name = "caf3c7832bc299ed1157bfc4c089ca44abc76f58f196c0b70283ab3f0f58938c"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:23"
  condition:
    hash.sha256(0, filesize) == "caf3c7832bc299ed1157bfc4c089ca44abc76f58f196c0b70283ab3f0f58938c"
}
```

### Sample 15: `1f715216367cfdb4`

| Field | Value |
|---|---|
| SHA-256 | `1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846` |
| Family label | `Mirai` |
| File name | `1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846` |
| File type | `elf` |
| First seen | `2026-10-25 02:24:18` |
| Reporter | `spydisec` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f3b50ea98c724a49e54c9ecfaed85bf` |
| SHA-1 | `e3d07d2b7711b2cd90a7b858a399b7d25db93680` |
| SHA-256 | `1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846` |
| SHA3-384 | `a98e80b498e95f8d21142aaa78c675c71f09591ce2049ac3d5c2d051d55be7fbbece00fc6e6be6ae1e4d33994a117ae1` |
| TLSH | `T13F73F756B8818B12D5D502BAFE1E118E33131B7CE3DEB3129D206B24778B96F0E77916` |
| TELFHASH | `t13501f4498dcc6bccc7f04b09c35db52235c275e5a773006e4d7f2c5e02128c23431825` |
| SSDEEP | `1536:5NnpuPjDPshNucOlmMgV2calyac6I9ibFxfVqTn+353Y3:QPjzsHuplm94cabFtVqTn+3tc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_1f715216
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846"
    family = "Mirai"
    file_name = "1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:18"
  condition:
    hash.sha256(0, filesize) == "1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846"
}
```

### Sample 16: `e77cd1fd16b6d11b`

| Field | Value |
|---|---|
| SHA-256 | `e77cd1fd16b6d11b3cb35a6fa3216f0e892c6fa567cfe2d3ab22199b08ea7d05` |
| Family label | `Mirai` |
| File name | `e77cd1fd16b6d11b3cb35a6fa3216f0e892c6fa567cfe2d3ab22199b08ea7d05` |
| File type | `elf` |
| First seen | `2026-10-25 02:24:11` |
| Reporter | `spydisec` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b595f024fda24f4daeee0b8eb9bd3874` |
| SHA-1 | `14208c9e597868cd5ffc58d50f1c7c18399be974` |
| SHA-256 | `e77cd1fd16b6d11b3cb35a6fa3216f0e892c6fa567cfe2d3ab22199b08ea7d05` |
| SHA3-384 | `6d64ee8dfbfd5d70c03d3189cd02618e4ce94666816fa0f5f71c3199935ebfda8f05d7cacf4602f094fa8c530cbd46cd` |
| TLSH | `T171931A46BD819F12D4D621BAFB9E414933536FB8E3FE7112DC206F50238A99B0E77612` |
| TELFHASH | `t10c011050c88489ed93f0de68c099f333245535e4f307191e0987ab5904228c2e322422` |
| SSDEEP | `1536:TanvKPzf7bttWDcJPPvSYeaGKmj1kHdIOllkMilCB/Z4Y7P6Lu:pPzTbtgDSPPvSYearmj1kHezCB/Z406S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_e77cd1fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e77cd1fd16b6d11b3cb35a6fa3216f0e892c6fa567cfe2d3ab22199b08ea7d05"
    family = "Mirai"
    file_name = "e77cd1fd16b6d11b3cb35a6fa3216f0e892c6fa567cfe2d3ab22199b08ea7d05"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:11"
  condition:
    hash.sha256(0, filesize) == "e77cd1fd16b6d11b3cb35a6fa3216f0e892c6fa567cfe2d3ab22199b08ea7d05"
}
```

### Sample 17: `d959381329171033`

| Field | Value |
|---|---|
| SHA-256 | `d959381329171033019f0407a82f5ae23760f4a596940a7635592093792be8c5` |
| Family label | `Mirai` |
| File name | `d959381329171033019f0407a82f5ae23760f4a596940a7635592093792be8c5` |
| File type | `elf` |
| First seen | `2026-10-25 02:24:04` |
| Reporter | `spydisec` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7800cb8eedd91c14f0ee0fe0a30da94` |
| SHA-1 | `851cbdfb56f7e5b48bc496909b3c4f7b61fbe8c3` |
| SHA-256 | `d959381329171033019f0407a82f5ae23760f4a596940a7635592093792be8c5` |
| SHA3-384 | `a8ed61b5260e8512589822545a2e74889df29c94f1d41543b60b3c12693e006bbf50e43ac3f581777ef1486ecd4805af` |
| TLSH | `T162531891BCD19A13C6D01277FB5E428D732657A8D2EE7317AC262F11378B82F0E67642` |
| TELFHASH | `t1470189a056831accb3d1d55ec5de2333932936fc1b12252c63993baf47b7943e52583a` |
| SSDEEP | `768:1SRYjBtNMHwy0Wp4qe/9Wy1R+dlUAsT/U2maLZwE+CG8/NRFoQQAUdwPMkG0KXcX:qYjaw5WWzR+6M2maLxJlUVkL4RiuKvU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_d9593813
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d959381329171033019f0407a82f5ae23760f4a596940a7635592093792be8c5"
    family = "Mirai"
    file_name = "d959381329171033019f0407a82f5ae23760f4a596940a7635592093792be8c5"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:04"
  condition:
    hash.sha256(0, filesize) == "d959381329171033019f0407a82f5ae23760f4a596940a7635592093792be8c5"
}
```

### Sample 18: `d872e02c03b4896f`

| Field | Value |
|---|---|
| SHA-256 | `d872e02c03b4896fd58eea4adfc8dd62342661808595f456f64cf1d3cee43a25` |
| Family label | `Mirai` |
| File name | `d872e02c03b4896fd58eea4adfc8dd62342661808595f456f64cf1d3cee43a25` |
| File type | `elf` |
| First seen | `2026-10-25 02:23:57` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, Mirai, powerpc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad37f4de25e371b846058cbe69db4146` |
| SHA-1 | `717cd488ff726354733f3754bdd59d8644385fe4` |
| SHA-256 | `d872e02c03b4896fd58eea4adfc8dd62342661808595f456f64cf1d3cee43a25` |
| SHA3-384 | `e17f3c9fda37b25502f2be0b869b0d82e71b08042cdc712507728e8d8f7cb7b8aa926f8f020f3f797bc8530aace810c2` |
| TLSH | `T124532B02731C0947D1A35AB02A3F27D093EEE99021F4F68D351E974A9275E3A1686FCD` |
| SSDEEP | `768:d7EeP0q9yb6V2MRprtzRcjs4tls4cF/YjxTE5B9c5NWYzpbqTUGuC8Ilc8SSaFxU:TP0qUWVT1yG1YYc3W4ZqZ8Iz611F+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_d872e02c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d872e02c03b4896fd58eea4adfc8dd62342661808595f456f64cf1d3cee43a25"
    family = "Mirai"
    file_name = "d872e02c03b4896fd58eea4adfc8dd62342661808595f456f64cf1d3cee43a25"
    file_type = "elf"
    first_seen = "2026-10-25 02:23:57"
  condition:
    hash.sha256(0, filesize) == "d872e02c03b4896fd58eea4adfc8dd62342661808595f456f64cf1d3cee43a25"
}
```

### Sample 19: `766aa9a5da632922`

| Field | Value |
|---|---|
| SHA-256 | `766aa9a5da63292222ae34b9037d8cd606db3cdedf3167389d40b3dfaf231367` |
| Family label | `Mirai` |
| File name | `766aa9a5da63292222ae34b9037d8cd606db3cdedf3167389d40b3dfaf231367` |
| File type | `elf` |
| First seen | `2026-10-25 02:23:50` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, mips, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f4746b57cad85deafb51db330fe14ff` |
| SHA-1 | `3d385327d9e6523870c44c79fc5cf184483bea68` |
| SHA-256 | `766aa9a5da63292222ae34b9037d8cd606db3cdedf3167389d40b3dfaf231367` |
| SHA3-384 | `ef27023ea4873bca70b54ed93590ecf780fb9e65a97808ac14fdca9bcab1a96cc67e30ca671daab5cea5f6ea413c6180` |
| TLSH | `T1BB83F715BB904FBBEC6FCD370AA9170134CC591A22A97B3A7934C91CF64F54B06E3968` |
| SSDEEP | `1536:eGCdmM8Sk3OMm9BHLH7Y+qvCeWNa+aZ79NaHE+Z:eGCdmMj9PNa+ainZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_766aa9a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "766aa9a5da63292222ae34b9037d8cd606db3cdedf3167389d40b3dfaf231367"
    family = "Mirai"
    file_name = "766aa9a5da63292222ae34b9037d8cd606db3cdedf3167389d40b3dfaf231367"
    file_type = "elf"
    first_seen = "2026-10-25 02:23:50"
  condition:
    hash.sha256(0, filesize) == "766aa9a5da63292222ae34b9037d8cd606db3cdedf3167389d40b3dfaf231367"
}
```

### Sample 20: `336d289148053d2a`

| Field | Value |
|---|---|
| SHA-256 | `336d289148053d2ad4530e1dcdeba03c14ef731854986b580a243faa20c5fe85` |
| Family label | `Mirai` |
| File name | `336d289148053d2ad4530e1dcdeba03c14ef731854986b580a243faa20c5fe85` |
| File type | `elf` |
| First seen | `2026-10-25 02:23:43` |
| Reporter | `spydisec` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d566704bb7ba2d4ce05cdc9b4742c39f` |
| SHA-1 | `cc644853031c662c417f5a7b0429726d4f6920ad` |
| SHA-256 | `336d289148053d2ad4530e1dcdeba03c14ef731854986b580a243faa20c5fe85` |
| SHA3-384 | `eb54bc1e66099df721d74ae89699978c0f901e7261a2a049a1d7aea777b800919ca57c9bd48d21947db5d9bb5de1f309` |
| TLSH | `T1E4532991BC919A13C6D012B7FB6E428D332757A8D2EE73039C266F11378792F0E67652` |
| TELFHASH | `t1ad018ea0968907ccb3c0d509d1ca5217c71e31ad4e21251c17d87eae02b75c17635436` |
| SSDEEP | `768:2Z6XMQwnZpkW/hDqx9eY1RMXdssh7LREpKP+CEo/NRjn3b1azMrASELOoRZXn8V/:HXgnZpZ/8RMH3RE+XLfr4LXzX8SOEvO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_336d2891
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "336d289148053d2ad4530e1dcdeba03c14ef731854986b580a243faa20c5fe85"
    family = "Mirai"
    file_name = "336d289148053d2ad4530e1dcdeba03c14ef731854986b580a243faa20c5fe85"
    file_type = "elf"
    first_seen = "2026-10-25 02:23:43"
  condition:
    hash.sha256(0, filesize) == "336d289148053d2ad4530e1dcdeba03c14ef731854986b580a243faa20c5fe85"
}
```

### Sample 21: `1c16b8d89542e113`

| Field | Value |
|---|---|
| SHA-256 | `1c16b8d89542e11371cae61830489b86aab13ad82a872ee7c892cf2333078a6d` |
| Family label | `Mirai` |
| File name | `1c16b8d89542e11371cae61830489b86aab13ad82a872ee7c892cf2333078a6d` |
| File type | `elf` |
| First seen | `2026-10-25 02:23:36` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, mips, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ea315ca152bece348c0ead68f766dc3` |
| SHA-1 | `0e9760508d8bebacc94c55f13350c3876a5af6e0` |
| SHA-256 | `1c16b8d89542e11371cae61830489b86aab13ad82a872ee7c892cf2333078a6d` |
| SHA3-384 | `d6ed3abcfa96b6701f4b320183f7b74aef440b84e85ac3c79a69fb9cd022df5b3c00f893572458fa51c1bb7cd622031b` |
| TLSH | `T1A673B71D2E618FADF7A8C23547B78F21939C378627E1D685E29CD6001F6034E645FBA8` |
| TELFHASH | `t108110908993863f49bb51d996bedff75e49170ef47215e378e00e9ae5a2dc429a00c1c` |
| SSDEEP | `1536:4iOT1XOVgCdSQ0HAuzYWR9KqZKpoLGexNGz:4PTVOxdSQ0OqZKpoLNGz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_1c16b8d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c16b8d89542e11371cae61830489b86aab13ad82a872ee7c892cf2333078a6d"
    family = "Mirai"
    file_name = "1c16b8d89542e11371cae61830489b86aab13ad82a872ee7c892cf2333078a6d"
    file_type = "elf"
    first_seen = "2026-10-25 02:23:36"
  condition:
    hash.sha256(0, filesize) == "1c16b8d89542e11371cae61830489b86aab13ad82a872ee7c892cf2333078a6d"
}
```

### Sample 22: `44aaf7dc43cf054f`

| Field | Value |
|---|---|
| SHA-256 | `44aaf7dc43cf054f82c676257ad7941fdddeb115b687804164ec673e9f098ad4` |
| Family label | `Mirai` |
| File name | `44aaf7dc43cf054f82c676257ad7941fdddeb115b687804164ec673e9f098ad4` |
| File type | `elf` |
| First seen | `2026-10-25 02:23:30` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, i386, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e9800d3cb6258fc7eab1c9de0164270` |
| SHA-1 | `762faf046b0ce609bc462a5df88e24ac57bddd35` |
| SHA-256 | `44aaf7dc43cf054f82c676257ad7941fdddeb115b687804164ec673e9f098ad4` |
| SHA3-384 | `ed5c1bc68c4b05057d17a205b703bbf9459c5039a5c967da64effc8d100678202a7740f18068f566ac0e1bd45d9fc649` |
| TLSH | `T1BD333AC49647E8F5FC560A752073E7738BB3F93E0129D997D368A532B862A01E60739C` |
| TELFHASH | `t1b921a2bb2e7648fd73d1ac48c31a26e3163ad2771aa032f545b66d9133f1ed480a4836` |
| SSDEEP | `1536:5NaTy+zeC/aqfWb2FySj0F4NP0J5rZ3WasqTgjw7Sa:6e+zR/3fWU64N8vrUasMiw5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_44aaf7dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44aaf7dc43cf054f82c676257ad7941fdddeb115b687804164ec673e9f098ad4"
    family = "Mirai"
    file_name = "44aaf7dc43cf054f82c676257ad7941fdddeb115b687804164ec673e9f098ad4"
    file_type = "elf"
    first_seen = "2026-10-25 02:23:30"
  condition:
    hash.sha256(0, filesize) == "44aaf7dc43cf054f82c676257ad7941fdddeb115b687804164ec673e9f098ad4"
}
```

### Sample 23: `30f4e1bc0cd96d42`

| Field | Value |
|---|---|
| SHA-256 | `30f4e1bc0cd96d4210765b18533eb0c5343f155a36b1a567132538242487d09c` |
| Family label | `unknown` |
| File name | `com.hagaseca.thost9.apk` |
| File type | `apk` |
| First seen | `2026-10-25 02:20:17` |
| Reporter | `tipo_deincognito` |
| Tags | `apk, dropper, hagaseca, loader, stage2` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfd9c7dee4f4a16d636917de35a510b7` |
| SHA-1 | `3a8138debf528361bf7093e3aa85a5f84105ebf6` |
| SHA-256 | `30f4e1bc0cd96d4210765b18533eb0c5343f155a36b1a567132538242487d09c` |
| SHA3-384 | `426cd2dbe5d50efc6fb626fd10922647f5f476e5f66b062c57d1c9bb44d20cbbcb4be2e1ab4cbc4fa399fb19fcc21ad5` |
| TLSH | `T1FD13E16B9B955667E336B7700AA0CBE27936CC5B33033B695841A3E16CF923BC710485` |
| SSDEEP | `768:pUXoMlAGza+XLHaVm6ce7CV70WSmujunaMP5Cj181C:pooM4IHaVfce7CVtcjpMoj181C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_30f4e1bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30f4e1bc0cd96d4210765b18533eb0c5343f155a36b1a567132538242487d09c"
    family = "unknown"
    file_name = "com.hagaseca.thost9.apk"
    file_type = "apk"
    first_seen = "2026-10-25 02:20:17"
  condition:
    hash.sha256(0, filesize) == "30f4e1bc0cd96d4210765b18533eb0c5343f155a36b1a567132538242487d09c"
}
```

### Sample 24: `eb88cf325bda936f`

| Field | Value |
|---|---|
| SHA-256 | `eb88cf325bda936f2f53ea935ab8cdcd27cc75fdf9f06a6e203a9fd3eb5b9fe9` |
| Family label | `unknown` |
| File name | `exploit_hp-021419-758075.sh` |
| File type | `sh` |
| First seen | `2026-10-25 02:14:43` |
| Reporter | `BedRock` |
| Tags | `BedrockSafeguard, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a87be78dade4e51f7f2a38ee092f3131` |
| SHA-1 | `e3bcd6df4aec0b5cf46134955c881329d7ab11fd` |
| SHA-256 | `eb88cf325bda936f2f53ea935ab8cdcd27cc75fdf9f06a6e203a9fd3eb5b9fe9` |
| SHA3-384 | `23cf4bc95b056b8bbc40181f7c3c82fd7eb2438dd8eba356812d29e8a66d8b86f636266a3fd17799cc32d3c5f4e5ce1d` |
| TLSH | `TNULL` |
| SSDEEP | `3:3AXKAJJvuXARfn:Hs8XARf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_eb88cf32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb88cf325bda936f2f53ea935ab8cdcd27cc75fdf9f06a6e203a9fd3eb5b9fe9"
    family = "unknown"
    file_name = "exploit_hp-021419-758075.sh"
    file_type = "sh"
    first_seen = "2026-10-25 02:14:43"
  condition:
    hash.sha256(0, filesize) == "eb88cf325bda936f2f53ea935ab8cdcd27cc75fdf9f06a6e203a9fd3eb5b9fe9"
}
```

### Sample 25: `ccb17e61a3dcf640`

| Field | Value |
|---|---|
| SHA-256 | `ccb17e61a3dcf6408f6176a50dfcba804497a71581de6158d9d37a4125a5735b` |
| Family label | `unknown` |
| File name | `exploit_hp-185800-ffa3fe.sh` |
| File type | `sh` |
| First seen | `2026-10-25 02:09:04` |
| Reporter | `BedRock` |
| Tags | `BedrockSafeguard, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e17fade9d2044b5073eb66f96021ef4` |
| SHA-1 | `6a87da218e3a6ccb2f25dd9053a779dbd30ae36e` |
| SHA-256 | `ccb17e61a3dcf6408f6176a50dfcba804497a71581de6158d9d37a4125a5735b` |
| SHA3-384 | `fa5ca3408d224f66d1bc99b72601df21a5e8bce2ddc869fa25b5970a5436e7aaaaad9bbc430512f71b3f45d4a946adc6` |
| TLSH | `TNULL` |
| SSDEEP | `3:iCtM2LRJn:4k` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_ccb17e61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccb17e61a3dcf6408f6176a50dfcba804497a71581de6158d9d37a4125a5735b"
    family = "unknown"
    file_name = "exploit_hp-185800-ffa3fe.sh"
    file_type = "sh"
    first_seen = "2026-10-25 02:09:04"
  condition:
    hash.sha256(0, filesize) == "ccb17e61a3dcf6408f6176a50dfcba804497a71581de6158d9d37a4125a5735b"
}
```

### Sample 26: `a27095084f1a8a42`

| Field | Value |
|---|---|
| SHA-256 | `a27095084f1a8a42c556bf27c41812e22af8cd68858271507878415123b6e62c` |
| Family label | `Mirai` |
| File name | `a27095084f1a8a42c556bf27c41812e22af8cd68858271507878415123b6e62c` |
| File type | `sh` |
| First seen | `2026-10-25 02:08:51` |
| Reporter | `spydisec` |
| Tags | `cowrie, dropper, honeypot, Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31651e29cf7abe34e5f66f3d2dc4a164` |
| SHA-1 | `8852b2707ae4d8813beee3190caedfa53fe12faa` |
| SHA-256 | `a27095084f1a8a42c556bf27c41812e22af8cd68858271507878415123b6e62c` |
| SHA3-384 | `1b784447e3bbbbb7343267505b54419ece6f339d39c79b2fa1141b93d33dc197815e3fd96aaa174f2d635b87a468f02d` |
| TLSH | `T128A1C2A413EBD4B79F938F18F226CB29E50175AE12CD7D04DCAD6991E18EC84B30AF51` |
| SSDEEP | `48:vpKCh7hEhPeph+hnhAhoph0hNh2hG+phAhEEhChEmph0hNh2hAyphahzhMhnsphN:vKeAE+JTjsGxDDy1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_a2709508
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a27095084f1a8a42c556bf27c41812e22af8cd68858271507878415123b6e62c"
    family = "Mirai"
    file_name = "a27095084f1a8a42c556bf27c41812e22af8cd68858271507878415123b6e62c"
    file_type = "sh"
    first_seen = "2026-10-25 02:08:51"
  condition:
    hash.sha256(0, filesize) == "a27095084f1a8a42c556bf27c41812e22af8cd68858271507878415123b6e62c"
}
```

### Sample 27: `23aa5f6cd8d20391`

| Field | Value |
|---|---|
| SHA-256 | `23aa5f6cd8d203918af2a80b7dde7b4aa5d0032006150b752cc710c724f0e5dd` |
| Family label | `unknown` |
| File name | `open_dir_193_149_176_102_bins.sh` |
| File type | `sh` |
| First seen | `2026-10-25 02:01:45` |
| Reporter | `BedRock` |
| Tags | `BedrockSafeguard, honeypot, Mozi, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4b0865e9fe2459295ac2d85db67c108` |
| SHA-1 | `c0374984a31eb2e98d7cfb4b9a9f235dc596c46f` |
| SHA-256 | `23aa5f6cd8d203918af2a80b7dde7b4aa5d0032006150b752cc710c724f0e5dd` |
| SHA3-384 | `da7b5e7fdbe2448be3c37bfaa4731ce07ffec2f98c97552a7c370921d2024cdc4b0b0d22471b49183f20fbbdf127d873` |
| TLSH | `T19A017BC822A00365DCCC478A737A60A3B2469CED99824DA043995D35044DFB9B9A4E21` |
| SSDEEP | `12:AjKV8KIaEEYyKYc4GhZK5JiOwk6oJ+ps+RrFH2sUHhrRBrJa/:YKV8vE8VXK5JiOwXowSo1VUBNc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_23aa5f6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23aa5f6cd8d203918af2a80b7dde7b4aa5d0032006150b752cc710c724f0e5dd"
    family = "unknown"
    file_name = "open_dir_193_149_176_102_bins.sh"
    file_type = "sh"
    first_seen = "2026-10-25 02:01:45"
  condition:
    hash.sha256(0, filesize) == "23aa5f6cd8d203918af2a80b7dde7b4aa5d0032006150b752cc710c724f0e5dd"
}
```

### Sample 28: `a6716a57efc3a128`

| Field | Value |
|---|---|
| SHA-256 | `a6716a57efc3a1281fd9f4cc80b815dc7a79fae58907b10b872b5db87ad08cd4` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-10-25 01:49:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c14536f40540bdc783abf7084135bf42` |
| SHA-1 | `3a1b5665545a7bee5b18e285d2eab80744931527` |
| SHA-256 | `a6716a57efc3a1281fd9f4cc80b815dc7a79fae58907b10b872b5db87ad08cd4` |
| SHA3-384 | `65df8b099d1a7e016c021c8285b84d60961c6c32259097b3acc2b00e14daaf878e352704d3a9f7930bfe8e59fcee0334` |
| TLSH | `T179A33C96BD82566EC6D013BFF95E538D732663F8C2DE3013DA108B25378E51F0A76A90` |
| TELFHASH | `t179f0e108fa769e1d58f2a670ec6803e08157963395631734efadcad0c43e54db208e1d` |
| SSDEEP | `1536:gYoUg6972o1G6sa0obZPaNShBKh6Ddor03XYZR6yh5OR6o2mWfhIydLRF2:hoUgu3f/bZPaNOBKheouy7ORHetdY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_a6716a57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6716a57efc3a1281fd9f4cc80b815dc7a79fae58907b10b872b5db87ad08cd4"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-10-25 01:49:49"
  condition:
    hash.sha256(0, filesize) == "a6716a57efc3a1281fd9f4cc80b815dc7a79fae58907b10b872b5db87ad08cd4"
}
```

### Sample 29: `2de0e353270c3bed`

| Field | Value |
|---|---|
| SHA-256 | `2de0e353270c3beddc1f38b860c09f86757d9c7006208bbf09a7cc22055442eb` |
| Family label | `unknown` |
| File name | `macho_2de0e353270c.bin` |
| File type | `macho` |
| First seen | `2026-10-25 01:36:28` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3abdf980933cc13963aac0771818d7e` |
| SHA-1 | `e8fb81302e328c5cb73792f17992653f7e39ff19` |
| SHA-256 | `2de0e353270c3beddc1f38b860c09f86757d9c7006208bbf09a7cc22055442eb` |
| SHA3-384 | `26b0060650ac5b4621a5f3d934be2348a1a0f789de81b95f208e6d816bed7d98fcf548a5a96729ead416b3cb5a1840ee` |
| TLSH | `T105A5F2605A754356E4AA20728E297FC52590B7B12FA8B2E56E14D2171C33FD3F0E3F1A` |
| SSDEEP | `49152:0SlCSdESJAJMIHN9qdtb0Zk1NHhABqm/L1w:0kE6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_2de0e353
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2de0e353270c3beddc1f38b860c09f86757d9c7006208bbf09a7cc22055442eb"
    family = "unknown"
    file_name = "macho_2de0e353270c.bin"
    file_type = "macho"
    first_seen = "2026-10-25 01:36:28"
  condition:
    hash.sha256(0, filesize) == "2de0e353270c3beddc1f38b860c09f86757d9c7006208bbf09a7cc22055442eb"
}
```

### Sample 30: `63c1057ce0510ec1`

| Field | Value |
|---|---|
| SHA-256 | `63c1057ce0510ec13d51209b71579079dabc120ea92e8125965005edbd7fc99c` |
| Family label | `ConnectWise` |
| File name | `63c1057ce0510ec1.bin` |
| File type | `msi` |
| First seen | `2026-10-25 01:24:41` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe96a530e787dba1d7f54f56e29b4a13` |
| SHA-1 | `4174b5c5cc6e5e1f6fdcdf12ff596c182ee55c4b` |
| SHA-256 | `63c1057ce0510ec13d51209b71579079dabc120ea92e8125965005edbd7fc99c` |
| SHA3-384 | `a77e2d37bac8979b2921194f87cc8fc044a7184dbe37b93383adebe1973094fe1b7471aed3709572ba6b2843392cb50b` |
| TLSH | `T15D0733211BF8C855EAB30B75FA7B86B44637BC51A912D05F13A03E1D1932E819EA3377` |
| SSDEEP | `393216:+6ohU+8bjJ8YQq9ySZ8Et6ohU+8bjJ8P6ohU+8bjJ8E6ohU+8bjJ8:5oh0bj19ySZzEoh0bjroh0bjYoh0bj` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_030_63c1057c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c1057ce0510ec13d51209b71579079dabc120ea92e8125965005edbd7fc99c"
    family = "ConnectWise"
    file_name = "63c1057ce0510ec1.bin"
    file_type = "msi"
    first_seen = "2026-10-25 01:24:41"
  condition:
    hash.sha256(0, filesize) == "63c1057ce0510ec13d51209b71579079dabc120ea92e8125965005edbd7fc99c"
}
```

### Sample 31: `6ceef8cdde345460`

| Field | Value |
|---|---|
| SHA-256 | `6ceef8cdde345460463264ed20c225f867a0ef015e10322466b041d987903d9e` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-25 01:09:06` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e22f102e1260ac3c696ddb559253367` |
| SHA-1 | `186d7d20a085e865c274e5b40e55229c9d905c7e` |
| SHA-256 | `6ceef8cdde345460463264ed20c225f867a0ef015e10322466b041d987903d9e` |
| SHA3-384 | `283cc349e50b8f11dc315f93d3c2f5fdabda29e3ef42d45b1d8f8acc60e2f6abe6fbef4dc58f96c416e74b7189ec80ca` |
| IMPHASH | `693aa83bc5cbb713d157f125c9665f61` |
| TLSH | `T11735CE52B3934FF8F0D6B5748D055915A6E17B040BE1B6EB63CCD7260EE23A08AF9B14` |
| SSDEEP | `12288:gx6v1uMAxzEr2LAIzfsvIVtlF7b8yqwEFX9NqfE2S5G4sGlC9kj8W8SJ0HQcF4R:DvrczMMt3qfJ6fE2S5tjH8SCo` |
| ICON-DHASH | `4cb2694d4d69b24c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_6ceef8cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ceef8cdde345460463264ed20c225f867a0ef015e10322466b041d987903d9e"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-25 01:09:06"
  condition:
    hash.sha256(0, filesize) == "6ceef8cdde345460463264ed20c225f867a0ef015e10322466b041d987903d9e"
}
```

### Sample 32: `e60fa60fd8d32a32`

| Field | Value |
|---|---|
| SHA-256 | `e60fa60fd8d32a32314c8ea1c5b5c797cb57e3270470aa7b7934ef1678176851` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-25 01:05:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a16940625bed457cb5817f047319d59e` |
| SHA-1 | `1bf1c714a42b148dd1e18a64767dfc87568f76fd` |
| SHA-256 | `e60fa60fd8d32a32314c8ea1c5b5c797cb57e3270470aa7b7934ef1678176851` |
| SHA3-384 | `7c161dbf27675298a834f5ee3a24d7a86115e95bdca6e98245226214d3898787c65e7c06d48bf96489f137ee2b47f5ce` |
| TLSH | `T11E556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmM:OSCX9B9tGNnD+pb0qAYPWTM2wza6t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_e60fa60f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e60fa60fd8d32a32314c8ea1c5b5c797cb57e3270470aa7b7934ef1678176851"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-25 01:05:47"
  condition:
    hash.sha256(0, filesize) == "e60fa60fd8d32a32314c8ea1c5b5c797cb57e3270470aa7b7934ef1678176851"
}
```

### Sample 33: `d838168d234ce4be`

| Field | Value |
|---|---|
| SHA-256 | `d838168d234ce4bedef14162b85b2c47ac97539e16a3d451682d493b5a173785` |
| Family label | `unknown` |
| File name | `macho_d838168d234c.bin` |
| File type | `macho` |
| First seen | `2026-10-25 01:00:48` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff7e0f93594a2b0fde48d4b6c40f2d17` |
| SHA-1 | `ff291c643a172da5f5cd1d734de801bc621839ff` |
| SHA-256 | `d838168d234ce4bedef14162b85b2c47ac97539e16a3d451682d493b5a173785` |
| SHA3-384 | `37f22d83921da2c8fe61ffcc97e123e1aa196e208e16a0b1429c74ef61a3807f4bb2a8e013623a0d2d6c5b8eb1d16f2a` |
| TLSH | `T11185F1601E79536AE4413433DD0C4F8B17A0B3A16E8CB5F5A724C70A6D396D3F6A7B22` |
| SSDEEP | `24576:4/KaP+rFJIKlBvHISjo+2JBSj7cYohdd28ZXmgfYcB9a+DKGW1Zy1LmwohH:QavJ8CKXX3AcBB+SE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_d838168d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d838168d234ce4bedef14162b85b2c47ac97539e16a3d451682d493b5a173785"
    family = "unknown"
    file_name = "macho_d838168d234c.bin"
    file_type = "macho"
    first_seen = "2026-10-25 01:00:48"
  condition:
    hash.sha256(0, filesize) == "d838168d234ce4bedef14162b85b2c47ac97539e16a3d451682d493b5a173785"
}
```

### Sample 34: `dc4db648c1277502`

| Field | Value |
|---|---|
| SHA-256 | `dc4db648c12775028fd2eaa82e831fafb1aa0b9e950fea74033eeb23220d1bca` |
| Family label | `unknown` |
| File name | `macho_dc4db648c127.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:57:41` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6527d6da6f92194f9931fe048ca460ed` |
| SHA-1 | `31ecc1cf19a73082b0b1bab0e7623f94e2cd3fdc` |
| SHA-256 | `dc4db648c12775028fd2eaa82e831fafb1aa0b9e950fea74033eeb23220d1bca` |
| SHA3-384 | `c850fa256d5a443ae88139c83f4ef5f6ede63129eacbfd8c4f9e2f7bd3736a4e10e8330ad116b700cfdfda3e11b2585d` |
| TLSH | `T1DB950250B71A22EBD583347A9D0C0FB626D092A01A28BFF66A15D7753C359D37E63332` |
| SSDEEP | `49152:TuNNGhlydarD2pAUGpnOsN8Qp2cNZVOwaCuC+MTN8qjUgXzETSs:CNQhMtpQ8B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_dc4db648
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc4db648c12775028fd2eaa82e831fafb1aa0b9e950fea74033eeb23220d1bca"
    family = "unknown"
    file_name = "macho_dc4db648c127.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:57:41"
  condition:
    hash.sha256(0, filesize) == "dc4db648c12775028fd2eaa82e831fafb1aa0b9e950fea74033eeb23220d1bca"
}
```

### Sample 35: `78d0bbf3ddb244ca`

| Field | Value |
|---|---|
| SHA-256 | `78d0bbf3ddb244caae5b955e6e9476e26f33f5a2e37b9d02863ad34b6476fb64` |
| Family label | `unknown` |
| File name | `macho_78d0bbf3ddb2.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:54:36` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e27489907206d6ae7987c80a20701a4a` |
| SHA-1 | `95e9f55fecefc15c3601cbaecf25d8479ab23f43` |
| SHA-256 | `78d0bbf3ddb244caae5b955e6e9476e26f33f5a2e37b9d02863ad34b6476fb64` |
| SHA3-384 | `c030d023d6eb04dd34e417a36be7737279b81a02b0f148f378268c46da0483c5a36a02d5e9da0d48e17d2d337044b72d` |
| TLSH | `T1EC950110CA27536FD8423A739C5F2FF57460B5811A4C6EFA2270D72A2C3DAD7B967221` |
| SSDEEP | `49152:D1Buor8BGXWk7GzoBPdo0LGqwmqImATGVq75y7vm3wXbHX:DDNSeW9AGRIBTGVqFy1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_78d0bbf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78d0bbf3ddb244caae5b955e6e9476e26f33f5a2e37b9d02863ad34b6476fb64"
    family = "unknown"
    file_name = "macho_78d0bbf3ddb2.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:54:36"
  condition:
    hash.sha256(0, filesize) == "78d0bbf3ddb244caae5b955e6e9476e26f33f5a2e37b9d02863ad34b6476fb64"
}
```

### Sample 36: `f19355620754c842`

| Field | Value |
|---|---|
| SHA-256 | `f19355620754c842dd19e57d0b71f27e4c508d51c2f4b1a28f40db3e33cd7d5c` |
| Family label | `unknown` |
| File name | `newisbest.exe` |
| File type | `exe` |
| First seen | `2026-10-25 00:52:34` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14c20a0b2a8e79d14fb059e6f714784e` |
| SHA-1 | `31d3cd3d134325e8ad6034d7029b0639fdd05aa6` |
| SHA-256 | `f19355620754c842dd19e57d0b71f27e4c508d51c2f4b1a28f40db3e33cd7d5c` |
| SHA3-384 | `d1ab8220f839f34ba28f7bc0639854f2a7ed0c1802186e3710ed83f4c67e1d28b519e21aa744b61dc4370abe98bd2b64` |
| IMPHASH | `6650eba3b564c29106658611b02b3e3c` |
| TLSH | `T1B845F085BBB67EFCF83585B1494A15257A2434121FE058FB42FC174B0E2A6C05EFEB29` |
| SSDEEP | `12288:3/bymlsdahF8sFoocK6r42CtiXVGW5KuEF4xULdJfI9gK/IEupJ0R5Q0Gili113p:3Dymlwfo12C+fEF4GdJfI9g+O0bEDcO` |
| ICON-DHASH | `4416716969711644` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_f1935562
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f19355620754c842dd19e57d0b71f27e4c508d51c2f4b1a28f40db3e33cd7d5c"
    family = "unknown"
    file_name = "newisbest.exe"
    file_type = "exe"
    first_seen = "2026-10-25 00:52:34"
  condition:
    hash.sha256(0, filesize) == "f19355620754c842dd19e57d0b71f27e4c508d51c2f4b1a28f40db3e33cd7d5c"
}
```

### Sample 37: `71cfefd6acba8892`

| Field | Value |
|---|---|
| SHA-256 | `71cfefd6acba889266eb65ad63992d288a1c30deaa2bd38f1d22b9ec7dfa9220` |
| Family label | `unknown` |
| File name | `export.php` |
| File type | `exe` |
| First seen | `2026-10-25 00:52:28` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d69a7974e45db534b5dfc9b785f8ce0f` |
| SHA-1 | `291026858ad74c324de13d2dc9b6b369fee4df6a` |
| SHA-256 | `71cfefd6acba889266eb65ad63992d288a1c30deaa2bd38f1d22b9ec7dfa9220` |
| SHA3-384 | `4fcaf52c2a80542c3f07b720f038f26a6b28bd797e4f06ed98e6afc5f56f3a06f2bf1ef8b7c53eca8b4341bc25829713` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16D25E0942670FACDD4F90F3765B03A2498C006228F5BD54331AB26BE02B979797613FE` |
| SSDEEP | `24576:TKUvhQiR4D6XUvWn5RGDLorPqHneK/9Pni3yEx67M16s:TKmhQiCD6XUvO+HeKF/i3R67Mz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_71cfefd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71cfefd6acba889266eb65ad63992d288a1c30deaa2bd38f1d22b9ec7dfa9220"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-10-25 00:52:28"
  condition:
    hash.sha256(0, filesize) == "71cfefd6acba889266eb65ad63992d288a1c30deaa2bd38f1d22b9ec7dfa9220"
}
```

### Sample 38: `dba12dd044d53dc3`

| Field | Value |
|---|---|
| SHA-256 | `dba12dd044d53dc35cb15d9432a2e6fa139d9f76d813ace626b3f84bac9f67ea` |
| Family label | `unknown` |
| File name | `macho_dba12dd044d5.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:51:37` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ff66ec653216b6b50151b0aed9a5e54` |
| SHA-1 | `98b3363738e2daaafb2ef9ed41b667aa4953f0b0` |
| SHA-256 | `dba12dd044d53dc35cb15d9432a2e6fa139d9f76d813ace626b3f84bac9f67ea` |
| SHA3-384 | `e1472174e23fe2a92c7ff29176b55a348392c1653d414342b33c415fb25dc30839b839c52a61e6d447c12cbdebc15253` |
| TLSH | `T1BF95F12462E7E12DE0022A32BC100FD554E166B15D9DBAF7BB21D7726C31A8766E3373` |
| SSDEEP | `24576:oYWkJeaU+8K57FSoQ4SkObn9qGquXqS88R6ajjTJAlSy8QbX3m26oni:hWo7Fy4gqxxS8jqjTJAlSOm3x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_dba12dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dba12dd044d53dc35cb15d9432a2e6fa139d9f76d813ace626b3f84bac9f67ea"
    family = "unknown"
    file_name = "macho_dba12dd044d5.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:51:37"
  condition:
    hash.sha256(0, filesize) == "dba12dd044d53dc35cb15d9432a2e6fa139d9f76d813ace626b3f84bac9f67ea"
}
```

### Sample 39: `917a3a55eb7f0633`

| Field | Value |
|---|---|
| SHA-256 | `917a3a55eb7f0633d7869768dc16cc3bdc3727844cfc76c8628d93807792e9c0` |
| Family label | `unknown` |
| File name | `917a3a55eb7f0633.ps1` |
| File type | `ps1` |
| First seen | `2026-10-25 00:48:40` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d66f34d27c29e72bcb93467f9fea2806` |
| SHA-1 | `cab1c3818f7ba233c193796f846e554ab73fe824` |
| SHA-256 | `917a3a55eb7f0633d7869768dc16cc3bdc3727844cfc76c8628d93807792e9c0` |
| SHA3-384 | `a92b184411b312cebbb94e3557dfe61a98c9a76976ebda16401bced15c020cd9f13c8bf21bd4a273f4d51abbed7b5d0a` |
| TLSH | `T188D47E707E021EFF5BB860C248C6C11C563872B4D9682DF56ACB4CA3291D77A27B79B1` |
| SSDEEP | `6144:4mrx1y1BmWalWGZsy4hrRH+sT8vgFPZcxTdOefi8CTelL9a63ZoOlhI84yd+DooU:XxLGRhrBgvgF6xDSqt9doOl34o9l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_917a3a55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "917a3a55eb7f0633d7869768dc16cc3bdc3727844cfc76c8628d93807792e9c0"
    family = "unknown"
    file_name = "917a3a55eb7f0633.ps1"
    file_type = "ps1"
    first_seen = "2026-10-25 00:48:40"
  condition:
    hash.sha256(0, filesize) == "917a3a55eb7f0633d7869768dc16cc3bdc3727844cfc76c8628d93807792e9c0"
}
```

### Sample 40: `540d24a82a36a3e6`

| Field | Value |
|---|---|
| SHA-256 | `540d24a82a36a3e60497ee29fa51e3cc9963ecc50a9fa77fb245670d34879e09` |
| Family label | `unknown` |
| File name | `macho_540d24a82a36.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:48:22` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b57989cd2e1744ca4598dc9b59909df9` |
| SHA-1 | `16a5fa52abf7a12b1efb7d76ad003ef93fb89cdb` |
| SHA-256 | `540d24a82a36a3e60497ee29fa51e3cc9963ecc50a9fa77fb245670d34879e09` |
| SHA3-384 | `f309e320a1bf341eee9be8134906907067045854bfc8c42aada4d1e31e3ce51b8c8a69cf76cec2315534ef3b003bb41f` |
| TLSH | `T1EF95F1602F31055AF06724B39D05DF3590A0F6E0BF08B6E9AD25D7036D3A6D3A6B3366` |
| SSDEEP | `24576:+tupE2nUucOpf8LnYbfm4cw5ujCkjmZMPQmZNWLHLcynrx7i/JRfSbtqwcxbXETK:+s1SAzMjCLoiLHLcSx7i/JlotbDkSq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_540d24a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "540d24a82a36a3e60497ee29fa51e3cc9963ecc50a9fa77fb245670d34879e09"
    family = "unknown"
    file_name = "macho_540d24a82a36.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:48:22"
  condition:
    hash.sha256(0, filesize) == "540d24a82a36a3e60497ee29fa51e3cc9963ecc50a9fa77fb245670d34879e09"
}
```

### Sample 41: `f09773a220d16e25`

| Field | Value |
|---|---|
| SHA-256 | `f09773a220d16e25ff8626af5ae925829bf180bcceb84431f72778bfe84a0475` |
| Family label | `unknown` |
| File name | `macho_f09773a220d1.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:45:16` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc768f1075d2e933e7e2ca8121d0e1a1` |
| SHA-1 | `404b3dc103c2c84c61ac8fb877d6318815d7d0c3` |
| SHA-256 | `f09773a220d16e25ff8626af5ae925829bf180bcceb84431f72778bfe84a0475` |
| SHA3-384 | `30edc538a02dd3e41b92d3298642f25ca2758ea46cb2705e3f449cc4689da7d34ff0d60e4d23c348a0f21c20b643694a` |
| TLSH | `T18995F260166219EEE3832032DA0D0F54A560FBB1DE8879FA9530D779FC315D3BA63672` |
| SSDEEP | `24576:CDTrTeRYol41yskmfAYWQ+omP0fNSsT+hvB3m3iMmKRamy5+eCFn02m11yemrek4:gK9cM3IiMmKsMeCFrm1cemrekDUEPq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_f09773a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f09773a220d16e25ff8626af5ae925829bf180bcceb84431f72778bfe84a0475"
    family = "unknown"
    file_name = "macho_f09773a220d1.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:45:16"
  condition:
    hash.sha256(0, filesize) == "f09773a220d16e25ff8626af5ae925829bf180bcceb84431f72778bfe84a0475"
}
```

### Sample 42: `d60004e652baebc1`

| Field | Value |
|---|---|
| SHA-256 | `d60004e652baebc1230dc7262b2983b3d8c62f1f7b132edaba8b68c6a82b20c0` |
| Family label | `unknown` |
| File name | `macho_d60004e652ba.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:42:15` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1f2f09beb29ab8243d9cd7c50063862` |
| SHA-1 | `7678c914837e2b2e6128f24252b81ea731cd8807` |
| SHA-256 | `d60004e652baebc1230dc7262b2983b3d8c62f1f7b132edaba8b68c6a82b20c0` |
| SHA3-384 | `dc9a26a61a424e06be9846e50870212086b140ca02ccf4adbf7fe578e5c3a33f88f2cbfde9d57396ed0dfc90f79ced54` |
| TLSH | `T19375F1004F6F6216E58E0073AD99CB19857932F0CE49C8DA6312539A9E3D3D3B7572BB` |
| SSDEEP | `24576:hXaM+xd53kWRS2/pxT+hHFZjUGOZQbYGg9R0WlDwqvqqZvkF7Zxrkc4h8B8Q:hXaZNkQf/zKhskbYG3W2qzMF0qB8Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_d60004e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d60004e652baebc1230dc7262b2983b3d8c62f1f7b132edaba8b68c6a82b20c0"
    family = "unknown"
    file_name = "macho_d60004e652ba.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:42:15"
  condition:
    hash.sha256(0, filesize) == "d60004e652baebc1230dc7262b2983b3d8c62f1f7b132edaba8b68c6a82b20c0"
}
```

### Sample 43: `6bbd6311fa06d6db`

| Field | Value |
|---|---|
| SHA-256 | `6bbd6311fa06d6dba192c8739fb1519b9a86074f718bae304c2bdc92c2608e7f` |
| Family label | `unknown` |
| File name | `macho_6bbd6311fa06.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:39:11` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b659a70dc1de03c950f2fb2bf1c47645` |
| SHA-1 | `b0d4cf788ea578cdd34a45755d023598601ed6ec` |
| SHA-256 | `6bbd6311fa06d6dba192c8739fb1519b9a86074f718bae304c2bdc92c2608e7f` |
| SHA3-384 | `53c3a3a28106048bed98dccf083f8df78041ba448b76834777193b2c2d393ec426b457052e5b3788adca6a66db7951f6` |
| TLSH | `T18685F1906F7D6216DD8620B3CD204F5F84B0668A5748FAE86225E3176874793B7FB323` |
| SSDEEP | `24576:hMutC5ExwvGG0V81hWcPua0zWnsa/nb8isKxIIgOXT41DAnrlPpw89umez+VsaNi:Dr6R0zVKxIt0T4qrNfezn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_6bbd6311
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bbd6311fa06d6dba192c8739fb1519b9a86074f718bae304c2bdc92c2608e7f"
    family = "unknown"
    file_name = "macho_6bbd6311fa06.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:39:11"
  condition:
    hash.sha256(0, filesize) == "6bbd6311fa06d6dba192c8739fb1519b9a86074f718bae304c2bdc92c2608e7f"
}
```

### Sample 44: `8eec2049532e7442`

| Field | Value |
|---|---|
| SHA-256 | `8eec2049532e744253e3a5a654d7ce173e874ab8e6e247d6db8e51c97437e25f` |
| Family label | `unknown` |
| File name | `8eec2049532e744253e3a5a654d7ce173e874ab8e6e247d6db8e51c97437e25f.exe` |
| File type | `exe` |
| First seen | `2026-10-25 00:38:10` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7a019ce3e8cf5c9ba381169136e9a2f` |
| SHA-1 | `d902980cf94a3f463f38444a74d9223b9c6dbd43` |
| SHA-256 | `8eec2049532e744253e3a5a654d7ce173e874ab8e6e247d6db8e51c97437e25f` |
| SHA3-384 | `cc6d4f94ea4133c23c7601081c976ae2a26fcb31f35d2ed27e07ef28b48c3015a265b87cadc40f6ab351adda8765fa90` |
| TLSH | `T178C4E753BE858F46E6A42E7143EF7D18038694B69FB27B0B2F20237B58411E7ED94784` |
| SSDEEP | `12288:jWSIxrG3JwTNmGdCBmAiztYJ7hhthx9HgkMWMTs5r:jGxr5/A6YJ7hP5HxM5Tst` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_8eec2049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8eec2049532e744253e3a5a654d7ce173e874ab8e6e247d6db8e51c97437e25f"
    family = "unknown"
    file_name = "8eec2049532e744253e3a5a654d7ce173e874ab8e6e247d6db8e51c97437e25f.exe"
    file_type = "exe"
    first_seen = "2026-10-25 00:38:10"
  condition:
    hash.sha256(0, filesize) == "8eec2049532e744253e3a5a654d7ce173e874ab8e6e247d6db8e51c97437e25f"
}
```

### Sample 45: `49006e5ef2cd5c0b`

| Field | Value |
|---|---|
| SHA-256 | `49006e5ef2cd5c0b48dcd4ec4f14ff17e15b737191dbb22c93bbac963f89ab15` |
| Family label | `unknown` |
| File name | `macho_49006e5ef2cd.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:36:00` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a874de7371a128b0f9656978b47e7ea8` |
| SHA-1 | `5c95e9948fbefb5ada5d73f98724095a7d9d05d8` |
| SHA-256 | `49006e5ef2cd5c0b48dcd4ec4f14ff17e15b737191dbb22c93bbac963f89ab15` |
| SHA3-384 | `0af013f597bf6814d94e63dff763455664b3ac3236d824e4015eabb7aab7da2f679ae4c2eff5bc35337bfbaa147fc10e` |
| TLSH | `T1309501308667E15AE9732032CB1C4FB09450E6E159686AF72A1FF367AC319C77927372` |
| SSDEEP | `49152:1bB5Qrc2cylAV17AqkhP8BhUddEKm8OGbFjrhyOJF+Nq4/KLlcm/4zPHIxjp/A+A:D5h2lQ1RSdEKNFjVI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_49006e5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49006e5ef2cd5c0b48dcd4ec4f14ff17e15b737191dbb22c93bbac963f89ab15"
    family = "unknown"
    file_name = "macho_49006e5ef2cd.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:36:00"
  condition:
    hash.sha256(0, filesize) == "49006e5ef2cd5c0b48dcd4ec4f14ff17e15b737191dbb22c93bbac963f89ab15"
}
```

### Sample 46: `3ab2cca8113b6224`

| Field | Value |
|---|---|
| SHA-256 | `3ab2cca8113b62240a9bce2d312a920a55f0a2313c6a8f76d0427400e6d6ab3f` |
| Family label | `unknown` |
| File name | `macho_3ab2cca8113b.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:32:59` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a0b7cc5f8a167ef5f14bfc937713f60` |
| SHA-1 | `5422521ece9f828dd5d7aaec15252dc60ec123c3` |
| SHA-256 | `3ab2cca8113b62240a9bce2d312a920a55f0a2313c6a8f76d0427400e6d6ab3f` |
| SHA3-384 | `4c57f3bebee317ca56f857b73184f66a631083e93b84b0c5523a8533bead495dd03771e3f30100d4f3f780cfc63bc8ba` |
| TLSH | `T15995E0808FAAA15AD48D52739C968B18857831C0CE85DDDE930263DBDD3D3A3F7171AB` |
| SSDEEP | `24576:b3Kys38KLGSA9vpD0tFLNsRw8CK1KRxkyHvHEmhVjfzQ3Ic8G3src:WrvEmtPxkyHvHRL7c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_3ab2cca8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ab2cca8113b62240a9bce2d312a920a55f0a2313c6a8f76d0427400e6d6ab3f"
    family = "unknown"
    file_name = "macho_3ab2cca8113b.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:32:59"
  condition:
    hash.sha256(0, filesize) == "3ab2cca8113b62240a9bce2d312a920a55f0a2313c6a8f76d0427400e6d6ab3f"
}
```

### Sample 47: `757ac091dec67dd9`

| Field | Value |
|---|---|
| SHA-256 | `757ac091dec67dd9d7987ffe9a8c3cfc9be0fb643c6678faa831993a0343f46f` |
| Family label | `unknown` |
| File name | `macho_757ac091dec6.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:29:41` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `790f7546bf66331e92c231bbf20088db` |
| SHA-1 | `9803d6f495664bef7320e75a6f170c647f2fec74` |
| SHA-256 | `757ac091dec67dd9d7987ffe9a8c3cfc9be0fb643c6678faa831993a0343f46f` |
| SHA3-384 | `7d077e9ae31dd0db7489e54849ca72df61b88d83db93d67d4ac5b053b850718c009d0775afaa299cc710b2ee7aa16227` |
| TLSH | `T1C9A5D0819E9A608BD54E5173DC9A8F1944743080DE85DEED6302A78BCD3A7D3B7630FA` |
| SSDEEP | `24576:/rxr5gRGIS3gIo4cXZ+Ib5ZNnPFo6lYQq4FeNH3RrhTxramj524ZNRPofnTpOkbC:95ghI0Xg2PFDluhBxrxjzTPUpXbC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_757ac091
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "757ac091dec67dd9d7987ffe9a8c3cfc9be0fb643c6678faa831993a0343f46f"
    family = "unknown"
    file_name = "macho_757ac091dec6.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:29:41"
  condition:
    hash.sha256(0, filesize) == "757ac091dec67dd9d7987ffe9a8c3cfc9be0fb643c6678faa831993a0343f46f"
}
```

### Sample 48: `4fce2a5d9ba8e953`

| Field | Value |
|---|---|
| SHA-256 | `4fce2a5d9ba8e95349c421083190430383249980fe9a4ee9ef22e8037ffd0188` |
| Family label | `SalatStealer` |
| File name | `3fc6de71f563acff.bin` |
| File type | `exe` |
| First seen | `2026-10-25 00:25:37` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8608111a696552639d43786e54a1b11d` |
| SHA-1 | `23aaeb6bf7f4b10b89731b6ed93cc6c26a039e04` |
| SHA-256 | `4fce2a5d9ba8e95349c421083190430383249980fe9a4ee9ef22e8037ffd0188` |
| SHA3-384 | `b0add51c0b8c70996ce055b32aacfb126b4440c4c2b511b9ec0d999ba8d02cb9ff510720b8cdb0068cd8129d412e5571` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A5C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+f:yBkKr5rszpNDy+f` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_048_4fce2a5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fce2a5d9ba8e95349c421083190430383249980fe9a4ee9ef22e8037ffd0188"
    family = "SalatStealer"
    file_name = "3fc6de71f563acff.bin"
    file_type = "exe"
    first_seen = "2026-10-25 00:25:37"
  condition:
    hash.sha256(0, filesize) == "4fce2a5d9ba8e95349c421083190430383249980fe9a4ee9ef22e8037ffd0188"
}
```

### Sample 49: `833f41ac5e8787a2`

| Field | Value |
|---|---|
| SHA-256 | `833f41ac5e8787a25037a1badb65cdd1add14ae683af7486e1575762fbeeed60` |
| Family label | `RustyStealer` |
| File name | `833f41ac5e8787a2.bin` |
| File type | `exe` |
| First seen | `2026-10-25 00:25:28` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a48bfa67ba9b5a065f8f7ccdce4cd98` |
| SHA-1 | `fd1097ca3233d23c359a697273f47abf643379ce` |
| SHA-256 | `833f41ac5e8787a25037a1badb65cdd1add14ae683af7486e1575762fbeeed60` |
| SHA3-384 | `21d65dc2a6db423909279820a38cfea6db07fd5b1118ebcbccc7b6ea41232147ac43fffb354307c5f6b3b8d97e72c962` |
| IMPHASH | `603a12af845feb44eeaee4af0f3efa0b` |
| TLSH | `T1E9A57D07FEA580ECC55EC078C3479632EA23B88D492177AB17D09B242F6AF506B1D779` |
| SSDEEP | `49152:Wyq6XhizXRpuk+XZDh5KyR7F/Rip4arEFzWwIU6istJ6:WyVQgJFIP+s` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_049_833f41ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "833f41ac5e8787a25037a1badb65cdd1add14ae683af7486e1575762fbeeed60"
    family = "RustyStealer"
    file_name = "833f41ac5e8787a2.bin"
    file_type = "exe"
    first_seen = "2026-10-25 00:25:28"
  condition:
    hash.sha256(0, filesize) == "833f41ac5e8787a25037a1badb65cdd1add14ae683af7486e1575762fbeeed60"
}
```

### Sample 50: `02f4f05b9697d1cb`

| Field | Value |
|---|---|
| SHA-256 | `02f4f05b9697d1cbef49f3fd7ab92f99abd0e64f595eb533e286cadb635d95b3` |
| Family label | `RustyStealer` |
| File name | `02f4f05b9697d1cb.bin` |
| File type | `exe` |
| First seen | `2026-10-25 00:25:21` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `033a2d1807afe6278ab6f2d573c3296c` |
| SHA-1 | `f8cf0ce1e3897e7eebfd20833a9beb2fd1219dda` |
| SHA-256 | `02f4f05b9697d1cbef49f3fd7ab92f99abd0e64f595eb533e286cadb635d95b3` |
| SHA3-384 | `73e919c886987d50c5ff1bbf0b8f133c36632e0c719585a56a9c684033dbff1a27cb65ac54f300c8ae586f907867553d` |
| IMPHASH | `603a12af845feb44eeaee4af0f3efa0b` |
| TLSH | `T1FAA57D03E6A580E8D55EF07883479633EA62B88DC935B2AB37D09B243E26FD05F0D755` |
| SSDEEP | `49152:Pyq6nhizXRpuk+XZDh5KyR7F/OsWwIU6istJ6:PyFQgJFmtP+s` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_050_02f4f05b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02f4f05b9697d1cbef49f3fd7ab92f99abd0e64f595eb533e286cadb635d95b3"
    family = "RustyStealer"
    file_name = "02f4f05b9697d1cb.bin"
    file_type = "exe"
    first_seen = "2026-10-25 00:25:21"
  condition:
    hash.sha256(0, filesize) == "02f4f05b9697d1cbef49f3fd7ab92f99abd0e64f595eb533e286cadb635d95b3"
}
```

### Sample 51: `66ed73200174f455`

| Field | Value |
|---|---|
| SHA-256 | `66ed73200174f455ce49b39793eebcad7e3ea094a500e0c7ed2d42f92181039e` |
| Family label | `unknown` |
| File name | `66ed73200174f455.bin` |
| File type | `elf` |
| First seen | `2026-10-25 00:25:15` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e33503559228af39200749e7b5ecf097` |
| SHA-1 | `927d7cea7d21eb20c39cb78a2cd42d7c5120fba1` |
| SHA-256 | `66ed73200174f455ce49b39793eebcad7e3ea094a500e0c7ed2d42f92181039e` |
| SHA3-384 | `b19ceafdc8ff95d7c9daa18b98b1c81b0b14220c7aff7bfe9c2a6564f658a53872be74b683681a45f582db5f1d1bd0a2` |
| TLSH | `T117B63A17ECA554E4C1ED85308AB792527F327C4A0B2537E72B60F6382F76BD06AB9350` |
| TELFHASH | `t1625275754abd35b5b2a6da10b3a3b4f495371ca462f438f01063e991ffc5e801ca687b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:DnPG5fZVcxZRK59BRDKnd4B6H9Q6jbjV8JdGHbSYSAY4mGXVK0KtEkwa/v1oE3SI:DniffGRxbgh7M03S1luPUzJV+x9yEH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_66ed7320
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66ed73200174f455ce49b39793eebcad7e3ea094a500e0c7ed2d42f92181039e"
    family = "unknown"
    file_name = "66ed73200174f455.bin"
    file_type = "elf"
    first_seen = "2026-10-25 00:25:15"
  condition:
    hash.sha256(0, filesize) == "66ed73200174f455ce49b39793eebcad7e3ea094a500e0c7ed2d42f92181039e"
}
```

### Sample 52: `3fc6de71f563acff`

| Field | Value |
|---|---|
| SHA-256 | `3fc6de71f563acffc3935b197cfcbeb181567f28b549360a1637d42415322f62` |
| Family label | `SalatStealer` |
| File name | `3fc6de71f563acff.bin` |
| File type | `exe` |
| First seen | `2026-10-25 00:25:05` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9599fceef53a661f683edf1b9dd36ca9` |
| SHA-1 | `cc040190f2dbde7a4979e96f40f93eb1566941eb` |
| SHA-256 | `3fc6de71f563acffc3935b197cfcbeb181567f28b549360a1637d42415322f62` |
| SHA3-384 | `8aa623b05d607ae3731e8b7aaa4e286df303f607a803439cbbed8e961129a0c175bdf72c92ded6874460a10ed1288ead` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1A0F5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oj:iJiafuIO7rhWEES4g` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_052_3fc6de71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fc6de71f563acffc3935b197cfcbeb181567f28b549360a1637d42415322f62"
    family = "SalatStealer"
    file_name = "3fc6de71f563acff.bin"
    file_type = "exe"
    first_seen = "2026-10-25 00:25:05"
  condition:
    hash.sha256(0, filesize) == "3fc6de71f563acffc3935b197cfcbeb181567f28b549360a1637d42415322f62"
}
```

### Sample 53: `51754c16d7f70607`

| Field | Value |
|---|---|
| SHA-256 | `51754c16d7f70607d607d7c1bc6e1ed40ac29538b585784f69ea00b9dabe805f` |
| Family label | `unknown` |
| File name | `macho_51754c16d7f7.bin` |
| File type | `macho` |
| First seen | `2026-10-25 00:23:39` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `761fd9cb13ded30b070b726b45d1a986` |
| SHA-1 | `5342e9749980de2a05da938e1af4b43bffb483ca` |
| SHA-256 | `51754c16d7f70607d607d7c1bc6e1ed40ac29538b585784f69ea00b9dabe805f` |
| SHA3-384 | `a47c08229fee7d0ad98695b225123d724044ce4f7f5599d1049deb91c6822c461b93bb9e806c2417e32422317c3a591a` |
| TLSH | `T1A4A5F11051ABE269D4423D73ECD00BA454F0A98199CCBEF8A266DB267D37D42F6E3335` |
| SSDEEP | `49152:uA8+jXATKFfKH2XBKKQTSDp2yjtPFAFlUFt2Lkh:N8Ww20yjoK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_51754c16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51754c16d7f70607d607d7c1bc6e1ed40ac29538b585784f69ea00b9dabe805f"
    family = "unknown"
    file_name = "macho_51754c16d7f7.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:23:39"
  condition:
    hash.sha256(0, filesize) == "51754c16d7f70607d607d7c1bc6e1ed40ac29538b585784f69ea00b9dabe805f"
}
```

### Sample 54: `6fe3779ca5f37dde`

| Field | Value |
|---|---|
| SHA-256 | `6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1` |
| Family label | `Mirai` |
| File name | `6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1` |
| File type | `elf` |
| First seen | `2026-10-25 00:02:19` |
| Reporter | `vlasovmichael` |
| Tags | `elf, honeypot, Mirai, trojan.flooder` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d83aed0249451e2ff1e57a0b1a7a68a3` |
| SHA-1 | `82ebed022fb09a45dc126c00959b400d9c5dfd09` |
| SHA-256 | `6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1` |
| SHA3-384 | `01368a4da80bd3cfd2ec6da7c1c8e8a4e6faff3200b64b64b77f39835a61fc86aae05e1e39566b2e210c4292b2b0241e` |
| TLSH | `T157565B03ECA565E9D1ADE63086629263BA71BC485F3123D33F50F3692F76BC06A79704` |
| TELFHASH | `t1c12249755dbd7974b696da20b3a7b5b4957729a066f838f01023ad80ffc1e801ce2c27` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:ii6QGg/VaIiRcugcfApWJHITizPaHtrol6G4J0DBtIi7c5e1YUnYIBHyp6BjqOKP:i5aS+E4kam8GvDFZYUY3IKEC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_6fe3779c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1"
    family = "Mirai"
    file_name = "6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1"
    file_type = "elf"
    first_seen = "2026-10-25 00:02:19"
  condition:
    hash.sha256(0, filesize) == "6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1"
}
```

### Sample 55: `31b246282c688ab9`

| Field | Value |
|---|---|
| SHA-256 | `31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293` |
| Family label | `Mirai` |
| File name | `31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293` |
| File type | `elf` |
| First seen | `2026-10-25 00:02:15` |
| Reporter | `vlasovmichael` |
| Tags | `elf, honeypot, Mirai, trojan.flooder` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2990087bb033a3ef1769f0050ceccbd2` |
| SHA-1 | `1278f88b23bb14128c0c8d89fef0e809270a200e` |
| SHA-256 | `31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293` |
| SHA3-384 | `ff3ddb6a778c410ec38f5a3b94be3deefeee1ac1893cd6f91fbf6bb7b299721ee67313e138f8e2e640ec628ff0f64469` |
| TLSH | `T188565B13ECA555E9C1ADE63086629263BA717C486F3123D33F50F3682F76BC0AA79744` |
| TELFHASH | `t1c12249755dbd7974b696da20b3a7b5b4957729a066f838f01023ad80ffc1e801ce2c27` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:CcJ7+5B54ThiaUnEaEqYXg5iWxcWuqbjVXGTaDCB7lgfcGk+RpRsBHyp3BzqOKxS:CIbcGORc1m9GwCEe+RTuIGER` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_31b24628
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293"
    family = "Mirai"
    file_name = "31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293"
    file_type = "elf"
    first_seen = "2026-10-25 00:02:15"
  condition:
    hash.sha256(0, filesize) == "31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293"
}
```

### Sample 56: `c41923f219244fb0`

| Field | Value |
|---|---|
| SHA-256 | `c41923f219244fb0b28882e01c540c35706f19966b5fc070adf8be235b8be008` |
| Family label | `Mirai` |
| File name | `nz.sh4` |
| File type | `elf` |
| First seen | `2026-10-24 23:53:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6b1471cbccc77fd73a3e1e81838bdf7` |
| SHA-1 | `3dee5be90d77e1aaff98aad97cfb867b56d2098f` |
| SHA-256 | `c41923f219244fb0b28882e01c540c35706f19966b5fc070adf8be235b8be008` |
| SHA3-384 | `1a4ec6f0ee96c5947568aeda3a5d816a882d7342d9c3d812591a3f80c2f549131e261f90ea792eff4c2b19ce5863b509` |
| TLSH | `T14B04AE63DC256E98D658D8B0F4F19F7C1B43996481832FA9A8A7C6754087ECDF9043F8` |
| SSDEEP | `3072:SVa2pkTZk+jRDWD1SBnkgRNTQ9bFQWNyIOK5uMWlr:SVa1z5WxSBnncB5NsK5uzB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_c41923f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c41923f219244fb0b28882e01c540c35706f19966b5fc070adf8be235b8be008"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-10-24 23:53:45"
  condition:
    hash.sha256(0, filesize) == "c41923f219244fb0b28882e01c540c35706f19966b5fc070adf8be235b8be008"
}
```

### Sample 57: `7fdb4ed5896bbfd3`

| Field | Value |
|---|---|
| SHA-256 | `7fdb4ed5896bbfd34f05a2aa00aa05b480df97673304f2b2f84122e65e387cbc` |
| Family label | `unknown` |
| File name | `stage1_7fdb4ed58968.zsh` |
| File type | `zsh` |
| First seen | `2026-10-24 23:32:37` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, dropper, Foxveil, macOS, zsh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37d5ba9125428fb9bab26227e1d025e7` |
| SHA-1 | `2a1ca784da110db1f8ce7b981cda59cad5213930` |
| SHA-256 | `7fdb4ed5896bbfd34f05a2aa00aa05b480df97673304f2b2f84122e65e387cbc` |
| SHA3-384 | `f3283b871346af6df27555b3d7728df36935114a65f0b2ca442fb080900fca2d0b7de895ca0e7e34c1ed19d2b4b994fb` |
| TLSH | `T17461F979E82084B3D9EA4079D7D978341BDE37DD8AD0B035F0569F8426AEFD4C468009` |
| SSDEEP | `96:YnHVz3QSDoTJIKczUnW7FGsD65TiQVmmUqiNDCmOWXRQxTx7:YHh3QSDoNYzUnW7FGsD69iQVEqiJCmYz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zsh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_7fdb4ed5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fdb4ed5896bbfd34f05a2aa00aa05b480df97673304f2b2f84122e65e387cbc"
    family = "unknown"
    file_name = "stage1_7fdb4ed58968.zsh"
    file_type = "zsh"
    first_seen = "2026-10-24 23:32:37"
  condition:
    hash.sha256(0, filesize) == "7fdb4ed5896bbfd34f05a2aa00aa05b480df97673304f2b2f84122e65e387cbc"
}
```

### Sample 58: `e59471dbb08a04c5`

| Field | Value |
|---|---|
| SHA-256 | `e59471dbb08a04c5ec6df736f149919cc5333ef19da2b2de298d4f429d0c3612` |
| Family label | `unknown` |
| File name | `macho_e59471dbb08a.bin` |
| File type | `macho` |
| First seen | `2026-10-24 23:25:33` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a970540cd1870778c321d945ab8f16cd` |
| SHA-1 | `f449ada8401d93e94f0d9dd3e58aff4ef926961b` |
| SHA-256 | `e59471dbb08a04c5ec6df736f149919cc5333ef19da2b2de298d4f429d0c3612` |
| SHA3-384 | `a8c244d940d8556d02577c6956bcb6bb425f35bcfa7a8a841227b8693b34f5361cf1bf1cedc6dfa5605fee62f0702113` |
| TLSH | `T16585F2202237B166E0023A339C010BD5549862F15F1DBAFB6B29D7B67C359F395A23B7` |
| SSDEEP | `24576:8l1yUi82JmfCpwAIouExW2Ir/vnXSdNsj04g4Yu2tQKizz+:0GHbxEXnXo403PHOC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_e59471db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e59471dbb08a04c5ec6df736f149919cc5333ef19da2b2de298d4f429d0c3612"
    family = "unknown"
    file_name = "macho_e59471dbb08a.bin"
    file_type = "macho"
    first_seen = "2026-10-24 23:25:33"
  condition:
    hash.sha256(0, filesize) == "e59471dbb08a04c5ec6df736f149919cc5333ef19da2b2de298d4f429d0c3612"
}
```

### Sample 59: `a9c7b69cece1e599`

| Field | Value |
|---|---|
| SHA-256 | `a9c7b69cece1e5999a2302d4152bc038ffe8305e84e3d974ace49132241c3206` |
| Family label | `unknown` |
| File name | `macho_a9c7b69cece1.bin` |
| File type | `macho` |
| First seen | `2026-10-24 23:25:21` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b21aca2edb7db5334baf81dd39d92de` |
| SHA-1 | `c82b16fa8f45775fb879fa38a32be17de2ec3abe` |
| SHA-256 | `a9c7b69cece1e5999a2302d4152bc038ffe8305e84e3d974ace49132241c3206` |
| SHA3-384 | `cd531bf8e87a987af24b0b44320746a49e3465511402e8dc8d10bff19ce0112bd323c2f9f75e77ca8af6f268f2764470` |
| TLSH | `T118A5F1200A1F21DAD4461033AD9A0F9D84B468B0CD0EE9EF5701B3A6DE3A7D7B752677` |
| SSDEEP | `24576:iM+0SyirVNGW6SKJ/Sl1bdvzMrnN7kyQvDfxhc3BnNZeb3XS3DQlzXAgxuxLhHrX:itIZ+pdlm3BnNZeHS3DYjt0VzfSDBC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_a9c7b69c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9c7b69cece1e5999a2302d4152bc038ffe8305e84e3d974ace49132241c3206"
    family = "unknown"
    file_name = "macho_a9c7b69cece1.bin"
    file_type = "macho"
    first_seen = "2026-10-24 23:25:21"
  condition:
    hash.sha256(0, filesize) == "a9c7b69cece1e5999a2302d4152bc038ffe8305e84e3d974ace49132241c3206"
}
```

### Sample 60: `aa2dac35eec9f05c`

| Field | Value |
|---|---|
| SHA-256 | `aa2dac35eec9f05c91eac1a3f9abf8f3d3f42023a91b2487ee03fb18d40aca7e` |
| Family label | `unknown` |
| File name | `xzblib0.dll` |
| File type | `exe` |
| First seen | `2026-10-24 22:40:19` |
| Reporter | `KnownSpotter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `841d3be75d4488e9f25bfe2f3e1114a3` |
| SHA-1 | `4c6d6d5d7051a83dd769f9d65e4c6ab76a33dae7` |
| SHA-256 | `aa2dac35eec9f05c91eac1a3f9abf8f3d3f42023a91b2487ee03fb18d40aca7e` |
| SHA3-384 | `60c9dbd2f2693330556856c759b681d825b64f03eaa180b47f030d48ebca5ae2a703164424a3b721e74a247f349fed8f` |
| IMPHASH | `23359b5a2488fdb9d279b1ead9561c4e` |
| TLSH | `T1A7C623D95AD242F4D0D30610728A439AB481A64D86FD1C293DD62C462B5DCBF628FFFB` |
| SSDEEP | `196608:mEQETp0PBvtDCOSbAnqcaUuTwnJ7i72wGkYTUFuxBkxTMr:j/N0PuOWAnqW7ikwFuxiw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_aa2dac35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa2dac35eec9f05c91eac1a3f9abf8f3d3f42023a91b2487ee03fb18d40aca7e"
    family = "unknown"
    file_name = "xzblib0.dll"
    file_type = "exe"
    first_seen = "2026-10-24 22:40:19"
  condition:
    hash.sha256(0, filesize) == "aa2dac35eec9f05c91eac1a3f9abf8f3d3f42023a91b2487ee03fb18d40aca7e"
}
```

### Sample 61: `f791769f0d47f571`

| Field | Value |
|---|---|
| SHA-256 | `f791769f0d47f571f10468938866750301b228422b623307d623f06af81fca5f` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-24 22:29:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fef67922a94fca6ec1dfeabe8c7f9bdb` |
| SHA-1 | `a4b69c268ddad741884a7412591521b2eb5a896c` |
| SHA-256 | `f791769f0d47f571f10468938866750301b228422b623307d623f06af81fca5f` |
| SHA3-384 | `d788fee8372656733dbdde1173d9d6aa9ab25cc4f2149fb51e75371dbfdff3aab188a3101ccdc09dba9529b0fbe65fce` |
| TLSH | `T170556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmc:OSCX9B9tGNnD+pb0qAYPWTM2wza6J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_f791769f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f791769f0d47f571f10468938866750301b228422b623307d623f06af81fca5f"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-24 22:29:56"
  condition:
    hash.sha256(0, filesize) == "f791769f0d47f571f10468938866750301b228422b623307d623f06af81fca5f"
}
```

### Sample 62: `04ef642ea5f51c77`

| Field | Value |
|---|---|
| SHA-256 | `04ef642ea5f51c774c5f879827f989c5070efd2767c4d7d4022b1111ac6f7a94` |
| Family label | `Amadey` |
| File name | `10a320ba7543dcad47f4fef1c330f8c6.exe` |
| File type | `exe` |
| First seen | `2026-10-24 22:20:10` |
| Reporter | `abuse_ch` |
| Tags | `Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10a320ba7543dcad47f4fef1c330f8c6` |
| SHA-1 | `f9dcd5060a7d57b2b10e54f753af69c649e07bcf` |
| SHA-256 | `04ef642ea5f51c774c5f879827f989c5070efd2767c4d7d4022b1111ac6f7a94` |
| SHA3-384 | `b5019749fbd1dbceabf040a0b814f5d9659f692b3911fb66a634f65a39f698224f5aaeb2b77bee4af1d311f2b62cdecb` |
| IMPHASH | `b58bd4e4812298baf53153e8025268f6` |
| TLSH | `T1A3A45B203857C032D66191B10E7AFFF695ADA8259B3109DBB7D40E779D202D26B31F3A` |
| SSDEEP | `6144:EWgDaADwKk5dC6iI+KcjRr3lPeriztKjT1UXS+cnhUiAOxDTaVFh3pg:EWgDaADwKH971PerixehRkFh3pg` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_062_04ef642e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04ef642ea5f51c774c5f879827f989c5070efd2767c4d7d4022b1111ac6f7a94"
    family = "Amadey"
    file_name = "10a320ba7543dcad47f4fef1c330f8c6.exe"
    file_type = "exe"
    first_seen = "2026-10-24 22:20:10"
  condition:
    hash.sha256(0, filesize) == "04ef642ea5f51c774c5f879827f989c5070efd2767c4d7d4022b1111ac6f7a94"
}
```

### Sample 63: `5b6458c024a0333e`

| Field | Value |
|---|---|
| SHA-256 | `5b6458c024a0333edf779148aa23e3072fb1508103001f4dd6477f5805e262f5` |
| Family label | `Mirai` |
| File name | `nyx_bot_linux_amd64_hkdf` |
| File type | `elf` |
| First seen | `2026-10-24 21:49:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54a94898e7a879f25b9bb1c79a0e34c2` |
| SHA-1 | `3e7918af4258870a40037f900da02f29251d6db7` |
| SHA-256 | `5b6458c024a0333edf779148aa23e3072fb1508103001f4dd6477f5805e262f5` |
| SHA3-384 | `c670edc40d84af4a94fd72c0ecfab8c6c748aa8142fc66a8c8c2922472f18cd94aeab7d04249a0a018723a35927e09c0` |
| TLSH | `T1B3565B07EC6555E9C1AEE6348A629263BA717C486B3163D33F50F3782F72BC06A79704` |
| TELFHASH | `t1ab2248705dbc74b4b6a6da10b3a3b5b4567719a167f838b11023ad94ffc1e801ce683b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:USzf574he3RhNulFzN7e3/wvMG/YQOLNNvUsgCVhYKgdAHeLG1vPo9VYvEPKOKDF:UURBeK3YLOZN4Cdgd8RoIsTEv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_5b6458c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b6458c024a0333edf779148aa23e3072fb1508103001f4dd6477f5805e262f5"
    family = "Mirai"
    file_name = "nyx_bot_linux_amd64_hkdf"
    file_type = "elf"
    first_seen = "2026-10-24 21:49:56"
  condition:
    hash.sha256(0, filesize) == "5b6458c024a0333edf779148aa23e3072fb1508103001f4dd6477f5805e262f5"
}
```

### Sample 64: `6e136391f87beac4`

| Field | Value |
|---|---|
| SHA-256 | `6e136391f87beac4ae152e4f3f24ad61fb7b06df0fdb39d0005660ea1c5ea55e` |
| Family label | `Mirai` |
| File name | `llx.apk` |
| File type | `apk` |
| First seen | `2026-10-24 21:17:19` |
| Reporter | `tipo_deincognito` |
| Tags | `adb, aisuru, apk, loader, mirai, persistence, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad8c877da8ddb70a2d90ad98fe48a86e` |
| SHA-1 | `5e6cc3932bb168879a117765c541040afe922fc0` |
| SHA-256 | `6e136391f87beac4ae152e4f3f24ad61fb7b06df0fdb39d0005660ea1c5ea55e` |
| SHA3-384 | `57ae97050c8e2a34a934c9ae80d3f8a63a4e685a5e6e200592fae0645b5c95d6242e0393382e45ff0aa61c476704bd89` |
| TLSH | `T136642337A71A5E03FDDF75B89A9EED61C241A2148436E6351E30A5D07E09760C322BFD` |
| SSDEEP | `6144:agEsdPl3M6ig3Au1UMk51chrQi6hc829J6JuwL9hLJasFiqMnc50Uu:KC9DZUMe1c+i6hc8298TnFFFiqMn20Uu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_6e136391
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e136391f87beac4ae152e4f3f24ad61fb7b06df0fdb39d0005660ea1c5ea55e"
    family = "Mirai"
    file_name = "llx.apk"
    file_type = "apk"
    first_seen = "2026-10-24 21:17:19"
  condition:
    hash.sha256(0, filesize) == "6e136391f87beac4ae152e4f3f24ad61fb7b06df0fdb39d0005660ea1c5ea55e"
}
```

### Sample 65: `3cad72ca97f43944`

| Field | Value |
|---|---|
| SHA-256 | `3cad72ca97f4394491d63bbcb0c33f79c3871e4b58f2913a7270520a2b6da162` |
| Family label | `WannaCry` |
| File name | `3cad72ca97f4394491d63bbcb0c33f79c3871e4b58f2913a7270520a2b6da162` |
| File type | `exe` |
| First seen | `2026-10-24 21:15:09` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29d8f23fb69d3ba861a8ae3303a65c01` |
| SHA-1 | `473f0897af02b5746306c786bb3931e460a4aa8e` |
| SHA-256 | `3cad72ca97f4394491d63bbcb0c33f79c3871e4b58f2913a7270520a2b6da162` |
| SHA3-384 | `bff543f14ad55729e23d0aab05cdac82e43e2fbdbc296823262181aa2757c2d57df0e917957e49eca0917be50914a806` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T13A36239931BC81FCD106297484B78E22F3B37C6A22FE5B0F9B40457A2E53B56B750B52` |
| SSDEEP | `49152:jnXnGMSPbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnv:DXGPoBhz1aRxcSUDk36SAEdhv` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_065_3cad72ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cad72ca97f4394491d63bbcb0c33f79c3871e4b58f2913a7270520a2b6da162"
    family = "WannaCry"
    file_name = "3cad72ca97f4394491d63bbcb0c33f79c3871e4b58f2913a7270520a2b6da162"
    file_type = "exe"
    first_seen = "2026-10-24 21:15:09"
  condition:
    hash.sha256(0, filesize) == "3cad72ca97f4394491d63bbcb0c33f79c3871e4b58f2913a7270520a2b6da162"
}
```

### Sample 66: `d42fede1058f62ba`

| Field | Value |
|---|---|
| SHA-256 | `d42fede1058f62ba45ce9eff1923d644fd2cc1ab6ac1994abc58bd1fd6c666e6` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-24 20:52:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3886cebbe0394e565af8da1260d0b21b` |
| SHA-1 | `948c4d8f16a988c0f000c6dedb24e69e6418c08c` |
| SHA-256 | `d42fede1058f62ba45ce9eff1923d644fd2cc1ab6ac1994abc58bd1fd6c666e6` |
| SHA3-384 | `70d84528011af02af68e17d5cc9b8dd0c2c01e79221fee7c8859a869faebcff09188a57392fc677be503d7a05fa5dba3` |
| TLSH | `T1DF556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmk:OSCX9B9tGNnD+pb0qAYPWTM2wza6N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_d42fede1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d42fede1058f62ba45ce9eff1923d644fd2cc1ab6ac1994abc58bd1fd6c666e6"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-24 20:52:23"
  condition:
    hash.sha256(0, filesize) == "d42fede1058f62ba45ce9eff1923d644fd2cc1ab6ac1994abc58bd1fd6c666e6"
}
```

### Sample 67: `7505f68c6428914e`

| Field | Value |
|---|---|
| SHA-256 | `7505f68c6428914e3d2fc83a22440694370d3b55013485595f9863950256f7c4` |
| Family label | `unknown` |
| File name | `Adobe Installer.iso` |
| File type | `iso` |
| First seen | `2026-10-24 20:36:04` |
| Reporter | `smica83` |
| Tags | `cyuop-com, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8399cff4b78969dc3ec2bb55d59f3c8` |
| SHA-1 | `a238fb860a500f70a67228b1b595ae5203160a61` |
| SHA-256 | `7505f68c6428914e3d2fc83a22440694370d3b55013485595f9863950256f7c4` |
| SHA3-384 | `b1f45117e31b27f31931c7017f01002dadf6c8280fd2225659219e9f877b298e7ad37d71cc5cfdd86b886f343acf0b83` |
| TLSH | `T13A37BE16B2588199D467907CC893865BE3B2BC25AB6183DF30A6B32D1F337D12B7E354` |
| SSDEEP | `393216:LoJesJnkfB846yhT/evPMRL31CPwDvt3uFhCkcFe9Xbp8kY3ucN6OJVBlH:GefBUEBNuc8Cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_7505f68c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7505f68c6428914e3d2fc83a22440694370d3b55013485595f9863950256f7c4"
    family = "unknown"
    file_name = "Adobe Installer.iso"
    file_type = "iso"
    first_seen = "2026-10-24 20:36:04"
  condition:
    hash.sha256(0, filesize) == "7505f68c6428914e3d2fc83a22440694370d3b55013485595f9863950256f7c4"
}
```

### Sample 68: `8b88b5ce9263f49c`

| Field | Value |
|---|---|
| SHA-256 | `8b88b5ce9263f49cbc0a2f05d754a75a860e970ceb9eb416cb767595a1d2451b` |
| Family label | `unknown` |
| File name | `Adobe Installer.iso` |
| File type | `iso` |
| First seen | `2026-10-24 20:34:07` |
| Reporter | `smica83` |
| Tags | `cyuop-com, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40f747b537eb469e2d106ec2e8bf4860` |
| SHA-1 | `8773a14a80f23ec6ce9c5eae72480e7c18d8daf3` |
| SHA-256 | `8b88b5ce9263f49cbc0a2f05d754a75a860e970ceb9eb416cb767595a1d2451b` |
| SHA3-384 | `77157cb5b5fb33a018e36ff066079aa7e31b58a0d488ba0f0f6a37a9d10fd77f260c4e2147284cb10c0f325676d6ce63` |
| TLSH | `T10D37BE16B2988199D467907CC853865BE3B2BC25AB6183DF30A6B32D1F337D12B7E354` |
| SSDEEP | `393216:boJesJnkfBTky1b4UyhT/evPMRL31CPwDvt3uFhCkcFe9Xbp8kY3ucN6OyVBlH:2efBTky1DEBNuc8lr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_8b88b5ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b88b5ce9263f49cbc0a2f05d754a75a860e970ceb9eb416cb767595a1d2451b"
    family = "unknown"
    file_name = "Adobe Installer.iso"
    file_type = "iso"
    first_seen = "2026-10-24 20:34:07"
  condition:
    hash.sha256(0, filesize) == "8b88b5ce9263f49cbc0a2f05d754a75a860e970ceb9eb416cb767595a1d2451b"
}
```

### Sample 69: `c189d6a23a412aea`

| Field | Value |
|---|---|
| SHA-256 | `c189d6a23a412aeabdb65e6ce77cee8632323bbc70c44435c2940d8725c69a01` |
| Family label | `unknown` |
| File name | `Adobe Installer.iso` |
| File type | `iso` |
| First seen | `2026-10-24 20:32:34` |
| Reporter | `smica83` |
| Tags | `cyuop-com, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a658f79a04be1f9ec69d742661c0a58` |
| SHA-1 | `4a23463dcf59c250e51f8d54cd0d1a2ce322b442` |
| SHA-256 | `c189d6a23a412aeabdb65e6ce77cee8632323bbc70c44435c2940d8725c69a01` |
| SHA3-384 | `65ae379496ef4bbb906ca08515a4d8f59a066c7e6c785d10601f8f66efe76c3adbb9fa28f8ad0679c26a7cc9682248d5` |
| TLSH | `T10D052211B8D0AB67C41A027A5006E30C5373DC48AFBA4447BAADF7191B7BF12D565BF2` |
| SSDEEP | `12288:J9peKPmY3fWQ+W1oDGLuLmdpl1kk5gNXT/AF9jc:JvJdWQq6LjflK4gloL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_c189d6a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c189d6a23a412aeabdb65e6ce77cee8632323bbc70c44435c2940d8725c69a01"
    family = "unknown"
    file_name = "Adobe Installer.iso"
    file_type = "iso"
    first_seen = "2026-10-24 20:32:34"
  condition:
    hash.sha256(0, filesize) == "c189d6a23a412aeabdb65e6ce77cee8632323bbc70c44435c2940d8725c69a01"
}
```

### Sample 70: `eaddd0e6bf1c3968`

| Field | Value |
|---|---|
| SHA-256 | `eaddd0e6bf1c396859cee853792e6878977c8951829e1c43a66b204cc11a6a47` |
| Family label | `unknown` |
| File name | `macho_eaddd0e6bf1c.bin` |
| File type | `macho` |
| First seen | `2026-10-24 20:22:58` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3effbcfeee25a6e428d67e075a228344` |
| SHA-1 | `e4737ec9f81ea8487946a51d24c5d8b8c19a449c` |
| SHA-256 | `eaddd0e6bf1c396859cee853792e6878977c8951829e1c43a66b204cc11a6a47` |
| SHA3-384 | `eb9f7cd148a47b77e3e30ce5b4592e41e205f164b3e6e40fc0840f8c3f55aee31735722e2d801abc53f6bd8d13e24890` |
| TLSH | `T12295F1201E1F218AE04611339C894F9E847068B0CD4EE9DE5352B3A6EE3A7D77762777` |
| SSDEEP | `24576:PbV/AWfnclFLTeS8tzv5xn4kfLYp5sL9E8LN+KPMPhSqbzFQ3ZEppkCn:PyTFLOZbYTKN+Kef9Qpg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_eaddd0e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaddd0e6bf1c396859cee853792e6878977c8951829e1c43a66b204cc11a6a47"
    family = "unknown"
    file_name = "macho_eaddd0e6bf1c.bin"
    file_type = "macho"
    first_seen = "2026-10-24 20:22:58"
  condition:
    hash.sha256(0, filesize) == "eaddd0e6bf1c396859cee853792e6878977c8951829e1c43a66b204cc11a6a47"
}
```

### Sample 71: `62e1c8b2f427296a`

| Field | Value |
|---|---|
| SHA-256 | `62e1c8b2f427296a64de68031105058afa1dfa0ada054cd98026746e51ba87c1` |
| Family label | `Mirai` |
| File name | `llx.powerpc` |
| File type | `elf` |
| First seen | `2026-10-24 19:49:41` |
| Reporter | `tipo_deincognito` |
| Tags | `adb, aisuru, ddos, elf, mirai, powerpc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0197fd67bc22b0a88ed8042b0e2324a7` |
| SHA-1 | `02524afcfdace33b1d2bd4b8654f08ccb32cd480` |
| SHA-256 | `62e1c8b2f427296a64de68031105058afa1dfa0ada054cd98026746e51ba87c1` |
| SHA3-384 | `120a63ef267cc3e55e0a55acb6d1f29c32dc1369ffed2dbd1a6b56b5fbdb28b6898765b248af59053afbad4c5dfbc35c` |
| TLSH | `T193848D81FF080522E0536DF0CA7F0FE6C30C47A17DF6B6197946769E0A36632DAA6395` |
| SSDEEP | `6144:shqvBgQ1PXda6kvZ/lfF/rg8JJ0LMqxd5B+OCRRkmR1DJ+biykcuPxNPJjtVLCLu:0Q9dattlfF/FJ8MntDlPJjtVUu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_62e1c8b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62e1c8b2f427296a64de68031105058afa1dfa0ada054cd98026746e51ba87c1"
    family = "Mirai"
    file_name = "llx.powerpc"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:41"
  condition:
    hash.sha256(0, filesize) == "62e1c8b2f427296a64de68031105058afa1dfa0ada054cd98026746e51ba87c1"
}
```

### Sample 72: `95d3b53b17d267bd`

| Field | Value |
|---|---|
| SHA-256 | `95d3b53b17d267bdb6b547a0c5f167d4807ce31349eb06fa698a6b0c111f2af2` |
| Family label | `Mirai` |
| File name | `llx.mipsel` |
| File type | `elf` |
| First seen | `2026-10-24 19:49:34` |
| Reporter | `tipo_deincognito` |
| Tags | `adb, aisuru, ddos, elf, mipsel, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb11bb4a61c948e7751c9c90520bf9a1` |
| SHA-1 | `a2e15b44f232cd513801de8e865005cca7191822` |
| SHA-256 | `95d3b53b17d267bdb6b547a0c5f167d4807ce31349eb06fa698a6b0c111f2af2` |
| SHA3-384 | `097e2548612904464c402e708d689fe07db04551b37692ba2081e186bd45f611e580b9611398744ca21796620e69d5bd` |
| TLSH | `T1C2846B8ADF510FDBC05ECD31015A830A169C1C5AAAF96B37A9B8F8767E793C54AD340C` |
| TELFHASH | `t1b23164097c3e9e162692ca50eec8b760c4dbe801490e0d3bde98499c5935197668dddf` |
| SSDEEP | `6144:LlvBp89HYj60FpgaXtm6H5f511VgBm1bYEgcHP2W7M698Myjo26Qj:Llwij60X3r1blOQ98Myjouj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_95d3b53b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95d3b53b17d267bdb6b547a0c5f167d4807ce31349eb06fa698a6b0c111f2af2"
    family = "Mirai"
    file_name = "llx.mipsel"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:34"
  condition:
    hash.sha256(0, filesize) == "95d3b53b17d267bdb6b547a0c5f167d4807ce31349eb06fa698a6b0c111f2af2"
}
```

### Sample 73: `9d12a0b1dac54677`

| Field | Value |
|---|---|
| SHA-256 | `9d12a0b1dac5467771edfeccb3c599b73412c0754051f5b0aabc8013e9346d50` |
| Family label | `Mirai` |
| File name | `llx.mips` |
| File type | `elf` |
| First seen | `2026-10-24 19:49:27` |
| Reporter | `tipo_deincognito` |
| Tags | `adb, aisuru, ddos, elf, mips, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a069bc8fc2275502e6b240f8b97b51fe` |
| SHA-1 | `001c42455a14a83a02129cce81b8b07228117f8b` |
| SHA-256 | `9d12a0b1dac5467771edfeccb3c599b73412c0754051f5b0aabc8013e9346d50` |
| SHA3-384 | `dfa781dc67c2ba7962bf58db8804a7a799d0ec6f8812ff87fc5b83e02e0f3d5d25e98245e397a250f6a729c06aad69dd` |
| TLSH | `T165846B4B67D24F65D296853001B38A2ED29626113FE2C794EA1DFD302EA4368FC6FF54` |
| TELFHASH | `t1b23164097c3e9e162692ca50eec8b760c4dbe801490e0d3bde98499c5935197668dddf` |
| SSDEEP | `6144:poEecZL3WJRWJZUcy1ZJeuJKUwsJvZDThM9LP3iM4gyhpVHejXZ:ld3aeUFef9MaLob+jXZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_9d12a0b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d12a0b1dac5467771edfeccb3c599b73412c0754051f5b0aabc8013e9346d50"
    family = "Mirai"
    file_name = "llx.mips"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:27"
  condition:
    hash.sha256(0, filesize) == "9d12a0b1dac5467771edfeccb3c599b73412c0754051f5b0aabc8013e9346d50"
}
```

### Sample 74: `9bd91039bad7799c`

| Field | Value |
|---|---|
| SHA-256 | `9bd91039bad7799c22da48a6ddfd7e83510c0c4adddbb8c4151f3eb9b2d52d23` |
| Family label | `Mirai` |
| File name | `llx.x86_64` |
| File type | `elf` |
| First seen | `2026-10-24 19:49:19` |
| Reporter | `tipo_deincognito` |
| Tags | `adb, aisuru, ddos, elf, mirai, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8034edec0f4f810cf22281ea4b5d5675` |
| SHA-1 | `fe88f39bc5e8c96dcd9c9669494754a38a78db48` |
| SHA-256 | `9bd91039bad7799c22da48a6ddfd7e83510c0c4adddbb8c4151f3eb9b2d52d23` |
| SHA3-384 | `2b2080a2469592ea8df838184b1dc9fe7d3daad460f9abae3cf371c46207c25279909b31af1b95add11a390c239a0960` |
| TLSH | `T145A4E642FDC3A4ACD13584F68F7D4FF6AE22F4582519A9B91694C2327A32F04CB99DD0` |
| SSDEEP | `3072:fv246nPp1AWWm/Ol4AJj/XmbWwhohSL2Kk1E68I3s97XrC7ehX/ya+JMlnLu+Hv0:EAWBcw2hSKebIOXrCFJM1PPAb8kskv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_9bd91039
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd91039bad7799c22da48a6ddfd7e83510c0c4adddbb8c4151f3eb9b2d52d23"
    family = "Mirai"
    file_name = "llx.x86_64"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:19"
  condition:
    hash.sha256(0, filesize) == "9bd91039bad7799c22da48a6ddfd7e83510c0c4adddbb8c4151f3eb9b2d52d23"
}
```

### Sample 75: `20740f7da1421e9f`

| Field | Value |
|---|---|
| SHA-256 | `20740f7da1421e9fea1199c7a44689b53317da9f6c63fd6c96f0cf1c13567f78` |
| Family label | `Mirai` |
| File name | `llx.i686` |
| File type | `elf` |
| First seen | `2026-10-24 19:49:12` |
| Reporter | `tipo_deincognito` |
| Tags | `adb, aisuru, ddos, elf, i686, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40296564ab6b0103c0e6805ceb46b2ec` |
| SHA-1 | `9a486510c60813266d366ce5519e3c82d1efbcce` |
| SHA-256 | `20740f7da1421e9fea1199c7a44689b53317da9f6c63fd6c96f0cf1c13567f78` |
| SHA3-384 | `27aa3455bac7c0a1d312c9e2bad36b90aaeb6f3370a714ae5e15ab039a649a8fdab746a691f43563400971b14a623dec` |
| TLSH | `T18A743985FE67CDF0E2BF89701036A2265530572FD12AE7E5FF813A61B9756018C09AEC` |
| SSDEEP | `6144:LyBdGk2WTu6G8L1URE/B1cuO5wDsu4ku5ECGRr4/x:Zk2W9A6BfO5csu4ku5ECGRr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_20740f7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20740f7da1421e9fea1199c7a44689b53317da9f6c63fd6c96f0cf1c13567f78"
    family = "Mirai"
    file_name = "llx.i686"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:12"
  condition:
    hash.sha256(0, filesize) == "20740f7da1421e9fea1199c7a44689b53317da9f6c63fd6c96f0cf1c13567f78"
}
```

### Sample 76: `2dc2cda5399b4d50`

| Field | Value |
|---|---|
| SHA-256 | `2dc2cda5399b4d50d123592f8d4c890f84ce94b15b7f68d9084a362dbb9ede46` |
| Family label | `Mirai` |
| File name | `main_arm` |
| File type | `elf` |
| First seen | `2026-10-24 19:49:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0be551da761c51f6e61e51f0509cdcf7` |
| SHA-1 | `949e8063787b183e0cf31cc32895b3d0a8e41786` |
| SHA-256 | `2dc2cda5399b4d50d123592f8d4c890f84ce94b15b7f68d9084a362dbb9ede46` |
| SHA3-384 | `d2912ab6aff12e2075a68ffcd4cfe14f44985ae369a2de7fc7bb046f48f2582e6664748351489fc7c5a85f1a6c9986ec` |
| TLSH | `T185E31945F8415B23C6C612BBFB5E428D3B2A17E9D3EF720399215F60378686B0E3B546` |
| TELFHASH | `t1412123651fd54ed857e04e8951ce6170765d3ce7df143ca3c8186f2bc753ae23124422` |
| SSDEEP | `1536:uF6vveSAAXEqTys04fNaxDX0hFJAYMz4V3GHhzZEbfOTuPI4+LImGPvJSlStwyws:uFACCySEzsFJc4wHBCbfOQMUm8vw9kd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_2dc2cda5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dc2cda5399b4d50d123592f8d4c890f84ce94b15b7f68d9084a362dbb9ede46"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:10"
  condition:
    hash.sha256(0, filesize) == "2dc2cda5399b4d50d123592f8d4c890f84ce94b15b7f68d9084a362dbb9ede46"
}
```

### Sample 77: `b99da9425f9a73c0`

| Field | Value |
|---|---|
| SHA-256 | `b99da9425f9a73c0c887485fb5692987ec123a239ae0f6ceb7d4b788b059f330` |
| Family label | `Mirai` |
| File name | `llx.armv5l` |
| File type | `elf` |
| First seen | `2026-10-24 19:49:05` |
| Reporter | `tipo_deincognito` |
| Tags | `adb, aisuru, arm, ddos, elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a08b7fc4ec491b927131e42c9082356a` |
| SHA-1 | `f661258d05536f1d9652b00da759af0ae4e26ff3` |
| SHA-256 | `b99da9425f9a73c0c887485fb5692987ec123a239ae0f6ceb7d4b788b059f330` |
| SHA3-384 | `3fca69cc6b8cdf78aa48de3e92a394f19dba13c302cca6787ef7caea602b91cb9bf2605f50a966a7df19f1df0d52c6e4` |
| TLSH | `T1D9646A41FCA08E11DAD01A7ABA3E028D7353177CD3DBB317DD104F2A67EB51A4A7A609` |
| SSDEEP | `6144:tgbJ9tv0wCPRTfb2QneweStdN1UBKHOsdUwSB0hgXj9PSpSQ:tWXv0wcZzb+KHxA0mXj9PSAQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_b99da942
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b99da9425f9a73c0c887485fb5692987ec123a239ae0f6ceb7d4b788b059f330"
    family = "Mirai"
    file_name = "llx.armv5l"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:05"
  condition:
    hash.sha256(0, filesize) == "b99da9425f9a73c0c887485fb5692987ec123a239ae0f6ceb7d4b788b059f330"
}
```

### Sample 78: `66d809ab37751057`

| Field | Value |
|---|---|
| SHA-256 | `66d809ab37751057afa220c80f31325357c8078780d6e35580e2b6f3a7b59a94` |
| Family label | `Mirai` |
| File name | `llx.armv7l` |
| File type | `elf` |
| First seen | `2026-10-24 19:48:58` |
| Reporter | `tipo_deincognito` |
| Tags | `adb, aisuru, arm, ddos, elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec515c822005018151840c1af8f084ab` |
| SHA-1 | `4fe951a066ab59e88b658f9f91486297ad71dc7b` |
| SHA-256 | `66d809ab37751057afa220c80f31325357c8078780d6e35580e2b6f3a7b59a94` |
| SHA3-384 | `68baac7eeb818fa604836391d023e08a01876ec4c46492af2525ed892aa1944b3bde8d21c8eafd0618941da3c57454b7` |
| TLSH | `T139645B89E8408E61C6D11A3AB67D429C73D3177DC3DBF31BDD300F28A79B9568A3A641` |
| SSDEEP | `6144:FgbJ9tv0wC+FQEU32oQlAqp/zAGdpWLEBl/70Y6bWHufmp6vgXj9dJhV:FWXv0wk4owAG02xhuOpjXj9dl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_66d809ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66d809ab37751057afa220c80f31325357c8078780d6e35580e2b6f3a7b59a94"
    family = "Mirai"
    file_name = "llx.armv7l"
    file_type = "elf"
    first_seen = "2026-10-24 19:48:58"
  condition:
    hash.sha256(0, filesize) == "66d809ab37751057afa220c80f31325357c8078780d6e35580e2b6f3a7b59a94"
}
```

### Sample 79: `a51f6d785ad9d195`

| Field | Value |
|---|---|
| SHA-256 | `a51f6d785ad9d1952603177b431918fab29e969e4946b8baf9d9cffb1f8c92d9` |
| Family label | `Mirai` |
| File name | `llx.aarch64` |
| File type | `elf` |
| First seen | `2026-10-24 19:48:50` |
| Reporter | `tipo_deincognito` |
| Tags | `aarch64, adb, aisuru, ddos, elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44798bcce6be6d6bec93e2b8cca4a192` |
| SHA-1 | `1332f10c45947294ceaef8e70fdcdb124f7e6441` |
| SHA-256 | `a51f6d785ad9d1952603177b431918fab29e969e4946b8baf9d9cffb1f8c92d9` |
| SHA3-384 | `bcd9e30a7dfb13a018acfd8753ffa2b1a23de127d5234b844b90fe5c8fa9e7fe8d671c886961fe201a09a960024e4cdf` |
| TLSH | `T196A4096DEF0DFB80ED8C47B4898B0FE3BA2EA46445E1C9611750826CB6C77E48937D52` |
| SSDEEP | `6144:80hqFoNH5w8cMlseDNiD0zuLYv58y6BOlDKon3Fli:Lkiw8N6OXui8N8n3Fl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_a51f6d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a51f6d785ad9d1952603177b431918fab29e969e4946b8baf9d9cffb1f8c92d9"
    family = "Mirai"
    file_name = "llx.aarch64"
    file_type = "elf"
    first_seen = "2026-10-24 19:48:50"
  condition:
    hash.sha256(0, filesize) == "a51f6d785ad9d1952603177b431918fab29e969e4946b8baf9d9cffb1f8c92d9"
}
```

### Sample 80: `29d9f9085b69b3d2`

| Field | Value |
|---|---|
| SHA-256 | `29d9f9085b69b3d26f92fb76e1bb037a195250400ba0d38df2179185760ee783` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.arm` |
| File type | `elf` |
| First seen | `2026-10-24 19:35:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6169947aa93756a257044f44208ed012` |
| SHA-1 | `5ba3c335f7720dd3d0f52efa9091234698ccf451` |
| SHA-256 | `29d9f9085b69b3d26f92fb76e1bb037a195250400ba0d38df2179185760ee783` |
| SHA3-384 | `b46a631c8d694dcc4b1f5f339d25693f764c615d376ff909f4010aaa454d88829f5fb82af947fd5650485b955809b4a7` |
| TLSH | `T1F3A31942FC91CE66C9D4577ADB6E109C332253B9D7C93302CD1847346FDEA880E6AB96` |
| TELFHASH | `t154d09710bcb40b0859e76974dacc5725ad057313a96a4b208e10caf4dc3f018f309c86` |
| SSDEEP | `1536:6CvhvOEMSL2NsKpp2OGWjvtpXfGV5AB0lWPz1o+jL0Uw/Y4dIOKmR/:VhbMSyUJWj+V6PzFoUw/Y12` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_29d9f908
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29d9f9085b69b3d26f92fb76e1bb037a195250400ba0d38df2179185760ee783"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm"
    file_type = "elf"
    first_seen = "2026-10-24 19:35:02"
  condition:
    hash.sha256(0, filesize) == "29d9f9085b69b3d26f92fb76e1bb037a195250400ba0d38df2179185760ee783"
}
```

### Sample 81: `8816810a3f8520a0`

| Field | Value |
|---|---|
| SHA-256 | `8816810a3f8520a0520afa391b25ac58b5d8bf918ecd320e1f8e4a28d61848e6` |
| Family label | `Mirai` |
| File name | `titanjr.ppc` |
| File type | `elf` |
| First seen | `2026-10-24 19:21:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e5863bbc307e387e4caff2ed671f04a` |
| SHA-1 | `45cb455ee482a41a2bc9a0b6fe865ba6c87fb6ea` |
| SHA-256 | `8816810a3f8520a0520afa391b25ac58b5d8bf918ecd320e1f8e4a28d61848e6` |
| SHA3-384 | `4157ed7587f68b41cea5ebb7546eb734db687503041d7f5ba8bbbdbc2bb846ec1a0a463e89eed6679cdb9c9cf4323a13` |
| TLSH | `T1A6143A02B31C0947D2632EF0363B17D0D3EF9AA220F4F645394FAA8991B2D365586DDE` |
| SSDEEP | `3072:mx6QA85lFejIRghm+DtzEDDxb8Dw8vwneQ2HtFKur+7e8:mNw0GmWzEDDxb2NYne7HWuya8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_8816810a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8816810a3f8520a0520afa391b25ac58b5d8bf918ecd320e1f8e4a28d61848e6"
    family = "Mirai"
    file_name = "titanjr.ppc"
    file_type = "elf"
    first_seen = "2026-10-24 19:21:01"
  condition:
    hash.sha256(0, filesize) == "8816810a3f8520a0520afa391b25ac58b5d8bf918ecd320e1f8e4a28d61848e6"
}
```

### Sample 82: `2e2612d964aaf92e`

| Field | Value |
|---|---|
| SHA-256 | `2e2612d964aaf92e7b57bccab58349518bcdfd3a3f07e1c70a71f4f6f6fef16c` |
| Family label | `unknown` |
| File name | `AS-2026-1048.zip` |
| File type | `zip` |
| First seen | `2026-10-24 19:17:33` |
| Reporter | `skocherhan` |
| Tags | `share-adminsimple-s3-eu-west-2-amazonaws-com, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b12193eafd58af055f425227fa1977d` |
| SHA-1 | `eb778efaa71bdc1ed56a11550122f81cdfa32e93` |
| SHA-256 | `2e2612d964aaf92e7b57bccab58349518bcdfd3a3f07e1c70a71f4f6f6fef16c` |
| SHA3-384 | `4f91e7270d206456f503bfdb064827c030fb1216e02aa4b459bf17e571055d5b25ef96e815d89fa3589b509f2e29fe81` |
| TLSH | `T105A4231C47EC90AE3E1EF8F07BE8C550E4DB5A1563D142A06401A79EBBDF6A25BDC324` |
| SSDEEP | `12288:RsMqHLqc9WtzeoZKNBDS5yHZI9aw828Ik:RsVHOcEtz5gNBDOy53w8Qk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_2e2612d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e2612d964aaf92e7b57bccab58349518bcdfd3a3f07e1c70a71f4f6f6fef16c"
    family = "unknown"
    file_name = "AS-2026-1048.zip"
    file_type = "zip"
    first_seen = "2026-10-24 19:17:33"
  condition:
    hash.sha256(0, filesize) == "2e2612d964aaf92e7b57bccab58349518bcdfd3a3f07e1c70a71f4f6f6fef16c"
}
```

### Sample 83: `fe5ab151cc1bc84e`

| Field | Value |
|---|---|
| SHA-256 | `fe5ab151cc1bc84e985263a4af1bde172c17ea6c3733e48d8da6631ca5ff82f3` |
| Family label | `WannaCry` |
| File name | `fe5ab151cc1bc84e985263a4af1bde172c17ea6c3733e48d8da6631ca5ff82f3` |
| File type | `exe` |
| First seen | `2026-10-24 19:15:40` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2788e1c9b85ddc3e598179c2e3cc929` |
| SHA-1 | `83a80b5baa2a3e24a7e5e3a6466c3a49ff34c802` |
| SHA-256 | `fe5ab151cc1bc84e985263a4af1bde172c17ea6c3733e48d8da6631ca5ff82f3` |
| SHA3-384 | `c40035fc52f7969828a36003b5934df0c4f28dc42471c59b2756584cb447965ed1934bc539a99d2806797903f4a02123` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T135363354626CA1BCF0510E7484B38D2AF7B37C6A97BA4F0F47C486AA0E53B976BD0741` |
| SSDEEP | `98304:DXDqPoBU1aRxcSUZk36SAEdhvxWa9P593R8yAVp2H:DXDqPT1Cxc7k3ZAEUadzR8yc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_083_fe5ab151
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe5ab151cc1bc84e985263a4af1bde172c17ea6c3733e48d8da6631ca5ff82f3"
    family = "WannaCry"
    file_name = "fe5ab151cc1bc84e985263a4af1bde172c17ea6c3733e48d8da6631ca5ff82f3"
    file_type = "exe"
    first_seen = "2026-10-24 19:15:40"
  condition:
    hash.sha256(0, filesize) == "fe5ab151cc1bc84e985263a4af1bde172c17ea6c3733e48d8da6631ca5ff82f3"
}
```

### Sample 84: `5cc1be09f0f23fc6`

| Field | Value |
|---|---|
| SHA-256 | `5cc1be09f0f23fc66b108e0de730189f7401db6b1ef1c525b8cbf6c7b2999365` |
| Family label | `unknown` |
| File name | `DivX.exe` |
| File type | `exe` |
| First seen | `2026-10-24 19:15:15` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9997314e52904f75468764553a63859` |
| SHA-1 | `2d8d3ad172421237c9acacfa177b07c26b57f45d` |
| SHA-256 | `5cc1be09f0f23fc66b108e0de730189f7401db6b1ef1c525b8cbf6c7b2999365` |
| SHA3-384 | `c880cb452bb2a7433b490d684a6b0d6c0b5d9660f926e2c26b1825bf025dc65ca1a422a62786b280297bc381fe16ee62` |
| IMPHASH | `f6c10cda88d849d7e8df3bc898aac756` |
| TLSH | `T15D35BC51B3D31AF9F175F5F8C605C102AA6D6B0D0EE075AA629C731E0B225B18BFE613` |
| SSDEEP | `24576:mgY1RMtj0i9lpcX0opi1hE1OfqLfs6P3:mgY16tj0eMdYE1qYJv` |
| ICON-DHASH | `449071696971162c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_5cc1be09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cc1be09f0f23fc66b108e0de730189f7401db6b1ef1c525b8cbf6c7b2999365"
    family = "unknown"
    file_name = "DivX.exe"
    file_type = "exe"
    first_seen = "2026-10-24 19:15:15"
  condition:
    hash.sha256(0, filesize) == "5cc1be09f0f23fc66b108e0de730189f7401db6b1ef1c525b8cbf6c7b2999365"
}
```

### Sample 85: `ec69d3e0d4d9e797`

| Field | Value |
|---|---|
| SHA-256 | `ec69d3e0d4d9e797c2942cd2aa177b269db94edf5bd104d7a8eb2ecc73029b4c` |
| Family label | `Mirai` |
| File name | `main_mips` |
| File type | `elf` |
| First seen | `2026-10-24 19:06:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51c61b435f49d8818ca274b710f0fa33` |
| SHA-1 | `2870abe706f9681bea40125f3ad941c912a5f99a` |
| SHA-256 | `ec69d3e0d4d9e797c2942cd2aa177b269db94edf5bd104d7a8eb2ecc73029b4c` |
| SHA3-384 | `176bf0864fe825ed483e7d97db736a3ed658c306829fb7832762180c9cbe097e55ba56926fc61993bd03c7e2633abc40` |
| TLSH | `T1AB14981E6E228F7EF2A8873447B75E259B5C23D627E1D644E1ACC1105E6038E641FFE8` |
| TELFHASH | `t14041800c097817e0a7356c5e099dff37d6a331eb7e262c278a51e46aab69b439c10c0d` |
| SSDEEP | `3072:R96Cg/fJ6/tHFEsc9BVZTJWBmxEU8pEalkleY:R9DNpQ5OBvU8yaeleY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_ec69d3e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec69d3e0d4d9e797c2942cd2aa177b269db94edf5bd104d7a8eb2ecc73029b4c"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-10-24 19:06:57"
  condition:
    hash.sha256(0, filesize) == "ec69d3e0d4d9e797c2942cd2aa177b269db94edf5bd104d7a8eb2ecc73029b4c"
}
```

### Sample 86: `229d92d5ee1ad82b`

| Field | Value |
|---|---|
| SHA-256 | `229d92d5ee1ad82be7388975dacf2087363ff4371515e711b29fdeb35dc06c1d` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.x86_64` |
| File type | `elf` |
| First seen | `2026-10-24 19:06:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `247d067786fc08ee23a29db78904a1b7` |
| SHA-1 | `97668dac95c051965bd29f47aeb1d0490fa8f31b` |
| SHA-256 | `229d92d5ee1ad82be7388975dacf2087363ff4371515e711b29fdeb35dc06c1d` |
| SHA3-384 | `d94e331d36638b24c5f0d9937ebbe20e382fc8986cf6b75f64b9447bef5dc98f236e28b36b48d78b1389da3a71761667` |
| TLSH | `T135B33A16A2925EFCC086C834877FA027D63074BD8532772F6BD49B316E53F780B26A65` |
| TELFHASH | `t10ce07d00fc75871c58db9a74dddd07b49500321250574b00cf10d6f0c83f444e308d5e` |
| SSDEEP | `3072:bnPMCL/odE0+tLjR7AJDesArld2nHpDCy+aOUf3Jh69qjT6R3G+C+Ah36+MK9d4s:bBTodE00LjR7AJDyrld2nHpDCy+a56J4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_229d92d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "229d92d5ee1ad82be7388975dacf2087363ff4371515e711b29fdeb35dc06c1d"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.x86_64"
    file_type = "elf"
    first_seen = "2026-10-24 19:06:55"
  condition:
    hash.sha256(0, filesize) == "229d92d5ee1ad82be7388975dacf2087363ff4371515e711b29fdeb35dc06c1d"
}
```

### Sample 87: `ecadbe1c7666d720`

| Field | Value |
|---|---|
| SHA-256 | `ecadbe1c7666d720590cadedfb26b570fdbac1a7e2b4ce239a616581ef9f93f0` |
| Family label | `Amadey` |
| File name | `03562fb03cff2628801a9b1d555e744b.exe` |
| File type | `exe` |
| First seen | `2026-10-24 18:55:09` |
| Reporter | `abuse_ch` |
| Tags | `Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03562fb03cff2628801a9b1d555e744b` |
| SHA-1 | `16d92473a1891fb21a4965f1cf5eab1eec71df7c` |
| SHA-256 | `ecadbe1c7666d720590cadedfb26b570fdbac1a7e2b4ce239a616581ef9f93f0` |
| SHA3-384 | `a1c29ae00b005c0ac87d6ea996dd5d5b267e00a8e86969052d3483db83ec319fd8232efb63ee636dbeaed661d03927d4` |
| IMPHASH | `3e3c7cd3783c316bb26868db037273eb` |
| TLSH | `T1E767338563CC7879F0B8DBB356D7A0C4733EE7A11A08A25F4968F6873B650D69343B42` |
| SSDEEP | `786432:dQ5+B4J2zTiPHOgrqndjZiypzqttTLWmbbII3s/i2uXii/fzQ6:7WPHOeUiywLWm/O/iLLzQ` |
| ICON-DHASH | `8e3371cccc71310b` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_087_ecadbe1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecadbe1c7666d720590cadedfb26b570fdbac1a7e2b4ce239a616581ef9f93f0"
    family = "Amadey"
    file_name = "03562fb03cff2628801a9b1d555e744b.exe"
    file_type = "exe"
    first_seen = "2026-10-24 18:55:09"
  condition:
    hash.sha256(0, filesize) == "ecadbe1c7666d720590cadedfb26b570fdbac1a7e2b4ce239a616581ef9f93f0"
}
```

### Sample 88: `8a67f2bc78d859d3`

| Field | Value |
|---|---|
| SHA-256 | `8a67f2bc78d859d328a491b68ab53f3f2680b183df0f2773ad511802007c8fbb` |
| Family label | `unknown` |
| File name | `8a67f2bc78d859d3.ps1` |
| File type | `ps1` |
| First seen | `2026-10-24 18:48:38` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b154681f0d800edb2627917d9734bf5c` |
| SHA-1 | `2566cbd57a4d94a8432b478d54a773eaa512f864` |
| SHA-256 | `8a67f2bc78d859d328a491b68ab53f3f2680b183df0f2773ad511802007c8fbb` |
| SHA3-384 | `a4b47236f55f055e2b743198ee5aa9bfa8472d5ceb41c1333827d92e3e731fbaafbdb0ae72111fb7381b3ed11d87442a` |
| TLSH | `T155D46D34BA022EFF5BB820C248C5811C563C36B4CA686DF569CB4CA3391D77627B79B5` |
| SSDEEP | `6144:O0wDgYUfC4F+NRrN7KxjCbBSVYqW7TdQgYeKCxdjIkotZd+fAPpP0yQn2VESiS1U:OjDSfmGgYWzj3khxP0NSiAPYQY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_8a67f2bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a67f2bc78d859d328a491b68ab53f3f2680b183df0f2773ad511802007c8fbb"
    family = "unknown"
    file_name = "8a67f2bc78d859d3.ps1"
    file_type = "ps1"
    first_seen = "2026-10-24 18:48:38"
  condition:
    hash.sha256(0, filesize) == "8a67f2bc78d859d328a491b68ab53f3f2680b183df0f2773ad511802007c8fbb"
}
```

### Sample 89: `2c4229230fdcb224`

| Field | Value |
|---|---|
| SHA-256 | `2c4229230fdcb224538828468a8642aaf4429a1591fe83776f8b3aa683d65050` |
| Family label | `unknown` |
| File name | `macho_2c4229230fdc.bin` |
| File type | `macho` |
| First seen | `2026-10-24 18:23:38` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e4f8c2a1d89208b20b9e526df937fa4` |
| SHA-1 | `fc5ed4e5960bf22f29e8a2ce8b88ea608de47c1a` |
| SHA-256 | `2c4229230fdcb224538828468a8642aaf4429a1591fe83776f8b3aa683d65050` |
| SHA3-384 | `3561c773345a917269128230203a5fc0ade80e67fcbe1d77025924e49b6c0786c8bfb831f7a35b2a3e000b3564f88fd8` |
| TLSH | `T1A895F2606A3E125AD8442072DC244FFA27B0B781A68CFAF9613487D73D35363F56726E` |
| SSDEEP | `24576:pFHgjoNV/KJsKFD8Cot3/+WO0Hszrc591y3k8uyG/TUnzpvfe9CWdyu5XkfZz2Gr:p4F4CP4yn5GTUzpQCxuVak/P+dx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_2c422923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c4229230fdcb224538828468a8642aaf4429a1591fe83776f8b3aa683d65050"
    family = "unknown"
    file_name = "macho_2c4229230fdc.bin"
    file_type = "macho"
    first_seen = "2026-10-24 18:23:38"
  condition:
    hash.sha256(0, filesize) == "2c4229230fdcb224538828468a8642aaf4429a1591fe83776f8b3aa683d65050"
}
```

### Sample 90: `1913ed2ad175632b`

| Field | Value |
|---|---|
| SHA-256 | `1913ed2ad175632b1b75e99bf5e291f551302b16dea51df318379e77a36f1ce9` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-10-24 18:21:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09651ebaab2f0e617f60f1090b8d1fe8` |
| SHA-1 | `7c24346e21f251fb9b37be36879424276230d748` |
| SHA-256 | `1913ed2ad175632b1b75e99bf5e291f551302b16dea51df318379e77a36f1ce9` |
| SHA3-384 | `39876e635f3208f5cef1791320f656818f76e84481c78d9c35337e8c0a4a0cacea6ae2e2a4cafa2314512b414ef46dab` |
| TLSH | `T19414D71AAB610FBBDCAFDD3702E90B0639CCA55722A43B353674D528F54A50B49E3C78` |
| SSDEEP | `1536:gaxspZ5BV+HUL+DHbJjzUMzuTOjYnuXxrK7dgUWFineZDoYz0onRBN3bmWWWZ5wm:Hx0V+0M9aBgTie7JtbmCZ5hHktReCo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_1913ed2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1913ed2ad175632b1b75e99bf5e291f551302b16dea51df318379e77a36f1ce9"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-10-24 18:21:12"
  condition:
    hash.sha256(0, filesize) == "1913ed2ad175632b1b75e99bf5e291f551302b16dea51df318379e77a36f1ce9"
}
```

### Sample 91: `0f1f82ed773b41db`

| Field | Value |
|---|---|
| SHA-256 | `0f1f82ed773b41dbcda1bb48984d8dc0b14e4192db2f3aea45f54cb592523a86` |
| Family label | `Mirai` |
| File name | `titanjr.m68k` |
| File type | `elf` |
| First seen | `2026-10-24 18:21:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `def0c3562f43fe3de3a1b8639723e1bf` |
| SHA-1 | `a32d0dd13ed4f90681fec6567ff18962b34c2c94` |
| SHA-256 | `0f1f82ed773b41dbcda1bb48984d8dc0b14e4192db2f3aea45f54cb592523a86` |
| SHA3-384 | `3c7ad4d00248486cf3e76772ee2994b0441a8b1d3dc42fdbbb1a6b7a599ca1f9ef3f223adeb46c037e807893b72587ca` |
| TLSH | `T1CD145BC3F900EDBDF80BE33B84174919B530A7A214935A33A257797BED3A1990537E86` |
| SSDEEP | `3072:BGJ5wF3ycqsa/Pdtctk3RRevIEQgbMtbZVijbiZLLzEqiyBO9Qhyiod:ogdyZCk3REv9wtbVLLEyB2Itod` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_0f1f82ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f1f82ed773b41dbcda1bb48984d8dc0b14e4192db2f3aea45f54cb592523a86"
    family = "Mirai"
    file_name = "titanjr.m68k"
    file_type = "elf"
    first_seen = "2026-10-24 18:21:10"
  condition:
    hash.sha256(0, filesize) == "0f1f82ed773b41dbcda1bb48984d8dc0b14e4192db2f3aea45f54cb592523a86"
}
```

### Sample 92: `d53a8a4ad1409c06`

| Field | Value |
|---|---|
| SHA-256 | `d53a8a4ad1409c069299e1217986badd91baa034c5795860f9eb5607f96cda79` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.mips` |
| File type | `elf` |
| First seen | `2026-10-24 18:19:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bc3164ad1149efe5b393fa79a42b66b` |
| SHA-1 | `1f2f176cb517a16c3360ead9f3290557b059200b` |
| SHA-256 | `d53a8a4ad1409c069299e1217986badd91baa034c5795860f9eb5607f96cda79` |
| SHA3-384 | `9a4ea865184c203dd5f29897cac33dbdfba726d9a06ea10b83c15de1bee7154efc99b375a0268c564f3f53dfa7a56bb2` |
| TLSH | `T165D3098BB7328F48F3A1D27346E78B7151A460510AE18196D12CFB563AC0F293C6BBD7` |
| TELFHASH | `t1bb11eab29f202b265692cc6898ef6327251cc2075708fe33e830845c105a0edf237caf` |
| SSDEEP | `1536:+nOD/iTuiX73YFej75R4iMCC47uxHYzihj0KPVd6aCrqsnXIJ/oDOMOjvLfL:+nODq7xR4iMn47uxHQihjt4XIJPMO/fL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_d53a8a4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d53a8a4ad1409c069299e1217986badd91baa034c5795860f9eb5607f96cda79"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.mips"
    file_type = "elf"
    first_seen = "2026-10-24 18:19:06"
  condition:
    hash.sha256(0, filesize) == "d53a8a4ad1409c069299e1217986badd91baa034c5795860f9eb5607f96cda79"
}
```

### Sample 93: `26117ae94f91603e`

| Field | Value |
|---|---|
| SHA-256 | `26117ae94f91603edcfd4811af97db75cc910ce11bc29da1fbc8ed7d5651c837` |
| Family label | `unknown` |
| File name | `DvX.exe` |
| File type | `exe` |
| First seen | `2026-10-24 18:09:01` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd2041f8dcb34cc11dac58363ff357c6` |
| SHA-1 | `2949ddc940027d87d35080d72a000a318c74cb4b` |
| SHA-256 | `26117ae94f91603edcfd4811af97db75cc910ce11bc29da1fbc8ed7d5651c837` |
| SHA3-384 | `ace232b50ecccb659c5227b7fc4e49be9dca31f547493224b5ce86df27faf6489bb77acc5287755c1850e2b0aeb181f5` |
| IMPHASH | `48217b0d534ee945af06b495ac510516` |
| TLSH | `T1EE456BE0BFAB0D7DF114CD7D58524135E92C311612EA687F086D53AB863F8C14AFAA6C` |
| SSDEEP | `12288:oo1yCpso285jb5jjTQjoq+/vc6yGXx++BFryHlAwU/0ThcCs+8/BDYyvbWU1Ilr9:o1SBBTQj2vJffFrOAwwSMb0R0IFm6` |
| ICON-DHASH | `6896716969719629` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_26117ae9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26117ae94f91603edcfd4811af97db75cc910ce11bc29da1fbc8ed7d5651c837"
    family = "unknown"
    file_name = "DvX.exe"
    file_type = "exe"
    first_seen = "2026-10-24 18:09:01"
  condition:
    hash.sha256(0, filesize) == "26117ae94f91603edcfd4811af97db75cc910ce11bc29da1fbc8ed7d5651c837"
}
```

### Sample 94: `2ab90b276553446e`

| Field | Value |
|---|---|
| SHA-256 | `2ab90b276553446e47c1de9507e1b8b9851fc5d89c783f2dbddc645dda1d7beb` |
| Family label | `unknown` |
| File name | `libcurl.dll` |
| File type | `exe` |
| First seen | `2026-10-24 18:01:55` |
| Reporter | `AmadeyHunter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb7f318ae8f09ce154dfbbebaaba4623` |
| SHA-1 | `e953f42fb6904f93f0efb1f4a56676c0b46488e7` |
| SHA-256 | `2ab90b276553446e47c1de9507e1b8b9851fc5d89c783f2dbddc645dda1d7beb` |
| SHA3-384 | `6a34af22fb5d8d35573bc61b71eb11d759d0dfd05061f8734dcfc8a5c05b6e6d7669b08d795c8433d0f6bb7580365f77` |
| IMPHASH | `26feafefb0c11ffb902e13b50866e63e` |
| TLSH | `T191C6305B5E360970DE2867335CB782B6EBF834CDC0AC9F21359969605EFA269307039D` |
| SSDEEP | `49152:4Vqm2u0ks4yb0UzeIwZGGlIeQQAlkn/i6jCf+0WmAFdsd+lY3/tnRUEdhpUk8wSa:41mIyQUzzX6j6HW7FdsH/XP15SxA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_2ab90b27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ab90b276553446e47c1de9507e1b8b9851fc5d89c783f2dbddc645dda1d7beb"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-10-24 18:01:55"
  condition:
    hash.sha256(0, filesize) == "2ab90b276553446e47c1de9507e1b8b9851fc5d89c783f2dbddc645dda1d7beb"
}
```

### Sample 95: `22bc6453262b24d0`

| Field | Value |
|---|---|
| SHA-256 | `22bc6453262b24d0811bd368c922a201e5f8fee726634448d9ff55794619a0b7` |
| Family label | `Mirai` |
| File name | `main_ppc` |
| File type | `elf` |
| First seen | `2026-10-24 17:54:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83290c3aeced6ee55436f217bef56de5` |
| SHA-1 | `4e89c6991fcf19ad2bda76e1276f3b3f38d94ee9` |
| SHA-256 | `22bc6453262b24d0811bd368c922a201e5f8fee726634448d9ff55794619a0b7` |
| SHA3-384 | `9e355e811d8a47368f7d9d62c4bb16cfb2d23fec3f39c66efe808fd8cbf9055e7d40f0f48fc42a934854aeb8ff2c6d39` |
| TLSH | `T120E33A42B30C0A47D2632EF03A3F67E097AFDAC121E4F645255FAB8991B5E321546ECD` |
| SSDEEP | `1536:aeAKTSFHRhV2irlxZ6oH0jxdjbZfwS56Hi31gixZ74UwsZRHszvAqunAvKxFMNus:a1FHp2irlrCjxjfws2wp7usQkqujkxJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_22bc6453
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22bc6453262b24d0811bd368c922a201e5f8fee726634448d9ff55794619a0b7"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-10-24 17:54:57"
  condition:
    hash.sha256(0, filesize) == "22bc6453262b24d0811bd368c922a201e5f8fee726634448d9ff55794619a0b7"
}
```

### Sample 96: `cff237dcf3ab4cdc`

| Field | Value |
|---|---|
| SHA-256 | `cff237dcf3ab4cdc554209a469c4a85e8545bb568189401982aaf2e321af564b` |
| Family label | `unknown` |
| File name | `DvX.exe` |
| File type | `exe` |
| First seen | `2026-10-24 17:47:53` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27c1c2f73df60fedf8de22d908ffa7a2` |
| SHA-1 | `f25e071becaf549e3783614f1c6f73e4bc9731ce` |
| SHA-256 | `cff237dcf3ab4cdc554209a469c4a85e8545bb568189401982aaf2e321af564b` |
| SHA3-384 | `187b3566705df0e6d43b2027f6576d0f227e8cde490185eefd4916f85cafd52b187e2d3d3e1f1343fd6eca3ccba99f91` |
| IMPHASH | `3cf6c0d91e72ff16be862bc169f19540` |
| TLSH | `T1D0355CA57BC10AB4F8D9A9B04513A3DB7FAC62A9F6F7432B0139CD9FD02589C4BD1490` |
| SSDEEP | `12288:WtqSlXtEKeug+0CVud/0zxzg/ZL7e2gB5jyR9chs5Uolh/Q0KAr9Vpd:WtnZbK/gtghm5k9chsLr/Qqr9bd` |
| ICON-DHASH | `4db271696961b2cd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_cff237dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cff237dcf3ab4cdc554209a469c4a85e8545bb568189401982aaf2e321af564b"
    family = "unknown"
    file_name = "DvX.exe"
    file_type = "exe"
    first_seen = "2026-10-24 17:47:53"
  condition:
    hash.sha256(0, filesize) == "cff237dcf3ab4cdc554209a469c4a85e8545bb568189401982aaf2e321af564b"
}
```

### Sample 97: `d02034ee326121d1`

| Field | Value |
|---|---|
| SHA-256 | `d02034ee326121d11671db64a82c14d1a9261a78158d6341b5aae03a43d410f0` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.arm5` |
| File type | `elf` |
| First seen | `2026-10-24 17:47:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24b3942466feefef76337bdefa35b0d1` |
| SHA-1 | `e40fb519c07983674d11a02659f33d62b9da715b` |
| SHA-256 | `d02034ee326121d11671db64a82c14d1a9261a78158d6341b5aae03a43d410f0` |
| SHA3-384 | `b907d5bf9280f75ff452f3948611cd7705a1fb59b7a7b2936192bd792d5e5d5def24aa8615ca1efddabc3fbd3aacdb55` |
| TLSH | `T179A3FA46FCC1CD66C9D4677AA66F51AC332263F8C7C53313CC1846256BDEA8C0A79B4A` |
| TELFHASH | `t154d09710bcb40b0859e76974dacc5725ad057313a96a4b208e10caf4dc3f018f309c86` |
| SSDEEP | `1536:vKpIoCFIxjb+1AlrCfR2W/gS2rdHgwR/gfFGPfVA9wEImBJf:ypI7MNE282FRiFGPf+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_d02034ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d02034ee326121d11671db64a82c14d1a9261a78158d6341b5aae03a43d410f0"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm5"
    file_type = "elf"
    first_seen = "2026-10-24 17:47:02"
  condition:
    hash.sha256(0, filesize) == "d02034ee326121d11671db64a82c14d1a9261a78158d6341b5aae03a43d410f0"
}
```

### Sample 98: `205ec415fbd019c4`

| Field | Value |
|---|---|
| SHA-256 | `205ec415fbd019c483684154649f9428fd35f0329bc954d0e5406abb20836586` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-24 17:43:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7207209e981124d8269254e13a826040` |
| SHA-1 | `6ff8fe60a2a43cba93a2c8701ff327659d12ac2d` |
| SHA-256 | `205ec415fbd019c483684154649f9428fd35f0329bc954d0e5406abb20836586` |
| SHA3-384 | `d74e5c74417e89ae1b3d19ddd16139cafd54dbf7fa0084a345714349f1bbc5f05a4fd2575cdcc188c2891abcd860ede4` |
| TLSH | `T163556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmIk:OSCX9B9tGNnD+pb0qAYPWTM2wza62` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_205ec415
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "205ec415fbd019c483684154649f9428fd35f0329bc954d0e5406abb20836586"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-24 17:43:00"
  condition:
    hash.sha256(0, filesize) == "205ec415fbd019c483684154649f9428fd35f0329bc954d0e5406abb20836586"
}
```

### Sample 99: `52196a9dcc2f5aa5`

| Field | Value |
|---|---|
| SHA-256 | `52196a9dcc2f5aa5578bebbbbf9acb8bea4bc35244fcba589ccc16f5db7332af` |
| Family label | `Mirai` |
| File name | `nyx_bot_linux_arm64_hkdf` |
| File type | `elf` |
| First seen | `2026-10-24 17:34:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8424bfc4a26a738390ac8b5cf11ab7f2` |
| SHA-1 | `0e4ea6e916a19bf44ec3224ba13933a12c2f7da1` |
| SHA-256 | `52196a9dcc2f5aa5578bebbbbf9acb8bea4bc35244fcba589ccc16f5db7332af` |
| SHA3-384 | `7fd8d4255608de405c29b9d68e2dc8db85ff3b938dd4b51d186289bda15cdb0a16c2a258e9b83b9bfd707215648f2ca8` |
| TLSH | `T13F566C99FC1D7462D5C97A752F7652953238BC098F82C3272614BB7CAEF23588F23261` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:6Iv6CEUixTer0JdviT7/jtqlS0aFz7GHtW5E1:6U6CE1xTc0JdviTTjtjmNME1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_52196a9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52196a9dcc2f5aa5578bebbbbf9acb8bea4bc35244fcba589ccc16f5db7332af"
    family = "Mirai"
    file_name = "nyx_bot_linux_arm64_hkdf"
    file_type = "elf"
    first_seen = "2026-10-24 17:34:55"
  condition:
    hash.sha256(0, filesize) == "52196a9dcc2f5aa5578bebbbbf9acb8bea4bc35244fcba589ccc16f5db7332af"
}
```

### Sample 100: `0d98501ac73fd2c3`

| Field | Value |
|---|---|
| SHA-256 | `0d98501ac73fd2c318e0e1a4a223b9e2589f235627e512eac8b88a275315b69a` |
| Family label | `unknown` |
| File name | `macho_0d98501ac73f.bin` |
| File type | `macho` |
| First seen | `2026-10-24 17:25:49` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `918d6c5b92de73a2fa4d8732af9c2efd` |
| SHA-1 | `887756ce1100ee5c76c70843b4678fca4949ac2d` |
| SHA-256 | `0d98501ac73fd2c318e0e1a4a223b9e2589f235627e512eac8b88a275315b69a` |
| SHA3-384 | `93f2800a039201d66da66c5e5f205f44185a7767e2a16341efbdf6e614611f827f01a2047810b0e1b2d607a9992166e2` |
| TLSH | `T14585F1145B7A42B7E488A1328C004F5E15E063F1AA4DB5F9B639C2976CF86C7F7A7312` |
| SSDEEP | `24576:lqtohkEhHX/SdnwMm5UJMJSRbtTdQ/BTyIliNn5h7Oz2HG9cMIDYop2MWLYXMvyR:LOnzMJs9+4IliBiz2m9wYgMvmBC6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_0d98501a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d98501ac73fd2c318e0e1a4a223b9e2589f235627e512eac8b88a275315b69a"
    family = "unknown"
    file_name = "macho_0d98501ac73f.bin"
    file_type = "macho"
    first_seen = "2026-10-24 17:25:49"
  condition:
    hash.sha256(0, filesize) == "0d98501ac73fd2c318e0e1a4a223b9e2589f235627e512eac8b88a275315b69a"
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
 * Generated: 2026-10-25T04:54:04.802633+00:00
 */

rule MalwareBazaar_unknown_001_579080b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "579080b865b3ad6d5801f001c05d63091ece5e6d358a260568cb6471a21dc665"
    family = "unknown"
    file_name = "579080b865b3ad6d.js"
    file_type = "js"
    first_seen = "2026-10-25 04:47:35"
  condition:
    hash.sha256(0, filesize) == "579080b865b3ad6d5801f001c05d63091ece5e6d358a260568cb6471a21dc665"
}

rule MalwareBazaar_unknown_002_0bdc6590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bdc6590285d46cafdea0cf8f136beeacc120aee708285d2c656a7f615514990"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-10-25 04:39:43"
  condition:
    hash.sha256(0, filesize) == "0bdc6590285d46cafdea0cf8f136beeacc120aee708285d2c656a7f615514990"
}

rule MalwareBazaar_unknown_003_47881d63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47881d6351a790090a82c7df270b27e430d1d09c967f9e32af40c49edb763791"
    family = "unknown"
    file_name = "47881d6351a790090a82c7df270b27e430d1d09c967f9e32af40c49edb763791"
    file_type = "gz"
    first_seen = "2026-10-25 03:51:08"
  condition:
    hash.sha256(0, filesize) == "47881d6351a790090a82c7df270b27e430d1d09c967f9e32af40c49edb763791"
}

rule MalwareBazaar_Mirai_004_a016f637
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a016f6371a48aeceb793cc80e22bbcf2bb946525c6500b56530ee0cd7751ce58"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-25 03:43:50"
  condition:
    hash.sha256(0, filesize) == "a016f6371a48aeceb793cc80e22bbcf2bb946525c6500b56530ee0cd7751ce58"
}

rule MalwareBazaar_Mirai_005_f7862077
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7862077e802e8cdb0117b2c9c2e43ceeed7dcde5b3e6dd7935cae71afd44d5a"
    family = "Mirai"
    file_name = "f7862077e802e8cdb0117b2c9c2e43ceeed7dcde5b3e6dd7935cae71afd44d5a.elf"
    file_type = "elf"
    first_seen = "2026-10-25 03:27:46"
  condition:
    hash.sha256(0, filesize) == "f7862077e802e8cdb0117b2c9c2e43ceeed7dcde5b3e6dd7935cae71afd44d5a"
}

rule MalwareBazaar_Vidar_006_f828c277
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f828c277b3316e0ee7a13b35b00c26553785e7e260d2d9f386ad97b94e6dbfe2"
    family = "Vidar"
    file_name = "f828c277b3316e0ee7a13b35b00c26553785e7e260d2d9f386ad97b94e6dbfe2.bin"
    file_type = "exe"
    first_seen = "2026-10-25 03:13:56"
  condition:
    hash.sha256(0, filesize) == "f828c277b3316e0ee7a13b35b00c26553785e7e260d2d9f386ad97b94e6dbfe2"
}

rule MalwareBazaar_Mirai_007_90950ae9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90950ae9570d317ba26d8a72f45c3d64821d4d2c8a916e78e01c24b6b13368dd"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-25 03:05:38"
  condition:
    hash.sha256(0, filesize) == "90950ae9570d317ba26d8a72f45c3d64821d4d2c8a916e78e01c24b6b13368dd"
}

rule MalwareBazaar_unknown_008_0de787cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0de787cffbec4dcc42e0ecd9491795c7dfe8fe4a955cb67a87544d5c36070982"
    family = "unknown"
    file_name = "0de787cffbec4dcc42e0ecd9491795c7dfe8fe4a955cb67a87544d5c36070982"
    file_type = "elf"
    first_seen = "2026-10-25 03:00:34"
  condition:
    hash.sha256(0, filesize) == "0de787cffbec4dcc42e0ecd9491795c7dfe8fe4a955cb67a87544d5c36070982"
}

rule MalwareBazaar_unknown_009_3fd5cc72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fd5cc721a1bc604d1300c9063eea7e63a3c9bef34fd1aae438b539980621017"
    family = "unknown"
    file_name = "3fd5cc721a1bc604.js"
    file_type = "js"
    first_seen = "2026-10-25 02:32:25"
  condition:
    hash.sha256(0, filesize) == "3fd5cc721a1bc604d1300c9063eea7e63a3c9bef34fd1aae438b539980621017"
}

rule MalwareBazaar_unknown_010_5efc93a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5efc93a8488495931f5b0eda5413a23077808fdcc676903055901be64ff22024"
    family = "unknown"
    file_name = "5efc93a8488495931f5b0eda5413a23077808fdcc676903055901be64ff22024"
    file_type = "elf"
    first_seen = "2026-10-25 02:30:35"
  condition:
    hash.sha256(0, filesize) == "5efc93a8488495931f5b0eda5413a23077808fdcc676903055901be64ff22024"
}

rule MalwareBazaar_unknown_011_f7e0b6ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7e0b6accc041625c706774b9bf0dc832d41c30f0ec63e4dc8aa27c1b062f3a1"
    family = "unknown"
    file_name = "f7e0b6accc041625.bin"
    file_type = "exe"
    first_seen = "2026-10-25 02:25:08"
  condition:
    hash.sha256(0, filesize) == "f7e0b6accc041625c706774b9bf0dc832d41c30f0ec63e4dc8aa27c1b062f3a1"
}

rule MalwareBazaar_Mirai_012_ee4a9b4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee4a9b4b2661ebb022274343293643073f13baf29622e889a484fd295f3b6196"
    family = "Mirai"
    file_name = "ee4a9b4b2661ebb022274343293643073f13baf29622e889a484fd295f3b6196"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:36"
  condition:
    hash.sha256(0, filesize) == "ee4a9b4b2661ebb022274343293643073f13baf29622e889a484fd295f3b6196"
}

rule MalwareBazaar_Mirai_013_d332dc8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d332dc8d033bf9687075a977ec3120bee7fcc4586592cc986fd432bb5525f7bc"
    family = "Mirai"
    file_name = "d332dc8d033bf9687075a977ec3120bee7fcc4586592cc986fd432bb5525f7bc"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:29"
  condition:
    hash.sha256(0, filesize) == "d332dc8d033bf9687075a977ec3120bee7fcc4586592cc986fd432bb5525f7bc"
}

rule MalwareBazaar_Mirai_014_caf3c783
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caf3c7832bc299ed1157bfc4c089ca44abc76f58f196c0b70283ab3f0f58938c"
    family = "Mirai"
    file_name = "caf3c7832bc299ed1157bfc4c089ca44abc76f58f196c0b70283ab3f0f58938c"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:23"
  condition:
    hash.sha256(0, filesize) == "caf3c7832bc299ed1157bfc4c089ca44abc76f58f196c0b70283ab3f0f58938c"
}

rule MalwareBazaar_Mirai_015_1f715216
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846"
    family = "Mirai"
    file_name = "1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:18"
  condition:
    hash.sha256(0, filesize) == "1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846"
}

rule MalwareBazaar_Mirai_016_e77cd1fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e77cd1fd16b6d11b3cb35a6fa3216f0e892c6fa567cfe2d3ab22199b08ea7d05"
    family = "Mirai"
    file_name = "e77cd1fd16b6d11b3cb35a6fa3216f0e892c6fa567cfe2d3ab22199b08ea7d05"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:11"
  condition:
    hash.sha256(0, filesize) == "e77cd1fd16b6d11b3cb35a6fa3216f0e892c6fa567cfe2d3ab22199b08ea7d05"
}

rule MalwareBazaar_Mirai_017_d9593813
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d959381329171033019f0407a82f5ae23760f4a596940a7635592093792be8c5"
    family = "Mirai"
    file_name = "d959381329171033019f0407a82f5ae23760f4a596940a7635592093792be8c5"
    file_type = "elf"
    first_seen = "2026-10-25 02:24:04"
  condition:
    hash.sha256(0, filesize) == "d959381329171033019f0407a82f5ae23760f4a596940a7635592093792be8c5"
}

rule MalwareBazaar_Mirai_018_d872e02c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d872e02c03b4896fd58eea4adfc8dd62342661808595f456f64cf1d3cee43a25"
    family = "Mirai"
    file_name = "d872e02c03b4896fd58eea4adfc8dd62342661808595f456f64cf1d3cee43a25"
    file_type = "elf"
    first_seen = "2026-10-25 02:23:57"
  condition:
    hash.sha256(0, filesize) == "d872e02c03b4896fd58eea4adfc8dd62342661808595f456f64cf1d3cee43a25"
}

rule MalwareBazaar_Mirai_019_766aa9a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "766aa9a5da63292222ae34b9037d8cd606db3cdedf3167389d40b3dfaf231367"
    family = "Mirai"
    file_name = "766aa9a5da63292222ae34b9037d8cd606db3cdedf3167389d40b3dfaf231367"
    file_type = "elf"
    first_seen = "2026-10-25 02:23:50"
  condition:
    hash.sha256(0, filesize) == "766aa9a5da63292222ae34b9037d8cd606db3cdedf3167389d40b3dfaf231367"
}

rule MalwareBazaar_Mirai_020_336d2891
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "336d289148053d2ad4530e1dcdeba03c14ef731854986b580a243faa20c5fe85"
    family = "Mirai"
    file_name = "336d289148053d2ad4530e1dcdeba03c14ef731854986b580a243faa20c5fe85"
    file_type = "elf"
    first_seen = "2026-10-25 02:23:43"
  condition:
    hash.sha256(0, filesize) == "336d289148053d2ad4530e1dcdeba03c14ef731854986b580a243faa20c5fe85"
}

rule MalwareBazaar_Mirai_021_1c16b8d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c16b8d89542e11371cae61830489b86aab13ad82a872ee7c892cf2333078a6d"
    family = "Mirai"
    file_name = "1c16b8d89542e11371cae61830489b86aab13ad82a872ee7c892cf2333078a6d"
    file_type = "elf"
    first_seen = "2026-10-25 02:23:36"
  condition:
    hash.sha256(0, filesize) == "1c16b8d89542e11371cae61830489b86aab13ad82a872ee7c892cf2333078a6d"
}

rule MalwareBazaar_Mirai_022_44aaf7dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44aaf7dc43cf054f82c676257ad7941fdddeb115b687804164ec673e9f098ad4"
    family = "Mirai"
    file_name = "44aaf7dc43cf054f82c676257ad7941fdddeb115b687804164ec673e9f098ad4"
    file_type = "elf"
    first_seen = "2026-10-25 02:23:30"
  condition:
    hash.sha256(0, filesize) == "44aaf7dc43cf054f82c676257ad7941fdddeb115b687804164ec673e9f098ad4"
}

rule MalwareBazaar_unknown_023_30f4e1bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30f4e1bc0cd96d4210765b18533eb0c5343f155a36b1a567132538242487d09c"
    family = "unknown"
    file_name = "com.hagaseca.thost9.apk"
    file_type = "apk"
    first_seen = "2026-10-25 02:20:17"
  condition:
    hash.sha256(0, filesize) == "30f4e1bc0cd96d4210765b18533eb0c5343f155a36b1a567132538242487d09c"
}

rule MalwareBazaar_unknown_024_eb88cf32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb88cf325bda936f2f53ea935ab8cdcd27cc75fdf9f06a6e203a9fd3eb5b9fe9"
    family = "unknown"
    file_name = "exploit_hp-021419-758075.sh"
    file_type = "sh"
    first_seen = "2026-10-25 02:14:43"
  condition:
    hash.sha256(0, filesize) == "eb88cf325bda936f2f53ea935ab8cdcd27cc75fdf9f06a6e203a9fd3eb5b9fe9"
}

rule MalwareBazaar_unknown_025_ccb17e61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccb17e61a3dcf6408f6176a50dfcba804497a71581de6158d9d37a4125a5735b"
    family = "unknown"
    file_name = "exploit_hp-185800-ffa3fe.sh"
    file_type = "sh"
    first_seen = "2026-10-25 02:09:04"
  condition:
    hash.sha256(0, filesize) == "ccb17e61a3dcf6408f6176a50dfcba804497a71581de6158d9d37a4125a5735b"
}

rule MalwareBazaar_Mirai_026_a2709508
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a27095084f1a8a42c556bf27c41812e22af8cd68858271507878415123b6e62c"
    family = "Mirai"
    file_name = "a27095084f1a8a42c556bf27c41812e22af8cd68858271507878415123b6e62c"
    file_type = "sh"
    first_seen = "2026-10-25 02:08:51"
  condition:
    hash.sha256(0, filesize) == "a27095084f1a8a42c556bf27c41812e22af8cd68858271507878415123b6e62c"
}

rule MalwareBazaar_unknown_027_23aa5f6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23aa5f6cd8d203918af2a80b7dde7b4aa5d0032006150b752cc710c724f0e5dd"
    family = "unknown"
    file_name = "open_dir_193_149_176_102_bins.sh"
    file_type = "sh"
    first_seen = "2026-10-25 02:01:45"
  condition:
    hash.sha256(0, filesize) == "23aa5f6cd8d203918af2a80b7dde7b4aa5d0032006150b752cc710c724f0e5dd"
}

rule MalwareBazaar_Mirai_028_a6716a57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6716a57efc3a1281fd9f4cc80b815dc7a79fae58907b10b872b5db87ad08cd4"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-10-25 01:49:49"
  condition:
    hash.sha256(0, filesize) == "a6716a57efc3a1281fd9f4cc80b815dc7a79fae58907b10b872b5db87ad08cd4"
}

rule MalwareBazaar_unknown_029_2de0e353
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2de0e353270c3beddc1f38b860c09f86757d9c7006208bbf09a7cc22055442eb"
    family = "unknown"
    file_name = "macho_2de0e353270c.bin"
    file_type = "macho"
    first_seen = "2026-10-25 01:36:28"
  condition:
    hash.sha256(0, filesize) == "2de0e353270c3beddc1f38b860c09f86757d9c7006208bbf09a7cc22055442eb"
}

rule MalwareBazaar_ConnectWise_030_63c1057c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c1057ce0510ec13d51209b71579079dabc120ea92e8125965005edbd7fc99c"
    family = "ConnectWise"
    file_name = "63c1057ce0510ec1.bin"
    file_type = "msi"
    first_seen = "2026-10-25 01:24:41"
  condition:
    hash.sha256(0, filesize) == "63c1057ce0510ec13d51209b71579079dabc120ea92e8125965005edbd7fc99c"
}

rule MalwareBazaar_unknown_031_6ceef8cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ceef8cdde345460463264ed20c225f867a0ef015e10322466b041d987903d9e"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-25 01:09:06"
  condition:
    hash.sha256(0, filesize) == "6ceef8cdde345460463264ed20c225f867a0ef015e10322466b041d987903d9e"
}

rule MalwareBazaar_Mirai_032_e60fa60f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e60fa60fd8d32a32314c8ea1c5b5c797cb57e3270470aa7b7934ef1678176851"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-25 01:05:47"
  condition:
    hash.sha256(0, filesize) == "e60fa60fd8d32a32314c8ea1c5b5c797cb57e3270470aa7b7934ef1678176851"
}

rule MalwareBazaar_unknown_033_d838168d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d838168d234ce4bedef14162b85b2c47ac97539e16a3d451682d493b5a173785"
    family = "unknown"
    file_name = "macho_d838168d234c.bin"
    file_type = "macho"
    first_seen = "2026-10-25 01:00:48"
  condition:
    hash.sha256(0, filesize) == "d838168d234ce4bedef14162b85b2c47ac97539e16a3d451682d493b5a173785"
}

rule MalwareBazaar_unknown_034_dc4db648
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc4db648c12775028fd2eaa82e831fafb1aa0b9e950fea74033eeb23220d1bca"
    family = "unknown"
    file_name = "macho_dc4db648c127.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:57:41"
  condition:
    hash.sha256(0, filesize) == "dc4db648c12775028fd2eaa82e831fafb1aa0b9e950fea74033eeb23220d1bca"
}

rule MalwareBazaar_unknown_035_78d0bbf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78d0bbf3ddb244caae5b955e6e9476e26f33f5a2e37b9d02863ad34b6476fb64"
    family = "unknown"
    file_name = "macho_78d0bbf3ddb2.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:54:36"
  condition:
    hash.sha256(0, filesize) == "78d0bbf3ddb244caae5b955e6e9476e26f33f5a2e37b9d02863ad34b6476fb64"
}

rule MalwareBazaar_unknown_036_f1935562
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f19355620754c842dd19e57d0b71f27e4c508d51c2f4b1a28f40db3e33cd7d5c"
    family = "unknown"
    file_name = "newisbest.exe"
    file_type = "exe"
    first_seen = "2026-10-25 00:52:34"
  condition:
    hash.sha256(0, filesize) == "f19355620754c842dd19e57d0b71f27e4c508d51c2f4b1a28f40db3e33cd7d5c"
}

rule MalwareBazaar_unknown_037_71cfefd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71cfefd6acba889266eb65ad63992d288a1c30deaa2bd38f1d22b9ec7dfa9220"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-10-25 00:52:28"
  condition:
    hash.sha256(0, filesize) == "71cfefd6acba889266eb65ad63992d288a1c30deaa2bd38f1d22b9ec7dfa9220"
}

rule MalwareBazaar_unknown_038_dba12dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dba12dd044d53dc35cb15d9432a2e6fa139d9f76d813ace626b3f84bac9f67ea"
    family = "unknown"
    file_name = "macho_dba12dd044d5.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:51:37"
  condition:
    hash.sha256(0, filesize) == "dba12dd044d53dc35cb15d9432a2e6fa139d9f76d813ace626b3f84bac9f67ea"
}

rule MalwareBazaar_unknown_039_917a3a55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "917a3a55eb7f0633d7869768dc16cc3bdc3727844cfc76c8628d93807792e9c0"
    family = "unknown"
    file_name = "917a3a55eb7f0633.ps1"
    file_type = "ps1"
    first_seen = "2026-10-25 00:48:40"
  condition:
    hash.sha256(0, filesize) == "917a3a55eb7f0633d7869768dc16cc3bdc3727844cfc76c8628d93807792e9c0"
}

rule MalwareBazaar_unknown_040_540d24a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "540d24a82a36a3e60497ee29fa51e3cc9963ecc50a9fa77fb245670d34879e09"
    family = "unknown"
    file_name = "macho_540d24a82a36.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:48:22"
  condition:
    hash.sha256(0, filesize) == "540d24a82a36a3e60497ee29fa51e3cc9963ecc50a9fa77fb245670d34879e09"
}

rule MalwareBazaar_unknown_041_f09773a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f09773a220d16e25ff8626af5ae925829bf180bcceb84431f72778bfe84a0475"
    family = "unknown"
    file_name = "macho_f09773a220d1.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:45:16"
  condition:
    hash.sha256(0, filesize) == "f09773a220d16e25ff8626af5ae925829bf180bcceb84431f72778bfe84a0475"
}

rule MalwareBazaar_unknown_042_d60004e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d60004e652baebc1230dc7262b2983b3d8c62f1f7b132edaba8b68c6a82b20c0"
    family = "unknown"
    file_name = "macho_d60004e652ba.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:42:15"
  condition:
    hash.sha256(0, filesize) == "d60004e652baebc1230dc7262b2983b3d8c62f1f7b132edaba8b68c6a82b20c0"
}

rule MalwareBazaar_unknown_043_6bbd6311
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bbd6311fa06d6dba192c8739fb1519b9a86074f718bae304c2bdc92c2608e7f"
    family = "unknown"
    file_name = "macho_6bbd6311fa06.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:39:11"
  condition:
    hash.sha256(0, filesize) == "6bbd6311fa06d6dba192c8739fb1519b9a86074f718bae304c2bdc92c2608e7f"
}

rule MalwareBazaar_unknown_044_8eec2049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8eec2049532e744253e3a5a654d7ce173e874ab8e6e247d6db8e51c97437e25f"
    family = "unknown"
    file_name = "8eec2049532e744253e3a5a654d7ce173e874ab8e6e247d6db8e51c97437e25f.exe"
    file_type = "exe"
    first_seen = "2026-10-25 00:38:10"
  condition:
    hash.sha256(0, filesize) == "8eec2049532e744253e3a5a654d7ce173e874ab8e6e247d6db8e51c97437e25f"
}

rule MalwareBazaar_unknown_045_49006e5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49006e5ef2cd5c0b48dcd4ec4f14ff17e15b737191dbb22c93bbac963f89ab15"
    family = "unknown"
    file_name = "macho_49006e5ef2cd.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:36:00"
  condition:
    hash.sha256(0, filesize) == "49006e5ef2cd5c0b48dcd4ec4f14ff17e15b737191dbb22c93bbac963f89ab15"
}

rule MalwareBazaar_unknown_046_3ab2cca8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ab2cca8113b62240a9bce2d312a920a55f0a2313c6a8f76d0427400e6d6ab3f"
    family = "unknown"
    file_name = "macho_3ab2cca8113b.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:32:59"
  condition:
    hash.sha256(0, filesize) == "3ab2cca8113b62240a9bce2d312a920a55f0a2313c6a8f76d0427400e6d6ab3f"
}

rule MalwareBazaar_unknown_047_757ac091
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "757ac091dec67dd9d7987ffe9a8c3cfc9be0fb643c6678faa831993a0343f46f"
    family = "unknown"
    file_name = "macho_757ac091dec6.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:29:41"
  condition:
    hash.sha256(0, filesize) == "757ac091dec67dd9d7987ffe9a8c3cfc9be0fb643c6678faa831993a0343f46f"
}

rule MalwareBazaar_SalatStealer_048_4fce2a5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fce2a5d9ba8e95349c421083190430383249980fe9a4ee9ef22e8037ffd0188"
    family = "SalatStealer"
    file_name = "3fc6de71f563acff.bin"
    file_type = "exe"
    first_seen = "2026-10-25 00:25:37"
  condition:
    hash.sha256(0, filesize) == "4fce2a5d9ba8e95349c421083190430383249980fe9a4ee9ef22e8037ffd0188"
}

rule MalwareBazaar_RustyStealer_049_833f41ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "833f41ac5e8787a25037a1badb65cdd1add14ae683af7486e1575762fbeeed60"
    family = "RustyStealer"
    file_name = "833f41ac5e8787a2.bin"
    file_type = "exe"
    first_seen = "2026-10-25 00:25:28"
  condition:
    hash.sha256(0, filesize) == "833f41ac5e8787a25037a1badb65cdd1add14ae683af7486e1575762fbeeed60"
}

rule MalwareBazaar_RustyStealer_050_02f4f05b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02f4f05b9697d1cbef49f3fd7ab92f99abd0e64f595eb533e286cadb635d95b3"
    family = "RustyStealer"
    file_name = "02f4f05b9697d1cb.bin"
    file_type = "exe"
    first_seen = "2026-10-25 00:25:21"
  condition:
    hash.sha256(0, filesize) == "02f4f05b9697d1cbef49f3fd7ab92f99abd0e64f595eb533e286cadb635d95b3"
}

rule MalwareBazaar_unknown_051_66ed7320
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66ed73200174f455ce49b39793eebcad7e3ea094a500e0c7ed2d42f92181039e"
    family = "unknown"
    file_name = "66ed73200174f455.bin"
    file_type = "elf"
    first_seen = "2026-10-25 00:25:15"
  condition:
    hash.sha256(0, filesize) == "66ed73200174f455ce49b39793eebcad7e3ea094a500e0c7ed2d42f92181039e"
}

rule MalwareBazaar_SalatStealer_052_3fc6de71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fc6de71f563acffc3935b197cfcbeb181567f28b549360a1637d42415322f62"
    family = "SalatStealer"
    file_name = "3fc6de71f563acff.bin"
    file_type = "exe"
    first_seen = "2026-10-25 00:25:05"
  condition:
    hash.sha256(0, filesize) == "3fc6de71f563acffc3935b197cfcbeb181567f28b549360a1637d42415322f62"
}

rule MalwareBazaar_unknown_053_51754c16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51754c16d7f70607d607d7c1bc6e1ed40ac29538b585784f69ea00b9dabe805f"
    family = "unknown"
    file_name = "macho_51754c16d7f7.bin"
    file_type = "macho"
    first_seen = "2026-10-25 00:23:39"
  condition:
    hash.sha256(0, filesize) == "51754c16d7f70607d607d7c1bc6e1ed40ac29538b585784f69ea00b9dabe805f"
}

rule MalwareBazaar_Mirai_054_6fe3779c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1"
    family = "Mirai"
    file_name = "6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1"
    file_type = "elf"
    first_seen = "2026-10-25 00:02:19"
  condition:
    hash.sha256(0, filesize) == "6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1"
}

rule MalwareBazaar_Mirai_055_31b24628
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293"
    family = "Mirai"
    file_name = "31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293"
    file_type = "elf"
    first_seen = "2026-10-25 00:02:15"
  condition:
    hash.sha256(0, filesize) == "31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293"
}

rule MalwareBazaar_Mirai_056_c41923f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c41923f219244fb0b28882e01c540c35706f19966b5fc070adf8be235b8be008"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-10-24 23:53:45"
  condition:
    hash.sha256(0, filesize) == "c41923f219244fb0b28882e01c540c35706f19966b5fc070adf8be235b8be008"
}

rule MalwareBazaar_unknown_057_7fdb4ed5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fdb4ed5896bbfd34f05a2aa00aa05b480df97673304f2b2f84122e65e387cbc"
    family = "unknown"
    file_name = "stage1_7fdb4ed58968.zsh"
    file_type = "zsh"
    first_seen = "2026-10-24 23:32:37"
  condition:
    hash.sha256(0, filesize) == "7fdb4ed5896bbfd34f05a2aa00aa05b480df97673304f2b2f84122e65e387cbc"
}

rule MalwareBazaar_unknown_058_e59471db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e59471dbb08a04c5ec6df736f149919cc5333ef19da2b2de298d4f429d0c3612"
    family = "unknown"
    file_name = "macho_e59471dbb08a.bin"
    file_type = "macho"
    first_seen = "2026-10-24 23:25:33"
  condition:
    hash.sha256(0, filesize) == "e59471dbb08a04c5ec6df736f149919cc5333ef19da2b2de298d4f429d0c3612"
}

rule MalwareBazaar_unknown_059_a9c7b69c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9c7b69cece1e5999a2302d4152bc038ffe8305e84e3d974ace49132241c3206"
    family = "unknown"
    file_name = "macho_a9c7b69cece1.bin"
    file_type = "macho"
    first_seen = "2026-10-24 23:25:21"
  condition:
    hash.sha256(0, filesize) == "a9c7b69cece1e5999a2302d4152bc038ffe8305e84e3d974ace49132241c3206"
}

rule MalwareBazaar_unknown_060_aa2dac35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa2dac35eec9f05c91eac1a3f9abf8f3d3f42023a91b2487ee03fb18d40aca7e"
    family = "unknown"
    file_name = "xzblib0.dll"
    file_type = "exe"
    first_seen = "2026-10-24 22:40:19"
  condition:
    hash.sha256(0, filesize) == "aa2dac35eec9f05c91eac1a3f9abf8f3d3f42023a91b2487ee03fb18d40aca7e"
}

rule MalwareBazaar_Mirai_061_f791769f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f791769f0d47f571f10468938866750301b228422b623307d623f06af81fca5f"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-24 22:29:56"
  condition:
    hash.sha256(0, filesize) == "f791769f0d47f571f10468938866750301b228422b623307d623f06af81fca5f"
}

rule MalwareBazaar_Amadey_062_04ef642e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04ef642ea5f51c774c5f879827f989c5070efd2767c4d7d4022b1111ac6f7a94"
    family = "Amadey"
    file_name = "10a320ba7543dcad47f4fef1c330f8c6.exe"
    file_type = "exe"
    first_seen = "2026-10-24 22:20:10"
  condition:
    hash.sha256(0, filesize) == "04ef642ea5f51c774c5f879827f989c5070efd2767c4d7d4022b1111ac6f7a94"
}

rule MalwareBazaar_Mirai_063_5b6458c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b6458c024a0333edf779148aa23e3072fb1508103001f4dd6477f5805e262f5"
    family = "Mirai"
    file_name = "nyx_bot_linux_amd64_hkdf"
    file_type = "elf"
    first_seen = "2026-10-24 21:49:56"
  condition:
    hash.sha256(0, filesize) == "5b6458c024a0333edf779148aa23e3072fb1508103001f4dd6477f5805e262f5"
}

rule MalwareBazaar_Mirai_064_6e136391
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e136391f87beac4ae152e4f3f24ad61fb7b06df0fdb39d0005660ea1c5ea55e"
    family = "Mirai"
    file_name = "llx.apk"
    file_type = "apk"
    first_seen = "2026-10-24 21:17:19"
  condition:
    hash.sha256(0, filesize) == "6e136391f87beac4ae152e4f3f24ad61fb7b06df0fdb39d0005660ea1c5ea55e"
}

rule MalwareBazaar_WannaCry_065_3cad72ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cad72ca97f4394491d63bbcb0c33f79c3871e4b58f2913a7270520a2b6da162"
    family = "WannaCry"
    file_name = "3cad72ca97f4394491d63bbcb0c33f79c3871e4b58f2913a7270520a2b6da162"
    file_type = "exe"
    first_seen = "2026-10-24 21:15:09"
  condition:
    hash.sha256(0, filesize) == "3cad72ca97f4394491d63bbcb0c33f79c3871e4b58f2913a7270520a2b6da162"
}

rule MalwareBazaar_Mirai_066_d42fede1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d42fede1058f62ba45ce9eff1923d644fd2cc1ab6ac1994abc58bd1fd6c666e6"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-24 20:52:23"
  condition:
    hash.sha256(0, filesize) == "d42fede1058f62ba45ce9eff1923d644fd2cc1ab6ac1994abc58bd1fd6c666e6"
}

rule MalwareBazaar_unknown_067_7505f68c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7505f68c6428914e3d2fc83a22440694370d3b55013485595f9863950256f7c4"
    family = "unknown"
    file_name = "Adobe Installer.iso"
    file_type = "iso"
    first_seen = "2026-10-24 20:36:04"
  condition:
    hash.sha256(0, filesize) == "7505f68c6428914e3d2fc83a22440694370d3b55013485595f9863950256f7c4"
}

rule MalwareBazaar_unknown_068_8b88b5ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b88b5ce9263f49cbc0a2f05d754a75a860e970ceb9eb416cb767595a1d2451b"
    family = "unknown"
    file_name = "Adobe Installer.iso"
    file_type = "iso"
    first_seen = "2026-10-24 20:34:07"
  condition:
    hash.sha256(0, filesize) == "8b88b5ce9263f49cbc0a2f05d754a75a860e970ceb9eb416cb767595a1d2451b"
}

rule MalwareBazaar_unknown_069_c189d6a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c189d6a23a412aeabdb65e6ce77cee8632323bbc70c44435c2940d8725c69a01"
    family = "unknown"
    file_name = "Adobe Installer.iso"
    file_type = "iso"
    first_seen = "2026-10-24 20:32:34"
  condition:
    hash.sha256(0, filesize) == "c189d6a23a412aeabdb65e6ce77cee8632323bbc70c44435c2940d8725c69a01"
}

rule MalwareBazaar_unknown_070_eaddd0e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaddd0e6bf1c396859cee853792e6878977c8951829e1c43a66b204cc11a6a47"
    family = "unknown"
    file_name = "macho_eaddd0e6bf1c.bin"
    file_type = "macho"
    first_seen = "2026-10-24 20:22:58"
  condition:
    hash.sha256(0, filesize) == "eaddd0e6bf1c396859cee853792e6878977c8951829e1c43a66b204cc11a6a47"
}

rule MalwareBazaar_Mirai_071_62e1c8b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62e1c8b2f427296a64de68031105058afa1dfa0ada054cd98026746e51ba87c1"
    family = "Mirai"
    file_name = "llx.powerpc"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:41"
  condition:
    hash.sha256(0, filesize) == "62e1c8b2f427296a64de68031105058afa1dfa0ada054cd98026746e51ba87c1"
}

rule MalwareBazaar_Mirai_072_95d3b53b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95d3b53b17d267bdb6b547a0c5f167d4807ce31349eb06fa698a6b0c111f2af2"
    family = "Mirai"
    file_name = "llx.mipsel"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:34"
  condition:
    hash.sha256(0, filesize) == "95d3b53b17d267bdb6b547a0c5f167d4807ce31349eb06fa698a6b0c111f2af2"
}

rule MalwareBazaar_Mirai_073_9d12a0b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d12a0b1dac5467771edfeccb3c599b73412c0754051f5b0aabc8013e9346d50"
    family = "Mirai"
    file_name = "llx.mips"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:27"
  condition:
    hash.sha256(0, filesize) == "9d12a0b1dac5467771edfeccb3c599b73412c0754051f5b0aabc8013e9346d50"
}

rule MalwareBazaar_Mirai_074_9bd91039
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd91039bad7799c22da48a6ddfd7e83510c0c4adddbb8c4151f3eb9b2d52d23"
    family = "Mirai"
    file_name = "llx.x86_64"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:19"
  condition:
    hash.sha256(0, filesize) == "9bd91039bad7799c22da48a6ddfd7e83510c0c4adddbb8c4151f3eb9b2d52d23"
}

rule MalwareBazaar_Mirai_075_20740f7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20740f7da1421e9fea1199c7a44689b53317da9f6c63fd6c96f0cf1c13567f78"
    family = "Mirai"
    file_name = "llx.i686"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:12"
  condition:
    hash.sha256(0, filesize) == "20740f7da1421e9fea1199c7a44689b53317da9f6c63fd6c96f0cf1c13567f78"
}

rule MalwareBazaar_Mirai_076_2dc2cda5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dc2cda5399b4d50d123592f8d4c890f84ce94b15b7f68d9084a362dbb9ede46"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:10"
  condition:
    hash.sha256(0, filesize) == "2dc2cda5399b4d50d123592f8d4c890f84ce94b15b7f68d9084a362dbb9ede46"
}

rule MalwareBazaar_Mirai_077_b99da942
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b99da9425f9a73c0c887485fb5692987ec123a239ae0f6ceb7d4b788b059f330"
    family = "Mirai"
    file_name = "llx.armv5l"
    file_type = "elf"
    first_seen = "2026-10-24 19:49:05"
  condition:
    hash.sha256(0, filesize) == "b99da9425f9a73c0c887485fb5692987ec123a239ae0f6ceb7d4b788b059f330"
}

rule MalwareBazaar_Mirai_078_66d809ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66d809ab37751057afa220c80f31325357c8078780d6e35580e2b6f3a7b59a94"
    family = "Mirai"
    file_name = "llx.armv7l"
    file_type = "elf"
    first_seen = "2026-10-24 19:48:58"
  condition:
    hash.sha256(0, filesize) == "66d809ab37751057afa220c80f31325357c8078780d6e35580e2b6f3a7b59a94"
}

rule MalwareBazaar_Mirai_079_a51f6d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a51f6d785ad9d1952603177b431918fab29e969e4946b8baf9d9cffb1f8c92d9"
    family = "Mirai"
    file_name = "llx.aarch64"
    file_type = "elf"
    first_seen = "2026-10-24 19:48:50"
  condition:
    hash.sha256(0, filesize) == "a51f6d785ad9d1952603177b431918fab29e969e4946b8baf9d9cffb1f8c92d9"
}

rule MalwareBazaar_Mirai_080_29d9f908
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29d9f9085b69b3d26f92fb76e1bb037a195250400ba0d38df2179185760ee783"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm"
    file_type = "elf"
    first_seen = "2026-10-24 19:35:02"
  condition:
    hash.sha256(0, filesize) == "29d9f9085b69b3d26f92fb76e1bb037a195250400ba0d38df2179185760ee783"
}

rule MalwareBazaar_Mirai_081_8816810a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8816810a3f8520a0520afa391b25ac58b5d8bf918ecd320e1f8e4a28d61848e6"
    family = "Mirai"
    file_name = "titanjr.ppc"
    file_type = "elf"
    first_seen = "2026-10-24 19:21:01"
  condition:
    hash.sha256(0, filesize) == "8816810a3f8520a0520afa391b25ac58b5d8bf918ecd320e1f8e4a28d61848e6"
}

rule MalwareBazaar_unknown_082_2e2612d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e2612d964aaf92e7b57bccab58349518bcdfd3a3f07e1c70a71f4f6f6fef16c"
    family = "unknown"
    file_name = "AS-2026-1048.zip"
    file_type = "zip"
    first_seen = "2026-10-24 19:17:33"
  condition:
    hash.sha256(0, filesize) == "2e2612d964aaf92e7b57bccab58349518bcdfd3a3f07e1c70a71f4f6f6fef16c"
}

rule MalwareBazaar_WannaCry_083_fe5ab151
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe5ab151cc1bc84e985263a4af1bde172c17ea6c3733e48d8da6631ca5ff82f3"
    family = "WannaCry"
    file_name = "fe5ab151cc1bc84e985263a4af1bde172c17ea6c3733e48d8da6631ca5ff82f3"
    file_type = "exe"
    first_seen = "2026-10-24 19:15:40"
  condition:
    hash.sha256(0, filesize) == "fe5ab151cc1bc84e985263a4af1bde172c17ea6c3733e48d8da6631ca5ff82f3"
}

rule MalwareBazaar_unknown_084_5cc1be09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cc1be09f0f23fc66b108e0de730189f7401db6b1ef1c525b8cbf6c7b2999365"
    family = "unknown"
    file_name = "DivX.exe"
    file_type = "exe"
    first_seen = "2026-10-24 19:15:15"
  condition:
    hash.sha256(0, filesize) == "5cc1be09f0f23fc66b108e0de730189f7401db6b1ef1c525b8cbf6c7b2999365"
}

rule MalwareBazaar_Mirai_085_ec69d3e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec69d3e0d4d9e797c2942cd2aa177b269db94edf5bd104d7a8eb2ecc73029b4c"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-10-24 19:06:57"
  condition:
    hash.sha256(0, filesize) == "ec69d3e0d4d9e797c2942cd2aa177b269db94edf5bd104d7a8eb2ecc73029b4c"
}

rule MalwareBazaar_Mirai_086_229d92d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "229d92d5ee1ad82be7388975dacf2087363ff4371515e711b29fdeb35dc06c1d"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.x86_64"
    file_type = "elf"
    first_seen = "2026-10-24 19:06:55"
  condition:
    hash.sha256(0, filesize) == "229d92d5ee1ad82be7388975dacf2087363ff4371515e711b29fdeb35dc06c1d"
}

rule MalwareBazaar_Amadey_087_ecadbe1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecadbe1c7666d720590cadedfb26b570fdbac1a7e2b4ce239a616581ef9f93f0"
    family = "Amadey"
    file_name = "03562fb03cff2628801a9b1d555e744b.exe"
    file_type = "exe"
    first_seen = "2026-10-24 18:55:09"
  condition:
    hash.sha256(0, filesize) == "ecadbe1c7666d720590cadedfb26b570fdbac1a7e2b4ce239a616581ef9f93f0"
}

rule MalwareBazaar_unknown_088_8a67f2bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a67f2bc78d859d328a491b68ab53f3f2680b183df0f2773ad511802007c8fbb"
    family = "unknown"
    file_name = "8a67f2bc78d859d3.ps1"
    file_type = "ps1"
    first_seen = "2026-10-24 18:48:38"
  condition:
    hash.sha256(0, filesize) == "8a67f2bc78d859d328a491b68ab53f3f2680b183df0f2773ad511802007c8fbb"
}

rule MalwareBazaar_unknown_089_2c422923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c4229230fdcb224538828468a8642aaf4429a1591fe83776f8b3aa683d65050"
    family = "unknown"
    file_name = "macho_2c4229230fdc.bin"
    file_type = "macho"
    first_seen = "2026-10-24 18:23:38"
  condition:
    hash.sha256(0, filesize) == "2c4229230fdcb224538828468a8642aaf4429a1591fe83776f8b3aa683d65050"
}

rule MalwareBazaar_Mirai_090_1913ed2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1913ed2ad175632b1b75e99bf5e291f551302b16dea51df318379e77a36f1ce9"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-10-24 18:21:12"
  condition:
    hash.sha256(0, filesize) == "1913ed2ad175632b1b75e99bf5e291f551302b16dea51df318379e77a36f1ce9"
}

rule MalwareBazaar_Mirai_091_0f1f82ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f1f82ed773b41dbcda1bb48984d8dc0b14e4192db2f3aea45f54cb592523a86"
    family = "Mirai"
    file_name = "titanjr.m68k"
    file_type = "elf"
    first_seen = "2026-10-24 18:21:10"
  condition:
    hash.sha256(0, filesize) == "0f1f82ed773b41dbcda1bb48984d8dc0b14e4192db2f3aea45f54cb592523a86"
}

rule MalwareBazaar_Mirai_092_d53a8a4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d53a8a4ad1409c069299e1217986badd91baa034c5795860f9eb5607f96cda79"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.mips"
    file_type = "elf"
    first_seen = "2026-10-24 18:19:06"
  condition:
    hash.sha256(0, filesize) == "d53a8a4ad1409c069299e1217986badd91baa034c5795860f9eb5607f96cda79"
}

rule MalwareBazaar_unknown_093_26117ae9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26117ae94f91603edcfd4811af97db75cc910ce11bc29da1fbc8ed7d5651c837"
    family = "unknown"
    file_name = "DvX.exe"
    file_type = "exe"
    first_seen = "2026-10-24 18:09:01"
  condition:
    hash.sha256(0, filesize) == "26117ae94f91603edcfd4811af97db75cc910ce11bc29da1fbc8ed7d5651c837"
}

rule MalwareBazaar_unknown_094_2ab90b27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ab90b276553446e47c1de9507e1b8b9851fc5d89c783f2dbddc645dda1d7beb"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-10-24 18:01:55"
  condition:
    hash.sha256(0, filesize) == "2ab90b276553446e47c1de9507e1b8b9851fc5d89c783f2dbddc645dda1d7beb"
}

rule MalwareBazaar_Mirai_095_22bc6453
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22bc6453262b24d0811bd368c922a201e5f8fee726634448d9ff55794619a0b7"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-10-24 17:54:57"
  condition:
    hash.sha256(0, filesize) == "22bc6453262b24d0811bd368c922a201e5f8fee726634448d9ff55794619a0b7"
}

rule MalwareBazaar_unknown_096_cff237dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cff237dcf3ab4cdc554209a469c4a85e8545bb568189401982aaf2e321af564b"
    family = "unknown"
    file_name = "DvX.exe"
    file_type = "exe"
    first_seen = "2026-10-24 17:47:53"
  condition:
    hash.sha256(0, filesize) == "cff237dcf3ab4cdc554209a469c4a85e8545bb568189401982aaf2e321af564b"
}

rule MalwareBazaar_Mirai_097_d02034ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d02034ee326121d11671db64a82c14d1a9261a78158d6341b5aae03a43d410f0"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm5"
    file_type = "elf"
    first_seen = "2026-10-24 17:47:02"
  condition:
    hash.sha256(0, filesize) == "d02034ee326121d11671db64a82c14d1a9261a78158d6341b5aae03a43d410f0"
}

rule MalwareBazaar_Mirai_098_205ec415
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "205ec415fbd019c483684154649f9428fd35f0329bc954d0e5406abb20836586"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-24 17:43:00"
  condition:
    hash.sha256(0, filesize) == "205ec415fbd019c483684154649f9428fd35f0329bc954d0e5406abb20836586"
}

rule MalwareBazaar_Mirai_099_52196a9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52196a9dcc2f5aa5578bebbbbf9acb8bea4bc35244fcba589ccc16f5db7332af"
    family = "Mirai"
    file_name = "nyx_bot_linux_arm64_hkdf"
    file_type = "elf"
    first_seen = "2026-10-24 17:34:55"
  condition:
    hash.sha256(0, filesize) == "52196a9dcc2f5aa5578bebbbbf9acb8bea4bc35244fcba589ccc16f5db7332af"
}

rule MalwareBazaar_unknown_100_0d98501a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d98501ac73fd2c318e0e1a4a223b9e2589f235627e512eac8b88a275315b69a"
    family = "unknown"
    file_name = "macho_0d98501ac73f.bin"
    file_type = "macho"
    first_seen = "2026-10-24 17:25:49"
  condition:
    hash.sha256(0, filesize) == "0d98501ac73fd2c318e0e1a4a223b9e2589f235627e512eac8b88a275315b69a"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

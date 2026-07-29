# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-29

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
| Unique family labels | 12 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 54 |
| Mirai | 31 |
| Phorpiex | 4 |
| CoinMiner | 2 |
| WannaCry | 2 |
| RemcosRAT | 1 |
| AgentTesla | 1 |
| WSHRAT | 1 |
| njrat | 1 |
| Formbook | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 34 |
| elf | 32 |
| sh | 10 |
| js | 7 |
| unknown | 6 |
| vbs | 3 |
| zip | 3 |
| msi | 2 |
| hta | 2 |
| tar | 1 |

## Per-Sample Analysis

### Sample 1: `9a5f306198f54047`

| Field | Value |
|---|---|
| SHA-256 | `9a5f306198f54047e7be608395869dc6d6dfc30757a04035c3c422f8c1a3495d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 03:41:25` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a44f85bfafe3d8011148c51f38f604e8` |
| SHA-1 | `38dab750a3a216aca66f4ae05e8c0a8e43dd2b77` |
| SHA-256 | `9a5f306198f54047e7be608395869dc6d6dfc30757a04035c3c422f8c1a3495d` |
| SHA3-384 | `120009674c6365857da1a99eaa08634cf74374b6e44495bb9248392c028e7be05446eb571923e8337d37d712ab769ce2` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T1B8823B0FB8424316E1E110B4967696BBD9B9AC7633C414EBF7D44AEE0A686C1FC3210F` |
| SSDEEP | `384:A+ZbmcmhzwEUaUu94gXTP+av8U9c+q4P:K5UaF9Ka0U11` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_9a5f3061
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a5f306198f54047e7be608395869dc6d6dfc30757a04035c3c422f8c1a3495d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 03:41:25"
  condition:
    hash.sha256(0, filesize) == "9a5f306198f54047e7be608395869dc6d6dfc30757a04035c3c422f8c1a3495d"
}
```

### Sample 2: `3f09145757282e6a`

| Field | Value |
|---|---|
| SHA-256 | `3f09145757282e6a59cd69319ac3b9da3265022a1d4f92a1646f8ddbaad89333` |
| Family label | `unknown` |
| File name | `請求書.JS` |
| File type | `js` |
| First seen | `2026-07-29 03:39:55` |
| Reporter | `Malfindal` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc76a69330918c7327b4990c7747ea67` |
| SHA-256 | `3f09145757282e6a59cd69319ac3b9da3265022a1d4f92a1646f8ddbaad89333` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_3f091457
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f09145757282e6a59cd69319ac3b9da3265022a1d4f92a1646f8ddbaad89333"
    family = "unknown"
    file_name = "請求書.JS"
    file_type = "js"
    first_seen = "2026-07-29 03:39:55"
  condition:
    hash.sha256(0, filesize) == "3f09145757282e6a59cd69319ac3b9da3265022a1d4f92a1646f8ddbaad89333"
}
```

### Sample 3: `4a6450f5a3676568`

| Field | Value |
|---|---|
| SHA-256 | `4a6450f5a3676568e1d3d993d1c6f908af7ca07c41887bf48d1ae9672fc58512` |
| Family label | `RemcosRAT` |
| File name | `7556TH364640.vbs` |
| File type | `vbs` |
| First seen | `2026-07-29 03:06:00` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2183f36851773f9cd4fdbc79e3eb1ef` |
| SHA-1 | `b20254344d0df6cf8bf08a8e3c55a0c041cefded` |
| SHA-256 | `4a6450f5a3676568e1d3d993d1c6f908af7ca07c41887bf48d1ae9672fc58512` |
| SHA3-384 | `33d0b7aead0243ae610fac1503f12b4c8f856c32f983fea7b61f035ec481b64758e1c6fd03a77fdbb3580f5e9b9c00f6` |
| TLSH | `T1DD441720DCD80B3A0E5707DDFE510A65C9FDC5298627D0ECEA9E171E50125ACEBBF268` |
| SSDEEP | `6144:FupSvRhXaMj2WSUYVrNpX+ChnQ+4U9RggxYsTQ:i1Mj2WinpzO+ZYT` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_003_4a6450f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a6450f5a3676568e1d3d993d1c6f908af7ca07c41887bf48d1ae9672fc58512"
    family = "RemcosRAT"
    file_name = "7556TH364640.vbs"
    file_type = "vbs"
    first_seen = "2026-07-29 03:06:00"
  condition:
    hash.sha256(0, filesize) == "4a6450f5a3676568e1d3d993d1c6f908af7ca07c41887bf48d1ae9672fc58512"
}
```

### Sample 4: `44df3b2362cac083`

| Field | Value |
|---|---|
| SHA-256 | `44df3b2362cac083812b2069678032b4b2dd91589023f9bae4fbd3746a23b1f9` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-29 02:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c469916e01f1764882d32285e439344` |
| SHA-1 | `6169ac3ced1b02027325a3ac80577ce536572bfb` |
| SHA-256 | `44df3b2362cac083812b2069678032b4b2dd91589023f9bae4fbd3746a23b1f9` |
| SHA3-384 | `1feaa3ea7c8a2a8573e3038bb8ca1cd4e5da7fa200f640e47d14fcdf6c68de16c8b7237e1bef5eef3b7b2ceeeb407d10` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T19CE633487ED001EEE9F3C138AEE15299D6B678B40BB3C9CF17A463A95D1B1E0453E247` |
| SSDEEP | `393216:kHMb7T1cSqhKqmWtCHxUSwXMCHWUjXQcuI3/PGTAI:ksb7T1XEK5WtCHqBXMb8XFH/O7` |
| ICON-DHASH | `f0d88ea29ac6f4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_44df3b23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44df3b2362cac083812b2069678032b4b2dd91589023f9bae4fbd3746a23b1f9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 02:52:32"
  condition:
    hash.sha256(0, filesize) == "44df3b2362cac083812b2069678032b4b2dd91589023f9bae4fbd3746a23b1f9"
}
```

### Sample 5: `cf8b604d9e3f1dc4`

| Field | Value |
|---|---|
| SHA-256 | `cf8b604d9e3f1dc4470ad1e5cdf8922a3a84021b08ee8b0700b76ea63e0781fb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 02:52:24` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a74be2b7ab2e316dbd6df0e295255c0b` |
| SHA-1 | `460e33b14cceb514393ca54fe3abb8eb33808b15` |
| SHA-256 | `cf8b604d9e3f1dc4470ad1e5cdf8922a3a84021b08ee8b0700b76ea63e0781fb` |
| SHA3-384 | `d5ed0607f40ca64b9a432572a9cc848c98861bee76410cded106dfc654c11d7ecb777936cb2d909c56cf1fbeb7d28d03` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T179823A0FB8424216E1D110B4957596BBD9B99C7633C418DBFBD44AEE1A686C1FC3250F` |
| SSDEEP | `192:AW26SkQzngjoWLsmBDTlIUqRQQPcleSMv9fKUSiu9zwfge+VOgbOOqmEd6FQv9P6:ANZbmsmBTQU0Vu94gXTPuav8U9c+w4P` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_cf8b604d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf8b604d9e3f1dc4470ad1e5cdf8922a3a84021b08ee8b0700b76ea63e0781fb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 02:52:24"
  condition:
    hash.sha256(0, filesize) == "cf8b604d9e3f1dc4470ad1e5cdf8922a3a84021b08ee8b0700b76ea63e0781fb"
}
```

### Sample 6: `6d785f191a10799f`

| Field | Value |
|---|---|
| SHA-256 | `6d785f191a10799f38e08cfc5563bd559729ec74efe2aa242c4542fd853f90d1` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-29 02:02:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17cfec542adc8dadd3e2ddc86e209327` |
| SHA-1 | `a1e333da3fb3406aeef2588d00f219431fb6ffab` |
| SHA-256 | `6d785f191a10799f38e08cfc5563bd559729ec74efe2aa242c4542fd853f90d1` |
| SHA3-384 | `3f2d17b9225a319a1695987764dd0872b1eff94b943ce380c4379133baf776259cf90280fa2c5c2ce14492fc8bf10144` |
| TLSH | `T163F30845FC519B13C6C612BBFB6E428D372A17A8D3EE32039D215F61378A85B0E3B546` |
| SSDEEP | `1536:9nG9tcj712jNwLGa3MRA+j4de2ozs4V/QHTDy2atbqE0kFGhz30lmdwyw+GrU+78:9ngONT3c8dem4uHfZaLw1/WPzrnq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_6d785f19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d785f191a10799f38e08cfc5563bd559729ec74efe2aa242c4542fd853f90d1"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-29 02:02:52"
  condition:
    hash.sha256(0, filesize) == "6d785f191a10799f38e08cfc5563bd559729ec74efe2aa242c4542fd853f90d1"
}
```

### Sample 7: `336ff5d2c361e594`

| Field | Value |
|---|---|
| SHA-256 | `336ff5d2c361e594327c54a8a5398bc0255f152d175f99bf3a9efd621c51a3b0` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-29 02:01:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `616d444d5d09d06f7a2c79d9e04d517d` |
| SHA-1 | `8eccb26b2367a367160ab29637830cb2ecc00b0a` |
| SHA-256 | `336ff5d2c361e594327c54a8a5398bc0255f152d175f99bf3a9efd621c51a3b0` |
| SHA3-384 | `971507d4ba388fafd8344ca5b187cfda590b0e16f773d72917abee91f4330b568e2ff4a9847c29ba1748120155ca2071` |
| TLSH | `T184042A56F8818B15C5C612BAFA2D524A37171778E3DF7203AD106F647B8B87B0F3A906` |
| TELFHASH | `t1b3f04694ab5462ed76e1034183a4756eafaa702d1e323850e1994e0e1ba1dc9653bc29` |
| SSDEEP | `3072:W+HeB+EYnNXOQ9EoKcXj5aMXRpVpbLbInh5KWZO:rHeB+EYN+Q9EkXNaMhpVmh5KW4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_336ff5d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "336ff5d2c361e594327c54a8a5398bc0255f152d175f99bf3a9efd621c51a3b0"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-29 02:01:07"
  condition:
    hash.sha256(0, filesize) == "336ff5d2c361e594327c54a8a5398bc0255f152d175f99bf3a9efd621c51a3b0"
}
```

### Sample 8: `eae10853be098476`

| Field | Value |
|---|---|
| SHA-256 | `eae10853be098476c31a1cb7d37c3b2dbc7ef80d73ce9d64306962eca8be8cc2` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-29 01:59:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fef8fcd25ca8007f5cd5d3eed991c1c0` |
| SHA-1 | `0744720e7bc8ba5cd65c050f641fce7af1c28464` |
| SHA-256 | `eae10853be098476c31a1cb7d37c3b2dbc7ef80d73ce9d64306962eca8be8cc2` |
| SHA3-384 | `33676e46c5132d5077d5627249cf66431c50135256b160bc00a1cf0e91cd736584cd8b6d4df5b0b6645e6d7d6cd258b1` |
| TLSH | `T17F044956B9C188FEC4D9D1780BFAF437E931F0AD526CB25727C4AE261E4DE204B2CA45` |
| TELFHASH | `t18951cb743c8f7a9c61d3a31ab30eed59fc3205111de274d5ae2b6ae5ce067880d634a2` |
| SSDEEP | `3072:Vw/DeklbF3a9sFuWS1ZVquHa1Uz1V6Dr1TkqdXxhbO/csFA/4:VwbeklbF3+FWItAgVOTdBjYA/4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_eae10853
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eae10853be098476c31a1cb7d37c3b2dbc7ef80d73ce9d64306962eca8be8cc2"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-29 01:59:30"
  condition:
    hash.sha256(0, filesize) == "eae10853be098476c31a1cb7d37c3b2dbc7ef80d73ce9d64306962eca8be8cc2"
}
```

### Sample 9: `c74820349ce06caf`

| Field | Value |
|---|---|
| SHA-256 | `c74820349ce06caf983178ef5ad7c8748afb1078caa98d66d1bb325a6f99d414` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-29 01:52:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97e9bd358da99b670578c833bf2fe245` |
| SHA-1 | `9d53153124d4888f69d32e0b2a34d73fc4202e29` |
| SHA-256 | `c74820349ce06caf983178ef5ad7c8748afb1078caa98d66d1bb325a6f99d414` |
| SHA3-384 | `86bd7f9978eb467a0f235fde1f91cbf99d19315fe9cc2610f48a52a20d2f590703a965f69797a668d788a2f40bc27a1c` |
| TLSH | `T13E01AFCAD26498404099C41D769F1154F831C3CA198BCBA4BF9CB43D9B54F10B036F88` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha7FCrJBkDW31EuX:e9Qp+Ms7QDCS1EuX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_c7482034
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c74820349ce06caf983178ef5ad7c8748afb1078caa98d66d1bb325a6f99d414"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-29 01:52:31"
  condition:
    hash.sha256(0, filesize) == "c74820349ce06caf983178ef5ad7c8748afb1078caa98d66d1bb325a6f99d414"
}
```

### Sample 10: `7d6f5eb4bc8cdea4`

| Field | Value |
|---|---|
| SHA-256 | `7d6f5eb4bc8cdea4b40f7a3f659c50b35020602abdd8e8a2e2fc31732330a92a` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-07-29 01:50:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `734ea4993da57f44368650260febf468` |
| SHA-1 | `f3213afec77a01847857e9b01278c844e4bb4e06` |
| SHA-256 | `7d6f5eb4bc8cdea4b40f7a3f659c50b35020602abdd8e8a2e2fc31732330a92a` |
| SHA3-384 | `672b5255247d90ad0ead2afe5f09719fd40e46f628a8330597c8ef97bad3222f1ab776d91b4c37ad6b65157c2188cb9f` |
| TLSH | `T120E3BE9BBA8B0090C44701F0278F4BEEAB6315859FAFC2E76D69B53B083D1DB9516B50` |
| SSDEEP | `1536:gVVaAFrSKjNLdqmK8jdfObjZAPxlKkNFap5nrRIgTKa10FHiqJ2O/LWSG7:gVkitN8/8jdmbFAPx13aKgTflOq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_7d6f5eb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d6f5eb4bc8cdea4b40f7a3f659c50b35020602abdd8e8a2e2fc31732330a92a"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-07-29 01:50:32"
  condition:
    hash.sha256(0, filesize) == "7d6f5eb4bc8cdea4b40f7a3f659c50b35020602abdd8e8a2e2fc31732330a92a"
}
```

### Sample 11: `96aa9b5fcc9f02bf`

| Field | Value |
|---|---|
| SHA-256 | `96aa9b5fcc9f02bf0879ae9b1e088b3f8dc978ec323da003b194fb660acd0713` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 01:48:45` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `682b9aca0ad2123c253d8324633cf648` |
| SHA-1 | `f05a7689454b9a1ae949f8177eaf6c1d682b8d57` |
| SHA-256 | `96aa9b5fcc9f02bf0879ae9b1e088b3f8dc978ec323da003b194fb660acd0713` |
| SHA3-384 | `66b6c447da3d20b32f136cd7c66160932da372323c9a950f88d497ecc58364b51ec568a8def7d5a2a48e707519da0842` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T13B823B0FB9424316E1E110B4966596BFD9B9AC7633C414EBF7D44AEE0A686C1FC3610F` |
| SSDEEP | `384:AZZbmcmhzcEUaUu94gXTP+av8U9c+z4P:l9UaF9Ka0U1+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_96aa9b5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96aa9b5fcc9f02bf0879ae9b1e088b3f8dc978ec323da003b194fb660acd0713"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 01:48:45"
  condition:
    hash.sha256(0, filesize) == "96aa9b5fcc9f02bf0879ae9b1e088b3f8dc978ec323da003b194fb660acd0713"
}
```

### Sample 12: `9c9dcacd3a247c78`

| Field | Value |
|---|---|
| SHA-256 | `9c9dcacd3a247c7860113f842cf920b8cfa205431c5f1e40747c774ba13069d7` |
| Family label | `AgentTesla` |
| File name | `Revised PI.js` |
| File type | `js` |
| First seen | `2026-07-29 01:37:26` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9452ccef2ed2f38e61bf4f1838c5fa13` |
| SHA-1 | `288348b56571068fb11a0579de46e84d3097f2da` |
| SHA-256 | `9c9dcacd3a247c7860113f842cf920b8cfa205431c5f1e40747c774ba13069d7` |
| SHA3-384 | `828babbfb86f52fbcb68fcf6bfa6101955ee79ce78df12b12e0e7718731e5251ec6f2bb7a9c77272179cfdef6543cac4` |
| TLSH | `T198750AB7872A13408B74D270463A8A74FDA886A10B8B5C46303DADC4AF7B1D5C75FAF5` |
| SSDEEP | `768:4ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddv:EfDFdO/b67` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_012_9c9dcacd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c9dcacd3a247c7860113f842cf920b8cfa205431c5f1e40747c774ba13069d7"
    family = "AgentTesla"
    file_name = "Revised PI.js"
    file_type = "js"
    first_seen = "2026-07-29 01:37:26"
  condition:
    hash.sha256(0, filesize) == "9c9dcacd3a247c7860113f842cf920b8cfa205431c5f1e40747c774ba13069d7"
}
```

### Sample 13: `441cb0179c91c4c3`

| Field | Value |
|---|---|
| SHA-256 | `441cb0179c91c4c36cbd05b75c6b9b8bd4a668518bceb7ba028a0b077d2a14eb` |
| Family label | `unknown` |
| File name | `Installer.msi` |
| File type | `msi` |
| First seen | `2026-07-29 01:35:35` |
| Reporter | `lfr` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67965bd0cd526b0ac5862e5ec90b6084` |
| SHA-1 | `666851917aaddb876ecb24818c5a6029da0e868f` |
| SHA-256 | `441cb0179c91c4c36cbd05b75c6b9b8bd4a668518bceb7ba028a0b077d2a14eb` |
| SHA3-384 | `aa3d6500589349d8c08a86a89f595e93528918f4ad44015eee8b26735eed184dfc6a6f5a7ef7ea88fc2abc8fd0db9e64` |
| TLSH | `T1CA2733A62C262E83CA5466BB23531342AF310DB33B1247412D7DE92D1CBD1FA5B5D39B` |
| SSDEEP | `393216:5jcQb0kS3gllQv87upa4GCAKUd2Cu3et11G+ahvcThiY:5akpC06ZA7dpIeRTUY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_441cb017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "441cb0179c91c4c36cbd05b75c6b9b8bd4a668518bceb7ba028a0b077d2a14eb"
    family = "unknown"
    file_name = "Installer.msi"
    file_type = "msi"
    first_seen = "2026-07-29 01:35:35"
  condition:
    hash.sha256(0, filesize) == "441cb0179c91c4c36cbd05b75c6b9b8bd4a668518bceb7ba028a0b077d2a14eb"
}
```

### Sample 14: `f47db0bc0f9accb6`

| Field | Value |
|---|---|
| SHA-256 | `f47db0bc0f9accb6cf4c033d81ceb1f79065c54616f90df4647ec0cb2d6f2ac0` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-29 01:34:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c78f84e27a9d0e544c00e1c3a4fb5798` |
| SHA-1 | `58d8cb699d5da0ea10acdb829c1fb29d6eb587d3` |
| SHA-256 | `f47db0bc0f9accb6cf4c033d81ceb1f79065c54616f90df4647ec0cb2d6f2ac0` |
| SHA3-384 | `7a0ed99a6c7220836c297eb27ada37ca8651626325073aa7a81a164b704c02cd915d3459f88fc4818f9cdc279376bc3d` |
| TLSH | `T1FC144AC7F801CDBEF80BF3764857040975B0B79164935A3B63A779ABAC3A0D52923D86` |
| SSDEEP | `3072:LXKHbrDEmBRai/26mT84H/ImMSV8jbiTL52lKy3Qcaafg:jK7Xwi/26mQ4wmMUL5y3iMg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_f47db0bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f47db0bc0f9accb6cf4c033d81ceb1f79065c54616f90df4647ec0cb2d6f2ac0"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-29 01:34:30"
  condition:
    hash.sha256(0, filesize) == "f47db0bc0f9accb6cf4c033d81ceb1f79065c54616f90df4647ec0cb2d6f2ac0"
}
```

### Sample 15: `a046184ae4efc3f0`

| Field | Value |
|---|---|
| SHA-256 | `a046184ae4efc3f09a283a3c24d1533a191d05dc843c78534c3f129ceaa9946e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-29 01:27:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `276e9e960593b4a8a547c88c572f15fc` |
| SHA-1 | `846df1a2e8606cd4d41f419f60f2a9b4d5a6e478` |
| SHA-256 | `a046184ae4efc3f09a283a3c24d1533a191d05dc843c78534c3f129ceaa9946e` |
| SHA3-384 | `2c56aebafed76b7cc1385d242b932fa80f26925b2a47498171cf3a12c3be91bb8623188097f0b92512579daf3860234a` |
| TLSH | `T1F2C27C966A867C44BEC94A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C15FACC618B1A` |
| SSDEEP | `768:c8vCB+25j6es8Rs69FYpMSUpi+20qUpi+20YQX:c8l25Jssd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_a046184a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a046184ae4efc3f09a283a3c24d1533a191d05dc843c78534c3f129ceaa9946e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-29 01:27:38"
  condition:
    hash.sha256(0, filesize) == "a046184ae4efc3f09a283a3c24d1533a191d05dc843c78534c3f129ceaa9946e"
}
```

### Sample 16: `79df12fb0a083f52`

| Field | Value |
|---|---|
| SHA-256 | `79df12fb0a083f52bf77cffe998c9be6e9f588b7f918af11435fc5629c1d82b6` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-29 01:23:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a0fed1a5a5ed0c161ca63b92dda3bdb` |
| SHA-1 | `f204f8e410bd99c14b8a7660e157103fda2fefac` |
| SHA-256 | `79df12fb0a083f52bf77cffe998c9be6e9f588b7f918af11435fc5629c1d82b6` |
| SHA3-384 | `b506df470b767e20f96239c4d99276e14470668ddd57a3b421c9aebdd6994d50af87be0d601e261b117e24b8adb0a78e` |
| TLSH | `T1F3043A02732C0D03D1A32EB03B3F27E097EF999221A4B541295F6F9E9175E326945ECE` |
| SSDEEP | `3072:8pK5PKdRpSMKN5FZXJx6qPSPYV7zxgzVu2:gMP0qXxBPSPk3xgZu2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_79df12fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79df12fb0a083f52bf77cffe998c9be6e9f588b7f918af11435fc5629c1d82b6"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-29 01:23:33"
  condition:
    hash.sha256(0, filesize) == "79df12fb0a083f52bf77cffe998c9be6e9f588b7f918af11435fc5629c1d82b6"
}
```

### Sample 17: `af03598bef65613a`

| Field | Value |
|---|---|
| SHA-256 | `af03598bef65613ab2c8a64fed066b9fd384d92da2fda23893b80ad5887812dc` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-29 01:09:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f11e121f524d11eb1bbd8eff4f6399eb` |
| SHA-1 | `2cd5e21ec078bdac860ccc25e72f5caef05a0ec7` |
| SHA-256 | `af03598bef65613ab2c8a64fed066b9fd384d92da2fda23893b80ad5887812dc` |
| SHA3-384 | `72c5a66faf61ff5bca3389f53287ed3590cd48fdaa734f16a436705e5979f38102cc4673c2528f6a5418eb02cd0a0565` |
| TLSH | `T150016FCAE250D5504059C55EA69F5290B421C3CA4A8B4BA47FDCA43DAB5CF14B037E58` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHka7ChsTBQCXbl8CNWs1CdXs01CdaauD:kXCKysE2hi0ziQvZoha7FOmakWwu1Ea7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_af03598b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af03598bef65613ab2c8a64fed066b9fd384d92da2fda23893b80ad5887812dc"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-29 01:09:33"
  condition:
    hash.sha256(0, filesize) == "af03598bef65613ab2c8a64fed066b9fd384d92da2fda23893b80ad5887812dc"
}
```

### Sample 18: `f2b628567c919427`

| Field | Value |
|---|---|
| SHA-256 | `f2b628567c9194272993484fc7b706d0ebf036e30fddab42cf0ef95310782b17` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-29 01:05:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c39c5267c9ac48b45112f668febd042f` |
| SHA-1 | `93057b9981cfed30ab46f974eff0782db5918074` |
| SHA-256 | `f2b628567c9194272993484fc7b706d0ebf036e30fddab42cf0ef95310782b17` |
| SHA3-384 | `a58e92c1d30fb5584b66116c6735c61160a6e54cb9df42e0ef7fd44289bd3e1d779dcb94d3e81ac7980d81ef777728be` |
| TLSH | `T1AF24D81F6E229F7EF6A9873547B78E24AB5933D613D1D541E1ACC1001E6038E642FFA8` |
| TELFHASH | `t1e441b0180a7817a0a3756c99459dff76d2a330db7e172d338e11e86eab69f839d10c0c` |
| SSDEEP | `3072:YzUX7ipxr9v+oDajycYJbKSP/IFtxQO0PxMG2a/Yl8c34joE:YIO7r9v+oDajsGSQtWvyGfYlh3y9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_f2b62856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b628567c9194272993484fc7b706d0ebf036e30fddab42cf0ef95310782b17"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-29 01:05:38"
  condition:
    hash.sha256(0, filesize) == "f2b628567c9194272993484fc7b706d0ebf036e30fddab42cf0ef95310782b17"
}
```

### Sample 19: `30cf8b82a53fff20`

| Field | Value |
|---|---|
| SHA-256 | `30cf8b82a53fff20b564597e56123ddeb16a87441a8b94f621e52c3213aeaa2c` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 01:00:20` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c735bfeb6d34be3b8cd6008476541d0` |
| SHA-1 | `513401f23f65a63d0e7754118b56edb06c9ad676` |
| SHA-256 | `30cf8b82a53fff20b564597e56123ddeb16a87441a8b94f621e52c3213aeaa2c` |
| SHA3-384 | `951254eaa1651f3da42a1b044ec7690057886acb59da67a2c0f51ce6084814e7cbd0ccbf17e0f23cb90456f09905a2f1` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T18C220A197E8A0332E3A048F45479824B543E5533E787E3EFF373959A4A963448850EBF` |
| SSDEEP | `96:CYdFo2Yz/J4h/wQBDB2dyaVDL1x+ZQ75ZTMwmmpPFJxGE9mZ2FFhxC7tCEmJe:CmoFeJBDBgx+e75tpPFJxTEZmFhSm` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_019_30cf8b82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30cf8b82a53fff20b564597e56123ddeb16a87441a8b94f621e52c3213aeaa2c"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 01:00:20"
  condition:
    hash.sha256(0, filesize) == "30cf8b82a53fff20b564597e56123ddeb16a87441a8b94f621e52c3213aeaa2c"
}
```

### Sample 20: `3788186a5d8e95fd`

| Field | Value |
|---|---|
| SHA-256 | `3788186a5d8e95fdcd9f6386bf85939b865cdd50c2ea28708e673af164aa61ee` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-29 00:57:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75a490fa24ac602f41a42cb1315da15f` |
| SHA-1 | `740fd6cb284df2a27e3fe4d3c7730326b52c0aee` |
| SHA-256 | `3788186a5d8e95fdcd9f6386bf85939b865cdd50c2ea28708e673af164aa61ee` |
| SHA3-384 | `88f600873a0a878d93bf3a93d4d7767e02c22603d50357f6e89c5caf8c176aafaf37d407facbbfb0e410d18db924c145` |
| TLSH | `T1AAC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11F9CD618B1A` |
| SSDEEP | `768:lx8vCB+25j6es8RG9FYpMSUpi+20qUpi+20YQX:lx8l25Jwd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_3788186a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3788186a5d8e95fdcd9f6386bf85939b865cdd50c2ea28708e673af164aa61ee"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-29 00:57:00"
  condition:
    hash.sha256(0, filesize) == "3788186a5d8e95fdcd9f6386bf85939b865cdd50c2ea28708e673af164aa61ee"
}
```

### Sample 21: `b8ba5580699a6e79`

| Field | Value |
|---|---|
| SHA-256 | `b8ba5580699a6e79742e679b4f8bc293fa903e31410a4a2bad0271731bb3c887` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-29 00:56:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68f0d5f1d26379b7937b55d78d8bbc1e` |
| SHA-1 | `ab8d7dfc80e3e08a6de971f21d6cd2476a4a9148` |
| SHA-256 | `b8ba5580699a6e79742e679b4f8bc293fa903e31410a4a2bad0271731bb3c887` |
| SHA3-384 | `38b91a97ef105ff5b2850dab55ce53708330ed5a0d10419815067c666c0fcc5268b68e07655c06a142e433fa5986c6ae` |
| TLSH | `T143E39DB3E4356E68C1628574B0348FB42B63A99992431FFB65B6C27410C7D9EFA1C3B4` |
| SSDEEP | `1536:3aA0ggGZzqiH8NtJqC6EKp7cWDRz1eCWDeWp7+J07EEa10rb9EJ/2:3VgCeiH8Ntsrrpvz1eteWFn7EBr2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_b8ba5580
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8ba5580699a6e79742e679b4f8bc293fa903e31410a4a2bad0271731bb3c887"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-29 00:56:59"
  condition:
    hash.sha256(0, filesize) == "b8ba5580699a6e79742e679b4f8bc293fa903e31410a4a2bad0271731bb3c887"
}
```

### Sample 22: `46eb8bc5b1f25752`

| Field | Value |
|---|---|
| SHA-256 | `46eb8bc5b1f257520507bb81b2d010ea9d5a56b1843c0168953f3662b53d7a15` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-29 00:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bad6907be1e22a4cd2eb198d921ef57` |
| SHA-1 | `23637b17c84bcf8ab0763673ec6935fccaac9048` |
| SHA-256 | `46eb8bc5b1f257520507bb81b2d010ea9d5a56b1843c0168953f3662b53d7a15` |
| SHA3-384 | `47358ad41b224f14e8b41d793e2f88c7e490ef9266a07a3b0fcc75c9d2cb94a50b1ac8639f7232d052f98e4eef2c21f2` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1E7E6338896E012EED9F3413CEED26654F12978711B32C9DF5F4893A53EA71908C3D62B` |
| SSDEEP | `393216:ZhIt98Pj+d5YOXuo7VnANqXMCHWUjXJcuI3/PGTAI:ZIU+d5Vj7ZwqXMb8X+H/O7` |
| ICON-DHASH | `50f8d0f0e0e8f0b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_46eb8bc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46eb8bc5b1f257520507bb81b2d010ea9d5a56b1843c0168953f3662b53d7a15"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 00:52:32"
  condition:
    hash.sha256(0, filesize) == "46eb8bc5b1f257520507bb81b2d010ea9d5a56b1843c0168953f3662b53d7a15"
}
```

### Sample 23: `403cf85efeba8cc0`

| Field | Value |
|---|---|
| SHA-256 | `403cf85efeba8cc0e48dcb4fb7b22fa830426d4ac26d613d1e637ef64009581c` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-29 00:52:29` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44bbbb4ae98a461f7326543e0c0a4947` |
| SHA-1 | `76f80956191acb8aa809e89b6dc49274707c1758` |
| SHA-256 | `403cf85efeba8cc0e48dcb4fb7b22fa830426d4ac26d613d1e637ef64009581c` |
| SHA3-384 | `1949a1837b2478a2bc25e1453c2bafc0b57bb54899537c5fc22829d1dbb06f4805ec37433b838b382a80cd63ff8f3d1c` |
| TLSH | `T1B3235C651A857C14AA98C4361D7F2F0CB9AD43E6320492EE7FCF3CF28C5A6AD910572D` |
| SSDEEP | `768:u6Utd8/R9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ycr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_403cf85e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "403cf85efeba8cc0e48dcb4fb7b22fa830426d4ac26d613d1e637ef64009581c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-29 00:52:29"
  condition:
    hash.sha256(0, filesize) == "403cf85efeba8cc0e48dcb4fb7b22fa830426d4ac26d613d1e637ef64009581c"
}
```

### Sample 24: `e2f44b25a44109ce`

| Field | Value |
|---|---|
| SHA-256 | `e2f44b25a44109cea9ed49bb14fd4038da41912a75ccd2496194359af0eb1b41` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-29 00:50:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `669c31a8a3cd23c84de699bff9f93270` |
| SHA-1 | `0a4d9f9d36987fee3f545abbb3a5f39aec8d0731` |
| SHA-256 | `e2f44b25a44109cea9ed49bb14fd4038da41912a75ccd2496194359af0eb1b41` |
| SHA3-384 | `66aff01ba76cd8e0c40a040e256ccbb4e514fc2a3e385ab4601c11782301f5857db165292ee9a12f5ee1273a72f24e7b` |
| TLSH | `T1CCD36CC5F343E6F6D80604725027E736CA3692A6252DEE83D7A8DF76ECB1501C916E8C` |
| TELFHASH | `t1d95117f96a7e1ce8abc09801e24e5f316d5d977b246036f605f3d87532abd82417ac38` |
| SSDEEP | `1536:gvY+4cf9+gfLxGchrEMXV/BT4zkqeCrRPx2yO1K6E2SSx8KomX8jfHmWxLkb9EJO:ynf9+YLxT3NCMEF4yoK6T7x8VmX8PZ1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_e2f44b25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2f44b25a44109cea9ed49bb14fd4038da41912a75ccd2496194359af0eb1b41"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-29 00:50:55"
  condition:
    hash.sha256(0, filesize) == "e2f44b25a44109cea9ed49bb14fd4038da41912a75ccd2496194359af0eb1b41"
}
```

### Sample 25: `92d27e98374b3657`

| Field | Value |
|---|---|
| SHA-256 | `92d27e98374b36575b4c12c8ab050c55befef8a27401a97dd2493d40469981fd` |
| Family label | `unknown` |
| File name | `MV_CHRYSANTHI_S_VSL_DESCRIPTIONpdf.js` |
| File type | `js` |
| First seen | `2026-07-29 00:46:33` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61442f20e71092e3a7a91893ce9c9b34` |
| SHA-1 | `3fbc56b3deb26fcfef0276b2cbdebcc5f472ece7` |
| SHA-256 | `92d27e98374b36575b4c12c8ab050c55befef8a27401a97dd2493d40469981fd` |
| SHA3-384 | `84e55153ff74f335945287b114f515d9dc67f8cb2c9a0138bd10a7e433c8f1e008fde064c71f2be478868bcc6c8d570d` |
| TLSH | `T1E4F51AB132DE6B06AE0D7719984C4F18431AC0299F63F48570DF97C5474F98A6AA8CBF` |
| SSDEEP | `12288:hYdB/HsX1uHnSvylUWM8fX6jiKz+c6nkv/WtuelYK7AWQNlvkANSBYbmeMXotu3c:hQfyZR2elT9RMqUAl5S146o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_92d27e98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92d27e98374b36575b4c12c8ab050c55befef8a27401a97dd2493d40469981fd"
    family = "unknown"
    file_name = "MV_CHRYSANTHI_S_VSL_DESCRIPTIONpdf.js"
    file_type = "js"
    first_seen = "2026-07-29 00:46:33"
  condition:
    hash.sha256(0, filesize) == "92d27e98374b36575b4c12c8ab050c55befef8a27401a97dd2493d40469981fd"
}
```

### Sample 26: `777e17fa8a709873`

| Field | Value |
|---|---|
| SHA-256 | `777e17fa8a709873f33cdbf7793948ae2f1c84dd7524c2f1fd911d4c14c372cd` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-07-29 00:44:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fe7e99183aba55c587dedaa70861c41` |
| SHA-1 | `705eacd9669c15d16c4f09ba2c24eeec5bc384bb` |
| SHA-256 | `777e17fa8a709873f33cdbf7793948ae2f1c84dd7524c2f1fd911d4c14c372cd` |
| SHA3-384 | `0d3a26c749227f95def7076afdafb382d12edfacb9e4283cc6a5071e1b5eacad861b07e18961cd4c63c4f16313e8c49e` |
| TLSH | `T18F634B2731356913C0E0E6FA11B7C762B2961BD91388D3CEBE630D5FAE263405966DF4` |
| TELFHASH | `t17ae02b00bc69de1959d75974dcdd07a45501615350665b118f14dbe4c43f114960c99e` |
| SSDEEP | `1536:5TIb9b1T9nVnE4+b2nFw7HM/3zoBZ+/jcqZfiV09bdUJ1:5TS9b+4HFb5Aqon` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_777e17fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "777e17fa8a709873f33cdbf7793948ae2f1c84dd7524c2f1fd911d4c14c372cd"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-29 00:44:54"
  condition:
    hash.sha256(0, filesize) == "777e17fa8a709873f33cdbf7793948ae2f1c84dd7524c2f1fd911d4c14c372cd"
}
```

### Sample 27: `9b5a9954e031bf01`

| Field | Value |
|---|---|
| SHA-256 | `9b5a9954e031bf017324e3cbe578cb7f0148d428ee0172003846bc9486543aa4` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-29 00:40:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3283f939a1ee7b1b9d418555990d299c` |
| SHA-1 | `d389c6a125b4f0efae980debe688402fb1ec4933` |
| SHA-256 | `9b5a9954e031bf017324e3cbe578cb7f0148d428ee0172003846bc9486543aa4` |
| SHA3-384 | `e09710dec24b4ed8f14526e5ff4831093fe6b20816c4a7cef6f6b3a8ee8d6e9152bb83572c1b30f0f49c8c70b1947d96` |
| TLSH | `T15124E90A6F510EBBD8AFCD3706E9070129CC955B22A43B357674C918F54EA4F5AE3CB8` |
| SSDEEP | `3072:sgXHOxgYRsJtAaTcPVCFkqvTfEqwnLrBfN4+DH:sgXHOx1sTAaTbZT5wHBlz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_9b5a9954
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b5a9954e031bf017324e3cbe578cb7f0148d428ee0172003846bc9486543aa4"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-29 00:40:27"
  condition:
    hash.sha256(0, filesize) == "9b5a9954e031bf017324e3cbe578cb7f0148d428ee0172003846bc9486543aa4"
}
```

### Sample 28: `543dcff189a5f2fa`

| Field | Value |
|---|---|
| SHA-256 | `543dcff189a5f2fa7beeb6863e78edd31d74226196687185ad3e655c3ea034de` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 00:36:07` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fcec564fdae661e05b257376d996671` |
| SHA-1 | `ad6ed7c361ebc42a297df23b4a3452ee5b24f2cc` |
| SHA-256 | `543dcff189a5f2fa7beeb6863e78edd31d74226196687185ad3e655c3ea034de` |
| SHA3-384 | `f72a7a7b04181d1c9a8aefc38f9deb25327b3c2541f5ddba6ca9207da41e4e112752f66cbbc850b0e9824e2138a82bc7` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T1DB623C0AB4808035EBE144B4827F526645BDACB623C4F9CBF7E064CA5EB46E1F43616F` |
| SSDEEP | `192:AWbsGnjXgjk8LMRI+4NJTMVJFeIFFBKUSfEzQ0XFd1gJxTmv8U9cth89ik:AqSMqcUlEHryav8U9cyX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_543dcff1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "543dcff189a5f2fa7beeb6863e78edd31d74226196687185ad3e655c3ea034de"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 00:36:07"
  condition:
    hash.sha256(0, filesize) == "543dcff189a5f2fa7beeb6863e78edd31d74226196687185ad3e655c3ea034de"
}
```

### Sample 29: `41c0e8e47dfa4844`

| Field | Value |
|---|---|
| SHA-256 | `41c0e8e47dfa4844066f4b76f2fe979694320bce1c4f7a9bb5e20a07b618b98c` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-29 00:29:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71592b8af339e0c56af960954953773d` |
| SHA-1 | `1f68cd9d23ee65fc2138f703d279b575f5436825` |
| SHA-256 | `41c0e8e47dfa4844066f4b76f2fe979694320bce1c4f7a9bb5e20a07b618b98c` |
| SHA3-384 | `8e6ea25d25556b75de01cb42e7c26b5b39a6847603c41f0edc853a882f14ac85cb253b72f7aa8033c36a6ce1d40ca494` |
| TLSH | `T14D144B46E6818E17C0D717B9B6AF8201333257A5D3DB73069A14AFF83F8765A0F27906` |
| TELFHASH | `t1d74134e1423b86045a67ff9c9cddab65316e8a1a9346ff73ef1184ac900705a9520c9f` |
| SSDEEP | `6144:ch/9I0YkaqbYaWl40V5SnLEZLGZn+zcIM/9RxvmvwciztsR:mlI0YfqbYaWl40V51y5x/ZvmvLiztsR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_41c0e8e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41c0e8e47dfa4844066f4b76f2fe979694320bce1c4f7a9bb5e20a07b618b98c"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-29 00:29:31"
  condition:
    hash.sha256(0, filesize) == "41c0e8e47dfa4844066f4b76f2fe979694320bce1c4f7a9bb5e20a07b618b98c"
}
```

### Sample 30: `c4e659790c6a66c5`

| Field | Value |
|---|---|
| SHA-256 | `c4e659790c6a66c5ffc8a091edc4ea823258a6c684d8e50d147371e88d8b5775` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-29 00:25:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `924e0875019486184fc6de7c9b94a186` |
| SHA-1 | `9d1998de836e414d53e8bd59800ed900b2839e9a` |
| SHA-256 | `c4e659790c6a66c5ffc8a091edc4ea823258a6c684d8e50d147371e88d8b5775` |
| SHA3-384 | `a774a3c3d7ac628b7ed96edffe848fad6094a39b8fcb73ca63c56920ba2f81f5e3c2f3e1c3fb5ecacd32ad929882eb78` |
| TLSH | `T1C3631985FC825B1AC2C117BAA5BE668D3320A3F4D3CE3127DD224B213BC951F5936E85` |
| TELFHASH | `t17ae02b00bc69de1959d75974dcdd07a45501615350665b118f14dbe4c43f114960c99e` |
| SSDEEP | `1536:z5V+/ftpZtPZRmF5YiDQR+jKplQJa10rb9EJ:zX+n3LWfkmC24` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_c4e65979
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4e659790c6a66c5ffc8a091edc4ea823258a6c684d8e50d147371e88d8b5775"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-29 00:25:41"
  condition:
    hash.sha256(0, filesize) == "c4e659790c6a66c5ffc8a091edc4ea823258a6c684d8e50d147371e88d8b5775"
}
```

### Sample 31: `ea1da54f1c5b56ae`

| Field | Value |
|---|---|
| SHA-256 | `ea1da54f1c5b56aeed6fb6d138027f295c54713205b24d10371e8f0f42326ff1` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-29 00:23:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71c1763d06711bf697faee183da0b531` |
| SHA-1 | `b6f389d7dd72db88f1619c13b5c48e03a0123c42` |
| SHA-256 | `ea1da54f1c5b56aeed6fb6d138027f295c54713205b24d10371e8f0f42326ff1` |
| SHA3-384 | `57dcab8aad3979e235c0a99b7bfedf88101d225c561d07941bab5f3ed055f29a716314c2e1f0e4fe64e50122339b77f1` |
| TLSH | `T15B836CC8F753E0F0DD1B0570054FB72A8A75AE529124DE6EDB987E326D32B13621B62C` |
| TELFHASH | `t1984139bb0eba08e8b3c55806974a5b514e2dd63b3110779782b1aa5433d3fe1c376c38` |
| SSDEEP | `1536:UovA8vFuKT7ajKm6p9KgJK/a8xuAWE6wkKgb85HUP31QGtNQcezr:UiAFk7ajKmY9Kg9+uf31uA23` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_ea1da54f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea1da54f1c5b56aeed6fb6d138027f295c54713205b24d10371e8f0f42326ff1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-29 00:23:31"
  condition:
    hash.sha256(0, filesize) == "ea1da54f1c5b56aeed6fb6d138027f295c54713205b24d10371e8f0f42326ff1"
}
```

### Sample 32: `6c37739ac0fa9f67`

| Field | Value |
|---|---|
| SHA-256 | `6c37739ac0fa9f67869f6c1ecdc939d5b05ad783b85d12f661c432f528ba7389` |
| Family label | `unknown` |
| File name | `setting.xml` |
| File type | `unknown` |
| First seen | `2026-07-29 00:23:30` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c816233843df005e0e0d954f40b35397` |
| SHA-256 | `6c37739ac0fa9f67869f6c1ecdc939d5b05ad783b85d12f661c432f528ba7389` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_6c37739a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c37739ac0fa9f67869f6c1ecdc939d5b05ad783b85d12f661c432f528ba7389"
    family = "unknown"
    file_name = "setting.xml"
    file_type = "unknown"
    first_seen = "2026-07-29 00:23:30"
  condition:
    hash.sha256(0, filesize) == "6c37739ac0fa9f67869f6c1ecdc939d5b05ad783b85d12f661c432f528ba7389"
}
```

### Sample 33: `ab074ae168e50392`

| Field | Value |
|---|---|
| SHA-256 | `ab074ae168e50392c6981f6bf426900642c684b13f72b4de681e0b9b4cd1a55d` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 00:11:54` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c57f426fd8099b5a14b1415a2394b92f` |
| SHA-1 | `0e1bdba547ebff6804278358fc98fa8e2f867b8d` |
| SHA-256 | `ab074ae168e50392c6981f6bf426900642c684b13f72b4de681e0b9b4cd1a55d` |
| SHA3-384 | `243709d2d79aff6cb1c56da019fceea9eedd3b2fc5948ab3ec5195b582816ec1eb9f43b2ad60c616158f821c9965b35b` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T110624C0BA4808035EBF14474927F526648FEACB623C5F9DBF7E0648A4AB46E1F43116F` |
| SSDEEP | `192:AWtsGnjXgjk8LcRI+IdJDMBIfeF5oIV1BKUSfEzQ0X1d1gJxTmv8U9cth19ik:AUScqpferoFEH7yav8U9cfX` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_033_ab074ae1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab074ae168e50392c6981f6bf426900642c684b13f72b4de681e0b9b4cd1a55d"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 00:11:54"
  condition:
    hash.sha256(0, filesize) == "ab074ae168e50392c6981f6bf426900642c684b13f72b4de681e0b9b4cd1a55d"
}
```

### Sample 34: `52d4cc210d5031b0`

| Field | Value |
|---|---|
| SHA-256 | `52d4cc210d5031b02c2e06f3978ec2b042e69946995381d4dfc999f57f0f0887` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 00:03:25` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2542513d55514d50c332445af112dab5` |
| SHA-1 | `3dae016fe5a9fd62184d3f6d0f0ec4e986532c3c` |
| SHA-256 | `52d4cc210d5031b02c2e06f3978ec2b042e69946995381d4dfc999f57f0f0887` |
| SHA3-384 | `0343336d07aec2c9df785fddb4737249e93fb1756b55db67eefccc1ee5db433a00b18ae0458c219292ce5dbbbd41c902` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T153624C0BA4808035EBF14474927F526648FEACB623C5F9DBF7E0648A4AB46E1F43116F` |
| SSDEEP | `192:AWssGnjXgjk8LcRI+IdJDMBIfeF5oIV1BKUSfEzQ0X1d1gJxTmv8U9cth69ik:ARScqpferoFEH7yav8U9ccX` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_034_52d4cc21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52d4cc210d5031b02c2e06f3978ec2b042e69946995381d4dfc999f57f0f0887"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 00:03:25"
  condition:
    hash.sha256(0, filesize) == "52d4cc210d5031b02c2e06f3978ec2b042e69946995381d4dfc999f57f0f0887"
}
```

### Sample 35: `30793394a8638778`

| Field | Value |
|---|---|
| SHA-256 | `30793394a8638778432c95d8c121b00f7a4c64226588d1a5d2538bd62f3b187b` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 00:01:42` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4a15cdf5b5324ab79e610ced133da8b` |
| SHA-1 | `6558d352c7dcce247b385127d29e7e280db5a5d6` |
| SHA-256 | `30793394a8638778432c95d8c121b00f7a4c64226588d1a5d2538bd62f3b187b` |
| SHA3-384 | `b34963417ac028c4a44254e4fff3682162c388311fc3f734e1f8ef314519d7086a003ff99a7f5887267b70e765901003` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T18A624B0BA4808035EBF14474927F526644FEACB623C1F9DBF7E0688A4AB46E1F43116F` |
| SSDEEP | `192:AW5sGnjXgjk8LcRI+IdJDMBIfeF5oIV1BKUSfEzQ0X1d1gJxTmv8U9cthY9ik:AgScqpferoFEH7yav8U9cOX` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_035_30793394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30793394a8638778432c95d8c121b00f7a4c64226588d1a5d2538bd62f3b187b"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 00:01:42"
  condition:
    hash.sha256(0, filesize) == "30793394a8638778432c95d8c121b00f7a4c64226588d1a5d2538bd62f3b187b"
}
```

### Sample 36: `d273b3948f88184e`

| Field | Value |
|---|---|
| SHA-256 | `d273b3948f88184ed005c3947fa2a4021e8e6e0c8a91bbe05d43693ede8a4023` |
| Family label | `unknown` |
| File name | `d273b3948f88184ed005c3947fa2a4021e8e6e0c8a91bbe05d43693ede8a4023` |
| File type | `unknown` |
| First seen | `2026-07-29 00:00:12` |
| Reporter | `anonymous` |
| Tags | `cowrie, hermes-noc, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c9f13ca5fa8bfbba357389bf208552f` |
| SHA-256 | `d273b3948f88184ed005c3947fa2a4021e8e6e0c8a91bbe05d43693ede8a4023` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_d273b394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d273b3948f88184ed005c3947fa2a4021e8e6e0c8a91bbe05d43693ede8a4023"
    family = "unknown"
    file_name = "d273b3948f88184ed005c3947fa2a4021e8e6e0c8a91bbe05d43693ede8a4023"
    file_type = "unknown"
    first_seen = "2026-07-29 00:00:12"
  condition:
    hash.sha256(0, filesize) == "d273b3948f88184ed005c3947fa2a4021e8e6e0c8a91bbe05d43693ede8a4023"
}
```

### Sample 37: `5180b1ff84229f30`

| Field | Value |
|---|---|
| SHA-256 | `5180b1ff84229f3034fec1de2534600cb07999a71bff2bf6319199a38320a187` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-28 23:52:34` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fc1254ae188c5a5f04ee8eaec1b19a6` |
| SHA-1 | `f746e8decca83830a611619532c1f9760cc1b11e` |
| SHA-256 | `5180b1ff84229f3034fec1de2534600cb07999a71bff2bf6319199a38320a187` |
| SHA3-384 | `aac3dedcfe4b8463ea241a096ba3695ad8da2623159269ea053bb622b2670dcdc4384fc28fd71260c286c3608dff1523` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T13EE6339806E112EFED63927CC9E265B0D19678760731C6DB6BA823F16E472D08D3D713` |
| SSDEEP | `393216:NgLSWPmHsNW1afFW3Dnj7XMCHWUjXPcuI3/PGTAI:NgLS6mHs3FgnvXMb8XEH/O7` |
| ICON-DHASH | `7471d4d8c8e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_5180b1ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5180b1ff84229f3034fec1de2534600cb07999a71bff2bf6319199a38320a187"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 23:52:34"
  condition:
    hash.sha256(0, filesize) == "5180b1ff84229f3034fec1de2534600cb07999a71bff2bf6319199a38320a187"
}
```

### Sample 38: `84b4c113491f67bf`

| Field | Value |
|---|---|
| SHA-256 | `84b4c113491f67bf4a0c16629f003325575dd34de7120b4f94541544a1498da0` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 23:35:08` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f33d1d9e1ab34026cea3f95862f0798a` |
| SHA-1 | `36837d1116f2f06cb43d1d0958cba70fcdc3f4fe` |
| SHA-256 | `84b4c113491f67bf4a0c16629f003325575dd34de7120b4f94541544a1498da0` |
| SHA3-384 | `68db87fddc592e16aa0a6ea1a02f33280fe5f1ef270c9b138813c3424d4aade4a695862a238867aaf9e649b77def5dc7` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T17D623A0AA4818035EAE04075927F526649FEADB623C4F9D7F7E0A8C94DB4BD1F43116F` |
| SSDEEP | `192:AWRsGnjXgjk8LcRI+Q1RDMRYfV/F5oIVUBKUSftzQFBrfgJxTmv8U9cthDO9ik:AkScCRfV/ro6toB0av8U9ccX` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_038_84b4c113
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84b4c113491f67bf4a0c16629f003325575dd34de7120b4f94541544a1498da0"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 23:35:08"
  condition:
    hash.sha256(0, filesize) == "84b4c113491f67bf4a0c16629f003325575dd34de7120b4f94541544a1498da0"
}
```

### Sample 39: `21bf44a654a0059f`

| Field | Value |
|---|---|
| SHA-256 | `21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471` |
| Family label | `unknown` |
| File name | `yea8hw1uN1NGD0za.exe` |
| File type | `exe` |
| First seen | `2026-07-28 23:03:47` |
| Reporter | `Kejult` |
| Tags | `exe, RAT, Remcos, RemcosRAT, ZIGCRYPTOSTEALER` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca789369076efaafc596f836d928abdd` |
| SHA-1 | `e6d3f4d33263f731a78b914227ee9d12422830e8` |
| SHA-256 | `21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471` |
| SHA3-384 | `36822fc7235e1464440879a3b41ff17ca4af4eded25cdda90071b275006c682d38f9ce74fd6d4309621f3466e8188585` |
| IMPHASH | `d7a140ad86093e229082e6f8b7493b94` |
| TLSH | `T1BC06121DE38D52DCD223D134CBA69232E6B5B85A0761BDDF169AC2192FB39D01F3A311` |
| SSDEEP | `98304:wuQgRnUx/PdELDYwWCLK2ZCouvZ4NTLCmAI:wEiVmYtXUoAL4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_21bf44a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471"
    family = "unknown"
    file_name = "yea8hw1uN1NGD0za.exe"
    file_type = "exe"
    first_seen = "2026-07-28 23:03:47"
  condition:
    hash.sha256(0, filesize) == "21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471"
}
```

### Sample 40: `045ada423b20079a`

| Field | Value |
|---|---|
| SHA-256 | `045ada423b20079a8d1175a47077c1933b06a7e7963eab4dff8d4bb11702c2a4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 23:00:35` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1c9c724efe90addefa31262586c8662` |
| SHA-1 | `d39a7f528748d1b7b1517bc4dfc7d797a9188d38` |
| SHA-256 | `045ada423b20079a8d1175a47077c1933b06a7e7963eab4dff8d4bb11702c2a4` |
| SHA3-384 | `b21be53910c270c5d75de49a8f4428ed2b2875c32015ba5598eb67d082593940628dffded8c62f5990dbe2faedc1d297` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T191823B0FB9424316E1E110B49665967BD9B9AC7637C414EBFBD44AEE0A686C1FC3210F` |
| SSDEEP | `384:AHZbmcmhzcEUaUu94gXFP+av8U9c+h4P:P9UaF9Qa0U10` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_045ada42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "045ada423b20079a8d1175a47077c1933b06a7e7963eab4dff8d4bb11702c2a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 23:00:35"
  condition:
    hash.sha256(0, filesize) == "045ada423b20079a8d1175a47077c1933b06a7e7963eab4dff8d4bb11702c2a4"
}
```

### Sample 41: `1441e39c7dd35914`

| Field | Value |
|---|---|
| SHA-256 | `1441e39c7dd359145a88309bcf004282ce178df47635b5be6b48dd0e2ccb58a0` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-28 22:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95ab435432ad8bb2853d3fa8782acec2` |
| SHA-1 | `9dfb638fe8b4300ae278ee5f32ecbbbdb4f93895` |
| SHA-256 | `1441e39c7dd359145a88309bcf004282ce178df47635b5be6b48dd0e2ccb58a0` |
| SHA3-384 | `0a69addeb14138d045ff42357159430f6d69f600498a775f31d0ee4cd7b3aa2d71afbba14ad0a633b5001266496ff739` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D1E63348F2D025FEE773423DEEE64599E0AEB8510772C9DB576887906E672E04C38363` |
| SSDEEP | `393216:lvj9alSt4ErJiN7oYE777LdnXMCHWUjXBcuI3/PGTAI:lvYlSt/K7oYE777LtXMb8XWH/O7` |
| ICON-DHASH | `b2f0e8cccce8f1b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_1441e39c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1441e39c7dd359145a88309bcf004282ce178df47635b5be6b48dd0e2ccb58a0"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 22:52:31"
  condition:
    hash.sha256(0, filesize) == "1441e39c7dd359145a88309bcf004282ce178df47635b5be6b48dd0e2ccb58a0"
}
```

### Sample 42: `0663b7b3bc56e8c2`

| Field | Value |
|---|---|
| SHA-256 | `0663b7b3bc56e8c2554fdb91b92d3ed648fb3cc45dde224eb869f8222ce795b0` |
| Family label | `unknown` |
| File name | `0663b7b3bc56e8c2554fdb91b92d3ed648fb3cc45dde224eb869f8222ce795b0` |
| File type | `unknown` |
| First seen | `2026-07-28 22:30:32` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `916ebb290ff86445cca2622aeb723949` |
| SHA-256 | `0663b7b3bc56e8c2554fdb91b92d3ed648fb3cc45dde224eb869f8222ce795b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_0663b7b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0663b7b3bc56e8c2554fdb91b92d3ed648fb3cc45dde224eb869f8222ce795b0"
    family = "unknown"
    file_name = "0663b7b3bc56e8c2554fdb91b92d3ed648fb3cc45dde224eb869f8222ce795b0"
    file_type = "unknown"
    first_seen = "2026-07-28 22:30:32"
  condition:
    hash.sha256(0, filesize) == "0663b7b3bc56e8c2554fdb91b92d3ed648fb3cc45dde224eb869f8222ce795b0"
}
```

### Sample 43: `27c74bd229840f70`

| Field | Value |
|---|---|
| SHA-256 | `27c74bd229840f70bb35cf28c00756d6fda16b0371789df00dd718c901041131` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 22:07:13` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ef44458a9e859c23bad9df6bca69073` |
| SHA-1 | `4182de78b83ea32b64e219842f60fb9b76275d94` |
| SHA-256 | `27c74bd229840f70bb35cf28c00756d6fda16b0371789df00dd718c901041131` |
| SHA3-384 | `64f398180eaa8c6f10ca81f886b02e9df6de84ed8f419ba36ed735d26ee7b5605f886e378eb1516eb3f62801133a3bbf` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T1B9624C0AB4808035EBE144B4827F526644BDACB623C4F9CBF7E0648A5EB46E1F43216F` |
| SSDEEP | `192:AW1sGnjXgjk8LMRI+4NJTMVJFeIFFBKUSfEzQ0XFd1gJxTmv8U9cth89ik:AgSMqcUlEHryav8U9cyX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_27c74bd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27c74bd229840f70bb35cf28c00756d6fda16b0371789df00dd718c901041131"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 22:07:13"
  condition:
    hash.sha256(0, filesize) == "27c74bd229840f70bb35cf28c00756d6fda16b0371789df00dd718c901041131"
}
```

### Sample 44: `44c62e465a3ad8c8`

| Field | Value |
|---|---|
| SHA-256 | `44c62e465a3ad8c8fe0f851466427f132722d21c416220c37f1c87a95ecd45ae` |
| Family label | `unknown` |
| File name | `44c62e465a3ad8c8fe0f851466427f132722d21c416220c37f1c87a95ecd45ae` |
| File type | `elf` |
| First seen | `2026-07-28 22:03:18` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1e7b8463782585cae61d8c6dc011323` |
| SHA-1 | `1a4f8b913a8c334ed755219a1feb558ddb292568` |
| SHA-256 | `44c62e465a3ad8c8fe0f851466427f132722d21c416220c37f1c87a95ecd45ae` |
| SHA3-384 | `feb1d8d04fa2ffd6fb356369a8f9a3cf323b0f368dd908efe5269c5affd65943c9f290eb679abad297ff93589ace31da` |
| TLSH | `T1BB17BE77814338E9E5A98CB4D51025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQQ:cqYUQuVDt0TZEL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_44c62e46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44c62e465a3ad8c8fe0f851466427f132722d21c416220c37f1c87a95ecd45ae"
    family = "unknown"
    file_name = "44c62e465a3ad8c8fe0f851466427f132722d21c416220c37f1c87a95ecd45ae"
    file_type = "elf"
    first_seen = "2026-07-28 22:03:18"
  condition:
    hash.sha256(0, filesize) == "44c62e465a3ad8c8fe0f851466427f132722d21c416220c37f1c87a95ecd45ae"
}
```

### Sample 45: `362d59aeb45ccaa8`

| Field | Value |
|---|---|
| SHA-256 | `362d59aeb45ccaa8f46889a6760d9fdd4bf1a1849548483a4ed164d232458868` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-28 21:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d7dcb19327ba5cd1893d4469f3c8d56` |
| SHA-1 | `0d5ca6501cd3d83943bd80bf6c70112e75d456cd` |
| SHA-256 | `362d59aeb45ccaa8f46889a6760d9fdd4bf1a1849548483a4ed164d232458868` |
| SHA3-384 | `ccb1fa9f53d6ecb5acd101f7081394a40b1f5ced6729ebb926cd14bf167b789c1b27579e538c35526793c73cd2fe57ec` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1DBE63304E5D151EDDAF3113DBCE19A96D26978B11B32CACF4BB862B22D171D08C7EA43` |
| SSDEEP | `393216:2g1+ML7gSQJp6bxPTyHcGXMCHWUjXKcuI3/PGTAI:2goM8UPTy8GXMb8XnH/O7` |
| ICON-DHASH | `e86864e1d8e8ec4a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_362d59ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "362d59aeb45ccaa8f46889a6760d9fdd4bf1a1849548483a4ed164d232458868"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 21:52:30"
  condition:
    hash.sha256(0, filesize) == "362d59aeb45ccaa8f46889a6760d9fdd4bf1a1849548483a4ed164d232458868"
}
```

### Sample 46: `460210f3fd404749`

| Field | Value |
|---|---|
| SHA-256 | `460210f3fd4047499e12f4e4fcbbf556f2a1957f1ef276238aaa152554a02b37` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 21:25:21` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f620f266c74d2bd871f50ea4b7fa2ee` |
| SHA-1 | `e8d952715fc718968bc810f43a683f3d56c7c3fd` |
| SHA-256 | `460210f3fd4047499e12f4e4fcbbf556f2a1957f1ef276238aaa152554a02b37` |
| SHA3-384 | `b36aecdba23be659ee461a974abee86cf17487693e02792e68ed7d5a043df81cb8f7a674db90d484dc8da419f2d366a0` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T1BA32900E2E470321EE5008B4F576464A542D1EE3B342FBEBE672E1DB4AD5E4584C1AAF` |
| SSDEEP | `192:FoNSkS5B3lxSHO8K5hHPFJxTEZmFhqer:FoslsuPLPFwZA` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_046_460210f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "460210f3fd4047499e12f4e4fcbbf556f2a1957f1ef276238aaa152554a02b37"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 21:25:21"
  condition:
    hash.sha256(0, filesize) == "460210f3fd4047499e12f4e4fcbbf556f2a1957f1ef276238aaa152554a02b37"
}
```

### Sample 47: `4fc548d4267d30ac`

| Field | Value |
|---|---|
| SHA-256 | `4fc548d4267d30acd658a3a43e30b4924dade9371cf6448cb1ae9e374f7dd69a` |
| Family label | `unknown` |
| File name | `communigatepro.tar` |
| File type | `tar` |
| First seen | `2026-07-28 21:12:11` |
| Reporter | `smica83` |
| Tags | `AshenLoader, tar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `561b4d321e756c05752571b54bce8a65` |
| SHA-1 | `d9f554eb2d81ab6293235c42e19d4113f91b7725` |
| SHA-256 | `4fc548d4267d30acd658a3a43e30b4924dade9371cf6448cb1ae9e374f7dd69a` |
| SHA3-384 | `1f29bb381dad26e714d6e22f6290220211e9c3119d09818861e5be59d22f7366a44f5b891853e15eca61cfada47a81a3` |
| TLSH | `T1E2542B71B0C4589DE8C9C97C44E9760A0B3D7D1F8AE928AB371CEE25A7043C1BF15A67` |
| SSDEEP | `6144:oNJX3NAbLf8KTloA8rEQ4FLyj2Un161ajwC+57v5:oN28KlFLM16` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `tar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_4fc548d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fc548d4267d30acd658a3a43e30b4924dade9371cf6448cb1ae9e374f7dd69a"
    family = "unknown"
    file_name = "communigatepro.tar"
    file_type = "tar"
    first_seen = "2026-07-28 21:12:11"
  condition:
    hash.sha256(0, filesize) == "4fc548d4267d30acd658a3a43e30b4924dade9371cf6448cb1ae9e374f7dd69a"
}
```

### Sample 48: `a8d04c3d4a97c48d`

| Field | Value |
|---|---|
| SHA-256 | `a8d04c3d4a97c48d33d9e14009bb3765f22242d51d9a6c9cabdaaa0bb7b22270` |
| Family label | `unknown` |
| File name | `CGP_Заполненный_опросный_лист_по_внедрению_CommuniGate_Pro_Деловые_Линии_2026.zip` |
| File type | `zip` |
| First seen | `2026-07-28 21:09:35` |
| Reporter | `smica83` |
| Tags | `AshenLoader, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb0c82265258d1996b059f941b9d529a` |
| SHA-1 | `9cc4a2bc84540b8218167b250c2422ec07b22624` |
| SHA-256 | `a8d04c3d4a97c48d33d9e14009bb3765f22242d51d9a6c9cabdaaa0bb7b22270` |
| SHA3-384 | `45e50b7feee9f92d8028af5525aa52c56ae698d7faccfa2452bf09a58e9deeea1db6374841a2e119d8fee1d5fdcbfc6e` |
| TLSH | `T18FD2E16D6C035C0C89517436F69C6D8694A1FCD829791358FEE8B0835EE70BDB18277E` |
| SSDEEP | `768:/CTUty+CFmYiyzFy0ZR3XQ6UyO9iqGMXHgNDWYPCHJ0jL:wUs7tiMy0LQ6U/kjMXUgJoL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_a8d04c3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8d04c3d4a97c48d33d9e14009bb3765f22242d51d9a6c9cabdaaa0bb7b22270"
    family = "unknown"
    file_name = "CGP_Заполненный_опросный_лист_по_внедрению_CommuniGate_Pro_Деловые_Линии_2026.zip"
    file_type = "zip"
    first_seen = "2026-07-28 21:09:35"
  condition:
    hash.sha256(0, filesize) == "a8d04c3d4a97c48d33d9e14009bb3765f22242d51d9a6c9cabdaaa0bb7b22270"
}
```

### Sample 49: `8ac348ba6ce78dc9`

| Field | Value |
|---|---|
| SHA-256 | `8ac348ba6ce78dc9e0003c0568be8341e736563504c1956ad9b30d556b564070` |
| Family label | `Mirai` |
| File name | `qme1` |
| File type | `elf` |
| First seen | `2026-07-28 21:09:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc653443c459d8c85afa87334ca17851` |
| SHA-1 | `8c601c76666d8ab9c2f71b49e851440b937ed486` |
| SHA-256 | `8ac348ba6ce78dc9e0003c0568be8341e736563504c1956ad9b30d556b564070` |
| SHA3-384 | `814be80f302ef8948ddd0e1f740c58a27e28314cdf37f6f04b6d7b56a6e0a30ddf55a2a640fe8e451f442bea8473435d` |
| TLSH | `T16DA3D81F3F619FACF3A9823497B74B30AA5C63D122E1C684D5ACD5042E3434E594F7AA` |
| TELFHASH | `t11631e519487812f4d3610d9d6eeefb31e0a170df29261e378f22ed5aee1d8428d10c1d` |
| SSDEEP | `1536:XfFZ8BcQlFGINSH7Ei9N15HUd/W8x7Q8puFgACbPaR0F/LX6:9oFGIYH73H1Gd/HbuFg/u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_8ac348ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ac348ba6ce78dc9e0003c0568be8341e736563504c1956ad9b30d556b564070"
    family = "Mirai"
    file_name = "qme1"
    file_type = "elf"
    first_seen = "2026-07-28 21:09:32"
  condition:
    hash.sha256(0, filesize) == "8ac348ba6ce78dc9e0003c0568be8341e736563504c1956ad9b30d556b564070"
}
```

### Sample 50: `00bd53b28e21671f`

| Field | Value |
|---|---|
| SHA-256 | `00bd53b28e21671f2bbbe4aff588c4ce7a41f357bb69c920f3b8227cd27d24cf` |
| Family label | `Mirai` |
| File name | `5FF` |
| File type | `elf` |
| First seen | `2026-07-28 21:09:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39126c3e430e2e8d42034b125201971e` |
| SHA-1 | `2a2441a37c815d46536beec79e5f36bb3ee6d457` |
| SHA-256 | `00bd53b28e21671f2bbbe4aff588c4ce7a41f357bb69c920f3b8227cd27d24cf` |
| SHA3-384 | `8d2bc6e8a6d8f5d0fa26f444a4e36559c84a691c2880ef5f13d8f6db65e5558641ca66370374c2515d46d5d89f9bc2b7` |
| TLSH | `T105632A6BB9919F15C5C0167AFE1D534D33132BBCE3DEB213EE042B642B8B56B0E2A445` |
| TELFHASH | `t135f08b29ce5c0add9be0c14188ff370455e0b1b27b006607eefc8f998111682729b41c` |
| SSDEEP | `1536:xtnrrlWcNjqc7kBWvHpIcqAAqxtoDAWMiT8alJ1xEOilN:vrTjtnIfAXxtU18alJ1nW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_00bd53b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00bd53b28e21671f2bbbe4aff588c4ce7a41f357bb69c920f3b8227cd27d24cf"
    family = "Mirai"
    file_name = "5FF"
    file_type = "elf"
    first_seen = "2026-07-28 21:09:31"
  condition:
    hash.sha256(0, filesize) == "00bd53b28e21671f2bbbe4aff588c4ce7a41f357bb69c920f3b8227cd27d24cf"
}
```

### Sample 51: `f53377f1c4282703`

| Field | Value |
|---|---|
| SHA-256 | `f53377f1c4282703ee09bb8123cc93932f5eb282936551b1379ba91e8df1228a` |
| Family label | `WSHRAT` |
| File name | `ORDER-270728-200878.PDF..vbs` |
| File type | `vbs` |
| First seen | `2026-07-28 21:05:08` |
| Reporter | `abuse_ch` |
| Tags | `RAT, vbs, WSHRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14993e1b390800b0ac04e9d47b800c87` |
| SHA-1 | `64a928fbab046e707c9a10473887ecff6eb70a60` |
| SHA-256 | `f53377f1c4282703ee09bb8123cc93932f5eb282936551b1379ba91e8df1228a` |
| SHA3-384 | `d8b0dd02354a5eb820bbd8e4c9bf65badf3dfe7a31422ba0b628e1636fefb7d62ad6588498d20d20c79a59820158d62c` |
| TLSH | `T1D394E53C83D3D4DAA0CBA76EF653A3C64A14E36365D16A70AE6273B0647044D7C8D2ED` |
| SSDEEP | `12288:j8veDAHhRfukVFB/MlLOMPzr9b4i0Z/6ZQC8Z99B+rdD6yMcGhvPoxMWAyGMWnNW:j8veDAHhRfukVFB/MlLOMPzr9b4i0Z/g` |

#### Technical Assessment

- The sample is tracked as `WSHRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WSHRAT_051_f53377f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f53377f1c4282703ee09bb8123cc93932f5eb282936551b1379ba91e8df1228a"
    family = "WSHRAT"
    file_name = "ORDER-270728-200878.PDF..vbs"
    file_type = "vbs"
    first_seen = "2026-07-28 21:05:08"
  condition:
    hash.sha256(0, filesize) == "f53377f1c4282703ee09bb8123cc93932f5eb282936551b1379ba91e8df1228a"
}
```

### Sample 52: `e95766d2d9dcc598`

| Field | Value |
|---|---|
| SHA-256 | `e95766d2d9dcc598cada3c33133935fda7d54d245d8a46fc05be47986e036fff` |
| Family label | `njrat` |
| File name | `CEE0E495ADC06BBAC4BE33544BD393CA.exe` |
| File type | `exe` |
| First seen | `2026-07-28 21:05:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cee0e495adc06bbac4be33544bd393ca` |
| SHA-1 | `b65b3aba7086a8db3b452f171782af7eab4cbeb5` |
| SHA-256 | `e95766d2d9dcc598cada3c33133935fda7d54d245d8a46fc05be47986e036fff` |
| SHA3-384 | `54514132ca547db7b21d1259e927b24faff347d495348f1ac2b391b101b3c226bc13ad1296cf5a650059bc2854845bbd` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T176447317AB79AC0BC25CC6309CB6E278A5EC2E67DC1CC708ABC19D5F762718E8D0465D` |
| SSDEEP | `3072:xMDnk5ELWDhwsNMDzXExI3pmUHLB2VsgyxTOao8oY0h6:xMwwWvMDrtgSTXLV0` |
| ICON-DHASH | `cc866b687131a6cc` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_052_e95766d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e95766d2d9dcc598cada3c33133935fda7d54d245d8a46fc05be47986e036fff"
    family = "njrat"
    file_name = "CEE0E495ADC06BBAC4BE33544BD393CA.exe"
    file_type = "exe"
    first_seen = "2026-07-28 21:05:05"
  condition:
    hash.sha256(0, filesize) == "e95766d2d9dcc598cada3c33133935fda7d54d245d8a46fc05be47986e036fff"
}
```

### Sample 53: `03dfc82a8c47cd17`

| Field | Value |
|---|---|
| SHA-256 | `03dfc82a8c47cd17e2c443d5121b5a19c3355afd69ed08dee1210250f628282f` |
| Family label | `unknown` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-07-28 20:52:41` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbb84eeb69eaba4ccb0abba05e62bc00` |
| SHA-1 | `c12985bed4baa647ba28a4143426cd78e92b5eeb` |
| SHA-256 | `03dfc82a8c47cd17e2c443d5121b5a19c3355afd69ed08dee1210250f628282f` |
| SHA3-384 | `dbc525db505bc1352229bad5c86751b35aeb29734697fe68b6b9227068c8f89cf5486b4454f55e832cd6e4e66b6d037a` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C4B66B47FC9118FAC0AAA33189A35A527775BC182B3627DB2E60B7782F727D08D35714` |
| SSDEEP | `49152:LooAYY44HBu/mcpb65YyQpYJhWNqqZUk2ZZ9sNj9Mkgoogc8:Li6H3ywxN+a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_03dfc82a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03dfc82a8c47cd17e2c443d5121b5a19c3355afd69ed08dee1210250f628282f"
    family = "unknown"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-07-28 20:52:41"
  condition:
    hash.sha256(0, filesize) == "03dfc82a8c47cd17e2c443d5121b5a19c3355afd69ed08dee1210250f628282f"
}
```

### Sample 54: `33180419d2e3b176`

| Field | Value |
|---|---|
| SHA-256 | `33180419d2e3b1763ef0e67e1a98d9964c16efa97ea164242d098d8d1eaf172a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-28 20:52:29` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `416574c8aa11daaf9c463308b444a21f` |
| SHA-1 | `3ff5ca5530132c7747ecf9a3e7d7873da0cf2e3c` |
| SHA-256 | `33180419d2e3b1763ef0e67e1a98d9964c16efa97ea164242d098d8d1eaf172a` |
| SHA3-384 | `a692c8de616d92efba40ccc080755259cec6a117209d1956e8351a8c1c375504b1a184fcbd6a3d645744a4309f9cc524` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T12CE6331896D012FDE5B3213CAEE281AAE5B874B51772CADF47D893A16E271E04C3D743` |
| SSDEEP | `393216:On+M8ULqWXwZjpGkjd1aS1NSVs7TOfEXMCHWUjXfcuI3/PGTAI:SCWXmGkjjXHHUEXMb8X0H/O7` |
| ICON-DHASH | `71f0d4d8c8e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_33180419
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33180419d2e3b1763ef0e67e1a98d9964c16efa97ea164242d098d8d1eaf172a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 20:52:29"
  condition:
    hash.sha256(0, filesize) == "33180419d2e3b1763ef0e67e1a98d9964c16efa97ea164242d098d8d1eaf172a"
}
```

### Sample 55: `0c77c688c8e96f30`

| Field | Value |
|---|---|
| SHA-256 | `0c77c688c8e96f308e67772abeb7de9bfed680d186301daf720338fc7780ea6a` |
| Family label | `Mirai` |
| File name | `LFt3` |
| File type | `elf` |
| First seen | `2026-07-28 20:44:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41409ad703019aea6d370fcca8c0cb87` |
| SHA-1 | `0f72e46291b324cc7f2d06b5c8549a43e4f05b0d` |
| SHA-256 | `0c77c688c8e96f308e67772abeb7de9bfed680d186301daf720338fc7780ea6a` |
| SHA3-384 | `be095148b91e6ffd5d121bc5137d6c6889d9dd4c309bfc0ae7536ad5459ac04f8fcf8e48b22e97dc43653a50c1f0b67a` |
| TLSH | `T1AA83185AFD819F15D5D526BAFF1E534A33536BBCE3EE7102DE102B24278A91B0F2A401` |
| TELFHASH | `t166f081a0075d0dcd07f4c604c7ee57291c71b45e37004907bee9ef0745e21d3725921a` |
| SSDEEP | `1536:fZntNY3Ls5zEXFGfBC41fvNWsWaRZPdVCJkGGI05wdllcie4vLrkE:vNY7uEVmvws5RRdVCJkGGRgM4v3L` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_0c77c688
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c77c688c8e96f308e67772abeb7de9bfed680d186301daf720338fc7780ea6a"
    family = "Mirai"
    file_name = "LFt3"
    file_type = "elf"
    first_seen = "2026-07-28 20:44:29"
  condition:
    hash.sha256(0, filesize) == "0c77c688c8e96f308e67772abeb7de9bfed680d186301daf720338fc7780ea6a"
}
```

### Sample 56: `6c1abc6c731f272e`

| Field | Value |
|---|---|
| SHA-256 | `6c1abc6c731f272e22deabeeb92b6378fdc32507a1fac93271b45a2a577aa88c` |
| Family label | `Formbook` |
| File name | `Quotation.JS` |
| File type | `js` |
| First seen | `2026-07-28 20:44:18` |
| Reporter | `James_inthe_box` |
| Tags | `exe, Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bc85fa0861e29220ac221302bcd4fe5` |
| SHA-1 | `f04d5be78e3d6f33e12a53f1dbb17033a51e2116` |
| SHA-256 | `6c1abc6c731f272e22deabeeb92b6378fdc32507a1fac93271b45a2a577aa88c` |
| SHA3-384 | `d17e92521f680547c438f3fa65474b354d1a54d8cdcdc3d0704b11906a1e43f280c585a4b7507556ed66b849837e1689` |
| TLSH | `T1A716E8974F544A9D55ACC76CC96EEB484B7D120B033CAE0E3BB938D4DE56FAB104C09A` |
| SSDEEP | `98304:CMq69t2ynXIkZt/n4Ynab8USlsH7dX65iAM83i4M8BFdz7:kqII4oab8US+dKXzi+z7` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_056_6c1abc6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c1abc6c731f272e22deabeeb92b6378fdc32507a1fac93271b45a2a577aa88c"
    family = "Formbook"
    file_name = "Quotation.JS"
    file_type = "js"
    first_seen = "2026-07-28 20:44:18"
  condition:
    hash.sha256(0, filesize) == "6c1abc6c731f272e22deabeeb92b6378fdc32507a1fac93271b45a2a577aa88c"
}
```

### Sample 57: `6436c0d5db9dfda7`

| Field | Value |
|---|---|
| SHA-256 | `6436c0d5db9dfda7cb951774c4c466c47c5c0df446178b229e75c58139161a81` |
| Family label | `unknown` |
| File name | `9ff72d21-8502-4a6a-b740-c41133dd8265` |
| File type | `unknown` |
| First seen | `2026-07-28 20:43:45` |
| Reporter | `skocherhan` |
| Tags | `azale1980-duckdns-org, robin43hf-duckdns-org` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a770c365f35ac9783c24514853a5d733` |
| SHA-256 | `6436c0d5db9dfda7cb951774c4c466c47c5c0df446178b229e75c58139161a81` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_6436c0d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6436c0d5db9dfda7cb951774c4c466c47c5c0df446178b229e75c58139161a81"
    family = "unknown"
    file_name = "9ff72d21-8502-4a6a-b740-c41133dd8265"
    file_type = "unknown"
    first_seen = "2026-07-28 20:43:45"
  condition:
    hash.sha256(0, filesize) == "6436c0d5db9dfda7cb951774c4c466c47c5c0df446178b229e75c58139161a81"
}
```

### Sample 58: `194b02279c7aa385`

| Field | Value |
|---|---|
| SHA-256 | `194b02279c7aa385261c8badb611011aed5677311dbdb96d26e7b5951205d354` |
| Family label | `Mirai` |
| File name | `Lrtt` |
| File type | `elf` |
| First seen | `2026-07-28 20:42:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c71ad53df2819f5cef21166aa022cbb3` |
| SHA-1 | `45c49ad92fe0ca3e2f4331886a9a2ff5babd8fbc` |
| SHA-256 | `194b02279c7aa385261c8badb611011aed5677311dbdb96d26e7b5951205d354` |
| SHA3-384 | `64460b85456ee1e49dd049e0388250b8dd12468c350ea6853948a335e7866a10b0d3f5f0ae5b053094e606cf9259c68f` |
| TLSH | `T177633B66B9419F16C2C16677FF1EC389332763E8E3DA7203DD142F69338B42A0E2A551` |
| TELFHASH | `t1b8f0e135448b28dc79e8c144c2df43538d5432792200561c36ecde438493d53b22dc1d` |
| SSDEEP | `1536:R32EjYaoQeTvjCZc6QY0dKkhrUBT+JmR94YAoZcom1FvEoX3xWSBM:R32EjYa7eTGUOkhUB6JE9Ea/QFvEA31M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_194b0227
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "194b02279c7aa385261c8badb611011aed5677311dbdb96d26e7b5951205d354"
    family = "Mirai"
    file_name = "Lrtt"
    file_type = "elf"
    first_seen = "2026-07-28 20:42:56"
  condition:
    hash.sha256(0, filesize) == "194b02279c7aa385261c8badb611011aed5677311dbdb96d26e7b5951205d354"
}
```

### Sample 59: `77755cc0490521af`

| Field | Value |
|---|---|
| SHA-256 | `77755cc0490521af6f766826172706f091c6963af70e5e23cecd9567a72cd336` |
| Family label | `Mirai` |
| File name | `LrHq` |
| File type | `elf` |
| First seen | `2026-07-28 20:42:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ede604f1401d7e455a118127ea175266` |
| SHA-1 | `b84a50caa282ace91b3a567d8d0386fb67576e95` |
| SHA-256 | `77755cc0490521af6f766826172706f091c6963af70e5e23cecd9567a72cd336` |
| SHA3-384 | `cabb1e5826ec3aa49e33590247c736fb351c71e009fef53c05ffb6142248e04d105805292b30e6b2267583fd4842f4ed` |
| TLSH | `T10DA3E94AAF651DB7D81BCD3705AD0B4235CCAA0771683B763934C928F64A54F8AE3CB4` |
| SSDEEP | `1536:FyerkQ52P0oXGBiNlwVf4SF8836992xPfTuJ5+U4pyU0tcmY5y/b:UIwP0oXciNl2889/yR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_77755cc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77755cc0490521af6f766826172706f091c6963af70e5e23cecd9567a72cd336"
    family = "Mirai"
    file_name = "LrHq"
    file_type = "elf"
    first_seen = "2026-07-28 20:42:55"
  condition:
    hash.sha256(0, filesize) == "77755cc0490521af6f766826172706f091c6963af70e5e23cecd9567a72cd336"
}
```

### Sample 60: `0605015c8428fb4e`

| Field | Value |
|---|---|
| SHA-256 | `0605015c8428fb4efc98e0abd8af027c7a01f2e87471dbc7e4389a3c6e5844c4` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 20:38:37` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc23b8b8afcffbf1798d09ebf443af85` |
| SHA-1 | `a7793c7102527152dc5972d13adb21969fe49e7a` |
| SHA-256 | `0605015c8428fb4efc98e0abd8af027c7a01f2e87471dbc7e4389a3c6e5844c4` |
| SHA3-384 | `b1ea09866ec4e878b6a59e4af6519be746cf40d4cda11d9f67f7cfa3ac68687f2dccea3b769157ec0a919355cbcb3a8b` |
| IMPHASH | `b949039b6ebe4372b35d3494c33e4a51` |
| TLSH | `T1E925BE53B291A27DD15BC0B4835AC9B6B536B0C90631BDBF21E4D7343E9AE920F1CB19` |
| SSDEEP | `12288:/4yljr5bCTpu7BIopiE1uLwpQk4ls9dJW76G3L6m442wOyITRMc08SdhccB:DASBnsE1e2QZuyT3L6mt5ONTRb08Yh` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_060_0605015c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0605015c8428fb4efc98e0abd8af027c7a01f2e87471dbc7e4389a3c6e5844c4"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 20:38:37"
  condition:
    hash.sha256(0, filesize) == "0605015c8428fb4efc98e0abd8af027c7a01f2e87471dbc7e4389a3c6e5844c4"
}
```

### Sample 61: `ad87c521a094b77f`

| Field | Value |
|---|---|
| SHA-256 | `ad87c521a094b77faf0cb2c0da769b619dbdb567039eee489fcfdb13a23ce124` |
| Family label | `unknown` |
| File name | `kol.js` |
| File type | `js` |
| First seen | `2026-07-28 20:33:58` |
| Reporter | `skocherhan` |
| Tags | `js, junction-equation-kodak-counseling-trycloudflare-com, opendir, WsgiDAV` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28954d2e39f29e67359abbcc02a3bd91` |
| SHA-1 | `72c6da777889c4a4801dc7a313a1b951e77a9372` |
| SHA-256 | `ad87c521a094b77faf0cb2c0da769b619dbdb567039eee489fcfdb13a23ce124` |
| SHA3-384 | `eb82a40bf2a248ee7846b72930362b522a239b180bd563d1ea32a7709c07f7ed67975de3f5ce88d80e1a5e58cfcfe44c` |
| TLSH | `T102E0C2456A14D0D0986667D2565D82D881B806822C15F2ABFE508BC65E7B67043D4D8B` |
| SSDEEP | `6:hFqrTFILwCfLKzd+2iN7yeHdxRRMes2/eQSAqoUF045:rqrGEGKAHNJHdxRps2/eQSAnUFX5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_ad87c521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad87c521a094b77faf0cb2c0da769b619dbdb567039eee489fcfdb13a23ce124"
    family = "unknown"
    file_name = "kol.js"
    file_type = "js"
    first_seen = "2026-07-28 20:33:58"
  condition:
    hash.sha256(0, filesize) == "ad87c521a094b77faf0cb2c0da769b619dbdb567039eee489fcfdb13a23ce124"
}
```

### Sample 62: `9fba3a68221cc6d7`

| Field | Value |
|---|---|
| SHA-256 | `9fba3a68221cc6d7ca5a0f14881e0ce7e1c201009901e715e9f49aa2c5447da1` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-28 20:32:30` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5b72f88f042c0215aefcfc88f003343` |
| SHA-1 | `5cc353e77e2c62a9ca916a5aed3faaceb360f24d` |
| SHA-256 | `9fba3a68221cc6d7ca5a0f14881e0ce7e1c201009901e715e9f49aa2c5447da1` |
| SHA3-384 | `210c4eeacb3b61daf0a724d6ef2d7aaaba8d78dd8fd8de4c4377346bb28436a1b53042c9efaeb50cd429c54cb72dcc5c` |
| TLSH | `T110C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C12F9CD618B1A` |
| SSDEEP | `768:eeY8vCB+25j6es8RD9FYpMSUpi+20qUpi+20YQX:o8l25JFd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_9fba3a68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fba3a68221cc6d7ca5a0f14881e0ce7e1c201009901e715e9f49aa2c5447da1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-28 20:32:30"
  condition:
    hash.sha256(0, filesize) == "9fba3a68221cc6d7ca5a0f14881e0ce7e1c201009901e715e9f49aa2c5447da1"
}
```

### Sample 63: `ad402539ef20003f`

| Field | Value |
|---|---|
| SHA-256 | `ad402539ef20003f7fce7cb87a0549f04d78c8c066c26c2cba032ee329705ed2` |
| Family label | `unknown` |
| File name | `Purchase_Order_28_07_2026.js` |
| File type | `js` |
| First seen | `2026-07-28 20:31:26` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `832b8c806e8ada7badc460b765395652` |
| SHA-1 | `776afd118b27365c7de155e835d6c205c8f0bc00` |
| SHA-256 | `ad402539ef20003f7fce7cb87a0549f04d78c8c066c26c2cba032ee329705ed2` |
| SHA3-384 | `c013ca500c41d8dbe5d6ea1c6a4f6e0f03ef495f1bbe558dd616da4c350f54d53ad2d3936730df1e60243c6bb4d56bda` |
| TLSH | `T121955C45EFA2AB3455472F82115331CE3BA11FB498518361FBA8654B3646EEFF87A330` |
| SSDEEP | `24576:p/eWxpB4YWJ4yqnAGvW19Hsuk8BRjTM637ZV4NN1tTqW35bUmtu9TYiW4lkijGvh:p1zaNEFOj42iN1t4moYt9guwU+Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_ad402539
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad402539ef20003f7fce7cb87a0549f04d78c8c066c26c2cba032ee329705ed2"
    family = "unknown"
    file_name = "Purchase_Order_28_07_2026.js"
    file_type = "js"
    first_seen = "2026-07-28 20:31:26"
  condition:
    hash.sha256(0, filesize) == "ad402539ef20003f7fce7cb87a0549f04d78c8c066c26c2cba032ee329705ed2"
}
```

### Sample 64: `350e280370d76945`

| Field | Value |
|---|---|
| SHA-256 | `350e280370d76945e1b4d460009d97d6976fcc4e33c966d73c78d4b520b50874` |
| Family label | `PythonStealer` |
| File name | `New_Specification_Of_Industrial_Power_Generator_and_Quantities_Needed_For_Each.zip` |
| File type | `zip` |
| First seen | `2026-07-28 20:25:07` |
| Reporter | `smica83` |
| Tags | `PythonStealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd4e18657cb4ccf267b1c2f5a7b548aa` |
| SHA-1 | `86cfdf3f47b77909ad4288ba2176e066a86982ef` |
| SHA-256 | `350e280370d76945e1b4d460009d97d6976fcc4e33c966d73c78d4b520b50874` |
| SHA3-384 | `1cedc6ccb034a2daf66b6bf85b8ece98e2ec932078a42e41f4bdb65a77ac6ef01b927a35bda55e33f2acb42caaafb619` |
| TLSH | `T1D096336B692179C641CFBB715C206F425BB921B11CBF854A3D9FCA27EB080BD78297D0` |
| SSDEEP | `196608:qP/2RiSqhv9KDyT1VRZU+CktN9iBtAB/oB76qZXW6znj:y+0SmWQ5ZUqOBgOdXtj` |

#### Technical Assessment

- The sample is tracked as `PythonStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PythonStealer_064_350e2803
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "350e280370d76945e1b4d460009d97d6976fcc4e33c966d73c78d4b520b50874"
    family = "PythonStealer"
    file_name = "New_Specification_Of_Industrial_Power_Generator_and_Quantities_Needed_For_Each.zip"
    file_type = "zip"
    first_seen = "2026-07-28 20:25:07"
  condition:
    hash.sha256(0, filesize) == "350e280370d76945e1b4d460009d97d6976fcc4e33c966d73c78d4b520b50874"
}
```

### Sample 65: `7539c48603f670a8`

| Field | Value |
|---|---|
| SHA-256 | `7539c48603f670a8a14c59391c1bbc01371635b89ea06f2f68cf273ac709f8bb` |
| Family label | `unknown` |
| File name | `payload(1).exe` |
| File type | `exe` |
| First seen | `2026-07-28 20:21:45` |
| Reporter | `smica83` |
| Tags | `103-193-173-83, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e4077197293253a06bdd46ce433b505` |
| SHA-1 | `c57ef42c52efa15f8f9ec2cf14e1d6d94d925c9e` |
| SHA-256 | `7539c48603f670a8a14c59391c1bbc01371635b89ea06f2f68cf273ac709f8bb` |
| SHA3-384 | `150bc03650d99d6b7f14476d512431ea90630e2750abb55fdc425c8900c6da39bf1b549f39648ae68a4f7e823b79ff6b` |
| IMPHASH | `49b533d8c0ce90df0101f35a2c0af7d4` |
| TLSH | `T14AA58D56E2B360ECC66BC171875BEA67F674742C41207E7B9990C7302E72F50271AF2A` |
| SSDEEP | `49152:EBkjNIR9hbVDy/mqtP3G3c/3eWJrePHfR:qhb+osv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_7539c486
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7539c48603f670a8a14c59391c1bbc01371635b89ea06f2f68cf273ac709f8bb"
    family = "unknown"
    file_name = "payload(1).exe"
    file_type = "exe"
    first_seen = "2026-07-28 20:21:45"
  condition:
    hash.sha256(0, filesize) == "7539c48603f670a8a14c59391c1bbc01371635b89ea06f2f68cf273ac709f8bb"
}
```

### Sample 66: `d02fb84cea88610d`

| Field | Value |
|---|---|
| SHA-256 | `d02fb84cea88610da9c7d84902c64e2e11d66795ef56ed8a5e4f77d19c294175` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-28 20:20:30` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe0fdf14f854f154d45ea5afd572e851` |
| SHA-1 | `8714ebae8ae100d40d526d00ec9e6c1cec1caa80` |
| SHA-256 | `d02fb84cea88610da9c7d84902c64e2e11d66795ef56ed8a5e4f77d19c294175` |
| SHA3-384 | `98a2d61b6fb6dd46ae7987b1f7c6076e666c94ab430955d7829f585e4953f9c4ad9f3a8f42cb9044c42ee8222fe3292e` |
| TLSH | `T190C28D956A867C44BDC98A3E4CBE2B0D6DF5C3D1324942AC3D8B3C719C15F9CD618B2A` |
| SSDEEP | `768:vr8vCB+25j6es8Rd9FYpMSUpi+20qUpi+20YQX:T8l25JLd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_d02fb84c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d02fb84cea88610da9c7d84902c64e2e11d66795ef56ed8a5e4f77d19c294175"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-28 20:20:30"
  condition:
    hash.sha256(0, filesize) == "d02fb84cea88610da9c7d84902c64e2e11d66795ef56ed8a5e4f77d19c294175"
}
```

### Sample 67: `1a569dd1087367b8`

| Field | Value |
|---|---|
| SHA-256 | `1a569dd1087367b863590e8e1a6e8755a368473d86ebd3213b9be3ed971668e5` |
| Family label | `unknown` |
| File name | `payload.exe` |
| File type | `exe` |
| First seen | `2026-07-28 20:20:28` |
| Reporter | `smica83` |
| Tags | `103-193-173-83, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1eea14a025deda739b2d66985ee8d7bd` |
| SHA-1 | `205a898f45c962893751fb40e40678ec51fde2c5` |
| SHA-256 | `1a569dd1087367b863590e8e1a6e8755a368473d86ebd3213b9be3ed971668e5` |
| SHA3-384 | `108acfe75201159fe792018f74f8c87973d4833b76331f8718a0bbfcbf33a732056773464d1692715508a3b4d9a01354` |
| IMPHASH | `e5288f788faa45e831987b5d5eeb91cd` |
| TLSH | `T146A59D56E27360ECC66BC1708B5BEA67F674742C41207E7B9990C7302E72F50671AF2A` |
| SSDEEP | `49152:rmNkvLkwZbfxcQvMb96IlAl8eDdX7nPHa0o:BbfIdPei` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_1a569dd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a569dd1087367b863590e8e1a6e8755a368473d86ebd3213b9be3ed971668e5"
    family = "unknown"
    file_name = "payload.exe"
    file_type = "exe"
    first_seen = "2026-07-28 20:20:28"
  condition:
    hash.sha256(0, filesize) == "1a569dd1087367b863590e8e1a6e8755a368473d86ebd3213b9be3ed971668e5"
}
```

### Sample 68: `668c0851af5a3a1f`

| Field | Value |
|---|---|
| SHA-256 | `668c0851af5a3a1f685f3e632e4cce3f71aed73808deefe4c5b59bf40088d4fa` |
| Family label | `unknown` |
| File name | `version.dll` |
| File type | `exe` |
| First seen | `2026-07-28 20:20:10` |
| Reporter | `smica83` |
| Tags | `103-193-173-83, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc8656d5372f7aaef67d2c8ecdc1a20c` |
| SHA-1 | `f857f8c6e71d93e73f9846a793005338313b1380` |
| SHA-256 | `668c0851af5a3a1f685f3e632e4cce3f71aed73808deefe4c5b59bf40088d4fa` |
| SHA3-384 | `5ad504d272dbe0d82c43993c45c66ac8780dde200bc3ca9f6e1ba6088f7cdc3fb4de820ccee47cf396a65251afe53ebe` |
| IMPHASH | `d4434b8b9fc94456394b657184fed035` |
| TLSH | `T1F292E74FEA8A18ECCDE7E2B8D4E71B31E9B179180569B77F0714C0766D22E45E5BC220` |
| SSDEEP | `384:QSf/S2y46GmxTIicuVPR8F7RmckVPxIiTDTjUlW8EBW:QS3ohGmxTIicuVPR+RmckVPxIiTLyE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_668c0851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668c0851af5a3a1f685f3e632e4cce3f71aed73808deefe4c5b59bf40088d4fa"
    family = "unknown"
    file_name = "version.dll"
    file_type = "exe"
    first_seen = "2026-07-28 20:20:10"
  condition:
    hash.sha256(0, filesize) == "668c0851af5a3a1f685f3e632e4cce3f71aed73808deefe4c5b59bf40088d4fa"
}
```

### Sample 69: `a1a91d9cd396186c`

| Field | Value |
|---|---|
| SHA-256 | `a1a91d9cd396186c4fde28e050f88aa68062b05195aaea091e7b3a1ca7539893` |
| Family label | `unknown` |
| File name | `dropper-msvc-x64-no-bait-noselfdel.exe` |
| File type | `exe` |
| First seen | `2026-07-28 20:19:55` |
| Reporter | `smica83` |
| Tags | `103-193-173-83, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fbe2ded02e88e4d9318c068437e4358` |
| SHA-1 | `b936c514f6fbb82ecddbf281f52ebfee2f0c4f6d` |
| SHA-256 | `a1a91d9cd396186c4fde28e050f88aa68062b05195aaea091e7b3a1ca7539893` |
| SHA3-384 | `572032947abbcbfd8a7490a770988c8cdc1bd4b7fec72359182627f814482ccee5483c4db570d0c51f2b75e8c87e463a` |
| IMPHASH | `f2646023aecc478287007e824cca1e49` |
| TLSH | `T1D0565B17F26611EDC07EC174834AA232FA71784947357AEF4AD09B212F62FE05B7A709` |
| SSDEEP | `98304:0kerL0AbCfxzGkVsF09zk7ZWAvXk/Fw/qBmT+LLNFgZ:sL0AbXfvUqyNa` |
| ICON-DHASH | `74e4d4d4ecf4d4d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_a1a91d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1a91d9cd396186c4fde28e050f88aa68062b05195aaea091e7b3a1ca7539893"
    family = "unknown"
    file_name = "dropper-msvc-x64-no-bait-noselfdel.exe"
    file_type = "exe"
    first_seen = "2026-07-28 20:19:55"
  condition:
    hash.sha256(0, filesize) == "a1a91d9cd396186c4fde28e050f88aa68062b05195aaea091e7b3a1ca7539893"
}
```

### Sample 70: `46effa2a273d465e`

| Field | Value |
|---|---|
| SHA-256 | `46effa2a273d465e4a4bb96c0519ca0b5ac51ff141f8affcf9c9803c1689aa1e` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-28 20:17:02` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da8f88f7e94164bba3dd736ec9093a09` |
| SHA-1 | `c1acba9705f23da7f8b00a619db667100583692f` |
| SHA-256 | `46effa2a273d465e4a4bb96c0519ca0b5ac51ff141f8affcf9c9803c1689aa1e` |
| SHA3-384 | `992c384329c3bb5ed4502ff8fe51d29ae9cfec60fac7bf964536557e8749799a3718dae10d267f15f4ab32eb82296e6e` |
| TLSH | `T1F2235C6516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF68C4A6ADD109B1D` |
| SSDEEP | `768:Bn+O9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:J+bcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_46effa2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46effa2a273d465e4a4bb96c0519ca0b5ac51ff141f8affcf9c9803c1689aa1e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-28 20:17:02"
  condition:
    hash.sha256(0, filesize) == "46effa2a273d465e4a4bb96c0519ca0b5ac51ff141f8affcf9c9803c1689aa1e"
}
```

### Sample 71: `beeb2032f9a69f24`

| Field | Value |
|---|---|
| SHA-256 | `beeb2032f9a69f24e399a12568a2bbc5d184bb5461264e9ce7abf1298f77d003` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-28 20:13:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7931fe21f24ec88d27bb4037cdd423b9` |
| SHA-1 | `a40bc12cf0af76b69866b27d9ba421a6aa4e3745` |
| SHA-256 | `beeb2032f9a69f24e399a12568a2bbc5d184bb5461264e9ce7abf1298f77d003` |
| SHA3-384 | `8433ddaf966f6b3f3e1e8b2835136b7edfea733ec2c905c20b65618c2c4ff5dfde4b4f4c5bfae0700cf94b38b14d6fb5` |
| TLSH | `T150A35E9BF401EE7DF80BD5BA04674A0AF630E3E11B930B366397BD57ED351A50826E81` |
| SSDEEP | `1536:iPhR5NUppD0SKDTh7BN8H9/oRLfZAufjW1t0NPtwCkw8:ipqfoS+7BsKLhzvNPtwCkw8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_beeb2032
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "beeb2032f9a69f24e399a12568a2bbc5d184bb5461264e9ce7abf1298f77d003"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-28 20:13:54"
  condition:
    hash.sha256(0, filesize) == "beeb2032f9a69f24e399a12568a2bbc5d184bb5461264e9ce7abf1298f77d003"
}
```

### Sample 72: `4be16b2978b746c0`

| Field | Value |
|---|---|
| SHA-256 | `4be16b2978b746c0eb0533f91a5de765f783ccd1bfd914deb921e90d7301d2ea` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-28 20:13:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90889c8219f16e46b4fd3d6f4f6e9a7c` |
| SHA-1 | `8a1b05490faf66c97f18793ba48dbce2e2b1886b` |
| SHA-256 | `4be16b2978b746c0eb0533f91a5de765f783ccd1bfd914deb921e90d7301d2ea` |
| SHA3-384 | `b2c34360f18ee4d08fff9b096939bbfaffa7c624cb6527321930f5cd56647515fba3c72be8f0833ebba4287a5cb1d7f3` |
| TLSH | `T187932A03B58090FCC5C6C1344B7FA636EA72F1ED1275B69A37E4EF222D4AE211E2D954` |
| TELFHASH | `t142216b316da91890a1f3e337b307f1d5a9221e1025f235e4dd77acd6cfa67864c72052` |
| SSDEEP | `1536:KPvjFFjrKGGg17rsyCcpUu1v/43WL4vwi252xPSUUN4J+LDR:KvjLrKGG4syfImLviNxpUN48LD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_4be16b29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4be16b2978b746c0eb0533f91a5de765f783ccd1bfd914deb921e90d7301d2ea"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-28 20:13:53"
  condition:
    hash.sha256(0, filesize) == "4be16b2978b746c0eb0533f91a5de765f783ccd1bfd914deb921e90d7301d2ea"
}
```

### Sample 73: `ded67d13db4b3311`

| Field | Value |
|---|---|
| SHA-256 | `ded67d13db4b33119436c67e94142e5e903ac5c7dbad6e98274914dc0f8d6182` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-28 20:13:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9deecb8f9c95ae0696c0758f8fd986fe` |
| SHA-1 | `77698accd857c188a127aac8088429e6290c0e4a` |
| SHA-256 | `ded67d13db4b33119436c67e94142e5e903ac5c7dbad6e98274914dc0f8d6182` |
| SHA3-384 | `03455cac5f1de8de0f8898b51b81f8cf8509277d8d8216e19237dafaa100b2575ee7dd28fdf982297519754858095e47` |
| TLSH | `T157532B9AF801CE7DF85BD77B4457090AB532B3D112831B3623A7B997BC731A81D22E85` |
| SSDEEP | `1536:m7Eg48H4K+3a38/yph8Ci+HaJEc7DnbaNmMaW8YOi:m7E98Yl3a48h8mHwEcfSv8YOi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_ded67d13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ded67d13db4b33119436c67e94142e5e903ac5c7dbad6e98274914dc0f8d6182"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-28 20:13:51"
  condition:
    hash.sha256(0, filesize) == "ded67d13db4b33119436c67e94142e5e903ac5c7dbad6e98274914dc0f8d6182"
}
```

### Sample 74: `64904cd80ec7985e`

| Field | Value |
|---|---|
| SHA-256 | `64904cd80ec7985ef0cefcb50e2c44fb5da42317c856f69b4a11d992f6631a58` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-28 20:02:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b32ae34689885f625ffb4d96d5d8d88` |
| SHA-1 | `526456bbf0f4721ce3a410069a3e67bf41a132b0` |
| SHA-256 | `64904cd80ec7985ef0cefcb50e2c44fb5da42317c856f69b4a11d992f6631a58` |
| SHA3-384 | `83dc73de310159e554991fff7405c9223c987d3f958b01b4ac023c287b2c393a78b245d10650c7f35cad7a156c784e9e` |
| TLSH | `T15214945E2E228F7DF678C33447F74A20976D73DA26E1D684D2ACD1052F2025E641FBA8` |
| TELFHASH | `t126418c180e7417f0a3355d9e19ddfb76e6a330da7e162d338f21e85aab699834e10c0c` |
| SSDEEP | `3072:ZviBF3ROK55Moi/1Y4U9SOAKMKDRq7ig+nzW661DRh82LUlvFiElzK1STphnuqSK:ZviBZ37wYlvFHlkSTeqS5Y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_64904cd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64904cd80ec7985ef0cefcb50e2c44fb5da42317c856f69b4a11d992f6631a58"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-28 20:02:39"
  condition:
    hash.sha256(0, filesize) == "64904cd80ec7985ef0cefcb50e2c44fb5da42317c856f69b4a11d992f6631a58"
}
```

### Sample 75: `f4c32b3f9a949e5a`

| Field | Value |
|---|---|
| SHA-256 | `f4c32b3f9a949e5a17ff0b8ad130ba5ca15e5d9a037c7a97dcc68a6b4c3212f7` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-28 19:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `219b5d691744d7a98c8b4df067b0b136` |
| SHA-1 | `8587723e626cb2b73b27e79c8828abe8d5bc1996` |
| SHA-256 | `f4c32b3f9a949e5a17ff0b8ad130ba5ca15e5d9a037c7a97dcc68a6b4c3212f7` |
| SHA3-384 | `67af4751f4049119a67c4f7fd84cbf803385cd36bbe35a86543228aabb683a873cb616cd745b25e8199be334c09c586a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T140E63348B7E492EEF5B3843CBCA160A5D5A4F8734732C5DB4B6883B2AD172E04939753` |
| SSDEEP | `393216:ELZKsRWVOpGJEst1yGXMCHWUjX6cuI3/PGTAI:ErWVOpGuI1TXMb8X3H/O7` |
| ICON-DHASH | `f0f89ca69ac6f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_f4c32b3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4c32b3f9a949e5a17ff0b8ad130ba5ca15e5d9a037c7a97dcc68a6b4c3212f7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 19:52:31"
  condition:
    hash.sha256(0, filesize) == "f4c32b3f9a949e5a17ff0b8ad130ba5ca15e5d9a037c7a97dcc68a6b4c3212f7"
}
```

### Sample 76: `3d4c5602c640bf6f`

| Field | Value |
|---|---|
| SHA-256 | `3d4c5602c640bf6f7787546e82e65c5436a08f90f19089c4f185e0e12132abcd` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-28 19:42:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a31dc14cab9edf5821a97fe6ad9161c` |
| SHA-1 | `8f4784412679f8394cbb042446e3d230993c0f39` |
| SHA-256 | `3d4c5602c640bf6f7787546e82e65c5436a08f90f19089c4f185e0e12132abcd` |
| SHA3-384 | `0f749c01710dce7b5bdf4effa55e76f982d6dfc400e6e91bef29e765279277b6114ebb1a1394db17effee7809ba1c3a6` |
| TLSH | `T18A236C651A857C149E98C4371D7E2F0CB9AD43E6320852DE7FCB3CF68C8AA9D920971D` |
| SSDEEP | `768:dVEJVIhtMU9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:zEJ2MZcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_3d4c5602
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d4c5602c640bf6f7787546e82e65c5436a08f90f19089c4f185e0e12132abcd"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-28 19:42:50"
  condition:
    hash.sha256(0, filesize) == "3d4c5602c640bf6f7787546e82e65c5436a08f90f19089c4f185e0e12132abcd"
}
```

### Sample 77: `5823135e1fae078b`

| Field | Value |
|---|---|
| SHA-256 | `5823135e1fae078b8bb4d256f6cb03140f04f4c8293103a5cb08e07535bfae2b` |
| Family label | `unknown` |
| File name | `Notice from Tax Departmen.dmg` |
| File type | `unknown` |
| First seen | `2026-07-28 19:41:12` |
| Reporter | `smica83` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f292983ded309e0e62f53a013fc27f2c` |
| SHA-256 | `5823135e1fae078b8bb4d256f6cb03140f04f4c8293103a5cb08e07535bfae2b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_5823135e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5823135e1fae078b8bb4d256f6cb03140f04f4c8293103a5cb08e07535bfae2b"
    family = "unknown"
    file_name = "Notice from Tax Departmen.dmg"
    file_type = "unknown"
    first_seen = "2026-07-28 19:41:12"
  condition:
    hash.sha256(0, filesize) == "5823135e1fae078b8bb4d256f6cb03140f04f4c8293103a5cb08e07535bfae2b"
}
```

### Sample 78: `606f4256012f37e7`

| Field | Value |
|---|---|
| SHA-256 | `606f4256012f37e7e120966888e6a7bad12abb004e135c4f663bc73e124699ea` |
| Family label | `unknown` |
| File name | `5.msi` |
| File type | `msi` |
| First seen | `2026-07-28 19:36:35` |
| Reporter | `smica83` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1b655657e09f8d882fce9ca90139fb7` |
| SHA-1 | `5846dbbce0d4df103d0d0fb19a3230f8a87b0d65` |
| SHA-256 | `606f4256012f37e7e120966888e6a7bad12abb004e135c4f663bc73e124699ea` |
| SHA3-384 | `9bfcb7736eff599bd48642984811ae677c30f73419088b830c5d363316c66ce3fe4f4e635af8754f686090c47c50cb80` |
| TLSH | `T130571285F6518879FA5F0231A6FABF08547BFCEA13D4624934E8B118A3E3ED90D520D7` |
| SSDEEP | `393216:Pp1s7O5Sz3ds708J/LrRQLJg3g9DGH0bpZlJjfFx3O1lP1ICVmTovfYwOv4QS0V:v1qNgBQL+3g9DGHWjdxyICVo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_606f4256
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "606f4256012f37e7e120966888e6a7bad12abb004e135c4f663bc73e124699ea"
    family = "unknown"
    file_name = "5.msi"
    file_type = "msi"
    first_seen = "2026-07-28 19:36:35"
  condition:
    hash.sha256(0, filesize) == "606f4256012f37e7e120966888e6a7bad12abb004e135c4f663bc73e124699ea"
}
```

### Sample 79: `309373483b37a15c`

| Field | Value |
|---|---|
| SHA-256 | `309373483b37a15cf1f6372a918418681c4fbc549cc128429c672e8d837dbf88` |
| Family label | `unknown` |
| File name | `OTBank_Payment_28_07_2026_440802.pdf.js` |
| File type | `js` |
| First seen | `2026-07-28 19:32:59` |
| Reporter | `smica83` |
| Tags | `js, UKR` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28abf9601234e3e8a372878eafcf589e` |
| SHA-1 | `2061168b948a71fe6b2f5f55621f4e27fd3e07dc` |
| SHA-256 | `309373483b37a15cf1f6372a918418681c4fbc549cc128429c672e8d837dbf88` |
| SHA3-384 | `de37294655fa39512b6c232f72a4656fdfa0ab8b167fca576ec125f135a8d45d233e13ad1aa80b04279c09d04abc401c` |
| TLSH | `T117668389EEF722419D4370394BAF1042F1B9AA0B544DDD40B90EE3705FB162925EEBF9` |
| SSDEEP | `49152:SdBawcWYI3hJhdOQ2t8X7xfN3jVR4E0oRADEWm:SdB0W3db0E0RDEWm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_30937348
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "309373483b37a15cf1f6372a918418681c4fbc549cc128429c672e8d837dbf88"
    family = "unknown"
    file_name = "OTBank_Payment_28_07_2026_440802.pdf.js"
    file_type = "js"
    first_seen = "2026-07-28 19:32:59"
  condition:
    hash.sha256(0, filesize) == "309373483b37a15cf1f6372a918418681c4fbc549cc128429c672e8d837dbf88"
}
```

### Sample 80: `ed714a097ff6169e`

| Field | Value |
|---|---|
| SHA-256 | `ed714a097ff6169e1a9935c9b8b7e09afffc45aab659cac9c3bed8a146f83851` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-28 19:22:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `599c16f5fbabf462caab4456efd51609` |
| SHA-1 | `7c6dbeff47c93357ff9803f22d570cc162d6af69` |
| SHA-256 | `ed714a097ff6169e1a9935c9b8b7e09afffc45aab659cac9c3bed8a146f83851` |
| SHA3-384 | `335c1cff1919f7f0f58e0eedc0db85582b12f3a1b813d40e25ad4097152f0b6b173eef2766fefd6a7c8d90c9645d0dbc` |
| TLSH | `T130831959FD80AF15E5D625BAFF0E514933634B6CE3EE72029E245B2523CA91B0F3B406` |
| TELFHASH | `t19fb092302e1d6b8c12e4d7d229b2e0840424a4a5058c1778a9e9280a41a76a21155238` |
| SSDEEP | `1536:UdnPNbbcPF14nuoFska9A5+mpiMwq5o82lkuIiY7ooBk12oZWYAcRN:M3cPWuoFska9AcmoMwqmG7ooBk12owUN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_ed714a09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed714a097ff6169e1a9935c9b8b7e09afffc45aab659cac9c3bed8a146f83851"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-28 19:22:32"
  condition:
    hash.sha256(0, filesize) == "ed714a097ff6169e1a9935c9b8b7e09afffc45aab659cac9c3bed8a146f83851"
}
```

### Sample 81: `47f9779b48eeda53`

| Field | Value |
|---|---|
| SHA-256 | `47f9779b48eeda53a846a2460456c738ad752ad0e02483231d927930f3f37dce` |
| Family label | `WannaCry` |
| File name | `47f9779b48eeda53a846a2460456c738ad752ad0e02483231d927930f3f37dce` |
| File type | `exe` |
| First seen | `2026-07-28 19:15:22` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `700fb7e2c6a2ff13cd27e08a18703423` |
| SHA-1 | `19cdc7a8624c614cb8c06dc4f439fe86f9e6a515` |
| SHA-256 | `47f9779b48eeda53a846a2460456c738ad752ad0e02483231d927930f3f37dce` |
| SHA3-384 | `8662cc61f7a1bdd5e118a3c4a2a31397253e3639739bf82e14d87fe05f10dcfc7fe3f4d08abc60319d5825a81be2f2d4` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T14336239631FC80B8D206157484F79E12F3B2BC6922BA6A4F9F8049752E23B57F724753` |
| SSDEEP | `49152:jnsnRMSPbcBVQejduNRx+TSqTdX1HkQo6SAARdhnv:DMRPoBhpcRxcSUDk36SAEdhv` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_081_47f9779b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47f9779b48eeda53a846a2460456c738ad752ad0e02483231d927930f3f37dce"
    family = "WannaCry"
    file_name = "47f9779b48eeda53a846a2460456c738ad752ad0e02483231d927930f3f37dce"
    file_type = "exe"
    first_seen = "2026-07-28 19:15:22"
  condition:
    hash.sha256(0, filesize) == "47f9779b48eeda53a846a2460456c738ad752ad0e02483231d927930f3f37dce"
}
```

### Sample 82: `d81fc15c5209b181`

| Field | Value |
|---|---|
| SHA-256 | `d81fc15c5209b18130b08a9d7182a78aa3f6184ffb79cabd7dce4cf5a3d3cab4` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-28 19:12:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2316fec3153c834239670393bc6fc3fb` |
| SHA-1 | `daa41c82789618e1bb1a18774024f4db7c4e34c3` |
| SHA-256 | `d81fc15c5209b18130b08a9d7182a78aa3f6184ffb79cabd7dce4cf5a3d3cab4` |
| SHA3-384 | `197f7d18dea196c6e5555f77cfb3dda20a3e0c97bf39587b2f0ecb22678d70e65749080c68c0a46382059c7447d17f3a` |
| TLSH | `T15DE30849F8519F22C6C615BBFF4E828C772617A8D3EE72039D156F25378B85A0E3B142` |
| TELFHASH | `t197d01235871204f9d1835551422d109709fd305e5562348695fd6b5590a67c275de523` |
| SSDEEP | `3072:UDNgbcaYDekl2LQ4vVdYoHcSjsJshPknugs:UDNOgDmQ4vLZcQYshFgs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_d81fc15c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d81fc15c5209b18130b08a9d7182a78aa3f6184ffb79cabd7dce4cf5a3d3cab4"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-28 19:12:33"
  condition:
    hash.sha256(0, filesize) == "d81fc15c5209b18130b08a9d7182a78aa3f6184ffb79cabd7dce4cf5a3d3cab4"
}
```

### Sample 83: `aa64bf1471d43b21`

| Field | Value |
|---|---|
| SHA-256 | `aa64bf1471d43b21cc0b6f761473ed2903439364e5495656b67fb9e747910bb9` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-28 19:06:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55f97dd27d007bc1af1ffca99dc2c6f9` |
| SHA-1 | `c26ede663049aae3c012376527850958f227cba0` |
| SHA-256 | `aa64bf1471d43b21cc0b6f761473ed2903439364e5495656b67fb9e747910bb9` |
| SHA3-384 | `fa31af94eb63de580e3edb5d16bf5e65e4775e115a0835471705875b42f26ba7bf1d4e9a8ed5d06ef2decba46429717c` |
| TLSH | `T14CF3985A2E228FADF678873047F74A34976923DA23E1D684E1ACC1141F6435E641FBBC` |
| TELFHASH | `t1a341a2180e7817f0a3356c5d09ddfb3ad6a730da7e262c338e51e86ae7699835d10c0c` |
| SSDEEP | `3072:F1RCBE/uJ/n9d5S/voXNA4jKeAWt23rm6:FvSSE/n+AXN9jKUt27m6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_aa64bf14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa64bf1471d43b21cc0b6f761473ed2903439364e5495656b67fb9e747910bb9"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-28 19:06:38"
  condition:
    hash.sha256(0, filesize) == "aa64bf1471d43b21cc0b6f761473ed2903439364e5495656b67fb9e747910bb9"
}
```

### Sample 84: `5f1225fee9a33296`

| Field | Value |
|---|---|
| SHA-256 | `5f1225fee9a3329606862f1f8b2e4100f06e9b3c874cd319f763dcdd030a650c` |
| Family label | `unknown` |
| File name | `CrossDNS_Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-28 19:01:26` |
| Reporter | `Alex_sev` |
| Tags | `babar, dns, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ed7223bd26d5daf2b3120da798e7942` |
| SHA-1 | `9effb84c10917de2eedb8b66e3e50ec1a67e2fc6` |
| SHA-256 | `5f1225fee9a3329606862f1f8b2e4100f06e9b3c874cd319f763dcdd030a650c` |
| SHA3-384 | `179a859056d3a5e2e20f9697f47e05a584bd7c87a3849cab339ce0cc61466ab756388f797e87e7c533673c3a9c6d6b09` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T157F5F13FB28B753EE06E5A367A76A210583B676165138C16A6F4C84CCF250B01E3F797` |
| SSDEEP | `49152:vuI3hANFl6Op2KHPMrp9cEYX40VK/32EgqAmlVDyn1PC:v5xANFl6S2KHEUE0440TJ/Dyn16` |
| ICON-DHASH | `8671698ccc69728c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_5f1225fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f1225fee9a3329606862f1f8b2e4100f06e9b3c874cd319f763dcdd030a650c"
    family = "unknown"
    file_name = "CrossDNS_Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-28 19:01:26"
  condition:
    hash.sha256(0, filesize) == "5f1225fee9a3329606862f1f8b2e4100f06e9b3c874cd319f763dcdd030a650c"
}
```

### Sample 85: `82fb67cb2438bd02`

| Field | Value |
|---|---|
| SHA-256 | `82fb67cb2438bd0265f4e06f974456a8b212b70d45f8f3fc18e04155fa45791a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 18:55:17` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29bc41f6124aa659725fb39fee074724` |
| SHA-1 | `5a6aaa8ec7c2ab5e034b8d13f9ffe3f84b9b5242` |
| SHA-256 | `82fb67cb2438bd0265f4e06f974456a8b212b70d45f8f3fc18e04155fa45791a` |
| SHA3-384 | `1a501e98285b1e10fa73704a55a627c3cb85bb56d997daacbebf8fb8ded31059a741911488a4a6f2ccf157b1502bcd3e` |
| IMPHASH | `314d8821850121a2699e6f8c98b72945` |
| TLSH | `T104D46C0B978E29FFD1A6D0B9C14505A2A92274421F70EEDB53C19E362E366D01F3B3D6` |
| SSDEEP | `12288:BppbQrmufuZME7S4AQrn/pTcmbKLbKOabsDfeVYugvzs5NzQjCTI:IA+bKTgW7gvEc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_82fb67cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82fb67cb2438bd0265f4e06f974456a8b212b70d45f8f3fc18e04155fa45791a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 18:55:17"
  condition:
    hash.sha256(0, filesize) == "82fb67cb2438bd0265f4e06f974456a8b212b70d45f8f3fc18e04155fa45791a"
}
```

### Sample 86: `7f4947195d352f01`

| Field | Value |
|---|---|
| SHA-256 | `7f4947195d352f01a517e5f472d3ae734d22b1d8a6fc5a69b42e6db42f9a11ef` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-28 18:52:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef4bebc790aacb3ed0ccb59844ceda52` |
| SHA-1 | `cf525bddad87af6136de6a2ece8a3308f6b72ce1` |
| SHA-256 | `7f4947195d352f01a517e5f472d3ae734d22b1d8a6fc5a69b42e6db42f9a11ef` |
| SHA3-384 | `6d5e7cb10fb7067654f02623f08c4ca5a2c145fca253b19f4bae6b277e8948c3ac641616bbb6b0f57f95a6ea3419869b` |
| TLSH | `T158C27D956A867C44BEC98A3E4CBD2B0D6DF5C3D1324952AC3D8B3C719C12F9CD618B1A` |
| SSDEEP | `768:68vCB+25j6es8RZ9FYpMSUpi+20qUpi+20YQX:68l25J/d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_7f494719
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f4947195d352f01a517e5f472d3ae734d22b1d8a6fc5a69b42e6db42f9a11ef"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-28 18:52:35"
  condition:
    hash.sha256(0, filesize) == "7f4947195d352f01a517e5f472d3ae734d22b1d8a6fc5a69b42e6db42f9a11ef"
}
```

### Sample 87: `0bdbb0f2361160d4`

| Field | Value |
|---|---|
| SHA-256 | `0bdbb0f2361160d4c5e71ed923fde9e0133ee6927c8a02a3f491cee1b83a1982` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-28 18:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1795dc309add7a85887fe95758ed3ae8` |
| SHA-1 | `3aa3b396a17eb6f470771407946bd2dbee22bba1` |
| SHA-256 | `0bdbb0f2361160d4c5e71ed923fde9e0133ee6927c8a02a3f491cee1b83a1982` |
| SHA3-384 | `aa2a369752ce167db751c7be26a01eb7e31e0f744a7de26b882116d4983448ab939b3c96256cba1a4ce5fd1fa52cce19` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1AFE6338969D502EEFEF3513CD8E1A692E9B478B60BB0C49F17849B512E133E14D3D326` |
| SSDEEP | `393216:X1WlQ7wzNJbAm+yHgFg1SEveXMCHWUjXzcuI3/PGTAI:XzcDbAm+fFgSZXMb8XwH/O7` |
| ICON-DHASH | `d4f071e8e8607130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_0bdbb0f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bdbb0f2361160d4c5e71ed923fde9e0133ee6927c8a02a3f491cee1b83a1982"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 18:52:32"
  condition:
    hash.sha256(0, filesize) == "0bdbb0f2361160d4c5e71ed923fde9e0133ee6927c8a02a3f491cee1b83a1982"
}
```

### Sample 88: `7f758dd54c10e678`

| Field | Value |
|---|---|
| SHA-256 | `7f758dd54c10e678c40fc022fa61f8ea4dd9780070c3b1f30b8dc5163cfbc7a2` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-28 18:50:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a1ddd54742863ba237b35a94ae97be6` |
| SHA-1 | `8cc036911a626779fa3e7e6ee9b00d9769946f2f` |
| SHA-256 | `7f758dd54c10e678c40fc022fa61f8ea4dd9780070c3b1f30b8dc5163cfbc7a2` |
| SHA3-384 | `c86b70d848c886bf0bebd64a19f40c0cb7fa5c26f20e43d5648264592f3dbe8870cfffdd33b13004b3f4a8b522847a78` |
| TLSH | `T1D4C30845F8508B17C6C612BBFF4E428D7B2A1758E3EE720399256F25378B46B0E3B146` |
| TELFHASH | `t1deb012b3030945dca750629b83fb6a0403dafca123d36c22ca4c6043c16f0c8ac1f060` |
| SSDEEP | `1536:4cimfQEuBkkP4Qm2Kd84VxfNTTjg8DHOgLO1JiDpT8MlTjwyw2NiHk0VWkPMmgmh:PABbAQmG47B/g8DuI5i8ev4i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_7f758dd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f758dd54c10e678c40fc022fa61f8ea4dd9780070c3b1f30b8dc5163cfbc7a2"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-28 18:50:34"
  condition:
    hash.sha256(0, filesize) == "7f758dd54c10e678c40fc022fa61f8ea4dd9780070c3b1f30b8dc5163cfbc7a2"
}
```

### Sample 89: `f80e14057062c1b9`

| Field | Value |
|---|---|
| SHA-256 | `f80e14057062c1b9b24819c8aa524c6fa7991a720bfd15e784d0d21f7a78c2b1` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-28 18:46:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11f63a6bdc877d4d13f3e1ede033c59f` |
| SHA-1 | `14905d456ef4662b56b909b131c11f6e13b5ce93` |
| SHA-256 | `f80e14057062c1b9b24819c8aa524c6fa7991a720bfd15e784d0d21f7a78c2b1` |
| SHA3-384 | `f2336a4ac596518700a42e05c2df51e1d3704f8125b300c9dbfbe39ab3f3bced7ac613c4a9053e852fe88f18212a3fa4` |
| TLSH | `T14BC30745FC509B16C6C611BBFF4E428D7B2A1758E3EE720399256F24378B86B0E3B146` |
| TELFHASH | `t1deb012b3030945dca750629b83fb6a0403dafca123d36c22ca4c6043c16f0c8ac1f060` |
| SSDEEP | `1536:3l9m6vQ0GWkXB272F5Yr4VxhPT8j7r3t6gLOZZzqGuAMlflkKwywla+YTu+xVSLB:GfpR27t41Pwvr3ESGvGpbKf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_f80e1405
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f80e14057062c1b9b24819c8aa524c6fa7991a720bfd15e784d0d21f7a78c2b1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-28 18:46:33"
  condition:
    hash.sha256(0, filesize) == "f80e14057062c1b9b24819c8aa524c6fa7991a720bfd15e784d0d21f7a78c2b1"
}
```

### Sample 90: `839562002478702c`

| Field | Value |
|---|---|
| SHA-256 | `839562002478702c3792ab598e9a85cf400efd128ecc496e3ab540743eabaa8b` |
| Family label | `unknown` |
| File name | `839562002478702c3792ab598e9a85cf400efd128ecc496e3ab540743eabaa8b` |
| File type | `unknown` |
| First seen | `2026-07-28 18:45:19` |
| Reporter | `boehm` |
| Tags | `cowrie, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37c47550d52c28e316b3aa47d87ae7b3` |
| SHA-256 | `839562002478702c3792ab598e9a85cf400efd128ecc496e3ab540743eabaa8b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_83956200
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "839562002478702c3792ab598e9a85cf400efd128ecc496e3ab540743eabaa8b"
    family = "unknown"
    file_name = "839562002478702c3792ab598e9a85cf400efd128ecc496e3ab540743eabaa8b"
    file_type = "unknown"
    first_seen = "2026-07-28 18:45:19"
  condition:
    hash.sha256(0, filesize) == "839562002478702c3792ab598e9a85cf400efd128ecc496e3ab540743eabaa8b"
}
```

### Sample 91: `fba2efd8f909afa2`

| Field | Value |
|---|---|
| SHA-256 | `fba2efd8f909afa2e76f9cbaf6dfd19487682458ee90126b06e4889feeb44592` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-28 18:41:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4347bfbe25d3c5410d3cf3c4b6684024` |
| SHA-1 | `8da40e299659dfa715a813ba6d30fae0b39552df` |
| SHA-256 | `fba2efd8f909afa2e76f9cbaf6dfd19487682458ee90126b06e4889feeb44592` |
| SHA3-384 | `2e924560ac4de8ed0c7efce0203ea1dfaaf4d10572498870f5e1d9d6ab798ee9953c8a0d7832c7aeb7b211bf1b79de7f` |
| TLSH | `T1C4E30949F8519F23C6C615BBFF4E828C772617A8D3EE72039D156F25368B85B0E3A142` |
| TELFHASH | `t135d01231c70344e581835911422c019715fd305e59a1344696fd6f5595e77c1759a033` |
| SSDEEP | `3072:xvui5u2Swe4VQn04BCfTjmtkz8/nuvhE:xvuWwow04BsTjmU82vh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_fba2efd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fba2efd8f909afa2e76f9cbaf6dfd19487682458ee90126b06e4889feeb44592"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-28 18:41:32"
  condition:
    hash.sha256(0, filesize) == "fba2efd8f909afa2e76f9cbaf6dfd19487682458ee90126b06e4889feeb44592"
}
```

### Sample 92: `c21959d86c4bc6db`

| Field | Value |
|---|---|
| SHA-256 | `c21959d86c4bc6dbb47a02fb397f1180b5cfc1ca40519d708f1cbef5561faa3e` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-28 18:39:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61bc180ce970b2604676a24b9ecc0595` |
| SHA-1 | `1ee8052a83c574079b2210e63c52b295f611a25e` |
| SHA-256 | `c21959d86c4bc6dbb47a02fb397f1180b5cfc1ca40519d708f1cbef5561faa3e` |
| SHA3-384 | `5d6e2292eeb94111266b02e26a5f2fac05a60792d361c8b16bb9f23e19c601b6e31f3a5f377db24d51052f7ce5af7e95` |
| TLSH | `T1BFA3F65AF9819B11D4D525BEFE0F818D33235BACE3EF7212AD145B2537CA92B0E7A101` |
| TELFHASH | `t138f097f69b6916ec13e2600442ef33224b60f8920e01383b51dc9e5a80a2f0af718416` |
| SSDEEP | `3072:rnMfSQ+uEsoLsDRGYNlaseSN/UoCffwdvSaMkLPenboQ:rnMfz+JLsNG2laseSN/VCHwEaM0PioQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_c21959d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c21959d86c4bc6dbb47a02fb397f1180b5cfc1ca40519d708f1cbef5561faa3e"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-28 18:39:31"
  condition:
    hash.sha256(0, filesize) == "c21959d86c4bc6dbb47a02fb397f1180b5cfc1ca40519d708f1cbef5561faa3e"
}
```

### Sample 93: `facb03a4bb57c093`

| Field | Value |
|---|---|
| SHA-256 | `facb03a4bb57c0935aa23e44d0400648abb3299d8799421d3f6ea90d8be07e14` |
| Family label | `unknown` |
| File name | `don12089.hta` |
| File type | `hta` |
| First seen | `2026-07-28 18:28:33` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcdf3489e52fd46318c6542acb539113` |
| SHA-1 | `6812d14be2344c3d191c7220ba0c5bdf5117a436` |
| SHA-256 | `facb03a4bb57c0935aa23e44d0400648abb3299d8799421d3f6ea90d8be07e14` |
| SHA3-384 | `bd90bb8eea892a880515d4e881fac3faf729d06b946d80ce61310d111e1b9ea0ae97ff7c75236d55ca96a7ed873228bb` |
| TLSH | `T1F93209CCFEE16270F31303CE37AB2826122461D72008C5C5FA4D9DE57F467D98627A5A` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxz25JYb55qa5HdrI74bthOO:sXX+/DV7k/325WHqur84bTOO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_facb03a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "facb03a4bb57c0935aa23e44d0400648abb3299d8799421d3f6ea90d8be07e14"
    family = "unknown"
    file_name = "don12089.hta"
    file_type = "hta"
    first_seen = "2026-07-28 18:28:33"
  condition:
    hash.sha256(0, filesize) == "facb03a4bb57c0935aa23e44d0400648abb3299d8799421d3f6ea90d8be07e14"
}
```

### Sample 94: `885e45a141aaba36`

| Field | Value |
|---|---|
| SHA-256 | `885e45a141aaba366ed919fae0aef40f465a1703fe8d657b12d3b3acd70bb62a` |
| Family label | `unknown` |
| File name | `images_20260727_230703.zip` |
| File type | `zip` |
| First seen | `2026-07-28 18:27:20` |
| Reporter | `k3dg3` |
| Tags | `TonRAT, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb37efba5d716335100469b2bd1602f0` |
| SHA-1 | `ebdc8ad3b579d4e17e0b849616451cb4b4c40e9c` |
| SHA-256 | `885e45a141aaba366ed919fae0aef40f465a1703fe8d657b12d3b3acd70bb62a` |
| SHA3-384 | `9f445e36116e3718c84d3b007e71ffba759238219c14167cda3c2f35bf5797678efc8cbe444d9c677034af70d9868673` |
| TLSH | `T1AB02BF8086B198FF9BBB1C313F63ED97A5AD61BDDC0266D686120499324A6434FC13E0` |
| SSDEEP | `192:Gtm1BsS7dSHVCTuvgL0E0/dhS7xKU9fqKxBgliMs/PSI:xsS7dSVxoV4PS739fqKx/XSI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_885e45a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "885e45a141aaba366ed919fae0aef40f465a1703fe8d657b12d3b3acd70bb62a"
    family = "unknown"
    file_name = "images_20260727_230703.zip"
    file_type = "zip"
    first_seen = "2026-07-28 18:27:20"
  condition:
    hash.sha256(0, filesize) == "885e45a141aaba366ed919fae0aef40f465a1703fe8d657b12d3b3acd70bb62a"
}
```

### Sample 95: `59d7d3a604e5c3a9`

| Field | Value |
|---|---|
| SHA-256 | `59d7d3a604e5c3a999f01a662faab73a65f036c2e36f7e10c58c8ccd76967861` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-28 18:26:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `767e17fdb97580979e56222dc4ecd0e0` |
| SHA-1 | `d7457b85642b99ac3c300f43409aad1a0aa5bb5f` |
| SHA-256 | `59d7d3a604e5c3a999f01a662faab73a65f036c2e36f7e10c58c8ccd76967861` |
| SHA3-384 | `b18e0300b489525dab512d5821bc70f1266ca5b66b3c26a5d15d21f9b379d161af67d34c31244118571d099130a58fea` |
| TLSH | `T14A14D81AAF510EFBD8ABCD3701E90B4639CC644722A43B753574D528F64A94F4AE3CB8` |
| SSDEEP | `3072:Y/qYyOcQS9ijdHnBBtlYAZ5Vyt8KnuWMeU:YIObS9iNnXz3kQWMe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_59d7d3a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59d7d3a604e5c3a999f01a662faab73a65f036c2e36f7e10c58c8ccd76967861"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-28 18:26:43"
  condition:
    hash.sha256(0, filesize) == "59d7d3a604e5c3a999f01a662faab73a65f036c2e36f7e10c58c8ccd76967861"
}
```

### Sample 96: `f88d9094a90f7000`

| Field | Value |
|---|---|
| SHA-256 | `f88d9094a90f7000a3fb2cd7c981e03357ce2b39df9de5ee1d0742e619e3860f` |
| Family label | `unknown` |
| File name | `Bank account details.vbs` |
| File type | `vbs` |
| First seen | `2026-07-28 18:17:37` |
| Reporter | `James_inthe_box` |
| Tags | `exe, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ec5a4d805472352a10492d311a80fa7` |
| SHA-1 | `da190ccb0e6cdb6b55f40532a0ee7064d31ba760` |
| SHA-256 | `f88d9094a90f7000a3fb2cd7c981e03357ce2b39df9de5ee1d0742e619e3860f` |
| SHA3-384 | `a89f92a7db40f3e528a7a603b532f250035bc0b1cdfd4db3c84cc978e6803ebc110fb707041867c31e3b71c661582e39` |
| TLSH | `T171469F606E5859F5EF8C690E90AEAF1D83F042176A33706BFB41DF05BDDA241864B21F` |
| SSDEEP | `24576:QYuC2NrO/LXTGqatNo3sk/mUjIo/f8YpQneRZQ5msYFFXNBYWuXT1I365ZaL47Hn:75J0r+D93O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_f88d9094
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f88d9094a90f7000a3fb2cd7c981e03357ce2b39df9de5ee1d0742e619e3860f"
    family = "unknown"
    file_name = "Bank account details.vbs"
    file_type = "vbs"
    first_seen = "2026-07-28 18:17:37"
  condition:
    hash.sha256(0, filesize) == "f88d9094a90f7000a3fb2cd7c981e03357ce2b39df9de5ee1d0742e619e3860f"
}
```

### Sample 97: `376968a612e976c2`

| Field | Value |
|---|---|
| SHA-256 | `376968a612e976c22025dc552cf79c6eda5af8a82136fe2dbff48fd72afaacaa` |
| Family label | `WannaCry` |
| File name | `376968a612e976c22025dc552cf79c6eda5af8a82136fe2dbff48fd72afaacaa` |
| File type | `exe` |
| First seen | `2026-07-28 18:15:21` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d017feba12f5960520155ba240beb093` |
| SHA-1 | `7ce58221e01efa4d0f3cb605530e295e62f1e662` |
| SHA-256 | `376968a612e976c22025dc552cf79c6eda5af8a82136fe2dbff48fd72afaacaa` |
| SHA3-384 | `b09f86b4bcc7430710f8149836c4a4966fac51773bfb3db319c7e726d3631d4c0de99c48d54ae15b76212321486a1900` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T147363349317881BCD106197844B78E63F7B37C5A56FEAB0F8B40867A1E63B45BBA4703` |
| SSDEEP | `49152:jnYnjQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAARdhE:DI8qPoBhz1aRxcSUDk36SAEdhE` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_097_376968a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "376968a612e976c22025dc552cf79c6eda5af8a82136fe2dbff48fd72afaacaa"
    family = "WannaCry"
    file_name = "376968a612e976c22025dc552cf79c6eda5af8a82136fe2dbff48fd72afaacaa"
    file_type = "exe"
    first_seen = "2026-07-28 18:15:21"
  condition:
    hash.sha256(0, filesize) == "376968a612e976c22025dc552cf79c6eda5af8a82136fe2dbff48fd72afaacaa"
}
```

### Sample 98: `6289f36d2b3589b2`

| Field | Value |
|---|---|
| SHA-256 | `6289f36d2b3589b2db489a9213ec465a55c77bc469ecee9217ba45e0c47de03b` |
| Family label | `unknown` |
| File name | `don12089.hta` |
| File type | `hta` |
| First seen | `2026-07-28 18:00:34` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9126a8e00fe9a913ca49edb4a3224c82` |
| SHA-1 | `69019f74d621ef7c2c34ab7806bc66c6a103ff24` |
| SHA-256 | `6289f36d2b3589b2db489a9213ec465a55c77bc469ecee9217ba45e0c47de03b` |
| SHA3-384 | `46b18d5f10251be4eb30a2301e8e1df27e352e412728350054950da1ba3b50002edea3466e180cda833c85e70585cbfd` |
| TLSH | `T1FE3209DCFEE56270F31303CE37AB2926122460D72008C5C5FA4D9DE57F467D98627A5A` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxz25JYb55qo5Hd8I74GthOO:sXX+/DV7k/325WjqQ884GTOO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_6289f36d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6289f36d2b3589b2db489a9213ec465a55c77bc469ecee9217ba45e0c47de03b"
    family = "unknown"
    file_name = "don12089.hta"
    file_type = "hta"
    first_seen = "2026-07-28 18:00:34"
  condition:
    hash.sha256(0, filesize) == "6289f36d2b3589b2db489a9213ec465a55c77bc469ecee9217ba45e0c47de03b"
}
```

### Sample 99: `8df36a81c2a9ad02`

| Field | Value |
|---|---|
| SHA-256 | `8df36a81c2a9ad02bd7fa3fdc2b9b619cbde32b9b98fadf1595d82b478eaa62a` |
| Family label | `unknown` |
| File name | `Rivex Suite.exe` |
| File type | `exe` |
| First seen | `2026-07-28 17:54:21` |
| Reporter | `JaffaCakes118` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40ad3bd07568c98de1b82466bc3783e0` |
| SHA-1 | `1aa1ecfebe487106c58526ed99c600649c54670b` |
| SHA-256 | `8df36a81c2a9ad02bd7fa3fdc2b9b619cbde32b9b98fadf1595d82b478eaa62a` |
| SHA3-384 | `c2820afbf70957f8994a9758668b1cd660864b28586e33e4cfcf001f9683945ae62746d0b3a2e7de91a7a6e9601c0069` |
| IMPHASH | `0c9aa527f272b1232c87f4113457d246` |
| TLSH | `T11DD733ACD37CA478D465969DCB90D9B3C6E83621AC460DFB01B49BD0FEB0B7A264CD44` |
| SSDEEP | `1572864:ae7I4bOC+PzyConwaxPJr89n5sAfFN5Jl1D:aeyHAVSVJJl1D` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_8df36a81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8df36a81c2a9ad02bd7fa3fdc2b9b619cbde32b9b98fadf1595d82b478eaa62a"
    family = "unknown"
    file_name = "Rivex Suite.exe"
    file_type = "exe"
    first_seen = "2026-07-28 17:54:21"
  condition:
    hash.sha256(0, filesize) == "8df36a81c2a9ad02bd7fa3fdc2b9b619cbde32b9b98fadf1595d82b478eaa62a"
}
```

### Sample 100: `e2285fd2c1e26a1d`

| Field | Value |
|---|---|
| SHA-256 | `e2285fd2c1e26a1d394c23a73756f71540e2b9d78486c9f4f67d1fe3a370500e` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-28 17:52:33` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2904c0f521b413fec9903435f6b5e3b6` |
| SHA-1 | `fed5adea5763161422d144116e8d2c3e31bd68a6` |
| SHA-256 | `e2285fd2c1e26a1d394c23a73756f71540e2b9d78486c9f4f67d1fe3a370500e` |
| SHA3-384 | `84e58a79e66bb8004ec362667d58c96992dbb89ce00a29ed1d6d437596b04e08b68e3751ba08d30e4e7540d03a5b43ac` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1DCE633083AE122EDE6B3503CC8F11956F6B674A50730C59B4BA8C3A5BE531D1493EBA7` |
| SSDEEP | `393216:Q2vBe9TNkQm5yP7eKiMYxRG3+FjZSXMCHWUjX8cuI3/PGTAI:/JQNk1wTeJMRktSXMb8XpH/O7` |
| ICON-DHASH | `71f8fcdccce4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_e2285fd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2285fd2c1e26a1d394c23a73756f71540e2b9d78486c9f4f67d1fe3a370500e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 17:52:33"
  condition:
    hash.sha256(0, filesize) == "e2285fd2c1e26a1d394c23a73756f71540e2b9d78486c9f4f67d1fe3a370500e"
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
 * Generated: 2026-07-29T03:44:42.555978+00:00
 */

rule MalwareBazaar_unknown_001_9a5f3061
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a5f306198f54047e7be608395869dc6d6dfc30757a04035c3c422f8c1a3495d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 03:41:25"
  condition:
    hash.sha256(0, filesize) == "9a5f306198f54047e7be608395869dc6d6dfc30757a04035c3c422f8c1a3495d"
}

rule MalwareBazaar_unknown_002_3f091457
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f09145757282e6a59cd69319ac3b9da3265022a1d4f92a1646f8ddbaad89333"
    family = "unknown"
    file_name = "請求書.JS"
    file_type = "js"
    first_seen = "2026-07-29 03:39:55"
  condition:
    hash.sha256(0, filesize) == "3f09145757282e6a59cd69319ac3b9da3265022a1d4f92a1646f8ddbaad89333"
}

rule MalwareBazaar_RemcosRAT_003_4a6450f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a6450f5a3676568e1d3d993d1c6f908af7ca07c41887bf48d1ae9672fc58512"
    family = "RemcosRAT"
    file_name = "7556TH364640.vbs"
    file_type = "vbs"
    first_seen = "2026-07-29 03:06:00"
  condition:
    hash.sha256(0, filesize) == "4a6450f5a3676568e1d3d993d1c6f908af7ca07c41887bf48d1ae9672fc58512"
}

rule MalwareBazaar_unknown_004_44df3b23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44df3b2362cac083812b2069678032b4b2dd91589023f9bae4fbd3746a23b1f9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 02:52:32"
  condition:
    hash.sha256(0, filesize) == "44df3b2362cac083812b2069678032b4b2dd91589023f9bae4fbd3746a23b1f9"
}

rule MalwareBazaar_unknown_005_cf8b604d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf8b604d9e3f1dc4470ad1e5cdf8922a3a84021b08ee8b0700b76ea63e0781fb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 02:52:24"
  condition:
    hash.sha256(0, filesize) == "cf8b604d9e3f1dc4470ad1e5cdf8922a3a84021b08ee8b0700b76ea63e0781fb"
}

rule MalwareBazaar_Mirai_006_6d785f19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d785f191a10799f38e08cfc5563bd559729ec74efe2aa242c4542fd853f90d1"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-29 02:02:52"
  condition:
    hash.sha256(0, filesize) == "6d785f191a10799f38e08cfc5563bd559729ec74efe2aa242c4542fd853f90d1"
}

rule MalwareBazaar_Mirai_007_336ff5d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "336ff5d2c361e594327c54a8a5398bc0255f152d175f99bf3a9efd621c51a3b0"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-29 02:01:07"
  condition:
    hash.sha256(0, filesize) == "336ff5d2c361e594327c54a8a5398bc0255f152d175f99bf3a9efd621c51a3b0"
}

rule MalwareBazaar_Mirai_008_eae10853
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eae10853be098476c31a1cb7d37c3b2dbc7ef80d73ce9d64306962eca8be8cc2"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-29 01:59:30"
  condition:
    hash.sha256(0, filesize) == "eae10853be098476c31a1cb7d37c3b2dbc7ef80d73ce9d64306962eca8be8cc2"
}

rule MalwareBazaar_unknown_009_c7482034
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c74820349ce06caf983178ef5ad7c8748afb1078caa98d66d1bb325a6f99d414"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-29 01:52:31"
  condition:
    hash.sha256(0, filesize) == "c74820349ce06caf983178ef5ad7c8748afb1078caa98d66d1bb325a6f99d414"
}

rule MalwareBazaar_Mirai_010_7d6f5eb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d6f5eb4bc8cdea4b40f7a3f659c50b35020602abdd8e8a2e2fc31732330a92a"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-07-29 01:50:32"
  condition:
    hash.sha256(0, filesize) == "7d6f5eb4bc8cdea4b40f7a3f659c50b35020602abdd8e8a2e2fc31732330a92a"
}

rule MalwareBazaar_unknown_011_96aa9b5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96aa9b5fcc9f02bf0879ae9b1e088b3f8dc978ec323da003b194fb660acd0713"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 01:48:45"
  condition:
    hash.sha256(0, filesize) == "96aa9b5fcc9f02bf0879ae9b1e088b3f8dc978ec323da003b194fb660acd0713"
}

rule MalwareBazaar_AgentTesla_012_9c9dcacd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c9dcacd3a247c7860113f842cf920b8cfa205431c5f1e40747c774ba13069d7"
    family = "AgentTesla"
    file_name = "Revised PI.js"
    file_type = "js"
    first_seen = "2026-07-29 01:37:26"
  condition:
    hash.sha256(0, filesize) == "9c9dcacd3a247c7860113f842cf920b8cfa205431c5f1e40747c774ba13069d7"
}

rule MalwareBazaar_unknown_013_441cb017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "441cb0179c91c4c36cbd05b75c6b9b8bd4a668518bceb7ba028a0b077d2a14eb"
    family = "unknown"
    file_name = "Installer.msi"
    file_type = "msi"
    first_seen = "2026-07-29 01:35:35"
  condition:
    hash.sha256(0, filesize) == "441cb0179c91c4c36cbd05b75c6b9b8bd4a668518bceb7ba028a0b077d2a14eb"
}

rule MalwareBazaar_Mirai_014_f47db0bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f47db0bc0f9accb6cf4c033d81ceb1f79065c54616f90df4647ec0cb2d6f2ac0"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-29 01:34:30"
  condition:
    hash.sha256(0, filesize) == "f47db0bc0f9accb6cf4c033d81ceb1f79065c54616f90df4647ec0cb2d6f2ac0"
}

rule MalwareBazaar_unknown_015_a046184a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a046184ae4efc3f09a283a3c24d1533a191d05dc843c78534c3f129ceaa9946e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-29 01:27:38"
  condition:
    hash.sha256(0, filesize) == "a046184ae4efc3f09a283a3c24d1533a191d05dc843c78534c3f129ceaa9946e"
}

rule MalwareBazaar_Mirai_016_79df12fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79df12fb0a083f52bf77cffe998c9be6e9f588b7f918af11435fc5629c1d82b6"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-29 01:23:33"
  condition:
    hash.sha256(0, filesize) == "79df12fb0a083f52bf77cffe998c9be6e9f588b7f918af11435fc5629c1d82b6"
}

rule MalwareBazaar_unknown_017_af03598b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af03598bef65613ab2c8a64fed066b9fd384d92da2fda23893b80ad5887812dc"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-29 01:09:33"
  condition:
    hash.sha256(0, filesize) == "af03598bef65613ab2c8a64fed066b9fd384d92da2fda23893b80ad5887812dc"
}

rule MalwareBazaar_Mirai_018_f2b62856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b628567c9194272993484fc7b706d0ebf036e30fddab42cf0ef95310782b17"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-29 01:05:38"
  condition:
    hash.sha256(0, filesize) == "f2b628567c9194272993484fc7b706d0ebf036e30fddab42cf0ef95310782b17"
}

rule MalwareBazaar_CoinMiner_019_30cf8b82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30cf8b82a53fff20b564597e56123ddeb16a87441a8b94f621e52c3213aeaa2c"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 01:00:20"
  condition:
    hash.sha256(0, filesize) == "30cf8b82a53fff20b564597e56123ddeb16a87441a8b94f621e52c3213aeaa2c"
}

rule MalwareBazaar_unknown_020_3788186a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3788186a5d8e95fdcd9f6386bf85939b865cdd50c2ea28708e673af164aa61ee"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-29 00:57:00"
  condition:
    hash.sha256(0, filesize) == "3788186a5d8e95fdcd9f6386bf85939b865cdd50c2ea28708e673af164aa61ee"
}

rule MalwareBazaar_Mirai_021_b8ba5580
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8ba5580699a6e79742e679b4f8bc293fa903e31410a4a2bad0271731bb3c887"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-29 00:56:59"
  condition:
    hash.sha256(0, filesize) == "b8ba5580699a6e79742e679b4f8bc293fa903e31410a4a2bad0271731bb3c887"
}

rule MalwareBazaar_unknown_022_46eb8bc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46eb8bc5b1f257520507bb81b2d010ea9d5a56b1843c0168953f3662b53d7a15"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 00:52:32"
  condition:
    hash.sha256(0, filesize) == "46eb8bc5b1f257520507bb81b2d010ea9d5a56b1843c0168953f3662b53d7a15"
}

rule MalwareBazaar_unknown_023_403cf85e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "403cf85efeba8cc0e48dcb4fb7b22fa830426d4ac26d613d1e637ef64009581c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-29 00:52:29"
  condition:
    hash.sha256(0, filesize) == "403cf85efeba8cc0e48dcb4fb7b22fa830426d4ac26d613d1e637ef64009581c"
}

rule MalwareBazaar_Mirai_024_e2f44b25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2f44b25a44109cea9ed49bb14fd4038da41912a75ccd2496194359af0eb1b41"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-29 00:50:55"
  condition:
    hash.sha256(0, filesize) == "e2f44b25a44109cea9ed49bb14fd4038da41912a75ccd2496194359af0eb1b41"
}

rule MalwareBazaar_unknown_025_92d27e98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92d27e98374b36575b4c12c8ab050c55befef8a27401a97dd2493d40469981fd"
    family = "unknown"
    file_name = "MV_CHRYSANTHI_S_VSL_DESCRIPTIONpdf.js"
    file_type = "js"
    first_seen = "2026-07-29 00:46:33"
  condition:
    hash.sha256(0, filesize) == "92d27e98374b36575b4c12c8ab050c55befef8a27401a97dd2493d40469981fd"
}

rule MalwareBazaar_Mirai_026_777e17fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "777e17fa8a709873f33cdbf7793948ae2f1c84dd7524c2f1fd911d4c14c372cd"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-29 00:44:54"
  condition:
    hash.sha256(0, filesize) == "777e17fa8a709873f33cdbf7793948ae2f1c84dd7524c2f1fd911d4c14c372cd"
}

rule MalwareBazaar_Mirai_027_9b5a9954
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b5a9954e031bf017324e3cbe578cb7f0148d428ee0172003846bc9486543aa4"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-29 00:40:27"
  condition:
    hash.sha256(0, filesize) == "9b5a9954e031bf017324e3cbe578cb7f0148d428ee0172003846bc9486543aa4"
}

rule MalwareBazaar_unknown_028_543dcff1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "543dcff189a5f2fa7beeb6863e78edd31d74226196687185ad3e655c3ea034de"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 00:36:07"
  condition:
    hash.sha256(0, filesize) == "543dcff189a5f2fa7beeb6863e78edd31d74226196687185ad3e655c3ea034de"
}

rule MalwareBazaar_Mirai_029_41c0e8e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41c0e8e47dfa4844066f4b76f2fe979694320bce1c4f7a9bb5e20a07b618b98c"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-29 00:29:31"
  condition:
    hash.sha256(0, filesize) == "41c0e8e47dfa4844066f4b76f2fe979694320bce1c4f7a9bb5e20a07b618b98c"
}

rule MalwareBazaar_Mirai_030_c4e65979
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4e659790c6a66c5ffc8a091edc4ea823258a6c684d8e50d147371e88d8b5775"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-29 00:25:41"
  condition:
    hash.sha256(0, filesize) == "c4e659790c6a66c5ffc8a091edc4ea823258a6c684d8e50d147371e88d8b5775"
}

rule MalwareBazaar_Mirai_031_ea1da54f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea1da54f1c5b56aeed6fb6d138027f295c54713205b24d10371e8f0f42326ff1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-29 00:23:31"
  condition:
    hash.sha256(0, filesize) == "ea1da54f1c5b56aeed6fb6d138027f295c54713205b24d10371e8f0f42326ff1"
}

rule MalwareBazaar_unknown_032_6c37739a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c37739ac0fa9f67869f6c1ecdc939d5b05ad783b85d12f661c432f528ba7389"
    family = "unknown"
    file_name = "setting.xml"
    file_type = "unknown"
    first_seen = "2026-07-29 00:23:30"
  condition:
    hash.sha256(0, filesize) == "6c37739ac0fa9f67869f6c1ecdc939d5b05ad783b85d12f661c432f528ba7389"
}

rule MalwareBazaar_Phorpiex_033_ab074ae1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab074ae168e50392c6981f6bf426900642c684b13f72b4de681e0b9b4cd1a55d"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 00:11:54"
  condition:
    hash.sha256(0, filesize) == "ab074ae168e50392c6981f6bf426900642c684b13f72b4de681e0b9b4cd1a55d"
}

rule MalwareBazaar_Phorpiex_034_52d4cc21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52d4cc210d5031b02c2e06f3978ec2b042e69946995381d4dfc999f57f0f0887"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 00:03:25"
  condition:
    hash.sha256(0, filesize) == "52d4cc210d5031b02c2e06f3978ec2b042e69946995381d4dfc999f57f0f0887"
}

rule MalwareBazaar_Phorpiex_035_30793394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30793394a8638778432c95d8c121b00f7a4c64226588d1a5d2538bd62f3b187b"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 00:01:42"
  condition:
    hash.sha256(0, filesize) == "30793394a8638778432c95d8c121b00f7a4c64226588d1a5d2538bd62f3b187b"
}

rule MalwareBazaar_unknown_036_d273b394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d273b3948f88184ed005c3947fa2a4021e8e6e0c8a91bbe05d43693ede8a4023"
    family = "unknown"
    file_name = "d273b3948f88184ed005c3947fa2a4021e8e6e0c8a91bbe05d43693ede8a4023"
    file_type = "unknown"
    first_seen = "2026-07-29 00:00:12"
  condition:
    hash.sha256(0, filesize) == "d273b3948f88184ed005c3947fa2a4021e8e6e0c8a91bbe05d43693ede8a4023"
}

rule MalwareBazaar_unknown_037_5180b1ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5180b1ff84229f3034fec1de2534600cb07999a71bff2bf6319199a38320a187"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 23:52:34"
  condition:
    hash.sha256(0, filesize) == "5180b1ff84229f3034fec1de2534600cb07999a71bff2bf6319199a38320a187"
}

rule MalwareBazaar_Phorpiex_038_84b4c113
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84b4c113491f67bf4a0c16629f003325575dd34de7120b4f94541544a1498da0"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 23:35:08"
  condition:
    hash.sha256(0, filesize) == "84b4c113491f67bf4a0c16629f003325575dd34de7120b4f94541544a1498da0"
}

rule MalwareBazaar_unknown_039_21bf44a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471"
    family = "unknown"
    file_name = "yea8hw1uN1NGD0za.exe"
    file_type = "exe"
    first_seen = "2026-07-28 23:03:47"
  condition:
    hash.sha256(0, filesize) == "21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471"
}

rule MalwareBazaar_unknown_040_045ada42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "045ada423b20079a8d1175a47077c1933b06a7e7963eab4dff8d4bb11702c2a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 23:00:35"
  condition:
    hash.sha256(0, filesize) == "045ada423b20079a8d1175a47077c1933b06a7e7963eab4dff8d4bb11702c2a4"
}

rule MalwareBazaar_unknown_041_1441e39c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1441e39c7dd359145a88309bcf004282ce178df47635b5be6b48dd0e2ccb58a0"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 22:52:31"
  condition:
    hash.sha256(0, filesize) == "1441e39c7dd359145a88309bcf004282ce178df47635b5be6b48dd0e2ccb58a0"
}

rule MalwareBazaar_unknown_042_0663b7b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0663b7b3bc56e8c2554fdb91b92d3ed648fb3cc45dde224eb869f8222ce795b0"
    family = "unknown"
    file_name = "0663b7b3bc56e8c2554fdb91b92d3ed648fb3cc45dde224eb869f8222ce795b0"
    file_type = "unknown"
    first_seen = "2026-07-28 22:30:32"
  condition:
    hash.sha256(0, filesize) == "0663b7b3bc56e8c2554fdb91b92d3ed648fb3cc45dde224eb869f8222ce795b0"
}

rule MalwareBazaar_unknown_043_27c74bd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27c74bd229840f70bb35cf28c00756d6fda16b0371789df00dd718c901041131"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 22:07:13"
  condition:
    hash.sha256(0, filesize) == "27c74bd229840f70bb35cf28c00756d6fda16b0371789df00dd718c901041131"
}

rule MalwareBazaar_unknown_044_44c62e46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44c62e465a3ad8c8fe0f851466427f132722d21c416220c37f1c87a95ecd45ae"
    family = "unknown"
    file_name = "44c62e465a3ad8c8fe0f851466427f132722d21c416220c37f1c87a95ecd45ae"
    file_type = "elf"
    first_seen = "2026-07-28 22:03:18"
  condition:
    hash.sha256(0, filesize) == "44c62e465a3ad8c8fe0f851466427f132722d21c416220c37f1c87a95ecd45ae"
}

rule MalwareBazaar_unknown_045_362d59ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "362d59aeb45ccaa8f46889a6760d9fdd4bf1a1849548483a4ed164d232458868"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 21:52:30"
  condition:
    hash.sha256(0, filesize) == "362d59aeb45ccaa8f46889a6760d9fdd4bf1a1849548483a4ed164d232458868"
}

rule MalwareBazaar_CoinMiner_046_460210f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "460210f3fd4047499e12f4e4fcbbf556f2a1957f1ef276238aaa152554a02b37"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 21:25:21"
  condition:
    hash.sha256(0, filesize) == "460210f3fd4047499e12f4e4fcbbf556f2a1957f1ef276238aaa152554a02b37"
}

rule MalwareBazaar_unknown_047_4fc548d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fc548d4267d30acd658a3a43e30b4924dade9371cf6448cb1ae9e374f7dd69a"
    family = "unknown"
    file_name = "communigatepro.tar"
    file_type = "tar"
    first_seen = "2026-07-28 21:12:11"
  condition:
    hash.sha256(0, filesize) == "4fc548d4267d30acd658a3a43e30b4924dade9371cf6448cb1ae9e374f7dd69a"
}

rule MalwareBazaar_unknown_048_a8d04c3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8d04c3d4a97c48d33d9e14009bb3765f22242d51d9a6c9cabdaaa0bb7b22270"
    family = "unknown"
    file_name = "CGP_Заполненный_опросный_лист_по_внедрению_CommuniGate_Pro_Деловые_Линии_2026.zip"
    file_type = "zip"
    first_seen = "2026-07-28 21:09:35"
  condition:
    hash.sha256(0, filesize) == "a8d04c3d4a97c48d33d9e14009bb3765f22242d51d9a6c9cabdaaa0bb7b22270"
}

rule MalwareBazaar_Mirai_049_8ac348ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ac348ba6ce78dc9e0003c0568be8341e736563504c1956ad9b30d556b564070"
    family = "Mirai"
    file_name = "qme1"
    file_type = "elf"
    first_seen = "2026-07-28 21:09:32"
  condition:
    hash.sha256(0, filesize) == "8ac348ba6ce78dc9e0003c0568be8341e736563504c1956ad9b30d556b564070"
}

rule MalwareBazaar_Mirai_050_00bd53b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00bd53b28e21671f2bbbe4aff588c4ce7a41f357bb69c920f3b8227cd27d24cf"
    family = "Mirai"
    file_name = "5FF"
    file_type = "elf"
    first_seen = "2026-07-28 21:09:31"
  condition:
    hash.sha256(0, filesize) == "00bd53b28e21671f2bbbe4aff588c4ce7a41f357bb69c920f3b8227cd27d24cf"
}

rule MalwareBazaar_WSHRAT_051_f53377f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f53377f1c4282703ee09bb8123cc93932f5eb282936551b1379ba91e8df1228a"
    family = "WSHRAT"
    file_name = "ORDER-270728-200878.PDF..vbs"
    file_type = "vbs"
    first_seen = "2026-07-28 21:05:08"
  condition:
    hash.sha256(0, filesize) == "f53377f1c4282703ee09bb8123cc93932f5eb282936551b1379ba91e8df1228a"
}

rule MalwareBazaar_njrat_052_e95766d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e95766d2d9dcc598cada3c33133935fda7d54d245d8a46fc05be47986e036fff"
    family = "njrat"
    file_name = "CEE0E495ADC06BBAC4BE33544BD393CA.exe"
    file_type = "exe"
    first_seen = "2026-07-28 21:05:05"
  condition:
    hash.sha256(0, filesize) == "e95766d2d9dcc598cada3c33133935fda7d54d245d8a46fc05be47986e036fff"
}

rule MalwareBazaar_unknown_053_03dfc82a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03dfc82a8c47cd17e2c443d5121b5a19c3355afd69ed08dee1210250f628282f"
    family = "unknown"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-07-28 20:52:41"
  condition:
    hash.sha256(0, filesize) == "03dfc82a8c47cd17e2c443d5121b5a19c3355afd69ed08dee1210250f628282f"
}

rule MalwareBazaar_unknown_054_33180419
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33180419d2e3b1763ef0e67e1a98d9964c16efa97ea164242d098d8d1eaf172a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 20:52:29"
  condition:
    hash.sha256(0, filesize) == "33180419d2e3b1763ef0e67e1a98d9964c16efa97ea164242d098d8d1eaf172a"
}

rule MalwareBazaar_Mirai_055_0c77c688
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c77c688c8e96f308e67772abeb7de9bfed680d186301daf720338fc7780ea6a"
    family = "Mirai"
    file_name = "LFt3"
    file_type = "elf"
    first_seen = "2026-07-28 20:44:29"
  condition:
    hash.sha256(0, filesize) == "0c77c688c8e96f308e67772abeb7de9bfed680d186301daf720338fc7780ea6a"
}

rule MalwareBazaar_Formbook_056_6c1abc6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c1abc6c731f272e22deabeeb92b6378fdc32507a1fac93271b45a2a577aa88c"
    family = "Formbook"
    file_name = "Quotation.JS"
    file_type = "js"
    first_seen = "2026-07-28 20:44:18"
  condition:
    hash.sha256(0, filesize) == "6c1abc6c731f272e22deabeeb92b6378fdc32507a1fac93271b45a2a577aa88c"
}

rule MalwareBazaar_unknown_057_6436c0d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6436c0d5db9dfda7cb951774c4c466c47c5c0df446178b229e75c58139161a81"
    family = "unknown"
    file_name = "9ff72d21-8502-4a6a-b740-c41133dd8265"
    file_type = "unknown"
    first_seen = "2026-07-28 20:43:45"
  condition:
    hash.sha256(0, filesize) == "6436c0d5db9dfda7cb951774c4c466c47c5c0df446178b229e75c58139161a81"
}

rule MalwareBazaar_Mirai_058_194b0227
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "194b02279c7aa385261c8badb611011aed5677311dbdb96d26e7b5951205d354"
    family = "Mirai"
    file_name = "Lrtt"
    file_type = "elf"
    first_seen = "2026-07-28 20:42:56"
  condition:
    hash.sha256(0, filesize) == "194b02279c7aa385261c8badb611011aed5677311dbdb96d26e7b5951205d354"
}

rule MalwareBazaar_Mirai_059_77755cc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77755cc0490521af6f766826172706f091c6963af70e5e23cecd9567a72cd336"
    family = "Mirai"
    file_name = "LrHq"
    file_type = "elf"
    first_seen = "2026-07-28 20:42:55"
  condition:
    hash.sha256(0, filesize) == "77755cc0490521af6f766826172706f091c6963af70e5e23cecd9567a72cd336"
}

rule MalwareBazaar_RustyStealer_060_0605015c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0605015c8428fb4efc98e0abd8af027c7a01f2e87471dbc7e4389a3c6e5844c4"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 20:38:37"
  condition:
    hash.sha256(0, filesize) == "0605015c8428fb4efc98e0abd8af027c7a01f2e87471dbc7e4389a3c6e5844c4"
}

rule MalwareBazaar_unknown_061_ad87c521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad87c521a094b77faf0cb2c0da769b619dbdb567039eee489fcfdb13a23ce124"
    family = "unknown"
    file_name = "kol.js"
    file_type = "js"
    first_seen = "2026-07-28 20:33:58"
  condition:
    hash.sha256(0, filesize) == "ad87c521a094b77faf0cb2c0da769b619dbdb567039eee489fcfdb13a23ce124"
}

rule MalwareBazaar_unknown_062_9fba3a68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fba3a68221cc6d7ca5a0f14881e0ce7e1c201009901e715e9f49aa2c5447da1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-28 20:32:30"
  condition:
    hash.sha256(0, filesize) == "9fba3a68221cc6d7ca5a0f14881e0ce7e1c201009901e715e9f49aa2c5447da1"
}

rule MalwareBazaar_unknown_063_ad402539
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad402539ef20003f7fce7cb87a0549f04d78c8c066c26c2cba032ee329705ed2"
    family = "unknown"
    file_name = "Purchase_Order_28_07_2026.js"
    file_type = "js"
    first_seen = "2026-07-28 20:31:26"
  condition:
    hash.sha256(0, filesize) == "ad402539ef20003f7fce7cb87a0549f04d78c8c066c26c2cba032ee329705ed2"
}

rule MalwareBazaar_PythonStealer_064_350e2803
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "350e280370d76945e1b4d460009d97d6976fcc4e33c966d73c78d4b520b50874"
    family = "PythonStealer"
    file_name = "New_Specification_Of_Industrial_Power_Generator_and_Quantities_Needed_For_Each.zip"
    file_type = "zip"
    first_seen = "2026-07-28 20:25:07"
  condition:
    hash.sha256(0, filesize) == "350e280370d76945e1b4d460009d97d6976fcc4e33c966d73c78d4b520b50874"
}

rule MalwareBazaar_unknown_065_7539c486
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7539c48603f670a8a14c59391c1bbc01371635b89ea06f2f68cf273ac709f8bb"
    family = "unknown"
    file_name = "payload(1).exe"
    file_type = "exe"
    first_seen = "2026-07-28 20:21:45"
  condition:
    hash.sha256(0, filesize) == "7539c48603f670a8a14c59391c1bbc01371635b89ea06f2f68cf273ac709f8bb"
}

rule MalwareBazaar_unknown_066_d02fb84c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d02fb84cea88610da9c7d84902c64e2e11d66795ef56ed8a5e4f77d19c294175"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-28 20:20:30"
  condition:
    hash.sha256(0, filesize) == "d02fb84cea88610da9c7d84902c64e2e11d66795ef56ed8a5e4f77d19c294175"
}

rule MalwareBazaar_unknown_067_1a569dd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a569dd1087367b863590e8e1a6e8755a368473d86ebd3213b9be3ed971668e5"
    family = "unknown"
    file_name = "payload.exe"
    file_type = "exe"
    first_seen = "2026-07-28 20:20:28"
  condition:
    hash.sha256(0, filesize) == "1a569dd1087367b863590e8e1a6e8755a368473d86ebd3213b9be3ed971668e5"
}

rule MalwareBazaar_unknown_068_668c0851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668c0851af5a3a1f685f3e632e4cce3f71aed73808deefe4c5b59bf40088d4fa"
    family = "unknown"
    file_name = "version.dll"
    file_type = "exe"
    first_seen = "2026-07-28 20:20:10"
  condition:
    hash.sha256(0, filesize) == "668c0851af5a3a1f685f3e632e4cce3f71aed73808deefe4c5b59bf40088d4fa"
}

rule MalwareBazaar_unknown_069_a1a91d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1a91d9cd396186c4fde28e050f88aa68062b05195aaea091e7b3a1ca7539893"
    family = "unknown"
    file_name = "dropper-msvc-x64-no-bait-noselfdel.exe"
    file_type = "exe"
    first_seen = "2026-07-28 20:19:55"
  condition:
    hash.sha256(0, filesize) == "a1a91d9cd396186c4fde28e050f88aa68062b05195aaea091e7b3a1ca7539893"
}

rule MalwareBazaar_unknown_070_46effa2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46effa2a273d465e4a4bb96c0519ca0b5ac51ff141f8affcf9c9803c1689aa1e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-28 20:17:02"
  condition:
    hash.sha256(0, filesize) == "46effa2a273d465e4a4bb96c0519ca0b5ac51ff141f8affcf9c9803c1689aa1e"
}

rule MalwareBazaar_Mirai_071_beeb2032
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "beeb2032f9a69f24e399a12568a2bbc5d184bb5461264e9ce7abf1298f77d003"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-28 20:13:54"
  condition:
    hash.sha256(0, filesize) == "beeb2032f9a69f24e399a12568a2bbc5d184bb5461264e9ce7abf1298f77d003"
}

rule MalwareBazaar_Mirai_072_4be16b29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4be16b2978b746c0eb0533f91a5de765f783ccd1bfd914deb921e90d7301d2ea"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-28 20:13:53"
  condition:
    hash.sha256(0, filesize) == "4be16b2978b746c0eb0533f91a5de765f783ccd1bfd914deb921e90d7301d2ea"
}

rule MalwareBazaar_Mirai_073_ded67d13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ded67d13db4b33119436c67e94142e5e903ac5c7dbad6e98274914dc0f8d6182"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-28 20:13:51"
  condition:
    hash.sha256(0, filesize) == "ded67d13db4b33119436c67e94142e5e903ac5c7dbad6e98274914dc0f8d6182"
}

rule MalwareBazaar_Mirai_074_64904cd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64904cd80ec7985ef0cefcb50e2c44fb5da42317c856f69b4a11d992f6631a58"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-28 20:02:39"
  condition:
    hash.sha256(0, filesize) == "64904cd80ec7985ef0cefcb50e2c44fb5da42317c856f69b4a11d992f6631a58"
}

rule MalwareBazaar_unknown_075_f4c32b3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4c32b3f9a949e5a17ff0b8ad130ba5ca15e5d9a037c7a97dcc68a6b4c3212f7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 19:52:31"
  condition:
    hash.sha256(0, filesize) == "f4c32b3f9a949e5a17ff0b8ad130ba5ca15e5d9a037c7a97dcc68a6b4c3212f7"
}

rule MalwareBazaar_unknown_076_3d4c5602
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d4c5602c640bf6f7787546e82e65c5436a08f90f19089c4f185e0e12132abcd"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-28 19:42:50"
  condition:
    hash.sha256(0, filesize) == "3d4c5602c640bf6f7787546e82e65c5436a08f90f19089c4f185e0e12132abcd"
}

rule MalwareBazaar_unknown_077_5823135e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5823135e1fae078b8bb4d256f6cb03140f04f4c8293103a5cb08e07535bfae2b"
    family = "unknown"
    file_name = "Notice from Tax Departmen.dmg"
    file_type = "unknown"
    first_seen = "2026-07-28 19:41:12"
  condition:
    hash.sha256(0, filesize) == "5823135e1fae078b8bb4d256f6cb03140f04f4c8293103a5cb08e07535bfae2b"
}

rule MalwareBazaar_unknown_078_606f4256
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "606f4256012f37e7e120966888e6a7bad12abb004e135c4f663bc73e124699ea"
    family = "unknown"
    file_name = "5.msi"
    file_type = "msi"
    first_seen = "2026-07-28 19:36:35"
  condition:
    hash.sha256(0, filesize) == "606f4256012f37e7e120966888e6a7bad12abb004e135c4f663bc73e124699ea"
}

rule MalwareBazaar_unknown_079_30937348
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "309373483b37a15cf1f6372a918418681c4fbc549cc128429c672e8d837dbf88"
    family = "unknown"
    file_name = "OTBank_Payment_28_07_2026_440802.pdf.js"
    file_type = "js"
    first_seen = "2026-07-28 19:32:59"
  condition:
    hash.sha256(0, filesize) == "309373483b37a15cf1f6372a918418681c4fbc549cc128429c672e8d837dbf88"
}

rule MalwareBazaar_Mirai_080_ed714a09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed714a097ff6169e1a9935c9b8b7e09afffc45aab659cac9c3bed8a146f83851"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-28 19:22:32"
  condition:
    hash.sha256(0, filesize) == "ed714a097ff6169e1a9935c9b8b7e09afffc45aab659cac9c3bed8a146f83851"
}

rule MalwareBazaar_WannaCry_081_47f9779b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47f9779b48eeda53a846a2460456c738ad752ad0e02483231d927930f3f37dce"
    family = "WannaCry"
    file_name = "47f9779b48eeda53a846a2460456c738ad752ad0e02483231d927930f3f37dce"
    file_type = "exe"
    first_seen = "2026-07-28 19:15:22"
  condition:
    hash.sha256(0, filesize) == "47f9779b48eeda53a846a2460456c738ad752ad0e02483231d927930f3f37dce"
}

rule MalwareBazaar_Mirai_082_d81fc15c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d81fc15c5209b18130b08a9d7182a78aa3f6184ffb79cabd7dce4cf5a3d3cab4"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-28 19:12:33"
  condition:
    hash.sha256(0, filesize) == "d81fc15c5209b18130b08a9d7182a78aa3f6184ffb79cabd7dce4cf5a3d3cab4"
}

rule MalwareBazaar_Mirai_083_aa64bf14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa64bf1471d43b21cc0b6f761473ed2903439364e5495656b67fb9e747910bb9"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-28 19:06:38"
  condition:
    hash.sha256(0, filesize) == "aa64bf1471d43b21cc0b6f761473ed2903439364e5495656b67fb9e747910bb9"
}

rule MalwareBazaar_unknown_084_5f1225fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f1225fee9a3329606862f1f8b2e4100f06e9b3c874cd319f763dcdd030a650c"
    family = "unknown"
    file_name = "CrossDNS_Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-28 19:01:26"
  condition:
    hash.sha256(0, filesize) == "5f1225fee9a3329606862f1f8b2e4100f06e9b3c874cd319f763dcdd030a650c"
}

rule MalwareBazaar_unknown_085_82fb67cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82fb67cb2438bd0265f4e06f974456a8b212b70d45f8f3fc18e04155fa45791a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 18:55:17"
  condition:
    hash.sha256(0, filesize) == "82fb67cb2438bd0265f4e06f974456a8b212b70d45f8f3fc18e04155fa45791a"
}

rule MalwareBazaar_unknown_086_7f494719
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f4947195d352f01a517e5f472d3ae734d22b1d8a6fc5a69b42e6db42f9a11ef"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-28 18:52:35"
  condition:
    hash.sha256(0, filesize) == "7f4947195d352f01a517e5f472d3ae734d22b1d8a6fc5a69b42e6db42f9a11ef"
}

rule MalwareBazaar_unknown_087_0bdbb0f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bdbb0f2361160d4c5e71ed923fde9e0133ee6927c8a02a3f491cee1b83a1982"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 18:52:32"
  condition:
    hash.sha256(0, filesize) == "0bdbb0f2361160d4c5e71ed923fde9e0133ee6927c8a02a3f491cee1b83a1982"
}

rule MalwareBazaar_Mirai_088_7f758dd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f758dd54c10e678c40fc022fa61f8ea4dd9780070c3b1f30b8dc5163cfbc7a2"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-28 18:50:34"
  condition:
    hash.sha256(0, filesize) == "7f758dd54c10e678c40fc022fa61f8ea4dd9780070c3b1f30b8dc5163cfbc7a2"
}

rule MalwareBazaar_Mirai_089_f80e1405
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f80e14057062c1b9b24819c8aa524c6fa7991a720bfd15e784d0d21f7a78c2b1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-28 18:46:33"
  condition:
    hash.sha256(0, filesize) == "f80e14057062c1b9b24819c8aa524c6fa7991a720bfd15e784d0d21f7a78c2b1"
}

rule MalwareBazaar_unknown_090_83956200
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "839562002478702c3792ab598e9a85cf400efd128ecc496e3ab540743eabaa8b"
    family = "unknown"
    file_name = "839562002478702c3792ab598e9a85cf400efd128ecc496e3ab540743eabaa8b"
    file_type = "unknown"
    first_seen = "2026-07-28 18:45:19"
  condition:
    hash.sha256(0, filesize) == "839562002478702c3792ab598e9a85cf400efd128ecc496e3ab540743eabaa8b"
}

rule MalwareBazaar_Mirai_091_fba2efd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fba2efd8f909afa2e76f9cbaf6dfd19487682458ee90126b06e4889feeb44592"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-28 18:41:32"
  condition:
    hash.sha256(0, filesize) == "fba2efd8f909afa2e76f9cbaf6dfd19487682458ee90126b06e4889feeb44592"
}

rule MalwareBazaar_Mirai_092_c21959d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c21959d86c4bc6dbb47a02fb397f1180b5cfc1ca40519d708f1cbef5561faa3e"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-28 18:39:31"
  condition:
    hash.sha256(0, filesize) == "c21959d86c4bc6dbb47a02fb397f1180b5cfc1ca40519d708f1cbef5561faa3e"
}

rule MalwareBazaar_unknown_093_facb03a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "facb03a4bb57c0935aa23e44d0400648abb3299d8799421d3f6ea90d8be07e14"
    family = "unknown"
    file_name = "don12089.hta"
    file_type = "hta"
    first_seen = "2026-07-28 18:28:33"
  condition:
    hash.sha256(0, filesize) == "facb03a4bb57c0935aa23e44d0400648abb3299d8799421d3f6ea90d8be07e14"
}

rule MalwareBazaar_unknown_094_885e45a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "885e45a141aaba366ed919fae0aef40f465a1703fe8d657b12d3b3acd70bb62a"
    family = "unknown"
    file_name = "images_20260727_230703.zip"
    file_type = "zip"
    first_seen = "2026-07-28 18:27:20"
  condition:
    hash.sha256(0, filesize) == "885e45a141aaba366ed919fae0aef40f465a1703fe8d657b12d3b3acd70bb62a"
}

rule MalwareBazaar_Mirai_095_59d7d3a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59d7d3a604e5c3a999f01a662faab73a65f036c2e36f7e10c58c8ccd76967861"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-28 18:26:43"
  condition:
    hash.sha256(0, filesize) == "59d7d3a604e5c3a999f01a662faab73a65f036c2e36f7e10c58c8ccd76967861"
}

rule MalwareBazaar_unknown_096_f88d9094
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f88d9094a90f7000a3fb2cd7c981e03357ce2b39df9de5ee1d0742e619e3860f"
    family = "unknown"
    file_name = "Bank account details.vbs"
    file_type = "vbs"
    first_seen = "2026-07-28 18:17:37"
  condition:
    hash.sha256(0, filesize) == "f88d9094a90f7000a3fb2cd7c981e03357ce2b39df9de5ee1d0742e619e3860f"
}

rule MalwareBazaar_WannaCry_097_376968a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "376968a612e976c22025dc552cf79c6eda5af8a82136fe2dbff48fd72afaacaa"
    family = "WannaCry"
    file_name = "376968a612e976c22025dc552cf79c6eda5af8a82136fe2dbff48fd72afaacaa"
    file_type = "exe"
    first_seen = "2026-07-28 18:15:21"
  condition:
    hash.sha256(0, filesize) == "376968a612e976c22025dc552cf79c6eda5af8a82136fe2dbff48fd72afaacaa"
}

rule MalwareBazaar_unknown_098_6289f36d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6289f36d2b3589b2db489a9213ec465a55c77bc469ecee9217ba45e0c47de03b"
    family = "unknown"
    file_name = "don12089.hta"
    file_type = "hta"
    first_seen = "2026-07-28 18:00:34"
  condition:
    hash.sha256(0, filesize) == "6289f36d2b3589b2db489a9213ec465a55c77bc469ecee9217ba45e0c47de03b"
}

rule MalwareBazaar_unknown_099_8df36a81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8df36a81c2a9ad02bd7fa3fdc2b9b619cbde32b9b98fadf1595d82b478eaa62a"
    family = "unknown"
    file_name = "Rivex Suite.exe"
    file_type = "exe"
    first_seen = "2026-07-28 17:54:21"
  condition:
    hash.sha256(0, filesize) == "8df36a81c2a9ad02bd7fa3fdc2b9b619cbde32b9b98fadf1595d82b478eaa62a"
}

rule MalwareBazaar_unknown_100_e2285fd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2285fd2c1e26a1d394c23a73756f71540e2b9d78486c9f4f67d1fe3a370500e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 17:52:33"
  condition:
    hash.sha256(0, filesize) == "e2285fd2c1e26a1d394c23a73756f71540e2b9d78486c9f4f67d1fe3a370500e"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

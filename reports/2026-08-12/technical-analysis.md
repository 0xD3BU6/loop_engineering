# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-12

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 660 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 660 |
| Unique family labels | 5 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 61 |
| Mirai | 32 |
| Vidar | 5 |
| WannaCry | 1 |
| SalatStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 49 |
| exe | 43 |
| sh | 5 |
| zip | 2 |
| js | 1 |

## Per-Sample Analysis

### Sample 1: `9ec67d8a8d2e0fe0`

| Field | Value |
|---|---|
| SHA-256 | `9ec67d8a8d2e0fe0b045cdf0ff06c0bf90a01f959c3b945eebd81b8a33f7f837` |
| Family label | `unknown` |
| File name | `boatnet.mpsl` |
| File type | `elf` |
| First seen | `2026-08-12 02:58:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b3f849286d835b8119571625fa2ea74` |
| SHA-1 | `85ffa84f2f9b28c4fce39679248ed285836b31f2` |
| SHA-256 | `9ec67d8a8d2e0fe0b045cdf0ff06c0bf90a01f959c3b945eebd81b8a33f7f837` |
| SHA3-384 | `241fb5a331459155e6c7f0eaf94d06536773bbf36de7649a8ffc8f0bd2eb24de0f3cb88695bad2e78f09f65f46b1972f` |
| TLSH | `T11834D80ABB510FBBD8ABCD3701E81B0628CCA55722A93F357674C528F94A54F4AD3D78` |
| SSDEEP | `6144:r/Z4smCCKpuveHfG/DJKdgcBRY9PH63MAh8SE1o+UJtLdl5:rbO/d6gkRYctLr5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_9ec67d8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ec67d8a8d2e0fe0b045cdf0ff06c0bf90a01f959c3b945eebd81b8a33f7f837"
    family = "unknown"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-12 02:58:38"
  condition:
    hash.sha256(0, filesize) == "9ec67d8a8d2e0fe0b045cdf0ff06c0bf90a01f959c3b945eebd81b8a33f7f837"
}
```

### Sample 2: `a571bd3aed290eb2`

| Field | Value |
|---|---|
| SHA-256 | `a571bd3aed290eb2ed071ed8207456975fa2309a9e179ee57512b5647e0364f9` |
| Family label | `unknown` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-08-12 02:58:35` |
| Reporter | `hexinglarps` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a8dc8b82ea0b3670ae175e34017e7d6` |
| SHA-1 | `3ae39ae197f8d8a6e872fbb163a41a694b40781d` |
| SHA-256 | `a571bd3aed290eb2ed071ed8207456975fa2309a9e179ee57512b5647e0364f9` |
| SHA3-384 | `9f713beb7d72d589215a2d430391c821e4856ad5fe183e52f77b7761e2d7035068729c95116b6dc3a3c9126d98f9113e` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1F45629779E019874E5D9EA38C977410AA678BCAD877433A32EE06DB02F753D18E35B40` |
| SSDEEP | `98304:F625gYq/LElvWsRIXuJsDnZ5vLJH3rZdf7hhmI1PzsF8gk6hl1TaQjqXgWoIP/By:FPjqBjCM1R8b7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_a571bd3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a571bd3aed290eb2ed071ed8207456975fa2309a9e179ee57512b5647e0364f9"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-08-12 02:58:35"
  condition:
    hash.sha256(0, filesize) == "a571bd3aed290eb2ed071ed8207456975fa2309a9e179ee57512b5647e0364f9"
}
```

### Sample 3: `6cc212883df28616`

| Field | Value |
|---|---|
| SHA-256 | `6cc212883df2861669b9b61feeb9b7735fbadc81093f20feea95612375f87d64` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-12 02:57:28` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ba20c44231a7372332801fc0f8f3f80` |
| SHA-1 | `ed3775ed4bb729e88444aab680f63ebb962f16a2` |
| SHA-256 | `6cc212883df2861669b9b61feeb9b7735fbadc81093f20feea95612375f87d64` |
| SHA3-384 | `1a25d53ff0857e80b990f232f278f7c6fb14d0331cb06f8d27905fd7b56b61e6bdc37e5ec9f143837f7be12c7aff32d2` |
| TLSH | `T146D3126AEE48A2C5CDDCCE7C67C7509155B870E3432AA2B4AEE04194CD1704BF97FA39` |
| SSDEEP | `3072:3qVu4HohRQqW6QYG/SPRCLhMCSOn5AHgz7M6W0zCFQ4H2Z:aUv0qSXaRehth5AHgTW0zCFQY2Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_6cc21288
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cc212883df2861669b9b61feeb9b7735fbadc81093f20feea95612375f87d64"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-12 02:57:28"
  condition:
    hash.sha256(0, filesize) == "6cc212883df2861669b9b61feeb9b7735fbadc81093f20feea95612375f87d64"
}
```

### Sample 4: `3364e0bd2291aa6b`

| Field | Value |
|---|---|
| SHA-256 | `3364e0bd2291aa6be29617a98610e8a06752a452c789c5135609f28bcb532e64` |
| Family label | `Mirai` |
| File name | `boatnet.mpsl` |
| File type | `elf` |
| First seen | `2026-08-12 02:57:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07cb2194f5c3f9f6c4cfb40b75cdb854` |
| SHA-1 | `f94f591e062f839331860b971389f05ff9c9e3c3` |
| SHA-256 | `3364e0bd2291aa6be29617a98610e8a06752a452c789c5135609f28bcb532e64` |
| SHA3-384 | `fa5b62dab71f7d1785c95fab24be2eeb7c7686a6af05c1e29ceb9aeedc1666ec8690408fd1221ca79231fdf3d211c913` |
| TLSH | `T1346302E8DB60FBCADE3DBD382CCF9141AA122093B1DF468A076B950CE5EB95533454C8` |
| SSDEEP | `768:u46oEsCvRU0V7bN0QoqGqZtwzQ5vMqTPpRjeGmpSegfKa4wEXeYL35GyN02M9Oge:u5N5BV7bSHqZT3axgioEOYVPN0NW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_3364e0bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3364e0bd2291aa6be29617a98610e8a06752a452c789c5135609f28bcb532e64"
    family = "Mirai"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-12 02:57:27"
  condition:
    hash.sha256(0, filesize) == "3364e0bd2291aa6be29617a98610e8a06752a452c789c5135609f28bcb532e64"
}
```

### Sample 5: `fe1390d20a45bef3`

| Field | Value |
|---|---|
| SHA-256 | `fe1390d20a45bef35ae7129bc34db63e5370dbedf4e239628c5a5112fa14c9e4` |
| Family label | `unknown` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-08-12 02:53:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9dd4b6c0f00c7e5befe8054c1406a47` |
| SHA-1 | `1a84acc03ae61fc3c9b5e79d66edf5fd0a81ba0e` |
| SHA-256 | `fe1390d20a45bef35ae7129bc34db63e5370dbedf4e239628c5a5112fa14c9e4` |
| SHA3-384 | `1dda8020e9aa5845069f56abd83f01058f5e98f1a52c699d7e4d5e2467f7b8d97817fe67da50d6459086b8f9fe78e4db` |
| TLSH | `T149A35CC1F683F1F6FC1251B51027A7339733D839503ADA97C3ADEA26EC126529A1B61C` |
| TELFHASH | `t1515123b71e6a0ce873d09801c31e6be11919e67b14603be704b398b4339b9c141fad39` |
| SSDEEP | `1536:fdk8E8H1RE6PevE1RWFAqVsjUTYVYcK3c/BtoSr5eAWYg:lkXY1BhW2RQsV1K361hb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_fe1390d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe1390d20a45bef35ae7129bc34db63e5370dbedf4e239628c5a5112fa14c9e4"
    family = "unknown"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-08-12 02:53:44"
  condition:
    hash.sha256(0, filesize) == "fe1390d20a45bef35ae7129bc34db63e5370dbedf4e239628c5a5112fa14c9e4"
}
```

### Sample 6: `9ca34a13a9100ca0`

| Field | Value |
|---|---|
| SHA-256 | `9ca34a13a9100ca08c5e4f2c236ab388ed482cc0879a9af52ae28b24b6dea57e` |
| Family label | `Mirai` |
| File name | `boatnet.arc` |
| File type | `elf` |
| First seen | `2026-08-12 02:53:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6238097210a6d8e36336e98eb35014b8` |
| SHA-1 | `43697314e7fb870c5576c1f66d8f751f28de5a4a` |
| SHA-256 | `9ca34a13a9100ca08c5e4f2c236ab388ed482cc0879a9af52ae28b24b6dea57e` |
| SHA3-384 | `3f6bf31002bc4dbf1b1b6ed9be91c918e8e8b944d738c1a06207e889ae9344989bb39ea9899397a7626d15d8e68a6540` |
| TLSH | `T13EE38D6BB30F2055C42206F417CBBF9D2E3312C24E6BD5E76C69267A2AB65DB1801FD1` |
| SSDEEP | `3072:TQAH16WiutGPV25H86PdTfyR9QMgeCfzeN5v7EvNq:cKNAP36lrMQUCfz85wvNq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_9ca34a13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ca34a13a9100ca08c5e4f2c236ab388ed482cc0879a9af52ae28b24b6dea57e"
    family = "Mirai"
    file_name = "boatnet.arc"
    file_type = "elf"
    first_seen = "2026-08-12 02:53:24"
  condition:
    hash.sha256(0, filesize) == "9ca34a13a9100ca08c5e4f2c236ab388ed482cc0879a9af52ae28b24b6dea57e"
}
```

### Sample 7: `68d89ae2eeae9808`

| Field | Value |
|---|---|
| SHA-256 | `68d89ae2eeae98080cf9e643ed5f5827860bc19caac80be924c5b909a979160e` |
| Family label | `unknown` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-08-12 02:53:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `724cb6db067359fd3576665c0b56dfd6` |
| SHA-1 | `ab9274cd755f70f872f34c1c8f5d6bb903042635` |
| SHA-256 | `68d89ae2eeae98080cf9e643ed5f5827860bc19caac80be924c5b909a979160e` |
| SHA3-384 | `115cd421782f88641970b14985c91d4dd79afd60b1f189c74fe4a2d6f12a68682b9611fdda3e807aa93d24dd33638a14` |
| TLSH | `T1A413E05B998BD346D4FD01B1385D7DA92C14D61BACCE03239FD269214CEBF1D2908A5B` |
| SSDEEP | `768:3TVhqZQS0ERZirEQwFjGn9g2IaR7uI/Fx3MlTP+OL5L+nbcuyD7U0/2F:3JhqZr0Sih4l2pR7dX3+54nouy8jF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_68d89ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68d89ae2eeae98080cf9e643ed5f5827860bc19caac80be924c5b909a979160e"
    family = "unknown"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-08-12 02:53:22"
  condition:
    hash.sha256(0, filesize) == "68d89ae2eeae98080cf9e643ed5f5827860bc19caac80be924c5b909a979160e"
}
```

### Sample 8: `d2ae3982f07f8925`

| Field | Value |
|---|---|
| SHA-256 | `d2ae3982f07f89253b21d45321e97f57b4b81c78164c2504b2578958ca186362` |
| Family label | `unknown` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-08-12 02:53:21` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a89928369ce1200e8133f16232b180d8` |
| SHA-1 | `c5a4bf59b653f0cb871956fe46ff074f3c08fe6e` |
| SHA-256 | `d2ae3982f07f89253b21d45321e97f57b4b81c78164c2504b2578958ca186362` |
| SHA3-384 | `36dec179ddd63dcc470dc6c7f3b11ffaafbd8aeab9d1fd0de6a9fb82dc5171c1b7b70ac428190ff8d8c741cf0fb4da6a` |
| TLSH | `T117C31223CABD5F2393E019603D9B46028133B6A4A0EFE51E54314FD827C50A93EE697F` |
| SSDEEP | `3072:N1bXPQy+JVYzbc60HdMWIFGxqKNOfisC+HrX5EvHqmm0VutT:HPQygVd60HKow/C4KvH2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_d2ae3982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2ae3982f07f89253b21d45321e97f57b4b81c78164c2504b2578958ca186362"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-08-12 02:53:21"
  condition:
    hash.sha256(0, filesize) == "d2ae3982f07f89253b21d45321e97f57b4b81c78164c2504b2578958ca186362"
}
```

### Sample 9: `c391b6a62a440019`

| Field | Value |
|---|---|
| SHA-256 | `c391b6a62a44001982eb46e69da8d969a9de4e2164e67964bd99f5783e2381c8` |
| Family label | `Mirai` |
| File name | `boatnet.sh4` |
| File type | `elf` |
| First seen | `2026-08-12 02:53:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00e6114eeb482411970568fda986deb5` |
| SHA-1 | `c59484ac4afe3f01ef208d07fc675c0450c226f3` |
| SHA-256 | `c391b6a62a44001982eb46e69da8d969a9de4e2164e67964bd99f5783e2381c8` |
| SHA3-384 | `756f815b856a8c8356bab95c2a0936f7faa6044d76eda0fac17f15c27b29eb5709f8a8d255b745c1b22de9d26b883aef` |
| TLSH | `T1ABE37B72E8262E68C165E474B034BF795F6395D582835FAB65B7C2B04043DCDF908BB8` |
| SSDEEP | `3072:zue03q0tp+vXeYPM/X+e6acKomTWXLmsYH8vm:zVAHX/X+YRCXtYcvm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_c391b6a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c391b6a62a44001982eb46e69da8d969a9de4e2164e67964bd99f5783e2381c8"
    family = "Mirai"
    file_name = "boatnet.sh4"
    file_type = "elf"
    first_seen = "2026-08-12 02:53:20"
  condition:
    hash.sha256(0, filesize) == "c391b6a62a44001982eb46e69da8d969a9de4e2164e67964bd99f5783e2381c8"
}
```

### Sample 10: `dff2505a7a6a1462`

| Field | Value |
|---|---|
| SHA-256 | `dff2505a7a6a1462ad535faef9ed0fd9d39d9b22c7ae2224f4bab3f4e6aa9773` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-12 02:52:28` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c1f104242056de9b38cfaf1e44de20c` |
| SHA-1 | `4fd33b9d285e3aaf94c7fba84c29e8c89f880741` |
| SHA-256 | `dff2505a7a6a1462ad535faef9ed0fd9d39d9b22c7ae2224f4bab3f4e6aa9773` |
| SHA3-384 | `04b035821591b7bced47ff5ff4437f79ced85d58e26697215ec13e2195ad0ef721c69ec84b3019e76c32b09b4dfadfc5` |
| IMPHASH | `976d2ad389e8b21847d44dfb70916b1f` |
| TLSH | `T122E6331D64C4668EC9B0E13DBFE202B0A164B2B51B3743FF525997226CB73A09C3AD57` |
| SSDEEP | `393216:508vKf74fiYwvIt3XX7clXMCHWUjBcuI3/PGTAI:508Vf+It3XXSXMb8WH/O7` |
| ICON-DHASH | `50f9fcbccce4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_dff2505a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dff2505a7a6a1462ad535faef9ed0fd9d39d9b22c7ae2224f4bab3f4e6aa9773"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-12 02:52:28"
  condition:
    hash.sha256(0, filesize) == "dff2505a7a6a1462ad535faef9ed0fd9d39d9b22c7ae2224f4bab3f4e6aa9773"
}
```

### Sample 11: `97c5dc8c66c4b51b`

| Field | Value |
|---|---|
| SHA-256 | `97c5dc8c66c4b51ba6179244cbefd3498669392f06528d840b38790981e21aa2` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-08-12 02:49:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca2ef10d568ab44a4ffd933951a520d8` |
| SHA-1 | `b7bfe4ef2cc1cc79354597d0a47d286a7635fe4a` |
| SHA-256 | `97c5dc8c66c4b51ba6179244cbefd3498669392f06528d840b38790981e21aa2` |
| SHA3-384 | `c2f0da4ccca9db498bf339e21fa223ea28d2e3929d8b8dc97e96167d58afc3af91ac0342a1ea36fd126fe466a4a48177` |
| TLSH | `T17D533AC8E383E4F6EC1B0670101BF77EAA75AD222024D967EBD8F663AD32752911751C` |
| TELFHASH | `t13a21f2ba1cb618e4b3c0a501c31b7be10e39d9372a50769347b3721037c2e92a23ac39` |
| SSDEEP | `768:euiqIMrjRKKP43M5NSNku3AAW0mDRu2b0olCL07ywS1cBkhRwY34PYD6iRR/7qDV:eGIMrVKq433CuQlFhoTwS2i34m6i/T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_97c5dc8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97c5dc8c66c4b51ba6179244cbefd3498669392f06528d840b38790981e21aa2"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-12 02:49:44"
  condition:
    hash.sha256(0, filesize) == "97c5dc8c66c4b51ba6179244cbefd3498669392f06528d840b38790981e21aa2"
}
```

### Sample 12: `e9b252e799ee5152`

| Field | Value |
|---|---|
| SHA-256 | `e9b252e799ee515217ec51d87aa4c6355fcd030021eb305f0d728bde80f83155` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-08-12 02:49:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b97c504fa0e65adadd5224c7fe7fd94` |
| SHA-1 | `892aed5b067080abde5e1e980722c68c3f79c860` |
| SHA-256 | `e9b252e799ee515217ec51d87aa4c6355fcd030021eb305f0d728bde80f83155` |
| SHA3-384 | `fd08c942cf4ef3d03cba79ab60739a8a04e604089f365e2556f1ad132abbed607e300dcf72b6afdac5564ef9027753af` |
| TLSH | `T103E2F1BBE51A6F82E23C8178695F7CA14815670D714DC653DBEC78A34C74B272A50F82` |
| SSDEEP | `768:Bg5EO7ekFp649EUv9cdNp5Bue7FH6tp/29CM4nbcuyD7U4/2t:C5EOR6U8zueB6H2QM4nouy8Pt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_e9b252e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9b252e799ee515217ec51d87aa4c6355fcd030021eb305f0d728bde80f83155"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-12 02:49:15"
  condition:
    hash.sha256(0, filesize) == "e9b252e799ee515217ec51d87aa4c6355fcd030021eb305f0d728bde80f83155"
}
```

### Sample 13: `6e061c8b4c4c97b1`

| Field | Value |
|---|---|
| SHA-256 | `6e061c8b4c4c97b16eb51f90538686bc5378ecf7a1072786f91ae5556ea3d383` |
| Family label | `Mirai` |
| File name | `boatnet.mips` |
| File type | `elf` |
| First seen | `2026-08-12 02:46:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93f5a59281610bcd209613b130b7b48e` |
| SHA-1 | `c62e56a40e38a98453c90d86a552322049aa37ad` |
| SHA-256 | `6e061c8b4c4c97b16eb51f90538686bc5378ecf7a1072786f91ae5556ea3d383` |
| SHA3-384 | `2bf55205a994e3595aa400b40a5e4af19316cf65300381efca01634ccf3e9da4d132286530e713840ee9fc9a10de1064` |
| TLSH | `T13034B71EAE228F7EF669873447B75E259B5D23C623E1D541D2ACC2101E202DE641FFB8` |
| TELFHASH | `t16941a3580a7807b0a7656c5e499dff76d6a330df3f166c238e11e86eeb69a435d10c0c` |
| SSDEEP | `6144:5JPrzzWFDd6Ojhmqr9abSyH+7YWOIn0l1A:TrzyFDd6OjIDHgU1A` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_6e061c8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e061c8b4c4c97b16eb51f90538686bc5378ecf7a1072786f91ae5556ea3d383"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-12 02:46:28"
  condition:
    hash.sha256(0, filesize) == "6e061c8b4c4c97b16eb51f90538686bc5378ecf7a1072786f91ae5556ea3d383"
}
```

### Sample 14: `563f794f2126d622`

| Field | Value |
|---|---|
| SHA-256 | `563f794f2126d6221e5fc5e60a38836a832b84cd9cbb9c6db03a6eb2b35057ca` |
| Family label | `unknown` |
| File name | `main.riscv64` |
| File type | `elf` |
| First seen | `2026-08-12 02:44:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fe4ca857f76da839d7a51671bf5b80c` |
| SHA-1 | `9df5104aa1f0a573793a574f34fba92b6e03f594` |
| SHA-256 | `563f794f2126d6221e5fc5e60a38836a832b84cd9cbb9c6db03a6eb2b35057ca` |
| SHA3-384 | `0716ce7f1a5e76bd7db3cd60e4e6d674a400862ac09c0a37533c0f02d81d64ab1bf6b1b49e6f63e6b49d2371993df3ef` |
| TLSH | `T1A5734A829C218724C2E613B857F94A55E3D11F123ACB3301CAA1F735BD9E164B693D9F` |
| SSDEEP | `1536:KouZ9On3ch4G5FBNKtX/7Zdo+DzVJc/XQ6A2xyLoTySoRQ30rW:s9OQ4IFBctX/g+DEI6A2xyLoTyjQMW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_563f794f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "563f794f2126d6221e5fc5e60a38836a832b84cd9cbb9c6db03a6eb2b35057ca"
    family = "unknown"
    file_name = "main.riscv64"
    file_type = "elf"
    first_seen = "2026-08-12 02:44:35"
  condition:
    hash.sha256(0, filesize) == "563f794f2126d6221e5fc5e60a38836a832b84cd9cbb9c6db03a6eb2b35057ca"
}
```

### Sample 15: `e1f3a4483c1c2743`

| Field | Value |
|---|---|
| SHA-256 | `e1f3a4483c1c27436eb19cae9850237da14a3d3964f49690a6b375b827f6391b` |
| Family label | `Mirai` |
| File name | `boatnet.mips` |
| File type | `elf` |
| First seen | `2026-08-12 02:44:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1449ad2e63382c5dd9bd444c9c386db` |
| SHA-1 | `6fffc188f190db240714c50413563d696241ecef` |
| SHA-256 | `e1f3a4483c1c27436eb19cae9850237da14a3d3964f49690a6b375b827f6391b` |
| SHA3-384 | `45f50d7ca423e4742a072a3bf4c3ee4fcb2f70c5a87a09a82ec840a8fc013a728653b15326dbaa61d5256962f5bee159` |
| TLSH | `T16D5302ABC7C884C1F88EFD7D12B483103EA11E927248EC13A139E7549D58CFF681AB94` |
| SSDEEP | `1536:vU4xTHeGGTuZzdyN3GPuldgiCVjoSsq7M2jtDVJuv:vXTHHGqZ8RLgguMaVVQv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_e1f3a448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1f3a4483c1c27436eb19cae9850237da14a3d3964f49690a6b375b827f6391b"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-12 02:44:34"
  condition:
    hash.sha256(0, filesize) == "e1f3a4483c1c27436eb19cae9850237da14a3d3964f49690a6b375b827f6391b"
}
```

### Sample 16: `15d44f49786a0e06`

| Field | Value |
|---|---|
| SHA-256 | `15d44f49786a0e06bb026e05ee4c6f6245fc24d9b002e2f6ca4f847693fcf321` |
| Family label | `Mirai` |
| File name | `boatnet.arm7` |
| File type | `elf` |
| First seen | `2026-08-12 02:41:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ee92f0edb63283ea03a1b1405861e26` |
| SHA-1 | `a7637a6a897d53392b97c3abe681af0513f3e766` |
| SHA-256 | `15d44f49786a0e06bb026e05ee4c6f6245fc24d9b002e2f6ca4f847693fcf321` |
| SHA3-384 | `7395b47d1596130dd5cbbe1d8141bc2841cb72b9e3d4a4807e64907f0cbcb6cd4eccf7d1eef9546d961adb5ec73ef324` |
| TLSH | `T148342B46F6418F13C0D617BAFACF56463333A794D3DB730699286BB03F8679A4E12A05` |
| TELFHASH | `t15a5112b45b2a58255aa1df6cd9fa2772451ec6211b41ef33ef67c8dc140a44ee226c0f` |
| SSDEEP | `6144:RFhO/D8P8Q90BANWxDFjaxZkXD81FTPEFsSyAa0r6pTM/RipbN3:+80e0q+DFjaxZkXD81FjisyaNpI/w3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_15d44f49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15d44f49786a0e06bb026e05ee4c6f6245fc24d9b002e2f6ca4f847693fcf321"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-12 02:41:13"
  condition:
    hash.sha256(0, filesize) == "15d44f49786a0e06bb026e05ee4c6f6245fc24d9b002e2f6ca4f847693fcf321"
}
```

### Sample 17: `29ce742b425c2d79`

| Field | Value |
|---|---|
| SHA-256 | `29ce742b425c2d7987bca449d9a7a55b97eced1083b816522bb44853fd1299f1` |
| Family label | `Mirai` |
| File name | `boatnet.arm` |
| File type | `elf` |
| First seen | `2026-08-12 02:41:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b47989f7d07744d2e52ae292675939bd` |
| SHA-1 | `e80fc47ad4e7ba53b1c91f175de534c989500ac0` |
| SHA-256 | `29ce742b425c2d7987bca449d9a7a55b97eced1083b816522bb44853fd1299f1` |
| SHA3-384 | `de42f81e5a224cb1b9d011c923e01eac44eb53d72737882b3f6ce9c2773f8d54f25ba13eae0dfe3dbfd01c6d71d58e88` |
| TLSH | `T18AF31845F8519A27C6C6127BFB4E428D3B2667D8E3DE7203DD215F20378B59B0E3AA41` |
| TELFHASH | `t10bb0128b4b4165e4b1e54d8b00a5351ddffe30eb152200d080cc1957cb03d00f232300` |
| SSDEEP | `3072:YyaLPiC0pAeYXw4khllowncpQ4DkDUqsxzMkQ+bm:YHqCWAnkD2Q0Q4YDUq8vQ+bm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_29ce742b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29ce742b425c2d7987bca449d9a7a55b97eced1083b816522bb44853fd1299f1"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-12 02:41:07"
  condition:
    hash.sha256(0, filesize) == "29ce742b425c2d7987bca449d9a7a55b97eced1083b816522bb44853fd1299f1"
}
```

### Sample 18: `28d8431c29a332a3`

| Field | Value |
|---|---|
| SHA-256 | `28d8431c29a332a3c2cf4340f441edf32a47dda3f20ed599dda6fdae35e03db6` |
| Family label | `Mirai` |
| File name | `boatnet.arm6` |
| File type | `elf` |
| First seen | `2026-08-12 02:41:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ace8cb14db216e8f80dbf82ec34c315` |
| SHA-1 | `9b733d8803432c448847ac8126314040eac4c4f1` |
| SHA-256 | `28d8431c29a332a3c2cf4340f441edf32a47dda3f20ed599dda6fdae35e03db6` |
| SHA3-384 | `a8617d54b85d495861e906d126ec6f048c27ade9c526e5daf89e1d385e869deea2e350b7e56b66b7734e3972286b7514` |
| TLSH | `T118040B56F8818B15D5C1117EFE0E128E372327F8E2DE72039D245B707BCA5AB0E3AA55` |
| TELFHASH | `t1e9c02260eb3835d43746028282ca0e0f17e039a700003a50cae06b078d07d037016826` |
| SSDEEP | `3072:ri00/HY7/nRJQSNuo7DgjO/D2YM2HtQDms4eeXPqAGa4D/4cGFOrRJXARuWOCGL:jGSt7DgjID292NZzXPqras/ttrR+RuWk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_28d8431c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28d8431c29a332a3c2cf4340f441edf32a47dda3f20ed599dda6fdae35e03db6"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-12 02:41:02"
  condition:
    hash.sha256(0, filesize) == "28d8431c29a332a3c2cf4340f441edf32a47dda3f20ed599dda6fdae35e03db6"
}
```

### Sample 19: `bad4f48c884eddb9`

| Field | Value |
|---|---|
| SHA-256 | `bad4f48c884eddb98d4db505fbfa0dec3c8bf331b4914c613754fea60256b165` |
| Family label | `Mirai` |
| File name | `boatnet.arm7` |
| File type | `elf` |
| First seen | `2026-08-12 02:40:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1becdfe11e5aa0182e41c9b9555c03c6` |
| SHA-1 | `048b77ffdb378af5ca58cd23d62dcc2a70b879e1` |
| SHA-256 | `bad4f48c884eddb98d4db505fbfa0dec3c8bf331b4914c613754fea60256b165` |
| SHA3-384 | `3cb10ae1c2c7ec16817db5741f03fefd9ed58679a89e916f1c14f25ad12d5dd767ea69472e63f344bda51b2be8b8092c` |
| TLSH | `T1C383020B4813B5E5CDC1A93AE2DC19DF730BDF3C649165911BB94A9C3E4D38AAFB8085` |
| SSDEEP | `1536:dlb3TtO821Z3CCyOOrLTUOPuQxOOo/S0LB0t/Ee/9q97+q3kNU:dJ5I1JCjTUOPCt/tLi/EiIYNU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_bad4f48c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bad4f48c884eddb98d4db505fbfa0dec3c8bf331b4914c613754fea60256b165"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-12 02:40:27"
  condition:
    hash.sha256(0, filesize) == "bad4f48c884eddb98d4db505fbfa0dec3c8bf331b4914c613754fea60256b165"
}
```

### Sample 20: `c90bb2d7835e0978`

| Field | Value |
|---|---|
| SHA-256 | `c90bb2d7835e0978738ee925c44880218e258aefc126f3f11bd364ce52312bef` |
| Family label | `Mirai` |
| File name | `boatnet.arm` |
| File type | `elf` |
| First seen | `2026-08-12 02:40:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b68b73f32ee01549f31154ffd851970` |
| SHA-1 | `1180708f761d37fb6c08febb47d9ec74e196e07a` |
| SHA-256 | `c90bb2d7835e0978738ee925c44880218e258aefc126f3f11bd364ce52312bef` |
| SHA3-384 | `3f1889cbec332ce194d86de7312dcdf958f7eb344d0e7909a0cb1f8ad1c6e6cb4fcf3cb48ea72bdb2ec61aae9a331b58` |
| TLSH | `T10E43F2262EB1F371D57DE8282E74C1EA97E2027CD74D38692229C1E523D1F4799E250F` |
| SSDEEP | `768:noqfcu/w/oaGzssiIexqZquQs5L62Pc8wU5oIowtUa3nOjU9hpWt24DWwuOaeovN:o/WwgJssix+qbp2PolfwtDXWhKOaB8zu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_c90bb2d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c90bb2d7835e0978738ee925c44880218e258aefc126f3f11bd364ce52312bef"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-12 02:40:26"
  condition:
    hash.sha256(0, filesize) == "c90bb2d7835e0978738ee925c44880218e258aefc126f3f11bd364ce52312bef"
}
```

### Sample 21: `9e683655d9bb7f7b`

| Field | Value |
|---|---|
| SHA-256 | `9e683655d9bb7f7bc5af246e5d9a19df5b35325e662750b468ded4a3eb842de7` |
| Family label | `Mirai` |
| File name | `boatnet.arm6` |
| File type | `elf` |
| First seen | `2026-08-12 02:40:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59e8ba2b9cd3a06e53e3fb18623fee2c` |
| SHA-1 | `e4e71ef2cbb7530388088837be3a32de29596202` |
| SHA-256 | `9e683655d9bb7f7bc5af246e5d9a19df5b35325e662750b468ded4a3eb842de7` |
| SHA3-384 | `c7aba410416a8028a0cd721d99a2c2d10f226dbb2b661174a42e6973a6f8808c080ec1e860dc1a68b3b75372214bc3f0` |
| TLSH | `T1DC53023859016A31847449FEF18E46AA5CD789C0D0E9B85307569CFCA2E3FF9448EBCB` |
| SSDEEP | `1536:i/oh0zxtxXuWPnbdq7zuBGsmv3pdPOhQLq:i/XxHXuIn8vuBDqphOhQLq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_9e683655
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e683655d9bb7f7bc5af246e5d9a19df5b35325e662750b468ded4a3eb842de7"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-12 02:40:24"
  condition:
    hash.sha256(0, filesize) == "9e683655d9bb7f7bc5af246e5d9a19df5b35325e662750b468ded4a3eb842de7"
}
```

### Sample 22: `437a1080ad80dc18`

| Field | Value |
|---|---|
| SHA-256 | `437a1080ad80dc1849d2f9bf90048dad0b916f5e76ddab0d468bed0f00169534` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-08-12 02:36:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `221df53f7b5e1cf694c9ba017797f347` |
| SHA-1 | `bd9d1ea815181f2509142b6a17d5cbc4f4b645a2` |
| SHA-256 | `437a1080ad80dc1849d2f9bf90048dad0b916f5e76ddab0d468bed0f00169534` |
| SHA3-384 | `e46a6ffc7d963eb86145720e5c267c94e361419a78d8718636d4906fac89b5b8504e8955de0dd51feb0f4ed6a6ab4b98` |
| TLSH | `T191F31802B31C0943D2A32DF0363B2BE197AFDAD222A4F645351F969991B1D336945ECD` |
| SSDEEP | `1536:bta4TS+ipgrCzPDm3KxO9oztrbwE5yqzukoJZNZeeEvAMWcQsZE/fBA8qAT0Hkpp:o4TSyrCzPDmaxUiIgziZJZMSptwo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_437a1080
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "437a1080ad80dc1849d2f9bf90048dad0b916f5e76ddab0d468bed0f00169534"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-08-12 02:36:54"
  condition:
    hash.sha256(0, filesize) == "437a1080ad80dc1849d2f9bf90048dad0b916f5e76ddab0d468bed0f00169534"
}
```

### Sample 23: `e55d4c51938a7ed2`

| Field | Value |
|---|---|
| SHA-256 | `e55d4c51938a7ed21604c569610988680db50ec0c7ff446205fbcdb0c21ae903` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-08-12 02:36:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e93c99f407d8d120780b764f86389a07` |
| SHA-1 | `5e5432e656d0a002eef3a824750a18ad5ce73942` |
| SHA-256 | `e55d4c51938a7ed21604c569610988680db50ec0c7ff446205fbcdb0c21ae903` |
| SHA3-384 | `0bdec92a70f793ec6c74b7c80146809c24a26bfa67aa94ebe04b51c5b7cd6d5abc06a7ea359da10710a1c7aab447f8d6` |
| TLSH | `T1EA4302C0D35CE79EE5AE18FF2EA5E3593B90454F4633DAF2A1C25A059842F3B13A1D44` |
| SSDEEP | `1536:xspndeZgJnkIy0UjU/lbVjgqgQWXUEQHXN4u+qgw09R:xsnkD0YU/rzdzXN4u+qgwo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_e55d4c51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e55d4c51938a7ed21604c569610988680db50ec0c7ff446205fbcdb0c21ae903"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-08-12 02:36:18"
  condition:
    hash.sha256(0, filesize) == "e55d4c51938a7ed21604c569610988680db50ec0c7ff446205fbcdb0c21ae903"
}
```

### Sample 24: `cf5bb941c7345be0`

| Field | Value |
|---|---|
| SHA-256 | `cf5bb941c7345be0e4066363b3b9f1a7ccf821f3b925881986cd097e71d319e7` |
| Family label | `unknown` |
| File name | `cf5bb941c7345be0e4066363b3b9f1a7ccf821f3b925881986cd097e71d319e7.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:35:59` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b917b58a2119b802960e7efff7e4f521` |
| SHA-1 | `6fada042f8de85e27a731a6995088ba12073b61e` |
| SHA-256 | `cf5bb941c7345be0e4066363b3b9f1a7ccf821f3b925881986cd097e71d319e7` |
| SHA3-384 | `e59a5e5b3fd3df31c4eca553b8d80c4e1a6c4253a9e0facbd9f3b632c53c4e7d680eb40a243356515fb3f2d54f0018ca` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T10D069D0BBD9089B5D099733248B652417B3CFC5A8B3A33DB1E51BA792E727D25D39B00` |
| SSDEEP | `49152:sK4h7N4yTuy8Oq9wjeoLNftU2MdhTnzf7517eVGH0dTlx4:sKklXq9C9ed5kUmJx4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_cf5bb941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf5bb941c7345be0e4066363b3b9f1a7ccf821f3b925881986cd097e71d319e7"
    family = "unknown"
    file_name = "cf5bb941c7345be0e4066363b3b9f1a7ccf821f3b925881986cd097e71d319e7.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:59"
  condition:
    hash.sha256(0, filesize) == "cf5bb941c7345be0e4066363b3b9f1a7ccf821f3b925881986cd097e71d319e7"
}
```

### Sample 25: `6438ceeb6f74863c`

| Field | Value |
|---|---|
| SHA-256 | `6438ceeb6f74863c6fe9981de0074cbd781e9b1cdf7ae08c9fb0a5091936f322` |
| Family label | `unknown` |
| File name | `6438ceeb6f74863c6fe9981de0074cbd781e9b1cdf7ae08c9fb0a5091936f322.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:35:57` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4efb555da547ea6bfce7dc2688dbdb06` |
| SHA-1 | `d74ce11455ebde99d19bacc49ea5be495ba52f1c` |
| SHA-256 | `6438ceeb6f74863c6fe9981de0074cbd781e9b1cdf7ae08c9fb0a5091936f322` |
| SHA3-384 | `dc798fffa1b7918fd37977b992b53f63f146398fe027469115dcfc3e79f2a8a8426f7e32622b9b76eaa1a91d26be0fe4` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1A1069D07BED058B5C499773649B752453B38BC5A4B3A33D72EA1B53A2E723C29C35B80` |
| SSDEEP | `49152:dcyctANkuFFga1PZpy2RBPOIjdv7Sqn60slQMuL:dc7mf1BODDqMuL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_6438ceeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6438ceeb6f74863c6fe9981de0074cbd781e9b1cdf7ae08c9fb0a5091936f322"
    family = "unknown"
    file_name = "6438ceeb6f74863c6fe9981de0074cbd781e9b1cdf7ae08c9fb0a5091936f322.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:57"
  condition:
    hash.sha256(0, filesize) == "6438ceeb6f74863c6fe9981de0074cbd781e9b1cdf7ae08c9fb0a5091936f322"
}
```

### Sample 26: `412ec3e5a96657e8`

| Field | Value |
|---|---|
| SHA-256 | `412ec3e5a96657e849f427f416348d97351aa0c4692f29b783ffa6e8e00fd648` |
| Family label | `unknown` |
| File name | `412ec3e5a96657e849f427f416348d97351aa0c4692f29b783ffa6e8e00fd648.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:35:54` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22f0652763cdd555e1bfb933ba836ddf` |
| SHA-1 | `3bdd59c7936f7809b3367b2e80374d06383f518e` |
| SHA-256 | `412ec3e5a96657e849f427f416348d97351aa0c4692f29b783ffa6e8e00fd648` |
| SHA3-384 | `55652b342e74bc16b66e7c3254b5e4d957613e2c4ab1109a5b95b110f4ccfaa8cfa569045eb149cd9deb5f78eb6fb27d` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T183068D077E9158BAC49AA73648B702553B7DBC198B7733E72E50A2793F223C15C3AB44` |
| SSDEEP | `49152:yHrfrhepFpI3asyPNTiGIJ8ciY1sumDL94Pm0iDslRcYx/:yH/PATiuEsLiWyRLx/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_412ec3e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "412ec3e5a96657e849f427f416348d97351aa0c4692f29b783ffa6e8e00fd648"
    family = "unknown"
    file_name = "412ec3e5a96657e849f427f416348d97351aa0c4692f29b783ffa6e8e00fd648.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:54"
  condition:
    hash.sha256(0, filesize) == "412ec3e5a96657e849f427f416348d97351aa0c4692f29b783ffa6e8e00fd648"
}
```

### Sample 27: `7d4eac37592a4a17`

| Field | Value |
|---|---|
| SHA-256 | `7d4eac37592a4a17d138b74421e93bbd426e5ab37248a280f0ee6c41538b37f7` |
| Family label | `unknown` |
| File name | `7d4eac37592a4a17d138b74421e93bbd426e5ab37248a280f0ee6c41538b37f7.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:35:52` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0546a6692d41bfa19eed4f9a247084c1` |
| SHA-1 | `e6e48c81d1f0a43b46e1f43fd327bd6aa8a536fa` |
| SHA-256 | `7d4eac37592a4a17d138b74421e93bbd426e5ab37248a280f0ee6c41538b37f7` |
| SHA3-384 | `0c269236a78aaeb0e0e70b869426f2a9082c1ecb7c989b6f2e5e45c58c3ef79a21c7ed11888fc4bad0b50d1368d08742` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T143E5AE477CE409E9D49A933289A69296BB35BC050F3233D36F90B3782E76BD05C79790` |
| SSDEEP | `49152:eeXZA9VUk6QiZhvPrIeMIqNJGwZh2fg5iL8nH6w:eeJlvP19qjGwZh2fg5iL8R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_7d4eac37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d4eac37592a4a17d138b74421e93bbd426e5ab37248a280f0ee6c41538b37f7"
    family = "unknown"
    file_name = "7d4eac37592a4a17d138b74421e93bbd426e5ab37248a280f0ee6c41538b37f7.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:52"
  condition:
    hash.sha256(0, filesize) == "7d4eac37592a4a17d138b74421e93bbd426e5ab37248a280f0ee6c41538b37f7"
}
```

### Sample 28: `f81c167e57a709eb`

| Field | Value |
|---|---|
| SHA-256 | `f81c167e57a709eb3cb71290e7910757bdcc131ed166bb4a5b94f9a7b9311fe4` |
| Family label | `unknown` |
| File name | `f81c167e57a709eb3cb71290e7910757bdcc131ed166bb4a5b94f9a7b9311fe4.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:35:50` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17d018a05378de55cf28f9e7e91d82cd` |
| SHA-1 | `3e0360ceb5da0aee6638010910f2634ae998841f` |
| SHA-256 | `f81c167e57a709eb3cb71290e7910757bdcc131ed166bb4a5b94f9a7b9311fe4` |
| SHA3-384 | `47ae4347b687b8a63897353048f9d5e062c055e6272964e6611748f6fcb68dbcb51f5b6b4a1d6c1fbf7110b1d4bbdb06` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T15106AE0BBCA004B5C8AA673688BA42417778FC4A4B3233D72E50F57A2F727E19D75B45` |
| SSDEEP | `49152:Wv2E6zt9fanhCzd9gQXha6oI1u08hQwJjnN8GdJTsFxw:Wvk7sU9Xh4FXQxw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_f81c167e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f81c167e57a709eb3cb71290e7910757bdcc131ed166bb4a5b94f9a7b9311fe4"
    family = "unknown"
    file_name = "f81c167e57a709eb3cb71290e7910757bdcc131ed166bb4a5b94f9a7b9311fe4.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:50"
  condition:
    hash.sha256(0, filesize) == "f81c167e57a709eb3cb71290e7910757bdcc131ed166bb4a5b94f9a7b9311fe4"
}
```

### Sample 29: `4ac72d69d5120ec9`

| Field | Value |
|---|---|
| SHA-256 | `4ac72d69d5120ec9f95f729856de5c8c23c03bcd3d38df8333d7fcb7c1ab6eb5` |
| Family label | `unknown` |
| File name | `4ac72d69d5120ec9f95f729856de5c8c23c03bcd3d38df8333d7fcb7c1ab6eb5.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:35:48` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5338c82a024e1f22d610639c5094c845` |
| SHA-1 | `5441f564c313d3b491d6525db445d05859f1e764` |
| SHA-256 | `4ac72d69d5120ec9f95f729856de5c8c23c03bcd3d38df8333d7fcb7c1ab6eb5` |
| SHA3-384 | `28bb7c8311f99d4af192d1043ad608b3feb523ec2e7abd54a8f50e8e3139df80967ec8dde14ee96470fa149cf9451965` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T167E5AF0B7CD409EAC4AA673688B651967B34BC494F3223C72E8077782F76BD19D39394` |
| SSDEEP | `49152:bOoEHPG+nw05k5slmZTB/EJuFN+Ju0/aIX4n:bODafs0Z4uSvaIXQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_4ac72d69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ac72d69d5120ec9f95f729856de5c8c23c03bcd3d38df8333d7fcb7c1ab6eb5"
    family = "unknown"
    file_name = "4ac72d69d5120ec9f95f729856de5c8c23c03bcd3d38df8333d7fcb7c1ab6eb5.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:48"
  condition:
    hash.sha256(0, filesize) == "4ac72d69d5120ec9f95f729856de5c8c23c03bcd3d38df8333d7fcb7c1ab6eb5"
}
```

### Sample 30: `ad36e9e4f0bcf886`

| Field | Value |
|---|---|
| SHA-256 | `ad36e9e4f0bcf8860fe600947bf9eac7baa1b05829f735e1145dbf9e8d1776de` |
| Family label | `unknown` |
| File name | `ad36e9e4f0bcf8860fe600947bf9eac7baa1b05829f735e1145dbf9e8d1776de.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:35:45` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c993304c951a6ff894cd5204300cba94` |
| SHA-1 | `efd6a39b46f7dd015d1504921f8606da0bb9a885` |
| SHA-256 | `ad36e9e4f0bcf8860fe600947bf9eac7baa1b05829f735e1145dbf9e8d1776de` |
| SHA3-384 | `594d424b8d342f09810163235e17fa95932bf28e8714ad077a2b12391cbb8936ffb78e6f10517ba4e6743d4a76e08d50` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T15CF58C07BCD548E6C0AE923688B3459A7B75BC090B3227D32E60B7782F727D05D75BA4` |
| SSDEEP | `49152:TbvJ+9b+gN7AIgAHw3ibkUPWAmAWchSVsQT0VdcRqTB9mYE/l:T0/b5/ktoeRMqd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_ad36e9e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad36e9e4f0bcf8860fe600947bf9eac7baa1b05829f735e1145dbf9e8d1776de"
    family = "unknown"
    file_name = "ad36e9e4f0bcf8860fe600947bf9eac7baa1b05829f735e1145dbf9e8d1776de.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:45"
  condition:
    hash.sha256(0, filesize) == "ad36e9e4f0bcf8860fe600947bf9eac7baa1b05829f735e1145dbf9e8d1776de"
}
```

### Sample 31: `f72ac6dadd552d8e`

| Field | Value |
|---|---|
| SHA-256 | `f72ac6dadd552d8e27799b945c33c933b47a1b171595850d9ce102be0997fbdb` |
| Family label | `unknown` |
| File name | `f72ac6dadd552d8e27799b945c33c933b47a1b171595850d9ce102be0997fbdb.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:35:43` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7aa340019eacd9dbbaaece6b18293daf` |
| SHA-1 | `8225857a9b6c273a6001d933fb523dbbb43d5ec5` |
| SHA-256 | `f72ac6dadd552d8e27799b945c33c933b47a1b171595850d9ce102be0997fbdb` |
| SHA3-384 | `0ca2c31ddcf54fab3e8f2f51b69a0c3cf059ae649bbbc558f07bac7f55ef99d3a058d61a9b8c8303a1b418f16a31a228` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1C4665C03BE9154A9C065EB3185BA43567729B85D873037E32E31EF78AF267D24E39B40` |
| SSDEEP | `49152:u1ydIKd2okKPC5m9PGB1hw+H9/Cacw6/zMV+TTK6//LkiyxLeatKmaVs7/:uo6p5mMBTwA996/zMV16rv2JKW7/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_f72ac6da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f72ac6dadd552d8e27799b945c33c933b47a1b171595850d9ce102be0997fbdb"
    family = "unknown"
    file_name = "f72ac6dadd552d8e27799b945c33c933b47a1b171595850d9ce102be0997fbdb.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:43"
  condition:
    hash.sha256(0, filesize) == "f72ac6dadd552d8e27799b945c33c933b47a1b171595850d9ce102be0997fbdb"
}
```

### Sample 32: `dc14f1e442332012`

| Field | Value |
|---|---|
| SHA-256 | `dc14f1e442332012b8c078d6117cb6bde38c51d59aa82778ecf563bbe4e0e8a5` |
| Family label | `unknown` |
| File name | `Roblox Hack.exe` |
| File type | `exe` |
| First seen | `2026-08-12 02:34:48` |
| Reporter | `hexinglarps` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3ee58b231cffa28101542dff1ab07e3` |
| SHA-1 | `611ec1bd5f0886d076a71da1093e3330985df8f7` |
| SHA-256 | `dc14f1e442332012b8c078d6117cb6bde38c51d59aa82778ecf563bbe4e0e8a5` |
| SHA3-384 | `9b2cff68c462e11c96e15059d90aad0d10bd920b10d4c7796f5190c5903ae23b04e6a0060d7a0b780e13239738521e0a` |
| IMPHASH | `445554923421947cbff896012e27345a` |
| TLSH | `T1F91633E5D3A2325CD82FCD363A544A07FA485041AB063BBF2A6F5DEB06DC0AEDF15581` |
| SSDEEP | `98304:cz0O0n6vgwMKoyQ0M1LRC3dcf9JtSZhBTOiOxXXU:dxKF2183O9JkZHOi+nU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_dc14f1e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc14f1e442332012b8c078d6117cb6bde38c51d59aa82778ecf563bbe4e0e8a5"
    family = "unknown"
    file_name = "Roblox Hack.exe"
    file_type = "exe"
    first_seen = "2026-08-12 02:34:48"
  condition:
    hash.sha256(0, filesize) == "dc14f1e442332012b8c078d6117cb6bde38c51d59aa82778ecf563bbe4e0e8a5"
}
```

### Sample 33: `a7fee620e24fadf8`

| Field | Value |
|---|---|
| SHA-256 | `a7fee620e24fadf8042fa7cab43301d0cb3c49fb29d8184c7b2649b565a197d4` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-12 02:31:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c144e1c2ffb67865c7d16a3f72d85784` |
| SHA-1 | `fdae5179475d498b0d0601a69928b99da2109788` |
| SHA-256 | `a7fee620e24fadf8042fa7cab43301d0cb3c49fb29d8184c7b2649b565a197d4` |
| SHA3-384 | `2db5584604e6fa5007b8117409f84b9883d863bbb4e19d76c03cb1b4f29f317c6c2252f4f3cb761c8ccc3ce943ce61c4` |
| TLSH | `T1F174CF76F5477E2CF0BD9DB7833A3916B1A7E0914A42FCEE1142F737D92B1660610AA0` |
| SSDEEP | `3072:gB3ijrzug9AcNBFhikfYuEP7qJ2fhov//a64vRmw/j8YW9vK1Z5Owg7YISPUp+Cm:jvKg9ziPucGoaN4cqluiPUrm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_a7fee620
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7fee620e24fadf8042fa7cab43301d0cb3c49fb29d8184c7b2649b565a197d4"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-12 02:31:47"
  condition:
    hash.sha256(0, filesize) == "a7fee620e24fadf8042fa7cab43301d0cb3c49fb29d8184c7b2649b565a197d4"
}
```

### Sample 34: `3e765d910b715b2d`

| Field | Value |
|---|---|
| SHA-256 | `3e765d910b715b2d69d17254cd5e65cbfa4590ca8847e45ce434b26fded67430` |
| Family label | `unknown` |
| File name | `boatnet.arm5` |
| File type | `elf` |
| First seen | `2026-08-12 02:28:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3570ee590ead0499f498bf17a04acbb` |
| SHA-1 | `a505c3d7415d8c8e6b1368764ce45b9383503087` |
| SHA-256 | `3e765d910b715b2d69d17254cd5e65cbfa4590ca8847e45ce434b26fded67430` |
| SHA3-384 | `592ad26dcf502558ffa0f17815e8a2a8089a05904a80334c70328b20dc6dbe101e962126f10c291bccc23b4acc043a2f` |
| TLSH | `T17263B451F8929A6FC1D1137AF68EAB8E372173D4D3CE7223CC654721378A28B0956F91` |
| TELFHASH | `t156f08b04be3e8e0954e299709c7a0362c443a22290b29b19df17ded0883e458e328d1e` |
| SSDEEP | `1536:NvOoHHmF/aVErxu8OMSp/llG8ri/WTyQA+/Fy:NvbmBaEE89Sp/lrO/WTyQFy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_3e765d91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e765d910b715b2d69d17254cd5e65cbfa4590ca8847e45ce434b26fded67430"
    family = "unknown"
    file_name = "boatnet.arm5"
    file_type = "elf"
    first_seen = "2026-08-12 02:28:31"
  condition:
    hash.sha256(0, filesize) == "3e765d910b715b2d69d17254cd5e65cbfa4590ca8847e45ce434b26fded67430"
}
```

### Sample 35: `426cf29f2636dd4f`

| Field | Value |
|---|---|
| SHA-256 | `426cf29f2636dd4f6a658e76c475c735d3ad517889e8d051854e085784fbb146` |
| Family label | `Mirai` |
| File name | `boatnet.arm5` |
| File type | `elf` |
| First seen | `2026-08-12 02:27:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc4675f27ccbe5076178434a704fc8a0` |
| SHA-1 | `5c63bb6785d36726b5e1c49537d2b64c2dbbccce` |
| SHA-256 | `426cf29f2636dd4f6a658e76c475c735d3ad517889e8d051854e085784fbb146` |
| SHA3-384 | `82961e4feb6bd1eb471cf5ae01daacc05dc01a30b562541093bf8fb94d6326e0c34c13b1b10d6f4eb62622ec411596ad` |
| TLSH | `T189B2D0A1308C7A62C6600DB5C9DDCA6AAF9317F4F1EE733311245126974806A7DBC78E` |
| SSDEEP | `384:vsuS+d5tvR3+mgwrPUqcKlzZxCNu6tXwDYzBSIM+8zXDunnWJhymdGUop5hUF:Fdd5tvR3pLrhZQNLZdSrTunnWJs3Uoz6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_426cf29f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "426cf29f2636dd4f6a658e76c475c735d3ad517889e8d051854e085784fbb146"
    family = "Mirai"
    file_name = "boatnet.arm5"
    file_type = "elf"
    first_seen = "2026-08-12 02:27:24"
  condition:
    hash.sha256(0, filesize) == "426cf29f2636dd4f6a658e76c475c735d3ad517889e8d051854e085784fbb146"
}
```

### Sample 36: `bb5c1edcefe73120`

| Field | Value |
|---|---|
| SHA-256 | `bb5c1edcefe73120769c5e8ac1f518641c99eb07e1789e12ab54434c9e98973b` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-12 02:18:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82c9b40ee7623fd586b2765f22e0543e` |
| SHA-1 | `10f1674a1136caf7aa381a4426ed1f65a60f3d03` |
| SHA-256 | `bb5c1edcefe73120769c5e8ac1f518641c99eb07e1789e12ab54434c9e98973b` |
| SHA3-384 | `193f55b030d8ab08e2d298fcb9cf0dc25205ea46a01df98a302983becdcd7f7eabd3ae966939352e961b5680af8d021a` |
| TLSH | `T17D94B291A4104ADBCE1088BB7B2C8F7463922C71C36B0F7D5D568559A28F8CBF5CABD4` |
| SSDEEP | `6144:VRYgBizQqBrVDnzY7jd9hg4LxneQx+k6W/her91KWHa2P:VRYgwz5BrVDnUV9XeO+RW/her9FHaE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_bb5c1edc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb5c1edcefe73120769c5e8ac1f518641c99eb07e1789e12ab54434c9e98973b"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-12 02:18:25"
  condition:
    hash.sha256(0, filesize) == "bb5c1edcefe73120769c5e8ac1f518641c99eb07e1789e12ab54434c9e98973b"
}
```

### Sample 37: `8525891ea500f864`

| Field | Value |
|---|---|
| SHA-256 | `8525891ea500f864200ea363c6a554de547e4672b74e52a950f16f06af58bebe` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-12 02:13:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3776191e0a66e32c591009dd262619cb` |
| SHA-1 | `a187e345aa7832d4ff269ad52ada761243d76b32` |
| SHA-256 | `8525891ea500f864200ea363c6a554de547e4672b74e52a950f16f06af58bebe` |
| SHA3-384 | `60be502b14f998ca57a9113fe770bde30d1a929906d3d7b970ba73a0d0980d55d5e703cf4a93779d9ba5b8cda6394f99` |
| TLSH | `T1D83164DA54141A312502CA9E7772390CA29FA2FB2D8FD7D49C9C0E9942887CCF661B59` |
| SSDEEP | `24:+WSWg6SDTFpJCSzFbEXLFqUrQcUtUn1JLOejIBQHpGubuAW1XW1avv:+Tp6SDDJCSzF4oU7JGubuAuXua3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_8525891e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8525891ea500f864200ea363c6a554de547e4672b74e52a950f16f06af58bebe"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-12 02:13:46"
  condition:
    hash.sha256(0, filesize) == "8525891ea500f864200ea363c6a554de547e4672b74e52a950f16f06af58bebe"
}
```

### Sample 38: `db0395da3759cdb7`

| Field | Value |
|---|---|
| SHA-256 | `db0395da3759cdb7998ca6ea997a0480fc15b04a0faa3d1bef59672552bbfd68` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-12 02:11:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fce157045fc2296db8a7083775b71d0b` |
| SHA-1 | `985153ebdb664cfb4ce2d37322c0afeb60a0e823` |
| SHA-256 | `db0395da3759cdb7998ca6ea997a0480fc15b04a0faa3d1bef59672552bbfd68` |
| SHA3-384 | `98382e1d795fd275303a69a4cb4012973e02690a67fb7175acfd0f37aea4f26001a83d04eeb76d252b9307661f856fc0` |
| TLSH | `T1C6E30946F8819B15D5D651BEFE0E128E33231B7CE3DE73029D245B307B8A8AB0E7A515` |
| TELFHASH | `t1cde022427f6c5ca832d6431981b575124eccb5c827106cb1eefca68f8025dd0f11d41b` |
| SSDEEP | `3072:nIe39cc7MUfPxJyf3ras2n82LEqNci3mNYfJOq:/3uMryfbajn8CN74YfJOq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_db0395da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db0395da3759cdb7998ca6ea997a0480fc15b04a0faa3d1bef59672552bbfd68"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-12 02:11:02"
  condition:
    hash.sha256(0, filesize) == "db0395da3759cdb7998ca6ea997a0480fc15b04a0faa3d1bef59672552bbfd68"
}
```

### Sample 39: `86df3302af26ae93`

| Field | Value |
|---|---|
| SHA-256 | `86df3302af26ae932bf1704023ea4bc9399301563cf8207bb1a119fa6d01371e` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-12 02:09:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24ea35a58c6a8f218623c38000d26192` |
| SHA-1 | `19294672bd61d0a8c0c6283142515f9f54225d22` |
| SHA-256 | `86df3302af26ae932bf1704023ea4bc9399301563cf8207bb1a119fa6d01371e` |
| SHA3-384 | `b125d37c3600b7ab2bc3ee4063d377fe5882a19405eeb3fddf5e62ec55cf6174307fb78c6fe567f94934d9a17bef2b14` |
| TLSH | `T14C43026166628530C9F87174E662868D8D4B26FCD2EA61FB6FF6000B51D2E40F77F583` |
| SSDEEP | `1536:eebWWq0TXb8r/qtH/wUXgi2X2Ng94/PZ/Y6AX:eeb3qmr80+i4Ud/U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_86df3302
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86df3302af26ae932bf1704023ea4bc9399301563cf8207bb1a119fa6d01371e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-12 02:09:27"
  condition:
    hash.sha256(0, filesize) == "86df3302af26ae932bf1704023ea4bc9399301563cf8207bb1a119fa6d01371e"
}
```

### Sample 40: `de3f3a426136416f`

| Field | Value |
|---|---|
| SHA-256 | `de3f3a426136416f1338a5d6639258273c922e37b126b25ff0b983d030bd036a` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-12 02:09:26` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `903cccb97f570df4ac9a782cfb50578e` |
| SHA-1 | `bc2b9d758bfe87ec308b5bddc741c68ec6eee8f0` |
| SHA-256 | `de3f3a426136416f1338a5d6639258273c922e37b126b25ff0b983d030bd036a` |
| SHA3-384 | `72a0cd1ec203fb8f5ce85a9d5a7635bdb6df383f7bf09f15c48a5b7f85220fd5abab1b5949da51d2a36df8fca8653580` |
| TLSH | `T163236D661A857C24AA98D4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5A69DD10871D` |
| SSDEEP | `768:ERXRWNGxVB9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Erlx0cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_de3f3a42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de3f3a426136416f1338a5d6639258273c922e37b126b25ff0b983d030bd036a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-12 02:09:26"
  condition:
    hash.sha256(0, filesize) == "de3f3a426136416f1338a5d6639258273c922e37b126b25ff0b983d030bd036a"
}
```

### Sample 41: `75761cb6afe1c0f9`

| Field | Value |
|---|---|
| SHA-256 | `75761cb6afe1c0f94bf99b0d0647fcc843f205904892f71c912f7d3290ed29ad` |
| Family label | `unknown` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-08-12 02:06:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ade92ace8354b4e3c4fadb9d4eafb28b` |
| SHA-1 | `876a77efcd4faf421f67e273bf5514410d5d33be` |
| SHA-256 | `75761cb6afe1c0f94bf99b0d0647fcc843f205904892f71c912f7d3290ed29ad` |
| SHA3-384 | `7949268a10e54b4fbc23e466b83c5ca019e07d211dead6a976b98a8caa7c5e6bf485d208683308432e5ed8f64bc96af0` |
| TLSH | `T1DFE34B41B32C0A47D1632EF43A3F27D1D3AFDA5120F4E644255FAB899272E32454AEDD` |
| SSDEEP | `3072:P+BtB9p5pJB9p5r4B9p5QDFxdZWrf1jxRDJHlBjSzGmaZRnx+:P+BxF+rf1jxNJHlBQGNZRx+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_75761cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75761cb6afe1c0f94bf99b0d0647fcc843f205904892f71c912f7d3290ed29ad"
    family = "unknown"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-12 02:06:17"
  condition:
    hash.sha256(0, filesize) == "75761cb6afe1c0f94bf99b0d0647fcc843f205904892f71c912f7d3290ed29ad"
}
```

### Sample 42: `468ec617a18a15cf`

| Field | Value |
|---|---|
| SHA-256 | `468ec617a18a15cf015d73178ab210c2a24311b0b584eb75e8dbf2fedf4fc15f` |
| Family label | `Vidar` |
| File name | `468ec617a18a15cf015d73178ab210c2a24311b0b584eb75e8dbf2fedf4fc15f.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:05:30` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dad626724bd9930f5a39c6ea5bb6700` |
| SHA-1 | `edf6e6079d8bc084d5d3fb824d61f3ab2bfe9671` |
| SHA-256 | `468ec617a18a15cf015d73178ab210c2a24311b0b584eb75e8dbf2fedf4fc15f` |
| SHA3-384 | `556b4ca6775141612fa37b2cf8381162eef747bcec5b2cf9adae00afbc20c3ed2cc4561f5aaa6549cd40a85368f61aa8` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T163265A03BDA508F9C09AA73189B75252BB74BC4C4B3133E32E50AA782F767D15E39B54` |
| SSDEEP | `49152:5FEOg4k+5S1XO959TT/CzAMj0ncEZdbiUWiorigWkcp9:52+5X/j7O6gm` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_042_468ec617
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "468ec617a18a15cf015d73178ab210c2a24311b0b584eb75e8dbf2fedf4fc15f"
    family = "Vidar"
    file_name = "468ec617a18a15cf015d73178ab210c2a24311b0b584eb75e8dbf2fedf4fc15f.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:30"
  condition:
    hash.sha256(0, filesize) == "468ec617a18a15cf015d73178ab210c2a24311b0b584eb75e8dbf2fedf4fc15f"
}
```

### Sample 43: `4f18fb2dfbd0673d`

| Field | Value |
|---|---|
| SHA-256 | `4f18fb2dfbd0673d83f8ae33461761dcea0a38510a731881ba5cc96732c2ef63` |
| Family label | `unknown` |
| File name | `4f18fb2dfbd0673d83f8ae33461761dcea0a38510a731881ba5cc96732c2ef63.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:05:28` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ddae91bbdf7a1db6d33c1fbde5bd410` |
| SHA-1 | `464702e6b1b09fbe9f396436f018517834627417` |
| SHA-256 | `4f18fb2dfbd0673d83f8ae33461761dcea0a38510a731881ba5cc96732c2ef63` |
| SHA3-384 | `2fdd60c75c86aa18a6a8d04955259b49be9fbb9d31ba4ae185261df8edb19ad7302a355499f96ed4fea37a8d8b75669e` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1FF167B0B6E904965C8A9D23689B54241B32CBC0F4B3B73F72D427A757E727E0DA39B50` |
| SSDEEP | `49152:FHLxH6c/g8s7PtUO0uJGCs1/HFxG6fW8zabu/fpRpzMzP58q2QdC7H3bfsG+sCHt:FHFGZTXhdUHYiVq3BoirPXL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_4f18fb2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f18fb2dfbd0673d83f8ae33461761dcea0a38510a731881ba5cc96732c2ef63"
    family = "unknown"
    file_name = "4f18fb2dfbd0673d83f8ae33461761dcea0a38510a731881ba5cc96732c2ef63.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:28"
  condition:
    hash.sha256(0, filesize) == "4f18fb2dfbd0673d83f8ae33461761dcea0a38510a731881ba5cc96732c2ef63"
}
```

### Sample 44: `c3bb2ed2e9082d89`

| Field | Value |
|---|---|
| SHA-256 | `c3bb2ed2e9082d896d46c00a900e5dd07591a44dbe4cf5c6581c3d86a10df6a9` |
| Family label | `unknown` |
| File name | `c3bb2ed2e9082d896d46c00a900e5dd07591a44dbe4cf5c6581c3d86a10df6a9.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:05:25` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da36e5356b11f58b7c8588a4d7d57b76` |
| SHA-1 | `297025b132da5ea66f02daec205198640df8c9f9` |
| SHA-256 | `c3bb2ed2e9082d896d46c00a900e5dd07591a44dbe4cf5c6581c3d86a10df6a9` |
| SHA3-384 | `8944e67ef06de35fe5f42c0cd432dda16034a06dc4b4d778ed81180e9ec8a4362cac680511f559d808014fd345c07b78` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1A9566C13AD95897EC0A5EB3685B682037629BC4C873133D32E71AE783F267D25E35B50` |
| SSDEEP | `49152:F3wRn7KZkmf8VHHBykpspavQAkBJ59gfGK6Kl2RnGNmDRJm1qaPs:FANpMBr4HQLV6qaPs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_c3bb2ed2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3bb2ed2e9082d896d46c00a900e5dd07591a44dbe4cf5c6581c3d86a10df6a9"
    family = "unknown"
    file_name = "c3bb2ed2e9082d896d46c00a900e5dd07591a44dbe4cf5c6581c3d86a10df6a9.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:25"
  condition:
    hash.sha256(0, filesize) == "c3bb2ed2e9082d896d46c00a900e5dd07591a44dbe4cf5c6581c3d86a10df6a9"
}
```

### Sample 45: `b53cda93234482a8`

| Field | Value |
|---|---|
| SHA-256 | `b53cda93234482a8c2369722b4e7b43fcf08fc4a60662343ea6d40dfd570f148` |
| Family label | `unknown` |
| File name | `b53cda93234482a8c2369722b4e7b43fcf08fc4a60662343ea6d40dfd570f148.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:05:22` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ee8cd2b3d1f6d691835f3f113acb60d` |
| SHA-1 | `931f8e9d325c41876cf700f68cddadeb517ef102` |
| SHA-256 | `b53cda93234482a8c2369722b4e7b43fcf08fc4a60662343ea6d40dfd570f148` |
| SHA3-384 | `010a9fef821616446d106fdabca342a72cff28ab6a8c75e7d12537cb7e1af61fdc00bfbf9c0e7e4568d42a9667c75574` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T155565B07BF5218B4C098EB35847A4295BA74BC8C8734B3B72D92AD786F293D1593DB43` |
| SSDEEP | `49152:x4abbQ70M924Lioyw8qfN20XS2tEb2uq2Mi212c2cF2Vf2Ek2AI2oY2S2WWZIRMF:xz2iop8qHMWc0oAQYrSQj3e5px7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_b53cda93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b53cda93234482a8c2369722b4e7b43fcf08fc4a60662343ea6d40dfd570f148"
    family = "unknown"
    file_name = "b53cda93234482a8c2369722b4e7b43fcf08fc4a60662343ea6d40dfd570f148.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:22"
  condition:
    hash.sha256(0, filesize) == "b53cda93234482a8c2369722b4e7b43fcf08fc4a60662343ea6d40dfd570f148"
}
```

### Sample 46: `f51ae7f0c46bdeb2`

| Field | Value |
|---|---|
| SHA-256 | `f51ae7f0c46bdeb283578db0a83c79e7cf92919f34eeedba9165d7eecf39f689` |
| Family label | `unknown` |
| File name | `f51ae7f0c46bdeb283578db0a83c79e7cf92919f34eeedba9165d7eecf39f689.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:05:20` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d49825b244bad8dbdc63dfe538d1d88f` |
| SHA-1 | `87a5955d77ee06029763179128d70effe9b7db4b` |
| SHA-256 | `f51ae7f0c46bdeb283578db0a83c79e7cf92919f34eeedba9165d7eecf39f689` |
| SHA3-384 | `2b9520f1aca81731cb2a845695d85ed89bb17d555909342a08c3f82b7e59c38fad567d2d0c81876bdc81fd62b3f8064b` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1B9666A0BAF5194B4C494EB30887A4296BA74BC8C8734B3F39D56AE346F593D21D38B47` |
| SSDEEP | `49152:RHrSXju6w1cRHAkiTTY71ecnjfZObTR/fal5zJ9ERgC/eNMC931pO0dm2K:Rg8kinYxp+/Sl5zJZa2K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_f51ae7f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f51ae7f0c46bdeb283578db0a83c79e7cf92919f34eeedba9165d7eecf39f689"
    family = "unknown"
    file_name = "f51ae7f0c46bdeb283578db0a83c79e7cf92919f34eeedba9165d7eecf39f689.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:20"
  condition:
    hash.sha256(0, filesize) == "f51ae7f0c46bdeb283578db0a83c79e7cf92919f34eeedba9165d7eecf39f689"
}
```

### Sample 47: `b8430c0a28c5e9fa`

| Field | Value |
|---|---|
| SHA-256 | `b8430c0a28c5e9fa15d843bcc665e7e87d248d3960b84925bea5f96cc082e1af` |
| Family label | `unknown` |
| File name | `b8430c0a28c5e9fa15d843bcc665e7e87d248d3960b84925bea5f96cc082e1af.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:05:18` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b99dc756e37ffcc3eff6eb5d77b0c2bc` |
| SHA-1 | `4e2ed5351353cc1297235497d2ed254b944409da` |
| SHA-256 | `b8430c0a28c5e9fa15d843bcc665e7e87d248d3960b84925bea5f96cc082e1af` |
| SHA3-384 | `ab4a1d48f0e29b5cacd51c5f45e26baa6dfa1125eb6b3a97588ecceb76cf2cba37e4384c4d2feddc6942c5a809c6f6fb` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T16D563907BB901878C495FA35887A5686BA78BC8CC734F3B32D91AD786F193D15938B43` |
| SSDEEP | `49152:2FesT0CTsG9+egORunKJMW/WXKgedSsJfi553XrYJsowMcBHaRkBM/akDUf6Kpmd:2fkORrJMtScEvKpxA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_b8430c0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8430c0a28c5e9fa15d843bcc665e7e87d248d3960b84925bea5f96cc082e1af"
    family = "unknown"
    file_name = "b8430c0a28c5e9fa15d843bcc665e7e87d248d3960b84925bea5f96cc082e1af.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:18"
  condition:
    hash.sha256(0, filesize) == "b8430c0a28c5e9fa15d843bcc665e7e87d248d3960b84925bea5f96cc082e1af"
}
```

### Sample 48: `4ac6ab5d9557368b`

| Field | Value |
|---|---|
| SHA-256 | `4ac6ab5d9557368b0cfd1f5f8b122cfe11524d93def1c53030a30e5a4886e362` |
| Family label | `unknown` |
| File name | `4ac6ab5d9557368b0cfd1f5f8b122cfe11524d93def1c53030a30e5a4886e362.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:05:15` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13a683b5b99e72f79eae941657f55ba5` |
| SHA-1 | `ad9fb2a44f037665050756db45927cd6f1cb3eb1` |
| SHA-256 | `4ac6ab5d9557368b0cfd1f5f8b122cfe11524d93def1c53030a30e5a4886e362` |
| SHA3-384 | `b0a38f9414b3971a8465dcacabd59381cf93b8f792cf68c9a6bb775cf65da3b05b7cbca94fcdff833c2b94133466d260` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T11E566B07BFA22474C095EA3488BA4656BB78BC4C873033E32E51AE786F227D15D39757` |
| SSDEEP | `49152:bzaK2YlbeYhXYPK6+X58pgGvJJ+NIXafgKisZSCqmVsAcRi6hQdXyM8Bo6HPmYmb:bxhYPYLCuZ812dXyMUnvNUgqD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_4ac6ab5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ac6ab5d9557368b0cfd1f5f8b122cfe11524d93def1c53030a30e5a4886e362"
    family = "unknown"
    file_name = "4ac6ab5d9557368b0cfd1f5f8b122cfe11524d93def1c53030a30e5a4886e362.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:15"
  condition:
    hash.sha256(0, filesize) == "4ac6ab5d9557368b0cfd1f5f8b122cfe11524d93def1c53030a30e5a4886e362"
}
```

### Sample 49: `719b5941f17a6bb3`

| Field | Value |
|---|---|
| SHA-256 | `719b5941f17a6bb3b8692f531d7f335c774cd679c9662baed9364cd08f40f6a4` |
| Family label | `unknown` |
| File name | `719b5941f17a6bb3b8692f531d7f335c774cd679c9662baed9364cd08f40f6a4.bin` |
| File type | `exe` |
| First seen | `2026-08-12 02:05:12` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fa6948805ff8fcae8c922517892052d` |
| SHA-1 | `9f41a035120349c0a3b9dca85bb1baa37f73f3b6` |
| SHA-256 | `719b5941f17a6bb3b8692f531d7f335c774cd679c9662baed9364cd08f40f6a4` |
| SHA3-384 | `d8ac417e31cfb2843bd42e466c73acf4390e8f53e60c31865b97cdba8397a7d25452c2c8870cce07d3b2c6caff690f1c` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T18C168C03BDE009A6D099A3328DB652927739B84A5B3273D32E50B77A3F7A3D09D35714` |
| SSDEEP | `49152:Lk6SB3e3FDHJ8thPBy+ADh3dNDn36knJYd5yS3IkQxVAXeZKaOkZyvrUB6e8t+7b:L2VtCfXDITVBYH0qmuDElj27` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_719b5941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "719b5941f17a6bb3b8692f531d7f335c774cd679c9662baed9364cd08f40f6a4"
    family = "unknown"
    file_name = "719b5941f17a6bb3b8692f531d7f335c774cd679c9662baed9364cd08f40f6a4.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:12"
  condition:
    hash.sha256(0, filesize) == "719b5941f17a6bb3b8692f531d7f335c774cd679c9662baed9364cd08f40f6a4"
}
```

### Sample 50: `5fa4d1b124b9129e`

| Field | Value |
|---|---|
| SHA-256 | `5fa4d1b124b9129e088b730ee262f8a6d6afb3ee355fb60b0b336e08fe0a6006` |
| Family label | `unknown` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-08-12 02:04:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0eb9fa945b9ec2e37adf13f80fd05e42` |
| SHA-1 | `345c9cc9b4713204c01c4f0efa87e83b56e6104c` |
| SHA-256 | `5fa4d1b124b9129e088b730ee262f8a6d6afb3ee355fb60b0b336e08fe0a6006` |
| SHA3-384 | `56f29153b6365954e8e08ac595dccb6e93f993550bea03c5cfbe059e6c077cb011e2323c8d930fd0abd2abb46f8adaf8` |
| TLSH | `T1D843F194F0488DB4F64B48B46CEBC5C067F1DF9577428EB249C08FA25161DA23BEA19F` |
| SSDEEP | `1536:kCoQp04I0Naku1dFb1qhSE1qqUH4UZHgeMvLFL7UAVQbyUmn4u+qgw09O:dqQIH1dqhSEcqU/gJpLwAVQbu4u+qgwr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_5fa4d1b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fa4d1b124b9129e088b730ee262f8a6d6afb3ee355fb60b0b336e08fe0a6006"
    family = "unknown"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-12 02:04:56"
  condition:
    hash.sha256(0, filesize) == "5fa4d1b124b9129e088b730ee262f8a6d6afb3ee355fb60b0b336e08fe0a6006"
}
```

### Sample 51: `8c7dfe6e0c62d3ff`

| Field | Value |
|---|---|
| SHA-256 | `8c7dfe6e0c62d3ff25f1f0b24c78a9d7932bdd8c20a9ce69881bb86e28f02ba6` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-12 02:01:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6e6def07b228ba159ffb033fe084837` |
| SHA-1 | `62696859184f65fa0531d38517404135ee949539` |
| SHA-256 | `8c7dfe6e0c62d3ff25f1f0b24c78a9d7932bdd8c20a9ce69881bb86e28f02ba6` |
| SHA3-384 | `220cbb52c0bbc3bd1d2e27e6612a6791eae7adf98364872f634774a4639a1ff7bab9546f045d2ed942ad932b50b99035` |
| TLSH | `T10D14A71E5E228F7EF668C73047F74A20A76923D627E0D684E1ACD2145F2029E545FFA8` |
| TELFHASH | `t11941a21809b817f0a6256c5d049dff57d6a330db3f272c238e51e86eab69b839e10c0c` |
| SSDEEP | `3072:0tzNco/MebNK8DFic87nVXvw+wRYam6xh8tgJ+WE:0tzd/Me5K8DKRvwVhmK8t3WE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_8c7dfe6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7dfe6e0c62d3ff25f1f0b24c78a9d7932bdd8c20a9ce69881bb86e28f02ba6"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-12 02:01:45"
  condition:
    hash.sha256(0, filesize) == "8c7dfe6e0c62d3ff25f1f0b24c78a9d7932bdd8c20a9ce69881bb86e28f02ba6"
}
```

### Sample 52: `52cddeab331e78ae`

| Field | Value |
|---|---|
| SHA-256 | `52cddeab331e78ae9afb57aa525fdba03ded8d8ef58a58f0265e4dc3a3d1c042` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-12 02:00:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ecc5ff6a6ca06b62f4baabb1a98a74a` |
| SHA-1 | `721d0a91f82af54f90dc5bd2d083e5224e68f829` |
| SHA-256 | `52cddeab331e78ae9afb57aa525fdba03ded8d8ef58a58f0265e4dc3a3d1c042` |
| SHA3-384 | `65844fb16c2717c38f656f5ff5a9bf294c4a478fddb708a3c004d6a681f382b5d4875569c212d383bcf88eb1b078f191` |
| TLSH | `T1F153013E5722D28FE6B9DCB5123B07D47BF246C84217CB06E87093646A356293C7ADD1` |
| SSDEEP | `1536:cF0FlccEbhNXErerW2mU7vvoYU5OlM0nBdeTZVEWo:cOATv3WfU7vvXfnBdeVE3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_52cddeab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52cddeab331e78ae9afb57aa525fdba03ded8d8ef58a58f0265e4dc3a3d1c042"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-12 02:00:27"
  condition:
    hash.sha256(0, filesize) == "52cddeab331e78ae9afb57aa525fdba03ded8d8ef58a58f0265e4dc3a3d1c042"
}
```

### Sample 53: `e02b22dbb4074aa2`

| Field | Value |
|---|---|
| SHA-256 | `e02b22dbb4074aa2aef9f606d7b86808f882ab9752dadd18bc486176d4c99da9` |
| Family label | `unknown` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-08-12 02:00:25` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80dc058741cb825234c2070cf06c0f79` |
| SHA-1 | `3b4857535990f26c243804dc858c15c7ebf2ea57` |
| SHA-256 | `e02b22dbb4074aa2aef9f606d7b86808f882ab9752dadd18bc486176d4c99da9` |
| SHA3-384 | `b9d1c4ccb8bc79bcc7c74f89e83da9cf398da01b7a18187383b22004ea26d817831d705187fb014f0320870a8f657f02` |
| TLSH | `T170C31235894DE7B6EBC24E70D8F08B577951ACB0E3C2B4502428EA29B78C0757EF858C` |
| SSDEEP | `3072:aM1w+SgkBeCEGssBZr4fN2xDS3xzk13qWAOu7:ao1J4p3BWlGOxzk5AOu7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_e02b22db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e02b22dbb4074aa2aef9f606d7b86808f882ab9752dadd18bc486176d4c99da9"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-12 02:00:25"
  condition:
    hash.sha256(0, filesize) == "e02b22dbb4074aa2aef9f606d7b86808f882ab9752dadd18bc486176d4c99da9"
}
```

### Sample 54: `0cdb6ae2118a96d6`

| Field | Value |
|---|---|
| SHA-256 | `0cdb6ae2118a96d618839532a4cd1166f0f1c9d83c6e020a19cbc5e7e5e0b30a` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-12 01:52:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `154c4d2eb9fc3df8b9342f363bcd6d52` |
| SHA-1 | `d4d9cd1e551720f6f1a46445489e8711c7323391` |
| SHA-256 | `0cdb6ae2118a96d618839532a4cd1166f0f1c9d83c6e020a19cbc5e7e5e0b30a` |
| SHA3-384 | `54df47d33a5b454635afba90bc78d47b7f5188bde66d6c053d1dd530a3f0a4b29e8c55b05a9183d3bb7c1657301415a4` |
| TLSH | `T113D31945FD419F26CAD225BBFB4E428D772A1768D3EE3203D9255F20379A8670E37242` |
| TELFHASH | `t12ce09261c67d01d46fcc0b4946fa10589ec831ad78481465aafd7f8701667e4383d90a` |
| SSDEEP | `1536:0OHInTgVvqtCpOTbd0sffGAUfllKADvgITxfv6iWCZ0OWOMsEsjwUzl3DwywTemk:0bT+ZGfGDPKAsItX6i3DBEssexGX4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_0cdb6ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cdb6ae2118a96d618839532a4cd1166f0f1c9d83c6e020a19cbc5e7e5e0b30a"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-12 01:52:43"
  condition:
    hash.sha256(0, filesize) == "0cdb6ae2118a96d618839532a4cd1166f0f1c9d83c6e020a19cbc5e7e5e0b30a"
}
```

### Sample 55: `97c6e06d93c29474`

| Field | Value |
|---|---|
| SHA-256 | `97c6e06d93c29474c6aec258a9dfa0b2f6c1071b46b8b7dfec3d8e0a1e4a9f09` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-12 01:52:28` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52b62b3845fa3d72b7a81db636fe1633` |
| SHA-1 | `5c6ccb150a830fb70b8c3215456275a08f729f24` |
| SHA-256 | `97c6e06d93c29474c6aec258a9dfa0b2f6c1071b46b8b7dfec3d8e0a1e4a9f09` |
| SHA3-384 | `127299848762ebbbfc4edb8f5b3ab26139903a8d5d117ace60a47b3a466fb8d9a8ca8bde496b77d0534cb52cb74270c1` |
| IMPHASH | `976d2ad389e8b21847d44dfb70916b1f` |
| TLSH | `T106D6330058D2329FE873CA79B7E046B0685ABC7917F71BFF148D8355ACA70D0687899B` |
| SSDEEP | `393216:pM9KWlN1sqQMYDqV4tD7ZXgPGXMCHWUjVcuI3/PGTAI:pMcKsS244tJXgPGXMb8iH/O7` |
| ICON-DHASH | `d4e0d4d8e8e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_97c6e06d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97c6e06d93c29474c6aec258a9dfa0b2f6c1071b46b8b7dfec3d8e0a1e4a9f09"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-12 01:52:28"
  condition:
    hash.sha256(0, filesize) == "97c6e06d93c29474c6aec258a9dfa0b2f6c1071b46b8b7dfec3d8e0a1e4a9f09"
}
```

### Sample 56: `2c33eca7982abb1e`

| Field | Value |
|---|---|
| SHA-256 | `2c33eca7982abb1e2bfad8e559af61c0326e19fb48c21059eebc5dbf14f866c2` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-12 01:51:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1935aba3419b21dc494e0336fc0dd194` |
| SHA-1 | `fff987df63aba110c5c2a4c47e2c385f6167d83c` |
| SHA-256 | `2c33eca7982abb1e2bfad8e559af61c0326e19fb48c21059eebc5dbf14f866c2` |
| SHA3-384 | `8017dbc0e25f16c1ad68e3448bd15478d3bb7d15f247093e72f9ccc29176c76e5079d2cff8b2496bfdaa740ca173e844` |
| TLSH | `T1A933F1B0EAD71C60CE716E31BA7DB11F1308567CA0EA09395B54CD64BBB14CE616EA22` |
| SSDEEP | `1536:QLGikNkmnHhFwzVZ0zKpIuJ66AepDDcbZA+X66ST4Rt:nvktZ0+06AjBXRt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_2c33eca7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c33eca7982abb1e2bfad8e559af61c0326e19fb48c21059eebc5dbf14f866c2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-12 01:51:49"
  condition:
    hash.sha256(0, filesize) == "2c33eca7982abb1e2bfad8e559af61c0326e19fb48c21059eebc5dbf14f866c2"
}
```

### Sample 57: `2f823f9602e10377`

| Field | Value |
|---|---|
| SHA-256 | `2f823f9602e103771ff0dcf0828107a3e10ad672d14541b8dc55e6c545b8ce16` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-12 01:48:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5216fee62bd47503ae5047ad3f9c998d` |
| SHA-1 | `e95d89fd0d673f5a1c0c4d49b29645fe64382e98` |
| SHA-256 | `2f823f9602e103771ff0dcf0828107a3e10ad672d14541b8dc55e6c545b8ce16` |
| SHA3-384 | `1e9539a5713f7f5e066ab75561b4cf63bbac430bef608c1c3f34148e682186f4e6fd0b19b302024f51ab82e298db7b6c` |
| TLSH | `T10BE35C0AB0C188FEC4EAC1744B9AF537D971F51D1134B6AF27D5AB622E4EE205F2DA10` |
| TELFHASH | `t12151d0713e6b3984b2d7b776734ec6a9ac32196209e534e0ef7758d1ce023c81cb5491` |
| SSDEEP | `3072:nXOedTqq342/pyqYQlva+lUkwAVTJTBLTyyyyyyyyyyyyyyyQyPyyyyyyy+yyyo4:XjdB3llnBLTyyyyyyyyyyyyyyyQyPyyS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_2f823f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f823f9602e103771ff0dcf0828107a3e10ad672d14541b8dc55e6c545b8ce16"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-12 01:48:54"
  condition:
    hash.sha256(0, filesize) == "2f823f9602e103771ff0dcf0828107a3e10ad672d14541b8dc55e6c545b8ce16"
}
```

### Sample 58: `0c798c8d0b07bc61`

| Field | Value |
|---|---|
| SHA-256 | `0c798c8d0b07bc618204c6f2fc9365d2efb023816e13af33a7a4d4ed86c8cb82` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-12 01:48:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bda04843d18b8cb644a0ff1e955cc22` |
| SHA-1 | `422929c0a3171ad32cb15e200882c39640013b7b` |
| SHA-256 | `0c798c8d0b07bc618204c6f2fc9365d2efb023816e13af33a7a4d4ed86c8cb82` |
| SHA3-384 | `ef0b73d20ca15b66abc8a56fbbbca1a71ab355dd4415dc98b30ce522f34ae9974f1dbfb10b94ff152afe4caa8984d7b6` |
| TLSH | `T1A5A34AC5FA8BD0F6E4170475402BB33FC732952A9022C69BDBA99F67DE23782561620D` |
| TELFHASH | `t16a513bbf1a761df8bbd09840e31e6b651d1ee77b156072b241b39420329add283b9c3d` |
| SSDEEP | `1536:qNnPLnehr33ludh3WM7n6xKWNa5OBzZFmQ+VmAgIxb:qRPA8dh3WOnI05OBzZFwb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_0c798c8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c798c8d0b07bc618204c6f2fc9365d2efb023816e13af33a7a4d4ed86c8cb82"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-12 01:48:52"
  condition:
    hash.sha256(0, filesize) == "0c798c8d0b07bc618204c6f2fc9365d2efb023816e13af33a7a4d4ed86c8cb82"
}
```

### Sample 59: `8bf58a0e93c7bf55`

| Field | Value |
|---|---|
| SHA-256 | `8bf58a0e93c7bf558d7edf84f24a6e690fc8cfb0e48b2bab4060240606c61c8d` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-12 01:47:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `330d97a2295896b5db6f24071d6e3e5e` |
| SHA-1 | `16856bf17dfde3e6cef0b3aaef637b36814c0b8b` |
| SHA-256 | `8bf58a0e93c7bf558d7edf84f24a6e690fc8cfb0e48b2bab4060240606c61c8d` |
| SHA3-384 | `9c45fb445223678dfebb1409da4ea0cd368d0c1d134ebc7a2be59fd5d54278d767d0160ca38fa407534c74e6a24863c0` |
| TLSH | `T1A043021251B7A536C561F73F7E21EB986424764EBB680EFB40D86ABBC4131223F29F50` |
| SSDEEP | `768:Oocd4IoJHbhFrqbtcv4+Hb4wmSwtVd5KJaFRlOL5SK9UJ3WKlstNKVCFAf5+C:OeXFxaU4wmSw7dMWI9uWMs4CY+C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_8bf58a0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bf58a0e93c7bf558d7edf84f24a6e690fc8cfb0e48b2bab4060240606c61c8d"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-12 01:47:30"
  condition:
    hash.sha256(0, filesize) == "8bf58a0e93c7bf558d7edf84f24a6e690fc8cfb0e48b2bab4060240606c61c8d"
}
```

### Sample 60: `ab849c8883fdfa4f`

| Field | Value |
|---|---|
| SHA-256 | `ab849c8883fdfa4fab650d3f1ae76db47d4facbaca1a5a97d1e6d6d0512961d2` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-12 01:47:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc748742a3b44e254afc12aba5093157` |
| SHA-1 | `91186d4b883c67d987da953c7fb08667e25429eb` |
| SHA-256 | `ab849c8883fdfa4fab650d3f1ae76db47d4facbaca1a5a97d1e6d6d0512961d2` |
| SHA3-384 | `515e73565a3dfbd17a6534b29ddfd73183c2eaf28fc88c654375753ac10af978dfd9fb556a1fd12d61bc0c10f5d2ab88` |
| TLSH | `T1E613F1A7C058CF54D22E503B354FA2DADE85D80D6178CC1FAFE4B1608EA6FB5E118386` |
| SSDEEP | `768:EUSDMhUqrcByFX9GnWehr/yaKiYm4Tvdkvf7MCzDgH+JFKAe6QAf3tEiEnbcuyD0:fyBy9AnWSr/ysB4TvdSjMAo+JFKB6Htc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_ab849c88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab849c8883fdfa4fab650d3f1ae76db47d4facbaca1a5a97d1e6d6d0512961d2"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-12 01:47:29"
  condition:
    hash.sha256(0, filesize) == "ab849c8883fdfa4fab650d3f1ae76db47d4facbaca1a5a97d1e6d6d0512961d2"
}
```

### Sample 61: `4039878821a2d563`

| Field | Value |
|---|---|
| SHA-256 | `4039878821a2d5636b60b8d1d4290a765b22f66fb338cfc9091055b4fa929262` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-12 01:47:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c52bc5b8f11d2f1d7045559a4f629093` |
| SHA-1 | `5adea62c25b52816953dd60d52ed744612712850` |
| SHA-256 | `4039878821a2d5636b60b8d1d4290a765b22f66fb338cfc9091055b4fa929262` |
| SHA3-384 | `5bb43b5c49ad5b6b904056b4869e4246ada5c92e4388093853c6674a45c1071ce6110913daff85900fb5c3d5f6879f52` |
| TLSH | `T1E8C26C966A867C44BEC98A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11F9CD618B1A` |
| SSDEEP | `768:s8vCB+25j6es8R59FYpMSUpi+20qUpi+20YQX:s8l25Jfd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_40398788
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4039878821a2d5636b60b8d1d4290a765b22f66fb338cfc9091055b4fa929262"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-12 01:47:27"
  condition:
    hash.sha256(0, filesize) == "4039878821a2d5636b60b8d1d4290a765b22f66fb338cfc9091055b4fa929262"
}
```

### Sample 62: `9e9094cb5d81ce2c`

| Field | Value |
|---|---|
| SHA-256 | `9e9094cb5d81ce2c4c6bc13a5e6bb76bdf8883c225c99b6c9f9928b212f1954d` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-12 01:42:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8a83d73a5db2db8ef71a467f8f34657` |
| SHA-1 | `1a9c00a321724b7e92bb551c5e63df1d0a908a32` |
| SHA-256 | `9e9094cb5d81ce2c4c6bc13a5e6bb76bdf8883c225c99b6c9f9928b212f1954d` |
| SHA3-384 | `c00d8bd500836824b78b9ecbe685911a8bbcf68600f3e1118ed644c38af0858f5fb8f9c457fec1092d3099aabd99b576` |
| TLSH | `T1DCC27D956A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11FACD618B2A` |
| SSDEEP | `768:UKj8vCB+25j6es8RT9FYpMSUpi+20qUpi+20YQX:UKj8l25JVd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_9e9094cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e9094cb5d81ce2c4c6bc13a5e6bb76bdf8883c225c99b6c9f9928b212f1954d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-12 01:42:56"
  condition:
    hash.sha256(0, filesize) == "9e9094cb5d81ce2c4c6bc13a5e6bb76bdf8883c225c99b6c9f9928b212f1954d"
}
```

### Sample 63: `675129bca5e2d893`

| Field | Value |
|---|---|
| SHA-256 | `675129bca5e2d893f1852243d6cd4c8ffa8cb8dbc9e60deb794e35fdb5b50e80` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-12 01:42:55` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1faf64eb621769755ad01550bc39007` |
| SHA-1 | `e1418373ada2c562343add5a8223e99848fea083` |
| SHA-256 | `675129bca5e2d893f1852243d6cd4c8ffa8cb8dbc9e60deb794e35fdb5b50e80` |
| SHA3-384 | `e5b52c214f20f57b5b16a8062e7c1c20c952ce5b6b28b38569e9959fce1f16b7020cb5c9f5edbaad66700322d232e5ba` |
| TLSH | `T141236D6126857C14AA99C8371D7E2F0CBDAD43E6320452EE7FCB3CF68C4A69DA10971D` |
| SSDEEP | `768:F6rDTPjHX9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Yr3Mcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_675129bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "675129bca5e2d893f1852243d6cd4c8ffa8cb8dbc9e60deb794e35fdb5b50e80"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-12 01:42:55"
  condition:
    hash.sha256(0, filesize) == "675129bca5e2d893f1852243d6cd4c8ffa8cb8dbc9e60deb794e35fdb5b50e80"
}
```

### Sample 64: `84bedc6e24f76a48`

| Field | Value |
|---|---|
| SHA-256 | `84bedc6e24f76a488a88f28078cca8d8d0a720201e753119b7d51f20c070a023` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-12 01:39:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efe65b8c5d863c8eae40c392e93b52b4` |
| SHA-1 | `c2cc55d57b954b6ac58af858493a247836d68dea` |
| SHA-256 | `84bedc6e24f76a488a88f28078cca8d8d0a720201e753119b7d51f20c070a023` |
| SHA3-384 | `1a5cb52140516d194567070c7c93865180ede8d0fb84fd7ecfad3d2b232e488362406940dde6d80b043e295e2b858242` |
| TLSH | `T18314D909AB610FFBDC6FDE3702E9060539CC651722A43B7A3674D528F54A90F5AE3C68` |
| SSDEEP | `1536:IIU/ALpuviU6OYO/gC61PhA8wLh3jmTYxU0FhNQF16YOYcJZeWW5TREqSgyLJzOp:nKvfYOP61ZWJNQFsYcJclMJzgOOx6Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_84bedc6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84bedc6e24f76a488a88f28078cca8d8d0a720201e753119b7d51f20c070a023"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-12 01:39:38"
  condition:
    hash.sha256(0, filesize) == "84bedc6e24f76a488a88f28078cca8d8d0a720201e753119b7d51f20c070a023"
}
```

### Sample 65: `6d10e468b2d515ac`

| Field | Value |
|---|---|
| SHA-256 | `6d10e468b2d515ac2a5a9113c4feb3ad06b3cd7f1df92fd94acf056c35836996` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-12 01:38:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0529da452641ee0146d85b69b31ce7c9` |
| SHA-1 | `c25fdac85ff3c46e22348a1f4842a7143f7612c4` |
| SHA-256 | `6d10e468b2d515ac2a5a9113c4feb3ad06b3cd7f1df92fd94acf056c35836996` |
| SHA3-384 | `643908e3d13b40558fa6130d27e2dd71b32fdef823f0a2842c7b968c8baf259e24ea6fe38fbd8018a01610c04a15bc71` |
| TLSH | `T13453F17EC1872EDAC69DDE79F068B3459D8554F160EE42D42B13D882B602706D8C9CFE` |
| SSDEEP | `1536:kTV6S9NUwTtqSoz07EgDGejE7LpiC1rl0KV27bYaGMhic1NS:wvtoz0ogyxpi+rlt2xrHS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_6d10e468
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d10e468b2d515ac2a5a9113c4feb3ad06b3cd7f1df92fd94acf056c35836996"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-12 01:38:30"
  condition:
    hash.sha256(0, filesize) == "6d10e468b2d515ac2a5a9113c4feb3ad06b3cd7f1df92fd94acf056c35836996"
}
```

### Sample 66: `9a37eea45a4d7926`

| Field | Value |
|---|---|
| SHA-256 | `9a37eea45a4d792638abcca359020013eef8be927baf1b5a7440a8a1b91e9224` |
| Family label | `unknown` |
| File name | `9a37eea45a4d792638abcca359020013eef8be927baf1b5a7440a8a1b91e9224.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:35:00` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `382d1c2f05853b26131790747afdeb9a` |
| SHA-1 | `706b2dc55ad09955248558009629644f5dbe0c5d` |
| SHA-256 | `9a37eea45a4d792638abcca359020013eef8be927baf1b5a7440a8a1b91e9224` |
| SHA3-384 | `cb83cfe37cce746376d9606667b04f66d7fdb6bcb6a5414a1a7a7f8b927d5aaeaa5100f45a7d48fd2772999721b0eb4a` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T194167C076E9045B1C8A5D23A8AB25241B72CBC0F873B37F72D927A757E327D0563AB50` |
| SSDEEP | `49152:lpffMttWSFjTbqKjhofLikJVq0yfwC3WTWBbgGDaM8mIVaRcljEyn8yU80/rfqvT:lpno99rduGz+2opC29C1wUb3YNd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_9a37eea4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a37eea45a4d792638abcca359020013eef8be927baf1b5a7440a8a1b91e9224"
    family = "unknown"
    file_name = "9a37eea45a4d792638abcca359020013eef8be927baf1b5a7440a8a1b91e9224.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:35:00"
  condition:
    hash.sha256(0, filesize) == "9a37eea45a4d792638abcca359020013eef8be927baf1b5a7440a8a1b91e9224"
}
```

### Sample 67: `16d66eebf8d2ec73`

| Field | Value |
|---|---|
| SHA-256 | `16d66eebf8d2ec738234449ec480e0a9eb98a140347671f4650fead082c01f4f` |
| Family label | `unknown` |
| File name | `16d66eebf8d2ec738234449ec480e0a9eb98a140347671f4650fead082c01f4f.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:34:58` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b257ab18e4161d4d5ed5efd535f798d` |
| SHA-1 | `bb5ad008bb1d5b796a00c734e8a2cb728b15f5ca` |
| SHA-256 | `16d66eebf8d2ec738234449ec480e0a9eb98a140347671f4650fead082c01f4f` |
| SHA3-384 | `46dd4a8aa9bf4655d13c9ac45359924314ef8d11bfd5ac527d87341c03ee2233cc83637240f2b49782b449c52acbf534` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1CC667E13BDA25568C0B5E73089BB8351B728B84C873133E32E21EE786F267D55E36B54` |
| SSDEEP | `49152:4R+4lw4v3mu7hBAlzxiCWkYC/E3wGsGuMcborjquNpdNEYH8/1XuT6maEZ4X+:m57AlzsnxsjUj5p7EUAppX+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_16d66eeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16d66eebf8d2ec738234449ec480e0a9eb98a140347671f4650fead082c01f4f"
    family = "unknown"
    file_name = "16d66eebf8d2ec738234449ec480e0a9eb98a140347671f4650fead082c01f4f.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:58"
  condition:
    hash.sha256(0, filesize) == "16d66eebf8d2ec738234449ec480e0a9eb98a140347671f4650fead082c01f4f"
}
```

### Sample 68: `8a461217574508ee`

| Field | Value |
|---|---|
| SHA-256 | `8a461217574508eec77f12bd6cd3ad1d43ba28050e853ff664fdd0873382377e` |
| Family label | `unknown` |
| File name | `8a461217574508eec77f12bd6cd3ad1d43ba28050e853ff664fdd0873382377e.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:34:56` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b2ed2db17c8d5d18ff73010d2b3a896` |
| SHA-1 | `024e4dcd12e55586d9bb07d823e71a8f4b66bbce` |
| SHA-256 | `8a461217574508eec77f12bd6cd3ad1d43ba28050e853ff664fdd0873382377e` |
| SHA3-384 | `1b9b7da65561b33d996aad066bbdecb64d1425059e122662553f3ce0204b1e44fe5457e871f12f8ba94fe06caf4ae419` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T149665A07AEA15478C085E77488B652557B38B88C873173E32E21BE78AF2A7E11D3C757` |
| SSDEEP | `49152:8Yk9q51FtLOfqppWUGDux8uTY76MVzDIrcTwbsTDvJ0maAyUabsmaPPIi:83ffq5xUV3PwgDvGsyjs7Ii` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_8a461217
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a461217574508eec77f12bd6cd3ad1d43ba28050e853ff664fdd0873382377e"
    family = "unknown"
    file_name = "8a461217574508eec77f12bd6cd3ad1d43ba28050e853ff664fdd0873382377e.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:56"
  condition:
    hash.sha256(0, filesize) == "8a461217574508eec77f12bd6cd3ad1d43ba28050e853ff664fdd0873382377e"
}
```

### Sample 69: `5a35dea1e941c4ae`

| Field | Value |
|---|---|
| SHA-256 | `5a35dea1e941c4ae1f19d3ec781aa816cdfcde2982b4be30db1f9ef933329de3` |
| Family label | `unknown` |
| File name | `5a35dea1e941c4ae1f19d3ec781aa816cdfcde2982b4be30db1f9ef933329de3.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:34:54` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e739c58250d1b6caf92f358e9ff0bd6e` |
| SHA-1 | `3d686b5cbab9e57ef65af0e5dfdd9ee5853d0d14` |
| SHA-256 | `5a35dea1e941c4ae1f19d3ec781aa816cdfcde2982b4be30db1f9ef933329de3` |
| SHA3-384 | `8f20645a653fe24a5ab9976276e6e8c63f6e3832f2615596ac56c200f41ef4857c4f3226a0616687208298fc90e6722c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T126165A037EA448F5C099EB3188BB5252B674BC4D8B3173E72E50AA782F367D15D39B81` |
| SSDEEP | `49152:qytk/FzCeEdUlKU6keK6YP0hW8iRRWsSDOnxszA7rJoxLo5F:q7q+P6s6rR87rJo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_5a35dea1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a35dea1e941c4ae1f19d3ec781aa816cdfcde2982b4be30db1f9ef933329de3"
    family = "unknown"
    file_name = "5a35dea1e941c4ae1f19d3ec781aa816cdfcde2982b4be30db1f9ef933329de3.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:54"
  condition:
    hash.sha256(0, filesize) == "5a35dea1e941c4ae1f19d3ec781aa816cdfcde2982b4be30db1f9ef933329de3"
}
```

### Sample 70: `8936b492f1e4a8c7`

| Field | Value |
|---|---|
| SHA-256 | `8936b492f1e4a8c7685cb07d40df6e818cb8eb2997d2d2542a26c2204a9224fc` |
| Family label | `unknown` |
| File name | `8936b492f1e4a8c7685cb07d40df6e818cb8eb2997d2d2542a26c2204a9224fc.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:34:52` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b32a7e44dc8171d56cf610bfbcfa6d4c` |
| SHA-1 | `d95e5b9cebf1dde21a036dc429cffb0ddba522ca` |
| SHA-256 | `8936b492f1e4a8c7685cb07d40df6e818cb8eb2997d2d2542a26c2204a9224fc` |
| SHA3-384 | `f12b047494f33ed76df54dd7e02931d6a7a471ddb3c3811c8e71df98a684d9a7da70294e2972a5bb764e8207889dd23f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T12A165903BC916CE7C0A5A73189B75242B6A4BE085B3273EB2E507EB82E737D05D36754` |
| SSDEEP | `49152:Oajn9EUdo/3qOwU+9MUqvPIRwABekhI+tRB7j/BGu/Ewy:OA/M2RRrB5lfy` |
| ICON-DHASH | `9987c4c8c8cc8799` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_8936b492
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8936b492f1e4a8c7685cb07d40df6e818cb8eb2997d2d2542a26c2204a9224fc"
    family = "unknown"
    file_name = "8936b492f1e4a8c7685cb07d40df6e818cb8eb2997d2d2542a26c2204a9224fc.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:52"
  condition:
    hash.sha256(0, filesize) == "8936b492f1e4a8c7685cb07d40df6e818cb8eb2997d2d2542a26c2204a9224fc"
}
```

### Sample 71: `06c9957d333dcc91`

| Field | Value |
|---|---|
| SHA-256 | `06c9957d333dcc91e5a13fd7feb79d18aeaa5cd929df0cdf82085f98481afa66` |
| Family label | `unknown` |
| File name | `06c9957d333dcc91e5a13fd7feb79d18aeaa5cd929df0cdf82085f98481afa66.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:34:50` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a6b61d32f19e1e2e8c85b38e65167bd` |
| SHA-1 | `f3e8b6e96bdf7ce360c97f89983588b9d0866bc9` |
| SHA-256 | `06c9957d333dcc91e5a13fd7feb79d18aeaa5cd929df0cdf82085f98481afa66` |
| SHA3-384 | `d8bce03deea68645e50ca22bfa525bf58db536e06f5b0f9b8fedf8805095c4a26334c5ff595c32c2d5940f106f72f0a3` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D4164A037EA448F5C099E73588AB5252B674BC4D8B3133E72E90AE782F763D16D79B40` |
| SSDEEP | `49152:T52ee7ZG0XbW1yk5q0kIfdJS6RaCpMcwOJBgDu4xKa5qX:Tfmyykst0Oen0Hi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_06c9957d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06c9957d333dcc91e5a13fd7feb79d18aeaa5cd929df0cdf82085f98481afa66"
    family = "unknown"
    file_name = "06c9957d333dcc91e5a13fd7feb79d18aeaa5cd929df0cdf82085f98481afa66.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:50"
  condition:
    hash.sha256(0, filesize) == "06c9957d333dcc91e5a13fd7feb79d18aeaa5cd929df0cdf82085f98481afa66"
}
```

### Sample 72: `d9a5009fa613140d`

| Field | Value |
|---|---|
| SHA-256 | `d9a5009fa613140dbcb9d185278cc6c9d4a34984979a1414c5a9c3dc786c6874` |
| Family label | `unknown` |
| File name | `d9a5009fa613140dbcb9d185278cc6c9d4a34984979a1414c5a9c3dc786c6874.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:34:48` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5dee0e5910844e961eb4b2eadf83df6` |
| SHA-1 | `e696bdcbaabb21ead59eed34e4f558dbbae9ecbf` |
| SHA-256 | `d9a5009fa613140dbcb9d185278cc6c9d4a34984979a1414c5a9c3dc786c6874` |
| SHA3-384 | `836016188a2b3586f077a5163870f7c0bbbb4fcb3dcd4878671bf95dfc13694fc2b8644a9c2ff7662868cb7f312f6c36` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T163165A037E9448F5C0A9E73188AB5252B674BC4D8B3173E72E50BA782F763D1AD79B40` |
| SSDEEP | `49152:0qTipsMDWkwuvo1oHFcx3W/ebI8Q6RpVUWxgtgEIYiMQpN+oxcY5Si:0rd18oHk3WGTByBNwN+of` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_d9a5009f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9a5009fa613140dbcb9d185278cc6c9d4a34984979a1414c5a9c3dc786c6874"
    family = "unknown"
    file_name = "d9a5009fa613140dbcb9d185278cc6c9d4a34984979a1414c5a9c3dc786c6874.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:48"
  condition:
    hash.sha256(0, filesize) == "d9a5009fa613140dbcb9d185278cc6c9d4a34984979a1414c5a9c3dc786c6874"
}
```

### Sample 73: `d2133a2a00bc7f25`

| Field | Value |
|---|---|
| SHA-256 | `d2133a2a00bc7f25331d795316cf3b7b9ed3f36003897e99ed5cd5c56d669dad` |
| Family label | `unknown` |
| File name | `d2133a2a00bc7f25331d795316cf3b7b9ed3f36003897e99ed5cd5c56d669dad.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:34:46` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa2a3671a579f85a4f133e59992ad5eb` |
| SHA-1 | `0ea61be0d24c025f349c66f0e20d285bce107911` |
| SHA-256 | `d2133a2a00bc7f25331d795316cf3b7b9ed3f36003897e99ed5cd5c56d669dad` |
| SHA3-384 | `56787305761e05631960b5df30963f1a0b665215fb833302a10da59c80b9a527c0f7a255fdf1bf5fbe64b59196e9541e` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1D8566B07BF6165B4C494EB34843A4246BAB4BC8C8B34B3F71D51AE786F5A3E14978B43` |
| SSDEEP | `49152:Jqiq8GPGyk0wGzKCr77cMEO1aQ4MRO5ZaOXR3or44LWtOITk2Lpn5qzEOkxg:J09r7QMEOAMMZa254LWfTPLTDxg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_d2133a2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2133a2a00bc7f25331d795316cf3b7b9ed3f36003897e99ed5cd5c56d669dad"
    family = "unknown"
    file_name = "d2133a2a00bc7f25331d795316cf3b7b9ed3f36003897e99ed5cd5c56d669dad.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:46"
  condition:
    hash.sha256(0, filesize) == "d2133a2a00bc7f25331d795316cf3b7b9ed3f36003897e99ed5cd5c56d669dad"
}
```

### Sample 74: `1d5c206d5d27fc95`

| Field | Value |
|---|---|
| SHA-256 | `1d5c206d5d27fc95aa51c40e5428ab1bc0468c994e5b6b20f6b861521deac226` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-12 01:34:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f697d972257de63e691e47363e2ba96` |
| SHA-1 | `bcdb4f6b11cd1310cb7e0dfea6ff70105b64617c` |
| SHA-256 | `1d5c206d5d27fc95aa51c40e5428ab1bc0468c994e5b6b20f6b861521deac226` |
| SHA3-384 | `b00ab59d25772af1ab716bbd8f0257fb8dd6fa5dd68b9748e45710814a1a1be80a0e80a711568d4ab4599683bbb8bce6` |
| TLSH | `T172C30849BD419B10D9DA36BEFF4E028973575B6CE3FE7202D9204B2127CAA5B0F76502` |
| TELFHASH | `t1f7e0680fe69d604e36ed061191af73030bd8fe6e2b08789405af5a9351b2ac6f11c51f` |
| SSDEEP | `3072:G/hiIsmbBkHaqzdcj7OaCQ50CZHU77SmvkPHn:WiIyaqZc7OaCQ50CZ0SmsPHn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_1d5c206d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d5c206d5d27fc95aa51c40e5428ab1bc0468c994e5b6b20f6b861521deac226"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-12 01:34:34"
  condition:
    hash.sha256(0, filesize) == "1d5c206d5d27fc95aa51c40e5428ab1bc0468c994e5b6b20f6b861521deac226"
}
```

### Sample 75: `e62736b6d3e6b82a`

| Field | Value |
|---|---|
| SHA-256 | `e62736b6d3e6b82a82650b82d924f9018b040416294ec6cc858135f724264444` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-08-12 01:34:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b13ec7fb75fc9a53e2ac5ca1c0e1e4a` |
| SHA-1 | `c94f3ac4913daa28fc48576665c688aec40a7d7e` |
| SHA-256 | `e62736b6d3e6b82a82650b82d924f9018b040416294ec6cc858135f724264444` |
| SHA3-384 | `2be83288206b46a4769d9d1e911d5257680f54e09f08c3ecbca6093556a79abb427a30a5ff87d2fbec88aa3e66376d75` |
| TLSH | `T11CE31945FC505F26C6D621BBFB4E428D372A1BA8D3EE720389255F303B9A9570E77242` |
| TELFHASH | `t10ce09254ca2d00986be84bc542bc64069ecc345cb91a3c399afd7f4b02221d1782d51b` |
| SSDEEP | `1536:Kpqh/ljEpD2uMOE1WnBIGPlVAB17QDAD2GMToTldZbZmOOPbJOYTHtrBlH2wywxn:K+jyDbGolVDAbMERdFWbJr56Nq5r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_e62736b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e62736b6d3e6b82a82650b82d924f9018b040416294ec6cc858135f724264444"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-12 01:34:32"
  condition:
    hash.sha256(0, filesize) == "e62736b6d3e6b82a82650b82d924f9018b040416294ec6cc858135f724264444"
}
```

### Sample 76: `5439695869e49b0d`

| Field | Value |
|---|---|
| SHA-256 | `5439695869e49b0deb3c8de9c07aac99cd32515f5bcdfa5aff546e151911b06b` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-12 01:33:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c21f286b7f34c2716a7c26fbcbc4d1c` |
| SHA-1 | `0cdf964428386754764fd30193d69a926fb4555f` |
| SHA-256 | `5439695869e49b0deb3c8de9c07aac99cd32515f5bcdfa5aff546e151911b06b` |
| SHA3-384 | `b5f1c453e12cbc9f37a22da1f29c289b1d34c3e99a41f7560074db64590aca5650225e409610f8f907fa5d7c591e669b` |
| TLSH | `T1CE33021062AB1AF1E7702A7DED6E0E62EF497BEC9380F1631ACB871CBC1145621B85D1` |
| SSDEEP | `768:cCQmfvz9jxYnJ0g1knCYu8DM6kahxwHnG6xo2N/gLIaOehGWRt78kW2+un4q3Uii:cEfLV631kgG1nxAG6iZt78kzfn0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_54396958
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5439695869e49b0deb3c8de9c07aac99cd32515f5bcdfa5aff546e151911b06b"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-12 01:33:37"
  condition:
    hash.sha256(0, filesize) == "5439695869e49b0deb3c8de9c07aac99cd32515f5bcdfa5aff546e151911b06b"
}
```

### Sample 77: `20385fae2224fb4f`

| Field | Value |
|---|---|
| SHA-256 | `20385fae2224fb4fa4a5f4aaa01a8a58ae1a53a889fdd65edce8414e4ec2be3f` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-08-12 01:33:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6082de2c61fea2c28839413267b70489` |
| SHA-1 | `ea7d0b3011781b1d1b1492a112fa87d19b539f6f` |
| SHA-256 | `20385fae2224fb4fa4a5f4aaa01a8a58ae1a53a889fdd65edce8414e4ec2be3f` |
| SHA3-384 | `47551c9d3bd0a7347e6cdaa96201ebe978abb30c364845bf0946ec7e0f5aaa617f80b1a6aaa921db10c95c0620d020ed` |
| TLSH | `T1AF43F248219F4BA2EE611FB0C2C5B000F301557C71795A75F17B8B82FBA2896FEF6259` |
| SSDEEP | `1536:3QZy58bWvfzbM0g8jgZNfsqy1KQ65RLE2/:3QhSv0zxbspG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_20385fae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20385fae2224fb4fa4a5f4aaa01a8a58ae1a53a889fdd65edce8414e4ec2be3f"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-12 01:33:36"
  condition:
    hash.sha256(0, filesize) == "20385fae2224fb4fa4a5f4aaa01a8a58ae1a53a889fdd65edce8414e4ec2be3f"
}
```

### Sample 78: `0f0111f70ed0f619`

| Field | Value |
|---|---|
| SHA-256 | `0f0111f70ed0f619d5a47744dd319ba00312bee71f545e51e1c5e754df837d5b` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-08-12 01:28:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82c0494217d805cf83b8cfef02b3b1d2` |
| SHA-1 | `f4d8e72b54315be6c2e4ab85bcedb5df41d297d9` |
| SHA-256 | `0f0111f70ed0f619d5a47744dd319ba00312bee71f545e51e1c5e754df837d5b` |
| SHA3-384 | `878251d246c62ea0732cc550dd7b7012a84f0ad7a568876ddc851fd829b2d405eabb8e8b91abc8607fa7b60c1d7e3af3` |
| TLSH | `T156C31295460346B2D988AA34E155DBFB618AA13B397AEFB42C2CCD71FF411381D83D1B` |
| SSDEEP | `3072:kzIxxpr8SbvwxHctOfwkhT3HjKE8xRWgdC/A6H/RV/GeuJZ:k6ySo/wkhT3DKPvaf/RV/GH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_0f0111f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f0111f70ed0f619d5a47744dd319ba00312bee71f545e51e1c5e754df837d5b"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-12 01:28:36"
  condition:
    hash.sha256(0, filesize) == "0f0111f70ed0f619d5a47744dd319ba00312bee71f545e51e1c5e754df837d5b"
}
```

### Sample 79: `3a3192754cbd8864`

| Field | Value |
|---|---|
| SHA-256 | `3a3192754cbd88649ada4b0d33d9d2c6f4348960271084f74d4686ebdc34c670` |
| Family label | `unknown` |
| File name | `main.sh4` |
| File type | `elf` |
| First seen | `2026-08-12 01:28:34` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5428d8894542c509ed2d9e6701c8a3cb` |
| SHA-1 | `e08fd49c83f464c4fd99f0f60b3445faf520ba74` |
| SHA-256 | `3a3192754cbd88649ada4b0d33d9d2c6f4348960271084f74d4686ebdc34c670` |
| SHA3-384 | `5c778ab2088df8e51a7f0b3cbb37224060d01f22b9e0885855453789d5ca0546fa61a2860ac186683cdf8f06f1a6bee7` |
| TLSH | `T188031B93C52B9FB5C006B8F1A5F68E780B277D458A1B0DA5A13ACBF0038B9D8F145776` |
| SSDEEP | `384:73u1Uk+2XWo5s7kKAdi/mgkvkF/ghaX2fdQr2S2DTr/ThmfHPgC1jYBwZY1z1R+v:WC2vmkhDgXah5fQfHPJY6ZIJRW7pRms` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_3a319275
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a3192754cbd88649ada4b0d33d9d2c6f4348960271084f74d4686ebdc34c670"
    family = "unknown"
    file_name = "main.sh4"
    file_type = "elf"
    first_seen = "2026-08-12 01:28:34"
  condition:
    hash.sha256(0, filesize) == "3a3192754cbd88649ada4b0d33d9d2c6f4348960271084f74d4686ebdc34c670"
}
```

### Sample 80: `c5dd9e8c0208ef12`

| Field | Value |
|---|---|
| SHA-256 | `c5dd9e8c0208ef12b84edbb57362e2a07c5c0bf94b581036411dfa55962b6129` |
| Family label | `unknown` |
| File name | `c5dd9e8c0208ef12b84edbb57362e2a07c5c0bf94b581036411dfa55962b6129.elf` |
| File type | `elf` |
| First seen | `2026-08-12 01:18:52` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b93773f9b9095ee65825af3993f9fbfd` |
| SHA-1 | `5285863411f46cb73e4239428f30485e46dcfc34` |
| SHA-256 | `c5dd9e8c0208ef12b84edbb57362e2a07c5c0bf94b581036411dfa55962b6129` |
| SHA3-384 | `3e8952e6c2391027cd9aac15532188bcdf623f0b6fb3b47808d8e083475c3818259463e990e04e842b7063040d0ff888` |
| TLSH | `T1BAD312E388FEEDF8D8348176256077A6DA0B7946A5315F5F00B703EA15CB20A7A40F38` |
| SSDEEP | `3072:btsxPD3fh/NQS3ygOJqxxj3C+YpQW3WhoHKmOG:bt6TiJcj3C+YpQW3WhoHKmL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_c5dd9e8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5dd9e8c0208ef12b84edbb57362e2a07c5c0bf94b581036411dfa55962b6129"
    family = "unknown"
    file_name = "c5dd9e8c0208ef12b84edbb57362e2a07c5c0bf94b581036411dfa55962b6129.elf"
    file_type = "elf"
    first_seen = "2026-08-12 01:18:52"
  condition:
    hash.sha256(0, filesize) == "c5dd9e8c0208ef12b84edbb57362e2a07c5c0bf94b581036411dfa55962b6129"
}
```

### Sample 81: `cea846a93d72c55d`

| Field | Value |
|---|---|
| SHA-256 | `cea846a93d72c55d3a36191e995d89a8b6774f4b5de22680685b87f8c07d0d5e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-12 01:16:59` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX1.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c4561ad60b9f8c69fcab6fbc05959e0` |
| SHA-1 | `c07bf0a128ae2444f896747ffe0fc0a56c0dcae1` |
| SHA-256 | `cea846a93d72c55d3a36191e995d89a8b6774f4b5de22680685b87f8c07d0d5e` |
| SHA3-384 | `b254fec208500fc2cabcc10570572fc7ebf548ced22f905e3ad270f90cfb24ff60dde502adf9133238546bcfe81b45d2` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E9264917AD6104F5C1D9E334C8BB8216BB74BC484B3533E32EA0AA782E767D15E39B54` |
| SSDEEP | `49152:2YjYecj/y+nSKpywKwFcmafEMyRnG4HEjhTD0e+c5:2LKqIfakPl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_cea846a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cea846a93d72c55d3a36191e995d89a8b6774f4b5de22680685b87f8c07d0d5e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-12 01:16:59"
  condition:
    hash.sha256(0, filesize) == "cea846a93d72c55d3a36191e995d89a8b6774f4b5de22680685b87f8c07d0d5e"
}
```

### Sample 82: `1b2db3fb7efde444`

| Field | Value |
|---|---|
| SHA-256 | `1b2db3fb7efde4444b041844049425c2106f53393305ee8ee528990cb9d64d91` |
| Family label | `WannaCry` |
| File name | `1b2db3fb7efde4444b041844049425c2106f53393305ee8ee528990cb9d64d91` |
| File type | `exe` |
| First seen | `2026-08-12 01:15:12` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84d768495ad6bd0e2ca596ee551e32d0` |
| SHA-1 | `ad9a5047004a34f50dd796e4987a19a7c070b15a` |
| SHA-256 | `1b2db3fb7efde4444b041844049425c2106f53393305ee8ee528990cb9d64d91` |
| SHA3-384 | `63dcc1f5c08401473c6f2fc2ad8873d0758c18b61eadf6f80eb6ccce8adbec319f1db37bab948d7e6e190d5e4a4457b1` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T174363358726C81FCD1060D7488E7CA27A7B73C6556FEA60F8B9082771E53B5A7B24702` |
| SSDEEP | `98304:DI8qPoBhz1aRxcSUDk36SAEdhvxWa9mbdW:DI8qPe1Cxcxk3ZAEUacbd` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_082_1b2db3fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b2db3fb7efde4444b041844049425c2106f53393305ee8ee528990cb9d64d91"
    family = "WannaCry"
    file_name = "1b2db3fb7efde4444b041844049425c2106f53393305ee8ee528990cb9d64d91"
    file_type = "exe"
    first_seen = "2026-08-12 01:15:12"
  condition:
    hash.sha256(0, filesize) == "1b2db3fb7efde4444b041844049425c2106f53393305ee8ee528990cb9d64d91"
}
```

### Sample 83: `98c3a5f5142672e5`

| Field | Value |
|---|---|
| SHA-256 | `98c3a5f5142672e5206dbe7c7858541f215686cf836a11ce729763de21db96f2` |
| Family label | `unknown` |
| File name | `98c3a5f5142672e5206dbe7c7858541f215686cf836a11ce729763de21db96f2.elf` |
| File type | `elf` |
| First seen | `2026-08-12 01:13:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c2283bff507402ae7c141f9f25a84b7` |
| SHA-1 | `4c635ab833f1286bb7909dd60fe00c8a5f1b708e` |
| SHA-256 | `98c3a5f5142672e5206dbe7c7858541f215686cf836a11ce729763de21db96f2` |
| SHA3-384 | `56873afc5b531116c8d5972fe10b3c2535fb7e559652015caf4e6bb51b0a18771eee5bd04a9898f14f114521d1d61e19` |
| TLSH | `T1D0C312B0534CA4E66F935DB9A1FD106E22CA6F3C8D1FF05672004924B2D3166367A6CE` |
| SSDEEP | `3072:zmDppwDk8+0x4UNssD+xe2IHCEh796qhaVasvvTUSi84:zmDpSkwp+4+xGCEW+4Dt4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_98c3a5f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98c3a5f5142672e5206dbe7c7858541f215686cf836a11ce729763de21db96f2"
    family = "unknown"
    file_name = "98c3a5f5142672e5206dbe7c7858541f215686cf836a11ce729763de21db96f2.elf"
    file_type = "elf"
    first_seen = "2026-08-12 01:13:59"
  condition:
    hash.sha256(0, filesize) == "98c3a5f5142672e5206dbe7c7858541f215686cf836a11ce729763de21db96f2"
}
```

### Sample 84: `e32122ad84f51184`

| Field | Value |
|---|---|
| SHA-256 | `e32122ad84f511843008e2d7f8c1f3f80df5f38ded4e7e3ae56bddefad0d6d11` |
| Family label | `Mirai` |
| File name | `e32122ad84f511843008e2d7f8c1f3f80df5f38ded4e7e3ae56bddefad0d6d11.elf` |
| File type | `elf` |
| First seen | `2026-08-12 01:13:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5994447f104ea7dd9c121d4d7d242cdd` |
| SHA-1 | `c81b214bd3815dd1b85bf645989487b8d9ca3cae` |
| SHA-256 | `e32122ad84f511843008e2d7f8c1f3f80df5f38ded4e7e3ae56bddefad0d6d11` |
| SHA3-384 | `96153aacd9b9538751fb342231bd2ce67e6e80aae1c402f3f8e87d3c4c158c668d7889047fb1fd079142f2fbce243fb8` |
| TLSH | `T1D1C3127E9667BC76E6D0A979FE0CB8888C23D8ED7C6E76555304839190F0A0769F44C3` |
| SSDEEP | `3072:NQ+Cpkc+q4dcQqTbzSl8pQIDRHYkbDiLbnjtq1k:NQ+WLSW5DZYk3ujtCk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_e32122ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e32122ad84f511843008e2d7f8c1f3f80df5f38ded4e7e3ae56bddefad0d6d11"
    family = "Mirai"
    file_name = "e32122ad84f511843008e2d7f8c1f3f80df5f38ded4e7e3ae56bddefad0d6d11.elf"
    file_type = "elf"
    first_seen = "2026-08-12 01:13:55"
  condition:
    hash.sha256(0, filesize) == "e32122ad84f511843008e2d7f8c1f3f80df5f38ded4e7e3ae56bddefad0d6d11"
}
```

### Sample 85: `cbc9a1a22f5cef93`

| Field | Value |
|---|---|
| SHA-256 | `cbc9a1a22f5cef93269bf47f2cb52c566dc95bc536a62ece27cbea006d6c63f4` |
| Family label | `SalatStealer` |
| File name | `MM2DUPE.exe` |
| File type | `exe` |
| First seen | `2026-08-12 01:08:49` |
| Reporter | `hexinglarps` |
| Tags | `exe, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab086467dfac61d025686ffe13917b74` |
| SHA-1 | `3fc4ab319007dc0b36c832073b6f20d23464de7d` |
| SHA-256 | `cbc9a1a22f5cef93269bf47f2cb52c566dc95bc536a62ece27cbea006d6c63f4` |
| SHA3-384 | `caaa5451ef0ebddc1db7c0e27d07e8e48700cfddf5d9347b3333da48c97ab8465a09dfd2e41438ee83f28b82001f77e8` |
| IMPHASH | `f60a2674d3a7b81ede413bee880e7e3a` |
| TLSH | `T157749F19F7A414F9D667C57CC9524906EB72BC124760EBCF23A04A972F236E09E3EB11` |
| SSDEEP | `6144:YtjeQjoWjJK5pGtYAEfzgsb0/0MJgllOeuN:mc0UpGtGs10MJaO` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_085_cbc9a1a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbc9a1a22f5cef93269bf47f2cb52c566dc95bc536a62ece27cbea006d6c63f4"
    family = "SalatStealer"
    file_name = "MM2DUPE.exe"
    file_type = "exe"
    first_seen = "2026-08-12 01:08:49"
  condition:
    hash.sha256(0, filesize) == "cbc9a1a22f5cef93269bf47f2cb52c566dc95bc536a62ece27cbea006d6c63f4"
}
```

### Sample 86: `43ec2662d839781b`

| Field | Value |
|---|---|
| SHA-256 | `43ec2662d839781bbd41eb59f40ce37b0e505bf836d31410bc944a19fe72d1fc` |
| Family label | `unknown` |
| File name | `MV_SEA_LADY_VESSEL_MAIN_INFORMATION.js` |
| File type | `js` |
| First seen | `2026-08-12 01:08:38` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75e3edf01d356d77c3800670284a0f55` |
| SHA-1 | `a93cc5775f7b632defc6a25f94d6b615a67bc3db` |
| SHA-256 | `43ec2662d839781bbd41eb59f40ce37b0e505bf836d31410bc944a19fe72d1fc` |
| SHA3-384 | `8410509595b75bdc2aa50c63d2580128db4482e252c5774717275932b692d45cafe5fcffa0971c2a01e5691cf286c643` |
| TLSH | `T10DE52B5133FEA6452E143B55B88C88494B0EE4356983A6F8F5DF0BD0672F09B6260F9F` |
| SSDEEP | `12288:yALW+sLDO0EB/KewZzKKToiJJ/yVsBNvrkuHnS27qFhhq5NdNu+YOmj8dlD6N/WT:yAy+svFEB/Kew3e+9gsQY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_43ec2662
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43ec2662d839781bbd41eb59f40ce37b0e505bf836d31410bc944a19fe72d1fc"
    family = "unknown"
    file_name = "MV_SEA_LADY_VESSEL_MAIN_INFORMATION.js"
    file_type = "js"
    first_seen = "2026-08-12 01:08:38"
  condition:
    hash.sha256(0, filesize) == "43ec2662d839781bbd41eb59f40ce37b0e505bf836d31410bc944a19fe72d1fc"
}
```

### Sample 87: `876634b69315538b`

| Field | Value |
|---|---|
| SHA-256 | `876634b69315538b382e7e046e61c3323c704737cb4b2b2d637aa25382d513a1` |
| Family label | `unknown` |
| File name | `876634b69315538b382e7e046e61c3323c704737cb4b2b2d637aa25382d513a1.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:04:36` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8551bdd3bedb5dad0271923e0f071ff` |
| SHA-1 | `b20e30db31150507e52cf235858e3671a256f1c3` |
| SHA-256 | `876634b69315538b382e7e046e61c3323c704737cb4b2b2d637aa25382d513a1` |
| SHA3-384 | `055555c29f92a0936c59ff7ec534e7e308d764de411016500660342dc4cc86cf88ec4ba8055f6eebfa76241a7b8f72b5` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1EA964A179B614C74C0AAEB358477861BBA70B86D873073A30D626D786F353D26E38B53` |
| SSDEEP | `49152:bW6miotS3AxgVXErcD6BXd5uhJcLzqBRKR6GlIs6eHkXN1Tuc0SIlszIBnP7dFy/:bFcF2YZlIsLHu/ySIlszknP7di3Xd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_876634b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "876634b69315538b382e7e046e61c3323c704737cb4b2b2d637aa25382d513a1"
    family = "unknown"
    file_name = "876634b69315538b382e7e046e61c3323c704737cb4b2b2d637aa25382d513a1.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:36"
  condition:
    hash.sha256(0, filesize) == "876634b69315538b382e7e046e61c3323c704737cb4b2b2d637aa25382d513a1"
}
```

### Sample 88: `3fb4958a2615b465`

| Field | Value |
|---|---|
| SHA-256 | `3fb4958a2615b4652d6b55b22d623ca8409e1d452ca6134ce00a4caa118b74e9` |
| Family label | `Vidar` |
| File name | `3fb4958a2615b4652d6b55b22d623ca8409e1d452ca6134ce00a4caa118b74e9.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:04:34` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ea19964d71482f9455ef5d346f37d3f` |
| SHA-1 | `ee659798992758bcb8e17e01be072311fa3a9d35` |
| SHA-256 | `3fb4958a2615b4652d6b55b22d623ca8409e1d452ca6134ce00a4caa118b74e9` |
| SHA3-384 | `57a7540f484fc41051826dd7474aabee79ccdd9d04c359e45fc323b69f6c344d6fe4e0a770a9236ca925510bf99e0614` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T189165A037EA448F5C0A9E73588BB5252B674BC4D8B3173EB2D506AB82F763D06D39B41` |
| SSDEEP | `49152:am8YPwpyVSwGZ7hFl5yDZxQRlaqM89AgRu/mhfKxSnf5dW:aAaDBhFuDTqM89XfKv` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_088_3fb4958a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fb4958a2615b4652d6b55b22d623ca8409e1d452ca6134ce00a4caa118b74e9"
    family = "Vidar"
    file_name = "3fb4958a2615b4652d6b55b22d623ca8409e1d452ca6134ce00a4caa118b74e9.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:34"
  condition:
    hash.sha256(0, filesize) == "3fb4958a2615b4652d6b55b22d623ca8409e1d452ca6134ce00a4caa118b74e9"
}
```

### Sample 89: `3d8ea1a7e14847c1`

| Field | Value |
|---|---|
| SHA-256 | `3d8ea1a7e14847c1b25582a02cd208bd700de5420932b2905d4cf4272114d630` |
| Family label | `Vidar` |
| File name | `3d8ea1a7e14847c1b25582a02cd208bd700de5420932b2905d4cf4272114d630.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:04:23` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71d0ec374dc30f91201ab99f17dac0b6` |
| SHA-1 | `4567a020b1e5ab7d0c81c932ea64f81d949fbfeb` |
| SHA-256 | `3d8ea1a7e14847c1b25582a02cd208bd700de5420932b2905d4cf4272114d630` |
| SHA3-384 | `a8ab54e72d97cdb86df9d3dce83c405d3e1ce8b11dc9d53a454882c2041476775e9f7de0bb737558ee0be266ebc31163` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1D9765B17EE125DA4C0D9EB398536811BA728BC6D87393BA32D615EB03F353E14E39B14` |
| SSDEEP | `49152:oMMB4jxcdKlgZ0Zn5oCLLNRaC2IWLfgUTdS5oLR/RZQqxRu+ftNhzCUcEFLZvpQc:osj+5IGIH20oL9QAft+UNFhswcR1o4xo` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_089_3d8ea1a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d8ea1a7e14847c1b25582a02cd208bd700de5420932b2905d4cf4272114d630"
    family = "Vidar"
    file_name = "3d8ea1a7e14847c1b25582a02cd208bd700de5420932b2905d4cf4272114d630.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:23"
  condition:
    hash.sha256(0, filesize) == "3d8ea1a7e14847c1b25582a02cd208bd700de5420932b2905d4cf4272114d630"
}
```

### Sample 90: `1f40d6ff2f88c58b`

| Field | Value |
|---|---|
| SHA-256 | `1f40d6ff2f88c58bf2a2685da8a847fd9cf7a54e28a3ea994390bd0af4e96a80` |
| Family label | `Vidar` |
| File name | `1f40d6ff2f88c58bf2a2685da8a847fd9cf7a54e28a3ea994390bd0af4e96a80.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:04:21` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47a03ce6ad0046e4e79a5cc29dcf6874` |
| SHA-1 | `73c778fd1ae7ff90ed9375d50028a42d89337e16` |
| SHA-256 | `1f40d6ff2f88c58bf2a2685da8a847fd9cf7a54e28a3ea994390bd0af4e96a80` |
| SHA3-384 | `b5a984a59e332ae214570cfeed4f8f9bad831e79916caef61ee9fd067051c521a923082c262ad754ca4b568e38f1c0ca` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T113167C13AC9189FAC4A9A335C8B75252B664BC0C4B3237DB2E50BEB82F327D06D75754` |
| SSDEEP | `49152:PHMtiMH0Dv8Bm+6SopLexXHMXogG0c+sVwzpGU9dKwF:PMrm1SXX+npTHlF` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_090_1f40d6ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f40d6ff2f88c58bf2a2685da8a847fd9cf7a54e28a3ea994390bd0af4e96a80"
    family = "Vidar"
    file_name = "1f40d6ff2f88c58bf2a2685da8a847fd9cf7a54e28a3ea994390bd0af4e96a80.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:21"
  condition:
    hash.sha256(0, filesize) == "1f40d6ff2f88c58bf2a2685da8a847fd9cf7a54e28a3ea994390bd0af4e96a80"
}
```

### Sample 91: `0b3ce056d3aa8ec0`

| Field | Value |
|---|---|
| SHA-256 | `0b3ce056d3aa8ec05069acc49ae887e2b2b4d210d4219221778abdbda9f4c458` |
| Family label | `unknown` |
| File name | `0b3ce056d3aa8ec05069acc49ae887e2b2b4d210d4219221778abdbda9f4c458.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:04:19` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07ebd45100f063d7fa9beb67b6a762b9` |
| SHA-1 | `1b762addb20e43d13c7f426688a81341f3fcdeb2` |
| SHA-256 | `0b3ce056d3aa8ec05069acc49ae887e2b2b4d210d4219221778abdbda9f4c458` |
| SHA3-384 | `232fdbe13d9db71fa5f30c9106e4ea6e352909eeb7fb68942d36d028374a25bee5efd47b3c7eefce4f46fb0e36f30489` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E5366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaY:uc3XND1aJrCOkY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_0b3ce056
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b3ce056d3aa8ec05069acc49ae887e2b2b4d210d4219221778abdbda9f4c458"
    family = "unknown"
    file_name = "0b3ce056d3aa8ec05069acc49ae887e2b2b4d210d4219221778abdbda9f4c458.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:19"
  condition:
    hash.sha256(0, filesize) == "0b3ce056d3aa8ec05069acc49ae887e2b2b4d210d4219221778abdbda9f4c458"
}
```

### Sample 92: `fda5fdd2f8923bc9`

| Field | Value |
|---|---|
| SHA-256 | `fda5fdd2f8923bc9f7a397628ec274981e6983d3de812fe5d14a4c7fcd4282b6` |
| Family label | `unknown` |
| File name | `fda5fdd2f8923bc9f7a397628ec274981e6983d3de812fe5d14a4c7fcd4282b6.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:04:17` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36cbc71e7c0a2cca0d53f56bab8e954e` |
| SHA-1 | `57c99ffb9c6f9b55d27e676de1a4a857e902cd95` |
| SHA-256 | `fda5fdd2f8923bc9f7a397628ec274981e6983d3de812fe5d14a4c7fcd4282b6` |
| SHA3-384 | `999e60836774c8c0bc7f24b461a7de85b1897733bf3add5a10283ada906e171d38b5e87acdbedc533c0dcbe7a1aa595d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T156366A03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaO:uc3XND1aJrCOkO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_fda5fdd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fda5fdd2f8923bc9f7a397628ec274981e6983d3de812fe5d14a4c7fcd4282b6"
    family = "unknown"
    file_name = "fda5fdd2f8923bc9f7a397628ec274981e6983d3de812fe5d14a4c7fcd4282b6.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:17"
  condition:
    hash.sha256(0, filesize) == "fda5fdd2f8923bc9f7a397628ec274981e6983d3de812fe5d14a4c7fcd4282b6"
}
```

### Sample 93: `53dbad87c3016f7a`

| Field | Value |
|---|---|
| SHA-256 | `53dbad87c3016f7ae7f7561f58fdbf5fe5fa32c248c7678928dd2f34be69ee01` |
| Family label | `unknown` |
| File name | `53dbad87c3016f7ae7f7561f58fdbf5fe5fa32c248c7678928dd2f34be69ee01.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:04:15` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f35e32f0fa612235e8109ad9975599b7` |
| SHA-1 | `0e541869b2ad3dda43b85c3cefc3dc026e67b5a6` |
| SHA-256 | `53dbad87c3016f7ae7f7561f58fdbf5fe5fa32c248c7678928dd2f34be69ee01` |
| SHA3-384 | `3cc7a584c5e04ac9a61c8071d693edd0e27ca9713483c3cc09a29cbbbec60a2454db4552cc708d00540afec580477490` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T103366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaF:uc3XND1aJrCOkF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_53dbad87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53dbad87c3016f7ae7f7561f58fdbf5fe5fa32c248c7678928dd2f34be69ee01"
    family = "unknown"
    file_name = "53dbad87c3016f7ae7f7561f58fdbf5fe5fa32c248c7678928dd2f34be69ee01.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:15"
  condition:
    hash.sha256(0, filesize) == "53dbad87c3016f7ae7f7561f58fdbf5fe5fa32c248c7678928dd2f34be69ee01"
}
```

### Sample 94: `d84030d162793a2e`

| Field | Value |
|---|---|
| SHA-256 | `d84030d162793a2e0a87c3b11b5b997332b80ec53d2f12c309339cb290131f2d` |
| Family label | `unknown` |
| File name | `d84030d162793a2e0a87c3b11b5b997332b80ec53d2f12c309339cb290131f2d.bin` |
| File type | `exe` |
| First seen | `2026-08-12 01:04:13` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `484fa3c9b8ffaae0dda78b8635485477` |
| SHA-1 | `a6a7faa13eb59c9259b3f1d08b89b6211a4aa7b4` |
| SHA-256 | `d84030d162793a2e0a87c3b11b5b997332b80ec53d2f12c309339cb290131f2d` |
| SHA3-384 | `846143edf910e7b799ee030f288c14493cc1e1787501ebf8bf9f1e42e4261a0590b46c7ef4f497dc2bd7043f59364243` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T165366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaS:uc3XND1aJrCOkS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_d84030d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d84030d162793a2e0a87c3b11b5b997332b80ec53d2f12c309339cb290131f2d"
    family = "unknown"
    file_name = "d84030d162793a2e0a87c3b11b5b997332b80ec53d2f12c309339cb290131f2d.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:13"
  condition:
    hash.sha256(0, filesize) == "d84030d162793a2e0a87c3b11b5b997332b80ec53d2f12c309339cb290131f2d"
}
```

### Sample 95: `a5d5bd497eda2289`

| Field | Value |
|---|---|
| SHA-256 | `a5d5bd497eda2289310c6559d89caaa2013485fd2c19a06b3c03ef507607fdd6` |
| Family label | `unknown` |
| File name | `Windows.Internal.System.UserProfile.zip` |
| File type | `zip` |
| First seen | `2026-08-12 00:36:27` |
| Reporter | `anonymous` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d26d314a27975a600bad471b6c5a705e` |
| SHA-1 | `b4d31fd7e5466573798456e68a94bde3bb0f0ccd` |
| SHA-256 | `a5d5bd497eda2289310c6559d89caaa2013485fd2c19a06b3c03ef507607fdd6` |
| SHA3-384 | `fe561309078b32b870dc2fa941e53c417a5080b949ebf4d292c537c69525fa2c1fe74d0405fdf2696a03df3b7cc00ca8` |
| TLSH | `T141373387C6864CAFFE41D13BA368942E98D761CCBC2A150F0DE66F4D8E1FC1545E6AE0` |
| SSDEEP | `393216:wnLZ4URzIGGWomB1h+bTyhDDOR6MmovuCOypEBFgKndpCU97v8NvWsl/yJJ2FCN:wLK4zWWXBWbTyheNv1vpEjgKXCU97vI6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_a5d5bd49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5d5bd497eda2289310c6559d89caaa2013485fd2c19a06b3c03ef507607fdd6"
    family = "unknown"
    file_name = "Windows.Internal.System.UserProfile.zip"
    file_type = "zip"
    first_seen = "2026-08-12 00:36:27"
  condition:
    hash.sha256(0, filesize) == "a5d5bd497eda2289310c6559d89caaa2013485fd2c19a06b3c03ef507607fdd6"
}
```

### Sample 96: `4dfba261e914d206`

| Field | Value |
|---|---|
| SHA-256 | `4dfba261e914d206c8417ea0fd93a8a760ffef744fabe799ae25f52b0deca527` |
| Family label | `unknown` |
| File name | `Windows.AI.Agents.zip` |
| File type | `zip` |
| First seen | `2026-08-12 00:35:22` |
| Reporter | `anonymous` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08696e552700fddb4656e81305f95a5c` |
| SHA-1 | `043f0755f4bf563d1110cfee27be18c9004369e9` |
| SHA-256 | `4dfba261e914d206c8417ea0fd93a8a760ffef744fabe799ae25f52b0deca527` |
| SHA3-384 | `a28d370bdb0bb2512ef261441d91cc23c329d1e8703673f19f8be86984c6e3cc10fe293254d013c2dbef333f4e0eae35` |
| TLSH | `T11E17333290B7440AC70647B3D687C810689C85AFD66238D6F4F6FFD338ED9BEA254646` |
| SSDEEP | `393216:Sbxrt1Sny+2QsZ86YLT9XVWxMgl2XNX+vGsItkFbXRe6Rn2MwwNosUmn2:KtIy+/sZ86YuxVlyZ+espbheYn2JwNol` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_4dfba261
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dfba261e914d206c8417ea0fd93a8a760ffef744fabe799ae25f52b0deca527"
    family = "unknown"
    file_name = "Windows.AI.Agents.zip"
    file_type = "zip"
    first_seen = "2026-08-12 00:35:22"
  condition:
    hash.sha256(0, filesize) == "4dfba261e914d206c8417ea0fd93a8a760ffef744fabe799ae25f52b0deca527"
}
```

### Sample 97: `42a0c075c468870f`

| Field | Value |
|---|---|
| SHA-256 | `42a0c075c468870f9c705a605d49de7d4c2f3faad9783f54c5b589e9495bbedc` |
| Family label | `unknown` |
| File name | `42a0c075c468870f9c705a605d49de7d4c2f3faad9783f54c5b589e9495bbedc.bin` |
| File type | `exe` |
| First seen | `2026-08-12 00:34:10` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61ee8c539a8c153c2404d023a37639cd` |
| SHA-1 | `82ac55b0852416e25b12ab9d7b140d0e9b6e0b8c` |
| SHA-256 | `42a0c075c468870f9c705a605d49de7d4c2f3faad9783f54c5b589e9495bbedc` |
| SHA3-384 | `97bd27558da7e6239d88ae4b0ed1f61f4b16b88ef01ad385df0e095f5910f15814c6bc92137c2913e29b1f9665e16dbe` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T104964A17AB614C74C498D735847B465BBAA0B86D8334B3A31E62BDB86F313C15E39B13` |
| SSDEEP | `49152:NQ25n6M1Jz5GPa3Ro73lZeYT6EONpfN7f25KV3qCCGM8t5fokaOZl4t+iL/e9WY5:N1/9BvNXD2cV6Byl4t+ue93gAJcxt8Xd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_42a0c075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42a0c075c468870f9c705a605d49de7d4c2f3faad9783f54c5b589e9495bbedc"
    family = "unknown"
    file_name = "42a0c075c468870f9c705a605d49de7d4c2f3faad9783f54c5b589e9495bbedc.bin"
    file_type = "exe"
    first_seen = "2026-08-12 00:34:10"
  condition:
    hash.sha256(0, filesize) == "42a0c075c468870f9c705a605d49de7d4c2f3faad9783f54c5b589e9495bbedc"
}
```

### Sample 98: `101a3bfb62b015b4`

| Field | Value |
|---|---|
| SHA-256 | `101a3bfb62b015b49bbe08f3f53c5174c94f4d9633ac982e295274f661b35466` |
| Family label | `Vidar` |
| File name | `101a3bfb62b015b49bbe08f3f53c5174c94f4d9633ac982e295274f661b35466.bin` |
| File type | `exe` |
| First seen | `2026-08-12 00:34:07` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36d7c723f4bff69f10b9dfac9a326e75` |
| SHA-1 | `f6ac839cb4466498d740c5782eb400890303da97` |
| SHA-256 | `101a3bfb62b015b49bbe08f3f53c5174c94f4d9633ac982e295274f661b35466` |
| SHA3-384 | `a1138fe32080f0789f4a7d79ecce5c1cf16f3f19b88fa2c458b2fedbf1c2675f6d300af3c35899468f8ffc08632eb9df` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T19F564A17AB5548FAC0A9D735C4B74615BA70B84E8B3233D31E52BE782E317D06E35BA0` |
| SSDEEP | `49152:8NCM4HOw7Ge1Avfj66/thorZwv8/OZMNc1Wv3u9oRRx4WjGx8+NsKb:8BdLNEbu9oJ4SUnz` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_098_101a3bfb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "101a3bfb62b015b49bbe08f3f53c5174c94f4d9633ac982e295274f661b35466"
    family = "Vidar"
    file_name = "101a3bfb62b015b49bbe08f3f53c5174c94f4d9633ac982e295274f661b35466.bin"
    file_type = "exe"
    first_seen = "2026-08-12 00:34:07"
  condition:
    hash.sha256(0, filesize) == "101a3bfb62b015b49bbe08f3f53c5174c94f4d9633ac982e295274f661b35466"
}
```

### Sample 99: `bbf4b40be130ef82`

| Field | Value |
|---|---|
| SHA-256 | `bbf4b40be130ef821968942b27184f6f70c1faecce7a5f4e9aa25eac8d9b47ea` |
| Family label | `unknown` |
| File name | `bbf4b40be130ef821968942b27184f6f70c1faecce7a5f4e9aa25eac8d9b47ea.bin` |
| File type | `exe` |
| First seen | `2026-08-12 00:34:05` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9eda5859bd77f9fe1dc39cec96dcecec` |
| SHA-1 | `2a221d2c643904d2a67ba1a41a860639c899dfff` |
| SHA-256 | `bbf4b40be130ef821968942b27184f6f70c1faecce7a5f4e9aa25eac8d9b47ea` |
| SHA3-384 | `587e761e70b6f8c956b8f06711389cc03239927a69a9f4cfb8724c9ce27ed4eecb7672aeb98535d116973d3f2f40eb14` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1AD964B175B514C79C4A8E730C4B74A2BBA60787D8334B3A70E62AE786F217C16D39B53` |
| SSDEEP | `49152:gLdDcwhscOPuk3tC0Aknpi9LvIRTFtzM7n4h9N/hv8NPLx/xQxNdjrvq0prfJXWb:g+Xm7yKWzbxS7OSAbn/0t4KsJhXE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_bbf4b40b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbf4b40be130ef821968942b27184f6f70c1faecce7a5f4e9aa25eac8d9b47ea"
    family = "unknown"
    file_name = "bbf4b40be130ef821968942b27184f6f70c1faecce7a5f4e9aa25eac8d9b47ea.bin"
    file_type = "exe"
    first_seen = "2026-08-12 00:34:05"
  condition:
    hash.sha256(0, filesize) == "bbf4b40be130ef821968942b27184f6f70c1faecce7a5f4e9aa25eac8d9b47ea"
}
```

### Sample 100: `f04837713c07587b`

| Field | Value |
|---|---|
| SHA-256 | `f04837713c07587b67f080677b5914b14124b158eca4bcc3cf7e7a6ae5afcd49` |
| Family label | `unknown` |
| File name | `f04837713c07587b67f080677b5914b14124b158eca4bcc3cf7e7a6ae5afcd49.bin` |
| File type | `exe` |
| First seen | `2026-08-12 00:34:03` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb0bb2240f2900a4351d7d260d34e0ed` |
| SHA-1 | `efaf64da8e179e9bf9343b9a721b3f9574763a62` |
| SHA-256 | `f04837713c07587b67f080677b5914b14124b158eca4bcc3cf7e7a6ae5afcd49` |
| SHA3-384 | `4588e84033a437f67cd678c5543f55afe255a5b4d908073639f01c4abb774fcdc9ebddacf2852e5d31cbc8ef7412dea5` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1D696381B5A614D78C0A8E73584B7466FBA707C6D8730B3630E627E78AF213D55E28B43` |
| SSDEEP | `49152:UZhKxEsfCRkkZmf9xEW6d0YWm7CV6acwoOcj45WMH4JnM4UuyvhDpggVbKixNX6:UmmWSRCV6k424UVFggm+X6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_f0483771
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f04837713c07587b67f080677b5914b14124b158eca4bcc3cf7e7a6ae5afcd49"
    family = "unknown"
    file_name = "f04837713c07587b67f080677b5914b14124b158eca4bcc3cf7e7a6ae5afcd49.bin"
    file_type = "exe"
    first_seen = "2026-08-12 00:34:03"
  condition:
    hash.sha256(0, filesize) == "f04837713c07587b67f080677b5914b14124b158eca4bcc3cf7e7a6ae5afcd49"
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
 * Generated: 2026-08-12T02:59:23.861872+00:00
 */

rule MalwareBazaar_unknown_001_9ec67d8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ec67d8a8d2e0fe0b045cdf0ff06c0bf90a01f959c3b945eebd81b8a33f7f837"
    family = "unknown"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-12 02:58:38"
  condition:
    hash.sha256(0, filesize) == "9ec67d8a8d2e0fe0b045cdf0ff06c0bf90a01f959c3b945eebd81b8a33f7f837"
}

rule MalwareBazaar_unknown_002_a571bd3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a571bd3aed290eb2ed071ed8207456975fa2309a9e179ee57512b5647e0364f9"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-08-12 02:58:35"
  condition:
    hash.sha256(0, filesize) == "a571bd3aed290eb2ed071ed8207456975fa2309a9e179ee57512b5647e0364f9"
}

rule MalwareBazaar_unknown_003_6cc21288
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cc212883df2861669b9b61feeb9b7735fbadc81093f20feea95612375f87d64"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-12 02:57:28"
  condition:
    hash.sha256(0, filesize) == "6cc212883df2861669b9b61feeb9b7735fbadc81093f20feea95612375f87d64"
}

rule MalwareBazaar_Mirai_004_3364e0bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3364e0bd2291aa6be29617a98610e8a06752a452c789c5135609f28bcb532e64"
    family = "Mirai"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-12 02:57:27"
  condition:
    hash.sha256(0, filesize) == "3364e0bd2291aa6be29617a98610e8a06752a452c789c5135609f28bcb532e64"
}

rule MalwareBazaar_unknown_005_fe1390d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe1390d20a45bef35ae7129bc34db63e5370dbedf4e239628c5a5112fa14c9e4"
    family = "unknown"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-08-12 02:53:44"
  condition:
    hash.sha256(0, filesize) == "fe1390d20a45bef35ae7129bc34db63e5370dbedf4e239628c5a5112fa14c9e4"
}

rule MalwareBazaar_Mirai_006_9ca34a13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ca34a13a9100ca08c5e4f2c236ab388ed482cc0879a9af52ae28b24b6dea57e"
    family = "Mirai"
    file_name = "boatnet.arc"
    file_type = "elf"
    first_seen = "2026-08-12 02:53:24"
  condition:
    hash.sha256(0, filesize) == "9ca34a13a9100ca08c5e4f2c236ab388ed482cc0879a9af52ae28b24b6dea57e"
}

rule MalwareBazaar_unknown_007_68d89ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68d89ae2eeae98080cf9e643ed5f5827860bc19caac80be924c5b909a979160e"
    family = "unknown"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-08-12 02:53:22"
  condition:
    hash.sha256(0, filesize) == "68d89ae2eeae98080cf9e643ed5f5827860bc19caac80be924c5b909a979160e"
}

rule MalwareBazaar_unknown_008_d2ae3982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2ae3982f07f89253b21d45321e97f57b4b81c78164c2504b2578958ca186362"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-08-12 02:53:21"
  condition:
    hash.sha256(0, filesize) == "d2ae3982f07f89253b21d45321e97f57b4b81c78164c2504b2578958ca186362"
}

rule MalwareBazaar_Mirai_009_c391b6a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c391b6a62a44001982eb46e69da8d969a9de4e2164e67964bd99f5783e2381c8"
    family = "Mirai"
    file_name = "boatnet.sh4"
    file_type = "elf"
    first_seen = "2026-08-12 02:53:20"
  condition:
    hash.sha256(0, filesize) == "c391b6a62a44001982eb46e69da8d969a9de4e2164e67964bd99f5783e2381c8"
}

rule MalwareBazaar_unknown_010_dff2505a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dff2505a7a6a1462ad535faef9ed0fd9d39d9b22c7ae2224f4bab3f4e6aa9773"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-12 02:52:28"
  condition:
    hash.sha256(0, filesize) == "dff2505a7a6a1462ad535faef9ed0fd9d39d9b22c7ae2224f4bab3f4e6aa9773"
}

rule MalwareBazaar_Mirai_011_97c5dc8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97c5dc8c66c4b51ba6179244cbefd3498669392f06528d840b38790981e21aa2"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-12 02:49:44"
  condition:
    hash.sha256(0, filesize) == "97c5dc8c66c4b51ba6179244cbefd3498669392f06528d840b38790981e21aa2"
}

rule MalwareBazaar_Mirai_012_e9b252e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9b252e799ee515217ec51d87aa4c6355fcd030021eb305f0d728bde80f83155"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-12 02:49:15"
  condition:
    hash.sha256(0, filesize) == "e9b252e799ee515217ec51d87aa4c6355fcd030021eb305f0d728bde80f83155"
}

rule MalwareBazaar_Mirai_013_6e061c8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e061c8b4c4c97b16eb51f90538686bc5378ecf7a1072786f91ae5556ea3d383"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-12 02:46:28"
  condition:
    hash.sha256(0, filesize) == "6e061c8b4c4c97b16eb51f90538686bc5378ecf7a1072786f91ae5556ea3d383"
}

rule MalwareBazaar_unknown_014_563f794f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "563f794f2126d6221e5fc5e60a38836a832b84cd9cbb9c6db03a6eb2b35057ca"
    family = "unknown"
    file_name = "main.riscv64"
    file_type = "elf"
    first_seen = "2026-08-12 02:44:35"
  condition:
    hash.sha256(0, filesize) == "563f794f2126d6221e5fc5e60a38836a832b84cd9cbb9c6db03a6eb2b35057ca"
}

rule MalwareBazaar_Mirai_015_e1f3a448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1f3a4483c1c27436eb19cae9850237da14a3d3964f49690a6b375b827f6391b"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-12 02:44:34"
  condition:
    hash.sha256(0, filesize) == "e1f3a4483c1c27436eb19cae9850237da14a3d3964f49690a6b375b827f6391b"
}

rule MalwareBazaar_Mirai_016_15d44f49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15d44f49786a0e06bb026e05ee4c6f6245fc24d9b002e2f6ca4f847693fcf321"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-12 02:41:13"
  condition:
    hash.sha256(0, filesize) == "15d44f49786a0e06bb026e05ee4c6f6245fc24d9b002e2f6ca4f847693fcf321"
}

rule MalwareBazaar_Mirai_017_29ce742b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29ce742b425c2d7987bca449d9a7a55b97eced1083b816522bb44853fd1299f1"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-12 02:41:07"
  condition:
    hash.sha256(0, filesize) == "29ce742b425c2d7987bca449d9a7a55b97eced1083b816522bb44853fd1299f1"
}

rule MalwareBazaar_Mirai_018_28d8431c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28d8431c29a332a3c2cf4340f441edf32a47dda3f20ed599dda6fdae35e03db6"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-12 02:41:02"
  condition:
    hash.sha256(0, filesize) == "28d8431c29a332a3c2cf4340f441edf32a47dda3f20ed599dda6fdae35e03db6"
}

rule MalwareBazaar_Mirai_019_bad4f48c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bad4f48c884eddb98d4db505fbfa0dec3c8bf331b4914c613754fea60256b165"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-12 02:40:27"
  condition:
    hash.sha256(0, filesize) == "bad4f48c884eddb98d4db505fbfa0dec3c8bf331b4914c613754fea60256b165"
}

rule MalwareBazaar_Mirai_020_c90bb2d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c90bb2d7835e0978738ee925c44880218e258aefc126f3f11bd364ce52312bef"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-12 02:40:26"
  condition:
    hash.sha256(0, filesize) == "c90bb2d7835e0978738ee925c44880218e258aefc126f3f11bd364ce52312bef"
}

rule MalwareBazaar_Mirai_021_9e683655
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e683655d9bb7f7bc5af246e5d9a19df5b35325e662750b468ded4a3eb842de7"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-12 02:40:24"
  condition:
    hash.sha256(0, filesize) == "9e683655d9bb7f7bc5af246e5d9a19df5b35325e662750b468ded4a3eb842de7"
}

rule MalwareBazaar_Mirai_022_437a1080
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "437a1080ad80dc1849d2f9bf90048dad0b916f5e76ddab0d468bed0f00169534"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-08-12 02:36:54"
  condition:
    hash.sha256(0, filesize) == "437a1080ad80dc1849d2f9bf90048dad0b916f5e76ddab0d468bed0f00169534"
}

rule MalwareBazaar_Mirai_023_e55d4c51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e55d4c51938a7ed21604c569610988680db50ec0c7ff446205fbcdb0c21ae903"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-08-12 02:36:18"
  condition:
    hash.sha256(0, filesize) == "e55d4c51938a7ed21604c569610988680db50ec0c7ff446205fbcdb0c21ae903"
}

rule MalwareBazaar_unknown_024_cf5bb941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf5bb941c7345be0e4066363b3b9f1a7ccf821f3b925881986cd097e71d319e7"
    family = "unknown"
    file_name = "cf5bb941c7345be0e4066363b3b9f1a7ccf821f3b925881986cd097e71d319e7.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:59"
  condition:
    hash.sha256(0, filesize) == "cf5bb941c7345be0e4066363b3b9f1a7ccf821f3b925881986cd097e71d319e7"
}

rule MalwareBazaar_unknown_025_6438ceeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6438ceeb6f74863c6fe9981de0074cbd781e9b1cdf7ae08c9fb0a5091936f322"
    family = "unknown"
    file_name = "6438ceeb6f74863c6fe9981de0074cbd781e9b1cdf7ae08c9fb0a5091936f322.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:57"
  condition:
    hash.sha256(0, filesize) == "6438ceeb6f74863c6fe9981de0074cbd781e9b1cdf7ae08c9fb0a5091936f322"
}

rule MalwareBazaar_unknown_026_412ec3e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "412ec3e5a96657e849f427f416348d97351aa0c4692f29b783ffa6e8e00fd648"
    family = "unknown"
    file_name = "412ec3e5a96657e849f427f416348d97351aa0c4692f29b783ffa6e8e00fd648.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:54"
  condition:
    hash.sha256(0, filesize) == "412ec3e5a96657e849f427f416348d97351aa0c4692f29b783ffa6e8e00fd648"
}

rule MalwareBazaar_unknown_027_7d4eac37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d4eac37592a4a17d138b74421e93bbd426e5ab37248a280f0ee6c41538b37f7"
    family = "unknown"
    file_name = "7d4eac37592a4a17d138b74421e93bbd426e5ab37248a280f0ee6c41538b37f7.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:52"
  condition:
    hash.sha256(0, filesize) == "7d4eac37592a4a17d138b74421e93bbd426e5ab37248a280f0ee6c41538b37f7"
}

rule MalwareBazaar_unknown_028_f81c167e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f81c167e57a709eb3cb71290e7910757bdcc131ed166bb4a5b94f9a7b9311fe4"
    family = "unknown"
    file_name = "f81c167e57a709eb3cb71290e7910757bdcc131ed166bb4a5b94f9a7b9311fe4.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:50"
  condition:
    hash.sha256(0, filesize) == "f81c167e57a709eb3cb71290e7910757bdcc131ed166bb4a5b94f9a7b9311fe4"
}

rule MalwareBazaar_unknown_029_4ac72d69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ac72d69d5120ec9f95f729856de5c8c23c03bcd3d38df8333d7fcb7c1ab6eb5"
    family = "unknown"
    file_name = "4ac72d69d5120ec9f95f729856de5c8c23c03bcd3d38df8333d7fcb7c1ab6eb5.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:48"
  condition:
    hash.sha256(0, filesize) == "4ac72d69d5120ec9f95f729856de5c8c23c03bcd3d38df8333d7fcb7c1ab6eb5"
}

rule MalwareBazaar_unknown_030_ad36e9e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad36e9e4f0bcf8860fe600947bf9eac7baa1b05829f735e1145dbf9e8d1776de"
    family = "unknown"
    file_name = "ad36e9e4f0bcf8860fe600947bf9eac7baa1b05829f735e1145dbf9e8d1776de.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:45"
  condition:
    hash.sha256(0, filesize) == "ad36e9e4f0bcf8860fe600947bf9eac7baa1b05829f735e1145dbf9e8d1776de"
}

rule MalwareBazaar_unknown_031_f72ac6da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f72ac6dadd552d8e27799b945c33c933b47a1b171595850d9ce102be0997fbdb"
    family = "unknown"
    file_name = "f72ac6dadd552d8e27799b945c33c933b47a1b171595850d9ce102be0997fbdb.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:35:43"
  condition:
    hash.sha256(0, filesize) == "f72ac6dadd552d8e27799b945c33c933b47a1b171595850d9ce102be0997fbdb"
}

rule MalwareBazaar_unknown_032_dc14f1e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc14f1e442332012b8c078d6117cb6bde38c51d59aa82778ecf563bbe4e0e8a5"
    family = "unknown"
    file_name = "Roblox Hack.exe"
    file_type = "exe"
    first_seen = "2026-08-12 02:34:48"
  condition:
    hash.sha256(0, filesize) == "dc14f1e442332012b8c078d6117cb6bde38c51d59aa82778ecf563bbe4e0e8a5"
}

rule MalwareBazaar_Mirai_033_a7fee620
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7fee620e24fadf8042fa7cab43301d0cb3c49fb29d8184c7b2649b565a197d4"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-12 02:31:47"
  condition:
    hash.sha256(0, filesize) == "a7fee620e24fadf8042fa7cab43301d0cb3c49fb29d8184c7b2649b565a197d4"
}

rule MalwareBazaar_unknown_034_3e765d91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e765d910b715b2d69d17254cd5e65cbfa4590ca8847e45ce434b26fded67430"
    family = "unknown"
    file_name = "boatnet.arm5"
    file_type = "elf"
    first_seen = "2026-08-12 02:28:31"
  condition:
    hash.sha256(0, filesize) == "3e765d910b715b2d69d17254cd5e65cbfa4590ca8847e45ce434b26fded67430"
}

rule MalwareBazaar_Mirai_035_426cf29f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "426cf29f2636dd4f6a658e76c475c735d3ad517889e8d051854e085784fbb146"
    family = "Mirai"
    file_name = "boatnet.arm5"
    file_type = "elf"
    first_seen = "2026-08-12 02:27:24"
  condition:
    hash.sha256(0, filesize) == "426cf29f2636dd4f6a658e76c475c735d3ad517889e8d051854e085784fbb146"
}

rule MalwareBazaar_Mirai_036_bb5c1edc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb5c1edcefe73120769c5e8ac1f518641c99eb07e1789e12ab54434c9e98973b"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-12 02:18:25"
  condition:
    hash.sha256(0, filesize) == "bb5c1edcefe73120769c5e8ac1f518641c99eb07e1789e12ab54434c9e98973b"
}

rule MalwareBazaar_unknown_037_8525891e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8525891ea500f864200ea363c6a554de547e4672b74e52a950f16f06af58bebe"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-12 02:13:46"
  condition:
    hash.sha256(0, filesize) == "8525891ea500f864200ea363c6a554de547e4672b74e52a950f16f06af58bebe"
}

rule MalwareBazaar_Mirai_038_db0395da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db0395da3759cdb7998ca6ea997a0480fc15b04a0faa3d1bef59672552bbfd68"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-12 02:11:02"
  condition:
    hash.sha256(0, filesize) == "db0395da3759cdb7998ca6ea997a0480fc15b04a0faa3d1bef59672552bbfd68"
}

rule MalwareBazaar_Mirai_039_86df3302
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86df3302af26ae932bf1704023ea4bc9399301563cf8207bb1a119fa6d01371e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-12 02:09:27"
  condition:
    hash.sha256(0, filesize) == "86df3302af26ae932bf1704023ea4bc9399301563cf8207bb1a119fa6d01371e"
}

rule MalwareBazaar_unknown_040_de3f3a42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de3f3a426136416f1338a5d6639258273c922e37b126b25ff0b983d030bd036a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-12 02:09:26"
  condition:
    hash.sha256(0, filesize) == "de3f3a426136416f1338a5d6639258273c922e37b126b25ff0b983d030bd036a"
}

rule MalwareBazaar_unknown_041_75761cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75761cb6afe1c0f94bf99b0d0647fcc843f205904892f71c912f7d3290ed29ad"
    family = "unknown"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-12 02:06:17"
  condition:
    hash.sha256(0, filesize) == "75761cb6afe1c0f94bf99b0d0647fcc843f205904892f71c912f7d3290ed29ad"
}

rule MalwareBazaar_Vidar_042_468ec617
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "468ec617a18a15cf015d73178ab210c2a24311b0b584eb75e8dbf2fedf4fc15f"
    family = "Vidar"
    file_name = "468ec617a18a15cf015d73178ab210c2a24311b0b584eb75e8dbf2fedf4fc15f.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:30"
  condition:
    hash.sha256(0, filesize) == "468ec617a18a15cf015d73178ab210c2a24311b0b584eb75e8dbf2fedf4fc15f"
}

rule MalwareBazaar_unknown_043_4f18fb2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f18fb2dfbd0673d83f8ae33461761dcea0a38510a731881ba5cc96732c2ef63"
    family = "unknown"
    file_name = "4f18fb2dfbd0673d83f8ae33461761dcea0a38510a731881ba5cc96732c2ef63.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:28"
  condition:
    hash.sha256(0, filesize) == "4f18fb2dfbd0673d83f8ae33461761dcea0a38510a731881ba5cc96732c2ef63"
}

rule MalwareBazaar_unknown_044_c3bb2ed2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3bb2ed2e9082d896d46c00a900e5dd07591a44dbe4cf5c6581c3d86a10df6a9"
    family = "unknown"
    file_name = "c3bb2ed2e9082d896d46c00a900e5dd07591a44dbe4cf5c6581c3d86a10df6a9.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:25"
  condition:
    hash.sha256(0, filesize) == "c3bb2ed2e9082d896d46c00a900e5dd07591a44dbe4cf5c6581c3d86a10df6a9"
}

rule MalwareBazaar_unknown_045_b53cda93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b53cda93234482a8c2369722b4e7b43fcf08fc4a60662343ea6d40dfd570f148"
    family = "unknown"
    file_name = "b53cda93234482a8c2369722b4e7b43fcf08fc4a60662343ea6d40dfd570f148.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:22"
  condition:
    hash.sha256(0, filesize) == "b53cda93234482a8c2369722b4e7b43fcf08fc4a60662343ea6d40dfd570f148"
}

rule MalwareBazaar_unknown_046_f51ae7f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f51ae7f0c46bdeb283578db0a83c79e7cf92919f34eeedba9165d7eecf39f689"
    family = "unknown"
    file_name = "f51ae7f0c46bdeb283578db0a83c79e7cf92919f34eeedba9165d7eecf39f689.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:20"
  condition:
    hash.sha256(0, filesize) == "f51ae7f0c46bdeb283578db0a83c79e7cf92919f34eeedba9165d7eecf39f689"
}

rule MalwareBazaar_unknown_047_b8430c0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8430c0a28c5e9fa15d843bcc665e7e87d248d3960b84925bea5f96cc082e1af"
    family = "unknown"
    file_name = "b8430c0a28c5e9fa15d843bcc665e7e87d248d3960b84925bea5f96cc082e1af.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:18"
  condition:
    hash.sha256(0, filesize) == "b8430c0a28c5e9fa15d843bcc665e7e87d248d3960b84925bea5f96cc082e1af"
}

rule MalwareBazaar_unknown_048_4ac6ab5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ac6ab5d9557368b0cfd1f5f8b122cfe11524d93def1c53030a30e5a4886e362"
    family = "unknown"
    file_name = "4ac6ab5d9557368b0cfd1f5f8b122cfe11524d93def1c53030a30e5a4886e362.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:15"
  condition:
    hash.sha256(0, filesize) == "4ac6ab5d9557368b0cfd1f5f8b122cfe11524d93def1c53030a30e5a4886e362"
}

rule MalwareBazaar_unknown_049_719b5941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "719b5941f17a6bb3b8692f531d7f335c774cd679c9662baed9364cd08f40f6a4"
    family = "unknown"
    file_name = "719b5941f17a6bb3b8692f531d7f335c774cd679c9662baed9364cd08f40f6a4.bin"
    file_type = "exe"
    first_seen = "2026-08-12 02:05:12"
  condition:
    hash.sha256(0, filesize) == "719b5941f17a6bb3b8692f531d7f335c774cd679c9662baed9364cd08f40f6a4"
}

rule MalwareBazaar_unknown_050_5fa4d1b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fa4d1b124b9129e088b730ee262f8a6d6afb3ee355fb60b0b336e08fe0a6006"
    family = "unknown"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-12 02:04:56"
  condition:
    hash.sha256(0, filesize) == "5fa4d1b124b9129e088b730ee262f8a6d6afb3ee355fb60b0b336e08fe0a6006"
}

rule MalwareBazaar_unknown_051_8c7dfe6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7dfe6e0c62d3ff25f1f0b24c78a9d7932bdd8c20a9ce69881bb86e28f02ba6"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-12 02:01:45"
  condition:
    hash.sha256(0, filesize) == "8c7dfe6e0c62d3ff25f1f0b24c78a9d7932bdd8c20a9ce69881bb86e28f02ba6"
}

rule MalwareBazaar_unknown_052_52cddeab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52cddeab331e78ae9afb57aa525fdba03ded8d8ef58a58f0265e4dc3a3d1c042"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-12 02:00:27"
  condition:
    hash.sha256(0, filesize) == "52cddeab331e78ae9afb57aa525fdba03ded8d8ef58a58f0265e4dc3a3d1c042"
}

rule MalwareBazaar_unknown_053_e02b22db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e02b22dbb4074aa2aef9f606d7b86808f882ab9752dadd18bc486176d4c99da9"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-12 02:00:25"
  condition:
    hash.sha256(0, filesize) == "e02b22dbb4074aa2aef9f606d7b86808f882ab9752dadd18bc486176d4c99da9"
}

rule MalwareBazaar_Mirai_054_0cdb6ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cdb6ae2118a96d618839532a4cd1166f0f1c9d83c6e020a19cbc5e7e5e0b30a"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-12 01:52:43"
  condition:
    hash.sha256(0, filesize) == "0cdb6ae2118a96d618839532a4cd1166f0f1c9d83c6e020a19cbc5e7e5e0b30a"
}

rule MalwareBazaar_unknown_055_97c6e06d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97c6e06d93c29474c6aec258a9dfa0b2f6c1071b46b8b7dfec3d8e0a1e4a9f09"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-12 01:52:28"
  condition:
    hash.sha256(0, filesize) == "97c6e06d93c29474c6aec258a9dfa0b2f6c1071b46b8b7dfec3d8e0a1e4a9f09"
}

rule MalwareBazaar_Mirai_056_2c33eca7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c33eca7982abb1e2bfad8e559af61c0326e19fb48c21059eebc5dbf14f866c2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-12 01:51:49"
  condition:
    hash.sha256(0, filesize) == "2c33eca7982abb1e2bfad8e559af61c0326e19fb48c21059eebc5dbf14f866c2"
}

rule MalwareBazaar_Mirai_057_2f823f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f823f9602e103771ff0dcf0828107a3e10ad672d14541b8dc55e6c545b8ce16"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-12 01:48:54"
  condition:
    hash.sha256(0, filesize) == "2f823f9602e103771ff0dcf0828107a3e10ad672d14541b8dc55e6c545b8ce16"
}

rule MalwareBazaar_Mirai_058_0c798c8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c798c8d0b07bc618204c6f2fc9365d2efb023816e13af33a7a4d4ed86c8cb82"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-12 01:48:52"
  condition:
    hash.sha256(0, filesize) == "0c798c8d0b07bc618204c6f2fc9365d2efb023816e13af33a7a4d4ed86c8cb82"
}

rule MalwareBazaar_Mirai_059_8bf58a0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bf58a0e93c7bf558d7edf84f24a6e690fc8cfb0e48b2bab4060240606c61c8d"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-12 01:47:30"
  condition:
    hash.sha256(0, filesize) == "8bf58a0e93c7bf558d7edf84f24a6e690fc8cfb0e48b2bab4060240606c61c8d"
}

rule MalwareBazaar_Mirai_060_ab849c88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab849c8883fdfa4fab650d3f1ae76db47d4facbaca1a5a97d1e6d6d0512961d2"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-12 01:47:29"
  condition:
    hash.sha256(0, filesize) == "ab849c8883fdfa4fab650d3f1ae76db47d4facbaca1a5a97d1e6d6d0512961d2"
}

rule MalwareBazaar_unknown_061_40398788
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4039878821a2d5636b60b8d1d4290a765b22f66fb338cfc9091055b4fa929262"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-12 01:47:27"
  condition:
    hash.sha256(0, filesize) == "4039878821a2d5636b60b8d1d4290a765b22f66fb338cfc9091055b4fa929262"
}

rule MalwareBazaar_unknown_062_9e9094cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e9094cb5d81ce2c4c6bc13a5e6bb76bdf8883c225c99b6c9f9928b212f1954d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-12 01:42:56"
  condition:
    hash.sha256(0, filesize) == "9e9094cb5d81ce2c4c6bc13a5e6bb76bdf8883c225c99b6c9f9928b212f1954d"
}

rule MalwareBazaar_unknown_063_675129bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "675129bca5e2d893f1852243d6cd4c8ffa8cb8dbc9e60deb794e35fdb5b50e80"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-12 01:42:55"
  condition:
    hash.sha256(0, filesize) == "675129bca5e2d893f1852243d6cd4c8ffa8cb8dbc9e60deb794e35fdb5b50e80"
}

rule MalwareBazaar_unknown_064_84bedc6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84bedc6e24f76a488a88f28078cca8d8d0a720201e753119b7d51f20c070a023"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-12 01:39:38"
  condition:
    hash.sha256(0, filesize) == "84bedc6e24f76a488a88f28078cca8d8d0a720201e753119b7d51f20c070a023"
}

rule MalwareBazaar_Mirai_065_6d10e468
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d10e468b2d515ac2a5a9113c4feb3ad06b3cd7f1df92fd94acf056c35836996"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-12 01:38:30"
  condition:
    hash.sha256(0, filesize) == "6d10e468b2d515ac2a5a9113c4feb3ad06b3cd7f1df92fd94acf056c35836996"
}

rule MalwareBazaar_unknown_066_9a37eea4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a37eea45a4d792638abcca359020013eef8be927baf1b5a7440a8a1b91e9224"
    family = "unknown"
    file_name = "9a37eea45a4d792638abcca359020013eef8be927baf1b5a7440a8a1b91e9224.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:35:00"
  condition:
    hash.sha256(0, filesize) == "9a37eea45a4d792638abcca359020013eef8be927baf1b5a7440a8a1b91e9224"
}

rule MalwareBazaar_unknown_067_16d66eeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16d66eebf8d2ec738234449ec480e0a9eb98a140347671f4650fead082c01f4f"
    family = "unknown"
    file_name = "16d66eebf8d2ec738234449ec480e0a9eb98a140347671f4650fead082c01f4f.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:58"
  condition:
    hash.sha256(0, filesize) == "16d66eebf8d2ec738234449ec480e0a9eb98a140347671f4650fead082c01f4f"
}

rule MalwareBazaar_unknown_068_8a461217
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a461217574508eec77f12bd6cd3ad1d43ba28050e853ff664fdd0873382377e"
    family = "unknown"
    file_name = "8a461217574508eec77f12bd6cd3ad1d43ba28050e853ff664fdd0873382377e.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:56"
  condition:
    hash.sha256(0, filesize) == "8a461217574508eec77f12bd6cd3ad1d43ba28050e853ff664fdd0873382377e"
}

rule MalwareBazaar_unknown_069_5a35dea1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a35dea1e941c4ae1f19d3ec781aa816cdfcde2982b4be30db1f9ef933329de3"
    family = "unknown"
    file_name = "5a35dea1e941c4ae1f19d3ec781aa816cdfcde2982b4be30db1f9ef933329de3.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:54"
  condition:
    hash.sha256(0, filesize) == "5a35dea1e941c4ae1f19d3ec781aa816cdfcde2982b4be30db1f9ef933329de3"
}

rule MalwareBazaar_unknown_070_8936b492
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8936b492f1e4a8c7685cb07d40df6e818cb8eb2997d2d2542a26c2204a9224fc"
    family = "unknown"
    file_name = "8936b492f1e4a8c7685cb07d40df6e818cb8eb2997d2d2542a26c2204a9224fc.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:52"
  condition:
    hash.sha256(0, filesize) == "8936b492f1e4a8c7685cb07d40df6e818cb8eb2997d2d2542a26c2204a9224fc"
}

rule MalwareBazaar_unknown_071_06c9957d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06c9957d333dcc91e5a13fd7feb79d18aeaa5cd929df0cdf82085f98481afa66"
    family = "unknown"
    file_name = "06c9957d333dcc91e5a13fd7feb79d18aeaa5cd929df0cdf82085f98481afa66.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:50"
  condition:
    hash.sha256(0, filesize) == "06c9957d333dcc91e5a13fd7feb79d18aeaa5cd929df0cdf82085f98481afa66"
}

rule MalwareBazaar_unknown_072_d9a5009f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9a5009fa613140dbcb9d185278cc6c9d4a34984979a1414c5a9c3dc786c6874"
    family = "unknown"
    file_name = "d9a5009fa613140dbcb9d185278cc6c9d4a34984979a1414c5a9c3dc786c6874.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:48"
  condition:
    hash.sha256(0, filesize) == "d9a5009fa613140dbcb9d185278cc6c9d4a34984979a1414c5a9c3dc786c6874"
}

rule MalwareBazaar_unknown_073_d2133a2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2133a2a00bc7f25331d795316cf3b7b9ed3f36003897e99ed5cd5c56d669dad"
    family = "unknown"
    file_name = "d2133a2a00bc7f25331d795316cf3b7b9ed3f36003897e99ed5cd5c56d669dad.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:34:46"
  condition:
    hash.sha256(0, filesize) == "d2133a2a00bc7f25331d795316cf3b7b9ed3f36003897e99ed5cd5c56d669dad"
}

rule MalwareBazaar_Mirai_074_1d5c206d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d5c206d5d27fc95aa51c40e5428ab1bc0468c994e5b6b20f6b861521deac226"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-12 01:34:34"
  condition:
    hash.sha256(0, filesize) == "1d5c206d5d27fc95aa51c40e5428ab1bc0468c994e5b6b20f6b861521deac226"
}

rule MalwareBazaar_Mirai_075_e62736b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e62736b6d3e6b82a82650b82d924f9018b040416294ec6cc858135f724264444"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-12 01:34:32"
  condition:
    hash.sha256(0, filesize) == "e62736b6d3e6b82a82650b82d924f9018b040416294ec6cc858135f724264444"
}

rule MalwareBazaar_Mirai_076_54396958
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5439695869e49b0deb3c8de9c07aac99cd32515f5bcdfa5aff546e151911b06b"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-12 01:33:37"
  condition:
    hash.sha256(0, filesize) == "5439695869e49b0deb3c8de9c07aac99cd32515f5bcdfa5aff546e151911b06b"
}

rule MalwareBazaar_Mirai_077_20385fae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20385fae2224fb4fa4a5f4aaa01a8a58ae1a53a889fdd65edce8414e4ec2be3f"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-12 01:33:36"
  condition:
    hash.sha256(0, filesize) == "20385fae2224fb4fa4a5f4aaa01a8a58ae1a53a889fdd65edce8414e4ec2be3f"
}

rule MalwareBazaar_unknown_078_0f0111f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f0111f70ed0f619d5a47744dd319ba00312bee71f545e51e1c5e754df837d5b"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-12 01:28:36"
  condition:
    hash.sha256(0, filesize) == "0f0111f70ed0f619d5a47744dd319ba00312bee71f545e51e1c5e754df837d5b"
}

rule MalwareBazaar_unknown_079_3a319275
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a3192754cbd88649ada4b0d33d9d2c6f4348960271084f74d4686ebdc34c670"
    family = "unknown"
    file_name = "main.sh4"
    file_type = "elf"
    first_seen = "2026-08-12 01:28:34"
  condition:
    hash.sha256(0, filesize) == "3a3192754cbd88649ada4b0d33d9d2c6f4348960271084f74d4686ebdc34c670"
}

rule MalwareBazaar_unknown_080_c5dd9e8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5dd9e8c0208ef12b84edbb57362e2a07c5c0bf94b581036411dfa55962b6129"
    family = "unknown"
    file_name = "c5dd9e8c0208ef12b84edbb57362e2a07c5c0bf94b581036411dfa55962b6129.elf"
    file_type = "elf"
    first_seen = "2026-08-12 01:18:52"
  condition:
    hash.sha256(0, filesize) == "c5dd9e8c0208ef12b84edbb57362e2a07c5c0bf94b581036411dfa55962b6129"
}

rule MalwareBazaar_unknown_081_cea846a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cea846a93d72c55d3a36191e995d89a8b6774f4b5de22680685b87f8c07d0d5e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-12 01:16:59"
  condition:
    hash.sha256(0, filesize) == "cea846a93d72c55d3a36191e995d89a8b6774f4b5de22680685b87f8c07d0d5e"
}

rule MalwareBazaar_WannaCry_082_1b2db3fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b2db3fb7efde4444b041844049425c2106f53393305ee8ee528990cb9d64d91"
    family = "WannaCry"
    file_name = "1b2db3fb7efde4444b041844049425c2106f53393305ee8ee528990cb9d64d91"
    file_type = "exe"
    first_seen = "2026-08-12 01:15:12"
  condition:
    hash.sha256(0, filesize) == "1b2db3fb7efde4444b041844049425c2106f53393305ee8ee528990cb9d64d91"
}

rule MalwareBazaar_unknown_083_98c3a5f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98c3a5f5142672e5206dbe7c7858541f215686cf836a11ce729763de21db96f2"
    family = "unknown"
    file_name = "98c3a5f5142672e5206dbe7c7858541f215686cf836a11ce729763de21db96f2.elf"
    file_type = "elf"
    first_seen = "2026-08-12 01:13:59"
  condition:
    hash.sha256(0, filesize) == "98c3a5f5142672e5206dbe7c7858541f215686cf836a11ce729763de21db96f2"
}

rule MalwareBazaar_Mirai_084_e32122ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e32122ad84f511843008e2d7f8c1f3f80df5f38ded4e7e3ae56bddefad0d6d11"
    family = "Mirai"
    file_name = "e32122ad84f511843008e2d7f8c1f3f80df5f38ded4e7e3ae56bddefad0d6d11.elf"
    file_type = "elf"
    first_seen = "2026-08-12 01:13:55"
  condition:
    hash.sha256(0, filesize) == "e32122ad84f511843008e2d7f8c1f3f80df5f38ded4e7e3ae56bddefad0d6d11"
}

rule MalwareBazaar_SalatStealer_085_cbc9a1a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbc9a1a22f5cef93269bf47f2cb52c566dc95bc536a62ece27cbea006d6c63f4"
    family = "SalatStealer"
    file_name = "MM2DUPE.exe"
    file_type = "exe"
    first_seen = "2026-08-12 01:08:49"
  condition:
    hash.sha256(0, filesize) == "cbc9a1a22f5cef93269bf47f2cb52c566dc95bc536a62ece27cbea006d6c63f4"
}

rule MalwareBazaar_unknown_086_43ec2662
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43ec2662d839781bbd41eb59f40ce37b0e505bf836d31410bc944a19fe72d1fc"
    family = "unknown"
    file_name = "MV_SEA_LADY_VESSEL_MAIN_INFORMATION.js"
    file_type = "js"
    first_seen = "2026-08-12 01:08:38"
  condition:
    hash.sha256(0, filesize) == "43ec2662d839781bbd41eb59f40ce37b0e505bf836d31410bc944a19fe72d1fc"
}

rule MalwareBazaar_unknown_087_876634b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "876634b69315538b382e7e046e61c3323c704737cb4b2b2d637aa25382d513a1"
    family = "unknown"
    file_name = "876634b69315538b382e7e046e61c3323c704737cb4b2b2d637aa25382d513a1.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:36"
  condition:
    hash.sha256(0, filesize) == "876634b69315538b382e7e046e61c3323c704737cb4b2b2d637aa25382d513a1"
}

rule MalwareBazaar_Vidar_088_3fb4958a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fb4958a2615b4652d6b55b22d623ca8409e1d452ca6134ce00a4caa118b74e9"
    family = "Vidar"
    file_name = "3fb4958a2615b4652d6b55b22d623ca8409e1d452ca6134ce00a4caa118b74e9.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:34"
  condition:
    hash.sha256(0, filesize) == "3fb4958a2615b4652d6b55b22d623ca8409e1d452ca6134ce00a4caa118b74e9"
}

rule MalwareBazaar_Vidar_089_3d8ea1a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d8ea1a7e14847c1b25582a02cd208bd700de5420932b2905d4cf4272114d630"
    family = "Vidar"
    file_name = "3d8ea1a7e14847c1b25582a02cd208bd700de5420932b2905d4cf4272114d630.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:23"
  condition:
    hash.sha256(0, filesize) == "3d8ea1a7e14847c1b25582a02cd208bd700de5420932b2905d4cf4272114d630"
}

rule MalwareBazaar_Vidar_090_1f40d6ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f40d6ff2f88c58bf2a2685da8a847fd9cf7a54e28a3ea994390bd0af4e96a80"
    family = "Vidar"
    file_name = "1f40d6ff2f88c58bf2a2685da8a847fd9cf7a54e28a3ea994390bd0af4e96a80.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:21"
  condition:
    hash.sha256(0, filesize) == "1f40d6ff2f88c58bf2a2685da8a847fd9cf7a54e28a3ea994390bd0af4e96a80"
}

rule MalwareBazaar_unknown_091_0b3ce056
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b3ce056d3aa8ec05069acc49ae887e2b2b4d210d4219221778abdbda9f4c458"
    family = "unknown"
    file_name = "0b3ce056d3aa8ec05069acc49ae887e2b2b4d210d4219221778abdbda9f4c458.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:19"
  condition:
    hash.sha256(0, filesize) == "0b3ce056d3aa8ec05069acc49ae887e2b2b4d210d4219221778abdbda9f4c458"
}

rule MalwareBazaar_unknown_092_fda5fdd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fda5fdd2f8923bc9f7a397628ec274981e6983d3de812fe5d14a4c7fcd4282b6"
    family = "unknown"
    file_name = "fda5fdd2f8923bc9f7a397628ec274981e6983d3de812fe5d14a4c7fcd4282b6.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:17"
  condition:
    hash.sha256(0, filesize) == "fda5fdd2f8923bc9f7a397628ec274981e6983d3de812fe5d14a4c7fcd4282b6"
}

rule MalwareBazaar_unknown_093_53dbad87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53dbad87c3016f7ae7f7561f58fdbf5fe5fa32c248c7678928dd2f34be69ee01"
    family = "unknown"
    file_name = "53dbad87c3016f7ae7f7561f58fdbf5fe5fa32c248c7678928dd2f34be69ee01.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:15"
  condition:
    hash.sha256(0, filesize) == "53dbad87c3016f7ae7f7561f58fdbf5fe5fa32c248c7678928dd2f34be69ee01"
}

rule MalwareBazaar_unknown_094_d84030d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d84030d162793a2e0a87c3b11b5b997332b80ec53d2f12c309339cb290131f2d"
    family = "unknown"
    file_name = "d84030d162793a2e0a87c3b11b5b997332b80ec53d2f12c309339cb290131f2d.bin"
    file_type = "exe"
    first_seen = "2026-08-12 01:04:13"
  condition:
    hash.sha256(0, filesize) == "d84030d162793a2e0a87c3b11b5b997332b80ec53d2f12c309339cb290131f2d"
}

rule MalwareBazaar_unknown_095_a5d5bd49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5d5bd497eda2289310c6559d89caaa2013485fd2c19a06b3c03ef507607fdd6"
    family = "unknown"
    file_name = "Windows.Internal.System.UserProfile.zip"
    file_type = "zip"
    first_seen = "2026-08-12 00:36:27"
  condition:
    hash.sha256(0, filesize) == "a5d5bd497eda2289310c6559d89caaa2013485fd2c19a06b3c03ef507607fdd6"
}

rule MalwareBazaar_unknown_096_4dfba261
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dfba261e914d206c8417ea0fd93a8a760ffef744fabe799ae25f52b0deca527"
    family = "unknown"
    file_name = "Windows.AI.Agents.zip"
    file_type = "zip"
    first_seen = "2026-08-12 00:35:22"
  condition:
    hash.sha256(0, filesize) == "4dfba261e914d206c8417ea0fd93a8a760ffef744fabe799ae25f52b0deca527"
}

rule MalwareBazaar_unknown_097_42a0c075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42a0c075c468870f9c705a605d49de7d4c2f3faad9783f54c5b589e9495bbedc"
    family = "unknown"
    file_name = "42a0c075c468870f9c705a605d49de7d4c2f3faad9783f54c5b589e9495bbedc.bin"
    file_type = "exe"
    first_seen = "2026-08-12 00:34:10"
  condition:
    hash.sha256(0, filesize) == "42a0c075c468870f9c705a605d49de7d4c2f3faad9783f54c5b589e9495bbedc"
}

rule MalwareBazaar_Vidar_098_101a3bfb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "101a3bfb62b015b49bbe08f3f53c5174c94f4d9633ac982e295274f661b35466"
    family = "Vidar"
    file_name = "101a3bfb62b015b49bbe08f3f53c5174c94f4d9633ac982e295274f661b35466.bin"
    file_type = "exe"
    first_seen = "2026-08-12 00:34:07"
  condition:
    hash.sha256(0, filesize) == "101a3bfb62b015b49bbe08f3f53c5174c94f4d9633ac982e295274f661b35466"
}

rule MalwareBazaar_unknown_099_bbf4b40b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbf4b40be130ef821968942b27184f6f70c1faecce7a5f4e9aa25eac8d9b47ea"
    family = "unknown"
    file_name = "bbf4b40be130ef821968942b27184f6f70c1faecce7a5f4e9aa25eac8d9b47ea.bin"
    file_type = "exe"
    first_seen = "2026-08-12 00:34:05"
  condition:
    hash.sha256(0, filesize) == "bbf4b40be130ef821968942b27184f6f70c1faecce7a5f4e9aa25eac8d9b47ea"
}

rule MalwareBazaar_unknown_100_f0483771
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f04837713c07587b67f080677b5914b14124b158eca4bcc3cf7e7a6ae5afcd49"
    family = "unknown"
    file_name = "f04837713c07587b67f080677b5914b14124b158eca4bcc3cf7e7a6ae5afcd49.bin"
    file_type = "exe"
    first_seen = "2026-08-12 00:34:03"
  condition:
    hash.sha256(0, filesize) == "f04837713c07587b67f080677b5914b14124b158eca4bcc3cf7e7a6ae5afcd49"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

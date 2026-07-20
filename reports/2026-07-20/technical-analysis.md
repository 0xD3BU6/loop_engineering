# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-20

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 652 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 652 |
| Unique family labels | 9 |
| Unique file types | 3 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 65 |
| unknown | 25 |
| Amadey | 2 |
| ValleyRAT | 2 |
| RemusStealer | 2 |
| MaskGramStealer | 1 |
| Gafgyt | 1 |
| Phorpiex | 1 |
| RedLineStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 72 |
| exe | 17 |
| sh | 11 |

## Per-Sample Analysis

### Sample 1: `fa1e42eccf2edbaa`

| Field | Value |
|---|---|
| SHA-256 | `fa1e42eccf2edbaa7306cd40636bf579a6588e3d0fa61584e1ccb92a00d01ecf` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-20 03:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f35901a1bfb87b6c31f16bed491bc64d` |
| SHA-1 | `87a981d160bd9ec14de5fdb46f74f989fbf559b5` |
| SHA-256 | `fa1e42eccf2edbaa7306cd40636bf579a6588e3d0fa61584e1ccb92a00d01ecf` |
| SHA3-384 | `e5a68799599642c0f63f210adb4d8f2fdb5aa7f7d517f2f48f7b0576863d850b22994585a489d34470bb91f298a4b2ee` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1BAE6331C56D012FBEEA3843CDDD19195D9AEF46A6B3AC6CF43548321AF570E04D3EA12` |
| SSDEEP | `393216:ZLRAo/tmA29LctHwymYXMCHWUjX7cuI3/PGTAI:ZLRAfAcLyHxXMb8X4H/O7` |
| ICON-DHASH | `e4b960c0dcf97258` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_fa1e42ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa1e42eccf2edbaa7306cd40636bf579a6588e3d0fa61584e1ccb92a00d01ecf"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 03:52:08"
  condition:
    hash.sha256(0, filesize) == "fa1e42eccf2edbaa7306cd40636bf579a6588e3d0fa61584e1ccb92a00d01ecf"
}
```

### Sample 2: `c125bbd2333186b2`

| Field | Value |
|---|---|
| SHA-256 | `c125bbd2333186b24a2dc74b99c7f3db4fca9fbe86af42e68cc4999252453a2a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-20 02:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6e9c0fbdb1865cb396d7d8f9e810eba` |
| SHA-1 | `0ae402fdc9baf13b4143c8fe10e90baea060d043` |
| SHA-256 | `c125bbd2333186b24a2dc74b99c7f3db4fca9fbe86af42e68cc4999252453a2a` |
| SHA3-384 | `6e6e60337b476b46cdfb5f21c2ad3a8ec0806a0d4694a820b40e4868d405d6132cff49d668a88e76575d0aeb6a56807b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T114E633685AE052FAE4B7503CEED10696D1AA74604B31C9DF0B9C9AB55F1B0E09E3DF03` |
| SSDEEP | `393216:Fte4wcR8OajKjccqclXMCHWUjX8cuI3/PGTAI:F3bR6jaD9XMb8XpH/O7` |
| ICON-DHASH | `007860c0dcf9f100` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_c125bbd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c125bbd2333186b24a2dc74b99c7f3db4fca9fbe86af42e68cc4999252453a2a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 02:52:09"
  condition:
    hash.sha256(0, filesize) == "c125bbd2333186b24a2dc74b99c7f3db4fca9fbe86af42e68cc4999252453a2a"
}
```

### Sample 3: `da49d5a6abbb9643`

| Field | Value |
|---|---|
| SHA-256 | `da49d5a6abbb96438cd2daecd2643fb5f38122ce4d9cda6d072704e54c17d3ed` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-20 02:11:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `054a878b0602e90b03be851d84fca1fa` |
| SHA-1 | `d8f022c3628f7e33a173054793c81a302946aef2` |
| SHA-256 | `da49d5a6abbb96438cd2daecd2643fb5f38122ce4d9cda6d072704e54c17d3ed` |
| SHA3-384 | `89dec56bf1d09ee2a581ebb5cbb50bae31c9c021507029ce19513c6df7f8ed45c8b2450d5a355d441ee5e6b20695ef16` |
| TLSH | `T109236D6516857C14AE99C4365C7F2F0CBDAD43E6314492DE7FCE3CF28C4A6AC920861D` |
| SSDEEP | `768:Sr9NyXsZztCBZ9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:8HusZhcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_da49d5a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da49d5a6abbb96438cd2daecd2643fb5f38122ce4d9cda6d072704e54c17d3ed"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-20 02:11:36"
  condition:
    hash.sha256(0, filesize) == "da49d5a6abbb96438cd2daecd2643fb5f38122ce4d9cda6d072704e54c17d3ed"
}
```

### Sample 4: `c3ba74fb10475f9e`

| Field | Value |
|---|---|
| SHA-256 | `c3ba74fb10475f9e9db534ad484bbcfaa7ee1fd571639b35f57906e1fca1d716` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-20 02:01:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf76fba4e234b4ddb25cd20bbf10476f` |
| SHA-1 | `26c2ebdefb901d3b40c81baadada8213a12258eb` |
| SHA-256 | `c3ba74fb10475f9e9db534ad484bbcfaa7ee1fd571639b35f57906e1fca1d716` |
| SHA3-384 | `18a87cb65740eed9a453c21d4336c920e6438afa6e97d58daa607bf350bf36b38d24d408afe9bd07f287e8f43307d49e` |
| TLSH | `T18204E80AAF500EB7E85FDD3B05E93B0635CC755322E83B753634D918BA0A64B0AE3D64` |
| SSDEEP | `3072:WeVk6qQDxP/mZOJep4VkEYbOdrCo/lIE7PhGX:XVLPDjVkEYKRSE7w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_c3ba74fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3ba74fb10475f9e9db534ad484bbcfaa7ee1fd571639b35f57906e1fca1d716"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 02:01:35"
  condition:
    hash.sha256(0, filesize) == "c3ba74fb10475f9e9db534ad484bbcfaa7ee1fd571639b35f57906e1fca1d716"
}
```

### Sample 5: `5f85a860b374bb80`

| Field | Value |
|---|---|
| SHA-256 | `5f85a860b374bb803aff4cc9e1d928b5ad3d678c0e252b45e7b88d3bed88b152` |
| Family label | `Mirai` |
| File name | `ohshit.mpsl` |
| File type | `elf` |
| First seen | `2026-07-20 01:59:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51a2ed663fe6309f4903007807f35080` |
| SHA-1 | `e26999d09f28c57b6e9155f8154fe22df2946eeb` |
| SHA-256 | `5f85a860b374bb803aff4cc9e1d928b5ad3d678c0e252b45e7b88d3bed88b152` |
| SHA3-384 | `7eaad3d4bbf27335819d12e0ae4196aaedd5fe29d55be72bf7df088704a69604da8f6726acf7d8d47c41ebe5fdcc536d` |
| TLSH | `T105E3D649AF610FF7E8AFCD3709ED2B05258C596721A83F35B974D418B24B28F16E3960` |
| SSDEEP | `3072:2Ru0D1FV24MgEf4cyOKnaOsGQ/d3jCk7H1Hvv0n:2RXD3VbMgEf4cy3naOsb/d3jCkTNv0n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_5f85a860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f85a860b374bb803aff4cc9e1d928b5ad3d678c0e252b45e7b88d3bed88b152"
    family = "Mirai"
    file_name = "ohshit.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 01:59:25"
  condition:
    hash.sha256(0, filesize) == "5f85a860b374bb803aff4cc9e1d928b5ad3d678c0e252b45e7b88d3bed88b152"
}
```

### Sample 6: `45ce79bbac91e3ca`

| Field | Value |
|---|---|
| SHA-256 | `45ce79bbac91e3ca67d3cc7dd150ada9109cf6a52b09d3e6eaad8adb4df30777` |
| Family label | `unknown` |
| File name | `mload.sh` |
| File type | `sh` |
| First seen | `2026-07-20 01:55:21` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83a52d42c62bec87c510d55965565c0f` |
| SHA-1 | `43b49da0b67b0fe4428cd9939cdb00a39e79ff24` |
| SHA-256 | `45ce79bbac91e3ca67d3cc7dd150ada9109cf6a52b09d3e6eaad8adb4df30777` |
| SHA3-384 | `b1d95615d36230a0b36ba579edb2b5e13aff9e072609e291380126e2db0c22a1f80d914277fe60750400e5900fc19e0a` |
| TLSH | `T1BA314B0DC2C2EA2095815CE6F0C69112B913D7DCBBA31E74FE0AE7B1782C8497132D72` |
| SSDEEP | `48:QvQhnojhnojhnojhno0jDGEeECEhEoEgoEP:AQhnAhnAhnAhn/jqEeECEhEoErEP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_45ce79bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45ce79bbac91e3ca67d3cc7dd150ada9109cf6a52b09d3e6eaad8adb4df30777"
    family = "unknown"
    file_name = "mload.sh"
    file_type = "sh"
    first_seen = "2026-07-20 01:55:21"
  condition:
    hash.sha256(0, filesize) == "45ce79bbac91e3ca67d3cc7dd150ada9109cf6a52b09d3e6eaad8adb4df30777"
}
```

### Sample 7: `bec299c617dfa95b`

| Field | Value |
|---|---|
| SHA-256 | `bec299c617dfa95b0b9ccb083ee9d2510b4b1c8f5785d1d6d9f389a1b9e4f9b9` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-20 01:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f59c96c0279175790adc28261fc77ee1` |
| SHA-1 | `d9f6cb49425f4cdff58608b2346b66a5dcef48b1` |
| SHA-256 | `bec299c617dfa95b0b9ccb083ee9d2510b4b1c8f5785d1d6d9f389a1b9e4f9b9` |
| SHA3-384 | `4b1fe39155f6d6e417c9921bc4520a7b5a936c2493baa918ddab03136253df38a0fe6b336f7ef922e8ff7542de3ea7fa` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T120E6332C65C016EEEE73417DEEF012B5E5B5B4720331C99B4BA8C366EE231A1493A717` |
| SSDEEP | `393216:qOT3DlJLM8f+2mM3EksU2bMZXMCHWUjX1cuI3/PGTAI:qw3vLM8f+2mjU2CXMb8XCH/O7` |
| ICON-DHASH | `e4b960c0dcf97258` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_bec299c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bec299c617dfa95b0b9ccb083ee9d2510b4b1c8f5785d1d6d9f389a1b9e4f9b9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 01:52:09"
  condition:
    hash.sha256(0, filesize) == "bec299c617dfa95b0b9ccb083ee9d2510b4b1c8f5785d1d6d9f389a1b9e4f9b9"
}
```

### Sample 8: `3bc7efeed4bbebc6`

| Field | Value |
|---|---|
| SHA-256 | `3bc7efeed4bbebc6a515be55736e6726dd3873553b00e70af513f8ab05761422` |
| Family label | `Mirai` |
| File name | `ohshit.arm` |
| File type | `elf` |
| First seen | `2026-07-20 01:48:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ec9908086bfe5344e03908ddc7a27a4` |
| SHA-1 | `fd3493cc67e88d67ca01bf22d1b1c283e3f654fb` |
| SHA-256 | `3bc7efeed4bbebc6a515be55736e6726dd3873553b00e70af513f8ab05761422` |
| SHA3-384 | `dea9c70b6765d1562787f1e6f904be7d148e32bad48ffe595bdf797979aa805d3c8ab6f8d5d1f9d313523b1800405204` |
| TLSH | `T103B34C45FD819662C6C7177AFB5E628D332363A4D3DA32039E285F21338B59B0E7B641` |
| TELFHASH | `t132f0dd85ce549cd876d22601422eb60359ecb1cf3b4a70931ca99ede00035c4b03441b` |
| SSDEEP | `3072:Q3YMO1a6Tmt1OE7UpJHuW4vwCdQEkfykjYFld8B:Q3RO1a6TmLOE7CduW4vZdQEkf7jgld8B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_3bc7efee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bc7efeed4bbebc6a515be55736e6726dd3873553b00e70af513f8ab05761422"
    family = "Mirai"
    file_name = "ohshit.arm"
    file_type = "elf"
    first_seen = "2026-07-20 01:48:40"
  condition:
    hash.sha256(0, filesize) == "3bc7efeed4bbebc6a515be55736e6726dd3873553b00e70af513f8ab05761422"
}
```

### Sample 9: `5c299c0278faf2fb`

| Field | Value |
|---|---|
| SHA-256 | `5c299c0278faf2fb51febdde019a7f24ea147e6c968b688cb05f7cef4d4f76a0` |
| Family label | `Mirai` |
| File name | `ohshit.arm6` |
| File type | `elf` |
| First seen | `2026-07-20 01:48:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd37896c6c6607c70ec4180d5a123b8e` |
| SHA-1 | `863b72acaacdf74ab347a843011195a3a3c85802` |
| SHA-256 | `5c299c0278faf2fb51febdde019a7f24ea147e6c968b688cb05f7cef4d4f76a0` |
| SHA3-384 | `b0fbd0118324843a5b81882633b2754ce7c2cb3313e0e331a9a83e875b465d95f492f50ed47262cddadb930767a186ec` |
| TLSH | `T1CEB33A56F8819B61C5C712BEFA1E618E33131778E3DE32129D185F21778B5AB0EBB601` |
| TELFHASH | `t11231aee6d77425de67d68248c18e611e4dedb29e3b493891cb5cab4f41839c2702dc3b` |
| SSDEEP | `3072:0trGt2EYUAe8vLWyA2C6NzaDunZhdi3ZtjKGluetn:0trZHS8vLWJ2C6ta2nqZtzlue` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_5c299c02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c299c0278faf2fb51febdde019a7f24ea147e6c968b688cb05f7cef4d4f76a0"
    family = "Mirai"
    file_name = "ohshit.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 01:48:38"
  condition:
    hash.sha256(0, filesize) == "5c299c0278faf2fb51febdde019a7f24ea147e6c968b688cb05f7cef4d4f76a0"
}
```

### Sample 10: `b3512d6dd7174665`

| Field | Value |
|---|---|
| SHA-256 | `b3512d6dd71746655648180b30a3812939c7adbcbb2958b3abf6ae004f691156` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-07-20 01:40:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d970c128513e30d30a1e170b0c27545b` |
| SHA-1 | `c9525be80db4174aa5b7743c80e7f5c0c6d4c303` |
| SHA-256 | `b3512d6dd71746655648180b30a3812939c7adbcbb2958b3abf6ae004f691156` |
| SHA3-384 | `f71c664959b85e6d194db5bb2a30de1eb4d322e5ef80b6d3b8eb8be996a31fff5a27906cd432450fd8f4866fe56e2023` |
| TLSH | `T1FD749D53BBC28FA6F232A5B049F3C1B9A9DA3A4707B7C457C3795B16125C2D07809EC9` |
| TELFHASH | `t196111448683ec45a7de30664cc3c5a95d70fcd3538514720df08c7c4897e4059219f5f` |
| SSDEEP | `6144:ASeYpUPrvUfFHmghX9t0plAY90EBQ6QlUI+63c9FN4S8q0wMeX:ASeYpgvUdmetteAYKEB+Q63c9FWS8q0A` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_b3512d6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3512d6dd71746655648180b30a3812939c7adbcbb2958b3abf6ae004f691156"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-07-20 01:40:09"
  condition:
    hash.sha256(0, filesize) == "b3512d6dd71746655648180b30a3812939c7adbcbb2958b3abf6ae004f691156"
}
```

### Sample 11: `338b19ba5a4d15cc`

| Field | Value |
|---|---|
| SHA-256 | `338b19ba5a4d15cca22d48c02c298064164d9db9654e7473880d12211f3cd185` |
| Family label | `Mirai` |
| File name | `ohshit.spc` |
| File type | `elf` |
| First seen | `2026-07-20 01:40:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `802e8368a506edcd3a33cb34fcaa6669` |
| SHA-1 | `d7985db46d4d569df9252f0fef74820f7d9276d9` |
| SHA-256 | `338b19ba5a4d15cca22d48c02c298064164d9db9654e7473880d12211f3cd185` |
| SHA3-384 | `3316ef8ed3a1eb6b473c60ed90aa78262278b735b725fb330398f729231da44e0dc3dcf9d3d1ecd116790894ef588977` |
| TLSH | `T195B36C22B879192BC9E4643611F35376F1F6438B20A88B1E7D710E8DBF246D036977B9` |
| SSDEEP | `1536:k2vLmFZ6+KHRCXkbeE9GK14elk/GxwKh0KB4tIgo95VOBPEFgCtyPn1:7NIK9l+Pr5ugoPYBPn1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_338b19ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "338b19ba5a4d15cca22d48c02c298064164d9db9654e7473880d12211f3cd185"
    family = "Mirai"
    file_name = "ohshit.spc"
    file_type = "elf"
    first_seen = "2026-07-20 01:40:07"
  condition:
    hash.sha256(0, filesize) == "338b19ba5a4d15cca22d48c02c298064164d9db9654e7473880d12211f3cd185"
}
```

### Sample 12: `49d9e5fda3eb3064`

| Field | Value |
|---|---|
| SHA-256 | `49d9e5fda3eb3064f04e6d2ac0e4876b509392cc65ad2445f0806339c6a1a356` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-20 01:38:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdc4c54a7d9c30f9e4698299dbd4e150` |
| SHA-1 | `5dfe63b71ec2954a97baf394f9349a635718a2fe` |
| SHA-256 | `49d9e5fda3eb3064f04e6d2ac0e4876b509392cc65ad2445f0806339c6a1a356` |
| SHA3-384 | `d2e63a7448156273d6fc1a34f6f8abbb9b6ef215f9f36c497b9ba190b33f71e07b60326f1dc246581625ff1c5a8b2e7d` |
| TLSH | `T101C33A0675A144FDC166C474877FA937EA31B85D13243B6F3784BA712E22E361F0AB92` |
| SSDEEP | `1536:l9eX2E5LhbOPKhQKoh6AGPKba4t6364PUKtxn0a6ehMM1/B4CGXDzahG44NorFA9:l9NE5pOPKhi/GyjwkOSa4CGfahG458F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_49d9e5fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49d9e5fda3eb3064f04e6d2ac0e4876b509392cc65ad2445f0806339c6a1a356"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 01:38:30"
  condition:
    hash.sha256(0, filesize) == "49d9e5fda3eb3064f04e6d2ac0e4876b509392cc65ad2445f0806339c6a1a356"
}
```

### Sample 13: `aee705055f820ed7`

| Field | Value |
|---|---|
| SHA-256 | `aee705055f820ed7147ce7ecd39f293ee56e71a2118d5bd0ca21584bfb89124f` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-20 01:38:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38861af6991c63ace92a35f1a3410992` |
| SHA-1 | `15ba530e5450f147f7944ceb1249767bdd99fcf6` |
| SHA-256 | `aee705055f820ed7147ce7ecd39f293ee56e71a2118d5bd0ca21584bfb89124f` |
| SHA3-384 | `eaae42059b7e0b1d45b812c4abd66d07f49ebd0947e7379698bfe6b46d70ade4fe2c14b7a6a67416745cff4d81a0de41` |
| TLSH | `T14F4302FE9AEA6FF4D83D97367216C3E455A23EC8900606DF45E427368D32506FD28E12` |
| SSDEEP | `1536:28GcXsuzYlMP6ck1ndijK/kaHcK3hkKe7s9pY:3BsuzYmSckMsN8ohkKQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_aee70505
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aee705055f820ed7147ce7ecd39f293ee56e71a2118d5bd0ca21584bfb89124f"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 01:38:05"
  condition:
    hash.sha256(0, filesize) == "aee705055f820ed7147ce7ecd39f293ee56e71a2118d5bd0ca21584bfb89124f"
}
```

### Sample 14: `6327eb7f0e774b2b`

| Field | Value |
|---|---|
| SHA-256 | `6327eb7f0e774b2be50bcc9665bfcb4a35f120c101368d4800de7e0b94827b0d` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-20 01:33:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a330d3aecd7a95e33aa8cabc5223def` |
| SHA-1 | `b43c6fc4c5838b09538f14aab83782f4789f45f7` |
| SHA-256 | `6327eb7f0e774b2be50bcc9665bfcb4a35f120c101368d4800de7e0b94827b0d` |
| SHA3-384 | `2045366b6cec2c18d53316fcca4ccbdd6dbc6fdffd0bd4be463087757a3bf8d8ad58cf55d5a8ed7ba811542a0b0e7112` |
| TLSH | `T14A84A291A41059CBCE1098BA7B2C8F7463823CB1935B1F7D1E568559A28F8CFF5C6BE0` |
| SSDEEP | `6144:ISYWMcpnLYbxnpoI4s+1NbQ6cOCZ0CuoEjlPcKTu:ISYBgnL6joDbpcfZ0CuHlPrq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_6327eb7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6327eb7f0e774b2be50bcc9665bfcb4a35f120c101368d4800de7e0b94827b0d"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-20 01:33:28"
  condition:
    hash.sha256(0, filesize) == "6327eb7f0e774b2be50bcc9665bfcb4a35f120c101368d4800de7e0b94827b0d"
}
```

### Sample 15: `c0685aa4c68bbecb`

| Field | Value |
|---|---|
| SHA-256 | `c0685aa4c68bbecb0bc5a61c3ee46eb9056ae33ded414784761d8ccac48e5bbd` |
| Family label | `Mirai` |
| File name | `ohshit.ppc` |
| File type | `elf` |
| First seen | `2026-07-20 01:31:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c98764d1898aa764aa2747b18a945e7` |
| SHA-1 | `3cce0313a7077aa4b8af5ae6bae3b21a7b31880b` |
| SHA-256 | `c0685aa4c68bbecb0bc5a61c3ee46eb9056ae33ded414784761d8ccac48e5bbd` |
| SHA3-384 | `911ad2803145c6805710d5d372aaba40f3a4b9afe359d03d78bd1984883f818545730f936b747ab2c329b9aa02721461` |
| TLSH | `T181B34B41735C0B43D1575EB02E3B37E583AED9E121F4BB48291EAB5642B2DB3158AFC8` |
| SSDEEP | `1536:QtjAm7wENW+dudN24Cz4q1A44fj2X9k1JUDTbCyYUyv68:QtjAm8GW+4vO9H4U9EJn3v68` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_c0685aa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0685aa4c68bbecb0bc5a61c3ee46eb9056ae33ded414784761d8ccac48e5bbd"
    family = "Mirai"
    file_name = "ohshit.ppc"
    file_type = "elf"
    first_seen = "2026-07-20 01:31:24"
  condition:
    hash.sha256(0, filesize) == "c0685aa4c68bbecb0bc5a61c3ee46eb9056ae33ded414784761d8ccac48e5bbd"
}
```

### Sample 16: `e8c73ce5eb660ea6`

| Field | Value |
|---|---|
| SHA-256 | `e8c73ce5eb660ea6570b5bf5f560eaf994394da02148f7df10aefac1fda8a756` |
| Family label | `MaskGramStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-20 01:30:47` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, MaskGramStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d60750568e3e66fbf3eaf27daf14df83` |
| SHA-1 | `904a17f3cf30e965029aa8ead1350e4cbab70f2c` |
| SHA-256 | `e8c73ce5eb660ea6570b5bf5f560eaf994394da02148f7df10aefac1fda8a756` |
| SHA3-384 | `260dce514cdde0da1f59b3771d7642f8f5c4a6c0ad62dbbec7985eae6053dba41eefe85f005026bfbd38c765160751f4` |
| IMPHASH | `d1c35276ff2b8e9d448afb940bccb1f0` |
| TLSH | `T151144B1BD4D540E9EC1AC6788A59E237A4B2FC5A1936B64F6BA0DF061F90B30B71DF04` |
| SSDEEP | `3072:iHfoDhOAuLOM6mABtOoRF/UT8ekQJzit+EMTKhpx11Q7qk7g9/t:N68BMoRF/MWQpIXhpGJg9/` |

#### Technical Assessment

- The sample is tracked as `MaskGramStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MaskGramStealer_016_e8c73ce5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8c73ce5eb660ea6570b5bf5f560eaf994394da02148f7df10aefac1fda8a756"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-20 01:30:47"
  condition:
    hash.sha256(0, filesize) == "e8c73ce5eb660ea6570b5bf5f560eaf994394da02148f7df10aefac1fda8a756"
}
```

### Sample 17: `850847440cf30804`

| Field | Value |
|---|---|
| SHA-256 | `850847440cf308046af0139b1c74e7059d19e82f591705f772d4568d854c1079` |
| Family label | `Mirai` |
| File name | `ohshit.arm5` |
| File type | `elf` |
| First seen | `2026-07-20 01:26:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e35d65934cbab5a9ef8f39dd696f8f63` |
| SHA-1 | `0f237f04c82843901a888453ea22ed096fdf3b8b` |
| SHA-256 | `850847440cf308046af0139b1c74e7059d19e82f591705f772d4568d854c1079` |
| SHA3-384 | `e3afbd159d9fd9225c5d3a651547c01e23f976a2d214ad2fa8c5d9a65f482e359582312501105c814e4f5624e8053c40` |
| TLSH | `T1F6632B84FC928AAEC5C01779E76EB78E33627391D3CB3213CD145B1127C96CE5A66B81` |
| TELFHASH | `t1dae05500bd798a194ce36a309ced07b49511a257a06687118f14cae1883f158a31cd2e` |
| SSDEEP | `1536:jDG2SlV+9Ji3Krb/DqKBz8nZ0MN1k7MaqG1chjSFFl0:jDG2o1aX/+KR8nWW1k7APjSPl0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_85084744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "850847440cf308046af0139b1c74e7059d19e82f591705f772d4568d854c1079"
    family = "Mirai"
    file_name = "ohshit.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 01:26:36"
  condition:
    hash.sha256(0, filesize) == "850847440cf308046af0139b1c74e7059d19e82f591705f772d4568d854c1079"
}
```

### Sample 18: `628492c45cbb8e26`

| Field | Value |
|---|---|
| SHA-256 | `628492c45cbb8e26f573675db32cb5687a40b2b4dd6d5e1c73a37c14558bb9a6` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-20 01:26:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `753a89c82af6532baee03a84279693d9` |
| SHA-1 | `c917ba718e7c0b3ca8ed82e6ec400bb7e393c153` |
| SHA-256 | `628492c45cbb8e26f573675db32cb5687a40b2b4dd6d5e1c73a37c14558bb9a6` |
| SHA3-384 | `d5f243c8dadc737eee74b52a5cc5111fbf297d42f5fa468edd96e0ba4110ab0bf184aa136a4366707a295f70c2f28ed7` |
| TLSH | `T158016FDA85409D004099DA5D22975058F820D3CF254B8FB5BF6C6D7EEB84C14F06BFA4` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaSEDqj9aZH/PINlJmUwcFcX:e9Qp+MsSEwQ3oTcX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_628492c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "628492c45cbb8e26f573675db32cb5687a40b2b4dd6d5e1c73a37c14558bb9a6"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-20 01:26:34"
  condition:
    hash.sha256(0, filesize) == "628492c45cbb8e26f573675db32cb5687a40b2b4dd6d5e1c73a37c14558bb9a6"
}
```

### Sample 19: `388a9e43f9baec11`

| Field | Value |
|---|---|
| SHA-256 | `388a9e43f9baec112abc28f1e058072e5ee847b0331388896f71517b832aff0d` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-20 01:20:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b54011777c19da0cf0a7ce339509f41` |
| SHA-1 | `17adac1dfb4f70e5a5c735f4285825dc77fbd6d3` |
| SHA-256 | `388a9e43f9baec112abc28f1e058072e5ee847b0331388896f71517b832aff0d` |
| SHA3-384 | `ffdfa27a13e4fb65a3b0c46f69f2823f2f94d6cc9d1e50e91bc46e919f38271a3fa71ffe9b41ca864a401851d1067865` |
| TLSH | `T191834B02B3480D43D1671DF02A3F37E5D3AFD59121F4BA89664E9B4A41B6EF2254AFC8` |
| SSDEEP | `1536:P1UIP6P3LziR4NNcpoO9cFr+QmqOYq39Eb0O:P1U3c441cFHmHU0O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_388a9e43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "388a9e43f9baec112abc28f1e058072e5ee847b0331388896f71517b832aff0d"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-20 01:20:57"
  condition:
    hash.sha256(0, filesize) == "388a9e43f9baec112abc28f1e058072e5ee847b0331388896f71517b832aff0d"
}
```

### Sample 20: `f77256eb64c144a1`

| Field | Value |
|---|---|
| SHA-256 | `f77256eb64c144a1f433705087bcefffbf59c79f6953a39d7c0d745ceab31573` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-20 01:20:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `204e7526670fdf665aef0f259cd3c84e` |
| SHA-1 | `333e1b767048383263589c8a7e0ac6dc02e87664` |
| SHA-256 | `f77256eb64c144a1f433705087bcefffbf59c79f6953a39d7c0d745ceab31573` |
| SHA3-384 | `d66dec8f20caee085d15655967ec619576306efdd931844d50f8a9bb5276559479643c9f3cb5974fbd6b52be26ad4c76` |
| TLSH | `T15103E137D1821AD5DFEF957414B1BFC023E10FCC01AEE6AB1192AE02BC5F429525A6DD` |
| SSDEEP | `768:SGfe47AQMTPqcOQ6utk3eZVw3JOt8QCSeEvH1es6h72lCqFbLkOAv4uVcqgw09c:Sx4Csput0qVwg6Q5eEvVMdKn64u+qgwp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_f77256eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f77256eb64c144a1f433705087bcefffbf59c79f6953a39d7c0d745ceab31573"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-20 01:20:16"
  condition:
    hash.sha256(0, filesize) == "f77256eb64c144a1f433705087bcefffbf59c79f6953a39d7c0d745ceab31573"
}
```

### Sample 21: `6afda92c73f89ddc`

| Field | Value |
|---|---|
| SHA-256 | `6afda92c73f89ddce818f752d2d3fb7f39cef34c53478ecd993cd42936a12efc` |
| Family label | `Gafgyt` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-20 01:15:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b39448d80d3f0fb50d8867c2c972dca` |
| SHA-1 | `3dce555abd0a1849bf3ab9aa64a9b1f133c8c3bc` |
| SHA-256 | `6afda92c73f89ddce818f752d2d3fb7f39cef34c53478ecd993cd42936a12efc` |
| SHA3-384 | `379bdf9dff20ba0e066e1596952e8141257ddafeb0327861b3fa1393095bfe284792878c61fbdf88342449a50017f606` |
| TLSH | `T171F3D61E6E618F7DF668873087F77E35A25833C72AE1C545D1ACD5111E2038EA81FBA8` |
| TELFHASH | `t17d21801c497822f0a7761c9d67deef76e5a070df46266d378e00ec6d9a6d9425e00c1c` |
| SSDEEP | `3072:XX64OQ/fVT4OnAUeJB1Ir2VE/iYXftdgPhExBqh:XXmQ/f1HnAUy1IrkIvt25MBqh` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_021_6afda92c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6afda92c73f89ddce818f752d2d3fb7f39cef34c53478ecd993cd42936a12efc"
    family = "Gafgyt"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-20 01:15:21"
  condition:
    hash.sha256(0, filesize) == "6afda92c73f89ddce818f752d2d3fb7f39cef34c53478ecd993cd42936a12efc"
}
```

### Sample 22: `b32f71c40fffc533`

| Field | Value |
|---|---|
| SHA-256 | `b32f71c40fffc53327ca712d82ad9349d2a4f396826fac9940824f48c878461f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-20 01:15:19` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5bc18792e65d0c36225a181dcc1c2b3` |
| SHA-1 | `b1228f2389a84f1b08100b510af2f73641383c80` |
| SHA-256 | `b32f71c40fffc53327ca712d82ad9349d2a4f396826fac9940824f48c878461f` |
| SHA3-384 | `18baca9315b864b52a3bd18bb1b4fa640d056aeaa481843abb256c1942c3b2df90b3593787afa8af485a811ab906abe1` |
| TLSH | `T15CC27D966A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:V18vCB+25j6es8RH9FYpMSUpi+20qUpi+20YQX:V18l25Jhd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_b32f71c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b32f71c40fffc53327ca712d82ad9349d2a4f396826fac9940824f48c878461f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-20 01:15:19"
  condition:
    hash.sha256(0, filesize) == "b32f71c40fffc53327ca712d82ad9349d2a4f396826fac9940824f48c878461f"
}
```

### Sample 23: `875257991745c055`

| Field | Value |
|---|---|
| SHA-256 | `875257991745c0557dd2fb00cd40934de6281ded379289c26d900bca2628f25f` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-20 01:08:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `831a58da295518e15059c5fb400195b1` |
| SHA-1 | `51d0fafed0cd277fce5503c6bb280e5c34b393d9` |
| SHA-256 | `875257991745c0557dd2fb00cd40934de6281ded379289c26d900bca2628f25f` |
| SHA3-384 | `559d3f6799a82feddffe7035bc805299e9eef8737e09a099d85d2926e8d2a4383b3213e216ebc73404db7c01b2dcdbf0` |
| TLSH | `T1A4E39FA89B4EBD42D2C7E3BEAE593FA3312738B041D4C1B64D00954EE5DAED58CE1523` |
| SSDEEP | `3072:miSpaiWD3wLvTRyHR3g34yM0W4RbOhow8XXPD3b6a3KhRWB:mdMT6OR3goyM0BbOhwXXTb6wKo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_87525799
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "875257991745c0557dd2fb00cd40934de6281ded379289c26d900bca2628f25f"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-20 01:08:32"
  condition:
    hash.sha256(0, filesize) == "875257991745c0557dd2fb00cd40934de6281ded379289c26d900bca2628f25f"
}
```

### Sample 24: `02e960e5278a686f`

| Field | Value |
|---|---|
| SHA-256 | `02e960e5278a686f38a356e5e7842def5797e07ec0b06b8fe5f34d0b28fde0b2` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-20 01:08:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1330a8a7da029a7eb311e4be5c733d2b` |
| SHA-1 | `c18aad82a1f930b93beb3d9360330780e835b8a0` |
| SHA-256 | `02e960e5278a686f38a356e5e7842def5797e07ec0b06b8fe5f34d0b28fde0b2` |
| SHA3-384 | `dd9b21af62d4b2c23242da0aa2cabba8d4dcbbee3a2b7e4b899da22ce96e9d153cff3c9c1f010fa6d6fcdc0d6f1f3244` |
| TLSH | `T149C31855BD829A12C6C22677FB5EB2CD331733A8E3EE7117DE245F25338B51A0E2A141` |
| SSDEEP | `1536:t1OJ2qrIOHj6k54wgwgobpxfhsMOyZVyaKmKi1VPCXoZ8vqNdkyVhQdlSHRgaOUu:tnqrLHuk5JfhsMOy4i1oXmQdlSxBFr4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_02e960e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02e960e5278a686f38a356e5e7842def5797e07ec0b06b8fe5f34d0b28fde0b2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-20 01:08:30"
  condition:
    hash.sha256(0, filesize) == "02e960e5278a686f38a356e5e7842def5797e07ec0b06b8fe5f34d0b28fde0b2"
}
```

### Sample 25: `e7889354c0d2cce6`

| Field | Value |
|---|---|
| SHA-256 | `e7889354c0d2cce6cc0c6a34ec13afd79bf361388e76ed2b3b987e0613d9c6a6` |
| Family label | `Mirai` |
| File name | `ohshit.mips` |
| File type | `elf` |
| First seen | `2026-07-20 01:08:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b63faef998f2b9c03e5be0e5f5b1de7` |
| SHA-1 | `d8b49ec3c5f2bcd30a0a9452456a56cb8df34e58` |
| SHA-256 | `e7889354c0d2cce6cc0c6a34ec13afd79bf361388e76ed2b3b987e0613d9c6a6` |
| SHA3-384 | `eeafcad8ab2669e5da786e6708a51e6cc82ddfb98fbdc145013328323a01a649146953c49f5d9e74ee533787dd0367e4` |
| TLSH | `T1DDD3D70E6E715F7CFBA8C23447B39B25A788639637E1C585E19CD6012E7038E681FB64` |
| TELFHASH | `t139217c1c493853f0d7b51dae2bedfb76e56170eb0a252e378d00e9a9da2dd425e00c2c` |
| SSDEEP | `3072:iuXLQcSHo038hz7OKuXGo/icO47xQw/vah:McSI0Mhz7OKuXl1z71/vah` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_e7889354
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7889354c0d2cce6cc0c6a34ec13afd79bf361388e76ed2b3b987e0613d9c6a6"
    family = "Mirai"
    file_name = "ohshit.mips"
    file_type = "elf"
    first_seen = "2026-07-20 01:08:29"
  condition:
    hash.sha256(0, filesize) == "e7889354c0d2cce6cc0c6a34ec13afd79bf361388e76ed2b3b987e0613d9c6a6"
}
```

### Sample 26: `ce05cafc84ca9fa7`

| Field | Value |
|---|---|
| SHA-256 | `ce05cafc84ca9fa75f97cc1c857170870252ef286c4940189a3c8499ae00a148` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-07-20 01:04:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fbdc1b15f9d1337b711c6b298830173` |
| SHA-1 | `4156be61a91d6f0f96b0573e8b237c3e3e3d1d4d` |
| SHA-256 | `ce05cafc84ca9fa75f97cc1c857170870252ef286c4940189a3c8499ae00a148` |
| SHA3-384 | `f3b22aba08156bffeee018c7dca8af712dec2aeec73d9201c261f2f127f1ee8105eae2310753c5ff19cf6b87f86c50dd` |
| TLSH | `T1A0A32946F8814A21C5D512BEFA1E318E331357BCE2DE73229E14AF3173865AB0E7B615` |
| TELFHASH | `t1e411d07183920adc57f4e15c818f102d9afe3ab9271530684a1d6bcb92d7181f319d3f` |
| SSDEEP | `1536:gAnQiGQoOTk+5KqmLUEqg/qSapwAo1MKb3TOaew4oXBDsRiciWRkOg8S7vJ5DYW1:JGKXg/qwSM3TOae6WRkOgJ7JJL+q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_ce05cafc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce05cafc84ca9fa75f97cc1c857170870252ef286c4940189a3c8499ae00a148"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:45"
  condition:
    hash.sha256(0, filesize) == "ce05cafc84ca9fa75f97cc1c857170870252ef286c4940189a3c8499ae00a148"
}
```

### Sample 27: `8c689ba49385129e`

| Field | Value |
|---|---|
| SHA-256 | `8c689ba49385129e4f8df15b11f315f1b31f3fc3ee1a610a186d948490f5cd14` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-20 01:04:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d17ef75a01428afb4de6d7de70e98b4e` |
| SHA-1 | `7912649a7914b6339e73246a76df42c900246599` |
| SHA-256 | `8c689ba49385129e4f8df15b11f315f1b31f3fc3ee1a610a186d948490f5cd14` |
| SHA3-384 | `d14612619dccad923aeecf3fff429073d3df3c9453e6d3770dd142a2423accd5f781c8fbb9d6f48edef9841127335a16` |
| TLSH | `T1938328C1FA8BC0F1D91B88304067F63FCB31E9695061D75DEF9A9E36DA33581A216389` |
| TELFHASH | `t15c31fff6067a0de897d01d44e25e6f612d1eab7b602037e34273c930222fc42527bc3a` |
| SSDEEP | `1536:ivDwDhVtcU4xiUWaqH3FY2SlGe80WJi+Kj/Osv4gv9l7vv:sDWKzQLH3FalGzo+Kj/Oc4Ev` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_8c689ba4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c689ba49385129e4f8df15b11f315f1b31f3fc3ee1a610a186d948490f5cd14"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:42"
  condition:
    hash.sha256(0, filesize) == "8c689ba49385129e4f8df15b11f315f1b31f3fc3ee1a610a186d948490f5cd14"
}
```

### Sample 28: `a373bfd15be694b9`

| Field | Value |
|---|---|
| SHA-256 | `a373bfd15be694b9145c506e9356e54dad6c6fe18ec6c628145b6018ca3e70ee` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-20 01:04:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d125f95b5cc5d85652cabc920421ad5c` |
| SHA-1 | `fb22effd1fdfe4ead51d356c13633d9b74054bae` |
| SHA-256 | `a373bfd15be694b9145c506e9356e54dad6c6fe18ec6c628145b6018ca3e70ee` |
| SHA3-384 | `0b2781364f2315abcf01ac808c3969ac157d0552f6361f9f51379a13bc8e3278b4387310092f2883ccf812b540d6e984` |
| TLSH | `T178837DC5EAC3C8F5ED2309351272BB275AB2D03E2268EA83C3A5D975EC125C0F556B5C` |
| TELFHASH | `t1e931d4f52a7e08d9a7c4a940c24e4f30385ed7bb155076a109b36978236be81a0bac39` |
| SSDEEP | `1536:RWOLMM5Md27oHyLijia3tAjw19KHVdxYQ5LBn:PLxMdOTLAigti+9IYQhBn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_a373bfd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a373bfd15be694b9145c506e9356e54dad6c6fe18ec6c628145b6018ca3e70ee"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:38"
  condition:
    hash.sha256(0, filesize) == "a373bfd15be694b9145c506e9356e54dad6c6fe18ec6c628145b6018ca3e70ee"
}
```

### Sample 29: `acdc1b5cfe4a154f`

| Field | Value |
|---|---|
| SHA-256 | `acdc1b5cfe4a154fd2c3de022622508a402d2d12927f26e67d5e77c3c92e267b` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-20 01:04:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8aab58e571a6e145139ddb1f3b6fe4f6` |
| SHA-1 | `91aef41c0fba8e9af6f20a23e9a04dae159abf72` |
| SHA-256 | `acdc1b5cfe4a154fd2c3de022622508a402d2d12927f26e67d5e77c3c92e267b` |
| SHA3-384 | `3bb9c45ea26d988218b63500b899c832280f5653b72e96ed7108e5cf8149ec792a1394165176f3ee7e86369d832e7f44` |
| TLSH | `T191B3E709EF611EF7E8AFCD370AF9270124CD592A22A97F757530D818B24A28F15E3974` |
| SSDEEP | `3072:bdub7djS5HECh6Qb1ShRhFczcmVRh865xP:bdo7djS5ECJSozcmVRbP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_acdc1b5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acdc1b5cfe4a154fd2c3de022622508a402d2d12927f26e67d5e77c3c92e267b"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:22"
  condition:
    hash.sha256(0, filesize) == "acdc1b5cfe4a154fd2c3de022622508a402d2d12927f26e67d5e77c3c92e267b"
}
```

### Sample 30: `6416561faf40a608`

| Field | Value |
|---|---|
| SHA-256 | `6416561faf40a608b2e9290e28bdcdc4e256a8e905afee3f450683ee588ec03a` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-07-20 01:04:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8cd2ad7f4ab8d8084ab8a4e9fba680c` |
| SHA-1 | `14038e434622f4918d14e1be3be0179d618f46de` |
| SHA-256 | `6416561faf40a608b2e9290e28bdcdc4e256a8e905afee3f450683ee588ec03a` |
| SHA3-384 | `f8ff1517819ccafae6f07d64dc472d23b992467a40e41e8b2af896c5914b690ef4fcf51cb74c33d5b259344412d47269` |
| TLSH | `T1A1B3E84E6F318F7DFBA8C23447B39A21975923D227E2C685D19CDA011E7028E645FBB4` |
| TELFHASH | `t143118b184a3823e097751d9d6bedffb2e59170db4a255d338c00e9ae9b6dd418d01c1c` |
| SSDEEP | `1536:aEkWiTLiZECcpHOWWJDmun5Pd1Oe4+YLxlrwTH+E7+TeVedVPneQBZN010an:oni50po9vYNlrwr7+Te0dVPZ010an` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_6416561f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6416561faf40a608b2e9290e28bdcdc4e256a8e905afee3f450683ee588ec03a"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:14"
  condition:
    hash.sha256(0, filesize) == "6416561faf40a608b2e9290e28bdcdc4e256a8e905afee3f450683ee588ec03a"
}
```

### Sample 31: `0927ba3ed85ba9a8`

| Field | Value |
|---|---|
| SHA-256 | `0927ba3ed85ba9a8f3984e1e6d135e5db7f37316af7189d894d56dde90b986a4` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-20 01:04:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04d6fe4ad8804679aa4a5337c7e5b0a3` |
| SHA-1 | `e7c2ec8edd060db7dff6883dd4c0a37c693d822c` |
| SHA-256 | `0927ba3ed85ba9a8f3984e1e6d135e5db7f37316af7189d894d56dde90b986a4` |
| SHA3-384 | `b09a93cf76fa7b57749d84446945da0ec3185ff41fed672a36d758577325a666ccfbe2eeb4a7829d4b60002f7dde6209` |
| TLSH | `T162431681F8D2996EC6D4137AA73E358E33A1B3E0D1CB3613CD585B25338A68F5D66B40` |
| TELFHASH | `t187e06140fe764b1844e75634ecdd07b49511211761664710cf54daf0883f118a31cd5e` |
| SSDEEP | `768:vcyaknuYHAf/StW3QQoyLEFMApBV5kTCS8kTIsYcLHKIoNDitRMfgrBNNTWnDrKL:vJnbHA36AzrEFMOkZcsrLHKotR7t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_0927ba3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0927ba3ed85ba9a8f3984e1e6d135e5db7f37316af7189d894d56dde90b986a4"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:02"
  condition:
    hash.sha256(0, filesize) == "0927ba3ed85ba9a8f3984e1e6d135e5db7f37316af7189d894d56dde90b986a4"
}
```

### Sample 32: `6fce1623d06754d0`

| Field | Value |
|---|---|
| SHA-256 | `6fce1623d06754d0eca7e3e05542baef73a05f120217e407fc3a4b60b032bbc7` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e818ecd6bb280937df3673e5dc82c648` |
| SHA-1 | `aa71558abc51da39c9907cf226ddddadb88c4fee` |
| SHA-256 | `6fce1623d06754d0eca7e3e05542baef73a05f120217e407fc3a4b60b032bbc7` |
| SHA3-384 | `7142afc108b180c621c4da9a3683e1f3a8a7d65481e3d7339eed419025696d3eedbdc9336453a2785434c27d58deb70d` |
| TLSH | `T131045C46EB818A13C0D62779F69F524533239BA4D3DB33069918AFB43F867DE0E67601` |
| TELFHASH | `t13c31fe31573151196ab1d954edec97b2152a87132349ee33df36c8dc181a09be93ec0f` |
| SSDEEP | `3072:WMdy5RuL6KaI5dPRdLBBoJYXoCyj8Ulduysd0LM/9VamtTM:WMIuuKaI5dPRdtBAFC68cduysdQM/99M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_6fce1623
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fce1623d06754d0eca7e3e05542baef73a05f120217e407fc3a4b60b032bbc7"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:58"
  condition:
    hash.sha256(0, filesize) == "6fce1623d06754d0eca7e3e05542baef73a05f120217e407fc3a4b60b032bbc7"
}
```

### Sample 33: `485bbf2e949d6c00`

| Field | Value |
|---|---|
| SHA-256 | `485bbf2e949d6c00b78fa3a69c346b5a587f9c416310f9496d838d9a0236a40f` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `645ae72a7a03815057cdf1122eb610e6` |
| SHA-1 | `265312e42d7cb92549f9017de19ca91f246592b2` |
| SHA-256 | `485bbf2e949d6c00b78fa3a69c346b5a587f9c416310f9496d838d9a0236a40f` |
| SHA3-384 | `3b9c68efb46a7d7e2f5452e6223dd14a79311dfdaff9e073bb584b799eae40ae2abd0e2220a788c6dad644b19b9b3589` |
| TLSH | `T1B0933A45FC919A12C6D5137BF72E228E372663A8E2DE3203DE156F22338659B0D7B741` |
| TELFHASH | `t11151f0f6eb900ecc2bd8924482de752d4fed316e17052497d65caf8f98439c2b12e827` |
| SSDEEP | `1536:9Ot4/NGRVrAFcqyJwBb86PVLIzAX5iXffdXLamvt4:9Ot4/OVEWNj6PZIzhPjt4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_485bbf2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "485bbf2e949d6c00b78fa3a69c346b5a587f9c416310f9496d838d9a0236a40f"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:55"
  condition:
    hash.sha256(0, filesize) == "485bbf2e949d6c00b78fa3a69c346b5a587f9c416310f9496d838d9a0236a40f"
}
```

### Sample 34: `bbfec9da453e630b`

| Field | Value |
|---|---|
| SHA-256 | `bbfec9da453e630b7efde190a50687f3833ffe4725069ebecd42ca7cd06750bd` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc437b1fff41b1f5813127327a90a37a` |
| SHA-1 | `fcb7290c084bebe7e770fd888069c86972b22307` |
| SHA-256 | `bbfec9da453e630b7efde190a50687f3833ffe4725069ebecd42ca7cd06750bd` |
| SHA3-384 | `0f80058145d66bfe74fedbdf3b5de613c99e005bf84d933e855e4585c6d7e869e05f2f968e87759ba0743057b7cabbcd` |
| TLSH | `T1E1736CC4FA83D4F6EC130A350136BB379AB3E13E2169DB83D3A9A525DC125C2DA1635C` |
| TELFHASH | `t1d531e5fe0ab748f8e7c46880830f2b61695ed777251032a30672d964629fec184bec39` |
| SSDEEP | `1536:IbMP6X3uwvlzydgREdwHE2N5Xekch3K68cSwv:IbMC3ZludgR0wDN4kM39v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_bbfec9da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbfec9da453e630b7efde190a50687f3833ffe4725069ebecd42ca7cd06750bd"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:48"
  condition:
    hash.sha256(0, filesize) == "bbfec9da453e630b7efde190a50687f3833ffe4725069ebecd42ca7cd06750bd"
}
```

### Sample 35: `8e78c6d44d095554`

| Field | Value |
|---|---|
| SHA-256 | `8e78c6d44d095554ab431b2d22a0fe6724f1b0312bbfc990f5f7339af72247a3` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32cac052654b5994417aa74d4574784c` |
| SHA-1 | `a3ef2b0312cd8734193223164baaee374ecd67ba` |
| SHA-256 | `8e78c6d44d095554ab431b2d22a0fe6724f1b0312bbfc990f5f7339af72247a3` |
| SHA3-384 | `0cf012f41e020fbdddf624d1bdc07c2c1f068a1c18ec4710211b10baa4f86e8565e760289bc1c106b21e9e7a9f819ee4` |
| TLSH | `T11D13F159535F85E2CD202D39FC204B8B0FC496B1A2AD24108B9D97AFFE9C77367B6144` |
| SSDEEP | `768:aFU5jg+eO3dCE5M+nHo2mu3NnrQy3txM3cP11R1gHv6tpfVO6fAJFaqWDjKwz6K/:aFU1g+F3nM+nr33NnFLYK10v4XYWqqKa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_8e78c6d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e78c6d44d095554ab431b2d22a0fe6724f1b0312bbfc990f5f7339af72247a3"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:20"
  condition:
    hash.sha256(0, filesize) == "8e78c6d44d095554ab431b2d22a0fe6724f1b0312bbfc990f5f7339af72247a3"
}
```

### Sample 36: `a978a84fe498c755`

| Field | Value |
|---|---|
| SHA-256 | `a978a84fe498c755e481d161e22ed41087b93100a6b2648943c251208eeda3eb` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a0c389d34a8d78404fe82c289ad0417` |
| SHA-1 | `774803d6578cee5ba77c5f47d06f153cb2d21f0b` |
| SHA-256 | `a978a84fe498c755e481d161e22ed41087b93100a6b2648943c251208eeda3eb` |
| SHA3-384 | `2cf22dbe687f70934e3a3c8524ab656c41a736c6547e3b405812989f4723d44558aec01da746d040a6eb954a06bfbd88` |
| TLSH | `T1C2030217367A4A16E84A403D02EFB1673810DA6FB41769E039F48437AB5CF087D7D697` |
| SSDEEP | `768:ngQcD4ioAAYVyCH1DIQcjxDyELLLl4bZZxOTOCZVf0FZnNz9Zhi3wnbcuyD7UHQC:g6diVlth2xDNLLLl4bZZxexf4xignoup` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_a978a84f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a978a84fe498c755e481d161e22ed41087b93100a6b2648943c251208eeda3eb"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:19"
  condition:
    hash.sha256(0, filesize) == "a978a84fe498c755e481d161e22ed41087b93100a6b2648943c251208eeda3eb"
}
```

### Sample 37: `26af57f0a8259e9d`

| Field | Value |
|---|---|
| SHA-256 | `26af57f0a8259e9d19a8239f6d681bb0d99e9c643ad21336e967477f66ccda89` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df1cd12eb28a9b39db6a36a683881c06` |
| SHA-1 | `bf638d9d56f290bb57151ef49666f585342ed9ed` |
| SHA-256 | `26af57f0a8259e9d19a8239f6d681bb0d99e9c643ad21336e967477f66ccda89` |
| SHA3-384 | `07ec695bc04bf8d6a34c04d35c35029b0ebf30c304b4c42cfa67162f8cc2b1edf82c4aa4323b2b01aa9127a411db88ac` |
| TLSH | `T1FB13F18E72780E52EF7C787C849E7AC510908E4BEF914D92FBC2232E66C5F11B6185C6` |
| SSDEEP | `768:wzDT+5mfT/P0B4e92Q5m99YrBLuqKC7iA67rquN/mL4OlgfnbcuyD7UHQRjH/:wa5E2xDG9yhJ70H/QT0nouy8HyL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_26af57f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26af57f0a8259e9d19a8239f6d681bb0d99e9c643ad21336e967477f66ccda89"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:18"
  condition:
    hash.sha256(0, filesize) == "26af57f0a8259e9d19a8239f6d681bb0d99e9c643ad21336e967477f66ccda89"
}
```

### Sample 38: `5d06e47b6a89d906`

| Field | Value |
|---|---|
| SHA-256 | `5d06e47b6a89d9069c501df5dda25f82d7cd21819ca10a6f16d562ed9053e3e8` |
| Family label | `Mirai` |
| File name | `nz.sh` |
| File type | `sh` |
| First seen | `2026-07-20 01:03:16` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6ccb4e86a1f4dd484f31a5833c99646` |
| SHA-1 | `f2d486505932447e8b0ffd07809eda7d74b929aa` |
| SHA-256 | `5d06e47b6a89d9069c501df5dda25f82d7cd21819ca10a6f16d562ed9053e3e8` |
| SHA3-384 | `8d6fbbcab61aabefed13f0504268b1fb875c542f13387e990a6faebec98f5542056ff6db69169bacda20a0f7ca1e73eb` |
| TLSH | `T1415110C6126207722E529D23BBEB8D2971C0A0DE689BDF66A9DCBCF5518CD083C4D647` |
| SSDEEP | `24:It6sYUIhOEh33A9PsaSTrTGF7JvVGAALoRNINksWrCj1TlyUmy7J:i7vEh3waaSTrTGFlTALLJWre1TlVPF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_5d06e47b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d06e47b6a89d9069c501df5dda25f82d7cd21819ca10a6f16d562ed9053e3e8"
    family = "Mirai"
    file_name = "nz.sh"
    file_type = "sh"
    first_seen = "2026-07-20 01:03:16"
  condition:
    hash.sha256(0, filesize) == "5d06e47b6a89d9069c501df5dda25f82d7cd21819ca10a6f16d562ed9053e3e8"
}
```

### Sample 39: `01e10a0d58ddfef9`

| Field | Value |
|---|---|
| SHA-256 | `01e10a0d58ddfef9d4f5c8f16f6397a8f3cde32759f0a2a9458aa4416a8fa8ce` |
| Family label | `Mirai` |
| File name | `nz.arc` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef5c3fa7c602553e5f972bbdc495f302` |
| SHA-1 | `a289fd93dd211682cab4a08405285d16f9d5ded7` |
| SHA-256 | `01e10a0d58ddfef9d4f5c8f16f6397a8f3cde32759f0a2a9458aa4416a8fa8ce` |
| SHA3-384 | `89ceb9f481398cafe29c66b9e6822e1cbe40951cc689f82ce291550ec372ceb5e9a0b3ba9cd7b91055fe3465a37f9a8a` |
| TLSH | `T14EC3AE97F78B24A1C86146F007C76B8D3EA362019E6BE9E76C1E753B193A1DF19063C1` |
| SSDEEP | `1536:nq189r2mIHgqH8INi8TNB4ZPLaLWq0IijTQEE8+FCUxZJ3eg9B/LWg:q1ur2nj7BZqZPLetETQC+FCkeg9Bq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_01e10a0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01e10a0d58ddfef9d4f5c8f16f6397a8f3cde32759f0a2a9458aa4416a8fa8ce"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:15"
  condition:
    hash.sha256(0, filesize) == "01e10a0d58ddfef9d4f5c8f16f6397a8f3cde32759f0a2a9458aa4416a8fa8ce"
}
```

### Sample 40: `c683d44aec123273`

| Field | Value |
|---|---|
| SHA-256 | `c683d44aec123273b706f948e25ac772f6275175479724a676fde168a7d42fa8` |
| Family label | `Mirai` |
| File name | `nz.sh4` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e88de81932e49688ee7d49ce425fe012` |
| SHA-1 | `a1fdaf4217e768e64088165ce1e8efd20d73b29b` |
| SHA-256 | `c683d44aec123273b706f948e25ac772f6275175479724a676fde168a7d42fa8` |
| SHA3-384 | `78dd803129c96bb18998ec91311d4772e71219b7f68cd7d8e1c56387e3d62ac255bf613a797f6483b66a82495f7c08a8` |
| TLSH | `T13273AE73CCAA2CA8D55842B4B5B4BE362773E41466871FF71696CA369007EDCF8093B4` |
| SSDEEP | `1536:P/Q0G/PRRILXNHJKtmmHT74t73RCAZuj8FvgsMU:Po0GXRMX5wt5s73RTZuA1FMU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_c683d44a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c683d44aec123273b706f948e25ac772f6275175479724a676fde168a7d42fa8"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:14"
  condition:
    hash.sha256(0, filesize) == "c683d44aec123273b706f948e25ac772f6275175479724a676fde168a7d42fa8"
}
```

### Sample 41: `ffd0d42db56574e5`

| Field | Value |
|---|---|
| SHA-256 | `ffd0d42db56574e5cdcf9c1c898cd900ed7b71bf799f8212a6a08c235ac76d62` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e603fdc076b57686e2f760a404b8b59` |
| SHA-1 | `71b4f8e0ae93382733d003663eb2c9b15f0febad` |
| SHA-256 | `ffd0d42db56574e5cdcf9c1c898cd900ed7b71bf799f8212a6a08c235ac76d62` |
| SHA3-384 | `6404b46233b5f61425580c9d58919c7d2a840ffe4fbe7e271f6eed7dd8570da48dce02ff8e72d20e0bafad3d9fa08cd4` |
| TLSH | `T1D713E18DE1D4A95BCD6D6CB7C49E07703DDE818323CB1ADA6349CC98AE35A4B35910F8` |
| SSDEEP | `768:tx4mYFaluq7c2hrjYJO5AhCA7ks2Q4kUx8vdgBxTgO5qJ5a4RvSxmtyCm0aJ0WHP:txhYYuqYZJOFE20d+xTfzSSxVCmlpP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_ffd0d42d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffd0d42db56574e5cdcf9c1c898cd900ed7b71bf799f8212a6a08c235ac76d62"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:12"
  condition:
    hash.sha256(0, filesize) == "ffd0d42db56574e5cdcf9c1c898cd900ed7b71bf799f8212a6a08c235ac76d62"
}
```

### Sample 42: `9cccf931d90f97b1`

| Field | Value |
|---|---|
| SHA-256 | `9cccf931d90f97b1380731af74213b539574e975c4e8b0c6a683aa0fc0e7183f` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21c5786fe8a5c59d02df1a58b4ff833c` |
| SHA-1 | `e972aa9d979562a8330507eac99dd32edc828124` |
| SHA-256 | `9cccf931d90f97b1380731af74213b539574e975c4e8b0c6a683aa0fc0e7183f` |
| SHA3-384 | `0e88284f997b16700ed825007aae1591447f842d89997cfaf5fa00aa91f781065e6ecfe011120c7cac97fc26498835dc` |
| TLSH | `T15913F1F805128EF5D91AF1B306F20B124E809FE2CC07FC47849AB58AD8E9C9D5C537A9` |
| SSDEEP | `768:fVKH+MeiZH7vnvd68KHyM5Fg1/WKbJjCn7SVxcOgEXjgZJgGlzDpbuR1JU:fV+1eObvnvd65HyMjiW4+7SVxcOgEXjM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_9cccf931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cccf931d90f97b1380731af74213b539574e975c4e8b0c6a683aa0fc0e7183f"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:11"
  condition:
    hash.sha256(0, filesize) == "9cccf931d90f97b1380731af74213b539574e975c4e8b0c6a683aa0fc0e7183f"
}
```

### Sample 43: `197cc8cb6a519636`

| Field | Value |
|---|---|
| SHA-256 | `197cc8cb6a519636b797ba4ecb540e908486c581c99f653971bc6bb328041d17` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f366c32cbf1af0fe563595db24b0a32f` |
| SHA-1 | `ac871a53c9869281ff009ed5db7028ec12cdee40` |
| SHA-256 | `197cc8cb6a519636b797ba4ecb540e908486c581c99f653971bc6bb328041d17` |
| SHA3-384 | `bb9bac1435f4039e5330dcd84b72facc9b2caa3124fbf95f5b0b05d08d87d1c535e8908440df3c6f10e72b7ece8bf01d` |
| TLSH | `T167C33B0779C18AFEC486D67803BF7526C522F83E1B36338B67D47D693A09AD42A1D319` |
| TELFHASH | `t1c4314231477155292eb0c914acec97b2651a87171748ee33ce31c89c242a0aef93fc0f` |
| SSDEEP | `3072:S6SblaZFi4q0KI1XeN31xwnPEbt+uYr0uBtuerGulNpS:tyUFi4ZVEDwPRuYpBt9rGulNpS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_197cc8cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "197cc8cb6a519636b797ba4ecb540e908486c581c99f653971bc6bb328041d17"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:10"
  condition:
    hash.sha256(0, filesize) == "197cc8cb6a519636b797ba4ecb540e908486c581c99f653971bc6bb328041d17"
}
```

### Sample 44: `2ca55a0c23087341`

| Field | Value |
|---|---|
| SHA-256 | `2ca55a0c2308734109690550078dfe7281e40755fb203d077e3b68f3115f204d` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a51f416d457be70e20e83557b74e8d11` |
| SHA-1 | `04419f176c860cdb197be9ced6ec5c188a1b972f` |
| SHA-256 | `2ca55a0c2308734109690550078dfe7281e40755fb203d077e3b68f3115f204d` |
| SHA3-384 | `ae7502044534677a1278b6eead48b097b60d1a33ddae50fabdbf44e94edc2557774781f1276c3d4f4cf7de6becc5f4d6` |
| TLSH | `T1C4B2E1B4730A2571D8B0083A7A3C4146768702F5E5EB5B3F2421863DDEAE607EABC7D5` |
| SSDEEP | `768:fG4rcUl3p9byh2Uy+2XpOhD4oRCOQs3UozMgV:NrPj3o8kFzB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_2ca55a0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ca55a0c2308734109690550078dfe7281e40755fb203d077e3b68f3115f204d"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:08"
  condition:
    hash.sha256(0, filesize) == "2ca55a0c2308734109690550078dfe7281e40755fb203d077e3b68f3115f204d"
}
```

### Sample 45: `5f6cc8466655754c`

| Field | Value |
|---|---|
| SHA-256 | `5f6cc8466655754cb6753127743d2f07d5201f1d6c0e0eb1db12c5696e4d9773` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73feacb286b5ddf597a87a713655ee38` |
| SHA-1 | `8109c221f73b43484a708bcea5654f852a00a0dc` |
| SHA-256 | `5f6cc8466655754cb6753127743d2f07d5201f1d6c0e0eb1db12c5696e4d9773` |
| SHA3-384 | `0ab514cf7fe3264207d6d66380f23967f93c28f449d91c4110f991a155069d9d6aad86e038b12f95b142421be44e331d` |
| TLSH | `T1DD63017EF707989874747E76F8D6EA0A15F40DB5CEAF2AA682142E306FD3D815030362` |
| SSDEEP | `1536:VU3Bp2NvAdO9spSBKC5pOJzYgLR4SraHLG8gZNt:VUKNodhMBKCkLRLraHLG8wt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_5f6cc846
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f6cc8466655754cb6753127743d2f07d5201f1d6c0e0eb1db12c5696e4d9773"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:07"
  condition:
    hash.sha256(0, filesize) == "5f6cc8466655754cb6753127743d2f07d5201f1d6c0e0eb1db12c5696e4d9773"
}
```

### Sample 46: `f6b00f2f991671e1`

| Field | Value |
|---|---|
| SHA-256 | `f6b00f2f991671e105a03c5eb80b810e14372dcba7cc33703d428c9a264c3711` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `088918ee5cbd843420a7bdd497c2d0bf` |
| SHA-1 | `3af1e5cb893acb461bceba30833535fd1407859f` |
| SHA-256 | `f6b00f2f991671e105a03c5eb80b810e14372dcba7cc33703d428c9a264c3711` |
| SHA3-384 | `c79183fde1ffbe2838a030f770ac40d3e319a2acdb483197b76ceb638319c11672982510581f8529df66e17f8ec250bf` |
| TLSH | `T14813F1730889BEB2C1750C32EC4E15553F27077DD6A2643D3A9C0AADE15224BE97C2CB` |
| SSDEEP | `768:fiifDEdlpr8S3nuzKg+t4q38MmTDzXmjypcOVR2s0+PC7zM7hs3Uozc:dDQVqzT32+FCsm7CMzc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_f6b00f2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6b00f2f991671e105a03c5eb80b810e14372dcba7cc33703d428c9a264c3711"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:05"
  condition:
    hash.sha256(0, filesize) == "f6b00f2f991671e105a03c5eb80b810e14372dcba7cc33703d428c9a264c3711"
}
```

### Sample 47: `566ee3dfd8bee695`

| Field | Value |
|---|---|
| SHA-256 | `566ee3dfd8bee695f40e780f990946df38180dd286d3ef98123b310cc9fe80c2` |
| Family label | `Mirai` |
| File name | `nz.spc` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf51047fc939b81fe5ac742406f0524e` |
| SHA-1 | `975b640fdef030add7ae86ef78a9eb18e61e42f4` |
| SHA-256 | `566ee3dfd8bee695f40e780f990946df38180dd286d3ef98123b310cc9fe80c2` |
| SHA3-384 | `78dac094bb637a94acc49809a0a8823c5bc47fe66f816ac01133c7d7ba43f9d442ced61022a4cbe31b7e439c4eb6c4d1` |
| TLSH | `T1DE935B22B539193BC4E4953722F35326F1F6438A14A88B1E7E720E8EBF256D036477B5` |
| SSDEEP | `1536:0sRsLVu48xrIz6YqPog6N8HGdtAQkYm5V4A1Ywt1cx:0kqLMPmdi1YOyWcx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_566ee3df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "566ee3dfd8bee695f40e780f990946df38180dd286d3ef98123b310cc9fe80c2"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:04"
  condition:
    hash.sha256(0, filesize) == "566ee3dfd8bee695f40e780f990946df38180dd286d3ef98123b310cc9fe80c2"
}
```

### Sample 48: `f93fdc21623eddd5`

| Field | Value |
|---|---|
| SHA-256 | `f93fdc21623eddd541ac3b5d92f83b31ea6ea3dd7b0359b09aaa1287ba58579f` |
| Family label | `Mirai` |
| File name | `nz.m68k` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0eaf308701b61bafc75cd8e542a21f7b` |
| SHA-1 | `fcbbdfe6769c9e3e63db9f8379f9ad8651b48c68` |
| SHA-256 | `f93fdc21623eddd541ac3b5d92f83b31ea6ea3dd7b0359b09aaa1287ba58579f` |
| SHA3-384 | `4ce42aac2bf4a022c8c7f95b35fc3099f9b35c3f96d8fe2c6ccdee19586f16ef5c8b026d63eeee2ea684a1ce07a0d726` |
| TLSH | `T1849329C6B401DC7EF80FDABB4463690EB631E2511A831B26675BFD53AD321E45923F82` |
| SSDEEP | `1536:xsdLEbXJld35KM6hRozWD/TJsP8dFWqvl1Pj8b4b29wv5tLBo0zzHlplo9K+tMUP:xjKvhgWD/T/wqvlNLCetdoqOK+tPKqB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_f93fdc21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f93fdc21623eddd541ac3b5d92f83b31ea6ea3dd7b0359b09aaa1287ba58579f"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:03"
  condition:
    hash.sha256(0, filesize) == "f93fdc21623eddd541ac3b5d92f83b31ea6ea3dd7b0359b09aaa1287ba58579f"
}
```

### Sample 49: `ce23b01e50afa5dd`

| Field | Value |
|---|---|
| SHA-256 | `ce23b01e50afa5dd35213b5cb7198e677e32adefbbf3ebd735e8a0a440d40bbf` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-20 01:03:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ebb8ce66dae2910251bbf008a94adb2` |
| SHA-1 | `72d458062613eae8fb74d1d6c808d4f5699ab0ff` |
| SHA-256 | `ce23b01e50afa5dd35213b5cb7198e677e32adefbbf3ebd735e8a0a440d40bbf` |
| SHA3-384 | `a9b583ee5c1a64827b4888048f95129473c7a6d3f76fa1b09ae7cd73f34516e29485c03ab9adc64e9b9de33a50c7275f` |
| TLSH | `T11903F1C5D4CC7D35E49D21B01CF9EB4F5810E68CD0F889EBDEC9150B2BE5A693A28A17` |
| SSDEEP | `768:JpDDQdmx3ELhtPG5AZhTHgQtiLDPNie3Asw64gE6nBjIfqlwXvnbcuyD7UHQRjY:JpfQdmx3EdtPnZhrft+Me3Asw6C6B0yE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_ce23b01e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce23b01e50afa5dd35213b5cb7198e677e32adefbbf3ebd735e8a0a440d40bbf"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:01"
  condition:
    hash.sha256(0, filesize) == "ce23b01e50afa5dd35213b5cb7198e677e32adefbbf3ebd735e8a0a440d40bbf"
}
```

### Sample 50: `75f5413dcdf4c69f`

| Field | Value |
|---|---|
| SHA-256 | `75f5413dcdf4c69f8b49ab6bec5c9a9948c768d5abbbbd0c093c971b39e4398e` |
| Family label | `Mirai` |
| File name | `tarm7` |
| File type | `elf` |
| First seen | `2026-07-20 00:58:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c3d92164408f3764d012667ed49f133` |
| SHA-1 | `c897ba4c611bc95f07d921b44d318b34fc125d63` |
| SHA-256 | `75f5413dcdf4c69f8b49ab6bec5c9a9948c768d5abbbbd0c093c971b39e4398e` |
| SHA3-384 | `084a310338333935c7efac4fc89937bb825b1151063ea46112402cb4172b7efc2745ddd00db11b2f2db33cd79f512676` |
| TLSH | `T1D9B32989B9816B25D6C256BBFE4F018933135BACE3EE7212DD144B6037CB91B0F7A506` |
| TELFHASH | `t16601c082fbb0658d73d5831541feb12a99dcb59c1f02a8b258fe3f0b4222750b43b40b` |
| SSDEEP | `3072:y8XKO+pKeFOTUnaFDdKiC33FUUWIa297x9FXrHnoFB+SEwd:ymKJcUnaFDdKx314Ia297x9FrIFUSt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_75f5413d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75f5413dcdf4c69f8b49ab6bec5c9a9948c768d5abbbbd0c093c971b39e4398e"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-20 00:58:51"
  condition:
    hash.sha256(0, filesize) == "75f5413dcdf4c69f8b49ab6bec5c9a9948c768d5abbbbd0c093c971b39e4398e"
}
```

### Sample 51: `c1c1046c507058c0`

| Field | Value |
|---|---|
| SHA-256 | `c1c1046c507058c0ca6d14bb5369a84a45791d58475ce12fc6995451f0c5eb14` |
| Family label | `Mirai` |
| File name | `ohshit.arc` |
| File type | `elf` |
| First seen | `2026-07-20 00:58:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49fcd5cee7cc01a6eead2a2dd016396a` |
| SHA-1 | `d16dbcb093f9b1011992d846a232327db13a4ffc` |
| SHA-256 | `c1c1046c507058c0ca6d14bb5369a84a45791d58475ce12fc6995451f0c5eb14` |
| SHA3-384 | `7c0ec9672a558a198d3b33b0374402bbe1f7e4354cc8d04ce684988c97974338ac204b68f88b72d2a49d0a0260466592` |
| TLSH | `T1AFD3BFD7B7672499C4A343F047CB678D2E931111CF9BA8E63D0E613B18BE0EB16163A1` |
| SSDEEP | `3072:QRZJCiyi/BvQzXKAgewbtrdn1Mosbpi5knDzxqE:Qzyw4zXKDxMo4DzxqE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_c1c1046c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1c1046c507058c0ca6d14bb5369a84a45791d58475ce12fc6995451f0c5eb14"
    family = "Mirai"
    file_name = "ohshit.arc"
    file_type = "elf"
    first_seen = "2026-07-20 00:58:50"
  condition:
    hash.sha256(0, filesize) == "c1c1046c507058c0ca6d14bb5369a84a45791d58475ce12fc6995451f0c5eb14"
}
```

### Sample 52: `698a65556d1937d3`

| Field | Value |
|---|---|
| SHA-256 | `698a65556d1937d391e85ddb0c2c4419e907214033dbf68401c92f635bb61c82` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-20 00:56:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `543c9c04c44dd41d3b0431f5285f9c7f` |
| SHA-1 | `2a37c778da5328a71e5d825b53c9e984b089a6b0` |
| SHA-256 | `698a65556d1937d391e85ddb0c2c4419e907214033dbf68401c92f635bb61c82` |
| SHA3-384 | `9fdf08e68adb6f5934b67dec0edb337d5bc0542496499c0570605e5f4833b2fca9c8a31ac7c6b7a85f678a59bacc37f4` |
| TLSH | `T1EFD313139C83B62EC8B5573CC2BA636F480374C855A28A096B314CDF9B56396A2774F7` |
| SSDEEP | `3072:BHqVzcIqwppRfmqK9tMM3bXVJkN0+KF6ApbH:Bszk6B5K9tnbQN0+fApbH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_698a6555
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "698a65556d1937d391e85ddb0c2c4419e907214033dbf68401c92f635bb61c82"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 00:56:53"
  condition:
    hash.sha256(0, filesize) == "698a65556d1937d391e85ddb0c2c4419e907214033dbf68401c92f635bb61c82"
}
```

### Sample 53: `4c2032f518894d18`

| Field | Value |
|---|---|
| SHA-256 | `4c2032f518894d18f9463850cd1159d2e8664079f8d2526f0a9b1470cbf3488c` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-20 00:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d22faac1e3af1c95d0dfb6b3565e95d2` |
| SHA-1 | `3e72fd76310c89053a3af411477dfa48319540dd` |
| SHA-256 | `4c2032f518894d18f9463850cd1159d2e8664079f8d2526f0a9b1470cbf3488c` |
| SHA3-384 | `bc60d022dff1622fbe8e59cd688717633e1b265b7735ac2519e613232ed9b6d664e076eac98cf2063981cbc7a8364117` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1CEE633156AE023DEFAA35039DFD18B94E469F8660BB1C5CF439885B07E133E68C3D616` |
| SSDEEP | `393216:xnAdBBECaPy0iF7kzrW+XMCHWUjXCcuI3/PGTAI:xntCcUk++XMb8X/H/O7` |
| ICON-DHASH | `d4f071e8e8607030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_4c2032f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c2032f518894d18f9463850cd1159d2e8664079f8d2526f0a9b1470cbf3488c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 00:52:08"
  condition:
    hash.sha256(0, filesize) == "4c2032f518894d18f9463850cd1159d2e8664079f8d2526f0a9b1470cbf3488c"
}
```

### Sample 54: `8fb4cfabec6fa0b8`

| Field | Value |
|---|---|
| SHA-256 | `8fb4cfabec6fa0b8f0e0d25135e87e88c13c3dce61c1335a89ee2e474a3d1570` |
| Family label | `Mirai` |
| File name | `ohshit.x86` |
| File type | `elf` |
| First seen | `2026-07-20 00:50:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a89b89214289251afa03c2cc05733561` |
| SHA-1 | `18af6df7a4d1aaff38db64c8ead737773b748615` |
| SHA-256 | `8fb4cfabec6fa0b8f0e0d25135e87e88c13c3dce61c1335a89ee2e474a3d1570` |
| SHA3-384 | `8bd69209a820223383398b5e43099a58b30b6abaa37cba672627aef4aebfc3fcf3f8377788389d251f371952ad560057` |
| TLSH | `T17F936DC5E687D0F2EC2605712177FB378A77E13E2129EB83D7A86931AC126C1D21679C` |
| TELFHASH | `t19831e6f5162a0cec77c0a942b2495b21bc0d6a3b612037e605b31879352bd8553bbd3c` |
| SSDEEP | `1536:1jJ0iBtDGXb00Vr1eMf6fGN4Q+ihVoPrNMxzHOLUdF5VmEikSLxj:NJ0iBte9rn6fY4QnVowzuodvidLxj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_8fb4cfab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fb4cfabec6fa0b8f0e0d25135e87e88c13c3dce61c1335a89ee2e474a3d1570"
    family = "Mirai"
    file_name = "ohshit.x86"
    file_type = "elf"
    first_seen = "2026-07-20 00:50:59"
  condition:
    hash.sha256(0, filesize) == "8fb4cfabec6fa0b8f0e0d25135e87e88c13c3dce61c1335a89ee2e474a3d1570"
}
```

### Sample 55: `e0e2e7ce1b38f04d`

| Field | Value |
|---|---|
| SHA-256 | `e0e2e7ce1b38f04d6e20e22cb25915bdc4e1cc90f08e7114243ceadffa9e4a59` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-20 00:47:01` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c33b6d076a762fdce6f982c00841feeb` |
| SHA-1 | `f95ced71807acae9f84e03b71163d1c6e900d681` |
| SHA-256 | `e0e2e7ce1b38f04d6e20e22cb25915bdc4e1cc90f08e7114243ceadffa9e4a59` |
| SHA3-384 | `41b907a147e74d1087b2423bdbaebfb8a541c30046d815b698aa92ebcb7f5989ba5b79c949fa565b00921110fed2e7a1` |
| TLSH | `T116016BDA8640AD004019D95D229B5194B821D3CF1A8B4FB87F9C5D3EFB88814F06BFA4` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaSEDq/9aZD/PI7JmUwwFY7:e9Qp+MsSEK+3KZY7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_e0e2e7ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0e2e7ce1b38f04d6e20e22cb25915bdc4e1cc90f08e7114243ceadffa9e4a59"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-20 00:47:01"
  condition:
    hash.sha256(0, filesize) == "e0e2e7ce1b38f04d6e20e22cb25915bdc4e1cc90f08e7114243ceadffa9e4a59"
}
```

### Sample 56: `81962ba664cb7cd0`

| Field | Value |
|---|---|
| SHA-256 | `81962ba664cb7cd0865577bc257c1899bfa18df9f2d48482d3fb8b831058e60d` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-20 00:42:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7cc57affdaffc545e99cca3dffbe4d3` |
| SHA-1 | `905d7f6d70681f9b6651fdd241a835e542313a0f` |
| SHA-256 | `81962ba664cb7cd0865577bc257c1899bfa18df9f2d48482d3fb8b831058e60d` |
| SHA3-384 | `1f51e888550466a2c73876005b52ef88e7c7b6a60f6d15bdcd0f40eb57eb51828a34fc9796df616a0d3b72fec6e1d250` |
| TLSH | `T156018ECBD1249900609ED56C22EB5154F831C3CA1D4B4B79FFACA47A9BD4E14F0AAF94` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaGF4XFOy6ZgMi+8uX:e9Qp+MsS4XFh6ZgMi+8uX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_81962ba6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81962ba664cb7cd0865577bc257c1899bfa18df9f2d48482d3fb8b831058e60d"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-20 00:42:49"
  condition:
    hash.sha256(0, filesize) == "81962ba664cb7cd0865577bc257c1899bfa18df9f2d48482d3fb8b831058e60d"
}
```

### Sample 57: `c442326ba5603e08`

| Field | Value |
|---|---|
| SHA-256 | `c442326ba5603e08ebabb9960cab7567b49ae9d30fad73256d53870322015045` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-20 00:40:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `838cc2f4736d5b59da1fc6c410d1963c` |
| SHA-1 | `c7e2765d75484fc941f87a7151cb7d14fd8aaeb7` |
| SHA-256 | `c442326ba5603e08ebabb9960cab7567b49ae9d30fad73256d53870322015045` |
| SHA3-384 | `5c522428c5bb51a9fa540390c38b37cb36da088964bc5a334e25001a4b58492b54b5c2e01020aad366b76406ce3cd273` |
| TLSH | `T177236D652A817C14AA98D4371D7E2F0CB9AD43E6320492ED7FCF3CF68C4A69D911871D` |
| SSDEEP | `768:vXOGVv/9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:PLAcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_c442326b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c442326ba5603e08ebabb9960cab7567b49ae9d30fad73256d53870322015045"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-20 00:40:57"
  condition:
    hash.sha256(0, filesize) == "c442326ba5603e08ebabb9960cab7567b49ae9d30fad73256d53870322015045"
}
```

### Sample 58: `d8a8cea14b12aa75`

| Field | Value |
|---|---|
| SHA-256 | `d8a8cea14b12aa75047979f929bdf10b9003884580398c3c13d2b4fb04209410` |
| Family label | `Mirai` |
| File name | `tmips` |
| File type | `elf` |
| First seen | `2026-07-20 00:36:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c87935d34c8fefd8c41da2d57cab535d` |
| SHA-1 | `f2dae90dd8269af3942a69394a576b8f4a772334` |
| SHA-256 | `d8a8cea14b12aa75047979f929bdf10b9003884580398c3c13d2b4fb04209410` |
| SHA3-384 | `14258f3b6a1be96b778e30dd1c13c5a2806298cd39a18bf2aa5550f1b1b05cad8f1fbeeebab063581f5f191038e348c2` |
| TLSH | `T199C3B70A3E218F6EF369C23447F78E25A75927D617E1C686D19CD5101F603CEA81FBA8` |
| TELFHASH | `t19621815c493823f097751c9e2bedff75e5a130df4a252d338e10e9adaa6d9425d00c1c` |
| SSDEEP | `3072:Jo9hmbzIWIj3KQc7mda1XijmYewRlqSO0:JoPmHIr6QraA9HlqSO0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_d8a8cea1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8a8cea14b12aa75047979f929bdf10b9003884580398c3c13d2b4fb04209410"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-07-20 00:36:55"
  condition:
    hash.sha256(0, filesize) == "d8a8cea14b12aa75047979f929bdf10b9003884580398c3c13d2b4fb04209410"
}
```

### Sample 59: `310181ccdbc4129d`

| Field | Value |
|---|---|
| SHA-256 | `310181ccdbc4129d5a8052af9101013df6e8e2871c6c42b6e86ef5a7f162caa3` |
| Family label | `unknown` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-07-20 00:34:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e23c91606d1f4a7922c389e5eea5e6a8` |
| SHA-1 | `8e7eba648538c931df72df5efe7787fe4960b90a` |
| SHA-256 | `310181ccdbc4129d5a8052af9101013df6e8e2871c6c42b6e86ef5a7f162caa3` |
| SHA3-384 | `2dbed6cfc6c0f9e49f22d3c29fd639ed8425fe23a93ec8684fb7c3ceac0562870c2a6e41c86ff48742a05167c45bdf6b` |
| TLSH | `T1F5B312B936509C75C77F3B3648BD2E55E60310299E34B2128B099FFB70C472A6D84EE9` |
| SSDEEP | `1536:wesFVmGAl2CE0vGBUxcnUrG93W7n580g4uOr3LVzMCFGFv82O+kI55sWZW6SnCJB:0T//BUxcnUk8n58NM6CkEcKCuG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_310181cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310181ccdbc4129d5a8052af9101013df6e8e2871c6c42b6e86ef5a7f162caa3"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-20 00:34:52"
  condition:
    hash.sha256(0, filesize) == "310181ccdbc4129d5a8052af9101013df6e8e2871c6c42b6e86ef5a7f162caa3"
}
```

### Sample 60: `517164c29c0e178b`

| Field | Value |
|---|---|
| SHA-256 | `517164c29c0e178b1bb4613d3d5ceb552329c9596791624d8277f2dc5ba37c50` |
| Family label | `Mirai` |
| File name | `ohshit.arm7` |
| File type | `elf` |
| First seen | `2026-07-20 00:34:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `889ec695feeae43ccd91b66a544734e2` |
| SHA-1 | `1ae5a73fc8778fde5f283b0c2ba3ace213415dc7` |
| SHA-256 | `517164c29c0e178b1bb4613d3d5ceb552329c9596791624d8277f2dc5ba37c50` |
| SHA3-384 | `2098e2e1938bfe3bba16eb130fa32e7a03e3e6540d2b0ae95973834c58fe1faee9834b23a6d707be0eaa2d44d9841b75` |
| TLSH | `T15C144B46EA418A13C0D727B9B69F524A33339764D3DB33069D18AFB43F8679E0E67601` |
| TELFHASH | `t14e31ec315731551a6a61c964ecec97b2252987131684ee33df3ac8dc182a09ad53ac0f` |
| SSDEEP | `6144:FMOTrLD1PYH5hJaeXHJMGrjtEKbCMblbIjOAM/9GH7:FMOXH1PeXJaqHJMGrjtZNN/5/kb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_517164c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "517164c29c0e178b1bb4613d3d5ceb552329c9596791624d8277f2dc5ba37c50"
    family = "Mirai"
    file_name = "ohshit.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 00:34:51"
  condition:
    hash.sha256(0, filesize) == "517164c29c0e178b1bb4613d3d5ceb552329c9596791624d8277f2dc5ba37c50"
}
```

### Sample 61: `d1e7bb3d3a56b3fa`

| Field | Value |
|---|---|
| SHA-256 | `d1e7bb3d3a56b3fa0810838df4885c5c3c794519502f3bc7ae335c9720099215` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-20 00:33:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a07aa832791dd5235d65a74374d7731` |
| SHA-1 | `3130a48287f4408df677cac03d5fc2c211e78647` |
| SHA-256 | `d1e7bb3d3a56b3fa0810838df4885c5c3c794519502f3bc7ae335c9720099215` |
| SHA3-384 | `80e2b081874e966563f29b9701e8d2fe2308dc0dc68af1ad4c9e454ddf39f715030fe933ac997008a0db5ac9497e1e9e` |
| TLSH | `T192D31955BC829A16C6C2167BFB5EB2CD331733A8E3EE7107CE255F21378B51A0E2A141` |
| TELFHASH | `t16ed05e23f9482adc3ac1537041c80605aad8a4db036114e292ca5e6fcb42be0b416a31` |
| SSDEEP | `1536:J7lXIgZgOHjkk5KYawgYApJrXCW2xZ8ylwmciCVZJcE8TZ8vqNDCyBhPB7ejYgau:JWgZTHwk58rXCW6QiCptsPB7esPcn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_d1e7bb3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1e7bb3d3a56b3fa0810838df4885c5c3c794519502f3bc7ae335c9720099215"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-20 00:33:05"
  condition:
    hash.sha256(0, filesize) == "d1e7bb3d3a56b3fa0810838df4885c5c3c794519502f3bc7ae335c9720099215"
}
```

### Sample 62: `24d8adc83594c77c`

| Field | Value |
|---|---|
| SHA-256 | `24d8adc83594c77c97fe59a84db8ffda1fbe13faefb495e2075b1feb80018bef` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-20 00:28:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b9a28e8ed3df1e0a23bde802df2408e` |
| SHA-1 | `2520428f59adb8b15277f83036459c94cf14ac96` |
| SHA-256 | `24d8adc83594c77c97fe59a84db8ffda1fbe13faefb495e2075b1feb80018bef` |
| SHA3-384 | `8b1c2e758e654d969dceddbc4e86711816139581a6d02e578a6e3a578bb6f88d414ee2f736113791de0d565e879b70da` |
| TLSH | `T145747ED3FC01E97EF86FD732C8134E04B531E36154821A3A21A3B779A92B15A5D73E86` |
| SSDEEP | `6144:AtGd8qf4fkbL8Mm7HfGVDMvW/hDvBo1z1hiFs1ZshyMhD+MS84hf47LEnkT:A8gD7navBo1z1hiFs1Q4LnkT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_24d8adc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24d8adc83594c77c97fe59a84db8ffda1fbe13faefb495e2075b1feb80018bef"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-20 00:28:52"
  condition:
    hash.sha256(0, filesize) == "24d8adc83594c77c97fe59a84db8ffda1fbe13faefb495e2075b1feb80018bef"
}
```

### Sample 63: `12d21b742c5e2a9e`

| Field | Value |
|---|---|
| SHA-256 | `12d21b742c5e2a9e28bf0fc232a3b8d8963cf0c6c4278d4d551bda774495c3ae` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-20 00:27:03` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0043cc3241b422bd0ccdf5cbbd7937c` |
| SHA-1 | `329341116a4e35883118b5b1285af6a43cabc132` |
| SHA-256 | `12d21b742c5e2a9e28bf0fc232a3b8d8963cf0c6c4278d4d551bda774495c3ae` |
| SHA3-384 | `f7481a3ae670322bdbcda2f0d27074889fd335ed563a0a4ba3cf1827946a5afd5e8df37c68c3ff8d2a9fd338842ed2e4` |
| TLSH | `T1A4B312B29D6F02AD59EA2A732FED4608510CF98CDA61D5F70AD572E590F8E693C03603` |
| SSDEEP | `3072:hLewLuzXXObGiPXsOyYQEfwq9ftB4x7R3quTkkoutD:8OEOyHjq9FB4xd3qMjoSD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_12d21b74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12d21b742c5e2a9e28bf0fc232a3b8d8963cf0c6c4278d4d551bda774495c3ae"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-20 00:27:03"
  condition:
    hash.sha256(0, filesize) == "12d21b742c5e2a9e28bf0fc232a3b8d8963cf0c6c4278d4d551bda774495c3ae"
}
```

### Sample 64: `eef5c5fa574616e7`

| Field | Value |
|---|---|
| SHA-256 | `eef5c5fa574616e79c45b3901e6d843172b8c7bebed1fd797c35f23155b7db9b` |
| Family label | `unknown` |
| File name | `Dolphin 06_Q88 V6 (Oil and Chemical)_19Jul2026.exe` |
| File type | `exe` |
| First seen | `2026-07-20 00:24:40` |
| Reporter | `threatcat_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06d9071ed8b15a6d9871f47b311f3e97` |
| SHA-1 | `fbd17a868c8ec29b54c77fe504a8647a27c00131` |
| SHA-256 | `eef5c5fa574616e79c45b3901e6d843172b8c7bebed1fd797c35f23155b7db9b` |
| SHA3-384 | `596b68240015f0c92ccdb42b73ed191230441e486b9bdc4e7e717954b1decfa6e96a4f12a75ea6265d9eeecaaf7b8a5e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T12F45F11523E89A68E4FEA73167B5002187F2F80A9735D71E795C51EE0F32B819927B33` |
| SSDEEP | `24576:gEOF8HKLZ4e2sAh8cYH4QoDPHk/Sf4iS:gr2HKtH2t2cYYQoDPjg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_eef5c5fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eef5c5fa574616e79c45b3901e6d843172b8c7bebed1fd797c35f23155b7db9b"
    family = "unknown"
    file_name = "Dolphin 06_Q88 V6 (Oil and Chemical)_19Jul2026.exe"
    file_type = "exe"
    first_seen = "2026-07-20 00:24:40"
  condition:
    hash.sha256(0, filesize) == "eef5c5fa574616e79c45b3901e6d843172b8c7bebed1fd797c35f23155b7db9b"
}
```

### Sample 65: `ee44fb0df1cf9740`

| Field | Value |
|---|---|
| SHA-256 | `ee44fb0df1cf9740c5779bc5a811e4d1c984365fd5e0482434f58fc1cc54d638` |
| Family label | `Mirai` |
| File name | `ohshit.x86_64` |
| File type | `elf` |
| First seen | `2026-07-20 00:22:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43560d06730f2937a40717f4c654500a` |
| SHA-1 | `9c0f3349e9b30284687d010805af46db8e3a84fc` |
| SHA-256 | `ee44fb0df1cf9740c5779bc5a811e4d1c984365fd5e0482434f58fc1cc54d638` |
| SHA3-384 | `f18befc5105c76fc3e52179f848bc243a107593fd698d867a045928e52c99a40a9eea27e3f2bf9ea2cd1278ee7e59af0` |
| TLSH | `T13DA34B07B9C098FDC459D13847BF713AD462F46E2239728F27C4AE27299DED02B193A5` |
| TELFHASH | `t17b315cb43d9b3a4420e7977ab34bf2a6c46216301ae138d49e337cd7ce62bc44d82465` |
| SSDEEP | `1536:GTJAHeDvngiZi3INrBuXuV3Su6YLNQWgU7L7tWQJgu1K9ik5v:uAHeDfgAnNtueVJ6uQWP7wQJ7Y9is` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_ee44fb0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee44fb0df1cf9740c5779bc5a811e4d1c984365fd5e0482434f58fc1cc54d638"
    family = "Mirai"
    file_name = "ohshit.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 00:22:47"
  condition:
    hash.sha256(0, filesize) == "ee44fb0df1cf9740c5779bc5a811e4d1c984365fd5e0482434f58fc1cc54d638"
}
```

### Sample 66: `13f6c8dcecb6677e`

| Field | Value |
|---|---|
| SHA-256 | `13f6c8dcecb6677e77680f2b75d82b17fcee135cc00b474bcff5d9c64a06e9bb` |
| Family label | `Mirai` |
| File name | `ohshit.m68k` |
| File type | `elf` |
| First seen | `2026-07-20 00:14:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97c4cd3a6398602c98512605e29df1a9` |
| SHA-1 | `5a710afe6600050143d1ac0afc92eb00e0e81f86` |
| SHA-256 | `13f6c8dcecb6677e77680f2b75d82b17fcee135cc00b474bcff5d9c64a06e9bb` |
| SHA3-384 | `482db8c6a595fcf86befb42dac67129e3798c2459772ef0c7d34d872213e3c3370422fe2b57c9c1cb6fcb9e42caedeb7` |
| TLSH | `T1C5B34BCAF801DD7EF81FC6764463690AB931E2615A831F73A367B953AC311E06923F85` |
| SSDEEP | `3072:bEqlTGXzA07KXSbWavdyyt0RdAVhQjloBPX5BA6:oWTIE07/0ytydAbQkPX5BA6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_13f6c8dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13f6c8dcecb6677e77680f2b75d82b17fcee135cc00b474bcff5d9c64a06e9bb"
    family = "Mirai"
    file_name = "ohshit.m68k"
    file_type = "elf"
    first_seen = "2026-07-20 00:14:44"
  condition:
    hash.sha256(0, filesize) == "13f6c8dcecb6677e77680f2b75d82b17fcee135cc00b474bcff5d9c64a06e9bb"
}
```

### Sample 67: `f9191fbfcd25b4d0`

| Field | Value |
|---|---|
| SHA-256 | `f9191fbfcd25b4d0274e7831ae190d888c42be4e3794c4bb3dea7517b704fdee` |
| Family label | `Mirai` |
| File name | `ohshit.sh4` |
| File type | `elf` |
| First seen | `2026-07-20 00:12:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbd42190e42a1f25cce46ebb230cfb0a` |
| SHA-1 | `e2bdf1cf47f42ff081a8448a84c5e07cd54f84a3` |
| SHA-256 | `f9191fbfcd25b4d0274e7831ae190d888c42be4e3794c4bb3dea7517b704fdee` |
| SHA3-384 | `b363639d9de640f4257aa83bcd29c3b9b37a1c6417d42934867527a677edb0b7fe40cba8c31b8ae1be11ef7b31e7ceb1` |
| TLSH | `T1E0A3BE62C8742DD4C154C1B9A4A4FFBA6B33E81056836FB3165BC636E087EDCB5863B4` |
| SSDEEP | `1536:uZ/GPxiqRW2HXqobEMP3YLADz0PdKISOtmuoaICc1tWTmNv+Hb:c+ZisHPbEMPIiz0PEIGuoaIR8qNv+Hb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_f9191fbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9191fbfcd25b4d0274e7831ae190d888c42be4e3794c4bb3dea7517b704fdee"
    family = "Mirai"
    file_name = "ohshit.sh4"
    file_type = "elf"
    first_seen = "2026-07-20 00:12:46"
  condition:
    hash.sha256(0, filesize) == "f9191fbfcd25b4d0274e7831ae190d888c42be4e3794c4bb3dea7517b704fdee"
}
```

### Sample 68: `3ee8b4e38efa5f87`

| Field | Value |
|---|---|
| SHA-256 | `3ee8b4e38efa5f872f5f1f4fac720d80eb7c079fc538ef75f2d8a8dc7068ef9f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-20 00:12:45` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2008a2aab04bc0c7a015aeebe01c7d0` |
| SHA-1 | `9142c74cd0de1543afb2bea83c609c0a6b309fbd` |
| SHA-256 | `3ee8b4e38efa5f872f5f1f4fac720d80eb7c079fc538ef75f2d8a8dc7068ef9f` |
| SHA3-384 | `cbdc29e19161e79c9d143f7893675f778a719d980f136396d837cd18719db7e3b5637bc4ade5c4d1bb62b37c4362d9bc` |
| TLSH | `T100C27D956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D4B3C719C11F9CD618B1A` |
| SSDEEP | `768:s8vCB+25j6es8Rh9FYpMSUpi+20qUpi+20YQX:s8l25JXd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_3ee8b4e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ee8b4e38efa5f872f5f1f4fac720d80eb7c079fc538ef75f2d8a8dc7068ef9f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-20 00:12:45"
  condition:
    hash.sha256(0, filesize) == "3ee8b4e38efa5f872f5f1f4fac720d80eb7c079fc538ef75f2d8a8dc7068ef9f"
}
```

### Sample 69: `276fdef74ff71efa`

| Field | Value |
|---|---|
| SHA-256 | `276fdef74ff71efaeb345c04a3ecfbeb2e99ad97584f4eba24e9936f0de6bd60` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-20 00:12:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `026849d7f28fa44078829e23c8908d84` |
| SHA-1 | `85c3bb96d147f66ed1747d9dbf59e6f83d1148e9` |
| SHA-256 | `276fdef74ff71efaeb345c04a3ecfbeb2e99ad97584f4eba24e9936f0de6bd60` |
| SHA3-384 | `268b1d0b06d79262931064a9da4bf0097acc1acc124bacdf0104adaf12fbef36d9713f360f06587c2a0ebb9b2ee00747` |
| TLSH | `T1DDC312A313CE7728C2FD8E3BDA854B45A24E559A97AFCE2F123D5231D407B62803564F` |
| SSDEEP | `3072:uTcgFiozRvfpYBlkHeXbLflWgztSv+6hc:scgtvRYBZXbIgzt3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_276fdef7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "276fdef74ff71efaeb345c04a3ecfbeb2e99ad97584f4eba24e9936f0de6bd60"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-20 00:12:43"
  condition:
    hash.sha256(0, filesize) == "276fdef74ff71efaeb345c04a3ecfbeb2e99ad97584f4eba24e9936f0de6bd60"
}
```

### Sample 70: `5e3c607ce72d5126`

| Field | Value |
|---|---|
| SHA-256 | `5e3c607ce72d51263e201321cc76e30c8c027feeab35a10d1f1ca70f60f1e671` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-20 00:10:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `797db5498c12ca9b73a72af53567fb8f` |
| SHA-1 | `ec21f7a49c3d1a11250f241d9aba9b1d23ae32b9` |
| SHA-256 | `5e3c607ce72d51263e201321cc76e30c8c027feeab35a10d1f1ca70f60f1e671` |
| SHA3-384 | `68da327bef9395eb18b9acae632636c0ec2c492ae38f84ae614ede1be2b32c283c048a79b5f2fc0b7796348bf23a38ff` |
| TLSH | `T12EB37DC6FA43D4F0E8560AB1113BB7264B71F93145F9EF86DBA52C329D23A009A1B75C` |
| TELFHASH | `t151515ab9be7b0de877906907964e5b616f0de7bb247032f505f325a132f244240bac39` |
| SSDEEP | `1536:LuYxTD/l1yCTBUiGe2PcXdz1RM7ePS6qxdtnZW9IQcJh2ORsgizMHrigMG:iOfyC1UfPc9/M7cS6U/ZWyNhlagmM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_5e3c607c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e3c607ce72d51263e201321cc76e30c8c027feeab35a10d1f1ca70f60f1e671"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-20 00:10:50"
  condition:
    hash.sha256(0, filesize) == "5e3c607ce72d51263e201321cc76e30c8c027feeab35a10d1f1ca70f60f1e671"
}
```

### Sample 71: `310c6c65766a41fd`

| Field | Value |
|---|---|
| SHA-256 | `310c6c65766a41fda319acbc604fd200741c31d6151341e49e3d84f076860005` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-07-20 00:09:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0939e435cb0dc86c29b2b5b2278c5ba1` |
| SHA-1 | `c95126a0f886abdd5b620743356c2aa75bf5b639` |
| SHA-256 | `310c6c65766a41fda319acbc604fd200741c31d6151341e49e3d84f076860005` |
| SHA3-384 | `a15dbaefbaba9e23793c1983c08a58720a41de38d84ffe80857b11c45ffbf3d318018926884efdcfbf2f6bd5fa582f93` |
| TLSH | `T13DC312D092891506D2D47173BF3946E2336998BD84F7E1237E01BF25B5C2A1206DA7F7` |
| SSDEEP | `3072:7KK0Ojvju1uMfbLN6ottthd7oMkZbQI7e3OCMyT6gdk9p:7AwMzLNtnhd7oM60I7e6yTdk9p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_310c6c65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310c6c65766a41fda319acbc604fd200741c31d6151341e49e3d84f076860005"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-20 00:09:02"
  condition:
    hash.sha256(0, filesize) == "310c6c65766a41fda319acbc604fd200741c31d6151341e49e3d84f076860005"
}
```

### Sample 72: `6dfd535055df7f3f`

| Field | Value |
|---|---|
| SHA-256 | `6dfd535055df7f3f0658ff58e3a625f38ef4c0bfc13f0279181db7adf37f688b` |
| Family label | `unknown` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-20 00:07:03` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9a04f975b96b6860c6ff9af16bf1fd1` |
| SHA-1 | `81a686d661c92f3a86f313c435ad3202b42770bd` |
| SHA-256 | `6dfd535055df7f3f0658ff58e3a625f38ef4c0bfc13f0279181db7adf37f688b` |
| SHA3-384 | `5a1f716158e6b7b53952928baaed508e8d452828970b57c741895ec883c3ac60fa9a9539c069e9dca79e5ec61aa21788` |
| TLSH | `T158B3128DA8409E14CD12ECF4A8DB97635FB18597722BD6A3FB45DD312B8462B2602DCC` |
| SSDEEP | `3072:Nq/5YlO4pft8KIc4DyhSicyhKzU/9qDqmk4u+qgw2uk:FlDpf+ydcyBlbk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_6dfd5350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dfd535055df7f3f0658ff58e3a625f38ef4c0bfc13f0279181db7adf37f688b"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-20 00:07:03"
  condition:
    hash.sha256(0, filesize) == "6dfd535055df7f3f0658ff58e3a625f38ef4c0bfc13f0279181db7adf37f688b"
}
```

### Sample 73: `ccc0ba109fd1e38f`

| Field | Value |
|---|---|
| SHA-256 | `ccc0ba109fd1e38f414e9354d5afaf1f32cbef61118517fac5c36b0d3d93a743` |
| Family label | `unknown` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-07-20 00:07:02` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `846b24b4c7ded55fd90ccdcaa61bceaa` |
| SHA-1 | `05ec4c08fdf0b19290c0c7ddbd5992d0e0f2fb7d` |
| SHA-256 | `ccc0ba109fd1e38f414e9354d5afaf1f32cbef61118517fac5c36b0d3d93a743` |
| SHA3-384 | `80b6a03b043bd3cd914acccb444c1aa49f3e2dcc9e72be185232c8ed6fa08fcd92c9f292e4347147468a6ca469404788` |
| TLSH | `T181B30266A90070D4D79212BE91FFCBC38B2CDF5AC12790A32513FF653B405259BBB689` |
| SSDEEP | `3072:oCNTFc0fcbTbY+V3aSm+8TW9Jd4yNjjj37KtkSgb09P4h:oUpc7Y+VK1VTWrf9jf0l4h` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_ccc0ba10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccc0ba109fd1e38f414e9354d5afaf1f32cbef61118517fac5c36b0d3d93a743"
    family = "unknown"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-07-20 00:07:02"
  condition:
    hash.sha256(0, filesize) == "ccc0ba109fd1e38f414e9354d5afaf1f32cbef61118517fac5c36b0d3d93a743"
}
```

### Sample 74: `45f072085e50c50a`

| Field | Value |
|---|---|
| SHA-256 | `45f072085e50c50ac363bf8a88cd4b362df1230758123e04703c431818b86034` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-07-20 00:03:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd442a5c42c78736b8f81e892e69c1dc` |
| SHA-1 | `ed63448a4953ce94c06ef639ce932314de78d101` |
| SHA-256 | `45f072085e50c50ac363bf8a88cd4b362df1230758123e04703c431818b86034` |
| SHA3-384 | `ea77d1a9adb8985726bcd269e5888b0dbaef6ab7f67a0cafdd8b37c4eb67884bd680233962dcd454a36480ba4a0950b5` |
| TLSH | `T155E35B59FA5BC0F0D6D340F4063BEB6A9A3A9D116173F5A1FF5A3A62FCB1301248526C` |
| SSDEEP | `3072:/2earQ8QEFZO0mKJVMj/rpanXmKWIICtMLEf:O1QDESLjz4WKiSMo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_45f07208
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45f072085e50c50ac363bf8a88cd4b362df1230758123e04703c431818b86034"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-20 00:03:42"
  condition:
    hash.sha256(0, filesize) == "45f072085e50c50ac363bf8a88cd4b362df1230758123e04703c431818b86034"
}
```

### Sample 75: `19fdce2472485db5`

| Field | Value |
|---|---|
| SHA-256 | `19fdce2472485db5fc8d8820cda7c798212d01a830f76d22e6e1612f38dde37c` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-07-20 00:03:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cc5db6b5bb1ff767813f918a5de0fa4` |
| SHA-1 | `4efcf94ffb9e9fec4df62912f82f3beadefeed2f` |
| SHA-256 | `19fdce2472485db5fc8d8820cda7c798212d01a830f76d22e6e1612f38dde37c` |
| SHA3-384 | `c2b4916e741c009eae6949c2bf02f34d94571f1c055f4364f500f841c307f903c6d1e8721e406fe03a5e4013b52639d4` |
| TLSH | `T11A53F2A854CC63A0CB4A403825FEB2569C0D99A6DC59CED356DC983F64C3B443EE63CB` |
| SSDEEP | `1536:qYvrcMtBE9odJRwdzC1XM4HUAp/SVS1T3HsJymA0NgTN++nouy8DMb:nBBGcGhecoUA9YcCf/gTN+eoutDMb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_19fdce24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19fdce2472485db5fc8d8820cda7c798212d01a830f76d22e6e1612f38dde37c"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-20 00:03:00"
  condition:
    hash.sha256(0, filesize) == "19fdce2472485db5fc8d8820cda7c798212d01a830f76d22e6e1612f38dde37c"
}
```

### Sample 76: `c533aeec0e53aca3`

| Field | Value |
|---|---|
| SHA-256 | `c533aeec0e53aca326d421c3d1483e742c8476e4e17125ac6267de6bc8df2dcc` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-07-19 23:58:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6362cd5c7110adfc5a80b1729afdea7` |
| SHA-1 | `3f756adc090988135422868e17ff8431c6288ce2` |
| SHA-256 | `c533aeec0e53aca326d421c3d1483e742c8476e4e17125ac6267de6bc8df2dcc` |
| SHA3-384 | `08bef1cfd8424a61e76f51aefe17ecd44833f10ce6424f4ea53fcfe690f5fac4c75103052b72384e76caa63481cc1210` |
| TLSH | `T1CAB312774DAFD44186D1125F60424982F88AF6A69DCEF07735B3791933EBD4E20FA260` |
| SSDEEP | `3072:uoMkRyvQZ2h6JzWPgMLiKziw3IAgOIIr9k8o:uoqoOHP/LiKmw47m93o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_c533aeec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c533aeec0e53aca326d421c3d1483e742c8476e4e17125ac6267de6bc8df2dcc"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-19 23:58:44"
  condition:
    hash.sha256(0, filesize) == "c533aeec0e53aca326d421c3d1483e742c8476e4e17125ac6267de6bc8df2dcc"
}
```

### Sample 77: `71458c54a327762a`

| Field | Value |
|---|---|
| SHA-256 | `71458c54a327762a69035b4076ab75dc325572294d2c06994b7a23dca1523f3e` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-07-19 23:57:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c08044ec23321c4df7fd08c6e1f5007` |
| SHA-1 | `4de9355acfa63ce23563ea94bb4d4f739527a00c` |
| SHA-256 | `71458c54a327762a69035b4076ab75dc325572294d2c06994b7a23dca1523f3e` |
| SHA3-384 | `96e10516c080027adf4be7990ff06ed6c5aa90ca081266d7df8802dba74f7c05f2dbb1ae6304d87593687d3674b63fc3` |
| TLSH | `T160C32B99F890DE52C6D42675FA5E428C732317B8C3EA7106CD209F3477EBD5A0E3A942` |
| SSDEEP | `3072:bfQSR06/dtBMozi7Gj2UQ4g8OeC9yUcIj/3ieJ0EsZZf1Dlwu:bf661pj2UQ4g8Ob9yUUeJ0/Z95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_71458c54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71458c54a327762a69035b4076ab75dc325572294d2c06994b7a23dca1523f3e"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-19 23:57:31"
  condition:
    hash.sha256(0, filesize) == "71458c54a327762a69035b4076ab75dc325572294d2c06994b7a23dca1523f3e"
}
```

### Sample 78: `0a39e484b65980b5`

| Field | Value |
|---|---|
| SHA-256 | `0a39e484b65980b577ad59bc3e5a634c900784ea54b8b6e2ff1200e9a5957511` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-07-19 23:56:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddd47cf8db5a8e32ed4e8a588c126ed3` |
| SHA-1 | `b007edeb98be39a9f83a6f5ae3662cdb9adf2f45` |
| SHA-256 | `0a39e484b65980b577ad59bc3e5a634c900784ea54b8b6e2ff1200e9a5957511` |
| SHA3-384 | `4f6bf9b4831ca88a3095bd4579c85421b8dbbf0198ec3b2c26b4c0bfdfb48d88a92882ce1b12e7bc8be7822b181e6c90` |
| TLSH | `T1F933F16BAE89EB81CB585C36E67B5FC22B0A0DB5C2717463F504904C11AB66017FEB87` |
| SSDEEP | `1536:4hOsRdBzty9xZLEnIdGmjySEDEKJqhzusLdfiE:4hJRddkvZYn0GmjmQKgtugr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_0a39e484
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a39e484b65980b577ad59bc3e5a634c900784ea54b8b6e2ff1200e9a5957511"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-19 23:56:47"
  condition:
    hash.sha256(0, filesize) == "0a39e484b65980b577ad59bc3e5a634c900784ea54b8b6e2ff1200e9a5957511"
}
```

### Sample 79: `dd67a211107f8237`

| Field | Value |
|---|---|
| SHA-256 | `dd67a211107f82378b1a0fe465f66f06a5b3e035ae8ff64fd8d9607d343f3fa9` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-19 23:54:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e96d8fa5fdb08ecb52919d14a9a313fb` |
| SHA-1 | `2dc96bd9e8dde4b48dc6486ac420f590f5a33cb3` |
| SHA-256 | `dd67a211107f82378b1a0fe465f66f06a5b3e035ae8ff64fd8d9607d343f3fa9` |
| SHA3-384 | `e38c381f8ef6666455492cc24f35ebce78f50e3a68f5de60df24303e083acd815bab6ff37fe111fbf334a09f216f0025` |
| TLSH | `T1F5C312DF11827143F9BE043FFEDC538A96F62A42FA39CCD77417940447DB0A1A8A6A54` |
| SSDEEP | `3072:Xa1cuYnXFtdCO7Gzo7VYWG22AmMP3gBPoYRLVK:Xx/XFtdCO7GzCiWGRAlP3YrRZK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_dd67a211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd67a211107f82378b1a0fe465f66f06a5b3e035ae8ff64fd8d9607d343f3fa9"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-19 23:54:45"
  condition:
    hash.sha256(0, filesize) == "dd67a211107f82378b1a0fe465f66f06a5b3e035ae8ff64fd8d9607d343f3fa9"
}
```

### Sample 80: `cee1fd2f7f8b07ac`

| Field | Value |
|---|---|
| SHA-256 | `cee1fd2f7f8b07acf1e012412219e2c1624b600a5716d885dba24c10453d26c7` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-19 23:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e99d191d1a82f4cbdd81859baf7405c` |
| SHA-1 | `4e49f3aee8a959a81511750151b82fb404869573` |
| SHA-256 | `cee1fd2f7f8b07acf1e012412219e2c1624b600a5716d885dba24c10453d26c7` |
| SHA3-384 | `14af5baa59bccdf36b0d237b21755a84561dc0cd14d01ae478d04f4e4e4c9e2a4690c5622706db78834aa2bed6c421f5` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F3E63324B6E012FFF6B2413CE8D190DAE2E5F46607B1C4DF468493E22E5B2D0897D667` |
| SSDEEP | `393216:bUeMzL2Cz3cR6QnyrNXMCHWUjXzcuI3/PGTAI:bUeaqCg9kNXMb8XwH/O7` |
| ICON-DHASH | `71f8d0f0e0e8f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_cee1fd2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cee1fd2f7f8b07acf1e012412219e2c1624b600a5716d885dba24c10453d26c7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 23:52:08"
  condition:
    hash.sha256(0, filesize) == "cee1fd2f7f8b07acf1e012412219e2c1624b600a5716d885dba24c10453d26c7"
}
```

### Sample 81: `a86c023a02f14547`

| Field | Value |
|---|---|
| SHA-256 | `a86c023a02f1454738b39f753f50777c238b4ea296ffc76cd41c3059f216be10` |
| Family label | `Amadey` |
| File name | `a86c023a02f1454738b39f753f50777c238b4ea296ffc.exe` |
| File type | `exe` |
| First seen | `2026-07-19 23:50:12` |
| Reporter | `abuse_ch` |
| Tags | `Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d11d7b9b175695c197014bc6aa2fbdb` |
| SHA-1 | `c25b20a5f15a0f69e0343b539bb4408a4e3739db` |
| SHA-256 | `a86c023a02f1454738b39f753f50777c238b4ea296ffc76cd41c3059f216be10` |
| SHA3-384 | `1ed84df2d19ae76712b87577937b9a336dcfd284752445bd12c8f5ef5c23353a944b31e0ab84d96d18b9ea6cf4126fb6` |
| IMPHASH | `8db30f7f23140d78d7f34e827c0f7dbd` |
| TLSH | `T12BB44A5AA25943FDE07BA17CD9535E42F639744703B18AEF039005772E532E2AF3AB60` |
| SSDEEP | `6144:LyB4DWmxd3DH+SOe3I3qEQ1kRtFlHvNzubRDePTRBhUCaraPOlfj1ohEVL8On:Lyi5h+SU3VQ1kRDhv0ibRQnoaVLN` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_081_a86c023a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a86c023a02f1454738b39f753f50777c238b4ea296ffc76cd41c3059f216be10"
    family = "Amadey"
    file_name = "a86c023a02f1454738b39f753f50777c238b4ea296ffc.exe"
    file_type = "exe"
    first_seen = "2026-07-19 23:50:12"
  condition:
    hash.sha256(0, filesize) == "a86c023a02f1454738b39f753f50777c238b4ea296ffc76cd41c3059f216be10"
}
```

### Sample 82: `e85149704da6ee8f`

| Field | Value |
|---|---|
| SHA-256 | `e85149704da6ee8f9bc1c55304c560d1a792180489d4859a64cf0a4e056ccf52` |
| Family label | `Amadey` |
| File name | `F8E68CDDF13A94D821A4B265172A0E32.exe` |
| File type | `exe` |
| First seen | `2026-07-19 23:45:09` |
| Reporter | `abuse_ch` |
| Tags | `Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8e68cddf13a94d821a4b265172a0e32` |
| SHA-1 | `16646bfd7f6554cd170fb373ce813c24f37e829e` |
| SHA-256 | `e85149704da6ee8f9bc1c55304c560d1a792180489d4859a64cf0a4e056ccf52` |
| SHA3-384 | `38bb14e6c381d318d9a55f39e7bc6158d33f033d79409177329d31836fcddf02c411dbcc289d018f400ba18fde761e79` |
| IMPHASH | `cd702dbfbd74cf5a80f59195b2460134` |
| TLSH | `T1A4D4C013B9A18476E1724635CD68EB54977DBC700F20ABCB67C005AA6EB06C0AF37767` |
| SSDEEP | `12288:L7bqVdZJ9HO5ov7zbrjr2RMh+luyxBlDetAqxSvwiA:L7evcojzbqRM+luyb4i` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_082_e8514970
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e85149704da6ee8f9bc1c55304c560d1a792180489d4859a64cf0a4e056ccf52"
    family = "Amadey"
    file_name = "F8E68CDDF13A94D821A4B265172A0E32.exe"
    file_type = "exe"
    first_seen = "2026-07-19 23:45:09"
  condition:
    hash.sha256(0, filesize) == "e85149704da6ee8f9bc1c55304c560d1a792180489d4859a64cf0a4e056ccf52"
}
```

### Sample 83: `e6f4c46f2a72a4d8`

| Field | Value |
|---|---|
| SHA-256 | `e6f4c46f2a72a4d8b1eda2c2c431c64d73eae7057221b35a6fc16138e4dc4d43` |
| Family label | `ValleyRAT` |
| File name | `DingTalkD_Setup2026.exe` |
| File type | `exe` |
| First seen | `2026-07-19 23:10:26` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0561a3921c93fe5913454241362e80e2` |
| SHA-1 | `602862693c2edba1df17afd61b4fcdc3a5ca139f` |
| SHA-256 | `e6f4c46f2a72a4d8b1eda2c2c431c64d73eae7057221b35a6fc16138e4dc4d43` |
| SHA3-384 | `c97ae0708c750760959eb23c491268b69f940b5e862189307c8157380962d52b853e9b34480bee535399a4327b8b46d2` |
| IMPHASH | `40ab50289f7ef5fae60801f88d4541fc` |
| TLSH | `T1F7A73323B3C7A13FF45E0B3B16B3A16094FB9A11B512BD678AC440ECDE264541E7E61B` |
| SSDEEP | `786432:LhGfMHhij2MOLPstwdk0dyRFsNBvkOPFkFFQB7msB/PZkl4h2r6HWeyZpy0bfiGs:LhGfMBijDO0rs0OPBysNxklDrvpy0bf6` |
| ICON-DHASH | `c488b8f0e2b692cc` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_083_e6f4c46f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6f4c46f2a72a4d8b1eda2c2c431c64d73eae7057221b35a6fc16138e4dc4d43"
    family = "ValleyRAT"
    file_name = "DingTalkD_Setup2026.exe"
    file_type = "exe"
    first_seen = "2026-07-19 23:10:26"
  condition:
    hash.sha256(0, filesize) == "e6f4c46f2a72a4d8b1eda2c2c431c64d73eae7057221b35a6fc16138e4dc4d43"
}
```

### Sample 84: `2c292ea5d66b3aa9`

| Field | Value |
|---|---|
| SHA-256 | `2c292ea5d66b3aa9b531e60f55d6af341d101961a649614d022111ff743492f3` |
| Family label | `RemusStealer` |
| File name | `setup_euone.bin` |
| File type | `exe` |
| First seen | `2026-07-19 22:52:07` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, GCleaner, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0b2dbfbc3a1d6474628f5268cf884fc` |
| SHA-1 | `0bf07f316fe80ace56c947a2021e56a07dab0d6b` |
| SHA-256 | `2c292ea5d66b3aa9b531e60f55d6af341d101961a649614d022111ff743492f3` |
| SHA3-384 | `ef9ee21db50c02c9779f3039b3c192622c2e053534c16c8fe475e8b51b61fe85e3ade66eedfae1092a573e0af4a73190` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BF75192C27F969A8F1B77F358AF56145DB3BBB72A93BD64E0500820F1532A018D52F36` |
| SSDEEP | `24576:z/oH+J7+nEv4+540g7LYWgq2mJShCYu+hn6Ji1kLA7BieniYvmMBjz:DQEv4+O0g7LYW72mUhPu0n6JiyzYuy` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_084_2c292ea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c292ea5d66b3aa9b531e60f55d6af341d101961a649614d022111ff743492f3"
    family = "RemusStealer"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-07-19 22:52:07"
  condition:
    hash.sha256(0, filesize) == "2c292ea5d66b3aa9b531e60f55d6af341d101961a649614d022111ff743492f3"
}
```

### Sample 85: `70005bbb6db8afaf`

| Field | Value |
|---|---|
| SHA-256 | `70005bbb6db8afaf30661df0311395fb3cf7bf1ece51d511841d4f4def908a29` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-19 22:40:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97657493b3bddf2092af5c890f971a33` |
| SHA-1 | `9fedac487a28b0520ef0fd67e509d95701058bd4` |
| SHA-256 | `70005bbb6db8afaf30661df0311395fb3cf7bf1ece51d511841d4f4def908a29` |
| SHA3-384 | `cd41f2adf8a8a5273ba4e720c16f15c6c2e1990d8f13bca0fe0aaf5e369e48ba0413a4fc28ec42d6cac3f8c4059d5dc5` |
| TLSH | `T1CCC32999F880DE52C6D5267AFB5E418C33231778D3DA7106CE109E3477EBA5A0E3A942` |
| SSDEEP | `3072:hH0Q8oVUpSaVDSMcMZIBTcYEEUAeMMWmNwhNAfSsXMFNKFpAiuKf1Dll:hKUeHZwTcYEEUAeMMWAwoasXdiFK95l` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_70005bbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70005bbb6db8afaf30661df0311395fb3cf7bf1ece51d511841d4f4def908a29"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-19 22:40:53"
  condition:
    hash.sha256(0, filesize) == "70005bbb6db8afaf30661df0311395fb3cf7bf1ece51d511841d4f4def908a29"
}
```

### Sample 86: `f0ea2d0017a88323`

| Field | Value |
|---|---|
| SHA-256 | `f0ea2d0017a88323d730042c2b571a4d06cd8dbe169c3cef2e457bd0c5d676ff` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-19 22:40:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6e9faf0f85c8f030cd7b8373a409769` |
| SHA-1 | `3e8c93ca78831ebf02f99a402766b3fcd6e71fd2` |
| SHA-256 | `f0ea2d0017a88323d730042c2b571a4d06cd8dbe169c3cef2e457bd0c5d676ff` |
| SHA3-384 | `d894f709e50fc8c8c0af3ba2ec5a3f120a2da3bb877d3ae502f27b307d470ba440e86aa82b725b4b7a0655f63e18e487` |
| TLSH | `T11B43F182CE61FE4AFB742233C91E8A41680999FCDD6579B291B215146AF32DC3FF0583` |
| SSDEEP | `768:fySvUwRefU1hhRRjTj15WXdQv8qzYrHQKKPvyMuAnFy09p3U4RufefPh5BnuppR9:DvUwV15WGkqzewK6avAnFyOUquUP1fe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_f0ea2d00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0ea2d0017a88323d730042c2b571a4d06cd8dbe169c3cef2e457bd0c5d676ff"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-19 22:40:40"
  condition:
    hash.sha256(0, filesize) == "f0ea2d0017a88323d730042c2b571a4d06cd8dbe169c3cef2e457bd0c5d676ff"
}
```

### Sample 87: `4280445841f4898c`

| Field | Value |
|---|---|
| SHA-256 | `4280445841f4898c26f409239f1a623304b637363087bd88a6ee9506e0256463` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Bot.20354.26072` |
| File type | `elf` |
| First seen | `2026-07-19 22:26:25` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d18fa4617e884ead6bca454ce4184440` |
| SHA-1 | `c15d1b9d400d518c91ec4e105aaf6ac46b93954a` |
| SHA-256 | `4280445841f4898c26f409239f1a623304b637363087bd88a6ee9506e0256463` |
| SHA3-384 | `7ab47d194a392afa33e09ce290aab5d768380955e29e0f2744b808c9aa87e37fd2009d3726893521d528af95d7153faf` |
| TLSH | `T191E3FA07A951DF12D1C211B9FF5E425937136F78D3EE72029D24AFB0278A8EB0E7A116` |
| SSDEEP | `3072:Ss7DUEY1wmZXvNfclfalIxnqjPNoQNyMKrvBT:ScDTYLZXFfcpasn2NoXMKrvBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_42804458
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4280445841f4898c26f409239f1a623304b637363087bd88a6ee9506e0256463"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Bot.20354.26072"
    file_type = "elf"
    first_seen = "2026-07-19 22:26:25"
  condition:
    hash.sha256(0, filesize) == "4280445841f4898c26f409239f1a623304b637363087bd88a6ee9506e0256463"
}
```

### Sample 88: `a832528ba9cac310`

| Field | Value |
|---|---|
| SHA-256 | `a832528ba9cac310fd4e5bcb7f8523865a6a19b2c95891515f323009910f610e` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Linux.Bot.14621.11299` |
| File type | `elf` |
| First seen | `2026-07-19 22:26:24` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2279338d70c41939fdf34740ab1871c8` |
| SHA-1 | `edca14f6f023ac919a5a55495b95c51a5d7fc33d` |
| SHA-256 | `a832528ba9cac310fd4e5bcb7f8523865a6a19b2c95891515f323009910f610e` |
| SHA3-384 | `fe5a71c3badcf2e078f51d082e06a69aeb9e0393e3c2a3f47eafdf96f76a13fd869bea36fe9172765c49f2f601ae7dac` |
| TLSH | `T1ACC3E749A9429F01D4D735FAFB9F425833536BACE3F97101EA206F6023CA99B0F76512` |
| SSDEEP | `3072:hV/OR8I3fQOon5rJUGaxCwYNXmt5Waq/DsAMYjLArC:r/08ali5ruGaxCw4m5S/4ALjLArC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_a832528b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a832528ba9cac310fd4e5bcb7f8523865a6a19b2c95891515f323009910f610e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.Bot.14621.11299"
    file_type = "elf"
    first_seen = "2026-07-19 22:26:24"
  condition:
    hash.sha256(0, filesize) == "a832528ba9cac310fd4e5bcb7f8523865a6a19b2c95891515f323009910f610e"
}
```

### Sample 89: `2d0ae80f9689433e`

| Field | Value |
|---|---|
| SHA-256 | `2d0ae80f9689433e7b84ee280e11ce5263f918f6f23288c3d9bfe6ea187408b2` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-19 22:10:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c2b6219006241fa746000734eb7b8ce` |
| SHA-1 | `809a43c46691ed2703aa48e3f2b2fae736da08f0` |
| SHA-256 | `2d0ae80f9689433e7b84ee280e11ce5263f918f6f23288c3d9bfe6ea187408b2` |
| SHA3-384 | `bfaf13263c401768736045473dcfe666ffabe0548ce05ecd88c2fe58a5edbfe48ddc529918de16a9a608ffb5d3b12ab8` |
| TLSH | `T1B6C28E966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:g8vCB+25j6es8Ruzg9FYpMSUpi+20qUpi+20YQX:g8l25JOmd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_2d0ae80f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d0ae80f9689433e7b84ee280e11ce5263f918f6f23288c3d9bfe6ea187408b2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-19 22:10:42"
  condition:
    hash.sha256(0, filesize) == "2d0ae80f9689433e7b84ee280e11ce5263f918f6f23288c3d9bfe6ea187408b2"
}
```

### Sample 90: `2ac492ce3b66a797`

| Field | Value |
|---|---|
| SHA-256 | `2ac492ce3b66a7979ceba5f26c594f0a69698d19b2ffdb56ac8b741dc30f8e5e` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-19 22:10:11` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0c4fe17a83df1621ce3db824684bb55` |
| SHA-1 | `5a8031f3c9ff3c65ebaa0aa60f9e59feba83c71c` |
| SHA-256 | `2ac492ce3b66a7979ceba5f26c594f0a69698d19b2ffdb56ac8b741dc30f8e5e` |
| SHA3-384 | `34b28d7e671e777654731d2e74f43b9bc010c6379ee677b8fe72a8ef9699cdadcf1ca6461652c27ba998006dfc95397a` |
| IMPHASH | `d619fbf0a108fb3ff7113afe795582e3` |
| TLSH | `T1C1728D07EE959212E3E44CB401719B5F067F587333A6A2DFF373660A6F747504920AAB` |
| SSDEEP | `384:KV88In4z+hDTXJMQWSc7BLs1QuCm6Ee9nlAnXX5GMLWV:I8Tny+hvaQENs1Qum3O7LW` |
| ICON-DHASH | `3b67173b1b1f2f3b` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_090_2ac492ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ac492ce3b66a7979ceba5f26c594f0a69698d19b2ffdb56ac8b741dc30f8e5e"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-19 22:10:11"
  condition:
    hash.sha256(0, filesize) == "2ac492ce3b66a7979ceba5f26c594f0a69698d19b2ffdb56ac8b741dc30f8e5e"
}
```

### Sample 91: `b0f43bcb2af12810`

| Field | Value |
|---|---|
| SHA-256 | `b0f43bcb2af128106bda1ac0495f70028d364056e4a9521e4e06f1b83769e022` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-19 22:03:24` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX9.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00e4147f5e232c04d27d48fff55abf96` |
| SHA-1 | `794dd38cf7afcd86b2420ccc3d65c7b2bc4aaba5` |
| SHA-256 | `b0f43bcb2af128106bda1ac0495f70028d364056e4a9521e4e06f1b83769e022` |
| SHA3-384 | `fd29767a609bc319a0e296ab37b1fceb6fdebf256d7828e9c571ea98b50838b539e888fb5a26d015a84201c8dd87b35e` |
| IMPHASH | `013c74198fc6e42dcf33737d6c40c012` |
| TLSH | `T18C852353A7E88163F6A6377CA8F11323B2793CA01B7393DF5A406A9C29337C65531726` |
| SSDEEP | `49152:HkfovDwaxCH/WmLWoi3xS0TASv9hiXScHQ:DEu34crv9YScw` |
| ICON-DHASH | `fc60f0f6f7b6f061` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_b0f43bcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0f43bcb2af128106bda1ac0495f70028d364056e4a9521e4e06f1b83769e022"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-19 22:03:24"
  condition:
    hash.sha256(0, filesize) == "b0f43bcb2af128106bda1ac0495f70028d364056e4a9521e4e06f1b83769e022"
}
```

### Sample 92: `932e3c4ae1d5404c`

| Field | Value |
|---|---|
| SHA-256 | `932e3c4ae1d5404ceade8dfd386182800b91eb93794c914b7f09b094996b061e` |
| Family label | `Mirai` |
| File name | `tmpsl` |
| File type | `elf` |
| First seen | `2026-07-19 22:02:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `faaf40134b1b9b479e1540e86c82705e` |
| SHA-1 | `16cb6e9c55652f71f5d0f7bb12c02fe2af2edbfc` |
| SHA-256 | `932e3c4ae1d5404ceade8dfd386182800b91eb93794c914b7f09b094996b061e` |
| SHA3-384 | `31ebae9ea9f41de06bd4f327af86d6196d4eabadfa6a502a4521509a8f26b0ebd0c04dfe8c6b5b70a1635ac6d88da675` |
| TLSH | `T154C3190BFB600EFBE81FDD3705A9174A35CCA55622E93B767634C92CB64A14B09E3C64` |
| SSDEEP | `1536:t/jxpfpkJSkipJREqofJoiLckd5uw4uTEnxm5CgRjB0I63lVLXP8UZDl3xRhjBRh:tdhpkJUWeiqss1VbprdRwv9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_932e3c4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "932e3c4ae1d5404ceade8dfd386182800b91eb93794c914b7f09b094996b061e"
    family = "Mirai"
    file_name = "tmpsl"
    file_type = "elf"
    first_seen = "2026-07-19 22:02:49"
  condition:
    hash.sha256(0, filesize) == "932e3c4ae1d5404ceade8dfd386182800b91eb93794c914b7f09b094996b061e"
}
```

### Sample 93: `726ca85760e03548`

| Field | Value |
|---|---|
| SHA-256 | `726ca85760e035489a885da5b01dbe62c7a1e0b52e1735b656adbc899090a572` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-19 22:00:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69d16a5ab6e1de58af06039c365f7a91` |
| SHA-1 | `7b0dec3128dc6ed5f1490d3c2596804a012f695c` |
| SHA-256 | `726ca85760e035489a885da5b01dbe62c7a1e0b52e1735b656adbc899090a572` |
| SHA3-384 | `6fced0b4c0d10e76c87906682a73219c21d144f02e964f4929f836d5bfd650ebc6df817b85afd59c2887d284514aec00` |
| TLSH | `T15C237D652A817C14AA98C4371D7E2F0CB9AD43E6324452ED7FCF3CF68C4A69DA11871D` |
| SSDEEP | `768:8pXOGVvw9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:8VLFcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_726ca857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "726ca85760e035489a885da5b01dbe62c7a1e0b52e1735b656adbc899090a572"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-19 22:00:43"
  condition:
    hash.sha256(0, filesize) == "726ca85760e035489a885da5b01dbe62c7a1e0b52e1735b656adbc899090a572"
}
```

### Sample 94: `c7e7d77602c121eb`

| Field | Value |
|---|---|
| SHA-256 | `c7e7d77602c121ebe2785d8e4068b7d459abe975ad9e3e8471ba28e9783b8dca` |
| Family label | `Mirai` |
| File name | `ohshit.i686` |
| File type | `elf` |
| First seen | `2026-07-19 22:00:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7b10af0ce884e8fd49c240eb2fdd249` |
| SHA-1 | `a81d2162ac5bb8a757d0e95be268f6fa73d9b9a9` |
| SHA-256 | `c7e7d77602c121ebe2785d8e4068b7d459abe975ad9e3e8471ba28e9783b8dca` |
| SHA3-384 | `2d34284b26f8bb278057eae3bb754b78af197f62df94715a2305cc97715c215b5d6dfe1e66142a2c90d0c8801b825f9e` |
| TLSH | `T1F3A329C5FA8B80F6D90748309027F73FD632E9798071DBA9EF559E36D933581A216388` |
| TELFHASH | `t18531f3f9aa761ce867d0a803e28e6f31bd1d67b755303ae205f72078396664111bad38` |
| SSDEEP | `1536:pu8JYvDni1mLnTWZT+9TGZ7VGeIpgGp7EnW2W1sSZFfDZd4sP+l6ik4qt88:s8xsLTIOTG52KGp9uSZFftd5iK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_c7e7d776
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7e7d77602c121ebe2785d8e4068b7d459abe975ad9e3e8471ba28e9783b8dca"
    family = "Mirai"
    file_name = "ohshit.i686"
    file_type = "elf"
    first_seen = "2026-07-19 22:00:41"
  condition:
    hash.sha256(0, filesize) == "c7e7d77602c121ebe2785d8e4068b7d459abe975ad9e3e8471ba28e9783b8dca"
}
```

### Sample 95: `40c98ff9673f67cf`

| Field | Value |
|---|---|
| SHA-256 | `40c98ff9673f67cfa82d9e2e16a2e55644f71fec87e2d92f25821a2b917f8145` |
| Family label | `ValleyRAT` |
| File name | `9C986D7E311CE1E8DB7BD65B8271A87D.exe` |
| File type | `exe` |
| First seen | `2026-07-19 22:00:16` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c986d7e311ce1e8db7bd65b8271a87d` |
| SHA-1 | `5c542d609013e48e6095af6ce5ef28208a35bb3f` |
| SHA-256 | `40c98ff9673f67cfa82d9e2e16a2e55644f71fec87e2d92f25821a2b917f8145` |
| SHA3-384 | `8beb180ac740b5a7ed929023c19802012f71ffa41a453d26c6813e927ababf9f1d8bf75463ed5d4e32755af098db79a1` |
| IMPHASH | `d3f487c6c23e9d9845b2eca3fbdd93dd` |
| TLSH | `T1F4D77C0272A54A61FDA23B7186D81727EF3ABD3157B648973E0C2BF20F7A3154A27711` |
| SSDEEP | `393216:GyXTrculw3aURH+EIXBYNitrgaFa1305l/9CidVeJoqaQKiYq7eSdK0ngpk+HcM+:RgRErYd7IzIT9WAHNei` |
| ICON-DHASH | `fadadac2a2b8c4e4` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_095_40c98ff9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40c98ff9673f67cfa82d9e2e16a2e55644f71fec87e2d92f25821a2b917f8145"
    family = "ValleyRAT"
    file_name = "9C986D7E311CE1E8DB7BD65B8271A87D.exe"
    file_type = "exe"
    first_seen = "2026-07-19 22:00:16"
  condition:
    hash.sha256(0, filesize) == "40c98ff9673f67cfa82d9e2e16a2e55644f71fec87e2d92f25821a2b917f8145"
}
```

### Sample 96: `5a99dfdf7905c92e`

| Field | Value |
|---|---|
| SHA-256 | `5a99dfdf7905c92ed743dd1d5fdec044ad2fcb2ecee6d088a7349f7a719d552b` |
| Family label | `Mirai` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-07-19 21:56:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5ee25c5b2ad46869e6051b05fa33498` |
| SHA-1 | `769de354ed58edf0058a1050672956785ee67667` |
| SHA-256 | `5a99dfdf7905c92ed743dd1d5fdec044ad2fcb2ecee6d088a7349f7a719d552b` |
| SHA3-384 | `77fa049e35c6a71266077a473f0ad6f5302909aa33b5fa3c605e32b322ec65104f9ed1ca17cd9c11444b6eccc1d42d67` |
| TLSH | `T10FC37BC2B10D7EAEE5932E7DC20617176E1C5E519C83410290B5FE532AB76E31E36ACB` |
| TELFHASH | `t18ad0b1f1878fa601458cdbcd83ca775c4a0dd141004bef43fd22553c80a591cb91998f` |
| SSDEEP | `3072:5groW5JrtBP0Py3HZRUyqsPTFESRvgWR6sQLLjyoK:iroGp0PKkyfPpzvgWEsQXvK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_5a99dfdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a99dfdf7905c92ed743dd1d5fdec044ad2fcb2ecee6d088a7349f7a719d552b"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-07-19 21:56:42"
  condition:
    hash.sha256(0, filesize) == "5a99dfdf7905c92ed743dd1d5fdec044ad2fcb2ecee6d088a7349f7a719d552b"
}
```

### Sample 97: `5f85e22acb86ebc9`

| Field | Value |
|---|---|
| SHA-256 | `5f85e22acb86ebc9031256efb11af9f1eed58621312a0c0bf448fe699e809c92` |
| Family label | `RemusStealer` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-07-19 21:52:17` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52f56cc1abe3ed2f437aaae0c74f5db9` |
| SHA-1 | `196515f98d4a043751629ffdc6e4fc371391b5b3` |
| SHA-256 | `5f85e22acb86ebc9031256efb11af9f1eed58621312a0c0bf448fe699e809c92` |
| SHA3-384 | `c51e35d0238fdde3f43a7148b0c8efc12a61db19c5d2122816e0a0dcb95c0a45602a65b66e8b6f62728143fb6273122b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T13DC54A077CE049E5C0AAA33589B66192B775BC090B3633E72E9077782F727D09E79B44` |
| SSDEEP | `24576:VpTdyJ3QrMFVmj1Efw8p8S2l0uVyTFNAJCQi1ZrSEtxJBele5r9DY7v7Skn0ih:VpTy3QYFUJEnp8S2hgJNECyoKSu06` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_097_5f85e22a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f85e22acb86ebc9031256efb11af9f1eed58621312a0c0bf448fe699e809c92"
    family = "RemusStealer"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-19 21:52:17"
  condition:
    hash.sha256(0, filesize) == "5f85e22acb86ebc9031256efb11af9f1eed58621312a0c0bf448fe699e809c92"
}
```

### Sample 98: `36e8a488df3ed19c`

| Field | Value |
|---|---|
| SHA-256 | `36e8a488df3ed19cc2f393271814f04569bd1f63fd32349ad13c533f6421e9ce` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-19 21:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eeb1d2d5f588e18ced050255403a41c4` |
| SHA-1 | `05d359cb2de06e7cbb1c336d33ce4f0e3071fdb6` |
| SHA-256 | `36e8a488df3ed19cc2f393271814f04569bd1f63fd32349ad13c533f6421e9ce` |
| SHA3-384 | `ea86921d54ad70c3c5ba26e7cc9a3129dfb4452a8d2318c170bbf7392366b422106793e7643c1a7ca765a64ad5d84852` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T160E63328A6D002FEF6734038EED2659ADAA5B46917B2C5CF5B6887D15E031F0CD39723` |
| SSDEEP | `393216:94YSlOp8OEQbQ5F26Ae1uKACVeXMCHWUjXicuI3/PGTAI:92kbQ51AekrXMb8XfH/O7` |
| ICON-DHASH | `71f0d0d8c8e8f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_36e8a488
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36e8a488df3ed19cc2f393271814f04569bd1f63fd32349ad13c533f6421e9ce"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 21:52:09"
  condition:
    hash.sha256(0, filesize) == "36e8a488df3ed19cc2f393271814f04569bd1f63fd32349ad13c533f6421e9ce"
}
```

### Sample 99: `b59653f1e2b8dae7`

| Field | Value |
|---|---|
| SHA-256 | `b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0` |
| Family label | `RedLineStealer` |
| File name | `8C21B2FBDED2FAEB6DB2E7A20C513CDB.exe` |
| File type | `exe` |
| First seen | `2026-07-19 21:50:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, RedLineStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c21b2fbded2faeb6db2e7a20c513cdb` |
| SHA-1 | `38b837cc5fe814ca9580f9029386aa405f8e94df` |
| SHA-256 | `b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0` |
| SHA3-384 | `7f3aa4bc816d7a0724effda2ddadff69eb5305762c8a3e15927baab9e5b3654d4cc054832981e94a854091d426bb370c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19DA35D3067AC9F19EAFD1B75B4B2012043F0E08A9091FB4A4DC194E71FA7B865957EF2` |
| SSDEEP | `1536:5qsCbqDylbG6jejoigIj43Ywzi0Zb78ivombfexv0ujXyyed2z3tmulgS6p8l:XEwiYj+zi0ZbYe1g0ujyzdT8` |

#### Technical Assessment

- The sample is tracked as `RedLineStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RedLineStealer_099_b59653f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0"
    family = "RedLineStealer"
    file_name = "8C21B2FBDED2FAEB6DB2E7A20C513CDB.exe"
    file_type = "exe"
    first_seen = "2026-07-19 21:50:05"
  condition:
    hash.sha256(0, filesize) == "b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0"
}
```

### Sample 100: `50fa67706d725e7a`

| Field | Value |
|---|---|
| SHA-256 | `50fa67706d725e7a22247a361c6d6907eab4633c20c471705cae8b10228627f0` |
| Family label | `Mirai` |
| File name | `tarm6` |
| File type | `elf` |
| First seen | `2026-07-19 21:46:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2567790fb43acf9e15ea987d2ef1c1d` |
| SHA-1 | `d0897e85582aee9929e63bc0b5accbadffd75af7` |
| SHA-256 | `50fa67706d725e7a22247a361c6d6907eab4633c20c471705cae8b10228627f0` |
| SHA3-384 | `6f03b96e00940bb17901ee3acfd2ac335acff9b5fc1c193463e22858e32a348706884fb56b1bd2d64a0a114766b209b3` |
| TLSH | `T123A32A96B881AA24C6C1467BFE0F118E33135BBCE2DF73129D145B6077CB56B0E3A916` |
| TELFHASH | `t1a5f0c0a097b019e837c0438382af446e5fec703f2606a631e8ec2b2bd615251f073017` |
| SSDEEP | `3072:p88HoCuXoD1GgnI/8JPQFC33Xvaaax+WERGPsaVlCEwuq:phHXognI/ePQg3nvaBx+gP32+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_50fa6770
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50fa67706d725e7a22247a361c6d6907eab4633c20c471705cae8b10228627f0"
    family = "Mirai"
    file_name = "tarm6"
    file_type = "elf"
    first_seen = "2026-07-19 21:46:41"
  condition:
    hash.sha256(0, filesize) == "50fa67706d725e7a22247a361c6d6907eab4633c20c471705cae8b10228627f0"
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
 * Generated: 2026-07-20T04:08:51.801177+00:00
 */

rule MalwareBazaar_unknown_001_fa1e42ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa1e42eccf2edbaa7306cd40636bf579a6588e3d0fa61584e1ccb92a00d01ecf"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 03:52:08"
  condition:
    hash.sha256(0, filesize) == "fa1e42eccf2edbaa7306cd40636bf579a6588e3d0fa61584e1ccb92a00d01ecf"
}

rule MalwareBazaar_unknown_002_c125bbd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c125bbd2333186b24a2dc74b99c7f3db4fca9fbe86af42e68cc4999252453a2a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 02:52:09"
  condition:
    hash.sha256(0, filesize) == "c125bbd2333186b24a2dc74b99c7f3db4fca9fbe86af42e68cc4999252453a2a"
}

rule MalwareBazaar_unknown_003_da49d5a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da49d5a6abbb96438cd2daecd2643fb5f38122ce4d9cda6d072704e54c17d3ed"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-20 02:11:36"
  condition:
    hash.sha256(0, filesize) == "da49d5a6abbb96438cd2daecd2643fb5f38122ce4d9cda6d072704e54c17d3ed"
}

rule MalwareBazaar_Mirai_004_c3ba74fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3ba74fb10475f9e9db534ad484bbcfaa7ee1fd571639b35f57906e1fca1d716"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 02:01:35"
  condition:
    hash.sha256(0, filesize) == "c3ba74fb10475f9e9db534ad484bbcfaa7ee1fd571639b35f57906e1fca1d716"
}

rule MalwareBazaar_Mirai_005_5f85a860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f85a860b374bb803aff4cc9e1d928b5ad3d678c0e252b45e7b88d3bed88b152"
    family = "Mirai"
    file_name = "ohshit.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 01:59:25"
  condition:
    hash.sha256(0, filesize) == "5f85a860b374bb803aff4cc9e1d928b5ad3d678c0e252b45e7b88d3bed88b152"
}

rule MalwareBazaar_unknown_006_45ce79bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45ce79bbac91e3ca67d3cc7dd150ada9109cf6a52b09d3e6eaad8adb4df30777"
    family = "unknown"
    file_name = "mload.sh"
    file_type = "sh"
    first_seen = "2026-07-20 01:55:21"
  condition:
    hash.sha256(0, filesize) == "45ce79bbac91e3ca67d3cc7dd150ada9109cf6a52b09d3e6eaad8adb4df30777"
}

rule MalwareBazaar_unknown_007_bec299c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bec299c617dfa95b0b9ccb083ee9d2510b4b1c8f5785d1d6d9f389a1b9e4f9b9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 01:52:09"
  condition:
    hash.sha256(0, filesize) == "bec299c617dfa95b0b9ccb083ee9d2510b4b1c8f5785d1d6d9f389a1b9e4f9b9"
}

rule MalwareBazaar_Mirai_008_3bc7efee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bc7efeed4bbebc6a515be55736e6726dd3873553b00e70af513f8ab05761422"
    family = "Mirai"
    file_name = "ohshit.arm"
    file_type = "elf"
    first_seen = "2026-07-20 01:48:40"
  condition:
    hash.sha256(0, filesize) == "3bc7efeed4bbebc6a515be55736e6726dd3873553b00e70af513f8ab05761422"
}

rule MalwareBazaar_Mirai_009_5c299c02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c299c0278faf2fb51febdde019a7f24ea147e6c968b688cb05f7cef4d4f76a0"
    family = "Mirai"
    file_name = "ohshit.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 01:48:38"
  condition:
    hash.sha256(0, filesize) == "5c299c0278faf2fb51febdde019a7f24ea147e6c968b688cb05f7cef4d4f76a0"
}

rule MalwareBazaar_Mirai_010_b3512d6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3512d6dd71746655648180b30a3812939c7adbcbb2958b3abf6ae004f691156"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-07-20 01:40:09"
  condition:
    hash.sha256(0, filesize) == "b3512d6dd71746655648180b30a3812939c7adbcbb2958b3abf6ae004f691156"
}

rule MalwareBazaar_Mirai_011_338b19ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "338b19ba5a4d15cca22d48c02c298064164d9db9654e7473880d12211f3cd185"
    family = "Mirai"
    file_name = "ohshit.spc"
    file_type = "elf"
    first_seen = "2026-07-20 01:40:07"
  condition:
    hash.sha256(0, filesize) == "338b19ba5a4d15cca22d48c02c298064164d9db9654e7473880d12211f3cd185"
}

rule MalwareBazaar_Mirai_012_49d9e5fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49d9e5fda3eb3064f04e6d2ac0e4876b509392cc65ad2445f0806339c6a1a356"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 01:38:30"
  condition:
    hash.sha256(0, filesize) == "49d9e5fda3eb3064f04e6d2ac0e4876b509392cc65ad2445f0806339c6a1a356"
}

rule MalwareBazaar_Mirai_013_aee70505
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aee705055f820ed7147ce7ecd39f293ee56e71a2118d5bd0ca21584bfb89124f"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 01:38:05"
  condition:
    hash.sha256(0, filesize) == "aee705055f820ed7147ce7ecd39f293ee56e71a2118d5bd0ca21584bfb89124f"
}

rule MalwareBazaar_Mirai_014_6327eb7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6327eb7f0e774b2be50bcc9665bfcb4a35f120c101368d4800de7e0b94827b0d"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-20 01:33:28"
  condition:
    hash.sha256(0, filesize) == "6327eb7f0e774b2be50bcc9665bfcb4a35f120c101368d4800de7e0b94827b0d"
}

rule MalwareBazaar_Mirai_015_c0685aa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0685aa4c68bbecb0bc5a61c3ee46eb9056ae33ded414784761d8ccac48e5bbd"
    family = "Mirai"
    file_name = "ohshit.ppc"
    file_type = "elf"
    first_seen = "2026-07-20 01:31:24"
  condition:
    hash.sha256(0, filesize) == "c0685aa4c68bbecb0bc5a61c3ee46eb9056ae33ded414784761d8ccac48e5bbd"
}

rule MalwareBazaar_MaskGramStealer_016_e8c73ce5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8c73ce5eb660ea6570b5bf5f560eaf994394da02148f7df10aefac1fda8a756"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-20 01:30:47"
  condition:
    hash.sha256(0, filesize) == "e8c73ce5eb660ea6570b5bf5f560eaf994394da02148f7df10aefac1fda8a756"
}

rule MalwareBazaar_Mirai_017_85084744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "850847440cf308046af0139b1c74e7059d19e82f591705f772d4568d854c1079"
    family = "Mirai"
    file_name = "ohshit.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 01:26:36"
  condition:
    hash.sha256(0, filesize) == "850847440cf308046af0139b1c74e7059d19e82f591705f772d4568d854c1079"
}

rule MalwareBazaar_unknown_018_628492c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "628492c45cbb8e26f573675db32cb5687a40b2b4dd6d5e1c73a37c14558bb9a6"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-20 01:26:34"
  condition:
    hash.sha256(0, filesize) == "628492c45cbb8e26f573675db32cb5687a40b2b4dd6d5e1c73a37c14558bb9a6"
}

rule MalwareBazaar_Mirai_019_388a9e43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "388a9e43f9baec112abc28f1e058072e5ee847b0331388896f71517b832aff0d"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-20 01:20:57"
  condition:
    hash.sha256(0, filesize) == "388a9e43f9baec112abc28f1e058072e5ee847b0331388896f71517b832aff0d"
}

rule MalwareBazaar_Mirai_020_f77256eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f77256eb64c144a1f433705087bcefffbf59c79f6953a39d7c0d745ceab31573"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-20 01:20:16"
  condition:
    hash.sha256(0, filesize) == "f77256eb64c144a1f433705087bcefffbf59c79f6953a39d7c0d745ceab31573"
}

rule MalwareBazaar_Gafgyt_021_6afda92c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6afda92c73f89ddce818f752d2d3fb7f39cef34c53478ecd993cd42936a12efc"
    family = "Gafgyt"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-20 01:15:21"
  condition:
    hash.sha256(0, filesize) == "6afda92c73f89ddce818f752d2d3fb7f39cef34c53478ecd993cd42936a12efc"
}

rule MalwareBazaar_unknown_022_b32f71c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b32f71c40fffc53327ca712d82ad9349d2a4f396826fac9940824f48c878461f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-20 01:15:19"
  condition:
    hash.sha256(0, filesize) == "b32f71c40fffc53327ca712d82ad9349d2a4f396826fac9940824f48c878461f"
}

rule MalwareBazaar_unknown_023_87525799
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "875257991745c0557dd2fb00cd40934de6281ded379289c26d900bca2628f25f"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-20 01:08:32"
  condition:
    hash.sha256(0, filesize) == "875257991745c0557dd2fb00cd40934de6281ded379289c26d900bca2628f25f"
}

rule MalwareBazaar_Mirai_024_02e960e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02e960e5278a686f38a356e5e7842def5797e07ec0b06b8fe5f34d0b28fde0b2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-20 01:08:30"
  condition:
    hash.sha256(0, filesize) == "02e960e5278a686f38a356e5e7842def5797e07ec0b06b8fe5f34d0b28fde0b2"
}

rule MalwareBazaar_Mirai_025_e7889354
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7889354c0d2cce6cc0c6a34ec13afd79bf361388e76ed2b3b987e0613d9c6a6"
    family = "Mirai"
    file_name = "ohshit.mips"
    file_type = "elf"
    first_seen = "2026-07-20 01:08:29"
  condition:
    hash.sha256(0, filesize) == "e7889354c0d2cce6cc0c6a34ec13afd79bf361388e76ed2b3b987e0613d9c6a6"
}

rule MalwareBazaar_Mirai_026_ce05cafc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce05cafc84ca9fa75f97cc1c857170870252ef286c4940189a3c8499ae00a148"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:45"
  condition:
    hash.sha256(0, filesize) == "ce05cafc84ca9fa75f97cc1c857170870252ef286c4940189a3c8499ae00a148"
}

rule MalwareBazaar_Mirai_027_8c689ba4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c689ba49385129e4f8df15b11f315f1b31f3fc3ee1a610a186d948490f5cd14"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:42"
  condition:
    hash.sha256(0, filesize) == "8c689ba49385129e4f8df15b11f315f1b31f3fc3ee1a610a186d948490f5cd14"
}

rule MalwareBazaar_Mirai_028_a373bfd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a373bfd15be694b9145c506e9356e54dad6c6fe18ec6c628145b6018ca3e70ee"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:38"
  condition:
    hash.sha256(0, filesize) == "a373bfd15be694b9145c506e9356e54dad6c6fe18ec6c628145b6018ca3e70ee"
}

rule MalwareBazaar_Mirai_029_acdc1b5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acdc1b5cfe4a154fd2c3de022622508a402d2d12927f26e67d5e77c3c92e267b"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:22"
  condition:
    hash.sha256(0, filesize) == "acdc1b5cfe4a154fd2c3de022622508a402d2d12927f26e67d5e77c3c92e267b"
}

rule MalwareBazaar_Mirai_030_6416561f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6416561faf40a608b2e9290e28bdcdc4e256a8e905afee3f450683ee588ec03a"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:14"
  condition:
    hash.sha256(0, filesize) == "6416561faf40a608b2e9290e28bdcdc4e256a8e905afee3f450683ee588ec03a"
}

rule MalwareBazaar_Mirai_031_0927ba3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0927ba3ed85ba9a8f3984e1e6d135e5db7f37316af7189d894d56dde90b986a4"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 01:04:02"
  condition:
    hash.sha256(0, filesize) == "0927ba3ed85ba9a8f3984e1e6d135e5db7f37316af7189d894d56dde90b986a4"
}

rule MalwareBazaar_Mirai_032_6fce1623
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fce1623d06754d0eca7e3e05542baef73a05f120217e407fc3a4b60b032bbc7"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:58"
  condition:
    hash.sha256(0, filesize) == "6fce1623d06754d0eca7e3e05542baef73a05f120217e407fc3a4b60b032bbc7"
}

rule MalwareBazaar_Mirai_033_485bbf2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "485bbf2e949d6c00b78fa3a69c346b5a587f9c416310f9496d838d9a0236a40f"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:55"
  condition:
    hash.sha256(0, filesize) == "485bbf2e949d6c00b78fa3a69c346b5a587f9c416310f9496d838d9a0236a40f"
}

rule MalwareBazaar_Mirai_034_bbfec9da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbfec9da453e630b7efde190a50687f3833ffe4725069ebecd42ca7cd06750bd"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:48"
  condition:
    hash.sha256(0, filesize) == "bbfec9da453e630b7efde190a50687f3833ffe4725069ebecd42ca7cd06750bd"
}

rule MalwareBazaar_Mirai_035_8e78c6d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e78c6d44d095554ab431b2d22a0fe6724f1b0312bbfc990f5f7339af72247a3"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:20"
  condition:
    hash.sha256(0, filesize) == "8e78c6d44d095554ab431b2d22a0fe6724f1b0312bbfc990f5f7339af72247a3"
}

rule MalwareBazaar_Mirai_036_a978a84f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a978a84fe498c755e481d161e22ed41087b93100a6b2648943c251208eeda3eb"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:19"
  condition:
    hash.sha256(0, filesize) == "a978a84fe498c755e481d161e22ed41087b93100a6b2648943c251208eeda3eb"
}

rule MalwareBazaar_Mirai_037_26af57f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26af57f0a8259e9d19a8239f6d681bb0d99e9c643ad21336e967477f66ccda89"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:18"
  condition:
    hash.sha256(0, filesize) == "26af57f0a8259e9d19a8239f6d681bb0d99e9c643ad21336e967477f66ccda89"
}

rule MalwareBazaar_Mirai_038_5d06e47b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d06e47b6a89d9069c501df5dda25f82d7cd21819ca10a6f16d562ed9053e3e8"
    family = "Mirai"
    file_name = "nz.sh"
    file_type = "sh"
    first_seen = "2026-07-20 01:03:16"
  condition:
    hash.sha256(0, filesize) == "5d06e47b6a89d9069c501df5dda25f82d7cd21819ca10a6f16d562ed9053e3e8"
}

rule MalwareBazaar_Mirai_039_01e10a0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01e10a0d58ddfef9d4f5c8f16f6397a8f3cde32759f0a2a9458aa4416a8fa8ce"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:15"
  condition:
    hash.sha256(0, filesize) == "01e10a0d58ddfef9d4f5c8f16f6397a8f3cde32759f0a2a9458aa4416a8fa8ce"
}

rule MalwareBazaar_Mirai_040_c683d44a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c683d44aec123273b706f948e25ac772f6275175479724a676fde168a7d42fa8"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:14"
  condition:
    hash.sha256(0, filesize) == "c683d44aec123273b706f948e25ac772f6275175479724a676fde168a7d42fa8"
}

rule MalwareBazaar_Mirai_041_ffd0d42d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffd0d42db56574e5cdcf9c1c898cd900ed7b71bf799f8212a6a08c235ac76d62"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:12"
  condition:
    hash.sha256(0, filesize) == "ffd0d42db56574e5cdcf9c1c898cd900ed7b71bf799f8212a6a08c235ac76d62"
}

rule MalwareBazaar_Mirai_042_9cccf931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cccf931d90f97b1380731af74213b539574e975c4e8b0c6a683aa0fc0e7183f"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:11"
  condition:
    hash.sha256(0, filesize) == "9cccf931d90f97b1380731af74213b539574e975c4e8b0c6a683aa0fc0e7183f"
}

rule MalwareBazaar_Mirai_043_197cc8cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "197cc8cb6a519636b797ba4ecb540e908486c581c99f653971bc6bb328041d17"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:10"
  condition:
    hash.sha256(0, filesize) == "197cc8cb6a519636b797ba4ecb540e908486c581c99f653971bc6bb328041d17"
}

rule MalwareBazaar_Mirai_044_2ca55a0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ca55a0c2308734109690550078dfe7281e40755fb203d077e3b68f3115f204d"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:08"
  condition:
    hash.sha256(0, filesize) == "2ca55a0c2308734109690550078dfe7281e40755fb203d077e3b68f3115f204d"
}

rule MalwareBazaar_Mirai_045_5f6cc846
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f6cc8466655754cb6753127743d2f07d5201f1d6c0e0eb1db12c5696e4d9773"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:07"
  condition:
    hash.sha256(0, filesize) == "5f6cc8466655754cb6753127743d2f07d5201f1d6c0e0eb1db12c5696e4d9773"
}

rule MalwareBazaar_Mirai_046_f6b00f2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6b00f2f991671e105a03c5eb80b810e14372dcba7cc33703d428c9a264c3711"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:05"
  condition:
    hash.sha256(0, filesize) == "f6b00f2f991671e105a03c5eb80b810e14372dcba7cc33703d428c9a264c3711"
}

rule MalwareBazaar_Mirai_047_566ee3df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "566ee3dfd8bee695f40e780f990946df38180dd286d3ef98123b310cc9fe80c2"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:04"
  condition:
    hash.sha256(0, filesize) == "566ee3dfd8bee695f40e780f990946df38180dd286d3ef98123b310cc9fe80c2"
}

rule MalwareBazaar_Mirai_048_f93fdc21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f93fdc21623eddd541ac3b5d92f83b31ea6ea3dd7b0359b09aaa1287ba58579f"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:03"
  condition:
    hash.sha256(0, filesize) == "f93fdc21623eddd541ac3b5d92f83b31ea6ea3dd7b0359b09aaa1287ba58579f"
}

rule MalwareBazaar_Mirai_049_ce23b01e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce23b01e50afa5dd35213b5cb7198e677e32adefbbf3ebd735e8a0a440d40bbf"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-20 01:03:01"
  condition:
    hash.sha256(0, filesize) == "ce23b01e50afa5dd35213b5cb7198e677e32adefbbf3ebd735e8a0a440d40bbf"
}

rule MalwareBazaar_Mirai_050_75f5413d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75f5413dcdf4c69f8b49ab6bec5c9a9948c768d5abbbbd0c093c971b39e4398e"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-20 00:58:51"
  condition:
    hash.sha256(0, filesize) == "75f5413dcdf4c69f8b49ab6bec5c9a9948c768d5abbbbd0c093c971b39e4398e"
}

rule MalwareBazaar_Mirai_051_c1c1046c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1c1046c507058c0ca6d14bb5369a84a45791d58475ce12fc6995451f0c5eb14"
    family = "Mirai"
    file_name = "ohshit.arc"
    file_type = "elf"
    first_seen = "2026-07-20 00:58:50"
  condition:
    hash.sha256(0, filesize) == "c1c1046c507058c0ca6d14bb5369a84a45791d58475ce12fc6995451f0c5eb14"
}

rule MalwareBazaar_Mirai_052_698a6555
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "698a65556d1937d391e85ddb0c2c4419e907214033dbf68401c92f635bb61c82"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 00:56:53"
  condition:
    hash.sha256(0, filesize) == "698a65556d1937d391e85ddb0c2c4419e907214033dbf68401c92f635bb61c82"
}

rule MalwareBazaar_unknown_053_4c2032f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c2032f518894d18f9463850cd1159d2e8664079f8d2526f0a9b1470cbf3488c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 00:52:08"
  condition:
    hash.sha256(0, filesize) == "4c2032f518894d18f9463850cd1159d2e8664079f8d2526f0a9b1470cbf3488c"
}

rule MalwareBazaar_Mirai_054_8fb4cfab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fb4cfabec6fa0b8f0e0d25135e87e88c13c3dce61c1335a89ee2e474a3d1570"
    family = "Mirai"
    file_name = "ohshit.x86"
    file_type = "elf"
    first_seen = "2026-07-20 00:50:59"
  condition:
    hash.sha256(0, filesize) == "8fb4cfabec6fa0b8f0e0d25135e87e88c13c3dce61c1335a89ee2e474a3d1570"
}

rule MalwareBazaar_unknown_055_e0e2e7ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0e2e7ce1b38f04d6e20e22cb25915bdc4e1cc90f08e7114243ceadffa9e4a59"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-20 00:47:01"
  condition:
    hash.sha256(0, filesize) == "e0e2e7ce1b38f04d6e20e22cb25915bdc4e1cc90f08e7114243ceadffa9e4a59"
}

rule MalwareBazaar_unknown_056_81962ba6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81962ba664cb7cd0865577bc257c1899bfa18df9f2d48482d3fb8b831058e60d"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-20 00:42:49"
  condition:
    hash.sha256(0, filesize) == "81962ba664cb7cd0865577bc257c1899bfa18df9f2d48482d3fb8b831058e60d"
}

rule MalwareBazaar_unknown_057_c442326b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c442326ba5603e08ebabb9960cab7567b49ae9d30fad73256d53870322015045"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-20 00:40:57"
  condition:
    hash.sha256(0, filesize) == "c442326ba5603e08ebabb9960cab7567b49ae9d30fad73256d53870322015045"
}

rule MalwareBazaar_Mirai_058_d8a8cea1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8a8cea14b12aa75047979f929bdf10b9003884580398c3c13d2b4fb04209410"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-07-20 00:36:55"
  condition:
    hash.sha256(0, filesize) == "d8a8cea14b12aa75047979f929bdf10b9003884580398c3c13d2b4fb04209410"
}

rule MalwareBazaar_unknown_059_310181cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310181ccdbc4129d5a8052af9101013df6e8e2871c6c42b6e86ef5a7f162caa3"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-20 00:34:52"
  condition:
    hash.sha256(0, filesize) == "310181ccdbc4129d5a8052af9101013df6e8e2871c6c42b6e86ef5a7f162caa3"
}

rule MalwareBazaar_Mirai_060_517164c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "517164c29c0e178b1bb4613d3d5ceb552329c9596791624d8277f2dc5ba37c50"
    family = "Mirai"
    file_name = "ohshit.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 00:34:51"
  condition:
    hash.sha256(0, filesize) == "517164c29c0e178b1bb4613d3d5ceb552329c9596791624d8277f2dc5ba37c50"
}

rule MalwareBazaar_Mirai_061_d1e7bb3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1e7bb3d3a56b3fa0810838df4885c5c3c794519502f3bc7ae335c9720099215"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-20 00:33:05"
  condition:
    hash.sha256(0, filesize) == "d1e7bb3d3a56b3fa0810838df4885c5c3c794519502f3bc7ae335c9720099215"
}

rule MalwareBazaar_Mirai_062_24d8adc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24d8adc83594c77c97fe59a84db8ffda1fbe13faefb495e2075b1feb80018bef"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-20 00:28:52"
  condition:
    hash.sha256(0, filesize) == "24d8adc83594c77c97fe59a84db8ffda1fbe13faefb495e2075b1feb80018bef"
}

rule MalwareBazaar_unknown_063_12d21b74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12d21b742c5e2a9e28bf0fc232a3b8d8963cf0c6c4278d4d551bda774495c3ae"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-20 00:27:03"
  condition:
    hash.sha256(0, filesize) == "12d21b742c5e2a9e28bf0fc232a3b8d8963cf0c6c4278d4d551bda774495c3ae"
}

rule MalwareBazaar_unknown_064_eef5c5fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eef5c5fa574616e79c45b3901e6d843172b8c7bebed1fd797c35f23155b7db9b"
    family = "unknown"
    file_name = "Dolphin 06_Q88 V6 (Oil and Chemical)_19Jul2026.exe"
    file_type = "exe"
    first_seen = "2026-07-20 00:24:40"
  condition:
    hash.sha256(0, filesize) == "eef5c5fa574616e79c45b3901e6d843172b8c7bebed1fd797c35f23155b7db9b"
}

rule MalwareBazaar_Mirai_065_ee44fb0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee44fb0df1cf9740c5779bc5a811e4d1c984365fd5e0482434f58fc1cc54d638"
    family = "Mirai"
    file_name = "ohshit.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 00:22:47"
  condition:
    hash.sha256(0, filesize) == "ee44fb0df1cf9740c5779bc5a811e4d1c984365fd5e0482434f58fc1cc54d638"
}

rule MalwareBazaar_Mirai_066_13f6c8dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13f6c8dcecb6677e77680f2b75d82b17fcee135cc00b474bcff5d9c64a06e9bb"
    family = "Mirai"
    file_name = "ohshit.m68k"
    file_type = "elf"
    first_seen = "2026-07-20 00:14:44"
  condition:
    hash.sha256(0, filesize) == "13f6c8dcecb6677e77680f2b75d82b17fcee135cc00b474bcff5d9c64a06e9bb"
}

rule MalwareBazaar_Mirai_067_f9191fbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9191fbfcd25b4d0274e7831ae190d888c42be4e3794c4bb3dea7517b704fdee"
    family = "Mirai"
    file_name = "ohshit.sh4"
    file_type = "elf"
    first_seen = "2026-07-20 00:12:46"
  condition:
    hash.sha256(0, filesize) == "f9191fbfcd25b4d0274e7831ae190d888c42be4e3794c4bb3dea7517b704fdee"
}

rule MalwareBazaar_unknown_068_3ee8b4e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ee8b4e38efa5f872f5f1f4fac720d80eb7c079fc538ef75f2d8a8dc7068ef9f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-20 00:12:45"
  condition:
    hash.sha256(0, filesize) == "3ee8b4e38efa5f872f5f1f4fac720d80eb7c079fc538ef75f2d8a8dc7068ef9f"
}

rule MalwareBazaar_unknown_069_276fdef7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "276fdef74ff71efaeb345c04a3ecfbeb2e99ad97584f4eba24e9936f0de6bd60"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-20 00:12:43"
  condition:
    hash.sha256(0, filesize) == "276fdef74ff71efaeb345c04a3ecfbeb2e99ad97584f4eba24e9936f0de6bd60"
}

rule MalwareBazaar_Mirai_070_5e3c607c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e3c607ce72d51263e201321cc76e30c8c027feeab35a10d1f1ca70f60f1e671"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-20 00:10:50"
  condition:
    hash.sha256(0, filesize) == "5e3c607ce72d51263e201321cc76e30c8c027feeab35a10d1f1ca70f60f1e671"
}

rule MalwareBazaar_Mirai_071_310c6c65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310c6c65766a41fda319acbc604fd200741c31d6151341e49e3d84f076860005"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-20 00:09:02"
  condition:
    hash.sha256(0, filesize) == "310c6c65766a41fda319acbc604fd200741c31d6151341e49e3d84f076860005"
}

rule MalwareBazaar_unknown_072_6dfd5350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dfd535055df7f3f0658ff58e3a625f38ef4c0bfc13f0279181db7adf37f688b"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-20 00:07:03"
  condition:
    hash.sha256(0, filesize) == "6dfd535055df7f3f0658ff58e3a625f38ef4c0bfc13f0279181db7adf37f688b"
}

rule MalwareBazaar_unknown_073_ccc0ba10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccc0ba109fd1e38f414e9354d5afaf1f32cbef61118517fac5c36b0d3d93a743"
    family = "unknown"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-07-20 00:07:02"
  condition:
    hash.sha256(0, filesize) == "ccc0ba109fd1e38f414e9354d5afaf1f32cbef61118517fac5c36b0d3d93a743"
}

rule MalwareBazaar_Mirai_074_45f07208
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45f072085e50c50ac363bf8a88cd4b362df1230758123e04703c431818b86034"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-20 00:03:42"
  condition:
    hash.sha256(0, filesize) == "45f072085e50c50ac363bf8a88cd4b362df1230758123e04703c431818b86034"
}

rule MalwareBazaar_Mirai_075_19fdce24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19fdce2472485db5fc8d8820cda7c798212d01a830f76d22e6e1612f38dde37c"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-20 00:03:00"
  condition:
    hash.sha256(0, filesize) == "19fdce2472485db5fc8d8820cda7c798212d01a830f76d22e6e1612f38dde37c"
}

rule MalwareBazaar_Mirai_076_c533aeec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c533aeec0e53aca326d421c3d1483e742c8476e4e17125ac6267de6bc8df2dcc"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-07-19 23:58:44"
  condition:
    hash.sha256(0, filesize) == "c533aeec0e53aca326d421c3d1483e742c8476e4e17125ac6267de6bc8df2dcc"
}

rule MalwareBazaar_Mirai_077_71458c54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71458c54a327762a69035b4076ab75dc325572294d2c06994b7a23dca1523f3e"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-19 23:57:31"
  condition:
    hash.sha256(0, filesize) == "71458c54a327762a69035b4076ab75dc325572294d2c06994b7a23dca1523f3e"
}

rule MalwareBazaar_Mirai_078_0a39e484
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a39e484b65980b577ad59bc3e5a634c900784ea54b8b6e2ff1200e9a5957511"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-19 23:56:47"
  condition:
    hash.sha256(0, filesize) == "0a39e484b65980b577ad59bc3e5a634c900784ea54b8b6e2ff1200e9a5957511"
}

rule MalwareBazaar_Mirai_079_dd67a211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd67a211107f82378b1a0fe465f66f06a5b3e035ae8ff64fd8d9607d343f3fa9"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-19 23:54:45"
  condition:
    hash.sha256(0, filesize) == "dd67a211107f82378b1a0fe465f66f06a5b3e035ae8ff64fd8d9607d343f3fa9"
}

rule MalwareBazaar_unknown_080_cee1fd2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cee1fd2f7f8b07acf1e012412219e2c1624b600a5716d885dba24c10453d26c7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 23:52:08"
  condition:
    hash.sha256(0, filesize) == "cee1fd2f7f8b07acf1e012412219e2c1624b600a5716d885dba24c10453d26c7"
}

rule MalwareBazaar_Amadey_081_a86c023a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a86c023a02f1454738b39f753f50777c238b4ea296ffc76cd41c3059f216be10"
    family = "Amadey"
    file_name = "a86c023a02f1454738b39f753f50777c238b4ea296ffc.exe"
    file_type = "exe"
    first_seen = "2026-07-19 23:50:12"
  condition:
    hash.sha256(0, filesize) == "a86c023a02f1454738b39f753f50777c238b4ea296ffc76cd41c3059f216be10"
}

rule MalwareBazaar_Amadey_082_e8514970
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e85149704da6ee8f9bc1c55304c560d1a792180489d4859a64cf0a4e056ccf52"
    family = "Amadey"
    file_name = "F8E68CDDF13A94D821A4B265172A0E32.exe"
    file_type = "exe"
    first_seen = "2026-07-19 23:45:09"
  condition:
    hash.sha256(0, filesize) == "e85149704da6ee8f9bc1c55304c560d1a792180489d4859a64cf0a4e056ccf52"
}

rule MalwareBazaar_ValleyRAT_083_e6f4c46f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6f4c46f2a72a4d8b1eda2c2c431c64d73eae7057221b35a6fc16138e4dc4d43"
    family = "ValleyRAT"
    file_name = "DingTalkD_Setup2026.exe"
    file_type = "exe"
    first_seen = "2026-07-19 23:10:26"
  condition:
    hash.sha256(0, filesize) == "e6f4c46f2a72a4d8b1eda2c2c431c64d73eae7057221b35a6fc16138e4dc4d43"
}

rule MalwareBazaar_RemusStealer_084_2c292ea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c292ea5d66b3aa9b531e60f55d6af341d101961a649614d022111ff743492f3"
    family = "RemusStealer"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-07-19 22:52:07"
  condition:
    hash.sha256(0, filesize) == "2c292ea5d66b3aa9b531e60f55d6af341d101961a649614d022111ff743492f3"
}

rule MalwareBazaar_Mirai_085_70005bbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70005bbb6db8afaf30661df0311395fb3cf7bf1ece51d511841d4f4def908a29"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-19 22:40:53"
  condition:
    hash.sha256(0, filesize) == "70005bbb6db8afaf30661df0311395fb3cf7bf1ece51d511841d4f4def908a29"
}

rule MalwareBazaar_Mirai_086_f0ea2d00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0ea2d0017a88323d730042c2b571a4d06cd8dbe169c3cef2e457bd0c5d676ff"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-19 22:40:40"
  condition:
    hash.sha256(0, filesize) == "f0ea2d0017a88323d730042c2b571a4d06cd8dbe169c3cef2e457bd0c5d676ff"
}

rule MalwareBazaar_Mirai_087_42804458
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4280445841f4898c26f409239f1a623304b637363087bd88a6ee9506e0256463"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Bot.20354.26072"
    file_type = "elf"
    first_seen = "2026-07-19 22:26:25"
  condition:
    hash.sha256(0, filesize) == "4280445841f4898c26f409239f1a623304b637363087bd88a6ee9506e0256463"
}

rule MalwareBazaar_unknown_088_a832528b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a832528ba9cac310fd4e5bcb7f8523865a6a19b2c95891515f323009910f610e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.Bot.14621.11299"
    file_type = "elf"
    first_seen = "2026-07-19 22:26:24"
  condition:
    hash.sha256(0, filesize) == "a832528ba9cac310fd4e5bcb7f8523865a6a19b2c95891515f323009910f610e"
}

rule MalwareBazaar_unknown_089_2d0ae80f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d0ae80f9689433e7b84ee280e11ce5263f918f6f23288c3d9bfe6ea187408b2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-19 22:10:42"
  condition:
    hash.sha256(0, filesize) == "2d0ae80f9689433e7b84ee280e11ce5263f918f6f23288c3d9bfe6ea187408b2"
}

rule MalwareBazaar_Phorpiex_090_2ac492ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ac492ce3b66a7979ceba5f26c594f0a69698d19b2ffdb56ac8b741dc30f8e5e"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-19 22:10:11"
  condition:
    hash.sha256(0, filesize) == "2ac492ce3b66a7979ceba5f26c594f0a69698d19b2ffdb56ac8b741dc30f8e5e"
}

rule MalwareBazaar_unknown_091_b0f43bcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0f43bcb2af128106bda1ac0495f70028d364056e4a9521e4e06f1b83769e022"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-19 22:03:24"
  condition:
    hash.sha256(0, filesize) == "b0f43bcb2af128106bda1ac0495f70028d364056e4a9521e4e06f1b83769e022"
}

rule MalwareBazaar_Mirai_092_932e3c4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "932e3c4ae1d5404ceade8dfd386182800b91eb93794c914b7f09b094996b061e"
    family = "Mirai"
    file_name = "tmpsl"
    file_type = "elf"
    first_seen = "2026-07-19 22:02:49"
  condition:
    hash.sha256(0, filesize) == "932e3c4ae1d5404ceade8dfd386182800b91eb93794c914b7f09b094996b061e"
}

rule MalwareBazaar_unknown_093_726ca857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "726ca85760e035489a885da5b01dbe62c7a1e0b52e1735b656adbc899090a572"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-19 22:00:43"
  condition:
    hash.sha256(0, filesize) == "726ca85760e035489a885da5b01dbe62c7a1e0b52e1735b656adbc899090a572"
}

rule MalwareBazaar_Mirai_094_c7e7d776
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7e7d77602c121ebe2785d8e4068b7d459abe975ad9e3e8471ba28e9783b8dca"
    family = "Mirai"
    file_name = "ohshit.i686"
    file_type = "elf"
    first_seen = "2026-07-19 22:00:41"
  condition:
    hash.sha256(0, filesize) == "c7e7d77602c121ebe2785d8e4068b7d459abe975ad9e3e8471ba28e9783b8dca"
}

rule MalwareBazaar_ValleyRAT_095_40c98ff9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40c98ff9673f67cfa82d9e2e16a2e55644f71fec87e2d92f25821a2b917f8145"
    family = "ValleyRAT"
    file_name = "9C986D7E311CE1E8DB7BD65B8271A87D.exe"
    file_type = "exe"
    first_seen = "2026-07-19 22:00:16"
  condition:
    hash.sha256(0, filesize) == "40c98ff9673f67cfa82d9e2e16a2e55644f71fec87e2d92f25821a2b917f8145"
}

rule MalwareBazaar_Mirai_096_5a99dfdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a99dfdf7905c92ed743dd1d5fdec044ad2fcb2ecee6d088a7349f7a719d552b"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-07-19 21:56:42"
  condition:
    hash.sha256(0, filesize) == "5a99dfdf7905c92ed743dd1d5fdec044ad2fcb2ecee6d088a7349f7a719d552b"
}

rule MalwareBazaar_RemusStealer_097_5f85e22a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f85e22acb86ebc9031256efb11af9f1eed58621312a0c0bf448fe699e809c92"
    family = "RemusStealer"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-19 21:52:17"
  condition:
    hash.sha256(0, filesize) == "5f85e22acb86ebc9031256efb11af9f1eed58621312a0c0bf448fe699e809c92"
}

rule MalwareBazaar_unknown_098_36e8a488
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36e8a488df3ed19cc2f393271814f04569bd1f63fd32349ad13c533f6421e9ce"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 21:52:09"
  condition:
    hash.sha256(0, filesize) == "36e8a488df3ed19cc2f393271814f04569bd1f63fd32349ad13c533f6421e9ce"
}

rule MalwareBazaar_RedLineStealer_099_b59653f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0"
    family = "RedLineStealer"
    file_name = "8C21B2FBDED2FAEB6DB2E7A20C513CDB.exe"
    file_type = "exe"
    first_seen = "2026-07-19 21:50:05"
  condition:
    hash.sha256(0, filesize) == "b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0"
}

rule MalwareBazaar_Mirai_100_50fa6770
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50fa67706d725e7a22247a361c6d6907eab4633c20c471705cae8b10228627f0"
    family = "Mirai"
    file_name = "tarm6"
    file_type = "elf"
    first_seen = "2026-07-19 21:46:41"
  condition:
    hash.sha256(0, filesize) == "50fa67706d725e7a22247a361c6d6907eab4633c20c471705cae8b10228627f0"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-19

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 667 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 667 |
| Unique family labels | 15 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 37 |
| Mirai | 37 |
| AMOS | 8 |
| SalatStealer | 2 |
| RemcosRAT | 2 |
| Formbook | 2 |
| VShell | 2 |
| ValleyRAT | 2 |
| Snowlight | 2 |
| Phorpiex | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 49 |
| exe | 27 |
| macho | 11 |
| vbs | 3 |
| zip | 3 |
| sh | 2 |
| zsh | 2 |
| bat | 1 |
| msi | 1 |
| js | 1 |

## Per-Sample Analysis

### Sample 1: `2a5308255e8cfbe7`

| Field | Value |
|---|---|
| SHA-256 | `2a5308255e8cfbe7fe2941a832e8ef637ca25114057ab08be65d8539f489069f` |
| Family label | `unknown` |
| File name | `New PO SGN260918167.vbs` |
| File type | `vbs` |
| First seen | `2026-10-19 04:44:34` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fe0609eaecbebca7181a12f586c3694` |
| SHA-1 | `a6be1374f671fe6a11798c85dbe3a981b6e05038` |
| SHA-256 | `2a5308255e8cfbe7fe2941a832e8ef637ca25114057ab08be65d8539f489069f` |
| SHA3-384 | `c6b662f82767f837d4c7a9a78b1b9fc703c2402f6fc54525c73f0bb8004d5a74b54ed05507804d4065d7d6694937b7bf` |
| TLSH | `T108749DE15F842A019F25EB97CEA8897A53C02F32A2D06C70DDD609DC3128F59A1DFBD5` |
| SSDEEP | `1536:KuXFslKfYanWwOU7i/+UY0AGYvj80xQcpEUJFjXhpm9Bv:t1sl+oF+U9AGy8xQJFhQL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_2a530825
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a5308255e8cfbe7fe2941a832e8ef637ca25114057ab08be65d8539f489069f"
    family = "unknown"
    file_name = "New PO SGN260918167.vbs"
    file_type = "vbs"
    first_seen = "2026-10-19 04:44:34"
  condition:
    hash.sha256(0, filesize) == "2a5308255e8cfbe7fe2941a832e8ef637ca25114057ab08be65d8539f489069f"
}
```

### Sample 2: `e9c0c38dc0128214`

| Field | Value |
|---|---|
| SHA-256 | `e9c0c38dc0128214ac58ded574ab2628c4fa1cd7c2101552b34b72641ac3583e` |
| Family label | `unknown` |
| File name | `mbupload-vtc0u44o.bin` |
| File type | `exe` |
| First seen | `2026-10-19 04:44:22` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `adc56caf0a4f563b16c134cfd5f3b3d4` |
| SHA-1 | `ebcf5e9dc403d2c7bf5f16078078ca3845d3eca1` |
| SHA-256 | `e9c0c38dc0128214ac58ded574ab2628c4fa1cd7c2101552b34b72641ac3583e` |
| SHA3-384 | `22a68efa9bf5a7f72fa9ab9ba7012c03104260982d1106f49bedc639bb74cdc299404104db42ed13feb0128d9700a44a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T169C66C11FACB54F5E9035831506BB27F23315D048B28CBDBEB183B6AF87B6A1197A705` |
| SSDEEP | `98304:pcnIiZ6JHtwUXioDuvleDwVCw9Tz4fG2IfSEpY:m68UBD2dVCwTzx3pY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_e9c0c38d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9c0c38dc0128214ac58ded574ab2628c4fa1cd7c2101552b34b72641ac3583e"
    family = "unknown"
    file_name = "mbupload-vtc0u44o.bin"
    file_type = "exe"
    first_seen = "2026-10-19 04:44:22"
  condition:
    hash.sha256(0, filesize) == "e9c0c38dc0128214ac58ded574ab2628c4fa1cd7c2101552b34b72641ac3583e"
}
```

### Sample 3: `9e6dd02b923469c4`

| Field | Value |
|---|---|
| SHA-256 | `9e6dd02b923469c4f9a022f52d7fba9849b63fc1f66f20173e514401af8f3f64` |
| Family label | `SalatStealer` |
| File name | `mbupload-vtc0u44o.bin` |
| File type | `exe` |
| First seen | `2026-10-19 04:43:37` |
| Reporter | `wristhulk` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0839234f56e8ebaa533b9ff10b59a4ce` |
| SHA-1 | `e0e88ceb779b6e9f444c8c01689b0f5b80f46ce5` |
| SHA-256 | `9e6dd02b923469c4f9a022f52d7fba9849b63fc1f66f20173e514401af8f3f64` |
| SHA3-384 | `3f7180a246a431e75ce5311eb1d129157fc86886cc4feacfeb682a9e3c5bec711cf7802b178b1d23477dec58081949ed` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C3F53314E6C5FDE3E228E33887ACC048359FB565414CA9EA7C8FE888AD725BC56D1D24` |
| SSDEEP | `98304:XNfl3h+ud3qyrGS55+UQHAXV4Yg6bxfjnyGhJ9I:XRl3hbd33GY5+U75FlyiJ9I` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_003_9e6dd02b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e6dd02b923469c4f9a022f52d7fba9849b63fc1f66f20173e514401af8f3f64"
    family = "SalatStealer"
    file_name = "mbupload-vtc0u44o.bin"
    file_type = "exe"
    first_seen = "2026-10-19 04:43:37"
  condition:
    hash.sha256(0, filesize) == "9e6dd02b923469c4f9a022f52d7fba9849b63fc1f66f20173e514401af8f3f64"
}
```

### Sample 4: `613c0de40c32f534`

| Field | Value |
|---|---|
| SHA-256 | `613c0de40c32f5347f49ccf4c61c9998d4b1dc4ebda699d282121b7dc48f44c7` |
| Family label | `unknown` |
| File name | `PO-SINCO-AUTOMATIOM-86757786-Ref-6777.vbs` |
| File type | `vbs` |
| First seen | `2026-10-19 04:42:44` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56b1c383743ecec77a1d8e085d3d1056` |
| SHA-1 | `d9ec0e55a736f7dedb5bbf9f7e00fe663f50bf3a` |
| SHA-256 | `613c0de40c32f5347f49ccf4c61c9998d4b1dc4ebda699d282121b7dc48f44c7` |
| SHA3-384 | `e6ccad16f28e4002ddf7423fdcdb9363fa6a80796893f3e3efdc11973d707feaf23b0d54ede8fcdfa3b6a7e63d66ea78` |
| TLSH | `T186749DE15F852A019F21EB97CEAC897E53C02F32A2D06C70DDD649DC2028E59A1DFBD5` |
| SSDEEP | `1536:0TEI5OGsQwYanWwOU7i/+Uigmjy0IzpUxiAYXhpo:0QYVsBoF+UVsylGr0hK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_613c0de4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "613c0de40c32f5347f49ccf4c61c9998d4b1dc4ebda699d282121b7dc48f44c7"
    family = "unknown"
    file_name = "PO-SINCO-AUTOMATIOM-86757786-Ref-6777.vbs"
    file_type = "vbs"
    first_seen = "2026-10-19 04:42:44"
  condition:
    hash.sha256(0, filesize) == "613c0de40c32f5347f49ccf4c61c9998d4b1dc4ebda699d282121b7dc48f44c7"
}
```

### Sample 5: `32a8e16900374395`

| Field | Value |
|---|---|
| SHA-256 | `32a8e169003743952a8405d3bb9799142af3edc216ae3c8b246561b0d0644cbc` |
| Family label | `Mirai` |
| File name | `boatnet.x86` |
| File type | `elf` |
| First seen | `2026-10-19 04:42:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cdd6ee8ffc588322e996070c3213308` |
| SHA-1 | `f0fc3e8b05f068c78d2b100981e4bbc74df91690` |
| SHA-256 | `32a8e169003743952a8405d3bb9799142af3edc216ae3c8b246561b0d0644cbc` |
| SHA3-384 | `1c2b4cf86eeff7586467f7d026f9cf01127e67b752e22cfa7278dc46e9c231aa2bd0b3853efcbdcd87c5d567585028a5` |
| TLSH | `T11C2309C8F443D9F9DC5A09742036FB27DBB2F6BA2329DE43D7A49523AC51702A805D9C` |
| TELFHASH | `t1a811c8f75da609fdf3d09c00c71d67e1296ad26b0a7166a404b12de533d1cd190b8c3e` |
| SSDEEP | `1536:6nJRT4QPfZfW5XTOeY3Dve3AGAZq/4Qw7bn2iSe:Gv4QPfZfW5XTOeoEz0qAQwf2i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_32a8e169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32a8e169003743952a8405d3bb9799142af3edc216ae3c8b246561b0d0644cbc"
    family = "Mirai"
    file_name = "boatnet.x86"
    file_type = "elf"
    first_seen = "2026-10-19 04:42:26"
  condition:
    hash.sha256(0, filesize) == "32a8e169003743952a8405d3bb9799142af3edc216ae3c8b246561b0d0644cbc"
}
```

### Sample 6: `1f15fc801140d41f`

| Field | Value |
|---|---|
| SHA-256 | `1f15fc801140d41f3f0eaccf9aa115da51c693f1265ba00fbf35bf31269a739f` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-10-19 04:42:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2aab7f5c4d0d2151d07467922068450f` |
| SHA-1 | `5434e6edc49ce7ce94b88fe286d07f3557d8aa5b` |
| SHA-256 | `1f15fc801140d41f3f0eaccf9aa115da51c693f1265ba00fbf35bf31269a739f` |
| SHA3-384 | `46776db66ef6abb5468794e1e9a10bd22fcdb1c16170999a35f8a5431df58898e6520f818d74fbc1696695617402d036` |
| TLSH | `T120334B42322C0F17C0A35974252F5BE487FFFAD122E4F685251F8B668A78E371489E9D` |
| SSDEEP | `768:3SjbGSLlRrYj0a8C/dQOhPC/+I20Ja6ZZ+GwPS4yns96BktDgIPi8TwB:ivW3jdQGqt7Y+Z+zN9cGgI6bB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_1f15fc80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f15fc801140d41f3f0eaccf9aa115da51c693f1265ba00fbf35bf31269a739f"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-10-19 04:42:23"
  condition:
    hash.sha256(0, filesize) == "1f15fc801140d41f3f0eaccf9aa115da51c693f1265ba00fbf35bf31269a739f"
}
```

### Sample 7: `bf7562c880967fc2`

| Field | Value |
|---|---|
| SHA-256 | `bf7562c880967fc2afca8669b0ef1cdfa8c273d5338300c455418c0c234d23a4` |
| Family label | `Mirai` |
| File name | `boatnet.arm7` |
| File type | `elf` |
| First seen | `2026-10-19 04:42:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c48b6352f91b0bde37d6238de7a9ccf` |
| SHA-1 | `fdaec816d367428f4f24179ef5916ce06765b1ee` |
| SHA-256 | `bf7562c880967fc2afca8669b0ef1cdfa8c273d5338300c455418c0c234d23a4` |
| SHA3-384 | `c5c1cdb487fce0f1f201ee98c27dcf50a2ea05f07a4d3c9416f9527dbb25b4a86852718db1549c41a72a59b717be9d5c` |
| TLSH | `T1F0C35B42FA418F13C0D61779B6EF42493322A79593DB73069A249FB43F8679F0E63A05` |
| TELFHASH | `t17a211db1573a96295955de9c8aec6775062cd3062282ef33ff3184ac640004eea2ac0f` |
| SSDEEP | `3072:cowpuQyNSG2eRa1styK9flTQPHoorScVM/9OAvjik:cowpuQyNSG24a1styKdlTuIorSmM/9nd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_bf7562c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf7562c880967fc2afca8669b0ef1cdfa8c273d5338300c455418c0c234d23a4"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-10-19 04:42:19"
  condition:
    hash.sha256(0, filesize) == "bf7562c880967fc2afca8669b0ef1cdfa8c273d5338300c455418c0c234d23a4"
}
```

### Sample 8: `62dd4a817a173e16`

| Field | Value |
|---|---|
| SHA-256 | `62dd4a817a173e1687ac9ae1f43a3fe7af05b65314127043d141e134ffeb3434` |
| Family label | `Mirai` |
| File name | `boatnet.x86` |
| File type | `elf` |
| First seen | `2026-10-19 04:41:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1326aa8a101444e28c5d4a9889e14732` |
| SHA-1 | `725fe857b7f01aa64bf16d9378337b2f7e9df8dd` |
| SHA-256 | `62dd4a817a173e1687ac9ae1f43a3fe7af05b65314127043d141e134ffeb3434` |
| SHA3-384 | `fcd76880eab591e990fe13308147a2805002e8597878197580681543eeeb7c54127764e5246e664d26ba283fb3ef4e93` |
| TLSH | `T1B2A2E015BF1886CBC832693451E9EAD21297FC71F2DDCC092540C16FF4A33A96474F86` |
| SSDEEP | `384:Mg9Lpj8s/qPui8uZxoIA57RWQjJiEVi+ZkXaqOKV14b+502F2vwA9dWuMW21bAKl:798o08kxofBE+ZkXaqGbp2F2TWul0c5A` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_62dd4a81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62dd4a817a173e1687ac9ae1f43a3fe7af05b65314127043d141e134ffeb3434"
    family = "Mirai"
    file_name = "boatnet.x86"
    file_type = "elf"
    first_seen = "2026-10-19 04:41:55"
  condition:
    hash.sha256(0, filesize) == "62dd4a817a173e1687ac9ae1f43a3fe7af05b65314127043d141e134ffeb3434"
}
```

### Sample 9: `e749be812bb42a78`

| Field | Value |
|---|---|
| SHA-256 | `e749be812bb42a783b3d5e18d7b9c17abea3677ec8905b9bee14ded50b745fa6` |
| Family label | `Mirai` |
| File name | `boatnet.spc` |
| File type | `elf` |
| First seen | `2026-10-19 04:41:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a2b2e4770a87bff6777b3ac8313c61f` |
| SHA-1 | `e6322067963a94575913576c69e74d42dd665365` |
| SHA-256 | `e749be812bb42a783b3d5e18d7b9c17abea3677ec8905b9bee14ded50b745fa6` |
| SHA3-384 | `e9330b880ce8c4a5f546d5eaee0f8966f7143e33d410a355e20a972461f46cac1990fe08b862a071da7d889ddd5e8013` |
| TLSH | `T154432921B63A1F13D0E0A47D21FB4B59B1A15ADE26A4C64E7D720F4FFF11680A943DB8` |
| SSDEEP | `768:RqowmZPu9wtnfbltWgC6BSJsBcfDSTFIuQKqgESnmC/xO+KpAwq:RqtmZPuutfbltZFBSJsBcfDSTFI+BEq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_e749be81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e749be812bb42a783b3d5e18d7b9c17abea3677ec8905b9bee14ded50b745fa6"
    family = "Mirai"
    file_name = "boatnet.spc"
    file_type = "elf"
    first_seen = "2026-10-19 04:41:53"
  condition:
    hash.sha256(0, filesize) == "e749be812bb42a783b3d5e18d7b9c17abea3677ec8905b9bee14ded50b745fa6"
}
```

### Sample 10: `08250a73e7e7386e`

| Field | Value |
|---|---|
| SHA-256 | `08250a73e7e7386e4543cc30e819c0eab7e7a438d1ee77f81613314d40d178bc` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-10-19 04:41:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a88ed56548ab5de30ac74bf884f491f` |
| SHA-1 | `3da97db13a319692dabcdb7137b50529799a44c0` |
| SHA-256 | `08250a73e7e7386e4543cc30e819c0eab7e7a438d1ee77f81613314d40d178bc` |
| SHA3-384 | `cb6d328926f6a52ce0b8476cd301f4bebdd82f30b3d3668aeb223c1c2c9c3426cef47969248706e0eae06a8d9407596c` |
| TLSH | `T1ECA2D025E345AEF4DFEF9D9052C1C2C27AF587C72786C8E340EEAF016506056B789C59` |
| SSDEEP | `384:m/JywWc84Tp2YshxqlDeAkSqjGJLeCE5zRW6C5xM4uVcqgw05VxJp:mRxsSVsMD6xiJJE5zRWNE4uVcqgw09T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_08250a73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08250a73e7e7386e4543cc30e819c0eab7e7a438d1ee77f81613314d40d178bc"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-10-19 04:41:51"
  condition:
    hash.sha256(0, filesize) == "08250a73e7e7386e4543cc30e819c0eab7e7a438d1ee77f81613314d40d178bc"
}
```

### Sample 11: `42480c00b3f4874c`

| Field | Value |
|---|---|
| SHA-256 | `42480c00b3f4874c08265fda54e54bf6a609c8358b91c7b78c8064f839fe6cf3` |
| Family label | `Mirai` |
| File name | `boatnet.arm7` |
| File type | `elf` |
| First seen | `2026-10-19 04:41:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `315ebaa0bc0251b1b9be65cf7e4ce3e0` |
| SHA-1 | `1422cedaaa912c18dee48df92bc73457f163a2ec` |
| SHA-256 | `42480c00b3f4874c08265fda54e54bf6a609c8358b91c7b78c8064f839fe6cf3` |
| SHA3-384 | `1800ca6e46cc37c730a8194d58972f651faf8fd23141119752c09aa3787ee21b74f00b912fd19f0694ad98f2603e42f4` |
| TLSH | `T127230231850E9DF165303C72DAD5D79379E12AB2C667301396290B3C6F68B231E57F4A` |
| SSDEEP | `768:D/TYCoIxdEk+AxoTZAZHFeq8b309q3UELbUXfi6nVMQHI4vcGpvd:DECFd+A6YHAxdLRQZd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_42480c00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42480c00b3f4874c08265fda54e54bf6a609c8358b91c7b78c8064f839fe6cf3"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-10-19 04:41:49"
  condition:
    hash.sha256(0, filesize) == "42480c00b3f4874c08265fda54e54bf6a609c8358b91c7b78c8064f839fe6cf3"
}
```

### Sample 12: `5f4838a39b064a01`

| Field | Value |
|---|---|
| SHA-256 | `5f4838a39b064a0165cc673526d2d7a0be456d259b1f392964ed4dd2084a194d` |
| Family label | `RemcosRAT` |
| File name | `20261019 UTS.bat` |
| File type | `bat` |
| First seen | `2026-10-19 04:40:08` |
| Reporter | `abuse_ch` |
| Tags | `bat, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1d2de294f50cefa7bef8e66b970eb72` |
| SHA-1 | `851c682a8899af90ccbce32e85b6248b6d26d2c9` |
| SHA-256 | `5f4838a39b064a0165cc673526d2d7a0be456d259b1f392964ed4dd2084a194d` |
| SHA3-384 | `6d9e554eb0a6a7822c14fc17a897202a254f69151e673ff102a86eb66a864cfa40d19026301446e5592a60c18720e388` |
| TLSH | `T12EF1A67457317746DE873760898EA44772BA323E27C84C4973BDFE49BE6281D21E8C98` |
| SSDEEP | `192:3JvNlt2zJsDbrcDFDtl3H80+c2gyBMaAKwUNNiSu1R3Ub+:ZvN7boF3HYUm+ujiSuD3K+` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_012_5f4838a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f4838a39b064a0165cc673526d2d7a0be456d259b1f392964ed4dd2084a194d"
    family = "RemcosRAT"
    file_name = "20261019 UTS.bat"
    file_type = "bat"
    first_seen = "2026-10-19 04:40:08"
  condition:
    hash.sha256(0, filesize) == "5f4838a39b064a0165cc673526d2d7a0be456d259b1f392964ed4dd2084a194d"
}
```

### Sample 13: `dc50ab477a38a56c`

| Field | Value |
|---|---|
| SHA-256 | `dc50ab477a38a56cfcce2c3a630f309b4d39c555882845702ba5eb389fa53f8b` |
| Family label | `Formbook` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-19 04:30:27` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remcos, exe, Formbook, RemoteHost` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `930dcdaff1c9d762e2c99e428de68d13` |
| SHA-1 | `17ccd04387ffad7296a7fca6015dd7ef4fad6224` |
| SHA-256 | `dc50ab477a38a56cfcce2c3a630f309b4d39c555882845702ba5eb389fa53f8b` |
| SHA3-384 | `4a998c905ff1e1c8c4dfbdef765d3405a48207bf9ebade938d9b5dbbc1fab5a40335cd64035885633295eeeed82b71af` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17C359C9032781F52F1BA87F81927E63087B53A9E752EE31C4DC678CF3A75B411A11A27` |
| SSDEEP | `12288:Fe45JEi1K4U2XHVdSkujcUcBw1zzltfyiJTdjWrgzVdAcY5JP5hOtkL5P+SVXOQ1:JTEi1ssAjIBwNugLxYP5hOkN+pLon` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_013_dc50ab47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc50ab477a38a56cfcce2c3a630f309b4d39c555882845702ba5eb389fa53f8b"
    family = "Formbook"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-19 04:30:27"
  condition:
    hash.sha256(0, filesize) == "dc50ab477a38a56cfcce2c3a630f309b4d39c555882845702ba5eb389fa53f8b"
}
```

### Sample 14: `aed64d1a94fe8182`

| Field | Value |
|---|---|
| SHA-256 | `aed64d1a94fe8182f45f84a8f7ba420b90b076c34c448e141d11be350bb728bf` |
| Family label | `Formbook` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-19 04:30:20` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remcos, exe, Formbook, RemoteHost` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e29d71ef45870b3ca2b9954ad6c8c22` |
| SHA-1 | `f1625c5ba05a8041ddd3a762d51e29b2fb872e16` |
| SHA-256 | `aed64d1a94fe8182f45f84a8f7ba420b90b076c34c448e141d11be350bb728bf` |
| SHA3-384 | `391eed45344d311598192af1ad06d6694ec9988f27d861bb753d40ebe89e1ee7a1bc82f83400c91ad52d0f88b0c7849a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T10A359D9032785F22F1B987F41926E5308BF93A5E752ED32D4DC278CF3A75B815A01A27` |
| SSDEEP | `12288:Qe45mR42JXHo5uart7dVZzXNfN2LElp6Bkd74zlTkaE1zke7m+fc13q2K7YoKqkO:2yJe57dV/7fgS7vaERm+aa2KMPPvm` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_014_aed64d1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aed64d1a94fe8182f45f84a8f7ba420b90b076c34c448e141d11be350bb728bf"
    family = "Formbook"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-19 04:30:20"
  condition:
    hash.sha256(0, filesize) == "aed64d1a94fe8182f45f84a8f7ba420b90b076c34c448e141d11be350bb728bf"
}
```

### Sample 15: `c0dfdf35c03086c0`

| Field | Value |
|---|---|
| SHA-256 | `c0dfdf35c03086c024a70249340ff1f6a03ecabc74b8a065e1a4c6220797ac30` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-10-19 04:29:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c62d79700054c9421078fc002da6fc4` |
| SHA-1 | `b90286dc54b09fe7cbf0bf88670c4be8aab82395` |
| SHA-256 | `c0dfdf35c03086c024a70249340ff1f6a03ecabc74b8a065e1a4c6220797ac30` |
| SHA3-384 | `6fe725ee437f822d9de8593d7e6b3a4e2199433d2f9333426789327bfb1f30c6c759cc1bb48222b05fbfdb4a2e54e81c` |
| TLSH | `T131D31945FC505F67C6D512BBFB5E428C372A17A8D2EE72039D256F20378686B0E3B246` |
| TELFHASH | `t125112f994f68486cafc0c08e82cad225db3070ed6ecb68074915ba098b4fce1b475967` |
| SSDEEP | `1536:rz5tg1kh9RL8vYSgMmb2TnJ4VXJP1Tgyns38oVnOdUI2gBKwNuAmldywywsYPMRf:rz55f4Asmb84ft5ns3fDYIhX0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_c0dfdf35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0dfdf35c03086c024a70249340ff1f6a03ecabc74b8a065e1a4c6220797ac30"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-19 04:29:49"
  condition:
    hash.sha256(0, filesize) == "c0dfdf35c03086c024a70249340ff1f6a03ecabc74b8a065e1a4c6220797ac30"
}
```

### Sample 16: `d8cbb7c00689d7fd`

| Field | Value |
|---|---|
| SHA-256 | `d8cbb7c00689d7fd518151cccdc8c24c5b6b44a49ce2e60ae9d74256ac366896` |
| Family label | `unknown` |
| File name | `rev.sh` |
| File type | `sh` |
| First seen | `2026-10-19 04:14:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbb66280daa8c7a7a63448694f29a1cb` |
| SHA-1 | `c4dc69d7614dc790b142e48c4eb5548b1482b35b` |
| SHA-256 | `d8cbb7c00689d7fd518151cccdc8c24c5b6b44a49ce2e60ae9d74256ac366896` |
| SHA3-384 | `40cf1a07a8faca7d97e02a694ea386db421d00205024028599a5f7e8ba7a522cfacf7c8a45ff2255e61e02d0e10010df` |
| TLSH | `T1FB219AB1F5F12AB93F74C85C618AE26036DA2B474B9C9CE2593C6AB13E13544E090B10` |
| SSDEEP | `24:w1NL7e/edkTr+SrNvNSL5lOK90TGz5lOK90TGP:wT3d46SuOK90TGGK90TGP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_d8cbb7c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8cbb7c00689d7fd518151cccdc8c24c5b6b44a49ce2e60ae9d74256ac366896"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-10-19 04:14:58"
  condition:
    hash.sha256(0, filesize) == "d8cbb7c00689d7fd518151cccdc8c24c5b6b44a49ce2e60ae9d74256ac366896"
}
```

### Sample 17: `15ccc62d46951d69`

| Field | Value |
|---|---|
| SHA-256 | `15ccc62d46951d6967d31fa6e8a3ceb13865cd319d6a7876420388a311efe651` |
| Family label | `unknown` |
| File name | `bot_s390x` |
| File type | `elf` |
| First seen | `2026-10-19 03:59:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c62f9639a0ccc09974cde0f446a45df` |
| SHA-1 | `c816f6e91beba5dc0864c3cb9e3b4cec454bcd58` |
| SHA-256 | `15ccc62d46951d6967d31fa6e8a3ceb13865cd319d6a7876420388a311efe651` |
| SHA3-384 | `56f9ad809aa30724aa00a62e8264b4c88092dd4699ed163e41e8762f155ee0328cf5cc139e26bbef835df1d08d002504` |
| TLSH | `T1B536F5C1BCA0C24AD63D6A71EFD9EFD8D22B7E315CC45A4BEAD5F73E18B214440A54A0` |
| GIMPHASH | `3575a815b22596ba947cb7d6eed1defef51eb54ea1ceb7f74f4addd3e596fb36` |
| SSDEEP | `49152:YuqdDL2qKS4lgKix9QxJDN73FV/WCTwqDLUmLOEUAV:Yuqdv2qvKgKix9QxJDp3SCvUA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_15ccc62d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15ccc62d46951d6967d31fa6e8a3ceb13865cd319d6a7876420388a311efe651"
    family = "unknown"
    file_name = "bot_s390x"
    file_type = "elf"
    first_seen = "2026-10-19 03:59:55"
  condition:
    hash.sha256(0, filesize) == "15ccc62d46951d6967d31fa6e8a3ceb13865cd319d6a7876420388a311efe651"
}
```

### Sample 18: `d3ec060c8459ece5`

| Field | Value |
|---|---|
| SHA-256 | `d3ec060c8459ece5a17730985c4751976f276c3d16e4487b6d19dfc998980a22` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `exe` |
| First seen | `2026-10-19 03:57:40` |
| Reporter | `z3r0s6` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54e155cb7609bdd268a89555a610a2f9` |
| SHA-1 | `6b7f7c6c73f2d77bd55af44cb2e04bd7c0e2cd9e` |
| SHA-256 | `d3ec060c8459ece5a17730985c4751976f276c3d16e4487b6d19dfc998980a22` |
| SHA3-384 | `1fa4d77a0b1def241416381036d0f8923f02b355b31240abb7cd34e102e8d52c39e0a0347a3864079e64bc7244711046` |
| IMPHASH | `a5156d126601b2b9a4b7c702224eaab8` |
| TLSH | `T11F48AE4AB27545D8C87EC13CCB228563F6B574895330AAEB26F08B762F13AF05A3D715` |
| SSDEEP | `1572864:3t0HaubQmIc+E3KFNVfottppkwWSck3Rzk:pNh2K50DSqhA` |
| ICON-DHASH | `d09e3c78f8e8e0c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_d3ec060c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3ec060c8459ece5a17730985c4751976f276c3d16e4487b6d19dfc998980a22"
    family = "unknown"
    file_name = "sample"
    file_type = "exe"
    first_seen = "2026-10-19 03:57:40"
  condition:
    hash.sha256(0, filesize) == "d3ec060c8459ece5a17730985c4751976f276c3d16e4487b6d19dfc998980a22"
}
```

### Sample 19: `838c6c0f247c3347`

| Field | Value |
|---|---|
| SHA-256 | `838c6c0f247c3347075a71d18fb4a51b0ecc06c3db3ab337d666092d533129cb` |
| Family label | `unknown` |
| File name | `mbupload-87n186oc.bin` |
| File type | `exe` |
| First seen | `2026-10-19 03:47:50` |
| Reporter | `wristhulk` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a848b2ef2542957acb754a393bd3ffd` |
| SHA-1 | `11b127708610bec31124e5d2a56c0a0e9e81ccf3` |
| SHA-256 | `838c6c0f247c3347075a71d18fb4a51b0ecc06c3db3ab337d666092d533129cb` |
| SHA3-384 | `e5b0c2773634556651dfc8c3ddb7e326bb39dce798a1fe262d1eafa09db5f083cce93c3b96cea36a17758dbeb6997a0f` |
| IMPHASH | `9647813c66e51e2c6fe5726b49557a29` |
| TLSH | `T126F6649B789B8950DCDA85378C378076E3F804C0BA6EDE7135D979706EE36746C602E2` |
| SSDEEP | `49152:4+3Ra/U8Iv4ehTe3CZ6IOX8KK0gKuKHD50pwiBju+Y0GbcWfX3sRJ5ey9E9:4ac/U8e4Cu19D505BjNIbtHsRJPg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_838c6c0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "838c6c0f247c3347075a71d18fb4a51b0ecc06c3db3ab337d666092d533129cb"
    family = "unknown"
    file_name = "mbupload-87n186oc.bin"
    file_type = "exe"
    first_seen = "2026-10-19 03:47:50"
  condition:
    hash.sha256(0, filesize) == "838c6c0f247c3347075a71d18fb4a51b0ecc06c3db3ab337d666092d533129cb"
}
```

### Sample 20: `6c3731a2777b436a`

| Field | Value |
|---|---|
| SHA-256 | `6c3731a2777b436a1be8274135298572414024391b77d9c5d9435bfb9d4b7ef6` |
| Family label | `unknown` |
| File name | `mbupload-4an3c499.bin` |
| File type | `zip` |
| First seen | `2026-10-19 03:47:31` |
| Reporter | `wristhulk` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e70b96aed79537b22c371cf538a000a5` |
| SHA-1 | `829362f0ad2a10dc9a4e9ff23d5fec01af27baa3` |
| SHA-256 | `6c3731a2777b436a1be8274135298572414024391b77d9c5d9435bfb9d4b7ef6` |
| SHA3-384 | `a5142b94c2b07bc623133ca5dcbb530c5b14001eb9e59d81f79cf313ab2ce499f68a71a87f08928d020fc08f100d3e4f` |
| TLSH | `T15C5633C5DD099EB7DAF3F5B181D7820CBB6A0EA014FF3A7A703753E6004A99D8196394` |
| SSDEEP | `98304:mr0fSAs0VvvPMTQLBQXadFrpES2CBhsqzdhkqIfLHFhaY6GGu8nboyFHEr0fSLhl:UmvVLBEoF/2CkqvkqIx/1f0oyFH6Lz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_6c3731a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c3731a2777b436a1be8274135298572414024391b77d9c5d9435bfb9d4b7ef6"
    family = "unknown"
    file_name = "mbupload-4an3c499.bin"
    file_type = "zip"
    first_seen = "2026-10-19 03:47:31"
  condition:
    hash.sha256(0, filesize) == "6c3731a2777b436a1be8274135298572414024391b77d9c5d9435bfb9d4b7ef6"
}
```

### Sample 21: `ac08c52835b555fb`

| Field | Value |
|---|---|
| SHA-256 | `ac08c52835b555fb2bb899f798468e9011ac321b60d5a2763d485e6f0d59aaa7` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `exe` |
| First seen | `2026-10-19 03:28:58` |
| Reporter | `z3r0s6` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06854601d68d22b4f93e688f6a137251` |
| SHA-1 | `05fb13650a7aec6ff46e2ed0786b6d4cd877c7db` |
| SHA-256 | `ac08c52835b555fb2bb899f798468e9011ac321b60d5a2763d485e6f0d59aaa7` |
| SHA3-384 | `c1deb8a60045f15add0f5ee0c015a82aa1b7851c87b6515cca3aa1e3f503463c625054b464135966160fa9103aaea27d` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1FF67333FA2C7713ED07A0A3979B2B565583B7B6168064C12DAF0D48CDF219712E3E786` |
| SSDEEP | `786432:oxp3Y6YISH2WnRphIqa/CQ8Ym2Zsifg+WKI/XAQZKZ:o3Y/ISWWnRphI1/B8YmWM7XtZKZ` |
| ICON-DHASH | `4b26aaa22672c219` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_ac08c528
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac08c52835b555fb2bb899f798468e9011ac321b60d5a2763d485e6f0d59aaa7"
    family = "unknown"
    file_name = "sample"
    file_type = "exe"
    first_seen = "2026-10-19 03:28:58"
  condition:
    hash.sha256(0, filesize) == "ac08c52835b555fb2bb899f798468e9011ac321b60d5a2763d485e6f0d59aaa7"
}
```

### Sample 22: `57a23842ad1e35d7`

| Field | Value |
|---|---|
| SHA-256 | `57a23842ad1e35d74a7668ab2112de54d92b2a70f6949d7f892002aeb5d69db6` |
| Family label | `RemcosRAT` |
| File name | `sample` |
| File type | `exe` |
| First seen | `2026-10-19 03:28:40` |
| Reporter | `z3r0s6` |
| Tags | `RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d91435c7250f01daa3dc6ddbd0bc9df0` |
| SHA-1 | `6d60f55c781940ce29af3d8c154d819620e4c028` |
| SHA-256 | `57a23842ad1e35d74a7668ab2112de54d92b2a70f6949d7f892002aeb5d69db6` |
| SHA3-384 | `479be50b6fd93a0ef9d79eca97728e0a07751de9a1f154e217fc273c0e04469369e1509037429b8fdccbe4c49bb58b6d` |
| TLSH | `T17155D0AC3210B99FC457CA368EA4ED30A6646CB75707D20395D71DEFBA0DA968F101E3` |
| SSDEEP | `24576:WYZoisSQa6vMcoTZ1UEqE/fc+xju4lxv4YQtlVT/aWX51rXwURaZHUgZm7iVQaZx:ISQ1MbU2VJjAY8VT/5bgZm+eC` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_022_57a23842
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57a23842ad1e35d74a7668ab2112de54d92b2a70f6949d7f892002aeb5d69db6"
    family = "RemcosRAT"
    file_name = "sample"
    file_type = "exe"
    first_seen = "2026-10-19 03:28:40"
  condition:
    hash.sha256(0, filesize) == "57a23842ad1e35d74a7668ab2112de54d92b2a70f6949d7f892002aeb5d69db6"
}
```

### Sample 23: `719a47231d3f1fb7`

| Field | Value |
|---|---|
| SHA-256 | `719a47231d3f1fb7e3522cf842a06c64f6cbddbfde46e79846fc0ad3e79f5014` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-19 03:19:33` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `656deb0542b95f5fc176eadf8e5d49c6` |
| SHA-1 | `6c8cac170d8891f2db89ba4a3fda03eb43e2f760` |
| SHA-256 | `719a47231d3f1fb7e3522cf842a06c64f6cbddbfde46e79846fc0ad3e79f5014` |
| SHA3-384 | `587839d793f94c92fe873cdb9d79124f555894d0178c47041515d770ee3c36d5d24abb942dfc80253dcdb03266a06e32` |
| IMPHASH | `9bd4d61f2bdd759a3539d644c013268c` |
| TLSH | `T14422D60E2E4B0231DD5149B0E6B48A0A557D6CF32792FAEBE333C1DB1AD4F8584C169B` |
| SSDEEP | `192:hYM8dGOBq08leW8jMjVGFJxTEimFhkee:hYMyGo8UYGFwi` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_023_719a4723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "719a47231d3f1fb7e3522cf842a06c64f6cbddbfde46e79846fc0ad3e79f5014"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-19 03:19:33"
  condition:
    hash.sha256(0, filesize) == "719a47231d3f1fb7e3522cf842a06c64f6cbddbfde46e79846fc0ad3e79f5014"
}
```

### Sample 24: `125b3a8bfa122c84`

| Field | Value |
|---|---|
| SHA-256 | `125b3a8bfa122c8467d6a0978ec1b413261543a4b0fa6a3f7a1bd3b067aedf0d` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `msi` |
| First seen | `2026-10-19 03:15:30` |
| Reporter | `z3r0s6` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1fd340790c0a84c8f3543a81c80145b` |
| SHA-1 | `2aa0a1db038ee620e9d117e0de585b173ba244eb` |
| SHA-256 | `125b3a8bfa122c8467d6a0978ec1b413261543a4b0fa6a3f7a1bd3b067aedf0d` |
| SHA3-384 | `ff743fe1261bcf044c7ca973ca050bba843d667bc1a0856dbda3f21b616c1cfd0c24440899649c04e83f127fa66fe281` |
| TLSH | `T13FB55C636A50600642B5A8FABEBD5E37795F340D101AD98EFFD30B86E51E6F44802E1F` |
| SSDEEP | `24576:XfxK1PcpukylEL3CJEdBPHjzWO1UauftimpvpYe0DZp52lHF6Y5mJYAppfSKMxA4:XQSdDSidBLZUamiuX0Df52lMUll6o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_125b3a8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "125b3a8bfa122c8467d6a0978ec1b413261543a4b0fa6a3f7a1bd3b067aedf0d"
    family = "unknown"
    file_name = "sample"
    file_type = "msi"
    first_seen = "2026-10-19 03:15:30"
  condition:
    hash.sha256(0, filesize) == "125b3a8bfa122c8467d6a0978ec1b413261543a4b0fa6a3f7a1bd3b067aedf0d"
}
```

### Sample 25: `30be992d1c779f11`

| Field | Value |
|---|---|
| SHA-256 | `30be992d1c779f119e2e52711d6966289de06e24fba306050264d3b10301de0f` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `exe` |
| First seen | `2026-10-19 03:15:25` |
| Reporter | `z3r0s6` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bda9f9b4bdc277b6b2af90d9149dfc4` |
| SHA-1 | `7b38d7c4451b2955e3719f2ca9b050e0ec1927f3` |
| SHA-256 | `30be992d1c779f119e2e52711d6966289de06e24fba306050264d3b10301de0f` |
| SHA3-384 | `80247c2d537262ac8e51adec448db5339ebe8880dad671de263c575430e8900374a1a04f38670446e6b448160b8406bd` |
| TLSH | `T18675012712969A0BC59867F88965F53403BAADEB7D21E3469FC97CEB3436FC049001B7` |
| SSDEEP | `24576:JhhlcIELjvyTr5GNnUNprKJA8XEKmjA4dRuB/5AcDbxLioydAsR:JMXvyTr5sUNtK2/9PuhTuoAzR` |
| ICON-DHASH | `0c12b212dac82c93` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_30be992d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30be992d1c779f119e2e52711d6966289de06e24fba306050264d3b10301de0f"
    family = "unknown"
    file_name = "sample"
    file_type = "exe"
    first_seen = "2026-10-19 03:15:25"
  condition:
    hash.sha256(0, filesize) == "30be992d1c779f119e2e52711d6966289de06e24fba306050264d3b10301de0f"
}
```

### Sample 26: `c2e6edab80c83e9f`

| Field | Value |
|---|---|
| SHA-256 | `c2e6edab80c83e9fca3aca4a86040e00398dde5ebb652934d852387bfa5e1561` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `exe` |
| First seen | `2026-10-19 03:13:30` |
| Reporter | `z3r0s6` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bf63c227852c7091ce84db69921679f` |
| SHA-1 | `e94c7db96d983387421e9cafd52c309109768c45` |
| SHA-256 | `c2e6edab80c83e9fca3aca4a86040e00398dde5ebb652934d852387bfa5e1561` |
| SHA3-384 | `40a367d26431e1ed40372fbbe2b1e31844f3c6471e335885d5dbe0006e997c706f8b3357f8336bf2bd5797a7695f6faf` |
| TLSH | `T119A73BB7F139A92ED20851B35C6D6C430761B7A855FFE0EA3B433E37A5444ED8D242A2` |
| SSDEEP | `98304:DrqAcmxvqrQGqBYYYBC/81j957jnYAyr1Ii7MDXFpWGpzpRh8qxziOu44tNEB6ia:qVBxSA4tqFuzcJvr2bTL3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_c2e6edab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2e6edab80c83e9fca3aca4a86040e00398dde5ebb652934d852387bfa5e1561"
    family = "unknown"
    file_name = "sample"
    file_type = "exe"
    first_seen = "2026-10-19 03:13:30"
  condition:
    hash.sha256(0, filesize) == "c2e6edab80c83e9fca3aca4a86040e00398dde5ebb652934d852387bfa5e1561"
}
```

### Sample 27: `8d65192fabdefc20`

| Field | Value |
|---|---|
| SHA-256 | `8d65192fabdefc204ea73e9c19b22c81af46c9b3946cc2ff4df40d18516f97e2` |
| Family label | `unknown` |
| File name | `mbupload-m8tv7yba.bin` |
| File type | `zip` |
| First seen | `2026-10-19 03:08:05` |
| Reporter | `wristhulk` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f76adbf0d6dbfa223a96e40aa7375fb` |
| SHA-1 | `528038d6c259a5e6d5f64fdb497ec905fb28ba68` |
| SHA-256 | `8d65192fabdefc204ea73e9c19b22c81af46c9b3946cc2ff4df40d18516f97e2` |
| SHA3-384 | `d26e48369a21ef69f7a09786078f2793740cabc2cb08d4f730142544e3efb5ac6023f031bf3a0026c94bd1aeca872c78` |
| TLSH | `T1E2B633ECCA403CCDE8C7BA3D8BE819EAE9D58A378A10D5E6D145A3E0247E1FD2C51457` |
| SSDEEP | `196608:xoslj+RxnaqYfoYhvhVo6PfrlPW2zvT6VpsaurXkJWcaiJ5uQdQnBhv:xflinDUh7o67QaT6vslTkJWlQdQnBB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_8d65192f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d65192fabdefc204ea73e9c19b22c81af46c9b3946cc2ff4df40d18516f97e2"
    family = "unknown"
    file_name = "mbupload-m8tv7yba.bin"
    file_type = "zip"
    first_seen = "2026-10-19 03:08:05"
  condition:
    hash.sha256(0, filesize) == "8d65192fabdefc204ea73e9c19b22c81af46c9b3946cc2ff4df40d18516f97e2"
}
```

### Sample 28: `22874b6a6184d2f7`

| Field | Value |
|---|---|
| SHA-256 | `22874b6a6184d2f77ba2c24b8948fe2af261aea99d641423e4c69644b994e6ea` |
| Family label | `unknown` |
| File name | `mbupload-pdewblml.bin` |
| File type | `zip` |
| First seen | `2026-10-19 03:07:47` |
| Reporter | `wristhulk` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a8a75ed5c43572b70fe1a4363c9497e` |
| SHA-1 | `60326febdebb6f5c791b454fbda10315601b8be0` |
| SHA-256 | `22874b6a6184d2f77ba2c24b8948fe2af261aea99d641423e4c69644b994e6ea` |
| SHA3-384 | `d5ce1475b125b47657351978271c91cc87b4319d93aa2b8f3434dae683e9cb614eec1b9859bfb1757deb41dbf5a84a64` |
| TLSH | `T1A3B633E8C6413CCDE8C7BA3D87E819EAE9C9CA378A10D5E6D145A3E024BE1FD1C51457` |
| SSDEEP | `196608:roslj+RxnaqYfoYhvhVo6PfrlPW2zvT6VpsaurXkJWcaiJ5uQdQnBhK:rflinDUh7o67QaT6vslTkJWlQdQnBQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_22874b6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22874b6a6184d2f77ba2c24b8948fe2af261aea99d641423e4c69644b994e6ea"
    family = "unknown"
    file_name = "mbupload-pdewblml.bin"
    file_type = "zip"
    first_seen = "2026-10-19 03:07:47"
  condition:
    hash.sha256(0, filesize) == "22874b6a6184d2f77ba2c24b8948fe2af261aea99d641423e4c69644b994e6ea"
}
```

### Sample 29: `ccaf6b28b9fe286e`

| Field | Value |
|---|---|
| SHA-256 | `ccaf6b28b9fe286efa1533e0af5ce57dba11be068aee39e08d1ad5a7796d7d79` |
| Family label | `unknown` |
| File name | `ccaf6b28b9fe286efa1533e0af5ce57dba11be068aee39e08d1ad5a7796d7d79.elf` |
| File type | `elf` |
| First seen | `2026-10-19 03:06:35` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fd4c6973258612c637ee4230d371d8d` |
| SHA-1 | `617b0311cfaddf29406ec85ab011da4bd1fdd6c2` |
| SHA-256 | `ccaf6b28b9fe286efa1533e0af5ce57dba11be068aee39e08d1ad5a7796d7d79` |
| SHA3-384 | `fe18539f709dbfbe8cecabe9645c0d04dd192ab16192f1df70ce3aa34b85829b1e82c80e41a1e81cc0ce00928adce082` |
| TLSH | `T197F3D81AAF950EBBDCAFDD3706E90A0139CC914722A83B753674D528F54A50F4AE3C78` |
| SSDEEP | `1536:NebNAbzN+YC54oxnnlJsCYMX8i5NuT+I+EXuZONj60oqQA74TNNsaQikmVYsXzQ/:+A/JCWEnA9+EeGEPNN3QnmVYsSmM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_ccaf6b28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccaf6b28b9fe286efa1533e0af5ce57dba11be068aee39e08d1ad5a7796d7d79"
    family = "unknown"
    file_name = "ccaf6b28b9fe286efa1533e0af5ce57dba11be068aee39e08d1ad5a7796d7d79.elf"
    file_type = "elf"
    first_seen = "2026-10-19 03:06:35"
  condition:
    hash.sha256(0, filesize) == "ccaf6b28b9fe286efa1533e0af5ce57dba11be068aee39e08d1ad5a7796d7d79"
}
```

### Sample 30: `2ad9f14bb36743f1`

| Field | Value |
|---|---|
| SHA-256 | `2ad9f14bb36743f1e361f2039aedf0b369958a254b618e172b0240f58191ba47` |
| Family label | `Mirai` |
| File name | `disssh4` |
| File type | `elf` |
| First seen | `2026-10-19 03:03:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d363c2ce2cd068045a3b3c0fa9f8d2cd` |
| SHA-1 | `2fd288bc4d8f629a0c15a14a08dfb645b85b6fbc` |
| SHA-256 | `2ad9f14bb36743f1e361f2039aedf0b369958a254b618e172b0240f58191ba47` |
| SHA3-384 | `1649810efbc589de48de957ffb04eddfded4f262d15c72024f9d8cb8165688d2fc80d8c2ef89f96a35330e336e749e6c` |
| TLSH | `T1FD040731A8B13FA4D037F3B8D7B587382366D6500B0A5EBB8136806589B7D6DB94177C` |
| SSDEEP | `3072:0QNo6to/CHkdSupdrYF8+N71WHfBn/SaCrj:0l/ddSupSzAHfwrj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_2ad9f14b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ad9f14bb36743f1e361f2039aedf0b369958a254b618e172b0240f58191ba47"
    family = "Mirai"
    file_name = "disssh4"
    file_type = "elf"
    first_seen = "2026-10-19 03:03:17"
  condition:
    hash.sha256(0, filesize) == "2ad9f14bb36743f1e361f2039aedf0b369958a254b618e172b0240f58191ba47"
}
```

### Sample 31: `a1284c71db02401d`

| Field | Value |
|---|---|
| SHA-256 | `a1284c71db02401df19887a51a738b39fcd5c96716a26bf6cfd0f7de3a5619a3` |
| Family label | `unknown` |
| File name | `bot_mips` |
| File type | `elf` |
| First seen | `2026-10-19 02:34:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b93ef948bbb8c3898686adc45233daa` |
| SHA-1 | `264ca0c9d8d329baf6821e2b4369146b075cde33` |
| SHA-256 | `a1284c71db02401df19887a51a738b39fcd5c96716a26bf6cfd0f7de3a5619a3` |
| SHA3-384 | `d4325b5d566cd9ae079cdb4535965ad954e5687b1b3d02ca61bde94c09dc97bf08bb40c4ed39fdc168981ee15e4c77b0` |
| TLSH | `T10B4618137E18D71EC225213449B2CA947B3A3C8941DA9613B386F30EB9F126C696FDF1` |
| TELFHASH | `t15ac08c418650649c298019a18fccf42374f8e523293a10adf73a5083892c8b3a14c818` |
| GIMPHASH | `513dfb33e3f67e7a545599851d8d9df12966e36e56cdd6281e57353d089c3dd9` |
| SSDEEP | `49152:1/rtATd8bvmXQzQ6APyvCX078qUPMfXM3ev6VL/7CH22N1Vip8is/oLjLDF/4FtA:md84q5iFOq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_a1284c71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1284c71db02401df19887a51a738b39fcd5c96716a26bf6cfd0f7de3a5619a3"
    family = "unknown"
    file_name = "bot_mips"
    file_type = "elf"
    first_seen = "2026-10-19 02:34:47"
  condition:
    hash.sha256(0, filesize) == "a1284c71db02401df19887a51a738b39fcd5c96716a26bf6cfd0f7de3a5619a3"
}
```

### Sample 32: `5c0c2965baddcf82`

| Field | Value |
|---|---|
| SHA-256 | `5c0c2965baddcf82f7edd84d959f151d3180cd687e6d65f78f095c015954cc96` |
| Family label | `unknown` |
| File name | `bot_mips64le` |
| File type | `elf` |
| First seen | `2026-10-19 02:31:18` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64712ef5bfa8e80723f8fa55853a6125` |
| SHA-1 | `6575f425f245afb07a9f1b28df421ac6fd686361` |
| SHA-256 | `5c0c2965baddcf82f7edd84d959f151d3180cd687e6d65f78f095c015954cc96` |
| SHA3-384 | `981c743a5b09c0e22d6eda1e5d93cf5024de85962f48bfdb24b8887f40bc077bacbce409b7a645c488beaa6aa05e52b3` |
| TLSH | `T1BB460911ADC26B66C2CC077445FEA79663503E499B96072323B4EFA9397773CEF06848` |
| GIMPHASH | `ea62c63d131af51aed9894a2d5a1c8d31d93c2791771a0c5a831581ad7a72fea` |
| SSDEEP | `98304:0A0UM8XRZAnWAaIAAVVpAYTAAA6QoVaTDWK/UAavj:KOZAnWAaIAAVVpAYTAAA6QoVaPWK/UAK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_5c0c2965
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c0c2965baddcf82f7edd84d959f151d3180cd687e6d65f78f095c015954cc96"
    family = "unknown"
    file_name = "bot_mips64le"
    file_type = "elf"
    first_seen = "2026-10-19 02:31:18"
  condition:
    hash.sha256(0, filesize) == "5c0c2965baddcf82f7edd84d959f151d3180cd687e6d65f78f095c015954cc96"
}
```

### Sample 33: `ec36ef56f434d83d`

| Field | Value |
|---|---|
| SHA-256 | `ec36ef56f434d83d349ce67d2edc544c6f7f13b093713217ca57fdc7fc214601` |
| Family label | `unknown` |
| File name | `bot_arm` |
| File type | `elf` |
| First seen | `2026-10-19 02:16:14` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16e0d57e3e19f4a49d5a15f1a536e198` |
| SHA-1 | `5682a92557306b0c4de3242713ddd53d8ff4d0b4` |
| SHA-256 | `ec36ef56f434d83d349ce67d2edc544c6f7f13b093713217ca57fdc7fc214601` |
| SHA3-384 | `88c5348aecaaad5c1a539e288f9034b037c918590dc0c13cb220d3eaead895f98e9786487da2eb36ffc56782e2ca6c04` |
| TLSH | `T1D5262A97F8918643C0E43676B8BD81C433632EB96B9B22576D05FE3D3ABE1990E35704` |
| TELFHASH | `t15bd01232464c00b83fdac28865011389c6d638b1261152f94f2572835e81df3775d41b` |
| GIMPHASH | `513dfb33e3f67e7a545599851d8d9df12966e36e56cdd6281e57353d089c3dd9` |
| SSDEEP | `49152:JK8ZpmtMNT2nYB9lrOqoFn2kO5joLD9G22vCU1F1:Q8ZpmSoYB9lre6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_ec36ef56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec36ef56f434d83d349ce67d2edc544c6f7f13b093713217ca57fdc7fc214601"
    family = "unknown"
    file_name = "bot_arm"
    file_type = "elf"
    first_seen = "2026-10-19 02:16:14"
  condition:
    hash.sha256(0, filesize) == "ec36ef56f434d83d349ce67d2edc544c6f7f13b093713217ca57fdc7fc214601"
}
```

### Sample 34: `2fcb0f77a76ae4af`

| Field | Value |
|---|---|
| SHA-256 | `2fcb0f77a76ae4afe0f8edb6e487f7cd31723af5f05d8b99742905b4cf645a04` |
| Family label | `unknown` |
| File name | `bot_arm64` |
| File type | `elf` |
| First seen | `2026-10-19 02:16:11` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dd2a46b3e1f1706dfee1a8b03faf32a` |
| SHA-1 | `803213542f02361a28572191ef101dc70135fb7b` |
| SHA-256 | `2fcb0f77a76ae4afe0f8edb6e487f7cd31723af5f05d8b99742905b4cf645a04` |
| SHA3-384 | `d2a1283459a3f540d1e6b7356ce18926ceb0e65022dd08f8fafbe07e0ed18d4c5a6677d48208e1b0e8d2974d65d9ed46` |
| TLSH | `T106266C65BD1EE963E6C873707B6583D4323EBC449F41D2236610BFAE59F63688F12122` |
| GIMPHASH | `3575a815b22596ba947cb7d6eed1defef51eb54ea1ceb7f74f4addd3e596fb36` |
| SSDEEP | `49152:FFwRR35OwKWr2cta27VGEBwAY5EYkaLGzyXpi1B1:vwRR35OwKgta27VGE6HE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_2fcb0f77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fcb0f77a76ae4afe0f8edb6e487f7cd31723af5f05d8b99742905b4cf645a04"
    family = "unknown"
    file_name = "bot_arm64"
    file_type = "elf"
    first_seen = "2026-10-19 02:16:11"
  condition:
    hash.sha256(0, filesize) == "2fcb0f77a76ae4afe0f8edb6e487f7cd31723af5f05d8b99742905b4cf645a04"
}
```

### Sample 35: `9faa8777e0cbb575`

| Field | Value |
|---|---|
| SHA-256 | `9faa8777e0cbb5751123e356ded1e8d3f2681064ae3bfdc048e6f7666c511033` |
| Family label | `unknown` |
| File name | `Phantom.exe` |
| File type | `exe` |
| First seen | `2026-10-19 02:03:00` |
| Reporter | `AmadeyHunter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc12db8ccbc9ffae86e67f857dca9d04` |
| SHA-1 | `dd0d9c7cc3df9485d618f6366b96161b7786bc36` |
| SHA-256 | `9faa8777e0cbb5751123e356ded1e8d3f2681064ae3bfdc048e6f7666c511033` |
| SHA3-384 | `cbb75781b1215e58340b99d33eed674255e80bae1a8f23a3792cffba3420c31a4e3dd3caeafe6fb1ed8cdd0717029c35` |
| IMPHASH | `9eba512b03d8cac8a6c4424e25e9f06e` |
| TLSH | `T1B948F01663E111AAD577D138C7AB6603EB72B40713308BDB329C43652F63AE45E7BB60` |
| SSDEEP | `1572864:1Pp36F/iKRzDo0EL9uXpXFxAI/MZqNrGZVOc4XIoC3MnluZQrZ7:1PpIlDheuXpX/z/5NivOcC7hlTrR` |
| ICON-DHASH | `f89efcf8f971f2e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_9faa8777
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9faa8777e0cbb5751123e356ded1e8d3f2681064ae3bfdc048e6f7666c511033"
    family = "unknown"
    file_name = "Phantom.exe"
    file_type = "exe"
    first_seen = "2026-10-19 02:03:00"
  condition:
    hash.sha256(0, filesize) == "9faa8777e0cbb5751123e356ded1e8d3f2681064ae3bfdc048e6f7666c511033"
}
```

### Sample 36: `10a76ea065179912`

| Field | Value |
|---|---|
| SHA-256 | `10a76ea06517991202d6766a1d55e5aba67e81600f67ea55bcbf5363ac1f6d42` |
| Family label | `Mirai` |
| File name | `adb.arm7` |
| File type | `elf` |
| First seen | `2026-10-19 02:00:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de775ba938a43bf9c6371d739e4b497c` |
| SHA-1 | `3ee38c16c18009e1edd22f3d26d8dd2cadb9b582` |
| SHA-256 | `10a76ea06517991202d6766a1d55e5aba67e81600f67ea55bcbf5363ac1f6d42` |
| SHA3-384 | `33e0079e488ea7027fe81fb7ed2ee4b0f3e7fc12450b85326fb50fb24083229929c6a10f31d3d299c5901a53506b3f80` |
| TLSH | `T10C14F925B8916B11D0E373BAEBBE41443367AB78CBB97003C5305F6167FA5AE0E72425` |
| TELFHASH | `t158b01240ec1d04c0f440421cc1e2e70715f4eb04030c41de49095f0f06a3459f449533` |
| SSDEEP | `6144:G0XWNK27hCCLd9+aiY4hBbvxINGBsGZndFmNz/:tId59+aiY2bvxecZndF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_10a76ea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10a76ea06517991202d6766a1d55e5aba67e81600f67ea55bcbf5363ac1f6d42"
    family = "Mirai"
    file_name = "adb.arm7"
    file_type = "elf"
    first_seen = "2026-10-19 02:00:59"
  condition:
    hash.sha256(0, filesize) == "10a76ea06517991202d6766a1d55e5aba67e81600f67ea55bcbf5363ac1f6d42"
}
```

### Sample 37: `cf5d3dcba7d9e58e`

| Field | Value |
|---|---|
| SHA-256 | `cf5d3dcba7d9e58e808501a6867b99f4a28060891e37050be2ed1fff5f517b0a` |
| Family label | `Mirai` |
| File name | `dissarm6` |
| File type | `elf` |
| First seen | `2026-10-19 01:47:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8831e1b7fc0594df069d3a736f09eec3` |
| SHA-1 | `d19eb71bb44df9f2174b8f26763811939af99cfd` |
| SHA-256 | `cf5d3dcba7d9e58e808501a6867b99f4a28060891e37050be2ed1fff5f517b0a` |
| SHA3-384 | `d6c68a962293b2c6f678fd1b811305b682367d4699a4b0476635af1cb3ac434baebd966d28cd44d2030b2bdcdcaa20d9` |
| TLSH | `T168240725B891A711D0E3737AEF7D014833279B78C7DE710389345A60ABFA97E0E76429` |
| TELFHASH | `t144b012173d448ecac150e05dc27403186e30e54f1f2135820128d60c8a01ed3223c103` |
| SSDEEP | `3072:CDkjNQLE8ir5J6fQGlOXwXzCGv/aEjD7DTusMl846Z0ca6VguKG:BjsE8+KZtXzCGXaKD7f2l846k6VgVG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_cf5d3dcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf5d3dcba7d9e58e808501a6867b99f4a28060891e37050be2ed1fff5f517b0a"
    family = "Mirai"
    file_name = "dissarm6"
    file_type = "elf"
    first_seen = "2026-10-19 01:47:23"
  condition:
    hash.sha256(0, filesize) == "cf5d3dcba7d9e58e808501a6867b99f4a28060891e37050be2ed1fff5f517b0a"
}
```

### Sample 38: `40dc77a48faae52f`

| Field | Value |
|---|---|
| SHA-256 | `40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c` |
| Family label | `AMOS` |
| File name | `macho_40dc77a48faa.bin` |
| File type | `macho` |
| First seen | `2026-10-19 01:46:31` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a635c28c24aa6e3e73fad857e3347659` |
| SHA-1 | `b997928aaa11438ab6611e44d7322e5164798160` |
| SHA-256 | `40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c` |
| SHA3-384 | `2bf922012a2825e9ff98269184e7fdba5e98ca39567aed3ac7f415db73ff4dccb59bdbc402eb8ef42b0a1866df062e68` |
| TLSH | `T1D185F1946A7E026AE4422433DC243F4A45E066B19E5CB3FB6229C7C27D35687F673363` |
| SSDEEP | `49152:QilFvxg55mdRu1t5TC76sM3FX+Bu/VU6tZv8e:QilPvRa+2sM39+k/Ka` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_038_40dc77a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c"
    family = "AMOS"
    file_name = "macho_40dc77a48faa.bin"
    file_type = "macho"
    first_seen = "2026-10-19 01:46:31"
  condition:
    hash.sha256(0, filesize) == "40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c"
}
```

### Sample 39: `eae1ad551a79a4c8`

| Field | Value |
|---|---|
| SHA-256 | `eae1ad551a79a4c8333b098258aab12566f538efcc0c8a3166bcf2f26a0ae2c5` |
| Family label | `AMOS` |
| File name | `macho_eae1ad551a79.bin` |
| File type | `macho` |
| First seen | `2026-10-19 01:43:19` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce86d2860291a0d82d54f7d547cc6250` |
| SHA-1 | `734557b8ba528923b7d9c67c16154ccf829f24f0` |
| SHA-256 | `eae1ad551a79a4c8333b098258aab12566f538efcc0c8a3166bcf2f26a0ae2c5` |
| SHA3-384 | `59a0af8910cfb4afef5692ca49ef42fc8d027a2b8f772eab3bed436b173429af4dc8294a189197971c9ab2abcd756c50` |
| TLSH | `T101A5F124517B2236E0432532DC200FD994AD6AF099DCF9E76625D3222CB6AE7E573373` |
| SSDEEP | `24576:CovTGm6aR41rBhlV1PhCPEolojEXMSrUn3N2k5SmdenIhpbAL9PVFs34bpUb5fXn:l76aSlBhDLEUWs3N7eWpL4pUpXmVxXA` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_039_eae1ad55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eae1ad551a79a4c8333b098258aab12566f538efcc0c8a3166bcf2f26a0ae2c5"
    family = "AMOS"
    file_name = "macho_eae1ad551a79.bin"
    file_type = "macho"
    first_seen = "2026-10-19 01:43:19"
  condition:
    hash.sha256(0, filesize) == "eae1ad551a79a4c8333b098258aab12566f538efcc0c8a3166bcf2f26a0ae2c5"
}
```

### Sample 40: `447cc1be6fdca78d`

| Field | Value |
|---|---|
| SHA-256 | `447cc1be6fdca78d738314f2d56b7981d7369247cdf8e97d548946f6f9919244` |
| Family label | `AMOS` |
| File name | `macho_447cc1be6fdc.bin` |
| File type | `macho` |
| First seen | `2026-10-19 01:40:13` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `069a88fe99bed5e1a272d321243a5209` |
| SHA-1 | `1b8d4e33bfe383fe6848511280f6770e40104bbc` |
| SHA-256 | `447cc1be6fdca78d738314f2d56b7981d7369247cdf8e97d548946f6f9919244` |
| SHA3-384 | `2171d06c8225408f4adb930e3411c6a8f7d02321484ab8d9f73dafa825236e6a098aceade515662292206b8ac80dc35d` |
| TLSH | `T1C2A5F150CE779E6EE84620B3CC130F992CB0EA495E48AEF91674C7267D35657F8A3630` |
| SSDEEP | `49152:wI/D4QqZ+rRel3yqed5q8L74/iPwWqJ0hj6x:wQI3yn5q8L746k` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_040_447cc1be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "447cc1be6fdca78d738314f2d56b7981d7369247cdf8e97d548946f6f9919244"
    family = "AMOS"
    file_name = "macho_447cc1be6fdc.bin"
    file_type = "macho"
    first_seen = "2026-10-19 01:40:13"
  condition:
    hash.sha256(0, filesize) == "447cc1be6fdca78d738314f2d56b7981d7369247cdf8e97d548946f6f9919244"
}
```

### Sample 41: `c60641f340d10694`

| Field | Value |
|---|---|
| SHA-256 | `c60641f340d10694fe999d6ac39d74de35aadb3b9e0c5dbac98dda7e35febdd6` |
| Family label | `Mirai` |
| File name | `adissarm5` |
| File type | `elf` |
| First seen | `2026-10-19 01:34:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d32b8bd0c1a88259cf5311765ca1474` |
| SHA-1 | `23b327f1af76dd711a205edeed61163ecfe43089` |
| SHA-256 | `c60641f340d10694fe999d6ac39d74de35aadb3b9e0c5dbac98dda7e35febdd6` |
| SHA3-384 | `f2ec5209d0c4e153cdf3f4a68a14beb4fd064c06a67e2bb4cc3d68b459419dd09a8005e699ec49c18b11449419b98a01` |
| TLSH | `T19514F865F8A16722C1E3B37AFB7E4248333A9378C7E9310385341A617BFA56E0D72465` |
| TELFHASH | `t18f1104368f484f5ce3e1e07f525e5119022830fe7515364495be9ebe8f538d17615a1c` |
| SSDEEP | `3072:LZvO8pClMDBwRS4DzZSomvZ494iA5cyN4XXYjhLJSFAQJ8N4KX1:LZvjpeSqzZSomIdqjN4HYj5JSD8NvF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_c60641f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c60641f340d10694fe999d6ac39d74de35aadb3b9e0c5dbac98dda7e35febdd6"
    family = "Mirai"
    file_name = "adissarm5"
    file_type = "elf"
    first_seen = "2026-10-19 01:34:06"
  condition:
    hash.sha256(0, filesize) == "c60641f340d10694fe999d6ac39d74de35aadb3b9e0c5dbac98dda7e35febdd6"
}
```

### Sample 42: `7c70782ad24660bc`

| Field | Value |
|---|---|
| SHA-256 | `7c70782ad24660bc90117473dfeca948075d0de5244ea47da6e6e87a7fc2d550` |
| Family label | `unknown` |
| File name | `dissarm4` |
| File type | `elf` |
| First seen | `2026-10-19 01:27:10` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba0d67d947be7f71e9d07b3eee3ce4e8` |
| SHA-1 | `7e5469a91763cf2dcc0b635f90d057ef26ac9be5` |
| SHA-256 | `7c70782ad24660bc90117473dfeca948075d0de5244ea47da6e6e87a7fc2d550` |
| SHA3-384 | `d19c3c6bf222db41f99258e771141058bfb313507765e886ad7a4e6d2bf2663e2bb952964d934594a81444472278c763` |
| TLSH | `T176141965F8A16722C5E7737AEB7E4288333A9378C7EA310385341A207BFA53E0D76455` |
| TELFHASH | `t10a114829954419cc3ad4e0f9d0ad5306161e31f53d651415e7f4ca1fdd13ad27112d1f` |
| SSDEEP | `3072:196kTtlSDhb717QDFf8AqT2B+bgkNX/5C4pemj/jEMKF8ek+:197Tk17iFf8AqaEMav84wmjbEMRex` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_7c70782a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c70782ad24660bc90117473dfeca948075d0de5244ea47da6e6e87a7fc2d550"
    family = "unknown"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-19 01:27:10"
  condition:
    hash.sha256(0, filesize) == "7c70782ad24660bc90117473dfeca948075d0de5244ea47da6e6e87a7fc2d550"
}
```

### Sample 43: `72dcf3b5d7cd9832`

| Field | Value |
|---|---|
| SHA-256 | `72dcf3b5d7cd9832908d30bc412ada04e8ed3124e66494d14c6f0714e44dee22` |
| Family label | `unknown` |
| File name | `72dcf3b5d7cd9832.bin` |
| File type | `exe` |
| First seen | `2026-10-19 01:26:11` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99020755659ea520b8b2c3be32433e39` |
| SHA-1 | `16ebd4e325591813194289009c0ee0a2f94e43ea` |
| SHA-256 | `72dcf3b5d7cd9832908d30bc412ada04e8ed3124e66494d14c6f0714e44dee22` |
| SHA3-384 | `589cf424a02bba425ca7f00903c2abbea9c95ace7e1daa3078f0af1cf6242b2ce61e4755db399fd031a02625fd6d63e4` |
| IMPHASH | `cdb284481e0ae3463deb8f461d5e56ac` |
| TLSH | `T1B9956D03F69580FCC55EC1788347A632EA22BC8E092576EB27D09B253E76F915F0DB19` |
| SSDEEP | `24576:5RfqQSFbnTwprZMo9wxGmUGJZ4bkFFJ8dtAGcMVTvHdOmdVIH06iy9FMsYX:5oQSVqrZMoob4bkFJ8oGrVBbIU6isvW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_72dcf3b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72dcf3b5d7cd9832908d30bc412ada04e8ed3124e66494d14c6f0714e44dee22"
    family = "unknown"
    file_name = "72dcf3b5d7cd9832.bin"
    file_type = "exe"
    first_seen = "2026-10-19 01:26:11"
  condition:
    hash.sha256(0, filesize) == "72dcf3b5d7cd9832908d30bc412ada04e8ed3124e66494d14c6f0714e44dee22"
}
```

### Sample 44: `c6504ab6ba9ab645`

| Field | Value |
|---|---|
| SHA-256 | `c6504ab6ba9ab6453092ac9da059559b4dde092aae898cd1cbdd930c6e5fa2f1` |
| Family label | `Mirai` |
| File name | `c6504ab6ba9ab645.bin` |
| File type | `elf` |
| First seen | `2026-10-19 01:26:02` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a9497436064ffe517f50a5335dd4039` |
| SHA-1 | `4ee2f9374c45befad13d45db2af7fe72f7c117f6` |
| SHA-256 | `c6504ab6ba9ab6453092ac9da059559b4dde092aae898cd1cbdd930c6e5fa2f1` |
| SHA3-384 | `aed935885f629614c84a6b825a22ed212ae54a4213ea2ff626fd904d261507639ab0cde87d20ad22e27fea26df31ddb6` |
| TLSH | `T18DF13356BAEBCD73CCAD233907678714337588D2AF42AB13511C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtQPWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/744OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_c6504ab6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6504ab6ba9ab6453092ac9da059559b4dde092aae898cd1cbdd930c6e5fa2f1"
    family = "Mirai"
    file_name = "c6504ab6ba9ab645.bin"
    file_type = "elf"
    first_seen = "2026-10-19 01:26:02"
  condition:
    hash.sha256(0, filesize) == "c6504ab6ba9ab6453092ac9da059559b4dde092aae898cd1cbdd930c6e5fa2f1"
}
```

### Sample 45: `d0a8249c6dd019cd`

| Field | Value |
|---|---|
| SHA-256 | `d0a8249c6dd019cdbe2aff5d89d0188250ffa8496bb7d887ccf8897855c2dd2c` |
| Family label | `unknown` |
| File name | `d0a8249c6dd019cd.bin` |
| File type | `elf` |
| First seen | `2026-10-19 01:25:54` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac8d89b03b0f5b1c609db6cb8196dc86` |
| SHA-1 | `865fbbd202843c42f456db4a13ceb2f243bef119` |
| SHA-256 | `d0a8249c6dd019cdbe2aff5d89d0188250ffa8496bb7d887ccf8897855c2dd2c` |
| SHA3-384 | `7c00d3944b4e1dbca5c9f2b56b16545d4f4730cf3336552fae43a13ac064258ccad2f50e14775db1fe57d09e6ba5bdf7` |
| TLSH | `T160E14482BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AEC6D76BD5` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsKLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvvg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_d0a8249c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0a8249c6dd019cdbe2aff5d89d0188250ffa8496bb7d887ccf8897855c2dd2c"
    family = "unknown"
    file_name = "d0a8249c6dd019cd.bin"
    file_type = "elf"
    first_seen = "2026-10-19 01:25:54"
  condition:
    hash.sha256(0, filesize) == "d0a8249c6dd019cdbe2aff5d89d0188250ffa8496bb7d887ccf8897855c2dd2c"
}
```

### Sample 46: `1ec4a6bdc648657e`

| Field | Value |
|---|---|
| SHA-256 | `1ec4a6bdc648657e80fe7ad8a7f6e70e65d0b647b6eca9bb87383f1ad3c7285f` |
| Family label | `Mirai` |
| File name | `1ec4a6bdc648657e.bin` |
| File type | `elf` |
| First seen | `2026-10-19 01:25:45` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `201c7accfb63a8d6c3fd1fd18eef3dd3` |
| SHA-1 | `1c0f7520e95e4624c37b440e0efa8ffd3be5caf6` |
| SHA-256 | `1ec4a6bdc648657e80fe7ad8a7f6e70e65d0b647b6eca9bb87383f1ad3c7285f` |
| SHA3-384 | `2d2c2ade6c09929f6827db919254133bf11c50528409d878828e958a45f1aa724a78fd1e43fce8248854e9f6552857e3` |
| TLSH | `T180E15207E2D5CE72D8CD133846935749213AC86EAB83EF03650C599AEE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFd146Kwz7cSym4S2ofahbpZiQ:fsue7cUJlFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_1ec4a6bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ec4a6bdc648657e80fe7ad8a7f6e70e65d0b647b6eca9bb87383f1ad3c7285f"
    family = "Mirai"
    file_name = "1ec4a6bdc648657e.bin"
    file_type = "elf"
    first_seen = "2026-10-19 01:25:45"
  condition:
    hash.sha256(0, filesize) == "1ec4a6bdc648657e80fe7ad8a7f6e70e65d0b647b6eca9bb87383f1ad3c7285f"
}
```

### Sample 47: `b7e5ba1d34071824`

| Field | Value |
|---|---|
| SHA-256 | `b7e5ba1d340718247c4fa0bb1705cbb63ff875edad3baa81b62cd4d55e7676ce` |
| Family label | `unknown` |
| File name | `b7e5ba1d34071824.bin` |
| File type | `macho` |
| First seen | `2026-10-19 01:25:36` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5cc088057c2a77752d5e8c3b839d043` |
| SHA-1 | `86a3257e155fea62a5e80cced6a048db3048502e` |
| SHA-256 | `b7e5ba1d340718247c4fa0bb1705cbb63ff875edad3baa81b62cd4d55e7676ce` |
| SHA3-384 | `69fa70b3e204bbf681368f2c1802641682bae27fabc6eeaf5c9e8e88aa6444b9ffebc20353e7031b7eb3f7659340c506` |
| TLSH | `T191E23D43AB4C8965C26D42301AF71BC6A615F6B09EE16B875750C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvU0VZqDDt0TOTLZ0BbFw22HKk6XrMclSibFqAMcl:z4ZZXvvRVZMt0TO2bVa/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_b7e5ba1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7e5ba1d340718247c4fa0bb1705cbb63ff875edad3baa81b62cd4d55e7676ce"
    family = "unknown"
    file_name = "b7e5ba1d34071824.bin"
    file_type = "macho"
    first_seen = "2026-10-19 01:25:36"
  condition:
    hash.sha256(0, filesize) == "b7e5ba1d340718247c4fa0bb1705cbb63ff875edad3baa81b62cd4d55e7676ce"
}
```

### Sample 48: `1931e1ea251e762a`

| Field | Value |
|---|---|
| SHA-256 | `1931e1ea251e762ae6a9af8b4fdfc6ad84de26701c16d6b3028453b3690ebe76` |
| Family label | `unknown` |
| File name | `1931e1ea251e762a.bin` |
| File type | `macho` |
| First seen | `2026-10-19 01:25:27` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40c7f5464b13389ea8c55be7fe21683f` |
| SHA-1 | `402dc7a718dfaa84449a0d428e13f088afe8e0b3` |
| SHA-256 | `1931e1ea251e762ae6a9af8b4fdfc6ad84de26701c16d6b3028453b3690ebe76` |
| SHA3-384 | `5b60386bb91c8a2b8e2c2d0e332b36e43ef6de7e6c222c0c646da22c20bc05be50e72ec1454f8f22f9f930a74229f075` |
| TLSH | `T192E23D43AF4C8965C26D82301AF70BC6A615F5B09EE16B875350C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUqVZqDDt0TOTLZ0BbFw24HKk6XrMclSibFqAMcl:z4ZZXvvTVZMt0TO2bVI/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_1931e1ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1931e1ea251e762ae6a9af8b4fdfc6ad84de26701c16d6b3028453b3690ebe76"
    family = "unknown"
    file_name = "1931e1ea251e762a.bin"
    file_type = "macho"
    first_seen = "2026-10-19 01:25:27"
  condition:
    hash.sha256(0, filesize) == "1931e1ea251e762ae6a9af8b4fdfc6ad84de26701c16d6b3028453b3690ebe76"
}
```

### Sample 49: `131479d9f3e5946b`

| Field | Value |
|---|---|
| SHA-256 | `131479d9f3e5946bea46578ad2356ce60b507d406c844aa36f9470610a979354` |
| Family label | `Mirai` |
| File name | `131479d9f3e5946bea46578ad2356ce60b507d406c844aa36f9470610a979354.elf` |
| File type | `elf` |
| First seen | `2026-10-19 01:11:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01878db0b5a3dc51577f02e0edbe64ea` |
| SHA-1 | `0db6834fad54a59f5b268912d13c64d1a71d9a79` |
| SHA-256 | `131479d9f3e5946bea46578ad2356ce60b507d406c844aa36f9470610a979354` |
| SHA3-384 | `d884f89e3dbe4313b457b4ef55501db492338c4f9e326bbcef5abc3baa44c927ba81e284036175def7c98cc595376ef6` |
| TLSH | `T149938EC1A243E4F1ED590274203AF337A632D9B91128FEE7FB54A732A461991B14BF4D` |
| TELFHASH | `t19831e1f41a391df49bc09801b24e6721be1da77b256476a309a36935312ed83937bc3d` |
| SSDEEP | `1536:HuWetiFLq2QcxgsrgREEXXzfsxddjZSqg/ds96S0OZeTMy+WqJXMufNv2rici5:HMck2QYgsrELnz0xddjZSqg/ds90OZeY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_131479d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "131479d9f3e5946bea46578ad2356ce60b507d406c844aa36f9470610a979354"
    family = "Mirai"
    file_name = "131479d9f3e5946bea46578ad2356ce60b507d406c844aa36f9470610a979354.elf"
    file_type = "elf"
    first_seen = "2026-10-19 01:11:33"
  condition:
    hash.sha256(0, filesize) == "131479d9f3e5946bea46578ad2356ce60b507d406c844aa36f9470610a979354"
}
```

### Sample 50: `49a73e2e4621af6e`

| Field | Value |
|---|---|
| SHA-256 | `49a73e2e4621af6e6a2f6c3ba3e5a1380cab49a21d89c501659eb7f6188a5483` |
| Family label | `VShell` |
| File name | `2ffcc2cd369d9b59752154520fc6bf2b.exe` |
| File type | `exe` |
| First seen | `2026-10-19 01:10:31` |
| Reporter | `abuse_ch` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ffcc2cd369d9b59752154520fc6bf2b` |
| SHA-1 | `d97caf60fa136f4821b56013881b7a3137864ebb` |
| SHA-256 | `49a73e2e4621af6e6a2f6c3ba3e5a1380cab49a21d89c501659eb7f6188a5483` |
| SHA3-384 | `8dc6d5b339bc31e189fb2ae532b2c94fd81d344e0976533cd85e375d2a9a59f6912b74eb170c2056aaef4c23a7bb746a` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T12D71B541605456F2D94CA37F8587B8A5FD4EB248A2C80B0F0798981A3F7607BB0DD613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6D65ZRjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6D65Zp++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_050_49a73e2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49a73e2e4621af6e6a2f6c3ba3e5a1380cab49a21d89c501659eb7f6188a5483"
    family = "VShell"
    file_name = "2ffcc2cd369d9b59752154520fc6bf2b.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:31"
  condition:
    hash.sha256(0, filesize) == "49a73e2e4621af6e6a2f6c3ba3e5a1380cab49a21d89c501659eb7f6188a5483"
}
```

### Sample 51: `251b4c120712ffab`

| Field | Value |
|---|---|
| SHA-256 | `251b4c120712ffab8d4dffd968d3657ae6e7bc698593b726af2f415d1867578f` |
| Family label | `VShell` |
| File name | `0e1d1d6b59447eff7fe7619284a4b298.exe` |
| File type | `exe` |
| First seen | `2026-10-19 01:10:27` |
| Reporter | `abuse_ch` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e1d1d6b59447eff7fe7619284a4b298` |
| SHA-1 | `16893e1f487bfdf3fddd5ccc2815e7b3e82caeba` |
| SHA-256 | `251b4c120712ffab8d4dffd968d3657ae6e7bc698593b726af2f415d1867578f` |
| SHA3-384 | `0ce85daece0bea118d01bc0400077129d3921567de7a78c26befac8158408fe7c00b3a72ff130f9b0a28fb3d18d53bd5` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1D271A341605016F2D94DA37F8487B8A5FD8EB248A2C80B0B0798E81A2F7207BB0DA613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DQ1jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DQl++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_051_251b4c12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "251b4c120712ffab8d4dffd968d3657ae6e7bc698593b726af2f415d1867578f"
    family = "VShell"
    file_name = "0e1d1d6b59447eff7fe7619284a4b298.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:27"
  condition:
    hash.sha256(0, filesize) == "251b4c120712ffab8d4dffd968d3657ae6e7bc698593b726af2f415d1867578f"
}
```

### Sample 52: `fd240746ebef01cd`

| Field | Value |
|---|---|
| SHA-256 | `fd240746ebef01cd378b4ffea19cdf139d44960caf41f88dce4bbab8faceb7d7` |
| Family label | `RemusStealer` |
| File name | `398fab919e699bc954eb11db12962965.exe` |
| File type | `exe` |
| First seen | `2026-10-19 01:10:23` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `398fab919e699bc954eb11db12962965` |
| SHA-1 | `c01a270056ee845acdec349dc026ac7c9b5ed44b` |
| SHA-256 | `fd240746ebef01cd378b4ffea19cdf139d44960caf41f88dce4bbab8faceb7d7` |
| SHA3-384 | `3f6e70e971923b07c857c656628f34821c3dc9359343e7c5e331bd460e395c8857246fcd5010d26bb02e20212850cd4b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T127165B63AAA041F4C1779A34CA674662B631BC5C973133E71D81BA346F3ABD06F7A305` |
| SSDEEP | `49152:I2MS/0G4UkGV2JlLJc/fIJdh8Lfbqbvy28:I2AUoJNJUfIHcWjj8` |
| ICON-DHASH | `f0c0f0f0f0f0c8e0` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_052_fd240746
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd240746ebef01cd378b4ffea19cdf139d44960caf41f88dce4bbab8faceb7d7"
    family = "RemusStealer"
    file_name = "398fab919e699bc954eb11db12962965.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:23"
  condition:
    hash.sha256(0, filesize) == "fd240746ebef01cd378b4ffea19cdf139d44960caf41f88dce4bbab8faceb7d7"
}
```

### Sample 53: `4421ccd153aa864e`

| Field | Value |
|---|---|
| SHA-256 | `4421ccd153aa864e3eb4ac89044c92eba48a1ecca7efc759203368004a7ded05` |
| Family label | `ValleyRAT` |
| File name | `3D07FA7F9489DD52A1DCA5811C000096.exe` |
| File type | `exe` |
| First seen | `2026-10-19 01:10:16` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d07fa7f9489dd52a1dca5811c000096` |
| SHA-1 | `bb6f65e29e6b6148c5ebb775dca524e9301d6743` |
| SHA-256 | `4421ccd153aa864e3eb4ac89044c92eba48a1ecca7efc759203368004a7ded05` |
| SHA3-384 | `3964d7702936821b156da16de545ba0cd462e2ea3140c3e18b32a1d55ec6bba8c99515f7f77fffcc9052bf09dfb18f27` |
| IMPHASH | `0c8e7f86aa98fbe0072e66319fe8d685` |
| TLSH | `T103B37C217290C032D0A3253198F9DBB24E7EF931077855CBF7E41ABA9F607C16A7539A` |
| SSDEEP | `3072:xFRPE2Utdrqfi1EcSxiu2TuNcVXEPKeo9:xFRPENdrqfkSxicDyeo9` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_053_4421ccd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4421ccd153aa864e3eb4ac89044c92eba48a1ecca7efc759203368004a7ded05"
    family = "ValleyRAT"
    file_name = "3D07FA7F9489DD52A1DCA5811C000096.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:16"
  condition:
    hash.sha256(0, filesize) == "4421ccd153aa864e3eb4ac89044c92eba48a1ecca7efc759203368004a7ded05"
}
```

### Sample 54: `8bf1aefe99486ba2`

| Field | Value |
|---|---|
| SHA-256 | `8bf1aefe99486ba24e1bce15035046809d9af0d8d98e0b58c23c38456749b09e` |
| Family label | `ValleyRAT` |
| File name | `09e226a3ade6b9d479d1b19b1d534dcb.exe` |
| File type | `exe` |
| First seen | `2026-10-19 01:10:11` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09e226a3ade6b9d479d1b19b1d534dcb` |
| SHA-1 | `cb23964b74a20f30354f66bc2715f0f122d92e62` |
| SHA-256 | `8bf1aefe99486ba24e1bce15035046809d9af0d8d98e0b58c23c38456749b09e` |
| SHA3-384 | `ce6028073d232674544e1d23652250c6588ca21c47147218ee69ae0cf8009223bbaef251757a880cfd147155c6e14af3` |
| IMPHASH | `e975e3210d4eff6a558b0692075ca5b9` |
| TLSH | `T1C846AF828F4B89E4B115D63BCB67322394F03CD85338EDF7BBA8460A2354B5A463D55E` |
| SSDEEP | `98304:NHgki/kxPSUnWCOhpzViXhKVlgTaFlGtd5mhIkP:htakxPSiW73i+lgT8E7m2W` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_054_8bf1aefe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bf1aefe99486ba24e1bce15035046809d9af0d8d98e0b58c23c38456749b09e"
    family = "ValleyRAT"
    file_name = "09e226a3ade6b9d479d1b19b1d534dcb.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:11"
  condition:
    hash.sha256(0, filesize) == "8bf1aefe99486ba24e1bce15035046809d9af0d8d98e0b58c23c38456749b09e"
}
```

### Sample 55: `6b39054cd0facc18`

| Field | Value |
|---|---|
| SHA-256 | `6b39054cd0facc18c46cf4ad3bdab92072a34933fab5cf67adefeb787e78b11c` |
| Family label | `njrat` |
| File name | `08637a5f2fb2789dd0f9e3f186001bed.exe` |
| File type | `exe` |
| First seen | `2026-10-19 01:10:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08637a5f2fb2789dd0f9e3f186001bed` |
| SHA-1 | `db71dc60a407bce99680fe4228bca26d90695dfb` |
| SHA-256 | `6b39054cd0facc18c46cf4ad3bdab92072a34933fab5cf67adefeb787e78b11c` |
| SHA3-384 | `db7df15d892e055a4a9fba5e18f6527af63390d8613305c4948954f55904baf0cc5aa04eb77737908bc7d8ae0a5b4c2c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CC13E74CB694E175D5FF8BF0B4A1B2890B70A01BA906930F99F114D98FB3EC09611EE7` |
| SSDEEP | `384:lHZyGssV6LkcyG29EfOmwVE3pOhC0pf/pqzkIij+ZsNO3PlpJKkkjh/TzF7pWn90:l5xtsYZGEEfiWpuLf/uuXQ/oYC+L` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_055_6b39054c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b39054cd0facc18c46cf4ad3bdab92072a34933fab5cf67adefeb787e78b11c"
    family = "njrat"
    file_name = "08637a5f2fb2789dd0f9e3f186001bed.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:06"
  condition:
    hash.sha256(0, filesize) == "6b39054cd0facc18c46cf4ad3bdab92072a34933fab5cf67adefeb787e78b11c"
}
```

### Sample 56: `90003d7c7be95da3`

| Field | Value |
|---|---|
| SHA-256 | `90003d7c7be95da3a2d5a6160f71c3fb2fe3a463c2419345fc7fc7081d06a380` |
| Family label | `unknown` |
| File name | `bot_ppc64` |
| File type | `elf` |
| First seen | `2026-10-19 00:55:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98d75ee0e5cd286f215d9fbb57d750f7` |
| SHA-1 | `2a1ffb3c511c44c6cb00da55a8e14cc51bb16bda` |
| SHA-256 | `90003d7c7be95da3a2d5a6160f71c3fb2fe3a463c2419345fc7fc7081d06a380` |
| SHA3-384 | `aa863cbd264c65e3af88fd2c8a5f7991ff946249575bfda957088e685d54093c6113b2dc271d67a7172fc99c1944a04f` |
| TLSH | `T1FC264CC0B708D139DA5F0B7249638B6463617D46C1E0896FB30AF76F06B16E66A0FED4` |
| GIMPHASH | `185c04963b05cae8e4b3efc14a63292022c46da9a09303585da55a4db61f8ab4` |
| SSDEEP | `49152:t1uI7DJlr5FiEgUfam7WGSKlMoN7luLGiV:twI7DJl9FiEgUfaWWXKlxBi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_90003d7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90003d7c7be95da3a2d5a6160f71c3fb2fe3a463c2419345fc7fc7081d06a380"
    family = "unknown"
    file_name = "bot_ppc64"
    file_type = "elf"
    first_seen = "2026-10-19 00:55:35"
  condition:
    hash.sha256(0, filesize) == "90003d7c7be95da3a2d5a6160f71c3fb2fe3a463c2419345fc7fc7081d06a380"
}
```

### Sample 57: `ca82f79b9262ed0d`

| Field | Value |
|---|---|
| SHA-256 | `ca82f79b9262ed0d97bd262afdb1cac993ef52eb478512c5659cc240fefb562b` |
| Family label | `unknown` |
| File name | `ADNOC ContractorVendorSuppliers' Enrollment For The 20262027 Projects.vbs` |
| File type | `vbs` |
| First seen | `2026-10-19 00:50:40` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91bcdde43d2be7fbcbcf87d10dc64bd0` |
| SHA-1 | `6afdc3d72d1f5ae64e54ba4b8435d36b4db0bb29` |
| SHA-256 | `ca82f79b9262ed0d97bd262afdb1cac993ef52eb478512c5659cc240fefb562b` |
| SHA3-384 | `cf7bbdcb6452e5516b1620b0e34fbd12caa24c839c7cce10d243a7b3c87a6a8890bdc5e6a0daa4d01daa5ff11f057de5` |
| TLSH | `T1DF749DE15F852A018F25EB97CEA8897E53C02F32A2D06C70DDD609DC2128F59A1DFBD5` |
| SSDEEP | `1536:AsXsYQYanWwOU7i/+UPxsSjD0OmpPD1IXhpsC5:AUsZoF+U5sQDrKGhaA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_ca82f79b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca82f79b9262ed0d97bd262afdb1cac993ef52eb478512c5659cc240fefb562b"
    family = "unknown"
    file_name = "ADNOC ContractorVendorSuppliers' Enrollment For The 20262027 Projects.vbs"
    file_type = "vbs"
    first_seen = "2026-10-19 00:50:40"
  condition:
    hash.sha256(0, filesize) == "ca82f79b9262ed0d97bd262afdb1cac993ef52eb478512c5659cc240fefb562b"
}
```

### Sample 58: `3f7089c857d85f2e`

| Field | Value |
|---|---|
| SHA-256 | `3f7089c857d85f2e3f7d9d2f5788649e4e3520d3fd575000b1d1e8db9022c263` |
| Family label | `unknown` |
| File name | `MV S-BREEZE VESSEL PARTICULARS.js` |
| File type | `js` |
| First seen | `2026-10-19 00:38:43` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1a9ec5ad063979741973a296215631f` |
| SHA-1 | `4520763b1cca5e75ff51c84e09519bf1085c5d8e` |
| SHA-256 | `3f7089c857d85f2e3f7d9d2f5788649e4e3520d3fd575000b1d1e8db9022c263` |
| SHA3-384 | `3874ec38b0ba832d435fa356740b332bb1b04957c449e24b41d28f40cf3fe7deb32aaafb304d4d63baeba0be1407b07b` |
| TLSH | `T1D62502179605EF4B8E50293F6F450D46B917A80B97CDEAC234CD8A3EE39DF5C182C266` |
| SSDEEP | `24576:GQkDeGeF92CHHZFsLUU7g9M/2jR77qrdsBOSYX:PjZEPC5FJ2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_3f7089c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f7089c857d85f2e3f7d9d2f5788649e4e3520d3fd575000b1d1e8db9022c263"
    family = "unknown"
    file_name = "MV S-BREEZE VESSEL PARTICULARS.js"
    file_type = "js"
    first_seen = "2026-10-19 00:38:43"
  condition:
    hash.sha256(0, filesize) == "3f7089c857d85f2e3f7d9d2f5788649e4e3520d3fd575000b1d1e8db9022c263"
}
```

### Sample 59: `70c5abd20b484a76`

| Field | Value |
|---|---|
| SHA-256 | `70c5abd20b484a7691fcc7188c1ad2f970ee6c426897a346f0f10f68a6666b20` |
| Family label | `unknown` |
| File name | `70c5abd20b484a76.bin` |
| File type | `macho` |
| First seen | `2026-10-19 00:26:18` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d9f795066bd674969bda1e11915c1ac` |
| SHA-1 | `1cb7ac8e68f808e8975ad6e68bb2c051846b1fa5` |
| SHA-256 | `70c5abd20b484a7691fcc7188c1ad2f970ee6c426897a346f0f10f68a6666b20` |
| SHA3-384 | `46fc039fff3b752687f42e0f7a682bd8c8e6cebd895e0ac54dafdc4f8b03d158e3345cbb43d10c74387397a9c9ab0651` |
| TLSH | `T13EF25F139B1C0A61C45C633C92BB1B026236F5D086C56B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRHPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfelilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_70c5abd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70c5abd20b484a7691fcc7188c1ad2f970ee6c426897a346f0f10f68a6666b20"
    family = "unknown"
    file_name = "70c5abd20b484a76.bin"
    file_type = "macho"
    first_seen = "2026-10-19 00:26:18"
  condition:
    hash.sha256(0, filesize) == "70c5abd20b484a7691fcc7188c1ad2f970ee6c426897a346f0f10f68a6666b20"
}
```

### Sample 60: `ce6978f97f4fec24`

| Field | Value |
|---|---|
| SHA-256 | `ce6978f97f4fec247c87d9a0323891169ca645c6602e0c969ba48fdf53895a8a` |
| Family label | `unknown` |
| File name | `ce6978f97f4fec24.bin` |
| File type | `macho` |
| First seen | `2026-10-19 00:26:11` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a0d077258680b66c2a7a7a73fc36fdb` |
| SHA-1 | `654fdaa9652f87f067a44f9f510407540d438c77` |
| SHA-256 | `ce6978f97f4fec247c87d9a0323891169ca645c6602e0c969ba48fdf53895a8a` |
| SHA3-384 | `6f457052c5dc1ed52f37f7d4b1711be89e5512f75f447c60247980f02157f79ccdfb5da8507c69e1b2d3b2835fdeb800` |
| TLSH | `T19AE22E43AB4C8965C26D52301AF71BC6A615F5B09EE16B875750C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUsVZqDDt0TOTLZ0BbFw20HKk6XrMclSibFqAMcl:z4ZZXvvNVZMt0TO2bVc/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_ce6978f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce6978f97f4fec247c87d9a0323891169ca645c6602e0c969ba48fdf53895a8a"
    family = "unknown"
    file_name = "ce6978f97f4fec24.bin"
    file_type = "macho"
    first_seen = "2026-10-19 00:26:11"
  condition:
    hash.sha256(0, filesize) == "ce6978f97f4fec247c87d9a0323891169ca645c6602e0c969ba48fdf53895a8a"
}
```

### Sample 61: `9f6ac6b4abb82120`

| Field | Value |
|---|---|
| SHA-256 | `9f6ac6b4abb82120b339a282ac8cdd5f49c4ef25d10d608f3bd02963201af665` |
| Family label | `unknown` |
| File name | `9f6ac6b4abb82120.bin` |
| File type | `elf` |
| First seen | `2026-10-19 00:26:03` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbc361b1bdbb929cbdd72f95f6941b98` |
| SHA-1 | `c87413858ef06a60fe21a8b03507871c871f4c32` |
| SHA-256 | `9f6ac6b4abb82120b339a282ac8cdd5f49c4ef25d10d608f3bd02963201af665` |
| SHA3-384 | `8a93632c0120e6ef61864f6f7daec31b261c1b9db2acf2876361d5d0e63aeaf8f4a22ebb0f893d5c6947c156ecbd5763` |
| TLSH | `T10522EC17F3E5DDFFC8AA577409A313703223C836DB428783680C46543FAB29E6EA5684` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMOWtsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dxWtsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_9f6ac6b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f6ac6b4abb82120b339a282ac8cdd5f49c4ef25d10d608f3bd02963201af665"
    family = "unknown"
    file_name = "9f6ac6b4abb82120.bin"
    file_type = "elf"
    first_seen = "2026-10-19 00:26:03"
  condition:
    hash.sha256(0, filesize) == "9f6ac6b4abb82120b339a282ac8cdd5f49c4ef25d10d608f3bd02963201af665"
}
```

### Sample 62: `d3a26db9b714a3b5`

| Field | Value |
|---|---|
| SHA-256 | `d3a26db9b714a3b54c5a7aea6bef5ad93312e03d1fc120e637b4f228ec8dacc4` |
| Family label | `Snowlight` |
| File name | `d3a26db9b714a3b5.bin` |
| File type | `elf` |
| First seen | `2026-10-19 00:25:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight, vshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2610a8c3d062000126cb2295d3624363` |
| SHA-1 | `63b67caf2cca1a3e98c1fd44d8f50c35525206aa` |
| SHA-256 | `d3a26db9b714a3b54c5a7aea6bef5ad93312e03d1fc120e637b4f228ec8dacc4` |
| SHA3-384 | `64ccbeada15f2055aef59ffc6009f1bce920fb01682fa30ebd0f9aed2d478700e434faf6aac0032effa6b38628aa447e` |
| TLSH | `T11EE16017E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3AJheuhill5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbwJhAlZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_062_d3a26db9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3a26db9b714a3b54c5a7aea6bef5ad93312e03d1fc120e637b4f228ec8dacc4"
    family = "Snowlight"
    file_name = "d3a26db9b714a3b5.bin"
    file_type = "elf"
    first_seen = "2026-10-19 00:25:55"
  condition:
    hash.sha256(0, filesize) == "d3a26db9b714a3b54c5a7aea6bef5ad93312e03d1fc120e637b4f228ec8dacc4"
}
```

### Sample 63: `b116aefeb274d95f`

| Field | Value |
|---|---|
| SHA-256 | `b116aefeb274d95fdd609567f73885e39621a2c72d9b10eb271c1f3a29389f08` |
| Family label | `Snowlight` |
| File name | `b116aefeb274d95f.bin` |
| File type | `elf` |
| First seen | `2026-10-19 00:25:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight, vshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74aba272c28332473f009fdbf8a87467` |
| SHA-1 | `76c2c36e8df9b8bcb98718e3dfd52df812f3aa5c` |
| SHA-256 | `b116aefeb274d95fdd609567f73885e39621a2c72d9b10eb271c1f3a29389f08` |
| SHA3-384 | `0b1b691198579fc4993c54c945aba1b4eb8cb39c0e731f853420d581047f5b505abbc538ccbc4bdce885cf4299a1141f` |
| TLSH | `T169124047A2D0CE3FC8D953384467122472B394BEDF629713064915B63F427E81E2EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6ZH5ML09V1J9G8Ym6O+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWH6ZMWT1YmMhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_063_b116aefe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b116aefeb274d95fdd609567f73885e39621a2c72d9b10eb271c1f3a29389f08"
    family = "Snowlight"
    file_name = "b116aefeb274d95f.bin"
    file_type = "elf"
    first_seen = "2026-10-19 00:25:47"
  condition:
    hash.sha256(0, filesize) == "b116aefeb274d95fdd609567f73885e39621a2c72d9b10eb271c1f3a29389f08"
}
```

### Sample 64: `423dc680eb304393`

| Field | Value |
|---|---|
| SHA-256 | `423dc680eb30439391632cf05fde7dbc6d81f31e382454989051cd04e51705d1` |
| Family label | `WannaCry` |
| File name | `423dc680eb30439391632cf05fde7dbc6d81f31e382454989051cd04e51705d1` |
| File type | `exe` |
| First seen | `2026-10-19 00:15:08` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `644c7dc1ba482e63029c226100429eaa` |
| SHA-1 | `80e0874f018150b0ebacc57268f2f89efb6755cf` |
| SHA-256 | `423dc680eb30439391632cf05fde7dbc6d81f31e382454989051cd04e51705d1` |
| SHA3-384 | `0843a84f469533089ca0c924eb3a8825c8457081c59adc636cf1297b2a7f1e9fbca2e55bee6452707a669505c405ca1c` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T16336221932AC80BCD11B6274A4B38E26A3B37C56227D870F9B9487661D13790FF78B57` |
| SSDEEP | `24576:jbLg3bLgddQhfdmMSirYbcMNgef0QeQjG/:jn2nAQqMSPbcBVQej/` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_064_423dc680
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "423dc680eb30439391632cf05fde7dbc6d81f31e382454989051cd04e51705d1"
    family = "WannaCry"
    file_name = "423dc680eb30439391632cf05fde7dbc6d81f31e382454989051cd04e51705d1"
    file_type = "exe"
    first_seen = "2026-10-19 00:15:08"
  condition:
    hash.sha256(0, filesize) == "423dc680eb30439391632cf05fde7dbc6d81f31e382454989051cd04e51705d1"
}
```

### Sample 65: `86788ddca0dcb082`

| Field | Value |
|---|---|
| SHA-256 | `86788ddca0dcb082532fcf7bdbac3486a57c277fe64447fc1a42d5ccd6101332` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-19 00:13:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `512f5fb5803a7f3c1067612d84f3eec3` |
| SHA-1 | `af2685bf576c815514879aac58d065f19083bcbf` |
| SHA-256 | `86788ddca0dcb082532fcf7bdbac3486a57c277fe64447fc1a42d5ccd6101332` |
| SHA3-384 | `1bdf61a5f2a9e3c6b46c2d123658ef7885db3c527bc426b1d4b542e8b30dc08b5155cbe44d81ed222cbd1a77f1cf1393` |
| TLSH | `T18A04881E2F228F6EF668873147B74925A76C23D627E1D684D1ACC1106F6039E641FFE8` |
| TELFHASH | `t1d7416e180e7817a0a3396d5d159cff7b96a720db7f172c278e61e86aab68a435d10c0c` |
| SSDEEP | `1536:rT2q/a+RaFyL3tqg1GbUKAOOf0XPdG3SqnZkBp+eRDDV+7apHTaJGY/e4gxj6e:v3aoaoLdMFXPdkSOZkrPDDV5e42e4gNX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_86788ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86788ddca0dcb082532fcf7bdbac3486a57c277fe64447fc1a42d5ccd6101332"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-19 00:13:44"
  condition:
    hash.sha256(0, filesize) == "86788ddca0dcb082532fcf7bdbac3486a57c277fe64447fc1a42d5ccd6101332"
}
```

### Sample 66: `0119e2bc22813791`

| Field | Value |
|---|---|
| SHA-256 | `0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f` |
| Family label | `AMOS` |
| File name | `macho_0119e2bc2281.bin` |
| File type | `macho` |
| First seen | `2026-10-19 00:09:42` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e13cb75e45b5ddea87ac24bbd7866c94` |
| SHA-1 | `a2d5d7d783d6535613785c94c3e88890d0c72798` |
| SHA-256 | `0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f` |
| SHA3-384 | `9d53957b8e2d528f6aedacd98a7ca94eee2702a720dc0a61796f256d90fbe6ef04265711d47e388814d32c79c9e31801` |
| TLSH | `T1C985F168572A126BDB7931738C300FDA50A0A981DAD8A7EDAB24CF167F35713B573312` |
| SSDEEP | `49152:BqFhEPkIFPZbOSLLtkc8vUsCtAlO61BL/E1:B78csC5` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_066_0119e2bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f"
    family = "AMOS"
    file_name = "macho_0119e2bc2281.bin"
    file_type = "macho"
    first_seen = "2026-10-19 00:09:42"
  condition:
    hash.sha256(0, filesize) == "0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f"
}
```

### Sample 67: `ff9c8f57fa3ec4c9`

| Field | Value |
|---|---|
| SHA-256 | `ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598` |
| Family label | `AMOS` |
| File name | `macho_ff9c8f57fa3e.bin` |
| File type | `macho` |
| First seen | `2026-10-19 00:04:52` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2592299ed996606a84f8e51ef06e215` |
| SHA-1 | `70b9fe56b60c8d01d6a156f3daa3eafd20d0fe2c` |
| SHA-256 | `ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598` |
| SHA3-384 | `d05e605e9db277e339848702757bc3c404301d0035e0e494b30ea8c4269598ed58f5e07b6e063afeff50660f1421f695` |
| TLSH | `T14C95F1F42276616CE80227F3F4100BD45AA067B16E0D76EA2B21E7617D35BD3AD62733` |
| SSDEEP | `49152:oE65tqy/XMYQA+ebGxEa+L02Mp8unpi6gkkeF:qrq9gL2` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_067_ff9c8f57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598"
    family = "AMOS"
    file_name = "macho_ff9c8f57fa3e.bin"
    file_type = "macho"
    first_seen = "2026-10-19 00:04:52"
  condition:
    hash.sha256(0, filesize) == "ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598"
}
```

### Sample 68: `6261cf6d60051c55`

| Field | Value |
|---|---|
| SHA-256 | `6261cf6d60051c557b8e09a6f8e7ac9fa0199c487df72c5492baf96b3802aead` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-10-19 00:00:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33a50b96e00287b83c667d6950f675c4` |
| SHA-1 | `bd0578e4110e5df7c49164097523ec818975a74b` |
| SHA-256 | `6261cf6d60051c557b8e09a6f8e7ac9fa0199c487df72c5492baf96b3802aead` |
| SHA3-384 | `85eec14593feeb0f65bab1395a7e9bf84363ebb2258198bc8fbae4f47107363b7c98d4e5017e82e5e6b5987a546a094c` |
| TLSH | `T1D204C816AB610FFBDCAFDD3706E9070139CCA50B22A53B763674D528F54A50B4AE3C68` |
| SSDEEP | `1536:FyydDIljrs4iPs7L5i6twNwvCSA8+QpKDBPvhXBDUWetJZWAsbVJ4obvexnlJfxF:gy1ujrDLP8ACbRDyJShbvClGQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_6261cf6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6261cf6d60051c557b8e09a6f8e7ac9fa0199c487df72c5492baf96b3802aead"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-19 00:00:59"
  condition:
    hash.sha256(0, filesize) == "6261cf6d60051c557b8e09a6f8e7ac9fa0199c487df72c5492baf96b3802aead"
}
```

### Sample 69: `1410244e815eabf7`

| Field | Value |
|---|---|
| SHA-256 | `1410244e815eabf714a977ab9b20372c270046ec5bd90c8e05e94bf62386d9b5` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-18 23:54:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a981f8e5e92e62a95ae400ad4b661469` |
| SHA-1 | `59ded0f3faef7e8075e3383180e294b4a318456f` |
| SHA-256 | `1410244e815eabf714a977ab9b20372c270046ec5bd90c8e05e94bf62386d9b5` |
| SHA3-384 | `ee792454d1a6b09bb4c5aed455d9bbaf70311e64b0417bd9909a810dc9abdd5e2e3f6cdfa19834b1c31b792d198264f6` |
| TLSH | `T1E1E33C55F880EF66CAD0767FFB9E428C335307B8D2EA7002CD249B2467DA5594F3A942` |
| TELFHASH | `t156d0a79bcfc009ec978515155587256a0d9a39d807021982cb04268e475c5c0b427672` |
| SSDEEP | `3072:ouNCp8iWE6/rv4r3CtUFbYcQrjBk2TFoGoB98TOUIhpM:ougZWE6zVUFbYc+ZoGoB98TFyu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_1410244e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1410244e815eabf714a977ab9b20372c270046ec5bd90c8e05e94bf62386d9b5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-18 23:54:15"
  condition:
    hash.sha256(0, filesize) == "1410244e815eabf714a977ab9b20372c270046ec5bd90c8e05e94bf62386d9b5"
}
```

### Sample 70: `3ed85e9cd1b68ad5`

| Field | Value |
|---|---|
| SHA-256 | `3ed85e9cd1b68ad525101e63ab867fc5b3a31e195b88ef82b7a1096bdde68841` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-18 23:51:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25cb431f0e6f0fc379e25ef9a46c9650` |
| SHA-1 | `661982633d2d10cc3920a4a93118b6900f09e4b3` |
| SHA-256 | `3ed85e9cd1b68ad525101e63ab867fc5b3a31e195b88ef82b7a1096bdde68841` |
| SHA3-384 | `52f44670cd81d59e39212d31e377aa8046a86f77ec9fb3fb7041fd8f27b7e21515387f9f858df9eb68edbd1c9aa5bfb9` |
| TLSH | `T12004881E6E228F6DF668873147B74D25A76C23DA27E1D684D1ACC1106F2039E641FFE8` |
| TELFHASH | `t1d7416e180e7817a0a3396d5d159cff7b96a720db7f172c278e61e86aab68a435d10c0c` |
| SSDEEP | `3072:u3aoa4LOANPeQTqOO5DK0SjXsXYjh1Ki/KT/////b:uqPIOANfNO4XDjhUi/KT/////b` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_3ed85e9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ed85e9cd1b68ad525101e63ab867fc5b3a31e195b88ef82b7a1096bdde68841"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-18 23:51:10"
  condition:
    hash.sha256(0, filesize) == "3ed85e9cd1b68ad525101e63ab867fc5b3a31e195b88ef82b7a1096bdde68841"
}
```

### Sample 71: `671574f7454bbe4c`

| Field | Value |
|---|---|
| SHA-256 | `671574f7454bbe4cc277d9caa4c513d2ccc11073f46f9a3f5998136fe0ef9927` |
| Family label | `Mirai` |
| File name | `dissmips` |
| File type | `elf` |
| First seen | `2026-10-18 23:51:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `824030ebcbf96028e739c75313de460f` |
| SHA-1 | `380dacd3ed8d825de223380589261fe07e34433b` |
| SHA-256 | `671574f7454bbe4cc277d9caa4c513d2ccc11073f46f9a3f5998136fe0ef9927` |
| SHA3-384 | `0cc597ff77e6281bbf7f7b57bd92408ff01563a24d644452f476f46aa1a376a636fa25f15db1bf6f765e1bb0ddaefdd6` |
| TLSH | `T10C44C62A6D719B7DF27AE33487B74A20A76C63D61BA1D582C17CC0105E7025E681FBBC` |
| TELFHASH | `t16a4162580a7817f0a3386c5d05ddfb76d6a730df7e166c238f11e86aab69a839d11c0c` |
| SSDEEP | `3072:b7jjGR3Gu1mE8kmymVduMxEb3i+ARoKTIMlTgxY1gFSGFjO6jwF:b7jji3p1mNdBkSQklRO0GFjhwF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_671574f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "671574f7454bbe4cc277d9caa4c513d2ccc11073f46f9a3f5998136fe0ef9927"
    family = "Mirai"
    file_name = "dissmips"
    file_type = "elf"
    first_seen = "2026-10-18 23:51:08"
  condition:
    hash.sha256(0, filesize) == "671574f7454bbe4cc277d9caa4c513d2ccc11073f46f9a3f5998136fe0ef9927"
}
```

### Sample 72: `03e2f6194b0252b1`

| Field | Value |
|---|---|
| SHA-256 | `03e2f6194b0252b1e157f33a4f673973fbeab3a95604181fb0fcb064a815ba60` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-10-18 23:48:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79a9196dbc95af6aed19022a17ef10a5` |
| SHA-1 | `4b15613adab4cbaffe808b21a01b79c4ef49e413` |
| SHA-256 | `03e2f6194b0252b1e157f33a4f673973fbeab3a95604181fb0fcb064a815ba60` |
| SHA3-384 | `692abec948a1761e119ac8011a584926886f2d6267e1e2acfe440a063fd48ad4fae373e21c5ddc2c36dfed88a42dfd41` |
| TLSH | `T125442A43B7BD55A1CAE38F7421B107B9924DC1D76DF9F44CDA065EC2AA38070B26E386` |
| SSDEEP | `6144:3AIOUbRmtXbtBook80h9IJMuF9S4L9KceR:33Pwo5WmdceR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_03e2f619
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03e2f6194b0252b1e157f33a4f673973fbeab3a95604181fb0fcb064a815ba60"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-18 23:48:04"
  condition:
    hash.sha256(0, filesize) == "03e2f6194b0252b1e157f33a4f673973fbeab3a95604181fb0fcb064a815ba60"
}
```

### Sample 73: `93de911f3ec5cb14`

| Field | Value |
|---|---|
| SHA-256 | `93de911f3ec5cb14664ade2b7885b1d643ac951c564f1453e795eec9e3ba7129` |
| Family label | `unknown` |
| File name | `8yga71.sh` |
| File type | `sh` |
| First seen | `2026-10-18 23:44:58` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4872c80fb1ce261488ba682e7463269` |
| SHA-1 | `6b5ae7a2f9565eaad00ead344ec73f1dd360eabf` |
| SHA-256 | `93de911f3ec5cb14664ade2b7885b1d643ac951c564f1453e795eec9e3ba7129` |
| SHA3-384 | `e308b1dcd4938df240c8089ff97970d09e603201e7c8684cb795593e74b0b4c1282ed72a63cdd0cf469393047d04683e` |
| TLSH | `T11951BFDE6412E533A5AED8386A097D48490385870725EE1CBCCD38587FAACB0FD27B34` |
| SSDEEP | `48:HsKRDRM/Sco5whWrDztDz+ULN8swRQRfSjgVAhGiGlLIWCsuzmsezSs6zAsdzRsT:HsKBiqTamDhDCkxwq05GiG2W5qisYrHv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_93de911f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93de911f3ec5cb14664ade2b7885b1d643ac951c564f1453e795eec9e3ba7129"
    family = "unknown"
    file_name = "8yga71.sh"
    file_type = "sh"
    first_seen = "2026-10-18 23:44:58"
  condition:
    hash.sha256(0, filesize) == "93de911f3ec5cb14664ade2b7885b1d643ac951c564f1453e795eec9e3ba7129"
}
```

### Sample 74: `b5d4aba0fe4004e8`

| Field | Value |
|---|---|
| SHA-256 | `b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298` |
| Family label | `AMOS` |
| File name | `macho_b5d4aba0fe40.bin` |
| File type | `macho` |
| First seen | `2026-10-18 23:28:21` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `685da7c3ebba4f06f024aad8881e85e4` |
| SHA-1 | `0dffd0a0a2acda6b7ce4734baa052d541ce1a219` |
| SHA-256 | `b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298` |
| SHA3-384 | `7e48808bb67f76e5e156bf1d9b5afacf478657687c335a7a5824251a9ad906fca172a5b918a4b8eb5bc8cdf60211be7b` |
| TLSH | `T1CB95F1E0DF7B0267E44624BE9D044FF70550B6A2AE38B6F96E10D7022D359D7B1A3362` |
| SSDEEP | `49152:5bfOYbYctH17FIVPCJ2UWNXHVcom9C+0jjr68Vsv7K:5bfOIYqZ2pBm9C/Z` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_074_b5d4aba0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298"
    family = "AMOS"
    file_name = "macho_b5d4aba0fe40.bin"
    file_type = "macho"
    first_seen = "2026-10-18 23:28:21"
  condition:
    hash.sha256(0, filesize) == "b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298"
}
```

### Sample 75: `f108998292512b5e`

| Field | Value |
|---|---|
| SHA-256 | `f108998292512b5ec1ce20f5f67c15bacf337e53192e36c6f33c09dd4cd6abbd` |
| Family label | `AMOS` |
| File name | `stage1_f10899829251.zsh` |
| File type | `zsh` |
| First seen | `2026-10-18 23:28:15` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, macOS, zsh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `784b8fb5ff30f753bc123c4e63105d01` |
| SHA-1 | `83bec3a67a31c35c24b0877afa71497a90ba4c62` |
| SHA-256 | `f108998292512b5ec1ce20f5f67c15bacf337e53192e36c6f33c09dd4cd6abbd` |
| SHA3-384 | `d665d6d4d24819d01ba9b768458bc37dc4de63e0af053b8ffa11efaae6ab0c288178b2b491ec56a583f4e466cbc82669` |
| TLSH | `T14D512BA4ED08C476D6F12778998CBCB403DF38F98BE8316574821B8840BFB9A254F52D` |
| SSDEEP | `96:AL1raOWDKgxlYgsQQ9DCmOWXJJCj6+DYxiwFzCg+xTxGV:kWOgYgsQQZCmfAj6q9xMV` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `zsh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_075_f1089982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f108998292512b5ec1ce20f5f67c15bacf337e53192e36c6f33c09dd4cd6abbd"
    family = "AMOS"
    file_name = "stage1_f10899829251.zsh"
    file_type = "zsh"
    first_seen = "2026-10-18 23:28:15"
  condition:
    hash.sha256(0, filesize) == "f108998292512b5ec1ce20f5f67c15bacf337e53192e36c6f33c09dd4cd6abbd"
}
```

### Sample 76: `34b1590817537f05`

| Field | Value |
|---|---|
| SHA-256 | `34b1590817537f05bfa8ce5fc071287780f798e5aa301aaff1a7eadd6569b265` |
| Family label | `PureLogsStealer` |
| File name | `34b1590817537f05bfa8ce5fc071287780f798e5aa301aaff1a7eadd6569b265.exe` |
| File type | `exe` |
| First seen | `2026-10-18 23:21:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3adbe59a4100cce52d8c2a1a6f7b0e6` |
| SHA-1 | `3101bd120265e67233ea6296ea13f9f3292cb2b5` |
| SHA-256 | `34b1590817537f05bfa8ce5fc071287780f798e5aa301aaff1a7eadd6569b265` |
| SHA3-384 | `dbfa75d2bcf6e1fb60f3001227d11d0947cb318e9bb30b535586a88fc1012174070f570e1c81ec003d73f03776b3c613` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19605AE6A73954E20D2881377C0DB0541C3A5A983BAA7F30E76C423966D433FFDE4A697` |
| SSDEEP | `12288:Ps7PAyJtHGSdsOv+AQ7h+i5C+yRxTZR3BvX9BcmA3TePdNmsHB:6oSaOZiA3Z3cmxPn1` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_076_34b15908
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34b1590817537f05bfa8ce5fc071287780f798e5aa301aaff1a7eadd6569b265"
    family = "PureLogsStealer"
    file_name = "34b1590817537f05bfa8ce5fc071287780f798e5aa301aaff1a7eadd6569b265.exe"
    file_type = "exe"
    first_seen = "2026-10-18 23:21:39"
  condition:
    hash.sha256(0, filesize) == "34b1590817537f05bfa8ce5fc071287780f798e5aa301aaff1a7eadd6569b265"
}
```

### Sample 77: `ece8528fe3f27d20`

| Field | Value |
|---|---|
| SHA-256 | `ece8528fe3f27d206dbe159c78f315cfc191fb7415ca8cf0112086150d4120b3` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-10-18 22:39:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05ac136c5d0307e4599c14bc518e5a72` |
| SHA-1 | `cdb51b143712e1796626767713669e6e2a39f7d1` |
| SHA-256 | `ece8528fe3f27d206dbe159c78f315cfc191fb7415ca8cf0112086150d4120b3` |
| SHA3-384 | `f72c35ef7742b83843d1b3fa3dc05a8efea88afefd45467e8c0d742cb19900215a0dc53b4fbf36bbb47ae30e89bb49a5` |
| TLSH | `T111545B03EE404ECBF41ECDB045BDC2972EE1A5D7A5E2A539B1BC4DCDBB5A2464A834C4` |
| SSDEEP | `6144:qc8ZpQoNBspBwIZY0kpr1VFEetx5MwwVjj+do+aVB6Xq:v8ZpQs0tSFtrMNjj+6+U6X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_ece8528f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ece8528fe3f27d206dbe159c78f315cfc191fb7415ca8cf0112086150d4120b3"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-18 22:39:28"
  condition:
    hash.sha256(0, filesize) == "ece8528fe3f27d206dbe159c78f315cfc191fb7415ca8cf0112086150d4120b3"
}
```

### Sample 78: `4efb335bc6357df3`

| Field | Value |
|---|---|
| SHA-256 | `4efb335bc6357df3b48ed5e73db1fe454c926f6015bd4447b9386eb8f13fb7cc` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-10-18 22:33:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaa42833183d6cbcbbf551fc39cea2f5` |
| SHA-1 | `5947c9dfd0825cd87425e7a7212277b8b01bbe5d` |
| SHA-256 | `4efb335bc6357df3b48ed5e73db1fe454c926f6015bd4447b9386eb8f13fb7cc` |
| SHA3-384 | `ec59634a7e4f84273a9c887510a83e8b24b08b056e1c77c57302d67f9d3881fad8aab582a4f51d3fb18e61691925df71` |
| TLSH | `T185E34C95F880EF66CAD4767FFBAD028C33630778D2EA7001CD249B2467DA5598F3A542` |
| TELFHASH | `t190d0a7c5eade028c33d1020d44cee63f8dd6b4d409006a8b4f487b6f054d7583135237` |
| SSDEEP | `3072:EtT2JutC6XvhYmQmD1u3XKG0zMLpL4euo3ixR6aG6vYDk:EtTnVh7QfKG0zMLlduo3ixR6WL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_4efb335b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4efb335bc6357df3b48ed5e73db1fe454c926f6015bd4447b9386eb8f13fb7cc"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-18 22:33:02"
  condition:
    hash.sha256(0, filesize) == "4efb335bc6357df3b48ed5e73db1fe454c926f6015bd4447b9386eb8f13fb7cc"
}
```

### Sample 79: `61f8e4e3e263934a`

| Field | Value |
|---|---|
| SHA-256 | `61f8e4e3e263934a04d18e29fd5edaa0840b1a8137b649e8241e5bae013f200d` |
| Family label | `MacSync` |
| File name | `stage1_61f8e4e3e263.zsh` |
| File type | `zsh` |
| First seen | `2026-10-18 22:27:13` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, macOS, MacSync, stealer, zsh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2fb735e38f6dcd54a7cce5c09614645` |
| SHA-1 | `a30d781cab4875123c767a9a15f18129d0a17114` |
| SHA-256 | `61f8e4e3e263934a04d18e29fd5edaa0840b1a8137b649e8241e5bae013f200d` |
| SHA3-384 | `42562f7ca911ccacf77954100f0413d376242c15546fc2a2ef916b2018dc1bd22726ad0b393f8e19ac0a9412b0dd5b41` |
| TLSH | `T1063139A0438982321B206C938F6CC1C2036FE91FCFA4A320FCE488E1212260FF8D6D18` |
| SSDEEP | `24:LtEAzya7OcEXJ4uhgc4tQp+OHgsHd5VZEMMmvdofMqDw2KDkkXZGZW6azydF4lTj:Ry6OPXJ4IwQpVgQdyMMFfMiKFUW6e9P` |

#### Technical Assessment

- The sample is tracked as `MacSync` by MalwareBazaar metadata.
- The observed artifact type is `zsh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MacSync_079_61f8e4e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61f8e4e3e263934a04d18e29fd5edaa0840b1a8137b649e8241e5bae013f200d"
    family = "MacSync"
    file_name = "stage1_61f8e4e3e263.zsh"
    file_type = "zsh"
    first_seen = "2026-10-18 22:27:13"
  condition:
    hash.sha256(0, filesize) == "61f8e4e3e263934a04d18e29fd5edaa0840b1a8137b649e8241e5bae013f200d"
}
```

### Sample 80: `371cd811b69df854`

| Field | Value |
|---|---|
| SHA-256 | `371cd811b69df8544c9dd43df74afd3d6db210edc7b3d3c124e9bbc7d0638816` |
| Family label | `AMOS` |
| File name | `macho_371cd811b69d.bin` |
| File type | `macho` |
| First seen | `2026-10-18 22:25:09` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9b532d25db382a7b70886319ad81cd7` |
| SHA-1 | `9b177635eff9a8edf1c459547e80aef5efe0fea4` |
| SHA-256 | `371cd811b69df8544c9dd43df74afd3d6db210edc7b3d3c124e9bbc7d0638816` |
| SHA3-384 | `5ecfa8f1414e5a1c681ea6700546f2601855cae02dc9b64584f6958b316a33a4cc819c616477ae785db69af967672749` |
| TLSH | `T18CA5E0104ABB5239F405253398108FE56CE0B9817ACCBEF593769F226D33652B5E3E71` |
| SSDEEP | `49152:RJNxfNc15AxXkjJKEmDFkIHd+n7+vr7IxrMjVGS:ju2kIHW+j` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_080_371cd811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "371cd811b69df8544c9dd43df74afd3d6db210edc7b3d3c124e9bbc7d0638816"
    family = "AMOS"
    file_name = "macho_371cd811b69d.bin"
    file_type = "macho"
    first_seen = "2026-10-18 22:25:09"
  condition:
    hash.sha256(0, filesize) == "371cd811b69df8544c9dd43df74afd3d6db210edc7b3d3c124e9bbc7d0638816"
}
```

### Sample 81: `51d17edc97d15762`

| Field | Value |
|---|---|
| SHA-256 | `51d17edc97d157620defeb37c7b3aa6516869ae0e4c9564781cde51ea59628d6` |
| Family label | `Mirai` |
| File name | `51d17edc97d157620defeb37c7b3aa6516869ae0e4c9564781cde51ea59628d6.elf` |
| File type | `elf` |
| First seen | `2026-10-18 22:16:30` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc05467949534cb31a362f136c13499f` |
| SHA-1 | `da9b576ffcf2fa8fbcfb1f0148bb7f483c651eb1` |
| SHA-256 | `51d17edc97d157620defeb37c7b3aa6516869ae0e4c9564781cde51ea59628d6` |
| SHA3-384 | `994618badf36f0199a42b57ff1227ff069836e875ec759b7cf8e1017e13c8902824be99e84ee2f38a1975c53b48e6859` |
| TLSH | `T1F9B3298ABC81C612C5E161F6FB1F91CD372643B8E3E67107DD18AB29674B8670E3B245` |
| TELFHASH | `t191312016df540fdc73f5035991da4217661934ad0b12102b5ebdba8f9e128d37036139` |
| SSDEEP | `1536:AHJoQUlGIY1Q8RnDfidxM4A3AL6Pg6Wb5LKeJcybMpMx1gvVT:MJUcIGQWD8O4A33I6Wb5L8K2R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_51d17edc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51d17edc97d157620defeb37c7b3aa6516869ae0e4c9564781cde51ea59628d6"
    family = "Mirai"
    file_name = "51d17edc97d157620defeb37c7b3aa6516869ae0e4c9564781cde51ea59628d6.elf"
    file_type = "elf"
    first_seen = "2026-10-18 22:16:30"
  condition:
    hash.sha256(0, filesize) == "51d17edc97d157620defeb37c7b3aa6516869ae0e4c9564781cde51ea59628d6"
}
```

### Sample 82: `9a05910fedc8ea2f`

| Field | Value |
|---|---|
| SHA-256 | `9a05910fedc8ea2f92e3f223740d147e3a731dfdc2b697432d9c1ee2142fd803` |
| Family label | `Mirai` |
| File name | `dissmpsl` |
| File type | `elf` |
| First seen | `2026-10-18 22:09:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3e2ec8f98b9c34027a241173b8e127e` |
| SHA-1 | `db54d8cb6e05089d9ac8484062ccb4f8c3f0dea0` |
| SHA-256 | `9a05910fedc8ea2f92e3f223740d147e3a731dfdc2b697432d9c1ee2142fd803` |
| SHA3-384 | `bb5ca99a00f05d130217a62999c9ce15eaeb7aba35d76719beca83e96e126c039a60002f98de577052bbe699df5536e7` |
| TLSH | `T1F544B3196FA11FBBD87BEF3746F80701239CA60616683B7B6634C414F9AA50F49D3878` |
| SSDEEP | `3072:kWeKfZMFIBQqvKtWEMeJxiOplldEdru2EMY3Gu06rg:kWDfZm8KwenLTEd1MGulr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_9a05910f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a05910fedc8ea2f92e3f223740d147e3a731dfdc2b697432d9c1ee2142fd803"
    family = "Mirai"
    file_name = "dissmpsl"
    file_type = "elf"
    first_seen = "2026-10-18 22:09:56"
  condition:
    hash.sha256(0, filesize) == "9a05910fedc8ea2f92e3f223740d147e3a731dfdc2b697432d9c1ee2142fd803"
}
```

### Sample 83: `90d265704bba45a6`

| Field | Value |
|---|---|
| SHA-256 | `90d265704bba45a63037136dd348e05221569b6e90033270d4ee1d82f863dce6` |
| Family label | `Mirai` |
| File name | `jklmpsl` |
| File type | `elf` |
| First seen | `2026-10-18 22:03:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07aec60fae44c2311d4c549496ff846f` |
| SHA-1 | `55fbc16b5100c5a9a6a27b3f09a11195072ee406` |
| SHA-256 | `90d265704bba45a63037136dd348e05221569b6e90033270d4ee1d82f863dce6` |
| SHA3-384 | `ceebc217b2295f38e9227b16bd5a3363e0b6b877bb6523c485ce1faaf74470b2cc8f24f21e90b19d661d873d45ac40e5` |
| TLSH | `T1D6D31A0ABF711FFBD4AFCE3306A90749299C594621A43B3A3674D81CF64A24F4AE3C54` |
| SSDEEP | `1536:OGmztBYPB2xA59TP+Nwlw+/kSrxaEQ9uofvdgb8M8WF5fMoO95aqyhAexcK35AeA:OFzYZlw+/7wJWTAe9QT+BzpdNoFqTG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_90d26570
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90d265704bba45a63037136dd348e05221569b6e90033270d4ee1d82f863dce6"
    family = "Mirai"
    file_name = "jklmpsl"
    file_type = "elf"
    first_seen = "2026-10-18 22:03:11"
  condition:
    hash.sha256(0, filesize) == "90d265704bba45a63037136dd348e05221569b6e90033270d4ee1d82f863dce6"
}
```

### Sample 84: `341df173a5a6bb6c`

| Field | Value |
|---|---|
| SHA-256 | `341df173a5a6bb6c29fc10b5e711cfac5137441db164fbf47408cd1ed9c0e5f6` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-18 21:59:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46d078a47a5270b66dc6e1c29033fbf4` |
| SHA-1 | `a40d742f8e8f50a4ad801550ef5586a097c09f45` |
| SHA-256 | `341df173a5a6bb6c29fc10b5e711cfac5137441db164fbf47408cd1ed9c0e5f6` |
| SHA3-384 | `ea8f5a25c88e7b7518987702cb6c40317a4a8d76a06b496c292c1876ff1014c38fdd7d4cc80524757827e561b263d5e3` |
| TLSH | `T116D3C74F6E629F6DF36882344BB78B35A35523D223F0C685D2ACDA105E6038D586FF94` |
| TELFHASH | `t103114918893813f087b11d9d6becfe72e0a170eb4a255e378e50f9a99a6dd019e00c2c` |
| SSDEEP | `1536:j5i5gvf1etYIMykQiyCiytlyM13QNro5wu+jDytwU51LrToLScXbSaueVbCg8U9Q:jYMf1+Bnkt3EroCDyaU5VToLScX+c8gQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_341df173
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "341df173a5a6bb6c29fc10b5e711cfac5137441db164fbf47408cd1ed9c0e5f6"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-18 21:59:53"
  condition:
    hash.sha256(0, filesize) == "341df173a5a6bb6c29fc10b5e711cfac5137441db164fbf47408cd1ed9c0e5f6"
}
```

### Sample 85: `8709b33b1ecdf875`

| Field | Value |
|---|---|
| SHA-256 | `8709b33b1ecdf875070f5d17ff8ccb39a652813a8b2ea6eba4d576bbd50c4b2e` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-18 21:59:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48548dc0415b6166798e62a4a7f7b177` |
| SHA-1 | `df83c48d944037e2897e3f7405cae2f4825ba945` |
| SHA-256 | `8709b33b1ecdf875070f5d17ff8ccb39a652813a8b2ea6eba4d576bbd50c4b2e` |
| SHA3-384 | `82aca386f81a90cf1ef856496c94673115db6c8e68e663027ef2f96ddcdf29bb01fb32d3461dc08806b5e670dbc2ee71` |
| TLSH | `T108B33CD5BC818B11D5C126BAFE1E518E33134B7CE3FE72139E189B2D638A8670A3B515` |
| TELFHASH | `t10cf05c747e84065ca7e1c480c1ffa22562d960cb7d2a295e8826aa4f4d6b390351c452` |
| SSDEEP | `3072:2NPRAEeYsSghe8EGucdHvXZgEv35IPba6AnQBLTz4+KTf5s:U+eOZF6+35yba7nQx4J1s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_8709b33b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8709b33b1ecdf875070f5d17ff8ccb39a652813a8b2ea6eba4d576bbd50c4b2e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-18 21:59:51"
  condition:
    hash.sha256(0, filesize) == "8709b33b1ecdf875070f5d17ff8ccb39a652813a8b2ea6eba4d576bbd50c4b2e"
}
```

### Sample 86: `62f65b335e3a7d4c`

| Field | Value |
|---|---|
| SHA-256 | `62f65b335e3a7d4cf806440134105f533ce5f639856a2edaea03013217bf6ec4` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-10-18 21:59:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e99dcf31fee557aa0822acbffac8842` |
| SHA-1 | `1dcb6546195b03ff215237af887bdcef05e7823f` |
| SHA-256 | `62f65b335e3a7d4cf806440134105f533ce5f639856a2edaea03013217bf6ec4` |
| SHA3-384 | `b8126193252fb78e64e986cfa476e7f52fa711f4507dd23c29a2ef2e5f7316fdd7983ab0640f49c9e39116923aa56527` |
| TLSH | `T1E4B34A41B3694407F2E74DB02D3F7BF593DED1A121A0A6C5695EDB0F8232A322586FC9` |
| SSDEEP | `1536:gp2qyqHS8sBJnTkrLYIHiv2b8aqtLHxVJqJAom/wbqML1MpKQjj4O4AK9vfZ:m2WyHo8lXiKrpfj+PZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_62f65b33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62f65b335e3a7d4cf806440134105f533ce5f639856a2edaea03013217bf6ec4"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-18 21:59:47"
  condition:
    hash.sha256(0, filesize) == "62f65b335e3a7d4cf806440134105f533ce5f639856a2edaea03013217bf6ec4"
}
```

### Sample 87: `598d8e60da3039e4`

| Field | Value |
|---|---|
| SHA-256 | `598d8e60da3039e42c7f50aa015bb4536053152dd108bb2ad8ddebb8a9ae7249` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-18 21:57:41` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `804b8ff75817161d8f1da3e821f98e7e` |
| SHA-1 | `4880de1d1fe43cd9e7e599f1d500039186103f67` |
| SHA-256 | `598d8e60da3039e42c7f50aa015bb4536053152dd108bb2ad8ddebb8a9ae7249` |
| SHA3-384 | `f7af99943bc3452a98394633c680046ee717fd3d69cc33241d5d0534c7ac156afd4f780d5847d5fda8fe84b10a8b15c6` |
| IMPHASH | `12896c3d6ac0fc631e589bc128d05f14` |
| TLSH | `T19245EF41A385BDF9F93280784BB185119560FCBC07E396FB168C2A6A1E326D17FF8719` |
| SSDEEP | `24576:HSg4lcTX8LERrmWeMILt3O4RjF8/s0Qjyc:yg4uj8LEzIpZ8Uh` |
| ICON-DHASH | `106c9a72729a6c10` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_598d8e60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "598d8e60da3039e42c7f50aa015bb4536053152dd108bb2ad8ddebb8a9ae7249"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-18 21:57:41"
  condition:
    hash.sha256(0, filesize) == "598d8e60da3039e42c7f50aa015bb4536053152dd108bb2ad8ddebb8a9ae7249"
}
```

### Sample 88: `6079816d1a3be671`

| Field | Value |
|---|---|
| SHA-256 | `6079816d1a3be67178175549197a44fd939f306332ea67799ce06301ad25d8d3` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-18 21:56:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de439808771d3769fbfeb0062dea950d` |
| SHA-1 | `e3b574ab4ee12c77e1d86ba0e4cd4a92cbf49760` |
| SHA-256 | `6079816d1a3be67178175549197a44fd939f306332ea67799ce06301ad25d8d3` |
| SHA3-384 | `71699d9ef3f942b7b59cf9d1608a467993a595eba5ee25c8cc3ac09ab0898ab1466b8953c810f06919e8406a0349c641` |
| TLSH | `T1E1545B037B129FA1F21591B149FBC5996ED912D32BF148B5A36DC3483F222A5385FEE0` |
| TELFHASH | `t14311e918483c13f0d3845d9d5bedff35d46050df46225e378d00fdaa9b219825e00c2c` |
| SSDEEP | `6144:+PtYkfiWDC2SpI1w4VTogcNH4qPNB1dOMLrNOiIU:yRiUC2SD4JKPNtOUOiL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_6079816d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6079816d1a3be67178175549197a44fd939f306332ea67799ce06301ad25d8d3"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-18 21:56:29"
  condition:
    hash.sha256(0, filesize) == "6079816d1a3be67178175549197a44fd939f306332ea67799ce06301ad25d8d3"
}
```

### Sample 89: `79be40471ef3344b`

| Field | Value |
|---|---|
| SHA-256 | `79be40471ef3344bbf30712fddee64e4b1d9e50747ce72205052ed71a3fa0b06` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-10-18 21:56:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ab0ded852309e393a928cede97b5abe` |
| SHA-1 | `bf1fec813b5e0a7bde337b713202a4033b71e568` |
| SHA-256 | `79be40471ef3344bbf30712fddee64e4b1d9e50747ce72205052ed71a3fa0b06` |
| SHA3-384 | `02e33d691d7cc07b09a6377f45dee8eab8675e1fbf730f772acf5495aa5d9854dc3930a4279fb6c0c9a3d599227289d4` |
| TLSH | `T14FB33B25ED75583BC5C0717B51E34631E1B6439929BC9A1B7EA31C8CEF28350313FAAA` |
| SSDEEP | `1536:0ScCXnP2NLuCUViVXda1laA1CLgtUt4F5z7wJlHw6hNWj5S9IJRbtbzU:TcGP8/UUlBsx6hN++6U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_79be4047
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79be40471ef3344bbf30712fddee64e4b1d9e50747ce72205052ed71a3fa0b06"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-18 21:56:27"
  condition:
    hash.sha256(0, filesize) == "79be40471ef3344bbf30712fddee64e4b1d9e50747ce72205052ed71a3fa0b06"
}
```

### Sample 90: `cc7872eb663295da`

| Field | Value |
|---|---|
| SHA-256 | `cc7872eb663295da180c9bfb5cb0bbbea0275537b0bd676e23fcf12533bd05d6` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-18 21:56:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38a135a580c45d433a9afa02c793a40e` |
| SHA-1 | `a377a244617a4a2a15b9ce83aa2db07d95fe36b4` |
| SHA-256 | `cc7872eb663295da180c9bfb5cb0bbbea0275537b0bd676e23fcf12533bd05d6` |
| SHA3-384 | `cb8a4c4fc4965063ea60bba8f113c5ef7aa52e40e380df2de28b2e37eaa011c84459865c86f6b86eed86e6786f3e7b9e` |
| TLSH | `T139C31989BC819B10D5D625BAFE1E518D33534BBCE3FA71138E149B2A638AC5B0F77601` |
| TELFHASH | `t142f0dcb1dda80c9ad7c5c401c09c73120cde6046793a21193eeb6b4d0aa34823a28a03` |
| SSDEEP | `3072:sOoRAkWKMe0vDjEOYyHfZcd2DMIUMDaX5VoqKHz5SfXIagnG37:wID/VH+EDMyDaX5VoqKT5UItnW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_cc7872eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc7872eb663295da180c9bfb5cb0bbbea0275537b0bd676e23fcf12533bd05d6"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-18 21:56:24"
  condition:
    hash.sha256(0, filesize) == "cc7872eb663295da180c9bfb5cb0bbbea0275537b0bd676e23fcf12533bd05d6"
}
```

### Sample 91: `767f289c4f916a3d`

| Field | Value |
|---|---|
| SHA-256 | `767f289c4f916a3dbb3d82435c1e5755a63d7d689f4536f54c90f7b2b078dff3` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-18 21:56:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f008f69131c2ee77cbc25b6806282ee8` |
| SHA-1 | `4b357a381a784aa222b8849f0bc2cd7b66ef8785` |
| SHA-256 | `767f289c4f916a3dbb3d82435c1e5755a63d7d689f4536f54c90f7b2b078dff3` |
| SHA3-384 | `90f04ab5a93dd1a50da65a37cbb5000bda21527b9db524cae86093fb4965f284012b531bfe13199ee7a3b51c57b72763` |
| TLSH | `T175B32A8ABCC1D702C5E060B2FF1F91CD376643A8D3E672579D18AB29674B8670E3B641` |
| TELFHASH | `t1b7f04612ce845ddc77f6059920ada797000c79dd29204487b3fddeaf8d36997b02224c` |
| SSDEEP | `1536:VNAdZ/MKNY2yGtn5hGrpA8e4RoyvzGWqcVwdlpD/JVLd0kzV:VNAz/VNly6mc4R1LqcVw5/LBB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_767f289c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "767f289c4f916a3dbb3d82435c1e5755a63d7d689f4536f54c90f7b2b078dff3"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-18 21:56:22"
  condition:
    hash.sha256(0, filesize) == "767f289c4f916a3dbb3d82435c1e5755a63d7d689f4536f54c90f7b2b078dff3"
}
```

### Sample 92: `f2c8253354f500ce`

| Field | Value |
|---|---|
| SHA-256 | `f2c8253354f500ce620b8794edc18a1aecb217c0021d86c73fd858a591ec653b` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-10-18 21:56:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bef66ed31de11b2755ea47e18645c31a` |
| SHA-1 | `7fa35388b1724755fd1f28207451cafdd4fe0c4f` |
| SHA-256 | `f2c8253354f500ce620b8794edc18a1aecb217c0021d86c73fd858a591ec653b` |
| SHA3-384 | `3c81c66b0ec75a7b4ce4eff091af2a9391e2336bed0e631fab956578e3507f761841e80fdce9c27f772ba13b540bc4b9` |
| TLSH | `T1D2A3AF12CD641DACF06A6D3120B98AFA4723B484991B6EFB3C4782255057EDCF197BF8` |
| SSDEEP | `1536:IJ1EUL5Yu6PKIyFZkIM5WL/sJkyinndTEy3AGKZ1HA7atMhCdRuotkZX9:IJ1EUL5YfxyFZkhWoj+VdCZWmMhSfMt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_f2c82533
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2c8253354f500ce620b8794edc18a1aecb217c0021d86c73fd858a591ec653b"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-18 21:56:19"
  condition:
    hash.sha256(0, filesize) == "f2c8253354f500ce620b8794edc18a1aecb217c0021d86c73fd858a591ec653b"
}
```

### Sample 93: `bd90fa0a64f8482a`

| Field | Value |
|---|---|
| SHA-256 | `bd90fa0a64f8482a0a1a56b85daf11129b5ea373e0df93260a2da096fd011f7d` |
| Family label | `Mirai` |
| File name | `jklm68k` |
| File type | `elf` |
| First seen | `2026-10-18 21:50:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c936b535ac2eb1e382e78417bf1d9e32` |
| SHA-1 | `01fcfd2f9a8240511131ff7d509ed5e658c714f1` |
| SHA-256 | `bd90fa0a64f8482a0a1a56b85daf11129b5ea373e0df93260a2da096fd011f7d` |
| SHA3-384 | `21b57b4b7f4ae5a7cb24827987c0ee6f332f7e8caad48adfe2d0b599481a9b0815f9491700855850a6aedf1d3ec38190` |
| TLSH | `T1C1B33BA6F400DC3EF41BE7B780970706B160A3E50A522B277657FD23EE791A41C66E86` |
| SSDEEP | `3072:ntB1M+BW6EMLxLfq4t33yd5LcqMtffwWJRDo:ntI6EMLZdU54ptNJVo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_bd90fa0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd90fa0a64f8482a0a1a56b85daf11129b5ea373e0df93260a2da096fd011f7d"
    family = "Mirai"
    file_name = "jklm68k"
    file_type = "elf"
    first_seen = "2026-10-18 21:50:04"
  condition:
    hash.sha256(0, filesize) == "bd90fa0a64f8482a0a1a56b85daf11129b5ea373e0df93260a2da096fd011f7d"
}
```

### Sample 94: `438b9c35cc8b0a24`

| Field | Value |
|---|---|
| SHA-256 | `438b9c35cc8b0a24b63848f50b934c03479937e0ec10a2424c904686aebbac46` |
| Family label | `Mirai` |
| File name | `sora.x86` |
| File type | `elf` |
| First seen | `2026-10-18 21:09:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a099f9a88b9112b14904c279c329357` |
| SHA-1 | `e86fcd50701316fcbc9d381d788067e50d7656ae` |
| SHA-256 | `438b9c35cc8b0a24b63848f50b934c03479937e0ec10a2424c904686aebbac46` |
| SHA3-384 | `a23234c8afe03da9d71f5db439d4e733624de9c0d256dec46214b07e4780d3edebaee989f958e79ce01cef6d67ee8fff` |
| TLSH | `T159C2D1A350B6CA03C4F6837A2E3C4AA622605834A35EE92D77794BC477460D4657ACCB` |
| SSDEEP | `768:t5+Kcrb9VDJee2KTgdTHOBcK5ZCAy5HxXU:Olrb9veKTg9QB5Vwk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_438b9c35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "438b9c35cc8b0a24b63848f50b934c03479937e0ec10a2424c904686aebbac46"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-10-18 21:09:37"
  condition:
    hash.sha256(0, filesize) == "438b9c35cc8b0a24b63848f50b934c03479937e0ec10a2424c904686aebbac46"
}
```

### Sample 95: `cf54666174d7e8b7`

| Field | Value |
|---|---|
| SHA-256 | `cf54666174d7e8b7c3b2077029476608b570d65b1b3b58c1c0b03663555d1527` |
| Family label | `Mirai` |
| File name | `dissx86` |
| File type | `elf` |
| First seen | `2026-10-18 21:06:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8024ce8a89156a41978134643738dec` |
| SHA-1 | `199979d85d3fbc1125978d017b62e396de2ca9ad` |
| SHA-256 | `cf54666174d7e8b7c3b2077029476608b570d65b1b3b58c1c0b03663555d1527` |
| SHA3-384 | `75d892e40024dfe395fc1376ccb9e66b6a032c1b22f2cc68efe2ea71cae2257ed7084d2d320cec4411f77fca65acf237` |
| TLSH | `T17114392578E161FCC4A7F338CBBE9221A774F60C0B24B84F437459529EBDE3D4A68529` |
| TELFHASH | `t1ab51cb742ca2395852d7d267b34fdae9ec7206110fe270a64f57ace2ce877cc1e82815` |
| SSDEEP | `3072:zs53dvTzGua1/pbY7zi9t5DsCICMpP6i7WKSs:zkbSayhB9N1s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_cf546661
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf54666174d7e8b7c3b2077029476608b570d65b1b3b58c1c0b03663555d1527"
    family = "Mirai"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-18 21:06:40"
  condition:
    hash.sha256(0, filesize) == "cf54666174d7e8b7c3b2077029476608b570d65b1b3b58c1c0b03663555d1527"
}
```

### Sample 96: `188a79e5b0aeb265`

| Field | Value |
|---|---|
| SHA-256 | `188a79e5b0aeb2656c15fc167bac923b94752b98996f1981e95c173729ce7a0f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-18 20:41:52` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX1.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c5df0e83c30e697d1eea864e447c1e1` |
| SHA-1 | `497b62abc027510c03a3c76aac1f9f261d9e7b46` |
| SHA-256 | `188a79e5b0aeb2656c15fc167bac923b94752b98996f1981e95c173729ce7a0f` |
| SHA3-384 | `366955a289fa8f05b6a9e61fc9295cb600621225e16f45618da77c7df4ba9769877bd8996c0a34926e8183275991b01b` |
| IMPHASH | `8f132b0d040842398ed264d9e395a584` |
| TLSH | `T10B84E10B76A631F9E077823588914A46E772B83647215FFF03A883576F236D48D3EB61` |
| SSDEEP | `6144:fpUmUupK5bDF8IA+Mu831cJTOFVb7ufg4CIOOA0UTOgSocUGW:f2mG5b+J0a1cxOFV2CDTOoNGW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_188a79e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "188a79e5b0aeb2656c15fc167bac923b94752b98996f1981e95c173729ce7a0f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-18 20:41:52"
  condition:
    hash.sha256(0, filesize) == "188a79e5b0aeb2656c15fc167bac923b94752b98996f1981e95c173729ce7a0f"
}
```

### Sample 97: `f731bd0c7a45984d`

| Field | Value |
|---|---|
| SHA-256 | `f731bd0c7a45984dc706a425ae02844dcf20b357cee27c60e407e0ca1a2aefa2` |
| Family label | `unknown` |
| File name | `f731bd0c7a45984dc706a425ae02844dcf20b357cee27c60e407e0ca1a2aefa2.exe` |
| File type | `exe` |
| First seen | `2026-10-18 20:27:38` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41dbe989bdceff0341067a6e83be475e` |
| SHA-1 | `343e671a503e08b41439314c146e076c2e796069` |
| SHA-256 | `f731bd0c7a45984dc706a425ae02844dcf20b357cee27c60e407e0ca1a2aefa2` |
| SHA3-384 | `05ed6c7e279cc067715188cc70ca528cd99647a164c3281c0b11d13145902a6fbd6febb9c71bea89cbc1b3b0395be806` |
| IMPHASH | `a801eb4906742ed883c11e43e19cb9dd` |
| TLSH | `T1F666AD15D3E901A5E92BC738CA16C333DAB1BC925734C50F0559F6122F73EA29B6F226` |
| SSDEEP | `49152:aIAkzTphtg1HEBId0iooDo7ob/BOOic0a/+Pa40QFSD9cefMAItkZ3QAOBT8Rb3x:BmEO4zoz4nPspZmwEHtIWfAN+O8G4` |
| ICON-DHASH | `003271f0f8713200` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_f731bd0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f731bd0c7a45984dc706a425ae02844dcf20b357cee27c60e407e0ca1a2aefa2"
    family = "unknown"
    file_name = "f731bd0c7a45984dc706a425ae02844dcf20b357cee27c60e407e0ca1a2aefa2.exe"
    file_type = "exe"
    first_seen = "2026-10-18 20:27:38"
  condition:
    hash.sha256(0, filesize) == "f731bd0c7a45984dc706a425ae02844dcf20b357cee27c60e407e0ca1a2aefa2"
}
```

### Sample 98: `dfadfad813e1fcdb`

| Field | Value |
|---|---|
| SHA-256 | `dfadfad813e1fcdbad43cc2b26e1a2ad8c3bac2665e760803aa9c7b234528fca` |
| Family label | `unknown` |
| File name | `dfadfad813e1fcdbad43cc2b26e1a2ad8c3bac2665e760803aa9c7b234528fca.exe` |
| File type | `exe` |
| First seen | `2026-10-18 20:27:33` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1991c3d93019f66fe6c462a0b1d9130` |
| SHA-1 | `391151b32062c31450644421cb11c7c903685b66` |
| SHA-256 | `dfadfad813e1fcdbad43cc2b26e1a2ad8c3bac2665e760803aa9c7b234528fca` |
| SHA3-384 | `a7831161d83b4085cd8abdac359af261ec049c4b94ca902ec1de6f75840a909ba1fc4948614ab996acc0835d3dcfead8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T164F26B18BBDDC526E6FE87F81DB10350033AE95F1172E78F0CD9A5AE0D36B904A84B52` |
| SSDEEP | `384:av+qDpoSd3BI+qjULt0rcDc3npcwU0mlkv4ZDVQpNEHk+XijOMxnI3sRqVCTs/cU:aWqDW+q0p0ejDHk+yjdxI3sRGB/cU` |
| ICON-DHASH | `c892696ccc6812c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_dfadfad8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfadfad813e1fcdbad43cc2b26e1a2ad8c3bac2665e760803aa9c7b234528fca"
    family = "unknown"
    file_name = "dfadfad813e1fcdbad43cc2b26e1a2ad8c3bac2665e760803aa9c7b234528fca.exe"
    file_type = "exe"
    first_seen = "2026-10-18 20:27:33"
  condition:
    hash.sha256(0, filesize) == "dfadfad813e1fcdbad43cc2b26e1a2ad8c3bac2665e760803aa9c7b234528fca"
}
```

### Sample 99: `ac630d2e5a5bc25e`

| Field | Value |
|---|---|
| SHA-256 | `ac630d2e5a5bc25e8c743cde099dc65087aa8fc35e5e0b354e6a74d630be752d` |
| Family label | `unknown` |
| File name | `ac630d2e5a5bc25e8c743cde099dc65087aa8fc35e5e0b354e6a74d630be752d.exe` |
| File type | `exe` |
| First seen | `2026-10-18 20:27:28` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cf9491a570541c1363f017db30575c7` |
| SHA-1 | `219ece9bea991b5fa91bacde1fe75d6e2894bd86` |
| SHA-256 | `ac630d2e5a5bc25e8c743cde099dc65087aa8fc35e5e0b354e6a74d630be752d` |
| SHA3-384 | `5564e9c469d465e000e7530e63844e5b881e32f58125c579d35e9ffc60e8135f2ea50fb33d7f4e1555c87c4c4c257b9e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T179E4E017F305DB0BE09A0E3999B2D3A55374F9293E6B830FB5C99D5CAC47AC00E0569E` |
| SSDEEP | `12288:1tKexTDcwokAzWI+j81UkpD9WAD3fdWI0mLraqbcQcuqX6mon:1tvrokhIc81NpDrD3f+UcQ/` |
| ICON-DHASH | `ea163371713396e8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_ac630d2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac630d2e5a5bc25e8c743cde099dc65087aa8fc35e5e0b354e6a74d630be752d"
    family = "unknown"
    file_name = "ac630d2e5a5bc25e8c743cde099dc65087aa8fc35e5e0b354e6a74d630be752d.exe"
    file_type = "exe"
    first_seen = "2026-10-18 20:27:28"
  condition:
    hash.sha256(0, filesize) == "ac630d2e5a5bc25e8c743cde099dc65087aa8fc35e5e0b354e6a74d630be752d"
}
```

### Sample 100: `2b8535175e934363`

| Field | Value |
|---|---|
| SHA-256 | `2b8535175e93436354114e5a11c0dc8a92fa440b97bbcfccb9d9f34a7ac9daed` |
| Family label | `SalatStealer` |
| File name | `g3.exe` |
| File type | `exe` |
| First seen | `2026-10-18 20:23:26` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3895a76f116211eb553862b357c88db` |
| SHA-1 | `8750c85e675d70fc9c4115ec65fde51cffc2d41a` |
| SHA-256 | `2b8535175e93436354114e5a11c0dc8a92fa440b97bbcfccb9d9f34a7ac9daed` |
| SHA3-384 | `829f34837afd08bc024c98b445f2d248a89bac540d97b25546baf5f0420aed9ba4bf6413a9538ffb1cc7e6ecab80cb67` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T138C65B11FACB54F6F8036831416BB27F23315D048B24DB9BEB587F6AF87B691186A305` |
| SSDEEP | `49152:7gcHiHARniGBfkMRZA9RGNHtCGvTEKRPhww+nTGLbdHfXP2G2RQf6k1xJCGmEnim:PHYAFHZAjINCkEqHRR2W7CGb64JxE6` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_100_2b853517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b8535175e93436354114e5a11c0dc8a92fa440b97bbcfccb9d9f34a7ac9daed"
    family = "SalatStealer"
    file_name = "g3.exe"
    file_type = "exe"
    first_seen = "2026-10-18 20:23:26"
  condition:
    hash.sha256(0, filesize) == "2b8535175e93436354114e5a11c0dc8a92fa440b97bbcfccb9d9f34a7ac9daed"
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
 * Generated: 2026-10-19T04:52:04.730803+00:00
 */

rule MalwareBazaar_unknown_001_2a530825
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a5308255e8cfbe7fe2941a832e8ef637ca25114057ab08be65d8539f489069f"
    family = "unknown"
    file_name = "New PO SGN260918167.vbs"
    file_type = "vbs"
    first_seen = "2026-10-19 04:44:34"
  condition:
    hash.sha256(0, filesize) == "2a5308255e8cfbe7fe2941a832e8ef637ca25114057ab08be65d8539f489069f"
}

rule MalwareBazaar_unknown_002_e9c0c38d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9c0c38dc0128214ac58ded574ab2628c4fa1cd7c2101552b34b72641ac3583e"
    family = "unknown"
    file_name = "mbupload-vtc0u44o.bin"
    file_type = "exe"
    first_seen = "2026-10-19 04:44:22"
  condition:
    hash.sha256(0, filesize) == "e9c0c38dc0128214ac58ded574ab2628c4fa1cd7c2101552b34b72641ac3583e"
}

rule MalwareBazaar_SalatStealer_003_9e6dd02b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e6dd02b923469c4f9a022f52d7fba9849b63fc1f66f20173e514401af8f3f64"
    family = "SalatStealer"
    file_name = "mbupload-vtc0u44o.bin"
    file_type = "exe"
    first_seen = "2026-10-19 04:43:37"
  condition:
    hash.sha256(0, filesize) == "9e6dd02b923469c4f9a022f52d7fba9849b63fc1f66f20173e514401af8f3f64"
}

rule MalwareBazaar_unknown_004_613c0de4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "613c0de40c32f5347f49ccf4c61c9998d4b1dc4ebda699d282121b7dc48f44c7"
    family = "unknown"
    file_name = "PO-SINCO-AUTOMATIOM-86757786-Ref-6777.vbs"
    file_type = "vbs"
    first_seen = "2026-10-19 04:42:44"
  condition:
    hash.sha256(0, filesize) == "613c0de40c32f5347f49ccf4c61c9998d4b1dc4ebda699d282121b7dc48f44c7"
}

rule MalwareBazaar_Mirai_005_32a8e169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32a8e169003743952a8405d3bb9799142af3edc216ae3c8b246561b0d0644cbc"
    family = "Mirai"
    file_name = "boatnet.x86"
    file_type = "elf"
    first_seen = "2026-10-19 04:42:26"
  condition:
    hash.sha256(0, filesize) == "32a8e169003743952a8405d3bb9799142af3edc216ae3c8b246561b0d0644cbc"
}

rule MalwareBazaar_Mirai_006_1f15fc80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f15fc801140d41f3f0eaccf9aa115da51c693f1265ba00fbf35bf31269a739f"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-10-19 04:42:23"
  condition:
    hash.sha256(0, filesize) == "1f15fc801140d41f3f0eaccf9aa115da51c693f1265ba00fbf35bf31269a739f"
}

rule MalwareBazaar_Mirai_007_bf7562c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf7562c880967fc2afca8669b0ef1cdfa8c273d5338300c455418c0c234d23a4"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-10-19 04:42:19"
  condition:
    hash.sha256(0, filesize) == "bf7562c880967fc2afca8669b0ef1cdfa8c273d5338300c455418c0c234d23a4"
}

rule MalwareBazaar_Mirai_008_62dd4a81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62dd4a817a173e1687ac9ae1f43a3fe7af05b65314127043d141e134ffeb3434"
    family = "Mirai"
    file_name = "boatnet.x86"
    file_type = "elf"
    first_seen = "2026-10-19 04:41:55"
  condition:
    hash.sha256(0, filesize) == "62dd4a817a173e1687ac9ae1f43a3fe7af05b65314127043d141e134ffeb3434"
}

rule MalwareBazaar_Mirai_009_e749be81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e749be812bb42a783b3d5e18d7b9c17abea3677ec8905b9bee14ded50b745fa6"
    family = "Mirai"
    file_name = "boatnet.spc"
    file_type = "elf"
    first_seen = "2026-10-19 04:41:53"
  condition:
    hash.sha256(0, filesize) == "e749be812bb42a783b3d5e18d7b9c17abea3677ec8905b9bee14ded50b745fa6"
}

rule MalwareBazaar_Mirai_010_08250a73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08250a73e7e7386e4543cc30e819c0eab7e7a438d1ee77f81613314d40d178bc"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-10-19 04:41:51"
  condition:
    hash.sha256(0, filesize) == "08250a73e7e7386e4543cc30e819c0eab7e7a438d1ee77f81613314d40d178bc"
}

rule MalwareBazaar_Mirai_011_42480c00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42480c00b3f4874c08265fda54e54bf6a609c8358b91c7b78c8064f839fe6cf3"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-10-19 04:41:49"
  condition:
    hash.sha256(0, filesize) == "42480c00b3f4874c08265fda54e54bf6a609c8358b91c7b78c8064f839fe6cf3"
}

rule MalwareBazaar_RemcosRAT_012_5f4838a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f4838a39b064a0165cc673526d2d7a0be456d259b1f392964ed4dd2084a194d"
    family = "RemcosRAT"
    file_name = "20261019 UTS.bat"
    file_type = "bat"
    first_seen = "2026-10-19 04:40:08"
  condition:
    hash.sha256(0, filesize) == "5f4838a39b064a0165cc673526d2d7a0be456d259b1f392964ed4dd2084a194d"
}

rule MalwareBazaar_Formbook_013_dc50ab47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc50ab477a38a56cfcce2c3a630f309b4d39c555882845702ba5eb389fa53f8b"
    family = "Formbook"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-19 04:30:27"
  condition:
    hash.sha256(0, filesize) == "dc50ab477a38a56cfcce2c3a630f309b4d39c555882845702ba5eb389fa53f8b"
}

rule MalwareBazaar_Formbook_014_aed64d1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aed64d1a94fe8182f45f84a8f7ba420b90b076c34c448e141d11be350bb728bf"
    family = "Formbook"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-19 04:30:20"
  condition:
    hash.sha256(0, filesize) == "aed64d1a94fe8182f45f84a8f7ba420b90b076c34c448e141d11be350bb728bf"
}

rule MalwareBazaar_Mirai_015_c0dfdf35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0dfdf35c03086c024a70249340ff1f6a03ecabc74b8a065e1a4c6220797ac30"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-19 04:29:49"
  condition:
    hash.sha256(0, filesize) == "c0dfdf35c03086c024a70249340ff1f6a03ecabc74b8a065e1a4c6220797ac30"
}

rule MalwareBazaar_unknown_016_d8cbb7c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8cbb7c00689d7fd518151cccdc8c24c5b6b44a49ce2e60ae9d74256ac366896"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-10-19 04:14:58"
  condition:
    hash.sha256(0, filesize) == "d8cbb7c00689d7fd518151cccdc8c24c5b6b44a49ce2e60ae9d74256ac366896"
}

rule MalwareBazaar_unknown_017_15ccc62d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15ccc62d46951d6967d31fa6e8a3ceb13865cd319d6a7876420388a311efe651"
    family = "unknown"
    file_name = "bot_s390x"
    file_type = "elf"
    first_seen = "2026-10-19 03:59:55"
  condition:
    hash.sha256(0, filesize) == "15ccc62d46951d6967d31fa6e8a3ceb13865cd319d6a7876420388a311efe651"
}

rule MalwareBazaar_unknown_018_d3ec060c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3ec060c8459ece5a17730985c4751976f276c3d16e4487b6d19dfc998980a22"
    family = "unknown"
    file_name = "sample"
    file_type = "exe"
    first_seen = "2026-10-19 03:57:40"
  condition:
    hash.sha256(0, filesize) == "d3ec060c8459ece5a17730985c4751976f276c3d16e4487b6d19dfc998980a22"
}

rule MalwareBazaar_unknown_019_838c6c0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "838c6c0f247c3347075a71d18fb4a51b0ecc06c3db3ab337d666092d533129cb"
    family = "unknown"
    file_name = "mbupload-87n186oc.bin"
    file_type = "exe"
    first_seen = "2026-10-19 03:47:50"
  condition:
    hash.sha256(0, filesize) == "838c6c0f247c3347075a71d18fb4a51b0ecc06c3db3ab337d666092d533129cb"
}

rule MalwareBazaar_unknown_020_6c3731a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c3731a2777b436a1be8274135298572414024391b77d9c5d9435bfb9d4b7ef6"
    family = "unknown"
    file_name = "mbupload-4an3c499.bin"
    file_type = "zip"
    first_seen = "2026-10-19 03:47:31"
  condition:
    hash.sha256(0, filesize) == "6c3731a2777b436a1be8274135298572414024391b77d9c5d9435bfb9d4b7ef6"
}

rule MalwareBazaar_unknown_021_ac08c528
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac08c52835b555fb2bb899f798468e9011ac321b60d5a2763d485e6f0d59aaa7"
    family = "unknown"
    file_name = "sample"
    file_type = "exe"
    first_seen = "2026-10-19 03:28:58"
  condition:
    hash.sha256(0, filesize) == "ac08c52835b555fb2bb899f798468e9011ac321b60d5a2763d485e6f0d59aaa7"
}

rule MalwareBazaar_RemcosRAT_022_57a23842
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57a23842ad1e35d74a7668ab2112de54d92b2a70f6949d7f892002aeb5d69db6"
    family = "RemcosRAT"
    file_name = "sample"
    file_type = "exe"
    first_seen = "2026-10-19 03:28:40"
  condition:
    hash.sha256(0, filesize) == "57a23842ad1e35d74a7668ab2112de54d92b2a70f6949d7f892002aeb5d69db6"
}

rule MalwareBazaar_Phorpiex_023_719a4723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "719a47231d3f1fb7e3522cf842a06c64f6cbddbfde46e79846fc0ad3e79f5014"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-19 03:19:33"
  condition:
    hash.sha256(0, filesize) == "719a47231d3f1fb7e3522cf842a06c64f6cbddbfde46e79846fc0ad3e79f5014"
}

rule MalwareBazaar_unknown_024_125b3a8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "125b3a8bfa122c8467d6a0978ec1b413261543a4b0fa6a3f7a1bd3b067aedf0d"
    family = "unknown"
    file_name = "sample"
    file_type = "msi"
    first_seen = "2026-10-19 03:15:30"
  condition:
    hash.sha256(0, filesize) == "125b3a8bfa122c8467d6a0978ec1b413261543a4b0fa6a3f7a1bd3b067aedf0d"
}

rule MalwareBazaar_unknown_025_30be992d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30be992d1c779f119e2e52711d6966289de06e24fba306050264d3b10301de0f"
    family = "unknown"
    file_name = "sample"
    file_type = "exe"
    first_seen = "2026-10-19 03:15:25"
  condition:
    hash.sha256(0, filesize) == "30be992d1c779f119e2e52711d6966289de06e24fba306050264d3b10301de0f"
}

rule MalwareBazaar_unknown_026_c2e6edab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2e6edab80c83e9fca3aca4a86040e00398dde5ebb652934d852387bfa5e1561"
    family = "unknown"
    file_name = "sample"
    file_type = "exe"
    first_seen = "2026-10-19 03:13:30"
  condition:
    hash.sha256(0, filesize) == "c2e6edab80c83e9fca3aca4a86040e00398dde5ebb652934d852387bfa5e1561"
}

rule MalwareBazaar_unknown_027_8d65192f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d65192fabdefc204ea73e9c19b22c81af46c9b3946cc2ff4df40d18516f97e2"
    family = "unknown"
    file_name = "mbupload-m8tv7yba.bin"
    file_type = "zip"
    first_seen = "2026-10-19 03:08:05"
  condition:
    hash.sha256(0, filesize) == "8d65192fabdefc204ea73e9c19b22c81af46c9b3946cc2ff4df40d18516f97e2"
}

rule MalwareBazaar_unknown_028_22874b6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22874b6a6184d2f77ba2c24b8948fe2af261aea99d641423e4c69644b994e6ea"
    family = "unknown"
    file_name = "mbupload-pdewblml.bin"
    file_type = "zip"
    first_seen = "2026-10-19 03:07:47"
  condition:
    hash.sha256(0, filesize) == "22874b6a6184d2f77ba2c24b8948fe2af261aea99d641423e4c69644b994e6ea"
}

rule MalwareBazaar_unknown_029_ccaf6b28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccaf6b28b9fe286efa1533e0af5ce57dba11be068aee39e08d1ad5a7796d7d79"
    family = "unknown"
    file_name = "ccaf6b28b9fe286efa1533e0af5ce57dba11be068aee39e08d1ad5a7796d7d79.elf"
    file_type = "elf"
    first_seen = "2026-10-19 03:06:35"
  condition:
    hash.sha256(0, filesize) == "ccaf6b28b9fe286efa1533e0af5ce57dba11be068aee39e08d1ad5a7796d7d79"
}

rule MalwareBazaar_Mirai_030_2ad9f14b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ad9f14bb36743f1e361f2039aedf0b369958a254b618e172b0240f58191ba47"
    family = "Mirai"
    file_name = "disssh4"
    file_type = "elf"
    first_seen = "2026-10-19 03:03:17"
  condition:
    hash.sha256(0, filesize) == "2ad9f14bb36743f1e361f2039aedf0b369958a254b618e172b0240f58191ba47"
}

rule MalwareBazaar_unknown_031_a1284c71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1284c71db02401df19887a51a738b39fcd5c96716a26bf6cfd0f7de3a5619a3"
    family = "unknown"
    file_name = "bot_mips"
    file_type = "elf"
    first_seen = "2026-10-19 02:34:47"
  condition:
    hash.sha256(0, filesize) == "a1284c71db02401df19887a51a738b39fcd5c96716a26bf6cfd0f7de3a5619a3"
}

rule MalwareBazaar_unknown_032_5c0c2965
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c0c2965baddcf82f7edd84d959f151d3180cd687e6d65f78f095c015954cc96"
    family = "unknown"
    file_name = "bot_mips64le"
    file_type = "elf"
    first_seen = "2026-10-19 02:31:18"
  condition:
    hash.sha256(0, filesize) == "5c0c2965baddcf82f7edd84d959f151d3180cd687e6d65f78f095c015954cc96"
}

rule MalwareBazaar_unknown_033_ec36ef56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec36ef56f434d83d349ce67d2edc544c6f7f13b093713217ca57fdc7fc214601"
    family = "unknown"
    file_name = "bot_arm"
    file_type = "elf"
    first_seen = "2026-10-19 02:16:14"
  condition:
    hash.sha256(0, filesize) == "ec36ef56f434d83d349ce67d2edc544c6f7f13b093713217ca57fdc7fc214601"
}

rule MalwareBazaar_unknown_034_2fcb0f77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fcb0f77a76ae4afe0f8edb6e487f7cd31723af5f05d8b99742905b4cf645a04"
    family = "unknown"
    file_name = "bot_arm64"
    file_type = "elf"
    first_seen = "2026-10-19 02:16:11"
  condition:
    hash.sha256(0, filesize) == "2fcb0f77a76ae4afe0f8edb6e487f7cd31723af5f05d8b99742905b4cf645a04"
}

rule MalwareBazaar_unknown_035_9faa8777
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9faa8777e0cbb5751123e356ded1e8d3f2681064ae3bfdc048e6f7666c511033"
    family = "unknown"
    file_name = "Phantom.exe"
    file_type = "exe"
    first_seen = "2026-10-19 02:03:00"
  condition:
    hash.sha256(0, filesize) == "9faa8777e0cbb5751123e356ded1e8d3f2681064ae3bfdc048e6f7666c511033"
}

rule MalwareBazaar_Mirai_036_10a76ea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10a76ea06517991202d6766a1d55e5aba67e81600f67ea55bcbf5363ac1f6d42"
    family = "Mirai"
    file_name = "adb.arm7"
    file_type = "elf"
    first_seen = "2026-10-19 02:00:59"
  condition:
    hash.sha256(0, filesize) == "10a76ea06517991202d6766a1d55e5aba67e81600f67ea55bcbf5363ac1f6d42"
}

rule MalwareBazaar_Mirai_037_cf5d3dcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf5d3dcba7d9e58e808501a6867b99f4a28060891e37050be2ed1fff5f517b0a"
    family = "Mirai"
    file_name = "dissarm6"
    file_type = "elf"
    first_seen = "2026-10-19 01:47:23"
  condition:
    hash.sha256(0, filesize) == "cf5d3dcba7d9e58e808501a6867b99f4a28060891e37050be2ed1fff5f517b0a"
}

rule MalwareBazaar_AMOS_038_40dc77a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c"
    family = "AMOS"
    file_name = "macho_40dc77a48faa.bin"
    file_type = "macho"
    first_seen = "2026-10-19 01:46:31"
  condition:
    hash.sha256(0, filesize) == "40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c"
}

rule MalwareBazaar_AMOS_039_eae1ad55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eae1ad551a79a4c8333b098258aab12566f538efcc0c8a3166bcf2f26a0ae2c5"
    family = "AMOS"
    file_name = "macho_eae1ad551a79.bin"
    file_type = "macho"
    first_seen = "2026-10-19 01:43:19"
  condition:
    hash.sha256(0, filesize) == "eae1ad551a79a4c8333b098258aab12566f538efcc0c8a3166bcf2f26a0ae2c5"
}

rule MalwareBazaar_AMOS_040_447cc1be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "447cc1be6fdca78d738314f2d56b7981d7369247cdf8e97d548946f6f9919244"
    family = "AMOS"
    file_name = "macho_447cc1be6fdc.bin"
    file_type = "macho"
    first_seen = "2026-10-19 01:40:13"
  condition:
    hash.sha256(0, filesize) == "447cc1be6fdca78d738314f2d56b7981d7369247cdf8e97d548946f6f9919244"
}

rule MalwareBazaar_Mirai_041_c60641f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c60641f340d10694fe999d6ac39d74de35aadb3b9e0c5dbac98dda7e35febdd6"
    family = "Mirai"
    file_name = "adissarm5"
    file_type = "elf"
    first_seen = "2026-10-19 01:34:06"
  condition:
    hash.sha256(0, filesize) == "c60641f340d10694fe999d6ac39d74de35aadb3b9e0c5dbac98dda7e35febdd6"
}

rule MalwareBazaar_unknown_042_7c70782a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c70782ad24660bc90117473dfeca948075d0de5244ea47da6e6e87a7fc2d550"
    family = "unknown"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-19 01:27:10"
  condition:
    hash.sha256(0, filesize) == "7c70782ad24660bc90117473dfeca948075d0de5244ea47da6e6e87a7fc2d550"
}

rule MalwareBazaar_unknown_043_72dcf3b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72dcf3b5d7cd9832908d30bc412ada04e8ed3124e66494d14c6f0714e44dee22"
    family = "unknown"
    file_name = "72dcf3b5d7cd9832.bin"
    file_type = "exe"
    first_seen = "2026-10-19 01:26:11"
  condition:
    hash.sha256(0, filesize) == "72dcf3b5d7cd9832908d30bc412ada04e8ed3124e66494d14c6f0714e44dee22"
}

rule MalwareBazaar_Mirai_044_c6504ab6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6504ab6ba9ab6453092ac9da059559b4dde092aae898cd1cbdd930c6e5fa2f1"
    family = "Mirai"
    file_name = "c6504ab6ba9ab645.bin"
    file_type = "elf"
    first_seen = "2026-10-19 01:26:02"
  condition:
    hash.sha256(0, filesize) == "c6504ab6ba9ab6453092ac9da059559b4dde092aae898cd1cbdd930c6e5fa2f1"
}

rule MalwareBazaar_unknown_045_d0a8249c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0a8249c6dd019cdbe2aff5d89d0188250ffa8496bb7d887ccf8897855c2dd2c"
    family = "unknown"
    file_name = "d0a8249c6dd019cd.bin"
    file_type = "elf"
    first_seen = "2026-10-19 01:25:54"
  condition:
    hash.sha256(0, filesize) == "d0a8249c6dd019cdbe2aff5d89d0188250ffa8496bb7d887ccf8897855c2dd2c"
}

rule MalwareBazaar_Mirai_046_1ec4a6bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ec4a6bdc648657e80fe7ad8a7f6e70e65d0b647b6eca9bb87383f1ad3c7285f"
    family = "Mirai"
    file_name = "1ec4a6bdc648657e.bin"
    file_type = "elf"
    first_seen = "2026-10-19 01:25:45"
  condition:
    hash.sha256(0, filesize) == "1ec4a6bdc648657e80fe7ad8a7f6e70e65d0b647b6eca9bb87383f1ad3c7285f"
}

rule MalwareBazaar_unknown_047_b7e5ba1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7e5ba1d340718247c4fa0bb1705cbb63ff875edad3baa81b62cd4d55e7676ce"
    family = "unknown"
    file_name = "b7e5ba1d34071824.bin"
    file_type = "macho"
    first_seen = "2026-10-19 01:25:36"
  condition:
    hash.sha256(0, filesize) == "b7e5ba1d340718247c4fa0bb1705cbb63ff875edad3baa81b62cd4d55e7676ce"
}

rule MalwareBazaar_unknown_048_1931e1ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1931e1ea251e762ae6a9af8b4fdfc6ad84de26701c16d6b3028453b3690ebe76"
    family = "unknown"
    file_name = "1931e1ea251e762a.bin"
    file_type = "macho"
    first_seen = "2026-10-19 01:25:27"
  condition:
    hash.sha256(0, filesize) == "1931e1ea251e762ae6a9af8b4fdfc6ad84de26701c16d6b3028453b3690ebe76"
}

rule MalwareBazaar_Mirai_049_131479d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "131479d9f3e5946bea46578ad2356ce60b507d406c844aa36f9470610a979354"
    family = "Mirai"
    file_name = "131479d9f3e5946bea46578ad2356ce60b507d406c844aa36f9470610a979354.elf"
    file_type = "elf"
    first_seen = "2026-10-19 01:11:33"
  condition:
    hash.sha256(0, filesize) == "131479d9f3e5946bea46578ad2356ce60b507d406c844aa36f9470610a979354"
}

rule MalwareBazaar_VShell_050_49a73e2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49a73e2e4621af6e6a2f6c3ba3e5a1380cab49a21d89c501659eb7f6188a5483"
    family = "VShell"
    file_name = "2ffcc2cd369d9b59752154520fc6bf2b.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:31"
  condition:
    hash.sha256(0, filesize) == "49a73e2e4621af6e6a2f6c3ba3e5a1380cab49a21d89c501659eb7f6188a5483"
}

rule MalwareBazaar_VShell_051_251b4c12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "251b4c120712ffab8d4dffd968d3657ae6e7bc698593b726af2f415d1867578f"
    family = "VShell"
    file_name = "0e1d1d6b59447eff7fe7619284a4b298.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:27"
  condition:
    hash.sha256(0, filesize) == "251b4c120712ffab8d4dffd968d3657ae6e7bc698593b726af2f415d1867578f"
}

rule MalwareBazaar_RemusStealer_052_fd240746
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd240746ebef01cd378b4ffea19cdf139d44960caf41f88dce4bbab8faceb7d7"
    family = "RemusStealer"
    file_name = "398fab919e699bc954eb11db12962965.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:23"
  condition:
    hash.sha256(0, filesize) == "fd240746ebef01cd378b4ffea19cdf139d44960caf41f88dce4bbab8faceb7d7"
}

rule MalwareBazaar_ValleyRAT_053_4421ccd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4421ccd153aa864e3eb4ac89044c92eba48a1ecca7efc759203368004a7ded05"
    family = "ValleyRAT"
    file_name = "3D07FA7F9489DD52A1DCA5811C000096.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:16"
  condition:
    hash.sha256(0, filesize) == "4421ccd153aa864e3eb4ac89044c92eba48a1ecca7efc759203368004a7ded05"
}

rule MalwareBazaar_ValleyRAT_054_8bf1aefe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bf1aefe99486ba24e1bce15035046809d9af0d8d98e0b58c23c38456749b09e"
    family = "ValleyRAT"
    file_name = "09e226a3ade6b9d479d1b19b1d534dcb.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:11"
  condition:
    hash.sha256(0, filesize) == "8bf1aefe99486ba24e1bce15035046809d9af0d8d98e0b58c23c38456749b09e"
}

rule MalwareBazaar_njrat_055_6b39054c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b39054cd0facc18c46cf4ad3bdab92072a34933fab5cf67adefeb787e78b11c"
    family = "njrat"
    file_name = "08637a5f2fb2789dd0f9e3f186001bed.exe"
    file_type = "exe"
    first_seen = "2026-10-19 01:10:06"
  condition:
    hash.sha256(0, filesize) == "6b39054cd0facc18c46cf4ad3bdab92072a34933fab5cf67adefeb787e78b11c"
}

rule MalwareBazaar_unknown_056_90003d7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90003d7c7be95da3a2d5a6160f71c3fb2fe3a463c2419345fc7fc7081d06a380"
    family = "unknown"
    file_name = "bot_ppc64"
    file_type = "elf"
    first_seen = "2026-10-19 00:55:35"
  condition:
    hash.sha256(0, filesize) == "90003d7c7be95da3a2d5a6160f71c3fb2fe3a463c2419345fc7fc7081d06a380"
}

rule MalwareBazaar_unknown_057_ca82f79b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca82f79b9262ed0d97bd262afdb1cac993ef52eb478512c5659cc240fefb562b"
    family = "unknown"
    file_name = "ADNOC ContractorVendorSuppliers' Enrollment For The 20262027 Projects.vbs"
    file_type = "vbs"
    first_seen = "2026-10-19 00:50:40"
  condition:
    hash.sha256(0, filesize) == "ca82f79b9262ed0d97bd262afdb1cac993ef52eb478512c5659cc240fefb562b"
}

rule MalwareBazaar_unknown_058_3f7089c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f7089c857d85f2e3f7d9d2f5788649e4e3520d3fd575000b1d1e8db9022c263"
    family = "unknown"
    file_name = "MV S-BREEZE VESSEL PARTICULARS.js"
    file_type = "js"
    first_seen = "2026-10-19 00:38:43"
  condition:
    hash.sha256(0, filesize) == "3f7089c857d85f2e3f7d9d2f5788649e4e3520d3fd575000b1d1e8db9022c263"
}

rule MalwareBazaar_unknown_059_70c5abd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70c5abd20b484a7691fcc7188c1ad2f970ee6c426897a346f0f10f68a6666b20"
    family = "unknown"
    file_name = "70c5abd20b484a76.bin"
    file_type = "macho"
    first_seen = "2026-10-19 00:26:18"
  condition:
    hash.sha256(0, filesize) == "70c5abd20b484a7691fcc7188c1ad2f970ee6c426897a346f0f10f68a6666b20"
}

rule MalwareBazaar_unknown_060_ce6978f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce6978f97f4fec247c87d9a0323891169ca645c6602e0c969ba48fdf53895a8a"
    family = "unknown"
    file_name = "ce6978f97f4fec24.bin"
    file_type = "macho"
    first_seen = "2026-10-19 00:26:11"
  condition:
    hash.sha256(0, filesize) == "ce6978f97f4fec247c87d9a0323891169ca645c6602e0c969ba48fdf53895a8a"
}

rule MalwareBazaar_unknown_061_9f6ac6b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f6ac6b4abb82120b339a282ac8cdd5f49c4ef25d10d608f3bd02963201af665"
    family = "unknown"
    file_name = "9f6ac6b4abb82120.bin"
    file_type = "elf"
    first_seen = "2026-10-19 00:26:03"
  condition:
    hash.sha256(0, filesize) == "9f6ac6b4abb82120b339a282ac8cdd5f49c4ef25d10d608f3bd02963201af665"
}

rule MalwareBazaar_Snowlight_062_d3a26db9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3a26db9b714a3b54c5a7aea6bef5ad93312e03d1fc120e637b4f228ec8dacc4"
    family = "Snowlight"
    file_name = "d3a26db9b714a3b5.bin"
    file_type = "elf"
    first_seen = "2026-10-19 00:25:55"
  condition:
    hash.sha256(0, filesize) == "d3a26db9b714a3b54c5a7aea6bef5ad93312e03d1fc120e637b4f228ec8dacc4"
}

rule MalwareBazaar_Snowlight_063_b116aefe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b116aefeb274d95fdd609567f73885e39621a2c72d9b10eb271c1f3a29389f08"
    family = "Snowlight"
    file_name = "b116aefeb274d95f.bin"
    file_type = "elf"
    first_seen = "2026-10-19 00:25:47"
  condition:
    hash.sha256(0, filesize) == "b116aefeb274d95fdd609567f73885e39621a2c72d9b10eb271c1f3a29389f08"
}

rule MalwareBazaar_WannaCry_064_423dc680
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "423dc680eb30439391632cf05fde7dbc6d81f31e382454989051cd04e51705d1"
    family = "WannaCry"
    file_name = "423dc680eb30439391632cf05fde7dbc6d81f31e382454989051cd04e51705d1"
    file_type = "exe"
    first_seen = "2026-10-19 00:15:08"
  condition:
    hash.sha256(0, filesize) == "423dc680eb30439391632cf05fde7dbc6d81f31e382454989051cd04e51705d1"
}

rule MalwareBazaar_Mirai_065_86788ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86788ddca0dcb082532fcf7bdbac3486a57c277fe64447fc1a42d5ccd6101332"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-19 00:13:44"
  condition:
    hash.sha256(0, filesize) == "86788ddca0dcb082532fcf7bdbac3486a57c277fe64447fc1a42d5ccd6101332"
}

rule MalwareBazaar_AMOS_066_0119e2bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f"
    family = "AMOS"
    file_name = "macho_0119e2bc2281.bin"
    file_type = "macho"
    first_seen = "2026-10-19 00:09:42"
  condition:
    hash.sha256(0, filesize) == "0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f"
}

rule MalwareBazaar_AMOS_067_ff9c8f57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598"
    family = "AMOS"
    file_name = "macho_ff9c8f57fa3e.bin"
    file_type = "macho"
    first_seen = "2026-10-19 00:04:52"
  condition:
    hash.sha256(0, filesize) == "ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598"
}

rule MalwareBazaar_Mirai_068_6261cf6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6261cf6d60051c557b8e09a6f8e7ac9fa0199c487df72c5492baf96b3802aead"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-19 00:00:59"
  condition:
    hash.sha256(0, filesize) == "6261cf6d60051c557b8e09a6f8e7ac9fa0199c487df72c5492baf96b3802aead"
}

rule MalwareBazaar_Mirai_069_1410244e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1410244e815eabf714a977ab9b20372c270046ec5bd90c8e05e94bf62386d9b5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-18 23:54:15"
  condition:
    hash.sha256(0, filesize) == "1410244e815eabf714a977ab9b20372c270046ec5bd90c8e05e94bf62386d9b5"
}

rule MalwareBazaar_Mirai_070_3ed85e9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ed85e9cd1b68ad525101e63ab867fc5b3a31e195b88ef82b7a1096bdde68841"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-18 23:51:10"
  condition:
    hash.sha256(0, filesize) == "3ed85e9cd1b68ad525101e63ab867fc5b3a31e195b88ef82b7a1096bdde68841"
}

rule MalwareBazaar_Mirai_071_671574f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "671574f7454bbe4cc277d9caa4c513d2ccc11073f46f9a3f5998136fe0ef9927"
    family = "Mirai"
    file_name = "dissmips"
    file_type = "elf"
    first_seen = "2026-10-18 23:51:08"
  condition:
    hash.sha256(0, filesize) == "671574f7454bbe4cc277d9caa4c513d2ccc11073f46f9a3f5998136fe0ef9927"
}

rule MalwareBazaar_Mirai_072_03e2f619
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03e2f6194b0252b1e157f33a4f673973fbeab3a95604181fb0fcb064a815ba60"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-18 23:48:04"
  condition:
    hash.sha256(0, filesize) == "03e2f6194b0252b1e157f33a4f673973fbeab3a95604181fb0fcb064a815ba60"
}

rule MalwareBazaar_unknown_073_93de911f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93de911f3ec5cb14664ade2b7885b1d643ac951c564f1453e795eec9e3ba7129"
    family = "unknown"
    file_name = "8yga71.sh"
    file_type = "sh"
    first_seen = "2026-10-18 23:44:58"
  condition:
    hash.sha256(0, filesize) == "93de911f3ec5cb14664ade2b7885b1d643ac951c564f1453e795eec9e3ba7129"
}

rule MalwareBazaar_AMOS_074_b5d4aba0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298"
    family = "AMOS"
    file_name = "macho_b5d4aba0fe40.bin"
    file_type = "macho"
    first_seen = "2026-10-18 23:28:21"
  condition:
    hash.sha256(0, filesize) == "b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298"
}

rule MalwareBazaar_AMOS_075_f1089982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f108998292512b5ec1ce20f5f67c15bacf337e53192e36c6f33c09dd4cd6abbd"
    family = "AMOS"
    file_name = "stage1_f10899829251.zsh"
    file_type = "zsh"
    first_seen = "2026-10-18 23:28:15"
  condition:
    hash.sha256(0, filesize) == "f108998292512b5ec1ce20f5f67c15bacf337e53192e36c6f33c09dd4cd6abbd"
}

rule MalwareBazaar_PureLogsStealer_076_34b15908
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34b1590817537f05bfa8ce5fc071287780f798e5aa301aaff1a7eadd6569b265"
    family = "PureLogsStealer"
    file_name = "34b1590817537f05bfa8ce5fc071287780f798e5aa301aaff1a7eadd6569b265.exe"
    file_type = "exe"
    first_seen = "2026-10-18 23:21:39"
  condition:
    hash.sha256(0, filesize) == "34b1590817537f05bfa8ce5fc071287780f798e5aa301aaff1a7eadd6569b265"
}

rule MalwareBazaar_Mirai_077_ece8528f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ece8528fe3f27d206dbe159c78f315cfc191fb7415ca8cf0112086150d4120b3"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-18 22:39:28"
  condition:
    hash.sha256(0, filesize) == "ece8528fe3f27d206dbe159c78f315cfc191fb7415ca8cf0112086150d4120b3"
}

rule MalwareBazaar_Mirai_078_4efb335b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4efb335bc6357df3b48ed5e73db1fe454c926f6015bd4447b9386eb8f13fb7cc"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-18 22:33:02"
  condition:
    hash.sha256(0, filesize) == "4efb335bc6357df3b48ed5e73db1fe454c926f6015bd4447b9386eb8f13fb7cc"
}

rule MalwareBazaar_MacSync_079_61f8e4e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61f8e4e3e263934a04d18e29fd5edaa0840b1a8137b649e8241e5bae013f200d"
    family = "MacSync"
    file_name = "stage1_61f8e4e3e263.zsh"
    file_type = "zsh"
    first_seen = "2026-10-18 22:27:13"
  condition:
    hash.sha256(0, filesize) == "61f8e4e3e263934a04d18e29fd5edaa0840b1a8137b649e8241e5bae013f200d"
}

rule MalwareBazaar_AMOS_080_371cd811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "371cd811b69df8544c9dd43df74afd3d6db210edc7b3d3c124e9bbc7d0638816"
    family = "AMOS"
    file_name = "macho_371cd811b69d.bin"
    file_type = "macho"
    first_seen = "2026-10-18 22:25:09"
  condition:
    hash.sha256(0, filesize) == "371cd811b69df8544c9dd43df74afd3d6db210edc7b3d3c124e9bbc7d0638816"
}

rule MalwareBazaar_Mirai_081_51d17edc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51d17edc97d157620defeb37c7b3aa6516869ae0e4c9564781cde51ea59628d6"
    family = "Mirai"
    file_name = "51d17edc97d157620defeb37c7b3aa6516869ae0e4c9564781cde51ea59628d6.elf"
    file_type = "elf"
    first_seen = "2026-10-18 22:16:30"
  condition:
    hash.sha256(0, filesize) == "51d17edc97d157620defeb37c7b3aa6516869ae0e4c9564781cde51ea59628d6"
}

rule MalwareBazaar_Mirai_082_9a05910f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a05910fedc8ea2f92e3f223740d147e3a731dfdc2b697432d9c1ee2142fd803"
    family = "Mirai"
    file_name = "dissmpsl"
    file_type = "elf"
    first_seen = "2026-10-18 22:09:56"
  condition:
    hash.sha256(0, filesize) == "9a05910fedc8ea2f92e3f223740d147e3a731dfdc2b697432d9c1ee2142fd803"
}

rule MalwareBazaar_Mirai_083_90d26570
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90d265704bba45a63037136dd348e05221569b6e90033270d4ee1d82f863dce6"
    family = "Mirai"
    file_name = "jklmpsl"
    file_type = "elf"
    first_seen = "2026-10-18 22:03:11"
  condition:
    hash.sha256(0, filesize) == "90d265704bba45a63037136dd348e05221569b6e90033270d4ee1d82f863dce6"
}

rule MalwareBazaar_Mirai_084_341df173
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "341df173a5a6bb6c29fc10b5e711cfac5137441db164fbf47408cd1ed9c0e5f6"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-18 21:59:53"
  condition:
    hash.sha256(0, filesize) == "341df173a5a6bb6c29fc10b5e711cfac5137441db164fbf47408cd1ed9c0e5f6"
}

rule MalwareBazaar_Mirai_085_8709b33b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8709b33b1ecdf875070f5d17ff8ccb39a652813a8b2ea6eba4d576bbd50c4b2e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-18 21:59:51"
  condition:
    hash.sha256(0, filesize) == "8709b33b1ecdf875070f5d17ff8ccb39a652813a8b2ea6eba4d576bbd50c4b2e"
}

rule MalwareBazaar_Mirai_086_62f65b33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62f65b335e3a7d4cf806440134105f533ce5f639856a2edaea03013217bf6ec4"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-18 21:59:47"
  condition:
    hash.sha256(0, filesize) == "62f65b335e3a7d4cf806440134105f533ce5f639856a2edaea03013217bf6ec4"
}

rule MalwareBazaar_unknown_087_598d8e60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "598d8e60da3039e42c7f50aa015bb4536053152dd108bb2ad8ddebb8a9ae7249"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-18 21:57:41"
  condition:
    hash.sha256(0, filesize) == "598d8e60da3039e42c7f50aa015bb4536053152dd108bb2ad8ddebb8a9ae7249"
}

rule MalwareBazaar_Mirai_088_6079816d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6079816d1a3be67178175549197a44fd939f306332ea67799ce06301ad25d8d3"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-18 21:56:29"
  condition:
    hash.sha256(0, filesize) == "6079816d1a3be67178175549197a44fd939f306332ea67799ce06301ad25d8d3"
}

rule MalwareBazaar_Mirai_089_79be4047
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79be40471ef3344bbf30712fddee64e4b1d9e50747ce72205052ed71a3fa0b06"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-18 21:56:27"
  condition:
    hash.sha256(0, filesize) == "79be40471ef3344bbf30712fddee64e4b1d9e50747ce72205052ed71a3fa0b06"
}

rule MalwareBazaar_Mirai_090_cc7872eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc7872eb663295da180c9bfb5cb0bbbea0275537b0bd676e23fcf12533bd05d6"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-18 21:56:24"
  condition:
    hash.sha256(0, filesize) == "cc7872eb663295da180c9bfb5cb0bbbea0275537b0bd676e23fcf12533bd05d6"
}

rule MalwareBazaar_Mirai_091_767f289c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "767f289c4f916a3dbb3d82435c1e5755a63d7d689f4536f54c90f7b2b078dff3"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-18 21:56:22"
  condition:
    hash.sha256(0, filesize) == "767f289c4f916a3dbb3d82435c1e5755a63d7d689f4536f54c90f7b2b078dff3"
}

rule MalwareBazaar_Mirai_092_f2c82533
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2c8253354f500ce620b8794edc18a1aecb217c0021d86c73fd858a591ec653b"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-18 21:56:19"
  condition:
    hash.sha256(0, filesize) == "f2c8253354f500ce620b8794edc18a1aecb217c0021d86c73fd858a591ec653b"
}

rule MalwareBazaar_Mirai_093_bd90fa0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd90fa0a64f8482a0a1a56b85daf11129b5ea373e0df93260a2da096fd011f7d"
    family = "Mirai"
    file_name = "jklm68k"
    file_type = "elf"
    first_seen = "2026-10-18 21:50:04"
  condition:
    hash.sha256(0, filesize) == "bd90fa0a64f8482a0a1a56b85daf11129b5ea373e0df93260a2da096fd011f7d"
}

rule MalwareBazaar_Mirai_094_438b9c35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "438b9c35cc8b0a24b63848f50b934c03479937e0ec10a2424c904686aebbac46"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-10-18 21:09:37"
  condition:
    hash.sha256(0, filesize) == "438b9c35cc8b0a24b63848f50b934c03479937e0ec10a2424c904686aebbac46"
}

rule MalwareBazaar_Mirai_095_cf546661
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf54666174d7e8b7c3b2077029476608b570d65b1b3b58c1c0b03663555d1527"
    family = "Mirai"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-18 21:06:40"
  condition:
    hash.sha256(0, filesize) == "cf54666174d7e8b7c3b2077029476608b570d65b1b3b58c1c0b03663555d1527"
}

rule MalwareBazaar_unknown_096_188a79e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "188a79e5b0aeb2656c15fc167bac923b94752b98996f1981e95c173729ce7a0f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-18 20:41:52"
  condition:
    hash.sha256(0, filesize) == "188a79e5b0aeb2656c15fc167bac923b94752b98996f1981e95c173729ce7a0f"
}

rule MalwareBazaar_unknown_097_f731bd0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f731bd0c7a45984dc706a425ae02844dcf20b357cee27c60e407e0ca1a2aefa2"
    family = "unknown"
    file_name = "f731bd0c7a45984dc706a425ae02844dcf20b357cee27c60e407e0ca1a2aefa2.exe"
    file_type = "exe"
    first_seen = "2026-10-18 20:27:38"
  condition:
    hash.sha256(0, filesize) == "f731bd0c7a45984dc706a425ae02844dcf20b357cee27c60e407e0ca1a2aefa2"
}

rule MalwareBazaar_unknown_098_dfadfad8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfadfad813e1fcdbad43cc2b26e1a2ad8c3bac2665e760803aa9c7b234528fca"
    family = "unknown"
    file_name = "dfadfad813e1fcdbad43cc2b26e1a2ad8c3bac2665e760803aa9c7b234528fca.exe"
    file_type = "exe"
    first_seen = "2026-10-18 20:27:33"
  condition:
    hash.sha256(0, filesize) == "dfadfad813e1fcdbad43cc2b26e1a2ad8c3bac2665e760803aa9c7b234528fca"
}

rule MalwareBazaar_unknown_099_ac630d2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac630d2e5a5bc25e8c743cde099dc65087aa8fc35e5e0b354e6a74d630be752d"
    family = "unknown"
    file_name = "ac630d2e5a5bc25e8c743cde099dc65087aa8fc35e5e0b354e6a74d630be752d.exe"
    file_type = "exe"
    first_seen = "2026-10-18 20:27:28"
  condition:
    hash.sha256(0, filesize) == "ac630d2e5a5bc25e8c743cde099dc65087aa8fc35e5e0b354e6a74d630be752d"
}

rule MalwareBazaar_SalatStealer_100_2b853517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b8535175e93436354114e5a11c0dc8a92fa440b97bbcfccb9d9f34a7ac9daed"
    family = "SalatStealer"
    file_name = "g3.exe"
    file_type = "exe"
    first_seen = "2026-10-18 20:23:26"
  condition:
    hash.sha256(0, filesize) == "2b8535175e93436354114e5a11c0dc8a92fa440b97bbcfccb9d9f34a7ac9daed"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

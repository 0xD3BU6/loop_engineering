# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-17

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 662 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 662 |
| Unique family labels | 9 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 45 |
| unknown | 39 |
| AMOS | 6 |
| Vidar | 4 |
| ConnectWise | 2 |
| Adware.Generic | 1 |
| NanoCore | 1 |
| ValleyRAT | 1 |
| GhostPulse | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 57 |
| exe | 30 |
| macho | 6 |
| dll | 2 |
| sh | 2 |
| msi | 1 |
| js | 1 |
| zip | 1 |

## Per-Sample Analysis

### Sample 1: `7ad81cd5580035c6`

| Field | Value |
|---|---|
| SHA-256 | `7ad81cd5580035c6e048d12a76a82b85b0f3278cedf9f55c6fceab171820cfd2` |
| Family label | `Adware.Generic` |
| File name | `7ad81cd5580035c6e048d12a76a82b85b0f3278cedf9f55c6fceab171820cfd2.exe` |
| File type | `exe` |
| First seen | `2026-10-17 04:26:11` |
| Reporter | `Tuxxin` |
| Tags | `Adware.Generic, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `414654138697b0f8fe04e8a6c5b0c5cc` |
| SHA-1 | `86edd55c3fa394fb4493c2e20a06d28681305d8c` |
| SHA-256 | `7ad81cd5580035c6e048d12a76a82b85b0f3278cedf9f55c6fceab171820cfd2` |
| SHA3-384 | `1841bea164efd5b200c5ca13da7fe533cc35b07996ed1fa8d30d82d5959bfddb84c19fc154067bb8159ce81693a5364a` |
| IMPHASH | `e569e6f445d32ba23766ad67d1e3787f` |
| TLSH | `T18737333FF25CE53EC46F0A3285B292109A777A15640A8C1EA3FC744DCF769601E3B696` |
| SSDEEP | `393216:RTXZK22o6WYPmRaLeoTh/Dyi8y//+iGFV0N+bxYMWFBnjrNbuF1zTCyPjgo98:Rzk22o6maLeoTclo2iGbkFBnjp4z+yPW` |
| ICON-DHASH | `5050d270cccc82ae` |

#### Technical Assessment

- The sample is tracked as `Adware.Generic` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_Generic_001_7ad81cd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ad81cd5580035c6e048d12a76a82b85b0f3278cedf9f55c6fceab171820cfd2"
    family = "Adware.Generic"
    file_name = "7ad81cd5580035c6e048d12a76a82b85b0f3278cedf9f55c6fceab171820cfd2.exe"
    file_type = "exe"
    first_seen = "2026-10-17 04:26:11"
  condition:
    hash.sha256(0, filesize) == "7ad81cd5580035c6e048d12a76a82b85b0f3278cedf9f55c6fceab171820cfd2"
}
```

### Sample 2: `e0a7753a0bcd1162`

| Field | Value |
|---|---|
| SHA-256 | `e0a7753a0bcd11621a102e4d0cf5e7a1b1fb7eb3dd2996ad765f00fb288b90a2` |
| Family label | `Mirai` |
| File name | `e0a7753a0bcd1162.bin` |
| File type | `elf` |
| First seen | `2026-10-17 04:25:50` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b74179607cc478829577a0013c8ea9a0` |
| SHA-1 | `5a23e1d098d64addb674718236ac18947395c25d` |
| SHA-256 | `e0a7753a0bcd11621a102e4d0cf5e7a1b1fb7eb3dd2996ad765f00fb288b90a2` |
| SHA3-384 | `ba5d28c9266368988c27e66911d95cbbf642bd0c72062da6beb31b8ac2e91a74317932827be3b9812454760f6409c5a8` |
| TLSH | `T1A4140A87B5B9AAA1CAE74439B19403BC724683AAD3FEB00DCE154DD1FB5D4016A3D2C7` |
| SSDEEP | `3072:nSI8oq0oq0D4J8Aje48A/wLnDQLyUG/jaDKEp3LSZiXK9uXkPg:nSI8HaNpp8A/wLnsLyUG/QLSH9Bg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_e0a7753a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0a7753a0bcd11621a102e4d0cf5e7a1b1fb7eb3dd2996ad765f00fb288b90a2"
    family = "Mirai"
    file_name = "e0a7753a0bcd1162.bin"
    file_type = "elf"
    first_seen = "2026-10-17 04:25:50"
  condition:
    hash.sha256(0, filesize) == "e0a7753a0bcd11621a102e4d0cf5e7a1b1fb7eb3dd2996ad765f00fb288b90a2"
}
```

### Sample 3: `a3e4d8b0ba72c138`

| Field | Value |
|---|---|
| SHA-256 | `a3e4d8b0ba72c13852d1d7a33a15993755c4b01529c3cf344d376774fa24a8b5` |
| Family label | `unknown` |
| File name | `a3e4d8b0ba72c138.bin` |
| File type | `dll` |
| First seen | `2026-10-17 04:25:41` |
| Reporter | `Tuxxin` |
| Tags | `dll, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b4c3b58df5a792652e4a49351411a53` |
| SHA-1 | `9f9463b7b55d08865cf3a49f667a7da0a2931e98` |
| SHA-256 | `a3e4d8b0ba72c13852d1d7a33a15993755c4b01529c3cf344d376774fa24a8b5` |
| SHA3-384 | `51718739275a6a5c1a03c1f72c6db6d2007efe7cdb18bf3f7919c8e4fd90a10fa1afa8475d75c3ab6e671560f4127437` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T11641CE272BF90163E76B17B00CA3075417B2E9A89B32C65E2B44416CAF026949F71F93` |
| SSDEEP | `24:etGSvjI4D8eMhetzFIzMkm+taqFwtsuL+v8FwtsPIfls3V:6vjI4D81hCzpkBB2z+82UI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_a3e4d8b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3e4d8b0ba72c13852d1d7a33a15993755c4b01529c3cf344d376774fa24a8b5"
    family = "unknown"
    file_name = "a3e4d8b0ba72c138.bin"
    file_type = "dll"
    first_seen = "2026-10-17 04:25:41"
  condition:
    hash.sha256(0, filesize) == "a3e4d8b0ba72c13852d1d7a33a15993755c4b01529c3cf344d376774fa24a8b5"
}
```

### Sample 4: `e14647c08925cce2`

| Field | Value |
|---|---|
| SHA-256 | `e14647c08925cce2d51fc520ffe34d3c4ff41015ddaeea274836c1832d6b8ef8` |
| Family label | `unknown` |
| File name | `e14647c08925cce2.bin` |
| File type | `dll` |
| First seen | `2026-10-17 04:25:32` |
| Reporter | `Tuxxin` |
| Tags | `dll, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b19cc42fbf6b424be8e18aa4bbcffc57` |
| SHA-1 | `eba3cba0ab03308108f6ed18fc0daf46e1aea170` |
| SHA-256 | `e14647c08925cce2d51fc520ffe34d3c4ff41015ddaeea274836c1832d6b8ef8` |
| SHA3-384 | `7cd1bda71ba2e4a5389c0b5c0ee5ae15a144c14c452ed46535a7a85fc20f31f8190a6d681d7b4aec1376f759f8dab3b7` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T199B19502BBE48237F0BF477456A34B3057B2B6658622C7AE1DC4916D6CA2558CB327A3` |
| SSDEEP | `48:6uHZSWgcJDTwEiJ4CndXaGb5szy+/z/Ws5j+lZUQNodxprl1XRvqOPulU0e1I:55SCRVGBaUSZz/+UtH/ai0e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_e14647c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e14647c08925cce2d51fc520ffe34d3c4ff41015ddaeea274836c1832d6b8ef8"
    family = "unknown"
    file_name = "e14647c08925cce2.bin"
    file_type = "dll"
    first_seen = "2026-10-17 04:25:32"
  condition:
    hash.sha256(0, filesize) == "e14647c08925cce2d51fc520ffe34d3c4ff41015ddaeea274836c1832d6b8ef8"
}
```

### Sample 5: `679372386b687d4a`

| Field | Value |
|---|---|
| SHA-256 | `679372386b687d4aa79d13af9e2929cdfd1ab1e388eaeac1a31c81f08ad84c37` |
| Family label | `unknown` |
| File name | `warden_a1c9f2ad_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-10-17 03:34:30` |
| Reporter | `Daydream` |
| Tags | `exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0482e2ad8e3cd587bb0010d013552da0` |
| SHA-1 | `51d5db258410f5ba1aeef823fb9b5e78becce63e` |
| SHA-256 | `679372386b687d4aa79d13af9e2929cdfd1ab1e388eaeac1a31c81f08ad84c37` |
| SHA3-384 | `c7409427f942abe708e622289125680ec77f474572c6234635dbe2345cf4036f2a4e8f95be5ca1ab3be5eee560aabbf1` |
| IMPHASH | `7cacdd7b2bdb99de3c4adff902872079` |
| TLSH | `T151845B17F68401B4D45DD5B88B69D623B5A0BC4C8B34B6EF0BF04A921F21BE4B779709` |
| SSDEEP | `6144:bxv69asT6+FV0G8FG1bvEponeBubf/5CouPzDNa5FRrR:VATrFh8YWCl/AzDNw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_67937238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "679372386b687d4aa79d13af9e2929cdfd1ab1e388eaeac1a31c81f08ad84c37"
    family = "unknown"
    file_name = "warden_a1c9f2ad_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:34:30"
  condition:
    hash.sha256(0, filesize) == "679372386b687d4aa79d13af9e2929cdfd1ab1e388eaeac1a31c81f08ad84c37"
}
```

### Sample 6: `2b4bb4ab724ee6f0`

| Field | Value |
|---|---|
| SHA-256 | `2b4bb4ab724ee6f0741b9366fb6e8ceda68d4cbbd4bb2aed74a7c21cd28c63cb` |
| Family label | `unknown` |
| File name | `warden_6546bdb2_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-10-17 03:34:22` |
| Reporter | `Daydream` |
| Tags | `exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2224a7e29d766443910228814b560c71` |
| SHA-1 | `34273192b56a406e524b4945c0f2e673da87e54e` |
| SHA-256 | `2b4bb4ab724ee6f0741b9366fb6e8ceda68d4cbbd4bb2aed74a7c21cd28c63cb` |
| SHA3-384 | `a4fdac18665f029b107b56bf882b864ddea7f4c60a42ba546cb1d8a633891c4007a4b7e504c0ab2c90356d43288fa94b` |
| IMPHASH | `4f83ff0662c11df8802ed2208b81c48b` |
| TLSH | `T1BDB47D03F28811A9C46EDC74CA5FAD27A2D1FC0D8D64AA2E56261E516FFB770A3DD304` |
| SSDEEP | `6144:+rVdAnFZLb02jwfCxIZqxm9/AgDOGEO9eL/vd1NasIiR/TJ5UjYZmPL:OVdSaCaes6iSMPib6jm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_2b4bb4ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b4bb4ab724ee6f0741b9366fb6e8ceda68d4cbbd4bb2aed74a7c21cd28c63cb"
    family = "unknown"
    file_name = "warden_6546bdb2_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:34:22"
  condition:
    hash.sha256(0, filesize) == "2b4bb4ab724ee6f0741b9366fb6e8ceda68d4cbbd4bb2aed74a7c21cd28c63cb"
}
```

### Sample 7: `bd90b742908dec4c`

| Field | Value |
|---|---|
| SHA-256 | `bd90b742908dec4cd7a1ab54cc6b3e7e36498ee112fd788c1679471eccc59a95` |
| Family label | `unknown` |
| File name | `warden_49902b86_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-10-17 03:34:14` |
| Reporter | `Daydream` |
| Tags | `exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f5c9e66e6127ec7623cecfaa2f4a721` |
| SHA-1 | `1be6b0984b918138c99e55c2c25112732919fd4e` |
| SHA-256 | `bd90b742908dec4cd7a1ab54cc6b3e7e36498ee112fd788c1679471eccc59a95` |
| SHA3-384 | `0f95499e9ed017daa280567341f9d060cec011681ea07fab55de6ab6dd0fe21f5e84e6630af7653cc3b8b92a2080594d` |
| IMPHASH | `fed9f6c7ac95fec59e76a01328067a68` |
| TLSH | `T19EA45C03F59580F7D449C431C69B9233AB22FC5BC934BF6B6B945E217EA6B90B728305` |
| SSDEEP | `12288:423kLgM5LP+IYT2eWVyenwwiXm/I57y0umw1K:42ULgM5LtYT2eWRwwiXm/I5q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_bd90b742
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd90b742908dec4cd7a1ab54cc6b3e7e36498ee112fd788c1679471eccc59a95"
    family = "unknown"
    file_name = "warden_49902b86_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:34:14"
  condition:
    hash.sha256(0, filesize) == "bd90b742908dec4cd7a1ab54cc6b3e7e36498ee112fd788c1679471eccc59a95"
}
```

### Sample 8: `3f49702643263375`

| Field | Value |
|---|---|
| SHA-256 | `3f497026432633757122a8b5a6565b6aef2e1286af56e09d3374aa24c3b525bc` |
| Family label | `unknown` |
| File name | `warden_0c489965_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-10-17 03:34:06` |
| Reporter | `Daydream` |
| Tags | `exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7b73746df4d547814974db4a33bb43c` |
| SHA-1 | `c956ee71ed17752da05b9b3120de26b1398dde4a` |
| SHA-256 | `3f497026432633757122a8b5a6565b6aef2e1286af56e09d3374aa24c3b525bc` |
| SHA3-384 | `b3c6e64b4f175e8d50cfc50349dfc4bf1a45fd420ba3ac998cd1cfce9c9f9a62f7fac76967ce1d2b45237bda0d7ff2d8` |
| IMPHASH | `dfb9ea16b80b08d4e0254bf6bf232dab` |
| TLSH | `T119C45E03F2C541E5D01AC4B5839A5133F675B89F8E30BEBF5B985A622E27BC06B2D345` |
| SSDEEP | `12288:lcsxqRb+iaYo4XH2h2aZjJHHbX/0XP+74mn:lxxqRCGH2h2aJHQfG4M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_3f497026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f497026432633757122a8b5a6565b6aef2e1286af56e09d3374aa24c3b525bc"
    family = "unknown"
    file_name = "warden_0c489965_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:34:06"
  condition:
    hash.sha256(0, filesize) == "3f497026432633757122a8b5a6565b6aef2e1286af56e09d3374aa24c3b525bc"
}
```

### Sample 9: `4d4fbdc2366d9c44`

| Field | Value |
|---|---|
| SHA-256 | `4d4fbdc2366d9c4488d02a12aadc4596b05f3e0b8f855e679bfc425aae3aa72f` |
| Family label | `unknown` |
| File name | `warden_3874acb3_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-10-17 03:33:59` |
| Reporter | `Daydream` |
| Tags | `dropped-by-OffLoader, DvnX, exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b87ff1783d67670773bd44621c77a4f7` |
| SHA-1 | `c268e1571d436d66fa1f346311160abbb1f3352b` |
| SHA-256 | `4d4fbdc2366d9c4488d02a12aadc4596b05f3e0b8f855e679bfc425aae3aa72f` |
| SHA3-384 | `5f26de5dd56806f72460dfeb72a7907c556732aa770012c8cbbafaa5daab174669e923acfeba9a1655d04ad2ab2636e7` |
| IMPHASH | `a6db1588c77974053f453e078df7b1ab` |
| TLSH | `T104E45B13F3A246D8D02AC9B5435A9123F6B47C8D4630B6BF67946B251F36BA0EB3D704` |
| SSDEEP | `12288:zI0fq3ounmQURWTR5pLeNx32Ys/KKcl2wm+nMtxlMUBsg:s0i3o4mQUwRLeNx3k5C2WnTsX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_4d4fbdc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d4fbdc2366d9c4488d02a12aadc4596b05f3e0b8f855e679bfc425aae3aa72f"
    family = "unknown"
    file_name = "warden_3874acb3_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:33:59"
  condition:
    hash.sha256(0, filesize) == "4d4fbdc2366d9c4488d02a12aadc4596b05f3e0b8f855e679bfc425aae3aa72f"
}
```

### Sample 10: `7aa8a13432f1999f`

| Field | Value |
|---|---|
| SHA-256 | `7aa8a13432f1999f37809e8576ea7e442d57e1902e991d11dedbfbdfc156a3de` |
| Family label | `unknown` |
| File name | `warden_a16051a1_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-10-17 03:33:49` |
| Reporter | `Daydream` |
| Tags | `dropped-by-OffLoader, exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0937d25140f9b65990939e77ec2bb707` |
| SHA-1 | `cf0ceaf23749cabd01617db53af238053f7ac951` |
| SHA-256 | `7aa8a13432f1999f37809e8576ea7e442d57e1902e991d11dedbfbdfc156a3de` |
| SHA3-384 | `0b43ab0a91f66adcd750347f1ffd272ba134c469b0c09d66090ef96b987f72fd51d6e7d38207e900f1b84e6657d3cef5` |
| IMPHASH | `456f18caf5a8ddca6bcf277cd2ad3e59` |
| TLSH | `T10BD45B53F39285ECD02AC9B583169233F6B57C884A30BABF67945B251F36BA0D72D704` |
| SSDEEP | `12288:KKNl+aomg4xe2fiVITz79sykwMUVZBQf2sr+i:KK/+sg4xe2fcITz79h2fr+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_7aa8a134
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7aa8a13432f1999f37809e8576ea7e442d57e1902e991d11dedbfbdfc156a3de"
    family = "unknown"
    file_name = "warden_a16051a1_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:33:49"
  condition:
    hash.sha256(0, filesize) == "7aa8a13432f1999f37809e8576ea7e442d57e1902e991d11dedbfbdfc156a3de"
}
```

### Sample 11: `1c2f944aa593e4d5`

| Field | Value |
|---|---|
| SHA-256 | `1c2f944aa593e4d55343ed4ec5074160ee8a85bfb5b551ee734e6f26b1a95bf4` |
| Family label | `unknown` |
| File name | `warden_d5a8157b_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-10-17 03:33:41` |
| Reporter | `Daydream` |
| Tags | `dropped-by-OffLoader, exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73eec062a8c670f81961827367fde2b1` |
| SHA-1 | `01e8dac1d83983c74e156d3dea16724487c00cb1` |
| SHA-256 | `1c2f944aa593e4d55343ed4ec5074160ee8a85bfb5b551ee734e6f26b1a95bf4` |
| SHA3-384 | `afa80f3952eeef67164dde1fb43a6d9db37c8c4b26f3a081d6ab223d1bd52078c0bada8cbc6f48978ff70b0ff0772284` |
| IMPHASH | `fa93f0bd414e3835a3d886119242431b` |
| TLSH | `T19ED45A13F3A286D8D02AC9B5836A5133F6753C4D4A30BABB67945F215F36BA0E72D704` |
| SSDEEP | `12288:VacsDz624w/ffXyyO3QwgWuQy/DC0RW0LlVy6KqW9Khb:V3i4arO3QwgEyvRadmhb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_1c2f944a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c2f944aa593e4d55343ed4ec5074160ee8a85bfb5b551ee734e6f26b1a95bf4"
    family = "unknown"
    file_name = "warden_d5a8157b_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:33:41"
  condition:
    hash.sha256(0, filesize) == "1c2f944aa593e4d55343ed4ec5074160ee8a85bfb5b551ee734e6f26b1a95bf4"
}
```

### Sample 12: `afb1126f9454e8b9`

| Field | Value |
|---|---|
| SHA-256 | `afb1126f9454e8b94376b43cd09200b971ff39ffcaed57c2f55e133e41c36e6d` |
| Family label | `unknown` |
| File name | `warden_fc233953_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-10-17 03:33:32` |
| Reporter | `Daydream` |
| Tags | `dropped-by-OffLoader, exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9e6694dc415007c193c5f82b9439d0c` |
| SHA-1 | `47eb9345ba96a8477c770d7d342617fe7de2633c` |
| SHA-256 | `afb1126f9454e8b94376b43cd09200b971ff39ffcaed57c2f55e133e41c36e6d` |
| SHA3-384 | `d8e95c78319831c1f3f3bf22831f741bc5da4e2b3885bbbab5dc1347044bd112073c6621b10bb018e51f5f1c4d07b39f` |
| IMPHASH | `dd89ccb2d32019238bc87ebccd24e466` |
| TLSH | `T12EC45D03F2D541E6D01AC4B5839A5133E675BC9B8E34BEBF1B981F621E16BC06B2D349` |
| SSDEEP | `12288:6HLU7qqyO/ZrvFhthoHK5PLweIQLqLvHNqAKs9:6HTqyO/XhoHKtLwpnnF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_afb1126f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afb1126f9454e8b94376b43cd09200b971ff39ffcaed57c2f55e133e41c36e6d"
    family = "unknown"
    file_name = "warden_fc233953_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:33:32"
  condition:
    hash.sha256(0, filesize) == "afb1126f9454e8b94376b43cd09200b971ff39ffcaed57c2f55e133e41c36e6d"
}
```

### Sample 13: `e9af652d27614eb8`

| Field | Value |
|---|---|
| SHA-256 | `e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78` |
| Family label | `Vidar` |
| File name | `e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78.bin` |
| File type | `exe` |
| First seen | `2026-10-17 03:22:22` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `835501773c0b0d4a3b2d8bd7c2eb5c6d` |
| SHA-1 | `97bcd084339885a90a5bbb45d32782c09bbb589c` |
| SHA-256 | `e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78` |
| SHA3-384 | `6c780d4f7065beb4c10e6ba81ab9004c7ec032d2ade12db538c713eda07a0445b1d9adf00371e05f9338ca19852b90ab` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T175168D07FD9248B5C099A3328CB68252BB3DBC4A1B3227D32E51B67A3E727D09D35754` |
| SSDEEP | `98304:TaVWawGyrjXI+hU+vIhoRyAdVZVc7/e2l:TvawGyrjXI+hU+vI+9dBcbP` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_013_e9af652d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78"
    family = "Vidar"
    file_name = "e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78.bin"
    file_type = "exe"
    first_seen = "2026-10-17 03:22:22"
  condition:
    hash.sha256(0, filesize) == "e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78"
}
```

### Sample 14: `37ddd1a7b72fdb49`

| Field | Value |
|---|---|
| SHA-256 | `37ddd1a7b72fdb4986d966157ac085035b32d8cc3f84edef61808dec7158e12f` |
| Family label | `Vidar` |
| File name | `37ddd1a7b72fdb4986d966157ac085035b32d8cc3f84edef61808dec7158e12f.bin` |
| File type | `exe` |
| First seen | `2026-10-17 03:22:18` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a32ce3219397af53d87f77ca3b918182` |
| SHA-1 | `25ee7017276026771e44f637d0e61d963c9869fb` |
| SHA-256 | `37ddd1a7b72fdb4986d966157ac085035b32d8cc3f84edef61808dec7158e12f` |
| SHA3-384 | `f8e287af8563baae70a0551a48c79ab7fc74064cb2971f7f239a52ebc69db4a8a3beeab8c3ae0c3cbaadb64debac8ace` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T12E168C07FE9119A5C499A3328D764202B76CFC0E8B3263D71E91767A3F327D158B9B09` |
| SSDEEP | `49152:JOUxgA0DVWIyO1kCjZz4fgxqNGGGD8Z4oYTX6DpAtw9PcgGNvzwam47:JOIlMjZzpIIGGoZTgYAtw9Pc7p0y7` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_014_37ddd1a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37ddd1a7b72fdb4986d966157ac085035b32d8cc3f84edef61808dec7158e12f"
    family = "Vidar"
    file_name = "37ddd1a7b72fdb4986d966157ac085035b32d8cc3f84edef61808dec7158e12f.bin"
    file_type = "exe"
    first_seen = "2026-10-17 03:22:18"
  condition:
    hash.sha256(0, filesize) == "37ddd1a7b72fdb4986d966157ac085035b32d8cc3f84edef61808dec7158e12f"
}
```

### Sample 15: `d7234d9249e7cc45`

| Field | Value |
|---|---|
| SHA-256 | `d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c` |
| Family label | `unknown` |
| File name | `d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c` |
| File type | `sh` |
| First seen | `2026-10-17 03:17:06` |
| Reporter | `thinngo` |
| Tags | `honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c954d47452f8bb1aa03e3ecbbc90d5c9` |
| SHA-1 | `45a59f9963683c0274419f4e1e3269dec99dab09` |
| SHA-256 | `d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c` |
| SHA3-384 | `2ec539a5ab76361b3082adf837590603f47dd2002e570744041fcfc17057afb6dd76de90f9160c42922f6627c34155c9` |
| TLSH | `T11EE02669242511B2EDC5CAD591B6C290B10242F5ACCA646D3C3B963D071C1C9E17DFF0` |
| SSDEEP | `6:h/qqJwHOvtJ3RsVCbBsAomNFL3M90QF8aFH0QINFL3ZaKQcQSQJfRX50:5FtKMrQ90QjFUQmIKQcQVtk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_d7234d92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c"
    family = "unknown"
    file_name = "d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c"
    file_type = "sh"
    first_seen = "2026-10-17 03:17:06"
  condition:
    hash.sha256(0, filesize) == "d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c"
}
```

### Sample 16: `ff8a872e26abc29f`

| Field | Value |
|---|---|
| SHA-256 | `ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661` |
| Family label | `Mirai` |
| File name | `ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661.elf` |
| File type | `elf` |
| First seen | `2026-10-17 03:16:13` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b791ea12874d9b68764baf2bfbb81f3` |
| SHA-1 | `6065b5f334316377068b8ebc3ae364c35efbe1f6` |
| SHA-256 | `ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661` |
| SHA3-384 | `8d6014f2738fdc738739249852a034ea0c23a9476c423e337cf1f212c24bdb21aa54d2ab3788bb1630ad1ed4f6141ecc` |
| TLSH | `T1C844A45E6E228F7EF378873447B74B30976923D623E1D684E1ACD1151E6034E681FBA8` |
| TELFHASH | `t1c651d41c0d7817f0a2256c4d45ddff27d6a331db7e266c278e11e85aab29b439e21c1c` |
| SSDEEP | `6144:jW4sg83i9VgL92a4bEEYrz0k3qiaBaApwV4YT3b81/x:HSiPgAPbEClBay1/x` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_ff8a872e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661"
    family = "Mirai"
    file_name = "ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661.elf"
    file_type = "elf"
    first_seen = "2026-10-17 03:16:13"
  condition:
    hash.sha256(0, filesize) == "ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661"
}
```

### Sample 17: `453505bf331a5646`

| Field | Value |
|---|---|
| SHA-256 | `453505bf331a5646152b88692dd2e3d9e40f61b2ac97945f78c76f05ad5a57a0` |
| Family label | `Mirai` |
| File name | `mbupload-oa0493qn.bin` |
| File type | `elf` |
| First seen | `2026-10-17 02:58:26` |
| Reporter | `wristhulk` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `595ba47a3f6aa50ad27aa25978691341` |
| SHA-1 | `ac15d6d5adbcd7dd2498ddd170f77e48744eb6bb` |
| SHA-256 | `453505bf331a5646152b88692dd2e3d9e40f61b2ac97945f78c76f05ad5a57a0` |
| SHA3-384 | `b6d99937a974f6fa48a8c9f97552edcc27d0bde0579f65f3b34134eace8fe4e866914b1166bb807a703904ae3477833d` |
| TLSH | `T17B217252E0C46D68DF28D73C4E715A103B02D9A8C94FE3DE4E0C56BA292F28C76540D4` |
| SSDEEP | `24:wa3dGtSnUpzzbBWpzmIIyKYB5gDrm3EvC/dikC7m17hhVNfq:wa3dxnUpzzbBWpzmIIy+Drm3EvC/s77d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_453505bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "453505bf331a5646152b88692dd2e3d9e40f61b2ac97945f78c76f05ad5a57a0"
    family = "Mirai"
    file_name = "mbupload-oa0493qn.bin"
    file_type = "elf"
    first_seen = "2026-10-17 02:58:26"
  condition:
    hash.sha256(0, filesize) == "453505bf331a5646152b88692dd2e3d9e40f61b2ac97945f78c76f05ad5a57a0"
}
```

### Sample 18: `b7ce973bae02b7db`

| Field | Value |
|---|---|
| SHA-256 | `b7ce973bae02b7dba67176c33da4664da3c3d6ecd11d22067549e63505e5c3bd` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-17 02:49:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `059097f633a57408087ebffd7c4a9f51` |
| SHA-1 | `07476baa00070b46300efdac9628358b999e3559` |
| SHA-256 | `b7ce973bae02b7dba67176c33da4664da3c3d6ecd11d22067549e63505e5c3bd` |
| SHA3-384 | `c75ebe123c5538979d54d95a0effeb6b5e6c38248927562cfde95bdbf75561b4d9676428a64cc5d88a0597c0d32607b2` |
| TLSH | `T100140B97B5B9AEA0CAE74439B19403BC7246839AD3FEF00DCA154ED1BB5B0056A3D1C7` |
| SSDEEP | `3072:D/V4hVRwm6t8OU8rE10tiQJd8HjCrEifhzwQBbhL+XkP:DNK7uswtiQJd8HjCrEgPhpx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_b7ce973b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7ce973bae02b7dba67176c33da4664da3c3d6ecd11d22067549e63505e5c3bd"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-17 02:49:02"
  condition:
    hash.sha256(0, filesize) == "b7ce973bae02b7dba67176c33da4664da3c3d6ecd11d22067549e63505e5c3bd"
}
```

### Sample 19: `276efc07b5ed6ab6`

| Field | Value |
|---|---|
| SHA-256 | `276efc07b5ed6ab633028ec992c5b765a05770a5ff56506f86240569efbfbc93` |
| Family label | `unknown` |
| File name | `hb_x86` |
| File type | `elf` |
| First seen | `2026-10-17 02:44:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `539c57b98b0899287a138a6daeb60532` |
| SHA-1 | `48fd73a4144ba625ad2b003317e775d41b3f48e5` |
| SHA-256 | `276efc07b5ed6ab633028ec992c5b765a05770a5ff56506f86240569efbfbc93` |
| SHA3-384 | `0f7e040d104ad6bd0177b8b1a4b9e8f51a71f40cfa2dfc95f95484d5af8d9793e4561a5d1af0165d4f2c213ab91b1d87` |
| TLSH | `T1FF6423CCE99EE8B1E945033C6D0316D2B52AEA74CE1C1DAB9E0DD9BB2F3D1211E04D91` |
| SSDEEP | `6144:NxqfU957+U47a8XWW6NwTq+JeYe6m3kOadgq4Fja8TSaM9QbUluxANg:N8fU95CKg/6H+JXe6V3SnTK7luxA2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_276efc07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "276efc07b5ed6ab633028ec992c5b765a05770a5ff56506f86240569efbfbc93"
    family = "unknown"
    file_name = "hb_x86"
    file_type = "elf"
    first_seen = "2026-10-17 02:44:52"
  condition:
    hash.sha256(0, filesize) == "276efc07b5ed6ab633028ec992c5b765a05770a5ff56506f86240569efbfbc93"
}
```

### Sample 20: `eb3e86ee5977b3f9`

| Field | Value |
|---|---|
| SHA-256 | `eb3e86ee5977b3f92fadb23eb8cf7135a5371ea3f7e7b73c80cc4c06f3e30756` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-17 02:44:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d002796cecefb25d10498503f730b3a5` |
| SHA-1 | `d80cb829c42491313db7133ff1894421ff89bbb1` |
| SHA-256 | `eb3e86ee5977b3f92fadb23eb8cf7135a5371ea3f7e7b73c80cc4c06f3e30756` |
| SHA3-384 | `d2ba483f83d3983e6f1ea8016283580d4d38b839d06eebf33d733ee7e097884c30839688ebf8978f9a7c1ea87401f6be` |
| TLSH | `T12F2439C7F900DEBAF80AE73744130505B130F7B204525A37625B357BED7A1AA197BE8A` |
| SSDEEP | `3072:Efrt8NHX+wus3gj0/07WXGd0WFyzFzO0BgMWTrCz8s0tm/VMjbi1LUW1QVEek:u6NHFeQbMByz5O0BghTRTtmpLBNek` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_eb3e86ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb3e86ee5977b3f92fadb23eb8cf7135a5371ea3f7e7b73c80cc4c06f3e30756"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-17 02:44:50"
  condition:
    hash.sha256(0, filesize) == "eb3e86ee5977b3f92fadb23eb8cf7135a5371ea3f7e7b73c80cc4c06f3e30756"
}
```

### Sample 21: `b7c562089fbc80dc`

| Field | Value |
|---|---|
| SHA-256 | `b7c562089fbc80dca34a8dd924e7436dde1428cccc5e2cb81f5e69b2da9f2922` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-10-17 02:43:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96449fa73caeb681a7bdc78d3e5ba8c8` |
| SHA-1 | `e3fa955e0edbac5f3c663d79714d518500fa6cfb` |
| SHA-256 | `b7c562089fbc80dca34a8dd924e7436dde1428cccc5e2cb81f5e69b2da9f2922` |
| SHA3-384 | `a91a3886c3eda4aab503b92cf4878ad94d10abff8b10092bd3f09dcd78d42e919e41900c2d1e228e2cd1034cae84771c` |
| TLSH | `T142145B01B71D0943E2632EF0363F27E1C3DEAAE135F5E6442A0EA68592B1D325585EDE` |
| SSDEEP | `3072:IKa4Dv7cYbFKVSZw0knUqxU0+OvwNPKczdRiCBS7vzH6w:IKa4Dv7JDwv3xyOvwNPKCdRZBGmw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_b7c56208
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7c562089fbc80dca34a8dd924e7436dde1428cccc5e2cb81f5e69b2da9f2922"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-17 02:43:17"
  condition:
    hash.sha256(0, filesize) == "b7c562089fbc80dca34a8dd924e7436dde1428cccc5e2cb81f5e69b2da9f2922"
}
```

### Sample 22: `a0f8eb2b9458ffc5`

| Field | Value |
|---|---|
| SHA-256 | `a0f8eb2b9458ffc5f5641d400c300f16b6ffe2e560906f0c6f9cbb04c38c031a` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-10-17 02:42:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17753b30266da710c8b2814a9963322e` |
| SHA-1 | `aad44951bf48250f25dc098add8db13bc5d7a029` |
| SHA-256 | `a0f8eb2b9458ffc5f5641d400c300f16b6ffe2e560906f0c6f9cbb04c38c031a` |
| SHA3-384 | `192c2344ad2ca9c24f3a1b63e54293b31b274e11486c78239ec5ac78af88cdd39a5a8b33bf66d5d5b17c7a4c111ff0f0` |
| TLSH | `T1D273021CF9B91916FFCB7F319659F2E9A751AA8D4AC36550EB48B283B18C5C02F0C119` |
| SSDEEP | `1536:n7WWosxHiQvs3I8A6SDMbcfgSblg0M5j1wpCf/j4f4u+qgw09k:7uKy3I8AjClSa5e4f74f4u+qgwd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_a0f8eb2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0f8eb2b9458ffc5f5641d400c300f16b6ffe2e560906f0c6f9cbb04c38c031a"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-17 02:42:42"
  condition:
    hash.sha256(0, filesize) == "a0f8eb2b9458ffc5f5641d400c300f16b6ffe2e560906f0c6f9cbb04c38c031a"
}
```

### Sample 23: `602ea10b62bc2664`

| Field | Value |
|---|---|
| SHA-256 | `602ea10b62bc266484fe6c2de86c56c79747203e12fba6a824e66ba697d1be45` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-17 02:35:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eee57497af1ddc40625bcbb01670696f` |
| SHA-1 | `b2517a1f489f28b078468c250599b224a92294cf` |
| SHA-256 | `602ea10b62bc266484fe6c2de86c56c79747203e12fba6a824e66ba697d1be45` |
| SHA3-384 | `9089346cf19456e0572632e3416e18d92a0e78c054c93fb6f69a32da99b61ac89b428323b7c31f696f2e7182162bb8bc` |
| TLSH | `T18244831E6A328F7DF368877447B74B30A75D22D622E1DA84E1ACD1101E6435E681FFAC` |
| TELFHASH | `t11d51f2ac097803b5a2546c1d44ddff2ad6e314ef7e1a2c239a50d86df722f838c24c09` |
| SSDEEP | `6144:TpEephaz6mS1wc61K8d/J2c7N7Nt3yrPCcHs12rL0j71a+d:Tpltq1K8/2c7RYPCcLrPo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_602ea10b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "602ea10b62bc266484fe6c2de86c56c79747203e12fba6a824e66ba697d1be45"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-17 02:35:29"
  condition:
    hash.sha256(0, filesize) == "602ea10b62bc266484fe6c2de86c56c79747203e12fba6a824e66ba697d1be45"
}
```

### Sample 24: `3425587876d45c0a`

| Field | Value |
|---|---|
| SHA-256 | `3425587876d45c0a1eaea90741b0f1a8e490af891ce848bfc5b685683a6d2533` |
| Family label | `NanoCore` |
| File name | `5F281E55C1E07DABEB5E59D3A5194294.exe` |
| File type | `exe` |
| First seen | `2026-10-17 02:35:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f281e55c1e07dabeb5e59d3a5194294` |
| SHA-1 | `39488afa3338d6eaf40faef07c80d816a8c0fa75` |
| SHA-256 | `3425587876d45c0a1eaea90741b0f1a8e490af891ce848bfc5b685683a6d2533` |
| SHA3-384 | `b2b311e3cae72c15f8f85010a27583ee8bca5dfc3444a0ce48340b0ed228b6c061c0f7227276922655c565b40bed477d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F324CF267BA94A3FE28F86B9611201029378C2E7ACC3F7DE68D455B74B563E40A071D7` |
| SSDEEP | `6144:ALV6Bta6dtJmakIM5CfbJ+kiHdFd5JeHVdkw:ALV6Btpmkxfjs2H75` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_024_34255878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3425587876d45c0a1eaea90741b0f1a8e490af891ce848bfc5b685683a6d2533"
    family = "NanoCore"
    file_name = "5F281E55C1E07DABEB5E59D3A5194294.exe"
    file_type = "exe"
    first_seen = "2026-10-17 02:35:07"
  condition:
    hash.sha256(0, filesize) == "3425587876d45c0a1eaea90741b0f1a8e490af891ce848bfc5b685683a6d2533"
}
```

### Sample 25: `40ca1cc50908ba62`

| Field | Value |
|---|---|
| SHA-256 | `40ca1cc50908ba6247b4a12a20c30f9bc5f11b61ebd4fa45a61bbfcf725efb88` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-17 02:34:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cd2a2489598c53dc2958d5e481fbc3c` |
| SHA-1 | `fa9c030f8848d4b060f7f5ecea30cc10508be7b5` |
| SHA-256 | `40ca1cc50908ba6247b4a12a20c30f9bc5f11b61ebd4fa45a61bbfcf725efb88` |
| SHA3-384 | `18f6d8f3f1ed534f4f12a67f8acab36c2dfca7ee39f09003675bb58d0733baaeaa787038209161f01d299bc655f3d239` |
| TLSH | `T1178312A481879F99D9F6F3F89C702701BD700B709A0BEADE7B1835D2546B07AA485FD0` |
| SSDEEP | `1536:A0osGSHJK+GJ6DSIQ7rgAKcBRvS/tbYNU5lv0POXmXqGVziUHVJuY:9FGSHJDGJKp0r6gRvAYNUlv0POCqGRVJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_40ca1cc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ca1cc50908ba6247b4a12a20c30f9bc5f11b61ebd4fa45a61bbfcf725efb88"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-17 02:34:37"
  condition:
    hash.sha256(0, filesize) == "40ca1cc50908ba6247b4a12a20c30f9bc5f11b61ebd4fa45a61bbfcf725efb88"
}
```

### Sample 26: `9fd7f2f32f4bdeb7`

| Field | Value |
|---|---|
| SHA-256 | `9fd7f2f32f4bdeb718cc9e4f3f431ab0549efc4211492a975f82b46da90f1f08` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-17 02:29:23` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `469292921884ec54c435514ca3150f10` |
| SHA-1 | `cc4650defb67fa4ac1a98622e82e0537a7987013` |
| SHA-256 | `9fd7f2f32f4bdeb718cc9e4f3f431ab0549efc4211492a975f82b46da90f1f08` |
| SHA3-384 | `6e8f04c397c20d1e8ad77396ad458e7c0b8d06a6325d0eb7bcc672ad4ef07c9ed4d4f6ff82ffbe44d0dd1c03f8b90dfe` |
| IMPHASH | `62848721a0fe32270ffbda7abe4e1f5c` |
| TLSH | `T15F15391EAFB3C072EE63D5B2F6645221393DB82D173885CB62B0282DE9907C1DAF5355` |
| SSDEEP | `12288:jYEd//LbpeDJ4jfiIaBRtwfESz9pfYbVC3pKEVj4988f7N:jbJIJ4TiIaBYfTz9wC3pKqH8f7N` |
| ICON-DHASH | `e0341a1c1d9a9a9a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_9fd7f2f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fd7f2f32f4bdeb718cc9e4f3f431ab0549efc4211492a975f82b46da90f1f08"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-17 02:29:23"
  condition:
    hash.sha256(0, filesize) == "9fd7f2f32f4bdeb718cc9e4f3f431ab0549efc4211492a975f82b46da90f1f08"
}
```

### Sample 27: `9bd0fcad7e6ca59c`

| Field | Value |
|---|---|
| SHA-256 | `9bd0fcad7e6ca59c3caeed5b9fae6ecb499d274bfff2042a855f7b9f5b3b1657` |
| Family label | `Mirai` |
| File name | `6` |
| File type | `elf` |
| First seen | `2026-10-17 02:28:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `671b76c1239e557a0e96d91f0708e983` |
| SHA-1 | `b15555247754ee1d150b037a55bfafc88a814f46` |
| SHA-256 | `9bd0fcad7e6ca59c3caeed5b9fae6ecb499d274bfff2042a855f7b9f5b3b1657` |
| SHA3-384 | `ac9196cc389bd589aaaadb746ee4f82335488041fce64e0e4728a561f8399ed20c8f1e24b46c6dcfb7951813f53d7493` |
| TLSH | `T100257C16EF441FEBC8AFCE304A2E830715ED9DC742D1A739A1FC8D8CBA592595AD3448` |
| SSDEEP | `12288:z+JKTB6NSkFMwOoLpBF5iLJ7L/C8qogMQNzJLYOy+OZZtYijhCV8kLeyJbfRcn/t:xkqbO2MlsvEOonDnefBmLQoOmrIp/t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_9bd0fcad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd0fcad7e6ca59c3caeed5b9fae6ecb499d274bfff2042a855f7b9f5b3b1657"
    family = "Mirai"
    file_name = "6"
    file_type = "elf"
    first_seen = "2026-10-17 02:28:33"
  condition:
    hash.sha256(0, filesize) == "9bd0fcad7e6ca59c3caeed5b9fae6ecb499d274bfff2042a855f7b9f5b3b1657"
}
```

### Sample 28: `5c390a72ec6f1a3e`

| Field | Value |
|---|---|
| SHA-256 | `5c390a72ec6f1a3e7978542c2146f9c0d785cc217f132a876181b9c7f3c8bdf9` |
| Family label | `unknown` |
| File name | `cegg_x86` |
| File type | `elf` |
| First seen | `2026-10-17 02:26:31` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93ba8d692ab24077b2ab3f59924d79ff` |
| SHA-1 | `53296359138e620f7fe2e923fa34c1fe7ed10aed` |
| SHA-256 | `5c390a72ec6f1a3e7978542c2146f9c0d785cc217f132a876181b9c7f3c8bdf9` |
| SHA3-384 | `1b9350db4b11732a40ab6a8fedc8bc7a78ddb24fedeb421e52ef3a74bfb5695de210dc544adc8e99a3ac1bee92967548` |
| TLSH | `T15E135CBBE1766A2FC905C33784A8BC63E1A33B4C9293DD1938D5769F67C59CD0A101B2` |
| SSDEEP | `768:SYmrifPJpZikHKrGqSBwE00nVUrdEa4Bd/evJaIhdsFq/f:SE5pYkwkw22+AJzsFqH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_5c390a72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c390a72ec6f1a3e7978542c2146f9c0d785cc217f132a876181b9c7f3c8bdf9"
    family = "unknown"
    file_name = "cegg_x86"
    file_type = "elf"
    first_seen = "2026-10-17 02:26:31"
  condition:
    hash.sha256(0, filesize) == "5c390a72ec6f1a3e7978542c2146f9c0d785cc217f132a876181b9c7f3c8bdf9"
}
```

### Sample 29: `39196442ee82d435`

| Field | Value |
|---|---|
| SHA-256 | `39196442ee82d4353d938e6507287316b7ff92927fc599df618d45df9dd0b2dd` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-17 02:20:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ded2e4ea99dc1a009efd78673649662a` |
| SHA-1 | `19199c6a3c8b3ea5f2edc800e3b4343c52f3eaf1` |
| SHA-256 | `39196442ee82d4353d938e6507287316b7ff92927fc599df618d45df9dd0b2dd` |
| SHA3-384 | `4d1e86c2a613e405d1ca9d87f678abdbb2b959c28f72af7e65bbe3828934fe1dacd3921ca0166597e1c46ad5ebae4cc7` |
| TLSH | `T17E555BBAF2A770BCC067D030479BCBA2AC35B4B501212D7B61C4A9763D62DE11766F27` |
| TELFHASH | `t171d1af700bf635b562dbca20f323f4758d3218ba64f435b466227d98ef85e814c6e867` |
| SSDEEP | `24576:s7aPpTWYDnvgFStBCUiEhPGTM2VlPVDYyESkuxJmF:sOPpCYDnv0StwIhPGTM2DJFmN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_39196442
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39196442ee82d4353d938e6507287316b7ff92927fc599df618d45df9dd0b2dd"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-17 02:20:34"
  condition:
    hash.sha256(0, filesize) == "39196442ee82d4353d938e6507287316b7ff92927fc599df618d45df9dd0b2dd"
}
```

### Sample 30: `400a6316ccd012a0`

| Field | Value |
|---|---|
| SHA-256 | `400a6316ccd012a0cb468f44790f73e326db4acca66645c0c8c4ed0f7fc53da1` |
| Family label | `unknown` |
| File name | `cegg_arm64` |
| File type | `elf` |
| First seen | `2026-10-17 02:18:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f210f56fd3e50befc57cedf96424afea` |
| SHA-1 | `59aa601a3e62a9df8bf976bbd9cdcf034240f776` |
| SHA-256 | `400a6316ccd012a0cb468f44790f73e326db4acca66645c0c8c4ed0f7fc53da1` |
| SHA3-384 | `0d1d3f1e427bc53c1484a8aa9f1b159746aeda16953214f153826eb9f61c53f974f61a4a38b61618990ed71eb469e821` |
| TLSH | `T1E7E44C7FD5FA261FCA08835B88D89C33A3937709D3A3D8083AD637695A955DD0F202B5` |
| SSDEEP | `12288:TaPWMScfB2XSjYZLJjNu6XpTnFnadBD4wmnFkB2a/APv:TaPOasSWFjNu6XdnF2DTmnql/APv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_400a6316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "400a6316ccd012a0cb468f44790f73e326db4acca66645c0c8c4ed0f7fc53da1"
    family = "unknown"
    file_name = "cegg_arm64"
    file_type = "elf"
    first_seen = "2026-10-17 02:18:37"
  condition:
    hash.sha256(0, filesize) == "400a6316ccd012a0cb468f44790f73e326db4acca66645c0c8c4ed0f7fc53da1"
}
```

### Sample 31: `6dec9ce44114bef5`

| Field | Value |
|---|---|
| SHA-256 | `6dec9ce44114bef5cec56e6f4f00d8a00692d140cb7f9de2735baffda39d2f69` |
| Family label | `unknown` |
| File name | `cegg_mipsle` |
| File type | `elf` |
| First seen | `2026-10-17 02:14:29` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12c6eb5ded7b89a6be09c7fcfa74798d` |
| SHA-1 | `856d7a50f30a8c1f7d7879115725cbcfa8aef29b` |
| SHA-256 | `6dec9ce44114bef5cec56e6f4f00d8a00692d140cb7f9de2735baffda39d2f69` |
| SHA3-384 | `a66f457d5118d94d45819217be3f4f7de24ed0dee25ca8f44673f396a68977d07dff5e8e5f0208c560a71fb11438988b` |
| TLSH | `T114F44CBFD9F52A1F8A08835B44D85C33A3A33749D3A398083AC637295BA55DD0F216F5` |
| SSDEEP | `12288:Go5Bl7LWSlraGZKA8CIKiCMj+P3XbLS5Apr7n7iRYyiv+j2UKin:FrlPWSlraGZKA8CIKiCMj+PvNpr7nORL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_6dec9ce4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dec9ce44114bef5cec56e6f4f00d8a00692d140cb7f9de2735baffda39d2f69"
    family = "unknown"
    file_name = "cegg_mipsle"
    file_type = "elf"
    first_seen = "2026-10-17 02:14:29"
  condition:
    hash.sha256(0, filesize) == "6dec9ce44114bef5cec56e6f4f00d8a00692d140cb7f9de2735baffda39d2f69"
}
```

### Sample 32: `7a0649ca3761da27`

| Field | Value |
|---|---|
| SHA-256 | `7a0649ca3761da27ff399e4b01bf4bc11a3e170f529deba0a8c31468a90a2749` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-10-17 02:11:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `083fc49b8fc7bfb1400878083b1370dd` |
| SHA-1 | `8a84b241af60e58c501f3a9deb9fe98c9d9bf665` |
| SHA-256 | `7a0649ca3761da27ff399e4b01bf4bc11a3e170f529deba0a8c31468a90a2749` |
| SHA3-384 | `06f7826fe18e795af3f918c29809bee3630854468bd1401fa4702844244fcf1becc47f9a8c9f31cf3476c09ebc3e1152` |
| TLSH | `T1BBE35A07F783E1F0D95A07B1015BFB3A4A74DD322025CE5BDBE4FD76AC66642A20662C` |
| TELFHASH | `t1de514b7abee505e477d19501d79e2721ce28a43f151039b949f22bc427f3e02b366c79` |
| SSDEEP | `3072:u0osBtIp6Fsa1AcldturBGFq/EuEurxYVJx+:BBtIpjcRuMKPlkx+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_7a0649ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a0649ca3761da27ff399e4b01bf4bc11a3e170f529deba0a8c31468a90a2749"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-10-17 02:11:24"
  condition:
    hash.sha256(0, filesize) == "7a0649ca3761da27ff399e4b01bf4bc11a3e170f529deba0a8c31468a90a2749"
}
```

### Sample 33: `fdc632c0698508a9`

| Field | Value |
|---|---|
| SHA-256 | `fdc632c0698508a9afe744e6c29b200f9e2221958d7594d29843676fc6994232` |
| Family label | `Mirai` |
| File name | `fdc632c0698508a9afe744e6c29b200f9e2221958d7594d29843676fc6994232.elf` |
| File type | `elf` |
| First seen | `2026-10-17 02:11:10` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75f06b0ca8b3dac9fcfda53afd79923a` |
| SHA-1 | `a6bca441d7b2043415b78395ba59d08c9f4258ab` |
| SHA-256 | `fdc632c0698508a9afe744e6c29b200f9e2221958d7594d29843676fc6994232` |
| SHA3-384 | `76deee99d3e52b78f241dcb14503b616132e2bbb760d02639ae225a8ffd79d3efde11afbd2fec0e1ee4a6b939c6003d3` |
| TLSH | `T177156C99D7C3D8E1F66300F10A8FDBE3192452165013F6F2EB8D6A977432B622E17369` |
| TELFHASH | `t1b0e148b719b598eca3f04501c75b7220ce26e03b25e0357259e3a4e1a772e036b77db9` |
| SSDEEP | `24576:TLKjBh4+hBb/D+84dx+i/ohjovvrREFRmBzIRdN:uh4+hx7Yoa+o7RUN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_fdc632c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdc632c0698508a9afe744e6c29b200f9e2221958d7594d29843676fc6994232"
    family = "Mirai"
    file_name = "fdc632c0698508a9afe744e6c29b200f9e2221958d7594d29843676fc6994232.elf"
    file_type = "elf"
    first_seen = "2026-10-17 02:11:10"
  condition:
    hash.sha256(0, filesize) == "fdc632c0698508a9afe744e6c29b200f9e2221958d7594d29843676fc6994232"
}
```

### Sample 34: `a0db0b57eaa2b978`

| Field | Value |
|---|---|
| SHA-256 | `a0db0b57eaa2b978651c7c3f4c3c63b382fcc66a03f2a8031f423c21ba97f378` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-10-17 02:10:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `349bcea8ba9ad958d7a672344bceb5a6` |
| SHA-1 | `823f6e9d9d0ffc34d906950d80b7249cce81f6d4` |
| SHA-256 | `a0db0b57eaa2b978651c7c3f4c3c63b382fcc66a03f2a8031f423c21ba97f378` |
| SHA3-384 | `d71d5a175909b54afb6ffca762a6e5a727eaa715476b192ff1b479945f9805aa11504714efb60f88eaba6f374741bdc8` |
| TLSH | `T1516302BF979813C4C83C49756AEFF284C45BCA8EB865D47ABFC6305F4C1B109B285992` |
| SSDEEP | `1536:rZq7U3yqoqFikM//tEh2UuxRUutYPgovvTxvVkSJZMVnouy86zkkG3:QCZDml1RUutYPg8vVJZKoutrkG3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_a0db0b57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0db0b57eaa2b978651c7c3f4c3c63b382fcc66a03f2a8031f423c21ba97f378"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-10-17 02:10:28"
  condition:
    hash.sha256(0, filesize) == "a0db0b57eaa2b978651c7c3f4c3c63b382fcc66a03f2a8031f423c21ba97f378"
}
```

### Sample 35: `b9841eb5df6b9dcd`

| Field | Value |
|---|---|
| SHA-256 | `b9841eb5df6b9dcd76b1db4569dd5248345ed430119a1acca55a8d64f3c908c1` |
| Family label | `unknown` |
| File name | `b9841eb5df6b9dcd76b1db4569dd5248345ed430119a1acca55a8d64f3c908c1` |
| File type | `sh` |
| First seen | `2026-10-17 01:52:40` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc8fd9908226b48424e4f6e29eb481b2` |
| SHA-1 | `8bdb939d141ef33ceaea19c4dfa769fad2699897` |
| SHA-256 | `b9841eb5df6b9dcd76b1db4569dd5248345ed430119a1acca55a8d64f3c908c1` |
| SHA3-384 | `13b4e2e4b9ff0951b6e7e5b7d7d6477199578a0d4d427340617eddc4eea1bb30a0e0793db317da32d3db3751583472f6` |
| TLSH | `T19801CEF5FCF8E850788C48EA366CC1306C868DFB64C43A965817A870951C698B028B72` |
| SSDEEP | `12:8H+4L/dlt3jrhPyz8on/1gign1ECuoXppzkbY714ryKKN5A0NEkeHl:7I/p3BvQeig1ECbXppwbap73NEL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_b9841eb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9841eb5df6b9dcd76b1db4569dd5248345ed430119a1acca55a8d64f3c908c1"
    family = "unknown"
    file_name = "b9841eb5df6b9dcd76b1db4569dd5248345ed430119a1acca55a8d64f3c908c1"
    file_type = "sh"
    first_seen = "2026-10-17 01:52:40"
  condition:
    hash.sha256(0, filesize) == "b9841eb5df6b9dcd76b1db4569dd5248345ed430119a1acca55a8d64f3c908c1"
}
```

### Sample 36: `5861d36ffa3c3dee`

| Field | Value |
|---|---|
| SHA-256 | `5861d36ffa3c3deea7ab3b6a1faf4ee0af5dde2ae9fe491bdbb6b34c4125b7bc` |
| Family label | `AMOS` |
| File name | `macho_5861d36ffa3c.bin` |
| File type | `macho` |
| First seen | `2026-10-17 01:39:22` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1824333cfe9ed4220763c12a93dbf92` |
| SHA-1 | `d9fffc6d65347852bb58c6921ee54c04770bb2b9` |
| SHA-256 | `5861d36ffa3c3deea7ab3b6a1faf4ee0af5dde2ae9fe491bdbb6b34c4125b7bc` |
| SHA3-384 | `92b405f16ce1704a9752b03f660adf813972e6332fef3f31474cb8ff3f32a3e55ad29bfac96ee01d8028c8fdec17db4f` |
| TLSH | `T1DBA5F164A22A126AE453107FCD550FDD279462D05A38FAF6A628CB3A3C30DF37967731` |
| SSDEEP | `49152:aOxG0lxqWN0jmiNDII8STMBxHZT5lWDaOLKNPsx:o0omEDIIJ8xHZT5Uf` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_036_5861d36f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5861d36ffa3c3deea7ab3b6a1faf4ee0af5dde2ae9fe491bdbb6b34c4125b7bc"
    family = "AMOS"
    file_name = "macho_5861d36ffa3c.bin"
    file_type = "macho"
    first_seen = "2026-10-17 01:39:22"
  condition:
    hash.sha256(0, filesize) == "5861d36ffa3c3deea7ab3b6a1faf4ee0af5dde2ae9fe491bdbb6b34c4125b7bc"
}
```

### Sample 37: `fa60cde5a2831ea7`

| Field | Value |
|---|---|
| SHA-256 | `fa60cde5a2831ea760f1ceda647caec7543592fd1c4cc8bcf383ffad62fec084` |
| Family label | `Mirai` |
| File name | `adissarm5` |
| File type | `elf` |
| First seen | `2026-10-17 01:38:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `907e58c999e4d94a68398d29be677496` |
| SHA-1 | `93d52a65a2ef89842e05f5e7263295362b138e1c` |
| SHA-256 | `fa60cde5a2831ea760f1ceda647caec7543592fd1c4cc8bcf383ffad62fec084` |
| SHA3-384 | `bbb36fdfdf743fdff4d7a166dcd8564c38171698069c0405aa6fb7c09371bc0a9170edc1d92b26193fde51b806fe593d` |
| TLSH | `T108142B95F8519F17C6C1167BFB2E828C372B13B8D2EA31029D116F24379B46B0E7A642` |
| TELFHASH | `t19a3111309a8445ec77d48495d58e1239a21138b77e663e548fa3a9cd8b518e1703693a` |
| SSDEEP | `6144:cURy6g/H1R3IYmD7386ZttT4ONc4egcFH0FDfHhQ:cUJmVRy3xtT4OG4gFYDfHhQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_fa60cde5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa60cde5a2831ea760f1ceda647caec7543592fd1c4cc8bcf383ffad62fec084"
    family = "Mirai"
    file_name = "adissarm5"
    file_type = "elf"
    first_seen = "2026-10-17 01:38:40"
  condition:
    hash.sha256(0, filesize) == "fa60cde5a2831ea760f1ceda647caec7543592fd1c4cc8bcf383ffad62fec084"
}
```

### Sample 38: `07a491805b23d8eb`

| Field | Value |
|---|---|
| SHA-256 | `07a491805b23d8ebf039f56c43107261a6d3a2014ae39ec513dfb4415220ca73` |
| Family label | `unknown` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-10-17 01:36:24` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, Stealer, WardenStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `883eae22718ef960648a369451a43fa7` |
| SHA-1 | `c7be88111ad714d30886643110a00a6fd659d2a9` |
| SHA-256 | `07a491805b23d8ebf039f56c43107261a6d3a2014ae39ec513dfb4415220ca73` |
| SHA3-384 | `30fb53a63fc9f516cebea8c814d313f44bb8e16f3a8a868a8f1a79f2c1ff7c00ef5fd1cfa74f3b64ca3f683c0d1f661c` |
| IMPHASH | `33d48d6712eba4a3fd50e4311df5017e` |
| TLSH | `T1C9150204B227C29EE872C53E9537465AFEE1B8A41370E3FF93854B295DA19E4837B350` |
| SSDEEP | `24576:qDBVUoqTk4bhJfuP/IfYJqnBPEWvh9iyRPp/H:qVVUokjVuYfYJoJA+P` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_07a49180
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07a491805b23d8ebf039f56c43107261a6d3a2014ae39ec513dfb4415220ca73"
    family = "unknown"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-10-17 01:36:24"
  condition:
    hash.sha256(0, filesize) == "07a491805b23d8ebf039f56c43107261a6d3a2014ae39ec513dfb4415220ca73"
}
```

### Sample 39: `269b268ad5416817`

| Field | Value |
|---|---|
| SHA-256 | `269b268ad54168172f307ae50896b64735e3164946f4abc91c2e8257b0fb6300` |
| Family label | `unknown` |
| File name | `Qt5Widgets.dll` |
| File type | `exe` |
| First seen | `2026-10-17 01:35:19` |
| Reporter | `Daydream` |
| Tags | `dll, DvnX, exe, Qt5Widgets, sideloading, TeamSpeak` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75e97138c2309d7319a38867b4571e86` |
| SHA-1 | `4362ed9596e4a1122638c47388e2158773ce5a4f` |
| SHA-256 | `269b268ad54168172f307ae50896b64735e3164946f4abc91c2e8257b0fb6300` |
| SHA3-384 | `af6343e85a4ff09f76e7ac915311972a3d89e6f63367388b56595971e60d730f1d20cede4970e42ca3e674a330797af2` |
| IMPHASH | `8ac796c200bcdb47fab6297f47883022` |
| TLSH | `T17C466B87B3A50185C16BD238CA8B8613D6B2B04447639BCF256ACF592F737E12E7E711` |
| SSDEEP | `49152:jK+LIFYAPZtMym9RRQ7/KKIXSewIa/2Xqq1sfeOoKGOhhwNmiHYYwBrK8KMlH0gD:9GoKZdRq3D10rK8KMlH0gi5GX0oKG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_269b268a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "269b268ad54168172f307ae50896b64735e3164946f4abc91c2e8257b0fb6300"
    family = "unknown"
    file_name = "Qt5Widgets.dll"
    file_type = "exe"
    first_seen = "2026-10-17 01:35:19"
  condition:
    hash.sha256(0, filesize) == "269b268ad54168172f307ae50896b64735e3164946f4abc91c2e8257b0fb6300"
}
```

### Sample 40: `8351041a32a2c892`

| Field | Value |
|---|---|
| SHA-256 | `8351041a32a2c892ab9349120616870b5095d05752f4d3e355d8158c2bc02cbd` |
| Family label | `unknown` |
| File name | `dvnx_e5b790c3_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-10-17 01:35:10` |
| Reporter | `Daydream` |
| Tags | `DvnX, exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `455b03cc8c12e32499877f00b9146e3b` |
| SHA-1 | `2dcf41701a5819a318491e8420d63b36021328ce` |
| SHA-256 | `8351041a32a2c892ab9349120616870b5095d05752f4d3e355d8158c2bc02cbd` |
| SHA3-384 | `bc0e02a9abeef692a3d0a6a7b1348b6ed1fc84884d16b25368c973bafa6009ee17e69ae90b3f46f2fa75b3170ad418f9` |
| IMPHASH | `4f3beab9d6def07c37d6a08235d6c43a` |
| TLSH | `T1ACD44B53F3A146DCD42AC9B5832A9133E6757C8C4630B67B67946F211F3ABA0EB2D704` |
| SSDEEP | `12288:zA+D8cAENGp94gfRUDJpFFB0k3CPC1B+Hu5Lpbg5Wtj9iPqK:zAwhGggCJpFok3CPZu5LXdyqK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_8351041a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8351041a32a2c892ab9349120616870b5095d05752f4d3e355d8158c2bc02cbd"
    family = "unknown"
    file_name = "dvnx_e5b790c3_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 01:35:10"
  condition:
    hash.sha256(0, filesize) == "8351041a32a2c892ab9349120616870b5095d05752f4d3e355d8158c2bc02cbd"
}
```

### Sample 41: `cefd574917e8625d`

| Field | Value |
|---|---|
| SHA-256 | `cefd574917e8625d7e43d210ce4a473e068210f944d998335feac56d02a63f7e` |
| Family label | `unknown` |
| File name | `dvnx_463f5610_unpacked.exe` |
| File type | `exe` |
| First seen | `2026-10-17 01:35:01` |
| Reporter | `Daydream` |
| Tags | `DvnX, exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f55582ca0a6a2fefdb5111e2f60beeb3` |
| SHA-1 | `1e776aebaebf78a774c93f5b10e8961c6a6f5e30` |
| SHA-256 | `cefd574917e8625d7e43d210ce4a473e068210f944d998335feac56d02a63f7e` |
| SHA3-384 | `333501405d494c38e4e671ef065525000b074422500192518ff733bc02a7ff77a0a33c26e7eabf44a2b03c51d2eeec1d` |
| IMPHASH | `aece746d2c7d4dc08252af46848bfba7` |
| TLSH | `T1AED45B53F79282D8D02AC5B5836A5223F6743C8C4A30BABF57942B651F76BA0E73D704` |
| SSDEEP | `12288:HmjrV5MIQOX2yLdf8zrs6MghpTP0I9XrFI9I4AZRoD:Hmj/J7X2yLdEzrwYueIBAZe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_cefd5749
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cefd574917e8625d7e43d210ce4a473e068210f944d998335feac56d02a63f7e"
    family = "unknown"
    file_name = "dvnx_463f5610_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 01:35:01"
  condition:
    hash.sha256(0, filesize) == "cefd574917e8625d7e43d210ce4a473e068210f944d998335feac56d02a63f7e"
}
```

### Sample 42: `05d377c8263e2000`

| Field | Value |
|---|---|
| SHA-256 | `05d377c8263e20008aca7bcd0f9b9187d2c70599fdfec334bb6bbfb03e52ebd4` |
| Family label | `unknown` |
| File name | `warden_8360_fixed.exe` |
| File type | `exe` |
| First seen | `2026-10-17 01:34:53` |
| Reporter | `Daydream` |
| Tags | `exe, stealer, unpacked, WardenStealer, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0040ba2b1eada462974b8edd74730a26` |
| SHA-1 | `d16177efccfab8df8d9013f6a44ca88a994c6c61` |
| SHA-256 | `05d377c8263e20008aca7bcd0f9b9187d2c70599fdfec334bb6bbfb03e52ebd4` |
| SHA3-384 | `da9c08ff81984865b1bd2c4be8e6d865a7b3fdf6022e67c8e0960e6911ce732bd56732e547cb266abb09f098fd72ed38` |
| IMPHASH | `f3c18fd716bf8dce17589aefb078af92` |
| TLSH | `T12DC45E03F6D541E6D01AC87183DA5133E675BC9B8E30BEBF1B945E622E26BC05B2D349` |
| SSDEEP | `12288:Fmo1yGsaUCcVUFvFjIc6odKSSkFPwXrP7Lr5nglw1ith:woMNNVoSc6o4S1kNglI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_05d377c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05d377c8263e20008aca7bcd0f9b9187d2c70599fdfec334bb6bbfb03e52ebd4"
    family = "unknown"
    file_name = "warden_8360_fixed.exe"
    file_type = "exe"
    first_seen = "2026-10-17 01:34:53"
  condition:
    hash.sha256(0, filesize) == "05d377c8263e20008aca7bcd0f9b9187d2c70599fdfec334bb6bbfb03e52ebd4"
}
```

### Sample 43: `5757bb1fa8d85ec5`

| Field | Value |
|---|---|
| SHA-256 | `5757bb1fa8d85ec537730756ba96c57d32482b8813db22fc1152a6274619559e` |
| Family label | `Mirai` |
| File name | `5` |
| File type | `elf` |
| First seen | `2026-10-17 01:28:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6414d5f079b1ef04aa93f694897ed3f4` |
| SHA-1 | `8a5b8ac01e41c43c388f414c186a5bab32840e8b` |
| SHA-256 | `5757bb1fa8d85ec537730756ba96c57d32482b8813db22fc1152a6274619559e` |
| SHA3-384 | `d9b0df68c8893f46d293e7704490d237ee351053f7f4523d82d4facfcae238a4576b1d10358e0fca9bdec87a3b7708a1` |
| TLSH | `T1CD258C5377218F58F365D27005F38765BAA911E30BE294C693BCD2207A50A2D6C6FFE8` |
| TELFHASH | `t1c351be58087813b4a3215c9d49edff36e6a260df7e1a2c378a10e85da72ae839d10c1d` |
| SSDEEP | `12288:1uVBIUAq5QIKdFvbCQ4Q7g0kNxuZQNx70F4KXGc/RITj7zbNUBSgpZtllR3x/K:U0qevbz4Kxq0F4KXGc/Ej7zurlRg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_5757bb1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5757bb1fa8d85ec537730756ba96c57d32482b8813db22fc1152a6274619559e"
    family = "Mirai"
    file_name = "5"
    file_type = "elf"
    first_seen = "2026-10-17 01:28:34"
  condition:
    hash.sha256(0, filesize) == "5757bb1fa8d85ec537730756ba96c57d32482b8813db22fc1152a6274619559e"
}
```

### Sample 44: `126bffcade3468d8`

| Field | Value |
|---|---|
| SHA-256 | `126bffcade3468d8b84243ce192422077d23e802865b35a7c9e780fc99c02fed` |
| Family label | `Mirai` |
| File name | `disspoor` |
| File type | `elf` |
| First seen | `2026-10-17 01:24:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46c54123fe6480bd7f9dbc5640f3ec7f` |
| SHA-1 | `1fdd11ebfb7dba8ad49615368189683b12a1b439` |
| SHA-256 | `126bffcade3468d8b84243ce192422077d23e802865b35a7c9e780fc99c02fed` |
| SHA3-384 | `ba3330a31896349113b548e2710dec386229b45e8733cf8c2fd430d2d48dec4cc315f003633d2d290c78a5010a45de2d` |
| TLSH | `T1A8145C05731D0943E1672EF03B3F27D193EF9A9221F5EA442A0FBA498272D326589DDD` |
| SSDEEP | `6144:umZlJhi2riAErnMYp8AxD5AhAnU8vQny3i:uqrDMMYp8aKWQy3i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_126bffca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "126bffcade3468d8b84243ce192422077d23e802865b35a7c9e780fc99c02fed"
    family = "Mirai"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-17 01:24:31"
  condition:
    hash.sha256(0, filesize) == "126bffcade3468d8b84243ce192422077d23e802865b35a7c9e780fc99c02fed"
}
```

### Sample 45: `a1d2ffce407ed2f0`

| Field | Value |
|---|---|
| SHA-256 | `a1d2ffce407ed2f042eaf0ffdadea3e3dca0d9831ca51d743e6bae9c8ff64036` |
| Family label | `Mirai` |
| File name | `a1d2ffce407ed2f042eaf0ffdadea3e3dca0d9831ca51d743e6bae9c8ff64036` |
| File type | `elf` |
| First seen | `2026-10-17 01:22:02` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcaeac22e93540dbccc9d9e8a322117c` |
| SHA-1 | `8f82c580015a268226bcb7a60f1bdd7568d141a6` |
| SHA-256 | `a1d2ffce407ed2f042eaf0ffdadea3e3dca0d9831ca51d743e6bae9c8ff64036` |
| SHA3-384 | `36be761540e9df269956cc3dd4c74fb2fb522d84b7c7a7e4ce76ab9af49a31a4780b081416f2ad2f8becff38b5f660b5` |
| TLSH | `T14F358D1AB2B3F6BCD007C03087DBCAA15531F07569323D7B27C4DA392EA6DA51369B25` |
| TELFHASH | `t143117a314b6155264792cd44dcde6363212dca6a9b0dfeb7ea704a4c21050fed93bc8f` |
| SSDEEP | `24576:b9DaU4ISfUyr0SSallNgwP5tNX2RwMcsSpqEFTWo1:0llNgwP5v2ZON` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_a1d2ffce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1d2ffce407ed2f042eaf0ffdadea3e3dca0d9831ca51d743e6bae9c8ff64036"
    family = "Mirai"
    file_name = "a1d2ffce407ed2f042eaf0ffdadea3e3dca0d9831ca51d743e6bae9c8ff64036"
    file_type = "elf"
    first_seen = "2026-10-17 01:22:02"
  condition:
    hash.sha256(0, filesize) == "a1d2ffce407ed2f042eaf0ffdadea3e3dca0d9831ca51d743e6bae9c8ff64036"
}
```

### Sample 46: `060b43e899cf21be`

| Field | Value |
|---|---|
| SHA-256 | `060b43e899cf21bee854bd3b7cab84024328c95961570f72c22b359bc327129e` |
| Family label | `Mirai` |
| File name | `dissarm6` |
| File type | `elf` |
| First seen | `2026-10-17 01:16:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d6670b5f9bffc6f25dc18f038f5bcc1` |
| SHA-1 | `1eeb131a4044aced61f7f80f016fbf9128a56a85` |
| SHA-256 | `060b43e899cf21bee854bd3b7cab84024328c95961570f72c22b359bc327129e` |
| SHA3-384 | `ac0361913ff59d87bc1ebfcf8fb084797037a851e14724b5a01b9b65b5d68845b4f30aec7cf1a032b160763d6ec414d5` |
| TLSH | `T1C0241956F8819F11D5D016BAFE1E528D33231B78E2EE32169E246F30778A87B0E3E515` |
| TELFHASH | `t1dec08c30aa440190f071448240ed231002f2c1476c023a1c66c0376efa52fceb012a2a` |
| SSDEEP | `6144:yoKnZBYNQXgHfgo+XVAF9aqF8FXq1OmT6OG:yoKnZ+NQwHfg/Xe9aqCa1OmTnG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_060b43e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "060b43e899cf21bee854bd3b7cab84024328c95961570f72c22b359bc327129e"
    family = "Mirai"
    file_name = "dissarm6"
    file_type = "elf"
    first_seen = "2026-10-17 01:16:35"
  condition:
    hash.sha256(0, filesize) == "060b43e899cf21bee854bd3b7cab84024328c95961570f72c22b359bc327129e"
}
```

### Sample 47: `1e5da327a36b6bbe`

| Field | Value |
|---|---|
| SHA-256 | `1e5da327a36b6bbe46f7fba5ab2e64536f1b368a115cc5e5349a127191a4423e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-17 01:00:39` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, s, soft` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e61c954624c9dcb7530418d90cb1885` |
| SHA-1 | `e8585e54aaf7c1d699d1256b1e4aeb68b46abb54` |
| SHA-256 | `1e5da327a36b6bbe46f7fba5ab2e64536f1b368a115cc5e5349a127191a4423e` |
| SHA3-384 | `a492097c831aa7f40afb8dc2c084196dcf42b226b1beeb4bc5f02a420f5c78928abf0d2e52f604c0da2ccb03c83b4570` |
| IMPHASH | `766fcbd1b8bf42b2c44f38dc87f985c8` |
| TLSH | `T18EC53807E3FA41D8E1FBE730CAB6A2731D72BC195538B55D1685DA251E30E708F29B22` |
| SSDEEP | `49152:DAccPeJ3Ekxms8mUpSnrxmywt7nl0bvexJYlJi:z3lvnkfbl0bvexe` |
| ICON-DHASH | `944a63b4125848c4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_1e5da327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e5da327a36b6bbe46f7fba5ab2e64536f1b368a115cc5e5349a127191a4423e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-17 01:00:39"
  condition:
    hash.sha256(0, filesize) == "1e5da327a36b6bbe46f7fba5ab2e64536f1b368a115cc5e5349a127191a4423e"
}
```

### Sample 48: `79dfb54e43915655`

| Field | Value |
|---|---|
| SHA-256 | `79dfb54e439156550fc92509ad4c9b809e98d46cd5dfe48068569012ffb84290` |
| Family label | `unknown` |
| File name | `cegg_x86_64` |
| File type | `elf` |
| First seen | `2026-10-17 00:44:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e18252003658b715b8709ab818db4dc` |
| SHA-1 | `eebf2571e0eb86328eeee8226bb51b17722d70f0` |
| SHA-256 | `79dfb54e439156550fc92509ad4c9b809e98d46cd5dfe48068569012ffb84290` |
| SHA3-384 | `29019404c014ce2a60e08c8decd3e08e73bffc8e30940d258f15e5bb470d4ac097ef70b81d19e3e9d3d65a39b4175d84` |
| TLSH | `T15D134BBBE1766A2FC905C33784A8BC63E1E33B0C9293DD1978D5769E67859CD0A101B2` |
| SSDEEP | `768:SYmrifPJpZikHKrGqSBwE00nVUrdEa4Bd/evJaIhdsFq/C:SE5pYkwkw22+AJzsFqK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_79dfb54e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79dfb54e439156550fc92509ad4c9b809e98d46cd5dfe48068569012ffb84290"
    family = "unknown"
    file_name = "cegg_x86_64"
    file_type = "elf"
    first_seen = "2026-10-17 00:44:35"
  condition:
    hash.sha256(0, filesize) == "79dfb54e439156550fc92509ad4c9b809e98d46cd5dfe48068569012ffb84290"
}
```

### Sample 49: `e850c2892c9017cf`

| Field | Value |
|---|---|
| SHA-256 | `e850c2892c9017cfd3c5cf371e18c0da2cf399571b923200655701dd5075fbdd` |
| Family label | `unknown` |
| File name | `e850c2892c9017cfd3c5cf371e18c0da2cf399571b923200655701dd5075fbdd` |
| File type | `elf` |
| First seen | `2026-10-17 00:42:34` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf0aa101eba0916f4ae356c7e52bc52c` |
| SHA-1 | `5d95fb6270df81697bf027d8467c1db23dfb7eac` |
| SHA-256 | `e850c2892c9017cfd3c5cf371e18c0da2cf399571b923200655701dd5075fbdd` |
| SHA3-384 | `bc5c44056215e32aa5b8d342a5fae9a2e5ab2a61885b467b6de4055614b3eed22d31cb8e19d98481b4f138521d718d0e` |
| TLSH | `T1CCC5E853E8E21194C9EFD264D666812BFD763009077C23D739A187301F2AFF4A9B9B52` |
| TELFHASH | `t1ef429fb549bc34f1b6aaca50f7b27474a63725b563e838f01423a881efd1e811896877` |
| SSDEEP | `49152:Sap5TiLKUkiiWFkWumVCtQeo5lAeiDW4MJjkpqo9K:SMkKU7kWuuuoYeeMuw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_e850c289
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e850c2892c9017cfd3c5cf371e18c0da2cf399571b923200655701dd5075fbdd"
    family = "unknown"
    file_name = "e850c2892c9017cfd3c5cf371e18c0da2cf399571b923200655701dd5075fbdd"
    file_type = "elf"
    first_seen = "2026-10-17 00:42:34"
  condition:
    hash.sha256(0, filesize) == "e850c2892c9017cfd3c5cf371e18c0da2cf399571b923200655701dd5075fbdd"
}
```

### Sample 50: `ffba182b6c188536`

| Field | Value |
|---|---|
| SHA-256 | `ffba182b6c188536938e85f1f61d86304224cee6fcb33d1fdc9928c0e01c9631` |
| Family label | `unknown` |
| File name | `ffba182b6c188536938e85f1f61d86304224cee6fcb33d1fdc9928c0e01c9631` |
| File type | `elf` |
| First seen | `2026-10-17 00:41:40` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f69075373fa791c0412e662cfa63f8f8` |
| SHA-1 | `02754881d16ef726ad1c1b0627de65e8fa491632` |
| SHA-256 | `ffba182b6c188536938e85f1f61d86304224cee6fcb33d1fdc9928c0e01c9631` |
| SHA3-384 | `09e93e132201b116a16ebbe73523738ea4ff44b287f788306a5acba46d2ebf241a78bb2559e0a58000cf525e5acc6555` |
| TLSH | `T10907C769E9C700F7E5869C7060BE712F2335A21A8739E8B2E1C03F57F967B71492152E` |
| TELFHASH | `t189d21673169864eca7f08403825bb528cee2f0772af078b538e37c91d672d576726939` |
| SSDEEP | `196608:QTMvNxYm+z3VXg4isJNsTeKF3CYKFNRvoY1gl5thJwwZNHokoo7anMK9TUjPyKZj:QgvdbSgT7317aJ0UO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_ffba182b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffba182b6c188536938e85f1f61d86304224cee6fcb33d1fdc9928c0e01c9631"
    family = "unknown"
    file_name = "ffba182b6c188536938e85f1f61d86304224cee6fcb33d1fdc9928c0e01c9631"
    file_type = "elf"
    first_seen = "2026-10-17 00:41:40"
  condition:
    hash.sha256(0, filesize) == "ffba182b6c188536938e85f1f61d86304224cee6fcb33d1fdc9928c0e01c9631"
}
```

### Sample 51: `4a5582464baaef23`

| Field | Value |
|---|---|
| SHA-256 | `4a5582464baaef23f15f2a03ef7aaa6d8e11f60e6fb091d377051b26c9d3dad4` |
| Family label | `unknown` |
| File name | `4a5582464baaef23f15f2a03ef7aaa6d8e11f60e6fb091d377051b26c9d3dad4` |
| File type | `elf` |
| First seen | `2026-10-17 00:41:36` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cebca265221601978da7ff9d0354a5a` |
| SHA-1 | `62585837a8f91da20b772311ec09748ce6836910` |
| SHA-256 | `4a5582464baaef23f15f2a03ef7aaa6d8e11f60e6fb091d377051b26c9d3dad4` |
| SHA3-384 | `7118eca8d4d55759cc868d9b1ae104597d98f2ae8feaec469a5d2eaa48c814a4ac75de248344ab14fad26675251848ae` |
| TLSH | `T1B507C769E9C700F7E5869C7060BE712F2335A21A8739E8B2E1C03F57F967B71492152E` |
| TELFHASH | `t189d21673169864eca7f08403825bb528cee2f0772af078b538e37c91d672d576726939` |
| SSDEEP | `196608:QTMvNxYm+z3VXg4isJNsTeKF3CYKFNRvoY1gl5thJwwZNHokoo7anMK9TUjPyKZd:QgvdbSgT7317aJ0Us` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_4a558246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a5582464baaef23f15f2a03ef7aaa6d8e11f60e6fb091d377051b26c9d3dad4"
    family = "unknown"
    file_name = "4a5582464baaef23f15f2a03ef7aaa6d8e11f60e6fb091d377051b26c9d3dad4"
    file_type = "elf"
    first_seen = "2026-10-17 00:41:36"
  condition:
    hash.sha256(0, filesize) == "4a5582464baaef23f15f2a03ef7aaa6d8e11f60e6fb091d377051b26c9d3dad4"
}
```

### Sample 52: `8cb15278aabcfc7f`

| Field | Value |
|---|---|
| SHA-256 | `8cb15278aabcfc7fe1ef27c54b2a3264d29390e8f1a2cdb7857ab241eff911cb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-17 00:41:35` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, signed, SLOT1.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a32181dbc204cbf41d96a82f6fa5e15` |
| SHA-1 | `c16ca15842ee2b91bb0e992daa2e5e1072189e6d` |
| SHA-256 | `8cb15278aabcfc7fe1ef27c54b2a3264d29390e8f1a2cdb7857ab241eff911cb` |
| SHA3-384 | `87a9bd87a49b16c669ffeae41c096900e2753e85fd292563392970500314dea3b8155106244ff0a29b81adcac0c2e67e` |
| IMPHASH | `3e9ea78ba3fffae496ea28e81ab04a04` |
| TLSH | `T15FB45A13E7A36DECD672C17880696627BF717D3B8625B63B8B10460BAF13B605D2D309` |
| SSDEEP | `12288:GplG66IVLyDAtUJ6VCxjTN1TSjeYnB8bu6ZaMu+9vqf:GplG6hVLyDAtkvXQ8btZpu+9Sf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_8cb15278
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cb15278aabcfc7fe1ef27c54b2a3264d29390e8f1a2cdb7857ab241eff911cb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-17 00:41:35"
  condition:
    hash.sha256(0, filesize) == "8cb15278aabcfc7fe1ef27c54b2a3264d29390e8f1a2cdb7857ab241eff911cb"
}
```

### Sample 53: `cc8692dc9180b48c`

| Field | Value |
|---|---|
| SHA-256 | `cc8692dc9180b48c118438c6703d25861689822fffc9f067a3d8294e3a47afc2` |
| Family label | `Mirai` |
| File name | `dissmpsl` |
| File type | `elf` |
| First seen | `2026-10-17 00:38:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20058e1bc2b6de7b16eb3ba3dcbf6db8` |
| SHA-1 | `e43edd2739d90e8cf0bd82e7dbd3463e279d20e4` |
| SHA-256 | `cc8692dc9180b48c118438c6703d25861689822fffc9f067a3d8294e3a47afc2` |
| SHA3-384 | `4feebf11da5c8d15b97357bff96894457299e7b75171dc8d9e9037d065beebb4f37c4de3777742dc79a105a6385b70fb` |
| TLSH | `T19B44C70AAF610EFBD8ABDD3746E90B01258C654712A83F3A3974D928F54B54F4AD3C78` |
| SSDEEP | `3072:b5tyhTmyQ5hCDeK89OsiZKgf8qjOD7hrnPbPeYE:b5EXQLCqK8ekRqIVnPDeYE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_cc8692dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc8692dc9180b48c118438c6703d25861689822fffc9f067a3d8294e3a47afc2"
    family = "Mirai"
    file_name = "dissmpsl"
    file_type = "elf"
    first_seen = "2026-10-17 00:38:41"
  condition:
    hash.sha256(0, filesize) == "cc8692dc9180b48c118438c6703d25861689822fffc9f067a3d8294e3a47afc2"
}
```

### Sample 54: `322a9bdadc796f2b`

| Field | Value |
|---|---|
| SHA-256 | `322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d` |
| Family label | `AMOS` |
| File name | `macho_322a9bdadc79.bin` |
| File type | `macho` |
| First seen | `2026-10-17 00:38:39` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `063d431494f6334fcb4ff7bed85cc4f4` |
| SHA-1 | `adf18b48661a7e4bc48619f332d03ea343a301c5` |
| SHA-256 | `322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d` |
| SHA3-384 | `af2e00980c56e28791e22496a0b3585aa6e619275e99e5cb9fce120912d7f7e9a29599452dd4781e1b7995aea574f8b1` |
| TLSH | `T1408501209E7106D7F4812232AD988F4175B06BA0AFC8B7FD6625D2462E3D2D3F673356` |
| SSDEEP | `24576:FNDpUqb4eisbhNEnyf0EOWN8uT4TMeNaI7USvset2lGIEqEXEsT0:rCy8EOWbETpNaI7USvseti9EqEhA` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_054_322a9bda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d"
    family = "AMOS"
    file_name = "macho_322a9bdadc79.bin"
    file_type = "macho"
    first_seen = "2026-10-17 00:38:39"
  condition:
    hash.sha256(0, filesize) == "322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d"
}
```

### Sample 55: `972345fe982568da`

| Field | Value |
|---|---|
| SHA-256 | `972345fe982568daf6404e8b6099920f7eaf78fdc8a027525eac8989ebd222d0` |
| Family label | `unknown` |
| File name | `972345fe982568daf6404e8b6099920f7eaf78fdc8a027525eac8989ebd222d0` |
| File type | `elf` |
| First seen | `2026-10-17 00:38:04` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25b10fd028521d7f3e6f6bf8aa75c976` |
| SHA-1 | `793dfca5eb591e7f8f1f0f41c4410968671a7fc0` |
| SHA-256 | `972345fe982568daf6404e8b6099920f7eaf78fdc8a027525eac8989ebd222d0` |
| SHA3-384 | `e69df1b072f8dd6ee5c563b9fa34f419859aa4eab4cf88766f72cd99833002b0280a165de524d0de9a8889f7f936f188` |
| TLSH | `T160E6E869E9C700F7E5869C7060AA712F3335A21A8739E8B3E1C03F57F967B71492152E` |
| TELFHASH | `t189d21673169864eca7f08403825bb528cee2f0772af078b538e37c91d672d576726939` |
| SSDEEP | `196608:QTMvNxYm+z3VXg4isJNsTeKF3CYKFNRvoY1gl5thJwwZNHokoo7anMK9TUjPf:QgvdbSgT7317a+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_972345fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "972345fe982568daf6404e8b6099920f7eaf78fdc8a027525eac8989ebd222d0"
    family = "unknown"
    file_name = "972345fe982568daf6404e8b6099920f7eaf78fdc8a027525eac8989ebd222d0"
    file_type = "elf"
    first_seen = "2026-10-17 00:38:04"
  condition:
    hash.sha256(0, filesize) == "972345fe982568daf6404e8b6099920f7eaf78fdc8a027525eac8989ebd222d0"
}
```

### Sample 56: `7b79ca4b369cc7e9`

| Field | Value |
|---|---|
| SHA-256 | `7b79ca4b369cc7e95fd543727325e05eb19658b4b786ec758ba83072b01e7d52` |
| Family label | `Mirai` |
| File name | `dissarch64` |
| File type | `elf` |
| First seen | `2026-10-17 00:36:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `133e24d0c77f864ec9c89201b23eb169` |
| SHA-1 | `a0d4d75672880dc4cdd769b98595f5e21543a0aa` |
| SHA-256 | `7b79ca4b369cc7e95fd543727325e05eb19658b4b786ec758ba83072b01e7d52` |
| SHA3-384 | `905e8cc602042fc42364b46541c8c0f4f0b9db12646f836536cc1b94f9a502d02555a2863d1637ce75deac220bc6af86` |
| TLSH | `T1FCE49E987A8D7C43E3C7F33DCE8ACA71322BB5E99312D2A23501525DD4C6EA9CEB1541` |
| SSDEEP | `12288:QikbNL3ean4ctq8kp3hfVlMJ7mGq7+Pab+Vh97F2Swu8BFs5sgV6N:QT3n4ctuvVl+7mGq6k+z9/wB+0N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_7b79ca4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b79ca4b369cc7e95fd543727325e05eb19658b4b786ec758ba83072b01e7d52"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-17 00:36:41"
  condition:
    hash.sha256(0, filesize) == "7b79ca4b369cc7e95fd543727325e05eb19658b4b786ec758ba83072b01e7d52"
}
```

### Sample 57: `5b3c6ec6e558bf2e`

| Field | Value |
|---|---|
| SHA-256 | `5b3c6ec6e558bf2e4dcff9b8f810fc5522cb9ab6271522c2ce8b0f140151ba8b` |
| Family label | `AMOS` |
| File name | `macho_5b3c6ec6e558.bin` |
| File type | `macho` |
| First seen | `2026-10-17 00:36:09` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4055fb4bba8472488e2882f338b39e78` |
| SHA-1 | `3e6e9b7b56aac06890129070c22c42cbe36de456` |
| SHA-256 | `5b3c6ec6e558bf2e4dcff9b8f810fc5522cb9ab6271522c2ce8b0f140151ba8b` |
| SHA3-384 | `736ef3b6c0bf9cdc03dcffa8d9831a4dd858bc73033fd10a31c097a38921f33af06dd8b5b21f9e155002a3e4632fbf87` |
| TLSH | `T1AEA5F1109F6A226EF7CA3173DC205F25B850A5810E545FFAA235D37AED35683BA33631` |
| SSDEEP | `24576:iUbR9D5Eh89gaZ7SJgGtQWZLuCkglU06S3yBTq3DWAI38G1N7m59KuGykLM+V0mT:HGgBvVqzWAIhN7mfKuAL6Tha7` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_057_5b3c6ec6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b3c6ec6e558bf2e4dcff9b8f810fc5522cb9ab6271522c2ce8b0f140151ba8b"
    family = "AMOS"
    file_name = "macho_5b3c6ec6e558.bin"
    file_type = "macho"
    first_seen = "2026-10-17 00:36:09"
  condition:
    hash.sha256(0, filesize) == "5b3c6ec6e558bf2e4dcff9b8f810fc5522cb9ab6271522c2ce8b0f140151ba8b"
}
```

### Sample 58: `51ad0fe8782d9756`

| Field | Value |
|---|---|
| SHA-256 | `51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8` |
| Family label | `AMOS` |
| File name | `macho_51ad0fe8782d.bin` |
| File type | `macho` |
| First seen | `2026-10-17 00:32:55` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2c79175abeac23f568643b24aea5938` |
| SHA-1 | `de157bb94c8edd99d7c635d6128d1dda7a3db338` |
| SHA-256 | `51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8` |
| SHA3-384 | `894ea863104dc24f63a35e9061f1735c35768259cdda1a541e76786ba0916291fcfee94e46e302d7baa59400ab2fd66a` |
| TLSH | `T1D285F1404F6AA146C54E1173AC8ACF1845B870E0CE45DEEA6341A29ACE367D3B7671FF` |
| SSDEEP | `49152:ZbvQIbfqzFjlpILod4jy7URTYpOolScPxNjypNHoKRUb+nBZB:ZLKe` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_058_51ad0fe8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8"
    family = "AMOS"
    file_name = "macho_51ad0fe8782d.bin"
    file_type = "macho"
    first_seen = "2026-10-17 00:32:55"
  condition:
    hash.sha256(0, filesize) == "51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8"
}
```

### Sample 59: `285037bfb99b2dbf`

| Field | Value |
|---|---|
| SHA-256 | `285037bfb99b2dbf6376998f11f31623965af6ff7128c811c67619b3838014fe` |
| Family label | `Mirai` |
| File name | `dissx86` |
| File type | `elf` |
| First seen | `2026-10-17 00:32:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `582558e0e123878997864661cf820619` |
| SHA-1 | `388976e8996ab2827a64d6b4be2f1beed30bb6aa` |
| SHA-256 | `285037bfb99b2dbf6376998f11f31623965af6ff7128c811c67619b3838014fe` |
| SHA3-384 | `4e5b17cb569b600d314206dcf0898e9275ed4bcffa05517a42b61501fcdfa64352ea7247cbabcea4256d43e4a04b0911` |
| TLSH | `T178145C0AB5C190FDC8C6C27887AFE536E932B44D1234B51F1BD4AE226E5EE306B2D751` |
| TELFHASH | `t1f161da741dd6759c21d39749b24eed1dfe3208008ee671e8be17ece4ed4bb884d92462` |
| SSDEEP | `3072:brhpDYXvFP05pwERlBLRsQJ10D7/i2L0shei5OKSYtD1qyeXuYh:brhpDYXR+GEo2sLig0MOj1uYh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_285037bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "285037bfb99b2dbf6376998f11f31623965af6ff7128c811c67619b3838014fe"
    family = "Mirai"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-17 00:32:44"
  condition:
    hash.sha256(0, filesize) == "285037bfb99b2dbf6376998f11f31623965af6ff7128c811c67619b3838014fe"
}
```

### Sample 60: `13135f3ecb191728`

| Field | Value |
|---|---|
| SHA-256 | `13135f3ecb191728666b54ca56844f5c35e7d60ac056a8398bfcbd22e6d6f729` |
| Family label | `Mirai` |
| File name | `dissarm7` |
| File type | `elf` |
| First seen | `2026-10-17 00:30:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d1e3456163d25162747f86645bd319f` |
| SHA-1 | `ad57332bde7f2486b1a2ace366eca9359eba7d10` |
| SHA-256 | `13135f3ecb191728666b54ca56844f5c35e7d60ac056a8398bfcbd22e6d6f729` |
| SHA3-384 | `b242f5184a8439a075adf009230b8a9c10983d16dce6193b3afcb754707d8a4b0b9aa24fb343e94d9d088ffc5f7478d7` |
| TLSH | `T123142959FC81AF11D5D526BAFA5E4189336717BCE3FA71029E205F2423CA92F0F7A502` |
| TELFHASH | `t1e7c02b822a0d90e473dea80fd5bd2306c760d3424b84700d9504f8312ce64d3e030c03` |
| SSDEEP | `3072:cCXLUatkvmjP7+XjtI20svUOVziT31Zc8gm+DanBLmMzFYNKidI/hjKRlFcRp0xi:cCbAvmn85t0svjK31ZcJ/DanByMzFYN0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_13135f3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13135f3ecb191728666b54ca56844f5c35e7d60ac056a8398bfcbd22e6d6f729"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-17 00:30:51"
  condition:
    hash.sha256(0, filesize) == "13135f3ecb191728666b54ca56844f5c35e7d60ac056a8398bfcbd22e6d6f729"
}
```

### Sample 61: `ecf0f6b181632fb3`

| Field | Value |
|---|---|
| SHA-256 | `ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d` |
| Family label | `AMOS` |
| File name | `macho_ecf0f6b18163.bin` |
| File type | `macho` |
| First seen | `2026-10-17 00:29:29` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d05c4e8e90385e4a6b026c6fd19977be` |
| SHA-1 | `b17ec40f915e3c5bde2b7dbfecffcd9b675ca4c6` |
| SHA-256 | `ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d` |
| SHA3-384 | `f4c094770fcdaad5160579fb6e2a45f9df3ec3beabe9e67ef5470f7ac46491343472459007df2ca2cd2ebc78a5f58fb0` |
| TLSH | `T1FB85F11CFA295127D88529F2DC9C3F765790A3C39B4CABE863248777EC35643B527222` |
| SSDEEP | `24576:O6t4Ra/dZ3zjqg/lf/ilryVEUNR508oq/u7j0VO572J7UpJagbjUXk2dD9KA0ABn:RqIfalul5qP0VON1Xasop9+i` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_061_ecf0f6b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d"
    family = "AMOS"
    file_name = "macho_ecf0f6b18163.bin"
    file_type = "macho"
    first_seen = "2026-10-17 00:29:29"
  condition:
    hash.sha256(0, filesize) == "ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d"
}
```

### Sample 62: `a19c0b926b6fdc64`

| Field | Value |
|---|---|
| SHA-256 | `a19c0b926b6fdc64733bf7fb34685df27427fe01b8241ae1b1ff966004db1d35` |
| Family label | `Mirai` |
| File name | `bot` |
| File type | `elf` |
| First seen | `2026-10-17 00:28:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `874484b00138d9ec4c7b7ff281563c0e` |
| SHA-1 | `37ff7c37de1eb6ec55bbb88902df18b23acba467` |
| SHA-256 | `a19c0b926b6fdc64733bf7fb34685df27427fe01b8241ae1b1ff966004db1d35` |
| SHA3-384 | `acedb19a7830d5b3e60cde0c3150f18e101f542574d000ac3d937217cad232a7d15c20f845dd1b0686b28aea2cab11a8` |
| TLSH | `T187358C1AB2F3F6BCD007C0308B9BC6A15531F0756A322D7B37C4DA352EA6DA51369B25` |
| TELFHASH | `t12d21ad308b615a364b91de44d8de6363212dc92bcb0daeb7e9718a4c62060fdd53bc5f` |
| SSDEEP | `24576:akTIct9kvAN6DTDKZ4f6NkNgx1EtfUwW1KZDPuZrL/Q9EA:uKbNkNgx1L1AUL/o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_a19c0b92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a19c0b926b6fdc64733bf7fb34685df27427fe01b8241ae1b1ff966004db1d35"
    family = "Mirai"
    file_name = "bot"
    file_type = "elf"
    first_seen = "2026-10-17 00:28:32"
  condition:
    hash.sha256(0, filesize) == "a19c0b926b6fdc64733bf7fb34685df27427fe01b8241ae1b1ff966004db1d35"
}
```

### Sample 63: `9dd946dcf324d6a0`

| Field | Value |
|---|---|
| SHA-256 | `9dd946dcf324d6a0b54eec727d463103b18fe4013986b840867ac1053b4ff507` |
| Family label | `unknown` |
| File name | `cegg_mips` |
| File type | `elf` |
| First seen | `2026-10-17 00:28:30` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05231775187dade16708a82a49a16e84` |
| SHA-1 | `2799302fb4a71d57e6874ec9fdd414659704b220` |
| SHA-256 | `9dd946dcf324d6a0b54eec727d463103b18fe4013986b840867ac1053b4ff507` |
| SHA3-384 | `acd2b25fb12a739b67b91d62332e692a1c730105f1bddd476b57f62305c6c51945dc4df8de33773506de29560ffaa1fe` |
| TLSH | `T1F9F44CBFE9F92A2F8B18831B44D45C33A3A37749D3A398043AC637295B955DD0F206E5` |
| SSDEEP | `12288:m2dC14iwH6dHKWJAZ/MNZopLpuUHE02Cb2ghuHLr8hliA6ThqIiFO44hip:moC1QadHKoAZ/dpL0UHE02YhuHLr8hln` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_9dd946dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dd946dcf324d6a0b54eec727d463103b18fe4013986b840867ac1053b4ff507"
    family = "unknown"
    file_name = "cegg_mips"
    file_type = "elf"
    first_seen = "2026-10-17 00:28:30"
  condition:
    hash.sha256(0, filesize) == "9dd946dcf324d6a0b54eec727d463103b18fe4013986b840867ac1053b4ff507"
}
```

### Sample 64: `3bf9ac9cb26ecffd`

| Field | Value |
|---|---|
| SHA-256 | `3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3` |
| Family label | `AMOS` |
| File name | `macho_3bf9ac9cb26e.bin` |
| File type | `macho` |
| First seen | `2026-10-17 00:26:55` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c75f5fe56280172fc4c3e0a1c5745a1` |
| SHA-1 | `76b121f865cf60eb67e2548a459963f1fe7bd8e4` |
| SHA-256 | `3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3` |
| SHA3-384 | `b9b3c57b73162f4c4a48ba8992dfa0fde386778edff91f9e30c58600ece8cf421e58cd4d9d202ac959ddfa9b46cc0203` |
| TLSH | `T11E85E010516A117AD44A2D33ECA00BAC54F0AA915ACCBFF95371EB267D37F43B9A7321` |
| SSDEEP | `49152:0yuSuKRFe7Pp8AxdIr1RtL5b5+tJGWhl85vNf:qvqV` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_064_3bf9ac9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3"
    family = "AMOS"
    file_name = "macho_3bf9ac9cb26e.bin"
    file_type = "macho"
    first_seen = "2026-10-17 00:26:55"
  condition:
    hash.sha256(0, filesize) == "3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3"
}
```

### Sample 65: `fbeacf6c0412e4a6`

| Field | Value |
|---|---|
| SHA-256 | `fbeacf6c0412e4a610b4dcde1d6156c18dccf100003799ccc0703069e0419786` |
| Family label | `Vidar` |
| File name | `975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2.exe` |
| File type | `exe` |
| First seen | `2026-10-17 00:26:24` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e805fdd8992fdfca7d2b73e308617829` |
| SHA-1 | `7738e751c2ba4f8c8aab90741c4258a68adb6368` |
| SHA-256 | `fbeacf6c0412e4a610b4dcde1d6156c18dccf100003799ccc0703069e0419786` |
| SHA3-384 | `798e03bb5a4c8ed1ce746a79e779856a33e985faa1eb55c3d2f20374e82e551b982de6ba4167564f711470713093bb57` |
| TLSH | `T1D055518EC48253B6B3D6F723961DD622ACF6350980B68675CF453E794F06F20A428EDD` |
| SSDEEP | `12288:3wsu/dST3qB4t6RVqx8tgBdlFhyWII5jvVLeXAQTHhadwEpxHD:3wvST3qB4ERExFWIAqxHD` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_065_fbeacf6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbeacf6c0412e4a610b4dcde1d6156c18dccf100003799ccc0703069e0419786"
    family = "Vidar"
    file_name = "975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2.exe"
    file_type = "exe"
    first_seen = "2026-10-17 00:26:24"
  condition:
    hash.sha256(0, filesize) == "fbeacf6c0412e4a610b4dcde1d6156c18dccf100003799ccc0703069e0419786"
}
```

### Sample 66: `975f5c0dd3dc7fc5`

| Field | Value |
|---|---|
| SHA-256 | `975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2` |
| Family label | `Vidar` |
| File name | `975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2.exe` |
| File type | `exe` |
| First seen | `2026-10-17 00:26:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `533346133d52982b903922926fc76610` |
| SHA-1 | `7a88b1c12bbbce1162fa8440186dc4a25e439e9e` |
| SHA-256 | `975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2` |
| SHA3-384 | `561aeef576f6a16441a81bc8348235b6276132c5cf16e540cc6280c3687d29669510a5a49b3c71b8f62bf83b2c3f8509` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T14C8422A1E110A2ADFDEC8E73426083C96A0EBF7C75CFD774964CD14073E8EA0AA15748` |
| SSDEEP | `6144:rKvFHLLfyDGBkbXxcijx8WyKLHMGbYmbJQmLeD2wUILOn87ErG7CjNTAb5+eDFJl:rKdCD7bBcYxlHHMGkmlQmLMS2O8Er2C2` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_066_975f5c0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2"
    family = "Vidar"
    file_name = "975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2.exe"
    file_type = "exe"
    first_seen = "2026-10-17 00:26:09"
  condition:
    hash.sha256(0, filesize) == "975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2"
}
```

### Sample 67: `067120ddcaa4c0da`

| Field | Value |
|---|---|
| SHA-256 | `067120ddcaa4c0dab76f83e7a194a3f230e9b94749ede86ba17ca318d250f70c` |
| Family label | `Mirai` |
| File name | `067120ddcaa4c0da.bin` |
| File type | `elf` |
| First seen | `2026-10-17 00:24:49` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `079d2d4792e57f4b87807a265e4c870b` |
| SHA-1 | `e5c3b17fb56ff79318f58b5e8e2b6ab4783ed51d` |
| SHA-256 | `067120ddcaa4c0dab76f83e7a194a3f230e9b94749ede86ba17ca318d250f70c` |
| SHA3-384 | `b7ec4f51b212f8d22dc89fadd6e52b56acc8fb5a3c01886c45e10fd31b755a49d9249279e0c240c08aeae51860d6c20b` |
| TLSH | `T188441B877AB55ED6C8AFCD3051ADC33A01CC84CB93F9B31FD6688DC9B9181C0A5EA594` |
| TELFHASH | `t11401cb496e3f0a29eea32928ccac1bb1600b804274b24b31cf1cc6c0c07b50ba109e5f` |
| SSDEEP | `6144:X1DWD+HtZigATWqGpeVSAJ6gp8Vtv0jIL:X1DWdgATWI6eStv0jIL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_067120dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "067120ddcaa4c0dab76f83e7a194a3f230e9b94749ede86ba17ca318d250f70c"
    family = "Mirai"
    file_name = "067120ddcaa4c0da.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:49"
  condition:
    hash.sha256(0, filesize) == "067120ddcaa4c0dab76f83e7a194a3f230e9b94749ede86ba17ca318d250f70c"
}
```

### Sample 68: `0eb31ddca6741091`

| Field | Value |
|---|---|
| SHA-256 | `0eb31ddca6741091e0abfd838fdbaa473566a410072f39beefc855938253b4ab` |
| Family label | `Mirai` |
| File name | `0eb31ddca6741091.bin` |
| File type | `elf` |
| First seen | `2026-10-17 00:24:41` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3030948f3769a3df32c91610276119e0` |
| SHA-1 | `a38d476f7db53a15deb8f959ccf655bb84f0589c` |
| SHA-256 | `0eb31ddca6741091e0abfd838fdbaa473566a410072f39beefc855938253b4ab` |
| SHA3-384 | `c1f83fb499e8f63a90241737cc96a557997c53ef3d70daf086efc3df7081661a83187bc42929b02270d79952692f4404` |
| TLSH | `T13734098EED7EEE80CEF68134A4E00B7B7079908AC3F8F45AC64149F9F65B5C0A61D552` |
| SSDEEP | `3072:aVHrJmz8xypE3hLDkk1SjPW1deTfbIrCRmeKhRMnE4Gg4:YrJE80pERLDN1SjRfMC0eKMG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_0eb31ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eb31ddca6741091e0abfd838fdbaa473566a410072f39beefc855938253b4ab"
    family = "Mirai"
    file_name = "0eb31ddca6741091.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:41"
  condition:
    hash.sha256(0, filesize) == "0eb31ddca6741091e0abfd838fdbaa473566a410072f39beefc855938253b4ab"
}
```

### Sample 69: `2199147ebc24b697`

| Field | Value |
|---|---|
| SHA-256 | `2199147ebc24b697e11f273806e82e71471c2e56d2583b455cf3216c0bd1f871` |
| Family label | `Mirai` |
| File name | `2199147ebc24b697.bin` |
| File type | `elf` |
| First seen | `2026-10-17 00:24:32` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `546b0cd2655f8654cb139f7d8c8c3f7a` |
| SHA-1 | `3fa826cf08db2b628510da0db8c20dab306a61f6` |
| SHA-256 | `2199147ebc24b697e11f273806e82e71471c2e56d2583b455cf3216c0bd1f871` |
| SHA3-384 | `b253f9c87b369b65be9d796fcb42f5e4f4cf28def67536e23d5a018521302a68f78b3303ec41b5e0d91508d304d4629c` |
| TLSH | `T144140B8775B5AEA0CAF78435B1A503BC724683AAD3FEF40CCA154ED1AB5B0016B3D647` |
| SSDEEP | `3072:JEZ08HJZghTvnHayUTekv6QrLqnzQ/98aHXk3jkQ:J20/TSyUTekv6QrL+kCa2jkQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_2199147e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2199147ebc24b697e11f273806e82e71471c2e56d2583b455cf3216c0bd1f871"
    family = "Mirai"
    file_name = "2199147ebc24b697.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:32"
  condition:
    hash.sha256(0, filesize) == "2199147ebc24b697e11f273806e82e71471c2e56d2583b455cf3216c0bd1f871"
}
```

### Sample 70: `4710c3b055ffa309`

| Field | Value |
|---|---|
| SHA-256 | `4710c3b055ffa309aad3bca0420f2c9e573c9684d156c0cac4a648e2ebbd2bd3` |
| Family label | `Mirai` |
| File name | `4710c3b055ffa309.bin` |
| File type | `elf` |
| First seen | `2026-10-17 00:24:23` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fbca0226b6b6723529fd5b40ec79139f` |
| SHA-1 | `a54567845e15a0bb904e54c0a0e2ed28b68f3b2f` |
| SHA-256 | `4710c3b055ffa309aad3bca0420f2c9e573c9684d156c0cac4a648e2ebbd2bd3` |
| SHA3-384 | `2783e451d4ef658b88975fcd6cfc77cccbf47a05c16bb5a5b98edb7382b2027d9f53de6f5f34aa6a0e05ebcb07b33322` |
| TLSH | `T13464E84227E9EE92CEBA4134D5E1433C79AC5282D6FAE48FD3164A854D2B3C8791CFC5` |
| TELFHASH | `t143017b49ad7b492afd935968dca81bb1640b845274b64a21df0cdac0847b60ba10de5f` |
| SSDEEP | `3072:N6lg4erYu194osmOYMc5H1xn/W/lPH7gPZxLPG+AQM+w1qgyw95F2MA3nEejCbha:0K4eQc1C/lvWPG+AIwk8K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_4710c3b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4710c3b055ffa309aad3bca0420f2c9e573c9684d156c0cac4a648e2ebbd2bd3"
    family = "Mirai"
    file_name = "4710c3b055ffa309.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:23"
  condition:
    hash.sha256(0, filesize) == "4710c3b055ffa309aad3bca0420f2c9e573c9684d156c0cac4a648e2ebbd2bd3"
}
```

### Sample 71: `24f58f4db5552583`

| Field | Value |
|---|---|
| SHA-256 | `24f58f4db5552583f9be9d51b71cc9edcc3cdc8ea347528d36408bf1ed2ba56d` |
| Family label | `Mirai` |
| File name | `24f58f4db5552583.bin` |
| File type | `elf` |
| First seen | `2026-10-17 00:24:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6bf9ee3f624e4a66b2697cfa856242e` |
| SHA-1 | `5fc9d10e2c28e6defe82ceb55ac91d91e314f538` |
| SHA-256 | `24f58f4db5552583f9be9d51b71cc9edcc3cdc8ea347528d36408bf1ed2ba56d` |
| SHA3-384 | `0ee19935ded2e98c55a6bb409f9613e7e4c2300410d8a7dbdd6ff58f5de736f22786172d797161ab95e8978056f3d906` |
| TLSH | `T10A14F987B5B9AAA1CAF74439B19403BC724683AAD3FEB00DDE154DD1FB5D4012A3D2C6` |
| SSDEEP | `3072:IrDyUAEU/b2SYOmOyiu+DQdxUVRVKAjAtpeGiXKhdXk3W9:ICvboLOyiu+DYxUrmpe2hUW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_24f58f4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24f58f4db5552583f9be9d51b71cc9edcc3cdc8ea347528d36408bf1ed2ba56d"
    family = "Mirai"
    file_name = "24f58f4db5552583.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:14"
  condition:
    hash.sha256(0, filesize) == "24f58f4db5552583f9be9d51b71cc9edcc3cdc8ea347528d36408bf1ed2ba56d"
}
```

### Sample 72: `541b55560e4ec2a5`

| Field | Value |
|---|---|
| SHA-256 | `541b55560e4ec2a51d5afebafafa82f15d1bcadeacaf1dd58d3687838e758715` |
| Family label | `Mirai` |
| File name | `541b55560e4ec2a5.bin` |
| File type | `elf` |
| First seen | `2026-10-17 00:24:05` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffde071bc52298256c522c7e3c274ca1` |
| SHA-1 | `ab1b560716a5a4544765456da0e5a6fd2b6ef75d` |
| SHA-256 | `541b55560e4ec2a51d5afebafafa82f15d1bcadeacaf1dd58d3687838e758715` |
| SHA3-384 | `0e06ee18a88bcaf56a2306599f36d73434ae9de184815294029fdc39dfe924a3b54ec3d036ea84b474d19120f77741c4` |
| TLSH | `T131B34B21FD756C2BC5C4657B61E34231F5B64399257C8A1B7EA31D8CEF18320312FAAA` |
| SSDEEP | `1536:1Y5i3mQMri/xr8+c21eGyHMZ2tbiZtRAKveLXPLJblH256NWj5Vawiu/t+7ChT1l:m5zQ9xNcHKhAKmLegN+QpqH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_541b5556
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "541b55560e4ec2a51d5afebafafa82f15d1bcadeacaf1dd58d3687838e758715"
    family = "Mirai"
    file_name = "541b55560e4ec2a5.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:05"
  condition:
    hash.sha256(0, filesize) == "541b55560e4ec2a51d5afebafafa82f15d1bcadeacaf1dd58d3687838e758715"
}
```

### Sample 73: `33b6b85a3b873294`

| Field | Value |
|---|---|
| SHA-256 | `33b6b85a3b873294043e64c1320892ada5b99a24f0ab712ccd998e19619a14b6` |
| Family label | `unknown` |
| File name | `cegg_arm` |
| File type | `elf` |
| First seen | `2026-10-17 00:20:27` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7c084d6cc226e6a3fc006dbfa3c5bee` |
| SHA-1 | `03414b6d02181da2b95d49034f2981f52646f833` |
| SHA-256 | `33b6b85a3b873294043e64c1320892ada5b99a24f0ab712ccd998e19619a14b6` |
| SHA3-384 | `57e0ca6193f32f6259dba80da8c34ec9b499b7f43d7a2e91c4bce389c94d66f7e5b35384177cac9636600bbae0876061` |
| TLSH | `T179D44CBBE6F5261FCB04831F84D46C33A2937709E3A398083AD637695AA45DD4F206F5` |
| SSDEEP | `12288:zjPI5o6glkszsZTywPJOQZMAUYDn27Ohgl0cMMEiIwi/b1AMzISGI9RM:PPIy6uksoNywPIQZZU62ihgacX5IwUbA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_33b6b85a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33b6b85a3b873294043e64c1320892ada5b99a24f0ab712ccd998e19619a14b6"
    family = "unknown"
    file_name = "cegg_arm"
    file_type = "elf"
    first_seen = "2026-10-17 00:20:27"
  condition:
    hash.sha256(0, filesize) == "33b6b85a3b873294043e64c1320892ada5b99a24f0ab712ccd998e19619a14b6"
}
```

### Sample 74: `db2add78820b944a`

| Field | Value |
|---|---|
| SHA-256 | `db2add78820b944a2e2be6db47cb02111a387050ab2bc299f9f335edd2672ffa` |
| Family label | `Mirai` |
| File name | `adb.arm7` |
| File type | `elf` |
| First seen | `2026-10-17 00:20:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fa8ea543585a63c0db4c8523e98c5c9` |
| SHA-1 | `b6b8621232d031080d4959db41b7fd966fb63657` |
| SHA-256 | `db2add78820b944a2e2be6db47cb02111a387050ab2bc299f9f335edd2672ffa` |
| SHA3-384 | `998977717f7f1596150980e3d23f4273327f9215456dc0f63ca8727783ffbace2f8017b8e77c10619efbc5bdcc3488b5` |
| TLSH | `T19E141946F9419F01D5D235BAFAAF814933576BB8D3FA3101DE206F6023CA99B0F76612` |
| TELFHASH | `t1e7c02b822a0d90e473dea80fd5bd2306c760d3424b84700d9504f8312ce64d3e030c03` |
| SSDEEP | `3072:nCXLUatkvmjP7+XjtI20svUOVziT31Zc8gm+DanBLmMzFYNKidI/hjKRlFcRp0xa:nCbAvmn85t0svjK31ZcJ/DanByMzFYNA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_db2add78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db2add78820b944a2e2be6db47cb02111a387050ab2bc299f9f335edd2672ffa"
    family = "Mirai"
    file_name = "adb.arm7"
    file_type = "elf"
    first_seen = "2026-10-17 00:20:24"
  condition:
    hash.sha256(0, filesize) == "db2add78820b944a2e2be6db47cb02111a387050ab2bc299f9f335edd2672ffa"
}
```

### Sample 75: `d76706ec1ef248c6`

| Field | Value |
|---|---|
| SHA-256 | `d76706ec1ef248c678aeb8bf6484e2f8f6822d0d537dbce2be1de23045e65ae6` |
| Family label | `ValleyRAT` |
| File name | `18390d1648bf678684d5fcdfa07ae03d.exe` |
| File type | `exe` |
| First seen | `2026-10-17 00:15:11` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18390d1648bf678684d5fcdfa07ae03d` |
| SHA-1 | `1ef3498aaf1f8dbdf0127b6cb15a518a023ee5be` |
| SHA-256 | `d76706ec1ef248c678aeb8bf6484e2f8f6822d0d537dbce2be1de23045e65ae6` |
| SHA3-384 | `37d31560fbc5856e0983ac7ca610322c1e7db010ce654dd82967c0993a1b847d08033d3f5c1ddef14d1a6bb527da5856` |
| IMPHASH | `e975e3210d4eff6a558b0692075ca5b9` |
| TLSH | `T16C66D182CE5B8EF4B611D63DDF7A2B63A4F43CD80338E8F76B68420A3654B55463C51A` |
| SSDEEP | `98304:JL72KPALqtk4wooCt35gV7c357QCIaWap6SMrn7LhVCQcoma7z:+ooA5D57QCGap6SMrn7Ly2d` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_075_d76706ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d76706ec1ef248c678aeb8bf6484e2f8f6822d0d537dbce2be1de23045e65ae6"
    family = "ValleyRAT"
    file_name = "18390d1648bf678684d5fcdfa07ae03d.exe"
    file_type = "exe"
    first_seen = "2026-10-17 00:15:11"
  condition:
    hash.sha256(0, filesize) == "d76706ec1ef248c678aeb8bf6484e2f8f6822d0d537dbce2be1de23045e65ae6"
}
```

### Sample 76: `26f91ce3d8ee20dd`

| Field | Value |
|---|---|
| SHA-256 | `26f91ce3d8ee20dd027d4de026d6e5dd08604b6bec6b3142b55749150493285c` |
| Family label | `Mirai` |
| File name | `2` |
| File type | `elf` |
| First seen | `2026-10-17 00:14:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07b8cdd24ba7c4b968a881fbe7ba8f8d` |
| SHA-1 | `4cf96096a63f10e7411a74f382267986e4d6ce9a` |
| SHA-256 | `26f91ce3d8ee20dd027d4de026d6e5dd08604b6bec6b3142b55749150493285c` |
| SHA3-384 | `b3f4684454838340b6306ae4c8a0139377fe7f2534358d36b63fe35c2ab81ef75f7438e05c16a040480e07e860eafa3d` |
| TLSH | `T1DF457C89D7C3D4F1F26340F0068FDBF7156062355043FAF6EB482A66B476BD26A1632A` |
| TELFHASH | `t1ae22aeb36a6d58ec7be08515c65f3620cea6d13725f039b208f320e16b72e435e758b9` |
| SSDEEP | `24576:FsG56rKKLhhfahI/n6UeRKer201ZebJM75kMVeHgtvyfmFpt1X1/pt8:FKrKKthfah46hrSaZoJMNz1bJH8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_26f91ce3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26f91ce3d8ee20dd027d4de026d6e5dd08604b6bec6b3142b55749150493285c"
    family = "Mirai"
    file_name = "2"
    file_type = "elf"
    first_seen = "2026-10-17 00:14:20"
  condition:
    hash.sha256(0, filesize) == "26f91ce3d8ee20dd027d4de026d6e5dd08604b6bec6b3142b55749150493285c"
}
```

### Sample 77: `b0870f37b0968f0b`

| Field | Value |
|---|---|
| SHA-256 | `b0870f37b0968f0b10e698e2bb6815323ae8d5e88f67a753879974fccb28f58b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-17 00:04:42` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd19447a6cae8561f03e7961f5a5bfa7` |
| SHA-1 | `c4ab3ff2fa979a5a3970bb0d88865ba38ec97b6e` |
| SHA-256 | `b0870f37b0968f0b10e698e2bb6815323ae8d5e88f67a753879974fccb28f58b` |
| SHA3-384 | `a2546ed7ddf8356fe9326efd430ddcee74828c19e639f3ac5a897e3b57488f0c562ed4205ffb219911adfb12b6bc326e` |
| IMPHASH | `c573e0011fe51dfaa95f091456225dac` |
| TLSH | `T15435DF4DB69D4CECC156897C56F14D03AA6338D6076366FB52946FE93E322F38A3B600` |
| SSDEEP | `12288:NiqPh5UC6gDBeh912wNe/5UHOqmP0NV1cKH+nFyknbfnie3TEUucdf4h6i7mG0M1:Aq/KX2vRUHTmPNFykTndTxnf4hXA` |
| ICON-DHASH | `146896868e966814` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_b0870f37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0870f37b0968f0b10e698e2bb6815323ae8d5e88f67a753879974fccb28f58b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-17 00:04:42"
  condition:
    hash.sha256(0, filesize) == "b0870f37b0968f0b10e698e2bb6815323ae8d5e88f67a753879974fccb28f58b"
}
```

### Sample 78: `74c6f27ce2a20dd3`

| Field | Value |
|---|---|
| SHA-256 | `74c6f27ce2a20dd393e72bb54293cfece0cb05e599ff0010607f29e7c8a0f5dc` |
| Family label | `Mirai` |
| File name | `4` |
| File type | `elf` |
| First seen | `2026-10-16 23:57:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa1c9362956d092e065d0bf95562f902` |
| SHA-1 | `2de32bb466a4a454d20bf1592e15c9a2958342dc` |
| SHA-256 | `74c6f27ce2a20dd393e72bb54293cfece0cb05e599ff0010607f29e7c8a0f5dc` |
| SHA3-384 | `9ea42c80bfd4c7b7d23544e650919961245cc37d35024a0237bcc72f955555fe63bbf8a1f02357eec5e91bd9d154f510` |
| TLSH | `T1B3257C59FA0E3C42E3CAF37C9F4E87E5B21FB1A0C22351A23942524CD5C6AE9CAF1555` |
| SSDEEP | `24576:8txXyS0KDLKMSFG5wDIO7sqbeaEuR9inmmc5v9vAp:hMNGkO7q5uc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_74c6f27c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74c6f27ce2a20dd393e72bb54293cfece0cb05e599ff0010607f29e7c8a0f5dc"
    family = "Mirai"
    file_name = "4"
    file_type = "elf"
    first_seen = "2026-10-16 23:57:17"
  condition:
    hash.sha256(0, filesize) == "74c6f27ce2a20dd393e72bb54293cfece0cb05e599ff0010607f29e7c8a0f5dc"
}
```

### Sample 79: `69960c0c2f1efd9e`

| Field | Value |
|---|---|
| SHA-256 | `69960c0c2f1efd9e9e228d3ec1b435cdea5ad6ac7b5bb0c82b890a551dfff5f9` |
| Family label | `Mirai` |
| File name | `dissarm4` |
| File type | `elf` |
| First seen | `2026-10-16 23:55:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b40ae43fdd459b0ecb4cb5655685f5cf` |
| SHA-1 | `d13e4dcf9673f77686a28e5acd22c9ee11f9a56d` |
| SHA-256 | `69960c0c2f1efd9e9e228d3ec1b435cdea5ad6ac7b5bb0c82b890a551dfff5f9` |
| SHA3-384 | `8c619109a7b1f6be29a73bc351b8e7289d23fde00fea8dafbe7ecbe05feeaa0f61c96e07d7f1769caaa5e704a85722d8` |
| TLSH | `T15E141995FC519B23C6C1167BFB5E428C372B13B8D2EA31079D156F24378B86B0E7A642` |
| TELFHASH | `t1613128348acc18fc67d054cf50bea72ba37221b5775128552b6baf4a4653cd27530437` |
| SSDEEP | `6144:P7KLECiux8VrfhLPjewNq814PZE5/61YI8n:zKFiux8zJ14Pi5Ob8n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_69960c0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69960c0c2f1efd9e9e228d3ec1b435cdea5ad6ac7b5bb0c82b890a551dfff5f9"
    family = "Mirai"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-16 23:55:17"
  condition:
    hash.sha256(0, filesize) == "69960c0c2f1efd9e9e228d3ec1b435cdea5ad6ac7b5bb0c82b890a551dfff5f9"
}
```

### Sample 80: `345fd6e63c2c817f`

| Field | Value |
|---|---|
| SHA-256 | `345fd6e63c2c817ff28ac5e4fc6792e8ada4efadebe6a3692f334300fb35b187` |
| Family label | `Mirai` |
| File name | `3` |
| File type | `elf` |
| First seen | `2026-10-16 23:53:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50ddc4df542a85c49ed03a48dc3e61c1` |
| SHA-1 | `04412837ff08132b9464b74d5e6d79b98022ec67` |
| SHA-256 | `345fd6e63c2c817ff28ac5e4fc6792e8ada4efadebe6a3692f334300fb35b187` |
| SHA3-384 | `99f94a654f8ed81446f48ed360cce04dad363e73731810e31c417e72b4f24ad7b8bc034aefa07ed2707409630a18cbfa` |
| TLSH | `T1F3D4F199F7072E46C4D7E936588AC6824756E95B33F393093E43A6BB382D3714F28349` |
| SSDEEP | `12288:wXRTLObfafaSy3dWgTlS68XU25Dkjrzc+SIo/aBjBH/6jdXgpZ4J2aDEIi0d:wXRTLOcc3Tl38pkOyBjUR2I` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_345fd6e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "345fd6e63c2c817ff28ac5e4fc6792e8ada4efadebe6a3692f334300fb35b187"
    family = "Mirai"
    file_name = "3"
    file_type = "elf"
    first_seen = "2026-10-16 23:53:15"
  condition:
    hash.sha256(0, filesize) == "345fd6e63c2c817ff28ac5e4fc6792e8ada4efadebe6a3692f334300fb35b187"
}
```

### Sample 81: `4fa0c513e52bc0e0`

| Field | Value |
|---|---|
| SHA-256 | `4fa0c513e52bc0e01425e82cc533d915cde8e6a34041b16616eb064736dbb80e` |
| Family label | `Mirai` |
| File name | `7` |
| File type | `elf` |
| First seen | `2026-10-16 23:49:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ab0e487cd567c9ae72fae0616e3dac0` |
| SHA-1 | `0fca27608632730ba0e2ac1f500084e3333cf966` |
| SHA-256 | `4fa0c513e52bc0e01425e82cc533d915cde8e6a34041b16616eb064736dbb80e` |
| SHA3-384 | `7424f303641c2b30829356480952a6139ec611884bd68c504a81776851dcb40db519f492b1323db872a7ff800fdb7aef` |
| TLSH | `T133355B46FB1C8563C9470DF05A3F43D5F7287A4340F99229370EAB672621E3AA9C7399` |
| SSDEEP | `24576:nhE0X6OWQLr65vMU57GEqp/S2ZOMEn/aILX+HowJWN/+1mOYAa:hH6O/365vBaEqp/9ZOMEn/PDQo1NUmhh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_4fa0c513
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fa0c513e52bc0e01425e82cc533d915cde8e6a34041b16616eb064736dbb80e"
    family = "Mirai"
    file_name = "7"
    file_type = "elf"
    first_seen = "2026-10-16 23:49:15"
  condition:
    hash.sha256(0, filesize) == "4fa0c513e52bc0e01425e82cc533d915cde8e6a34041b16616eb064736dbb80e"
}
```

### Sample 82: `e39ad7aefcd3c46b`

| Field | Value |
|---|---|
| SHA-256 | `e39ad7aefcd3c46b3d45bc9ba81f906e9ff8521e5d654379f304ea9e90d103c9` |
| Family label | `Mirai` |
| File name | `disssh4` |
| File type | `elf` |
| First seen | `2026-10-16 23:49:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c920267509f9ff91301845dab7b290cf` |
| SHA-1 | `afc20cea22c5c5bf819567eed9b1f1e4b42729ed` |
| SHA-256 | `e39ad7aefcd3c46b3d45bc9ba81f906e9ff8521e5d654379f304ea9e90d103c9` |
| SHA3-384 | `68392078cf42dbb2a8dac4b529077eb9a63218259e36b35a9897e47e8d441d3dcaa1b5087528df7d2f0c0561cbda152c` |
| TLSH | `T120048CB2CC65BED8D224D0F4F5F18E792B139AA145471FBE6566C6B84083D8CF6063B8` |
| SSDEEP | `3072:OC9s/mRXc/73Bq6hENuzbkmRKxJRMeoBKUg6gC7bWMuoQjqUzj5EbX:OC9s/mRqHaGbxRGRMeRnEKMdQjljibX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_e39ad7ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e39ad7aefcd3c46b3d45bc9ba81f906e9ff8521e5d654379f304ea9e90d103c9"
    family = "Mirai"
    file_name = "disssh4"
    file_type = "elf"
    first_seen = "2026-10-16 23:49:13"
  condition:
    hash.sha256(0, filesize) == "e39ad7aefcd3c46b3d45bc9ba81f906e9ff8521e5d654379f304ea9e90d103c9"
}
```

### Sample 83: `6d2de1fb1a561c2e`

| Field | Value |
|---|---|
| SHA-256 | `6d2de1fb1a561c2e19e4a91894cb6bee1bc045ecff9d20eaf48488500bf577d8` |
| Family label | `unknown` |
| File name | `hb_arm` |
| File type | `elf` |
| First seen | `2026-10-16 23:47:17` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `587d5c56ca5860267e4999e90b17d2e6` |
| SHA-1 | `085da2c6ca01faedce9207871c3a6d8cdf5b1e50` |
| SHA-256 | `6d2de1fb1a561c2e19e4a91894cb6bee1bc045ecff9d20eaf48488500bf577d8` |
| SHA3-384 | `edbd779f80c4a5a58e4fd2c55703414ae6ae5467d07b55fc85305f897920343d28c8cec90e7577900fb39f190a6d2c93` |
| TLSH | `T147242363D682D447B38A038B087D5EB6529392C5157DB04E9CBFEB672C871E6AA30D70` |
| SSDEEP | `6144:qTZ4j+eIl8ByxaObxznu1+1LheXorOhSmx8LCPi:UZ4Kb8ByEObxzu1QrDmxVi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_6d2de1fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d2de1fb1a561c2e19e4a91894cb6bee1bc045ecff9d20eaf48488500bf577d8"
    family = "unknown"
    file_name = "hb_arm"
    file_type = "elf"
    first_seen = "2026-10-16 23:47:17"
  condition:
    hash.sha256(0, filesize) == "6d2de1fb1a561c2e19e4a91894cb6bee1bc045ecff9d20eaf48488500bf577d8"
}
```

### Sample 84: `81d1ed7640838826`

| Field | Value |
|---|---|
| SHA-256 | `81d1ed7640838826c40418b5680f1ed5942b73dbccc81b3c37895bafecc39d0a` |
| Family label | `Mirai` |
| File name | `dissmips` |
| File type | `elf` |
| First seen | `2026-10-16 23:43:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af8089a291b29e748f391f62a2d66390` |
| SHA-1 | `b0ad0714f03680b6143bb081f289a53d1d79c404` |
| SHA-256 | `81d1ed7640838826c40418b5680f1ed5942b73dbccc81b3c37895bafecc39d0a` |
| SHA3-384 | `8687cfcefea569c21975f9337f31ff7c9937862165824b760535b910bfb1f5cc47fb7452f73ed6f98a450ada6842208a` |
| TLSH | `T11544A45E6E328F7DF278873447B74B30A76923D623E1D684E1ACD1141E2035E685FBA8` |
| TELFHASH | `t12951c11c0d7813f0a2295c4d45ddff26d6a331db7e266c278e10e85aab29b839e21c0c` |
| SSDEEP | `6144:6d7Hgj3TgsgL9m8hLB591djGpg4w5/7GtYHF6RzospSsC:h7TDgQULB9dj/KfSh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_81d1ed76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81d1ed7640838826c40418b5680f1ed5942b73dbccc81b3c37895bafecc39d0a"
    family = "Mirai"
    file_name = "dissmips"
    file_type = "elf"
    first_seen = "2026-10-16 23:43:16"
  condition:
    hash.sha256(0, filesize) == "81d1ed7640838826c40418b5680f1ed5942b73dbccc81b3c37895bafecc39d0a"
}
```

### Sample 85: `ce1eb64fc04650f2`

| Field | Value |
|---|---|
| SHA-256 | `ce1eb64fc04650f2e124bbae21a41cbaaf6e583c5b8783e2519fada7f6e8e957` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 23:29:13` |
| Reporter | `Bitsight` |
| Tags | `BB4.file, dropped-by-GCleaner, exe, F` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e7226b66846f399e30f1dd94a004353` |
| SHA-1 | `b9a9fea976845f844adc99e956397ff1db6ad844` |
| SHA-256 | `ce1eb64fc04650f2e124bbae21a41cbaaf6e583c5b8783e2519fada7f6e8e957` |
| SHA3-384 | `5205852b2935f39af708e1536537d9c9b296ef79b2bb30729568acc215556bb98fb62459dbabd8e8bb0af4a409c4441c` |
| IMPHASH | `8fd8a85adcf38e28b1db634b7f4ebec9` |
| TLSH | `T187B56B829BC067BBFFD2CFBC962890DFEA127AD8875095165264CA50533ADF32CDD118` |
| SSDEEP | `49152:690qim+vGIljuWDQ10LYKXWkITdgJ1TDeDOP:Sqm+/ljNDO0LhkYa0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_ce1eb64f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce1eb64fc04650f2e124bbae21a41cbaaf6e583c5b8783e2519fada7f6e8e957"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 23:29:13"
  condition:
    hash.sha256(0, filesize) == "ce1eb64fc04650f2e124bbae21a41cbaaf6e583c5b8783e2519fada7f6e8e957"
}
```

### Sample 86: `1502ca97953e7168`

| Field | Value |
|---|---|
| SHA-256 | `1502ca97953e7168f856d6ac9e5940b4f65f55ed52d91ed14fa3946b713ee12f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 23:28:56` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX8.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a73a181588192eb21b36cbe0b29d330` |
| SHA-1 | `e9367a1365aff2ef6ee71f3aeaf56a6f27e3cdc5` |
| SHA-256 | `1502ca97953e7168f856d6ac9e5940b4f65f55ed52d91ed14fa3946b713ee12f` |
| SHA3-384 | `98142449ea50045ca6aa5bd71fd88f400d6f1c7ad7de2280199ef768f08d63c44da05488af7b8f2fdbb44f336f303909` |
| IMPHASH | `006018265ff2d2da862461a4170c43d1` |
| TLSH | `T17DE52390FAC31AF6C056E3B0855273BEF12A3B959FA39D077ACD36102F236195A39345` |
| SSDEEP | `49152:IICWN7xbVDmH3PVo0yeryROz9jawhykNqLUtORnJMHt2kCj2KYpY2NsYUIJiwMFj:5PmNKM8gqLUYRjkE2BBUIM19b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_1502ca97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1502ca97953e7168f856d6ac9e5940b4f65f55ed52d91ed14fa3946b713ee12f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 23:28:56"
  condition:
    hash.sha256(0, filesize) == "1502ca97953e7168f856d6ac9e5940b4f65f55ed52d91ed14fa3946b713ee12f"
}
```

### Sample 87: `e1c4d064c1353ba7`

| Field | Value |
|---|---|
| SHA-256 | `e1c4d064c1353ba75771662a61b7b529d4a206aa3cce1d5ca6529c53ab8b0946` |
| Family label | `GhostPulse` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 23:24:30` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, GhostPulse, PMIX0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7ca207e0b068efc1215dee80ae617b7` |
| SHA-1 | `cd005eeb916dddb3d30966c5bbb71caabd403464` |
| SHA-256 | `e1c4d064c1353ba75771662a61b7b529d4a206aa3cce1d5ca6529c53ab8b0946` |
| SHA3-384 | `90e8a57ef117ea7366fc40df010fbf154b69928346d04b8542409a3c282a6a9199776533e4c0bff96304669c305b107f` |
| IMPHASH | `20dd26497880c05caed9305b3c8b9109` |
| TLSH | `T1DBE63353B2861977E4A67A3425B684001F6F38D420FA904D7C7BDA8E2A713EC9E757C2` |
| SSDEEP | `196608:heWycAZ8BZZAnqtJywo24vZhkfVsNMiF9RuNgEKTDEnexI0eNuwMXP7U02OelRo5:NGUZCwkKhENE+DKexI9BMTU02OelRa` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `GhostPulse` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GhostPulse_087_e1c4d064
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1c4d064c1353ba75771662a61b7b529d4a206aa3cce1d5ca6529c53ab8b0946"
    family = "GhostPulse"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 23:24:30"
  condition:
    hash.sha256(0, filesize) == "e1c4d064c1353ba75771662a61b7b529d4a206aa3cce1d5ca6529c53ab8b0946"
}
```

### Sample 88: `6fab0497af603366`

| Field | Value |
|---|---|
| SHA-256 | `6fab0497af6033669821a65fc491f172e2b830c73a1b15994b7b68f57364fc27` |
| Family label | `Mirai` |
| File name | `dissarch64` |
| File type | `elf` |
| First seen | `2026-10-16 23:07:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b12b18b455aa4dbc570e9e3dd205afe4` |
| SHA-1 | `e05a799fc34a648cfe6d31238cda1f63fd0f1331` |
| SHA-256 | `6fab0497af6033669821a65fc491f172e2b830c73a1b15994b7b68f57364fc27` |
| SHA3-384 | `ba41c949e23d04ed674cc6ea39c778b5528d666562af901caafbcf04b12c764c359dd51703568759d63bed1b7de701c2` |
| TLSH | `T162E49D987B8D7D43D387F33DDE8ACA71322BB5E99352D2A23901525CD4C6EA9CBB0501` |
| SSDEEP | `12288:wpsx3F14ufIcz685VDZM9fkbEek4FtJ7xk44dUzip1qLdes53Tqui:wQDfIczbM9fkbEekiPxP451+jF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_6fab0497
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fab0497af6033669821a65fc491f172e2b830c73a1b15994b7b68f57364fc27"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-16 23:07:11"
  condition:
    hash.sha256(0, filesize) == "6fab0497af6033669821a65fc491f172e2b830c73a1b15994b7b68f57364fc27"
}
```

### Sample 89: `1f01ff480f1e0efd`

| Field | Value |
|---|---|
| SHA-256 | `1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31` |
| Family label | `ConnectWise` |
| File name | `1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31.msi` |
| File type | `msi` |
| First seen | `2026-10-16 23:06:09` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `042a0634bc50b45310d240d0b393c6c0` |
| SHA-1 | `58af783c595205edc53ed6bb97aacac6dc8451ac` |
| SHA-256 | `1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31` |
| SHA3-384 | `fc43199f17d77a87adbf3ee863ae5b67100134b3132d3011ed28ee311476a42df933217a36176f52e49c81417332d722` |
| TLSH | `T1B4A623116BF8D278F1F12A39D876A0B1A53A7D119E23C12E2324791E2C75EC0CA63777` |
| SSDEEP | `196608:oHxcp9ym3nltDUJVRHxcp9ym3YHxcp9ym39Hxcp9ym3aHxcp9ym3:2GplpeGpmGpvGpoGp` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_089_1f01ff48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31"
    family = "ConnectWise"
    file_name = "1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31.msi"
    file_type = "msi"
    first_seen = "2026-10-16 23:06:09"
  condition:
    hash.sha256(0, filesize) == "1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31"
}
```

### Sample 90: `bd809482df80b166`

| Field | Value |
|---|---|
| SHA-256 | `bd809482df80b166a2bb067629569be412561ebb88dcb6777e0c540bb309c878` |
| Family label | `Mirai` |
| File name | `bd809482df80b166a2bb067629569be412561ebb88dcb6777e0c540bb309c878.elf` |
| File type | `elf` |
| First seen | `2026-10-16 22:51:13` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1faf6f9293ee343684635deeee8576d3` |
| SHA-1 | `4db67a39ad5640457e85a8447edc4a8b632979ac` |
| SHA-256 | `bd809482df80b166a2bb067629569be412561ebb88dcb6777e0c540bb309c878` |
| SHA3-384 | `75c1384603d64ee50db10e99d7b14fdad7b75f19900ede342b60435d8889916111372373d4f641297eb6522eb4f51901` |
| TLSH | `T13ED3C70F7E229F6DF36882344BB78B35A35523D523F0C685D2ACDA105E6029D586FFA4` |
| TELFHASH | `t103114918893813f087b11d9d6becfe72e0a170eb4a255e378e50f9a99a6dd019e00c2c` |
| SSDEEP | `1536:05i5nvf1etYIDykAiyiiydVy813EfdUw4++Ri+HZ1LTTP+d1ArfmWeHU5/DidP:0Ydf1+B2kN3qdUpi+HZdTP+d1ADXDyP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_bd809482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd809482df80b166a2bb067629569be412561ebb88dcb6777e0c540bb309c878"
    family = "Mirai"
    file_name = "bd809482df80b166a2bb067629569be412561ebb88dcb6777e0c540bb309c878.elf"
    file_type = "elf"
    first_seen = "2026-10-16 22:51:13"
  condition:
    hash.sha256(0, filesize) == "bd809482df80b166a2bb067629569be412561ebb88dcb6777e0c540bb309c878"
}
```

### Sample 91: `448eefd781b3b6ec`

| Field | Value |
|---|---|
| SHA-256 | `448eefd781b3b6ecee0658169cf957924c985e578af5d94745f1c7460044c637` |
| Family label | `Mirai` |
| File name | `448eefd781b3b6ecee0658169cf957924c985e578af5d94745f1c7460044c637.elf` |
| File type | `elf` |
| First seen | `2026-10-16 22:51:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0f702413fa36aa091582f42d4f3b462` |
| SHA-1 | `463057bc08fc3af4dfafebd9f125ecb120e5bf16` |
| SHA-256 | `448eefd781b3b6ecee0658169cf957924c985e578af5d94745f1c7460044c637` |
| SHA3-384 | `72147e01e54672907daa1d2b33a934adb06bc6dca4bdd0ae4a5c0a6cab4386d86bcaabe5df6949227031a4fedd3a2d84` |
| TLSH | `T1D2A3AF12CD645DACF06A6D3020B98AFA4723B444981B2EFB3C4782655057EDCF19BBF8` |
| SSDEEP | `1536:ypVuUZ5Yu6zM+oFZkIM5Qi/k8ktiSUdryuAKKZ1zo7aeW5CdJdotAzfC:ypVuUZ5YfBoFZkhQQ4TVHZq1W5CUKa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_448eefd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "448eefd781b3b6ecee0658169cf957924c985e578af5d94745f1c7460044c637"
    family = "Mirai"
    file_name = "448eefd781b3b6ecee0658169cf957924c985e578af5d94745f1c7460044c637.elf"
    file_type = "elf"
    first_seen = "2026-10-16 22:51:08"
  condition:
    hash.sha256(0, filesize) == "448eefd781b3b6ecee0658169cf957924c985e578af5d94745f1c7460044c637"
}
```

### Sample 92: `9d2519c26fc99039`

| Field | Value |
|---|---|
| SHA-256 | `9d2519c26fc99039bf0d22af806baac93048dedbd557a275cb19478e886d63ff` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 22:23:35` |
| Reporter | `Bitsight` |
| Tags | `B, BB1.file, dropped-by-GCleaner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd61a8dc87785e2b3db3dc1de6dd242b` |
| SHA-1 | `534daae72fb241235ddc92bf93ddb428c0267a92` |
| SHA-256 | `9d2519c26fc99039bf0d22af806baac93048dedbd557a275cb19478e886d63ff` |
| SHA3-384 | `0c4f816fb31d1a7a4c68111ce7d679059f251f9371fbcb385a202c73d100e1c3158901e86f2c3829c0af69a23b21bb1c` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1F4E6335A5E9051F6C32FF97549833B2ED73BB8381BA39F4F8365AC640B33154992A312` |
| SSDEEP | `393216:8sO3MbKyDDYw4TFnEv4H4Fv2ROZVz2oWnK6pi:8/3qK+4ux/z2oWNi` |
| ICON-DHASH | `8270e88e61d8a400` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_9d2519c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d2519c26fc99039bf0d22af806baac93048dedbd557a275cb19478e886d63ff"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 22:23:35"
  condition:
    hash.sha256(0, filesize) == "9d2519c26fc99039bf0d22af806baac93048dedbd557a275cb19478e886d63ff"
}
```

### Sample 93: `ee735503a6d76a9e`

| Field | Value |
|---|---|
| SHA-256 | `ee735503a6d76a9eb6a0b7b511eb430aed0e8325c4ebdece5ea4c8c61e551c95` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 22:19:12` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `852996e10e45f7d5ef919155ecd1ae4a` |
| SHA-1 | `21e4f8c36e0060c2299dd1bf4e08db38917f34fd` |
| SHA-256 | `ee735503a6d76a9eb6a0b7b511eb430aed0e8325c4ebdece5ea4c8c61e551c95` |
| SHA3-384 | `02572a036ff1913fe77b9558c7cbf4d9e1545b35a873a1dddb7512b0edea1fb63b0ae4465431fe34cecf38129c64dae0` |
| IMPHASH | `56604ebebfc295d1dd249cf3afd9062c` |
| TLSH | `T16D456CD7F7254C34F2A92EF864C08521EB5DB58355EC54BB943CA08FA9BADD489F0838` |
| SSDEEP | `12288:at6NIB5xMOQk1J/gwD96BGhUd1E6pLhDWXCayZqM7Cuyh3jO5ekE8nVy3BsVgUTx:a8S7GOEi8BKMLLBL7CJ3jO5dVoSV/5T` |
| ICON-DHASH | `0010716969711000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_ee735503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee735503a6d76a9eb6a0b7b511eb430aed0e8325c4ebdece5ea4c8c61e551c95"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 22:19:12"
  condition:
    hash.sha256(0, filesize) == "ee735503a6d76a9eb6a0b7b511eb430aed0e8325c4ebdece5ea4c8c61e551c95"
}
```

### Sample 94: `9896ae4692789332`

| Field | Value |
|---|---|
| SHA-256 | `9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129` |
| Family label | `Mirai` |
| File name | `9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129.elf` |
| File type | `elf` |
| First seen | `2026-10-16 22:16:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3b157394576c6ba4f20d80ebb5b6f0f` |
| SHA-1 | `c97016e5bd722efdea668913a0ed7da252f5a14f` |
| SHA-256 | `9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129` |
| SHA3-384 | `1bd3be445ecf0a528030af9136d84f9b8e50a9f773bfc6e55f8a0a09c7bdf041d99e0f3984cd63efd7368b5190b3d29d` |
| TLSH | `T18CB35B41B35A4407F2E74DB12D3F6BF197DED1A121A0A6C5691EDB0F8232A321686FCD` |
| SSDEEP | `1536:enkpB6Fd0pJNqnTkrLYIHiv2c3cKD9XgUCVXGyPoa3Abq/YySpMQj37rzJK1Lhq:akmy4n3cGQ7twphjzEq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_9896ae46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129"
    family = "Mirai"
    file_name = "9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129.elf"
    file_type = "elf"
    first_seen = "2026-10-16 22:16:08"
  condition:
    hash.sha256(0, filesize) == "9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129"
}
```

### Sample 95: `1442f715afabfbbb`

| Field | Value |
|---|---|
| SHA-256 | `1442f715afabfbbb9c1ab2699832bd4f24c06b776ce0a04ccb5beedb067ffc20` |
| Family label | `Mirai` |
| File name | `8` |
| File type | `elf` |
| First seen | `2026-10-16 22:07:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94b28b22cbe6b9a7b3ced5dc4f401e20` |
| SHA-1 | `1b95f64965059e5d4359c47728d6764fcdc88348` |
| SHA-256 | `1442f715afabfbbb9c1ab2699832bd4f24c06b776ce0a04ccb5beedb067ffc20` |
| SHA3-384 | `5f4cc13e1f731cbd36f3088ae4d2fb4cc5c53eb8b9ea524536efbcbdc381211a6946149536f6d0d0c70afb72c5cccdf1` |
| TLSH | `T132F4D073E2305DD6C01A0BB424FDE3348F09B69213977594F7FAC284185B5A6FEA97A0` |
| SSDEEP | `12288:QEv7u3hZiuCbiUGids8ZtmFryXcGamADAgWs2aUTuNLT6+0ukppxaQpZRHAdcaTh:QMsiT/3ZLsqFgEiEj//i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_1442f715
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1442f715afabfbbb9c1ab2699832bd4f24c06b776ce0a04ccb5beedb067ffc20"
    family = "Mirai"
    file_name = "8"
    file_type = "elf"
    first_seen = "2026-10-16 22:07:15"
  condition:
    hash.sha256(0, filesize) == "1442f715afabfbbb9c1ab2699832bd4f24c06b776ce0a04ccb5beedb067ffc20"
}
```

### Sample 96: `e050ddccbdac97df`

| Field | Value |
|---|---|
| SHA-256 | `e050ddccbdac97dfc8eb41760a76b1ae7f0c9e22a44034304462ea20c3ed51f5` |
| Family label | `ConnectWise` |
| File name | `ZoomInstallerFull.js` |
| File type | `js` |
| First seen | `2026-10-16 22:05:42` |
| Reporter | `smica83` |
| Tags | `ConnectWise, HUN, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `110bc2f64340792da19a3b27aa2c649d` |
| SHA-1 | `ab837e6e1338780706bd3d8b295ca7ad85f66243` |
| SHA-256 | `e050ddccbdac97dfc8eb41760a76b1ae7f0c9e22a44034304462ea20c3ed51f5` |
| SHA3-384 | `5b9355cd7bcd210ba9151906af911f7994c9c7a8ff472bc9281b2e3a85837df7c9c755b00ba73e0a966ab49cbdd7e845` |
| TLSH | `T1AF527288499B52E9A0B3A32797366D21FE9B33573700820BF57CB543DFF930016569BA` |
| SSDEEP | `192:IC4jYg+s4Rc5g1jSpj0IewRtlIT9sv3rkmqdUGdAXsNfwUvAxWGSlZe4:IC4Je91jSRlBRA5CbV6A8NfMhSr` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_096_e050ddcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e050ddccbdac97dfc8eb41760a76b1ae7f0c9e22a44034304462ea20c3ed51f5"
    family = "ConnectWise"
    file_name = "ZoomInstallerFull.js"
    file_type = "js"
    first_seen = "2026-10-16 22:05:42"
  condition:
    hash.sha256(0, filesize) == "e050ddccbdac97dfc8eb41760a76b1ae7f0c9e22a44034304462ea20c3ed51f5"
}
```

### Sample 97: `c9f7fada2b226ef9`

| Field | Value |
|---|---|
| SHA-256 | `c9f7fada2b226ef942e7ffd5eb5a63c8ac741b53dd3328cd6c907cea135849e0` |
| Family label | `Mirai` |
| File name | `mbupload-1bgovsky.bin` |
| File type | `elf` |
| First seen | `2026-10-16 22:02:28` |
| Reporter | `wristhulk` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9eb82b0572205b69af0ceefb1d4ee03b` |
| SHA-1 | `5c1e3595402f4e336642012fbba1cfcd7535b642` |
| SHA-256 | `c9f7fada2b226ef942e7ffd5eb5a63c8ac741b53dd3328cd6c907cea135849e0` |
| SHA3-384 | `3b811e0e251707411985b8b74dffd07f326e22a3e1a9f0ef195e31a14a11836f15d4e41df4f59240ecebcf078a781483` |
| TLSH | `T1EF217252E0C46D68DF28D73C4E715A103B02D9A8C94FE3DE4E0C56BA292F28C76540D4` |
| SSDEEP | `24:wa3dGtSnUpzzbBWpzmIIyKYB5gDrm3EvC/dikC7m17hhVNfq:wa3dxnUpzzbBWpzmIIy+Drm3EvC/s77d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_c9f7fada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9f7fada2b226ef942e7ffd5eb5a63c8ac741b53dd3328cd6c907cea135849e0"
    family = "Mirai"
    file_name = "mbupload-1bgovsky.bin"
    file_type = "elf"
    first_seen = "2026-10-16 22:02:28"
  condition:
    hash.sha256(0, filesize) == "c9f7fada2b226ef942e7ffd5eb5a63c8ac741b53dd3328cd6c907cea135849e0"
}
```

### Sample 98: `8182fdf5fffca2a3`

| Field | Value |
|---|---|
| SHA-256 | `8182fdf5fffca2a35ea0c59210fe6e47c6eb670a794bad8f10e0c33d9896741c` |
| Family label | `Mirai` |
| File name | `mbupload-5xvyfmsk.bin` |
| File type | `elf` |
| First seen | `2026-10-16 22:01:23` |
| Reporter | `wristhulk` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b690424fd0e79a86067ac6b68744eea2` |
| SHA-1 | `866c58994e9468945ff86fb4f22bca2c8560f1d7` |
| SHA-256 | `8182fdf5fffca2a35ea0c59210fe6e47c6eb670a794bad8f10e0c33d9896741c` |
| SHA3-384 | `bac3246c85b62b20154d9398977ea0737ea59c1ae1add1c681d2079f087461c717fc0d08d850a9e194cc5ef94d2fa4ff` |
| TLSH | `T18BB32A86BC81C612C5E161B6FB1F91CD372743B8E3E67247DD18AB29674B8670E3B241` |
| TELFHASH | `t145314016cb940fcc73f4076d92da9317956934fe1b1110269ebdbb9f9a138e33026134` |
| SSDEEP | `1536:bGr3SNsynnMWA+GpqxZCcVEqcrn9TO5kGPPYWU6s7Z/d3vEN:bGmNlnMWUs3cD9O5kGP+T/o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_8182fdf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8182fdf5fffca2a35ea0c59210fe6e47c6eb670a794bad8f10e0c33d9896741c"
    family = "Mirai"
    file_name = "mbupload-5xvyfmsk.bin"
    file_type = "elf"
    first_seen = "2026-10-16 22:01:23"
  condition:
    hash.sha256(0, filesize) == "8182fdf5fffca2a35ea0c59210fe6e47c6eb670a794bad8f10e0c33d9896741c"
}
```

### Sample 99: `ee39f091a23c7467`

| Field | Value |
|---|---|
| SHA-256 | `ee39f091a23c746763ff44a273d11307abe5ca531f363b5621dfaa695f39a37b` |
| Family label | `unknown` |
| File name | `건강검진.zip` |
| File type | `zip` |
| First seen | `2026-10-16 22:00:48` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7bf14df8aef9f0d21f2c30759f82dab5` |
| SHA-1 | `349022ab858a125368e342204d136c1107c72aeb` |
| SHA-256 | `ee39f091a23c746763ff44a273d11307abe5ca531f363b5621dfaa695f39a37b` |
| SHA3-384 | `577df6d0f58c9bae35177e47533c74cc9127656ab309df041993857c5eb70f2c319c7934b94975555936db154ae96e4a` |
| TLSH | `T18341CA0DF40DE025D29C17FD820FE857D601C41DF506B0B59E1DD1F99BA88634988D09` |
| SSDEEP | `48:9T03A6Z+GelqA5COYH5bq7+NTUzUCS7NzEVOVbFbIq+:TjlqA5COYHRM+l8TeNzu2FZ+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_ee39f091
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee39f091a23c746763ff44a273d11307abe5ca531f363b5621dfaa695f39a37b"
    family = "unknown"
    file_name = "건강검진.zip"
    file_type = "zip"
    first_seen = "2026-10-16 22:00:48"
  condition:
    hash.sha256(0, filesize) == "ee39f091a23c746763ff44a273d11307abe5ca531f363b5621dfaa695f39a37b"
}
```

### Sample 100: `bc3ba9feddc78c12`

| Field | Value |
|---|---|
| SHA-256 | `bc3ba9feddc78c129369cfb771ec653a8cdc8da555117e4036fa39f20c01c78f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-16 22:00:38` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94c6a7baff23576a1a9b425fbd077abc` |
| SHA-1 | `22109434fbff328fe408d6022984f57cd34cd081` |
| SHA-256 | `bc3ba9feddc78c129369cfb771ec653a8cdc8da555117e4036fa39f20c01c78f` |
| SHA3-384 | `2dc9ebec34d23a92653422d69dd7f4d7bb618863bd4cc573c1e56df00a069b755b89b03ee5c29d4a5a789de3e1d5e1fb` |
| IMPHASH | `53d5c0deb073886f309ff587b7fd642e` |
| TLSH | `T15B96339E5031B670C0A11FFB270910C4B0EE0FA2D99CD15A5BF962528FC9A876D47BCE` |
| SSDEEP | `196608:UtlduLKv5aFklrWgDcfAEyAUw2H+XF6M31kUMTHuta:kl03LgQ4EyAUwnEo1kvJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_bc3ba9fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc3ba9feddc78c129369cfb771ec653a8cdc8da555117e4036fa39f20c01c78f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 22:00:38"
  condition:
    hash.sha256(0, filesize) == "bc3ba9feddc78c129369cfb771ec653a8cdc8da555117e4036fa39f20c01c78f"
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
 * Generated: 2026-10-17T04:38:34.979873+00:00
 */

rule MalwareBazaar_Adware_Generic_001_7ad81cd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ad81cd5580035c6e048d12a76a82b85b0f3278cedf9f55c6fceab171820cfd2"
    family = "Adware.Generic"
    file_name = "7ad81cd5580035c6e048d12a76a82b85b0f3278cedf9f55c6fceab171820cfd2.exe"
    file_type = "exe"
    first_seen = "2026-10-17 04:26:11"
  condition:
    hash.sha256(0, filesize) == "7ad81cd5580035c6e048d12a76a82b85b0f3278cedf9f55c6fceab171820cfd2"
}

rule MalwareBazaar_Mirai_002_e0a7753a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0a7753a0bcd11621a102e4d0cf5e7a1b1fb7eb3dd2996ad765f00fb288b90a2"
    family = "Mirai"
    file_name = "e0a7753a0bcd1162.bin"
    file_type = "elf"
    first_seen = "2026-10-17 04:25:50"
  condition:
    hash.sha256(0, filesize) == "e0a7753a0bcd11621a102e4d0cf5e7a1b1fb7eb3dd2996ad765f00fb288b90a2"
}

rule MalwareBazaar_unknown_003_a3e4d8b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3e4d8b0ba72c13852d1d7a33a15993755c4b01529c3cf344d376774fa24a8b5"
    family = "unknown"
    file_name = "a3e4d8b0ba72c138.bin"
    file_type = "dll"
    first_seen = "2026-10-17 04:25:41"
  condition:
    hash.sha256(0, filesize) == "a3e4d8b0ba72c13852d1d7a33a15993755c4b01529c3cf344d376774fa24a8b5"
}

rule MalwareBazaar_unknown_004_e14647c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e14647c08925cce2d51fc520ffe34d3c4ff41015ddaeea274836c1832d6b8ef8"
    family = "unknown"
    file_name = "e14647c08925cce2.bin"
    file_type = "dll"
    first_seen = "2026-10-17 04:25:32"
  condition:
    hash.sha256(0, filesize) == "e14647c08925cce2d51fc520ffe34d3c4ff41015ddaeea274836c1832d6b8ef8"
}

rule MalwareBazaar_unknown_005_67937238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "679372386b687d4aa79d13af9e2929cdfd1ab1e388eaeac1a31c81f08ad84c37"
    family = "unknown"
    file_name = "warden_a1c9f2ad_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:34:30"
  condition:
    hash.sha256(0, filesize) == "679372386b687d4aa79d13af9e2929cdfd1ab1e388eaeac1a31c81f08ad84c37"
}

rule MalwareBazaar_unknown_006_2b4bb4ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b4bb4ab724ee6f0741b9366fb6e8ceda68d4cbbd4bb2aed74a7c21cd28c63cb"
    family = "unknown"
    file_name = "warden_6546bdb2_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:34:22"
  condition:
    hash.sha256(0, filesize) == "2b4bb4ab724ee6f0741b9366fb6e8ceda68d4cbbd4bb2aed74a7c21cd28c63cb"
}

rule MalwareBazaar_unknown_007_bd90b742
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd90b742908dec4cd7a1ab54cc6b3e7e36498ee112fd788c1679471eccc59a95"
    family = "unknown"
    file_name = "warden_49902b86_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:34:14"
  condition:
    hash.sha256(0, filesize) == "bd90b742908dec4cd7a1ab54cc6b3e7e36498ee112fd788c1679471eccc59a95"
}

rule MalwareBazaar_unknown_008_3f497026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f497026432633757122a8b5a6565b6aef2e1286af56e09d3374aa24c3b525bc"
    family = "unknown"
    file_name = "warden_0c489965_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:34:06"
  condition:
    hash.sha256(0, filesize) == "3f497026432633757122a8b5a6565b6aef2e1286af56e09d3374aa24c3b525bc"
}

rule MalwareBazaar_unknown_009_4d4fbdc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d4fbdc2366d9c4488d02a12aadc4596b05f3e0b8f855e679bfc425aae3aa72f"
    family = "unknown"
    file_name = "warden_3874acb3_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:33:59"
  condition:
    hash.sha256(0, filesize) == "4d4fbdc2366d9c4488d02a12aadc4596b05f3e0b8f855e679bfc425aae3aa72f"
}

rule MalwareBazaar_unknown_010_7aa8a134
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7aa8a13432f1999f37809e8576ea7e442d57e1902e991d11dedbfbdfc156a3de"
    family = "unknown"
    file_name = "warden_a16051a1_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:33:49"
  condition:
    hash.sha256(0, filesize) == "7aa8a13432f1999f37809e8576ea7e442d57e1902e991d11dedbfbdfc156a3de"
}

rule MalwareBazaar_unknown_011_1c2f944a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c2f944aa593e4d55343ed4ec5074160ee8a85bfb5b551ee734e6f26b1a95bf4"
    family = "unknown"
    file_name = "warden_d5a8157b_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:33:41"
  condition:
    hash.sha256(0, filesize) == "1c2f944aa593e4d55343ed4ec5074160ee8a85bfb5b551ee734e6f26b1a95bf4"
}

rule MalwareBazaar_unknown_012_afb1126f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afb1126f9454e8b94376b43cd09200b971ff39ffcaed57c2f55e133e41c36e6d"
    family = "unknown"
    file_name = "warden_fc233953_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 03:33:32"
  condition:
    hash.sha256(0, filesize) == "afb1126f9454e8b94376b43cd09200b971ff39ffcaed57c2f55e133e41c36e6d"
}

rule MalwareBazaar_Vidar_013_e9af652d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78"
    family = "Vidar"
    file_name = "e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78.bin"
    file_type = "exe"
    first_seen = "2026-10-17 03:22:22"
  condition:
    hash.sha256(0, filesize) == "e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78"
}

rule MalwareBazaar_Vidar_014_37ddd1a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37ddd1a7b72fdb4986d966157ac085035b32d8cc3f84edef61808dec7158e12f"
    family = "Vidar"
    file_name = "37ddd1a7b72fdb4986d966157ac085035b32d8cc3f84edef61808dec7158e12f.bin"
    file_type = "exe"
    first_seen = "2026-10-17 03:22:18"
  condition:
    hash.sha256(0, filesize) == "37ddd1a7b72fdb4986d966157ac085035b32d8cc3f84edef61808dec7158e12f"
}

rule MalwareBazaar_unknown_015_d7234d92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c"
    family = "unknown"
    file_name = "d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c"
    file_type = "sh"
    first_seen = "2026-10-17 03:17:06"
  condition:
    hash.sha256(0, filesize) == "d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c"
}

rule MalwareBazaar_Mirai_016_ff8a872e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661"
    family = "Mirai"
    file_name = "ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661.elf"
    file_type = "elf"
    first_seen = "2026-10-17 03:16:13"
  condition:
    hash.sha256(0, filesize) == "ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661"
}

rule MalwareBazaar_Mirai_017_453505bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "453505bf331a5646152b88692dd2e3d9e40f61b2ac97945f78c76f05ad5a57a0"
    family = "Mirai"
    file_name = "mbupload-oa0493qn.bin"
    file_type = "elf"
    first_seen = "2026-10-17 02:58:26"
  condition:
    hash.sha256(0, filesize) == "453505bf331a5646152b88692dd2e3d9e40f61b2ac97945f78c76f05ad5a57a0"
}

rule MalwareBazaar_Mirai_018_b7ce973b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7ce973bae02b7dba67176c33da4664da3c3d6ecd11d22067549e63505e5c3bd"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-17 02:49:02"
  condition:
    hash.sha256(0, filesize) == "b7ce973bae02b7dba67176c33da4664da3c3d6ecd11d22067549e63505e5c3bd"
}

rule MalwareBazaar_unknown_019_276efc07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "276efc07b5ed6ab633028ec992c5b765a05770a5ff56506f86240569efbfbc93"
    family = "unknown"
    file_name = "hb_x86"
    file_type = "elf"
    first_seen = "2026-10-17 02:44:52"
  condition:
    hash.sha256(0, filesize) == "276efc07b5ed6ab633028ec992c5b765a05770a5ff56506f86240569efbfbc93"
}

rule MalwareBazaar_Mirai_020_eb3e86ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb3e86ee5977b3f92fadb23eb8cf7135a5371ea3f7e7b73c80cc4c06f3e30756"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-17 02:44:50"
  condition:
    hash.sha256(0, filesize) == "eb3e86ee5977b3f92fadb23eb8cf7135a5371ea3f7e7b73c80cc4c06f3e30756"
}

rule MalwareBazaar_Mirai_021_b7c56208
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7c562089fbc80dca34a8dd924e7436dde1428cccc5e2cb81f5e69b2da9f2922"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-17 02:43:17"
  condition:
    hash.sha256(0, filesize) == "b7c562089fbc80dca34a8dd924e7436dde1428cccc5e2cb81f5e69b2da9f2922"
}

rule MalwareBazaar_Mirai_022_a0f8eb2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0f8eb2b9458ffc5f5641d400c300f16b6ffe2e560906f0c6f9cbb04c38c031a"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-17 02:42:42"
  condition:
    hash.sha256(0, filesize) == "a0f8eb2b9458ffc5f5641d400c300f16b6ffe2e560906f0c6f9cbb04c38c031a"
}

rule MalwareBazaar_Mirai_023_602ea10b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "602ea10b62bc266484fe6c2de86c56c79747203e12fba6a824e66ba697d1be45"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-17 02:35:29"
  condition:
    hash.sha256(0, filesize) == "602ea10b62bc266484fe6c2de86c56c79747203e12fba6a824e66ba697d1be45"
}

rule MalwareBazaar_NanoCore_024_34255878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3425587876d45c0a1eaea90741b0f1a8e490af891ce848bfc5b685683a6d2533"
    family = "NanoCore"
    file_name = "5F281E55C1E07DABEB5E59D3A5194294.exe"
    file_type = "exe"
    first_seen = "2026-10-17 02:35:07"
  condition:
    hash.sha256(0, filesize) == "3425587876d45c0a1eaea90741b0f1a8e490af891ce848bfc5b685683a6d2533"
}

rule MalwareBazaar_Mirai_025_40ca1cc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ca1cc50908ba6247b4a12a20c30f9bc5f11b61ebd4fa45a61bbfcf725efb88"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-17 02:34:37"
  condition:
    hash.sha256(0, filesize) == "40ca1cc50908ba6247b4a12a20c30f9bc5f11b61ebd4fa45a61bbfcf725efb88"
}

rule MalwareBazaar_unknown_026_9fd7f2f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fd7f2f32f4bdeb718cc9e4f3f431ab0549efc4211492a975f82b46da90f1f08"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-17 02:29:23"
  condition:
    hash.sha256(0, filesize) == "9fd7f2f32f4bdeb718cc9e4f3f431ab0549efc4211492a975f82b46da90f1f08"
}

rule MalwareBazaar_Mirai_027_9bd0fcad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd0fcad7e6ca59c3caeed5b9fae6ecb499d274bfff2042a855f7b9f5b3b1657"
    family = "Mirai"
    file_name = "6"
    file_type = "elf"
    first_seen = "2026-10-17 02:28:33"
  condition:
    hash.sha256(0, filesize) == "9bd0fcad7e6ca59c3caeed5b9fae6ecb499d274bfff2042a855f7b9f5b3b1657"
}

rule MalwareBazaar_unknown_028_5c390a72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c390a72ec6f1a3e7978542c2146f9c0d785cc217f132a876181b9c7f3c8bdf9"
    family = "unknown"
    file_name = "cegg_x86"
    file_type = "elf"
    first_seen = "2026-10-17 02:26:31"
  condition:
    hash.sha256(0, filesize) == "5c390a72ec6f1a3e7978542c2146f9c0d785cc217f132a876181b9c7f3c8bdf9"
}

rule MalwareBazaar_Mirai_029_39196442
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39196442ee82d4353d938e6507287316b7ff92927fc599df618d45df9dd0b2dd"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-17 02:20:34"
  condition:
    hash.sha256(0, filesize) == "39196442ee82d4353d938e6507287316b7ff92927fc599df618d45df9dd0b2dd"
}

rule MalwareBazaar_unknown_030_400a6316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "400a6316ccd012a0cb468f44790f73e326db4acca66645c0c8c4ed0f7fc53da1"
    family = "unknown"
    file_name = "cegg_arm64"
    file_type = "elf"
    first_seen = "2026-10-17 02:18:37"
  condition:
    hash.sha256(0, filesize) == "400a6316ccd012a0cb468f44790f73e326db4acca66645c0c8c4ed0f7fc53da1"
}

rule MalwareBazaar_unknown_031_6dec9ce4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dec9ce44114bef5cec56e6f4f00d8a00692d140cb7f9de2735baffda39d2f69"
    family = "unknown"
    file_name = "cegg_mipsle"
    file_type = "elf"
    first_seen = "2026-10-17 02:14:29"
  condition:
    hash.sha256(0, filesize) == "6dec9ce44114bef5cec56e6f4f00d8a00692d140cb7f9de2735baffda39d2f69"
}

rule MalwareBazaar_Mirai_032_7a0649ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a0649ca3761da27ff399e4b01bf4bc11a3e170f529deba0a8c31468a90a2749"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-10-17 02:11:24"
  condition:
    hash.sha256(0, filesize) == "7a0649ca3761da27ff399e4b01bf4bc11a3e170f529deba0a8c31468a90a2749"
}

rule MalwareBazaar_Mirai_033_fdc632c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdc632c0698508a9afe744e6c29b200f9e2221958d7594d29843676fc6994232"
    family = "Mirai"
    file_name = "fdc632c0698508a9afe744e6c29b200f9e2221958d7594d29843676fc6994232.elf"
    file_type = "elf"
    first_seen = "2026-10-17 02:11:10"
  condition:
    hash.sha256(0, filesize) == "fdc632c0698508a9afe744e6c29b200f9e2221958d7594d29843676fc6994232"
}

rule MalwareBazaar_Mirai_034_a0db0b57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0db0b57eaa2b978651c7c3f4c3c63b382fcc66a03f2a8031f423c21ba97f378"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-10-17 02:10:28"
  condition:
    hash.sha256(0, filesize) == "a0db0b57eaa2b978651c7c3f4c3c63b382fcc66a03f2a8031f423c21ba97f378"
}

rule MalwareBazaar_unknown_035_b9841eb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9841eb5df6b9dcd76b1db4569dd5248345ed430119a1acca55a8d64f3c908c1"
    family = "unknown"
    file_name = "b9841eb5df6b9dcd76b1db4569dd5248345ed430119a1acca55a8d64f3c908c1"
    file_type = "sh"
    first_seen = "2026-10-17 01:52:40"
  condition:
    hash.sha256(0, filesize) == "b9841eb5df6b9dcd76b1db4569dd5248345ed430119a1acca55a8d64f3c908c1"
}

rule MalwareBazaar_AMOS_036_5861d36f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5861d36ffa3c3deea7ab3b6a1faf4ee0af5dde2ae9fe491bdbb6b34c4125b7bc"
    family = "AMOS"
    file_name = "macho_5861d36ffa3c.bin"
    file_type = "macho"
    first_seen = "2026-10-17 01:39:22"
  condition:
    hash.sha256(0, filesize) == "5861d36ffa3c3deea7ab3b6a1faf4ee0af5dde2ae9fe491bdbb6b34c4125b7bc"
}

rule MalwareBazaar_Mirai_037_fa60cde5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa60cde5a2831ea760f1ceda647caec7543592fd1c4cc8bcf383ffad62fec084"
    family = "Mirai"
    file_name = "adissarm5"
    file_type = "elf"
    first_seen = "2026-10-17 01:38:40"
  condition:
    hash.sha256(0, filesize) == "fa60cde5a2831ea760f1ceda647caec7543592fd1c4cc8bcf383ffad62fec084"
}

rule MalwareBazaar_unknown_038_07a49180
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07a491805b23d8ebf039f56c43107261a6d3a2014ae39ec513dfb4415220ca73"
    family = "unknown"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-10-17 01:36:24"
  condition:
    hash.sha256(0, filesize) == "07a491805b23d8ebf039f56c43107261a6d3a2014ae39ec513dfb4415220ca73"
}

rule MalwareBazaar_unknown_039_269b268a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "269b268ad54168172f307ae50896b64735e3164946f4abc91c2e8257b0fb6300"
    family = "unknown"
    file_name = "Qt5Widgets.dll"
    file_type = "exe"
    first_seen = "2026-10-17 01:35:19"
  condition:
    hash.sha256(0, filesize) == "269b268ad54168172f307ae50896b64735e3164946f4abc91c2e8257b0fb6300"
}

rule MalwareBazaar_unknown_040_8351041a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8351041a32a2c892ab9349120616870b5095d05752f4d3e355d8158c2bc02cbd"
    family = "unknown"
    file_name = "dvnx_e5b790c3_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 01:35:10"
  condition:
    hash.sha256(0, filesize) == "8351041a32a2c892ab9349120616870b5095d05752f4d3e355d8158c2bc02cbd"
}

rule MalwareBazaar_unknown_041_cefd5749
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cefd574917e8625d7e43d210ce4a473e068210f944d998335feac56d02a63f7e"
    family = "unknown"
    file_name = "dvnx_463f5610_unpacked.exe"
    file_type = "exe"
    first_seen = "2026-10-17 01:35:01"
  condition:
    hash.sha256(0, filesize) == "cefd574917e8625d7e43d210ce4a473e068210f944d998335feac56d02a63f7e"
}

rule MalwareBazaar_unknown_042_05d377c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05d377c8263e20008aca7bcd0f9b9187d2c70599fdfec334bb6bbfb03e52ebd4"
    family = "unknown"
    file_name = "warden_8360_fixed.exe"
    file_type = "exe"
    first_seen = "2026-10-17 01:34:53"
  condition:
    hash.sha256(0, filesize) == "05d377c8263e20008aca7bcd0f9b9187d2c70599fdfec334bb6bbfb03e52ebd4"
}

rule MalwareBazaar_Mirai_043_5757bb1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5757bb1fa8d85ec537730756ba96c57d32482b8813db22fc1152a6274619559e"
    family = "Mirai"
    file_name = "5"
    file_type = "elf"
    first_seen = "2026-10-17 01:28:34"
  condition:
    hash.sha256(0, filesize) == "5757bb1fa8d85ec537730756ba96c57d32482b8813db22fc1152a6274619559e"
}

rule MalwareBazaar_Mirai_044_126bffca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "126bffcade3468d8b84243ce192422077d23e802865b35a7c9e780fc99c02fed"
    family = "Mirai"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-17 01:24:31"
  condition:
    hash.sha256(0, filesize) == "126bffcade3468d8b84243ce192422077d23e802865b35a7c9e780fc99c02fed"
}

rule MalwareBazaar_Mirai_045_a1d2ffce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1d2ffce407ed2f042eaf0ffdadea3e3dca0d9831ca51d743e6bae9c8ff64036"
    family = "Mirai"
    file_name = "a1d2ffce407ed2f042eaf0ffdadea3e3dca0d9831ca51d743e6bae9c8ff64036"
    file_type = "elf"
    first_seen = "2026-10-17 01:22:02"
  condition:
    hash.sha256(0, filesize) == "a1d2ffce407ed2f042eaf0ffdadea3e3dca0d9831ca51d743e6bae9c8ff64036"
}

rule MalwareBazaar_Mirai_046_060b43e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "060b43e899cf21bee854bd3b7cab84024328c95961570f72c22b359bc327129e"
    family = "Mirai"
    file_name = "dissarm6"
    file_type = "elf"
    first_seen = "2026-10-17 01:16:35"
  condition:
    hash.sha256(0, filesize) == "060b43e899cf21bee854bd3b7cab84024328c95961570f72c22b359bc327129e"
}

rule MalwareBazaar_unknown_047_1e5da327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e5da327a36b6bbe46f7fba5ab2e64536f1b368a115cc5e5349a127191a4423e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-17 01:00:39"
  condition:
    hash.sha256(0, filesize) == "1e5da327a36b6bbe46f7fba5ab2e64536f1b368a115cc5e5349a127191a4423e"
}

rule MalwareBazaar_unknown_048_79dfb54e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79dfb54e439156550fc92509ad4c9b809e98d46cd5dfe48068569012ffb84290"
    family = "unknown"
    file_name = "cegg_x86_64"
    file_type = "elf"
    first_seen = "2026-10-17 00:44:35"
  condition:
    hash.sha256(0, filesize) == "79dfb54e439156550fc92509ad4c9b809e98d46cd5dfe48068569012ffb84290"
}

rule MalwareBazaar_unknown_049_e850c289
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e850c2892c9017cfd3c5cf371e18c0da2cf399571b923200655701dd5075fbdd"
    family = "unknown"
    file_name = "e850c2892c9017cfd3c5cf371e18c0da2cf399571b923200655701dd5075fbdd"
    file_type = "elf"
    first_seen = "2026-10-17 00:42:34"
  condition:
    hash.sha256(0, filesize) == "e850c2892c9017cfd3c5cf371e18c0da2cf399571b923200655701dd5075fbdd"
}

rule MalwareBazaar_unknown_050_ffba182b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffba182b6c188536938e85f1f61d86304224cee6fcb33d1fdc9928c0e01c9631"
    family = "unknown"
    file_name = "ffba182b6c188536938e85f1f61d86304224cee6fcb33d1fdc9928c0e01c9631"
    file_type = "elf"
    first_seen = "2026-10-17 00:41:40"
  condition:
    hash.sha256(0, filesize) == "ffba182b6c188536938e85f1f61d86304224cee6fcb33d1fdc9928c0e01c9631"
}

rule MalwareBazaar_unknown_051_4a558246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a5582464baaef23f15f2a03ef7aaa6d8e11f60e6fb091d377051b26c9d3dad4"
    family = "unknown"
    file_name = "4a5582464baaef23f15f2a03ef7aaa6d8e11f60e6fb091d377051b26c9d3dad4"
    file_type = "elf"
    first_seen = "2026-10-17 00:41:36"
  condition:
    hash.sha256(0, filesize) == "4a5582464baaef23f15f2a03ef7aaa6d8e11f60e6fb091d377051b26c9d3dad4"
}

rule MalwareBazaar_unknown_052_8cb15278
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cb15278aabcfc7fe1ef27c54b2a3264d29390e8f1a2cdb7857ab241eff911cb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-17 00:41:35"
  condition:
    hash.sha256(0, filesize) == "8cb15278aabcfc7fe1ef27c54b2a3264d29390e8f1a2cdb7857ab241eff911cb"
}

rule MalwareBazaar_Mirai_053_cc8692dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc8692dc9180b48c118438c6703d25861689822fffc9f067a3d8294e3a47afc2"
    family = "Mirai"
    file_name = "dissmpsl"
    file_type = "elf"
    first_seen = "2026-10-17 00:38:41"
  condition:
    hash.sha256(0, filesize) == "cc8692dc9180b48c118438c6703d25861689822fffc9f067a3d8294e3a47afc2"
}

rule MalwareBazaar_AMOS_054_322a9bda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d"
    family = "AMOS"
    file_name = "macho_322a9bdadc79.bin"
    file_type = "macho"
    first_seen = "2026-10-17 00:38:39"
  condition:
    hash.sha256(0, filesize) == "322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d"
}

rule MalwareBazaar_unknown_055_972345fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "972345fe982568daf6404e8b6099920f7eaf78fdc8a027525eac8989ebd222d0"
    family = "unknown"
    file_name = "972345fe982568daf6404e8b6099920f7eaf78fdc8a027525eac8989ebd222d0"
    file_type = "elf"
    first_seen = "2026-10-17 00:38:04"
  condition:
    hash.sha256(0, filesize) == "972345fe982568daf6404e8b6099920f7eaf78fdc8a027525eac8989ebd222d0"
}

rule MalwareBazaar_Mirai_056_7b79ca4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b79ca4b369cc7e95fd543727325e05eb19658b4b786ec758ba83072b01e7d52"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-17 00:36:41"
  condition:
    hash.sha256(0, filesize) == "7b79ca4b369cc7e95fd543727325e05eb19658b4b786ec758ba83072b01e7d52"
}

rule MalwareBazaar_AMOS_057_5b3c6ec6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b3c6ec6e558bf2e4dcff9b8f810fc5522cb9ab6271522c2ce8b0f140151ba8b"
    family = "AMOS"
    file_name = "macho_5b3c6ec6e558.bin"
    file_type = "macho"
    first_seen = "2026-10-17 00:36:09"
  condition:
    hash.sha256(0, filesize) == "5b3c6ec6e558bf2e4dcff9b8f810fc5522cb9ab6271522c2ce8b0f140151ba8b"
}

rule MalwareBazaar_AMOS_058_51ad0fe8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8"
    family = "AMOS"
    file_name = "macho_51ad0fe8782d.bin"
    file_type = "macho"
    first_seen = "2026-10-17 00:32:55"
  condition:
    hash.sha256(0, filesize) == "51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8"
}

rule MalwareBazaar_Mirai_059_285037bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "285037bfb99b2dbf6376998f11f31623965af6ff7128c811c67619b3838014fe"
    family = "Mirai"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-17 00:32:44"
  condition:
    hash.sha256(0, filesize) == "285037bfb99b2dbf6376998f11f31623965af6ff7128c811c67619b3838014fe"
}

rule MalwareBazaar_Mirai_060_13135f3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13135f3ecb191728666b54ca56844f5c35e7d60ac056a8398bfcbd22e6d6f729"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-17 00:30:51"
  condition:
    hash.sha256(0, filesize) == "13135f3ecb191728666b54ca56844f5c35e7d60ac056a8398bfcbd22e6d6f729"
}

rule MalwareBazaar_AMOS_061_ecf0f6b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d"
    family = "AMOS"
    file_name = "macho_ecf0f6b18163.bin"
    file_type = "macho"
    first_seen = "2026-10-17 00:29:29"
  condition:
    hash.sha256(0, filesize) == "ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d"
}

rule MalwareBazaar_Mirai_062_a19c0b92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a19c0b926b6fdc64733bf7fb34685df27427fe01b8241ae1b1ff966004db1d35"
    family = "Mirai"
    file_name = "bot"
    file_type = "elf"
    first_seen = "2026-10-17 00:28:32"
  condition:
    hash.sha256(0, filesize) == "a19c0b926b6fdc64733bf7fb34685df27427fe01b8241ae1b1ff966004db1d35"
}

rule MalwareBazaar_unknown_063_9dd946dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dd946dcf324d6a0b54eec727d463103b18fe4013986b840867ac1053b4ff507"
    family = "unknown"
    file_name = "cegg_mips"
    file_type = "elf"
    first_seen = "2026-10-17 00:28:30"
  condition:
    hash.sha256(0, filesize) == "9dd946dcf324d6a0b54eec727d463103b18fe4013986b840867ac1053b4ff507"
}

rule MalwareBazaar_AMOS_064_3bf9ac9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3"
    family = "AMOS"
    file_name = "macho_3bf9ac9cb26e.bin"
    file_type = "macho"
    first_seen = "2026-10-17 00:26:55"
  condition:
    hash.sha256(0, filesize) == "3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3"
}

rule MalwareBazaar_Vidar_065_fbeacf6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbeacf6c0412e4a610b4dcde1d6156c18dccf100003799ccc0703069e0419786"
    family = "Vidar"
    file_name = "975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2.exe"
    file_type = "exe"
    first_seen = "2026-10-17 00:26:24"
  condition:
    hash.sha256(0, filesize) == "fbeacf6c0412e4a610b4dcde1d6156c18dccf100003799ccc0703069e0419786"
}

rule MalwareBazaar_Vidar_066_975f5c0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2"
    family = "Vidar"
    file_name = "975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2.exe"
    file_type = "exe"
    first_seen = "2026-10-17 00:26:09"
  condition:
    hash.sha256(0, filesize) == "975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2"
}

rule MalwareBazaar_Mirai_067_067120dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "067120ddcaa4c0dab76f83e7a194a3f230e9b94749ede86ba17ca318d250f70c"
    family = "Mirai"
    file_name = "067120ddcaa4c0da.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:49"
  condition:
    hash.sha256(0, filesize) == "067120ddcaa4c0dab76f83e7a194a3f230e9b94749ede86ba17ca318d250f70c"
}

rule MalwareBazaar_Mirai_068_0eb31ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eb31ddca6741091e0abfd838fdbaa473566a410072f39beefc855938253b4ab"
    family = "Mirai"
    file_name = "0eb31ddca6741091.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:41"
  condition:
    hash.sha256(0, filesize) == "0eb31ddca6741091e0abfd838fdbaa473566a410072f39beefc855938253b4ab"
}

rule MalwareBazaar_Mirai_069_2199147e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2199147ebc24b697e11f273806e82e71471c2e56d2583b455cf3216c0bd1f871"
    family = "Mirai"
    file_name = "2199147ebc24b697.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:32"
  condition:
    hash.sha256(0, filesize) == "2199147ebc24b697e11f273806e82e71471c2e56d2583b455cf3216c0bd1f871"
}

rule MalwareBazaar_Mirai_070_4710c3b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4710c3b055ffa309aad3bca0420f2c9e573c9684d156c0cac4a648e2ebbd2bd3"
    family = "Mirai"
    file_name = "4710c3b055ffa309.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:23"
  condition:
    hash.sha256(0, filesize) == "4710c3b055ffa309aad3bca0420f2c9e573c9684d156c0cac4a648e2ebbd2bd3"
}

rule MalwareBazaar_Mirai_071_24f58f4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24f58f4db5552583f9be9d51b71cc9edcc3cdc8ea347528d36408bf1ed2ba56d"
    family = "Mirai"
    file_name = "24f58f4db5552583.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:14"
  condition:
    hash.sha256(0, filesize) == "24f58f4db5552583f9be9d51b71cc9edcc3cdc8ea347528d36408bf1ed2ba56d"
}

rule MalwareBazaar_Mirai_072_541b5556
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "541b55560e4ec2a51d5afebafafa82f15d1bcadeacaf1dd58d3687838e758715"
    family = "Mirai"
    file_name = "541b55560e4ec2a5.bin"
    file_type = "elf"
    first_seen = "2026-10-17 00:24:05"
  condition:
    hash.sha256(0, filesize) == "541b55560e4ec2a51d5afebafafa82f15d1bcadeacaf1dd58d3687838e758715"
}

rule MalwareBazaar_unknown_073_33b6b85a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33b6b85a3b873294043e64c1320892ada5b99a24f0ab712ccd998e19619a14b6"
    family = "unknown"
    file_name = "cegg_arm"
    file_type = "elf"
    first_seen = "2026-10-17 00:20:27"
  condition:
    hash.sha256(0, filesize) == "33b6b85a3b873294043e64c1320892ada5b99a24f0ab712ccd998e19619a14b6"
}

rule MalwareBazaar_Mirai_074_db2add78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db2add78820b944a2e2be6db47cb02111a387050ab2bc299f9f335edd2672ffa"
    family = "Mirai"
    file_name = "adb.arm7"
    file_type = "elf"
    first_seen = "2026-10-17 00:20:24"
  condition:
    hash.sha256(0, filesize) == "db2add78820b944a2e2be6db47cb02111a387050ab2bc299f9f335edd2672ffa"
}

rule MalwareBazaar_ValleyRAT_075_d76706ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d76706ec1ef248c678aeb8bf6484e2f8f6822d0d537dbce2be1de23045e65ae6"
    family = "ValleyRAT"
    file_name = "18390d1648bf678684d5fcdfa07ae03d.exe"
    file_type = "exe"
    first_seen = "2026-10-17 00:15:11"
  condition:
    hash.sha256(0, filesize) == "d76706ec1ef248c678aeb8bf6484e2f8f6822d0d537dbce2be1de23045e65ae6"
}

rule MalwareBazaar_Mirai_076_26f91ce3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26f91ce3d8ee20dd027d4de026d6e5dd08604b6bec6b3142b55749150493285c"
    family = "Mirai"
    file_name = "2"
    file_type = "elf"
    first_seen = "2026-10-17 00:14:20"
  condition:
    hash.sha256(0, filesize) == "26f91ce3d8ee20dd027d4de026d6e5dd08604b6bec6b3142b55749150493285c"
}

rule MalwareBazaar_unknown_077_b0870f37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0870f37b0968f0b10e698e2bb6815323ae8d5e88f67a753879974fccb28f58b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-17 00:04:42"
  condition:
    hash.sha256(0, filesize) == "b0870f37b0968f0b10e698e2bb6815323ae8d5e88f67a753879974fccb28f58b"
}

rule MalwareBazaar_Mirai_078_74c6f27c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74c6f27ce2a20dd393e72bb54293cfece0cb05e599ff0010607f29e7c8a0f5dc"
    family = "Mirai"
    file_name = "4"
    file_type = "elf"
    first_seen = "2026-10-16 23:57:17"
  condition:
    hash.sha256(0, filesize) == "74c6f27ce2a20dd393e72bb54293cfece0cb05e599ff0010607f29e7c8a0f5dc"
}

rule MalwareBazaar_Mirai_079_69960c0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69960c0c2f1efd9e9e228d3ec1b435cdea5ad6ac7b5bb0c82b890a551dfff5f9"
    family = "Mirai"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-16 23:55:17"
  condition:
    hash.sha256(0, filesize) == "69960c0c2f1efd9e9e228d3ec1b435cdea5ad6ac7b5bb0c82b890a551dfff5f9"
}

rule MalwareBazaar_Mirai_080_345fd6e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "345fd6e63c2c817ff28ac5e4fc6792e8ada4efadebe6a3692f334300fb35b187"
    family = "Mirai"
    file_name = "3"
    file_type = "elf"
    first_seen = "2026-10-16 23:53:15"
  condition:
    hash.sha256(0, filesize) == "345fd6e63c2c817ff28ac5e4fc6792e8ada4efadebe6a3692f334300fb35b187"
}

rule MalwareBazaar_Mirai_081_4fa0c513
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fa0c513e52bc0e01425e82cc533d915cde8e6a34041b16616eb064736dbb80e"
    family = "Mirai"
    file_name = "7"
    file_type = "elf"
    first_seen = "2026-10-16 23:49:15"
  condition:
    hash.sha256(0, filesize) == "4fa0c513e52bc0e01425e82cc533d915cde8e6a34041b16616eb064736dbb80e"
}

rule MalwareBazaar_Mirai_082_e39ad7ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e39ad7aefcd3c46b3d45bc9ba81f906e9ff8521e5d654379f304ea9e90d103c9"
    family = "Mirai"
    file_name = "disssh4"
    file_type = "elf"
    first_seen = "2026-10-16 23:49:13"
  condition:
    hash.sha256(0, filesize) == "e39ad7aefcd3c46b3d45bc9ba81f906e9ff8521e5d654379f304ea9e90d103c9"
}

rule MalwareBazaar_unknown_083_6d2de1fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d2de1fb1a561c2e19e4a91894cb6bee1bc045ecff9d20eaf48488500bf577d8"
    family = "unknown"
    file_name = "hb_arm"
    file_type = "elf"
    first_seen = "2026-10-16 23:47:17"
  condition:
    hash.sha256(0, filesize) == "6d2de1fb1a561c2e19e4a91894cb6bee1bc045ecff9d20eaf48488500bf577d8"
}

rule MalwareBazaar_Mirai_084_81d1ed76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81d1ed7640838826c40418b5680f1ed5942b73dbccc81b3c37895bafecc39d0a"
    family = "Mirai"
    file_name = "dissmips"
    file_type = "elf"
    first_seen = "2026-10-16 23:43:16"
  condition:
    hash.sha256(0, filesize) == "81d1ed7640838826c40418b5680f1ed5942b73dbccc81b3c37895bafecc39d0a"
}

rule MalwareBazaar_unknown_085_ce1eb64f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce1eb64fc04650f2e124bbae21a41cbaaf6e583c5b8783e2519fada7f6e8e957"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 23:29:13"
  condition:
    hash.sha256(0, filesize) == "ce1eb64fc04650f2e124bbae21a41cbaaf6e583c5b8783e2519fada7f6e8e957"
}

rule MalwareBazaar_unknown_086_1502ca97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1502ca97953e7168f856d6ac9e5940b4f65f55ed52d91ed14fa3946b713ee12f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 23:28:56"
  condition:
    hash.sha256(0, filesize) == "1502ca97953e7168f856d6ac9e5940b4f65f55ed52d91ed14fa3946b713ee12f"
}

rule MalwareBazaar_GhostPulse_087_e1c4d064
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1c4d064c1353ba75771662a61b7b529d4a206aa3cce1d5ca6529c53ab8b0946"
    family = "GhostPulse"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 23:24:30"
  condition:
    hash.sha256(0, filesize) == "e1c4d064c1353ba75771662a61b7b529d4a206aa3cce1d5ca6529c53ab8b0946"
}

rule MalwareBazaar_Mirai_088_6fab0497
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fab0497af6033669821a65fc491f172e2b830c73a1b15994b7b68f57364fc27"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-16 23:07:11"
  condition:
    hash.sha256(0, filesize) == "6fab0497af6033669821a65fc491f172e2b830c73a1b15994b7b68f57364fc27"
}

rule MalwareBazaar_ConnectWise_089_1f01ff48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31"
    family = "ConnectWise"
    file_name = "1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31.msi"
    file_type = "msi"
    first_seen = "2026-10-16 23:06:09"
  condition:
    hash.sha256(0, filesize) == "1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31"
}

rule MalwareBazaar_Mirai_090_bd809482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd809482df80b166a2bb067629569be412561ebb88dcb6777e0c540bb309c878"
    family = "Mirai"
    file_name = "bd809482df80b166a2bb067629569be412561ebb88dcb6777e0c540bb309c878.elf"
    file_type = "elf"
    first_seen = "2026-10-16 22:51:13"
  condition:
    hash.sha256(0, filesize) == "bd809482df80b166a2bb067629569be412561ebb88dcb6777e0c540bb309c878"
}

rule MalwareBazaar_Mirai_091_448eefd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "448eefd781b3b6ecee0658169cf957924c985e578af5d94745f1c7460044c637"
    family = "Mirai"
    file_name = "448eefd781b3b6ecee0658169cf957924c985e578af5d94745f1c7460044c637.elf"
    file_type = "elf"
    first_seen = "2026-10-16 22:51:08"
  condition:
    hash.sha256(0, filesize) == "448eefd781b3b6ecee0658169cf957924c985e578af5d94745f1c7460044c637"
}

rule MalwareBazaar_unknown_092_9d2519c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d2519c26fc99039bf0d22af806baac93048dedbd557a275cb19478e886d63ff"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 22:23:35"
  condition:
    hash.sha256(0, filesize) == "9d2519c26fc99039bf0d22af806baac93048dedbd557a275cb19478e886d63ff"
}

rule MalwareBazaar_unknown_093_ee735503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee735503a6d76a9eb6a0b7b511eb430aed0e8325c4ebdece5ea4c8c61e551c95"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 22:19:12"
  condition:
    hash.sha256(0, filesize) == "ee735503a6d76a9eb6a0b7b511eb430aed0e8325c4ebdece5ea4c8c61e551c95"
}

rule MalwareBazaar_Mirai_094_9896ae46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129"
    family = "Mirai"
    file_name = "9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129.elf"
    file_type = "elf"
    first_seen = "2026-10-16 22:16:08"
  condition:
    hash.sha256(0, filesize) == "9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129"
}

rule MalwareBazaar_Mirai_095_1442f715
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1442f715afabfbbb9c1ab2699832bd4f24c06b776ce0a04ccb5beedb067ffc20"
    family = "Mirai"
    file_name = "8"
    file_type = "elf"
    first_seen = "2026-10-16 22:07:15"
  condition:
    hash.sha256(0, filesize) == "1442f715afabfbbb9c1ab2699832bd4f24c06b776ce0a04ccb5beedb067ffc20"
}

rule MalwareBazaar_ConnectWise_096_e050ddcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e050ddccbdac97dfc8eb41760a76b1ae7f0c9e22a44034304462ea20c3ed51f5"
    family = "ConnectWise"
    file_name = "ZoomInstallerFull.js"
    file_type = "js"
    first_seen = "2026-10-16 22:05:42"
  condition:
    hash.sha256(0, filesize) == "e050ddccbdac97dfc8eb41760a76b1ae7f0c9e22a44034304462ea20c3ed51f5"
}

rule MalwareBazaar_Mirai_097_c9f7fada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9f7fada2b226ef942e7ffd5eb5a63c8ac741b53dd3328cd6c907cea135849e0"
    family = "Mirai"
    file_name = "mbupload-1bgovsky.bin"
    file_type = "elf"
    first_seen = "2026-10-16 22:02:28"
  condition:
    hash.sha256(0, filesize) == "c9f7fada2b226ef942e7ffd5eb5a63c8ac741b53dd3328cd6c907cea135849e0"
}

rule MalwareBazaar_Mirai_098_8182fdf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8182fdf5fffca2a35ea0c59210fe6e47c6eb670a794bad8f10e0c33d9896741c"
    family = "Mirai"
    file_name = "mbupload-5xvyfmsk.bin"
    file_type = "elf"
    first_seen = "2026-10-16 22:01:23"
  condition:
    hash.sha256(0, filesize) == "8182fdf5fffca2a35ea0c59210fe6e47c6eb670a794bad8f10e0c33d9896741c"
}

rule MalwareBazaar_unknown_099_ee39f091
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee39f091a23c746763ff44a273d11307abe5ca531f363b5621dfaa695f39a37b"
    family = "unknown"
    file_name = "건강검진.zip"
    file_type = "zip"
    first_seen = "2026-10-16 22:00:48"
  condition:
    hash.sha256(0, filesize) == "ee39f091a23c746763ff44a273d11307abe5ca531f363b5621dfaa695f39a37b"
}

rule MalwareBazaar_unknown_100_bc3ba9fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc3ba9feddc78c129369cfb771ec653a8cdc8da555117e4036fa39f20c01c78f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-16 22:00:38"
  condition:
    hash.sha256(0, filesize) == "bc3ba9feddc78c129369cfb771ec653a8cdc8da555117e4036fa39f20c01c78f"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

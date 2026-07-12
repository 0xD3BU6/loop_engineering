# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-12

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 630 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 630 |
| Unique family labels | 5 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 56 |
| unknown | 41 |
| NanoCore | 1 |
| Socks5Systemz | 1 |
| NetSupport | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 53 |
| exe | 19 |
| sh | 19 |
| unknown | 3 |
| gz | 3 |
| xapk | 1 |
| msi | 1 |
| jar | 1 |

## Per-Sample Analysis

### Sample 1: `3059240b64dcdb77`

| Field | Value |
|---|---|
| SHA-256 | `3059240b64dcdb773b76b64d9a7a70e51b50720025b3275deda1e34350d252b1` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-12 03:52:13` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd28045cb9ffb91331a4ffbc206b3e31` |
| SHA-1 | `bc39db0d45e00c290ae4d600117ca7da4e8692d4` |
| SHA-256 | `3059240b64dcdb773b76b64d9a7a70e51b50720025b3275deda1e34350d252b1` |
| SHA3-384 | `62ffa58dca9d2d12d10c751f4147a33b92fd6482cf6088c59f185553378befbd322d00eefad5fc9b8b1bbf9c032f6eb6` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T141E6334C94E416FFE5B3223997C1AA11D4E974710BB2C8DB17A4CBB26E831A18D3C767` |
| SSDEEP | `393216:yqeGQGzChEdh9wqWWALQOaoXMCHWUjX/cuI3/PGTAI:yMddXwAOvaoXMb8XUH/O7` |
| ICON-DHASH | `71d89ea29ac6e471` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_3059240b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3059240b64dcdb773b76b64d9a7a70e51b50720025b3275deda1e34350d252b1"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-12 03:52:13"
  condition:
    hash.sha256(0, filesize) == "3059240b64dcdb773b76b64d9a7a70e51b50720025b3275deda1e34350d252b1"
}
```

### Sample 2: `85c71cb954f79b09`

| Field | Value |
|---|---|
| SHA-256 | `85c71cb954f79b09d239900289b10d40290caf5501302103587c43fb96c65dec` |
| Family label | `unknown` |
| File name | `womp` |
| File type | `sh` |
| First seen | `2026-07-12 03:12:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de030e52f66dd69b3d931a3d2a5e8675` |
| SHA-1 | `6e9b3a86155641d8b26a5274df705a3959b805f6` |
| SHA-256 | `85c71cb954f79b09d239900289b10d40290caf5501302103587c43fb96c65dec` |
| SHA3-384 | `a34bf22ea7503a8c6709b782a3da4295968478512a942d87375cb9baae782c1d0dc6a4cd78245553c0d7eae815f9fa07` |
| TLSH | `T16D512DCD30BF26366E033DDAB119D884F506F2D618DA5E05FC84EEA2DC979653838698` |
| SSDEEP | `24:fvp8wWPNIo8KQ8pt78z/ASRpKdQ8tvp8fVPNI38K/8OLLeiPSRpKwq8Wp8GNITKw:R1RpKQQqRpKEIsRpK3U` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_85c71cb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85c71cb954f79b09d239900289b10d40290caf5501302103587c43fb96c65dec"
    family = "unknown"
    file_name = "womp"
    file_type = "sh"
    first_seen = "2026-07-12 03:12:51"
  condition:
    hash.sha256(0, filesize) == "85c71cb954f79b09d239900289b10d40290caf5501302103587c43fb96c65dec"
}
```

### Sample 3: `5ac877f1702cfb39`

| Field | Value |
|---|---|
| SHA-256 | `5ac877f1702cfb39fdc4b8c4650fb4cffabfcff00757ea40c7860e6eae6f84d6` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-12 02:52:13` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da5b9ae440090b076b7cea6b35d6fd5b` |
| SHA-1 | `9a96f88a43bae446faacb26faf28477efcf93fbe` |
| SHA-256 | `5ac877f1702cfb39fdc4b8c4650fb4cffabfcff00757ea40c7860e6eae6f84d6` |
| SHA3-384 | `8d801914566d862367d7864e209b611f15da8132e3886668794621895fab80c77f8316295d52815c99cb1ea8c1c6ad4b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1CAE6336867D006FAE973803D9DC28590D6E9B81A1733CD9F5FA483A25E172E09D3C747` |
| SSDEEP | `393216:DQIxdwsuKSU/PNbhAXMCHWUjXGcuI3/PGTAI:DHBl/7AXMb8X7H/O7` |
| ICON-DHASH | `f0f8dcb692c6f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_5ac877f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ac877f1702cfb39fdc4b8c4650fb4cffabfcff00757ea40c7860e6eae6f84d6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-12 02:52:13"
  condition:
    hash.sha256(0, filesize) == "5ac877f1702cfb39fdc4b8c4650fb4cffabfcff00757ea40c7860e6eae6f84d6"
}
```

### Sample 4: `78d584e29cf2af46`

| Field | Value |
|---|---|
| SHA-256 | `78d584e29cf2af465baa137c03d6644a8d8c269716349b03eddde76f3b9c88a0` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-07-12 02:38:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0603f6162bc0970c925752f9c7d338a6` |
| SHA-1 | `1e7f5d2ccc76208f117a834213c118bd05efdb77` |
| SHA-256 | `78d584e29cf2af465baa137c03d6644a8d8c269716349b03eddde76f3b9c88a0` |
| SHA3-384 | `e665d26ef1c2c726aa490a2abe10dc6bd99079635b900f82801abaaa4b94dbb6109cb44e903946ae40bdb8e008555c79` |
| TLSH | `T13ED37D00BB184917D1921D745B3F0762D3BDD44368B8E109190BBB561732EFBAACBB9B` |
| SSDEEP | `3072:cBsu7X+0TZihY0U4YK46yhyo73hoI/eVA7CMA1D6cC:VKu0T+Y0dY56m3doI/eVA7BmWcC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_78d584e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78d584e29cf2af465baa137c03d6644a8d8c269716349b03eddde76f3b9c88a0"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-12 02:38:00"
  condition:
    hash.sha256(0, filesize) == "78d584e29cf2af465baa137c03d6644a8d8c269716349b03eddde76f3b9c88a0"
}
```

### Sample 5: `80f66f2a896623bf`

| Field | Value |
|---|---|
| SHA-256 | `80f66f2a896623bf068089121aba8be0104f1ad71f0c3b503f6775b57705c858` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-12 02:37:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38f7048e3c632fd7dc38bfee214eca7f` |
| SHA-1 | `9e9601e41b8259f2b823d715c0705310d781190d` |
| SHA-256 | `80f66f2a896623bf068089121aba8be0104f1ad71f0c3b503f6775b57705c858` |
| SHA3-384 | `342b237ac8290416aa4a790152208a0ff04443709501a47924bb4476be0462065cd74fe86a324155dc729f836ee48433` |
| TLSH | `T1D2B31906356198FCC167C034D73FE937EA31785D12243A6E6BC4BA711E22E365F0AB96` |
| SSDEEP | `1536:VSFqSKVn5GuXQ9v/qGPdqMG7WSh1VolZhhdei7POSUvElRg79VRCG44k6H:VSvUcuXQZ/qGlqTma2OtEI9bCG4sH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_80f66f2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80f66f2a896623bf068089121aba8be0104f1ad71f0c3b503f6775b57705c858"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:57"
  condition:
    hash.sha256(0, filesize) == "80f66f2a896623bf068089121aba8be0104f1ad71f0c3b503f6775b57705c858"
}
```

### Sample 6: `66d7509a1d19c4f6`

| Field | Value |
|---|---|
| SHA-256 | `66d7509a1d19c4f6a25b5aec9f432e8423b3b123b6359b4d5be2cc52385b3842` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-12 02:37:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1c5ee42de2466c1db34b90bb0486ce0` |
| SHA-1 | `8422c0d2720dd3609d4c5f2ce35260d0e74df5f4` |
| SHA-256 | `66d7509a1d19c4f6a25b5aec9f432e8423b3b123b6359b4d5be2cc52385b3842` |
| SHA3-384 | `124007bf465963ba8364e4d62edc23a1f060d58c7b48c8536a3af3702f619bbbd5702137ee6e95c5f68b0b6bb169d238` |
| TLSH | `T1ACF3294F7721CF21D71DC93149B38B9626F926512AD28889F35CDE083E6034DA86FEE5` |
| TELFHASH | `t16b318ef08b3b66218a89cbec89dd775a461e9115470bdf33fe2181bc501a4ede229d4f` |
| SSDEEP | `1536:76RyyCAgBSyxKhMgX7tREbwfsIWfDIZXIBJD9visEldjutsRGWgTtEf9KR95ElhE:GR6myivtWBqsylRGWK7o414EOm1Dh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_66d7509a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66d7509a1d19c4f6a25b5aec9f432e8423b3b123b6359b4d5be2cc52385b3842"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:54"
  condition:
    hash.sha256(0, filesize) == "66d7509a1d19c4f6a25b5aec9f432e8423b3b123b6359b4d5be2cc52385b3842"
}
```

### Sample 7: `19fca0c2200f6443`

| Field | Value |
|---|---|
| SHA-256 | `19fca0c2200f6443cd0bcb954503a677eaef23bb5edf3025690e768d67255f3d` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-07-12 02:37:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4768f2aa106a18a13ded44b3b19b6dc0` |
| SHA-1 | `5b64e10fac9b776909f0a2f4063721404eea8621` |
| SHA-256 | `19fca0c2200f6443cd0bcb954503a677eaef23bb5edf3025690e768d67255f3d` |
| SHA3-384 | `ca383ddb32c8d5661e18bef372ed26ee556047ac5867e59c944354d6bf30fa6d8a2fad43d1ae12913d94cf9e5c164531` |
| TLSH | `T145D32A41BD982BEBC81FCE34C92DC34A01E7A49F61D5F2BE663CCD4C749E61A19A3494` |
| SSDEEP | `1536:nPa3rs086wrEwtTPjSwQj4zUy9faWyL1aZspvVxQkHle3gvHK93Bb7gj3ksAwZQC:nP6rB87trpy3xQ19329AvfA1De` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_19fca0c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19fca0c2200f6443cd0bcb954503a677eaef23bb5edf3025690e768d67255f3d"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:49"
  condition:
    hash.sha256(0, filesize) == "19fca0c2200f6443cd0bcb954503a677eaef23bb5edf3025690e768d67255f3d"
}
```

### Sample 8: `24c1f320e51df584`

| Field | Value |
|---|---|
| SHA-256 | `24c1f320e51df5849f6b1dffe253a72558117e911c2ba210ec085cd15ec42ca1` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-12 02:37:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4bdb4d95851223de861274eadce1f8d` |
| SHA-1 | `11d69ab1e083b8a9331cb99c190aa5ae66b3d76b` |
| SHA-256 | `24c1f320e51df5849f6b1dffe253a72558117e911c2ba210ec085cd15ec42ca1` |
| SHA3-384 | `25a74904cbb89939d2c08db7aa46bcb157d1a4e15417d5ca6a046c74fb14534c8890764c99102c56a38f321b7584d17d` |
| TLSH | `T1A1B329A9F880DE52C6D4267AFB5D014D33231778C3DE7109CE209E346BEB95A0E3B942` |
| SSDEEP | `3072:E1mTrBKGyuEHVB+P9Nt9vJpUcYEEU8s7140QZjyBBx7UWKSzf1D:E1m3B2fy7UcYEEU8s7e0KOBBx4Sz9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_24c1f320
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24c1f320e51df5849f6b1dffe253a72558117e911c2ba210ec085cd15ec42ca1"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:46"
  condition:
    hash.sha256(0, filesize) == "24c1f320e51df5849f6b1dffe253a72558117e911c2ba210ec085cd15ec42ca1"
}
```

### Sample 9: `a77c058ead923018`

| Field | Value |
|---|---|
| SHA-256 | `a77c058ead923018c2aaf9266e7d2ee57a40f97de14a52282930dcac96f9cec0` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-07-12 02:37:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d90bb5cc519bf7937952b40c45f2306` |
| SHA-1 | `2c37bd39a6a7a05299810824b815c5896291a578` |
| SHA-256 | `a77c058ead923018c2aaf9266e7d2ee57a40f97de14a52282930dcac96f9cec0` |
| SHA3-384 | `8272fc88910b01cb55700c58ead7274a11812b083f5b0f7e9179fae50c4b02c98f3670ce6ea76850fd4a509289971373` |
| TLSH | `T1F4C33A5CFA17C0F0E5C345F1067BA7AA963B99126237F1E2FF562762F871302598922C` |
| SSDEEP | `1536:tjpIk5FphkrM2kSXrakAf3/3ABhjodBZb2ZDKjwcMZp+U0Y1xWIpyiH7:os0w3f/3AkBZaZD3cMiqxWIpyiH7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_a77c058e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a77c058ead923018c2aaf9266e7d2ee57a40f97de14a52282930dcac96f9cec0"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:42"
  condition:
    hash.sha256(0, filesize) == "a77c058ead923018c2aaf9266e7d2ee57a40f97de14a52282930dcac96f9cec0"
}
```

### Sample 10: `b8445de08b5f8dc7`

| Field | Value |
|---|---|
| SHA-256 | `b8445de08b5f8dc796f0e20a3df7ef4ff1e3c17c8241367e067a93b44541f469` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-07-12 02:37:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06c8a05632b2ede63ce321d123069d71` |
| SHA-1 | `b6e8e672f072710fc29c92355a694e40ce66a83b` |
| SHA-256 | `b8445de08b5f8dc796f0e20a3df7ef4ff1e3c17c8241367e067a93b44541f469` |
| SHA3-384 | `65df50c20d905937b6df001429931f5a535bc3d705c856f5d6723282b507f2ada53c5e0f8458aecbe2dabaa567a01ac6` |
| TLSH | `T14CB31B99F890DE52C6D52675FA5E418C332353B8C3DA72068D249E3477EBC9A0E3ED42` |
| SSDEEP | `3072:IUPZjTuolizTrrgUQ4g8O2CRb0gsT1vO1OEtzf1D:IUxjTW3gUQ4g8OjRbn0O1Omz9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_b8445de0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8445de08b5f8dc796f0e20a3df7ef4ff1e3c17c8241367e067a93b44541f469"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:36"
  condition:
    hash.sha256(0, filesize) == "b8445de08b5f8dc796f0e20a3df7ef4ff1e3c17c8241367e067a93b44541f469"
}
```

### Sample 11: `01dd3eeddc0ff280`

| Field | Value |
|---|---|
| SHA-256 | `01dd3eeddc0ff280ab0ae9272d20a807c80f10afe4b1394fa68e427a87cebadd` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-07-12 02:36:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2e57ceb077251f9db228ad6de4aef57` |
| SHA-1 | `42655ff9c03f6ab8531c5f5913c7bcdd6c429cab` |
| SHA-256 | `01dd3eeddc0ff280ab0ae9272d20a807c80f10afe4b1394fa68e427a87cebadd` |
| SHA3-384 | `b8c196613f55a6ed342eea4e803e845175349b91be54b5da8d892679552071e9edea10ed83676c2c9973c9922d26cddb` |
| TLSH | `T14833F153E24A6829EE975CF47C92DAD563F805926D6A4DE30A84DBC13C43FA63302CD9` |
| SSDEEP | `1536:arlSzHDyb3Ws1vdVebb4DhbMqbP64u+qgw0ra:IlSzHDe3WoeX2hMqbP64u+qgwh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_01dd3eed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01dd3eeddc0ff280ab0ae9272d20a807c80f10afe4b1394fa68e427a87cebadd"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:57"
  condition:
    hash.sha256(0, filesize) == "01dd3eeddc0ff280ab0ae9272d20a807c80f10afe4b1394fa68e427a87cebadd"
}
```

### Sample 12: `42dbebaa947798c6`

| Field | Value |
|---|---|
| SHA-256 | `42dbebaa947798c63208f77fc2bf81ba4749dbf8c423cd30663e4fc95d46c32d` |
| Family label | `Mirai` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-07-12 02:36:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `846f6f750d925c98614e83b206203cc1` |
| SHA-1 | `831e176df466c896015aafd42ca4ecf58861d656` |
| SHA-256 | `42dbebaa947798c63208f77fc2bf81ba4749dbf8c423cd30663e4fc95d46c32d` |
| SHA3-384 | `41d83f49e9a1f030da77ff5b6c0bb2a09a28c883cf65b5390953cd9f33b17fecb9012dca95133bf45a89cf3c49c795f9` |
| TLSH | `T1B9B35BD5B50C7EADD5977E7CC20A53176B1C9E409C83860190A2FE072AB36E71E369CB` |
| TELFHASH | `t160e024f2834fa625064dcbdd83ca739c5a2de0480147ef53fe41043c909a94e361498f` |
| SSDEEP | `1536:Nzic4kKYQMhkItoQ6NR8RaDFTtM3hxBj283GzCGS0m69Qpvuw/qIRalQLLjeH:TEYzhzohzJlGBRfGS07QpvAlQLLjO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_42dbebaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42dbebaa947798c63208f77fc2bf81ba4749dbf8c423cd30663e4fc95d46c32d"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:55"
  condition:
    hash.sha256(0, filesize) == "42dbebaa947798c63208f77fc2bf81ba4749dbf8c423cd30663e4fc95d46c32d"
}
```

### Sample 13: `f203c98a908119c7`

| Field | Value |
|---|---|
| SHA-256 | `f203c98a908119c7bbd8f4be45a8ca429e1cedce7c971d59b1d432bbdb4595b0` |
| Family label | `unknown` |
| File name | `busywget.sh` |
| File type | `sh` |
| First seen | `2026-07-12 02:36:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17c0ccbb94b1a3fba9048def3efa927f` |
| SHA-1 | `d8f7dc0dbccbd2af4d281df423fdc2f8275e50f8` |
| SHA-256 | `f203c98a908119c7bbd8f4be45a8ca429e1cedce7c971d59b1d432bbdb4595b0` |
| SHA3-384 | `d82f3b1cb50ca60395b3f73167a4bb72b635bb1614c4afe121589ebe8233406fe7503e8750303642c9969d41a44edef5` |
| TLSH | `T1281166C5046449DDDC028E40F76784C8CA4D4AD7FD82BB4EA99D04AAE69CE34F1DEAC8` |
| SSDEEP | `6:hCQzhw/Se3Ko3g3vwbjSe1JotrlSeODJoO3rw/Se/Fo/q+nSeBobzSef0oC+Seee:MC2qgq2pDLU44GOxDfKJeNIysAAa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_f203c98a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f203c98a908119c7bbd8f4be45a8ca429e1cedce7c971d59b1d432bbdb4595b0"
    family = "unknown"
    file_name = "busywget.sh"
    file_type = "sh"
    first_seen = "2026-07-12 02:36:52"
  condition:
    hash.sha256(0, filesize) == "f203c98a908119c7bbd8f4be45a8ca429e1cedce7c971d59b1d432bbdb4595b0"
}
```

### Sample 14: `795896a03556795d`

| Field | Value |
|---|---|
| SHA-256 | `795896a03556795d8c69818b26b5779f2e949c29b0f67d037e78be3da7765326` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-12 02:36:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `adb7997d0a288c3ae6454ee7223c7c0c` |
| SHA-1 | `f4dde76732f54cfd162975f70da4b1b376ea107d` |
| SHA-256 | `795896a03556795d8c69818b26b5779f2e949c29b0f67d037e78be3da7765326` |
| SHA3-384 | `26e4e00d80700fd0538d5d309f791db3d6491aa76bf48c97ec6277856744b5df750f113c6cb81d00b3fb7f2fefa67db1` |
| TLSH | `T13033F162D67AB7FCCE7CD3F64DA186C8CF1A99B6E54E1236106440FACE9658D2304783` |
| SSDEEP | `768:HH0F54T2OcsCsZu12+ZLuWBthfw28xKV8+wr2lGLpqPYGXfT6wVIZTcxTfh8pLmV:HH0F54THZc9lPLfl8xPV4YG7Lycx7hjV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_795896a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "795896a03556795d8c69818b26b5779f2e949c29b0f67d037e78be3da7765326"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:50"
  condition:
    hash.sha256(0, filesize) == "795896a03556795d8c69818b26b5779f2e949c29b0f67d037e78be3da7765326"
}
```

### Sample 15: `b2c0cae650ddf10b`

| Field | Value |
|---|---|
| SHA-256 | `b2c0cae650ddf10b0d3be03931adb4f7ade22e061b71e6728205f8a11b02f5a5` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-12 02:36:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `170e626f9c595f98c42d3ea81f78a587` |
| SHA-1 | `a1e2a3641cc5dcdbd443f02c879bada1057c1541` |
| SHA-256 | `b2c0cae650ddf10b0d3be03931adb4f7ade22e061b71e6728205f8a11b02f5a5` |
| SHA3-384 | `374bb84a2bdd4e1e12f3a1feb075ac300ca736633da38009f61d079b04b5802e05684d0cacd19ee6d8534c19aee22e91` |
| TLSH | `T1A06302C4EB9E0589C84D33B50C555B8B3454F651ADE01554F9CB8A1A2FBF83C28B4FAE` |
| SSDEEP | `1536:gvhhzFBU8f1b7mE3cAMUi8l8AXb4GqtAzUtrBM3NyFOeQw:gZhzFBl171c1UiarCtaUt634D` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_b2c0cae6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2c0cae650ddf10b0d3be03931adb4f7ade22e061b71e6728205f8a11b02f5a5"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:47"
  condition:
    hash.sha256(0, filesize) == "b2c0cae650ddf10b0d3be03931adb4f7ade22e061b71e6728205f8a11b02f5a5"
}
```

### Sample 16: `9679b99144febbed`

| Field | Value |
|---|---|
| SHA-256 | `9679b99144febbed9aae1222361e08578897e83d9b5d12024850a8aa57a011a8` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-07-12 02:36:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cae732539ab3103bbdf3bdcb3638e70` |
| SHA-1 | `b1936c1cfbffb262e761f71edf4a4244720637ef` |
| SHA-256 | `9679b99144febbed9aae1222361e08578897e83d9b5d12024850a8aa57a011a8` |
| SHA3-384 | `d3f95e348bdf234568514db106068f787d7dfa4743780e5d255ab5f1fb463a237d0bd4a45c6131d30c8072b1155ff05f` |
| TLSH | `T1B2111786052489CDDD128E44F7A744C0DA4D429BFDA3BB0EE9D5456BE4ACE38F4DCAC2` |
| SSDEEP | `6:hCQzhSpSe3Ko3g3vS5Se1Jotr8cSeODJoO3r+Se/Fo/q+tSeBob3NF5Sef0oCADR:MCEUx2XDBKhU4vDjkUPDfKYUeNIyyAAa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_9679b991
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9679b99144febbed9aae1222361e08578897e83d9b5d12024850a8aa57a011a8"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-12 02:36:43"
  condition:
    hash.sha256(0, filesize) == "9679b99144febbed9aae1222361e08578897e83d9b5d12024850a8aa57a011a8"
}
```

### Sample 17: `f4f3d6cfb309115d`

| Field | Value |
|---|---|
| SHA-256 | `f4f3d6cfb309115d5ac33dbdd5a850e97cf542be479f2bdfe87bbc68af86df27` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-07-12 02:36:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79190736e65e2cd1a001359854fbf04c` |
| SHA-1 | `5049abcc9f1efbad498ef4cc656fda764e149a53` |
| SHA-256 | `f4f3d6cfb309115d5ac33dbdd5a850e97cf542be479f2bdfe87bbc68af86df27` |
| SHA3-384 | `093174d01445cf40845abb9065b4bd0b9227142c0b59572d269f68fdece38e8ee6b6a8abd2889d354533bf1cd6f8bd1f` |
| TLSH | `T1465312B69F449C01CE79D2F81ABA4DBB8FA9203F405547EF8EA0499467FE878D510827` |
| SSDEEP | `1536:ipcA4IMaChjt8H0biyah7WS8xV3TInY6Tc+6p40pQE:lGGhY0bi6xlInY6QFp40pQE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_f4f3d6cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4f3d6cfb309115d5ac33dbdd5a850e97cf542be479f2bdfe87bbc68af86df27"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:40"
  condition:
    hash.sha256(0, filesize) == "f4f3d6cfb309115d5ac33dbdd5a850e97cf542be479f2bdfe87bbc68af86df27"
}
```

### Sample 18: `a92ba723f321aa6a`

| Field | Value |
|---|---|
| SHA-256 | `a92ba723f321aa6a37d07ed61538f259c859e63cf4768a07e253361800e48758` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-12 02:36:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `313d2bbe173988f47fc4ec6477323dfe` |
| SHA-1 | `80577cd959e65f39893155b657df24a9eb8b06bf` |
| SHA-256 | `a92ba723f321aa6a37d07ed61538f259c859e63cf4768a07e253361800e48758` |
| SHA3-384 | `44ae05d34bcc249c4593b416dd0d150c91892a704d12b5fdddc7f77c7bbce51149209cf6430fada69ca5fa891cdb6181` |
| TLSH | `T11323E1178522EF30E47441F3B4A64001AE59BE21EDFE3AFF12044D65ABE65CD3BB8198` |
| SSDEEP | `768:eyc9gYwGswWAFVQ38oVMJRYCVtUHcqhj75ZcQ31CscTxsFJQHLWuN1JO3U03wf0:Xyr9YCI8qVrcQgnOFO6SJnf0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_a92ba723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a92ba723f321aa6a37d07ed61538f259c859e63cf4768a07e253361800e48758"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:37"
  condition:
    hash.sha256(0, filesize) == "a92ba723f321aa6a37d07ed61538f259c859e63cf4768a07e253361800e48758"
}
```

### Sample 19: `50302d86e61e5e6c`

| Field | Value |
|---|---|
| SHA-256 | `50302d86e61e5e6cea8e71c74a4a3284334de374e41f6075485be16c7e45bc6e` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-07-12 02:36:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebe8a3c3ff031c6f38f1aee6b11f4fc8` |
| SHA-1 | `2e6fc88bcd6777b803769e458f8b037898bcac49` |
| SHA-256 | `50302d86e61e5e6cea8e71c74a4a3284334de374e41f6075485be16c7e45bc6e` |
| SHA3-384 | `758cc04d5638aa4f905ee543a72bb0a30ec5fd19d56dcb98df6e9395f88e96c231cd106d49ed1f488ecc1b1a6dc987ea` |
| TLSH | `T1FE33F153E6E90609D886D17B9DC3B8558488D35DCA4FE236E6683233F2DBB423D6D704` |
| SSDEEP | `768:iL8siXu4NuLxNDaOHf4mCmt+XKYgDhJpFCZPSXJ/MwnbcuyD7UDMuGP:Vul1NxfNC3XODhQZPUFnouy8DMN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_50302d86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50302d86e61e5e6cea8e71c74a4a3284334de374e41f6075485be16c7e45bc6e"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:34"
  condition:
    hash.sha256(0, filesize) == "50302d86e61e5e6cea8e71c74a4a3284334de374e41f6075485be16c7e45bc6e"
}
```

### Sample 20: `01c727469c703060`

| Field | Value |
|---|---|
| SHA-256 | `01c727469c703060764c88239e7a02fbc9582ba31a3a4a44c958958521bcad58` |
| Family label | `unknown` |
| File name | `callaputa.sh` |
| File type | `sh` |
| First seen | `2026-07-12 02:36:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efb1721958b04808ca280ccbb541acab` |
| SHA-1 | `b324bce98608c9dabf5fa206fa6fba4978387c33` |
| SHA-256 | `01c727469c703060764c88239e7a02fbc9582ba31a3a4a44c958958521bcad58` |
| SHA3-384 | `4ca6deb9a9e60b641780e00b958b089b0a62ddbb056bcdc9c8dae2eeb40ce6865be12c6b0b7ec0c7270262f2a29e9726` |
| TLSH | `T11C315084053489CEDD47CE88F76680D0DE0916A7FDC37A1ED986095AE41CA38F4DFAC0` |
| SSDEEP | `24:HEUFzkehdJTBoCRcwhEEwXkaxbOxTejU6qLtM6:kUFzkWdJTBoMcwhgXkaxbOxTeA6qLtM6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_01c72746
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01c727469c703060764c88239e7a02fbc9582ba31a3a4a44c958958521bcad58"
    family = "unknown"
    file_name = "callaputa.sh"
    file_type = "sh"
    first_seen = "2026-07-12 02:36:31"
  condition:
    hash.sha256(0, filesize) == "01c727469c703060764c88239e7a02fbc9582ba31a3a4a44c958958521bcad58"
}
```

### Sample 21: `1a200226e352bb22`

| Field | Value |
|---|---|
| SHA-256 | `1a200226e352bb22c9009bebcbaaabc755a3d56d03ba97152a7c6277c09ef8ff` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-07-12 02:36:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6e4a17d0c32cf7b94e351d4aaccb993` |
| SHA-1 | `a5d4a4fc5263d06566a6745865bf1967ec1ea357` |
| SHA-256 | `1a200226e352bb22c9009bebcbaaabc755a3d56d03ba97152a7c6277c09ef8ff` |
| SHA3-384 | `0cb3574fee0c0e7fbdd01e4c9fd1480a63c4ad22214f7eec6d05889f775f435e77f8b6a22b09b54a118679d8e728663c` |
| TLSH | `T1D123F10123D82D10FAA8793F855DD845F5958FB863FA79235F28C8DE8AF191523B21CB` |
| SSDEEP | `768:1Cl4xEN2MsH5l7X5HDjWZa4kLCdtnwCmY3vqhj2nLQS7R4S73U03wfP:1VB9lljjX4YEtvm+ywP7RpafP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_1a200226
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a200226e352bb22c9009bebcbaaabc755a3d56d03ba97152a7c6277c09ef8ff"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:28"
  condition:
    hash.sha256(0, filesize) == "1a200226e352bb22c9009bebcbaaabc755a3d56d03ba97152a7c6277c09ef8ff"
}
```

### Sample 22: `766d88722c18c472`

| Field | Value |
|---|---|
| SHA-256 | `766d88722c18c4722e1b3a28281133b0c88082a5f3b58d4c58391879ed20a643` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-12 02:24:13` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX7.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e34490ccfb4ee2b193eb197b273b202` |
| SHA-1 | `de31fee2c26ecadfbf65cf5200b7b272089e220f` |
| SHA-256 | `766d88722c18c4722e1b3a28281133b0c88082a5f3b58d4c58391879ed20a643` |
| SHA3-384 | `2fb26fb4255708babdeadcf5145704e1f4cb7119e8cbb6da2c1262260f820b363062c699f20ff21f36822381b69b9068` |
| IMPHASH | `35cdf706d9aa8edbc924bfbdab2dc355` |
| TLSH | `T10DC623EA26E481B4D0925630B68BC3A97481B90C45FC4E1E3DD76D02AB18CDF6549FFB` |
| SSDEEP | `196608:pk9Dof/oFOV40SUu9tkcmuPkoBHYyiEhRm4l8clhp1i2q50dSfxaEi3h:Sl2/oFObpugSHtiEK4lZhp1ixlgD` |
| ICON-DHASH | `d430f0f071694c10` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_766d8872
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "766d88722c18c4722e1b3a28281133b0c88082a5f3b58d4c58391879ed20a643"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-12 02:24:13"
  condition:
    hash.sha256(0, filesize) == "766d88722c18c4722e1b3a28281133b0c88082a5f3b58d4c58391879ed20a643"
}
```

### Sample 23: `a236eaa0c6592016`

| Field | Value |
|---|---|
| SHA-256 | `a236eaa0c659201680739c3dcbb028a5d58de8b11471d3110a03e82d029f7aca` |
| Family label | `unknown` |
| File name | `Phone+Clean+Fix_1.0.1.6.xapk` |
| File type | `xapk` |
| First seen | `2026-07-12 01:53:11` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a833313dac6a135f1adcb4e829c229bf` |
| SHA-1 | `bbcdf4563d2f9222f17f2a362167d552ebb8b83b` |
| SHA-256 | `a236eaa0c659201680739c3dcbb028a5d58de8b11471d3110a03e82d029f7aca` |
| SHA3-384 | `e9f291f9965ee36df19165224f9a67d1b6d823bd9a9725366c0d46f20b63ea5ae2d855ebdc20673987fb0b1114692f0b` |
| TLSH | `T16147224BE70DA81FDDE6F5798D7A0232A02758A85306D7D72902F12CEEA7AC54F04BC5` |
| SSDEEP | `393216:CZIQwWFMa0o95KGI8hoPG4q9IjxKfINktlx3owpIq+ZloCO1QxG+Wx3eZHLGTkxM:CdHN5Rx0G47jgfISx3bpIbGaGb3eu6M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_a236eaa0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a236eaa0c659201680739c3dcbb028a5d58de8b11471d3110a03e82d029f7aca"
    family = "unknown"
    file_name = "Phone+Clean+Fix_1.0.1.6.xapk"
    file_type = "xapk"
    first_seen = "2026-07-12 01:53:11"
  condition:
    hash.sha256(0, filesize) == "a236eaa0c659201680739c3dcbb028a5d58de8b11471d3110a03e82d029f7aca"
}
```

### Sample 24: `886eb34b664e06f2`

| Field | Value |
|---|---|
| SHA-256 | `886eb34b664e06f2d543b0dc5f41c2bc56b2da02f0ecce54413af8128e050b54` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-12 01:52:14` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8156051e4f18c42cc2c459e1ad0172f` |
| SHA-1 | `8e385c455f796264c8ffad0c35e32b244fa1556c` |
| SHA-256 | `886eb34b664e06f2d543b0dc5f41c2bc56b2da02f0ecce54413af8128e050b54` |
| SHA3-384 | `57cfd034c29e6f1a7b4ae0746ab85aac9d16c772bdc829a7d9f77a438cbf0e710027f3cdb753c8945e8480acb8465d8c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C3E63358F6E023EDE6A38138DEF285A4E56174B50732C8DB177C8A55AE272D00E3E753` |
| SSDEEP | `393216:Oe04wr8F+CN9kdZsobN1XMCHWUjXHcuI3/PGTAI:OhYFhNmTXMb8X8H/O7` |
| ICON-DHASH | `71f0e4d4c4e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_886eb34b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "886eb34b664e06f2d543b0dc5f41c2bc56b2da02f0ecce54413af8128e050b54"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-12 01:52:14"
  condition:
    hash.sha256(0, filesize) == "886eb34b664e06f2d543b0dc5f41c2bc56b2da02f0ecce54413af8128e050b54"
}
```

### Sample 25: `50c3831d8653c9d2`

| Field | Value |
|---|---|
| SHA-256 | `50c3831d8653c9d2f31e612a3c68e8f27fbe9e4b18274d5d6338b5ede0896834` |
| Family label | `NanoCore` |
| File name | `cakhiatvwc02.info.exe` |
| File type | `exe` |
| First seen | `2026-07-12 01:45:04` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84aadf08ccddfa963b7e9a0ec0a83301` |
| SHA-1 | `01e85adef10443ce4e1a5264f8d0817141142de4` |
| SHA-256 | `50c3831d8653c9d2f31e612a3c68e8f27fbe9e4b18274d5d6338b5ede0896834` |
| SHA3-384 | `918a08c059e305adedad1202968e191972badc2e940c663d022e52be8835a8e390a96aabdf81cbe2f6799e2ad0381458` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16A14CF2677A84A2FE2DE85B9611211478378C2E3DCC3F3EE18D855B39B663E50A071D7` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5muvImfVqflRj0vkL:MLV6BtpmkjkGlt08L` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_025_50c3831d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50c3831d8653c9d2f31e612a3c68e8f27fbe9e4b18274d5d6338b5ede0896834"
    family = "NanoCore"
    file_name = "cakhiatvwc02.info.exe"
    file_type = "exe"
    first_seen = "2026-07-12 01:45:04"
  condition:
    hash.sha256(0, filesize) == "50c3831d8653c9d2f31e612a3c68e8f27fbe9e4b18274d5d6338b5ede0896834"
}
```

### Sample 26: `a8a60a1ca586d6b3`

| Field | Value |
|---|---|
| SHA-256 | `a8a60a1ca586d6b3b8a2cdb7058ca20665318bc1743c75b7b56101e9ff06f814` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.10589.15085.17293` |
| File type | `elf` |
| First seen | `2026-07-12 01:44:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08984c6587a270ee930f40c314429f40` |
| SHA-1 | `432fc2b05bfdf6b5658818c2c2f0f6e765032b09` |
| SHA-256 | `a8a60a1ca586d6b3b8a2cdb7058ca20665318bc1743c75b7b56101e9ff06f814` |
| SHA3-384 | `14dc45149d4cd9c268a7e626b5848c0074f81a92cd3ade1b6d2676b60850f8ffbb4e6ea62206e33b34a13927a5e6640e` |
| TLSH | `T174831995B9814B12C5D512BAFE1E118E3323177CE3DE73129D206F24778B96B0E7BA06` |
| TELFHASH | `t10811dc281ec48fde93f48e18c5cab1a2ba963e35c533393e4e96761b43231d1701682e` |
| SSDEEP | `1536:ZTnJWOzhCrfmhD0CS4UIYaZaUDDYX/QTMCiob5c5eCqfZ737pY8V/hX:2AhFjS4NYaZaUj5cYCqfZXpJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_a8a60a1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8a60a1ca586d6b3b8a2cdb7058ca20665318bc1743c75b7b56101e9ff06f814"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.15085.17293"
    file_type = "elf"
    first_seen = "2026-07-12 01:44:41"
  condition:
    hash.sha256(0, filesize) == "a8a60a1ca586d6b3b8a2cdb7058ca20665318bc1743c75b7b56101e9ff06f814"
}
```

### Sample 27: `83a6436320441c98`

| Field | Value |
|---|---|
| SHA-256 | `83a6436320441c985d8c9aff65d35e5925f8298629be3bda1df5877e1113b72c` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.10589.6778.4375` |
| File type | `elf` |
| First seen | `2026-07-12 01:44:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10d83ee16c520993977e65a4b339eece` |
| SHA-1 | `6a4b34b1d286e49be07d3718f5e60ab0ed3aef6b` |
| SHA-256 | `83a6436320441c985d8c9aff65d35e5925f8298629be3bda1df5877e1113b72c` |
| SHA3-384 | `9677b82af0578ccefb251345550ce149eba3688c070346453aa6963712d9d20a35555452b28f0a1439a340fca8eb33ec` |
| TLSH | `T1B7F33C46E6414A13C0D6177ABBEF42453323AB6493DB73059928BFF43F8679E0E63605` |
| TELFHASH | `t1f031fd325721411aae52cc60dcee57f1251d86272744ee33ef3ac8cc651a49ae62bc8f` |
| SSDEEP | `3072:8hG77R4X2HaUJbXUc1df4RVaEFkINdLfhLNM/9tMiOZH7v5w2F:8hGPKGHaUJbXUcrf4aEqIzLfhZM/9Wnv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_83a64363
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83a6436320441c985d8c9aff65d35e5925f8298629be3bda1df5877e1113b72c"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.6778.4375"
    file_type = "elf"
    first_seen = "2026-07-12 01:44:38"
  condition:
    hash.sha256(0, filesize) == "83a6436320441c985d8c9aff65d35e5925f8298629be3bda1df5877e1113b72c"
}
```

### Sample 28: `a973b2e00f825078`

| Field | Value |
|---|---|
| SHA-256 | `a973b2e00f8250789c5d78d286156fea7482d3082cada7fd1771412986c54050` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.10589.13407.32427` |
| File type | `elf` |
| First seen | `2026-07-12 01:44:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52a9d5df1280233c0aacb79471526c0e` |
| SHA-1 | `090384b316486fe06fb81f098cc9ee522d338948` |
| SHA-256 | `a973b2e00f8250789c5d78d286156fea7482d3082cada7fd1771412986c54050` |
| SHA3-384 | `4a1166e113b6f5ab95d34b30888abb27199e6fec03effa4aadf889884bc3c505541d9d36d311529028475489be015435` |
| TLSH | `T17C93C71E6E228FBDF769C33447B78E21A35C37D616E1C685E16CD2105E6028D642FFA8` |
| TELFHASH | `t11721001c1f7823e4713a5c5d045deb6b96a331da7b272c278e12946eb77d8829d20c1c` |
| SSDEEP | `1536:Cw4h0fLnw2U8POwzHXH3Lrxowl0EqH0ueMOuBwINV/Bdo:Yh0fLw2UrJw2EqUVIfo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_a973b2e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a973b2e00f8250789c5d78d286156fea7482d3082cada7fd1771412986c54050"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.13407.32427"
    file_type = "elf"
    first_seen = "2026-07-12 01:44:35"
  condition:
    hash.sha256(0, filesize) == "a973b2e00f8250789c5d78d286156fea7482d3082cada7fd1771412986c54050"
}
```

### Sample 29: `83d866a2c3640eb8`

| Field | Value |
|---|---|
| SHA-256 | `83d866a2c3640eb8edebd26b2258c52c0fc55eb583235c5756dbb75413d9155b` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.10589.15085.17293` |
| File type | `elf` |
| First seen | `2026-07-12 01:43:36` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cea20e90b6c32dd62790d6959c07c7f6` |
| SHA-1 | `d2cc75ee8b39a41f61dc9e4d4c50449203dd6c61` |
| SHA-256 | `83d866a2c3640eb8edebd26b2258c52c0fc55eb583235c5756dbb75413d9155b` |
| SHA3-384 | `4409786e4768bf9a35681095d8efb98e3afc474b1a699644d4f24e5711629714f5be7ee91d2462eee261baad98ea5497` |
| TLSH | `T18803F1953E9E4564CF105433FBBD988767FD8FAC8255D836290DC19C2C9FA80AEFA045` |
| SSDEEP | `768:Zdz8twyz76Bq7TY8bUAZz6BmUZme4DIZTvOgRHBiD0KIfTFIJXHjy9q3UELSp:ZR8twyzGM8fAZn+meSmTvvruOf2JXbLK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_83d866a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83d866a2c3640eb8edebd26b2258c52c0fc55eb583235c5756dbb75413d9155b"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.15085.17293"
    file_type = "elf"
    first_seen = "2026-07-12 01:43:36"
  condition:
    hash.sha256(0, filesize) == "83d866a2c3640eb8edebd26b2258c52c0fc55eb583235c5756dbb75413d9155b"
}
```

### Sample 30: `6f90b696fe88bfcc`

| Field | Value |
|---|---|
| SHA-256 | `6f90b696fe88bfccce71a3864cf1ca5fb68e92dd8b30e1745d2d7610ca427b11` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Linux.Siggen.13385.32702.11656` |
| File type | `elf` |
| First seen | `2026-07-12 01:43:35` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f698bcd49baf834dabab461e232bc1ae` |
| SHA-1 | `328c0b61941e07cfafba5793e0fdf80ec1bbca7f` |
| SHA-256 | `6f90b696fe88bfccce71a3864cf1ca5fb68e92dd8b30e1745d2d7610ca427b11` |
| SHA3-384 | `75599dfedbc0c5a662c2af2cb0269e6284a2045959f57a9b0ea88e226215efe0631d460c75a6ed47d0d23f10ff0056fe` |
| TLSH | `T1A852D160971CCE0BFF1575781D7E4DF17706C88C60A13E52A8C1A3D9031E8969EE6D49` |
| SSDEEP | `192:G83RaiOtxjiVYXBZPNju8wR2c9ktPF/2Ru7bjn50k8AMY4jcXMNlnHVSFyAOBO2s:tOtxjiiXBNNjuFktt/PV9cPVRBuV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_6f90b696
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f90b696fe88bfccce71a3864cf1ca5fb68e92dd8b30e1745d2d7610ca427b11"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.Siggen.13385.32702.11656"
    file_type = "elf"
    first_seen = "2026-07-12 01:43:35"
  condition:
    hash.sha256(0, filesize) == "6f90b696fe88bfccce71a3864cf1ca5fb68e92dd8b30e1745d2d7610ca427b11"
}
```

### Sample 31: `56182524f8086b40`

| Field | Value |
|---|---|
| SHA-256 | `56182524f8086b409cfb3f149690218e5b4c94d3e7fadd95062cd7fd2c125b1f` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.10589.6778.4375` |
| File type | `elf` |
| First seen | `2026-07-12 01:43:34` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `426af863c7fb972b69a3b82b2ac96e92` |
| SHA-1 | `d500ea02d62cf8282f05b5dd837ef854460d7573` |
| SHA-256 | `56182524f8086b409cfb3f149690218e5b4c94d3e7fadd95062cd7fd2c125b1f` |
| SHA3-384 | `2c1f8fab2d1967627a51fc5aa5d108861d425173fbffb36ea41dfdafc39e05fd39d1629f0a405ff90ac91c64558659d8` |
| TLSH | `T1DE43F2A0E855E929AA331FB818408E8E6D1153F5E156B976B36D0F74B067A810EF92C3` |
| SSDEEP | `1536:+cS0NqVfLRNwXetE/WxWTLHei7WG8zjP02i1:+cSsqVfNzE/WiLBx8PPI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_56182524
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56182524f8086b409cfb3f149690218e5b4c94d3e7fadd95062cd7fd2c125b1f"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.6778.4375"
    file_type = "elf"
    first_seen = "2026-07-12 01:43:34"
  condition:
    hash.sha256(0, filesize) == "56182524f8086b409cfb3f149690218e5b4c94d3e7fadd95062cd7fd2c125b1f"
}
```

### Sample 32: `3eb84b562b448b68`

| Field | Value |
|---|---|
| SHA-256 | `3eb84b562b448b6833cb2636ad8ad32370b4ed45839349d7845ff71f6dd874e7` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.10589.13407.32427` |
| File type | `elf` |
| First seen | `2026-07-12 01:43:33` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9edf7fe48853006a5fb90bc10ddb928` |
| SHA-1 | `b135231d1d7af2295169dd579b1ff819bd87c053` |
| SHA-256 | `3eb84b562b448b6833cb2636ad8ad32370b4ed45839349d7845ff71f6dd874e7` |
| SHA3-384 | `93709bd0677f48fc6702880d7713b110616aaa78c774d9a94ebbc73487d432a71dac26ebe7a28a7e90624c5ecd47fba5` |
| TLSH | `T1ABF2E0DDAB2D50CED28BD47909B013124EB60F52B046CE889DD4EBC7781A7F9264B9D4` |
| SSDEEP | `768:zmeHcYYYUEDhtv833lpy0oGBFgk6PsQdmASNQJgGlzDpbuR1JX:ae8YYYUEDhtaDFBF163mNNQVJuF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_3eb84b56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3eb84b562b448b6833cb2636ad8ad32370b4ed45839349d7845ff71f6dd874e7"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.13407.32427"
    file_type = "elf"
    first_seen = "2026-07-12 01:43:33"
  condition:
    hash.sha256(0, filesize) == "3eb84b562b448b6833cb2636ad8ad32370b4ed45839349d7845ff71f6dd874e7"
}
```

### Sample 33: `1e10e0f923b8dfd4`

| Field | Value |
|---|---|
| SHA-256 | `1e10e0f923b8dfd4097bd4aeb69f1e27ba444b6b5d88c2a0b0240c81d7dc1498` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-12 01:19:23` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01884408262c5d3133feb6c35ab61812` |
| SHA-1 | `63386381d6f09dd8c4ddd92629a78f27b63a1831` |
| SHA-256 | `1e10e0f923b8dfd4097bd4aeb69f1e27ba444b6b5d88c2a0b0240c81d7dc1498` |
| SHA3-384 | `2122cb8af7626b852bc89f95b1cd1dc2caa7cc62b22c48e785da496814d726c6c446e25d90d5626481e7c909370740a1` |
| IMPHASH | `e387f9bdbdc891a56417c52c45ed0b91` |
| TLSH | `T162B523050AE49065F6B0433D19F152A78E31BC6687AC9BEF2680B5BD4F328E1ED75B07` |
| SSDEEP | `49152:R6ZeX6oSml55Gx/KqH+Z9cy3rDZihOfnyx35sOhYVGHMGP8U:R365SM/KR3cybD7naJsOWGHM` |
| ICON-DHASH | `c0dada0010000000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_1e10e0f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e10e0f923b8dfd4097bd4aeb69f1e27ba444b6b5d88c2a0b0240c81d7dc1498"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-12 01:19:23"
  condition:
    hash.sha256(0, filesize) == "1e10e0f923b8dfd4097bd4aeb69f1e27ba444b6b5d88c2a0b0240c81d7dc1498"
}
```

### Sample 34: `47e557f9048a3cc5`

| Field | Value |
|---|---|
| SHA-256 | `47e557f9048a3cc5adb4e4611a165550aa2d087ca9d02b3cb38e285edc4440d6` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-12 01:01:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7595e0c1024f929415cc0aa459c7b37` |
| SHA-1 | `cf109c1ad86369fc1d62c8ca0445a7330a40bd18` |
| SHA-256 | `47e557f9048a3cc5adb4e4611a165550aa2d087ca9d02b3cb38e285edc4440d6` |
| SHA3-384 | `9eee81518135a95264708f912e1763a6bd74a8376f6dffb8dcded8d127cb1c1e29e30d578c57af407205633e678bee6a` |
| TLSH | `T120A42959EC409B51DAD16ABFFF1E824A73131F78F2EE72129D155B2063CB84A0E7B502` |
| TELFHASH | `t10bd0959b9750d0d445840042dccd7134097da55a55f5144d72bf3dd740533435d3bc15` |
| SSDEEP | `12288:o0jiv/CGwKMk71h4cQs4789kMnm0Lg4gRsasJ5IjPwr5Ex:oHC6bJmUm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_47e557f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47e557f9048a3cc5adb4e4611a165550aa2d087ca9d02b3cb38e285edc4440d6"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-12 01:01:28"
  condition:
    hash.sha256(0, filesize) == "47e557f9048a3cc5adb4e4611a165550aa2d087ca9d02b3cb38e285edc4440d6"
}
```

### Sample 35: `92afb5b482be852d`

| Field | Value |
|---|---|
| SHA-256 | `92afb5b482be852d9e83533fb74558fd92b6513c7fdd4a18273ad1a674148c25` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-12 01:00:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c485cba1a7ccadb6e9580f54e097668e` |
| SHA-1 | `3c491684147385c48b676efe88cbfd442c029d54` |
| SHA-256 | `92afb5b482be852d9e83533fb74558fd92b6513c7fdd4a18273ad1a674148c25` |
| SHA3-384 | `8dd587d34d215255254c462f624291cea039a2a7dadff2d78904d22b98a5ef54aa41b7fa9eb034c8fb9d59241c6ab592` |
| TLSH | `T1483423BB7E308F55B9E8846EAA5B33D2E70B93D50255208206CE47EF039E55DFC25887` |
| SSDEEP | `6144:9B+t7BEc72WBR9+fEXfCyZ9+Jxx2KbRk63xZ7lSLAR:9Y1LR9+HyZ9+Zzk6rlS6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_92afb5b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92afb5b482be852d9e83533fb74558fd92b6513c7fdd4a18273ad1a674148c25"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-12 01:00:47"
  condition:
    hash.sha256(0, filesize) == "92afb5b482be852d9e83533fb74558fd92b6513c7fdd4a18273ad1a674148c25"
}
```

### Sample 36: `afac2f3414146f23`

| Field | Value |
|---|---|
| SHA-256 | `afac2f3414146f23409b3025b08a8b396ae457e8f0ca7fb6e6fd32c2942afec7` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-12 00:52:15` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1716b064b674843322936e5e5450f7fb` |
| SHA-1 | `1a7bc9eecd62a0160ba78c7936f9a585d1f43b1e` |
| SHA-256 | `afac2f3414146f23409b3025b08a8b396ae457e8f0ca7fb6e6fd32c2942afec7` |
| SHA3-384 | `105eae36ef473f7867abc743f27bd5947623e5ff32a6f158161a157b8e9a582d442edf407cc815af6441cfdd862463a0` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F9E6335C53F815FFEDF6113DAFC15991B028B8716376CADB07D843A2AE5B2A04D3A602` |
| SSDEEP | `393216:Y0JZ9CZBaXzQEpt4aOcd1Q7TTXMCHWUjXkcuI3/PGTAI:Y+CZBaDNPO3TXMb8XxH/O7` |
| ICON-DHASH | `7071e4d6a6e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_afac2f34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afac2f3414146f23409b3025b08a8b396ae457e8f0ca7fb6e6fd32c2942afec7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-12 00:52:15"
  condition:
    hash.sha256(0, filesize) == "afac2f3414146f23409b3025b08a8b396ae457e8f0ca7fb6e6fd32c2942afec7"
}
```

### Sample 37: `f8ba9f2170d4304a`

| Field | Value |
|---|---|
| SHA-256 | `f8ba9f2170d4304a292942b3d4a635266bbf3177bbb35f3cde1dfbb96d01f9bf` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-12 00:28:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `433013aa0f51be0edbb011f07940c97c` |
| SHA-1 | `26c168dd67318a91450ac98c8d1b484fb9f3a2bb` |
| SHA-256 | `f8ba9f2170d4304a292942b3d4a635266bbf3177bbb35f3cde1dfbb96d01f9bf` |
| SHA3-384 | `1ed6f985c2a62adcb16aa270f54d979e0b4eb9156cea6f43bd5b436ee9cab5ef3b42d6d135dc2d0418f5773e2ff76c27` |
| TLSH | `T1F9336D651A857C24DA98C5361C7F2F0CB9AD43E6310492EE7FCF3CF28C5AAADA105719` |
| SSDEEP | `768:q6Utd8/s9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnB:9cK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_f8ba9f21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8ba9f2170d4304a292942b3d4a635266bbf3177bbb35f3cde1dfbb96d01f9bf"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-12 00:28:38"
  condition:
    hash.sha256(0, filesize) == "f8ba9f2170d4304a292942b3d4a635266bbf3177bbb35f3cde1dfbb96d01f9bf"
}
```

### Sample 38: `70d8a0bd68353458`

| Field | Value |
|---|---|
| SHA-256 | `70d8a0bd683534586713936af02288e65c0ebb0fae26e357757f241b691c26f3` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-07-12 00:18:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60367a80f2a2e3112e2df0a85d577b66` |
| SHA-1 | `d4e1f67f94a00aabde339604517eda87db120859` |
| SHA-256 | `70d8a0bd683534586713936af02288e65c0ebb0fae26e357757f241b691c26f3` |
| SHA3-384 | `f86d2809878a889f778c695869fd25fa9da3913b6853a6f5090d08e6c73d976f897e509a4acdf3336977d2420e5e0c7d` |
| TLSH | `T122D38EC1E743E0F5E95206F1103BA7258BB6D43BA43AEB52D7A93D32EC625508B1B35C` |
| TELFHASH | `t186511af92a7a0cec6b909811a24f5b117e4e577b382436bb05b35475327bd4182bbc39` |
| SSDEEP | `3072:hRB/BmY4ImwNkDdOEKw8wb7zBvlpMZ8/M:hRB5mYWLDfTLeZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_70d8a0bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70d8a0bd683534586713936af02288e65c0ebb0fae26e357757f241b691c26f3"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-07-12 00:18:08"
  condition:
    hash.sha256(0, filesize) == "70d8a0bd683534586713936af02288e65c0ebb0fae26e357757f241b691c26f3"
}
```

### Sample 39: `30add75b83a74e07`

| Field | Value |
|---|---|
| SHA-256 | `30add75b83a74e078a70e970d8ae2b604cac0d4a06e3e03bd61b9faeba64e5f3` |
| Family label | `unknown` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-07-11 23:52:23` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bfa77ff91405a0b1fb38457d8030ced` |
| SHA-1 | `ff4ad7b3804b0a65e52af3b5d47f5c7ffabe1e96` |
| SHA-256 | `30add75b83a74e078a70e970d8ae2b604cac0d4a06e3e03bd61b9faeba64e5f3` |
| SHA3-384 | `e3bb0db4f1d56aab39d4bd8ef0077afe5b9a5963faad37b9091f5500c6b7f819cfb452edc87241ea2ee4c48f7ca79610` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T179C54807BDA049E9C09E923199B751A67B75BC090F3223EB2E90B7782F727D09D35B50` |
| SSDEEP | `24576:tZZyVsLpgRbNQs+9S8pVcyvUmcDLfBC+CGVuuZyxYrzwckaq5vA2Bele5rK2y0HF:tZZqsdgDQ0uNVcQ+CGhcxYHwVFT84n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_30add75b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30add75b83a74e078a70e970d8ae2b604cac0d4a06e3e03bd61b9faeba64e5f3"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-11 23:52:23"
  condition:
    hash.sha256(0, filesize) == "30add75b83a74e078a70e970d8ae2b604cac0d4a06e3e03bd61b9faeba64e5f3"
}
```

### Sample 40: `b956c9732f3d5aa7`

| Field | Value |
|---|---|
| SHA-256 | `b956c9732f3d5aa72bd2b8b78e03b519fdf15d9ea3ddcd5ada2c0f158105b96c` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-11 23:52:15` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df66a72f23cb22a05bdc4ca67ed79b18` |
| SHA-1 | `71c83615c1e7128a9cd191c47331934de89a2639` |
| SHA-256 | `b956c9732f3d5aa72bd2b8b78e03b519fdf15d9ea3ddcd5ada2c0f158105b96c` |
| SHA3-384 | `eb6b7f623c2ff062aed7a65d5ada464e244d008fe1541d0a2aa28b4097cc6622bcad39f3ed89062151d53de2825b461f` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1CAE6339CAAF012EFD963013DBEF296A6A479F4324B30C5574734C3A52E471E0A839D67` |
| SSDEEP | `393216:mwrmoxMfmr7dt65IiX4XMCHWUjX7cuI3/PGTAI:mONxM+dt6qXMb8X4H/O7` |
| ICON-DHASH | `71f0d4d8c8ecf070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_b956c973
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b956c9732f3d5aa72bd2b8b78e03b519fdf15d9ea3ddcd5ada2c0f158105b96c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 23:52:15"
  condition:
    hash.sha256(0, filesize) == "b956c9732f3d5aa72bd2b8b78e03b519fdf15d9ea3ddcd5ada2c0f158105b96c"
}
```

### Sample 41: `c8a2d4ff2c12a7f0`

| Field | Value |
|---|---|
| SHA-256 | `c8a2d4ff2c12a7f081244dfa55a14bc7b0a4e029afd96fa06111c21eaf44c096` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-11 23:48:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `312d795dc8b1af6956c9217c9e7f0285` |
| SHA-1 | `222807af34580411589863ef424ce7c16ee0882a` |
| SHA-256 | `c8a2d4ff2c12a7f081244dfa55a14bc7b0a4e029afd96fa06111c21eaf44c096` |
| SHA3-384 | `5187714698b0eb801107976efec7019ddd05c39fe39cb7f8e02edd29a312d78ecbfa8960da27c7c05462fc305221af24` |
| TLSH | `T178C27D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:Z8vCB+25j6es8R+9FYpMSUpi+20qUpi+20YQX:Z8l25JYd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_c8a2d4ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8a2d4ff2c12a7f081244dfa55a14bc7b0a4e029afd96fa06111c21eaf44c096"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-11 23:48:48"
  condition:
    hash.sha256(0, filesize) == "c8a2d4ff2c12a7f081244dfa55a14bc7b0a4e029afd96fa06111c21eaf44c096"
}
```

### Sample 42: `d95c3b7ae4b91b28`

| Field | Value |
|---|---|
| SHA-256 | `d95c3b7ae4b91b28b942f8a150f0da86a0c5c19641933a3edb80800aab67775b` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-11 23:40:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0f54f4f794bdaf3535b13358894c8e8` |
| SHA-1 | `7ab417e614dedabefb9020be1418459392db80ba` |
| SHA-256 | `d95c3b7ae4b91b28b942f8a150f0da86a0c5c19641933a3edb80800aab67775b` |
| SHA3-384 | `5ce368880888cdf8d78c62037e49701b0b558cf3bc3677f6de1efbdaff8ee2766c515d0223bf8031808170bbb7ce630f` |
| TLSH | `T123C28D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:B8vCB+25j6es8Rt9FYpMSUpi+20qUpi+20YQX:B8l25Jbd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_d95c3b7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d95c3b7ae4b91b28b942f8a150f0da86a0c5c19641933a3edb80800aab67775b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-11 23:40:50"
  condition:
    hash.sha256(0, filesize) == "d95c3b7ae4b91b28b942f8a150f0da86a0c5c19641933a3edb80800aab67775b"
}
```

### Sample 43: `d5d7ba7df2e3e909`

| Field | Value |
|---|---|
| SHA-256 | `d5d7ba7df2e3e90930879859614cdebacce22236a1d6d15486a8187b63f81082` |
| Family label | `Mirai` |
| File name | `bot_x86_64` |
| File type | `elf` |
| First seen | `2026-07-11 23:34:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a278828bcedac955a99034f5ab16dc3` |
| SHA-1 | `62bc6551a3814ff1aa4741dc36d1245fdd82fe01` |
| SHA-256 | `d5d7ba7df2e3e90930879859614cdebacce22236a1d6d15486a8187b63f81082` |
| SHA3-384 | `a3e1d2de7672f624f1719e167e8bbae2d8bb5d36a10900be390eeeac7bd91f59b610af80726fe5b038ad4d06e6703e25` |
| TLSH | `T163456B47B2B364FDC093C43087DBD6A2A931B42546226E7F65C4CB312FA7E641B1DB62` |
| TELFHASH | `t1ac2141e7543da4a04adeac80e59b2724e10ff19458b10a23fca0c65c72fe61f49674eb` |
| SSDEEP | `24576:NLHe+4krUyvQb9xcundjFLQgg2H0RKYYVBd9qvB/eH:NL++4krUj1jiT2HpYid9qkH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_d5d7ba7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5d7ba7df2e3e90930879859614cdebacce22236a1d6d15486a8187b63f81082"
    family = "Mirai"
    file_name = "bot_x86_64"
    file_type = "elf"
    first_seen = "2026-07-11 23:34:51"
  condition:
    hash.sha256(0, filesize) == "d5d7ba7df2e3e90930879859614cdebacce22236a1d6d15486a8187b63f81082"
}
```

### Sample 44: `889f8101436dbf4c`

| Field | Value |
|---|---|
| SHA-256 | `889f8101436dbf4c3d7bf4a8ed9c399bbacedaaf0c64c731eeebcd2cee6f435b` |
| Family label | `Mirai` |
| File name | `nz.sh` |
| File type | `sh` |
| First seen | `2026-07-11 23:31:13` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ac8b3af4ea3ffcc3bdca85467468bd9` |
| SHA-1 | `0f1419d47ddb5bfa187a753d49b6261aafeaaa8a` |
| SHA-256 | `889f8101436dbf4c3d7bf4a8ed9c399bbacedaaf0c64c731eeebcd2cee6f435b` |
| SHA3-384 | `25cebea3537d14a5b87b67eabb2d3817119c11cf21969a86b02b69cd7e9bd8a0303ab28274af918fc44a5ff50638c79c` |
| TLSH | `T1A95191C7510517312EB2DDA6BBBB886D30D0D1AB64C7FFA6A4D8BCA4428DD0C7C4265B` |
| SSDEEP | `48:iJv5J+YEJ993J6PJILJcLJiTKiTGFlJXZJkvLJZ7JJmTrJITJlhTJrjVJcwV:iHA9EeacxazPwLVAClDTV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_889f8101
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889f8101436dbf4c3d7bf4a8ed9c399bbacedaaf0c64c731eeebcd2cee6f435b"
    family = "Mirai"
    file_name = "nz.sh"
    file_type = "sh"
    first_seen = "2026-07-11 23:31:13"
  condition:
    hash.sha256(0, filesize) == "889f8101436dbf4c3d7bf4a8ed9c399bbacedaaf0c64c731eeebcd2cee6f435b"
}
```

### Sample 45: `94d90962079506e9`

| Field | Value |
|---|---|
| SHA-256 | `94d90962079506e9c9d6661c69ecdf56fb0e16a7a2282d271942e2c7a165ffe7` |
| Family label | `unknown` |
| File name | `wwg` |
| File type | `sh` |
| First seen | `2026-07-11 23:26:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `999699df7def173805f54e4b773acb21` |
| SHA-1 | `8932db97a663ce30020981dff0cf52b617eacc3d` |
| SHA-256 | `94d90962079506e9c9d6661c69ecdf56fb0e16a7a2282d271942e2c7a165ffe7` |
| SHA3-384 | `1e34db81e5a7b22507cf44b9cf5f4ba6325a96ac51553d965f7d23a12f720bde3da3aba5bbea97d53a83fe3272d833c5` |
| TLSH | `T142E01265D7DA186B84BF5AC4B4730908F701E173BE154B1C3B8295A1CA74225746D554` |
| SSDEEP | `6:ho2VLnSDNe3EeiNcAPovH6UFxcFs7smI9//P6Q//D7B/+bZJbKXFs7Yjs:NtKNcAPovH6KGTsJbKKEjs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_94d90962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94d90962079506e9c9d6661c69ecdf56fb0e16a7a2282d271942e2c7a165ffe7"
    family = "unknown"
    file_name = "wwg"
    file_type = "sh"
    first_seen = "2026-07-11 23:26:59"
  condition:
    hash.sha256(0, filesize) == "94d90962079506e9c9d6661c69ecdf56fb0e16a7a2282d271942e2c7a165ffe7"
}
```

### Sample 46: `aa43f85f89297eb6`

| Field | Value |
|---|---|
| SHA-256 | `aa43f85f89297eb67a66198cb9d16373a9edbbc93503be45674d44ac8149c27a` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-11 23:12:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7ec7541e757a9de64891c917d9b00a4` |
| SHA-1 | `ad09b2918b5c44ff381ee96dcfef6378f9871eb6` |
| SHA-256 | `aa43f85f89297eb67a66198cb9d16373a9edbbc93503be45674d44ac8149c27a` |
| SHA3-384 | `50a628a474dbc7bdd0f2cc2758e2dd0e8ee73db73e00bdeec9aaccc225078baf6a061aa6de33e0ddcc05d9243f543ae5` |
| TLSH | `T11BC27D966A967C44BDC94A3E4CBD2B0D6DF5C3D1324942AC3D8A3C71DC11F9CD618B1A` |
| SSDEEP | `768:E8vCB+25j6es8RK9FYpMSUpi+20qUpi+20YQX:E8l25J8d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_aa43f85f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa43f85f89297eb67a66198cb9d16373a9edbbc93503be45674d44ac8149c27a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-11 23:12:44"
  condition:
    hash.sha256(0, filesize) == "aa43f85f89297eb67a66198cb9d16373a9edbbc93503be45674d44ac8149c27a"
}
```

### Sample 47: `5bdcf2d4fd8a65c1`

| Field | Value |
|---|---|
| SHA-256 | `5bdcf2d4fd8a65c17237d4808e2b613deb0f54de1b90839f1f8e450d8b2acc19` |
| Family label | `unknown` |
| File name | `Drv_ceo_12.8.1.exe` |
| File type | `exe` |
| First seen | `2026-07-11 23:05:23` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa246c59edb665b82b92e0788a41337f` |
| SHA-1 | `1ebf85b32bffb858911ea65289cdbcf4ca3bc304` |
| SHA-256 | `5bdcf2d4fd8a65c17237d4808e2b613deb0f54de1b90839f1f8e450d8b2acc19` |
| SHA3-384 | `7ac278e3eb881a25fbce5a6273543b33d9cbd3bc806b99998a8982adb335251150a4e9501f1bdaaf71f9e149786ca54f` |
| IMPHASH | `94184592e4150dd6cb6610037032ac80` |
| TLSH | `T1C847338023F00398F473F770CEB24B67E6BA7858FA62D74D9681254F1E3A6519990F26` |
| SSDEEP | `393216:dLAmLbNyS3QBin05X2NXehAJ1q8pQ9bwXxxcyOQr2YUfg3Acdf65bThCfRYsWlul:9A+bP3dgX2NuGLQ8+y4kAciBC` |
| ICON-DHASH | `f1d93f9de4c4e1b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_5bdcf2d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bdcf2d4fd8a65c17237d4808e2b613deb0f54de1b90839f1f8e450d8b2acc19"
    family = "unknown"
    file_name = "Drv_ceo_12.8.1.exe"
    file_type = "exe"
    first_seen = "2026-07-11 23:05:23"
  condition:
    hash.sha256(0, filesize) == "5bdcf2d4fd8a65c17237d4808e2b613deb0f54de1b90839f1f8e450d8b2acc19"
}
```

### Sample 48: `0e4931df7ea30255`

| Field | Value |
|---|---|
| SHA-256 | `0e4931df7ea30255b2820e6bd65b43477897c5c20b0d1ba34fd16b4063d92ebd` |
| Family label | `unknown` |
| File name | `app_setup.6653008.msi` |
| File type | `msi` |
| First seen | `2026-07-11 23:01:38` |
| Reporter | `CNGaoLing` |
| Tags | `msi, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05ad15b0439fd395d7228fe76fc986af` |
| SHA-1 | `1dd7b107e45ad76c1e1d9d1f0ae641a197255b7f` |
| SHA-256 | `0e4931df7ea30255b2820e6bd65b43477897c5c20b0d1ba34fd16b4063d92ebd` |
| SHA3-384 | `58c0b04cf01546868026a6b9b6a243e3aa1297471884d3d6afa769854091af6d5230025c841416aabadfcb94fe0e8bf7` |
| TLSH | `T17DA63391B6CB0570C01BC7B4964A927E702C3FD51FA00D266BD8BF489F73A642E776A1` |
| SSDEEP | `196608:iEXfU34m3qRRF+vyt9WGcRNtCKmyLOS+GKe3nGVaOR4OLqgY5fV:iEXfpL3F+vy2RCK+S+GKPVaa4OLqgu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_0e4931df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e4931df7ea30255b2820e6bd65b43477897c5c20b0d1ba34fd16b4063d92ebd"
    family = "unknown"
    file_name = "app_setup.6653008.msi"
    file_type = "msi"
    first_seen = "2026-07-11 23:01:38"
  condition:
    hash.sha256(0, filesize) == "0e4931df7ea30255b2820e6bd65b43477897c5c20b0d1ba34fd16b4063d92ebd"
}
```

### Sample 49: `7279052dbfd3f10c`

| Field | Value |
|---|---|
| SHA-256 | `7279052dbfd3f10ce49890a529d3595b052507cca7df6438e0e6ad8ec7bd8239` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-11 22:52:15` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47639143ecb3cb35697d04ca098110cc` |
| SHA-1 | `2983defb1af6bf39a029556ce0e3f1c634b57011` |
| SHA-256 | `7279052dbfd3f10ce49890a529d3595b052507cca7df6438e0e6ad8ec7bd8239` |
| SHA3-384 | `82a7f624480fc1ff6391747a59993b529f2a063fa7a55e2565d461f5b95b17294e61a892f6aaee164c3fa433c919dbbe` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T112E63304A9E041B9E9A3013DDDF12655E3B4B87107B3C5CB4B6C53A66C7B2F18D3AA27` |
| SSDEEP | `393216:9gvUbVywBmDC/1BpN1KAXMCHWUjXzcuI3/PGTAI:9gW7B6MpNcAXMb8XwH/O7` |
| ICON-DHASH | `f0d89ea29ac6e4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_7279052d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7279052dbfd3f10ce49890a529d3595b052507cca7df6438e0e6ad8ec7bd8239"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 22:52:15"
  condition:
    hash.sha256(0, filesize) == "7279052dbfd3f10ce49890a529d3595b052507cca7df6438e0e6ad8ec7bd8239"
}
```

### Sample 50: `6d1aadf48d83beb7`

| Field | Value |
|---|---|
| SHA-256 | `6d1aadf48d83beb7dafe4bf7160c5ebb1c4b8b5a43d81ea4823e31c57a798ea6` |
| Family label | `unknown` |
| File name | `mcrypt_payload.bin` |
| File type | `unknown` |
| First seen | `2026-07-11 22:34:53` |
| Reporter | `anonymous` |
| Tags | `dudu, encrypted, silo` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c9a313ad5a71252a9478872af907a9d` |
| SHA-256 | `6d1aadf48d83beb7dafe4bf7160c5ebb1c4b8b5a43d81ea4823e31c57a798ea6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_6d1aadf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d1aadf48d83beb7dafe4bf7160c5ebb1c4b8b5a43d81ea4823e31c57a798ea6"
    family = "unknown"
    file_name = "mcrypt_payload.bin"
    file_type = "unknown"
    first_seen = "2026-07-11 22:34:53"
  condition:
    hash.sha256(0, filesize) == "6d1aadf48d83beb7dafe4bf7160c5ebb1c4b8b5a43d81ea4823e31c57a798ea6"
}
```

### Sample 51: `939614ca17f25bf3`

| Field | Value |
|---|---|
| SHA-256 | `939614ca17f25bf319a2e14e349add40d753a529e6b21d1243b887cf4b65aaae` |
| Family label | `unknown` |
| File name | `gz_2085.gz` |
| File type | `gz` |
| First seen | `2026-07-11 22:34:45` |
| Reporter | `anonymous` |
| Tags | `dude, gz, loader, silo` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77cd8cf953b147e974b1fe3b093385d7` |
| SHA-1 | `834dd32cecfc5f7bb5209aedb7954cd7891c9bfe` |
| SHA-256 | `939614ca17f25bf319a2e14e349add40d753a529e6b21d1243b887cf4b65aaae` |
| SHA3-384 | `f34f270c715661f3969048dc55f724d69fef22ec1cf3bfcefbd266a53a37cf55f3feab625ea4d6cb47251accc3e1d4e4` |
| TLSH | `T1292523EC32346456FE984ABE9B937F204DE4F2C1BB6E46E2574E35300CCD6A686451CE` |
| SSDEEP | `24576:GM5UD5IhEyEzHUJklZ4LvOwsPxEjmLqH+PEEGssmk2L1:GMWVIuy+H8DhsPxvmTvsLj1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_939614ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "939614ca17f25bf319a2e14e349add40d753a529e6b21d1243b887cf4b65aaae"
    family = "unknown"
    file_name = "gz_2085.gz"
    file_type = "gz"
    first_seen = "2026-07-11 22:34:45"
  condition:
    hash.sha256(0, filesize) == "939614ca17f25bf319a2e14e349add40d753a529e6b21d1243b887cf4b65aaae"
}
```

### Sample 52: `431f16e6453e3c9b`

| Field | Value |
|---|---|
| SHA-256 | `431f16e6453e3c9b1dfe663b9da917ba0fa8a20c6ba3f0cd834d093f6a1a416f` |
| Family label | `unknown` |
| File name | `gz_2079.gz` |
| File type | `gz` |
| First seen | `2026-07-11 22:34:37` |
| Reporter | `anonymous` |
| Tags | `dude, gz, loader, silo` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33d6e9f4c40987b751720173745df9e3` |
| SHA-256 | `431f16e6453e3c9b1dfe663b9da917ba0fa8a20c6ba3f0cd834d093f6a1a416f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_431f16e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "431f16e6453e3c9b1dfe663b9da917ba0fa8a20c6ba3f0cd834d093f6a1a416f"
    family = "unknown"
    file_name = "gz_2079.gz"
    file_type = "gz"
    first_seen = "2026-07-11 22:34:37"
  condition:
    hash.sha256(0, filesize) == "431f16e6453e3c9b1dfe663b9da917ba0fa8a20c6ba3f0cd834d093f6a1a416f"
}
```

### Sample 53: `44210eecc61cae50`

| Field | Value |
|---|---|
| SHA-256 | `44210eecc61cae505249b012ce0a84af436442f4ee4b73b66b69ce3c14ef3498` |
| Family label | `unknown` |
| File name | `gz_2046.gz` |
| File type | `gz` |
| First seen | `2026-07-11 22:34:27` |
| Reporter | `anonymous` |
| Tags | `dudu, gz, loader, silo, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8eb352778696c076074157adc1e94bbd` |
| SHA-256 | `44210eecc61cae505249b012ce0a84af436442f4ee4b73b66b69ce3c14ef3498` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_44210eec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44210eecc61cae505249b012ce0a84af436442f4ee4b73b66b69ce3c14ef3498"
    family = "unknown"
    file_name = "gz_2046.gz"
    file_type = "gz"
    first_seen = "2026-07-11 22:34:27"
  condition:
    hash.sha256(0, filesize) == "44210eecc61cae505249b012ce0a84af436442f4ee4b73b66b69ce3c14ef3498"
}
```

### Sample 54: `2b9c0d3b76eb1bbc`

| Field | Value |
|---|---|
| SHA-256 | `2b9c0d3b76eb1bbc348d233199ef24a54f74a1fb965072e95c2f645501d7e50e` |
| Family label | `unknown` |
| File name | `screnc_raw.bin` |
| File type | `unknown` |
| First seen | `2026-07-11 22:34:12` |
| Reporter | `anonymous` |
| Tags | `dudu, loader, silo, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a2b70352630a7f62afdd67109df2e70` |
| SHA-256 | `2b9c0d3b76eb1bbc348d233199ef24a54f74a1fb965072e95c2f645501d7e50e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_2b9c0d3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b9c0d3b76eb1bbc348d233199ef24a54f74a1fb965072e95c2f645501d7e50e"
    family = "unknown"
    file_name = "screnc_raw.bin"
    file_type = "unknown"
    first_seen = "2026-07-11 22:34:12"
  condition:
    hash.sha256(0, filesize) == "2b9c0d3b76eb1bbc348d233199ef24a54f74a1fb965072e95c2f645501d7e50e"
}
```

### Sample 55: `963f836a69b3e3e0`

| Field | Value |
|---|---|
| SHA-256 | `963f836a69b3e3e02dcf177e0d34cf7fc37fa323f3f0011aac40dbbc9c06094c` |
| Family label | `Socks5Systemz` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-11 22:24:38` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, Socks5Systemz, UNIQTWO.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b64cd8edd663a35111041d1aad54c9e` |
| SHA-1 | `5bd1df7712f99aeafdbec0d9fa154abf4f0af188` |
| SHA-256 | `963f836a69b3e3e02dcf177e0d34cf7fc37fa323f3f0011aac40dbbc9c06094c` |
| SHA3-384 | `afe028fd9d28c2bb829524d57a3a305a21eb60544ee4530347f079f807491a3a24da6e39c5a56128283caf7b3decb1da` |
| IMPHASH | `884310b1928934402ea6fec1dbd3cf5e` |
| TLSH | `T14006331293894E35E3B19FF1CFA35BA98713331532B612157896EC0B2E4AD51A01BFE7` |
| SSDEEP | `98304:NnXpBJzjOtbPr9NWIuz7g5URuUohsDxTekHOtfdjhKqdQ6:FS90IuPZEwHOVdjd` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `Socks5Systemz` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Socks5Systemz_055_963f836a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "963f836a69b3e3e02dcf177e0d34cf7fc37fa323f3f0011aac40dbbc9c06094c"
    family = "Socks5Systemz"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-11 22:24:38"
  condition:
    hash.sha256(0, filesize) == "963f836a69b3e3e02dcf177e0d34cf7fc37fa323f3f0011aac40dbbc9c06094c"
}
```

### Sample 56: `c47be75ba9204ee9`

| Field | Value |
|---|---|
| SHA-256 | `c47be75ba9204ee9cc3d812bde65145e09a13a389bcce8cc15171aa4c04d1a4f` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-11 21:52:13` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2e958826bd6e14b123ea5fe4f55fc74` |
| SHA-1 | `0b91d2a4a872fe800002285b813ad8f981eb6c8e` |
| SHA-256 | `c47be75ba9204ee9cc3d812bde65145e09a13a389bcce8cc15171aa4c04d1a4f` |
| SHA3-384 | `e3692c774c3c70a603d20f6a7845cbb2e27dd1faf698e03a315497f35d50d8943b016d8473da0425a02bc88f062bf485` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1BEE6334485E001BDEBF3407DEAB165A4E5E9B8730771CADF57988366BE231E00A39B53` |
| SSDEEP | `393216:khqy3uPvYedF3FZq0Uytt6lfjfXMCHWUjXCcuI3/PGTAI:kX3uPvYedVZUyt6BjfXMb8X/H/O7` |
| ICON-DHASH | `54f1f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_c47be75b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c47be75ba9204ee9cc3d812bde65145e09a13a389bcce8cc15171aa4c04d1a4f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 21:52:13"
  condition:
    hash.sha256(0, filesize) == "c47be75ba9204ee9cc3d812bde65145e09a13a389bcce8cc15171aa4c04d1a4f"
}
```

### Sample 57: `a4a332b84be4855c`

| Field | Value |
|---|---|
| SHA-256 | `a4a332b84be4855c71f6fec63b61e9b3703082b25547002140bc66e082e817e3` |
| Family label | `Mirai` |
| File name | `a4a332b84be4855c71f6fec63b61e9b3703082b25547002140bc66e082e817e3` |
| File type | `elf` |
| First seen | `2026-07-11 21:37:25` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bec742f1a98e38d189e7a39c48430012` |
| SHA-1 | `d7affa513f61beefc546324dbc817b561d554ad2` |
| SHA-256 | `a4a332b84be4855c71f6fec63b61e9b3703082b25547002140bc66e082e817e3` |
| SHA3-384 | `2e10e95a1a0c67586b42bbfd754853fbaf12180a9a1761d7eee8b53d72f1e16d7ba5b8796a99c01cbeceda2d381f4d64` |
| TLSH | `T1D4A2D0409E9043D6CDC4BCBA1E8C6731E2BAAB80BEA6D43143D5C1A9D776D51DE32254` |
| SSDEEP | `384:GaiAgXHo4zkejSudOylMns6PmUipfaES8TR057HUkOeZHoc4wLO:GfI4zlmuIruFUZ+47HU49oc+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_a4a332b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4a332b84be4855c71f6fec63b61e9b3703082b25547002140bc66e082e817e3"
    family = "Mirai"
    file_name = "a4a332b84be4855c71f6fec63b61e9b3703082b25547002140bc66e082e817e3"
    file_type = "elf"
    first_seen = "2026-07-11 21:37:25"
  condition:
    hash.sha256(0, filesize) == "a4a332b84be4855c71f6fec63b61e9b3703082b25547002140bc66e082e817e3"
}
```

### Sample 58: `6e95d3011ecc51a7`

| Field | Value |
|---|---|
| SHA-256 | `6e95d3011ecc51a72fec8b2a8e5b06b4e134c2b2cfe513bfce42d9029c6c8dd1` |
| Family label | `unknown` |
| File name | `6e95d3011ecc51a72fec8b2a8e5b06b4e134c2b2cfe513bfce42d9029c6c8dd1` |
| File type | `unknown` |
| First seen | `2026-07-11 21:30:11` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb1be3f5478c6751f0de6e9128fecbf2` |
| SHA-256 | `6e95d3011ecc51a72fec8b2a8e5b06b4e134c2b2cfe513bfce42d9029c6c8dd1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_6e95d301
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e95d3011ecc51a72fec8b2a8e5b06b4e134c2b2cfe513bfce42d9029c6c8dd1"
    family = "unknown"
    file_name = "6e95d3011ecc51a72fec8b2a8e5b06b4e134c2b2cfe513bfce42d9029c6c8dd1"
    file_type = "unknown"
    first_seen = "2026-07-11 21:30:11"
  condition:
    hash.sha256(0, filesize) == "6e95d3011ecc51a72fec8b2a8e5b06b4e134c2b2cfe513bfce42d9029c6c8dd1"
}
```

### Sample 59: `915a6f0c68ae8695`

| Field | Value |
|---|---|
| SHA-256 | `915a6f0c68ae869517620fc7c756c551378e4bde11c5f8adb80a0dc40515fb9e` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-11 20:52:21` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7fd5ab5abbe24e0337e5c6317f1a17a` |
| SHA-1 | `182eca8129b8b19e17d49b9a7cdf002412c2becf` |
| SHA-256 | `915a6f0c68ae869517620fc7c756c551378e4bde11c5f8adb80a0dc40515fb9e` |
| SHA3-384 | `8a54e1366556e1c7c9872e693a22cdc66198e48439cdfe89c737fbf0f4a499303e738e4209dae73fe84c05607b66938c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T175E633481AF022EEE5B39078DAE4A451E7BD70750B32C9CB2368C6B59E175D04E3DB63` |
| SSDEEP | `393216:+UupF/hkaIZdNmybxBSubUPDtwXMCHWUjXNcuI3/PGTAI:+U8ItmylFU+XMb8X6H/O7` |
| ICON-DHASH | `f0f8dc8682c4f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_915a6f0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "915a6f0c68ae869517620fc7c756c551378e4bde11c5f8adb80a0dc40515fb9e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 20:52:21"
  condition:
    hash.sha256(0, filesize) == "915a6f0c68ae869517620fc7c756c551378e4bde11c5f8adb80a0dc40515fb9e"
}
```

### Sample 60: `3e1f434c282f58b8`

| Field | Value |
|---|---|
| SHA-256 | `3e1f434c282f58b8da8d8c4067adf9b90ffc407a5962fb97fe0172e25e5810b9` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-11 19:52:13` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21eb0e8ba5e3013302e924966f1c0973` |
| SHA-1 | `202e1e61f6d5b9f0574b88f627502c811b01ea1f` |
| SHA-256 | `3e1f434c282f58b8da8d8c4067adf9b90ffc407a5962fb97fe0172e25e5810b9` |
| SHA3-384 | `fa56c93a42620362976e892101c541cb3e05002124669f6dc032ad39168884899fa3959f22d2b5c1de073491773e472f` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T19AE6330469E022EEC663463C6EF145D6E4A9F0764B75C5DF8FA483666D232E08D3DB0B` |
| SSDEEP | `393216:erMlr9JekuokbYO8tj+X0aDhnXMCHWUjXkcuI3/PGTAI:eryrubEtjSNNnXMb8XxH/O7` |
| ICON-DHASH | `5479d0f0e0e870b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_3e1f434c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e1f434c282f58b8da8d8c4067adf9b90ffc407a5962fb97fe0172e25e5810b9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 19:52:13"
  condition:
    hash.sha256(0, filesize) == "3e1f434c282f58b8da8d8c4067adf9b90ffc407a5962fb97fe0172e25e5810b9"
}
```

### Sample 61: `12ec85335eb93017`

| Field | Value |
|---|---|
| SHA-256 | `12ec85335eb93017704668019ec603db69d3703573301278e195f904872032bc` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-11 19:13:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `631fed927ce34aae17569b0238d9f51f` |
| SHA-1 | `defd375d4aa7c3e705f9bc5b315e3271b9122b52` |
| SHA-256 | `12ec85335eb93017704668019ec603db69d3703573301278e195f904872032bc` |
| SHA3-384 | `4046c57f5a0094b728621df91572c55d358e5594b5c3d862311f91a240ddb7567f674611d5954cb99e1e6f129e20cfca` |
| TLSH | `T1DEE42D0BAF540EFBD82FCD3705A91A0635CCA58732A677363538DE14BA5A50A89D3C7C` |
| SSDEEP | `12288:yZ97saPL1A1k4AD0BA9MCS4HwnIBR6iu:yIaPBA64QuAMCSowIBoZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_12ec8533
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12ec85335eb93017704668019ec603db69d3703573301278e195f904872032bc"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-11 19:13:34"
  condition:
    hash.sha256(0, filesize) == "12ec85335eb93017704668019ec603db69d3703573301278e195f904872032bc"
}
```

### Sample 62: `1dd0d38cd124cc17`

| Field | Value |
|---|---|
| SHA-256 | `1dd0d38cd124cc1704d8d73d35752d3784892a88aa087e10d544782cdf232b47` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-11 19:12:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf138eaeef51de564f7c97c960ca8810` |
| SHA-1 | `8904a1c1a2459d99d9f30a0823a3a252fd9ecf08` |
| SHA-256 | `1dd0d38cd124cc1704d8d73d35752d3784892a88aa087e10d544782cdf232b47` |
| SHA3-384 | `ee1d00675ffc71858394e574951cc7f8d9fa935426deecba6e24b21808ea3701d0d5cb7dee68d94a1165fd01a76f2a63` |
| TLSH | `T171542334C83732B4D4D3EAF54E4EAB739E9845759BFB4190476C86D250BE18CABD2328` |
| SSDEEP | `6144:3ormJZ4ENvZTmAg97ss9LiJQCtRpk5D8L74PUH:3Dp2AcN9WrYY74Pk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_1dd0d38c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dd0d38cd124cc1704d8d73d35752d3784892a88aa087e10d544782cdf232b47"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-11 19:12:41"
  condition:
    hash.sha256(0, filesize) == "1dd0d38cd124cc1704d8d73d35752d3784892a88aa087e10d544782cdf232b47"
}
```

### Sample 63: `b81ba14cb5fd16df`

| Field | Value |
|---|---|
| SHA-256 | `b81ba14cb5fd16dfaaebc558de473723619700ec04292d3bad98df88d0876f2f` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-11 19:12:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a378b43ee28bc268254b34d712d18468` |
| SHA-1 | `7e5ac61d1f9bafb1fe5a300df70c67d7500ab94f` |
| SHA-256 | `b81ba14cb5fd16dfaaebc558de473723619700ec04292d3bad98df88d0876f2f` |
| SHA3-384 | `f656f300562143cfb5de02c98122bdf91bf198cc1f8e77b2cd6a4d5a98e898dd11da8cca1db24ba35e91d4b4aeb41bc5` |
| TLSH | `T1ECB43A51FC419BA7C6D12ABBFF6D828C732317B8E2DE71129D155B2063CB85A0E7B142` |
| TELFHASH | `t14fd097e32ba800f022708b87c1bf5e201fb3603ac9507bf939ca6c1216832238813d31` |
| SSDEEP | `12288:iWKjbFJJV28UZeDf6omE4ipfhRyhHDXzOv4rGfqe:iJj/kO6IT6/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_b81ba14c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b81ba14cb5fd16dfaaebc558de473723619700ec04292d3bad98df88d0876f2f"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-11 19:12:40"
  condition:
    hash.sha256(0, filesize) == "b81ba14cb5fd16dfaaebc558de473723619700ec04292d3bad98df88d0876f2f"
}
```

### Sample 64: `7ef83c3a3c06f079`

| Field | Value |
|---|---|
| SHA-256 | `7ef83c3a3c06f079a710e0b62181231ef5961aa9c64e8c8951ba2883c139ee65` |
| Family label | `Mirai` |
| File name | `tplink.sh` |
| File type | `sh` |
| First seen | `2026-07-11 19:07:00` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a3bc6fc6c8f1b206ca9488387aaf80b` |
| SHA-1 | `edbc6dd028710a78fd5dd6117b016a6ca05e052e` |
| SHA-256 | `7ef83c3a3c06f079a710e0b62181231ef5961aa9c64e8c8951ba2883c139ee65` |
| SHA3-384 | `f86dddad1461c45fb68188fb18f32aea38f76dbfd3124ec934f6354b9bb41fba3a1d9b7e67fd557831c60cb833552f4b` |
| TLSH | `T12621F8EC2C992E1A0F22CD40F07261AAE15FEBC872D23B1FED5A757068D85107120BC5` |
| SSDEEP | `24:QvQhBh9M0oyCxjeqxUNRxKx6iJx6KdxWrxLFIxje9xUNsxdx6ikx6KwxWOxLF8:QvQhnog9iyc9i5O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_7ef83c3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ef83c3a3c06f079a710e0b62181231ef5961aa9c64e8c8951ba2883c139ee65"
    family = "Mirai"
    file_name = "tplink.sh"
    file_type = "sh"
    first_seen = "2026-07-11 19:07:00"
  condition:
    hash.sha256(0, filesize) == "7ef83c3a3c06f079a710e0b62181231ef5961aa9c64e8c8951ba2883c139ee65"
}
```

### Sample 65: `edd51919f84f00e2`

| Field | Value |
|---|---|
| SHA-256 | `edd51919f84f00e29342b8a5698a7288845efbf2e57ea712cf4dc902456134f3` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-11 18:52:14` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2d3a1ec2597e6910bb52ddbd707e549` |
| SHA-1 | `3617049a013b859b7b621a611f83e61362507c1f` |
| SHA-256 | `edd51919f84f00e29342b8a5698a7288845efbf2e57ea712cf4dc902456134f3` |
| SHA3-384 | `b5914159688e43f3c8b068fd5e2e6e0734aef213c47efce57f0c45c74ac1777ba3162bc22346f4ce8405d3c5f16b19e9` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1A0E6335869E001FAE973403DEFF09B89E179B4631B71C9AF5BA08767AC132914C39637` |
| SSDEEP | `393216:hzpRTwsiIJMp75wPHGFQRezFdlhXMCHWUjXXcuI3/PGTAI:hzXT7JMx5gIzTXMb8XsH/O7` |
| ICON-DHASH | `7071e4d6a6e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_edd51919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edd51919f84f00e29342b8a5698a7288845efbf2e57ea712cf4dc902456134f3"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 18:52:14"
  condition:
    hash.sha256(0, filesize) == "edd51919f84f00e29342b8a5698a7288845efbf2e57ea712cf4dc902456134f3"
}
```

### Sample 66: `a7475b46ac26987a`

| Field | Value |
|---|---|
| SHA-256 | `a7475b46ac26987a5d9a6c7aca0cbae6ce2559ac0d4957743f38ce9ef70e4f72` |
| Family label | `NetSupport` |
| File name | `0ae0f719d08a68c58763c89c332ebbc1.exe` |
| File type | `exe` |
| First seen | `2026-07-11 18:45:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, NetSupport` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ae0f719d08a68c58763c89c332ebbc1` |
| SHA-1 | `8a0b0fc342dc1aac244262e34eac2deddf75bd97` |
| SHA-256 | `a7475b46ac26987a5d9a6c7aca0cbae6ce2559ac0d4957743f38ce9ef70e4f72` |
| SHA3-384 | `1206311d0f5ed98a57c0f3e128ab6ec754c585529d066207ad36b65fc6fd9175bc7dc5c2158b882ae55159de4f2c59d5` |
| IMPHASH | `4eab2188a80a18b3611bd2581bbcb919` |
| TLSH | `T110363303F1BAE0F6D953D0B995E8B3B5E212F4016D02CBFE2850D5792C6AD42ADF4B46` |
| SSDEEP | `98304:RfY587MugUTvEQaLhaVmwUry3GeMAUo/IA1krH0M4DPGNVZq:RAq71gUTvwImwsy3rUo99INVM` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_066_a7475b46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7475b46ac26987a5d9a6c7aca0cbae6ce2559ac0d4957743f38ce9ef70e4f72"
    family = "NetSupport"
    file_name = "0ae0f719d08a68c58763c89c332ebbc1.exe"
    file_type = "exe"
    first_seen = "2026-07-11 18:45:09"
  condition:
    hash.sha256(0, filesize) == "a7475b46ac26987a5d9a6c7aca0cbae6ce2559ac0d4957743f38ce9ef70e4f72"
}
```

### Sample 67: `8b35bc886f3c46af`

| Field | Value |
|---|---|
| SHA-256 | `8b35bc886f3c46afe759dad21cd8bbb05b2c360a4a6b6e8bae8a8be334ac012c` |
| Family label | `Mirai` |
| File name | `titanjr.m68k` |
| File type | `elf` |
| First seen | `2026-07-11 18:40:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c8381134691e6e41206c5bfd2c55ed2` |
| SHA-1 | `0678df09b1065c5cb4e6126a4b2fdc60dc480b0b` |
| SHA-256 | `8b35bc886f3c46afe759dad21cd8bbb05b2c360a4a6b6e8bae8a8be334ac012c` |
| SHA3-384 | `c8ac3ce74afd89f94137fbcae2a44e5b1b3504448a94c882a05222ae7c3bfb5569724dd03a5714e5f2339c35b58c6945` |
| TLSH | `T1EAA34AD7B402CDBDF84ADB7B44531906B531E3A20A831F36625BB917BC361A85937F82` |
| SSDEEP | `1536:sNLBpg4ORXcJpjrRcBoMtnP4++Y8E788E36HDeSHJ3PdNi6KXXltP5CdkzDne:RczjrRgLP3+Y8E7rF3PniZRCdkzTe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_8b35bc88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b35bc886f3c46afe759dad21cd8bbb05b2c360a4a6b6e8bae8a8be334ac012c"
    family = "Mirai"
    file_name = "titanjr.m68k"
    file_type = "elf"
    first_seen = "2026-07-11 18:40:41"
  condition:
    hash.sha256(0, filesize) == "8b35bc886f3c46afe759dad21cd8bbb05b2c360a4a6b6e8bae8a8be334ac012c"
}
```

### Sample 68: `48a8dfd966544046`

| Field | Value |
|---|---|
| SHA-256 | `48a8dfd9665440464f0b2a79f3679a00c21757a208ec96aabcf5166ac8e6ad31` |
| Family label | `Mirai` |
| File name | `bot_x86_64` |
| File type | `elf` |
| First seen | `2026-07-11 18:40:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e818d918cf3ba57e91ff1c189f1a4a49` |
| SHA-1 | `d79f5ffd7464221b8af8a4b9a000a39445d5c5c1` |
| SHA-256 | `48a8dfd9665440464f0b2a79f3679a00c21757a208ec96aabcf5166ac8e6ad31` |
| SHA3-384 | `990b454452604d2dcfca7b94a97f22eba562953e9e520ec170ccad52c9ffe4899c59f126c5bf1879dcd2ee2d95fea9fb` |
| TLSH | `T196456B57B2B364BDC093C43087DBD662A932B42546222E7F65C4CB312FA7E641B1DB63` |
| TELFHASH | `t1ac2141e7543da4a04adeac80e59b2724e10ff19458b10a23fca0c65c72fe61f49674eb` |
| SSDEEP | `24576:5MU1YjYc4kAUftW9Idcn4Po2Q3+FKf5ClKuTZXqvL/f:5MUKjYc4kAUly2ZAf5CA8ZXqD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_48a8dfd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48a8dfd9665440464f0b2a79f3679a00c21757a208ec96aabcf5166ac8e6ad31"
    family = "Mirai"
    file_name = "bot_x86_64"
    file_type = "elf"
    first_seen = "2026-07-11 18:40:40"
  condition:
    hash.sha256(0, filesize) == "48a8dfd9665440464f0b2a79f3679a00c21757a208ec96aabcf5166ac8e6ad31"
}
```

### Sample 69: `d39b90c9e009ce32`

| Field | Value |
|---|---|
| SHA-256 | `d39b90c9e009ce32e161f0dd70bec898213dbb35edabe01047a0b6419b755652` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-11 18:36:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba10cc8ab0a49978f046baa079710174` |
| SHA-1 | `c4adb893efe8c916dae5940f8e491415a2a6688c` |
| SHA-256 | `d39b90c9e009ce32e161f0dd70bec898213dbb35edabe01047a0b6419b755652` |
| SHA3-384 | `ff70b20bbf16579734b54da74d4b64cacc03f838224d70e8f200546799a19cffd5028c4323a5e4feb8ce0dd616b95caa` |
| TLSH | `T101C31999FC929A22C6C616BBFA4F42CD37262398E3DE7117CD155B2437CB42A0E3B141` |
| TELFHASH | `t1c9d09536ef5c1cdc1645ce15400f39041afdf16c25110a7175ec2e8f1041dc1742dd11` |
| SSDEEP | `3072:uci8lKOj2FjUYbQ2pIXzsc7bNYCvdyIomnbfd:ucd4AYc3NYIdoqfd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_d39b90c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d39b90c9e009ce32e161f0dd70bec898213dbb35edabe01047a0b6419b755652"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-11 18:36:46"
  condition:
    hash.sha256(0, filesize) == "d39b90c9e009ce32e161f0dd70bec898213dbb35edabe01047a0b6419b755652"
}
```

### Sample 70: `09553506b298fd49`

| Field | Value |
|---|---|
| SHA-256 | `09553506b298fd49150090669238577ce5127b53d70718c2bbb7b99b0f74e257` |
| Family label | `unknown` |
| File name | `c.sh` |
| File type | `sh` |
| First seen | `2026-07-11 18:34:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed7cceb2da43d17aa8275406574c1d8d` |
| SHA-1 | `7ec2546408381b4105a6edd51a40a2cbc512ef6c` |
| SHA-256 | `09553506b298fd49150090669238577ce5127b53d70718c2bbb7b99b0f74e257` |
| SHA3-384 | `bb2a5e70a76d978bfa88fd289e5e43d0949787f0bd7e59108c5fa29eedf730dc424538394baf64030577fed4e1e9f6d5` |
| TLSH | `T13D11198B425873421B588D98BD7BC8BD7990C2E771F2F5A1F114CC6496C92087C56B7F` |
| SSDEEP | `24:3J3UK/9GBKqszKYNIxOKYXKhKRWKIfh+KiTks2UKGp3IKCZkKXSKdhO5KChlHA:1ldq/z9YX3R1QXiTkx7GxCZLXJdhLChS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_09553506
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09553506b298fd49150090669238577ce5127b53d70718c2bbb7b99b0f74e257"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-11 18:34:41"
  condition:
    hash.sha256(0, filesize) == "09553506b298fd49150090669238577ce5127b53d70718c2bbb7b99b0f74e257"
}
```

### Sample 71: `bdb2209c0d4b4cc2`

| Field | Value |
|---|---|
| SHA-256 | `bdb2209c0d4b4cc273541f9313385ba6a56b60ca9b7046987c0e7669bf06093e` |
| Family label | `Mirai` |
| File name | `3.sh` |
| File type | `sh` |
| First seen | `2026-07-11 18:34:40` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e6bbca459ffa5a7cd7a40ee683853c0` |
| SHA-1 | `16a5456067f477fe6d6446e352571fcab5c6d633` |
| SHA-256 | `bdb2209c0d4b4cc273541f9313385ba6a56b60ca9b7046987c0e7669bf06093e` |
| SHA3-384 | `031f3d3ee029604b3e2f4c10339046fdfadc0f0b0e4341861d54cfb767203334e0c70d7f90d827beadc35478f0794dd7` |
| TLSH | `T11E0152C7110623315FE2D9A6BBBBC99C7090C1D764C3BEAAA498ACB5C18ED1C7C42657` |
| SSDEEP | `12:JCkp0FlkKrHkKUX0FlkKSPxHkKSPIhOf0FlkKYHkK8VZX0FlkK8HkKch:ItSKwKUsSKI+KIIhOESKtK8PsSKZKO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_bdb2209c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdb2209c0d4b4cc273541f9313385ba6a56b60ca9b7046987c0e7669bf06093e"
    family = "Mirai"
    file_name = "3.sh"
    file_type = "sh"
    first_seen = "2026-07-11 18:34:40"
  condition:
    hash.sha256(0, filesize) == "bdb2209c0d4b4cc273541f9313385ba6a56b60ca9b7046987c0e7669bf06093e"
}
```

### Sample 72: `84d81af465f76c5b`

| Field | Value |
|---|---|
| SHA-256 | `84d81af465f76c5bfcbe193748a17d6b597a3cd3875a96ed7791eb18cfe10c4f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-11 18:34:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9391a75ffd287b67fec10d3760a46a61` |
| SHA-1 | `c8d0b3630f028bbee91a0ca4828817fcf11cd5d0` |
| SHA-256 | `84d81af465f76c5bfcbe193748a17d6b597a3cd3875a96ed7791eb18cfe10c4f` |
| SHA3-384 | `3fb0849e6b0e25f2de55b5b24b07cc3784835fa2e436f02ebdb6e7bbc707c32359e0272c08a0aca488dab25b271a3cf0` |
| TLSH | `T136337C6616817C24AA98C8371D7F1F0CBDAD43E6320492DE7FCA3CF28C5AA9D911871D` |
| SSDEEP | `768:XXRWNGxVPA9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnB:xlxzcK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_84d81af4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84d81af465f76c5bfcbe193748a17d6b597a3cd3875a96ed7791eb18cfe10c4f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-11 18:34:39"
  condition:
    hash.sha256(0, filesize) == "84d81af465f76c5bfcbe193748a17d6b597a3cd3875a96ed7791eb18cfe10c4f"
}
```

### Sample 73: `de56f039a49168ee`

| Field | Value |
|---|---|
| SHA-256 | `de56f039a49168eeaba7aec02e0be7ffcb1062ca0c0714df29808a8f27188552` |
| Family label | `Mirai` |
| File name | `titanjr.arm6` |
| File type | `elf` |
| First seen | `2026-07-11 18:33:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57bdf1fb197a281083d175d006f0886a` |
| SHA-1 | `49466c10b3ff149b097918e97b1fdcfaf7a3abb8` |
| SHA-256 | `de56f039a49168eeaba7aec02e0be7ffcb1062ca0c0714df29808a8f27188552` |
| SHA3-384 | `2c14200889af1633b6910819f0b871292f2eb2b2154963f0c6a37f5074d67399cd716ff67a6b1f574b9d01664d6dd5e8` |
| TLSH | `T148A32956F9818B61C6C112BAFA1E528E3313177CE2EF73129D146F20778B96B0E7B845` |
| TELFHASH | `t10af09ee73a5846ed77c28aac87ad701b12fcb2b0263439c59fdd3c0b9121591715401d` |
| SSDEEP | `1536:MOnuJOg2qNIOclQ9nCzrgEB6+WC5dmfaFeB9oV/UnBiPkshx5dyL769YVkp5:kJOgUOQz+ZCXmfaFIEksL5dyLG9h5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_de56f039
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de56f039a49168eeaba7aec02e0be7ffcb1062ca0c0714df29808a8f27188552"
    family = "Mirai"
    file_name = "titanjr.arm6"
    file_type = "elf"
    first_seen = "2026-07-11 18:33:32"
  condition:
    hash.sha256(0, filesize) == "de56f039a49168eeaba7aec02e0be7ffcb1062ca0c0714df29808a8f27188552"
}
```

### Sample 74: `bc2ddf63fb0fba2d`

| Field | Value |
|---|---|
| SHA-256 | `bc2ddf63fb0fba2d53bfc11e1f87dd466ad3bea900712eb9ae03f91119b67dfc` |
| Family label | `Mirai` |
| File name | `titanjr.arm6` |
| File type | `elf` |
| First seen | `2026-07-11 18:32:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd050a3b5f3c2e77a14ae346acb83fa9` |
| SHA-1 | `f381508cfbfee69efc5f9de8e9a8ffd9c70e75a3` |
| SHA-256 | `bc2ddf63fb0fba2d53bfc11e1f87dd466ad3bea900712eb9ae03f91119b67dfc` |
| SHA3-384 | `a0ed709afcaf433f88e34b95d828d16436218e85732b674a5671b62badec9e3aa753047e10c925e60b98f837c6e8274a` |
| TLSH | `T12213F285159D17D2D73024784D590A02BACFEDBDED67B88DC664E9887DC320317986C3` |
| SSDEEP | `768:Lueeojfw3xI44IPP30ljtzPoGFkf2XAf9Irdakk5Q9q3UELOh:eo83m44IXAH82wy0ZL+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_bc2ddf63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc2ddf63fb0fba2d53bfc11e1f87dd466ad3bea900712eb9ae03f91119b67dfc"
    family = "Mirai"
    file_name = "titanjr.arm6"
    file_type = "elf"
    first_seen = "2026-07-11 18:32:44"
  condition:
    hash.sha256(0, filesize) == "bc2ddf63fb0fba2d53bfc11e1f87dd466ad3bea900712eb9ae03f91119b67dfc"
}
```

### Sample 75: `e749175fdc943fad`

| Field | Value |
|---|---|
| SHA-256 | `e749175fdc943fad5f97ef2d384217fe0d80c5c0795e0c804baa212c5e21c747` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-11 18:31:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08118f1620c2f86f17eb01631fdf8b0d` |
| SHA-1 | `db41d8f3f63ac6eac764e7394da014559d549204` |
| SHA-256 | `e749175fdc943fad5f97ef2d384217fe0d80c5c0795e0c804baa212c5e21c747` |
| SHA3-384 | `d7d41d59cf3ea6b5d5b0cee7cb71f44b94f54ef4d3ab46017fd301de5c5ef54026c6ac8eea06b7b47de5a9a34eb71fbd` |
| TLSH | `T178E3075AFC819F21D5C626BEFE4E518D332327A8E3EE7112DD245B2437CA95A0E7B101` |
| TELFHASH | `t1f2d0a731d9e063bc7b91d097c16d431366f9a5ae6703344a2ac07f275c43c537032813` |
| SSDEEP | `3072:VhrqRxgGd5Zk2k/tjhuYp/A25JMSaz79ARbNagxw/AiCEbB27uoBh8fnbzN:VhrqRmMnk2GphXprJ3anqZNagxw/AiCq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_e749175f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e749175fdc943fad5f97ef2d384217fe0d80c5c0795e0c804baa212c5e21c747"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-11 18:31:05"
  condition:
    hash.sha256(0, filesize) == "e749175fdc943fad5f97ef2d384217fe0d80c5c0795e0c804baa212c5e21c747"
}
```

### Sample 76: `022ecdc03e542dec`

| Field | Value |
|---|---|
| SHA-256 | `022ecdc03e542dec7f460d92692009bd9dd0fc3ac1eab9593945c84ff0a4fa30` |
| Family label | `Mirai` |
| File name | `titanjr.arc` |
| File type | `elf` |
| First seen | `2026-07-11 18:22:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3a63807a3feb84f880449577dfc4b71` |
| SHA-1 | `fc020e42fe719cd2e74c726c8547852b8c870124` |
| SHA-256 | `022ecdc03e542dec7f460d92692009bd9dd0fc3ac1eab9593945c84ff0a4fa30` |
| SHA3-384 | `852475e7f0ad6227a3ae30ebc62de271ba0dea7a956f6f53a857a6d3fffc5cef0446ab80b1ed6ba18eab95e3b0f0dc87` |
| TLSH | `T101C3AEC3FA8714A1C86206F013C70BAD6B93A112CF5FE4E7AD1DB53B5A7A0DA19167C1` |
| SSDEEP | `1536:xPcakPsaaavKaicvcmqiCvyzwwsWdoPzaDv9tlakCJcTxs559gFSmE3/LWE:dQsQvKqNnzwHA+GDv9tnCJcaggq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_022ecdc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "022ecdc03e542dec7f460d92692009bd9dd0fc3ac1eab9593945c84ff0a4fa30"
    family = "Mirai"
    file_name = "titanjr.arc"
    file_type = "elf"
    first_seen = "2026-07-11 18:22:36"
  condition:
    hash.sha256(0, filesize) == "022ecdc03e542dec7f460d92692009bd9dd0fc3ac1eab9593945c84ff0a4fa30"
}
```

### Sample 77: `6f64ea246118283c`

| Field | Value |
|---|---|
| SHA-256 | `6f64ea246118283c5e6de77bfb8e6528eaac21288985240c42bd76bf797508f8` |
| Family label | `Mirai` |
| File name | `titanjr.i686` |
| File type | `elf` |
| First seen | `2026-07-11 18:16:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26db9ddb5a559a07cab6110dc1722345` |
| SHA-1 | `ab47281aedf7ca5a85e953749a7ae8ac599ff529` |
| SHA-256 | `6f64ea246118283c5e6de77bfb8e6528eaac21288985240c42bd76bf797508f8` |
| SHA3-384 | `ccfeee62e198f6144aefe8736817e20873112614bc54bf904d9f4040ed0f387cf461f90bb69d3f73dc3524081d6d3e5a` |
| TLSH | `T1D08328C2BA4BC4F5D9074830406BF33FCB32E6394061D75EEF5A9E69DE336025626299` |
| TELFHASH | `t18c31e2fa197e08f8a7d44940c34d3e62396ae77b75a076b005b3593433a7e8160bac39` |
| SSDEEP | `1536:oolW/mih9H+KE7lMzTwuWAFclsWSANxHU+7AoGV1hSvt:BlemU9HI7YwuAvPDU+79GY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_6f64ea24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f64ea246118283c5e6de77bfb8e6528eaac21288985240c42bd76bf797508f8"
    family = "Mirai"
    file_name = "titanjr.i686"
    file_type = "elf"
    first_seen = "2026-07-11 18:16:51"
  condition:
    hash.sha256(0, filesize) == "6f64ea246118283c5e6de77bfb8e6528eaac21288985240c42bd76bf797508f8"
}
```

### Sample 78: `0731276bc9222d86`

| Field | Value |
|---|---|
| SHA-256 | `0731276bc9222d86586dae368226ed3945430aac4d2025e9275e0b5f503a4c05` |
| Family label | `Mirai` |
| File name | `titanjr.x86` |
| File type | `elf` |
| First seen | `2026-07-11 18:16:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e853cc6af1c8e8d6099e1a6c26d72e9` |
| SHA-1 | `e55ab8c31b04c44078e9808cff55604d6ec1346e` |
| SHA-256 | `0731276bc9222d86586dae368226ed3945430aac4d2025e9275e0b5f503a4c05` |
| SHA3-384 | `a178d81ce6c1dfb0d7aeb640f0d30696f9d1db02b4730905fa02a4b35fe31728f8451f9346ed1c289d58fe2046701733` |
| TLSH | `T169737DC6A683D0F4E8534573217BF7325A33E53E1029EB83D769A932ED13541AA1B39C` |
| TELFHASH | `t17131f5f70eba1df4f7c5a440834e6f52191af67b182036a242228c2073beec650bac30` |
| SSDEEP | `1536:yrGGVUzXByEGID/jM2rrWpVb/03RqQGhW+NKzhsIMcHM:yqnAyD7M2rir/03gjhW+QNbI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_0731276b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0731276bc9222d86586dae368226ed3945430aac4d2025e9275e0b5f503a4c05"
    family = "Mirai"
    file_name = "titanjr.x86"
    file_type = "elf"
    first_seen = "2026-07-11 18:16:49"
  condition:
    hash.sha256(0, filesize) == "0731276bc9222d86586dae368226ed3945430aac4d2025e9275e0b5f503a4c05"
}
```

### Sample 79: `fa7909526294f9a9`

| Field | Value |
|---|---|
| SHA-256 | `fa7909526294f9a963b87b828c32b336a4ef87c2e7ca8bc81a83da68a6d8cc7d` |
| Family label | `Mirai` |
| File name | `titanjr.i686` |
| File type | `elf` |
| First seen | `2026-07-11 18:16:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `064597c7820ee422c49cc317ca5d9933` |
| SHA-1 | `32f599a01f2fa4230ef3f5fc09d802eef9a7740e` |
| SHA-256 | `fa7909526294f9a963b87b828c32b336a4ef87c2e7ca8bc81a83da68a6d8cc7d` |
| SHA3-384 | `7cb9cf531dc7e3c461912fb45731c9e2cf33b5659e111b95674a521a4e0c4404a2d70550899c37b66c3f69ca5493094f` |
| TLSH | `T19F13F11588E1DB54D571B17122F3265A24782E6E30E84F78B7E4BA3171ABF0D4B8CF85` |
| SSDEEP | `768:kzGlucmDx6amz/qIqjuVfiQxJjR7aWLanLsMvPdV6gu2he0fHbgMs67FRZnbcuyb:kkQmzvqs7snLsadAiI0f7dFPnouy8Hyd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_fa790952
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa7909526294f9a963b87b828c32b336a4ef87c2e7ca8bc81a83da68a6d8cc7d"
    family = "Mirai"
    file_name = "titanjr.i686"
    file_type = "elf"
    first_seen = "2026-07-11 18:16:41"
  condition:
    hash.sha256(0, filesize) == "fa7909526294f9a963b87b828c32b336a4ef87c2e7ca8bc81a83da68a6d8cc7d"
}
```

### Sample 80: `3a25b82a489e1e05`

| Field | Value |
|---|---|
| SHA-256 | `3a25b82a489e1e0529e1bd2b422199289a205edcc62b8c03aedc05915ffdff1b` |
| Family label | `Mirai` |
| File name | `titanjr.x86` |
| File type | `elf` |
| First seen | `2026-07-11 18:16:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1897953bfe7d04c82134ef661d96492d` |
| SHA-1 | `7f258e4b917506ef4e38498839868718b5032bb3` |
| SHA-256 | `3a25b82a489e1e0529e1bd2b422199289a205edcc62b8c03aedc05915ffdff1b` |
| SHA3-384 | `e93463663ba32f673ae6ff9b10ad589dc2fbba14152bd7fa66bf54b362c8b97123dfe6c72c520bf8ca7308b0a99b589b` |
| TLSH | `T12C03F1C746F5DF15CB2FA6B14C56B6DE6230E01FDA5593622ED090BB46EBF1022392C2` |
| SSDEEP | `768:0Tud3PX52+LZg54NocytP5EpRIaB8t+ON15XnnbcuyD7UHQRjb:0Tu50uNlytP5EpRIZ+OV3nouy8HyX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_3a25b82a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a25b82a489e1e0529e1bd2b422199289a205edcc62b8c03aedc05915ffdff1b"
    family = "Mirai"
    file_name = "titanjr.x86"
    file_type = "elf"
    first_seen = "2026-07-11 18:16:40"
  condition:
    hash.sha256(0, filesize) == "3a25b82a489e1e0529e1bd2b422199289a205edcc62b8c03aedc05915ffdff1b"
}
```

### Sample 81: `ec36fe8cf355a8a4`

| Field | Value |
|---|---|
| SHA-256 | `ec36fe8cf355a8a4d95392f8f6410c9d524704e7d7ce51d7f64bd950135c492e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-11 18:13:57` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29096f2d4484dad3057b212bd525202a` |
| SHA-1 | `cc80eef46eebc570a35568e99afa45c08441c1c5` |
| SHA-256 | `ec36fe8cf355a8a4d95392f8f6410c9d524704e7d7ce51d7f64bd950135c492e` |
| SHA3-384 | `a9532950990e44b27e3338cac0beb303e5a10afc99e48a7c4e5e5f635099d6096ca97c1c53c444b89a301a3533b8dab0` |
| IMPHASH | `59667224ee0313970348dd1811a42053` |
| TLSH | `T1F6043B799682B9E9F596263F7B59BB19EE0EFE0103A9E49F06D4416F00934385F33B40` |
| SSDEEP | `3072:bCMzGYvgQTujce0DPWYNQ/NeSrkcupM+xMb4xsgMhwLebAoAK:eQyz0Du9dwcupM+xMMxspwLcAo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_ec36fe8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec36fe8cf355a8a4d95392f8f6410c9d524704e7d7ce51d7f64bd950135c492e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-11 18:13:57"
  condition:
    hash.sha256(0, filesize) == "ec36fe8cf355a8a4d95392f8f6410c9d524704e7d7ce51d7f64bd950135c492e"
}
```

### Sample 82: `83850b796647f863`

| Field | Value |
|---|---|
| SHA-256 | `83850b796647f863101c5ea49c0e0472b8b7931ba53b3c4e1f5486a4121f9339` |
| Family label | `Mirai` |
| File name | `titanjr.sh` |
| File type | `sh` |
| First seen | `2026-07-11 18:12:34` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14ea85e2e2960af7515b20a7ef812ef6` |
| SHA-1 | `2f167ff22b688a2bfb6b19e8b059ab886aabd42e` |
| SHA-256 | `83850b796647f863101c5ea49c0e0472b8b7931ba53b3c4e1f5486a4121f9339` |
| SHA3-384 | `d7adb3bb7dbf5c5b28a77546fc20cc2c38b9f79225717a2f0570a2a6fae1c9b62955a5994322446b6c0cc149c3e379c3` |
| TLSH | `T15A519E85215C2B31AC99DAD632AB403C619750E74FCF5FBD98D828F948CCE1578C36A2` |
| SSDEEP | `24:ItInm7v+ltsgAjCLM858NIG4ksayq037xzv:iom7mlWt+LTJa237Fv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_83850b79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83850b796647f863101c5ea49c0e0472b8b7931ba53b3c4e1f5486a4121f9339"
    family = "Mirai"
    file_name = "titanjr.sh"
    file_type = "sh"
    first_seen = "2026-07-11 18:12:34"
  condition:
    hash.sha256(0, filesize) == "83850b796647f863101c5ea49c0e0472b8b7931ba53b3c4e1f5486a4121f9339"
}
```

### Sample 83: `85a8df9964a72810`

| Field | Value |
|---|---|
| SHA-256 | `85a8df9964a728109e6b06241d5c9622f34035da24dc316336ccaf49b36fcbfe` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-11 18:10:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60fe55a7577d0fe9f9f9e928b58a149d` |
| SHA-1 | `65a042c02e2fb1e029589935ffb85a338a23267d` |
| SHA-256 | `85a8df9964a728109e6b06241d5c9622f34035da24dc316336ccaf49b36fcbfe` |
| SHA3-384 | `d9cfd036c81eccffe5ca688f023276bec2d0453fbc0326838feec3200921ec50687285ea447585c733cc5647ea44a059` |
| TLSH | `T14CC28D956A867C44BDC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C15F9CD618B1A` |
| SSDEEP | `768:c8vCB+25j6es8Rdx9FYpMSUpi+20qUpi+20YQX:c8l25Jdnd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_85a8df99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85a8df9964a728109e6b06241d5c9622f34035da24dc316336ccaf49b36fcbfe"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-11 18:10:33"
  condition:
    hash.sha256(0, filesize) == "85a8df9964a728109e6b06241d5c9622f34035da24dc316336ccaf49b36fcbfe"
}
```

### Sample 84: `e9272a5448f10a32`

| Field | Value |
|---|---|
| SHA-256 | `e9272a5448f10a323a0bb2f46aa41b0205bfa5dcb5c38cb5ec276737335df421` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-07-11 18:10:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e85e6673da67d81c6bb8b156761fb8b` |
| SHA-1 | `07a378c086976979d4baed555f793e576f9c654e` |
| SHA-256 | `e9272a5448f10a323a0bb2f46aa41b0205bfa5dcb5c38cb5ec276737335df421` |
| SHA3-384 | `267ef0210ee68e2fa56b5858ab5b4fb2d23b7370f83adda8b4df895c95f3c2d8a4291606b8fc96643694b8cd2602cd53` |
| TLSH | `T11A34F90AAB610EFBDC6BDD3711E91B0625CC641722A53F367274C918F94A64F4AE3C78` |
| SSDEEP | `3072:czaPIQD3fxIJp+1opQM/M9MOdUqfRdelRdQt9Dlq:oaPFSrHQKQ1fRkELw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_e9272a54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9272a5448f10a323a0bb2f46aa41b0205bfa5dcb5c38cb5ec276737335df421"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-07-11 18:10:32"
  condition:
    hash.sha256(0, filesize) == "e9272a5448f10a323a0bb2f46aa41b0205bfa5dcb5c38cb5ec276737335df421"
}
```

### Sample 85: `9f66434f98f3fa3e`

| Field | Value |
|---|---|
| SHA-256 | `9f66434f98f3fa3e9c36ca3c8e1bf7beb295f567acc70b04e120cf94d182043a` |
| Family label | `Mirai` |
| File name | `titanjr.spc` |
| File type | `elf` |
| First seen | `2026-07-11 18:08:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d14e82f215b932797d47d588051bae5` |
| SHA-1 | `13e42577f373beb4d78b06ea4345b36d546a86a9` |
| SHA-256 | `9f66434f98f3fa3e9c36ca3c8e1bf7beb295f567acc70b04e120cf94d182043a` |
| SHA3-384 | `53f060ba5856128bac4a6f6649ce8b8481b541ecd8d57ef9b9f598c9b5550665b79bed0406483648a3302f0a0a51c7f6` |
| TLSH | `T14A934922FDB5193BC8C4A47721F34335F2F6478A24A88A1F7D610E8DAF2565032A76F5` |
| SSDEEP | `1536:04nhLuA9FcStUTb4msamvcfIn7u+twZ0o95rTjpQg+xtsucr:dJfQeeGoPrTFRr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_9f66434f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f66434f98f3fa3e9c36ca3c8e1bf7beb295f567acc70b04e120cf94d182043a"
    family = "Mirai"
    file_name = "titanjr.spc"
    file_type = "elf"
    first_seen = "2026-07-11 18:08:37"
  condition:
    hash.sha256(0, filesize) == "9f66434f98f3fa3e9c36ca3c8e1bf7beb295f567acc70b04e120cf94d182043a"
}
```

### Sample 86: `a7d9ed955149f13f`

| Field | Value |
|---|---|
| SHA-256 | `a7d9ed955149f13f510804a3f8cdd123d8135a8b6bb9f37f5cbca43396001fbe` |
| Family label | `unknown` |
| File name | `SMP-1.0.0.jar` |
| File type | `jar` |
| First seen | `2026-07-11 17:56:46` |
| Reporter | `anonymous` |
| Tags | `dropper, jar, KurdishMyth, MythJs, MythPrivate` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebfc77bfd190560838e4ba8fa41b82b7` |
| SHA-1 | `0ebc16e5e861f6d2215edd1387c66ed63a221259` |
| SHA-256 | `a7d9ed955149f13f510804a3f8cdd123d8135a8b6bb9f37f5cbca43396001fbe` |
| SHA3-384 | `082594380e03737838bbf1388f2a23e2f7fc99af7e23de73a08596c60cae626c6f0f5e18ce8022b7c08d274c923bae25` |
| TLSH | `T10961A5583DA6D11ED907427785D6FDE678681F4A5604AA0F28332F580CD0A8F0B0BFCE` |
| SSDEEP | `48:9coV+mugzcT+H72LcJtcOcTcgtcetcAtc/tcfrSXxjK/TOa9/Q+bY0FPkgA0wJRp:NVJL2itcLT9Q1B+/BJY0GgWRoJxGSgv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_a7d9ed95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7d9ed955149f13f510804a3f8cdd123d8135a8b6bb9f37f5cbca43396001fbe"
    family = "unknown"
    file_name = "SMP-1.0.0.jar"
    file_type = "jar"
    first_seen = "2026-07-11 17:56:46"
  condition:
    hash.sha256(0, filesize) == "a7d9ed955149f13f510804a3f8cdd123d8135a8b6bb9f37f5cbca43396001fbe"
}
```

### Sample 87: `90f59a43308e41fe`

| Field | Value |
|---|---|
| SHA-256 | `90f59a43308e41fe58fc58ab71ad60dc5454fac4ddee5185d90a7f93a1de7e80` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-11 17:52:15` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `178357fa29ad96571b4ede32769b77e6` |
| SHA-1 | `ec691e72df157fbcf89a7a7f6fa0fc98db7ac4a6` |
| SHA-256 | `90f59a43308e41fe58fc58ab71ad60dc5454fac4ddee5185d90a7f93a1de7e80` |
| SHA3-384 | `8e3df9e13b35705bd3f754ec97df8deccaf6a99602741a141e5ad563053e202c25c106d209f712e9662fd1ef0d968559` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T126E6334C2AD021FEE3738179EFA129A6ED7470A16732C8CB0B548269BF875D14D3D52B` |
| SSDEEP | `393216:FgLG1MkveDp1IvJN3FhPLFXMCHWUjXWcuI3/PGTAI:FgKBv0YlrPLFXMb8XrH/O7` |
| ICON-DHASH | `38dcf8f8dcf8e042` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_90f59a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90f59a43308e41fe58fc58ab71ad60dc5454fac4ddee5185d90a7f93a1de7e80"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 17:52:15"
  condition:
    hash.sha256(0, filesize) == "90f59a43308e41fe58fc58ab71ad60dc5454fac4ddee5185d90a7f93a1de7e80"
}
```

### Sample 88: `d3f8a2e798316d31`

| Field | Value |
|---|---|
| SHA-256 | `d3f8a2e798316d3138ff713661de2edaed8bbc33a8ed13796806032f0568595f` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-11 17:51:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `402ee9befdfc5c5b425f9735c53cd77c` |
| SHA-1 | `967d9df847e27ac0e2e8e8f35692eae3de8510f0` |
| SHA-256 | `d3f8a2e798316d3138ff713661de2edaed8bbc33a8ed13796806032f0568595f` |
| SHA3-384 | `fd7ce5aa58e164cd6dda96813385dd2fd6531bcdef930841d8908dac50a43716b98f1f06627f03f0003894ed6ecae9a0` |
| TLSH | `T1BCF3C50E6E318F3DF779873487F74E21979873C626D0D685D2ACE5111E2028E681FBA9` |
| TELFHASH | `t14421800c497423f0a7715c9d5aaeff77e55030df6b256d278e01a9a9abbc9828e00c1c` |
| SSDEEP | `3072:6j1wrZPZtB9pkTWPv2yMxvIbdJOgXcu9RnmG4wKYQUjVcnPaxOocNnbEvj6:6R+ZPZtB9KvUePaxkJEvj6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_d3f8a2e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3f8a2e798316d3138ff713661de2edaed8bbc33a8ed13796806032f0568595f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-11 17:51:59"
  condition:
    hash.sha256(0, filesize) == "d3f8a2e798316d3138ff713661de2edaed8bbc33a8ed13796806032f0568595f"
}
```

### Sample 89: `84563043237682a7`

| Field | Value |
|---|---|
| SHA-256 | `84563043237682a743bb3e7ae7b57d50aaa0f1ae9abf453c4b00828d15b70ddc` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-07-11 17:42:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88147c46a2db536a445f0f8ddd9af28e` |
| SHA-1 | `4c67a2e0543f7aedecd76b8c9c2588095f57163f` |
| SHA-256 | `84563043237682a743bb3e7ae7b57d50aaa0f1ae9abf453c4b00828d15b70ddc` |
| SHA3-384 | `a742da7f457ace29431fe62ac08e15504c3fdbf18550c1dd983e303b90a7e488f9be04c7deb10e04a8eae810122be71f` |
| TLSH | `T155F3E70AAF601EF7E86FCD3351E95B0620CC655622A83FB57534D928F64A14F8AE3C74` |
| SSDEEP | `3072:noJWv6U582Eo3NDJCqgF8wQSapzCnbdJM:oS6U7Eo3NDJCqgWlSfdJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_84563043
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84563043237682a743bb3e7ae7b57d50aaa0f1ae9abf453c4b00828d15b70ddc"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-11 17:42:29"
  condition:
    hash.sha256(0, filesize) == "84563043237682a743bb3e7ae7b57d50aaa0f1ae9abf453c4b00828d15b70ddc"
}
```

### Sample 90: `f1e053dc9a7df16e`

| Field | Value |
|---|---|
| SHA-256 | `f1e053dc9a7df16e55cf465d1ef2afe6024a80f71a186c2832843b18385b1e1a` |
| Family label | `unknown` |
| File name | `f1e053dc9a7df16e55cf465d1ef2afe6024a80f71a186c2832843b18385b1e1a` |
| File type | `sh` |
| First seen | `2026-07-11 17:30:12` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9b964d132447cfb46b24f16578e34fb` |
| SHA-1 | `f3683ec0c132f0b7e85947d309fe6b66a6e7cd70` |
| SHA-256 | `f1e053dc9a7df16e55cf465d1ef2afe6024a80f71a186c2832843b18385b1e1a` |
| SHA3-384 | `02511ac3b8f4393cf14e7b5f3b94160bfef1374ea6e968caee378493dd5381a09bc9824acef15972ef27d703a3d5b49b` |
| TLSH | `T17151DAC7A49D8132E31AC0EA4F97F0402663202B5F53DB3CB9BE68518F55532A6D3A76` |
| SSDEEP | `48:EL9Tht1xX/5KIM/EO+xX/TI8feaJoHcSNLfUNp3G5/Ws/7sWobDgFwj9yquf/9Pb:EL9TNxP5KIaoxPTI8P+8SRsn2NV/gWYY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_f1e053dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1e053dc9a7df16e55cf465d1ef2afe6024a80f71a186c2832843b18385b1e1a"
    family = "unknown"
    file_name = "f1e053dc9a7df16e55cf465d1ef2afe6024a80f71a186c2832843b18385b1e1a"
    file_type = "sh"
    first_seen = "2026-07-11 17:30:12"
  condition:
    hash.sha256(0, filesize) == "f1e053dc9a7df16e55cf465d1ef2afe6024a80f71a186c2832843b18385b1e1a"
}
```

### Sample 91: `b0afa6ab7762455a`

| Field | Value |
|---|---|
| SHA-256 | `b0afa6ab7762455ad68d8e368b0e80341df9a4571e73d3165a93a33bbc7b23f1` |
| Family label | `Mirai` |
| File name | `XDppc` |
| File type | `elf` |
| First seen | `2026-07-11 17:23:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `136e763e7692b70dba5638dd64241615` |
| SHA-1 | `1ddc56bd122d682c0051d02bee80413314464b11` |
| SHA-256 | `b0afa6ab7762455ad68d8e368b0e80341df9a4571e73d3165a93a33bbc7b23f1` |
| SHA3-384 | `852ebaa61aa7aea5ad3c8096a0c0ecc310f10e2195e8db54680dd3b47417e4c63c5adac5f357273d176a09aa9130dc0f` |
| TLSH | `T184633C02B31C0E47C1635DB42A3F17E193AFA99121F4F789651E9B8A9276E321186FCD` |
| SSDEEP | `1536:H83cgtEbm75ZcWY8H84j2cBJlWFm9/8NIK/5DxwyRXLV/nu/:KvDjw8H8U2nNI+87/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_b0afa6ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0afa6ab7762455ad68d8e368b0e80341df9a4571e73d3165a93a33bbc7b23f1"
    family = "Mirai"
    file_name = "XDppc"
    file_type = "elf"
    first_seen = "2026-07-11 17:23:29"
  condition:
    hash.sha256(0, filesize) == "b0afa6ab7762455ad68d8e368b0e80341df9a4571e73d3165a93a33bbc7b23f1"
}
```

### Sample 92: `5ecad6764c40bac3`

| Field | Value |
|---|---|
| SHA-256 | `5ecad6764c40bac3f71661ae6601930acb0e51a961ee837a3f2f90ca3fd952a4` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-11 17:21:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52ba905ab2dbbb5691f4b518c39a17b7` |
| SHA-1 | `f10cdba8ca9daf2b92df729f1c1823bcad47887c` |
| SHA-256 | `5ecad6764c40bac3f71661ae6601930acb0e51a961ee837a3f2f90ca3fd952a4` |
| SHA3-384 | `9c938f5798b8e42c32d8e758a9e1931779ad6f4b4ea029f66bed48579206c787f5ef5072704035da99b24010e6009df0` |
| TLSH | `T178336C5516817C24EA99C8361C7E2F0CB9AD43E6324492EE7FCB3CF28C4AA9D911971D` |
| SSDEEP | `768:6+X9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnB:6+gcK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_5ecad676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ecad6764c40bac3f71661ae6601930acb0e51a961ee837a3f2f90ca3fd952a4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-11 17:21:35"
  condition:
    hash.sha256(0, filesize) == "5ecad6764c40bac3f71661ae6601930acb0e51a961ee837a3f2f90ca3fd952a4"
}
```

### Sample 93: `da50ab4a0d77e1e1`

| Field | Value |
|---|---|
| SHA-256 | `da50ab4a0d77e1e1a518a0e3baeda28ede523deb958d28e33af8fdffb4d88c5a` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-11 17:21:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `395cf5151f59f3927d717632aa5c881e` |
| SHA-1 | `735429eed2e8eb65faf1ab57e3e79e0af0609786` |
| SHA-256 | `da50ab4a0d77e1e1a518a0e3baeda28ede523deb958d28e33af8fdffb4d88c5a` |
| SHA3-384 | `7d81d9d7f62a9d7a3d309dfb4bba5cde67611e8f2d6e9325413fee597d28e6c1372845ce42660fff3de0444afd4c2c7c` |
| TLSH | `T1BEC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:K8vCB+25j6es8RI9FYpMSUpi+20qUpi+20YQX:K8l25Jed2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_da50ab4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da50ab4a0d77e1e1a518a0e3baeda28ede523deb958d28e33af8fdffb4d88c5a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-11 17:21:33"
  condition:
    hash.sha256(0, filesize) == "da50ab4a0d77e1e1a518a0e3baeda28ede523deb958d28e33af8fdffb4d88c5a"
}
```

### Sample 94: `8ddad5973d0ed85b`

| Field | Value |
|---|---|
| SHA-256 | `8ddad5973d0ed85ba2babe36121d16fa9307b8804206f645630b10f772010680` |
| Family label | `Mirai` |
| File name | `amd64` |
| File type | `elf` |
| First seen | `2026-07-11 17:13:57` |
| Reporter | `nicholaslegitt` |
| Tags | `cnc, elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7316c535e9c5808429d058d733d85fe6` |
| SHA-256 | `8ddad5973d0ed85ba2babe36121d16fa9307b8804206f645630b10f772010680` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_8ddad597
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ddad5973d0ed85ba2babe36121d16fa9307b8804206f645630b10f772010680"
    family = "Mirai"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-07-11 17:13:57"
  condition:
    hash.sha256(0, filesize) == "8ddad5973d0ed85ba2babe36121d16fa9307b8804206f645630b10f772010680"
}
```

### Sample 95: `a69d189f06bc78e5`

| Field | Value |
|---|---|
| SHA-256 | `a69d189f06bc78e50496b7247deb5cb41569aec1c949481c2ac55a202cb1c947` |
| Family label | `Mirai` |
| File name | `XDx86` |
| File type | `elf` |
| First seen | `2026-07-11 16:53:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81c56cef4efc722e2e9864412c79d04a` |
| SHA-1 | `9c60e50b133f3f57d013220aff826c1ba43be964` |
| SHA-256 | `a69d189f06bc78e50496b7247deb5cb41569aec1c949481c2ac55a202cb1c947` |
| SHA3-384 | `6c9220474fed21a6bb2bbee803d23694cd887599bcd2c782dfb15553faa2205930abdc2722beaa11f4091226161fc1e4` |
| TLSH | `T127535BC1AA87E8F7F91602752177E7378636F4361129DAC7C7A4EC32AC52901EA2735C` |
| TELFHASH | `t12f31c3fa2df909ecb3d0ad08c31e5fe31a3ad6b715a129b544b6581537f3d918065c32` |
| SSDEEP | `1536:5xCTpF8kbRKPrW96GsAifPnc+L4LOWDRhGlegZLh+GvvtUmLXjWK:5xAv8kbRKSxfiN4SyhSe+9tRWK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_a69d189f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a69d189f06bc78e50496b7247deb5cb41569aec1c949481c2ac55a202cb1c947"
    family = "Mirai"
    file_name = "XDx86"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:33"
  condition:
    hash.sha256(0, filesize) == "a69d189f06bc78e50496b7247deb5cb41569aec1c949481c2ac55a202cb1c947"
}
```

### Sample 96: `082b1860bb35d773`

| Field | Value |
|---|---|
| SHA-256 | `082b1860bb35d7730671367077fc0bc64e9a576b4c08a9a8e1d67b311580ca45` |
| Family label | `Mirai` |
| File name | `XDspc` |
| File type | `elf` |
| First seen | `2026-07-11 16:53:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `883e91e165f5233d3b570d4435bb39c8` |
| SHA-1 | `1ba81dc65a6bd8a7de9199a2cee36a95b8df0245` |
| SHA-256 | `082b1860bb35d7730671367077fc0bc64e9a576b4c08a9a8e1d67b311580ca45` |
| SHA3-384 | `397cf0e5f2e28d1e8783ebdffb4fcedefe1dd6dec1cdeb7337fdb03e8daf68fe5f285339d34ca98ebe28042358686b42` |
| TLSH | `T144735C32B9750D2BC5D5A8BA61F30325F2F2478A24ACCA1A7DB10D4EBF2564032577F9` |
| SSDEEP | `1536:X4YS2EBCq/5DA0jl1u1Q9tnZTgN95BU9bFU51jt2rF1/A+:o9HbRbFuNPWxbM+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_082b1860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "082b1860bb35d7730671367077fc0bc64e9a576b4c08a9a8e1d67b311580ca45"
    family = "Mirai"
    file_name = "XDspc"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:32"
  condition:
    hash.sha256(0, filesize) == "082b1860bb35d7730671367077fc0bc64e9a576b4c08a9a8e1d67b311580ca45"
}
```

### Sample 97: `f97d41ff38f168ec`

| Field | Value |
|---|---|
| SHA-256 | `f97d41ff38f168ec24969ee0cae1817a8f507bfdc03dec82740b84bfc900ab28` |
| Family label | `Mirai` |
| File name | `XDm68k` |
| File type | `elf` |
| First seen | `2026-07-11 16:53:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `527c35079a47ed5cb118888ab32dfad1` |
| SHA-1 | `8c4bf5e20f1325c802968258e3d764b9975cb51d` |
| SHA-256 | `f97d41ff38f168ec24969ee0cae1817a8f507bfdc03dec82740b84bfc900ab28` |
| SHA3-384 | `d1e97aa638950e7fb82a147d76920d46360b79485a4e7f90b41bcbe7f5bdcab8ecddb11ba1cee48f471e32d78900bce7` |
| TLSH | `T13A832A97F401DDBDF80ED77B4463490AB631A3A106830F3A675BBA67ED321945826FC2` |
| SSDEEP | `1536:4jKI91vPhM54FwSAakqE8Pc/CbmjhFaipTO1f7/aNisFp+/qXvm8:4eI9FPvOSbkqrUGiZOxmFp+/2m8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_f97d41ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f97d41ff38f168ec24969ee0cae1817a8f507bfdc03dec82740b84bfc900ab28"
    family = "Mirai"
    file_name = "XDm68k"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:31"
  condition:
    hash.sha256(0, filesize) == "f97d41ff38f168ec24969ee0cae1817a8f507bfdc03dec82740b84bfc900ab28"
}
```

### Sample 98: `b6ceeca61f6b6549`

| Field | Value |
|---|---|
| SHA-256 | `b6ceeca61f6b65490b0451e300e8283f99f5c6c00cbe985ed057078b9638670e` |
| Family label | `Mirai` |
| File name | `XDarm6` |
| File type | `elf` |
| First seen | `2026-07-11 16:53:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec7649e71cd8d6d9947b6944dfc9fc1e` |
| SHA-1 | `1d415152dd54764b85f6b096b93d42b8a9929305` |
| SHA-256 | `b6ceeca61f6b65490b0451e300e8283f99f5c6c00cbe985ed057078b9638670e` |
| SHA3-384 | `6a97aae8a35a0e88696470af5df9c904eb20f2da12c6e9f62a63064127c0644ae83450dbdbe93dc70705de438593dbf2` |
| TLSH | `T131831995B9814B12C5D512BAFE1E118E3323177CE3DE73129D206F24778B96B0E7BA06` |
| TELFHASH | `t10811dc281ec48fde93f48e18c5cab1a2ba963e35c533393e4e96761b43231d1701682e` |
| SSDEEP | `1536:ZTnJWOzhCrfmhDECS4UIYaZaUDDYX/QTMCiob5c5eCqfZ737pY8V/hX:2AhFDS4NYaZaUj5cYCqfZXpJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_b6ceeca6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6ceeca61f6b65490b0451e300e8283f99f5c6c00cbe985ed057078b9638670e"
    family = "Mirai"
    file_name = "XDarm6"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:30"
  condition:
    hash.sha256(0, filesize) == "b6ceeca61f6b65490b0451e300e8283f99f5c6c00cbe985ed057078b9638670e"
}
```

### Sample 99: `5eb20bf4b6ff91ac`

| Field | Value |
|---|---|
| SHA-256 | `5eb20bf4b6ff91ac45d4f7632661ff2166c7cf1270022a201a2dab8e600a1817` |
| Family label | `Mirai` |
| File name | `XDarm7` |
| File type | `elf` |
| First seen | `2026-07-11 16:53:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61cff27d1865e1cfcdcedccc68fba15c` |
| SHA-1 | `19a26d0a2a00618d7f711ca99746f38f9e600db2` |
| SHA-256 | `5eb20bf4b6ff91ac45d4f7632661ff2166c7cf1270022a201a2dab8e600a1817` |
| SHA3-384 | `0f0e6e8ee76833775bd5e9c6846055c7a40db3466e016f0d1a2a16c0b1a56dbe0c0a1973bd64c0188069f93f1e36cc12` |
| TLSH | `T13BF33C46E6414A13C0D6177ABBEF42453323AB6493DB73069928BFF43F8679E0E63605` |
| TELFHASH | `t1f031fd325721411aae52cc60dcee57f1251d86272744ee33ef3ac8cc651a49ae62bc8f` |
| SSDEEP | `3072:8hG77R4X2HaUJbXUc1df4RVaEFkINdLfhLNM/9tMiOZH7v5w2F:8hGvKGHaUJbXUcrf4aEqIzLfhZM/9Wnv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_5eb20bf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5eb20bf4b6ff91ac45d4f7632661ff2166c7cf1270022a201a2dab8e600a1817"
    family = "Mirai"
    file_name = "XDarm7"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:28"
  condition:
    hash.sha256(0, filesize) == "5eb20bf4b6ff91ac45d4f7632661ff2166c7cf1270022a201a2dab8e600a1817"
}
```

### Sample 100: `230bfc4605e6aa5a`

| Field | Value |
|---|---|
| SHA-256 | `230bfc4605e6aa5ab39f7c5049f246360a6edc6da1fb7209957bfa0dc4163aa9` |
| Family label | `Mirai` |
| File name | `XDarm` |
| File type | `elf` |
| First seen | `2026-07-11 16:53:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20c708e0a7957e53880fdb01fed31d16` |
| SHA-1 | `b50a9089ce475a8c25e98d19f91dd129fb871303` |
| SHA-256 | `230bfc4605e6aa5ab39f7c5049f246360a6edc6da1fb7209957bfa0dc4163aa9` |
| SHA3-384 | `8f761713aff49dbee81f154d17a08bf8dbace701d607448721b01b01b7e4f40fde61b420f462ea148fbefab24d8ec1ab` |
| TLSH | `T167733991BC819713C6D012BBFB6E028E372613A8D3EF32139D226F21778795B0E67645` |
| TELFHASH | `t15d51f1a5cf591aec1bd4c70842cb723daeea70b95f10285b8e197b4bc1536c1f516833` |
| SSDEEP | `1536:CnBtsMBC0J/L+HeCx1Ol1QS0XCSkdOLcpvDV/hVd:CnB9J9aOl1QjSDlt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_230bfc46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "230bfc4605e6aa5ab39f7c5049f246360a6edc6da1fb7209957bfa0dc4163aa9"
    family = "Mirai"
    file_name = "XDarm"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:27"
  condition:
    hash.sha256(0, filesize) == "230bfc4605e6aa5ab39f7c5049f246360a6edc6da1fb7209957bfa0dc4163aa9"
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
 * Generated: 2026-07-12T04:02:38.438212+00:00
 */

rule MalwareBazaar_unknown_001_3059240b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3059240b64dcdb773b76b64d9a7a70e51b50720025b3275deda1e34350d252b1"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-12 03:52:13"
  condition:
    hash.sha256(0, filesize) == "3059240b64dcdb773b76b64d9a7a70e51b50720025b3275deda1e34350d252b1"
}

rule MalwareBazaar_unknown_002_85c71cb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85c71cb954f79b09d239900289b10d40290caf5501302103587c43fb96c65dec"
    family = "unknown"
    file_name = "womp"
    file_type = "sh"
    first_seen = "2026-07-12 03:12:51"
  condition:
    hash.sha256(0, filesize) == "85c71cb954f79b09d239900289b10d40290caf5501302103587c43fb96c65dec"
}

rule MalwareBazaar_unknown_003_5ac877f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ac877f1702cfb39fdc4b8c4650fb4cffabfcff00757ea40c7860e6eae6f84d6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-12 02:52:13"
  condition:
    hash.sha256(0, filesize) == "5ac877f1702cfb39fdc4b8c4650fb4cffabfcff00757ea40c7860e6eae6f84d6"
}

rule MalwareBazaar_Mirai_004_78d584e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78d584e29cf2af465baa137c03d6644a8d8c269716349b03eddde76f3b9c88a0"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-12 02:38:00"
  condition:
    hash.sha256(0, filesize) == "78d584e29cf2af465baa137c03d6644a8d8c269716349b03eddde76f3b9c88a0"
}

rule MalwareBazaar_Mirai_005_80f66f2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80f66f2a896623bf068089121aba8be0104f1ad71f0c3b503f6775b57705c858"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:57"
  condition:
    hash.sha256(0, filesize) == "80f66f2a896623bf068089121aba8be0104f1ad71f0c3b503f6775b57705c858"
}

rule MalwareBazaar_Mirai_006_66d7509a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66d7509a1d19c4f6a25b5aec9f432e8423b3b123b6359b4d5be2cc52385b3842"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:54"
  condition:
    hash.sha256(0, filesize) == "66d7509a1d19c4f6a25b5aec9f432e8423b3b123b6359b4d5be2cc52385b3842"
}

rule MalwareBazaar_Mirai_007_19fca0c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19fca0c2200f6443cd0bcb954503a677eaef23bb5edf3025690e768d67255f3d"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:49"
  condition:
    hash.sha256(0, filesize) == "19fca0c2200f6443cd0bcb954503a677eaef23bb5edf3025690e768d67255f3d"
}

rule MalwareBazaar_Mirai_008_24c1f320
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24c1f320e51df5849f6b1dffe253a72558117e911c2ba210ec085cd15ec42ca1"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:46"
  condition:
    hash.sha256(0, filesize) == "24c1f320e51df5849f6b1dffe253a72558117e911c2ba210ec085cd15ec42ca1"
}

rule MalwareBazaar_Mirai_009_a77c058e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a77c058ead923018c2aaf9266e7d2ee57a40f97de14a52282930dcac96f9cec0"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:42"
  condition:
    hash.sha256(0, filesize) == "a77c058ead923018c2aaf9266e7d2ee57a40f97de14a52282930dcac96f9cec0"
}

rule MalwareBazaar_Mirai_010_b8445de0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8445de08b5f8dc796f0e20a3df7ef4ff1e3c17c8241367e067a93b44541f469"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-12 02:37:36"
  condition:
    hash.sha256(0, filesize) == "b8445de08b5f8dc796f0e20a3df7ef4ff1e3c17c8241367e067a93b44541f469"
}

rule MalwareBazaar_Mirai_011_01dd3eed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01dd3eeddc0ff280ab0ae9272d20a807c80f10afe4b1394fa68e427a87cebadd"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:57"
  condition:
    hash.sha256(0, filesize) == "01dd3eeddc0ff280ab0ae9272d20a807c80f10afe4b1394fa68e427a87cebadd"
}

rule MalwareBazaar_Mirai_012_42dbebaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42dbebaa947798c63208f77fc2bf81ba4749dbf8c423cd30663e4fc95d46c32d"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:55"
  condition:
    hash.sha256(0, filesize) == "42dbebaa947798c63208f77fc2bf81ba4749dbf8c423cd30663e4fc95d46c32d"
}

rule MalwareBazaar_unknown_013_f203c98a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f203c98a908119c7bbd8f4be45a8ca429e1cedce7c971d59b1d432bbdb4595b0"
    family = "unknown"
    file_name = "busywget.sh"
    file_type = "sh"
    first_seen = "2026-07-12 02:36:52"
  condition:
    hash.sha256(0, filesize) == "f203c98a908119c7bbd8f4be45a8ca429e1cedce7c971d59b1d432bbdb4595b0"
}

rule MalwareBazaar_Mirai_014_795896a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "795896a03556795d8c69818b26b5779f2e949c29b0f67d037e78be3da7765326"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:50"
  condition:
    hash.sha256(0, filesize) == "795896a03556795d8c69818b26b5779f2e949c29b0f67d037e78be3da7765326"
}

rule MalwareBazaar_Mirai_015_b2c0cae6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2c0cae650ddf10b0d3be03931adb4f7ade22e061b71e6728205f8a11b02f5a5"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:47"
  condition:
    hash.sha256(0, filesize) == "b2c0cae650ddf10b0d3be03931adb4f7ade22e061b71e6728205f8a11b02f5a5"
}

rule MalwareBazaar_unknown_016_9679b991
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9679b99144febbed9aae1222361e08578897e83d9b5d12024850a8aa57a011a8"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-12 02:36:43"
  condition:
    hash.sha256(0, filesize) == "9679b99144febbed9aae1222361e08578897e83d9b5d12024850a8aa57a011a8"
}

rule MalwareBazaar_Mirai_017_f4f3d6cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4f3d6cfb309115d5ac33dbdd5a850e97cf542be479f2bdfe87bbc68af86df27"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:40"
  condition:
    hash.sha256(0, filesize) == "f4f3d6cfb309115d5ac33dbdd5a850e97cf542be479f2bdfe87bbc68af86df27"
}

rule MalwareBazaar_Mirai_018_a92ba723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a92ba723f321aa6a37d07ed61538f259c859e63cf4768a07e253361800e48758"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:37"
  condition:
    hash.sha256(0, filesize) == "a92ba723f321aa6a37d07ed61538f259c859e63cf4768a07e253361800e48758"
}

rule MalwareBazaar_Mirai_019_50302d86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50302d86e61e5e6cea8e71c74a4a3284334de374e41f6075485be16c7e45bc6e"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:34"
  condition:
    hash.sha256(0, filesize) == "50302d86e61e5e6cea8e71c74a4a3284334de374e41f6075485be16c7e45bc6e"
}

rule MalwareBazaar_unknown_020_01c72746
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01c727469c703060764c88239e7a02fbc9582ba31a3a4a44c958958521bcad58"
    family = "unknown"
    file_name = "callaputa.sh"
    file_type = "sh"
    first_seen = "2026-07-12 02:36:31"
  condition:
    hash.sha256(0, filesize) == "01c727469c703060764c88239e7a02fbc9582ba31a3a4a44c958958521bcad58"
}

rule MalwareBazaar_Mirai_021_1a200226
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a200226e352bb22c9009bebcbaaabc755a3d56d03ba97152a7c6277c09ef8ff"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-12 02:36:28"
  condition:
    hash.sha256(0, filesize) == "1a200226e352bb22c9009bebcbaaabc755a3d56d03ba97152a7c6277c09ef8ff"
}

rule MalwareBazaar_unknown_022_766d8872
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "766d88722c18c4722e1b3a28281133b0c88082a5f3b58d4c58391879ed20a643"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-12 02:24:13"
  condition:
    hash.sha256(0, filesize) == "766d88722c18c4722e1b3a28281133b0c88082a5f3b58d4c58391879ed20a643"
}

rule MalwareBazaar_unknown_023_a236eaa0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a236eaa0c659201680739c3dcbb028a5d58de8b11471d3110a03e82d029f7aca"
    family = "unknown"
    file_name = "Phone+Clean+Fix_1.0.1.6.xapk"
    file_type = "xapk"
    first_seen = "2026-07-12 01:53:11"
  condition:
    hash.sha256(0, filesize) == "a236eaa0c659201680739c3dcbb028a5d58de8b11471d3110a03e82d029f7aca"
}

rule MalwareBazaar_unknown_024_886eb34b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "886eb34b664e06f2d543b0dc5f41c2bc56b2da02f0ecce54413af8128e050b54"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-12 01:52:14"
  condition:
    hash.sha256(0, filesize) == "886eb34b664e06f2d543b0dc5f41c2bc56b2da02f0ecce54413af8128e050b54"
}

rule MalwareBazaar_NanoCore_025_50c3831d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50c3831d8653c9d2f31e612a3c68e8f27fbe9e4b18274d5d6338b5ede0896834"
    family = "NanoCore"
    file_name = "cakhiatvwc02.info.exe"
    file_type = "exe"
    first_seen = "2026-07-12 01:45:04"
  condition:
    hash.sha256(0, filesize) == "50c3831d8653c9d2f31e612a3c68e8f27fbe9e4b18274d5d6338b5ede0896834"
}

rule MalwareBazaar_Mirai_026_a8a60a1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8a60a1ca586d6b3b8a2cdb7058ca20665318bc1743c75b7b56101e9ff06f814"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.15085.17293"
    file_type = "elf"
    first_seen = "2026-07-12 01:44:41"
  condition:
    hash.sha256(0, filesize) == "a8a60a1ca586d6b3b8a2cdb7058ca20665318bc1743c75b7b56101e9ff06f814"
}

rule MalwareBazaar_Mirai_027_83a64363
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83a6436320441c985d8c9aff65d35e5925f8298629be3bda1df5877e1113b72c"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.6778.4375"
    file_type = "elf"
    first_seen = "2026-07-12 01:44:38"
  condition:
    hash.sha256(0, filesize) == "83a6436320441c985d8c9aff65d35e5925f8298629be3bda1df5877e1113b72c"
}

rule MalwareBazaar_Mirai_028_a973b2e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a973b2e00f8250789c5d78d286156fea7482d3082cada7fd1771412986c54050"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.13407.32427"
    file_type = "elf"
    first_seen = "2026-07-12 01:44:35"
  condition:
    hash.sha256(0, filesize) == "a973b2e00f8250789c5d78d286156fea7482d3082cada7fd1771412986c54050"
}

rule MalwareBazaar_Mirai_029_83d866a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83d866a2c3640eb8edebd26b2258c52c0fc55eb583235c5756dbb75413d9155b"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.15085.17293"
    file_type = "elf"
    first_seen = "2026-07-12 01:43:36"
  condition:
    hash.sha256(0, filesize) == "83d866a2c3640eb8edebd26b2258c52c0fc55eb583235c5756dbb75413d9155b"
}

rule MalwareBazaar_unknown_030_6f90b696
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f90b696fe88bfccce71a3864cf1ca5fb68e92dd8b30e1745d2d7610ca427b11"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.Siggen.13385.32702.11656"
    file_type = "elf"
    first_seen = "2026-07-12 01:43:35"
  condition:
    hash.sha256(0, filesize) == "6f90b696fe88bfccce71a3864cf1ca5fb68e92dd8b30e1745d2d7610ca427b11"
}

rule MalwareBazaar_Mirai_031_56182524
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56182524f8086b409cfb3f149690218e5b4c94d3e7fadd95062cd7fd2c125b1f"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.6778.4375"
    file_type = "elf"
    first_seen = "2026-07-12 01:43:34"
  condition:
    hash.sha256(0, filesize) == "56182524f8086b409cfb3f149690218e5b4c94d3e7fadd95062cd7fd2c125b1f"
}

rule MalwareBazaar_Mirai_032_3eb84b56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3eb84b562b448b6833cb2636ad8ad32370b4ed45839349d7845ff71f6dd874e7"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.10589.13407.32427"
    file_type = "elf"
    first_seen = "2026-07-12 01:43:33"
  condition:
    hash.sha256(0, filesize) == "3eb84b562b448b6833cb2636ad8ad32370b4ed45839349d7845ff71f6dd874e7"
}

rule MalwareBazaar_unknown_033_1e10e0f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e10e0f923b8dfd4097bd4aeb69f1e27ba444b6b5d88c2a0b0240c81d7dc1498"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-12 01:19:23"
  condition:
    hash.sha256(0, filesize) == "1e10e0f923b8dfd4097bd4aeb69f1e27ba444b6b5d88c2a0b0240c81d7dc1498"
}

rule MalwareBazaar_Mirai_034_47e557f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47e557f9048a3cc5adb4e4611a165550aa2d087ca9d02b3cb38e285edc4440d6"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-12 01:01:28"
  condition:
    hash.sha256(0, filesize) == "47e557f9048a3cc5adb4e4611a165550aa2d087ca9d02b3cb38e285edc4440d6"
}

rule MalwareBazaar_Mirai_035_92afb5b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92afb5b482be852d9e83533fb74558fd92b6513c7fdd4a18273ad1a674148c25"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-12 01:00:47"
  condition:
    hash.sha256(0, filesize) == "92afb5b482be852d9e83533fb74558fd92b6513c7fdd4a18273ad1a674148c25"
}

rule MalwareBazaar_unknown_036_afac2f34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afac2f3414146f23409b3025b08a8b396ae457e8f0ca7fb6e6fd32c2942afec7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-12 00:52:15"
  condition:
    hash.sha256(0, filesize) == "afac2f3414146f23409b3025b08a8b396ae457e8f0ca7fb6e6fd32c2942afec7"
}

rule MalwareBazaar_unknown_037_f8ba9f21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8ba9f2170d4304a292942b3d4a635266bbf3177bbb35f3cde1dfbb96d01f9bf"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-12 00:28:38"
  condition:
    hash.sha256(0, filesize) == "f8ba9f2170d4304a292942b3d4a635266bbf3177bbb35f3cde1dfbb96d01f9bf"
}

rule MalwareBazaar_Mirai_038_70d8a0bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70d8a0bd683534586713936af02288e65c0ebb0fae26e357757f241b691c26f3"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-07-12 00:18:08"
  condition:
    hash.sha256(0, filesize) == "70d8a0bd683534586713936af02288e65c0ebb0fae26e357757f241b691c26f3"
}

rule MalwareBazaar_unknown_039_30add75b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30add75b83a74e078a70e970d8ae2b604cac0d4a06e3e03bd61b9faeba64e5f3"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-11 23:52:23"
  condition:
    hash.sha256(0, filesize) == "30add75b83a74e078a70e970d8ae2b604cac0d4a06e3e03bd61b9faeba64e5f3"
}

rule MalwareBazaar_unknown_040_b956c973
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b956c9732f3d5aa72bd2b8b78e03b519fdf15d9ea3ddcd5ada2c0f158105b96c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 23:52:15"
  condition:
    hash.sha256(0, filesize) == "b956c9732f3d5aa72bd2b8b78e03b519fdf15d9ea3ddcd5ada2c0f158105b96c"
}

rule MalwareBazaar_unknown_041_c8a2d4ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8a2d4ff2c12a7f081244dfa55a14bc7b0a4e029afd96fa06111c21eaf44c096"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-11 23:48:48"
  condition:
    hash.sha256(0, filesize) == "c8a2d4ff2c12a7f081244dfa55a14bc7b0a4e029afd96fa06111c21eaf44c096"
}

rule MalwareBazaar_unknown_042_d95c3b7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d95c3b7ae4b91b28b942f8a150f0da86a0c5c19641933a3edb80800aab67775b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-11 23:40:50"
  condition:
    hash.sha256(0, filesize) == "d95c3b7ae4b91b28b942f8a150f0da86a0c5c19641933a3edb80800aab67775b"
}

rule MalwareBazaar_Mirai_043_d5d7ba7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5d7ba7df2e3e90930879859614cdebacce22236a1d6d15486a8187b63f81082"
    family = "Mirai"
    file_name = "bot_x86_64"
    file_type = "elf"
    first_seen = "2026-07-11 23:34:51"
  condition:
    hash.sha256(0, filesize) == "d5d7ba7df2e3e90930879859614cdebacce22236a1d6d15486a8187b63f81082"
}

rule MalwareBazaar_Mirai_044_889f8101
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889f8101436dbf4c3d7bf4a8ed9c399bbacedaaf0c64c731eeebcd2cee6f435b"
    family = "Mirai"
    file_name = "nz.sh"
    file_type = "sh"
    first_seen = "2026-07-11 23:31:13"
  condition:
    hash.sha256(0, filesize) == "889f8101436dbf4c3d7bf4a8ed9c399bbacedaaf0c64c731eeebcd2cee6f435b"
}

rule MalwareBazaar_unknown_045_94d90962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94d90962079506e9c9d6661c69ecdf56fb0e16a7a2282d271942e2c7a165ffe7"
    family = "unknown"
    file_name = "wwg"
    file_type = "sh"
    first_seen = "2026-07-11 23:26:59"
  condition:
    hash.sha256(0, filesize) == "94d90962079506e9c9d6661c69ecdf56fb0e16a7a2282d271942e2c7a165ffe7"
}

rule MalwareBazaar_unknown_046_aa43f85f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa43f85f89297eb67a66198cb9d16373a9edbbc93503be45674d44ac8149c27a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-11 23:12:44"
  condition:
    hash.sha256(0, filesize) == "aa43f85f89297eb67a66198cb9d16373a9edbbc93503be45674d44ac8149c27a"
}

rule MalwareBazaar_unknown_047_5bdcf2d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bdcf2d4fd8a65c17237d4808e2b613deb0f54de1b90839f1f8e450d8b2acc19"
    family = "unknown"
    file_name = "Drv_ceo_12.8.1.exe"
    file_type = "exe"
    first_seen = "2026-07-11 23:05:23"
  condition:
    hash.sha256(0, filesize) == "5bdcf2d4fd8a65c17237d4808e2b613deb0f54de1b90839f1f8e450d8b2acc19"
}

rule MalwareBazaar_unknown_048_0e4931df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e4931df7ea30255b2820e6bd65b43477897c5c20b0d1ba34fd16b4063d92ebd"
    family = "unknown"
    file_name = "app_setup.6653008.msi"
    file_type = "msi"
    first_seen = "2026-07-11 23:01:38"
  condition:
    hash.sha256(0, filesize) == "0e4931df7ea30255b2820e6bd65b43477897c5c20b0d1ba34fd16b4063d92ebd"
}

rule MalwareBazaar_unknown_049_7279052d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7279052dbfd3f10ce49890a529d3595b052507cca7df6438e0e6ad8ec7bd8239"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 22:52:15"
  condition:
    hash.sha256(0, filesize) == "7279052dbfd3f10ce49890a529d3595b052507cca7df6438e0e6ad8ec7bd8239"
}

rule MalwareBazaar_unknown_050_6d1aadf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d1aadf48d83beb7dafe4bf7160c5ebb1c4b8b5a43d81ea4823e31c57a798ea6"
    family = "unknown"
    file_name = "mcrypt_payload.bin"
    file_type = "unknown"
    first_seen = "2026-07-11 22:34:53"
  condition:
    hash.sha256(0, filesize) == "6d1aadf48d83beb7dafe4bf7160c5ebb1c4b8b5a43d81ea4823e31c57a798ea6"
}

rule MalwareBazaar_unknown_051_939614ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "939614ca17f25bf319a2e14e349add40d753a529e6b21d1243b887cf4b65aaae"
    family = "unknown"
    file_name = "gz_2085.gz"
    file_type = "gz"
    first_seen = "2026-07-11 22:34:45"
  condition:
    hash.sha256(0, filesize) == "939614ca17f25bf319a2e14e349add40d753a529e6b21d1243b887cf4b65aaae"
}

rule MalwareBazaar_unknown_052_431f16e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "431f16e6453e3c9b1dfe663b9da917ba0fa8a20c6ba3f0cd834d093f6a1a416f"
    family = "unknown"
    file_name = "gz_2079.gz"
    file_type = "gz"
    first_seen = "2026-07-11 22:34:37"
  condition:
    hash.sha256(0, filesize) == "431f16e6453e3c9b1dfe663b9da917ba0fa8a20c6ba3f0cd834d093f6a1a416f"
}

rule MalwareBazaar_unknown_053_44210eec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44210eecc61cae505249b012ce0a84af436442f4ee4b73b66b69ce3c14ef3498"
    family = "unknown"
    file_name = "gz_2046.gz"
    file_type = "gz"
    first_seen = "2026-07-11 22:34:27"
  condition:
    hash.sha256(0, filesize) == "44210eecc61cae505249b012ce0a84af436442f4ee4b73b66b69ce3c14ef3498"
}

rule MalwareBazaar_unknown_054_2b9c0d3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b9c0d3b76eb1bbc348d233199ef24a54f74a1fb965072e95c2f645501d7e50e"
    family = "unknown"
    file_name = "screnc_raw.bin"
    file_type = "unknown"
    first_seen = "2026-07-11 22:34:12"
  condition:
    hash.sha256(0, filesize) == "2b9c0d3b76eb1bbc348d233199ef24a54f74a1fb965072e95c2f645501d7e50e"
}

rule MalwareBazaar_Socks5Systemz_055_963f836a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "963f836a69b3e3e02dcf177e0d34cf7fc37fa323f3f0011aac40dbbc9c06094c"
    family = "Socks5Systemz"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-11 22:24:38"
  condition:
    hash.sha256(0, filesize) == "963f836a69b3e3e02dcf177e0d34cf7fc37fa323f3f0011aac40dbbc9c06094c"
}

rule MalwareBazaar_unknown_056_c47be75b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c47be75ba9204ee9cc3d812bde65145e09a13a389bcce8cc15171aa4c04d1a4f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 21:52:13"
  condition:
    hash.sha256(0, filesize) == "c47be75ba9204ee9cc3d812bde65145e09a13a389bcce8cc15171aa4c04d1a4f"
}

rule MalwareBazaar_Mirai_057_a4a332b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4a332b84be4855c71f6fec63b61e9b3703082b25547002140bc66e082e817e3"
    family = "Mirai"
    file_name = "a4a332b84be4855c71f6fec63b61e9b3703082b25547002140bc66e082e817e3"
    file_type = "elf"
    first_seen = "2026-07-11 21:37:25"
  condition:
    hash.sha256(0, filesize) == "a4a332b84be4855c71f6fec63b61e9b3703082b25547002140bc66e082e817e3"
}

rule MalwareBazaar_unknown_058_6e95d301
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e95d3011ecc51a72fec8b2a8e5b06b4e134c2b2cfe513bfce42d9029c6c8dd1"
    family = "unknown"
    file_name = "6e95d3011ecc51a72fec8b2a8e5b06b4e134c2b2cfe513bfce42d9029c6c8dd1"
    file_type = "unknown"
    first_seen = "2026-07-11 21:30:11"
  condition:
    hash.sha256(0, filesize) == "6e95d3011ecc51a72fec8b2a8e5b06b4e134c2b2cfe513bfce42d9029c6c8dd1"
}

rule MalwareBazaar_unknown_059_915a6f0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "915a6f0c68ae869517620fc7c756c551378e4bde11c5f8adb80a0dc40515fb9e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 20:52:21"
  condition:
    hash.sha256(0, filesize) == "915a6f0c68ae869517620fc7c756c551378e4bde11c5f8adb80a0dc40515fb9e"
}

rule MalwareBazaar_unknown_060_3e1f434c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e1f434c282f58b8da8d8c4067adf9b90ffc407a5962fb97fe0172e25e5810b9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 19:52:13"
  condition:
    hash.sha256(0, filesize) == "3e1f434c282f58b8da8d8c4067adf9b90ffc407a5962fb97fe0172e25e5810b9"
}

rule MalwareBazaar_Mirai_061_12ec8533
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12ec85335eb93017704668019ec603db69d3703573301278e195f904872032bc"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-11 19:13:34"
  condition:
    hash.sha256(0, filesize) == "12ec85335eb93017704668019ec603db69d3703573301278e195f904872032bc"
}

rule MalwareBazaar_Mirai_062_1dd0d38c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dd0d38cd124cc1704d8d73d35752d3784892a88aa087e10d544782cdf232b47"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-11 19:12:41"
  condition:
    hash.sha256(0, filesize) == "1dd0d38cd124cc1704d8d73d35752d3784892a88aa087e10d544782cdf232b47"
}

rule MalwareBazaar_Mirai_063_b81ba14c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b81ba14cb5fd16dfaaebc558de473723619700ec04292d3bad98df88d0876f2f"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-11 19:12:40"
  condition:
    hash.sha256(0, filesize) == "b81ba14cb5fd16dfaaebc558de473723619700ec04292d3bad98df88d0876f2f"
}

rule MalwareBazaar_Mirai_064_7ef83c3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ef83c3a3c06f079a710e0b62181231ef5961aa9c64e8c8951ba2883c139ee65"
    family = "Mirai"
    file_name = "tplink.sh"
    file_type = "sh"
    first_seen = "2026-07-11 19:07:00"
  condition:
    hash.sha256(0, filesize) == "7ef83c3a3c06f079a710e0b62181231ef5961aa9c64e8c8951ba2883c139ee65"
}

rule MalwareBazaar_unknown_065_edd51919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edd51919f84f00e29342b8a5698a7288845efbf2e57ea712cf4dc902456134f3"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 18:52:14"
  condition:
    hash.sha256(0, filesize) == "edd51919f84f00e29342b8a5698a7288845efbf2e57ea712cf4dc902456134f3"
}

rule MalwareBazaar_NetSupport_066_a7475b46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7475b46ac26987a5d9a6c7aca0cbae6ce2559ac0d4957743f38ce9ef70e4f72"
    family = "NetSupport"
    file_name = "0ae0f719d08a68c58763c89c332ebbc1.exe"
    file_type = "exe"
    first_seen = "2026-07-11 18:45:09"
  condition:
    hash.sha256(0, filesize) == "a7475b46ac26987a5d9a6c7aca0cbae6ce2559ac0d4957743f38ce9ef70e4f72"
}

rule MalwareBazaar_Mirai_067_8b35bc88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b35bc886f3c46afe759dad21cd8bbb05b2c360a4a6b6e8bae8a8be334ac012c"
    family = "Mirai"
    file_name = "titanjr.m68k"
    file_type = "elf"
    first_seen = "2026-07-11 18:40:41"
  condition:
    hash.sha256(0, filesize) == "8b35bc886f3c46afe759dad21cd8bbb05b2c360a4a6b6e8bae8a8be334ac012c"
}

rule MalwareBazaar_Mirai_068_48a8dfd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48a8dfd9665440464f0b2a79f3679a00c21757a208ec96aabcf5166ac8e6ad31"
    family = "Mirai"
    file_name = "bot_x86_64"
    file_type = "elf"
    first_seen = "2026-07-11 18:40:40"
  condition:
    hash.sha256(0, filesize) == "48a8dfd9665440464f0b2a79f3679a00c21757a208ec96aabcf5166ac8e6ad31"
}

rule MalwareBazaar_Mirai_069_d39b90c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d39b90c9e009ce32e161f0dd70bec898213dbb35edabe01047a0b6419b755652"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-11 18:36:46"
  condition:
    hash.sha256(0, filesize) == "d39b90c9e009ce32e161f0dd70bec898213dbb35edabe01047a0b6419b755652"
}

rule MalwareBazaar_unknown_070_09553506
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09553506b298fd49150090669238577ce5127b53d70718c2bbb7b99b0f74e257"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-11 18:34:41"
  condition:
    hash.sha256(0, filesize) == "09553506b298fd49150090669238577ce5127b53d70718c2bbb7b99b0f74e257"
}

rule MalwareBazaar_Mirai_071_bdb2209c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdb2209c0d4b4cc273541f9313385ba6a56b60ca9b7046987c0e7669bf06093e"
    family = "Mirai"
    file_name = "3.sh"
    file_type = "sh"
    first_seen = "2026-07-11 18:34:40"
  condition:
    hash.sha256(0, filesize) == "bdb2209c0d4b4cc273541f9313385ba6a56b60ca9b7046987c0e7669bf06093e"
}

rule MalwareBazaar_unknown_072_84d81af4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84d81af465f76c5bfcbe193748a17d6b597a3cd3875a96ed7791eb18cfe10c4f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-11 18:34:39"
  condition:
    hash.sha256(0, filesize) == "84d81af465f76c5bfcbe193748a17d6b597a3cd3875a96ed7791eb18cfe10c4f"
}

rule MalwareBazaar_Mirai_073_de56f039
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de56f039a49168eeaba7aec02e0be7ffcb1062ca0c0714df29808a8f27188552"
    family = "Mirai"
    file_name = "titanjr.arm6"
    file_type = "elf"
    first_seen = "2026-07-11 18:33:32"
  condition:
    hash.sha256(0, filesize) == "de56f039a49168eeaba7aec02e0be7ffcb1062ca0c0714df29808a8f27188552"
}

rule MalwareBazaar_Mirai_074_bc2ddf63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc2ddf63fb0fba2d53bfc11e1f87dd466ad3bea900712eb9ae03f91119b67dfc"
    family = "Mirai"
    file_name = "titanjr.arm6"
    file_type = "elf"
    first_seen = "2026-07-11 18:32:44"
  condition:
    hash.sha256(0, filesize) == "bc2ddf63fb0fba2d53bfc11e1f87dd466ad3bea900712eb9ae03f91119b67dfc"
}

rule MalwareBazaar_Mirai_075_e749175f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e749175fdc943fad5f97ef2d384217fe0d80c5c0795e0c804baa212c5e21c747"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-11 18:31:05"
  condition:
    hash.sha256(0, filesize) == "e749175fdc943fad5f97ef2d384217fe0d80c5c0795e0c804baa212c5e21c747"
}

rule MalwareBazaar_Mirai_076_022ecdc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "022ecdc03e542dec7f460d92692009bd9dd0fc3ac1eab9593945c84ff0a4fa30"
    family = "Mirai"
    file_name = "titanjr.arc"
    file_type = "elf"
    first_seen = "2026-07-11 18:22:36"
  condition:
    hash.sha256(0, filesize) == "022ecdc03e542dec7f460d92692009bd9dd0fc3ac1eab9593945c84ff0a4fa30"
}

rule MalwareBazaar_Mirai_077_6f64ea24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f64ea246118283c5e6de77bfb8e6528eaac21288985240c42bd76bf797508f8"
    family = "Mirai"
    file_name = "titanjr.i686"
    file_type = "elf"
    first_seen = "2026-07-11 18:16:51"
  condition:
    hash.sha256(0, filesize) == "6f64ea246118283c5e6de77bfb8e6528eaac21288985240c42bd76bf797508f8"
}

rule MalwareBazaar_Mirai_078_0731276b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0731276bc9222d86586dae368226ed3945430aac4d2025e9275e0b5f503a4c05"
    family = "Mirai"
    file_name = "titanjr.x86"
    file_type = "elf"
    first_seen = "2026-07-11 18:16:49"
  condition:
    hash.sha256(0, filesize) == "0731276bc9222d86586dae368226ed3945430aac4d2025e9275e0b5f503a4c05"
}

rule MalwareBazaar_Mirai_079_fa790952
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa7909526294f9a963b87b828c32b336a4ef87c2e7ca8bc81a83da68a6d8cc7d"
    family = "Mirai"
    file_name = "titanjr.i686"
    file_type = "elf"
    first_seen = "2026-07-11 18:16:41"
  condition:
    hash.sha256(0, filesize) == "fa7909526294f9a963b87b828c32b336a4ef87c2e7ca8bc81a83da68a6d8cc7d"
}

rule MalwareBazaar_Mirai_080_3a25b82a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a25b82a489e1e0529e1bd2b422199289a205edcc62b8c03aedc05915ffdff1b"
    family = "Mirai"
    file_name = "titanjr.x86"
    file_type = "elf"
    first_seen = "2026-07-11 18:16:40"
  condition:
    hash.sha256(0, filesize) == "3a25b82a489e1e0529e1bd2b422199289a205edcc62b8c03aedc05915ffdff1b"
}

rule MalwareBazaar_unknown_081_ec36fe8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec36fe8cf355a8a4d95392f8f6410c9d524704e7d7ce51d7f64bd950135c492e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-11 18:13:57"
  condition:
    hash.sha256(0, filesize) == "ec36fe8cf355a8a4d95392f8f6410c9d524704e7d7ce51d7f64bd950135c492e"
}

rule MalwareBazaar_Mirai_082_83850b79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83850b796647f863101c5ea49c0e0472b8b7931ba53b3c4e1f5486a4121f9339"
    family = "Mirai"
    file_name = "titanjr.sh"
    file_type = "sh"
    first_seen = "2026-07-11 18:12:34"
  condition:
    hash.sha256(0, filesize) == "83850b796647f863101c5ea49c0e0472b8b7931ba53b3c4e1f5486a4121f9339"
}

rule MalwareBazaar_unknown_083_85a8df99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85a8df9964a728109e6b06241d5c9622f34035da24dc316336ccaf49b36fcbfe"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-11 18:10:33"
  condition:
    hash.sha256(0, filesize) == "85a8df9964a728109e6b06241d5c9622f34035da24dc316336ccaf49b36fcbfe"
}

rule MalwareBazaar_Mirai_084_e9272a54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9272a5448f10a323a0bb2f46aa41b0205bfa5dcb5c38cb5ec276737335df421"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-07-11 18:10:32"
  condition:
    hash.sha256(0, filesize) == "e9272a5448f10a323a0bb2f46aa41b0205bfa5dcb5c38cb5ec276737335df421"
}

rule MalwareBazaar_Mirai_085_9f66434f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f66434f98f3fa3e9c36ca3c8e1bf7beb295f567acc70b04e120cf94d182043a"
    family = "Mirai"
    file_name = "titanjr.spc"
    file_type = "elf"
    first_seen = "2026-07-11 18:08:37"
  condition:
    hash.sha256(0, filesize) == "9f66434f98f3fa3e9c36ca3c8e1bf7beb295f567acc70b04e120cf94d182043a"
}

rule MalwareBazaar_unknown_086_a7d9ed95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7d9ed955149f13f510804a3f8cdd123d8135a8b6bb9f37f5cbca43396001fbe"
    family = "unknown"
    file_name = "SMP-1.0.0.jar"
    file_type = "jar"
    first_seen = "2026-07-11 17:56:46"
  condition:
    hash.sha256(0, filesize) == "a7d9ed955149f13f510804a3f8cdd123d8135a8b6bb9f37f5cbca43396001fbe"
}

rule MalwareBazaar_unknown_087_90f59a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90f59a43308e41fe58fc58ab71ad60dc5454fac4ddee5185d90a7f93a1de7e80"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-11 17:52:15"
  condition:
    hash.sha256(0, filesize) == "90f59a43308e41fe58fc58ab71ad60dc5454fac4ddee5185d90a7f93a1de7e80"
}

rule MalwareBazaar_Mirai_088_d3f8a2e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3f8a2e798316d3138ff713661de2edaed8bbc33a8ed13796806032f0568595f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-11 17:51:59"
  condition:
    hash.sha256(0, filesize) == "d3f8a2e798316d3138ff713661de2edaed8bbc33a8ed13796806032f0568595f"
}

rule MalwareBazaar_Mirai_089_84563043
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84563043237682a743bb3e7ae7b57d50aaa0f1ae9abf453c4b00828d15b70ddc"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-11 17:42:29"
  condition:
    hash.sha256(0, filesize) == "84563043237682a743bb3e7ae7b57d50aaa0f1ae9abf453c4b00828d15b70ddc"
}

rule MalwareBazaar_unknown_090_f1e053dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1e053dc9a7df16e55cf465d1ef2afe6024a80f71a186c2832843b18385b1e1a"
    family = "unknown"
    file_name = "f1e053dc9a7df16e55cf465d1ef2afe6024a80f71a186c2832843b18385b1e1a"
    file_type = "sh"
    first_seen = "2026-07-11 17:30:12"
  condition:
    hash.sha256(0, filesize) == "f1e053dc9a7df16e55cf465d1ef2afe6024a80f71a186c2832843b18385b1e1a"
}

rule MalwareBazaar_Mirai_091_b0afa6ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0afa6ab7762455ad68d8e368b0e80341df9a4571e73d3165a93a33bbc7b23f1"
    family = "Mirai"
    file_name = "XDppc"
    file_type = "elf"
    first_seen = "2026-07-11 17:23:29"
  condition:
    hash.sha256(0, filesize) == "b0afa6ab7762455ad68d8e368b0e80341df9a4571e73d3165a93a33bbc7b23f1"
}

rule MalwareBazaar_unknown_092_5ecad676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ecad6764c40bac3f71661ae6601930acb0e51a961ee837a3f2f90ca3fd952a4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-11 17:21:35"
  condition:
    hash.sha256(0, filesize) == "5ecad6764c40bac3f71661ae6601930acb0e51a961ee837a3f2f90ca3fd952a4"
}

rule MalwareBazaar_unknown_093_da50ab4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da50ab4a0d77e1e1a518a0e3baeda28ede523deb958d28e33af8fdffb4d88c5a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-11 17:21:33"
  condition:
    hash.sha256(0, filesize) == "da50ab4a0d77e1e1a518a0e3baeda28ede523deb958d28e33af8fdffb4d88c5a"
}

rule MalwareBazaar_Mirai_094_8ddad597
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ddad5973d0ed85ba2babe36121d16fa9307b8804206f645630b10f772010680"
    family = "Mirai"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-07-11 17:13:57"
  condition:
    hash.sha256(0, filesize) == "8ddad5973d0ed85ba2babe36121d16fa9307b8804206f645630b10f772010680"
}

rule MalwareBazaar_Mirai_095_a69d189f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a69d189f06bc78e50496b7247deb5cb41569aec1c949481c2ac55a202cb1c947"
    family = "Mirai"
    file_name = "XDx86"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:33"
  condition:
    hash.sha256(0, filesize) == "a69d189f06bc78e50496b7247deb5cb41569aec1c949481c2ac55a202cb1c947"
}

rule MalwareBazaar_Mirai_096_082b1860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "082b1860bb35d7730671367077fc0bc64e9a576b4c08a9a8e1d67b311580ca45"
    family = "Mirai"
    file_name = "XDspc"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:32"
  condition:
    hash.sha256(0, filesize) == "082b1860bb35d7730671367077fc0bc64e9a576b4c08a9a8e1d67b311580ca45"
}

rule MalwareBazaar_Mirai_097_f97d41ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f97d41ff38f168ec24969ee0cae1817a8f507bfdc03dec82740b84bfc900ab28"
    family = "Mirai"
    file_name = "XDm68k"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:31"
  condition:
    hash.sha256(0, filesize) == "f97d41ff38f168ec24969ee0cae1817a8f507bfdc03dec82740b84bfc900ab28"
}

rule MalwareBazaar_Mirai_098_b6ceeca6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6ceeca61f6b65490b0451e300e8283f99f5c6c00cbe985ed057078b9638670e"
    family = "Mirai"
    file_name = "XDarm6"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:30"
  condition:
    hash.sha256(0, filesize) == "b6ceeca61f6b65490b0451e300e8283f99f5c6c00cbe985ed057078b9638670e"
}

rule MalwareBazaar_Mirai_099_5eb20bf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5eb20bf4b6ff91ac45d4f7632661ff2166c7cf1270022a201a2dab8e600a1817"
    family = "Mirai"
    file_name = "XDarm7"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:28"
  condition:
    hash.sha256(0, filesize) == "5eb20bf4b6ff91ac45d4f7632661ff2166c7cf1270022a201a2dab8e600a1817"
}

rule MalwareBazaar_Mirai_100_230bfc46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "230bfc4605e6aa5ab39f7c5049f246360a6edc6da1fb7209957bfa0dc4163aa9"
    family = "Mirai"
    file_name = "XDarm"
    file_type = "elf"
    first_seen = "2026-07-11 16:53:27"
  condition:
    hash.sha256(0, filesize) == "230bfc4605e6aa5ab39f7c5049f246360a6edc6da1fb7209957bfa0dc4163aa9"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-08

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 670 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 670 |
| Unique family labels | 12 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 56 |
| unknown | 30 |
| CoinMiner | 3 |
| ValleyRAT | 2 |
| RemcosRAT | 2 |
| Vidar | 1 |
| njrat | 1 |
| AgentTesla | 1 |
| Gafgyt | 1 |
| Stealc | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 63 |
| exe | 24 |
| sh | 5 |
| js | 2 |
| msi | 2 |
| vbs | 1 |
| gz | 1 |
| tar | 1 |
| zip | 1 |

## Per-Sample Analysis

### Sample 1: `f8c56b8a1ecfa061`

| Field | Value |
|---|---|
| SHA-256 | `f8c56b8a1ecfa06186f0d1dc3e566223aba52e282dcce895d493cbe78d9db512` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-08 03:32:45` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, signed, US0.file, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78039a133fe132a8d1bfe231649ae463` |
| SHA-1 | `9f4aa0f7bd9dfb8ae72a6e108b7fec2a434ed91e` |
| SHA-256 | `f8c56b8a1ecfa06186f0d1dc3e566223aba52e282dcce895d493cbe78d9db512` |
| SHA3-384 | `d154895a15e3b1c415c0ce9118a90a4bfb09195924985c7c91ab98971b81466349fd9e14a815809bf5783d41cf19175f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T184D58D0B6CE409EAC4AA533189B651917B70BC594F3227D72E90B7783F72BE1AD36740` |
| SSDEEP | `49152:WRXjM09Hv/i4NFvvqy5a+PEHT/BMAsO3rHMh4XVL8lTdgXFA:WRzM7I1vk+PEHlMAsO3rHE4VolTdgVA` |
| ICON-DHASH | `deb168ecb2d4cd7f` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_001_f8c56b8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8c56b8a1ecfa06186f0d1dc3e566223aba52e282dcce895d493cbe78d9db512"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-08 03:32:45"
  condition:
    hash.sha256(0, filesize) == "f8c56b8a1ecfa06186f0d1dc3e566223aba52e282dcce895d493cbe78d9db512"
}
```

### Sample 2: `69cd34ef2d9b26fa`

| Field | Value |
|---|---|
| SHA-256 | `69cd34ef2d9b26fad86387d6ef3556a7a7bdd13bf7e45f810fd7c2bbff30974b` |
| Family label | `njrat` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-08 03:20:25` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, njrat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bfbeaa25be3ec5055a3a53473bebc99` |
| SHA-1 | `e12fe772e8c8f715e64c34addae2f930c2987ad5` |
| SHA-256 | `69cd34ef2d9b26fad86387d6ef3556a7a7bdd13bf7e45f810fd7c2bbff30974b` |
| SHA3-384 | `6b80e536ddc5e0aced3d1c848fbda325e5d74f1564e4d4f3d80a9c686835943e6afd0784e6103a4bd14bf79744647f0d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18F232B4973D59521C5FD9E385565A20207BAB20BAC1FFB0D0CDADCE91BB37D10D10AEA` |
| SSDEEP | `768:czXpEHBoMBHbzS/fPX3SpkPEA590TRXZ66QDY/X9u0hcbKyU:65EHBoMBHbzSPSpkPETKY/Xg8cbKy` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_002_69cd34ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69cd34ef2d9b26fad86387d6ef3556a7a7bdd13bf7e45f810fd7c2bbff30974b"
    family = "njrat"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-08 03:20:25"
  condition:
    hash.sha256(0, filesize) == "69cd34ef2d9b26fad86387d6ef3556a7a7bdd13bf7e45f810fd7c2bbff30974b"
}
```

### Sample 3: `3a2ce5b01dc23cbe`

| Field | Value |
|---|---|
| SHA-256 | `3a2ce5b01dc23cbe768df69bc04fcb4e68ee58f1341a767f0cbfd3cd15440a59` |
| Family label | `unknown` |
| File name | `Sprogvidenskabsmandens.vbs` |
| File type | `vbs` |
| First seen | `2026-07-08 03:14:37` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8090ffc96151a7b7cd83dd60d607f63c` |
| SHA-1 | `b85775c4503835306751de188a9668795c459ac7` |
| SHA-256 | `3a2ce5b01dc23cbe768df69bc04fcb4e68ee58f1341a767f0cbfd3cd15440a59` |
| SHA3-384 | `3bf5170376c35cf8d68f4e2dd4ecf27cd7d9deca6bace5e145f918ee760c6c226883b986a77e154b2712c8ef8ff48bbb` |
| TLSH | `T1FB433B11C9C44B3E5D0307FDBE405A64D0FDC6194B2580EDEA9D332E541A6ECEB7EAA8` |
| SSDEEP | `768:99Zm72CFcvEgxWnClzOtGi1ea6pmATGtfiAO4+BKCnEwneX0k4142Cc14GPet6nR:3ZmSvNm+ztraW+tfihDKCn144lecnlz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_3a2ce5b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a2ce5b01dc23cbe768df69bc04fcb4e68ee58f1341a767f0cbfd3cd15440a59"
    family = "unknown"
    file_name = "Sprogvidenskabsmandens.vbs"
    file_type = "vbs"
    first_seen = "2026-07-08 03:14:37"
  condition:
    hash.sha256(0, filesize) == "3a2ce5b01dc23cbe768df69bc04fcb4e68ee58f1341a767f0cbfd3cd15440a59"
}
```

### Sample 4: `24b1c3f96179633e`

| Field | Value |
|---|---|
| SHA-256 | `24b1c3f96179633ed7a40190ea103c558cc182c32cab38e3399a81524cb578b5` |
| Family label | `unknown` |
| File name | `Clash-X64.exe` |
| File type | `exe` |
| First seen | `2026-07-08 02:55:22` |
| Reporter | `CNGaoLing` |
| Tags | `exe, RAT, Yephiler` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2edb118e4db7268d2b51963f1fbbe72a` |
| SHA-1 | `9606c6cf4d6ad6cfa143845e80461539f942d589` |
| SHA-256 | `24b1c3f96179633ed7a40190ea103c558cc182c32cab38e3399a81524cb578b5` |
| SHA3-384 | `aed0269b7a519fe92581ff955a2f5007501297a26743cbd4199f1441f0f95f8bf8d566f450280ba66349fb6b204ea542` |
| IMPHASH | `4fac38a977655de0f2858087be1ed60a` |
| TLSH | `T150A73347914E94E2CBA8B4B21016098C277850F33C30A6DB77AF0D49D7696DB2FE9D9C` |
| SSDEEP | `786432:MqYWNfsvVp1VhX1D7k2Jhk0SCiQ/Kr2fAz+oGij+xzUqz4AOG6ai:M/W0L1VhZk2s0SBMKq4WxjvR` |
| ICON-DHASH | `0f034d61d469330f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_24b1c3f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24b1c3f96179633ed7a40190ea103c558cc182c32cab38e3399a81524cb578b5"
    family = "unknown"
    file_name = "Clash-X64.exe"
    file_type = "exe"
    first_seen = "2026-07-08 02:55:22"
  condition:
    hash.sha256(0, filesize) == "24b1c3f96179633ed7a40190ea103c558cc182c32cab38e3399a81524cb578b5"
}
```

### Sample 5: `f8d9727dcae3e079`

| Field | Value |
|---|---|
| SHA-256 | `f8d9727dcae3e07980899001689724c3b0d71f446ded7344bb0550df9f4e157e` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-08 02:52:12` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91ba383b15c069fb8d8147fc8c4f6cc4` |
| SHA-1 | `46a4786fe79dac1a4df8716c4c406871749f5ea5` |
| SHA-256 | `f8d9727dcae3e07980899001689724c3b0d71f446ded7344bb0550df9f4e157e` |
| SHA3-384 | `9497f853eb5485e11df821ef5adc0220ee532df461c8aeba8416de8cd749e97e94774d31a68208fbfc6d1e782437cbda` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1B1E6334CEAD522FEE6F3507CAEB096D2D17578B10731C5DB27A882E09E471918C3E627` |
| SSDEEP | `393216:9Me8SpmNPxX7CwXMCHWUjXrcuI3/PGTAI:9bt+5rCwXMb8XIH/O7` |
| ICON-DHASH | `38dcf8f8fcf8e040` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_f8d9727d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8d9727dcae3e07980899001689724c3b0d71f446ded7344bb0550df9f4e157e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-08 02:52:12"
  condition:
    hash.sha256(0, filesize) == "f8d9727dcae3e07980899001689724c3b0d71f446ded7344bb0550df9f4e157e"
}
```

### Sample 6: `6c303e19f1337a7e`

| Field | Value |
|---|---|
| SHA-256 | `6c303e19f1337a7eacef23bdd882d97329bebc7aff0d42f0726d2c876e3cdea5` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-08 02:41:27` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `490bcc9e85b3600ea2cea36151acf8d6` |
| SHA-1 | `763f4398c2527fcb954ad8b794a4ae54ecacd0ab` |
| SHA-256 | `6c303e19f1337a7eacef23bdd882d97329bebc7aff0d42f0726d2c876e3cdea5` |
| SHA3-384 | `6cf27e98bb45ce56555bc587e10cdecde05ad5753aaa4028dc0401f600cdd83e62bf046922f92194a27f3cdfc3a5cf6c` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T1F63209197E494331D3A089F85479838BA53D5633E7C3E3EBF373965E4A962448840EAF` |
| SSDEEP | `192:3nomWEzBa/Vx+eTRHj5PFJxTEZmFhSac:3no+w9w2lPFwZ` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_006_6c303e19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c303e19f1337a7eacef23bdd882d97329bebc7aff0d42f0726d2c876e3cdea5"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-08 02:41:27"
  condition:
    hash.sha256(0, filesize) == "6c303e19f1337a7eacef23bdd882d97329bebc7aff0d42f0726d2c876e3cdea5"
}
```

### Sample 7: `6a83689b2dfdaed0`

| Field | Value |
|---|---|
| SHA-256 | `6a83689b2dfdaed0f04d621d34b066aca3238d224575f961dc2448b8bfdd0658` |
| Family label | `unknown` |
| File name | `6a83689b2dfdaed0f04d621d34b066aca3238d224575f961dc2448b8bfdd0658` |
| File type | `exe` |
| First seen | `2026-07-08 02:15:25` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f77eef5f24bf43c423e6336601130cb` |
| SHA-1 | `e3e268a96b118551d4b16634b3aa6dbc10561783` |
| SHA-256 | `6a83689b2dfdaed0f04d621d34b066aca3238d224575f961dc2448b8bfdd0658` |
| SHA3-384 | `6e407b0e2bb0525a1d255cea15b4f5af10d48c411d439ce5839aad178e279f45b56c5fe0a665424f5570f9dbe5632a7c` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T19936125A32AC80FCC11B5274A4B34D26E7B37C5A227D970F8B9487660E13790BE78B57` |
| SSDEEP | `12288:jbLgmwbLgPluxQhMbaIMu7L5NVErCA4z2g6rTcbckPU82900Ve7zw+K+DHeQYSUY:jbLg1bLgdeQhfdmMSirYbcMNgef0QeQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_6a83689b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a83689b2dfdaed0f04d621d34b066aca3238d224575f961dc2448b8bfdd0658"
    family = "unknown"
    file_name = "6a83689b2dfdaed0f04d621d34b066aca3238d224575f961dc2448b8bfdd0658"
    file_type = "exe"
    first_seen = "2026-07-08 02:15:25"
  condition:
    hash.sha256(0, filesize) == "6a83689b2dfdaed0f04d621d34b066aca3238d224575f961dc2448b8bfdd0658"
}
```

### Sample 8: `c8415587863d57e1`

| Field | Value |
|---|---|
| SHA-256 | `c8415587863d57e1cc4aa543ee9c0cb04ec486f031b49f2d7448631c4a5b29da` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-08 02:11:32` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92b274e8cc85fe15f8ddf066725bcc69` |
| SHA-1 | `4e0d350ebb2ab380db1b1fbf4d5f99a3d4559436` |
| SHA-256 | `c8415587863d57e1cc4aa543ee9c0cb04ec486f031b49f2d7448631c4a5b29da` |
| SHA3-384 | `f3f0b747998755d55db8aaeb6b7abff528cae1a2f2d9fe63dca46fa7d1bf09382e3bbf985755d64964716ba22d7d8303` |
| IMPHASH | `d9cdc56d00b82d68dd1cc6a7338127bf` |
| TLSH | `T1E5320729FF4A0331E3A489F45479828BA57D5623A397E3EBF333965E4E552448800E6F` |
| SSDEEP | `192:FM0o92WPrBxl+W4OX+PFJxTEZmFhvScP:FPoDf0lOX+PFwZ` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_008_c8415587
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8415587863d57e1cc4aa543ee9c0cb04ec486f031b49f2d7448631c4a5b29da"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-08 02:11:32"
  condition:
    hash.sha256(0, filesize) == "c8415587863d57e1cc4aa543ee9c0cb04ec486f031b49f2d7448631c4a5b29da"
}
```

### Sample 9: `e4897305c584eb9c`

| Field | Value |
|---|---|
| SHA-256 | `e4897305c584eb9c2dee7fbf0cea9f454a2aadf83736edfa497b610d60e6aa3e` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-08 02:08:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52aabad745746d348248cbe3059355f1` |
| SHA-1 | `e59a9ae26fb769a6809d9c9da760465edca1ffab` |
| SHA-256 | `e4897305c584eb9c2dee7fbf0cea9f454a2aadf83736edfa497b610d60e6aa3e` |
| SHA3-384 | `711c72647c009324b5483a3f7df9d009f69ce46646530af7b0ec4a7ff0ffbe22c4980e111e98ca8fdd5883246750804b` |
| TLSH | `T13A93F781B8824A6AC6E02379E66E718E33A0B3F5D2CF3127DD615B12779518B0D67F81` |
| TELFHASH | `t187e06140fe764b1844e75634ecdd07b49511211761664710cf54daf0883f118a31cd5e` |
| SSDEEP | `1536:9m0L9q1B6mDftrSq1hu9TnTb4UUhL2o2jDthSDH8ku8oeIH:9rBq1BtD6wq5UIORIH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_e4897305
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4897305c584eb9c2dee7fbf0cea9f454a2aadf83736edfa497b610d60e6aa3e"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-08 02:08:39"
  condition:
    hash.sha256(0, filesize) == "e4897305c584eb9c2dee7fbf0cea9f454a2aadf83736edfa497b610d60e6aa3e"
}
```

### Sample 10: `7433b8c9472586d7`

| Field | Value |
|---|---|
| SHA-256 | `7433b8c9472586d713797a725388c7cad5c070311051a2355ce1f880d41f94f6` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-08 02:07:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0821c6c6fc42697e6ab4d1081c7e14c` |
| SHA-1 | `73b5b842092c01a4310958ff1d19d3f944145c2b` |
| SHA-256 | `7433b8c9472586d713797a725388c7cad5c070311051a2355ce1f880d41f94f6` |
| SHA3-384 | `1d570cd4bf110f615165b7ce65b81f45d46330f3438881b93fb92b865d66ca85792511596731c4bf14eac87769c6fc69` |
| TLSH | `T1E8E2E19224D41D70CB71C431EFB492C7B6C22B3D8187A19B67898FF466FE9D809B8947` |
| SSDEEP | `768:SZ+6GyLuOzsD5AwQhe4ljYaDTTqu79rXEJys3UozLe:SKawDq3he4ljYaHTqu79r+vzC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_7433b8c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7433b8c9472586d713797a725388c7cad5c070311051a2355ce1f880d41f94f6"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-08 02:07:38"
  condition:
    hash.sha256(0, filesize) == "7433b8c9472586d713797a725388c7cad5c070311051a2355ce1f880d41f94f6"
}
```

### Sample 11: `90e72cb310525972`

| Field | Value |
|---|---|
| SHA-256 | `90e72cb310525972af1e9d97cd837d48aaf87a429930b507f56befddff1ff713` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-07-08 02:04:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27c926823687337fe491a0578dcee3bf` |
| SHA-1 | `3c11433b0e5a3354dab55eea7b535074e3c11103` |
| SHA-256 | `90e72cb310525972af1e9d97cd837d48aaf87a429930b507f56befddff1ff713` |
| SHA3-384 | `2ecf5f5902c3804d111cdc2f1666df95f66e05bafd7910ea316d3137279456bbcc86e59cbe133fbbd357f14b98844c09` |
| TLSH | `T12B8171E6F834A522304DFAFCF217A7848746CEB990BB3601A046AD7301CF558B54DBB1` |
| SSDEEP | `24:j96f0fs+L+Jmgs+LJlSlLxs+L5M7ldls+L0fxf2Us+LuifibVs+Lcmfm0GCGs+Le:ev5F7Fh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_90e72cb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90e72cb310525972af1e9d97cd837d48aaf87a429930b507f56befddff1ff713"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-08 02:04:27"
  condition:
    hash.sha256(0, filesize) == "90e72cb310525972af1e9d97cd837d48aaf87a429930b507f56befddff1ff713"
}
```

### Sample 12: `3afefe3a97b3df9d`

| Field | Value |
|---|---|
| SHA-256 | `3afefe3a97b3df9dffee6259161dd4e1c37a59f4726f68d9194921a631b1058b` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-08 02:02:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e531e28099ba33434b92f8698f7973d` |
| SHA-1 | `09cb3b96b11395ea767e78165ebeada5d961f52b` |
| SHA-256 | `3afefe3a97b3df9dffee6259161dd4e1c37a59f4726f68d9194921a631b1058b` |
| SHA3-384 | `539ff807ac220eb3e94cca1183e3f818e7a28efdfbe8861e701b181c7b537fa0dc9ef01898bcc48821aaa9e0bc583cd9` |
| TLSH | `T194330741B8815A23C6E1137AF56E46CD3B3563E8E2DFB21B9D226F20379681F0C67E45` |
| TELFHASH | `t10b2138408d4919c87bf08e5792cdb02b719a3e75de2228564f4b6f6f8766de1703603b` |
| SSDEEP | `768:9QWX82FGIw2wzsVaOshfCYjIO9XNn/06zVhToWNLyT7i3F/YbP2pw:z82FGN2wzcjedS6Jhm30UV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_3afefe3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3afefe3a97b3df9dffee6259161dd4e1c37a59f4726f68d9194921a631b1058b"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-08 02:02:20"
  condition:
    hash.sha256(0, filesize) == "3afefe3a97b3df9dffee6259161dd4e1c37a59f4726f68d9194921a631b1058b"
}
```

### Sample 13: `0bfb8671ec522cc7`

| Field | Value |
|---|---|
| SHA-256 | `0bfb8671ec522cc77656f514c3cff9034ef67f97a780672ade79804eccafe7a4` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-08 02:00:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd8a8c786bee729b89c4d54ca2ebf507` |
| SHA-1 | `50dd7d65e44a69c16a4ba37489deab900e7b8a54` |
| SHA-256 | `0bfb8671ec522cc77656f514c3cff9034ef67f97a780672ade79804eccafe7a4` |
| SHA3-384 | `2dbd2a56867c6722f81fce3c4e4f43b0dc73caecacd95fa145967286426f03138c6a4cc8d2ea7452e7c4367013f10a1c` |
| TLSH | `T129A2D070616D6930D325853ADFAC84071B4B8E78E1FF32182A1D2638B8C790725FE66B` |
| SSDEEP | `384:KckgAL0EJP1jbF+bMfOsJuIMPbLMRXlJUo6hymdGUop5hMV:KckgAhSFsJ6jLkVuo6s3Uoz6V` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_0bfb8671
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bfb8671ec522cc77656f514c3cff9034ef67f97a780672ade79804eccafe7a4"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-08 02:00:42"
  condition:
    hash.sha256(0, filesize) == "0bfb8671ec522cc77656f514c3cff9034ef67f97a780672ade79804eccafe7a4"
}
```

### Sample 14: `02666285148eae09`

| Field | Value |
|---|---|
| SHA-256 | `02666285148eae0968f8e25b6c6de6ebe8827b8b15e25ef617635ad3b4e24007` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-08 01:52:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04f65af5fbec750c21d7d33c84a178b4` |
| SHA-1 | `19090434303b65e68428e75bd0ea6f6483910cf8` |
| SHA-256 | `02666285148eae0968f8e25b6c6de6ebe8827b8b15e25ef617635ad3b4e24007` |
| SHA3-384 | `337f8a3e906b997a92ea1088c58793bb4c74aeda1b5d87bc34a4c6573496007889c97b046dbbc6fa16a54cfa8d76b3aa` |
| TLSH | `T1613319DAF8019E7DF95BE27E44174908BA3173D112832B2B27BBFDA36C720595D12E81` |
| SSDEEP | `768:7Iyef6zs1j76X+7EQdkjSl88YbHriM/+oG8Y1lWuwSxGi:7xQj74c7dMSl880Hf/+oGP1Uxi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_02666285
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02666285148eae0968f8e25b6c6de6ebe8827b8b15e25ef617635ad3b4e24007"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-08 01:52:50"
  condition:
    hash.sha256(0, filesize) == "02666285148eae0968f8e25b6c6de6ebe8827b8b15e25ef617635ad3b4e24007"
}
```

### Sample 15: `53315d3131904093`

| Field | Value |
|---|---|
| SHA-256 | `53315d3131904093f56cffcccb235424aa53eb24ff814c68c6dece1a3744a2fe` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-07-08 01:52:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed872b0fe5df2c7175d2828e8495ca64` |
| SHA-1 | `61c74d2c193ec487fcfc0d6a8290b6869f746fd7` |
| SHA-256 | `53315d3131904093f56cffcccb235424aa53eb24ff814c68c6dece1a3744a2fe` |
| SHA3-384 | `b099c0723e34e4eb7e70f86e3ead24c23c74b68f77c243d16dfed2f4421daaeaa4b1c7f17724eebc04eac64f035538c4` |
| TLSH | `T1C3B39D9BF24B12A1C86246F047CB0BDE3E6322925F5BD9E33C2D213A1C7A1CB5D05B95` |
| SSDEEP | `1536:XQWJKy2BaeidhAVxQalazuYwyUg0n/LWO:XQWJKy+aei7CxQayuYwyUg0nq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_53315d31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53315d3131904093f56cffcccb235424aa53eb24ff814c68c6dece1a3744a2fe"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-07-08 01:52:49"
  condition:
    hash.sha256(0, filesize) == "53315d3131904093f56cffcccb235424aa53eb24ff814c68c6dece1a3744a2fe"
}
```

### Sample 16: `87b25bb68d599cee`

| Field | Value |
|---|---|
| SHA-256 | `87b25bb68d599cee8dcd11fee91b3b1a03c87eca0f460c6ed0962fc26239674c` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-08 01:52:47` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2083bceb73991db1f2483a6fe14e5cc` |
| SHA-1 | `e8a42ec3282560b9baee22b5cb48149c7a75b3e8` |
| SHA-256 | `87b25bb68d599cee8dcd11fee91b3b1a03c87eca0f460c6ed0962fc26239674c` |
| SHA3-384 | `8ce9deaffdd0f1b19c1d361bfe3750ee78a457900312dccdf9b83f2da15955de241e9646038a42d44832f5136b234186` |
| TLSH | `T101336D6616817C24AA98D8361D7F1F0CBDAD43E6320492DE7FCA3CF28C5AA9D911871D` |
| SSDEEP | `768:SXRWNGxVm9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnB:elxJcK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_87b25bb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87b25bb68d599cee8dcd11fee91b3b1a03c87eca0f460c6ed0962fc26239674c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-08 01:52:47"
  condition:
    hash.sha256(0, filesize) == "87b25bb68d599cee8dcd11fee91b3b1a03c87eca0f460c6ed0962fc26239674c"
}
```

### Sample 17: `85752e86ea189634`

| Field | Value |
|---|---|
| SHA-256 | `85752e86ea189634b042f5bb296f4fe0851a1a71ecd3a8228110740fff89f4bc` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-08 01:52:12` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c054e4ac40efec39798d76fcdfae45a2` |
| SHA-1 | `8c80bf39118b8533ad972e370922dcebfd931c33` |
| SHA-256 | `85752e86ea189634b042f5bb296f4fe0851a1a71ecd3a8228110740fff89f4bc` |
| SHA3-384 | `c05b3f1114df2d3c018d6b4621c7d0dda78b68a8457f7eb2c6e35761ade59866f53148bac3421b2c808a74542baef102` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F5E633546BE012FED6B3507C6DD295A2C5B874B30732C98F6B18E7E26E672A00D3D613` |
| SSDEEP | `393216:TA+pn1t5R0dw4KZQMXMCHWUjXrcuI3/PGTAI:TlVb0m4uXMb8XIH/O7` |
| ICON-DHASH | `70f0f0e8e8f0f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_85752e86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85752e86ea189634b042f5bb296f4fe0851a1a71ecd3a8228110740fff89f4bc"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-08 01:52:12"
  condition:
    hash.sha256(0, filesize) == "85752e86ea189634b042f5bb296f4fe0851a1a71ecd3a8228110740fff89f4bc"
}
```

### Sample 18: `524fef057a18f499`

| Field | Value |
|---|---|
| SHA-256 | `524fef057a18f499117e6ab2c3cde2bef7f6d2c9fc2b51a462b269261f3fa713` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-08 01:48:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc7b88d9f7b3950d439ef12647e1c1a6` |
| SHA-1 | `a29b73aee998974a5277d85c6aa05f847853335a` |
| SHA-256 | `524fef057a18f499117e6ab2c3cde2bef7f6d2c9fc2b51a462b269261f3fa713` |
| SHA3-384 | `d7a0a56bdb05597333b5755eb0b7f24e4d082892837a343c25060da61682718b1010af5debeb98dc58ac7a79d6d79e4d` |
| TLSH | `T1ED53B616BB590EFBECEBDC3746A81B0134CC548A22D56B367634C868F40B65F1AE3D64` |
| SSDEEP | `768:4MyK7uY/Ot9ycpdoveHSeF9ePoxAkNMuI7BEm4THYZ2cSXi9I+XOctwF:4W7uvd02Sg9HekNMuI7BEm4sZ2chXk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_524fef05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "524fef057a18f499117e6ab2c3cde2bef7f6d2c9fc2b51a462b269261f3fa713"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:59"
  condition:
    hash.sha256(0, filesize) == "524fef057a18f499117e6ab2c3cde2bef7f6d2c9fc2b51a462b269261f3fa713"
}
```

### Sample 19: `d7eb9ab28d047c28`

| Field | Value |
|---|---|
| SHA-256 | `d7eb9ab28d047c28fb5310415c8fd29b37498c855f8a3ea446248e7f5fd08a15` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-08 01:48:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f97fc35cbaf1c6beec8f4403300e801` |
| SHA-1 | `49998af94add4f04829dd6249b3c8630c44208ba` |
| SHA-256 | `d7eb9ab28d047c28fb5310415c8fd29b37498c855f8a3ea446248e7f5fd08a15` |
| SHA3-384 | `048e3b5dbfeafce910c3494d3deef609ea3c511aab2d690b6f4b9fad847d90118196a28de6a417f658050bf44134076b` |
| TLSH | `T13BC34B0273180B47C5A319B02E3E3BE687FFE5E021E4BB89251E8B564575EB75849FC8` |
| SSDEEP | `1536:KqL5Jj5lED60/rhmvQ+f2evxDNScNGPuFZ+1mWdHKyELsHsI:KqL5JjQ2w5qbDPfFUmLGHsI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_d7eb9ab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7eb9ab28d047c28fb5310415c8fd29b37498c855f8a3ea446248e7f5fd08a15"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:56"
  condition:
    hash.sha256(0, filesize) == "d7eb9ab28d047c28fb5310415c8fd29b37498c855f8a3ea446248e7f5fd08a15"
}
```

### Sample 20: `ce9d2c70b2ce2eb2`

| Field | Value |
|---|---|
| SHA-256 | `ce9d2c70b2ce2eb27ba7f39b374f4529a3c27e8e1ad450c9697d066a88ad28fe` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-08 01:48:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `719937afdeed9c98fa8eee8f667115e6` |
| SHA-1 | `8f5f33bd7dd7a68974d5d65d5616ccfec078ffa5` |
| SHA-256 | `ce9d2c70b2ce2eb27ba7f39b374f4529a3c27e8e1ad450c9697d066a88ad28fe` |
| SHA3-384 | `9371877adf7dcdf353202c489aac902f8848d20595136bd1a47f9b4583bc2b0ceccfd63454574a40b6008d06c3255015` |
| TLSH | `T153B31907BDC18DFDC089C038477F753ED822F0ED0239B2AB67D4AE262D5DEA11A19A55` |
| TELFHASH | `t1cb2177b03ed27a5c20c3d39ab35ede7ae0b209241a92b1e58f0b6dd98e06fc80c41456` |
| SSDEEP | `3072:gHoE9uzAHZeQ9eAT9kkzyQtJGCvR0MeITI8IunXYUxre:gIE4zAHZeQ9XT9kKjGMeKIIXYUxre` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_ce9d2c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce9d2c70b2ce2eb27ba7f39b374f4529a3c27e8e1ad450c9697d066a88ad28fe"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:51"
  condition:
    hash.sha256(0, filesize) == "ce9d2c70b2ce2eb27ba7f39b374f4529a3c27e8e1ad450c9697d066a88ad28fe"
}
```

### Sample 21: `0d0e414d42ca89f5`

| Field | Value |
|---|---|
| SHA-256 | `0d0e414d42ca89f5556132fece6b5e9493e6f3b349edcec249edfb32c38fc3d3` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-08 01:48:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `752427e0ff54c99ed7773694b7320db9` |
| SHA-1 | `a3f9d1dcff084c53fda971e5586a87110bfee25f` |
| SHA-256 | `0d0e414d42ca89f5556132fece6b5e9493e6f3b349edcec249edfb32c38fc3d3` |
| SHA3-384 | `26ea70cbd7eeb78149f405c9679adcf345e20c34ff2eb44f2d340d5e27cd1ecafffb7f459334fe2b923dbdd01002a52a` |
| TLSH | `T1E2B2D09DE294F646DFAD2EB9519A87F06DE222E23359079CC3302CD6B22191F744E03C` |
| SSDEEP | `768:JibGdJ/0Bf5uPc/uqisCYz7gg3NvRJdWx:JhD0BfIP0ufYzpbs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_0d0e414d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d0e414d42ca89f5556132fece6b5e9493e6f3b349edcec249edfb32c38fc3d3"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:18"
  condition:
    hash.sha256(0, filesize) == "0d0e414d42ca89f5556132fece6b5e9493e6f3b349edcec249edfb32c38fc3d3"
}
```

### Sample 22: `f687804910db04e2`

| Field | Value |
|---|---|
| SHA-256 | `f687804910db04e241f6f734522ab8af7ae2135d173a98173c17b11b3a65824f` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-08 01:48:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48b795ccab412fcda689d5f333e4e26f` |
| SHA-1 | `d19f767c46a5bf0125d5d0cfeb3440c08c9f24e9` |
| SHA-256 | `f687804910db04e241f6f734522ab8af7ae2135d173a98173c17b11b3a65824f` |
| SHA3-384 | `2101c6dbc92d4b34e6e0fd1ee045ba42b7f389e586014d8a1f25d53cfe706855b89709bb861bb1c4f461e6742e07d885` |
| TLSH | `T16D23E118D2F45FAADFCB51B2158891A22361DBEB9367CD8230CEF5603195D12B8EDB90` |
| SSDEEP | `768:fmBrN1oPOSI35TzozdYvuP+3zx8QnjL5JnK+08vKOfdx/IA/k6xt6/NC/ngcnTgV:fCrN1oPO5KzdYvuCNPnjLvnKxoKmXIAk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_f6878049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f687804910db04e241f6f734522ab8af7ae2135d173a98173c17b11b3a65824f"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:16"
  condition:
    hash.sha256(0, filesize) == "f687804910db04e241f6f734522ab8af7ae2135d173a98173c17b11b3a65824f"
}
```

### Sample 23: `e67901d60d2dfbfc`

| Field | Value |
|---|---|
| SHA-256 | `e67901d60d2dfbfc71154b1aa0aeb10a828a346910869d75629ebbdb2b89bd8d` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-08 01:48:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f921edf399e0d4c6c28aa4fe7836e17f` |
| SHA-1 | `0337c5129da90d9f305182ded5347a560929a009` |
| SHA-256 | `e67901d60d2dfbfc71154b1aa0aeb10a828a346910869d75629ebbdb2b89bd8d` |
| SHA3-384 | `880636a31d48d674a201d06c1c7c900b7403c7f0bba644ef533b0ff56e58662e4140d6f23fd93ee4f21ebb4747bd56ad` |
| TLSH | `T16B23F1D351BFAA3DC552DA76408F9250EA3EC80E2955C3877AF812ED4FABD5B5C21E00` |
| SSDEEP | `768:a+an3RY7qKS4o2SeAgPBOAcLorb6T8/s/hOMBtE47fJmfHq2BwyNIriUudGpWoIO:y3+7k4oZCAonl/aTE47BmApgdGp/IBxu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_e67901d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e67901d60d2dfbfc71154b1aa0aeb10a828a346910869d75629ebbdb2b89bd8d"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:14"
  condition:
    hash.sha256(0, filesize) == "e67901d60d2dfbfc71154b1aa0aeb10a828a346910869d75629ebbdb2b89bd8d"
}
```

### Sample 24: `490ea48be8568bea`

| Field | Value |
|---|---|
| SHA-256 | `490ea48be8568beaaa07f1f269b482fa3cf0515232720de76b9fbd6614465d97` |
| Family label | `Mirai` |
| File name | `nz.arc` |
| File type | `elf` |
| First seen | `2026-07-08 01:48:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `872047b160183098f6cb683fbd602505` |
| SHA-1 | `59909de7e6bc5344cfd97836ffdb92f311fbc730` |
| SHA-256 | `490ea48be8568beaaa07f1f269b482fa3cf0515232720de76b9fbd6614465d97` |
| SHA3-384 | `8078281c6a8e81133e2d7cbdcf948db46ba1ca54f478c9eabae6a1e2d1577dc99c89fe917eb8afc9a86385312bfe1da4` |
| TLSH | `T166E3BE97F6472092C96302F407CB6BCD2E6362825F9BD9E7AD2F753B19360DB1402792` |
| SSDEEP | `3072:jfpcpGAcRtyMNJYPpQZE9wXyQbaYOdHgu7qq:jgGF7CIXfq7qq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_490ea48b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "490ea48be8568beaaa07f1f269b482fa3cf0515232720de76b9fbd6614465d97"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:13"
  condition:
    hash.sha256(0, filesize) == "490ea48be8568beaaa07f1f269b482fa3cf0515232720de76b9fbd6614465d97"
}
```

### Sample 25: `2318a3412ad9136d`

| Field | Value |
|---|---|
| SHA-256 | `2318a3412ad9136dc4b997a1159748cd6f15e2cdf9efb861f7461076112e498c` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-08 01:48:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf90d30ab36738d663feb8eec7de6913` |
| SHA-1 | `2439a69764c84ae1e7107972e7f221174f8c1d5e` |
| SHA-256 | `2318a3412ad9136dc4b997a1159748cd6f15e2cdf9efb861f7461076112e498c` |
| SHA3-384 | `f0d07f1d2c77ec1c632599e44c635b80397f586d29f0873fe21f6479e22d2b94f922af6dab5f112bdc22b57042a005c3` |
| TLSH | `T17B135B77E46A5F94C0464170B5648E781F13F5C493832EFB1AA982B154439B8F90EFF9` |
| SSDEEP | `768:SauEhehYyJEEDKR4LrNHHRLW3VIC+locjdwSaCYqw:SaRhg/uE2StxL4VI+ctaCYj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_2318a341
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2318a3412ad9136dc4b997a1159748cd6f15e2cdf9efb861f7461076112e498c"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:11"
  condition:
    hash.sha256(0, filesize) == "2318a3412ad9136dc4b997a1159748cd6f15e2cdf9efb861f7461076112e498c"
}
```

### Sample 26: `8f3e745546f76f64`

| Field | Value |
|---|---|
| SHA-256 | `8f3e745546f76f645ff13164d65a18c60a7e74324ac902bca3c1af0f7b21a40c` |
| Family label | `AgentTesla` |
| File name | `NEW_PURCHASE_ORDER.js` |
| File type | `js` |
| First seen | `2026-07-08 01:46:38` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2186779b8b0ea0d203aa817c8691c3e1` |
| SHA-1 | `baa9f746c6149076b4dfa113c519a803920d96f1` |
| SHA-256 | `8f3e745546f76f645ff13164d65a18c60a7e74324ac902bca3c1af0f7b21a40c` |
| SHA3-384 | `292761267978e490a8f71a0c119da09063eaf002e8710c5672fbcff95128d8cdc46511a0ce76a1b37f189c924a81d4b4` |
| TLSH | `T1F75501055EC07F74CFE9662950FE161EE3B04D8A5019A989FB23FD4AFFA7B04511B288` |
| SSDEEP | `24576:gBjPi2oTNs1rxI1DpMS2vpJ/YotvOGRDyMlybagD/bveEr:YB+gIENhN89r` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_026_8f3e7455
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f3e745546f76f645ff13164d65a18c60a7e74324ac902bca3c1af0f7b21a40c"
    family = "AgentTesla"
    file_name = "NEW_PURCHASE_ORDER.js"
    file_type = "js"
    first_seen = "2026-07-08 01:46:38"
  condition:
    hash.sha256(0, filesize) == "8f3e745546f76f645ff13164d65a18c60a7e74324ac902bca3c1af0f7b21a40c"
}
```

### Sample 27: `b072f91c6091716c`

| Field | Value |
|---|---|
| SHA-256 | `b072f91c6091716c3300189e14c3a0d6b6f52b3f1a2baf36f8df5456275da4a0` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-08 01:37:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47178cb8fae3cf048f7f335357f74c97` |
| SHA-1 | `946377d83f555083d5991171033c0a20c8cce0bb` |
| SHA-256 | `b072f91c6091716c3300189e14c3a0d6b6f52b3f1a2baf36f8df5456275da4a0` |
| SHA3-384 | `6d4e14f2a87b157ee8ec717970849063b97fecd3f8b60a7dbe724a5df07a0cc1a451e6a64a0f81b864962f4d92715594` |
| TLSH | `T11A233A02721C0B57C0A35A70263F57D09BBFEAD022E4F685665F5BAA8A35D371482FCD` |
| SSDEEP | `768:LcI0yS1+wRl+RjHR4GtKDHdzzVECjOELqxVNKywesIFAGsawRH:h0hexGHMGTYK2sICPzd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_b072f91c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b072f91c6091716c3300189e14c3a0d6b6f52b3f1a2baf36f8df5456275da4a0"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-08 01:37:55"
  condition:
    hash.sha256(0, filesize) == "b072f91c6091716c3300189e14c3a0d6b6f52b3f1a2baf36f8df5456275da4a0"
}
```

### Sample 28: `5293f5c2af79144e`

| Field | Value |
|---|---|
| SHA-256 | `5293f5c2af79144e8643cbdfd3ecd913eb5687551ee91376e6416c9624f7c96d` |
| Family label | `unknown` |
| File name | `x` |
| File type | `sh` |
| First seen | `2026-07-08 01:35:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24b5d77a8c8a667787848bbbab1ef1fc` |
| SHA-1 | `27a221b763380b88e66cb54992d34a1d6a739dc1` |
| SHA-256 | `5293f5c2af79144e8643cbdfd3ecd913eb5687551ee91376e6416c9624f7c96d` |
| SHA3-384 | `ddf9d7fdca1f1b6e2926db0f32d946f0ff1d25d4a2feac1cf12050639ac075ad567b73cce57e36f3d2035507d109af7e` |
| TLSH | `T1C2C2F1F1F8ECA435369D853ABB9CA805A9DF7C2F4DAB7D2014175938421CB1DA019B3E` |
| SSDEEP | `384:NV9bud3s15u7isjsKG6q/A4UAbMdhQuW57:tQs5lUMdUA4z4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_5293f5c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5293f5c2af79144e8643cbdfd3ecd913eb5687551ee91376e6416c9624f7c96d"
    family = "unknown"
    file_name = "x"
    file_type = "sh"
    first_seen = "2026-07-08 01:35:52"
  condition:
    hash.sha256(0, filesize) == "5293f5c2af79144e8643cbdfd3ecd913eb5687551ee91376e6416c9624f7c96d"
}
```

### Sample 29: `e232ea3c0d93fb98`

| Field | Value |
|---|---|
| SHA-256 | `e232ea3c0d93fb985c774ac8dcb41cc6c2301ab7f06a5054fbf25c14d839ac1c` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-08 01:35:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1e05ecbc76b7deaf290e6d93fce272d` |
| SHA-1 | `b4c377d4ba45bacca077015a2cdbdb44b9992295` |
| SHA-256 | `e232ea3c0d93fb985c774ac8dcb41cc6c2301ab7f06a5054fbf25c14d839ac1c` |
| SHA3-384 | `7566ba080fffbedee986fa4f25ed29e49e84230b93be7a6abe9e1d42a4f7cd7cfa7f3eab5f4631c9daa4d0aeffe3c38b` |
| TLSH | `T134A2CF50BA662F91DFFA39F4C8A8EAC037916F8C77C5CEA33C9517211F04412261ABD9` |
| SSDEEP | `384:gZb1DeKoPW9YaOBlu1sCZDEcsFNeLdkEtCzJTtZjSigcOpbxHSM4uVcqgw05VxJ7:8bsK39YaO/axo3GyEtC5fSigNxHJ4uVu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_e232ea3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e232ea3c0d93fb985c774ac8dcb41cc6c2301ab7f06a5054fbf25c14d839ac1c"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-08 01:35:46"
  condition:
    hash.sha256(0, filesize) == "e232ea3c0d93fb985c774ac8dcb41cc6c2301ab7f06a5054fbf25c14d839ac1c"
}
```

### Sample 30: `04091fb5f36bccd3`

| Field | Value |
|---|---|
| SHA-256 | `04091fb5f36bccd38e322b8201b8cb4dccb97934faad702686bce72a155a7be4` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-08 01:29:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d230b6e5f564595a56afde31f8f57c57` |
| SHA-1 | `38168244f4fcf3388cd0e6593989648f38020ce3` |
| SHA-256 | `04091fb5f36bccd38e322b8201b8cb4dccb97934faad702686bce72a155a7be4` |
| SHA3-384 | `bffa8a8c388112153038c53e4d3f6961d6692e2017f04d95c47e0e72f26d8de805bc9e60b19e720fe4e50053cb74d20c` |
| TLSH | `T1D7F3F805BB610EF7E85FCC3706E9270128CDA51622B97B36B534D958F64B28B26E3D70` |
| SSDEEP | `3072:ldrx+vzsw8TONAdQLty5l6Gm7UxbiuyZ6RlPP4FQQm8DrfIHm:lJx+vzXUONAdQLtKlTm7UxbiuyZ6RlPI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_04091fb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04091fb5f36bccd38e322b8201b8cb4dccb97934faad702686bce72a155a7be4"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-08 01:29:20"
  condition:
    hash.sha256(0, filesize) == "04091fb5f36bccd38e322b8201b8cb4dccb97934faad702686bce72a155a7be4"
}
```

### Sample 31: `7351070d88ba2bdd`

| Field | Value |
|---|---|
| SHA-256 | `7351070d88ba2bddfc44f0aba506065fba845d18804d716a7a5c64cecd74e3cc` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-08 01:29:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `221723bfbea08427586cd769c43065ca` |
| SHA-1 | `9ddc53e8adb91594d1f1a944137ef7d29b9397e4` |
| SHA-256 | `7351070d88ba2bddfc44f0aba506065fba845d18804d716a7a5c64cecd74e3cc` |
| SHA3-384 | `8ebdb8935053c92f5145e5c1b40ee3913e20e9eeaecfe8f64b929ac2e69fe30ea859a55e0687fe9812660c35be9b58fa` |
| TLSH | `T19433E807B94281FDC05AC174066FBA3ED926B5FE1338F1E67BD4B6322C95E215E19C48` |
| TELFHASH | `t1361197a229225850f1e3f4626b43e0244d750f2560d176fae6b2b9f79b10f420bbac27` |
| SSDEEP | `1536:+I9ZDyBGhPbbNBA1Exvpy5v0PYWmC2O6AOwV:z9ZeBGhPbZK1qBIv0PYfOiwV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_7351070d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7351070d88ba2bddfc44f0aba506065fba845d18804d716a7a5c64cecd74e3cc"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-08 01:29:07"
  condition:
    hash.sha256(0, filesize) == "7351070d88ba2bddfc44f0aba506065fba845d18804d716a7a5c64cecd74e3cc"
}
```

### Sample 32: `4b86b1ccd44841f0`

| Field | Value |
|---|---|
| SHA-256 | `4b86b1ccd44841f0639b8946d9fae2f82e8b759e22cb412a0f6e3ec326737052` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-08 01:28:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fa5387460298364bb31a32a71cb8820` |
| SHA-1 | `547b3fb183152ad2b8ed813fe59444a236968fbf` |
| SHA-256 | `4b86b1ccd44841f0639b8946d9fae2f82e8b759e22cb412a0f6e3ec326737052` |
| SHA3-384 | `23d11ee8e36f1daf6a3b8b0d238aa322276d42ee9e1b4eda6ff59f6762f02a02797248ece6874ca45fb394a8482dd9ab` |
| TLSH | `T14933F1EBEA1B38C48ABC497D96DD6B755B5220F47137A35CC7952C4C530ABB83A9E00C` |
| SSDEEP | `768:c4MsSKFz9Q3V71gRjZ6G7wxPiix0RGuoFhrzwexQa0fvIY0JjKE67PMHN15CiPoR:/FFOh157E81u+Wex5MX0J+E6Axx6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_4b86b1cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b86b1ccd44841f0639b8946d9fae2f82e8b759e22cb412a0f6e3ec326737052"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:16"
  condition:
    hash.sha256(0, filesize) == "4b86b1ccd44841f0639b8946d9fae2f82e8b759e22cb412a0f6e3ec326737052"
}
```

### Sample 33: `6196d48e1cb75190`

| Field | Value |
|---|---|
| SHA-256 | `6196d48e1cb751908020b6f3a04c69855ddb4b7eb4c5003f22185ff5f52a156d` |
| Family label | `unknown` |
| File name | `kworkerd-blkcg` |
| File type | `elf` |
| First seen | `2026-07-08 01:28:14` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fa53a84be3a6d89f430b34222117979` |
| SHA-1 | `71b4cb32c465381a1be8badf722e5b60c56c0d06` |
| SHA-256 | `6196d48e1cb751908020b6f3a04c69855ddb4b7eb4c5003f22185ff5f52a156d` |
| SHA3-384 | `07a0e0e6815b6d0b6f1ded8b59f1e0f819121742bf7c6e9366468e5fdce8d4a95605f78100b66595913f3a7ddbb56da9` |
| TLSH | `T1C6442919BD419F02C5D126FAFBAE8299331B7BB8D3EE7112E9105F60338A58F0F66151` |
| TELFHASH | `t1c3d0a767100794c4f214d94001ef13051b7de62f662bb4c115c21ff88d501a2c4e5712` |
| SSDEEP | `6144:uQ/Lzg2dHcjSN0spipPqZclV7sgAVfZ/nbh30abIqpU4PAZdtiI4ZYUE9e:zA2JbpipPqSDI3x/nbhEab5U4PAZTEZE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_6196d48e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6196d48e1cb751908020b6f3a04c69855ddb4b7eb4c5003f22185ff5f52a156d"
    family = "unknown"
    file_name = "kworkerd-blkcg"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:14"
  condition:
    hash.sha256(0, filesize) == "6196d48e1cb751908020b6f3a04c69855ddb4b7eb4c5003f22185ff5f52a156d"
}
```

### Sample 34: `477948f3000fcffc`

| Field | Value |
|---|---|
| SHA-256 | `477948f3000fcffc496816eb3688faf63f9969d15211ce647f0bba17c25867b5` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-08 01:28:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9dbf497d03d001a1e2ff0dafb4e20dd` |
| SHA-1 | `a357cbadc7a35f3c6c9509be060b3ecdd0b1b9c9` |
| SHA-256 | `477948f3000fcffc496816eb3688faf63f9969d15211ce647f0bba17c25867b5` |
| SHA3-384 | `379ad6d4bae2c46b56f9757604866de22ee9e6be87e3ba1a136deb48ac73949341b93f95c73cd7666f9435f1c26ca04b` |
| TLSH | `T163B2D1D84E85009BEDA145BA1BF407607FB91BB89543DE0AE50AF217DFCA1E07553AC3` |
| SSDEEP | `384:r6jz4ptun3MEHBRp0HI7GOLNPKVrzbm06bIzHV8mQfRqG5ilcjLcXnQJgGlzDpHq:2f4p6Ma/RJ5x06shFGJgGlzDpbuR1JD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_477948f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "477948f3000fcffc496816eb3688faf63f9969d15211ce647f0bba17c25867b5"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:13"
  condition:
    hash.sha256(0, filesize) == "477948f3000fcffc496816eb3688faf63f9969d15211ce647f0bba17c25867b5"
}
```

### Sample 35: `ec184ac73eb46121`

| Field | Value |
|---|---|
| SHA-256 | `ec184ac73eb461219a481eefff4b6406c88fde59b8074859ddb1a66ade533e33` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-08 01:28:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16b728683d0995c97c9a0d05eae00733` |
| SHA-1 | `7460387e55f888a8228401a876a8c9293b28a7d3` |
| SHA-256 | `ec184ac73eb461219a481eefff4b6406c88fde59b8074859ddb1a66ade533e33` |
| SHA3-384 | `f397655ca2b4989aae2a038b8762cfcdb9a2df0ea1e8873e9b4650dfcf528d9d4ca43b8a204603cf806e7d4852b8d8d6` |
| TLSH | `T183A2E0BFF38D6B22F1D343304C62290DE5E2D753DBA63A0DA51A26D413ABD10E538561` |
| SSDEEP | `384:vwMGfqOYJvDbU4eL40GmRvqBjntatfpioB8XiHF8hn5l9Emm3C2cviFqcJO:vqfq3Q4PiMstf0oBOHN2m4Gsk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_ec184ac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec184ac73eb461219a481eefff4b6406c88fde59b8074859ddb1a66ade533e33"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:11"
  condition:
    hash.sha256(0, filesize) == "ec184ac73eb461219a481eefff4b6406c88fde59b8074859ddb1a66ade533e33"
}
```

### Sample 36: `0203c5c6f6ecbcfa`

| Field | Value |
|---|---|
| SHA-256 | `0203c5c6f6ecbcfa7eb83c7e9cd222635643a587637b9c538740ad687cc0d5cf` |
| Family label | `Mirai` |
| File name | `kworkerd-irq-bal` |
| File type | `elf` |
| First seen | `2026-07-08 01:28:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f44c63eaaaa7454f1cd7824e4161791` |
| SHA-1 | `d03d17a02335cb6817b6b4f335ac63675b24f2f4` |
| SHA-256 | `0203c5c6f6ecbcfa7eb83c7e9cd222635643a587637b9c538740ad687cc0d5cf` |
| SHA3-384 | `8864256cc50b276f29fc31e918b3fda4e266010f01bda51511b32368f0c46422782fe6a72e884b01cbc3cd478232837c` |
| TLSH | `T1E0440856BE419F17C5D216F7FBAE4298371A7BA8C6EE3112D8146F90339B48F0E36241` |
| TELFHASH | `t1e3d022b2001f61c2f201c99844ce0a88c8d0c037db19abe4a0f83cbf86e04e020b2b03` |
| SSDEEP | `6144:oeDgeaqNQCLxQQmKwuoP724teXTAa9Ulsk8yB209X:oeOqNBLxpu24t8Lbk/209` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_0203c5c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0203c5c6f6ecbcfa7eb83c7e9cd222635643a587637b9c538740ad687cc0d5cf"
    family = "Mirai"
    file_name = "kworkerd-irq-bal"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:10"
  condition:
    hash.sha256(0, filesize) == "0203c5c6f6ecbcfa7eb83c7e9cd222635643a587637b9c538740ad687cc0d5cf"
}
```

### Sample 37: `05686c56837324d1`

| Field | Value |
|---|---|
| SHA-256 | `05686c56837324d1bbb9b98c331bd689af81de4a27c52a4d84ace7e25302e111` |
| Family label | `Gafgyt` |
| File name | `kworkerd` |
| File type | `elf` |
| First seen | `2026-07-08 01:28:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54f0648f2e7cee0cb382eec995843eb2` |
| SHA-1 | `d2f5dbec007fc5ab00891651aaf56e1feefd9b63` |
| SHA-256 | `05686c56837324d1bbb9b98c331bd689af81de4a27c52a4d84ace7e25302e111` |
| SHA3-384 | `7882bb37db6b74eb5db808aefabc267b401350f3ef0dd31cae4bef0db320d52f2f5a81ab71692d6b021deef044a0fa2a` |
| TLSH | `T1AE445B036580D5BAC487D0B5CBDFA2274961783D5C7A724B27A07FA23F4AEB05B19B13` |
| TELFHASH | `t195a1ad301895305172d3c5467607ea3dbd350864d7ed76f9bad3b8f8ac9ba804da2c3a` |
| SSDEEP | `6144:+Oq94BgLBMx0E/bJghAzZ6DvFc9NqHH9JLOf9E5:VyEgFMx0E/bJghAYvFc98HH9y9E5` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_037_05686c56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05686c56837324d1bbb9b98c331bd689af81de4a27c52a4d84ace7e25302e111"
    family = "Gafgyt"
    file_name = "kworkerd"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:08"
  condition:
    hash.sha256(0, filesize) == "05686c56837324d1bbb9b98c331bd689af81de4a27c52a4d84ace7e25302e111"
}
```

### Sample 38: `cab38a319673fd9b`

| Field | Value |
|---|---|
| SHA-256 | `cab38a319673fd9b4c336423781b32cc9128250e2acc1cd0a5bc06ade673e40a` |
| Family label | `Mirai` |
| File name | `kworkerd-crypto` |
| File type | `elf` |
| First seen | `2026-07-08 01:28:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9b5e7d3b7cee282d18e8426b06d4c1c` |
| SHA-1 | `620da0b7576e0177006f5f9709d7bef86c68087c` |
| SHA-256 | `cab38a319673fd9b4c336423781b32cc9128250e2acc1cd0a5bc06ade673e40a` |
| SHA3-384 | `c1ffdcf4fa915af85456d07b2925b3b0a3d66ecc6ff8457617c4730c372b0a550e59b8a85f8a291fb067d7bafbb32b02` |
| TLSH | `T1EB348D67ED329F86C022A8F5B1F2CF780F16BD3A49471E999576E9B08183DD8B601374` |
| SSDEEP | `6144:+w678vQLz7EpN6eG9LPYejb6Ki7i+1uv:+wdvQv7EpN6eTejb6viVv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_cab38a31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab38a319673fd9b4c336423781b32cc9128250e2acc1cd0a5bc06ade673e40a"
    family = "Mirai"
    file_name = "kworkerd-crypto"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:06"
  condition:
    hash.sha256(0, filesize) == "cab38a319673fd9b4c336423781b32cc9128250e2acc1cd0a5bc06ade673e40a"
}
```

### Sample 39: `10c76163201a46c7`

| Field | Value |
|---|---|
| SHA-256 | `10c76163201a46c7a7e5df1f2bb2d25bd79bc348baba7c17ee46bd4eef5148f6` |
| Family label | `Mirai` |
| File name | `kworkerd-events` |
| File type | `elf` |
| First seen | `2026-07-08 01:25:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3725c717fafe309bc1e83ecc124c693` |
| SHA-1 | `b49563ff1ddcb83890bea4a621d3116c381b1a14` |
| SHA-256 | `10c76163201a46c7a7e5df1f2bb2d25bd79bc348baba7c17ee46bd4eef5148f6` |
| SHA3-384 | `7b1f7fa3c762974f286aa997193323ae27a405aa8cb69bc032cbbbc2589f3c16c9140dc14be58b82ab6ae57a85ec69ab` |
| TLSH | `T136246D43AA43DAF2E01315B112E79B665A32FC3A0C2FC5C6E7653DA1CDA11C4A716B3D` |
| TELFHASH | `t139b18ef22e5a16f973e49d43930f2b12ee4ac56b6d6421f601f325d632f6e02537143a` |
| SSDEEP | `3072:QHW83e61SCSGGH4s0j4Azl2J5FFFboLMeexI36rozh37eQ/EogR1O:ue6DtFs0jS1/s3bzhC4EoU1O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_10c76163
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10c76163201a46c7a7e5df1f2bb2d25bd79bc348baba7c17ee46bd4eef5148f6"
    family = "Mirai"
    file_name = "kworkerd-events"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:45"
  condition:
    hash.sha256(0, filesize) == "10c76163201a46c7a7e5df1f2bb2d25bd79bc348baba7c17ee46bd4eef5148f6"
}
```

### Sample 40: `7e1c84a430b80218`

| Field | Value |
|---|---|
| SHA-256 | `7e1c84a430b802180aff2c1e2aa1eca1bc5361f9040c5eb801b34b3517aabba9` |
| Family label | `unknown` |
| File name | `kworkerd-softirq` |
| File type | `elf` |
| First seen | `2026-07-08 01:25:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2aa9abbdf7a03ab53f37c077f61e7d9` |
| SHA-1 | `65904986ded7f8135fc7e5d0cf0f4af1cb46a068` |
| SHA-256 | `7e1c84a430b802180aff2c1e2aa1eca1bc5361f9040c5eb801b34b3517aabba9` |
| SHA3-384 | `5020a2b78c7aa69b6ad238bff7d04e3466a6fe0fd07c453dcf510413304f0e3fb8e1235e75b492f1db1f0f042e3ca3b6` |
| TLSH | `T18F541916AD419B02C1D116FAFF6E829A33173FB8D2DE3112DD246FA4378A49F0E7A151` |
| TELFHASH | `t121d0a908442ca4e0f3809a4188da33208168e10baf43a08004c02d8dc9a28e1b0eae0b` |
| SSDEEP | `6144:++/xamiWDaapJ02VxEhWCGNnntX6F7x5af62GZoA44PNWUu0Dv:BV902Vxmb8ntXQ5afeR44PNRL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_7e1c84a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e1c84a430b802180aff2c1e2aa1eca1bc5361f9040c5eb801b34b3517aabba9"
    family = "unknown"
    file_name = "kworkerd-softirq"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:43"
  condition:
    hash.sha256(0, filesize) == "7e1c84a430b802180aff2c1e2aa1eca1bc5361f9040c5eb801b34b3517aabba9"
}
```

### Sample 41: `4dc47959cb6437a9`

| Field | Value |
|---|---|
| SHA-256 | `4dc47959cb6437a9de370647fcc8bc63c2882def695e008536b539152acd103c` |
| Family label | `unknown` |
| File name | `kworkerd-rcu` |
| File type | `elf` |
| First seen | `2026-07-08 01:25:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7421638659b5dcfebf10a8a2b6ae7c71` |
| SHA-1 | `4435c18465ec0dc7fbf3ef41aa6bc038473bc71b` |
| SHA-256 | `4dc47959cb6437a9de370647fcc8bc63c2882def695e008536b539152acd103c` |
| SHA3-384 | `3d5af6e027bf1dd39073bdf752421b2cd4f01cb8419aae81efec4c06f9419d5f46d9e9af0d45f17511abaf4f57bc73e2` |
| TLSH | `T1EB84235BB102F80AD84D58F238A3C6293D887F1E67632E08D175E9BC3B495FF5491A9C` |
| SSDEEP | `6144:F7nSu4LTS7cnSvChIZtwFcfFyni9GTfnrdeXNBb7WpvGeDHG6ydmljryvDiHa4O:NSugS6LF74GXdGNleVmvmlSvDiHa4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_4dc47959
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dc47959cb6437a9de370647fcc8bc63c2882def695e008536b539152acd103c"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:41"
  condition:
    hash.sha256(0, filesize) == "4dc47959cb6437a9de370647fcc8bc63c2882def695e008536b539152acd103c"
}
```

### Sample 42: `2081580b46e6903e`

| Field | Value |
|---|---|
| SHA-256 | `2081580b46e6903e856f457ee1511c1a89d571a2285e2f227308fafc402db71c` |
| Family label | `unknown` |
| File name | `kworkerd-netns` |
| File type | `elf` |
| First seen | `2026-07-08 01:25:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e24da9195399831f986432b6f5c766f7` |
| SHA-1 | `752ea337bb50fdb53de3893188499abc73982d9f` |
| SHA-256 | `2081580b46e6903e856f457ee1511c1a89d571a2285e2f227308fafc402db71c` |
| SHA3-384 | `cc460fd6e7a84f2e8df0e77c0058e8c49f40224167b99eb823109c4d416eee9719628313441836d96a7683031dec3c45` |
| TLSH | `T1A38422FB5823A4DBF296943579B3C628360C37867E422848BBBEADC10F2D5AC5D453C5` |
| TELFHASH | `t192d00224587813b052cd8c6e55dceb08a860a5e7aaa31d1fdd94c899ea26e4b9d01d2c` |
| SSDEEP | `6144:UHhGHABxUR4fAGAPF83McRxccQ3TwCeiyTthE8SZuGHc9yWYfBxx+SuxQKt96snh:9gB+PFQ23aiyRhWlAyZ4xh1crH4XZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_2081580b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2081580b46e6903e856f457ee1511c1a89d571a2285e2f227308fafc402db71c"
    family = "unknown"
    file_name = "kworkerd-netns"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:39"
  condition:
    hash.sha256(0, filesize) == "2081580b46e6903e856f457ee1511c1a89d571a2285e2f227308fafc402db71c"
}
```

### Sample 43: `ae5946d2ee25fbdb`

| Field | Value |
|---|---|
| SHA-256 | `ae5946d2ee25fbdbd341d3909c8226d3152376d2b68e523cbb323bccf29a0481` |
| Family label | `unknown` |
| File name | `kworkerd-netns-rt` |
| File type | `elf` |
| First seen | `2026-07-08 01:25:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92709ceeee5228c3dc87b9f5e8aac524` |
| SHA-1 | `743ec272e7a263d1cefb6c8646fb10efb2880c30` |
| SHA-256 | `ae5946d2ee25fbdbd341d3909c8226d3152376d2b68e523cbb323bccf29a0481` |
| SHA3-384 | `aa653a63ac45c37a13b8767acad84a9daae08b15d43f6a48043bb876889b7fe9b478de40877b2d20a7901087d74c6cde` |
| TLSH | `T1978423C49432990EE5AA48BFEEFF83B96B98F5551BC128C4C52CED460F2419D804E7EC` |
| TELFHASH | `t13ad01230043403b0d18dcc1d05dcfb0868a071eba5510c1fca84c89096609475d00c2c` |
| SSDEEP | `6144:JT1rObSMsvymUnNSBqEsKA0tju+YoLJdyKeDdjnJilzQggF5xF2iQuGIWXnzIjnz:DVJDw3EsKAT+YojxonJipQzxF2OuXBYl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_ae5946d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae5946d2ee25fbdbd341d3909c8226d3152376d2b68e523cbb323bccf29a0481"
    family = "unknown"
    file_name = "kworkerd-netns-rt"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:36"
  condition:
    hash.sha256(0, filesize) == "ae5946d2ee25fbdbd341d3909c8226d3152376d2b68e523cbb323bccf29a0481"
}
```

### Sample 44: `0b6f085766781229`

| Field | Value |
|---|---|
| SHA-256 | `0b6f0857667812293553e16851e032db675666ee17b52385fb33dc0a6c60f24d` |
| Family label | `Mirai` |
| File name | `kworkerd-irq` |
| File type | `elf` |
| First seen | `2026-07-08 01:25:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cb584fbe20a10a90fab49bb29467fd6` |
| SHA-1 | `14328faa3df136fcee12c6403406065a7184e45f` |
| SHA-256 | `0b6f0857667812293553e16851e032db675666ee17b52385fb33dc0a6c60f24d` |
| SHA3-384 | `508e45a4ed4c446ae62e2ba38996dc39f82c56df389a84fd6dd926bee75945f84f9db9fee6aa1f02177def33993b6970` |
| TLSH | `T14D44F85ABD419F17C6D216F7FBAE4288371A7BA8C6EE3113D8146F50339B48F0E26251` |
| TELFHASH | `t14ed02202001b16c7f2090cb551ea13698ccc943f4e26ab98e2ea2cfa0c929e010b1e07` |
| SSDEEP | `6144:m5iqxCLQPTeAAQi7XNHVF45Ur2jSHACGCj2o3q:m5sLITnyVF4OkATN3q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_0b6f0857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b6f0857667812293553e16851e032db675666ee17b52385fb33dc0a6c60f24d"
    family = "Mirai"
    file_name = "kworkerd-irq"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:34"
  condition:
    hash.sha256(0, filesize) == "0b6f0857667812293553e16851e032db675666ee17b52385fb33dc0a6c60f24d"
}
```

### Sample 45: `1f152c19dab01a89`

| Field | Value |
|---|---|
| SHA-256 | `1f152c19dab01a8928ac2f7fc48e69c742983e05ce5b98437a88c7f3967854d4` |
| Family label | `unknown` |
| File name | `kworkerd-writeback` |
| File type | `elf` |
| First seen | `2026-07-08 01:25:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9392643d268f3d02370be753947c51e1` |
| SHA-1 | `dabd56a3edfa13c3d91ccba1a3db5845f3eb1e4d` |
| SHA-256 | `1f152c19dab01a8928ac2f7fc48e69c742983e05ce5b98437a88c7f3967854d4` |
| SHA3-384 | `51ee2c1d2c65e80e300d0c5a139c8fd2f28cc4e06cd4ffe7eb8fa75443ba5da88db8170d7f8f4efb3c2a4bca436922df` |
| TLSH | `T1FD543A02FB1C0E03E1272EF0263B87F197DFA9A12DB4B640695EBEC54273D71A545AC9` |
| SSDEEP | `6144:fSGhpUkufLSkbp6egFmEGIsBx9c4mFL5FwjcOc0Uo:f3pUk4zbXg0jXcvD6jrUo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_1f152c19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f152c19dab01a8928ac2f7fc48e69c742983e05ce5b98437a88c7f3967854d4"
    family = "unknown"
    file_name = "kworkerd-writeback"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:32"
  condition:
    hash.sha256(0, filesize) == "1f152c19dab01a8928ac2f7fc48e69c742983e05ce5b98437a88c7f3967854d4"
}
```

### Sample 46: `0dcf6d7ee47fb371`

| Field | Value |
|---|---|
| SHA-256 | `0dcf6d7ee47fb371d7ebbca1d4f62d4707514237215d8044e588783cf0aae1bb` |
| Family label | `Mirai` |
| File name | `nz.sh4` |
| File type | `elf` |
| First seen | `2026-07-08 01:25:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9665df56a7849acaab86694a8c4b5c79` |
| SHA-1 | `e4b64b2f9c47280aa43a6578519b75b6f4741aa7` |
| SHA-256 | `0dcf6d7ee47fb371d7ebbca1d4f62d4707514237215d8044e588783cf0aae1bb` |
| SHA3-384 | `3233f15f6d012ea26ffbebc61bbe137efdd9b286a547cf684c721b2316bf2bcfdc6c78d79a25b5f136d1c56bc8d4014c` |
| TLSH | `T17BB3AE36E81968F4C07E8574E5A4BE790BA3F48052931EF716E6C6B65047EE4F806BF0` |
| SSDEEP | `1536:t/juy48gLDajwrmRZ2QprowQi1YKiC7p74Pe/9C/6otd1pHB:t7uy7eaMYZProwQi1fiQye/93efpHB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_0dcf6d7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dcf6d7ee47fb371d7ebbca1d4f62d4707514237215d8044e588783cf0aae1bb"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:29"
  condition:
    hash.sha256(0, filesize) == "0dcf6d7ee47fb371d7ebbca1d4f62d4707514237215d8044e588783cf0aae1bb"
}
```

### Sample 47: `95fb2c80e84f84f6`

| Field | Value |
|---|---|
| SHA-256 | `95fb2c80e84f84f6dfb95d31d9c3baa1e22735f8951ed9024a88deebd839a0af` |
| Family label | `Mirai` |
| File name | `nz.m68k` |
| File type | `elf` |
| First seen | `2026-07-08 01:21:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa3078695c65f03ff363751ecd8286d5` |
| SHA-1 | `a20d49bda4adbe99af42ed309772696e9b661fee` |
| SHA-256 | `95fb2c80e84f84f6dfb95d31d9c3baa1e22735f8951ed9024a88deebd839a0af` |
| SHA3-384 | `3b90c11a9faa18954db39b6a615586f1a4cebc0001f04e6b3033b0e0676617ffc28ee421fb0c7419402d1208dbaf4bc9` |
| TLSH | `T120C34B9AB4019D3DF94FD57B58632D1ABD20A3925183272A639BFD93AC321F47C02F85` |
| SSDEEP | `3072:XjXiHb1ZoCGRs0rBlpUjeZ5JqieX8KJFLOTs:TSHbPoCGRHqCZrquKJFLOTs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_95fb2c80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95fb2c80e84f84f6dfb95d31d9c3baa1e22735f8951ed9024a88deebd839a0af"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-07-08 01:21:17"
  condition:
    hash.sha256(0, filesize) == "95fb2c80e84f84f6dfb95d31d9c3baa1e22735f8951ed9024a88deebd839a0af"
}
```

### Sample 48: `5f6fd4e77c577137`

| Field | Value |
|---|---|
| SHA-256 | `5f6fd4e77c577137130fe0777ff434fac5dfb03908a6e094fc3fb33cc39fb189` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-08 01:12:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f0a327908e91cb8c292a0d117af07e4` |
| SHA-1 | `a526a7717df077b5e56fd261964594453b054933` |
| SHA-256 | `5f6fd4e77c577137130fe0777ff434fac5dfb03908a6e094fc3fb33cc39fb189` |
| SHA3-384 | `885a6856f4a752b001a23ea6fdf05ba937ef9ca75b0f1d3a9ab3ef3962e61c6372a995b0fcc6c011bf26bc92a248dddf` |
| TLSH | `T124C32BC0F98B81F6C40B88305166F73FDB7198A95123DA9DEF999F72DA73582912234C` |
| TELFHASH | `t1843124b1f9b21eec5bd08803c6cf4b02ec0de6bb356021bd09fa1a5032b2151517ac3a` |
| SSDEEP | `3072:6FjlzYNVoZXRgn4c30tItERjnDBBMesWrhK8H1:mYNVoZhkD3OItYzDjw8H1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_5f6fd4e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f6fd4e77c577137130fe0777ff434fac5dfb03908a6e094fc3fb33cc39fb189"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-08 01:12:47"
  condition:
    hash.sha256(0, filesize) == "5f6fd4e77c577137130fe0777ff434fac5dfb03908a6e094fc3fb33cc39fb189"
}
```

### Sample 49: `c18a7f266c4e1ad9`

| Field | Value |
|---|---|
| SHA-256 | `c18a7f266c4e1ad9447389bb6911539cda1b59a03d795c7932070aee5fc27ee2` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-08 01:11:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `accbdfd3ef6223ea852cc6ae6bd76e85` |
| SHA-1 | `17d5663ecb7440b165af6652967a6c904ca94a54` |
| SHA-256 | `c18a7f266c4e1ad9447389bb6911539cda1b59a03d795c7932070aee5fc27ee2` |
| SHA3-384 | `16176812c642d713ef20b8f87fd75882b8109f4ca71706d1ef9539da66e91759c86cdbba264efa7d6a571d0b9f904e9b` |
| TLSH | `T16223F12811F66E65B21B86F7195EFB1E2B2471052721D5C735E0E070D6E3B3A0F2C7AA` |
| SSDEEP | `768:mYcUTiSFnR+ZW54r03UK12jc8/xCrNhRQeccxdk05pHFFGxhUWVuA5pMuMwcnbcY:mYcUTiMnR+1rKm9gTRRcyplFGxn3563N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_c18a7f26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c18a7f266c4e1ad9447389bb6911539cda1b59a03d795c7932070aee5fc27ee2"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-08 01:11:42"
  condition:
    hash.sha256(0, filesize) == "c18a7f266c4e1ad9447389bb6911539cda1b59a03d795c7932070aee5fc27ee2"
}
```

### Sample 50: `32884e5b3f5005b8`

| Field | Value |
|---|---|
| SHA-256 | `32884e5b3f5005b89af62bb44fab9e112e59f5c97fe465efc99702627cced30a` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-08 01:08:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f475387fbcc555e6c7a1d2278ba79370` |
| SHA-1 | `ab22344537e74b478c0b334da94c6078475aa3a4` |
| SHA-256 | `32884e5b3f5005b89af62bb44fab9e112e59f5c97fe465efc99702627cced30a` |
| SHA3-384 | `7143758126f086c7041f09a44c66f9fc19c5742f34a8be0a7e02fe57b6f74109690c4aa257705eea8dea242f1b5bfd1c` |
| TLSH | `T117133AC8F543D8F5D85705702137EB37AF72F1F62229E653D3A49633AC92A02E90699C` |
| TELFHASH | `t1c811efb61eab09fcfbd0a988d76f47c35b39d9631a3169b480f928503bf16419436436` |
| SSDEEP | `768:r8ZB4sEag3ZTr8VMILNSiXkuEA3Y5MYpv1X7hgHqs:rq2dag3ZTr8VMILNvX/3JYptLhgHX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_32884e5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32884e5b3f5005b89af62bb44fab9e112e59f5c97fe465efc99702627cced30a"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-08 01:08:46"
  condition:
    hash.sha256(0, filesize) == "32884e5b3f5005b89af62bb44fab9e112e59f5c97fe465efc99702627cced30a"
}
```

### Sample 51: `3b5ba0aeaea18d4a`

| Field | Value |
|---|---|
| SHA-256 | `3b5ba0aeaea18d4a15b3959b0ec7fd105d9da813121734d7b3f37929b9a8a9a1` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-08 01:07:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3656c2db63f828021bb59db5b8bc1b29` |
| SHA-1 | `111ee79a7cc9b76abb285e4e2af84f83cbd11e86` |
| SHA-256 | `3b5ba0aeaea18d4a15b3959b0ec7fd105d9da813121734d7b3f37929b9a8a9a1` |
| SHA3-384 | `f77f8a9e5bad49d639a946c50230f2066a2ea3738c98e7bd39923814985234605f56394e4d82b9e525607bff23db6299` |
| TLSH | `T1D492E0F8699D0643DA69C33F322B488FC0A58D68C38C92C95A6C8A5FD683045273D4AE` |
| SSDEEP | `384:MkgKiCWhs1ttJskx81N+EUw/g6cOGrYD8inlRX+v1Rs:WKiCWhgttJv8j/UucZw8inlRgs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_3b5ba0ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b5ba0aeaea18d4a15b3959b0ec7fd105d9da813121734d7b3f37929b9a8a9a1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-08 01:07:57"
  condition:
    hash.sha256(0, filesize) == "3b5ba0aeaea18d4a15b3959b0ec7fd105d9da813121734d7b3f37929b9a8a9a1"
}
```

### Sample 52: `fdef885dbd4fe4d9`

| Field | Value |
|---|---|
| SHA-256 | `fdef885dbd4fe4d9a38821c0eac2d3ea77702ab890debb47c9957908d9398e81` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-07-08 01:06:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5cd6b827eb268d135153bfc6d11a56fe` |
| SHA-1 | `667199bfe223fa94af699662bb8d426ea7c12ab6` |
| SHA-256 | `fdef885dbd4fe4d9a38821c0eac2d3ea77702ab890debb47c9957908d9398e81` |
| SHA3-384 | `c4e010fb71ec7c211960fc0acc4a58d59e5780f9c3418dbf3217c952a5b17bdc4f65db74cf0d7c8b59c1e8bd93ad7368` |
| TLSH | `T1AA23F880F40B86F6D41B487050A7FA3FDF31E4EA51B0D5AEEF999F35DE675029102A88` |
| TELFHASH | `t1ee11e6b71e7644f8b3e5a900c36a26e61875da2715a126f904732cd823e2dc2d0f9c3f` |
| SSDEEP | `768:j5vBkpOrWJyMG2oZpi27BvPIRAz0/EYrQq7og0M6mFm8d8BWY5q6nMspYmLCs:jkUrnMGBZpi0tIRAw/Elhg0JkdeWY5s4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_fdef885d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdef885dbd4fe4d9a38821c0eac2d3ea77702ab890debb47c9957908d9398e81"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-08 01:06:24"
  condition:
    hash.sha256(0, filesize) == "fdef885dbd4fe4d9a38821c0eac2d3ea77702ab890debb47c9957908d9398e81"
}
```

### Sample 53: `42a1f2fa4c787a11`

| Field | Value |
|---|---|
| SHA-256 | `42a1f2fa4c787a112d65ce7382d47c56e4747127ebc6dbef96e27cc2ff4e88f0` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-07-08 01:06:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bec0822fe96acacec2e38251f8b75afb` |
| SHA-1 | `f1c285c7f4d8d4e41b6eb2fa3d1a47bad51d3a5a` |
| SHA-256 | `42a1f2fa4c787a112d65ce7382d47c56e4747127ebc6dbef96e27cc2ff4e88f0` |
| SHA3-384 | `a53875ac36e7e27f4a9b2c0d082dcaade2e1c5a9c01454cb537a3408c1935753a88310f353a13b568fba79dbcbc83bca` |
| TLSH | `T112D32946FC824A22C5D722BEF92D218E331317B8E3DE32129E245F6137C659B0D7BA55` |
| TELFHASH | `t1bbe0205abbac095926c91190a6df760667f87dc612172179c77e871f4452c42782e10f` |
| SSDEEP | `3072:whnw1dzzJI8WseDYgd7IafuDKxyCqiR/oHvM:+nAJI8F7gdMaEtCqUoHvM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_42a1f2fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42a1f2fa4c787a112d65ce7382d47c56e4747127ebc6dbef96e27cc2ff4e88f0"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-08 01:06:16"
  condition:
    hash.sha256(0, filesize) == "42a1f2fa4c787a112d65ce7382d47c56e4747127ebc6dbef96e27cc2ff4e88f0"
}
```

### Sample 54: `3be63fb0d1ddaef2`

| Field | Value |
|---|---|
| SHA-256 | `3be63fb0d1ddaef2a579aa419ce6762d50817620bcf0484e083b1c1952d9964e` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-07-08 01:05:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0aa5a8445b91cc28b4fa1fbb223860ad` |
| SHA-1 | `290f185925c2613bcc5a531ac76cb2bcfbf80899` |
| SHA-256 | `3be63fb0d1ddaef2a579aa419ce6762d50817620bcf0484e083b1c1952d9964e` |
| SHA3-384 | `593cd0109406f151d9a3d25c588949a14919fa760ec1402da0d88468be62556a7b3e66afb4c93ec9bf8885673e58d9d3` |
| TLSH | `T16DA2E068D5D10557C82ED43DE7FE8493C42AE845976F23C8B7EB9627854B819C730A0C` |
| SSDEEP | `384:MtPFIlqax5D9tN4uS61t2qWVl/cMReX1zFGCOHFfx4+fkY669C+v1RKe:P5ptHKLV23l5GCAx4+cd6nKe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_3be63fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3be63fb0d1ddaef2a579aa419ce6762d50817620bcf0484e083b1c1952d9964e"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-08 01:05:22"
  condition:
    hash.sha256(0, filesize) == "3be63fb0d1ddaef2a579aa419ce6762d50817620bcf0484e083b1c1952d9964e"
}
```

### Sample 55: `57a2703848d25574`

| Field | Value |
|---|---|
| SHA-256 | `57a2703848d25574cc777185449251a59ecf6c0a753c510af8da61e26741e8a4` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-07-08 01:05:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c9f698a0e03a3c9cb97c0dc6d9d1371` |
| SHA-1 | `0d38f788b3ac7ab898476ad7665383f9c033ba0b` |
| SHA-256 | `57a2703848d25574cc777185449251a59ecf6c0a753c510af8da61e26741e8a4` |
| SHA3-384 | `4e84cb63350b7aef12dffaf184f09ef2fbbb9e79917126a4f6b80abf2cb93972c5b7b65c224d2fac4488a079294b9d3b` |
| TLSH | `T1DE33F1695C25DB71FA530C71CF19CBC73A1BA7B500A479E3026C8638CBD8A6A5F85883` |
| SSDEEP | `1536:a7DfXSjDmI+ShaNHJG2obod5ZAv0RZVHL1:a7D6/mIlhaNRSq0sRZxL1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_57a27038
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57a2703848d25574cc777185449251a59ecf6c0a753c510af8da61e26741e8a4"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-08 01:05:20"
  condition:
    hash.sha256(0, filesize) == "57a2703848d25574cc777185449251a59ecf6c0a753c510af8da61e26741e8a4"
}
```

### Sample 56: `9b6e06c78785a4e2`

| Field | Value |
|---|---|
| SHA-256 | `9b6e06c78785a4e2878a05702b1965036beb82a15104c03993720d621218acab` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-08 01:02:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5be685d7104ad8a2f832a674f7c97c5a` |
| SHA-1 | `91592fb3450e715655644384a7b407502981a084` |
| SHA-256 | `9b6e06c78785a4e2878a05702b1965036beb82a15104c03993720d621218acab` |
| SHA3-384 | `d4341f28bb254cfb926c02ade305d8529f992e063bc95fc6134803ad14e65f31bef6f1cb62d6abd824c84e8e96a6de94` |
| TLSH | `T10A43F795F8814B22C5D5127AF92D118D332367F8E3DFB2139E202F607B8696B0E36D56` |
| TELFHASH | `t16b01bd1413844df8bae0c919c3be569034203974ed4300929fbb6dca8279be63931835` |
| SSDEEP | `1536:+In0Msd76aMEgYlSE/dvoY7ffkQIMVio/Osm:Hs56VGN7fr/Osm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_9b6e06c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b6e06c78785a4e2878a05702b1965036beb82a15104c03993720d621218acab"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-08 01:02:59"
  condition:
    hash.sha256(0, filesize) == "9b6e06c78785a4e2878a05702b1965036beb82a15104c03993720d621218acab"
}
```

### Sample 57: `f4d8dc95bb1d7310`

| Field | Value |
|---|---|
| SHA-256 | `f4d8dc95bb1d731026ad139f3a25f338fc4879704e0afd38e91ccc416b06279e` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-08 01:02:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df51435006b01e5083f9ca5450452209` |
| SHA-1 | `a87fce8c32c7d2255c141b4ed23de178f2ceeac5` |
| SHA-256 | `f4d8dc95bb1d731026ad139f3a25f338fc4879704e0afd38e91ccc416b06279e` |
| SHA3-384 | `834b01bdb21f57fd66963b5618379b45b4716698d4278388c2c2b11d459c508318d24dfab8d24cfd1db3ac2b6ade94d8` |
| TLSH | `T131C2E07A195DFD21E3306C33D72846CBBA080FFAC1E73265348456CC69EA6039BB5792` |
| SSDEEP | `768:i/ScWTELq+MOSuZKa1LxOq8goo9q3UELzzS:i4T+MUrLxODDLS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_f4d8dc95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d8dc95bb1d731026ad139f3a25f338fc4879704e0afd38e91ccc416b06279e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-08 01:02:24"
  condition:
    hash.sha256(0, filesize) == "f4d8dc95bb1d731026ad139f3a25f338fc4879704e0afd38e91ccc416b06279e"
}
```

### Sample 58: `65ce16346db5e4d0`

| Field | Value |
|---|---|
| SHA-256 | `65ce16346db5e4d0abb76776b550325ff32b01bfe69d3b0eda52bb9e5e119a0d` |
| Family label | `unknown` |
| File name | `65ce16346db5e4d0abb76776b550325ff32b01bfe69d3b0eda52bb9e5e119a0d` |
| File type | `gz` |
| First seen | `2026-07-08 01:01:35` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, gz` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05ae97e3bc2aae70a800b719a2356fc7` |
| SHA-1 | `1e113600a1aece7dd7c165b148329e9381c6bdec` |
| SHA-256 | `65ce16346db5e4d0abb76776b550325ff32b01bfe69d3b0eda52bb9e5e119a0d` |
| SHA3-384 | `0b94b753776a90aa6e7b7f613289b7f4c1e45116e737544214f9fdbf923fa7d08ca11f5613e046df260efd032aed7787` |
| TLSH | `T1CB83122B6EE80B5BEF406191521D73C754532404B00A77DAB64BCE73E8FE24A62EBC74` |
| SSDEEP | `1536:cQ3TPtuYdUxWKgEo80wUxnbhfXrW8CJyfr38+rnWAJUvNVmMWV1W:13UR7o/wAnF/rxvj9nWAJUvNVms` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_65ce1634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65ce16346db5e4d0abb76776b550325ff32b01bfe69d3b0eda52bb9e5e119a0d"
    family = "unknown"
    file_name = "65ce16346db5e4d0abb76776b550325ff32b01bfe69d3b0eda52bb9e5e119a0d"
    file_type = "gz"
    first_seen = "2026-07-08 01:01:35"
  condition:
    hash.sha256(0, filesize) == "65ce16346db5e4d0abb76776b550325ff32b01bfe69d3b0eda52bb9e5e119a0d"
}
```

### Sample 59: `ade67d4d7e7a5e57`

| Field | Value |
|---|---|
| SHA-256 | `ade67d4d7e7a5e572e78d5a1b47033c21080f7e136c108129b0e287774e83cc2` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-08 00:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4765ffefd972d03a0f34b92791c9c50` |
| SHA-1 | `87019b0991b0219c52c5ab9048a10d5cadcf3fca` |
| SHA-256 | `ade67d4d7e7a5e572e78d5a1b47033c21080f7e136c108129b0e287774e83cc2` |
| SHA3-384 | `137bae32ae7fedfbec0e362de7c32afb81fb5e7e3b858d5151d934fd09030d4ee38fe2103877fad6bf625291953eef8d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T167E6335CB6E011EFFAB3413CE9E29194D4B874B32377CA9B475883619E530E14E3A663` |
| SSDEEP | `393216:Kjkd35hVVSQaTGwUw1Ls/UT7XXMCHWUjX8cuI3/PGTAI:KmhVVSp2/UnXXMb8XpH/O7` |
| ICON-DHASH | `f0f89ca292c6f4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_ade67d4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ade67d4d7e7a5e572e78d5a1b47033c21080f7e136c108129b0e287774e83cc2"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-08 00:52:09"
  condition:
    hash.sha256(0, filesize) == "ade67d4d7e7a5e572e78d5a1b47033c21080f7e136c108129b0e287774e83cc2"
}
```

### Sample 60: `720e20680e137359`

| Field | Value |
|---|---|
| SHA-256 | `720e20680e13735954dc42eb2aa09cba84c7b0aaff69d594fd4c01fd7323de44` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-07-08 00:51:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46c707a015550bc6013ae190d5e43f6c` |
| SHA-1 | `89f59dd9c740b6717e42ee2b3ecfd8fbbe2ec9c1` |
| SHA-256 | `720e20680e13735954dc42eb2aa09cba84c7b0aaff69d594fd4c01fd7323de44` |
| SHA3-384 | `3dbf7fe4f98c9909b19dfe29ebbfcb2d99c180bc973d5ef9ffd8eae30c446a98d6ad8260760dc6909983bd494bb42084` |
| TLSH | `T1D5245C46EA814E23C4D7177AB6AF114A333297A4D3DB730689286FB43B8679F0D63705` |
| TELFHASH | `t118311e72933052266a61d924ddec97b2162ec7071688fe33df36849c141a49ee53fc1f` |
| SSDEEP | `6144:GUiB0UfyVEaak87zNos2thrCGFTHuGLavM/912s:GUiyUqVEaak87zNos2Drnolk/L` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_720e2068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "720e20680e13735954dc42eb2aa09cba84c7b0aaff69d594fd4c01fd7323de44"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-08 00:51:45"
  condition:
    hash.sha256(0, filesize) == "720e20680e13735954dc42eb2aa09cba84c7b0aaff69d594fd4c01fd7323de44"
}
```

### Sample 61: `b60a4c6391bcab56`

| Field | Value |
|---|---|
| SHA-256 | `b60a4c6391bcab56d7b152aabec161ef462ca4a3dd5469019aca5b45a4b09c91` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-07-08 00:51:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fa99938af45a5279d07d97e6974f192` |
| SHA-1 | `fa3a6005518e553a06ddd98c23ada17d9187194f` |
| SHA-256 | `b60a4c6391bcab56d7b152aabec161ef462ca4a3dd5469019aca5b45a4b09c91` |
| SHA3-384 | `4a434ba78f53be975f089598a37d2d60460b5f74057fd8e172b1352ed0a64575998561e85fe66654aa093fbf6d8267f5` |
| TLSH | `T14D73023CD9337CAA6C407A27A8060FC0264A657CD0E5A45F8AD44118AC9CDD96F7BEC3` |
| SSDEEP | `1536:0C63v+lqi/A3n9OHtOuu1m/LO2FosZr5PKTi917LcrAf4YfCOYCin:0bvW/cQFB/Lf1BlKTi9dLc84pCq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_b60a4c63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b60a4c6391bcab56d7b152aabec161ef462ca4a3dd5469019aca5b45a4b09c91"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-08 00:51:35"
  condition:
    hash.sha256(0, filesize) == "b60a4c6391bcab56d7b152aabec161ef462ca4a3dd5469019aca5b45a4b09c91"
}
```

### Sample 62: `6a89179df5a928a0`

| Field | Value |
|---|---|
| SHA-256 | `6a89179df5a928a0dabbc9a792f4f39729a343f8c13c10487cdf9271d44d8383` |
| Family label | `Mirai` |
| File name | `bot_x86_64` |
| File type | `elf` |
| First seen | `2026-07-08 00:17:23` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e371fb7094454c787bacbb278675b101` |
| SHA-1 | `aca0d3b30e98167bcb66fcbe0fe945f6788feadb` |
| SHA-256 | `6a89179df5a928a0dabbc9a792f4f39729a343f8c13c10487cdf9271d44d8383` |
| SHA3-384 | `8f2b7df24563c9a250a1019c4afc246c4862f8d117e3a078451fede355ad208d02fe0beea9bde448ec90fe09fd788605` |
| TLSH | `T1C5457C57B2F364FEC053C43087DBD6A2A935B42542326E7F65C4CA302FA6E641B1DB62` |
| TELFHASH | `t1aa0172b4d67c86c488d2ccd4d6be4420e15ff2a82cb24813d8b0c58e32bc21f4a4b86b` |
| SSDEEP | `24576:+dETE4kzUyXNyRqXEU8YgHwp2GlaaTuOcpMgv8DHS:+dCE4kzUvqDgq2waaicgv5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_6a89179d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a89179df5a928a0dabbc9a792f4f39729a343f8c13c10487cdf9271d44d8383"
    family = "Mirai"
    file_name = "bot_x86_64"
    file_type = "elf"
    first_seen = "2026-07-08 00:17:23"
  condition:
    hash.sha256(0, filesize) == "6a89179df5a928a0dabbc9a792f4f39729a343f8c13c10487cdf9271d44d8383"
}
```

### Sample 63: `f56929affb830daa`

| Field | Value |
|---|---|
| SHA-256 | `f56929affb830daae30c1be4d1864df512d48b9210a2976eb38260d54cb33149` |
| Family label | `Mirai` |
| File name | `bot` |
| File type | `elf` |
| First seen | `2026-07-08 00:17:22` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd1c1812702d4c5cb835d80dca5d5784` |
| SHA-1 | `d4a08165a4f27bed3a4d64b6a7a358509dbf4ae8` |
| SHA-256 | `f56929affb830daae30c1be4d1864df512d48b9210a2976eb38260d54cb33149` |
| SHA3-384 | `f9b54a74641bc84a56f683f02b3f48d05aca9721693ffd2f47007dcaff7099b9dfaa2becfaadc2ac2d8ba09c3f8d3e20` |
| TLSH | `T17F33F87F6720C279C183E7740AEB52A09574B0F74B32B01F76045A766F52F88CE2EA56` |
| TELFHASH | `t19ce0e505f23d0a8905f35e248c2449d65293e4765565a575fb69edc1443e400ea2c95e` |
| SSDEEP | `768:uTdD8nKkhEu/njPgl5bnlviomR0j/Yo5inXNTm:QD8nK/+Evi5ownJm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_f56929af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f56929affb830daae30c1be4d1864df512d48b9210a2976eb38260d54cb33149"
    family = "Mirai"
    file_name = "bot"
    file_type = "elf"
    first_seen = "2026-07-08 00:17:22"
  condition:
    hash.sha256(0, filesize) == "f56929affb830daae30c1be4d1864df512d48b9210a2976eb38260d54cb33149"
}
```

### Sample 64: `6c1aaef872faae9e`

| Field | Value |
|---|---|
| SHA-256 | `6c1aaef872faae9ec1c56d5230d2f9c17e4bee0d95545e2541f8f68ba1d5b9eb` |
| Family label | `unknown` |
| File name | `bot.sh` |
| File type | `sh` |
| First seen | `2026-07-08 00:17:21` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61e068c8d08bc57e9f76efd0089111a6` |
| SHA-1 | `205f766f6a9cd5e90e6c39f72ede772441aa5178` |
| SHA-256 | `6c1aaef872faae9ec1c56d5230d2f9c17e4bee0d95545e2541f8f68ba1d5b9eb` |
| SHA3-384 | `7e021256b3fdb8764d48d3449340315d43761ce82678a26ef3a0e1574708d02c821b12a502645d34650c0a1f71b0d038` |
| TLSH | `T1BEA244423940BAF03D4E8478566F90017612644F5E203C3D74DEA9246FA97ADB2FEBE7` |
| SSDEEP | `192:JFu6cgIGhJAVZmfYM+HT0phWZBNhbIyuyzyeU4ZcZfv/YJS0q6NUeTn7kBVsJZrO:qJi+pYvf4JBq6OBeJJYLvSyLc6scp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_6c1aaef8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c1aaef872faae9ec1c56d5230d2f9c17e4bee0d95545e2541f8f68ba1d5b9eb"
    family = "unknown"
    file_name = "bot.sh"
    file_type = "sh"
    first_seen = "2026-07-08 00:17:21"
  condition:
    hash.sha256(0, filesize) == "6c1aaef872faae9ec1c56d5230d2f9c17e4bee0d95545e2541f8f68ba1d5b9eb"
}
```

### Sample 65: `7ddfafe75d3b3605`

| Field | Value |
|---|---|
| SHA-256 | `7ddfafe75d3b360530299abea5838bc26d6430be756030e1b9cccc2ec5fe4134` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-08 00:16:14` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `caec665edddcc92a1c70e8752ad2a03f` |
| SHA-1 | `670e253939e2797454418f337b535690e0b6690b` |
| SHA-256 | `7ddfafe75d3b360530299abea5838bc26d6430be756030e1b9cccc2ec5fe4134` |
| SHA3-384 | `af17ce255d03c2fb0470124b9cac4ab1a14a7ebfbbc39256769d2a0ce2ca487ebf4c6bb5b16a850ab77b61a9febf6626` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T1AE3209197E494331D3A089F85479838BA53D5633E7C3E3EBF373965E4A962448840EAF` |
| SSDEEP | `192:rnomWEzBa/Vx+eTRHj5PFJxTEZmFhSac:rno+w9w2lPFwZ` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_065_7ddfafe7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ddfafe75d3b360530299abea5838bc26d6430be756030e1b9cccc2ec5fe4134"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-08 00:16:14"
  condition:
    hash.sha256(0, filesize) == "7ddfafe75d3b360530299abea5838bc26d6430be756030e1b9cccc2ec5fe4134"
}
```

### Sample 66: `7dcc39a70a58be78`

| Field | Value |
|---|---|
| SHA-256 | `7dcc39a70a58be7899ca6d3fbcbd7aeba3e6665bc38a7a0125e9fda5d84dee0f` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.9816.6486.20935` |
| File type | `elf` |
| First seen | `2026-07-08 00:01:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d6a68bbe5aa2cc3fc42c2cd6ca4ec2e` |
| SHA-1 | `0325ed308e42589be8285a14da1a5deb6738a66a` |
| SHA-256 | `7dcc39a70a58be7899ca6d3fbcbd7aeba3e6665bc38a7a0125e9fda5d84dee0f` |
| SHA3-384 | `dd334e0dc1fcd2170c12543db75696ee605ae307a1d646f4dd85562a0a6d60f00b72869c2b01b91abdcaa682f1717b93` |
| TLSH | `T18DC32B56E7414F13C0D61779B6EF42453322AB9493DB73069928BFF43F8279A0E63A06` |
| TELFHASH | `t10121fe356b25a1295d61dd949cfe47b1262c87132780ef33ef25c4cc641909aea2bc4f` |
| SSDEEP | `1536:OOn3DydtUaywqQ690Ll/ThemKw4kTWaNle5iQr2NVL8lx8HWZOWOkpUc6zw/9aHY:3ybU7v+ThemKw4Lvr2N+lqHRW4M/9GAj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_7dcc39a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dcc39a70a58be7899ca6d3fbcbd7aeba3e6665bc38a7a0125e9fda5d84dee0f"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.6486.20935"
    file_type = "elf"
    first_seen = "2026-07-08 00:01:36"
  condition:
    hash.sha256(0, filesize) == "7dcc39a70a58be7899ca6d3fbcbd7aeba3e6665bc38a7a0125e9fda5d84dee0f"
}
```

### Sample 67: `11f2932b3e4903e9`

| Field | Value |
|---|---|
| SHA-256 | `11f2932b3e4903e934f08fb6f7c099650f1f62a52f4cb3cd65e0445fbc6ad84c` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.9816.6486.20935` |
| File type | `elf` |
| First seen | `2026-07-07 23:59:32` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `291c065b9469f9e4bfaf042e523fe6c2` |
| SHA-1 | `26e1be4e9913af80cfa31d6ee5f69a39cf3ab98c` |
| SHA-256 | `11f2932b3e4903e934f08fb6f7c099650f1f62a52f4cb3cd65e0445fbc6ad84c` |
| SHA3-384 | `7c6f8aa10fa65c600b6e8dcb2d3b84ebe94ee6449317a1a1c3948782ea4be0b2b18fc3f7ee4160aae8c6db4c8783dab9` |
| TLSH | `T12C23F160E1B19122C1F90C39D1778AC93B5E25F2D0D7E834D22E5EA6DAE3457F892F42` |
| SSDEEP | `768:u45CXumaJ4aLrLYBLG83w4xGziGfJ0gbdw0Iz4yeS3R8z9q3UELV5Oz6L6kbujwg:u45+d+r8b3w7mcC0I1/3SyLV5v6kbsjD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_11f2932b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11f2932b3e4903e934f08fb6f7c099650f1f62a52f4cb3cd65e0445fbc6ad84c"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.6486.20935"
    file_type = "elf"
    first_seen = "2026-07-07 23:59:32"
  condition:
    hash.sha256(0, filesize) == "11f2932b3e4903e934f08fb6f7c099650f1f62a52f4cb3cd65e0445fbc6ad84c"
}
```

### Sample 68: `5261f86cf9d88e31`

| Field | Value |
|---|---|
| SHA-256 | `5261f86cf9d88e316622856618f5624aa0887860c456176bce9fc8b4729f3d2a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-07 23:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5067e3f4ac0690d777eb4f8ffbffd40a` |
| SHA-1 | `381fccbc05209f136b50176c884073a8a7c55037` |
| SHA-256 | `5261f86cf9d88e316622856618f5624aa0887860c456176bce9fc8b4729f3d2a` |
| SHA3-384 | `c40d3d4292e5244ea746b1bbc424aeeb09236b2bf7cb610b6cac22e0d54d725cc50e6d6ff1420969acce8dbd9138e133` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T108E63349EAD102FDEDB3923CEAF1A261E5F5B4662731CADF575883210D670E18C3DA12` |
| SSDEEP | `393216:uer8HsR8EBgyUwXMCHWUjXTcuI3/PGTAI:uxQ8EC1wXMb8XQH/O7` |
| ICON-DHASH | `71f0e4d4c4e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_5261f86c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5261f86cf9d88e316622856618f5624aa0887860c456176bce9fc8b4729f3d2a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 23:52:09"
  condition:
    hash.sha256(0, filesize) == "5261f86cf9d88e316622856618f5624aa0887860c456176bce9fc8b4729f3d2a"
}
```

### Sample 69: `8b7537c662499842`

| Field | Value |
|---|---|
| SHA-256 | `8b7537c6624998423c0dc5e63d133a4380df59ff64a623f35f2f669e63061c52` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-07 23:48:34` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4709f0e6e3ec48968747e30fb1323583` |
| SHA-1 | `ccd8f58632dfdca6ffc48f3f64920bab547ad452` |
| SHA-256 | `8b7537c6624998423c0dc5e63d133a4380df59ff64a623f35f2f669e63061c52` |
| SHA3-384 | `0d0c37f0d33d906215a397bec16dd1cee03cd49c523c5182f479651bdc5f001f06e653c5da5dceaa408cf70db309d160` |
| IMPHASH | `e387f9bdbdc891a56417c52c45ed0b91` |
| TLSH | `T1F9A5232212D85405E0BA7BBE05F3461E6531BC1593754BEF31E4B8AD8FB35D4E632B0A` |
| SSDEEP | `49152:dKu7Z0GOnOSieDx2eQlxtIqtcAF+g0clT/HHT:dHF0GOn+eDHQjIqqakc1/n` |
| ICON-DHASH | `f8cf7f3d75777fb9` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_069_8b7537c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b7537c6624998423c0dc5e63d133a4380df59ff64a623f35f2f669e63061c52"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 23:48:34"
  condition:
    hash.sha256(0, filesize) == "8b7537c6624998423c0dc5e63d133a4380df59ff64a623f35f2f669e63061c52"
}
```

### Sample 70: `11feb1239237e308`

| Field | Value |
|---|---|
| SHA-256 | `11feb1239237e30844191c3c493ec317e78a0db27c99bf3358c18b8388f5469a` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-07 23:41:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0d2ba78a41a8c645856a35029b5786d` |
| SHA-1 | `7607fff6c4923c45b2b397be96ed45a55b6a16c4` |
| SHA-256 | `11feb1239237e30844191c3c493ec317e78a0db27c99bf3358c18b8388f5469a` |
| SHA3-384 | `6af2311c45d2efbc79ee23f34f85a65c6e1cd5590ea05b345c6dc90040c0cc369a661c013e9cebab06b3b345ae796aae` |
| TLSH | `T1CF03E891B8825B6BC5E0137AB6BE568C373063E9E3CFB61BD8205B147AC551F0C62F91` |
| TELFHASH | `t1a4e06840fd698b1c48eb9a74dcec47f49401221395768b10cf01d7e0883f054e30ca6e` |
| SSDEEP | `768:18QGtw0G5ijUdwkRBK2e5ZdfPLZqwOwm9CQ+W5NDG5oP9Zw:ItPG5ijsBKtDdHEoKAW5BGt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_11feb123
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11feb1239237e30844191c3c493ec317e78a0db27c99bf3358c18b8388f5469a"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-07 23:41:40"
  condition:
    hash.sha256(0, filesize) == "11feb1239237e30844191c3c493ec317e78a0db27c99bf3358c18b8388f5469a"
}
```

### Sample 71: `a1511521dc5f5a5f`

| Field | Value |
|---|---|
| SHA-256 | `a1511521dc5f5a5f7fb8f5ab3a52b63a600edf5adf4f5d1f1264212e52d338bf` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-07 23:40:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3ad069fa1346a501a37c2da84622554` |
| SHA-1 | `ae7d0c06f3bb530340a0de552b11d331e9b7768d` |
| SHA-256 | `a1511521dc5f5a5f7fb8f5ab3a52b63a600edf5adf4f5d1f1264212e52d338bf` |
| SHA3-384 | `72199611d866f90d5f581a1bdc5e621014ed6bae06b0055a31bad3f5e7da60b3359d3662076a2b8c55d9fea25c6dda77` |
| TLSH | `T16482B0215180ECE1D2310577A7A7888B7A5257BCE0F7306321C99AA8B69781FA0BD9C7` |
| SSDEEP | `384:iSPWqRnDRsgnMF8frCglVGukPqIOKgyhymdGUop5h8X:iSPdDRs9QjrkCvKfs3Uoz+X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_a1511521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1511521dc5f5a5f7fb8f5ab3a52b63a600edf5adf4f5d1f1264212e52d338bf"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-07 23:40:55"
  condition:
    hash.sha256(0, filesize) == "a1511521dc5f5a5f7fb8f5ab3a52b63a600edf5adf4f5d1f1264212e52d338bf"
}
```

### Sample 72: `fe206a7571e80bb1`

| Field | Value |
|---|---|
| SHA-256 | `fe206a7571e80bb15a6cd0427f904dc859e2bd3b92a410ce2a3e1fac31599c2b` |
| Family label | `unknown` |
| File name | `zinst.6638258007.msi` |
| File type | `msi` |
| First seen | `2026-07-07 23:30:51` |
| Reporter | `CNGaoLing` |
| Tags | `msi, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87dd43b7afc87d9ec141ed0d074cf0d7` |
| SHA-1 | `fa4778bba475de66106dd994abc965fb9d607014` |
| SHA-256 | `fe206a7571e80bb15a6cd0427f904dc859e2bd3b92a410ce2a3e1fac31599c2b` |
| SHA3-384 | `31d6183e49cf4f798974d42cccf5876447494fa77afcd31927a7e15a72fb27d9f77464f4284f6fcc4180623693fc980a` |
| TLSH | `T1AC8633856CCB5231C45BE3B00A48157F326E3FCA6FB44E2E36E6B55D3E3242944B6789` |
| SSDEEP | `196608:qUV55WM4PgZyGlpYP5ovOx/Hli9BsHSlNV7LF4QNN/OkNv:P7QAlSPKvOR0Bsyt7LiMN/Okh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_fe206a75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe206a7571e80bb15a6cd0427f904dc859e2bd3b92a410ce2a3e1fac31599c2b"
    family = "unknown"
    file_name = "zinst.6638258007.msi"
    file_type = "msi"
    first_seen = "2026-07-07 23:30:51"
  condition:
    hash.sha256(0, filesize) == "fe206a7571e80bb15a6cd0427f904dc859e2bd3b92a410ce2a3e1fac31599c2b"
}
```

### Sample 73: `308fbf5c75a79e0e`

| Field | Value |
|---|---|
| SHA-256 | `308fbf5c75a79e0e2dcf061ec57f8a4e67b7259d7595cca1f6c2142028a5019f` |
| Family label | `unknown` |
| File name | `nRFQ_Clinica_Radiologia_Medicals_PNG.tar` |
| File type | `tar` |
| First seen | `2026-07-07 23:30:10` |
| Reporter | `fabiodemartin` |
| Tags | `tar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f02e02a5b6b31b3f57639c9911873c33` |
| SHA-1 | `dbe13bca46bf472c07a8a8f3201e300d0f204d30` |
| SHA-256 | `308fbf5c75a79e0e2dcf061ec57f8a4e67b7259d7595cca1f6c2142028a5019f` |
| SHA3-384 | `c3f7282e6fef6e8d7854113463cec28d5a94b232a160bca28e0fc7375d8df55daed29958bec552e3f8865abf0189caf3` |
| TLSH | `T195A423F41D8699E9DCD57AE433D3ABE2713523DC9849AE7D08A096BC96F7C06C0C8076` |
| SSDEEP | `12288:AgaXbIpyE2gRDdEURzfcIHBUEGJ7l70PE7vDSVP7G+u:TaXkYEhDdEU+IY2E7vuVP+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `tar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_308fbf5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "308fbf5c75a79e0e2dcf061ec57f8a4e67b7259d7595cca1f6c2142028a5019f"
    family = "unknown"
    file_name = "nRFQ_Clinica_Radiologia_Medicals_PNG.tar"
    file_type = "tar"
    first_seen = "2026-07-07 23:30:10"
  condition:
    hash.sha256(0, filesize) == "308fbf5c75a79e0e2dcf061ec57f8a4e67b7259d7595cca1f6c2142028a5019f"
}
```

### Sample 74: `efbc44c07e46535a`

| Field | Value |
|---|---|
| SHA-256 | `efbc44c07e46535a1c7e53e276c7d106b6aebe071004cb84a5b89db573679006` |
| Family label | `ValleyRAT` |
| File name | `DeepL.msi` |
| File type | `msi` |
| First seen | `2026-07-07 23:30:02` |
| Reporter | `CNGaoLing` |
| Tags | `Dllhijack, msi, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf0a006484bd71753c68bca429ac7be3` |
| SHA-1 | `d89da8e2e00da108e6387a0fff7fd57642cd5fff` |
| SHA-256 | `efbc44c07e46535a1c7e53e276c7d106b6aebe071004cb84a5b89db573679006` |
| SHA3-384 | `345f05d5a715bd538b53b49cc4ac852554f1ecfeeed93eeefd1ffa78f01b5136c671262e731097927b3e1830e29707ab` |
| TLSH | `T1C7F62320A6868433D62E4177E92CEF5E09357EB30B3245DBB7E43D7E09F18C1A579A42` |
| SSDEEP | `393216:TCGyo6FqQd72gOnfhbtD/mt451QIrUAv1FYbbFhbJ:S7MQd72gUhxy451QIQAnybF` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_074_efbc44c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efbc44c07e46535a1c7e53e276c7d106b6aebe071004cb84a5b89db573679006"
    family = "ValleyRAT"
    file_name = "DeepL.msi"
    file_type = "msi"
    first_seen = "2026-07-07 23:30:02"
  condition:
    hash.sha256(0, filesize) == "efbc44c07e46535a1c7e53e276c7d106b6aebe071004cb84a5b89db573679006"
}
```

### Sample 75: `c99e82c28b5fd8eb`

| Field | Value |
|---|---|
| SHA-256 | `c99e82c28b5fd8ebd3c0b8e07cd3f24a65208c26e3aedf0ef60111e28ca71444` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-07 23:24:04` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe32a927f3647ccb4f459587581604db` |
| SHA-1 | `bc22f354ecce5254b74d97c28df1e0b2df9880e1` |
| SHA-256 | `c99e82c28b5fd8ebd3c0b8e07cd3f24a65208c26e3aedf0ef60111e28ca71444` |
| SHA3-384 | `41f4589d2e7529c6aea4dc965b4ee9f2fcb0351f366dd31282d124090158a8d02ffc553fe985b6317b44023b54be1ec7` |
| IMPHASH | `c5fe8ca908c881b9bfa85dc5bbca1bc6` |
| TLSH | `T17AD512537F01D402D56A5E319565CBF89326FC4CAB1A838B31D2BE6BBCEE6C34D12294` |
| SSDEEP | `49152:/Lfj9LG5qjT9ifQ9mHQLV9IXb6yGltpLjAC6gKl+9T:/L5pjt2QLI9GlECz4K` |
| ICON-DHASH | `0071e8f06971b2b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_c99e82c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c99e82c28b5fd8ebd3c0b8e07cd3f24a65208c26e3aedf0ef60111e28ca71444"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 23:24:04"
  condition:
    hash.sha256(0, filesize) == "c99e82c28b5fd8ebd3c0b8e07cd3f24a65208c26e3aedf0ef60111e28ca71444"
}
```

### Sample 76: `433d2421b7f116b3`

| Field | Value |
|---|---|
| SHA-256 | `433d2421b7f116b32b878c36cb68512331588d1b679b1c6b8c716fcea7a919b4` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-07 23:11:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f823870586ca47eff4f9dacf4e55f3d8` |
| SHA-1 | `426f7c3404361b5dae2a5efc9ffe84375acf53ff` |
| SHA-256 | `433d2421b7f116b32b878c36cb68512331588d1b679b1c6b8c716fcea7a919b4` |
| SHA3-384 | `f553c0b0a4f4917365172c60a7be96363535e2d83a8ef387258170b4f541b4ee8268f2196f067253559e8045fcfe6ae0` |
| TLSH | `T10D738D77C8292E54D18585F1B4B08FB40BA3A95082876FBE2667C2798047FECF7453E5` |
| SSDEEP | `1536:8ttu+4+KpKot5bPI9LUDKfa3zrzQkJzCeCg2VM:8HuQKpKot509DfOzQkJzKM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_433d2421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "433d2421b7f116b32b878c36cb68512331588d1b679b1c6b8c716fcea7a919b4"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:14"
  condition:
    hash.sha256(0, filesize) == "433d2421b7f116b32b878c36cb68512331588d1b679b1c6b8c716fcea7a919b4"
}
```

### Sample 77: `359edf4c860783ce`

| Field | Value |
|---|---|
| SHA-256 | `359edf4c860783ce7876a502e2e3a6f456378a485b5a8141689709bf2b13ba09` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-07-07 23:11:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93c4993031ff5ccbb81704ef63c8b3d3` |
| SHA-1 | `92cf0ef35367f8634e3b4f9db25ed320798847b2` |
| SHA-256 | `359edf4c860783ce7876a502e2e3a6f456378a485b5a8141689709bf2b13ba09` |
| SHA3-384 | `96e69a4b6d815c2d9d000826f59a92a5191455f38ce749ace72c713ffd767bfd561b41b9d6e4fbcff6f8882703d280e7` |
| TLSH | `T178934B21B9760D2BC4D4B87A21F34725F2F2574921FCCA1E7D620E4EAF696002647BF4` |
| SSDEEP | `1536:36Fis9HSoucWdqq8MnZeh2GQoAM/75G9tdxTrtoRoG:36RyoCwQAt/VyfxiRoG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_359edf4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "359edf4c860783ce7876a502e2e3a6f456378a485b5a8141689709bf2b13ba09"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:12"
  condition:
    hash.sha256(0, filesize) == "359edf4c860783ce7876a502e2e3a6f456378a485b5a8141689709bf2b13ba09"
}
```

### Sample 78: `37116a5f09fb37c1`

| Field | Value |
|---|---|
| SHA-256 | `37116a5f09fb37c1c60820754595847b7b6e97e2f0f5d5b8ee5be954a21e078d` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-07 23:11:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3d4706b4ab01de2ad3cd6b6eae7f817` |
| SHA-1 | `2c73eb969ca5f17a89ca25391e3f130dd0eeb563` |
| SHA-256 | `37116a5f09fb37c1c60820754595847b7b6e97e2f0f5d5b8ee5be954a21e078d` |
| SHA3-384 | `3e8daae375e42d4152ca380371ef0e147349a7ee915c941208622159c42b515dfd5387f0925372900959ed634f19ad67` |
| TLSH | `T109733917B48480FCC4AAC1784BABB63BD573797D1138B6AA37D0EF226D49E214E5E640` |
| TELFHASH | `t1e13134b1399a09e0a1f7e236b356e4a959321f1024e035e28ab77df5cf213404d75837` |
| SSDEEP | `1536:aEZlOY8IPDFTHBga3VfbKtVl20U63WBI/XNZ/wz4P3kGniwz3mH:RZl78aZTHRl+tHj3WMXNZ4E3kGnBmH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_37116a5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37116a5f09fb37c1c60820754595847b7b6e97e2f0f5d5b8ee5be954a21e078d"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:10"
  condition:
    hash.sha256(0, filesize) == "37116a5f09fb37c1c60820754595847b7b6e97e2f0f5d5b8ee5be954a21e078d"
}
```

### Sample 79: `15870cf9f5b2df29`

| Field | Value |
|---|---|
| SHA-256 | `15870cf9f5b2df29de3389b23ce73412d7f1d5ebac77f74e6ea9b01e5ee40388` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-07 23:11:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06a227c62aeb103aa4a93a6d74dcfe08` |
| SHA-1 | `9fbfbfd39984f409d8e513032705f98d65382c76` |
| SHA-256 | `15870cf9f5b2df29de3389b23ce73412d7f1d5ebac77f74e6ea9b01e5ee40388` |
| SHA3-384 | `bb706cb4141475d040c5930f378ceb566901f674ed48fdfb81769ac4ca88ae5ff1cac19ab45f5587a341a31ac04b0b02` |
| TLSH | `T13FF34C56FA818A13C4D21776BADF42463323AB64D3DB730699287FB43F4679E0E23605` |
| TELFHASH | `t11631bb325b7156156fb2e8509cedaba311199b136345af33ef31c4cc241a0aad936c9f` |
| SSDEEP | `3072:z5Z0P3aLKIxyad+/f0TlSaqZcgCzd8/robNM/91sImYwNzpdaWL:zr0P3vyyad+/f0TkaeCz6/roJM/9WImn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_15870cf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15870cf9f5b2df29de3389b23ce73412d7f1d5ebac77f74e6ea9b01e5ee40388"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:08"
  condition:
    hash.sha256(0, filesize) == "15870cf9f5b2df29de3389b23ce73412d7f1d5ebac77f74e6ea9b01e5ee40388"
}
```

### Sample 80: `f2530a4564ee2d03`

| Field | Value |
|---|---|
| SHA-256 | `f2530a4564ee2d036ea9e75f5c944bb4bf051e8fe63db5abbcd51c6d16b903e4` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-07 23:11:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bd12fb1bad2ff415e7c51afa1e71f21` |
| SHA-1 | `76a3b3994207cdf655e30b30edbd36c2bb5fc21b` |
| SHA-256 | `f2530a4564ee2d036ea9e75f5c944bb4bf051e8fe63db5abbcd51c6d16b903e4` |
| SHA3-384 | `acc6306d5e1b5811742fa6096ae8464481c36b36ffb649d6fb6a0ef32e0f731734bf167abd3f0b2a181cdf96f46eef30` |
| TLSH | `T19DB3D605BB114FFBDC6FDD370AA91B0534CD691622A83B3A7634C918F64B24B4AF3964` |
| SSDEEP | `1536:QEyyWDbtLuhrkVTgw9kW4hn+RdtVbqmc0Zf5Lq5MRXtWdUfJ/u:QEyyWDbUq3nbqmc0XPxA8/u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_f2530a45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2530a4564ee2d036ea9e75f5c944bb4bf051e8fe63db5abbcd51c6d16b903e4"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:06"
  condition:
    hash.sha256(0, filesize) == "f2530a4564ee2d036ea9e75f5c944bb4bf051e8fe63db5abbcd51c6d16b903e4"
}
```

### Sample 81: `3418bbac4672fcf4`

| Field | Value |
|---|---|
| SHA-256 | `3418bbac4672fcf49bfa5c17c4e8e9cb99248f0e64225bcad090e8abfb71df13` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-07 23:11:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c5967182c5f24ca2444545991808695` |
| SHA-1 | `e87f775c2f64f7b802c9a117563cd79e6668b6b2` |
| SHA-256 | `3418bbac4672fcf49bfa5c17c4e8e9cb99248f0e64225bcad090e8abfb71df13` |
| SHA3-384 | `1b20f9ec482325b73aab6ca1e6e2dab9ea45d54f429ac16de16e8886fe6a26367969d3b9a8e70f3ff669df1577fb4fc2` |
| TLSH | `T12C831A02771C0947E1635AF0393F27E093EEAED021F4F688290E6B869275E355587EDD` |
| SSDEEP | `1536:hBvzn/n4kYGTft2j6jyIR78JsJHlfDc8UVrEl:jIOfQja1IsJF7cbSl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_3418bbac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3418bbac4672fcf49bfa5c17c4e8e9cb99248f0e64225bcad090e8abfb71df13"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:04"
  condition:
    hash.sha256(0, filesize) == "3418bbac4672fcf49bfa5c17c4e8e9cb99248f0e64225bcad090e8abfb71df13"
}
```

### Sample 82: `74f9b450ab197042`

| Field | Value |
|---|---|
| SHA-256 | `74f9b450ab1970423b27a92930cc2fcef2d58d9a6b84d23116027d749d6fedc8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-07 23:09:40` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX3.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e26180f49299679ebe1b15d8bea8ce80` |
| SHA-1 | `0a53aacd55a632ba46d40c4daaf028da08bdd7b2` |
| SHA-256 | `74f9b450ab1970423b27a92930cc2fcef2d58d9a6b84d23116027d749d6fedc8` |
| SHA3-384 | `06e4aa66deacb89abb1040727b06949c2c71c5045daad9e37231ee3d0224204ed9c81f38f0ebe1367c07407d9bd37f10` |
| IMPHASH | `67f6728bb9c2c56c262f6da70935d9d5` |
| TLSH | `T1D0547D5AF7A518FAEE77817CC9524601EA727C164760E6CF03A04A672F237E09E3E711` |
| SSDEEP | `3072:mFrVsVCP56K+bUmQLc643IlQxuzBR5AEDn3em5LQG66jCO6Ja3jj7HS5Hj25HSXa:i8KNl4sBRWEz/yp+TjE9xvVMRD1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_74f9b450
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f9b450ab1970423b27a92930cc2fcef2d58d9a6b84d23116027d749d6fedc8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 23:09:40"
  condition:
    hash.sha256(0, filesize) == "74f9b450ab1970423b27a92930cc2fcef2d58d9a6b84d23116027d749d6fedc8"
}
```

### Sample 83: `1a01cf874059dc90`

| Field | Value |
|---|---|
| SHA-256 | `1a01cf874059dc90a50f255035c31ba2f55cd8084747d7b5812dc7475b47bd93` |
| Family label | `unknown` |
| File name | `spkvol.dll` |
| File type | `exe` |
| First seen | `2026-07-07 23:04:41` |
| Reporter | `anonymous` |
| Tags | `exe, Oreans CodeVirtualizer, rust` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a6077b5152aa23186d9700ce48c65af` |
| SHA-1 | `a7169b64558a43aee32e054637c91c9cdfb7e0b9` |
| SHA-256 | `1a01cf874059dc90a50f255035c31ba2f55cd8084747d7b5812dc7475b47bd93` |
| SHA3-384 | `a92c1881fdcb41410ca5470da93fa048def54c390d132e88603aab146688d53d6c6e6187ae4e606f54fcc946455c57a1` |
| IMPHASH | `8f2f1c754154f4d7eee29d32d1472398` |
| TLSH | `T139C6E04761E2569CC49FC178025B7C6FB1B2B8690423EEBB22504A7A7F56E34B70DB0D` |
| SSDEEP | `98304:MNssT+OG2dSnSva8R/pSkgoTtONLUFeb5IoGySWwTNugMSi:0Vd4n8zSkhFeQjNLMSi` |
| ICON-DHASH | `1ec1c4c4c4c4c11e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_1a01cf87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a01cf874059dc90a50f255035c31ba2f55cd8084747d7b5812dc7475b47bd93"
    family = "unknown"
    file_name = "spkvol.dll"
    file_type = "exe"
    first_seen = "2026-07-07 23:04:41"
  condition:
    hash.sha256(0, filesize) == "1a01cf874059dc90a50f255035c31ba2f55cd8084747d7b5812dc7475b47bd93"
}
```

### Sample 84: `03a6c5877cf8a3c4`

| Field | Value |
|---|---|
| SHA-256 | `03a6c5877cf8a3c45e3672db2067bccc7b6242a48fbc415805dd614ca3fc4810` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-07 22:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4026ce54f0865017327a753dec4cba11` |
| SHA-1 | `5a94c7b5268cee9fb35d05a978dbc604d2e305be` |
| SHA-256 | `03a6c5877cf8a3c45e3672db2067bccc7b6242a48fbc415805dd614ca3fc4810` |
| SHA3-384 | `b499754783c65861968fe931e4690ffaa3a2b916ebc7a7a6effcde561222649333fe2ac628157d6430e40a5513de395e` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1A0E6330862D013EDD9A3417CEDA06B68F0E974720B72DADB1768C7B5BD1B3A0497C627` |
| SSDEEP | `393216:TmQYAYJGspneLV5UwS9sQrrXMCHWUjX7cuI3/PGTAI:Tp8IueZPqsAXMb8X4H/O7` |
| ICON-DHASH | `a078e0e0d8f8f03a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_03a6c587
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03a6c5877cf8a3c45e3672db2067bccc7b6242a48fbc415805dd614ca3fc4810"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 22:52:10"
  condition:
    hash.sha256(0, filesize) == "03a6c5877cf8a3c45e3672db2067bccc7b6242a48fbc415805dd614ca3fc4810"
}
```

### Sample 85: `ed1427c973e2c1fe`

| Field | Value |
|---|---|
| SHA-256 | `ed1427c973e2c1fecdf2536e270fec2af98e31e229fbdae6664b0e23af321f9a` |
| Family label | `RemcosRAT` |
| File name | `436d5a5d5c35f34cdb4f6be2c4ff30dc.exe` |
| File type | `exe` |
| First seen | `2026-07-07 22:50:10` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `436d5a5d5c35f34cdb4f6be2c4ff30dc` |
| SHA-1 | `d4dd068388524efa1d301f43ec2de47c7fe9a6f0` |
| SHA-256 | `ed1427c973e2c1fecdf2536e270fec2af98e31e229fbdae6664b0e23af321f9a` |
| SHA3-384 | `effadb3cbd5091ffcf1312f55ff548d5364b959295ddc80ee36fc8005f76495741ca8684761136e6d1d6555c6a908463` |
| IMPHASH | `cd443d07fb22cc071cc33eee6cd16e2e` |
| TLSH | `T1B4B4BF01B6F2C1B2DA7654300936E735CEBC7C21183699AB63D61D5BBD30191DB3ABB2` |
| SSDEEP | `12288:g97mmDmUefn1CvVkeClYRLwvcHk2c+IsPZOr6s:glxDmRnkvVkhYHk2c+DZe` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_085_ed1427c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed1427c973e2c1fecdf2536e270fec2af98e31e229fbdae6664b0e23af321f9a"
    family = "RemcosRAT"
    file_name = "436d5a5d5c35f34cdb4f6be2c4ff30dc.exe"
    file_type = "exe"
    first_seen = "2026-07-07 22:50:10"
  condition:
    hash.sha256(0, filesize) == "ed1427c973e2c1fecdf2536e270fec2af98e31e229fbdae6664b0e23af321f9a"
}
```

### Sample 86: `dd86527ed05af146`

| Field | Value |
|---|---|
| SHA-256 | `dd86527ed05af146c6eb44676ffb8dcde757171b0089bfe2bd90e20e0662fd43` |
| Family label | `unknown` |
| File name | `Sassy_Game.exe` |
| File type | `exe` |
| First seen | `2026-07-07 22:43:58` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d811b8cf5eaf542181aa74e53dc11757` |
| SHA-1 | `af0eb163788513ede247983d5ef666f5a1d98a77` |
| SHA-256 | `dd86527ed05af146c6eb44676ffb8dcde757171b0089bfe2bd90e20e0662fd43` |
| SHA3-384 | `d434c70151c1e76507fe7f2df3189f1c0946d791d9776936b63ce3ce62e7f76b48e96193333321c15a07561828fb054e` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T120F7330E08A9C487C67F9AFA7E927475D344DD2B2C78942E1B0E4AE8F1E5D22107D637` |
| SSDEEP | `1572864:wt9IKPRP+2KRWYsJImKljUoEkB9dNDsMLXgiMZrIuEt98ZST7:wUKJm2KRWxImKljUvOhLXMxIu4ZT7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_dd86527e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd86527ed05af146c6eb44676ffb8dcde757171b0089bfe2bd90e20e0662fd43"
    family = "unknown"
    file_name = "Sassy_Game.exe"
    file_type = "exe"
    first_seen = "2026-07-07 22:43:58"
  condition:
    hash.sha256(0, filesize) == "dd86527ed05af146c6eb44676ffb8dcde757171b0089bfe2bd90e20e0662fd43"
}
```

### Sample 87: `5043ac3dbdaf116d`

| Field | Value |
|---|---|
| SHA-256 | `5043ac3dbdaf116d560a90466c1a146da6140a3e7aecd36310f9cf538df62872` |
| Family label | `unknown` |
| File name | `AfterSchoolMemories_winx64.exe` |
| File type | `exe` |
| First seen | `2026-07-07 22:43:27` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aeb1a740dfbc19ca583453b9b184b5a5` |
| SHA-1 | `051510269233ad8d0dd8ef92702f302bb12dda47` |
| SHA-256 | `5043ac3dbdaf116d560a90466c1a146da6140a3e7aecd36310f9cf538df62872` |
| SHA3-384 | `3ee3bd569d456176301dac1368795bd50bc125f8e450e9ef5c92ae6549a9ee23e34ce00d2521747ae1e6121d5b4f2926` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T1E408333CCBFAA29BED6F9CFC1670E536E92814695D68388B9BF860717132404057D68F` |
| SSDEEP | `1572864:1t9IKPGGjzYdeTqowzKYypCPRfYLgRLlPBnU6InslAlHi5K++AL7:1UKOGjzYHoyKYyuB/5PU6InseD++AL7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_5043ac3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5043ac3dbdaf116d560a90466c1a146da6140a3e7aecd36310f9cf538df62872"
    family = "unknown"
    file_name = "AfterSchoolMemories_winx64.exe"
    file_type = "exe"
    first_seen = "2026-07-07 22:43:27"
  condition:
    hash.sha256(0, filesize) == "5043ac3dbdaf116d560a90466c1a146da6140a3e7aecd36310f9cf538df62872"
}
```

### Sample 88: `81e2f4427c80e9d0`

| Field | Value |
|---|---|
| SHA-256 | `81e2f4427c80e9d08a685876ec317bf49924ea7ac08250760132459acef76778` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-07 21:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afabf8a2ff98d0ed600c6e5f6a170667` |
| SHA-1 | `81e0da8186d085289f2ce9ef935ab8689043d076` |
| SHA-256 | `81e2f4427c80e9d08a685876ec317bf49924ea7ac08250760132459acef76778` |
| SHA3-384 | `9ec5000a6bb0efbef61341ee4d2ee31576126e76f24d12c26625595233a002bc8916497def478b0e668f1449f94790dd` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T117E63308A1D152FDD9F34278FDD210E9A565B0A24732C1DB1FA893ADAE672D0CC3DA47` |
| SSDEEP | `393216:qMEt0juG7PDlOg4ompU0JfXMCHWUjXxcuI3/PGTAI:qMXukZSU0JfXMb8XmH/O7` |
| ICON-DHASH | `70f0f0d8f8f0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_81e2f442
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81e2f4427c80e9d08a685876ec317bf49924ea7ac08250760132459acef76778"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 21:52:10"
  condition:
    hash.sha256(0, filesize) == "81e2f4427c80e9d08a685876ec317bf49924ea7ac08250760132459acef76778"
}
```

### Sample 89: `dc57f496cc489f27`

| Field | Value |
|---|---|
| SHA-256 | `dc57f496cc489f275bb58e36d47c760794a0da5532ad13655b761ff79f7651a1` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `sh` |
| First seen | `2026-07-07 21:35:57` |
| Reporter | `abuserobot66609` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31e7b00aa399c66784e2752049886019` |
| SHA-1 | `5051439569bdcbd0428af3157f564966988bea3d` |
| SHA-256 | `dc57f496cc489f275bb58e36d47c760794a0da5532ad13655b761ff79f7651a1` |
| SHA3-384 | `666b9dc8770f6b76f215573f3d6131fc2f44a6f37538331ee0075053bfb8d0daa7b1bfa58b1e5c9f74707cc09e025837` |
| TLSH | `T1D3E026AAB7163C3B0C8ACD6EB162C0B6E09261F04C0B0C889C536C76D05CE0CFC025AA` |
| SSDEEP | `6:h03Z7S6pJ+d9FEc0FpmmbrFHIlmBmmw6fmfUbOWr6Q:cpJ+zF4v3FHdwmGRWrx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_dc57f496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc57f496cc489f275bb58e36d47c760794a0da5532ad13655b761ff79f7651a1"
    family = "unknown"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-07-07 21:35:57"
  condition:
    hash.sha256(0, filesize) == "dc57f496cc489f275bb58e36d47c760794a0da5532ad13655b761ff79f7651a1"
}
```

### Sample 90: `aa4d642727be33ec`

| Field | Value |
|---|---|
| SHA-256 | `aa4d642727be33ecd94acb8a24e546aeed325f08367333bb8974f5e54d99e715` |
| Family label | `RemcosRAT` |
| File name | `379717f664cc19a3f295a11e189dd386.exe` |
| File type | `exe` |
| First seen | `2026-07-07 21:35:12` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `379717f664cc19a3f295a11e189dd386` |
| SHA-1 | `12dec3f8af35e88e3cb377218572081cd619590f` |
| SHA-256 | `aa4d642727be33ecd94acb8a24e546aeed325f08367333bb8974f5e54d99e715` |
| SHA3-384 | `5cf7319e71f9025d30ac1156df91687558d01f0bcc356af17d8833ac1b528b93cd9a953136cf81bd7f90aa9b6ea75d24` |
| IMPHASH | `7d5125df1b721f19e7f94988d3e3ee5a` |
| TLSH | `T131B4AF02B6F2C0B2DA7664300936E735DEBC7C31183699AB63D61D5BBD30151DB39AB2` |
| SSDEEP | `12288:VlQAiR49ckiK7JV8AuE4lKC/kPHM9/IsPZSNj/:Vl0GcNUJV8i4mHM9/DZC` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_090_aa4d6427
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa4d642727be33ecd94acb8a24e546aeed325f08367333bb8974f5e54d99e715"
    family = "RemcosRAT"
    file_name = "379717f664cc19a3f295a11e189dd386.exe"
    file_type = "exe"
    first_seen = "2026-07-07 21:35:12"
  condition:
    hash.sha256(0, filesize) == "aa4d642727be33ecd94acb8a24e546aeed325f08367333bb8974f5e54d99e715"
}
```

### Sample 91: `0fa2579031a74d6a`

| Field | Value |
|---|---|
| SHA-256 | `0fa2579031a74d6ac6477c036f2a53695ab92d907fd0220c48bba31dffa976da` |
| Family label | `ValleyRAT` |
| File name | `32f90f34610520f8dbded26e5e7494c1.exe` |
| File type | `exe` |
| First seen | `2026-07-07 21:09:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32f90f34610520f8dbded26e5e7494c1` |
| SHA-1 | `293e8c07c7a74d66703573907f0562600a782596` |
| SHA-256 | `0fa2579031a74d6ac6477c036f2a53695ab92d907fd0220c48bba31dffa976da` |
| SHA3-384 | `fc53625b9dfb1afedfdf38c1e2a8c1d43074fa9d4b9a2e4c652dc38550c674620442e85d2abadba2193588c4ced76f2f` |
| IMPHASH | `623e33d672ccbd789eb8f17339ff261f` |
| TLSH | `T1DDF4AE0236C55162C4A8CCF29863DA68DEFBAC57ABD171DB4031BABA17FCDE4050CA57` |
| SSDEEP | `12288:lxsyaEDRxhHfV8cQfh19+VCx9TPkF57GvZx148Bo0ya5598lwL:lxJaEVjra9ZYD7GBx14co0ym98lwL` |
| ICON-DHASH | `e6a5b2b296a2ba86` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_091_0fa25790
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fa2579031a74d6ac6477c036f2a53695ab92d907fd0220c48bba31dffa976da"
    family = "ValleyRAT"
    file_name = "32f90f34610520f8dbded26e5e7494c1.exe"
    file_type = "exe"
    first_seen = "2026-07-07 21:09:18"
  condition:
    hash.sha256(0, filesize) == "0fa2579031a74d6ac6477c036f2a53695ab92d907fd0220c48bba31dffa976da"
}
```

### Sample 92: `95a0c24f7192be97`

| Field | Value |
|---|---|
| SHA-256 | `95a0c24f7192be97f40b3d3a6e53b85f33d94fe676415b003517518cf92e663f` |
| Family label | `Mirai` |
| File name | `95a0c24f7192be97f40b3d3a6e53b85f33d94fe676415b003517518cf92e663f` |
| File type | `elf` |
| First seen | `2026-07-07 20:58:23` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d997619c908107fe8d8d96a9697a496c` |
| SHA-1 | `247d8a91b604382c5cc156d0fca4623b68267b95` |
| SHA-256 | `95a0c24f7192be97f40b3d3a6e53b85f33d94fe676415b003517518cf92e663f` |
| SHA3-384 | `cddd280181fcdf3ef691d590c9a2b0aeb30a841248d371584ec9be94ffb6ea85dfe770a417a6083d3710364bb2574650` |
| TLSH | `T134852951FECB54F2E5171E3144ABA2AF27316D054F20EBC7E644BE6EE9376D20832219` |
| TELFHASH | `t1ac428a7329aa68e877f04811866b7220cea6e43715f038721df36490f772d536b76db8` |
| GIMPHASH | `65427d11846b71125298ea1d45c17b269e9dc23c57896bb8789331e2b261409c` |
| SSDEEP | `24576:HHTkJhb/CjCcy/H/gyNDHSVWnNIlzvD/e8NayMz6Q3UWvIDK859b1bVlrSMB/92B:HEx2u8H6DI11ZJ41iYD1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_95a0c24f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95a0c24f7192be97f40b3d3a6e53b85f33d94fe676415b003517518cf92e663f"
    family = "Mirai"
    file_name = "95a0c24f7192be97f40b3d3a6e53b85f33d94fe676415b003517518cf92e663f"
    file_type = "elf"
    first_seen = "2026-07-07 20:58:23"
  condition:
    hash.sha256(0, filesize) == "95a0c24f7192be97f40b3d3a6e53b85f33d94fe676415b003517518cf92e663f"
}
```

### Sample 93: `9bdb2fcdffebcb27`

| Field | Value |
|---|---|
| SHA-256 | `9bdb2fcdffebcb27ae8583801d454d467501bb6ece9054e5fdd64d728bd3cd72` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-07-07 20:57:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9abb6c14837e46fb759d9ab2c66ad3fb` |
| SHA-1 | `77852648bae976e76cb7f6f198b492e4f1ed84e7` |
| SHA-256 | `9bdb2fcdffebcb27ae8583801d454d467501bb6ece9054e5fdd64d728bd3cd72` |
| SHA3-384 | `9a62fcec86bcb249ba88112f815b790c4d980f658fc49f54ad603f31be56f00729bba6fdaf05e46b0933e7ebacc8bdc3` |
| TLSH | `T105333B24B9761E17C0D1687A61FB4B24B6F116CE26E8C65F3D720E8EFF619406903AF4` |
| SSDEEP | `768:vwo0WBxH9bKeW7atS5sk1/L+ejxm4JvtKDBO+lsiyw2:vwGBxH99tS5skZL+e1m42Dxld2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_9bdb2fcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bdb2fcdffebcb27ae8583801d454d467501bb6ece9054e5fdd64d728bd3cd72"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-07 20:57:27"
  condition:
    hash.sha256(0, filesize) == "9bdb2fcdffebcb27ae8583801d454d467501bb6ece9054e5fdd64d728bd3cd72"
}
```

### Sample 94: `3590c31b65c14be9`

| Field | Value |
|---|---|
| SHA-256 | `3590c31b65c14be9cdc6ea70726525be8a1df07d454a6f7b359d1eeac0cd8621` |
| Family label | `ConnectWise` |
| File name | `Google Meet.zip` |
| File type | `zip` |
| First seen | `2026-07-07 20:54:42` |
| Reporter | `skocherhan` |
| Tags | `ConnectWise, join-google-meet-com, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0b682dbbf1a08daf85c0e25ceb8dd8b` |
| SHA-1 | `3cef29d934d54d784b2c715617029fc37168541b` |
| SHA-256 | `3590c31b65c14be9cdc6ea70726525be8a1df07d454a6f7b359d1eeac0cd8621` |
| SHA3-384 | `f81793bd35eadf9da9eab66d0d6474538ebf0e05768fe006a9b39137c3c3815980ee06bfa978f508aae382b33635b725` |
| TLSH | `T104A633246A3FE905B0E86D3FBB4DA8614B684B742C975649970CFBC6C405F3C21CAE79` |
| SSDEEP | `196608:ijHLkU8rbYW37a1VtpbvhQkabkCebFF3YGjfcaprRhSISZn/f:ijHLd8b37aHtpbv/akbFFoG4aprRhwZn` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_094_3590c31b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3590c31b65c14be9cdc6ea70726525be8a1df07d454a6f7b359d1eeac0cd8621"
    family = "ConnectWise"
    file_name = "Google Meet.zip"
    file_type = "zip"
    first_seen = "2026-07-07 20:54:42"
  condition:
    hash.sha256(0, filesize) == "3590c31b65c14be9cdc6ea70726525be8a1df07d454a6f7b359d1eeac0cd8621"
}
```

### Sample 95: `4db0eef20a14febe`

| Field | Value |
|---|---|
| SHA-256 | `4db0eef20a14febe6082fc641d33539ec86d2c38379556d9f315789fa6f58296` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-07 20:52:12` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e3a7715a512f529a017d099781e4e19` |
| SHA-1 | `c996d6f321d0a75c7e551d07acd4170599ef6a75` |
| SHA-256 | `4db0eef20a14febe6082fc641d33539ec86d2c38379556d9f315789fa6f58296` |
| SHA3-384 | `1042cef19e57897c161391997cd8170f4a3c58137034410ff6c02e97fd3a8c5e82c05e7d0e0c662bb8f18578e36f7cf8` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T14FE6330C66E012FAE677C23CEAE04555E17578760B73C5E7177466A36E272F0883EA23` |
| SSDEEP | `393216:djw6WMoUT89lI0qNqaJ7XMCHWUjXOcuI3/PGTAI:dNWFk8jINq+7XMb8XjH/O7` |
| ICON-DHASH | `5471d4d8c8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_4db0eef2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4db0eef20a14febe6082fc641d33539ec86d2c38379556d9f315789fa6f58296"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 20:52:12"
  condition:
    hash.sha256(0, filesize) == "4db0eef20a14febe6082fc641d33539ec86d2c38379556d9f315789fa6f58296"
}
```

### Sample 96: `ca9b8a1113669683`

| Field | Value |
|---|---|
| SHA-256 | `ca9b8a1113669683961f2ee4bf028f54dcb42daf35b51ba2c60195769247f7ef` |
| Family label | `Mirai` |
| File name | `zlkbnkpmc` |
| File type | `elf` |
| First seen | `2026-07-07 20:31:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `982c80e82b96b6ab930e7f82953f5215` |
| SHA-1 | `7fe69f5c9ed5858a7159987a07aa18da13b8b84c` |
| SHA-256 | `ca9b8a1113669683961f2ee4bf028f54dcb42daf35b51ba2c60195769247f7ef` |
| SHA3-384 | `9bd286d4cd08dced57e5e48cec0ee166005218a20ede8c9a2fe92b5f9acf9c43eaccd25fcfad83b06813eb8e98877660` |
| TLSH | `T172935B42F3080A47DAA31EB0363727E253AAE58223E9F6847A0FDB51D171D326D45EDD` |
| SSDEEP | `1536:WdU183G3iRIqQYNrnVNJAazE4g2h5yasQ5dIdAcYLKtOtOv8FsNc:m/3G3iRI0NrHJeGh0Id0Accz7Uc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_ca9b8a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca9b8a1113669683961f2ee4bf028f54dcb42daf35b51ba2c60195769247f7ef"
    family = "Mirai"
    file_name = "zlkbnkpmc"
    file_type = "elf"
    first_seen = "2026-07-07 20:31:53"
  condition:
    hash.sha256(0, filesize) == "ca9b8a1113669683961f2ee4bf028f54dcb42daf35b51ba2c60195769247f7ef"
}
```

### Sample 97: `2d6156646c286071`

| Field | Value |
|---|---|
| SHA-256 | `2d6156646c286071b94fb2d75089974912c1eeb8b83457a24d346c397794043c` |
| Family label | `AsyncRAT` |
| File name | `lnvoice8343783.js` |
| File type | `js` |
| First seen | `2026-07-07 20:23:16` |
| Reporter | `James_inthe_box` |
| Tags | `AsyncRAT, exe, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c40f48e089adbcc9f1ab7ff1b364dd2c` |
| SHA-1 | `a7817f0a2516746cec97a268ec39cef2bd8cd1c4` |
| SHA-256 | `2d6156646c286071b94fb2d75089974912c1eeb8b83457a24d346c397794043c` |
| SHA3-384 | `7573faf79587fb6365315235ed3edc4c5f80303e104166b82f81fd804bd6128d8196e65e3ec730463c314cde8d3c50f1` |
| TLSH | `T1C3269FC089A6F8272666DD25AF0BAB9D688DD45FD6D3EB04F4C41B4FE668139C0E47C0` |
| SSDEEP | `12288:VZU/ABAICGUF4HpBMtJ9ggX+BYVO+w2kyU5v4wZn/beYViloo4boPAB7lH++fC9d:gPSj1rx7YmJNYakU1O` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_097_2d615664
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d6156646c286071b94fb2d75089974912c1eeb8b83457a24d346c397794043c"
    family = "AsyncRAT"
    file_name = "lnvoice8343783.js"
    file_type = "js"
    first_seen = "2026-07-07 20:23:16"
  condition:
    hash.sha256(0, filesize) == "2d6156646c286071b94fb2d75089974912c1eeb8b83457a24d346c397794043c"
}
```

### Sample 98: `cc3a50e9fdd6d553`

| Field | Value |
|---|---|
| SHA-256 | `cc3a50e9fdd6d553fe77d77ed4603786a18b9e4068df1edac44d84fd491a9dac` |
| Family label | `Mirai` |
| File name | `ytaabxcxa` |
| File type | `elf` |
| First seen | `2026-07-07 20:21:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `019859f22df35de6730392a87a070025` |
| SHA-1 | `bed1eb171ec98fe449af4a5615e30d4c91c7b4df` |
| SHA-256 | `cc3a50e9fdd6d553fe77d77ed4603786a18b9e4068df1edac44d84fd491a9dac` |
| SHA3-384 | `1f8e67662de77c566bb6af0d449b71b4536346d2b3b8b7435abce6013f172ed0f97ebe507a7e3fc131b6c3a4406136d5` |
| TLSH | `T128A34B44E6C3E4F5F801157930676B76E973E13A7136EB8BEBDC8A328822601E50B75D` |
| TELFHASH | `t19331e5f6aa714ca87bc09906f78f2772dd2dab772570237a09f5281032e1402527bd3c` |
| SSDEEP | `3072:ax9pMoY2EOYaNZe5McyFTrDwy0XczkT0Lddz:ax9p/KPcU7II7Wl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_cc3a50e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc3a50e9fdd6d553fe77d77ed4603786a18b9e4068df1edac44d84fd491a9dac"
    family = "Mirai"
    file_name = "ytaabxcxa"
    file_type = "elf"
    first_seen = "2026-07-07 20:21:31"
  condition:
    hash.sha256(0, filesize) == "cc3a50e9fdd6d553fe77d77ed4603786a18b9e4068df1edac44d84fd491a9dac"
}
```

### Sample 99: `761e0518edc0ffba`

| Field | Value |
|---|---|
| SHA-256 | `761e0518edc0ffba669d4212bb00b24b884af4b2973575a71516d37abe186fa5` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-07 19:58:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee716a7084270614ae4112f414b45659` |
| SHA-1 | `617d55a499920550a3116700c63e0b093a2b0a96` |
| SHA-256 | `761e0518edc0ffba669d4212bb00b24b884af4b2973575a71516d37abe186fa5` |
| SHA3-384 | `58e9ea3610112e37cb20b65ca2aaadae4fba5f5f13f9772c3b767474cb4df18f2ce91ddcb4b0f279e82e67382c18ff4f` |
| TLSH | `T1DC831951F8915A13C6D122B7FB9E428D332717ACD2FA32039D256F21738B85B0E77646` |
| TELFHASH | `t1f7412ea29eac0bdc27f0435480cf255e42a435e937103a11df5eb74fa2429d2b02dc36` |
| SSDEEP | `1536:siAvy5td378Kdy5JFzCfcG7OUJz51RXcakMvQ0AyIxXOIYva:lAa5r378FFc1OUJz5DIyIka` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_761e0518
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "761e0518edc0ffba669d4212bb00b24b884af4b2973575a71516d37abe186fa5"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-07 19:58:27"
  condition:
    hash.sha256(0, filesize) == "761e0518edc0ffba669d4212bb00b24b884af4b2973575a71516d37abe186fa5"
}
```

### Sample 100: `093775d9ef9ad626`

| Field | Value |
|---|---|
| SHA-256 | `093775d9ef9ad6267c340a26c03432f4a40951071130526a109ec191a6dcf27d` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-07 19:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe7e8511187db490f21214a63da39e6b` |
| SHA-1 | `890f52b74c1bc87fde6ddacab7e238bfa4529644` |
| SHA-256 | `093775d9ef9ad6267c340a26c03432f4a40951071130526a109ec191a6dcf27d` |
| SHA3-384 | `1997215c8d4f2d69fd916db2601234b6aaeb4fee95bafe828b8b93f5429fd1fc24dd10a8ac7f1afc8470fc25b7628638` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T167E6330CAAD002FEDBB2413DEDE11295D5A474BB17B2C5DB079483E0ED2B2E48936B57` |
| SSDEEP | `393216:hX816dQTM9qPlXMCHWUjX3cuI3/PGTAI:hs16dylXMb8XMH/O7` |
| ICON-DHASH | `70f0f0e8e8f0f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_093775d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "093775d9ef9ad6267c340a26c03432f4a40951071130526a109ec191a6dcf27d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 19:52:11"
  condition:
    hash.sha256(0, filesize) == "093775d9ef9ad6267c340a26c03432f4a40951071130526a109ec191a6dcf27d"
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
 * Generated: 2026-07-08T03:49:43.440122+00:00
 */

rule MalwareBazaar_Vidar_001_f8c56b8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8c56b8a1ecfa06186f0d1dc3e566223aba52e282dcce895d493cbe78d9db512"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-08 03:32:45"
  condition:
    hash.sha256(0, filesize) == "f8c56b8a1ecfa06186f0d1dc3e566223aba52e282dcce895d493cbe78d9db512"
}

rule MalwareBazaar_njrat_002_69cd34ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69cd34ef2d9b26fad86387d6ef3556a7a7bdd13bf7e45f810fd7c2bbff30974b"
    family = "njrat"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-08 03:20:25"
  condition:
    hash.sha256(0, filesize) == "69cd34ef2d9b26fad86387d6ef3556a7a7bdd13bf7e45f810fd7c2bbff30974b"
}

rule MalwareBazaar_unknown_003_3a2ce5b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a2ce5b01dc23cbe768df69bc04fcb4e68ee58f1341a767f0cbfd3cd15440a59"
    family = "unknown"
    file_name = "Sprogvidenskabsmandens.vbs"
    file_type = "vbs"
    first_seen = "2026-07-08 03:14:37"
  condition:
    hash.sha256(0, filesize) == "3a2ce5b01dc23cbe768df69bc04fcb4e68ee58f1341a767f0cbfd3cd15440a59"
}

rule MalwareBazaar_unknown_004_24b1c3f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24b1c3f96179633ed7a40190ea103c558cc182c32cab38e3399a81524cb578b5"
    family = "unknown"
    file_name = "Clash-X64.exe"
    file_type = "exe"
    first_seen = "2026-07-08 02:55:22"
  condition:
    hash.sha256(0, filesize) == "24b1c3f96179633ed7a40190ea103c558cc182c32cab38e3399a81524cb578b5"
}

rule MalwareBazaar_unknown_005_f8d9727d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8d9727dcae3e07980899001689724c3b0d71f446ded7344bb0550df9f4e157e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-08 02:52:12"
  condition:
    hash.sha256(0, filesize) == "f8d9727dcae3e07980899001689724c3b0d71f446ded7344bb0550df9f4e157e"
}

rule MalwareBazaar_CoinMiner_006_6c303e19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c303e19f1337a7eacef23bdd882d97329bebc7aff0d42f0726d2c876e3cdea5"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-08 02:41:27"
  condition:
    hash.sha256(0, filesize) == "6c303e19f1337a7eacef23bdd882d97329bebc7aff0d42f0726d2c876e3cdea5"
}

rule MalwareBazaar_unknown_007_6a83689b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a83689b2dfdaed0f04d621d34b066aca3238d224575f961dc2448b8bfdd0658"
    family = "unknown"
    file_name = "6a83689b2dfdaed0f04d621d34b066aca3238d224575f961dc2448b8bfdd0658"
    file_type = "exe"
    first_seen = "2026-07-08 02:15:25"
  condition:
    hash.sha256(0, filesize) == "6a83689b2dfdaed0f04d621d34b066aca3238d224575f961dc2448b8bfdd0658"
}

rule MalwareBazaar_CoinMiner_008_c8415587
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8415587863d57e1cc4aa543ee9c0cb04ec486f031b49f2d7448631c4a5b29da"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-08 02:11:32"
  condition:
    hash.sha256(0, filesize) == "c8415587863d57e1cc4aa543ee9c0cb04ec486f031b49f2d7448631c4a5b29da"
}

rule MalwareBazaar_Mirai_009_e4897305
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4897305c584eb9c2dee7fbf0cea9f454a2aadf83736edfa497b610d60e6aa3e"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-08 02:08:39"
  condition:
    hash.sha256(0, filesize) == "e4897305c584eb9c2dee7fbf0cea9f454a2aadf83736edfa497b610d60e6aa3e"
}

rule MalwareBazaar_Mirai_010_7433b8c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7433b8c9472586d713797a725388c7cad5c070311051a2355ce1f880d41f94f6"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-08 02:07:38"
  condition:
    hash.sha256(0, filesize) == "7433b8c9472586d713797a725388c7cad5c070311051a2355ce1f880d41f94f6"
}

rule MalwareBazaar_unknown_011_90e72cb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90e72cb310525972af1e9d97cd837d48aaf87a429930b507f56befddff1ff713"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-08 02:04:27"
  condition:
    hash.sha256(0, filesize) == "90e72cb310525972af1e9d97cd837d48aaf87a429930b507f56befddff1ff713"
}

rule MalwareBazaar_Mirai_012_3afefe3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3afefe3a97b3df9dffee6259161dd4e1c37a59f4726f68d9194921a631b1058b"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-08 02:02:20"
  condition:
    hash.sha256(0, filesize) == "3afefe3a97b3df9dffee6259161dd4e1c37a59f4726f68d9194921a631b1058b"
}

rule MalwareBazaar_Mirai_013_0bfb8671
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bfb8671ec522cc77656f514c3cff9034ef67f97a780672ade79804eccafe7a4"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-08 02:00:42"
  condition:
    hash.sha256(0, filesize) == "0bfb8671ec522cc77656f514c3cff9034ef67f97a780672ade79804eccafe7a4"
}

rule MalwareBazaar_Mirai_014_02666285
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02666285148eae0968f8e25b6c6de6ebe8827b8b15e25ef617635ad3b4e24007"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-08 01:52:50"
  condition:
    hash.sha256(0, filesize) == "02666285148eae0968f8e25b6c6de6ebe8827b8b15e25ef617635ad3b4e24007"
}

rule MalwareBazaar_Mirai_015_53315d31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53315d3131904093f56cffcccb235424aa53eb24ff814c68c6dece1a3744a2fe"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-07-08 01:52:49"
  condition:
    hash.sha256(0, filesize) == "53315d3131904093f56cffcccb235424aa53eb24ff814c68c6dece1a3744a2fe"
}

rule MalwareBazaar_unknown_016_87b25bb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87b25bb68d599cee8dcd11fee91b3b1a03c87eca0f460c6ed0962fc26239674c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-08 01:52:47"
  condition:
    hash.sha256(0, filesize) == "87b25bb68d599cee8dcd11fee91b3b1a03c87eca0f460c6ed0962fc26239674c"
}

rule MalwareBazaar_unknown_017_85752e86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85752e86ea189634b042f5bb296f4fe0851a1a71ecd3a8228110740fff89f4bc"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-08 01:52:12"
  condition:
    hash.sha256(0, filesize) == "85752e86ea189634b042f5bb296f4fe0851a1a71ecd3a8228110740fff89f4bc"
}

rule MalwareBazaar_Mirai_018_524fef05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "524fef057a18f499117e6ab2c3cde2bef7f6d2c9fc2b51a462b269261f3fa713"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:59"
  condition:
    hash.sha256(0, filesize) == "524fef057a18f499117e6ab2c3cde2bef7f6d2c9fc2b51a462b269261f3fa713"
}

rule MalwareBazaar_Mirai_019_d7eb9ab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7eb9ab28d047c28fb5310415c8fd29b37498c855f8a3ea446248e7f5fd08a15"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:56"
  condition:
    hash.sha256(0, filesize) == "d7eb9ab28d047c28fb5310415c8fd29b37498c855f8a3ea446248e7f5fd08a15"
}

rule MalwareBazaar_Mirai_020_ce9d2c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce9d2c70b2ce2eb27ba7f39b374f4529a3c27e8e1ad450c9697d066a88ad28fe"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:51"
  condition:
    hash.sha256(0, filesize) == "ce9d2c70b2ce2eb27ba7f39b374f4529a3c27e8e1ad450c9697d066a88ad28fe"
}

rule MalwareBazaar_Mirai_021_0d0e414d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d0e414d42ca89f5556132fece6b5e9493e6f3b349edcec249edfb32c38fc3d3"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:18"
  condition:
    hash.sha256(0, filesize) == "0d0e414d42ca89f5556132fece6b5e9493e6f3b349edcec249edfb32c38fc3d3"
}

rule MalwareBazaar_Mirai_022_f6878049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f687804910db04e241f6f734522ab8af7ae2135d173a98173c17b11b3a65824f"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:16"
  condition:
    hash.sha256(0, filesize) == "f687804910db04e241f6f734522ab8af7ae2135d173a98173c17b11b3a65824f"
}

rule MalwareBazaar_Mirai_023_e67901d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e67901d60d2dfbfc71154b1aa0aeb10a828a346910869d75629ebbdb2b89bd8d"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:14"
  condition:
    hash.sha256(0, filesize) == "e67901d60d2dfbfc71154b1aa0aeb10a828a346910869d75629ebbdb2b89bd8d"
}

rule MalwareBazaar_Mirai_024_490ea48b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "490ea48be8568beaaa07f1f269b482fa3cf0515232720de76b9fbd6614465d97"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:13"
  condition:
    hash.sha256(0, filesize) == "490ea48be8568beaaa07f1f269b482fa3cf0515232720de76b9fbd6614465d97"
}

rule MalwareBazaar_Mirai_025_2318a341
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2318a3412ad9136dc4b997a1159748cd6f15e2cdf9efb861f7461076112e498c"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-08 01:48:11"
  condition:
    hash.sha256(0, filesize) == "2318a3412ad9136dc4b997a1159748cd6f15e2cdf9efb861f7461076112e498c"
}

rule MalwareBazaar_AgentTesla_026_8f3e7455
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f3e745546f76f645ff13164d65a18c60a7e74324ac902bca3c1af0f7b21a40c"
    family = "AgentTesla"
    file_name = "NEW_PURCHASE_ORDER.js"
    file_type = "js"
    first_seen = "2026-07-08 01:46:38"
  condition:
    hash.sha256(0, filesize) == "8f3e745546f76f645ff13164d65a18c60a7e74324ac902bca3c1af0f7b21a40c"
}

rule MalwareBazaar_Mirai_027_b072f91c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b072f91c6091716c3300189e14c3a0d6b6f52b3f1a2baf36f8df5456275da4a0"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-08 01:37:55"
  condition:
    hash.sha256(0, filesize) == "b072f91c6091716c3300189e14c3a0d6b6f52b3f1a2baf36f8df5456275da4a0"
}

rule MalwareBazaar_unknown_028_5293f5c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5293f5c2af79144e8643cbdfd3ecd913eb5687551ee91376e6416c9624f7c96d"
    family = "unknown"
    file_name = "x"
    file_type = "sh"
    first_seen = "2026-07-08 01:35:52"
  condition:
    hash.sha256(0, filesize) == "5293f5c2af79144e8643cbdfd3ecd913eb5687551ee91376e6416c9624f7c96d"
}

rule MalwareBazaar_Mirai_029_e232ea3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e232ea3c0d93fb985c774ac8dcb41cc6c2301ab7f06a5054fbf25c14d839ac1c"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-08 01:35:46"
  condition:
    hash.sha256(0, filesize) == "e232ea3c0d93fb985c774ac8dcb41cc6c2301ab7f06a5054fbf25c14d839ac1c"
}

rule MalwareBazaar_Mirai_030_04091fb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04091fb5f36bccd38e322b8201b8cb4dccb97934faad702686bce72a155a7be4"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-08 01:29:20"
  condition:
    hash.sha256(0, filesize) == "04091fb5f36bccd38e322b8201b8cb4dccb97934faad702686bce72a155a7be4"
}

rule MalwareBazaar_Mirai_031_7351070d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7351070d88ba2bddfc44f0aba506065fba845d18804d716a7a5c64cecd74e3cc"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-08 01:29:07"
  condition:
    hash.sha256(0, filesize) == "7351070d88ba2bddfc44f0aba506065fba845d18804d716a7a5c64cecd74e3cc"
}

rule MalwareBazaar_Mirai_032_4b86b1cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b86b1ccd44841f0639b8946d9fae2f82e8b759e22cb412a0f6e3ec326737052"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:16"
  condition:
    hash.sha256(0, filesize) == "4b86b1ccd44841f0639b8946d9fae2f82e8b759e22cb412a0f6e3ec326737052"
}

rule MalwareBazaar_unknown_033_6196d48e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6196d48e1cb751908020b6f3a04c69855ddb4b7eb4c5003f22185ff5f52a156d"
    family = "unknown"
    file_name = "kworkerd-blkcg"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:14"
  condition:
    hash.sha256(0, filesize) == "6196d48e1cb751908020b6f3a04c69855ddb4b7eb4c5003f22185ff5f52a156d"
}

rule MalwareBazaar_Mirai_034_477948f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "477948f3000fcffc496816eb3688faf63f9969d15211ce647f0bba17c25867b5"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:13"
  condition:
    hash.sha256(0, filesize) == "477948f3000fcffc496816eb3688faf63f9969d15211ce647f0bba17c25867b5"
}

rule MalwareBazaar_Mirai_035_ec184ac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec184ac73eb461219a481eefff4b6406c88fde59b8074859ddb1a66ade533e33"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:11"
  condition:
    hash.sha256(0, filesize) == "ec184ac73eb461219a481eefff4b6406c88fde59b8074859ddb1a66ade533e33"
}

rule MalwareBazaar_Mirai_036_0203c5c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0203c5c6f6ecbcfa7eb83c7e9cd222635643a587637b9c538740ad687cc0d5cf"
    family = "Mirai"
    file_name = "kworkerd-irq-bal"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:10"
  condition:
    hash.sha256(0, filesize) == "0203c5c6f6ecbcfa7eb83c7e9cd222635643a587637b9c538740ad687cc0d5cf"
}

rule MalwareBazaar_Gafgyt_037_05686c56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05686c56837324d1bbb9b98c331bd689af81de4a27c52a4d84ace7e25302e111"
    family = "Gafgyt"
    file_name = "kworkerd"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:08"
  condition:
    hash.sha256(0, filesize) == "05686c56837324d1bbb9b98c331bd689af81de4a27c52a4d84ace7e25302e111"
}

rule MalwareBazaar_Mirai_038_cab38a31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab38a319673fd9b4c336423781b32cc9128250e2acc1cd0a5bc06ade673e40a"
    family = "Mirai"
    file_name = "kworkerd-crypto"
    file_type = "elf"
    first_seen = "2026-07-08 01:28:06"
  condition:
    hash.sha256(0, filesize) == "cab38a319673fd9b4c336423781b32cc9128250e2acc1cd0a5bc06ade673e40a"
}

rule MalwareBazaar_Mirai_039_10c76163
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10c76163201a46c7a7e5df1f2bb2d25bd79bc348baba7c17ee46bd4eef5148f6"
    family = "Mirai"
    file_name = "kworkerd-events"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:45"
  condition:
    hash.sha256(0, filesize) == "10c76163201a46c7a7e5df1f2bb2d25bd79bc348baba7c17ee46bd4eef5148f6"
}

rule MalwareBazaar_unknown_040_7e1c84a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e1c84a430b802180aff2c1e2aa1eca1bc5361f9040c5eb801b34b3517aabba9"
    family = "unknown"
    file_name = "kworkerd-softirq"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:43"
  condition:
    hash.sha256(0, filesize) == "7e1c84a430b802180aff2c1e2aa1eca1bc5361f9040c5eb801b34b3517aabba9"
}

rule MalwareBazaar_unknown_041_4dc47959
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dc47959cb6437a9de370647fcc8bc63c2882def695e008536b539152acd103c"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:41"
  condition:
    hash.sha256(0, filesize) == "4dc47959cb6437a9de370647fcc8bc63c2882def695e008536b539152acd103c"
}

rule MalwareBazaar_unknown_042_2081580b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2081580b46e6903e856f457ee1511c1a89d571a2285e2f227308fafc402db71c"
    family = "unknown"
    file_name = "kworkerd-netns"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:39"
  condition:
    hash.sha256(0, filesize) == "2081580b46e6903e856f457ee1511c1a89d571a2285e2f227308fafc402db71c"
}

rule MalwareBazaar_unknown_043_ae5946d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae5946d2ee25fbdbd341d3909c8226d3152376d2b68e523cbb323bccf29a0481"
    family = "unknown"
    file_name = "kworkerd-netns-rt"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:36"
  condition:
    hash.sha256(0, filesize) == "ae5946d2ee25fbdbd341d3909c8226d3152376d2b68e523cbb323bccf29a0481"
}

rule MalwareBazaar_Mirai_044_0b6f0857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b6f0857667812293553e16851e032db675666ee17b52385fb33dc0a6c60f24d"
    family = "Mirai"
    file_name = "kworkerd-irq"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:34"
  condition:
    hash.sha256(0, filesize) == "0b6f0857667812293553e16851e032db675666ee17b52385fb33dc0a6c60f24d"
}

rule MalwareBazaar_unknown_045_1f152c19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f152c19dab01a8928ac2f7fc48e69c742983e05ce5b98437a88c7f3967854d4"
    family = "unknown"
    file_name = "kworkerd-writeback"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:32"
  condition:
    hash.sha256(0, filesize) == "1f152c19dab01a8928ac2f7fc48e69c742983e05ce5b98437a88c7f3967854d4"
}

rule MalwareBazaar_Mirai_046_0dcf6d7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dcf6d7ee47fb371d7ebbca1d4f62d4707514237215d8044e588783cf0aae1bb"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-08 01:25:29"
  condition:
    hash.sha256(0, filesize) == "0dcf6d7ee47fb371d7ebbca1d4f62d4707514237215d8044e588783cf0aae1bb"
}

rule MalwareBazaar_Mirai_047_95fb2c80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95fb2c80e84f84f6dfb95d31d9c3baa1e22735f8951ed9024a88deebd839a0af"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-07-08 01:21:17"
  condition:
    hash.sha256(0, filesize) == "95fb2c80e84f84f6dfb95d31d9c3baa1e22735f8951ed9024a88deebd839a0af"
}

rule MalwareBazaar_Mirai_048_5f6fd4e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f6fd4e77c577137130fe0777ff434fac5dfb03908a6e094fc3fb33cc39fb189"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-08 01:12:47"
  condition:
    hash.sha256(0, filesize) == "5f6fd4e77c577137130fe0777ff434fac5dfb03908a6e094fc3fb33cc39fb189"
}

rule MalwareBazaar_Mirai_049_c18a7f26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c18a7f266c4e1ad9447389bb6911539cda1b59a03d795c7932070aee5fc27ee2"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-08 01:11:42"
  condition:
    hash.sha256(0, filesize) == "c18a7f266c4e1ad9447389bb6911539cda1b59a03d795c7932070aee5fc27ee2"
}

rule MalwareBazaar_Mirai_050_32884e5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32884e5b3f5005b89af62bb44fab9e112e59f5c97fe465efc99702627cced30a"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-08 01:08:46"
  condition:
    hash.sha256(0, filesize) == "32884e5b3f5005b89af62bb44fab9e112e59f5c97fe465efc99702627cced30a"
}

rule MalwareBazaar_Mirai_051_3b5ba0ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b5ba0aeaea18d4a15b3959b0ec7fd105d9da813121734d7b3f37929b9a8a9a1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-08 01:07:57"
  condition:
    hash.sha256(0, filesize) == "3b5ba0aeaea18d4a15b3959b0ec7fd105d9da813121734d7b3f37929b9a8a9a1"
}

rule MalwareBazaar_Mirai_052_fdef885d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdef885dbd4fe4d9a38821c0eac2d3ea77702ab890debb47c9957908d9398e81"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-08 01:06:24"
  condition:
    hash.sha256(0, filesize) == "fdef885dbd4fe4d9a38821c0eac2d3ea77702ab890debb47c9957908d9398e81"
}

rule MalwareBazaar_Mirai_053_42a1f2fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42a1f2fa4c787a112d65ce7382d47c56e4747127ebc6dbef96e27cc2ff4e88f0"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-08 01:06:16"
  condition:
    hash.sha256(0, filesize) == "42a1f2fa4c787a112d65ce7382d47c56e4747127ebc6dbef96e27cc2ff4e88f0"
}

rule MalwareBazaar_Mirai_054_3be63fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3be63fb0d1ddaef2a579aa419ce6762d50817620bcf0484e083b1c1952d9964e"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-07-08 01:05:22"
  condition:
    hash.sha256(0, filesize) == "3be63fb0d1ddaef2a579aa419ce6762d50817620bcf0484e083b1c1952d9964e"
}

rule MalwareBazaar_Mirai_055_57a27038
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57a2703848d25574cc777185449251a59ecf6c0a753c510af8da61e26741e8a4"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-08 01:05:20"
  condition:
    hash.sha256(0, filesize) == "57a2703848d25574cc777185449251a59ecf6c0a753c510af8da61e26741e8a4"
}

rule MalwareBazaar_Mirai_056_9b6e06c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b6e06c78785a4e2878a05702b1965036beb82a15104c03993720d621218acab"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-08 01:02:59"
  condition:
    hash.sha256(0, filesize) == "9b6e06c78785a4e2878a05702b1965036beb82a15104c03993720d621218acab"
}

rule MalwareBazaar_Mirai_057_f4d8dc95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d8dc95bb1d731026ad139f3a25f338fc4879704e0afd38e91ccc416b06279e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-08 01:02:24"
  condition:
    hash.sha256(0, filesize) == "f4d8dc95bb1d731026ad139f3a25f338fc4879704e0afd38e91ccc416b06279e"
}

rule MalwareBazaar_unknown_058_65ce1634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65ce16346db5e4d0abb76776b550325ff32b01bfe69d3b0eda52bb9e5e119a0d"
    family = "unknown"
    file_name = "65ce16346db5e4d0abb76776b550325ff32b01bfe69d3b0eda52bb9e5e119a0d"
    file_type = "gz"
    first_seen = "2026-07-08 01:01:35"
  condition:
    hash.sha256(0, filesize) == "65ce16346db5e4d0abb76776b550325ff32b01bfe69d3b0eda52bb9e5e119a0d"
}

rule MalwareBazaar_unknown_059_ade67d4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ade67d4d7e7a5e572e78d5a1b47033c21080f7e136c108129b0e287774e83cc2"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-08 00:52:09"
  condition:
    hash.sha256(0, filesize) == "ade67d4d7e7a5e572e78d5a1b47033c21080f7e136c108129b0e287774e83cc2"
}

rule MalwareBazaar_Mirai_060_720e2068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "720e20680e13735954dc42eb2aa09cba84c7b0aaff69d594fd4c01fd7323de44"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-08 00:51:45"
  condition:
    hash.sha256(0, filesize) == "720e20680e13735954dc42eb2aa09cba84c7b0aaff69d594fd4c01fd7323de44"
}

rule MalwareBazaar_Mirai_061_b60a4c63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b60a4c6391bcab56d7b152aabec161ef462ca4a3dd5469019aca5b45a4b09c91"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-08 00:51:35"
  condition:
    hash.sha256(0, filesize) == "b60a4c6391bcab56d7b152aabec161ef462ca4a3dd5469019aca5b45a4b09c91"
}

rule MalwareBazaar_Mirai_062_6a89179d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a89179df5a928a0dabbc9a792f4f39729a343f8c13c10487cdf9271d44d8383"
    family = "Mirai"
    file_name = "bot_x86_64"
    file_type = "elf"
    first_seen = "2026-07-08 00:17:23"
  condition:
    hash.sha256(0, filesize) == "6a89179df5a928a0dabbc9a792f4f39729a343f8c13c10487cdf9271d44d8383"
}

rule MalwareBazaar_Mirai_063_f56929af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f56929affb830daae30c1be4d1864df512d48b9210a2976eb38260d54cb33149"
    family = "Mirai"
    file_name = "bot"
    file_type = "elf"
    first_seen = "2026-07-08 00:17:22"
  condition:
    hash.sha256(0, filesize) == "f56929affb830daae30c1be4d1864df512d48b9210a2976eb38260d54cb33149"
}

rule MalwareBazaar_unknown_064_6c1aaef8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c1aaef872faae9ec1c56d5230d2f9c17e4bee0d95545e2541f8f68ba1d5b9eb"
    family = "unknown"
    file_name = "bot.sh"
    file_type = "sh"
    first_seen = "2026-07-08 00:17:21"
  condition:
    hash.sha256(0, filesize) == "6c1aaef872faae9ec1c56d5230d2f9c17e4bee0d95545e2541f8f68ba1d5b9eb"
}

rule MalwareBazaar_CoinMiner_065_7ddfafe7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ddfafe75d3b360530299abea5838bc26d6430be756030e1b9cccc2ec5fe4134"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-08 00:16:14"
  condition:
    hash.sha256(0, filesize) == "7ddfafe75d3b360530299abea5838bc26d6430be756030e1b9cccc2ec5fe4134"
}

rule MalwareBazaar_Mirai_066_7dcc39a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dcc39a70a58be7899ca6d3fbcbd7aeba3e6665bc38a7a0125e9fda5d84dee0f"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.6486.20935"
    file_type = "elf"
    first_seen = "2026-07-08 00:01:36"
  condition:
    hash.sha256(0, filesize) == "7dcc39a70a58be7899ca6d3fbcbd7aeba3e6665bc38a7a0125e9fda5d84dee0f"
}

rule MalwareBazaar_Mirai_067_11f2932b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11f2932b3e4903e934f08fb6f7c099650f1f62a52f4cb3cd65e0445fbc6ad84c"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.6486.20935"
    file_type = "elf"
    first_seen = "2026-07-07 23:59:32"
  condition:
    hash.sha256(0, filesize) == "11f2932b3e4903e934f08fb6f7c099650f1f62a52f4cb3cd65e0445fbc6ad84c"
}

rule MalwareBazaar_unknown_068_5261f86c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5261f86cf9d88e316622856618f5624aa0887860c456176bce9fc8b4729f3d2a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 23:52:09"
  condition:
    hash.sha256(0, filesize) == "5261f86cf9d88e316622856618f5624aa0887860c456176bce9fc8b4729f3d2a"
}

rule MalwareBazaar_Stealc_069_8b7537c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b7537c6624998423c0dc5e63d133a4380df59ff64a623f35f2f669e63061c52"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 23:48:34"
  condition:
    hash.sha256(0, filesize) == "8b7537c6624998423c0dc5e63d133a4380df59ff64a623f35f2f669e63061c52"
}

rule MalwareBazaar_Mirai_070_11feb123
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11feb1239237e30844191c3c493ec317e78a0db27c99bf3358c18b8388f5469a"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-07 23:41:40"
  condition:
    hash.sha256(0, filesize) == "11feb1239237e30844191c3c493ec317e78a0db27c99bf3358c18b8388f5469a"
}

rule MalwareBazaar_Mirai_071_a1511521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1511521dc5f5a5f7fb8f5ab3a52b63a600edf5adf4f5d1f1264212e52d338bf"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-07 23:40:55"
  condition:
    hash.sha256(0, filesize) == "a1511521dc5f5a5f7fb8f5ab3a52b63a600edf5adf4f5d1f1264212e52d338bf"
}

rule MalwareBazaar_unknown_072_fe206a75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe206a7571e80bb15a6cd0427f904dc859e2bd3b92a410ce2a3e1fac31599c2b"
    family = "unknown"
    file_name = "zinst.6638258007.msi"
    file_type = "msi"
    first_seen = "2026-07-07 23:30:51"
  condition:
    hash.sha256(0, filesize) == "fe206a7571e80bb15a6cd0427f904dc859e2bd3b92a410ce2a3e1fac31599c2b"
}

rule MalwareBazaar_unknown_073_308fbf5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "308fbf5c75a79e0e2dcf061ec57f8a4e67b7259d7595cca1f6c2142028a5019f"
    family = "unknown"
    file_name = "nRFQ_Clinica_Radiologia_Medicals_PNG.tar"
    file_type = "tar"
    first_seen = "2026-07-07 23:30:10"
  condition:
    hash.sha256(0, filesize) == "308fbf5c75a79e0e2dcf061ec57f8a4e67b7259d7595cca1f6c2142028a5019f"
}

rule MalwareBazaar_ValleyRAT_074_efbc44c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efbc44c07e46535a1c7e53e276c7d106b6aebe071004cb84a5b89db573679006"
    family = "ValleyRAT"
    file_name = "DeepL.msi"
    file_type = "msi"
    first_seen = "2026-07-07 23:30:02"
  condition:
    hash.sha256(0, filesize) == "efbc44c07e46535a1c7e53e276c7d106b6aebe071004cb84a5b89db573679006"
}

rule MalwareBazaar_unknown_075_c99e82c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c99e82c28b5fd8ebd3c0b8e07cd3f24a65208c26e3aedf0ef60111e28ca71444"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 23:24:04"
  condition:
    hash.sha256(0, filesize) == "c99e82c28b5fd8ebd3c0b8e07cd3f24a65208c26e3aedf0ef60111e28ca71444"
}

rule MalwareBazaar_Mirai_076_433d2421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "433d2421b7f116b32b878c36cb68512331588d1b679b1c6b8c716fcea7a919b4"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:14"
  condition:
    hash.sha256(0, filesize) == "433d2421b7f116b32b878c36cb68512331588d1b679b1c6b8c716fcea7a919b4"
}

rule MalwareBazaar_Mirai_077_359edf4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "359edf4c860783ce7876a502e2e3a6f456378a485b5a8141689709bf2b13ba09"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:12"
  condition:
    hash.sha256(0, filesize) == "359edf4c860783ce7876a502e2e3a6f456378a485b5a8141689709bf2b13ba09"
}

rule MalwareBazaar_Mirai_078_37116a5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37116a5f09fb37c1c60820754595847b7b6e97e2f0f5d5b8ee5be954a21e078d"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:10"
  condition:
    hash.sha256(0, filesize) == "37116a5f09fb37c1c60820754595847b7b6e97e2f0f5d5b8ee5be954a21e078d"
}

rule MalwareBazaar_Mirai_079_15870cf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15870cf9f5b2df29de3389b23ce73412d7f1d5ebac77f74e6ea9b01e5ee40388"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:08"
  condition:
    hash.sha256(0, filesize) == "15870cf9f5b2df29de3389b23ce73412d7f1d5ebac77f74e6ea9b01e5ee40388"
}

rule MalwareBazaar_Mirai_080_f2530a45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2530a4564ee2d036ea9e75f5c944bb4bf051e8fe63db5abbcd51c6d16b903e4"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:06"
  condition:
    hash.sha256(0, filesize) == "f2530a4564ee2d036ea9e75f5c944bb4bf051e8fe63db5abbcd51c6d16b903e4"
}

rule MalwareBazaar_Mirai_081_3418bbac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3418bbac4672fcf49bfa5c17c4e8e9cb99248f0e64225bcad090e8abfb71df13"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-07 23:11:04"
  condition:
    hash.sha256(0, filesize) == "3418bbac4672fcf49bfa5c17c4e8e9cb99248f0e64225bcad090e8abfb71df13"
}

rule MalwareBazaar_unknown_082_74f9b450
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f9b450ab1970423b27a92930cc2fcef2d58d9a6b84d23116027d749d6fedc8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-07 23:09:40"
  condition:
    hash.sha256(0, filesize) == "74f9b450ab1970423b27a92930cc2fcef2d58d9a6b84d23116027d749d6fedc8"
}

rule MalwareBazaar_unknown_083_1a01cf87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a01cf874059dc90a50f255035c31ba2f55cd8084747d7b5812dc7475b47bd93"
    family = "unknown"
    file_name = "spkvol.dll"
    file_type = "exe"
    first_seen = "2026-07-07 23:04:41"
  condition:
    hash.sha256(0, filesize) == "1a01cf874059dc90a50f255035c31ba2f55cd8084747d7b5812dc7475b47bd93"
}

rule MalwareBazaar_unknown_084_03a6c587
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03a6c5877cf8a3c45e3672db2067bccc7b6242a48fbc415805dd614ca3fc4810"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 22:52:10"
  condition:
    hash.sha256(0, filesize) == "03a6c5877cf8a3c45e3672db2067bccc7b6242a48fbc415805dd614ca3fc4810"
}

rule MalwareBazaar_RemcosRAT_085_ed1427c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed1427c973e2c1fecdf2536e270fec2af98e31e229fbdae6664b0e23af321f9a"
    family = "RemcosRAT"
    file_name = "436d5a5d5c35f34cdb4f6be2c4ff30dc.exe"
    file_type = "exe"
    first_seen = "2026-07-07 22:50:10"
  condition:
    hash.sha256(0, filesize) == "ed1427c973e2c1fecdf2536e270fec2af98e31e229fbdae6664b0e23af321f9a"
}

rule MalwareBazaar_unknown_086_dd86527e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd86527ed05af146c6eb44676ffb8dcde757171b0089bfe2bd90e20e0662fd43"
    family = "unknown"
    file_name = "Sassy_Game.exe"
    file_type = "exe"
    first_seen = "2026-07-07 22:43:58"
  condition:
    hash.sha256(0, filesize) == "dd86527ed05af146c6eb44676ffb8dcde757171b0089bfe2bd90e20e0662fd43"
}

rule MalwareBazaar_unknown_087_5043ac3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5043ac3dbdaf116d560a90466c1a146da6140a3e7aecd36310f9cf538df62872"
    family = "unknown"
    file_name = "AfterSchoolMemories_winx64.exe"
    file_type = "exe"
    first_seen = "2026-07-07 22:43:27"
  condition:
    hash.sha256(0, filesize) == "5043ac3dbdaf116d560a90466c1a146da6140a3e7aecd36310f9cf538df62872"
}

rule MalwareBazaar_unknown_088_81e2f442
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81e2f4427c80e9d08a685876ec317bf49924ea7ac08250760132459acef76778"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 21:52:10"
  condition:
    hash.sha256(0, filesize) == "81e2f4427c80e9d08a685876ec317bf49924ea7ac08250760132459acef76778"
}

rule MalwareBazaar_unknown_089_dc57f496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc57f496cc489f275bb58e36d47c760794a0da5532ad13655b761ff79f7651a1"
    family = "unknown"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-07-07 21:35:57"
  condition:
    hash.sha256(0, filesize) == "dc57f496cc489f275bb58e36d47c760794a0da5532ad13655b761ff79f7651a1"
}

rule MalwareBazaar_RemcosRAT_090_aa4d6427
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa4d642727be33ecd94acb8a24e546aeed325f08367333bb8974f5e54d99e715"
    family = "RemcosRAT"
    file_name = "379717f664cc19a3f295a11e189dd386.exe"
    file_type = "exe"
    first_seen = "2026-07-07 21:35:12"
  condition:
    hash.sha256(0, filesize) == "aa4d642727be33ecd94acb8a24e546aeed325f08367333bb8974f5e54d99e715"
}

rule MalwareBazaar_ValleyRAT_091_0fa25790
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fa2579031a74d6ac6477c036f2a53695ab92d907fd0220c48bba31dffa976da"
    family = "ValleyRAT"
    file_name = "32f90f34610520f8dbded26e5e7494c1.exe"
    file_type = "exe"
    first_seen = "2026-07-07 21:09:18"
  condition:
    hash.sha256(0, filesize) == "0fa2579031a74d6ac6477c036f2a53695ab92d907fd0220c48bba31dffa976da"
}

rule MalwareBazaar_Mirai_092_95a0c24f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95a0c24f7192be97f40b3d3a6e53b85f33d94fe676415b003517518cf92e663f"
    family = "Mirai"
    file_name = "95a0c24f7192be97f40b3d3a6e53b85f33d94fe676415b003517518cf92e663f"
    file_type = "elf"
    first_seen = "2026-07-07 20:58:23"
  condition:
    hash.sha256(0, filesize) == "95a0c24f7192be97f40b3d3a6e53b85f33d94fe676415b003517518cf92e663f"
}

rule MalwareBazaar_Mirai_093_9bdb2fcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bdb2fcdffebcb27ae8583801d454d467501bb6ece9054e5fdd64d728bd3cd72"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-07 20:57:27"
  condition:
    hash.sha256(0, filesize) == "9bdb2fcdffebcb27ae8583801d454d467501bb6ece9054e5fdd64d728bd3cd72"
}

rule MalwareBazaar_ConnectWise_094_3590c31b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3590c31b65c14be9cdc6ea70726525be8a1df07d454a6f7b359d1eeac0cd8621"
    family = "ConnectWise"
    file_name = "Google Meet.zip"
    file_type = "zip"
    first_seen = "2026-07-07 20:54:42"
  condition:
    hash.sha256(0, filesize) == "3590c31b65c14be9cdc6ea70726525be8a1df07d454a6f7b359d1eeac0cd8621"
}

rule MalwareBazaar_unknown_095_4db0eef2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4db0eef20a14febe6082fc641d33539ec86d2c38379556d9f315789fa6f58296"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 20:52:12"
  condition:
    hash.sha256(0, filesize) == "4db0eef20a14febe6082fc641d33539ec86d2c38379556d9f315789fa6f58296"
}

rule MalwareBazaar_Mirai_096_ca9b8a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca9b8a1113669683961f2ee4bf028f54dcb42daf35b51ba2c60195769247f7ef"
    family = "Mirai"
    file_name = "zlkbnkpmc"
    file_type = "elf"
    first_seen = "2026-07-07 20:31:53"
  condition:
    hash.sha256(0, filesize) == "ca9b8a1113669683961f2ee4bf028f54dcb42daf35b51ba2c60195769247f7ef"
}

rule MalwareBazaar_AsyncRAT_097_2d615664
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d6156646c286071b94fb2d75089974912c1eeb8b83457a24d346c397794043c"
    family = "AsyncRAT"
    file_name = "lnvoice8343783.js"
    file_type = "js"
    first_seen = "2026-07-07 20:23:16"
  condition:
    hash.sha256(0, filesize) == "2d6156646c286071b94fb2d75089974912c1eeb8b83457a24d346c397794043c"
}

rule MalwareBazaar_Mirai_098_cc3a50e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc3a50e9fdd6d553fe77d77ed4603786a18b9e4068df1edac44d84fd491a9dac"
    family = "Mirai"
    file_name = "ytaabxcxa"
    file_type = "elf"
    first_seen = "2026-07-07 20:21:31"
  condition:
    hash.sha256(0, filesize) == "cc3a50e9fdd6d553fe77d77ed4603786a18b9e4068df1edac44d84fd491a9dac"
}

rule MalwareBazaar_Mirai_099_761e0518
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "761e0518edc0ffba669d4212bb00b24b884af4b2973575a71516d37abe186fa5"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-07 19:58:27"
  condition:
    hash.sha256(0, filesize) == "761e0518edc0ffba669d4212bb00b24b884af4b2973575a71516d37abe186fa5"
}

rule MalwareBazaar_unknown_100_093775d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "093775d9ef9ad6267c340a26c03432f4a40951071130526a109ec191a6dcf27d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-07 19:52:11"
  condition:
    hash.sha256(0, filesize) == "093775d9ef9ad6267c340a26c03432f4a40951071130526a109ec191a6dcf27d"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

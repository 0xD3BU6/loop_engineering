# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-13

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 462 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 462 |
| Unique family labels | 6 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 79 |
| ConnectWise | 11 |
| DDoSAgent | 6 |
| SalatStealer | 2 |
| Mirai | 1 |
| SnappyClient | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| unknown | 40 |
| exe | 19 |
| sh | 17 |
| msi | 11 |
| elf | 9 |
| php | 1 |
| zip | 1 |
| apk | 1 |
| bat | 1 |

## Per-Sample Analysis

### Sample 1: `5029424f01c38be6`

| Field | Value |
|---|---|
| SHA-256 | `5029424f01c38be64318839ce1a7d95c84c7a2f0a42cbacafab71936576b76f2` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-13 04:28:45` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c70b5a96cf97ee95518e7aa0fdcc1b98` |
| SHA-1 | `3f1779d05b212d7686165c5532748551602e259a` |
| SHA-256 | `5029424f01c38be64318839ce1a7d95c84c7a2f0a42cbacafab71936576b76f2` |
| SHA3-384 | `695b7cab6417a105e190158adf4e21ac5607957d96007f618b5d0068b7233f251af9a927b9df2f9da14a41d74a3353f5` |
| TLSH | `T1B3C26C956A867C44BEC98A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:r8vCB+25j6es8Rt9FYpMSUpi+20qUpi+20YQX:r8l25Jbd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_5029424f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5029424f01c38be64318839ce1a7d95c84c7a2f0a42cbacafab71936576b76f2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-13 04:28:45"
  condition:
    hash.sha256(0, filesize) == "5029424f01c38be64318839ce1a7d95c84c7a2f0a42cbacafab71936576b76f2"
}
```

### Sample 2: `045f86cbdd13e187`

| Field | Value |
|---|---|
| SHA-256 | `045f86cbdd13e187fb76f1f90c20e972bfdb0cded22cc226e3d635b332eb732c` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-13 04:24:51` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5805a9068b35115c33f58a2c2967d01` |
| SHA-256 | `045f86cbdd13e187fb76f1f90c20e972bfdb0cded22cc226e3d635b332eb732c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_045f86cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "045f86cbdd13e187fb76f1f90c20e972bfdb0cded22cc226e3d635b332eb732c"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 04:24:51"
  condition:
    hash.sha256(0, filesize) == "045f86cbdd13e187fb76f1f90c20e972bfdb0cded22cc226e3d635b332eb732c"
}
```

### Sample 3: `3461b097ea026c91`

| Field | Value |
|---|---|
| SHA-256 | `3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-13 04:18:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be809872eb1115c985a6685e54790bb4` |
| SHA-1 | `a282e14dd43419434b3a136ea92bd7a1ea6e33e9` |
| SHA-256 | `3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc` |
| SHA3-384 | `5fcafe0599e3e94f16f6be7484c6205e9ad8321772a2a2f39c31b0ed0cadfb5439e5c33621a2f9df851993c08fa3d0a2` |
| TLSH | `T1A6444B82E7D3C1F1F49601B1443B5B6B6B37C839903AD657EBA52A21DD62641872F33C` |
| TELFHASH | `t170e1cef32a7919ed73e0ad82d30e2f11fd0bc27b585831b201f265d43272e5292b547a` |
| SSDEEP | `3072:AIrGkWKKykeeUD013WaMy+ARkMJVOLvGK7h+VPDgGcqlU933eEyNzqIK:Qtn7My3lVuG7bgt++3FgOIK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_3461b097
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-13 04:18:47"
  condition:
    hash.sha256(0, filesize) == "3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc"
}
```

### Sample 4: `abb5266660f5a976`

| Field | Value |
|---|---|
| SHA-256 | `abb5266660f5a976deeb8b0c4b3f556e9969f8e99a67864a2afe08e3389fdc30` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-13 04:02:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0e720cd69dfb333f3e391e29a259551` |
| SHA-1 | `f52464a4e5f5b61f2002c2c175e2ac4710138aaf` |
| SHA-256 | `abb5266660f5a976deeb8b0c4b3f556e9969f8e99a67864a2afe08e3389fdc30` |
| SHA3-384 | `9f62c634b60610b3e287c1a565791229b649ff8798c09a65ab45a14a50badcd23ac202a40fd88b87143355aa4b8aea99` |
| TLSH | `T15B235C551A857C149E98C4371D7E2F0CBDA943E6321452EE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:sVEJVIhtM99GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:yEJ2Mecr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_abb52666
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb5266660f5a976deeb8b0c4b3f556e9969f8e99a67864a2afe08e3389fdc30"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-13 04:02:48"
  condition:
    hash.sha256(0, filesize) == "abb5266660f5a976deeb8b0c4b3f556e9969f8e99a67864a2afe08e3389fdc30"
}
```

### Sample 5: `1f224b30051a7347`

| Field | Value |
|---|---|
| SHA-256 | `1f224b30051a7347bbfc7f644cd7221ecf7ac2835fb725d7bd7d8660c880ff7c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 04:00:55` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, james` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `809b89d16bd8f8a08b50bf1da4938304` |
| SHA-256 | `1f224b30051a7347bbfc7f644cd7221ecf7ac2835fb725d7bd7d8660c880ff7c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_1f224b30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f224b30051a7347bbfc7f644cd7221ecf7ac2835fb725d7bd7d8660c880ff7c"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 04:00:55"
  condition:
    hash.sha256(0, filesize) == "1f224b30051a7347bbfc7f644cd7221ecf7ac2835fb725d7bd7d8660c880ff7c"
}
```

### Sample 6: `5474e510e5adc3a0`

| Field | Value |
|---|---|
| SHA-256 | `5474e510e5adc3a0d708b8af25829ab68ce12934f56ae901ccff2e2f5a482c2b` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-13 03:54:44` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db3964fbe1839eb33baabe3783e2c739` |
| SHA-256 | `5474e510e5adc3a0d708b8af25829ab68ce12934f56ae901ccff2e2f5a482c2b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_5474e510
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5474e510e5adc3a0d708b8af25829ab68ce12934f56ae901ccff2e2f5a482c2b"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 03:54:44"
  condition:
    hash.sha256(0, filesize) == "5474e510e5adc3a0d708b8af25829ab68ce12934f56ae901ccff2e2f5a482c2b"
}
```

### Sample 7: `48f7a0fd3cb39a4a`

| Field | Value |
|---|---|
| SHA-256 | `48f7a0fd3cb39a4a400a06331d73d74fe84817d8e6f2b7f34d853e61049a322c` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-13 03:52:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12f6089b5a3e29e5b47f6b6d92dad1be` |
| SHA-1 | `d827a4be2adf8a7aa48d64712296b0d1023ddd7a` |
| SHA-256 | `48f7a0fd3cb39a4a400a06331d73d74fe84817d8e6f2b7f34d853e61049a322c` |
| SHA3-384 | `e1e7ad4357ffbf7832546a50e1360b37019f39eb09ddf6b94fe3d750607c1ff6fe952990135a69c75f1ba455f78d7b99` |
| TLSH | `T136236C6516857C14AE99C4365C7F2F0CBDAD43E6314492EE7FCA3CF28C4A6ADA20871D` |
| SSDEEP | `768:0r9NyXsZztCE9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:yHusZkcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_48f7a0fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48f7a0fd3cb39a4a400a06331d73d74fe84817d8e6f2b7f34d853e61049a322c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-13 03:52:44"
  condition:
    hash.sha256(0, filesize) == "48f7a0fd3cb39a4a400a06331d73d74fe84817d8e6f2b7f34d853e61049a322c"
}
```

### Sample 8: `c88eab2d3c72bf4b`

| Field | Value |
|---|---|
| SHA-256 | `c88eab2d3c72bf4b4e9a4605281e2369310698093079762f13317e58ae8dfcc2` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-13 03:37:48` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e61db57e19b371ba5588fdc97be9f38a` |
| SHA-256 | `c88eab2d3c72bf4b4e9a4605281e2369310698093079762f13317e58ae8dfcc2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_c88eab2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c88eab2d3c72bf4b4e9a4605281e2369310698093079762f13317e58ae8dfcc2"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 03:37:48"
  condition:
    hash.sha256(0, filesize) == "c88eab2d3c72bf4b4e9a4605281e2369310698093079762f13317e58ae8dfcc2"
}
```

### Sample 9: `52c06775e28c145b`

| Field | Value |
|---|---|
| SHA-256 | `52c06775e28c145b7ec96b7d7f2120bfc97c8d073f21d548d1a7c1aebfa5169b` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-13 03:37:47` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f62e67081098a3198655dbc4af9bffb` |
| SHA-1 | `a132511db6f04a0314932d3ceb652cd223dcab21` |
| SHA-256 | `52c06775e28c145b7ec96b7d7f2120bfc97c8d073f21d548d1a7c1aebfa5169b` |
| SHA3-384 | `c61503423de01ba1fa70689f58d5df4effed0ac844e1cefe29a95060e45eba945aa9d077a8ae5bba6a15012587756126` |
| TLSH | `T155C27C956A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8A3C71DC11FACD618B2A` |
| SSDEEP | `768:38vCB+25j6es8R29FYpMSUpi+20qUpi+20YQX:38l25Jgd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_52c06775
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52c06775e28c145b7ec96b7d7f2120bfc97c8d073f21d548d1a7c1aebfa5169b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-13 03:37:47"
  condition:
    hash.sha256(0, filesize) == "52c06775e28c145b7ec96b7d7f2120bfc97c8d073f21d548d1a7c1aebfa5169b"
}
```

### Sample 10: `b54a9f76aaa20aff`

| Field | Value |
|---|---|
| SHA-256 | `b54a9f76aaa20aff72fd978bca433b67ca210e9466db9ddb32d448204beb705b` |
| Family label | `unknown` |
| File name | `rev.sh` |
| File type | `sh` |
| First seen | `2026-09-13 03:29:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `971cd8cd2581d7832efdd0b7bb84ceb8` |
| SHA-1 | `b2daeb6259693db56e8717fd8f849c33296dbf4d` |
| SHA-256 | `b54a9f76aaa20aff72fd978bca433b67ca210e9466db9ddb32d448204beb705b` |
| SHA3-384 | `83b642a021a13599f8d3556b850091fd85de7b7b1f951c8c9f789c7df76bbaf1e5f84e82873235e21e53ec5de2fe3b76` |
| TLSH | `T15921ACB2F1F169753F70C49C6106E13037EA3B5A9B8C5EE2987C5AA13617565F0A0F11` |
| SSDEEP | `24:w1NLSDe/BBB5or+SrNvNSL5lOKob0TGz5lOKob0TGP:wTqj6SuOKK0TGGKK0TGP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_b54a9f76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b54a9f76aaa20aff72fd978bca433b67ca210e9466db9ddb32d448204beb705b"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-09-13 03:29:46"
  condition:
    hash.sha256(0, filesize) == "b54a9f76aaa20aff72fd978bca433b67ca210e9466db9ddb32d448204beb705b"
}
```

### Sample 11: `6b700b6ed41413e3`

| Field | Value |
|---|---|
| SHA-256 | `6b700b6ed41413e36dcffb50d8d9f0b082e8b2f514a123636ba715fde1bc7487` |
| Family label | `unknown` |
| File name | `6b700b6ed41413e36dcffb50d8d9f0b082e8b2f514a123636ba715fde1bc7487.sh` |
| File type | `sh` |
| First seen | `2026-09-13 03:05:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `530141c5000a7c335d3b301f0b2115cb` |
| SHA-1 | `07fab5ef09adcc3849b7694e1f7221cc976dcc27` |
| SHA-256 | `6b700b6ed41413e36dcffb50d8d9f0b082e8b2f514a123636ba715fde1bc7487` |
| SHA3-384 | `c7b12ea6c9a5ba1d5761daa3011ed791bf0c4378f0cc0466b68b961c916ada5a64ce957777aa9981a7123ab31cb6323c` |
| TLSH | `T17622477B21F08B32D3D450C953660EA14E72AB4B996618B5F4BE93369F2C90331E7F61` |
| SSDEEP | `192:cCu7e1OJi1OyPsN8GsNDM6p4hvZ5m5FoKNpivm:ye1OJi1OyPsN8GsND3p4hvZ5m5FoKNp1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_6b700b6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b700b6ed41413e36dcffb50d8d9f0b082e8b2f514a123636ba715fde1bc7487"
    family = "unknown"
    file_name = "6b700b6ed41413e36dcffb50d8d9f0b082e8b2f514a123636ba715fde1bc7487.sh"
    file_type = "sh"
    first_seen = "2026-09-13 03:05:54"
  condition:
    hash.sha256(0, filesize) == "6b700b6ed41413e36dcffb50d8d9f0b082e8b2f514a123636ba715fde1bc7487"
}
```

### Sample 12: `c60f6d4b408ec849`

| Field | Value |
|---|---|
| SHA-256 | `c60f6d4b408ec8492546db16df6c2c8b5606413ff084138f87df1cc1a101f86d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 02:01:52` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, YT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bfc599b113bd9dd0fac4946ff4283b1` |
| SHA-256 | `c60f6d4b408ec8492546db16df6c2c8b5606413ff084138f87df1cc1a101f86d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_c60f6d4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c60f6d4b408ec8492546db16df6c2c8b5606413ff084138f87df1cc1a101f86d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 02:01:52"
  condition:
    hash.sha256(0, filesize) == "c60f6d4b408ec8492546db16df6c2c8b5606413ff084138f87df1cc1a101f86d"
}
```

### Sample 13: `7fca62a702cc2817`

| Field | Value |
|---|---|
| SHA-256 | `7fca62a702cc28175ec0e16fc3fc5a33a6e3a0cd7871630af4ab97893903cb42` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 01:42:24` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f8d81d5d7f6579ffa44078aae6b880f` |
| SHA-256 | `7fca62a702cc28175ec0e16fc3fc5a33a6e3a0cd7871630af4ab97893903cb42` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_7fca62a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fca62a702cc28175ec0e16fc3fc5a33a6e3a0cd7871630af4ab97893903cb42"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 01:42:24"
  condition:
    hash.sha256(0, filesize) == "7fca62a702cc28175ec0e16fc3fc5a33a6e3a0cd7871630af4ab97893903cb42"
}
```

### Sample 14: `72e26c564ae2f23f`

| Field | Value |
|---|---|
| SHA-256 | `72e26c564ae2f23fd7b3017e3df2debadc0592a17c9f379cc34c538d978978b9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 01:42:02` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5138ddcc540f6ef3218c2ff19e31d5f8` |
| SHA-256 | `72e26c564ae2f23fd7b3017e3df2debadc0592a17c9f379cc34c538d978978b9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_72e26c56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72e26c564ae2f23fd7b3017e3df2debadc0592a17c9f379cc34c538d978978b9"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 01:42:02"
  condition:
    hash.sha256(0, filesize) == "72e26c564ae2f23fd7b3017e3df2debadc0592a17c9f379cc34c538d978978b9"
}
```

### Sample 15: `565b155cdd681e0b`

| Field | Value |
|---|---|
| SHA-256 | `565b155cdd681e0bcbde174a74ddb4dbe621001517b4665c37ccbf323c7c38e1` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-13 01:24:45` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1874fa58556a5f3ee72bbc319b43ccc7` |
| SHA-256 | `565b155cdd681e0bcbde174a74ddb4dbe621001517b4665c37ccbf323c7c38e1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_565b155c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "565b155cdd681e0bcbde174a74ddb4dbe621001517b4665c37ccbf323c7c38e1"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 01:24:45"
  condition:
    hash.sha256(0, filesize) == "565b155cdd681e0bcbde174a74ddb4dbe621001517b4665c37ccbf323c7c38e1"
}
```

### Sample 16: `5b73969e4df42bd5`

| Field | Value |
|---|---|
| SHA-256 | `5b73969e4df42bd57becfd96fdc5ce13873c48995a19a877bf3030e1399fbf2c` |
| Family label | `unknown` |
| File name | `5b73969e4df42bd57becfd96fdc5ce13873c48995a19a877bf3030e1399fbf2c` |
| File type | `sh` |
| First seen | `2026-09-13 01:10:53` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `004044b4c527a9075153da79b2af9212` |
| SHA-1 | `975bbfd0e9bdcd0e5bedd2dee20d12e19563df45` |
| SHA-256 | `5b73969e4df42bd57becfd96fdc5ce13873c48995a19a877bf3030e1399fbf2c` |
| SHA3-384 | `dd83d9a558aa18ba1468620e714d5e683f80c69e821c3720fc112e818da8d2144c1f41d2878b0c6a77ba21d1c4a6972c` |
| TLSH | `T1DA1149D3BC508A327346111DA34D8070E602B47F46CF3E01724D88769FEB9287415331` |
| SSDEEP | `12:dcv7MYR0SSRNwryRXKQ/fskFKFx2fsk57/fskMJj2FFyyQCkkV+2LleLBKK:q7b0S+S5QXskoFxisktXskejMLH8AK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_5b73969e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b73969e4df42bd57becfd96fdc5ce13873c48995a19a877bf3030e1399fbf2c"
    family = "unknown"
    file_name = "5b73969e4df42bd57becfd96fdc5ce13873c48995a19a877bf3030e1399fbf2c"
    file_type = "sh"
    first_seen = "2026-09-13 01:10:53"
  condition:
    hash.sha256(0, filesize) == "5b73969e4df42bd57becfd96fdc5ce13873c48995a19a877bf3030e1399fbf2c"
}
```

### Sample 17: `d3b0aac81593144d`

| Field | Value |
|---|---|
| SHA-256 | `d3b0aac81593144d230e0422f7d306809aa302f5b7bf9831d6a7dbe36fa9a94e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 00:40:05` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc780960a6e588ed02f0534b829e9301` |
| SHA-256 | `d3b0aac81593144d230e0422f7d306809aa302f5b7bf9831d6a7dbe36fa9a94e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_d3b0aac8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3b0aac81593144d230e0422f7d306809aa302f5b7bf9831d6a7dbe36fa9a94e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 00:40:05"
  condition:
    hash.sha256(0, filesize) == "d3b0aac81593144d230e0422f7d306809aa302f5b7bf9831d6a7dbe36fa9a94e"
}
```

### Sample 18: `72d22964f41e7045`

| Field | Value |
|---|---|
| SHA-256 | `72d22964f41e704579302aaf0496a15bc3a3070832fbdb1c6e522b5d7ed329db` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 00:40:01` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d35e305e34b8ae6ed71236ed5e387a9` |
| SHA-256 | `72d22964f41e704579302aaf0496a15bc3a3070832fbdb1c6e522b5d7ed329db` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_72d22964
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72d22964f41e704579302aaf0496a15bc3a3070832fbdb1c6e522b5d7ed329db"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 00:40:01"
  condition:
    hash.sha256(0, filesize) == "72d22964f41e704579302aaf0496a15bc3a3070832fbdb1c6e522b5d7ed329db"
}
```

### Sample 19: `8d69e03384fa3fc4`

| Field | Value |
|---|---|
| SHA-256 | `8d69e03384fa3fc4aae31027ab7bfab539b9bbd4a7cff1bc63a3e749bfa670ea` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 00:39:44` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de49c8917b10e1d0ce0fbe1a7ceb242f` |
| SHA-256 | `8d69e03384fa3fc4aae31027ab7bfab539b9bbd4a7cff1bc63a3e749bfa670ea` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_8d69e033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d69e03384fa3fc4aae31027ab7bfab539b9bbd4a7cff1bc63a3e749bfa670ea"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 00:39:44"
  condition:
    hash.sha256(0, filesize) == "8d69e03384fa3fc4aae31027ab7bfab539b9bbd4a7cff1bc63a3e749bfa670ea"
}
```

### Sample 20: `da9a78ac208ff909`

| Field | Value |
|---|---|
| SHA-256 | `da9a78ac208ff90959b6fddbc7d64347fcaa9429a46cc4ed5ce1fa28d2a7e9f4` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.msi` |
| File type | `msi` |
| First seen | `2026-09-13 00:20:16` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26185db46ad8fa6aa25dc1dff57dd36a` |
| SHA-1 | `825d219b83f5bd5da0727583831f469c221e4d6b` |
| SHA-256 | `da9a78ac208ff90959b6fddbc7d64347fcaa9429a46cc4ed5ce1fa28d2a7e9f4` |
| SHA3-384 | `91c0bb2255d2d070108bd8952757e9aab06cc7d822a2588a7227477132a95f4fd684db9f81c811329c2d8dd29d1b357c` |
| TLSH | `T1EFC6233267FD4918E1F36778ED3A91E291367C64CF12C09F2614786E6871E8096A373B` |
| SSDEEP | `196608:rrnLYG3zDhukOHrnLYG3z5rnLYG3z0rnLYG3zYrnLYG3zGrnLYG3z:rbDDDgvHbDD5bDD0bDDYbDDGbDD` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_020_da9a78ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da9a78ac208ff90959b6fddbc7d64347fcaa9429a46cc4ed5ce1fa28d2a7e9f4"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:20:16"
  condition:
    hash.sha256(0, filesize) == "da9a78ac208ff90959b6fddbc7d64347fcaa9429a46cc4ed5ce1fa28d2a7e9f4"
}
```

### Sample 21: `f7a54dccd317d4c7`

| Field | Value |
|---|---|
| SHA-256 | `f7a54dccd317d4c7908ec453fb26df4db518e520b507dd3a69b2dc2d145bd588` |
| Family label | `unknown` |
| File name | `f7a54dccd317d4c7908ec453fb26df4db518e520b507dd3a69b2dc2d145bd588.bin` |
| File type | `unknown` |
| First seen | `2026-09-13 00:11:23` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdc3dc90787e5e63469c4518b862b6e3` |
| SHA-256 | `f7a54dccd317d4c7908ec453fb26df4db518e520b507dd3a69b2dc2d145bd588` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_f7a54dcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7a54dccd317d4c7908ec453fb26df4db518e520b507dd3a69b2dc2d145bd588"
    family = "unknown"
    file_name = "f7a54dccd317d4c7908ec453fb26df4db518e520b507dd3a69b2dc2d145bd588.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:11:23"
  condition:
    hash.sha256(0, filesize) == "f7a54dccd317d4c7908ec453fb26df4db518e520b507dd3a69b2dc2d145bd588"
}
```

### Sample 22: `ed7e5a6a6d543584`

| Field | Value |
|---|---|
| SHA-256 | `ed7e5a6a6d5435842166e8153501d120616aa851069677b3202a95f9158b8f90` |
| Family label | `unknown` |
| File name | `ed7e5a6a6d5435842166e8153501d120616aa851069677b3202a95f9158b8f90.bin` |
| File type | `unknown` |
| First seen | `2026-09-13 00:11:06` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ba7b7c97640a30981b486bcb43126e2` |
| SHA-256 | `ed7e5a6a6d5435842166e8153501d120616aa851069677b3202a95f9158b8f90` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_ed7e5a6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed7e5a6a6d5435842166e8153501d120616aa851069677b3202a95f9158b8f90"
    family = "unknown"
    file_name = "ed7e5a6a6d5435842166e8153501d120616aa851069677b3202a95f9158b8f90.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:11:06"
  condition:
    hash.sha256(0, filesize) == "ed7e5a6a6d5435842166e8153501d120616aa851069677b3202a95f9158b8f90"
}
```

### Sample 23: `d0738acb402e1949`

| Field | Value |
|---|---|
| SHA-256 | `d0738acb402e1949f5c7ac6a70070be3f2ae43b1282fba315714b7209ca3ba25` |
| Family label | `unknown` |
| File name | `d0738acb402e1949f5c7ac6a70070be3f2ae43b1282fba315714b7209ca3ba25.bin` |
| File type | `php` |
| First seen | `2026-09-13 00:10:49` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f5e1b50507947c3507bf85bd40e916d` |
| SHA-1 | `2ff44cf653ce8a55ad3ea420355a5513cc6a3d89` |
| SHA-256 | `d0738acb402e1949f5c7ac6a70070be3f2ae43b1282fba315714b7209ca3ba25` |
| SHA3-384 | `0bc58f386d844809793ad234044edb8bfcbf6f903c7ab45d1c5fd867d45cd2ce6457a9aa0b787bf4e6711e3b5f331b7d` |
| TLSH | `T19C2187760BC078583A143E6780EDEC0F04F129497B25488C23A587C74A08D8D2E7FE98` |
| SSDEEP | `24:iNWFUvMhpqJ6lsSZCp6nlvP73DfFU4nQGijM28dpkSqm+u:iN2XZ88L3DfFzQGiY28DOu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_d0738acb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0738acb402e1949f5c7ac6a70070be3f2ae43b1282fba315714b7209ca3ba25"
    family = "unknown"
    file_name = "d0738acb402e1949f5c7ac6a70070be3f2ae43b1282fba315714b7209ca3ba25.bin"
    file_type = "php"
    first_seen = "2026-09-13 00:10:49"
  condition:
    hash.sha256(0, filesize) == "d0738acb402e1949f5c7ac6a70070be3f2ae43b1282fba315714b7209ca3ba25"
}
```

### Sample 24: `bbcb1063b9730907`

| Field | Value |
|---|---|
| SHA-256 | `bbcb1063b9730907b2c47910eeff1b7c8d0c02e272c77444c1a91e3532672cfa` |
| Family label | `unknown` |
| File name | `bbcb1063b9730907b2c47910eeff1b7c8d0c02e272c77444c1a91e3532672cfa.bin` |
| File type | `unknown` |
| First seen | `2026-09-13 00:10:32` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3366ce37e5d7abdcd5f1215b58213412` |
| SHA-256 | `bbcb1063b9730907b2c47910eeff1b7c8d0c02e272c77444c1a91e3532672cfa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_bbcb1063
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbcb1063b9730907b2c47910eeff1b7c8d0c02e272c77444c1a91e3532672cfa"
    family = "unknown"
    file_name = "bbcb1063b9730907b2c47910eeff1b7c8d0c02e272c77444c1a91e3532672cfa.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:10:32"
  condition:
    hash.sha256(0, filesize) == "bbcb1063b9730907b2c47910eeff1b7c8d0c02e272c77444c1a91e3532672cfa"
}
```

### Sample 25: `a84517ac01ee61f1`

| Field | Value |
|---|---|
| SHA-256 | `a84517ac01ee61f1f980508f4a66b0c8bc12c05d7c8190fef2033c23232628c3` |
| Family label | `unknown` |
| File name | `a84517ac01ee61f1f980508f4a66b0c8bc12c05d7c8190fef2033c23232628c3.bin` |
| File type | `unknown` |
| First seen | `2026-09-13 00:10:14` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6679319d2234572c17c744a6c171b58f` |
| SHA-256 | `a84517ac01ee61f1f980508f4a66b0c8bc12c05d7c8190fef2033c23232628c3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_a84517ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a84517ac01ee61f1f980508f4a66b0c8bc12c05d7c8190fef2033c23232628c3"
    family = "unknown"
    file_name = "a84517ac01ee61f1f980508f4a66b0c8bc12c05d7c8190fef2033c23232628c3.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:10:14"
  condition:
    hash.sha256(0, filesize) == "a84517ac01ee61f1f980508f4a66b0c8bc12c05d7c8190fef2033c23232628c3"
}
```

### Sample 26: `73a80d9f0b26a8ae`

| Field | Value |
|---|---|
| SHA-256 | `73a80d9f0b26a8ae1785972a4febee9df8bb95969aa256bc817a1665d5aef6d4` |
| Family label | `unknown` |
| File name | `73a80d9f0b26a8ae1785972a4febee9df8bb95969aa256bc817a1665d5aef6d4.bin` |
| File type | `unknown` |
| First seen | `2026-09-13 00:09:57` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8946cfc61f976d35abe20fedc32615ee` |
| SHA-256 | `73a80d9f0b26a8ae1785972a4febee9df8bb95969aa256bc817a1665d5aef6d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_73a80d9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73a80d9f0b26a8ae1785972a4febee9df8bb95969aa256bc817a1665d5aef6d4"
    family = "unknown"
    file_name = "73a80d9f0b26a8ae1785972a4febee9df8bb95969aa256bc817a1665d5aef6d4.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:09:57"
  condition:
    hash.sha256(0, filesize) == "73a80d9f0b26a8ae1785972a4febee9df8bb95969aa256bc817a1665d5aef6d4"
}
```

### Sample 27: `32f024ff47848ef4`

| Field | Value |
|---|---|
| SHA-256 | `32f024ff47848ef46530822aa5f8e78d5dfc07d61c9402c98eb0b27219235567` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup(4).msi` |
| File type | `msi` |
| First seen | `2026-09-13 00:09:49` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10ea5227fd65a0af7cd0a85496dbb724` |
| SHA-1 | `8bb14e3104fb66a45af9f7ed98e405872c86389d` |
| SHA-256 | `32f024ff47848ef46530822aa5f8e78d5dfc07d61c9402c98eb0b27219235567` |
| SHA3-384 | `603d0528b93aa185f613f100c47cb5389688177e61fbbba115cb5181c754fa7f4fdf55c639e009d770941c6c3d271409` |
| TLSH | `T16096232063E98A28E1B61B75EE7A55F14D39BC45EF23C11E4778795E2A30E8095B3333` |
| SSDEEP | `196608:KQyiixtMjGZ1jhlrwUNQyiixtMjoQyiixtMjXQyiixtMjBQyiixtMj:DPnjGrrGPnj5PnjgPnjqPnj` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_027_32f024ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f024ff47848ef46530822aa5f8e78d5dfc07d61c9402c98eb0b27219235567"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup(4).msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:09:49"
  condition:
    hash.sha256(0, filesize) == "32f024ff47848ef46530822aa5f8e78d5dfc07d61c9402c98eb0b27219235567"
}
```

### Sample 28: `3777ea8f92b3bc5a`

| Field | Value |
|---|---|
| SHA-256 | `3777ea8f92b3bc5af807bf7ebf26010dd361e23d521fcc88db2b19240f4cc9e3` |
| Family label | `unknown` |
| File name | `3777ea8f92b3bc5af807bf7ebf26010dd361e23d521fcc88db2b19240f4cc9e3.bin` |
| File type | `unknown` |
| First seen | `2026-09-13 00:09:40` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbbbf7738d78f3071471768fd250f718` |
| SHA-256 | `3777ea8f92b3bc5af807bf7ebf26010dd361e23d521fcc88db2b19240f4cc9e3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_3777ea8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3777ea8f92b3bc5af807bf7ebf26010dd361e23d521fcc88db2b19240f4cc9e3"
    family = "unknown"
    file_name = "3777ea8f92b3bc5af807bf7ebf26010dd361e23d521fcc88db2b19240f4cc9e3.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:09:40"
  condition:
    hash.sha256(0, filesize) == "3777ea8f92b3bc5af807bf7ebf26010dd361e23d521fcc88db2b19240f4cc9e3"
}
```

### Sample 29: `a3bf052506056f37`

| Field | Value |
|---|---|
| SHA-256 | `a3bf052506056f37844e5677b56bf3aa841473e68567228be048c7aa11590888` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup(3).msi` |
| File type | `msi` |
| First seen | `2026-09-13 00:09:33` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff72d87bcb8e748991dd439ec5941e78` |
| SHA-1 | `81f144ff70fe5dc5fdafb24a9018550018dc4fde` |
| SHA-256 | `a3bf052506056f37844e5677b56bf3aa841473e68567228be048c7aa11590888` |
| SHA3-384 | `26c8784d61d52ab6e406f3190366ab7a559f1f86d2aa221d92fb8c10a01e8fa32bcac0f3d33eec5b31df34f84ad5aec5` |
| TLSH | `T13E96232063E98A28E1B61B75EE7A55F14D39BC45EF23C11E4778795E2A30E8095B3333` |
| SSDEEP | `196608:NQyiixtMjGZ1jhlrwUCQyiixtMjoQyiixtMjXQyiixtMjBQyiixtMj:GPnjGrrbPnj5PnjgPnjqPnj` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_029_a3bf0525
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3bf052506056f37844e5677b56bf3aa841473e68567228be048c7aa11590888"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup(3).msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:09:33"
  condition:
    hash.sha256(0, filesize) == "a3bf052506056f37844e5677b56bf3aa841473e68567228be048c7aa11590888"
}
```

### Sample 30: `37302e86fb203943`

| Field | Value |
|---|---|
| SHA-256 | `37302e86fb20394354731dec8fb0c67a2b1714acce952be888cca052befbb368` |
| Family label | `unknown` |
| File name | `37302e86fb20394354731dec8fb0c67a2b1714acce952be888cca052befbb368.bin` |
| File type | `unknown` |
| First seen | `2026-09-13 00:09:22` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58bf1bdd5a16e6c65118171d8bc9aef3` |
| SHA-256 | `37302e86fb20394354731dec8fb0c67a2b1714acce952be888cca052befbb368` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_37302e86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37302e86fb20394354731dec8fb0c67a2b1714acce952be888cca052befbb368"
    family = "unknown"
    file_name = "37302e86fb20394354731dec8fb0c67a2b1714acce952be888cca052befbb368.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:09:22"
  condition:
    hash.sha256(0, filesize) == "37302e86fb20394354731dec8fb0c67a2b1714acce952be888cca052befbb368"
}
```

### Sample 31: `18234cb137f84dfc`

| Field | Value |
|---|---|
| SHA-256 | `18234cb137f84dfceedc95e81c66fdfcb2f7ceaddfdda8c2a861d92834fc26d0` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup(2).msi` |
| File type | `msi` |
| First seen | `2026-09-13 00:09:17` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `253a5d6ba1cbd9ec6b4107d95556e6d2` |
| SHA-1 | `eb08c08532e2efb619dec438672da4b9ff6a1a09` |
| SHA-256 | `18234cb137f84dfceedc95e81c66fdfcb2f7ceaddfdda8c2a861d92834fc26d0` |
| SHA3-384 | `83ea2e1e71a174e52c28a2f58b981485249b31c114e247151e3106bf0bea884327314fa89073ca20eae4923984b2cdd4` |
| TLSH | `T13F96232063E98A28E1B61B75EE7A55F14D39BC45EF23C11E4778795E2A30E8095B3333` |
| SSDEEP | `196608:0QyiixtMjGZ1jhlrwUCQyiixtMjoQyiixtMjXQyiixtMjBQyiixtMj:FPnjGrrbPnj5PnjgPnjqPnj` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_031_18234cb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18234cb137f84dfceedc95e81c66fdfcb2f7ceaddfdda8c2a861d92834fc26d0"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup(2).msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:09:17"
  condition:
    hash.sha256(0, filesize) == "18234cb137f84dfceedc95e81c66fdfcb2f7ceaddfdda8c2a861d92834fc26d0"
}
```

### Sample 32: `180975de9c76759e`

| Field | Value |
|---|---|
| SHA-256 | `180975de9c76759efb2e77992c44ac40b5534852ba63eb365dc6f520dc693b7d` |
| Family label | `unknown` |
| File name | `180975de9c76759efb2e77992c44ac40b5534852ba63eb365dc6f520dc693b7d.bin` |
| File type | `unknown` |
| First seen | `2026-09-13 00:09:05` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d161e94709e6f5f472cf873eb865c309` |
| SHA-256 | `180975de9c76759efb2e77992c44ac40b5534852ba63eb365dc6f520dc693b7d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_180975de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "180975de9c76759efb2e77992c44ac40b5534852ba63eb365dc6f520dc693b7d"
    family = "unknown"
    file_name = "180975de9c76759efb2e77992c44ac40b5534852ba63eb365dc6f520dc693b7d.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:09:05"
  condition:
    hash.sha256(0, filesize) == "180975de9c76759efb2e77992c44ac40b5534852ba63eb365dc6f520dc693b7d"
}
```

### Sample 33: `c780e43077af07e9`

| Field | Value |
|---|---|
| SHA-256 | `c780e43077af07e993c957ea6509d473d448d25b144584f18e5bc62e9d408c5c` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup(1).msi` |
| File type | `msi` |
| First seen | `2026-09-13 00:09:03` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e588f8923e5bcc5788405216b5f0a94` |
| SHA-1 | `ba7b5f8e76f0c9aabcf91c626710ef5eeaf6965d` |
| SHA-256 | `c780e43077af07e993c957ea6509d473d448d25b144584f18e5bc62e9d408c5c` |
| SHA3-384 | `acdf1002cc8ec215004581f9b5c35b635514386bdb78475be9d3770af74dbfdd7965335ba4f03fc48d45dcc4bf0f5aa0` |
| TLSH | `T16096232063E98A28E1B61B75EE7A55F14D39BC45EF23C11E4778795E2A30E8095B3333` |
| SSDEEP | `196608:8QyiixtMjGZ1jhlrwUNQyiixtMjoQyiixtMjXQyiixtMjBQyiixtMj:tPnjGrrGPnj5PnjgPnjqPnj` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_033_c780e430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c780e43077af07e993c957ea6509d473d448d25b144584f18e5bc62e9d408c5c"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup(1).msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:09:03"
  condition:
    hash.sha256(0, filesize) == "c780e43077af07e993c957ea6509d473d448d25b144584f18e5bc62e9d408c5c"
}
```

### Sample 34: `014afe690cdbc0ca`

| Field | Value |
|---|---|
| SHA-256 | `014afe690cdbc0ca84216a6c241f413e10f92cae8c87e885304ffed0989024a0` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.msi` |
| File type | `msi` |
| First seen | `2026-09-13 00:08:48` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18b6c80756258415b4762c3e595ee7eb` |
| SHA-1 | `fc4b0cd76fc4e9ac3ad842aeb19a9cb898a0b181` |
| SHA-256 | `014afe690cdbc0ca84216a6c241f413e10f92cae8c87e885304ffed0989024a0` |
| SHA3-384 | `2142a51b4a942d21564de68a8143b88320cdfa6ab862d4fd916ca8629d4743e8ff26117b3c0ee302a4561c1e76fad77e` |
| TLSH | `T15196232063E98A28E1B61B75EE7A55F14D39BC45EF23C11E4778795E2A30E8095B3333` |
| SSDEEP | `196608:hQyiixtMjGZ1jhlrwUNQyiixtMjoQyiixtMjXQyiixtMjBQyiixtMj:KPnjGrrGPnj5PnjgPnjqPnj` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_034_014afe69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "014afe690cdbc0ca84216a6c241f413e10f92cae8c87e885304ffed0989024a0"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:08:48"
  condition:
    hash.sha256(0, filesize) == "014afe690cdbc0ca84216a6c241f413e10f92cae8c87e885304ffed0989024a0"
}
```

### Sample 35: `e6a8250c008318c3`

| Field | Value |
|---|---|
| SHA-256 | `e6a8250c008318c3a1339942bd24668965be86d33488bc754df8ad938825caaf` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-13 00:02:01` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cc292718d361dd5dac564e960540864` |
| SHA-1 | `fbeab0296c7fde42e299cb1b608de0ea905bacd0` |
| SHA-256 | `e6a8250c008318c3a1339942bd24668965be86d33488bc754df8ad938825caaf` |
| SHA3-384 | `07dcfe187d0e0e0a130aa45c4a2f48a13e0fc70b5acb3f298c99089ff9ec7d159e2d3398b0b070b2f918672621c50dc3` |
| TLSH | `T123235B6516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCF3CF28C4A69D910971D` |
| SSDEEP | `768:9+b9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:9+scr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_e6a8250c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6a8250c008318c3a1339942bd24668965be86d33488bc754df8ad938825caaf"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-13 00:02:01"
  condition:
    hash.sha256(0, filesize) == "e6a8250c008318c3a1339942bd24668965be86d33488bc754df8ad938825caaf"
}
```

### Sample 36: `63ca3b10fcbb6387`

| Field | Value |
|---|---|
| SHA-256 | `63ca3b10fcbb63879ff42dd7bc35a1373c980198ffafb375350b113976948420` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 00:01:32` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, YT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bff1acb11174865f5e877fa5f186213` |
| SHA-256 | `63ca3b10fcbb63879ff42dd7bc35a1373c980198ffafb375350b113976948420` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_63ca3b10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63ca3b10fcbb63879ff42dd7bc35a1373c980198ffafb375350b113976948420"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 00:01:32"
  condition:
    hash.sha256(0, filesize) == "63ca3b10fcbb63879ff42dd7bc35a1373c980198ffafb375350b113976948420"
}
```

### Sample 37: `b6b745cb96ec0560`

| Field | Value |
|---|---|
| SHA-256 | `b6b745cb96ec0560f9dfd52bec4d9d16a6ecf63713a8ea36e5bb6d55a3d6594a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-13 00:00:30` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, james` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcb0494208213ac4ac951bc94349dd97` |
| SHA-256 | `b6b745cb96ec0560f9dfd52bec4d9d16a6ecf63713a8ea36e5bb6d55a3d6594a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_b6b745cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6b745cb96ec0560f9dfd52bec4d9d16a6ecf63713a8ea36e5bb6d55a3d6594a"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 00:00:30"
  condition:
    hash.sha256(0, filesize) == "b6b745cb96ec0560f9dfd52bec4d9d16a6ecf63713a8ea36e5bb6d55a3d6594a"
}
```

### Sample 38: `8fd1afe6505f6d48`

| Field | Value |
|---|---|
| SHA-256 | `8fd1afe6505f6d48c7d52f65098a40216d46a97fce1f7534cdda5b3f40144d94` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 23:39:23` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1095343a05ce72e27ccd0e8ec1699c2` |
| SHA-256 | `8fd1afe6505f6d48c7d52f65098a40216d46a97fce1f7534cdda5b3f40144d94` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_8fd1afe6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fd1afe6505f6d48c7d52f65098a40216d46a97fce1f7534cdda5b3f40144d94"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 23:39:23"
  condition:
    hash.sha256(0, filesize) == "8fd1afe6505f6d48c7d52f65098a40216d46a97fce1f7534cdda5b3f40144d94"
}
```

### Sample 39: `bdb8567cfe7d8789`

| Field | Value |
|---|---|
| SHA-256 | `bdb8567cfe7d8789ddb37e4faa584a3221411e8d9f603c0f943bafe6bcafe3b7` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-12 23:02:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `869322e156d79424a9084ee26844b618` |
| SHA-1 | `7f81aa43976f0b87d599ae42b64f2b1de6185d1c` |
| SHA-256 | `bdb8567cfe7d8789ddb37e4faa584a3221411e8d9f603c0f943bafe6bcafe3b7` |
| SHA3-384 | `ca22951e1268f83577fc78672abae46cd3decdc941124adacc11856ec29adbdcfb13e8541c83115d5dde6ad0067b717a` |
| TLSH | `T12EC27D956A867C44BEC98A3E4CBD2B1D6DF5C3D1224942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:A8vCB+25j6es8RdU9FYpMSUpi+20qUpi+20YQX:A8l25Jdyd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_bdb8567c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdb8567cfe7d8789ddb37e4faa584a3221411e8d9f603c0f943bafe6bcafe3b7"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 23:02:46"
  condition:
    hash.sha256(0, filesize) == "bdb8567cfe7d8789ddb37e4faa584a3221411e8d9f603c0f943bafe6bcafe3b7"
}
```

### Sample 40: `3590eb0fe1ea5872`

| Field | Value |
|---|---|
| SHA-256 | `3590eb0fe1ea587258592d3a3db69e363f59cbfe5c1447810135ce5106c7df46` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-12 22:47:47` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46017eae068e6722cc069b861a20531f` |
| SHA-256 | `3590eb0fe1ea587258592d3a3db69e363f59cbfe5c1447810135ce5106c7df46` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_3590eb0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3590eb0fe1ea587258592d3a3db69e363f59cbfe5c1447810135ce5106c7df46"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 22:47:47"
  condition:
    hash.sha256(0, filesize) == "3590eb0fe1ea587258592d3a3db69e363f59cbfe5c1447810135ce5106c7df46"
}
```

### Sample 41: `e92ea71674c6fe09`

| Field | Value |
|---|---|
| SHA-256 | `e92ea71674c6fe0911ba61d8bf404ef875a93d2ee18ec4445f8c07f5bcd49412` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-12 22:40:49` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a72003a20332986f72cc248a01cb6cfa` |
| SHA-256 | `e92ea71674c6fe0911ba61d8bf404ef875a93d2ee18ec4445f8c07f5bcd49412` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_e92ea716
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e92ea71674c6fe0911ba61d8bf404ef875a93d2ee18ec4445f8c07f5bcd49412"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 22:40:49"
  condition:
    hash.sha256(0, filesize) == "e92ea71674c6fe0911ba61d8bf404ef875a93d2ee18ec4445f8c07f5bcd49412"
}
```

### Sample 42: `704a33c176e3a63a`

| Field | Value |
|---|---|
| SHA-256 | `704a33c176e3a63a2a60811683cbf9ef7c60b6befd1d95b02c4e67c2924eec51` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Python.Stealer.4925.5889.9280` |
| File type | `exe` |
| First seen | `2026-09-12 22:34:36` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `979d13c02b2787f20bb36865c45e7cef` |
| SHA-1 | `158ae6bf6fa8aa86a9697c5b91ba0835dcbd34da` |
| SHA-256 | `704a33c176e3a63a2a60811683cbf9ef7c60b6befd1d95b02c4e67c2924eec51` |
| SHA3-384 | `437acf9ce05cedb1b1738a9c298d28756547f37ff136d12a3127f6a5cd3372ce9c74c4ed35f944d03f62ace1389b9cbb` |
| IMPHASH | `1b391fc77bb90cff1c2e8bacbd2b5b38` |
| TLSH | `T19A173388D29122DDEE63A13FD9638E05C933347E4765C8C71A788767AE236804D7DB52` |
| SSDEEP | `393216:X85vzasFl7dCR1C99fdJNsCq7rAGuOWCEDMJ83a10LQXdwWws84xPtOn:M5vzJFlUR1OXNsCqFupCEDOEaWQtwjB` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_704a33c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "704a33c176e3a63a2a60811683cbf9ef7c60b6befd1d95b02c4e67c2924eec51"
    family = "unknown"
    file_name = "SecuriteInfo.com.Python.Stealer.4925.5889.9280"
    file_type = "exe"
    first_seen = "2026-09-12 22:34:36"
  condition:
    hash.sha256(0, filesize) == "704a33c176e3a63a2a60811683cbf9ef7c60b6befd1d95b02c4e67c2924eec51"
}
```

### Sample 43: `34d7cf7269c88989`

| Field | Value |
|---|---|
| SHA-256 | `34d7cf7269c8898978c35a3963f76cf09466b5ab8695d16d7184ddbe587a681b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-12 22:26:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73f8f66b6a0f5aa1f54ef1d3c2abd226` |
| SHA-1 | `b714a4e99b48a13a2c8dfd1f9ff673183d56f722` |
| SHA-256 | `34d7cf7269c8898978c35a3963f76cf09466b5ab8695d16d7184ddbe587a681b` |
| SHA3-384 | `2ea7f3161f99a2f6124cab80961c5b5228114f92a4cd04fe0b3cff7df51c6dd49c04d8c777dae5f925770faae24d6675` |
| TLSH | `T1CA235C6516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF68C4AA9DD109B1D` |
| SSDEEP | `768:m+u9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:m+7cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_34d7cf72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34d7cf7269c8898978c35a3963f76cf09466b5ab8695d16d7184ddbe587a681b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 22:26:49"
  condition:
    hash.sha256(0, filesize) == "34d7cf7269c8898978c35a3963f76cf09466b5ab8695d16d7184ddbe587a681b"
}
```

### Sample 44: `b23943dc5ab42e33`

| Field | Value |
|---|---|
| SHA-256 | `b23943dc5ab42e339bbc5a83bb1fa95b2bae70e7b00a8070d0de489ba9731b7b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 22:22:20` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22cebd3ccdd8efab543383d38df54381` |
| SHA-1 | `870f22c415f3c9d5a599ed21c2854b688aa233a4` |
| SHA-256 | `b23943dc5ab42e339bbc5a83bb1fa95b2bae70e7b00a8070d0de489ba9731b7b` |
| SHA3-384 | `b1fb32c4430229173c1d184de4d622814e4b9091f6c1f4d54e8f6d63022a44723b85af78fd51e6000f3ff32606f2fd17` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T1B5824B0FB8428316E0D11070A676827BE979A87A37C814DBF7D449DD0A786D5FC3215F` |
| SSDEEP | `192:z5Y86SCngTBv8vVaFXq651ln5aZuyMGleQJrQKUSiu9zwDi7sVTgbOBqmEiLFTGS:zz6I8vVaF6OjGUQgu94irUwav8U9cEl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_b23943dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b23943dc5ab42e339bbc5a83bb1fa95b2bae70e7b00a8070d0de489ba9731b7b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:22:20"
  condition:
    hash.sha256(0, filesize) == "b23943dc5ab42e339bbc5a83bb1fa95b2bae70e7b00a8070d0de489ba9731b7b"
}
```

### Sample 45: `837f3b41488599ff`

| Field | Value |
|---|---|
| SHA-256 | `837f3b41488599ff02ffc32a795c073a32143349088c97f786b910c0cbe46503` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 22:21:00` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7868f2ac2276680a3ddcc0ef9f886650` |
| SHA-1 | `0191f69a9fe7e77b612197daca92c26e71c1ba21` |
| SHA-256 | `837f3b41488599ff02ffc32a795c073a32143349088c97f786b910c0cbe46503` |
| SHA3-384 | `1f66d128ac214c967f4c982a45fe2095dda2203e73404e8a845ec029d9909188f68dea178771e63e002a9cf995b90cf5` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T133825C0FB8424316E0D11070A676827BEA79A8BA37C814DBF7D449DD0A786D5FC3215F` |
| SSDEEP | `192:XfY86SCngTBv8vVaFXq651ln5aZuyMGleQJrQKUSiu9zwDi7sVTgbOBqmEiLFTG/:XR6I8vVaF6OjGUQgu94irUwav8U9cdl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_837f3b41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "837f3b41488599ff02ffc32a795c073a32143349088c97f786b910c0cbe46503"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:21:00"
  condition:
    hash.sha256(0, filesize) == "837f3b41488599ff02ffc32a795c073a32143349088c97f786b910c0cbe46503"
}
```

### Sample 46: `5462d0338800b440`

| Field | Value |
|---|---|
| SHA-256 | `5462d0338800b440fec5b6a6133cd943c9ef5c05883859c70fbd5326a8e54ccc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 22:20:27` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7143db771d9cd4cc578cd3117368cbbb` |
| SHA-1 | `fe3fea608d434635324832fa9f19287e8e20efe5` |
| SHA-256 | `5462d0338800b440fec5b6a6133cd943c9ef5c05883859c70fbd5326a8e54ccc` |
| SHA3-384 | `f27ac93927f3d34d2b3ef226515df860ec7a7fdf2b1112c60ecffdab2e7188d54a4059f3cbdfd500312afc5bfeac9a54` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T18D824B0FB8424316E0D11070A676867BE979A87A37C814DBF7D449ED0A786D5FC3215F` |
| SSDEEP | `192:XAY86SCngTBv8vVaFXq651ln5aZuyMGleQJrQKUSiu9zwDi7sVTgbOBqmEiLFTG3:X+6I8vVaF6OjGUQgu94irUwav8U9cll` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_5462d033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5462d0338800b440fec5b6a6133cd943c9ef5c05883859c70fbd5326a8e54ccc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:20:27"
  condition:
    hash.sha256(0, filesize) == "5462d0338800b440fec5b6a6133cd943c9ef5c05883859c70fbd5326a8e54ccc"
}
```

### Sample 47: `02c7d7ffc279d2d7`

| Field | Value |
|---|---|
| SHA-256 | `02c7d7ffc279d2d791fac163ce8252bfb9f4fff406266fb69a4d381ab6e315e4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 22:17:22` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aca7c39c5104d3ce16117e040783f853` |
| SHA-1 | `a7e7feea48f60ec068a97cb3462a721ace16a61b` |
| SHA-256 | `02c7d7ffc279d2d791fac163ce8252bfb9f4fff406266fb69a4d381ab6e315e4` |
| SHA3-384 | `64d9d9a0c37e42507f57700dfa481ef1a7eea474421897bec0d31ae7e1f668cfc5a70dc1f6e8b33ce9693aca26ccd65d` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T1EF824B0FB8424316E0E11070A676867BDA79A87A37C814DBF7D449ED0A686D5FC3215F` |
| SSDEEP | `192:kyY86SCngTBv8vVaFXq651ln5aZuyMGleQJrQKUSiu9zwDi7sVTgbOBqmEiLFTG/:kY6I8vVaF6OjGUQgu94irUwav8U9cdl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_02c7d7ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02c7d7ffc279d2d791fac163ce8252bfb9f4fff406266fb69a4d381ab6e315e4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:17:22"
  condition:
    hash.sha256(0, filesize) == "02c7d7ffc279d2d791fac163ce8252bfb9f4fff406266fb69a4d381ab6e315e4"
}
```

### Sample 48: `7ec862eeff86921c`

| Field | Value |
|---|---|
| SHA-256 | `7ec862eeff86921c9f7c591820ca0780576d6ce13f4ddc1e690cc8342e0145cc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 22:15:40` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a408b814a64621c15f42b4ddfa92540b` |
| SHA-1 | `06804356ef8b7d3678de5a057ee0a5372c0aa73c` |
| SHA-256 | `7ec862eeff86921c9f7c591820ca0780576d6ce13f4ddc1e690cc8342e0145cc` |
| SHA3-384 | `411b5a16fb181415a4ae6211872f0af4f7f5fda626f0aad6f76576e2ff992c5932390f781d9856fc911c0bf37e2b9e11` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T1FC825C0FB8424316E0D11070A276867BE979A87A37C814DBF7D489EE0A786D5FC3215F` |
| SSDEEP | `192:FhY86SCngTBv8vVaFXq651ln5aZuyMGleQJrQKUSiu9zwDi7sVTgbOBqmEiLFTGN:F76I8vVaF6OjGUQgu94irUwav8U9c/l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_7ec862ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ec862eeff86921c9f7c591820ca0780576d6ce13f4ddc1e690cc8342e0145cc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:15:40"
  condition:
    hash.sha256(0, filesize) == "7ec862eeff86921c9f7c591820ca0780576d6ce13f4ddc1e690cc8342e0145cc"
}
```

### Sample 49: `2bca57bf92ff112d`

| Field | Value |
|---|---|
| SHA-256 | `2bca57bf92ff112d5e3f30563f235084a415921972598a6400e8f30eb28bd16f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-12 22:12:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd79cbdea67eb9d536f7d108f0dba6a9` |
| SHA-1 | `7b3fe4243a6c9b18eca2f7998f1f9df6973b08b3` |
| SHA-256 | `2bca57bf92ff112d5e3f30563f235084a415921972598a6400e8f30eb28bd16f` |
| SHA3-384 | `8f5466fd8b24900e8d730aa4d68ea1578011734d8edccc4dd1c0feb731a7cb13552416ecacfa1faf3514b55624ab465b` |
| TLSH | `T153235C651A857C14AA98C4361D7F2F0CB9AD43E6320452EE7FCF3CF28C5A6AD910572D` |
| SSDEEP | `768:F6Utd8/U9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ocr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_2bca57bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bca57bf92ff112d5e3f30563f235084a415921972598a6400e8f30eb28bd16f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 22:12:48"
  condition:
    hash.sha256(0, filesize) == "2bca57bf92ff112d5e3f30563f235084a415921972598a6400e8f30eb28bd16f"
}
```

### Sample 50: `a8c4128d95766a9b`

| Field | Value |
|---|---|
| SHA-256 | `a8c4128d95766a9ba9050fae86efbfdc177d1bff75d77f1a51321216ffc7d8be` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-12 22:08:47` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a97b75501d05de374f772a50118774ae` |
| SHA-256 | `a8c4128d95766a9ba9050fae86efbfdc177d1bff75d77f1a51321216ffc7d8be` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_a8c4128d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8c4128d95766a9ba9050fae86efbfdc177d1bff75d77f1a51321216ffc7d8be"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 22:08:47"
  condition:
    hash.sha256(0, filesize) == "a8c4128d95766a9ba9050fae86efbfdc177d1bff75d77f1a51321216ffc7d8be"
}
```

### Sample 51: `63d87d4569a49155`

| Field | Value |
|---|---|
| SHA-256 | `63d87d4569a491553e14757dc267aa29ae8b606b0396dd16acc5c642f629fc7e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 22:05:29` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be41cf7a1e6f096175aae247e48cb98c` |
| SHA-1 | `e70e067b32ec5848a114276f6740ccce3f0f54f9` |
| SHA-256 | `63d87d4569a491553e14757dc267aa29ae8b606b0396dd16acc5c642f629fc7e` |
| SHA3-384 | `90c88c9dd2eb88ad1c199d18d6dc2b85be9161f1b1cb176776d1f62b3fea7345b32cd6b2fce1c4ee259382db0d1c6dbd` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T10B32D51E2E460331DE5008B4E535864A513D1EE37393EBDBE633E59B0AD6E8584C1AAF` |
| SSDEEP | `96:M7OdbIo1Yz/9PYz/mUJait7BwZbdCOjDbhxef2qMDQKGmo1PFJxGE9mZ2FFh/C7Q:TIo2W7tBwLxeuqMNgPFJxTEZmFhEucS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_63d87d45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63d87d4569a491553e14757dc267aa29ae8b606b0396dd16acc5c642f629fc7e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:05:29"
  condition:
    hash.sha256(0, filesize) == "63d87d4569a491553e14757dc267aa29ae8b606b0396dd16acc5c642f629fc7e"
}
```

### Sample 52: `14bc3a778e14a6ee`

| Field | Value |
|---|---|
| SHA-256 | `14bc3a778e14a6eef9eaec220b8902af61f153efef037280a7ce21af47ddfc3f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 22:02:49` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3638e23d5a94ceaf66a65af2d3b69a75` |
| SHA-1 | `1c000b83317f1905082ba29b0ac16ce5cd86af49` |
| SHA-256 | `14bc3a778e14a6eef9eaec220b8902af61f153efef037280a7ce21af47ddfc3f` |
| SHA3-384 | `14c8917d6e1bcb2fa7bd127af7294efcdee35203c3763872bc26711dce92ba7fb9abc1eef0888d122bdcfdabde5fc469` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T19E824B0FB8424316E1D11070A676827BEA79A8BA37C814DBF7D449DD0A786D5FC3215F` |
| SSDEEP | `192:hVY86SCngTBv8vVaFXq651ln5aZuyMGleQJrQKUSiu9zwDi7sVTgbOBqmEiLFTGt:hH6I8vVaF6OjGUQgu94irUwav8U9cfl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_14bc3a77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14bc3a778e14a6eef9eaec220b8902af61f153efef037280a7ce21af47ddfc3f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:02:49"
  condition:
    hash.sha256(0, filesize) == "14bc3a778e14a6eef9eaec220b8902af61f153efef037280a7ce21af47ddfc3f"
}
```

### Sample 53: `d019021b688b5589`

| Field | Value |
|---|---|
| SHA-256 | `d019021b688b5589ad8a45fe2541967649b2cd9c89fdd49074c844f518887fff` |
| Family label | `unknown` |
| File name | `vicelocity_sample.exe` |
| File type | `exe` |
| First seen | `2026-09-12 22:01:08` |
| Reporter | `turnasmyth015` |
| Tags | `exe, golang, notvelo.com, roblox, stealc, stealer, vicelocity, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9fa0af33e676367a0ddf4c20d766483` |
| SHA-256 | `d019021b688b5589ad8a45fe2541967649b2cd9c89fdd49074c844f518887fff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_d019021b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d019021b688b5589ad8a45fe2541967649b2cd9c89fdd49074c844f518887fff"
    family = "unknown"
    file_name = "vicelocity_sample.exe"
    file_type = "exe"
    first_seen = "2026-09-12 22:01:08"
  condition:
    hash.sha256(0, filesize) == "d019021b688b5589ad8a45fe2541967649b2cd9c89fdd49074c844f518887fff"
}
```

### Sample 54: `48139ce0c5abb601`

| Field | Value |
|---|---|
| SHA-256 | `48139ce0c5abb601cca6a634ef33579b63c3cc109cc3aa7439c6d2e415e4b504` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 22:01:04` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, exe, signed, YT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a422da1c7a6d1e70cf066b71d4c5544` |
| SHA-1 | `495a2f32b53ed6c08bff79a1f53f259f03ca3af1` |
| SHA-256 | `48139ce0c5abb601cca6a634ef33579b63c3cc109cc3aa7439c6d2e415e4b504` |
| SHA3-384 | `4c4e6d7539dda574c6e36ae1fb14cea57eea4067bff8ac52b2b0a9b1d5257324446f3f2c2d3bf994a2b410df31e90aa2` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T115674A07AA5410E4D06EEB78D97B92673B61BC8D433633A71DA06A306F363D26EF5704` |
| SSDEEP | `49152:qdcmnzvgDLQj/wDxnzt0dgUz2wwyogxJw0ekvx8FBPdq8YU83uEyxc/IaMIR3zg:qdD7GplUvbDvxSBQEn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_48139ce0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48139ce0c5abb601cca6a634ef33579b63c3cc109cc3aa7439c6d2e415e4b504"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:01:04"
  condition:
    hash.sha256(0, filesize) == "48139ce0c5abb601cca6a634ef33579b63c3cc109cc3aa7439c6d2e415e4b504"
}
```

### Sample 55: `47965b1026efde3f`

| Field | Value |
|---|---|
| SHA-256 | `47965b1026efde3f30153e881ce0a2ea62ff6191ec5341cb1695fff051cdfb6c` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-12 21:47:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31e0d56ea37f37ddb680f79444931c94` |
| SHA-1 | `c84ada7c326f08e2258c4e5bd8dc98af3f4e0a72` |
| SHA-256 | `47965b1026efde3f30153e881ce0a2ea62ff6191ec5341cb1695fff051cdfb6c` |
| SHA3-384 | `173aefb3e6e3a2126d9096f59c2c20055ae1c3107deb8f5d54e24b939fe5e0ada1d69962075793375729b7ef72d2fa03` |
| TLSH | `T10D236C651A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10971D` |
| SSDEEP | `768:eXRWNGxV09GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:alx7cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_47965b10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47965b1026efde3f30153e881ce0a2ea62ff6191ec5341cb1695fff051cdfb6c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 21:47:52"
  condition:
    hash.sha256(0, filesize) == "47965b1026efde3f30153e881ce0a2ea62ff6191ec5341cb1695fff051cdfb6c"
}
```

### Sample 56: `e71834bb6b472868`

| Field | Value |
|---|---|
| SHA-256 | `e71834bb6b4728689510701d2e58443a1e675d7cef2fc47dea6fa3c690f4c38b` |
| Family label | `unknown` |
| File name | `COPIA_DE_TRANSACCION_EKNFW5CD.svg_b.svg.zip` |
| File type | `zip` |
| First seen | `2026-09-12 21:45:53` |
| Reporter | `anonymous` |
| Tags | `chile, comprobante, correo, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a06a93f6bf95d96f67944adef41e4bb` |
| SHA-256 | `e71834bb6b4728689510701d2e58443a1e675d7cef2fc47dea6fa3c690f4c38b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_e71834bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e71834bb6b4728689510701d2e58443a1e675d7cef2fc47dea6fa3c690f4c38b"
    family = "unknown"
    file_name = "COPIA_DE_TRANSACCION_EKNFW5CD.svg_b.svg.zip"
    file_type = "zip"
    first_seen = "2026-09-12 21:45:53"
  condition:
    hash.sha256(0, filesize) == "e71834bb6b4728689510701d2e58443a1e675d7cef2fc47dea6fa3c690f4c38b"
}
```

### Sample 57: `00f2bc3455fbb1aa`

| Field | Value |
|---|---|
| SHA-256 | `00f2bc3455fbb1aaa20a7c892357b3610fd2c099d408e9f8743e4d6627d1607c` |
| Family label | `DDoSAgent` |
| File name | `bot_client_mipsle` |
| File type | `elf` |
| First seen | `2026-09-12 21:43:05` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b973e8d45c60b46fb68a30549cb1b1e1` |
| SHA-1 | `1517a33093d8b5abdfbd64c61f0bb83c3230fc90` |
| SHA-256 | `00f2bc3455fbb1aaa20a7c892357b3610fd2c099d408e9f8743e4d6627d1607c` |
| SHA3-384 | `e927364dc41377221fe712a1c9905d6945e210d9f5398fe17cfa7e0cfe375c50cb876dd96d024107c6359ebf2b6c0c5f` |
| TLSH | `T11616E814EDC42BA6C02C4B7494FACA5622745D144BF14B2626A4FFE8BCB62797F43C9C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:PBtg0g+7hwEqcYkYgfEt9dWMbNn1sTWwhmCN9keXfa+tiPZ6AMWbf+1lIOKkSW22:8+2EakzE7ZCfPj2X56hr` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_057_00f2bc34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00f2bc3455fbb1aaa20a7c892357b3610fd2c099d408e9f8743e4d6627d1607c"
    family = "DDoSAgent"
    file_name = "bot_client_mipsle"
    file_type = "elf"
    first_seen = "2026-09-12 21:43:05"
  condition:
    hash.sha256(0, filesize) == "00f2bc3455fbb1aaa20a7c892357b3610fd2c099d408e9f8743e4d6627d1607c"
}
```

### Sample 58: `af40e385ad62e939`

| Field | Value |
|---|---|
| SHA-256 | `af40e385ad62e939c3bfa7f38884f49c69b04d35da630213aa22e2d2f82f92e4` |
| Family label | `DDoSAgent` |
| File name | `bot_client_mips` |
| File type | `elf` |
| First seen | `2026-09-12 21:43:03` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bb83518475ba4c2266150fe90309d45` |
| SHA-1 | `988ad842c86ba2f8da4214c180399444f01981bf` |
| SHA-256 | `af40e385ad62e939c3bfa7f38884f49c69b04d35da630213aa22e2d2f82f92e4` |
| SHA3-384 | `4a626a4fe023f14fdccfb674d327ea7483da3aeaede02288036e488f29ea1124404743112b587ecf12b6455749f2a872` |
| TLSH | `T17E1619127F18EB0EC62821351CB2CA986B791C8646DA9627B351F319F4F21BD4D6ECF1` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:b0bu7ow74YC13HL/VsaRNRFnsN4itYSFWeK1dpVeEFB3l7lPU4ekAfgH9C51xbQ:d8xP3MEC51xU` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_058_af40e385
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af40e385ad62e939c3bfa7f38884f49c69b04d35da630213aa22e2d2f82f92e4"
    family = "DDoSAgent"
    file_name = "bot_client_mips"
    file_type = "elf"
    first_seen = "2026-09-12 21:43:03"
  condition:
    hash.sha256(0, filesize) == "af40e385ad62e939c3bfa7f38884f49c69b04d35da630213aa22e2d2f82f92e4"
}
```

### Sample 59: `51a3af22bcd96f85`

| Field | Value |
|---|---|
| SHA-256 | `51a3af22bcd96f85e9158d29078850ea3f06742a8f2279c14526b97c713c2614` |
| Family label | `DDoSAgent` |
| File name | `bot_client_mips64le` |
| File type | `elf` |
| First seen | `2026-09-12 21:43:02` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57968cdd351a38efb8a576fdfd6042fe` |
| SHA-1 | `8b1e0190d45ffd7372327d290408fead29d18d4e` |
| SHA-256 | `51a3af22bcd96f85e9158d29078850ea3f06742a8f2279c14526b97c713c2614` |
| SHA3-384 | `6290751c899af5eea6c9dceba0baefe41a9a2cbea95ecaf85ae6383331c13c9f98fc60f35e8f44c0b61615f7d251d282` |
| TLSH | `T1F016E725BDC22B66C5CC177845FE625A22507E449B95072323E8FBAC3E7733CAF56488` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:v0SwBCye4D2W4m66YQd7FpDIePLF6Th5JDfAws6vxznL+2TYUe+NsDc8pl1E6y9l:Me4l/WTYUs3Iii6j6rCYwAF+G` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_059_51a3af22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51a3af22bcd96f85e9158d29078850ea3f06742a8f2279c14526b97c713c2614"
    family = "DDoSAgent"
    file_name = "bot_client_mips64le"
    file_type = "elf"
    first_seen = "2026-09-12 21:43:02"
  condition:
    hash.sha256(0, filesize) == "51a3af22bcd96f85e9158d29078850ea3f06742a8f2279c14526b97c713c2614"
}
```

### Sample 60: `5bf715c1088adf21`

| Field | Value |
|---|---|
| SHA-256 | `5bf715c1088adf216db2c1470d7e88d98cbcb25e00a4ce3513dacbaeb3be3953` |
| Family label | `unknown` |
| File name | `bot_client_arm` |
| File type | `elf` |
| First seen | `2026-09-12 21:43:00` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a7f3324191cda39bf92ef6d112f8681` |
| SHA-1 | `9d23ccd877160553ca37b37d2c98be6cb7e8aa49` |
| SHA-256 | `5bf715c1088adf216db2c1470d7e88d98cbcb25e00a4ce3513dacbaeb3be3953` |
| SHA3-384 | `2396206f087bba1e1d57989b5e0e3c9c02925b373ebbf6341f87e8f755c78b1755eaab26980d0db875c7ed46d61f56ce` |
| TLSH | `T1A9060957B8D14986C4E43A37B87E81C433A75EB99B96131B6D04FE3C3ABE1A90D39314` |
| TELFHASH | `t1a6e0d8867f0e27cc23d4a24441493616dbe934f7023017789d88af9f1d45c6331d9821` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:nCoGk4PwovqKste/YncDH6GY70ocFNFzkOzZwJFFZEcbkzkQQHO3MsiN/c8dUecd:PwBJahbs/S7VZMKXo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_5bf715c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bf715c1088adf216db2c1470d7e88d98cbcb25e00a4ce3513dacbaeb3be3953"
    family = "unknown"
    file_name = "bot_client_arm"
    file_type = "elf"
    first_seen = "2026-09-12 21:43:00"
  condition:
    hash.sha256(0, filesize) == "5bf715c1088adf216db2c1470d7e88d98cbcb25e00a4ce3513dacbaeb3be3953"
}
```

### Sample 61: `48caea2d6482c7d2`

| Field | Value |
|---|---|
| SHA-256 | `48caea2d6482c7d2b0b97a05bca70ab87a8d9347f3f888e9984ea5cbf99d82f3` |
| Family label | `DDoSAgent` |
| File name | `bot_client_x86_64` |
| File type | `elf` |
| First seen | `2026-09-12 21:42:58` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34dae7496776d7ba1afba67c90f2d0eb` |
| SHA-1 | `8103062f071f073ce71a60b071b17f772cc7b96d` |
| SHA-256 | `48caea2d6482c7d2b0b97a05bca70ab87a8d9347f3f888e9984ea5cbf99d82f3` |
| SHA3-384 | `e4b510eb36798073835e34ec6caba8b406c4ce6c39a0754245d853402fbd82caf217fc618f7d304f8d08165e8770db43` |
| TLSH | `T14F064A13FCA545E9C4AAE2358A629253BA717C885B3123D33F90F7782F72BD06979740` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:on+z+leCEndSK7gfk7lmMJLAI5EbPhlrFYwgIMBPoOG:Yjgi+/EbPN7pGAOG` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_061_48caea2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48caea2d6482c7d2b0b97a05bca70ab87a8d9347f3f888e9984ea5cbf99d82f3"
    family = "DDoSAgent"
    file_name = "bot_client_x86_64"
    file_type = "elf"
    first_seen = "2026-09-12 21:42:58"
  condition:
    hash.sha256(0, filesize) == "48caea2d6482c7d2b0b97a05bca70ab87a8d9347f3f888e9984ea5cbf99d82f3"
}
```

### Sample 62: `4315615b2f9e7000`

| Field | Value |
|---|---|
| SHA-256 | `4315615b2f9e700018303979a1b9d7ab6cdce3be5360bd3a29f0d7d3e349ffdc` |
| Family label | `DDoSAgent` |
| File name | `bot_client_mips64` |
| File type | `elf` |
| First seen | `2026-09-12 21:42:56` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14b6b0aa63fd3ed14721ade36d44c39d` |
| SHA-1 | `7aeb811d4017e9f25c89820a6c3fc519109ffab9` |
| SHA-256 | `4315615b2f9e700018303979a1b9d7ab6cdce3be5360bd3a29f0d7d3e349ffdc` |
| SHA3-384 | `5e42ca45136c2207d9b5cea1cf346371c6f001d54bae9271a8a637031702acb2aa67dd3d9ccaad358228f4e3f5eeaf4f` |
| TLSH | `T18B160921BF85DE0BD2A8223589A6C23473D53D4182F025379716FB192EBF2B49D1BDD8` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:hhNj4D1aYQByRhew+2UqtWKEBe1wklEPZuZo56Ze9YX8bnRU0nZE1UIg/2DoEHNr:q0nrI1gWtxWHMzr2Y/AFnLLMbV` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_062_4315615b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4315615b2f9e700018303979a1b9d7ab6cdce3be5360bd3a29f0d7d3e349ffdc"
    family = "DDoSAgent"
    file_name = "bot_client_mips64"
    file_type = "elf"
    first_seen = "2026-09-12 21:42:56"
  condition:
    hash.sha256(0, filesize) == "4315615b2f9e700018303979a1b9d7ab6cdce3be5360bd3a29f0d7d3e349ffdc"
}
```

### Sample 63: `c979ad4c75cdf793`

| Field | Value |
|---|---|
| SHA-256 | `c979ad4c75cdf793fea7e600974d8bc2422260b31b5ed19e00cf6d9fea7ab552` |
| Family label | `unknown` |
| File name | `bot_client_arm64` |
| File type | `elf` |
| First seen | `2026-09-12 21:42:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26e45dd4c42925b3a90ff172a1428860` |
| SHA-1 | `97f8b2a5d92956ccfb6a45596720791410171ad8` |
| SHA-256 | `c979ad4c75cdf793fea7e600974d8bc2422260b31b5ed19e00cf6d9fea7ab552` |
| SHA3-384 | `fe32debadff99751cb00664bf8e024bf0e20c9cf54dee7de037693f15b7fcfaef1f27d4ad9de73de877c24ea0fc98830` |
| TLSH | `T1E7066C94BC1DB462E9C9BAB87F2541D87239FC485F8183377604FBAD69F23548F22660` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:qR2syQMB5/6ACvLoee+yqabphBln9iyMXpuu6XO/K++kGpXYP1ik59yj+NriWOWX:qRNyXs5yqabpR9xMXPx5E+Z3a2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_c979ad4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c979ad4c75cdf793fea7e600974d8bc2422260b31b5ed19e00cf6d9fea7ab552"
    family = "unknown"
    file_name = "bot_client_arm64"
    file_type = "elf"
    first_seen = "2026-09-12 21:42:54"
  condition:
    hash.sha256(0, filesize) == "c979ad4c75cdf793fea7e600974d8bc2422260b31b5ed19e00cf6d9fea7ab552"
}
```

### Sample 64: `dc689e89652ccb9f`

| Field | Value |
|---|---|
| SHA-256 | `dc689e89652ccb9f54599e9403a8d610fe5603c3ec65a10249fb4ab78b79cb1e` |
| Family label | `DDoSAgent` |
| File name | `bot_client_amd64` |
| File type | `elf` |
| First seen | `2026-09-12 21:42:53` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49898ebd4ab5ede3ccf258453c6f1dd7` |
| SHA-1 | `7d09fbebd2120488d34784cf55625981cec438da` |
| SHA-256 | `dc689e89652ccb9f54599e9403a8d610fe5603c3ec65a10249fb4ab78b79cb1e` |
| SHA3-384 | `4a41fbbd16a669f7add1cbf1c661e5d552633d799983c85504cdcec2585bad2683dae1d8bad8e347354dad8a6036dee4` |
| TLSH | `T161064A13FCA545E9C4AAE2358A629253BA717C885B3123D33F90F7782F72BD06979740` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:Vn+z+leCEndSK7gfk7lmMJLAI5EbPhlrFYwgIMoPoO4:1jgi+/EbPN7pjAO4` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_064_dc689e89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc689e89652ccb9f54599e9403a8d610fe5603c3ec65a10249fb4ab78b79cb1e"
    family = "DDoSAgent"
    file_name = "bot_client_amd64"
    file_type = "elf"
    first_seen = "2026-09-12 21:42:53"
  condition:
    hash.sha256(0, filesize) == "dc689e89652ccb9f54599e9403a8d610fe5603c3ec65a10249fb4ab78b79cb1e"
}
```

### Sample 65: `821928cd11678295`

| Field | Value |
|---|---|
| SHA-256 | `821928cd116782950ebaa535aef8f3ad40f1ee6fbda9a8b04e7bf92caf771814` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-12 21:38:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `765f3a1df470dd5b63b189c0a4a1e679` |
| SHA-1 | `7587d9080c5f0df97773b841239f85120abdf376` |
| SHA-256 | `821928cd116782950ebaa535aef8f3ad40f1ee6fbda9a8b04e7bf92caf771814` |
| SHA3-384 | `19dd7e387d01d26efe5843fe108cd4a5aedb9b06b47a24f9ee22c2ce23e11b5a6ec84d2ea633e191229e80f5e957321f` |
| TLSH | `T16EC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:P8vCB+25j6es8RR9FYpMSUpi+20qUpi+20YQX:P8l25JHd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_821928cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "821928cd116782950ebaa535aef8f3ad40f1ee6fbda9a8b04e7bf92caf771814"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 21:38:50"
  condition:
    hash.sha256(0, filesize) == "821928cd116782950ebaa535aef8f3ad40f1ee6fbda9a8b04e7bf92caf771814"
}
```

### Sample 66: `773a11af4eda8474`

| Field | Value |
|---|---|
| SHA-256 | `773a11af4eda847418827c4f17c97a56b98662f80b45c58c9cd3d99e0cb20016` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 21:38:07` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc095d5cb9ab5cfc46096bb70f8b0454` |
| SHA-256 | `773a11af4eda847418827c4f17c97a56b98662f80b45c58c9cd3d99e0cb20016` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_773a11af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "773a11af4eda847418827c4f17c97a56b98662f80b45c58c9cd3d99e0cb20016"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 21:38:07"
  condition:
    hash.sha256(0, filesize) == "773a11af4eda847418827c4f17c97a56b98662f80b45c58c9cd3d99e0cb20016"
}
```

### Sample 67: `b23e89bd49361d2c`

| Field | Value |
|---|---|
| SHA-256 | `b23e89bd49361d2c5f98eac947e86d08d1002469e46908216c2ac5960f1abeeb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 21:37:57` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bdccc8ac2c7450594f687fc769e752b` |
| SHA-256 | `b23e89bd49361d2c5f98eac947e86d08d1002469e46908216c2ac5960f1abeeb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_b23e89bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b23e89bd49361d2c5f98eac947e86d08d1002469e46908216c2ac5960f1abeeb"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 21:37:57"
  condition:
    hash.sha256(0, filesize) == "b23e89bd49361d2c5f98eac947e86d08d1002469e46908216c2ac5960f1abeeb"
}
```

### Sample 68: `9f93d7a9fc452e1b`

| Field | Value |
|---|---|
| SHA-256 | `9f93d7a9fc452e1b4514bfd4e231febd7b4005740a592cefbc9e94ec29584664` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-12 21:36:50` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88ce45f685cb3969b36aa2a203578e6a` |
| SHA-256 | `9f93d7a9fc452e1b4514bfd4e231febd7b4005740a592cefbc9e94ec29584664` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_9f93d7a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f93d7a9fc452e1b4514bfd4e231febd7b4005740a592cefbc9e94ec29584664"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 21:36:50"
  condition:
    hash.sha256(0, filesize) == "9f93d7a9fc452e1b4514bfd4e231febd7b4005740a592cefbc9e94ec29584664"
}
```

### Sample 69: `90e2c6ef2062148c`

| Field | Value |
|---|---|
| SHA-256 | `90e2c6ef2062148c89b4b66d3cfbf75012a273ff9ec5bc1a6a88215ac4b340fd` |
| Family label | `unknown` |
| File name | `90e2c6ef2062148c89b4b66d3cfbf75012a273ff9ec5bc1a6a88215ac4b340fd.bin` |
| File type | `exe` |
| First seen | `2026-09-12 20:54:24` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8409fb4eb2c25721555a20bb5b11f6e1` |
| SHA-1 | `85590357f811a8f0353bc732a8774b8ef3f9f576` |
| SHA-256 | `90e2c6ef2062148c89b4b66d3cfbf75012a273ff9ec5bc1a6a88215ac4b340fd` |
| SHA3-384 | `f97b4af6a7e489b6c8ec340b18df540b3f6e9eb0e9c979c32f8e90d82d57b37222db42661a02acc19f74995396703dec` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T17A168C076C8144E5E5BA5B7A84B30112B764BC18CF36A7EB1E647B382F723C19DB6B44` |
| SSDEEP | `98304:Fa7KmmoabJN85ua3JbLU0tPHttutHekg4YZ5:KFmoabJK5ua3JbLU0tPHttuxekp25` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_90e2c6ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90e2c6ef2062148c89b4b66d3cfbf75012a273ff9ec5bc1a6a88215ac4b340fd"
    family = "unknown"
    file_name = "90e2c6ef2062148c89b4b66d3cfbf75012a273ff9ec5bc1a6a88215ac4b340fd.bin"
    file_type = "exe"
    first_seen = "2026-09-12 20:54:24"
  condition:
    hash.sha256(0, filesize) == "90e2c6ef2062148c89b4b66d3cfbf75012a273ff9ec5bc1a6a88215ac4b340fd"
}
```

### Sample 70: `89ea7049eae2af35`

| Field | Value |
|---|---|
| SHA-256 | `89ea7049eae2af35ebbd64531a11d50f9364992db0dc8960b8961551289779cd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 20:44:57` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `774ef6bc2f8625205611ced30bb4eee4` |
| SHA-1 | `b81bdac4a08284cb86b20498403d5f0c245fd198` |
| SHA-256 | `89ea7049eae2af35ebbd64531a11d50f9364992db0dc8960b8961551289779cd` |
| SHA3-384 | `1caedea0685889a82ce96a5a21eb3431eeabe8e36669c80abdee56c2279cb1ae10f639ffa259405a2d42fbdacc0a9550` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T118223A2E6E890032D3900DF016B54A5DA57E457327C6B3EBF333C5990EE62448042BEF` |
| SSDEEP | `192:N0oVWUBJBqcx+ep/I5PFJxTEZmFhSKcq:N0ozBecwCI5PFwZ2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_89ea7049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89ea7049eae2af35ebbd64531a11d50f9364992db0dc8960b8961551289779cd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 20:44:57"
  condition:
    hash.sha256(0, filesize) == "89ea7049eae2af35ebbd64531a11d50f9364992db0dc8960b8961551289779cd"
}
```

### Sample 71: `de957022f833e299`

| Field | Value |
|---|---|
| SHA-256 | `de957022f833e299f66364722daf215791413c7d70be4a8c97ad8edd5206110e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 20:37:32` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0435320594bde4760c146d88f81e538d` |
| SHA-256 | `de957022f833e299f66364722daf215791413c7d70be4a8c97ad8edd5206110e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_de957022
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de957022f833e299f66364722daf215791413c7d70be4a8c97ad8edd5206110e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 20:37:32"
  condition:
    hash.sha256(0, filesize) == "de957022f833e299f66364722daf215791413c7d70be4a8c97ad8edd5206110e"
}
```

### Sample 72: `605d219f115457c4`

| Field | Value |
|---|---|
| SHA-256 | `605d219f115457c4825d787d4d7c6d1b56503b36c4e2eabd29d67b160a34249e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 20:37:27` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3acacbcf17a8c9e7d799fca262c273b` |
| SHA-256 | `605d219f115457c4825d787d4d7c6d1b56503b36c4e2eabd29d67b160a34249e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_605d219f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "605d219f115457c4825d787d4d7c6d1b56503b36c4e2eabd29d67b160a34249e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 20:37:27"
  condition:
    hash.sha256(0, filesize) == "605d219f115457c4825d787d4d7c6d1b56503b36c4e2eabd29d67b160a34249e"
}
```

### Sample 73: `dc5378ee70625061`

| Field | Value |
|---|---|
| SHA-256 | `dc5378ee70625061263a7550e6ea6524ee99e98d8ae92755097aeba8a14adb14` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 20:37:23` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26b1398917b7969e18e9d4430d7d5074` |
| SHA-256 | `dc5378ee70625061263a7550e6ea6524ee99e98d8ae92755097aeba8a14adb14` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_dc5378ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc5378ee70625061263a7550e6ea6524ee99e98d8ae92755097aeba8a14adb14"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 20:37:23"
  condition:
    hash.sha256(0, filesize) == "dc5378ee70625061263a7550e6ea6524ee99e98d8ae92755097aeba8a14adb14"
}
```

### Sample 74: `c5acc4bcc957fb7e`

| Field | Value |
|---|---|
| SHA-256 | `c5acc4bcc957fb7e0e3bc000a5c391f4122a4d5a59644fd8d39673aaf7c41956` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 20:37:19` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f36eb69f695dec1df1c423a41de6b582` |
| SHA-256 | `c5acc4bcc957fb7e0e3bc000a5c391f4122a4d5a59644fd8d39673aaf7c41956` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_c5acc4bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5acc4bcc957fb7e0e3bc000a5c391f4122a4d5a59644fd8d39673aaf7c41956"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 20:37:19"
  condition:
    hash.sha256(0, filesize) == "c5acc4bcc957fb7e0e3bc000a5c391f4122a4d5a59644fd8d39673aaf7c41956"
}
```

### Sample 75: `434ffec81e6c1be4`

| Field | Value |
|---|---|
| SHA-256 | `434ffec81e6c1be4873754fa5854fd6c5b3d387a4b9f2119a7bfec8bbe181d9f` |
| Family label | `ConnectWise` |
| File name | `472922.msi` |
| File type | `msi` |
| First seen | `2026-09-12 20:22:23` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34e491628226e530a2a298f6e1a5c960` |
| SHA-1 | `5bce0848e9583ce06feb197cfe8b5d855687c966` |
| SHA-256 | `434ffec81e6c1be4873754fa5854fd6c5b3d387a4b9f2119a7bfec8bbe181d9f` |
| SHA3-384 | `1c1b7854025a07ab876b286418009bb476a4464d45cb1975fcb102a8ec7b173f5e0115d74cca34400b9f91a177f8791a` |
| TLSH | `T18FC6233267FD4918E1F36778ED3A91E291367C65CF12C08F2654786E6871E8096A333B` |
| SSDEEP | `196608:QrnLYG3zDhukOUrnLYG3zErnLYG3zSrnLYG3z8rnLYG3zgrnLYG3z:QbDDDgvUbDDEbDDSbDD8bDDgbDD` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_075_434ffec8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "434ffec81e6c1be4873754fa5854fd6c5b3d387a4b9f2119a7bfec8bbe181d9f"
    family = "ConnectWise"
    file_name = "472922.msi"
    file_type = "msi"
    first_seen = "2026-09-12 20:22:23"
  condition:
    hash.sha256(0, filesize) == "434ffec81e6c1be4873754fa5854fd6c5b3d387a4b9f2119a7bfec8bbe181d9f"
}
```

### Sample 76: `ede450e3c9f6bdfc`

| Field | Value |
|---|---|
| SHA-256 | `ede450e3c9f6bdfc7de2fbda91eac908510f970a1e1e17bebb8fb9ecd1721342` |
| Family label | `ConnectWise` |
| File name | `13beb.msi` |
| File type | `msi` |
| First seen | `2026-09-12 20:18:53` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12c5e6b81f3635de5d0c56418afa3cee` |
| SHA-1 | `54d85ce60781543edd50fc1fa4adbbf4c27118e3` |
| SHA-256 | `ede450e3c9f6bdfc7de2fbda91eac908510f970a1e1e17bebb8fb9ecd1721342` |
| SHA3-384 | `2fc66919a38d2d42f3718cb0e63ece2dd2854d36d50d9266b9fbbaba7d632c93bf951885e993576f0ebe32ccf6197e58` |
| TLSH | `T134C622216BF88064F1FB6B78B9BD80A14A36BC658E26C01F0374395E18B1F54D9B6737` |
| SSDEEP | `196608:NnCtVYqI5MvbWEpKkqHIJqKxnCtVYqI5MvbWEpKkqNnCtVYqI5MvbWEpKkqrnCt9:NCXvI5MvHxTJPCXvI5MvHxiCXvI5MvHu` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_076_ede450e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ede450e3c9f6bdfc7de2fbda91eac908510f970a1e1e17bebb8fb9ecd1721342"
    family = "ConnectWise"
    file_name = "13beb.msi"
    file_type = "msi"
    first_seen = "2026-09-12 20:18:53"
  condition:
    hash.sha256(0, filesize) == "ede450e3c9f6bdfc7de2fbda91eac908510f970a1e1e17bebb8fb9ecd1721342"
}
```

### Sample 77: `893c62949e0430b6`

| Field | Value |
|---|---|
| SHA-256 | `893c62949e0430b65f75f2b28b565fa0b056dfc9dea24ae795577788fedac3f6` |
| Family label | `ConnectWise` |
| File name | `13b9c.msi` |
| File type | `msi` |
| First seen | `2026-09-12 20:18:37` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4130dba8286722da340cf32a5f46f2f2` |
| SHA-1 | `96ba79df9d326511c9347baa6c1b33c520f08801` |
| SHA-256 | `893c62949e0430b65f75f2b28b565fa0b056dfc9dea24ae795577788fedac3f6` |
| SHA3-384 | `cdd8badecbc2dd9545bd559455a425f4fc5cac198503d38674e802a53362fa033308bf8b99d1e8419fa5b829b0c07eec` |
| TLSH | `T13EA6233262ECCD69E1B30A76E97981B1597ABD248A22C05F4370780E3D71F5499B33B7` |
| SSDEEP | `196608:9U+sjdk64s9ooLj5TjuU+sjdk64s9KU+sjdk64s9tU+sjdk64s9:q+w4s9XLj5TT+w4s9L+w4s9a+w4s9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_077_893c6294
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "893c62949e0430b65f75f2b28b565fa0b056dfc9dea24ae795577788fedac3f6"
    family = "ConnectWise"
    file_name = "13b9c.msi"
    file_type = "msi"
    first_seen = "2026-09-12 20:18:37"
  condition:
    hash.sha256(0, filesize) == "893c62949e0430b65f75f2b28b565fa0b056dfc9dea24ae795577788fedac3f6"
}
```

### Sample 78: `ad69bdba7b5725e5`

| Field | Value |
|---|---|
| SHA-256 | `ad69bdba7b5725e5c5d63025f8625697aaa27e7b817eb1e57e7c7555e4bdfdcc` |
| Family label | `ConnectWise` |
| File name | `11e7f.msi` |
| File type | `msi` |
| First seen | `2026-09-12 20:18:24` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1963452c89a0e8ebe2d6b5aebb588d7a` |
| SHA-1 | `4a83e581286b86906f4367c853c6518ddf5ff0f8` |
| SHA-256 | `ad69bdba7b5725e5c5d63025f8625697aaa27e7b817eb1e57e7c7555e4bdfdcc` |
| SHA3-384 | `09bf39434b06b53768e1d7becbeeb84139e3629e7c14734be0bc6470f73c3a18856083160e05a5752d94d9133f3b2a68` |
| TLSH | `T132A623216BF88174F1FB2A78E97D80B14A36BC648A26C05F0774395E28B0F54D6B6737` |
| SSDEEP | `196608:knCtVYqI5MvbWEpKkqHIJqK5nCtVYqI5MvbWEpKkqdnCtVYqI5MvbWEpKkqWnCtO:wCXvI5MvHxrJXCXvI5MvHx6CXvI5MvHS` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_078_ad69bdba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad69bdba7b5725e5c5d63025f8625697aaa27e7b817eb1e57e7c7555e4bdfdcc"
    family = "ConnectWise"
    file_name = "11e7f.msi"
    file_type = "msi"
    first_seen = "2026-09-12 20:18:24"
  condition:
    hash.sha256(0, filesize) == "ad69bdba7b5725e5c5d63025f8625697aaa27e7b817eb1e57e7c7555e4bdfdcc"
}
```

### Sample 79: `5ac7b697d01dd223`

| Field | Value |
|---|---|
| SHA-256 | `5ac7b697d01dd22359ecfb4687b1e21ee09f3fe9aaca8e571565717ae8af3bd5` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.msi` |
| File type | `msi` |
| First seen | `2026-09-12 20:11:23` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d76e53a36bddf8e0757a7b96a7261c61` |
| SHA-1 | `577fe91fcd27b80be9ef30693dfb67f35bc080ce` |
| SHA-256 | `5ac7b697d01dd22359ecfb4687b1e21ee09f3fe9aaca8e571565717ae8af3bd5` |
| SHA3-384 | `47850b027902f663eaf8537e8a900ba352b0aef023fbe1f91e98e9a7865a99acceba28490f0e8d9f02941f24bbb9a18e` |
| TLSH | `T161E6233167FD1A14E1B32738ED3991F2913ABC658F22D55F2350786E68B4E40D6A233B` |
| SSDEEP | `196608:srnLYG3zDhukOLrnLYG3zErnLYG3z+rnLYG3zwrnLYG3zJrnLYG3zKrnLYG3zi:sbDDDgvLbDDEbDD+bDDwbDDJbDDKbDDi` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_079_5ac7b697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ac7b697d01dd22359ecfb4687b1e21ee09f3fe9aaca8e571565717ae8af3bd5"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-09-12 20:11:23"
  condition:
    hash.sha256(0, filesize) == "5ac7b697d01dd22359ecfb4687b1e21ee09f3fe9aaca8e571565717ae8af3bd5"
}
```

### Sample 80: `16e3ebf714f2526e`

| Field | Value |
|---|---|
| SHA-256 | `16e3ebf714f2526e68829ade831b9d5ed4be3b8f66550d0643cf4afdd6b48bc0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 19:36:58` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ae0af795b416645a9e43d9bfe49daa4` |
| SHA-256 | `16e3ebf714f2526e68829ade831b9d5ed4be3b8f66550d0643cf4afdd6b48bc0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_16e3ebf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16e3ebf714f2526e68829ade831b9d5ed4be3b8f66550d0643cf4afdd6b48bc0"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 19:36:58"
  condition:
    hash.sha256(0, filesize) == "16e3ebf714f2526e68829ade831b9d5ed4be3b8f66550d0643cf4afdd6b48bc0"
}
```

### Sample 81: `8814cb7416aba1d2`

| Field | Value |
|---|---|
| SHA-256 | `8814cb7416aba1d2469f8f9bdae51beb8d58f17dac28d260f00dcfe076ada40f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 19:36:39` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9e40f46f38de84c7f51cb154952d9f6` |
| SHA-256 | `8814cb7416aba1d2469f8f9bdae51beb8d58f17dac28d260f00dcfe076ada40f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_8814cb74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8814cb7416aba1d2469f8f9bdae51beb8d58f17dac28d260f00dcfe076ada40f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 19:36:39"
  condition:
    hash.sha256(0, filesize) == "8814cb7416aba1d2469f8f9bdae51beb8d58f17dac28d260f00dcfe076ada40f"
}
```

### Sample 82: `ad613fc80699e19b`

| Field | Value |
|---|---|
| SHA-256 | `ad613fc80699e19ba1c887056153c3f86ba100b6c1cd362635b60e8078da5a16` |
| Family label | `unknown` |
| File name | `tax-refund.apk` |
| File type | `apk` |
| First seen | `2026-09-12 19:15:32` |
| Reporter | `skocherhan` |
| Tags | `apk, gdfhlsf-s3-us-east-1-amazonaws-com, kong06-s3-us-east-1-amazonaws-com, poiwalsd-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbab133ebc17fc8285225b6452b493c6` |
| SHA-1 | `920cb4f3776eee46281befe1fc4a6a3c2b81f6ec` |
| SHA-256 | `ad613fc80699e19ba1c887056153c3f86ba100b6c1cd362635b60e8078da5a16` |
| SHA3-384 | `e59e5d24e09051e058eb68ab02a4232385e35355d9d45a34a3974be246e9c3293a6cfb09e0ad5f28e7e31012e6841d55` |
| TLSH | `T178A7339BFB88987AC0F3937154365721608B8D358B439BC79A68717C65F32C02F8A6DD` |
| SSDEEP | `786432:p0OqVuTexECIJ0ZWyO8HKm/OMHGjasBNWTzUEUtNlwLpo3gMg5nrxtPeghXrw6Qj:yRVTyCIJ0EOBIaYNWTpIwpvMgegRk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_ad613fc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad613fc80699e19ba1c887056153c3f86ba100b6c1cd362635b60e8078da5a16"
    family = "unknown"
    file_name = "tax-refund.apk"
    file_type = "apk"
    first_seen = "2026-09-12 19:15:32"
  condition:
    hash.sha256(0, filesize) == "ad613fc80699e19ba1c887056153c3f86ba100b6c1cd362635b60e8078da5a16"
}
```

### Sample 83: `84596497251e3847`

| Field | Value |
|---|---|
| SHA-256 | `84596497251e3847ce4389cb389a56fe87e08944474ffd4019ec315d306f449e` |
| Family label | `SalatStealer` |
| File name | `DiscordFix.exe` |
| File type | `exe` |
| First seen | `2026-09-12 18:45:57` |
| Reporter | `Alex_sev` |
| Tags | `exe, salat, salatstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75cfecbb3316ad279ac4e7fd6dadaa76` |
| SHA-1 | `1de1cb57d11bfdae49e04d78b17e8a3579af5f29` |
| SHA-256 | `84596497251e3847ce4389cb389a56fe87e08944474ffd4019ec315d306f449e` |
| SHA3-384 | `29a7d9dbac91a5a9203f553d4c95b6a7f5b45501b41a001a66034d4417b662d3ae78e72df93b64ca08386aca5b8d3522` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T15736E147BCD158B5D0AE92324A76A1627A71BC440F3223D73EA0B37C2F72BE05A75794` |
| SSDEEP | `98304:BVQJ6AbxQuImEkn6GMWUcYrveIvoaIda+rU4QP2+2LGvsMYQ:jLKOr5WUhptIda+A4J+GYsMYQ` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_083_84596497
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84596497251e3847ce4389cb389a56fe87e08944474ffd4019ec315d306f449e"
    family = "SalatStealer"
    file_name = "DiscordFix.exe"
    file_type = "exe"
    first_seen = "2026-09-12 18:45:57"
  condition:
    hash.sha256(0, filesize) == "84596497251e3847ce4389cb389a56fe87e08944474ffd4019ec315d306f449e"
}
```

### Sample 84: `2840fc2abb24a746`

| Field | Value |
|---|---|
| SHA-256 | `2840fc2abb24a746ea1edd7e828affad3a5a1f92dd91778fe2af7f23ed489f7c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 18:40:49` |
| Reporter | `Bitsight` |
| Tags | `B, BB3.file, dropped-by-GCleaner, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ce4f6ddda3998b385d90b3ee3987008` |
| SHA-1 | `7fc8442e0b3414d5a5b70367d63cb77340d722af` |
| SHA-256 | `2840fc2abb24a746ea1edd7e828affad3a5a1f92dd91778fe2af7f23ed489f7c` |
| SHA3-384 | `200d5da356b7ff0b4c0cc646747ed4f42c639d5d74f4b8fc3007979bd0387fee066a3dc18a4b8e3a3b54b4ca6bc44650` |
| IMPHASH | `9b763104e1c7e7b7334a1e9ed4235cd3` |
| TLSH | `T17C66C003BD5621E4C89ED6B5CA3A868A3B607C094B3223DB6F55BE349E31BD19C7D704` |
| SSDEEP | `98304:Smp5sk02EcQhwzwMNWJkHk4F/PpV3/nA+AY7K/MtujpWjNTpLK:Np02TQhw8GWeE4F/PpVPAeuEcjp2NlLK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_2840fc2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2840fc2abb24a746ea1edd7e828affad3a5a1f92dd91778fe2af7f23ed489f7c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 18:40:49"
  condition:
    hash.sha256(0, filesize) == "2840fc2abb24a746ea1edd7e828affad3a5a1f92dd91778fe2af7f23ed489f7c"
}
```

### Sample 85: `3d9a86801bebaf54`

| Field | Value |
|---|---|
| SHA-256 | `3d9a86801bebaf5495e8c024623215ad6984b4b8a0cc1268391d951eeab8c906` |
| Family label | `SalatStealer` |
| File name | `zapret-discord.bat` |
| File type | `bat` |
| First seen | `2026-09-12 18:40:28` |
| Reporter | `Alex_sev` |
| Tags | `bat, dropper, salat, salatstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2672295888575e831f4c18e3ddf1421b` |
| SHA-1 | `9b734df0425b65b3d5e44c283ea6fdb0bc3c9088` |
| SHA-256 | `3d9a86801bebaf5495e8c024623215ad6984b4b8a0cc1268391d951eeab8c906` |
| SHA3-384 | `49559640ca97e01e59fb970adec9192964f6d3a629b38de473115d815f710a061de4832c67aa16b31b469e0892671d59` |
| TLSH | `T13BD69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzz:k` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_085_3d9a8680
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d9a86801bebaf5495e8c024623215ad6984b4b8a0cc1268391d951eeab8c906"
    family = "SalatStealer"
    file_name = "zapret-discord.bat"
    file_type = "bat"
    first_seen = "2026-09-12 18:40:28"
  condition:
    hash.sha256(0, filesize) == "3d9a86801bebaf5495e8c024623215ad6984b4b8a0cc1268391d951eeab8c906"
}
```

### Sample 86: `24ba57c66610c95e`

| Field | Value |
|---|---|
| SHA-256 | `24ba57c66610c95e835d3eac5cce7bee48bae93da8b7505a433ea68760f741a0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 18:36:16` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6732a0bb9d7bff71120382097699404f` |
| SHA-256 | `24ba57c66610c95e835d3eac5cce7bee48bae93da8b7505a433ea68760f741a0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_24ba57c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24ba57c66610c95e835d3eac5cce7bee48bae93da8b7505a433ea68760f741a0"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 18:36:16"
  condition:
    hash.sha256(0, filesize) == "24ba57c66610c95e835d3eac5cce7bee48bae93da8b7505a433ea68760f741a0"
}
```

### Sample 87: `e94ba8f32e9047af`

| Field | Value |
|---|---|
| SHA-256 | `e94ba8f32e9047aff463736b999826271dafb73e9240b84cfb9fef46873440b2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 18:36:12` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e72a6e6ab2e58415fc178272de38f823` |
| SHA-256 | `e94ba8f32e9047aff463736b999826271dafb73e9240b84cfb9fef46873440b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_e94ba8f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e94ba8f32e9047aff463736b999826271dafb73e9240b84cfb9fef46873440b2"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 18:36:12"
  condition:
    hash.sha256(0, filesize) == "e94ba8f32e9047aff463736b999826271dafb73e9240b84cfb9fef46873440b2"
}
```

### Sample 88: `bf69929345b96342`

| Field | Value |
|---|---|
| SHA-256 | `bf69929345b9634292ae54c96ff18419eedd417950de87e83554b2483e8ae518` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 18:36:08` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76224ee1ae1961182884bf09327a9ba8` |
| SHA-256 | `bf69929345b9634292ae54c96ff18419eedd417950de87e83554b2483e8ae518` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_bf699293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf69929345b9634292ae54c96ff18419eedd417950de87e83554b2483e8ae518"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 18:36:08"
  condition:
    hash.sha256(0, filesize) == "bf69929345b9634292ae54c96ff18419eedd417950de87e83554b2483e8ae518"
}
```

### Sample 89: `64f14d7a3266e928`

| Field | Value |
|---|---|
| SHA-256 | `64f14d7a3266e928f94c682d48a14e8195a4b70ad4a75e1ead25ded18b5dfe81` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-12 18:33:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d19a80a72bb61997c7fda435893d1a8` |
| SHA-1 | `956615e22e19c175ce433e5ab8be92f5e3a3e379` |
| SHA-256 | `64f14d7a3266e928f94c682d48a14e8195a4b70ad4a75e1ead25ded18b5dfe81` |
| SHA3-384 | `f261fed014cb31f56b2304fb565e9521bfcee58534ccd75e9816f2e69a9ec31d2e0a3cf6734b03c94d152e17e1496da1` |
| TLSH | `T13CC27D956A867C44BEC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C15FACD618B1A` |
| SSDEEP | `768:H8vCB+25j6es8Rs9FYpMSUpi+20qUpi+20YQX:H8l25J6d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_64f14d7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64f14d7a3266e928f94c682d48a14e8195a4b70ad4a75e1ead25ded18b5dfe81"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 18:33:57"
  condition:
    hash.sha256(0, filesize) == "64f14d7a3266e928f94c682d48a14e8195a4b70ad4a75e1ead25ded18b5dfe81"
}
```

### Sample 90: `6786e4724fae275b`

| Field | Value |
|---|---|
| SHA-256 | `6786e4724fae275be1baa3ab4bcbc0f5c34bb6e1c5f16879876700f48c1454f9` |
| Family label | `unknown` |
| File name | `6786e4724fae275be1baa3ab4bcbc0f5c34bb6e1c5f16879876700f48c1454f9.bin` |
| File type | `unknown` |
| First seen | `2026-09-12 18:02:49` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d263c0831608bfd8c9e79d889eaa3ca3` |
| SHA-256 | `6786e4724fae275be1baa3ab4bcbc0f5c34bb6e1c5f16879876700f48c1454f9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_6786e472
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6786e4724fae275be1baa3ab4bcbc0f5c34bb6e1c5f16879876700f48c1454f9"
    family = "unknown"
    file_name = "6786e4724fae275be1baa3ab4bcbc0f5c34bb6e1c5f16879876700f48c1454f9.bin"
    file_type = "unknown"
    first_seen = "2026-09-12 18:02:49"
  condition:
    hash.sha256(0, filesize) == "6786e4724fae275be1baa3ab4bcbc0f5c34bb6e1c5f16879876700f48c1454f9"
}
```

### Sample 91: `4eb19048d5442ede`

| Field | Value |
|---|---|
| SHA-256 | `4eb19048d5442ede28d747f07496d5401462f36938963093b38b949187e4cb98` |
| Family label | `unknown` |
| File name | `4eb19048d5442ede28d747f07496d5401462f36938963093b38b949187e4cb98.bin` |
| File type | `unknown` |
| First seen | `2026-09-12 18:02:31` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a80975fc739540080f325f9f50de341` |
| SHA-256 | `4eb19048d5442ede28d747f07496d5401462f36938963093b38b949187e4cb98` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_4eb19048
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eb19048d5442ede28d747f07496d5401462f36938963093b38b949187e4cb98"
    family = "unknown"
    file_name = "4eb19048d5442ede28d747f07496d5401462f36938963093b38b949187e4cb98.bin"
    file_type = "unknown"
    first_seen = "2026-09-12 18:02:31"
  condition:
    hash.sha256(0, filesize) == "4eb19048d5442ede28d747f07496d5401462f36938963093b38b949187e4cb98"
}
```

### Sample 92: `e4452c248159c576`

| Field | Value |
|---|---|
| SHA-256 | `e4452c248159c57608a0cbf75cd795b5c597156725fab13b83bf3a9eaa467ea1` |
| Family label | `unknown` |
| File name | `setup_euone.bin` |
| File type | `exe` |
| First seen | `2026-09-12 17:52:05` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, GCleaner` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8638366e9bf35c54ea9dbbc8814c8b3f` |
| SHA-1 | `b052474a240bc3b03901b5d8333adb414d0af933` |
| SHA-256 | `e4452c248159c57608a0cbf75cd795b5c597156725fab13b83bf3a9eaa467ea1` |
| SHA3-384 | `a7e4e810d9e94a83a198da38355ab94945cb3d0eaa2db91dee6f214aa1e519b6905376fbf3d75b8a1cbf10b4575c351d` |
| IMPHASH | `ae39746b6bdd5748807aaa9387171a8b` |
| TLSH | `T1E424BF57B3E930F8D137867DC4911A41EB76B8350761ABEF03A047592F236D19E3AB22` |
| SSDEEP | `3072:Cx49x7UxcivtuwN8pPzl4gZuIs0OW6L5y6Nv5EWYmUMCkFTWcK02EWFZwOSvBDKV:cYCb0PzEIsj3NvGWYnZwO6BmwuAA/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_e4452c24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4452c248159c57608a0cbf75cd795b5c597156725fab13b83bf3a9eaa467ea1"
    family = "unknown"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-09-12 17:52:05"
  condition:
    hash.sha256(0, filesize) == "e4452c248159c57608a0cbf75cd795b5c597156725fab13b83bf3a9eaa467ea1"
}
```

### Sample 93: `5d43f472743ec596`

| Field | Value |
|---|---|
| SHA-256 | `5d43f472743ec596067f96a143e0058a8bd27b119f59e2705293334c21fd05f4` |
| Family label | `SnappyClient` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 17:22:33` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX7.file, SnappyClient` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72b4cbacd5e0f967cda3a9adfd04a136` |
| SHA-1 | `ca0114a1d5d941287431fd5f506b85df0b1d4a62` |
| SHA-256 | `5d43f472743ec596067f96a143e0058a8bd27b119f59e2705293334c21fd05f4` |
| SHA3-384 | `102817a200a820192af2be6722c8b27b3ca5de7665e8bb3ff9a34f10ab945723405a145735094deed662eee362a7d0a2` |
| IMPHASH | `20dd26497880c05caed9305b3c8b9109` |
| TLSH | `T1B6763383A2C30875F13C1D381CF488489E4AFCF905F5AE1B2DB5D48E95B9DEA6C3464A` |
| SSDEEP | `196608:flXGKkvo0dQC2kNbZtsvEAxSz/IluupkTKtwOFd:Nird9YvEQDl5QKKOb` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_093_5d43f472
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d43f472743ec596067f96a143e0058a8bd27b119f59e2705293334c21fd05f4"
    family = "SnappyClient"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 17:22:33"
  condition:
    hash.sha256(0, filesize) == "5d43f472743ec596067f96a143e0058a8bd27b119f59e2705293334c21fd05f4"
}
```

### Sample 94: `4f1bd5445453ff3d`

| Field | Value |
|---|---|
| SHA-256 | `4f1bd5445453ff3d2101666d5e1adcd77a2cb9ab0bdfb6d1c4f2529625ec4ac9` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-12 17:21:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e58b28e90d4171b951dfed52f6e059de` |
| SHA-1 | `37fddfa4a1e74bb0484c6793c3ed1667358f69b0` |
| SHA-256 | `4f1bd5445453ff3d2101666d5e1adcd77a2cb9ab0bdfb6d1c4f2529625ec4ac9` |
| SHA3-384 | `3f533d67b7edbe369a490cb822e0a342512a377d0a0700344c6f7c12137117bca3eec04c63493281e82b43dfcc5de458` |
| TLSH | `T14B236C6516857C14AA99C8375C7F2F0CB9AD43E6314492DE7ECA3CF28C4A6ACA20871D` |
| SSDEEP | `768:k99NyXsZztCB9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:8HusZvcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_4f1bd544
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f1bd5445453ff3d2101666d5e1adcd77a2cb9ab0bdfb6d1c4f2529625ec4ac9"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 17:21:56"
  condition:
    hash.sha256(0, filesize) == "4f1bd5445453ff3d2101666d5e1adcd77a2cb9ab0bdfb6d1c4f2529625ec4ac9"
}
```

### Sample 95: `e014dadf6d93b312`

| Field | Value |
|---|---|
| SHA-256 | `e014dadf6d93b312b93e2fc857791c241692da4015da7a24a4d42a946551add2` |
| Family label | `unknown` |
| File name | `aphp.exe` |
| File type | `exe` |
| First seen | `2026-09-12 17:15:33` |
| Reporter | `jeans` |
| Tags | `exe, PLC, S7Flip, Siemens` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdf8f8a09a04c3c2e1c0e75e4a21d7da` |
| SHA-1 | `355299da48c613a85783e662acd044e542ddf016` |
| SHA-256 | `e014dadf6d93b312b93e2fc857791c241692da4015da7a24a4d42a946551add2` |
| SHA3-384 | `fcd37a3802b5f4cc57a3ce0f1e05095810a7c3de043bdb943316dc2b3a93d92169cee0985a08a6622ceb602a38a198b4` |
| IMPHASH | `a285969101a563c6f30fc1c0f71c6d51` |
| TLSH | `T195D5F84369DB0DE9CDD677B861C76335A738FD318E295F2BA608C2212D536C4AE1EB40` |
| SSDEEP | `49152:MOKQm8qRmfFGJDKfJQebVuITn3dTOeBRpV+:yebptBRpV+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_e014dadf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e014dadf6d93b312b93e2fc857791c241692da4015da7a24a4d42a946551add2"
    family = "unknown"
    file_name = "aphp.exe"
    file_type = "exe"
    first_seen = "2026-09-12 17:15:33"
  condition:
    hash.sha256(0, filesize) == "e014dadf6d93b312b93e2fc857791c241692da4015da7a24a4d42a946551add2"
}
```

### Sample 96: `5834c911358884cf`

| Field | Value |
|---|---|
| SHA-256 | `5834c911358884cfa89a737e22cb7bde4d287aa47fc790d81b04f654fbd74450` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-12 17:09:56` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9276364fe166b18ce96790a90e99f170` |
| SHA-256 | `5834c911358884cfa89a737e22cb7bde4d287aa47fc790d81b04f654fbd74450` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_5834c911
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5834c911358884cfa89a737e22cb7bde4d287aa47fc790d81b04f654fbd74450"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 17:09:56"
  condition:
    hash.sha256(0, filesize) == "5834c911358884cfa89a737e22cb7bde4d287aa47fc790d81b04f654fbd74450"
}
```

### Sample 97: `0f2b408c28b3e36b`

| Field | Value |
|---|---|
| SHA-256 | `0f2b408c28b3e36b47c226b1a984606a9de5421d60c8e1ffd90e53da2ab69796` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-12 17:07:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de8267a6374396f9790cea73837b3f91` |
| SHA-1 | `9656a52adb7954f7f05eec180b2d7597e15bfa59` |
| SHA-256 | `0f2b408c28b3e36b47c226b1a984606a9de5421d60c8e1ffd90e53da2ab69796` |
| SHA3-384 | `75ce168eedd8a3730e6d108de13b1acfd74987089ee0d4b0a581493f027fae2b0e8afc39b1730a5aba58431fdb445e22` |
| TLSH | `T1C9C27D956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:a8vCB+25j6es8RX9FYpMSUpi+20qUpi+20YQX:a8l25Jxd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_0f2b408c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f2b408c28b3e36b47c226b1a984606a9de5421d60c8e1ffd90e53da2ab69796"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 17:07:56"
  condition:
    hash.sha256(0, filesize) == "0f2b408c28b3e36b47c226b1a984606a9de5421d60c8e1ffd90e53da2ab69796"
}
```

### Sample 98: `3d5018ba2ee3677c`

| Field | Value |
|---|---|
| SHA-256 | `3d5018ba2ee3677c6861959bb5ce1f2b0c896883c8618db1a0aa3b27d3369f10` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-12 17:03:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `442d99452d0231c1b955e605fad0ae6b` |
| SHA-1 | `71161969b2b0cd129818aa988084b0bb474d92ce` |
| SHA-256 | `3d5018ba2ee3677c6861959bb5ce1f2b0c896883c8618db1a0aa3b27d3369f10` |
| SHA3-384 | `84ae0758afec8312d1334d3fd690e299d822e33ac264d3b6f48a4528088735d7004c03fce37ace3fef248b738d53fc0c` |
| TLSH | `T160236C6516857C14AA99C4375C7F2F0CB9AD43E6314492EE7FCE3CF28C4A6ADA20871D` |
| SSDEEP | `768:0r9NyXsZztC49GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:yHusZgcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_3d5018ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d5018ba2ee3677c6861959bb5ce1f2b0c896883c8618db1a0aa3b27d3369f10"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 17:03:57"
  condition:
    hash.sha256(0, filesize) == "3d5018ba2ee3677c6861959bb5ce1f2b0c896883c8618db1a0aa3b27d3369f10"
}
```

### Sample 99: `9741e24cffbf4549`

| Field | Value |
|---|---|
| SHA-256 | `9741e24cffbf4549bf5f5d3aa20ee691c1bcb1b5fbe45274cee257b310c70257` |
| Family label | `unknown` |
| File name | `starter_c4f0b03c-12e6-499f-9a1d-439f7bddf6ef.dll` |
| File type | `exe` |
| First seen | `2026-09-12 16:58:27` |
| Reporter | `ffforward` |
| Tags | `dll, dotnet, dropped-by-wailsloader, exe, netdll, WailsLoader, websocket-rat, x64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0fdb40d42afdc880bec986cd6544f3e` |
| SHA-1 | `3b5c7c2a47dc4be1bf7126251441d24b72774075` |
| SHA-256 | `9741e24cffbf4549bf5f5d3aa20ee691c1bcb1b5fbe45274cee257b310c70257` |
| SHA3-384 | `858da8e41b74ec56e1bd43f466bac0cb54ad2075de9a74d18466c9b3a896faabcf3abb783c14917128a225baf3b49ad4` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T18C720B09BFE8441EF1FE87B91DB1852086B1FA0A5A72EF4D1DD528DD4C736818B107B5` |
| SSDEEP | `384:r3oJD3lG0vZ2qY1f431kyZYOxj6qG6vHKD8:EZXEzqBYv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_9741e24c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9741e24cffbf4549bf5f5d3aa20ee691c1bcb1b5fbe45274cee257b310c70257"
    family = "unknown"
    file_name = "starter_c4f0b03c-12e6-499f-9a1d-439f7bddf6ef.dll"
    file_type = "exe"
    first_seen = "2026-09-12 16:58:27"
  condition:
    hash.sha256(0, filesize) == "9741e24cffbf4549bf5f5d3aa20ee691c1bcb1b5fbe45274cee257b310c70257"
}
```

### Sample 100: `d1585ac714ef2f5b`

| Field | Value |
|---|---|
| SHA-256 | `d1585ac714ef2f5bd01e2a782c1442b188b5b0c5c068abc91ef484434bbbe8f6` |
| Family label | `unknown` |
| File name | `api.exe` |
| File type | `exe` |
| First seen | `2026-09-12 16:58:23` |
| Reporter | `ffforward` |
| Tags | `dropped-by-wailsloader, exe, lolbin-target, native-loader, WailsLoader, x64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9debefbcf7a77436bb62a9af5dd19bd` |
| SHA-1 | `325d0d64493d61375858ff812d61575ab3d5f9ae` |
| SHA-256 | `d1585ac714ef2f5bd01e2a782c1442b188b5b0c5c068abc91ef484434bbbe8f6` |
| SHA3-384 | `4ffb8a2d9b4f8d81f81f31e10691852c6ee12dcae9eb6f9433c5d8ba1d3d799aced4f5db5b87275f359da448d7ed3b41` |
| IMPHASH | `8d70e9948c196d328770a1903d8756c2` |
| TLSH | `T124C1842EF717246AE52AD27854EF4531B8A6781123704B3F53AAE4313C25A61943DA08` |
| SSDEEP | `96:40Epu8y86WaBQ7QtJqXrnHbBxApwv75hAVU:Uup861dq7nHtxiwv73Au` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_d1585ac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1585ac714ef2f5bd01e2a782c1442b188b5b0c5c068abc91ef484434bbbe8f6"
    family = "unknown"
    file_name = "api.exe"
    file_type = "exe"
    first_seen = "2026-09-12 16:58:23"
  condition:
    hash.sha256(0, filesize) == "d1585ac714ef2f5bd01e2a782c1442b188b5b0c5c068abc91ef484434bbbe8f6"
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
 * Generated: 2026-09-13T04:56:26.671435+00:00
 */

rule MalwareBazaar_unknown_001_5029424f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5029424f01c38be64318839ce1a7d95c84c7a2f0a42cbacafab71936576b76f2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-13 04:28:45"
  condition:
    hash.sha256(0, filesize) == "5029424f01c38be64318839ce1a7d95c84c7a2f0a42cbacafab71936576b76f2"
}

rule MalwareBazaar_unknown_002_045f86cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "045f86cbdd13e187fb76f1f90c20e972bfdb0cded22cc226e3d635b332eb732c"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 04:24:51"
  condition:
    hash.sha256(0, filesize) == "045f86cbdd13e187fb76f1f90c20e972bfdb0cded22cc226e3d635b332eb732c"
}

rule MalwareBazaar_Mirai_003_3461b097
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-13 04:18:47"
  condition:
    hash.sha256(0, filesize) == "3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc"
}

rule MalwareBazaar_unknown_004_abb52666
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb5266660f5a976deeb8b0c4b3f556e9969f8e99a67864a2afe08e3389fdc30"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-13 04:02:48"
  condition:
    hash.sha256(0, filesize) == "abb5266660f5a976deeb8b0c4b3f556e9969f8e99a67864a2afe08e3389fdc30"
}

rule MalwareBazaar_unknown_005_1f224b30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f224b30051a7347bbfc7f644cd7221ecf7ac2835fb725d7bd7d8660c880ff7c"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 04:00:55"
  condition:
    hash.sha256(0, filesize) == "1f224b30051a7347bbfc7f644cd7221ecf7ac2835fb725d7bd7d8660c880ff7c"
}

rule MalwareBazaar_unknown_006_5474e510
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5474e510e5adc3a0d708b8af25829ab68ce12934f56ae901ccff2e2f5a482c2b"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 03:54:44"
  condition:
    hash.sha256(0, filesize) == "5474e510e5adc3a0d708b8af25829ab68ce12934f56ae901ccff2e2f5a482c2b"
}

rule MalwareBazaar_unknown_007_48f7a0fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48f7a0fd3cb39a4a400a06331d73d74fe84817d8e6f2b7f34d853e61049a322c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-13 03:52:44"
  condition:
    hash.sha256(0, filesize) == "48f7a0fd3cb39a4a400a06331d73d74fe84817d8e6f2b7f34d853e61049a322c"
}

rule MalwareBazaar_unknown_008_c88eab2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c88eab2d3c72bf4b4e9a4605281e2369310698093079762f13317e58ae8dfcc2"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 03:37:48"
  condition:
    hash.sha256(0, filesize) == "c88eab2d3c72bf4b4e9a4605281e2369310698093079762f13317e58ae8dfcc2"
}

rule MalwareBazaar_unknown_009_52c06775
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52c06775e28c145b7ec96b7d7f2120bfc97c8d073f21d548d1a7c1aebfa5169b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-13 03:37:47"
  condition:
    hash.sha256(0, filesize) == "52c06775e28c145b7ec96b7d7f2120bfc97c8d073f21d548d1a7c1aebfa5169b"
}

rule MalwareBazaar_unknown_010_b54a9f76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b54a9f76aaa20aff72fd978bca433b67ca210e9466db9ddb32d448204beb705b"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-09-13 03:29:46"
  condition:
    hash.sha256(0, filesize) == "b54a9f76aaa20aff72fd978bca433b67ca210e9466db9ddb32d448204beb705b"
}

rule MalwareBazaar_unknown_011_6b700b6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b700b6ed41413e36dcffb50d8d9f0b082e8b2f514a123636ba715fde1bc7487"
    family = "unknown"
    file_name = "6b700b6ed41413e36dcffb50d8d9f0b082e8b2f514a123636ba715fde1bc7487.sh"
    file_type = "sh"
    first_seen = "2026-09-13 03:05:54"
  condition:
    hash.sha256(0, filesize) == "6b700b6ed41413e36dcffb50d8d9f0b082e8b2f514a123636ba715fde1bc7487"
}

rule MalwareBazaar_unknown_012_c60f6d4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c60f6d4b408ec8492546db16df6c2c8b5606413ff084138f87df1cc1a101f86d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 02:01:52"
  condition:
    hash.sha256(0, filesize) == "c60f6d4b408ec8492546db16df6c2c8b5606413ff084138f87df1cc1a101f86d"
}

rule MalwareBazaar_unknown_013_7fca62a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fca62a702cc28175ec0e16fc3fc5a33a6e3a0cd7871630af4ab97893903cb42"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 01:42:24"
  condition:
    hash.sha256(0, filesize) == "7fca62a702cc28175ec0e16fc3fc5a33a6e3a0cd7871630af4ab97893903cb42"
}

rule MalwareBazaar_unknown_014_72e26c56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72e26c564ae2f23fd7b3017e3df2debadc0592a17c9f379cc34c538d978978b9"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 01:42:02"
  condition:
    hash.sha256(0, filesize) == "72e26c564ae2f23fd7b3017e3df2debadc0592a17c9f379cc34c538d978978b9"
}

rule MalwareBazaar_unknown_015_565b155c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "565b155cdd681e0bcbde174a74ddb4dbe621001517b4665c37ccbf323c7c38e1"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-13 01:24:45"
  condition:
    hash.sha256(0, filesize) == "565b155cdd681e0bcbde174a74ddb4dbe621001517b4665c37ccbf323c7c38e1"
}

rule MalwareBazaar_unknown_016_5b73969e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b73969e4df42bd57becfd96fdc5ce13873c48995a19a877bf3030e1399fbf2c"
    family = "unknown"
    file_name = "5b73969e4df42bd57becfd96fdc5ce13873c48995a19a877bf3030e1399fbf2c"
    file_type = "sh"
    first_seen = "2026-09-13 01:10:53"
  condition:
    hash.sha256(0, filesize) == "5b73969e4df42bd57becfd96fdc5ce13873c48995a19a877bf3030e1399fbf2c"
}

rule MalwareBazaar_unknown_017_d3b0aac8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3b0aac81593144d230e0422f7d306809aa302f5b7bf9831d6a7dbe36fa9a94e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 00:40:05"
  condition:
    hash.sha256(0, filesize) == "d3b0aac81593144d230e0422f7d306809aa302f5b7bf9831d6a7dbe36fa9a94e"
}

rule MalwareBazaar_unknown_018_72d22964
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72d22964f41e704579302aaf0496a15bc3a3070832fbdb1c6e522b5d7ed329db"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 00:40:01"
  condition:
    hash.sha256(0, filesize) == "72d22964f41e704579302aaf0496a15bc3a3070832fbdb1c6e522b5d7ed329db"
}

rule MalwareBazaar_unknown_019_8d69e033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d69e03384fa3fc4aae31027ab7bfab539b9bbd4a7cff1bc63a3e749bfa670ea"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 00:39:44"
  condition:
    hash.sha256(0, filesize) == "8d69e03384fa3fc4aae31027ab7bfab539b9bbd4a7cff1bc63a3e749bfa670ea"
}

rule MalwareBazaar_ConnectWise_020_da9a78ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da9a78ac208ff90959b6fddbc7d64347fcaa9429a46cc4ed5ce1fa28d2a7e9f4"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:20:16"
  condition:
    hash.sha256(0, filesize) == "da9a78ac208ff90959b6fddbc7d64347fcaa9429a46cc4ed5ce1fa28d2a7e9f4"
}

rule MalwareBazaar_unknown_021_f7a54dcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7a54dccd317d4c7908ec453fb26df4db518e520b507dd3a69b2dc2d145bd588"
    family = "unknown"
    file_name = "f7a54dccd317d4c7908ec453fb26df4db518e520b507dd3a69b2dc2d145bd588.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:11:23"
  condition:
    hash.sha256(0, filesize) == "f7a54dccd317d4c7908ec453fb26df4db518e520b507dd3a69b2dc2d145bd588"
}

rule MalwareBazaar_unknown_022_ed7e5a6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed7e5a6a6d5435842166e8153501d120616aa851069677b3202a95f9158b8f90"
    family = "unknown"
    file_name = "ed7e5a6a6d5435842166e8153501d120616aa851069677b3202a95f9158b8f90.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:11:06"
  condition:
    hash.sha256(0, filesize) == "ed7e5a6a6d5435842166e8153501d120616aa851069677b3202a95f9158b8f90"
}

rule MalwareBazaar_unknown_023_d0738acb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0738acb402e1949f5c7ac6a70070be3f2ae43b1282fba315714b7209ca3ba25"
    family = "unknown"
    file_name = "d0738acb402e1949f5c7ac6a70070be3f2ae43b1282fba315714b7209ca3ba25.bin"
    file_type = "php"
    first_seen = "2026-09-13 00:10:49"
  condition:
    hash.sha256(0, filesize) == "d0738acb402e1949f5c7ac6a70070be3f2ae43b1282fba315714b7209ca3ba25"
}

rule MalwareBazaar_unknown_024_bbcb1063
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbcb1063b9730907b2c47910eeff1b7c8d0c02e272c77444c1a91e3532672cfa"
    family = "unknown"
    file_name = "bbcb1063b9730907b2c47910eeff1b7c8d0c02e272c77444c1a91e3532672cfa.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:10:32"
  condition:
    hash.sha256(0, filesize) == "bbcb1063b9730907b2c47910eeff1b7c8d0c02e272c77444c1a91e3532672cfa"
}

rule MalwareBazaar_unknown_025_a84517ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a84517ac01ee61f1f980508f4a66b0c8bc12c05d7c8190fef2033c23232628c3"
    family = "unknown"
    file_name = "a84517ac01ee61f1f980508f4a66b0c8bc12c05d7c8190fef2033c23232628c3.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:10:14"
  condition:
    hash.sha256(0, filesize) == "a84517ac01ee61f1f980508f4a66b0c8bc12c05d7c8190fef2033c23232628c3"
}

rule MalwareBazaar_unknown_026_73a80d9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73a80d9f0b26a8ae1785972a4febee9df8bb95969aa256bc817a1665d5aef6d4"
    family = "unknown"
    file_name = "73a80d9f0b26a8ae1785972a4febee9df8bb95969aa256bc817a1665d5aef6d4.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:09:57"
  condition:
    hash.sha256(0, filesize) == "73a80d9f0b26a8ae1785972a4febee9df8bb95969aa256bc817a1665d5aef6d4"
}

rule MalwareBazaar_ConnectWise_027_32f024ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f024ff47848ef46530822aa5f8e78d5dfc07d61c9402c98eb0b27219235567"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup(4).msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:09:49"
  condition:
    hash.sha256(0, filesize) == "32f024ff47848ef46530822aa5f8e78d5dfc07d61c9402c98eb0b27219235567"
}

rule MalwareBazaar_unknown_028_3777ea8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3777ea8f92b3bc5af807bf7ebf26010dd361e23d521fcc88db2b19240f4cc9e3"
    family = "unknown"
    file_name = "3777ea8f92b3bc5af807bf7ebf26010dd361e23d521fcc88db2b19240f4cc9e3.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:09:40"
  condition:
    hash.sha256(0, filesize) == "3777ea8f92b3bc5af807bf7ebf26010dd361e23d521fcc88db2b19240f4cc9e3"
}

rule MalwareBazaar_ConnectWise_029_a3bf0525
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3bf052506056f37844e5677b56bf3aa841473e68567228be048c7aa11590888"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup(3).msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:09:33"
  condition:
    hash.sha256(0, filesize) == "a3bf052506056f37844e5677b56bf3aa841473e68567228be048c7aa11590888"
}

rule MalwareBazaar_unknown_030_37302e86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37302e86fb20394354731dec8fb0c67a2b1714acce952be888cca052befbb368"
    family = "unknown"
    file_name = "37302e86fb20394354731dec8fb0c67a2b1714acce952be888cca052befbb368.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:09:22"
  condition:
    hash.sha256(0, filesize) == "37302e86fb20394354731dec8fb0c67a2b1714acce952be888cca052befbb368"
}

rule MalwareBazaar_ConnectWise_031_18234cb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18234cb137f84dfceedc95e81c66fdfcb2f7ceaddfdda8c2a861d92834fc26d0"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup(2).msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:09:17"
  condition:
    hash.sha256(0, filesize) == "18234cb137f84dfceedc95e81c66fdfcb2f7ceaddfdda8c2a861d92834fc26d0"
}

rule MalwareBazaar_unknown_032_180975de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "180975de9c76759efb2e77992c44ac40b5534852ba63eb365dc6f520dc693b7d"
    family = "unknown"
    file_name = "180975de9c76759efb2e77992c44ac40b5534852ba63eb365dc6f520dc693b7d.bin"
    file_type = "unknown"
    first_seen = "2026-09-13 00:09:05"
  condition:
    hash.sha256(0, filesize) == "180975de9c76759efb2e77992c44ac40b5534852ba63eb365dc6f520dc693b7d"
}

rule MalwareBazaar_ConnectWise_033_c780e430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c780e43077af07e993c957ea6509d473d448d25b144584f18e5bc62e9d408c5c"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup(1).msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:09:03"
  condition:
    hash.sha256(0, filesize) == "c780e43077af07e993c957ea6509d473d448d25b144584f18e5bc62e9d408c5c"
}

rule MalwareBazaar_ConnectWise_034_014afe69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "014afe690cdbc0ca84216a6c241f413e10f92cae8c87e885304ffed0989024a0"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-09-13 00:08:48"
  condition:
    hash.sha256(0, filesize) == "014afe690cdbc0ca84216a6c241f413e10f92cae8c87e885304ffed0989024a0"
}

rule MalwareBazaar_unknown_035_e6a8250c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6a8250c008318c3a1339942bd24668965be86d33488bc754df8ad938825caaf"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-13 00:02:01"
  condition:
    hash.sha256(0, filesize) == "e6a8250c008318c3a1339942bd24668965be86d33488bc754df8ad938825caaf"
}

rule MalwareBazaar_unknown_036_63ca3b10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63ca3b10fcbb63879ff42dd7bc35a1373c980198ffafb375350b113976948420"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 00:01:32"
  condition:
    hash.sha256(0, filesize) == "63ca3b10fcbb63879ff42dd7bc35a1373c980198ffafb375350b113976948420"
}

rule MalwareBazaar_unknown_037_b6b745cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6b745cb96ec0560f9dfd52bec4d9d16a6ecf63713a8ea36e5bb6d55a3d6594a"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-13 00:00:30"
  condition:
    hash.sha256(0, filesize) == "b6b745cb96ec0560f9dfd52bec4d9d16a6ecf63713a8ea36e5bb6d55a3d6594a"
}

rule MalwareBazaar_unknown_038_8fd1afe6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fd1afe6505f6d48c7d52f65098a40216d46a97fce1f7534cdda5b3f40144d94"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 23:39:23"
  condition:
    hash.sha256(0, filesize) == "8fd1afe6505f6d48c7d52f65098a40216d46a97fce1f7534cdda5b3f40144d94"
}

rule MalwareBazaar_unknown_039_bdb8567c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdb8567cfe7d8789ddb37e4faa584a3221411e8d9f603c0f943bafe6bcafe3b7"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 23:02:46"
  condition:
    hash.sha256(0, filesize) == "bdb8567cfe7d8789ddb37e4faa584a3221411e8d9f603c0f943bafe6bcafe3b7"
}

rule MalwareBazaar_unknown_040_3590eb0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3590eb0fe1ea587258592d3a3db69e363f59cbfe5c1447810135ce5106c7df46"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 22:47:47"
  condition:
    hash.sha256(0, filesize) == "3590eb0fe1ea587258592d3a3db69e363f59cbfe5c1447810135ce5106c7df46"
}

rule MalwareBazaar_unknown_041_e92ea716
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e92ea71674c6fe0911ba61d8bf404ef875a93d2ee18ec4445f8c07f5bcd49412"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 22:40:49"
  condition:
    hash.sha256(0, filesize) == "e92ea71674c6fe0911ba61d8bf404ef875a93d2ee18ec4445f8c07f5bcd49412"
}

rule MalwareBazaar_unknown_042_704a33c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "704a33c176e3a63a2a60811683cbf9ef7c60b6befd1d95b02c4e67c2924eec51"
    family = "unknown"
    file_name = "SecuriteInfo.com.Python.Stealer.4925.5889.9280"
    file_type = "exe"
    first_seen = "2026-09-12 22:34:36"
  condition:
    hash.sha256(0, filesize) == "704a33c176e3a63a2a60811683cbf9ef7c60b6befd1d95b02c4e67c2924eec51"
}

rule MalwareBazaar_unknown_043_34d7cf72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34d7cf7269c8898978c35a3963f76cf09466b5ab8695d16d7184ddbe587a681b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 22:26:49"
  condition:
    hash.sha256(0, filesize) == "34d7cf7269c8898978c35a3963f76cf09466b5ab8695d16d7184ddbe587a681b"
}

rule MalwareBazaar_unknown_044_b23943dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b23943dc5ab42e339bbc5a83bb1fa95b2bae70e7b00a8070d0de489ba9731b7b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:22:20"
  condition:
    hash.sha256(0, filesize) == "b23943dc5ab42e339bbc5a83bb1fa95b2bae70e7b00a8070d0de489ba9731b7b"
}

rule MalwareBazaar_unknown_045_837f3b41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "837f3b41488599ff02ffc32a795c073a32143349088c97f786b910c0cbe46503"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:21:00"
  condition:
    hash.sha256(0, filesize) == "837f3b41488599ff02ffc32a795c073a32143349088c97f786b910c0cbe46503"
}

rule MalwareBazaar_unknown_046_5462d033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5462d0338800b440fec5b6a6133cd943c9ef5c05883859c70fbd5326a8e54ccc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:20:27"
  condition:
    hash.sha256(0, filesize) == "5462d0338800b440fec5b6a6133cd943c9ef5c05883859c70fbd5326a8e54ccc"
}

rule MalwareBazaar_unknown_047_02c7d7ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02c7d7ffc279d2d791fac163ce8252bfb9f4fff406266fb69a4d381ab6e315e4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:17:22"
  condition:
    hash.sha256(0, filesize) == "02c7d7ffc279d2d791fac163ce8252bfb9f4fff406266fb69a4d381ab6e315e4"
}

rule MalwareBazaar_unknown_048_7ec862ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ec862eeff86921c9f7c591820ca0780576d6ce13f4ddc1e690cc8342e0145cc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:15:40"
  condition:
    hash.sha256(0, filesize) == "7ec862eeff86921c9f7c591820ca0780576d6ce13f4ddc1e690cc8342e0145cc"
}

rule MalwareBazaar_unknown_049_2bca57bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bca57bf92ff112d5e3f30563f235084a415921972598a6400e8f30eb28bd16f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 22:12:48"
  condition:
    hash.sha256(0, filesize) == "2bca57bf92ff112d5e3f30563f235084a415921972598a6400e8f30eb28bd16f"
}

rule MalwareBazaar_unknown_050_a8c4128d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8c4128d95766a9ba9050fae86efbfdc177d1bff75d77f1a51321216ffc7d8be"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 22:08:47"
  condition:
    hash.sha256(0, filesize) == "a8c4128d95766a9ba9050fae86efbfdc177d1bff75d77f1a51321216ffc7d8be"
}

rule MalwareBazaar_unknown_051_63d87d45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63d87d4569a491553e14757dc267aa29ae8b606b0396dd16acc5c642f629fc7e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:05:29"
  condition:
    hash.sha256(0, filesize) == "63d87d4569a491553e14757dc267aa29ae8b606b0396dd16acc5c642f629fc7e"
}

rule MalwareBazaar_unknown_052_14bc3a77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14bc3a778e14a6eef9eaec220b8902af61f153efef037280a7ce21af47ddfc3f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:02:49"
  condition:
    hash.sha256(0, filesize) == "14bc3a778e14a6eef9eaec220b8902af61f153efef037280a7ce21af47ddfc3f"
}

rule MalwareBazaar_unknown_053_d019021b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d019021b688b5589ad8a45fe2541967649b2cd9c89fdd49074c844f518887fff"
    family = "unknown"
    file_name = "vicelocity_sample.exe"
    file_type = "exe"
    first_seen = "2026-09-12 22:01:08"
  condition:
    hash.sha256(0, filesize) == "d019021b688b5589ad8a45fe2541967649b2cd9c89fdd49074c844f518887fff"
}

rule MalwareBazaar_unknown_054_48139ce0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48139ce0c5abb601cca6a634ef33579b63c3cc109cc3aa7439c6d2e415e4b504"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 22:01:04"
  condition:
    hash.sha256(0, filesize) == "48139ce0c5abb601cca6a634ef33579b63c3cc109cc3aa7439c6d2e415e4b504"
}

rule MalwareBazaar_unknown_055_47965b10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47965b1026efde3f30153e881ce0a2ea62ff6191ec5341cb1695fff051cdfb6c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 21:47:52"
  condition:
    hash.sha256(0, filesize) == "47965b1026efde3f30153e881ce0a2ea62ff6191ec5341cb1695fff051cdfb6c"
}

rule MalwareBazaar_unknown_056_e71834bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e71834bb6b4728689510701d2e58443a1e675d7cef2fc47dea6fa3c690f4c38b"
    family = "unknown"
    file_name = "COPIA_DE_TRANSACCION_EKNFW5CD.svg_b.svg.zip"
    file_type = "zip"
    first_seen = "2026-09-12 21:45:53"
  condition:
    hash.sha256(0, filesize) == "e71834bb6b4728689510701d2e58443a1e675d7cef2fc47dea6fa3c690f4c38b"
}

rule MalwareBazaar_DDoSAgent_057_00f2bc34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00f2bc3455fbb1aaa20a7c892357b3610fd2c099d408e9f8743e4d6627d1607c"
    family = "DDoSAgent"
    file_name = "bot_client_mipsle"
    file_type = "elf"
    first_seen = "2026-09-12 21:43:05"
  condition:
    hash.sha256(0, filesize) == "00f2bc3455fbb1aaa20a7c892357b3610fd2c099d408e9f8743e4d6627d1607c"
}

rule MalwareBazaar_DDoSAgent_058_af40e385
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af40e385ad62e939c3bfa7f38884f49c69b04d35da630213aa22e2d2f82f92e4"
    family = "DDoSAgent"
    file_name = "bot_client_mips"
    file_type = "elf"
    first_seen = "2026-09-12 21:43:03"
  condition:
    hash.sha256(0, filesize) == "af40e385ad62e939c3bfa7f38884f49c69b04d35da630213aa22e2d2f82f92e4"
}

rule MalwareBazaar_DDoSAgent_059_51a3af22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51a3af22bcd96f85e9158d29078850ea3f06742a8f2279c14526b97c713c2614"
    family = "DDoSAgent"
    file_name = "bot_client_mips64le"
    file_type = "elf"
    first_seen = "2026-09-12 21:43:02"
  condition:
    hash.sha256(0, filesize) == "51a3af22bcd96f85e9158d29078850ea3f06742a8f2279c14526b97c713c2614"
}

rule MalwareBazaar_unknown_060_5bf715c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bf715c1088adf216db2c1470d7e88d98cbcb25e00a4ce3513dacbaeb3be3953"
    family = "unknown"
    file_name = "bot_client_arm"
    file_type = "elf"
    first_seen = "2026-09-12 21:43:00"
  condition:
    hash.sha256(0, filesize) == "5bf715c1088adf216db2c1470d7e88d98cbcb25e00a4ce3513dacbaeb3be3953"
}

rule MalwareBazaar_DDoSAgent_061_48caea2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48caea2d6482c7d2b0b97a05bca70ab87a8d9347f3f888e9984ea5cbf99d82f3"
    family = "DDoSAgent"
    file_name = "bot_client_x86_64"
    file_type = "elf"
    first_seen = "2026-09-12 21:42:58"
  condition:
    hash.sha256(0, filesize) == "48caea2d6482c7d2b0b97a05bca70ab87a8d9347f3f888e9984ea5cbf99d82f3"
}

rule MalwareBazaar_DDoSAgent_062_4315615b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4315615b2f9e700018303979a1b9d7ab6cdce3be5360bd3a29f0d7d3e349ffdc"
    family = "DDoSAgent"
    file_name = "bot_client_mips64"
    file_type = "elf"
    first_seen = "2026-09-12 21:42:56"
  condition:
    hash.sha256(0, filesize) == "4315615b2f9e700018303979a1b9d7ab6cdce3be5360bd3a29f0d7d3e349ffdc"
}

rule MalwareBazaar_unknown_063_c979ad4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c979ad4c75cdf793fea7e600974d8bc2422260b31b5ed19e00cf6d9fea7ab552"
    family = "unknown"
    file_name = "bot_client_arm64"
    file_type = "elf"
    first_seen = "2026-09-12 21:42:54"
  condition:
    hash.sha256(0, filesize) == "c979ad4c75cdf793fea7e600974d8bc2422260b31b5ed19e00cf6d9fea7ab552"
}

rule MalwareBazaar_DDoSAgent_064_dc689e89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc689e89652ccb9f54599e9403a8d610fe5603c3ec65a10249fb4ab78b79cb1e"
    family = "DDoSAgent"
    file_name = "bot_client_amd64"
    file_type = "elf"
    first_seen = "2026-09-12 21:42:53"
  condition:
    hash.sha256(0, filesize) == "dc689e89652ccb9f54599e9403a8d610fe5603c3ec65a10249fb4ab78b79cb1e"
}

rule MalwareBazaar_unknown_065_821928cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "821928cd116782950ebaa535aef8f3ad40f1ee6fbda9a8b04e7bf92caf771814"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 21:38:50"
  condition:
    hash.sha256(0, filesize) == "821928cd116782950ebaa535aef8f3ad40f1ee6fbda9a8b04e7bf92caf771814"
}

rule MalwareBazaar_unknown_066_773a11af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "773a11af4eda847418827c4f17c97a56b98662f80b45c58c9cd3d99e0cb20016"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 21:38:07"
  condition:
    hash.sha256(0, filesize) == "773a11af4eda847418827c4f17c97a56b98662f80b45c58c9cd3d99e0cb20016"
}

rule MalwareBazaar_unknown_067_b23e89bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b23e89bd49361d2c5f98eac947e86d08d1002469e46908216c2ac5960f1abeeb"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 21:37:57"
  condition:
    hash.sha256(0, filesize) == "b23e89bd49361d2c5f98eac947e86d08d1002469e46908216c2ac5960f1abeeb"
}

rule MalwareBazaar_unknown_068_9f93d7a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f93d7a9fc452e1b4514bfd4e231febd7b4005740a592cefbc9e94ec29584664"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 21:36:50"
  condition:
    hash.sha256(0, filesize) == "9f93d7a9fc452e1b4514bfd4e231febd7b4005740a592cefbc9e94ec29584664"
}

rule MalwareBazaar_unknown_069_90e2c6ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90e2c6ef2062148c89b4b66d3cfbf75012a273ff9ec5bc1a6a88215ac4b340fd"
    family = "unknown"
    file_name = "90e2c6ef2062148c89b4b66d3cfbf75012a273ff9ec5bc1a6a88215ac4b340fd.bin"
    file_type = "exe"
    first_seen = "2026-09-12 20:54:24"
  condition:
    hash.sha256(0, filesize) == "90e2c6ef2062148c89b4b66d3cfbf75012a273ff9ec5bc1a6a88215ac4b340fd"
}

rule MalwareBazaar_unknown_070_89ea7049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89ea7049eae2af35ebbd64531a11d50f9364992db0dc8960b8961551289779cd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 20:44:57"
  condition:
    hash.sha256(0, filesize) == "89ea7049eae2af35ebbd64531a11d50f9364992db0dc8960b8961551289779cd"
}

rule MalwareBazaar_unknown_071_de957022
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de957022f833e299f66364722daf215791413c7d70be4a8c97ad8edd5206110e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 20:37:32"
  condition:
    hash.sha256(0, filesize) == "de957022f833e299f66364722daf215791413c7d70be4a8c97ad8edd5206110e"
}

rule MalwareBazaar_unknown_072_605d219f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "605d219f115457c4825d787d4d7c6d1b56503b36c4e2eabd29d67b160a34249e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 20:37:27"
  condition:
    hash.sha256(0, filesize) == "605d219f115457c4825d787d4d7c6d1b56503b36c4e2eabd29d67b160a34249e"
}

rule MalwareBazaar_unknown_073_dc5378ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc5378ee70625061263a7550e6ea6524ee99e98d8ae92755097aeba8a14adb14"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 20:37:23"
  condition:
    hash.sha256(0, filesize) == "dc5378ee70625061263a7550e6ea6524ee99e98d8ae92755097aeba8a14adb14"
}

rule MalwareBazaar_unknown_074_c5acc4bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5acc4bcc957fb7e0e3bc000a5c391f4122a4d5a59644fd8d39673aaf7c41956"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 20:37:19"
  condition:
    hash.sha256(0, filesize) == "c5acc4bcc957fb7e0e3bc000a5c391f4122a4d5a59644fd8d39673aaf7c41956"
}

rule MalwareBazaar_ConnectWise_075_434ffec8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "434ffec81e6c1be4873754fa5854fd6c5b3d387a4b9f2119a7bfec8bbe181d9f"
    family = "ConnectWise"
    file_name = "472922.msi"
    file_type = "msi"
    first_seen = "2026-09-12 20:22:23"
  condition:
    hash.sha256(0, filesize) == "434ffec81e6c1be4873754fa5854fd6c5b3d387a4b9f2119a7bfec8bbe181d9f"
}

rule MalwareBazaar_ConnectWise_076_ede450e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ede450e3c9f6bdfc7de2fbda91eac908510f970a1e1e17bebb8fb9ecd1721342"
    family = "ConnectWise"
    file_name = "13beb.msi"
    file_type = "msi"
    first_seen = "2026-09-12 20:18:53"
  condition:
    hash.sha256(0, filesize) == "ede450e3c9f6bdfc7de2fbda91eac908510f970a1e1e17bebb8fb9ecd1721342"
}

rule MalwareBazaar_ConnectWise_077_893c6294
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "893c62949e0430b65f75f2b28b565fa0b056dfc9dea24ae795577788fedac3f6"
    family = "ConnectWise"
    file_name = "13b9c.msi"
    file_type = "msi"
    first_seen = "2026-09-12 20:18:37"
  condition:
    hash.sha256(0, filesize) == "893c62949e0430b65f75f2b28b565fa0b056dfc9dea24ae795577788fedac3f6"
}

rule MalwareBazaar_ConnectWise_078_ad69bdba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad69bdba7b5725e5c5d63025f8625697aaa27e7b817eb1e57e7c7555e4bdfdcc"
    family = "ConnectWise"
    file_name = "11e7f.msi"
    file_type = "msi"
    first_seen = "2026-09-12 20:18:24"
  condition:
    hash.sha256(0, filesize) == "ad69bdba7b5725e5c5d63025f8625697aaa27e7b817eb1e57e7c7555e4bdfdcc"
}

rule MalwareBazaar_ConnectWise_079_5ac7b697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ac7b697d01dd22359ecfb4687b1e21ee09f3fe9aaca8e571565717ae8af3bd5"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-09-12 20:11:23"
  condition:
    hash.sha256(0, filesize) == "5ac7b697d01dd22359ecfb4687b1e21ee09f3fe9aaca8e571565717ae8af3bd5"
}

rule MalwareBazaar_unknown_080_16e3ebf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16e3ebf714f2526e68829ade831b9d5ed4be3b8f66550d0643cf4afdd6b48bc0"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 19:36:58"
  condition:
    hash.sha256(0, filesize) == "16e3ebf714f2526e68829ade831b9d5ed4be3b8f66550d0643cf4afdd6b48bc0"
}

rule MalwareBazaar_unknown_081_8814cb74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8814cb7416aba1d2469f8f9bdae51beb8d58f17dac28d260f00dcfe076ada40f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 19:36:39"
  condition:
    hash.sha256(0, filesize) == "8814cb7416aba1d2469f8f9bdae51beb8d58f17dac28d260f00dcfe076ada40f"
}

rule MalwareBazaar_unknown_082_ad613fc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad613fc80699e19ba1c887056153c3f86ba100b6c1cd362635b60e8078da5a16"
    family = "unknown"
    file_name = "tax-refund.apk"
    file_type = "apk"
    first_seen = "2026-09-12 19:15:32"
  condition:
    hash.sha256(0, filesize) == "ad613fc80699e19ba1c887056153c3f86ba100b6c1cd362635b60e8078da5a16"
}

rule MalwareBazaar_SalatStealer_083_84596497
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84596497251e3847ce4389cb389a56fe87e08944474ffd4019ec315d306f449e"
    family = "SalatStealer"
    file_name = "DiscordFix.exe"
    file_type = "exe"
    first_seen = "2026-09-12 18:45:57"
  condition:
    hash.sha256(0, filesize) == "84596497251e3847ce4389cb389a56fe87e08944474ffd4019ec315d306f449e"
}

rule MalwareBazaar_unknown_084_2840fc2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2840fc2abb24a746ea1edd7e828affad3a5a1f92dd91778fe2af7f23ed489f7c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 18:40:49"
  condition:
    hash.sha256(0, filesize) == "2840fc2abb24a746ea1edd7e828affad3a5a1f92dd91778fe2af7f23ed489f7c"
}

rule MalwareBazaar_SalatStealer_085_3d9a8680
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d9a86801bebaf5495e8c024623215ad6984b4b8a0cc1268391d951eeab8c906"
    family = "SalatStealer"
    file_name = "zapret-discord.bat"
    file_type = "bat"
    first_seen = "2026-09-12 18:40:28"
  condition:
    hash.sha256(0, filesize) == "3d9a86801bebaf5495e8c024623215ad6984b4b8a0cc1268391d951eeab8c906"
}

rule MalwareBazaar_unknown_086_24ba57c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24ba57c66610c95e835d3eac5cce7bee48bae93da8b7505a433ea68760f741a0"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 18:36:16"
  condition:
    hash.sha256(0, filesize) == "24ba57c66610c95e835d3eac5cce7bee48bae93da8b7505a433ea68760f741a0"
}

rule MalwareBazaar_unknown_087_e94ba8f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e94ba8f32e9047aff463736b999826271dafb73e9240b84cfb9fef46873440b2"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 18:36:12"
  condition:
    hash.sha256(0, filesize) == "e94ba8f32e9047aff463736b999826271dafb73e9240b84cfb9fef46873440b2"
}

rule MalwareBazaar_unknown_088_bf699293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf69929345b9634292ae54c96ff18419eedd417950de87e83554b2483e8ae518"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 18:36:08"
  condition:
    hash.sha256(0, filesize) == "bf69929345b9634292ae54c96ff18419eedd417950de87e83554b2483e8ae518"
}

rule MalwareBazaar_unknown_089_64f14d7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64f14d7a3266e928f94c682d48a14e8195a4b70ad4a75e1ead25ded18b5dfe81"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 18:33:57"
  condition:
    hash.sha256(0, filesize) == "64f14d7a3266e928f94c682d48a14e8195a4b70ad4a75e1ead25ded18b5dfe81"
}

rule MalwareBazaar_unknown_090_6786e472
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6786e4724fae275be1baa3ab4bcbc0f5c34bb6e1c5f16879876700f48c1454f9"
    family = "unknown"
    file_name = "6786e4724fae275be1baa3ab4bcbc0f5c34bb6e1c5f16879876700f48c1454f9.bin"
    file_type = "unknown"
    first_seen = "2026-09-12 18:02:49"
  condition:
    hash.sha256(0, filesize) == "6786e4724fae275be1baa3ab4bcbc0f5c34bb6e1c5f16879876700f48c1454f9"
}

rule MalwareBazaar_unknown_091_4eb19048
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eb19048d5442ede28d747f07496d5401462f36938963093b38b949187e4cb98"
    family = "unknown"
    file_name = "4eb19048d5442ede28d747f07496d5401462f36938963093b38b949187e4cb98.bin"
    file_type = "unknown"
    first_seen = "2026-09-12 18:02:31"
  condition:
    hash.sha256(0, filesize) == "4eb19048d5442ede28d747f07496d5401462f36938963093b38b949187e4cb98"
}

rule MalwareBazaar_unknown_092_e4452c24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4452c248159c57608a0cbf75cd795b5c597156725fab13b83bf3a9eaa467ea1"
    family = "unknown"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-09-12 17:52:05"
  condition:
    hash.sha256(0, filesize) == "e4452c248159c57608a0cbf75cd795b5c597156725fab13b83bf3a9eaa467ea1"
}

rule MalwareBazaar_SnappyClient_093_5d43f472
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d43f472743ec596067f96a143e0058a8bd27b119f59e2705293334c21fd05f4"
    family = "SnappyClient"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 17:22:33"
  condition:
    hash.sha256(0, filesize) == "5d43f472743ec596067f96a143e0058a8bd27b119f59e2705293334c21fd05f4"
}

rule MalwareBazaar_unknown_094_4f1bd544
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f1bd5445453ff3d2101666d5e1adcd77a2cb9ab0bdfb6d1c4f2529625ec4ac9"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 17:21:56"
  condition:
    hash.sha256(0, filesize) == "4f1bd5445453ff3d2101666d5e1adcd77a2cb9ab0bdfb6d1c4f2529625ec4ac9"
}

rule MalwareBazaar_unknown_095_e014dadf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e014dadf6d93b312b93e2fc857791c241692da4015da7a24a4d42a946551add2"
    family = "unknown"
    file_name = "aphp.exe"
    file_type = "exe"
    first_seen = "2026-09-12 17:15:33"
  condition:
    hash.sha256(0, filesize) == "e014dadf6d93b312b93e2fc857791c241692da4015da7a24a4d42a946551add2"
}

rule MalwareBazaar_unknown_096_5834c911
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5834c911358884cfa89a737e22cb7bde4d287aa47fc790d81b04f654fbd74450"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 17:09:56"
  condition:
    hash.sha256(0, filesize) == "5834c911358884cfa89a737e22cb7bde4d287aa47fc790d81b04f654fbd74450"
}

rule MalwareBazaar_unknown_097_0f2b408c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f2b408c28b3e36b47c226b1a984606a9de5421d60c8e1ffd90e53da2ab69796"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 17:07:56"
  condition:
    hash.sha256(0, filesize) == "0f2b408c28b3e36b47c226b1a984606a9de5421d60c8e1ffd90e53da2ab69796"
}

rule MalwareBazaar_unknown_098_3d5018ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d5018ba2ee3677c6861959bb5ce1f2b0c896883c8618db1a0aa3b27d3369f10"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 17:03:57"
  condition:
    hash.sha256(0, filesize) == "3d5018ba2ee3677c6861959bb5ce1f2b0c896883c8618db1a0aa3b27d3369f10"
}

rule MalwareBazaar_unknown_099_9741e24c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9741e24cffbf4549bf5f5d3aa20ee691c1bcb1b5fbe45274cee257b310c70257"
    family = "unknown"
    file_name = "starter_c4f0b03c-12e6-499f-9a1d-439f7bddf6ef.dll"
    file_type = "exe"
    first_seen = "2026-09-12 16:58:27"
  condition:
    hash.sha256(0, filesize) == "9741e24cffbf4549bf5f5d3aa20ee691c1bcb1b5fbe45274cee257b310c70257"
}

rule MalwareBazaar_unknown_100_d1585ac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1585ac714ef2f5bd01e2a782c1442b188b5b0c5c068abc91ef484434bbbe8f6"
    family = "unknown"
    file_name = "api.exe"
    file_type = "exe"
    first_seen = "2026-09-12 16:58:23"
  condition:
    hash.sha256(0, filesize) == "d1585ac714ef2f5bd01e2a782c1442b188b5b0c5c068abc91ef484434bbbe8f6"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

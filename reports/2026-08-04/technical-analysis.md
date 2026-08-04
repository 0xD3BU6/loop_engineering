# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-04

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 637 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 637 |
| Unique family labels | 6 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 67 |
| unknown | 29 |
| Sliver | 1 |
| WannaCry | 1 |
| AgentTesla | 1 |
| CoinMiner | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 77 |
| exe | 10 |
| dll | 3 |
| sh | 3 |
| unknown | 2 |
| js | 2 |
| html | 1 |
| iso | 1 |
| ps1 | 1 |

## Per-Sample Analysis

### Sample 1: `28685dff00aa1752`

| Field | Value |
|---|---|
| SHA-256 | `28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11` |
| Family label | `unknown` |
| File name | `sys_d1c5307f.exe` |
| File type | `exe` |
| First seen | `2026-08-04 03:37:00` |
| Reporter | `RakeshKrish12` |
| Tags | `CRPX0, exe, ransomware` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ff86a4fdfec4a5b49d5545f9a62ec4c` |
| SHA-1 | `3c92be8d6c8380bb7122a80aa3f9880fa81e64ec` |
| SHA-256 | `28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11` |
| SHA3-384 | `f172d9dc2c9cd2d0956fd272fd92566d5d51678d1f8462a195154918fbce82fc1e2e84d343945320ab61764449fcf0e9` |
| IMPHASH | `e7cf2daa84faef10a947f01b56d02d24` |
| TLSH | `T18006336D57FBCECBD24009F689EDB0A1974A95ACD9A4C2B358BD8C047E43111A4FBB13` |
| SSDEEP | `98304:xi1EdOFiqwkDLMJSHyVoc9PyULeBXCoxQBiwj9O:WQOwCLMoG9CxfCLjc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_28685dff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11"
    family = "unknown"
    file_name = "sys_d1c5307f.exe"
    file_type = "exe"
    first_seen = "2026-08-04 03:37:00"
  condition:
    hash.sha256(0, filesize) == "28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11"
}
```

### Sample 2: `ef431e36a8ac1205`

| Field | Value |
|---|---|
| SHA-256 | `ef431e36a8ac12051af588d800e1d8128d583a9d4c68187709263a13564081cd` |
| Family label | `unknown` |
| File name | `sys_9ae934e3.dll` |
| File type | `dll` |
| First seen | `2026-08-04 03:36:28` |
| Reporter | `RakeshKrish12` |
| Tags | `CRPX0, dll, ransomware` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea3f9230bb76deb18dedfaea490fd687` |
| SHA-1 | `1a63533c69f48ca183cc81c797003ece38f9e3f9` |
| SHA-256 | `ef431e36a8ac12051af588d800e1d8128d583a9d4c68187709263a13564081cd` |
| SHA3-384 | `1808c4ee5020b1eca4b3f9b4a14dd5d86f67bf6e244d20707c8d54804bed2b9e1f6777846f99adfad03288860e7f52a3` |
| IMPHASH | `8021f32be9faef6137ea9d442ebe0059` |
| TLSH | `T1110633A45AA655D0F22166B6B54CFDF803C2E4510FA91A1735F6FFCADB0BAC0D80E493` |
| SSDEEP | `98304:vVnxNKUD4ErrOLU2YKRi+qt4vg2BntsIs5M5wJQvHFg+v0:vVnxNneYolt5s5/QvNv0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_ef431e36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef431e36a8ac12051af588d800e1d8128d583a9d4c68187709263a13564081cd"
    family = "unknown"
    file_name = "sys_9ae934e3.dll"
    file_type = "dll"
    first_seen = "2026-08-04 03:36:28"
  condition:
    hash.sha256(0, filesize) == "ef431e36a8ac12051af588d800e1d8128d583a9d4c68187709263a13564081cd"
}
```

### Sample 3: `55a81d88fff3dc3d`

| Field | Value |
|---|---|
| SHA-256 | `55a81d88fff3dc3de0e42724b0a992d4ef382b0e1a82187abf9d635ab89b2bae` |
| Family label | `unknown` |
| File name | `captcha_obf.html` |
| File type | `html` |
| First seen | `2026-08-04 03:36:01` |
| Reporter | `RakeshKrish12` |
| Tags | `CRPX0, html, ransomware` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ef19373aae940002a980a984f25555b` |
| SHA-1 | `08466e5d2a8bd0ced4a148fe4ce0585ea44a9d77` |
| SHA-256 | `55a81d88fff3dc3de0e42724b0a992d4ef382b0e1a82187abf9d635ab89b2bae` |
| SHA3-384 | `2186e80a6251e26fd811c03da984ccad354e4d3c5d6dd1eadbe0d3af07149cda4c279cc5817dcd32cb906221f854563e` |
| TLSH | `T13866F11189C42FF8CFAC4A1990FE1A1D97B0074E55166D8EEB337D5FAFE7908520B09A` |
| SSDEEP | `49152:7oPmg910auMQXh0cMW/KaC1jq4Eb147OXdedZNakcDsyTjDhDfb5ZdAzycZ6cd1S:7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `html`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_55a81d88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55a81d88fff3dc3de0e42724b0a992d4ef382b0e1a82187abf9d635ab89b2bae"
    family = "unknown"
    file_name = "captcha_obf.html"
    file_type = "html"
    first_seen = "2026-08-04 03:36:01"
  condition:
    hash.sha256(0, filesize) == "55a81d88fff3dc3de0e42724b0a992d4ef382b0e1a82187abf9d635ab89b2bae"
}
```

### Sample 4: `ae09b3fd7eea012f`

| Field | Value |
|---|---|
| SHA-256 | `ae09b3fd7eea012f655e9467f694d1fb41a1b14033a904ce66105a6869ae00ae` |
| Family label | `unknown` |
| File name | `XenoExtractorSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-04 03:35:32` |
| Reporter | `hexinglarps` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3acb300d4eeb534c7e188b6fbdec9a9` |
| SHA-1 | `b5d23c58d87ca55aa12c2eaed3fdf7bb17dfec74` |
| SHA-256 | `ae09b3fd7eea012f655e9467f694d1fb41a1b14033a904ce66105a6869ae00ae` |
| SHA3-384 | `de04bdbcecac334eae91049c4e350f5c2fb823119a31d885e0d59cc9289efd6f134a0fb04f1e096f7cd97c78ae63edbc` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1DA15F1890E31989AC1471E3F5BD4E25DC62D93D8EC2EA3467D8502E41F36F8D396F6A0` |
| SSDEEP | `24576:WYid/JoqN67ARlInMOEnr43DedwlYvNaak5BkA/g:+heuShwnr4yClY1azc6` |
| ICON-DHASH | `c8f0e1c9e260c4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_ae09b3fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae09b3fd7eea012f655e9467f694d1fb41a1b14033a904ce66105a6869ae00ae"
    family = "unknown"
    file_name = "XenoExtractorSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-04 03:35:32"
  condition:
    hash.sha256(0, filesize) == "ae09b3fd7eea012f655e9467f694d1fb41a1b14033a904ce66105a6869ae00ae"
}
```

### Sample 5: `0dc6a5ce14838813`

| Field | Value |
|---|---|
| SHA-256 | `0dc6a5ce14838813e297a83e3c3c0868c7a211ee2da9c9705e5a282e65f089fe` |
| Family label | `unknown` |
| File name | `sys_f3799809.exe` |
| File type | `exe` |
| First seen | `2026-08-04 03:23:46` |
| Reporter | `RakeshKrish12` |
| Tags | `CRPX0, exe, ransomware` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc2c8ac5aea8d7c36e9161d54e4255f3` |
| SHA-1 | `c7bbc3728ccbc968688e7ea5b9cff8c6f75238b1` |
| SHA-256 | `0dc6a5ce14838813e297a83e3c3c0868c7a211ee2da9c9705e5a282e65f089fe` |
| SHA3-384 | `fc0a83a0ca06bdd1703f9cc23483c8f25105cb14cedb6c2710d1b710ea99ef906f36cf7667de92ed825431ce67aa2059` |
| IMPHASH | `e7cf2daa84faef10a947f01b56d02d24` |
| TLSH | `T1010633190D86B0E5C2A8BAF405E7A7F974617CF8F2908D605A92C5E5E0CB117A4F1FE3` |
| SSDEEP | `98304:ECjw1RLiKHRWeQQgfpZvvXuPM3JRbJmxCjz7CCUNSW6W3dtrjQ:IRLB4XzvJmojgN/7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_0dc6a5ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dc6a5ce14838813e297a83e3c3c0868c7a211ee2da9c9705e5a282e65f089fe"
    family = "unknown"
    file_name = "sys_f3799809.exe"
    file_type = "exe"
    first_seen = "2026-08-04 03:23:46"
  condition:
    hash.sha256(0, filesize) == "0dc6a5ce14838813e297a83e3c3c0868c7a211ee2da9c9705e5a282e65f089fe"
}
```

### Sample 6: `8af1afc82c0d578a`

| Field | Value |
|---|---|
| SHA-256 | `8af1afc82c0d578a54cc34d09544a0695ec2b0d5f244bf1f1bb4993ee7614734` |
| Family label | `unknown` |
| File name | `sys_81242b01.dll` |
| File type | `dll` |
| First seen | `2026-08-04 03:23:13` |
| Reporter | `RakeshKrish12` |
| Tags | `CRPX0, dll, ransomware` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8e9a638aa9e1c2d73f3432b997d7a7f` |
| SHA-1 | `1b316a7c4fcdae8248f65f14098fec3ade135eff` |
| SHA-256 | `8af1afc82c0d578a54cc34d09544a0695ec2b0d5f244bf1f1bb4993ee7614734` |
| SHA3-384 | `4cbeff5d02d7d3f89155aba3ac7d1c089c023fff38b9021e5dcb10c5d366bb3bd6297e2b30d0f65c17c579dbefc3a346` |
| IMPHASH | `8021f32be9faef6137ea9d442ebe0059` |
| TLSH | `T1F506335C096E8EF4E329FC71EFC5EB68882C313F09827132BE2C61279B5E4731995859` |
| SSDEEP | `98304:0iIjOrjmQJLHdRq65o8vgTKBvQRUy4jH:0GPJq05fMUy4j` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_8af1afc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8af1afc82c0d578a54cc34d09544a0695ec2b0d5f244bf1f1bb4993ee7614734"
    family = "unknown"
    file_name = "sys_81242b01.dll"
    file_type = "dll"
    first_seen = "2026-08-04 03:23:13"
  condition:
    hash.sha256(0, filesize) == "8af1afc82c0d578a54cc34d09544a0695ec2b0d5f244bf1f1bb4993ee7614734"
}
```

### Sample 7: `9cfe9b894af68946`

| Field | Value |
|---|---|
| SHA-256 | `9cfe9b894af68946ddc7e6f4cbdb085a92c4009ea00554c407beb5a8fc29f6b7` |
| Family label | `unknown` |
| File name | `sys_c67f50d5.exe` |
| File type | `exe` |
| First seen | `2026-08-04 03:22:42` |
| Reporter | `RakeshKrish12` |
| Tags | `CRPX0, exe, ransomware` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00956814c51e79250e684fbd4a39b71f` |
| SHA-1 | `84346770f454a280ebc93ae95e43f523dee63db9` |
| SHA-256 | `9cfe9b894af68946ddc7e6f4cbdb085a92c4009ea00554c407beb5a8fc29f6b7` |
| SHA3-384 | `66d94f406d4811a91416f01d78bd0ac482078419fc5115de4bccc09e8932fab5f42a51a38b515412031bfb63a818bb61` |
| IMPHASH | `e7cf2daa84faef10a947f01b56d02d24` |
| TLSH | `T1C80633F3EDA8F4E9FD0A0DB6598D921389D9638C40B34050B9A9CEC5B1DB68C6DC7C16` |
| SSDEEP | `98304:7kdQ8bYisEzpBDhFph5ZxiuAJibhAOusv9JNqqxBK:7kC8baeJhAYdZtN5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_9cfe9b89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cfe9b894af68946ddc7e6f4cbdb085a92c4009ea00554c407beb5a8fc29f6b7"
    family = "unknown"
    file_name = "sys_c67f50d5.exe"
    file_type = "exe"
    first_seen = "2026-08-04 03:22:42"
  condition:
    hash.sha256(0, filesize) == "9cfe9b894af68946ddc7e6f4cbdb085a92c4009ea00554c407beb5a8fc29f6b7"
}
```

### Sample 8: `290d41e743623806`

| Field | Value |
|---|---|
| SHA-256 | `290d41e7436238066a8aacbd63a805aeeefc00d8798116dc702eccf6df3eae37` |
| Family label | `unknown` |
| File name | `sys_6510b971.dll` |
| File type | `dll` |
| First seen | `2026-08-04 03:21:51` |
| Reporter | `RakeshKrish12` |
| Tags | `CRPX0, dll, ransomware` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ced4c9b53c3c93a4dbefe2f243cd1c71` |
| SHA-1 | `d6470a458fea20c8954034b236a5d4753ca41651` |
| SHA-256 | `290d41e7436238066a8aacbd63a805aeeefc00d8798116dc702eccf6df3eae37` |
| SHA3-384 | `7e32c28fc8684fd6b3180e6ddbeefad77b667b4a7e68c9ea34626c77f4f0295f1a37528c691986423893effa575eef65` |
| IMPHASH | `8021f32be9faef6137ea9d442ebe0059` |
| TLSH | `T10906333F0252A7F1C5E919B44E7CF8ADC1D1C0C9B9A503BC62AFC49B107A25AE8DD706` |
| SSDEEP | `98304:KJAtX45jlzr6Lt1NEt/5RjjOg6k6t2UsrrOge:KJUX41lzW50XqsUsF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_290d41e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "290d41e7436238066a8aacbd63a805aeeefc00d8798116dc702eccf6df3eae37"
    family = "unknown"
    file_name = "sys_6510b971.dll"
    file_type = "dll"
    first_seen = "2026-08-04 03:21:51"
  condition:
    hash.sha256(0, filesize) == "290d41e7436238066a8aacbd63a805aeeefc00d8798116dc702eccf6df3eae37"
}
```

### Sample 9: `bac340524549410f`

| Field | Value |
|---|---|
| SHA-256 | `bac340524549410f51b060f21abb7db30c0c5378edd2e3ac15b526e141417e89` |
| Family label | `unknown` |
| File name | `sys_7f6670d8.exe` |
| File type | `exe` |
| First seen | `2026-08-04 03:21:06` |
| Reporter | `RakeshKrish12` |
| Tags | `crpx0, exe, ransomware` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4966992c81f7062ed3913ee023240edc` |
| SHA-1 | `7ef833c2b5d000ec8577f235d5071d961ffb4ecd` |
| SHA-256 | `bac340524549410f51b060f21abb7db30c0c5378edd2e3ac15b526e141417e89` |
| SHA3-384 | `2e8ecce3b5c51b873a1a98b90d94ea49050dd760782b51a6a38ff49957c1524e5be43ad3d97234c1922c2f17bbadbc1b` |
| IMPHASH | `e7cf2daa84faef10a947f01b56d02d24` |
| TLSH | `T17806335A7F52C237F44A827EB1FB872C9A7A0AC60A69E4DC38CF6E13794D8437758045` |
| SSDEEP | `98304:WeJrwKgCGcPRqlNcuj2A/ZVD2yYHCkeFbPXhNzCqy9VZuh+:XJ+C5wNcVAxcHleFDhNzCqy9H/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_bac34052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bac340524549410f51b060f21abb7db30c0c5378edd2e3ac15b526e141417e89"
    family = "unknown"
    file_name = "sys_7f6670d8.exe"
    file_type = "exe"
    first_seen = "2026-08-04 03:21:06"
  condition:
    hash.sha256(0, filesize) == "bac340524549410f51b060f21abb7db30c0c5378edd2e3ac15b526e141417e89"
}
```

### Sample 10: `1eb088ba9bb20301`

| Field | Value |
|---|---|
| SHA-256 | `1eb088ba9bb20301add4fb1a99002431d1cb542edcc1ae038557e2435d162935` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-04 03:01:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `819a57d9b72bc3601537a2ba2c4c7aec` |
| SHA-1 | `29441f7e1db9ec98c1cde40d653d579918a13e2d` |
| SHA-256 | `1eb088ba9bb20301add4fb1a99002431d1cb542edcc1ae038557e2435d162935` |
| SHA3-384 | `4c7343160169730b0d3c3bc28ece53add09df994ddddb5766abf0d49d649c09c5425c8bf0e880f310d1b1f1d712b652d` |
| TLSH | `T179E2E815EF504EBBD8A7CD3344B84B4230CD6C2723F52B2B2D71E929B11A54A9BD39E4` |
| SSDEEP | `768:LXnUWeCvISc5UBHlwef7eNusXOXiq6OeXEO:LkagDyBCu70W6OW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_1eb088ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eb088ba9bb20301add4fb1a99002431d1cb542edcc1ae038557e2435d162935"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-04 03:01:48"
  condition:
    hash.sha256(0, filesize) == "1eb088ba9bb20301add4fb1a99002431d1cb542edcc1ae038557e2435d162935"
}
```

### Sample 11: `5d722c70d2ccd3e5`

| Field | Value |
|---|---|
| SHA-256 | `5d722c70d2ccd3e588321d3dea5ea7c8500b4c381654f1eded1381e87016c610` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-04 03:01:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0eb600f338959653a9b3ef1eb3879193` |
| SHA-1 | `668715f812304f5e8f74cbe2c7dd224b5a3f14b1` |
| SHA-256 | `5d722c70d2ccd3e588321d3dea5ea7c8500b4c381654f1eded1381e87016c610` |
| SHA3-384 | `eed2cee176c8ebd1f55450290015e10ebb45072550941a1a432e939221a22e4bba0c4ece5bac5f32a68a73a2591cf70d` |
| TLSH | `T11CE2954F6E328FDDF669C7344AF34E30A799238226E1C686D36CD1501E6024E985FBE5` |
| TELFHASH | `t184e0e51c1ab413a436348859485def57d1e030df77263c178b1314f977fc8425d29d04` |
| SSDEEP | `768:HFPuV73QkBfPgmj2/S3zLMiXoQ0eTK3yPnA:HVuVd8SDLLYIBnA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_5d722c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d722c70d2ccd3e588321d3dea5ea7c8500b4c381654f1eded1381e87016c610"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 03:01:46"
  condition:
    hash.sha256(0, filesize) == "5d722c70d2ccd3e588321d3dea5ea7c8500b4c381654f1eded1381e87016c610"
}
```

### Sample 12: `d216ea4fe9d0ae50`

| Field | Value |
|---|---|
| SHA-256 | `d216ea4fe9d0ae5089b95340953bbfdb16f87c383a95ce1fd77fec5f95893365` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-08-04 03:01:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5ee12a9e4f9e911b008b7809a7f654c` |
| SHA-1 | `f049a5c9c46a2a86b326f7ca658faaef91260268` |
| SHA-256 | `d216ea4fe9d0ae5089b95340953bbfdb16f87c383a95ce1fd77fec5f95893365` |
| SHA3-384 | `cf3527dc8b4c4f97114626927d3eb1130e738015c5220435b98f58289e05ab5b92b867e2455e161ecad085000aeeee61` |
| TLSH | `T1C1B22B81E487E0F2E41B46B98092A73EDB30D61A2515D91BFF7097BDEE13911830F319` |
| TELFHASH | `t149f0c8a1bd6204f9fbc7bd4ceb1e2643db365db20b1164fd58f6610179d1641d0b2001` |
| SSDEEP | `384:fCXJdg5g3tI4cjfaxWapnTUIsc83SFG1bhs7yURpOLja0pqKEtkzw:y7tIffgWkYIsnvdeGURpwa0pqK+Ow` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_d216ea4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d216ea4fe9d0ae5089b95340953bbfdb16f87c383a95ce1fd77fec5f95893365"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-04 03:01:44"
  condition:
    hash.sha256(0, filesize) == "d216ea4fe9d0ae5089b95340953bbfdb16f87c383a95ce1fd77fec5f95893365"
}
```

### Sample 13: `e42737c443cd36a6`

| Field | Value |
|---|---|
| SHA-256 | `e42737c443cd36a64856465be6ef776cd5a81fe51ce7ae8cc63597c364742be9` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-04 03:01:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da364dcf23af8faa865f5d1a5515306b` |
| SHA-1 | `5efa6baecbcc774e74c0ecc48a670f9f28eba235` |
| SHA-256 | `e42737c443cd36a64856465be6ef776cd5a81fe51ce7ae8cc63597c364742be9` |
| SHA3-384 | `11c0899c43620fd925939b66e42d5b3cd77a9d57d2aadc196301f33d91cb089a75a2471774cdf5ddf891d35a89f5c326` |
| TLSH | `T10023074AFD805F00D9E525BAFE1E424D33934B7CE3FE7111AE215B2523C6A2B0B7A911` |
| TELFHASH | `t18cf09e104a856cedf3d2190ad38e76439912aaea3f746c8633ebbc075337f82053029d` |
| SSDEEP | `1536:5lnESiKbuDyyyyyyyyoPo0/IOWNFXiK2lnkivAt+JHCBD:vikr/IOWNFA1At+JiV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_e42737c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e42737c443cd36a64856465be6ef776cd5a81fe51ce7ae8cc63597c364742be9"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-04 03:01:40"
  condition:
    hash.sha256(0, filesize) == "e42737c443cd36a64856465be6ef776cd5a81fe51ce7ae8cc63597c364742be9"
}
```

### Sample 14: `a3bbf4f02b6b1030`

| Field | Value |
|---|---|
| SHA-256 | `a3bbf4f02b6b10305ad5e96cf4e360026caca7bdfb4b053628c7e963f6605aac` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-04 03:01:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11e527b41069d037aa8a9bf30967032f` |
| SHA-1 | `276655d14899d81bca77e596cfea82b808b216c1` |
| SHA-256 | `a3bbf4f02b6b10305ad5e96cf4e360026caca7bdfb4b053628c7e963f6605aac` |
| SHA3-384 | `9d20484f4d4e44da5d0c03f3fd6c0a887b2ce5f346083fd86e6123631f7ab1661f4ff0392b22970e331e6785d722dfec` |
| TLSH | `T1E103194AF9818B12C5E015BAFE2E524D3313077CE3EF7226AE106A34679757B0B3A815` |
| TELFHASH | `t12bf0592002449de865fc4445de7ed4827041abb636bc380b7be3bd6d832b5a1b03009e` |
| SSDEEP | `768:ttnvcGn539x6CfbVUjanfnrhpgD5mkcIYGWi0HGBFDKAM:ttnfn53mCvnfnr4g3ImiuGr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_a3bbf4f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3bbf4f02b6b10305ad5e96cf4e360026caca7bdfb4b053628c7e963f6605aac"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-04 03:01:37"
  condition:
    hash.sha256(0, filesize) == "a3bbf4f02b6b10305ad5e96cf4e360026caca7bdfb4b053628c7e963f6605aac"
}
```

### Sample 15: `c003e3244c180d0b`

| Field | Value |
|---|---|
| SHA-256 | `c003e3244c180d0b7d3a23e227c6a36aa461afbd2d5a2ddbd8e27eef77084af5` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-04 03:00:05` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74cdc790419087eeb9a0d8cca468fc6c` |
| SHA-1 | `19f1f1f52f818717fc147f27b6b49a27ceaab9e0` |
| SHA-256 | `c003e3244c180d0b7d3a23e227c6a36aa461afbd2d5a2ddbd8e27eef77084af5` |
| SHA3-384 | `d493747c3058827e0d1827eb28641dbcccddeb23e1d38bfd92436738318e6e08d9750668d6ea606942b4576ad173cb47` |
| TLSH | `T12672AE8ED4E93F9ACFDE2E3C59A823706D81F090626D5F4CB31A8C81A31A507B98D075` |
| SSDEEP | `384:NxjFfh7KRhyAYjiJiwSKT5Yye6eoxyTdRWGVCzhMhHblQ:NxjFp2Ixji0wSo5eY0/WMq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_c003e324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c003e3244c180d0b7d3a23e227c6a36aa461afbd2d5a2ddbd8e27eef77084af5"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-04 03:00:05"
  condition:
    hash.sha256(0, filesize) == "c003e3244c180d0b7d3a23e227c6a36aa461afbd2d5a2ddbd8e27eef77084af5"
}
```

### Sample 16: `115fc7d85f327558`

| Field | Value |
|---|---|
| SHA-256 | `115fc7d85f327558cc5787b54c33a831446b4ee8694c1a2490abbf904a41c829` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-04 03:00:02` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `944811e8a1603197263778df5aa2b9b3` |
| SHA-1 | `b3e873375dbae255ff6e3af1ec38c987247789ab` |
| SHA-256 | `115fc7d85f327558cc5787b54c33a831446b4ee8694c1a2490abbf904a41c829` |
| SHA3-384 | `55027833bd8692588c9e742fc02d7b68e3e547571413232f054012a65f0b6b97b3e439985c1c1731eea95de6339fdd06` |
| TLSH | `T15062AF7D134631F7D83694B312AD07802C390FFE9A03DC1B5689E6E2DD098B5A467AF9` |
| SSDEEP | `384:QnxMbDo/EqEFZTOkQyT5hxvJgGlzDpH0+73s8:kxg8vEFZ60DxvJgGlzDpUYs8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_115fc7d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "115fc7d85f327558cc5787b54c33a831446b4ee8694c1a2490abbf904a41c829"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 03:00:02"
  condition:
    hash.sha256(0, filesize) == "115fc7d85f327558cc5787b54c33a831446b4ee8694c1a2490abbf904a41c829"
}
```

### Sample 17: `b1fd6828ad7f33f8`

| Field | Value |
|---|---|
| SHA-256 | `b1fd6828ad7f33f8727067385ccc9a048c0f03fb5cfbf204003366b3becb0e58` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-04 03:00:00` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4da47b25096974c8d09390e3b8fc17b1` |
| SHA-1 | `adeebbdfe6b11cb8227efe2dd7426bb861f67fa3` |
| SHA-256 | `b1fd6828ad7f33f8727067385ccc9a048c0f03fb5cfbf204003366b3becb0e58` |
| SHA3-384 | `07022175ac52ef767fd5a63be4de27b0d0e80d260509e9baa60d77a68fdb96efc727fce2d91728340bd7df6bd67badc1` |
| TLSH | `T193B2C1515580862391E20C3BF9779303D3D82FE949E7683933644E2CA3CE59A67BC687` |
| SSDEEP | `384:Zg3WjvMR52Ys5Mf7lyRONcru9kGFrv+bFJ6Dzt+KrFQLaqmdGU5EeCZdPU:u3WjvMRsMxKOD9dvW2zRFZq3UI8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_b1fd6828
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1fd6828ad7f33f8727067385ccc9a048c0f03fb5cfbf204003366b3becb0e58"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-04 03:00:00"
  condition:
    hash.sha256(0, filesize) == "b1fd6828ad7f33f8727067385ccc9a048c0f03fb5cfbf204003366b3becb0e58"
}
```

### Sample 18: `bed43d309f45747c`

| Field | Value |
|---|---|
| SHA-256 | `bed43d309f45747c5c9ac611b189780e0cd48f907f4d909c6ecc784759df5d36` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-08-04 03:00:00` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5800ed81e0533610689d151d8cd36256` |
| SHA-1 | `0087eaa129a5c42dd49767428fe26cd859b4977a` |
| SHA-256 | `bed43d309f45747c5c9ac611b189780e0cd48f907f4d909c6ecc784759df5d36` |
| SHA3-384 | `ec6dccd883e1e65e05aed13b97b8b4fd6c1cd2f4754583bffeeb5444652e940968d6e4023507ae12d9a8f3010b774d18` |
| TLSH | `T1EA62AF9BC3F64905C17E50B20C5F3D043D24E21EF28CA9BB7BD860765562F66392C6A9` |
| SSDEEP | `384:MIu4BjdrDUZRY9A+/xV1c76N3Cau1q6PT6WANaNJawcudoD7UqhCk0M:/u4BOp+S2N3C1Y6rDnbcuyD7U2Ck0M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_bed43d30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bed43d309f45747c5c9ac611b189780e0cd48f907f4d909c6ecc784759df5d36"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-04 03:00:00"
  condition:
    hash.sha256(0, filesize) == "bed43d309f45747c5c9ac611b189780e0cd48f907f4d909c6ecc784759df5d36"
}
```

### Sample 19: `711d580edcb17c29`

| Field | Value |
|---|---|
| SHA-256 | `711d580edcb17c294c3c7942873d38c70db5346a30b8963dee11b79019ce5b5c` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-04 02:59:59` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f825de6d04124e7f5137470a19df594d` |
| SHA-1 | `c9096a31aae5a993f0097af691fbc3b7be686e6d` |
| SHA-256 | `711d580edcb17c294c3c7942873d38c70db5346a30b8963dee11b79019ce5b5c` |
| SHA3-384 | `c44f19607ca57eb82048ce945b30da0cc3bc3950420f9d51e5635f216876608f4e66e2adba094b88aa27459fb8cfd842` |
| TLSH | `T1E5B25C86FD814517CEE51176FA2E928D37665BB4E2FF3303AA261F642742A1F0F3A405` |
| TELFHASH | `t158115711864c8d9eb240856ce1ad46031626e1ba3c7e3a62bdfb981f810bcf39471926` |
| SSDEEP | `384:dG2m2FfIQp9Mgj6JwqQ87+2eZvaBcjQOF9hM4tXV5aceBy6jdmFx4ef:dfyRVg87+zvaOPFLM6qy6jF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_711d580e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "711d580edcb17c294c3c7942873d38c70db5346a30b8963dee11b79019ce5b5c"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-04 02:59:59"
  condition:
    hash.sha256(0, filesize) == "711d580edcb17c294c3c7942873d38c70db5346a30b8963dee11b79019ce5b5c"
}
```

### Sample 20: `053159bc4da6952d`

| Field | Value |
|---|---|
| SHA-256 | `053159bc4da6952d2920f832b6aa2fee39c910422a9696a56cbd046478515f61` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-04 02:59:58` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b4f333930d4d433752753d1abdc7f57` |
| SHA-1 | `69a9304da399b2f4e046b3163bacb6e5bc6db90d` |
| SHA-256 | `053159bc4da6952d2920f832b6aa2fee39c910422a9696a56cbd046478515f61` |
| SHA3-384 | `b2858b85f651a56479146a36ab5ffe7e41cf0d53b8a26bbca9d7ebecb4f1173293c36d263992153a2c34e8151dae0164` |
| TLSH | `T1DF92C0358263A793C9B20876A121498BF72E6631F4EF70442372A774DBC7001E7E616B` |
| SSDEEP | `384:Cs8o6sY6ut0jEumRVPIrMOkuB4we03wrUUCGqmdGU5EeCZd+:Ixt8mrP9OkuqwegEJCGq3UI+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_053159bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "053159bc4da6952d2920f832b6aa2fee39c910422a9696a56cbd046478515f61"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-04 02:59:58"
  condition:
    hash.sha256(0, filesize) == "053159bc4da6952d2920f832b6aa2fee39c910422a9696a56cbd046478515f61"
}
```

### Sample 21: `a2362c6b241ede3f`

| Field | Value |
|---|---|
| SHA-256 | `a2362c6b241ede3fc4b9fe8ae8a13116504790091663305852034a55fe2e5596` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-04 02:57:13` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, PMIX0.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffa9a95f51f3bf95c26b167293e20df8` |
| SHA-1 | `17654186a11a379bf9566d71a89295c493f54ced` |
| SHA-256 | `a2362c6b241ede3fc4b9fe8ae8a13116504790091663305852034a55fe2e5596` |
| SHA3-384 | `13b79ba107fd634c0ab462ad60c4741cf90bdbe998b353b172531305cce6e8ae51b02cccf30cb0848e3988405f7a6bae` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11E368C17BA9049F5C0A9D731C87B5616BA71B84D8B3033D72E616E782F327C1AE39B44` |
| SSDEEP | `49152:dHLrVTexueDyU9aBCbQGnrEepqPZaLXA+WpDdbWHN451kl7e7oY2tNYwO86Ws7bn:ddNYCh4XA+WpDRWHy51L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_a2362c6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2362c6b241ede3fc4b9fe8ae8a13116504790091663305852034a55fe2e5596"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 02:57:13"
  condition:
    hash.sha256(0, filesize) == "a2362c6b241ede3fc4b9fe8ae8a13116504790091663305852034a55fe2e5596"
}
```

### Sample 22: `114d63f0ee478b2f`

| Field | Value |
|---|---|
| SHA-256 | `114d63f0ee478b2fda75083283372cecd3064c6a425d06b9179f147454fe0a17` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-04 02:56:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `009b0cf066b7448b4fa962597017ac1d` |
| SHA-1 | `3a44f59a7b04619e727f334e99f1826d3968aec2` |
| SHA-256 | `114d63f0ee478b2fda75083283372cecd3064c6a425d06b9179f147454fe0a17` |
| SHA3-384 | `dca6ad969943ad360147bef2bd5308c1443b4d8018cc31353b2c487b14043a3912613347adac812bc316848bfa6ac400` |
| TLSH | `T18C84194492F1E2FDE198EA30531AB81BAD7275363073768E729DAD7313B665006FDB20` |
| TELFHASH | `t1c9618c7108d534a472ebc902b353977e9f3254e085ec35b96a236db0def5ac50cc2866` |
| SSDEEP | `6144:TnZ3bWsb4ogK0wrTf1a25EHbAnjOTlPBFWuH9N90a9Qi:TFQwr5LE0nKTlJFd9N90a9Qi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_114d63f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "114d63f0ee478b2fda75083283372cecd3064c6a425d06b9179f147454fe0a17"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:56:32"
  condition:
    hash.sha256(0, filesize) == "114d63f0ee478b2fda75083283372cecd3064c6a425d06b9179f147454fe0a17"
}
```

### Sample 23: `2bf4b9346368e0e0`

| Field | Value |
|---|---|
| SHA-256 | `2bf4b9346368e0e01627bbb9f9ac46ade32bcc5d858863fcc1b77101843235d8` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b3c8bb5f89bf8fef68cc41d55adefd6` |
| SHA-1 | `587ffc9aad7d0066c5b7ef8f3d757f25a3ce4033` |
| SHA-256 | `2bf4b9346368e0e01627bbb9f9ac46ade32bcc5d858863fcc1b77101843235d8` |
| SHA3-384 | `db9065cb8f3104a83420ce3c002bf645130dedbe22e627e7b8c86ca8c6773fc2e2cd8141d624b18081991c5fcdff229b` |
| TLSH | `T108A43B8C9BF19BDFE06DDD3063196A171CBE493730E777A6A17DE86232AB14405E7820` |
| SSDEEP | `6144:PFq3b1I55MOfbi7Vob/TO5gqYqYtVSr1GhRLlGlLWD1jTFFXa9AsC:Cxw5MBZoja5gq9s26vFFXa9As` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_2bf4b934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bf4b9346368e0e01627bbb9f9ac46ade32bcc5d858863fcc1b77101843235d8"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:38"
  condition:
    hash.sha256(0, filesize) == "2bf4b9346368e0e01627bbb9f9ac46ade32bcc5d858863fcc1b77101843235d8"
}
```

### Sample 24: `3c500648c5608920`

| Field | Value |
|---|---|
| SHA-256 | `3c500648c56089205ba5ee22fa60ba32d9933750849c1fab0296405ae4dc4cd8` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d384a96545c984eaad737baa2c703e5` |
| SHA-1 | `7bb4df4b1c8599b7070f5cee64405957d1729482` |
| SHA-256 | `3c500648c56089205ba5ee22fa60ba32d9933750849c1fab0296405ae4dc4cd8` |
| SHA3-384 | `957918152e4eb421823a578e9da1f3f6f27e8f8a0a869144edb6651a57b15e2f656f9dff1ec45bb2009511cc29614f2a` |
| TLSH | `T1D0A4098D53B1DFD9F368E93003736E575DB6062731D3A186E16EED2223A524848AFE70` |
| TELFHASH | `t171f01c28243c13b4d2c09c5e96ecff20e4a194dba8b62d2bc954c969e775e864d00d3c` |
| SSDEEP | `6144:OK4A+lf1+eIdwFp1v1D8EItBmsSUP354DKubvfX:OK4Rlf1LIi34tL30KWvfX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_3c500648
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c500648c56089205ba5ee22fa60ba32d9933750849c1fab0296405ae4dc4cd8"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:35"
  condition:
    hash.sha256(0, filesize) == "3c500648c56089205ba5ee22fa60ba32d9933750849c1fab0296405ae4dc4cd8"
}
```

### Sample 25: `310ac3902f066cb2`

| Field | Value |
|---|---|
| SHA-256 | `310ac3902f066cb2f1e5e006847b0f5985f8d418e71dcdb8f012eb65535a7656` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:31` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ecb3ac053ed9e7dcb634dea7512f80d` |
| SHA-1 | `8df4c2dcd7148717c4f71f3d40db48e432ab4c74` |
| SHA-256 | `310ac3902f066cb2f1e5e006847b0f5985f8d418e71dcdb8f012eb65535a7656` |
| SHA3-384 | `c2422ee99da3539162bb1ea9217b43f2066b000b791a6c5cce13c7e7ac45e9a6d4143f4f922949b114d04571ca7d51ab` |
| TLSH | `T10AC312B7E7214A2DE377EA3301A4DF92A3B124F214140B8A4BBC767CE367DA51061B95` |
| SSDEEP | `3072:9BZn/N6CEgyGivBHaMOfEVVdY6qzg3KuXlbzkjtYmTx:HZn16CPy1JwEfdY6BauXlbzlmd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_310ac390
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310ac3902f066cb2f1e5e006847b0f5985f8d418e71dcdb8f012eb65535a7656"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:31"
  condition:
    hash.sha256(0, filesize) == "310ac3902f066cb2f1e5e006847b0f5985f8d418e71dcdb8f012eb65535a7656"
}
```

### Sample 26: `a6426a32489d5c82`

| Field | Value |
|---|---|
| SHA-256 | `a6426a32489d5c827fe5ad2eb7fcdaed1c45445b45865d5dd6b231a3b9e32704` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:30` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `067a87c99707ecb051573fc48e8548de` |
| SHA-1 | `c6ef6e592bc24c5c7b63e0ab57283597e4ab31a3` |
| SHA-256 | `a6426a32489d5c827fe5ad2eb7fcdaed1c45445b45865d5dd6b231a3b9e32704` |
| SHA3-384 | `8fd040e5e062023dafde8a759abe400111d17669bab44f598e39fc9f0e36dc44b58aacff9d964a7821890c6edcf8a803` |
| TLSH | `T16E741988D2E3E2FDF155DA7013257A1B5D324A373093F24AF39E697392B624045EEA34` |
| TELFHASH | `t1306192085e82f58cf7734ad8cdb6e111057a626ef3ea538243c16df62e031969067c13` |
| SSDEEP | `6144:cN+vMMN5j/xWuY0c7AuVQgwVWaj4nUEbMeKsrEa9zY:BVF/xWuLc77VQhrEbMeKwEa9zY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_a6426a32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6426a32489d5c827fe5ad2eb7fcdaed1c45445b45865d5dd6b231a3b9e32704"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:30"
  condition:
    hash.sha256(0, filesize) == "a6426a32489d5c827fe5ad2eb7fcdaed1c45445b45865d5dd6b231a3b9e32704"
}
```

### Sample 27: `bbd7f06ab627494c`

| Field | Value |
|---|---|
| SHA-256 | `bbd7f06ab627494cdd44ae6f5b03649754c7e500a92bcdf055ee7973ddbdc693` |
| Family label | `Mirai` |
| File name | `s390x` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:29` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2c01b33c633e072df9886e9a74fb12c` |
| SHA-1 | `56030463cbe2a181dfc3782d8cfca6d68247ee02` |
| SHA-256 | `bbd7f06ab627494cdd44ae6f5b03649754c7e500a92bcdf055ee7973ddbdc693` |
| SHA3-384 | `a6e21e001073a3675efeeb0841df06c5725dc0ac5f43261c9d55cc4a05522388c3af790020cd8d7591dc4cfb945f2d85` |
| TLSH | `T1D494F7CC51B1E3CED060AD32D22579B79967123724837A8C61DEEB7B12F724606B9E31` |
| SSDEEP | `6144:OV9XNYcE30HY6PzzRyGoc6vtXerrvx1T65CvpiyCmHe:wUqY6LzRyGQ9exN65rjIe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_bbd7f06a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbd7f06ab627494cdd44ae6f5b03649754c7e500a92bcdf055ee7973ddbdc693"
    family = "Mirai"
    file_name = "s390x"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:29"
  condition:
    hash.sha256(0, filesize) == "bbd7f06ab627494cdd44ae6f5b03649754c7e500a92bcdf055ee7973ddbdc693"
}
```

### Sample 28: `c70f20a8d2dec9cb`

| Field | Value |
|---|---|
| SHA-256 | `c70f20a8d2dec9cb679631b40d9f86cf050b7bef46c7f3fab67bd4db4b8dbe9b` |
| Family label | `Mirai` |
| File name | `riscv64` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:29` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f7857f6fe7b023137ec7d47690ee099` |
| SHA-1 | `736e0c95c77db8ea3551947ca0d015fa9364225a` |
| SHA-256 | `c70f20a8d2dec9cb679631b40d9f86cf050b7bef46c7f3fab67bd4db4b8dbe9b` |
| SHA3-384 | `d9120cda9586d9e1671e59d5f5c53ab11a6b506b68e611e97eb56b3ede040bdbc9d25f697fc45764bb3981a8bbfd57e9` |
| TLSH | `T1E8742A8C92F1E3DEE158EA7563207C1A5C76463B3097B28A619EF97313A71844AFDD30` |
| SSDEEP | `3072:ZVaLj7MaWRckGpnDtnKaCe7ra9Kw/zgkskasd5NyFWLaHIsuBZ1POfyvgw0+aRqJ:HUDtkEDtnKZe7rafzAkn5UWLeaa9pU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_c70f20a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c70f20a8d2dec9cb679631b40d9f86cf050b7bef46c7f3fab67bd4db4b8dbe9b"
    family = "Mirai"
    file_name = "riscv64"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:29"
  condition:
    hash.sha256(0, filesize) == "c70f20a8d2dec9cb679631b40d9f86cf050b7bef46c7f3fab67bd4db4b8dbe9b"
}
```

### Sample 29: `54a53cf88b6371a5`

| Field | Value |
|---|---|
| SHA-256 | `54a53cf88b6371a57090067aafe8721fe44e0d7342a6778c752f939aa75e99f0` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:28` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a917338d0a89b5cafdf75b59df13c821` |
| SHA-1 | `002addf4728b501e1e1bd7af3a50826350a04805` |
| SHA-256 | `54a53cf88b6371a57090067aafe8721fe44e0d7342a6778c752f939aa75e99f0` |
| SHA3-384 | `f3de76d376420596320e5f948b84216b7a15571419d93866e380f10af0d4787ab10ea1837ca923f3005bd6a2d0e4d303` |
| TLSH | `T100841A44B3F1D3CBD254EE7053362E66AB6A863238E7B189610FBB73137317445DAA60` |
| SSDEEP | `6144:IDvZJI2t9WLgQrLmdocWDF6z0hF4PWPQSx6pVDG8srNwatOv2J2JYVCYlGfaj/jc:mHuYz0UOPKDWNwr+OU/j/k` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_54a53cf8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54a53cf88b6371a57090067aafe8721fe44e0d7342a6778c752f939aa75e99f0"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:28"
  condition:
    hash.sha256(0, filesize) == "54a53cf88b6371a57090067aafe8721fe44e0d7342a6778c752f939aa75e99f0"
}
```

### Sample 30: `fca74b77494968bc`

| Field | Value |
|---|---|
| SHA-256 | `fca74b77494968bc93fff695cde2810dfeb36b4af74aaa12b46299bb48c84474` |
| Family label | `Mirai` |
| File name | `ppc64` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:28` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09d5b26c543ef3f8228cf5f45acd314b` |
| SHA-1 | `1539be30c6bf63a8d320dbd88ee99603776a4cac` |
| SHA-256 | `fca74b77494968bc93fff695cde2810dfeb36b4af74aaa12b46299bb48c84474` |
| SHA3-384 | `698492e97518bc34a1f1ce9ac5acd9917faf8558a4a91772945b20dbe29bbe96b5dcb4899e1a350bc69de3740b1b820e` |
| TLSH | `T155842A5463F1D2CAD254E974D3227F16ABB2063634B7B24A324EB66313F327548DEE60` |
| SSDEEP | `6144:0dQ6MaLAY559AE9jUvxyG5PHHlHV11YtqS0NBvM4o5no+:0IaL7jgn1VRmFo+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_fca74b77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fca74b77494968bc93fff695cde2810dfeb36b4af74aaa12b46299bb48c84474"
    family = "Mirai"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:28"
  condition:
    hash.sha256(0, filesize) == "fca74b77494968bc93fff695cde2810dfeb36b4af74aaa12b46299bb48c84474"
}
```

### Sample 31: `1afcf3ea18f2b7a8`

| Field | Value |
|---|---|
| SHA-256 | `1afcf3ea18f2b7a87906799801be4a4e8fa6b82d402333446daa06b4eda3f399` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:24` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c511b1afc025725e3f1289cd67af293` |
| SHA-1 | `cb05d1431937ed05bc364f1efe8665e0d3a4c067` |
| SHA-256 | `1afcf3ea18f2b7a87906799801be4a4e8fa6b82d402333446daa06b4eda3f399` |
| SHA3-384 | `6b01e6745872387b798bf265dcd0331f6dba795dfced1f3039e8a6ea13b6c3a33bfe97df5e8ca09e8932dbe14932616d` |
| TLSH | `T13CE3139E902E5D46EFD55B3C307AB71AA954F0C2607FD35007E28E845219D0EBBFE898` |
| SSDEEP | `3072:45ft7I5MyAuymqMqiDbnzvuId043TQOCK5LF1XXbE3VdSXzaXU00Xh:c7YXqvC7uIaM5BtE3jSX+XpKh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_1afcf3ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1afcf3ea18f2b7a87906799801be4a4e8fa6b82d402333446daa06b4eda3f399"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:24"
  condition:
    hash.sha256(0, filesize) == "1afcf3ea18f2b7a87906799801be4a4e8fa6b82d402333446daa06b4eda3f399"
}
```

### Sample 32: `5b88cc74ad84267f`

| Field | Value |
|---|---|
| SHA-256 | `5b88cc74ad84267f02f2151d4dc05d0b7adb4fba2df96b27229a643cded55747` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:24` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a6c4d5dbce55473b5b829934c8b4172` |
| SHA-1 | `4bcd4fcb802dfa7a888d99306710c9426fcfa508` |
| SHA-256 | `5b88cc74ad84267f02f2151d4dc05d0b7adb4fba2df96b27229a643cded55747` |
| SHA3-384 | `dd4a6c0966cc220a32b70b257a48f56c98dd9d937d648a7982cca9949b36e4153075492b82aa4ee67efc4653bd89c21f` |
| TLSH | `T13FA44C8853E3D7CEF254E97043A2781A6CB6073374E7A18BE26EB53303E719458ADD61` |
| SSDEEP | `6144:Yf7xR2DEsj0aw+jd9DNQFscb2abLahF1I95Z4qj0RwuMJGF:e7xIjjYIo2am1iiqj0Rw3JGF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_5b88cc74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b88cc74ad84267f02f2151d4dc05d0b7adb4fba2df96b27229a643cded55747"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:24"
  condition:
    hash.sha256(0, filesize) == "5b88cc74ad84267f02f2151d4dc05d0b7adb4fba2df96b27229a643cded55747"
}
```

### Sample 33: `ab434585775518b7`

| Field | Value |
|---|---|
| SHA-256 | `ab434585775518b79d589ee36a56eafc9a83c81e9bd4fb5c8b5cb9939220ecd4` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:23` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7c6a2642b0538ab740dbb5885a53e2f` |
| SHA-1 | `5feb754035e6d55eaf2b224657537a9bd82dc398` |
| SHA-256 | `ab434585775518b79d589ee36a56eafc9a83c81e9bd4fb5c8b5cb9939220ecd4` |
| SHA3-384 | `10428fda33a9da7f34d1c67939884a33060cb7c6397afe37a28f59ad8b52305578874172bda3e481702837e440bd2ec9` |
| TLSH | `T11E842A8862F5FBDEE256FD3983047C166C29CB367483758560AEF96313B71850AFE860` |
| SSDEEP | `6144:My5huxtmroOAQQvtHYKTGShbExHIn9q0JAyHuk+vr36KZ:hhwtmru/tHbzbcg9iKIr368` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_ab434585
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab434585775518b79d589ee36a56eafc9a83c81e9bd4fb5c8b5cb9939220ecd4"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:23"
  condition:
    hash.sha256(0, filesize) == "ab434585775518b79d589ee36a56eafc9a83c81e9bd4fb5c8b5cb9939220ecd4"
}
```

### Sample 34: `c1ff3505ce4decd2`

| Field | Value |
|---|---|
| SHA-256 | `c1ff3505ce4decd2c9ef6381a1c0e62a03f78e17b1cf92793d9f41df68ace755` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:23` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b31775ec6ecc1e13204f5dc97e360dd` |
| SHA-1 | `bc48b08af9663223fa19e9c1ab9ff8304b39e3a2` |
| SHA-256 | `c1ff3505ce4decd2c9ef6381a1c0e62a03f78e17b1cf92793d9f41df68ace755` |
| SHA3-384 | `19cc9ecab96a14f59aaf7a9efa2b925b035ba82b35d79949fa83c7846691b466342d88899e7ec247c2e066888311a440` |
| TLSH | `T163E3122B020D1CF7D9AB94B653970BE48331C6D0A8629EDD1FECB8DAD29D1D2585F1E0` |
| SSDEEP | `3072:KMEZbXGJAEIcSRV76Z/eouwX09XKL1sG8fx4rlDUhVopwdVX:5u2iT6Z5uwW618JeDUhVopwTX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_c1ff3505
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1ff3505ce4decd2c9ef6381a1c0e62a03f78e17b1cf92793d9f41df68ace755"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:23"
  condition:
    hash.sha256(0, filesize) == "c1ff3505ce4decd2c9ef6381a1c0e62a03f78e17b1cf92793d9f41df68ace755"
}
```

### Sample 35: `163be3d0ac9a9e99`

| Field | Value |
|---|---|
| SHA-256 | `163be3d0ac9a9e99fb76eda1891b97d049758873420df45e5369532fe615f940` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:21` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21eb7fbf80f9e9deb85a7e62de817a5c` |
| SHA-1 | `d877968036d2cecb472b57a7556b0a5a1f8d69c7` |
| SHA-256 | `163be3d0ac9a9e99fb76eda1891b97d049758873420df45e5369532fe615f940` |
| SHA3-384 | `701a113dbea241d26a666c2697fdd6514a2eb55aba94d1211ca1f971d3b0795ab5fccf51a843b2e6011e0b42c8ef4eb3` |
| TLSH | `T11584F988E1F1E7DED2D4AA75B318794D3A230736B0D73146A51DFE3223EB1490ABD921` |
| TELFHASH | `t1d9f0540454ce482efbe1c48505bdd95344f823ceef3401104130eb3e5844cc274ac853` |
| SSDEEP | `6144:Z0qv5IG+kbBO2Gpt45kqLqpv49ymaIQYinwwEgf/I3IRa9SZ:FNbBOJpu5kwq149V8CgfQia9SZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_163be3d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "163be3d0ac9a9e99fb76eda1891b97d049758873420df45e5369532fe615f940"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:21"
  condition:
    hash.sha256(0, filesize) == "163be3d0ac9a9e99fb76eda1891b97d049758873420df45e5369532fe615f940"
}
```

### Sample 36: `ccaaa24e22ba38aa`

| Field | Value |
|---|---|
| SHA-256 | `ccaaa24e22ba38aad988ea069bc92db12e83bf5d9ee94e632600fe39482459ba` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-08-04 02:55:19` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c7706398985db499746c85c43218e43` |
| SHA-1 | `a333d7d34bc9c134cccb90b1953b2e09ad2ef795` |
| SHA-256 | `ccaaa24e22ba38aad988ea069bc92db12e83bf5d9ee94e632600fe39482459ba` |
| SHA3-384 | `1b6a197d0fa1b0277b0294e5bc4d3de028d807df06f7dfdbe2e07c0e9a9f8b57a1a7caaf1f15ae9c0dc492bd0dc18db0` |
| TLSH | `T12A84F988E1E1E7DED2D4AA75B31C780D3A230736B1D73146A51DEE3323EB1590AF9921` |
| TELFHASH | `t1fdf0dc0c7d991298f78e60e4ca5ad0b2cd8c320a8a6231e75e41f91f4702ee378d1473` |
| SSDEEP | `6144:vGjzbyc7ml7egGXz/CbLcDUG1DbCTHBDJcwap4Kx4jha9SZ:vKxCpegGqPXGJCLc4MIa9SZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_ccaaa24e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccaaa24e22ba38aad988ea069bc92db12e83bf5d9ee94e632600fe39482459ba"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:19"
  condition:
    hash.sha256(0, filesize) == "ccaaa24e22ba38aad988ea069bc92db12e83bf5d9ee94e632600fe39482459ba"
}
```

### Sample 37: `1fa5a63614596e6f`

| Field | Value |
|---|---|
| SHA-256 | `1fa5a63614596e6f47af8176b409acb6a4792efc9a7c49cfcbdb9b3697904b0a` |
| Family label | `unknown` |
| File name | `bins.sh` |
| File type | `sh` |
| First seen | `2026-08-04 02:53:39` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1da21aed3c8832a1e0a52f65158dc897` |
| SHA-1 | `13389a9d64c8eccd9ee652d3b2456e398545d798` |
| SHA-256 | `1fa5a63614596e6f47af8176b409acb6a4792efc9a7c49cfcbdb9b3697904b0a` |
| SHA3-384 | `6454c3745e2d453dd03f5552799030324d10eafedca24d343892c444540a10524a4db54c8a560ffa3c60770de673f0bb` |
| TLSH | `T15BF054D80559303917D7DA0B1326C845F36ADC54F9672EBC8ECCEB91A895C60247CAFD` |
| SSDEEP | `6:lOnFflE0Fph3viMxzh3viMBviMuiMfyjcbnMAMQrAmNrjPcbZus1hylD5MAMulmM:v0Fph33zh3gygTNnrZNrzMylD5N7Q5q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_1fa5a636
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fa5a63614596e6f47af8176b409acb6a4792efc9a7c49cfcbdb9b3697904b0a"
    family = "unknown"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-08-04 02:53:39"
  condition:
    hash.sha256(0, filesize) == "1fa5a63614596e6f47af8176b409acb6a4792efc9a7c49cfcbdb9b3697904b0a"
}
```

### Sample 38: `e55e33ad6adcdaff`

| Field | Value |
|---|---|
| SHA-256 | `e55e33ad6adcdaffb331b91eb4384a88cb8d186c9321a26f28933f9919a0395b` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-04 02:40:06` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78fa16aa50c01dc2ea3e2fb4c99d7662` |
| SHA-1 | `8db56c9ffabb028de64402f96a9a8c1a8d9ba3e7` |
| SHA-256 | `e55e33ad6adcdaffb331b91eb4384a88cb8d186c9321a26f28933f9919a0395b` |
| SHA3-384 | `04f9b346e5583e5b5963c24945f917830d61491544a388f1e7278ef921d61d1412c0c052ca1fe3c45253cd9946477079` |
| TLSH | `T164534A17A580C0FDC8DEC2759BBE6366E533703D0276B12E27D8AE266E2DD211E5E710` |
| TELFHASH | `t1b421f3707a1a3c90b0e7b123b74be0358c711d3614e175e2d1f269b5ea60b505ab1537` |
| SSDEEP | `1536:0/GxKp56tuHYxPLkNj6cw7MxJeLPSdl3XuRuM:TsIt7xzkNG57MHeuj+EM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_e55e33ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e55e33ad6adcdaffb331b91eb4384a88cb8d186c9321a26f28933f9919a0395b"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:40:06"
  condition:
    hash.sha256(0, filesize) == "e55e33ad6adcdaffb331b91eb4384a88cb8d186c9321a26f28933f9919a0395b"
}
```

### Sample 39: `16db64af8dea727d`

| Field | Value |
|---|---|
| SHA-256 | `16db64af8dea727dd54cb9c2046fc33012e66c0c459c7a9c95667433ea530071` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-04 02:40:02` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5baaff55931e9fed4efda67d145e493` |
| SHA-1 | `c44f8aa77375ec56d3cc5b96d6525b963ec321d1` |
| SHA-256 | `16db64af8dea727dd54cb9c2046fc33012e66c0c459c7a9c95667433ea530071` |
| SHA3-384 | `f2000373afcbf454d01acae0c736451229ab6a3dfd69b4ae1e36c40dcdbb55d224db9f666f4a269e8cb1b1f04784117b` |
| TLSH | `T1C8436BA2CA652E5CD09AA5B0B0309F795BA3D165C1472FFA2572C3798483ECDF2057F8` |
| SSDEEP | `768:W4o246BeOIimOpgKn/oRacAo2empT1CrWkPFlfdwZAvOtC/S1s+vP/WIGp:W4oKBoKn/o8I2LphCrWST7/Sde5p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_16db64af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16db64af8dea727dd54cb9c2046fc33012e66c0c459c7a9c95667433ea530071"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-04 02:40:02"
  condition:
    hash.sha256(0, filesize) == "16db64af8dea727dd54cb9c2046fc33012e66c0c459c7a9c95667433ea530071"
}
```

### Sample 40: `45f9fb0c53194904`

| Field | Value |
|---|---|
| SHA-256 | `45f9fb0c531949041c9d33965c57e9cdd49571d7bad9c4f6f3d3f4500e38cada` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-04 02:40:01` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `759e4d0ec17891b464491a13150a9db8` |
| SHA-1 | `dab166883d642f82cac5579bd008960d4cec538b` |
| SHA-256 | `45f9fb0c531949041c9d33965c57e9cdd49571d7bad9c4f6f3d3f4500e38cada` |
| SHA3-384 | `d63142bc4562bd016ee3e24248dc80de5d415d73c240058e4060476eb7fcbb6a98d7dd36a62550048f5341ee8ac7b281` |
| TLSH | `T125533D42B70C0557D1676EF03A3F23E1A3DFDE9111A4B684250FFA4592B2E325287ED9` |
| SSDEEP | `1536:3HmqahciQLR/i1cpgI2ui4QaBn8TDls/rLOS5Ui1l:2TGiQNNoTxsHBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_45f9fb0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45f9fb0c531949041c9d33965c57e9cdd49571d7bad9c4f6f3d3f4500e38cada"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-04 02:40:01"
  condition:
    hash.sha256(0, filesize) == "45f9fb0c531949041c9d33965c57e9cdd49571d7bad9c4f6f3d3f4500e38cada"
}
```

### Sample 41: `7635a144c4278f92`

| Field | Value |
|---|---|
| SHA-256 | `7635a144c4278f92c8cd2efd3b59a000e0bcd4b4b55dd277ce0507301c746c58` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-04 02:40:01` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `118c4999abd279fbf0cc1ebb40fa67c3` |
| SHA-1 | `e6076b05071ce6a213ca78e24807c0358c334600` |
| SHA-256 | `7635a144c4278f92c8cd2efd3b59a000e0bcd4b4b55dd277ce0507301c746c58` |
| SHA3-384 | `57dd1336f2a316faa1b4ffb3ed315c9c1580c9ad21bc592199a951e2cc30fc1852edc58c81dfb5e6f359c0a3dcb4c294` |
| TLSH | `T16D336C86E782D4B6E85345F1117FA7638A32FAEA0625C687D75D7D31DC2A42083273BC` |
| TELFHASH | `t1e23137ab6ea608f8b3d4bc4ec75b43d3a235c937924161ed84f21ed137e1ea58530830` |
| SSDEEP | `1536:jH1EvsGST1QSLUuOjxLLGRxhpf6tWUzI263Thg4:qjcLyHGR7pfmhsO4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_7635a144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7635a144c4278f92c8cd2efd3b59a000e0bcd4b4b55dd277ce0507301c746c58"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-04 02:40:01"
  condition:
    hash.sha256(0, filesize) == "7635a144c4278f92c8cd2efd3b59a000e0bcd4b4b55dd277ce0507301c746c58"
}
```

### Sample 42: `363600aafcb52184`

| Field | Value |
|---|---|
| SHA-256 | `363600aafcb52184b61cbedea14e287a644c1352596a403e0bc1c087a9d2a3c6` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-08-04 02:40:00` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c849c19c647d3739dc5c89c4f559c10` |
| SHA-1 | `f4f8398f45d5eb4f4dddf41e6b7b0671529e500a` |
| SHA-256 | `363600aafcb52184b61cbedea14e287a644c1352596a403e0bc1c087a9d2a3c6` |
| SHA3-384 | `844c6c0a8160764e555030c738ef762f50506b5c591cfefd1d200d86ed662e620875af47f6fbe9e87741b971ce21be7c` |
| TLSH | `T1D9334C82F647C5F5C85309716477A77A8B31D92A8021D3A7EB58AD33ED2BD0253273AC` |
| TELFHASH | `t118313ae73e7a09ecb3d4ec4dd71592e3da26ca730a5475f940f51a5432e2ca281b1c36` |
| SSDEEP | `768:EOsaaJQnMHvea9WJTBhq4ZpqN0+TAnFCLGF/qpMDOwaHowEaOCt9YuVLnG5dBICs:EOfadHH9WVqrN0+ZLULhrmf5nmdB9g` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_363600aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "363600aafcb52184b61cbedea14e287a644c1352596a403e0bc1c087a9d2a3c6"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-04 02:40:00"
  condition:
    hash.sha256(0, filesize) == "363600aafcb52184b61cbedea14e287a644c1352596a403e0bc1c087a9d2a3c6"
}
```

### Sample 43: `09afd8afb7abfd16`

| Field | Value |
|---|---|
| SHA-256 | `09afd8afb7abfd16691468337405e0f65a9371431f1fb4d17d80526e3f9be206` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:57` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e768e1f12fd4ce345b32cb8df98dbcd` |
| SHA-1 | `5c0b4bc359a5b0e52e6bed837b0aa1b549b31fde` |
| SHA-256 | `09afd8afb7abfd16691468337405e0f65a9371431f1fb4d17d80526e3f9be206` |
| SHA3-384 | `968ccd660585b088d312b6716e9318acd9b82e6a9de6f44dc880bea8390fa43316cc068ac128d702f6e41d1acd7da721` |
| TLSH | `T187531995FC419A12C5E516B7FB1E428D772B436CD3EA330399265F21379B86B0E3B602` |
| TELFHASH | `t1ad01703088081c9d33d85901b9ec214331598afd7c3f3e1171b7dc9e1256472d91a289` |
| SSDEEP | `1536:xQ4x1eIl4OqznaEBO1W+iXHHQ5EGtWPck:fxrl4O8aOdHvt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_09afd8af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09afd8afb7abfd16691468337405e0f65a9371431f1fb4d17d80526e3f9be206"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:57"
  condition:
    hash.sha256(0, filesize) == "09afd8afb7abfd16691468337405e0f65a9371431f1fb4d17d80526e3f9be206"
}
```

### Sample 44: `64cbda8d6f960a04`

| Field | Value |
|---|---|
| SHA-256 | `64cbda8d6f960a04736830247064caeb498b55d56f93c3d7a6ed0bd3e2f88d82` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:57` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9cc5d8f48f1feef7127271d4388e202b` |
| SHA-1 | `678face8c195ea7ca1f46272fcf864735af02fc4` |
| SHA-256 | `64cbda8d6f960a04736830247064caeb498b55d56f93c3d7a6ed0bd3e2f88d82` |
| SHA3-384 | `0d648ee929655cc18dddc728f80fcc542cb6fcc3988b51742a28d70517c01c3366ba7b99134d873ef36706f1d322542f` |
| TLSH | `T184532995FD419A12C6D142B7FB1E028D772B036CD3EA33039A2A9F61378B96B0D3B545` |
| TELFHASH | `t1c31125348d485ddd66c48c6ef14d3202624a52f93c7e3816767a7d4c4b53cf3a52745d` |
| SSDEEP | `1536:3xwwn1xqBzjmHzfEoOWus9w6Dgktgb5aCv1tJ:6wGBzjsfAQlgDHJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_64cbda8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64cbda8d6f960a04736830247064caeb498b55d56f93c3d7a6ed0bd3e2f88d82"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:57"
  condition:
    hash.sha256(0, filesize) == "64cbda8d6f960a04736830247064caeb498b55d56f93c3d7a6ed0bd3e2f88d82"
}
```

### Sample 45: `cc4c9f763e6dc7e5`

| Field | Value |
|---|---|
| SHA-256 | `cc4c9f763e6dc7e564f96c4ed7982ad8a4e8a3c64b3d711570fc21eb7355eb44` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:56` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27cb7f974f0b70299b6b64b13d5e498c` |
| SHA-1 | `02b9227c6657a175553b9ac42c88ce4fd903126b` |
| SHA-256 | `cc4c9f763e6dc7e564f96c4ed7982ad8a4e8a3c64b3d711570fc21eb7355eb44` |
| SHA3-384 | `d6d8c37d089ddc981c6ecb98bd77a7af3519eef49d73840a0b3202a1414786ed7f705911b058e8510933ad73703067e4` |
| TLSH | `T1EF83D64AEF510EFBDC6FDD3742A90B0135CC560722A43B367674C928F64A64B4AE3DA4` |
| SSDEEP | `1536:RhHBaJhJURHXX1xLApxfvbvzeCQ+OiXA4m/WfP:MJU3XnspxfvgFiTn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_cc4c9f76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc4c9f763e6dc7e564f96c4ed7982ad8a4e8a3c64b3d711570fc21eb7355eb44"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:56"
  condition:
    hash.sha256(0, filesize) == "cc4c9f763e6dc7e564f96c4ed7982ad8a4e8a3c64b3d711570fc21eb7355eb44"
}
```

### Sample 46: `fa0c24efa54419db`

| Field | Value |
|---|---|
| SHA-256 | `fa0c24efa54419dbb95cac0d13e7ae2ef06770592a63d7bab53f54584077c29b` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:56` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84a77c93f1412fd7b8fa52245a5326de` |
| SHA-1 | `db27590da87c25b5201aa1a418ed00b7f72dc8ab` |
| SHA-256 | `fa0c24efa54419dbb95cac0d13e7ae2ef06770592a63d7bab53f54584077c29b` |
| SHA3-384 | `c429fc7868fc2044914452e0b7880a3632b932a375a20171bd0edcf4ab931b4abfb63a5725b86c531aa50243f48938de` |
| TLSH | `T12D83B81E6F324FFDF67C863447B74A21A39823D633E18685E2ACC1141F6124D685FBA4` |
| TELFHASH | `t15921e2480db463e467325c9a1a1dff3ad5a130df6b222c378e11a9adb7bcc825e00c0c` |
| SSDEEP | `1536:B6Ezi5qsaeCZxYxu6wzPzBULzt0e3atDkXBJT/oK:mqsXgzPtEz9atob/oK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_fa0c24ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa0c24efa54419dbb95cac0d13e7ae2ef06770592a63d7bab53f54584077c29b"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:56"
  condition:
    hash.sha256(0, filesize) == "fa0c24efa54419dbb95cac0d13e7ae2ef06770592a63d7bab53f54584077c29b"
}
```

### Sample 47: `270dcab0e04e6672`

| Field | Value |
|---|---|
| SHA-256 | `270dcab0e04e667231291b7ca501e791719813e0cec08369ee48214ebf58446c` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:55` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76f7ef07eb31d7833603c329735620aa` |
| SHA-1 | `5033e5043d9076600ea8c923ecfe79c482d51ebc` |
| SHA-256 | `270dcab0e04e667231291b7ca501e791719813e0cec08369ee48214ebf58446c` |
| SHA3-384 | `cb196ee5b472593ed947892ffdf4a388ac4b8b9ff9b589e502c216c78a530e5e7bb64aaf1660d7eb77499a153e453f61` |
| TLSH | `T1717309EBF821DDB9F809DF3744634C0AB234A36309862EB57357256EDC76194142BF8A` |
| SSDEEP | `1536:3fu8lnQq8VE/Ph82Ivoxy4ybpA9qkvQWPYDDzLhoPhA8eVjhgG:3W8l2VE/PQoU4ybpA97Qq+Y3OOG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_270dcab0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "270dcab0e04e667231291b7ca501e791719813e0cec08369ee48214ebf58446c"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:55"
  condition:
    hash.sha256(0, filesize) == "270dcab0e04e667231291b7ca501e791719813e0cec08369ee48214ebf58446c"
}
```

### Sample 48: `2b50206086057d4f`

| Field | Value |
|---|---|
| SHA-256 | `2b50206086057d4fff0b97b84005a042686a5fdba742049d9a25ab8b50a81c20` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:52` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dff14100fa5ed86154791ceb60076d7` |
| SHA-1 | `07e1391c106972ba3ef4e6830d0b1c48f5ff778f` |
| SHA-256 | `2b50206086057d4fff0b97b84005a042686a5fdba742049d9a25ab8b50a81c20` |
| SHA3-384 | `17ce947013e79d66d1ad9d6356c70309b584f1d95a1a9f41f81b867c2c3b72f1027923292679caa76d1c79780daf2ef2` |
| TLSH | `T11FE31A46E6418B13C0D22B79BBDF425533239B28D7AB63069928BFF43F4279A4E27505` |
| TELFHASH | `t170211072a274d1226e208c589e5e9ff2013a87223356ab77ff22e4dc543b4019515c6f` |
| SSDEEP | `3072:oouaRCj0nmaXypPW4n4w3x3bq0w32Mn5M/94C8mIPLWxuJf:JuaR80nmaX2PWK3x3bqr32M5M/94C8mm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_2b502060
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b50206086057d4fff0b97b84005a042686a5fdba742049d9a25ab8b50a81c20"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:52"
  condition:
    hash.sha256(0, filesize) == "2b50206086057d4fff0b97b84005a042686a5fdba742049d9a25ab8b50a81c20"
}
```

### Sample 49: `fbd757b745b5dbe3`

| Field | Value |
|---|---|
| SHA-256 | `fbd757b745b5dbe31420a15ad26ee95a20ea614cc35eb5fece7da72040732797` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:51` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a313071573c51c177c670c1587a4cb9b` |
| SHA-1 | `7745b78f7835f00b0d4da9b8a27a5827571d3d82` |
| SHA-256 | `fbd757b745b5dbe31420a15ad26ee95a20ea614cc35eb5fece7da72040732797` |
| SHA3-384 | `b4837946cb834cd1ced24c0354dc926ff834d3431da2e6bb1e710f7b5d8a25a137b7d55be19ff65915b4e9b0006e2e8e` |
| TLSH | `T1BE73199AFD819B11D5D216BAFE0E124E7323073CD3EE72169D24AF30678696B0E3B505` |
| TELFHASH | `t1af012b118f4c1cec72e7e42982bd6612312835eb3d111813b3fdaddd8e17cd1591941d` |
| SSDEEP | `1536:+Bn9PjtzWYJaelI3XFgFkMHiymtRy6/Uwdp/HR5sY/VZ:ohzWYJaYeamt46Xp/xGm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_fbd757b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbd757b745b5dbe31420a15ad26ee95a20ea614cc35eb5fece7da72040732797"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:51"
  condition:
    hash.sha256(0, filesize) == "fbd757b745b5dbe31420a15ad26ee95a20ea614cc35eb5fece7da72040732797"
}
```

### Sample 50: `2e2a591728f7579b`

| Field | Value |
|---|---|
| SHA-256 | `2e2a591728f7579bfd716d35ccd5d2bdeca939c6794ce034e7aad99346714d2c` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:46` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d354f7cfce218aaa4a4678ab810a7f4` |
| SHA-1 | `bbb29305830f4b34ee00481937cb7f8448a7b9af` |
| SHA-256 | `2e2a591728f7579bfd716d35ccd5d2bdeca939c6794ce034e7aad99346714d2c` |
| SHA3-384 | `bec4c98a0208f51abaa663358ab5af12dd5245b7089010a14c5f887ca18372ee3a3409d87c31b06dfa3c3805d1ec78de` |
| TLSH | `T174736C17F4C090FDC99DE2745BAEA326E93770391134B22E27C4EE267E9DE211E5E250` |
| TELFHASH | `t1be31f5b13d553ed0e1e7fc77a206e16ac9391e3110e039f28ab299f5f7213420c66827` |
| SSDEEP | `1536:pj8pRV8QzKCu2l/laVwi+/nurTg53qqRu:URV8QzY2pl9i+0TgJHE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_2e2a5917
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e2a591728f7579bfd716d35ccd5d2bdeca939c6794ce034e7aad99346714d2c"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:46"
  condition:
    hash.sha256(0, filesize) == "2e2a591728f7579bfd716d35ccd5d2bdeca939c6794ce034e7aad99346714d2c"
}
```

### Sample 51: `998f4b03231f4cc9`

| Field | Value |
|---|---|
| SHA-256 | `998f4b03231f4cc9253754fcda3aa32b0435a10880568fd128e5351ec76489ab` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:45` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d9b9a89c70706dbadaffb9ffd2e054a` |
| SHA-1 | `91e6b641013a73b0d328ae13d82bc9e67a95653b` |
| SHA-256 | `998f4b03231f4cc9253754fcda3aa32b0435a10880568fd128e5351ec76489ab` |
| SHA3-384 | `1505313d2c845ec1140a58efcb9daee540c3a953aaf5f9b8326a7dd84bbbd5fc8e62c93b45b8457a624e9af0fb69b6dc` |
| TLSH | `T1A6636D85FA53E0F2E9631172113FA7679A32E63A4025CA87D72C6F32DC67401DA2736C` |
| TELFHASH | `t1954136eb2eae1cf8f3d1dc4cc31e2e93a63ae66b192132a441f2595132e39d15075c34` |
| SSDEEP | `1536:j71SzkGuerW7Mbzonf2gIsHFw7JBzEzd5FjG6FjFgU+TZgh:NVG/Af2gEJFEzEc9yWh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_998f4b03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "998f4b03231f4cc9253754fcda3aa32b0435a10880568fd128e5351ec76489ab"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:45"
  condition:
    hash.sha256(0, filesize) == "998f4b03231f4cc9253754fcda3aa32b0435a10880568fd128e5351ec76489ab"
}
```

### Sample 52: `e65abd6d9c1ee8f6`

| Field | Value |
|---|---|
| SHA-256 | `e65abd6d9c1ee8f6adca6dd3b9b389e70eb3c451643f2f23cca3274e66860e2d` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:44` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6613d08fe0ea708b72293a5acef05cb7` |
| SHA-1 | `c1c57f552abb4e8e3fc9fd38935aea893577a8ba` |
| SHA-256 | `e65abd6d9c1ee8f6adca6dd3b9b389e70eb3c451643f2f23cca3274e66860e2d` |
| SHA3-384 | `afe6ab3792f8a4e2e4c56f7b55e775dbfee36e7ce8d820f4ab68a6f68a38adc8e829f3e46a98b403959e649e8932a814` |
| TLSH | `T1D7833B26BE764C2BC5C4647A62E30735F2FB438724BCCA1A3E610D8CAF6565032677E5` |
| SSDEEP | `768:RPuH0UAryBIBW/tiSC0XjIO+l95VkeLpIe6Gt8odpgO/iAKVteJSYx7vn1LofTIR:4hAGUitiz02l95DwUpgGiLtqxKfT7e` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_e65abd6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e65abd6d9c1ee8f6adca6dd3b9b389e70eb3c451643f2f23cca3274e66860e2d"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:44"
  condition:
    hash.sha256(0, filesize) == "e65abd6d9c1ee8f6adca6dd3b9b389e70eb3c451643f2f23cca3274e66860e2d"
}
```

### Sample 53: `6e8375102046ab69`

| Field | Value |
|---|---|
| SHA-256 | `6e8375102046ab698aa2a81457edef9aaf6ab1a3e08ce42406ea8e33f62870ee` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:43` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56e4fdcbbf9994da35b200c2ae585e2c` |
| SHA-1 | `aa3ed9b8d8844845e5a75d366d518f34dbd8851a` |
| SHA-256 | `6e8375102046ab698aa2a81457edef9aaf6ab1a3e08ce42406ea8e33f62870ee` |
| SHA3-384 | `b3fe234eb9518032368cdddd36cd116a795e5d83ee8725d84cfe30964adc03a65e42cc25c6b5cb984e11492a79e53dad` |
| TLSH | `T18A638C67C82A6E08D115A6F0B0B19B391B63D56081CB0FF96666C779D083ECCF605BF8` |
| SSDEEP | `1536:DuLdvs9G51KYx7QHsmICCMBsv7cingFH61:tFYfmICFspgI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_6e837510
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e8375102046ab698aa2a81457edef9aaf6ab1a3e08ce42406ea8e33f62870ee"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:43"
  condition:
    hash.sha256(0, filesize) == "6e8375102046ab698aa2a81457edef9aaf6ab1a3e08ce42406ea8e33f62870ee"
}
```

### Sample 54: `cfc08d5ae14fe953`

| Field | Value |
|---|---|
| SHA-256 | `cfc08d5ae14fe95345dd920e223eb5ace0793c0d328cab3d68909b805b132378` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:42` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72d57f1b1725625bbc2c7c000b0aa266` |
| SHA-1 | `0d4ed499323629e1217971b506e7fdf3b8173fce` |
| SHA-256 | `cfc08d5ae14fe95345dd920e223eb5ace0793c0d328cab3d68909b805b132378` |
| SHA3-384 | `384a737ba226e5f6a7210ce39ed35eaa2b93c370fa52b54618a9648e97a5919a3c6366198e324e893ddf6c497e73c165` |
| TLSH | `T187833B02B71D0943D1672EF03A3B33E5E39FEAD011B4E684265EBA8591B1A335186EDD` |
| SSDEEP | `1536:ZLuvNrw1M/WAGQ9fcwMujypgJQ10JO3X2wiZYIn6Q1KZT+iMQpF7:MpKMuBUjJjwiZ+Q4Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_cfc08d5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfc08d5ae14fe95345dd920e223eb5ace0793c0d328cab3d68909b805b132378"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:42"
  condition:
    hash.sha256(0, filesize) == "cfc08d5ae14fe95345dd920e223eb5ace0793c0d328cab3d68909b805b132378"
}
```

### Sample 55: `8d759c64d6c49f1d`

| Field | Value |
|---|---|
| SHA-256 | `8d759c64d6c49f1d87c1be2b590990d72ef946184f956cb6bbbb00ce443e17a7` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:41` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc4da9ffe5fa0b76e5248b3b199ce00b` |
| SHA-1 | `012c4d335fa02494b2ae80daaa37a578799c9ef6` |
| SHA-256 | `8d759c64d6c49f1d87c1be2b590990d72ef946184f956cb6bbbb00ce443e17a7` |
| SHA3-384 | `919d9e144addbeafbae086d645727af412448c6095ecfc26425ff79155fc4bc3c098400b7ddb3b1ca8921782405dcacc` |
| TLSH | `T198A3C50AEF600EFBD86FDE3745A90A0535CC554722A83B3A7674C928F64A54B4AF3C74` |
| SSDEEP | `1536:AX/710ISFGVmDeC3Td4Jq2GtkZ26ffGVjFpeIvqi3B5yDTV/L3FQl:K/72nBt2t8baiMTVbF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_8d759c64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d759c64d6c49f1d87c1be2b590990d72ef946184f956cb6bbbb00ce443e17a7"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:41"
  condition:
    hash.sha256(0, filesize) == "8d759c64d6c49f1d87c1be2b590990d72ef946184f956cb6bbbb00ce443e17a7"
}
```

### Sample 56: `cff2d7f00e2d3dab`

| Field | Value |
|---|---|
| SHA-256 | `cff2d7f00e2d3dab42786b56e1d565c4e5dae6c28440d05090897bed645ece7e` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:41` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6e866e9fafe5d11cf1a15e9f7a35763` |
| SHA-1 | `4bf7a1d6e5843bad03626f4c1a2ae668b991a3bb` |
| SHA-256 | `cff2d7f00e2d3dab42786b56e1d565c4e5dae6c28440d05090897bed645ece7e` |
| SHA3-384 | `750f41082f571dcea6df39a5739fd4b041a37d6a488c69bff0e70125d4a2aa901889d2b2d48a4578c270c950490c7e70` |
| TLSH | `T19FA3A91E6E319FBDF578873047B74B30939D63D623E19685E2ACC1141F6024E681FBA8` |
| TELFHASH | `t1a521af4848b823f097704d992addff77e5b130df1b266e378e11a9a9a5bdd425e00c1c` |
| SSDEEP | `1536:X774B8PhdWllcoUu11HHAuGnNgkC5Wq9ebkZpz6BRFXcbfLbTe0n:hPmHArnK1WqNpz6BR9crK0n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_cff2d7f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cff2d7f00e2d3dab42786b56e1d565c4e5dae6c28440d05090897bed645ece7e"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:41"
  condition:
    hash.sha256(0, filesize) == "cff2d7f00e2d3dab42786b56e1d565c4e5dae6c28440d05090897bed645ece7e"
}
```

### Sample 57: `be6849de8d422b60`

| Field | Value |
|---|---|
| SHA-256 | `be6849de8d422b60f886f6c384cbc344cb976c3ead185d904bed04bcfc6a5a2f` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:40` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `678d83660fe57536e63a0474f2ee9372` |
| SHA-1 | `f215dc5cab362aff909592237d3ee5d27704555d` |
| SHA-256 | `be6849de8d422b60f886f6c384cbc344cb976c3ead185d904bed04bcfc6a5a2f` |
| SHA3-384 | `d2cfea0de76ad795f5cae10e0b9a368fa1ce402880a5a1200cf77a8c936fbafd97e5c22ca816c333d6fc9300a7d20dcb` |
| TLSH | `T1F6933BD7F840EF79F809D7774593081AB230ABA189875BB63207296BEC361D41877F86` |
| SSDEEP | `1536:S5+xca3RbtoDJ82Cvwb6vycwYAYkovheBShDIJDKcFA128AahA1Jxgj:S0xca3NtoDqw2vycwYAohkSZIe1285hR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_be6849de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be6849de8d422b60f886f6c384cbc344cb976c3ead185d904bed04bcfc6a5a2f"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:40"
  condition:
    hash.sha256(0, filesize) == "be6849de8d422b60f886f6c384cbc344cb976c3ead185d904bed04bcfc6a5a2f"
}
```

### Sample 58: `c1d94a4e5f38ee96`

| Field | Value |
|---|---|
| SHA-256 | `c1d94a4e5f38ee96f0c95fff899271929a8c2cbf7149af23a3e9f969bde29775` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:34` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1ef9e2eb2af24c04eff7a15532c8e7e` |
| SHA-1 | `fcc9a3eff6daee965dc7d8a4d132cd145e612661` |
| SHA-256 | `c1d94a4e5f38ee96f0c95fff899271929a8c2cbf7149af23a3e9f969bde29775` |
| SHA3-384 | `912838c07b36216f4810a2f3fde6c01b5e000bb10121cf990b143dd441b45b7855842121b5abeefe5d2e9d7a11dcdec6` |
| TLSH | `T105634B81F653C4F5D8531171507AB77FCB32DA164031C64BEB2A9F36DD27842AA273A8` |
| TELFHASH | `t1f441e4f73e7a09e8f3d47c4c8b1e5b525b6a99731a2132e940f2596132daed1c0b4c39` |
| SSDEEP | `1536:mMlKbMX8gWqAWcjIKIijm286MzAKo/7OSA9g:edjfIKIijm28RAKoyq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_c1d94a4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1d94a4e5f38ee96f0c95fff899271929a8c2cbf7149af23a3e9f969bde29775"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:34"
  condition:
    hash.sha256(0, filesize) == "c1d94a4e5f38ee96f0c95fff899271929a8c2cbf7149af23a3e9f969bde29775"
}
```

### Sample 59: `036f5b0ccd595315`

| Field | Value |
|---|---|
| SHA-256 | `036f5b0ccd595315d4c10fca45bca7fcbb786d93b01c42d5b979bc5d45c02d46` |
| Family label | `Mirai` |
| File name | `dbg` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:33` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dc6423df0fa01f34aa767414e4d4a43` |
| SHA-1 | `8a6a785dd6687feb64cd160181428c1dc6194456` |
| SHA-256 | `036f5b0ccd595315d4c10fca45bca7fcbb786d93b01c42d5b979bc5d45c02d46` |
| SHA3-384 | `beaea3c366d6d86d173fbf7c32477333762a1dd932a813cdb575cdb26664f92d597773c4bdd495d5b24c463f0bcc55f9` |
| TLSH | `T11B737C17E59090FDC899E2755BAE6232D933B03D1231B22E23C4ED627E6DE212F6D750` |
| TELFHASH | `t1a231efb5696438d0e1fbfd737206e029c8390e7018e13af79a72adf6db167850c6a417` |
| SSDEEP | `1536:BZOvkXi/jUFITQwd8VJ5m2vxesldiWeK1VPy3sERu:JXiLUFhwCz5FeslIk1VPuXE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_036f5b0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "036f5b0ccd595315d4c10fca45bca7fcbb786d93b01c42d5b979bc5d45c02d46"
    family = "Mirai"
    file_name = "dbg"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:33"
  condition:
    hash.sha256(0, filesize) == "036f5b0ccd595315d4c10fca45bca7fcbb786d93b01c42d5b979bc5d45c02d46"
}
```

### Sample 60: `835dd72dbd00dc43`

| Field | Value |
|---|---|
| SHA-256 | `835dd72dbd00dc430061807cac9522b1845f8afec4091c93d6542d123dc5c747` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:32` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d59abe2b02ec748b7901eedfd764bc8` |
| SHA-1 | `de21625a55b5b3b2e08926fe9ccabb58f6bcf5ab` |
| SHA-256 | `835dd72dbd00dc430061807cac9522b1845f8afec4091c93d6542d123dc5c747` |
| SHA3-384 | `bfbd4d8233ef276a1fbc43e81f27d0bbc9184f5c0df3c21772f24d188ad924cb88122090aaad652fd20e6edb86a84d1c` |
| TLSH | `T10473F795FD409B92C9C216BBFB1E428D772A4368D3FA330399259F21379B85B0E3B511` |
| TELFHASH | `t17721c0618988895de3c0d54ea19ed161153875b6ba72282d7e7aea2ec3cb4e17820073` |
| SSDEEP | `1536:kMIXSnQDzWMUf3CxW8OSz6gJF2MCImcO+KAGYS5vt:1ICnQDzWMmSxrFUrIfWL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_835dd72d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "835dd72dbd00dc430061807cac9522b1845f8afec4091c93d6542d123dc5c747"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:32"
  condition:
    hash.sha256(0, filesize) == "835dd72dbd00dc430061807cac9522b1845f8afec4091c93d6542d123dc5c747"
}
```

### Sample 61: `f7be5b76f4d34cb0`

| Field | Value |
|---|---|
| SHA-256 | `f7be5b76f4d34cb064557bf6392debf71d1b3448af63c7e99c24495722980cf0` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:32` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3b169a9a75ab954c23f857e9aba088c` |
| SHA-1 | `2c3d143901092d233ee8906c2ceb02e7ae70c269` |
| SHA-256 | `f7be5b76f4d34cb064557bf6392debf71d1b3448af63c7e99c24495722980cf0` |
| SHA3-384 | `164752b96c21145b82731d7e38458e37501153d72bc312be0a4f533501ba46cb3d8ebe35819e09a962844a53f352173d` |
| TLSH | `T15DF32B46EA418B53C0D61BB9FB9F824533239B24D7A763059928BFF43F4279E4E27205` |
| TELFHASH | `t17c311032a225d5276e3088649e2e9bf2012a872262956b73ef37d5dc552b4029516c1f` |
| SSDEEP | `3072:ido3QYaZF3Ewtarhg/TA6Bww9yqPOF+VveS4x262/M/9gepAmqS7YStQ6:VQYaZNEwtay/Tww9ZPOUVve9x26iM/9d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_f7be5b76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7be5b76f4d34cb064557bf6392debf71d1b3448af63c7e99c24495722980cf0"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:32"
  condition:
    hash.sha256(0, filesize) == "f7be5b76f4d34cb064557bf6392debf71d1b3448af63c7e99c24495722980cf0"
}
```

### Sample 62: `a64edd8f53f76ed2`

| Field | Value |
|---|---|
| SHA-256 | `a64edd8f53f76ed2af41dca7396e3bf14f9b26d7f64cc9d125a1e84bf87f504c` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:31` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0d3b194894d87b17ffe38890afe92f0` |
| SHA-1 | `bc8ca3d7ff910c0e3fe69e1e61e137002742483d` |
| SHA-256 | `a64edd8f53f76ed2af41dca7396e3bf14f9b26d7f64cc9d125a1e84bf87f504c` |
| SHA3-384 | `c5efb2fe7355ce5420010dd4f1f11490dc09526a3d9bf4f1d6521bb29844e8da0ef87ae9053adc9cd2f1a2473bc94560` |
| TLSH | `T1D983089AFD819B11D5C156BAFE0E214E7313077CD3EE72129E24AF20678796B0E3B505` |
| TELFHASH | `t13d01ce208e4c6ccdb9e0829c11ed66c75d2475363e7c08807efe8dae5192cf21020e36` |
| SSDEEP | `1536:hgnqyiJN4htWYxa8w0/OJsFaMZiZ8FwOuhMW07YCw5+YzIoZ:fyQ2WYxa3Gg8FwOuhMW0TwI6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_a64edd8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a64edd8f53f76ed2af41dca7396e3bf14f9b26d7f64cc9d125a1e84bf87f504c"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:31"
  condition:
    hash.sha256(0, filesize) == "a64edd8f53f76ed2af41dca7396e3bf14f9b26d7f64cc9d125a1e84bf87f504c"
}
```

### Sample 63: `c6467b63a9998524`

| Field | Value |
|---|---|
| SHA-256 | `c6467b63a99985244bb1f6d10ff9312f36bb4829b935980c98bc19f1ec2ed4c3` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-08-04 02:39:31` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81556e397f3aba0ed8e52587b0dcf700` |
| SHA-1 | `8b32e748100e9e91506153ef7455d56c5b54efb5` |
| SHA-256 | `c6467b63a99985244bb1f6d10ff9312f36bb4829b935980c98bc19f1ec2ed4c3` |
| SHA3-384 | `cc42998e6facd9ce4139998f244a18d836213a550a38ec48b132b76452c13b0404dc532fac10eed76e5467b123a0d175` |
| TLSH | `T158831A95FD408B52CAC256BBFB1E428D772B0368D3FA32079A255F61378B85B0E3B151` |
| TELFHASH | `t11d219d754a4809b863c0d4aee0df9012155825f92b73280ebf7eaa5e96cb8d2a534836` |
| SSDEEP | `1536:ko8P5Hwh5vbVrBR3YiWrOXcUX0mT4r2DtCni1wLvrCt:kxP5wh5vbVrjIiSZmcK58W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_c6467b63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6467b63a99985244bb1f6d10ff9312f36bb4829b935980c98bc19f1ec2ed4c3"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:31"
  condition:
    hash.sha256(0, filesize) == "c6467b63a99985244bb1f6d10ff9312f36bb4829b935980c98bc19f1ec2ed4c3"
}
```

### Sample 64: `8b84fede49c33a63`

| Field | Value |
|---|---|
| SHA-256 | `8b84fede49c33a6375c6994884f6079ef8db1638ac1ee8426dfd645edaa7dfdb` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-04 02:37:46` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d171a13da558af9bb98f660c24225954` |
| SHA-1 | `d7286b406db2235553c592cf1707842f355269f9` |
| SHA-256 | `8b84fede49c33a6375c6994884f6079ef8db1638ac1ee8426dfd645edaa7dfdb` |
| SHA3-384 | `3633297e657e12494f0a745f6a3e7ef0c0e43c38b713dbdb5a4320381f5be718c8ecdf9d30d553c0f832a2a295e383c4` |
| TLSH | `T184E31A09BFA00FFBE89FCD3345E90B5A258D691713A53F3A7574D828F15A24B0AD3864` |
| SSDEEP | `1536:MaDa8hOy/sq2AwaHaEP1I+ulOKmiuIcU8AnDTczElcrQeArHxCLKuFEyZC8p/X0Z:zG8Tzz1gcU8AHcYzMLKuEoof9tNAt4x` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_8b84fede
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b84fede49c33a6375c6994884f6079ef8db1638ac1ee8426dfd645edaa7dfdb"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-04 02:37:46"
  condition:
    hash.sha256(0, filesize) == "8b84fede49c33a6375c6994884f6079ef8db1638ac1ee8426dfd645edaa7dfdb"
}
```

### Sample 65: `dd55efc4766c21d6`

| Field | Value |
|---|---|
| SHA-256 | `dd55efc4766c21d6a1a974a8636f7174353e10b8367fec0021d7a364a0d2f64e` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-04 02:37:44` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `424c61ddd84544219d9c743121903a07` |
| SHA-1 | `31e06f8f7fd69c8cf60e39bfd6c479eaff4a005a` |
| SHA-256 | `dd55efc4766c21d6a1a974a8636f7174353e10b8367fec0021d7a364a0d2f64e` |
| SHA3-384 | `ec2ece8cf5ba23306a142d4b1010d0319b9dc238250a7f2944fe91d2970656d158f3ecdfc860fb986745dc39e3f9c2c0` |
| TLSH | `T10EE3E81FBE619F6CF7A883350BF74E34A29927C627D1C546D26CE2101E6028E645FFA4` |
| TELFHASH | `t1e721955c4e7423e467325c995a6dfbb7e56030df2a256d378e11786d6b6cc824e20c0c` |
| SSDEEP | `3072:YCXPgmH01jehCsNMv0bba5hMgAHkkc73C8u/26U4ch:YC/gukvlKN4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_dd55efc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd55efc4766c21d6a1a974a8636f7174353e10b8367fec0021d7a364a0d2f64e"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 02:37:44"
  condition:
    hash.sha256(0, filesize) == "dd55efc4766c21d6a1a974a8636f7174353e10b8367fec0021d7a364a0d2f64e"
}
```

### Sample 66: `75289c50ef398215`

| Field | Value |
|---|---|
| SHA-256 | `75289c50ef39821585cf68d36aebb6b46f184d4089182ea23cceab96323222d0` |
| Family label | `Sliver` |
| File name | `tyler-v6.iso` |
| File type | `iso` |
| First seen | `2026-08-04 02:36:24` |
| Reporter | `BlinkzSec` |
| Tags | `Sliver` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c78c6f9901e47d23a97a71350c9de79` |
| SHA-1 | `0db80f6c404c8cad57a54ec454fc6b3e6a1ee316` |
| SHA-256 | `75289c50ef39821585cf68d36aebb6b46f184d4089182ea23cceab96323222d0` |
| SHA3-384 | `5c7bda7240bc3591679c2bfa97795492f30c2eaed94b290b2b7bee167e99e4911e95454df3f5e4c4d88eec876b8e296d` |
| TLSH | `T149D6AD12B5A08074F4A73231B43D67B949327EA29B3185CFB65C7C845F786E2613A39F` |
| SSDEEP | `393216:czABUF+eOFLXBpbbSnW0uXhVwNdqcn5C7midi+z8vHJiaVb/8dtU1MsotbvAtc:6F2VwNrn5Dstb4tc` |

#### Technical Assessment

- The sample is tracked as `Sliver` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Sliver_066_75289c50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75289c50ef39821585cf68d36aebb6b46f184d4089182ea23cceab96323222d0"
    family = "Sliver"
    file_name = "tyler-v6.iso"
    file_type = "iso"
    first_seen = "2026-08-04 02:36:24"
  condition:
    hash.sha256(0, filesize) == "75289c50ef39821585cf68d36aebb6b46f184d4089182ea23cceab96323222d0"
}
```

### Sample 67: `c61382e927b0020d`

| Field | Value |
|---|---|
| SHA-256 | `c61382e927b0020d7d55b9901648b9fb4b5d050c24f16e09bd66e8bde34d2fcd` |
| Family label | `Mirai` |
| File name | `miron.x86_64` |
| File type | `elf` |
| First seen | `2026-08-04 02:26:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eebafee524a7134d451b55fda8cc1886` |
| SHA-1 | `286d777c379a53c61091b85a6ef4540697ea6c3d` |
| SHA-256 | `c61382e927b0020d7d55b9901648b9fb4b5d050c24f16e09bd66e8bde34d2fcd` |
| SHA3-384 | `df62fed2a9ac044e36d4796c0df79b97274af6968e551bf4318d0b07b333a052b4ba2fd99e0baad08f45a1bfceb5408e` |
| TLSH | `T17F23020542B27003CF0D6779BE445CFD27D5F0A627B9742A5945F0A61638DAC8CF1D93` |
| SSDEEP | `768:jaV+sb8KQAGzVrl592aoykUDjzmqI3+xXTL7dKlp6kScIDyQdcKADzGLcscy:ugO8LRR92tUDeqI3uTElpxScIDxdcNqh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_c61382e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c61382e927b0020d7d55b9901648b9fb4b5d050c24f16e09bd66e8bde34d2fcd"
    family = "Mirai"
    file_name = "miron.x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:26:49"
  condition:
    hash.sha256(0, filesize) == "c61382e927b0020d7d55b9901648b9fb4b5d050c24f16e09bd66e8bde34d2fcd"
}
```

### Sample 68: `168135afc7ed9948`

| Field | Value |
|---|---|
| SHA-256 | `168135afc7ed99484e1ee0774b57c7c77ecd222b40821afef63392f5ea4b3d5c` |
| Family label | `Mirai` |
| File name | `miron.armv7l` |
| File type | `elf` |
| First seen | `2026-08-04 02:24:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b113656aa30bd1f90133cc81a997458` |
| SHA-1 | `14c6d41f53e7252206e1d091490370b667836cb5` |
| SHA-256 | `168135afc7ed99484e1ee0774b57c7c77ecd222b40821afef63392f5ea4b3d5c` |
| SHA3-384 | `dfd47128118ae9803ee55f853b9cec79bfa8b8fb2b281cdfd60b58dda869e58aee6f6a3ad20c37ece6787eb2ef4f363d` |
| TLSH | `T1CF33194AFD819F05D4D521FAFF0E114A33175B6CE3EE7202AE255B2523CA96B0F36906` |
| TELFHASH | `t1c8d02244814c8dfca3cce1b6b27b5224282904a20a103d41f26a982e0223ed7086041c` |
| SSDEEP | `768:VVnLgszu1g1NswZs1UjTXQkwsGqTeMewhY6SAPPQnl6CKW4/YFNi1M0HY1LDf4t6:VVnLs3d1Gp6MxhYXAPPQl2gFNiKR1f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_168135af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "168135afc7ed99484e1ee0774b57c7c77ecd222b40821afef63392f5ea4b3d5c"
    family = "Mirai"
    file_name = "miron.armv7l"
    file_type = "elf"
    first_seen = "2026-08-04 02:24:24"
  condition:
    hash.sha256(0, filesize) == "168135afc7ed99484e1ee0774b57c7c77ecd222b40821afef63392f5ea4b3d5c"
}
```

### Sample 69: `1c8d75b82fa11334`

| Field | Value |
|---|---|
| SHA-256 | `1c8d75b82fa11334ee40d7f09393b2f78396489428b5d8ea105ea3b57ae61484` |
| Family label | `Mirai` |
| File name | `miron.armv7l` |
| File type | `elf` |
| First seen | `2026-08-04 02:23:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d351a6b30f1186f817afb36022e7e5c` |
| SHA-1 | `816fa54f5aa1915013e3370437db720ac70f551d` |
| SHA-256 | `1c8d75b82fa11334ee40d7f09393b2f78396489428b5d8ea105ea3b57ae61484` |
| SHA3-384 | `cc4fca3288d4c3234fe9b18df284d91f823f606f2ac2b751073091341eb190f0843f1b62568be2fbaea80c88afea60c7` |
| TLSH | `T11CD2E053430A3EB3D9081F7B177644BBC27693612C16881753B05E2E07BAD6BDE15987` |
| SSDEEP | `768:CWKuIJxsVb/7iPgJ+O0RtCK8wv+1Qum7/fPN62eDAg7CE90:CJuisVcgUOmtCK831napciE90` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_1c8d75b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c8d75b82fa11334ee40d7f09393b2f78396489428b5d8ea105ea3b57ae61484"
    family = "Mirai"
    file_name = "miron.armv7l"
    file_type = "elf"
    first_seen = "2026-08-04 02:23:34"
  condition:
    hash.sha256(0, filesize) == "1c8d75b82fa11334ee40d7f09393b2f78396489428b5d8ea105ea3b57ae61484"
}
```

### Sample 70: `79df04757d6927d1`

| Field | Value |
|---|---|
| SHA-256 | `79df04757d6927d13860cff93c5f9c1cef787761f16688eb0a6b62feef29762c` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-08-04 02:20:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad79ff2cf55187265d5acb6b2726771f` |
| SHA-1 | `b6cbaf7af932632c5189a5619af6b8c73af2c290` |
| SHA-256 | `79df04757d6927d13860cff93c5f9c1cef787761f16688eb0a6b62feef29762c` |
| SHA3-384 | `5d586f92036744cecfc9f4c1246824ccd9986fa6f22f6b588e482a1059286821c34ab886561c812a2fb5753cc4926684` |
| TLSH | `T16DD32A86FC824A22C5D722BEF92D218E331317B8E3DE32229D145F2177C659B0E77A55` |
| TELFHASH | `t149b012261f884f4869d050c050ef204913e0651303242c77c44d8f034911981f51ca22` |
| SSDEEP | `3072:FCfI7MV9hHvoeGOku7JafpDfxtKE4RuoHc:0fxHwMkuNaFDKE3oHc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_79df0475
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79df04757d6927d13860cff93c5f9c1cef787761f16688eb0a6b62feef29762c"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-04 02:20:41"
  condition:
    hash.sha256(0, filesize) == "79df04757d6927d13860cff93c5f9c1cef787761f16688eb0a6b62feef29762c"
}
```

### Sample 71: `804d8830744c3f42`

| Field | Value |
|---|---|
| SHA-256 | `804d8830744c3f429686379f84b6b6bbdccc8c5c05af2a443ad4a2e73026b19e` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-08-04 02:19:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a671e39273fca5ca323ce2c6b38979b6` |
| SHA-1 | `3be7832406cacaead44f639ef4be1c829ebc9cd3` |
| SHA-256 | `804d8830744c3f429686379f84b6b6bbdccc8c5c05af2a443ad4a2e73026b19e` |
| SHA3-384 | `888dd996242b398b04471c9e957dabcd42648c92adc35115632f17f7bc0fd5f7915b9b27057e411664ddfb7131b6dda2` |
| TLSH | `T13A33012151923E6FAC131C70FAFEA995DA427EFCA05738520884592D34F3E66F8BA0C1` |
| SSDEEP | `768:oSWl8Bqn4Lrd4c0cufurrNXkOrCn41Y3EeXem5Pj52vqn/UAccuEqABfEcrWWv1/:ob4Lrd4JcufkCzOajIqn/UITRBfaW6LM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_804d8830
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "804d8830744c3f429686379f84b6b6bbdccc8c5c05af2a443ad4a2e73026b19e"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-04 02:19:21"
  condition:
    hash.sha256(0, filesize) == "804d8830744c3f429686379f84b6b6bbdccc8c5c05af2a443ad4a2e73026b19e"
}
```

### Sample 72: `9797d77b700b481d`

| Field | Value |
|---|---|
| SHA-256 | `9797d77b700b481dd845982f0bf879d3d9bfcd3b7c3db4fb1f488a4ea49790a9` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-04 02:19:20` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9491ab13186932a406847c9f8aec4625` |
| SHA-1 | `730574a1027afef038e261a3efbf94de91ed9f01` |
| SHA-256 | `9797d77b700b481dd845982f0bf879d3d9bfcd3b7c3db4fb1f488a4ea49790a9` |
| SHA3-384 | `2364eff5056543e262891353cf4eecccdff59940b2f6f517457ebe674d08282c20151c5181cec5099760aca4eb8bd7b3` |
| TLSH | `T18DC27D966A867C44BEC94A3E4CBD2B0D6DF5C3D1324942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:Ko8vCB+25j6es8Rbi9FYpMSUpi+20qUpi+20YQX:p8l25Jod2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_9797d77b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9797d77b700b481dd845982f0bf879d3d9bfcd3b7c3db4fb1f488a4ea49790a9"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-04 02:19:20"
  condition:
    hash.sha256(0, filesize) == "9797d77b700b481dd845982f0bf879d3d9bfcd3b7c3db4fb1f488a4ea49790a9"
}
```

### Sample 73: `555d78938859dc3b`

| Field | Value |
|---|---|
| SHA-256 | `555d78938859dc3b4ea2b6f148363b1f8434dd071ab1a8f5dbdb8d21a0ca4337` |
| Family label | `unknown` |
| File name | `dropper.sh` |
| File type | `sh` |
| First seen | `2026-08-04 02:19:19` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a87e51c910aba6862fd14a02e30c108e` |
| SHA-1 | `f9fe19cb21a9e2bee457592c3c1370e1750c8959` |
| SHA-256 | `555d78938859dc3b4ea2b6f148363b1f8434dd071ab1a8f5dbdb8d21a0ca4337` |
| SHA3-384 | `c9bbf44c5171b5f2a3859814e95ba0fc27ceb79d1dcd52506be6f72b20b4192bb46019c03e937dfb99ad86bdc7cee5a0` |
| TLSH | `T16F9174F4F83C6A23B48C0558B45C5616EEA7693F56A43C51B087BDAD233E00A71B9336` |
| SSDEEP | `96:9GFQyF/51AEd+C0Mk0XWNcsNQvEu0vatgZ/tr2kd:kQyx515dR0hHNcsNQvKv9Ld` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_555d7893
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "555d78938859dc3b4ea2b6f148363b1f8434dd071ab1a8f5dbdb8d21a0ca4337"
    family = "unknown"
    file_name = "dropper.sh"
    file_type = "sh"
    first_seen = "2026-08-04 02:19:19"
  condition:
    hash.sha256(0, filesize) == "555d78938859dc3b4ea2b6f148363b1f8434dd071ab1a8f5dbdb8d21a0ca4337"
}
```

### Sample 74: `482419cf06b8c073`

| Field | Value |
|---|---|
| SHA-256 | `482419cf06b8c073ba3e9f5bbe665c6c797276b55218f927dda753bd859c28a3` |
| Family label | `WannaCry` |
| File name | `482419cf06b8c073ba3e9f5bbe665c6c797276b55218f927dda753bd859c28a3` |
| File type | `exe` |
| First seen | `2026-08-04 02:15:23` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8eb101ec4f1af4001893fa7f22bc987` |
| SHA-1 | `fc30b97a314f61d332e8af269bfc1bf1869db2e3` |
| SHA-256 | `482419cf06b8c073ba3e9f5bbe665c6c797276b55218f927dda753bd859c28a3` |
| SHA3-384 | `218ca5e12c84278f18db794f399d66b796e0cff51ff84a388b8d487b3505e7815178a8d4e2729a61e23f5a24643623b5` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T16E36F601D2E51AA0DAF25FF7267ADB10933A6E45895BA66E1221500F0C77F0CDDE6F2C` |
| SSDEEP | `49152:jnYnjQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAA:DI8qPoBhz1aRxcSUDk36SA` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_074_482419cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "482419cf06b8c073ba3e9f5bbe665c6c797276b55218f927dda753bd859c28a3"
    family = "WannaCry"
    file_name = "482419cf06b8c073ba3e9f5bbe665c6c797276b55218f927dda753bd859c28a3"
    file_type = "exe"
    first_seen = "2026-08-04 02:15:23"
  condition:
    hash.sha256(0, filesize) == "482419cf06b8c073ba3e9f5bbe665c6c797276b55218f927dda753bd859c28a3"
}
```

### Sample 75: `3bed436212466098`

| Field | Value |
|---|---|
| SHA-256 | `3bed4362124660989e9b4f82ed59cdd88663131ebd49363d9c96f0bf844972d9` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-04 02:10:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d33655711ed2c4e62dfbea2c8e1f1adf` |
| SHA-1 | `c3da60395b501ac5f3319825bfde991599e537ba` |
| SHA-256 | `3bed4362124660989e9b4f82ed59cdd88663131ebd49363d9c96f0bf844972d9` |
| SHA3-384 | `31a0ab8723e5a2bdeb9843d4ead65c2b3b2763c0a5cc1f727a502d07bdafb419824c9403db2150656d192af6edddca48` |
| TLSH | `T1E9C20853A9C7F0FDC86982794187B034A273B039127ABD463BE5E72F6E7AE124F59401` |
| TELFHASH | `t1cff082b1b36638f0b6eb7d17a349d461c97c19f5046039e586b29cfdaf04fd04c05812` |
| SSDEEP | `384:DGBwSak2nTZD+zagYIpTtr5WXv+zXiL3zh8YyMm:DmU1DEYsIHzzhj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_3bed4362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bed4362124660989e9b4f82ed59cdd88663131ebd49363d9c96f0bf844972d9"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:10:38"
  condition:
    hash.sha256(0, filesize) == "3bed4362124660989e9b4f82ed59cdd88663131ebd49363d9c96f0bf844972d9"
}
```

### Sample 76: `39c18a61b0b292dd`

| Field | Value |
|---|---|
| SHA-256 | `39c18a61b0b292dda5cf7dea6a3518aa2956f66fd3c78cd851e101146d426a18` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-04 02:10:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb60eb153d55db358e6503dad0bcd5de` |
| SHA-1 | `0a6e06ab2735e3ec28e55c049e6e9d3a4778a9ec` |
| SHA-256 | `39c18a61b0b292dda5cf7dea6a3518aa2956f66fd3c78cd851e101146d426a18` |
| SHA3-384 | `5282f016f71e7edf1daecdb848aed975f9023293292d3624d2fb728f6f53843c62bb76ab14b581761d8c97a5d64d92c5` |
| TLSH | `T1EA72AEE3A016F1F1C531793A64545AC4FE67B4352A17CB0B06E072FDDCB5AC46820F96` |
| SSDEEP | `384:+Lu2HCUhIQKNdoNoSgdYiP+nUxaVXALPqmD1:OtHNIQK0ilP+DmD1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_39c18a61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39c18a61b0b292dda5cf7dea6a3518aa2956f66fd3c78cd851e101146d426a18"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:10:18"
  condition:
    hash.sha256(0, filesize) == "39c18a61b0b292dda5cf7dea6a3518aa2956f66fd3c78cd851e101146d426a18"
}
```

### Sample 77: `be59ab761e9e8cdd`

| Field | Value |
|---|---|
| SHA-256 | `be59ab761e9e8cdd940bb912a64c406710b7e87ab5af5540c89457092b4c0cc6` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-04 02:09:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a1ce033d161221b68deedf6e29a28b0` |
| SHA-1 | `e65585a64438dffc53d6dbc93691d5b626e80092` |
| SHA-256 | `be59ab761e9e8cdd940bb912a64c406710b7e87ab5af5540c89457092b4c0cc6` |
| SHA3-384 | `4ced615cff2f25aa5e8db2fafea52cf3f4e3ff13be1a497b8c8873b5437c2196af34d90e4bab451aa68aeb7819288996` |
| TLSH | `T188B23B91E7C3E0F7E88401FD1152D7516336F438216AFD4BEB2026BBB812921E757BA9` |
| TELFHASH | `t1d4f046c23daa01e8fa80fe4dd31f2a43db2a6ab8173570ef4cf5b20632c111481a141a` |
| SSDEEP | `384:fORoHGlOvCRVvpnzR3sGzBWl7uRI9BcwQZU8c1j9v4IFWkS+UGuyJ:kYGlOvCRVvpnV3NAH9YU8cL4IFNStZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_be59ab76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be59ab761e9e8cdd940bb912a64c406710b7e87ab5af5540c89457092b4c0cc6"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-04 02:09:43"
  condition:
    hash.sha256(0, filesize) == "be59ab761e9e8cdd940bb912a64c406710b7e87ab5af5540c89457092b4c0cc6"
}
```

### Sample 78: `d4e0d79b6c02fcc4`

| Field | Value |
|---|---|
| SHA-256 | `d4e0d79b6c02fcc46e3e7bd07b7a3b1dd1ad8e0954337f4812173e4ad04fad8a` |
| Family label | `unknown` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-04 02:09:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b6917ceaeb37c76621f5fd79e80dc65` |
| SHA-1 | `05d424e32183ba9c5cbb8859fa47bdcf9ccf68c0` |
| SHA-256 | `d4e0d79b6c02fcc46e3e7bd07b7a3b1dd1ad8e0954337f4812173e4ad04fad8a` |
| SHA3-384 | `e68fc32174e8336fd58396deb13db90b72148e0d009ef06fc524444aedd45adeee7aba9ccf01ab1c78e3d9ecbbc84c58` |
| TLSH | `T164B2090677580E5BD1AFBAB03A3F1BD493EBFF5122A4D681160EA7CAC1B5E371141C89` |
| SSDEEP | `384:rRT9osofADj7cIxakDJTDx/7NwgAVjTdAkA/bttVLV3OZ1:rbom7cIB1VzAZAp/5tr3C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_d4e0d79b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4e0d79b6c02fcc46e3e7bd07b7a3b1dd1ad8e0954337f4812173e4ad04fad8a"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-04 02:09:41"
  condition:
    hash.sha256(0, filesize) == "d4e0d79b6c02fcc46e3e7bd07b7a3b1dd1ad8e0954337f4812173e4ad04fad8a"
}
```

### Sample 79: `4c1added9d5685e6`

| Field | Value |
|---|---|
| SHA-256 | `4c1added9d5685e6cca7c7811238110bd27ba49ee4ac13afd786b998b3429f17` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-04 02:08:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7948505ed0bf904e9134f5998709db1b` |
| SHA-1 | `412912c8ba858e7ae1b62f0ae17b4d5f2080860d` |
| SHA-256 | `4c1added9d5685e6cca7c7811238110bd27ba49ee4ac13afd786b998b3429f17` |
| SHA3-384 | `17c9a591926755ab2bdf27012976809f4831beaea1b993f4b99c7872b42f9b42edad17ac64e124ae4eb3454817967b58` |
| TLSH | `T1DB62B023D26B0AD0D36990390DAFBCCF2414A01DE71C657BB758617EC952F693D1CAD2` |
| SSDEEP | `384:M1ZeCivRadYdy/nfBD6AKzLxHgKK0VyANaNJawcudoD7UqtCS:fCiEP5omKK0VMnbcuyD7UiCS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_4c1added
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c1added9d5685e6cca7c7811238110bd27ba49ee4ac13afd786b998b3429f17"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:46"
  condition:
    hash.sha256(0, filesize) == "4c1added9d5685e6cca7c7811238110bd27ba49ee4ac13afd786b998b3429f17"
}
```

### Sample 80: `131513147a338f72`

| Field | Value |
|---|---|
| SHA-256 | `131513147a338f72be094bd81bce2bb5a15dab2c749199ae171b940dceed9dc5` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-04 02:08:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `649e991f25df23463f407b413bb80350` |
| SHA-1 | `96cf5ec9a62d2fe1ca2618a6dc5d5bd0c6137a0e` |
| SHA-256 | `131513147a338f72be094bd81bce2bb5a15dab2c749199ae171b940dceed9dc5` |
| SHA3-384 | `454f76c74e51566231bce0b22e80082266d114ba26576e74b7ff1aeb97ce6db7f433ad3f11ef768f81398f40a3980cc7` |
| TLSH | `T14F62CFB4E1959CB2F37F2AF19585B3E1BBFA4F8D15ACCED260D0AF5162391214611CC4` |
| SSDEEP | `384:gmJ4FLkHIa4w+IAN7ib5kLCt7FM4uVcqgw0OarxWXkl:9Jd4N75m7q4uVcqgw0RNWXQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_13151314
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "131513147a338f72be094bd81bce2bb5a15dab2c749199ae171b940dceed9dc5"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:44"
  condition:
    hash.sha256(0, filesize) == "131513147a338f72be094bd81bce2bb5a15dab2c749199ae171b940dceed9dc5"
}
```

### Sample 81: `c3005ae4be1bc1fa`

| Field | Value |
|---|---|
| SHA-256 | `c3005ae4be1bc1faa6e16fd3d68f02223a05311c2cef1e2c9194b43736fbfb99` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-04 02:08:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32aa1236796fc0590f620df81a4e6d08` |
| SHA-1 | `5e28faed3c74267dc566a652dc896752d644da40` |
| SHA-256 | `c3005ae4be1bc1faa6e16fd3d68f02223a05311c2cef1e2c9194b43736fbfb99` |
| SHA3-384 | `626fc9bfba6fe4d532979ffd71a788fa424261cf89b632cb2da161fda51ea88f435b161eba438c955994dcfde31f4c0e` |
| TLSH | `T1E5B26CE18F3A1F94E26443B464218B385B53E41AB74F0EBE162FA3618453D8DF1967F8` |
| SSDEEP | `384:KG1lMaIPgfe4QFlCgg+Xzf38FmfIfRXomENGNXevVLZhdr75zoZ/ynTqBg7xpj:KG1KaIWe4QbCT+emfI5XV2LDoJuvzj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_c3005ae4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3005ae4be1bc1faa6e16fd3d68f02223a05311c2cef1e2c9194b43736fbfb99"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:43"
  condition:
    hash.sha256(0, filesize) == "c3005ae4be1bc1faa6e16fd3d68f02223a05311c2cef1e2c9194b43736fbfb99"
}
```

### Sample 82: `f732ff61847a0b06`

| Field | Value |
|---|---|
| SHA-256 | `f732ff61847a0b0636e30916b7aed159299a1a417b1def3eab6a285fc43e9bf1` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-08-04 02:08:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a72bb2e0f60a82d06e9ca06951b5246c` |
| SHA-1 | `c95bf79ee967d4fbf242e7b17913dea90ea83132` |
| SHA-256 | `f732ff61847a0b0636e30916b7aed159299a1a417b1def3eab6a285fc43e9bf1` |
| SHA3-384 | `f542c5aeeb901886b0823b1ea89c37013a6f182d1fa63c641b543458fd8f756482b75e4ad291f8be29006051f467fd54` |
| TLSH | `T199B24C86FD414917CEE11137FA2E828C37664BB4E2EF3307AB265F642746A1B0F3A545` |
| TELFHASH | `t1e7117d514588ccade1c081aef06d93128516a1663c7d3c62f8ff580cd273df22831969` |
| SSDEEP | `384:Zi1e4fKN9F32SkSb1TGdAy31pBGST5efRBjMeY/Fx4e:ZaePt32SVNGWi1jdQjMex` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_f732ff61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f732ff61847a0b0636e30916b7aed159299a1a417b1def3eab6a285fc43e9bf1"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:41"
  condition:
    hash.sha256(0, filesize) == "f732ff61847a0b0636e30916b7aed159299a1a417b1def3eab6a285fc43e9bf1"
}
```

### Sample 83: `40b8de73ad7ad7ea`

| Field | Value |
|---|---|
| SHA-256 | `40b8de73ad7ad7eac84e573f316d89b1c52770d4744760ff25aeeedb9074e771` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-04 02:08:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25521e5a20257e11b1d3e36e82aab335` |
| SHA-1 | `69619466b08fb5877bb80f1fe63cb34d09446419` |
| SHA-256 | `40b8de73ad7ad7eac84e573f316d89b1c52770d4744760ff25aeeedb9074e771` |
| SHA3-384 | `33569f871bca69b598d743156e5071027eca7dd9d87b4f7fe7165e4806652a7a4b8311d2478e1ab634906cce2d596634` |
| TLSH | `T111C2F7FDF512A9ADF84EFB3E8401410D7A70A72550411A7537AAA937DC333A8193AED3` |
| SSDEEP | `384:KPda6gfFNg0fPL7WAlJFLMhOmJpcFuoZ8HAp3KV7Khb26oNwIkfabiQcwS:KVavfFfLW8FuK8E3Kkx26kwIkf+idwS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_40b8de73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40b8de73ad7ad7eac84e573f316d89b1c52770d4744760ff25aeeedb9074e771"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:40"
  condition:
    hash.sha256(0, filesize) == "40b8de73ad7ad7eac84e573f316d89b1c52770d4744760ff25aeeedb9074e771"
}
```

### Sample 84: `870274776465d632`

| Field | Value |
|---|---|
| SHA-256 | `870274776465d63231cc3f047d9d13e486349f56d7285f50f8deedc973bd94db` |
| Family label | `unknown` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-08-04 02:08:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b417ea896e5c127bfe67468d2d4f5b27` |
| SHA-1 | `25597427f29ca4016ac4e9c47230aff5a541a45c` |
| SHA-256 | `870274776465d63231cc3f047d9d13e486349f56d7285f50f8deedc973bd94db` |
| SHA3-384 | `5823f0a42cbe8166fcd35604f009e2d3142bf5c5a502fa8da2634a44f5efb165f58ac6a3df6f34ed6cd8a96538a27bd7` |
| TLSH | `T1D9D21A3AEB724913C4D499B895F7832CB9F9425F647D4A163C6B0EC4EB91AC06113FE8` |
| SSDEEP | `384:6ysT8AllDko1OxoUmdKzN57tSezXasmFFU+pph1K7R2f:6ysTZ3OxoHqBNeO+3K7Ef` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_87027477
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "870274776465d63231cc3f047d9d13e486349f56d7285f50f8deedc973bd94db"
    family = "unknown"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:38"
  condition:
    hash.sha256(0, filesize) == "870274776465d63231cc3f047d9d13e486349f56d7285f50f8deedc973bd94db"
}
```

### Sample 85: `d24637f9b7f69eba`

| Field | Value |
|---|---|
| SHA-256 | `d24637f9b7f69ebac3e17977f21ef91529217c600e3bf0ecff775b916941ca75` |
| Family label | `unknown` |
| File name | `shellc.bin` |
| File type | `unknown` |
| First seen | `2026-08-04 01:57:16` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98b100f078edd400a8ccd631024ef345` |
| SHA-256 | `d24637f9b7f69ebac3e17977f21ef91529217c600e3bf0ecff775b916941ca75` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_d24637f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d24637f9b7f69ebac3e17977f21ef91529217c600e3bf0ecff775b916941ca75"
    family = "unknown"
    file_name = "shellc.bin"
    file_type = "unknown"
    first_seen = "2026-08-04 01:57:16"
  condition:
    hash.sha256(0, filesize) == "d24637f9b7f69ebac3e17977f21ef91529217c600e3bf0ecff775b916941ca75"
}
```

### Sample 86: `a7e982a1c2d0e1f4`

| Field | Value |
|---|---|
| SHA-256 | `a7e982a1c2d0e1f4d09e675bb95901b7e470126f26f513a88a850f62cb6adaf7` |
| Family label | `unknown` |
| File name | `shell.jsp` |
| File type | `unknown` |
| First seen | `2026-08-04 01:57:00` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd87e3281feac8d9ec2ecdb573873a9a` |
| SHA-256 | `a7e982a1c2d0e1f4d09e675bb95901b7e470126f26f513a88a850f62cb6adaf7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_a7e982a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7e982a1c2d0e1f4d09e675bb95901b7e470126f26f513a88a850f62cb6adaf7"
    family = "unknown"
    file_name = "shell.jsp"
    file_type = "unknown"
    first_seen = "2026-08-04 01:57:00"
  condition:
    hash.sha256(0, filesize) == "a7e982a1c2d0e1f4d09e675bb95901b7e470126f26f513a88a850f62cb6adaf7"
}
```

### Sample 87: `4945914236b4a5d6`

| Field | Value |
|---|---|
| SHA-256 | `4945914236b4a5d627aab874227938f10547f42d1db9f9f319a0bd36b89a9f38` |
| Family label | `unknown` |
| File name | `p.ps1` |
| File type | `ps1` |
| First seen | `2026-08-04 01:56:59` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `009ce05c5e2fd0d8746852c670694280` |
| SHA-1 | `d6cdb877995e1a9380e52dd4a64a8473a9fdd626` |
| SHA-256 | `4945914236b4a5d627aab874227938f10547f42d1db9f9f319a0bd36b89a9f38` |
| SHA3-384 | `289715a2f85c940adc258d8c2d6bbda32d47d8f22cb66542e172498f70cbfe72db099d3395a772de5ba197d1bc3d6cc6` |
| TLSH | `T124D0222AB15C6134C7428B42F9E50503E54B96670514304023BD9809FA715D2C1CC182` |
| SSDEEP | `3:RAlFoWnfxHuxdAJ3TtmAcLhzVv+m4jUSLU6YL4AKFyDLqmTrZjAWIvLqM2oI1MFh:A5fd6dAJQzV74ngtkJTAxh3V1MFfR3KC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_49459142
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4945914236b4a5d627aab874227938f10547f42d1db9f9f319a0bd36b89a9f38"
    family = "unknown"
    file_name = "p.ps1"
    file_type = "ps1"
    first_seen = "2026-08-04 01:56:59"
  condition:
    hash.sha256(0, filesize) == "4945914236b4a5d627aab874227938f10547f42d1db9f9f319a0bd36b89a9f38"
}
```

### Sample 88: `5ce81ed3419f9057`

| Field | Value |
|---|---|
| SHA-256 | `5ce81ed3419f9057c86686b522d2474913a5a70a0401f5795b460b6feed2c198` |
| Family label | `unknown` |
| File name | `v.exe` |
| File type | `exe` |
| First seen | `2026-08-04 01:56:58` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fa812684e65f26ea7b2217b1f448403` |
| SHA-1 | `daaa189172750dd821d5e62b683a42314e9db55e` |
| SHA-256 | `5ce81ed3419f9057c86686b522d2474913a5a70a0401f5795b460b6feed2c198` |
| SHA3-384 | `22a89ff3da4667821eabbe02c521fc0c59f9192299f7309c5d436e2a14962bc7675a01dc9b2efcade514bdadc11dd3ca` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1A471D641A05416F2E94CE37F8487B899FD5FB248A2C80B4F0798981A3F7147BB1DD613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DC6wajk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DC1Y++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_5ce81ed3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ce81ed3419f9057c86686b522d2474913a5a70a0401f5795b460b6feed2c198"
    family = "unknown"
    file_name = "v.exe"
    file_type = "exe"
    first_seen = "2026-08-04 01:56:58"
  condition:
    hash.sha256(0, filesize) == "5ce81ed3419f9057c86686b522d2474913a5a70a0401f5795b460b6feed2c198"
}
```

### Sample 89: `95d154b27a24df2b`

| Field | Value |
|---|---|
| SHA-256 | `95d154b27a24df2bb82ba0d3e6a3b2d268900904119291637d6890d8e3e55d6b` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-08-04 01:48:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7fbd4e82dcb11217eb1c3b926414be4` |
| SHA-1 | `ea755d860fed72984329169653666d7e30d7c8bc` |
| SHA-256 | `95d154b27a24df2bb82ba0d3e6a3b2d268900904119291637d6890d8e3e55d6b` |
| SHA3-384 | `8e09627e21a00883a4e415a78edc41e69646a795edae1bd4f3884d5c4d968cb2743dbb9f80db4ff1fac82597fa39d57c` |
| TLSH | `T178C34B0273180B4BC4A30AB11E3E37E587FBE9E021F4BB89251E8B564575EB76549FC8` |
| SSDEEP | `1536:bC6PrHToS8R9ZbeQmioN5sNFPPFZ+1mW94ryELKHLeY:GeieQmQTFUmHAHLeY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_95d154b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95d154b27a24df2bb82ba0d3e6a3b2d268900904119291637d6890d8e3e55d6b"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-04 01:48:25"
  condition:
    hash.sha256(0, filesize) == "95d154b27a24df2bb82ba0d3e6a3b2d268900904119291637d6890d8e3e55d6b"
}
```

### Sample 90: `be0826d7b02fc838`

| Field | Value |
|---|---|
| SHA-256 | `be0826d7b02fc8380b8ef9003d2e54c8602c7891c3db7b62fc6616f49244b9da` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-08-04 01:47:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f86342e6af73204f9ebdaee6d293ab1d` |
| SHA-1 | `9b4f5f6a15ff38ca56333ef35672900cb84ed9c9` |
| SHA-256 | `be0826d7b02fc8380b8ef9003d2e54c8602c7891c3db7b62fc6616f49244b9da` |
| SHA3-384 | `7e75e1ca707ccd918a1ae348cd596d4a5d9f04046d942390c1b30fe0f5988ee9b5159caa1a99fa04b535c68dbe026cd8` |
| TLSH | `T1652302E7F10A2D01D19C65F4A6E263FB2FE34E4307B2E8D094A8EF03445B4DB49465EA` |
| SSDEEP | `768:3BtksPQkoCqn59JhsF2RlwitstgYTck9HnMFKEVqVuMA5ugzemzb4uVcqgw09Q:xmsYkoCq5ThO2nwiBYT7HntWbMRgzZb/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_be0826d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be0826d7b02fc8380b8ef9003d2e54c8602c7891c3db7b62fc6616f49244b9da"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-04 01:47:40"
  condition:
    hash.sha256(0, filesize) == "be0826d7b02fc8380b8ef9003d2e54c8602c7891c3db7b62fc6616f49244b9da"
}
```

### Sample 91: `b721bbe345a775c3`

| Field | Value |
|---|---|
| SHA-256 | `b721bbe345a775c346e36af404ea28602c92ed7b7f451b1b9eb4e5aac6bbe976` |
| Family label | `AgentTesla` |
| File name | `Proforma Invoice No. 00124 - CONFIRM.JS` |
| File type | `js` |
| First seen | `2026-08-04 01:43:32` |
| Reporter | `nat` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `333b7c65d9d95c045d2847a95abffbed` |
| SHA-1 | `0631d8b428ef85e1ae5ca04460b7a7dd73f138b4` |
| SHA-256 | `b721bbe345a775c346e36af404ea28602c92ed7b7f451b1b9eb4e5aac6bbe976` |
| SHA3-384 | `1a364845efcb6f958fa20e883738a35503bbd52ec88abb13f26ecd30e69d22f379ff6668843d170acab1e9f941cc674c` |
| TLSH | `T1F5F5C4421788A032777A679C533AE930D90B919714C9DF16347CD228BF6CE1793E8AF6` |
| SSDEEP | `98304:wOdQf/H+qxoJAFkYimTGINWfM3m1bccdQm+bo0jqP+LbJMyr:wv/H+/m2pvIAfA5m6qWJMyr` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_091_b721bbe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b721bbe345a775c346e36af404ea28602c92ed7b7f451b1b9eb4e5aac6bbe976"
    family = "AgentTesla"
    file_name = "Proforma Invoice No. 00124 - CONFIRM.JS"
    file_type = "js"
    first_seen = "2026-08-04 01:43:32"
  condition:
    hash.sha256(0, filesize) == "b721bbe345a775c346e36af404ea28602c92ed7b7f451b1b9eb4e5aac6bbe976"
}
```

### Sample 92: `0eb39f56dc09aa56`

| Field | Value |
|---|---|
| SHA-256 | `0eb39f56dc09aa566d3bdd4181cd896fdadcbd40c772b75f885e856f64a20af9` |
| Family label | `unknown` |
| File name | `version-validator.js` |
| File type | `js` |
| First seen | `2026-08-04 01:37:47` |
| Reporter | `anonymous` |
| Tags | `ClickFix, js, SmartApeSG` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7bd78112ad335ad41bba40887ec744c` |
| SHA-256 | `0eb39f56dc09aa566d3bdd4181cd896fdadcbd40c772b75f885e856f64a20af9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_0eb39f56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eb39f56dc09aa566d3bdd4181cd896fdadcbd40c772b75f885e856f64a20af9"
    family = "unknown"
    file_name = "version-validator.js"
    file_type = "js"
    first_seen = "2026-08-04 01:37:47"
  condition:
    hash.sha256(0, filesize) == "0eb39f56dc09aa566d3bdd4181cd896fdadcbd40c772b75f885e856f64a20af9"
}
```

### Sample 93: `a9fc9779102c5ff1`

| Field | Value |
|---|---|
| SHA-256 | `a9fc9779102c5ff1f6e03bc8d1880bb52ac7c0dfe543eb93c07aa28766e8a876` |
| Family label | `Mirai` |
| File name | `nz.sh4` |
| File type | `elf` |
| First seen | `2026-08-04 01:37:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfb9fa77cac7b699e25b89c37efed2b0` |
| SHA-1 | `8a4b2f21a16a30f74b728b30ff482d3a0e492f6b` |
| SHA-256 | `a9fc9779102c5ff1f6e03bc8d1880bb52ac7c0dfe543eb93c07aa28766e8a876` |
| SHA3-384 | `ac9dc1699b75249f6c406fa4e3af31d6c17bb032dd05442f7059decfa7419ab96127e4aa1d6205edd2ae191d46966015` |
| TLSH | `T18AB3AF36C4154AE8C5594574A8A5FE3E1F63E18046631EF71AEAC6B250C7FE8F809BF0` |
| SSDEEP | `1536:s/pmXVHHy9WecBg0A0ds5bU+OXKNH+d7YgPs7CEGRo8a/Hc:sBmX9KWeUG0q5U+fNihPs7G+j/Hc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_a9fc9779
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9fc9779102c5ff1f6e03bc8d1880bb52ac7c0dfe543eb93c07aa28766e8a876"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-08-04 01:37:25"
  condition:
    hash.sha256(0, filesize) == "a9fc9779102c5ff1f6e03bc8d1880bb52ac7c0dfe543eb93c07aa28766e8a876"
}
```

### Sample 94: `39ea33a5244a003b`

| Field | Value |
|---|---|
| SHA-256 | `39ea33a5244a003b92e588735ba8bcb0b3c6d5d095df550f5d1ccd1848c1884c` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-08-04 01:35:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc8b285766fc7fc4bc4fba0f2f7cfafe` |
| SHA-1 | `bdfddaa733c70b9ed3192b6a6c420be540677685` |
| SHA-256 | `39ea33a5244a003b92e588735ba8bcb0b3c6d5d095df550f5d1ccd1848c1884c` |
| SHA3-384 | `c00ca87b77b9745346fece762d3beed7fccc319ea9564346494ffa50bc0230d1a364f95fd1a3c3722eaf17b1aef6d4c6` |
| TLSH | `T17BB35AC5E247D0F9DC5609302276FB375E76E1BB1229CA83D7F49A32AC12AC1D4167AC` |
| TELFHASH | `t11031f5f6f1630cedabe09803a68e3771dd0d6a7b386026f909f22515367624161b9c39` |
| SSDEEP | `3072:0qj7vT6oGJ9WGKMJCFd5zp0xzYNUJdBNVHOZGCtB3UJ:0qj7viyGKMJaTpwZVHOZGCtB3UJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_39ea33a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39ea33a5244a003b92e588735ba8bcb0b3c6d5d095df550f5d1ccd1848c1884c"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-04 01:35:38"
  condition:
    hash.sha256(0, filesize) == "39ea33a5244a003b92e588735ba8bcb0b3c6d5d095df550f5d1ccd1848c1884c"
}
```

### Sample 95: `c27cc06efd48dc2d`

| Field | Value |
|---|---|
| SHA-256 | `c27cc06efd48dc2d6bcbe8153f5ee23574a85f0a87878f579929c50dcbd32f2a` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-08-04 01:34:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed92fa567b1820caa2bb079ad15e4457` |
| SHA-1 | `515da106246d358dc14f5e52dc0a40445ce044e1` |
| SHA-256 | `c27cc06efd48dc2d6bcbe8153f5ee23574a85f0a87878f579929c50dcbd32f2a` |
| SHA3-384 | `27a5b071581a4801406b13bbfcba4b2b7de56e2b17ac60692f5ee1f0f361e7a13306b5426ceb2c6e83a4511b5863c505` |
| TLSH | `T15F23F1B7C5D3DA67C91EC13B6DED3A5D9604E112A94846BA98E1313BCB01315BE0CB8F` |
| SSDEEP | `1536:XeYVOK59fwd7e4oh/cay+xmScjI792WmQe2Anouy8Hyh:XTfMdPohUB+xmA792WmTout6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_c27cc06e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c27cc06efd48dc2d6bcbe8153f5ee23574a85f0a87878f579929c50dcbd32f2a"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-04 01:34:21"
  condition:
    hash.sha256(0, filesize) == "c27cc06efd48dc2d6bcbe8153f5ee23574a85f0a87878f579929c50dcbd32f2a"
}
```

### Sample 96: `2ec3ecd161efa3f8`

| Field | Value |
|---|---|
| SHA-256 | `2ec3ecd161efa3f8e77545aa629318cb0257f7ee6a09f98f02a81dab006d1fd6` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-08-04 01:32:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `343dd2c178727c4b65d08d420785f5f4` |
| SHA-1 | `f91be87e02a5a7330c8f8350fae75f3f3ec4e474` |
| SHA-256 | `2ec3ecd161efa3f8e77545aa629318cb0257f7ee6a09f98f02a81dab006d1fd6` |
| SHA3-384 | `e70c99c3b43b0541a113832a782c9b3f9ae174b60637322153a0082678a1e86df59ce996a797f8c610f55919518c6949` |
| TLSH | `T14AE3D80E7E258F7CF7A5823447F79E16965833C637E1C585D1ACEA016E2028E245FFA8` |
| TELFHASH | `t1ce114c184d7813f097755d9d5adeff72e59170eb06225d378e00e8adaa6d9429e00c2c` |
| SSDEEP | `3072:ydK+SE7ktsNOT8wR41M7qlkoKrMh8XQPr6elpPgBkoAP3nu1StIFD247mFW7mYbM:ydK+SE7ktsNOT8wR41M7qlkoKrMh8XQj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_2ec3ecd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec3ecd161efa3f8e77545aa629318cb0257f7ee6a09f98f02a81dab006d1fd6"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-08-04 01:32:30"
  condition:
    hash.sha256(0, filesize) == "2ec3ecd161efa3f8e77545aa629318cb0257f7ee6a09f98f02a81dab006d1fd6"
}
```

### Sample 97: `7b651e4f66c0bcc2`

| Field | Value |
|---|---|
| SHA-256 | `7b651e4f66c0bcc2befa5a981caaf7ea1180b8bb530bb1e384ba42e70f097db1` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-08-04 01:31:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1e1f7c2898dad77550b8056b0cd6cf5` |
| SHA-1 | `1ab1629c76b62ec8877ffb9b23ec749fdf87a580` |
| SHA-256 | `7b651e4f66c0bcc2befa5a981caaf7ea1180b8bb530bb1e384ba42e70f097db1` |
| SHA3-384 | `3fc16f53fc30ed5852cfc932579a056d0457cfcd9b03224fa6500603835cb428a2f2282d6318eaac62723f7c1595ad2f` |
| TLSH | `T1A733F2E8FF0424ECD05954F003E88EA16F768776DA46EC5FF55BF89B9C81098A086E61` |
| SSDEEP | `768:5Z/+0urUozBFuchHaWcNE5NZuXSO/M5uAHrd2DK417Z2DanZIFbuVX4y8JgGlzDe:5xcrGxWcNTCUMfID0aZ8buVoy0VJu3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_7b651e4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b651e4f66c0bcc2befa5a981caaf7ea1180b8bb530bb1e384ba42e70f097db1"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-08-04 01:31:28"
  condition:
    hash.sha256(0, filesize) == "7b651e4f66c0bcc2befa5a981caaf7ea1180b8bb530bb1e384ba42e70f097db1"
}
```

### Sample 98: `b1e7123c09c5cc0d`

| Field | Value |
|---|---|
| SHA-256 | `b1e7123c09c5cc0d00ba274aa17f7f0c6b1871251063d071398d3199449115b9` |
| Family label | `Mirai` |
| File name | `nz.m68k` |
| File type | `elf` |
| First seen | `2026-08-04 01:31:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2947f49971f7f26e433c2ec570eb4749` |
| SHA-1 | `6763a5b2bee659f7c5097b6bafa13c90c01c7c90` |
| SHA-256 | `b1e7123c09c5cc0d00ba274aa17f7f0c6b1871251063d071398d3199449115b9` |
| SHA3-384 | `bf762469c6f8c9649dab3bdbf2ae38fa175f854fbe19018bd4c8a369abb28530e2bad13ee5655510c6fa715cce83767e` |
| TLSH | `T1D1C34ADAB4019E3DF94FD5BB48636919B920A35255C3172A23ABFD93AC321F47C12F81` |
| SSDEEP | `3072:ae7IQp0jn/vPP6vd/UMWFkbD5hBq6uPE3hUNFvE/W:Vxp0bnPPwWu35bqu3SNFvE/W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_b1e7123c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1e7123c09c5cc0d00ba274aa17f7f0c6b1871251063d071398d3199449115b9"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-08-04 01:31:27"
  condition:
    hash.sha256(0, filesize) == "b1e7123c09c5cc0d00ba274aa17f7f0c6b1871251063d071398d3199449115b9"
}
```

### Sample 99: `8967d2cf0329e481`

| Field | Value |
|---|---|
| SHA-256 | `8967d2cf0329e481541119aec9ec6e585a448739f11357cebdfbd308cc8722f4` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-04 01:30:27` |
| Reporter | `Bitsight` |
| Tags | `4372983ee83c7c5a55b3bd05810657d2, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7f3c8f61ecb422d0efeff4bdf206842` |
| SHA-1 | `8b0fc1b6c42bc606a268f63fcdb0a2d4e33e8d72` |
| SHA-256 | `8967d2cf0329e481541119aec9ec6e585a448739f11357cebdfbd308cc8722f4` |
| SHA3-384 | `448781bb184e25bf65fb2c5d0f9e2f6dceab8248b0876ca5d5450a4e9ddb8f0b876086be5ebc0ef0572a46a4ac1f687c` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1E43633C768D69878D080C7F8A513B0BDB23EB7664621BC5F76CCA9194EB7B11443E782` |
| SSDEEP | `98304:K4QKMuvmuoWArWf3cFNblEYaczjviO3ggRvk0nd8XB7GUaa:K+MWArWfmMYaMvHRv3nd8Xdvaa` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_099_8967d2cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8967d2cf0329e481541119aec9ec6e585a448739f11357cebdfbd308cc8722f4"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 01:30:27"
  condition:
    hash.sha256(0, filesize) == "8967d2cf0329e481541119aec9ec6e585a448739f11357cebdfbd308cc8722f4"
}
```

### Sample 100: `0565c099d16a7c3d`

| Field | Value |
|---|---|
| SHA-256 | `0565c099d16a7c3dba0468785efba40d0cdc0ac57916e453035c665e74ad1417` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-04 01:30:19` |
| Reporter | `Bitsight` |
| Tags | `4372983ee83c7c5a55b3bd05810657d2, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16276506ff9128eeb68cfdceedb13907` |
| SHA-1 | `0777a56257c9899e5ae7b8b86e5c2c950126df73` |
| SHA-256 | `0565c099d16a7c3dba0468785efba40d0cdc0ac57916e453035c665e74ad1417` |
| SHA3-384 | `78a56e7621abe0df9f5cbb47e32c0e7f48b761c492f395ff497dcbc5a0815bd50615870bb83ab7a8d78b790d8d0bc2ef` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1CFD52392A5F70974C436C3729F42F4AEB1A53B61CA728E57B6CC4A14CC276C49C367B2` |
| SSDEEP | `49152:tmxd65fa79t3A0iW/XsZ/ZKp8uELvKNt1vI9yqAFvI65yD39GkiDBcV3bC6Ev:6qfa79liW/8Z4p8uGI1vI9PAFoBlb2v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_0565c099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0565c099d16a7c3dba0468785efba40d0cdc0ac57916e453035c665e74ad1417"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 01:30:19"
  condition:
    hash.sha256(0, filesize) == "0565c099d16a7c3dba0468785efba40d0cdc0ac57916e453035c665e74ad1417"
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
 * Generated: 2026-08-04T03:42:59.964998+00:00
 */

rule MalwareBazaar_unknown_001_28685dff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11"
    family = "unknown"
    file_name = "sys_d1c5307f.exe"
    file_type = "exe"
    first_seen = "2026-08-04 03:37:00"
  condition:
    hash.sha256(0, filesize) == "28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11"
}

rule MalwareBazaar_unknown_002_ef431e36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef431e36a8ac12051af588d800e1d8128d583a9d4c68187709263a13564081cd"
    family = "unknown"
    file_name = "sys_9ae934e3.dll"
    file_type = "dll"
    first_seen = "2026-08-04 03:36:28"
  condition:
    hash.sha256(0, filesize) == "ef431e36a8ac12051af588d800e1d8128d583a9d4c68187709263a13564081cd"
}

rule MalwareBazaar_unknown_003_55a81d88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55a81d88fff3dc3de0e42724b0a992d4ef382b0e1a82187abf9d635ab89b2bae"
    family = "unknown"
    file_name = "captcha_obf.html"
    file_type = "html"
    first_seen = "2026-08-04 03:36:01"
  condition:
    hash.sha256(0, filesize) == "55a81d88fff3dc3de0e42724b0a992d4ef382b0e1a82187abf9d635ab89b2bae"
}

rule MalwareBazaar_unknown_004_ae09b3fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae09b3fd7eea012f655e9467f694d1fb41a1b14033a904ce66105a6869ae00ae"
    family = "unknown"
    file_name = "XenoExtractorSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-04 03:35:32"
  condition:
    hash.sha256(0, filesize) == "ae09b3fd7eea012f655e9467f694d1fb41a1b14033a904ce66105a6869ae00ae"
}

rule MalwareBazaar_unknown_005_0dc6a5ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dc6a5ce14838813e297a83e3c3c0868c7a211ee2da9c9705e5a282e65f089fe"
    family = "unknown"
    file_name = "sys_f3799809.exe"
    file_type = "exe"
    first_seen = "2026-08-04 03:23:46"
  condition:
    hash.sha256(0, filesize) == "0dc6a5ce14838813e297a83e3c3c0868c7a211ee2da9c9705e5a282e65f089fe"
}

rule MalwareBazaar_unknown_006_8af1afc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8af1afc82c0d578a54cc34d09544a0695ec2b0d5f244bf1f1bb4993ee7614734"
    family = "unknown"
    file_name = "sys_81242b01.dll"
    file_type = "dll"
    first_seen = "2026-08-04 03:23:13"
  condition:
    hash.sha256(0, filesize) == "8af1afc82c0d578a54cc34d09544a0695ec2b0d5f244bf1f1bb4993ee7614734"
}

rule MalwareBazaar_unknown_007_9cfe9b89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cfe9b894af68946ddc7e6f4cbdb085a92c4009ea00554c407beb5a8fc29f6b7"
    family = "unknown"
    file_name = "sys_c67f50d5.exe"
    file_type = "exe"
    first_seen = "2026-08-04 03:22:42"
  condition:
    hash.sha256(0, filesize) == "9cfe9b894af68946ddc7e6f4cbdb085a92c4009ea00554c407beb5a8fc29f6b7"
}

rule MalwareBazaar_unknown_008_290d41e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "290d41e7436238066a8aacbd63a805aeeefc00d8798116dc702eccf6df3eae37"
    family = "unknown"
    file_name = "sys_6510b971.dll"
    file_type = "dll"
    first_seen = "2026-08-04 03:21:51"
  condition:
    hash.sha256(0, filesize) == "290d41e7436238066a8aacbd63a805aeeefc00d8798116dc702eccf6df3eae37"
}

rule MalwareBazaar_unknown_009_bac34052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bac340524549410f51b060f21abb7db30c0c5378edd2e3ac15b526e141417e89"
    family = "unknown"
    file_name = "sys_7f6670d8.exe"
    file_type = "exe"
    first_seen = "2026-08-04 03:21:06"
  condition:
    hash.sha256(0, filesize) == "bac340524549410f51b060f21abb7db30c0c5378edd2e3ac15b526e141417e89"
}

rule MalwareBazaar_unknown_010_1eb088ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eb088ba9bb20301add4fb1a99002431d1cb542edcc1ae038557e2435d162935"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-04 03:01:48"
  condition:
    hash.sha256(0, filesize) == "1eb088ba9bb20301add4fb1a99002431d1cb542edcc1ae038557e2435d162935"
}

rule MalwareBazaar_unknown_011_5d722c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d722c70d2ccd3e588321d3dea5ea7c8500b4c381654f1eded1381e87016c610"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 03:01:46"
  condition:
    hash.sha256(0, filesize) == "5d722c70d2ccd3e588321d3dea5ea7c8500b4c381654f1eded1381e87016c610"
}

rule MalwareBazaar_unknown_012_d216ea4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d216ea4fe9d0ae5089b95340953bbfdb16f87c383a95ce1fd77fec5f95893365"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-04 03:01:44"
  condition:
    hash.sha256(0, filesize) == "d216ea4fe9d0ae5089b95340953bbfdb16f87c383a95ce1fd77fec5f95893365"
}

rule MalwareBazaar_Mirai_013_e42737c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e42737c443cd36a64856465be6ef776cd5a81fe51ce7ae8cc63597c364742be9"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-04 03:01:40"
  condition:
    hash.sha256(0, filesize) == "e42737c443cd36a64856465be6ef776cd5a81fe51ce7ae8cc63597c364742be9"
}

rule MalwareBazaar_Mirai_014_a3bbf4f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3bbf4f02b6b10305ad5e96cf4e360026caca7bdfb4b053628c7e963f6605aac"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-04 03:01:37"
  condition:
    hash.sha256(0, filesize) == "a3bbf4f02b6b10305ad5e96cf4e360026caca7bdfb4b053628c7e963f6605aac"
}

rule MalwareBazaar_Mirai_015_c003e324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c003e3244c180d0b7d3a23e227c6a36aa461afbd2d5a2ddbd8e27eef77084af5"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-04 03:00:05"
  condition:
    hash.sha256(0, filesize) == "c003e3244c180d0b7d3a23e227c6a36aa461afbd2d5a2ddbd8e27eef77084af5"
}

rule MalwareBazaar_Mirai_016_115fc7d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "115fc7d85f327558cc5787b54c33a831446b4ee8694c1a2490abbf904a41c829"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 03:00:02"
  condition:
    hash.sha256(0, filesize) == "115fc7d85f327558cc5787b54c33a831446b4ee8694c1a2490abbf904a41c829"
}

rule MalwareBazaar_Mirai_017_b1fd6828
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1fd6828ad7f33f8727067385ccc9a048c0f03fb5cfbf204003366b3becb0e58"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-04 03:00:00"
  condition:
    hash.sha256(0, filesize) == "b1fd6828ad7f33f8727067385ccc9a048c0f03fb5cfbf204003366b3becb0e58"
}

rule MalwareBazaar_unknown_018_bed43d30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bed43d309f45747c5c9ac611b189780e0cd48f907f4d909c6ecc784759df5d36"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-04 03:00:00"
  condition:
    hash.sha256(0, filesize) == "bed43d309f45747c5c9ac611b189780e0cd48f907f4d909c6ecc784759df5d36"
}

rule MalwareBazaar_Mirai_019_711d580e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "711d580edcb17c294c3c7942873d38c70db5346a30b8963dee11b79019ce5b5c"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-04 02:59:59"
  condition:
    hash.sha256(0, filesize) == "711d580edcb17c294c3c7942873d38c70db5346a30b8963dee11b79019ce5b5c"
}

rule MalwareBazaar_Mirai_020_053159bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "053159bc4da6952d2920f832b6aa2fee39c910422a9696a56cbd046478515f61"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-04 02:59:58"
  condition:
    hash.sha256(0, filesize) == "053159bc4da6952d2920f832b6aa2fee39c910422a9696a56cbd046478515f61"
}

rule MalwareBazaar_unknown_021_a2362c6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2362c6b241ede3fc4b9fe8ae8a13116504790091663305852034a55fe2e5596"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 02:57:13"
  condition:
    hash.sha256(0, filesize) == "a2362c6b241ede3fc4b9fe8ae8a13116504790091663305852034a55fe2e5596"
}

rule MalwareBazaar_Mirai_022_114d63f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "114d63f0ee478b2fda75083283372cecd3064c6a425d06b9179f147454fe0a17"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:56:32"
  condition:
    hash.sha256(0, filesize) == "114d63f0ee478b2fda75083283372cecd3064c6a425d06b9179f147454fe0a17"
}

rule MalwareBazaar_Mirai_023_2bf4b934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bf4b9346368e0e01627bbb9f9ac46ade32bcc5d858863fcc1b77101843235d8"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:38"
  condition:
    hash.sha256(0, filesize) == "2bf4b9346368e0e01627bbb9f9ac46ade32bcc5d858863fcc1b77101843235d8"
}

rule MalwareBazaar_Mirai_024_3c500648
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c500648c56089205ba5ee22fa60ba32d9933750849c1fab0296405ae4dc4cd8"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:35"
  condition:
    hash.sha256(0, filesize) == "3c500648c56089205ba5ee22fa60ba32d9933750849c1fab0296405ae4dc4cd8"
}

rule MalwareBazaar_Mirai_025_310ac390
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310ac3902f066cb2f1e5e006847b0f5985f8d418e71dcdb8f012eb65535a7656"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:31"
  condition:
    hash.sha256(0, filesize) == "310ac3902f066cb2f1e5e006847b0f5985f8d418e71dcdb8f012eb65535a7656"
}

rule MalwareBazaar_Mirai_026_a6426a32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6426a32489d5c827fe5ad2eb7fcdaed1c45445b45865d5dd6b231a3b9e32704"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:30"
  condition:
    hash.sha256(0, filesize) == "a6426a32489d5c827fe5ad2eb7fcdaed1c45445b45865d5dd6b231a3b9e32704"
}

rule MalwareBazaar_Mirai_027_bbd7f06a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbd7f06ab627494cdd44ae6f5b03649754c7e500a92bcdf055ee7973ddbdc693"
    family = "Mirai"
    file_name = "s390x"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:29"
  condition:
    hash.sha256(0, filesize) == "bbd7f06ab627494cdd44ae6f5b03649754c7e500a92bcdf055ee7973ddbdc693"
}

rule MalwareBazaar_Mirai_028_c70f20a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c70f20a8d2dec9cb679631b40d9f86cf050b7bef46c7f3fab67bd4db4b8dbe9b"
    family = "Mirai"
    file_name = "riscv64"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:29"
  condition:
    hash.sha256(0, filesize) == "c70f20a8d2dec9cb679631b40d9f86cf050b7bef46c7f3fab67bd4db4b8dbe9b"
}

rule MalwareBazaar_Mirai_029_54a53cf8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54a53cf88b6371a57090067aafe8721fe44e0d7342a6778c752f939aa75e99f0"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:28"
  condition:
    hash.sha256(0, filesize) == "54a53cf88b6371a57090067aafe8721fe44e0d7342a6778c752f939aa75e99f0"
}

rule MalwareBazaar_Mirai_030_fca74b77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fca74b77494968bc93fff695cde2810dfeb36b4af74aaa12b46299bb48c84474"
    family = "Mirai"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:28"
  condition:
    hash.sha256(0, filesize) == "fca74b77494968bc93fff695cde2810dfeb36b4af74aaa12b46299bb48c84474"
}

rule MalwareBazaar_Mirai_031_1afcf3ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1afcf3ea18f2b7a87906799801be4a4e8fa6b82d402333446daa06b4eda3f399"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:24"
  condition:
    hash.sha256(0, filesize) == "1afcf3ea18f2b7a87906799801be4a4e8fa6b82d402333446daa06b4eda3f399"
}

rule MalwareBazaar_Mirai_032_5b88cc74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b88cc74ad84267f02f2151d4dc05d0b7adb4fba2df96b27229a643cded55747"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:24"
  condition:
    hash.sha256(0, filesize) == "5b88cc74ad84267f02f2151d4dc05d0b7adb4fba2df96b27229a643cded55747"
}

rule MalwareBazaar_Mirai_033_ab434585
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab434585775518b79d589ee36a56eafc9a83c81e9bd4fb5c8b5cb9939220ecd4"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:23"
  condition:
    hash.sha256(0, filesize) == "ab434585775518b79d589ee36a56eafc9a83c81e9bd4fb5c8b5cb9939220ecd4"
}

rule MalwareBazaar_Mirai_034_c1ff3505
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1ff3505ce4decd2c9ef6381a1c0e62a03f78e17b1cf92793d9f41df68ace755"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:23"
  condition:
    hash.sha256(0, filesize) == "c1ff3505ce4decd2c9ef6381a1c0e62a03f78e17b1cf92793d9f41df68ace755"
}

rule MalwareBazaar_Mirai_035_163be3d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "163be3d0ac9a9e99fb76eda1891b97d049758873420df45e5369532fe615f940"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:21"
  condition:
    hash.sha256(0, filesize) == "163be3d0ac9a9e99fb76eda1891b97d049758873420df45e5369532fe615f940"
}

rule MalwareBazaar_Mirai_036_ccaaa24e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccaaa24e22ba38aad988ea069bc92db12e83bf5d9ee94e632600fe39482459ba"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-04 02:55:19"
  condition:
    hash.sha256(0, filesize) == "ccaaa24e22ba38aad988ea069bc92db12e83bf5d9ee94e632600fe39482459ba"
}

rule MalwareBazaar_unknown_037_1fa5a636
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fa5a63614596e6f47af8176b409acb6a4792efc9a7c49cfcbdb9b3697904b0a"
    family = "unknown"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-08-04 02:53:39"
  condition:
    hash.sha256(0, filesize) == "1fa5a63614596e6f47af8176b409acb6a4792efc9a7c49cfcbdb9b3697904b0a"
}

rule MalwareBazaar_Mirai_038_e55e33ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e55e33ad6adcdaffb331b91eb4384a88cb8d186c9321a26f28933f9919a0395b"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:40:06"
  condition:
    hash.sha256(0, filesize) == "e55e33ad6adcdaffb331b91eb4384a88cb8d186c9321a26f28933f9919a0395b"
}

rule MalwareBazaar_Mirai_039_16db64af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16db64af8dea727dd54cb9c2046fc33012e66c0c459c7a9c95667433ea530071"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-04 02:40:02"
  condition:
    hash.sha256(0, filesize) == "16db64af8dea727dd54cb9c2046fc33012e66c0c459c7a9c95667433ea530071"
}

rule MalwareBazaar_Mirai_040_45f9fb0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45f9fb0c531949041c9d33965c57e9cdd49571d7bad9c4f6f3d3f4500e38cada"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-04 02:40:01"
  condition:
    hash.sha256(0, filesize) == "45f9fb0c531949041c9d33965c57e9cdd49571d7bad9c4f6f3d3f4500e38cada"
}

rule MalwareBazaar_Mirai_041_7635a144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7635a144c4278f92c8cd2efd3b59a000e0bcd4b4b55dd277ce0507301c746c58"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-04 02:40:01"
  condition:
    hash.sha256(0, filesize) == "7635a144c4278f92c8cd2efd3b59a000e0bcd4b4b55dd277ce0507301c746c58"
}

rule MalwareBazaar_Mirai_042_363600aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "363600aafcb52184b61cbedea14e287a644c1352596a403e0bc1c087a9d2a3c6"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-04 02:40:00"
  condition:
    hash.sha256(0, filesize) == "363600aafcb52184b61cbedea14e287a644c1352596a403e0bc1c087a9d2a3c6"
}

rule MalwareBazaar_Mirai_043_09afd8af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09afd8afb7abfd16691468337405e0f65a9371431f1fb4d17d80526e3f9be206"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:57"
  condition:
    hash.sha256(0, filesize) == "09afd8afb7abfd16691468337405e0f65a9371431f1fb4d17d80526e3f9be206"
}

rule MalwareBazaar_Mirai_044_64cbda8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64cbda8d6f960a04736830247064caeb498b55d56f93c3d7a6ed0bd3e2f88d82"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:57"
  condition:
    hash.sha256(0, filesize) == "64cbda8d6f960a04736830247064caeb498b55d56f93c3d7a6ed0bd3e2f88d82"
}

rule MalwareBazaar_Mirai_045_cc4c9f76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc4c9f763e6dc7e564f96c4ed7982ad8a4e8a3c64b3d711570fc21eb7355eb44"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:56"
  condition:
    hash.sha256(0, filesize) == "cc4c9f763e6dc7e564f96c4ed7982ad8a4e8a3c64b3d711570fc21eb7355eb44"
}

rule MalwareBazaar_Mirai_046_fa0c24ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa0c24efa54419dbb95cac0d13e7ae2ef06770592a63d7bab53f54584077c29b"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:56"
  condition:
    hash.sha256(0, filesize) == "fa0c24efa54419dbb95cac0d13e7ae2ef06770592a63d7bab53f54584077c29b"
}

rule MalwareBazaar_Mirai_047_270dcab0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "270dcab0e04e667231291b7ca501e791719813e0cec08369ee48214ebf58446c"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:55"
  condition:
    hash.sha256(0, filesize) == "270dcab0e04e667231291b7ca501e791719813e0cec08369ee48214ebf58446c"
}

rule MalwareBazaar_Mirai_048_2b502060
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b50206086057d4fff0b97b84005a042686a5fdba742049d9a25ab8b50a81c20"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:52"
  condition:
    hash.sha256(0, filesize) == "2b50206086057d4fff0b97b84005a042686a5fdba742049d9a25ab8b50a81c20"
}

rule MalwareBazaar_Mirai_049_fbd757b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbd757b745b5dbe31420a15ad26ee95a20ea614cc35eb5fece7da72040732797"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:51"
  condition:
    hash.sha256(0, filesize) == "fbd757b745b5dbe31420a15ad26ee95a20ea614cc35eb5fece7da72040732797"
}

rule MalwareBazaar_Mirai_050_2e2a5917
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e2a591728f7579bfd716d35ccd5d2bdeca939c6794ce034e7aad99346714d2c"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:46"
  condition:
    hash.sha256(0, filesize) == "2e2a591728f7579bfd716d35ccd5d2bdeca939c6794ce034e7aad99346714d2c"
}

rule MalwareBazaar_Mirai_051_998f4b03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "998f4b03231f4cc9253754fcda3aa32b0435a10880568fd128e5351ec76489ab"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:45"
  condition:
    hash.sha256(0, filesize) == "998f4b03231f4cc9253754fcda3aa32b0435a10880568fd128e5351ec76489ab"
}

rule MalwareBazaar_Mirai_052_e65abd6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e65abd6d9c1ee8f6adca6dd3b9b389e70eb3c451643f2f23cca3274e66860e2d"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:44"
  condition:
    hash.sha256(0, filesize) == "e65abd6d9c1ee8f6adca6dd3b9b389e70eb3c451643f2f23cca3274e66860e2d"
}

rule MalwareBazaar_Mirai_053_6e837510
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e8375102046ab698aa2a81457edef9aaf6ab1a3e08ce42406ea8e33f62870ee"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:43"
  condition:
    hash.sha256(0, filesize) == "6e8375102046ab698aa2a81457edef9aaf6ab1a3e08ce42406ea8e33f62870ee"
}

rule MalwareBazaar_Mirai_054_cfc08d5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfc08d5ae14fe95345dd920e223eb5ace0793c0d328cab3d68909b805b132378"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:42"
  condition:
    hash.sha256(0, filesize) == "cfc08d5ae14fe95345dd920e223eb5ace0793c0d328cab3d68909b805b132378"
}

rule MalwareBazaar_Mirai_055_8d759c64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d759c64d6c49f1d87c1be2b590990d72ef946184f956cb6bbbb00ce443e17a7"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:41"
  condition:
    hash.sha256(0, filesize) == "8d759c64d6c49f1d87c1be2b590990d72ef946184f956cb6bbbb00ce443e17a7"
}

rule MalwareBazaar_Mirai_056_cff2d7f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cff2d7f00e2d3dab42786b56e1d565c4e5dae6c28440d05090897bed645ece7e"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:41"
  condition:
    hash.sha256(0, filesize) == "cff2d7f00e2d3dab42786b56e1d565c4e5dae6c28440d05090897bed645ece7e"
}

rule MalwareBazaar_Mirai_057_be6849de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be6849de8d422b60f886f6c384cbc344cb976c3ead185d904bed04bcfc6a5a2f"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:40"
  condition:
    hash.sha256(0, filesize) == "be6849de8d422b60f886f6c384cbc344cb976c3ead185d904bed04bcfc6a5a2f"
}

rule MalwareBazaar_Mirai_058_c1d94a4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1d94a4e5f38ee96f0c95fff899271929a8c2cbf7149af23a3e9f969bde29775"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:34"
  condition:
    hash.sha256(0, filesize) == "c1d94a4e5f38ee96f0c95fff899271929a8c2cbf7149af23a3e9f969bde29775"
}

rule MalwareBazaar_Mirai_059_036f5b0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "036f5b0ccd595315d4c10fca45bca7fcbb786d93b01c42d5b979bc5d45c02d46"
    family = "Mirai"
    file_name = "dbg"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:33"
  condition:
    hash.sha256(0, filesize) == "036f5b0ccd595315d4c10fca45bca7fcbb786d93b01c42d5b979bc5d45c02d46"
}

rule MalwareBazaar_Mirai_060_835dd72d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "835dd72dbd00dc430061807cac9522b1845f8afec4091c93d6542d123dc5c747"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:32"
  condition:
    hash.sha256(0, filesize) == "835dd72dbd00dc430061807cac9522b1845f8afec4091c93d6542d123dc5c747"
}

rule MalwareBazaar_Mirai_061_f7be5b76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7be5b76f4d34cb064557bf6392debf71d1b3448af63c7e99c24495722980cf0"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:32"
  condition:
    hash.sha256(0, filesize) == "f7be5b76f4d34cb064557bf6392debf71d1b3448af63c7e99c24495722980cf0"
}

rule MalwareBazaar_Mirai_062_a64edd8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a64edd8f53f76ed2af41dca7396e3bf14f9b26d7f64cc9d125a1e84bf87f504c"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:31"
  condition:
    hash.sha256(0, filesize) == "a64edd8f53f76ed2af41dca7396e3bf14f9b26d7f64cc9d125a1e84bf87f504c"
}

rule MalwareBazaar_Mirai_063_c6467b63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6467b63a99985244bb1f6d10ff9312f36bb4829b935980c98bc19f1ec2ed4c3"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-04 02:39:31"
  condition:
    hash.sha256(0, filesize) == "c6467b63a99985244bb1f6d10ff9312f36bb4829b935980c98bc19f1ec2ed4c3"
}

rule MalwareBazaar_Mirai_064_8b84fede
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b84fede49c33a6375c6994884f6079ef8db1638ac1ee8426dfd645edaa7dfdb"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-04 02:37:46"
  condition:
    hash.sha256(0, filesize) == "8b84fede49c33a6375c6994884f6079ef8db1638ac1ee8426dfd645edaa7dfdb"
}

rule MalwareBazaar_Mirai_065_dd55efc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd55efc4766c21d6a1a974a8636f7174353e10b8367fec0021d7a364a0d2f64e"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-04 02:37:44"
  condition:
    hash.sha256(0, filesize) == "dd55efc4766c21d6a1a974a8636f7174353e10b8367fec0021d7a364a0d2f64e"
}

rule MalwareBazaar_Sliver_066_75289c50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75289c50ef39821585cf68d36aebb6b46f184d4089182ea23cceab96323222d0"
    family = "Sliver"
    file_name = "tyler-v6.iso"
    file_type = "iso"
    first_seen = "2026-08-04 02:36:24"
  condition:
    hash.sha256(0, filesize) == "75289c50ef39821585cf68d36aebb6b46f184d4089182ea23cceab96323222d0"
}

rule MalwareBazaar_Mirai_067_c61382e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c61382e927b0020d7d55b9901648b9fb4b5d050c24f16e09bd66e8bde34d2fcd"
    family = "Mirai"
    file_name = "miron.x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:26:49"
  condition:
    hash.sha256(0, filesize) == "c61382e927b0020d7d55b9901648b9fb4b5d050c24f16e09bd66e8bde34d2fcd"
}

rule MalwareBazaar_Mirai_068_168135af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "168135afc7ed99484e1ee0774b57c7c77ecd222b40821afef63392f5ea4b3d5c"
    family = "Mirai"
    file_name = "miron.armv7l"
    file_type = "elf"
    first_seen = "2026-08-04 02:24:24"
  condition:
    hash.sha256(0, filesize) == "168135afc7ed99484e1ee0774b57c7c77ecd222b40821afef63392f5ea4b3d5c"
}

rule MalwareBazaar_Mirai_069_1c8d75b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c8d75b82fa11334ee40d7f09393b2f78396489428b5d8ea105ea3b57ae61484"
    family = "Mirai"
    file_name = "miron.armv7l"
    file_type = "elf"
    first_seen = "2026-08-04 02:23:34"
  condition:
    hash.sha256(0, filesize) == "1c8d75b82fa11334ee40d7f09393b2f78396489428b5d8ea105ea3b57ae61484"
}

rule MalwareBazaar_Mirai_070_79df0475
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79df04757d6927d13860cff93c5f9c1cef787761f16688eb0a6b62feef29762c"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-04 02:20:41"
  condition:
    hash.sha256(0, filesize) == "79df04757d6927d13860cff93c5f9c1cef787761f16688eb0a6b62feef29762c"
}

rule MalwareBazaar_Mirai_071_804d8830
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "804d8830744c3f429686379f84b6b6bbdccc8c5c05af2a443ad4a2e73026b19e"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-04 02:19:21"
  condition:
    hash.sha256(0, filesize) == "804d8830744c3f429686379f84b6b6bbdccc8c5c05af2a443ad4a2e73026b19e"
}

rule MalwareBazaar_unknown_072_9797d77b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9797d77b700b481dd845982f0bf879d3d9bfcd3b7c3db4fb1f488a4ea49790a9"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-04 02:19:20"
  condition:
    hash.sha256(0, filesize) == "9797d77b700b481dd845982f0bf879d3d9bfcd3b7c3db4fb1f488a4ea49790a9"
}

rule MalwareBazaar_unknown_073_555d7893
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "555d78938859dc3b4ea2b6f148363b1f8434dd071ab1a8f5dbdb8d21a0ca4337"
    family = "unknown"
    file_name = "dropper.sh"
    file_type = "sh"
    first_seen = "2026-08-04 02:19:19"
  condition:
    hash.sha256(0, filesize) == "555d78938859dc3b4ea2b6f148363b1f8434dd071ab1a8f5dbdb8d21a0ca4337"
}

rule MalwareBazaar_WannaCry_074_482419cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "482419cf06b8c073ba3e9f5bbe665c6c797276b55218f927dda753bd859c28a3"
    family = "WannaCry"
    file_name = "482419cf06b8c073ba3e9f5bbe665c6c797276b55218f927dda753bd859c28a3"
    file_type = "exe"
    first_seen = "2026-08-04 02:15:23"
  condition:
    hash.sha256(0, filesize) == "482419cf06b8c073ba3e9f5bbe665c6c797276b55218f927dda753bd859c28a3"
}

rule MalwareBazaar_unknown_075_3bed4362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bed4362124660989e9b4f82ed59cdd88663131ebd49363d9c96f0bf844972d9"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:10:38"
  condition:
    hash.sha256(0, filesize) == "3bed4362124660989e9b4f82ed59cdd88663131ebd49363d9c96f0bf844972d9"
}

rule MalwareBazaar_unknown_076_39c18a61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39c18a61b0b292dda5cf7dea6a3518aa2956f66fd3c78cd851e101146d426a18"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 02:10:18"
  condition:
    hash.sha256(0, filesize) == "39c18a61b0b292dda5cf7dea6a3518aa2956f66fd3c78cd851e101146d426a18"
}

rule MalwareBazaar_unknown_077_be59ab76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be59ab761e9e8cdd940bb912a64c406710b7e87ab5af5540c89457092b4c0cc6"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-04 02:09:43"
  condition:
    hash.sha256(0, filesize) == "be59ab761e9e8cdd940bb912a64c406710b7e87ab5af5540c89457092b4c0cc6"
}

rule MalwareBazaar_unknown_078_d4e0d79b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4e0d79b6c02fcc46e3e7bd07b7a3b1dd1ad8e0954337f4812173e4ad04fad8a"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-04 02:09:41"
  condition:
    hash.sha256(0, filesize) == "d4e0d79b6c02fcc46e3e7bd07b7a3b1dd1ad8e0954337f4812173e4ad04fad8a"
}

rule MalwareBazaar_unknown_079_4c1added
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c1added9d5685e6cca7c7811238110bd27ba49ee4ac13afd786b998b3429f17"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:46"
  condition:
    hash.sha256(0, filesize) == "4c1added9d5685e6cca7c7811238110bd27ba49ee4ac13afd786b998b3429f17"
}

rule MalwareBazaar_Mirai_080_13151314
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "131513147a338f72be094bd81bce2bb5a15dab2c749199ae171b940dceed9dc5"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:44"
  condition:
    hash.sha256(0, filesize) == "131513147a338f72be094bd81bce2bb5a15dab2c749199ae171b940dceed9dc5"
}

rule MalwareBazaar_Mirai_081_c3005ae4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3005ae4be1bc1faa6e16fd3d68f02223a05311c2cef1e2c9194b43736fbfb99"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:43"
  condition:
    hash.sha256(0, filesize) == "c3005ae4be1bc1faa6e16fd3d68f02223a05311c2cef1e2c9194b43736fbfb99"
}

rule MalwareBazaar_Mirai_082_f732ff61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f732ff61847a0b0636e30916b7aed159299a1a417b1def3eab6a285fc43e9bf1"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:41"
  condition:
    hash.sha256(0, filesize) == "f732ff61847a0b0636e30916b7aed159299a1a417b1def3eab6a285fc43e9bf1"
}

rule MalwareBazaar_Mirai_083_40b8de73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40b8de73ad7ad7eac84e573f316d89b1c52770d4744760ff25aeeedb9074e771"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:40"
  condition:
    hash.sha256(0, filesize) == "40b8de73ad7ad7eac84e573f316d89b1c52770d4744760ff25aeeedb9074e771"
}

rule MalwareBazaar_unknown_084_87027477
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "870274776465d63231cc3f047d9d13e486349f56d7285f50f8deedc973bd94db"
    family = "unknown"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-04 02:08:38"
  condition:
    hash.sha256(0, filesize) == "870274776465d63231cc3f047d9d13e486349f56d7285f50f8deedc973bd94db"
}

rule MalwareBazaar_unknown_085_d24637f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d24637f9b7f69ebac3e17977f21ef91529217c600e3bf0ecff775b916941ca75"
    family = "unknown"
    file_name = "shellc.bin"
    file_type = "unknown"
    first_seen = "2026-08-04 01:57:16"
  condition:
    hash.sha256(0, filesize) == "d24637f9b7f69ebac3e17977f21ef91529217c600e3bf0ecff775b916941ca75"
}

rule MalwareBazaar_unknown_086_a7e982a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7e982a1c2d0e1f4d09e675bb95901b7e470126f26f513a88a850f62cb6adaf7"
    family = "unknown"
    file_name = "shell.jsp"
    file_type = "unknown"
    first_seen = "2026-08-04 01:57:00"
  condition:
    hash.sha256(0, filesize) == "a7e982a1c2d0e1f4d09e675bb95901b7e470126f26f513a88a850f62cb6adaf7"
}

rule MalwareBazaar_unknown_087_49459142
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4945914236b4a5d627aab874227938f10547f42d1db9f9f319a0bd36b89a9f38"
    family = "unknown"
    file_name = "p.ps1"
    file_type = "ps1"
    first_seen = "2026-08-04 01:56:59"
  condition:
    hash.sha256(0, filesize) == "4945914236b4a5d627aab874227938f10547f42d1db9f9f319a0bd36b89a9f38"
}

rule MalwareBazaar_unknown_088_5ce81ed3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ce81ed3419f9057c86686b522d2474913a5a70a0401f5795b460b6feed2c198"
    family = "unknown"
    file_name = "v.exe"
    file_type = "exe"
    first_seen = "2026-08-04 01:56:58"
  condition:
    hash.sha256(0, filesize) == "5ce81ed3419f9057c86686b522d2474913a5a70a0401f5795b460b6feed2c198"
}

rule MalwareBazaar_Mirai_089_95d154b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95d154b27a24df2bb82ba0d3e6a3b2d268900904119291637d6890d8e3e55d6b"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-04 01:48:25"
  condition:
    hash.sha256(0, filesize) == "95d154b27a24df2bb82ba0d3e6a3b2d268900904119291637d6890d8e3e55d6b"
}

rule MalwareBazaar_Mirai_090_be0826d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be0826d7b02fc8380b8ef9003d2e54c8602c7891c3db7b62fc6616f49244b9da"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-04 01:47:40"
  condition:
    hash.sha256(0, filesize) == "be0826d7b02fc8380b8ef9003d2e54c8602c7891c3db7b62fc6616f49244b9da"
}

rule MalwareBazaar_AgentTesla_091_b721bbe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b721bbe345a775c346e36af404ea28602c92ed7b7f451b1b9eb4e5aac6bbe976"
    family = "AgentTesla"
    file_name = "Proforma Invoice No. 00124 - CONFIRM.JS"
    file_type = "js"
    first_seen = "2026-08-04 01:43:32"
  condition:
    hash.sha256(0, filesize) == "b721bbe345a775c346e36af404ea28602c92ed7b7f451b1b9eb4e5aac6bbe976"
}

rule MalwareBazaar_unknown_092_0eb39f56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eb39f56dc09aa566d3bdd4181cd896fdadcbd40c772b75f885e856f64a20af9"
    family = "unknown"
    file_name = "version-validator.js"
    file_type = "js"
    first_seen = "2026-08-04 01:37:47"
  condition:
    hash.sha256(0, filesize) == "0eb39f56dc09aa566d3bdd4181cd896fdadcbd40c772b75f885e856f64a20af9"
}

rule MalwareBazaar_Mirai_093_a9fc9779
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9fc9779102c5ff1f6e03bc8d1880bb52ac7c0dfe543eb93c07aa28766e8a876"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-08-04 01:37:25"
  condition:
    hash.sha256(0, filesize) == "a9fc9779102c5ff1f6e03bc8d1880bb52ac7c0dfe543eb93c07aa28766e8a876"
}

rule MalwareBazaar_Mirai_094_39ea33a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39ea33a5244a003b92e588735ba8bcb0b3c6d5d095df550f5d1ccd1848c1884c"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-04 01:35:38"
  condition:
    hash.sha256(0, filesize) == "39ea33a5244a003b92e588735ba8bcb0b3c6d5d095df550f5d1ccd1848c1884c"
}

rule MalwareBazaar_Mirai_095_c27cc06e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c27cc06efd48dc2d6bcbe8153f5ee23574a85f0a87878f579929c50dcbd32f2a"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-04 01:34:21"
  condition:
    hash.sha256(0, filesize) == "c27cc06efd48dc2d6bcbe8153f5ee23574a85f0a87878f579929c50dcbd32f2a"
}

rule MalwareBazaar_Mirai_096_2ec3ecd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec3ecd161efa3f8e77545aa629318cb0257f7ee6a09f98f02a81dab006d1fd6"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-08-04 01:32:30"
  condition:
    hash.sha256(0, filesize) == "2ec3ecd161efa3f8e77545aa629318cb0257f7ee6a09f98f02a81dab006d1fd6"
}

rule MalwareBazaar_Mirai_097_7b651e4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b651e4f66c0bcc2befa5a981caaf7ea1180b8bb530bb1e384ba42e70f097db1"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-08-04 01:31:28"
  condition:
    hash.sha256(0, filesize) == "7b651e4f66c0bcc2befa5a981caaf7ea1180b8bb530bb1e384ba42e70f097db1"
}

rule MalwareBazaar_Mirai_098_b1e7123c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1e7123c09c5cc0d00ba274aa17f7f0c6b1871251063d071398d3199449115b9"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-08-04 01:31:27"
  condition:
    hash.sha256(0, filesize) == "b1e7123c09c5cc0d00ba274aa17f7f0c6b1871251063d071398d3199449115b9"
}

rule MalwareBazaar_CoinMiner_099_8967d2cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8967d2cf0329e481541119aec9ec6e585a448739f11357cebdfbd308cc8722f4"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 01:30:27"
  condition:
    hash.sha256(0, filesize) == "8967d2cf0329e481541119aec9ec6e585a448739f11357cebdfbd308cc8722f4"
}

rule MalwareBazaar_unknown_100_0565c099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0565c099d16a7c3dba0468785efba40d0cdc0ac57916e453035c665e74ad1417"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 01:30:19"
  condition:
    hash.sha256(0, filesize) == "0565c099d16a7c3dba0468785efba40d0cdc0ac57916e453035c665e74ad1417"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

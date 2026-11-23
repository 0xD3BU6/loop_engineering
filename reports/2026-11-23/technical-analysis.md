# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-23

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 649 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 649 |
| Unique family labels | 9 |
| Unique file types | 14 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 39 |
| unknown | 25 |
| EasyShell | 21 |
| Formbook | 5 |
| Prometei | 4 |
| WARDENStealer | 3 |
| a310Logger | 1 |
| MassLogger | 1 |
| AgentTesla | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 58 |
| exe | 9 |
| js | 8 |
| macho | 6 |
| wsf | 5 |
| sh | 4 |
| hta | 3 |
| xls | 1 |
| cmd | 1 |
| xlsx | 1 |

## Per-Sample Analysis

### Sample 1: `a777021b7738db64`

| Field | Value |
|---|---|
| SHA-256 | `a777021b7738db64481bbcc158bf527ebcf56d38cd17c415680f819409d48da9` |
| Family label | `unknown` |
| File name | `TeklifFormu_23898.wsf` |
| File type | `wsf` |
| First seen | `2026-11-23 07:48:53` |
| Reporter | `lowmal3` |
| Tags | `wsf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b97a3943467a70fffc9da580453164a7` |
| SHA-1 | `72001bd70a2b669124033a5197d22dade22332aa` |
| SHA-256 | `a777021b7738db64481bbcc158bf527ebcf56d38cd17c415680f819409d48da9` |
| SHA3-384 | `0453179d042368458f5dfd1ca2802ee95085a2dc2cb1ca23e95734f3c454040bfcf3fd1d341a3ceb392f052689fbfc87` |
| TLSH | `T1C6B112016D90CCD60833C9324331DC8CF61880130080D81879CC1E034F315C00F43950` |
| SSDEEP | `3:vFWWMNHUzpbUO9pY7ovFNS3GXIMBUjn:TMV0p1YOXSlMejn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `wsf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_a777021b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a777021b7738db64481bbcc158bf527ebcf56d38cd17c415680f819409d48da9"
    family = "unknown"
    file_name = "TeklifFormu_23898.wsf"
    file_type = "wsf"
    first_seen = "2026-11-23 07:48:53"
  condition:
    hash.sha256(0, filesize) == "a777021b7738db64481bbcc158bf527ebcf56d38cd17c415680f819409d48da9"
}
```

### Sample 2: `982d91ce5e89a7e8`

| Field | Value |
|---|---|
| SHA-256 | `982d91ce5e89a7e8b4b2444608d99dd2c260e837bf57f61e69cf3c0271d9a326` |
| Family label | `unknown` |
| File name | `6000245011_ONE TIME VENDOR RFQ ONLY.js` |
| File type | `js` |
| First seen | `2026-11-23 07:48:33` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9925f9d145121906fb3d358593024cee` |
| SHA-1 | `e922619aca27939f5b1f94121b3ea463f14885cd` |
| SHA-256 | `982d91ce5e89a7e8b4b2444608d99dd2c260e837bf57f61e69cf3c0271d9a326` |
| SHA3-384 | `ed2616594d5a582d4b6de5705bdb2284b1147034bb74007d3f6dd5d3c6ba8698b2d38fac58fe3ddc4ab093b4a3502d37` |
| TLSH | `T1D2B1CD88BD4AA1548D32F37DCF3F920EEB6B50272A09C145759D9B801F7145641ECEDE` |
| SSDEEP | `48:yXZBJLOwZ4i8Jo6O+QdeoybpZSCJV7UZieRxT18pa7aBgav7qbwNCe6KC:yxT4i8m6ar6zQu8ItvWsNCeJC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_982d91ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "982d91ce5e89a7e8b4b2444608d99dd2c260e837bf57f61e69cf3c0271d9a326"
    family = "unknown"
    file_name = "6000245011_ONE TIME VENDOR RFQ ONLY.js"
    file_type = "js"
    first_seen = "2026-11-23 07:48:33"
  condition:
    hash.sha256(0, filesize) == "982d91ce5e89a7e8b4b2444608d99dd2c260e837bf57f61e69cf3c0271d9a326"
}
```

### Sample 3: `e3f7ea3d69f0f40c`

| Field | Value |
|---|---|
| SHA-256 | `e3f7ea3d69f0f40ce291f760ab5f0c30be31dfa3f7906d5656778fbe1f1e616b` |
| Family label | `unknown` |
| File name | `1.  Instruction to Bidders.wsf` |
| File type | `wsf` |
| First seen | `2026-11-23 07:48:25` |
| Reporter | `lowmal3` |
| Tags | `wsf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1dbf750c1060bbb606ebf9af144a60c` |
| SHA-1 | `345aa411382a34aa87794f4b84640bf1c02c132e` |
| SHA-256 | `e3f7ea3d69f0f40ce291f760ab5f0c30be31dfa3f7906d5656778fbe1f1e616b` |
| SHA3-384 | `36c360b58fe433f5ace69a84c34ee1093d28de92325f5b3e7f22a1c8b63c9cdb30e254cab0a0bb7a06803bed59259484` |
| TLSH | `T19CB1EB8D2C85E0A80973F37D9B3BA509FB2664670505C258BE9D97406FB081146ECEFE` |
| SSDEEP | `48:PwXy0OH1FQO1vClkGaRKpkFKryMW/zXJW+D2z5AktvvMa/Fq+4:Ihm1CO1Ki3waYjzP0a/Fc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `wsf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_e3f7ea3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3f7ea3d69f0f40ce291f760ab5f0c30be31dfa3f7906d5656778fbe1f1e616b"
    family = "unknown"
    file_name = "1.  Instruction to Bidders.wsf"
    file_type = "wsf"
    first_seen = "2026-11-23 07:48:25"
  condition:
    hash.sha256(0, filesize) == "e3f7ea3d69f0f40ce291f760ab5f0c30be31dfa3f7906d5656778fbe1f1e616b"
}
```

### Sample 4: `a13033b9999cb57f`

| Field | Value |
|---|---|
| SHA-256 | `a13033b9999cb57f45b08a66f5aaa7ab722c5152f6329e0b9f69a7a9d9675c91` |
| Family label | `unknown` |
| File name | `Disbursement.xls` |
| File type | `xls` |
| First seen | `2026-11-23 07:48:05` |
| Reporter | `lowmal3` |
| Tags | `CVE-2017-0199, xls` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5b6d6e82a3b12fe08f24fa05092a6f4` |
| SHA-1 | `7834b00873b9b9328c49f9603d05719e22c034fd` |
| SHA-256 | `a13033b9999cb57f45b08a66f5aaa7ab722c5152f6329e0b9f69a7a9d9675c91` |
| SHA3-384 | `1bcffdb4770571143b8b951bd29e64ff3cdb7884812fef91aca29ade655dbca10f53e63a36788077bb510f37dcb2bfd6` |
| TLSH | `T18213CF1171A2CA54F819A93A5ED4E2DF2762BEA2EE17425F37C0770F2438891D927B43` |
| SSDEEP | `768:EWjt/4e0Fk8hF2xrHIarJWGBlzyePnWPg5YOKc7UnB:E+CF2xzisRye+2YOKOUn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xls`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_a13033b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a13033b9999cb57f45b08a66f5aaa7ab722c5152f6329e0b9f69a7a9d9675c91"
    family = "unknown"
    file_name = "Disbursement.xls"
    file_type = "xls"
    first_seen = "2026-11-23 07:48:05"
  condition:
    hash.sha256(0, filesize) == "a13033b9999cb57f45b08a66f5aaa7ab722c5152f6329e0b9f69a7a9d9675c91"
}
```

### Sample 5: `f439661f7db6f089`

| Field | Value |
|---|---|
| SHA-256 | `f439661f7db6f089e46c4567728cb06ad4802f128bbcb769acedd0c46b8cab84` |
| Family label | `unknown` |
| File name | `6000190834.cmd` |
| File type | `cmd` |
| First seen | `2026-11-23 07:47:21` |
| Reporter | `lowmal3` |
| Tags | `cmd` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c09c84ae1b70d5bab40650c4aca8893b` |
| SHA-1 | `4192a0a62f65ebc6d7b5933dde4d59ee5afbf2fb` |
| SHA-256 | `f439661f7db6f089e46c4567728cb06ad4802f128bbcb769acedd0c46b8cab84` |
| SHA3-384 | `2e39a608e323350e130dbc87deb5ef8a4c9541b0e884cfd9b10b7f1f34bccf86a4a4754782b48a72b381f09fedd88b13` |
| TLSH | `T18BF19678A7EEDAADC1DB489AD5C8D844A6F631A78E70040785BCAF081F579CCDD1C634` |
| SSDEEP | `96:6rYoeoe5SaqtbLivN4I/UMerXUGYselVFAdRRapak/zFZLgAtlursgAOJ:n81yt/U/Eu0VFI3ap7zzkAtcrsyJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `cmd`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_f439661f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f439661f7db6f089e46c4567728cb06ad4802f128bbcb769acedd0c46b8cab84"
    family = "unknown"
    file_name = "6000190834.cmd"
    file_type = "cmd"
    first_seen = "2026-11-23 07:47:21"
  condition:
    hash.sha256(0, filesize) == "f439661f7db6f089e46c4567728cb06ad4802f128bbcb769acedd0c46b8cab84"
}
```

### Sample 6: `a85c22086899c405`

| Field | Value |
|---|---|
| SHA-256 | `a85c22086899c4053e831c5ebbe659b05fcdba98e3118667e3a8567e8ea34dab` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Exploit.CVE-2017-0199.04.Gen.26425832` |
| File type | `xlsx` |
| First seen | `2026-11-23 07:45:25` |
| Reporter | `SecuriteInfoCom` |
| Tags | `CVE-2017-0199, xlsx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d6db153a1776ec53907abd761a0fecf` |
| SHA-1 | `dfbcae6d7c23416fcc13b3c2c017d878bd600c68` |
| SHA-256 | `a85c22086899c4053e831c5ebbe659b05fcdba98e3118667e3a8567e8ea34dab` |
| SHA3-384 | `c14abd4e3fc4cbfe864c9d0fb103bf6f0c8e280e816b3e6b44db03ae19a800b9614afdf81c29af952c79965579f59f09` |
| TLSH | `T1D564121D32A2C7CBC14B897D4DC8C5872A22FE695F1BC64B7380B78D09393D1AA5935E` |
| SSDEEP | `6144:UAgY8KY3fv4T1ddUiVqy81bzWLp8OGW6gzt28gtibMAx32ZkATPR9:UAh8KYHm1XUiVENWuOrd5jkM32bV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xlsx`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_a85c2208
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a85c22086899c4053e831c5ebbe659b05fcdba98e3118667e3a8567e8ea34dab"
    family = "unknown"
    file_name = "SecuriteInfo.com.Exploit.CVE-2017-0199.04.Gen.26425832"
    file_type = "xlsx"
    first_seen = "2026-11-23 07:45:25"
  condition:
    hash.sha256(0, filesize) == "a85c22086899c4053e831c5ebbe659b05fcdba98e3118667e3a8567e8ea34dab"
}
```

### Sample 7: `ac6c4b597101ee06`

| Field | Value |
|---|---|
| SHA-256 | `ac6c4b597101ee0621921621c2f687595d24a8829176a2cbd0f1a0fc8cefde4b` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_arm64-ac6c4b597101ee06.bin` |
| File type | `macho` |
| First seen | `2026-11-23 07:37:28` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1aa289e3ac9ac741fa64186c3216dea` |
| SHA-1 | `b9b91553d320c51830b1b729d5d1ca3fcebadd20` |
| SHA-256 | `ac6c4b597101ee0621921621c2f687595d24a8829176a2cbd0f1a0fc8cefde4b` |
| SHA3-384 | `35b6bb85d18528f6dcd3a6b9e7e9ce8e133f3cceff4d9754282889d1ab7dfe24d08e999d4cee871112206f81f28f6220` |
| TLSH | `T137F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1TgXsj5g5FIU6icBV8GQU5NZm+lzy:8SeI1gkkvTgXt5C+OGU5NZm+lzy` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_007_ac6c4b59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac6c4b597101ee0621921621c2f687595d24a8829176a2cbd0f1a0fc8cefde4b"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-ac6c4b597101ee06.bin"
    file_type = "macho"
    first_seen = "2026-11-23 07:37:28"
  condition:
    hash.sha256(0, filesize) == "ac6c4b597101ee0621921621c2f687595d24a8829176a2cbd0f1a0fc8cefde4b"
}
```

### Sample 8: `acd9f7e4079b5d0e`

| Field | Value |
|---|---|
| SHA-256 | `acd9f7e4079b5d0e6682b607f780795b11e5be20fe11283e5c1705a36fbfc1c5` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_amd64-acd9f7e4079b5d0e.bin` |
| File type | `macho` |
| First seen | `2026-11-23 07:37:17` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84955fa963c6f40e82701da4f7066d5d` |
| SHA-1 | `4d00f7891d0e6bac512861007ca50270d386a0a7` |
| SHA-256 | `acd9f7e4079b5d0e6682b607f780795b11e5be20fe11283e5c1705a36fbfc1c5` |
| SHA3-384 | `9da29cc226d46e37a453279fc26ea93296eae884a673700173288932be538cf17ff2608824878bda4280dd12d647b7b6` |
| TLSH | `T142168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6wKhx+wgbZmBlzgX:kyLbLNomEr6wKj+` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_008_acd9f7e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acd9f7e4079b5d0e6682b607f780795b11e5be20fe11283e5c1705a36fbfc1c5"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-acd9f7e4079b5d0e.bin"
    file_type = "macho"
    first_seen = "2026-11-23 07:37:17"
  condition:
    hash.sha256(0, filesize) == "acd9f7e4079b5d0e6682b607f780795b11e5be20fe11283e5c1705a36fbfc1c5"
}
```

### Sample 9: `2c5acecebf16c6f0`

| Field | Value |
|---|---|
| SHA-256 | `2c5acecebf16c6f00435c6bbd08afcc04936c5cd6291a8ed2987c5e05e667409` |
| Family label | `EasyShell` |
| File name | `easyshell-a64-2c5acecebf16c6f0.bin` |
| File type | `elf` |
| First seen | `2026-11-23 07:37:09` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `042ace826f8ca97660a1d723a83c878f` |
| SHA-1 | `190210a4281c2d51df2e85c3dd8530c3409c4f3f` |
| SHA-256 | `2c5acecebf16c6f00435c6bbd08afcc04936c5cd6291a8ed2987c5e05e667409` |
| SHA3-384 | `f440e8f990373f341fd8cf588f5e79a259c40891106b2b8cc4baac9510b79c0695b85b89a58aa67de34536d39a1053ab` |
| TLSH | `T1DF06B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712W2GYKIU6iKx4YzjJHz2b3:EWBWoO2OC712W2Ld+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_009_2c5acece
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c5acecebf16c6f00435c6bbd08afcc04936c5cd6291a8ed2987c5e05e667409"
    family = "EasyShell"
    file_name = "easyshell-a64-2c5acecebf16c6f0.bin"
    file_type = "elf"
    first_seen = "2026-11-23 07:37:09"
  condition:
    hash.sha256(0, filesize) == "2c5acecebf16c6f00435c6bbd08afcc04936c5cd6291a8ed2987c5e05e667409"
}
```

### Sample 10: `3716548d748d8bb4`

| Field | Value |
|---|---|
| SHA-256 | `3716548d748d8bb486ec339fa4d9d54076264a6bbe9b88fc7b548296c5c10a99` |
| Family label | `EasyShell` |
| File name | `easyshell-a32-3716548d748d8bb4.bin` |
| File type | `elf` |
| First seen | `2026-11-23 07:37:01` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f432f4a24210d98cf59cc84408351e46` |
| SHA-1 | `38e6745c0fe21257b5ae8851245d99a31d796e06` |
| SHA-256 | `3716548d748d8bb486ec339fa4d9d54076264a6bbe9b88fc7b548296c5c10a99` |
| SHA3-384 | `df4b46314f11fa8f490a7841fa7ae7c66ac4b3886e143a879e8a12062455a38c0c78d214148665133187be61a6143ec0` |
| TLSH | `T14EF53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBy:FhvZpiEGUx+pVdqt2laB` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_010_3716548d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3716548d748d8bb486ec339fa4d9d54076264a6bbe9b88fc7b548296c5c10a99"
    family = "EasyShell"
    file_name = "easyshell-a32-3716548d748d8bb4.bin"
    file_type = "elf"
    first_seen = "2026-11-23 07:37:01"
  condition:
    hash.sha256(0, filesize) == "3716548d748d8bb486ec339fa4d9d54076264a6bbe9b88fc7b548296c5c10a99"
}
```

### Sample 11: `30eed7cc22eca8d8`

| Field | Value |
|---|---|
| SHA-256 | `30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc` |
| Family label | `unknown` |
| File name | `COMMERCIAL INVOICE AND PACKING LIST.exe` |
| File type | `exe` |
| First seen | `2026-11-23 07:32:35` |
| Reporter | `threatcat_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5010b8399509839408562b25414645bc` |
| SHA-1 | `678c208a9fc9a174127dac6f2a2393aa88011ba7` |
| SHA-256 | `30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc` |
| SHA3-384 | `18778ff9a811a0c8e677cdbfe5d116b552e808bdd513fc91418bee923f01de2eb98dd2e5812cb0fcee2c5b4c444a0d36` |
| IMPHASH | `34c1613ad57f5792b6bb9a7a4b724d84` |
| TLSH | `T16A85CF59F39802E8D917D2B4CB551273E7317836077469DB13AAEA091F339E06E3E722` |
| SSDEEP | `24576:jnAKdG61ZP7325wYtt4s6Mool0U0PHpAylSvpwlFjfkegAX3uxFXhXd:jnAWV4ks6Moox0Ppblc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_30eed7cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc"
    family = "unknown"
    file_name = "COMMERCIAL INVOICE AND PACKING LIST.exe"
    file_type = "exe"
    first_seen = "2026-11-23 07:32:35"
  condition:
    hash.sha256(0, filesize) == "30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc"
}
```

### Sample 12: `13663488e8447854`

| Field | Value |
|---|---|
| SHA-256 | `13663488e8447854d98e1526b7d640cbe340266b4b2480538408555bdfb24d0e` |
| Family label | `Mirai` |
| File name | `s` |
| File type | `sh` |
| First seen | `2026-11-23 07:23:21` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74d46397f419a750db193f2f91038c84` |
| SHA-1 | `280a3bcdab12b158be4d58d629f49f241f69bfd8` |
| SHA-256 | `13663488e8447854d98e1526b7d640cbe340266b4b2480538408555bdfb24d0e` |
| SHA3-384 | `683936af29648ae237452b11221b53c9ccc97b251c4c66e5805d98d8b6be7e0959b33b0af6dede70a480976179576f38` |
| TLSH | `T10652C7B3E6A016B275C2C83DA74AA15129473567BD642880F08FB5447FFCD7AB131BB4` |
| SSDEEP | `192:cLz4uv7bRxiA+GU7MNM/e2t4CWxZ0L+tJtOJEQqZTGpizSbyjCLESBy0gOUM1sto:6zvIG4U2t41x/f84+1gO41p/lgYo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_13663488
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13663488e8447854d98e1526b7d640cbe340266b4b2480538408555bdfb24d0e"
    family = "Mirai"
    file_name = "s"
    file_type = "sh"
    first_seen = "2026-11-23 07:23:21"
  condition:
    hash.sha256(0, filesize) == "13663488e8447854d98e1526b7d640cbe340266b4b2480538408555bdfb24d0e"
}
```

### Sample 13: `ab5ea6651fa00f33`

| Field | Value |
|---|---|
| SHA-256 | `ab5ea6651fa00f33f10de1069c377904acf6d99cc0fabe349b31eeba491f836b` |
| Family label | `unknown` |
| File name | `8844` |
| File type | `elf` |
| First seen | `2026-11-23 07:22:33` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f28151b4373c88d3e0a830c35691a80` |
| SHA-1 | `a66c0d26bc13737746af850a7a266737901854cc` |
| SHA-256 | `ab5ea6651fa00f33f10de1069c377904acf6d99cc0fabe349b31eeba491f836b` |
| SHA3-384 | `a0d0896a697485ae7a85e95f3683b026f42b7919d13adf346c7026f2074a58de3b7d1342100e7618d18f1f8ab0bf9d17` |
| TLSH | `T129457D0EEA42DAB2E1B19171068FE7725531843AC633D163EF5E7F68B476310AE0D35A` |
| TELFHASH | `t1bcd0a70fe210731b7ed5088237cd17c90197c3561dc55e9fec994904a63517d7c68c92` |
| SSDEEP | `24576:qdrY6gr1l5rR5mf42AOJvl9dPcZ6p4cwRc8ocWrTPkK5HcoMyG39wNvpAo:EFYbXKJ5K4TPkKWoMyG+Nd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_ab5ea665
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab5ea6651fa00f33f10de1069c377904acf6d99cc0fabe349b31eeba491f836b"
    family = "unknown"
    file_name = "8844"
    file_type = "elf"
    first_seen = "2026-11-23 07:22:33"
  condition:
    hash.sha256(0, filesize) == "ab5ea6651fa00f33f10de1069c377904acf6d99cc0fabe349b31eeba491f836b"
}
```

### Sample 14: `bc0b1e172b1505ee`

| Field | Value |
|---|---|
| SHA-256 | `bc0b1e172b1505ee2a202a3a61f7133631523c936b37ef645612ca51ed4e87d0` |
| Family label | `a310Logger` |
| File name | `Payment_Advice_and_Surrender_BL_Request_SITRGCEG251528.msi` |
| File type | `msi` |
| First seen | `2026-11-23 07:06:35` |
| Reporter | `lowmal3` |
| Tags | `a310Logger, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01e2f8b60e7bef265c68cc99be8ce2e6` |
| SHA-1 | `834cc84cfc2a0b71a475902fb8dd81643c45c4ac` |
| SHA-256 | `bc0b1e172b1505ee2a202a3a61f7133631523c936b37ef645612ca51ed4e87d0` |
| SHA3-384 | `3d20909246c518e91a4a211e2bb720383e5a2b60215447d79c4f5b08e219275b643c13d70637997588f913c74d848d8a` |
| TLSH | `T1031523E9B2DA9330C886737693AD12FE4D5A6D2C5F4C2656317BB4CC59BFC20E2211D8` |
| SSDEEP | `24576:BcnBIYFxtEcg/6JR2RupAJGQu6zqpFOKvtg:6B6cDIuCGQ+wKlg` |

#### Technical Assessment

- The sample is tracked as `a310Logger` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_a310Logger_014_bc0b1e17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc0b1e172b1505ee2a202a3a61f7133631523c936b37ef645612ca51ed4e87d0"
    family = "a310Logger"
    file_name = "Payment_Advice_and_Surrender_BL_Request_SITRGCEG251528.msi"
    file_type = "msi"
    first_seen = "2026-11-23 07:06:35"
  condition:
    hash.sha256(0, filesize) == "bc0b1e172b1505ee2a202a3a61f7133631523c936b37ef645612ca51ed4e87d0"
}
```

### Sample 15: `07c2c1fd1700e569`

| Field | Value |
|---|---|
| SHA-256 | `07c2c1fd1700e569d04e6e2fbea1bed75422caec72344ed3eebc2f012bbb089e` |
| Family label | `EasyShell` |
| File name | `easyshell-l64-07c2c1fd1700e569.bin` |
| File type | `elf` |
| First seen | `2026-11-23 07:05:38` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca670fc0de21b7c6470076d8ad1ff178` |
| SHA-1 | `60491ede4d5a9aa0448f11b62d92bc15d15dd98c` |
| SHA-256 | `07c2c1fd1700e569d04e6e2fbea1bed75422caec72344ed3eebc2f012bbb089e` |
| SHA3-384 | `0cec8b5f87196bfdfcf0fc8f3e88ff4e947a602fce4807f3d33cd1ff11640f5b4d3c3e19a68a0392a36b11a7bf39dd79` |
| TLSH | `T16F267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxiQH8hIU6iKHh:OYjiiKgib9qRGcEulQcW+gh` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_015_07c2c1fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07c2c1fd1700e569d04e6e2fbea1bed75422caec72344ed3eebc2f012bbb089e"
    family = "EasyShell"
    file_name = "easyshell-l64-07c2c1fd1700e569.bin"
    file_type = "elf"
    first_seen = "2026-11-23 07:05:38"
  condition:
    hash.sha256(0, filesize) == "07c2c1fd1700e569d04e6e2fbea1bed75422caec72344ed3eebc2f012bbb089e"
}
```

### Sample 16: `0781ae0479ce0c1a`

| Field | Value |
|---|---|
| SHA-256 | `0781ae0479ce0c1ae23a3133aaec7d466852b037361aeb108ef1431b436096fb` |
| Family label | `EasyShell` |
| File name | `easyshell-l32-0781ae0479ce0c1a.bin` |
| File type | `elf` |
| First seen | `2026-11-23 07:05:29` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ac3869a14d4ef507db3a5e294ce668e` |
| SHA-1 | `d08fb4d57b19b5d6cf405d1a9511fddb8d7ebc3d` |
| SHA-256 | `0781ae0479ce0c1ae23a3133aaec7d466852b037361aeb108ef1431b436096fb` |
| SHA3-384 | `62dd7dca2984acfa4ba33b80314b8e51c127495cb339502c17cd1014e19d417e73900c150fc8a00277c325d053c6e563` |
| TLSH | `T1B8068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1RF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1Rdb` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_016_0781ae04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0781ae0479ce0c1ae23a3133aaec7d466852b037361aeb108ef1431b436096fb"
    family = "EasyShell"
    file_name = "easyshell-l32-0781ae0479ce0c1a.bin"
    file_type = "elf"
    first_seen = "2026-11-23 07:05:29"
  condition:
    hash.sha256(0, filesize) == "0781ae0479ce0c1ae23a3133aaec7d466852b037361aeb108ef1431b436096fb"
}
```

### Sample 17: `f8b7c4ffaceb2896`

| Field | Value |
|---|---|
| SHA-256 | `f8b7c4ffaceb2896e1a09846f6ae430e7de4a633c154cc66f4827b806dffab0b` |
| Family label | `EasyShell` |
| File name | `easyshell-l128-f8b7c4ffaceb2896.bin` |
| File type | `elf` |
| First seen | `2026-11-23 07:05:21` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b8918957f914392e09491c353762107` |
| SHA-1 | `3dabd4fdca0dec1ff6f30c670642c29a10cde684` |
| SHA-256 | `f8b7c4ffaceb2896e1a09846f6ae430e7de4a633c154cc66f4827b806dffab0b` |
| SHA3-384 | `9534cb01e538ee4b3e5ef014290c54ae7810adee5b6142c28c2e230e20006764884beb2bbb8b6673012f5573e7556f56` |
| TLSH | `T147067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1C6:FUkCxwUGnaPdX8PPAS` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_017_f8b7c4ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b7c4ffaceb2896e1a09846f6ae430e7de4a633c154cc66f4827b806dffab0b"
    family = "EasyShell"
    file_name = "easyshell-l128-f8b7c4ffaceb2896.bin"
    file_type = "elf"
    first_seen = "2026-11-23 07:05:21"
  condition:
    hash.sha256(0, filesize) == "f8b7c4ffaceb2896e1a09846f6ae430e7de4a633c154cc66f4827b806dffab0b"
}
```

### Sample 18: `6a90bad16168d6d0`

| Field | Value |
|---|---|
| SHA-256 | `6a90bad16168d6d0807383e48bf5a3ebc705bcb6fc45812a496500ee9d26d0c3` |
| Family label | `unknown` |
| File name | `Plastic Connection Piece.hta` |
| File type | `hta` |
| First seen | `2026-11-23 06:56:31` |
| Reporter | `lowmal3` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02b52db42e8e035c399ae2d2ce0e20a1` |
| SHA-1 | `7d7e489dd3bf15ad1dd86be84a0154300ebdb085` |
| SHA-256 | `6a90bad16168d6d0807383e48bf5a3ebc705bcb6fc45812a496500ee9d26d0c3` |
| SHA3-384 | `02f4ff02d56baac30702d7c1a79be164ab3a2287c6483abbb5d3c32467ce2b681b1428e795f7a28988b86a9027eedeb0` |
| TLSH | `T1A4A20E045581A554977B6B37B726A8E4F7B70A6B00904A47B87CB884DFF2D0CDEE0CB6` |
| SSDEEP | `384:ilcBJZL/OHYluG0emWMzDVTchXmbyLdLi+YrkckXUmdAfc1d:ilch/OHYlugmWMXVT2XmbcdLi+YrEU3e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_6a90bad1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a90bad16168d6d0807383e48bf5a3ebc705bcb6fc45812a496500ee9d26d0c3"
    family = "unknown"
    file_name = "Plastic Connection Piece.hta"
    file_type = "hta"
    first_seen = "2026-11-23 06:56:31"
  condition:
    hash.sha256(0, filesize) == "6a90bad16168d6d0807383e48bf5a3ebc705bcb6fc45812a496500ee9d26d0c3"
}
```

### Sample 19: `9149061f9cd11ad1`

| Field | Value |
|---|---|
| SHA-256 | `9149061f9cd11ad182a505fbd09df0045c54a48f0177ed685891c9f824a74d4f` |
| Family label | `Formbook` |
| File name | `MqQFgHFgSV6aWli.exe` |
| File type | `exe` |
| First seen | `2026-11-23 06:55:19` |
| Reporter | `lowmal3` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0be099bc5ceb2bcac0ffcfa4d59f6a86` |
| SHA-1 | `5d068743a2e7da03a6324fec0a806c60c9c9b2f5` |
| SHA-256 | `9149061f9cd11ad182a505fbd09df0045c54a48f0177ed685891c9f824a74d4f` |
| SHA3-384 | `f01b072bfa34795c1ea4ed3845ebe5d0bad56bfe35dac715581562c162172814ece78ed643de962d332bc39efd3685a9` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B105F1483254CB06D93A57F915B2E27923F6AE9EA421E30A5FD67DDB7972F001D08323` |
| SSDEEP | `12288:oik+5O+2qIjpzuK/jmh43JqUSG/kff9o5cpZMvdi2tE1POKb1:T5BYt/jmQqUSG/A9o5ckrE1Pl1` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_019_9149061f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9149061f9cd11ad182a505fbd09df0045c54a48f0177ed685891c9f824a74d4f"
    family = "Formbook"
    file_name = "MqQFgHFgSV6aWli.exe"
    file_type = "exe"
    first_seen = "2026-11-23 06:55:19"
  condition:
    hash.sha256(0, filesize) == "9149061f9cd11ad182a505fbd09df0045c54a48f0177ed685891c9f824a74d4f"
}
```

### Sample 20: `912705df252116cc`

| Field | Value |
|---|---|
| SHA-256 | `912705df252116cc5387043ed1243765c85603e2051736ec4f7c93e234f8ca21` |
| Family label | `unknown` |
| File name | `Packing List, Commercial Invoice and Bill Of Lading.JS` |
| File type | `js` |
| First seen | `2026-11-23 06:55:01` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f109ec39786153f8f4192491375cd0e` |
| SHA-1 | `010b27b7e25cfdb7f46cb73f9ca71f65eac121db` |
| SHA-256 | `912705df252116cc5387043ed1243765c85603e2051736ec4f7c93e234f8ca21` |
| SHA3-384 | `7d6d8e894ee8dfbbaf1bebfdc566fb4cba6a893013e7563a3a4e7c567b6431e54f2652a30a129fed5cd43c83030a799c` |
| TLSH | `T189F5B55527449632666DAB3CF136BA245A1F601311C7DB3F30AC9224B62CE1BD7DCAE3` |
| SSDEEP | `98304:3fXke4HM5vuPi1tmAAb3AyKjZjZAhgkpU791+53Ej7NQ1Ap84j+dhkSFomzS/4FI:3fXkpHM52Pi1t9Ab3AyKlZAAhuk7W1/G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_912705df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "912705df252116cc5387043ed1243765c85603e2051736ec4f7c93e234f8ca21"
    family = "unknown"
    file_name = "Packing List, Commercial Invoice and Bill Of Lading.JS"
    file_type = "js"
    first_seen = "2026-11-23 06:55:01"
  condition:
    hash.sha256(0, filesize) == "912705df252116cc5387043ed1243765c85603e2051736ec4f7c93e234f8ca21"
}
```

### Sample 21: `38505e84d36a1808`

| Field | Value |
|---|---|
| SHA-256 | `38505e84d36a18082944ffa13d569182782eb1a52475691781146ec89e07c198` |
| Family label | `unknown` |
| File name | `20032838 - TEKLİF FORMU_pdf.hta` |
| File type | `hta` |
| First seen | `2026-11-23 06:54:12` |
| Reporter | `lowmal3` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c717262530ab1f08bf7035005f40693` |
| SHA-1 | `250f5cb25a9023d134506ed98434a30c7c59280a` |
| SHA-256 | `38505e84d36a18082944ffa13d569182782eb1a52475691781146ec89e07c198` |
| SHA3-384 | `40a05bca683046e40ec9a20eccfab8c0a7f9b68664a46ee7ba7817b6a7a736824046d872adcfd1539d22984e72c0b0f4` |
| TLSH | `T1F8A20E045581A554977B6B37B726A8E4F7B70A6B00904A47B87CB884DFF2D0CDEE0CB6` |
| SSDEEP | `384:ilcBJZL/OHYluG0emWZzDVTchXmbyLdLi+YrkckXUmdAfc1d:ilch/OHYlugmWZXVT2XmbcdLi+YrEU3e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_38505e84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38505e84d36a18082944ffa13d569182782eb1a52475691781146ec89e07c198"
    family = "unknown"
    file_name = "20032838 - TEKLİF FORMU_pdf.hta"
    file_type = "hta"
    first_seen = "2026-11-23 06:54:12"
  condition:
    hash.sha256(0, filesize) == "38505e84d36a18082944ffa13d569182782eb1a52475691781146ec89e07c198"
}
```

### Sample 22: `27957fd69ffe2579`

| Field | Value |
|---|---|
| SHA-256 | `27957fd69ffe2579e76bd091186af4f47d6fa244afa6539783d8e9db1a77664c` |
| Family label | `Formbook` |
| File name | `DİOKİ_MALZEME FİYAT TEKLİFİ İSTEĞİ HK.wsf` |
| File type | `wsf` |
| First seen | `2026-11-23 06:53:26` |
| Reporter | `lowmal3` |
| Tags | `Formbook, wsf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba000bc17f1ecbf0e7dcfca5ec2091d4` |
| SHA-1 | `aa0f574dfe9e1da2e723cfc62a26a670f44219ca` |
| SHA-256 | `27957fd69ffe2579e76bd091186af4f47d6fa244afa6539783d8e9db1a77664c` |
| SHA3-384 | `5d984d0d980f32d22887c25395b6920699128190d697e513b0ecaa2cc6dadf76f478102eab2523f9eea79fe5f1b71bd4` |
| TLSH | `T1C281AB8D2CC7B0148677F33D8B6F940DFB6BA963165A8255B88CA2912F71028426DEDD` |
| SSDEEP | `48:0glmepANlpeLUMXJWoRIz73DmrKDbNyCO6jN/cDTGTphLozorQI4:0g4D8VYF3olyjN/cfGTHUorQp` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `wsf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_022_27957fd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27957fd69ffe2579e76bd091186af4f47d6fa244afa6539783d8e9db1a77664c"
    family = "Formbook"
    file_name = "DİOKİ_MALZEME FİYAT TEKLİFİ İSTEĞİ HK.wsf"
    file_type = "wsf"
    first_seen = "2026-11-23 06:53:26"
  condition:
    hash.sha256(0, filesize) == "27957fd69ffe2579e76bd091186af4f47d6fa244afa6539783d8e9db1a77664c"
}
```

### Sample 23: `a8526e3335b0c8e6`

| Field | Value |
|---|---|
| SHA-256 | `a8526e3335b0c8e6e0dab8ba95e815f3c0caa733c280f4944d34cc5f70bb7e9a` |
| Family label | `Formbook` |
| File name | `ÜÇAY FIYAT TEKLIFI (TOLGA BEY PROJESİ) ÜÇAY MÜHENDİSLİK WILO POMPA.wsf` |
| File type | `wsf` |
| First seen | `2026-11-23 06:52:47` |
| Reporter | `lowmal3` |
| Tags | `Formbook, wsf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `942a0adfaefb02dcc6aec9263a5705ee` |
| SHA-1 | `5f3533d47688bce81092c0fc639a411f38aafcef` |
| SHA-256 | `a8526e3335b0c8e6e0dab8ba95e815f3c0caa733c280f4944d34cc5f70bb7e9a` |
| SHA3-384 | `a545e012997a94fcb40639a96d777629266a06f5326f8008c6b37eca17fd9002f8ecd1d6676193c788db4cb0f89f5b6c` |
| TLSH | `T1B681CD8D3CC7B0148677F33C8B6F940DFB6BA963165A8255B88CA2912F71028426DFDD` |
| SSDEEP | `48:0glmepANlpeLUMXJWoRIz73DmrKJqyCO6jN/cDTGTphLozorQI4:0g4D8VYF3oiyjN/cfGTHUorQp` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `wsf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_023_a8526e33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8526e3335b0c8e6e0dab8ba95e815f3c0caa733c280f4944d34cc5f70bb7e9a"
    family = "Formbook"
    file_name = "ÜÇAY FIYAT TEKLIFI (TOLGA BEY PROJESİ) ÜÇAY MÜHENDİSLİK WILO POMPA.wsf"
    file_type = "wsf"
    first_seen = "2026-11-23 06:52:47"
  condition:
    hash.sha256(0, filesize) == "a8526e3335b0c8e6e0dab8ba95e815f3c0caa733c280f4944d34cc5f70bb7e9a"
}
```

### Sample 24: `c07f09b938a87928`

| Field | Value |
|---|---|
| SHA-256 | `c07f09b938a879280282d717345fe11e59e41e6e743e20077816708a7f0a3e7e` |
| Family label | `MassLogger` |
| File name | `Dekont.VBE` |
| File type | `vbe` |
| First seen | `2026-11-23 06:52:31` |
| Reporter | `lowmal3` |
| Tags | `MassLogger, vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29505cdc3c37f62c636ed75d6746b588` |
| SHA-1 | `098ff60f6e978c28cdda1c6e99d78601dcaec53b` |
| SHA-256 | `c07f09b938a879280282d717345fe11e59e41e6e743e20077816708a7f0a3e7e` |
| SHA3-384 | `513931d0dfda5e400c58b6ddccb0060f9d3fd2725842d1ee1c342a176744b24d11cd8f1adeeb36d27450b754088c7ea0` |
| TLSH | `T1D0E4F11588C43EE8EEBD961840FD563EE3B1069B482DA949F733FE829FB7544530618B` |
| SSDEEP | `12288:F2teFYNUbmuKVcSbjaqKNvPxp4nZ7g02e/8ViwJMWU4UW8hf:FvYemuKWV4n7+VcWK` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_024_c07f09b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c07f09b938a879280282d717345fe11e59e41e6e743e20077816708a7f0a3e7e"
    family = "MassLogger"
    file_name = "Dekont.VBE"
    file_type = "vbe"
    first_seen = "2026-11-23 06:52:31"
  condition:
    hash.sha256(0, filesize) == "c07f09b938a879280282d717345fe11e59e41e6e743e20077816708a7f0a3e7e"
}
```

### Sample 25: `47b6cd26a1cd791c`

| Field | Value |
|---|---|
| SHA-256 | `47b6cd26a1cd791cbc9607abac4ec9e97d752ff55c17310062685cee4301953a` |
| Family label | `unknown` |
| File name | `SHIPMENT-PL & CI & BL draft for HF26XF0116A.js` |
| File type | `js` |
| First seen | `2026-11-23 06:51:21` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9ca1bf8d2485ba51ead207b30dccf45` |
| SHA-1 | `bc262f268712c2358a0a8213bc381b21fa29791b` |
| SHA-256 | `47b6cd26a1cd791cbc9607abac4ec9e97d752ff55c17310062685cee4301953a` |
| SHA3-384 | `bfc87081f0092028732fd90fc81238ca7f1e8154bb4b9663d135df8c82a4da875f5df2f94c2466adb0ff6e5300e962bf` |
| TLSH | `T1FE2512469D05AE5F4D6C275EB8010D0DA6163E13D0B69BD63ADE0CFE232E95835FC368` |
| SSDEEP | `12288:iH2kFhe7eh4mtM4qgMvY6PbGHm0gfqbJhlb204OYuj8at6wAIQBCoO30nxxAqjxW:e2FBXdl4Q5OYAVooo/zIyvE2Ab+P3k5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_47b6cd26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47b6cd26a1cd791cbc9607abac4ec9e97d752ff55c17310062685cee4301953a"
    family = "unknown"
    file_name = "SHIPMENT-PL & CI & BL draft for HF26XF0116A.js"
    file_type = "js"
    first_seen = "2026-11-23 06:51:21"
  condition:
    hash.sha256(0, filesize) == "47b6cd26a1cd791cbc9607abac4ec9e97d752ff55c17310062685cee4301953a"
}
```

### Sample 26: `55ea024e1028f67c`

| Field | Value |
|---|---|
| SHA-256 | `55ea024e1028f67c5b5c1912336d3225951d4884e078446c4602023bea7e502b` |
| Family label | `Formbook` |
| File name | `Panduan Mengisi SST-02 (Manual) dan Pindaan - BM (2025) (4)_pdf.wsf` |
| File type | `wsf` |
| First seen | `2026-11-23 06:48:35` |
| Reporter | `lowmal3` |
| Tags | `Formbook, wsf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1517bec987a4e7a35e2776f33c3dbfef` |
| SHA-1 | `908220a20d07a7e97347a9029a7c3d87cfa5ff95` |
| SHA-256 | `55ea024e1028f67c5b5c1912336d3225951d4884e078446c4602023bea7e502b` |
| SHA3-384 | `cb27be8f98b7018f803b49da61305b5600e3fff9f1ac0914d995dec79c0e7b997818a03ad72c7557ad7e2294a08911df` |
| TLSH | `T10AB1CB48BD82E0544A73F37E8B6B940DFB765917000AD204BA9CD3945F7142887ADFED` |
| SSDEEP | `48:aVbGoFXupLWagoe772EIfQYCXJWRGxTLr/f6cycA5sN7Eb3AqNB64VPFqH4:mFqLBgoA2APY8DyIA5sN7EbT364VPFX` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `wsf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_026_55ea024e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55ea024e1028f67c5b5c1912336d3225951d4884e078446c4602023bea7e502b"
    family = "Formbook"
    file_name = "Panduan Mengisi SST-02 (Manual) dan Pindaan - BM (2025) (4)_pdf.wsf"
    file_type = "wsf"
    first_seen = "2026-11-23 06:48:35"
  condition:
    hash.sha256(0, filesize) == "55ea024e1028f67c5b5c1912336d3225951d4884e078446c4602023bea7e502b"
}
```

### Sample 27: `462a3a6a60418ce6`

| Field | Value |
|---|---|
| SHA-256 | `462a3a6a60418ce6ed83d837ab71b7352b060ea4b327e08a7cec6f523f4ec6a0` |
| Family label | `unknown` |
| File name | `GUIDELINE FOR E-DISBURSEMENT REGISTRATION.hta` |
| File type | `hta` |
| First seen | `2026-11-23 06:47:54` |
| Reporter | `lowmal3` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a2f5fdc48e761c6c8a4328d05c269f6` |
| SHA-1 | `45dd5cd0cdd2abccb70c5a16099df68b1332cccb` |
| SHA-256 | `462a3a6a60418ce6ed83d837ab71b7352b060ea4b327e08a7cec6f523f4ec6a0` |
| SHA3-384 | `c334215d17fd26583ee793f209ae4571807da51914d2c94bf39b960a9c8457f5cd194551d925a7be126246eb5998aed9` |
| TLSH | `T1ACA20E045581A554977B6B37B726A8E4F7B70A6B00904A47B87CB884DFF2D0CDEE0CB6` |
| SSDEEP | `384:ilcBJZL/OHYluG0emWwzDVTchXmbyLdLi+YrkckXUmdAfc1d:ilch/OHYlugmWwXVT2XmbcdLi+YrEU3e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_462a3a6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "462a3a6a60418ce6ed83d837ab71b7352b060ea4b327e08a7cec6f523f4ec6a0"
    family = "unknown"
    file_name = "GUIDELINE FOR E-DISBURSEMENT REGISTRATION.hta"
    file_type = "hta"
    first_seen = "2026-11-23 06:47:54"
  condition:
    hash.sha256(0, filesize) == "462a3a6a60418ce6ed83d837ab71b7352b060ea4b327e08a7cec6f523f4ec6a0"
}
```

### Sample 28: `eac83fa7cd9542f4`

| Field | Value |
|---|---|
| SHA-256 | `eac83fa7cd9542f4d467dab553fd81b535a7c0ab970d7be743973aaee15f366f` |
| Family label | `unknown` |
| File name | `280298206_Acknowledgement copy for delivery order request.js` |
| File type | `js` |
| First seen | `2026-11-23 06:47:35` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32bfb67b10c6fe66e7fa1a260a01d604` |
| SHA-1 | `4a8e0447e9171660b96e427f8e910bf4a7dfa20f` |
| SHA-256 | `eac83fa7cd9542f4d467dab553fd81b535a7c0ab970d7be743973aaee15f366f` |
| SHA3-384 | `08fe8eac3b3b7aa4f63bce1f0f8a975fbe4e91226cd020ab20a81f36cb56c8bf883500c5d5d19ed7564d4fcc759e2675` |
| TLSH | `T1D17283C810DCDB83481E14F792F87710638A0D6DE455CB5C3B9DA9DE7C0A8609A7EBAC` |
| SSDEEP | `384:puQ/HZtsuQ/HZtsuQ/HZtGYeYuQ/HZtsuQ/HZtsuQ/HZt4:pNsNsNSYNsNsN4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_eac83fa7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eac83fa7cd9542f4d467dab553fd81b535a7c0ab970d7be743973aaee15f366f"
    family = "unknown"
    file_name = "280298206_Acknowledgement copy for delivery order request.js"
    file_type = "js"
    first_seen = "2026-11-23 06:47:35"
  condition:
    hash.sha256(0, filesize) == "eac83fa7cd9542f4d467dab553fd81b535a7c0ab970d7be743973aaee15f366f"
}
```

### Sample 29: `78da3eac7d17ec53`

| Field | Value |
|---|---|
| SHA-256 | `78da3eac7d17ec539e96f866c820519d273e991d8bf61103a4f942e252a1bbca` |
| Family label | `unknown` |
| File name | `document.scr` |
| File type | `exe` |
| First seen | `2026-11-23 06:47:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58aff32a8c3b9c347b9ccd8126c314e4` |
| SHA-1 | `8b6050e90bb3033e6c9fd64a15df663dae74ed2a` |
| SHA-256 | `78da3eac7d17ec539e96f866c820519d273e991d8bf61103a4f942e252a1bbca` |
| SHA3-384 | `8727d71cddb884a1d70d96d383ca697163b4599bdfbf9c1b03fff45e81851337ce70dd0bb263e73a3cd50e1082b6c576` |
| IMPHASH | `7ee89a85ea0ffd700fd28e6cfa3d968f` |
| TLSH | `T1EA137C73544094F7C58244706A81EA62AEB9DD771749E383F6D0AA5EECB84C76B3CF02` |
| SSDEEP | `768:Gq9m/ZsybSg2ts4L3RLc/qjhsKmHbk1+qJ0UtHG/:Gqk/Zdic/qjh8w19JDHy` |
| ICON-DHASH | `b270e0d292c0c482` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_78da3eac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78da3eac7d17ec539e96f866c820519d273e991d8bf61103a4f942e252a1bbca"
    family = "unknown"
    file_name = "document.scr"
    file_type = "exe"
    first_seen = "2026-11-23 06:47:18"
  condition:
    hash.sha256(0, filesize) == "78da3eac7d17ec539e96f866c820519d273e991d8bf61103a4f942e252a1bbca"
}
```

### Sample 30: `d5b1a5dea7412f0a`

| Field | Value |
|---|---|
| SHA-256 | `d5b1a5dea7412f0a2dc65e7fbefa7d836a289ec48c2b401bf4237cace47e4f40` |
| Family label | `Formbook` |
| File name | `REQUEST FOR QUOTATION_VMECH TECHNOLOGIES 25112026.js` |
| File type | `js` |
| First seen | `2026-11-23 06:47:12` |
| Reporter | `lowmal3` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d963d87052d5b4b94fe9409e31095c0` |
| SHA-1 | `d91c462d1bf26211191bcce80c784c131f3de808` |
| SHA-256 | `d5b1a5dea7412f0a2dc65e7fbefa7d836a289ec48c2b401bf4237cace47e4f40` |
| SHA3-384 | `108b93a44997b2e38d3a36b4795b5763fc2dd9cda6035d3787e4153a0e26aeae41bad1a82086152f4c4181a5d0d2a63e` |
| TLSH | `T1DAB1C948BD82A0644A73F37E8B6B940EFB761917040AD204BA9CD3D45F7142887ADFED` |
| SSDEEP | `48:VVbNoFXupLWagoe772EIfQYCXJWRGxTLr/f6cycA5sN7Eb3AqNB64VPFq8:KFqLBgoA2APY8DyIA5sN7EbT364VPFT` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_030_d5b1a5de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5b1a5dea7412f0a2dc65e7fbefa7d836a289ec48c2b401bf4237cace47e4f40"
    family = "Formbook"
    file_name = "REQUEST FOR QUOTATION_VMECH TECHNOLOGIES 25112026.js"
    file_type = "js"
    first_seen = "2026-11-23 06:47:12"
  condition:
    hash.sha256(0, filesize) == "d5b1a5dea7412f0a2dc65e7fbefa7d836a289ec48c2b401bf4237cace47e4f40"
}
```

### Sample 31: `668e065f8b7353d0`

| Field | Value |
|---|---|
| SHA-256 | `668e065f8b7353d0cf41d4730e5ec2e90b97b3ca5cbb7cb2db115a5516d488e8` |
| Family label | `unknown` |
| File name | `document.scr` |
| File type | `exe` |
| First seen | `2026-11-23 06:46:55` |
| Reporter | `lowmal3` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23e8b26a71bfb4293e2e5ded937999f1` |
| SHA-1 | `d79a0052afabea1a61e46e27e9015523863b5c55` |
| SHA-256 | `668e065f8b7353d0cf41d4730e5ec2e90b97b3ca5cbb7cb2db115a5516d488e8` |
| SHA3-384 | `55532e1bae450cc5fdde597acf53fcb06280a953249ecd1fbb812fc052d0f6437e1793a7a92a5781ef16c977975acf0e` |
| IMPHASH | `98cd465c2ab2841f9fd90d5e847563f4` |
| TLSH | `T18AD2C085B010BAA6C05282735D87C471F8529C640A9BD2DBB664BF7FFDF13850B0C93A` |
| SSDEEP | `384:1vxBbK26lj5Id8SpHx9jLhsznnVxA1WmP5w7GGCJlqqwMyNYl9f:Dv8IRRdsxq1DjJcqfn/` |
| ICON-DHASH | `b270e0d292c0c482` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_668e065f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668e065f8b7353d0cf41d4730e5ec2e90b97b3ca5cbb7cb2db115a5516d488e8"
    family = "unknown"
    file_name = "document.scr"
    file_type = "exe"
    first_seen = "2026-11-23 06:46:55"
  condition:
    hash.sha256(0, filesize) == "668e065f8b7353d0cf41d4730e5ec2e90b97b3ca5cbb7cb2db115a5516d488e8"
}
```

### Sample 32: `4c4507a6d7c6b7ac`

| Field | Value |
|---|---|
| SHA-256 | `4c4507a6d7c6b7ac3c165ae6dcd017c1b8ead7411e0e47ff956d5dbe63e976fd` |
| Family label | `unknown` |
| File name | `Shipment advice & HBL draft copies.JS` |
| File type | `js` |
| First seen | `2026-11-23 06:46:37` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `377e2171847f47641572f690a31f2c77` |
| SHA-1 | `8bf5b64d7051347dbfd5824bc43b5bb3ea6770c8` |
| SHA-256 | `4c4507a6d7c6b7ac3c165ae6dcd017c1b8ead7411e0e47ff956d5dbe63e976fd` |
| SHA3-384 | `928965d40fa4b982758ccbf3b177885169929aaff671d9addeb6c304f7abef56ea78602b34369ba8b66c92a63507c7da` |
| TLSH | `T18926F5B14E18A730A52DA72FC5B26A540A2E254F5EA5FF3F35BC0280725DB1722CD5B3` |
| SSDEEP | `98304:CTkMUQa4uFAVxCD6jpEm9UCG6h2AxJec940a1VuoaeqdLel4Vmwu1U+qeQkPcaNW:E2xAxDc1VtfqdLPUwu/QkPcaZKhK0cPs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_4c4507a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c4507a6d7c6b7ac3c165ae6dcd017c1b8ead7411e0e47ff956d5dbe63e976fd"
    family = "unknown"
    file_name = "Shipment advice & HBL draft copies.JS"
    file_type = "js"
    first_seen = "2026-11-23 06:46:37"
  condition:
    hash.sha256(0, filesize) == "4c4507a6d7c6b7ac3c165ae6dcd017c1b8ead7411e0e47ff956d5dbe63e976fd"
}
```

### Sample 33: `2796310b515b9d70`

| Field | Value |
|---|---|
| SHA-256 | `2796310b515b9d70e96ff2fe9239aa36ac13cba8ccbf9ca91028bee3a59e4112` |
| Family label | `unknown` |
| File name | `RFQ-Q1196-2026v4.JS` |
| File type | `js` |
| First seen | `2026-11-23 06:45:51` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `659f36ca20dca2c9b91e55365feb234b` |
| SHA-1 | `faf0ef6b00fedbd68a706cfb64470ed8dbc94c1d` |
| SHA-256 | `2796310b515b9d70e96ff2fe9239aa36ac13cba8ccbf9ca91028bee3a59e4112` |
| SHA3-384 | `a0a63461fb12aece719105e467efc18116750e2827fc4c4b97e2f7ddd7add5e0e52a6b17351544922732ba14d406a9f2` |
| TLSH | `T1324619A11F0C9970A63EA72FD0B6A5604A5D22036985EF3F34BC1644B74AB1727DD8F3` |
| SSDEEP | `98304:00Ko9CFFOX2mxyxRIrdQS1lttylLchdkLWvh8R4Cks6zbEDobpL5Oq2CapRm9+WN:+Aa6CizbEDobN5T8Y9+OHRVTB6ATgjVG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_2796310b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2796310b515b9d70e96ff2fe9239aa36ac13cba8ccbf9ca91028bee3a59e4112"
    family = "unknown"
    file_name = "RFQ-Q1196-2026v4.JS"
    file_type = "js"
    first_seen = "2026-11-23 06:45:51"
  condition:
    hash.sha256(0, filesize) == "2796310b515b9d70e96ff2fe9239aa36ac13cba8ccbf9ca91028bee3a59e4112"
}
```

### Sample 34: `6156800f481bd1a8`

| Field | Value |
|---|---|
| SHA-256 | `6156800f481bd1a8e729d7e6d5922cd517d047515467e3950a9c1aff527ba5fa` |
| Family label | `unknown` |
| File name | `Neworder_Product_List_Specifications_Request_for_Pricing.js` |
| File type | `js` |
| First seen | `2026-11-23 06:45:29` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89ab2611d3b60d5790028e7ae89e5fda` |
| SHA-1 | `9578507cdad5d66bf215bd07188d78435e4f8127` |
| SHA-256 | `6156800f481bd1a8e729d7e6d5922cd517d047515467e3950a9c1aff527ba5fa` |
| SHA3-384 | `ad4105baa1d554e3373831bbad750772f2cd464eb683469d30a309bdfd237999afa1fd7543cb094050f114af9f836338` |
| TLSH | `T11F435C7FF91A0BF74F467FC8BCF40961CA698214852601A0F199CF0D714399CE7BA1AA` |
| SSDEEP | `1536:61yztHd0BWaFj85/5wozi0G6nm21MmIkH:6MtHd0fFC/5BAImiCkH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_6156800f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6156800f481bd1a8e729d7e6d5922cd517d047515467e3950a9c1aff527ba5fa"
    family = "unknown"
    file_name = "Neworder_Product_List_Specifications_Request_for_Pricing.js"
    file_type = "js"
    first_seen = "2026-11-23 06:45:29"
  condition:
    hash.sha256(0, filesize) == "6156800f481bd1a8e729d7e6d5922cd517d047515467e3950a9c1aff527ba5fa"
}
```

### Sample 35: `b8ca5f05d259f13d`

| Field | Value |
|---|---|
| SHA-256 | `b8ca5f05d259f13d9e97d7ec6c6a2581643754659753950b3db245c35104a2ab` |
| Family label | `AgentTesla` |
| File name | `SHIPPING ADVICE.exe` |
| File type | `exe` |
| First seen | `2026-11-23 06:45:02` |
| Reporter | `lowmal3` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c6d103cbff38afea4a50901d2cc206d` |
| SHA-1 | `b1d4ea64cdca0f0ab4f0a8dc863414460b2e7e2c` |
| SHA-256 | `b8ca5f05d259f13d9e97d7ec6c6a2581643754659753950b3db245c35104a2ab` |
| SHA3-384 | `3319a42d87cda542700a5872a728e38135b519b91299c61d0d7705a09e51376d66c099269eea97d21c2fb8b44199036e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16305F06022B9CF02D8B65BF41872E37493F53E99A471CA0B5EE27CEB7936B501904B53` |
| SSDEEP | `24576:xbV/q7kdFzqwm5ejJO0IRAqG3R34j1s2la9OfDJPP:xn/SsCi3RIjgADl` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_035_b8ca5f05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8ca5f05d259f13d9e97d7ec6c6a2581643754659753950b3db245c35104a2ab"
    family = "AgentTesla"
    file_name = "SHIPPING ADVICE.exe"
    file_type = "exe"
    first_seen = "2026-11-23 06:45:02"
  condition:
    hash.sha256(0, filesize) == "b8ca5f05d259f13d9e97d7ec6c6a2581643754659753950b3db245c35104a2ab"
}
```

### Sample 36: `3b0ec2286f877f0f`

| Field | Value |
|---|---|
| SHA-256 | `3b0ec2286f877f0f92ceb2105f5189e472839731dbcd1a99fb1d947ed47d377d` |
| Family label | `unknown` |
| File name | `d57f98470f955162e7a6cbbb26e62bc2` |
| File type | `dll` |
| First seen | `2026-11-23 06:40:08` |
| Reporter | `malwareontap` |
| Tags | `dionaea, dll, honeypot, pe, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d57f98470f955162e7a6cbbb26e62bc2` |
| SHA-1 | `98b457a85688783de29d4f82890b729f8d35f0f1` |
| SHA-256 | `3b0ec2286f877f0f92ceb2105f5189e472839731dbcd1a99fb1d947ed47d377d` |
| SHA3-384 | `3a3f1a7f813c32f52345cc5b9313b0da619cf97266ae0e8052f1f295a4c22e361dcdfc2d14f0f893945dd240e83ea708` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T14C3623AA70BC80F8D2052974847B8E17B6B63C3A22FA690FEF4049662D53F56F750743` |
| SSDEEP | `49152:RnvMSPbcBVQej01INRx+TSqTdX1HkQo6SAARdhnv:1vPoBhI1aRxcSUDk36SAEdhv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_3b0ec228
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b0ec2286f877f0f92ceb2105f5189e472839731dbcd1a99fb1d947ed47d377d"
    family = "unknown"
    file_name = "d57f98470f955162e7a6cbbb26e62bc2"
    file_type = "dll"
    first_seen = "2026-11-23 06:40:08"
  condition:
    hash.sha256(0, filesize) == "3b0ec2286f877f0f92ceb2105f5189e472839731dbcd1a99fb1d947ed47d377d"
}
```

### Sample 37: `596f856a0c6f2e66`

| Field | Value |
|---|---|
| SHA-256 | `596f856a0c6f2e66c21c8c6cd5ea858cdc3fdf7c38f3a728897b9617af579196` |
| Family label | `EasyShell` |
| File name | `easyshell-l64-596f856a0c6f2e66.bin` |
| File type | `elf` |
| First seen | `2026-11-23 06:36:35` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53d0e3dc34e2fc83565843100395242c` |
| SHA-1 | `298191fa5563ae04f56ae18427f649f6c7257117` |
| SHA-256 | `596f856a0c6f2e66c21c8c6cd5ea858cdc3fdf7c38f3a728897b9617af579196` |
| SHA3-384 | `e62ff6172c8feb3c33786aef9102480e8fbeddfdf27c278be4c0feeb64c68491cb22a65a815edf55101d835126033c96` |
| TLSH | `T11F267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxiAH8hIU6iKHh:OYjiiKgib9qRGcEulAcW+gh` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_037_596f856a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "596f856a0c6f2e66c21c8c6cd5ea858cdc3fdf7c38f3a728897b9617af579196"
    family = "EasyShell"
    file_name = "easyshell-l64-596f856a0c6f2e66.bin"
    file_type = "elf"
    first_seen = "2026-11-23 06:36:35"
  condition:
    hash.sha256(0, filesize) == "596f856a0c6f2e66c21c8c6cd5ea858cdc3fdf7c38f3a728897b9617af579196"
}
```

### Sample 38: `133e9624f08ae2fc`

| Field | Value |
|---|---|
| SHA-256 | `133e9624f08ae2fc0b8532438fbe6e0b4552ae9e8956abfa925fb27da20d8b0c` |
| Family label | `EasyShell` |
| File name | `easyshell-l32-133e9624f08ae2fc.bin` |
| File type | `elf` |
| First seen | `2026-11-23 06:36:25` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `373e742c4b57c8d943b64810e0c5ab0d` |
| SHA-1 | `b501bd0f4ecb484a18c1d96a26531f43dadd458e` |
| SHA-256 | `133e9624f08ae2fc0b8532438fbe6e0b4552ae9e8956abfa925fb27da20d8b0c` |
| SHA3-384 | `d1cba2cb706f7c2258f46d66128f6bf7a8ed89482c272608dc49ef643cb8f1a47cf4f9ea72754e9d6336a0aad80b1741` |
| TLSH | `T14F068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1EF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1Edb` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_038_133e9624
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "133e9624f08ae2fc0b8532438fbe6e0b4552ae9e8956abfa925fb27da20d8b0c"
    family = "EasyShell"
    file_name = "easyshell-l32-133e9624f08ae2fc.bin"
    file_type = "elf"
    first_seen = "2026-11-23 06:36:25"
  condition:
    hash.sha256(0, filesize) == "133e9624f08ae2fc0b8532438fbe6e0b4552ae9e8956abfa925fb27da20d8b0c"
}
```

### Sample 39: `e924109a74b5f594`

| Field | Value |
|---|---|
| SHA-256 | `e924109a74b5f594e0f3a67abdfbb7d079ac9f430715c7a651462f09e7653cdd` |
| Family label | `EasyShell` |
| File name | `easyshell-l128-e924109a74b5f594.bin` |
| File type | `elf` |
| First seen | `2026-11-23 06:36:17` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c24f3254a27e45db098e15e63f37c235` |
| SHA-1 | `697a344572b77cd758965e97e20c218ed5df9dc3` |
| SHA-256 | `e924109a74b5f594e0f3a67abdfbb7d079ac9f430715c7a651462f09e7653cdd` |
| SHA3-384 | `14ac568b40f88056b9e4e42aee4a633ed0049bcb976bdd1b0e61cac6436ee602ffbc95ed55e899e0cff84001a90f8b01` |
| TLSH | `T1E1067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1Cy:FUkCxwUGnaPdX8PHAS` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_039_e924109a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e924109a74b5f594e0f3a67abdfbb7d079ac9f430715c7a651462f09e7653cdd"
    family = "EasyShell"
    file_name = "easyshell-l128-e924109a74b5f594.bin"
    file_type = "elf"
    first_seen = "2026-11-23 06:36:17"
  condition:
    hash.sha256(0, filesize) == "e924109a74b5f594e0f3a67abdfbb7d079ac9f430715c7a651462f09e7653cdd"
}
```

### Sample 40: `78bbcc31287f5cd1`

| Field | Value |
|---|---|
| SHA-256 | `78bbcc31287f5cd18450833f6b111cc02853b82ee90a2a43f2d60d92609a305d` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_arm64-78bbcc31287f5cd1.bin` |
| File type | `macho` |
| First seen | `2026-11-23 06:36:09` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b82abe3973640ac8e4fb93b21e4e789f` |
| SHA-1 | `f299ea0bf0d00b2bed2b4904ed0bfff1a4a30453` |
| SHA-256 | `78bbcc31287f5cd18450833f6b111cc02853b82ee90a2a43f2d60d92609a305d` |
| SHA3-384 | `a4ba1d47a077da4e55704cccacadc4f180eb7f3c16dc84442aeac574b3580d9d19dd93dc74f2f0f6f1733d810d4b58ae` |
| TLSH | `T1A4F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1Tggsj5g5FIU6icBV8GQU5NZm+lzx:8SeI1gkkvTggt5C+OGU5NZm+lzx` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_040_78bbcc31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78bbcc31287f5cd18450833f6b111cc02853b82ee90a2a43f2d60d92609a305d"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-78bbcc31287f5cd1.bin"
    file_type = "macho"
    first_seen = "2026-11-23 06:36:09"
  condition:
    hash.sha256(0, filesize) == "78bbcc31287f5cd18450833f6b111cc02853b82ee90a2a43f2d60d92609a305d"
}
```

### Sample 41: `7e6a0512790f203e`

| Field | Value |
|---|---|
| SHA-256 | `7e6a0512790f203eec0a00ca4fe24be9e5c76851cbe04a616e0f86cf5560ed47` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_amd64-7e6a0512790f203e.bin` |
| File type | `macho` |
| First seen | `2026-11-23 06:36:00` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9c1e47a38478b12d31b9eddebd75eb4` |
| SHA-1 | `09d4f2bcdb29bd19a325e397fd233798ea9f20d6` |
| SHA-256 | `7e6a0512790f203eec0a00ca4fe24be9e5c76851cbe04a616e0f86cf5560ed47` |
| SHA3-384 | `dafe436865164027866585ec449ae9595106092732720b8a61fb5b00561eb8bc64cdec2edaf33bd0bdb8de8a9cb95baf` |
| TLSH | `T113168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6HKhx+wgbZmBlztX:kyLbLNomEr6HKjp` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_041_7e6a0512
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e6a0512790f203eec0a00ca4fe24be9e5c76851cbe04a616e0f86cf5560ed47"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-7e6a0512790f203e.bin"
    file_type = "macho"
    first_seen = "2026-11-23 06:36:00"
  condition:
    hash.sha256(0, filesize) == "7e6a0512790f203eec0a00ca4fe24be9e5c76851cbe04a616e0f86cf5560ed47"
}
```

### Sample 42: `038c5519a79b5a92`

| Field | Value |
|---|---|
| SHA-256 | `038c5519a79b5a920b3bc4d435c455ff85e8c425fea83b82297c2d475f2a1adb` |
| Family label | `EasyShell` |
| File name | `easyshell-a64-038c5519a79b5a92.bin` |
| File type | `elf` |
| First seen | `2026-11-23 06:35:50` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f0333ac490fde4cb67d56f86abe1e77` |
| SHA-1 | `9519044a0b5d35a15f173ff6e88ee261405aa52d` |
| SHA-256 | `038c5519a79b5a920b3bc4d435c455ff85e8c425fea83b82297c2d475f2a1adb` |
| SHA3-384 | `0c5b21925c12671645795f6ad60a666090d01825a678040557a083faa990e77b581cf7a97bdd8b12c43c98d86b24cbc2` |
| TLSH | `T13C06B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WgGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WgLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_042_038c5519
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "038c5519a79b5a920b3bc4d435c455ff85e8c425fea83b82297c2d475f2a1adb"
    family = "EasyShell"
    file_name = "easyshell-a64-038c5519a79b5a92.bin"
    file_type = "elf"
    first_seen = "2026-11-23 06:35:50"
  condition:
    hash.sha256(0, filesize) == "038c5519a79b5a920b3bc4d435c455ff85e8c425fea83b82297c2d475f2a1adb"
}
```

### Sample 43: `4274df7e8bcc5fa5`

| Field | Value |
|---|---|
| SHA-256 | `4274df7e8bcc5fa5a75bf87c8fabcf4be139131c7791799a9e14b13616806a44` |
| Family label | `EasyShell` |
| File name | `easyshell-a32-4274df7e8bcc5fa5.bin` |
| File type | `elf` |
| First seen | `2026-11-23 06:35:40` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cf39c83ce537adec81e7a28dbdb4189` |
| SHA-1 | `ef311d92eb01e3b6f9d6b3582dcbd1561d43d5ad` |
| SHA-256 | `4274df7e8bcc5fa5a75bf87c8fabcf4be139131c7791799a9e14b13616806a44` |
| SHA3-384 | `447a7e59c788717a428760e3c57478eca44fcc73226d043173c90d4b8cb26e094af44ca89fddde8087af8c8951dc2859` |
| TLSH | `T1CBF53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBN:FhvZpiEGUx+pVdqk2laB` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_043_4274df7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4274df7e8bcc5fa5a75bf87c8fabcf4be139131c7791799a9e14b13616806a44"
    family = "EasyShell"
    file_name = "easyshell-a32-4274df7e8bcc5fa5.bin"
    file_type = "elf"
    first_seen = "2026-11-23 06:35:40"
  condition:
    hash.sha256(0, filesize) == "4274df7e8bcc5fa5a75bf87c8fabcf4be139131c7791799a9e14b13616806a44"
}
```

### Sample 44: `61b5e8b4baa85cfe`

| Field | Value |
|---|---|
| SHA-256 | `61b5e8b4baa85cfe656a9759df34135acbbbe9d9853a08f54b4b63dae7565458` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `sh` |
| First seen | `2026-11-23 06:29:40` |
| Reporter | `pickledrick` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d13fef8445e94c4bf33941d13850b31` |
| SHA-1 | `599b9492c0637d9ff9abf33465abdc65d33f6c57` |
| SHA-256 | `61b5e8b4baa85cfe656a9759df34135acbbbe9d9853a08f54b4b63dae7565458` |
| SHA3-384 | `5f78186be4d8170c449c4bf566cb8e23d457ad4e498a9ad1cfe9df10c39abf8506ca6de646254c39f70ab60ede03d18a` |
| TLSH | `T1B4263360BE223CF54B69C728B0AF7F1C0A710BA3D44CB5EA819566D7159EBC0D867C68` |
| SSDEEP | `49152:UDsBDiqNl4/EYImVOKIuZENJ16EdEonGbD5k69W81bClF1ms/:5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_61b5e8b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61b5e8b4baa85cfe656a9759df34135acbbbe9d9853a08f54b4b63dae7565458"
    family = "unknown"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-11-23 06:29:40"
  condition:
    hash.sha256(0, filesize) == "61b5e8b4baa85cfe656a9759df34135acbbbe9d9853a08f54b4b63dae7565458"
}
```

### Sample 45: `b2b386edce5af808`

| Field | Value |
|---|---|
| SHA-256 | `b2b386edce5af8084484858ac2310f214bf01e363714133ed0f9c322f2c727a1` |
| Family label | `unknown` |
| File name | `DaiichiLife.apk` |
| File type | `apk` |
| First seen | `2026-11-23 06:27:19` |
| Reporter | `masaomi346` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14066aec838dfac5fadb334d6d40f7f5` |
| SHA-1 | `22c984a79ddc93164fef1b18445ac22a9086ffe8` |
| SHA-256 | `b2b386edce5af8084484858ac2310f214bf01e363714133ed0f9c322f2c727a1` |
| SHA3-384 | `cfe7d04122ee7ec30c4ad6407da21b3a38a52c828146cd795589fd3930df892d8eceed4c009d7c87a29c4facf7a990e7` |
| TLSH | `T1BC572367FB88A87AF4F2833508315721D90B9C358B5392CB9914727C68B76D12F99ECC` |
| SSDEEP | `393216:uxkw5WcIRr1PdbzVd3HxvRQzbWwhOS7Ur67lFYwYmuf3LT0AILKolt:u95P8rbbz3+WwhP7Ld83UKof` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_b2b386ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2b386edce5af8084484858ac2310f214bf01e363714133ed0f9c322f2c727a1"
    family = "unknown"
    file_name = "DaiichiLife.apk"
    file_type = "apk"
    first_seen = "2026-11-23 06:27:19"
  condition:
    hash.sha256(0, filesize) == "b2b386edce5af8084484858ac2310f214bf01e363714133ed0f9c322f2c727a1"
}
```

### Sample 46: `f54c081f216590de`

| Field | Value |
|---|---|
| SHA-256 | `f54c081f216590deb7b964981d911f66e5bfdb603da976dfd125ceb677a65738` |
| Family label | `unknown` |
| File name | `nano.sh` |
| File type | `sh` |
| First seen | `2026-11-23 06:26:15` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e4ce5cba14bcb80f24eaee119486560` |
| SHA-1 | `f9865e34bf7567ee7a844bcda68a376d3f147b92` |
| SHA-256 | `f54c081f216590deb7b964981d911f66e5bfdb603da976dfd125ceb677a65738` |
| SHA3-384 | `8100e26a028d3746e0f61b863be0de6723e8084263d2e863a1cf18a163ba25bee7dd46f90f4eca0555661058dd77686d` |
| TLSH | `T12DC08C8F00713A2092028D08F3428BE4C0009CA224444822A41619B0058321C6472708` |
| SSDEEP | `3:TKH/P7ISdTsULU5UYdCORTJLezHXLISdqwBKTi9GNIKBofiaLKx:m73dRLjoTYDL3dqyIga3Bssx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_f54c081f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f54c081f216590deb7b964981d911f66e5bfdb603da976dfd125ceb677a65738"
    family = "unknown"
    file_name = "nano.sh"
    file_type = "sh"
    first_seen = "2026-11-23 06:26:15"
  condition:
    hash.sha256(0, filesize) == "f54c081f216590deb7b964981d911f66e5bfdb603da976dfd125ceb677a65738"
}
```

### Sample 47: `1d536954415b2bf1`

| Field | Value |
|---|---|
| SHA-256 | `1d536954415b2bf1dc25e03e8f73f94b58a8646d4e6d672b71880389843c5d4b` |
| Family label | `unknown` |
| File name | `1d536954415b2bf1dc25e03e8f73f94b58a8646d4e6d672b71880389843c5d4b.sh` |
| File type | `sh` |
| First seen | `2026-11-23 06:18:08` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c190de3411c7d341578495724c2ca5ff` |
| SHA-1 | `86fd53b7cec2d971ec6d76becb405fefb75cf470` |
| SHA-256 | `1d536954415b2bf1dc25e03e8f73f94b58a8646d4e6d672b71880389843c5d4b` |
| SHA3-384 | `0d9c8095fa2c2a7e3c581c0bc51e1ec24ef5597295ad6c6557aef0092909e60622efc723258c7cd357bd0d1d3394e5c7` |
| TLSH | `T1E65157F5B8328E7278CD587A736D9140B8C7C573406D7684D9C6BD32291DD4CA21AF32` |
| SSDEEP | `48:ZjDgLeBz1ihiSmOiSSiS46XtD4WEyB2gBAsDfK/UUUUUUd:pbzQUvlmAtD4fSesLOUUUUUUd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_1d536954
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d536954415b2bf1dc25e03e8f73f94b58a8646d4e6d672b71880389843c5d4b"
    family = "unknown"
    file_name = "1d536954415b2bf1dc25e03e8f73f94b58a8646d4e6d672b71880389843c5d4b.sh"
    file_type = "sh"
    first_seen = "2026-11-23 06:18:08"
  condition:
    hash.sha256(0, filesize) == "1d536954415b2bf1dc25e03e8f73f94b58a8646d4e6d672b71880389843c5d4b"
}
```

### Sample 48: `d0868826e42a8b12`

| Field | Value |
|---|---|
| SHA-256 | `d0868826e42a8b12a7dda66a13680161b79e518611258622c8dfa9d74558d381` |
| Family label | `Mirai` |
| File name | `jew.x86` |
| File type | `elf` |
| First seen | `2026-11-23 06:18:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d36b4e41545e75687d7ec71790465bd2` |
| SHA-1 | `60bc09b6c45c96c4adc192951b63fee981113d35` |
| SHA-256 | `d0868826e42a8b12a7dda66a13680161b79e518611258622c8dfa9d74558d381` |
| SHA3-384 | `0d8113b7f0cca6837132cbf1e598bcab136b390fd591555907a2fefe8475ddb004da58972e9788306778e334a971cb7b` |
| TLSH | `T1B7430882BA07CAF2C42345F006E3F63FCE31E93E6471558AEF996EB5DA275C26101359` |
| TELFHASH | `t14311b26b1dea28ecf7e65014475617110a7af03b15603aba47b2e80417e2bc1e1bac38` |
| SSDEEP | `768:ECCxt7Qqo0T/qQT1uJlis+b+3TDa7VWksMRqSnffxRdQ97yKW9IdC0GWE:h1qX/MGs+GvaFsGqSffrd8mKWWdC0tE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_d0868826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0868826e42a8b12a7dda66a13680161b79e518611258622c8dfa9d74558d381"
    family = "Mirai"
    file_name = "jew.x86"
    file_type = "elf"
    first_seen = "2026-11-23 06:18:05"
  condition:
    hash.sha256(0, filesize) == "d0868826e42a8b12a7dda66a13680161b79e518611258622c8dfa9d74558d381"
}
```

### Sample 49: `ae744069e73d8fa8`

| Field | Value |
|---|---|
| SHA-256 | `ae744069e73d8fa89e8e5414c85a8b0fd1dd6d648647eced09ddfa47188c7374` |
| Family label | `Mirai` |
| File name | `kaizen.x86` |
| File type | `elf` |
| First seen | `2026-11-23 06:13:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06e956daa591ed22783698f2baaf7765` |
| SHA-1 | `1a92988a8cd2fb5d3a876d505adc4570ee6bbbff` |
| SHA-256 | `ae744069e73d8fa89e8e5414c85a8b0fd1dd6d648647eced09ddfa47188c7374` |
| SHA3-384 | `c25ed59a97830f4885c07fff031cfc4e227861dd6e2cc6e26f1f0b7355e39b821d435329c74baef11d09474fe8aeb11d` |
| TLSH | `T1BC347ED6A683E0F2CC254AB4B06BE7366C35F877A00ACBC7E7606C71EC15511992B36D` |
| TELFHASH | `t16d4166b2296e5ddc73e09001829ebb94dd1bd167a41d39b716f378446273e03a338cba` |
| SSDEEP | `6144:QzXgjbDjMRiV7V5gA5NJrmR0vuVQ/pKPBsVq3oGYMNQ9mRQx84FzAFFqNaa:LgA5NJrmR0vuVQ/pKPBsVq3oGYMG9aQ9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_ae744069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae744069e73d8fa89e8e5414c85a8b0fd1dd6d648647eced09ddfa47188c7374"
    family = "Mirai"
    file_name = "kaizen.x86"
    file_type = "elf"
    first_seen = "2026-11-23 06:13:24"
  condition:
    hash.sha256(0, filesize) == "ae744069e73d8fa89e8e5414c85a8b0fd1dd6d648647eced09ddfa47188c7374"
}
```

### Sample 50: `032bbeaa3106eff8`

| Field | Value |
|---|---|
| SHA-256 | `032bbeaa3106eff8c14d11a3439ee8e58d7ff8a87019155065f190e71e5fa730` |
| Family label | `Mirai` |
| File name | `kaizen.sh4` |
| File type | `elf` |
| First seen | `2026-11-23 06:13:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cbe3f8b98540f8129c3eea21e0997da` |
| SHA-1 | `c759b025f7fbfd53a11d662e14c726b7ee5b5eca` |
| SHA-256 | `032bbeaa3106eff8c14d11a3439ee8e58d7ff8a87019155065f190e71e5fa730` |
| SHA3-384 | `454291f2dd6aa9a98bd077423d0b3465e244087235c9f89c61276c71c9ea0c2b4e81e97b70172be3d3d889dcc749525d` |
| TLSH | `T1F614AF719080E6F1C0B54A3671F1847E87629811E05B3E76BAAB8C279447D6CFCBD3B9` |
| SSDEEP | `3072:n9wgXn6PViu1N9luiv8Zockh9IqBw35iauPuF7SnA1BTnYvNngE:n9wC6Viu1N9Au8WpLzOiaGznAzTYvu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_032bbeaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "032bbeaa3106eff8c14d11a3439ee8e58d7ff8a87019155065f190e71e5fa730"
    family = "Mirai"
    file_name = "kaizen.sh4"
    file_type = "elf"
    first_seen = "2026-11-23 06:13:09"
  condition:
    hash.sha256(0, filesize) == "032bbeaa3106eff8c14d11a3439ee8e58d7ff8a87019155065f190e71e5fa730"
}
```

### Sample 51: `44ba2238310ceb94`

| Field | Value |
|---|---|
| SHA-256 | `44ba2238310ceb94198d0f086f9ed4edf727b680569b330b10344140e41d08f0` |
| Family label | `Mirai` |
| File name | `kaizen.x86` |
| File type | `elf` |
| First seen | `2026-11-23 06:13:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1dc2c2cf160f17ab762131b70485523` |
| SHA-1 | `3de00e7c5a54d8bbfa4bec1153af4727406cb7b1` |
| SHA-256 | `44ba2238310ceb94198d0f086f9ed4edf727b680569b330b10344140e41d08f0` |
| SHA3-384 | `837c4ccabe7cd5763fcb26c62b48f657225de4623f5a7c1e83712e284f45659dcaa1f0afafb7897229c65732c3d01916` |
| TLSH | `T1338302A4F3D91E1ECD065A31B2DE10528B159849EF0B6F608D7B9A329EF7A1100AC5FD` |
| SSDEEP | `1536:TwxiEOkoR2PrGlOGSdTYH6s2omr0QJIRGFyWBagBA83HFwjArKLrB:TwwEUR2DLxdTo12oOfJIRGFZXy83Hmjh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_44ba2238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44ba2238310ceb94198d0f086f9ed4edf727b680569b330b10344140e41d08f0"
    family = "Mirai"
    file_name = "kaizen.x86"
    file_type = "elf"
    first_seen = "2026-11-23 06:13:06"
  condition:
    hash.sha256(0, filesize) == "44ba2238310ceb94198d0f086f9ed4edf727b680569b330b10344140e41d08f0"
}
```

### Sample 52: `82b7ab720e0a7875`

| Field | Value |
|---|---|
| SHA-256 | `82b7ab720e0a787544b9d8a71ae71e73ddefbbab6b7aebcf9cdd085b4943b9f3` |
| Family label | `Mirai` |
| File name | `kaizen.ppc` |
| File type | `elf` |
| First seen | `2026-11-23 06:12:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b88d48b170e02a7a55c08e40ec322c95` |
| SHA-1 | `02c8f9dbeb2920549fef45e597283b18ba9d79ea` |
| SHA-256 | `82b7ab720e0a787544b9d8a71ae71e73ddefbbab6b7aebcf9cdd085b4943b9f3` |
| SHA3-384 | `74c678a1b3621d51ac5c61a3c6ac9401ede480fd05a8648f78e125269c36edf1a27c3fb19edc546381b33668682c9a6c` |
| TLSH | `T1A9246C167A258307E6734EB5303F27D083AED491F0F1AA887E4B5E154271D3639AAECD` |
| SSDEEP | `6144:rgVpLQUYJ5AsTFhv+xg3sHLXhwcwIX09wiRTKxRE:EVmU83+TbdUgXE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_82b7ab72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82b7ab720e0a787544b9d8a71ae71e73ddefbbab6b7aebcf9cdd085b4943b9f3"
    family = "Mirai"
    file_name = "kaizen.ppc"
    file_type = "elf"
    first_seen = "2026-11-23 06:12:07"
  condition:
    hash.sha256(0, filesize) == "82b7ab720e0a787544b9d8a71ae71e73ddefbbab6b7aebcf9cdd085b4943b9f3"
}
```

### Sample 53: `5f27bb695949987e`

| Field | Value |
|---|---|
| SHA-256 | `5f27bb695949987e1feff780c5cc002842342e128c2153fc19a10e56ab7b73e8` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-23 06:12:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e79600c9855dd073a2eec94250ee0d82` |
| SHA-1 | `6ed0ab41bee7d7c4f687dd5e7a7862fcd2674de8` |
| SHA-256 | `5f27bb695949987e1feff780c5cc002842342e128c2153fc19a10e56ab7b73e8` |
| SHA3-384 | `850ddc100330d32840554d40a962444fddef882cfdf5d2d011afbb5475963aa967805357ac6313913baad6a2b97f9ebc` |
| TLSH | `T15F556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS+:SDjxB4m5n8XlaPWi+d+a4TjxQP4I` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_053_5f27bb69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f27bb695949987e1feff780c5cc002842342e128c2153fc19a10e56ab7b73e8"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-23 06:12:05"
  condition:
    hash.sha256(0, filesize) == "5f27bb695949987e1feff780c5cc002842342e128c2153fc19a10e56ab7b73e8"
}
```

### Sample 54: `d7766716ce3e0b8f`

| Field | Value |
|---|---|
| SHA-256 | `d7766716ce3e0b8f2e4038bc7dc15cd5c3a51aa2a88ec7b937664c31e2c2adb2` |
| Family label | `WARDENStealer` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-23 06:11:17` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd084fbfc4a70923c0b272ed26305ed8` |
| SHA-1 | `cc2dd344bd1214315753fce253a49ed6851adf90` |
| SHA-256 | `d7766716ce3e0b8f2e4038bc7dc15cd5c3a51aa2a88ec7b937664c31e2c2adb2` |
| SHA3-384 | `6898163648d664adc9becae473f56be1269ec43c2ecd95d87a790572bd005093e905568a671b3af4b8c39ba7b4deac9c` |
| IMPHASH | `50edb634617d62ec9d88f672b50b7d50` |
| TLSH | `T1C4E41251F6A648FED02A90358A271A25A7B27C0547209AFB57D0A73E2F737D4873EF00` |
| SSDEEP | `12288:zw4DilBuS+LEPBA3mXM3DmX9RgXWGmvFxR9uUG0CZqjcrdARDmq:J2IEW38M3DmtRgXUvFf9uF0CZqjOu` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_054_d7766716
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7766716ce3e0b8f2e4038bc7dc15cd5c3a51aa2a88ec7b937664c31e2c2adb2"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-23 06:11:17"
  condition:
    hash.sha256(0, filesize) == "d7766716ce3e0b8f2e4038bc7dc15cd5c3a51aa2a88ec7b937664c31e2c2adb2"
}
```

### Sample 55: `61618c5d2b6383dc`

| Field | Value |
|---|---|
| SHA-256 | `61618c5d2b6383dc9154499d9c8582a20f29768656f75aac50bec31c7efe4209` |
| Family label | `WARDENStealer` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-23 06:10:48` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, stealer, upx, Warden, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f999f89c14a662940d02145fd2b64c8` |
| SHA-1 | `a8a3bfd252d00878d30631ef3bd79dd840c7aa59` |
| SHA-256 | `61618c5d2b6383dc9154499d9c8582a20f29768656f75aac50bec31c7efe4209` |
| SHA3-384 | `6e6150fd4661320af93a21b3e16bfb29703890a26c4f3023497e61309c5c23cd08f76c2fb73d14767786f7ac37cf54ac` |
| IMPHASH | `dceb1ad342b507f0446a9ebe5b19f296` |
| TLSH | `T18ED423884A1CD6D2ED263D35E699A830DFF7ACEC53357E8C1A2D175042C7258F46A60F` |
| SSDEEP | `12288:GSf21EI6rk5XWm5phoOjxdAms4I+G9fz0PypXNwHddzMzx:G021yk7phpWNM0oPyp2i` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_055_61618c5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61618c5d2b6383dc9154499d9c8582a20f29768656f75aac50bec31c7efe4209"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-23 06:10:48"
  condition:
    hash.sha256(0, filesize) == "61618c5d2b6383dc9154499d9c8582a20f29768656f75aac50bec31c7efe4209"
}
```

### Sample 56: `8ddf5b0c23e5dd2e`

| Field | Value |
|---|---|
| SHA-256 | `8ddf5b0c23e5dd2e2aafc37dd1dc1b501a620e0c30c8cce4f442518135998b97` |
| Family label | `WARDENStealer` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-23 06:10:21` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, HYPERFINEX, stealer, Warden, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c13b21a5b6c262c9a7c4d668bdfa932` |
| SHA-1 | `a600ecd9e335a58e2cebbf43a547212efa1fb4a3` |
| SHA-256 | `8ddf5b0c23e5dd2e2aafc37dd1dc1b501a620e0c30c8cce4f442518135998b97` |
| SHA3-384 | `e28c34f96f469cb6f8f31d57919ead2fedcfd7dc7fe2d16932de4f999611b3eb7fd522ad06cd5ba4da3a0e503a659560` |
| IMPHASH | `50edb634617d62ec9d88f672b50b7d50` |
| TLSH | `T116E40251F6AA58FED02A90358A271A25A7B17C0547209AFB57D0A73E2F737D4873EF00` |
| SSDEEP | `12288:Dw4DilBuS+HEPBA3mXM3DmX9RgXWGbvFxR9uUG0CZqjcrdARDmq:528EW38M3DmtRgXZvFf9uF0CZqjOu` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_056_8ddf5b0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ddf5b0c23e5dd2e2aafc37dd1dc1b501a620e0c30c8cce4f442518135998b97"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-23 06:10:21"
  condition:
    hash.sha256(0, filesize) == "8ddf5b0c23e5dd2e2aafc37dd1dc1b501a620e0c30c8cce4f442518135998b97"
}
```

### Sample 57: `f353cd7de97831ec`

| Field | Value |
|---|---|
| SHA-256 | `f353cd7de97831ec9577ae8270a9adab5a1d84061f7f476213322a6af2ab8e03` |
| Family label | `Mirai` |
| File name | `nabarm6` |
| File type | `elf` |
| First seen | `2026-11-23 06:10:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `183822287bb915e8eab88470ce3a8ac9` |
| SHA-1 | `d688c74083209a693299fa3ca63a7c079b862053` |
| SHA-256 | `f353cd7de97831ec9577ae8270a9adab5a1d84061f7f476213322a6af2ab8e03` |
| SHA3-384 | `6f6e0bec00b4daac4300e00b3b7b9da172d096f9f5a97c84982c913481ddc0c9e5ecc50baaacb8ac6d9543d55b7b096d` |
| TLSH | `T11CC31B9ABD819B51D5C2657AFE2F51CD331307BCE3EE32129E24AB2467878670E3A501` |
| TELFHASH | `t15c11c025ef60156c77e9c0ba80df711e4ada31ce31063c40572e625f911199df93c82b` |
| SSDEEP | `3072:AH051K6pvheGqXJSoU577IDSO3xiuwChY4a58Cv7iH46+BX7G2:AH051vpkzJ3U577BO3xwChVapeH4VXC2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_f353cd7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f353cd7de97831ec9577ae8270a9adab5a1d84061f7f476213322a6af2ab8e03"
    family = "Mirai"
    file_name = "nabarm6"
    file_type = "elf"
    first_seen = "2026-11-23 06:10:08"
  condition:
    hash.sha256(0, filesize) == "f353cd7de97831ec9577ae8270a9adab5a1d84061f7f476213322a6af2ab8e03"
}
```

### Sample 58: `3f86c7b63f7ad5ac`

| Field | Value |
|---|---|
| SHA-256 | `3f86c7b63f7ad5ace5e74fa5c5ad511372d88ac0e4d7d6758c6216aafbf46e6c` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-23 06:09:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bf34e72c5f01240b907e337e617fc11` |
| SHA-1 | `1d6079e679103d0ba797126822aabdf093072cc0` |
| SHA-256 | `3f86c7b63f7ad5ace5e74fa5c5ad511372d88ac0e4d7d6758c6216aafbf46e6c` |
| SHA3-384 | `c56d2a210981b5dacb8550fdffeb239286b7028d8934384fc8148aedb08c6ebec9ec3780b1994ff61e5ac731c71cbc18` |
| TLSH | `T1BB556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSr:SDjxB4m5n8XlaPWi+d+a4TjxQP4d` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_058_3f86c7b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f86c7b63f7ad5ace5e74fa5c5ad511372d88ac0e4d7d6758c6216aafbf46e6c"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-23 06:09:08"
  condition:
    hash.sha256(0, filesize) == "3f86c7b63f7ad5ace5e74fa5c5ad511372d88ac0e4d7d6758c6216aafbf46e6c"
}
```

### Sample 59: `fcd8384dabe51cd8`

| Field | Value |
|---|---|
| SHA-256 | `fcd8384dabe51cd85b8df552a97a77402c92c35fb5be42327023894ceef5f87e` |
| Family label | `Mirai` |
| File name | `nabppc` |
| File type | `elf` |
| First seen | `2026-11-23 06:09:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a24c7afc3e8baf46f77362590f241ba7` |
| SHA-1 | `ea274c38fecae09538526f68ee165963fc378ba8` |
| SHA-256 | `fcd8384dabe51cd85b8df552a97a77402c92c35fb5be42327023894ceef5f87e` |
| SHA3-384 | `c1992cfb7ce201abb9dd4bdf4da931c468a09d9472cf56b4746c3407600f86a84c554f6ee95cbbb278a3a2b4832fb8b4` |
| TLSH | `T138B37D41F7084953E2671CF02A3F3BE5D3EEDAD111B49A45750EAB4E82B2E32518ADCD` |
| SSDEEP | `3072:Cw9RUnRLLf6oUG9cUfwUR9SmoFcCg0G+c:Cw9ILjUG9FfwUR9Smoin7+c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_fcd8384d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcd8384dabe51cd85b8df552a97a77402c92c35fb5be42327023894ceef5f87e"
    family = "Mirai"
    file_name = "nabppc"
    file_type = "elf"
    first_seen = "2026-11-23 06:09:05"
  condition:
    hash.sha256(0, filesize) == "fcd8384dabe51cd85b8df552a97a77402c92c35fb5be42327023894ceef5f87e"
}
```

### Sample 60: `6b8bdb2c9c2be46c`

| Field | Value |
|---|---|
| SHA-256 | `6b8bdb2c9c2be46c79d6bbb1f1369acf24a685dedd06b1835179397e02dbe72e` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-23 06:08:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7202dc04241ecf747d6ebba40d271e39` |
| SHA-1 | `436ce8be959f6b9f00bd1fb7693890bd7e431e5e` |
| SHA-256 | `6b8bdb2c9c2be46c79d6bbb1f1369acf24a685dedd06b1835179397e02dbe72e` |
| SHA3-384 | `bb1e433e1fa9389bd81213e01ee1115d3bd5bf00b0b7fb16bf5c6e77a5496a247c0157a739cfa4573c817038d6aac971` |
| TLSH | `T1A4556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSz:SDjxB4m5n8XlaPWi+d+a4TjxQP4l` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_060_6b8bdb2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b8bdb2c9c2be46c79d6bbb1f1369acf24a685dedd06b1835179397e02dbe72e"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-23 06:08:06"
  condition:
    hash.sha256(0, filesize) == "6b8bdb2c9c2be46c79d6bbb1f1369acf24a685dedd06b1835179397e02dbe72e"
}
```

### Sample 61: `23c1f8ea43b5c7d6`

| Field | Value |
|---|---|
| SHA-256 | `23c1f8ea43b5c7d627971dd381436fcab6613ecb2c57c41cc545649d5494fe11` |
| Family label | `Mirai` |
| File name | `nklarm7` |
| File type | `elf` |
| First seen | `2026-11-23 06:07:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d1a456c5183453b8d99f42eb35ca905` |
| SHA-1 | `8bd29d0af2e11b9136049b3307920124ecfe4212` |
| SHA-256 | `23c1f8ea43b5c7d627971dd381436fcab6613ecb2c57c41cc545649d5494fe11` |
| SHA3-384 | `bfe0421753d139850a9dce2efa372d27528dcbfb8d98338584659232b9b73861f8e71bb707f6b41c21f15edcaba5f58e` |
| TLSH | `T1CCF31A89BC809F11D5D535BAFE1E518D33534BB8E3FA71039E149B29638AC2B0E3B645` |
| TELFHASH | `t111e02620a80c223876bbd06184ff6678951ea2d0671c3e55aaa8de982866cc1930b90e` |
| SSDEEP | `3072:VrRAqGVvuSB2sScYPnLwXy1q6eGn38VD1SDV6D2WkHV6Oxwawa+lv0I7PquFYjB0:o2oSd/Lwi1Mg8p1S66DV/wawa+lv0IbR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_23c1f8ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23c1f8ea43b5c7d627971dd381436fcab6613ecb2c57c41cc545649d5494fe11"
    family = "Mirai"
    file_name = "nklarm7"
    file_type = "elf"
    first_seen = "2026-11-23 06:07:07"
  condition:
    hash.sha256(0, filesize) == "23c1f8ea43b5c7d627971dd381436fcab6613ecb2c57c41cc545649d5494fe11"
}
```

### Sample 62: `1d48fe08ea5ba348`

| Field | Value |
|---|---|
| SHA-256 | `1d48fe08ea5ba348f168048d9585918ec4a47b80fa0366b0f3b2694d29dde964` |
| Family label | `Mirai` |
| File name | `nabm68k` |
| File type | `elf` |
| First seen | `2026-11-23 06:07:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1aeff4cdac8195fdfaf6d1577565c917` |
| SHA-1 | `f73b970e8941f77c27283dc7397027bc07039089` |
| SHA-256 | `1d48fe08ea5ba348f168048d9585918ec4a47b80fa0366b0f3b2694d29dde964` |
| SHA3-384 | `e996afb4e9669033bf5587005ed6b1856a28240f0efed06c5bc27c7e61c8c81e8f524d529c05d3115ae8ce95dd2f9e3d` |
| TLSH | `T1E1B34BD3F400DCBEF80BD73B88534B0AB671F7505A911B7AB217B467F976094582AE82` |
| SSDEEP | `3072:kAoVkITSnlGHHHHHHHHHRi8AheG+6QyNOpXtI8Id8QjZf4ShQ:kkIT2lpcyNEXWTd3f4ShQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_1d48fe08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d48fe08ea5ba348f168048d9585918ec4a47b80fa0366b0f3b2694d29dde964"
    family = "Mirai"
    file_name = "nabm68k"
    file_type = "elf"
    first_seen = "2026-11-23 06:07:05"
  condition:
    hash.sha256(0, filesize) == "1d48fe08ea5ba348f168048d9585918ec4a47b80fa0366b0f3b2694d29dde964"
}
```

### Sample 63: `3c2743136c545fad`

| Field | Value |
|---|---|
| SHA-256 | `3c2743136c545fad314f328a5f45cf0176e8a8e8042ec09a0f81e47271b3f5f7` |
| Family label | `Mirai` |
| File name | `nklarm` |
| File type | `elf` |
| First seen | `2026-11-23 06:05:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `325fc6b5f646ab923c9e74e48818562f` |
| SHA-1 | `d96693e5a6fb1d5b8597775e0343a5c05eb11ac3` |
| SHA-256 | `3c2743136c545fad314f328a5f45cf0176e8a8e8042ec09a0f81e47271b3f5f7` |
| SHA3-384 | `d5293239d0a801c9c331e46c3498e247877c45c4b35fdf4e4750f575f4210c17e2ba36cc0cea3e0c0ce087bbc257acf7` |
| TLSH | `T1B4D32985BC818A12C6E161B6FB2F92CD375203B8D3E67103DD19AF29774B8670E3B651` |
| TELFHASH | `t1a161654aaa8c399cb7d040e9c27b0129ede531b9671530449d1ce6af5f93dc3b036c27` |
| SSDEEP | `3072:eIbExJAnxisMG5AN/Ul84Vh1wJjYIcrX9yXFULvqNiG+:ZYMxiXqOUS4VhAlcrNyXFKCNF+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_3c274313
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c2743136c545fad314f328a5f45cf0176e8a8e8042ec09a0f81e47271b3f5f7"
    family = "Mirai"
    file_name = "nklarm"
    file_type = "elf"
    first_seen = "2026-11-23 06:05:08"
  condition:
    hash.sha256(0, filesize) == "3c2743136c545fad314f328a5f45cf0176e8a8e8042ec09a0f81e47271b3f5f7"
}
```

### Sample 64: `8ae6643547b0abea`

| Field | Value |
|---|---|
| SHA-256 | `8ae6643547b0abea7df801d29701707464226cfe6ed177315355b406604bcfa3` |
| Family label | `Mirai` |
| File name | `zerarm` |
| File type | `elf` |
| First seen | `2026-11-23 06:05:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbc1be03368989afa0f913e94faa7b49` |
| SHA-1 | `44878164fa2ca890bec75bd837f8221cdbe75239` |
| SHA-256 | `8ae6643547b0abea7df801d29701707464226cfe6ed177315355b406604bcfa3` |
| SHA3-384 | `1a57d6c58de30e1ff864daad288833969823835ae82393226c43fb4699c31e5b422e33a1a9b1f4f728b84aaa475c4819` |
| TLSH | `T175D32986BC818A12C5E161B6FB2F92CD371603B8D3E67103DD19AF29774B8670E3B651` |
| TELFHASH | `t17d613219aa4c3b5cbbe441d9c2bb5129eee431ad231634154e1ceb6f5e53dc27036c23` |
| SSDEEP | `3072:1unmG13oLRMLm1LPZtVWsPsjB/CMv9Oh4/FeClPGu:0TKuLUdtVW24/CMlOh4NNluu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_8ae66435
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ae6643547b0abea7df801d29701707464226cfe6ed177315355b406604bcfa3"
    family = "Mirai"
    file_name = "zerarm"
    file_type = "elf"
    first_seen = "2026-11-23 06:05:05"
  condition:
    hash.sha256(0, filesize) == "8ae6643547b0abea7df801d29701707464226cfe6ed177315355b406604bcfa3"
}
```

### Sample 65: `f2b94316e528c3c0`

| Field | Value |
|---|---|
| SHA-256 | `f2b94316e528c3c0c852710f1db84f9737bf00c346dcc0c7f23fb64d6b804163` |
| Family label | `Mirai` |
| File name | `kaizen.mips` |
| File type | `elf` |
| First seen | `2026-11-23 06:00:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcac97eaddf18d564165b275a73400f7` |
| SHA-1 | `08080834cd4161b33c39986949c6c6874f7276fd` |
| SHA-256 | `f2b94316e528c3c0c852710f1db84f9737bf00c346dcc0c7f23fb64d6b804163` |
| SHA3-384 | `dd35e801dfaf31eadec0961d8b52722cbe1e62c38e90848d1ce4d9997edc23a270ba02df7e5dfce1eba628e1e562eee2` |
| TLSH | `T1FB44081E3E30CF1DF7A5C63855A38931958823D732E5D488D1ACFA102EA1A4F785BF99` |
| TELFHASH | `t12e21951c0a7813f0e3755c5d4aedef36d6a770db2b272d374e11982aab6d9818e10d1c` |
| SSDEEP | `6144:vQo6y2qkSJkr53V7fisA6CwV1RomtfbVU7KQuRKQw7gU93GVMCRIzixoPTtkLaSQ:/6y+VfsK8ZtBxojLM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_f2b94316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b94316e528c3c0c852710f1db84f9737bf00c346dcc0c7f23fb64d6b804163"
    family = "Mirai"
    file_name = "kaizen.mips"
    file_type = "elf"
    first_seen = "2026-11-23 06:00:10"
  condition:
    hash.sha256(0, filesize) == "f2b94316e528c3c0c852710f1db84f9737bf00c346dcc0c7f23fb64d6b804163"
}
```

### Sample 66: `b810f6aa9e44eec4`

| Field | Value |
|---|---|
| SHA-256 | `b810f6aa9e44eec4cf0be0203eea115566c7af8a129aadbbb88d9eebcd376b13` |
| Family label | `Mirai` |
| File name | `nklarm6` |
| File type | `elf` |
| First seen | `2026-11-23 06:00:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e1450428aacde180ed2d208ec48cd6f` |
| SHA-1 | `98a79226754edbb4c92bdbe98b835d7b3a269c54` |
| SHA-256 | `b810f6aa9e44eec4cf0be0203eea115566c7af8a129aadbbb88d9eebcd376b13` |
| SHA3-384 | `0d2a944abd9fc6275ec256528ebd8d5e37fd5b424d1e70fe3c747edc3809ec27745109988c5fab5a536cde48828c2fe8` |
| TLSH | `T1F5E32CCABC818F11D5D125BAFE1E51CD33134BB8E3EE71139E149B29638A8670E3B651` |
| TELFHASH | `t109e0c0368a44040d7be8c1c1c0fa713af45d28c0321013c0aa3ce5fe7e92cc5028640b` |
| SSDEEP | `3072:tNRAk6F6WohmqsJ8Y+C+I0yMrqeGaNkTm7dF77kDBvPnrFNIoRZasBG0j/7aCXZw:H/Z2J9n+I9MbZkTUdF77IvfJNIojadAe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_b810f6aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b810f6aa9e44eec4cf0be0203eea115566c7af8a129aadbbb88d9eebcd376b13"
    family = "Mirai"
    file_name = "nklarm6"
    file_type = "elf"
    first_seen = "2026-11-23 06:00:07"
  condition:
    hash.sha256(0, filesize) == "b810f6aa9e44eec4cf0be0203eea115566c7af8a129aadbbb88d9eebcd376b13"
}
```

### Sample 67: `8263134fa2e45031`

| Field | Value |
|---|---|
| SHA-256 | `8263134fa2e45031dcd0b748531bb753213320ed92a70ef94a6c9647edc2aaba` |
| Family label | `Mirai` |
| File name | `kaizen.x86_64_srv` |
| File type | `elf` |
| First seen | `2026-11-23 05:58:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58c8d70b69977f7adc615cf2235abfad` |
| SHA-1 | `d3d15e786a976f6d026adcd8994f6f1dd727635b` |
| SHA-256 | `8263134fa2e45031dcd0b748531bb753213320ed92a70ef94a6c9647edc2aaba` |
| SHA3-384 | `fb2e85e74ae283695175c165fe548da8dd430fc79f7392182f75a916b2d2c6f88c36c194254e8eb3b8c32b047c9f07ce` |
| TLSH | `T14F258F46F1B370FCC027C030836FDA62A935F46551226E7B66C4EA352D66E701B29FA7` |
| TELFHASH | `t1eda157b00fd979f073d5d810b3a2e1b59a7668e561ed39b01a275e94afd0ec04c6381e` |
| SSDEEP | `24576:X45S1nbe+0n1OXJzRHINKrAEL/WzPTVlsE:QYJzRHIs8EL/WLTV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_8263134f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8263134fa2e45031dcd0b748531bb753213320ed92a70ef94a6c9647edc2aaba"
    family = "Mirai"
    file_name = "kaizen.x86_64_srv"
    file_type = "elf"
    first_seen = "2026-11-23 05:58:07"
  condition:
    hash.sha256(0, filesize) == "8263134fa2e45031dcd0b748531bb753213320ed92a70ef94a6c9647edc2aaba"
}
```

### Sample 68: `dd600dd0a1443e30`

| Field | Value |
|---|---|
| SHA-256 | `dd600dd0a1443e30a32faae094e600c408ff2340ab4690f663c2e23376584d3b` |
| Family label | `Mirai` |
| File name | `nabarm5` |
| File type | `elf` |
| First seen | `2026-11-23 05:58:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `751d70080eae5eafe69bf356398b393b` |
| SHA-1 | `9be3720095c813bc374cb3d5c8e48eb1516df69c` |
| SHA-256 | `dd600dd0a1443e30a32faae094e600c408ff2340ab4690f663c2e23376584d3b` |
| SHA3-384 | `bed380b62ead1b3a9917f66a13d45834d74abbcbb3385d759cbcd248fc735cf5a892f55ef5f7d79987d0473ba130cb66` |
| TLSH | `T199A32A95BD819A12CAC165BBFB6F92CD371703F8D2EA32039D149F64378B4660E3B941` |
| TELFHASH | `t1a801cbb2cba604ce37ca855591ce311a0eec72aa27083444d45dbf5e40034d0b02dc2f` |
| SSDEEP | `1536:ZXf89VvX8JexBUFZKQPQ8m7h4ItPFWzUsqnTzzRSmldvOPls1OMoNB1WAsE24ba0:tfAVujVPV8h5qmnP9ldvON/1904G0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_dd600dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd600dd0a1443e30a32faae094e600c408ff2340ab4690f663c2e23376584d3b"
    family = "Mirai"
    file_name = "nabarm5"
    file_type = "elf"
    first_seen = "2026-11-23 05:58:05"
  condition:
    hash.sha256(0, filesize) == "dd600dd0a1443e30a32faae094e600c408ff2340ab4690f663c2e23376584d3b"
}
```

### Sample 69: `c3630e79b3cc4aae`

| Field | Value |
|---|---|
| SHA-256 | `c3630e79b3cc4aae8a60396ff0b9549c2fe0546dd7f0c46ce6d424f734cf16ff` |
| Family label | `Mirai` |
| File name | `kaizen.arm7` |
| File type | `elf` |
| First seen | `2026-11-23 05:54:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d009512b980e8ebc3f94c7a5887a138f` |
| SHA-1 | `d071c57e4a660cffbdd7791e5c5cf622baa77d99` |
| SHA-256 | `c3630e79b3cc4aae8a60396ff0b9549c2fe0546dd7f0c46ce6d424f734cf16ff` |
| SHA3-384 | `1bd3a92b179a81656bcd853a4cc6bee4322501ec1f5fadc8fe6bc4cb0cbd6c2b99daae46c03d6837ac562e5373843bee` |
| TLSH | `T1F0343A557C91DA12C5E426F7FA2E018D3316A7B8E2EE7502CD244F3067CA86F0EBB551` |
| TELFHASH | `t19b518530ae1c69fcf2c1c0a08aaa2138e6f9355c631150618f4cfd6eae83ac17469c27` |
| SSDEEP | `6144:cSu3OsLVLolfOIb6hwXed03u1cB9qyPErHjvzak90XVpMlkgoBg7j:cSu3OzfOIb6hwXed03u1cB9qyPErHDz5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_c3630e79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3630e79b3cc4aae8a60396ff0b9549c2fe0546dd7f0c46ce6d424f734cf16ff"
    family = "Mirai"
    file_name = "kaizen.arm7"
    file_type = "elf"
    first_seen = "2026-11-23 05:54:08"
  condition:
    hash.sha256(0, filesize) == "c3630e79b3cc4aae8a60396ff0b9549c2fe0546dd7f0c46ce6d424f734cf16ff"
}
```

### Sample 70: `b9d873319ccee197`

| Field | Value |
|---|---|
| SHA-256 | `b9d873319ccee197d2a9c70183d081cb83504c02a0a6d2ae24e4288234e7e06c` |
| Family label | `Mirai` |
| File name | `nklx86` |
| File type | `elf` |
| First seen | `2026-11-23 05:54:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e9f4d4fdf2b11ad2e6572bec407603e` |
| SHA-1 | `becdee915543d99dabc5c9534e721ad15de5d48a` |
| SHA-256 | `b9d873319ccee197d2a9c70183d081cb83504c02a0a6d2ae24e4288234e7e06c` |
| SHA3-384 | `f847f0d700281e18bb54ae98737152a1fb1c738dff17da875eee576ecf9c762c94a803f6f698bed45463dd67cb540d1e` |
| TLSH | `T128C38DC1D643D4F2E9490470906BF33B6636DA7A4038FFE3F3649A3A9821B50944EB5E` |
| TELFHASH | `t19d4128bfbeb20dd867c19506c7ce2751de2ee1bb791427b909b618e4327264041bdc39` |
| SSDEEP | `3072:S35XrwTjoX0nGrW8xJmrgz+iWV3sDW/Z5YpG4H9XJuR:0BrwTjEVrZxJkgz+iWtAW8LdXJuR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_b9d87331
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9d873319ccee197d2a9c70183d081cb83504c02a0a6d2ae24e4288234e7e06c"
    family = "Mirai"
    file_name = "nklx86"
    file_type = "elf"
    first_seen = "2026-11-23 05:54:05"
  condition:
    hash.sha256(0, filesize) == "b9d873319ccee197d2a9c70183d081cb83504c02a0a6d2ae24e4288234e7e06c"
}
```

### Sample 71: `e0bec6c0e89fda7b`

| Field | Value |
|---|---|
| SHA-256 | `e0bec6c0e89fda7bdf623bcfe4c930fba7523958ecf3d4dc64b10f9175e5c95a` |
| Family label | `unknown` |
| File name | `apple.exe` |
| File type | `exe` |
| First seen | `2026-11-23 05:52:28` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b6efc289498d2354c2d55170d3bd9b6` |
| SHA-1 | `bf63d87543ad619f3172f6b490d4b359b2b74d8e` |
| SHA-256 | `e0bec6c0e89fda7bdf623bcfe4c930fba7523958ecf3d4dc64b10f9175e5c95a` |
| SHA3-384 | `20a8a323402ab328cf97ba2023964f694b109372824f3f6d1ce259a9bdcbfd6fc13e493221b2e78ae37da5a6b49d90ee` |
| IMPHASH | `58980702e8d96827eefca2e7b1b936bb` |
| TLSH | `T139050141F79543FDD02AC5388A461516EA727C024B21A6FF13A4577B1E32AEACF3EB10` |
| SSDEEP | `24576:5ItAHp+Q2u7EgZYR+tZMcEU97REKLhthei:1+Qd7ccEADL` |
| ICON-DHASH | `104c8e96968e4c10` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_e0bec6c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0bec6c0e89fda7bdf623bcfe4c930fba7523958ecf3d4dc64b10f9175e5c95a"
    family = "unknown"
    file_name = "apple.exe"
    file_type = "exe"
    first_seen = "2026-11-23 05:52:28"
  condition:
    hash.sha256(0, filesize) == "e0bec6c0e89fda7bdf623bcfe4c930fba7523958ecf3d4dc64b10f9175e5c95a"
}
```

### Sample 72: `c69018ff97094098`

| Field | Value |
|---|---|
| SHA-256 | `c69018ff9709409889b9c36184a4080e3eb6cced0d59abcda2a9710239a7965a` |
| Family label | `Mirai` |
| File name | `splspc` |
| File type | `elf` |
| First seen | `2026-11-23 05:52:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d76049b611e4b993e19dd6211745daed` |
| SHA-1 | `cb506c1f54e325735a11ffa0110c98d378720363` |
| SHA-256 | `c69018ff9709409889b9c36184a4080e3eb6cced0d59abcda2a9710239a7965a` |
| SHA3-384 | `1e64b29d3455e3488a720143e7a88328fe71326bc4a5b12c33d84de7d22ed4d9451064061f939278589181a67e26b671` |
| TLSH | `T153E37D22BD75182BC5C0753B61E74731F1B3139925BC9A1E7EA31D8CEF18710316BAAA` |
| SSDEEP | `3072:p3v79mayLU14v8J9NnGqzZq//e42GN+xL8utGkZ:p3v7QaE24vOHXzoZUxL8u4kZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_c69018ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c69018ff9709409889b9c36184a4080e3eb6cced0d59abcda2a9710239a7965a"
    family = "Mirai"
    file_name = "splspc"
    file_type = "elf"
    first_seen = "2026-11-23 05:52:08"
  condition:
    hash.sha256(0, filesize) == "c69018ff9709409889b9c36184a4080e3eb6cced0d59abcda2a9710239a7965a"
}
```

### Sample 73: `86da445addf19314`

| Field | Value |
|---|---|
| SHA-256 | `86da445addf19314441fdfc628552b5a8de684ed7945ed21caa7fe07b0badfbb` |
| Family label | `Mirai` |
| File name | `nklppc` |
| File type | `elf` |
| First seen | `2026-11-23 05:52:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9e1e13e10aa05b879bef46c46f1ad16` |
| SHA-1 | `19daef3e73e9277fb469324b1d26d29fdbb1e5e1` |
| SHA-256 | `86da445addf19314441fdfc628552b5a8de684ed7945ed21caa7fe07b0badfbb` |
| SHA3-384 | `1477c00aa735817e7aa98daf8f3c9ffafc6633d4f1da570e8fc2002d132a1f3ce1aa7c9552fdd774699738aee99de573` |
| TLSH | `T1DFD36B41B3694847F3A70DB0293F3BF593EED6A121E0A681691EEB4F8175E321146ECD` |
| SSDEEP | `3072:ND8QFfYON+ggGRhAYDLosx2AI7RwOTCw6GmHIX:rY0+ehQm2x7RwO2wdmoX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_86da445a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86da445addf19314441fdfc628552b5a8de684ed7945ed21caa7fe07b0badfbb"
    family = "Mirai"
    file_name = "nklppc"
    file_type = "elf"
    first_seen = "2026-11-23 05:52:05"
  condition:
    hash.sha256(0, filesize) == "86da445addf19314441fdfc628552b5a8de684ed7945ed21caa7fe07b0badfbb"
}
```

### Sample 74: `d1b7e1661e6db02b`

| Field | Value |
|---|---|
| SHA-256 | `d1b7e1661e6db02b11443b0093a3c41fcae239f36b241b3e7e777fa8b548ab56` |
| Family label | `Mirai` |
| File name | `zerarm5` |
| File type | `elf` |
| First seen | `2026-11-23 05:51:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6fde21a0f8042a478098af3a64dd12e` |
| SHA-1 | `cd509f112c486bcacf70f17cd4a845a2052a5a7c` |
| SHA-256 | `d1b7e1661e6db02b11443b0093a3c41fcae239f36b241b3e7e777fa8b548ab56` |
| SHA3-384 | `0a183d5bfa5a0a7705b11145b3ca5baf71f27f4f34b525d50645db571ddea9a9aa443662541ea9541e3d07e35b705e88` |
| TLSH | `T140D31A85BC81CA12C5E161B6FB2F92CD376643B8D3EA7103DD18AB29734B8570E3B651` |
| TELFHASH | `t14f610e05b55c2a9cb7c940e9c2af823be9e436d9272531198b5dab5f9b53cc37036823` |
| SSDEEP | `3072:QVC9cjoHAK8AzjDsdvVP/l6pV2tE9iEyvfURE9AGr:Qo9oGHzPQvVP8V2taiEy3cE9/r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_d1b7e166
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1b7e1661e6db02b11443b0093a3c41fcae239f36b241b3e7e777fa8b548ab56"
    family = "Mirai"
    file_name = "zerarm5"
    file_type = "elf"
    first_seen = "2026-11-23 05:51:05"
  condition:
    hash.sha256(0, filesize) == "d1b7e1661e6db02b11443b0093a3c41fcae239f36b241b3e7e777fa8b548ab56"
}
```

### Sample 75: `632ed85720a5c0ea`

| Field | Value |
|---|---|
| SHA-256 | `632ed85720a5c0ea5a8df4dafda58660fd23f22f13642a625c7d243b26ae5a86` |
| Family label | `Mirai` |
| File name | `kaizen.m68k` |
| File type | `elf` |
| First seen | `2026-11-23 05:50:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97f078d9902c305847c28c18ede75583` |
| SHA-1 | `a1c6080ff8ffc60b22148b30113910ddc2419c5a` |
| SHA-256 | `632ed85720a5c0ea5a8df4dafda58660fd23f22f13642a625c7d243b26ae5a86` |
| SHA3-384 | `612c28afe898e2dab68184708f234caab39bcc2937940483a041bba5ed6fc058391513bcb25e07c1e9fd150aa4b98d5c` |
| TLSH | `T156246DC9E4009F7DF4DBE9F591360A0A6511536290930F27F1A2FCA7BC711A66F07E86` |
| SSDEEP | `6144:+YPKouDxz35yqWco4eedboNLhtqHGWT65CIjaShcYkyA8uxDd:+0ud5yAajW+5SDd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_632ed857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "632ed85720a5c0ea5a8df4dafda58660fd23f22f13642a625c7d243b26ae5a86"
    family = "Mirai"
    file_name = "kaizen.m68k"
    file_type = "elf"
    first_seen = "2026-11-23 05:50:08"
  condition:
    hash.sha256(0, filesize) == "632ed85720a5c0ea5a8df4dafda58660fd23f22f13642a625c7d243b26ae5a86"
}
```

### Sample 76: `64cccb94d026b4d2`

| Field | Value |
|---|---|
| SHA-256 | `64cccb94d026b4d2e3a34ad83567216ee7206da1fb81e101aa6523fe02e0c5c1` |
| Family label | `Mirai` |
| File name | `nklarm5` |
| File type | `elf` |
| First seen | `2026-11-23 05:49:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `358143c6be078b7442bd6c25bf3f76e3` |
| SHA-1 | `133c1f477b876f77109d95875469f47cdfff30c7` |
| SHA-256 | `64cccb94d026b4d2e3a34ad83567216ee7206da1fb81e101aa6523fe02e0c5c1` |
| SHA3-384 | `b25859598dc8b0e6a263cf2ee2bfab023628de00dea966a56a3bf501e725c14e33b1925f01d2a1de63dafc6097b9b54d` |
| TLSH | `T1B2D32A85BC81CA12C5E161B6FB2F92CD376343B8D3EA7103DD19AB29634B8570E3B651` |
| TELFHASH | `t147614101a55c2aacbed940ecc1ae423beda536a9671230554b1de7af5f93cc23039c33` |
| SSDEEP | `3072:jmJRIZZo7QVCjTWHnVRplFpa3tE9aWNbIuVI/7GHV:CJqIuC/snVRy3taaWN8OI/C1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_64cccb94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64cccb94d026b4d2e3a34ad83567216ee7206da1fb81e101aa6523fe02e0c5c1"
    family = "Mirai"
    file_name = "nklarm5"
    file_type = "elf"
    first_seen = "2026-11-23 05:49:08"
  condition:
    hash.sha256(0, filesize) == "64cccb94d026b4d2e3a34ad83567216ee7206da1fb81e101aa6523fe02e0c5c1"
}
```

### Sample 77: `aeb2d193c4cbec1d`

| Field | Value |
|---|---|
| SHA-256 | `aeb2d193c4cbec1d4ad77952d208c7fe43cfa1296a7bd97a12c0985c81445bb7` |
| Family label | `Mirai` |
| File name | `nabmips` |
| File type | `elf` |
| First seen | `2026-11-23 05:49:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffef69f26197f5c8ff5e5d8d2b5ed98b` |
| SHA-1 | `e7599d5a03e62b25006ca3dc82ac1f1798ebf49e` |
| SHA-256 | `aeb2d193c4cbec1d4ad77952d208c7fe43cfa1296a7bd97a12c0985c81445bb7` |
| SHA3-384 | `c87d34c9d3a254691872602fc05585b7d22d57821e827499b30fafeaa48ceba99ea3a322cb2a480f3e104f2eab009fea` |
| TLSH | `T19AD3D60E7E718F6DF768C73147B79B30A75963D226E1C645E26CE5101E2034E682FBA8` |
| TELFHASH | `t13421fe484d7822e0a7711da91aeeef76e1a030df07262e378e24bc6d6d7d9825e00c1c` |
| SSDEEP | `1536:pyBjyBi2B7mq57BD0gBAhkoAzlTyl5jwGGMI/MHihiXiZwRRwmJPCxSWAt7aA/nX:Oq9lCAzlTylVI/vYyNmJP9F3mGjqGoM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_aeb2d193
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aeb2d193c4cbec1d4ad77952d208c7fe43cfa1296a7bd97a12c0985c81445bb7"
    family = "Mirai"
    file_name = "nabmips"
    file_type = "elf"
    first_seen = "2026-11-23 05:49:05"
  condition:
    hash.sha256(0, filesize) == "aeb2d193c4cbec1d4ad77952d208c7fe43cfa1296a7bd97a12c0985c81445bb7"
}
```

### Sample 78: `a6fef561622b93aa`

| Field | Value |
|---|---|
| SHA-256 | `a6fef561622b93aa142df123c7fbdddddb07bc3f66de364a8a89a8ed54ce9cff` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-11-23 05:46:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f861a394c1f2e1d2437d7ace4c8b225` |
| SHA-1 | `ec1e54d205d555aafcdc31cb5ffc356737f030ff` |
| SHA-256 | `a6fef561622b93aa142df123c7fbdddddb07bc3f66de364a8a89a8ed54ce9cff` |
| SHA3-384 | `2ea52ccae0a307e7f916358f1dc5e49d94ff32577efe71f70d8387c395178b794992ee5e5a370c27929c6a992e1b27e3` |
| TLSH | `T139044B0ABFA11FFBD46FCD3345EA0705258C195622A92F3A3674D81CB65B28F1AD3C64` |
| SSDEEP | `3072:9lgGOrm21SC9fI6Ut++ZA7CStzY5Q3lSGP/CrLaXjiGV:9lROrm21SCpI6UtLZGVpauFV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_a6fef561
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6fef561622b93aa142df123c7fbdddddb07bc3f66de364a8a89a8ed54ce9cff"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-23 05:46:06"
  condition:
    hash.sha256(0, filesize) == "a6fef561622b93aa142df123c7fbdddddb07bc3f66de364a8a89a8ed54ce9cff"
}
```

### Sample 79: `cea5a47828d5d384`

| Field | Value |
|---|---|
| SHA-256 | `cea5a47828d5d384465d3c69166da1908c0940ef0ca0821b6ea49169785e9d03` |
| Family label | `Mirai` |
| File name | `zermpsl` |
| File type | `elf` |
| First seen | `2026-11-23 05:44:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4abaf33b1ba6d2db23626bf757698d52` |
| SHA-1 | `5751c9173f4cd4634ccafccb06f65cc7e961cf25` |
| SHA-256 | `cea5a47828d5d384465d3c69166da1908c0940ef0ca0821b6ea49169785e9d03` |
| SHA3-384 | `7cb92ea768f3165a9330f4498966733a528935d05352651d957e287dcdf62d27958240a21b7b1fe3af4b951e3b4cf9d2` |
| TLSH | `T1E6F33A0AFFA11FFBD4AFCD3341AA4709249C595632A82B3635B4D81CF65A28F1AD3C54` |
| SSDEEP | `3072:dmA2ygnKmLfFGl80sUuyk0fEG9H4lW5HGcTzNULtG2:dmhygnKmLtGy0spy2w4imcGY2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_cea5a478
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cea5a47828d5d384465d3c69166da1908c0940ef0ca0821b6ea49169785e9d03"
    family = "Mirai"
    file_name = "zermpsl"
    file_type = "elf"
    first_seen = "2026-11-23 05:44:09"
  condition:
    hash.sha256(0, filesize) == "cea5a47828d5d384465d3c69166da1908c0940ef0ca0821b6ea49169785e9d03"
}
```

### Sample 80: `cf78cb089fcf06f8`

| Field | Value |
|---|---|
| SHA-256 | `cf78cb089fcf06f8ebb10e21ff797de6a39e0c619f7e95abff5a851a6d49eb4a` |
| Family label | `Mirai` |
| File name | `nabx86` |
| File type | `elf` |
| First seen | `2026-11-23 05:44:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e375c906b15bb6cb6de59b454d97ee7` |
| SHA-1 | `26801b3ed951f46f3547e24b3a1b521a3b65ba90` |
| SHA-256 | `cf78cb089fcf06f8ebb10e21ff797de6a39e0c619f7e95abff5a851a6d49eb4a` |
| SHA3-384 | `25df65b1cdd552e6305adfd8040b8a057bc7cf5fc8a81cf9f5d4cd56eabbf7ae9366cf13394c4fa05d95328191265c48` |
| TLSH | `T19C936BC9FA83D0F1E81605B110A7AB766B35E9395039FB42E760FE31EC12711A50AF9D` |
| TELFHASH | `t1ab410bf91e7d0ce477c09842e20a9f21bd5e977b145036a305b3593932afc059277c39` |
| SSDEEP | `1536:Xw5/MOsBmTg28Yj56O73sTEhiu22ggKsmii1E/6aTh6tECSGysQRO:XA+BmTgqj56O73+wx3K4i1E6aTZyyM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_cf78cb08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf78cb089fcf06f8ebb10e21ff797de6a39e0c619f7e95abff5a851a6d49eb4a"
    family = "Mirai"
    file_name = "nabx86"
    file_type = "elf"
    first_seen = "2026-11-23 05:44:06"
  condition:
    hash.sha256(0, filesize) == "cf78cb089fcf06f8ebb10e21ff797de6a39e0c619f7e95abff5a851a6d49eb4a"
}
```

### Sample 81: `a04ce98444aeb293`

| Field | Value |
|---|---|
| SHA-256 | `a04ce98444aeb2934c3cf1be7a9bc29fe716ced94376cfc515ea0f709e468cf5` |
| Family label | `Mirai` |
| File name | `nklsh4` |
| File type | `elf` |
| First seen | `2026-11-23 05:43:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `148eb40d5187eff2f799d56bf5179a29` |
| SHA-1 | `8e6b5d6b27b32fbe5e48f25a8ca76044f750f625` |
| SHA-256 | `a04ce98444aeb2934c3cf1be7a9bc29fe716ced94376cfc515ea0f709e468cf5` |
| SHA3-384 | `87e361679909e013204faa0ad884fafd571bed9dd6a2d160912502feed64150e3cf59811d07be8bc346a73c0d0c67616` |
| TLSH | `T13EC3BE12CCB85D98D16E7AB02075DEF94B23A08054571EF7799AC2265087ECCF19BBF8` |
| SSDEEP | `3072:S1wwaNXzx13Q2WveM91sHcLSi02yQf9TMkGd:mwwaNDToveM9aKqhwTMLd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_a04ce984
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a04ce98444aeb2934c3cf1be7a9bc29fe716ced94376cfc515ea0f709e468cf5"
    family = "Mirai"
    file_name = "nklsh4"
    file_type = "elf"
    first_seen = "2026-11-23 05:43:07"
  condition:
    hash.sha256(0, filesize) == "a04ce98444aeb2934c3cf1be7a9bc29fe716ced94376cfc515ea0f709e468cf5"
}
```

### Sample 82: `af551780cc6a4c7e`

| Field | Value |
|---|---|
| SHA-256 | `af551780cc6a4c7e074d4097b46b5f5a7c72693b6541ed5d56a9f043fb0503c6` |
| Family label | `Mirai` |
| File name | `zermips` |
| File type | `elf` |
| First seen | `2026-11-23 05:42:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83939528b0f7d42baa92c8ac6d22b2e9` |
| SHA-1 | `4fb3991f7d06919dea60c451b58a02c64031c437` |
| SHA-256 | `af551780cc6a4c7e074d4097b46b5f5a7c72693b6541ed5d56a9f043fb0503c6` |
| SHA3-384 | `9c0c7c2d4157922a6a0f945966bf7e58015de1948037bbee1ad5c0011763eaa86c2060e301a19accb3a887ce906f87e6` |
| TLSH | `T1CCF3D70F7E629F6DF36C82714BB78B25A75523D223E0C585D26CDA111E2038E586FFA4` |
| TELFHASH | `t14321811c493823f0a7711c995aedfb72e5a130df1a252e378d21a4ae9e6dd819d00c1c` |
| SSDEEP | `3072:shHvPBwjogL9Ui0Ed2lqhYxVDzP5IFGXpX:mPBuJZI+oRzBIQXpX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_af551780
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af551780cc6a4c7e074d4097b46b5f5a7c72693b6541ed5d56a9f043fb0503c6"
    family = "Mirai"
    file_name = "zermips"
    file_type = "elf"
    first_seen = "2026-11-23 05:42:08"
  condition:
    hash.sha256(0, filesize) == "af551780cc6a4c7e074d4097b46b5f5a7c72693b6541ed5d56a9f043fb0503c6"
}
```

### Sample 83: `d9b2780f87fb0cd8`

| Field | Value |
|---|---|
| SHA-256 | `d9b2780f87fb0cd87db6b80ea5dcde8367f3c27a7adfe527e6ae13e4e10df118` |
| Family label | `Mirai` |
| File name | `nklspc` |
| File type | `elf` |
| First seen | `2026-11-23 05:42:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `601bcefed9539788f9ed8832c76583f4` |
| SHA-1 | `31eb2dc2289424f849f4cebcf637735ba25e9645` |
| SHA-256 | `d9b2780f87fb0cd87db6b80ea5dcde8367f3c27a7adfe527e6ae13e4e10df118` |
| SHA3-384 | `8316e926e70e384b63b812f9acbb4c1383a5bf968bfa2ee0c30e35730715b8c9f727cf6ed09d6cb42fb19fda6df83e29` |
| TLSH | `T1DCD35C22BD791C2BC5D4753B51E34731F1B6139929BC8A1A7EA30D8CEF18710316BADA` |
| SSDEEP | `3072:yOSMwDUIB6taHhxhQ+pJIl6sw+1lezOs2xUGLgf:yOSMwgQ6ILTp4ZlexsrUf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_d9b2780f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9b2780f87fb0cd87db6b80ea5dcde8367f3c27a7adfe527e6ae13e4e10df118"
    family = "Mirai"
    file_name = "nklspc"
    file_type = "elf"
    first_seen = "2026-11-23 05:42:05"
  condition:
    hash.sha256(0, filesize) == "d9b2780f87fb0cd87db6b80ea5dcde8367f3c27a7adfe527e6ae13e4e10df118"
}
```

### Sample 84: `db5472efa9baffce`

| Field | Value |
|---|---|
| SHA-256 | `db5472efa9baffce26a43fe40129fa14b538a9e5cc4d8c49b88bd0c02cb2f32e` |
| Family label | `Mirai` |
| File name | `splmips` |
| File type | `elf` |
| First seen | `2026-11-23 05:40:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a8814cc6d899f581b877ffb07b24c09` |
| SHA-1 | `60d5b408799fbcbb653154ca4dad9a460857e989` |
| SHA-256 | `db5472efa9baffce26a43fe40129fa14b538a9e5cc4d8c49b88bd0c02cb2f32e` |
| SHA3-384 | `fb8104f597b9e041e4abcfbda36b65e0e610493f720de59f4ac5df4b7745e8f8551a010ace53bca2824b5618a454c009` |
| TLSH | `T11504F81F7E529F6DF36883344BB78B35A75923D227E18585D26CD9001E2038E686FFA4` |
| TELFHASH | `t112219f5c4d3423e0e7721ca96beeff72e4a030de0b211d278e65e8adae6d9415e00c1c` |
| SSDEEP | `1536:smd35yq7fLyf7aR6aRssR9l4gBgooxKPVHovf0vOQhCc3sNbI961gIRRTGAoNvKb:bdz7mfm4cRKf0mU3VsLkNvDnIDYdqGWB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_db5472ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db5472efa9baffce26a43fe40129fa14b538a9e5cc4d8c49b88bd0c02cb2f32e"
    family = "Mirai"
    file_name = "splmips"
    file_type = "elf"
    first_seen = "2026-11-23 05:40:08"
  condition:
    hash.sha256(0, filesize) == "db5472efa9baffce26a43fe40129fa14b538a9e5cc4d8c49b88bd0c02cb2f32e"
}
```

### Sample 85: `dd0a00bfd570e9cf`

| Field | Value |
|---|---|
| SHA-256 | `dd0a00bfd570e9cfa3d75e9870c678aaba35e1b875236219fc5211ca3cdd5fed` |
| Family label | `Mirai` |
| File name | `splm68k` |
| File type | `elf` |
| First seen | `2026-11-23 05:40:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f301127db746b0179d3f8a72d3183fa9` |
| SHA-1 | `169b2709e96ab7e57766f5972d61e50cdb6c2615` |
| SHA-256 | `dd0a00bfd570e9cfa3d75e9870c678aaba35e1b875236219fc5211ca3cdd5fed` |
| SHA3-384 | `d96a0c29bc451c71347be816b3b97f23d829568e36bc212ead948d07d043ff89bc06daa63a0cda7d46978bcaf3a9bb0b` |
| TLSH | `T116D35C96B400DD3FFC4FD67B80570B06B231A3B119521727721BF967EA3D1A52D2AE82` |
| SSDEEP | `3072:b2Y8y9epQjv/k3XSnlENboCyyyyyyyyylhjwT/I6bbCfyNXMNURhg8hoGlQCm+:LBepn3X2lENfzkyN8NUHgSlQCm+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_dd0a00bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd0a00bfd570e9cfa3d75e9870c678aaba35e1b875236219fc5211ca3cdd5fed"
    family = "Mirai"
    file_name = "splm68k"
    file_type = "elf"
    first_seen = "2026-11-23 05:40:05"
  condition:
    hash.sha256(0, filesize) == "dd0a00bfd570e9cfa3d75e9870c678aaba35e1b875236219fc5211ca3cdd5fed"
}
```

### Sample 86: `aca3615ab286ca8c`

| Field | Value |
|---|---|
| SHA-256 | `aca3615ab286ca8cd77c89cbe3aed00b7940a799cecd1165918924662c4e0a89` |
| Family label | `Mirai` |
| File name | `nklmpsl` |
| File type | `elf` |
| First seen | `2026-11-23 05:38:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `414e550832744bc7a7644bd140414f37` |
| SHA-1 | `79866d94d4166008f84511ce6da17cdf8e08d718` |
| SHA-256 | `aca3615ab286ca8cd77c89cbe3aed00b7940a799cecd1165918924662c4e0a89` |
| SHA3-384 | `27dca4b917ab2f08318f0088e0f95867a8919657638f2b45e34c570ac85fba7e1614ceb81fc42fbeb3f5992328208ab0` |
| TLSH | `T1B6F33A0ABFA11FFBD4AFCD3341AA1709249C595632B82F363574D81CF65A28B1AD3C64` |
| SSDEEP | `3072:gQAfS+yqx/cmvd3e/9nhKY4XIDE86mk4Iibg2ytGgs:gQcS+yqx/NvZeFhKiV65LikYg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_aca3615a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aca3615ab286ca8cd77c89cbe3aed00b7940a799cecd1165918924662c4e0a89"
    family = "Mirai"
    file_name = "nklmpsl"
    file_type = "elf"
    first_seen = "2026-11-23 05:38:09"
  condition:
    hash.sha256(0, filesize) == "aca3615ab286ca8cd77c89cbe3aed00b7940a799cecd1165918924662c4e0a89"
}
```

### Sample 87: `012751bfd413109a`

| Field | Value |
|---|---|
| SHA-256 | `012751bfd413109a99b2249a93f47caed9357821fd96f3faf4e16cab2f1bb7d2` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-23 05:38:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb92856f4e704eb44e3845dc7304887b` |
| SHA-1 | `56406f4ff41421170a321e4e1769a08f571164e1` |
| SHA-256 | `012751bfd413109a99b2249a93f47caed9357821fd96f3faf4e16cab2f1bb7d2` |
| SHA3-384 | `5b6f8c62a10511c294a8406c96406ff24febbf910573517c6697def1a8b337392b122fc8e24ddac637303c6a54c933fc` |
| TLSH | `T1C9556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSj:SDjxB4m5n8XlaPWi+d+a4TjxQP4p` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_087_012751bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "012751bfd413109a99b2249a93f47caed9357821fd96f3faf4e16cab2f1bb7d2"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-23 05:38:07"
  condition:
    hash.sha256(0, filesize) == "012751bfd413109a99b2249a93f47caed9357821fd96f3faf4e16cab2f1bb7d2"
}
```

### Sample 88: `85ab4afa171f93cf`

| Field | Value |
|---|---|
| SHA-256 | `85ab4afa171f93cf74dd412ab4cff3816df9a811b7eb7f773fbcf1ee00ff5fea` |
| Family label | `Mirai` |
| File name | `splarm7` |
| File type | `elf` |
| First seen | `2026-11-23 05:37:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd4d5e9592660dbf1fbb816c1af59d7d` |
| SHA-1 | `f6724ac23389577c1915297cb77913af36463863` |
| SHA-256 | `85ab4afa171f93cf74dd412ab4cff3816df9a811b7eb7f773fbcf1ee00ff5fea` |
| SHA3-384 | `5919a1c2dec6302d0033a590c255eef6bd47912c872a22fad85ee7c9e327499dceccdd619cc81192d8e54587cdaf6bc0` |
| TLSH | `T19DF31A8ABD808F11D5D535BAFE1E518D33134BB8E3FA71139E149B29638AC6B0E3B541` |
| TELFHASH | `t132e0c0205c184354b6fac4404cd2302a920d62c9e70425c4217cc47d1d304c06305d4a` |
| SSDEEP | `3072:CRAZEMMnnrCTuhYmb+Du/YZdmWeGjGn3slyDoCyoG5T2UYarKVYl+yM5jgHw2PaB:Sn2u6u+Du/Kdkxncl3Ce5dYarKVYl+yw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_85ab4afa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85ab4afa171f93cf74dd412ab4cff3816df9a811b7eb7f773fbcf1ee00ff5fea"
    family = "Mirai"
    file_name = "splarm7"
    file_type = "elf"
    first_seen = "2026-11-23 05:37:09"
  condition:
    hash.sha256(0, filesize) == "85ab4afa171f93cf74dd412ab4cff3816df9a811b7eb7f773fbcf1ee00ff5fea"
}
```

### Sample 89: `430a5bc591394803`

| Field | Value |
|---|---|
| SHA-256 | `430a5bc5913948037be4597d76d55770e961b721e7011219886e36cc4a995c86` |
| Family label | `Mirai` |
| File name | `splmpsl` |
| File type | `elf` |
| First seen | `2026-11-23 05:37:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04a228370524c7584d3c29e016e6600e` |
| SHA-1 | `63af9f2e306c595eb339f982455a1b7551067363` |
| SHA-256 | `430a5bc5913948037be4597d76d55770e961b721e7011219886e36cc4a995c86` |
| SHA3-384 | `8d7eb051cb9f7e3688faf38aeff2c16f8ed2489f81c1ffab790ef1365d2adf7497e4ec26988888c4326ce5c458973f12` |
| TLSH | `T19E044B0ABFA11FFBD46FCD3345EA0705258C195622A92F3A3674D81CB65B28F1AD3C64` |
| SSDEEP | `3072:9lgGOrm21SC9fI6Ut++ZA7CStzj5Q3lSGP/CrLaXjiGV:9lROrm21SCpI6UtLZ1VpauFV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_430a5bc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "430a5bc5913948037be4597d76d55770e961b721e7011219886e36cc4a995c86"
    family = "Mirai"
    file_name = "splmpsl"
    file_type = "elf"
    first_seen = "2026-11-23 05:37:07"
  condition:
    hash.sha256(0, filesize) == "430a5bc5913948037be4597d76d55770e961b721e7011219886e36cc4a995c86"
}
```

### Sample 90: `791b169be1f2e5da`

| Field | Value |
|---|---|
| SHA-256 | `791b169be1f2e5dadf8a2b5b0a86c973a1fa6318959ac9d3824c654411ee1adc` |
| Family label | `EasyShell` |
| File name | `easyshell-l64-791b169be1f2e5da.bin` |
| File type | `elf` |
| First seen | `2026-11-23 05:36:46` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a5a76b3e55630fd3f5a5e7bf44742b5` |
| SHA-1 | `eb1bc446df8702900c5f5c6e8627de5156c8df3f` |
| SHA-256 | `791b169be1f2e5dadf8a2b5b0a86c973a1fa6318959ac9d3824c654411ee1adc` |
| SHA3-384 | `e9a8f8b0f6e6c96c3c8f1eeaa471b5f364f6b6e7477be079de00c07ebe9a85d9e4028828f3922adb6f028da7968cfaff` |
| TLSH | `T1CA267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxiQH8hIU6iKHh:OYjiiKgib9qRGcEulQcW+gh` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_090_791b169b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "791b169be1f2e5dadf8a2b5b0a86c973a1fa6318959ac9d3824c654411ee1adc"
    family = "EasyShell"
    file_name = "easyshell-l64-791b169be1f2e5da.bin"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:46"
  condition:
    hash.sha256(0, filesize) == "791b169be1f2e5dadf8a2b5b0a86c973a1fa6318959ac9d3824c654411ee1adc"
}
```

### Sample 91: `248b0fd54187153e`

| Field | Value |
|---|---|
| SHA-256 | `248b0fd54187153e49814aed72b03e52e7378d3af69f2e4e4e99d4abd2ef1f55` |
| Family label | `EasyShell` |
| File name | `easyshell-l32-248b0fd54187153e.bin` |
| File type | `elf` |
| First seen | `2026-11-23 05:36:37` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `623ca4b3d2f4f6cd7a9d4ee8d2bbdd44` |
| SHA-1 | `8b2c18a97cce52c7f8483e1ea5f1d793a5a99e9c` |
| SHA-256 | `248b0fd54187153e49814aed72b03e52e7378d3af69f2e4e4e99d4abd2ef1f55` |
| SHA3-384 | `8656b3cd5e7ad8cf1f434afc0d71344c73f3469a735926895b9afce15a1a9eddea39d7fc0594e18b63fcd8db8f10fdd0` |
| TLSH | `T19C068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1ZF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1Zdb` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_091_248b0fd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "248b0fd54187153e49814aed72b03e52e7378d3af69f2e4e4e99d4abd2ef1f55"
    family = "EasyShell"
    file_name = "easyshell-l32-248b0fd54187153e.bin"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:37"
  condition:
    hash.sha256(0, filesize) == "248b0fd54187153e49814aed72b03e52e7378d3af69f2e4e4e99d4abd2ef1f55"
}
```

### Sample 92: `a2af915b17d29e75`

| Field | Value |
|---|---|
| SHA-256 | `a2af915b17d29e751c96b94a169350ab19bae3fa275150f9224aeb0350956f63` |
| Family label | `EasyShell` |
| File name | `easyshell-l128-a2af915b17d29e75.bin` |
| File type | `elf` |
| First seen | `2026-11-23 05:36:28` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `283afa4fd3b8a79bcea8b541249c93c9` |
| SHA-1 | `882854d1508bcb04f58695a98f9d3507bda36aad` |
| SHA-256 | `a2af915b17d29e751c96b94a169350ab19bae3fa275150f9224aeb0350956f63` |
| SHA3-384 | `8005e05212966a91ad20f3386f6256d9dd984811baa05c760ab58c05da4f9d66fc5bafb91f72d287b36a45840e86618e` |
| TLSH | `T19C067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1C0:FUkCxwUGnaPdX8P1AS` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_092_a2af915b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2af915b17d29e751c96b94a169350ab19bae3fa275150f9224aeb0350956f63"
    family = "EasyShell"
    file_name = "easyshell-l128-a2af915b17d29e75.bin"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:28"
  condition:
    hash.sha256(0, filesize) == "a2af915b17d29e751c96b94a169350ab19bae3fa275150f9224aeb0350956f63"
}
```

### Sample 93: `e41e8294cb2239cf`

| Field | Value |
|---|---|
| SHA-256 | `e41e8294cb2239cf221ce8d7834d88b534a80d59c3c03fbccfbc023aa637df3b` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_arm64-e41e8294cb2239cf.bin` |
| File type | `macho` |
| First seen | `2026-11-23 05:36:20` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61d3e82d59c4c9fef44c039e22e09e6b` |
| SHA-1 | `33c25e825072cc8ac5b9018410162a9e9c0b512e` |
| SHA-256 | `e41e8294cb2239cf221ce8d7834d88b534a80d59c3c03fbccfbc023aa637df3b` |
| SHA3-384 | `5b4a683a2dab8a5408a9230b9bba6e89358f82d0e4665a53af5ea2f3c8c5de15c0c5cc56e089e0d559216095ba47609e` |
| TLSH | `T1D8F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1Tgisj5g5FIU6icBV8GQU5NZm+lzd:8SeI1gkkvTgit5C+OGU5NZm+lzd` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_093_e41e8294
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e41e8294cb2239cf221ce8d7834d88b534a80d59c3c03fbccfbc023aa637df3b"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-e41e8294cb2239cf.bin"
    file_type = "macho"
    first_seen = "2026-11-23 05:36:20"
  condition:
    hash.sha256(0, filesize) == "e41e8294cb2239cf221ce8d7834d88b534a80d59c3c03fbccfbc023aa637df3b"
}
```

### Sample 94: `884053c7342bee4b`

| Field | Value |
|---|---|
| SHA-256 | `884053c7342bee4bd581acfc9affc17b7d296c47657138a2722f441b5984f233` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_amd64-884053c7342bee4b.bin` |
| File type | `macho` |
| First seen | `2026-11-23 05:36:11` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ce9a6edb193ddaab8a9bbca7d91c29a` |
| SHA-1 | `7138f433833ed0b4099380c3db27ac4b0e71d05c` |
| SHA-256 | `884053c7342bee4bd581acfc9affc17b7d296c47657138a2722f441b5984f233` |
| SHA3-384 | `803d0064877e53cf91886644f1f239172d609e07c33266ca5511008597049739bbde36ebbc4d9c0ddcc4abc00c96921e` |
| TLSH | `T1B7168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6IKhx+wgbZmBlzpX:kyLbLNomEr6IKjt` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_094_884053c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "884053c7342bee4bd581acfc9affc17b7d296c47657138a2722f441b5984f233"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-884053c7342bee4b.bin"
    file_type = "macho"
    first_seen = "2026-11-23 05:36:11"
  condition:
    hash.sha256(0, filesize) == "884053c7342bee4bd581acfc9affc17b7d296c47657138a2722f441b5984f233"
}
```

### Sample 95: `d2c59d92d30ca23b`

| Field | Value |
|---|---|
| SHA-256 | `d2c59d92d30ca23bd75790f217f922bd60da5755e69346224dc5076614de1f26` |
| Family label | `Mirai` |
| File name | `kaizen.arm6` |
| File type | `elf` |
| First seen | `2026-11-23 05:36:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e97fb61d1a7dc67100860bb37ae57784` |
| SHA-1 | `f50485d2373b97743006e7f296661516110ebab3` |
| SHA-256 | `d2c59d92d30ca23bd75790f217f922bd60da5755e69346224dc5076614de1f26` |
| SHA3-384 | `76a33b7182bc892192dd50c0414c576b3206ac6590d9637d3f0f3c1d67f23dc425b3e6688943435721b3d64c825bcf9a` |
| TLSH | `T135343A997C91DA12C6E416B7FA2E018E331663B8E1DF7552CE244F3467CA82F0EBB451` |
| TELFHASH | `t1da7166106e5da1ecf2d3c4e486bbe835a2f9316faf4221218694be3e5e43dc1b421c17` |
| SSDEEP | `6144:IsAzXMT1mmebfOIb6hwXed03u1cB9qkXfp7LcauSQRIcG:IsAzXMyfOIb6hwXed03u1cB9qkXfp7oG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_d2c59d92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2c59d92d30ca23bd75790f217f922bd60da5755e69346224dc5076614de1f26"
    family = "Mirai"
    file_name = "kaizen.arm6"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:07"
  condition:
    hash.sha256(0, filesize) == "d2c59d92d30ca23bd75790f217f922bd60da5755e69346224dc5076614de1f26"
}
```

### Sample 96: `11bc3d5be7e2ed58`

| Field | Value |
|---|---|
| SHA-256 | `11bc3d5be7e2ed5808be472f3e1394b9e39d2d04d5bd87d4353a77a4d5d4d48e` |
| Family label | `Mirai` |
| File name | `kaizen.arm5` |
| File type | `elf` |
| First seen | `2026-11-23 05:36:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Hajime, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af8d0923cc0fccaac77b5c35acf53f4a` |
| SHA-1 | `b58444cbd266dc3c19f25a1deaeccdf7c77da579` |
| SHA-256 | `11bc3d5be7e2ed5808be472f3e1394b9e39d2d04d5bd87d4353a77a4d5d4d48e` |
| SHA3-384 | `55a32472575ce96235ba49b853309f817606b3709c8e241896b5e45bbd8bf973a492c278d2a990645ef9ae8bf847130f` |
| TLSH | `T13D243B9A7CA2DA22C6E417B6FA2E018C331693E8D1DF7106CD341F3567CA92E1E7B541` |
| TELFHASH | `t12be026a0504c8cdce119a398a0bf2727493e10ec7b121f9193ea089f0c33a84a0b1f8f` |
| SSDEEP | `3072:OsN2WB61M4pJtQ1vlUrQw8EWSRMK9BBIPhbRefCmvccgpltnd:z2RMiJXWSRMK9Xamvccklf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_11bc3d5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11bc3d5be7e2ed5808be472f3e1394b9e39d2d04d5bd87d4353a77a4d5d4d48e"
    family = "Mirai"
    file_name = "kaizen.arm5"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:05"
  condition:
    hash.sha256(0, filesize) == "11bc3d5be7e2ed5808be472f3e1394b9e39d2d04d5bd87d4353a77a4d5d4d48e"
}
```

### Sample 97: `dd66ee61c603e850`

| Field | Value |
|---|---|
| SHA-256 | `dd66ee61c603e8500b9dd94f6ea05e9a9cc92c5f19f12775ff0449d4d38fa267` |
| Family label | `EasyShell` |
| File name | `easyshell-a64-dd66ee61c603e850.bin` |
| File type | `elf` |
| First seen | `2026-11-23 05:36:02` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90922dc7bd43170276ccb10fda73430a` |
| SHA-1 | `3fe83510940bceea258ba3eaeb580c15c1c1da30` |
| SHA-256 | `dd66ee61c603e8500b9dd94f6ea05e9a9cc92c5f19f12775ff0449d4d38fa267` |
| SHA3-384 | `d9a4e3f505122f1693482293cbdc4639ad2452f51c56215ef902d3441d2a66ce66af1a1ff6c1cd70ebebf5ba16092f05` |
| TLSH | `T11506B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WpGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WpLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_097_dd66ee61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd66ee61c603e8500b9dd94f6ea05e9a9cc92c5f19f12775ff0449d4d38fa267"
    family = "EasyShell"
    file_name = "easyshell-a64-dd66ee61c603e850.bin"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:02"
  condition:
    hash.sha256(0, filesize) == "dd66ee61c603e8500b9dd94f6ea05e9a9cc92c5f19f12775ff0449d4d38fa267"
}
```

### Sample 98: `b457bcec64d9ce0a`

| Field | Value |
|---|---|
| SHA-256 | `b457bcec64d9ce0a66c5fe2bd4e09a7109a0e01eccd37bc91b3c4b9da5fd78da` |
| Family label | `EasyShell` |
| File name | `easyshell-a32-b457bcec64d9ce0a.bin` |
| File type | `elf` |
| First seen | `2026-11-23 05:35:54` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe5911aae6411549c34447be1758802a` |
| SHA-1 | `a2dd610106b58a3d1369afd497b4f6aaeffd7173` |
| SHA-256 | `b457bcec64d9ce0a66c5fe2bd4e09a7109a0e01eccd37bc91b3c4b9da5fd78da` |
| SHA3-384 | `d8b2153143fbb55a9aac0506a39796d89c82f625c1536eaee7e5f67065725b8859131dc4e63635f4978dd71a1a430b44` |
| TLSH | `T1E8F53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBj:FhvZpiEGUx+pVdqi2laB` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_098_b457bcec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b457bcec64d9ce0a66c5fe2bd4e09a7109a0e01eccd37bc91b3c4b9da5fd78da"
    family = "EasyShell"
    file_name = "easyshell-a32-b457bcec64d9ce0a.bin"
    file_type = "elf"
    first_seen = "2026-11-23 05:35:54"
  condition:
    hash.sha256(0, filesize) == "b457bcec64d9ce0a66c5fe2bd4e09a7109a0e01eccd37bc91b3c4b9da5fd78da"
}
```

### Sample 99: `a20e90c799880831`

| Field | Value |
|---|---|
| SHA-256 | `a20e90c799880831329ef1910938888e3f87b1601e32d11f323af841b4a26acd` |
| Family label | `Mirai` |
| File name | `jklmips` |
| File type | `elf` |
| First seen | `2026-11-23 05:35:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77f3057810f48ddf22532b84b376294d` |
| SHA-1 | `3e1073badacbb6773b8be0a60580a0397d151aa8` |
| SHA-256 | `a20e90c799880831329ef1910938888e3f87b1601e32d11f323af841b4a26acd` |
| SHA3-384 | `90c446748f53dd36d7c029b7d0293fc4ca865e9b3d1936b872e42dfc58aa80630bd681e6979ea372a54ce7bd15615727` |
| TLSH | `T1DA04F81F7E529F6DF36883344BB78B35A75923D227E18585D26CD9001E2038E686FFA4` |
| TELFHASH | `t112219f5c4d3423e0e7721ca96beeff72e4a030de0b211d278e65e8adae6d9415e00c1c` |
| SSDEEP | `1536:smd35yq7fLyf7aR6aRssR9l4gBgooxKPVHovf0vOQhCL3sNbI961gIRRTGAoNvKC:bdz7mfm4cRKf0mz3VsLkNvDnIDYdqGWU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_a20e90c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a20e90c799880831329ef1910938888e3f87b1601e32d11f323af841b4a26acd"
    family = "Mirai"
    file_name = "jklmips"
    file_type = "elf"
    first_seen = "2026-11-23 05:35:05"
  condition:
    hash.sha256(0, filesize) == "a20e90c799880831329ef1910938888e3f87b1601e32d11f323af841b4a26acd"
}
```

### Sample 100: `1dc5f37bf10c9e5b`

| Field | Value |
|---|---|
| SHA-256 | `1dc5f37bf10c9e5bfae055c336fe687faeb946901b4afa0f7167cfcad8e9c31f` |
| Family label | `Mirai` |
| File name | `jklm68k` |
| File type | `elf` |
| First seen | `2026-11-23 05:33:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bee3eea01136da9de50690787c3a98b9` |
| SHA-1 | `14fdee7304f44822ab10dd949ad73eebebf989d0` |
| SHA-256 | `1dc5f37bf10c9e5bfae055c336fe687faeb946901b4afa0f7167cfcad8e9c31f` |
| SHA3-384 | `afe1627523b3690c6b5c779f4ad090b2f20fd04cd7677746e9aa803f69489b93fb244f2b40a28e75c0f9a4d340d79eab` |
| TLSH | `T1DFD35C96B400DD3FFC4FD67B80570B06B231A3B019521727721BF967EA7D1A52D2AE82` |
| SSDEEP | `3072:b2Y8y9epQjv/k3XSnlENbodyyyyyyyyylhawT/I6bbCfyNXMNURhg8hoGlQCmj:LBepn3X2lENtzkyN8NUHgSlQCmj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_1dc5f37b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dc5f37bf10c9e5bfae055c336fe687faeb946901b4afa0f7167cfcad8e9c31f"
    family = "Mirai"
    file_name = "jklm68k"
    file_type = "elf"
    first_seen = "2026-11-23 05:33:08"
  condition:
    hash.sha256(0, filesize) == "1dc5f37bf10c9e5bfae055c336fe687faeb946901b4afa0f7167cfcad8e9c31f"
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
 * Generated: 2026-11-23T07:51:44.666274+00:00
 */

rule MalwareBazaar_unknown_001_a777021b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a777021b7738db64481bbcc158bf527ebcf56d38cd17c415680f819409d48da9"
    family = "unknown"
    file_name = "TeklifFormu_23898.wsf"
    file_type = "wsf"
    first_seen = "2026-11-23 07:48:53"
  condition:
    hash.sha256(0, filesize) == "a777021b7738db64481bbcc158bf527ebcf56d38cd17c415680f819409d48da9"
}

rule MalwareBazaar_unknown_002_982d91ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "982d91ce5e89a7e8b4b2444608d99dd2c260e837bf57f61e69cf3c0271d9a326"
    family = "unknown"
    file_name = "6000245011_ONE TIME VENDOR RFQ ONLY.js"
    file_type = "js"
    first_seen = "2026-11-23 07:48:33"
  condition:
    hash.sha256(0, filesize) == "982d91ce5e89a7e8b4b2444608d99dd2c260e837bf57f61e69cf3c0271d9a326"
}

rule MalwareBazaar_unknown_003_e3f7ea3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3f7ea3d69f0f40ce291f760ab5f0c30be31dfa3f7906d5656778fbe1f1e616b"
    family = "unknown"
    file_name = "1.  Instruction to Bidders.wsf"
    file_type = "wsf"
    first_seen = "2026-11-23 07:48:25"
  condition:
    hash.sha256(0, filesize) == "e3f7ea3d69f0f40ce291f760ab5f0c30be31dfa3f7906d5656778fbe1f1e616b"
}

rule MalwareBazaar_unknown_004_a13033b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a13033b9999cb57f45b08a66f5aaa7ab722c5152f6329e0b9f69a7a9d9675c91"
    family = "unknown"
    file_name = "Disbursement.xls"
    file_type = "xls"
    first_seen = "2026-11-23 07:48:05"
  condition:
    hash.sha256(0, filesize) == "a13033b9999cb57f45b08a66f5aaa7ab722c5152f6329e0b9f69a7a9d9675c91"
}

rule MalwareBazaar_unknown_005_f439661f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f439661f7db6f089e46c4567728cb06ad4802f128bbcb769acedd0c46b8cab84"
    family = "unknown"
    file_name = "6000190834.cmd"
    file_type = "cmd"
    first_seen = "2026-11-23 07:47:21"
  condition:
    hash.sha256(0, filesize) == "f439661f7db6f089e46c4567728cb06ad4802f128bbcb769acedd0c46b8cab84"
}

rule MalwareBazaar_unknown_006_a85c2208
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a85c22086899c4053e831c5ebbe659b05fcdba98e3118667e3a8567e8ea34dab"
    family = "unknown"
    file_name = "SecuriteInfo.com.Exploit.CVE-2017-0199.04.Gen.26425832"
    file_type = "xlsx"
    first_seen = "2026-11-23 07:45:25"
  condition:
    hash.sha256(0, filesize) == "a85c22086899c4053e831c5ebbe659b05fcdba98e3118667e3a8567e8ea34dab"
}

rule MalwareBazaar_EasyShell_007_ac6c4b59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac6c4b597101ee0621921621c2f687595d24a8829176a2cbd0f1a0fc8cefde4b"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-ac6c4b597101ee06.bin"
    file_type = "macho"
    first_seen = "2026-11-23 07:37:28"
  condition:
    hash.sha256(0, filesize) == "ac6c4b597101ee0621921621c2f687595d24a8829176a2cbd0f1a0fc8cefde4b"
}

rule MalwareBazaar_EasyShell_008_acd9f7e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acd9f7e4079b5d0e6682b607f780795b11e5be20fe11283e5c1705a36fbfc1c5"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-acd9f7e4079b5d0e.bin"
    file_type = "macho"
    first_seen = "2026-11-23 07:37:17"
  condition:
    hash.sha256(0, filesize) == "acd9f7e4079b5d0e6682b607f780795b11e5be20fe11283e5c1705a36fbfc1c5"
}

rule MalwareBazaar_EasyShell_009_2c5acece
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c5acecebf16c6f00435c6bbd08afcc04936c5cd6291a8ed2987c5e05e667409"
    family = "EasyShell"
    file_name = "easyshell-a64-2c5acecebf16c6f0.bin"
    file_type = "elf"
    first_seen = "2026-11-23 07:37:09"
  condition:
    hash.sha256(0, filesize) == "2c5acecebf16c6f00435c6bbd08afcc04936c5cd6291a8ed2987c5e05e667409"
}

rule MalwareBazaar_EasyShell_010_3716548d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3716548d748d8bb486ec339fa4d9d54076264a6bbe9b88fc7b548296c5c10a99"
    family = "EasyShell"
    file_name = "easyshell-a32-3716548d748d8bb4.bin"
    file_type = "elf"
    first_seen = "2026-11-23 07:37:01"
  condition:
    hash.sha256(0, filesize) == "3716548d748d8bb486ec339fa4d9d54076264a6bbe9b88fc7b548296c5c10a99"
}

rule MalwareBazaar_unknown_011_30eed7cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc"
    family = "unknown"
    file_name = "COMMERCIAL INVOICE AND PACKING LIST.exe"
    file_type = "exe"
    first_seen = "2026-11-23 07:32:35"
  condition:
    hash.sha256(0, filesize) == "30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc"
}

rule MalwareBazaar_Mirai_012_13663488
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13663488e8447854d98e1526b7d640cbe340266b4b2480538408555bdfb24d0e"
    family = "Mirai"
    file_name = "s"
    file_type = "sh"
    first_seen = "2026-11-23 07:23:21"
  condition:
    hash.sha256(0, filesize) == "13663488e8447854d98e1526b7d640cbe340266b4b2480538408555bdfb24d0e"
}

rule MalwareBazaar_unknown_013_ab5ea665
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab5ea6651fa00f33f10de1069c377904acf6d99cc0fabe349b31eeba491f836b"
    family = "unknown"
    file_name = "8844"
    file_type = "elf"
    first_seen = "2026-11-23 07:22:33"
  condition:
    hash.sha256(0, filesize) == "ab5ea6651fa00f33f10de1069c377904acf6d99cc0fabe349b31eeba491f836b"
}

rule MalwareBazaar_a310Logger_014_bc0b1e17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc0b1e172b1505ee2a202a3a61f7133631523c936b37ef645612ca51ed4e87d0"
    family = "a310Logger"
    file_name = "Payment_Advice_and_Surrender_BL_Request_SITRGCEG251528.msi"
    file_type = "msi"
    first_seen = "2026-11-23 07:06:35"
  condition:
    hash.sha256(0, filesize) == "bc0b1e172b1505ee2a202a3a61f7133631523c936b37ef645612ca51ed4e87d0"
}

rule MalwareBazaar_EasyShell_015_07c2c1fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07c2c1fd1700e569d04e6e2fbea1bed75422caec72344ed3eebc2f012bbb089e"
    family = "EasyShell"
    file_name = "easyshell-l64-07c2c1fd1700e569.bin"
    file_type = "elf"
    first_seen = "2026-11-23 07:05:38"
  condition:
    hash.sha256(0, filesize) == "07c2c1fd1700e569d04e6e2fbea1bed75422caec72344ed3eebc2f012bbb089e"
}

rule MalwareBazaar_EasyShell_016_0781ae04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0781ae0479ce0c1ae23a3133aaec7d466852b037361aeb108ef1431b436096fb"
    family = "EasyShell"
    file_name = "easyshell-l32-0781ae0479ce0c1a.bin"
    file_type = "elf"
    first_seen = "2026-11-23 07:05:29"
  condition:
    hash.sha256(0, filesize) == "0781ae0479ce0c1ae23a3133aaec7d466852b037361aeb108ef1431b436096fb"
}

rule MalwareBazaar_EasyShell_017_f8b7c4ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b7c4ffaceb2896e1a09846f6ae430e7de4a633c154cc66f4827b806dffab0b"
    family = "EasyShell"
    file_name = "easyshell-l128-f8b7c4ffaceb2896.bin"
    file_type = "elf"
    first_seen = "2026-11-23 07:05:21"
  condition:
    hash.sha256(0, filesize) == "f8b7c4ffaceb2896e1a09846f6ae430e7de4a633c154cc66f4827b806dffab0b"
}

rule MalwareBazaar_unknown_018_6a90bad1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a90bad16168d6d0807383e48bf5a3ebc705bcb6fc45812a496500ee9d26d0c3"
    family = "unknown"
    file_name = "Plastic Connection Piece.hta"
    file_type = "hta"
    first_seen = "2026-11-23 06:56:31"
  condition:
    hash.sha256(0, filesize) == "6a90bad16168d6d0807383e48bf5a3ebc705bcb6fc45812a496500ee9d26d0c3"
}

rule MalwareBazaar_Formbook_019_9149061f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9149061f9cd11ad182a505fbd09df0045c54a48f0177ed685891c9f824a74d4f"
    family = "Formbook"
    file_name = "MqQFgHFgSV6aWli.exe"
    file_type = "exe"
    first_seen = "2026-11-23 06:55:19"
  condition:
    hash.sha256(0, filesize) == "9149061f9cd11ad182a505fbd09df0045c54a48f0177ed685891c9f824a74d4f"
}

rule MalwareBazaar_unknown_020_912705df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "912705df252116cc5387043ed1243765c85603e2051736ec4f7c93e234f8ca21"
    family = "unknown"
    file_name = "Packing List, Commercial Invoice and Bill Of Lading.JS"
    file_type = "js"
    first_seen = "2026-11-23 06:55:01"
  condition:
    hash.sha256(0, filesize) == "912705df252116cc5387043ed1243765c85603e2051736ec4f7c93e234f8ca21"
}

rule MalwareBazaar_unknown_021_38505e84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38505e84d36a18082944ffa13d569182782eb1a52475691781146ec89e07c198"
    family = "unknown"
    file_name = "20032838 - TEKLİF FORMU_pdf.hta"
    file_type = "hta"
    first_seen = "2026-11-23 06:54:12"
  condition:
    hash.sha256(0, filesize) == "38505e84d36a18082944ffa13d569182782eb1a52475691781146ec89e07c198"
}

rule MalwareBazaar_Formbook_022_27957fd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27957fd69ffe2579e76bd091186af4f47d6fa244afa6539783d8e9db1a77664c"
    family = "Formbook"
    file_name = "DİOKİ_MALZEME FİYAT TEKLİFİ İSTEĞİ HK.wsf"
    file_type = "wsf"
    first_seen = "2026-11-23 06:53:26"
  condition:
    hash.sha256(0, filesize) == "27957fd69ffe2579e76bd091186af4f47d6fa244afa6539783d8e9db1a77664c"
}

rule MalwareBazaar_Formbook_023_a8526e33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8526e3335b0c8e6e0dab8ba95e815f3c0caa733c280f4944d34cc5f70bb7e9a"
    family = "Formbook"
    file_name = "ÜÇAY FIYAT TEKLIFI (TOLGA BEY PROJESİ) ÜÇAY MÜHENDİSLİK WILO POMPA.wsf"
    file_type = "wsf"
    first_seen = "2026-11-23 06:52:47"
  condition:
    hash.sha256(0, filesize) == "a8526e3335b0c8e6e0dab8ba95e815f3c0caa733c280f4944d34cc5f70bb7e9a"
}

rule MalwareBazaar_MassLogger_024_c07f09b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c07f09b938a879280282d717345fe11e59e41e6e743e20077816708a7f0a3e7e"
    family = "MassLogger"
    file_name = "Dekont.VBE"
    file_type = "vbe"
    first_seen = "2026-11-23 06:52:31"
  condition:
    hash.sha256(0, filesize) == "c07f09b938a879280282d717345fe11e59e41e6e743e20077816708a7f0a3e7e"
}

rule MalwareBazaar_unknown_025_47b6cd26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47b6cd26a1cd791cbc9607abac4ec9e97d752ff55c17310062685cee4301953a"
    family = "unknown"
    file_name = "SHIPMENT-PL & CI & BL draft for HF26XF0116A.js"
    file_type = "js"
    first_seen = "2026-11-23 06:51:21"
  condition:
    hash.sha256(0, filesize) == "47b6cd26a1cd791cbc9607abac4ec9e97d752ff55c17310062685cee4301953a"
}

rule MalwareBazaar_Formbook_026_55ea024e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55ea024e1028f67c5b5c1912336d3225951d4884e078446c4602023bea7e502b"
    family = "Formbook"
    file_name = "Panduan Mengisi SST-02 (Manual) dan Pindaan - BM (2025) (4)_pdf.wsf"
    file_type = "wsf"
    first_seen = "2026-11-23 06:48:35"
  condition:
    hash.sha256(0, filesize) == "55ea024e1028f67c5b5c1912336d3225951d4884e078446c4602023bea7e502b"
}

rule MalwareBazaar_unknown_027_462a3a6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "462a3a6a60418ce6ed83d837ab71b7352b060ea4b327e08a7cec6f523f4ec6a0"
    family = "unknown"
    file_name = "GUIDELINE FOR E-DISBURSEMENT REGISTRATION.hta"
    file_type = "hta"
    first_seen = "2026-11-23 06:47:54"
  condition:
    hash.sha256(0, filesize) == "462a3a6a60418ce6ed83d837ab71b7352b060ea4b327e08a7cec6f523f4ec6a0"
}

rule MalwareBazaar_unknown_028_eac83fa7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eac83fa7cd9542f4d467dab553fd81b535a7c0ab970d7be743973aaee15f366f"
    family = "unknown"
    file_name = "280298206_Acknowledgement copy for delivery order request.js"
    file_type = "js"
    first_seen = "2026-11-23 06:47:35"
  condition:
    hash.sha256(0, filesize) == "eac83fa7cd9542f4d467dab553fd81b535a7c0ab970d7be743973aaee15f366f"
}

rule MalwareBazaar_unknown_029_78da3eac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78da3eac7d17ec539e96f866c820519d273e991d8bf61103a4f942e252a1bbca"
    family = "unknown"
    file_name = "document.scr"
    file_type = "exe"
    first_seen = "2026-11-23 06:47:18"
  condition:
    hash.sha256(0, filesize) == "78da3eac7d17ec539e96f866c820519d273e991d8bf61103a4f942e252a1bbca"
}

rule MalwareBazaar_Formbook_030_d5b1a5de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5b1a5dea7412f0a2dc65e7fbefa7d836a289ec48c2b401bf4237cace47e4f40"
    family = "Formbook"
    file_name = "REQUEST FOR QUOTATION_VMECH TECHNOLOGIES 25112026.js"
    file_type = "js"
    first_seen = "2026-11-23 06:47:12"
  condition:
    hash.sha256(0, filesize) == "d5b1a5dea7412f0a2dc65e7fbefa7d836a289ec48c2b401bf4237cace47e4f40"
}

rule MalwareBazaar_unknown_031_668e065f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668e065f8b7353d0cf41d4730e5ec2e90b97b3ca5cbb7cb2db115a5516d488e8"
    family = "unknown"
    file_name = "document.scr"
    file_type = "exe"
    first_seen = "2026-11-23 06:46:55"
  condition:
    hash.sha256(0, filesize) == "668e065f8b7353d0cf41d4730e5ec2e90b97b3ca5cbb7cb2db115a5516d488e8"
}

rule MalwareBazaar_unknown_032_4c4507a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c4507a6d7c6b7ac3c165ae6dcd017c1b8ead7411e0e47ff956d5dbe63e976fd"
    family = "unknown"
    file_name = "Shipment advice & HBL draft copies.JS"
    file_type = "js"
    first_seen = "2026-11-23 06:46:37"
  condition:
    hash.sha256(0, filesize) == "4c4507a6d7c6b7ac3c165ae6dcd017c1b8ead7411e0e47ff956d5dbe63e976fd"
}

rule MalwareBazaar_unknown_033_2796310b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2796310b515b9d70e96ff2fe9239aa36ac13cba8ccbf9ca91028bee3a59e4112"
    family = "unknown"
    file_name = "RFQ-Q1196-2026v4.JS"
    file_type = "js"
    first_seen = "2026-11-23 06:45:51"
  condition:
    hash.sha256(0, filesize) == "2796310b515b9d70e96ff2fe9239aa36ac13cba8ccbf9ca91028bee3a59e4112"
}

rule MalwareBazaar_unknown_034_6156800f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6156800f481bd1a8e729d7e6d5922cd517d047515467e3950a9c1aff527ba5fa"
    family = "unknown"
    file_name = "Neworder_Product_List_Specifications_Request_for_Pricing.js"
    file_type = "js"
    first_seen = "2026-11-23 06:45:29"
  condition:
    hash.sha256(0, filesize) == "6156800f481bd1a8e729d7e6d5922cd517d047515467e3950a9c1aff527ba5fa"
}

rule MalwareBazaar_AgentTesla_035_b8ca5f05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8ca5f05d259f13d9e97d7ec6c6a2581643754659753950b3db245c35104a2ab"
    family = "AgentTesla"
    file_name = "SHIPPING ADVICE.exe"
    file_type = "exe"
    first_seen = "2026-11-23 06:45:02"
  condition:
    hash.sha256(0, filesize) == "b8ca5f05d259f13d9e97d7ec6c6a2581643754659753950b3db245c35104a2ab"
}

rule MalwareBazaar_unknown_036_3b0ec228
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b0ec2286f877f0f92ceb2105f5189e472839731dbcd1a99fb1d947ed47d377d"
    family = "unknown"
    file_name = "d57f98470f955162e7a6cbbb26e62bc2"
    file_type = "dll"
    first_seen = "2026-11-23 06:40:08"
  condition:
    hash.sha256(0, filesize) == "3b0ec2286f877f0f92ceb2105f5189e472839731dbcd1a99fb1d947ed47d377d"
}

rule MalwareBazaar_EasyShell_037_596f856a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "596f856a0c6f2e66c21c8c6cd5ea858cdc3fdf7c38f3a728897b9617af579196"
    family = "EasyShell"
    file_name = "easyshell-l64-596f856a0c6f2e66.bin"
    file_type = "elf"
    first_seen = "2026-11-23 06:36:35"
  condition:
    hash.sha256(0, filesize) == "596f856a0c6f2e66c21c8c6cd5ea858cdc3fdf7c38f3a728897b9617af579196"
}

rule MalwareBazaar_EasyShell_038_133e9624
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "133e9624f08ae2fc0b8532438fbe6e0b4552ae9e8956abfa925fb27da20d8b0c"
    family = "EasyShell"
    file_name = "easyshell-l32-133e9624f08ae2fc.bin"
    file_type = "elf"
    first_seen = "2026-11-23 06:36:25"
  condition:
    hash.sha256(0, filesize) == "133e9624f08ae2fc0b8532438fbe6e0b4552ae9e8956abfa925fb27da20d8b0c"
}

rule MalwareBazaar_EasyShell_039_e924109a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e924109a74b5f594e0f3a67abdfbb7d079ac9f430715c7a651462f09e7653cdd"
    family = "EasyShell"
    file_name = "easyshell-l128-e924109a74b5f594.bin"
    file_type = "elf"
    first_seen = "2026-11-23 06:36:17"
  condition:
    hash.sha256(0, filesize) == "e924109a74b5f594e0f3a67abdfbb7d079ac9f430715c7a651462f09e7653cdd"
}

rule MalwareBazaar_EasyShell_040_78bbcc31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78bbcc31287f5cd18450833f6b111cc02853b82ee90a2a43f2d60d92609a305d"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-78bbcc31287f5cd1.bin"
    file_type = "macho"
    first_seen = "2026-11-23 06:36:09"
  condition:
    hash.sha256(0, filesize) == "78bbcc31287f5cd18450833f6b111cc02853b82ee90a2a43f2d60d92609a305d"
}

rule MalwareBazaar_EasyShell_041_7e6a0512
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e6a0512790f203eec0a00ca4fe24be9e5c76851cbe04a616e0f86cf5560ed47"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-7e6a0512790f203e.bin"
    file_type = "macho"
    first_seen = "2026-11-23 06:36:00"
  condition:
    hash.sha256(0, filesize) == "7e6a0512790f203eec0a00ca4fe24be9e5c76851cbe04a616e0f86cf5560ed47"
}

rule MalwareBazaar_EasyShell_042_038c5519
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "038c5519a79b5a920b3bc4d435c455ff85e8c425fea83b82297c2d475f2a1adb"
    family = "EasyShell"
    file_name = "easyshell-a64-038c5519a79b5a92.bin"
    file_type = "elf"
    first_seen = "2026-11-23 06:35:50"
  condition:
    hash.sha256(0, filesize) == "038c5519a79b5a920b3bc4d435c455ff85e8c425fea83b82297c2d475f2a1adb"
}

rule MalwareBazaar_EasyShell_043_4274df7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4274df7e8bcc5fa5a75bf87c8fabcf4be139131c7791799a9e14b13616806a44"
    family = "EasyShell"
    file_name = "easyshell-a32-4274df7e8bcc5fa5.bin"
    file_type = "elf"
    first_seen = "2026-11-23 06:35:40"
  condition:
    hash.sha256(0, filesize) == "4274df7e8bcc5fa5a75bf87c8fabcf4be139131c7791799a9e14b13616806a44"
}

rule MalwareBazaar_unknown_044_61b5e8b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61b5e8b4baa85cfe656a9759df34135acbbbe9d9853a08f54b4b63dae7565458"
    family = "unknown"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-11-23 06:29:40"
  condition:
    hash.sha256(0, filesize) == "61b5e8b4baa85cfe656a9759df34135acbbbe9d9853a08f54b4b63dae7565458"
}

rule MalwareBazaar_unknown_045_b2b386ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2b386edce5af8084484858ac2310f214bf01e363714133ed0f9c322f2c727a1"
    family = "unknown"
    file_name = "DaiichiLife.apk"
    file_type = "apk"
    first_seen = "2026-11-23 06:27:19"
  condition:
    hash.sha256(0, filesize) == "b2b386edce5af8084484858ac2310f214bf01e363714133ed0f9c322f2c727a1"
}

rule MalwareBazaar_unknown_046_f54c081f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f54c081f216590deb7b964981d911f66e5bfdb603da976dfd125ceb677a65738"
    family = "unknown"
    file_name = "nano.sh"
    file_type = "sh"
    first_seen = "2026-11-23 06:26:15"
  condition:
    hash.sha256(0, filesize) == "f54c081f216590deb7b964981d911f66e5bfdb603da976dfd125ceb677a65738"
}

rule MalwareBazaar_unknown_047_1d536954
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d536954415b2bf1dc25e03e8f73f94b58a8646d4e6d672b71880389843c5d4b"
    family = "unknown"
    file_name = "1d536954415b2bf1dc25e03e8f73f94b58a8646d4e6d672b71880389843c5d4b.sh"
    file_type = "sh"
    first_seen = "2026-11-23 06:18:08"
  condition:
    hash.sha256(0, filesize) == "1d536954415b2bf1dc25e03e8f73f94b58a8646d4e6d672b71880389843c5d4b"
}

rule MalwareBazaar_Mirai_048_d0868826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0868826e42a8b12a7dda66a13680161b79e518611258622c8dfa9d74558d381"
    family = "Mirai"
    file_name = "jew.x86"
    file_type = "elf"
    first_seen = "2026-11-23 06:18:05"
  condition:
    hash.sha256(0, filesize) == "d0868826e42a8b12a7dda66a13680161b79e518611258622c8dfa9d74558d381"
}

rule MalwareBazaar_Mirai_049_ae744069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae744069e73d8fa89e8e5414c85a8b0fd1dd6d648647eced09ddfa47188c7374"
    family = "Mirai"
    file_name = "kaizen.x86"
    file_type = "elf"
    first_seen = "2026-11-23 06:13:24"
  condition:
    hash.sha256(0, filesize) == "ae744069e73d8fa89e8e5414c85a8b0fd1dd6d648647eced09ddfa47188c7374"
}

rule MalwareBazaar_Mirai_050_032bbeaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "032bbeaa3106eff8c14d11a3439ee8e58d7ff8a87019155065f190e71e5fa730"
    family = "Mirai"
    file_name = "kaizen.sh4"
    file_type = "elf"
    first_seen = "2026-11-23 06:13:09"
  condition:
    hash.sha256(0, filesize) == "032bbeaa3106eff8c14d11a3439ee8e58d7ff8a87019155065f190e71e5fa730"
}

rule MalwareBazaar_Mirai_051_44ba2238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44ba2238310ceb94198d0f086f9ed4edf727b680569b330b10344140e41d08f0"
    family = "Mirai"
    file_name = "kaizen.x86"
    file_type = "elf"
    first_seen = "2026-11-23 06:13:06"
  condition:
    hash.sha256(0, filesize) == "44ba2238310ceb94198d0f086f9ed4edf727b680569b330b10344140e41d08f0"
}

rule MalwareBazaar_Mirai_052_82b7ab72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82b7ab720e0a787544b9d8a71ae71e73ddefbbab6b7aebcf9cdd085b4943b9f3"
    family = "Mirai"
    file_name = "kaizen.ppc"
    file_type = "elf"
    first_seen = "2026-11-23 06:12:07"
  condition:
    hash.sha256(0, filesize) == "82b7ab720e0a787544b9d8a71ae71e73ddefbbab6b7aebcf9cdd085b4943b9f3"
}

rule MalwareBazaar_Prometei_053_5f27bb69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f27bb695949987e1feff780c5cc002842342e128c2153fc19a10e56ab7b73e8"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-23 06:12:05"
  condition:
    hash.sha256(0, filesize) == "5f27bb695949987e1feff780c5cc002842342e128c2153fc19a10e56ab7b73e8"
}

rule MalwareBazaar_WARDENStealer_054_d7766716
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7766716ce3e0b8f2e4038bc7dc15cd5c3a51aa2a88ec7b937664c31e2c2adb2"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-23 06:11:17"
  condition:
    hash.sha256(0, filesize) == "d7766716ce3e0b8f2e4038bc7dc15cd5c3a51aa2a88ec7b937664c31e2c2adb2"
}

rule MalwareBazaar_WARDENStealer_055_61618c5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61618c5d2b6383dc9154499d9c8582a20f29768656f75aac50bec31c7efe4209"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-23 06:10:48"
  condition:
    hash.sha256(0, filesize) == "61618c5d2b6383dc9154499d9c8582a20f29768656f75aac50bec31c7efe4209"
}

rule MalwareBazaar_WARDENStealer_056_8ddf5b0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ddf5b0c23e5dd2e2aafc37dd1dc1b501a620e0c30c8cce4f442518135998b97"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-23 06:10:21"
  condition:
    hash.sha256(0, filesize) == "8ddf5b0c23e5dd2e2aafc37dd1dc1b501a620e0c30c8cce4f442518135998b97"
}

rule MalwareBazaar_Mirai_057_f353cd7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f353cd7de97831ec9577ae8270a9adab5a1d84061f7f476213322a6af2ab8e03"
    family = "Mirai"
    file_name = "nabarm6"
    file_type = "elf"
    first_seen = "2026-11-23 06:10:08"
  condition:
    hash.sha256(0, filesize) == "f353cd7de97831ec9577ae8270a9adab5a1d84061f7f476213322a6af2ab8e03"
}

rule MalwareBazaar_Prometei_058_3f86c7b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f86c7b63f7ad5ace5e74fa5c5ad511372d88ac0e4d7d6758c6216aafbf46e6c"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-23 06:09:08"
  condition:
    hash.sha256(0, filesize) == "3f86c7b63f7ad5ace5e74fa5c5ad511372d88ac0e4d7d6758c6216aafbf46e6c"
}

rule MalwareBazaar_Mirai_059_fcd8384d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcd8384dabe51cd85b8df552a97a77402c92c35fb5be42327023894ceef5f87e"
    family = "Mirai"
    file_name = "nabppc"
    file_type = "elf"
    first_seen = "2026-11-23 06:09:05"
  condition:
    hash.sha256(0, filesize) == "fcd8384dabe51cd85b8df552a97a77402c92c35fb5be42327023894ceef5f87e"
}

rule MalwareBazaar_Prometei_060_6b8bdb2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b8bdb2c9c2be46c79d6bbb1f1369acf24a685dedd06b1835179397e02dbe72e"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-23 06:08:06"
  condition:
    hash.sha256(0, filesize) == "6b8bdb2c9c2be46c79d6bbb1f1369acf24a685dedd06b1835179397e02dbe72e"
}

rule MalwareBazaar_Mirai_061_23c1f8ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23c1f8ea43b5c7d627971dd381436fcab6613ecb2c57c41cc545649d5494fe11"
    family = "Mirai"
    file_name = "nklarm7"
    file_type = "elf"
    first_seen = "2026-11-23 06:07:07"
  condition:
    hash.sha256(0, filesize) == "23c1f8ea43b5c7d627971dd381436fcab6613ecb2c57c41cc545649d5494fe11"
}

rule MalwareBazaar_Mirai_062_1d48fe08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d48fe08ea5ba348f168048d9585918ec4a47b80fa0366b0f3b2694d29dde964"
    family = "Mirai"
    file_name = "nabm68k"
    file_type = "elf"
    first_seen = "2026-11-23 06:07:05"
  condition:
    hash.sha256(0, filesize) == "1d48fe08ea5ba348f168048d9585918ec4a47b80fa0366b0f3b2694d29dde964"
}

rule MalwareBazaar_Mirai_063_3c274313
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c2743136c545fad314f328a5f45cf0176e8a8e8042ec09a0f81e47271b3f5f7"
    family = "Mirai"
    file_name = "nklarm"
    file_type = "elf"
    first_seen = "2026-11-23 06:05:08"
  condition:
    hash.sha256(0, filesize) == "3c2743136c545fad314f328a5f45cf0176e8a8e8042ec09a0f81e47271b3f5f7"
}

rule MalwareBazaar_Mirai_064_8ae66435
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ae6643547b0abea7df801d29701707464226cfe6ed177315355b406604bcfa3"
    family = "Mirai"
    file_name = "zerarm"
    file_type = "elf"
    first_seen = "2026-11-23 06:05:05"
  condition:
    hash.sha256(0, filesize) == "8ae6643547b0abea7df801d29701707464226cfe6ed177315355b406604bcfa3"
}

rule MalwareBazaar_Mirai_065_f2b94316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b94316e528c3c0c852710f1db84f9737bf00c346dcc0c7f23fb64d6b804163"
    family = "Mirai"
    file_name = "kaizen.mips"
    file_type = "elf"
    first_seen = "2026-11-23 06:00:10"
  condition:
    hash.sha256(0, filesize) == "f2b94316e528c3c0c852710f1db84f9737bf00c346dcc0c7f23fb64d6b804163"
}

rule MalwareBazaar_Mirai_066_b810f6aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b810f6aa9e44eec4cf0be0203eea115566c7af8a129aadbbb88d9eebcd376b13"
    family = "Mirai"
    file_name = "nklarm6"
    file_type = "elf"
    first_seen = "2026-11-23 06:00:07"
  condition:
    hash.sha256(0, filesize) == "b810f6aa9e44eec4cf0be0203eea115566c7af8a129aadbbb88d9eebcd376b13"
}

rule MalwareBazaar_Mirai_067_8263134f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8263134fa2e45031dcd0b748531bb753213320ed92a70ef94a6c9647edc2aaba"
    family = "Mirai"
    file_name = "kaizen.x86_64_srv"
    file_type = "elf"
    first_seen = "2026-11-23 05:58:07"
  condition:
    hash.sha256(0, filesize) == "8263134fa2e45031dcd0b748531bb753213320ed92a70ef94a6c9647edc2aaba"
}

rule MalwareBazaar_Mirai_068_dd600dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd600dd0a1443e30a32faae094e600c408ff2340ab4690f663c2e23376584d3b"
    family = "Mirai"
    file_name = "nabarm5"
    file_type = "elf"
    first_seen = "2026-11-23 05:58:05"
  condition:
    hash.sha256(0, filesize) == "dd600dd0a1443e30a32faae094e600c408ff2340ab4690f663c2e23376584d3b"
}

rule MalwareBazaar_Mirai_069_c3630e79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3630e79b3cc4aae8a60396ff0b9549c2fe0546dd7f0c46ce6d424f734cf16ff"
    family = "Mirai"
    file_name = "kaizen.arm7"
    file_type = "elf"
    first_seen = "2026-11-23 05:54:08"
  condition:
    hash.sha256(0, filesize) == "c3630e79b3cc4aae8a60396ff0b9549c2fe0546dd7f0c46ce6d424f734cf16ff"
}

rule MalwareBazaar_Mirai_070_b9d87331
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9d873319ccee197d2a9c70183d081cb83504c02a0a6d2ae24e4288234e7e06c"
    family = "Mirai"
    file_name = "nklx86"
    file_type = "elf"
    first_seen = "2026-11-23 05:54:05"
  condition:
    hash.sha256(0, filesize) == "b9d873319ccee197d2a9c70183d081cb83504c02a0a6d2ae24e4288234e7e06c"
}

rule MalwareBazaar_unknown_071_e0bec6c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0bec6c0e89fda7bdf623bcfe4c930fba7523958ecf3d4dc64b10f9175e5c95a"
    family = "unknown"
    file_name = "apple.exe"
    file_type = "exe"
    first_seen = "2026-11-23 05:52:28"
  condition:
    hash.sha256(0, filesize) == "e0bec6c0e89fda7bdf623bcfe4c930fba7523958ecf3d4dc64b10f9175e5c95a"
}

rule MalwareBazaar_Mirai_072_c69018ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c69018ff9709409889b9c36184a4080e3eb6cced0d59abcda2a9710239a7965a"
    family = "Mirai"
    file_name = "splspc"
    file_type = "elf"
    first_seen = "2026-11-23 05:52:08"
  condition:
    hash.sha256(0, filesize) == "c69018ff9709409889b9c36184a4080e3eb6cced0d59abcda2a9710239a7965a"
}

rule MalwareBazaar_Mirai_073_86da445a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86da445addf19314441fdfc628552b5a8de684ed7945ed21caa7fe07b0badfbb"
    family = "Mirai"
    file_name = "nklppc"
    file_type = "elf"
    first_seen = "2026-11-23 05:52:05"
  condition:
    hash.sha256(0, filesize) == "86da445addf19314441fdfc628552b5a8de684ed7945ed21caa7fe07b0badfbb"
}

rule MalwareBazaar_Mirai_074_d1b7e166
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1b7e1661e6db02b11443b0093a3c41fcae239f36b241b3e7e777fa8b548ab56"
    family = "Mirai"
    file_name = "zerarm5"
    file_type = "elf"
    first_seen = "2026-11-23 05:51:05"
  condition:
    hash.sha256(0, filesize) == "d1b7e1661e6db02b11443b0093a3c41fcae239f36b241b3e7e777fa8b548ab56"
}

rule MalwareBazaar_Mirai_075_632ed857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "632ed85720a5c0ea5a8df4dafda58660fd23f22f13642a625c7d243b26ae5a86"
    family = "Mirai"
    file_name = "kaizen.m68k"
    file_type = "elf"
    first_seen = "2026-11-23 05:50:08"
  condition:
    hash.sha256(0, filesize) == "632ed85720a5c0ea5a8df4dafda58660fd23f22f13642a625c7d243b26ae5a86"
}

rule MalwareBazaar_Mirai_076_64cccb94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64cccb94d026b4d2e3a34ad83567216ee7206da1fb81e101aa6523fe02e0c5c1"
    family = "Mirai"
    file_name = "nklarm5"
    file_type = "elf"
    first_seen = "2026-11-23 05:49:08"
  condition:
    hash.sha256(0, filesize) == "64cccb94d026b4d2e3a34ad83567216ee7206da1fb81e101aa6523fe02e0c5c1"
}

rule MalwareBazaar_Mirai_077_aeb2d193
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aeb2d193c4cbec1d4ad77952d208c7fe43cfa1296a7bd97a12c0985c81445bb7"
    family = "Mirai"
    file_name = "nabmips"
    file_type = "elf"
    first_seen = "2026-11-23 05:49:05"
  condition:
    hash.sha256(0, filesize) == "aeb2d193c4cbec1d4ad77952d208c7fe43cfa1296a7bd97a12c0985c81445bb7"
}

rule MalwareBazaar_Mirai_078_a6fef561
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6fef561622b93aa142df123c7fbdddddb07bc3f66de364a8a89a8ed54ce9cff"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-23 05:46:06"
  condition:
    hash.sha256(0, filesize) == "a6fef561622b93aa142df123c7fbdddddb07bc3f66de364a8a89a8ed54ce9cff"
}

rule MalwareBazaar_Mirai_079_cea5a478
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cea5a47828d5d384465d3c69166da1908c0940ef0ca0821b6ea49169785e9d03"
    family = "Mirai"
    file_name = "zermpsl"
    file_type = "elf"
    first_seen = "2026-11-23 05:44:09"
  condition:
    hash.sha256(0, filesize) == "cea5a47828d5d384465d3c69166da1908c0940ef0ca0821b6ea49169785e9d03"
}

rule MalwareBazaar_Mirai_080_cf78cb08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf78cb089fcf06f8ebb10e21ff797de6a39e0c619f7e95abff5a851a6d49eb4a"
    family = "Mirai"
    file_name = "nabx86"
    file_type = "elf"
    first_seen = "2026-11-23 05:44:06"
  condition:
    hash.sha256(0, filesize) == "cf78cb089fcf06f8ebb10e21ff797de6a39e0c619f7e95abff5a851a6d49eb4a"
}

rule MalwareBazaar_Mirai_081_a04ce984
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a04ce98444aeb2934c3cf1be7a9bc29fe716ced94376cfc515ea0f709e468cf5"
    family = "Mirai"
    file_name = "nklsh4"
    file_type = "elf"
    first_seen = "2026-11-23 05:43:07"
  condition:
    hash.sha256(0, filesize) == "a04ce98444aeb2934c3cf1be7a9bc29fe716ced94376cfc515ea0f709e468cf5"
}

rule MalwareBazaar_Mirai_082_af551780
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af551780cc6a4c7e074d4097b46b5f5a7c72693b6541ed5d56a9f043fb0503c6"
    family = "Mirai"
    file_name = "zermips"
    file_type = "elf"
    first_seen = "2026-11-23 05:42:08"
  condition:
    hash.sha256(0, filesize) == "af551780cc6a4c7e074d4097b46b5f5a7c72693b6541ed5d56a9f043fb0503c6"
}

rule MalwareBazaar_Mirai_083_d9b2780f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9b2780f87fb0cd87db6b80ea5dcde8367f3c27a7adfe527e6ae13e4e10df118"
    family = "Mirai"
    file_name = "nklspc"
    file_type = "elf"
    first_seen = "2026-11-23 05:42:05"
  condition:
    hash.sha256(0, filesize) == "d9b2780f87fb0cd87db6b80ea5dcde8367f3c27a7adfe527e6ae13e4e10df118"
}

rule MalwareBazaar_Mirai_084_db5472ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db5472efa9baffce26a43fe40129fa14b538a9e5cc4d8c49b88bd0c02cb2f32e"
    family = "Mirai"
    file_name = "splmips"
    file_type = "elf"
    first_seen = "2026-11-23 05:40:08"
  condition:
    hash.sha256(0, filesize) == "db5472efa9baffce26a43fe40129fa14b538a9e5cc4d8c49b88bd0c02cb2f32e"
}

rule MalwareBazaar_Mirai_085_dd0a00bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd0a00bfd570e9cfa3d75e9870c678aaba35e1b875236219fc5211ca3cdd5fed"
    family = "Mirai"
    file_name = "splm68k"
    file_type = "elf"
    first_seen = "2026-11-23 05:40:05"
  condition:
    hash.sha256(0, filesize) == "dd0a00bfd570e9cfa3d75e9870c678aaba35e1b875236219fc5211ca3cdd5fed"
}

rule MalwareBazaar_Mirai_086_aca3615a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aca3615ab286ca8cd77c89cbe3aed00b7940a799cecd1165918924662c4e0a89"
    family = "Mirai"
    file_name = "nklmpsl"
    file_type = "elf"
    first_seen = "2026-11-23 05:38:09"
  condition:
    hash.sha256(0, filesize) == "aca3615ab286ca8cd77c89cbe3aed00b7940a799cecd1165918924662c4e0a89"
}

rule MalwareBazaar_Prometei_087_012751bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "012751bfd413109a99b2249a93f47caed9357821fd96f3faf4e16cab2f1bb7d2"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-23 05:38:07"
  condition:
    hash.sha256(0, filesize) == "012751bfd413109a99b2249a93f47caed9357821fd96f3faf4e16cab2f1bb7d2"
}

rule MalwareBazaar_Mirai_088_85ab4afa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85ab4afa171f93cf74dd412ab4cff3816df9a811b7eb7f773fbcf1ee00ff5fea"
    family = "Mirai"
    file_name = "splarm7"
    file_type = "elf"
    first_seen = "2026-11-23 05:37:09"
  condition:
    hash.sha256(0, filesize) == "85ab4afa171f93cf74dd412ab4cff3816df9a811b7eb7f773fbcf1ee00ff5fea"
}

rule MalwareBazaar_Mirai_089_430a5bc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "430a5bc5913948037be4597d76d55770e961b721e7011219886e36cc4a995c86"
    family = "Mirai"
    file_name = "splmpsl"
    file_type = "elf"
    first_seen = "2026-11-23 05:37:07"
  condition:
    hash.sha256(0, filesize) == "430a5bc5913948037be4597d76d55770e961b721e7011219886e36cc4a995c86"
}

rule MalwareBazaar_EasyShell_090_791b169b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "791b169be1f2e5dadf8a2b5b0a86c973a1fa6318959ac9d3824c654411ee1adc"
    family = "EasyShell"
    file_name = "easyshell-l64-791b169be1f2e5da.bin"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:46"
  condition:
    hash.sha256(0, filesize) == "791b169be1f2e5dadf8a2b5b0a86c973a1fa6318959ac9d3824c654411ee1adc"
}

rule MalwareBazaar_EasyShell_091_248b0fd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "248b0fd54187153e49814aed72b03e52e7378d3af69f2e4e4e99d4abd2ef1f55"
    family = "EasyShell"
    file_name = "easyshell-l32-248b0fd54187153e.bin"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:37"
  condition:
    hash.sha256(0, filesize) == "248b0fd54187153e49814aed72b03e52e7378d3af69f2e4e4e99d4abd2ef1f55"
}

rule MalwareBazaar_EasyShell_092_a2af915b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2af915b17d29e751c96b94a169350ab19bae3fa275150f9224aeb0350956f63"
    family = "EasyShell"
    file_name = "easyshell-l128-a2af915b17d29e75.bin"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:28"
  condition:
    hash.sha256(0, filesize) == "a2af915b17d29e751c96b94a169350ab19bae3fa275150f9224aeb0350956f63"
}

rule MalwareBazaar_EasyShell_093_e41e8294
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e41e8294cb2239cf221ce8d7834d88b534a80d59c3c03fbccfbc023aa637df3b"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-e41e8294cb2239cf.bin"
    file_type = "macho"
    first_seen = "2026-11-23 05:36:20"
  condition:
    hash.sha256(0, filesize) == "e41e8294cb2239cf221ce8d7834d88b534a80d59c3c03fbccfbc023aa637df3b"
}

rule MalwareBazaar_EasyShell_094_884053c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "884053c7342bee4bd581acfc9affc17b7d296c47657138a2722f441b5984f233"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-884053c7342bee4b.bin"
    file_type = "macho"
    first_seen = "2026-11-23 05:36:11"
  condition:
    hash.sha256(0, filesize) == "884053c7342bee4bd581acfc9affc17b7d296c47657138a2722f441b5984f233"
}

rule MalwareBazaar_Mirai_095_d2c59d92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2c59d92d30ca23bd75790f217f922bd60da5755e69346224dc5076614de1f26"
    family = "Mirai"
    file_name = "kaizen.arm6"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:07"
  condition:
    hash.sha256(0, filesize) == "d2c59d92d30ca23bd75790f217f922bd60da5755e69346224dc5076614de1f26"
}

rule MalwareBazaar_Mirai_096_11bc3d5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11bc3d5be7e2ed5808be472f3e1394b9e39d2d04d5bd87d4353a77a4d5d4d48e"
    family = "Mirai"
    file_name = "kaizen.arm5"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:05"
  condition:
    hash.sha256(0, filesize) == "11bc3d5be7e2ed5808be472f3e1394b9e39d2d04d5bd87d4353a77a4d5d4d48e"
}

rule MalwareBazaar_EasyShell_097_dd66ee61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd66ee61c603e8500b9dd94f6ea05e9a9cc92c5f19f12775ff0449d4d38fa267"
    family = "EasyShell"
    file_name = "easyshell-a64-dd66ee61c603e850.bin"
    file_type = "elf"
    first_seen = "2026-11-23 05:36:02"
  condition:
    hash.sha256(0, filesize) == "dd66ee61c603e8500b9dd94f6ea05e9a9cc92c5f19f12775ff0449d4d38fa267"
}

rule MalwareBazaar_EasyShell_098_b457bcec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b457bcec64d9ce0a66c5fe2bd4e09a7109a0e01eccd37bc91b3c4b9da5fd78da"
    family = "EasyShell"
    file_name = "easyshell-a32-b457bcec64d9ce0a.bin"
    file_type = "elf"
    first_seen = "2026-11-23 05:35:54"
  condition:
    hash.sha256(0, filesize) == "b457bcec64d9ce0a66c5fe2bd4e09a7109a0e01eccd37bc91b3c4b9da5fd78da"
}

rule MalwareBazaar_Mirai_099_a20e90c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a20e90c799880831329ef1910938888e3f87b1601e32d11f323af841b4a26acd"
    family = "Mirai"
    file_name = "jklmips"
    file_type = "elf"
    first_seen = "2026-11-23 05:35:05"
  condition:
    hash.sha256(0, filesize) == "a20e90c799880831329ef1910938888e3f87b1601e32d11f323af841b4a26acd"
}

rule MalwareBazaar_Mirai_100_1dc5f37b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dc5f37bf10c9e5bfae055c336fe687faeb946901b4afa0f7167cfcad8e9c31f"
    family = "Mirai"
    file_name = "jklm68k"
    file_type = "elf"
    first_seen = "2026-11-23 05:33:08"
  condition:
    hash.sha256(0, filesize) == "1dc5f37bf10c9e5bfae055c336fe687faeb946901b4afa0f7167cfcad8e9c31f"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

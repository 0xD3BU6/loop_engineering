# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-06-21

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 646 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 646 |
| Unique family labels | 12 |
| Unique file types | 11 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 53 |
| Mirai | 27 |
| ConnectWise | 5 |
| RemcosRAT | 5 |
| NanoCore | 2 |
| SilentNet | 2 |
| AsyncRAT | 1 |
| Vidar | 1 |
| AnyDesk | 1 |
| njrat | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 52 |
| exe | 19 |
| sh | 12 |
| zip | 3 |
| jar | 3 |
| unknown | 3 |
| msi | 3 |
| js | 2 |
| vbs | 1 |
| hta | 1 |

## Per-Sample Analysis

### Sample 1: `95a6eeb9407cfae9`

| Field | Value |
|---|---|
| SHA-256 | `95a6eeb9407cfae94a99df9ca32c3b1858a5d6ff944eff33ad2228a1915c808b` |
| Family label | `unknown` |
| File name | `HMCL-3.13.zip` |
| File type | `zip` |
| First seen | `2026-06-21 16:10:17` |
| Reporter | `CNGaoLing` |
| Tags | `XWorm, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92167980027e13584ce5118e1e83ab0a` |
| SHA-1 | `2aab42f242abe16cc83703c742e0029403922d0e` |
| SHA-256 | `95a6eeb9407cfae94a99df9ca32c3b1858a5d6ff944eff33ad2228a1915c808b` |
| SHA3-384 | `536e58a361f03af89f6376b9e9ff7c53439bc916c3d6f69f9f8a438398a3ce8162e64b835a173b46c26ab8ff78bf6302` |
| TLSH | `T11DC63387A4BBA1D4CEA0D6E27E7652C4142698B4040E6E3EFF43EB504196FF51926C3F` |
| SSDEEP | `196608:ejBQPD7RO9CBTJj+nm1gSLuDUtxI3yqFRhTEzpcP9CzUqMRPOp2iUwhYvF/MCA/l:+BQ4wRJynfkuDwxVkEzpcFh2sJBF/fGh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_95a6eeb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95a6eeb9407cfae94a99df9ca32c3b1858a5d6ff944eff33ad2228a1915c808b"
    family = "unknown"
    file_name = "HMCL-3.13.zip"
    file_type = "zip"
    first_seen = "2026-06-21 16:10:17"
  condition:
    hash.sha256(0, filesize) == "95a6eeb9407cfae94a99df9ca32c3b1858a5d6ff944eff33ad2228a1915c808b"
}
```

### Sample 2: `2011c98d44911abf`

| Field | Value |
|---|---|
| SHA-256 | `2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af` |
| Family label | `NanoCore` |
| File name | `navent.io.exe` |
| File type | `exe` |
| First seen | `2026-06-21 16:10:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce8dbd9fce3e739bfed8a23a96a92fe0` |
| SHA-1 | `e68d17c94b4d37b1a9639bbebc542dafec3f9db3` |
| SHA-256 | `2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af` |
| SHA3-384 | `6846b20fce6b4845760c2b5d6ad791158a23f4c2b6703a476c3b480ff6c6c6cf7aa3d115410f3b50c0d18430161bcd8a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1FC14D0553BA84A2FE2DE85B9702212139379C2E7E8C3F3DE28E451B64F567E50A071D3` |
| SSDEEP | `3072:szEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HIfRsC6wwBLsjAIZnB/nFgMbszn:sLV6Bta6dtJmakIM5q+LsjAcW/zhIRg` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_002_2011c98d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af"
    family = "NanoCore"
    file_name = "navent.io.exe"
    file_type = "exe"
    first_seen = "2026-06-21 16:10:05"
  condition:
    hash.sha256(0, filesize) == "2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af"
}
```

### Sample 3: `00e99856b30d2f75`

| Field | Value |
|---|---|
| SHA-256 | `00e99856b30d2f75a452daf1dc13ed02396d38ff975db1f814668b8ff0b52eac` |
| Family label | `unknown` |
| File name | `kworkerd-netns-rt` |
| File type | `elf` |
| First seen | `2026-06-21 16:00:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bada65a963c478694a6ebf97d80c6890` |
| SHA-1 | `82f0775ea36f086c44a6e4e90f0ff034577aa20e` |
| SHA-256 | `00e99856b30d2f75a452daf1dc13ed02396d38ff975db1f814668b8ff0b52eac` |
| SHA3-384 | `68b759e82a88872165130c29860810c3154653f4d3fa1974dd8ca118d07f79b6deddd3882ce10b04fde09e906aa44e5f` |
| TLSH | `T1F3D3129F290686FEDA26683A863177E8DF10093FD191BF44120BDBF6C4D508AFE47952` |
| SSDEEP | `3072:enfpWLk2Unh2ywuN0aVXe7x6EsFl/on9ihyddCI7VU:enfpx2QtwuN0AX0b0W9RdtpU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_00e99856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00e99856b30d2f75a452daf1dc13ed02396d38ff975db1f814668b8ff0b52eac"
    family = "unknown"
    file_name = "kworkerd-netns-rt"
    file_type = "elf"
    first_seen = "2026-06-21 16:00:01"
  condition:
    hash.sha256(0, filesize) == "00e99856b30d2f75a452daf1dc13ed02396d38ff975db1f814668b8ff0b52eac"
}
```

### Sample 4: `6aa08b6fdb70023b`

| Field | Value |
|---|---|
| SHA-256 | `6aa08b6fdb70023bdd14805657a5d4e36b5733b8b4c372c95ce2ec17668a0f11` |
| Family label | `AsyncRAT` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-21 15:47:49` |
| Reporter | `Bitsight` |
| Tags | `282234, AsyncRAT, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e3c5aa594c8beaefb73e35b563379d7` |
| SHA-1 | `5f8e51e3cbc4530d86c2ee6cf77ccaf77e7189a2` |
| SHA-256 | `6aa08b6fdb70023bdd14805657a5d4e36b5733b8b4c372c95ce2ec17668a0f11` |
| SHA3-384 | `58c13dbdef96be845294446e8c46e28688e256176f801add984cb79ed1d82570e444ef2d3d28518ec2706852fb87f37c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15C57345CA490A7A09BC2759313DFE4CC6F903E91409C897B3CF746EB43666B4E86B364` |
| SSDEEP | `393216:YoSBaQl1q1Y0kUBNQ1B4BoC6fcRMenFe/s9ojyhRV5eICqDVkms9o83QcmcrS:PSH1UYwPScMwYJmhR/A4kmwtmh` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_004_6aa08b6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aa08b6fdb70023bdd14805657a5d4e36b5733b8b4c372c95ce2ec17668a0f11"
    family = "AsyncRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 15:47:49"
  condition:
    hash.sha256(0, filesize) == "6aa08b6fdb70023bdd14805657a5d4e36b5733b8b4c372c95ce2ec17668a0f11"
}
```

### Sample 5: `dd09d1fc879642e9`

| Field | Value |
|---|---|
| SHA-256 | `dd09d1fc879642e9b72ac07680a36a9f0b18cf31f8283295e7bc9c2456ff54bb` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-06-21 15:45:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `451aa4d4fdcd847b5232513beff91855` |
| SHA-1 | `c383a1ea51da82570e2ec6490fccdadafc0f7d05` |
| SHA-256 | `dd09d1fc879642e9b72ac07680a36a9f0b18cf31f8283295e7bc9c2456ff54bb` |
| SHA3-384 | `9d1fce586daafa1d70431ef1eaced9ad0a6adb6d7e40635fbc28fa2333d2321aae27a103fed07dec00fd23a0ff7aa254` |
| TLSH | `T1090182D685106D105019965E2AD75294F420C3CF0A5B0FB8BF9C5D3EFF98915F067F98` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha0ka8wNDD2Xw0Ft7:e9Qp+Ms0SwNGbFt7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_dd09d1fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd09d1fc879642e9b72ac07680a36a9f0b18cf31f8283295e7bc9c2456ff54bb"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-21 15:45:35"
  condition:
    hash.sha256(0, filesize) == "dd09d1fc879642e9b72ac07680a36a9f0b18cf31f8283295e7bc9c2456ff54bb"
}
```

### Sample 6: `05a5138226c9bcda`

| Field | Value |
|---|---|
| SHA-256 | `05a5138226c9bcda130f95e14b36c083fb4e0a7457a0647f4eba2fa147fd3bf5` |
| Family label | `unknown` |
| File name | `kworkerd-softirq` |
| File type | `elf` |
| First seen | `2026-06-21 15:37:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f8ef8ab36e030e2d9f18f09cc8a1263` |
| SHA-1 | `97bc1d26e325fae7e62b2c33bbbb26db1384f74b` |
| SHA-256 | `05a5138226c9bcda130f95e14b36c083fb4e0a7457a0647f4eba2fa147fd3bf5` |
| SHA3-384 | `38495a5bc8e886589caa26704167dc42c258cc35b0dbe43931d05152f86c67086fdf2695ed8911d3b4af99bdea73f6bc` |
| TLSH | `T19CA312A5E6D95E66E870207EED5940167BDF23BDF839B103290958DCEE327C4732C621` |
| SSDEEP | `1536:0B7rDL/AOIwCkeUf8wwxSiheJ78HmYA2B6ihD8RG0sZz69Zv2sMwGMI51Oi/iJ4O:0RL/AoeL56JPOspw0QE2fJMDJSL3l69` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_05a51382
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05a5138226c9bcda130f95e14b36c083fb4e0a7457a0647f4eba2fa147fd3bf5"
    family = "unknown"
    file_name = "kworkerd-softirq"
    file_type = "elf"
    first_seen = "2026-06-21 15:37:36"
  condition:
    hash.sha256(0, filesize) == "05a5138226c9bcda130f95e14b36c083fb4e0a7457a0647f4eba2fa147fd3bf5"
}
```

### Sample 7: `0343cc89b06f7a6e`

| Field | Value |
|---|---|
| SHA-256 | `0343cc89b06f7a6e45cb7d09f0328821c826d63216265d5d0c0a22902af835d1` |
| Family label | `unknown` |
| File name | `kworkerd` |
| File type | `elf` |
| First seen | `2026-06-21 15:31:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6de57935c77fa4eec94afcdf78380be7` |
| SHA-1 | `234948b7f836fe90f02fed565f18aafd8eb9d3f1` |
| SHA-256 | `0343cc89b06f7a6e45cb7d09f0328821c826d63216265d5d0c0a22902af835d1` |
| SHA3-384 | `ab1f1bb96f8f34d75a45491e8e95068cc2ae3f0aa12e1a72c04e6cbb164fb5e709508ca8ef002007a4459a9651e64161` |
| TLSH | `T128B31222D0592B42E258AB3763722784385DF8D4A9E42F53DF3417DDF28D702A22EF61` |
| SSDEEP | `3072:rde+cNrMUXu3sC47UXIEN3Yn5qrB04HuRh3VDBPJ0kc:rdzcNHu334rq3Y5qNaXPPJ0kc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_0343cc89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0343cc89b06f7a6e45cb7d09f0328821c826d63216265d5d0c0a22902af835d1"
    family = "unknown"
    file_name = "kworkerd"
    file_type = "elf"
    first_seen = "2026-06-21 15:31:37"
  condition:
    hash.sha256(0, filesize) == "0343cc89b06f7a6e45cb7d09f0328821c826d63216265d5d0c0a22902af835d1"
}
```

### Sample 8: `ea2b1c6fa88da27a`

| Field | Value |
|---|---|
| SHA-256 | `ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b` |
| Family label | `unknown` |
| File name | `init.sh` |
| File type | `sh` |
| First seen | `2026-06-21 15:27:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3a12d8a0dc98b06b548a766aa77dc9c` |
| SHA-1 | `adb94417d3aec78b7779161ba359ce18816a3e09` |
| SHA-256 | `ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b` |
| SHA3-384 | `b4c6acdc4f9402a61299252696b4421c5d152614da514ba6016d029cd584375717b1a817e29704dcb5043bfe201c6be7` |
| TLSH | `T15C529651ED26A270256D80F5BACB2501F50F412B460C7A05B1AFA254BF3CFAC61FD7BA` |
| SSDEEP | `192:5VtWxos/MbhrlqT8/2hEPVmhxZPKgjlhtOtHDmh5RDKlE3As+SU8x0PNIZXG8/Pm:dTlkES1LURYRQEw3FNnVUA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_ea2b1c6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b"
    family = "unknown"
    file_name = "init.sh"
    file_type = "sh"
    first_seen = "2026-06-21 15:27:42"
  condition:
    hash.sha256(0, filesize) == "ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b"
}
```

### Sample 9: `6e0593be7fe7b6a0`

| Field | Value |
|---|---|
| SHA-256 | `6e0593be7fe7b6a0789e78610de47a3c76c49bf39e66feaeb6c3169390bc1b91` |
| Family label | `unknown` |
| File name | `kworkerd-blkcg` |
| File type | `elf` |
| First seen | `2026-06-21 15:24:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf16a82b969204392cc11eb249da57c1` |
| SHA-1 | `b46720fa28a0d70cbc6bd9746f61b34d35dc2f58` |
| SHA-256 | `6e0593be7fe7b6a0789e78610de47a3c76c49bf39e66feaeb6c3169390bc1b91` |
| SHA3-384 | `4c2de1a88764b3f06030ec714734c9044a721a3cb92391e19a3d13649777d27cd9fc2ae9d8ab9571070a94c8076e8744` |
| TLSH | `T1023418A5BC40DB62C6D427BAFB5D829933134F74C3DE3506CC241F2976EA55F0A3A682` |
| SSDEEP | `6144:EiLiCwf8+wOqoGq0e7s8aMJBD77ZdqXpLSkkOM:9LiCwfvGq0ejJB7ZQ1M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_6e0593be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e0593be7fe7b6a0789e78610de47a3c76c49bf39e66feaeb6c3169390bc1b91"
    family = "unknown"
    file_name = "kworkerd-blkcg"
    file_type = "elf"
    first_seen = "2026-06-21 15:24:36"
  condition:
    hash.sha256(0, filesize) == "6e0593be7fe7b6a0789e78610de47a3c76c49bf39e66feaeb6c3169390bc1b91"
}
```

### Sample 10: `112035d781a0b726`

| Field | Value |
|---|---|
| SHA-256 | `112035d781a0b726569febbff97ded6401462c91b153e31e5bec7386dab34ff0` |
| Family label | `unknown` |
| File name | `kworkerd-blkcg` |
| File type | `elf` |
| First seen | `2026-06-21 15:23:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50d7740df6a12a658b93fce277b3ab85` |
| SHA-1 | `d3386b5d9a18588d733b91bded1e1a50433d687a` |
| SHA-256 | `112035d781a0b726569febbff97ded6401462c91b153e31e5bec7386dab34ff0` |
| SHA3-384 | `18724d1dd114f896409e831ce999a398678db8c80a65152940910922441d674ff1467ae9dbacaf2ae2848e87d25fcfea` |
| TLSH | `T196A312A5E6D95E26E870207EED5940267BDF23BDF879A1032A0958D8EE327C4732C611` |
| SSDEEP | `1536:0B7rDL/AOIwCkeUf8wwxSiheJ78HmYA2B6ihD8RG0sZz69Zv2sMwGMI51Oi/iJ4S:0RL/AoeL56JPOspw0QE2fJMDJSL3l6x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_112035d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "112035d781a0b726569febbff97ded6401462c91b153e31e5bec7386dab34ff0"
    family = "unknown"
    file_name = "kworkerd-blkcg"
    file_type = "elf"
    first_seen = "2026-06-21 15:23:36"
  condition:
    hash.sha256(0, filesize) == "112035d781a0b726569febbff97ded6401462c91b153e31e5bec7386dab34ff0"
}
```

### Sample 11: `74f5df72efa6a4e3`

| Field | Value |
|---|---|
| SHA-256 | `74f5df72efa6a4e3e19363f5aa04a2ffb37d86499df7055d1414953ea684f618` |
| Family label | `unknown` |
| File name | `kworkerd-writeback` |
| File type | `elf` |
| First seen | `2026-06-21 15:20:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3c4bfe9e60d96744898f7216ac961e2` |
| SHA-1 | `73af120035b14b35ac432d56199b2ea4a71db88b` |
| SHA-256 | `74f5df72efa6a4e3e19363f5aa04a2ffb37d86499df7055d1414953ea684f618` |
| SHA3-384 | `242fc7a70a17ea02f3b7fe23d0288dd9f3b006bd602cebaf7a7ad85b973d4b78c19cd9e53f4658cf1915312bb272f3c8` |
| TLSH | `T1D4645B02FF441E13C5411FB05D7B07B6E3AD48926CA9E13D9E0A7F2506B28B9A5CF789` |
| SSDEEP | `6144:SSAkbkVI06XG3d7NrJrV2GaCeh13f6JJN2sukGO4YbCFiGJOlcBX:Q1aCKGf0FlAlc5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_74f5df72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f5df72efa6a4e3e19363f5aa04a2ffb37d86499df7055d1414953ea684f618"
    family = "unknown"
    file_name = "kworkerd-writeback"
    file_type = "elf"
    first_seen = "2026-06-21 15:20:51"
  condition:
    hash.sha256(0, filesize) == "74f5df72efa6a4e3e19363f5aa04a2ffb37d86499df7055d1414953ea684f618"
}
```

### Sample 12: `b98d8b8f4e73e553`

| Field | Value |
|---|---|
| SHA-256 | `b98d8b8f4e73e553bd42bd8afd12d6afc1e5ff38a651f1e6fc3d1186d142a8ef` |
| Family label | `unknown` |
| File name | `kworkerd-writeback` |
| File type | `elf` |
| First seen | `2026-06-21 15:19:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5602173a4b3571d1723a2fb3e066c1dd` |
| SHA-1 | `69520de691eb1dff454c8139edb69a87807a612b` |
| SHA-256 | `b98d8b8f4e73e553bd42bd8afd12d6afc1e5ff38a651f1e6fc3d1186d142a8ef` |
| SHA3-384 | `c28fbf3900019db1d8fecc82c3a79ec8881f64f4257c1c44399209ce020252900f4ccf97dc25f80b0f9fba164c07d7de` |
| TLSH | `T1F9B31223C3685651F4D77D72E12D87A116E19A1EB442FDD9E268AE311D2FC81C0B38EC` |
| SSDEEP | `3072:nykkdgciUVeeuk6i82/NYVH0TDkd2BtxcKP+O7W4u+qgwV4u:ny/VeeRbFXMdWJ+Oy3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_b98d8b8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98d8b8f4e73e553bd42bd8afd12d6afc1e5ff38a651f1e6fc3d1186d142a8ef"
    family = "unknown"
    file_name = "kworkerd-writeback"
    file_type = "elf"
    first_seen = "2026-06-21 15:19:33"
  condition:
    hash.sha256(0, filesize) == "b98d8b8f4e73e553bd42bd8afd12d6afc1e5ff38a651f1e6fc3d1186d142a8ef"
}
```

### Sample 13: `a7990b9026200d4d`

| Field | Value |
|---|---|
| SHA-256 | `a7990b9026200d4d350e6e15750545cd3bb64b52965810807fd1b30bd87c6582` |
| Family label | `unknown` |
| File name | `kworkerd-netns` |
| File type | `elf` |
| First seen | `2026-06-21 15:15:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33e6d5006e096f18b3a368497a7cd67f` |
| SHA-1 | `d33d4498eca17834eafb15d97920ad6ecec6a618` |
| SHA-256 | `a7990b9026200d4d350e6e15750545cd3bb64b52965810807fd1b30bd87c6582` |
| SHA3-384 | `57b944209b4c27884bd2ac9f10652cc087f49289fc77bc30a6dc556175634b35e1719d8e05eabd94b5ac9a8104a95ab4` |
| TLSH | `T13374194AB7618FE4E378C13006F74BA6A6FE216616E254C6D33CED107A9434CA85FF94` |
| TELFHASH | `t16c41c988b43649bb7db65514cc151636d646f615f8b28f10ef1cc9814a2882a6949f8f` |
| SSDEEP | `6144:XtSku3vTxqi+5vasgeD+r5UenFcJ4CimRn2jC6IOTQPRuMcBYz:XtSniae7YRoNS2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_a7990b90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7990b9026200d4d350e6e15750545cd3bb64b52965810807fd1b30bd87c6582"
    family = "unknown"
    file_name = "kworkerd-netns"
    file_type = "elf"
    first_seen = "2026-06-21 15:15:55"
  condition:
    hash.sha256(0, filesize) == "a7990b9026200d4d350e6e15750545cd3bb64b52965810807fd1b30bd87c6582"
}
```

### Sample 14: `9349110551754e71`

| Field | Value |
|---|---|
| SHA-256 | `9349110551754e719b9eaeabc2b692cac6316e032ccb4dce4931ebfb6e291fbb` |
| Family label | `unknown` |
| File name | `kworkerd-netns` |
| File type | `elf` |
| First seen | `2026-06-21 15:15:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2d9e91763d93514284c5b72fcf5e85c` |
| SHA-1 | `bbd0e2ca195b72d50e982e9534b5e82241c6730e` |
| SHA-256 | `9349110551754e719b9eaeabc2b692cac6316e032ccb4dce4931ebfb6e291fbb` |
| SHA3-384 | `5470df67cb2394920c25c14e18a404cf7b19d5aa1b3d1dbfb8f502922be1d1a4fbe8840fe90469ba64ea0f0550c3bc52` |
| TLSH | `T16ED3129F290686FED926683A823177E8DF10093FD191BF54120BDBF6D4D508AFE47852` |
| SSDEEP | `3072:enfpWLk2Unh2ywuN0aVXe7x6EsFl/on9ihyddCI7Vq:enfpx2QtwuN0AX0b0W9Rdtpq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_93491105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9349110551754e719b9eaeabc2b692cac6316e032ccb4dce4931ebfb6e291fbb"
    family = "unknown"
    file_name = "kworkerd-netns"
    file_type = "elf"
    first_seen = "2026-06-21 15:15:37"
  condition:
    hash.sha256(0, filesize) == "9349110551754e719b9eaeabc2b692cac6316e032ccb4dce4931ebfb6e291fbb"
}
```

### Sample 15: `ab4f3bb1a973fb8e`

| Field | Value |
|---|---|
| SHA-256 | `ab4f3bb1a973fb8ed6eacfad3e0065b3bf541054cd680031948d43fcf8c84667` |
| Family label | `unknown` |
| File name | `kworkerd-irq` |
| File type | `elf` |
| First seen | `2026-06-21 15:05:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da91011a9d9504e6ffdc625158591e4e` |
| SHA-1 | `1df4f82465766103d73449123178ea829f8c1280` |
| SHA-256 | `ab4f3bb1a973fb8ed6eacfad3e0065b3bf541054cd680031948d43fcf8c84667` |
| SHA3-384 | `8aa90050ea089164cee0458d8e544f126c132e3a09b3923d965a9611051daf925580c0f267dd02bb53666d944c646cb2` |
| TLSH | `T15BA31252BD4DDC14D4902D726E4FA70C02A1AEF8E22D3E196A07E7307ADCD196974ABC` |
| SSDEEP | `3072:fq7F1/ZsLvWqXlPkcKRdXw3RXGzRmoy6z0OzYJdzu:fqp1CLvWqXlccKbXw35Mmm0OzYi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_ab4f3bb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab4f3bb1a973fb8ed6eacfad3e0065b3bf541054cd680031948d43fcf8c84667"
    family = "unknown"
    file_name = "kworkerd-irq"
    file_type = "elf"
    first_seen = "2026-06-21 15:05:35"
  condition:
    hash.sha256(0, filesize) == "ab4f3bb1a973fb8ed6eacfad3e0065b3bf541054cd680031948d43fcf8c84667"
}
```

### Sample 16: `d3bb5688c6e76be8`

| Field | Value |
|---|---|
| SHA-256 | `d3bb5688c6e76be8d010f8ed02ad374b5a03ea7d130f035d32abd4fb6a9bad72` |
| Family label | `unknown` |
| File name | `kworkerd-events` |
| File type | `elf` |
| First seen | `2026-06-21 15:03:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `343b787242cb0665446b7cb799f95eb2` |
| SHA-1 | `d3f5b54eff1bd919ff8a0f9302654f60b3e93397` |
| SHA-256 | `d3bb5688c6e76be8d010f8ed02ad374b5a03ea7d130f035d32abd4fb6a9bad72` |
| SHA3-384 | `ac0c2fc6ccb3373901a25e04bea483f37f7c25f72de3351f5652996d4d290d515d713346ae805e368de6742d949ba297` |
| TLSH | `T171345B06F652E4F0F5A61931028EC37A5A70ED344162D997FF4B3EB0EC75606AE1A72C` |
| SSDEEP | `6144:pBUz1Bz+/uL1uJfjXQ6WB/QNSOF6ZQFN2H0sUOzROw/MjR:+1Z4uL1afjXcBqBF60gH/BzROnR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_d3bb5688
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3bb5688c6e76be8d010f8ed02ad374b5a03ea7d130f035d32abd4fb6a9bad72"
    family = "unknown"
    file_name = "kworkerd-events"
    file_type = "elf"
    first_seen = "2026-06-21 15:03:35"
  condition:
    hash.sha256(0, filesize) == "d3bb5688c6e76be8d010f8ed02ad374b5a03ea7d130f035d32abd4fb6a9bad72"
}
```

### Sample 17: `e2aa280211036f68`

| Field | Value |
|---|---|
| SHA-256 | `e2aa280211036f684810d543f375c0d936316411ae4f6c4347baf7527ac3dd31` |
| Family label | `unknown` |
| File name | `kworkerd-rcu` |
| File type | `elf` |
| First seen | `2026-06-21 14:50:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e7a86a011111da09296728cacf35f52` |
| SHA-1 | `4a3d0593aa3ab543c0824d8c894331640ba09733` |
| SHA-256 | `e2aa280211036f684810d543f375c0d936316411ae4f6c4347baf7527ac3dd31` |
| SHA3-384 | `40f215a631ab1905a2c26de56298a036374938e03bee22e3267eadc73a044e0f8d8297a29c7e1ac1adb6592a1efb3e6e` |
| TLSH | `T1F9745B4ADF750FBFC5AECE3052AE022715DE885E92F6673761BCCD08B19A60446E3C58` |
| TELFHASH | `t16c41c988b43649bb7db65514cc151636d646f615f8b28f10ef1cc9814a2882a6949f8f` |
| SSDEEP | `6144:4SNOZd9ZlBAEHbHGkSogA1iMvDEOBssxZS9H09GZhuLHuGyM4KJ:4SefBTG3agMvqj09G/mHZ75J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_e2aa2802
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2aa280211036f684810d543f375c0d936316411ae4f6c4347baf7527ac3dd31"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-06-21 14:50:54"
  condition:
    hash.sha256(0, filesize) == "e2aa280211036f684810d543f375c0d936316411ae4f6c4347baf7527ac3dd31"
}
```

### Sample 18: `5c72bdfe8c816a15`

| Field | Value |
|---|---|
| SHA-256 | `5c72bdfe8c816a153926f00cb2c34c21352570e00a43df9e0fab939cd5a3889b` |
| Family label | `unknown` |
| File name | `kworkerd-rcu` |
| File type | `elf` |
| First seen | `2026-06-21 14:49:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0ab61f53c129c7bf71fd5d691c8556d` |
| SHA-1 | `8f677ecc4912730be9fe34496fe9d3154ed4b733` |
| SHA-256 | `5c72bdfe8c816a153926f00cb2c34c21352570e00a43df9e0fab939cd5a3889b` |
| SHA3-384 | `c73d20d7d4196ee4396f0ab06c0793a970cb57f3ac2fc648898433e74dc18f6bb0bb13867db59c2fece43d5527b312a6` |
| TLSH | `T1D4D313452162FDC9F9AF477824BD3192E4123A80F5DA2D8DFB213ECA8595C09B34D36E` |
| SSDEEP | `3072:gDu53z5rFnQHDYPWdKZDmETWKxcTN0LZqO0SDrg:553z5ajOFYEivN0TDrg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_5c72bdfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c72bdfe8c816a153926f00cb2c34c21352570e00a43df9e0fab939cd5a3889b"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-06-21 14:49:36"
  condition:
    hash.sha256(0, filesize) == "5c72bdfe8c816a153926f00cb2c34c21352570e00a43df9e0fab939cd5a3889b"
}
```

### Sample 19: `c7709ac88c8be581`

| Field | Value |
|---|---|
| SHA-256 | `c7709ac88c8be581a74510700227c2783acd350780b2e626946ea88d10bf3e73` |
| Family label | `unknown` |
| File name | `kworkerd-irq-bal` |
| File type | `elf` |
| First seen | `2026-06-21 14:48:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c55b34c253384691890c935ef3f56482` |
| SHA-1 | `5f64ad116d16c0d914ac470fcae830ac38e0a38f` |
| SHA-256 | `c7709ac88c8be581a74510700227c2783acd350780b2e626946ea88d10bf3e73` |
| SHA3-384 | `dd0edd790b40d29e455b12e763b153c17c0689a8ac4b08490b7ed6f080c2d07126ed5d3361d7176b4efaa75be96a8342` |
| TLSH | `T15C342AA9BC40DB66C6E427BAFB4D429933134F74C3DD3106CD245F2976EB55B0A3A282` |
| SSDEEP | `6144:/zURh8D86Uj6nhCOArXJ6GfoJ8449U8kz24zp7UOM:YX8Izj6nhCOArXJn4+k7tM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_c7709ac8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7709ac88c8be581a74510700227c2783acd350780b2e626946ea88d10bf3e73"
    family = "unknown"
    file_name = "kworkerd-irq-bal"
    file_type = "elf"
    first_seen = "2026-06-21 14:48:35"
  condition:
    hash.sha256(0, filesize) == "c7709ac88c8be581a74510700227c2783acd350780b2e626946ea88d10bf3e73"
}
```

### Sample 20: `745b2d3cd229fe21`

| Field | Value |
|---|---|
| SHA-256 | `745b2d3cd229fe218a8869e80100fe60c16ecc788c68a6d093a86291c63ac0cd` |
| Family label | `unknown` |
| File name | `kworkerd-irq-bal` |
| File type | `elf` |
| First seen | `2026-06-21 14:47:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eda8b66cfe7971b27e97921928a1793d` |
| SHA-1 | `c8efb24eae4cd482886f0c81e1ad110647a44de7` |
| SHA-256 | `745b2d3cd229fe218a8869e80100fe60c16ecc788c68a6d093a86291c63ac0cd` |
| SHA3-384 | `32b683a4ec264dc0db1b8fefaeaf7d6db02ea3322623107874202e0bc648182d6247a07c107220e0a40b697626f79b13` |
| TLSH | `T122A302527D4DDC14D4902D726E4FA70C02A1AEF8E22D3E196A07E6307ADCD196974ABC` |
| SSDEEP | `3072:fq7F1/ZsLvWqXlPkcKRdXw3RXGzRmoy6z0OzYJdzV:fqp1CLvWqXlccKbXw35Mmm0OzYZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_745b2d3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "745b2d3cd229fe218a8869e80100fe60c16ecc788c68a6d093a86291c63ac0cd"
    family = "unknown"
    file_name = "kworkerd-irq-bal"
    file_type = "elf"
    first_seen = "2026-06-21 14:47:35"
  condition:
    hash.sha256(0, filesize) == "745b2d3cd229fe218a8869e80100fe60c16ecc788c68a6d093a86291c63ac0cd"
}
```

### Sample 21: `8985fe09d5b08240`

| Field | Value |
|---|---|
| SHA-256 | `8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9` |
| Family label | `Mirai` |
| File name | `giga.sh` |
| File type | `sh` |
| First seen | `2026-06-21 14:45:34` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41b45aefd3f0a8e04abe7fd3a632ed94` |
| SHA-1 | `d0eddc89079aeac09b7894ddfbf41275d7189848` |
| SHA-256 | `8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9` |
| SHA3-384 | `7e248850f5a460bc68bb9685c2d275ce0c12abd437fd94b4392ae8132cfc38adc2c8c74ed6bb6d6dd181197507331a22` |
| TLSH | `T103E065A9B82538A24514FE34F4328615E15BFB81222DA318B2CD363A8CDC600753CEC6` |
| SSDEEP | `12:lRphviR9hviRAYNkhviR60LKDhviR1OhviRWH:rptQtbYWtoKDt8OtjH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_8985fe09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9"
    family = "Mirai"
    file_name = "giga.sh"
    file_type = "sh"
    first_seen = "2026-06-21 14:45:34"
  condition:
    hash.sha256(0, filesize) == "8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9"
}
```

### Sample 22: `e3c75454d745d76a`

| Field | Value |
|---|---|
| SHA-256 | `e3c75454d745d76a0e155891e294a02284a0fc2835acf44c68428ad5d6c2e0d3` |
| Family label | `unknown` |
| File name | `kworkerd-scsi` |
| File type | `elf` |
| First seen | `2026-06-21 14:39:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5c45f0582fdf1f46a500ff9a2fe6093` |
| SHA-1 | `a4776025946768c85223c551312eb073f23c9a76` |
| SHA-256 | `e3c75454d745d76a0e155891e294a02284a0fc2835acf44c68428ad5d6c2e0d3` |
| SHA3-384 | `7f68d83915597ab8739e2ba3aa30abb37782421d2c1d984924aae5f9a7be01417de6e3ba86ca6b2be52ea9b8d6aa1988` |
| TLSH | `T1DD344A81318C7EAEE2A72D3EC141A51B6C0CCF14B886DD2241F9FA471ABB5D71F3A145` |
| TELFHASH | `t10dc02b60243bd0298c05a509054a25cb34c74adb4b4d320600ac880401007274120138` |
| SSDEEP | `6144:sLSDfUAw2VJHbmJcOKeAQM93/gvkiPrVOoEh:5DfUxEJJ6kiPAXh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_e3c75454
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3c75454d745d76a0e155891e294a02284a0fc2835acf44c68428ad5d6c2e0d3"
    family = "unknown"
    file_name = "kworkerd-scsi"
    file_type = "elf"
    first_seen = "2026-06-21 14:39:35"
  condition:
    hash.sha256(0, filesize) == "e3c75454d745d76a0e155891e294a02284a0fc2835acf44c68428ad5d6c2e0d3"
}
```

### Sample 23: `d12cb562e6401d1d`

| Field | Value |
|---|---|
| SHA-256 | `d12cb562e6401d1d27ed0f880c659ecbfad84bc79d14e8866ca8d98ff601b36d` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-06-21 14:39:34` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e75c7490f9d9b2cfd9653d6876bb4806` |
| SHA-1 | `91eead808bdd29b83ebb2cce4213ec304a722e77` |
| SHA-256 | `d12cb562e6401d1d27ed0f880c659ecbfad84bc79d14e8866ca8d98ff601b36d` |
| SHA3-384 | `eb0231ca8ba479a936aa107f43c36b4706e79581b1eceb159c2ccced8cafbede325327d72b7b99f0cdb36fee65347f4f` |
| TLSH | `T12931929F90151A391203CADD73B3355CB20C85EB284BD798EC485EAE93892DCB1A9FC4` |
| SSDEEP | `24:sLPGr0o0ogZmC3GgG5wJ5+kI3niFEEyjx5mhPP:sLPGrppmGgG5wJ5+h3ni6x4hPP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_d12cb562
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d12cb562e6401d1d27ed0f880c659ecbfad84bc79d14e8866ca8d98ff601b36d"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-21 14:39:34"
  condition:
    hash.sha256(0, filesize) == "d12cb562e6401d1d27ed0f880c659ecbfad84bc79d14e8866ca8d98ff601b36d"
}
```

### Sample 24: `a28022c27f376c46`

| Field | Value |
|---|---|
| SHA-256 | `a28022c27f376c469740569538d1ae3c0837fe952383d0bd2cf5b8f304153f72` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-21 14:28:13` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37a929114a66aca686d48570c8210ee4` |
| SHA-1 | `fe42f6b4c71001ede052bcca8d8df0f0981cb825` |
| SHA-256 | `a28022c27f376c469740569538d1ae3c0837fe952383d0bd2cf5b8f304153f72` |
| SHA3-384 | `1f66172420e681d69ad70a0d5a5df968dcefa21d160a06fc4b335af867d1b73ed85e6add8efa1fd5a789e877b2343f09` |
| IMPHASH | `646167cce332c1c252cdcb1839e0cf48` |
| TLSH | `T15385234363E90061E9312FF018BA49836635BD926DB1872B27E4398E6D725C2FD7136F` |
| SSDEEP | `24576:iarluhWyYWhCG/I5Yu3rHWnY7xtMVofSBKI7tbb79ByzmoJsyDRG1qpZf/32Wxxj:xuhWypGR7HWnVoKcI7PBdP6H3DP8iEm` |
| ICON-DHASH | `0f0f4df0b04d2f0f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_a28022c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a28022c27f376c469740569538d1ae3c0837fe952383d0bd2cf5b8f304153f72"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 14:28:13"
  condition:
    hash.sha256(0, filesize) == "a28022c27f376c469740569538d1ae3c0837fe952383d0bd2cf5b8f304153f72"
}
```

### Sample 25: `76771c0cfe10218f`

| Field | Value |
|---|---|
| SHA-256 | `76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50` |
| Family label | `unknown` |
| File name | `RFQ-MRF-889-MHS-TLQ-520 # 2600260001.js` |
| File type | `js` |
| First seen | `2026-06-21 14:12:30` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0fde1288ef288731aef0855b08be049a` |
| SHA-1 | `827749fd69bc733ab31a00d2376f5fcdcf58968d` |
| SHA-256 | `76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50` |
| SHA3-384 | `c48a9387ba8b13c67b0478e7e6d5477fd9506c30de49272c617816b39c1c89f42a1742824e8036b5434de3417fb43f6b` |
| TLSH | `T1A8863734C5ACE41AF6FAF4FA5F865300DF318ED45A2CE40A37C6930EA409959D9EB24D` |
| SSDEEP | `3072:m8MLTZMDDcC2nyrQEyRd6osa/YhAYkb+SE88HQwzounh2w4mix8EoRsrRAc2xJZ1:E44C2GuR4kgC96RReKBsjoDWuinC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_76771c0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50"
    family = "unknown"
    file_name = "RFQ-MRF-889-MHS-TLQ-520 # 2600260001.js"
    file_type = "js"
    first_seen = "2026-06-21 14:12:30"
  condition:
    hash.sha256(0, filesize) == "76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50"
}
```

### Sample 26: `53cdbce7ef4a4978`

| Field | Value |
|---|---|
| SHA-256 | `53cdbce7ef4a497839babe6574569cf65a46ab2b204c0eef3350dfa50cb4a3e0` |
| Family label | `unknown` |
| File name | `CapCut-Template-Pro.exe` |
| File type | `exe` |
| First seen | `2026-06-21 14:11:49` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79a8a09790eb9eef3e9620b596788089` |
| SHA-1 | `bb5402bbd2e883175f96c3729aa5662e47b3f14e` |
| SHA-256 | `53cdbce7ef4a497839babe6574569cf65a46ab2b204c0eef3350dfa50cb4a3e0` |
| SHA3-384 | `21b15c0907377a2dd3d8daf3b4586a0514726de0780391e99c0bc28427afad58524f3f8c12bd8079dc1e6af53c82a352` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T10D08332CCAFAB69FED3E5CF811709632FA3964692D1C34D7ABF868617133009057D58A` |
| SSDEEP | `1572864:Nt9IKP0SdMP6YtIheTqowzKYypCPRfYLgRLlPBnU6InslA2GAd7:NUK8SeP6YtCoyKYyuB/5PU6InsDGAd7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_53cdbce7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53cdbce7ef4a497839babe6574569cf65a46ab2b204c0eef3350dfa50cb4a3e0"
    family = "unknown"
    file_name = "CapCut-Template-Pro.exe"
    file_type = "exe"
    first_seen = "2026-06-21 14:11:49"
  condition:
    hash.sha256(0, filesize) == "53cdbce7ef4a497839babe6574569cf65a46ab2b204c0eef3350dfa50cb4a3e0"
}
```

### Sample 27: `0b3581ab2acd2099`

| Field | Value |
|---|---|
| SHA-256 | `0b3581ab2acd2099ec8d7de4f77608a0e9a1b7b4810009c7eb1cc4007d30d487` |
| Family label | `SilentNet` |
| File name | `Sulur client.exe` |
| File type | `exe` |
| First seen | `2026-06-21 13:41:10` |
| Reporter | `nanoave` |
| Tags | `exe, SilentNet, XMRIG` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `252fe77945fba9b1426dd4ec923dd8eb` |
| SHA-1 | `cb599fcb6ada4fc6143e9eccfdeaee1e5911a972` |
| SHA-256 | `0b3581ab2acd2099ec8d7de4f77608a0e9a1b7b4810009c7eb1cc4007d30d487` |
| SHA3-384 | `4188cb0c2cc5229969638cd6bd24a685092e5eaec8665b8296efb123cf288b9b8e31ce64601da85553408f62ef2245bc` |
| IMPHASH | `73f461c771aef77ec43d53a0c54f0c8d` |
| TLSH | `T188357C83EBA385D8C156C8B5534FF137F9627C8E4A157196ABC41E633E67B64E22CB00` |
| SSDEEP | `12288:aZ+OE4MmD6/Oyspc5EEBBBHGBgzGerwGcvPqItNquB:acb4M06WpoPrwHvP3f5` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_027_0b3581ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b3581ab2acd2099ec8d7de4f77608a0e9a1b7b4810009c7eb1cc4007d30d487"
    family = "SilentNet"
    file_name = "Sulur client.exe"
    file_type = "exe"
    first_seen = "2026-06-21 13:41:10"
  condition:
    hash.sha256(0, filesize) == "0b3581ab2acd2099ec8d7de4f77608a0e9a1b7b4810009c7eb1cc4007d30d487"
}
```

### Sample 28: `4374049d24a766ea`

| Field | Value |
|---|---|
| SHA-256 | `4374049d24a766eac84cdd1995bbd236d14956a11123de0402a8cd4669aa0be0` |
| Family label | `unknown` |
| File name | `RFQ#PO - PO25-08-888.vbs` |
| File type | `vbs` |
| First seen | `2026-06-21 13:02:31` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c50f07c5da5e6dc8d165c5e98719a763` |
| SHA-1 | `a9746611bca26ba53c61ea3cf15f2775868789a4` |
| SHA-256 | `4374049d24a766eac84cdd1995bbd236d14956a11123de0402a8cd4669aa0be0` |
| SHA3-384 | `79ec37defa3ed8fd066b639633ad5ccdbcc2561ebd115a46f89e09896a08b66b4b532c693d5f300560f42c0da79b3259` |
| TLSH | `T11B853A38ADFA002B71B3EE998AD475D6EA5FB6733B1E6429109303CA4713941EDC163D` |
| SSDEEP | `24576:9nS3wQRgzoQnQ0/JiV8wLnDFoxItVzhAFBKcJHuJS8:y3V5o0Vov+S8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_4374049d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4374049d24a766eac84cdd1995bbd236d14956a11123de0402a8cd4669aa0be0"
    family = "unknown"
    file_name = "RFQ#PO - PO25-08-888.vbs"
    file_type = "vbs"
    first_seen = "2026-06-21 13:02:31"
  condition:
    hash.sha256(0, filesize) == "4374049d24a766eac84cdd1995bbd236d14956a11123de0402a8cd4669aa0be0"
}
```

### Sample 29: `54a62444672de4d1`

| Field | Value |
|---|---|
| SHA-256 | `54a62444672de4d11e9a3ebd67289f1afc4401d7f7631ac02e404c7d0ca257ca` |
| Family label | `SilentNet` |
| File name | `meteor-client-1.21.11-82.jar` |
| File type | `jar` |
| First seen | `2026-06-21 12:12:24` |
| Reporter | `burger403` |
| Tags | `jar, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `868065ae9448e3d2e6a1af009101795a` |
| SHA-1 | `ae0cbd55f27128e1de36690f0a5d385d4deb18a0` |
| SHA-256 | `54a62444672de4d11e9a3ebd67289f1afc4401d7f7631ac02e404c7d0ca257ca` |
| SHA3-384 | `74005ff208898876f3e80b817f6985ba000a6e25865a8ce1ed9a3d620ca7dae745f6a2298ec12d91b13b7dec62e8b5bc` |
| TLSH | `T1AD661221DA5D003AF833FB339082B9E174FBEF91520BF06A3A7D154D4855A838B7E956` |
| SSDEEP | `196608:uyqbondS2mGwoqTJ0FgMgNz7H5wDod6cCtr:u/ondoLoKzBziDsQr` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_029_54a62444
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54a62444672de4d11e9a3ebd67289f1afc4401d7f7631ac02e404c7d0ca257ca"
    family = "SilentNet"
    file_name = "meteor-client-1.21.11-82.jar"
    file_type = "jar"
    first_seen = "2026-06-21 12:12:24"
  condition:
    hash.sha256(0, filesize) == "54a62444672de4d11e9a3ebd67289f1afc4401d7f7631ac02e404c7d0ca257ca"
}
```

### Sample 30: `10d1620dbbb762a9`

| Field | Value |
|---|---|
| SHA-256 | `10d1620dbbb762a94bea71602b7f6d3a3167bf5f4e1cd7f3ab49aeac74c2a573` |
| Family label | `unknown` |
| File name | `DonutDupe.jar` |
| File type | `jar` |
| First seen | `2026-06-21 12:05:39` |
| Reporter | `burger403` |
| Tags | `jar, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8f5b51ecf230e52c3bd7bf4a30c59f0` |
| SHA-1 | `c08a7d452c22abb14f824d238582b607804d2546` |
| SHA-256 | `10d1620dbbb762a94bea71602b7f6d3a3167bf5f4e1cd7f3ab49aeac74c2a573` |
| SHA3-384 | `d6529c8aa153f7d768707986e075d2edc23e456df542d337e2d0e0ac40537bd38a3e59f151d13e653fb128ae7d5c135b` |
| TLSH | `T153063329BEB84939FCA05969CE44DD3723C068785D22435C2F1A7FC3D48D58A8DF972A` |
| SSDEEP | `98304:C6xnC7pdVku1Idc4Kh3SSOUqy+gIkikgo:wfVkuIWVhSbUqyokizo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_10d1620d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10d1620dbbb762a94bea71602b7f6d3a3167bf5f4e1cd7f3ab49aeac74c2a573"
    family = "unknown"
    file_name = "DonutDupe.jar"
    file_type = "jar"
    first_seen = "2026-06-21 12:05:39"
  condition:
    hash.sha256(0, filesize) == "10d1620dbbb762a94bea71602b7f6d3a3167bf5f4e1cd7f3ab49aeac74c2a573"
}
```

### Sample 31: `e5ca458678572893`

| Field | Value |
|---|---|
| SHA-256 | `e5ca4586785728938cb9de0e964a35bd36dfa534bd7bf47f2438af4a4c2103c2` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-21 12:04:11` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e2398c39af420f21172d898548c7570` |
| SHA-1 | `11f5c65ef619abba958fe56d33006250f5e6c0e0` |
| SHA-256 | `e5ca4586785728938cb9de0e964a35bd36dfa534bd7bf47f2438af4a4c2103c2` |
| SHA3-384 | `207699ef9ae43088ea65e14088dbb407e3f860621e2e606d9668b7faad42d5da7fff9a965c652639f3abfccc2ed10499` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1EFF57C03AD950DE9C099A33188B39691B779BC446B3127D33E907B782F72BD05D3A768` |
| SSDEEP | `49152:pgSACnsRSJVA/IpMNT1tMyWvinZZIJBGucWLbXZV0b:pbYKUTXMyWvinGB+W3Xob` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_031_e5ca4586
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5ca4586785728938cb9de0e964a35bd36dfa534bd7bf47f2438af4a4c2103c2"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 12:04:11"
  condition:
    hash.sha256(0, filesize) == "e5ca4586785728938cb9de0e964a35bd36dfa534bd7bf47f2438af4a4c2103c2"
}
```

### Sample 32: `bfaa02a0548850af`

| Field | Value |
|---|---|
| SHA-256 | `bfaa02a0548850aff68591dfaf8934ceb855aaac67c18eb9d12e553f91de60a9` |
| Family label | `unknown` |
| File name | `mod.jar` |
| File type | `jar` |
| First seen | `2026-06-21 12:04:05` |
| Reporter | `burger403` |
| Tags | `jar, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe49dd86aaafa36d28a52527581327e8` |
| SHA-1 | `c2ae660416ca8221abad82cd30bcc5e1d5ddc147` |
| SHA-256 | `bfaa02a0548850aff68591dfaf8934ceb855aaac67c18eb9d12e553f91de60a9` |
| SHA3-384 | `aed40ca22c349427a450c1cd918fe92dc7211e26fc6253ba01cd259ac96a3010c4b30db08e9c8881ba0face4ec1982d7` |
| TLSH | `T13826339CC489258ECD2644BEBBE91ED663DF87514BB0A8C3BE93C24ED0D104E71AED54` |
| SSDEEP | `98304:K1gjK8jL1D/eWz69ocggQHKTD51qISEmM5jVTuCPJb44ZsVBVm51IJ:KGjX/eAqTFwISYBzhb44gh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_bfaa02a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfaa02a0548850aff68591dfaf8934ceb855aaac67c18eb9d12e553f91de60a9"
    family = "unknown"
    file_name = "mod.jar"
    file_type = "jar"
    first_seen = "2026-06-21 12:04:05"
  condition:
    hash.sha256(0, filesize) == "bfaa02a0548850aff68591dfaf8934ceb855aaac67c18eb9d12e553f91de60a9"
}
```

### Sample 33: `9c5f121e984d76e4`

| Field | Value |
|---|---|
| SHA-256 | `9c5f121e984d76e479ca119499d35efe9402925a2c29b195bff88542c47b0c05` |
| Family label | `unknown` |
| File name | `Exodus.exe` |
| File type | `exe` |
| First seen | `2026-06-21 12:00:31` |
| Reporter | `burger403` |
| Tags | `exe, OverlordRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `350711ab2cb46a81b20e31eb756c073f` |
| SHA-1 | `f90d1887e54eb7c1af6f7abd3b17eee0d2e9eff7` |
| SHA-256 | `9c5f121e984d76e479ca119499d35efe9402925a2c29b195bff88542c47b0c05` |
| SHA3-384 | `4da04387d0206e26cb22d510c55f1d30d8c9f6a3b189dd6d8c8b1ed769dfd91c0d14d43dcc7bc90ebed6b41eef21f32e` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T157D6490BEC6945E8C5EED534897292527B707C494B2433D72B60F6287F36BE4AEB9340` |
| SSDEEP | `98304:C3gvJyaoH3v3dG+yZOk1n1eDpjsca6RQ/G8UseJE1Nxh:CSgaemn1eDp+Lf` |
| ICON-DHASH | `9269cccccccc6996` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_9c5f121e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c5f121e984d76e479ca119499d35efe9402925a2c29b195bff88542c47b0c05"
    family = "unknown"
    file_name = "Exodus.exe"
    file_type = "exe"
    first_seen = "2026-06-21 12:00:31"
  condition:
    hash.sha256(0, filesize) == "9c5f121e984d76e479ca119499d35efe9402925a2c29b195bff88542c47b0c05"
}
```

### Sample 34: `eb4ebe8f50e313f9`

| Field | Value |
|---|---|
| SHA-256 | `eb4ebe8f50e313f917ea49cac37dd5fe6e05dbf095e741c45938632f3bf1558e` |
| Family label | `unknown` |
| File name | `Installer.exe` |
| File type | `exe` |
| First seen | `2026-06-21 11:52:26` |
| Reporter | `alegonzriv` |
| Tags | `antivirusshield, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eeaaed8dab26729dcc2d4ea71c997668` |
| SHA-1 | `82cccffdb5139ea33c7cf907782f7936f7fbd144` |
| SHA-256 | `eb4ebe8f50e313f917ea49cac37dd5fe6e05dbf095e741c45938632f3bf1558e` |
| SHA3-384 | `eab9d680e9eff4380855e32e4aa2daee21908292f5e852d743f64883ec7a65d984c3a5691d57630eccff0e5b7dd30a28` |
| TLSH | `T19DD412507BBD872CE6BFABB45A1272427F35FB253135CE6C68CE128C19A17108660B77` |
| SSDEEP | `12288:vvnH8CdhTKv6GsA8Ef9J8DP9yRn9OIXSLen9OIXS9t:vfHD8vFVhlJsPA2ICXIC9t` |
| ICON-DHASH | `334d6933334d6933` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_eb4ebe8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb4ebe8f50e313f917ea49cac37dd5fe6e05dbf095e741c45938632f3bf1558e"
    family = "unknown"
    file_name = "Installer.exe"
    file_type = "exe"
    first_seen = "2026-06-21 11:52:26"
  condition:
    hash.sha256(0, filesize) == "eb4ebe8f50e313f917ea49cac37dd5fe6e05dbf095e741c45938632f3bf1558e"
}
```

### Sample 35: `5b5434cc8bb35560`

| Field | Value |
|---|---|
| SHA-256 | `5b5434cc8bb3556075c6967d2ffee5a6b33793de07b9d4701bc63d369de63861` |
| Family label | `AnyDesk` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-21 11:50:41` |
| Reporter | `Bitsight` |
| Tags | `54e64e, AnyDesk, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34651af99f5f8d4334fe37e2c7989e06` |
| SHA-1 | `7c0f669cd06e5ba8fdcdba107b9519fe73519368` |
| SHA-256 | `5b5434cc8bb3556075c6967d2ffee5a6b33793de07b9d4701bc63d369de63861` |
| SHA3-384 | `7948bb393031ef71e980c6722b496ad48b15143608ec43b7c5d3e37b7301e39c5d6a7a411273a29df2b9ba990cf4b093` |
| TLSH | `T14417339F11B894D4E43632B39529BF0EAE39BCE915A052CF0B064365F86E94D8D1F633` |
| SSDEEP | `393216:PX2Vw3ByMNus0YfLBc2pDic8L0KstVadqouPycSLItG/WZm/W9pcYEmV5pTs:/2VwRLNustVv8LbstU89ZFZt9ebmV5p4` |
| ICON-DHASH | `489669d8d8699648` |

#### Technical Assessment

- The sample is tracked as `AnyDesk` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AnyDesk_035_5b5434cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b5434cc8bb3556075c6967d2ffee5a6b33793de07b9d4701bc63d369de63861"
    family = "AnyDesk"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 11:50:41"
  condition:
    hash.sha256(0, filesize) == "5b5434cc8bb3556075c6967d2ffee5a6b33793de07b9d4701bc63d369de63861"
}
```

### Sample 36: `abe7da6b5be41348`

| Field | Value |
|---|---|
| SHA-256 | `abe7da6b5be41348ce74be00a5158c0fe7dc138051a84f41b1ebc5f9c49b35d6` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-06-21 10:39:32` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35425edb78f2b9cb8836385bd442fa56` |
| SHA-1 | `2f1d17e5ca6891af0f8a11491cfc9881ddfdcf0e` |
| SHA-256 | `abe7da6b5be41348ce74be00a5158c0fe7dc138051a84f41b1ebc5f9c49b35d6` |
| SHA3-384 | `53d9b884d59614a8485fb7619ba90608022816ba4c1f69c2e929c76a89f67694fc0019814e636b7489c2e97c0045f8b0` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T11C46E101B3D295B6D0BF0678D87A56696774BC058312CBBF5794B93D2E32BC08E32366` |
| SSDEEP | `98304:azIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zlT:ahfefPtHxcp9ym3nltDUJV5` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_036_abe7da6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abe7da6b5be41348ce74be00a5158c0fe7dc138051a84f41b1ebc5f9c49b35d6"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-21 10:39:32"
  condition:
    hash.sha256(0, filesize) == "abe7da6b5be41348ce74be00a5158c0fe7dc138051a84f41b1ebc5f9c49b35d6"
}
```

### Sample 37: `9d7ecd3a4aeefa44`

| Field | Value |
|---|---|
| SHA-256 | `9d7ecd3a4aeefa449a7313e98a6afab0ea28eb1f693380f2ef5a4c9fe612c5dd` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-06-21 10:39:31` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3d3fa71555ade263f753a6d543b81ab` |
| SHA-1 | `2a467b379b48b0d1a1a4616ae50763b20bd730be` |
| SHA-256 | `9d7ecd3a4aeefa449a7313e98a6afab0ea28eb1f693380f2ef5a4c9fe612c5dd` |
| SHA3-384 | `b23b194ffd6a08c564c0bf73c108c3cf88b76ca94e112f4b2d32c3da82f7231ba0c6514c393d4be193cc414c50354272` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1D7646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:amlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9r0:p1iw7gryNkSV1hy1Z1u2JLu9Q` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_037_9d7ecd3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d7ecd3a4aeefa449a7313e98a6afab0ea28eb1f693380f2ef5a4c9fe612c5dd"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-21 10:39:31"
  condition:
    hash.sha256(0, filesize) == "9d7ecd3a4aeefa449a7313e98a6afab0ea28eb1f693380f2ef5a4c9fe612c5dd"
}
```

### Sample 38: `f2b5721d0aaa1d29`

| Field | Value |
|---|---|
| SHA-256 | `f2b5721d0aaa1d2975cb5d2d8716b7b9ccec1139da2bf467080197a5aae82ae2` |
| Family label | `Mirai` |
| File name | `bot.armv6` |
| File type | `elf` |
| First seen | `2026-06-21 10:35:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf5dc662833bb1dc277fed24feb88bac` |
| SHA-1 | `04c89e4764feec065aff11ac9b629d38ffcb93e2` |
| SHA-256 | `f2b5721d0aaa1d2975cb5d2d8716b7b9ccec1139da2bf467080197a5aae82ae2` |
| SHA3-384 | `746351e6f2ebb566b0888ba332a22f6e3ab0f197969e56de1a1edb38e73a4ac9cab661296a91de2b7e6fe301db177b47` |
| TLSH | `T146B42855F8809F61C6D529B6F74D82A873074B79D3EBB2069A144B343BE786F0F3A601` |
| TELFHASH | `t103e0729b6abddfe423e1121aaa82a007914829818b11b4c2cb14b3482c03aa27de1133` |
| SSDEEP | `12288:jiKaCUdFf5VMSOei1VhLQ6metoH8L6v4q8prPx8Q:j9aCUdZM5e6vLXmeb/+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_f2b5721d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b5721d0aaa1d2975cb5d2d8716b7b9ccec1139da2bf467080197a5aae82ae2"
    family = "Mirai"
    file_name = "bot.armv6"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:53"
  condition:
    hash.sha256(0, filesize) == "f2b5721d0aaa1d2975cb5d2d8716b7b9ccec1139da2bf467080197a5aae82ae2"
}
```

### Sample 39: `70c8c4f63455ca66`

| Field | Value |
|---|---|
| SHA-256 | `70c8c4f63455ca66b3ec8113a954122a3b31267b6841c43ce163e53b5720b04a` |
| Family label | `unknown` |
| File name | `bot.mipsel` |
| File type | `elf` |
| First seen | `2026-06-21 10:35:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18ada948f636f83d3d109e7821ca0583` |
| SHA-1 | `a8ebd8d722fc5ea29b0688c098898d435e4fd427` |
| SHA-256 | `70c8c4f63455ca66b3ec8113a954122a3b31267b6841c43ce163e53b5720b04a` |
| SHA3-384 | `786f5fe2ac7b48b0cc51b2d46497aefed19439020358a9f41f11e1368d627b72d2cdf9046daf9e2747935c847761ce7b` |
| TLSH | `T131D44B02BF405EEBC0AFCD30492EC21B11DDD9D752D1A72A71FC4A9DBA6D25A0BD3588` |
| SSDEEP | `12288:3P25y9mIqJafoSDLkvSkN0fFapRGBK1Iv9Jntq7uZHTLVKoa76hgOGkxgACKrbdl:IM3rxtTXKmFv8HE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_70c8c4f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70c8c4f63455ca66b3ec8113a954122a3b31267b6841c43ce163e53b5720b04a"
    family = "unknown"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:52"
  condition:
    hash.sha256(0, filesize) == "70c8c4f63455ca66b3ec8113a954122a3b31267b6841c43ce163e53b5720b04a"
}
```

### Sample 40: `fd3b9be7ff9aad82`

| Field | Value |
|---|---|
| SHA-256 | `fd3b9be7ff9aad82baec194b849cec7478d59cdeec96e3421a372a585e79a70e` |
| Family label | `unknown` |
| File name | `bot.i386` |
| File type | `elf` |
| First seen | `2026-06-21 10:35:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ec21c5e05638b1867057e9d33f65046` |
| SHA-1 | `3a03a2f3d034007fdda7e26cf3fd8d5c1f8917fb` |
| SHA-256 | `fd3b9be7ff9aad82baec194b849cec7478d59cdeec96e3421a372a585e79a70e` |
| SHA3-384 | `8d63fc6a27effd45eea09df9c25460f2a1461588bbbbf3fa6a0d03a485c2040b1de92e9e2831f2853f4440c9a4edeff9` |
| TLSH | `T104E46D99E783D4F2F26340F1024FCBF20574A516A057FAF2EB852A5778727A22F15329` |
| TELFHASH | `t1fea1f9b629a998ecb3f04902825b72209e36e02765d035761df37550a7b3f03673ad7d` |
| SSDEEP | `12288:PuTT1KV3z0v6rTnhe6hFqrqmVGR/Hp5xNyr8VDh0dLQewkVgyv6p2R9ciaVt:U8V34ir7he6hNHpvNyIVDhWQbkCO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_fd3b9be7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd3b9be7ff9aad82baec194b849cec7478d59cdeec96e3421a372a585e79a70e"
    family = "unknown"
    file_name = "bot.i386"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:50"
  condition:
    hash.sha256(0, filesize) == "fd3b9be7ff9aad82baec194b849cec7478d59cdeec96e3421a372a585e79a70e"
}
```

### Sample 41: `e00d92ca28a2cfd7`

| Field | Value |
|---|---|
| SHA-256 | `e00d92ca28a2cfd75e96f71fc0408747f04942657fcab0f2a25ce79bc3ad23a8` |
| Family label | `unknown` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-06-21 10:35:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85e2c18dbb454c7651b76dd52259ddbd` |
| SHA-1 | `fbd618a6932d4b586b8f07f3819229e52c20ed1a` |
| SHA-256 | `e00d92ca28a2cfd75e96f71fc0408747f04942657fcab0f2a25ce79bc3ad23a8` |
| SHA3-384 | `42776b683d807865a01af81f06222dea35953e00c14216d7a3eebfff4beb5020ecffac20088a74df5a71d6c3f55cf99e` |
| TLSH | `T1DA057D5AF2B330FCC067C030835BDB62A835F46511226E7B25C4DA352DA6E711B29FB6` |
| TELFHASH | `t1448155708bfa7a74a2d7c615a366f4a2ba37682336f135a456662d84df14f900c72423` |
| SSDEEP | `12288:/d80rE7bvYQFAi5FfQEPKpuVBQmy+kQ7mYYm5k:/y0robjAi5FfQ6Kp+VK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_e00d92ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e00d92ca28a2cfd75e96f71fc0408747f04942657fcab0f2a25ce79bc3ad23a8"
    family = "unknown"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:48"
  condition:
    hash.sha256(0, filesize) == "e00d92ca28a2cfd75e96f71fc0408747f04942657fcab0f2a25ce79bc3ad23a8"
}
```

### Sample 42: `2916dbf3063abc63`

| Field | Value |
|---|---|
| SHA-256 | `2916dbf3063abc63897bc200cff4230287d6f8b72277eb86104c97169f9bdb27` |
| Family label | `Mirai` |
| File name | `bot.armv5l` |
| File type | `elf` |
| First seen | `2026-06-21 10:35:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `515d272a6c45443e42a7568accc4f74c` |
| SHA-1 | `b183e91c102180717b597a0032955c8ac60c8ffa` |
| SHA-256 | `2916dbf3063abc63897bc200cff4230287d6f8b72277eb86104c97169f9bdb27` |
| SHA3-384 | `461558003c8566a731eb60e076feca2502ff5175e7e18fc9ad29724ec7614d99a647cde78c396c442135ad2b41ee4973` |
| TLSH | `T162B43955F8809F61C6D539B6F74D82A873074779D3EBB2069A244B343BE786B0F3A601` |
| TELFHASH | `t16ee07d1a1515fbc872d24348ce55100e642434c8130879074e0d570e5d15484bc81d33` |
| SSDEEP | `12288:N75BaPR9AuKWxIE/5ejH1yzNR4stGhUlv3zTZ8prPxDM:hzaPR91Im5EVyb4sFYp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_2916dbf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2916dbf3063abc63897bc200cff4230287d6f8b72277eb86104c97169f9bdb27"
    family = "Mirai"
    file_name = "bot.armv5l"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:47"
  condition:
    hash.sha256(0, filesize) == "2916dbf3063abc63897bc200cff4230287d6f8b72277eb86104c97169f9bdb27"
}
```

### Sample 43: `b5d97c5e352ab436`

| Field | Value |
|---|---|
| SHA-256 | `b5d97c5e352ab436643e8bfe1428de72b0dd7616392bd6b0c3bf13a47b7f794c` |
| Family label | `unknown` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-06-21 10:35:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95eb6cfea10adb65bc28c30565b91ac5` |
| SHA-1 | `0f7e9f0321bd12e5cfc6291873b2b8c94df38f41` |
| SHA-256 | `b5d97c5e352ab436643e8bfe1428de72b0dd7616392bd6b0c3bf13a47b7f794c` |
| SHA3-384 | `80a5fe0d666f523e9b9b03fb75a1a0feb0e6842f13585c8ae0e8ba2b20c5a4f354533d4d9a47608c4516026a35509cbf` |
| TLSH | `T19AD46CA37B11CFA4E314C27009F3C6655AD521A20AE250C5B2BCD3187E61A6D6D6FFF8` |
| TELFHASH | `t1e1419e1c097813f0a3755c9e09ddff36e5a330db7e266d238e10e85aa769a824d14c1c` |
| SSDEEP | `12288:uI147lcaDO2lFlf6Whg6FPSmFu2rlJAP1FBPi8pkrRaKhyE:u+47lcaDO2Lf/hg6XFuwlKB+0Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_b5d97c5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5d97c5e352ab436643e8bfe1428de72b0dd7616392bd6b0c3bf13a47b7f794c"
    family = "unknown"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:45"
  condition:
    hash.sha256(0, filesize) == "b5d97c5e352ab436643e8bfe1428de72b0dd7616392bd6b0c3bf13a47b7f794c"
}
```

### Sample 44: `20a09a7cc48b9c5a`

| Field | Value |
|---|---|
| SHA-256 | `20a09a7cc48b9c5a181f5100b21cd31b3dd974400602c13c45d6bd3e71162a3a` |
| Family label | `Mirai` |
| File name | `bot.armv7` |
| File type | `elf` |
| First seen | `2026-06-21 10:35:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f58e5061b5259560c98a7a7cd01ed75` |
| SHA-1 | `7488fb3a766ebd8dce022104306ba02f28962a3c` |
| SHA-256 | `20a09a7cc48b9c5a181f5100b21cd31b3dd974400602c13c45d6bd3e71162a3a` |
| SHA3-384 | `fff17bbb8af6da94ae2abe8b4cb5befba66ea6c5984d18de196b916f4d449d6a71bd277c266585a989198703c05ff523` |
| TLSH | `T10CB43955F8809F61C6D539B6F74D82A873474B79D3EBB2069A144B303BE786B0F3A601` |
| TELFHASH | `t11401c0d298ac96ecb3d583c04d5a32474ab834fd2b2860f38a59ab6f4e164c370d5933` |
| SSDEEP | `12288:oMuOa50iM6dnJl5axRl5vzZprtYIJaYfie8v8prPxBy:lVa50itn/5ORPvVprG5u7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_20a09a7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20a09a7cc48b9c5a181f5100b21cd31b3dd974400602c13c45d6bd3e71162a3a"
    family = "Mirai"
    file_name = "bot.armv7"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:44"
  condition:
    hash.sha256(0, filesize) == "20a09a7cc48b9c5a181f5100b21cd31b3dd974400602c13c45d6bd3e71162a3a"
}
```

### Sample 45: `7aa2ae501f1572e5`

| Field | Value |
|---|---|
| SHA-256 | `7aa2ae501f1572e5957be77dc5d35a580a2697512b80fc39f6c1795463910626` |
| Family label | `Mirai` |
| File name | `bot.armv4` |
| File type | `elf` |
| First seen | `2026-06-21 10:35:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c5cf3155dc9518bb9a1e97d2ecbecdc` |
| SHA-1 | `395c56a7e3bc657747bd9ccbe4fccf496ed23203` |
| SHA-256 | `7aa2ae501f1572e5957be77dc5d35a580a2697512b80fc39f6c1795463910626` |
| SHA3-384 | `e2bc4597516a2ee65749e83225156706e2f6c4b45779781941bd9bfb2dadad9a8203078f84a163b4b5bfa51d6a30405e` |
| TLSH | `T1CFB43955F8809F61C6D539B6F74D82A873074B79D3EBB2069A154B303BE786B0F3A601` |
| TELFHASH | `t192e07d115250dfd432c2c3854e3bb82e05fd2786130514628354ba0d0e02ac07070f33` |
| SSDEEP | `12288:xyX3a5JbN6t1N41qqHLC4VuTl2UAtvTECBnN58prPxT1:Ana5Jbjq8LzcTIUAx0Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_7aa2ae50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7aa2ae501f1572e5957be77dc5d35a580a2697512b80fc39f6c1795463910626"
    family = "Mirai"
    file_name = "bot.armv4"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:42"
  condition:
    hash.sha256(0, filesize) == "7aa2ae501f1572e5957be77dc5d35a580a2697512b80fc39f6c1795463910626"
}
```

### Sample 46: `077bfdd22b49adee`

| Field | Value |
|---|---|
| SHA-256 | `077bfdd22b49adeeb86e80050de6bbf2ca9616279c426e21847f476761cba27d` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-06-21 10:29:57` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30cb9db600cbd4a03defb987066e3956` |
| SHA-1 | `d7313f4cbbc1ea4dca4954f58052fd671c0e3dfa` |
| SHA-256 | `077bfdd22b49adeeb86e80050de6bbf2ca9616279c426e21847f476761cba27d` |
| SHA3-384 | `f0536da66cc8a53e8b20abe0b11578ece725501ecc3397ba00fed288d85b9f5f5784ad1a3090754ecfd3c42e2681ce9c` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1C7646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:imlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji95:h1iw7gryNkSV1hy1Z1u2JLu95` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_046_077bfdd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "077bfdd22b49adeeb86e80050de6bbf2ca9616279c426e21847f476761cba27d"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-21 10:29:57"
  condition:
    hash.sha256(0, filesize) == "077bfdd22b49adeeb86e80050de6bbf2ca9616279c426e21847f476761cba27d"
}
```

### Sample 47: `894d32df224ee6fa`

| Field | Value |
|---|---|
| SHA-256 | `894d32df224ee6fad68f8fa19e50042819e7834edfc985be3369783d63ce95b2` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-06-21 10:29:57` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79a2c458c2f540fb85e4fd98f9183564` |
| SHA-1 | `c9bc0dfa7686958f7c1bb01438b7240984766f6b` |
| SHA-256 | `894d32df224ee6fad68f8fa19e50042819e7834edfc985be3369783d63ce95b2` |
| SHA3-384 | `c99c4939f755195928fe5626164081868f25a164d3975b23a2ac623020451c75ed87cc3ac24d18f7b0ff3d684a18db58` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T11446E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC08E32366` |
| SSDEEP | `98304:SzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:ShfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_047_894d32df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "894d32df224ee6fad68f8fa19e50042819e7834edfc985be3369783d63ce95b2"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-21 10:29:57"
  condition:
    hash.sha256(0, filesize) == "894d32df224ee6fad68f8fa19e50042819e7834edfc985be3369783d63ce95b2"
}
```

### Sample 48: `249512a11240bba5`

| Field | Value |
|---|---|
| SHA-256 | `249512a11240bba57171c0b5438b5a4d06ee2d751125957cda54d978c8a474eb` |
| Family label | `unknown` |
| File name | `249512a11240bba57171c0b5438b5a4d06ee2d751125957cda54d978c8a474eb` |
| File type | `unknown` |
| First seen | `2026-06-21 10:00:02` |
| Reporter | `lszovan` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `560791298ebccf9750fa03f99cbfaabf` |
| SHA-256 | `249512a11240bba57171c0b5438b5a4d06ee2d751125957cda54d978c8a474eb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_249512a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "249512a11240bba57171c0b5438b5a4d06ee2d751125957cda54d978c8a474eb"
    family = "unknown"
    file_name = "249512a11240bba57171c0b5438b5a4d06ee2d751125957cda54d978c8a474eb"
    file_type = "unknown"
    first_seen = "2026-06-21 10:00:02"
  condition:
    hash.sha256(0, filesize) == "249512a11240bba57171c0b5438b5a4d06ee2d751125957cda54d978c8a474eb"
}
```

### Sample 49: `41a9d327fd31b4b5`

| Field | Value |
|---|---|
| SHA-256 | `41a9d327fd31b4b512dd4b916db3e0458b5819303d940e56005be135f9872ee3` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-06-21 09:53:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9771aec8ffc9422f6133d485b0005d6a` |
| SHA-1 | `f8f79d959d8e894dfcf2aa0dcada167d6a96ba47` |
| SHA-256 | `41a9d327fd31b4b512dd4b916db3e0458b5819303d940e56005be135f9872ee3` |
| SHA3-384 | `7470882642dd1cc6b559c598914357fad993aa52cd105b9b1a00a52889cb69e6572f2c3c98bb3055d9d2d7bb70309c81` |
| TLSH | `T15AD05EBA68B321B5186A6C44F2D2A545B65197BE8C46D628FA9320706F8464DF5803A8` |
| SSDEEP | `6:hTP2+90vzrrNqYiSFbAulNXYq9DG+NjVsNXYrkJ:VPGz9JLbPiq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_41a9d327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41a9d327fd31b4b512dd4b916db3e0458b5819303d940e56005be135f9872ee3"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-21 09:53:40"
  condition:
    hash.sha256(0, filesize) == "41a9d327fd31b4b512dd4b916db3e0458b5819303d940e56005be135f9872ee3"
}
```

### Sample 50: `ea5bf6fd34986ea7`

| Field | Value |
|---|---|
| SHA-256 | `ea5bf6fd34986ea7ce7e9f9207742a2dad04700f23e25d2e3a861315503f8a2a` |
| Family label | `njrat` |
| File name | `Kjaa.exe` |
| File type | `exe` |
| First seen | `2026-06-21 09:50:56` |
| Reporter | `anonymous` |
| Tags | `email, exe, njrat, spam` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52141a7468dbfbc858f72d2ce947d6b3` |
| SHA-1 | `5b5c1b64b8d00704dabbdf7d453029b00fe61072` |
| SHA-256 | `ea5bf6fd34986ea7ce7e9f9207742a2dad04700f23e25d2e3a861315503f8a2a` |
| SHA3-384 | `f452a5dca783c4761ff4dc066ca7ae1d64d73cf9fee4e09fe7886aa077428ce3416ce9a54b021c9d0277b459836de369` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1DA23710B62ED6DA1D47D47767B3383C1C3B8DE024A03DA1E0DD560A5AA7E3837901BE6` |
| SSDEEP | `768:FwkMajwRh6UmzvwiDw8EMlpd01dQzQbCMV4x5K+jHYi:OL6UmUFopkUQbqx5KMHN` |
| ICON-DHASH | `414555c0d4d44503` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_050_ea5bf6fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea5bf6fd34986ea7ce7e9f9207742a2dad04700f23e25d2e3a861315503f8a2a"
    family = "njrat"
    file_name = "Kjaa.exe"
    file_type = "exe"
    first_seen = "2026-06-21 09:50:56"
  condition:
    hash.sha256(0, filesize) == "ea5bf6fd34986ea7ce7e9f9207742a2dad04700f23e25d2e3a861315503f8a2a"
}
```

### Sample 51: `1484054d6dd4b77d`

| Field | Value |
|---|---|
| SHA-256 | `1484054d6dd4b77d3fbe06b3d8e2bce10714811e94702b5eab6b28e25261b613` |
| Family label | `unknown` |
| File name | `tmph2yxi4at` |
| File type | `unknown` |
| First seen | `2026-06-21 09:48:16` |
| Reporter | `trpyn` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c59db06cdabcbf20496d8f505bccdd5c` |
| SHA-256 | `1484054d6dd4b77d3fbe06b3d8e2bce10714811e94702b5eab6b28e25261b613` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_1484054d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1484054d6dd4b77d3fbe06b3d8e2bce10714811e94702b5eab6b28e25261b613"
    family = "unknown"
    file_name = "tmph2yxi4at"
    file_type = "unknown"
    first_seen = "2026-06-21 09:48:16"
  condition:
    hash.sha256(0, filesize) == "1484054d6dd4b77d3fbe06b3d8e2bce10714811e94702b5eab6b28e25261b613"
}
```

### Sample 52: `682d29d3a9b484ca`

| Field | Value |
|---|---|
| SHA-256 | `682d29d3a9b484ca17caa23022b1d04643b46470ad94e5f8184a650527a70f6f` |
| Family label | `unknown` |
| File name | `sleestak_payload_1.zip` |
| File type | `zip` |
| First seen | `2026-06-21 09:47:38` |
| Reporter | `JAMESWT_WT` |
| Tags | `46-183-223-7, ps1, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d54b4e66f795452852e8891afc81d4e7` |
| SHA-1 | `7936969c204907cd28299090e703281bde4acfbd` |
| SHA-256 | `682d29d3a9b484ca17caa23022b1d04643b46470ad94e5f8184a650527a70f6f` |
| SHA3-384 | `b12207a340867762d3854b51cde88a8895d57e7675ee1586e530a16cdc61361950680310aa196f227c7d9540d69431fe` |
| TLSH | `T1D7017AD4A667E501FD36C1B58B61DDF818C132317E5836EFA47555322C15E81BD1C242` |
| SSDEEP | `12:5js29JAhj3pw3VTqixsNbUTafR9CcOtq+j3zxU0GoNYqaPfxz78jlKuK12uVtaj:9PU13QTT/Ts9Cd8w39U0GooxEKuK8uq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_682d29d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "682d29d3a9b484ca17caa23022b1d04643b46470ad94e5f8184a650527a70f6f"
    family = "unknown"
    file_name = "sleestak_payload_1.zip"
    file_type = "zip"
    first_seen = "2026-06-21 09:47:38"
  condition:
    hash.sha256(0, filesize) == "682d29d3a9b484ca17caa23022b1d04643b46470ad94e5f8184a650527a70f6f"
}
```

### Sample 53: `699d8fd14420e9c8`

| Field | Value |
|---|---|
| SHA-256 | `699d8fd14420e9c8bcbd65a3b7208a019933ba2e611ae3356cada3f04609f62c` |
| Family label | `unknown` |
| File name | `699d8fd14420e9c8bcbd65a3b7208a019933ba2e611ae3356cada3f04609f62c` |
| File type | `unknown` |
| First seen | `2026-06-21 09:44:05` |
| Reporter | `JAMESWT_WT` |
| Tags | `46-183-223-7` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6eb0a2e17bce856f4a99122a7789e1f` |
| SHA-256 | `699d8fd14420e9c8bcbd65a3b7208a019933ba2e611ae3356cada3f04609f62c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_699d8fd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "699d8fd14420e9c8bcbd65a3b7208a019933ba2e611ae3356cada3f04609f62c"
    family = "unknown"
    file_name = "699d8fd14420e9c8bcbd65a3b7208a019933ba2e611ae3356cada3f04609f62c"
    file_type = "unknown"
    first_seen = "2026-06-21 09:44:05"
  condition:
    hash.sha256(0, filesize) == "699d8fd14420e9c8bcbd65a3b7208a019933ba2e611ae3356cada3f04609f62c"
}
```

### Sample 54: `2dcdb89527b24098`

| Field | Value |
|---|---|
| SHA-256 | `2dcdb89527b240984a85645a4a41e4fed7ed33891fd91da07e1f8b62180f2c33` |
| Family label | `RemcosRAT` |
| File name | `2dcdb89527b240984a85645a4a41e4fed7ed33891fd91da07e1f8b62180f2c33` |
| File type | `exe` |
| First seen | `2026-06-21 09:43:55` |
| Reporter | `JAMESWT_WT` |
| Tags | `46-183-223-7, exe, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2f8bcbe8815b33869f87f1e99ab6f70` |
| SHA-1 | `39367cdbe465ccb091c30a9142d624a343f632ac` |
| SHA-256 | `2dcdb89527b240984a85645a4a41e4fed7ed33891fd91da07e1f8b62180f2c33` |
| SHA3-384 | `683ac464c18cf0b2de2071506fe52b4bdb399ba80ade304101628106569946380fc93590c0649d070f8de1fc2c622bb1` |
| IMPHASH | `8d5087ff5de35c3fbb9f212b47d63cad` |
| TLSH | `T1E9B4AF02BAD1C0B2D57514300D36F776EAB9BC202D354A7B73D51E5BFD31180BA2AAB6` |
| SSDEEP | `6144:8XIktXfM8Lv86r9uVWAa2je4Z5zl4hgDHQQs4NTQjoHFsAOZZDAXYcN95Gvr:8X7tPMK8ctGe4Dzl4h2QnuPs/ZDAcvr` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_054_2dcdb895
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dcdb89527b240984a85645a4a41e4fed7ed33891fd91da07e1f8b62180f2c33"
    family = "RemcosRAT"
    file_name = "2dcdb89527b240984a85645a4a41e4fed7ed33891fd91da07e1f8b62180f2c33"
    file_type = "exe"
    first_seen = "2026-06-21 09:43:55"
  condition:
    hash.sha256(0, filesize) == "2dcdb89527b240984a85645a4a41e4fed7ed33891fd91da07e1f8b62180f2c33"
}
```

### Sample 55: `43ee2409e135916f`

| Field | Value |
|---|---|
| SHA-256 | `43ee2409e135916fab34e910035ff437eb1eaa670000c4f0948ba33f11a7083b` |
| Family label | `RemcosRAT` |
| File name | `43ee2409e135916fab34e910035ff437eb1eaa670000c4f0948ba33f11a7083b` |
| File type | `exe` |
| First seen | `2026-06-21 09:42:34` |
| Reporter | `JAMESWT_WT` |
| Tags | `46-183-223-7, exe, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a4dcdc6cbe2bb676b37f9a24bd593a3` |
| SHA-1 | `d4d165ba51a52baff5e187f62e5d970f378ec119` |
| SHA-256 | `43ee2409e135916fab34e910035ff437eb1eaa670000c4f0948ba33f11a7083b` |
| SHA3-384 | `48e987f100d14120120f17e498a4591df30ee15dcea8787bc981b9c078cab476997f79010b39153bcc2bb1ad8034fba9` |
| IMPHASH | `8d5087ff5de35c3fbb9f212b47d63cad` |
| TLSH | `T127E59C13EB918AE8E65D09365F284150D62EF621AADF132175AC120DCF93387BF25E3D` |
| SSDEEP | `49152:RAQuyZpVmgbQIzZMPXpB91rHpn/qKmNAOaG6IOY/B+q:R7uDnLrHp/qKm2/Sb/gq` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_055_43ee2409
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43ee2409e135916fab34e910035ff437eb1eaa670000c4f0948ba33f11a7083b"
    family = "RemcosRAT"
    file_name = "43ee2409e135916fab34e910035ff437eb1eaa670000c4f0948ba33f11a7083b"
    file_type = "exe"
    first_seen = "2026-06-21 09:42:34"
  condition:
    hash.sha256(0, filesize) == "43ee2409e135916fab34e910035ff437eb1eaa670000c4f0948ba33f11a7083b"
}
```

### Sample 56: `daf2410a4e6da576`

| Field | Value |
|---|---|
| SHA-256 | `daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437` |
| Family label | `RemcosRAT` |
| File name | `givewegivingbestsolutionsforbetterplaces.js` |
| File type | `js` |
| First seen | `2026-06-21 09:42:19` |
| Reporter | `JAMESWT_WT` |
| Tags | `46-183-223-7, js, kelvin654-duckdns-org, RemcosRAT, spam-ita` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f749306e539eab248f698468a5ffc7f0` |
| SHA-1 | `d7bbb24c3a449bbdf9031fb92753b2d96a68a587` |
| SHA-256 | `daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437` |
| SHA3-384 | `4cdc441c1f4b25299a0387adc4b072877cc303479e9d3fbda5ca3ad4d2ad356071f60274a5f646ec3bbd347d24f721f8` |
| TLSH | `T159034C5F9F2B0D298EDCAE838C0E537368DD69B823636930B57A549F9E15203E1F54B0` |
| SSDEEP | `768:rrX0uNzecLsfDirMWqrGURG39Lp92CvsO0xLErmTe6RvhQenPAZWlfccKK4OmeUd:rrkuNzecLsfDirMWqqURG39LpgCvsO0Y` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_056_daf2410a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
    family = "RemcosRAT"
    file_name = "givewegivingbestsolutionsforbetterplaces.js"
    file_type = "js"
    first_seen = "2026-06-21 09:42:19"
  condition:
    hash.sha256(0, filesize) == "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
}
```

### Sample 57: `2b48b4d74ec2b1cf`

| Field | Value |
|---|---|
| SHA-256 | `2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d` |
| Family label | `RemcosRAT` |
| File name | `sweetnessgivenmebestthingsforever.hta` |
| File type | `hta` |
| First seen | `2026-06-21 09:41:27` |
| Reporter | `JAMESWT_WT` |
| Tags | `46-183-223-7, hta, kelvin654-duckdns-org, RemcosRAT, spam-ita` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `645b21ae90237079c4ff8d1c93442071` |
| SHA-1 | `82569fcb91410f416ce12b966b91519d5ea89608` |
| SHA-256 | `2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d` |
| SHA3-384 | `69685789093aef0c0d0756e967183ee4382785796f6640cb7b20e07d434ca755936088ee09cba554a942218b37494958` |
| TLSH | `T14523D97DC7C195AE994FA7500E6E27C5332C63F542A96618FCDD81339EFD52B2316014` |
| SSDEEP | `192:X+lyG58UMd+8+ccQPd21282w2Q2+m242b2ff+2u2bGBf+SD7igrMxs3+++lF:XNqHs7PvW3af9Fbw17imMCvG` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_057_2b48b4d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d"
    family = "RemcosRAT"
    file_name = "sweetnessgivenmebestthingsforever.hta"
    file_type = "hta"
    first_seen = "2026-06-21 09:41:27"
  condition:
    hash.sha256(0, filesize) == "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d"
}
```

### Sample 58: `d1acc92471213eb1`

| Field | Value |
|---|---|
| SHA-256 | `d1acc92471213eb14c54cd89c7de440811cd2293f36279dbedfb8583dc55344c` |
| Family label | `unknown` |
| File name | `050d4043af02c7cfaf00f257f28e8c8313f6f444c843def486fc2141d379da49.zip` |
| File type | `zip` |
| First seen | `2026-06-21 09:41:06` |
| Reporter | `JAMESWT_WT` |
| Tags | `46-183-223-7, kelvin654-duckdns-org, spam-ita, stego, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0ee7051cc66baa69fda565e1bb3b7f8` |
| SHA-1 | `3a9283b8969a40c226d387eba784f0bb2b38d3ca` |
| SHA-256 | `d1acc92471213eb14c54cd89c7de440811cd2293f36279dbedfb8583dc55344c` |
| SHA3-384 | `e792cd01d40a2cfbd06b7ede6d622dac3e69963e1c6c932a0f88e4100641833cbe1996fe5efefab4f0f6857dbbf4cf0c` |
| TLSH | `T18D263343C93AA8D6ECBE269392476CC81916539A6B25F95F0CD8F78178216F47B3D330` |
| SSDEEP | `98304:oUh4I/PQVZv/WLOmsjOjh5hM2hTZ8IYr02NN845HAXAVj:H4I3s6AOjhI2h+YSDj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_d1acc924
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1acc92471213eb14c54cd89c7de440811cd2293f36279dbedfb8583dc55344c"
    family = "unknown"
    file_name = "050d4043af02c7cfaf00f257f28e8c8313f6f444c843def486fc2141d379da49.zip"
    file_type = "zip"
    first_seen = "2026-06-21 09:41:06"
  condition:
    hash.sha256(0, filesize) == "d1acc92471213eb14c54cd89c7de440811cd2293f36279dbedfb8583dc55344c"
}
```

### Sample 59: `f93ff95b099ee0ae`

| Field | Value |
|---|---|
| SHA-256 | `f93ff95b099ee0ae13f3bb4e6b80d3160b0485bb1e4f629be6895442f90355b8` |
| Family label | `RemcosRAT` |
| File name | `Solicitud de presupuesto n.º 490526.xls` |
| File type | `xls` |
| First seen | `2026-06-21 09:40:47` |
| Reporter | `JAMESWT_WT` |
| Tags | `46-183-223-7, kelvin654-duckdns-org, RemcosRAT, spam-ita, xls` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cefc7d607d1bfb2ed3855cda11072c4` |
| SHA-1 | `4e04540fa4a792d958a8ac39ca1acbd42c6fac46` |
| SHA-256 | `f93ff95b099ee0ae13f3bb4e6b80d3160b0485bb1e4f629be6895442f90355b8` |
| SHA3-384 | `d89e0bc69737480cf6a8f3514a3d6f38443898123cba0c7c4f800d05a6cc9ac1d8a40e3c8d70e0cfe86990ad93b91ffc` |
| TLSH | `T129552326FE839E9BDD0E00349667A0D1791F9E22BB445D6F37483B4A6C72131C7B6A1C` |
| SSDEEP | `24576:FYNSz7NRNXjA/+OmXCKcsKftqgyoQmuo/2rBWQA5U740mecvjJ:emjljA/jmSsKftqJoQmuo/OBuS40mec` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `xls`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_059_f93ff95b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f93ff95b099ee0ae13f3bb4e6b80d3160b0485bb1e4f629be6895442f90355b8"
    family = "RemcosRAT"
    file_name = "Solicitud de presupuesto n.º 490526.xls"
    file_type = "xls"
    first_seen = "2026-06-21 09:40:47"
  condition:
    hash.sha256(0, filesize) == "f93ff95b099ee0ae13f3bb4e6b80d3160b0485bb1e4f629be6895442f90355b8"
}
```

### Sample 60: `8abae386ec6aaa1d`

| Field | Value |
|---|---|
| SHA-256 | `8abae386ec6aaa1d1bf03e39f339922053e4b66d7ebbbeba15701d3ecc183fb8` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-06-21 09:37:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c8c17a03eb76230a91b1880d40344e7` |
| SHA-1 | `c24109b3f3c2be27f3bb84eb747a4ede7a353030` |
| SHA-256 | `8abae386ec6aaa1d1bf03e39f339922053e4b66d7ebbbeba15701d3ecc183fb8` |
| SHA3-384 | `0a23f11a5118b2e14ca770012443aa3a5fe50fedb1d909aaa53a160cf4e7f4c9e7834bf28c8a7d36659beb070f0980d6` |
| TLSH | `T1F3A42966EC409B95DAD12ABEFF1E824973131B78F3EE72119D155B3063CB84A0E7B502` |
| SSDEEP | `12288:K7B7uNXw+hhybR2Fv8lZNAH2jj4GRLIpxg89Da9a/GBkenz+0KhB:8B7uRSlV/kO9Yl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_8abae386
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8abae386ec6aaa1d1bf03e39f339922053e4b66d7ebbbeba15701d3ecc183fb8"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-21 09:37:42"
  condition:
    hash.sha256(0, filesize) == "8abae386ec6aaa1d1bf03e39f339922053e4b66d7ebbbeba15701d3ecc183fb8"
}
```

### Sample 61: `33b554e0ba3a5c40`

| Field | Value |
|---|---|
| SHA-256 | `33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482` |
| Family label | `unknown` |
| File name | `Ciabins.sh` |
| File type | `sh` |
| First seen | `2026-06-21 09:31:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `127d91b5a6b945bf7f4111745d786e1a` |
| SHA-1 | `74c798eece8ac8486b418db8b57f265fa47236ed` |
| SHA-256 | `33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482` |
| SHA3-384 | `15579dedf0a199b913cfe2716f891d09c2b9da84fae0a1d15e19cacbe900dfb4ffe4a747b030b53522284818c2c17b16` |
| TLSH | `T1593184CA72A309F12DE4ED6B367A884531D1F5CB91D7EFA82CEC34E9419DE44B440A93` |
| SSDEEP | `48:vtgtEtc4ktcbtm9t4tEt0tSJtct0t3WLtOJtVh:vm6y4kabeu66uq6MLinh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_33b554e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482"
    family = "unknown"
    file_name = "Ciabins.sh"
    file_type = "sh"
    first_seen = "2026-06-21 09:31:48"
  condition:
    hash.sha256(0, filesize) == "33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482"
}
```

### Sample 62: `2b33df7907355444`

| Field | Value |
|---|---|
| SHA-256 | `2b33df7907355444e551355ad0c4aa6f789cf1e3755f43295c4bbf2de02f7eed` |
| Family label | `unknown` |
| File name | `LetsVPN.msi` |
| File type | `msi` |
| First seen | `2026-06-21 09:30:25` |
| Reporter | `smica83` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f54e580afa0ec72958494f3fc65c87be` |
| SHA-1 | `5e9de6bd6fbd50cdc7b8b4ce0b8979dc5301f14d` |
| SHA-256 | `2b33df7907355444e551355ad0c4aa6f789cf1e3755f43295c4bbf2de02f7eed` |
| SHA3-384 | `814515c3c6f78028f5b1b8bd78550301f45a6eaed94f5d4d6a312ebf2183248a32533bb215b3a4b97ce1f706f807694a` |
| TLSH | `T1AEF73330B13579D9EA2FA37FA0A91FC5807074E0B31BD56F63787FB59A9124660B2843` |
| SSDEEP | `1572864:LFELanPaFZBMczNsgRoJFTJQCQ5oFXY02NEbffoOd1cCnaPGwLzqoTQ:LnaF0cgdQ7mXYcbfoO5noGmXM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_2b33df79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b33df7907355444e551355ad0c4aa6f789cf1e3755f43295c4bbf2de02f7eed"
    family = "unknown"
    file_name = "LetsVPN.msi"
    file_type = "msi"
    first_seen = "2026-06-21 09:30:25"
  condition:
    hash.sha256(0, filesize) == "2b33df7907355444e551355ad0c4aa6f789cf1e3755f43295c4bbf2de02f7eed"
}
```

### Sample 63: `4b416e7b71b3a468`

| Field | Value |
|---|---|
| SHA-256 | `4b416e7b71b3a46854f08618d76d1146159d8da5c5061b9336dcf30b50cf6725` |
| Family label | `unknown` |
| File name | `LetsVPN.msi` |
| File type | `msi` |
| First seen | `2026-06-21 09:28:28` |
| Reporter | `smica83` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba5cf574a9f7a064fddbd51355ed428c` |
| SHA-1 | `9c42abd02102e2b466763338b581f44b7093f1f8` |
| SHA-256 | `4b416e7b71b3a46854f08618d76d1146159d8da5c5061b9336dcf30b50cf6725` |
| SHA3-384 | `c95426e7f1b85f8d12d0e0c2a528be3bd38561b26d5c0f4a803923ec40d4763d74269eb4c2c867328dac4dbea0842a08` |
| TLSH | `T1BEF73334717669E9EB3BD27FA0B84FE5805075E09365D5EF63782FA95EA028210F2D03` |
| SSDEEP | `1572864:cvV75w5itmpJfqdg9xF5BUEtjBm0V9JApmanieTJv5vDFx0eoX9PA2CiNJ:05wpJUgzdmMApmWdv5v8ei9YCr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_4b416e7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b416e7b71b3a46854f08618d76d1146159d8da5c5061b9336dcf30b50cf6725"
    family = "unknown"
    file_name = "LetsVPN.msi"
    file_type = "msi"
    first_seen = "2026-06-21 09:28:28"
  condition:
    hash.sha256(0, filesize) == "4b416e7b71b3a46854f08618d76d1146159d8da5c5061b9336dcf30b50cf6725"
}
```

### Sample 64: `a093015413d6d543`

| Field | Value |
|---|---|
| SHA-256 | `a093015413d6d543e3d5d863be6e44b853a2055849df37f8070175aae44d42e0` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-06-21 09:19:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9222bdff9810874530022442e242baf8` |
| SHA-1 | `257bf22146cc9c22d1ae6eb3431bea96a28ca1e0` |
| SHA-256 | `a093015413d6d543e3d5d863be6e44b853a2055849df37f8070175aae44d42e0` |
| SHA3-384 | `6943b20f151559e914d91b197ff93d140ebd3d493c3509eb9c9a93da0474c5247fe509f56e3d0645812d52412ff0a3c4` |
| TLSH | `T1A3316CDB44190E390603DADE73633548B10C9AEB286BDB94CC584EEDC68C2CCB266FC5` |
| SSDEEP | `24:gcxiHz3H5MLhmGrkEaxhCXECJhGXKn7oqs:gcxir5+hm2kEajCXECJhGa7e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_a0930154
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a093015413d6d543e3d5d863be6e44b853a2055849df37f8070175aae44d42e0"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-21 09:19:39"
  condition:
    hash.sha256(0, filesize) == "a093015413d6d543e3d5d863be6e44b853a2055849df37f8070175aae44d42e0"
}
```

### Sample 65: `87c8df8bca39bbb8`

| Field | Value |
|---|---|
| SHA-256 | `87c8df8bca39bbb86f4b2bccadb106aa7c3837db4b314694325cb25222c871e5` |
| Family label | `ConnectWise` |
| File name | `File_Summary.msi` |
| File type | `msi` |
| First seen | `2026-06-21 09:17:28` |
| Reporter | `SquiblydooBlog` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98c0feab8fe62fa78e99c346e7a72587` |
| SHA-1 | `233027c11c6ab4e98aeafac93882493c5d9ba21e` |
| SHA-256 | `87c8df8bca39bbb86f4b2bccadb106aa7c3837db4b314694325cb25222c871e5` |
| SHA3-384 | `17536f95af0a387fb4bb7cc23bb8907640f02f395a4b6076edac09c9bbc77e6c38ad86fab1f28f4e709b8c92022c3088` |
| TLSH | `T1539622212BF94918F1F72B79ED3541F25878BC24AA23C15F1769B95E38B0D40A9B2373` |
| SSDEEP | `196608:JiFoRlKlo1iFoRlkiFoRlfiFoRl7iFoRl:JCoRFCoR6CoRJCoR1CoR` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_065_87c8df8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87c8df8bca39bbb86f4b2bccadb106aa7c3837db4b314694325cb25222c871e5"
    family = "ConnectWise"
    file_name = "File_Summary.msi"
    file_type = "msi"
    first_seen = "2026-06-21 09:17:28"
  condition:
    hash.sha256(0, filesize) == "87c8df8bca39bbb86f4b2bccadb106aa7c3837db4b314694325cb25222c871e5"
}
```

### Sample 66: `d592ee8eddace6c5`

| Field | Value |
|---|---|
| SHA-256 | `d592ee8eddace6c5e01c80cc9369425559a9e6715104da7db979a5a6aa246a35` |
| Family label | `unknown` |
| File name | `d592ee8eddace6c5e01c80cc9369425559a9e6715104da7db979a5a6aa246a35` |
| File type | `elf` |
| First seen | `2026-06-21 09:01:06` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e5b05a7f10f7d05d907ec71548dc08c` |
| SHA-1 | `d55cd19ba9c0601e3deee506ad7edc1f2f1275c8` |
| SHA-256 | `d592ee8eddace6c5e01c80cc9369425559a9e6715104da7db979a5a6aa246a35` |
| SHA3-384 | `8197597c927064dcd527eaf742c9b9541c8f45d73e52546d6b5c8161e029b5c63ae505e4b060c1cd9629f04ff979814e` |
| TLSH | `T1FD44F55B6CA550E4D0FEE078C66BF212BDB27055073837E72EA05A610F26FE1A4F8B54` |
| TELFHASH | `t13091f6701cbd79b4b5a6ca107397ba78967728e022ed34b05137a880fec1ec01ce6c67` |
| SSDEEP | `3072:FxeuFzOPWO/E48DZpyxZIsCLl1Z9xhqmFKYZFNezBAVIaoF9WSjMhrp:FqW48KxWLlrnUBgIa4URp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_d592ee8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d592ee8eddace6c5e01c80cc9369425559a9e6715104da7db979a5a6aa246a35"
    family = "unknown"
    file_name = "d592ee8eddace6c5e01c80cc9369425559a9e6715104da7db979a5a6aa246a35"
    file_type = "elf"
    first_seen = "2026-06-21 09:01:06"
  condition:
    hash.sha256(0, filesize) == "d592ee8eddace6c5e01c80cc9369425559a9e6715104da7db979a5a6aa246a35"
}
```

### Sample 67: `57e48ba670405677`

| Field | Value |
|---|---|
| SHA-256 | `57e48ba67040567734000242541a9eeb4c9dafb008bfede2ade8057c3d9754a5` |
| Family label | `unknown` |
| File name | `57e48ba67040567734000242541a9eeb4c9dafb008bfede2ade8057c3d9754a5` |
| File type | `elf` |
| First seen | `2026-06-21 09:01:03` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `574716308fa6311590858118226c974c` |
| SHA-1 | `02fc44ecfdd8bc5b65e2e95271c5ed2d5e2db482` |
| SHA-256 | `57e48ba67040567734000242541a9eeb4c9dafb008bfede2ade8057c3d9754a5` |
| SHA3-384 | `453e6251907acce41d7e3446da03a6c6727eb9263e2c75dc7cc206c1ec7ebcf1de3ef480c906591c1575a8aa420ba3a2` |
| TLSH | `T1D747DF77814338E9E5A98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ1:cqYUQuVDt0TZEK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_57e48ba6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57e48ba67040567734000242541a9eeb4c9dafb008bfede2ade8057c3d9754a5"
    family = "unknown"
    file_name = "57e48ba67040567734000242541a9eeb4c9dafb008bfede2ade8057c3d9754a5"
    file_type = "elf"
    first_seen = "2026-06-21 09:01:03"
  condition:
    hash.sha256(0, filesize) == "57e48ba67040567734000242541a9eeb4c9dafb008bfede2ade8057c3d9754a5"
}
```

### Sample 68: `6a05487baf63509d`

| Field | Value |
|---|---|
| SHA-256 | `6a05487baf63509da9f48302827bdf5b5c239fb1018a42ab6a37b18b0bf100a8` |
| Family label | `Mirai` |
| File name | `b` |
| File type | `elf` |
| First seen | `2026-06-21 08:53:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4e97af863eb5db6e0d95ff67e5fed43` |
| SHA-1 | `cbd4e6600e3e486d7e69b2e0332acfd3ed73cc9f` |
| SHA-256 | `6a05487baf63509da9f48302827bdf5b5c239fb1018a42ab6a37b18b0bf100a8` |
| SHA3-384 | `748845cdcd564df4ff63a93cbd3a4f7cfccc106d32160949c0bd8b745fab1b549cc6e1201cd07e2f9a570853abaaf5d4` |
| TLSH | `T187074A47F9A214E8C0AEC43486679653BE717C88072177F72B94B6342F76FE06A79B10` |
| TELFHASH | `t1b85257314abc35b5b6a6da10b3a274b496772c6162f434b55063e985ffc1e801ceac3b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `196608:BgT3Hb8RHkVl4lcmDi1WIPFCBNcJ7oEkLsQXX:BSb0kTOqUqFCIkLsQXX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_6a05487b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a05487baf63509da9f48302827bdf5b5c239fb1018a42ab6a37b18b0bf100a8"
    family = "Mirai"
    file_name = "b"
    file_type = "elf"
    first_seen = "2026-06-21 08:53:40"
  condition:
    hash.sha256(0, filesize) == "6a05487baf63509da9f48302827bdf5b5c239fb1018a42ab6a37b18b0bf100a8"
}
```

### Sample 69: `0ac8cf56f1c5544b`

| Field | Value |
|---|---|
| SHA-256 | `0ac8cf56f1c5544bac181cc00b36a711333a132be36a05c23714f7d1d76108ee` |
| Family label | `unknown` |
| File name | `poop` |
| File type | `elf` |
| First seen | `2026-06-21 08:49:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01e53dcba958061b4b7368f5e03b10ed` |
| SHA-1 | `2b683bff1ece7e5f10e8b41356c0c546c670444a` |
| SHA-256 | `0ac8cf56f1c5544bac181cc00b36a711333a132be36a05c23714f7d1d76108ee` |
| SHA3-384 | `da99505c37eefe4f8da39a96163aa04cda2a78d8e1dfe1bec322adfcd77e4b729bb46b43a14b08f2e759dd2c7ca26163` |
| TLSH | `T104E423F14931A657ECE34426B9AE214091F2BBB1EE48F2650121BC79BE24EC6D30F4D7` |
| SSDEEP | `12288:aejIro9698mOhbGFWoJWdB4QN/42HTp8mFCmGYNDHOTD1lWT1zxIKV6Oh:5IrSo8lbGgoJWdBfZlTp8hz5bWTLIKVf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_0ac8cf56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ac8cf56f1c5544bac181cc00b36a711333a132be36a05c23714f7d1d76108ee"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-06-21 08:49:40"
  condition:
    hash.sha256(0, filesize) == "0ac8cf56f1c5544bac181cc00b36a711333a132be36a05c23714f7d1d76108ee"
}
```

### Sample 70: `35e66da427a1ad60`

| Field | Value |
|---|---|
| SHA-256 | `35e66da427a1ad60fd9de1d0efc5ae98275cea581d21e2aebca59491b936caec` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-06-21 08:49:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdd1d37f1b6cc05cf665577aa6df3f46` |
| SHA-1 | `13e0e3aabbbfa542c75a0a468474a7585b850207` |
| SHA-256 | `35e66da427a1ad60fd9de1d0efc5ae98275cea581d21e2aebca59491b936caec` |
| SHA3-384 | `54755efe57a8bf627a8b8e9d7ce28bb8ec0eae14038a2be3600fc20986fc1f600affdf53c178259a6201b58d0fe29877` |
| TLSH | `T19D0148D686417D105059DA9972979290B812D3CE094F0FB87FDC5E3DFB88D14B066E94` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaFvftirT/epviIvz0O7:e9Qp+MsFvfITIBYO7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_35e66da4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35e66da427a1ad60fd9de1d0efc5ae98275cea581d21e2aebca59491b936caec"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-21 08:49:39"
  condition:
    hash.sha256(0, filesize) == "35e66da427a1ad60fd9de1d0efc5ae98275cea581d21e2aebca59491b936caec"
}
```

### Sample 71: `8235816f709e06a1`

| Field | Value |
|---|---|
| SHA-256 | `8235816f709e06a15b65b0843704080c3066fa5645f686540905280cfa9d3ce1` |
| Family label | `Mirai` |
| File name | `b` |
| File type | `elf` |
| First seen | `2026-06-21 08:45:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f20fb68806b32a13d999c5052b93f0e4` |
| SHA-1 | `dd92f75eb183dc0eb3a70050f8e0536039c39467` |
| SHA-256 | `8235816f709e06a15b65b0843704080c3066fa5645f686540905280cfa9d3ce1` |
| SHA3-384 | `e289b6d8d7c3563e8c6fcc8643e0626a98e4782040e721a090ed17ee337203cdd272b7f94293fb486200d31619be2cda` |
| TLSH | `T152074A47F9A214E8C0AEC434866B9653BE707C49072177F72B94A6342F77FE06A79B10` |
| TELFHASH | `t1b85257314abc35b5b6a6da10b3a274b496772c6162f434b55063e985ffc1e801ceac3b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `196608:3SPRkMlPM2Yl4lcmDi1WIPFCBNcJ7oEkLsQXX:3+e2AOqUqFCIkLsQXX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_8235816f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8235816f709e06a15b65b0843704080c3066fa5645f686540905280cfa9d3ce1"
    family = "Mirai"
    file_name = "b"
    file_type = "elf"
    first_seen = "2026-06-21 08:45:43"
  condition:
    hash.sha256(0, filesize) == "8235816f709e06a15b65b0843704080c3066fa5645f686540905280cfa9d3ce1"
}
```

### Sample 72: `3b92622a7ff1323b`

| Field | Value |
|---|---|
| SHA-256 | `3b92622a7ff1323b5c647ac613d0cc78e113edc37acbe495cb060d986454dbf8` |
| Family label | `unknown` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-06-21 08:23:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd897925a25bb0dad996f8c694e4178d` |
| SHA-1 | `5a44577ffa459bd93f1b85291cf6dc3b6458995b` |
| SHA-256 | `3b92622a7ff1323b5c647ac613d0cc78e113edc37acbe495cb060d986454dbf8` |
| SHA3-384 | `61cffe47f243b5cf3338073f8e866a4a2d866230218dd2617d3a183e422568acd644c5ae43025aa9dcfcb99da684b2d0` |
| TLSH | `T15AF30985FC915F26C6C622BBFB5E42CC772A17B8D3EA310389255B24378B85B0E3B541` |
| TELFHASH | `t1db019025fa192c1c6bda80fed1ff6417343835d5792734a3a15f5b5b5092cc5b00a50b` |
| SSDEEP | `3072:0or0eAgv+WGOU5W9jzTj4BjnMbS4t3HGL:Lr0e7ZGOU5gjHj4B7Mb3t3mL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_3b92622a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b92622a7ff1323b5c647ac613d0cc78e113edc37acbe495cb060d986454dbf8"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-21 08:23:43"
  condition:
    hash.sha256(0, filesize) == "3b92622a7ff1323b5c647ac613d0cc78e113edc37acbe495cb060d986454dbf8"
}
```

### Sample 73: `abc7b3d5f6d8d045`

| Field | Value |
|---|---|
| SHA-256 | `abc7b3d5f6d8d04590b60aff1b49b5feeaa22f1b66dcbf8e6de5de28f499a4b6` |
| Family label | `Mirai` |
| File name | `lul.arm5` |
| File type | `elf` |
| First seen | `2026-06-21 08:21:33` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3c9f9a80bbf07d53bb21ec41786d4c6` |
| SHA-1 | `75c3fb71e4b403624f07bfc5868852d591da0997` |
| SHA-256 | `abc7b3d5f6d8d04590b60aff1b49b5feeaa22f1b66dcbf8e6de5de28f499a4b6` |
| SHA3-384 | `75d57cb8cdc5e1d2b189941ffc362d50483b41819b5c3e4435ae892f9018a299e437bd937f264bf467f864be7fe454d1` |
| TLSH | `T127634C84BCC19A12C6D1227AFB5E518D372663E8D3EF3207ED254F60378A96B0E77641` |
| TELFHASH | `t16d41ceb697651fcc1be18244858f616e4efd38b91b04205aca5c6b5bc2c35c0b60e83b` |
| SSDEEP | `1536:bdUNVkuKZULih+m9EiUbRPRoIe1FfLxu0goXi5lv6r7aX0:bdUNVkXZULiA6f8PiIWFfLxui2Z6rW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_abc7b3d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abc7b3d5f6d8d04590b60aff1b49b5feeaa22f1b66dcbf8e6de5de28f499a4b6"
    family = "Mirai"
    file_name = "lul.arm5"
    file_type = "elf"
    first_seen = "2026-06-21 08:21:33"
  condition:
    hash.sha256(0, filesize) == "abc7b3d5f6d8d04590b60aff1b49b5feeaa22f1b66dcbf8e6de5de28f499a4b6"
}
```

### Sample 74: `5a0bc5c4731aae2c`

| Field | Value |
|---|---|
| SHA-256 | `5a0bc5c4731aae2c5445ed0cf17aa3a22470496a27d4f330341b5a70645c3c3c` |
| Family label | `unknown` |
| File name | `kmips` |
| File type | `elf` |
| First seen | `2026-06-21 08:21:32` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c47314dc583ff4f95be4ddfb5dd39f2f` |
| SHA-1 | `3afe74a59d000cb8cb72ce3cfbf1e588a6fc66cd` |
| SHA-256 | `5a0bc5c4731aae2c5445ed0cf17aa3a22470496a27d4f330341b5a70645c3c3c` |
| SHA3-384 | `163a4c430484e3f5d08b0b3cda751a43a2456fcb8924bc2498315913092422c0ef26ea76a0c403ef1d98c3c76c0a1e45` |
| TLSH | `T1CB83D71E7E618FADF7AD823447B78E259358238737E1C685D29CD6002F6034D646FBA8` |
| TELFHASH | `t1841105488d3813f5db720d996badef76e0a130df06255e378d00f9aaaa2da425a00c1c` |
| SSDEEP | `1536:avStdbLlg12bDXp39T6j6F/cPy9zy9nD96E2U8ff8Soe7q/OC:avStdKyDN92j6F0SUmf8SG/b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_5a0bc5c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a0bc5c4731aae2c5445ed0cf17aa3a22470496a27d4f330341b5a70645c3c3c"
    family = "unknown"
    file_name = "kmips"
    file_type = "elf"
    first_seen = "2026-06-21 08:21:32"
  condition:
    hash.sha256(0, filesize) == "5a0bc5c4731aae2c5445ed0cf17aa3a22470496a27d4f330341b5a70645c3c3c"
}
```

### Sample 75: `bc0b6448957fc6fd`

| Field | Value |
|---|---|
| SHA-256 | `bc0b6448957fc6fde56f0c568c36fd0b9ed796cea2bd2a1d2d0c3051bd65f46a` |
| Family label | `Mirai` |
| File name | `lul.arm` |
| File type | `elf` |
| First seen | `2026-06-21 08:21:32` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7bfdd4b9e0d3e01cf688c0b25d86dff6` |
| SHA-1 | `c68fca609826cf86ee73ec13b6331b9159a46663` |
| SHA-256 | `bc0b6448957fc6fde56f0c568c36fd0b9ed796cea2bd2a1d2d0c3051bd65f46a` |
| SHA3-384 | `c60ddda2339e511385b72e7b8000cedcf92ebb4f06a13e648da9cddff982653de8c06e54e699a4da58a3aeabb8840d86` |
| TLSH | `T143632984BC819A13C6D1227AFB6E51CD332627E8D3EB3207DD255F61378A92B0E77641` |
| TELFHASH | `t17041bef75b741e9c57e8c248954f50290eed34fa1b14206bcf0ca75ed6d36c2f229826` |
| SSDEEP | `1536:eZ+TsS7SPXk4KtbCbZkt2Y9YAIledZmqH0TK/i6:eZ+TsS7SPXk4FbZov9Y/eyqU36` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_bc0b6448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc0b6448957fc6fde56f0c568c36fd0b9ed796cea2bd2a1d2d0c3051bd65f46a"
    family = "Mirai"
    file_name = "lul.arm"
    file_type = "elf"
    first_seen = "2026-06-21 08:21:32"
  condition:
    hash.sha256(0, filesize) == "bc0b6448957fc6fde56f0c568c36fd0b9ed796cea2bd2a1d2d0c3051bd65f46a"
}
```

### Sample 76: `fdacc304a9940201`

| Field | Value |
|---|---|
| SHA-256 | `fdacc304a99402012f5b9e6708344b24ff21d7c79178633a3cde1411bef56960` |
| Family label | `Mirai` |
| File name | `kmpsl` |
| File type | `elf` |
| First seen | `2026-06-21 08:21:32` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `478f333970ee3a1866a83d3a3f49f0ee` |
| SHA-1 | `c3673157f2d7af1b4e824d1aa2308be5dbb53ddf` |
| SHA-256 | `fdacc304a99402012f5b9e6708344b24ff21d7c79178633a3cde1411bef56960` |
| SHA3-384 | `8d7deb0b2d82e3f1f0fff08f5cbf89edf455b8b1ae3e7f7042fa8ecfb03c2bdc96a4b3bd3c94f6f0e648d15c3435a4a7` |
| TLSH | `T18A83C606BF610FFBEC6BCD3706B91B0525CC651A12B87B3A7534D92CF68A24B49D3864` |
| SSDEEP | `1536:uZFweyTOHoUxFo3kWMImsHLxGmhr1DR2WG:uZFwIoHLxGiwWG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_fdacc304
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdacc304a99402012f5b9e6708344b24ff21d7c79178633a3cde1411bef56960"
    family = "Mirai"
    file_name = "kmpsl"
    file_type = "elf"
    first_seen = "2026-06-21 08:21:32"
  condition:
    hash.sha256(0, filesize) == "fdacc304a99402012f5b9e6708344b24ff21d7c79178633a3cde1411bef56960"
}
```

### Sample 77: `e9c77b34663601ee`

| Field | Value |
|---|---|
| SHA-256 | `e9c77b34663601eeb0f3d89869b935315edfe27e794d572c0be0e1a66fcb6642` |
| Family label | `unknown` |
| File name | `lmips` |
| File type | `elf` |
| First seen | `2026-06-21 08:19:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7efff53c307c52ce0b0c8d4e0e1b062c` |
| SHA-1 | `62fe23dcfae70f7077e98649a85079a57e5d7a98` |
| SHA-256 | `e9c77b34663601eeb0f3d89869b935315edfe27e794d572c0be0e1a66fcb6642` |
| SHA3-384 | `74a1cb1d651392a00d407a63eeb18167c34d62ba7aec9d214efa215e2256b55c2d00763e98aea392e64decfa14d09f27` |
| TLSH | `T1E524B91A6E328F7EF368873047B74A34A75933D626E0D644D1ADD5142F1039E682FFA8` |
| TELFHASH | `t12141af5c0e7817e0a6356c99449dff37d6a330db7e262c278e20e86adb69b835d11c1c` |
| SSDEEP | `3072:V+Isqmt765X/k2c8VaeZyMgiqBczhQgw7oZFb:V+Tt7gs2ciwqq2hQd7mFb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_e9c77b34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9c77b34663601eeb0f3d89869b935315edfe27e794d572c0be0e1a66fcb6642"
    family = "unknown"
    file_name = "lmips"
    file_type = "elf"
    first_seen = "2026-06-21 08:19:42"
  condition:
    hash.sha256(0, filesize) == "e9c77b34663601eeb0f3d89869b935315edfe27e794d572c0be0e1a66fcb6642"
}
```

### Sample 78: `eafdad0e99c594f7`

| Field | Value |
|---|---|
| SHA-256 | `eafdad0e99c594f739c67f38820bfd2f37877b3f6a821d8253b13a954d2c219d` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-06-21 08:19:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `369d5a46897f834ff9b08123f5c22e29` |
| SHA-1 | `bcf6ac24631e0f5eb6d5a1fbb9fd986db6d71a9c` |
| SHA-256 | `eafdad0e99c594f739c67f38820bfd2f37877b3f6a821d8253b13a954d2c219d` |
| SHA3-384 | `f6549c45da159909843d5143e0f47ed1c8698d6091a50b762cebb6cacf2ae0a3ed4bb2834d96977cf09d9dd298123da2` |
| TLSH | `T112016FDA4650A900801A9A5F729765D0B811C3CF464F0B687F9D6D3DFB98904F176F88` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha1tXN1LETLuw187:e9Qp+Ms1tXN1Avuw187` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_eafdad0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eafdad0e99c594f739c67f38820bfd2f37877b3f6a821d8253b13a954d2c219d"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-21 08:19:41"
  condition:
    hash.sha256(0, filesize) == "eafdad0e99c594f739c67f38820bfd2f37877b3f6a821d8253b13a954d2c219d"
}
```

### Sample 79: `0e722e5561626daf`

| Field | Value |
|---|---|
| SHA-256 | `0e722e5561626daf18aa3e633425f181de9fc5d67027d530a8d2219d0e9ca38a` |
| Family label | `Mirai` |
| File name | `data_arm6` |
| File type | `elf` |
| First seen | `2026-06-21 08:15:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f1f8b6c6f777846fa4c9afe479cdcf4` |
| SHA-1 | `800152ae3e51e3ca7e842f31b04d980d3f5190f3` |
| SHA-256 | `0e722e5561626daf18aa3e633425f181de9fc5d67027d530a8d2219d0e9ca38a` |
| SHA3-384 | `744165c947b03e2c642c356b37e568da122236d2f1c42e2f4d0c51dd2e7938fe4444ec499218324f64f4173763a21ca6` |
| TLSH | `T185D32956B9518B12D5C311BAFB9F914D33132FB8E3EE32029D246F60678B8DB0E76512` |
| TELFHASH | `t1e8f0502623544ad99fd16459184f72165a9cfc666f302443aa8c85af4647db2b03c90b` |
| SSDEEP | `3072:kceqK1zb4OZJuVXdul8/a2qHz/ixFi+C9Zad1WqZ0xy5qMpxBj3:kO0X4OZJuVtk8iixY+CbauqUy5RBj3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_0e722e55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e722e5561626daf18aa3e633425f181de9fc5d67027d530a8d2219d0e9ca38a"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-06-21 08:15:40"
  condition:
    hash.sha256(0, filesize) == "0e722e5561626daf18aa3e633425f181de9fc5d67027d530a8d2219d0e9ca38a"
}
```

### Sample 80: `fda6258775198b58`

| Field | Value |
|---|---|
| SHA-256 | `fda6258775198b58c4578ac4305a410ff8a1b3631335e3d86645db79fb9e849b` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-06-21 08:11:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a39806439ca788eb5cfad73ead6c67bd` |
| SHA-1 | `0891d6e9310100cf396b7b829a02e338ebcca6e1` |
| SHA-256 | `fda6258775198b58c4578ac4305a410ff8a1b3631335e3d86645db79fb9e849b` |
| SHA3-384 | `365a71eaf957523f438ad74f56d5cf75789ce16b40e2d356232a5fb88dd4b05b0dc26a19de5268ec181fa09c0536cb77` |
| TLSH | `T12324D709AB610FFBD8AFDE3706E90B0239CC591722A43B793674D928F54A54F19D3C68` |
| SSDEEP | `3072:xYpvBaAhYyw2GfXDBen8egvGSrGvvWYRHIY4jc:xYpvBaA2fbBK87GSCvh2n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_fda62587
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fda6258775198b58c4578ac4305a410ff8a1b3631335e3d86645db79fb9e849b"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-21 08:11:42"
  condition:
    hash.sha256(0, filesize) == "fda6258775198b58c4578ac4305a410ff8a1b3631335e3d86645db79fb9e849b"
}
```

### Sample 81: `88038b3adfe86cd3`

| Field | Value |
|---|---|
| SHA-256 | `88038b3adfe86cd3aebd9a79688fff41b9857685e0224c8e63c217af1f921854` |
| Family label | `Mirai` |
| File name | `data_mips-uclibc` |
| File type | `elf` |
| First seen | `2026-06-21 08:09:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c03f336eba00e851a9508a842160125` |
| SHA-1 | `0bb1a7a691e74c7ad2f4bad23ff06f70ece5e052` |
| SHA-256 | `88038b3adfe86cd3aebd9a79688fff41b9857685e0224c8e63c217af1f921854` |
| SHA3-384 | `aadce3ad9e0bd02a25fee004736aaf19bd0dba9b71f141e661ae9ac87815ecedbbd5a981b78ad154110d8d578b51df3d` |
| TLSH | `T115243B437B324FA0D725D1714BB38F5A59EB11C11EE288E5936CCA103A20BA9685FFF4` |
| TELFHASH | `t12ff01228547c23b4d2c4dc5d55dcff19e8a1d4db99762d27c504c9a9e771e838d00d38` |
| SSDEEP | `3072:Llzk0ofoMHPX+GJX/Cz8r+azDVzaklCzcoJ5Ji2fDJMVitpC/9:l398PX+GAI+az5OklCIoD/fGViS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_88038b3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88038b3adfe86cd3aebd9a79688fff41b9857685e0224c8e63c217af1f921854"
    family = "Mirai"
    file_name = "data_mips-uclibc"
    file_type = "elf"
    first_seen = "2026-06-21 08:09:39"
  condition:
    hash.sha256(0, filesize) == "88038b3adfe86cd3aebd9a79688fff41b9857685e0224c8e63c217af1f921854"
}
```

### Sample 82: `ac2b95c6cdec6e57`

| Field | Value |
|---|---|
| SHA-256 | `ac2b95c6cdec6e5732a80799dfad73c8092f6e91c8ec9be2e02d99e6009f2464` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-06-21 08:07:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28bebd317a061e5baea37a794c130a50` |
| SHA-1 | `00c67904a6305e8419d43afa39800bd01230b9c1` |
| SHA-256 | `ac2b95c6cdec6e5732a80799dfad73c8092f6e91c8ec9be2e02d99e6009f2464` |
| SHA3-384 | `ce5bff24677c64f3c1303968770e3d1759501672476cdfa10b46689b505d5add6fe12630ece9d8eb5782eeaaccb0f790` |
| TLSH | `T1A2F34B16B6C090FDC8DAC1744FDAB136A971F85D0138B21F6B94AF622E1DF316B2D660` |
| TELFHASH | `t1cc51c2701d96798c11d3832a730ee9baf87205225ee270d59f6bb9d4cd43bc81e930d6` |
| SSDEEP | `3072:4y7pmqp7QbNBc03X5T4qU/YnDm8Ie8enEM2H8+GFufF:p7p9MJK035WXe89J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_ac2b95c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac2b95c6cdec6e5732a80799dfad73c8092f6e91c8ec9be2e02d99e6009f2464"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-21 08:07:38"
  condition:
    hash.sha256(0, filesize) == "ac2b95c6cdec6e5732a80799dfad73c8092f6e91c8ec9be2e02d99e6009f2464"
}
```

### Sample 83: `09c9ee2bdfc01916`

| Field | Value |
|---|---|
| SHA-256 | `09c9ee2bdfc0191610aa9ebf5077582e9feca4c368c817f5afb3f84e6574d5d1` |
| Family label | `Mirai` |
| File name | `womp` |
| File type | `sh` |
| First seen | `2026-06-21 08:01:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66b8723c0723ed90f46cab4a3ebc3876` |
| SHA-1 | `aacbf833cdeaf7e0b905c62e643b320f1cdb64f8` |
| SHA-256 | `09c9ee2bdfc0191610aa9ebf5077582e9feca4c368c817f5afb3f84e6574d5d1` |
| SHA3-384 | `a35107cdb5681a3e546600d2d99951376dae7bc7bcb7d17e56e02587ea925c106c775b67e614dc60fb72f2cf4d1c7d7f` |
| TLSH | `T1065123C830EF25756C017D97B11249D4F506F1EB68969F85FC44CEB0C9D6AB6302C798` |
| SSDEEP | `24:Jp8pNI3K3pP2RpKs6p8FNImKuAyRpKW9Wp8Cy0NIakKiS7NXUMuUsRpKPIcdU:FFRpKsoyRpKE4sRpKHU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_09c9ee2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09c9ee2bdfc0191610aa9ebf5077582e9feca4c368c817f5afb3f84e6574d5d1"
    family = "Mirai"
    file_name = "womp"
    file_type = "sh"
    first_seen = "2026-06-21 08:01:44"
  condition:
    hash.sha256(0, filesize) == "09c9ee2bdfc0191610aa9ebf5077582e9feca4c368c817f5afb3f84e6574d5d1"
}
```

### Sample 84: `409f260ddaaf0190`

| Field | Value |
|---|---|
| SHA-256 | `409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-21 07:59:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88c38702d8d4bbcabc9fb8db7f1aae91` |
| SHA-1 | `e579f6195a8338002f390aa8cd1dc8c4933fdb91` |
| SHA-256 | `409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc` |
| SHA3-384 | `1747cc2f78993c6bc7e2540112d00a17cab4205d7d672f7291f4d45db7055039d795bf0a23a4408fe7c17aae55dede17` |
| TLSH | `T171137D6966857C24AE99883B1C7E2F0CB9A983E1310451DDBFCB3CF58C49ADCE21971D` |
| SSDEEP | `768:N+Jx9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:N+cco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_409f260d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-21 07:59:38"
  condition:
    hash.sha256(0, filesize) == "409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc"
}
```

### Sample 85: `2a97e8ffb5cfbbcc`

| Field | Value |
|---|---|
| SHA-256 | `2a97e8ffb5cfbbccd8e2c812fb6f86769ec014692f9bd598ad446c096630d577` |
| Family label | `ValleyRAT` |
| File name | `updater.exe` |
| File type | `exe` |
| First seen | `2026-06-21 07:47:22` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.sa, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5377b90a65cef26fcfd075a0ee2b9822` |
| SHA-1 | `5019d6cfd60cb67191f009f781f772a074b1ce89` |
| SHA-256 | `2a97e8ffb5cfbbccd8e2c812fb6f86769ec014692f9bd598ad446c096630d577` |
| SHA3-384 | `6d909149c7ff6b82f3f5fc09fb1a1536c535d56352de59e1d3a5171ad1a97d4c886a0241b4c66b9df319d12b1dc8599f` |
| IMPHASH | `1063679ca25a505b671b8681ecfc841e` |
| TLSH | `T180948D2AF3A41DF8F82AE178C9565512EA31FC55076096EB33A096252F733D02E3FB51` |
| SSDEEP | `6144:ihgvqWVHEi02wuz2aXG2lNLuZYpV6wmOjfNoZYX/3PfcKrKywXJhm:i2S2HlwKXG2PaoQLOJHdGyqJU` |
| ICON-DHASH | `71d89e9696cce071` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_085_2a97e8ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a97e8ffb5cfbbccd8e2c812fb6f86769ec014692f9bd598ad446c096630d577"
    family = "ValleyRAT"
    file_name = "updater.exe"
    file_type = "exe"
    first_seen = "2026-06-21 07:47:22"
  condition:
    hash.sha256(0, filesize) == "2a97e8ffb5cfbbccd8e2c812fb6f86769ec014692f9bd598ad446c096630d577"
}
```

### Sample 86: `3fccd74f67cb1caa`

| Field | Value |
|---|---|
| SHA-256 | `3fccd74f67cb1caa7a9e972109a104a70303a11e6ad8e9c110381675d59b8a7c` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-06-21 07:45:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9f92b0190b311e5423430dd0bf9a667` |
| SHA-1 | `4b6847b7bf6a008a2f3bf060d862489986aa9517` |
| SHA-256 | `3fccd74f67cb1caa7a9e972109a104a70303a11e6ad8e9c110381675d59b8a7c` |
| SHA3-384 | `591caedab21669804d17ccc4210567ff6edabd0548ed57c2c44ede6555895cd8a66c03cc3c5d9d699f2990d911e5b3ae` |
| TLSH | `T1D7144B46EB804E17C0D62775BAAF83413323DB74D7E773068928ABB43F8679A4E72505` |
| TELFHASH | `t12a21eb01c821cb2e5962a7e89fdc43a64528c35196816f334f3dc5dc553a002ea63cfa` |
| SSDEEP | `6144:/Gq3cybJpIvZaEI7RySmBlKrqcG2NiL/KlzH:/GXybJavZaEI7RySwW5bo/+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_3fccd74f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fccd74f67cb1caa7a9e972109a104a70303a11e6ad8e9c110381675d59b8a7c"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-21 07:45:37"
  condition:
    hash.sha256(0, filesize) == "3fccd74f67cb1caa7a9e972109a104a70303a11e6ad8e9c110381675d59b8a7c"
}
```

### Sample 87: `f7613e56b2271e09`

| Field | Value |
|---|---|
| SHA-256 | `f7613e56b2271e091bcc13b9cdfc451a94d8335f0e377f87dd079d2da7bce6ea` |
| Family label | `Mirai` |
| File name | `data_aarch64` |
| File type | `elf` |
| First seen | `2026-06-21 07:43:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `094ef5b8de929aa37693e2fcc2ee81ca` |
| SHA-1 | `9c863f81318510bbcedd2eb68fab3880932d41ed` |
| SHA-256 | `f7613e56b2271e091bcc13b9cdfc451a94d8335f0e377f87dd079d2da7bce6ea` |
| SHA3-384 | `3ada6e67a72161e2cbc4910970bff4b08bf1a25c2cced2480d9a894a1690d015a6a34b80cb5645eb596041718fd4b5d2` |
| TLSH | `T154E47E9DFE4E3C42E2D7E3789E4987E1621B71E0D32391A33982434DD5C69D9CBE1A21` |
| SSDEEP | `12288:jcDwr0p63dMbjuaUUUcmabqaNcukFWE37+zpbEz9Sw5LdtqA66:oD3p63ruUcmabqlPWAzXwA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_f7613e56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7613e56b2271e091bcc13b9cdfc451a94d8335f0e377f87dd079d2da7bce6ea"
    family = "Mirai"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-06-21 07:43:38"
  condition:
    hash.sha256(0, filesize) == "f7613e56b2271e091bcc13b9cdfc451a94d8335f0e377f87dd079d2da7bce6ea"
}
```

### Sample 88: `d593956ab422b724`

| Field | Value |
|---|---|
| SHA-256 | `d593956ab422b724811177acfdffbeb232ca75a72b9a67acd689f0ce0a3e8799` |
| Family label | `Mirai` |
| File name | `data_mipsel-uclibc` |
| File type | `elf` |
| First seen | `2026-06-21 07:43:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d05ec3a356c7f98f8d981b433020d4b` |
| SHA-1 | `94679ecfaabb140657b3ad6b2efa619d614787d8` |
| SHA-256 | `d593956ab422b724811177acfdffbeb232ca75a72b9a67acd689f0ce0a3e8799` |
| SHA3-384 | `3c80360baa57e61527a61c18b33cfcb874e831176e7733144163144bee34861aed29b3eb1599bab7aa0467f4c53fec7a` |
| TLSH | `T1BF244A43EE890ADFC85BCDF086BE43AB19E7959B49C1F1F4447C8C4C745E28956E3688` |
| SSDEEP | `3072:p2Kx9xI1SO+yrCRFEva4u2AsePFK763NibcuERGPycSSa4d5Vpvf/sjOmOVqD:p2GnIxtVuJsw3GKRGPycV75vcjOmOVq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_d593956a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d593956ab422b724811177acfdffbeb232ca75a72b9a67acd689f0ce0a3e8799"
    family = "Mirai"
    file_name = "data_mipsel-uclibc"
    file_type = "elf"
    first_seen = "2026-06-21 07:43:37"
  condition:
    hash.sha256(0, filesize) == "d593956ab422b724811177acfdffbeb232ca75a72b9a67acd689f0ce0a3e8799"
}
```

### Sample 89: `063697f8cbaedc2a`

| Field | Value |
|---|---|
| SHA-256 | `063697f8cbaedc2a31af56896c9c2f2ef23c1bc5f8d839aa2c304daf8f809926` |
| Family label | `NanoCore` |
| File name | `iiwakashi.com.co.exe` |
| File type | `exe` |
| First seen | `2026-06-21 07:40:04` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe6daf3d6816030d2288947b6c0aa5ed` |
| SHA-1 | `fafb5d550f47c6b808736cda42762d86c8f9a78c` |
| SHA-256 | `063697f8cbaedc2a31af56896c9c2f2ef23c1bc5f8d839aa2c304daf8f809926` |
| SHA3-384 | `71c82da12b796f62f83b36988af8a3c2c2e498ce6ce1dd9572417a4253672116326285a68cdcdee2e94643f7734f095b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F714C0267BA84A2FE2DE85BD612202038379C2E3D8C3F3DE18D455B65F667E546071D3` |
| SSDEEP | `3072:wzEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HIB3fO32vT/T6BQ1bxjOhdiinvt:wLV6Bta6dtJmakIM5KfO32vTj19B+j` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_089_063697f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "063697f8cbaedc2a31af56896c9c2f2ef23c1bc5f8d839aa2c304daf8f809926"
    family = "NanoCore"
    file_name = "iiwakashi.com.co.exe"
    file_type = "exe"
    first_seen = "2026-06-21 07:40:04"
  condition:
    hash.sha256(0, filesize) == "063697f8cbaedc2a31af56896c9c2f2ef23c1bc5f8d839aa2c304daf8f809926"
}
```

### Sample 90: `4af44279693304f1`

| Field | Value |
|---|---|
| SHA-256 | `4af44279693304f1462070d863c57f8f583fbe023685ff27fa61419192cf4ad5` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-21 07:34:30` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b93710525513f2bfcb81d2a7b7c8feb2` |
| SHA-1 | `436ab6e98e3656ef94385eda89c62457424ed06f` |
| SHA-256 | `4af44279693304f1462070d863c57f8f583fbe023685ff27fa61419192cf4ad5` |
| SHA3-384 | `8c2736565be22e8bf889a3e4d874265ae4cc57d34df74ffe6b3bc834bbc5aa8e1654e5c42b1414c1dfe3f0d04a3bf025` |
| TLSH | `T1DE24DA1A6E228F7DF7A8C73447B78A30A75933D626E0D944D1ACD5141F2039E681FFA8` |
| TELFHASH | `t1f24165180d7817f0a6356c4d459dff6bd6a731db7e172c238e50e85aa769b839d10c0c` |
| SSDEEP | `3072:nZmNaAKecRMYNH/GHzsmdFrVZR/W4XohIsRBdO9xAc4:nZ3AKee1UrdBVy43svdSxc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_4af44279
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4af44279693304f1462070d863c57f8f583fbe023685ff27fa61419192cf4ad5"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-21 07:34:30"
  condition:
    hash.sha256(0, filesize) == "4af44279693304f1462070d863c57f8f583fbe023685ff27fa61419192cf4ad5"
}
```

### Sample 91: `d43ae49d93c621bd`

| Field | Value |
|---|---|
| SHA-256 | `d43ae49d93c621bdc22273954dac78d673b08241ff419057dba269a964ee1938` |
| Family label | `Mirai` |
| File name | `karm6` |
| File type | `elf` |
| First seen | `2026-06-21 07:32:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3f56488443ca189f695b5a75e321afd` |
| SHA-1 | `6b3ed17fc5f871ac890ec3a4407698261a753a8a` |
| SHA-256 | `d43ae49d93c621bdc22273954dac78d673b08241ff419057dba269a964ee1938` |
| SHA3-384 | `6b66cf8afe44ae6a3fa231897ed8caab8aaad5f1848e87958a08518f6abad69bc997b7aa16891a4cc4f9e61a3dd30404` |
| TLSH | `T10B73198AB8819B21D2D1227AFE1E118E33231BBCD3DE73169D145F2577CB96B0A37905` |
| TELFHASH | `t15ae07d3b8c4952c842b0038513cd5279539072f8230604978cbd4f4f0030057fe3e03b` |
| SSDEEP | `1536:nLJnETTLNMFM26hpShJqPES2iPdES0xfQJK1al1XHo35MPiXSvMyQmm75EYP:nK6FMHShJqtdEhfQJAarOSvMyQmm7mQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_d43ae49d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d43ae49d93c621bdc22273954dac78d673b08241ff419057dba269a964ee1938"
    family = "Mirai"
    file_name = "karm6"
    file_type = "elf"
    first_seen = "2026-06-21 07:32:32"
  condition:
    hash.sha256(0, filesize) == "d43ae49d93c621bdc22273954dac78d673b08241ff419057dba269a964ee1938"
}
```

### Sample 92: `45ee32938be4c01a`

| Field | Value |
|---|---|
| SHA-256 | `45ee32938be4c01a092ea4d31d8466fa8cd84f1ee856b557cda7cb517c7850de` |
| Family label | `Mirai` |
| File name | `karm` |
| File type | `elf` |
| First seen | `2026-06-21 07:27:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f72ab1e2b39b8a68d4536cfd959f401d` |
| SHA-1 | `e31cc8be2799b066972cfd3163ac136cd25cc9f4` |
| SHA-256 | `45ee32938be4c01a092ea4d31d8466fa8cd84f1ee856b557cda7cb517c7850de` |
| SHA3-384 | `524ca09d6d7aa4b6e97c08be1724315e6f542b2f5fa252ae92fbfc9417102ab37beef946d8bf9cd3874f6c2a99452695` |
| TLSH | `T186633984BC819623C6D5237AFF5E428D372627A8D3EB3207DD164F61378A96B0E37641` |
| TELFHASH | `t1fd41bfb69f980fec7fe0d384468e62698de931f92b00a5668f4c575b86835c1736e423` |
| SSDEEP | `1536:/nbvM0J1E48opWSVxDkDhEvr5xhCL6Tb:/nbvM0J1ERowExwEdxAub` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_45ee3293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45ee32938be4c01a092ea4d31d8466fa8cd84f1ee856b557cda7cb517c7850de"
    family = "Mirai"
    file_name = "karm"
    file_type = "elf"
    first_seen = "2026-06-21 07:27:47"
  condition:
    hash.sha256(0, filesize) == "45ee32938be4c01a092ea4d31d8466fa8cd84f1ee856b557cda7cb517c7850de"
}
```

### Sample 93: `d90a5315668119da`

| Field | Value |
|---|---|
| SHA-256 | `d90a5315668119da380e12a66a7155b0a67a3f9cce49d84e9c8ffeb59199f6b2` |
| Family label | `unknown` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-06-21 07:23:33` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `858e9c1389f67d7c40f4b6bf9c251eb5` |
| SHA-1 | `5de855cb97d10793c13a0093be72d379462e1c46` |
| SHA-256 | `d90a5315668119da380e12a66a7155b0a67a3f9cce49d84e9c8ffeb59199f6b2` |
| SHA3-384 | `5669b2fd13c705099dac83ee3719c503cde19973ca3df9ee9ec004922245f51339af4039864000b84e1157f28b9e626e` |
| TLSH | `T11F041946F9819B15D5D122BAFE1D528E33231B78E2DF72029D246B307B8B96F0E3B505` |
| TELFHASH | `t1c0010210ff482d146be1a094d26465105bb734c869352896be7c9b9fda33ecdfb11c2e` |
| SSDEEP | `3072:5WWp8X12EzaUUc5VHXCBytpfj9l+frpaDqz4aU9tS90MC:4Wp8kEzUc3XfTfjj+j8Dqz4au60` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_d90a5315
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d90a5315668119da380e12a66a7155b0a67a3f9cce49d84e9c8ffeb59199f6b2"
    family = "unknown"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-21 07:23:33"
  condition:
    hash.sha256(0, filesize) == "d90a5315668119da380e12a66a7155b0a67a3f9cce49d84e9c8ffeb59199f6b2"
}
```

### Sample 94: `48e03ec3fc526e27`

| Field | Value |
|---|---|
| SHA-256 | `48e03ec3fc526e27d50fce1757c505acb9cd7dc8df1b98bcd2bf22032368dab3` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-06-21 07:21:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11908ea28e51e99ff4693809b732b275` |
| SHA-1 | `c513c5f6bccf40bed32a541389ab20c94208219b` |
| SHA-256 | `48e03ec3fc526e27d50fce1757c505acb9cd7dc8df1b98bcd2bf22032368dab3` |
| SHA3-384 | `b0a8ae8a56a67c00e3a225a70bd9ab6d7cce130ff084d89b05db8e14b9ca8b5988020eb3b72a809b2f4dcef8f98a4409` |
| TLSH | `T104B2F642730C0957D1676EB5763F2BD193AFAEA021E4F2C0751F9B8A8175E3202D6E8D` |
| SSDEEP | `384:Y21wxQLA3s3CSOjd1n8XXgvQ40yr6GVedgjPZ5Q2xcC6R9YY8Va6ymR6sJ:vKK3unkyrFAa1xcBROpVa6yY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_48e03ec3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48e03ec3fc526e27d50fce1757c505acb9cd7dc8df1b98bcd2bf22032368dab3"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-21 07:21:53"
  condition:
    hash.sha256(0, filesize) == "48e03ec3fc526e27d50fce1757c505acb9cd7dc8df1b98bcd2bf22032368dab3"
}
```

### Sample 95: `f08cd9ef0d20cb57`

| Field | Value |
|---|---|
| SHA-256 | `f08cd9ef0d20cb574b19797ca5005d8bd189bf7a15e880d9bd578b6472b35b6b` |
| Family label | `Mirai` |
| File name | `data_x86` |
| File type | `elf` |
| First seen | `2026-06-21 07:20:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af55f4e398920e1f39da538bad6d778a` |
| SHA-1 | `fabb150ac25e06ce9924c2c378625703db6287b0` |
| SHA-256 | `f08cd9ef0d20cb574b19797ca5005d8bd189bf7a15e880d9bd578b6472b35b6b` |
| SHA3-384 | `8d3ac8563a701301375129257fb91fe9a9885787f82d5398aaafae12c0c86919426aa5f3f7e78d02d6bd4f97d7676d63` |
| TLSH | `T13A157B9DE7C6E0E1F26300F1025EDBF71934A12A9013FAF6EF45266374727916F1A21A` |
| TELFHASH | `t195e158b715b998dcf7e0841182ab7520ce2af12725f0397608f365a16a33e436f76c39` |
| SSDEEP | `24576:/GdkhRfh1uIz/sotx/0c62aoy7pKcpXoD+7X:rhRfh1uIrtxrAHt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_f08cd9ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f08cd9ef0d20cb574b19797ca5005d8bd189bf7a15e880d9bd578b6472b35b6b"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-06-21 07:20:26"
  condition:
    hash.sha256(0, filesize) == "f08cd9ef0d20cb574b19797ca5005d8bd189bf7a15e880d9bd578b6472b35b6b"
}
```

### Sample 96: `8f77f6ddc131d2f1`

| Field | Value |
|---|---|
| SHA-256 | `8f77f6ddc131d2f1fee02db52685543275739c05a179f533e25c57de8fd61fc8` |
| Family label | `Mirai` |
| File name | `data_arm7` |
| File type | `elf` |
| First seen | `2026-06-21 07:18:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e943701e7d42e89f9f5ef09769c2f097` |
| SHA-1 | `96e98c9eb9e915f53509057b27deae4cac15fab7` |
| SHA-256 | `8f77f6ddc131d2f1fee02db52685543275739c05a179f533e25c57de8fd61fc8` |
| SHA3-384 | `f55c01800c89cfdee9cc3c91bca001ffcf8a4237c51afe387bd3da3fc1fc4e85ff3fbbdc77a39f357d5f05406de9572f` |
| TLSH | `T12EE31956B9519F12D5C321FAFB9F914933136FB8E3F93102AD206F60638A99F0E76502` |
| TELFHASH | `t1faf0c0858e9002bd17c510844998465466f1bcb6af2c9446e94dd74fff81dd6703015f` |
| SSDEEP | `3072:MGyexx/+9fguzgvfCelJ6W/LAqjxNW/Fa1m6i0H2uibjCJY2Ol5Dpc3XSL:M8bsfpzgvfVJrjxAFa1m6i0H2u2jCPO/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_8f77f6dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f77f6ddc131d2f1fee02db52685543275739c05a179f533e25c57de8fd61fc8"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-06-21 07:18:32"
  condition:
    hash.sha256(0, filesize) == "8f77f6ddc131d2f1fee02db52685543275739c05a179f533e25c57de8fd61fc8"
}
```

### Sample 97: `f83a89d905554795`

| Field | Value |
|---|---|
| SHA-256 | `f83a89d905554795f50b66809f0183a5c3e335700723e74600e089f1ae3df3c6` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-06-21 07:12:26` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35c3a655cdac9779f6c5d6c3d1276cc4` |
| SHA-1 | `57ddd017abcc0d37a44f8fc521345cf16745036c` |
| SHA-256 | `f83a89d905554795f50b66809f0183a5c3e335700723e74600e089f1ae3df3c6` |
| SHA3-384 | `97b652b9769bd8ab1dee942e515471d6b2e780134a01c8ae00dc84c9311971c960844c2e3c772d4a3fbe49778ddba46b` |
| TLSH | `T1FA3180EF10206A380202D9DE7362264DB41C8AFF2D4BD764DD484FAD868C5987262F89` |
| SSDEEP | `24:OUUGmTE3VHHK/4vxSvI5lmK5/h/n6T5oViYa7+LQ:BmoFHnJSe9VnAoVNo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_f83a89d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f83a89d905554795f50b66809f0183a5c3e335700723e74600e089f1ae3df3c6"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-21 07:12:26"
  condition:
    hash.sha256(0, filesize) == "f83a89d905554795f50b66809f0183a5c3e335700723e74600e089f1ae3df3c6"
}
```

### Sample 98: `96ada74774413c01`

| Field | Value |
|---|---|
| SHA-256 | `96ada74774413c01c0e7d4707d9837bb30dba9132cc3519178e890596f2b5dbd` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-21 07:10:24` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c1469dfe6aed70e8bc529c68216b9ad` |
| SHA-1 | `796bb8aa995056739a6201720f3266da815e92bf` |
| SHA-256 | `96ada74774413c01c0e7d4707d9837bb30dba9132cc3519178e890596f2b5dbd` |
| SHA3-384 | `47ca09a4c00a6c2419558896a4e932730e8f1800a2325750643924eee7d57a4b5f803b2d30cf11830201437fa8c13779` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T12F825B0FB8424726D1E210749276977BDABDA872338414DBFBD489E90A686D6FC3311F` |
| SSDEEP | `384:hIqQ1VaFPte/SZCvBu9JgwHcev4av8U9cNF:FYUIE9r4a0U` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_098_96ada747
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96ada74774413c01c0e7d4707d9837bb30dba9132cc3519178e890596f2b5dbd"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 07:10:24"
  condition:
    hash.sha256(0, filesize) == "96ada74774413c01c0e7d4707d9837bb30dba9132cc3519178e890596f2b5dbd"
}
```

### Sample 99: `29bd3863397ab23a`

| Field | Value |
|---|---|
| SHA-256 | `29bd3863397ab23a61bf44a08f6c936e3592e3792b0755a43b03e73e1a570c12` |
| Family label | `Mirai` |
| File name | `data_arm4` |
| File type | `elf` |
| First seen | `2026-06-21 07:03:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c4933a46a9a19ff105a3eee2289ee7e` |
| SHA-1 | `6d27f93d881c10e049f47a03a796a458285508ff` |
| SHA-256 | `29bd3863397ab23a61bf44a08f6c936e3592e3792b0755a43b03e73e1a570c12` |
| SHA3-384 | `3a347ba9645ecda54819b5323160f91f4986a42b15fcca75135cac44d990490f55aacb70273781ee8356a2fac051bd4b` |
| TLSH | `T110C30A427E429B13C5C311F7FBAE42583B136B79D7EA7102ED24AF91278B8DB0E26511` |
| TELFHASH | `t19cf0ac1aa68c44cd7ac65818d09d515a88f938812bbf3856121dbe0f918f7c2f029522` |
| SSDEEP | `3072:4hbp9+xZJl1rpydHXHFiUrsrdzvZk/pzQ1ORTF2:dxPl1rMlliUSdzvZupaORTF2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_29bd3863
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29bd3863397ab23a61bf44a08f6c936e3592e3792b0755a43b03e73e1a570c12"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-06-21 07:03:28"
  condition:
    hash.sha256(0, filesize) == "29bd3863397ab23a61bf44a08f6c936e3592e3792b0755a43b03e73e1a570c12"
}
```

### Sample 100: `ceff5c70c2fbcc14`

| Field | Value |
|---|---|
| SHA-256 | `ceff5c70c2fbcc14df7c2ae0769e912b7b45fed21b7a4aec664327c9ebffa2f8` |
| Family label | `Mirai` |
| File name | `data_x86_64` |
| File type | `elf` |
| First seen | `2026-06-21 07:01:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26e2afea417339a7a698844edf4aa7d5` |
| SHA-1 | `e52523b027be01051d9eccbbb8dd718c5156490b` |
| SHA-256 | `ceff5c70c2fbcc14df7c2ae0769e912b7b45fed21b7a4aec664327c9ebffa2f8` |
| SHA3-384 | `e9b8e29787a6bb9efe3430fa93607c1190f127f7a6c9762b9f901fce302ad3fd2a72b1e4a8b3cb1a412729b559433fcf` |
| TLSH | `T1B6845B52F1A228FCD952C934825D6223E63874594322ADFB27C8DF753916ED0AF3EB50` |
| TELFHASH | `t16ba12bb1418a65b4c052a4e5cfb2fb32ebba03e593446975422dfd70ed43fb46925c03` |
| SSDEEP | `6144:rJVxUTJNk03VXCyAMq1o1gfQB5nWARit85FxHw/LmjT3fNo8LOvZ+HLEqIPdhS1:rDCnkJyxifQBhWA8gvQsjPLOvIrSPS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_ceff5c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceff5c70c2fbcc14df7c2ae0769e912b7b45fed21b7a4aec664327c9ebffa2f8"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-06-21 07:01:34"
  condition:
    hash.sha256(0, filesize) == "ceff5c70c2fbcc14df7c2ae0769e912b7b45fed21b7a4aec664327c9ebffa2f8"
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
 * Generated: 2026-06-21T16:21:37.404871+00:00
 */

rule MalwareBazaar_unknown_001_95a6eeb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95a6eeb9407cfae94a99df9ca32c3b1858a5d6ff944eff33ad2228a1915c808b"
    family = "unknown"
    file_name = "HMCL-3.13.zip"
    file_type = "zip"
    first_seen = "2026-06-21 16:10:17"
  condition:
    hash.sha256(0, filesize) == "95a6eeb9407cfae94a99df9ca32c3b1858a5d6ff944eff33ad2228a1915c808b"
}

rule MalwareBazaar_NanoCore_002_2011c98d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af"
    family = "NanoCore"
    file_name = "navent.io.exe"
    file_type = "exe"
    first_seen = "2026-06-21 16:10:05"
  condition:
    hash.sha256(0, filesize) == "2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af"
}

rule MalwareBazaar_unknown_003_00e99856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00e99856b30d2f75a452daf1dc13ed02396d38ff975db1f814668b8ff0b52eac"
    family = "unknown"
    file_name = "kworkerd-netns-rt"
    file_type = "elf"
    first_seen = "2026-06-21 16:00:01"
  condition:
    hash.sha256(0, filesize) == "00e99856b30d2f75a452daf1dc13ed02396d38ff975db1f814668b8ff0b52eac"
}

rule MalwareBazaar_AsyncRAT_004_6aa08b6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aa08b6fdb70023bdd14805657a5d4e36b5733b8b4c372c95ce2ec17668a0f11"
    family = "AsyncRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 15:47:49"
  condition:
    hash.sha256(0, filesize) == "6aa08b6fdb70023bdd14805657a5d4e36b5733b8b4c372c95ce2ec17668a0f11"
}

rule MalwareBazaar_unknown_005_dd09d1fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd09d1fc879642e9b72ac07680a36a9f0b18cf31f8283295e7bc9c2456ff54bb"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-21 15:45:35"
  condition:
    hash.sha256(0, filesize) == "dd09d1fc879642e9b72ac07680a36a9f0b18cf31f8283295e7bc9c2456ff54bb"
}

rule MalwareBazaar_unknown_006_05a51382
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05a5138226c9bcda130f95e14b36c083fb4e0a7457a0647f4eba2fa147fd3bf5"
    family = "unknown"
    file_name = "kworkerd-softirq"
    file_type = "elf"
    first_seen = "2026-06-21 15:37:36"
  condition:
    hash.sha256(0, filesize) == "05a5138226c9bcda130f95e14b36c083fb4e0a7457a0647f4eba2fa147fd3bf5"
}

rule MalwareBazaar_unknown_007_0343cc89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0343cc89b06f7a6e45cb7d09f0328821c826d63216265d5d0c0a22902af835d1"
    family = "unknown"
    file_name = "kworkerd"
    file_type = "elf"
    first_seen = "2026-06-21 15:31:37"
  condition:
    hash.sha256(0, filesize) == "0343cc89b06f7a6e45cb7d09f0328821c826d63216265d5d0c0a22902af835d1"
}

rule MalwareBazaar_unknown_008_ea2b1c6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b"
    family = "unknown"
    file_name = "init.sh"
    file_type = "sh"
    first_seen = "2026-06-21 15:27:42"
  condition:
    hash.sha256(0, filesize) == "ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b"
}

rule MalwareBazaar_unknown_009_6e0593be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e0593be7fe7b6a0789e78610de47a3c76c49bf39e66feaeb6c3169390bc1b91"
    family = "unknown"
    file_name = "kworkerd-blkcg"
    file_type = "elf"
    first_seen = "2026-06-21 15:24:36"
  condition:
    hash.sha256(0, filesize) == "6e0593be7fe7b6a0789e78610de47a3c76c49bf39e66feaeb6c3169390bc1b91"
}

rule MalwareBazaar_unknown_010_112035d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "112035d781a0b726569febbff97ded6401462c91b153e31e5bec7386dab34ff0"
    family = "unknown"
    file_name = "kworkerd-blkcg"
    file_type = "elf"
    first_seen = "2026-06-21 15:23:36"
  condition:
    hash.sha256(0, filesize) == "112035d781a0b726569febbff97ded6401462c91b153e31e5bec7386dab34ff0"
}

rule MalwareBazaar_unknown_011_74f5df72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f5df72efa6a4e3e19363f5aa04a2ffb37d86499df7055d1414953ea684f618"
    family = "unknown"
    file_name = "kworkerd-writeback"
    file_type = "elf"
    first_seen = "2026-06-21 15:20:51"
  condition:
    hash.sha256(0, filesize) == "74f5df72efa6a4e3e19363f5aa04a2ffb37d86499df7055d1414953ea684f618"
}

rule MalwareBazaar_unknown_012_b98d8b8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98d8b8f4e73e553bd42bd8afd12d6afc1e5ff38a651f1e6fc3d1186d142a8ef"
    family = "unknown"
    file_name = "kworkerd-writeback"
    file_type = "elf"
    first_seen = "2026-06-21 15:19:33"
  condition:
    hash.sha256(0, filesize) == "b98d8b8f4e73e553bd42bd8afd12d6afc1e5ff38a651f1e6fc3d1186d142a8ef"
}

rule MalwareBazaar_unknown_013_a7990b90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7990b9026200d4d350e6e15750545cd3bb64b52965810807fd1b30bd87c6582"
    family = "unknown"
    file_name = "kworkerd-netns"
    file_type = "elf"
    first_seen = "2026-06-21 15:15:55"
  condition:
    hash.sha256(0, filesize) == "a7990b9026200d4d350e6e15750545cd3bb64b52965810807fd1b30bd87c6582"
}

rule MalwareBazaar_unknown_014_93491105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9349110551754e719b9eaeabc2b692cac6316e032ccb4dce4931ebfb6e291fbb"
    family = "unknown"
    file_name = "kworkerd-netns"
    file_type = "elf"
    first_seen = "2026-06-21 15:15:37"
  condition:
    hash.sha256(0, filesize) == "9349110551754e719b9eaeabc2b692cac6316e032ccb4dce4931ebfb6e291fbb"
}

rule MalwareBazaar_unknown_015_ab4f3bb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab4f3bb1a973fb8ed6eacfad3e0065b3bf541054cd680031948d43fcf8c84667"
    family = "unknown"
    file_name = "kworkerd-irq"
    file_type = "elf"
    first_seen = "2026-06-21 15:05:35"
  condition:
    hash.sha256(0, filesize) == "ab4f3bb1a973fb8ed6eacfad3e0065b3bf541054cd680031948d43fcf8c84667"
}

rule MalwareBazaar_unknown_016_d3bb5688
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3bb5688c6e76be8d010f8ed02ad374b5a03ea7d130f035d32abd4fb6a9bad72"
    family = "unknown"
    file_name = "kworkerd-events"
    file_type = "elf"
    first_seen = "2026-06-21 15:03:35"
  condition:
    hash.sha256(0, filesize) == "d3bb5688c6e76be8d010f8ed02ad374b5a03ea7d130f035d32abd4fb6a9bad72"
}

rule MalwareBazaar_unknown_017_e2aa2802
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2aa280211036f684810d543f375c0d936316411ae4f6c4347baf7527ac3dd31"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-06-21 14:50:54"
  condition:
    hash.sha256(0, filesize) == "e2aa280211036f684810d543f375c0d936316411ae4f6c4347baf7527ac3dd31"
}

rule MalwareBazaar_unknown_018_5c72bdfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c72bdfe8c816a153926f00cb2c34c21352570e00a43df9e0fab939cd5a3889b"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-06-21 14:49:36"
  condition:
    hash.sha256(0, filesize) == "5c72bdfe8c816a153926f00cb2c34c21352570e00a43df9e0fab939cd5a3889b"
}

rule MalwareBazaar_unknown_019_c7709ac8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7709ac88c8be581a74510700227c2783acd350780b2e626946ea88d10bf3e73"
    family = "unknown"
    file_name = "kworkerd-irq-bal"
    file_type = "elf"
    first_seen = "2026-06-21 14:48:35"
  condition:
    hash.sha256(0, filesize) == "c7709ac88c8be581a74510700227c2783acd350780b2e626946ea88d10bf3e73"
}

rule MalwareBazaar_unknown_020_745b2d3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "745b2d3cd229fe218a8869e80100fe60c16ecc788c68a6d093a86291c63ac0cd"
    family = "unknown"
    file_name = "kworkerd-irq-bal"
    file_type = "elf"
    first_seen = "2026-06-21 14:47:35"
  condition:
    hash.sha256(0, filesize) == "745b2d3cd229fe218a8869e80100fe60c16ecc788c68a6d093a86291c63ac0cd"
}

rule MalwareBazaar_Mirai_021_8985fe09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9"
    family = "Mirai"
    file_name = "giga.sh"
    file_type = "sh"
    first_seen = "2026-06-21 14:45:34"
  condition:
    hash.sha256(0, filesize) == "8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9"
}

rule MalwareBazaar_unknown_022_e3c75454
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3c75454d745d76a0e155891e294a02284a0fc2835acf44c68428ad5d6c2e0d3"
    family = "unknown"
    file_name = "kworkerd-scsi"
    file_type = "elf"
    first_seen = "2026-06-21 14:39:35"
  condition:
    hash.sha256(0, filesize) == "e3c75454d745d76a0e155891e294a02284a0fc2835acf44c68428ad5d6c2e0d3"
}

rule MalwareBazaar_Mirai_023_d12cb562
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d12cb562e6401d1d27ed0f880c659ecbfad84bc79d14e8866ca8d98ff601b36d"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-21 14:39:34"
  condition:
    hash.sha256(0, filesize) == "d12cb562e6401d1d27ed0f880c659ecbfad84bc79d14e8866ca8d98ff601b36d"
}

rule MalwareBazaar_unknown_024_a28022c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a28022c27f376c469740569538d1ae3c0837fe952383d0bd2cf5b8f304153f72"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 14:28:13"
  condition:
    hash.sha256(0, filesize) == "a28022c27f376c469740569538d1ae3c0837fe952383d0bd2cf5b8f304153f72"
}

rule MalwareBazaar_unknown_025_76771c0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50"
    family = "unknown"
    file_name = "RFQ-MRF-889-MHS-TLQ-520 # 2600260001.js"
    file_type = "js"
    first_seen = "2026-06-21 14:12:30"
  condition:
    hash.sha256(0, filesize) == "76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50"
}

rule MalwareBazaar_unknown_026_53cdbce7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53cdbce7ef4a497839babe6574569cf65a46ab2b204c0eef3350dfa50cb4a3e0"
    family = "unknown"
    file_name = "CapCut-Template-Pro.exe"
    file_type = "exe"
    first_seen = "2026-06-21 14:11:49"
  condition:
    hash.sha256(0, filesize) == "53cdbce7ef4a497839babe6574569cf65a46ab2b204c0eef3350dfa50cb4a3e0"
}

rule MalwareBazaar_SilentNet_027_0b3581ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b3581ab2acd2099ec8d7de4f77608a0e9a1b7b4810009c7eb1cc4007d30d487"
    family = "SilentNet"
    file_name = "Sulur client.exe"
    file_type = "exe"
    first_seen = "2026-06-21 13:41:10"
  condition:
    hash.sha256(0, filesize) == "0b3581ab2acd2099ec8d7de4f77608a0e9a1b7b4810009c7eb1cc4007d30d487"
}

rule MalwareBazaar_unknown_028_4374049d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4374049d24a766eac84cdd1995bbd236d14956a11123de0402a8cd4669aa0be0"
    family = "unknown"
    file_name = "RFQ#PO - PO25-08-888.vbs"
    file_type = "vbs"
    first_seen = "2026-06-21 13:02:31"
  condition:
    hash.sha256(0, filesize) == "4374049d24a766eac84cdd1995bbd236d14956a11123de0402a8cd4669aa0be0"
}

rule MalwareBazaar_SilentNet_029_54a62444
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54a62444672de4d11e9a3ebd67289f1afc4401d7f7631ac02e404c7d0ca257ca"
    family = "SilentNet"
    file_name = "meteor-client-1.21.11-82.jar"
    file_type = "jar"
    first_seen = "2026-06-21 12:12:24"
  condition:
    hash.sha256(0, filesize) == "54a62444672de4d11e9a3ebd67289f1afc4401d7f7631ac02e404c7d0ca257ca"
}

rule MalwareBazaar_unknown_030_10d1620d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10d1620dbbb762a94bea71602b7f6d3a3167bf5f4e1cd7f3ab49aeac74c2a573"
    family = "unknown"
    file_name = "DonutDupe.jar"
    file_type = "jar"
    first_seen = "2026-06-21 12:05:39"
  condition:
    hash.sha256(0, filesize) == "10d1620dbbb762a94bea71602b7f6d3a3167bf5f4e1cd7f3ab49aeac74c2a573"
}

rule MalwareBazaar_Vidar_031_e5ca4586
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5ca4586785728938cb9de0e964a35bd36dfa534bd7bf47f2438af4a4c2103c2"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 12:04:11"
  condition:
    hash.sha256(0, filesize) == "e5ca4586785728938cb9de0e964a35bd36dfa534bd7bf47f2438af4a4c2103c2"
}

rule MalwareBazaar_unknown_032_bfaa02a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfaa02a0548850aff68591dfaf8934ceb855aaac67c18eb9d12e553f91de60a9"
    family = "unknown"
    file_name = "mod.jar"
    file_type = "jar"
    first_seen = "2026-06-21 12:04:05"
  condition:
    hash.sha256(0, filesize) == "bfaa02a0548850aff68591dfaf8934ceb855aaac67c18eb9d12e553f91de60a9"
}

rule MalwareBazaar_unknown_033_9c5f121e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c5f121e984d76e479ca119499d35efe9402925a2c29b195bff88542c47b0c05"
    family = "unknown"
    file_name = "Exodus.exe"
    file_type = "exe"
    first_seen = "2026-06-21 12:00:31"
  condition:
    hash.sha256(0, filesize) == "9c5f121e984d76e479ca119499d35efe9402925a2c29b195bff88542c47b0c05"
}

rule MalwareBazaar_unknown_034_eb4ebe8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb4ebe8f50e313f917ea49cac37dd5fe6e05dbf095e741c45938632f3bf1558e"
    family = "unknown"
    file_name = "Installer.exe"
    file_type = "exe"
    first_seen = "2026-06-21 11:52:26"
  condition:
    hash.sha256(0, filesize) == "eb4ebe8f50e313f917ea49cac37dd5fe6e05dbf095e741c45938632f3bf1558e"
}

rule MalwareBazaar_AnyDesk_035_5b5434cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b5434cc8bb3556075c6967d2ffee5a6b33793de07b9d4701bc63d369de63861"
    family = "AnyDesk"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 11:50:41"
  condition:
    hash.sha256(0, filesize) == "5b5434cc8bb3556075c6967d2ffee5a6b33793de07b9d4701bc63d369de63861"
}

rule MalwareBazaar_ConnectWise_036_abe7da6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abe7da6b5be41348ce74be00a5158c0fe7dc138051a84f41b1ebc5f9c49b35d6"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-21 10:39:32"
  condition:
    hash.sha256(0, filesize) == "abe7da6b5be41348ce74be00a5158c0fe7dc138051a84f41b1ebc5f9c49b35d6"
}

rule MalwareBazaar_ConnectWise_037_9d7ecd3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d7ecd3a4aeefa449a7313e98a6afab0ea28eb1f693380f2ef5a4c9fe612c5dd"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-21 10:39:31"
  condition:
    hash.sha256(0, filesize) == "9d7ecd3a4aeefa449a7313e98a6afab0ea28eb1f693380f2ef5a4c9fe612c5dd"
}

rule MalwareBazaar_Mirai_038_f2b5721d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b5721d0aaa1d2975cb5d2d8716b7b9ccec1139da2bf467080197a5aae82ae2"
    family = "Mirai"
    file_name = "bot.armv6"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:53"
  condition:
    hash.sha256(0, filesize) == "f2b5721d0aaa1d2975cb5d2d8716b7b9ccec1139da2bf467080197a5aae82ae2"
}

rule MalwareBazaar_unknown_039_70c8c4f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70c8c4f63455ca66b3ec8113a954122a3b31267b6841c43ce163e53b5720b04a"
    family = "unknown"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:52"
  condition:
    hash.sha256(0, filesize) == "70c8c4f63455ca66b3ec8113a954122a3b31267b6841c43ce163e53b5720b04a"
}

rule MalwareBazaar_unknown_040_fd3b9be7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd3b9be7ff9aad82baec194b849cec7478d59cdeec96e3421a372a585e79a70e"
    family = "unknown"
    file_name = "bot.i386"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:50"
  condition:
    hash.sha256(0, filesize) == "fd3b9be7ff9aad82baec194b849cec7478d59cdeec96e3421a372a585e79a70e"
}

rule MalwareBazaar_unknown_041_e00d92ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e00d92ca28a2cfd75e96f71fc0408747f04942657fcab0f2a25ce79bc3ad23a8"
    family = "unknown"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:48"
  condition:
    hash.sha256(0, filesize) == "e00d92ca28a2cfd75e96f71fc0408747f04942657fcab0f2a25ce79bc3ad23a8"
}

rule MalwareBazaar_Mirai_042_2916dbf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2916dbf3063abc63897bc200cff4230287d6f8b72277eb86104c97169f9bdb27"
    family = "Mirai"
    file_name = "bot.armv5l"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:47"
  condition:
    hash.sha256(0, filesize) == "2916dbf3063abc63897bc200cff4230287d6f8b72277eb86104c97169f9bdb27"
}

rule MalwareBazaar_unknown_043_b5d97c5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5d97c5e352ab436643e8bfe1428de72b0dd7616392bd6b0c3bf13a47b7f794c"
    family = "unknown"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:45"
  condition:
    hash.sha256(0, filesize) == "b5d97c5e352ab436643e8bfe1428de72b0dd7616392bd6b0c3bf13a47b7f794c"
}

rule MalwareBazaar_Mirai_044_20a09a7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20a09a7cc48b9c5a181f5100b21cd31b3dd974400602c13c45d6bd3e71162a3a"
    family = "Mirai"
    file_name = "bot.armv7"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:44"
  condition:
    hash.sha256(0, filesize) == "20a09a7cc48b9c5a181f5100b21cd31b3dd974400602c13c45d6bd3e71162a3a"
}

rule MalwareBazaar_Mirai_045_7aa2ae50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7aa2ae501f1572e5957be77dc5d35a580a2697512b80fc39f6c1795463910626"
    family = "Mirai"
    file_name = "bot.armv4"
    file_type = "elf"
    first_seen = "2026-06-21 10:35:42"
  condition:
    hash.sha256(0, filesize) == "7aa2ae501f1572e5957be77dc5d35a580a2697512b80fc39f6c1795463910626"
}

rule MalwareBazaar_ConnectWise_046_077bfdd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "077bfdd22b49adeeb86e80050de6bbf2ca9616279c426e21847f476761cba27d"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-21 10:29:57"
  condition:
    hash.sha256(0, filesize) == "077bfdd22b49adeeb86e80050de6bbf2ca9616279c426e21847f476761cba27d"
}

rule MalwareBazaar_ConnectWise_047_894d32df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "894d32df224ee6fad68f8fa19e50042819e7834edfc985be3369783d63ce95b2"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-21 10:29:57"
  condition:
    hash.sha256(0, filesize) == "894d32df224ee6fad68f8fa19e50042819e7834edfc985be3369783d63ce95b2"
}

rule MalwareBazaar_unknown_048_249512a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "249512a11240bba57171c0b5438b5a4d06ee2d751125957cda54d978c8a474eb"
    family = "unknown"
    file_name = "249512a11240bba57171c0b5438b5a4d06ee2d751125957cda54d978c8a474eb"
    file_type = "unknown"
    first_seen = "2026-06-21 10:00:02"
  condition:
    hash.sha256(0, filesize) == "249512a11240bba57171c0b5438b5a4d06ee2d751125957cda54d978c8a474eb"
}

rule MalwareBazaar_unknown_049_41a9d327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41a9d327fd31b4b512dd4b916db3e0458b5819303d940e56005be135f9872ee3"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-21 09:53:40"
  condition:
    hash.sha256(0, filesize) == "41a9d327fd31b4b512dd4b916db3e0458b5819303d940e56005be135f9872ee3"
}

rule MalwareBazaar_njrat_050_ea5bf6fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea5bf6fd34986ea7ce7e9f9207742a2dad04700f23e25d2e3a861315503f8a2a"
    family = "njrat"
    file_name = "Kjaa.exe"
    file_type = "exe"
    first_seen = "2026-06-21 09:50:56"
  condition:
    hash.sha256(0, filesize) == "ea5bf6fd34986ea7ce7e9f9207742a2dad04700f23e25d2e3a861315503f8a2a"
}

rule MalwareBazaar_unknown_051_1484054d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1484054d6dd4b77d3fbe06b3d8e2bce10714811e94702b5eab6b28e25261b613"
    family = "unknown"
    file_name = "tmph2yxi4at"
    file_type = "unknown"
    first_seen = "2026-06-21 09:48:16"
  condition:
    hash.sha256(0, filesize) == "1484054d6dd4b77d3fbe06b3d8e2bce10714811e94702b5eab6b28e25261b613"
}

rule MalwareBazaar_unknown_052_682d29d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "682d29d3a9b484ca17caa23022b1d04643b46470ad94e5f8184a650527a70f6f"
    family = "unknown"
    file_name = "sleestak_payload_1.zip"
    file_type = "zip"
    first_seen = "2026-06-21 09:47:38"
  condition:
    hash.sha256(0, filesize) == "682d29d3a9b484ca17caa23022b1d04643b46470ad94e5f8184a650527a70f6f"
}

rule MalwareBazaar_unknown_053_699d8fd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "699d8fd14420e9c8bcbd65a3b7208a019933ba2e611ae3356cada3f04609f62c"
    family = "unknown"
    file_name = "699d8fd14420e9c8bcbd65a3b7208a019933ba2e611ae3356cada3f04609f62c"
    file_type = "unknown"
    first_seen = "2026-06-21 09:44:05"
  condition:
    hash.sha256(0, filesize) == "699d8fd14420e9c8bcbd65a3b7208a019933ba2e611ae3356cada3f04609f62c"
}

rule MalwareBazaar_RemcosRAT_054_2dcdb895
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dcdb89527b240984a85645a4a41e4fed7ed33891fd91da07e1f8b62180f2c33"
    family = "RemcosRAT"
    file_name = "2dcdb89527b240984a85645a4a41e4fed7ed33891fd91da07e1f8b62180f2c33"
    file_type = "exe"
    first_seen = "2026-06-21 09:43:55"
  condition:
    hash.sha256(0, filesize) == "2dcdb89527b240984a85645a4a41e4fed7ed33891fd91da07e1f8b62180f2c33"
}

rule MalwareBazaar_RemcosRAT_055_43ee2409
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43ee2409e135916fab34e910035ff437eb1eaa670000c4f0948ba33f11a7083b"
    family = "RemcosRAT"
    file_name = "43ee2409e135916fab34e910035ff437eb1eaa670000c4f0948ba33f11a7083b"
    file_type = "exe"
    first_seen = "2026-06-21 09:42:34"
  condition:
    hash.sha256(0, filesize) == "43ee2409e135916fab34e910035ff437eb1eaa670000c4f0948ba33f11a7083b"
}

rule MalwareBazaar_RemcosRAT_056_daf2410a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
    family = "RemcosRAT"
    file_name = "givewegivingbestsolutionsforbetterplaces.js"
    file_type = "js"
    first_seen = "2026-06-21 09:42:19"
  condition:
    hash.sha256(0, filesize) == "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
}

rule MalwareBazaar_RemcosRAT_057_2b48b4d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d"
    family = "RemcosRAT"
    file_name = "sweetnessgivenmebestthingsforever.hta"
    file_type = "hta"
    first_seen = "2026-06-21 09:41:27"
  condition:
    hash.sha256(0, filesize) == "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d"
}

rule MalwareBazaar_unknown_058_d1acc924
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1acc92471213eb14c54cd89c7de440811cd2293f36279dbedfb8583dc55344c"
    family = "unknown"
    file_name = "050d4043af02c7cfaf00f257f28e8c8313f6f444c843def486fc2141d379da49.zip"
    file_type = "zip"
    first_seen = "2026-06-21 09:41:06"
  condition:
    hash.sha256(0, filesize) == "d1acc92471213eb14c54cd89c7de440811cd2293f36279dbedfb8583dc55344c"
}

rule MalwareBazaar_RemcosRAT_059_f93ff95b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f93ff95b099ee0ae13f3bb4e6b80d3160b0485bb1e4f629be6895442f90355b8"
    family = "RemcosRAT"
    file_name = "Solicitud de presupuesto n.º 490526.xls"
    file_type = "xls"
    first_seen = "2026-06-21 09:40:47"
  condition:
    hash.sha256(0, filesize) == "f93ff95b099ee0ae13f3bb4e6b80d3160b0485bb1e4f629be6895442f90355b8"
}

rule MalwareBazaar_Mirai_060_8abae386
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8abae386ec6aaa1d1bf03e39f339922053e4b66d7ebbbeba15701d3ecc183fb8"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-21 09:37:42"
  condition:
    hash.sha256(0, filesize) == "8abae386ec6aaa1d1bf03e39f339922053e4b66d7ebbbeba15701d3ecc183fb8"
}

rule MalwareBazaar_unknown_061_33b554e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482"
    family = "unknown"
    file_name = "Ciabins.sh"
    file_type = "sh"
    first_seen = "2026-06-21 09:31:48"
  condition:
    hash.sha256(0, filesize) == "33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482"
}

rule MalwareBazaar_unknown_062_2b33df79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b33df7907355444e551355ad0c4aa6f789cf1e3755f43295c4bbf2de02f7eed"
    family = "unknown"
    file_name = "LetsVPN.msi"
    file_type = "msi"
    first_seen = "2026-06-21 09:30:25"
  condition:
    hash.sha256(0, filesize) == "2b33df7907355444e551355ad0c4aa6f789cf1e3755f43295c4bbf2de02f7eed"
}

rule MalwareBazaar_unknown_063_4b416e7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b416e7b71b3a46854f08618d76d1146159d8da5c5061b9336dcf30b50cf6725"
    family = "unknown"
    file_name = "LetsVPN.msi"
    file_type = "msi"
    first_seen = "2026-06-21 09:28:28"
  condition:
    hash.sha256(0, filesize) == "4b416e7b71b3a46854f08618d76d1146159d8da5c5061b9336dcf30b50cf6725"
}

rule MalwareBazaar_unknown_064_a0930154
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a093015413d6d543e3d5d863be6e44b853a2055849df37f8070175aae44d42e0"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-21 09:19:39"
  condition:
    hash.sha256(0, filesize) == "a093015413d6d543e3d5d863be6e44b853a2055849df37f8070175aae44d42e0"
}

rule MalwareBazaar_ConnectWise_065_87c8df8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87c8df8bca39bbb86f4b2bccadb106aa7c3837db4b314694325cb25222c871e5"
    family = "ConnectWise"
    file_name = "File_Summary.msi"
    file_type = "msi"
    first_seen = "2026-06-21 09:17:28"
  condition:
    hash.sha256(0, filesize) == "87c8df8bca39bbb86f4b2bccadb106aa7c3837db4b314694325cb25222c871e5"
}

rule MalwareBazaar_unknown_066_d592ee8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d592ee8eddace6c5e01c80cc9369425559a9e6715104da7db979a5a6aa246a35"
    family = "unknown"
    file_name = "d592ee8eddace6c5e01c80cc9369425559a9e6715104da7db979a5a6aa246a35"
    file_type = "elf"
    first_seen = "2026-06-21 09:01:06"
  condition:
    hash.sha256(0, filesize) == "d592ee8eddace6c5e01c80cc9369425559a9e6715104da7db979a5a6aa246a35"
}

rule MalwareBazaar_unknown_067_57e48ba6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57e48ba67040567734000242541a9eeb4c9dafb008bfede2ade8057c3d9754a5"
    family = "unknown"
    file_name = "57e48ba67040567734000242541a9eeb4c9dafb008bfede2ade8057c3d9754a5"
    file_type = "elf"
    first_seen = "2026-06-21 09:01:03"
  condition:
    hash.sha256(0, filesize) == "57e48ba67040567734000242541a9eeb4c9dafb008bfede2ade8057c3d9754a5"
}

rule MalwareBazaar_Mirai_068_6a05487b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a05487baf63509da9f48302827bdf5b5c239fb1018a42ab6a37b18b0bf100a8"
    family = "Mirai"
    file_name = "b"
    file_type = "elf"
    first_seen = "2026-06-21 08:53:40"
  condition:
    hash.sha256(0, filesize) == "6a05487baf63509da9f48302827bdf5b5c239fb1018a42ab6a37b18b0bf100a8"
}

rule MalwareBazaar_unknown_069_0ac8cf56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ac8cf56f1c5544bac181cc00b36a711333a132be36a05c23714f7d1d76108ee"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-06-21 08:49:40"
  condition:
    hash.sha256(0, filesize) == "0ac8cf56f1c5544bac181cc00b36a711333a132be36a05c23714f7d1d76108ee"
}

rule MalwareBazaar_unknown_070_35e66da4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35e66da427a1ad60fd9de1d0efc5ae98275cea581d21e2aebca59491b936caec"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-21 08:49:39"
  condition:
    hash.sha256(0, filesize) == "35e66da427a1ad60fd9de1d0efc5ae98275cea581d21e2aebca59491b936caec"
}

rule MalwareBazaar_Mirai_071_8235816f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8235816f709e06a15b65b0843704080c3066fa5645f686540905280cfa9d3ce1"
    family = "Mirai"
    file_name = "b"
    file_type = "elf"
    first_seen = "2026-06-21 08:45:43"
  condition:
    hash.sha256(0, filesize) == "8235816f709e06a15b65b0843704080c3066fa5645f686540905280cfa9d3ce1"
}

rule MalwareBazaar_unknown_072_3b92622a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b92622a7ff1323b5c647ac613d0cc78e113edc37acbe495cb060d986454dbf8"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-21 08:23:43"
  condition:
    hash.sha256(0, filesize) == "3b92622a7ff1323b5c647ac613d0cc78e113edc37acbe495cb060d986454dbf8"
}

rule MalwareBazaar_Mirai_073_abc7b3d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abc7b3d5f6d8d04590b60aff1b49b5feeaa22f1b66dcbf8e6de5de28f499a4b6"
    family = "Mirai"
    file_name = "lul.arm5"
    file_type = "elf"
    first_seen = "2026-06-21 08:21:33"
  condition:
    hash.sha256(0, filesize) == "abc7b3d5f6d8d04590b60aff1b49b5feeaa22f1b66dcbf8e6de5de28f499a4b6"
}

rule MalwareBazaar_unknown_074_5a0bc5c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a0bc5c4731aae2c5445ed0cf17aa3a22470496a27d4f330341b5a70645c3c3c"
    family = "unknown"
    file_name = "kmips"
    file_type = "elf"
    first_seen = "2026-06-21 08:21:32"
  condition:
    hash.sha256(0, filesize) == "5a0bc5c4731aae2c5445ed0cf17aa3a22470496a27d4f330341b5a70645c3c3c"
}

rule MalwareBazaar_Mirai_075_bc0b6448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc0b6448957fc6fde56f0c568c36fd0b9ed796cea2bd2a1d2d0c3051bd65f46a"
    family = "Mirai"
    file_name = "lul.arm"
    file_type = "elf"
    first_seen = "2026-06-21 08:21:32"
  condition:
    hash.sha256(0, filesize) == "bc0b6448957fc6fde56f0c568c36fd0b9ed796cea2bd2a1d2d0c3051bd65f46a"
}

rule MalwareBazaar_Mirai_076_fdacc304
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdacc304a99402012f5b9e6708344b24ff21d7c79178633a3cde1411bef56960"
    family = "Mirai"
    file_name = "kmpsl"
    file_type = "elf"
    first_seen = "2026-06-21 08:21:32"
  condition:
    hash.sha256(0, filesize) == "fdacc304a99402012f5b9e6708344b24ff21d7c79178633a3cde1411bef56960"
}

rule MalwareBazaar_unknown_077_e9c77b34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9c77b34663601eeb0f3d89869b935315edfe27e794d572c0be0e1a66fcb6642"
    family = "unknown"
    file_name = "lmips"
    file_type = "elf"
    first_seen = "2026-06-21 08:19:42"
  condition:
    hash.sha256(0, filesize) == "e9c77b34663601eeb0f3d89869b935315edfe27e794d572c0be0e1a66fcb6642"
}

rule MalwareBazaar_unknown_078_eafdad0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eafdad0e99c594f739c67f38820bfd2f37877b3f6a821d8253b13a954d2c219d"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-21 08:19:41"
  condition:
    hash.sha256(0, filesize) == "eafdad0e99c594f739c67f38820bfd2f37877b3f6a821d8253b13a954d2c219d"
}

rule MalwareBazaar_Mirai_079_0e722e55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e722e5561626daf18aa3e633425f181de9fc5d67027d530a8d2219d0e9ca38a"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-06-21 08:15:40"
  condition:
    hash.sha256(0, filesize) == "0e722e5561626daf18aa3e633425f181de9fc5d67027d530a8d2219d0e9ca38a"
}

rule MalwareBazaar_Mirai_080_fda62587
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fda6258775198b58c4578ac4305a410ff8a1b3631335e3d86645db79fb9e849b"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-21 08:11:42"
  condition:
    hash.sha256(0, filesize) == "fda6258775198b58c4578ac4305a410ff8a1b3631335e3d86645db79fb9e849b"
}

rule MalwareBazaar_Mirai_081_88038b3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88038b3adfe86cd3aebd9a79688fff41b9857685e0224c8e63c217af1f921854"
    family = "Mirai"
    file_name = "data_mips-uclibc"
    file_type = "elf"
    first_seen = "2026-06-21 08:09:39"
  condition:
    hash.sha256(0, filesize) == "88038b3adfe86cd3aebd9a79688fff41b9857685e0224c8e63c217af1f921854"
}

rule MalwareBazaar_Mirai_082_ac2b95c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac2b95c6cdec6e5732a80799dfad73c8092f6e91c8ec9be2e02d99e6009f2464"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-21 08:07:38"
  condition:
    hash.sha256(0, filesize) == "ac2b95c6cdec6e5732a80799dfad73c8092f6e91c8ec9be2e02d99e6009f2464"
}

rule MalwareBazaar_Mirai_083_09c9ee2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09c9ee2bdfc0191610aa9ebf5077582e9feca4c368c817f5afb3f84e6574d5d1"
    family = "Mirai"
    file_name = "womp"
    file_type = "sh"
    first_seen = "2026-06-21 08:01:44"
  condition:
    hash.sha256(0, filesize) == "09c9ee2bdfc0191610aa9ebf5077582e9feca4c368c817f5afb3f84e6574d5d1"
}

rule MalwareBazaar_unknown_084_409f260d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-21 07:59:38"
  condition:
    hash.sha256(0, filesize) == "409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc"
}

rule MalwareBazaar_ValleyRAT_085_2a97e8ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a97e8ffb5cfbbccd8e2c812fb6f86769ec014692f9bd598ad446c096630d577"
    family = "ValleyRAT"
    file_name = "updater.exe"
    file_type = "exe"
    first_seen = "2026-06-21 07:47:22"
  condition:
    hash.sha256(0, filesize) == "2a97e8ffb5cfbbccd8e2c812fb6f86769ec014692f9bd598ad446c096630d577"
}

rule MalwareBazaar_Mirai_086_3fccd74f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fccd74f67cb1caa7a9e972109a104a70303a11e6ad8e9c110381675d59b8a7c"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-21 07:45:37"
  condition:
    hash.sha256(0, filesize) == "3fccd74f67cb1caa7a9e972109a104a70303a11e6ad8e9c110381675d59b8a7c"
}

rule MalwareBazaar_Mirai_087_f7613e56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7613e56b2271e091bcc13b9cdfc451a94d8335f0e377f87dd079d2da7bce6ea"
    family = "Mirai"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-06-21 07:43:38"
  condition:
    hash.sha256(0, filesize) == "f7613e56b2271e091bcc13b9cdfc451a94d8335f0e377f87dd079d2da7bce6ea"
}

rule MalwareBazaar_Mirai_088_d593956a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d593956ab422b724811177acfdffbeb232ca75a72b9a67acd689f0ce0a3e8799"
    family = "Mirai"
    file_name = "data_mipsel-uclibc"
    file_type = "elf"
    first_seen = "2026-06-21 07:43:37"
  condition:
    hash.sha256(0, filesize) == "d593956ab422b724811177acfdffbeb232ca75a72b9a67acd689f0ce0a3e8799"
}

rule MalwareBazaar_NanoCore_089_063697f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "063697f8cbaedc2a31af56896c9c2f2ef23c1bc5f8d839aa2c304daf8f809926"
    family = "NanoCore"
    file_name = "iiwakashi.com.co.exe"
    file_type = "exe"
    first_seen = "2026-06-21 07:40:04"
  condition:
    hash.sha256(0, filesize) == "063697f8cbaedc2a31af56896c9c2f2ef23c1bc5f8d839aa2c304daf8f809926"
}

rule MalwareBazaar_unknown_090_4af44279
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4af44279693304f1462070d863c57f8f583fbe023685ff27fa61419192cf4ad5"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-21 07:34:30"
  condition:
    hash.sha256(0, filesize) == "4af44279693304f1462070d863c57f8f583fbe023685ff27fa61419192cf4ad5"
}

rule MalwareBazaar_Mirai_091_d43ae49d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d43ae49d93c621bdc22273954dac78d673b08241ff419057dba269a964ee1938"
    family = "Mirai"
    file_name = "karm6"
    file_type = "elf"
    first_seen = "2026-06-21 07:32:32"
  condition:
    hash.sha256(0, filesize) == "d43ae49d93c621bdc22273954dac78d673b08241ff419057dba269a964ee1938"
}

rule MalwareBazaar_Mirai_092_45ee3293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45ee32938be4c01a092ea4d31d8466fa8cd84f1ee856b557cda7cb517c7850de"
    family = "Mirai"
    file_name = "karm"
    file_type = "elf"
    first_seen = "2026-06-21 07:27:47"
  condition:
    hash.sha256(0, filesize) == "45ee32938be4c01a092ea4d31d8466fa8cd84f1ee856b557cda7cb517c7850de"
}

rule MalwareBazaar_unknown_093_d90a5315
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d90a5315668119da380e12a66a7155b0a67a3f9cce49d84e9c8ffeb59199f6b2"
    family = "unknown"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-21 07:23:33"
  condition:
    hash.sha256(0, filesize) == "d90a5315668119da380e12a66a7155b0a67a3f9cce49d84e9c8ffeb59199f6b2"
}

rule MalwareBazaar_Mirai_094_48e03ec3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48e03ec3fc526e27d50fce1757c505acb9cd7dc8df1b98bcd2bf22032368dab3"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-21 07:21:53"
  condition:
    hash.sha256(0, filesize) == "48e03ec3fc526e27d50fce1757c505acb9cd7dc8df1b98bcd2bf22032368dab3"
}

rule MalwareBazaar_Mirai_095_f08cd9ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f08cd9ef0d20cb574b19797ca5005d8bd189bf7a15e880d9bd578b6472b35b6b"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-06-21 07:20:26"
  condition:
    hash.sha256(0, filesize) == "f08cd9ef0d20cb574b19797ca5005d8bd189bf7a15e880d9bd578b6472b35b6b"
}

rule MalwareBazaar_Mirai_096_8f77f6dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f77f6ddc131d2f1fee02db52685543275739c05a179f533e25c57de8fd61fc8"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-06-21 07:18:32"
  condition:
    hash.sha256(0, filesize) == "8f77f6ddc131d2f1fee02db52685543275739c05a179f533e25c57de8fd61fc8"
}

rule MalwareBazaar_unknown_097_f83a89d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f83a89d905554795f50b66809f0183a5c3e335700723e74600e089f1ae3df3c6"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-21 07:12:26"
  condition:
    hash.sha256(0, filesize) == "f83a89d905554795f50b66809f0183a5c3e335700723e74600e089f1ae3df3c6"
}

rule MalwareBazaar_Phorpiex_098_96ada747
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96ada74774413c01c0e7d4707d9837bb30dba9132cc3519178e890596f2b5dbd"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-21 07:10:24"
  condition:
    hash.sha256(0, filesize) == "96ada74774413c01c0e7d4707d9837bb30dba9132cc3519178e890596f2b5dbd"
}

rule MalwareBazaar_Mirai_099_29bd3863
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29bd3863397ab23a61bf44a08f6c936e3592e3792b0755a43b03e73e1a570c12"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-06-21 07:03:28"
  condition:
    hash.sha256(0, filesize) == "29bd3863397ab23a61bf44a08f6c936e3592e3792b0755a43b03e73e1a570c12"
}

rule MalwareBazaar_Mirai_100_ceff5c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceff5c70c2fbcc14df7c2ae0769e912b7b45fed21b7a4aec664327c9ebffa2f8"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-06-21 07:01:34"
  condition:
    hash.sha256(0, filesize) == "ceff5c70c2fbcc14df7c2ae0769e912b7b45fed21b7a4aec664327c9ebffa2f8"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

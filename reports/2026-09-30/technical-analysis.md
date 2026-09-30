# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-30

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 658 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 658 |
| Unique family labels | 10 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 62 |
| unknown | 28 |
| VShell | 3 |
| ConnectWise | 1 |
| AsyncRAT | 1 |
| Expiro | 1 |
| SalatStealer | 1 |
| RemcosRAT | 1 |
| Panchan | 1 |
| GuLoader | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 67 |
| exe | 18 |
| zip | 6 |
| js | 3 |
| sh | 2 |
| vbs | 2 |
| jar | 1 |
| zsh | 1 |

## Per-Sample Analysis

### Sample 1: `2f97c02e4b1ab2df`

| Field | Value |
|---|---|
| SHA-256 | `2f97c02e4b1ab2df51d41f7a7381eae1d32c235e5713872ce44da7cf2674b919` |
| Family label | `unknown` |
| File name | `stub.armv7l` |
| File type | `elf` |
| First seen | `2026-09-30 05:39:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8ccb0862981ebfba7b07d1aff3f9d9c` |
| SHA-1 | `789547f788a6082c1082677f4440c35b83e43b50` |
| SHA-256 | `2f97c02e4b1ab2df51d41f7a7381eae1d32c235e5713872ce44da7cf2674b919` |
| SHA3-384 | `1946a00ef49e41c3ecf3f70ffe0803817275c12394243532b798bd83c491e57aabcf9249929e691d002246ebb612967a` |
| TLSH | `T112D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKiq:YCp7mXtni6aBh321eSiVWKx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_2f97c02e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f97c02e4b1ab2df51d41f7a7381eae1d32c235e5713872ce44da7cf2674b919"
    family = "unknown"
    file_name = "stub.armv7l"
    file_type = "elf"
    first_seen = "2026-09-30 05:39:39"
  condition:
    hash.sha256(0, filesize) == "2f97c02e4b1ab2df51d41f7a7381eae1d32c235e5713872ce44da7cf2674b919"
}
```

### Sample 2: `ab17364d33e70a69`

| Field | Value |
|---|---|
| SHA-256 | `ab17364d33e70a6957e35317cc25b730c5d74bb4bc9eb7329c714d96c69dc8c8` |
| Family label | `unknown` |
| File name | `stub.arm7n` |
| File type | `elf` |
| First seen | `2026-09-30 05:39:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b12f7f6652f7296af852653e4f815373` |
| SHA-1 | `add59a285d1ba3f42b64869f609409339a1557b5` |
| SHA-256 | `ab17364d33e70a6957e35317cc25b730c5d74bb4bc9eb7329c714d96c69dc8c8` |
| SHA3-384 | `3a868ef820d34facd047ab730875e3ca0dbfbd97ace7a6a0b78e8436700b6684ac924a4ced773010fc62dfae9a1e7c90` |
| TLSH | `T182D44A55F8809F63C9C52A36F64E866833274778C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKiA:YCp7mXtni6aBh321eSiVWK9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_ab17364d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab17364d33e70a6957e35317cc25b730c5d74bb4bc9eb7329c714d96c69dc8c8"
    family = "unknown"
    file_name = "stub.arm7n"
    file_type = "elf"
    first_seen = "2026-09-30 05:39:37"
  condition:
    hash.sha256(0, filesize) == "ab17364d33e70a6957e35317cc25b730c5d74bb4bc9eb7329c714d96c69dc8c8"
}
```

### Sample 3: `e4cf87d31ce05e09`

| Field | Value |
|---|---|
| SHA-256 | `e4cf87d31ce05e0909033a02b3ea34379467b15d964615c02762313dc80c86a7` |
| Family label | `Mirai` |
| File name | `stub.armv7l` |
| File type | `elf` |
| First seen | `2026-09-30 05:35:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6cfbd71824179199fcc3405a9d297dc` |
| SHA-1 | `e10cf1139a86c0d0b2293cde9e3750df3e851765` |
| SHA-256 | `e4cf87d31ce05e0909033a02b3ea34379467b15d964615c02762313dc80c86a7` |
| SHA3-384 | `ad5a0573a0ab6d3151f06c1d474dd6fcdab135af6422a3c0cba8a6c5b7bffec7d3052ce0eb9d5b38b91a9fb2f0c10642` |
| TLSH | `T1D3D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKiJ:YCp7mXtni6aBh321eSiVWK6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_e4cf87d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4cf87d31ce05e0909033a02b3ea34379467b15d964615c02762313dc80c86a7"
    family = "Mirai"
    file_name = "stub.armv7l"
    file_type = "elf"
    first_seen = "2026-09-30 05:35:35"
  condition:
    hash.sha256(0, filesize) == "e4cf87d31ce05e0909033a02b3ea34379467b15d964615c02762313dc80c86a7"
}
```

### Sample 4: `67b17ca00fbade53`

| Field | Value |
|---|---|
| SHA-256 | `67b17ca00fbade5328efd11825f3db4539466074bfcaa0edc38e12aecca222ad` |
| Family label | `Mirai` |
| File name | `bot.mips64el` |
| File type | `elf` |
| First seen | `2026-09-30 05:31:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfb0322d57ef09a4663545359af93b75` |
| SHA-1 | `8c0b38e80efc63227a69b833126d8f329b5df128` |
| SHA-256 | `67b17ca00fbade5328efd11825f3db4539466074bfcaa0edc38e12aecca222ad` |
| SHA3-384 | `a6b90b0002f6167e783abda6aa05bf1f8326227868dd711708b1dd736e946236648a40df93c760d082cc18f6b9c27101` |
| TLSH | `T11D355C46EF406FEBC49FCD30492EC31721EDE8CB42D5A62971BC4A8C7A5D3590AD3698` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:ApvR6ZM35dQ4ZmHd7dcCoLJTxwpTmVXxTCnOKW8/:Y6QS97FixxxxTCnz/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_67b17ca0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67b17ca00fbade5328efd11825f3db4539466074bfcaa0edc38e12aecca222ad"
    family = "Mirai"
    file_name = "bot.mips64el"
    file_type = "elf"
    first_seen = "2026-09-30 05:31:44"
  condition:
    hash.sha256(0, filesize) == "67b17ca00fbade5328efd11825f3db4539466074bfcaa0edc38e12aecca222ad"
}
```

### Sample 5: `0794992cacb05667`

| Field | Value |
|---|---|
| SHA-256 | `0794992cacb0566792c0a3d5caf01122aa0015fbb014abb512b09eb8b3a53bff` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-09-30 05:31:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4090d1a8ccb826f8588bf6963685e279` |
| SHA-1 | `6adb3d44438c86283024e2e855e00434a0b1744c` |
| SHA-256 | `0794992cacb0566792c0a3d5caf01122aa0015fbb014abb512b09eb8b3a53bff` |
| SHA3-384 | `46fe3c38dac76b30fdb13742c9cdbcdb00bc899c7e75f6e76d18a3ec1530a30180c3550204b7a8e908c640fad2a4d842` |
| TLSH | `T14BC4A047A77A18A0C4E680B4A5E207FC8597828F56F7F5DBCF4AD9D2B925491332C3C2` |
| SSDEEP | `6144:Dt4eP90kSlNw16rS3XUHcyq9Y1Vdubj28g1Vf2sS4HinrCzpyQdZtjI0A/qX:JYg1620HI9I8bj2RfcleVI9/W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_0794992c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0794992cacb0566792c0a3d5caf01122aa0015fbb014abb512b09eb8b3a53bff"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-09-30 05:31:42"
  condition:
    hash.sha256(0, filesize) == "0794992cacb0566792c0a3d5caf01122aa0015fbb014abb512b09eb8b3a53bff"
}
```

### Sample 6: `495565141e708a35`

| Field | Value |
|---|---|
| SHA-256 | `495565141e708a35526c564e32a76a5bb9de1a6aaddf6d05ae59c0565b66d6e8` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-09-30 05:31:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e06f6aa01bd3b040951a3b14f99aebf` |
| SHA-1 | `7529f9ac3a68da27102513d1c1511807a05f1af5` |
| SHA-256 | `495565141e708a35526c564e32a76a5bb9de1a6aaddf6d05ae59c0565b66d6e8` |
| SHA3-384 | `6212fafaa97b75282df0b6ced072491bfe4f0616f159b587a9b0223303a1bbd381a9bfcd29ab310d5206c29e02ef151e` |
| TLSH | `T19FB49E03A6B7E8B1D4A142B1215557B95572C9B315B7E88FEFE52D80DE602C0F32C3AB` |
| TELFHASH | `t162f1aeb22abe0edc77d0a902c20a2b22ed1ad67359d435b248f3619932b3f415f71c35` |
| SSDEEP | `6144:nYjU6FiPSKVPbaXbMYfIL+6BSz8IEUwAJ/9A55BnzyU5hZdw9gOHY6Eppn:nYjU64JDIESVr2zyU5hZdwqO1EDn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_49556514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "495565141e708a35526c564e32a76a5bb9de1a6aaddf6d05ae59c0565b66d6e8"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-09-30 05:31:40"
  condition:
    hash.sha256(0, filesize) == "495565141e708a35526c564e32a76a5bb9de1a6aaddf6d05ae59c0565b66d6e8"
}
```

### Sample 7: `219b6a17cc639618`

| Field | Value |
|---|---|
| SHA-256 | `219b6a17cc6396182eb34177940893c511bf02d9e08f99fa6246e63b1b10f7e9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-30 05:28:30` |
| Reporter | `Bitsight` |
| Tags | `BB2.file, dropped-by-GCleaner, exe, F` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87e18d77c64296f29b634cfb0d63f0b4` |
| SHA-1 | `5b36ca6e385be7bcaeb4b2ffeeabd76942bfa1ec` |
| SHA-256 | `219b6a17cc6396182eb34177940893c511bf02d9e08f99fa6246e63b1b10f7e9` |
| SHA3-384 | `e3fb3c688b2b533303fc184dfa5c3a67e14cfc9b59ee6403125ea34ba23cc26baf3de8920756229c951a7af124086022` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T118162319DBE400FDF1769174CD534D17E776BC4853B1AA8F03A1AAA64F233909E3AB12` |
| SSDEEP | `98304:rKAVvbQWjzFPlmFGxILt56te1ssxPCYuDQmZvvT:rdvbQYNiGxIt5v2gMT7` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_219b6a17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "219b6a17cc6396182eb34177940893c511bf02d9e08f99fa6246e63b1b10f7e9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 05:28:30"
  condition:
    hash.sha256(0, filesize) == "219b6a17cc6396182eb34177940893c511bf02d9e08f99fa6246e63b1b10f7e9"
}
```

### Sample 8: `174dbc02039af436`

| Field | Value |
|---|---|
| SHA-256 | `174dbc02039af436613f492a86073791d364334bc645ffbbc4236e9a62d32032` |
| Family label | `Mirai` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-09-30 05:23:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12d8982f4082705548942ab983c2085d` |
| SHA-1 | `f9cf56032a0ff331314ababcdc556e1bc1596c4f` |
| SHA-256 | `174dbc02039af436613f492a86073791d364334bc645ffbbc4236e9a62d32032` |
| SHA3-384 | `9cffdd6a653566fcbbb306e251e6e33f85ad2344f6dd476e54d28879cf87142f6643c935d3ecdc8496933f744129955e` |
| TLSH | `T167C47C03AAF7E9B5F4A280B1115617B54523D977257BD88BDBD62C90DE201C0E32E3BE` |
| TELFHASH | `t116025ab33afd0eed73d0a902c20a2b26dd49d67759d035b209f7659523b2e429e71c38` |
| SSDEEP | `6144:pyg6gDLbmo4f4mVmtLXp02cvywfwZW3YHbXTwM1QyeMJsO:Rv/bssdxcvyYwZIM1QydsO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_174dbc02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "174dbc02039af436613f492a86073791d364334bc645ffbbc4236e9a62d32032"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-09-30 05:23:49"
  condition:
    hash.sha256(0, filesize) == "174dbc02039af436613f492a86073791d364334bc645ffbbc4236e9a62d32032"
}
```

### Sample 9: `73094f400276795d`

| Field | Value |
|---|---|
| SHA-256 | `73094f400276795deb15f6297d58528e024138ab1b2dd57005d4108f89d7253b` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-30 05:23:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c8200c2cc5b7276d3c5c5c3f6c15e9a` |
| SHA-1 | `90cbf64f15ffeee687ee88a64ea6cc831c28406a` |
| SHA-256 | `73094f400276795deb15f6297d58528e024138ab1b2dd57005d4108f89d7253b` |
| SHA3-384 | `cd79ee65d6d3d04fdea8e22501cff63e3f46fc6542e1baa1b24ede989f2dab11a6ecf778f93bff10fda2c624b694ea83` |
| TLSH | `T1AA05E70B6E32DF7EF579C3308BF34B74969962D626E1C584E19CD20C5E2028A651F7AC` |
| TELFHASH | `t1e1a126a9183413a4ab649c4d4a9dff36c9a234ef3e151c239f50e85ee72fa835e10c1d` |
| SSDEEP | `12288:/SM0PzJhCm70RfmDqIKhHVnfk6JHbxQ2qOKf35:/SMcq3fVJHbe2qFJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_73094f40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73094f400276795deb15f6297d58528e024138ab1b2dd57005d4108f89d7253b"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-30 05:23:47"
  condition:
    hash.sha256(0, filesize) == "73094f400276795deb15f6297d58528e024138ab1b2dd57005d4108f89d7253b"
}
```

### Sample 10: `5295617257bfc7b3`

| Field | Value |
|---|---|
| SHA-256 | `5295617257bfc7b31e3e72429a683e1d69b7bf9383620dffa56754ce851d0864` |
| Family label | `Mirai` |
| File name | `bot.armv7` |
| File type | `elf` |
| First seen | `2026-09-30 05:23:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ad345b75613d31e4890bf4ad65bf35b` |
| SHA-1 | `86ef01b8f10e2829d96312a947dc9e4a3c5ed7bc` |
| SHA-256 | `5295617257bfc7b31e3e72429a683e1d69b7bf9383620dffa56754ce851d0864` |
| SHA3-384 | `45a86eb3e47326809b2c7348cb83ca28c39610d6d96d08386f14e55ece34b746170870fe340d83e50703d379b4e338c8` |
| TLSH | `T156254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmVA:KdM4DmUj657yDAmVA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_52956172
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5295617257bfc7b31e3e72429a683e1d69b7bf9383620dffa56754ce851d0864"
    family = "Mirai"
    file_name = "bot.armv7"
    file_type = "elf"
    first_seen = "2026-09-30 05:23:46"
  condition:
    hash.sha256(0, filesize) == "5295617257bfc7b31e3e72429a683e1d69b7bf9383620dffa56754ce851d0864"
}
```

### Sample 11: `51411125ed12a9da`

| Field | Value |
|---|---|
| SHA-256 | `51411125ed12a9dae114511b4b7c5f0e8ee14b8cab86f92647d6dbbc450114c5` |
| Family label | `Mirai` |
| File name | `stub.x86_64` |
| File type | `elf` |
| First seen | `2026-09-30 05:19:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c9a0d116eb6d1728555e64ca940fcdf` |
| SHA-1 | `5cfcdd645327344ff6330152d0f637f7f476bf8a` |
| SHA-256 | `51411125ed12a9dae114511b4b7c5f0e8ee14b8cab86f92647d6dbbc450114c5` |
| SHA3-384 | `7fe16e2ba2ab3f2d540f3aac43bddcbe8ac1521eb8c98ae280be3a2afbe66b5b534dc5264f6b62fe62bc68075267d5ce` |
| TLSH | `T115157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/j:7NP46S4QVs7l6A5Zji59k0jZz06FYRsy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_51411125
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51411125ed12a9dae114511b4b7c5f0e8ee14b8cab86f92647d6dbbc450114c5"
    family = "Mirai"
    file_name = "stub.x86_64"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:53"
  condition:
    hash.sha256(0, filesize) == "51411125ed12a9dae114511b4b7c5f0e8ee14b8cab86f92647d6dbbc450114c5"
}
```

### Sample 12: `d5017febf2f9b128`

| Field | Value |
|---|---|
| SHA-256 | `d5017febf2f9b128d2fa5c575202bf2bb3efaf3c861734d4889278bb6b2b1f96` |
| Family label | `Mirai` |
| File name | `stub.armv8` |
| File type | `elf` |
| First seen | `2026-09-30 05:19:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1af088dcc4de3ae073f2e27623c96a03` |
| SHA-1 | `7910fdb9f2aa45bd0f49dbb93b50b4514433075d` |
| SHA-256 | `d5017febf2f9b128d2fa5c575202bf2bb3efaf3c861734d4889278bb6b2b1f96` |
| SHA3-384 | `e53f7becaaaffb0f1080718ceede82c082d39b43c751dcbf2bf7523eeccfeedce8d6c3dd1544c4bbc6aec8b1898102fe` |
| TLSH | `T19CF46C5DFD5F3D43C2C6E23ADB8AC3957227B0D8D61311A321C1021DE6CADAD8B5299E` |
| SSDEEP | `12288:qaOMNE5N3B76xF+y0ZdNd7JOSwa5YAmdlStnWtVfkHzO:qaReBKRU9r1aOnQfkHy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_d5017feb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5017febf2f9b128d2fa5c575202bf2bb3efaf3c861734d4889278bb6b2b1f96"
    family = "Mirai"
    file_name = "stub.armv8"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:52"
  condition:
    hash.sha256(0, filesize) == "d5017febf2f9b128d2fa5c575202bf2bb3efaf3c861734d4889278bb6b2b1f96"
}
```

### Sample 13: `1004a859d6e65095`

| Field | Value |
|---|---|
| SHA-256 | `1004a859d6e6509559172c2bb9a68549cc06688660dac750d7e1d4c343f927d3` |
| Family label | `Mirai` |
| File name | `stub.mips64` |
| File type | `elf` |
| First seen | `2026-09-30 05:19:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46671b688606e0985ea506394b81902c` |
| SHA-1 | `7f0b40efc4e6585791acce712412672aed77c640` |
| SHA-256 | `1004a859d6e6509559172c2bb9a68549cc06688660dac750d7e1d4c343f927d3` |
| SHA3-384 | `40e01fa2a8c5976aea26b0ec5899df56f30363a00ce6c073bb2022240a32ee225a527a3a9bc7bc828c59e6b452b8c39f` |
| TLSH | `T123F48D273B21DF65D355D67049F3C7914AE920A20AE340D6B268C3287E61B2D2D9FFE4` |
| SSDEEP | `12288:4EO7hT7XQRW4tWl9B11U+bs/w7iGtgpiGGhQi3BF1PNMBHUJTxVN:o7Vh4t+9B1do/w7iG+SQiZa0JTxn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_1004a859
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1004a859d6e6509559172c2bb9a68549cc06688660dac750d7e1d4c343f927d3"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:50"
  condition:
    hash.sha256(0, filesize) == "1004a859d6e6509559172c2bb9a68549cc06688660dac750d7e1d4c343f927d3"
}
```

### Sample 14: `1ecb01adec3af303`

| Field | Value |
|---|---|
| SHA-256 | `1ecb01adec3af3032989adfb1e79e0eb82d450430c6a868901e801e076dce030` |
| Family label | `Mirai` |
| File name | `stub.armv6` |
| File type | `elf` |
| First seen | `2026-09-30 05:19:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44007bd4def4da09db3523109aa96e50` |
| SHA-1 | `30dee019832596b5e4fa7dd0489744ef9228525a` |
| SHA-256 | `1ecb01adec3af3032989adfb1e79e0eb82d450430c6a868901e801e076dce030` |
| SHA3-384 | `04ee7c3f64553d008181ef169b81c12084c5eb03da7004966051d0881d43f49b52e63fb1f01c33a6d7f9f4c9b24a7fb5` |
| TLSH | `T178D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKid:YCp7mXtni6aBh321eSiVWKE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_1ecb01ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ecb01adec3af3032989adfb1e79e0eb82d450430c6a868901e801e076dce030"
    family = "Mirai"
    file_name = "stub.armv6"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:48"
  condition:
    hash.sha256(0, filesize) == "1ecb01adec3af3032989adfb1e79e0eb82d450430c6a868901e801e076dce030"
}
```

### Sample 15: `69b17e5f3531dc3f`

| Field | Value |
|---|---|
| SHA-256 | `69b17e5f3531dc3fa8e7d1ca4fe516ef5a575ff1d8a47ccecd17be8337d3be2c` |
| Family label | `Mirai` |
| File name | `stub.x86-64` |
| File type | `elf` |
| First seen | `2026-09-30 05:19:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2033c429cdd149246f628e9c3c6aecb0` |
| SHA-1 | `2aab61316bf3ef137a820f3f224d2470f4c0bf12` |
| SHA-256 | `69b17e5f3531dc3fa8e7d1ca4fe516ef5a575ff1d8a47ccecd17be8337d3be2c` |
| SHA3-384 | `cf979cd5f49f2f13710b892fc97df52401da3a2f108fa31ef2fa1e8180b673f1b518f126a1d3e552e7dbf45391c6dc93` |
| TLSH | `T10B157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/C:7NP46S4QVs7l6A5Zji59k0jZz06FYRsF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_69b17e5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69b17e5f3531dc3fa8e7d1ca4fe516ef5a575ff1d8a47ccecd17be8337d3be2c"
    family = "Mirai"
    file_name = "stub.x86-64"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:46"
  condition:
    hash.sha256(0, filesize) == "69b17e5f3531dc3fa8e7d1ca4fe516ef5a575ff1d8a47ccecd17be8337d3be2c"
}
```

### Sample 16: `00a1018204242147`

| Field | Value |
|---|---|
| SHA-256 | `00a1018204242147be0620ed850d74409a1e0da7fb991849740ca15a530b04ba` |
| Family label | `Mirai` |
| File name | `stub.armv6l` |
| File type | `elf` |
| First seen | `2026-09-30 05:19:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44b53114f7e103edcc75498613ea3220` |
| SHA-1 | `9ea5a5079d5ac0fd61c4f024ba91a8bd3ce82985` |
| SHA-256 | `00a1018204242147be0620ed850d74409a1e0da7fb991849740ca15a530b04ba` |
| SHA3-384 | `4676045356610786b6a580186cd79423be98611d0c56f5bc6d7ebe191150abf30800cb89e517ff7987f04d319b3d366d` |
| TLSH | `T1AED44A55F8809F63C9C52A36F64E826833274778C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKil:YCp7mXtni6aBh321eSiVWK4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_00a10182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00a1018204242147be0620ed850d74409a1e0da7fb991849740ca15a530b04ba"
    family = "Mirai"
    file_name = "stub.armv6l"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:44"
  condition:
    hash.sha256(0, filesize) == "00a1018204242147be0620ed850d74409a1e0da7fb991849740ca15a530b04ba"
}
```

### Sample 17: `b00d16792a16077d`

| Field | Value |
|---|---|
| SHA-256 | `b00d16792a16077d0a3e0a16149c1c7c0dc70ddf0147cea7c155c6f2dfa55032` |
| Family label | `Mirai` |
| File name | `stub.i486` |
| File type | `elf` |
| First seen | `2026-09-30 05:19:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1de9333d54dbb6a0003bb85865370c1a` |
| SHA-1 | `d2e963af37447f4acf6e060f8429fb2757bfd75a` |
| SHA-256 | `b00d16792a16077d0a3e0a16149c1c7c0dc70ddf0147cea7c155c6f2dfa55032` |
| SHA3-384 | `9eeefb87b7ea8bb53f4e1db0cc0ccff65e373403c03fe303130cbddb9a50649140faf4ee7a66309d0d09e88cc9947412` |
| TLSH | `T189157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/m:7NP46S4QVs7l6A5Zji59k0jZz06FYRsv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_b00d1679
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b00d16792a16077d0a3e0a16149c1c7c0dc70ddf0147cea7c155c6f2dfa55032"
    family = "Mirai"
    file_name = "stub.i486"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:43"
  condition:
    hash.sha256(0, filesize) == "b00d16792a16077d0a3e0a16149c1c7c0dc70ddf0147cea7c155c6f2dfa55032"
}
```

### Sample 18: `c07ab9f66f39cb14`

| Field | Value |
|---|---|
| SHA-256 | `c07ab9f66f39cb1423c8cc72782f3c5254c116bab2e239673eefbc54948659b9` |
| Family label | `Mirai` |
| File name | `c07ab9f66f39cb1423c8cc72782f3c5254c116bab2e239673eefbc54948659b9` |
| File type | `elf` |
| First seen | `2026-09-30 05:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7a0b926ca306c9d5a030e33500cd82f` |
| SHA-1 | `108fe1cf054bc06482098ac434b09b7b18100ab1` |
| SHA-256 | `c07ab9f66f39cb1423c8cc72782f3c5254c116bab2e239673eefbc54948659b9` |
| SHA3-384 | `560206863d409dacb574196f79c7cf9aee61827ebdbe4fc6085c1772aa84ae7a2e4d380d56486d2dc540230107fddf7b` |
| TLSH | `T1F644398AFD80AF25D5C5267BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJf:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_c07ab9f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c07ab9f66f39cb1423c8cc72782f3c5254c116bab2e239673eefbc54948659b9"
    family = "Mirai"
    file_name = "c07ab9f66f39cb1423c8cc72782f3c5254c116bab2e239673eefbc54948659b9"
    file_type = "elf"
    first_seen = "2026-09-30 05:17:14"
  condition:
    hash.sha256(0, filesize) == "c07ab9f66f39cb1423c8cc72782f3c5254c116bab2e239673eefbc54948659b9"
}
```

### Sample 19: `d9d8ea56ef343d1e`

| Field | Value |
|---|---|
| SHA-256 | `d9d8ea56ef343d1e63fa5665ecd1084e60f65c0fe9a471ac8f357c597e3613e1` |
| Family label | `Mirai` |
| File name | `bot.x86-64` |
| File type | `elf` |
| First seen | `2026-09-30 05:15:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5cd73d7f84a597f11e6e32a640302b05` |
| SHA-1 | `4e5592b5f9f8321684bbbbfb18e87d63b1396e48` |
| SHA-256 | `d9d8ea56ef343d1e63fa5665ecd1084e60f65c0fe9a471ac8f357c597e3613e1` |
| SHA3-384 | `fa6ad6c3fea217a8bf206b6585a29261f9351768d008231187db8abe9e2e6c9660b987aae01ae10b06ba6b57634a68fc` |
| TLSH | `T165355C5BB2B374BCC557C834839BDA62BD35B46502226E7BB5C4CA302E26D702719F72` |
| TELFHASH | `t1d3e16b754ff934b862d6ca24b352f0769a33142b66ec35f52612ad98ef40fc04c6682b` |
| SSDEEP | `24576:FtmY2nvov46dWqbb+VXu5C6wGRTiY8mUMh8Utu+MBF:6BAv46dYXuo6lixmUMdkvBF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_d9d8ea56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9d8ea56ef343d1e63fa5665ecd1084e60f65c0fe9a471ac8f357c597e3613e1"
    family = "Mirai"
    file_name = "bot.x86-64"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:43"
  condition:
    hash.sha256(0, filesize) == "d9d8ea56ef343d1e63fa5665ecd1084e60f65c0fe9a471ac8f357c597e3613e1"
}
```

### Sample 20: `a50900a3111e7f56`

| Field | Value |
|---|---|
| SHA-256 | `a50900a3111e7f5632717a37b19091deb5fefb0e57c2bbcde1930620ec995ec5` |
| Family label | `Mirai` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-09-30 05:15:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a87bf120ad168822589048592944073b` |
| SHA-1 | `a4d05a41f3d8694ca39b10648c7a11ca9b502f7a` |
| SHA-256 | `a50900a3111e7f5632717a37b19091deb5fefb0e57c2bbcde1930620ec995ec5` |
| SHA3-384 | `0f6f0e4044480b340aa18138d6c9ac5f886cf93096ac064a3482cef72841312500780a702df6ec4720fdf5da51c65caf` |
| TLSH | `T1FB355C5BB2B374BCC557C834839BDA62BD35B46502226E7BB5C4CA302E26D702719F72` |
| TELFHASH | `t1d3e16b754ff934b862d6ca24b352f0769a33142b66ec35f52612ad98ef40fc04c6682b` |
| SSDEEP | `24576:FtmY2nvov46dWqbb+VXu5C6wGRTiY8mUMh8Utu+MBK:6BAv46dYXuo6lixmUMdkvBK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_a50900a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a50900a3111e7f5632717a37b19091deb5fefb0e57c2bbcde1930620ec995ec5"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:42"
  condition:
    hash.sha256(0, filesize) == "a50900a3111e7f5632717a37b19091deb5fefb0e57c2bbcde1930620ec995ec5"
}
```

### Sample 21: `ac5d62a69da73a6c`

| Field | Value |
|---|---|
| SHA-256 | `ac5d62a69da73a6c6c62fa5f6fa2a77226a34568e84fcd5cc9461e18b521a758` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-09-30 05:15:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8b5c63c566b49515fbc42c231f80aa7` |
| SHA-1 | `fee5698316e940839714267a076002efe3ba4465` |
| SHA-256 | `ac5d62a69da73a6c6c62fa5f6fa2a77226a34568e84fcd5cc9461e18b521a758` |
| SHA3-384 | `5bc7769149604cf156f1428981949cd6067d9a351ecb5ad0fdd64a190a1b26b7478b8c544cd750e81079b6e898d926d4` |
| TLSH | `T139D46C56BD919B91C6E24ABBFBAE4368731357B9D2FF7006CA045F9037DA4C10A3E241` |
| TELFHASH | `t1fef0e1e68d8404ec71c112d8f0fea2097a15bcb77e1044d05dadec4f80528df307440c` |
| SSDEEP | `12288:iJJqmmLB92rIcT8lsP/zJ0vKo4H3JfMAQAuxR8GFA9Qe:EqmmPlcT8lsP/zJ0vKmp1FA9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_ac5d62a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac5d62a69da73a6c6c62fa5f6fa2a77226a34568e84fcd5cc9461e18b521a758"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:40"
  condition:
    hash.sha256(0, filesize) == "ac5d62a69da73a6c6c62fa5f6fa2a77226a34568e84fcd5cc9461e18b521a758"
}
```

### Sample 22: `10ebb20474532eec`

| Field | Value |
|---|---|
| SHA-256 | `10ebb20474532eec4293732cc3639c3c61b7a6e5247024c65230818adcc5a433` |
| Family label | `Mirai` |
| File name | `stub.aarch64_be` |
| File type | `elf` |
| First seen | `2026-09-30 05:15:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e430cf35278932186ffed09de0666c18` |
| SHA-1 | `08695b1c51e1fcb4330c6a437f4c7d9f61f52a8b` |
| SHA-256 | `10ebb20474532eec4293732cc3639c3c61b7a6e5247024c65230818adcc5a433` |
| SHA3-384 | `efd7aef8d885f4dab656e4acc5c8e458b00577f59a53b73a1c6886b11fa6f775d17ebf2d5b1cea890176d7831053f5e2` |
| TLSH | `T1D3F46C5DFD5F3D43C2C6E23ADB8AC3947227B0D8D61311A321C1021DE6CADAD8B5299E` |
| SSDEEP | `12288:qaOMNE5N3B76xF+y0ZdNd7JOSwa5YAmdlStnWtVfkHz9:qaReBKRU9r1aOnQfkHR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_10ebb204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10ebb20474532eec4293732cc3639c3c61b7a6e5247024c65230818adcc5a433"
    family = "Mirai"
    file_name = "stub.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:38"
  condition:
    hash.sha256(0, filesize) == "10ebb20474532eec4293732cc3639c3c61b7a6e5247024c65230818adcc5a433"
}
```

### Sample 23: `8f887f787a74418d`

| Field | Value |
|---|---|
| SHA-256 | `8f887f787a74418da051d03f591b7b08664550eb8fed9f1642d977f606ef7eaa` |
| Family label | `Mirai` |
| File name | `stub.armv5tel` |
| File type | `elf` |
| First seen | `2026-09-30 05:15:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29717913fff3da8c7648cc380a063dab` |
| SHA-1 | `d02f1d2e27f8a7d7fadd1b9510507f00c75742ed` |
| SHA-256 | `8f887f787a74418da051d03f591b7b08664550eb8fed9f1642d977f606ef7eaa` |
| SHA3-384 | `0d7413d32dd5db557ed2614b7a77aefecbbaa064b040b32aff6f2dd3b7c272f0fc18f996a1a9068859f8dbde89222b22` |
| TLSH | `T1B2D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKid:YCp7mXtni6aBh321eSiVWKm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_8f887f78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f887f787a74418da051d03f591b7b08664550eb8fed9f1642d977f606ef7eaa"
    family = "Mirai"
    file_name = "stub.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:36"
  condition:
    hash.sha256(0, filesize) == "8f887f787a74418da051d03f591b7b08664550eb8fed9f1642d977f606ef7eaa"
}
```

### Sample 24: `18062a5140b7f348`

| Field | Value |
|---|---|
| SHA-256 | `18062a5140b7f3488e2a63d3fea56f1065169f45759eedf0f310c2c316f2c2c6` |
| Family label | `Mirai` |
| File name | `bot.armv7l` |
| File type | `elf` |
| First seen | `2026-09-30 05:15:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c83b8192103aa3209afd8b319fc9d3dc` |
| SHA-1 | `affa7fe06c29526ca306d94fb13578e02cc89870` |
| SHA-256 | `18062a5140b7f3488e2a63d3fea56f1065169f45759eedf0f310c2c316f2c2c6` |
| SHA3-384 | `c4827d1be318d927b646fcf2de8db9f49d4a42a78790387e7be837dacc92c47cbe55f32d3f3ab06487e05df11fb7cc8a` |
| TLSH | `T107254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmh:KdM4DmUj657yDAmh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_18062a51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18062a5140b7f3488e2a63d3fea56f1065169f45759eedf0f310c2c316f2c2c6"
    family = "Mirai"
    file_name = "bot.armv7l"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:34"
  condition:
    hash.sha256(0, filesize) == "18062a5140b7f3488e2a63d3fea56f1065169f45759eedf0f310c2c316f2c2c6"
}
```

### Sample 25: `de6ab4878d659cbf`

| Field | Value |
|---|---|
| SHA-256 | `de6ab4878d659cbf6c912429800d335086f70f9a1a54b6475a12b8a4334d1fe9` |
| Family label | `Mirai` |
| File name | `bot.armv5l` |
| File type | `elf` |
| First seen | `2026-09-30 05:15:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `819458d455acd2e6c8dbdb5e5a534ae3` |
| SHA-1 | `791e1f7cc98694a792d492496ec61ff4a4a3a785` |
| SHA-256 | `de6ab4878d659cbf6c912429800d335086f70f9a1a54b6475a12b8a4334d1fe9` |
| SHA3-384 | `b71a90a74240e1a58e7418a0861e2fb44f732e2fa2297a112c73b1463da2068b142ae4dcf5e0d9140bb1481586616bc5` |
| TLSH | `T1DA254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmo:KdM4DmUj657yDAmo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_de6ab487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de6ab4878d659cbf6c912429800d335086f70f9a1a54b6475a12b8a4334d1fe9"
    family = "Mirai"
    file_name = "bot.armv5l"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:32"
  condition:
    hash.sha256(0, filesize) == "de6ab4878d659cbf6c912429800d335086f70f9a1a54b6475a12b8a4334d1fe9"
}
```

### Sample 26: `f5fd7750c893af2e`

| Field | Value |
|---|---|
| SHA-256 | `f5fd7750c893af2e8805bc5aef4541200272d043a22efb6b87c59a816ce905a8` |
| Family label | `unknown` |
| File name | `f5fd7750c893af2e8805bc5aef4541200272d043a22efb6b87c59a816ce905a8.bin` |
| File type | `zip` |
| First seen | `2026-09-30 05:13:08` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f53702cda1ef8bdc630a911fdf70310` |
| SHA-1 | `396702b9ace51343958673d2df2c17ee36a613ad` |
| SHA-256 | `f5fd7750c893af2e8805bc5aef4541200272d043a22efb6b87c59a816ce905a8` |
| SHA3-384 | `be3f9c9b553b3565db75ac4567317ccc0aa57d248657a505fd6c5fd85c7ddc35122b6c9241b672c2260a478f45090b3e` |
| TLSH | `T168B31232080B4912D01D1F4BEAE5E61922FBA1C3676B51CB293689F33DB9E4E05DD53E` |
| SSDEEP | `1536:IB8Lhb4gZkQrMQb6XFEs0hWFY39RhDqY1O8a2RDkHa8C4pRhYgyF/lgXuUJLinhD:fpyQr5mc6av1LRDclhYp9UZLeVTPmS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_f5fd7750
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5fd7750c893af2e8805bc5aef4541200272d043a22efb6b87c59a816ce905a8"
    family = "unknown"
    file_name = "f5fd7750c893af2e8805bc5aef4541200272d043a22efb6b87c59a816ce905a8.bin"
    file_type = "zip"
    first_seen = "2026-09-30 05:13:08"
  condition:
    hash.sha256(0, filesize) == "f5fd7750c893af2e8805bc5aef4541200272d043a22efb6b87c59a816ce905a8"
}
```

### Sample 27: `ebbfe99f9be30859`

| Field | Value |
|---|---|
| SHA-256 | `ebbfe99f9be30859d9948d905222769c8f8d690158e1baaaad14088e39adf282` |
| Family label | `unknown` |
| File name | `ebbfe99f9be30859d9948d905222769c8f8d690158e1baaaad14088e39adf282.bin` |
| File type | `zip` |
| First seen | `2026-09-30 05:13:05` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae4a137eef84b98bc738841d96250d1b` |
| SHA-1 | `c45131c966c8f7780a21c8565a1937568b23d144` |
| SHA-256 | `ebbfe99f9be30859d9948d905222769c8f8d690158e1baaaad14088e39adf282` |
| SHA3-384 | `2a3b37624d7b9358082aa6a6b1509454b531250c131e9e3467303753727454f34586a0e3e48a98bf82f4f2f67b4324b1` |
| TLSH | `T1DCC17EBD593AB49DF52FA1F24D6E33DC0D141369034D49831C3DAA04BB796E18D05D27` |
| SSDEEP | `96:KtGnx4Rs6Z3f7yWB350za0NcNeuCBB3nqFgREdA9Syq+3cm2ieHaDIWqB/KiTf8F:KtGnx0s6ZT4a0q2B9nqORKqqQYHaDIW/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_ebbfe99f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebbfe99f9be30859d9948d905222769c8f8d690158e1baaaad14088e39adf282"
    family = "unknown"
    file_name = "ebbfe99f9be30859d9948d905222769c8f8d690158e1baaaad14088e39adf282.bin"
    file_type = "zip"
    first_seen = "2026-09-30 05:13:05"
  condition:
    hash.sha256(0, filesize) == "ebbfe99f9be30859d9948d905222769c8f8d690158e1baaaad14088e39adf282"
}
```

### Sample 28: `4f67e0b3cfcf0297`

| Field | Value |
|---|---|
| SHA-256 | `4f67e0b3cfcf0297cd4cbc6449abf39962d2c40981bfd8f23a832b634e075a4a` |
| Family label | `unknown` |
| File name | `4f67e0b3cfcf0297cd4cbc6449abf39962d2c40981bfd8f23a832b634e075a4a.bin` |
| File type | `zip` |
| First seen | `2026-09-30 05:12:01` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28fddd561924e2e2eab44cb95d76c3c6` |
| SHA-1 | `201810d06f3cb22ea6826440f57eae537a5845f1` |
| SHA-256 | `4f67e0b3cfcf0297cd4cbc6449abf39962d2c40981bfd8f23a832b634e075a4a` |
| SHA3-384 | `6d2a24d5b71d18d820f93eb010aeed8736def1ccc1dcdef28e797fb37ac36887ccdd896948a070709836a6c327cea557` |
| TLSH | `T144F4231642BB84B9EDCB727E18307B21B4F74C4F3F818B6D925C2D6ADE81858261D723` |
| SSDEEP | `12288:WMw/q3g8ojlPL8/IQSJXux3paQO16ydOc9Wo3Frr5d6XiO/nTf23WUAr4pIgtcYQ:Nud35NRJo3pa716jmxrPWzn4AUKUcd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_4f67e0b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f67e0b3cfcf0297cd4cbc6449abf39962d2c40981bfd8f23a832b634e075a4a"
    family = "unknown"
    file_name = "4f67e0b3cfcf0297cd4cbc6449abf39962d2c40981bfd8f23a832b634e075a4a.bin"
    file_type = "zip"
    first_seen = "2026-09-30 05:12:01"
  condition:
    hash.sha256(0, filesize) == "4f67e0b3cfcf0297cd4cbc6449abf39962d2c40981bfd8f23a832b634e075a4a"
}
```

### Sample 29: `5e491de9a7635dc3`

| Field | Value |
|---|---|
| SHA-256 | `5e491de9a7635dc3a57305b9d4c48d7efc8187b1f995acb5e4fa785736a01d22` |
| Family label | `Mirai` |
| File name | `bot.i486` |
| File type | `elf` |
| First seen | `2026-09-30 05:11:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4b9244695eb2921e2af6a16e1bd2ed5` |
| SHA-1 | `1a0d971d2805d7b0e9b9e4c0195125b2fb2681a3` |
| SHA-256 | `5e491de9a7635dc3a57305b9d4c48d7efc8187b1f995acb5e4fa785736a01d22` |
| SHA3-384 | `aad79f53403c1922b03a125416645380c8b8b6c23c56fe41009bd1730b862b8c96b650be4570060bfdcfb8ad6e9e6677` |
| TLSH | `T1A5355C5BB2B374BCC557C834839BDA62BD35B46502226E7BB5C4CA302E26D702719F72` |
| TELFHASH | `t1d3e16b754ff934b862d6ca24b352f0769a33142b66ec35f52612ad98ef40fc04c6682b` |
| SSDEEP | `24576:FtmY2nvov46dWqbb+VXu5C6wGRTiY8mUMh8Utu+MBj:6BAv46dYXuo6lixmUMdkvBj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_5e491de9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e491de9a7635dc3a57305b9d4c48d7efc8187b1f995acb5e4fa785736a01d22"
    family = "Mirai"
    file_name = "bot.i486"
    file_type = "elf"
    first_seen = "2026-09-30 05:11:35"
  condition:
    hash.sha256(0, filesize) == "5e491de9a7635dc3a57305b9d4c48d7efc8187b1f995acb5e4fa785736a01d22"
}
```

### Sample 30: `f94bfad5371c9a30`

| Field | Value |
|---|---|
| SHA-256 | `f94bfad5371c9a30334f4149c4de23009dabeed9b6b69462236e2e60db1aacb1` |
| Family label | `Mirai` |
| File name | `bot.armv6l` |
| File type | `elf` |
| First seen | `2026-09-30 05:11:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b72c15ff6c034851aaac54c1feca0552` |
| SHA-1 | `619fc08bf52354fe1c8121892c7a918f8a97a97e` |
| SHA-256 | `f94bfad5371c9a30334f4149c4de23009dabeed9b6b69462236e2e60db1aacb1` |
| SHA3-384 | `8db8af08739a16daf7b5808c78d12f99c0c4027664a2f302a246b2d6d4ff61e42768a3c2f05d7f35baeef94676f38717` |
| TLSH | `T140254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmk:KdM4DmUj657yDAmk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_f94bfad5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f94bfad5371c9a30334f4149c4de23009dabeed9b6b69462236e2e60db1aacb1"
    family = "Mirai"
    file_name = "bot.armv6l"
    file_type = "elf"
    first_seen = "2026-09-30 05:11:34"
  condition:
    hash.sha256(0, filesize) == "f94bfad5371c9a30334f4149c4de23009dabeed9b6b69462236e2e60db1aacb1"
}
```

### Sample 31: `b8345cf70594c263`

| Field | Value |
|---|---|
| SHA-256 | `b8345cf70594c26324e6a416a2e460a6849f08a50ed901772db61eb80750726a` |
| Family label | `unknown` |
| File name | `b8345cf70594c26324e6a416a2e460a6849f08a50ed901772db61eb80750726a.bin` |
| File type | `zip` |
| First seen | `2026-09-30 05:11:16` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c350d3f293a7988ed9eaa2e4e0230002` |
| SHA-1 | `dde5ddb1e41b6efe140d0016f4007bf7f897c05e` |
| SHA-256 | `b8345cf70594c26324e6a416a2e460a6849f08a50ed901772db61eb80750726a` |
| SHA3-384 | `2a52b6c9c872d2a8445d5a73126894e57dc6f4421cbbe97e59bea14ae36afa3de5edf081b7548a4001d1690632cf43c3` |
| TLSH | `T1031633516EB7F169225F61F88086845AE4E330A13D2055F637FF4EE18BCD5E26B09CB2` |
| SSDEEP | `98304:UcZDIm6EsTDTDAaRyT/XjOlRRqnfnILa4fxdD0i3G4m0IC:LZD1byZIrK6nfmT7fmXC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_b8345cf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8345cf70594c26324e6a416a2e460a6849f08a50ed901772db61eb80750726a"
    family = "unknown"
    file_name = "b8345cf70594c26324e6a416a2e460a6849f08a50ed901772db61eb80750726a.bin"
    file_type = "zip"
    first_seen = "2026-09-30 05:11:16"
  condition:
    hash.sha256(0, filesize) == "b8345cf70594c26324e6a416a2e460a6849f08a50ed901772db61eb80750726a"
}
```

### Sample 32: `427bf5324d720898`

| Field | Value |
|---|---|
| SHA-256 | `427bf5324d72089825d253b3515c0d3615cf65623ff59705ad3b2d6a347bc4b5` |
| Family label | `unknown` |
| File name | `427bf5324d72089825d253b3515c0d3615cf65623ff59705ad3b2d6a347bc4b5.bin` |
| File type | `zip` |
| First seen | `2026-09-30 05:10:57` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdb5b1c351ef0edfef254ff89a173fd6` |
| SHA-1 | `ff6733409e27565058ee84ec556e3f6cc8ffdcd0` |
| SHA-256 | `427bf5324d72089825d253b3515c0d3615cf65623ff59705ad3b2d6a347bc4b5` |
| SHA3-384 | `c9277f5064a029dbe01c40a3bfc3ec1e561b9279b83c0936fe4a782fe345754afa31ba650d5234469a1434d2f9da6918` |
| TLSH | `T1E2B31240A919A8248A2FFD76307888E2D524015060EEFE5F8FF5DF9E45571C0EED83AB` |
| SSDEEP | `3072:vTySkDZ+RJlMn6w92zijjeUv9UmPuLTLLF:vGDFybS6Ojij0UvB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_427bf532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "427bf5324d72089825d253b3515c0d3615cf65623ff59705ad3b2d6a347bc4b5"
    family = "unknown"
    file_name = "427bf5324d72089825d253b3515c0d3615cf65623ff59705ad3b2d6a347bc4b5.bin"
    file_type = "zip"
    first_seen = "2026-09-30 05:10:57"
  condition:
    hash.sha256(0, filesize) == "427bf5324d72089825d253b3515c0d3615cf65623ff59705ad3b2d6a347bc4b5"
}
```

### Sample 33: `af3c3bc1808903b8`

| Field | Value |
|---|---|
| SHA-256 | `af3c3bc1808903b8c5efdfd6f7817c400f6c3652e22cea7ef46345877a59342a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-30 05:10:35` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, exe, payload_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62871e8ea0450cad9d40e37e370f2a0c` |
| SHA-1 | `c30cb6d8126bd458873ec13b58ccacbcb622d594` |
| SHA-256 | `af3c3bc1808903b8c5efdfd6f7817c400f6c3652e22cea7ef46345877a59342a` |
| SHA3-384 | `9079022b621b4447f6333a54671c439e1b7c77cad04ea2cf793e64707ad8e746b95cf3cf50645cd60fb6bee335205128` |
| IMPHASH | `bc31e60555f837ccfb8dd9fe80ff231d` |
| TLSH | `T1CF86B72592080395F539E3BE1AD97BB97B147F28B0340419F7DE6993A513DA0E3F43A8` |
| SSDEEP | `49152:FEYHbpJTUDUmrit5QfY4406YcNYyi3Ut3a46hr0T2aWYWc70LkrKhnx+U/j25t/c:vwg10PcRi3Ut376pEWDLTn` |
| ICON-DHASH | `84f4f4f0f4f4f4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_af3c3bc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af3c3bc1808903b8c5efdfd6f7817c400f6c3652e22cea7ef46345877a59342a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 05:10:35"
  condition:
    hash.sha256(0, filesize) == "af3c3bc1808903b8c5efdfd6f7817c400f6c3652e22cea7ef46345877a59342a"
}
```

### Sample 34: `8a4214bf59af8622`

| Field | Value |
|---|---|
| SHA-256 | `8a4214bf59af8622727edfdd720402f3535465701d5c536f10ccabb2fc5cdb33` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-30 05:07:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c73f66698a03ffdf22e2380564210ca` |
| SHA-1 | `f24cd55f7005f663f438c9120496b3054b28f826` |
| SHA-256 | `8a4214bf59af8622727edfdd720402f3535465701d5c536f10ccabb2fc5cdb33` |
| SHA3-384 | `f561265ae034387e29939737019cb69a7bfd33cc6ef89631794606cd2d8c4bcdd57623232d02cb5ddb450d98df0e4dc5` |
| TLSH | `T179D46D0779F484BDC8E6C0744B9BD33E9962F48A2139B68FE7C5AE817E19E90671C341` |
| TELFHASH | `t145f12f340871292571cbc515b303d2bc2d33580a4af539a5769369eeedeeac14cbbc76` |
| SSDEEP | `6144:Yt5XGppQqjSJ/OOehECV9xQmHElB9MILwI3f+nOcyjk3z5zCOdiBT5m92qESLNsF:YSQCqY9sxeyjkD5zCOLFExXXXEM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_8a4214bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a4214bf59af8622727edfdd720402f3535465701d5c536f10ccabb2fc5cdb33"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:43"
  condition:
    hash.sha256(0, filesize) == "8a4214bf59af8622727edfdd720402f3535465701d5c536f10ccabb2fc5cdb33"
}
```

### Sample 35: `1cd6c78ed6769819`

| Field | Value |
|---|---|
| SHA-256 | `1cd6c78ed6769819d03fbb748209f9f3493cec06b050baf5c402671b57632a46` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-09-30 05:07:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41fc020baf398c8e4cc1632302f1a462` |
| SHA-1 | `40ee2dd29fea9fdae438af87525cc03d4f3968ff` |
| SHA-256 | `1cd6c78ed6769819d03fbb748209f9f3493cec06b050baf5c402671b57632a46` |
| SHA3-384 | `8160b7610aafe3ab2df70b2806513e3764ab9cca59fcdeefa8f05bbb25eee4512f8d4c710b792016b3e9057ca680e5e2` |
| TLSH | `T1C1C48D03AAA3EDB1C4A380B561565FB54971D537207BD98FDBD62DA0DE205C0A32C3BB` |
| TELFHASH | `t18d027ab33aff1ded67e06802930b2b22de09966719d435b609f3548537b3a825f72835` |
| SSDEEP | `6144:4lx6v2yJQwav0NWDi+GeU3YYp9oXsMDmwLfvw9I3T0aby3kW/MOJsu:O7cNW5GDoyvsZ3nqM2su` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_1cd6c78e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cd6c78ed6769819d03fbb748209f9f3493cec06b050baf5c402671b57632a46"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:41"
  condition:
    hash.sha256(0, filesize) == "1cd6c78ed6769819d03fbb748209f9f3493cec06b050baf5c402671b57632a46"
}
```

### Sample 36: `72de1975db607721`

| Field | Value |
|---|---|
| SHA-256 | `72de1975db60772192ea98a5c73a2f599997a202c16257bd1958fa9066f8e466` |
| Family label | `Mirai` |
| File name | `bot.armv6` |
| File type | `elf` |
| First seen | `2026-09-30 05:07:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32c41753aad808a121439712a1a64e61` |
| SHA-1 | `f5c4c48650922684ec81d0b7e86afb0b8b224e93` |
| SHA-256 | `72de1975db60772192ea98a5c73a2f599997a202c16257bd1958fa9066f8e466` |
| SHA3-384 | `6a1bb6fc1dde8d08f2d8a7feea4d7429440e47ba039be05105d0750fe89b6dfd84b1d71a2c70c1dc311378fc552e5908` |
| TLSH | `T1FA254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmU:KdM4DmUj657yDAmU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_72de1975
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72de1975db60772192ea98a5c73a2f599997a202c16257bd1958fa9066f8e466"
    family = "Mirai"
    file_name = "bot.armv6"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:39"
  condition:
    hash.sha256(0, filesize) == "72de1975db60772192ea98a5c73a2f599997a202c16257bd1958fa9066f8e466"
}
```

### Sample 37: `948804a9a1599b0e`

| Field | Value |
|---|---|
| SHA-256 | `948804a9a1599b0ef0d72938e262429c4efea8d97186661d7ca2aac2317812e2` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-09-30 05:07:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9fc737136bdccfd14e4604a8b548323` |
| SHA-1 | `a064ad960f36d66e809f3f50c40588306cfe4f04` |
| SHA-256 | `948804a9a1599b0ef0d72938e262429c4efea8d97186661d7ca2aac2317812e2` |
| SHA3-384 | `4e82499ea4f29e57fd2b06e417163dfa523670fdb25c161212508a4c3a4f1aba9d8aa87b60f9f2331bff0b8a2937e72b` |
| TLSH | `T1D9456C5DFD0F3C43D2CAE23EDB4A83E47127B0D4D66311A336C2035DE68999D8B9295A` |
| TELFHASH | `t193b012071484c50c45779b514ca5034910419833e85b3e962f0cfa40402100803488ea` |
| SSDEEP | `24576:Jw9ghjWVQmLjFl1KQeu5fY4SJa6Shgk2g/HVh:JKWWpjxuNJI6ShgkzVh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_948804a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "948804a9a1599b0ef0d72938e262429c4efea8d97186661d7ca2aac2317812e2"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:38"
  condition:
    hash.sha256(0, filesize) == "948804a9a1599b0ef0d72938e262429c4efea8d97186661d7ca2aac2317812e2"
}
```

### Sample 38: `f2ea31b17031e00d`

| Field | Value |
|---|---|
| SHA-256 | `f2ea31b17031e00d5bc0c565764ae5c13f8e29db137c756310a6035b5f4a2c58` |
| Family label | `Mirai` |
| File name | `stub.mips64` |
| File type | `elf` |
| First seen | `2026-09-30 05:07:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1053cffa32f942cf8bfcc049a723a370` |
| SHA-1 | `60119228b8938ecf869e0f802332fccdf383cb40` |
| SHA-256 | `f2ea31b17031e00d5bc0c565764ae5c13f8e29db137c756310a6035b5f4a2c58` |
| SHA3-384 | `887d5c914b189f4009931d6cb78d30dcf9c5f360e466c9760adf3a9e78f5cbcc08e38412c46fbf5fd1faca0c04564d28` |
| TLSH | `T18DF48D273B21DF65D355D67049F3C7914AE920A20AE340D6B2A8C3287E6172D2D9FFE4` |
| SSDEEP | `12288:4EO7hT7XQRW4tWl9B11U+bs/w7iGtgpiGGhQi3BF1PNMBHUJTxVI:o7Vh4t+9B1do/w7iG+SQiZa0JTxi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_f2ea31b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2ea31b17031e00d5bc0c565764ae5c13f8e29db137c756310a6035b5f4a2c58"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:36"
  condition:
    hash.sha256(0, filesize) == "f2ea31b17031e00d5bc0c565764ae5c13f8e29db137c756310a6035b5f4a2c58"
}
```

### Sample 39: `7c0777d3bb15d39c`

| Field | Value |
|---|---|
| SHA-256 | `7c0777d3bb15d39c902825936f47393cf25df2316059f4e296f5ec3243e800fc` |
| Family label | `Mirai` |
| File name | `stub.arm7n` |
| File type | `elf` |
| First seen | `2026-09-30 05:07:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37fc394886f582c1e00a3536c9fa689d` |
| SHA-1 | `4ed8c5b0023c5f01cb702ae539b1f75c7527103d` |
| SHA-256 | `7c0777d3bb15d39c902825936f47393cf25df2316059f4e296f5ec3243e800fc` |
| SHA3-384 | `ec0fdc2333c9f2f14bafda4dda184a7ae59e77ec228b9e1af9ac73bac700cdd1471fb40d334b306b9a0020b730aac6e6` |
| TLSH | `T1B6D44A55F8809F63C9C52A36F64E866833274778C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKiIL:YCp7mXtni6aBh321eSiVWKj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_7c0777d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c0777d3bb15d39c902825936f47393cf25df2316059f4e296f5ec3243e800fc"
    family = "Mirai"
    file_name = "stub.arm7n"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:34"
  condition:
    hash.sha256(0, filesize) == "7c0777d3bb15d39c902825936f47393cf25df2316059f4e296f5ec3243e800fc"
}
```

### Sample 40: `136d36df1475e71d`

| Field | Value |
|---|---|
| SHA-256 | `136d36df1475e71d9bc33fb8a75cf7092e5507792f23d6bfff7440a17b0f076e` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-09-30 05:07:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8aa142937ddba8ec8d3e4705a328f7c2` |
| SHA-1 | `343f6385ac8241ec113df73e5374321b095e827f` |
| SHA-256 | `136d36df1475e71d9bc33fb8a75cf7092e5507792f23d6bfff7440a17b0f076e` |
| SHA3-384 | `a0ef83c9b2a1f7ca56d7ccfb75b5b265e9d42c2d89a90bfd8e3e5311e75f6fbb51f881fac8e9d976641a35b40b43bc75` |
| TLSH | `T126455C5DFD0F3C43D2CAE23EDB4A83E47127B0D4D66311A336C2035DE68999D8B9295A` |
| TELFHASH | `t193b012071484c50c45779b514ca5034910419833e85b3e962f0cfa40402100803488ea` |
| SSDEEP | `24576:Jw9ghjWVQmLjFl1KQeu5fY4SJa6Shgk2g/HVc:JKWWpjxuNJI6ShgkzVc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_136d36df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "136d36df1475e71d9bc33fb8a75cf7092e5507792f23d6bfff7440a17b0f076e"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:32"
  condition:
    hash.sha256(0, filesize) == "136d36df1475e71d9bc33fb8a75cf7092e5507792f23d6bfff7440a17b0f076e"
}
```

### Sample 41: `47d668860fad5c51`

| Field | Value |
|---|---|
| SHA-256 | `47d668860fad5c51f213d55587aaf7de2f3f02cd2c4b27d8a6a434517d0b79a2` |
| Family label | `Mirai` |
| File name | `bot.armv6l` |
| File type | `elf` |
| First seen | `2026-09-30 05:03:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8933bbcd32767389cb02ff025c1fc85` |
| SHA-1 | `6b71c45adad3a85ece1ee7b4575f2021d7028cdf` |
| SHA-256 | `47d668860fad5c51f213d55587aaf7de2f3f02cd2c4b27d8a6a434517d0b79a2` |
| SHA3-384 | `0c2777809282a922aa75856a671e07e21fcfe5719fca89a2c94ee7ead3e53e8cf76fb1f2feafc114bfe63488b4a1541b` |
| TLSH | `T14A254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmM:KdM4DmUj657yDAmM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_47d66886
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47d668860fad5c51f213d55587aaf7de2f3f02cd2c4b27d8a6a434517d0b79a2"
    family = "Mirai"
    file_name = "bot.armv6l"
    file_type = "elf"
    first_seen = "2026-09-30 05:03:39"
  condition:
    hash.sha256(0, filesize) == "47d668860fad5c51f213d55587aaf7de2f3f02cd2c4b27d8a6a434517d0b79a2"
}
```

### Sample 42: `9bd5581518f5dd65`

| Field | Value |
|---|---|
| SHA-256 | `9bd5581518f5dd65131da16bdf34072dca55b3b6121f4ad1090d2cf5e28f691c` |
| Family label | `unknown` |
| File name | `9bd5581518f5dd65131da16bdf34072dca55b3b6121f4ad1090d2cf5e28f691c` |
| File type | `elf` |
| First seen | `2026-09-30 05:00:11` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37c0211af2bb44984518284aff9db7cd` |
| SHA-1 | `8ff5307817cbbf0422ca19155d4aadbcf878df65` |
| SHA-256 | `9bd5581518f5dd65131da16bdf34072dca55b3b6121f4ad1090d2cf5e28f691c` |
| SHA3-384 | `f6dc7dd32e73280ee59f3fa765c59f7925a79b65a00f4451e2af15d89f03b8bc62fd63b9f768b3c5f580574ce9ab0266` |
| TLSH | `T1DB25332F3542724B9636623D3982FA7104FA02143449F9D1A76EE344EC1467FDA2ADEF` |
| SSDEEP | `24576:+nZLo3SaxaRqocd0O5PV8q5kNuMZY49VFU9hC8sbou2jCyk:CZLKHlog/V9KHRwKtby29` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_9bd55815
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd5581518f5dd65131da16bdf34072dca55b3b6121f4ad1090d2cf5e28f691c"
    family = "unknown"
    file_name = "9bd5581518f5dd65131da16bdf34072dca55b3b6121f4ad1090d2cf5e28f691c"
    file_type = "elf"
    first_seen = "2026-09-30 05:00:11"
  condition:
    hash.sha256(0, filesize) == "9bd5581518f5dd65131da16bdf34072dca55b3b6121f4ad1090d2cf5e28f691c"
}
```

### Sample 43: `a98178d4080f2fbc`

| Field | Value |
|---|---|
| SHA-256 | `a98178d4080f2fbc9281eb79be39cb5ec7906db27d221d3e05e413ed3b5e492d` |
| Family label | `Mirai` |
| File name | `bot.i586` |
| File type | `elf` |
| First seen | `2026-09-30 04:59:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `571cf6173aa88dea179b4ca086276c8e` |
| SHA-1 | `62c3975fbe705f32ebb5ebc2ddc3054fb92b2631` |
| SHA-256 | `a98178d4080f2fbc9281eb79be39cb5ec7906db27d221d3e05e413ed3b5e492d` |
| SHA3-384 | `aadb313df8d9609d78641f181bee5deb51c97c5cd8e8b3b120abdd068aafd8f080bd972cd08877e6a1ae34bf55f981af` |
| TLSH | `T1AB355C5BB2B374BCC557C834839BDA62BD35B46502226E7BB5C4CA302E26D702719F72` |
| TELFHASH | `t1d3e16b754ff934b862d6ca24b352f0769a33142b66ec35f52612ad98ef40fc04c6682b` |
| SSDEEP | `24576:FtmY2nvov46dWqbb+VXu5C6wGRTiY8mUMh8Utu+MBb:6BAv46dYXuo6lixmUMdkvBb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_a98178d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a98178d4080f2fbc9281eb79be39cb5ec7906db27d221d3e05e413ed3b5e492d"
    family = "Mirai"
    file_name = "bot.i586"
    file_type = "elf"
    first_seen = "2026-09-30 04:59:35"
  condition:
    hash.sha256(0, filesize) == "a98178d4080f2fbc9281eb79be39cb5ec7906db27d221d3e05e413ed3b5e492d"
}
```

### Sample 44: `59e1205cdec5c79c`

| Field | Value |
|---|---|
| SHA-256 | `59e1205cdec5c79c19e4a6b3dc80c1816717156111ef34080e82436d57e47866` |
| Family label | `Mirai` |
| File name | `stub.armv7` |
| File type | `elf` |
| First seen | `2026-09-30 04:59:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea578447169c8d24b245fc7f2d4d904f` |
| SHA-1 | `1d93a1fc14cd5ff1a2cd9e0530dffb1bf42424d3` |
| SHA-256 | `59e1205cdec5c79c19e4a6b3dc80c1816717156111ef34080e82436d57e47866` |
| SHA3-384 | `91cd816e63c5cda85670c32d769386c7ca86916b2114f57b84e768ad1c92dd7431c864b2c811f31c3ea2f2bd0e21250f` |
| TLSH | `T1B2D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKi8:YCp7mXtni6aBh321eSiVWKb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_59e1205c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59e1205cdec5c79c19e4a6b3dc80c1816717156111ef34080e82436d57e47866"
    family = "Mirai"
    file_name = "stub.armv7"
    file_type = "elf"
    first_seen = "2026-09-30 04:59:33"
  condition:
    hash.sha256(0, filesize) == "59e1205cdec5c79c19e4a6b3dc80c1816717156111ef34080e82436d57e47866"
}
```

### Sample 45: `496201bcd5b16c1a`

| Field | Value |
|---|---|
| SHA-256 | `496201bcd5b16c1ae13ee13a8589919521a1fec974d3064a2969a71e3038048b` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-09-30 04:59:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95fae5ce8b647574f984513172c4d89f` |
| SHA-1 | `660b082d273dbda2dd5545d10949068feffafdab` |
| SHA-256 | `496201bcd5b16c1ae13ee13a8589919521a1fec974d3064a2969a71e3038048b` |
| SHA3-384 | `fb53203e823d7cc58767774b9de131638cb5a6fa0e038413edad9af7b55d373e1e19205ec9f30e7f2154ae26a8dabf84` |
| TLSH | `T177D45D66BD919B80C5E159BEFB9E437872035BB9E2FFB106CA045FA16BC54850F3E201` |
| SSDEEP | `12288:LLmLuHRoDuzBKJssD7RSBss9ahqTFM/2ZKCK6A7vcmx:W2BK2iscPvc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_496201bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "496201bcd5b16c1ae13ee13a8589919521a1fec974d3064a2969a71e3038048b"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-09-30 04:59:31"
  condition:
    hash.sha256(0, filesize) == "496201bcd5b16c1ae13ee13a8589919521a1fec974d3064a2969a71e3038048b"
}
```

### Sample 46: `eb66a153d4efbbc1`

| Field | Value |
|---|---|
| SHA-256 | `eb66a153d4efbbc1a875d3e9f197c0393ba2e9250c972d050821f32ed20fe3e2` |
| Family label | `Mirai` |
| File name | `stub.aarch64_be` |
| File type | `elf` |
| First seen | `2026-09-30 04:59:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b09dd568bdf384228a2d1eb3f4ca0b17` |
| SHA-1 | `5dec3732cf291ea14f45f114464b01be991e2957` |
| SHA-256 | `eb66a153d4efbbc1a875d3e9f197c0393ba2e9250c972d050821f32ed20fe3e2` |
| SHA3-384 | `989ad5549ed120946a77473fdc150171c6d9da87b9ce0af4d9e508eb26284d8acf455fe0fadf0263fd0fb89a028e5155` |
| TLSH | `T1D1F46C5DFD5F3D43C2C6E23ADB8AC3957227B0D8D61311A321C1021DE6CADAD8B5299E` |
| SSDEEP | `12288:qaOMNE5N3B76xF+y0ZdNd7JOSwa5YAmdlStnWtVfkHzM:qaReBKRU9r1aOnQfkHI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_eb66a153
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb66a153d4efbbc1a875d3e9f197c0393ba2e9250c972d050821f32ed20fe3e2"
    family = "Mirai"
    file_name = "stub.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-30 04:59:30"
  condition:
    hash.sha256(0, filesize) == "eb66a153d4efbbc1a875d3e9f197c0393ba2e9250c972d050821f32ed20fe3e2"
}
```

### Sample 47: `74c6c9f2c96e8e7b`

| Field | Value |
|---|---|
| SHA-256 | `74c6c9f2c96e8e7b203e13352ed6d956d272775da8def9635bbfa68537151d95` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-09-30 04:55:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebf9ae62cbd4a38c4e206c86fdff1eac` |
| SHA-1 | `53d981786c4b357ab6ad646c3d69e1a0bd87852c` |
| SHA-256 | `74c6c9f2c96e8e7b203e13352ed6d956d272775da8def9635bbfa68537151d95` |
| SHA3-384 | `973ca76ced36fd00d21a2fbda0b1fe2be4a010ea152ddaef63b20a0512f69645ce28726d424102f8cf31b4885f12fabb` |
| TLSH | `T134053B076F509DF7C46BCC3706B5CB2624CDF88331A53B6A7678DA8CBD1960B46938A4` |
| SSDEEP | `6144:nOJ9DS6Oq8h8KNKUoq8p2pxcccR/8BmDKjv/e1JsJx15fwvjfu2aWzN+M7CBOTfR:aOphapX4eHAN2wshz3M0/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_74c6c9f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74c6c9f2c96e8e7b203e13352ed6d956d272775da8def9635bbfa68537151d95"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-30 04:55:34"
  condition:
    hash.sha256(0, filesize) == "74c6c9f2c96e8e7b203e13352ed6d956d272775da8def9635bbfa68537151d95"
}
```

### Sample 48: `d915a6fc0c35987c`

| Field | Value |
|---|---|
| SHA-256 | `d915a6fc0c35987caf6db0ec4da18b43dc87af1143138b1c888e9d169e932fb2` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-30 04:55:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ce9a88545210f256d8816a07a10c923` |
| SHA-1 | `82a527e7ec4787fbed226645f6d87b823b7a5e98` |
| SHA-256 | `d915a6fc0c35987caf6db0ec4da18b43dc87af1143138b1c888e9d169e932fb2` |
| SHA3-384 | `a4789e1f52bba4644eb58726a48ea949f1e6df18086ae37f3785340807d7366925e81bbaba738902165559645bda07bb` |
| TLSH | `T1CFD48DC7B6A0CDFEFC96D33645130A295020F6A251A29B2FE25F7D94DB2D1903538BC6` |
| SSDEEP | `6144:G1FcsnWiMDdx5WxGVGJsalKY6Y8WV3AlT+sCcEMb6gmyc5QDBTkabJlvLZInzLKK:G1FceWichxVUs4hz8xi639oaJInz2duB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_d915a6fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d915a6fc0c35987caf6db0ec4da18b43dc87af1143138b1c888e9d169e932fb2"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-30 04:55:32"
  condition:
    hash.sha256(0, filesize) == "d915a6fc0c35987caf6db0ec4da18b43dc87af1143138b1c888e9d169e932fb2"
}
```

### Sample 49: `73e4f1ab2f9def12`

| Field | Value |
|---|---|
| SHA-256 | `73e4f1ab2f9def12d230c086ba9c1de5ed737530306180fca334cad034c587ba` |
| Family label | `Mirai` |
| File name | `stub.arm` |
| File type | `elf` |
| First seen | `2026-09-30 04:55:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `150045a648a23a19da287ff8d50bcc23` |
| SHA-1 | `f2136a662e178a554aa09f65332e03a1b9897f8a` |
| SHA-256 | `73e4f1ab2f9def12d230c086ba9c1de5ed737530306180fca334cad034c587ba` |
| SHA3-384 | `d784acdf8112ecf63e58b26c3ed1d390a6674acbf4cee5799035698533bb10148259da74212b35b61400aae473d5863b` |
| TLSH | `T1BDD44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKiB:YCp7mXtni6aBh321eSiVWKU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_73e4f1ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73e4f1ab2f9def12d230c086ba9c1de5ed737530306180fca334cad034c587ba"
    family = "Mirai"
    file_name = "stub.arm"
    file_type = "elf"
    first_seen = "2026-09-30 04:55:30"
  condition:
    hash.sha256(0, filesize) == "73e4f1ab2f9def12d230c086ba9c1de5ed737530306180fca334cad034c587ba"
}
```

### Sample 50: `dbb314012d8274a9`

| Field | Value |
|---|---|
| SHA-256 | `dbb314012d8274a918884efeaa3501b31367e0c89386b81de23d60c1efa0cab3` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-09-30 04:55:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8163506b021cc09ad166f289b738bb8e` |
| SHA-1 | `6a44722909510dbc730d944c42ec75426418e80d` |
| SHA-256 | `dbb314012d8274a918884efeaa3501b31367e0c89386b81de23d60c1efa0cab3` |
| SHA3-384 | `c032bf916126bea065a5eee69f0e0e29c8d82d7192efb3c6d7c0a46f6e2ad2907c1025e4a215044959389f4a4adf603d` |
| TLSH | `T14DD46C16BD919B91C6E24ABBFBAE4368721757BDD2FF7007CA045F9037DA4810A3E241` |
| TELFHASH | `t1e2e0eb790a4404d2310041bff8866780b422c8932c80b82125d6f8bf0033a4eb051482` |
| SSDEEP | `12288:xDr+5Zk1hTUSZV8lsP/zJev48nJdz1ROqAMZVgmHWDZWe:h+5QPZV8lsP/zJev/rdWDZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_dbb31401
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbb314012d8274a918884efeaa3501b31367e0c89386b81de23d60c1efa0cab3"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-30 04:55:28"
  condition:
    hash.sha256(0, filesize) == "dbb314012d8274a918884efeaa3501b31367e0c89386b81de23d60c1efa0cab3"
}
```

### Sample 51: `92c8c99af3bdd8bc`

| Field | Value |
|---|---|
| SHA-256 | `92c8c99af3bdd8bc48242b0b30a742f6dc946a352b5a6047520fe73576b2637e` |
| Family label | `Mirai` |
| File name | `stub.mpsl` |
| File type | `elf` |
| First seen | `2026-09-30 04:51:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ce7ab90b4b14f0d1450c79ac584353f` |
| SHA-1 | `b32e64ef5c9567bcba43cd73cafd2e09daf28132` |
| SHA-256 | `92c8c99af3bdd8bc48242b0b30a742f6dc946a352b5a6047520fe73576b2637e` |
| SHA3-384 | `e0747a777e5b492f5c11bb645e7efadb5288f97b3f2ff8753fee9863ac79a504a0a7576272cbfbcd0ee2307769a05fc4` |
| TLSH | `T1F8F45B07FF815FEBC09FCD30852EC31721E9D48656C1A62A72FC4A8CBA5D6694BE3494` |
| SSDEEP | `12288:cAsRZePvWEwcj1b4D7QAEjYHZ6fxd8mg2cSAH07FFMk/mKsuSxzOTl1aplHPPhGJ:GZwv1jJ4/9UZnQ28N+0JTx4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_92c8c99a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92c8c99af3bdd8bc48242b0b30a742f6dc946a352b5a6047520fe73576b2637e"
    family = "Mirai"
    file_name = "stub.mpsl"
    file_type = "elf"
    first_seen = "2026-09-30 04:51:36"
  condition:
    hash.sha256(0, filesize) == "92c8c99af3bdd8bc48242b0b30a742f6dc946a352b5a6047520fe73576b2637e"
}
```

### Sample 52: `31052cb3bf27c7ca`

| Field | Value |
|---|---|
| SHA-256 | `31052cb3bf27c7cacd2008e4bb875929bebae7da347b18ac1737bff3cb41eff3` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-09-30 04:51:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a5ed24f4437f88c1a8eddc45e3110d4` |
| SHA-1 | `d1599813bf5ffb53f5f5255a2c541d07fcdc0f1b` |
| SHA-256 | `31052cb3bf27c7cacd2008e4bb875929bebae7da347b18ac1737bff3cb41eff3` |
| SHA3-384 | `caaaa53dff32536e1dfbb4a6b98f5cbfe93e7b76302ffa00d1de0a0e0efff8038b8ceb6b8a38e9e327e3060cb4f977b6` |
| TLSH | `T11DD45D67BC919B90C5D149BEFB6E436C72035B79E2EFB106DA045F906BCA8950F3E201` |
| SSDEEP | `12288:boZt04Lbu9otYOX+y+f2Ba8bl7745Ovi4T:kqoi1odK5Ovi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_31052cb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31052cb3bf27c7cacd2008e4bb875929bebae7da347b18ac1737bff3cb41eff3"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-09-30 04:51:35"
  condition:
    hash.sha256(0, filesize) == "31052cb3bf27c7cacd2008e4bb875929bebae7da347b18ac1737bff3cb41eff3"
}
```

### Sample 53: `e4ac0f86f31b76ae`

| Field | Value |
|---|---|
| SHA-256 | `e4ac0f86f31b76ae1f8e81dafa68abe025053cb17e3c1a85e4de740931fd494a` |
| Family label | `Mirai` |
| File name | `stub.arm` |
| File type | `elf` |
| First seen | `2026-09-30 04:51:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cd38c2dca0aee836d2c2760331c6ac8` |
| SHA-1 | `e086571d27b5d4df3bd68c1cb5a68d821566f350` |
| SHA-256 | `e4ac0f86f31b76ae1f8e81dafa68abe025053cb17e3c1a85e4de740931fd494a` |
| SHA3-384 | `581ae6d78b826aee31d7a6bf3f0f55885c5270449e73358bb563b5c5f08e6dc2a8cfade32ed4521b760d1771cf5b178b` |
| TLSH | `T1BAD44A55F8809F63C9C52A36F64E826833274778C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKia:YCp7mXtni6aBh321eSiVWK9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_e4ac0f86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4ac0f86f31b76ae1f8e81dafa68abe025053cb17e3c1a85e4de740931fd494a"
    family = "Mirai"
    file_name = "stub.arm"
    file_type = "elf"
    first_seen = "2026-09-30 04:51:33"
  condition:
    hash.sha256(0, filesize) == "e4ac0f86f31b76ae1f8e81dafa68abe025053cb17e3c1a85e4de740931fd494a"
}
```

### Sample 54: `df7bbe678d679725`

| Field | Value |
|---|---|
| SHA-256 | `df7bbe678d679725ed78c78ad23d1caea50e3c06d6da23cb087a55959c711f2d` |
| Family label | `Mirai` |
| File name | `bot.amd64` |
| File type | `elf` |
| First seen | `2026-09-30 04:51:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2698c06cb1baa139837077a714e8b503` |
| SHA-1 | `b019c0863f1a83546d8f7da54af7d3fbb4ab691a` |
| SHA-256 | `df7bbe678d679725ed78c78ad23d1caea50e3c06d6da23cb087a55959c711f2d` |
| SHA3-384 | `f7178cf05ba9cf25fab6a3603b37e351fcad83a3a8a4f5c813f17bb4a75d7b987c084e3e4cd775a0bef7d85f7f241d71` |
| TLSH | `T12C355C5BB2B374BCC557C834839BDA62BD35B46502226E7BB5C4CA302E26D702719F72` |
| TELFHASH | `t1d3e16b754ff934b862d6ca24b352f0769a33142b66ec35f52612ad98ef40fc04c6682b` |
| SSDEEP | `24576:FtmY2nvov46dWqbb+VXu5C6wGRTiY8mUMh8Utu+MBQ:6BAv46dYXuo6lixmUMdkvBQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_df7bbe67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df7bbe678d679725ed78c78ad23d1caea50e3c06d6da23cb087a55959c711f2d"
    family = "Mirai"
    file_name = "bot.amd64"
    file_type = "elf"
    first_seen = "2026-09-30 04:51:31"
  condition:
    hash.sha256(0, filesize) == "df7bbe678d679725ed78c78ad23d1caea50e3c06d6da23cb087a55959c711f2d"
}
```

### Sample 55: `6cabe8fbd5d60554`

| Field | Value |
|---|---|
| SHA-256 | `6cabe8fbd5d6055487cf87ffd78d968c70e443fbd7328911ddaa49a7da7e1c56` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-09-30 04:47:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59869bbca81c965a2bf70ffce33789c2` |
| SHA-1 | `7fdc577d4bb86ad443c655c4521e45ba31588eeb` |
| SHA-256 | `6cabe8fbd5d6055487cf87ffd78d968c70e443fbd7328911ddaa49a7da7e1c56` |
| SHA3-384 | `1ffa1c1d62da6d25ec80750093428e11a889c2d4113b7b352fda5d61a9f621de05d7185541f4ab8aa0effd5e49d20a53` |
| TLSH | `T10A456C5DFD0F3C43D2CAE23EDB4A83E47127B0D4D66311A336C2035DE68999D8B9295A` |
| TELFHASH | `t193b012071484c50c45779b514ca5034910419833e85b3e962f0cfa40402100803488ea` |
| SSDEEP | `24576:Jw9ghjWVQmLjFl1KQeu5fY4SJa6Shgk2g/HVJ:JKWWpjxuNJI6ShgkzVJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_6cabe8fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cabe8fbd5d6055487cf87ffd78d968c70e443fbd7328911ddaa49a7da7e1c56"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-30 04:47:39"
  condition:
    hash.sha256(0, filesize) == "6cabe8fbd5d6055487cf87ffd78d968c70e443fbd7328911ddaa49a7da7e1c56"
}
```

### Sample 56: `134e012f340b9616`

| Field | Value |
|---|---|
| SHA-256 | `134e012f340b9616787422c7e9d3d3db43f83abb1e19efc613bcf1c433ff992a` |
| Family label | `Mirai` |
| File name | `wife.arm7` |
| File type | `elf` |
| First seen | `2026-09-30 04:44:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c59fe23e23acc9359d3067f03b7ea6c` |
| SHA-1 | `297952f2b8e299d03139079fca8c5bb55391cc1a` |
| SHA-256 | `134e012f340b9616787422c7e9d3d3db43f83abb1e19efc613bcf1c433ff992a` |
| SHA3-384 | `e1a6799945ea37125fdcf792f8e9ae588f1116538c68a0802096e32c8ed468f76714cd50a559cd12fbea13da09455cf9` |
| TLSH | `T1E514290ABA419F01D5D636FAFBAE414933536BB9E3FA3002DD205F6423CA99B0F36511` |
| SSDEEP | `6144:St8AuKcy7nkPYLBjqatJbrH74puX7u8/OrNZeRMP:08ADcokPYLBjqath74pm/OrNZeR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_134e012f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "134e012f340b9616787422c7e9d3d3db43f83abb1e19efc613bcf1c433ff992a"
    family = "Mirai"
    file_name = "wife.arm7"
    file_type = "elf"
    first_seen = "2026-09-30 04:44:14"
  condition:
    hash.sha256(0, filesize) == "134e012f340b9616787422c7e9d3d3db43f83abb1e19efc613bcf1c433ff992a"
}
```

### Sample 57: `74f9ff9f9630f769`

| Field | Value |
|---|---|
| SHA-256 | `74f9ff9f9630f76926286dc42ee469ac4df44dc36e9e02f6309d559d3a76b75b` |
| Family label | `Mirai` |
| File name | `wife.arm7` |
| File type | `elf` |
| First seen | `2026-09-30 04:43:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ef7bada2e33c9aa020d1ba2dc2f9354` |
| SHA-1 | `4cd3801f570a7b964c35f1b6378d5f6a753827f8` |
| SHA-256 | `74f9ff9f9630f76926286dc42ee469ac4df44dc36e9e02f6309d559d3a76b75b` |
| SHA3-384 | `8e78d56aaf382ed2c3482f8717b9b356587db739c14f281c093b7d23011b021c562f4c64148c8ab253358a3bcbf5a283` |
| TLSH | `T1948312F60238F4524AB0ACA2DFAE52858353E8FD25D53113389347ADAB8765FDCDCA44` |
| SSDEEP | `1536:/dkJJhZTuIKUn4rpnOQhWWkvmPacPOrFvMVJ1Hb99vz8:e7ruaIOmWbvqacW56HbM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_74f9ff9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f9ff9f9630f76926286dc42ee469ac4df44dc36e9e02f6309d559d3a76b75b"
    family = "Mirai"
    file_name = "wife.arm7"
    file_type = "elf"
    first_seen = "2026-09-30 04:43:37"
  condition:
    hash.sha256(0, filesize) == "74f9ff9f9630f76926286dc42ee469ac4df44dc36e9e02f6309d559d3a76b75b"
}
```

### Sample 58: `a964a420b73c720a`

| Field | Value |
|---|---|
| SHA-256 | `a964a420b73c720a93354ec5d3e4143d01ce93725117e52cb89cedd5c8d98931` |
| Family label | `Mirai` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-09-30 04:43:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9489094eef75b0f342033a5de6279c45` |
| SHA-1 | `d26806e80d8c1aeb74a8582fcd30ddffd7471960` |
| SHA-256 | `a964a420b73c720a93354ec5d3e4143d01ce93725117e52cb89cedd5c8d98931` |
| SHA3-384 | `68e72221cbdd77729f59ae244d867419f7c4b726465c65d4f7a6e94c97e8783dc885d30d4a282be6664027afc74e5f08` |
| TLSH | `T1AF355C5BB2B374BCC557C834839BDA62BD35B46502226E7BB5C4CA302E26D702719F72` |
| TELFHASH | `t1d3e16b754ff934b862d6ca24b352f0769a33142b66ec35f52612ad98ef40fc04c6682b` |
| SSDEEP | `24576:FtmY2nvov46dWqbb+VXu5C6wGRTiY8mUMh8Utu+MBd:6BAv46dYXuo6lixmUMdkvBd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_a964a420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a964a420b73c720a93354ec5d3e4143d01ce93725117e52cb89cedd5c8d98931"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-30 04:43:35"
  condition:
    hash.sha256(0, filesize) == "a964a420b73c720a93354ec5d3e4143d01ce93725117e52cb89cedd5c8d98931"
}
```

### Sample 59: `566f16d07ed078f5`

| Field | Value |
|---|---|
| SHA-256 | `566f16d07ed078f574d35cbfa1ca7efca6843fdc364725df981f9d95e26741cd` |
| Family label | `Mirai` |
| File name | `bot.mpsl` |
| File type | `elf` |
| First seen | `2026-09-30 04:43:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `570e345d543281102ff5d57f5c8ae226` |
| SHA-1 | `8a15c9dedd5e6f1fa0721474070e202634cdd25c` |
| SHA-256 | `566f16d07ed078f574d35cbfa1ca7efca6843fdc364725df981f9d95e26741cd` |
| SHA3-384 | `cc8e99cf9bb605b398e95ebafc825d0ba98df0a45520b2acbaa52a824d1b44e5a59c3bfeb2a08d088f093fd711d2cf96` |
| TLSH | `T16F355C46EF406FEBC49FCD30492EC31721EDE8CB42D5A62971BC4A8C7A5D3590AD3698` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:ApvR6ZM35dQ4ZmHd7dcCoLJTxwpTmVXxTCnOKW8h:Y6QS97FixxxxTCnzh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_566f16d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "566f16d07ed078f574d35cbfa1ca7efca6843fdc364725df981f9d95e26741cd"
    family = "Mirai"
    file_name = "bot.mpsl"
    file_type = "elf"
    first_seen = "2026-09-30 04:43:33"
  condition:
    hash.sha256(0, filesize) == "566f16d07ed078f574d35cbfa1ca7efca6843fdc364725df981f9d95e26741cd"
}
```

### Sample 60: `5ecfc1826938bf3f`

| Field | Value |
|---|---|
| SHA-256 | `5ecfc1826938bf3f2b3212788fbd94eed23388d6ae8c80895d43fb934b0f3e0c` |
| Family label | `unknown` |
| File name | `Invoice_and_Packing_List.js` |
| File type | `js` |
| First seen | `2026-09-30 04:40:16` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abaa306eb750fa5aee44d4307a5069da` |
| SHA-1 | `91977e57a81bd4e3c7cf917485819383b7e8bd2d` |
| SHA-256 | `5ecfc1826938bf3f2b3212788fbd94eed23388d6ae8c80895d43fb934b0f3e0c` |
| SHA3-384 | `6b3b16a1adafca8e1104440cca140fe594da9b553b693745c449cd6a409f959ff8be090ca4cb9e01652f991a0ae299d0` |
| TLSH | `T10FA5F15089C03EE4DB795A1881FD952DE3B10A9B4C2E6D4AB73FBD45EFB750082071AB` |
| SSDEEP | `24576:T8C2FdJicB4h/QgjVpS7qPOE9OLoprqXwR3EzmxJcSKxd/U8DXdKQ+y9p474MAkS:MiM4h7asR0zmxJvKd9Doy/zL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_5ecfc182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ecfc1826938bf3f2b3212788fbd94eed23388d6ae8c80895d43fb934b0f3e0c"
    family = "unknown"
    file_name = "Invoice_and_Packing_List.js"
    file_type = "js"
    first_seen = "2026-09-30 04:40:16"
  condition:
    hash.sha256(0, filesize) == "5ecfc1826938bf3f2b3212788fbd94eed23388d6ae8c80895d43fb934b0f3e0c"
}
```

### Sample 61: `f904eca10c253c1c`

| Field | Value |
|---|---|
| SHA-256 | `f904eca10c253c1cfc8f9e44c8c21360c4857f7967ef591db8910e0e44985fe6` |
| Family label | `Mirai` |
| File name | `bot.armv5tel` |
| File type | `elf` |
| First seen | `2026-09-30 04:39:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8ec313f26a02f96195fd94def2762bb` |
| SHA-1 | `2def91a7eaec82fc9a1c0f11a8a458fb294a90dc` |
| SHA-256 | `f904eca10c253c1cfc8f9e44c8c21360c4857f7967ef591db8910e0e44985fe6` |
| SHA3-384 | `77bb66ad1777079166f0ff9557e30b653f57d0998ddccf547e691105d0456ea769e97d35fe4fa5c426a056a0eb2fc580` |
| TLSH | `T1EA254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmqf:KdM4DmUj657yDAmO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_f904eca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f904eca10c253c1cfc8f9e44c8c21360c4857f7967ef591db8910e0e44985fe6"
    family = "Mirai"
    file_name = "bot.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-30 04:39:43"
  condition:
    hash.sha256(0, filesize) == "f904eca10c253c1cfc8f9e44c8c21360c4857f7967ef591db8910e0e44985fe6"
}
```

### Sample 62: `f04343dea19a7571`

| Field | Value |
|---|---|
| SHA-256 | `f04343dea19a7571b3a7bb3e523b9d32d8e50d58201e60e7770e4a72648fbe64` |
| Family label | `unknown` |
| File name | `install.sh` |
| File type | `sh` |
| First seen | `2026-09-30 04:39:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6c75b61ec6e27611c217d3b954602e4` |
| SHA-1 | `805467e5611b56ef6355cd00b337d00d3de3e75b` |
| SHA-256 | `f04343dea19a7571b3a7bb3e523b9d32d8e50d58201e60e7770e4a72648fbe64` |
| SHA3-384 | `43f0663cc5205d7d04a5e141e4898ebd85418800086a9553540a64f7498801ddaa3a773f693e8c2e09a9475be6569e06` |
| TLSH | `T12DC2C653AE9909F61458C6742F8B510AE31562C702516C28BBFD73187F84B1E93BEE3B` |
| SSDEEP | `384:8Pk4vuLCgw3N8lVqv8yEUCAC/vsMxD3kIuuNRasi5kFq2dzu3AQvc6sbB5uIFyJ:8xn3NMqv8PjFU47asLxY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_f04343de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f04343dea19a7571b3a7bb3e523b9d32d8e50d58201e60e7770e4a72648fbe64"
    family = "unknown"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-09-30 04:39:41"
  condition:
    hash.sha256(0, filesize) == "f04343dea19a7571b3a7bb3e523b9d32d8e50d58201e60e7770e4a72648fbe64"
}
```

### Sample 63: `981462933077e0ce`

| Field | Value |
|---|---|
| SHA-256 | `981462933077e0ceece8b21dc32faf8f292e8ff878ae0e342eec0229e1b57d8c` |
| Family label | `Mirai` |
| File name | `bot.arm` |
| File type | `elf` |
| First seen | `2026-09-30 04:39:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec548ebf77e9a4d021dac9470c3776a4` |
| SHA-1 | `e0c60cb4d3d5e3b70db8c82f9e60a5952384c93a` |
| SHA-256 | `981462933077e0ceece8b21dc32faf8f292e8ff878ae0e342eec0229e1b57d8c` |
| SHA3-384 | `6c20de004ce5e33c6e48f2d4e89d9b24a869d4e74319610c613b27fe0ef47959be3e40b8e6a5e02143a82c46f52b8ddd` |
| TLSH | `T1BA254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmv:KdM4DmUj657yDAmv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_98146293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "981462933077e0ceece8b21dc32faf8f292e8ff878ae0e342eec0229e1b57d8c"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-09-30 04:39:39"
  condition:
    hash.sha256(0, filesize) == "981462933077e0ceece8b21dc32faf8f292e8ff878ae0e342eec0229e1b57d8c"
}
```

### Sample 64: `334787dcea96690e`

| Field | Value |
|---|---|
| SHA-256 | `334787dcea96690e2816b16ac6f5f02771c29ffcb691832dcc154a201e473a5c` |
| Family label | `Mirai` |
| File name | `bot.mipsel` |
| File type | `elf` |
| First seen | `2026-09-30 04:39:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9cc18c947ba4c94f2e73e68c02b5c21f` |
| SHA-1 | `2075b15dee8f63db1635b4cbd85ff3f62144b794` |
| SHA-256 | `334787dcea96690e2816b16ac6f5f02771c29ffcb691832dcc154a201e473a5c` |
| SHA3-384 | `52aeba97eea2b9a350e4d0f2dfc5dcddd6dd4ecb3e217dbffbe0cfd1cef155198e3fba562f00edbdef4d5df1520b9f71` |
| TLSH | `T171356C46EF406FEBC49FCD30492EC31721EDE8CA42D5A62971FC4A8C7A5D3590AD3698` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:ApvR6ZM35dQ4ZmHd7dcCoLJTxwpTmVXxTCnOKW88:Y6QS97FixxxxTCnz8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_334787dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "334787dcea96690e2816b16ac6f5f02771c29ffcb691832dcc154a201e473a5c"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-09-30 04:39:37"
  condition:
    hash.sha256(0, filesize) == "334787dcea96690e2816b16ac6f5f02771c29ffcb691832dcc154a201e473a5c"
}
```

### Sample 65: `7ccc09334c38cabc`

| Field | Value |
|---|---|
| SHA-256 | `7ccc09334c38cabc95ba4eb5ba41faa6167dbdff9faf23105b3c92e98f803774` |
| Family label | `Mirai` |
| File name | `stub.mpsl` |
| File type | `elf` |
| First seen | `2026-09-30 04:39:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef8c7030243555fdb787639b09a07abf` |
| SHA-1 | `c2b0764d472e207c492773b222c2b6443b7980d5` |
| SHA-256 | `7ccc09334c38cabc95ba4eb5ba41faa6167dbdff9faf23105b3c92e98f803774` |
| SHA3-384 | `5d9ca1616dd03ed6cd4179badffa4e0631a7abbaaac989818e031028789f6e54364f738a45ac10aabb50a497b5f525ca` |
| TLSH | `T166F45B07FF815FEBC09FCD30852EC31721E9D48656C1A62A72FC4A8CBA5D6694BE3494` |
| SSDEEP | `12288:cAsRZePvWEwcj1b4D7QAEjYHZ6fxd8mg2cSAH07FFMk/mKsuSxzOTl1aplHPPhG1:GZwv1jJ4/9UZnQ28N+0JTxe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_7ccc0933
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ccc09334c38cabc95ba4eb5ba41faa6167dbdff9faf23105b3c92e98f803774"
    family = "Mirai"
    file_name = "stub.mpsl"
    file_type = "elf"
    first_seen = "2026-09-30 04:39:36"
  condition:
    hash.sha256(0, filesize) == "7ccc09334c38cabc95ba4eb5ba41faa6167dbdff9faf23105b3c92e98f803774"
}
```

### Sample 66: `130e3e202b4c17ac`

| Field | Value |
|---|---|
| SHA-256 | `130e3e202b4c17ac6afea9a944739b3cbfe4a4f26b3a3f06b877588f4f0e256e` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-09-30 04:36:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e2f60c8ef203a5e5ccdab0d7a0df1df` |
| SHA-1 | `6ac2c19e95fac990c88993a711355e3dd773a0df` |
| SHA-256 | `130e3e202b4c17ac6afea9a944739b3cbfe4a4f26b3a3f06b877588f4f0e256e` |
| SHA3-384 | `af31358862db48535c8310c0cca8cab5896bf9b47e3c7ecd17557f51f0d870f2a75888e8374e4fe475410e937f3ec46f` |
| TLSH | `T157456C5DFD0F3C43D2CAE23EDB4A83E47127B0D4D66311A336C2035DE68999D8B9295A` |
| TELFHASH | `t193b012071484c50c45779b514ca5034910419833e85b3e962f0cfa40402100803488ea` |
| SSDEEP | `24576:Jw9ghjWVQmLjFl1KQeu5fY4SJa6Shgk2g/HVL:JKWWpjxuNJI6ShgkzVL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_130e3e20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "130e3e202b4c17ac6afea9a944739b3cbfe4a4f26b3a3f06b877588f4f0e256e"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-30 04:36:11"
  condition:
    hash.sha256(0, filesize) == "130e3e202b4c17ac6afea9a944739b3cbfe4a4f26b3a3f06b877588f4f0e256e"
}
```

### Sample 67: `a8ec3432b3097932`

| Field | Value |
|---|---|
| SHA-256 | `a8ec3432b30979327e26ef804d8014565240a5e3490690f305a0e4c9e15aa559` |
| Family label | `Mirai` |
| File name | `bot.armv6` |
| File type | `elf` |
| First seen | `2026-09-30 04:32:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25db836b235bd02ecd6f8fbce6c20ded` |
| SHA-1 | `73815fb45162ab100168ee03737723f76d2e782c` |
| SHA-256 | `a8ec3432b30979327e26ef804d8014565240a5e3490690f305a0e4c9e15aa559` |
| SHA3-384 | `efed7354fd6c51a0c9f6172192dddb4135f4ad90134f54ad5025f50c1d812d410e4729dbebab8bef2392dcf4c4b18f66` |
| TLSH | `T129254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmh:KdM4DmUj657yDAmh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_a8ec3432
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ec3432b30979327e26ef804d8014565240a5e3490690f305a0e4c9e15aa559"
    family = "Mirai"
    file_name = "bot.armv6"
    file_type = "elf"
    first_seen = "2026-09-30 04:32:28"
  condition:
    hash.sha256(0, filesize) == "a8ec3432b30979327e26ef804d8014565240a5e3490690f305a0e4c9e15aa559"
}
```

### Sample 68: `117a7ca405f65e3b`

| Field | Value |
|---|---|
| SHA-256 | `117a7ca405f65e3bc770fac74903e490011c35e65e1c359e8bea546841919da3` |
| Family label | `Mirai` |
| File name | `1` |
| File type | `elf` |
| First seen | `2026-09-30 04:32:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1498fa0337ee347897ec01516ed96be7` |
| SHA-1 | `0f31fd4ae805b4c11f8fe6720bc7c2e1ea8aa93e` |
| SHA-256 | `117a7ca405f65e3bc770fac74903e490011c35e65e1c359e8bea546841919da3` |
| SHA3-384 | `078e80892ed043c903fdad276629c64cd0c2e9328728df4eeffc7c6e91af282f8561f3066998b36de6c30b78b631adea` |
| TLSH | `T139558D1BB2E2A5BCD047C03447CFC6A24531F0B569323D7B37C4DA352EA6DA46769B22` |
| TELFHASH | `t1b1d111b5291ea8237811bf35b28c3bb30dd882be566d6672e736edcd20441987b4d80d` |
| SSDEEP | `24576:3yRExoA/1ht/NgmYvJkB5Xp14nDrvM1pN2LE0OuzbseS:3G2t/NgHOX16fvCytOuzs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_117a7ca4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "117a7ca405f65e3bc770fac74903e490011c35e65e1c359e8bea546841919da3"
    family = "Mirai"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-09-30 04:32:26"
  condition:
    hash.sha256(0, filesize) == "117a7ca405f65e3bc770fac74903e490011c35e65e1c359e8bea546841919da3"
}
```

### Sample 69: `e21fc021a38e4747`

| Field | Value |
|---|---|
| SHA-256 | `e21fc021a38e474746c2f3a4fb06e4d85ce64d2bbc107041e2c97cdf721d80bc` |
| Family label | `Mirai` |
| File name | `bot.aarch64_be` |
| File type | `elf` |
| First seen | `2026-09-30 04:25:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d3b3ec9206fcdf9b9f2972c337cf389` |
| SHA-1 | `e44587b76faad772736de5111fd1aee2da373ce8` |
| SHA-256 | `e21fc021a38e474746c2f3a4fb06e4d85ce64d2bbc107041e2c97cdf721d80bc` |
| SHA3-384 | `d1788a30850faa99a38276bcbb716eb7e39652f8eedd79240cacea6ccc7e1faf64f8a52ee31ed6986afdda8691e5cd25` |
| TLSH | `T106456C5DFD0F3C43D2CAE23EDB4A83E47127B0D4D66311A336C2035DE68999D8B9295A` |
| TELFHASH | `t193b012071484c50c45779b514ca5034910419833e85b3e962f0cfa40402100803488ea` |
| SSDEEP | `24576:Jw9ghjWVQmLjFl1KQeu5fY4SJa6Shgk2g/HVG:JKWWpjxuNJI6ShgkzVG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_e21fc021
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e21fc021a38e474746c2f3a4fb06e4d85ce64d2bbc107041e2c97cdf721d80bc"
    family = "Mirai"
    file_name = "bot.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-30 04:25:29"
  condition:
    hash.sha256(0, filesize) == "e21fc021a38e474746c2f3a4fb06e4d85ce64d2bbc107041e2c97cdf721d80bc"
}
```

### Sample 70: `d5b75afa907d0319`

| Field | Value |
|---|---|
| SHA-256 | `d5b75afa907d0319cb882da437539b700ca446ace13407bd3c84f9f003bab411` |
| Family label | `ConnectWise` |
| File name | `d5b75afa907d0319cb882da437539b700ca446ace13407bd3c84f9f003bab411.exe` |
| File type | `exe` |
| First seen | `2026-09-30 04:21:30` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `535fb7bcb44cbdf8be7ffd15f3cff9df` |
| SHA-1 | `1dd5204b27d88e533ac69f77ff2d372229ebc528` |
| SHA-256 | `d5b75afa907d0319cb882da437539b700ca446ace13407bd3c84f9f003bab411` |
| SHA3-384 | `bacbd0f66fbbb235df54432a570d09c6ab07422e8b5f1bc5f0f459e114a2362f9e6bd7778310be5510900e9de2fe1deb` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T159272301BBC69A66D87F0635987AA3106775BC404B52C7AF27E07B3D1D327C05E623EA` |
| SSDEEP | `393216:+i6ohU+8bjJ8gQq9ySZ8ES6ohU+8bjJ8P6ohU+8bjJ8K6ohU+8bjJ87:8oh0bjJ9ySZzdoh0bjroh0bjaoh0bjO` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_070_d5b75afa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5b75afa907d0319cb882da437539b700ca446ace13407bd3c84f9f003bab411"
    family = "ConnectWise"
    file_name = "d5b75afa907d0319cb882da437539b700ca446ace13407bd3c84f9f003bab411.exe"
    file_type = "exe"
    first_seen = "2026-09-30 04:21:30"
  condition:
    hash.sha256(0, filesize) == "d5b75afa907d0319cb882da437539b700ca446ace13407bd3c84f9f003bab411"
}
```

### Sample 71: `05913ee2a25cc2de`

| Field | Value |
|---|---|
| SHA-256 | `05913ee2a25cc2de7dc10ed47f6d74b4773d722c021d94b4aa6734243401dfdc` |
| Family label | `unknown` |
| File name | `Order specification invoice.js` |
| File type | `js` |
| First seen | `2026-09-30 04:20:39` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23f7818ecac6ab1e9f081c4da4cc2c9c` |
| SHA-1 | `d2fc789c84fc13b5d7f1a6a5b40640caa80905f4` |
| SHA-256 | `05913ee2a25cc2de7dc10ed47f6d74b4773d722c021d94b4aa6734243401dfdc` |
| SHA3-384 | `ecc1f0b17d61add37bcd1098f63530d1cc8c607410f0ebc1147abd9fb868ea5475bb7b5bc4f2b0ee1d22a096e9f804fa` |
| TLSH | `T1F3F0E5A265FDD20DB9FB5F24AD326861123B7F81AC38878C01D4181D0CE2600C0B2F73` |
| SSDEEP | `6:Qq3f2rc4YR2aujtlDeHJUYNQyXOOwOIIlYWeA8rcuXymlYW2g4lqJWKlJDjKmMKa:QqSA2ZtZe6QFflVAFrlV2dnKlK4k` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_05913ee2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05913ee2a25cc2de7dc10ed47f6d74b4773d722c021d94b4aa6734243401dfdc"
    family = "unknown"
    file_name = "Order specification invoice.js"
    file_type = "js"
    first_seen = "2026-09-30 04:20:39"
  condition:
    hash.sha256(0, filesize) == "05913ee2a25cc2de7dc10ed47f6d74b4773d722c021d94b4aa6734243401dfdc"
}
```

### Sample 72: `dada5f36380bdc60`

| Field | Value |
|---|---|
| SHA-256 | `dada5f36380bdc60e922b8dcb37b92fd603bcd6f6e691102270d2274e37b4827` |
| Family label | `Mirai` |
| File name | `dada5f36380bdc60e922b8dcb37b92fd603bcd6f6e691102270d2274e37b4827` |
| File type | `elf` |
| First seen | `2026-09-30 04:19:15` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f64d77543c68ecc8e07b26b15652e055` |
| SHA-1 | `9cf90fc1a9ce400468dc4af56975be92b4ae0484` |
| SHA-256 | `dada5f36380bdc60e922b8dcb37b92fd603bcd6f6e691102270d2274e37b4827` |
| SHA3-384 | `852eeb34d5ee4eaf457eb16d8809dc943ff5f2f461f1a193b95e837e24ffacaeb644b77669abc01276fc1b27fb951878` |
| TLSH | `T199543A8AFD81AE25D5C1267BFE2F428A331317B8D2EB71129D145F2876CA94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJR:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_dada5f36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dada5f36380bdc60e922b8dcb37b92fd603bcd6f6e691102270d2274e37b4827"
    family = "Mirai"
    file_name = "dada5f36380bdc60e922b8dcb37b92fd603bcd6f6e691102270d2274e37b4827"
    file_type = "elf"
    first_seen = "2026-09-30 04:19:15"
  condition:
    hash.sha256(0, filesize) == "dada5f36380bdc60e922b8dcb37b92fd603bcd6f6e691102270d2274e37b4827"
}
```

### Sample 73: `c89dfe68747f300a`

| Field | Value |
|---|---|
| SHA-256 | `c89dfe68747f300a3a2eef694544c2831ef411c38fbe5750d98add68f3462ea0` |
| Family label | `unknown` |
| File name | `FedEx Document_84665.js` |
| File type | `js` |
| First seen | `2026-09-30 04:11:01` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c49d9c2dece39a70e245ecdc5b2f14c1` |
| SHA-1 | `92f51b52de321652fa4c01b6119970f45603879f` |
| SHA-256 | `c89dfe68747f300a3a2eef694544c2831ef411c38fbe5750d98add68f3462ea0` |
| SHA3-384 | `0bbf307455e340afbd59f3f3558e2f95965ff7fa209bd26eb7bdacebc9b48d633d0013865dba3afe8e975d8fd8bfef81` |
| TLSH | `T19E364E50C9F998B3967D12A657FC88D4D855170522EE1C8382FE91BF3603B3E8E6943E` |
| SSDEEP | `768:T/LhK3taNGRoxh9eRU3uEbxwCYjAeCS4c9H7vxabxc+hjGGqvxeG9eC75E97+SZG:T/n0uika` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_c89dfe68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c89dfe68747f300a3a2eef694544c2831ef411c38fbe5750d98add68f3462ea0"
    family = "unknown"
    file_name = "FedEx Document_84665.js"
    file_type = "js"
    first_seen = "2026-09-30 04:11:01"
  condition:
    hash.sha256(0, filesize) == "c89dfe68747f300a3a2eef694544c2831ef411c38fbe5750d98add68f3462ea0"
}
```

### Sample 74: `f7914bc01cc76810`

| Field | Value |
|---|---|
| SHA-256 | `f7914bc01cc7681047160cdb1c34d6cb548c16045cb4ef4a868de43f9b8f6844` |
| Family label | `AsyncRAT` |
| File name | `P10R05AV_20260929141334 -  KAOHSIUNG, TAIWAN請投高掛.exe` |
| File type | `exe` |
| First seen | `2026-09-30 03:32:12` |
| Reporter | `threatcat_ch` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65b0cd351a2f6277af043cd8753f52ba` |
| SHA-1 | `9290a2150bf9a7c698684f93b633ba45a2c932b1` |
| SHA-256 | `f7914bc01cc7681047160cdb1c34d6cb548c16045cb4ef4a868de43f9b8f6844` |
| SHA3-384 | `099761841223aeb2d98d79a5230982b7a800885326db18b8fa2fe555d3c7b0c1c8015f86400d562dfae632651ad63324` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T152E4D064379ACE22C9A163B00F61F37113759D8DA631C3079EE57DD7383AB4629682E3` |
| SSDEEP | `12288:y1EMX5xcUJwFEvLvU//rt36VIIBLLSa4pc:y1XwF6vUnrNqIIdSa2` |
| ICON-DHASH | `38696dcce8f07070` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_074_f7914bc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7914bc01cc7681047160cdb1c34d6cb548c16045cb4ef4a868de43f9b8f6844"
    family = "AsyncRAT"
    file_name = "P10R05AV_20260929141334 -  KAOHSIUNG, TAIWAN請投高掛.exe"
    file_type = "exe"
    first_seen = "2026-09-30 03:32:12"
  condition:
    hash.sha256(0, filesize) == "f7914bc01cc7681047160cdb1c34d6cb548c16045cb4ef4a868de43f9b8f6844"
}
```

### Sample 75: `e43044d789e8b373`

| Field | Value |
|---|---|
| SHA-256 | `e43044d789e8b37333a7b919f7bbee52d6091c21d1e77941d2f9a369c3dded2a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-30 03:24:42` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f27036787a97ffe0258a0d0c4f41f6fd` |
| SHA-1 | `94a34acb5a7607fbee91641a95e448d18f14e5ac` |
| SHA-256 | `e43044d789e8b37333a7b919f7bbee52d6091c21d1e77941d2f9a369c3dded2a` |
| SHA3-384 | `2fa2fe3345c74e52f25ca02ab27ae5767095ea91fc6a4cb92a96b2a00e7b58e7d4f17acd1ec40c2c0de1d52e2da82b9b` |
| IMPHASH | `a97618426deb6fe67da89127b90ae877` |
| TLSH | `T1E994D827CBAA50D9F83FC13CD3D8F129F5A27D58413DB9BA9A1C86521F34A40532DB4A` |
| SSDEEP | `6144:bb8sh+PH8yjNVy5DGjNGCwKc1R0NAs0hUuPIUIE:EUyZIkGCwKc1ksh3Ptp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_e43044d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e43044d789e8b37333a7b919f7bbee52d6091c21d1e77941d2f9a369c3dded2a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 03:24:42"
  condition:
    hash.sha256(0, filesize) == "e43044d789e8b37333a7b919f7bbee52d6091c21d1e77941d2f9a369c3dded2a"
}
```

### Sample 76: `05328bd4ff7e54df`

| Field | Value |
|---|---|
| SHA-256 | `05328bd4ff7e54df043532cdc91a9ef7c2328583a058dbf1260ebc24827eb001` |
| Family label | `Mirai` |
| File name | `05328bd4ff7e54df043532cdc91a9ef7c2328583a058dbf1260ebc24827eb001` |
| File type | `elf` |
| First seen | `2026-09-30 03:18:10` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11e8393b2ec8b5d0bfd91693b116c437` |
| SHA-1 | `e277734b5e13902e60a73355722526e0c1dace62` |
| SHA-256 | `05328bd4ff7e54df043532cdc91a9ef7c2328583a058dbf1260ebc24827eb001` |
| SHA3-384 | `0e84616ce3f23fc83ea81769b87ba6384a5433cd2c60cdce91fe011d10f19ce09739b8a347994f4cf7523697b0f4a651` |
| TLSH | `T18444398AFD80AF25D5C5227BFE2F428A331317B8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_05328bd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05328bd4ff7e54df043532cdc91a9ef7c2328583a058dbf1260ebc24827eb001"
    family = "Mirai"
    file_name = "05328bd4ff7e54df043532cdc91a9ef7c2328583a058dbf1260ebc24827eb001"
    file_type = "elf"
    first_seen = "2026-09-30 03:18:10"
  condition:
    hash.sha256(0, filesize) == "05328bd4ff7e54df043532cdc91a9ef7c2328583a058dbf1260ebc24827eb001"
}
```

### Sample 77: `904be243ad96ab64`

| Field | Value |
|---|---|
| SHA-256 | `904be243ad96ab64bb8c8ae261f2e1a75b9108c90c5e76fae9b6f1362792cc8d` |
| Family label | `Expiro` |
| File name | `904be243ad96ab64bb8c8ae261f2e1a75b9108c90c5e76fae9b6f1362792cc8d.bin` |
| File type | `exe` |
| First seen | `2026-09-30 03:17:45` |
| Reporter | `anonymous` |
| Tags | `exe, Expiro, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f3951fa9e5e628a1006449e295d967d` |
| SHA-1 | `dee787e7ad84d36c33cf2de25770a0db28de8526` |
| SHA-256 | `904be243ad96ab64bb8c8ae261f2e1a75b9108c90c5e76fae9b6f1362792cc8d` |
| SHA3-384 | `f1b36b52c974c858844198147a8aa12f1bcd9f8b4dd54ce38ec4a0ba51ffb3c9ea5e38a1f4b0f274e5a053c2d3b9d55c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1EB369E13B9644CF9C196DB3A88775265BA75B8484B3133EB1E60BEB92F363C05E31394` |
| SSDEEP | `49152:2srGgL1+kMbT1hXjoeNXH8QzQu18HRSWdKwfPkqEsNiUpJKDcpHMIBm2Q/lFTjN4:21nbjJV8xSiKwf8gNiUjKDF4uLm` |

#### Technical Assessment

- The sample is tracked as `Expiro` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Expiro_077_904be243
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "904be243ad96ab64bb8c8ae261f2e1a75b9108c90c5e76fae9b6f1362792cc8d"
    family = "Expiro"
    file_name = "904be243ad96ab64bb8c8ae261f2e1a75b9108c90c5e76fae9b6f1362792cc8d.bin"
    file_type = "exe"
    first_seen = "2026-09-30 03:17:45"
  condition:
    hash.sha256(0, filesize) == "904be243ad96ab64bb8c8ae261f2e1a75b9108c90c5e76fae9b6f1362792cc8d"
}
```

### Sample 78: `b6376f4ba9be422d`

| Field | Value |
|---|---|
| SHA-256 | `b6376f4ba9be422d1dc5e8a26e367090d87fd880b73a02237937720ae1eeb394` |
| Family label | `VShell` |
| File name | `b6376f4ba9be422d1dc5e8a26e367090d87fd880b73a02237937720ae1eeb394.exe` |
| File type | `exe` |
| First seen | `2026-09-30 03:16:34` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d38eaed3541b20e284ea4dcfd2765f2` |
| SHA-1 | `6a04346f1819055da533698de16731b48bbf3e2a` |
| SHA-256 | `b6376f4ba9be422d1dc5e8a26e367090d87fd880b73a02237937720ae1eeb394` |
| SHA3-384 | `7c3d7e55c5734109bccda8e1d04188632ce53828eb9a42384e7cc9699834fa136e8405a0adfe3ca90a4e322298090837` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T152716198F3176AF5E42C86F940D3A554C019ABB8C250BF4D5E60381D3C210BA269EF97` |
| SSDEEP | `48:6Icwm0hxt2WdJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jGt/SNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_078_b6376f4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6376f4ba9be422d1dc5e8a26e367090d87fd880b73a02237937720ae1eeb394"
    family = "VShell"
    file_name = "b6376f4ba9be422d1dc5e8a26e367090d87fd880b73a02237937720ae1eeb394.exe"
    file_type = "exe"
    first_seen = "2026-09-30 03:16:34"
  condition:
    hash.sha256(0, filesize) == "b6376f4ba9be422d1dc5e8a26e367090d87fd880b73a02237937720ae1eeb394"
}
```

### Sample 79: `baf1b5d49623ad32`

| Field | Value |
|---|---|
| SHA-256 | `baf1b5d49623ad32cef0b3ce4b7d2cde4b205bf4c0f20968c9190a6c6d462fcc` |
| Family label | `unknown` |
| File name | `baf1b5d49623ad32cef0b3ce4b7d2cde4b205bf4c0f20968c9190a6c6d462fcc.exe` |
| File type | `exe` |
| First seen | `2026-09-30 03:12:19` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `068948bd7e237ce49dffa1a8e78eaae8` |
| SHA-1 | `fca527166487e5a5217115a572cea62a06d79840` |
| SHA-256 | `baf1b5d49623ad32cef0b3ce4b7d2cde4b205bf4c0f20968c9190a6c6d462fcc` |
| SHA3-384 | `2c5d618b263c61a8b8e9ef6e45045bf44feb16dbafa78c6fc0529632cd5896c63fc0d6988a4a188bc93bc7d7e7304bf4` |
| IMPHASH | `c990338f8145dc29c6f38fb73cf05c77` |
| TLSH | `T1D3D63388775D0CDDE95F4735A8E5570763C2B9B353A0C2EF1BA009460A9B1E8FEB5B20` |
| SSDEEP | `393216:h1oW0lLW8lL+8dQusl3VrAZYCuPJO4E3+d94egMP9:h1oWAW8lK8dQuOCJuxmOd94zMF` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_baf1b5d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baf1b5d49623ad32cef0b3ce4b7d2cde4b205bf4c0f20968c9190a6c6d462fcc"
    family = "unknown"
    file_name = "baf1b5d49623ad32cef0b3ce4b7d2cde4b205bf4c0f20968c9190a6c6d462fcc.exe"
    file_type = "exe"
    first_seen = "2026-09-30 03:12:19"
  condition:
    hash.sha256(0, filesize) == "baf1b5d49623ad32cef0b3ce4b7d2cde4b205bf4c0f20968c9190a6c6d462fcc"
}
```

### Sample 80: `da22fa6584627568`

| Field | Value |
|---|---|
| SHA-256 | `da22fa6584627568bbee2501b5b58d2d53f766a2dcf7fc75abb5fdb8beee68bd` |
| Family label | `unknown` |
| File name | `da22fa6584627568bbee2501b5b58d2d53f766a2dcf7fc75abb5fdb8beee68bd.bin` |
| File type | `zip` |
| First seen | `2026-09-30 03:10:30` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9ce2222ca6945f6bc51af5aa57b0b6f` |
| SHA-1 | `e136c08beb78a4fb4b5c93f735cfee583797cd27` |
| SHA-256 | `da22fa6584627568bbee2501b5b58d2d53f766a2dcf7fc75abb5fdb8beee68bd` |
| SHA3-384 | `35643d81f9d6533c08e62ac945612a9f563469b2335aeff3d95eb64cb98d60956f694aa427106b9ebd0846d7c6368a86` |
| TLSH | `T1598533A6CD091604886E7F76E57F81C6BA773E92B30C1F644EE345147EDAE847ECA810` |
| SSDEEP | `49152:vfAYc3QBFwHJeWrZjHfhzqVtQuMSgFnKWqL0:v4D3QBFwpeKjUnQuTgFPqL0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_da22fa65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da22fa6584627568bbee2501b5b58d2d53f766a2dcf7fc75abb5fdb8beee68bd"
    family = "unknown"
    file_name = "da22fa6584627568bbee2501b5b58d2d53f766a2dcf7fc75abb5fdb8beee68bd.bin"
    file_type = "zip"
    first_seen = "2026-09-30 03:10:30"
  condition:
    hash.sha256(0, filesize) == "da22fa6584627568bbee2501b5b58d2d53f766a2dcf7fc75abb5fdb8beee68bd"
}
```

### Sample 81: `5e1e89aa6a72d7ae`

| Field | Value |
|---|---|
| SHA-256 | `5e1e89aa6a72d7aeb2f6c710e0a7f0c673377f088cb187e8623b8a60d5be8792` |
| Family label | `SalatStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-30 03:09:21` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, exe, payload_proxy_v1, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddc410162d0ff0e945ce97c88c694dba` |
| SHA-1 | `78c52a2bb58e7578421393dd2b1075b585497ac0` |
| SHA-256 | `5e1e89aa6a72d7aeb2f6c710e0a7f0c673377f088cb187e8623b8a60d5be8792` |
| SHA3-384 | `f7e991716c8cfbbabd0c7edc66bedd1aee719b1f6728650ad967b88cc04f676a7191d7792da595fe9c281275d4f7586d` |
| IMPHASH | `1465e7eab8316965aaa8e0b0ce1d221d` |
| TLSH | `T1AA5733A863C38EEEEDC05BB78D3113E1E06CFC55D64C890AC97306C65EC7196AB72256` |
| SSDEEP | `393216:DDVCOqoybiDoXqkW+nsvm77zK/lwJPaet4PpLcFnhKE7lqdn3+u0sCMoX2HgJuEC:DDVCOBci8qkW+ndopL0vaN7/HQRTqdj5` |
| ICON-DHASH | `2896969696969696` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_081_5e1e89aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e1e89aa6a72d7aeb2f6c710e0a7f0c673377f088cb187e8623b8a60d5be8792"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 03:09:21"
  condition:
    hash.sha256(0, filesize) == "5e1e89aa6a72d7aeb2f6c710e0a7f0c673377f088cb187e8623b8a60d5be8792"
}
```

### Sample 82: `4642639dc64e95d1`

| Field | Value |
|---|---|
| SHA-256 | `4642639dc64e95d1b2bc142a6dfec376cf55cf313370e7fd434b95a5cc792bb4` |
| Family label | `RemcosRAT` |
| File name | `Fnblgen.vbs` |
| File type | `vbs` |
| First seen | `2026-09-30 03:07:18` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b603913323144de7e406b9f012feb430` |
| SHA-1 | `657caa9ed4ad20fba3442cd8ba8c7645c7e94fc0` |
| SHA-256 | `4642639dc64e95d1b2bc142a6dfec376cf55cf313370e7fd434b95a5cc792bb4` |
| SHA3-384 | `aabaf5dbd32e7ad49a05f750d710fa2bb5bbc32927eda5b4f0cd26d6b16e4ff372b4d380b84b0df192b26cdbd3ca2b79` |
| TLSH | `T1AA145C70ED34026A4F4717AAFCA51A62CABC8619462650F5FEDD030D60079ECE3FE66D` |
| SSDEEP | `3072:PEH+egxBA9o2mcfS6enl/r8aWtOACewRJYW/o0OCaSZpoxre9k7S:Pk+egxUo2mxNfoVCeC6WA0WKCxKd` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_082_4642639d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4642639dc64e95d1b2bc142a6dfec376cf55cf313370e7fd434b95a5cc792bb4"
    family = "RemcosRAT"
    file_name = "Fnblgen.vbs"
    file_type = "vbs"
    first_seen = "2026-09-30 03:07:18"
  condition:
    hash.sha256(0, filesize) == "4642639dc64e95d1b2bc142a6dfec376cf55cf313370e7fd434b95a5cc792bb4"
}
```

### Sample 83: `fa10747c83596b44`

| Field | Value |
|---|---|
| SHA-256 | `fa10747c83596b444b553166f6d9752e235dc043c8d276d5eb56e47c49a49412` |
| Family label | `unknown` |
| File name | `amtlib.dll` |
| File type | `exe` |
| First seen | `2026-09-30 03:01:41` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bcd7ff858c219c0e10f80944b982dc4` |
| SHA-1 | `b6087da32950c3bbb3529d45b86019e2695e726f` |
| SHA-256 | `fa10747c83596b444b553166f6d9752e235dc043c8d276d5eb56e47c49a49412` |
| SHA3-384 | `4b3ed64ef41c0c19e57faa4aab56259ad2a532ca3999573c4033cd5848532c4d1ffda2bf165aadb726e57fbccec504be` |
| IMPHASH | `654d46ac2ef87ad2261d7b2a3f91c4ac` |
| TLSH | `T1C4C56B0A3AA84165C0B7C1BDCA878787F2B2B4050B35ABCF46A4435E1F73BE5467E761` |
| SSDEEP | `49152:9r8DM50KiRb9a3K4Au+WlSOor+B0De35/2TUKzm4imV3Bjne/5yyGAu6MmXYN+6:9rQIB6m4hopr6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_fa10747c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa10747c83596b444b553166f6d9752e235dc043c8d276d5eb56e47c49a49412"
    family = "unknown"
    file_name = "amtlib.dll"
    file_type = "exe"
    first_seen = "2026-09-30 03:01:41"
  condition:
    hash.sha256(0, filesize) == "fa10747c83596b444b553166f6d9752e235dc043c8d276d5eb56e47c49a49412"
}
```

### Sample 84: `5df66da2a9a6cf62`

| Field | Value |
|---|---|
| SHA-256 | `5df66da2a9a6cf62c34f5521392665744ccdd568e50a2a825b554fee895f7453` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-30 02:54:44` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0b309d6fd4c6278c1ce883a453134a3` |
| SHA-1 | `c589d22b92c2ac368b7befa424c2c211a3e3f25a` |
| SHA-256 | `5df66da2a9a6cf62c34f5521392665744ccdd568e50a2a825b554fee895f7453` |
| SHA3-384 | `0523e01e8db5150b0bc3891984199d34c99a6dd6a42bd4e5b1e6891acbb618d02a20f41318498cb687e52a36911de75c` |
| IMPHASH | `2fd6e9fbce3c0193758128e9ae5dbfca` |
| TLSH | `T14784D737CBAA50D9F83BC13CD3DCB52AF5A27D58413DB5BE9A0886521F34A40532DB4A` |
| SSDEEP | `6144:xuWcHhe3uiChOY1BTUbyZ0P6ro9Lk169gcIi6fvW:x8Hh/i898ydroa69hh6fvW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_5df66da2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5df66da2a9a6cf62c34f5521392665744ccdd568e50a2a825b554fee895f7453"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 02:54:44"
  condition:
    hash.sha256(0, filesize) == "5df66da2a9a6cf62c34f5521392665744ccdd568e50a2a825b554fee895f7453"
}
```

### Sample 85: `6fabd20e37b43a88`

| Field | Value |
|---|---|
| SHA-256 | `6fabd20e37b43a88808632f87e5a0e1b953f6763d786af3411060657a3aed79f` |
| Family label | `unknown` |
| File name | `amtlib.dll` |
| File type | `exe` |
| First seen | `2026-09-30 02:47:47` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fa80fefe69439104775c603814f655c` |
| SHA-1 | `b1de488f1e6b3988b6b1dd2f5d2ec115398e5353` |
| SHA-256 | `6fabd20e37b43a88808632f87e5a0e1b953f6763d786af3411060657a3aed79f` |
| SHA3-384 | `6c4cfb6ffe6b6d1c51ba2cf9a095b70d0c11c0884fa0eb3bd44b0886a3d36d6dc284c0056f06194bfaf29a406e9eac47` |
| IMPHASH | `3a14fbca67f2bc2592912382d9740dab` |
| TLSH | `T1ECD57C09765841A1C077C1BDCA878B87F6B274094B31ABDB47A9836E1F33BE1463E761` |
| SSDEEP | `49152:Kxw9oBcZBECi2Dn9wHmkn3nzCwuyGoYQkmLaLuf6aLi5:KsLienMzdFHr6ay` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_6fabd20e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fabd20e37b43a88808632f87e5a0e1b953f6763d786af3411060657a3aed79f"
    family = "unknown"
    file_name = "amtlib.dll"
    file_type = "exe"
    first_seen = "2026-09-30 02:47:47"
  condition:
    hash.sha256(0, filesize) == "6fabd20e37b43a88808632f87e5a0e1b953f6763d786af3411060657a3aed79f"
}
```

### Sample 86: `9d809607203d739d`

| Field | Value |
|---|---|
| SHA-256 | `9d809607203d739d334e4cca3650761e4dcb2024089af4273e10d3e05d65c52c` |
| Family label | `VShell` |
| File name | `9d809607203d739d334e4cca3650761e4dcb2024089af4273e10d3e05d65c52c.exe` |
| File type | `exe` |
| First seen | `2026-09-30 02:45:55` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1db4943e60f05bd615a591d0e69bc31d` |
| SHA-1 | `3659642158521039007769e795b7d95db16a6d5e` |
| SHA-256 | `9d809607203d739d334e4cca3650761e4dcb2024089af4273e10d3e05d65c52c` |
| SHA3-384 | `b605f52564f3397861fe91adb557c4eac7cd5901fbf1c465e303e867b8f6baf1dd67cb1bf098a456c1500ed402bf6b17` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T13F71A74160545AF2D94DE37F8547B895FD5E7248A2C80B0B0798981A2F7507BB1D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DmV8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DWG++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_086_9d809607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d809607203d739d334e4cca3650761e4dcb2024089af4273e10d3e05d65c52c"
    family = "VShell"
    file_name = "9d809607203d739d334e4cca3650761e4dcb2024089af4273e10d3e05d65c52c.exe"
    file_type = "exe"
    first_seen = "2026-09-30 02:45:55"
  condition:
    hash.sha256(0, filesize) == "9d809607203d739d334e4cca3650761e4dcb2024089af4273e10d3e05d65c52c"
}
```

### Sample 87: `4cb75775ee2f88f3`

| Field | Value |
|---|---|
| SHA-256 | `4cb75775ee2f88f315353e180dd516551d0dd1fb3e41a6b6a2e93a988ddfc9ca` |
| Family label | `VShell` |
| File name | `4cb75775ee2f88f315353e180dd516551d0dd1fb3e41a6b6a2e93a988ddfc9ca.exe` |
| File type | `exe` |
| First seen | `2026-09-30 02:45:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7ebf8722a0cda79902f646df1620814` |
| SHA-1 | `08036157308509374a600aa50e996bbb359ae3cf` |
| SHA-256 | `4cb75775ee2f88f315353e180dd516551d0dd1fb3e41a6b6a2e93a988ddfc9ca` |
| SHA3-384 | `d28ee3ed853b2984d8b2d0ba53382376618320ce36b9601a1ab1adbcc97d1a69789620b6336a703bbca9ab3d782f4df5` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T11C71D641605416F2E94DE37F8487B895FD5FB24CA2D80B0F0798981A2F710BBB1DD613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6D12Hvjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6D1I7++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_087_4cb75775
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cb75775ee2f88f315353e180dd516551d0dd1fb3e41a6b6a2e93a988ddfc9ca"
    family = "VShell"
    file_name = "4cb75775ee2f88f315353e180dd516551d0dd1fb3e41a6b6a2e93a988ddfc9ca.exe"
    file_type = "exe"
    first_seen = "2026-09-30 02:45:49"
  condition:
    hash.sha256(0, filesize) == "4cb75775ee2f88f315353e180dd516551d0dd1fb3e41a6b6a2e93a988ddfc9ca"
}
```

### Sample 88: `0f8fcbb8b07a3a35`

| Field | Value |
|---|---|
| SHA-256 | `0f8fcbb8b07a3a3555c2fa2d1deaf2e314ca034e1d591922c647bb6689ddadd7` |
| Family label | `Panchan` |
| File name | `0f8fcbb8b07a3a3555c2fa2d1deaf2e314ca034e1d591922c647bb6689ddadd7` |
| File type | `elf` |
| First seen | `2026-09-30 02:39:40` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, Panchan, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fdb99b3a9f37d9d349054a219eec705` |
| SHA-1 | `fffd56f9723254c13e7dfa684f86b9c578ab653b` |
| SHA-256 | `0f8fcbb8b07a3a3555c2fa2d1deaf2e314ca034e1d591922c647bb6689ddadd7` |
| SHA3-384 | `82ffed882c0c0168791d8451dbfbda56ec8506ed56040760a9dce903c0294d54f469e0b83ae92c26a4d439aee0f01aff` |
| TLSH | `T1C2B68C73905334D9E5A88DB4D11416426DBC388B5738A3CBBAC471F667BABE48E39730` |
| SSDEEP | `49152:cSk1vGE1pFrb/T/vO90dL3BmAFd4A64nsfJvWSIsWWKbeJMJpn14PE9Z7rYPVnaV:sXyWSpV+Wu7rI3JEf` |

#### Technical Assessment

- The sample is tracked as `Panchan` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Panchan_088_0f8fcbb8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f8fcbb8b07a3a3555c2fa2d1deaf2e314ca034e1d591922c647bb6689ddadd7"
    family = "Panchan"
    file_name = "0f8fcbb8b07a3a3555c2fa2d1deaf2e314ca034e1d591922c647bb6689ddadd7"
    file_type = "elf"
    first_seen = "2026-09-30 02:39:40"
  condition:
    hash.sha256(0, filesize) == "0f8fcbb8b07a3a3555c2fa2d1deaf2e314ca034e1d591922c647bb6689ddadd7"
}
```

### Sample 89: `8de70090fceb1fe9`

| Field | Value |
|---|---|
| SHA-256 | `8de70090fceb1fe920e766e6af7c64d7a15e5172ec1315f83e0f9030dd28c354` |
| Family label | `unknown` |
| File name | `8de70090fceb1fe920e766e6af7c64d7a15e5172ec1315f83e0f9030dd28c354` |
| File type | `elf` |
| First seen | `2026-09-30 02:31:34` |
| Reporter | `APT6pack` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d2aad52666b73a317c33718459c089d` |
| SHA-1 | `97139853bd97709c0fb0710a0292dbbfe16a00aa` |
| SHA-256 | `8de70090fceb1fe920e766e6af7c64d7a15e5172ec1315f83e0f9030dd28c354` |
| SHA3-384 | `fb1cbcbb8aeccf93632baca25da0fca5eaf1344c16bdc2cac67d4a15573c77bc1ffb403e12c10a9953da2c33dc8f4540` |
| TLSH | `T17A967C73945224D8E1A9C9B4D51416527DB83C8B573873CBBAC472F61BBABE48E78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQP:cqYUQuVDt0TZEo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_8de70090
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8de70090fceb1fe920e766e6af7c64d7a15e5172ec1315f83e0f9030dd28c354"
    family = "unknown"
    file_name = "8de70090fceb1fe920e766e6af7c64d7a15e5172ec1315f83e0f9030dd28c354"
    file_type = "elf"
    first_seen = "2026-09-30 02:31:34"
  condition:
    hash.sha256(0, filesize) == "8de70090fceb1fe920e766e6af7c64d7a15e5172ec1315f83e0f9030dd28c354"
}
```

### Sample 90: `57d380ea2a26ea94`

| Field | Value |
|---|---|
| SHA-256 | `57d380ea2a26ea9417f6f29439faa74ca4714f1e387da00966414262e23cb58f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-30 02:30:15` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8db14ab16aa504b7546405747e958785` |
| SHA-1 | `3e21b893110f33af137a587139fddd92ca9658d5` |
| SHA-256 | `57d380ea2a26ea9417f6f29439faa74ca4714f1e387da00966414262e23cb58f` |
| SHA3-384 | `c67244b344f6a09317979ec524b61b5500b3e4a40fe52e2afc0eb45b914871e8ee9f3ab88beadaab5c52a36e86e9c311` |
| IMPHASH | `8564a6612f67bd19558c0551430ba523` |
| TLSH | `T1AA250872BB41CDFCF8B11A3C4140055AB071A97F95EA19A6A9BE41D04F2A9C16FF732C` |
| SSDEEP | `24576:6/D8Qhn+fbF5hoeUxsDlxFfFFJHv7YO2cgtTorkOMVMxMqMoMPMeMiMbMFMaMBMO:6b8QQJXpFFfpv7YO2cgtTorkOMVMxMqp` |
| ICON-DHASH | `0000696969701000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_57d380ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57d380ea2a26ea9417f6f29439faa74ca4714f1e387da00966414262e23cb58f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 02:30:15"
  condition:
    hash.sha256(0, filesize) == "57d380ea2a26ea9417f6f29439faa74ca4714f1e387da00966414262e23cb58f"
}
```

### Sample 91: `0c5f5128863d2941`

| Field | Value |
|---|---|
| SHA-256 | `0c5f5128863d2941055e187b3e9346a072230bff005a5bbf924c2664d561e121` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-30 02:29:53` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX14.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39b9113ced7577d7f9ee89cde31d9e79` |
| SHA-1 | `31732933fdd24c3149d99fb429d595bf55fa43a8` |
| SHA-256 | `0c5f5128863d2941055e187b3e9346a072230bff005a5bbf924c2664d561e121` |
| SHA3-384 | `9e8036ee5f09604382d2dbb11639c91fecddbdcad1c69f15bf7023fcadf4a36bbc7ffa8f3e11346622e16466c1e909d7` |
| IMPHASH | `fd6f6d07cc33ee9a2b65bda58a07bb94` |
| TLSH | `T189286C43A2E751D8F0BBD17496E65323E933BC490B3469EF12944B312F72AE0A779B11` |
| SSDEEP | `1572864:xZa7hmguP2nG0/Vyv7UhgxIabc/97Awb0:xZa7hmguP2nUOTAwb0` |
| ICON-DHASH | `9170cc9296cc7001` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_0c5f5128
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c5f5128863d2941055e187b3e9346a072230bff005a5bbf924c2664d561e121"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 02:29:53"
  condition:
    hash.sha256(0, filesize) == "0c5f5128863d2941055e187b3e9346a072230bff005a5bbf924c2664d561e121"
}
```

### Sample 92: `900ef753fe18d8d8`

| Field | Value |
|---|---|
| SHA-256 | `900ef753fe18d8d86c8ef735983590c65b378d03ffe6f546925a6b1c928e134a` |
| Family label | `Mirai` |
| File name | `900ef753fe18d8d8.bin` |
| File type | `elf` |
| First seen | `2026-09-30 02:25:15` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6664bc1b24dc9528410918759bedcaa4` |
| SHA-1 | `d498ef2686b5300806f21317314d8d8b954dc472` |
| SHA-256 | `900ef753fe18d8d86c8ef735983590c65b378d03ffe6f546925a6b1c928e134a` |
| SHA3-384 | `774ef33842c158e698640a2c3019524a9bf091451925bf179835a7affc3afbd3ff462dcbec9fc495cc328202968001f0` |
| TLSH | `T148D44A55F8809F63C9C52A36F64E866833274778C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKig:YCp7mXtni6aBh321eSiVWKv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_900ef753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "900ef753fe18d8d86c8ef735983590c65b378d03ffe6f546925a6b1c928e134a"
    family = "Mirai"
    file_name = "900ef753fe18d8d8.bin"
    file_type = "elf"
    first_seen = "2026-09-30 02:25:15"
  condition:
    hash.sha256(0, filesize) == "900ef753fe18d8d86c8ef735983590c65b378d03ffe6f546925a6b1c928e134a"
}
```

### Sample 93: `e5f9cf89459a82e0`

| Field | Value |
|---|---|
| SHA-256 | `e5f9cf89459a82e09b351021a182b41463feed3439cf775e76a988970c98b937` |
| Family label | `Mirai` |
| File name | `e5f9cf89459a82e0.bin` |
| File type | `elf` |
| First seen | `2026-09-30 02:25:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d36cd8ebb1fb32fc798fad252f88cc3a` |
| SHA-1 | `84cc49888f2f6a361997c79b66a747cd1a44f4b6` |
| SHA-256 | `e5f9cf89459a82e09b351021a182b41463feed3439cf775e76a988970c98b937` |
| SHA3-384 | `c502d3c38cb5d4d9fc5fad3b95141ae86650b783503ccaa63ffb8a1d372a188e635e41e3b633a21590bc6a6d237f6f73` |
| TLSH | `T178355C46EF406FEBC49FCD30492EC31721EDE8CB42D5A62971BC4A8C7A5D3590AD3698` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:ApvR6ZM35dQ4ZmHd7dcCoLJTxwpTmVXxTCnOKW80:Y6QS97FixxxxTCnz0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_e5f9cf89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5f9cf89459a82e09b351021a182b41463feed3439cf775e76a988970c98b937"
    family = "Mirai"
    file_name = "e5f9cf89459a82e0.bin"
    file_type = "elf"
    first_seen = "2026-09-30 02:25:07"
  condition:
    hash.sha256(0, filesize) == "e5f9cf89459a82e09b351021a182b41463feed3439cf775e76a988970c98b937"
}
```

### Sample 94: `6446239855653321`

| Field | Value |
|---|---|
| SHA-256 | `64462398556533215f30bebfe9c62a18baaf0ed882407106d646a4ac053f79b3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-30 02:21:51` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a1166bffeb8ea0f096f24abd3da3b05` |
| SHA-1 | `b832cba8019f1b226ebd45a5f95f3aad6240b5a7` |
| SHA-256 | `64462398556533215f30bebfe9c62a18baaf0ed882407106d646a4ac053f79b3` |
| SHA3-384 | `e422a6b4199cabdab768e48479de2e9c409e1baf696b67b97f3689ddb6c83b570443e9c635bbd43db4e5694b31a694a0` |
| IMPHASH | `dccb5acc1e2fed10ec52d2fcdbbceaaa` |
| TLSH | `T1A8957BC9DF6FD4A4F157CE37D91A004BA7D53D4288ECFB951A2EEE8069709DF186008A` |
| SSDEEP | `24576:6RyO7U8AE/vK7C7hbvkuu+dvFh7WY146LhzzWCNu7R1wQWhXsYz:MX5vkupdrN4+zRNKzE+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_64462398
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64462398556533215f30bebfe9c62a18baaf0ed882407106d646a4ac053f79b3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 02:21:51"
  condition:
    hash.sha256(0, filesize) == "64462398556533215f30bebfe9c62a18baaf0ed882407106d646a4ac053f79b3"
}
```

### Sample 95: `25f4118ae989c009`

| Field | Value |
|---|---|
| SHA-256 | `25f4118ae989c009c26943b29ad08553509947a72ee2e4374b5f26a2ba0b0399` |
| Family label | `unknown` |
| File name | `25f4118ae989c009c26943b29ad08553509947a72ee2e4374b5f26a2ba0b0399` |
| File type | `sh` |
| First seen | `2026-09-30 02:17:24` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, dropper, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29a4b6a65b316d780b7684391e1b87c1` |
| SHA-1 | `c6ab1efba99e35108aa61e713cd5225b0e2b02f7` |
| SHA-256 | `25f4118ae989c009c26943b29ad08553509947a72ee2e4374b5f26a2ba0b0399` |
| SHA3-384 | `4888eedc1a63399cb5f1fcf3b8269c7f68dc10691d5bf709b54e8b1cbdb9ed6f8cc2491ece2ca30a510249014b487835` |
| TLSH | `T11431448553724F126867C509F36888CCB45AF6AF1AD7BFBCCCDF16E8604890AF145E19` |
| SSDEEP | `48:EJk5JkbJk3JkHrJkWaJkVoSFJkNLFJkxJJkrbJk37CnsJkqsJkX:Ey5yby3yHryWayXyTyxJyrbyFyZyX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_25f4118a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25f4118ae989c009c26943b29ad08553509947a72ee2e4374b5f26a2ba0b0399"
    family = "unknown"
    file_name = "25f4118ae989c009c26943b29ad08553509947a72ee2e4374b5f26a2ba0b0399"
    file_type = "sh"
    first_seen = "2026-09-30 02:17:24"
  condition:
    hash.sha256(0, filesize) == "25f4118ae989c009c26943b29ad08553509947a72ee2e4374b5f26a2ba0b0399"
}
```

### Sample 96: `fa4f87cf4a160ada`

| Field | Value |
|---|---|
| SHA-256 | `fa4f87cf4a160adaf1ae493a24ae003a72bbbf6b20c283dd8da80e17ed8d4f0c` |
| Family label | `Mirai` |
| File name | `fa4f87cf4a160adaf1ae493a24ae003a72bbbf6b20c283dd8da80e17ed8d4f0c` |
| File type | `elf` |
| First seen | `2026-09-30 02:17:13` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b52e6f984799554e9cf2e9ee5665d941` |
| SHA-1 | `36a4dd3ea7af07dd0c6fc948eaca93b80a0bbd07` |
| SHA-256 | `fa4f87cf4a160adaf1ae493a24ae003a72bbbf6b20c283dd8da80e17ed8d4f0c` |
| SHA3-384 | `bae036e30837bb6638a19228f141cab76203e2f88fdb9d2705033712f8ec881f254c35a9ebbb9d6d3298f6428d7c182d` |
| TLSH | `T1A3D3199FFD81AE6546C0277BFE2E418A331327B4D2DB71139D041F28768A94F0E7A642` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmo:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_fa4f87cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa4f87cf4a160adaf1ae493a24ae003a72bbbf6b20c283dd8da80e17ed8d4f0c"
    family = "Mirai"
    file_name = "fa4f87cf4a160adaf1ae493a24ae003a72bbbf6b20c283dd8da80e17ed8d4f0c"
    file_type = "elf"
    first_seen = "2026-09-30 02:17:13"
  condition:
    hash.sha256(0, filesize) == "fa4f87cf4a160adaf1ae493a24ae003a72bbbf6b20c283dd8da80e17ed8d4f0c"
}
```

### Sample 97: `2731ec852d3fb2d6`

| Field | Value |
|---|---|
| SHA-256 | `2731ec852d3fb2d6da239978f376ffc94c86ac484b4521dfaef944388fd3fcae` |
| Family label | `unknown` |
| File name | `2731ec852d3fb2d6da239978f376ffc94c86ac484b4521dfaef944388fd3fcae.exe` |
| File type | `exe` |
| First seen | `2026-09-30 02:12:26` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dfc04091a89e5105c03cf7f9ef24811` |
| SHA-1 | `a05f17ff44007ac323fd2f5c8b25d5e9588e6d95` |
| SHA-256 | `2731ec852d3fb2d6da239978f376ffc94c86ac484b4521dfaef944388fd3fcae` |
| SHA3-384 | `824fffe9f77ff7458d03d703da887f15a2134db7462ea87e7f1251305ffdf11be0445637dfe20abebb7f3c010bc28e47` |
| IMPHASH | `c990338f8145dc29c6f38fb73cf05c77` |
| TLSH | `T1B3D63348774D0CDDE95F8735A8E6571763C2B9B353A0C2DF1BA009460A9B1E8FEB5B20` |
| SSDEEP | `393216:01oW0lLW8lL+8dQusl3VrAZYCuPJO4E3+d94eg/o9:01oWAW8lK8dQuOCJuxmOd94z/+` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_2731ec85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2731ec852d3fb2d6da239978f376ffc94c86ac484b4521dfaef944388fd3fcae"
    family = "unknown"
    file_name = "2731ec852d3fb2d6da239978f376ffc94c86ac484b4521dfaef944388fd3fcae.exe"
    file_type = "exe"
    first_seen = "2026-09-30 02:12:26"
  condition:
    hash.sha256(0, filesize) == "2731ec852d3fb2d6da239978f376ffc94c86ac484b4521dfaef944388fd3fcae"
}
```

### Sample 98: `a8e94547f655de34`

| Field | Value |
|---|---|
| SHA-256 | `a8e94547f655de34a6efdc4d77cdf857cef022cf9ad951d0de67cf25473fe58d` |
| Family label | `unknown` |
| File name | `larp-v9.jar` |
| File type | `jar` |
| First seen | `2026-09-30 02:08:51` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `164fb23c88c3714c5210597b4fb54395` |
| SHA-1 | `6f39c23b2a268d977efcdee7b44708365dc109c3` |
| SHA-256 | `a8e94547f655de34a6efdc4d77cdf857cef022cf9ad951d0de67cf25473fe58d` |
| SHA3-384 | `7940055cbbcb917669bb1be9a395d0b096cd6d8af73584239ac4a9b527ebeeea8488a51155765cf3d2751d85f9a9dc5c` |
| TLSH | `T15E0833E840F21724D21DC67D0ED52FB11AF06C2E266C2B9AFA30EFDB249576619DCD09` |
| SSDEEP | `1572864:7iP+BWk1RmNmGRDzISB24MoJxMTeFcCBYy8NJumM:rWkTHSDkKxv6lCeLrM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_a8e94547
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8e94547f655de34a6efdc4d77cdf857cef022cf9ad951d0de67cf25473fe58d"
    family = "unknown"
    file_name = "larp-v9.jar"
    file_type = "jar"
    first_seen = "2026-09-30 02:08:51"
  condition:
    hash.sha256(0, filesize) == "a8e94547f655de34a6efdc4d77cdf857cef022cf9ad951d0de67cf25473fe58d"
}
```

### Sample 99: `df703fb731180cfc`

| Field | Value |
|---|---|
| SHA-256 | `df703fb731180cfc090c985d06a5d5b0ee764b9a970c0ed7a2205ad34af48400` |
| Family label | `GuLoader` |
| File name | `Surveyor docs_compressed.vbs` |
| File type | `vbs` |
| First seen | `2026-09-30 01:58:09` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b4a5885cef0d2734853c6c81987254e` |
| SHA-1 | `0210e7f225334e336375c7dd5d398b8319541fc8` |
| SHA-256 | `df703fb731180cfc090c985d06a5d5b0ee764b9a970c0ed7a2205ad34af48400` |
| SHA3-384 | `01374680483659a87944654e00aa87371165b6e63abae32345cbe4ec42d3551ba87e22cf6c580fed22ccf70700731f7f` |
| TLSH | `T104B24D62DE4126259D071B96984D6874EF65006601630272FEFD722E2907F6CB7BCD1F` |
| SSDEEP | `768:RihPBUoGmvmVOWppTrLuZynvASLsB0/PksOy:MzE3OOLPvAHBImy` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_099_df703fb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df703fb731180cfc090c985d06a5d5b0ee764b9a970c0ed7a2205ad34af48400"
    family = "GuLoader"
    file_name = "Surveyor docs_compressed.vbs"
    file_type = "vbs"
    first_seen = "2026-09-30 01:58:09"
  condition:
    hash.sha256(0, filesize) == "df703fb731180cfc090c985d06a5d5b0ee764b9a970c0ed7a2205ad34af48400"
}
```

### Sample 100: `92f9d5ac6813ca77`

| Field | Value |
|---|---|
| SHA-256 | `92f9d5ac6813ca77e92a511f584bbc2017dd8b92cebb60bfc20a83df33f2631e` |
| Family label | `unknown` |
| File name | `stage1_92f9d5ac6813.zsh` |
| File type | `zsh` |
| First seen | `2026-09-30 01:52:58` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, macOS, stage1, zsh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b13641e5d100b2f67404aa2685f7db9b` |
| SHA-1 | `f4ddfbef286bbf42b6b717a4473a7e8d6f219f94` |
| SHA-256 | `92f9d5ac6813ca77e92a511f584bbc2017dd8b92cebb60bfc20a83df33f2631e` |
| SHA3-384 | `4bf3e1c87b39735c64410eb43946ede013e59a8e224cece20594dc65651d5333b5959a9fb0209ad5634bc3dc8a590038` |
| TLSH | `T1AE21E9DC574824D8BA58912D18287763609B07AFA813E8CE24088F9F51DB287908E13B` |
| SSDEEP | `24:QZstezSANMeKyuC05Hp9SftVs0hCH43GJVqnhBco2t+ifygVvjdEBwjRBke6VJaB:QhzS470Np94PCrJVqnhBgNvDkPV8XrVD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zsh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_92f9d5ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92f9d5ac6813ca77e92a511f584bbc2017dd8b92cebb60bfc20a83df33f2631e"
    family = "unknown"
    file_name = "stage1_92f9d5ac6813.zsh"
    file_type = "zsh"
    first_seen = "2026-09-30 01:52:58"
  condition:
    hash.sha256(0, filesize) == "92f9d5ac6813ca77e92a511f584bbc2017dd8b92cebb60bfc20a83df33f2631e"
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
 * Generated: 2026-09-30T05:41:32.572653+00:00
 */

rule MalwareBazaar_unknown_001_2f97c02e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f97c02e4b1ab2df51d41f7a7381eae1d32c235e5713872ce44da7cf2674b919"
    family = "unknown"
    file_name = "stub.armv7l"
    file_type = "elf"
    first_seen = "2026-09-30 05:39:39"
  condition:
    hash.sha256(0, filesize) == "2f97c02e4b1ab2df51d41f7a7381eae1d32c235e5713872ce44da7cf2674b919"
}

rule MalwareBazaar_unknown_002_ab17364d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab17364d33e70a6957e35317cc25b730c5d74bb4bc9eb7329c714d96c69dc8c8"
    family = "unknown"
    file_name = "stub.arm7n"
    file_type = "elf"
    first_seen = "2026-09-30 05:39:37"
  condition:
    hash.sha256(0, filesize) == "ab17364d33e70a6957e35317cc25b730c5d74bb4bc9eb7329c714d96c69dc8c8"
}

rule MalwareBazaar_Mirai_003_e4cf87d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4cf87d31ce05e0909033a02b3ea34379467b15d964615c02762313dc80c86a7"
    family = "Mirai"
    file_name = "stub.armv7l"
    file_type = "elf"
    first_seen = "2026-09-30 05:35:35"
  condition:
    hash.sha256(0, filesize) == "e4cf87d31ce05e0909033a02b3ea34379467b15d964615c02762313dc80c86a7"
}

rule MalwareBazaar_Mirai_004_67b17ca0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67b17ca00fbade5328efd11825f3db4539466074bfcaa0edc38e12aecca222ad"
    family = "Mirai"
    file_name = "bot.mips64el"
    file_type = "elf"
    first_seen = "2026-09-30 05:31:44"
  condition:
    hash.sha256(0, filesize) == "67b17ca00fbade5328efd11825f3db4539466074bfcaa0edc38e12aecca222ad"
}

rule MalwareBazaar_Mirai_005_0794992c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0794992cacb0566792c0a3d5caf01122aa0015fbb014abb512b09eb8b3a53bff"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-09-30 05:31:42"
  condition:
    hash.sha256(0, filesize) == "0794992cacb0566792c0a3d5caf01122aa0015fbb014abb512b09eb8b3a53bff"
}

rule MalwareBazaar_Mirai_006_49556514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "495565141e708a35526c564e32a76a5bb9de1a6aaddf6d05ae59c0565b66d6e8"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-09-30 05:31:40"
  condition:
    hash.sha256(0, filesize) == "495565141e708a35526c564e32a76a5bb9de1a6aaddf6d05ae59c0565b66d6e8"
}

rule MalwareBazaar_unknown_007_219b6a17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "219b6a17cc6396182eb34177940893c511bf02d9e08f99fa6246e63b1b10f7e9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 05:28:30"
  condition:
    hash.sha256(0, filesize) == "219b6a17cc6396182eb34177940893c511bf02d9e08f99fa6246e63b1b10f7e9"
}

rule MalwareBazaar_Mirai_008_174dbc02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "174dbc02039af436613f492a86073791d364334bc645ffbbc4236e9a62d32032"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-09-30 05:23:49"
  condition:
    hash.sha256(0, filesize) == "174dbc02039af436613f492a86073791d364334bc645ffbbc4236e9a62d32032"
}

rule MalwareBazaar_Mirai_009_73094f40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73094f400276795deb15f6297d58528e024138ab1b2dd57005d4108f89d7253b"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-30 05:23:47"
  condition:
    hash.sha256(0, filesize) == "73094f400276795deb15f6297d58528e024138ab1b2dd57005d4108f89d7253b"
}

rule MalwareBazaar_Mirai_010_52956172
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5295617257bfc7b31e3e72429a683e1d69b7bf9383620dffa56754ce851d0864"
    family = "Mirai"
    file_name = "bot.armv7"
    file_type = "elf"
    first_seen = "2026-09-30 05:23:46"
  condition:
    hash.sha256(0, filesize) == "5295617257bfc7b31e3e72429a683e1d69b7bf9383620dffa56754ce851d0864"
}

rule MalwareBazaar_Mirai_011_51411125
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51411125ed12a9dae114511b4b7c5f0e8ee14b8cab86f92647d6dbbc450114c5"
    family = "Mirai"
    file_name = "stub.x86_64"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:53"
  condition:
    hash.sha256(0, filesize) == "51411125ed12a9dae114511b4b7c5f0e8ee14b8cab86f92647d6dbbc450114c5"
}

rule MalwareBazaar_Mirai_012_d5017feb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5017febf2f9b128d2fa5c575202bf2bb3efaf3c861734d4889278bb6b2b1f96"
    family = "Mirai"
    file_name = "stub.armv8"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:52"
  condition:
    hash.sha256(0, filesize) == "d5017febf2f9b128d2fa5c575202bf2bb3efaf3c861734d4889278bb6b2b1f96"
}

rule MalwareBazaar_Mirai_013_1004a859
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1004a859d6e6509559172c2bb9a68549cc06688660dac750d7e1d4c343f927d3"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:50"
  condition:
    hash.sha256(0, filesize) == "1004a859d6e6509559172c2bb9a68549cc06688660dac750d7e1d4c343f927d3"
}

rule MalwareBazaar_Mirai_014_1ecb01ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ecb01adec3af3032989adfb1e79e0eb82d450430c6a868901e801e076dce030"
    family = "Mirai"
    file_name = "stub.armv6"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:48"
  condition:
    hash.sha256(0, filesize) == "1ecb01adec3af3032989adfb1e79e0eb82d450430c6a868901e801e076dce030"
}

rule MalwareBazaar_Mirai_015_69b17e5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69b17e5f3531dc3fa8e7d1ca4fe516ef5a575ff1d8a47ccecd17be8337d3be2c"
    family = "Mirai"
    file_name = "stub.x86-64"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:46"
  condition:
    hash.sha256(0, filesize) == "69b17e5f3531dc3fa8e7d1ca4fe516ef5a575ff1d8a47ccecd17be8337d3be2c"
}

rule MalwareBazaar_Mirai_016_00a10182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00a1018204242147be0620ed850d74409a1e0da7fb991849740ca15a530b04ba"
    family = "Mirai"
    file_name = "stub.armv6l"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:44"
  condition:
    hash.sha256(0, filesize) == "00a1018204242147be0620ed850d74409a1e0da7fb991849740ca15a530b04ba"
}

rule MalwareBazaar_Mirai_017_b00d1679
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b00d16792a16077d0a3e0a16149c1c7c0dc70ddf0147cea7c155c6f2dfa55032"
    family = "Mirai"
    file_name = "stub.i486"
    file_type = "elf"
    first_seen = "2026-09-30 05:19:43"
  condition:
    hash.sha256(0, filesize) == "b00d16792a16077d0a3e0a16149c1c7c0dc70ddf0147cea7c155c6f2dfa55032"
}

rule MalwareBazaar_Mirai_018_c07ab9f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c07ab9f66f39cb1423c8cc72782f3c5254c116bab2e239673eefbc54948659b9"
    family = "Mirai"
    file_name = "c07ab9f66f39cb1423c8cc72782f3c5254c116bab2e239673eefbc54948659b9"
    file_type = "elf"
    first_seen = "2026-09-30 05:17:14"
  condition:
    hash.sha256(0, filesize) == "c07ab9f66f39cb1423c8cc72782f3c5254c116bab2e239673eefbc54948659b9"
}

rule MalwareBazaar_Mirai_019_d9d8ea56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9d8ea56ef343d1e63fa5665ecd1084e60f65c0fe9a471ac8f357c597e3613e1"
    family = "Mirai"
    file_name = "bot.x86-64"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:43"
  condition:
    hash.sha256(0, filesize) == "d9d8ea56ef343d1e63fa5665ecd1084e60f65c0fe9a471ac8f357c597e3613e1"
}

rule MalwareBazaar_Mirai_020_a50900a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a50900a3111e7f5632717a37b19091deb5fefb0e57c2bbcde1930620ec995ec5"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:42"
  condition:
    hash.sha256(0, filesize) == "a50900a3111e7f5632717a37b19091deb5fefb0e57c2bbcde1930620ec995ec5"
}

rule MalwareBazaar_Mirai_021_ac5d62a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac5d62a69da73a6c6c62fa5f6fa2a77226a34568e84fcd5cc9461e18b521a758"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:40"
  condition:
    hash.sha256(0, filesize) == "ac5d62a69da73a6c6c62fa5f6fa2a77226a34568e84fcd5cc9461e18b521a758"
}

rule MalwareBazaar_Mirai_022_10ebb204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10ebb20474532eec4293732cc3639c3c61b7a6e5247024c65230818adcc5a433"
    family = "Mirai"
    file_name = "stub.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:38"
  condition:
    hash.sha256(0, filesize) == "10ebb20474532eec4293732cc3639c3c61b7a6e5247024c65230818adcc5a433"
}

rule MalwareBazaar_Mirai_023_8f887f78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f887f787a74418da051d03f591b7b08664550eb8fed9f1642d977f606ef7eaa"
    family = "Mirai"
    file_name = "stub.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:36"
  condition:
    hash.sha256(0, filesize) == "8f887f787a74418da051d03f591b7b08664550eb8fed9f1642d977f606ef7eaa"
}

rule MalwareBazaar_Mirai_024_18062a51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18062a5140b7f3488e2a63d3fea56f1065169f45759eedf0f310c2c316f2c2c6"
    family = "Mirai"
    file_name = "bot.armv7l"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:34"
  condition:
    hash.sha256(0, filesize) == "18062a5140b7f3488e2a63d3fea56f1065169f45759eedf0f310c2c316f2c2c6"
}

rule MalwareBazaar_Mirai_025_de6ab487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de6ab4878d659cbf6c912429800d335086f70f9a1a54b6475a12b8a4334d1fe9"
    family = "Mirai"
    file_name = "bot.armv5l"
    file_type = "elf"
    first_seen = "2026-09-30 05:15:32"
  condition:
    hash.sha256(0, filesize) == "de6ab4878d659cbf6c912429800d335086f70f9a1a54b6475a12b8a4334d1fe9"
}

rule MalwareBazaar_unknown_026_f5fd7750
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5fd7750c893af2e8805bc5aef4541200272d043a22efb6b87c59a816ce905a8"
    family = "unknown"
    file_name = "f5fd7750c893af2e8805bc5aef4541200272d043a22efb6b87c59a816ce905a8.bin"
    file_type = "zip"
    first_seen = "2026-09-30 05:13:08"
  condition:
    hash.sha256(0, filesize) == "f5fd7750c893af2e8805bc5aef4541200272d043a22efb6b87c59a816ce905a8"
}

rule MalwareBazaar_unknown_027_ebbfe99f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebbfe99f9be30859d9948d905222769c8f8d690158e1baaaad14088e39adf282"
    family = "unknown"
    file_name = "ebbfe99f9be30859d9948d905222769c8f8d690158e1baaaad14088e39adf282.bin"
    file_type = "zip"
    first_seen = "2026-09-30 05:13:05"
  condition:
    hash.sha256(0, filesize) == "ebbfe99f9be30859d9948d905222769c8f8d690158e1baaaad14088e39adf282"
}

rule MalwareBazaar_unknown_028_4f67e0b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f67e0b3cfcf0297cd4cbc6449abf39962d2c40981bfd8f23a832b634e075a4a"
    family = "unknown"
    file_name = "4f67e0b3cfcf0297cd4cbc6449abf39962d2c40981bfd8f23a832b634e075a4a.bin"
    file_type = "zip"
    first_seen = "2026-09-30 05:12:01"
  condition:
    hash.sha256(0, filesize) == "4f67e0b3cfcf0297cd4cbc6449abf39962d2c40981bfd8f23a832b634e075a4a"
}

rule MalwareBazaar_Mirai_029_5e491de9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e491de9a7635dc3a57305b9d4c48d7efc8187b1f995acb5e4fa785736a01d22"
    family = "Mirai"
    file_name = "bot.i486"
    file_type = "elf"
    first_seen = "2026-09-30 05:11:35"
  condition:
    hash.sha256(0, filesize) == "5e491de9a7635dc3a57305b9d4c48d7efc8187b1f995acb5e4fa785736a01d22"
}

rule MalwareBazaar_Mirai_030_f94bfad5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f94bfad5371c9a30334f4149c4de23009dabeed9b6b69462236e2e60db1aacb1"
    family = "Mirai"
    file_name = "bot.armv6l"
    file_type = "elf"
    first_seen = "2026-09-30 05:11:34"
  condition:
    hash.sha256(0, filesize) == "f94bfad5371c9a30334f4149c4de23009dabeed9b6b69462236e2e60db1aacb1"
}

rule MalwareBazaar_unknown_031_b8345cf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8345cf70594c26324e6a416a2e460a6849f08a50ed901772db61eb80750726a"
    family = "unknown"
    file_name = "b8345cf70594c26324e6a416a2e460a6849f08a50ed901772db61eb80750726a.bin"
    file_type = "zip"
    first_seen = "2026-09-30 05:11:16"
  condition:
    hash.sha256(0, filesize) == "b8345cf70594c26324e6a416a2e460a6849f08a50ed901772db61eb80750726a"
}

rule MalwareBazaar_unknown_032_427bf532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "427bf5324d72089825d253b3515c0d3615cf65623ff59705ad3b2d6a347bc4b5"
    family = "unknown"
    file_name = "427bf5324d72089825d253b3515c0d3615cf65623ff59705ad3b2d6a347bc4b5.bin"
    file_type = "zip"
    first_seen = "2026-09-30 05:10:57"
  condition:
    hash.sha256(0, filesize) == "427bf5324d72089825d253b3515c0d3615cf65623ff59705ad3b2d6a347bc4b5"
}

rule MalwareBazaar_unknown_033_af3c3bc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af3c3bc1808903b8c5efdfd6f7817c400f6c3652e22cea7ef46345877a59342a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 05:10:35"
  condition:
    hash.sha256(0, filesize) == "af3c3bc1808903b8c5efdfd6f7817c400f6c3652e22cea7ef46345877a59342a"
}

rule MalwareBazaar_Mirai_034_8a4214bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a4214bf59af8622727edfdd720402f3535465701d5c536f10ccabb2fc5cdb33"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:43"
  condition:
    hash.sha256(0, filesize) == "8a4214bf59af8622727edfdd720402f3535465701d5c536f10ccabb2fc5cdb33"
}

rule MalwareBazaar_Mirai_035_1cd6c78e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cd6c78ed6769819d03fbb748209f9f3493cec06b050baf5c402671b57632a46"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:41"
  condition:
    hash.sha256(0, filesize) == "1cd6c78ed6769819d03fbb748209f9f3493cec06b050baf5c402671b57632a46"
}

rule MalwareBazaar_Mirai_036_72de1975
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72de1975db60772192ea98a5c73a2f599997a202c16257bd1958fa9066f8e466"
    family = "Mirai"
    file_name = "bot.armv6"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:39"
  condition:
    hash.sha256(0, filesize) == "72de1975db60772192ea98a5c73a2f599997a202c16257bd1958fa9066f8e466"
}

rule MalwareBazaar_Mirai_037_948804a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "948804a9a1599b0ef0d72938e262429c4efea8d97186661d7ca2aac2317812e2"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:38"
  condition:
    hash.sha256(0, filesize) == "948804a9a1599b0ef0d72938e262429c4efea8d97186661d7ca2aac2317812e2"
}

rule MalwareBazaar_Mirai_038_f2ea31b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2ea31b17031e00d5bc0c565764ae5c13f8e29db137c756310a6035b5f4a2c58"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:36"
  condition:
    hash.sha256(0, filesize) == "f2ea31b17031e00d5bc0c565764ae5c13f8e29db137c756310a6035b5f4a2c58"
}

rule MalwareBazaar_Mirai_039_7c0777d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c0777d3bb15d39c902825936f47393cf25df2316059f4e296f5ec3243e800fc"
    family = "Mirai"
    file_name = "stub.arm7n"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:34"
  condition:
    hash.sha256(0, filesize) == "7c0777d3bb15d39c902825936f47393cf25df2316059f4e296f5ec3243e800fc"
}

rule MalwareBazaar_Mirai_040_136d36df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "136d36df1475e71d9bc33fb8a75cf7092e5507792f23d6bfff7440a17b0f076e"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-30 05:07:32"
  condition:
    hash.sha256(0, filesize) == "136d36df1475e71d9bc33fb8a75cf7092e5507792f23d6bfff7440a17b0f076e"
}

rule MalwareBazaar_Mirai_041_47d66886
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47d668860fad5c51f213d55587aaf7de2f3f02cd2c4b27d8a6a434517d0b79a2"
    family = "Mirai"
    file_name = "bot.armv6l"
    file_type = "elf"
    first_seen = "2026-09-30 05:03:39"
  condition:
    hash.sha256(0, filesize) == "47d668860fad5c51f213d55587aaf7de2f3f02cd2c4b27d8a6a434517d0b79a2"
}

rule MalwareBazaar_unknown_042_9bd55815
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd5581518f5dd65131da16bdf34072dca55b3b6121f4ad1090d2cf5e28f691c"
    family = "unknown"
    file_name = "9bd5581518f5dd65131da16bdf34072dca55b3b6121f4ad1090d2cf5e28f691c"
    file_type = "elf"
    first_seen = "2026-09-30 05:00:11"
  condition:
    hash.sha256(0, filesize) == "9bd5581518f5dd65131da16bdf34072dca55b3b6121f4ad1090d2cf5e28f691c"
}

rule MalwareBazaar_Mirai_043_a98178d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a98178d4080f2fbc9281eb79be39cb5ec7906db27d221d3e05e413ed3b5e492d"
    family = "Mirai"
    file_name = "bot.i586"
    file_type = "elf"
    first_seen = "2026-09-30 04:59:35"
  condition:
    hash.sha256(0, filesize) == "a98178d4080f2fbc9281eb79be39cb5ec7906db27d221d3e05e413ed3b5e492d"
}

rule MalwareBazaar_Mirai_044_59e1205c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59e1205cdec5c79c19e4a6b3dc80c1816717156111ef34080e82436d57e47866"
    family = "Mirai"
    file_name = "stub.armv7"
    file_type = "elf"
    first_seen = "2026-09-30 04:59:33"
  condition:
    hash.sha256(0, filesize) == "59e1205cdec5c79c19e4a6b3dc80c1816717156111ef34080e82436d57e47866"
}

rule MalwareBazaar_Mirai_045_496201bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "496201bcd5b16c1ae13ee13a8589919521a1fec974d3064a2969a71e3038048b"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-09-30 04:59:31"
  condition:
    hash.sha256(0, filesize) == "496201bcd5b16c1ae13ee13a8589919521a1fec974d3064a2969a71e3038048b"
}

rule MalwareBazaar_Mirai_046_eb66a153
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb66a153d4efbbc1a875d3e9f197c0393ba2e9250c972d050821f32ed20fe3e2"
    family = "Mirai"
    file_name = "stub.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-30 04:59:30"
  condition:
    hash.sha256(0, filesize) == "eb66a153d4efbbc1a875d3e9f197c0393ba2e9250c972d050821f32ed20fe3e2"
}

rule MalwareBazaar_Mirai_047_74c6c9f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74c6c9f2c96e8e7b203e13352ed6d956d272775da8def9635bbfa68537151d95"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-30 04:55:34"
  condition:
    hash.sha256(0, filesize) == "74c6c9f2c96e8e7b203e13352ed6d956d272775da8def9635bbfa68537151d95"
}

rule MalwareBazaar_Mirai_048_d915a6fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d915a6fc0c35987caf6db0ec4da18b43dc87af1143138b1c888e9d169e932fb2"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-30 04:55:32"
  condition:
    hash.sha256(0, filesize) == "d915a6fc0c35987caf6db0ec4da18b43dc87af1143138b1c888e9d169e932fb2"
}

rule MalwareBazaar_Mirai_049_73e4f1ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73e4f1ab2f9def12d230c086ba9c1de5ed737530306180fca334cad034c587ba"
    family = "Mirai"
    file_name = "stub.arm"
    file_type = "elf"
    first_seen = "2026-09-30 04:55:30"
  condition:
    hash.sha256(0, filesize) == "73e4f1ab2f9def12d230c086ba9c1de5ed737530306180fca334cad034c587ba"
}

rule MalwareBazaar_Mirai_050_dbb31401
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbb314012d8274a918884efeaa3501b31367e0c89386b81de23d60c1efa0cab3"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-30 04:55:28"
  condition:
    hash.sha256(0, filesize) == "dbb314012d8274a918884efeaa3501b31367e0c89386b81de23d60c1efa0cab3"
}

rule MalwareBazaar_Mirai_051_92c8c99a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92c8c99af3bdd8bc48242b0b30a742f6dc946a352b5a6047520fe73576b2637e"
    family = "Mirai"
    file_name = "stub.mpsl"
    file_type = "elf"
    first_seen = "2026-09-30 04:51:36"
  condition:
    hash.sha256(0, filesize) == "92c8c99af3bdd8bc48242b0b30a742f6dc946a352b5a6047520fe73576b2637e"
}

rule MalwareBazaar_Mirai_052_31052cb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31052cb3bf27c7cacd2008e4bb875929bebae7da347b18ac1737bff3cb41eff3"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-09-30 04:51:35"
  condition:
    hash.sha256(0, filesize) == "31052cb3bf27c7cacd2008e4bb875929bebae7da347b18ac1737bff3cb41eff3"
}

rule MalwareBazaar_Mirai_053_e4ac0f86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4ac0f86f31b76ae1f8e81dafa68abe025053cb17e3c1a85e4de740931fd494a"
    family = "Mirai"
    file_name = "stub.arm"
    file_type = "elf"
    first_seen = "2026-09-30 04:51:33"
  condition:
    hash.sha256(0, filesize) == "e4ac0f86f31b76ae1f8e81dafa68abe025053cb17e3c1a85e4de740931fd494a"
}

rule MalwareBazaar_Mirai_054_df7bbe67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df7bbe678d679725ed78c78ad23d1caea50e3c06d6da23cb087a55959c711f2d"
    family = "Mirai"
    file_name = "bot.amd64"
    file_type = "elf"
    first_seen = "2026-09-30 04:51:31"
  condition:
    hash.sha256(0, filesize) == "df7bbe678d679725ed78c78ad23d1caea50e3c06d6da23cb087a55959c711f2d"
}

rule MalwareBazaar_Mirai_055_6cabe8fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cabe8fbd5d6055487cf87ffd78d968c70e443fbd7328911ddaa49a7da7e1c56"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-30 04:47:39"
  condition:
    hash.sha256(0, filesize) == "6cabe8fbd5d6055487cf87ffd78d968c70e443fbd7328911ddaa49a7da7e1c56"
}

rule MalwareBazaar_Mirai_056_134e012f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "134e012f340b9616787422c7e9d3d3db43f83abb1e19efc613bcf1c433ff992a"
    family = "Mirai"
    file_name = "wife.arm7"
    file_type = "elf"
    first_seen = "2026-09-30 04:44:14"
  condition:
    hash.sha256(0, filesize) == "134e012f340b9616787422c7e9d3d3db43f83abb1e19efc613bcf1c433ff992a"
}

rule MalwareBazaar_Mirai_057_74f9ff9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f9ff9f9630f76926286dc42ee469ac4df44dc36e9e02f6309d559d3a76b75b"
    family = "Mirai"
    file_name = "wife.arm7"
    file_type = "elf"
    first_seen = "2026-09-30 04:43:37"
  condition:
    hash.sha256(0, filesize) == "74f9ff9f9630f76926286dc42ee469ac4df44dc36e9e02f6309d559d3a76b75b"
}

rule MalwareBazaar_Mirai_058_a964a420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a964a420b73c720a93354ec5d3e4143d01ce93725117e52cb89cedd5c8d98931"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-30 04:43:35"
  condition:
    hash.sha256(0, filesize) == "a964a420b73c720a93354ec5d3e4143d01ce93725117e52cb89cedd5c8d98931"
}

rule MalwareBazaar_Mirai_059_566f16d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "566f16d07ed078f574d35cbfa1ca7efca6843fdc364725df981f9d95e26741cd"
    family = "Mirai"
    file_name = "bot.mpsl"
    file_type = "elf"
    first_seen = "2026-09-30 04:43:33"
  condition:
    hash.sha256(0, filesize) == "566f16d07ed078f574d35cbfa1ca7efca6843fdc364725df981f9d95e26741cd"
}

rule MalwareBazaar_unknown_060_5ecfc182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ecfc1826938bf3f2b3212788fbd94eed23388d6ae8c80895d43fb934b0f3e0c"
    family = "unknown"
    file_name = "Invoice_and_Packing_List.js"
    file_type = "js"
    first_seen = "2026-09-30 04:40:16"
  condition:
    hash.sha256(0, filesize) == "5ecfc1826938bf3f2b3212788fbd94eed23388d6ae8c80895d43fb934b0f3e0c"
}

rule MalwareBazaar_Mirai_061_f904eca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f904eca10c253c1cfc8f9e44c8c21360c4857f7967ef591db8910e0e44985fe6"
    family = "Mirai"
    file_name = "bot.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-30 04:39:43"
  condition:
    hash.sha256(0, filesize) == "f904eca10c253c1cfc8f9e44c8c21360c4857f7967ef591db8910e0e44985fe6"
}

rule MalwareBazaar_unknown_062_f04343de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f04343dea19a7571b3a7bb3e523b9d32d8e50d58201e60e7770e4a72648fbe64"
    family = "unknown"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-09-30 04:39:41"
  condition:
    hash.sha256(0, filesize) == "f04343dea19a7571b3a7bb3e523b9d32d8e50d58201e60e7770e4a72648fbe64"
}

rule MalwareBazaar_Mirai_063_98146293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "981462933077e0ceece8b21dc32faf8f292e8ff878ae0e342eec0229e1b57d8c"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-09-30 04:39:39"
  condition:
    hash.sha256(0, filesize) == "981462933077e0ceece8b21dc32faf8f292e8ff878ae0e342eec0229e1b57d8c"
}

rule MalwareBazaar_Mirai_064_334787dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "334787dcea96690e2816b16ac6f5f02771c29ffcb691832dcc154a201e473a5c"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-09-30 04:39:37"
  condition:
    hash.sha256(0, filesize) == "334787dcea96690e2816b16ac6f5f02771c29ffcb691832dcc154a201e473a5c"
}

rule MalwareBazaar_Mirai_065_7ccc0933
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ccc09334c38cabc95ba4eb5ba41faa6167dbdff9faf23105b3c92e98f803774"
    family = "Mirai"
    file_name = "stub.mpsl"
    file_type = "elf"
    first_seen = "2026-09-30 04:39:36"
  condition:
    hash.sha256(0, filesize) == "7ccc09334c38cabc95ba4eb5ba41faa6167dbdff9faf23105b3c92e98f803774"
}

rule MalwareBazaar_Mirai_066_130e3e20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "130e3e202b4c17ac6afea9a944739b3cbfe4a4f26b3a3f06b877588f4f0e256e"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-30 04:36:11"
  condition:
    hash.sha256(0, filesize) == "130e3e202b4c17ac6afea9a944739b3cbfe4a4f26b3a3f06b877588f4f0e256e"
}

rule MalwareBazaar_Mirai_067_a8ec3432
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ec3432b30979327e26ef804d8014565240a5e3490690f305a0e4c9e15aa559"
    family = "Mirai"
    file_name = "bot.armv6"
    file_type = "elf"
    first_seen = "2026-09-30 04:32:28"
  condition:
    hash.sha256(0, filesize) == "a8ec3432b30979327e26ef804d8014565240a5e3490690f305a0e4c9e15aa559"
}

rule MalwareBazaar_Mirai_068_117a7ca4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "117a7ca405f65e3bc770fac74903e490011c35e65e1c359e8bea546841919da3"
    family = "Mirai"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-09-30 04:32:26"
  condition:
    hash.sha256(0, filesize) == "117a7ca405f65e3bc770fac74903e490011c35e65e1c359e8bea546841919da3"
}

rule MalwareBazaar_Mirai_069_e21fc021
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e21fc021a38e474746c2f3a4fb06e4d85ce64d2bbc107041e2c97cdf721d80bc"
    family = "Mirai"
    file_name = "bot.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-30 04:25:29"
  condition:
    hash.sha256(0, filesize) == "e21fc021a38e474746c2f3a4fb06e4d85ce64d2bbc107041e2c97cdf721d80bc"
}

rule MalwareBazaar_ConnectWise_070_d5b75afa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5b75afa907d0319cb882da437539b700ca446ace13407bd3c84f9f003bab411"
    family = "ConnectWise"
    file_name = "d5b75afa907d0319cb882da437539b700ca446ace13407bd3c84f9f003bab411.exe"
    file_type = "exe"
    first_seen = "2026-09-30 04:21:30"
  condition:
    hash.sha256(0, filesize) == "d5b75afa907d0319cb882da437539b700ca446ace13407bd3c84f9f003bab411"
}

rule MalwareBazaar_unknown_071_05913ee2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05913ee2a25cc2de7dc10ed47f6d74b4773d722c021d94b4aa6734243401dfdc"
    family = "unknown"
    file_name = "Order specification invoice.js"
    file_type = "js"
    first_seen = "2026-09-30 04:20:39"
  condition:
    hash.sha256(0, filesize) == "05913ee2a25cc2de7dc10ed47f6d74b4773d722c021d94b4aa6734243401dfdc"
}

rule MalwareBazaar_Mirai_072_dada5f36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dada5f36380bdc60e922b8dcb37b92fd603bcd6f6e691102270d2274e37b4827"
    family = "Mirai"
    file_name = "dada5f36380bdc60e922b8dcb37b92fd603bcd6f6e691102270d2274e37b4827"
    file_type = "elf"
    first_seen = "2026-09-30 04:19:15"
  condition:
    hash.sha256(0, filesize) == "dada5f36380bdc60e922b8dcb37b92fd603bcd6f6e691102270d2274e37b4827"
}

rule MalwareBazaar_unknown_073_c89dfe68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c89dfe68747f300a3a2eef694544c2831ef411c38fbe5750d98add68f3462ea0"
    family = "unknown"
    file_name = "FedEx Document_84665.js"
    file_type = "js"
    first_seen = "2026-09-30 04:11:01"
  condition:
    hash.sha256(0, filesize) == "c89dfe68747f300a3a2eef694544c2831ef411c38fbe5750d98add68f3462ea0"
}

rule MalwareBazaar_AsyncRAT_074_f7914bc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7914bc01cc7681047160cdb1c34d6cb548c16045cb4ef4a868de43f9b8f6844"
    family = "AsyncRAT"
    file_name = "P10R05AV_20260929141334 -  KAOHSIUNG, TAIWAN請投高掛.exe"
    file_type = "exe"
    first_seen = "2026-09-30 03:32:12"
  condition:
    hash.sha256(0, filesize) == "f7914bc01cc7681047160cdb1c34d6cb548c16045cb4ef4a868de43f9b8f6844"
}

rule MalwareBazaar_unknown_075_e43044d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e43044d789e8b37333a7b919f7bbee52d6091c21d1e77941d2f9a369c3dded2a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 03:24:42"
  condition:
    hash.sha256(0, filesize) == "e43044d789e8b37333a7b919f7bbee52d6091c21d1e77941d2f9a369c3dded2a"
}

rule MalwareBazaar_Mirai_076_05328bd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05328bd4ff7e54df043532cdc91a9ef7c2328583a058dbf1260ebc24827eb001"
    family = "Mirai"
    file_name = "05328bd4ff7e54df043532cdc91a9ef7c2328583a058dbf1260ebc24827eb001"
    file_type = "elf"
    first_seen = "2026-09-30 03:18:10"
  condition:
    hash.sha256(0, filesize) == "05328bd4ff7e54df043532cdc91a9ef7c2328583a058dbf1260ebc24827eb001"
}

rule MalwareBazaar_Expiro_077_904be243
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "904be243ad96ab64bb8c8ae261f2e1a75b9108c90c5e76fae9b6f1362792cc8d"
    family = "Expiro"
    file_name = "904be243ad96ab64bb8c8ae261f2e1a75b9108c90c5e76fae9b6f1362792cc8d.bin"
    file_type = "exe"
    first_seen = "2026-09-30 03:17:45"
  condition:
    hash.sha256(0, filesize) == "904be243ad96ab64bb8c8ae261f2e1a75b9108c90c5e76fae9b6f1362792cc8d"
}

rule MalwareBazaar_VShell_078_b6376f4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6376f4ba9be422d1dc5e8a26e367090d87fd880b73a02237937720ae1eeb394"
    family = "VShell"
    file_name = "b6376f4ba9be422d1dc5e8a26e367090d87fd880b73a02237937720ae1eeb394.exe"
    file_type = "exe"
    first_seen = "2026-09-30 03:16:34"
  condition:
    hash.sha256(0, filesize) == "b6376f4ba9be422d1dc5e8a26e367090d87fd880b73a02237937720ae1eeb394"
}

rule MalwareBazaar_unknown_079_baf1b5d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baf1b5d49623ad32cef0b3ce4b7d2cde4b205bf4c0f20968c9190a6c6d462fcc"
    family = "unknown"
    file_name = "baf1b5d49623ad32cef0b3ce4b7d2cde4b205bf4c0f20968c9190a6c6d462fcc.exe"
    file_type = "exe"
    first_seen = "2026-09-30 03:12:19"
  condition:
    hash.sha256(0, filesize) == "baf1b5d49623ad32cef0b3ce4b7d2cde4b205bf4c0f20968c9190a6c6d462fcc"
}

rule MalwareBazaar_unknown_080_da22fa65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da22fa6584627568bbee2501b5b58d2d53f766a2dcf7fc75abb5fdb8beee68bd"
    family = "unknown"
    file_name = "da22fa6584627568bbee2501b5b58d2d53f766a2dcf7fc75abb5fdb8beee68bd.bin"
    file_type = "zip"
    first_seen = "2026-09-30 03:10:30"
  condition:
    hash.sha256(0, filesize) == "da22fa6584627568bbee2501b5b58d2d53f766a2dcf7fc75abb5fdb8beee68bd"
}

rule MalwareBazaar_SalatStealer_081_5e1e89aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e1e89aa6a72d7aeb2f6c710e0a7f0c673377f088cb187e8623b8a60d5be8792"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 03:09:21"
  condition:
    hash.sha256(0, filesize) == "5e1e89aa6a72d7aeb2f6c710e0a7f0c673377f088cb187e8623b8a60d5be8792"
}

rule MalwareBazaar_RemcosRAT_082_4642639d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4642639dc64e95d1b2bc142a6dfec376cf55cf313370e7fd434b95a5cc792bb4"
    family = "RemcosRAT"
    file_name = "Fnblgen.vbs"
    file_type = "vbs"
    first_seen = "2026-09-30 03:07:18"
  condition:
    hash.sha256(0, filesize) == "4642639dc64e95d1b2bc142a6dfec376cf55cf313370e7fd434b95a5cc792bb4"
}

rule MalwareBazaar_unknown_083_fa10747c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa10747c83596b444b553166f6d9752e235dc043c8d276d5eb56e47c49a49412"
    family = "unknown"
    file_name = "amtlib.dll"
    file_type = "exe"
    first_seen = "2026-09-30 03:01:41"
  condition:
    hash.sha256(0, filesize) == "fa10747c83596b444b553166f6d9752e235dc043c8d276d5eb56e47c49a49412"
}

rule MalwareBazaar_unknown_084_5df66da2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5df66da2a9a6cf62c34f5521392665744ccdd568e50a2a825b554fee895f7453"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 02:54:44"
  condition:
    hash.sha256(0, filesize) == "5df66da2a9a6cf62c34f5521392665744ccdd568e50a2a825b554fee895f7453"
}

rule MalwareBazaar_unknown_085_6fabd20e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fabd20e37b43a88808632f87e5a0e1b953f6763d786af3411060657a3aed79f"
    family = "unknown"
    file_name = "amtlib.dll"
    file_type = "exe"
    first_seen = "2026-09-30 02:47:47"
  condition:
    hash.sha256(0, filesize) == "6fabd20e37b43a88808632f87e5a0e1b953f6763d786af3411060657a3aed79f"
}

rule MalwareBazaar_VShell_086_9d809607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d809607203d739d334e4cca3650761e4dcb2024089af4273e10d3e05d65c52c"
    family = "VShell"
    file_name = "9d809607203d739d334e4cca3650761e4dcb2024089af4273e10d3e05d65c52c.exe"
    file_type = "exe"
    first_seen = "2026-09-30 02:45:55"
  condition:
    hash.sha256(0, filesize) == "9d809607203d739d334e4cca3650761e4dcb2024089af4273e10d3e05d65c52c"
}

rule MalwareBazaar_VShell_087_4cb75775
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cb75775ee2f88f315353e180dd516551d0dd1fb3e41a6b6a2e93a988ddfc9ca"
    family = "VShell"
    file_name = "4cb75775ee2f88f315353e180dd516551d0dd1fb3e41a6b6a2e93a988ddfc9ca.exe"
    file_type = "exe"
    first_seen = "2026-09-30 02:45:49"
  condition:
    hash.sha256(0, filesize) == "4cb75775ee2f88f315353e180dd516551d0dd1fb3e41a6b6a2e93a988ddfc9ca"
}

rule MalwareBazaar_Panchan_088_0f8fcbb8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f8fcbb8b07a3a3555c2fa2d1deaf2e314ca034e1d591922c647bb6689ddadd7"
    family = "Panchan"
    file_name = "0f8fcbb8b07a3a3555c2fa2d1deaf2e314ca034e1d591922c647bb6689ddadd7"
    file_type = "elf"
    first_seen = "2026-09-30 02:39:40"
  condition:
    hash.sha256(0, filesize) == "0f8fcbb8b07a3a3555c2fa2d1deaf2e314ca034e1d591922c647bb6689ddadd7"
}

rule MalwareBazaar_unknown_089_8de70090
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8de70090fceb1fe920e766e6af7c64d7a15e5172ec1315f83e0f9030dd28c354"
    family = "unknown"
    file_name = "8de70090fceb1fe920e766e6af7c64d7a15e5172ec1315f83e0f9030dd28c354"
    file_type = "elf"
    first_seen = "2026-09-30 02:31:34"
  condition:
    hash.sha256(0, filesize) == "8de70090fceb1fe920e766e6af7c64d7a15e5172ec1315f83e0f9030dd28c354"
}

rule MalwareBazaar_unknown_090_57d380ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57d380ea2a26ea9417f6f29439faa74ca4714f1e387da00966414262e23cb58f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 02:30:15"
  condition:
    hash.sha256(0, filesize) == "57d380ea2a26ea9417f6f29439faa74ca4714f1e387da00966414262e23cb58f"
}

rule MalwareBazaar_unknown_091_0c5f5128
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c5f5128863d2941055e187b3e9346a072230bff005a5bbf924c2664d561e121"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 02:29:53"
  condition:
    hash.sha256(0, filesize) == "0c5f5128863d2941055e187b3e9346a072230bff005a5bbf924c2664d561e121"
}

rule MalwareBazaar_Mirai_092_900ef753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "900ef753fe18d8d86c8ef735983590c65b378d03ffe6f546925a6b1c928e134a"
    family = "Mirai"
    file_name = "900ef753fe18d8d8.bin"
    file_type = "elf"
    first_seen = "2026-09-30 02:25:15"
  condition:
    hash.sha256(0, filesize) == "900ef753fe18d8d86c8ef735983590c65b378d03ffe6f546925a6b1c928e134a"
}

rule MalwareBazaar_Mirai_093_e5f9cf89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5f9cf89459a82e09b351021a182b41463feed3439cf775e76a988970c98b937"
    family = "Mirai"
    file_name = "e5f9cf89459a82e0.bin"
    file_type = "elf"
    first_seen = "2026-09-30 02:25:07"
  condition:
    hash.sha256(0, filesize) == "e5f9cf89459a82e09b351021a182b41463feed3439cf775e76a988970c98b937"
}

rule MalwareBazaar_unknown_094_64462398
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64462398556533215f30bebfe9c62a18baaf0ed882407106d646a4ac053f79b3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 02:21:51"
  condition:
    hash.sha256(0, filesize) == "64462398556533215f30bebfe9c62a18baaf0ed882407106d646a4ac053f79b3"
}

rule MalwareBazaar_unknown_095_25f4118a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25f4118ae989c009c26943b29ad08553509947a72ee2e4374b5f26a2ba0b0399"
    family = "unknown"
    file_name = "25f4118ae989c009c26943b29ad08553509947a72ee2e4374b5f26a2ba0b0399"
    file_type = "sh"
    first_seen = "2026-09-30 02:17:24"
  condition:
    hash.sha256(0, filesize) == "25f4118ae989c009c26943b29ad08553509947a72ee2e4374b5f26a2ba0b0399"
}

rule MalwareBazaar_Mirai_096_fa4f87cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa4f87cf4a160adaf1ae493a24ae003a72bbbf6b20c283dd8da80e17ed8d4f0c"
    family = "Mirai"
    file_name = "fa4f87cf4a160adaf1ae493a24ae003a72bbbf6b20c283dd8da80e17ed8d4f0c"
    file_type = "elf"
    first_seen = "2026-09-30 02:17:13"
  condition:
    hash.sha256(0, filesize) == "fa4f87cf4a160adaf1ae493a24ae003a72bbbf6b20c283dd8da80e17ed8d4f0c"
}

rule MalwareBazaar_unknown_097_2731ec85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2731ec852d3fb2d6da239978f376ffc94c86ac484b4521dfaef944388fd3fcae"
    family = "unknown"
    file_name = "2731ec852d3fb2d6da239978f376ffc94c86ac484b4521dfaef944388fd3fcae.exe"
    file_type = "exe"
    first_seen = "2026-09-30 02:12:26"
  condition:
    hash.sha256(0, filesize) == "2731ec852d3fb2d6da239978f376ffc94c86ac484b4521dfaef944388fd3fcae"
}

rule MalwareBazaar_unknown_098_a8e94547
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8e94547f655de34a6efdc4d77cdf857cef022cf9ad951d0de67cf25473fe58d"
    family = "unknown"
    file_name = "larp-v9.jar"
    file_type = "jar"
    first_seen = "2026-09-30 02:08:51"
  condition:
    hash.sha256(0, filesize) == "a8e94547f655de34a6efdc4d77cdf857cef022cf9ad951d0de67cf25473fe58d"
}

rule MalwareBazaar_GuLoader_099_df703fb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df703fb731180cfc090c985d06a5d5b0ee764b9a970c0ed7a2205ad34af48400"
    family = "GuLoader"
    file_name = "Surveyor docs_compressed.vbs"
    file_type = "vbs"
    first_seen = "2026-09-30 01:58:09"
  condition:
    hash.sha256(0, filesize) == "df703fb731180cfc090c985d06a5d5b0ee764b9a970c0ed7a2205ad34af48400"
}

rule MalwareBazaar_unknown_100_92f9d5ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92f9d5ac6813ca77e92a511f584bbc2017dd8b92cebb60bfc20a83df33f2631e"
    family = "unknown"
    file_name = "stage1_92f9d5ac6813.zsh"
    file_type = "zsh"
    first_seen = "2026-09-30 01:52:58"
  condition:
    hash.sha256(0, filesize) == "92f9d5ac6813ca77e92a511f584bbc2017dd8b92cebb60bfc20a83df33f2631e"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

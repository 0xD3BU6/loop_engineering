# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-28

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 580 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 580 |
| Unique family labels | 20 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 65 |
| Mirai | 11 |
| QuasarRAT | 3 |
| Formbook | 2 |
| Vidar | 2 |
| RemusStealer | 2 |
| Gafgyt | 2 |
| PureLogsStealer | 1 |
| ConnectWise | 1 |
| LummaStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 37 |
| sh | 20 |
| elf | 19 |
| unknown | 14 |
| zip | 5 |
| dll | 2 |
| vbs | 2 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `797e1972be8425f0`

| Field | Value |
|---|---|
| SHA-256 | `797e1972be8425f00cb9d30818e1fb7a7961061e3276513bd1d48262aaceb186` |
| Family label | `unknown` |
| File name | `797e1972be8425f00cb9d30818e1fb7a7961061e3276513bd1d48262aaceb186` |
| File type | `elf` |
| First seen | `2026-08-28 11:20:59` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95b6a9af05da481f7b7d7a7dd6792975` |
| SHA-1 | `67aeeebc5020169551d39fb05e7f2935065351a2` |
| SHA-256 | `797e1972be8425f00cb9d30818e1fb7a7961061e3276513bd1d48262aaceb186` |
| SHA3-384 | `6229c68e029a015eb632847391753abadc8b42bf75733c9c05de671be2ef67d03908cedd2b38cb6dcd6f8e4732ab8f00` |
| TLSH | `T108765B73905664D8E1ADC974D5141213BEA8388B573863CBBBC076F51BBABE49E78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ9:cqYUQuVDt0TZEy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_797e1972
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "797e1972be8425f00cb9d30818e1fb7a7961061e3276513bd1d48262aaceb186"
    family = "unknown"
    file_name = "797e1972be8425f00cb9d30818e1fb7a7961061e3276513bd1d48262aaceb186"
    file_type = "elf"
    first_seen = "2026-08-28 11:20:59"
  condition:
    hash.sha256(0, filesize) == "797e1972be8425f00cb9d30818e1fb7a7961061e3276513bd1d48262aaceb186"
}
```

### Sample 2: `610ff7d4ee1c7f17`

| Field | Value |
|---|---|
| SHA-256 | `610ff7d4ee1c7f17438e7278dcf7397a6eadfbb41bca7b3cc3518b9ee91ae157` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-28 10:57:16` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5de58f5420f79c692b08c039974ec472` |
| SHA-1 | `dc1e16460e56fb213f6a8629b321e708a2bb4e3d` |
| SHA-256 | `610ff7d4ee1c7f17438e7278dcf7397a6eadfbb41bca7b3cc3518b9ee91ae157` |
| SHA3-384 | `4160663e6d684a953aa02a9cd3cc8e3eb33f5958730a884521abadcbdfac1cd5229a444a856693b2a1c596c778d8e349` |
| TLSH | `T15FB56BF9F5FF3365CA238B71A6C3CC0BD666F5284A726063C61113936A611BE6D9031E` |
| SSDEEP | `24576:+g0e6J6Ig6ZYB42msy/elMXo/DWe1og6Y+lhBmBOdtPOQqq6KPkX:jaJvnZYB42ogPh+laO6K` |
| ICON-DHASH | `b4b07268c9d4b402` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_610ff7d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "610ff7d4ee1c7f17438e7278dcf7397a6eadfbb41bca7b3cc3518b9ee91ae157"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 10:57:16"
  condition:
    hash.sha256(0, filesize) == "610ff7d4ee1c7f17438e7278dcf7397a6eadfbb41bca7b3cc3518b9ee91ae157"
}
```

### Sample 3: `04557843879213ba`

| Field | Value |
|---|---|
| SHA-256 | `04557843879213ba547f76a47ab80164aa55c4f03888ea7e03cb9cfe88301ff4` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-28 10:19:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ee8af8802c68987ca373301ee48c0b3` |
| SHA-1 | `c13335440b0fcc37e94dec2a860c843b76e4cc86` |
| SHA-256 | `04557843879213ba547f76a47ab80164aa55c4f03888ea7e03cb9cfe88301ff4` |
| SHA3-384 | `2520c66a3f43af23dcf6e6fc7ffb3b5acba9c53f6b9b6d2828ec61668f83ef13b6b99a89c032ce30fe4239efbd753ea7` |
| TLSH | `T15B236C652A857C14AA98C4371D7E2F0CB9AD43E6320452EDBFCF3CF68C4A69DA11871D` |
| SSDEEP | `768:hXOGVvH9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:dL4cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_04557843
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04557843879213ba547f76a47ab80164aa55c4f03888ea7e03cb9cfe88301ff4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 10:19:11"
  condition:
    hash.sha256(0, filesize) == "04557843879213ba547f76a47ab80164aa55c4f03888ea7e03cb9cfe88301ff4"
}
```

### Sample 4: `41eba5d22fb6ddd1`

| Field | Value |
|---|---|
| SHA-256 | `41eba5d22fb6ddd15fe89de5a085883d84470f1a43ac177c630af3ea3c9f5708` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-08-28 10:05:39` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e46e5cf2e1aceef8584ea39f3029d10` |
| SHA-256 | `41eba5d22fb6ddd15fe89de5a085883d84470f1a43ac177c630af3ea3c9f5708` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_41eba5d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41eba5d22fb6ddd15fe89de5a085883d84470f1a43ac177c630af3ea3c9f5708"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 10:05:39"
  condition:
    hash.sha256(0, filesize) == "41eba5d22fb6ddd15fe89de5a085883d84470f1a43ac177c630af3ea3c9f5708"
}
```

### Sample 5: `97fdbb5506534af8`

| Field | Value |
|---|---|
| SHA-256 | `97fdbb5506534af805db9e23503d93439322650eeaba8132c2627d8a1b9c2dfb` |
| Family label | `unknown` |
| File name | `97fdbb5506534af805db9e23503d93439322650eeaba8132c2627d8a1b9c2dfb.bin` |
| File type | `exe` |
| First seen | `2026-08-28 09:59:49` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c61f3f9e04f32f1d66edbf131ba9a6b` |
| SHA-1 | `8376ef7e11d99d7b14e2b5d2750fc0978dcf4a8a` |
| SHA-256 | `97fdbb5506534af805db9e23503d93439322650eeaba8132c2627d8a1b9c2dfb` |
| SHA3-384 | `369886421f911a7db9e86bdc64f83aafd2273fd4a7401b8631e345d9a89fbb78998f8b1196563f7c32f17041ef1030c8` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T12C06AE437C417DB2E9A6D231C5790151B670BE486B3173E72A41B7782E33BD81E7AB60` |
| SSDEEP | `49152:Kp13GC9U8QP2ZIrDxfHHSSQsc4wCGcP9oA3r9Y40D9xX0HmyB1bKnSgvcU/qfD1e:fP3SUcCiA3r9Hcx85VQ` |
| ICON-DHASH | `9887c4c8c8c88698` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_97fdbb55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97fdbb5506534af805db9e23503d93439322650eeaba8132c2627d8a1b9c2dfb"
    family = "unknown"
    file_name = "97fdbb5506534af805db9e23503d93439322650eeaba8132c2627d8a1b9c2dfb.bin"
    file_type = "exe"
    first_seen = "2026-08-28 09:59:49"
  condition:
    hash.sha256(0, filesize) == "97fdbb5506534af805db9e23503d93439322650eeaba8132c2627d8a1b9c2dfb"
}
```

### Sample 6: `52780b706dc25236`

| Field | Value |
|---|---|
| SHA-256 | `52780b706dc25236437afd0d49818afd31ba47c546331ee9338d82b9957cd919` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-28 09:57:07` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c478043114035bf290c6b6eaf2965cc` |
| SHA-1 | `dfee121260d497193d2c375ed9ea9892eddd9ef4` |
| SHA-256 | `52780b706dc25236437afd0d49818afd31ba47c546331ee9338d82b9957cd919` |
| SHA3-384 | `ca119bd4afa218228d34251db9a48fd52d51fbb4b11a86a54f732a9974e5ddd4aa620f0cd99019d7164eb9f2c33ae081` |
| TLSH | `T19C95DFF5A8FE23A6DB27CFF25AA18437DA667A2B0E7C5093CC6543C3251217E1D1434A` |
| SSDEEP | `49152:E3yXML9g+aSqqIeVlQ2QxArEk3zxvBtT:oy85gSzfE5` |
| ICON-DHASH | `b0708c8646ccf010` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_52780b70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52780b706dc25236437afd0d49818afd31ba47c546331ee9338d82b9957cd919"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 09:57:07"
  condition:
    hash.sha256(0, filesize) == "52780b706dc25236437afd0d49818afd31ba47c546331ee9338d82b9957cd919"
}
```

### Sample 7: `7108ff29916d0642`

| Field | Value |
|---|---|
| SHA-256 | `7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a` |
| Family label | `unknown` |
| File name | `Tax_Notice_23665.zip` |
| File type | `zip` |
| First seen | `2026-08-28 09:42:30` |
| Reporter | `netresec` |
| Tags | `PackClient, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f585ede33ccee3198f199a182504f8e0` |
| SHA-1 | `ed076a6c691f79008b6d2f77c1c0b4c8242f3c90` |
| SHA-256 | `7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a` |
| SHA3-384 | `79d141919dd4ba0c9ad4837f4d5376c27d1bc9bf27e92d7a06dc14f7998b5d846af7e113a5b7ea833c3cc5cf9745526d` |
| TLSH | `T1D43423CC82BB61C657E327B1E4634FC68F60667310BBB7ADC045B445AA21B584DF0AE3` |
| SSDEEP | `6144:uZu4qO4YPS781UQ3cNkHD8tM7R1SQFLXmDmJKm0uMeXUiGxPtfURnUJ:usgPk81l3hHItM9EQlmKU1hmUJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_7108ff29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a"
    family = "unknown"
    file_name = "Tax_Notice_23665.zip"
    file_type = "zip"
    first_seen = "2026-08-28 09:42:30"
  condition:
    hash.sha256(0, filesize) == "7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a"
}
```

### Sample 8: `c9067c5f7a975ad3`

| Field | Value |
|---|---|
| SHA-256 | `c9067c5f7a975ad3861fef91b4e82d3bb754d7dbf7e0bc2b774ad23cc3a295a1` |
| Family label | `unknown` |
| File name | `c9067c5f7a975ad3861fef91b4e82d3bb754d7dbf7e0bc2b774ad23cc3a295a1.exe` |
| File type | `exe` |
| First seen | `2026-08-28 09:41:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `823e29c4e524a72e307f3682e1c18d6c` |
| SHA-1 | `162473d25b878d2914f0def37c2b521c13701b37` |
| SHA-256 | `c9067c5f7a975ad3861fef91b4e82d3bb754d7dbf7e0bc2b774ad23cc3a295a1` |
| SHA3-384 | `d4e3588fbeb83c12277da80f3649ca00dfe479e7d8ad16036e21198749d19c5b149d31102ff6af7d285c57a356ef078f` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T11CD52298FDD62EB1E836C7B757D3A0BDB12A37A486604C6377C863005D226143D763BA` |
| SSDEEP | `49152:RIH5BsagXgIOjdj/SkBheK0eBAcyyFMXh7iD/m/3yeQj/8GkjAAVrQL5:RE5MXIjdj/PjfBAOeYe/33Qj/8GcAyQN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_c9067c5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9067c5f7a975ad3861fef91b4e82d3bb754d7dbf7e0bc2b774ad23cc3a295a1"
    family = "unknown"
    file_name = "c9067c5f7a975ad3861fef91b4e82d3bb754d7dbf7e0bc2b774ad23cc3a295a1.exe"
    file_type = "exe"
    first_seen = "2026-08-28 09:41:11"
  condition:
    hash.sha256(0, filesize) == "c9067c5f7a975ad3861fef91b4e82d3bb754d7dbf7e0bc2b774ad23cc3a295a1"
}
```

### Sample 9: `44b92b32e0316c96`

| Field | Value |
|---|---|
| SHA-256 | `44b92b32e0316c96f5c5a05f25f492083ee7f282080b0f5abc2d1bc9a800dece` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-28 09:40:24` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca3fcd6167a2b81c781670158a9f9437` |
| SHA-1 | `bf337ea49b4df43362b8124c80c44bba027259f3` |
| SHA-256 | `44b92b32e0316c96f5c5a05f25f492083ee7f282080b0f5abc2d1bc9a800dece` |
| SHA3-384 | `0b31413eb7a020742935f5569e6bea266e046b6581aaf72d049cf51bc2cb12e34dff3c9ac42aba9ccb98acb46419930b` |
| TLSH | `T1ED236C6516857C14AE99C4375C7E2F0CB9AD43E6314492EE7FCE3CF28C4A6ADA20861D` |
| SSDEEP | `768:Jr9NyXsZztCn9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:BHusZBcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_44b92b32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44b92b32e0316c96f5c5a05f25f492083ee7f282080b0f5abc2d1bc9a800dece"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 09:40:24"
  condition:
    hash.sha256(0, filesize) == "44b92b32e0316c96f5c5a05f25f492083ee7f282080b0f5abc2d1bc9a800dece"
}
```

### Sample 10: `be396a33faffcee8`

| Field | Value |
|---|---|
| SHA-256 | `be396a33faffcee871ad014ce0ecd317e8e878fefecd172c8d2bff211b3d8a22` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-28 09:38:44` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26b1aa9b466ab9c06c6a6cf5ac153d27` |
| SHA-1 | `6153bb8ebb22fd88c01e4a1fc46f530e6d24e9e7` |
| SHA-256 | `be396a33faffcee871ad014ce0ecd317e8e878fefecd172c8d2bff211b3d8a22` |
| SHA3-384 | `d2af3b4e1ee4b3cff7ae2d917b0845b4887bc742928d16c75d087d18cf1f8c57bd5fb38bb6ae0ebceebae0090b8542af` |
| TLSH | `T145959CE684B82364EE52B736BB85811BD62E3D2826735433C521278777331B9DED43E2` |
| SSDEEP | `24576:fOrlRO+cjZZ3GZCfYwUQIiXyaxNPAUZXl3TnORuJMsl9Y8Nq/5tfrgUZNw7ieexn:fOrfOxZyY4Yo2XlDo58nU7we` |
| ICON-DHASH | `727272620e727272` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_be396a33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be396a33faffcee871ad014ce0ecd317e8e878fefecd172c8d2bff211b3d8a22"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 09:38:44"
  condition:
    hash.sha256(0, filesize) == "be396a33faffcee871ad014ce0ecd317e8e878fefecd172c8d2bff211b3d8a22"
}
```

### Sample 11: `80cf59d0d509471a`

| Field | Value |
|---|---|
| SHA-256 | `80cf59d0d509471a0f837c4e5b8b52a53c1da93c6b1c8f24c205e45680f71e0d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-28 09:38:24` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27c4465c88428e16e85865c5e24df987` |
| SHA-256 | `80cf59d0d509471a0f837c4e5b8b52a53c1da93c6b1c8f24c205e45680f71e0d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_80cf59d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80cf59d0d509471a0f837c4e5b8b52a53c1da93c6b1c8f24c205e45680f71e0d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-28 09:38:24"
  condition:
    hash.sha256(0, filesize) == "80cf59d0d509471a0f837c4e5b8b52a53c1da93c6b1c8f24c205e45680f71e0d"
}
```

### Sample 12: `d247d169b650e0b2`

| Field | Value |
|---|---|
| SHA-256 | `d247d169b650e0b2c538e456d456e4d95f2aa81eb50a459cce71168fa4a59cd2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-28 09:28:24` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a85e9cf2add0a38f32aeb493cd46cd68` |
| SHA-1 | `952bd224bcfb4b60c10f15bfdc8bfacd0de3867a` |
| SHA-256 | `d247d169b650e0b2c538e456d456e4d95f2aa81eb50a459cce71168fa4a59cd2` |
| SHA3-384 | `2c0621e19e675a96c692bccf5baaef1faf8b61e422794ae52828dfd9e7fd7b741a2cdbea901cad6e83868aaa99ec1e97` |
| IMPHASH | `7072da7da46c78c19a7df03306d50254` |
| TLSH | `T1F6646C15E39810FDEA77C67CCD824906DA727C564771EACF03904A962F236E49E3EB21` |
| SSDEEP | `6144:gcL0vw/GzSsZFzylmi5I2/ox15QMvkj0O3DSjATVTMBREn2:DOglmiy2mkj5DzTVTA42` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_d247d169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d247d169b650e0b2c538e456d456e4d95f2aa81eb50a459cce71168fa4a59cd2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 09:28:24"
  condition:
    hash.sha256(0, filesize) == "d247d169b650e0b2c538e456d456e4d95f2aa81eb50a459cce71168fa4a59cd2"
}
```

### Sample 13: `8c570d090576cf05`

| Field | Value |
|---|---|
| SHA-256 | `8c570d090576cf05a6813c28574b2cf210de8054f7fa4cacd67428718348d143` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-28 09:26:53` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5269188c48af7c2274ab528c8f9ff22d` |
| SHA-1 | `f634cd013c1773dc8c151c8f1a5fe8bb185335bf` |
| SHA-256 | `8c570d090576cf05a6813c28574b2cf210de8054f7fa4cacd67428718348d143` |
| SHA3-384 | `3b6e13171d702ea9e270467178ea1873bcdc8408500f94558b2e132122dc067fccf88ac1bd2b3474575cea660bbcdd96` |
| TLSH | `T1AC31899B145206752202C98E73723588A18EA5F72C9FDBD0D85D0EA992983CCF632F5E` |
| SSDEEP | `24:qHXjrgMj4puBu56B9VQeh6eRm7df+5kYfUHI/:g/D4pw86lv87dfU/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_8c570d09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c570d090576cf05a6813c28574b2cf210de8054f7fa4cacd67428718348d143"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-28 09:26:53"
  condition:
    hash.sha256(0, filesize) == "8c570d090576cf05a6813c28574b2cf210de8054f7fa4cacd67428718348d143"
}
```

### Sample 14: `dd3e7e4fa68a68a3`

| Field | Value |
|---|---|
| SHA-256 | `dd3e7e4fa68a68a3b5cc810ffbac6d75a4759434d3dabe3c154eaae87d579c2e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-28 09:13:28` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f8c5c871cee50a1a73ec525eead249f` |
| SHA-1 | `951779f9bc09f0e8e3ea579a71ddba576fe1f898` |
| SHA-256 | `dd3e7e4fa68a68a3b5cc810ffbac6d75a4759434d3dabe3c154eaae87d579c2e` |
| SHA3-384 | `cf8bc98dd364aada7eb11afe1a06078114740dc9ac4bb21709d4cf5ef3fe7466952f5d88be7181831d58ea6bee384bc0` |
| TLSH | `T115C27C966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:fw8vCB+25j6es8R79FYpMSUpi+20qUpi+20YQX:48l25JNd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_dd3e7e4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd3e7e4fa68a68a3b5cc810ffbac6d75a4759434d3dabe3c154eaae87d579c2e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 09:13:28"
  condition:
    hash.sha256(0, filesize) == "dd3e7e4fa68a68a3b5cc810ffbac6d75a4759434d3dabe3c154eaae87d579c2e"
}
```

### Sample 15: `63d404aa43bfb74d`

| Field | Value |
|---|---|
| SHA-256 | `63d404aa43bfb74d8619dc7ceb950bd73e8525672c91077d40227c8bdf9ec387` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-28 09:10:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `706ec467a208f53f0f38639ec671dcc9` |
| SHA-1 | `9655c42ec866cfa14801545146414e39a5445c4d` |
| SHA-256 | `63d404aa43bfb74d8619dc7ceb950bd73e8525672c91077d40227c8bdf9ec387` |
| SHA3-384 | `a146a7e41455def55e3e8d148262dc45dcce2bbcb5d468bf8bb415386fc2c8bbf754fbfd591301172c484757abb67285` |
| TLSH | `T10FC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:p8vCB+25j6es8Rk9FYpMSUpi+20qUpi+20YQX:p8l25JCd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_63d404aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63d404aa43bfb74d8619dc7ceb950bd73e8525672c91077d40227c8bdf9ec387"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 09:10:31"
  condition:
    hash.sha256(0, filesize) == "63d404aa43bfb74d8619dc7ceb950bd73e8525672c91077d40227c8bdf9ec387"
}
```

### Sample 16: `e067e909729799eb`

| Field | Value |
|---|---|
| SHA-256 | `e067e909729799eb1074486fc299260c2233c499a4d612713ace2231162effac` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-08-28 09:08:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e326658f1eff05fed9f758728c327574` |
| SHA-1 | `c7c56101e797edf59b187ea10e31a48b716ddd86` |
| SHA-256 | `e067e909729799eb1074486fc299260c2233c499a4d612713ace2231162effac` |
| SHA3-384 | `a8988ed9798ea2a7511f5e4e796de49ada370d024855d3b5b4900360ab849429b51834fddeae6d03c1516c1495b37088` |
| TLSH | `T159E0C0E5672104333C4D8CBF726598C436891DDF6CC7E931A4877BA7019DD44B405363` |
| SSDEEP | `6:DHyvlOnFflH+3FicEZJnsAMvXyck68Pye2uJyec+Eb5a4KjhI6X:DHyScoJbcvej0e5qY4eqy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_e067e909
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e067e909729799eb1074486fc299260c2233c499a4d612713ace2231162effac"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-08-28 09:08:35"
  condition:
    hash.sha256(0, filesize) == "e067e909729799eb1074486fc299260c2233c499a4d612713ace2231162effac"
}
```

### Sample 17: `d2a720a5ee2b07ac`

| Field | Value |
|---|---|
| SHA-256 | `d2a720a5ee2b07ac1968c978e2a3e433949560efe01cc4449b3b394e610ba1fe` |
| Family label | `unknown` |
| File name | `main.lua` |
| File type | `unknown` |
| First seen | `2026-08-28 09:06:14` |
| Reporter | `bytecategory` |
| Tags | `lua` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9260ebcdf643fd9a2490eada183bc5ca` |
| SHA-256 | `d2a720a5ee2b07ac1968c978e2a3e433949560efe01cc4449b3b394e610ba1fe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_d2a720a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2a720a5ee2b07ac1968c978e2a3e433949560efe01cc4449b3b394e610ba1fe"
    family = "unknown"
    file_name = "main.lua"
    file_type = "unknown"
    first_seen = "2026-08-28 09:06:14"
  condition:
    hash.sha256(0, filesize) == "d2a720a5ee2b07ac1968c978e2a3e433949560efe01cc4449b3b394e610ba1fe"
}
```

### Sample 18: `6fa463dc05e3986c`

| Field | Value |
|---|---|
| SHA-256 | `6fa463dc05e3986c0046442d73e726d7d106805e7a734c1fa9e9592f9e646e8e` |
| Family label | `Mirai` |
| File name | `dlr.m68k` |
| File type | `elf` |
| First seen | `2026-08-28 08:57:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55c1b42b5e3bb6ca4c23441a9a03c90c` |
| SHA-1 | `596d897ac5926f8ce7079a53e668ec9f219861a4` |
| SHA-256 | `6fa463dc05e3986c0046442d73e726d7d106805e7a734c1fa9e9592f9e646e8e` |
| SHA3-384 | `cc4d4069da68319afc82d32cc53ae9fe8543bb4b52d354053b77df3f93a7140bb3d2d85207c7875f9dd928c6a1326a60` |
| TLSH | `T12C11DC4742516C2CEDA392758A57272478207D0AC8034609F32BED137E373CDAF51D89` |
| SSDEEP | `24:3WNiyAgfUz0QyMV2pO7AAIP3oxtt1pUyNTmPrl:CingjU2EkfP3sUyNSTl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_6fa463dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fa463dc05e3986c0046442d73e726d7d106805e7a734c1fa9e9592f9e646e8e"
    family = "Mirai"
    file_name = "dlr.m68k"
    file_type = "elf"
    first_seen = "2026-08-28 08:57:29"
  condition:
    hash.sha256(0, filesize) == "6fa463dc05e3986c0046442d73e726d7d106805e7a734c1fa9e9592f9e646e8e"
}
```

### Sample 19: `94a33fc48ecb5040`

| Field | Value |
|---|---|
| SHA-256 | `94a33fc48ecb504091be4ab6c64cb3b828ac0efe1c9449c8ee952774de38b44f` |
| Family label | `Formbook` |
| File name | `Solenis RFQ-BID--870994965701.exe` |
| File type | `exe` |
| First seen | `2026-08-28 08:57:12` |
| Reporter | `lowmal3` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c44e30aa705a5d352079d63eaa1f3dce` |
| SHA-1 | `dd10660387c33c8be281991f55a03f0f1a683b62` |
| SHA-256 | `94a33fc48ecb504091be4ab6c64cb3b828ac0efe1c9449c8ee952774de38b44f` |
| SHA3-384 | `c649beec0d1c8f83f89293590356eeb1e499d71db0dbfbc246320129c6ac35e581ecd0cd74a0fe38e3727d2cc1fd84fe` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A41512A1B749EA66D9BD13F50972E23647B56E5DD122E317CDED9DF73820B00AC08B02` |
| SSDEEP | `12288:S/Zo+0Hj9KtY50NJqWJ6V4HGJgtyxpH1dAxqRv667e/MY+B0c8S2tQBtJwrfZuwF:6o+feS0KGJgmpPnGFswSoQ7JzwfzoVO` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_019_94a33fc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94a33fc48ecb504091be4ab6c64cb3b828ac0efe1c9449c8ee952774de38b44f"
    family = "Formbook"
    file_name = "Solenis RFQ-BID--870994965701.exe"
    file_type = "exe"
    first_seen = "2026-08-28 08:57:12"
  condition:
    hash.sha256(0, filesize) == "94a33fc48ecb504091be4ab6c64cb3b828ac0efe1c9449c8ee952774de38b44f"
}
```

### Sample 20: `a2fc3ab543e72dec`

| Field | Value |
|---|---|
| SHA-256 | `a2fc3ab543e72decbea89ff3479cc9d813324bccccb291cba2536d95b0bdc64c` |
| Family label | `Formbook` |
| File name | `Purchasing Order Required Specification RQTC1FWfMShV.exe` |
| File type | `exe` |
| First seen | `2026-08-28 08:56:45` |
| Reporter | `lowmal3` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bedeeefa188f9fea4f050848adcb3f0a` |
| SHA-1 | `be6714ad8e992e7ef38c3d5c61edfb73259bb64b` |
| SHA-256 | `a2fc3ab543e72decbea89ff3479cc9d813324bccccb291cba2536d95b0bdc64c` |
| SHA3-384 | `c8885dc4b8db7cacbca2f0f608fc49c722a4704daf306cf5f867a89c3ce44a10f757403ebd304b5bfe0af5df38fe767b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A82512666358FB26D8BE17B91632E23617F52D0EA921E328DEED7DEB7C117006C10243` |
| SSDEEP | `24576:tmDo+iWIbymwZj4yaCc1oMyBFYwQjZO2vfUZ:tmDhINwlsCkoMA7avM` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_020_a2fc3ab5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2fc3ab543e72decbea89ff3479cc9d813324bccccb291cba2536d95b0bdc64c"
    family = "Formbook"
    file_name = "Purchasing Order Required Specification RQTC1FWfMShV.exe"
    file_type = "exe"
    first_seen = "2026-08-28 08:56:45"
  condition:
    hash.sha256(0, filesize) == "a2fc3ab543e72decbea89ff3479cc9d813324bccccb291cba2536d95b0bdc64c"
}
```

### Sample 21: `6f61cd63d740045a`

| Field | Value |
|---|---|
| SHA-256 | `6f61cd63d740045a86265e5a0320871f3a6271d6ca7ba65e4291f47ccb55c834` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-28 08:54:29` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8febfec17563f61da43e3c822bd4e50b` |
| SHA-256 | `6f61cd63d740045a86265e5a0320871f3a6271d6ca7ba65e4291f47ccb55c834` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_6f61cd63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f61cd63d740045a86265e5a0320871f3a6271d6ca7ba65e4291f47ccb55c834"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 08:54:29"
  condition:
    hash.sha256(0, filesize) == "6f61cd63d740045a86265e5a0320871f3a6271d6ca7ba65e4291f47ccb55c834"
}
```

### Sample 22: `f8666460abf01362`

| Field | Value |
|---|---|
| SHA-256 | `f8666460abf01362c5a9e24ecd86193425338e25c4cd9b2bb66caf726acacfc3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-28 08:53:38` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea128a0b600bd84d7132d74751e5dea7` |
| SHA-1 | `6f4496923a4944fff8519937f138cc3afcff1f8f` |
| SHA-256 | `f8666460abf01362c5a9e24ecd86193425338e25c4cd9b2bb66caf726acacfc3` |
| SHA3-384 | `33409665147e244e063963634fb92b64fd5c5dfef098180cac45bcc43d55736c95939950c62270723540d37d00fd28e5` |
| IMPHASH | `03cc13f2892a8bb4db3404549c3b67ea` |
| TLSH | `T1D745C01AA2A290F9F1D780754297B27FA4F3F81D1F205A6E1778DF352E62D700A3D624` |
| SSDEEP | `12288:b+eu1azTzCIUrp9MRx0a+wwsKxoAX0e8GNwxLJxGUwLLA4:bRzTmIUknSwwhfX0edMc3A4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_f8666460
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8666460abf01362c5a9e24ecd86193425338e25c4cd9b2bb66caf726acacfc3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 08:53:38"
  condition:
    hash.sha256(0, filesize) == "f8666460abf01362c5a9e24ecd86193425338e25c4cd9b2bb66caf726acacfc3"
}
```

### Sample 23: `b21e7c4fbe16a23c`

| Field | Value |
|---|---|
| SHA-256 | `b21e7c4fbe16a23c3421d84e2e8a173969aafe2701bbe3e8bba23b04a0ed3246` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-28 08:52:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5faa1cf910a976a842733e03104ea994` |
| SHA-1 | `fd11ad943045f6bcd14672b4431004c6ea07e404` |
| SHA-256 | `b21e7c4fbe16a23c3421d84e2e8a173969aafe2701bbe3e8bba23b04a0ed3246` |
| SHA3-384 | `4d30c15ab50aeedce239f55ef61f03dc12ec0b14027aaaaef2a2f31d25ea52b1ba5f222c08963348a6bb831ac197d03d` |
| TLSH | `T119C27D95AA867C44BDC94A3E4CBE2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:L8vCB+25j6es8RA9FYpMSUpi+20qUpi+20YQX:L8l25JGd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_b21e7c4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b21e7c4fbe16a23c3421d84e2e8a173969aafe2701bbe3e8bba23b04a0ed3246"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 08:52:34"
  condition:
    hash.sha256(0, filesize) == "b21e7c4fbe16a23c3421d84e2e8a173969aafe2701bbe3e8bba23b04a0ed3246"
}
```

### Sample 24: `995e43d70fad10c1`

| Field | Value |
|---|---|
| SHA-256 | `995e43d70fad10c13d296fc34de743fae2edfac447a244d99ced9d5f0e8c02eb` |
| Family label | `Mirai` |
| File name | `dlr.spc` |
| File type | `elf` |
| First seen | `2026-08-28 08:47:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1c3be11928dbe5424bb3da16d486b39` |
| SHA-1 | `7d8e7f6b7498d50b2bff8fd8aa4dcf3271bdfc89` |
| SHA-256 | `995e43d70fad10c13d296fc34de743fae2edfac447a244d99ced9d5f0e8c02eb` |
| SHA3-384 | `38a00595180fe5ef45cde3e4fdc91587bd8b2c006ede5a5b8547d2d9bf215b7508b6fc7953cecad5de44c40b9207cd89` |
| TLSH | `T13F21DC1A832B3493ED64353F46B35B3237B0A43D0125CB685F44BB2A9E1E3855F021F0` |
| SSDEEP | `12:BBSrsXkmTn8/i09q3/4NkWMjlcY5dnHHj3E3mJ9lbgHuV2BOilKG3FSaQ:3ShmAUANqcY5d42J9l8OVNTG3oaQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_995e43d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "995e43d70fad10c13d296fc34de743fae2edfac447a244d99ced9d5f0e8c02eb"
    family = "Mirai"
    file_name = "dlr.spc"
    file_type = "elf"
    first_seen = "2026-08-28 08:47:38"
  condition:
    hash.sha256(0, filesize) == "995e43d70fad10c13d296fc34de743fae2edfac447a244d99ced9d5f0e8c02eb"
}
```

### Sample 25: `df8e6699a99b0d06`

| Field | Value |
|---|---|
| SHA-256 | `df8e6699a99b0d061fe86419dc067a6ee02b10a3e18364a22aa8048630764520` |
| Family label | `unknown` |
| File name | `df8e6699a99b0d061fe86419dc067a6ee02b10a3e18364a22aa8048630764520.raw` |
| File type | `zip` |
| First seen | `2026-08-28 08:43:54` |
| Reporter | `ApiValex73693` |
| Tags | `cowrie, dionaea, honeypot, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8331625f886d1f8387275be3829aef4f` |
| SHA-256 | `df8e6699a99b0d061fe86419dc067a6ee02b10a3e18364a22aa8048630764520` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_df8e6699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df8e6699a99b0d061fe86419dc067a6ee02b10a3e18364a22aa8048630764520"
    family = "unknown"
    file_name = "df8e6699a99b0d061fe86419dc067a6ee02b10a3e18364a22aa8048630764520.raw"
    file_type = "zip"
    first_seen = "2026-08-28 08:43:54"
  condition:
    hash.sha256(0, filesize) == "df8e6699a99b0d061fe86419dc067a6ee02b10a3e18364a22aa8048630764520"
}
```

### Sample 26: `920d5a4380e783f4`

| Field | Value |
|---|---|
| SHA-256 | `920d5a4380e783f4fd7752766919c3ae67c21b687384e154610528aa7f5793a7` |
| Family label | `unknown` |
| File name | `17529dfc1fe186b5d40ec69df217dfe1` |
| File type | `dll` |
| First seen | `2026-08-28 08:43:50` |
| Reporter | `ApiValex73693` |
| Tags | `cowrie, dionaea, dll, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17529dfc1fe186b5d40ec69df217dfe1` |
| SHA-1 | `05a0fd5e8bf1e96ed63b99079f0673248c0ace5e` |
| SHA-256 | `920d5a4380e783f4fd7752766919c3ae67c21b687384e154610528aa7f5793a7` |
| SHA3-384 | `693a2e3d528624d5256b72f71f929ab9498862e2e051fe929f45a4fe7e5c503ee2f45145be143763f16f80e20fe30a60` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T19F362215766C91BCC12A2234A4B38936E6B77C6A12BD971F8B94CB520D13750FE78F0B` |
| SSDEEP | `12288:yvbLgPlu+QhMbaIMu7L5NVErCA4z2g6rTcbckPU82900Ve7zw+K+D18:SbLgddQhfdmMSirYbcMNgef01` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_920d5a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "920d5a4380e783f4fd7752766919c3ae67c21b687384e154610528aa7f5793a7"
    family = "unknown"
    file_name = "17529dfc1fe186b5d40ec69df217dfe1"
    file_type = "dll"
    first_seen = "2026-08-28 08:43:50"
  condition:
    hash.sha256(0, filesize) == "920d5a4380e783f4fd7752766919c3ae67c21b687384e154610528aa7f5793a7"
}
```

### Sample 27: `f7ce75170b15e0d2`

| Field | Value |
|---|---|
| SHA-256 | `f7ce75170b15e0d2aa37e3e9b65d949562fa90dd582c2753c23b414e80b8ea79` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-28 08:38:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6a073dae42ce8f8efc0b7496fc5200f` |
| SHA-1 | `64fc565d3bb1659c8fe8727ef40ce2c6faf74c8d` |
| SHA-256 | `f7ce75170b15e0d2aa37e3e9b65d949562fa90dd582c2753c23b414e80b8ea79` |
| SHA3-384 | `040500d529e66be05c8a82cc5e16c67cc99c2bdcbcc596426ff4c4336c13eecb41cd3dc9ef5a3af9a211f0b2fdd0318e` |
| TLSH | `T180C27D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11F9CD618B1A` |
| SSDEEP | `768:h8vCB+25j6es8RC9FYpMSUpi+20qUpi+20YQX:h8l25Jkd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_f7ce7517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7ce75170b15e0d2aa37e3e9b65d949562fa90dd582c2753c23b414e80b8ea79"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 08:38:31"
  condition:
    hash.sha256(0, filesize) == "f7ce75170b15e0d2aa37e3e9b65d949562fa90dd582c2753c23b414e80b8ea79"
}
```

### Sample 28: `969e189d841ff5aa`

| Field | Value |
|---|---|
| SHA-256 | `969e189d841ff5aa13e1ff3bd728b8c487f10f5ec9d9cc4959c21db4d369fc10` |
| Family label | `Mirai` |
| File name | `dlr.mips` |
| File type | `elf` |
| First seen | `2026-08-28 08:32:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53a8b8d5b2e5f3b6e870b0b0d9b7be5b` |
| SHA-1 | `4b42ac6089bf48240d72b2dffb55ec1e7f527056` |
| SHA-256 | `969e189d841ff5aa13e1ff3bd728b8c487f10f5ec9d9cc4959c21db4d369fc10` |
| SHA3-384 | `538458737d4d09514491601c624c41e568bb8a7d4dff49c5c801865968decd1112221a1cde2d2ab0447fe82c54d7cab2` |
| TLSH | `T1CF31238A67A0EAFDF1E8C138C713C71376D8E69407A04B85F17DE5015C5034E29EABC9` |
| SSDEEP | `24:33GhVzrQAtlxIzp3HfLVAOCAKgsHzcwG1TAffbr12MzLsCH/0Mnkc:HGXzrvKICKfHzGgF2Mzpf0Mnkc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_969e189d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "969e189d841ff5aa13e1ff3bd728b8c487f10f5ec9d9cc4959c21db4d369fc10"
    family = "Mirai"
    file_name = "dlr.mips"
    file_type = "elf"
    first_seen = "2026-08-28 08:32:40"
  condition:
    hash.sha256(0, filesize) == "969e189d841ff5aa13e1ff3bd728b8c487f10f5ec9d9cc4959c21db4d369fc10"
}
```

### Sample 29: `72665efcae90205b`

| Field | Value |
|---|---|
| SHA-256 | `72665efcae90205b756d4d7e1102e6c7d77b143a9c0ed0f73f926c0a86ccf878` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-28 08:25:33` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a8737c70575c805bc23341ee8d235be` |
| SHA-256 | `72665efcae90205b756d4d7e1102e6c7d77b143a9c0ed0f73f926c0a86ccf878` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_72665efc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72665efcae90205b756d4d7e1102e6c7d77b143a9c0ed0f73f926c0a86ccf878"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 08:25:33"
  condition:
    hash.sha256(0, filesize) == "72665efcae90205b756d4d7e1102e6c7d77b143a9c0ed0f73f926c0a86ccf878"
}
```

### Sample 30: `b76bd392d4d4da57`

| Field | Value |
|---|---|
| SHA-256 | `b76bd392d4d4da577f417631e3bc734b68361c1da07db27dc117356b1ec4f241` |
| Family label | `unknown` |
| File name | `physics_server_v2.sys` |
| File type | `unknown` |
| First seen | `2026-08-28 08:20:07` |
| Reporter | `asks` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `633b36811436ff5c5fabcca513ac160c` |
| SHA-256 | `b76bd392d4d4da577f417631e3bc734b68361c1da07db27dc117356b1ec4f241` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_b76bd392
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b76bd392d4d4da577f417631e3bc734b68361c1da07db27dc117356b1ec4f241"
    family = "unknown"
    file_name = "physics_server_v2.sys"
    file_type = "unknown"
    first_seen = "2026-08-28 08:20:07"
  condition:
    hash.sha256(0, filesize) == "b76bd392d4d4da577f417631e3bc734b68361c1da07db27dc117356b1ec4f241"
}
```

### Sample 31: `0f4e99a8f70adcb1`

| Field | Value |
|---|---|
| SHA-256 | `0f4e99a8f70adcb130fb965f740940c826aeafcaea80106df7d80aede8eb0d20` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-28 08:19:30` |
| Reporter | `asks` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3773ce51e91e38f7587908f9114f5d4c` |
| SHA-256 | `0f4e99a8f70adcb130fb965f740940c826aeafcaea80106df7d80aede8eb0d20` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_0f4e99a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f4e99a8f70adcb130fb965f740940c826aeafcaea80106df7d80aede8eb0d20"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-28 08:19:30"
  condition:
    hash.sha256(0, filesize) == "0f4e99a8f70adcb130fb965f740940c826aeafcaea80106df7d80aede8eb0d20"
}
```

### Sample 32: `a5e07742617f67d5`

| Field | Value |
|---|---|
| SHA-256 | `a5e07742617f67d52a065960000a01b6dccd0b4248a58f027926019de2287345` |
| Family label | `unknown` |
| File name | `thread2.yaml` |
| File type | `unknown` |
| First seen | `2026-08-28 08:16:00` |
| Reporter | `asks` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfab406f3ddd73cf50da23077d4b2e15` |
| SHA-256 | `a5e07742617f67d52a065960000a01b6dccd0b4248a58f027926019de2287345` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_a5e07742
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5e07742617f67d52a065960000a01b6dccd0b4248a58f027926019de2287345"
    family = "unknown"
    file_name = "thread2.yaml"
    file_type = "unknown"
    first_seen = "2026-08-28 08:16:00"
  condition:
    hash.sha256(0, filesize) == "a5e07742617f67d52a065960000a01b6dccd0b4248a58f027926019de2287345"
}
```

### Sample 33: `0aca67308f168b7f`

| Field | Value |
|---|---|
| SHA-256 | `0aca67308f168b7fd0b48ca2257fafbad30129b45a398ae39fdd2fef631f358f` |
| Family label | `unknown` |
| File name | `Zооm.vbs` |
| File type | `vbs` |
| First seen | `2026-08-28 08:15:49` |
| Reporter | `cocaman` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2203b30b5bbe43987e64af68ebc44d1d` |
| SHA-1 | `7ec32812a5eb2fe50ee9a7116eec3ea36657a89d` |
| SHA-256 | `0aca67308f168b7fd0b48ca2257fafbad30129b45a398ae39fdd2fef631f358f` |
| SHA3-384 | `9460fc0b41ebab5d995203dc588aafe76dbc23b5ae5b84134a07edd5c2233cf2aefc6e3cc8bb59762b706f4ee72ce2c9` |
| TLSH | `T16CB2E9F86E4DEA99BBE6CB47CF8EFF6525501CA24973D09CACB4894D045365D88C7420` |
| SSDEEP | `384:+UPhMF5rLSz1v5wYdYVfSmLdnWsnyJCmlTVJOn1sGXftM44bkGJahtFYuVh1:PCDPUmYdYNJYsyLTYD1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_0aca6730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0aca67308f168b7fd0b48ca2257fafbad30129b45a398ae39fdd2fef631f358f"
    family = "unknown"
    file_name = "Zооm.vbs"
    file_type = "vbs"
    first_seen = "2026-08-28 08:15:49"
  condition:
    hash.sha256(0, filesize) == "0aca67308f168b7fd0b48ca2257fafbad30129b45a398ae39fdd2fef631f358f"
}
```

### Sample 34: `2943e8c43da4ac3b`

| Field | Value |
|---|---|
| SHA-256 | `2943e8c43da4ac3b1f1970efd35ddeb5c6a120dd6241ecf2243f2938450663a3` |
| Family label | `unknown` |
| File name | `physics_server.sys` |
| File type | `unknown` |
| First seen | `2026-08-28 08:15:27` |
| Reporter | `asks` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86d2146f9369f09d586504eeb73e36af` |
| SHA-256 | `2943e8c43da4ac3b1f1970efd35ddeb5c6a120dd6241ecf2243f2938450663a3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_2943e8c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2943e8c43da4ac3b1f1970efd35ddeb5c6a120dd6241ecf2243f2938450663a3"
    family = "unknown"
    file_name = "physics_server.sys"
    file_type = "unknown"
    first_seen = "2026-08-28 08:15:27"
  condition:
    hash.sha256(0, filesize) == "2943e8c43da4ac3b1f1970efd35ddeb5c6a120dd6241ecf2243f2938450663a3"
}
```

### Sample 35: `aa4e0509b93a8ae6`

| Field | Value |
|---|---|
| SHA-256 | `aa4e0509b93a8ae6f4203aebb57e51e4a886bfc92f5650d3941aa97f0924bb54` |
| Family label | `unknown` |
| File name | `PPUtilLib.dll` |
| File type | `dll` |
| First seen | `2026-08-28 08:15:09` |
| Reporter | `asks` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6832bd8caba758d758109ef5b31db78` |
| SHA-256 | `aa4e0509b93a8ae6f4203aebb57e51e4a886bfc92f5650d3941aa97f0924bb54` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_aa4e0509
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa4e0509b93a8ae6f4203aebb57e51e4a886bfc92f5650d3941aa97f0924bb54"
    family = "unknown"
    file_name = "PPUtilLib.dll"
    file_type = "dll"
    first_seen = "2026-08-28 08:15:09"
  condition:
    hash.sha256(0, filesize) == "aa4e0509b93a8ae6f4203aebb57e51e4a886bfc92f5650d3941aa97f0924bb54"
}
```

### Sample 36: `03beb4af9fedfd21`

| Field | Value |
|---|---|
| SHA-256 | `03beb4af9fedfd21f18e9d204d28675ba6b1649afa3201fce16e3bdfab8a2b6f` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-28 08:09:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95dcc2377613d69b63a9cd061aec2b49` |
| SHA-1 | `464a7e896da4641b5c8486b4895603f41687f064` |
| SHA-256 | `03beb4af9fedfd21f18e9d204d28675ba6b1649afa3201fce16e3bdfab8a2b6f` |
| SHA3-384 | `8a7d82a10c3584ebf955e51e6f18bd28022bda536ab7e26265e624e135e28ac098012e558d2ff14d0c3360c7bcb16831` |
| TLSH | `T1B031A1DF01541B321102CE8DB3A37088B68EA5EB2C5FC7E08D494EEE42587DCF2A1B49` |
| SSDEEP | `24:+OgqE0sIRvK3r+wZAQGMTwOGODTuBEsC6ZeDZqI3:+Og6s2vW9Z4MTwOGONMeDZqO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_03beb4af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03beb4af9fedfd21f18e9d204d28675ba6b1649afa3201fce16e3bdfab8a2b6f"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-28 08:09:59"
  condition:
    hash.sha256(0, filesize) == "03beb4af9fedfd21f18e9d204d28675ba6b1649afa3201fce16e3bdfab8a2b6f"
}
```

### Sample 37: `7134cbfe70583aeb`

| Field | Value |
|---|---|
| SHA-256 | `7134cbfe70583aeb8673bc8c6f0e6b4966c0117c5c9820fc2d32535bb2f4e649` |
| Family label | `unknown` |
| File name | `lterouter` |
| File type | `unknown` |
| First seen | `2026-08-28 07:55:31` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ce804e1d1eea25e4998b1e11e9335f1` |
| SHA-256 | `7134cbfe70583aeb8673bc8c6f0e6b4966c0117c5c9820fc2d32535bb2f4e649` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_7134cbfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7134cbfe70583aeb8673bc8c6f0e6b4966c0117c5c9820fc2d32535bb2f4e649"
    family = "unknown"
    file_name = "lterouter"
    file_type = "unknown"
    first_seen = "2026-08-28 07:55:31"
  condition:
    hash.sha256(0, filesize) == "7134cbfe70583aeb8673bc8c6f0e6b4966c0117c5c9820fc2d32535bb2f4e649"
}
```

### Sample 38: `1876ef7a0995a738`

| Field | Value |
|---|---|
| SHA-256 | `1876ef7a0995a7383f5660bcd0b53de56bb9c21f04395f35a86e8195b99bf180` |
| Family label | `PureLogsStealer` |
| File name | `New Order-PO230824312.vbs` |
| File type | `vbs` |
| First seen | `2026-08-28 07:54:58` |
| Reporter | `abuse_ch` |
| Tags | `PureLogsStealer, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8494f1aac25120b614d16d35e146764` |
| SHA-1 | `aba63cdedc9d731f7c7b761cc1cb4d1b033baf65` |
| SHA-256 | `1876ef7a0995a7383f5660bcd0b53de56bb9c21f04395f35a86e8195b99bf180` |
| SHA3-384 | `d263a40607ca05596df23428a38eff8aee28c49f03c5ac1a74eca11bf52ee45b4f0b951f6a9064115cf2abdab4b1561e` |
| TLSH | `T166F3CF1102589D1EA11B9610C1E3AE5F827199BD9E1DF60EB30E7EACF5E8BE533011ED` |
| SSDEEP | `1536:psIJkbJL8lzbnsy3QJmvIwAVimJKaKSRns6cg9zQvnO9S96D8EfbfOtMIOKi+8GU:y` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_038_1876ef7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1876ef7a0995a7383f5660bcd0b53de56bb9c21f04395f35a86e8195b99bf180"
    family = "PureLogsStealer"
    file_name = "New Order-PO230824312.vbs"
    file_type = "vbs"
    first_seen = "2026-08-28 07:54:58"
  condition:
    hash.sha256(0, filesize) == "1876ef7a0995a7383f5660bcd0b53de56bb9c21f04395f35a86e8195b99bf180"
}
```

### Sample 39: `46ced738ab9a9a37`

| Field | Value |
|---|---|
| SHA-256 | `46ced738ab9a9a37df3e36c6a8603742f26783f0be2fa845bdec10b5ddb50bfb` |
| Family label | `unknown` |
| File name | `98f00e36daaf4c4bae91031d4b53ea9b.exe` |
| File type | `exe` |
| First seen | `2026-08-28 07:54:50` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98f00e36daaf4c4bae91031d4b53ea9b` |
| SHA-1 | `6c19930c2b6b2ec49b42399dcd8e477de347c010` |
| SHA-256 | `46ced738ab9a9a37df3e36c6a8603742f26783f0be2fa845bdec10b5ddb50bfb` |
| SHA3-384 | `bb676f184270c156d9eb99096078f550188033b060417ef6b5e93d1bb76e0faacfc53d6ad4ecb3d3160d6c1022ba7319` |
| IMPHASH | `e8ac1646024d52d1534a88da2e8037cd` |
| TLSH | `T14D56AE03F389612ED06A2A37693B9694983F7A6039168C57DBEC3F4C8F791401D3A767` |
| SSDEEP | `49152:pDXrwW+/stv7JInHg9lWRzHyWwT39s5RnVJESQHMc132SMjlyoVFNXM3QR/396sS:pDbkmjKAapl22SMjlyKFeaZqg333iL` |
| ICON-DHASH | `5050d270cccc82ae` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_46ced738
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46ced738ab9a9a37df3e36c6a8603742f26783f0be2fa845bdec10b5ddb50bfb"
    family = "unknown"
    file_name = "98f00e36daaf4c4bae91031d4b53ea9b.exe"
    file_type = "exe"
    first_seen = "2026-08-28 07:54:50"
  condition:
    hash.sha256(0, filesize) == "46ced738ab9a9a37df3e36c6a8603742f26783f0be2fa845bdec10b5ddb50bfb"
}
```

### Sample 40: `09fbf3e4ef290696`

| Field | Value |
|---|---|
| SHA-256 | `09fbf3e4ef2906968ec725e6794f16597ab2f53019f460417e9162f0d912ed35` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.msi` |
| File type | `msi` |
| First seen | `2026-08-28 07:50:24` |
| Reporter | `abuse_ch` |
| Tags | `ConnectWise, msi, RMM, ScreenConnect` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f68bd8f4af434be425fe38481e016ab` |
| SHA-1 | `9dcd218a2af5a8ac9c3618c32a266140262103f5` |
| SHA-256 | `09fbf3e4ef2906968ec725e6794f16597ab2f53019f460417e9162f0d912ed35` |
| SHA3-384 | `f309d73fd21e66e23930178aa28025f510e01f3f9fa48955e844d2edbcddb3283d27838d57e3faad38cb875e06f368f9` |
| TLSH | `T1F5A623116BF8D278F1F12A39D876A0B1A53A7D119E23D12E2324791E2C75EC0CA63777` |
| SSDEEP | `196608:lHxcp9ym3nltDUJVZHxcp9ym3YHxcp9ym39Hxcp9ym3FHxcp9ym3:XGplpGGpmGpvGp3Gp` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_040_09fbf3e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09fbf3e4ef2906968ec725e6794f16597ab2f53019f460417e9162f0d912ed35"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-08-28 07:50:24"
  condition:
    hash.sha256(0, filesize) == "09fbf3e4ef2906968ec725e6794f16597ab2f53019f460417e9162f0d912ed35"
}
```

### Sample 41: `e77f58904f6692e7`

| Field | Value |
|---|---|
| SHA-256 | `e77f58904f6692e7adbb1d8dac1ec89e827a6847d632e1ab0082a5ffc7a9553a` |
| Family label | `Mirai` |
| File name | `e77f58904f6692e7adbb1d8dac1ec89e827a6847d632e1ab0082a5ffc7a9553a.elf` |
| File type | `elf` |
| First seen | `2026-08-28 07:46:41` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `797d2b4c0862e3d9dc24c47e7c47ba6e` |
| SHA-1 | `03c56d13e58ab7dddd3d80eb3a91c5e564cba65c` |
| SHA-256 | `e77f58904f6692e7adbb1d8dac1ec89e827a6847d632e1ab0082a5ffc7a9553a` |
| SHA3-384 | `4e1bdf5e67d7c7ac501138e4ff83d64a046614785f0a73dd1337112f86388c780c60ec8a726642fde6cfaba47f0b9694` |
| TLSH | `T11511CE27F28A5F87DA1AC03E8921673037AAE9698A172FB5331CD0316D273837B56341` |
| SSDEEP | `12:BdgcZvrG49znT/84GtHmqkEYtrWA4AQ9Tnp7m17efV2BOilcZ0BzO:A6a49f84GtrkCALy7m17efVNfkz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_e77f5890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e77f58904f6692e7adbb1d8dac1ec89e827a6847d632e1ab0082a5ffc7a9553a"
    family = "Mirai"
    file_name = "e77f58904f6692e7adbb1d8dac1ec89e827a6847d632e1ab0082a5ffc7a9553a.elf"
    file_type = "elf"
    first_seen = "2026-08-28 07:46:41"
  condition:
    hash.sha256(0, filesize) == "e77f58904f6692e7adbb1d8dac1ec89e827a6847d632e1ab0082a5ffc7a9553a"
}
```

### Sample 42: `b926a44910e4f4d5`

| Field | Value |
|---|---|
| SHA-256 | `b926a44910e4f4d55c53fdc6d9cdbfb043059355d55fb3595a3434bd69b1e7e3` |
| Family label | `LummaStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-28 07:36:36` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, LummaStealer, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb65c6e1104854b87418a16fffd59230` |
| SHA-1 | `32452cd6c337772b89c6a83dfd1c96ab7af565c8` |
| SHA-256 | `b926a44910e4f4d55c53fdc6d9cdbfb043059355d55fb3595a3434bd69b1e7e3` |
| SHA3-384 | `6e1dc4420b06be2ac947b3e802f24c196ac4fef668721230107aa55ca04c58642da253d6340d13b1011c76414f1af99c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T13A866A41FE9B94F6E90319301567B27F63346D058F29CBE7EB447B2AF8776910832289` |
| SSDEEP | `98304:hykvhVK/OnUGvfsK4pPOw4SfnT9ETbnToV7QzEMIf5WZ0O5vZHrjt9s:hAqoZqxzFIsF7nt2` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_042_b926a449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b926a44910e4f4d55c53fdc6d9cdbfb043059355d55fb3595a3434bd69b1e7e3"
    family = "LummaStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 07:36:36"
  condition:
    hash.sha256(0, filesize) == "b926a44910e4f4d55c53fdc6d9cdbfb043059355d55fb3595a3434bd69b1e7e3"
}
```

### Sample 43: `3daa312d3539f72c`

| Field | Value |
|---|---|
| SHA-256 | `3daa312d3539f72c1fbf1c9647547c8e8271528ca0a525207ffa224d3f5ae5c8` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-28 07:35:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f95134e69ff07beb2b3d52d43bae4b6a` |
| SHA-1 | `b9f247e0cd8e3cfc7d0391dcb2e05e32e3e1551a` |
| SHA-256 | `3daa312d3539f72c1fbf1c9647547c8e8271528ca0a525207ffa224d3f5ae5c8` |
| SHA3-384 | `0b1cefcff32e2bc15d35f1f801b36637508c31044433f4163c6b861ce3eedd24f61097a8f1e53dc21a630f1c4a21a276` |
| TLSH | `T1D4236C651A857C24AA98C4371D7E2F0CBDAD43E6324492DE7FCB3CF28C5AA9D910871D` |
| SSDEEP | `768:lXRWNGxVv9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:vlxCcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_3daa312d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3daa312d3539f72c1fbf1c9647547c8e8271528ca0a525207ffa224d3f5ae5c8"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 07:35:31"
  condition:
    hash.sha256(0, filesize) == "3daa312d3539f72c1fbf1c9647547c8e8271528ca0a525207ffa224d3f5ae5c8"
}
```

### Sample 44: `e9499ef03470396b`

| Field | Value |
|---|---|
| SHA-256 | `e9499ef03470396b080045e9a502f02b0ac2cb33685a3cbe142051942dd29dd9` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-28 07:33:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1a62c4cbdc6fc9f0487b61810e4a5c0` |
| SHA-1 | `2662919ffff6d6cdeeef0de15d0a0b6107ca1904` |
| SHA-256 | `e9499ef03470396b080045e9a502f02b0ac2cb33685a3cbe142051942dd29dd9` |
| SHA3-384 | `9d7a5f44890b6bc53773845f3db4464478b028128cd3ecc2c14245ee368d1faa8e1294fcc88c9e514e2baf31b3fba467` |
| TLSH | `T10D236C6526857C24AA99C4371D7E2F0CBDAD43E6320492EE7FCA3CF28C5A69DD10871D` |
| SSDEEP | `768:CXRWNGxVG9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ulxpcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_e9499ef0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9499ef03470396b080045e9a502f02b0ac2cb33685a3cbe142051942dd29dd9"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 07:33:33"
  condition:
    hash.sha256(0, filesize) == "e9499ef03470396b080045e9a502f02b0ac2cb33685a3cbe142051942dd29dd9"
}
```

### Sample 45: `f0bc10c6e13d2da8`

| Field | Value |
|---|---|
| SHA-256 | `f0bc10c6e13d2da8a50767c193265db6da1ddd339c6da4fdeb518a501b47ff69` |
| Family label | `Mirai` |
| File name | `f0bc10c6e13d2da8a50767c193265db6da1ddd339c6da4fdeb518a501b47ff69.elf` |
| File type | `elf` |
| First seen | `2026-08-28 07:26:42` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2646ffaa5f15490cb6962ce6d43b4aa` |
| SHA-1 | `0f1fd7a92ca2edc0b69ec30315b8bb5774d4a098` |
| SHA-256 | `f0bc10c6e13d2da8a50767c193265db6da1ddd339c6da4fdeb518a501b47ff69` |
| SHA3-384 | `7e8b5feaf827ec71765829197b553614f98b43b5551538a921533db4574d3bd808b65b4cdaba5b98f82079d992a690d7` |
| TLSH | `T10721024E76FBACE1CA7840BD854B834D222BE784C2ABF613CB204C170C0256D0F14045` |
| SSDEEP | `24:DxvW2T9oGEOZu9yODq+1d0j2HAu8ZTBuLlRjY9gxj:Dxec9rQ9yEx0+Au8ZTBunjYWj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_f0bc10c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0bc10c6e13d2da8a50767c193265db6da1ddd339c6da4fdeb518a501b47ff69"
    family = "Mirai"
    file_name = "f0bc10c6e13d2da8a50767c193265db6da1ddd339c6da4fdeb518a501b47ff69.elf"
    file_type = "elf"
    first_seen = "2026-08-28 07:26:42"
  condition:
    hash.sha256(0, filesize) == "f0bc10c6e13d2da8a50767c193265db6da1ddd339c6da4fdeb518a501b47ff69"
}
```

### Sample 46: `7bebf7bcf09e72dd`

| Field | Value |
|---|---|
| SHA-256 | `7bebf7bcf09e72dde8e9b25baddab1d292c5815008a0d5795ddf5db72ba45432` |
| Family label | `unknown` |
| File name | `7bebf7bcf09e72dde8e9b25baddab1d292c5815008a0d5795ddf5db72ba45432.elf` |
| File type | `elf` |
| First seen | `2026-08-28 07:26:36` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28021974683500d254238645ddaff36c` |
| SHA-1 | `1a3f4c22953d73d433edfb582a6a7d927c7553b7` |
| SHA-256 | `7bebf7bcf09e72dde8e9b25baddab1d292c5815008a0d5795ddf5db72ba45432` |
| SHA3-384 | `a91ef9fdfd75e28e58027445d48776d38d474dfd2491470efe2826465b237856128fc279dee4fa36e1602dfdab3c9e09` |
| TLSH | `T1D5112F24BBE3CC87E5B0C03BC4CF039476A1C1E8827AEE16B37060370CA7616AE5108B` |
| SSDEEP | `24:2p/cPwAt9YpsDD8lqVUncRlaroQe5RwrED8IMIIlEVNfC:2pEPnWrqVUn8GoNRwwD8IMIoEVN6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_7bebf7bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bebf7bcf09e72dde8e9b25baddab1d292c5815008a0d5795ddf5db72ba45432"
    family = "unknown"
    file_name = "7bebf7bcf09e72dde8e9b25baddab1d292c5815008a0d5795ddf5db72ba45432.elf"
    file_type = "elf"
    first_seen = "2026-08-28 07:26:36"
  condition:
    hash.sha256(0, filesize) == "7bebf7bcf09e72dde8e9b25baddab1d292c5815008a0d5795ddf5db72ba45432"
}
```

### Sample 47: `a46408be582bfeff`

| Field | Value |
|---|---|
| SHA-256 | `a46408be582bfeff347490b12c0b24db7cabeb05498f72faf68dd4caa95882ce` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-08-28 07:26:33` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2f8566288889ccd275c0fd7504e274b` |
| SHA-256 | `a46408be582bfeff347490b12c0b24db7cabeb05498f72faf68dd4caa95882ce` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_a46408be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a46408be582bfeff347490b12c0b24db7cabeb05498f72faf68dd4caa95882ce"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 07:26:33"
  condition:
    hash.sha256(0, filesize) == "a46408be582bfeff347490b12c0b24db7cabeb05498f72faf68dd4caa95882ce"
}
```

### Sample 48: `6eb9386b0b6c2a75`

| Field | Value |
|---|---|
| SHA-256 | `6eb9386b0b6c2a75fc265317b697c1d16861020edc7f8cf68b1663b361633772` |
| Family label | `Mirai` |
| File name | `dlr.x86` |
| File type | `elf` |
| First seen | `2026-08-28 07:16:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d03f7e44a293a9bfb41081c8ff7151be` |
| SHA-1 | `0d3ee354ff44a0229720e03b154035581cc235f3` |
| SHA-256 | `6eb9386b0b6c2a75fc265317b697c1d16861020edc7f8cf68b1663b361633772` |
| SHA3-384 | `cbc84efc43a75b94c4117bdb6887347546f50a5f35836518329d1370eb1c05acb9e8ae0ca8d5ea742e56f8a82a0f0598` |
| TLSH | `T1EE11F686F5C2FC23DCDA85B953875F63EB09EDB85E1ACB03D39134314D3A5C65911548` |
| SSDEEP | `24:Fl9M3dn3X51VsX8okxQshGO0+2ruQS4MNfSc:f9gvVsX8okx7CFHWNp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_6eb9386b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eb9386b0b6c2a75fc265317b697c1d16861020edc7f8cf68b1663b361633772"
    family = "Mirai"
    file_name = "dlr.x86"
    file_type = "elf"
    first_seen = "2026-08-28 07:16:32"
  condition:
    hash.sha256(0, filesize) == "6eb9386b0b6c2a75fc265317b697c1d16861020edc7f8cf68b1663b361633772"
}
```

### Sample 49: `16168cc3b16d768b`

| Field | Value |
|---|---|
| SHA-256 | `16168cc3b16d768beffaf0fd10f74f86f79da7a2c7ca26edd91c09c1c101811d` |
| Family label | `Vidar` |
| File name | `16168cc3b16d768beffaf0fd10f74f86f79da7a2c7ca26edd91c09c1c101811d.bin` |
| File type | `exe` |
| First seen | `2026-08-28 07:13:31` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `356484cecd7e391a8376ad70afa8f97a` |
| SHA-1 | `eaf41de301f2e71c912836fd1eac285043ee841f` |
| SHA-256 | `16168cc3b16d768beffaf0fd10f74f86f79da7a2c7ca26edd91c09c1c101811d` |
| SHA3-384 | `d5417d5d5cccaea7363bc8e4dc0ef87affe5de10988a5338df1a922a6be2f1a2d1b7f92bfc9228e1fb8dc7c361df429f` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T149463A0F7740B1B8D8E2D639A16A4A28A661BC0DC33133D75E6249F09F363C57EB9758` |
| GIMPHASH | `6b8264727a15ac59e6594e0c23d8d2edf82734d005204871396b07a916915b1a` |
| SSDEEP | `49152:kszOht0eIhsBsS5INtHGCGibSCJ2Oaf+kl0uF1Iy2ttq89xJgG2V08L77yaHYFaC:O2HTrc6ta2mI1qml` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_049_16168cc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16168cc3b16d768beffaf0fd10f74f86f79da7a2c7ca26edd91c09c1c101811d"
    family = "Vidar"
    file_name = "16168cc3b16d768beffaf0fd10f74f86f79da7a2c7ca26edd91c09c1c101811d.bin"
    file_type = "exe"
    first_seen = "2026-08-28 07:13:31"
  condition:
    hash.sha256(0, filesize) == "16168cc3b16d768beffaf0fd10f74f86f79da7a2c7ca26edd91c09c1c101811d"
}
```

### Sample 50: `aae87ba174e92ebf`

| Field | Value |
|---|---|
| SHA-256 | `aae87ba174e92ebfaa0a63585920085cfaf0c1777471749c0ea1bc8f704238f1` |
| Family label | `unknown` |
| File name | `aae87ba174e92ebfaa0a63585920085cfaf0c1777471749c0ea1bc8f704238f1` |
| File type | `sh` |
| First seen | `2026-08-28 07:00:17` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f3ebc132443c3c37344af0bf3ce6d39` |
| SHA-1 | `ed5d9f2320e7eda0b07f72070a0b38f259c79792` |
| SHA-256 | `aae87ba174e92ebfaa0a63585920085cfaf0c1777471749c0ea1bc8f704238f1` |
| SHA3-384 | `c730bca10b5fab4b4c607b29aa213d0182a8fbefae22b6ba25ce8115bae8ae394287b6ef768ffcce0d04ef74d1c833b0` |
| TLSH | `T1C8315B9F44105E725102CE8E77A2B94C668EA1FB184FEBD4DC584DA982483CCF3A1F4D` |
| SSDEEP | `24:3EKv6ha78fYjNb5s9Qkhg19A9OGNiF+sQD2hHcAJDk8kLV7:0YQWkhg1y6QD2hHcAJDk8kLV7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_aae87ba1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aae87ba174e92ebfaa0a63585920085cfaf0c1777471749c0ea1bc8f704238f1"
    family = "unknown"
    file_name = "aae87ba174e92ebfaa0a63585920085cfaf0c1777471749c0ea1bc8f704238f1"
    file_type = "sh"
    first_seen = "2026-08-28 07:00:17"
  condition:
    hash.sha256(0, filesize) == "aae87ba174e92ebfaa0a63585920085cfaf0c1777471749c0ea1bc8f704238f1"
}
```

### Sample 51: `25fee2381d8f3e77`

| Field | Value |
|---|---|
| SHA-256 | `25fee2381d8f3e7724ba63a148642ff3201b58bd0b4325d5c38fa46cb88720e9` |
| Family label | `unknown` |
| File name | `25fee2381d8f3e7724ba63a148642ff3201b58bd0b4325d5c38fa46cb88720e9` |
| File type | `sh` |
| First seen | `2026-08-28 07:00:13` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb86c5614957830eb8589e28f90d7bd0` |
| SHA-1 | `addf202eeb1e7a4305cb6dbae7c477570758fd1f` |
| SHA-256 | `25fee2381d8f3e7724ba63a148642ff3201b58bd0b4325d5c38fa46cb88720e9` |
| SHA3-384 | `05b1579dd8e881fd661c49d839a290ab9a6c5cb825a21a45b1d6d6c84a0b34dfa5b76942f69e85dfb7cb9ae78a43572e` |
| TLSH | `T1E03198AF08251A311013CEDD77A23448729EA5E72C9FD7D4D85D1EAEC28978CF262F49` |
| SSDEEP | `24:1bvBFy7PRtC0Apu54PXYiKyK+RYcPNNZ4n:xZK5tC0ApuuPXYgUcFNZ4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_25fee238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25fee2381d8f3e7724ba63a148642ff3201b58bd0b4325d5c38fa46cb88720e9"
    family = "unknown"
    file_name = "25fee2381d8f3e7724ba63a148642ff3201b58bd0b4325d5c38fa46cb88720e9"
    file_type = "sh"
    first_seen = "2026-08-28 07:00:13"
  condition:
    hash.sha256(0, filesize) == "25fee2381d8f3e7724ba63a148642ff3201b58bd0b4325d5c38fa46cb88720e9"
}
```

### Sample 52: `c496e8e8f7cc2e40`

| Field | Value |
|---|---|
| SHA-256 | `c496e8e8f7cc2e40c515c9dbd98ffce43861acaf504466f478ceaebf712214b8` |
| Family label | `GCleaner` |
| File name | `setup_euone.bin` |
| File type | `exe` |
| First seen | `2026-08-28 06:52:06` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, GCleaner` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `801e7911d8ef33ab7843bb638c0b5abc` |
| SHA-1 | `3941abf37772bfdeefa1d8b8bc617f9e1ce4bd48` |
| SHA-256 | `c496e8e8f7cc2e40c515c9dbd98ffce43861acaf504466f478ceaebf712214b8` |
| SHA3-384 | `cf84081aec29b69042bcf43036270ec24c90b3600aa9bfdb3e28f32c5d4acb61f2240770ba5899dc8d16152d80c5dbce` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CF45D0A067EA4F3DED9E3231503A6C1A53F7F8D76B31DB4E021250981B91F849E49BD2` |
| SSDEEP | `24576:e2D0RPGsPf75YuCS/Z4x7YTMxjK4nRj1JUburjp5xMbVpdXEq:e2Ipeub4xUTMx2QRjQdXEq` |

#### Technical Assessment

- The sample is tracked as `GCleaner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GCleaner_052_c496e8e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c496e8e8f7cc2e40c515c9dbd98ffce43861acaf504466f478ceaebf712214b8"
    family = "GCleaner"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-08-28 06:52:06"
  condition:
    hash.sha256(0, filesize) == "c496e8e8f7cc2e40c515c9dbd98ffce43861acaf504466f478ceaebf712214b8"
}
```

### Sample 53: `3eecac099baf249d`

| Field | Value |
|---|---|
| SHA-256 | `3eecac099baf249d268aead626022f0947a13231bdb8cdec5aa6f68b2c584a37` |
| Family label | `Mirai` |
| File name | `3eecac099baf249d268aead626022f0947a13231bdb8cdec5aa6f68b2c584a37.elf` |
| File type | `elf` |
| First seen | `2026-08-28 06:41:06` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3b9025ba18c105c414ca7392c78178c` |
| SHA-1 | `e0e822860769f29a8e84f812f880d7ee3df6475d` |
| SHA-256 | `3eecac099baf249d268aead626022f0947a13231bdb8cdec5aa6f68b2c584a37` |
| SHA3-384 | `47ac3c6d06750e472483fc4ff0ae0e7835e82ce2862c4102de30ed1450f844272d64ef45447e874b009fccd26aa30b8a` |
| TLSH | `T1DF216102B949509BC683D836166F272003F1AA3B0AF2A94C9B092300C93C1FE2A5F48D` |
| SSDEEP | `24:3+G10C91+kQKI9sYB8G/ANndL+u/3wrc1+BiD1To0YRzc8V6xnWx:6wQKQsi8G/cntLxGjVenI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_3eecac09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3eecac099baf249d268aead626022f0947a13231bdb8cdec5aa6f68b2c584a37"
    family = "Mirai"
    file_name = "3eecac099baf249d268aead626022f0947a13231bdb8cdec5aa6f68b2c584a37.elf"
    file_type = "elf"
    first_seen = "2026-08-28 06:41:06"
  condition:
    hash.sha256(0, filesize) == "3eecac099baf249d268aead626022f0947a13231bdb8cdec5aa6f68b2c584a37"
}
```

### Sample 54: `76e6367d8123171a`

| Field | Value |
|---|---|
| SHA-256 | `76e6367d8123171afa540fe92a3758424ec7d1e029c4e5a3b9771e24fe0085c1` |
| Family label | `Amadey` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-28 06:40:41` |
| Reporter | `Bitsight` |
| Tags | `1TEST.file, Amadey, dropped-by-GCleaner, exe, F` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5616af2cef3dcdb095d8cc55db75c96` |
| SHA-1 | `3c584320e4f7523645ed71d09321d2f5a476f103` |
| SHA-256 | `76e6367d8123171afa540fe92a3758424ec7d1e029c4e5a3b9771e24fe0085c1` |
| SHA3-384 | `f8ce46c6247095ef5efa80a10d70c7ac6a69e39c401ca06b43a025d356cae2bc89f696d4568fc6edae78f7086725deef` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18355E1A06BEE4F3DED9A3731503A6C1A03E7F8D7AB31DB4E021250980B51F949E497D6` |
| SSDEEP | `24576:RROWX9rgfA2p7f75YuCS/Z4x7YTMxjK4nRj1JUburjKuv4bPRxq:5X907piub4xUTMx2QRjYbpxq` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_054_76e6367d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76e6367d8123171afa540fe92a3758424ec7d1e029c4e5a3b9771e24fe0085c1"
    family = "Amadey"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 06:40:41"
  condition:
    hash.sha256(0, filesize) == "76e6367d8123171afa540fe92a3758424ec7d1e029c4e5a3b9771e24fe0085c1"
}
```

### Sample 55: `af549a7f988cf26d`

| Field | Value |
|---|---|
| SHA-256 | `af549a7f988cf26d772accfdc120fac42a557302bb00f8294f6fad3a09aed5a4` |
| Family label | `Heodo` |
| File name | `telekom_invoice_malware_20260827.zip` |
| File type | `zip` |
| First seen | `2026-08-28 06:24:41` |
| Reporter | `uks_zik_inf_sic` |
| Tags | `invoice, telekom, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `283b615110893930ab9593d4e88a1247` |
| SHA-1 | `b0d68362c7105de4e6f787fc4528c29825fe2d73` |
| SHA-256 | `af549a7f988cf26d772accfdc120fac42a557302bb00f8294f6fad3a09aed5a4` |
| SHA3-384 | `f7b34863ea292eac0b5904ce5845f14a3271f924a96b6636e0e47dbd8e8b6a25a844b35e2ecda0c1f1d881d704bb95fe` |
| TLSH | `T183A63361D5ABAA80EA0F63597BF1C81C389C6913F744B187A7EC102993D34C6BE117DE` |
| SSDEEP | `196608:KlM3+rPIakgpoQ9BoedSXqF58J/1DcezkPd8DgopHnvYNHO:KoUv1pz9zdSq58J9L24jiO` |

#### Technical Assessment

- The sample is tracked as `Heodo` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Heodo_055_af549a7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af549a7f988cf26d772accfdc120fac42a557302bb00f8294f6fad3a09aed5a4"
    family = "Heodo"
    file_name = "telekom_invoice_malware_20260827.zip"
    file_type = "zip"
    first_seen = "2026-08-28 06:24:41"
  condition:
    hash.sha256(0, filesize) == "af549a7f988cf26d772accfdc120fac42a557302bb00f8294f6fad3a09aed5a4"
}
```

### Sample 56: `994cfadcb2b638fd`

| Field | Value |
|---|---|
| SHA-256 | `994cfadcb2b638fd685a14b326ed217315a54907a42486c72bd0a5311bc33476` |
| Family label | `unknown` |
| File name | `Telekom_Deutschland_Rechnung_August_2026...pdf.zip` |
| File type | `zip` |
| First seen | `2026-08-28 06:18:36` |
| Reporter | `anonymous` |
| Tags | `fraud, invoice, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `feaf74b38f83a70af35d4b0d2d6d38c5` |
| SHA-1 | `a0417a59dfbf27b3370dc13debbc5854337e4c97` |
| SHA-256 | `994cfadcb2b638fd685a14b326ed217315a54907a42486c72bd0a5311bc33476` |
| SHA3-384 | `28da36d4250ecfef9a4d6b85579b44084febb1392060f0d48363f0f5242909f3c0ada5fffaa062013f22eb9ff2851db0` |
| TLSH | `T15EE07D19DF0E5DCAF58D733C3D4225E20D0E104680209641B49839229F065CCFEA367D` |
| SSDEEP | `6:5j1+p7/B8TEhC039r81DYemXuvAlsV+tZznqIqRf4zO1+E7/B83t+lMu/:5j1+pDDtjemXuY2Vwzncgg+EDCtaMu/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_994cfadc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "994cfadcb2b638fd685a14b326ed217315a54907a42486c72bd0a5311bc33476"
    family = "unknown"
    file_name = "Telekom_Deutschland_Rechnung_August_2026...pdf.zip"
    file_type = "zip"
    first_seen = "2026-08-28 06:18:36"
  condition:
    hash.sha256(0, filesize) == "994cfadcb2b638fd685a14b326ed217315a54907a42486c72bd0a5311bc33476"
}
```

### Sample 57: `c8da8aeba2cce8ac`

| Field | Value |
|---|---|
| SHA-256 | `c8da8aeba2cce8ac2747caf1d3021e3b3b803322ca5afdb33aeb66bea3a255ae` |
| Family label | `unknown` |
| File name | `c8da8aeba2cce8ac2747caf1d3021e3b3b803322ca5afdb33aeb66bea3a255ae.exe` |
| File type | `exe` |
| First seen | `2026-08-28 06:16:05` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d9708c4e94b01cd89c06cad657f9c74` |
| SHA-1 | `f3126b2c13e54fc01a950d81d9d717357ff5fa2e` |
| SHA-256 | `c8da8aeba2cce8ac2747caf1d3021e3b3b803322ca5afdb33aeb66bea3a255ae` |
| SHA3-384 | `53983c4f40a837d20e6612fd888fb27186308aa13c9bf1621936b91c2954d50c25bd6e45117aa06bab6c8416b5614416` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T105D5238E65B51A74E83BC7B2CF83E47CB02D374556A18E8B76CE1D406E234586D3A3B1` |
| SSDEEP | `49152:tXsSrMzr0XhsXZbCWYTR16TA3MV9LzVp6yw1tTMl+IGKRK2UL8IRLZyeIqFfV0hp:VsSrMn3XZbCtTQAeVVp6yw3wRz/jIppq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_c8da8aeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8da8aeba2cce8ac2747caf1d3021e3b3b803322ca5afdb33aeb66bea3a255ae"
    family = "unknown"
    file_name = "c8da8aeba2cce8ac2747caf1d3021e3b3b803322ca5afdb33aeb66bea3a255ae.exe"
    file_type = "exe"
    first_seen = "2026-08-28 06:16:05"
  condition:
    hash.sha256(0, filesize) == "c8da8aeba2cce8ac2747caf1d3021e3b3b803322ca5afdb33aeb66bea3a255ae"
}
```

### Sample 58: `d19466c0ca1887e5`

| Field | Value |
|---|---|
| SHA-256 | `d19466c0ca1887e51e1e9bec743207fb24008371c67567be37325b27998dedd6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-28 05:56:18` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remcos, RemoteHost` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b041a661087ab87737f8a91ccad7ba2` |
| SHA-256 | `d19466c0ca1887e51e1e9bec743207fb24008371c67567be37325b27998dedd6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_d19466c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d19466c0ca1887e51e1e9bec743207fb24008371c67567be37325b27998dedd6"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-28 05:56:18"
  condition:
    hash.sha256(0, filesize) == "d19466c0ca1887e51e1e9bec743207fb24008371c67567be37325b27998dedd6"
}
```

### Sample 59: `245f6e3f6750701d`

| Field | Value |
|---|---|
| SHA-256 | `245f6e3f6750701d58c06bd96f4623c62942305fb32bcdc5a99bf367becaafd0` |
| Family label | `CoinMiner` |
| File name | `245f6e3f6750701d58c06bd96f4623c62942305fb32bcdc5a99bf367becaafd0.exe` |
| File type | `exe` |
| First seen | `2026-08-28 05:56:04` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18054d12b0ba2dc0c9918f455ec86699` |
| SHA-1 | `f4ecc1edd84194b94aceb5c3485b830081507508` |
| SHA-256 | `245f6e3f6750701d58c06bd96f4623c62942305fb32bcdc5a99bf367becaafd0` |
| SHA3-384 | `5f92a5609b0e3b0b1155c4a3c6e3e5174340ccd1a3f8b7e38e4b7505bcfd38f39704b241b3473d6da7f2281626a975e5` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T12536338A29C62A71C49BC3B46553386EF17E7B950F00FC2639CEAD0D5D8AE06747A3C5` |
| SSDEEP | `98304:2AYSn13ifpgNinCpxNLDeDj+GIpr0/90b9KxAOi0cfl2zXnNIdh5:xY+QtCprDepxON+NId` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_059_245f6e3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "245f6e3f6750701d58c06bd96f4623c62942305fb32bcdc5a99bf367becaafd0"
    family = "CoinMiner"
    file_name = "245f6e3f6750701d58c06bd96f4623c62942305fb32bcdc5a99bf367becaafd0.exe"
    file_type = "exe"
    first_seen = "2026-08-28 05:56:04"
  condition:
    hash.sha256(0, filesize) == "245f6e3f6750701d58c06bd96f4623c62942305fb32bcdc5a99bf367becaafd0"
}
```

### Sample 60: `5cb54c53e2169a23`

| Field | Value |
|---|---|
| SHA-256 | `5cb54c53e2169a23a815d87229b00c63d1d3c8c0d19e0f92b5e83bd231481419` |
| Family label | `RemusStealer` |
| File name | `cx-programmer 9.1 free download full.exe` |
| File type | `exe` |
| First seen | `2026-08-28 05:44:09` |
| Reporter | `abuse_ch` |
| Tags | `de-pumped, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4878d995e4e23c6961c91179e6e2c704` |
| SHA-1 | `bcf32c802a7a27b2bfe6ea5e26b75091c8a76175` |
| SHA-256 | `5cb54c53e2169a23a815d87229b00c63d1d3c8c0d19e0f92b5e83bd231481419` |
| SHA3-384 | `2a52cadb226aa79d5f4e68338d4c23945044e7a9ed07753e6ea195efb4974abd34c5e993b7863de490c42b3a7ae385fe` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T10FD57C077C8490A5C1EA8B35CA7692A1B6347C8CCB3133D72F44ABB62E727C25E79754` |
| GIMPHASH | `a36842493558c7c400770ac0117ac9ec1c448753ebbfeabea3cfe1c4c96e01f9` |
| SSDEEP | `49152:2JEOYtPsqIP/r2p1l7VSgkCyIcayg4ZgwM2j3RiDfD1t4:RBydaO0S` |
| ICON-DHASH | `3278c0c4d4dcf031` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_060_5cb54c53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cb54c53e2169a23a815d87229b00c63d1d3c8c0d19e0f92b5e83bd231481419"
    family = "RemusStealer"
    file_name = "cx-programmer 9.1 free download full.exe"
    file_type = "exe"
    first_seen = "2026-08-28 05:44:09"
  condition:
    hash.sha256(0, filesize) == "5cb54c53e2169a23a815d87229b00c63d1d3c8c0d19e0f92b5e83bd231481419"
}
```

### Sample 61: `3b2923ad0a2c7c0c`

| Field | Value |
|---|---|
| SHA-256 | `3b2923ad0a2c7c0c5386c5af90f8ef5a9ef8e1b51ecf7b70ee936cda46923c42` |
| Family label | `unknown` |
| File name | `567ec72e3720cfe55b799e115bb5d0daf49f9a877e758cd7d48f21c7b1e76a06.zip` |
| File type | `zip` |
| First seen | `2026-08-28 05:24:35` |
| Reporter | `malaiyappan` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f43032f1abfe01db654eafb4f826eef4` |
| SHA-256 | `3b2923ad0a2c7c0c5386c5af90f8ef5a9ef8e1b51ecf7b70ee936cda46923c42` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_3b2923ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b2923ad0a2c7c0c5386c5af90f8ef5a9ef8e1b51ecf7b70ee936cda46923c42"
    family = "unknown"
    file_name = "567ec72e3720cfe55b799e115bb5d0daf49f9a877e758cd7d48f21c7b1e76a06.zip"
    file_type = "zip"
    first_seen = "2026-08-28 05:24:35"
  condition:
    hash.sha256(0, filesize) == "3b2923ad0a2c7c0c5386c5af90f8ef5a9ef8e1b51ecf7b70ee936cda46923c42"
}
```

### Sample 62: `f63eb2664ac90762`

| Field | Value |
|---|---|
| SHA-256 | `f63eb2664ac9076250491b1cb0787042f75a056e235867d9f9967322c5cf20a4` |
| Family label | `PureRAT` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-28 05:09:55` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, PureRAT, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ca17777470b32e4e74b547e5f3f9306` |
| SHA-1 | `5bfdc93f36ecf75b5be5590a48bdc58503c34fb0` |
| SHA-256 | `f63eb2664ac9076250491b1cb0787042f75a056e235867d9f9967322c5cf20a4` |
| SHA3-384 | `9e6791e6131f9409497e068aeafbcb6ad495ea10858f84ac15279b3bef57c1f934e94e0ee1ee4239920a8e6e93250d57` |
| IMPHASH | `7fd6b4347e14fdba5750f7ad1b35461f` |
| TLSH | `T18DE57C07FCA558F6C4AEA23189229612BB71BC482F3113DB2F50B6B42FB27D05DB9754` |
| SSDEEP | `49152:LOqImxDbWybk5ik0Ow9H6gxdKgMl7pLXVlN+DBYe8jjndwDq:LO8JhBdMhpVjpwm` |

#### Technical Assessment

- The sample is tracked as `PureRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureRAT_062_f63eb266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f63eb2664ac9076250491b1cb0787042f75a056e235867d9f9967322c5cf20a4"
    family = "PureRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 05:09:55"
  condition:
    hash.sha256(0, filesize) == "f63eb2664ac9076250491b1cb0787042f75a056e235867d9f9967322c5cf20a4"
}
```

### Sample 63: `9b0e3f974dac0023`

| Field | Value |
|---|---|
| SHA-256 | `9b0e3f974dac0023599bb604b5b30e3e763c2d1d28ecff80d307ca73dc06243f` |
| Family label | `DCRat` |
| File name | `9FCE0558DD8B2061C7A8BAF0877D5384.exe` |
| File type | `exe` |
| First seen | `2026-08-28 05:05:17` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fce0558dd8b2061c7a8baf0877d5384` |
| SHA-1 | `92937973d50ddd6bff639bf35feb25b119f56edd` |
| SHA-256 | `9b0e3f974dac0023599bb604b5b30e3e763c2d1d28ecff80d307ca73dc06243f` |
| SHA3-384 | `4305c7e68d777c08d0087aa893ee54184b2f48f160334cdbedbc0084d96d718cc5af55f0d1c07336128573ad0065f029` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T12F05F6027F54CA01F1091237E2EF854847B4D95166AAE32BBDBE376D95123A73C0DACB` |
| SSDEEP | `12288:o0iIcMTun1f4iGTc28bOCR3E8u01cHDeQOzvxe9kQ4RNbgHbS4YAuDrnI:o08ce1f40RE8u0ujMz5wktrubSEuvI` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_063_9b0e3f97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b0e3f974dac0023599bb604b5b30e3e763c2d1d28ecff80d307ca73dc06243f"
    family = "DCRat"
    file_name = "9FCE0558DD8B2061C7A8BAF0877D5384.exe"
    file_type = "exe"
    first_seen = "2026-08-28 05:05:17"
  condition:
    hash.sha256(0, filesize) == "9b0e3f974dac0023599bb604b5b30e3e763c2d1d28ecff80d307ca73dc06243f"
}
```

### Sample 64: `ff08f124122ea1ed`

| Field | Value |
|---|---|
| SHA-256 | `ff08f124122ea1edb933d945458b65b5ce61330c8510f0e906b2edf331f045c2` |
| Family label | `Mirai` |
| File name | `dlr.mpsl` |
| File type | `elf` |
| First seen | `2026-08-28 04:49:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32dd4d96163c54adf0cb4498dfd35dae` |
| SHA-1 | `05276e72b68bb35a7574db3707d3f66912859bf3` |
| SHA-256 | `ff08f124122ea1edb933d945458b65b5ce61330c8510f0e906b2edf331f045c2` |
| SHA3-384 | `2805186b664a771adc58051e0c2baf99f787c1a2163cb16119523c57513634c4150fb93cc9a964169143d7552590e919` |
| TLSH | `T1FE3103499F945E21D456DC378D3497B422CC404BB1A61B8E6525D710BD0F741AFE7898` |
| SSDEEP | `48:xneLmujIDS7pCCqUKLnlTXWzkeHl2v7Jnc:ULmujIBXW/HlQ9c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_ff08f124
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff08f124122ea1edb933d945458b65b5ce61330c8510f0e906b2edf331f045c2"
    family = "Mirai"
    file_name = "dlr.mpsl"
    file_type = "elf"
    first_seen = "2026-08-28 04:49:33"
  condition:
    hash.sha256(0, filesize) == "ff08f124122ea1edb933d945458b65b5ce61330c8510f0e906b2edf331f045c2"
}
```

### Sample 65: `1469a7931d3da025`

| Field | Value |
|---|---|
| SHA-256 | `1469a7931d3da0258753eb7e758e08126895ccdb942d5e2dd3ed7a5e0889faf1` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-28 04:30:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb17a9892cff44d80c98630133c5a335` |
| SHA-1 | `58724066706c9c83364c286b1c12cc66555d4674` |
| SHA-256 | `1469a7931d3da0258753eb7e758e08126895ccdb942d5e2dd3ed7a5e0889faf1` |
| SHA3-384 | `3e16c8c166a491c0f2cf11b94ab4a64d7d7cea30bc72fa0e9560d253086322083546eb159352932d9dfe49aab4eef130` |
| TLSH | `T1043130DE541169311102CE8F73A3364CB19EB2FB2C4FD7E099590EA986883DCF162B5D` |
| SSDEEP | `24:GDQDSNw4Ss0Jo39jNk9cIhFvPN2VSUp8NfraLb+RM:Gkkj39jNJILJ4+RM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_1469a793
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1469a7931d3da0258753eb7e758e08126895ccdb942d5e2dd3ed7a5e0889faf1"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-28 04:30:33"
  condition:
    hash.sha256(0, filesize) == "1469a7931d3da0258753eb7e758e08126895ccdb942d5e2dd3ed7a5e0889faf1"
}
```

### Sample 66: `0bab062af7894bc4`

| Field | Value |
|---|---|
| SHA-256 | `0bab062af7894bc44d68ebc5b9633a84ffaae1f17671ff3949002c43321ec86a` |
| Family label | `ValleyRAT` |
| File name | `846F4ED47A679E24505470F61D9110DB.exe` |
| File type | `exe` |
| First seen | `2026-08-28 04:10:17` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `846f4ed47a679e24505470f61d9110db` |
| SHA-1 | `7be1989c25579401ac8638a889a1657d5182f7b8` |
| SHA-256 | `0bab062af7894bc44d68ebc5b9633a84ffaae1f17671ff3949002c43321ec86a` |
| SHA3-384 | `6449c187edeb296afd5b162b6aa50bf71b857167171ae915ece3756db3f4509163ee1425de7af8bbff7d4e35c80a9cf3` |
| IMPHASH | `59010c5840153cfa420aabe5bb8fa447` |
| TLSH | `T170857D01B7A89DF6F8021E3890CB67265E35BC2627124AD79B61BB125A333D19F37707` |
| SSDEEP | `24576:K21Ymflm4a6Ts6eIsJeNhaodobEz0IsJeNhaodobEqgVl14y:K0eIsJ63+bEz0IsJ63+bEq8` |
| ICON-DHASH | `4959515c796d5f5b` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_066_0bab062a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bab062af7894bc44d68ebc5b9633a84ffaae1f17671ff3949002c43321ec86a"
    family = "ValleyRAT"
    file_name = "846F4ED47A679E24505470F61D9110DB.exe"
    file_type = "exe"
    first_seen = "2026-08-28 04:10:17"
  condition:
    hash.sha256(0, filesize) == "0bab062af7894bc44d68ebc5b9633a84ffaae1f17671ff3949002c43321ec86a"
}
```

### Sample 67: `562622045c43b246`

| Field | Value |
|---|---|
| SHA-256 | `562622045c43b246078c942e1514a82a80413ded29337d79fec38471c21cc13f` |
| Family label | `unknown` |
| File name | `Frostix.exe` |
| File type | `exe` |
| First seen | `2026-08-28 04:02:38` |
| Reporter | `hexinglarps` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0039849884b1c79327e6b62be19a571` |
| SHA-1 | `f7d88eb37e90d506a060ad97fbd91fa076656638` |
| SHA-256 | `562622045c43b246078c942e1514a82a80413ded29337d79fec38471c21cc13f` |
| SHA3-384 | `4d83fbc8125d4f40c7f4708dbf7bfc9fe3977e48b714d8ab6b3a98e7629ad648408afcdf9bc5ce71e7e05794285c1438` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T12CF7337DE631E56FEFD059BF544612CAA10AAC9643A7106FBC3F34D229304C0962EA5F` |
| SSDEEP | `1572864:8ejOYfTFnfebPo6duNjPt1a2C2Uh2Qr9xuTJdpdbZf7:84BfeDdduhF1a2Cfr9IVf7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_56262204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "562622045c43b246078c942e1514a82a80413ded29337d79fec38471c21cc13f"
    family = "unknown"
    file_name = "Frostix.exe"
    file_type = "exe"
    first_seen = "2026-08-28 04:02:38"
  condition:
    hash.sha256(0, filesize) == "562622045c43b246078c942e1514a82a80413ded29337d79fec38471c21cc13f"
}
```

### Sample 68: `c1a20d4cc65d61cb`

| Field | Value |
|---|---|
| SHA-256 | `c1a20d4cc65d61cb4d60b780fc3678a7a18c585633636ebdb3aa04b070d4d5e2` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-28 03:50:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3802f829b4be77b345a6daa864ee8187` |
| SHA-1 | `39b57fd4e0d553aebf63fdd6361423247d886eff` |
| SHA-256 | `c1a20d4cc65d61cb4d60b780fc3678a7a18c585633636ebdb3aa04b070d4d5e2` |
| SHA3-384 | `f56d8b0f8f4e401d01dcd8995509b86a6b6a5b54963065271c7165c2fffdb4c9a961dddac1cb10f1d76176f3cb752cd2` |
| TLSH | `T178236C651A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10871D` |
| SSDEEP | `768:vXRWNGxVH9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Jlxicr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_c1a20d4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1a20d4cc65d61cb4d60b780fc3678a7a18c585633636ebdb3aa04b070d4d5e2"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 03:50:35"
  condition:
    hash.sha256(0, filesize) == "c1a20d4cc65d61cb4d60b780fc3678a7a18c585633636ebdb3aa04b070d4d5e2"
}
```

### Sample 69: `0c8c4a99337505f7`

| Field | Value |
|---|---|
| SHA-256 | `0c8c4a99337505f79c05af524ef2c8ce810269a1896b9bd83bbd39454a618b8d` |
| Family label | `Vidar` |
| File name | `0c8c4a99337505f79c05af524ef2c8ce810269a1896b9bd83bbd39454a618b8d.bin` |
| File type | `exe` |
| First seen | `2026-08-28 03:42:46` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `133027a245bc3253038e082b5115a9dc` |
| SHA-1 | `153d808ae3f57827a81024aa742ebbda96763f92` |
| SHA-256 | `0c8c4a99337505f79c05af524ef2c8ce810269a1896b9bd83bbd39454a618b8d` |
| SHA3-384 | `de04a2ea4fc0d00a3cca6e6ddb08d500bf777416ceaf78817430e135130cfb163bb88546e1872857b913c17ba6f58614` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T13216AE03FC91D1F5C8AB9235D6BA8291B630B8A94B3537D72E40B67A1F763E01E78354` |
| GIMPHASH | `f41cfbe49eefd75fcfa817ba45a51a77f13761d5656122a0a9698123e0fc0d46` |
| SSDEEP | `49152:07v33W1lfHlb10RtLK+fCjXSJcHyAMeztHEuBVSsLw47XmgwGDfyNpmD1L8z+m:vHB1n+5yS8BE27xGv` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_069_0c8c4a99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c8c4a99337505f79c05af524ef2c8ce810269a1896b9bd83bbd39454a618b8d"
    family = "Vidar"
    file_name = "0c8c4a99337505f79c05af524ef2c8ce810269a1896b9bd83bbd39454a618b8d.bin"
    file_type = "exe"
    first_seen = "2026-08-28 03:42:46"
  condition:
    hash.sha256(0, filesize) == "0c8c4a99337505f79c05af524ef2c8ce810269a1896b9bd83bbd39454a618b8d"
}
```

### Sample 70: `f19ce246b09aec50`

| Field | Value |
|---|---|
| SHA-256 | `f19ce246b09aec504d8cb547f9d3344e14a6ca898f8d88f2207ece0d74f0d3f1` |
| Family label | `RustyStealer` |
| File name | `f19ce246b09aec504d8cb547f9d3344e14a6ca898f8d88f2207ece0d74f0d3f1.bin` |
| File type | `exe` |
| First seen | `2026-08-28 03:42:42` |
| Reporter | `anonymous` |
| Tags | `exe, Gh0st, HijackLoader, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57629b1f3807d324e3c51a340228fe5a` |
| SHA-1 | `b07426979d61bbc20b209b88d2f6dd3f5cceb1ee` |
| SHA-256 | `f19ce246b09aec504d8cb547f9d3344e14a6ca898f8d88f2207ece0d74f0d3f1` |
| SHA3-384 | `8fb090e61074d8ca3d4990a6a92e20f42e9a050411f58d33d041520f836602f217ac6e1236beb6f79f2a54aa501e2797` |
| IMPHASH | `a6daaa77636e4c7606102480fbfd15c5` |
| TLSH | `T162F74A257B5AA469C55AC8B0834B4A631F3430CB1B35B9FF44D486B92FBDAF41A3D318` |
| SSDEEP | `393216:AVUHbopYso5Ysac+jMZFQ6yXwmn3U1DNkAlJ:zb6Ys/s815qDNkA` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_070_f19ce246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f19ce246b09aec504d8cb547f9d3344e14a6ca898f8d88f2207ece0d74f0d3f1"
    family = "RustyStealer"
    file_name = "f19ce246b09aec504d8cb547f9d3344e14a6ca898f8d88f2207ece0d74f0d3f1.bin"
    file_type = "exe"
    first_seen = "2026-08-28 03:42:42"
  condition:
    hash.sha256(0, filesize) == "f19ce246b09aec504d8cb547f9d3344e14a6ca898f8d88f2207ece0d74f0d3f1"
}
```

### Sample 71: `d55a97b3c7eaba8b`

| Field | Value |
|---|---|
| SHA-256 | `d55a97b3c7eaba8b619a790ea9bac46ce8d48cf7553a970f00ef18a1107ff9a5` |
| Family label | `unknown` |
| File name | `d55a97b3c7eaba8b619a790ea9bac46ce8d48cf7553a970f00ef18a1107ff9a5.exe` |
| File type | `exe` |
| First seen | `2026-08-28 03:36:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f69493929883c801bc5742580c468978` |
| SHA-1 | `caa758c12fa87f30afc4a872ec390a414c8c5ea6` |
| SHA-256 | `d55a97b3c7eaba8b619a790ea9bac46ce8d48cf7553a970f00ef18a1107ff9a5` |
| SHA3-384 | `babecb49c1e8f93da2cd43dfc36e9e900fa1464c0b8d01192c14a76d33082100aa263d2f69e1f58d8a8b6af9dd61110e` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T1AFE52398BCC679B1D072C7BB47A3A0FEB06C378542B48D0D3AD81710AD63A25AD77749` |
| SSDEEP | `49152:LEGt4j6k+oVp9pLQ578c0dTr6VHXNR2OdgE4fxTwdxTbjH54g/XKjFaWNFYfnPiB:Tq6wrMCc05mJXNRVdl4fxTwj5ZXKj9N3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_d55a97b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d55a97b3c7eaba8b619a790ea9bac46ce8d48cf7553a970f00ef18a1107ff9a5"
    family = "unknown"
    file_name = "d55a97b3c7eaba8b619a790ea9bac46ce8d48cf7553a970f00ef18a1107ff9a5.exe"
    file_type = "exe"
    first_seen = "2026-08-28 03:36:09"
  condition:
    hash.sha256(0, filesize) == "d55a97b3c7eaba8b619a790ea9bac46ce8d48cf7553a970f00ef18a1107ff9a5"
}
```

### Sample 72: `06574a1f939dc996`

| Field | Value |
|---|---|
| SHA-256 | `06574a1f939dc99681ab9f9df1ef7c4e072de301d023ddd947a72e1b868c7c08` |
| Family label | `unknown` |
| File name | `dlr.ppc` |
| File type | `elf` |
| First seen | `2026-08-28 03:31:08` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee5dbf4144a9a5ab4094dd967a9afd0d` |
| SHA-1 | `96d4e6e1434d95ce2cb5750e71c86fbdf3e56fef` |
| SHA-256 | `06574a1f939dc99681ab9f9df1ef7c4e072de301d023ddd947a72e1b868c7c08` |
| SHA3-384 | `629077d9704da20822bf8ac1007959e00746baaecb414c6e7af3695446d500eb4c20101dd7807bd5ebecd6f1ecb9081f` |
| TLSH | `T1DB926B5A3B108963F48705745D3FABD9B37D842400F1254DA28A8B05C178FEE6B0BBDE` |
| SSDEEP | `384:W4Y3qdu+hJug/24UoqQkd68XDsdEIYSwwV55Vrf/25gQzAx3358pxH40u4O08QT:W4NdbThqQEzXD4EIjww35xEpxHpu4G8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_06574a1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06574a1f939dc99681ab9f9df1ef7c4e072de301d023ddd947a72e1b868c7c08"
    family = "unknown"
    file_name = "dlr.ppc"
    file_type = "elf"
    first_seen = "2026-08-28 03:31:08"
  condition:
    hash.sha256(0, filesize) == "06574a1f939dc99681ab9f9df1ef7c4e072de301d023ddd947a72e1b868c7c08"
}
```

### Sample 73: `6fd06127cd5573a4`

| Field | Value |
|---|---|
| SHA-256 | `6fd06127cd5573a4f884e3c7a4425f56c1e277109bc86ceabcf57b524afd0075` |
| Family label | `VIPKeylogger` |
| File name | `INV09876545678HLK.bat` |
| File type | `exe` |
| First seen | `2026-08-28 03:20:20` |
| Reporter | `threatcat_ch` |
| Tags | `exe, VIPKeylogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a67659e909fb0f8caedd7cddcdfae640` |
| SHA-1 | `6c52353efc6174037879ed5096cb79f475fe4693` |
| SHA-256 | `6fd06127cd5573a4f884e3c7a4425f56c1e277109bc86ceabcf57b524afd0075` |
| SHA3-384 | `abc555ccc28dc7aa311853efec6d7f519cb3da526ac9db73f0d81baa0cadfaad8dad3e0f5cda9e9e5371b99b2ec6cc89` |
| IMPHASH | `9be4f90f50c714bc00cc8beb2e137299` |
| TLSH | `T10CD4E161BA9190E0C5B55A72E92BD53725367C2A1630911F2338BF3B3FFD683C939A05` |
| SSDEEP | `12288:arZbgKl9ykCxeIckh1WPSETCiv4l+DNZRozLHqSPVAeL+2enZ:amKXykCxeJPS0C84sqzLKYGeL+2enZ` |
| ICON-DHASH | `70f0d292ecf2f030` |

#### Technical Assessment

- The sample is tracked as `VIPKeylogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VIPKeylogger_073_6fd06127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fd06127cd5573a4f884e3c7a4425f56c1e277109bc86ceabcf57b524afd0075"
    family = "VIPKeylogger"
    file_name = "INV09876545678HLK.bat"
    file_type = "exe"
    first_seen = "2026-08-28 03:20:20"
  condition:
    hash.sha256(0, filesize) == "6fd06127cd5573a4f884e3c7a4425f56c1e277109bc86ceabcf57b524afd0075"
}
```

### Sample 74: `ba94e9c02b5a75e7`

| Field | Value |
|---|---|
| SHA-256 | `ba94e9c02b5a75e7d5ff6d030aa8800a486e593a311af0c35b1e21ddabe33929` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-28 03:03:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7433cac996bb08884493dc5c2d8d8393` |
| SHA-1 | `0fdc177ad449a88b26716bd5c3de187278c08fa6` |
| SHA-256 | `ba94e9c02b5a75e7d5ff6d030aa8800a486e593a311af0c35b1e21ddabe33929` |
| SHA3-384 | `7e5aa2acf12f52edd74b6686e600c7fa697b1fe51bbc29f6b6627865efed71b2f78e85500992676fa9d6e59de5adb43a` |
| TLSH | `T19AC28D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:F8vCB+25j6es8Ry9FYpMSUpi+20qUpi+20YQX:F8l25JUd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_ba94e9c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba94e9c02b5a75e7d5ff6d030aa8800a486e593a311af0c35b1e21ddabe33929"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 03:03:46"
  condition:
    hash.sha256(0, filesize) == "ba94e9c02b5a75e7d5ff6d030aa8800a486e593a311af0c35b1e21ddabe33929"
}
```

### Sample 75: `1a8ec15eece1741b`

| Field | Value |
|---|---|
| SHA-256 | `1a8ec15eece1741be0c93bcd0b9fac0a4c3b76f8f5eae3547586588e67f198fc` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-28 03:01:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05497aaf222b0d999831a2a58a112d1e` |
| SHA-1 | `849b41c333634437a05f5bbc0774ad5e69f0e740` |
| SHA-256 | `1a8ec15eece1741be0c93bcd0b9fac0a4c3b76f8f5eae3547586588e67f198fc` |
| SHA3-384 | `431b367ce0eed687ecf10d31a7c63d3d0d30df9403a248662561a9e780f8eb545177c082a23f5c1bf529452ae1fb0045` |
| TLSH | `T132C27D966A867C44BEC94B3E4CBD2B1D6DF5C3D1224942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:5k8vCB+25j6es8RZ9FYpMSUpi+20qUpi+20YQX:5k8l25J/d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_1a8ec15e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a8ec15eece1741be0c93bcd0b9fac0a4c3b76f8f5eae3547586588e67f198fc"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 03:01:49"
  condition:
    hash.sha256(0, filesize) == "1a8ec15eece1741be0c93bcd0b9fac0a4c3b76f8f5eae3547586588e67f198fc"
}
```

### Sample 76: `12da29fe8078e3fd`

| Field | Value |
|---|---|
| SHA-256 | `12da29fe8078e3fd582ad065217fd130e5ad6a9869b691fdb228679b94a7eaa7` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-28 02:57:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7529d7f3c7c6d682d6af67c878df864` |
| SHA-1 | `127020908a0973d320bd9f89a6136dce73af4443` |
| SHA-256 | `12da29fe8078e3fd582ad065217fd130e5ad6a9869b691fdb228679b94a7eaa7` |
| SHA3-384 | `4c703118d9e688f7beb23f7832879f74de2bcb4af246a4c537171f3cc932fc464b04cdabf9da342667c7ab2b3cfc66f4` |
| TLSH | `T198235B512A857C14AA98C8371D7F2F0CB9A943E6324452DE7FCF3CF68C4AA9DA10961D` |
| SSDEEP | `768:NeFWzZx5K9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Mkzdcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_12da29fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12da29fe8078e3fd582ad065217fd130e5ad6a9869b691fdb228679b94a7eaa7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 02:57:35"
  condition:
    hash.sha256(0, filesize) == "12da29fe8078e3fd582ad065217fd130e5ad6a9869b691fdb228679b94a7eaa7"
}
```

### Sample 77: `dba5d7c1fe4c4f1c`

| Field | Value |
|---|---|
| SHA-256 | `dba5d7c1fe4c4f1c8fbfc7d4f2392499c79e4fe381b8a89b6ee4e3df34502bf5` |
| Family label | `Mirai` |
| File name | `dba5d7c1fe4c4f1c8fbfc7d4f2392499c79e4fe381b8a89b6ee4e3df34502bf5.elf` |
| File type | `elf` |
| First seen | `2026-08-28 02:56:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a23aaba3390579494d55bc47d128742` |
| SHA-1 | `64fe3cf507bbf009ac82c49b8eae6489d1e56cd5` |
| SHA-256 | `dba5d7c1fe4c4f1c8fbfc7d4f2392499c79e4fe381b8a89b6ee4e3df34502bf5` |
| SHA3-384 | `086c2b996be576ba70d972554c620805938f445b98e433d060e7ee30f34bfb7ebe30fc66f4ce8d502cda301c15762031` |
| TLSH | `T132A69E4BF4A604BDC4BAC870875FE2B2AE3438980150657B7A5456723F76F302B6AFD1` |
| SSDEEP | `98304:CrfAVfSukDI7rHkONESzhsmaqp/EHeF0xa44mPIyb+TJyNRSawGqR6wmHDLH91k9:MZdPcyNRpNwmHDLH9/ES30UGAHc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_dba5d7c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dba5d7c1fe4c4f1c8fbfc7d4f2392499c79e4fe381b8a89b6ee4e3df34502bf5"
    family = "Mirai"
    file_name = "dba5d7c1fe4c4f1c8fbfc7d4f2392499c79e4fe381b8a89b6ee4e3df34502bf5.elf"
    file_type = "elf"
    first_seen = "2026-08-28 02:56:04"
  condition:
    hash.sha256(0, filesize) == "dba5d7c1fe4c4f1c8fbfc7d4f2392499c79e4fe381b8a89b6ee4e3df34502bf5"
}
```

### Sample 78: `f7eb82050604926b`

| Field | Value |
|---|---|
| SHA-256 | `f7eb82050604926b372ed7df21b9df90aa970eb20daec5d75d492a427a56e0d3` |
| Family label | `RemusStealer` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-08-28 02:52:10` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f600e2ba36d14fb98e336ef4c5e316f` |
| SHA-1 | `4a66f741c17567706b773b664f907b75ca4f284e` |
| SHA-256 | `f7eb82050604926b372ed7df21b9df90aa970eb20daec5d75d492a427a56e0d3` |
| SHA3-384 | `18ef6bd6a9783d49ebfa95c7ef7434f85d1de12f10938a4e79cb8208b9f9a361f11c20b836f15eb967cbd01ad735a7e9` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T15B064A03BB8491A4C8A7C638D7B69761B631BC5F873473D72E546A752E363D02E38B18` |
| GIMPHASH | `5b47c4043dcd0d05490b897a39e72c8e4bd0c8a0e2f3a1777884a2a135836dfb` |
| SSDEEP | `49152:gGUrL3IwEIT0FVZbStw5lD0Ougvnc/tD107wA:gYSW3blH7FF` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_078_f7eb8205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7eb82050604926b372ed7df21b9df90aa970eb20daec5d75d492a427a56e0d3"
    family = "RemusStealer"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-28 02:52:10"
  condition:
    hash.sha256(0, filesize) == "f7eb82050604926b372ed7df21b9df90aa970eb20daec5d75d492a427a56e0d3"
}
```

### Sample 79: `314c048ccfd30945`

| Field | Value |
|---|---|
| SHA-256 | `314c048ccfd30945314dea4c3764e7bffde5a1d4ac07966f4e05bb9d2c50e615` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-28 02:45:43` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b78c9d192d4aae2e5c2d7677b159dc36` |
| SHA-1 | `1b5e79f3aa6bd797d0c0f05e8929b14b616cadef` |
| SHA-256 | `314c048ccfd30945314dea4c3764e7bffde5a1d4ac07966f4e05bb9d2c50e615` |
| SHA3-384 | `aa1fefcdb064afe7eb9a844db80e3b1cf256a0cf1218334834c9e66030a4b18366671886da92e0d49fb60c84b120ae3b` |
| TLSH | `T1563186DE15301B365002CE8EB3A37448B68D95FB6C5FCBE4D9484DAC92893CCF562B49` |
| SSDEEP | `24:a+xaYMg4awB2ZFFq7QAh1BJH3cECDCDsDNY7HxV7:a+xaJBYFFqN1BJX1CG4hY7RV7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_314c048c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "314c048ccfd30945314dea4c3764e7bffde5a1d4ac07966f4e05bb9d2c50e615"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-28 02:45:43"
  condition:
    hash.sha256(0, filesize) == "314c048ccfd30945314dea4c3764e7bffde5a1d4ac07966f4e05bb9d2c50e615"
}
```

### Sample 80: `33cc64e622a224df`

| Field | Value |
|---|---|
| SHA-256 | `33cc64e622a224df172252aad00278e8f085925414d5fac4e821f5f7596e8c8c` |
| Family label | `QuasarRAT` |
| File name | `461E43DA65ED883C46B72C095FD72A3E.exe` |
| File type | `exe` |
| First seen | `2026-08-28 02:45:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, QuasarRAT, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `461e43da65ed883c46b72c095fd72a3e` |
| SHA-1 | `9e2535e029c887dc961f11690b3c59ed4ee936ac` |
| SHA-256 | `33cc64e622a224df172252aad00278e8f085925414d5fac4e821f5f7596e8c8c` |
| SHA3-384 | `eaf87ff448dd778822f45525aef51098690af127976fab5ad82169acd0a529c0c36fac0fc0bc6047ba75ebbdc06869c1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1ED96382439FA501AB173EFAA8BE479EADA6FB7733B07645D105003864723981DEC153E` |
| SSDEEP | `49152:mmsRRBvoJy/Yb/0m+4MtgRQekNjzU7XFO9U9M7uVlLRGMlC7gjJy8Tq8YyG3:` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_080_33cc64e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33cc64e622a224df172252aad00278e8f085925414d5fac4e821f5f7596e8c8c"
    family = "QuasarRAT"
    file_name = "461E43DA65ED883C46B72C095FD72A3E.exe"
    file_type = "exe"
    first_seen = "2026-08-28 02:45:09"
  condition:
    hash.sha256(0, filesize) == "33cc64e622a224df172252aad00278e8f085925414d5fac4e821f5f7596e8c8c"
}
```

### Sample 81: `86c0807408f58802`

| Field | Value |
|---|---|
| SHA-256 | `86c0807408f58802a8d42a3ffb4a0c1c52b7ea992da162207a3de31c9c9d0f3a` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-28 02:39:37` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80bb7b359fd8df3b1d2439bdb5ff6f3d` |
| SHA-256 | `86c0807408f58802a8d42a3ffb4a0c1c52b7ea992da162207a3de31c9c9d0f3a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_86c08074
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c0807408f58802a8d42a3ffb4a0c1c52b7ea992da162207a3de31c9c9d0f3a"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 02:39:37"
  condition:
    hash.sha256(0, filesize) == "86c0807408f58802a8d42a3ffb4a0c1c52b7ea992da162207a3de31c9c9d0f3a"
}
```

### Sample 82: `cb2ad0ac4f406026`

| Field | Value |
|---|---|
| SHA-256 | `cb2ad0ac4f4060268b24b28f7e7798ebe5da6e7c3fbf05939ba2277d563a32e9` |
| Family label | `unknown` |
| File name | `dlr.mpsl` |
| File type | `elf` |
| First seen | `2026-08-28 02:37:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc6d3680aa2eb51cb57f43a28e9065a1` |
| SHA-1 | `ab7ca1f671684ea31684e65343c432dd1cf1fcc9` |
| SHA-256 | `cb2ad0ac4f4060268b24b28f7e7798ebe5da6e7c3fbf05939ba2277d563a32e9` |
| SHA3-384 | `d7ac0bd62ff155c03b9e55f1b1b103714550ac80f36033ce6c18ad85e573838172a1c352c7cce62e69b3e263bb246ddd` |
| TLSH | `T10FB24A9A6FA10EF6C02FCC338A5D5758267C289873A10BFE4C69E424718E1C63BC3975` |
| SSDEEP | `384:m1CLD1wnXrN0/4Dpqpffq07OeBjfTzGLUw0D03+eNWWybxpWSysaqSO0k:GP0/4D+ffceZbSBEpWjsBSG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_cb2ad0ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb2ad0ac4f4060268b24b28f7e7798ebe5da6e7c3fbf05939ba2277d563a32e9"
    family = "unknown"
    file_name = "dlr.mpsl"
    file_type = "elf"
    first_seen = "2026-08-28 02:37:41"
  condition:
    hash.sha256(0, filesize) == "cb2ad0ac4f4060268b24b28f7e7798ebe5da6e7c3fbf05939ba2277d563a32e9"
}
```

### Sample 83: `2feb91cf421d8e7c`

| Field | Value |
|---|---|
| SHA-256 | `2feb91cf421d8e7c564b65e27315ae3c0b2f0df2496b97dfbaabc5ef216dbae4` |
| Family label | `unknown` |
| File name | `2feb91cf421d8e7c564b65e27315ae3c0b2f0df2496b97dfbaabc5ef216dbae4.bin` |
| File type | `exe` |
| First seen | `2026-08-28 02:34:45` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1795be3c0a052ba3bf15e61e905f4f7d` |
| SHA-1 | `449d3009a7dbfd3b0da4c780b62fc43f1fb9c4c5` |
| SHA-256 | `2feb91cf421d8e7c564b65e27315ae3c0b2f0df2496b97dfbaabc5ef216dbae4` |
| SHA3-384 | `da72beceba5d20a4790a3ecc30ec9fa5e808c8bc04bcf81b6579eb26c529c098ee3d19e0a344ebbd1c20b182bb8df24e` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T1F4169D13FC81D1A5D9A7923595B9D191A630B86A8B3537D32F00FA7A1F363E02F78358` |
| GIMPHASH | `e7fd180c4b468719da9e1021525baa753281ecc8c6745628eac3ceb4ab90bd7a` |
| SSDEEP | `98304:inUZwfTKwdn4mhveqFpfUnBO3X9mYfE80TG71KMb15:inzhTFpAOXEisMz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_2feb91cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2feb91cf421d8e7c564b65e27315ae3c0b2f0df2496b97dfbaabc5ef216dbae4"
    family = "unknown"
    file_name = "2feb91cf421d8e7c564b65e27315ae3c0b2f0df2496b97dfbaabc5ef216dbae4.bin"
    file_type = "exe"
    first_seen = "2026-08-28 02:34:45"
  condition:
    hash.sha256(0, filesize) == "2feb91cf421d8e7c564b65e27315ae3c0b2f0df2496b97dfbaabc5ef216dbae4"
}
```

### Sample 84: `7a0bdad6fac316f1`

| Field | Value |
|---|---|
| SHA-256 | `7a0bdad6fac316f1fcf006a02096b38773b8112b226ab1b8c6867dac48dcbc0b` |
| Family label | `unknown` |
| File name | `dlr.arm7` |
| File type | `elf` |
| First seen | `2026-08-28 02:33:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff85da9c16776e1ff7d42116c93ca956` |
| SHA-1 | `a519a5c7daafb80637fc6da4cc6d8bcc36213bfe` |
| SHA-256 | `7a0bdad6fac316f1fcf006a02096b38773b8112b226ab1b8c6867dac48dcbc0b` |
| SHA3-384 | `4ebaf2b675eabf90458c83302ce80d0a7f2542dcb64dae88d596096a9578241eae7d98b443f3f4ac6266dee3465cb94f` |
| TLSH | `T1A6A23AADA860E92AC9E532BAB77FD15D33132778E3F6704289268774234E0190F7ED51` |
| SSDEEP | `384:CN6y4NCKOj0TcglzjVcCKcXKGG67EYU7jodF6gXx4ei4O07C:+6yI7Oj0TxvGLYUPodFcp4lC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_7a0bdad6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a0bdad6fac316f1fcf006a02096b38773b8112b226ab1b8c6867dac48dcbc0b"
    family = "unknown"
    file_name = "dlr.arm7"
    file_type = "elf"
    first_seen = "2026-08-28 02:33:40"
  condition:
    hash.sha256(0, filesize) == "7a0bdad6fac316f1fcf006a02096b38773b8112b226ab1b8c6867dac48dcbc0b"
}
```

### Sample 85: `6aaff3d4ea521cbd`

| Field | Value |
|---|---|
| SHA-256 | `6aaff3d4ea521cbd426be4a23ecdb21063eb6afd9496fb83803c3c310b87ed39` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-08-28 02:31:43` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `828ffbdf7f3fd44a6e3dac1a79c0214c` |
| SHA-256 | `6aaff3d4ea521cbd426be4a23ecdb21063eb6afd9496fb83803c3c310b87ed39` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_6aaff3d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aaff3d4ea521cbd426be4a23ecdb21063eb6afd9496fb83803c3c310b87ed39"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 02:31:43"
  condition:
    hash.sha256(0, filesize) == "6aaff3d4ea521cbd426be4a23ecdb21063eb6afd9496fb83803c3c310b87ed39"
}
```

### Sample 86: `1738f890d5686b1c`

| Field | Value |
|---|---|
| SHA-256 | `1738f890d5686b1c17b43166659643dde6ff57fc9ed4143dc9801ae331036273` |
| Family label | `WannaCry` |
| File name | `1738f890d5686b1c17b43166659643dde6ff57fc9ed4143dc9801ae331036273` |
| File type | `exe` |
| First seen | `2026-08-28 02:15:13` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a4d5ab74aab4d6b8c24edb29d4b6d64` |
| SHA-1 | `4f6839725a41eee6426b1aeed61e7b27e40515d5` |
| SHA-256 | `1738f890d5686b1c17b43166659643dde6ff57fc9ed4143dc9801ae331036273` |
| SHA3-384 | `c77d8f22717f4c7ebb9d1b7cd6a3cc419cab87c8373f22d90ebada69a06954643833399006c0744f2dbbb8539702bf6e` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1D8363358726CA2FCE0450EB444B38E16F7B37C6567BA4B0F8780866B0E13B5BAF94751` |
| SSDEEP | `98304:DyDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2s:DyDqPe1Cxcxk3ZAEUadzR8yc4` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_086_1738f890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1738f890d5686b1c17b43166659643dde6ff57fc9ed4143dc9801ae331036273"
    family = "WannaCry"
    file_name = "1738f890d5686b1c17b43166659643dde6ff57fc9ed4143dc9801ae331036273"
    file_type = "exe"
    first_seen = "2026-08-28 02:15:13"
  condition:
    hash.sha256(0, filesize) == "1738f890d5686b1c17b43166659643dde6ff57fc9ed4143dc9801ae331036273"
}
```

### Sample 87: `27d22c374ffa52ab`

| Field | Value |
|---|---|
| SHA-256 | `27d22c374ffa52ab63cfb05c09b7925100f6ccd0eb00e314cf8f20be231da250` |
| Family label | `QuasarRAT` |
| File name | `3304B81686F03893B0A931F23C6665BA.exe` |
| File type | `exe` |
| First seen | `2026-08-28 02:15:12` |
| Reporter | `abuse_ch` |
| Tags | `exe, QuasarRAT, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3304b81686f03893b0a931f23c6665ba` |
| SHA-1 | `ce1f829dec06ac8558bc4d2a9973ac85cba073c0` |
| SHA-256 | `27d22c374ffa52ab63cfb05c09b7925100f6ccd0eb00e314cf8f20be231da250` |
| SHA3-384 | `e59f1697de7348e60867894ade33b1cf2955a17fd1cf0310a1e56cc4ff0ffd5e7fd98a166b722e421aa0e57e4cb16012` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1AE96382439FA501AB173EFAA8BE479EADA6FB7733B07645D109003864723981DDC153E` |
| SSDEEP | `49152:1ERqKorLZmuVbDNxzBQuLcv8efwUvnUSUqAhe2acJotLnmmTvQDKIL:` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_087_27d22c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27d22c374ffa52ab63cfb05c09b7925100f6ccd0eb00e314cf8f20be231da250"
    family = "QuasarRAT"
    file_name = "3304B81686F03893B0A931F23C6665BA.exe"
    file_type = "exe"
    first_seen = "2026-08-28 02:15:12"
  condition:
    hash.sha256(0, filesize) == "27d22c374ffa52ab63cfb05c09b7925100f6ccd0eb00e314cf8f20be231da250"
}
```

### Sample 88: `178b290d24527fda`

| Field | Value |
|---|---|
| SHA-256 | `178b290d24527fda41dcaa0960b289e024e4fac39b96a3d8aebf9be14f51a635` |
| Family label | `QuasarRAT` |
| File name | `3135BF9C620AEA1463C948D1BE481493.exe` |
| File type | `exe` |
| First seen | `2026-08-28 02:15:08` |
| Reporter | `abuse_ch` |
| Tags | `exe, QuasarRAT, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3135bf9c620aea1463c948d1be481493` |
| SHA-1 | `3de514f7e96a69e607258c05c68ddc58145a1531` |
| SHA-256 | `178b290d24527fda41dcaa0960b289e024e4fac39b96a3d8aebf9be14f51a635` |
| SHA3-384 | `f0c9779f37067f078972cec0ccabb7b48e98a0b9130619e098ee8fa04d76979213ea54bb088a286b96e7bb4fd5f85f61` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T10096382439FA501AB173EFAA8BE478EADA6FB7733B07645D105103864723981DEC153E` |
| SSDEEP | `49152:H3ZdRfG1Cl0xD8IJuWdzbZlO6xXdTEyEMyE8FR9pmFymKi2Ofp6F8RKho7q:` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_088_178b290d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "178b290d24527fda41dcaa0960b289e024e4fac39b96a3d8aebf9be14f51a635"
    family = "QuasarRAT"
    file_name = "3135BF9C620AEA1463C948D1BE481493.exe"
    file_type = "exe"
    first_seen = "2026-08-28 02:15:08"
  condition:
    hash.sha256(0, filesize) == "178b290d24527fda41dcaa0960b289e024e4fac39b96a3d8aebf9be14f51a635"
}
```

### Sample 89: `2e74c6a004d7cc73`

| Field | Value |
|---|---|
| SHA-256 | `2e74c6a004d7cc7323eaddc86da7c52f21deafc9e3a055c67956c44cb47b8220` |
| Family label | `unknown` |
| File name | `2e74c6a004d7cc7323eaddc86da7c52f21deafc9e3a055c67956c44cb47b8220.exe` |
| File type | `exe` |
| First seen | `2026-08-28 01:59:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b0f7e11581ef55883042a716ac2497a` |
| SHA-1 | `a5a8a6ff59d327592a2a02320dcc0a53905710b4` |
| SHA-256 | `2e74c6a004d7cc7323eaddc86da7c52f21deafc9e3a055c67956c44cb47b8220` |
| SHA3-384 | `f606bbd8704a7027ff301e0f66c7a0a9c9d4c68f1f5efaa09fce1dffa7450c8a9b60028190d33914042f369ffd8185f7` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T135D52398BCF11AB4D83AC3F68E82F5ADB01E3B9147714D573ACC59008D16A9C6C3A779` |
| SSDEEP | `49152:PR+wH1WKxgrBPDNtKzrVYkSu4cOrCLs4tin+CfsnSo+BIAqDdAD+a:1HgPhtKzr+kSu4vzuYFcADl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_2e74c6a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e74c6a004d7cc7323eaddc86da7c52f21deafc9e3a055c67956c44cb47b8220"
    family = "unknown"
    file_name = "2e74c6a004d7cc7323eaddc86da7c52f21deafc9e3a055c67956c44cb47b8220.exe"
    file_type = "exe"
    first_seen = "2026-08-28 01:59:36"
  condition:
    hash.sha256(0, filesize) == "2e74c6a004d7cc7323eaddc86da7c52f21deafc9e3a055c67956c44cb47b8220"
}
```

### Sample 90: `e36c6e71d1149b0d`

| Field | Value |
|---|---|
| SHA-256 | `e36c6e71d1149b0d5e7756446ae57c1c9132839aea012d3bb7e7e519bfa6128d` |
| Family label | `unknown` |
| File name | `94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00.sh` |
| File type | `unknown` |
| First seen | `2026-08-28 01:45:36` |
| Reporter | `roely15mol` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c6a75ce6abcb3e9778ab0a89c4c51c6` |
| SHA-256 | `e36c6e71d1149b0d5e7756446ae57c1c9132839aea012d3bb7e7e519bfa6128d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_e36c6e71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e36c6e71d1149b0d5e7756446ae57c1c9132839aea012d3bb7e7e519bfa6128d"
    family = "unknown"
    file_name = "94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00.sh"
    file_type = "unknown"
    first_seen = "2026-08-28 01:45:36"
  condition:
    hash.sha256(0, filesize) == "e36c6e71d1149b0d5e7756446ae57c1c9132839aea012d3bb7e7e519bfa6128d"
}
```

### Sample 91: `f2626a8c7efee8f1`

| Field | Value |
|---|---|
| SHA-256 | `f2626a8c7efee8f1e6d301bc928d02aab6a3d7e3ad51e58363d79ce4648e55c7` |
| Family label | `unknown` |
| File name | `dlr.sh4` |
| File type | `elf` |
| First seen | `2026-08-28 01:41:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26cf01cc60a6bd2f7e03f0be12fe261c` |
| SHA-1 | `1cf6d9cc60c0720bcbc910d3e1089c84502492e6` |
| SHA-256 | `f2626a8c7efee8f1e6d301bc928d02aab6a3d7e3ad51e58363d79ce4648e55c7` |
| SHA3-384 | `5a58adae8d380d6bf9e75cfc2dd2002355fefc5890b592cbd35ecbeae45cfdc17f7b7132c2c14ead05a37d7516a8fa4e` |
| TLSH | `T1F0828E929860ED5BFD1892B4E098DDBE534334611E9B6CF2B0C1EC20504F7787ACA3E9` |
| SSDEEP | `384:bpka4ktdp7zZ86xaZRlkcXGhiTE2Ss4049b:bpka4knx18bZRlkcXOh2SsJ49` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_f2626a8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2626a8c7efee8f1e6d301bc928d02aab6a3d7e3ad51e58363d79ce4648e55c7"
    family = "unknown"
    file_name = "dlr.sh4"
    file_type = "elf"
    first_seen = "2026-08-28 01:41:43"
  condition:
    hash.sha256(0, filesize) == "f2626a8c7efee8f1e6d301bc928d02aab6a3d7e3ad51e58363d79ce4648e55c7"
}
```

### Sample 92: `8cf074380ec4d971`

| Field | Value |
|---|---|
| SHA-256 | `8cf074380ec4d971c134f93b0fb94239eaea55f4f2047a48d75fc21fd827a75e` |
| Family label | `unknown` |
| File name | `8cf074380ec4d971c134f93b0fb94239eaea55f4f2047a48d75fc21fd827a75e.elf` |
| File type | `elf` |
| First seen | `2026-08-28 01:31:35` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afb7a03c5628108ec0337cb22d917460` |
| SHA-1 | `bd72b944afb8da3f4b3d769a0e74adf26fb5b5e2` |
| SHA-256 | `8cf074380ec4d971c134f93b0fb94239eaea55f4f2047a48d75fc21fd827a75e` |
| SHA3-384 | `32fee3a3823b6dba05e26fc9a8a6b36a67625d5bae3ea797bb83710f4665c0886bd28b5974bbcc0629ac8e9e82c31086` |
| TLSH | `T1B6822B69D4629973F4500076130CE3F2A29EBBB8132F4487F7D18CB6B9BD2D15194B5B` |
| TELFHASH | `t17eb011028c2a8c30b0e0b80ba00820028a32082308a08cc202328300bbc00b2a328222` |
| SSDEEP | `384:fAojBBBBBrOt0GmKejddRsTDtGJ2MS55JXwGLaRqP:rjBBBBBrOzK3RsT8suBO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_8cf07438
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cf074380ec4d971c134f93b0fb94239eaea55f4f2047a48d75fc21fd827a75e"
    family = "unknown"
    file_name = "8cf074380ec4d971c134f93b0fb94239eaea55f4f2047a48d75fc21fd827a75e.elf"
    file_type = "elf"
    first_seen = "2026-08-28 01:31:35"
  condition:
    hash.sha256(0, filesize) == "8cf074380ec4d971c134f93b0fb94239eaea55f4f2047a48d75fc21fd827a75e"
}
```

### Sample 93: `088f624bf51e8c9d`

| Field | Value |
|---|---|
| SHA-256 | `088f624bf51e8c9db46a345c3a85df89f5729a226da1846f70aae91b9b44ffe7` |
| Family label | `Gafgyt` |
| File name | `a-r.m-6.SNOOPY` |
| File type | `elf` |
| First seen | `2026-08-28 01:10:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60c139e7d57db9cc626510a6eaa2e0b8` |
| SHA-1 | `b3939bdb57a3a4a72037daaa4fc2e105bc58dbaa` |
| SHA-256 | `088f624bf51e8c9db46a345c3a85df89f5729a226da1846f70aae91b9b44ffe7` |
| SHA3-384 | `77e91987d5ef764b4372f8f0228c9b5c7b1d085f165c4d34fa1b9a8a85620db6fdf015f40ff0b30e4f28a02fdbf2b562` |
| TLSH | `T1F1B32801D5508B67C2D2277AB79F825D33332BA8979B33125A24BFB42BC27DD1E39521` |
| TELFHASH | `t1ee11dd12a1fa86182bf65924ac7c47f115502a2373867e717f0ec6c4593b003b979ddb` |
| SSDEEP | `3072:b6an17WtsWhdgYJk0D6mbPbmTQOWsXAOn:Wan17WPJk0D6ibmTQOWCAOn` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_093_088f624b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "088f624bf51e8c9db46a345c3a85df89f5729a226da1846f70aae91b9b44ffe7"
    family = "Gafgyt"
    file_name = "a-r.m-6.SNOOPY"
    file_type = "elf"
    first_seen = "2026-08-28 01:10:40"
  condition:
    hash.sha256(0, filesize) == "088f624bf51e8c9db46a345c3a85df89f5729a226da1846f70aae91b9b44ffe7"
}
```

### Sample 94: `deb1c78ca154989f`

| Field | Value |
|---|---|
| SHA-256 | `deb1c78ca154989f89979b9b0126f3781a0c6ac8cad6ef121598a4cceb7bc6f0` |
| Family label | `Gafgyt` |
| File name | `s-h.4-.SNOOPY` |
| File type | `elf` |
| First seen | `2026-08-28 01:10:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbe0113968931a07a040bd34ec4b1cb8` |
| SHA-1 | `13b7be9cea21f6bc8bafeb7947ccc87b74a7d219` |
| SHA-256 | `deb1c78ca154989f89979b9b0126f3781a0c6ac8cad6ef121598a4cceb7bc6f0` |
| SHA3-384 | `121266aea3327e3371f4ee633678c7410c0c02b6aa54cc0333f95b71c96bc985565962169c8eb346de93ac1013e17850` |
| TLSH | `T113734A47AD629FB7C146AAB525A759300723B8215F0F1B89713DAAF8470F8CDB80F764` |
| TELFHASH | `t1f411cc5271fa895d2bf249249cbc43b4265026237352beb5bf0ec6d45937002b979e8f` |
| SSDEEP | `1536:kAmbedEfIKy1BABWWNxiEVN/C63yzTN7mj9VqYLe8f26e:v+eefvyoWWF/B3Mhmj9VqYq8f26e` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_094_deb1c78c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "deb1c78ca154989f89979b9b0126f3781a0c6ac8cad6ef121598a4cceb7bc6f0"
    family = "Gafgyt"
    file_name = "s-h.4-.SNOOPY"
    file_type = "elf"
    first_seen = "2026-08-28 01:10:38"
  condition:
    hash.sha256(0, filesize) == "deb1c78ca154989f89979b9b0126f3781a0c6ac8cad6ef121598a4cceb7bc6f0"
}
```

### Sample 95: `30cb25122bca4c47`

| Field | Value |
|---|---|
| SHA-256 | `30cb25122bca4c471c18cf6771a4663c39745460ba6d37b32d372e00657e66eb` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-28 00:42:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `711303ae7da812fbe9b7b8e87877be6b` |
| SHA-1 | `ee17d52b0c482d850c66b1902e4b72b3a60b68eb` |
| SHA-256 | `30cb25122bca4c471c18cf6771a4663c39745460ba6d37b32d372e00657e66eb` |
| SHA3-384 | `a89fdf1625b62fde489b37b632cd2345308690be1614a3ddd2bcfc47fd4782be3255d0ed0b7473264bb6416a28902094` |
| TLSH | `T1B3C28D966A867C44BDC94A3E4CBD2B1D6DF4C3E1324942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:i8vCB+25j6es8RDqC9FYpMSUpi+20qUpi+20YQX:i8l25JOkd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_30cb2512
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30cb25122bca4c471c18cf6771a4663c39745460ba6d37b32d372e00657e66eb"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 00:42:43"
  condition:
    hash.sha256(0, filesize) == "30cb25122bca4c471c18cf6771a4663c39745460ba6d37b32d372e00657e66eb"
}
```

### Sample 96: `4e20a6ab95b60f31`

| Field | Value |
|---|---|
| SHA-256 | `4e20a6ab95b60f31d9e926a62800d03c2af89b2efd96c782aa022dca6ffa4a59` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-28 00:32:30` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8fcac4b9ee4c7c791961a975f5e7785` |
| SHA-1 | `5674f7b44bef79469bc3b79b7db320b819f73dd1` |
| SHA-256 | `4e20a6ab95b60f31d9e926a62800d03c2af89b2efd96c782aa022dca6ffa4a59` |
| SHA3-384 | `ca34ccb3d3852a7fe7a2bdb770c77c32996f6493c8cbe5c47f09cde53a7b12c41a88fd41d60284d6ee39cacea49fd32e` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T13D07123BB6AB653DF0ED0A353A72A662543B6E1174169C06D6E4E84CCF350B03D3F686` |
| SSDEEP | `196608:WPx1tOIK9/zLcRZYvmAPDsvqPmyA/3uUH4/cI:W5OBEZoTJPmy+3XW` |
| ICON-DHASH | `23dca68ad8e4d423` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_4e20a6ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e20a6ab95b60f31d9e926a62800d03c2af89b2efd96c782aa022dca6ffa4a59"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 00:32:30"
  condition:
    hash.sha256(0, filesize) == "4e20a6ab95b60f31d9e926a62800d03c2af89b2efd96c782aa022dca6ffa4a59"
}
```

### Sample 97: `db4a45d88c943be3`

| Field | Value |
|---|---|
| SHA-256 | `db4a45d88c943be3f60bf216bb6ac8a2d3b70dfa13e9669e402f11e2aaea1b74` |
| Family label | `unknown` |
| File name | `db4a45d88c943be3f60bf216bb6ac8a2d3b70dfa13e9669e402f11e2aaea1b74.bin` |
| File type | `exe` |
| First seen | `2026-08-28 00:25:09` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bbbf6e8040d137c142bbf1775be770c` |
| SHA-1 | `0d5f36f78a1cbf922f9e33c348c5693e93e24c06` |
| SHA-256 | `db4a45d88c943be3f60bf216bb6ac8a2d3b70dfa13e9669e402f11e2aaea1b74` |
| SHA3-384 | `41a3c96bf4066ce52dd8233cffbdce18caf04b0327e12301e370f7b38bde8fb656e3da8795fa79420f0e226fc185ddb9` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T152366A03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaab:uc3XND1aJrCOkb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_db4a45d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db4a45d88c943be3f60bf216bb6ac8a2d3b70dfa13e9669e402f11e2aaea1b74"
    family = "unknown"
    file_name = "db4a45d88c943be3f60bf216bb6ac8a2d3b70dfa13e9669e402f11e2aaea1b74.bin"
    file_type = "exe"
    first_seen = "2026-08-28 00:25:09"
  condition:
    hash.sha256(0, filesize) == "db4a45d88c943be3f60bf216bb6ac8a2d3b70dfa13e9669e402f11e2aaea1b74"
}
```

### Sample 98: `94cba66e8937b1b0`

| Field | Value |
|---|---|
| SHA-256 | `94cba66e8937b1b065e55b8174f5c349eab9a170cc41dd1aa3c5d96a620e09a2` |
| Family label | `unknown` |
| File name | `dlr.spc` |
| File type | `elf` |
| First seen | `2026-08-28 00:12:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a6621076628d2e6f53a356592747f1d` |
| SHA-1 | `60d83d6433c8d0058aee2ed5cd9b3b58922c5561` |
| SHA-256 | `94cba66e8937b1b065e55b8174f5c349eab9a170cc41dd1aa3c5d96a620e09a2` |
| SHA3-384 | `36fd1c5befde7069456c94d25dff93b3e74933fc5a1885eda6d1f83f3c6db6b7fc5470ea2b7354cbdc5546373bae6fa2` |
| TLSH | `T14BC25B27FE315E2AC4D1CB78012DC32E096F328F866C5EB4B8930E65D905E942565BFE` |
| SSDEEP | `768:GTR6KqiA4lHzK5K0ju4lHG8CwiKe1iJpPMfx10NwPO+pYME:K0iA4lHzK5K0ju4lHG8CwiKe1iJpEfxW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_94cba66e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94cba66e8937b1b065e55b8174f5c349eab9a170cc41dd1aa3c5d96a620e09a2"
    family = "unknown"
    file_name = "dlr.spc"
    file_type = "elf"
    first_seen = "2026-08-28 00:12:39"
  condition:
    hash.sha256(0, filesize) == "94cba66e8937b1b065e55b8174f5c349eab9a170cc41dd1aa3c5d96a620e09a2"
}
```

### Sample 99: `b078582be2c34648`

| Field | Value |
|---|---|
| SHA-256 | `b078582be2c3464848f3f891f249d7a9ae7317cf4405d78e99ea2fa43354bd1f` |
| Family label | `unknown` |
| File name | `b078582be2c3464848f3f891f249d7a9ae7317cf4405d78e99ea2fa43354bd1f.exe` |
| File type | `exe` |
| First seen | `2026-08-28 00:10:59` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41cf13e3ced555b2fce9be9386c06369` |
| SHA-1 | `c61ab858fcb97c5ffad1fd63259e8f621d3de6c6` |
| SHA-256 | `b078582be2c3464848f3f891f249d7a9ae7317cf4405d78e99ea2fa43354bd1f` |
| SHA3-384 | `397976bdf8db1b3b2ea4e2137a5adaa80d130ed3b342c9ea8e343607be51d1121c2ba501f73f656db9dd1cf615c1e701` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T198D523AAA4F519B1D877CBF1CF82F1ACB16937D08B748D87B2C91A2049536446C3B735` |
| SSDEEP | `49152:gpq6nnZtwa6WWPzVpICpfPQuPxWR/wvPG5CxGa0LPKPjUzdESeAB/G:Oq6nZlWPzDVDxWRovGaHodEgxG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_b078582b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b078582be2c3464848f3f891f249d7a9ae7317cf4405d78e99ea2fa43354bd1f"
    family = "unknown"
    file_name = "b078582be2c3464848f3f891f249d7a9ae7317cf4405d78e99ea2fa43354bd1f.exe"
    file_type = "exe"
    first_seen = "2026-08-28 00:10:59"
  condition:
    hash.sha256(0, filesize) == "b078582be2c3464848f3f891f249d7a9ae7317cf4405d78e99ea2fa43354bd1f"
}
```

### Sample 100: `fdd903d07811d9e1`

| Field | Value |
|---|---|
| SHA-256 | `fdd903d07811d9e1c843a8c4527936468e54d827cf8cfcc4ff896792c9fced76` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-28 00:01:38` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd470d9ea7c3b02ad8020704a727b9a2` |
| SHA-1 | `3c5447b6c4ecf3786a9f1f423bc1bc72618e010f` |
| SHA-256 | `fdd903d07811d9e1c843a8c4527936468e54d827cf8cfcc4ff896792c9fced76` |
| SHA3-384 | `961661240b11d4ed55673e65188312c9194b8e2ee91ac7fdd7ed1a5e5a97c011940e4789b4ff9e7fd519a0d1cc5b1911` |
| IMPHASH | `7fb62922d0d976155935ce16b04e0fae` |
| TLSH | `T134B4F0D6F6A406FCD47A82788E9A0A09A3F074452B526AFF027801572F732D51EBFF54` |
| SSDEEP | `12288:jyOYzDtVvai7dQ+mqsG9qhIzrZjR5VC1y:OxHaii+6CAqFjR5V` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_fdd903d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdd903d07811d9e1c843a8c4527936468e54d827cf8cfcc4ff896792c9fced76"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 00:01:38"
  condition:
    hash.sha256(0, filesize) == "fdd903d07811d9e1c843a8c4527936468e54d827cf8cfcc4ff896792c9fced76"
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
 * Generated: 2026-08-28T11:30:54.129315+00:00
 */

rule MalwareBazaar_unknown_001_797e1972
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "797e1972be8425f00cb9d30818e1fb7a7961061e3276513bd1d48262aaceb186"
    family = "unknown"
    file_name = "797e1972be8425f00cb9d30818e1fb7a7961061e3276513bd1d48262aaceb186"
    file_type = "elf"
    first_seen = "2026-08-28 11:20:59"
  condition:
    hash.sha256(0, filesize) == "797e1972be8425f00cb9d30818e1fb7a7961061e3276513bd1d48262aaceb186"
}

rule MalwareBazaar_unknown_002_610ff7d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "610ff7d4ee1c7f17438e7278dcf7397a6eadfbb41bca7b3cc3518b9ee91ae157"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 10:57:16"
  condition:
    hash.sha256(0, filesize) == "610ff7d4ee1c7f17438e7278dcf7397a6eadfbb41bca7b3cc3518b9ee91ae157"
}

rule MalwareBazaar_unknown_003_04557843
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04557843879213ba547f76a47ab80164aa55c4f03888ea7e03cb9cfe88301ff4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 10:19:11"
  condition:
    hash.sha256(0, filesize) == "04557843879213ba547f76a47ab80164aa55c4f03888ea7e03cb9cfe88301ff4"
}

rule MalwareBazaar_unknown_004_41eba5d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41eba5d22fb6ddd15fe89de5a085883d84470f1a43ac177c630af3ea3c9f5708"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 10:05:39"
  condition:
    hash.sha256(0, filesize) == "41eba5d22fb6ddd15fe89de5a085883d84470f1a43ac177c630af3ea3c9f5708"
}

rule MalwareBazaar_unknown_005_97fdbb55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97fdbb5506534af805db9e23503d93439322650eeaba8132c2627d8a1b9c2dfb"
    family = "unknown"
    file_name = "97fdbb5506534af805db9e23503d93439322650eeaba8132c2627d8a1b9c2dfb.bin"
    file_type = "exe"
    first_seen = "2026-08-28 09:59:49"
  condition:
    hash.sha256(0, filesize) == "97fdbb5506534af805db9e23503d93439322650eeaba8132c2627d8a1b9c2dfb"
}

rule MalwareBazaar_unknown_006_52780b70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52780b706dc25236437afd0d49818afd31ba47c546331ee9338d82b9957cd919"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 09:57:07"
  condition:
    hash.sha256(0, filesize) == "52780b706dc25236437afd0d49818afd31ba47c546331ee9338d82b9957cd919"
}

rule MalwareBazaar_unknown_007_7108ff29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a"
    family = "unknown"
    file_name = "Tax_Notice_23665.zip"
    file_type = "zip"
    first_seen = "2026-08-28 09:42:30"
  condition:
    hash.sha256(0, filesize) == "7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a"
}

rule MalwareBazaar_unknown_008_c9067c5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9067c5f7a975ad3861fef91b4e82d3bb754d7dbf7e0bc2b774ad23cc3a295a1"
    family = "unknown"
    file_name = "c9067c5f7a975ad3861fef91b4e82d3bb754d7dbf7e0bc2b774ad23cc3a295a1.exe"
    file_type = "exe"
    first_seen = "2026-08-28 09:41:11"
  condition:
    hash.sha256(0, filesize) == "c9067c5f7a975ad3861fef91b4e82d3bb754d7dbf7e0bc2b774ad23cc3a295a1"
}

rule MalwareBazaar_unknown_009_44b92b32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44b92b32e0316c96f5c5a05f25f492083ee7f282080b0f5abc2d1bc9a800dece"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 09:40:24"
  condition:
    hash.sha256(0, filesize) == "44b92b32e0316c96f5c5a05f25f492083ee7f282080b0f5abc2d1bc9a800dece"
}

rule MalwareBazaar_unknown_010_be396a33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be396a33faffcee871ad014ce0ecd317e8e878fefecd172c8d2bff211b3d8a22"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 09:38:44"
  condition:
    hash.sha256(0, filesize) == "be396a33faffcee871ad014ce0ecd317e8e878fefecd172c8d2bff211b3d8a22"
}

rule MalwareBazaar_unknown_011_80cf59d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80cf59d0d509471a0f837c4e5b8b52a53c1da93c6b1c8f24c205e45680f71e0d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-28 09:38:24"
  condition:
    hash.sha256(0, filesize) == "80cf59d0d509471a0f837c4e5b8b52a53c1da93c6b1c8f24c205e45680f71e0d"
}

rule MalwareBazaar_unknown_012_d247d169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d247d169b650e0b2c538e456d456e4d95f2aa81eb50a459cce71168fa4a59cd2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 09:28:24"
  condition:
    hash.sha256(0, filesize) == "d247d169b650e0b2c538e456d456e4d95f2aa81eb50a459cce71168fa4a59cd2"
}

rule MalwareBazaar_Mirai_013_8c570d09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c570d090576cf05a6813c28574b2cf210de8054f7fa4cacd67428718348d143"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-28 09:26:53"
  condition:
    hash.sha256(0, filesize) == "8c570d090576cf05a6813c28574b2cf210de8054f7fa4cacd67428718348d143"
}

rule MalwareBazaar_unknown_014_dd3e7e4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd3e7e4fa68a68a3b5cc810ffbac6d75a4759434d3dabe3c154eaae87d579c2e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 09:13:28"
  condition:
    hash.sha256(0, filesize) == "dd3e7e4fa68a68a3b5cc810ffbac6d75a4759434d3dabe3c154eaae87d579c2e"
}

rule MalwareBazaar_unknown_015_63d404aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63d404aa43bfb74d8619dc7ceb950bd73e8525672c91077d40227c8bdf9ec387"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 09:10:31"
  condition:
    hash.sha256(0, filesize) == "63d404aa43bfb74d8619dc7ceb950bd73e8525672c91077d40227c8bdf9ec387"
}

rule MalwareBazaar_unknown_016_e067e909
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e067e909729799eb1074486fc299260c2233c499a4d612713ace2231162effac"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-08-28 09:08:35"
  condition:
    hash.sha256(0, filesize) == "e067e909729799eb1074486fc299260c2233c499a4d612713ace2231162effac"
}

rule MalwareBazaar_unknown_017_d2a720a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2a720a5ee2b07ac1968c978e2a3e433949560efe01cc4449b3b394e610ba1fe"
    family = "unknown"
    file_name = "main.lua"
    file_type = "unknown"
    first_seen = "2026-08-28 09:06:14"
  condition:
    hash.sha256(0, filesize) == "d2a720a5ee2b07ac1968c978e2a3e433949560efe01cc4449b3b394e610ba1fe"
}

rule MalwareBazaar_Mirai_018_6fa463dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fa463dc05e3986c0046442d73e726d7d106805e7a734c1fa9e9592f9e646e8e"
    family = "Mirai"
    file_name = "dlr.m68k"
    file_type = "elf"
    first_seen = "2026-08-28 08:57:29"
  condition:
    hash.sha256(0, filesize) == "6fa463dc05e3986c0046442d73e726d7d106805e7a734c1fa9e9592f9e646e8e"
}

rule MalwareBazaar_Formbook_019_94a33fc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94a33fc48ecb504091be4ab6c64cb3b828ac0efe1c9449c8ee952774de38b44f"
    family = "Formbook"
    file_name = "Solenis RFQ-BID--870994965701.exe"
    file_type = "exe"
    first_seen = "2026-08-28 08:57:12"
  condition:
    hash.sha256(0, filesize) == "94a33fc48ecb504091be4ab6c64cb3b828ac0efe1c9449c8ee952774de38b44f"
}

rule MalwareBazaar_Formbook_020_a2fc3ab5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2fc3ab543e72decbea89ff3479cc9d813324bccccb291cba2536d95b0bdc64c"
    family = "Formbook"
    file_name = "Purchasing Order Required Specification RQTC1FWfMShV.exe"
    file_type = "exe"
    first_seen = "2026-08-28 08:56:45"
  condition:
    hash.sha256(0, filesize) == "a2fc3ab543e72decbea89ff3479cc9d813324bccccb291cba2536d95b0bdc64c"
}

rule MalwareBazaar_unknown_021_6f61cd63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f61cd63d740045a86265e5a0320871f3a6271d6ca7ba65e4291f47ccb55c834"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 08:54:29"
  condition:
    hash.sha256(0, filesize) == "6f61cd63d740045a86265e5a0320871f3a6271d6ca7ba65e4291f47ccb55c834"
}

rule MalwareBazaar_unknown_022_f8666460
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8666460abf01362c5a9e24ecd86193425338e25c4cd9b2bb66caf726acacfc3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 08:53:38"
  condition:
    hash.sha256(0, filesize) == "f8666460abf01362c5a9e24ecd86193425338e25c4cd9b2bb66caf726acacfc3"
}

rule MalwareBazaar_unknown_023_b21e7c4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b21e7c4fbe16a23c3421d84e2e8a173969aafe2701bbe3e8bba23b04a0ed3246"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 08:52:34"
  condition:
    hash.sha256(0, filesize) == "b21e7c4fbe16a23c3421d84e2e8a173969aafe2701bbe3e8bba23b04a0ed3246"
}

rule MalwareBazaar_Mirai_024_995e43d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "995e43d70fad10c13d296fc34de743fae2edfac447a244d99ced9d5f0e8c02eb"
    family = "Mirai"
    file_name = "dlr.spc"
    file_type = "elf"
    first_seen = "2026-08-28 08:47:38"
  condition:
    hash.sha256(0, filesize) == "995e43d70fad10c13d296fc34de743fae2edfac447a244d99ced9d5f0e8c02eb"
}

rule MalwareBazaar_unknown_025_df8e6699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df8e6699a99b0d061fe86419dc067a6ee02b10a3e18364a22aa8048630764520"
    family = "unknown"
    file_name = "df8e6699a99b0d061fe86419dc067a6ee02b10a3e18364a22aa8048630764520.raw"
    file_type = "zip"
    first_seen = "2026-08-28 08:43:54"
  condition:
    hash.sha256(0, filesize) == "df8e6699a99b0d061fe86419dc067a6ee02b10a3e18364a22aa8048630764520"
}

rule MalwareBazaar_unknown_026_920d5a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "920d5a4380e783f4fd7752766919c3ae67c21b687384e154610528aa7f5793a7"
    family = "unknown"
    file_name = "17529dfc1fe186b5d40ec69df217dfe1"
    file_type = "dll"
    first_seen = "2026-08-28 08:43:50"
  condition:
    hash.sha256(0, filesize) == "920d5a4380e783f4fd7752766919c3ae67c21b687384e154610528aa7f5793a7"
}

rule MalwareBazaar_unknown_027_f7ce7517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7ce75170b15e0d2aa37e3e9b65d949562fa90dd582c2753c23b414e80b8ea79"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 08:38:31"
  condition:
    hash.sha256(0, filesize) == "f7ce75170b15e0d2aa37e3e9b65d949562fa90dd582c2753c23b414e80b8ea79"
}

rule MalwareBazaar_Mirai_028_969e189d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "969e189d841ff5aa13e1ff3bd728b8c487f10f5ec9d9cc4959c21db4d369fc10"
    family = "Mirai"
    file_name = "dlr.mips"
    file_type = "elf"
    first_seen = "2026-08-28 08:32:40"
  condition:
    hash.sha256(0, filesize) == "969e189d841ff5aa13e1ff3bd728b8c487f10f5ec9d9cc4959c21db4d369fc10"
}

rule MalwareBazaar_unknown_029_72665efc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72665efcae90205b756d4d7e1102e6c7d77b143a9c0ed0f73f926c0a86ccf878"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 08:25:33"
  condition:
    hash.sha256(0, filesize) == "72665efcae90205b756d4d7e1102e6c7d77b143a9c0ed0f73f926c0a86ccf878"
}

rule MalwareBazaar_unknown_030_b76bd392
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b76bd392d4d4da577f417631e3bc734b68361c1da07db27dc117356b1ec4f241"
    family = "unknown"
    file_name = "physics_server_v2.sys"
    file_type = "unknown"
    first_seen = "2026-08-28 08:20:07"
  condition:
    hash.sha256(0, filesize) == "b76bd392d4d4da577f417631e3bc734b68361c1da07db27dc117356b1ec4f241"
}

rule MalwareBazaar_unknown_031_0f4e99a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f4e99a8f70adcb130fb965f740940c826aeafcaea80106df7d80aede8eb0d20"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-28 08:19:30"
  condition:
    hash.sha256(0, filesize) == "0f4e99a8f70adcb130fb965f740940c826aeafcaea80106df7d80aede8eb0d20"
}

rule MalwareBazaar_unknown_032_a5e07742
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5e07742617f67d52a065960000a01b6dccd0b4248a58f027926019de2287345"
    family = "unknown"
    file_name = "thread2.yaml"
    file_type = "unknown"
    first_seen = "2026-08-28 08:16:00"
  condition:
    hash.sha256(0, filesize) == "a5e07742617f67d52a065960000a01b6dccd0b4248a58f027926019de2287345"
}

rule MalwareBazaar_unknown_033_0aca6730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0aca67308f168b7fd0b48ca2257fafbad30129b45a398ae39fdd2fef631f358f"
    family = "unknown"
    file_name = "Zооm.vbs"
    file_type = "vbs"
    first_seen = "2026-08-28 08:15:49"
  condition:
    hash.sha256(0, filesize) == "0aca67308f168b7fd0b48ca2257fafbad30129b45a398ae39fdd2fef631f358f"
}

rule MalwareBazaar_unknown_034_2943e8c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2943e8c43da4ac3b1f1970efd35ddeb5c6a120dd6241ecf2243f2938450663a3"
    family = "unknown"
    file_name = "physics_server.sys"
    file_type = "unknown"
    first_seen = "2026-08-28 08:15:27"
  condition:
    hash.sha256(0, filesize) == "2943e8c43da4ac3b1f1970efd35ddeb5c6a120dd6241ecf2243f2938450663a3"
}

rule MalwareBazaar_unknown_035_aa4e0509
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa4e0509b93a8ae6f4203aebb57e51e4a886bfc92f5650d3941aa97f0924bb54"
    family = "unknown"
    file_name = "PPUtilLib.dll"
    file_type = "dll"
    first_seen = "2026-08-28 08:15:09"
  condition:
    hash.sha256(0, filesize) == "aa4e0509b93a8ae6f4203aebb57e51e4a886bfc92f5650d3941aa97f0924bb54"
}

rule MalwareBazaar_unknown_036_03beb4af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03beb4af9fedfd21f18e9d204d28675ba6b1649afa3201fce16e3bdfab8a2b6f"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-28 08:09:59"
  condition:
    hash.sha256(0, filesize) == "03beb4af9fedfd21f18e9d204d28675ba6b1649afa3201fce16e3bdfab8a2b6f"
}

rule MalwareBazaar_unknown_037_7134cbfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7134cbfe70583aeb8673bc8c6f0e6b4966c0117c5c9820fc2d32535bb2f4e649"
    family = "unknown"
    file_name = "lterouter"
    file_type = "unknown"
    first_seen = "2026-08-28 07:55:31"
  condition:
    hash.sha256(0, filesize) == "7134cbfe70583aeb8673bc8c6f0e6b4966c0117c5c9820fc2d32535bb2f4e649"
}

rule MalwareBazaar_PureLogsStealer_038_1876ef7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1876ef7a0995a7383f5660bcd0b53de56bb9c21f04395f35a86e8195b99bf180"
    family = "PureLogsStealer"
    file_name = "New Order-PO230824312.vbs"
    file_type = "vbs"
    first_seen = "2026-08-28 07:54:58"
  condition:
    hash.sha256(0, filesize) == "1876ef7a0995a7383f5660bcd0b53de56bb9c21f04395f35a86e8195b99bf180"
}

rule MalwareBazaar_unknown_039_46ced738
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46ced738ab9a9a37df3e36c6a8603742f26783f0be2fa845bdec10b5ddb50bfb"
    family = "unknown"
    file_name = "98f00e36daaf4c4bae91031d4b53ea9b.exe"
    file_type = "exe"
    first_seen = "2026-08-28 07:54:50"
  condition:
    hash.sha256(0, filesize) == "46ced738ab9a9a37df3e36c6a8603742f26783f0be2fa845bdec10b5ddb50bfb"
}

rule MalwareBazaar_ConnectWise_040_09fbf3e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09fbf3e4ef2906968ec725e6794f16597ab2f53019f460417e9162f0d912ed35"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-08-28 07:50:24"
  condition:
    hash.sha256(0, filesize) == "09fbf3e4ef2906968ec725e6794f16597ab2f53019f460417e9162f0d912ed35"
}

rule MalwareBazaar_Mirai_041_e77f5890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e77f58904f6692e7adbb1d8dac1ec89e827a6847d632e1ab0082a5ffc7a9553a"
    family = "Mirai"
    file_name = "e77f58904f6692e7adbb1d8dac1ec89e827a6847d632e1ab0082a5ffc7a9553a.elf"
    file_type = "elf"
    first_seen = "2026-08-28 07:46:41"
  condition:
    hash.sha256(0, filesize) == "e77f58904f6692e7adbb1d8dac1ec89e827a6847d632e1ab0082a5ffc7a9553a"
}

rule MalwareBazaar_LummaStealer_042_b926a449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b926a44910e4f4d55c53fdc6d9cdbfb043059355d55fb3595a3434bd69b1e7e3"
    family = "LummaStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 07:36:36"
  condition:
    hash.sha256(0, filesize) == "b926a44910e4f4d55c53fdc6d9cdbfb043059355d55fb3595a3434bd69b1e7e3"
}

rule MalwareBazaar_unknown_043_3daa312d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3daa312d3539f72c1fbf1c9647547c8e8271528ca0a525207ffa224d3f5ae5c8"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 07:35:31"
  condition:
    hash.sha256(0, filesize) == "3daa312d3539f72c1fbf1c9647547c8e8271528ca0a525207ffa224d3f5ae5c8"
}

rule MalwareBazaar_unknown_044_e9499ef0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9499ef03470396b080045e9a502f02b0ac2cb33685a3cbe142051942dd29dd9"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 07:33:33"
  condition:
    hash.sha256(0, filesize) == "e9499ef03470396b080045e9a502f02b0ac2cb33685a3cbe142051942dd29dd9"
}

rule MalwareBazaar_Mirai_045_f0bc10c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0bc10c6e13d2da8a50767c193265db6da1ddd339c6da4fdeb518a501b47ff69"
    family = "Mirai"
    file_name = "f0bc10c6e13d2da8a50767c193265db6da1ddd339c6da4fdeb518a501b47ff69.elf"
    file_type = "elf"
    first_seen = "2026-08-28 07:26:42"
  condition:
    hash.sha256(0, filesize) == "f0bc10c6e13d2da8a50767c193265db6da1ddd339c6da4fdeb518a501b47ff69"
}

rule MalwareBazaar_unknown_046_7bebf7bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bebf7bcf09e72dde8e9b25baddab1d292c5815008a0d5795ddf5db72ba45432"
    family = "unknown"
    file_name = "7bebf7bcf09e72dde8e9b25baddab1d292c5815008a0d5795ddf5db72ba45432.elf"
    file_type = "elf"
    first_seen = "2026-08-28 07:26:36"
  condition:
    hash.sha256(0, filesize) == "7bebf7bcf09e72dde8e9b25baddab1d292c5815008a0d5795ddf5db72ba45432"
}

rule MalwareBazaar_unknown_047_a46408be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a46408be582bfeff347490b12c0b24db7cabeb05498f72faf68dd4caa95882ce"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 07:26:33"
  condition:
    hash.sha256(0, filesize) == "a46408be582bfeff347490b12c0b24db7cabeb05498f72faf68dd4caa95882ce"
}

rule MalwareBazaar_Mirai_048_6eb9386b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eb9386b0b6c2a75fc265317b697c1d16861020edc7f8cf68b1663b361633772"
    family = "Mirai"
    file_name = "dlr.x86"
    file_type = "elf"
    first_seen = "2026-08-28 07:16:32"
  condition:
    hash.sha256(0, filesize) == "6eb9386b0b6c2a75fc265317b697c1d16861020edc7f8cf68b1663b361633772"
}

rule MalwareBazaar_Vidar_049_16168cc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16168cc3b16d768beffaf0fd10f74f86f79da7a2c7ca26edd91c09c1c101811d"
    family = "Vidar"
    file_name = "16168cc3b16d768beffaf0fd10f74f86f79da7a2c7ca26edd91c09c1c101811d.bin"
    file_type = "exe"
    first_seen = "2026-08-28 07:13:31"
  condition:
    hash.sha256(0, filesize) == "16168cc3b16d768beffaf0fd10f74f86f79da7a2c7ca26edd91c09c1c101811d"
}

rule MalwareBazaar_unknown_050_aae87ba1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aae87ba174e92ebfaa0a63585920085cfaf0c1777471749c0ea1bc8f704238f1"
    family = "unknown"
    file_name = "aae87ba174e92ebfaa0a63585920085cfaf0c1777471749c0ea1bc8f704238f1"
    file_type = "sh"
    first_seen = "2026-08-28 07:00:17"
  condition:
    hash.sha256(0, filesize) == "aae87ba174e92ebfaa0a63585920085cfaf0c1777471749c0ea1bc8f704238f1"
}

rule MalwareBazaar_unknown_051_25fee238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25fee2381d8f3e7724ba63a148642ff3201b58bd0b4325d5c38fa46cb88720e9"
    family = "unknown"
    file_name = "25fee2381d8f3e7724ba63a148642ff3201b58bd0b4325d5c38fa46cb88720e9"
    file_type = "sh"
    first_seen = "2026-08-28 07:00:13"
  condition:
    hash.sha256(0, filesize) == "25fee2381d8f3e7724ba63a148642ff3201b58bd0b4325d5c38fa46cb88720e9"
}

rule MalwareBazaar_GCleaner_052_c496e8e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c496e8e8f7cc2e40c515c9dbd98ffce43861acaf504466f478ceaebf712214b8"
    family = "GCleaner"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-08-28 06:52:06"
  condition:
    hash.sha256(0, filesize) == "c496e8e8f7cc2e40c515c9dbd98ffce43861acaf504466f478ceaebf712214b8"
}

rule MalwareBazaar_Mirai_053_3eecac09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3eecac099baf249d268aead626022f0947a13231bdb8cdec5aa6f68b2c584a37"
    family = "Mirai"
    file_name = "3eecac099baf249d268aead626022f0947a13231bdb8cdec5aa6f68b2c584a37.elf"
    file_type = "elf"
    first_seen = "2026-08-28 06:41:06"
  condition:
    hash.sha256(0, filesize) == "3eecac099baf249d268aead626022f0947a13231bdb8cdec5aa6f68b2c584a37"
}

rule MalwareBazaar_Amadey_054_76e6367d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76e6367d8123171afa540fe92a3758424ec7d1e029c4e5a3b9771e24fe0085c1"
    family = "Amadey"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 06:40:41"
  condition:
    hash.sha256(0, filesize) == "76e6367d8123171afa540fe92a3758424ec7d1e029c4e5a3b9771e24fe0085c1"
}

rule MalwareBazaar_Heodo_055_af549a7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af549a7f988cf26d772accfdc120fac42a557302bb00f8294f6fad3a09aed5a4"
    family = "Heodo"
    file_name = "telekom_invoice_malware_20260827.zip"
    file_type = "zip"
    first_seen = "2026-08-28 06:24:41"
  condition:
    hash.sha256(0, filesize) == "af549a7f988cf26d772accfdc120fac42a557302bb00f8294f6fad3a09aed5a4"
}

rule MalwareBazaar_unknown_056_994cfadc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "994cfadcb2b638fd685a14b326ed217315a54907a42486c72bd0a5311bc33476"
    family = "unknown"
    file_name = "Telekom_Deutschland_Rechnung_August_2026...pdf.zip"
    file_type = "zip"
    first_seen = "2026-08-28 06:18:36"
  condition:
    hash.sha256(0, filesize) == "994cfadcb2b638fd685a14b326ed217315a54907a42486c72bd0a5311bc33476"
}

rule MalwareBazaar_unknown_057_c8da8aeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8da8aeba2cce8ac2747caf1d3021e3b3b803322ca5afdb33aeb66bea3a255ae"
    family = "unknown"
    file_name = "c8da8aeba2cce8ac2747caf1d3021e3b3b803322ca5afdb33aeb66bea3a255ae.exe"
    file_type = "exe"
    first_seen = "2026-08-28 06:16:05"
  condition:
    hash.sha256(0, filesize) == "c8da8aeba2cce8ac2747caf1d3021e3b3b803322ca5afdb33aeb66bea3a255ae"
}

rule MalwareBazaar_unknown_058_d19466c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d19466c0ca1887e51e1e9bec743207fb24008371c67567be37325b27998dedd6"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-28 05:56:18"
  condition:
    hash.sha256(0, filesize) == "d19466c0ca1887e51e1e9bec743207fb24008371c67567be37325b27998dedd6"
}

rule MalwareBazaar_CoinMiner_059_245f6e3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "245f6e3f6750701d58c06bd96f4623c62942305fb32bcdc5a99bf367becaafd0"
    family = "CoinMiner"
    file_name = "245f6e3f6750701d58c06bd96f4623c62942305fb32bcdc5a99bf367becaafd0.exe"
    file_type = "exe"
    first_seen = "2026-08-28 05:56:04"
  condition:
    hash.sha256(0, filesize) == "245f6e3f6750701d58c06bd96f4623c62942305fb32bcdc5a99bf367becaafd0"
}

rule MalwareBazaar_RemusStealer_060_5cb54c53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cb54c53e2169a23a815d87229b00c63d1d3c8c0d19e0f92b5e83bd231481419"
    family = "RemusStealer"
    file_name = "cx-programmer 9.1 free download full.exe"
    file_type = "exe"
    first_seen = "2026-08-28 05:44:09"
  condition:
    hash.sha256(0, filesize) == "5cb54c53e2169a23a815d87229b00c63d1d3c8c0d19e0f92b5e83bd231481419"
}

rule MalwareBazaar_unknown_061_3b2923ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b2923ad0a2c7c0c5386c5af90f8ef5a9ef8e1b51ecf7b70ee936cda46923c42"
    family = "unknown"
    file_name = "567ec72e3720cfe55b799e115bb5d0daf49f9a877e758cd7d48f21c7b1e76a06.zip"
    file_type = "zip"
    first_seen = "2026-08-28 05:24:35"
  condition:
    hash.sha256(0, filesize) == "3b2923ad0a2c7c0c5386c5af90f8ef5a9ef8e1b51ecf7b70ee936cda46923c42"
}

rule MalwareBazaar_PureRAT_062_f63eb266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f63eb2664ac9076250491b1cb0787042f75a056e235867d9f9967322c5cf20a4"
    family = "PureRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 05:09:55"
  condition:
    hash.sha256(0, filesize) == "f63eb2664ac9076250491b1cb0787042f75a056e235867d9f9967322c5cf20a4"
}

rule MalwareBazaar_DCRat_063_9b0e3f97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b0e3f974dac0023599bb604b5b30e3e763c2d1d28ecff80d307ca73dc06243f"
    family = "DCRat"
    file_name = "9FCE0558DD8B2061C7A8BAF0877D5384.exe"
    file_type = "exe"
    first_seen = "2026-08-28 05:05:17"
  condition:
    hash.sha256(0, filesize) == "9b0e3f974dac0023599bb604b5b30e3e763c2d1d28ecff80d307ca73dc06243f"
}

rule MalwareBazaar_Mirai_064_ff08f124
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff08f124122ea1edb933d945458b65b5ce61330c8510f0e906b2edf331f045c2"
    family = "Mirai"
    file_name = "dlr.mpsl"
    file_type = "elf"
    first_seen = "2026-08-28 04:49:33"
  condition:
    hash.sha256(0, filesize) == "ff08f124122ea1edb933d945458b65b5ce61330c8510f0e906b2edf331f045c2"
}

rule MalwareBazaar_unknown_065_1469a793
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1469a7931d3da0258753eb7e758e08126895ccdb942d5e2dd3ed7a5e0889faf1"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-28 04:30:33"
  condition:
    hash.sha256(0, filesize) == "1469a7931d3da0258753eb7e758e08126895ccdb942d5e2dd3ed7a5e0889faf1"
}

rule MalwareBazaar_ValleyRAT_066_0bab062a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bab062af7894bc44d68ebc5b9633a84ffaae1f17671ff3949002c43321ec86a"
    family = "ValleyRAT"
    file_name = "846F4ED47A679E24505470F61D9110DB.exe"
    file_type = "exe"
    first_seen = "2026-08-28 04:10:17"
  condition:
    hash.sha256(0, filesize) == "0bab062af7894bc44d68ebc5b9633a84ffaae1f17671ff3949002c43321ec86a"
}

rule MalwareBazaar_unknown_067_56262204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "562622045c43b246078c942e1514a82a80413ded29337d79fec38471c21cc13f"
    family = "unknown"
    file_name = "Frostix.exe"
    file_type = "exe"
    first_seen = "2026-08-28 04:02:38"
  condition:
    hash.sha256(0, filesize) == "562622045c43b246078c942e1514a82a80413ded29337d79fec38471c21cc13f"
}

rule MalwareBazaar_unknown_068_c1a20d4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1a20d4cc65d61cb4d60b780fc3678a7a18c585633636ebdb3aa04b070d4d5e2"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 03:50:35"
  condition:
    hash.sha256(0, filesize) == "c1a20d4cc65d61cb4d60b780fc3678a7a18c585633636ebdb3aa04b070d4d5e2"
}

rule MalwareBazaar_Vidar_069_0c8c4a99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c8c4a99337505f79c05af524ef2c8ce810269a1896b9bd83bbd39454a618b8d"
    family = "Vidar"
    file_name = "0c8c4a99337505f79c05af524ef2c8ce810269a1896b9bd83bbd39454a618b8d.bin"
    file_type = "exe"
    first_seen = "2026-08-28 03:42:46"
  condition:
    hash.sha256(0, filesize) == "0c8c4a99337505f79c05af524ef2c8ce810269a1896b9bd83bbd39454a618b8d"
}

rule MalwareBazaar_RustyStealer_070_f19ce246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f19ce246b09aec504d8cb547f9d3344e14a6ca898f8d88f2207ece0d74f0d3f1"
    family = "RustyStealer"
    file_name = "f19ce246b09aec504d8cb547f9d3344e14a6ca898f8d88f2207ece0d74f0d3f1.bin"
    file_type = "exe"
    first_seen = "2026-08-28 03:42:42"
  condition:
    hash.sha256(0, filesize) == "f19ce246b09aec504d8cb547f9d3344e14a6ca898f8d88f2207ece0d74f0d3f1"
}

rule MalwareBazaar_unknown_071_d55a97b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d55a97b3c7eaba8b619a790ea9bac46ce8d48cf7553a970f00ef18a1107ff9a5"
    family = "unknown"
    file_name = "d55a97b3c7eaba8b619a790ea9bac46ce8d48cf7553a970f00ef18a1107ff9a5.exe"
    file_type = "exe"
    first_seen = "2026-08-28 03:36:09"
  condition:
    hash.sha256(0, filesize) == "d55a97b3c7eaba8b619a790ea9bac46ce8d48cf7553a970f00ef18a1107ff9a5"
}

rule MalwareBazaar_unknown_072_06574a1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06574a1f939dc99681ab9f9df1ef7c4e072de301d023ddd947a72e1b868c7c08"
    family = "unknown"
    file_name = "dlr.ppc"
    file_type = "elf"
    first_seen = "2026-08-28 03:31:08"
  condition:
    hash.sha256(0, filesize) == "06574a1f939dc99681ab9f9df1ef7c4e072de301d023ddd947a72e1b868c7c08"
}

rule MalwareBazaar_VIPKeylogger_073_6fd06127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fd06127cd5573a4f884e3c7a4425f56c1e277109bc86ceabcf57b524afd0075"
    family = "VIPKeylogger"
    file_name = "INV09876545678HLK.bat"
    file_type = "exe"
    first_seen = "2026-08-28 03:20:20"
  condition:
    hash.sha256(0, filesize) == "6fd06127cd5573a4f884e3c7a4425f56c1e277109bc86ceabcf57b524afd0075"
}

rule MalwareBazaar_unknown_074_ba94e9c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba94e9c02b5a75e7d5ff6d030aa8800a486e593a311af0c35b1e21ddabe33929"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 03:03:46"
  condition:
    hash.sha256(0, filesize) == "ba94e9c02b5a75e7d5ff6d030aa8800a486e593a311af0c35b1e21ddabe33929"
}

rule MalwareBazaar_unknown_075_1a8ec15e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a8ec15eece1741be0c93bcd0b9fac0a4c3b76f8f5eae3547586588e67f198fc"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 03:01:49"
  condition:
    hash.sha256(0, filesize) == "1a8ec15eece1741be0c93bcd0b9fac0a4c3b76f8f5eae3547586588e67f198fc"
}

rule MalwareBazaar_unknown_076_12da29fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12da29fe8078e3fd582ad065217fd130e5ad6a9869b691fdb228679b94a7eaa7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-28 02:57:35"
  condition:
    hash.sha256(0, filesize) == "12da29fe8078e3fd582ad065217fd130e5ad6a9869b691fdb228679b94a7eaa7"
}

rule MalwareBazaar_Mirai_077_dba5d7c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dba5d7c1fe4c4f1c8fbfc7d4f2392499c79e4fe381b8a89b6ee4e3df34502bf5"
    family = "Mirai"
    file_name = "dba5d7c1fe4c4f1c8fbfc7d4f2392499c79e4fe381b8a89b6ee4e3df34502bf5.elf"
    file_type = "elf"
    first_seen = "2026-08-28 02:56:04"
  condition:
    hash.sha256(0, filesize) == "dba5d7c1fe4c4f1c8fbfc7d4f2392499c79e4fe381b8a89b6ee4e3df34502bf5"
}

rule MalwareBazaar_RemusStealer_078_f7eb8205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7eb82050604926b372ed7df21b9df90aa970eb20daec5d75d492a427a56e0d3"
    family = "RemusStealer"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-28 02:52:10"
  condition:
    hash.sha256(0, filesize) == "f7eb82050604926b372ed7df21b9df90aa970eb20daec5d75d492a427a56e0d3"
}

rule MalwareBazaar_Mirai_079_314c048c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "314c048ccfd30945314dea4c3764e7bffde5a1d4ac07966f4e05bb9d2c50e615"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-28 02:45:43"
  condition:
    hash.sha256(0, filesize) == "314c048ccfd30945314dea4c3764e7bffde5a1d4ac07966f4e05bb9d2c50e615"
}

rule MalwareBazaar_QuasarRAT_080_33cc64e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33cc64e622a224df172252aad00278e8f085925414d5fac4e821f5f7596e8c8c"
    family = "QuasarRAT"
    file_name = "461E43DA65ED883C46B72C095FD72A3E.exe"
    file_type = "exe"
    first_seen = "2026-08-28 02:45:09"
  condition:
    hash.sha256(0, filesize) == "33cc64e622a224df172252aad00278e8f085925414d5fac4e821f5f7596e8c8c"
}

rule MalwareBazaar_unknown_081_86c08074
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c0807408f58802a8d42a3ffb4a0c1c52b7ea992da162207a3de31c9c9d0f3a"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 02:39:37"
  condition:
    hash.sha256(0, filesize) == "86c0807408f58802a8d42a3ffb4a0c1c52b7ea992da162207a3de31c9c9d0f3a"
}

rule MalwareBazaar_unknown_082_cb2ad0ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb2ad0ac4f4060268b24b28f7e7798ebe5da6e7c3fbf05939ba2277d563a32e9"
    family = "unknown"
    file_name = "dlr.mpsl"
    file_type = "elf"
    first_seen = "2026-08-28 02:37:41"
  condition:
    hash.sha256(0, filesize) == "cb2ad0ac4f4060268b24b28f7e7798ebe5da6e7c3fbf05939ba2277d563a32e9"
}

rule MalwareBazaar_unknown_083_2feb91cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2feb91cf421d8e7c564b65e27315ae3c0b2f0df2496b97dfbaabc5ef216dbae4"
    family = "unknown"
    file_name = "2feb91cf421d8e7c564b65e27315ae3c0b2f0df2496b97dfbaabc5ef216dbae4.bin"
    file_type = "exe"
    first_seen = "2026-08-28 02:34:45"
  condition:
    hash.sha256(0, filesize) == "2feb91cf421d8e7c564b65e27315ae3c0b2f0df2496b97dfbaabc5ef216dbae4"
}

rule MalwareBazaar_unknown_084_7a0bdad6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a0bdad6fac316f1fcf006a02096b38773b8112b226ab1b8c6867dac48dcbc0b"
    family = "unknown"
    file_name = "dlr.arm7"
    file_type = "elf"
    first_seen = "2026-08-28 02:33:40"
  condition:
    hash.sha256(0, filesize) == "7a0bdad6fac316f1fcf006a02096b38773b8112b226ab1b8c6867dac48dcbc0b"
}

rule MalwareBazaar_unknown_085_6aaff3d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aaff3d4ea521cbd426be4a23ecdb21063eb6afd9496fb83803c3c310b87ed39"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-28 02:31:43"
  condition:
    hash.sha256(0, filesize) == "6aaff3d4ea521cbd426be4a23ecdb21063eb6afd9496fb83803c3c310b87ed39"
}

rule MalwareBazaar_WannaCry_086_1738f890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1738f890d5686b1c17b43166659643dde6ff57fc9ed4143dc9801ae331036273"
    family = "WannaCry"
    file_name = "1738f890d5686b1c17b43166659643dde6ff57fc9ed4143dc9801ae331036273"
    file_type = "exe"
    first_seen = "2026-08-28 02:15:13"
  condition:
    hash.sha256(0, filesize) == "1738f890d5686b1c17b43166659643dde6ff57fc9ed4143dc9801ae331036273"
}

rule MalwareBazaar_QuasarRAT_087_27d22c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27d22c374ffa52ab63cfb05c09b7925100f6ccd0eb00e314cf8f20be231da250"
    family = "QuasarRAT"
    file_name = "3304B81686F03893B0A931F23C6665BA.exe"
    file_type = "exe"
    first_seen = "2026-08-28 02:15:12"
  condition:
    hash.sha256(0, filesize) == "27d22c374ffa52ab63cfb05c09b7925100f6ccd0eb00e314cf8f20be231da250"
}

rule MalwareBazaar_QuasarRAT_088_178b290d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "178b290d24527fda41dcaa0960b289e024e4fac39b96a3d8aebf9be14f51a635"
    family = "QuasarRAT"
    file_name = "3135BF9C620AEA1463C948D1BE481493.exe"
    file_type = "exe"
    first_seen = "2026-08-28 02:15:08"
  condition:
    hash.sha256(0, filesize) == "178b290d24527fda41dcaa0960b289e024e4fac39b96a3d8aebf9be14f51a635"
}

rule MalwareBazaar_unknown_089_2e74c6a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e74c6a004d7cc7323eaddc86da7c52f21deafc9e3a055c67956c44cb47b8220"
    family = "unknown"
    file_name = "2e74c6a004d7cc7323eaddc86da7c52f21deafc9e3a055c67956c44cb47b8220.exe"
    file_type = "exe"
    first_seen = "2026-08-28 01:59:36"
  condition:
    hash.sha256(0, filesize) == "2e74c6a004d7cc7323eaddc86da7c52f21deafc9e3a055c67956c44cb47b8220"
}

rule MalwareBazaar_unknown_090_e36c6e71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e36c6e71d1149b0d5e7756446ae57c1c9132839aea012d3bb7e7e519bfa6128d"
    family = "unknown"
    file_name = "94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00.sh"
    file_type = "unknown"
    first_seen = "2026-08-28 01:45:36"
  condition:
    hash.sha256(0, filesize) == "e36c6e71d1149b0d5e7756446ae57c1c9132839aea012d3bb7e7e519bfa6128d"
}

rule MalwareBazaar_unknown_091_f2626a8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2626a8c7efee8f1e6d301bc928d02aab6a3d7e3ad51e58363d79ce4648e55c7"
    family = "unknown"
    file_name = "dlr.sh4"
    file_type = "elf"
    first_seen = "2026-08-28 01:41:43"
  condition:
    hash.sha256(0, filesize) == "f2626a8c7efee8f1e6d301bc928d02aab6a3d7e3ad51e58363d79ce4648e55c7"
}

rule MalwareBazaar_unknown_092_8cf07438
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cf074380ec4d971c134f93b0fb94239eaea55f4f2047a48d75fc21fd827a75e"
    family = "unknown"
    file_name = "8cf074380ec4d971c134f93b0fb94239eaea55f4f2047a48d75fc21fd827a75e.elf"
    file_type = "elf"
    first_seen = "2026-08-28 01:31:35"
  condition:
    hash.sha256(0, filesize) == "8cf074380ec4d971c134f93b0fb94239eaea55f4f2047a48d75fc21fd827a75e"
}

rule MalwareBazaar_Gafgyt_093_088f624b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "088f624bf51e8c9db46a345c3a85df89f5729a226da1846f70aae91b9b44ffe7"
    family = "Gafgyt"
    file_name = "a-r.m-6.SNOOPY"
    file_type = "elf"
    first_seen = "2026-08-28 01:10:40"
  condition:
    hash.sha256(0, filesize) == "088f624bf51e8c9db46a345c3a85df89f5729a226da1846f70aae91b9b44ffe7"
}

rule MalwareBazaar_Gafgyt_094_deb1c78c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "deb1c78ca154989f89979b9b0126f3781a0c6ac8cad6ef121598a4cceb7bc6f0"
    family = "Gafgyt"
    file_name = "s-h.4-.SNOOPY"
    file_type = "elf"
    first_seen = "2026-08-28 01:10:38"
  condition:
    hash.sha256(0, filesize) == "deb1c78ca154989f89979b9b0126f3781a0c6ac8cad6ef121598a4cceb7bc6f0"
}

rule MalwareBazaar_unknown_095_30cb2512
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30cb25122bca4c471c18cf6771a4663c39745460ba6d37b32d372e00657e66eb"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-28 00:42:43"
  condition:
    hash.sha256(0, filesize) == "30cb25122bca4c471c18cf6771a4663c39745460ba6d37b32d372e00657e66eb"
}

rule MalwareBazaar_unknown_096_4e20a6ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e20a6ab95b60f31d9e926a62800d03c2af89b2efd96c782aa022dca6ffa4a59"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 00:32:30"
  condition:
    hash.sha256(0, filesize) == "4e20a6ab95b60f31d9e926a62800d03c2af89b2efd96c782aa022dca6ffa4a59"
}

rule MalwareBazaar_unknown_097_db4a45d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db4a45d88c943be3f60bf216bb6ac8a2d3b70dfa13e9669e402f11e2aaea1b74"
    family = "unknown"
    file_name = "db4a45d88c943be3f60bf216bb6ac8a2d3b70dfa13e9669e402f11e2aaea1b74.bin"
    file_type = "exe"
    first_seen = "2026-08-28 00:25:09"
  condition:
    hash.sha256(0, filesize) == "db4a45d88c943be3f60bf216bb6ac8a2d3b70dfa13e9669e402f11e2aaea1b74"
}

rule MalwareBazaar_unknown_098_94cba66e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94cba66e8937b1b065e55b8174f5c349eab9a170cc41dd1aa3c5d96a620e09a2"
    family = "unknown"
    file_name = "dlr.spc"
    file_type = "elf"
    first_seen = "2026-08-28 00:12:39"
  condition:
    hash.sha256(0, filesize) == "94cba66e8937b1b065e55b8174f5c349eab9a170cc41dd1aa3c5d96a620e09a2"
}

rule MalwareBazaar_unknown_099_b078582b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b078582be2c3464848f3f891f249d7a9ae7317cf4405d78e99ea2fa43354bd1f"
    family = "unknown"
    file_name = "b078582be2c3464848f3f891f249d7a9ae7317cf4405d78e99ea2fa43354bd1f.exe"
    file_type = "exe"
    first_seen = "2026-08-28 00:10:59"
  condition:
    hash.sha256(0, filesize) == "b078582be2c3464848f3f891f249d7a9ae7317cf4405d78e99ea2fa43354bd1f"
}

rule MalwareBazaar_unknown_100_fdd903d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdd903d07811d9e1c843a8c4527936468e54d827cf8cfcc4ff896792c9fced76"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-28 00:01:38"
  condition:
    hash.sha256(0, filesize) == "fdd903d07811d9e1c843a8c4527936468e54d827cf8cfcc4ff896792c9fced76"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-01

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 640 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 640 |
| Unique family labels | 14 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 40 |
| Mirai | 38 |
| Vidar | 6 |
| CoinMiner | 3 |
| ConnectWise | 3 |
| Stealc | 2 |
| Heodo | 1 |
| Formbook | 1 |
| AgentTesla | 1 |
| ACRStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 38 |
| elf | 37 |
| sh | 15 |
| unknown | 6 |
| js | 1 |
| tar | 1 |
| msi | 1 |
| hta | 1 |

## Per-Sample Analysis

### Sample 1: `8a6f1135fc2c48b4`

| Field | Value |
|---|---|
| SHA-256 | `8a6f1135fc2c48b4fe2de478e87dc158b78b708c7879ba6a0bca58087434fe27` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-09-01 05:14:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efb11e6c6b2d00aef0c5002cc601846f` |
| SHA-1 | `e2cf8a874d193b91a2d06cc7cffd93a19756d95c` |
| SHA-256 | `8a6f1135fc2c48b4fe2de478e87dc158b78b708c7879ba6a0bca58087434fe27` |
| SHA3-384 | `fc55d5ebc051e368043cc448efcafbdc70ab4a7f589238c32f4dccb15b92d074391acdf76edae2c98392d6f303976dd9` |
| TLSH | `T19301CCCD26916147C56CCD08746F8A04964683C6F4BB5E1EEC8868FB9CD5708F069F4B` |
| SSDEEP | `12:+f22j+lf2oq+lf2UNNIl5zA+lf2d0LKj+lf2TgOs+lf2leC+lf2PON/+lf2nSE+J:q/G1tzNI7fTKGX8bF1qmC/tBTYZEjxn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_8a6f1135
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a6f1135fc2c48b4fe2de478e87dc158b78b708c7879ba6a0bca58087434fe27"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-09-01 05:14:44"
  condition:
    hash.sha256(0, filesize) == "8a6f1135fc2c48b4fe2de478e87dc158b78b708c7879ba6a0bca58087434fe27"
}
```

### Sample 2: `3f406f1968f6c475`

| Field | Value |
|---|---|
| SHA-256 | `3f406f1968f6c47503b8ef56a39540d6cf3b2b7c80f6f58e952be5987eae64a5` |
| Family label | `Mirai` |
| File name | `3f406f1968f6c47503b8ef56a39540d6cf3b2b7c80f6f58e952be5987eae64a5.elf` |
| File type | `elf` |
| First seen | `2026-09-01 05:06:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b20a2beec7e081c2d1fe8abc1607a8b7` |
| SHA-1 | `b365b8e00fae34751f301ec1f1f1797facf8e90d` |
| SHA-256 | `3f406f1968f6c47503b8ef56a39540d6cf3b2b7c80f6f58e952be5987eae64a5` |
| SHA3-384 | `fec443000acf966b9d4df0421a92774183db1b5a7a155bf278c65666f3fc1e9e874145a8b9b241a5e4013e536910c9d9` |
| TLSH | `T19FF37CC1A9E3E0F1E5A3497A436F971A4A36D4370219DA01FB2E68347F46050E7BB79C` |
| TELFHASH | `t16c611bf56e7e08ecb7809c05a64e2f116e4e677b256472f604f3982532afd4141bad3c` |
| SSDEEP | `3072:do5lrHgJcLAVp9myCSCbsjoyzINpcyn8J1EssMZc/T03ImIys61X2h5or:mRHgJiAVNoyUncyn8EssMOjh5or` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_3f406f19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f406f1968f6c47503b8ef56a39540d6cf3b2b7c80f6f58e952be5987eae64a5"
    family = "Mirai"
    file_name = "3f406f1968f6c47503b8ef56a39540d6cf3b2b7c80f6f58e952be5987eae64a5.elf"
    file_type = "elf"
    first_seen = "2026-09-01 05:06:59"
  condition:
    hash.sha256(0, filesize) == "3f406f1968f6c47503b8ef56a39540d6cf3b2b7c80f6f58e952be5987eae64a5"
}
```

### Sample 3: `0ec3487f79cb0fc4`

| Field | Value |
|---|---|
| SHA-256 | `0ec3487f79cb0fc47ea70ce3f93b13bb3013e54cd65c2e9b3c83c4663652321f` |
| Family label | `unknown` |
| File name | `0ec3487f79cb0fc47ea70ce3f93b13bb3013e54cd65c2e9b3c83c4663652321f.exe` |
| File type | `exe` |
| First seen | `2026-09-01 04:52:22` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e055e41b4fcfae545c51506fa16d4085` |
| SHA-1 | `ee1089ea700471032c96531f52316c359ee2e696` |
| SHA-256 | `0ec3487f79cb0fc47ea70ce3f93b13bb3013e54cd65c2e9b3c83c4663652321f` |
| SHA3-384 | `173362f75f99d79d38155fa15d00413f171541b7fd8b0d03ac6c83f79962cef8f13128192428b149852955a79376206d` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T194E52354BDC67BB2E07AC3BB42E3A0BE3129378589A44C9D37896B113E639183D77345` |
| SSDEEP | `49152:/3VoV1Q8nE6+a9iD4KYDVyJv+CZXG+Eoi+IQywxoE9nLOf6OuEm3wHFiyr/Vkfvr:yV1QMETfcDsdZcrwGwn0Vrqwljrm5s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_0ec3487f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ec3487f79cb0fc47ea70ce3f93b13bb3013e54cd65c2e9b3c83c4663652321f"
    family = "unknown"
    file_name = "0ec3487f79cb0fc47ea70ce3f93b13bb3013e54cd65c2e9b3c83c4663652321f.exe"
    file_type = "exe"
    first_seen = "2026-09-01 04:52:22"
  condition:
    hash.sha256(0, filesize) == "0ec3487f79cb0fc47ea70ce3f93b13bb3013e54cd65c2e9b3c83c4663652321f"
}
```

### Sample 4: `774560697fd43c07`

| Field | Value |
|---|---|
| SHA-256 | `774560697fd43c072b6fa4b4719542370b15a3d932a924496af2193ae4e30cfb` |
| Family label | `Vidar` |
| File name | `774560697fd43c072b6fa4b4719542370b15a3d932a924496af2193ae4e30cfb.bin` |
| File type | `exe` |
| First seen | `2026-09-01 04:48:39` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bff0fbba2e5fbee4e5b5a9ce2ea707e` |
| SHA-1 | `162dd07032d4d3a683272b51c4a86271a2a22df1` |
| SHA-256 | `774560697fd43c072b6fa4b4719542370b15a3d932a924496af2193ae4e30cfb` |
| SHA3-384 | `18ba048f9a328c3fa30fcea9eab59dfdd7ac45a730db13b3a9481e67c5d5c5d472f4884bb2febba0afec1b14155d3415` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1691833075C91106AD25AA636D87A1552BB74BC4D973133E72F80E7B82E337C14EBAF18` |
| SSDEEP | `1572864:9QOw6y5oMu8oBV8dyfwFW7pJaTa3dqcYJH+Ij6m509ioh1VhyoxhqWgYfM/:eto7grerEKY/6ma9iQVhywhDg6M/` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_004_77456069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "774560697fd43c072b6fa4b4719542370b15a3d932a924496af2193ae4e30cfb"
    family = "Vidar"
    file_name = "774560697fd43c072b6fa4b4719542370b15a3d932a924496af2193ae4e30cfb.bin"
    file_type = "exe"
    first_seen = "2026-09-01 04:48:39"
  condition:
    hash.sha256(0, filesize) == "774560697fd43c072b6fa4b4719542370b15a3d932a924496af2193ae4e30cfb"
}
```

### Sample 5: `8ada7f5b671c1b3f`

| Field | Value |
|---|---|
| SHA-256 | `8ada7f5b671c1b3fad199826203eb4e5dbd1c6a8cf1791100651ac24358daef4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 04:40:10` |
| Reporter | `Bitsight` |
| Tags | `BB2.file, dropped-by-GCleaner, exe, F` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7f307ac60038e66cf8951bba64414d4` |
| SHA-1 | `9577ed72881b5b4b720737d628bcfc1bb837d132` |
| SHA-256 | `8ada7f5b671c1b3fad199826203eb4e5dbd1c6a8cf1791100651ac24358daef4` |
| SHA3-384 | `6a4e9b6f1ca1da0af1cdbcd6a402925d07d28d1aef07a45fee4d5eda639d4391b31a0e3bc2b1845f91a72c14e4bd545e` |
| IMPHASH | `c58a6fdd5514cc5114ad09dc07384b11` |
| TLSH | `T13CB52321B7C29073E57A1935AF38A719983C2C611FA6D5CBA3C02E5FAA305C1DB34327` |
| SSDEEP | `49152:AToifr9FXth5yR/vTrm4uW0+LH+qvLQGj9HJ7I7Pe8gmLi7SrH:ABrVov+4uvSH+qUCBJ7Ce0ESrH` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_8ada7f5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ada7f5b671c1b3fad199826203eb4e5dbd1c6a8cf1791100651ac24358daef4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 04:40:10"
  condition:
    hash.sha256(0, filesize) == "8ada7f5b671c1b3fad199826203eb4e5dbd1c6a8cf1791100651ac24358daef4"
}
```

### Sample 6: `b8b9654b57a0445e`

| Field | Value |
|---|---|
| SHA-256 | `b8b9654b57a0445ea1f5645d0f6063df790448dea4d5ae27d502a2b136bb8da1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 04:30:02` |
| Reporter | `Bitsight` |
| Tags | `B, BB5.file, dropped-by-GCleaner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5f84de99312955e298fd47bb1e3f1fa` |
| SHA-1 | `73f969a2cbff7f6184192566500acdc32f0b3777` |
| SHA-256 | `b8b9654b57a0445ea1f5645d0f6063df790448dea4d5ae27d502a2b136bb8da1` |
| SHA3-384 | `01c945570b6eedbf581e1aa0b116c2b4aefa1f0a2516ec4d33877daf4b0727406db1b69871ee0196373621e0fca84ac4` |
| IMPHASH | `395117ec633a907592db538201fb8168` |
| TLSH | `T112547D16B7A914FDED77813CC9421906EA727C5607A0DACF03A04A963F276E09E7F712` |
| SSDEEP | `6144:WsNfmj2A6875JAVmQFa64neI2KM2YL8//uoz:WUNAPAVjA7dcL8u` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_b8b9654b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8b9654b57a0445ea1f5645d0f6063df790448dea4d5ae27d502a2b136bb8da1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 04:30:02"
  condition:
    hash.sha256(0, filesize) == "b8b9654b57a0445ea1f5645d0f6063df790448dea4d5ae27d502a2b136bb8da1"
}
```

### Sample 7: `5159769b2b36c725`

| Field | Value |
|---|---|
| SHA-256 | `5159769b2b36c72598bb55b7d77340f95828e33c0e15fc0af186e9e94f6ed6ca` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-01 04:17:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d2655dd96414630257ab0a29f3b4c7a` |
| SHA-1 | `c97e8b88b38d6c7e9d987ff461789165b3ee6b02` |
| SHA-256 | `5159769b2b36c72598bb55b7d77340f95828e33c0e15fc0af186e9e94f6ed6ca` |
| SHA3-384 | `a0b0c448178d394b9dbfa219ad12758a38de5e11721167b1bdecdb9a398d4d55ea87198e8147b8b784be6bf45683287c` |
| TLSH | `T182236C6516857C14AA98C4365C7F2F0CB9AD43E6314492EE7FCA3CF28C4A6ADA20861D` |
| SSDEEP | `768:lr9NyXsZztCm9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:tHusZOcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_5159769b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5159769b2b36c72598bb55b7d77340f95828e33c0e15fc0af186e9e94f6ed6ca"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-01 04:17:57"
  condition:
    hash.sha256(0, filesize) == "5159769b2b36c72598bb55b7d77340f95828e33c0e15fc0af186e9e94f6ed6ca"
}
```

### Sample 8: `7397b8cf285c24e2`

| Field | Value |
|---|---|
| SHA-256 | `7397b8cf285c24e2cb4472a096538782aeb05d9189667bcd4f1798cf76aaee64` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-01 04:16:27` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6c4a276a097b85ea427dc165b0be24b` |
| SHA-1 | `660de12784ed426334d6372cf71541c13cfd794e` |
| SHA-256 | `7397b8cf285c24e2cb4472a096538782aeb05d9189667bcd4f1798cf76aaee64` |
| SHA3-384 | `a7eba3d43f3ac15facb96fff710457421d1b4d587f4b296a0eb8be497cbf3e2b506aa32d96c9468d6787b8c3dab797db` |
| TLSH | `T1513183DB04205E325112CA9D73B6344C668EE5EB2C8FC3D4E8590EEA928C7CCF562B49` |
| SSDEEP | `24:Jv+NYFuF8FfFIT709z2k1kxJW7+cG4GV/koPAUVapzTjHdAv:kTwhlmxJW7+cJ5oMpzTjHdAv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_7397b8cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7397b8cf285c24e2cb4472a096538782aeb05d9189667bcd4f1798cf76aaee64"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-01 04:16:27"
  condition:
    hash.sha256(0, filesize) == "7397b8cf285c24e2cb4472a096538782aeb05d9189667bcd4f1798cf76aaee64"
}
```

### Sample 9: `dc07a66104714414`

| Field | Value |
|---|---|
| SHA-256 | `dc07a6610471441482aa3261e1f5b49078f97be9177774de2abd569b62889f7b` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-01 04:13:19` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37a985ef811d6776f715b550f1ba7057` |
| SHA-1 | `2e9a7cba03a063faccdfae45c6e01737bee201c7` |
| SHA-256 | `dc07a6610471441482aa3261e1f5b49078f97be9177774de2abd569b62889f7b` |
| SHA3-384 | `9f468bab8dd0d789be12b7a8766969f0ed10a63ad0f306b097091bbe09f19939a458709825215a82cac98365b262fb78` |
| TLSH | `T1E3C27E966E867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:28vCB+25j6es8R6y9FYpMSUpi+20qUpi+20YQX:28l25Jxd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_dc07a661
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc07a6610471441482aa3261e1f5b49078f97be9177774de2abd569b62889f7b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-01 04:13:19"
  condition:
    hash.sha256(0, filesize) == "dc07a6610471441482aa3261e1f5b49078f97be9177774de2abd569b62889f7b"
}
```

### Sample 10: `ed36bed1b59a5608`

| Field | Value |
|---|---|
| SHA-256 | `ed36bed1b59a5608984b00f914b2f9e4a98790f2f181cbb89f31f3d1a6531ed4` |
| Family label | `unknown` |
| File name | `ed36bed1b59a5608984b00f914b2f9e4a98790f2f181cbb89f31f3d1a6531ed4.bin` |
| File type | `exe` |
| First seen | `2026-09-01 04:12:46` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c81586b06b76ab3cc5a746f1add767d8` |
| SHA-1 | `1eddb1e08c9ac334bd7d40799230e94a883a2b1c` |
| SHA-256 | `ed36bed1b59a5608984b00f914b2f9e4a98790f2f181cbb89f31f3d1a6531ed4` |
| SHA3-384 | `0225216004df233f6345fb8a74c8efb41a8428da4e6c37e10836df7e809a585efd82b15c63bb3411af5d446c8157f237` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1FF366A03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaai:uc3XND1aJrCOki` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_ed36bed1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed36bed1b59a5608984b00f914b2f9e4a98790f2f181cbb89f31f3d1a6531ed4"
    family = "unknown"
    file_name = "ed36bed1b59a5608984b00f914b2f9e4a98790f2f181cbb89f31f3d1a6531ed4.bin"
    file_type = "exe"
    first_seen = "2026-09-01 04:12:46"
  condition:
    hash.sha256(0, filesize) == "ed36bed1b59a5608984b00f914b2f9e4a98790f2f181cbb89f31f3d1a6531ed4"
}
```

### Sample 11: `c40e58e9eda2d0a7`

| Field | Value |
|---|---|
| SHA-256 | `c40e58e9eda2d0a753c5a6bce142b758d437d2878f5ae39d8486824881261128` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-01 03:39:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29c583af94d4743bf06a82ba99046bdd` |
| SHA-1 | `2bf5b7754c4ed8dc31522f3c5a36a4a28d88e746` |
| SHA-256 | `c40e58e9eda2d0a753c5a6bce142b758d437d2878f5ae39d8486824881261128` |
| SHA3-384 | `9f579de6573f17c8445290246393413106f68e952d587e013743d0905c9c403eaca6c2c0d6ecea6b536db2ed5791d9e1` |
| TLSH | `T1F7C3B74E6F319F7DFAA8C23487B39F21975923E623E1C585E1ACD6011D6034E681FBA4` |
| TELFHASH | `t1f1216a18493413f097b15cde6aecff76e5a070ef5a165e378e00f9ad9a5c9428d01c2c` |
| SSDEEP | `1536:AiIjetocXg/vXtUEwNdX56FpyRd7xK43vQN2fTmmr13woGeH8sYm5yXel9rNi:ACDOyRd9K43vQN2fTmmJ3woomLDrQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_c40e58e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c40e58e9eda2d0a753c5a6bce142b758d437d2878f5ae39d8486824881261128"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-01 03:39:47"
  condition:
    hash.sha256(0, filesize) == "c40e58e9eda2d0a753c5a6bce142b758d437d2878f5ae39d8486824881261128"
}
```

### Sample 12: `2b371117fd3dc235`

| Field | Value |
|---|---|
| SHA-256 | `2b371117fd3dc235ab72fa57397da7ed522ab65c665b2b0d62526ceafa3aa2c3` |
| Family label | `Heodo` |
| File name | `爱接码平台客户端.exe` |
| File type | `exe` |
| First seen | `2026-09-01 03:29:56` |
| Reporter | `CNGaoLing` |
| Tags | `Emotet, exe, Heodo, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1813869bc6abb707250d89ae8b57ccb1` |
| SHA-1 | `a2d518da5c2c73c5f209cec920532d756e7d931f` |
| SHA-256 | `2b371117fd3dc235ab72fa57397da7ed522ab65c665b2b0d62526ceafa3aa2c3` |
| SHA3-384 | `c3e06a45afa20e5cbb7206c7d571c9f472ed1a88727252d6e9719689db229778dee867f328bece6f4f4e0c288e3f5b89` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T15416023FB28B653EE06A5A367A76A210553F766165138C16D7F4C88CCF250B01E3FB86` |
| SSDEEP | `49152:puI2h0/UpSX/OSU/arO4Eo2uVryCoEjXecfxGeJF82hbNYFWfoSL3rdf/rVltjkY:p5O0/DlEarZEo2ayCoAppHJm2rJztF` |
| ICON-DHASH | `a24d8d35373e3025` |

#### Technical Assessment

- The sample is tracked as `Heodo` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Heodo_012_2b371117
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b371117fd3dc235ab72fa57397da7ed522ab65c665b2b0d62526ceafa3aa2c3"
    family = "Heodo"
    file_name = "爱接码平台客户端.exe"
    file_type = "exe"
    first_seen = "2026-09-01 03:29:56"
  condition:
    hash.sha256(0, filesize) == "2b371117fd3dc235ab72fa57397da7ed522ab65c665b2b0d62526ceafa3aa2c3"
}
```

### Sample 13: `5fc2d30f108373d1`

| Field | Value |
|---|---|
| SHA-256 | `5fc2d30f108373d11a5bcb3c6b6f840bb13506b7211ff088c83d9f3ca4b3b403` |
| Family label | `Formbook` |
| File name | `Harga RFQ New 0260891566.pdf.js` |
| File type | `js` |
| First seen | `2026-09-01 03:28:23` |
| Reporter | `threatcat_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29a02f10c81c3b42f0c0324484427707` |
| SHA-1 | `e8efd72c6c652ba2f8bc28f762bdf4018104e7ec` |
| SHA-256 | `5fc2d30f108373d11a5bcb3c6b6f840bb13506b7211ff088c83d9f3ca4b3b403` |
| SHA3-384 | `3367e095e662d3453555b32b137a5034132945e05c2e39cfe431855b2a4ea2729504df5c25f20551a0afd553dfc2a3fe` |
| TLSH | `T128920E05589238849373677B631BA8D0E7BB076B0144494BB8BCB8819FF2D1DCED59BA` |
| SSDEEP | `384:5UIheQKVDiUi/PeNkyvNAedmy2BQ0EpSgQrC37n8wZn/2VJ21Ky6656BkTMcB43v:eIheQ2DiUi/PeNJvNAedr2BQjYgQrC3+` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_013_5fc2d30f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fc2d30f108373d11a5bcb3c6b6f840bb13506b7211ff088c83d9f3ca4b3b403"
    family = "Formbook"
    file_name = "Harga RFQ New 0260891566.pdf.js"
    file_type = "js"
    first_seen = "2026-09-01 03:28:23"
  condition:
    hash.sha256(0, filesize) == "5fc2d30f108373d11a5bcb3c6b6f840bb13506b7211ff088c83d9f3ca4b3b403"
}
```

### Sample 14: `2ae07d8c604e0156`

| Field | Value |
|---|---|
| SHA-256 | `2ae07d8c604e0156932d22eba1f0da929821c1956a4a8830135b8a9bb40bb61e` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-01 03:22:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43f047ef3b95d1a805d25da4c9bd057b` |
| SHA-1 | `6b939e580085d386757182e6976e3af13b0cfa4d` |
| SHA-256 | `2ae07d8c604e0156932d22eba1f0da929821c1956a4a8830135b8a9bb40bb61e` |
| SHA3-384 | `7113a585d9dcd1dbd5195cb20de25383330f7277e2485c694ad37b7a286752e1b08e961c35c1778656a54d5d561cdac0` |
| TLSH | `T1A1235C512A857C14AA98C8371D7F2F0CB9A943E6324452DE7FCF3CF68C4AADD920961D` |
| SSDEEP | `768:hQFWzZx5/9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:akzicr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_2ae07d8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ae07d8c604e0156932d22eba1f0da929821c1956a4a8830135b8a9bb40bb61e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-01 03:22:42"
  condition:
    hash.sha256(0, filesize) == "2ae07d8c604e0156932d22eba1f0da929821c1956a4a8830135b8a9bb40bb61e"
}
```

### Sample 15: `bd7245522ba1de1a`

| Field | Value |
|---|---|
| SHA-256 | `bd7245522ba1de1a91f39588b5a9bd7d5fe947accaa0af28af138935b415e36d` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 03:19:38` |
| Reporter | `Bitsight` |
| Tags | `B, BB4.file, dropped-by-GCleaner, exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7915a6bc8875365dd0faf15f25aab41` |
| SHA-1 | `b61a9f87bb852c8a4cd44300c154f0de2612383e` |
| SHA-256 | `bd7245522ba1de1a91f39588b5a9bd7d5fe947accaa0af28af138935b415e36d` |
| SHA3-384 | `6c42d4b87981ecfdf6fdfd2ad5480d88fec15d10f1fe7708b9c34206aa3115a56093c059de0f4b6348a621b96e15cd27` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T197264903BD9508F9C19AA73189B74252BB74BC4C4B3133E32E60AAB82F767D15E35B54` |
| SSDEEP | `49152:wKnLG56cO0iAdicM2h/W3vCU+EWaerfNSpQRbsqBzu7lorp1JN8ck:wf/9luvd+EWZNSpcbBygn` |
| ICON-DHASH | `b29269e8ece4e8b2` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_015_bd724552
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd7245522ba1de1a91f39588b5a9bd7d5fe947accaa0af28af138935b415e36d"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 03:19:38"
  condition:
    hash.sha256(0, filesize) == "bd7245522ba1de1a91f39588b5a9bd7d5fe947accaa0af28af138935b415e36d"
}
```

### Sample 16: `20dba69956576e1b`

| Field | Value |
|---|---|
| SHA-256 | `20dba69956576e1be144cdebbfba349c1bb70eed69be10061426b6aedb63185d` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-01 03:18:29` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acc52e0779066b81ab8d1da42af619d3` |
| SHA-1 | `8b03fa2cfeb46a251d711b77a308edfca7ded294` |
| SHA-256 | `20dba69956576e1be144cdebbfba349c1bb70eed69be10061426b6aedb63185d` |
| SHA3-384 | `83bcf34f655767863114a1ec97879b95ee82a3ed6e889ead1bf59f70dd501bfbff9a6629c1fc1c5320c774814596e11c` |
| TLSH | `T1BCC28C966A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:b8vCB+25j6es8Ri9FYpMSUpi+20qUpi+20YQX:b8l25JEd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_20dba699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20dba69956576e1be144cdebbfba349c1bb70eed69be10061426b6aedb63185d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-01 03:18:29"
  condition:
    hash.sha256(0, filesize) == "20dba69956576e1be144cdebbfba349c1bb70eed69be10061426b6aedb63185d"
}
```

### Sample 17: `6b4ac27c66d4a77a`

| Field | Value |
|---|---|
| SHA-256 | `6b4ac27c66d4a77a4c2325afd61060001580043011194036c1a4a58702d836f7` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-01 03:16:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ca2abe20ac161fcedbd7a0d3e386576` |
| SHA-1 | `47e755175e8981503179cc4ac94e7ff226f9faf7` |
| SHA-256 | `6b4ac27c66d4a77a4c2325afd61060001580043011194036c1a4a58702d836f7` |
| SHA3-384 | `5b0f2c9af9628d4761b40ae2b381befe8b8bc422db76e0934e760e4c08f0a16e35e3a212dfe3a94c4f89d2bcce5cf01b` |
| TLSH | `T126C27D956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:NN8vCB+25j6es8RB9FYpMSUpi+20qUpi+20YQX:f8l25J3d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_6b4ac27c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b4ac27c66d4a77a4c2325afd61060001580043011194036c1a4a58702d836f7"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-01 03:16:33"
  condition:
    hash.sha256(0, filesize) == "6b4ac27c66d4a77a4c2325afd61060001580043011194036c1a4a58702d836f7"
}
```

### Sample 18: `8630ccb0f78e12c7`

| Field | Value |
|---|---|
| SHA-256 | `8630ccb0f78e12c7f7a283d49a34ff465c44ec994c874219d5c03bc7caf71abe` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-09-01 03:16:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2828d7a489228d5e9c12a8a2879a3a7e` |
| SHA-1 | `47ec193a08582d155894bad63317950a34b56c56` |
| SHA-256 | `8630ccb0f78e12c7f7a283d49a34ff465c44ec994c874219d5c03bc7caf71abe` |
| SHA3-384 | `a8bf82265cc1f436c1dab0542fa652831080745f65dea6415ce07ecdccd45309e21c6aae2885360acfed183c5f11d819` |
| TLSH | `T1BAD3ADABF34714A2C85202F003CB9B8D6D235292AE5BD5F73D1E1A37587A1CF1A16BD1` |
| SSDEEP | `1536:0K+km4GC9TGWeiNPVp4mdexBxlLiWr3xNKO/gty3bq+/LWU:cO9TGWdNrLdABxwWrr/g2Xq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_8630ccb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8630ccb0f78e12c7f7a283d49a34ff465c44ec994c874219d5c03bc7caf71abe"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-09-01 03:16:32"
  condition:
    hash.sha256(0, filesize) == "8630ccb0f78e12c7f7a283d49a34ff465c44ec994c874219d5c03bc7caf71abe"
}
```

### Sample 19: `6306fecf65be40a7`

| Field | Value |
|---|---|
| SHA-256 | `6306fecf65be40a727d3a199beb9bc3ad1a431b9af21ae66ef38d03655f89a95` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-09-01 03:16:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3d7a85ec61ae50cb499452f54bd8621` |
| SHA-1 | `d1b0a72e17ead88019add24195a344c20afaf5e7` |
| SHA-256 | `6306fecf65be40a727d3a199beb9bc3ad1a431b9af21ae66ef38d03655f89a95` |
| SHA3-384 | `79814e1ab904c7a3459fa29d2aba196b8d2824b70ca9588cef906b0057b5008fd44591f03231a98a6b17855309079454` |
| TLSH | `T19DA33B46FC824A12C6C516B7FB5E518D3B2643ECD2EA7203AE159F2137DB91B0D7B980` |
| TELFHASH | `t11631f0d5dba506ec33e1834552cf71658fa834ee7a1469b6de3c230f86462c2b13f422` |
| SSDEEP | `1536:23H6uUW7F7GdCaKFhUpwqVDKrX4W7oSstSG+pMgOeIcUiuX5Dm8vuyRDOH:m6uUW7F7Gsay8lQVstSG8nL4Ne` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_6306fecf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6306fecf65be40a727d3a199beb9bc3ad1a431b9af21ae66ef38d03655f89a95"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-01 03:16:31"
  condition:
    hash.sha256(0, filesize) == "6306fecf65be40a727d3a199beb9bc3ad1a431b9af21ae66ef38d03655f89a95"
}
```

### Sample 20: `503dd959a7d2fb53`

| Field | Value |
|---|---|
| SHA-256 | `503dd959a7d2fb5309e3870beb60a8c9ee518b71712dfd40161052fb838aef42` |
| Family label | `AgentTesla` |
| File name | `Payment_Advice_pdf.tar` |
| File type | `tar` |
| First seen | `2026-09-01 03:16:15` |
| Reporter | `nat` |
| Tags | `AgentTesla, tar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c80c2f7dd8d937d1db3a8b70076312bf` |
| SHA-1 | `d5fee08bcf992ee856c6a292eb743a2b34012931` |
| SHA-256 | `503dd959a7d2fb5309e3870beb60a8c9ee518b71712dfd40161052fb838aef42` |
| SHA3-384 | `4215702239f605632e69530103cc793edf04ea534283a22f6673391af03d4d816a6da01fb3f233fb01a7b75be42250ad` |
| TLSH | `T13E253308B97AE1F32F3000EB3055EF97B497CE9642414191A38F6EEA8EFD9256813DD5` |
| SSDEEP | `24576:anSP5aGI3nskpKvrNveeVEYdc+3R69wKfJ6K18auObTKF+01l3jDfAocq:045RILurMQZiOVKfJ6U9KQ01lz8oL` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `tar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_020_503dd959
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "503dd959a7d2fb5309e3870beb60a8c9ee518b71712dfd40161052fb838aef42"
    family = "AgentTesla"
    file_name = "Payment_Advice_pdf.tar"
    file_type = "tar"
    first_seen = "2026-09-01 03:16:15"
  condition:
    hash.sha256(0, filesize) == "503dd959a7d2fb5309e3870beb60a8c9ee518b71712dfd40161052fb838aef42"
}
```

### Sample 21: `45e959da77861667`

| Field | Value |
|---|---|
| SHA-256 | `45e959da778616679ad70a21ee3d179ca2e5f7a670dc96bc137cf411c7029723` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-01 03:11:48` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91a553eac22d875c9c29fdd00037fd84` |
| SHA-256 | `45e959da778616679ad70a21ee3d179ca2e5f7a670dc96bc137cf411c7029723` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_45e959da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45e959da778616679ad70a21ee3d179ca2e5f7a670dc96bc137cf411c7029723"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-01 03:11:48"
  condition:
    hash.sha256(0, filesize) == "45e959da778616679ad70a21ee3d179ca2e5f7a670dc96bc137cf411c7029723"
}
```

### Sample 22: `8610c817c54d0d1a`

| Field | Value |
|---|---|
| SHA-256 | `8610c817c54d0d1a4435fb8d604106281d43ec98eb1665d176f0467b50e67ca2` |
| Family label | `Mirai` |
| File name | `8610c817c54d0d1a4435fb8d604106281d43ec98eb1665d176f0467b50e67ca2.elf` |
| File type | `elf` |
| First seen | `2026-09-01 02:58:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28fbbd59d3b4af6a027e6562b9f94f37` |
| SHA-1 | `1f5720a3dc033b56057e40f620d0010444f67a1c` |
| SHA-256 | `8610c817c54d0d1a4435fb8d604106281d43ec98eb1665d176f0467b50e67ca2` |
| SHA3-384 | `0daa90e4397e04efc33dfdd5bf35fe6c3f705565e18fbbc5e71b64e1ec2bb79ccd75caed0eef45d4d593b396606a0ae3` |
| TLSH | `T1E9934A07F99180FDC456C13803BEBA36DC73F4EE1238B25B6BD0FE252D58D612A19A65` |
| TELFHASH | `t1e0313fb13a991d9891e7e635f34bf8a3d9220e6014d136e19f37ace6cf653d14c51432` |
| SSDEEP | `1536:ZcSbeuewgVc1UTbH+KWaZV0x3YQtcy+OPr7zGQNoRTNuh2HAyGGL4:ZIuVg8ebeKWDLfPTGQ4TNuOLL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_8610c817
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8610c817c54d0d1a4435fb8d604106281d43ec98eb1665d176f0467b50e67ca2"
    family = "Mirai"
    file_name = "8610c817c54d0d1a4435fb8d604106281d43ec98eb1665d176f0467b50e67ca2.elf"
    file_type = "elf"
    first_seen = "2026-09-01 02:58:07"
  condition:
    hash.sha256(0, filesize) == "8610c817c54d0d1a4435fb8d604106281d43ec98eb1665d176f0467b50e67ca2"
}
```

### Sample 23: `1bdabbd4b6ce4905`

| Field | Value |
|---|---|
| SHA-256 | `1bdabbd4b6ce490592faeaa2f5a45992bb396c52664c8a188aff0955b78a5d75` |
| Family label | `Mirai` |
| File name | `1bdabbd4b6ce490592faeaa2f5a45992bb396c52664c8a188aff0955b78a5d75.elf` |
| File type | `elf` |
| First seen | `2026-09-01 02:58:00` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98c816a34539d1b537b02374696f1dff` |
| SHA-1 | `96062d3648b083aea774d3d17cd3315cb26f87c3` |
| SHA-256 | `1bdabbd4b6ce490592faeaa2f5a45992bb396c52664c8a188aff0955b78a5d75` |
| SHA3-384 | `3acb1d1b17d88abc9a381d665b75739a163dd9d0fcc8f55eb7e622dec5cd34d7188fc213aab60ff0276d04f07b503bab` |
| TLSH | `T1E5044B46E6408A13C0D717BABA9F5245333397B4E3DB73069A28AFB43F8675A0E77501` |
| TELFHASH | `t12031cdb1272a85156a61ce989decb7b6411d87172346ef33ef29849c141909ae529c0f` |
| SSDEEP | `3072:RqJW84DNmCqDjOGB+n+s5MXqVgzOSJ2P8TcPSdYDGbyez1MpaVNcRReGGYfHaKVY:PKjOGB+n+s5MXqVgzOSJ2P8TcPSdYDGR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_1bdabbd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bdabbd4b6ce490592faeaa2f5a45992bb396c52664c8a188aff0955b78a5d75"
    family = "Mirai"
    file_name = "1bdabbd4b6ce490592faeaa2f5a45992bb396c52664c8a188aff0955b78a5d75.elf"
    file_type = "elf"
    first_seen = "2026-09-01 02:58:00"
  condition:
    hash.sha256(0, filesize) == "1bdabbd4b6ce490592faeaa2f5a45992bb396c52664c8a188aff0955b78a5d75"
}
```

### Sample 24: `d060ee9b0fbd1f2c`

| Field | Value |
|---|---|
| SHA-256 | `d060ee9b0fbd1f2c3067ed1ea0c105deaa1985e78a04fc89b599841433d52b9c` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-01 02:57:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b933dcd32ac11efcf198c15a710d229c` |
| SHA-1 | `ab4e51784796be677d72ec7d781bbffe4326939b` |
| SHA-256 | `d060ee9b0fbd1f2c3067ed1ea0c105deaa1985e78a04fc89b599841433d52b9c` |
| SHA3-384 | `f20bf0d9669e036a220ea25f90aa2b3fcabce2e6095811fe875f5161da13ba870da859bcf7ab3e25033e4b5acbb6493b` |
| TLSH | `T1CFC3F84DBF611EB7D86FDC3705AA2B4228CD555721A93B75B170C928B20B24F19E3CB4` |
| SSDEEP | `1536:1SmmcugIHP1HGCaISAH1psOZeKP77GGYWs9R6TePcPQzvZSYtC3Wp2kAuk6PGy4u:1rmTgsP1HGCd9ebmeBzvLN3PHir` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_d060ee9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d060ee9b0fbd1f2c3067ed1ea0c105deaa1985e78a04fc89b599841433d52b9c"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-01 02:57:18"
  condition:
    hash.sha256(0, filesize) == "d060ee9b0fbd1f2c3067ed1ea0c105deaa1985e78a04fc89b599841433d52b9c"
}
```

### Sample 25: `386df9ad75375fa7`

| Field | Value |
|---|---|
| SHA-256 | `386df9ad75375fa794a0caf827cce7025f179368ac9389a5db47bc4c40f6d954` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-01 02:52:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e12af97584d2e58ffcdfe1563bba652` |
| SHA-1 | `85c3d71494da8be00b7a3272c5b3824dfaef5b39` |
| SHA-256 | `386df9ad75375fa794a0caf827cce7025f179368ac9389a5db47bc4c40f6d954` |
| SHA3-384 | `a385960f4ddeac26a4ad4e31a92569749f1474f076c8106f2d864299a435b576fbbf85effcc19a9aac66c694bf0580b8` |
| TLSH | `T1E8B33B87F800DD7DF80BD6BA45630E0AB930A3A14A931B337767FD63EC721951926E81` |
| SSDEEP | `3072:+pumESClt2V2YjoeJyrvbyPZfh0/OsL/42W260yu:+paRt2V2YjozyPtu/pLQ260yu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_386df9ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "386df9ad75375fa794a0caf827cce7025f179368ac9389a5db47bc4c40f6d954"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-01 02:52:38"
  condition:
    hash.sha256(0, filesize) == "386df9ad75375fa794a0caf827cce7025f179368ac9389a5db47bc4c40f6d954"
}
```

### Sample 26: `02c05faa97ebc77d`

| Field | Value |
|---|---|
| SHA-256 | `02c05faa97ebc77db971a14b06fd99ec004e669b662a55d520031b1bed808199` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-09-01 02:51:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d7e10df86bcb04b1051e320bc445652` |
| SHA-1 | `6bd590fce821bedb3da8a8702dd29c33117432a3` |
| SHA-256 | `02c05faa97ebc77db971a14b06fd99ec004e669b662a55d520031b1bed808199` |
| SHA3-384 | `56dd4b41703dd951d176aab19133e8f00f2c56556725054ebf5105d1505dae1b5c5261d488b4a6e7bbf1c6055f43925b` |
| TLSH | `T15B933A86F98780F5C84748706167F63FDA31D8E92171C69DEFA58F31CA33A419623B89` |
| TELFHASH | `t19731c8fa197e0ce4a7d45802924e2f313e4db37b2860727315f3a434326ba81557bc39` |
| SSDEEP | `1536:ql0oaz5Lo7HgfupPyEe9lKGIGHFxMyW4sOlVi37wLdmbHcfCoyIZT:O0XNLoHgm/GIcFcx6837wJmwT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_02c05faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02c05faa97ebc77db971a14b06fd99ec004e669b662a55d520031b1bed808199"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-01 02:51:20"
  condition:
    hash.sha256(0, filesize) == "02c05faa97ebc77db971a14b06fd99ec004e669b662a55d520031b1bed808199"
}
```

### Sample 27: `1932cf80c5dac61c`

| Field | Value |
|---|---|
| SHA-256 | `1932cf80c5dac61c0e59a7ccb7efae5314e87645b304f4a4bc81ceecc16a4dde` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-01 02:49:39` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a5864bba6121cd58fbc2fe1bdd7d408` |
| SHA-1 | `7c8c210171841f01b0c939e6d4a4ae9e10c5a86c` |
| SHA-256 | `1932cf80c5dac61c0e59a7ccb7efae5314e87645b304f4a4bc81ceecc16a4dde` |
| SHA3-384 | `275e95fc5fc331d1bc5d4c7df32d830b6e95e97c39dc2c35d4300ce6b5cbfb2340ffe7426d3133d3b15924a1c2342795` |
| TLSH | `T128A1FA757781B0296BE611E6B57BA718363D4250340B4022EBAEFCD23C25D5B409BF85` |
| SSDEEP | `96:nIzJBd5pAJ9/OEeg2J9LCBCfq/0CqR4oDt/J4n6vDjfq97BoL:IzJBd5pAKEj8qCfY0hBJVDjfAyL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_1932cf80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1932cf80c5dac61c0e59a7ccb7efae5314e87645b304f4a4bc81ceecc16a4dde"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-01 02:49:39"
  condition:
    hash.sha256(0, filesize) == "1932cf80c5dac61c0e59a7ccb7efae5314e87645b304f4a4bc81ceecc16a4dde"
}
```

### Sample 28: `b96706b34eff4a73`

| Field | Value |
|---|---|
| SHA-256 | `b96706b34eff4a7301245feaf1b7f6e869977daaa9cc5f27822bd679ee1f472b` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-01 02:49:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `201de3aba2d22990974ebd89284e325d` |
| SHA-1 | `f2e6407287dc19f722b6af715b59d1cb155c5b28` |
| SHA-256 | `b96706b34eff4a7301245feaf1b7f6e869977daaa9cc5f27822bd679ee1f472b` |
| SHA3-384 | `e3587b367e960fe85abc1f80d01758740648f49c19d6055fcf313723b74c7885495493c6fdfd329754d490e109d25d90` |
| TLSH | `T117939E62C8654D94C66140F071A8EE3A5B33C0C052877FF766AAC6B5A49BECDF805BF4` |
| SSDEEP | `1536:vn/5q7QbHT30D9d8DA/KDJuT7FEsOQCT3ELa8GyBjzH:vYgHTob8DAiDCisOQW8Pdb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_b96706b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b96706b34eff4a7301245feaf1b7f6e869977daaa9cc5f27822bd679ee1f472b"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-01 02:49:38"
  condition:
    hash.sha256(0, filesize) == "b96706b34eff4a7301245feaf1b7f6e869977daaa9cc5f27822bd679ee1f472b"
}
```

### Sample 29: `f14759a0828bcafe`

| Field | Value |
|---|---|
| SHA-256 | `f14759a0828bcafe4e63de7b1e50b6952c98eec8d7515c3cb6ff77d21aff4ebe` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-01 02:45:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92ec460aff5fd5c976514fd52149d7a7` |
| SHA-1 | `34d5130957d575366c9ea29f1d5f9e3d64b65cbb` |
| SHA-256 | `f14759a0828bcafe4e63de7b1e50b6952c98eec8d7515c3cb6ff77d21aff4ebe` |
| SHA3-384 | `da1a5482a96138b5a9878fabd0aaf332dd33d071c46a198ded801ebed46ebe2dd69173e6d066574844b29b616ea5efcf` |
| TLSH | `T146B32A96F9818B11D5C516BAFA1E618D331307F8E3DE7213AE209F3567CA91B0E7B841` |
| TELFHASH | `t108e0269be70042d837e0638501ef32365a9c70cd2b4462e6a1546b4fc902e99f03a809` |
| SSDEEP | `3072:nqJWaAePmJqjOGB+n+V5MXqVgzOSJ2P8TcPSdYDspyw7wZa3D0rUWJ+n58Rn:PqjOGB+n+V5MXqVgzOSJ2P8TcPSdYDOW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_f14759a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f14759a0828bcafe4e63de7b1e50b6952c98eec8d7515c3cb6ff77d21aff4ebe"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-01 02:45:27"
  condition:
    hash.sha256(0, filesize) == "f14759a0828bcafe4e63de7b1e50b6952c98eec8d7515c3cb6ff77d21aff4ebe"
}
```

### Sample 30: `3d578e83e82ac112`

| Field | Value |
|---|---|
| SHA-256 | `3d578e83e82ac112c0dedc3f390b7ecbbca4ee77b4f50bff900bd30663bfe20f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-01 02:45:26` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fddd506a860cc54e9f6103be0ae0213` |
| SHA-1 | `8bbd518710f31c4ee9d03d2e7fb284216d4c2a8a` |
| SHA-256 | `3d578e83e82ac112c0dedc3f390b7ecbbca4ee77b4f50bff900bd30663bfe20f` |
| SHA3-384 | `6cfacbb8eda9e8075f07195cebdc6ab0b6c362ad889b98188afee537be2c328e98c21cace03524fcaaba0e56d684eef0` |
| TLSH | `T152236C6616857C14AA98D4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5A69DD10872D` |
| SSDEEP | `768:jtXRWNGxVv9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:rlxWcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_3d578e83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d578e83e82ac112c0dedc3f390b7ecbbca4ee77b4f50bff900bd30663bfe20f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-01 02:45:26"
  condition:
    hash.sha256(0, filesize) == "3d578e83e82ac112c0dedc3f390b7ecbbca4ee77b4f50bff900bd30663bfe20f"
}
```

### Sample 31: `64a9ab0128ae49ec`

| Field | Value |
|---|---|
| SHA-256 | `64a9ab0128ae49ec44ce91019fedecd5676372564f84455b9c55215a8f31bbbd` |
| Family label | `Vidar` |
| File name | `64a9ab0128ae49ec44ce91019fedecd5676372564f84455b9c55215a8f31bbbd.bin` |
| File type | `exe` |
| First seen | `2026-09-01 02:31:09` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b64858880be2a14420e0b4f4f45fa797` |
| SHA-1 | `c294ef12a084c8d62585b02a7c3730ce0d162bec` |
| SHA-256 | `64a9ab0128ae49ec44ce91019fedecd5676372564f84455b9c55215a8f31bbbd` |
| SHA3-384 | `147972478c493ced4118b9664804c48fb2a3dc62fe335f873cf7825a542e9799f7731c3aa1d65f60ad0009f2322d47d5` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F2765A07BF914198C01BEA39C5679213B6757C8C8B3473EB2EA1A1382E3A7D12D79F54` |
| SSDEEP | `196608:jP1aGx4LQa9IEkGvQVNs5CZcOzkWBKv1RzvDfhIw:DqyCj` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_031_64a9ab01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64a9ab0128ae49ec44ce91019fedecd5676372564f84455b9c55215a8f31bbbd"
    family = "Vidar"
    file_name = "64a9ab0128ae49ec44ce91019fedecd5676372564f84455b9c55215a8f31bbbd.bin"
    file_type = "exe"
    first_seen = "2026-09-01 02:31:09"
  condition:
    hash.sha256(0, filesize) == "64a9ab0128ae49ec44ce91019fedecd5676372564f84455b9c55215a8f31bbbd"
}
```

### Sample 32: `1ef57112f92d5496`

| Field | Value |
|---|---|
| SHA-256 | `1ef57112f92d5496e7956dd4d037da219dcd133b92ec582cc2267b23f12c5b9f` |
| Family label | `unknown` |
| File name | `1ef57112f92d5496e7956dd4d037da219dcd133b92ec582cc2267b23f12c5b9f.exe` |
| File type | `exe` |
| First seen | `2026-09-01 02:22:33` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ab3a9df60651713928e1113708b01e1` |
| SHA-1 | `5662d74d54e6c6457ab4244418f29199d06b94d0` |
| SHA-256 | `1ef57112f92d5496e7956dd4d037da219dcd133b92ec582cc2267b23f12c5b9f` |
| SHA3-384 | `04f087ed0fc38d0bd3d45d811d183a932739b2e36ebf30d6e70d6ebf70e91e65987362e454b5ae2107543bf5aba5aca5` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T1E4D5238D7DB61971E832C7A28E92F46CB07D3B810F358E5E7BCE69008D669115C367B8` |
| SSDEEP | `49152:UqKvZv61siwNC1E7WPRuMHQZx7OTQiFjwL5FLcC3xfiSyJTzjQSqr9ZikY6/CVwb:IZC8NEEa51QZx6TQAjYFwChf/y5jZqrH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_1ef57112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ef57112f92d5496e7956dd4d037da219dcd133b92ec582cc2267b23f12c5b9f"
    family = "unknown"
    file_name = "1ef57112f92d5496e7956dd4d037da219dcd133b92ec582cc2267b23f12c5b9f.exe"
    file_type = "exe"
    first_seen = "2026-09-01 02:22:33"
  condition:
    hash.sha256(0, filesize) == "1ef57112f92d5496e7956dd4d037da219dcd133b92ec582cc2267b23f12c5b9f"
}
```

### Sample 33: `b57e4c2581991afb`

| Field | Value |
|---|---|
| SHA-256 | `b57e4c2581991afbd8c89d3dc89f48fbdcc38446d18bc5f1b8f8472f49c86456` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 02:09:58` |
| Reporter | `Bitsight` |
| Tags | `B, BB2.file, dropped-by-GCleaner, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed0a74cd8e6aad0c48d0558eb32ce0ae` |
| SHA-1 | `894061a1d992fa0f851bc0447fd1e91afd416e13` |
| SHA-256 | `b57e4c2581991afbd8c89d3dc89f48fbdcc38446d18bc5f1b8f8472f49c86456` |
| SHA3-384 | `debe81695548d42ccf4f47af197bdc53334517b7a25e280e7cd2a61b34629e7663d00898a0436a9a5091debdf41a5e86` |
| IMPHASH | `7c75a83e117d2bdfb2814c53e840c172` |
| TLSH | `T17CD6335A93E009FDF47BE1788E520D01C772BC550B62A64F17A4B9B61EB32E18F36B11` |
| SSDEEP | `393216:zKNOc51KP6oEkTx/mlGEERFDUo7Q3tEkTB5jT3BTqgk5:mNOcaCkVOlG1RpUos9EkTT9TqV5` |
| ICON-DHASH | `f0cc968a8a86c4c8` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_033_b57e4c25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b57e4c2581991afbd8c89d3dc89f48fbdcc38446d18bc5f1b8f8472f49c86456"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 02:09:58"
  condition:
    hash.sha256(0, filesize) == "b57e4c2581991afbd8c89d3dc89f48fbdcc38446d18bc5f1b8f8472f49c86456"
}
```

### Sample 34: `622632461f08d057`

| Field | Value |
|---|---|
| SHA-256 | `622632461f08d057fe5a14c61257bee3cad49bd0c7b89f571dff86debbdb37d9` |
| Family label | `unknown` |
| File name | `tfmb_0a954e02c5c334fc_0a954e02c5c334fced26459329feccbe9750614c0bdb1cb26e9196d5a2d7044b.exe` |
| File type | `exe` |
| First seen | `2026-09-01 02:06:30` |
| Reporter | `anonymous` |
| Tags | `ClickFix, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08002e145a5b211e9541ef43e43a2903` |
| SHA-1 | `82bd237e7e610f7126e26c879c80247b33880d35` |
| SHA-256 | `622632461f08d057fe5a14c61257bee3cad49bd0c7b89f571dff86debbdb37d9` |
| SHA3-384 | `5fa087d1a38e78cc0ecc6e3df9fdf6c758a198b36d1f2897d84ee0c25af66fe49ee2aa0d3b482f8c863e6e70264abb78` |
| TLSH | `T146F58D475891516AC1AAE679843A6512EAA0FC4DC33433F72FD0A6B02F727C15EBEF05` |
| SSDEEP | `49152:RD+feoalkLgM2+S4qVCeimNqt40rpX+w6KUZsfU0+fHMWioBXMA9wjXK562VrhDk:Re4My+qQFlp6/Zs+IUxwrS6Erc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_62263246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "622632461f08d057fe5a14c61257bee3cad49bd0c7b89f571dff86debbdb37d9"
    family = "unknown"
    file_name = "tfmb_0a954e02c5c334fc_0a954e02c5c334fced26459329feccbe9750614c0bdb1cb26e9196d5a2d7044b.exe"
    file_type = "exe"
    first_seen = "2026-09-01 02:06:30"
  condition:
    hash.sha256(0, filesize) == "622632461f08d057fe5a14c61257bee3cad49bd0c7b89f571dff86debbdb37d9"
}
```

### Sample 35: `2467a949be1e7b47`

| Field | Value |
|---|---|
| SHA-256 | `2467a949be1e7b47aa11edaf1263469e9baf307a3cc0713b2980539d31ec3dab` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 02:05:09` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, exe, Stealc, trickbox_v1_proxy` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `affcc0650b0502fdba71ab39f526f2ff` |
| SHA-1 | `58b04f1cbfdfedef6889152a5dc58c1eb28aaf6e` |
| SHA-256 | `2467a949be1e7b47aa11edaf1263469e9baf307a3cc0713b2980539d31ec3dab` |
| SHA3-384 | `57ce5c1e6afefafd9f8c0d7c663246431f03b177399a67873ed7b394c867ab4b12a98dcca7b74a99c797baf721c511f9` |
| IMPHASH | `7c75a83e117d2bdfb2814c53e840c172` |
| TLSH | `T161F52319D7E404FCE1B7E5B5CE464A52EB36BC4907B1EACF03B465A51F232909A3E702` |
| SSDEEP | `98304:MvOTcV1DqkOC+tcoYKwobrzKPq46tWAd0iX3zV:DTymw+Qibv82WNa` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_035_2467a949
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2467a949be1e7b47aa11edaf1263469e9baf307a3cc0713b2980539d31ec3dab"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 02:05:09"
  condition:
    hash.sha256(0, filesize) == "2467a949be1e7b47aa11edaf1263469e9baf307a3cc0713b2980539d31ec3dab"
}
```

### Sample 36: `8c91e9ab5fbeb884`

| Field | Value |
|---|---|
| SHA-256 | `8c91e9ab5fbeb88473034e12ff9feb159fb367353500bdd471a92dc022ba4c21` |
| Family label | `unknown` |
| File name | `8c91e9ab5fbeb88473034e12ff9feb159fb367353500bdd471a92dc022ba4c21.bin` |
| File type | `exe` |
| First seen | `2026-09-01 02:01:01` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91d411d6c94261b62ceef211a58eb7a7` |
| SHA-1 | `8f71cb84ab98d7166316a661f777b455f72f3cc9` |
| SHA-256 | `8c91e9ab5fbeb88473034e12ff9feb159fb367353500bdd471a92dc022ba4c21` |
| SHA3-384 | `89e3679038beaed47078c45feef769dad23ce429ca18f39a428219d0dd067afd23a619aea3fd2b24a7db2a6c58209bbd` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T13B766A07BF9141A8C01AEA39C5B69213B7717C8C8B3473EB2EA065342E397D16DB6F54` |
| SSDEEP | `196608:Ms1ywidS8dI7XWO20z5xlTZbzAXCMLuKqAMQv:7MLuKq2v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_8c91e9ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c91e9ab5fbeb88473034e12ff9feb159fb367353500bdd471a92dc022ba4c21"
    family = "unknown"
    file_name = "8c91e9ab5fbeb88473034e12ff9feb159fb367353500bdd471a92dc022ba4c21.bin"
    file_type = "exe"
    first_seen = "2026-09-01 02:01:01"
  condition:
    hash.sha256(0, filesize) == "8c91e9ab5fbeb88473034e12ff9feb159fb367353500bdd471a92dc022ba4c21"
}
```

### Sample 37: `b646d2987f0f0a0c`

| Field | Value |
|---|---|
| SHA-256 | `b646d2987f0f0a0c7416eb4f6c5edf2f7faa088bbc57877cc48e8a463d497739` |
| Family label | `ACRStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 01:33:35` |
| Reporter | `Bitsight` |
| Tags | `ACRStealer, D, dropped-by-GCleaner, EU0.file, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d45dc255d9d01adb6756c104e989d6d9` |
| SHA-1 | `72ad987d04733238978c5b6eb9bf704f628969be` |
| SHA-256 | `b646d2987f0f0a0c7416eb4f6c5edf2f7faa088bbc57877cc48e8a463d497739` |
| SHA3-384 | `55e2f50b72bf2f2615b4b6943d7515c74c979dddeb126f080181769717ee167c2b08d3dc716223b366e2202ef46a3652` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1AD95231167F4C0BAD4E74F7189F40613F331BDD11B3097CF2AA5A98A1B22F98A63535A` |
| SSDEEP | `49152:yZ2AwyOX+f0ViW2STOdD8n0ywQEiaCQn7HDzunKo:bE0+TglKiaCQnTen` |
| ICON-DHASH | `9389a6a1b092d272` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_037_b646d298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b646d2987f0f0a0c7416eb4f6c5edf2f7faa088bbc57877cc48e8a463d497739"
    family = "ACRStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 01:33:35"
  condition:
    hash.sha256(0, filesize) == "b646d2987f0f0a0c7416eb4f6c5edf2f7faa088bbc57877cc48e8a463d497739"
}
```

### Sample 38: `2282000cd6def22a`

| Field | Value |
|---|---|
| SHA-256 | `2282000cd6def22a6473c19b1177c044d01aeea6a820cb4272c0106f1d4e5bbb` |
| Family label | `unknown` |
| File name | `2282000cd6def22a6473c19b1177c044d01aeea6a820cb4272c0106f1d4e5bbb.exe` |
| File type | `exe` |
| First seen | `2026-09-01 01:32:57` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecf2a814b720c1ec88a27bf517808154` |
| SHA-1 | `421806bb9022fad301b1a4940c4c79c56d580878` |
| SHA-256 | `2282000cd6def22a6473c19b1177c044d01aeea6a820cb4272c0106f1d4e5bbb` |
| SHA3-384 | `69f68e72c43ff15726eef9f585b012aef96692dc97bc4e2ac4941718948e050e11dc0427675cafc17e8b3cd9deacb4dc` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T177D52299B9F709B8D836C7B58F96F4EDB1287B9203704DCB3A8C39408D126685C36779` |
| SSDEEP | `49152:fcGC+h0AzvotZUIErW0Km0qumVNrF+/VjQcO0MgUTKwtOss2T1WMP:fcz+hX8ZUIEjKvqPF6VjUbrTKwcsseQw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_2282000c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2282000cd6def22a6473c19b1177c044d01aeea6a820cb4272c0106f1d4e5bbb"
    family = "unknown"
    file_name = "2282000cd6def22a6473c19b1177c044d01aeea6a820cb4272c0106f1d4e5bbb.exe"
    file_type = "exe"
    first_seen = "2026-09-01 01:32:57"
  condition:
    hash.sha256(0, filesize) == "2282000cd6def22a6473c19b1177c044d01aeea6a820cb4272c0106f1d4e5bbb"
}
```

### Sample 39: `0866f1acf9460fa1`

| Field | Value |
|---|---|
| SHA-256 | `0866f1acf9460fa133f76adff4182bbdf621083e807d49387b50a9e10bac3feb` |
| Family label | `unknown` |
| File name | `0866f1acf9460fa133f76adff4182bbdf621083e807d49387b50a9e10bac3feb.bin` |
| File type | `exe` |
| First seen | `2026-09-01 01:30:47` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e00379a6c31a72dc3b8f7937faad2cf` |
| SHA-1 | `283675e53d0d3d6a84a8e942e917fab0e81f1523` |
| SHA-256 | `0866f1acf9460fa133f76adff4182bbdf621083e807d49387b50a9e10bac3feb` |
| SHA3-384 | `5ba5212f80b49366428bda642af769bd34071348d23e4c6e508b7e4097cea670d73a4cecb0c90c7852f5391414c7d815` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1FE366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaV:uc3XND1aJrCOkV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_0866f1ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0866f1acf9460fa133f76adff4182bbdf621083e807d49387b50a9e10bac3feb"
    family = "unknown"
    file_name = "0866f1acf9460fa133f76adff4182bbdf621083e807d49387b50a9e10bac3feb.bin"
    file_type = "exe"
    first_seen = "2026-09-01 01:30:47"
  condition:
    hash.sha256(0, filesize) == "0866f1acf9460fa133f76adff4182bbdf621083e807d49387b50a9e10bac3feb"
}
```

### Sample 40: `00c4603f074afb65`

| Field | Value |
|---|---|
| SHA-256 | `00c4603f074afb652780bb8b3e703ae093c5644652b81954ec6d0fb983e79203` |
| Family label | `CoinMiner` |
| File name | `00c4603f074afb652780bb8b3e703ae093c5644652b81954ec6d0fb983e79203.exe` |
| File type | `exe` |
| First seen | `2026-09-01 01:12:03` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dde3aa953a54b22666dcadc568a870e` |
| SHA-1 | `bc451286285ba16909ec5c884bcfec381a17c91e` |
| SHA-256 | `00c4603f074afb652780bb8b3e703ae093c5644652b81954ec6d0fb983e79203` |
| SHA3-384 | `7cca647633264074296af75d1d2a785eacee62937d5e0a73658596fa161b87b855597dee8a304365f410ed8f405000ae` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T15A3633D368D698B8D076C3B857A3706CB3383BA18965BE4B36CD5A808D46F0C643E7D5` |
| SSDEEP | `98304:2iD/lciC3x4skpyjwgkejtnxHWQtlv1OSSAPeWDK/ChTcK5PcVnJWwv:NaxxlRkejtxHWQtlv1OfAPegK/9KqVJ9` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_040_00c4603f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00c4603f074afb652780bb8b3e703ae093c5644652b81954ec6d0fb983e79203"
    family = "CoinMiner"
    file_name = "00c4603f074afb652780bb8b3e703ae093c5644652b81954ec6d0fb983e79203.exe"
    file_type = "exe"
    first_seen = "2026-09-01 01:12:03"
  condition:
    hash.sha256(0, filesize) == "00c4603f074afb652780bb8b3e703ae093c5644652b81954ec6d0fb983e79203"
}
```

### Sample 41: `0d4db24c7534f64e`

| Field | Value |
|---|---|
| SHA-256 | `0d4db24c7534f64e080fddc211c026c56976187b7a30bd2fdd35316ad6f450e1` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-01 01:07:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05c2d033ed83f8d2f4967601626b8f36` |
| SHA-1 | `66e3425cbc77907a307053067cacd63703b54fd5` |
| SHA-256 | `0d4db24c7534f64e080fddc211c026c56976187b7a30bd2fdd35316ad6f450e1` |
| SHA3-384 | `06829a70800304a1afe49312c561c75df30a3d9cecb32ae39ea5030291967621238d021e313930d98c477dfa8bab49f4` |
| TLSH | `T19B31139B00105BB10112CE8E77A3784DB68F95EB2D9FDAD48C491EE982887DCF261F5D` |
| SSDEEP | `12:UF96FtBE6QFWGi6FWGlc8gT76gVB4vtir6tPvCDHI6HaBqXUDNnL6nK7pSiwJ6bt:3zGqGCJhH2RgK7d6+ovJv8N4yn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_0d4db24c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d4db24c7534f64e080fddc211c026c56976187b7a30bd2fdd35316ad6f450e1"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-01 01:07:52"
  condition:
    hash.sha256(0, filesize) == "0d4db24c7534f64e080fddc211c026c56976187b7a30bd2fdd35316ad6f450e1"
}
```

### Sample 42: `4ff5127f162125a8`

| Field | Value |
|---|---|
| SHA-256 | `4ff5127f162125a80bbeedf7ae42e56f24efba63a719f84d152c4266f3518242` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 00:59:58` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9376bd4425826b722f5ce824f68e2755` |
| SHA-1 | `b1edb18aac912484a1db382dbce512defa86d420` |
| SHA-256 | `4ff5127f162125a80bbeedf7ae42e56f24efba63a719f84d152c4266f3518242` |
| SHA3-384 | `94892b9b470e4d9901151251f7f3df9c14407a86ebb21327a19e6302da5992d9726cb70b46dc8b991df3ed96aa4eecd4` |
| IMPHASH | `e5cd8af6498ac8cd593af4ca716a6703` |
| TLSH | `T199868D1493E449E0E12FD634C9668732EB707C555B31C70F1A7AE20A2F736F1CE6AA25` |
| SSDEEP | `196608:kb4DdS4vCC2mV21TgfZZZZZSZZZZZZZZZZZZZeZHfSs8p:ICS4vCC2mV280` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_4ff5127f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ff5127f162125a80bbeedf7ae42e56f24efba63a719f84d152c4266f3518242"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 00:59:58"
  condition:
    hash.sha256(0, filesize) == "4ff5127f162125a80bbeedf7ae42e56f24efba63a719f84d152c4266f3518242"
}
```

### Sample 43: `21ca7ea24b9faedc`

| Field | Value |
|---|---|
| SHA-256 | `21ca7ea24b9faedcc3d82d803f71f3d61d407d518dd503b6da5ea9b8dac3d0bc` |
| Family label | `ConnectWise` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 00:24:59` |
| Reporter | `Bitsight` |
| Tags | `A, ConnectWise, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `548c6c4912046e948df0e2578cf4dd89` |
| SHA-1 | `ffdbb80d7302f58a6b44cde7b7c390afe99487f6` |
| SHA-256 | `21ca7ea24b9faedcc3d82d803f71f3d61d407d518dd503b6da5ea9b8dac3d0bc` |
| SHA3-384 | `b7489fb406f309851dcdac0f9a4f244b8bb3d418e3a1997ef4d92e9e95081c0b6b2a08ff633847095129aabbab77a536` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T1FD771256E2FD00E8D5BAC0BCC6575517EBB23459173097EB52A48A692F33BE0AE3D310` |
| SSDEEP | `786432:fuMLJsXoeOvHiwB3sn+h1nW25F+wX0ff6yajCs6+4S3NftN:f5coeeCwDrnWG+tf6fj4ulN` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_043_21ca7ea2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21ca7ea24b9faedcc3d82d803f71f3d61d407d518dd503b6da5ea9b8dac3d0bc"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 00:24:59"
  condition:
    hash.sha256(0, filesize) == "21ca7ea24b9faedcc3d82d803f71f3d61d407d518dd503b6da5ea9b8dac3d0bc"
}
```

### Sample 44: `609996da0ee3ae21`

| Field | Value |
|---|---|
| SHA-256 | `609996da0ee3ae21db2ecc8c98c656994723fc8359410a118a2042c418b53f03` |
| Family label | `WannaCry` |
| File name | `609996da0ee3ae21db2ecc8c98c656994723fc8359410a118a2042c418b53f03` |
| File type | `exe` |
| First seen | `2026-09-01 00:15:33` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6947fe506ee83239c32a4213a91e1365` |
| SHA-1 | `10956e3f7ca522e8c0c0841446d883f7f65a9c70` |
| SHA-256 | `609996da0ee3ae21db2ecc8c98c656994723fc8359410a118a2042c418b53f03` |
| SHA3-384 | `b263cf2a9150aae7fd4557947347a7e4d3079da6d5f7c05e87ad1b6eea4512248c41273aebef56f6a1bd776e65f2ec6a` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T13536239931BC81FCD106197484B78E22F3B37C6A26FE5B0F9B40457A1E13B56BB60B52` |
| SSDEEP | `49152:jnsnlMSPbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnv:DMlPoBhz1aRxcSUDk36SAEdhv` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_044_609996da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "609996da0ee3ae21db2ecc8c98c656994723fc8359410a118a2042c418b53f03"
    family = "WannaCry"
    file_name = "609996da0ee3ae21db2ecc8c98c656994723fc8359410a118a2042c418b53f03"
    file_type = "exe"
    first_seen = "2026-09-01 00:15:33"
  condition:
    hash.sha256(0, filesize) == "609996da0ee3ae21db2ecc8c98c656994723fc8359410a118a2042c418b53f03"
}
```

### Sample 45: `d70fc0b690b49176`

| Field | Value |
|---|---|
| SHA-256 | `d70fc0b690b491762a0f861cd129786e9e54c4a79dff6f7bd0b3a14c90b6ec24` |
| Family label | `NanoCore` |
| File name | `33970F0D2D3BA1F4D505DEC41EB157E6.exe` |
| File type | `exe` |
| First seen | `2026-09-01 00:15:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33970f0d2d3ba1f4d505dec41eb157e6` |
| SHA-1 | `05985936885fb7a0e70f4ea74aa5049695879952` |
| SHA-256 | `d70fc0b690b491762a0f861cd129786e9e54c4a79dff6f7bd0b3a14c90b6ec24` |
| SHA3-384 | `3396522b9a6ae8c28d1d578413a3e9df3ca3623ae3d2269acc2b1f3f907292283bb10a93aca9eb9e4e88c7745ed4abfb` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13414CF2677A84A2FE2DE85B9611201538378C2E3DDC3F3EE18D855B39B663E50A071D7` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM50uvImfVqflRj0vsg:MLV6BtpmklkGlt0L` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_045_d70fc0b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d70fc0b690b491762a0f861cd129786e9e54c4a79dff6f7bd0b3a14c90b6ec24"
    family = "NanoCore"
    file_name = "33970F0D2D3BA1F4D505DEC41EB157E6.exe"
    file_type = "exe"
    first_seen = "2026-09-01 00:15:06"
  condition:
    hash.sha256(0, filesize) == "d70fc0b690b491762a0f861cd129786e9e54c4a79dff6f7bd0b3a14c90b6ec24"
}
```

### Sample 46: `c6b8b6530e5e43df`

| Field | Value |
|---|---|
| SHA-256 | `c6b8b6530e5e43df058648b4004b66aa992cdbfdadc879a4ffe8f56f2c8dc63c` |
| Family label | `Mirai` |
| File name | `c6b8b6530e5e43df058648b4004b66aa992cdbfdadc879a4ffe8f56f2c8dc63c.elf` |
| File type | `elf` |
| First seen | `2026-09-01 00:02:16` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f680fd891ea359bf379cc5580710233` |
| SHA-1 | `136282a2faa07b3b6111877648a8d4ab3499ec2c` |
| SHA-256 | `c6b8b6530e5e43df058648b4004b66aa992cdbfdadc879a4ffe8f56f2c8dc63c` |
| SHA3-384 | `de4320184f443776b379ff03913a48e47d1472b30b4fbf46499b397abe10f2de331231e64fd912e19f070829f7318e44` |
| TLSH | `T1E3836CD9F683C4F5E81308701037FF36EA72C6FB7268E647D3A85976DC62502A502A9D` |
| TELFHASH | `t1653145f919be0ce8e3e09950c20daf223d6de67764a033b145f399312367d4215bac38` |
| SSDEEP | `1536:Aw2r81ElKcYDmOwYPX/M7IV4SbAgvvXBVFAAtSqyWCT:MdQDaTY//MsCSUgXxVoT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_c6b8b653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6b8b6530e5e43df058648b4004b66aa992cdbfdadc879a4ffe8f56f2c8dc63c"
    family = "Mirai"
    file_name = "c6b8b6530e5e43df058648b4004b66aa992cdbfdadc879a4ffe8f56f2c8dc63c.elf"
    file_type = "elf"
    first_seen = "2026-09-01 00:02:16"
  condition:
    hash.sha256(0, filesize) == "c6b8b6530e5e43df058648b4004b66aa992cdbfdadc879a4ffe8f56f2c8dc63c"
}
```

### Sample 47: `c8fd41ba910705bc`

| Field | Value |
|---|---|
| SHA-256 | `c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033` |
| Family label | `Mirai` |
| File name | `c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033.elf` |
| File type | `elf` |
| First seen | `2026-09-01 00:02:11` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19c420396cccb8801119f3602eab2f4e` |
| SHA-1 | `eaad697aede9678f233aeca1696d7c5c0a598332` |
| SHA-256 | `c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033` |
| SHA3-384 | `258193b0153c4098197c1ef4f549bec5818f95c341cad43f19b78a94b3330e7c715e50e9060f876cec38aae83dd27646` |
| TLSH | `T120A35B02B34C0A43C2971DF1393F27D6CBBBD9D122E4BA85791E8B459271E37194AED8` |
| SSDEEP | `1536:HTLl6+R1Y6RooF9AUeBWxA9BiuIomQxgrHs3Mh40477j44ypqyzStlI:Hl5s6RooFJxY75xgrHyMh1GByMHI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_c8fd41ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033"
    family = "Mirai"
    file_name = "c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033.elf"
    file_type = "elf"
    first_seen = "2026-09-01 00:02:11"
  condition:
    hash.sha256(0, filesize) == "c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033"
}
```

### Sample 48: `5a377ec931f19b8d`

| Field | Value |
|---|---|
| SHA-256 | `5a377ec931f19b8d8848f35dde27211101c7165212309e2065de22a32598506c` |
| Family label | `Mirai` |
| File name | `5a377ec931f19b8d8848f35dde27211101c7165212309e2065de22a32598506c.elf` |
| File type | `elf` |
| First seen | `2026-09-01 00:02:06` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cb8aff0a7e868c8394b316891963f7e` |
| SHA-1 | `05d9a381645b23097c258ad0133f7be250ddc4f3` |
| SHA-256 | `5a377ec931f19b8d8848f35dde27211101c7165212309e2065de22a32598506c` |
| SHA3-384 | `6f342c434530a349a9c50c4dbb2a71be5adfbe2c79b5e3a7cc2d4a3543454599fa34bbea0a8ff0a9200f15ae79b9e440` |
| TLSH | `T14E532992F882491EC6C417B5B79E765D3762A3F9D1CA3607FD104F113AEAA0B4C7AD80` |
| TELFHASH | `t1fae0ab84fe758a1988d31a70ec9d02b4d101226771564b21df18c7e08c3f011e20ca4e` |
| SSDEEP | `1536:i4buUW7vpqgFhfGNQeRNVrcqv8IN0BitYyRAqxG:iUuUW7vpqgFsQY9cqJqiE1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_5a377ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a377ec931f19b8d8848f35dde27211101c7165212309e2065de22a32598506c"
    family = "Mirai"
    file_name = "5a377ec931f19b8d8848f35dde27211101c7165212309e2065de22a32598506c.elf"
    file_type = "elf"
    first_seen = "2026-09-01 00:02:06"
  condition:
    hash.sha256(0, filesize) == "5a377ec931f19b8d8848f35dde27211101c7165212309e2065de22a32598506c"
}
```

### Sample 49: `9897c649dedea20a`

| Field | Value |
|---|---|
| SHA-256 | `9897c649dedea20a1743fecd392d220e43151d349ed060ac1c7403cdcb60c852` |
| Family label | `unknown` |
| File name | `9897c649dedea20a1743fecd392d220e43151d349ed060ac1c7403cdcb60c852.bin` |
| File type | `exe` |
| First seen | `2026-09-01 00:01:19` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d7e30af602720a142f2d4f2df0b0ba1` |
| SHA-1 | `c0b04a6f7d0e9ea7ee50dc8bf10763842ef208a8` |
| SHA-256 | `9897c649dedea20a1743fecd392d220e43151d349ed060ac1c7403cdcb60c852` |
| SHA3-384 | `1d43e5c73feaaf50da8c0ef4f63b65206fcae7b5db8ba427c90535721ce90e1779b70ea74d5edaf04dfed820a544396c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T184765B07BF914198C05AEA39C5B79253B6717C8C8B34B3EB2EA065742E397C12DB5F24` |
| SSDEEP | `196608:iFVySXbsIJgkEAaof+wVgc42zg8jgbLGK:6sf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_9897c649
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9897c649dedea20a1743fecd392d220e43151d349ed060ac1c7403cdcb60c852"
    family = "unknown"
    file_name = "9897c649dedea20a1743fecd392d220e43151d349ed060ac1c7403cdcb60c852.bin"
    file_type = "exe"
    first_seen = "2026-09-01 00:01:19"
  condition:
    hash.sha256(0, filesize) == "9897c649dedea20a1743fecd392d220e43151d349ed060ac1c7403cdcb60c852"
}
```

### Sample 50: `96986365c7730a62`

| Field | Value |
|---|---|
| SHA-256 | `96986365c7730a62601a2c435f332d6aa541e08244ca40ef1e5e35c3a3ae7cb7` |
| Family label | `unknown` |
| File name | `96986365c7730a62601a2c435f332d6aa541e08244ca40ef1e5e35c3a3ae7cb7.bin` |
| File type | `exe` |
| First seen | `2026-08-31 23:31:09` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6146a97d66898f7e4501a568ada3a223` |
| SHA-1 | `c0f807f2f7fba6fb79fe557dff5b8af6ef15a0de` |
| SHA-256 | `96986365c7730a62601a2c435f332d6aa541e08244ca40ef1e5e35c3a3ae7cb7` |
| SHA3-384 | `589e24b28a9acd23464db81594fe748d39274c7b42511512cadf7fb07e70dc50647291338c698bc8e1289616e9e34c4b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17E766A07BF9141A8C05BEA39C5B79213B6617C8C8B3473EB2E9065382E397D12DB5F64` |
| SSDEEP | `98304:KAGbS9lEHMKNcblaAghiTrfqJUB2pe0CCCo2rd0XCNW3NowP:K3S9lEHMKNcblaAgcHiyB2pr60p3D` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_96986365
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96986365c7730a62601a2c435f332d6aa541e08244ca40ef1e5e35c3a3ae7cb7"
    family = "unknown"
    file_name = "96986365c7730a62601a2c435f332d6aa541e08244ca40ef1e5e35c3a3ae7cb7.bin"
    file_type = "exe"
    first_seen = "2026-08-31 23:31:09"
  condition:
    hash.sha256(0, filesize) == "96986365c7730a62601a2c435f332d6aa541e08244ca40ef1e5e35c3a3ae7cb7"
}
```

### Sample 51: `31c24e66dd8b0c26`

| Field | Value |
|---|---|
| SHA-256 | `31c24e66dd8b0c26017ffa8aceee3305f99746163ece14d750f912b5cd10b00b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-31 23:13:31` |
| Reporter | `Bitsight` |
| Tags | `B, BB1.file, dropped-by-GCleaner, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b41169f6c3f78950e11f6d1902595d4` |
| SHA-1 | `ff32f806b4b886de3c626246ef3fb71effb6113a` |
| SHA-256 | `31c24e66dd8b0c26017ffa8aceee3305f99746163ece14d750f912b5cd10b00b` |
| SHA3-384 | `8ddce2672fa6ecebb8f27afd7268be64422b68111ef21ed8448986c1cd2881b170fd3c7c2cbd7bd5f8ce0d8a013a085c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E0265A43BD9148FAC0D5A33188B65256BB35BC0C1B3633D32E60ABB42E767D15E36B64` |
| SSDEEP | `49152:i6E58ITkSKZodnbdtdS5Zdc8qZqhsVZelNcQ9u:itPnbdeS8yqhUeDu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_31c24e66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31c24e66dd8b0c26017ffa8aceee3305f99746163ece14d750f912b5cd10b00b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-31 23:13:31"
  condition:
    hash.sha256(0, filesize) == "31c24e66dd8b0c26017ffa8aceee3305f99746163ece14d750f912b5cd10b00b"
}
```

### Sample 52: `9f2b31c6ee353fc8`

| Field | Value |
|---|---|
| SHA-256 | `9f2b31c6ee353fc8b1a9897357902cce09efa5f5ab1134ec5c17b5abac892ece` |
| Family label | `ConnectWise` |
| File name | `file` |
| File type | `msi` |
| First seen | `2026-08-31 23:08:29` |
| Reporter | `Bitsight` |
| Tags | `ConnectWise, d52f85, dropped-by-Amadey, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa35367529c268477b7b661b3f32112e` |
| SHA-1 | `d60086a4c9661991ce19218b1ccdc5266ca05c85` |
| SHA-256 | `9f2b31c6ee353fc8b1a9897357902cce09efa5f5ab1134ec5c17b5abac892ece` |
| SHA3-384 | `53954f74aa7dcdc9cbef2558d56ad3fdf04c733fd71652d47a56942474437ca1b2498527bbf5239da9d6ad24c36d78af` |
| TLSH | `T12AA623116BF8D278F1F12A39D876A0B1A53A7D119E23D12E2324791E2C75EC0CA63777` |
| SSDEEP | `196608:hHxcp9ym3nltDUJVDHxcp9ym3YHxcp9ym39Hxcp9ym3pHxcp9ym3:TGplpMGpmGpvGp7Gp` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_052_9f2b31c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f2b31c6ee353fc8b1a9897357902cce09efa5f5ab1134ec5c17b5abac892ece"
    family = "ConnectWise"
    file_name = "file"
    file_type = "msi"
    first_seen = "2026-08-31 23:08:29"
  condition:
    hash.sha256(0, filesize) == "9f2b31c6ee353fc8b1a9897357902cce09efa5f5ab1134ec5c17b5abac892ece"
}
```

### Sample 53: `61e1448bb643b752`

| Field | Value |
|---|---|
| SHA-256 | `61e1448bb643b75266b23f27256e2ab54ee1bdfe8bde759162ba24cf5102b44b` |
| Family label | `unknown` |
| File name | `skynet_dropper_61e1448b.exe` |
| File type | `exe` |
| First seen | `2026-08-31 22:25:19` |
| Reporter | `Stateoftheattack` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14176d078907e30ebcbe50b905b3c015` |
| SHA-1 | `ee3cbe75417a4b346315e2ed53de9f434a45cc62` |
| SHA-256 | `61e1448bb643b75266b23f27256e2ab54ee1bdfe8bde759162ba24cf5102b44b` |
| SHA3-384 | `a1b8c35445b8503eea49981823dec6b6271e7c7b07055ec388cd3e13f3e55820653475564016d7e52c62b1e4c2b3d639` |
| IMPHASH | `337804e527a143f26af77d8bd177a8c3` |
| TLSH | `T1B4061221F345C07AE85340F131AAC76EAAB8BF75162A4DC3F7841F4C6638AD9693570B` |
| SSDEEP | `49152:Sn/UAmN1TDCtrYWjl3RX2fsdVgd7s1k/K/YiqmUNLvIR:Sn2HDGYWZtNVC7Uk/K/PqmUNDk` |
| ICON-DHASH | `8c266a9594e91d22` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_61e1448b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61e1448bb643b75266b23f27256e2ab54ee1bdfe8bde759162ba24cf5102b44b"
    family = "unknown"
    file_name = "skynet_dropper_61e1448b.exe"
    file_type = "exe"
    first_seen = "2026-08-31 22:25:19"
  condition:
    hash.sha256(0, filesize) == "61e1448bb643b75266b23f27256e2ab54ee1bdfe8bde759162ba24cf5102b44b"
}
```

### Sample 54: `170ac61ecb942da7`

| Field | Value |
|---|---|
| SHA-256 | `170ac61ecb942da70576080c6bf25eecdad66c5843c7f8aac2d6a6cc44af7903` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-31 22:23:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba24b47d1aebc3c7ca2d5b41a01c5c6e` |
| SHA-1 | `bf42e5af85339fc33fa9d6a5ce0541ca28e3dd89` |
| SHA-256 | `170ac61ecb942da70576080c6bf25eecdad66c5843c7f8aac2d6a6cc44af7903` |
| SHA3-384 | `5a4212177fb4547d326f077bc997218d93ae3a0714363d824febecf685b907ae1e40dde9a00167cbefb169963845ea6b` |
| TLSH | `T116C28D966A867C44BEC94A3E4CBD2B0D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:c8vCB+25j6es8RCP9FYpMSUpi+20qUpi+20YQX:c8l25JCd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_170ac61e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "170ac61ecb942da70576080c6bf25eecdad66c5843c7f8aac2d6a6cc44af7903"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-31 22:23:36"
  condition:
    hash.sha256(0, filesize) == "170ac61ecb942da70576080c6bf25eecdad66c5843c7f8aac2d6a6cc44af7903"
}
```

### Sample 55: `9bf4339e422f5053`

| Field | Value |
|---|---|
| SHA-256 | `9bf4339e422f50532770dceabe5cc1467005aeb9322ff981202a3bc4d82e86f8` |
| Family label | `unknown` |
| File name | `goodthingsforbestpersonforme.hta` |
| File type | `hta` |
| First seen | `2026-08-31 22:23:35` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fd2f354ca7474263e6835233b3c787c` |
| SHA-1 | `edb9ed45e7714b9f77fe593c904fc49ed06e57f2` |
| SHA-256 | `9bf4339e422f50532770dceabe5cc1467005aeb9322ff981202a3bc4d82e86f8` |
| SHA3-384 | `8defd44531739fee996b3276a475992cdd246cad2795f36f97dbaadcd387ed1fc658fddb833c7e591c1784c1e1e87962` |
| TLSH | `T1D4F05C4284A08919523026142FC0F9055ADAEA47534A6D8872EA50BD4FC4BC1CDCF97C` |
| SSDEEP | `6:qTIuJzhqIwGiY63fAbplilAl3t11/+SR0AqIbR2AWHwluV4LKTjawlgxF0NAEdpz:qTp0JYyg9193R5qsPWBV8qAEd2QL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_9bf4339e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bf4339e422f50532770dceabe5cc1467005aeb9322ff981202a3bc4d82e86f8"
    family = "unknown"
    file_name = "goodthingsforbestpersonforme.hta"
    file_type = "hta"
    first_seen = "2026-08-31 22:23:35"
  condition:
    hash.sha256(0, filesize) == "9bf4339e422f50532770dceabe5cc1467005aeb9322ff981202a3bc4d82e86f8"
}
```

### Sample 56: `ba4702a586423e50`

| Field | Value |
|---|---|
| SHA-256 | `ba4702a586423e508da644eac65f17dc7096fdf97231d571aa81b2915225ffe3` |
| Family label | `Mirai` |
| File name | `daredevil.arc` |
| File type | `elf` |
| First seen | `2026-08-31 22:13:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52fb1b8fd395c694ec1d3af81b0299cd` |
| SHA-1 | `62de2937e17cee6e14d9cb0a4ec52eb563086fff` |
| SHA-256 | `ba4702a586423e508da644eac65f17dc7096fdf97231d571aa81b2915225ffe3` |
| SHA3-384 | `0549cf75e55b07bb97bf51c96e1894ba16b524368e161eb9579cc2cfe27967d9cfd6cc9e1ad167aeb8e31c9d8f95a3cf` |
| TLSH | `T1E6B39D9BB28754B0D86546F087E78BEE3A2773418F5B5CFB7C2E093A99310DE19113A1` |
| SSDEEP | `1536:44vPsaAdAauAHXkFK/OkG1nT5IBxXXsZK/kmglb/LW+Y:4KPXaAt+3OkG5NIBCZK/jglq+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_ba4702a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba4702a586423e508da644eac65f17dc7096fdf97231d571aa81b2915225ffe3"
    family = "Mirai"
    file_name = "daredevil.arc"
    file_type = "elf"
    first_seen = "2026-08-31 22:13:37"
  condition:
    hash.sha256(0, filesize) == "ba4702a586423e508da644eac65f17dc7096fdf97231d571aa81b2915225ffe3"
}
```

### Sample 57: `ed0509dfbec975e7`

| Field | Value |
|---|---|
| SHA-256 | `ed0509dfbec975e7e6b22d2b73d25b9643a9fb020906259e8c4fc55812c7ccf8` |
| Family label | `Mirai` |
| File name | `daredevil.i486` |
| File type | `elf` |
| First seen | `2026-08-31 22:08:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `faaaeb6c2b9b058bcf5ba5dd8a069001` |
| SHA-1 | `804c5999e467bb6ae15ccb752970d6d7376bcbd6` |
| SHA-256 | `ed0509dfbec975e7e6b22d2b73d25b9643a9fb020906259e8c4fc55812c7ccf8` |
| SHA3-384 | `c3977aae9f66da9b426a6aa82b0561087067b21bb9b480a67b880dbc787430aa6cc2c2ade1173a0bb51272ea37776078` |
| TLSH | `T1FD634C58E783E4F0DA4206F0216FFB3B5531D9611270DCFBEBE4FAEA99617819016A1C` |
| TELFHASH | `t10421b3f71eee0dc477d69900835e1f6146aae63f285033934361d84127a7f82507bc39` |
| SSDEEP | `1536:yaqsy4IKPVlBvLzcq/+I5uzTLuIP0gD4Uf31gOfg5r:1qsy4IKTtLz5X50TyAKOC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_ed0509df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed0509dfbec975e7e6b22d2b73d25b9643a9fb020906259e8c4fc55812c7ccf8"
    family = "Mirai"
    file_name = "daredevil.i486"
    file_type = "elf"
    first_seen = "2026-08-31 22:08:20"
  condition:
    hash.sha256(0, filesize) == "ed0509dfbec975e7e6b22d2b73d25b9643a9fb020906259e8c4fc55812c7ccf8"
}
```

### Sample 58: `21578d838b72e8ff`

| Field | Value |
|---|---|
| SHA-256 | `21578d838b72e8ffe8719a211c507ccf9a585b62e24924340d4a6bad8dde4f4a` |
| Family label | `Mirai` |
| File name | `daredevil.i486` |
| File type | `elf` |
| First seen | `2026-08-31 22:08:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `750253ba59d5e75d118207472d98ce52` |
| SHA-1 | `9e3917494c91d03fee3e38ba28400912d3288d94` |
| SHA-256 | `21578d838b72e8ffe8719a211c507ccf9a585b62e24924340d4a6bad8dde4f4a` |
| SHA3-384 | `24397c942722b22fb5c2fce8a696d9dd7b4e94b71c3d11f4fa928931788e67921d51a3f18813014d88b01ee9c130e8ea` |
| TLSH | `T1B2F2F1DEC8F6DD80E60FC5FB14E4394949A0D35CA7844DEE67F422B62500F5ABE8880A` |
| SSDEEP | `768:nKg0C/1gzx/M1xdwtHXXVHUbG/8SUQToK4MV6YXnKp4DzUjW/CnbcuyD7UkWykk5:LSVkJM3lwAWZhYXg8zMW/Cnouy8kzkk5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_21578d83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21578d838b72e8ffe8719a211c507ccf9a585b62e24924340d4a6bad8dde4f4a"
    family = "Mirai"
    file_name = "daredevil.i486"
    file_type = "elf"
    first_seen = "2026-08-31 22:08:01"
  condition:
    hash.sha256(0, filesize) == "21578d838b72e8ffe8719a211c507ccf9a585b62e24924340d4a6bad8dde4f4a"
}
```

### Sample 59: `1d64be0ba1bd9924`

| Field | Value |
|---|---|
| SHA-256 | `1d64be0ba1bd9924c3e29ae460db9407e4e33afeb864c9e39377ae4a87fa09db` |
| Family label | `CoinMiner` |
| File name | `1d64be0ba1bd9924c3e29ae460db9407e4e33afeb864c9e39377ae4a87fa09db` |
| File type | `sh` |
| First seen | `2026-08-31 22:04:52` |
| Reporter | `c2hunter` |
| Tags | `CoinMiner, sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ea444f1102f6217dad69dd026292f17` |
| SHA-1 | `4a172b157731784573017964dd6f63c0c11ef631` |
| SHA-256 | `1d64be0ba1bd9924c3e29ae460db9407e4e33afeb864c9e39377ae4a87fa09db` |
| SHA3-384 | `5b0c212128e805ef65ca5135b144adb058939ed6b50b8654d0c34db639be172034b8f4b857ae8c22e8d4d0b50336d162` |
| TLSH | `T1CF31F063E8A3C627A4C7283D2F7EB410D55B112F5DB0EC59344EBD60AF1CC117481B62` |
| SSDEEP | `48:HVC4hOlBoQbWkZ+N+l/+K1ZvQ+Om+jpzAXaV/H1fsr7s+KNwCIKI2uaNG8XuITn:ytT1Rqg0t` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_059_1d64be0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d64be0ba1bd9924c3e29ae460db9407e4e33afeb864c9e39377ae4a87fa09db"
    family = "CoinMiner"
    file_name = "1d64be0ba1bd9924c3e29ae460db9407e4e33afeb864c9e39377ae4a87fa09db"
    file_type = "sh"
    first_seen = "2026-08-31 22:04:52"
  condition:
    hash.sha256(0, filesize) == "1d64be0ba1bd9924c3e29ae460db9407e4e33afeb864c9e39377ae4a87fa09db"
}
```

### Sample 60: `0da821d9b5d6d28f`

| Field | Value |
|---|---|
| SHA-256 | `0da821d9b5d6d28f5a1c49e7c3fad8f0dc1080def5b0e2e8e832796102af5955` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-31 22:01:57` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffd1890bfd06da8a344c1ce251b83425` |
| SHA-256 | `0da821d9b5d6d28f5a1c49e7c3fad8f0dc1080def5b0e2e8e832796102af5955` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_0da821d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0da821d9b5d6d28f5a1c49e7c3fad8f0dc1080def5b0e2e8e832796102af5955"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 22:01:57"
  condition:
    hash.sha256(0, filesize) == "0da821d9b5d6d28f5a1c49e7c3fad8f0dc1080def5b0e2e8e832796102af5955"
}
```

### Sample 61: `2c46bade40bf7b25`

| Field | Value |
|---|---|
| SHA-256 | `2c46bade40bf7b255dcd7846f3969c697cc82325f9381e0089163415eb81716e` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-31 21:57:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5664120367a346ff2646ea315e41d33f` |
| SHA-1 | `573821a96bad4ce150c4572878fec8cc6e3e86e7` |
| SHA-256 | `2c46bade40bf7b255dcd7846f3969c697cc82325f9381e0089163415eb81716e` |
| SHA3-384 | `6daee8c47b42a9ddf2569842052f5a4495544b8b4cf640ec760814ea42469a0163bb65180e769d103d8cdccf0aad0c5a` |
| TLSH | `T136237D652A817C14AA98D4371D7E2F0CB9AD43E6320452EDBFCF3CF68C4A69DA11871D` |
| SSDEEP | `768:xXOGVvO9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:NLjcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_2c46bade
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c46bade40bf7b255dcd7846f3969c697cc82325f9381e0089163415eb81716e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-31 21:57:36"
  condition:
    hash.sha256(0, filesize) == "2c46bade40bf7b255dcd7846f3969c697cc82325f9381e0089163415eb81716e"
}
```

### Sample 62: `6da954cca9bff4ee`

| Field | Value |
|---|---|
| SHA-256 | `6da954cca9bff4eeed5d6506fdd80d70a0bb80882327ab8de7f10dc95df8693e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-31 21:57:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a57b053a0c093117ab21b71aaed059e` |
| SHA-1 | `4aad3031ad0a1a184f95ac6f3ead1ad7a7e9bf5c` |
| SHA-256 | `6da954cca9bff4eeed5d6506fdd80d70a0bb80882327ab8de7f10dc95df8693e` |
| SHA3-384 | `8a5cda195da5334b64b4aad6ffc7f52a8a3d8006293f57fd7e96bf9ed62e7a3c08f479cb79ef0b3ff79005ff7d07bec4` |
| TLSH | `T190C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:r8vCB+25j6es8RN9FYpMSUpi+20qUpi+20YQX:r8l25J7d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_6da954cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6da954cca9bff4eeed5d6506fdd80d70a0bb80882327ab8de7f10dc95df8693e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-31 21:57:35"
  condition:
    hash.sha256(0, filesize) == "6da954cca9bff4eeed5d6506fdd80d70a0bb80882327ab8de7f10dc95df8693e"
}
```

### Sample 63: `8d7c535c3073790d`

| Field | Value |
|---|---|
| SHA-256 | `8d7c535c3073790d9f08245d6ca5ba92b7e393a4b65dbe1aa1b29923caae7d4a` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-08-31 21:53:39` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8b8111b5471879bc07c718656591e27` |
| SHA-256 | `8d7c535c3073790d9f08245d6ca5ba92b7e393a4b65dbe1aa1b29923caae7d4a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_8d7c535c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d7c535c3073790d9f08245d6ca5ba92b7e393a4b65dbe1aa1b29923caae7d4a"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 21:53:39"
  condition:
    hash.sha256(0, filesize) == "8d7c535c3073790d9f08245d6ca5ba92b7e393a4b65dbe1aa1b29923caae7d4a"
}
```

### Sample 64: `69b8be812307119a`

| Field | Value |
|---|---|
| SHA-256 | `69b8be812307119aea9a2d41192765d5b51e27b61ec13b946953af68c065c287` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-31 21:53:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e9db8836445aeb04bc3d1e802c1a3a0` |
| SHA-1 | `e75facbeb36e23d03115d5117d60fd3af142d8cd` |
| SHA-256 | `69b8be812307119aea9a2d41192765d5b51e27b61ec13b946953af68c065c287` |
| SHA3-384 | `a5e81096d0b4692c3dcbd1878282034b8892fc335a094afc45129c7f18d05eb4f404ac36e1764c525059199f2c55156e` |
| TLSH | `T10931609B00142E701003CA6DB7A63488B68EE6EB1C9FD7D0DD881EE992897CCF165B4D` |
| SSDEEP | `12:UX6+4KK32UFr6FjJVrwgNh6jtjh/6G+hB6J9pnpKx6K71r66UfpN46NpSFuF6lxJ:dKKOotjaMM571C/SFuF7IJJcXe9Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_69b8be81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69b8be812307119aea9a2d41192765d5b51e27b61ec13b946953af68c065c287"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-31 21:53:38"
  condition:
    hash.sha256(0, filesize) == "69b8be812307119aea9a2d41192765d5b51e27b61ec13b946953af68c065c287"
}
```

### Sample 65: `7c357211fa3c4daa`

| Field | Value |
|---|---|
| SHA-256 | `7c357211fa3c4daa5cf500050b6bb7b0d5cc7d5fa9ffd61312d4873a9341d9af` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-31 21:49:37` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `288958793df320e7c96189f1766f7bfc` |
| SHA-256 | `7c357211fa3c4daa5cf500050b6bb7b0d5cc7d5fa9ffd61312d4873a9341d9af` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_7c357211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c357211fa3c4daa5cf500050b6bb7b0d5cc7d5fa9ffd61312d4873a9341d9af"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 21:49:37"
  condition:
    hash.sha256(0, filesize) == "7c357211fa3c4daa5cf500050b6bb7b0d5cc7d5fa9ffd61312d4873a9341d9af"
}
```

### Sample 66: `f4f93f133a02d001`

| Field | Value |
|---|---|
| SHA-256 | `f4f93f133a02d0016e359f3e21da4c35a49e773dac78796d261f2bc06018837a` |
| Family label | `Mirai` |
| File name | `daredevil.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-31 21:44:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3cba871d61036e89c78fdc57a2d9dd6` |
| SHA-1 | `b7d44c3f893ba202a979e5300d2ea49df6b511fe` |
| SHA-256 | `f4f93f133a02d0016e359f3e21da4c35a49e773dac78796d261f2bc06018837a` |
| SHA3-384 | `d30747009d523f1770ef513f22b1800392f2d37b345546cb548fb3115dd14e9a103e72de7af64e029fa953b6b0b76f37` |
| TLSH | `T13014C81E6E139F7DF27887344BB39E25A76923D623E0D684D2ACC6105E1029E541FFE8` |
| TELFHASH | `t1d64193180a7817f493399d8d059def76e6a330db3f221d378e51e86aa768d835e10d0c` |
| SSDEEP | `3072:pe8z0F+bRfGJRGEF6uLSXx9vUlCfdjv0CNv:pe8z0uK9Mx9CCFjR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_f4f93f13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4f93f133a02d0016e359f3e21da4c35a49e773dac78796d261f2bc06018837a"
    family = "Mirai"
    file_name = "daredevil.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-31 21:44:18"
  condition:
    hash.sha256(0, filesize) == "f4f93f133a02d0016e359f3e21da4c35a49e773dac78796d261f2bc06018837a"
}
```

### Sample 67: `849cece6b12e1eec`

| Field | Value |
|---|---|
| SHA-256 | `849cece6b12e1eec884b0adbc42885b303de2d905c6639a0b245ca548ad9eb41` |
| Family label | `Mirai` |
| File name | `daredevil.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-31 21:43:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4099f625b3b857791c3c2f64b6910e5` |
| SHA-1 | `bf9b90148cd2f01001b64d65f9b113c36f84f096` |
| SHA-256 | `849cece6b12e1eec884b0adbc42885b303de2d905c6639a0b245ca548ad9eb41` |
| SHA3-384 | `898f14bbea35cfae384ef917fd0b6dc3d56cbd3022f569aed8f17504ce53d50b1d4ce9a3722260f57c9fe6d46d1a12fd` |
| TLSH | `T17C430258291169FBECF9D1F148F3CB844BA04BA66F2371246B30D4928E0F95439FDE0A` |
| SSDEEP | `1536:i3nvkbeCjCtLON/vjpK1sD9dqD47QBRJMVJus:i3nvkbe6rXjgOdObIVQs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_849cece6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "849cece6b12e1eec884b0adbc42885b303de2d905c6639a0b245ca548ad9eb41"
    family = "Mirai"
    file_name = "daredevil.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-31 21:43:41"
  condition:
    hash.sha256(0, filesize) == "849cece6b12e1eec884b0adbc42885b303de2d905c6639a0b245ca548ad9eb41"
}
```

### Sample 68: `a4dbf22782b6fef6`

| Field | Value |
|---|---|
| SHA-256 | `a4dbf22782b6fef636b76a5082665b54d272a84b7c3ddac39f49d40d88b4226b` |
| Family label | `Mirai` |
| File name | `daredevil.mipsel` |
| File type | `elf` |
| First seen | `2026-08-31 21:38:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49dfd19dafe701d40cb08fc1a1383da0` |
| SHA-1 | `43896fa46d4f1f2b97f115d1e19860ed82aed0a5` |
| SHA-256 | `a4dbf22782b6fef636b76a5082665b54d272a84b7c3ddac39f49d40d88b4226b` |
| SHA3-384 | `f74e135c4bc312e7fc523499779142cd1f629e77c88b880e1324eee55c3785617c42f6d1626750e65ed3de7862ed7e5f` |
| TLSH | `T12014C70AAF620FBBD8BBDE3306E9070639DC644721B53B753674D928F50A64B4AD3C64` |
| SSDEEP | `3072:qqoZ3yPaOFrou4rJ0Boydr1klaqzHVdhJJDRuOdr:oZ3yPaOFrouIJ0ddBizHpJJg6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_a4dbf227
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4dbf22782b6fef636b76a5082665b54d272a84b7c3ddac39f49d40d88b4226b"
    family = "Mirai"
    file_name = "daredevil.mipsel"
    file_type = "elf"
    first_seen = "2026-08-31 21:38:19"
  condition:
    hash.sha256(0, filesize) == "a4dbf22782b6fef636b76a5082665b54d272a84b7c3ddac39f49d40d88b4226b"
}
```

### Sample 69: `fb73154cda3bf344`

| Field | Value |
|---|---|
| SHA-256 | `fb73154cda3bf3442a00bff97d5d291108fb2a1ba4cc4edab80bd721266dcfae` |
| Family label | `Mirai` |
| File name | `daredevil.mipsel` |
| File type | `elf` |
| First seen | `2026-08-31 21:37:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a51c7a3070b6dd42e793177e1a00360e` |
| SHA-1 | `13340cdf1462b2e3b595a3c294252e2232673006` |
| SHA-256 | `fb73154cda3bf3442a00bff97d5d291108fb2a1ba4cc4edab80bd721266dcfae` |
| SHA3-384 | `8b52786b3456be91856f7954a2d5d279b8d77b7c77f8f1388d36df7dac677b60884da0899fd4f406f008c6a1c1c47e3b` |
| TLSH | `T12653F1AB948D15CDC8CF56B7A4EA1315DA90FAC5BF6C0B0DCB64538C016228DB5AC2B8` |
| SSDEEP | `768:FRoAk0PunbBrdV3JdENF0IUaO9TBHY3Wjq2HjK04joUSVbDVW04ovqdO8TWL:MT02nlrLjEAINkCcb4PoDDfydc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_fb73154c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb73154cda3bf3442a00bff97d5d291108fb2a1ba4cc4edab80bd721266dcfae"
    family = "Mirai"
    file_name = "daredevil.mipsel"
    file_type = "elf"
    first_seen = "2026-08-31 21:37:38"
  condition:
    hash.sha256(0, filesize) == "fb73154cda3bf3442a00bff97d5d291108fb2a1ba4cc4edab80bd721266dcfae"
}
```

### Sample 70: `fe5af4a090b37fad`

| Field | Value |
|---|---|
| SHA-256 | `fe5af4a090b37fad65ce094b180d8d16c2b8f932214f82c6dbc0a79312e76939` |
| Family label | `Mirai` |
| File name | `daredevil.x86_64` |
| File type | `elf` |
| First seen | `2026-08-31 21:36:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cc4c76f972f4cec3bffe84f888d7dc3` |
| SHA-1 | `1f11f26e05ac27be94b48d8dbf0f4c1a449ebf9e` |
| SHA-256 | `fe5af4a090b37fad65ce094b180d8d16c2b8f932214f82c6dbc0a79312e76939` |
| SHA3-384 | `5f944254096a363f7072a2841720b94937c233b67ff69fc3b1a8d136206f52b03a50bce56fbc8fc064dfae16bac0f7cc` |
| TLSH | `T169E33A0BB8C098FDC499C2744BAAB136DD31F45E5138B6AF27D46E227E8DE207E5D241` |
| TELFHASH | `t16751bf703d9a3da861f7e22a738eda55ec72091109d271a0ef939cf6cf567c90e61052` |
| SSDEEP | `3072:YohqRbp1DP6Qc2ZLYvAwC5HChLQGyZt+c:Yohq9qYivRgwc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_fe5af4a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe5af4a090b37fad65ce094b180d8d16c2b8f932214f82c6dbc0a79312e76939"
    family = "Mirai"
    file_name = "daredevil.x86_64"
    file_type = "elf"
    first_seen = "2026-08-31 21:36:24"
  condition:
    hash.sha256(0, filesize) == "fe5af4a090b37fad65ce094b180d8d16c2b8f932214f82c6dbc0a79312e76939"
}
```

### Sample 71: `6aa6356e83451c2f`

| Field | Value |
|---|---|
| SHA-256 | `6aa6356e83451c2fb11ca6f42fd533d821f719c0ffc1972d7d1620f9636493de` |
| Family label | `Mirai` |
| File name | `daredevil.m68k` |
| File type | `elf` |
| First seen | `2026-08-31 21:35:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ae47daba8969deb5d911d66e923aeac` |
| SHA-1 | `16c2963d501e079f7a5c5236416e0a338a407f97` |
| SHA-256 | `6aa6356e83451c2fb11ca6f42fd533d821f719c0ffc1972d7d1620f9636493de` |
| SHA3-384 | `b54421781f2fa48ee4a65af0f63a016bd6b417ab4312f556b71f4ea71ec3a4365a0d4ecb6c3294de20912bdf4d212c88` |
| TLSH | `T19BF308D7F800DDBAF41FE33688530909B130B7A159426B377257792BDD3E1A91863E8A` |
| SSDEEP | `3072:69eq9IYhvxdTW98tkYExEJyTzbQoAVsjbicLa+CyORJx:6c6RO8GYExqyjQoNLWyOPx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_6aa6356e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aa6356e83451c2fb11ca6f42fd533d821f719c0ffc1972d7d1620f9636493de"
    family = "Mirai"
    file_name = "daredevil.m68k"
    file_type = "elf"
    first_seen = "2026-08-31 21:35:47"
  condition:
    hash.sha256(0, filesize) == "6aa6356e83451c2fb11ca6f42fd533d821f719c0ffc1972d7d1620f9636493de"
}
```

### Sample 72: `a51ad3b43629a1c9`

| Field | Value |
|---|---|
| SHA-256 | `a51ad3b43629a1c9d08cc25bd81ba5bf4765a9c5fc6cf59236ece7f570291bca` |
| Family label | `Mirai` |
| File name | `daredevil.x86_64` |
| File type | `elf` |
| First seen | `2026-08-31 21:35:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad058daf5d198bde8f78f43d4419ad16` |
| SHA-1 | `2bb5d3ae00a131b1b5fb3f0aefc9d8b6a0846937` |
| SHA-256 | `a51ad3b43629a1c9d08cc25bd81ba5bf4765a9c5fc6cf59236ece7f570291bca` |
| SHA3-384 | `f80276d5d9cebebee6d77c70cbfaa6a13e4c13403856d8a43f09f3d4c02458e9a7e7bc4fdf36c6ca6d9574b436a88b5c` |
| TLSH | `T10643F1F2E3058F78C9995BB60D239FD5BD282110B52706349073F8FB5A8E38DBEA4561` |
| SSDEEP | `1536:nx7fOHDVYHh2Z2AJZM7FZCV56H5hWkdidXLlvWgwZD:xiHDkG/ZAZygfldidAgwZD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_a51ad3b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a51ad3b43629a1c9d08cc25bd81ba5bf4765a9c5fc6cf59236ece7f570291bca"
    family = "Mirai"
    file_name = "daredevil.x86_64"
    file_type = "elf"
    first_seen = "2026-08-31 21:35:46"
  condition:
    hash.sha256(0, filesize) == "a51ad3b43629a1c9d08cc25bd81ba5bf4765a9c5fc6cf59236ece7f570291bca"
}
```

### Sample 73: `79831d5c99e4b529`

| Field | Value |
|---|---|
| SHA-256 | `79831d5c99e4b529a2f10c8cf335b6cbbc6f0b509981350174c93a87a77285a3` |
| Family label | `Mirai` |
| File name | `daredevil.sparc` |
| File type | `elf` |
| First seen | `2026-08-31 21:29:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac974e25f5ded263b2c32a3580279a3c` |
| SHA-1 | `3765e7a7e28043839e46f913d21a7d4bc014834e` |
| SHA-256 | `79831d5c99e4b529a2f10c8cf335b6cbbc6f0b509981350174c93a87a77285a3` |
| SHA3-384 | `04985337827cc670ad319a045bbc82b90aa4694904880045354955ed946d86381207a4d26d87a9d012da1d1822028e03` |
| TLSH | `T1A233E845DE786A27C6D0323748D34631E5B257A91B7C9A8FBEA72C0DDD08320317EAD9` |
| TELFHASH | `t102e0df41fdb98b1989e7aab4dc8d46a4a8025223a2664b20cf51dbe08c3f554b70dd6e` |
| SSDEEP | `1536:y9mpdgztXgWa5imljAPqq9/Oea/SMpz5a:yEdUtXp9mlcqXE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_79831d5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79831d5c99e4b529a2f10c8cf335b6cbbc6f0b509981350174c93a87a77285a3"
    family = "Mirai"
    file_name = "daredevil.sparc"
    file_type = "elf"
    first_seen = "2026-08-31 21:29:57"
  condition:
    hash.sha256(0, filesize) == "79831d5c99e4b529a2f10c8cf335b6cbbc6f0b509981350174c93a87a77285a3"
}
```

### Sample 74: `cae0a5bae0a415d5`

| Field | Value |
|---|---|
| SHA-256 | `cae0a5bae0a415d5c9cdbe1fd4d086026b450a2cf4ffbc9f6297652ebfb05016` |
| Family label | `Mirai` |
| File name | `daredevil.powerpc` |
| File type | `elf` |
| First seen | `2026-08-31 21:28:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c27bd92f41e04c50b4d6a7cfcacc91a5` |
| SHA-1 | `dfa47761cd3974771244f97e8937f6959dc01ae2` |
| SHA-256 | `cae0a5bae0a415d5c9cdbe1fd4d086026b450a2cf4ffbc9f6297652ebfb05016` |
| SHA3-384 | `ba94f4ae68d343b2afc1a846d58bbd9a08d496aced328b9d6a008be5ee7d7a3bf902dc83ed9323ae14b81ad69812098f` |
| TLSH | `T144E32941730C0447E2A76EF03A3F67E193DFDA9131F4A644295F9B8E8171A325986ECE` |
| SSDEEP | `1536:5fKnd4aSX04/5m5W/ZqDfxfe/Tk1KgW3ocVfCPSQ6OjuHqsvA4/1mWR9HmezuL//:5id4aK04/EyZkfxZKl7gStOjv4y/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_cae0a5ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae0a5bae0a415d5c9cdbe1fd4d086026b450a2cf4ffbc9f6297652ebfb05016"
    family = "Mirai"
    file_name = "daredevil.powerpc"
    file_type = "elf"
    first_seen = "2026-08-31 21:28:18"
  condition:
    hash.sha256(0, filesize) == "cae0a5bae0a415d5c9cdbe1fd4d086026b450a2cf4ffbc9f6297652ebfb05016"
}
```

### Sample 75: `9017db28c11dea6e`

| Field | Value |
|---|---|
| SHA-256 | `9017db28c11dea6e2e36633483476f208c26caaaa2ebb7be4c79860ac3df624a` |
| Family label | `Mirai` |
| File name | `daredevil.powerpc` |
| File type | `elf` |
| First seen | `2026-08-31 21:27:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26e2e1ecc8d3bdb77663ad55ee10fe21` |
| SHA-1 | `f0d73a21f5e66b88fbf372f1fc5fcfe80ae87cef` |
| SHA-256 | `9017db28c11dea6e2e36633483476f208c26caaaa2ebb7be4c79860ac3df624a` |
| SHA3-384 | `c8ebfd92001d39e9cb3a83abc62982f8c4e459d519df6045d9e5ed07cc753ecf037b1fbae080e7cfb359bab40b061bba` |
| TLSH | `T17333F10961621701FEBEDA644CE4D6E8BBB27B9F232B5C539538CF0121B35B9A3426C5` |
| SSDEEP | `1536:z7yWJ2woKHhJzNYTDEn4y4C8l5l1aWVZ/Q4u+qgw095:PyWJ2wFBRN4pHHOl4u+qgws` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_9017db28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9017db28c11dea6e2e36633483476f208c26caaaa2ebb7be4c79860ac3df624a"
    family = "Mirai"
    file_name = "daredevil.powerpc"
    file_type = "elf"
    first_seen = "2026-08-31 21:27:56"
  condition:
    hash.sha256(0, filesize) == "9017db28c11dea6e2e36633483476f208c26caaaa2ebb7be4c79860ac3df624a"
}
```

### Sample 76: `159b2822082e57ea`

| Field | Value |
|---|---|
| SHA-256 | `159b2822082e57ea6a745ee386aeb72b3e02570a571c987efa915d03b8832010` |
| Family label | `Mirai` |
| File name | `daredevil.sh4` |
| File type | `elf` |
| First seen | `2026-08-31 21:19:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7d0668d016e95d5ce3db3f148d31579` |
| SHA-1 | `1cbf3376cac7d42df0f0ebcab40d693f96df17f5` |
| SHA-256 | `159b2822082e57ea6a745ee386aeb72b3e02570a571c987efa915d03b8832010` |
| SHA3-384 | `6b5c798ef2a4a0af1a3b5fbdaebf58ca450b7d0730a500c9658f264d50d1ee70d3f011f3b835d9d91dc4fc82c30441db` |
| TLSH | `T16AD36963CC352FA8E566E970B035CBBA0763A455810B5FBE29A3C2715007D8CF6967F8` |
| SSDEEP | `1536:E7jOPo1ugZdcy11q1qtZnmCyKFcjDzpMQIHR+Wwjyg/OWqvn:E7ao1tcy11rtZm4FiMQ2+Wwygpqv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_159b2822
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "159b2822082e57ea6a745ee386aeb72b3e02570a571c987efa915d03b8832010"
    family = "Mirai"
    file_name = "daredevil.sh4"
    file_type = "elf"
    first_seen = "2026-08-31 21:19:12"
  condition:
    hash.sha256(0, filesize) == "159b2822082e57ea6a745ee386aeb72b3e02570a571c987efa915d03b8832010"
}
```

### Sample 77: `f68d138f6c5df634`

| Field | Value |
|---|---|
| SHA-256 | `f68d138f6c5df634fe3c57cb224d9f873af8f7c41a2174ac90914bce03b3cce7` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-31 21:19:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd45756e5879baeee1de8e75889011ad` |
| SHA-1 | `bb5a1c9cdb4a13e2b26b91bc9b2178ba0eb9d735` |
| SHA-256 | `f68d138f6c5df634fe3c57cb224d9f873af8f7c41a2174ac90914bce03b3cce7` |
| SHA3-384 | `09ce4dfbfe44056a84e2103921e74942bd7def5cd387fdeb44492b12fd7f11f4905a42a715ed6f2fc6d32e20082240fe` |
| TLSH | `T1CE235C6516867C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF68C4A69DD109B1D` |
| SSDEEP | `768:w+i9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:w+ncr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_f68d138f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f68d138f6c5df634fe3c57cb224d9f873af8f7c41a2174ac90914bce03b3cce7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-31 21:19:10"
  condition:
    hash.sha256(0, filesize) == "f68d138f6c5df634fe3c57cb224d9f873af8f7c41a2174ac90914bce03b3cce7"
}
```

### Sample 78: `6cc6ddf433301a70`

| Field | Value |
|---|---|
| SHA-256 | `6cc6ddf433301a7053aed3cc2895286dd4229ebfa294e84c229c80a1a94f1f76` |
| Family label | `Mirai` |
| File name | `daredevil.armv6l` |
| File type | `elf` |
| First seen | `2026-08-31 21:03:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e1aa9f741190cf96f4f9c43d4619b03` |
| SHA-1 | `411c8c4624ca7d39c08c8b8170538f59126a33ec` |
| SHA-256 | `6cc6ddf433301a7053aed3cc2895286dd4229ebfa294e84c229c80a1a94f1f76` |
| SHA3-384 | `161e6b23d7e84120d3be30d256ff74cebe59c2526facfdfa78a649fcf8840fbbf1cd0d4f94e01aab03c47da8fb3b2dbe` |
| TLSH | `T16CE30A96BC818B11D5D151BAFE1E124E33131B78E3EE72039D186B29778BCBB0A3B515` |
| TELFHASH | `t10de0685bfe002acc7ac640a082fb19ab179139ff3b153542813c0b5654d78e6700982c` |
| SSDEEP | `3072:puwcXsRgBOaiuS8Ea7XZrrrbYatSrW0Z4IiFLJ:pdg8j8jXJr0auTLiFLJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_6cc6ddf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cc6ddf433301a7053aed3cc2895286dd4229ebfa294e84c229c80a1a94f1f76"
    family = "Mirai"
    file_name = "daredevil.armv6l"
    file_type = "elf"
    first_seen = "2026-08-31 21:03:27"
  condition:
    hash.sha256(0, filesize) == "6cc6ddf433301a7053aed3cc2895286dd4229ebfa294e84c229c80a1a94f1f76"
}
```

### Sample 79: `96fea7d005d9c9bc`

| Field | Value |
|---|---|
| SHA-256 | `96fea7d005d9c9bc69db0b2e9cfa63904f1010995d0aa44d2aba4a9c07d4b5cb` |
| Family label | `Mirai` |
| File name | `daredevil.armv6l` |
| File type | `elf` |
| First seen | `2026-08-31 21:02:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ead4d904626b1ecfb1db51ec15efed3` |
| SHA-1 | `48013f2d5f944c930b98de226c43aa530767a911` |
| SHA-256 | `96fea7d005d9c9bc69db0b2e9cfa63904f1010995d0aa44d2aba4a9c07d4b5cb` |
| SHA3-384 | `fac486062e964a0e3a31164a310814d62cb408741e033db702434970651c71d6fbc18f5f4c8e2fbef66c5273750b1c89` |
| TLSH | `T19B430260E09DDDAAC860643C53C816C27A751F3650BD34AAB44F8AB4F4F3CC9847AB87` |
| SSDEEP | `768:lw+ITzLykZC6Dj8rca1JeZF7kk1KQx9WntkCPuCNoRtUlZeL/X6dLmHuhv6uhtg4:lgH+h6XA1Je3IUFokCPZorGmH+6uhPLx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_96fea7d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96fea7d005d9c9bc69db0b2e9cfa63904f1010995d0aa44d2aba4a9c07d4b5cb"
    family = "Mirai"
    file_name = "daredevil.armv6l"
    file_type = "elf"
    first_seen = "2026-08-31 21:02:33"
  condition:
    hash.sha256(0, filesize) == "96fea7d005d9c9bc69db0b2e9cfa63904f1010995d0aa44d2aba4a9c07d4b5cb"
}
```

### Sample 80: `742c11c31cc3a27f`

| Field | Value |
|---|---|
| SHA-256 | `742c11c31cc3a27ff7b602db2208b0c92411fc3e2b86423061b3ffc519c0fba5` |
| Family label | `Mirai` |
| File name | `daredevil.armv5l` |
| File type | `elf` |
| First seen | `2026-08-31 20:58:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc8a4997ade658ac164cf012ba7fc3e5` |
| SHA-1 | `10d9b4ff1ab99ded9ecb0792039bab51695f9cf7` |
| SHA-256 | `742c11c31cc3a27ff7b602db2208b0c92411fc3e2b86423061b3ffc519c0fba5` |
| SHA3-384 | `5b95ecf15518b9d9bed2eb965dbb81c08d200c278d57a15cf5add041c6bcd49b16babfdf6c9f2e2d024c3d858865179d` |
| TLSH | `T1F8E32B89BC848B13C6E161B7FF4E428D372B0769D3EA71038D196B65375B9970E3B242` |
| TELFHASH | `t1de216269ee481e8c77f8842ae2cd4126662531fcbb2734115f3b9a5f0e62dd07021837` |
| SSDEEP | `3072:NCC2YqNovdnM+d64Des4X+6GXxV5xwrFPCd:NCrYqOvdM+d6hs4XrGX/o5PCd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_742c11c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "742c11c31cc3a27ff7b602db2208b0c92411fc3e2b86423061b3ffc519c0fba5"
    family = "Mirai"
    file_name = "daredevil.armv5l"
    file_type = "elf"
    first_seen = "2026-08-31 20:58:17"
  condition:
    hash.sha256(0, filesize) == "742c11c31cc3a27ff7b602db2208b0c92411fc3e2b86423061b3ffc519c0fba5"
}
```

### Sample 81: `1ab7ad748f7523ae`

| Field | Value |
|---|---|
| SHA-256 | `1ab7ad748f7523ae7cfbc7ee3d535f461213edcbaf9faea0db34921a86574270` |
| Family label | `Mirai` |
| File name | `daredevil.armv5l` |
| File type | `elf` |
| First seen | `2026-08-31 20:57:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bb1286776d2350b380a7619ac92d423` |
| SHA-1 | `6946933379824c9c31d3945fb160e5793972e78f` |
| SHA-256 | `1ab7ad748f7523ae7cfbc7ee3d535f461213edcbaf9faea0db34921a86574270` |
| SHA3-384 | `303e45e6aafa9eb51a08eee3785cc6398c8164bef8c931f8d827556529e9575a08924f59188f68a7a16d8ea6c043edb3` |
| TLSH | `T1643302A2908BE434DF721C3BED7C6E57EA665990835D26E603F4220C70E3DA7C474390` |
| SSDEEP | `768:xr8ljrnMBJ5/ZKnbl3/06qrvEJI6ffENk9UjxSunF6rJXLJqSKs3UozA:d85MP50nbpJqrvwI6HENk94rWlRHzA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_1ab7ad74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ab7ad748f7523ae7cfbc7ee3d535f461213edcbaf9faea0db34921a86574270"
    family = "Mirai"
    file_name = "daredevil.armv5l"
    file_type = "elf"
    first_seen = "2026-08-31 20:57:43"
  condition:
    hash.sha256(0, filesize) == "1ab7ad748f7523ae7cfbc7ee3d535f461213edcbaf9faea0db34921a86574270"
}
```

### Sample 82: `dd0c4672a56e0251`

| Field | Value |
|---|---|
| SHA-256 | `dd0c4672a56e025141257044bcba49bca663c4288d0049ce524ab0745ac5085e` |
| Family label | `Mirai` |
| File name | `daredevil.armv4l` |
| File type | `elf` |
| First seen | `2026-08-31 20:54:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e805e7ca28169c7e6da446e431de74c4` |
| SHA-1 | `5c33d1077a19fed2f66fdaa1adb41f843bfed2a2` |
| SHA-256 | `dd0c4672a56e025141257044bcba49bca663c4288d0049ce524ab0745ac5085e` |
| SHA3-384 | `02bcb9f395e0ba72799fc241c6d9f5939cba392c1ceeecfd96eb18e26d57915c5afbcd12f471a0f0e371f281bd74c66c` |
| TLSH | `T1AEE32B49FC858713C6E261B7FB4E428D372B07A8D3EA71078D196B25375B5A70E3B242` |
| TELFHASH | `t1c931e212ee9c1eccabd1808c01af400b57aa35e9a7295446df7e5f4f4693ad1b53c83a` |
| SSDEEP | `3072:9y63GQ7Llp+5LqfmoX4ur9Iv45YGFvXpUmB:9yYj7LP+5LqfVX4uJIvo1BXp3B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_dd0c4672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd0c4672a56e025141257044bcba49bca663c4288d0049ce524ab0745ac5085e"
    family = "Mirai"
    file_name = "daredevil.armv4l"
    file_type = "elf"
    first_seen = "2026-08-31 20:54:18"
  condition:
    hash.sha256(0, filesize) == "dd0c4672a56e025141257044bcba49bca663c4288d0049ce524ab0745ac5085e"
}
```

### Sample 83: `4d17d32ed6efe92e`

| Field | Value |
|---|---|
| SHA-256 | `4d17d32ed6efe92ea61d16602f9c6cd5261cdd3820adec427ee68d4088b6ab5b` |
| Family label | `Mirai` |
| File name | `linux.bin` |
| File type | `elf` |
| First seen | `2026-08-31 20:53:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1fa4538693b955479135b0d6f6fc90c` |
| SHA-1 | `2442ad6a86fc19ca3a50f64005ebf50edbae9791` |
| SHA-256 | `4d17d32ed6efe92ea61d16602f9c6cd5261cdd3820adec427ee68d4088b6ab5b` |
| SHA3-384 | `d1ca5b1fe345372646aaeaeadf4d4204900226304e45db34d242fea09396c801a9b70a586508434956fe1bce2a176b56` |
| TLSH | `T167A69E4BF4A604BDC4BAC870875FE2B2AE3438980150657B7A5456723F76F302B6AFD1` |
| SSDEEP | `98304:CrhAVfSukDI7rHkONESzhsmaqp/EHeF0xa44mPIyb+TJyNRSawGqR6wmHDLH91k6:MDdPcyNRpNwmHDLH9/ES3BUGAHc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_4d17d32e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d17d32ed6efe92ea61d16602f9c6cd5261cdd3820adec427ee68d4088b6ab5b"
    family = "Mirai"
    file_name = "linux.bin"
    file_type = "elf"
    first_seen = "2026-08-31 20:53:42"
  condition:
    hash.sha256(0, filesize) == "4d17d32ed6efe92ea61d16602f9c6cd5261cdd3820adec427ee68d4088b6ab5b"
}
```

### Sample 84: `ce3b811ccd6e61f9`

| Field | Value |
|---|---|
| SHA-256 | `ce3b811ccd6e61f95475b63e7dbed1e78c5bc1835a55908c41ad67a37443fa2b` |
| Family label | `Mirai` |
| File name | `daredevil.armv4l` |
| File type | `elf` |
| First seen | `2026-08-31 20:53:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bd48f42a2e579d7add90dfdfef24bef` |
| SHA-1 | `fe63984693892b19e31953a9356ea46d46549612` |
| SHA-256 | `ce3b811ccd6e61f95475b63e7dbed1e78c5bc1835a55908c41ad67a37443fa2b` |
| SHA3-384 | `059136dfa8d5df004b2a76e47159cfd7f58821ccd1b2ce50ed4c585ee32a0ad4ee8c900ed65ccdb9331e2054815c0170` |
| TLSH | `T1C933011B0D8FEC349031407DAE34554EA4E36E62C16EBA6605F1857AD58437DBEFB183` |
| SSDEEP | `1536:ooWJF6dlXn8M81oHASBgpgTOOEuua4fCyPgzA:IcVwogsPtV43gE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_ce3b811c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce3b811ccd6e61f95475b63e7dbed1e78c5bc1835a55908c41ad67a37443fa2b"
    family = "Mirai"
    file_name = "daredevil.armv4l"
    file_type = "elf"
    first_seen = "2026-08-31 20:53:40"
  condition:
    hash.sha256(0, filesize) == "ce3b811ccd6e61f95475b63e7dbed1e78c5bc1835a55908c41ad67a37443fa2b"
}
```

### Sample 85: `91ecbc4e11331252`

| Field | Value |
|---|---|
| SHA-256 | `91ecbc4e11331252e0f73f30723339893f2f04bfbd1713bb033fc13e200d7a5b` |
| Family label | `Mirai` |
| File name | `daredevil.armv7l` |
| File type | `elf` |
| First seen | `2026-08-31 20:44:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1064abb4f774ee5833edaf7cd7a393bd` |
| SHA-1 | `5cbd89deeb20c07c13fbc4100ff9171299d0461b` |
| SHA-256 | `91ecbc4e11331252e0f73f30723339893f2f04bfbd1713bb033fc13e200d7a5b` |
| SHA3-384 | `6ffb1ce4687a630065ea60022959c9eb6309c809629f19941a466be6698de7fbfbf9a99da024a7ca7dde0983ae7eece2` |
| TLSH | `T14BA308D6BC805B01D5D626BAFE0F114933534BB8E3F9B103CE185B2E678AC6B0A77615` |
| TELFHASH | `t179e026b25b7c198d7fc5830140c87105a9ed35860d6611c3ae3de52d8667483f80da33` |
| SSDEEP | `1536:fQnGjcB//fbNJvbByNXqJgnlOuhan8v6yW9gelOchiADOj4M52YJ+F:u5/TNpByNXVlOuhan8v6dDLDOMMEDF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_91ecbc4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91ecbc4e11331252e0f73f30723339893f2f04bfbd1713bb033fc13e200d7a5b"
    family = "Mirai"
    file_name = "daredevil.armv7l"
    file_type = "elf"
    first_seen = "2026-08-31 20:44:18"
  condition:
    hash.sha256(0, filesize) == "91ecbc4e11331252e0f73f30723339893f2f04bfbd1713bb033fc13e200d7a5b"
}
```

### Sample 86: `68087159a07ff7dc`

| Field | Value |
|---|---|
| SHA-256 | `68087159a07ff7dcec0c23eade3e7781177a04a7fe7860a9df2a880a39d90df4` |
| Family label | `Mirai` |
| File name | `daredevil.armv7l` |
| File type | `elf` |
| First seen | `2026-08-31 20:43:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96a43ef06118942acaf1bfea835551e2` |
| SHA-1 | `84bf7d9d2763820254c787f1186054a3ce9fd3d5` |
| SHA-256 | `68087159a07ff7dcec0c23eade3e7781177a04a7fe7860a9df2a880a39d90df4` |
| SHA3-384 | `695185ee1901aa472ad31e6d62d364117f51373e5a362c0b503da5734fbd6a05081e155c191b85624801b1e05edf075e` |
| TLSH | `T13813E1A4D772F892CF35207BDB75854A1B155BA4E8FF9615333102E4E787C461ABC702` |
| SSDEEP | `768:sX+J17wzSqpD+haUT+wiQdgvgemcP8z69q3UELrc2:e+oFaAU7gELV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_68087159
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68087159a07ff7dcec0c23eade3e7781177a04a7fe7860a9df2a880a39d90df4"
    family = "Mirai"
    file_name = "daredevil.armv7l"
    file_type = "elf"
    first_seen = "2026-08-31 20:43:37"
  condition:
    hash.sha256(0, filesize) == "68087159a07ff7dcec0c23eade3e7781177a04a7fe7860a9df2a880a39d90df4"
}
```

### Sample 87: `6374eb353f02c7b2`

| Field | Value |
|---|---|
| SHA-256 | `6374eb353f02c7b26e00697a32f4a4f613402ca0296f5f10afdb3243f729c1b9` |
| Family label | `ConnectWise` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-31 20:42:44` |
| Reporter | `Bitsight` |
| Tags | `C, ConnectWise, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a56af1b76500fad38edb4958e6a29399` |
| SHA-1 | `98bf6e4cfe91f5a1154ae0e168437b81318dd24b` |
| SHA-256 | `6374eb353f02c7b26e00697a32f4a4f613402ca0296f5f10afdb3243f729c1b9` |
| SHA3-384 | `6dcee9c0eb923b17a50d67ebb6a0b1e336cdc16182b9d468a38b04596b629f9464a9eaaecfac7004af9929ec57e294c9` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T116771256E2FD00E8D5BAC0BCC6575517EBB23459173097EB52A48A692F33BE0AE3D310` |
| SSDEEP | `786432:iuML+5XoeOvHiwB3sn+h19W25F+wX0ff6yajCs6+4S3NftN:i5WoeeCwDr9WG+tf6fj4ulN` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_087_6374eb35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6374eb353f02c7b26e00697a32f4a4f613402ca0296f5f10afdb3243f729c1b9"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-31 20:42:44"
  condition:
    hash.sha256(0, filesize) == "6374eb353f02c7b26e00697a32f4a4f613402ca0296f5f10afdb3243f729c1b9"
}
```

### Sample 88: `bc13326814f70729`

| Field | Value |
|---|---|
| SHA-256 | `bc13326814f7072968ea74acdc47b873d733e8d1894a78e05a89b99db0ef014c` |
| Family label | `unknown` |
| File name | `bc13326814f7072968ea74acdc47b873d733e8d1894a78e05a89b99db0ef014c.bin` |
| File type | `exe` |
| First seen | `2026-08-31 20:38:11` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4d31628feacdf908bad5f70f4bafff7` |
| SHA-1 | `da3969b2b6f2a5342a54f6f08fde92e02e1cc38c` |
| SHA-256 | `bc13326814f7072968ea74acdc47b873d733e8d1894a78e05a89b99db0ef014c` |
| SHA3-384 | `894d1821ddd62af596cf150efe27f6a18992820cfe060272bebfeba38fe260f6384a4e0c8c1a9e848036b2bb364c7e51` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D4366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaau:uc3XND1aJrCOku` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_bc133268
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc13326814f7072968ea74acdc47b873d733e8d1894a78e05a89b99db0ef014c"
    family = "unknown"
    file_name = "bc13326814f7072968ea74acdc47b873d733e8d1894a78e05a89b99db0ef014c.bin"
    file_type = "exe"
    first_seen = "2026-08-31 20:38:11"
  condition:
    hash.sha256(0, filesize) == "bc13326814f7072968ea74acdc47b873d733e8d1894a78e05a89b99db0ef014c"
}
```

### Sample 89: `4469377d9fad4013`

| Field | Value |
|---|---|
| SHA-256 | `4469377d9fad4013ab26f9c55cc12d4cde554acca043d1a89dccc0d5cc88896d` |
| Family label | `unknown` |
| File name | `4469377d9fad4013ab26f9c55cc12d4cde554acca043d1a89dccc0d5cc88896d.bin` |
| File type | `exe` |
| First seen | `2026-08-31 20:38:08` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ce48c3ad77274bc25aa46a951c12b42` |
| SHA-1 | `5ad40f2d790ab484dbb579c7a4ec83790ac2fef8` |
| SHA-256 | `4469377d9fad4013ab26f9c55cc12d4cde554acca043d1a89dccc0d5cc88896d` |
| SHA3-384 | `f502a76f10acf33b542655b1c0eb40ddb43d39884a0bfb130f06e574e1f35bfbf467ce5b89f44e2b3aa2c1a9069722f1` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D9366A03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaX:uc3XND1aJrCOkX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_4469377d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4469377d9fad4013ab26f9c55cc12d4cde554acca043d1a89dccc0d5cc88896d"
    family = "unknown"
    file_name = "4469377d9fad4013ab26f9c55cc12d4cde554acca043d1a89dccc0d5cc88896d.bin"
    file_type = "exe"
    first_seen = "2026-08-31 20:38:08"
  condition:
    hash.sha256(0, filesize) == "4469377d9fad4013ab26f9c55cc12d4cde554acca043d1a89dccc0d5cc88896d"
}
```

### Sample 90: `e818ac036ed66a4b`

| Field | Value |
|---|---|
| SHA-256 | `e818ac036ed66a4bf55214ab534f25033de9608a733b5487ca2a1a97254017a3` |
| Family label | `unknown` |
| File name | `e818ac036ed66a4bf55214ab534f25033de9608a733b5487ca2a1a97254017a3.bin` |
| File type | `exe` |
| First seen | `2026-08-31 20:25:21` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c33af353c748bb3502ce3e6e8ba4cc50` |
| SHA-1 | `c30ae02ba309b0773b4f3f46d513ef996950a756` |
| SHA-256 | `e818ac036ed66a4bf55214ab534f25033de9608a733b5487ca2a1a97254017a3` |
| SHA3-384 | `08519ec2a74cd12962b106ebc1b0eec28792910f3a8d05ad5bc2fad168dc65a787d49e839cabd22c4394da0173065caa` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F9366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaT:uc3XND1aJrCOkT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_e818ac03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e818ac036ed66a4bf55214ab534f25033de9608a733b5487ca2a1a97254017a3"
    family = "unknown"
    file_name = "e818ac036ed66a4bf55214ab534f25033de9608a733b5487ca2a1a97254017a3.bin"
    file_type = "exe"
    first_seen = "2026-08-31 20:25:21"
  condition:
    hash.sha256(0, filesize) == "e818ac036ed66a4bf55214ab534f25033de9608a733b5487ca2a1a97254017a3"
}
```

### Sample 91: `b6caa545312250f6`

| Field | Value |
|---|---|
| SHA-256 | `b6caa545312250f634c618613441d164a8bfeb76fb8c811d141af191cc3345a8` |
| Family label | `Vidar` |
| File name | `f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514.exe` |
| File type | `exe` |
| First seen | `2026-08-31 19:42:21` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef02113b3b47834444477f5f63e08709` |
| SHA-1 | `42bbf4113e953048e10e94a3eca4da056cad6a9e` |
| SHA-256 | `b6caa545312250f634c618613441d164a8bfeb76fb8c811d141af191cc3345a8` |
| SHA3-384 | `f5615ace7527bd6eed5b653f06af06d390594c915acb6f25ee9f48dbd12f9c1b746ad25ec6101ce17ee26950068cbf5b` |
| TLSH | `T1F0551E8ED58213B5B393FB67A21AD6329DF6310580728635CF85AD359F02F24A02DEDD` |
| SSDEEP | `12288:A5C/oLYXGgfcKf+fkX6VzeGQzwFrSOYB:x/RXSgpG0w8` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_091_b6caa545
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6caa545312250f634c618613441d164a8bfeb76fb8c811d141af191cc3345a8"
    family = "Vidar"
    file_name = "f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:42:21"
  condition:
    hash.sha256(0, filesize) == "b6caa545312250f634c618613441d164a8bfeb76fb8c811d141af191cc3345a8"
}
```

### Sample 92: `f2b7145b0521b3ee`

| Field | Value |
|---|---|
| SHA-256 | `f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514` |
| Family label | `Vidar` |
| File name | `f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514.exe` |
| File type | `exe` |
| First seen | `2026-08-31 19:42:00` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a10410623b8b5ffaa0d7e7ce65ff21dc` |
| SHA-1 | `bd8511403c5959f7e764c730652da9df47e5dd1f` |
| SHA-256 | `f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514` |
| SHA3-384 | `bb144d4b34764f18604d28d44c29094cc4e421b3ade676b6082ea894580d1f15440a0529dae6339202d5c4c9f5174ef8` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1B874228987170393F5BD5B36C094C3563A9C163F78CAEB3259EC535A3380E04AB5ADB9` |
| SSDEEP | `6144:efyEidk2F1PFgctduPOjJNVwX8LcqSex1EHoO6orqg2laey:GHID1ictduGjJTfYqSb0B/` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_092_f2b7145b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514"
    family = "Vidar"
    file_name = "f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:42:00"
  condition:
    hash.sha256(0, filesize) == "f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514"
}
```

### Sample 93: `ab168436a009ee55`

| Field | Value |
|---|---|
| SHA-256 | `ab168436a009ee553b8a3357c34bf7efb1a834868029e5ee0611041d32441611` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-31 19:29:00` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `613489399e8693abdb9f1992e352f9d1` |
| SHA-256 | `ab168436a009ee553b8a3357c34bf7efb1a834868029e5ee0611041d32441611` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_ab168436
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab168436a009ee553b8a3357c34bf7efb1a834868029e5ee0611041d32441611"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 19:29:00"
  condition:
    hash.sha256(0, filesize) == "ab168436a009ee553b8a3357c34bf7efb1a834868029e5ee0611041d32441611"
}
```

### Sample 94: `94eb933e0fd821cd`

| Field | Value |
|---|---|
| SHA-256 | `94eb933e0fd821cddd5a94f4e8a6e14a562a13c6ae473d48f459ea745990dbc0` |
| Family label | `unknown` |
| File name | `9z7BGnRGpgs8cZv7.exe` |
| File type | `exe` |
| First seen | `2026-08-31 19:27:27` |
| Reporter | `skocherhan` |
| Tags | `192-162-199-246, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e16927831470d9b330f7c7392d01027a` |
| SHA-1 | `953fa1efcb71e5e9452707d15ca3db8eeb68c9f8` |
| SHA-256 | `94eb933e0fd821cddd5a94f4e8a6e14a562a13c6ae473d48f459ea745990dbc0` |
| SHA3-384 | `8e68ec3268488ab3eb7ed94a88064e20b1815deac34b9947526c0f1cac7cc43ac4fa6ac0bcf9d064da3703d9e10d36d5` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T1C9D52349B5FA0EB5C872C3B38F43F46EB06D3B455B608E96B6DC2A046D934582C763B1` |
| SSDEEP | `49152:OzudwG1GuH1FVCQ142cGH3LFgjkmXMuyfGEQEujuWW4a+vFbBkZDPQp+fkd7a9sC:OikuH5Z7PkOfvD+pWp3Cm9sh5C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_94eb933e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94eb933e0fd821cddd5a94f4e8a6e14a562a13c6ae473d48f459ea745990dbc0"
    family = "unknown"
    file_name = "9z7BGnRGpgs8cZv7.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:27:27"
  condition:
    hash.sha256(0, filesize) == "94eb933e0fd821cddd5a94f4e8a6e14a562a13c6ae473d48f459ea745990dbc0"
}
```

### Sample 95: `55ae76cd1de5cf58`

| Field | Value |
|---|---|
| SHA-256 | `55ae76cd1de5cf5824f5da8305260a96f45fc1a379377fd593912e502381609b` |
| Family label | `unknown` |
| File name | `55ae76cd1de5cf5824f5da8305260a96f45fc1a379377fd593912e502381609b.exe` |
| File type | `exe` |
| First seen | `2026-08-31 19:26:57` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee49e0012537cd4eba7b697937f6461b` |
| SHA-1 | `fdfc7112cdf2478088756141d874629b213d9673` |
| SHA-256 | `55ae76cd1de5cf5824f5da8305260a96f45fc1a379377fd593912e502381609b` |
| SHA3-384 | `ee43f0907797ac9a98b505d915b5a86322411ee5a921fd89eada1dd79490ef342328a84118a4a695e379e3bf5f3bf732` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T18ED5239364BA1970C433C7F68F52F4BEB06937908BA5CD83F2CD68005E626D4553ABB9` |
| SSDEEP | `49152:Tt4arse1THx0J8A0ZmfFWLiDvpSALd8Klouw86XXjB9eD/VxF1S7DSNgOS6jzDH:TeTedHK3wLwvpSALd1lo586XXW9zKajn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_55ae76cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55ae76cd1de5cf5824f5da8305260a96f45fc1a379377fd593912e502381609b"
    family = "unknown"
    file_name = "55ae76cd1de5cf5824f5da8305260a96f45fc1a379377fd593912e502381609b.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:26:57"
  condition:
    hash.sha256(0, filesize) == "55ae76cd1de5cf5824f5da8305260a96f45fc1a379377fd593912e502381609b"
}
```

### Sample 96: `a85fb25707cd8c24`

| Field | Value |
|---|---|
| SHA-256 | `a85fb25707cd8c24df4f43a59efa01fca8fc86ddca69d957f62800900ce0133f` |
| Family label | `unknown` |
| File name | `gM9anpOuZNKX8zHj.exe` |
| File type | `exe` |
| First seen | `2026-08-31 19:26:01` |
| Reporter | `skocherhan` |
| Tags | `192-162-199-246, exe, guard7-barnfabric-click, report-pantrystudio18-lol` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0f3957ca71f9380ff1dc216f4462db1` |
| SHA-1 | `a6bb938580ad1df0f64550cfb3b18c9044998989` |
| SHA-256 | `a85fb25707cd8c24df4f43a59efa01fca8fc86ddca69d957f62800900ce0133f` |
| SHA3-384 | `9464392b38c4ea735f93eb7491ede5dc582bf2dca052249411fea0bfda7feffd980205e2b8241253d9cbadaf88fa910a` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T117D5238DBDDA2D36E433CB7353D3607EB129778842604D5E2A886B153E629197C373B8` |
| SSDEEP | `49152:+crbhcaeBn7mB+H7BJOoezwa0Eby1TuCQLFf6lD8b2XDuMyb+cOH5HkmLU9ApX:+cPhPqK8La0t1qJClDqMbc25zR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_a85fb257
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a85fb25707cd8c24df4f43a59efa01fca8fc86ddca69d957f62800900ce0133f"
    family = "unknown"
    file_name = "gM9anpOuZNKX8zHj.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:26:01"
  condition:
    hash.sha256(0, filesize) == "a85fb25707cd8c24df4f43a59efa01fca8fc86ddca69d957f62800900ce0133f"
}
```

### Sample 97: `79b3612d856a4949`

| Field | Value |
|---|---|
| SHA-256 | `79b3612d856a4949395de781b875c1625ff8bd1c9cb8790209bfb4819a2240d9` |
| Family label | `njrat` |
| File name | `1807503a422d180ea91f0a23cbd76962.exe` |
| File type | `exe` |
| First seen | `2026-08-31 19:15:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1807503a422d180ea91f0a23cbd76962` |
| SHA-1 | `33759ebbbc586e2f574838c7fdba7421862e4689` |
| SHA-256 | `79b3612d856a4949395de781b875c1625ff8bd1c9cb8790209bfb4819a2240d9` |
| SHA3-384 | `6bab5479755bc250f8f03dbc1f55778b81983830f0956ba60b13d2c90ee664825d8c22ab3f22def97ff03f7ee005e5a4` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T195432844BFEA4A01E2BD8F3469F655150A34BA63E932DB1F4CD168DB13326C58C80FE6` |
| SSDEEP | `1536:mdv4Dnpe/NoTcwiDESPDywsNMDwWXExI3pmSm:e4Dn8ymDRPDywsNMDvXExI3pm` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_097_79b3612d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79b3612d856a4949395de781b875c1625ff8bd1c9cb8790209bfb4819a2240d9"
    family = "njrat"
    file_name = "1807503a422d180ea91f0a23cbd76962.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:15:07"
  condition:
    hash.sha256(0, filesize) == "79b3612d856a4949395de781b875c1625ff8bd1c9cb8790209bfb4819a2240d9"
}
```

### Sample 98: `2bd9ba7932c288d4`

| Field | Value |
|---|---|
| SHA-256 | `2bd9ba7932c288d4b2f8a1ef48e4628c04f8ed12c340d775b4765fbaaff61869` |
| Family label | `CoinMiner` |
| File name | `2bd9ba7932c288d4b2f8a1ef48e4628c04f8ed12c340d775b4765fbaaff61869.exe` |
| File type | `exe` |
| First seen | `2026-08-31 19:07:01` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7c515d44e5a53d4f695cee4d9ae67b1` |
| SHA-1 | `0e30b33acd596bd37ed8c0c5774fe5c1b5e88af2` |
| SHA-256 | `2bd9ba7932c288d4b2f8a1ef48e4628c04f8ed12c340d775b4765fbaaff61869` |
| SHA3-384 | `5df40cd14acf4ddefa6d53804df74a98bbf5612bc133843051d200013e49999d58476f7f68ef0a2f0023649ea4017901` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T19D36339678C25176E4A1C3F88692747EB377BB519A63BD0335DC6A08CC5BF28483E781` |
| SSDEEP | `98304:Wmz3/83RIx/OPRApmq2REhJ72Lbyr9GHaXJy0GUqTy462M4sD5:v3/Oy/OKpCRAsLbuxX00pqId` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_098_2bd9ba79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bd9ba7932c288d4b2f8a1ef48e4628c04f8ed12c340d775b4765fbaaff61869"
    family = "CoinMiner"
    file_name = "2bd9ba7932c288d4b2f8a1ef48e4628c04f8ed12c340d775b4765fbaaff61869.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:07:01"
  condition:
    hash.sha256(0, filesize) == "2bd9ba7932c288d4b2f8a1ef48e4628c04f8ed12c340d775b4765fbaaff61869"
}
```

### Sample 99: `149977f683910a1b`

| Field | Value |
|---|---|
| SHA-256 | `149977f683910a1b628460085407a8285817902b3e3d38952d78a6aa1f09f53a` |
| Family label | `Vidar` |
| File name | `149977f683910a1b628460085407a8285817902b3e3d38952d78a6aa1f09f53a.bin` |
| File type | `exe` |
| First seen | `2026-08-31 19:05:49` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74ce5e3a2f933a3eb411add5912bbdb6` |
| SHA-1 | `08fe619112112745270feec84c8bf592541b7cac` |
| SHA-256 | `149977f683910a1b628460085407a8285817902b3e3d38952d78a6aa1f09f53a` |
| SHA3-384 | `30b79222803621d2f8b7432a0a36cafd4f57321e4482412fd78d76a7f1776d62cf29ff13b90db2076637e689724f13de` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1A5069D0BBCA15D98C0E5377055778281B73DB8140B3A67E72E90A6753F3A6C1ADB7B80` |
| SSDEEP | `49152:FkVucPOrUCJ2KRmWsh5iDtle9DCvdnt2ebQs5QXVMsM6Mxstx:FkJwR+o7eyvbSXask4x` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_099_149977f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "149977f683910a1b628460085407a8285817902b3e3d38952d78a6aa1f09f53a"
    family = "Vidar"
    file_name = "149977f683910a1b628460085407a8285817902b3e3d38952d78a6aa1f09f53a.bin"
    file_type = "exe"
    first_seen = "2026-08-31 19:05:49"
  condition:
    hash.sha256(0, filesize) == "149977f683910a1b628460085407a8285817902b3e3d38952d78a6aa1f09f53a"
}
```

### Sample 100: `2b20eb4237ad2eab`

| Field | Value |
|---|---|
| SHA-256 | `2b20eb4237ad2eab05c4a2ad261bcfd436663cf32e2a45526e17dfd3a51a095d` |
| Family label | `Amadey` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-31 19:03:22` |
| Reporter | `Bitsight` |
| Tags | `1TEST.file, Amadey, C, dropped-by-GCleaner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d022bb6de095252f2b2051fe822c3fbe` |
| SHA-1 | `447ca548a1d7d6cbb50eafe0d0edc1580cf55c41` |
| SHA-256 | `2b20eb4237ad2eab05c4a2ad261bcfd436663cf32e2a45526e17dfd3a51a095d` |
| SHA3-384 | `0ce10518d22fd1ebbaefd8b1a5413c1ac56fdaf18f60eec22104c85b098ef7cf48619cf7a1d2d7194c3c318f43720707` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1FA65D06436708620CB7A4B395933C144633C509AEBBFC6553AAB1DBCA8D3BD749063B7` |
| SSDEEP | `24576:Ey9M+gOez/TiIPUzyo+96O3EkFYD6F+SCq6HAFpzrws8eKL5+ULeLMAby8U8UTA:EWJC/2IPUzyo+96O3EkFYD6F+SCq6HAl` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_100_2b20eb42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b20eb4237ad2eab05c4a2ad261bcfd436663cf32e2a45526e17dfd3a51a095d"
    family = "Amadey"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-31 19:03:22"
  condition:
    hash.sha256(0, filesize) == "2b20eb4237ad2eab05c4a2ad261bcfd436663cf32e2a45526e17dfd3a51a095d"
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
 * Generated: 2026-09-01T05:18:28.428487+00:00
 */

rule MalwareBazaar_unknown_001_8a6f1135
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a6f1135fc2c48b4fe2de478e87dc158b78b708c7879ba6a0bca58087434fe27"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-09-01 05:14:44"
  condition:
    hash.sha256(0, filesize) == "8a6f1135fc2c48b4fe2de478e87dc158b78b708c7879ba6a0bca58087434fe27"
}

rule MalwareBazaar_Mirai_002_3f406f19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f406f1968f6c47503b8ef56a39540d6cf3b2b7c80f6f58e952be5987eae64a5"
    family = "Mirai"
    file_name = "3f406f1968f6c47503b8ef56a39540d6cf3b2b7c80f6f58e952be5987eae64a5.elf"
    file_type = "elf"
    first_seen = "2026-09-01 05:06:59"
  condition:
    hash.sha256(0, filesize) == "3f406f1968f6c47503b8ef56a39540d6cf3b2b7c80f6f58e952be5987eae64a5"
}

rule MalwareBazaar_unknown_003_0ec3487f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ec3487f79cb0fc47ea70ce3f93b13bb3013e54cd65c2e9b3c83c4663652321f"
    family = "unknown"
    file_name = "0ec3487f79cb0fc47ea70ce3f93b13bb3013e54cd65c2e9b3c83c4663652321f.exe"
    file_type = "exe"
    first_seen = "2026-09-01 04:52:22"
  condition:
    hash.sha256(0, filesize) == "0ec3487f79cb0fc47ea70ce3f93b13bb3013e54cd65c2e9b3c83c4663652321f"
}

rule MalwareBazaar_Vidar_004_77456069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "774560697fd43c072b6fa4b4719542370b15a3d932a924496af2193ae4e30cfb"
    family = "Vidar"
    file_name = "774560697fd43c072b6fa4b4719542370b15a3d932a924496af2193ae4e30cfb.bin"
    file_type = "exe"
    first_seen = "2026-09-01 04:48:39"
  condition:
    hash.sha256(0, filesize) == "774560697fd43c072b6fa4b4719542370b15a3d932a924496af2193ae4e30cfb"
}

rule MalwareBazaar_unknown_005_8ada7f5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ada7f5b671c1b3fad199826203eb4e5dbd1c6a8cf1791100651ac24358daef4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 04:40:10"
  condition:
    hash.sha256(0, filesize) == "8ada7f5b671c1b3fad199826203eb4e5dbd1c6a8cf1791100651ac24358daef4"
}

rule MalwareBazaar_unknown_006_b8b9654b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8b9654b57a0445ea1f5645d0f6063df790448dea4d5ae27d502a2b136bb8da1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 04:30:02"
  condition:
    hash.sha256(0, filesize) == "b8b9654b57a0445ea1f5645d0f6063df790448dea4d5ae27d502a2b136bb8da1"
}

rule MalwareBazaar_unknown_007_5159769b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5159769b2b36c72598bb55b7d77340f95828e33c0e15fc0af186e9e94f6ed6ca"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-01 04:17:57"
  condition:
    hash.sha256(0, filesize) == "5159769b2b36c72598bb55b7d77340f95828e33c0e15fc0af186e9e94f6ed6ca"
}

rule MalwareBazaar_Mirai_008_7397b8cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7397b8cf285c24e2cb4472a096538782aeb05d9189667bcd4f1798cf76aaee64"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-01 04:16:27"
  condition:
    hash.sha256(0, filesize) == "7397b8cf285c24e2cb4472a096538782aeb05d9189667bcd4f1798cf76aaee64"
}

rule MalwareBazaar_unknown_009_dc07a661
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc07a6610471441482aa3261e1f5b49078f97be9177774de2abd569b62889f7b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-01 04:13:19"
  condition:
    hash.sha256(0, filesize) == "dc07a6610471441482aa3261e1f5b49078f97be9177774de2abd569b62889f7b"
}

rule MalwareBazaar_unknown_010_ed36bed1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed36bed1b59a5608984b00f914b2f9e4a98790f2f181cbb89f31f3d1a6531ed4"
    family = "unknown"
    file_name = "ed36bed1b59a5608984b00f914b2f9e4a98790f2f181cbb89f31f3d1a6531ed4.bin"
    file_type = "exe"
    first_seen = "2026-09-01 04:12:46"
  condition:
    hash.sha256(0, filesize) == "ed36bed1b59a5608984b00f914b2f9e4a98790f2f181cbb89f31f3d1a6531ed4"
}

rule MalwareBazaar_Mirai_011_c40e58e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c40e58e9eda2d0a753c5a6bce142b758d437d2878f5ae39d8486824881261128"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-01 03:39:47"
  condition:
    hash.sha256(0, filesize) == "c40e58e9eda2d0a753c5a6bce142b758d437d2878f5ae39d8486824881261128"
}

rule MalwareBazaar_Heodo_012_2b371117
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b371117fd3dc235ab72fa57397da7ed522ab65c665b2b0d62526ceafa3aa2c3"
    family = "Heodo"
    file_name = "爱接码平台客户端.exe"
    file_type = "exe"
    first_seen = "2026-09-01 03:29:56"
  condition:
    hash.sha256(0, filesize) == "2b371117fd3dc235ab72fa57397da7ed522ab65c665b2b0d62526ceafa3aa2c3"
}

rule MalwareBazaar_Formbook_013_5fc2d30f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fc2d30f108373d11a5bcb3c6b6f840bb13506b7211ff088c83d9f3ca4b3b403"
    family = "Formbook"
    file_name = "Harga RFQ New 0260891566.pdf.js"
    file_type = "js"
    first_seen = "2026-09-01 03:28:23"
  condition:
    hash.sha256(0, filesize) == "5fc2d30f108373d11a5bcb3c6b6f840bb13506b7211ff088c83d9f3ca4b3b403"
}

rule MalwareBazaar_unknown_014_2ae07d8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ae07d8c604e0156932d22eba1f0da929821c1956a4a8830135b8a9bb40bb61e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-01 03:22:42"
  condition:
    hash.sha256(0, filesize) == "2ae07d8c604e0156932d22eba1f0da929821c1956a4a8830135b8a9bb40bb61e"
}

rule MalwareBazaar_Vidar_015_bd724552
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd7245522ba1de1a91f39588b5a9bd7d5fe947accaa0af28af138935b415e36d"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 03:19:38"
  condition:
    hash.sha256(0, filesize) == "bd7245522ba1de1a91f39588b5a9bd7d5fe947accaa0af28af138935b415e36d"
}

rule MalwareBazaar_unknown_016_20dba699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20dba69956576e1be144cdebbfba349c1bb70eed69be10061426b6aedb63185d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-01 03:18:29"
  condition:
    hash.sha256(0, filesize) == "20dba69956576e1be144cdebbfba349c1bb70eed69be10061426b6aedb63185d"
}

rule MalwareBazaar_unknown_017_6b4ac27c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b4ac27c66d4a77a4c2325afd61060001580043011194036c1a4a58702d836f7"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-01 03:16:33"
  condition:
    hash.sha256(0, filesize) == "6b4ac27c66d4a77a4c2325afd61060001580043011194036c1a4a58702d836f7"
}

rule MalwareBazaar_Mirai_018_8630ccb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8630ccb0f78e12c7f7a283d49a34ff465c44ec994c874219d5c03bc7caf71abe"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-09-01 03:16:32"
  condition:
    hash.sha256(0, filesize) == "8630ccb0f78e12c7f7a283d49a34ff465c44ec994c874219d5c03bc7caf71abe"
}

rule MalwareBazaar_Mirai_019_6306fecf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6306fecf65be40a727d3a199beb9bc3ad1a431b9af21ae66ef38d03655f89a95"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-01 03:16:31"
  condition:
    hash.sha256(0, filesize) == "6306fecf65be40a727d3a199beb9bc3ad1a431b9af21ae66ef38d03655f89a95"
}

rule MalwareBazaar_AgentTesla_020_503dd959
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "503dd959a7d2fb5309e3870beb60a8c9ee518b71712dfd40161052fb838aef42"
    family = "AgentTesla"
    file_name = "Payment_Advice_pdf.tar"
    file_type = "tar"
    first_seen = "2026-09-01 03:16:15"
  condition:
    hash.sha256(0, filesize) == "503dd959a7d2fb5309e3870beb60a8c9ee518b71712dfd40161052fb838aef42"
}

rule MalwareBazaar_unknown_021_45e959da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45e959da778616679ad70a21ee3d179ca2e5f7a670dc96bc137cf411c7029723"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-01 03:11:48"
  condition:
    hash.sha256(0, filesize) == "45e959da778616679ad70a21ee3d179ca2e5f7a670dc96bc137cf411c7029723"
}

rule MalwareBazaar_Mirai_022_8610c817
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8610c817c54d0d1a4435fb8d604106281d43ec98eb1665d176f0467b50e67ca2"
    family = "Mirai"
    file_name = "8610c817c54d0d1a4435fb8d604106281d43ec98eb1665d176f0467b50e67ca2.elf"
    file_type = "elf"
    first_seen = "2026-09-01 02:58:07"
  condition:
    hash.sha256(0, filesize) == "8610c817c54d0d1a4435fb8d604106281d43ec98eb1665d176f0467b50e67ca2"
}

rule MalwareBazaar_Mirai_023_1bdabbd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bdabbd4b6ce490592faeaa2f5a45992bb396c52664c8a188aff0955b78a5d75"
    family = "Mirai"
    file_name = "1bdabbd4b6ce490592faeaa2f5a45992bb396c52664c8a188aff0955b78a5d75.elf"
    file_type = "elf"
    first_seen = "2026-09-01 02:58:00"
  condition:
    hash.sha256(0, filesize) == "1bdabbd4b6ce490592faeaa2f5a45992bb396c52664c8a188aff0955b78a5d75"
}

rule MalwareBazaar_Mirai_024_d060ee9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d060ee9b0fbd1f2c3067ed1ea0c105deaa1985e78a04fc89b599841433d52b9c"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-01 02:57:18"
  condition:
    hash.sha256(0, filesize) == "d060ee9b0fbd1f2c3067ed1ea0c105deaa1985e78a04fc89b599841433d52b9c"
}

rule MalwareBazaar_Mirai_025_386df9ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "386df9ad75375fa794a0caf827cce7025f179368ac9389a5db47bc4c40f6d954"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-01 02:52:38"
  condition:
    hash.sha256(0, filesize) == "386df9ad75375fa794a0caf827cce7025f179368ac9389a5db47bc4c40f6d954"
}

rule MalwareBazaar_Mirai_026_02c05faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02c05faa97ebc77db971a14b06fd99ec004e669b662a55d520031b1bed808199"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-01 02:51:20"
  condition:
    hash.sha256(0, filesize) == "02c05faa97ebc77db971a14b06fd99ec004e669b662a55d520031b1bed808199"
}

rule MalwareBazaar_unknown_027_1932cf80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1932cf80c5dac61c0e59a7ccb7efae5314e87645b304f4a4bc81ceecc16a4dde"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-01 02:49:39"
  condition:
    hash.sha256(0, filesize) == "1932cf80c5dac61c0e59a7ccb7efae5314e87645b304f4a4bc81ceecc16a4dde"
}

rule MalwareBazaar_Mirai_028_b96706b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b96706b34eff4a7301245feaf1b7f6e869977daaa9cc5f27822bd679ee1f472b"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-01 02:49:38"
  condition:
    hash.sha256(0, filesize) == "b96706b34eff4a7301245feaf1b7f6e869977daaa9cc5f27822bd679ee1f472b"
}

rule MalwareBazaar_Mirai_029_f14759a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f14759a0828bcafe4e63de7b1e50b6952c98eec8d7515c3cb6ff77d21aff4ebe"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-01 02:45:27"
  condition:
    hash.sha256(0, filesize) == "f14759a0828bcafe4e63de7b1e50b6952c98eec8d7515c3cb6ff77d21aff4ebe"
}

rule MalwareBazaar_unknown_030_3d578e83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d578e83e82ac112c0dedc3f390b7ecbbca4ee77b4f50bff900bd30663bfe20f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-01 02:45:26"
  condition:
    hash.sha256(0, filesize) == "3d578e83e82ac112c0dedc3f390b7ecbbca4ee77b4f50bff900bd30663bfe20f"
}

rule MalwareBazaar_Vidar_031_64a9ab01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64a9ab0128ae49ec44ce91019fedecd5676372564f84455b9c55215a8f31bbbd"
    family = "Vidar"
    file_name = "64a9ab0128ae49ec44ce91019fedecd5676372564f84455b9c55215a8f31bbbd.bin"
    file_type = "exe"
    first_seen = "2026-09-01 02:31:09"
  condition:
    hash.sha256(0, filesize) == "64a9ab0128ae49ec44ce91019fedecd5676372564f84455b9c55215a8f31bbbd"
}

rule MalwareBazaar_unknown_032_1ef57112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ef57112f92d5496e7956dd4d037da219dcd133b92ec582cc2267b23f12c5b9f"
    family = "unknown"
    file_name = "1ef57112f92d5496e7956dd4d037da219dcd133b92ec582cc2267b23f12c5b9f.exe"
    file_type = "exe"
    first_seen = "2026-09-01 02:22:33"
  condition:
    hash.sha256(0, filesize) == "1ef57112f92d5496e7956dd4d037da219dcd133b92ec582cc2267b23f12c5b9f"
}

rule MalwareBazaar_Stealc_033_b57e4c25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b57e4c2581991afbd8c89d3dc89f48fbdcc38446d18bc5f1b8f8472f49c86456"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 02:09:58"
  condition:
    hash.sha256(0, filesize) == "b57e4c2581991afbd8c89d3dc89f48fbdcc38446d18bc5f1b8f8472f49c86456"
}

rule MalwareBazaar_unknown_034_62263246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "622632461f08d057fe5a14c61257bee3cad49bd0c7b89f571dff86debbdb37d9"
    family = "unknown"
    file_name = "tfmb_0a954e02c5c334fc_0a954e02c5c334fced26459329feccbe9750614c0bdb1cb26e9196d5a2d7044b.exe"
    file_type = "exe"
    first_seen = "2026-09-01 02:06:30"
  condition:
    hash.sha256(0, filesize) == "622632461f08d057fe5a14c61257bee3cad49bd0c7b89f571dff86debbdb37d9"
}

rule MalwareBazaar_Stealc_035_2467a949
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2467a949be1e7b47aa11edaf1263469e9baf307a3cc0713b2980539d31ec3dab"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 02:05:09"
  condition:
    hash.sha256(0, filesize) == "2467a949be1e7b47aa11edaf1263469e9baf307a3cc0713b2980539d31ec3dab"
}

rule MalwareBazaar_unknown_036_8c91e9ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c91e9ab5fbeb88473034e12ff9feb159fb367353500bdd471a92dc022ba4c21"
    family = "unknown"
    file_name = "8c91e9ab5fbeb88473034e12ff9feb159fb367353500bdd471a92dc022ba4c21.bin"
    file_type = "exe"
    first_seen = "2026-09-01 02:01:01"
  condition:
    hash.sha256(0, filesize) == "8c91e9ab5fbeb88473034e12ff9feb159fb367353500bdd471a92dc022ba4c21"
}

rule MalwareBazaar_ACRStealer_037_b646d298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b646d2987f0f0a0c7416eb4f6c5edf2f7faa088bbc57877cc48e8a463d497739"
    family = "ACRStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 01:33:35"
  condition:
    hash.sha256(0, filesize) == "b646d2987f0f0a0c7416eb4f6c5edf2f7faa088bbc57877cc48e8a463d497739"
}

rule MalwareBazaar_unknown_038_2282000c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2282000cd6def22a6473c19b1177c044d01aeea6a820cb4272c0106f1d4e5bbb"
    family = "unknown"
    file_name = "2282000cd6def22a6473c19b1177c044d01aeea6a820cb4272c0106f1d4e5bbb.exe"
    file_type = "exe"
    first_seen = "2026-09-01 01:32:57"
  condition:
    hash.sha256(0, filesize) == "2282000cd6def22a6473c19b1177c044d01aeea6a820cb4272c0106f1d4e5bbb"
}

rule MalwareBazaar_unknown_039_0866f1ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0866f1acf9460fa133f76adff4182bbdf621083e807d49387b50a9e10bac3feb"
    family = "unknown"
    file_name = "0866f1acf9460fa133f76adff4182bbdf621083e807d49387b50a9e10bac3feb.bin"
    file_type = "exe"
    first_seen = "2026-09-01 01:30:47"
  condition:
    hash.sha256(0, filesize) == "0866f1acf9460fa133f76adff4182bbdf621083e807d49387b50a9e10bac3feb"
}

rule MalwareBazaar_CoinMiner_040_00c4603f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00c4603f074afb652780bb8b3e703ae093c5644652b81954ec6d0fb983e79203"
    family = "CoinMiner"
    file_name = "00c4603f074afb652780bb8b3e703ae093c5644652b81954ec6d0fb983e79203.exe"
    file_type = "exe"
    first_seen = "2026-09-01 01:12:03"
  condition:
    hash.sha256(0, filesize) == "00c4603f074afb652780bb8b3e703ae093c5644652b81954ec6d0fb983e79203"
}

rule MalwareBazaar_unknown_041_0d4db24c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d4db24c7534f64e080fddc211c026c56976187b7a30bd2fdd35316ad6f450e1"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-01 01:07:52"
  condition:
    hash.sha256(0, filesize) == "0d4db24c7534f64e080fddc211c026c56976187b7a30bd2fdd35316ad6f450e1"
}

rule MalwareBazaar_unknown_042_4ff5127f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ff5127f162125a80bbeedf7ae42e56f24efba63a719f84d152c4266f3518242"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 00:59:58"
  condition:
    hash.sha256(0, filesize) == "4ff5127f162125a80bbeedf7ae42e56f24efba63a719f84d152c4266f3518242"
}

rule MalwareBazaar_ConnectWise_043_21ca7ea2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21ca7ea24b9faedcc3d82d803f71f3d61d407d518dd503b6da5ea9b8dac3d0bc"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 00:24:59"
  condition:
    hash.sha256(0, filesize) == "21ca7ea24b9faedcc3d82d803f71f3d61d407d518dd503b6da5ea9b8dac3d0bc"
}

rule MalwareBazaar_WannaCry_044_609996da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "609996da0ee3ae21db2ecc8c98c656994723fc8359410a118a2042c418b53f03"
    family = "WannaCry"
    file_name = "609996da0ee3ae21db2ecc8c98c656994723fc8359410a118a2042c418b53f03"
    file_type = "exe"
    first_seen = "2026-09-01 00:15:33"
  condition:
    hash.sha256(0, filesize) == "609996da0ee3ae21db2ecc8c98c656994723fc8359410a118a2042c418b53f03"
}

rule MalwareBazaar_NanoCore_045_d70fc0b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d70fc0b690b491762a0f861cd129786e9e54c4a79dff6f7bd0b3a14c90b6ec24"
    family = "NanoCore"
    file_name = "33970F0D2D3BA1F4D505DEC41EB157E6.exe"
    file_type = "exe"
    first_seen = "2026-09-01 00:15:06"
  condition:
    hash.sha256(0, filesize) == "d70fc0b690b491762a0f861cd129786e9e54c4a79dff6f7bd0b3a14c90b6ec24"
}

rule MalwareBazaar_Mirai_046_c6b8b653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6b8b6530e5e43df058648b4004b66aa992cdbfdadc879a4ffe8f56f2c8dc63c"
    family = "Mirai"
    file_name = "c6b8b6530e5e43df058648b4004b66aa992cdbfdadc879a4ffe8f56f2c8dc63c.elf"
    file_type = "elf"
    first_seen = "2026-09-01 00:02:16"
  condition:
    hash.sha256(0, filesize) == "c6b8b6530e5e43df058648b4004b66aa992cdbfdadc879a4ffe8f56f2c8dc63c"
}

rule MalwareBazaar_Mirai_047_c8fd41ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033"
    family = "Mirai"
    file_name = "c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033.elf"
    file_type = "elf"
    first_seen = "2026-09-01 00:02:11"
  condition:
    hash.sha256(0, filesize) == "c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033"
}

rule MalwareBazaar_Mirai_048_5a377ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a377ec931f19b8d8848f35dde27211101c7165212309e2065de22a32598506c"
    family = "Mirai"
    file_name = "5a377ec931f19b8d8848f35dde27211101c7165212309e2065de22a32598506c.elf"
    file_type = "elf"
    first_seen = "2026-09-01 00:02:06"
  condition:
    hash.sha256(0, filesize) == "5a377ec931f19b8d8848f35dde27211101c7165212309e2065de22a32598506c"
}

rule MalwareBazaar_unknown_049_9897c649
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9897c649dedea20a1743fecd392d220e43151d349ed060ac1c7403cdcb60c852"
    family = "unknown"
    file_name = "9897c649dedea20a1743fecd392d220e43151d349ed060ac1c7403cdcb60c852.bin"
    file_type = "exe"
    first_seen = "2026-09-01 00:01:19"
  condition:
    hash.sha256(0, filesize) == "9897c649dedea20a1743fecd392d220e43151d349ed060ac1c7403cdcb60c852"
}

rule MalwareBazaar_unknown_050_96986365
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96986365c7730a62601a2c435f332d6aa541e08244ca40ef1e5e35c3a3ae7cb7"
    family = "unknown"
    file_name = "96986365c7730a62601a2c435f332d6aa541e08244ca40ef1e5e35c3a3ae7cb7.bin"
    file_type = "exe"
    first_seen = "2026-08-31 23:31:09"
  condition:
    hash.sha256(0, filesize) == "96986365c7730a62601a2c435f332d6aa541e08244ca40ef1e5e35c3a3ae7cb7"
}

rule MalwareBazaar_unknown_051_31c24e66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31c24e66dd8b0c26017ffa8aceee3305f99746163ece14d750f912b5cd10b00b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-31 23:13:31"
  condition:
    hash.sha256(0, filesize) == "31c24e66dd8b0c26017ffa8aceee3305f99746163ece14d750f912b5cd10b00b"
}

rule MalwareBazaar_ConnectWise_052_9f2b31c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f2b31c6ee353fc8b1a9897357902cce09efa5f5ab1134ec5c17b5abac892ece"
    family = "ConnectWise"
    file_name = "file"
    file_type = "msi"
    first_seen = "2026-08-31 23:08:29"
  condition:
    hash.sha256(0, filesize) == "9f2b31c6ee353fc8b1a9897357902cce09efa5f5ab1134ec5c17b5abac892ece"
}

rule MalwareBazaar_unknown_053_61e1448b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61e1448bb643b75266b23f27256e2ab54ee1bdfe8bde759162ba24cf5102b44b"
    family = "unknown"
    file_name = "skynet_dropper_61e1448b.exe"
    file_type = "exe"
    first_seen = "2026-08-31 22:25:19"
  condition:
    hash.sha256(0, filesize) == "61e1448bb643b75266b23f27256e2ab54ee1bdfe8bde759162ba24cf5102b44b"
}

rule MalwareBazaar_unknown_054_170ac61e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "170ac61ecb942da70576080c6bf25eecdad66c5843c7f8aac2d6a6cc44af7903"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-31 22:23:36"
  condition:
    hash.sha256(0, filesize) == "170ac61ecb942da70576080c6bf25eecdad66c5843c7f8aac2d6a6cc44af7903"
}

rule MalwareBazaar_unknown_055_9bf4339e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bf4339e422f50532770dceabe5cc1467005aeb9322ff981202a3bc4d82e86f8"
    family = "unknown"
    file_name = "goodthingsforbestpersonforme.hta"
    file_type = "hta"
    first_seen = "2026-08-31 22:23:35"
  condition:
    hash.sha256(0, filesize) == "9bf4339e422f50532770dceabe5cc1467005aeb9322ff981202a3bc4d82e86f8"
}

rule MalwareBazaar_Mirai_056_ba4702a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba4702a586423e508da644eac65f17dc7096fdf97231d571aa81b2915225ffe3"
    family = "Mirai"
    file_name = "daredevil.arc"
    file_type = "elf"
    first_seen = "2026-08-31 22:13:37"
  condition:
    hash.sha256(0, filesize) == "ba4702a586423e508da644eac65f17dc7096fdf97231d571aa81b2915225ffe3"
}

rule MalwareBazaar_Mirai_057_ed0509df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed0509dfbec975e7e6b22d2b73d25b9643a9fb020906259e8c4fc55812c7ccf8"
    family = "Mirai"
    file_name = "daredevil.i486"
    file_type = "elf"
    first_seen = "2026-08-31 22:08:20"
  condition:
    hash.sha256(0, filesize) == "ed0509dfbec975e7e6b22d2b73d25b9643a9fb020906259e8c4fc55812c7ccf8"
}

rule MalwareBazaar_Mirai_058_21578d83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21578d838b72e8ffe8719a211c507ccf9a585b62e24924340d4a6bad8dde4f4a"
    family = "Mirai"
    file_name = "daredevil.i486"
    file_type = "elf"
    first_seen = "2026-08-31 22:08:01"
  condition:
    hash.sha256(0, filesize) == "21578d838b72e8ffe8719a211c507ccf9a585b62e24924340d4a6bad8dde4f4a"
}

rule MalwareBazaar_CoinMiner_059_1d64be0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d64be0ba1bd9924c3e29ae460db9407e4e33afeb864c9e39377ae4a87fa09db"
    family = "CoinMiner"
    file_name = "1d64be0ba1bd9924c3e29ae460db9407e4e33afeb864c9e39377ae4a87fa09db"
    file_type = "sh"
    first_seen = "2026-08-31 22:04:52"
  condition:
    hash.sha256(0, filesize) == "1d64be0ba1bd9924c3e29ae460db9407e4e33afeb864c9e39377ae4a87fa09db"
}

rule MalwareBazaar_unknown_060_0da821d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0da821d9b5d6d28f5a1c49e7c3fad8f0dc1080def5b0e2e8e832796102af5955"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 22:01:57"
  condition:
    hash.sha256(0, filesize) == "0da821d9b5d6d28f5a1c49e7c3fad8f0dc1080def5b0e2e8e832796102af5955"
}

rule MalwareBazaar_unknown_061_2c46bade
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c46bade40bf7b255dcd7846f3969c697cc82325f9381e0089163415eb81716e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-31 21:57:36"
  condition:
    hash.sha256(0, filesize) == "2c46bade40bf7b255dcd7846f3969c697cc82325f9381e0089163415eb81716e"
}

rule MalwareBazaar_unknown_062_6da954cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6da954cca9bff4eeed5d6506fdd80d70a0bb80882327ab8de7f10dc95df8693e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-31 21:57:35"
  condition:
    hash.sha256(0, filesize) == "6da954cca9bff4eeed5d6506fdd80d70a0bb80882327ab8de7f10dc95df8693e"
}

rule MalwareBazaar_unknown_063_8d7c535c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d7c535c3073790d9f08245d6ca5ba92b7e393a4b65dbe1aa1b29923caae7d4a"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 21:53:39"
  condition:
    hash.sha256(0, filesize) == "8d7c535c3073790d9f08245d6ca5ba92b7e393a4b65dbe1aa1b29923caae7d4a"
}

rule MalwareBazaar_unknown_064_69b8be81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69b8be812307119aea9a2d41192765d5b51e27b61ec13b946953af68c065c287"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-31 21:53:38"
  condition:
    hash.sha256(0, filesize) == "69b8be812307119aea9a2d41192765d5b51e27b61ec13b946953af68c065c287"
}

rule MalwareBazaar_unknown_065_7c357211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c357211fa3c4daa5cf500050b6bb7b0d5cc7d5fa9ffd61312d4873a9341d9af"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 21:49:37"
  condition:
    hash.sha256(0, filesize) == "7c357211fa3c4daa5cf500050b6bb7b0d5cc7d5fa9ffd61312d4873a9341d9af"
}

rule MalwareBazaar_Mirai_066_f4f93f13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4f93f133a02d0016e359f3e21da4c35a49e773dac78796d261f2bc06018837a"
    family = "Mirai"
    file_name = "daredevil.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-31 21:44:18"
  condition:
    hash.sha256(0, filesize) == "f4f93f133a02d0016e359f3e21da4c35a49e773dac78796d261f2bc06018837a"
}

rule MalwareBazaar_Mirai_067_849cece6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "849cece6b12e1eec884b0adbc42885b303de2d905c6639a0b245ca548ad9eb41"
    family = "Mirai"
    file_name = "daredevil.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-31 21:43:41"
  condition:
    hash.sha256(0, filesize) == "849cece6b12e1eec884b0adbc42885b303de2d905c6639a0b245ca548ad9eb41"
}

rule MalwareBazaar_Mirai_068_a4dbf227
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4dbf22782b6fef636b76a5082665b54d272a84b7c3ddac39f49d40d88b4226b"
    family = "Mirai"
    file_name = "daredevil.mipsel"
    file_type = "elf"
    first_seen = "2026-08-31 21:38:19"
  condition:
    hash.sha256(0, filesize) == "a4dbf22782b6fef636b76a5082665b54d272a84b7c3ddac39f49d40d88b4226b"
}

rule MalwareBazaar_Mirai_069_fb73154c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb73154cda3bf3442a00bff97d5d291108fb2a1ba4cc4edab80bd721266dcfae"
    family = "Mirai"
    file_name = "daredevil.mipsel"
    file_type = "elf"
    first_seen = "2026-08-31 21:37:38"
  condition:
    hash.sha256(0, filesize) == "fb73154cda3bf3442a00bff97d5d291108fb2a1ba4cc4edab80bd721266dcfae"
}

rule MalwareBazaar_Mirai_070_fe5af4a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe5af4a090b37fad65ce094b180d8d16c2b8f932214f82c6dbc0a79312e76939"
    family = "Mirai"
    file_name = "daredevil.x86_64"
    file_type = "elf"
    first_seen = "2026-08-31 21:36:24"
  condition:
    hash.sha256(0, filesize) == "fe5af4a090b37fad65ce094b180d8d16c2b8f932214f82c6dbc0a79312e76939"
}

rule MalwareBazaar_Mirai_071_6aa6356e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aa6356e83451c2fb11ca6f42fd533d821f719c0ffc1972d7d1620f9636493de"
    family = "Mirai"
    file_name = "daredevil.m68k"
    file_type = "elf"
    first_seen = "2026-08-31 21:35:47"
  condition:
    hash.sha256(0, filesize) == "6aa6356e83451c2fb11ca6f42fd533d821f719c0ffc1972d7d1620f9636493de"
}

rule MalwareBazaar_Mirai_072_a51ad3b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a51ad3b43629a1c9d08cc25bd81ba5bf4765a9c5fc6cf59236ece7f570291bca"
    family = "Mirai"
    file_name = "daredevil.x86_64"
    file_type = "elf"
    first_seen = "2026-08-31 21:35:46"
  condition:
    hash.sha256(0, filesize) == "a51ad3b43629a1c9d08cc25bd81ba5bf4765a9c5fc6cf59236ece7f570291bca"
}

rule MalwareBazaar_Mirai_073_79831d5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79831d5c99e4b529a2f10c8cf335b6cbbc6f0b509981350174c93a87a77285a3"
    family = "Mirai"
    file_name = "daredevil.sparc"
    file_type = "elf"
    first_seen = "2026-08-31 21:29:57"
  condition:
    hash.sha256(0, filesize) == "79831d5c99e4b529a2f10c8cf335b6cbbc6f0b509981350174c93a87a77285a3"
}

rule MalwareBazaar_Mirai_074_cae0a5ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae0a5bae0a415d5c9cdbe1fd4d086026b450a2cf4ffbc9f6297652ebfb05016"
    family = "Mirai"
    file_name = "daredevil.powerpc"
    file_type = "elf"
    first_seen = "2026-08-31 21:28:18"
  condition:
    hash.sha256(0, filesize) == "cae0a5bae0a415d5c9cdbe1fd4d086026b450a2cf4ffbc9f6297652ebfb05016"
}

rule MalwareBazaar_Mirai_075_9017db28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9017db28c11dea6e2e36633483476f208c26caaaa2ebb7be4c79860ac3df624a"
    family = "Mirai"
    file_name = "daredevil.powerpc"
    file_type = "elf"
    first_seen = "2026-08-31 21:27:56"
  condition:
    hash.sha256(0, filesize) == "9017db28c11dea6e2e36633483476f208c26caaaa2ebb7be4c79860ac3df624a"
}

rule MalwareBazaar_Mirai_076_159b2822
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "159b2822082e57ea6a745ee386aeb72b3e02570a571c987efa915d03b8832010"
    family = "Mirai"
    file_name = "daredevil.sh4"
    file_type = "elf"
    first_seen = "2026-08-31 21:19:12"
  condition:
    hash.sha256(0, filesize) == "159b2822082e57ea6a745ee386aeb72b3e02570a571c987efa915d03b8832010"
}

rule MalwareBazaar_unknown_077_f68d138f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f68d138f6c5df634fe3c57cb224d9f873af8f7c41a2174ac90914bce03b3cce7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-31 21:19:10"
  condition:
    hash.sha256(0, filesize) == "f68d138f6c5df634fe3c57cb224d9f873af8f7c41a2174ac90914bce03b3cce7"
}

rule MalwareBazaar_Mirai_078_6cc6ddf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cc6ddf433301a7053aed3cc2895286dd4229ebfa294e84c229c80a1a94f1f76"
    family = "Mirai"
    file_name = "daredevil.armv6l"
    file_type = "elf"
    first_seen = "2026-08-31 21:03:27"
  condition:
    hash.sha256(0, filesize) == "6cc6ddf433301a7053aed3cc2895286dd4229ebfa294e84c229c80a1a94f1f76"
}

rule MalwareBazaar_Mirai_079_96fea7d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96fea7d005d9c9bc69db0b2e9cfa63904f1010995d0aa44d2aba4a9c07d4b5cb"
    family = "Mirai"
    file_name = "daredevil.armv6l"
    file_type = "elf"
    first_seen = "2026-08-31 21:02:33"
  condition:
    hash.sha256(0, filesize) == "96fea7d005d9c9bc69db0b2e9cfa63904f1010995d0aa44d2aba4a9c07d4b5cb"
}

rule MalwareBazaar_Mirai_080_742c11c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "742c11c31cc3a27ff7b602db2208b0c92411fc3e2b86423061b3ffc519c0fba5"
    family = "Mirai"
    file_name = "daredevil.armv5l"
    file_type = "elf"
    first_seen = "2026-08-31 20:58:17"
  condition:
    hash.sha256(0, filesize) == "742c11c31cc3a27ff7b602db2208b0c92411fc3e2b86423061b3ffc519c0fba5"
}

rule MalwareBazaar_Mirai_081_1ab7ad74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ab7ad748f7523ae7cfbc7ee3d535f461213edcbaf9faea0db34921a86574270"
    family = "Mirai"
    file_name = "daredevil.armv5l"
    file_type = "elf"
    first_seen = "2026-08-31 20:57:43"
  condition:
    hash.sha256(0, filesize) == "1ab7ad748f7523ae7cfbc7ee3d535f461213edcbaf9faea0db34921a86574270"
}

rule MalwareBazaar_Mirai_082_dd0c4672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd0c4672a56e025141257044bcba49bca663c4288d0049ce524ab0745ac5085e"
    family = "Mirai"
    file_name = "daredevil.armv4l"
    file_type = "elf"
    first_seen = "2026-08-31 20:54:18"
  condition:
    hash.sha256(0, filesize) == "dd0c4672a56e025141257044bcba49bca663c4288d0049ce524ab0745ac5085e"
}

rule MalwareBazaar_Mirai_083_4d17d32e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d17d32ed6efe92ea61d16602f9c6cd5261cdd3820adec427ee68d4088b6ab5b"
    family = "Mirai"
    file_name = "linux.bin"
    file_type = "elf"
    first_seen = "2026-08-31 20:53:42"
  condition:
    hash.sha256(0, filesize) == "4d17d32ed6efe92ea61d16602f9c6cd5261cdd3820adec427ee68d4088b6ab5b"
}

rule MalwareBazaar_Mirai_084_ce3b811c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce3b811ccd6e61f95475b63e7dbed1e78c5bc1835a55908c41ad67a37443fa2b"
    family = "Mirai"
    file_name = "daredevil.armv4l"
    file_type = "elf"
    first_seen = "2026-08-31 20:53:40"
  condition:
    hash.sha256(0, filesize) == "ce3b811ccd6e61f95475b63e7dbed1e78c5bc1835a55908c41ad67a37443fa2b"
}

rule MalwareBazaar_Mirai_085_91ecbc4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91ecbc4e11331252e0f73f30723339893f2f04bfbd1713bb033fc13e200d7a5b"
    family = "Mirai"
    file_name = "daredevil.armv7l"
    file_type = "elf"
    first_seen = "2026-08-31 20:44:18"
  condition:
    hash.sha256(0, filesize) == "91ecbc4e11331252e0f73f30723339893f2f04bfbd1713bb033fc13e200d7a5b"
}

rule MalwareBazaar_Mirai_086_68087159
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68087159a07ff7dcec0c23eade3e7781177a04a7fe7860a9df2a880a39d90df4"
    family = "Mirai"
    file_name = "daredevil.armv7l"
    file_type = "elf"
    first_seen = "2026-08-31 20:43:37"
  condition:
    hash.sha256(0, filesize) == "68087159a07ff7dcec0c23eade3e7781177a04a7fe7860a9df2a880a39d90df4"
}

rule MalwareBazaar_ConnectWise_087_6374eb35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6374eb353f02c7b26e00697a32f4a4f613402ca0296f5f10afdb3243f729c1b9"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-31 20:42:44"
  condition:
    hash.sha256(0, filesize) == "6374eb353f02c7b26e00697a32f4a4f613402ca0296f5f10afdb3243f729c1b9"
}

rule MalwareBazaar_unknown_088_bc133268
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc13326814f7072968ea74acdc47b873d733e8d1894a78e05a89b99db0ef014c"
    family = "unknown"
    file_name = "bc13326814f7072968ea74acdc47b873d733e8d1894a78e05a89b99db0ef014c.bin"
    file_type = "exe"
    first_seen = "2026-08-31 20:38:11"
  condition:
    hash.sha256(0, filesize) == "bc13326814f7072968ea74acdc47b873d733e8d1894a78e05a89b99db0ef014c"
}

rule MalwareBazaar_unknown_089_4469377d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4469377d9fad4013ab26f9c55cc12d4cde554acca043d1a89dccc0d5cc88896d"
    family = "unknown"
    file_name = "4469377d9fad4013ab26f9c55cc12d4cde554acca043d1a89dccc0d5cc88896d.bin"
    file_type = "exe"
    first_seen = "2026-08-31 20:38:08"
  condition:
    hash.sha256(0, filesize) == "4469377d9fad4013ab26f9c55cc12d4cde554acca043d1a89dccc0d5cc88896d"
}

rule MalwareBazaar_unknown_090_e818ac03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e818ac036ed66a4bf55214ab534f25033de9608a733b5487ca2a1a97254017a3"
    family = "unknown"
    file_name = "e818ac036ed66a4bf55214ab534f25033de9608a733b5487ca2a1a97254017a3.bin"
    file_type = "exe"
    first_seen = "2026-08-31 20:25:21"
  condition:
    hash.sha256(0, filesize) == "e818ac036ed66a4bf55214ab534f25033de9608a733b5487ca2a1a97254017a3"
}

rule MalwareBazaar_Vidar_091_b6caa545
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6caa545312250f634c618613441d164a8bfeb76fb8c811d141af191cc3345a8"
    family = "Vidar"
    file_name = "f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:42:21"
  condition:
    hash.sha256(0, filesize) == "b6caa545312250f634c618613441d164a8bfeb76fb8c811d141af191cc3345a8"
}

rule MalwareBazaar_Vidar_092_f2b7145b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514"
    family = "Vidar"
    file_name = "f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:42:00"
  condition:
    hash.sha256(0, filesize) == "f2b7145b0521b3ee29f92a7d8e401572d0eb7f8731249d349a914395cf841514"
}

rule MalwareBazaar_unknown_093_ab168436
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab168436a009ee553b8a3357c34bf7efb1a834868029e5ee0611041d32441611"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 19:29:00"
  condition:
    hash.sha256(0, filesize) == "ab168436a009ee553b8a3357c34bf7efb1a834868029e5ee0611041d32441611"
}

rule MalwareBazaar_unknown_094_94eb933e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94eb933e0fd821cddd5a94f4e8a6e14a562a13c6ae473d48f459ea745990dbc0"
    family = "unknown"
    file_name = "9z7BGnRGpgs8cZv7.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:27:27"
  condition:
    hash.sha256(0, filesize) == "94eb933e0fd821cddd5a94f4e8a6e14a562a13c6ae473d48f459ea745990dbc0"
}

rule MalwareBazaar_unknown_095_55ae76cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55ae76cd1de5cf5824f5da8305260a96f45fc1a379377fd593912e502381609b"
    family = "unknown"
    file_name = "55ae76cd1de5cf5824f5da8305260a96f45fc1a379377fd593912e502381609b.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:26:57"
  condition:
    hash.sha256(0, filesize) == "55ae76cd1de5cf5824f5da8305260a96f45fc1a379377fd593912e502381609b"
}

rule MalwareBazaar_unknown_096_a85fb257
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a85fb25707cd8c24df4f43a59efa01fca8fc86ddca69d957f62800900ce0133f"
    family = "unknown"
    file_name = "gM9anpOuZNKX8zHj.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:26:01"
  condition:
    hash.sha256(0, filesize) == "a85fb25707cd8c24df4f43a59efa01fca8fc86ddca69d957f62800900ce0133f"
}

rule MalwareBazaar_njrat_097_79b3612d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79b3612d856a4949395de781b875c1625ff8bd1c9cb8790209bfb4819a2240d9"
    family = "njrat"
    file_name = "1807503a422d180ea91f0a23cbd76962.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:15:07"
  condition:
    hash.sha256(0, filesize) == "79b3612d856a4949395de781b875c1625ff8bd1c9cb8790209bfb4819a2240d9"
}

rule MalwareBazaar_CoinMiner_098_2bd9ba79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bd9ba7932c288d4b2f8a1ef48e4628c04f8ed12c340d775b4765fbaaff61869"
    family = "CoinMiner"
    file_name = "2bd9ba7932c288d4b2f8a1ef48e4628c04f8ed12c340d775b4765fbaaff61869.exe"
    file_type = "exe"
    first_seen = "2026-08-31 19:07:01"
  condition:
    hash.sha256(0, filesize) == "2bd9ba7932c288d4b2f8a1ef48e4628c04f8ed12c340d775b4765fbaaff61869"
}

rule MalwareBazaar_Vidar_099_149977f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "149977f683910a1b628460085407a8285817902b3e3d38952d78a6aa1f09f53a"
    family = "Vidar"
    file_name = "149977f683910a1b628460085407a8285817902b3e3d38952d78a6aa1f09f53a.bin"
    file_type = "exe"
    first_seen = "2026-08-31 19:05:49"
  condition:
    hash.sha256(0, filesize) == "149977f683910a1b628460085407a8285817902b3e3d38952d78a6aa1f09f53a"
}

rule MalwareBazaar_Amadey_100_2b20eb42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b20eb4237ad2eab05c4a2ad261bcfd436663cf32e2a45526e17dfd3a51a095d"
    family = "Amadey"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-31 19:03:22"
  condition:
    hash.sha256(0, filesize) == "2b20eb4237ad2eab05c4a2ad261bcfd436663cf32e2a45526e17dfd3a51a095d"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.
